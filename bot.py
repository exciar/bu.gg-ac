"""Discord bot: /verify, /unverify and the /ac admin group.

Every reply is ephemeral -- verification status is nobody else's business, and
it keeps the channel clean.
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import discord
from discord import app_commands
from discord.ext import commands, tasks

from config import Config
from security import KickVerdict, Outcome, grace_deadline, kick_decision, make_state
from store import Roster, Store

log = logging.getLogger("anticheat.bot")


def build_join_dm(guild_name: str, deadline: datetime | None) -> str:
    """The welcome DM. Deliberately contains no verification link.

    A link would carry a signed token tied to this member's Discord ID, and
    anyone who got hold of it could attach their own school email to this
    account. Asking them to run /verify keeps that token inside an ephemeral
    reply that only they can see, and it never goes stale.
    """
    lines = [
        f"Welcome to **{guild_name}**!",
        "",
        "This server is for Bicol University students, so we ask members to "
        "confirm a school account before getting full access.",
        "",
        "**To verify:** go to the server and run the **`/verify`** command. "
        "You'll get a private link to sign in with your `@bicol-u.edu.ph` "
        "Google account. It takes about a minute.",
        "",
        "We store your school email, your name, and your Discord ID — nothing "
        "else, and we never see your password. Run `/unverify` at any time to "
        "delete it.",
    ]
    if deadline is not None:
        lines += [
            "",
            f"Please do this by <t:{int(deadline.timestamp())}:F> "
            f"(<t:{int(deadline.timestamp())}:R>). Unverified accounts are "
            "removed after that, though you're welcome to rejoin and verify.",
        ]
    lines += ["", "Questions? Message an officer in the server."]
    return "\n".join(lines)


def scan_members(members, *, cfg, verified_ids, bot_top_position, enforcement_started_at, now):
    """Apply kick_decision to every member, grouped by verdict.

    Takes an iterable of member-like objects so it can be tested with stubs
    instead of a live guild.
    """
    grouped: dict[KickVerdict, list] = {verdict: [] for verdict in KickVerdict}
    for member in members:
        verdict, deadline = kick_decision(
            is_bot=member.bot,
            is_verified=str(member.id) in verified_ids,
            role_ids={role.id for role in member.roles},
            top_role_position=member.top_role.position,
            joined_at=member.joined_at,
            now=now,
            enforcement_started_at=enforcement_started_at,
            kick_after_days=cfg.kick_after_days,
            admin_role_id=cfg.admin_role_id,
            exempt_role_ids=cfg.exempt_role_ids,
            bot_top_position=bot_top_position,
        )
        grouped[verdict].append((member, deadline))
    return grouped


class AntiCheatBot(commands.Bot):
    def __init__(self, cfg: Config, store: Store, roster: Roster) -> None:
        # Only what the job needs. members is privileged and must be enabled in
        # the Developer Portal; it is what lets the bot resolve a member to
        # assign a role to.
        intents = discord.Intents.none()
        intents.guilds = True
        intents.members = True

        super().__init__(command_prefix="!anticheat-unused", intents=intents, help_command=None)
        self.cfg = cfg
        self.store = store
        self.roster = roster

    async def setup_hook(self) -> None:
        register_commands(self)
        guild = discord.Object(id=self.cfg.guild_id)
        # Guild-scoped sync appears immediately instead of waiting on global
        # command propagation.
        self.tree.copy_global_to(guild=guild)
        synced = await self.tree.sync(guild=guild)
        log.info("synced %d commands to guild %s", len(synced), self.cfg.guild_id)
        self.enforce_loop.start()

    async def on_ready(self) -> None:
        started = self.store.get_enforcement_start()
        log.info(
            "logged in as %s (roster: %d emails, enforcement: %s)",
            self.user,
            len(self.roster),
            f"started {started:%Y-%m-%d %H:%M} UTC" if started else "off",
        )

    async def on_member_join(self, member: discord.Member) -> None:
        """Greet every new member with instructions to verify.

        Someone who verified before and is rejoining still has their link, so
        they get their role straight back rather than being asked again.
        """
        if member.bot or member.guild.id != self.cfg.guild_id:
            return

        if self.store.link_for_discord(member.id) is not None:
            restored = await grant_verified_role(self, member.guild.id, member.id)
            log.info(
                "join: discord_id=%s already linked, role %s",
                member.id,
                "restored" if restored else "could NOT be restored",
            )
            return

        deadline = None
        started = self.store.get_enforcement_start()
        if started is not None:
            deadline = grace_deadline(
                member.joined_at, started, self.cfg.kick_after_days
            )

        try:
            await member.send(build_join_dm(member.guild.name, deadline))
            self.store.log_attempt(member.id, "join_dm_sent")
            log.info("join: verification DM sent to discord_id=%s", member.id)
        except discord.Forbidden:
            # DMs closed to non-friends. Not an error -- they can still /verify.
            self.store.log_attempt(member.id, "join_dm_blocked")
            log.info("join: DMs closed for discord_id=%s", member.id)
        except discord.HTTPException as exc:
            log.warning("join: DM failed for discord_id=%s (%s)", member.id, exc)

    @tasks.loop(hours=1)
    async def enforce_loop(self) -> None:
        """Kick members who never verified, once their grace period expires.

        Does nothing at all until officers run /ac enforce start, so simply
        deploying this cannot remove anyone.
        """
        started = self.store.get_enforcement_start()
        if started is None:
            return

        guild = self.get_guild(self.cfg.guild_id)
        if guild is None:
            log.error("enforcement: guild %s unavailable", self.cfg.guild_id)
            return
        if not guild.me.guild_permissions.kick_members:
            log.error("enforcement: bot lacks Kick Members -- skipping this pass")
            return

        verified = {row["discord_id"] for row in self.store.all_links()}
        grouped = scan_members(
            guild.members,
            cfg=self.cfg,
            verified_ids=verified,
            bot_top_position=guild.me.top_role.position,
            enforcement_started_at=started,
            now=datetime.now(timezone.utc),
        )

        due = grouped[KickVerdict.KICK]
        blocked = grouped[KickVerdict.CANNOT_KICK]
        if blocked:
            log.warning(
                "enforcement: %d unverified member(s) outrank the bot and cannot be kicked",
                len(blocked),
            )
        if not due:
            return

        for member, _deadline in due:
            try:
                await member.send(
                    f"You have been removed from **{guild.name}** because your "
                    f"membership was not verified within {self.cfg.kick_after_days} days.\n\n"
                    "You can rejoin at any time and run `/verify` to confirm your "
                    "BU account. If you believe this is a mistake, contact an officer."
                )
            except discord.HTTPException:
                pass  # DMs closed; the kick still proceeds

            try:
                await member.kick(
                    reason=f"Anti-Cheat: unverified after {self.cfg.kick_after_days} days"
                )
                self.store.log_attempt(member.id, "kicked")
                log.info("enforcement: kicked discord_id=%s", member.id)
            except discord.Forbidden:
                log.error("enforcement: forbidden to kick discord_id=%s", member.id)
            except discord.HTTPException as exc:
                log.error("enforcement: kick failed discord_id=%s (%s)", member.id, exc)

    @enforce_loop.before_loop
    async def _before_enforce_loop(self) -> None:
        await self.wait_until_ready()


# --- role helpers --------------------------------------------------------


async def _resolve_member(
    bot: AntiCheatBot, guild_id: str | int, discord_id: str | int
) -> discord.Member | None:
    guild = bot.get_guild(int(guild_id))
    if guild is None:
        log.error("guild %s not found -- is the bot still in the server?", guild_id)
        return None
    member = guild.get_member(int(discord_id))
    if member is None:
        try:
            member = await guild.fetch_member(int(discord_id))
        except discord.NotFound:
            log.warning("member %s is not in guild %s", discord_id, guild_id)
            return None
    return member


async def grant_verified_role(
    bot: AntiCheatBot, guild_id: str | int, discord_id: str | int
) -> bool:
    """Assign VERIFIED_ROLE_ID. Returns False if the bot cannot -- almost always
    because its own role sits below the verified role."""
    member = await _resolve_member(bot, guild_id, discord_id)
    if member is None:
        return False
    role = member.guild.get_role(bot.cfg.verified_role_id)
    if role is None:
        log.error("VERIFIED_ROLE_ID %s does not exist", bot.cfg.verified_role_id)
        return False
    if role in member.roles:
        return True
    try:
        await member.add_roles(role, reason="Anti-Cheat: verified BU account")
        return True
    except discord.Forbidden:
        log.error(
            "cannot assign role %s -- move the bot's role above it in Server Settings",
            role.id,
        )
        return False


async def remove_verified_role(
    bot: AntiCheatBot, guild_id: str | int, discord_id: str | int
) -> bool:
    member = await _resolve_member(bot, guild_id, discord_id)
    if member is None:
        return False
    role = member.guild.get_role(bot.cfg.verified_role_id)
    if role is None or role not in member.roles:
        return True
    try:
        await member.remove_roles(role, reason="Anti-Cheat: link removed")
        return True
    except discord.Forbidden:
        log.error("cannot remove role %s -- bot role is too low", role.id)
        return False


# --- commands ------------------------------------------------------------


def register_commands(bot: AntiCheatBot) -> None:
    cfg = bot.cfg
    store = bot.store
    roster = bot.roster

    @bot.tree.command(name="verify", description="Verify your BU.gg membership with your school Google account")
    async def verify(interaction: discord.Interaction) -> None:
        if interaction.guild is None:
            await interaction.response.send_message(
                "Run this in the server, not in a DM.", ephemeral=True
            )
            return

        state = make_state(cfg.secret_key, interaction.user.id, interaction.guild.id)
        url = f"{cfg.base_url}/login?state={quote(state)}"

        view = discord.ui.View()
        view.add_item(
            discord.ui.Button(
                label="Verify with your school account",
                style=discord.ButtonStyle.link,
                url=url,
                emoji="\N{GRADUATION CAP}",
            )
        )
        await interaction.response.send_message(
            "Click below to sign in with your **@bicol-u.edu.ph** Google account.\n"
            "The link is personal to you and expires in **10 minutes**.",
            view=view,
            ephemeral=True,
        )

    @bot.tree.command(name="unverify", description="Remove your verification and delete your stored email")
    async def unverify(interaction: discord.Interaction) -> None:
        if interaction.guild is None:
            await interaction.response.send_message(
                "Run this in the server, not in a DM.", ephemeral=True
            )
            return

        await interaction.response.defer(ephemeral=True)
        removed = store.delete_link(interaction.user.id)
        await remove_verified_role(bot, interaction.guild.id, interaction.user.id)
        store.log_attempt(interaction.user.id, "unverify")
        # Log first, then anonymize, so this unverify row is scrubbed too. The
        # member leaves no identifier anywhere; only outcome counts remain.
        # (/ac revoke deliberately keeps its trail -- that is an officer action
        # and doubles as a moderation record.)
        store.anonymize_attempts(interaction.user.id)

        if removed:
            await interaction.followup.send(
                "Done. Your email has been deleted, your verified role removed, and "
                "your Discord ID cleared from our logs.\n"
                "Run `/verify` any time if you want to link again.",
                ephemeral=True,
            )
        else:
            await interaction.followup.send(
                "You do not have a verification on record. Nothing to delete.",
                ephemeral=True,
            )

    # --- /ac admin group ---

    ac = app_commands.Group(
        name="ac", description="Anti-Cheat admin commands", guild_only=True
    )

    def admin_only():
        async def predicate(interaction: discord.Interaction) -> bool:
            member = interaction.user
            if not isinstance(member, discord.Member):
                return False
            return any(role.id == cfg.admin_role_id for role in member.roles)

        return app_commands.check(predicate)

    @ac.command(name="lookup", description="Show the email linked to a member")
    @app_commands.describe(user="The member to look up")
    @admin_only()
    async def lookup(interaction: discord.Interaction, user: discord.Member) -> None:
        row = store.link_for_discord(user.id)
        if row is None:
            await interaction.response.send_message(
                f"{user.mention} is not verified.", ephemeral=True
            )
            return
        name = row["full_name"] or "_not recorded_"
        await interaction.response.send_message(
            f"{user.mention}\n**Name:** {name}\n**Email:** `{row['email']}`\n"
            f"**Verified:** {row['verified_at']}",
            ephemeral=True,
        )

    @ac.command(name="list", description="Every verified member, with names and emails")
    @admin_only()
    async def list_verified(interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        rows = store.all_links()
        if not rows:
            await interaction.followup.send("Nobody is verified yet.", ephemeral=True)
            return

        guild = interaction.guild
        table = []
        for row in rows:
            member = guild.get_member(int(row["discord_id"]))
            if member is None:
                discord_name, nickname = "(left server)", ""
            else:
                discord_name = member.name
                nickname = member.nick or ""
            table.append(
                {
                    "name": row["full_name"] or "",
                    "discord": discord_name,
                    "nickname": nickname,
                    "email": row["email"],
                    "verified_at": row["verified_at"],
                    "discord_id": row["discord_id"],
                }
            )

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(table[0].keys()))
        writer.writeheader()
        writer.writerows(table)
        export = discord.File(
            io.BytesIO(buffer.getvalue().encode("utf-8-sig")),  # BOM so Excel opens it cleanly
            filename=f"verified-{datetime.now(timezone.utc):%Y%m%d}.csv",
        )

        # Short preview inline; the CSV carries the full list and opens in a
        # spreadsheet next to the org's own membership records.
        preview = "\n".join(
            f"{r['name'] or '?':<24} {r['discord']:<20} {r['email']}" for r in table[:15]
        )
        more = f"\n… and {len(table) - 15} more in the file" if len(table) > 15 else ""
        body = (
            f"**{len(table)} verified member(s)**\n"
            f"```\n{'NAME':<24} {'DISCORD':<20} EMAIL\n{preview}\n```{more}"
        )
        if len(body) > 1900:  # Discord hard-caps messages at 2000 characters
            body = f"**{len(table)} verified member(s)** — see the attached CSV."
        await interaction.followup.send(body, file=export, ephemeral=True)

    @ac.command(name="revoke", description="Remove a member's link and verified role")
    @app_commands.describe(user="The member to revoke")
    @admin_only()
    async def revoke(interaction: discord.Interaction, user: discord.Member) -> None:
        await interaction.response.defer(ephemeral=True)
        removed = store.delete_link(user.id)
        await remove_verified_role(bot, interaction.guild.id, user.id)
        store.log_attempt(user.id, "revoked")
        await interaction.followup.send(
            f"Revoked {user.mention}. Link deleted and role removed."
            if removed
            else f"{user.mention} had no link on record; role removed anyway.",
            ephemeral=True,
        )

    @ac.command(name="reload-roster", description="Reload the roster CSV from disk")
    @admin_only()
    async def reload_roster(interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            count = roster.reload()
        except (OSError, ValueError) as exc:
            await interaction.followup.send(
                f"Could not reload the roster, so the old one is still active.\n```{exc}```",
                ephemeral=True,
            )
            return
        await interaction.followup.send(
            f"Roster reloaded: **{count}** emails from `{cfg.roster_path}`.", ephemeral=True
        )

    @ac.command(name="stats", description="Verification totals")
    @admin_only()
    async def stats(interaction: discord.Interaction) -> None:
        verified, by_outcome = store.stats()
        lines = [f"**Verified members:** {verified}", f"**Roster size:** {len(roster)}"]
        if cfg.domain_only:
            lines.append("_Roster mode: domain_only (roster check skipped)_")
        if by_outcome:
            lines.append("\n**Attempts by outcome**")
            lines += [f"`{row['outcome']}` - {row['n']}" for row in by_outcome]
        await interaction.response.send_message("\n".join(lines), ephemeral=True)

    # --- /ac enforce: the kick clock ---

    enforce = app_commands.Group(
        name="enforce",
        description="Kick members who never verify",
        parent=ac,
    )

    def _preview(guild: discord.Guild, started):
        """Group the guild by verdict, using a hypothetical start if enforcement
        is off, so officers can see the effect before committing."""
        return scan_members(
            guild.members,
            cfg=cfg,
            verified_ids={row["discord_id"] for row in store.all_links()},
            bot_top_position=guild.me.top_role.position,
            enforcement_started_at=started,
            now=datetime.now(timezone.utc),
        )

    @enforce.command(name="start", description="Start the kick clock (run this after your announcement)")
    @admin_only()
    async def enforce_start(interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        existing = store.get_enforcement_start()
        if existing is not None:
            await interaction.followup.send(
                f"Already running since <t:{int(existing.timestamp())}:f>. "
                "Use `/ac enforce stop` first if you want to restart the clock.",
                ephemeral=True,
            )
            return

        now = datetime.now(timezone.utc)
        store.set_enforcement_start(now)
        deadline = now + timedelta(days=cfg.kick_after_days)
        grouped = _preview(guild, now)
        at_risk = len(grouped[KickVerdict.WITHIN_GRACE])
        blocked = len(grouped[KickVerdict.CANNOT_KICK])

        note = (
            f"\n\n{blocked} unverified member(s) outrank the bot and can never be "
            "kicked — move the bot's role higher if that matters."
            if blocked
            else ""
        )
        await interaction.followup.send(
            f"**Kick clock started.**\n"
            f"Unverified members have until <t:{int(deadline.timestamp())}:F> "
            f"(<t:{int(deadline.timestamp())}:R>) to run `/verify`.\n"
            f"**{at_risk}** member(s) currently on the clock.\n"
            f"Nobody can be removed before that deadline. `/ac enforce status` to watch it, "
            f"`/ac enforce stop` to call it off.{note}",
            ephemeral=True,
        )

    @enforce.command(name="stop", description="Stop the kick clock; nobody is kicked")
    @admin_only()
    async def enforce_stop(interaction: discord.Interaction) -> None:
        if store.get_enforcement_start() is None:
            await interaction.response.send_message(
                "The kick clock is not running.", ephemeral=True
            )
            return
        store.set_enforcement_start(None)
        await interaction.response.send_message(
            "**Kick clock stopped.** Nobody will be kicked. Starting it again resets "
            "the grace period from scratch.",
            ephemeral=True,
        )

    @enforce.command(name="status", description="Who is on the clock, and when they are due")
    @admin_only()
    async def enforce_status(interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        started = store.get_enforcement_start()
        now = datetime.now(timezone.utc)
        # With enforcement off, preview as though it started now.
        grouped = _preview(guild, started or now)

        header = (
            f"**Kick clock: running** since <t:{int(started.timestamp())}:f>"
            if started
            else "**Kick clock: off** — the numbers below are a preview of what "
            "`/ac enforce start` would set up right now."
        )
        due = grouped[KickVerdict.KICK]
        pending = sorted(
            grouped[KickVerdict.WITHIN_GRACE], key=lambda pair: pair[1] or now
        )
        lines = [
            header,
            "",
            f"grace period: **{cfg.kick_after_days} days**",
            f"unverified, on the clock: **{len(pending)}**",
            f"past deadline (kicked next pass): **{len(due)}**",
            f"verified: **{len(grouped[KickVerdict.EXEMPT_VERIFIED])}**",
            f"exempt (officers/roles): "
            f"**{len(grouped[KickVerdict.EXEMPT_OFFICER]) + len(grouped[KickVerdict.EXEMPT_ROLE])}**",
            f"outrank the bot, cannot be kicked: **{len(grouped[KickVerdict.CANNOT_KICK])}**",
        ]
        if pending:
            lines += ["", "**Next due**"]
            lines += [
                f"{member.mention} — <t:{int(deadline.timestamp())}:R>"
                for member, deadline in pending[:10]
            ]
            if len(pending) > 10:
                lines.append(f"…and {len(pending) - 10} more")
        await interaction.followup.send("\n".join(lines)[:1900], ephemeral=True)

    @ac.error
    async def ac_error(interaction: discord.Interaction, error: Exception) -> None:
        if isinstance(error, app_commands.CheckFailure):
            message = "You need the officer role to use `/ac` commands."
        else:
            log.exception("admin command failed", exc_info=error)
            message = "That command failed. Check the service logs."
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)

    bot.tree.add_command(ac)


__all__ = [
    "AntiCheatBot",
    "Outcome",
    "grant_verified_role",
    "remove_verified_role",
    "register_commands",
]
