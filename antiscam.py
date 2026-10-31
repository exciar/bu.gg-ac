"""Anti-scam: catch hijacked accounts posting the crypto-casino image scam.

The pattern: infostealer malware takes a real member's Discord session, and the
attacker posts 2-4 blurry photos of a fake celebrity crypto-casino giveaway,
with little or no text, in every channel the account can reach. There are no
links, so link filters and AutoMod miss it, and the account is old and
trusted -- often staff -- so account-age checks don't help either.

Signals, cheapest first (weights in score_post):
  1. the same images in several channels within a minute -- confirms alone
  2. a scam-shaped message: 2-4 images, almost no text, maybe @everyone
  3. OCR, only for messages already flagged by 1 or 2, matched against scam
     keywords (promo code, withdrawal successful, USDT, a domain...)
  4. a perceptual hash (dHash) close to an image from an earlier confirmed hit

Everything above the Discord layer is pure and unit-tested. This module never
writes to the verification tables: it keeps its own tables in the same SQLite
file and only reads the officer role list from the config.
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import discord
from discord import app_commands
from discord.ext import commands
from PIL import Image, ImageOps

from config import ScamConfig

log = logging.getLogger("anticheat.antiscam")

# How long a user's image posts are remembered for burst detection.
TRACK_TTL_SECONDS = 120
# "Hasn't posted an image in a while" means this many days.
IMAGE_HISTORY_DAYS = 30

W_IDENTICAL = 10    # same images in several channels: confirms on its own
W_VARIED = 5        # image posts in several channels, different images
W_SHAPE = 3         # 2-4 images, almost no text
W_EVERYONE = 2      # ...plus @everyone / @here
W_FIRST_IMAGE = 2   # ...from someone who never posts images

# A softban deletes this much history before the first post we saw, because
# the attacker may have started in a channel the bot cannot read.
SOFTBAN_MARGIN_SECONDS = 300
MAX_DELETE_SECONDS = 7 * 24 * 3600  # Discord's limit for ban message deletion

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
IMAGES_PER_MESSAGE = 4    # downloaded per message for hashing / OCR
EVIDENCE_IMAGES = 8       # downloaded per incident before anything is deleted
ALERT_THUMBNAILS = 4
OCR_MAX_SIDE = 2000
OCR_TIMEOUT_SECONDS = 20
# ponytail: a raid queues at most this many OCR jobs and skips the rest; the
# burst signal still catches a raid without OCR.
OCR_QUEUE_LIMIT = 5

IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")
_MENTION = re.compile(r"<@[!&]?\d+>|<#\d+>|@everyone|@here")

_TLDS = (
    "com|net|org|io|gg|xyz|app|bet|vip|top|cc|co|win|casino|live|pro|club|site|"
    "online|fun|me|tv|ru|us|info|biz|games|bonus|cash|money|lol|link|click|best"
)
# (kind, pattern), longest phrases first: each match is blanked out before the
# next pattern runs, so "withdrawal successful" is never also a "withdraw".
_KEYWORDS = [
    (kind, re.compile(pattern))
    for kind, pattern in [
        ("withdrawal successful", r"withdrawal\s+successful"),
        ("withdraw", r"\bwithdraw\w*"),
        ("promo code", r"promo\s*code"),
        ("activate code", r"activate\s+code"),
        ("bonus", r"\bbonus\b"),
        ("casino", r"\bcasino\b"),
        ("deposit", r"\bdeposit\w*"),
        ("usdt", r"\busdt\b"),
        ("trc20", r"\btrc[\s-]?20\b"),
        ("erc20", r"\berc[\s-]?20\b"),
        ("2500", r"(?<![\w,.])\$?2,?500(?![\w,])"),
        ("domain", rf"\b[a-z0-9][a-z0-9-]*\.(?:{_TLDS})\b"),
    ]
]


# --- reading a message ---------------------------------------------------


def strip_mentions(text: str | None) -> str:
    """The text a human would see as words: mentions and spacing removed."""
    return " ".join(_MENTION.sub(" ", text or "").split())


def is_image(attachment) -> bool:
    if (attachment.content_type or "").startswith("image/"):
        return True
    return attachment.filename.lower().endswith(IMAGE_EXTENSIONS)


def fingerprint(images) -> tuple[int, ...]:
    """Image count plus sorted byte sizes. The attacker uploads the same files
    to every channel, so copies match. Filenames are left out: pasted images
    are all "image.png", and a randomised name would break the match."""
    return (len(images), *sorted(a.size for a in images))


@dataclass(frozen=True)
class Post:
    """One image post, reduced to what detection needs. images holds the
    attachment objects so they can be downloaded later."""

    user_id: int
    channel_id: int
    message_id: int
    created_at: datetime
    images: tuple
    text_len: int
    mentions_everyone: bool
    exempt_channel: bool = False

    @property
    def image_count(self) -> int:
        return len(self.images)

    @property
    def fingerprint(self) -> tuple[int, ...]:
        return fingerprint(self.images)


def post_from_message(message, exempt_channel_ids: frozenset[int]) -> Post:
    content = message.content or ""
    channel = message.channel
    return Post(
        user_id=message.author.id,
        channel_id=channel.id,
        message_id=message.id,
        created_at=message.created_at,
        images=tuple(a for a in message.attachments if is_image(a)),
        text_len=len(strip_mentions(content)),
        # The content, not message.mention_everyone: that flag is only set when
        # the author is allowed to ping, and the scam types it regardless.
        mentions_everyone="@everyone" in content or "@here" in content,
        # A thread counts as its parent channel, so exempting a media or
        # forum channel covers its threads too.
        exempt_channel=bool(
            {channel.id, getattr(channel, "parent_id", None)} & exempt_channel_ids
        ),
    )


# --- the burst detector --------------------------------------------------


class BurstTracker:
    """Each user's recent image posts, in memory, for TTL seconds."""

    def __init__(self, ttl_seconds: int = TRACK_TTL_SECONDS) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self._posts: dict[int, list[Post]] = {}

    def add(self, post: Post) -> list[Post]:
        """Record a post; return that user's posts still inside the TTL."""
        kept = [
            p for p in self._posts.get(post.user_id, [])
            if post.created_at - p.created_at <= self.ttl
        ]
        kept.append(post)
        self._posts[post.user_id] = kept
        return list(kept)

    def recent(self, user_id: int, now: datetime) -> list[Post]:
        return [p for p in self._posts.get(user_id, []) if now - p.created_at <= self.ttl]

    def sweep(self, now: datetime) -> None:
        """Drop expired posts and users with none left."""
        for user_id in list(self._posts):
            kept = self.recent(user_id, now)
            if kept:
                self._posts[user_id] = kept
            else:
                del self._posts[user_id]


@dataclass(frozen=True)
class Burst:
    identical_channels: int  # most channels sharing one set of images
    channels: int            # distinct channels with any qualifying post


def burst_signals(posts, latest: Post, *, window_seconds: int, min_images: int) -> Burst:
    """Cross-channel activity around the latest post. Exempt channels and
    posts with fewer than min_images images do not count."""
    window = timedelta(seconds=window_seconds)
    near = [
        p for p in posts
        if not p.exempt_channel
        and p.image_count >= min_images
        and abs(latest.created_at - p.created_at) <= window
    ]
    channels_by_print: dict[tuple[int, ...], set[int]] = defaultdict(set)
    for p in near:
        channels_by_print[p.fingerprint].add(p.channel_id)
    return Burst(
        identical_channels=max((len(c) for c in channels_by_print.values()), default=0),
        channels=len({p.channel_id for p in near}),
    )


# --- scoring -------------------------------------------------------------


@dataclass(frozen=True)
class Score:
    total: int
    signals: tuple[str, ...]


def score_post(
    post: Post,
    recent: list[Post],
    cfg: ScamConfig,
    *,
    history_ready: bool,
    last_image_at: datetime | None,
) -> Score:
    """Score one post. At cfg.flag_score it is OCR'd; at cfg.confirm_score it
    is treated as a confirmed scam.

    history_ready is False until the bot has watched image posts for
    IMAGE_HISTORY_DAYS -- before that, nobody has history, and the "first
    image in a month" signal would fire for everyone.
    """
    if post.exempt_channel:
        return Score(0, ())
    total, signals = 0, []
    window = cfg.burst_window_seconds

    burst = burst_signals(recent, post, window_seconds=window, min_images=cfg.min_images)
    if burst.identical_channels >= cfg.burst_min_channels:
        total += W_IDENTICAL
        signals.append(f"same images in {burst.identical_channels} channels within {window}s")
    elif burst.channels >= cfg.burst_min_channels:
        total += W_VARIED
        signals.append(f"image posts in {burst.channels} channels within {window}s")

    if cfg.min_images <= post.image_count <= cfg.max_images and post.text_len <= cfg.max_text_chars:
        total += W_SHAPE
        signals.append(f"{post.image_count} images with {post.text_len} characters of text")
        if post.mentions_everyone:
            total += W_EVERYONE
            signals.append("@everyone / @here")
        quiet = last_image_at is None or (
            post.created_at - last_image_at > timedelta(days=IMAGE_HISTORY_DAYS)
        )
        if history_ready and quiet:
            total += W_FIRST_IMAGE
            signals.append(f"first image post in {IMAGE_HISTORY_DAYS}+ days")

    return Score(total, tuple(signals))


def match_keywords(text: str | None) -> set[str]:
    """Distinct scam keyword kinds in OCR text. Case-insensitive; overlapping
    phrases count once; every domain-like token together counts once."""
    text = (text or "").lower()
    found: set[str] = set()
    for kind, pattern in _KEYWORDS:
        def blank(match: re.Match[str], kind: str = kind) -> str:
            found.add(kind)
            return " " * len(match.group())

        text = pattern.sub(blank, text)
    return found


# --- perceptual hash -----------------------------------------------------


def dhash(img: Image.Image) -> int:
    """64-bit difference hash: shrink to 9x8 grey, compare each pixel with
    its right-hand neighbour. Survives recompression, resizing and blur."""
    pixels = img.convert("L").resize((9, 8), Image.Resampling.LANCZOS).tobytes()
    value = 0
    for row in range(8):
        for col in range(8):
            value = (value << 1) | (pixels[row * 9 + col] > pixels[row * 9 + col + 1])
    return value


def hash_distance(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def best_match(h: int, known: Iterable[int], max_distance: int) -> int | None:
    """The smallest distance to a known hash, if it is within max_distance."""
    distance = min((hash_distance(h, k) for k in known), default=None)
    return distance if distance is not None and distance <= max_distance else None


def load_image(data: bytes) -> Image.Image | None:
    """Decode an untrusted upload, or None if it isn't an image we can read."""
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        return ImageOps.exif_transpose(img)
    except Exception:  # truncated, unsupported (HEIC), decompression bomb...
        return None


def ocr_text(images: list[Image.Image]) -> str:
    """Tesseract over each image. Blocking -- run it in a thread."""
    import pytesseract  # only needed once OCR actually runs

    parts = []
    for img in images:
        grey = img.convert("L")
        grey.thumbnail((OCR_MAX_SIDE, OCR_MAX_SIDE))
        try:
            parts.append(pytesseract.image_to_string(grey, timeout=OCR_TIMEOUT_SECONDS))
        except RuntimeError:  # pytesseract's timeout
            log.warning("anti-scam: OCR timed out on one image")
    return "\n".join(parts)


def thumbnail_jpeg(img: Image.Image) -> bytes:
    small = img.convert("RGB")
    small.thumbnail((480, 480))
    buffer = io.BytesIO()
    small.save(buffer, "JPEG", quality=70)
    return buffer.getvalue()


# --- the response --------------------------------------------------------


@dataclass(frozen=True)
class ResponsePlan:
    """What to do about one confirmed hit. In a dry run the action flags say
    what would have happened; the cog acts on none of them."""

    dry_run: bool = False
    timeout: bool = False
    softban: bool = False
    delete: bool = False
    dm: bool = False
    store_hashes: bool = False
    ping: bool = False
    problems: tuple[str, ...] = ()


def plan_response(
    *,
    dry_run: bool,
    action: str,
    is_owner: bool,
    outranks_bot: bool,
    is_admin: bool,
    can_manage_messages: bool,
    can_moderate_members: bool,
    can_ban: bool,
) -> ResponsePlan:
    """Decide what can be done about a confirmed hit, and what mods must be
    pinged about. Pure, so every refusal path is tested.

    A softban (ban that deletes their recent messages everywhere, then unban
    straight away) replaces the timeout and the per-message deletes when it is
    configured and possible. Anything that cannot be done becomes a problem,
    and problems ping the mods.
    """
    if is_owner:
        return ResponsePlan(
            dry_run=dry_run,
            ping=True,
            problems=("they own the server, so the bot never acts on them -- handle this by hand",),
        )

    problems = []
    timeout = softban = delete = False
    if outranks_bot:
        problems.append(
            "their top role is at or above the bot's, so the bot can't time them out or remove them"
        )
    if action == "softban" and not outranks_bot:
        if can_ban:
            softban = True
        else:
            problems.append("the bot lacks Ban Members, so it timed them out instead of a softban")
    if not softban:
        if not outranks_bot:
            if is_admin:
                problems.append("they have Administrator, which Discord never lets a bot time out")
            elif can_moderate_members:
                timeout = True
            else:
                problems.append("the bot lacks Moderate Members, so it can't time them out")
        if can_manage_messages:
            delete = True
        else:
            problems.append("the bot lacks Manage Messages, so it can't delete the posts")

    return ResponsePlan(
        dry_run=dry_run,
        timeout=timeout,
        softban=softban,
        delete=delete,
        dm=True,
        store_hashes=True,
        ping=bool(problems) and not dry_run,
        problems=tuple(problems),
    )


def softban_delete_seconds(earliest: datetime, now: datetime) -> int:
    """How much of their history a softban deletes: back to the first post we
    saw, plus a margin for channels the bot can't read."""
    seen = max(0, int((now - earliest).total_seconds()))
    return min(MAX_DELETE_SECONDS, seen + SOFTBAN_MARGIN_SECONDS)


def build_scam_dm(guild_name: str, *, softban: bool, timeout_hours: int) -> str:
    """Recovery steps for the member whose account was hijacked. No links:
    a link in a "your account was hacked" DM is exactly what phishing looks like."""
    done = (
        "removed you from the server (you're welcome back)"
        if softban
        else f"timed you out for {timeout_hours} hours"
    )
    return "\n".join([
        f"Your Discord account just posted scam images across **{guild_name}**, so we "
        f"deleted them and {done}.",
        "",
        "This almost always means your account was hijacked: malware on your computer "
        "stole your login session. Changing your password alone isn't enough while that "
        "malware is still there.",
        "",
        "**Please do this, in order:**",
        "1. Scan your PC with an up-to-date antivirus (a full Windows Security scan, or "
        "Malwarebytes) and remove what it finds. Fake games, cracks, \"free Nitro\" and "
        "mod files are the usual source.",
        "2. From a clean device such as your phone, change your Discord password.",
        "3. Settings → Devices → **Log out all known devices**.",
        "4. Settings → Authorized Apps: remove anything you don't recognise. Turn on "
        "two-factor authentication if it isn't on yet.",
        "5. Message an officer so we can "
        + ("send you a new invite." if softban else "lift the timeout."),
        "",
        "You're not in trouble -- this happens to careful people too.",
    ])


# --- storage -------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS scam_hashes (
    hash     TEXT NOT NULL,     -- 16 hex digits; 64 bits overflow SQLite INTEGER
    incident TEXT NOT NULL,     -- message ID that confirmed it, or was added by hand
    added_by TEXT,              -- officer for manual adds, NULL when automatic
    added_at TEXT NOT NULL,
    PRIMARY KEY (hash, incident)
);

-- When each member last posted an image, for the "first image in a month"
-- signal. Rows older than IMAGE_HISTORY_DAYS are pruned at startup.
CREATE TABLE IF NOT EXISTS scam_image_posts (
    discord_id    TEXT PRIMARY KEY,
    last_image_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scam_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).isoformat()


class ScamStore:
    """The module's own tables, on its own connection to the bot's database."""

    def __init__(self, db_path: str | Path) -> None:
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.execute(
            "INSERT OR IGNORE INTO scam_state (key, value) VALUES ('tracking_since', ?)",
            (_iso(datetime.now(timezone.utc)),),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def tracking_since(self) -> datetime:
        row = self.conn.execute(
            "SELECT value FROM scam_state WHERE key = 'tracking_since'"
        ).fetchone()
        return datetime.fromisoformat(row["value"])

    def hashes(self) -> list[tuple[int, str]]:
        rows = self.conn.execute("SELECT hash, incident FROM scam_hashes ORDER BY rowid")
        return [(int(row["hash"], 16), row["incident"]) for row in rows]

    def add_hashes(self, hashes: Iterable[int], incident: str | int, added_by: int | None) -> int:
        cur = self.conn.executemany(
            "INSERT OR IGNORE INTO scam_hashes (hash, incident, added_by, added_at) "
            "VALUES (?, ?, ?, ?)",
            [
                (format(h, "016x"), str(incident), None if added_by is None else str(added_by),
                 _iso(datetime.now(timezone.utc)))
                for h in hashes
            ],
        )
        self.conn.commit()
        return cur.rowcount

    def remove_incident(self, incident: str | int) -> int:
        cur = self.conn.execute("DELETE FROM scam_hashes WHERE incident = ?", (str(incident),))
        self.conn.commit()
        return cur.rowcount

    def last_image_at(self, discord_id: int) -> datetime | None:
        row = self.conn.execute(
            "SELECT last_image_at FROM scam_image_posts WHERE discord_id = ?", (str(discord_id),)
        ).fetchone()
        return datetime.fromisoformat(row["last_image_at"]) if row else None

    def record_image(self, discord_id: int, when: datetime) -> None:
        self.conn.execute(
            "INSERT INTO scam_image_posts (discord_id, last_image_at) VALUES (?, ?) "
            "ON CONFLICT(discord_id) DO UPDATE SET last_image_at = excluded.last_image_at",
            (str(discord_id), _iso(when)),
        )
        self.conn.commit()

    def prune_image_posts(self, before: datetime) -> int:
        cur = self.conn.execute(
            "DELETE FROM scam_image_posts WHERE last_image_at < ?", (_iso(before),)
        )
        self.conn.commit()
        return cur.rowcount


# --- Discord -------------------------------------------------------------

REASON = "Anti-scam: hijacked account posting scam images"


class FalsePositiveButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"antiscam:fp:(?P<user>\d+):(?P<incident>\d+)",
):
    """The alert's "False positive – restore" button. Its state lives in the
    custom_id, so it keeps working after a restart."""

    def __init__(self, user_id: int, incident: int) -> None:
        super().__init__(
            discord.ui.Button(
                label="False positive – restore",
                style=discord.ButtonStyle.secondary,
                custom_id=f"antiscam:fp:{user_id}:{incident}",
            )
        )
        self.user_id = user_id
        self.incident = incident

    @classmethod
    async def from_custom_id(cls, interaction, item, match, /):
        return cls(int(match["user"]), int(match["incident"]))

    async def callback(self, interaction: discord.Interaction) -> None:
        cog = interaction.client.get_cog("AntiScam")
        if cog is None:
            await interaction.response.send_message("Anti-scam is switched off.", ephemeral=True)
            return
        await cog.restore(interaction, self.user_id, self.incident)


class AntiScam(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.cfg: ScamConfig = bot.cfg.scam
        self.guild_id: int = bot.cfg.guild_id
        self.officer_role_ids: frozenset[int] = bot.cfg.admin_role_ids
        self.store = ScamStore(bot.cfg.db_path)
        self.tracking_since = self.store.tracking_since()
        self.tracker = BurstTracker(max(TRACK_TTL_SECONDS, 2 * self.cfg.burst_window_seconds))
        self.known = self.store.hashes()
        self.ocr_available = False
        self._ocr = asyncio.Semaphore(1)
        self._ocr_waiting = 0
        self._downloads = asyncio.Semaphore(2)
        self._incidents = asyncio.Semaphore(2)
        self._checking: set[int] = set()            # users with a download/OCR in flight
        self._confirmed: dict[int, datetime] = {}   # user -> until when late posts are mopped up
        self._last_sweep = datetime.now(timezone.utc)
        self._announced = False
        self.menu = app_commands.ContextMenu(
            name="Add to scam images", callback=self.add_to_scam_images
        )

    async def cog_load(self) -> None:
        self.bot.tree.add_command(self.menu)
        self.bot.add_dynamic_items(FalsePositiveButton)
        now = datetime.now(timezone.utc)
        self.store.prune_image_posts(now - timedelta(days=IMAGE_HISTORY_DAYS))
        try:
            import pytesseract

            await asyncio.to_thread(pytesseract.get_tesseract_version)
            self.ocr_available = True
        except Exception:
            log.warning(
                "anti-scam: Tesseract is not installed -- OCR is off; bursts and image "
                "matches still work (apt install tesseract-ocr)"
            )

    async def cog_unload(self) -> None:
        self.bot.tree.remove_command(self.menu.name, type=self.menu.type)
        self.bot.remove_dynamic_items(FalsePositiveButton)
        self.store.close()

    # --- startup checks ---

    @commands.Cog.listener()
    async def on_ready(self) -> None:
        if self._announced:
            return
        self._announced = True
        guild = self.bot.get_guild(self.guild_id)
        if guild is None:
            return
        perms = guild.me.guild_permissions
        needed = {"Manage Messages": perms.manage_messages, "Moderate Members": perms.moderate_members}
        if self.cfg.action == "softban":
            needed["Ban Members"] = perms.ban_members
        missing = [name for name, ok in needed.items() if not ok]
        if missing:
            log.warning("anti-scam: the bot lacks %s; hits will be reported, not handled", ", ".join(missing))
        channel = guild.get_channel(self.cfg.log_channel_id)
        if channel is None:
            log.error("anti-scam: SCAM_LOG_CHANNEL_ID %s is not a channel the bot can see", self.cfg.log_channel_id)
        elif not channel.permissions_for(guild.me).send_messages:
            log.error("anti-scam: the bot can't post in the log channel #%s", channel.name)
        log.info(
            "anti-scam: on (%s, action=%s, OCR %s, %d known scam image(s))",
            "DRY RUN" if self.cfg.dry_run else "live",
            self.cfg.action,
            "on" if self.ocr_available else "off",
            len(self.known),
        )

    # --- detection ---

    def _is_officer(self, user) -> bool:
        return isinstance(user, discord.Member) and any(
            role.id in self.officer_role_ids for role in user.roles
        )

    def _sweep(self, now: datetime) -> None:
        if now - self._last_sweep < self.tracker.ttl:
            return
        self._last_sweep = now
        self.tracker.sweep(now)
        self._confirmed = {u: until for u, until in self._confirmed.items() if until > now}

    def _is_confirmed(self, user_id: int, now: datetime) -> bool:
        until = self._confirmed.get(user_id)
        return until is not None and until > now

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.guild.id != self.guild_id:
            return
        if message.author.bot or message.webhook_id is not None or not message.attachments:
            return
        member = message.author
        if not isinstance(member, discord.Member):
            return
        if any(role.id in self.cfg.exempt_role_ids for role in member.roles):
            return
        post = post_from_message(message, self.cfg.exempt_channel_ids)
        if not post.images:
            return

        now = post.created_at
        self._sweep(now)
        recent = self.tracker.add(post)
        last_image_at = self.store.last_image_at(member.id)
        self.store.record_image(member.id, now)

        if self._is_confirmed(member.id, now):
            await self._mop_up(message.guild, post)
            return
        if post.exempt_channel:
            return  # tracked, so a confirmed burst can still clean it up

        score = score_post(
            post, recent, self.cfg,
            history_ready=now - self.tracking_since >= timedelta(days=IMAGE_HISTORY_DAYS),
            last_image_at=last_image_at,
        )
        if score.total >= self.cfg.confirm_score:
            await self._confirm(member, post, score)
            return

        need_hash = bool(self.known)
        need_ocr = score.total >= self.cfg.flag_score and self.ocr_available
        if not (need_hash or need_ocr) or member.id in self._checking:
            return
        self._checking.add(member.id)
        try:
            images = [img for _, img in await self._download(post.images)]
            if not images or self._is_confirmed(member.id, datetime.now(timezone.utc)):
                return
            if need_hash:
                hashes = await asyncio.to_thread(lambda: [dhash(img) for img in images])
                known = [h for h, _ in self.known]
                matches = [d for h in hashes if (d := best_match(h, known, self.cfg.hash_max_distance)) is not None]
                if matches:
                    await self._confirm(member, post, score, distance=min(matches))
                    return
            if need_ocr:
                keywords = await self._ocr_keywords(images)
                if len(keywords) >= self.cfg.ocr_min_keywords:
                    await self._confirm(member, post, score, keywords=keywords)
        finally:
            self._checking.discard(member.id)

    async def _download(self, attachments) -> list[tuple[bytes, Image.Image]]:
        """Fetch and decode images, skipping anything oversized or unreadable."""
        out = []
        async with self._downloads:
            for attachment in list(attachments)[:IMAGES_PER_MESSAGE]:
                pixels = (attachment.width or 0) * (attachment.height or 0)
                if attachment.size > MAX_IMAGE_BYTES or pixels > MAX_IMAGE_PIXELS:
                    continue
                try:
                    data = await attachment.read()
                except discord.HTTPException:
                    continue  # deleted meanwhile
                img = await asyncio.to_thread(load_image, data)
                if img is not None:
                    out.append((data, img))
        return out

    async def _ocr_keywords(self, images: list[Image.Image]) -> set[str]:
        if self._ocr_waiting >= OCR_QUEUE_LIMIT:
            log.warning("anti-scam: OCR queue full, skipping one message")
            return set()
        self._ocr_waiting += 1
        try:
            async with self._ocr:
                text = await asyncio.to_thread(ocr_text, images)
        except Exception:
            log.exception("anti-scam: OCR failed")
            return set()
        finally:
            self._ocr_waiting -= 1
        return match_keywords(text)

    # --- response ---

    async def _confirm(self, member, post, score, *, keywords=frozenset(), distance=None) -> None:
        now = datetime.now(timezone.utc)
        if self._is_confirmed(member.id, now):
            return  # another post of the same burst got here first
        self._confirmed[member.id] = now + self.tracker.ttl
        log.warning(
            "anti-scam: confirmed discord_id=%s score=%d keywords=%d hash_distance=%s",
            member.id, score.total, len(keywords), distance,
        )
        async with self._incidents:
            try:
                await self._handle(member, post, score, set(keywords), distance)
            except Exception:
                log.exception("anti-scam: handling discord_id=%s failed", member.id)

    async def _handle(self, member, trigger: Post, score: Score, keywords: set[str], distance) -> None:
        guild = member.guild
        me = guild.me
        now = datetime.now(timezone.utc)
        burst = self.tracker.recent(member.id, now) or [trigger]
        prints = {p.fingerprint for p in burst if not p.exempt_channel}
        # Every image post of theirs in the window; in exempt channels only
        # exact copies, so their real art post an hour ago is left alone.
        targets = [p for p in burst if not p.exempt_channel or p.fingerprint in prints]
        plan = plan_response(
            dry_run=self.cfg.dry_run,
            action=self.cfg.action,
            is_owner=member.id == guild.owner_id,
            outranks_bot=member.top_role >= me.top_role,
            is_admin=member.guild_permissions.administrator,
            can_manage_messages=me.guild_permissions.manage_messages,
            can_moderate_members=me.guild_permissions.moderate_members,
            can_ban=me.guild_permissions.ban_members,
        )
        evidence = await self._evidence(targets)  # before anything is deleted
        hashes = await asyncio.to_thread(lambda: sorted({dhash(img) for _, img in evidence}))

        done, problems = [], list(plan.problems)
        if not plan.dry_run:
            if plan.timeout:
                try:
                    await member.timeout(timedelta(hours=self.cfg.timeout_hours), reason=REASON)
                    done.append(f"timed out for {self.cfg.timeout_hours}h")
                except discord.HTTPException as exc:
                    problems.append(f"the timeout failed (HTTP {exc.status})")
            if plan.store_hashes and hashes:
                self.store.add_hashes(hashes, trigger.message_id, None)
                self.known = self.store.hashes()
                done.append(f"remembered {len(hashes)} image(s)")
            if plan.dm:
                done.append("DM sent" if await self._dm(member, softban=plan.softban) else "DMs closed, no DM")
            delete = plan.delete
            if plan.softban:
                seconds = softban_delete_seconds(min(p.created_at for p in targets), now)
                try:
                    await guild.ban(member, reason=REASON, delete_message_seconds=seconds)
                except discord.HTTPException as exc:
                    problems.append(f"the softban failed (HTTP {exc.status}), deleting post by post")
                    delete = True
                else:
                    try:
                        await guild.unban(member, reason="Anti-scam softban: free to rejoin")
                        done.append(
                            f"softbanned: removed, and their messages from the last "
                            f"{seconds // 60} min deleted in every channel"
                        )
                    except discord.HTTPException:
                        problems.append("they were BANNED but the unban failed -- unban them by hand")
            if delete:
                deleted, failed = await self._delete(guild, targets)
                done.append(f"deleted {deleted} of {len(targets)} post(s)")
                if failed:
                    problems.append(f"couldn't delete in {' '.join(failed)}")
        await self._alert(
            member, targets, score, keywords, distance, plan, done, problems, evidence, trigger.message_id,
        )

    async def _evidence(self, targets: list[Post]) -> list[tuple[bytes, Image.Image]]:
        """One download per distinct set of images, up to EVIDENCE_IMAGES."""
        seen, out = set(), []
        for p in targets:
            if p.fingerprint in seen or len(out) >= EVIDENCE_IMAGES:
                continue
            seen.add(p.fingerprint)
            out += await self._download(p.images)
        return out[:EVIDENCE_IMAGES]

    async def _delete(self, guild: discord.Guild, posts: list[Post]) -> tuple[int, list[str]]:
        by_channel: dict[int, list[int]] = defaultdict(list)
        for p in posts:
            by_channel[p.channel_id].append(p.message_id)
        deleted, failed = 0, []
        for channel_id, ids in by_channel.items():
            channel = guild.get_channel_or_thread(channel_id)
            if channel is None:
                failed.append(f"<#{channel_id}>")
                continue
            try:
                await channel.delete_messages([discord.Object(id=i) for i in ids], reason=REASON)
                deleted += len(ids)
            except discord.NotFound:
                deleted += len(ids)  # already gone
            except discord.HTTPException:
                failed.append(channel.mention)
        return deleted, failed

    async def _mop_up(self, guild: discord.Guild, post: Post) -> None:
        """A post from an already-confirmed account: delete it too (in an exempt
        channel, only if it is a copy of the burst)."""
        if self.cfg.dry_run:
            return
        if post.exempt_channel:
            recent = self.tracker.recent(post.user_id, post.created_at)
            if post.fingerprint not in {p.fingerprint for p in recent if not p.exempt_channel}:
                return
        _, failed = await self._delete(guild, [post])
        log.info("anti-scam: late post from discord_id=%s %s", post.user_id, "kept" if failed else "deleted")

    async def _dm(self, member: discord.Member, *, softban: bool) -> bool:
        try:
            await member.send(build_scam_dm(member.guild.name, softban=softban, timeout_hours=self.cfg.timeout_hours))
            return True
        except discord.HTTPException:
            return False

    def _would(self, plan: ResponsePlan, posts: int) -> list[str]:
        acts = []
        if plan.softban:
            acts.append("softban (remove + delete their recent messages everywhere)")
        if plan.timeout:
            acts.append(f"time out for {self.cfg.timeout_hours}h")
        if plan.delete:
            acts.append(f"delete {posts} post(s)")
        if plan.store_hashes:
            acts.append("remember the images")
        if plan.dm:
            acts.append("DM them recovery steps")
        return acts

    async def _alert(self, member, targets, score, keywords, distance, plan, done, problems, evidence, incident) -> None:
        guild = member.guild
        channel = guild.get_channel(self.cfg.log_channel_id)
        if channel is None:
            log.error("anti-scam: log channel %s missing; alert for discord_id=%s lost", self.cfg.log_channel_id, member.id)
            return
        signals = list(score.signals)
        if distance is not None:
            signals.append(f"matches a known scam image (distance {distance})")
        if keywords:
            signals.append(f"OCR keywords: {', '.join(sorted(keywords))}")
        channels = sorted({p.channel_id for p in targets})

        embed = discord.Embed(
            title=("Dry run: " if plan.dry_run else "") + "scam image burst",
            colour=discord.Colour.orange() if plan.dry_run else discord.Colour.red(),
            description=(
                f"{member.mention} · `{member}` · `{member.id}`\n"
                "Their account is probably hijacked (stolen session)."
            ),
            timestamp=datetime.now(timezone.utc),
        )
        embed.add_field(name=f"Channels hit ({len(channels)})", value=" ".join(f"<#{c}>" for c in channels)[:1024], inline=False)
        embed.add_field(name=f"Signals (score {score.total})", value="\n".join(f"• {s}" for s in signals)[:1024] or "—", inline=False)
        if plan.dry_run:
            would = self._would(plan, len(targets))
            embed.add_field(name="Would have", value="\n".join(f"• {a}" for a in would)[:1024] or "nothing", inline=False)
        else:
            embed.add_field(name="Done", value="\n".join(f"• {a}" for a in done)[:1024] or "nothing", inline=False)
        if problems:
            embed.add_field(name="Needs a human", value="\n".join(f"• {p}" for p in problems)[:1024], inline=False)

        thumbs = await asyncio.to_thread(lambda: [thumbnail_jpeg(img) for _, img in evidence[:ALERT_THUMBNAILS]])
        files = [discord.File(io.BytesIO(data), filename=f"scam-{i}.jpg") for i, data in enumerate(thumbs)]
        view = discord.ui.View(timeout=None)
        view.add_item(FalsePositiveButton(member.id, incident))
        ping = plan.ping or (bool(problems) and not plan.dry_run)
        try:
            await channel.send(
                content="@here a hijacked account needs a human" if ping else None,
                embed=embed,
                files=files,
                view=view,
                allowed_mentions=discord.AllowedMentions(everyone=True),
            )
        except discord.HTTPException:
            log.exception("anti-scam: couldn't post the alert for discord_id=%s", member.id)

    # --- officer actions ---

    async def restore(self, interaction: discord.Interaction, user_id: int, incident: int) -> None:
        if not self._is_officer(interaction.user):
            await interaction.response.send_message("You need an officer role for this.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        forgotten = self.store.remove_incident(incident)
        self.known = self.store.hashes()
        self._confirmed.pop(user_id, None)
        member = interaction.guild.get_member(user_id)
        if member is None:
            outcome = "they're not in the server (a softban removes them -- send an invite)"
        elif member.is_timed_out():
            try:
                await member.timeout(None, reason=f"Anti-scam false positive, restored by {interaction.user}")
                outcome = "timeout lifted"
            except discord.HTTPException as exc:
                outcome = f"couldn't lift the timeout (HTTP {exc.status}) -- do it by hand"
        else:
            outcome = "no timeout to lift"
        log.warning(
            "anti-scam: false positive for discord_id=%s incident=%s, marked by discord_id=%s",
            user_id, incident, interaction.user.id,
        )
        summary = (
            f"{outcome}; {forgotten} stored image(s) forgotten. Deleted posts can't be restored."
        )
        if interaction.message and interaction.message.embeds:
            embed = interaction.message.embeds[0]
            embed.colour = discord.Colour.green()
            embed.add_field(
                name="False positive",
                value=f"Marked by {interaction.user.mention} <t:{int(datetime.now(timezone.utc).timestamp())}:R>: {summary}",
                inline=False,
            )
            await interaction.message.edit(embed=embed, view=None)
        await interaction.followup.send(f"Restored: {summary}", ephemeral=True)

    async def add_to_scam_images(self, interaction: discord.Interaction, message: discord.Message) -> None:
        """Message menu → Apps → Add to scam images. Later posts of these
        images are confirmed on sight."""
        if not self._is_officer(interaction.user):
            await interaction.response.send_message("You need an officer role for this.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        decoded = await self._download([a for a in message.attachments if is_image(a)])
        if not decoded:
            await interaction.followup.send("That message has no image I can read.", ephemeral=True)
            return
        hashes = await asyncio.to_thread(lambda: sorted({dhash(img) for _, img in decoded}))
        added = self.store.add_hashes(hashes, message.id, interaction.user.id)
        self.known = self.store.hashes()
        log.info("anti-scam: %d image(s) added by discord_id=%s", added, interaction.user.id)
        await interaction.followup.send(
            f"Added {added} image(s) to the scam list ({len(self.known)} known). Posts of "
            "matching images are now confirmed on sight.",
            ephemeral=True,
        )
