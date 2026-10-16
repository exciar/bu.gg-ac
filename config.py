"""Configuration, read entirely from the environment.

Nothing in this project carries a default secret. Every sensitive value is
required at startup, so a misconfigured deploy fails loudly instead of running
with a blank signing key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# The only Google Workspace domain permitted to verify. This is a verification
# rule, not a tunable -- changing it changes who can join the server.
HD_DOMAIN = "bicol-u.edu.ph"

ROSTER_MODE_DOMAIN_ONLY = "domain_only"


class ConfigError(RuntimeError):
    """Raised when a required environment variable is missing or malformed."""


@dataclass(frozen=True)
class Config:
    discord_token: str
    guild_id: int
    verified_role_id: int
    admin_role_ids: frozenset[int]
    google_client_id: str
    google_client_secret: str
    base_url: str
    secret_key: str
    roster_path: str
    roster_mode: str
    db_path: str
    port: int
    kick_after_days: int
    existing_kick_after_days: int
    exempt_role_ids: frozenset[int]
    no_kick_role_ids: frozenset[int]
    reminder_days: tuple[int, ...]

    @property
    def redirect_uri(self) -> str:
        """Must match the Authorized redirect URI in the Google Cloud console."""
        return f"{self.base_url}/callback"

    @property
    def domain_only(self) -> bool:
        return self.roster_mode == ROSTER_MODE_DOMAIN_ONLY


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is not set. Copy .env.example to .env and fill it in.")
    return value


def _required_int(name: str) -> int:
    raw = _required(name)
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number, got {raw!r}.") from None


def _days(name: str, default: int) -> int:
    """An optional whole number of days, at least 1."""
    try:
        days = int(os.environ.get(name, str(default)))
    except ValueError:
        raise ConfigError(f"{name} must be a number of days.") from None
    if days < 1:
        raise ConfigError(f"{name} must be at least 1.")
    return days


def _int_list(name: str, what: str) -> list[int]:
    """Parse an optional comma-separated list of integers; blank means empty."""
    raw = os.environ.get(name, "").strip()
    try:
        return [int(part.strip()) for part in raw.split(",") if part.strip()]
    except ValueError:
        raise ConfigError(f"{name} must be a comma-separated list of {what}.") from None


def load_config() -> Config:
    load_dotenv()

    roster_mode = os.environ.get("ROSTER_MODE", "roster").strip().lower()
    roster_path = os.environ.get("ROSTER_PATH", "roster.csv").strip()
    if roster_mode != ROSTER_MODE_DOMAIN_ONLY and not roster_path:
        raise ConfigError("ROSTER_PATH is required unless ROSTER_MODE=domain_only.")

    try:
        port = int(os.environ.get("PORT", "8000"))
    except ValueError:
        raise ConfigError("PORT must be a number.") from None

    # Grace periods. Members who join while the clock runs count from joining;
    # members already here count from the clock start, and get longer because
    # nobody told them about a deadline when they joined.
    kick_after_days = _days("KICK_AFTER_DAYS", 3)
    existing_kick_after_days = _days("EXISTING_KICK_AFTER_DAYS", 14)

    # Officer roles: holders can run /ac and are never kicked. ADMIN_ROLE_ID is
    # the original single-role setting and is still honoured.
    admin_role_ids = frozenset(
        _int_list("ADMIN_ROLE_IDS", "role IDs") + _int_list("ADMIN_ROLE_ID", "role IDs")
    )
    if not admin_role_ids:
        raise ConfigError(
            "ADMIN_ROLE_IDS is not set. List the officer role IDs, comma-separated."
        )

    # Optional comma-separated role IDs that are never kicked, on top of the
    # built-in exemptions (bots, verified members, officer roles).
    exempt_role_ids = frozenset(_int_list("EXEMPT_ROLE_IDS", "role IDs"))
    # Optional comma-separated role IDs that are never kicked but are still
    # asked to verify: they get the same DMs, minus the removal warning.
    no_kick_role_ids = frozenset(_int_list("NO_KICK_ROLE_IDS", "role IDs"))

    # Days-left marks at which a member on the clock is DM'd a reminder. Unset
    # means the default; an empty value switches reminders off. Marks at or
    # beyond a member's own grace period are skipped per member by the bot.
    if os.environ.get("REMINDER_DAYS") is None:
        reminder_days = [7, 3, 1]
    else:
        reminder_days = _int_list("REMINDER_DAYS", "whole days")
    if any(day < 1 for day in reminder_days):
        raise ConfigError("REMINDER_DAYS must be whole days, each at least 1.")
    reminder_days = tuple(sorted(set(reminder_days), reverse=True))

    return Config(
        discord_token=_required("DISCORD_TOKEN"),
        guild_id=_required_int("GUILD_ID"),
        verified_role_id=_required_int("VERIFIED_ROLE_ID"),
        admin_role_ids=admin_role_ids,
        google_client_id=_required("GOOGLE_CLIENT_ID"),
        google_client_secret=_required("GOOGLE_CLIENT_SECRET"),
        # Trailing slash would produce "https://host//callback", which Google
        # treats as a different redirect URI and rejects.
        base_url=_required("BASE_URL").rstrip("/"),
        secret_key=_required("SECRET_KEY"),
        roster_path=roster_path,
        roster_mode=roster_mode,
        db_path=os.environ.get("DB_PATH", "anticheat.db").strip() or "anticheat.db",
        port=port,
        kick_after_days=kick_after_days,
        existing_kick_after_days=existing_kick_after_days,
        exempt_role_ids=exempt_role_ids,
        no_kick_role_ids=no_kick_role_ids,
        reminder_days=reminder_days,
    )
