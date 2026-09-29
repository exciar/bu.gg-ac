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
    admin_role_id: int
    google_client_id: str
    google_client_secret: str
    base_url: str
    secret_key: str
    roster_path: str
    roster_mode: str
    db_path: str
    port: int
    kick_after_days: int
    exempt_role_ids: frozenset[int]

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

    try:
        kick_after_days = int(os.environ.get("KICK_AFTER_DAYS", "14"))
    except ValueError:
        raise ConfigError("KICK_AFTER_DAYS must be a number of days.") from None
    if kick_after_days < 1:
        raise ConfigError("KICK_AFTER_DAYS must be at least 1.")

    # Optional comma-separated role IDs that are never kicked, on top of the
    # built-in exemptions (bots, verified members, ADMIN_ROLE_ID).
    raw_exempt = os.environ.get("EXEMPT_ROLE_IDS", "").strip()
    try:
        exempt_role_ids = frozenset(
            int(part.strip()) for part in raw_exempt.split(",") if part.strip()
        )
    except ValueError:
        raise ConfigError(
            "EXEMPT_ROLE_IDS must be a comma-separated list of role IDs."
        ) from None

    return Config(
        discord_token=_required("DISCORD_TOKEN"),
        guild_id=_required_int("GUILD_ID"),
        verified_role_id=_required_int("VERIFIED_ROLE_ID"),
        admin_role_id=_required_int("ADMIN_ROLE_ID"),
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
        exempt_role_ids=exempt_role_ids,
    )
