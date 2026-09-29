"""State tokens, Google ID-token verification, and the verification decision.

decide() is deliberately pure: it takes plain dicts and returns an Outcome, so
every rejection path is testable without a network, a database or Discord.
"""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from urllib.parse import urlencode

import aiohttp
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from joserfc import jwt as jose_jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from config import HD_DOMAIN
from store import normalize_email

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"]

STATE_SALT = "anticheat-state"
STATE_TTL_SECONDS = 600  # 10 minutes, per spec
JWKS_TTL_SECONDS = 3600


class Outcome(str, Enum):
    SUCCESS = "success"
    NOT_BU = "not_bu"
    NOT_ON_ROSTER = "not_on_roster"
    ALREADY_LINKED = "already_linked"
    EXPIRED = "expired"
    INVALID = "invalid"
    ERROR = "error"


class StateExpired(Exception):
    """The signed link is older than STATE_TTL_SECONDS."""


class StateInvalid(Exception):
    """The signed link was tampered with, truncated or never ours."""


class GoogleError(Exception):
    """Google rejected the exchange, or returned something unverifiable.

    Carries only a short reason code -- never the response body, which holds
    the access and ID tokens.
    """


# --- state tokens --------------------------------------------------------


def _serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt=STATE_SALT)


def make_state(secret_key: str, discord_id: str | int, guild_id: str | int) -> str:
    """Sign who started this verification, plus a nonce that binds the eventual
    ID token to this exact attempt."""
    return _serializer(secret_key).dumps(
        {
            "d": str(discord_id),
            "g": str(guild_id),
            "n": secrets.token_urlsafe(16),
        }
    )


def read_state(
    secret_key: str, token: str, max_age: int = STATE_TTL_SECONDS
) -> dict[str, str]:
    try:
        data = _serializer(secret_key).loads(token, max_age=max_age)
    except SignatureExpired as exc:
        raise StateExpired() from exc
    except BadSignature as exc:
        raise StateInvalid() from exc

    if not isinstance(data, dict) or not all(k in data for k in ("d", "g", "n")):
        raise StateInvalid()
    return data


def build_authorize_url(
    client_id: str, redirect_uri: str, state: str, nonce: str
) -> str:
    """hd is a UI hint only -- it pre-selects the school account picker. The
    real domain check happens server-side in decide()."""
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "hd": HD_DOMAIN,
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}"


# --- Google OIDC ---------------------------------------------------------


class GoogleOIDC:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._keyset: KeySet | None = None
        self._keyset_at: float = 0.0

    async def exchange_code(self, code: str, session: aiohttp.ClientSession) -> str:
        """Trade the authorization code for an ID token. Returns the raw JWT."""
        payload = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        async with session.post(GOOGLE_TOKEN_ENDPOINT, data=payload) as resp:
            body = await resp.json(content_type=None)
            if resp.status != 200:
                # body holds tokens on success and an error code on failure;
                # only the short code is safe to surface.
                reason = (body or {}).get("error", f"http_{resp.status}")
                raise GoogleError(str(reason))
            id_token = (body or {}).get("id_token")
            if not id_token:
                raise GoogleError("no_id_token")
            return id_token

    async def _get_keyset(self, session: aiohttp.ClientSession) -> KeySet:
        if self._keyset is not None and (time.time() - self._keyset_at) < JWKS_TTL_SECONDS:
            return self._keyset
        async with session.get(GOOGLE_JWKS_URI) as resp:
            if resp.status != 200:
                raise GoogleError(f"jwks_http_{resp.status}")
            jwks = await resp.json(content_type=None)
        self._keyset = KeySet.import_key_set(jwks)
        self._keyset_at = time.time()
        return self._keyset

    async def verify_id_token(
        self, raw_id_token: str, nonce: str, session: aiohttp.ClientSession
    ) -> dict[str, Any]:
        """Verify signature, issuer, audience, expiry and nonce. Returns claims."""
        keyset = await self._get_keyset(session)
        try:
            token = jose_jwt.decode(raw_id_token, keyset, algorithms=["RS256"])
            registry = jose_jwt.JWTClaimsRegistry(
                leeway=60,
                iss={"essential": True, "values": GOOGLE_ISSUERS},
                aud={"essential": True, "value": self.client_id},
                exp={"essential": True},
            )
            registry.validate(token.claims)
        except JoseError as exc:
            raise GoogleError(type(exc).__name__) from exc

        claims = dict(token.claims)
        # Replay binding: this ID token must belong to the attempt that the
        # signed state started, not one captured from another session.
        if not secrets.compare_digest(str(claims.get("nonce", "")), str(nonce)):
            raise GoogleError("nonce_mismatch")
        return claims


# --- the decision --------------------------------------------------------


def _is_true(value: Any) -> bool:
    """Google sends a JSON boolean; accept the string form too so a spec-legal
    provider response never produces a false rejection."""
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


class KickVerdict(str, Enum):
    """Why a member is or is not kicked. Every branch is named so the audit log
    and /ac enforce status can explain themselves."""

    NOT_STARTED = "not_started"        # officers have not started the clock
    EXEMPT_BOT = "exempt_bot"
    EXEMPT_VERIFIED = "exempt_verified"
    EXEMPT_OFFICER = "exempt_officer"
    EXEMPT_ROLE = "exempt_role"
    EXEMPT_EXISTING = "exempt_existing"  # already here when the clock started
    CANNOT_KICK = "cannot_kick"        # their role outranks the bot's
    WITHIN_GRACE = "within_grace"
    KICK = "kick"


def grace_deadline(joined_at: datetime, kick_after_days: int) -> datetime:
    """When a new member's grace period runs out: a full kick_after_days from
    the moment they joined. Shared by the kick logic, the welcome DM and the
    reminders so they can never quote different dates.
    """
    return joined_at + timedelta(days=kick_after_days)


def kick_decision(
    *,
    is_bot: bool,
    is_verified: bool,
    role_ids: frozenset[int] | set[int],
    top_role_position: int,
    joined_at: datetime | None,
    now: datetime,
    enforcement_started_at: datetime | None,
    kick_after_days: int,
    admin_role_ids: frozenset[int] | set[int],
    exempt_role_ids: frozenset[int] | set[int],
    bot_top_position: int,
) -> tuple[KickVerdict, datetime | None]:
    """Decide whether one member should be kicked, and when their deadline is.

    Pure: takes plain values, touches nothing. Only members who joined after
    officers started the clock are on it, each from the moment they joined.
    Everyone who was already in the server is never kicked, so starting
    enforcement cannot remove an existing member.
    """
    if enforcement_started_at is None:
        return KickVerdict.NOT_STARTED, None
    if is_bot:
        return KickVerdict.EXEMPT_BOT, None
    if is_verified:
        return KickVerdict.EXEMPT_VERIFIED, None
    if role_ids & set(admin_role_ids):
        return KickVerdict.EXEMPT_OFFICER, None
    if role_ids & set(exempt_role_ids):
        return KickVerdict.EXEMPT_ROLE, None
    # No join date means we cannot prove they are new, so they are not.
    if joined_at is None or joined_at < enforcement_started_at:
        return KickVerdict.EXEMPT_EXISTING, None
    if top_role_position >= bot_top_position:
        return KickVerdict.CANNOT_KICK, None

    deadline = grace_deadline(joined_at, kick_after_days)

    if now < deadline:
        return KickVerdict.WITHIN_GRACE, deadline
    return KickVerdict.KICK, deadline


def reminder_due(
    deadline: datetime,
    now: datetime,
    reminder_days: tuple[int, ...] | list[int],
    sent: set[int],
) -> int | None:
    """Which reminder, if any, to DM a member on the clock right now.

    Each stage is a number of days left. Only the most urgent stage reached is
    ever sent, so a member caught up after downtime gets one DM rather than
    several back to back, and a stage already sent is never repeated.
    """
    left = deadline - now
    if left <= timedelta(0):
        return None
    reached = [day for day in reminder_days if left <= timedelta(days=day)]
    if not reached:
        return None
    most_urgent = min(reached)
    return None if most_urgent in sent else most_urgent


def decide(
    claims: dict[str, Any],
    roster: Any,
    domain_only: bool,
    existing_owner: str | None,
    discord_id: str | int,
) -> Outcome:
    """Apply the verification rules, in order.

    roster is anything supporting `in` (a set, or the Roster holder).
    existing_owner is the discord_id already holding this email, or None.
    """
    if not _is_true(claims.get("email_verified")):
        return Outcome.NOT_BU

    # A personal Gmail carries no hd claim at all, so this also covers absence.
    if claims.get("hd") != HD_DOMAIN:
        return Outcome.NOT_BU

    email = normalize_email(claims.get("email"))
    if not email or not email.endswith(f"@{HD_DOMAIN}"):
        return Outcome.NOT_BU

    if not domain_only and email not in roster:
        return Outcome.NOT_ON_ROSTER

    # Re-verifying your own address is allowed; it just re-applies the role.
    if existing_owner is not None and str(existing_owner) != str(discord_id):
        return Outcome.ALREADY_LINKED

    return Outcome.SUCCESS
