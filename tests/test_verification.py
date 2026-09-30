"""Verification rules, storage constraints, and the callback flow.

Google is mocked by signing ID tokens with a locally generated RSA key and
serving the matching JWKS from a fake aiohttp session. Discord is mocked by a
recording stand-in for the role assignment. Nothing here touches the network.
"""

from __future__ import annotations

import sqlite3
import time

import pytest
from joserfc import jwt as jose_jwt
from joserfc.jwk import KeySet, RSAKey

from config import Config
from security import GoogleError, GoogleOIDC, Outcome, decide, make_state, read_state
from store import Store
from web import create_app

CLIENT_ID = "test-client-id.apps.googleusercontent.com"
SECRET = "test-secret-not-a-real-key"
BU = "bicol-u.edu.ph"
ROSTER = {"juan@bicol-u.edu.ph", "maria@bicol-u.edu.ph"}


def claims(**overrides):
    base = {
        "email": "juan@bicol-u.edu.ph",
        "email_verified": True,
        "hd": BU,
        "sub": "google-subject-1",
    }
    base.update(overrides)
    return base


# --- decide(): the verification rules ------------------------------------


@pytest.mark.parametrize(
    "given, expected",
    [
        pytest.param(claims(), Outcome.SUCCESS, id="happy-path"),
        pytest.param(
            claims(email_verified=False), Outcome.NOT_BU, id="email_verified-false"
        ),
        pytest.param(
            claims(email_verified=None), Outcome.NOT_BU, id="email_verified-missing"
        ),
        pytest.param(claims(hd="gmail.com"), Outcome.NOT_BU, id="wrong-hd"),
        pytest.param(claims(hd=None), Outcome.NOT_BU, id="hd-absent-personal-gmail"),
        pytest.param(
            claims(hd="bicol-u.edu.ph.evil.com"), Outcome.NOT_BU, id="hd-lookalike"
        ),
        pytest.param(
            claims(email="juan@evil.com"), Outcome.NOT_BU, id="email-domain-mismatch"
        ),
        pytest.param(claims(email=None), Outcome.NOT_BU, id="email-missing"),
        pytest.param(
            claims(email="nobody@bicol-u.edu.ph"),
            Outcome.NOT_ON_ROSTER,
            id="not-on-roster",
        ),
        pytest.param(
            claims(email_verified="true"), Outcome.SUCCESS, id="email_verified-string"
        ),
        pytest.param(
            claims(email="  JUAN@Bicol-U.EDU.PH  "),
            Outcome.SUCCESS,
            id="roster-match-is-normalized",
        ),
    ],
)
def test_decide_rules(given, expected):
    assert decide(given, ROSTER, False, None, "555") is expected


def test_domain_only_skips_the_roster_check():
    off_roster = claims(email="nobody@bicol-u.edu.ph")
    assert decide(off_roster, ROSTER, False, None, "555") is Outcome.NOT_ON_ROSTER
    assert decide(off_roster, ROSTER, True, None, "555") is Outcome.SUCCESS


def test_domain_only_still_requires_a_verified_bu_account():
    # domain_only relaxes the roster, never the domain or email_verified rules.
    assert decide(claims(hd="gmail.com"), ROSTER, True, None, "555") is Outcome.NOT_BU
    assert (
        decide(claims(email_verified=False), ROSTER, True, None, "555") is Outcome.NOT_BU
    )


def test_email_already_linked_to_another_discord_account():
    assert decide(claims(), ROSTER, False, "999", "555") is Outcome.ALREADY_LINKED


def test_reverifying_your_own_email_is_allowed():
    assert decide(claims(), ROSTER, False, "555", "555") is Outcome.SUCCESS
    # Discord IDs arrive as int in some paths and str in others.
    assert decide(claims(), ROSTER, False, "555", 555) is Outcome.SUCCESS


# --- storage constraints -------------------------------------------------


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "test.db")
    yield s
    s.close()


def test_link_is_stored_and_found_by_email(store):
    assert store.create_link("555", "Juan@Bicol-U.edu.ph", "777") is True
    assert store.owner_of_email("juan@bicol-u.edu.ph") == "555"
    row = store.link_for_discord("555")
    assert row["email"] == "juan@bicol-u.edu.ph"  # stored normalized
    assert row["verified_at"]


def test_one_email_cannot_link_to_a_second_discord_account(store):
    assert store.create_link("555", "juan@bicol-u.edu.ph", "777") is True
    assert store.create_link("666", "juan@bicol-u.edu.ph", "777") is False
    assert store.owner_of_email("juan@bicol-u.edu.ph") == "555"


def test_unique_constraint_exists_at_the_schema_level(store):
    store.create_link("555", "juan@bicol-u.edu.ph", "777")
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute(
            "INSERT INTO links (discord_id, email, guild_id, verified_at) "
            "VALUES (?, ?, ?, ?)",
            ("666", "juan@bicol-u.edu.ph", "777", "now"),
        )


def test_reverifying_updates_rather_than_duplicates(store):
    store.create_link("555", "juan@bicol-u.edu.ph", "777")
    assert store.create_link("555", "juan@bicol-u.edu.ph", "777") is True
    assert store.conn.execute("SELECT COUNT(*) AS n FROM links").fetchone()["n"] == 1


def test_unverify_deletes_the_row(store):
    store.create_link("555", "juan@bicol-u.edu.ph", "777")
    assert store.delete_link("555") is True
    assert store.link_for_discord("555") is None
    assert store.owner_of_email("juan@bicol-u.edu.ph") is None
    assert store.delete_link("555") is False


def test_full_name_is_stored_and_returned(store):
    store.create_link("555", "juan@bicol-u.edu.ph", "777", "Juan Dela Cruz")
    assert store.link_for_discord("555")["full_name"] == "Juan Dela Cruz"


def test_missing_or_blank_name_is_stored_as_null(store):
    store.create_link("555", "juan@bicol-u.edu.ph", "777", None)
    store.create_link("666", "maria@bicol-u.edu.ph", "777", "   ")
    assert store.link_for_discord("555")["full_name"] is None
    assert store.link_for_discord("666")["full_name"] is None


def test_reverifying_refreshes_a_changed_name(store):
    store.create_link("555", "juan@bicol-u.edu.ph", "777", "Juan Dela Cruz")
    store.create_link("555", "juan@bicol-u.edu.ph", "777", "Juan Dela Cruz Jr")
    assert store.link_for_discord("555")["full_name"] == "Juan Dela Cruz Jr"


def test_all_links_sorts_by_name_falling_back_to_email(store):
    store.create_link("1", "zeta@bicol-u.edu.ph", "777", "Ana Reyes")
    store.create_link("2", "alpha@bicol-u.edu.ph", "777", None)  # sorts on email
    store.create_link("3", "mid@bicol-u.edu.ph", "777", "bea santos")  # case-insensitive
    order = [(r["full_name"], r["email"]) for r in store.all_links()]
    assert order == [
        (None, "alpha@bicol-u.edu.ph"),  # no name, sorts on its email
        ("Ana Reyes", "zeta@bicol-u.edu.ph"),
        ("bea santos", "mid@bicol-u.edu.ph"),  # lowercase still sorts after "Ana"
    ]


def test_database_from_an_earlier_version_gains_the_name_column(tmp_path):
    """A DB created before full_name existed must migrate, not crash."""
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(
        "CREATE TABLE links (discord_id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,"
        " guild_id TEXT NOT NULL, verified_at TEXT NOT NULL);"
        "CREATE TABLE attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, discord_id TEXT,"
        " outcome TEXT NOT NULL, created_at TEXT NOT NULL);"
    )
    old.execute(
        "INSERT INTO links VALUES ('555','juan@bicol-u.edu.ph','777','2026-01-01T00:00:00+00:00')"
    )
    old.commit()
    old.close()

    s = Store(path)
    try:
        row = s.link_for_discord("555")
        assert row["email"] == "juan@bicol-u.edu.ph"
        assert row["full_name"] is None  # pre-existing row, no name recorded
        s.create_link("666", "maria@bicol-u.edu.ph", "777", "Maria Santos")
        assert s.link_for_discord("666")["full_name"] == "Maria Santos"
    finally:
        s.close()


def test_unverify_anonymizes_that_members_audit_rows(store):
    store.log_attempt("555", Outcome.SUCCESS.value)
    store.log_attempt("555", Outcome.NOT_ON_ROSTER.value)
    store.log_attempt("555", "unverify")
    store.log_attempt("666", Outcome.SUCCESS.value)  # a different member

    scrubbed = store.anonymize_attempts("555")
    assert scrubbed == 3

    rows = list(store.conn.execute("SELECT discord_id, outcome FROM attempts"))
    # Nothing ties any row back to 555 any more...
    assert all(r["discord_id"] != "555" for r in rows)
    # ...but the outcomes survive, so /ac stats stays accurate...
    verified, by_outcome = store.stats()
    counts = {r["outcome"]: r["n"] for r in by_outcome}
    assert counts == {"success": 2, "not_on_roster": 1, "unverify": 1}
    # ...and other members are untouched.
    assert sum(1 for r in rows if r["discord_id"] == "666") == 1


def test_anonymize_is_idempotent_and_safe_for_unknown_ids(store):
    store.log_attempt("555", Outcome.SUCCESS.value)
    assert store.anonymize_attempts("555") == 1
    assert store.anonymize_attempts("555") == 0
    assert store.anonymize_attempts("nobody") == 0


def test_attempts_are_logged_without_secrets(store):
    store.log_attempt("555", Outcome.SUCCESS.value)
    store.log_attempt("555", Outcome.NOT_BU.value)
    store.log_attempt(None, Outcome.EXPIRED.value)
    verified, by_outcome = store.stats()
    assert verified == 0
    counts = {row["outcome"]: row["n"] for row in by_outcome}
    assert counts == {"success": 1, "not_bu": 1, "expired": 1}

    columns = {r[1] for r in store.conn.execute("PRAGMA table_info(attempts)")}
    # No column exists that could hold a token, code or email.
    assert columns == {"id", "discord_id", "outcome", "created_at"}


# --- Google, mocked ------------------------------------------------------


@pytest.fixture(scope="module")
def signing_key():
    return RSAKey.generate_key(2048, parameters={"kid": "test-1", "use": "sig", "alg": "RS256"})


@pytest.fixture(scope="module")
def jwks(signing_key):
    return KeySet([signing_key]).as_dict(private=False)


def sign_id_token(key, **overrides):
    now = int(time.time())
    payload = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "sub": "google-subject-1",
        "email": "juan@bicol-u.edu.ph",
        "email_verified": True,
        "hd": BU,
        "nonce": "nonce-1",
        "iat": now,
        "exp": now + 3600,
    }
    payload.update(overrides)
    return jose_jwt.encode({"alg": "RS256", "kid": "test-1"}, payload, key)


class FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self._payload = payload

    async def json(self, content_type=None):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeGoogle:
    """Stands in for aiohttp.ClientSession pointed at Google."""

    def __init__(self, jwks, id_token=None, token_status=200, token_payload=None):
        self.jwks = jwks
        self.id_token = id_token
        self.token_status = token_status
        self.token_payload = token_payload
        self.posts = []
        self.jwks_fetches = 0

    def post(self, url, data=None):
        self.posts.append((url, data))
        if self.token_payload is not None:
            return FakeResponse(self.token_status, self.token_payload)
        return FakeResponse(self.token_status, {"id_token": self.id_token})

    def get(self, url):
        self.jwks_fetches += 1
        return FakeResponse(200, self.jwks)


def oidc():
    return GoogleOIDC(CLIENT_ID, "test-client-secret", "http://localhost:8000/callback")


async def test_valid_id_token_is_accepted(signing_key, jwks):
    session = FakeGoogle(jwks, id_token=sign_id_token(signing_key))
    client = oidc()
    raw = await client.exchange_code("auth-code", session)
    got = await client.verify_id_token(raw, "nonce-1", session)
    assert got["email"] == "juan@bicol-u.edu.ph"
    assert got["hd"] == BU


async def test_nonce_mismatch_is_rejected(signing_key, jwks):
    session = FakeGoogle(jwks, id_token=sign_id_token(signing_key, nonce="someone-elses"))
    with pytest.raises(GoogleError, match="nonce_mismatch"):
        await oidc().verify_id_token(session.id_token, "nonce-1", session)


async def test_token_for_another_audience_is_rejected(signing_key, jwks):
    session = FakeGoogle(jwks, id_token=sign_id_token(signing_key, aud="some-other-app"))
    with pytest.raises(GoogleError):
        await oidc().verify_id_token(session.id_token, "nonce-1", session)


async def test_expired_id_token_is_rejected(signing_key, jwks):
    stale = sign_id_token(signing_key, exp=int(time.time()) - 3600)
    session = FakeGoogle(jwks, id_token=stale)
    with pytest.raises(GoogleError):
        await oidc().verify_id_token(stale, "nonce-1", session)


async def test_token_from_the_wrong_issuer_is_rejected(signing_key, jwks):
    bad = sign_id_token(signing_key, iss="https://evil.example.com")
    session = FakeGoogle(jwks, id_token=bad)
    with pytest.raises(GoogleError):
        await oidc().verify_id_token(bad, "nonce-1", session)


async def test_token_signed_by_a_stranger_is_rejected(jwks):
    other = RSAKey.generate_key(2048, parameters={"kid": "test-1", "use": "sig", "alg": "RS256"})
    forged = sign_id_token(other)
    session = FakeGoogle(jwks, id_token=forged)
    with pytest.raises(GoogleError):
        await oidc().verify_id_token(forged, "nonce-1", session)


async def test_failed_exchange_surfaces_only_a_short_code(jwks):
    session = FakeGoogle(
        jwks,
        token_status=400,
        token_payload={"error": "invalid_grant", "error_description": "Bad Request"},
    )
    with pytest.raises(GoogleError) as excinfo:
        await oidc().exchange_code("used-already", session)
    assert str(excinfo.value) == "invalid_grant"


async def test_jwks_is_cached_between_verifications(signing_key, jwks):
    session = FakeGoogle(jwks, id_token=sign_id_token(signing_key))
    client = oidc()
    await client.verify_id_token(session.id_token, "nonce-1", session)
    await client.verify_id_token(session.id_token, "nonce-1", session)
    assert session.jwks_fetches == 1


# --- the callback route, with Google and Discord both mocked -------------


def make_config(tmp_path, roster_mode="roster"):
    return Config(
        discord_token="not-a-real-token",
        guild_id=777,
        verified_role_id=888,
        admin_role_ids=frozenset({999}),
        google_client_id=CLIENT_ID,
        google_client_secret="test-client-secret",
        base_url="http://localhost:8000",
        secret_key=SECRET,
        roster_path=str(tmp_path / "roster.csv"),
        roster_mode=roster_mode,
        db_path=str(tmp_path / "test.db"),
        port=8000,
        kick_after_days=14,
        exempt_role_ids=frozenset(),
        reminder_days=(7, 3, 1),
    )


class FakeDiscord:
    """Records role grants instead of calling Discord."""

    def __init__(self, succeed=True):
        self.granted = []
        self.succeed = succeed

    async def grant(self, guild_id, discord_id):
        self.granted.append((str(guild_id), str(discord_id)))
        return self.succeed


async def call(app, path, query):
    """Drive the ASGI app directly -- no HTTP client dependency."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query.encode(),
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 8000),
    }
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, body.decode()


@pytest.fixture()
def flow(tmp_path, jwks):
    """Wire the app together with fake Google and fake Discord."""
    cfg = make_config(tmp_path)
    store = Store(cfg.db_path)
    discord = FakeDiscord()
    session = FakeGoogle(jwks)
    client = oidc()
    app = create_app(cfg, store, ROSTER, client, discord.grant)
    app.state.http = session  # lifespan does not run under direct ASGI calls
    yield cfg, store, session, discord, app
    store.close()


async def test_callback_success_assigns_role_and_stores_link(flow, signing_key):
    cfg, store, session, discord, app = flow
    state = make_state(SECRET, "555", "777")
    session.id_token = sign_id_token(
        signing_key, nonce=read_state(SECRET, state)["n"]
    )

    status, body = await call(app, "/callback", f"state={state}&code=auth-code")

    assert status == 200
    assert "verified" in body.lower()
    assert discord.granted == [("777", "555")]
    assert store.link_for_discord("555")["email"] == "juan@bicol-u.edu.ph"


async def test_callback_stores_the_google_name(flow, signing_key):
    cfg, store, session, discord, app = flow
    state = make_state(SECRET, "555", "777")
    session.id_token = sign_id_token(
        signing_key, nonce=read_state(SECRET, state)["n"], name="Juan Dela Cruz"
    )

    status, _ = await call(app, "/callback", f"state={state}&code=auth-code")

    assert status == 200
    assert store.link_for_discord("555")["full_name"] == "Juan Dela Cruz"


async def test_consent_page_discloses_that_the_name_is_stored(flow):
    cfg, store, session, discord, app = flow
    state = make_state(SECRET, "555", "777")
    _, body = await call(app, "/login", f"state={state}")
    # The notice must match what the callback actually writes.
    assert "name" in body.lower()
    assert "Google account" in body


async def test_callback_rejects_off_roster_without_touching_discord(flow, signing_key):
    cfg, store, session, discord, app = flow
    state = make_state(SECRET, "555", "777")
    nonce = read_state(SECRET, state)["n"]
    session.id_token = sign_id_token(
        signing_key, nonce=nonce, email="stranger@bicol-u.edu.ph"
    )

    status, body = await call(app, "/callback", f"state={state}&code=auth-code")

    assert status == 403
    assert "roster" in body.lower()
    assert discord.granted == []
    assert store.link_for_discord("555") is None


async def test_callback_rejects_personal_gmail(flow, signing_key):
    cfg, store, session, discord, app = flow
    state = make_state(SECRET, "555", "777")
    nonce = read_state(SECRET, state)["n"]
    session.id_token = sign_id_token(
        signing_key, nonce=nonce, hd=None, email="someone@gmail.com"
    )

    status, body = await call(app, "/callback", f"state={state}&code=auth-code")

    assert status == 403
    assert "bicol university" in body.lower()
    assert discord.granted == []


async def test_callback_rejects_an_email_already_linked(flow, signing_key):
    cfg, store, session, discord, app = flow
    store.create_link("111", "juan@bicol-u.edu.ph", "777")

    state = make_state(SECRET, "555", "777")
    nonce = read_state(SECRET, state)["n"]
    session.id_token = sign_id_token(signing_key, nonce=nonce)

    status, body = await call(app, "/callback", f"state={state}&code=auth-code")

    assert status == 409
    assert "already linked" in body.lower()
    assert discord.granted == []
    assert store.owner_of_email("juan@bicol-u.edu.ph") == "111"


async def test_callback_rejects_an_expired_link(flow, monkeypatch, signing_key):
    import itsdangerous.timed

    cfg, store, session, discord, app = flow
    state = make_state(SECRET, "555", "777")
    session.id_token = sign_id_token(signing_key)

    real_time = itsdangerous.timed.time.time
    monkeypatch.setattr(itsdangerous.timed.time, "time", lambda: real_time() + 601)

    status, body = await call(app, "/callback", f"state={state}&code=auth-code")

    assert status == 400
    assert "expired" in body.lower()
    assert discord.granted == []


async def test_callback_rejects_a_forged_state(flow):
    cfg, store, session, discord, app = flow
    status, body = await call(app, "/callback", "state=forged&code=auth-code")
    assert status == 400
    assert discord.granted == []


async def test_login_page_shows_the_consent_notice(flow):
    cfg, store, session, discord, app = flow
    state = make_state(SECRET, "555", "777")
    status, body = await call(app, "/login", f"state={state}")

    assert status == 200
    assert "What we store" in body
    assert "/unverify" in body
    assert "Discord user ID" in body
    # The button must point at Google with the hd hint.
    assert "accounts.google.com/o/oauth2/v2/auth" in body
    assert "hd=bicol-u.edu.ph" in body


async def test_login_page_rejects_an_expired_link(flow, monkeypatch):
    import itsdangerous.timed

    cfg, store, session, discord, app = flow
    state = make_state(SECRET, "555", "777")
    real_time = itsdangerous.timed.time.time
    monkeypatch.setattr(itsdangerous.timed.time, "time", lambda: real_time() + 601)

    status, body = await call(app, "/login", f"state={state}")
    assert status == 400
    assert "expired" in body.lower()


def test_every_page_carries_the_credit():
    from web import page_error, page_expired, page_not_bu, page_success, render

    pages = [
        render("Verify your BU.gg membership", "<h1>consent</h1>"),
        page_success("juan@bicol-u.edu.ph"),
        page_not_bu(),
        page_expired(),
        page_error(),
    ]
    for page in pages:
        assert '<footer class="credit">made by Exclar</footer>' in page.body.decode()
