"""FastAPI callback server.

Runs on the same event loop as the bot, bound to 127.0.0.1. Caddy (or, during
development, your browser) is the only thing that talks to it.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from html import escape
from typing import Awaitable, Callable

import aiohttp
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from config import HD_DOMAIN, Config
from security import (
    GoogleError,
    GoogleOIDC,
    Outcome,
    StateExpired,
    StateInvalid,
    build_authorize_url,
    decide,
    read_state,
)
from store import Roster, Store, normalize_email

log = logging.getLogger("anticheat.web")

GrantRole = Callable[[str, str], Awaitable[bool]]

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ margin:0; min-height:100vh; display:flex; align-items:center;
         justify-content:center; padding:24px; box-sizing:border-box;
         font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;
         background:#f4f5f7; color:#1a1d21; position:relative; }}
  /* Sits inside the body's bottom padding, so it never covers the card. */
  .credit {{ position:absolute; right:14px; bottom:4px; font-size:12px;
             line-height:18px; opacity:.5; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background:#15171a; color:#e8eaed; }}
    .card {{ background:#1f2226 !important; border-color:#33373d !important; }}
    .note {{ background:#25282d !important; }}
  }}
  .card {{ max-width:460px; width:100%; background:#fff; border:1px solid #e1e4e8;
          border-radius:12px; padding:28px; box-sizing:border-box; }}
  h1 {{ margin:0 0 12px; font-size:20px; }}
  p {{ margin:0 0 12px; }}
  ul {{ margin:0 0 12px; padding-left:20px; }}
  .mark {{ font-size:28px; line-height:1; margin-bottom:8px; }}
  .note {{ background:#f0f2f5; border-radius:8px; padding:14px; font-size:14px; }}
  .btn {{ display:inline-block; margin-top:8px; padding:11px 18px; border-radius:8px;
         background:#1a73e8; color:#fff; text-decoration:none; font-weight:600; }}
  code {{ background:rgba(127,127,127,.18); padding:1px 5px; border-radius:4px; }}
</style></head>
<body><div class="card">{body}</div>
<footer class="credit">made by Exclar</footer></body></html>
"""


def render(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(PAGE.format(title=escape(title), body=body), status_code=status)


def _result(mark: str, heading: str, message: str, status: int = 200) -> HTMLResponse:
    return render(
        heading,
        f'<div class="mark">{mark}</div><h1>{escape(heading)}</h1><p>{message}</p>',
        status,
    )


# One page per outcome, as specified.
def page_success(email: str) -> HTMLResponse:
    return _result(
        "&#9989;",
        "You are verified",
        f"<code>{escape(email)}</code> is now linked to your Discord account and your "
        "role has been applied. You can close this tab and head back to the server."
        "<br><br>Changed your mind? Run <code>/unverify</code> in Discord to delete this link.",
    )


def page_not_bu() -> HTMLResponse:
    return _result(
        "&#9940;",
        "Not a Bicol University account",
        f"That sign-in was not a verified <code>@{HD_DOMAIN}</code> account. "
        "Personal Gmail addresses cannot be used. Start over with <code>/verify</code> "
        "and pick your school account.",
        status=403,
    )


def page_not_on_roster() -> HTMLResponse:
    return _result(
        "&#128203;",
        "Not on the roster",
        "Your school account checks out, but the address is not on the current org "
        "roster. If you have just joined or recently paid dues, ask an officer to add "
        "you, then run <code>/verify</code> again.",
        status=403,
    )


def page_already_linked() -> HTMLResponse:
    return _result(
        "&#128273;",
        "Email already linked",
        "That school email is already linked to a different Discord account. Each "
        "address can only verify one account. If this is a mistake, ask an officer "
        "to run <code>/ac revoke</code> on the old account.",
        status=409,
    )


def page_expired() -> HTMLResponse:
    return _result(
        "&#9203;",
        "This link expired",
        "Verification links are valid for 10 minutes. Run <code>/verify</code> in "
        "Discord to get a fresh one.",
        status=400,
    )


def page_invalid() -> HTMLResponse:
    return _result(
        "&#10060;",
        "Invalid link",
        "This link is not valid. Run <code>/verify</code> in Discord to get a new one.",
        status=400,
    )


def page_error() -> HTMLResponse:
    return _result(
        "&#9888;",
        "Something went wrong",
        "We could not finish verifying you. Please try <code>/verify</code> again, and "
        "tell an officer if it keeps happening.",
        status=502,
    )


def create_app(
    cfg: Config,
    store: Store,
    roster: Roster,
    oidc: GoogleOIDC,
    grant_role: GrantRole,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.http = aiohttp.ClientSession()
        try:
            yield
        finally:
            await app.state.http.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/login", response_class=HTMLResponse)
    async def login(request: Request) -> HTMLResponse:
        """Validate the signed state, then show the consent notice. The button
        carries the Google authorize URL, so nothing leaves the browser until
        the member has read what gets stored."""
        state = request.query_params.get("state", "")
        try:
            data = read_state(cfg.secret_key, state)
        except StateExpired:
            return page_expired()
        except StateInvalid:
            return page_invalid()

        authorize_url = build_authorize_url(
            cfg.google_client_id, cfg.redirect_uri, state, data["n"]
        )
        body = (
            "<h1>Verify your BU.gg membership</h1>"
            f"<p>You will sign in with your <code>@{HD_DOMAIN}</code> Google account "
            "to prove you are a current org member.</p>"
            '<div class="note"><strong>What we store</strong>'
            "<ul>"
            "<li>Your school email address</li>"
            "<li>Your name, as it appears on your Google account</li>"
            "<li>Your Discord user ID</li>"
            "<li>The date and time you verified</li>"
            "</ul>"
            "<p>Officers use your name to match your account against the org's "
            "membership records.</p>"
            "<p>That is all &mdash; we never see your password, and we do not read "
            "your mail, contacts or files.</p>"
            "<p><strong>Why:</strong> so officers can confirm the accounts in the "
            "server belong to real, current members.</p>"
            "<p><strong>Deleting it:</strong> run <code>/unverify</code> in Discord "
            "at any time and the record is removed immediately.</p></div>"
            f'<a class="btn" href="{escape(authorize_url, quote=True)}">Continue with Google</a>'
        )
        return render("Verify your BU.gg membership", body)

    @app.get("/callback", response_class=HTMLResponse)
    async def callback(request: Request) -> HTMLResponse:
        state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")
        error = request.query_params.get("error", "")

        try:
            data = read_state(cfg.secret_key, state)
        except StateExpired:
            store.log_attempt(None, Outcome.EXPIRED.value)
            log.info("verification attempt outcome=%s", Outcome.EXPIRED.value)
            return page_expired()
        except StateInvalid:
            store.log_attempt(None, Outcome.INVALID.value)
            log.info("verification attempt outcome=%s", Outcome.INVALID.value)
            return page_invalid()

        discord_id, guild_id, nonce = data["d"], data["g"], data["n"]

        def finish(outcome: Outcome) -> None:
            store.log_attempt(discord_id, outcome.value)
            log.info(
                "verification attempt discord_id=%s outcome=%s", discord_id, outcome.value
            )

        # The member declined at Google's consent screen, or Google refused.
        if error or not code:
            finish(Outcome.ERROR)
            return page_error()

        try:
            raw_id_token = await oidc.exchange_code(code, app.state.http)
            claims = await oidc.verify_id_token(raw_id_token, nonce, app.state.http)
        except GoogleError as exc:
            # exc carries a short reason code only, never token material.
            log.warning("google exchange failed reason=%s", exc)
            finish(Outcome.ERROR)
            return page_error()
        except Exception:
            log.exception("unexpected failure during google exchange")
            finish(Outcome.ERROR)
            return page_error()

        email = normalize_email(claims.get("email"))
        existing_owner = store.owner_of_email(email) if email else None
        outcome = decide(claims, roster, cfg.domain_only, existing_owner, discord_id)

        if outcome is not Outcome.SUCCESS:
            finish(outcome)
            return {
                Outcome.NOT_BU: page_not_bu,
                Outcome.NOT_ON_ROSTER: page_not_on_roster,
                Outcome.ALREADY_LINKED: page_already_linked,
            }[outcome]()

        # Write the link first: the UNIQUE index is the real guard against two
        # people racing for the same address.
        if not store.create_link(discord_id, email, guild_id, claims.get("name")):
            finish(Outcome.ALREADY_LINKED)
            return page_already_linked()

        try:
            granted = await grant_role(guild_id, discord_id)
        except Exception:
            log.exception("role assignment failed discord_id=%s", discord_id)
            granted = False

        if not granted:
            # The link is stored but the role did not land -- usually the bot's
            # role sits below VERIFIED_ROLE_ID. Say so rather than claiming success.
            finish(Outcome.ERROR)
            return _result(
                "&#9888;",
                "Verified, but the role did not apply",
                "Your account is linked, but we could not assign the role. Ask an "
                "officer to check that the bot's role sits above the verified role.",
                status=500,
            )

        finish(Outcome.SUCCESS)
        return page_success(email)

    return app
