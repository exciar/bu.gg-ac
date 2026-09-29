"""Entry point: one process, one event loop, both the bot and the web server.

The web callback needs to assign Discord roles, and the bot needs to hand out
links the web server will validate. Running them on the same loop means the
callback can simply await the Discord call -- no queue, no thread hand-off.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

import uvicorn

from bot import AntiCheatBot, grant_verified_role
from config import ConfigError, load_config
from security import GoogleOIDC
from store import Roster, Store
from web import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("anticheat")


async def run() -> None:
    cfg = load_config()

    store = Store(cfg.db_path)
    roster = Roster(cfg.roster_path)
    if cfg.domain_only:
        log.warning(
            "ROSTER_MODE=domain_only: any verified @%s account will be accepted",
            "bicol-u.edu.ph",
        )
    else:
        count = roster.reload()
        log.info("roster loaded: %d emails from %s", count, cfg.roster_path)

    bot = AntiCheatBot(cfg, store, roster)
    oidc = GoogleOIDC(cfg.google_client_id, cfg.google_client_secret, cfg.redirect_uri)

    async def grant_role(guild_id: str, discord_id: str) -> bool:
        return await grant_verified_role(bot, guild_id, discord_id)

    app = create_app(cfg, store, roster, oidc, grant_role)

    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",  # Caddy terminates TLS and proxies in; never public.
            port=cfg.port,
            log_level="info",
            # uvicorn's access log prints the full path including the query
            # string, which would write OAuth codes and state tokens into the
            # journal. The app logs its own sanitized line instead.
            access_log=False,
        )
    )

    stopping = asyncio.Event()

    def request_stop() -> None:
        if not stopping.is_set():
            log.info("shutdown requested")
            stopping.set()
            server.should_exit = True

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, request_stop)
        except NotImplementedError:
            # Windows: no add_signal_handler. KeyboardInterrupt is caught below.
            signal.signal(sig, lambda *_: request_stop())

    log.info("callback server on http://127.0.0.1:%d (public base: %s)", cfg.port, cfg.base_url)

    async with bot:
        tasks = [
            asyncio.create_task(server.serve(), name="uvicorn"),
            asyncio.create_task(bot.start(cfg.discord_token), name="discord"),
        ]
        try:
            # If either half dies, take the whole service down so systemd
            # restarts it, rather than limping along half-working.
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                if task.exception() is not None:
                    raise task.exception()
        finally:
            request_stop()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            store.close()
            log.info("stopped")


def cli() -> int:
    try:
        asyncio.run(run())
    except ConfigError as exc:
        log.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(cli())
