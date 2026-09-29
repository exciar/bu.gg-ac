"""SQLite storage and the in-memory roster.

Every query is parameterized. The schema enforces the one-email-one-account
rule at the database level, so two callbacks racing on the same address fail
closed on IntegrityError rather than relying on a check-then-insert.
"""

from __future__ import annotations

import csv
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS links (
    discord_id  TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    guild_id    TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    full_name   TEXT
);

CREATE TABLE IF NOT EXISTS attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id TEXT,
    outcome    TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attempts_outcome ON attempts(outcome);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# Set when officers run /ac enforce start. Absent means enforcement is off, so
# a fresh database can never kick anyone.
ENFORCEMENT_KEY = "enforcement_started_at"


def normalize_email(raw: str | None) -> str:
    """Trim and lowercase. Applied to both roster rows and Google claims so the
    two are always compared in the same shape."""
    return (raw or "").strip().lower()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_roster(path: str | Path) -> set[str]:
    """Read the officer-maintained CSV into a set of normalized addresses.

    Tolerates a UTF-8 BOM (Excel writes one), stray whitespace, blank rows and
    a differently-cased 'Email' header.
    """
    emails: set[str] = set()
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        key = next(
            (name for name in fieldnames if (name or "").strip().lower() == "email"),
            None,
        )
        if key is None:
            raise ValueError(
                f"{path} has no 'email' column (found: {fieldnames or 'nothing'})."
            )
        for row in reader:
            email = normalize_email(row.get(key))
            if email:
                emails.add(email)
    return emails


class Roster:
    """Holds the roster so the web and bot layers share one reloadable copy."""

    def __init__(self, path: str | Path) -> None:
        self.path = path
        self.emails: set[str] = set()

    def reload(self) -> int:
        """Swap in a freshly parsed set only once parsing has succeeded, so a
        malformed CSV leaves the working roster untouched."""
        self.emails = load_roster(self.path)
        return len(self.emails)

    def __contains__(self, email: str) -> bool:
        return email in self.emails

    def __len__(self) -> int:
        return len(self.emails)


class Store:
    def __init__(self, db_path: str | Path) -> None:
        # check_same_thread=False: uvicorn and discord.py share one event loop,
        # but discord.py's internals may touch the connection from a helper
        # thread during shutdown.
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns that CREATE TABLE IF NOT EXISTS would skip on a database
        created by an earlier version."""
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(links)")}
        if "full_name" not in columns:
            self.conn.execute("ALTER TABLE links ADD COLUMN full_name TEXT")
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # --- links -----------------------------------------------------------

    def link_for_discord(self, discord_id: str | int) -> sqlite3.Row | None:
        cur = self.conn.execute(
            "SELECT discord_id, email, guild_id, verified_at, full_name "
            "FROM links WHERE discord_id = ?",
            (str(discord_id),),
        )
        return cur.fetchone()

    def all_links(self) -> list[sqlite3.Row]:
        """Every verified member, for the officer roster export. Sorted by the
        name Google gave us, falling back to the email for older records."""
        return self.conn.execute(
            "SELECT discord_id, email, guild_id, verified_at, full_name "
            "FROM links ORDER BY COALESCE(NULLIF(full_name, ''), email) COLLATE NOCASE"
        ).fetchall()

    def owner_of_email(self, email: str) -> str | None:
        """Return the discord_id already holding this address, if any."""
        cur = self.conn.execute(
            "SELECT discord_id FROM links WHERE email = ?", (normalize_email(email),)
        )
        row = cur.fetchone()
        return row["discord_id"] if row else None

    def create_link(
        self,
        discord_id: str | int,
        email: str,
        guild_id: str | int,
        full_name: str | None = None,
    ) -> bool:
        """Insert or refresh a link. Returns False if the address belongs to a
        different Discord account (UNIQUE violation)."""
        try:
            self.conn.execute(
                "INSERT INTO links (discord_id, email, guild_id, verified_at, full_name) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(discord_id) DO UPDATE SET "
                "  email = excluded.email, "
                "  guild_id = excluded.guild_id, "
                "  verified_at = excluded.verified_at, "
                "  full_name = excluded.full_name",
                (
                    str(discord_id),
                    normalize_email(email),
                    str(guild_id),
                    _utcnow(),
                    (full_name or "").strip() or None,
                ),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            self.conn.rollback()
            return False

    def delete_link(self, discord_id: str | int) -> bool:
        cur = self.conn.execute(
            "DELETE FROM links WHERE discord_id = ?", (str(discord_id),)
        )
        self.conn.commit()
        return cur.rowcount > 0

    # --- audit log -------------------------------------------------------

    def log_attempt(self, discord_id: str | int | None, outcome: str) -> None:
        """Record one verification attempt. Never called with a token, code or
        email -- only the Discord ID, the outcome and the time."""
        self.conn.execute(
            "INSERT INTO attempts (discord_id, outcome, created_at) VALUES (?, ?, ?)",
            (None if discord_id is None else str(discord_id), outcome, _utcnow()),
        )
        self.conn.commit()

    def anonymize_attempts(self, discord_id: str | int) -> int:
        """Drop the Discord ID from this member's audit rows, keeping the
        outcomes. Called on /unverify so the member leaves no identifier behind
        while /ac stats counts stay accurate."""
        cur = self.conn.execute(
            "UPDATE attempts SET discord_id = NULL WHERE discord_id = ?",
            (str(discord_id),),
        )
        self.conn.commit()
        return cur.rowcount

    # --- enforcement toggle ---------------------------------------------

    def get_enforcement_start(self) -> datetime | None:
        """When officers started the kick clock, or None if enforcement is off."""
        row = self.conn.execute(
            "SELECT value FROM settings WHERE key = ?", (ENFORCEMENT_KEY,)
        ).fetchone()
        if row is None or not row["value"]:
            return None
        return datetime.fromisoformat(row["value"])

    def set_enforcement_start(self, when: datetime | None) -> None:
        """Pass a timestamp to start the clock, or None to turn enforcement off."""
        if when is None:
            self.conn.execute("DELETE FROM settings WHERE key = ?", (ENFORCEMENT_KEY,))
        else:
            self.conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (ENFORCEMENT_KEY, when.isoformat()),
            )
        self.conn.commit()

    def stats(self) -> tuple[int, list[sqlite3.Row]]:
        verified = self.conn.execute("SELECT COUNT(*) AS n FROM links").fetchone()["n"]
        by_outcome = self.conn.execute(
            "SELECT outcome, COUNT(*) AS n FROM attempts GROUP BY outcome ORDER BY n DESC"
        ).fetchall()
        return verified, by_outcome
