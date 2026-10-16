"""Reading officer roles and reminder stages from the environment."""

from __future__ import annotations

import pytest

import config
from config import ConfigError, load_config

BASE_ENV = {
    "DISCORD_TOKEN": "t",
    "GUILD_ID": "1",
    "VERIFIED_ROLE_ID": "2",
    "GOOGLE_CLIENT_ID": "c",
    "GOOGLE_CLIENT_SECRET": "s",
    "BASE_URL": "http://localhost:8000",
    "SECRET_KEY": "k",
}
OPTIONAL = ["ADMIN_ROLE_ID", "ADMIN_ROLE_IDS", "REMINDER_DAYS", "KICK_AFTER_DAYS",
            "EXISTING_KICK_AFTER_DAYS", "EXEMPT_ROLE_IDS", "ROSTER_MODE",
            "ROSTER_PATH", "PORT", "DB_PATH"]


@pytest.fixture()
def env(monkeypatch):
    """A clean environment; the developer's real .env is never read."""
    monkeypatch.setattr(config, "load_dotenv", lambda *a, **k: None)
    for name in OPTIONAL:
        monkeypatch.delenv(name, raising=False)
    for name, value in BASE_ENV.items():
        monkeypatch.setenv(name, value)
    return monkeypatch


def test_officer_roles_come_from_a_comma_separated_list(env):
    env.setenv("ADMIN_ROLE_IDS", "10, 20,30")
    assert load_config().admin_role_ids == frozenset({10, 20, 30})


def test_the_single_legacy_admin_role_still_works(env):
    env.setenv("ADMIN_ROLE_ID", "10")
    assert load_config().admin_role_ids == frozenset({10})


def test_both_admin_settings_are_combined(env):
    env.setenv("ADMIN_ROLE_ID", "10")
    env.setenv("ADMIN_ROLE_IDS", "20,30")
    assert load_config().admin_role_ids == frozenset({10, 20, 30})


def test_no_officer_role_at_all_fails_loudly(env):
    with pytest.raises(ConfigError, match="ADMIN_ROLE_IDS"):
        load_config()


def test_a_malformed_officer_role_fails_loudly(env):
    env.setenv("ADMIN_ROLE_IDS", "10,President")
    with pytest.raises(ConfigError, match="ADMIN_ROLE_IDS"):
        load_config()


def test_reminders_default_to_seven_three_and_one_day_left(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    assert load_config().reminder_days == (7, 3, 1)


def test_reminder_days_are_configurable(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    env.setenv("REMINDER_DAYS", "1, 5")
    assert load_config().reminder_days == (5, 1)


def test_grace_periods_default_to_three_days_new_and_fourteen_existing(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    cfg = load_config()
    assert (cfg.kick_after_days, cfg.existing_kick_after_days) == (3, 14)


def test_malformed_grace_periods_fail_loudly(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    for name in ("KICK_AFTER_DAYS", "EXISTING_KICK_AFTER_DAYS"):
        for bad in ("soon", "0"):
            env.setenv(name, bad)
            with pytest.raises(ConfigError, match=name):
                load_config()
        env.delenv(name)


def test_reminders_can_be_switched_off(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    env.setenv("REMINDER_DAYS", "")
    assert load_config().reminder_days == ()


def test_malformed_reminder_days_fail_loudly(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    for bad in ("soon", "3,-1", "0"):
        env.setenv("REMINDER_DAYS", bad)
        with pytest.raises(ConfigError, match="REMINDER_DAYS"):
            load_config()
