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
            "EXISTING_KICK_AFTER_DAYS", "EXEMPT_ROLE_IDS", "NO_KICK_ROLE_IDS",
            "ROSTER_MODE", "ROSTER_PATH", "PORT", "DB_PATH",
            "SCAM_ENABLED", "SCAM_DRY_RUN", "SCAM_LOG_CHANNEL_ID", "SCAM_ACTION",
            "SCAM_TIMEOUT_HOURS", "SCAM_BURST_WINDOW_SECONDS", "SCAM_BURST_MIN_CHANNELS",
            "SCAM_MIN_IMAGES", "SCAM_MAX_IMAGES", "SCAM_MAX_TEXT_CHARS", "SCAM_FLAG_SCORE",
            "SCAM_CONFIRM_SCORE", "SCAM_OCR_MIN_KEYWORDS", "SCAM_HASH_MAX_DISTANCE",
            "SCAM_EXEMPT_ROLE_IDS", "SCAM_EXEMPT_CHANNEL_IDS"]


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


def test_no_kick_roles_are_optional_and_comma_separated(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    assert load_config().no_kick_role_ids == frozenset()
    env.setenv("NO_KICK_ROLE_IDS", "40, 41")
    assert load_config().no_kick_role_ids == frozenset({40, 41})


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


# --- anti-scam -----------------------------------------------------------


def test_anti_scam_is_off_and_in_dry_run_by_default(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    scam = load_config().scam
    assert scam.enabled is False
    assert scam.dry_run is True
    assert scam.action == "timeout"
    assert (scam.timeout_hours, scam.burst_window_seconds, scam.burst_min_channels) == (24, 60, 2)
    assert (scam.min_images, scam.max_images, scam.max_text_chars) == (2, 4, 15)
    assert (scam.flag_score, scam.confirm_score) == (3, 10)
    assert (scam.ocr_min_keywords, scam.hash_max_distance) == (2, 10)


def test_enabling_anti_scam_needs_a_log_channel(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    env.setenv("SCAM_ENABLED", "true")
    with pytest.raises(ConfigError, match="SCAM_LOG_CHANNEL_ID"):
        load_config()
    env.setenv("SCAM_LOG_CHANNEL_ID", "555")
    scam = load_config().scam
    assert (scam.enabled, scam.log_channel_id) == (True, 555)


def test_anti_scam_settings_are_read(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    for name, value in {
        "SCAM_DRY_RUN": "off", "SCAM_ACTION": "Softban", "SCAM_TIMEOUT_HOURS": "48",
        "SCAM_EXEMPT_ROLE_IDS": "1,2", "SCAM_EXEMPT_CHANNEL_IDS": "3",
    }.items():
        env.setenv(name, value)
    scam = load_config().scam
    assert scam.dry_run is False
    assert scam.action == "softban"
    assert scam.timeout_hours == 48
    assert scam.exempt_role_ids == frozenset({1, 2})
    assert scam.exempt_channel_ids == frozenset({3})


def test_malformed_anti_scam_settings_fail_loudly(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    for name, bad in [
        ("SCAM_ENABLED", "maybe"),
        ("SCAM_ACTION", "ban"),
        ("SCAM_TIMEOUT_HOURS", "0"),
        ("SCAM_TIMEOUT_HOURS", "673"),  # Discord caps timeouts at 28 days
        ("SCAM_BURST_MIN_CHANNELS", "1"),
        ("SCAM_HASH_MAX_DISTANCE", "lots"),
    ]:
        env.setenv(name, bad)
        with pytest.raises(ConfigError, match=name):
            load_config()
        env.delenv(name)


def test_anti_scam_thresholds_must_be_consistent(env):
    env.setenv("ADMIN_ROLE_IDS", "10")
    env.setenv("SCAM_MIN_IMAGES", "3")
    env.setenv("SCAM_MAX_IMAGES", "2")
    with pytest.raises(ConfigError, match="SCAM_MAX_IMAGES"):
        load_config()
    env.delenv("SCAM_MAX_IMAGES")
    env.setenv("SCAM_FLAG_SCORE", "12")
    with pytest.raises(ConfigError, match="SCAM_CONFIRM_SCORE"):
        load_config()
