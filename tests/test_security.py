"""State token signing, expiry, and roster normalization. No network."""

from __future__ import annotations

import itsdangerous.timed
import pytest

from security import (
    STATE_TTL_SECONDS,
    StateExpired,
    StateInvalid,
    build_authorize_url,
    make_state,
    read_state,
)
from store import Roster, load_roster, normalize_email

SECRET = "test-secret-not-a-real-key"


# --- state tokens --------------------------------------------------------


def test_state_roundtrip_preserves_ids():
    token = make_state(SECRET, 123456789, 987654321)
    data = read_state(SECRET, token)
    assert data["d"] == "123456789"
    assert data["g"] == "987654321"
    assert data["n"]


def test_each_state_gets_a_fresh_nonce():
    first = read_state(SECRET, make_state(SECRET, 1, 2))
    second = read_state(SECRET, make_state(SECRET, 1, 2))
    assert first["n"] != second["n"]


def test_tampered_token_is_rejected():
    token = make_state(SECRET, 111, 222)
    # Flip a character in the payload, leaving the signature attached.
    payload, _, signature = token.partition(".")
    flipped = ("X" if payload[0] != "X" else "Y") + payload[1:]
    with pytest.raises(StateInvalid):
        read_state(SECRET, f"{flipped}.{signature}")


def test_token_signed_with_another_key_is_rejected():
    token = make_state("a-different-secret", 111, 222)
    with pytest.raises(StateInvalid):
        read_state(SECRET, token)


def test_garbage_is_rejected():
    with pytest.raises(StateInvalid):
        read_state(SECRET, "not-a-token")


def test_empty_state_is_rejected():
    with pytest.raises(StateInvalid):
        read_state(SECRET, "")


def test_token_expires_after_ten_minutes(monkeypatch):
    token = make_state(SECRET, 111, 222)
    # Still good just inside the window.
    read_state(SECRET, token)

    real_time = itsdangerous.timed.time.time
    monkeypatch.setattr(
        itsdangerous.timed.time,
        "time",
        lambda: real_time() + STATE_TTL_SECONDS + 1,
    )
    with pytest.raises(StateExpired):
        read_state(SECRET, token)


def test_expiry_is_ten_minutes():
    assert STATE_TTL_SECONDS == 600


def test_authorize_url_carries_hd_hint_and_openid_scope():
    url = build_authorize_url("client-id", "http://localhost:8000/callback", "st", "nonce-1")
    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "hd=bicol-u.edu.ph" in url
    assert "scope=openid+email+profile" in url
    assert "state=st" in url
    assert "nonce=nonce-1" in url
    assert "response_type=code" in url


# --- roster normalization ------------------------------------------------


def test_normalize_email_trims_and_lowercases():
    assert normalize_email("  Juan.Dela.Cruz@Bicol-U.edu.PH \n") == "juan.dela.cruz@bicol-u.edu.ph"
    assert normalize_email(None) == ""
    assert normalize_email("") == ""


def _write(tmp_path, text, encoding="utf-8"):
    path = tmp_path / "roster.csv"
    path.write_text(text, encoding=encoding)
    return path


def test_roster_normalizes_case_and_whitespace(tmp_path):
    path = _write(
        tmp_path,
        "email\n  Juan@BICOL-U.edu.ph  \nmaria@bicol-u.edu.ph\n",
    )
    emails = load_roster(path)
    assert emails == {"juan@bicol-u.edu.ph", "maria@bicol-u.edu.ph"}


def test_roster_skips_blank_rows(tmp_path):
    path = _write(tmp_path, "email\njuan@bicol-u.edu.ph\n\n   \n\nmaria@bicol-u.edu.ph\n")
    assert load_roster(path) == {"juan@bicol-u.edu.ph", "maria@bicol-u.edu.ph"}


def test_roster_tolerates_excel_bom_and_capitalized_header(tmp_path):
    path = _write(tmp_path, "Email\njuan@bicol-u.edu.ph\n", encoding="utf-8-sig")
    assert load_roster(path) == {"juan@bicol-u.edu.ph"}


def test_roster_collapses_duplicates(tmp_path):
    path = _write(
        tmp_path, "email\njuan@bicol-u.edu.ph\nJUAN@bicol-u.edu.ph\n Juan@Bicol-U.edu.ph\n"
    )
    assert load_roster(path) == {"juan@bicol-u.edu.ph"}


def test_roster_without_email_column_raises(tmp_path):
    path = _write(tmp_path, "name,section\njuan,BSBA-1A\n")
    with pytest.raises(ValueError, match="email"):
        load_roster(path)


def test_roster_ignores_extra_columns(tmp_path):
    path = _write(tmp_path, "name,email,section\nJuan,juan@bicol-u.edu.ph,BSBA-1A\n")
    assert load_roster(path) == {"juan@bicol-u.edu.ph"}


def test_bad_reload_leaves_previous_roster_intact(tmp_path):
    path = _write(tmp_path, "email\njuan@bicol-u.edu.ph\n")
    roster = Roster(path)
    assert roster.reload() == 1

    path.write_text("name,section\njuan,BSBA-1A\n", encoding="utf-8")
    with pytest.raises(ValueError):
        roster.reload()
    # The working roster must survive an officer uploading a malformed file.
    assert "juan@bicol-u.edu.ph" in roster
    assert len(roster) == 1
