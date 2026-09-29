"""The kick clock.

A bug here removes real people from the server, so every branch is pinned,
including the ones that must never fire: enforcement off, officers, exempt
roles, members who outrank the bot, and anyone still inside their grace period.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest

from config import Config
from security import KickVerdict, kick_decision
from store import Store

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
ADMIN_ROLE = 999
EXEMPT_ROLE = 4242
BOT_POSITION = 43


def verdict(**overrides):
    """kick_decision with a plain unverified member as the baseline."""
    kwargs = dict(
        is_bot=False,
        is_verified=False,
        role_ids=set(),
        top_role_position=10,
        joined_at=NOW - timedelta(days=400),
        now=NOW,
        enforcement_started_at=NOW - timedelta(days=20),
        kick_after_days=14,
        admin_role_id=ADMIN_ROLE,
        exempt_role_ids=frozenset({EXEMPT_ROLE}),
        bot_top_position=BOT_POSITION,
    )
    kwargs.update(overrides)
    return kick_decision(**kwargs)


# --- the safety rails ----------------------------------------------------


def test_nobody_is_kicked_until_officers_start_the_clock():
    got, deadline = verdict(enforcement_started_at=None)
    assert got is KickVerdict.NOT_STARTED
    assert deadline is None


def test_starting_the_clock_cannot_kick_anyone_the_same_day():
    """The whole point of the toggle: a long-standing member gets a full grace
    period from the announcement, not from when they joined."""
    got, deadline = verdict(
        enforcement_started_at=NOW,
        joined_at=NOW - timedelta(days=400),
    )
    assert got is KickVerdict.WITHIN_GRACE
    assert deadline == NOW + timedelta(days=14)


def test_bots_are_never_kicked():
    assert verdict(is_bot=True)[0] is KickVerdict.EXEMPT_BOT


def test_verified_members_are_never_kicked():
    assert verdict(is_verified=True)[0] is KickVerdict.EXEMPT_VERIFIED


def test_officers_are_never_kicked():
    assert verdict(role_ids={ADMIN_ROLE})[0] is KickVerdict.EXEMPT_OFFICER


def test_configured_exempt_roles_are_never_kicked():
    assert verdict(role_ids={EXEMPT_ROLE})[0] is KickVerdict.EXEMPT_ROLE


def test_members_outranking_the_bot_are_reported_not_attempted():
    # Discord would refuse anyway; naming it lets /ac enforce status warn.
    assert verdict(top_role_position=BOT_POSITION)[0] is KickVerdict.CANNOT_KICK
    assert verdict(top_role_position=BOT_POSITION + 5)[0] is KickVerdict.CANNOT_KICK


def test_exemptions_win_over_an_expired_deadline():
    long_overdue = {"enforcement_started_at": NOW - timedelta(days=365)}
    for extra, expected in [
        ({"is_bot": True}, KickVerdict.EXEMPT_BOT),
        ({"is_verified": True}, KickVerdict.EXEMPT_VERIFIED),
        ({"role_ids": {ADMIN_ROLE}}, KickVerdict.EXEMPT_OFFICER),
        ({"role_ids": {EXEMPT_ROLE}}, KickVerdict.EXEMPT_ROLE),
    ]:
        assert verdict(**long_overdue, **extra)[0] is expected


# --- the deadline --------------------------------------------------------


def test_kicked_once_the_grace_period_has_passed():
    got, deadline = verdict(enforcement_started_at=NOW - timedelta(days=14, seconds=1))
    assert got is KickVerdict.KICK
    assert deadline < NOW


def test_still_safe_one_second_before_the_deadline():
    got, deadline = verdict(enforcement_started_at=NOW - timedelta(days=14) + timedelta(seconds=1))
    assert got is KickVerdict.WITHIN_GRACE
    assert deadline > NOW


def test_a_member_who_joins_mid_clock_gets_their_own_full_grace():
    """Joining on day 13 must not mean being kicked on day 14."""
    got, deadline = verdict(
        enforcement_started_at=NOW - timedelta(days=13),
        joined_at=NOW - timedelta(hours=1),
    )
    assert got is KickVerdict.WITHIN_GRACE
    assert deadline == (NOW - timedelta(hours=1)) + timedelta(days=14)


def test_deadline_uses_whichever_anchor_is_later():
    started = NOW - timedelta(days=30)
    joined = NOW - timedelta(days=5)
    _, deadline = verdict(enforcement_started_at=started, joined_at=joined)
    assert deadline == joined + timedelta(days=14)


def test_missing_join_date_falls_back_to_the_start_of_enforcement():
    started = NOW - timedelta(days=3)
    got, deadline = verdict(enforcement_started_at=started, joined_at=None)
    assert got is KickVerdict.WITHIN_GRACE
    assert deadline == started + timedelta(days=14)


def test_grace_period_length_is_configurable():
    _, deadline = verdict(enforcement_started_at=NOW, kick_after_days=30)
    assert deadline == NOW + timedelta(days=30)


# --- the welcome DM ------------------------------------------------------


def test_join_dm_tells_them_to_run_verify():
    from bot import build_join_dm

    text = build_join_dm("BU.gg", None)
    assert "BU.gg" in text
    assert "/verify" in text
    assert "bicol-u.edu.ph" in text
    assert "/unverify" in text  # deletion right disclosed up front


def test_join_dm_never_contains_a_verification_link():
    """A link would carry a token tied to that member's Discord ID; anyone who
    got the DM forwarded could bind their own email to that account."""
    from bot import build_join_dm

    for deadline in (None, NOW + timedelta(days=14)):
        text = build_join_dm("BU.gg", deadline)
        assert "http://" not in text
        assert "https://" not in text
        assert "state=" not in text


def test_join_dm_states_the_deadline_only_when_enforcement_is_running():
    from bot import build_join_dm

    without = build_join_dm("BU.gg", None)
    assert "removed" not in without.lower()

    deadline = NOW + timedelta(days=14)
    with_deadline = build_join_dm("BU.gg", deadline)
    # Discord renders <t:...:F> in each reader's own timezone.
    assert f"<t:{int(deadline.timestamp())}:F>" in with_deadline
    assert "rejoin" in with_deadline.lower()


def test_join_dm_deadline_matches_what_the_kick_logic_would_use():
    """The DM and the kicker must never quote different dates."""
    from bot import build_join_dm
    from security import grace_deadline

    started = NOW - timedelta(days=3)
    joined = NOW
    deadline = grace_deadline(joined, started, 14)
    assert deadline == joined + timedelta(days=14)

    _, kick_deadline = verdict(
        enforcement_started_at=started, joined_at=joined, now=NOW
    )
    assert kick_deadline == deadline
    assert f"<t:{int(deadline.timestamp())}:F>" in build_join_dm("BU.gg", deadline)


def test_grace_deadline_picks_the_later_anchor():
    from security import grace_deadline

    started = NOW - timedelta(days=30)
    assert grace_deadline(NOW - timedelta(days=5), started, 14) == (
        NOW - timedelta(days=5) + timedelta(days=14)
    )
    assert grace_deadline(NOW - timedelta(days=90), started, 14) == started + timedelta(days=14)
    assert grace_deadline(None, started, 14) == started + timedelta(days=14)


# --- the toggle persists -------------------------------------------------


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "enforce.db")
    yield s
    s.close()


def test_enforcement_is_off_on_a_fresh_database(store):
    assert store.get_enforcement_start() is None


def test_start_and_stop_round_trip(store):
    store.set_enforcement_start(NOW)
    assert store.get_enforcement_start() == NOW
    store.set_enforcement_start(None)
    assert store.get_enforcement_start() is None


def test_toggle_survives_a_restart(tmp_path):
    path = tmp_path / "persist.db"
    first = Store(path)
    first.set_enforcement_start(NOW)
    first.close()

    second = Store(path)
    try:
        assert second.get_enforcement_start() == NOW
    finally:
        second.close()


def test_restarting_the_clock_replaces_the_old_timestamp(store):
    store.set_enforcement_start(NOW - timedelta(days=10))
    store.set_enforcement_start(NOW)
    assert store.get_enforcement_start() == NOW


# --- scanning a whole guild ---------------------------------------------


@dataclass
class FakeRole:
    id: int
    position: int = 10


@dataclass
class FakeMember:
    id: int
    bot: bool = False
    roles: list = field(default_factory=list)
    joined_at: datetime = NOW - timedelta(days=400)

    @property
    def top_role(self):
        return max(self.roles, key=lambda r: r.position) if self.roles else FakeRole(0, 0)


def make_config(**overrides):
    base = dict(
        discord_token="t", guild_id=1, verified_role_id=2, admin_role_id=ADMIN_ROLE,
        google_client_id="c", google_client_secret="s", base_url="http://localhost:8000",
        secret_key="k", roster_path="roster.csv", roster_mode="roster",
        db_path=":memory:", port=8000, kick_after_days=14,
        exempt_role_ids=frozenset({EXEMPT_ROLE}),
    )
    base.update(overrides)
    return Config(**base)


def test_scan_sorts_a_mixed_guild_into_the_right_buckets():
    from bot import scan_members

    members = [
        FakeMember(id=1),                                            # kick
        FakeMember(id=2),                                            # verified
        FakeMember(id=3, bot=True),                                  # bot
        FakeMember(id=4, roles=[FakeRole(ADMIN_ROLE)]),              # officer
        FakeMember(id=5, roles=[FakeRole(EXEMPT_ROLE)]),             # exempt role
        FakeMember(id=6, roles=[FakeRole(77, position=99)]),         # outranks bot
        FakeMember(id=7, joined_at=NOW - timedelta(days=1)),         # new joiner
    ]
    grouped = scan_members(
        members,
        cfg=make_config(),
        verified_ids={"2"},
        bot_top_position=BOT_POSITION,
        enforcement_started_at=NOW - timedelta(days=20),
        now=NOW,
    )

    def ids(verdict_key):
        return sorted(m.id for m, _ in grouped[verdict_key])

    assert ids(KickVerdict.KICK) == [1]
    assert ids(KickVerdict.EXEMPT_VERIFIED) == [2]
    assert ids(KickVerdict.EXEMPT_BOT) == [3]
    assert ids(KickVerdict.EXEMPT_OFFICER) == [4]
    assert ids(KickVerdict.EXEMPT_ROLE) == [5]
    assert ids(KickVerdict.CANNOT_KICK) == [6]
    assert ids(KickVerdict.WITHIN_GRACE) == [7]


def test_scan_kicks_nobody_while_enforcement_is_off():
    from bot import scan_members

    members = [FakeMember(id=i) for i in range(1, 6)]
    grouped = scan_members(
        members,
        cfg=make_config(),
        verified_ids=set(),
        bot_top_position=BOT_POSITION,
        enforcement_started_at=None,
        now=NOW,
    )
    assert grouped[KickVerdict.KICK] == []
    assert len(grouped[KickVerdict.NOT_STARTED]) == 5
