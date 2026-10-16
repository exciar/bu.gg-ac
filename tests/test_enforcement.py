"""The kick clock.

A bug here removes real people from the server, so every branch is pinned,
including the ones that must never fire: enforcement off, officers, exempt
roles, members who outrank the bot, anyone still inside their grace period,
and anyone already here at the moment the clock starts.
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
OFFICER_ROLE = 1000  # a second officer role, e.g. President
EXEMPT_ROLE = 4242
BOT_POSITION = 43
STARTED = NOW - timedelta(days=20)
NEW_DAYS = 3        # joined while the clock runs, counted from joining
EXISTING_DAYS = 14  # already here, counted from the clock start


def verdict(**overrides):
    """kick_decision with a baseline member who joined after the clock started
    and is one day past their deadline."""
    kwargs = dict(
        is_bot=False,
        is_verified=False,
        role_ids=set(),
        top_role_position=10,
        joined_at=NOW - timedelta(days=NEW_DAYS + 1),
        now=NOW,
        enforcement_started_at=STARTED,
        kick_after_days=NEW_DAYS,
        existing_kick_after_days=EXISTING_DAYS,
        admin_role_ids=frozenset({ADMIN_ROLE, OFFICER_ROLE}),
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


def test_starting_the_clock_never_removes_anyone_on_the_spot():
    """A member here for a year is not instantly overdue: everyone already in
    the server gets the full existing-member grace from the clock start."""
    got, deadline = verdict(enforcement_started_at=NOW, joined_at=NOW - timedelta(days=400))
    assert got is KickVerdict.WITHIN_GRACE
    assert deadline == NOW + timedelta(days=EXISTING_DAYS)


def test_members_already_here_count_from_the_clock_start():
    got, deadline = verdict(joined_at=STARTED - timedelta(seconds=1), now=STARTED)
    assert got is KickVerdict.WITHIN_GRACE
    assert deadline == STARTED + timedelta(days=EXISTING_DAYS)


def test_members_already_here_are_kicked_once_their_grace_runs_out():
    got, _ = verdict(
        enforcement_started_at=NOW - timedelta(days=EXISTING_DAYS, seconds=1),
        joined_at=NOW - timedelta(days=400),
    )
    assert got is KickVerdict.KICK


def test_missing_join_date_counts_as_already_here():
    """If Discord cannot tell us when they joined, we cannot prove they are
    new -- so they get the longer grace, from the clock start."""
    _, deadline = verdict(joined_at=None, now=STARTED)
    assert deadline == STARTED + timedelta(days=EXISTING_DAYS)


def test_bots_are_never_kicked():
    assert verdict(is_bot=True)[0] is KickVerdict.EXEMPT_BOT


def test_verified_members_are_never_kicked():
    assert verdict(is_verified=True)[0] is KickVerdict.EXEMPT_VERIFIED


def test_every_officer_role_is_exempt():
    for role in (ADMIN_ROLE, OFFICER_ROLE):
        assert verdict(role_ids={role})[0] is KickVerdict.EXEMPT_OFFICER


def test_configured_exempt_roles_are_never_kicked():
    assert verdict(role_ids={EXEMPT_ROLE})[0] is KickVerdict.EXEMPT_ROLE


def test_members_outranking_the_bot_are_reported_not_attempted():
    # Discord would refuse anyway; naming it lets /ac enforce status warn.
    assert verdict(top_role_position=BOT_POSITION)[0] is KickVerdict.CANNOT_KICK
    assert verdict(top_role_position=BOT_POSITION + 5)[0] is KickVerdict.CANNOT_KICK


def test_exemptions_win_over_an_expired_deadline():
    long_overdue = {"joined_at": NOW - timedelta(days=19)}
    assert verdict(**long_overdue)[0] is KickVerdict.KICK
    for extra, expected in [
        ({"is_bot": True}, KickVerdict.EXEMPT_BOT),
        ({"is_verified": True}, KickVerdict.EXEMPT_VERIFIED),
        ({"role_ids": {ADMIN_ROLE}}, KickVerdict.EXEMPT_OFFICER),
        ({"role_ids": {OFFICER_ROLE}}, KickVerdict.EXEMPT_OFFICER),
        ({"role_ids": {EXEMPT_ROLE}}, KickVerdict.EXEMPT_ROLE),
    ]:
        assert verdict(**long_overdue, **extra)[0] is expected


# --- the deadline --------------------------------------------------------


def test_kicked_once_the_grace_period_has_passed():
    got, deadline = verdict(joined_at=NOW - timedelta(days=NEW_DAYS, seconds=1))
    assert got is KickVerdict.KICK
    assert deadline < NOW


def test_still_safe_one_second_before_the_deadline():
    got, deadline = verdict(joined_at=NOW - timedelta(days=NEW_DAYS) + timedelta(seconds=1))
    assert got is KickVerdict.WITHIN_GRACE
    assert deadline > NOW


def test_the_timer_starts_the_moment_they_join():
    joined = NOW - timedelta(hours=1)
    got, deadline = verdict(joined_at=joined)
    assert got is KickVerdict.WITHIN_GRACE
    assert deadline == joined + timedelta(days=NEW_DAYS)


def test_joining_the_instant_the_clock_starts_counts_as_new():
    got, deadline = verdict(enforcement_started_at=NOW, joined_at=NOW)
    assert got is KickVerdict.WITHIN_GRACE
    assert deadline == NOW + timedelta(days=NEW_DAYS)


def test_a_member_who_joins_late_in_the_clock_gets_their_own_full_grace():
    """Joining on day 13 of the clock must not mean a shortened grace."""
    joined = STARTED + timedelta(days=13)
    _, deadline = verdict(joined_at=joined, now=joined + timedelta(days=1))
    assert deadline == joined + timedelta(days=NEW_DAYS)


def test_grace_period_lengths_are_configurable():
    _, deadline = verdict(joined_at=NOW, kick_after_days=30)
    assert deadline == NOW + timedelta(days=30)
    _, deadline = verdict(joined_at=None, now=STARTED, existing_kick_after_days=30)
    assert deadline == STARTED + timedelta(days=30)


def test_grace_deadline_counts_new_members_from_joining_and_others_from_the_start():
    from security import grace_deadline

    assert grace_deadline(NOW, STARTED, 3, 14) == NOW + timedelta(days=3)
    assert grace_deadline(STARTED - timedelta(days=1), STARTED, 3, 14) == STARTED + timedelta(days=14)
    assert grace_deadline(None, STARTED, 3, 14) == STARTED + timedelta(days=14)


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
        for existing in (False, True):
            text = build_join_dm("BU.gg", deadline, existing=existing)
            assert "http://" not in text
            assert "https://" not in text
            assert "state=" not in text


def test_notice_for_members_already_here_is_not_a_welcome():
    from bot import build_join_dm

    deadline = NOW + timedelta(days=EXISTING_DAYS)
    text = build_join_dm("BU.gg", deadline, existing=True)
    assert "Welcome" not in text
    assert "/verify" in text
    assert f"<t:{int(deadline.timestamp())}:F>" in text


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

    deadline = grace_deadline(NOW, STARTED, NEW_DAYS, EXISTING_DAYS)
    _, kick_deadline = verdict(joined_at=NOW, now=NOW)
    assert kick_deadline == deadline
    assert f"<t:{int(deadline.timestamp())}:F>" in build_join_dm("BU.gg", deadline)


# --- reminders -----------------------------------------------------------

DEADLINE = NOW + timedelta(days=14)
STAGES = (7, 3, 1)


def due(time_left, sent=frozenset()):
    from security import reminder_due

    return reminder_due(DEADLINE, DEADLINE - time_left, STAGES, set(sent))


def test_no_reminder_while_plenty_of_time_is_left():
    assert due(timedelta(days=13)) is None
    assert due(timedelta(days=7, seconds=1)) is None


def test_each_stage_fires_once_its_threshold_is_reached():
    assert due(timedelta(days=7)) == 7
    assert due(timedelta(days=3)) == 3
    assert due(timedelta(hours=23)) == 1


def test_a_stage_already_sent_is_not_sent_again():
    assert due(timedelta(days=6), sent={7}) is None
    assert due(timedelta(days=2), sent={7, 3}) is None


def test_catching_up_sends_only_the_most_urgent_stage():
    """After downtime, a member at 2 days left gets one reminder, not the
    7-day and 3-day ones back to back."""
    assert due(timedelta(days=2)) == 3
    assert due(timedelta(days=2), sent={3}) is None


def test_no_reminder_once_the_deadline_has_passed():
    assert due(timedelta(seconds=0)) is None
    assert due(-timedelta(hours=1)) is None


def test_reminder_marks_beyond_a_members_grace_are_skipped():
    """A 7- or 3-day reminder for someone with 3 days would land on top of
    their welcome DM."""
    from bot import reminder_stages

    assert reminder_stages(make_config(), existing=False) == (1,)


def test_members_already_here_get_one_notice_then_the_usual_reminders():
    from bot import reminder_stages
    from security import reminder_due

    stages = reminder_stages(make_config(), existing=True)
    assert stages == (EXISTING_DAYS, 7, 3, 1)
    deadline = NOW + timedelta(days=EXISTING_DAYS)
    # Right after the clock starts, the notice is what's due -- once.
    assert reminder_due(deadline, NOW, stages, set()) == EXISTING_DAYS
    assert reminder_due(deadline, NOW + timedelta(hours=1), stages, {EXISTING_DAYS}) is None
    assert reminder_due(deadline, deadline - timedelta(days=7), stages, {EXISTING_DAYS}) == 7


def test_reminder_dm_names_the_deadline_and_carries_no_link():
    from bot import build_reminder_dm

    text = build_reminder_dm("BU.gg", DEADLINE)
    assert "/verify" in text
    assert f"<t:{int(DEADLINE.timestamp())}:R>" in text
    assert "http://" not in text
    assert "https://" not in text


def test_outsiders_and_officers_are_never_asked_to_verify():
    """Exempt roles (e.g. Outsider) and officer roles are off the clock, so
    DMing them to verify would only confuse them."""
    from bot import wants_verification_dm

    cfg = make_config()
    assert wants_verification_dm(set(), cfg) is True
    assert wants_verification_dm({12345}, cfg) is True
    assert wants_verification_dm({EXEMPT_ROLE}, cfg) is False
    assert wants_verification_dm({ADMIN_ROLE}, cfg) is False
    assert wants_verification_dm({OFFICER_ROLE, 12345}, cfg) is False


def test_welcome_waits_for_onboarding_only_when_it_is_still_in_progress():
    """Onboarding is where members pick Outsider, and Discord assigns that role
    only once they finish -- after the join event."""
    from bot import needs_onboarding_wait

    assert needs_onboarding_wait({"GUILD_ONBOARDING"}, completed=False) is True
    assert needs_onboarding_wait({"GUILD_ONBOARDING"}, completed=True) is False
    assert needs_onboarding_wait({"COMMUNITY"}, completed=False) is False
    # A server that once had onboarding but switched it off never completes it.
    assert needs_onboarding_wait({"GUILD_ONBOARDING_EVER_ENABLED"}, completed=False) is False


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


# --- reminders sent are remembered ---------------------------------------


def test_sent_reminders_are_recorded_per_deadline(store):
    assert store.reminders_sent(1, DEADLINE) == set()
    store.mark_reminder(1, DEADLINE, 7)
    store.mark_reminder(1, DEADLINE, 3)
    assert store.reminders_sent(1, DEADLINE) == {7, 3}
    assert store.reminders_sent(2, DEADLINE) == set()


def test_marking_the_same_reminder_twice_is_harmless(store):
    store.mark_reminder(1, DEADLINE, 7)
    store.mark_reminder(1, DEADLINE, 7)
    assert store.reminders_sent(1, DEADLINE) == {7}


def test_rejoining_starts_a_fresh_set_of_reminders(store):
    """A new join means a new deadline, so the old stages do not carry over."""
    store.mark_reminder(1, DEADLINE, 7)
    assert store.reminders_sent(1, DEADLINE + timedelta(days=5)) == set()


def test_reminders_survive_a_restart(tmp_path):
    path = tmp_path / "reminders.db"
    first = Store(path)
    first.mark_reminder(1, DEADLINE, 3)
    first.close()

    second = Store(path)
    try:
        assert second.reminders_sent(1, DEADLINE) == {3}
    finally:
        second.close()


def test_prune_drops_everyone_no_longer_on_the_clock(store):
    for member in (1, 2, 3):
        store.mark_reminder(member, DEADLINE, 7)
    store.prune_reminders(keep={"2"})
    assert store.reminders_sent(1, DEADLINE) == set()
    assert store.reminders_sent(2, DEADLINE) == {7}
    assert store.reminders_sent(3, DEADLINE) == set()


def test_clear_reminders_forgets_one_member(store):
    store.mark_reminder(1, DEADLINE, 7)
    store.mark_reminder(2, DEADLINE, 7)
    store.clear_reminders(1)
    assert store.reminders_sent(1, DEADLINE) == set()
    assert store.reminders_sent(2, DEADLINE) == {7}


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
    joined_at: datetime | None = NOW - timedelta(days=15)  # new, and overdue

    @property
    def top_role(self):
        return max(self.roles, key=lambda r: r.position) if self.roles else FakeRole(0, 0)


def make_config(**overrides):
    base = dict(
        discord_token="t", guild_id=1, verified_role_id=2,
        admin_role_ids=frozenset({ADMIN_ROLE, OFFICER_ROLE}),
        google_client_id="c", google_client_secret="s", base_url="http://localhost:8000",
        secret_key="k", roster_path="roster.csv", roster_mode="roster",
        db_path=":memory:", port=8000,
        kick_after_days=NEW_DAYS, existing_kick_after_days=EXISTING_DAYS,
        exempt_role_ids=frozenset({EXEMPT_ROLE}), reminder_days=STAGES,
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
        FakeMember(id=8, joined_at=NOW - timedelta(days=400)),       # here first, grace over
        FakeMember(id=9, roles=[FakeRole(OFFICER_ROLE, position=57)]),  # President
    ]
    grouped = scan_members(
        members,
        cfg=make_config(),
        verified_ids={"2"},
        bot_top_position=BOT_POSITION,
        enforcement_started_at=STARTED,
        now=NOW,
    )

    def ids(verdict_key):
        return sorted(m.id for m, _ in grouped[verdict_key])

    assert ids(KickVerdict.KICK) == [1, 8]
    assert ids(KickVerdict.EXEMPT_VERIFIED) == [2]
    assert ids(KickVerdict.EXEMPT_BOT) == [3]
    assert ids(KickVerdict.EXEMPT_OFFICER) == [4, 9]
    assert ids(KickVerdict.EXEMPT_ROLE) == [5]
    assert ids(KickVerdict.CANNOT_KICK) == [6]
    assert ids(KickVerdict.WITHIN_GRACE) == [7]


def test_starting_the_clock_today_kicks_nobody_in_an_established_guild():
    """The deploy-day case: a guild full of long-time unverified members goes
    on the clock, and not one of them is due yet."""
    from bot import scan_members

    members = [FakeMember(id=i, joined_at=NOW - timedelta(days=30 * i)) for i in range(1, 6)]
    grouped = scan_members(
        members,
        cfg=make_config(),
        verified_ids=set(),
        bot_top_position=BOT_POSITION,
        enforcement_started_at=NOW,
        now=NOW,
    )
    assert grouped[KickVerdict.KICK] == []
    assert len(grouped[KickVerdict.WITHIN_GRACE]) == 5


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
