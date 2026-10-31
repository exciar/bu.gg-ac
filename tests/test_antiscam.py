"""The anti-scam module: catching hijacked accounts that post the crypto-casino
image scam in every channel they can reach.

Everything here runs on fake messages and generated images -- no Discord, no
network, and no Tesseract binary (the VPS deploy gate runs this suite).
"""

from __future__ import annotations

import io
import itertools
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from PIL import Image, ImageDraw, ImageFilter

from antiscam import (
    BurstTracker,
    Post,
    ScamStore,
    best_match,
    burst_signals,
    dhash,
    fingerprint,
    hash_distance,
    match_keywords,
    plan_response,
    post_from_message,
    score_post,
    softban_delete_seconds,
    strip_mentions,
)
from config import ScamConfig

T0 = datetime(2026, 10, 30, 18, 50, 49, tzinfo=timezone.utc)
SCAM_SIZES = (183_204, 240_118, 301_977)
CFG = ScamConfig()
_ids = itertools.count(1000)


@dataclass
class FakeAttachment:
    size: int
    filename: str = "image.png"
    content_type: str | None = "image/png"
    width: int | None = 1080
    height: int | None = 1920
    url: str = "https://cdn.example/a.png"


def post(*, user=1, channel=10, at=0.0, sizes=SCAM_SIZES, text="", everyone=False, exempt=False):
    return Post(
        user_id=user,
        channel_id=channel,
        message_id=next(_ids),
        created_at=T0 + timedelta(seconds=at),
        images=tuple(FakeAttachment(s) for s in sizes),
        text_len=len(text),
        mentions_everyone=everyone,
        exempt_channel=exempt,
    )


def score(p, recent=None, *, history_ready=False, last_image_at=None, cfg=CFG):
    return score_post(
        p, recent if recent is not None else [p], cfg,
        history_ready=history_ready, last_image_at=last_image_at,
    )


# --- reading a message ---------------------------------------------------


def test_mentions_and_whitespace_do_not_count_as_text():
    assert strip_mentions("<@123> <@!456> <@&789> <#42> @everyone @here  Bro ") == "Bro"
    assert strip_mentions("") == ""


def test_post_from_a_fake_message():
    message = SimpleNamespace(
        id=55,
        author=SimpleNamespace(id=7),
        channel=SimpleNamespace(id=10),
        created_at=T0,
        content="@everyone Bro",
        attachments=[
            FakeAttachment(100),
            FakeAttachment(200, filename="clip.mp4", content_type="video/mp4"),
            FakeAttachment(300, filename="IMG_1.JPG", content_type=None),
        ],
    )
    p = post_from_message(message, exempt_channel_ids=frozenset())
    assert (p.user_id, p.channel_id, p.message_id) == (7, 10, 55)
    assert p.image_count == 2  # the video is not an image; the bare .JPG is
    assert p.text_len == len("Bro")
    assert p.mentions_everyone is True
    assert p.exempt_channel is False
    assert post_from_message(message, exempt_channel_ids=frozenset({10})).exempt_channel


def test_fingerprint_matches_copies_regardless_of_order_or_filename():
    a = [FakeAttachment(3), FakeAttachment(1, filename="x.png"), FakeAttachment(2)]
    b = [FakeAttachment(1), FakeAttachment(2, filename="other.jpg"), FakeAttachment(3)]
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint(a[:2])
    assert fingerprint(a) != fingerprint([FakeAttachment(1), FakeAttachment(2), FakeAttachment(4)])


# --- the burst detector --------------------------------------------------


def test_same_images_in_two_channels_within_the_window_is_a_burst():
    first, second = post(channel=10), post(channel=11, at=2)
    burst = burst_signals([first, second], second, window_seconds=60, min_images=2)
    assert burst.identical_channels == 2
    assert burst.channels == 2


def test_reposting_in_the_same_channel_is_not_cross_channel():
    first, second = post(channel=10), post(channel=10, at=5)
    burst = burst_signals([first, second], second, window_seconds=60, min_images=2)
    assert burst.identical_channels == 1


def test_copies_further_apart_than_the_window_do_not_count():
    first, second = post(channel=10), post(channel=11, at=61)
    burst = burst_signals([first, second], second, window_seconds=60, min_images=2)
    assert burst.identical_channels == 1
    assert burst.channels == 1


def test_different_images_in_two_channels_count_only_as_channels():
    first = post(channel=10, sizes=(1, 2))
    second = post(channel=11, at=3, sizes=(3, 4))
    burst = burst_signals([first, second], second, window_seconds=60, min_images=2)
    assert burst.identical_channels == 1
    assert burst.channels == 2


def test_single_image_posts_are_not_burst_material():
    first, second = post(channel=10, sizes=(9,)), post(channel=11, at=1, sizes=(9,))
    burst = burst_signals([first, second], second, window_seconds=60, min_images=2)
    assert (burst.identical_channels, burst.channels) == (0, 0)


def test_exempt_channel_copies_do_not_count_towards_a_burst():
    art = post(channel=10, exempt=True)
    second = post(channel=11, at=2)
    burst = burst_signals([art, second], second, window_seconds=60, min_images=2)
    assert burst.identical_channels == 1


def test_tracker_forgets_posts_older_than_its_ttl():
    tracker = BurstTracker(ttl_seconds=120)
    tracker.add(post(user=1, channel=10))
    recent = tracker.add(post(user=1, channel=11, at=121))
    assert [p.channel_id for p in recent] == [11]
    assert tracker.recent(1, T0 + timedelta(seconds=500)) == []


def test_tracker_keeps_users_apart():
    tracker = BurstTracker(ttl_seconds=120)
    tracker.add(post(user=1, channel=10))
    recent = tracker.add(post(user=2, channel=11, at=1))
    assert [p.user_id for p in recent] == [2]


# --- scoring -------------------------------------------------------------


def test_identical_burst_confirms_on_its_own():
    first, second = post(channel=10), post(channel=11, at=2)
    got = score(second, [first, second])
    assert got.total >= CFG.confirm_score
    assert any("same images" in s for s in got.signals)


def test_the_october_30_timeline_confirms_at_the_second_post():
    """0.0_seannn's account posted the same images 2-8 s apart in 25 channels."""
    offsets = [0, 2, 4, 7, 15, 17, 22, 24, 32, 34, 37, 46, 49]
    tracker = BurstTracker(ttl_seconds=120)
    verdicts = []
    for channel, at in enumerate(offsets, start=100):
        p = post(channel=channel, at=at)
        verdicts.append(score(p, tracker.add(p)).total >= CFG.confirm_score)
    assert verdicts[0] is False
    assert all(verdicts[1:])


def test_different_images_in_two_channels_flag_but_do_not_confirm():
    first = post(channel=10, sizes=(1, 2), text="look at this lineup")
    second = post(channel=11, at=3, sizes=(3, 4), text="and the venue photos!!")
    got = score(second, [first, second])
    assert CFG.flag_score <= got.total < CFG.confirm_score


def test_scam_shape_alone_flags_for_ocr():
    got = score(post(text="Bro"))
    assert got.total == 3
    assert CFG.flag_score <= got.total < CFG.confirm_score


def test_everyone_ping_adds_weight_to_the_shape():
    assert score(post(text="", everyone=True)).total == 5


def test_everyone_ping_without_the_shape_adds_nothing():
    assert score(post(sizes=(1,), everyone=True)).total == 0


def test_long_text_is_not_the_scam_shape():
    assert score(post(text="here are the photos from saturday's meetup")).total == 0


def test_too_many_or_too_few_images_is_not_the_scam_shape():
    assert score(post(sizes=(1,))).total == 0
    assert score(post(sizes=(1, 2, 3, 4, 5))).total == 0


def test_first_image_in_a_month_adds_weight_once_history_is_ready():
    got = score(post(), history_ready=True, last_image_at=None)
    assert got.total == 5
    recent_poster = score(post(), history_ready=True, last_image_at=T0 - timedelta(days=2))
    assert recent_poster.total == 3


def test_first_image_signal_waits_until_tracking_has_run_a_month():
    """On a fresh install nobody has image history, so this would fire for
    everyone. It stays off until the bot has watched for 30 days."""
    assert score(post(), history_ready=False, last_image_at=None).total == 3


def test_exempt_channel_posts_score_nothing():
    assert score(post(exempt=True, everyone=True)).total == 0


# --- OCR keywords --------------------------------------------------------

SCAM_SCREEN = """MrBeast @MrBeast
I'm giving away $2,500 to celebrate 300M! Go to beastcasino.com
Enter promo code BEAST2500 and activate code
Withdrawal Successful
2500 USDT (TRC20)"""


def test_scam_screenshot_text_hits_many_keywords():
    assert match_keywords(SCAM_SCREEN) >= {
        "2500", "domain", "promo code", "activate code", "withdrawal successful", "usdt", "trc20",
    }


def test_keywords_are_case_insensitive_and_span_line_breaks():
    assert match_keywords("PROMO\nCODE  deposit") == {"promo code", "deposit"}


def test_overlapping_keywords_count_once():
    assert match_keywords("WITHDRAWAL SUCCESSFUL") == {"withdrawal successful"}
    assert match_keywords("withdraw now") == {"withdraw"}


def test_amount_must_stand_alone():
    assert match_keywords("$2,500") == {"2500"}
    assert match_keywords("2500") == {"2500"}
    assert match_keywords("12500 points, code BEAST2500") == set()


def test_all_domains_count_as_one_kind():
    assert match_keywords("spinwin.bet and luckydrop.vip") == {"domain"}


def test_casino_inside_a_domain_counts_as_the_domain():
    assert match_keywords("beastcasino.com") == {"domain"}


def test_ordinary_chat_hits_nothing():
    assert match_keywords("gg everyone, see you at the event tomorrow") == set()
    assert match_keywords("the bonus round in valorant was wild") == {"bonus"}


# --- perceptual hash -----------------------------------------------------


def picture(seed: int, size=(640, 480)) -> Image.Image:
    rng = random.Random(seed)
    img = Image.new("RGB", size, tuple(rng.randrange(256) for _ in range(3)))
    draw = ImageDraw.Draw(img)
    for _ in range(12):
        x0, y0 = rng.randrange(size[0]), rng.randrange(size[1])
        box = (x0, y0, x0 + rng.randrange(40, 300), y0 + rng.randrange(40, 240))
        draw.rectangle(box, fill=tuple(rng.randrange(256) for _ in range(3)))
    return img


def reencode(img: Image.Image, quality: int) -> Image.Image:
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    return Image.open(io.BytesIO(buf.getvalue()))


def test_dhash_is_a_64_bit_int():
    h = dhash(picture(1))
    assert isinstance(h, int)
    assert 0 <= h < 2**64


def test_identical_images_match_exactly():
    assert hash_distance(dhash(picture(1)), dhash(picture(1))) == 0


def test_recompressed_resized_and_blurred_copies_still_match():
    original = dhash(picture(1))
    for copy in (
        reencode(picture(1), 40),
        picture(1).resize((320, 240)),
        picture(1).filter(ImageFilter.GaussianBlur(2)),
    ):
        assert hash_distance(original, dhash(copy)) <= CFG.hash_max_distance


def test_different_images_do_not_match():
    assert hash_distance(dhash(picture(1)), dhash(picture(2))) > CFG.hash_max_distance


def test_best_match_returns_the_closest_distance_within_the_limit():
    target = dhash(picture(1))
    known = [dhash(picture(2)), dhash(reencode(picture(1), 50)), dhash(picture(3))]
    distance = best_match(target, known, max_distance=10)
    assert distance is not None and distance <= 10
    assert best_match(target, [dhash(picture(2))], max_distance=10) is None
    assert best_match(target, [], max_distance=10) is None


# --- what to do on a confirmed hit ---------------------------------------


def plan(**overrides):
    kwargs = dict(
        dry_run=False, action="timeout", is_owner=False, outranks_bot=False, is_admin=False,
        can_manage_messages=True, can_moderate_members=True, can_ban=True,
    )
    kwargs.update(overrides)
    return plan_response(**kwargs)


def test_normal_hit_times_out_deletes_dms_and_remembers_the_images():
    got = plan()
    assert (got.timeout, got.delete, got.dm, got.store_hashes) == (True, True, True, True)
    assert got.softban is False
    assert got.ping is False and got.problems == ()


def test_dry_run_acts_on_nothing_and_does_not_ping():
    got = plan(dry_run=True)
    assert got.dry_run is True
    assert got.ping is False


def test_server_owner_is_never_touched_but_mods_are_pinged():
    got = plan(is_owner=True)
    assert not (got.timeout or got.softban or got.delete or got.dm or got.store_hashes)
    assert got.ping is True
    assert got.problems


def test_target_above_the_bot_still_has_posts_deleted_and_mods_pinged():
    got = plan(outranks_bot=True)
    assert got.timeout is False
    assert got.delete is True
    assert got.ping is True


def test_administrators_cannot_be_timed_out():
    got = plan(is_admin=True)
    assert got.timeout is False
    assert got.delete is True
    assert got.ping is True


def test_missing_permissions_are_reported_loudly():
    got = plan(can_manage_messages=False, can_moderate_members=False)
    assert (got.timeout, got.delete) == (False, False)
    assert got.ping is True
    assert len(got.problems) == 2


def test_softban_replaces_timeout_and_per_message_deletes():
    got = plan(action="softban")
    assert got.softban is True
    assert (got.timeout, got.delete) == (False, False)
    assert got.dm is True


def test_softban_falls_back_to_deleting_when_the_target_outranks_the_bot():
    got = plan(action="softban", outranks_bot=True)
    assert got.softban is False
    assert got.delete is True
    assert got.ping is True


def test_softban_without_ban_permission_falls_back_to_timeout():
    got = plan(action="softban", can_ban=False)
    assert got.softban is False
    assert (got.timeout, got.delete) == (True, True)
    assert got.ping is True


def test_softban_window_covers_the_burst_plus_a_margin():
    seconds = softban_delete_seconds(T0, T0 + timedelta(seconds=76))
    assert 76 < seconds <= 76 + 600
    assert softban_delete_seconds(T0 - timedelta(days=30), T0) == 7 * 24 * 3600


# --- storage -------------------------------------------------------------


@pytest.fixture()
def store(tmp_path):
    s = ScamStore(tmp_path / "scam.db")
    yield s
    s.close()


def test_hashes_round_trip_and_survive_a_restart(tmp_path):
    path = tmp_path / "persist.db"
    first = ScamStore(path)
    big = 2**64 - 1  # beyond SQLite's signed 64-bit INTEGER
    assert first.add_hashes([big, 5], incident="111", added_by=9) == 2
    first.close()
    second = ScamStore(path)
    try:
        assert sorted(second.hashes()) == sorted([(big, "111"), (5, "111")])
    finally:
        second.close()


def test_adding_the_same_hash_twice_for_an_incident_is_harmless(store):
    store.add_hashes([5], incident="1", added_by=None)
    assert store.add_hashes([5], incident="1", added_by=None) == 0
    assert store.hashes() == [(5, "1")]


def test_false_positive_removes_only_that_incidents_hashes(store):
    store.add_hashes([1, 2], incident="a", added_by=None)
    store.add_hashes([3], incident="b", added_by=None)
    assert store.remove_incident("a") == 2
    assert store.hashes() == [(3, "b")]


def test_image_history_is_recorded_and_pruned(store):
    assert store.last_image_at(7) is None
    store.record_image(7, T0)
    assert store.last_image_at(7) == T0
    store.record_image(8, T0 - timedelta(days=40))
    assert store.prune_image_posts(T0 - timedelta(days=30)) == 1
    assert store.last_image_at(8) is None
    assert store.last_image_at(7) == T0


def test_tracking_start_is_set_once(tmp_path):
    path = tmp_path / "since.db"
    first = ScamStore(path)
    since = first.tracking_since()
    first.close()
    second = ScamStore(path)
    try:
        assert second.tracking_since() == since
    finally:
        second.close()


def test_recovery_dm_gives_the_steps_and_carries_no_link():
    from antiscam import build_scam_dm

    for softban in (False, True):
        text = build_scam_dm("BU.gg", softban=softban, timeout_hours=24)
        assert "malware" in text
        assert "Log out all known devices" in text
        assert "Authorized Apps" in text
        assert "http" not in text
    assert "24 hours" in build_scam_dm("BU.gg", softban=False, timeout_hours=24)
    assert "invite" in build_scam_dm("BU.gg", softban=True, timeout_hours=24)


# --- the incident handler, against fake Discord objects ------------------


class FakeChannel:
    def __init__(self, channel_id, *, can_delete=True):
        self.id = channel_id
        self.mention = f"<#{channel_id}>"
        self.can_delete = can_delete
        self.deleted, self.sent = [], []

    async def delete_messages(self, messages, *, reason=None):
        if not self.can_delete:
            import discord

            raise discord.Forbidden(SimpleNamespace(status=403, reason="Forbidden"), "Missing Permissions")
        self.deleted += [m.id for m in messages]

    async def send(self, content=None, **kwargs):
        self.sent.append(SimpleNamespace(content=content, **kwargs))


class FakeGuild:
    def __init__(self, channels, *, bot_position=42, perms=None, owner_id=1):
        self.id, self.name, self.owner_id = 77, "BU.gg", owner_id
        self.channels = {c.id: c for c in channels}
        self.me = SimpleNamespace(
            top_role=bot_position,
            guild_permissions=perms or SimpleNamespace(
                manage_messages=True, moderate_members=True, ban_members=True
            ),
        )
        self.bans, self.unbans = [], []

    def get_channel_or_thread(self, channel_id):
        return self.channels.get(channel_id)

    get_channel = get_channel_or_thread

    async def ban(self, member, *, reason=None, delete_message_seconds=0):
        self.bans.append(delete_message_seconds)

    async def unban(self, member, *, reason=None):
        self.unbans.append(member.id)


class FakeMember:
    def __init__(self, guild, *, member_id=7, top_role=10):
        self.id, self.guild, self.top_role = member_id, guild, top_role
        self.mention = f"<@{member_id}>"
        self.guild_permissions = SimpleNamespace(administrator=False)
        self.timeouts, self.dms = [], []

    def __str__(self):
        return "victim"

    async def timeout(self, until, *, reason=None):
        self.timeouts.append(until)

    async def send(self, text):
        self.dms.append(text)


def png(seed: int) -> bytes:
    buf = io.BytesIO()
    picture(seed).save(buf, "PNG")
    return buf.getvalue()


class ReadableAttachment(FakeAttachment):
    async def read(self):
        return png(self.size % 7)


def scam_post(channel, at):
    return Post(
        user_id=7, channel_id=channel, message_id=next(_ids),
        created_at=datetime.now(timezone.utc) + timedelta(seconds=at),
        images=tuple(ReadableAttachment(s) for s in SCAM_SIZES),
        text_len=0, mentions_everyone=False,
    )


async def run_incident(tmp_path, *, cfg, channels, guild_kwargs=None, member_kwargs=None):
    from antiscam import AntiScam

    log_channel = FakeChannel(999)
    guild = FakeGuild([*channels, log_channel], **(guild_kwargs or {}))
    member = FakeMember(guild, **(member_kwargs or {}))
    bot = SimpleNamespace(cfg=SimpleNamespace(
        scam=cfg, guild_id=77, admin_role_ids=frozenset({1000}), db_path=str(tmp_path / "s.db"),
    ))
    cog = AntiScam(bot)
    posts = [scam_post(c.id, i * 2) for i, c in enumerate(channels)]
    for p in posts:
        recent = cog.tracker.add(p)
    await cog._confirm(member, posts[-1], score(posts[-1], recent, cfg=cfg))
    known = cog.store.hashes()
    cog.store.close()
    return guild, member, log_channel, posts, known


async def test_live_hit_times_out_deletes_every_copy_and_alerts(tmp_path):
    cfg = ScamConfig(enabled=True, dry_run=False, log_channel_id=999)
    channels = [FakeChannel(c) for c in (10, 11, 12)]
    guild, member, log_channel, posts, known = await run_incident(tmp_path, cfg=cfg, channels=channels)
    assert len(member.timeouts) == 1
    assert [c.deleted for c in channels] == [[p.message_id] for p in posts]
    assert member.dms and "malware" in member.dms[0]
    assert known  # images remembered for next time
    alert = log_channel.sent[0]
    assert alert.content is None  # nothing needed a human
    assert alert.files and len(alert.files) <= 4
    assert "Done" in [f.name for f in alert.embed.fields]


async def test_dry_run_only_alerts(tmp_path):
    cfg = ScamConfig(enabled=True, dry_run=True, log_channel_id=999)
    channels = [FakeChannel(c) for c in (10, 11)]
    guild, member, log_channel, _, known = await run_incident(tmp_path, cfg=cfg, channels=channels)
    assert member.timeouts == [] and member.dms == []
    assert all(c.deleted == [] for c in channels)
    assert guild.bans == [] and known == []
    assert log_channel.sent[0].embed.title.startswith("Dry run")
    assert "Would have" in [f.name for f in log_channel.sent[0].embed.fields]


async def test_softban_removes_and_wipes_everywhere_then_unbans(tmp_path):
    cfg = ScamConfig(enabled=True, dry_run=False, log_channel_id=999, action="softban")
    channels = [FakeChannel(c) for c in (10, 11)]
    guild, member, log_channel, _, _ = await run_incident(tmp_path, cfg=cfg, channels=channels)
    assert len(guild.bans) == 1 and guild.bans[0] > 0
    assert guild.unbans == [member.id]
    assert member.timeouts == []
    assert all(c.deleted == [] for c in channels)  # the ban did the deleting
    assert member.dms  # sent before they were removed


async def test_staff_above_the_bot_get_posts_deleted_and_mods_pinged(tmp_path):
    cfg = ScamConfig(enabled=True, dry_run=False, log_channel_id=999)
    channels = [FakeChannel(10), FakeChannel(11, can_delete=False)]
    _, member, log_channel, posts, _ = await run_incident(
        tmp_path, cfg=cfg, channels=channels, member_kwargs={"top_role": 51},
    )
    assert member.timeouts == []
    assert channels[0].deleted == [posts[0].message_id]
    alert = log_channel.sent[0]
    assert alert.content.startswith("@here")
    problems = next(f.value for f in alert.embed.fields if f.name == "Needs a human")
    assert "above the bot" in problems and "<#11>" in problems


async def test_the_server_owner_is_only_reported(tmp_path):
    cfg = ScamConfig(enabled=True, dry_run=False, log_channel_id=999)
    channels = [FakeChannel(c) for c in (10, 11)]
    guild, member, log_channel, _, _ = await run_incident(
        tmp_path, cfg=cfg, channels=channels, guild_kwargs={"owner_id": 7},
    )
    assert member.timeouts == [] and member.dms == [] and guild.bans == []
    assert all(c.deleted == [] for c in channels)
    assert log_channel.sent[0].content.startswith("@here")
