"""Whole-path tests: a message arrives -> rules run -> images fetched and fingerprinted -> action.
Only Discord's network calls are faked. Run:  python3.13 -m unittest discover -s tests -v
"""
import io
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import discord
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ScamGuard as bot  # noqa: E402
import rules  # noqa: E402
import scanner  # noqa: E402
from test_bot import Role, attachment, make_guild  # noqa: E402
from test_scanner import scene  # noqa: E402

ASPECT = 273 / 173
TRAP, EXEMPT = 66, 55


class FakeMember(SimpleNamespace):
    def __str__(self):
        return f"user{self.id}"


def jpeg(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "JPEG", quality=85)
    return buf.getvalue()


class Pipeline(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scam = jpeg(scene(77, (960, 1280)))
        self.store = scanner.ReferenceStore(Path(self.tmp.name) / "refs.json")
        self.store.load()
        self.store.add(scanner.Reference(hash=scanner.phash(scanner.load_image(self.scam)), kind="full",
                                         label="test scam"))
        self.innocent = jpeg(scene(78, (960, 1280)))
        self.calls = []

    async def asyncTearDown(self):
        self.tmp.cleanup()

    def make(self, **settings):
        values = {"guild_id": 999, "honeypot_channel_ids": [TRAP], "exempt_channel_ids": [EXEMPT],
                  "dry_run": False, "dm_members": True}
        values.update(settings)
        b = bot.ScamGuard(Path(self.tmp.name), rules.Settings(**values), self.store, rules.State())
        b.report = mock.AsyncMock()
        b.forward = mock.AsyncMock(return_value=None)
        b.schedule_banner_update = mock.Mock()
        b.search_posts = mock.AsyncMock(return_value=[])  # Discord's search, faked
        self.guild = make_guild()
        return b

    def restart(self, b):
        """A new process: same settings and data folder, state read back from state.json."""
        again = bot.ScamGuard(b.data_dir, b.settings, self.store, rules.State.load(b.data_dir / "state.json"))
        again.report, again.forward = mock.AsyncMock(), mock.AsyncMock(return_value=None)
        again.schedule_banner_update, again.search_posts = mock.Mock(), mock.AsyncMock(return_value=[])
        return again

    def gone(self):
        """Someone who already left: Discord's member lookup answers Unknown Member."""
        self.guild.get_member = lambda uid: None
        self.guild.fetch_member = mock.AsyncMock(side_effect=discord.NotFound(
            SimpleNamespace(status=404, reason="Not Found"), {"code": 10007, "message": "Unknown Member"}))
        self.guild.ban = mock.AsyncMock()
        return FakeMember(id=50, bot=False, mention="<@50>", created_at=datetime(2016, 3, 18, tzinfo=timezone.utc))

    def mod_click(self, b, perms=discord.Permissions(ban_members=True)):
        """A moderator's button click, answered with a deferral and then an edit."""
        done = []
        response = SimpleNamespace(defer=mock.AsyncMock(side_effect=lambda *a, **k: done.append(1)),
                                   is_done=lambda: bool(done))
        return SimpleNamespace(client=b, guild_id=999, guild=self.guild, user=self.member(uid=60, perms=perms),
                               response=response, message=SimpleNamespace(content="report"),
                               edit_original_response=mock.AsyncMock())

    def member(self, uid=50, perms=None):
        def track(name):
            async def call(*a, **k):
                self.calls.append(name)
            return mock.AsyncMock(side_effect=call)
        m = FakeMember(id=uid, bot=False, guild=self.guild, top_role=Role(1), roles=[], mention=f"<@{uid}>",
                       guild_permissions=perms or discord.Permissions.none(),
                       created_at=datetime(2016, 3, 18, tzinfo=timezone.utc),
                       joined_at=datetime(2023, 12, 13, tzinfo=timezone.utc),
                       ban=track("ban"), kick=track("kick"), timeout=track("timeout"), send=track("dm"))
        return m

    def message(self, author, *, image=None, content="", channel_id=10, mid=1, guild_id=999, webhook_id=None,
                mtype=discord.MessageType.default, meta=None):
        guild = self.guild
        guild.id = guild_id
        return SimpleNamespace(
            id=mid, guild=guild, author=author, webhook_id=webhook_id, type=mtype, interaction_metadata=meta,
            content=content, channel=SimpleNamespace(id=channel_id, mention=f"<#{channel_id}>", name=f"c{channel_id}"),
            attachments=[attachment()] if image else [], embeds=[], message_snapshots=[],
            delete=mock.AsyncMock(),
        )

    async def send(self, b, msg, image=None):
        b.fetch = mock.AsyncMock(return_value=image)
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await b.on_message(msg)

    def report_text(self, b, n=-1):
        return "\n".join(b.report.await_args_list[n].args[1])

    # ------------------------------------------------------------ known images
    async def test_known_scam_image_is_deleted_and_poster_softbanned(self):
        b = self.make()
        m = self.member()
        msg = self.message(m, image=True)
        await self.send(b, msg, self.scam)
        msg.delete.assert_awaited_once()
        m.ban.assert_awaited_once()
        self.guild.unban.assert_awaited_once()
        self.assertEqual(self.calls[:2], ["dm", "ban"])  # the DM goes out while they still share the server
        text = self.report_text(b)
        self.assertIn("known scam image", text)
        self.assertIn("Softbanned", text)
        self.assertEqual(b.report.await_args.args[2], [self.scam])  # forward failed, so the image is re-uploaded
        self.assertEqual(b.state.totals, {"image": 1})

    async def test_screenshot_crop_reference_still_matches(self):
        tile = scanner.center_crop(Image.open(io.BytesIO(self.scam)), ASPECT).resize((273, 173))
        self.store.refs = [scanner.Reference(hash=scanner.phash(scanner.load_image(jpeg(tile))), kind="crop",
                                             aspect=round(ASPECT, 4), label="tile")]
        b = self.make()
        m = self.member()
        await self.send(b, self.message(m, image=True), self.scam)
        m.ban.assert_awaited_once()

    async def test_unrelated_image_is_left_alone(self):
        b = self.make()
        m = self.member()
        msg = self.message(m, image=True)
        await self.send(b, msg, self.innocent)
        msg.delete.assert_not_awaited()
        m.ban.assert_not_awaited()
        b.report.assert_not_awaited()

    async def test_staff_post_is_deleted_but_not_punished(self):
        b = self.make()
        m = self.member(perms=discord.Permissions(manage_messages=True))
        msg = self.message(m, image=True)
        await self.send(b, msg, self.scam)
        msg.delete.assert_awaited_once()
        m.ban.assert_not_awaited()
        m.send.assert_not_awaited()
        self.assertIn("compromised", self.report_text(b))

    async def test_dry_run_changes_nothing_and_offers_review(self):
        b = self.make(dry_run=True)
        m = self.member()
        msg = self.message(m, image=True)
        await self.send(b, msg, self.scam)
        msg.delete.assert_not_awaited()
        m.ban.assert_not_awaited()
        m.send.assert_not_awaited()
        self.assertIn("DRY RUN", self.report_text(b))
        view = b.report.await_args.args[3]
        self.assertEqual([c.custom_id for c in view.children], ["sg:apply:image:softban:50:10:1"])

    async def test_broken_image_is_skipped_safely(self):
        b = self.make()
        msg = self.message(self.member(), image=True)
        await self.send(b, msg, b"\x89PNG\r\n\x1a\n garbage")
        msg.delete.assert_not_awaited()
        b.report.assert_not_awaited()

    # -------------------------------------------------------------------- trap
    async def test_trap_catches_text_only_posts(self):
        b = self.make()
        m = self.member()
        msg = self.message(m, content="hey whats this?", channel_id=TRAP)
        await self.send(b, msg)
        msg.delete.assert_awaited_once()
        m.ban.assert_awaited_once()
        b.fetch.assert_not_awaited()  # trap posts need no image download
        self.assertIn(msg.id, b.state.handled)
        b.schedule_banner_update.assert_called_once()
        self.assertEqual(b.state.totals, {"trap": 1})

    async def test_trap_catches_its_own_thread_creator(self):
        b = self.make()
        m = self.member()
        msg = self.message(m, content="hi", channel_id=4242)
        msg.channel.parent_id, msg.channel.owner_id = TRAP, m.id
        await self.send(b, msg)
        m.ban.assert_awaited_once()

    async def test_replies_in_someone_elses_trap_thread_are_never_punished(self):
        b = self.make()
        for mid, uid in ((1, 50), (2, 51)):  # two people take the bait
            m = self.member(uid=uid)
            msg = self.message(m, content="free gifts?", channel_id=4242, mid=mid)
            msg.channel.parent_id, msg.channel.owner_id = TRAP, 99
            await self.send(b, msg)
            msg.delete.assert_not_awaited()
            m.ban.assert_not_awaited()
            m.send.assert_not_awaited()
        self.assertEqual(b.report.await_count, 1)  # one alert per thread
        self.assertIn("Not punished", self.report_text(b))
        self.assertEqual(b.state.totals, {})

    async def test_dm_names_the_parent_channel_and_never_a_link(self):
        b = self.make()
        m = self.member()
        thread = SimpleNamespace(name="[claim here](https://free-gifts.example)", parent=SimpleNamespace(name="trap_channel"))
        await b.dm(m, "trap", "softban", thread)
        text = m.send.await_args.args[0]
        self.assertIn("#trap", text)
        self.assertNotIn("free-gifts", text)
        self.assertNotIn("://", text)
        m2 = self.member(uid=51)  # a thread whose parent isn't cached: its own name, stripped
        await b.dm(m2, "trap", "softban", SimpleNamespace(name="[x](https://evil.example/claim)"))
        text2 = m2.send.await_args.args[0]
        self.assertNotIn("://", text2)
        self.assertNotIn("evil.example", text2)
        self.assertNotIn("](", text2)

    async def test_log_readable_by_members_gets_no_scam_content(self):
        b = self.make(log_channel_id=5)
        b.report = bot.ScamGuard.report.__get__(b)
        b.forward = bot.ScamGuard.forward.__get__(b)
        member_role = SimpleNamespace(id=7, managed=False, permissions=discord.Permissions.none())
        mod_role = SimpleNamespace(id=8, managed=False, permissions=discord.Permissions(ban_members=True))
        self.guild.roles = [member_role, mod_role]
        sent = []

        async def send(text, **extra):
            sent.append((text, extra))
        log_channel = SimpleNamespace(id=5, send=send, permissions_for=lambda who: SimpleNamespace(
            view_channel=who is not None, attach_files=True))
        self.guild.get_channel_or_thread = lambda cid: log_channel if cid == 5 else SimpleNamespace(
            id=cid, mention=f"<#{cid}>", get_partial_message=lambda mid: SimpleNamespace(id=mid, delete=mock.AsyncMock()))
        self.guild.me = SimpleNamespace(top_role=Role(10))
        with mock.patch.object(bot.discord.abc, "Messageable", SimpleNamespace):
            self.assertEqual(b.log_readers(self.guild, log_channel), [member_role])
            msg = self.message(self.member(), content="scam link https://scam.example", image=True)
            self.assertIsNone(await b.forward(msg, log_channel))
            await b.report(self.guild, ["**known scam image**: x", "Text:\n```scam link https://scam.example```"],
                           [b"\x89PNG fake"])
        text, extra = sent[-1]
        self.assertNotIn("scam.example", text)
        self.assertNotIn("files", extra)

    async def test_staff_in_trap_is_ignored(self):
        b = self.make()
        m = self.member(perms=discord.Permissions(ban_members=True))
        msg = self.message(m, content="testing the trap", channel_id=TRAP)
        await self.send(b, msg)
        msg.delete.assert_not_awaited()
        b.report.assert_not_awaited()

    async def test_slash_command_reply_in_trap_punishes_the_invoker(self):
        b = self.make()
        b._connection.user = SimpleNamespace(id=1)  # ScamGuard's own user ID
        m = self.member(uid=77)
        self.guild.get_member = lambda uid: m if uid == 77 else None
        other_bot = SimpleNamespace(id=5, bot=True)
        msg = self.message(other_bot, channel_id=TRAP, mtype=discord.MessageType.chat_input_command,
                           meta=SimpleNamespace(user=SimpleNamespace(id=77)))
        await self.send(b, msg)
        msg.delete.assert_awaited_once()
        m.ban.assert_awaited_once()

    async def test_webhook_in_trap_is_deleted_and_reported_once(self):
        b = self.make()
        hook = SimpleNamespace(id=9, bot=True, display_name="Spam Hook")
        for mid in (1, 2):
            msg = self.message(hook, channel_id=TRAP, webhook_id=9, mid=mid)
            await self.send(b, msg)
            msg.delete.assert_awaited_once()
        self.assertEqual(b.report.await_count, 1)
        self.assertIn("webhook", self.report_text(b))

    # ------------------------------------------------------------------- blast
    async def test_same_text_in_three_channels_times_out_and_cleans_up(self):
        b = self.make()
        m = self.member()
        msgs = [self.message(m, content="Free nitro, claim it at https://scam.example/n", channel_id=c, mid=i)
                for i, c in enumerate((10, 11, 12), start=1)]
        for msg in msgs:
            await self.send(b, msg)
        m.timeout.assert_awaited_once()
        msgs[2].delete.assert_awaited_once()
        text = self.report_text(b)
        self.assertIn("same post across channels", text)
        self.assertIn("Deleted 3 of 3", text)
        view = b.report.await_args.args[3]
        self.assertEqual([c.custom_id for c in view.children], ["sg:untimeout:50"])

    async def test_harmless_posts_edited_into_the_same_scam_are_caught(self):
        b = self.make()
        m = self.member()
        originals = [self.message(m, content=f"a harmless long message, number {i}", channel_id=c, mid=i)
                     for i, c in enumerate((10, 11, 12), start=1)]
        for msg in originals:
            await self.send(b, msg)
        b.report.assert_not_awaited()
        for before in originals:
            after = self.message(m, content="Free nitro, claim it at https://scam.example/n",
                                 channel_id=before.channel.id, mid=before.id)
            after.edited_at = datetime.now(timezone.utc)
            with mock.patch.object(bot.discord, "Member", FakeMember):
                await b.on_raw_message_edit(SimpleNamespace(message=after, cached_message=before))
        m.timeout.assert_awaited_once()
        text = self.report_text(b)
        self.assertIn("same post across channels", text)
        self.assertIn("Deleted 3 of 3", text)

    async def test_one_message_edited_again_and_again_is_not_a_blast(self):
        b = self.make()
        m = self.member()
        before = self.message(m, content="a harmless long message to start", channel_id=10, mid=1)
        await self.send(b, before)
        for i in range(5):
            after = self.message(m, content=f"Free nitro for everyone, claim it here {i}", channel_id=10, mid=1)
            after.edited_at = datetime.now(timezone.utc)
            with mock.patch.object(bot.discord, "Member", FakeMember):
                await b.on_raw_message_edit(SimpleNamespace(message=after, cached_message=before))
            before = after
        m.timeout.assert_not_awaited()
        self.assertEqual(len(b.blasts.posts[(999, 50)]), 1)

    async def test_pins_and_link_previews_are_not_edits(self):
        b = self.make()
        b.inspect = mock.AsyncMock()
        msg = self.message(self.member(), content="Free nitro for everyone, claim it here")
        msg.edited_at = None  # Discord leaves it unset for a pin or a preview arriving
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await b.on_raw_message_edit(SimpleNamespace(message=msg, cached_message=None))
        b.inspect.assert_not_awaited()

    async def test_short_replies_in_three_channels_are_fine(self):
        b = self.make()
        m = self.member()
        for i, c in enumerate((10, 11, 12), start=1):
            await self.send(b, self.message(m, content="thanks!", channel_id=c, mid=i))
        m.timeout.assert_not_awaited()
        b.report.assert_not_awaited()

    # ------------------------------------------------------------ after a catch
    async def test_late_posts_from_a_removed_member_are_deleted_quietly(self):
        b = self.make()
        m = self.member()
        await self.send(b, self.message(m, content="hi", channel_id=TRAP, mid=1))
        late = self.message(m, content="more spam", channel_id=10, mid=2)
        await self.send(b, late)
        late.delete.assert_awaited_once()
        self.assertEqual(m.ban.await_count, 1)
        self.assertEqual(b.report.await_count, 1)

    async def test_recent_posts_are_swept_on_removal(self):
        b = self.make()
        m = self.member()
        await self.send(b, self.message(m, content="earlier text post", channel_id=10, mid=1))
        await self.send(b, self.message(m, content="hi", channel_id=TRAP, mid=2))
        self.assertIn("Also deleted 1 other recent message", self.report_text(b))

    async def test_take_action_button_applies_a_dry_run_catch(self):
        b = self.make(dry_run=True)
        m = self.member()
        self.guild.get_member = lambda uid: m if uid == 50 else None
        mod = self.member(uid=60, perms=discord.Permissions(ban_members=True))
        done = []
        response = SimpleNamespace(defer=mock.AsyncMock(side_effect=lambda *a, **k: done.append(1)),
                                   is_done=lambda: bool(done))
        interaction = SimpleNamespace(client=b, guild_id=999, guild=self.guild, user=mod, response=response,
                                      message=SimpleNamespace(content="report"),
                                      edit_original_response=mock.AsyncMock())
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.ApplyButton("trap", 50, TRAP, 1).callback(interaction)
        self.assertEqual(self.calls[:2], ["dm", "ban"])
        b.schedule_banner_update.assert_called_once()
        self.assertEqual(b.state.totals, {"trap": 1})
        self.assertIn("took action", interaction.edit_original_response.await_args.kwargs["content"])

    async def test_take_action_needs_the_matching_permission(self):
        b = self.make(dry_run=True)
        mod = self.member(uid=60, perms=discord.Permissions(moderate_members=True))  # no Ban Members
        response = SimpleNamespace(send_message=mock.AsyncMock())
        interaction = SimpleNamespace(client=b, guild_id=999, guild=self.guild, user=mod, response=response)
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.ApplyButton("trap", 50, TRAP, 1).callback(interaction)
        self.assertIn("Ban Members", response.send_message.await_args.args[0])

    async def test_trap_add_counts_uncached_authors(self):
        b = self.make()
        staff = self.member(uid=61, perms=discord.Permissions(ban_members=True))
        msgs = [SimpleNamespace(author=SimpleNamespace(id=i, bot=False), webhook_id=None) for i in (1, 2, 3, 3)]
        msgs += [SimpleNamespace(author=staff, webhook_id=None),
                 SimpleNamespace(author=SimpleNamespace(id=4, bot=True), webhook_id=None)]

        async def history(**kwargs):
            for msg in msgs:
                yield msg
        with mock.patch.object(bot.discord, "Member", FakeMember):
            self.assertEqual(await bot.recent_posters(SimpleNamespace(history=history), b), 3)

    async def test_console_log_never_holds_message_text(self):
        b = self.make()
        lines = b.describe(self.message(self.member(), content="secret words here", channel_id=10),
                           self.member(), "trap", "posted in a trap channel")
        self.assertIn("Text:\n```secret words here```", lines)
        with self.assertLogs("scamguard", level="INFO") as logs:
            await bot.ScamGuard.report(b, self.guild, lines)
        self.assertNotIn("secret words", "\n".join(logs.output))
        self.assertIn("trap channel", "\n".join(logs.output))

    async def test_scam_image_arriving_in_an_edit_is_caught(self):
        b = self.make()
        m = self.member()
        before = self.message(m, content="look https://example.com/x")
        after = self.message(m, content="look https://example.com/x", image=True)
        b.fetch = mock.AsyncMock(return_value=self.scam)
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await b.on_raw_message_edit(SimpleNamespace(message=after, cached_message=before))
        after.delete.assert_awaited_once()
        m.ban.assert_awaited_once()

    async def test_edit_to_a_message_outside_the_cache_is_still_checked(self):
        b = self.make()
        m = self.member()
        after = self.message(m, content="look https://example.com/x", image=True)
        b.fetch = mock.AsyncMock(return_value=self.scam)
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await b.on_raw_message_edit(SimpleNamespace(message=after, cached_message=None))
        after.delete.assert_awaited_once()
        m.ban.assert_awaited_once()

    async def test_edit_that_adds_no_image_downloads_nothing(self):
        b = self.make()
        m = self.member()
        before = self.message(m, content="look", image=True)
        after = self.message(m, content="look, edited", image=True)
        b.fetch = mock.AsyncMock(return_value=self.scam)
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await b.on_raw_message_edit(SimpleNamespace(message=after, cached_message=before))
        b.fetch.assert_not_awaited()

    async def test_cleanup_deletes_trap_posts_and_the_burst_but_not_later_chat(self):
        b = self.make()
        caught = 1_800_000_000.0
        def post(channel, offset):
            return {"id": str(bot.snowflake_at(caught + offset)), "channel_id": str(channel), "author": {"id": "50"}}
        keep_later, keep_old = post(10, 2700), post(10, -7200)
        b.search_posts = mock.AsyncMock(return_value=[post(TRAP, 3600), post(10, -1800), post(10, 60), keep_later, keep_old])
        deleted = []
        self.guild.get_channel_or_thread = lambda cid: SimpleNamespace(
            id=cid, get_partial_message=lambda mid: SimpleNamespace(id=mid, delete=mock.AsyncMock(
                side_effect=lambda *a, **k: deleted.append(mid))))
        n = await b.cleanup(self.guild, 50, bot.snowflake_at(caught), "softban")
        self.assertEqual(n, 3)
        self.assertNotIn(int(keep_later["id"]), deleted)
        self.assertNotIn(int(keep_old["id"]), deleted)

    async def test_search_waits_out_indexing_and_keeps_only_the_author(self):
        b = self.make()
        b.http.request = mock.AsyncMock(side_effect=[
            {"retry_after": 0},
            {"total_results": 2, "messages": [[{"id": "1", "channel_id": "10", "author": {"id": "50"}}],
                                              [{"id": "2", "channel_id": "10", "author": {"id": "99"}}]]}])
        found = await bot.ScamGuard.search_posts(b, self.guild, 50, 1_800_000_000.0)
        self.assertEqual([m["id"] for m in found], ["1"])
        params = dict(b.http.request.await_args.kwargs["params"])
        self.assertEqual((params["author_id"], params["limit"], params["sort_by"], params["sort_order"]),
                         ("50", "25", "timestamp", "asc"))

    async def test_search_pages_by_the_total_and_stops_at_the_cap(self):
        b = self.make()
        page = [[{"id": str(i), "channel_id": "10", "author": {"id": "50"}}] for i in range(3)]  # a short page
        b.http.request = mock.AsyncMock(return_value={"total_results": 1000, "messages": page})
        found = await b.search_messages(self.guild, [("has", "image")], 1_800_000_000.0, cap=100)
        self.assertEqual(b.http.request.await_count, 4)  # 100 / 25 pages, though each page came back short
        self.assertEqual(len(found), 12)
        offsets = [dict(c.kwargs["params"])["offset"] for c in b.http.request.await_args_list]
        self.assertEqual(offsets, ["0", "25", "50", "75"])

    async def test_queued_cleanup_survives_in_state_and_runs_when_due(self):
        b = self.make()
        b.queue_cleanup(999, 50, 1234, "softban")
        saved = rules.State.load(Path(self.tmp.name) / "state.json")
        self.assertEqual(saved.cleanups[0][:4], [999, 50, 1234, "softban"])
        b.state.cleanups[0][4] = 0  # due now
        b.cleanup = mock.AsyncMock(return_value=2)
        b.get_guild = lambda gid: self.guild
        await b.run_cleanups()
        b.cleanup.assert_awaited_once_with(self.guild, 50, 1234, "softban")
        self.assertEqual(b.state.cleanups, [])

    async def test_console_log_names_members_and_channels(self):
        b = self.make()
        m = self.member()
        with self.assertLogs("scamguard", level="INFO") as logs:
            await bot.ScamGuard.report(b, self.guild, [f"**trap channel**: <@{m.id}> in <#{TRAP}>"], users={m.id: m})
        self.assertIn("@user50 (50)", logs.output[0])
        self.assertIn(f"#chan{TRAP} ({TRAP})", logs.output[0])

    # ------------------------------------------------------ restarts and gaps
    async def test_already_reported_survives_a_restart_but_not_a_rejoin(self):
        b = self.make()
        m = self.member()  # joined in 2023
        await self.send(b, self.message(m, content="hi", channel_id=TRAP, mid=1))
        b = self.restart(b)
        again = self.message(m, content="still here", channel_id=TRAP, mid=2)
        await self.send(b, again)
        again.delete.assert_awaited_once()  # cleaned up quietly
        self.assertEqual(m.ban.await_count, 1)
        b.report.assert_not_awaited()
        m.joined_at = datetime.now(timezone.utc)  # they rejoined after the catch: a new case
        await self.send(b, self.message(m, content="back again", channel_id=TRAP, mid=3))
        self.assertEqual(m.ban.await_count, 2)

    async def test_every_new_session_catches_up_from_the_last_connected_minute(self):
        b = self.make()
        b.announce, b.catch_up = mock.AsyncMock(), mock.AsyncMock()
        b.state.last_seen = 1000.0
        with mock.patch.object(bot.ScamGuard, "guilds", new_callable=mock.PropertyMock, return_value=[self.guild]):
            await b.on_ready()
            b.catch_up.assert_awaited_once_with(self.guild, 1000.0)
            await b.housekeep()
            stamped = b.state.last_seen
            self.assertGreater(stamped, 1000.0)
            await b.on_disconnect()
            await b.housekeep()  # disconnected: the stamp stays where the connection ended
            self.assertEqual(b.state.last_seen, stamped)
            await b.on_ready()   # Discord opened a new session instead of resuming the old one
        self.assertEqual(b.catch_up.await_args.args, (self.guild, stamped))
        b.announce.assert_awaited_once()

    async def test_catch_up_bans_a_trap_poster_who_already_left(self):
        b = self.make()
        departed = self.gone()
        msg = self.message(departed, content="hi", channel_id=TRAP, mid=7)

        async def history(**kwargs):
            yield msg
        self.guild.get_channel_or_thread(TRAP).history = history
        b.cleanup = mock.AsyncMock(return_value=0)
        b.catch_up_images = mock.AsyncMock(return_value=(4, 0))
        with self.assertLogs("scamguard", level="INFO") as logs:
            await b.catch_up(self.guild, time.time() - 120)
        self.assertIn("1 trap post(s), 4 image post(s) checked, 0 known scam(s)", "\n".join(logs.output))
        msg.delete.assert_awaited_once()
        self.assertEqual(self.guild.ban.await_args.args[0].id, 50)
        self.guild.unban.assert_awaited_once()  # softban: purged, free to rejoin
        text = self.report_text(b)
        self.assertIn("left the server before ScamGuard saw this post", text)
        self.assertIn("Softbanned by ID", text)
        self.assertIn(7, b.state.handled)
        b.catch_up_images.assert_awaited_once()

    async def test_catch_up_checks_images_posted_while_offline(self):
        b = self.make()
        m = self.member()
        self.guild.get_member = lambda uid: m if uid == 50 else None
        msg = self.message(m, image=True, channel_id=10, mid=7)
        b.search_messages = mock.AsyncMock(return_value=[{"id": "7", "channel_id": "10"},
                                                         {"id": "8", "channel_id": str(TRAP)}])
        b.fetch = mock.AsyncMock(return_value=self.scam)
        with mock.patch.object(b._connection, "create_message", lambda *, channel, data: msg):
            self.assertEqual(await b.catch_up_images(self.guild, time.time() - 120), (2, 1))
        self.assertEqual(b.search_messages.await_args.args[1], [("has", "image"), ("author_type", "user")])
        msg.delete.assert_awaited_once()
        m.ban.assert_awaited_once()
        self.assertEqual(b.fetch.await_count, 1)  # the trap channel's post was left to the history read
        self.assertIn("known scam image", self.report_text(b))

    async def test_take_action_applies_the_action_its_report_named(self):
        b = self.make(dry_run=True)
        m = self.member()
        self.guild.get_member = lambda uid: m if uid == 50 else None
        b.settings.honeypot_action = "ban"  # changed after the report went out
        click = self.mod_click(b, discord.Permissions(ban_members=True, kick_members=True))
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.ApplyButton("trap", 50, TRAP, 1, "kick").callback(click)
        m.kick.assert_awaited_once()
        m.ban.assert_not_awaited()

    async def test_take_action_on_someone_who_left_bans_by_id(self):
        b = self.make(dry_run=True)
        self.gone()
        b.cleanup = mock.AsyncMock(return_value=2)
        button = bot.ApplyButton("trap", 50, TRAP, 1, "ban")
        discord.ui.View(timeout=None).add_item(button)
        click = self.mod_click(b)
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await button.callback(click)
        self.assertEqual(self.guild.ban.await_args.args[0].id, 50)
        edit = click.edit_original_response.await_args.kwargs
        self.assertIn("They had already left. Banned by ID", edit["content"])
        self.assertIn("Also deleted 2", edit["content"])
        self.assertEqual([c.custom_id for c in edit["view"].children], ["sg:unban:50"])
        self.assertEqual(b.state.totals, {"trap": 1})

    async def test_take_action_changes_nothing_when_discord_cant_look_them_up(self):
        b = self.make(dry_run=True)
        self.gone()
        self.guild.fetch_member.side_effect = discord.HTTPException(SimpleNamespace(status=503, reason="x"), "down")
        b.delete = mock.AsyncMock(return_value=0)
        click = self.mod_click(b)
        click.followup = SimpleNamespace(send=mock.AsyncMock())
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.ApplyButton("trap", 50, TRAP, 1, "ban").callback(click)
        self.guild.ban.assert_not_awaited()  # an outage doesn't make them look like they left
        b.delete.assert_not_awaited()
        self.assertIn("nothing was done", click.followup.send.await_args.args[0])
        self.assertEqual(b.state.totals, {})

    # ------------------------------------------------- the safety brake, dry run
    async def test_brake_on_means_no_dm_and_no_removal(self):
        b = self.make()
        b.state.braked.append(999)
        m = self.member()
        msg = self.message(m, image=True)
        await self.send(b, msg, self.scam)
        msg.delete.assert_awaited_once()
        m.send.assert_not_awaited()  # 2.0 told them they were removed, then didn't remove them
        m.ban.assert_not_awaited()
        self.assertIn("Safety brake is on", self.report_text(b))

    async def test_dry_run_never_deletes_after_a_live_catch(self):
        b = self.make()
        m = self.member()
        await self.send(b, self.message(m, content="hi", channel_id=TRAP, mid=1))
        b.settings.dry_run = True  # switched within the two minutes that follow a removal
        late = self.message(m, content="a later post", channel_id=10, mid=2)
        await self.send(b, late)
        late.delete.assert_not_awaited()

    async def test_failed_ban_lets_a_later_catch_try_again(self):
        b = self.make()
        m = self.member()
        m.ban = mock.AsyncMock(side_effect=discord.HTTPException(SimpleNamespace(status=500, reason="x"), "boom"))
        await self.send(b, self.message(m, content="hi", channel_id=TRAP, mid=1))
        self.assertIn("failed (HTTP 500)", self.report_text(b))
        b.condemned.clear()  # the two minutes of quiet deletes have passed
        await self.send(b, self.message(m, content="again", channel_id=TRAP, mid=2))
        self.assertEqual(m.ban.await_count, 2)
        self.assertEqual(b.report.await_count, 2)

    # ------------------------------------------------- downloads, labels, status
    async def test_link_preview_download_is_tried_again(self):
        b = self.make()
        preview = bot.ImageSource("preview", ("https://images-ext-1.discordapp.net/external/x/https/a.example/p.png",),
                                  (0.0, 0.0))
        b.fetch = mock.AsyncMock(side_effect=[bot.DownloadError("HTTP 401", retry=True), self.scam])
        with self.assertLogs("scamguard", level="INFO") as logs:
            scan = await b.scan_one(preview, (), " from @user50 (50) in #c10 (10)")
        self.assertIsNotNone(scan)
        out = "\n".join(logs.output)
        self.assertIn("failed (HTTP 401), trying again in 0s", out)
        self.assertIn("downloaded on try 2", out)
        self.assertIn("from @user50 (50) in #c10 (10)", out)
        b.fetch = mock.AsyncMock(side_effect=bot.DownloadError("file too large"))
        self.assertIsNone(await b.scan_one(preview, ()))
        self.assertEqual(b.fetch.await_count, 1)  # another try can't fix that

    async def test_fingerprint_label_names_the_channel_the_image_came_from(self):
        b = self.make()
        click = SimpleNamespace(client=b, guild=self.guild, user=self.member(uid=60))
        msg = self.message(self.member(), image=True, channel_id=10, mid=5)
        msg.jump_url = "https://discord.com/channels/999/10/5"
        b.fetch = mock.AsyncMock(return_value=self.innocent)
        _, added = await bot.learn_from(click, msg)
        self.assertTrue(added)
        self.assertEqual(self.store.refs[-1].label, "a.png from #chan10")
        forward = self.message(self.member(), channel_id=5, mid=6)  # a copy forwarded into the log channel
        forward.message_snapshots = [SimpleNamespace(attachments=[attachment(id=9)], embeds=[])]
        forward.reference, forward.jump_url = SimpleNamespace(channel_id=20), "https://discord.com/channels/999/5/6"
        b.fetch = mock.AsyncMock(return_value=jpeg(scene(79, (960, 1280))))
        await bot.learn_from(click, forward)
        self.assertEqual(self.store.refs[-1].label, "a.png from #chan20")

    async def test_status_finds_reports_still_waiting_for_take_action(self):
        b = self.make(log_channel_id=5)
        b._connection.user = SimpleNamespace(id=1)

        def post(author, mid, custom_ids):
            return SimpleNamespace(author=SimpleNamespace(id=author), jump_url=f"https://discord.com/channels/999/5/{mid}",
                                   components=[SimpleNamespace(children=[SimpleNamespace(custom_id=c) for c in custom_ids])])
        waiting = post(1, 2, ["sg:apply:trap:softban:50:66:1"])
        older = post(1, 3, ["sg:apply:trap:50:66:1"])  # posted by 2.0
        posts = [waiting, post(1, 4, ["sg:unban:51"]), post(9, 5, ["sg:apply:trap:52:66:1"]), older]

        async def history(**kwargs):
            for p in posts:
                yield p
        log_channel = SimpleNamespace(id=5, history=history)
        self.guild.get_channel_or_thread = lambda cid: log_channel
        with mock.patch.object(bot.discord.abc, "Messageable", SimpleNamespace):
            self.assertEqual(await b.pending_reviews(self.guild), [waiting.jump_url, older.jump_url])

    async def test_ignored_cases(self):
        cases = {
            "exempt channel": dict(channel_id=EXEMPT),
            "other server": dict(guild_id=123),
            "system message": dict(mtype=discord.MessageType.new_member),
        }
        for name, kw in cases.items():
            with self.subTest(name):
                b = self.make()
                msg = self.message(self.member(), image=True, **kw)
                await self.send(b, msg, self.scam)
                msg.delete.assert_not_awaited()
                b.fetch.assert_not_awaited()  # nothing is even downloaded
        b = self.make()
        msg = self.message(SimpleNamespace(id=5, bot=True), image=True)
        await self.send(b, msg, self.scam)
        b.fetch.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
