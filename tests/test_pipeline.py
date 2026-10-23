"""Whole-path tests: a message arrives -> rules run -> images fetched and fingerprinted -> action.
Only Discord's network calls are faked. Run:  python3.13 -m unittest discover -s tests -v
"""
import io
import os
import sys
import tempfile
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
        self.assertEqual([c.custom_id for c in view.children], ["sg:apply:image:50:10:1"])

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
            await b.on_message_edit(before, after)
        after.delete.assert_awaited_once()
        m.ban.assert_awaited_once()

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
        params = b.http.request.await_args.kwargs["params"]
        self.assertEqual((params["author_id"], params["limit"]), ("50", 25))

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
