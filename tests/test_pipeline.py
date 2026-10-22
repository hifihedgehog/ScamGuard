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

    async def test_trap_catches_threads_under_the_trap(self):
        b = self.make()
        m = self.member()
        msg = self.message(m, content="hi", channel_id=4242)
        msg.channel.parent_id = TRAP
        await self.send(b, msg)
        m.ban.assert_awaited_once()

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
