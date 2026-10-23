"""Tests for URL safety, config, punishment, the safety brake and shared-token safety.
Run from the project folder:  python3.13 -m unittest discover -s tests -v
"""
import asyncio
import io
import logging
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import discord

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ScamGuard as bot  # noqa: E402
import rules  # noqa: E402
import scanner  # noqa: E402


class UrlSafety(unittest.TestCase):
    def test_only_discord_media_hosts(self):
        ok = [
            "https://cdn.discordapp.com/attachments/1/2/a.png?ex=1&is=2&hm=3",
            "https://media.discordapp.net/attachments/1/2/a.png",
            "https://images-ext-1.discordapp.net/external/abc/https/example.com/a.png",
            "https://CDN.DISCORDAPP.COM/x.png",
        ]
        bad = [
            None, "", "http://cdn.discordapp.com/a.png", "https://cdn.discordapp.com.evil.com/a.png",
            "https://evil.com/cdn.discordapp.com/a.png", "https://evil.com/?u=https://cdn.discordapp.com",
            "https://cdn.discordapp.com@evil.com/a.png", "https://user@cdn.discordapp.com/a.png",
            "https://cdn.discordapp.com:8443/a.png", "https://images-ext-1.discordapp.net.evil.com/a.png",
            "https://xmedia.discordapp.net/a.png", "ftp://cdn.discordapp.com/a.png",
            "https://cdn.discordapp.com:99999/a.png", "https://127.0.0.1/a.png", "file:///etc/passwd",
        ]
        for url in ok:
            self.assertTrue(bot.is_discord_media(url), url)
        for url in bad:
            self.assertFalse(bot.is_discord_media(url), url)

    def test_rendition_url_keeps_signature_and_scales(self):
        url = bot.rendition_url("https://media.discordapp.net/attachments/1/2/a.png?ex=aa&is=bb&hm=cc&width=5",
                                4000, 2000)
        q = parse_qs(urlsplit(url).query)
        self.assertEqual((q["ex"], q["is"], q["hm"]), (["aa"], ["bb"], ["cc"]))
        self.assertEqual((q["width"], q["height"], q["format"]), (["1024"], ["512"], ["webp"]))
        self.assertIsNone(bot.rendition_url("https://evil.com/a.png", 100, 100))
        self.assertIsNone(bot.rendition_url("https://media.discordapp.net/a.png", None, None))
        small = parse_qs(urlsplit(bot.rendition_url("https://media.discordapp.net/a.png", 300, 200)).query)
        self.assertEqual((small["width"], small["height"]), (["300"], ["200"]))


def attachment(**over):
    data = {"id": 1, "size": 1000, "filename": "a.png", "url": "https://cdn.discordapp.com/attachments/1/2/a.png",
            "proxy_url": "https://media.discordapp.net/attachments/1/2/a.png", "content_type": "image/png",
            "width": 800, "height": 600}
    data.update(over)
    return discord.Attachment(data=data, state=SimpleNamespace(http=None))


class Sources(unittest.TestCase):
    def test_attachment_sources(self):
        src = bot.attachment_source(attachment())
        self.assertEqual(len(src.urls), 2)  # downscaled copy first, then original
        self.assertIn("format=webp", src.urls[0])
        self.assertIsNone(bot.attachment_source(attachment(content_type="video/mp4", filename="a.mp4")))
        self.assertIsNone(bot.attachment_source(attachment(content_type="text/plain", filename="a.txt",
                                                           width=None, height=None)))
        huge = bot.attachment_source(attachment(size=bot.MAX_DOWNLOAD_BYTES + 1))
        self.assertEqual(len(huge.urls), 1)  # never downloads an oversized original
        evil = bot.attachment_source(attachment(url="https://evil.com/a.png", proxy_url="https://evil.com/a.png"))
        self.assertIsNone(evil)

    def test_forwarded_and_embedded_images_are_found(self):
        embed = discord.Embed.from_dict({"type": "image", "thumbnail": {
            "url": "https://example.com/x.png",
            "proxy_url": "https://images-ext-1.discordapp.net/external/a/https/example.com/x.png"}})
        snap = SimpleNamespace(attachments=[attachment(id=2)], embeds=[])
        msg = SimpleNamespace(attachments=[attachment()], embeds=[embed], message_snapshots=[snap])
        self.assertEqual(len(bot.image_sources(msg)), 3)
        # Only link previews get tried again: Discord's media proxy can refuse a new one for a few seconds.
        self.assertEqual([s.retries for s in bot.image_sources(msg)], [(), (), bot.PREVIEW_RETRIES])


class Edits(unittest.TestCase):
    def test_only_a_fresh_text_change_counts_as_an_edit(self):
        now = datetime.now(timezone.utc)

        def msg(text, edited_at=None):
            return SimpleNamespace(content=text, edited_at=edited_at)
        self.assertTrue(bot.text_edited(msg("old text"), msg("new text", now)))
        self.assertTrue(bot.text_edited(None, msg("new text", now)))  # the old version wasn't cached
        self.assertFalse(bot.text_edited(msg("same text"), msg("same text", now)))  # a preview after an edit
        self.assertFalse(bot.text_edited(None, msg("pinned")))  # no stamp: a pin or a preview
        self.assertFalse(bot.text_edited(None, msg("edited long ago", now - timedelta(hours=1))))


class Startup(unittest.TestCase):
    def test_token_from_file_and_env_cleanup(self):
        with mock.patch.dict(os.environ, {"DISCORD_TOKEN": "abc.def"}, clear=True):
            self.assertEqual(bot.read_token(), "abc.def")
            self.assertNotIn("DISCORD_TOKEN", os.environ)
        missing = {"DISCORD_TOKEN_FILE": "/nonexistent/token"}
        with mock.patch.dict(os.environ, missing, clear=True), self.assertRaises(bot.ConfigError):
            bot.read_token()

    def test_first_run_saves_defaults_then_keeps_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            s = bot.load_settings(folder)
            self.assertEqual((s.guild_id, s.dry_run, s.honeypot_action, s.image_action, s.blast_action),
                             (0, True, "softban", "softban", "timeout"))
            self.assertEqual((s.blast_channels, s.blast_seconds, s.purge_hours, s.match_threshold), (3, 10, 1, 48))
            rules.Settings(guild_id=5, dry_run=False).save(folder / "settings.json")
            self.assertEqual((bot.load_settings(folder).guild_id, bot.load_settings(folder).dry_run), (5, False))


class Messages(unittest.TestCase):
    def test_dm_text(self):
        soft = bot.dm_text("Example Server", "trap", "softban", "trap-channel", 24,
                           "https://discord.gg/example")
        self.assertIn("removed from Example Server", soft)
        self.assertIn("#trap-channel", soft)
        self.assertIn("https://discord.gg/example", soft)
        self.assertNotIn("welcome back", bot.dm_text("Example Server", "image", "ban", "x", 24, "https://discord.gg/x"))
        self.assertIn("timed out in Example Server for 24 hours",
                      bot.dm_text("Example Server", "blast", "timeout", "x", 24, ""))
        self.assertIn("welcome back.", bot.dm_text("G", "trap", "kick", "x", 24, ""))

    def test_banner_text_follows_action(self):
        self.assertIn("removed from the server", bot.banner_text("softban"))
        self.assertIn("banned", bot.banner_text("ban"))
        self.assertIn("is deleted", bot.banner_text("delete"))

    def test_rejoin_link(self):
        b = make_bot()
        guild = SimpleNamespace(vanity_url_code="example")
        self.assertEqual(b.rejoin_link(guild), "https://discord.gg/example")  # automatic
        self.assertEqual(b.rejoin_link(SimpleNamespace(vanity_url_code=None)), "")
        b.settings.rejoin_invite = "https://discord.gg/other"
        self.assertEqual(b.rejoin_link(guild), "https://discord.gg/other")
        b.settings.rejoin_invite = "none"
        self.assertEqual(b.rejoin_link(guild), "")


# ------------------------------------------------------------------ fakes
class Role:
    def __init__(self, position, rid=0):
        self.position, self.id = position, rid

    def __gt__(self, other):
        return self.position > other.position


def make_guild(owner_id=1, my_position=10):
    guild = SimpleNamespace(id=999, owner_id=owner_id, name="test", unban=mock.AsyncMock(), get_member=lambda uid: None)
    guild.me = SimpleNamespace(top_role=Role(my_position))
    channels = {}

    def get_channel_or_thread(cid):
        ch = channels.setdefault(cid, SimpleNamespace(id=cid, mention=f"<#{cid}>", name=f"chan{cid}"))
        ch.get_partial_message = lambda mid: SimpleNamespace(id=mid, delete=mock.AsyncMock())
        return ch
    guild.get_channel_or_thread = get_channel_or_thread
    return guild


def make_member(guild, uid=50, position=1, perms=None, roles=()):
    return SimpleNamespace(id=uid, guild=guild, top_role=Role(position), roles=list(roles),
                           guild_permissions=perms or discord.Permissions.none(),
                           timeout=mock.AsyncMock(), kick=mock.AsyncMock(), ban=mock.AsyncMock())


def make_bot(**settings):
    tmp = Path(tempfile.mkdtemp())
    values = {"guild_id": 999, "dry_run": False}
    values.update(settings)
    return bot.ScamGuard(tmp, rules.Settings(**values), scanner.ReferenceStore(tmp / "refs.json"), rules.State())


class Punishment(unittest.IsolatedAsyncioTestCase):
    async def test_softban_bans_with_purge_then_unbans(self):
        b, g = make_bot(), make_guild()
        m = make_member(g)
        out = await b.punish(m, "softban", "trap")
        m.ban.assert_awaited_once()
        self.assertEqual(m.ban.await_args.kwargs["delete_message_seconds"], 3600)
        g.unban.assert_awaited_once()
        self.assertTrue(out.applied)
        self.assertFalse(out.banned)
        self.assertIn("Softbanned", out.text)

    async def test_failed_unban_reports_still_banned(self):
        b, g = make_bot(), make_guild()
        g.unban.side_effect = discord.HTTPException(SimpleNamespace(status=500, reason="x"), "boom")
        out = await b.punish(make_member(g), "softban", "trap")
        self.assertTrue(out.banned)
        self.assertIn("still banned", out.text)

    async def test_unknown_ban_on_the_unban_step_counts_as_unbanned(self):
        b, g = make_bot(), make_guild()
        g.unban.side_effect = discord.NotFound(SimpleNamespace(status=404, reason="Not Found"),
                                               {"code": 10026, "message": "Unknown Ban"})
        out = await b.punish(make_member(g), "softban", "trap")
        self.assertFalse(out.banned)
        self.assertIn("Softbanned", out.text)

    async def test_never_punishes_staff_owner_exempt_or_higher_roles(self):
        b, g = make_bot(exempt_role_ids=[77]), make_guild(owner_id=50)
        cases = {
            "owner": make_member(g, uid=50),
            "manage_messages": make_member(make_guild(), perms=discord.Permissions(manage_messages=True)),
            "ban_members": make_member(make_guild(), perms=discord.Permissions(ban_members=True)),
            "exempt role": make_member(make_guild(), roles=[Role(1, rid=77)]),
            "higher role": make_member(make_guild(), position=20),
        }
        for name, m in cases.items():
            with self.subTest(name):
                out = await b.punish(m, "ban", "image")
                m.ban.assert_not_awaited()
                self.assertFalse(out.applied)

    async def test_safety_brake_stops_image_and_blast_but_not_trap(self):
        b, g = make_bot(brake_limit=3), make_guild()
        members = [make_member(g, uid=100 + i) for i in range(5)]
        outs = [await b.punish(m, "kick", "image") for m in members]
        self.assertEqual(sum(m.kick.await_count for m in members), 3)
        self.assertTrue(outs[2].braked)
        self.assertIn("Safety brake engaged", outs[2].text)
        self.assertIn("Safety brake is on", outs[3].text)
        self.assertIn("Safety brake is on", (await b.punish(make_member(g, uid=200), "kick", "blast")).text)
        trap = [make_member(g, uid=300 + i) for i in range(5)]
        for m in trap:
            await b.punish(m, "kick", "trap")
        self.assertEqual(sum(m.kick.await_count for m in trap), 5)

    async def test_delete_only_action(self):
        b, g = make_bot(), make_guild()
        m = make_member(g)
        out = await b.punish(m, "delete", "image")
        for fn in (m.ban, m.kick, m.timeout):
            fn.assert_not_awaited()
        self.assertFalse(out.applied)

    async def test_brake_holds_when_catches_arrive_together(self):
        b, g = make_bot(brake_limit=3), make_guild()
        members = [make_member(g, uid=100 + i) for i in range(6)]

        async def slow(**kwargs):
            await asyncio.sleep(0.05)  # Discord takes a moment to answer
        for m in members:
            m.kick = mock.AsyncMock(side_effect=slow)
        outs = await asyncio.gather(*(b.punish(m, "kick", "image") for m in members))
        self.assertEqual(sum(m.kick.await_count for m in members), 3)
        self.assertEqual(sum(o.braked for o in outs), 1)

    async def test_brake_and_its_count_survive_a_restart(self):
        b, g = make_bot(brake_limit=2), make_guild()
        await b.punish(make_member(g, uid=100), "kick", "image")

        def restarted():
            return bot.ScamGuard(b.data_dir, b.settings, b.store, rules.State.load(b.data_dir / "state.json"))
        later = restarted()
        self.assertEqual(len(later.state.punishments), 1)
        self.assertTrue((await later.punish(make_member(g, uid=101), "kick", "image")).braked)
        again = restarted()
        self.assertTrue(again.is_braked(999))
        self.assertIn("Safety brake is on", (await again.punish(make_member(g, uid=102), "kick", "image")).text)
        self.assertTrue(again.release_brake(999))
        self.assertEqual(rules.State.load(b.data_dir / "state.json").braked, [])

    async def test_removal_discord_refuses_is_taken_back_off_the_count(self):
        b, g = make_bot(brake_limit=2), make_guild()
        m = make_member(g)
        m.kick.side_effect = discord.HTTPException(SimpleNamespace(status=500, reason="x"), "boom")
        out = await b.punish(m, "kick", "image")
        self.assertTrue(out.retry)
        self.assertEqual(b.state.punishments, [])
        m.kick.side_effect = discord.Forbidden(SimpleNamespace(status=403, reason="Forbidden"), "no")
        out = await b.punish(m, "kick", "image")
        self.assertFalse(out.retry)  # a missing permission stays missing
        self.assertIn("missing permission", out.text)

    async def test_someone_who_left_is_banned_by_id(self):
        b, g = make_bot(), make_guild()
        g.ban = mock.AsyncMock()
        b.cleanup = mock.AsyncMock(return_value=3)
        out = await b.punish_departed(g, 42, "ban", "image", 1234)
        self.assertEqual(g.ban.await_args.args[0].id, 42)
        self.assertEqual(g.ban.await_args.kwargs["delete_message_seconds"], 3600)
        self.assertTrue(out.applied and out.banned)
        self.assertIn("Also deleted 3", out.text)
        g.unban.assert_not_awaited()
        soft = await b.punish_departed(g, 43, "softban", "trap", 1234)
        g.unban.assert_awaited_once()
        self.assertFalse(soft.banned)
        kick = await b.punish_departed(g, 44, "kick", "trap", 1234)
        self.assertEqual(g.ban.await_count, 2)  # nothing to kick, but their posts are still cleared
        self.assertIn("Nobody to kick", kick.text)
        b.cleanup.assert_awaited_with(g, 44, 1234, "kick")


class SharedTokenSafety(unittest.IsolatedAsyncioTestCase):
    """If someone reuses another bot's token, ScamGuard must not damage that bot."""

    async def test_never_overwrites_another_bots_commands(self):
        cases = {
            "empty server": ([], True),
            "only ours (restart)": ([SimpleNamespace(name="scamguard")], True),
            "another bot's commands": ([SimpleNamespace(name="ping"), SimpleNamespace(name="scamguard")], False),
        }
        for name, (existing, should_sync) in cases.items():
            with self.subTest(name):
                b = make_bot()
                with mock.patch.object(b.tree, "fetch_commands", mock.AsyncMock(return_value=existing)), \
                        mock.patch.object(b.tree, "sync", mock.AsyncMock()) as sync:
                    await b.sync_commands(999)
                self.assertEqual(sync.await_count, int(should_sync))

    async def test_setup_registers_commands_in_the_bound_server_only(self):
        b = make_bot()
        with mock.patch.object(b.tree, "fetch_commands", mock.AsyncMock(return_value=[])), \
                mock.patch.object(b.tree, "sync", mock.AsyncMock()) as sync:
            await b.setup_hook()
        b.housekeeper.cancel()
        await b.web.close()
        self.assertEqual([call.kwargs["guild"].id for call in sync.await_args_list], [999])

    async def test_unbound_bot_registers_nothing_at_startup(self):
        b = make_bot(guild_id=0)
        with mock.patch.object(b.tree, "fetch_commands", mock.AsyncMock(return_value=[])), \
                mock.patch.object(b.tree, "sync", mock.AsyncMock()) as sync:
            await b.setup_hook()
        b.housekeeper.cancel()
        await b.web.close()
        sync.assert_not_awaited()

    async def test_unlisted_servers_are_ignored_not_left(self):
        b = make_bot()
        b.announce = mock.AsyncMock()
        b.catch_up = mock.AsyncMock()
        other = SimpleNamespace(id=1, name="someone else's server", leave=mock.AsyncMock())
        mine = SimpleNamespace(id=999, name="mine", leave=mock.AsyncMock())
        with mock.patch.object(bot.ScamGuard, "guilds", new_callable=mock.PropertyMock, return_value=[other, mine]):
            await b.on_ready()
        other.leave.assert_not_awaited()
        mine.leave.assert_not_awaited()
        b.announce.assert_awaited_once_with(mine)
        b.catch_up.assert_awaited_once_with(mine, 0.0)
        await b.on_guild_join(other)
        other.leave.assert_not_awaited()


class Binding(unittest.IsolatedAsyncioTestCase):
    def quiet(self, b):
        b.announce, b.catch_up, b.sync_commands = mock.AsyncMock(), mock.AsyncMock(), mock.AsyncMock()
        b._owner_ids = {42}  # the application owner's user ID
        return b

    @staticmethod
    def server(gid, owner_present=True):
        missing = discord.NotFound(SimpleNamespace(status=404, reason="Not Found"),
                                   {"code": 10007, "message": "Unknown Member"})
        return SimpleNamespace(id=gid, name=f"server{gid}", owner_id=42 if owner_present else 5,
                               get_member=lambda uid: None, fetch_member=mock.AsyncMock(side_effect=missing))

    async def test_binds_to_the_only_server_and_saves_it(self):
        b = self.quiet(make_bot(guild_id=0))
        mine = self.server(999)
        with mock.patch.object(bot.ScamGuard, "guilds", new_callable=mock.PropertyMock, return_value=[mine]):
            await b.on_ready()
        self.assertEqual(b.settings.guild_id, 999)
        self.assertEqual(rules.Settings.load(b.data_dir / "settings.json").guild_id, 999)
        b.sync_commands.assert_awaited_once_with(999)
        b.announce.assert_awaited_once_with(mine)

    async def test_first_invite_binds_on_join(self):
        b = self.quiet(make_bot(guild_id=0))
        mine = self.server(999)
        with mock.patch.object(bot.ScamGuard, "guilds", new_callable=mock.PropertyMock, return_value=[mine]):
            await b.on_guild_join(mine)
        self.assertEqual(b.settings.guild_id, 999)
        b.sync_commands.assert_awaited_once_with(999)

    async def test_removal_from_the_bound_server_releases_it(self):
        b = make_bot()
        await b.on_guild_remove(SimpleNamespace(id=1, name="other"))
        self.assertEqual(b.settings.guild_id, 999)
        await b.on_guild_remove(SimpleNamespace(id=999, name="mine"))
        self.assertEqual(b.settings.guild_id, 0)
        self.assertEqual(rules.Settings.load(b.data_dir / "settings.json").guild_id, 0)

    async def test_never_binds_to_a_server_without_its_owner(self):
        b = self.quiet(make_bot(guild_id=0))
        stranger = self.server(7, owner_present=False)
        with mock.patch.object(bot.ScamGuard, "guilds", new_callable=mock.PropertyMock, return_value=[stranger]):
            await b.on_guild_join(stranger)
        self.assertEqual(b.settings.guild_id, 0)
        stranger.fetch_member.assert_awaited_once_with(42)
        mine = self.server(999)
        with mock.patch.object(bot.ScamGuard, "guilds", new_callable=mock.PropertyMock, return_value=[stranger, mine]):
            await b.on_guild_join(mine)
        self.assertEqual(b.settings.guild_id, 999)

    async def test_owner_found_by_lookup_counts(self):
        b = self.quiet(make_bot(guild_id=0))
        mine = self.server(999, owner_present=False)  # owned by someone else, but the app owner is a member
        mine.fetch_member = mock.AsyncMock(return_value=SimpleNamespace(id=42))
        with mock.patch.object(bot.ScamGuard, "guilds", new_callable=mock.PropertyMock, return_value=[mine]):
            await b.on_ready()
        self.assertEqual(b.settings.guild_id, 999)

    async def test_never_binds_while_in_several_servers(self):
        b = self.quiet(make_bot(guild_id=0))
        two = [self.server(1), self.server(2)]
        with mock.patch.object(bot.ScamGuard, "guilds", new_callable=mock.PropertyMock, return_value=two):
            await b.on_ready()
        self.assertEqual(b.settings.guild_id, 0)
        b.announce.assert_not_awaited()
        b.sync_commands.assert_not_awaited()


class FakeMember(SimpleNamespace):
    pass


def admin_interaction(b, perms):
    user = FakeMember(id=60, roles=[], guild_permissions=perms, mention="<@60>")
    return SimpleNamespace(client=b, guild_id=999, guild=SimpleNamespace(id=999), user=user,
                           response=SimpleNamespace(send_message=mock.AsyncMock()))


class SettingsCommands(unittest.IsolatedAsyncioTestCase):
    async def test_exempt_and_manager_lists(self):
        b = make_bot()
        b.report = mock.AsyncMock()
        it = admin_interaction(b, discord.Permissions(manage_guild=True))
        role = SimpleNamespace(id=77, mention="<@&77>", is_default=lambda: False)
        channel = SimpleNamespace(id=55, mention="<#55>")
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.exempt_add.callback(it, role=role, channel=channel)
            await bot.managers_add.callback(it, role=role)
            await bot.exempt_add.callback(it, role=role, channel=None)  # already there
        saved = rules.Settings.load(b.data_dir / "settings.json")
        self.assertEqual((saved.exempt_role_ids, saved.exempt_channel_ids, saved.manager_role_ids), ([77], [55], [77]))
        self.assertIn("already", it.response.send_message.await_args.args[0])
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.exempt_remove.callback(it, role=role, channel=None)
        self.assertEqual(b.settings.exempt_role_ids, [])
        self.assertEqual(b.report.await_count, 3)

    async def test_manager_role_alone_cannot_add_fingerprints_or_release_the_brake(self):
        b = make_bot(manager_role_ids=[33])
        it = admin_interaction(b, discord.Permissions.none())
        it.user.roles = [SimpleNamespace(id=33)]
        with mock.patch.object(bot.discord, "Member", FakeMember):
            self.assertTrue(bot.is_moderator(it))  # status, list and check still work
            await bot.add_scam_image.callback(it, SimpleNamespace(id=1))
            self.assertIn("Ban Members", it.response.send_message.await_args.args[0])
            b.state.braked.append(999)
            await bot.resume_cmd.callback(it)
            self.assertIn("Ban Members", it.response.send_message.await_args.args[0])
        self.assertTrue(b.is_braked(999))

    async def test_lists_need_manage_server(self):
        b = make_bot()
        it = admin_interaction(b, discord.Permissions(ban_members=True))
        role = SimpleNamespace(id=77, mention="<@&77>", is_default=lambda: False)
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.managers_add.callback(it, role=role)
        self.assertIn("Manage Server", it.response.send_message.await_args.args[0])
        self.assertEqual(b.settings.manager_role_ids, [])

    async def test_going_live_posts_the_banner(self):
        b = make_bot(dry_run=True, log_channel_id=5)
        b.report = mock.AsyncMock()
        b.refresh_banners = mock.AsyncMock(return_value=["Posted a banner in <#66>."])
        b.problems = lambda guild: []
        it = admin_interaction(b, discord.Permissions(manage_guild=True))
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.config_cmd.callback(it, mode=bot.app_commands.Choice(name="live", value="live"))
        self.assertFalse(b.settings.dry_run)
        b.refresh_banners.assert_awaited_once()
        self.assertTrue(b.refresh_banners.await_args.kwargs["post_missing"])

    async def test_going_live_needs_a_log_channel(self):
        b = make_bot(dry_run=True)
        b.report = mock.AsyncMock()
        it = admin_interaction(b, discord.Permissions(manage_guild=True))
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.config_cmd.callback(it, mode=bot.app_commands.Choice(name="live", value="live"))
        self.assertTrue(b.settings.dry_run)
        self.assertIn("log channel", it.response.send_message.await_args.args[0])

    async def test_rejoin_invite_keywords(self):
        b = make_bot()
        b.report = mock.AsyncMock()
        b.problems = lambda guild: []
        it = admin_interaction(b, discord.Permissions(manage_guild=True))
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.config_cmd.callback(it, rejoin_invite="none")
            self.assertEqual(b.settings.rejoin_invite, "none")
            await bot.config_cmd.callback(it, rejoin_invite="auto")
            self.assertEqual(b.settings.rejoin_invite, "")

    async def test_settings_changes_read_as_words_and_mentions(self):
        b = make_bot(dry_run=True, log_channel_id=5)
        b.report = mock.AsyncMock()
        b.refresh_banners = mock.AsyncMock(return_value=[])
        b.problems = lambda guild: []
        it = admin_interaction(b, discord.Permissions(manage_guild=True))
        role = SimpleNamespace(id=77, is_default=lambda: False)
        with mock.patch.object(bot.discord, "Member", FakeMember):
            await bot.config_cmd.callback(it, mode=bot.app_commands.Choice(name="live", value="live"),
                                          alert_role=role, timeout_hours=12, blast_channels=0)
        lines = b.report.await_args_list[0].args[1]
        for line in ("Mode: dry run → live", "Alert role: none → <@&77>", "Timeout: 24 hours → 12 hours",
                     "Cross-channel rule: 3 channels → off"):
            self.assertIn(line, lines)
        self.assertNotIn("alert_role_id", "\n".join(lines))

    async def test_remove_suggests_fingerprints_as_you_type(self):
        b = make_bot()
        b.store.refs = [scanner.Reference(hash=int("ab" * 32, 16), label="gift.png from #general"),
                        scanner.Reference(hash=int("cd" * 32, 16), label="nitro.png from #help")]
        it = admin_interaction(b, discord.Permissions(ban_members=True))
        with mock.patch.object(bot.discord, "Member", FakeMember):
            choices = await bot.fingerprint_choices(it, "NITRO")
        self.assertEqual([c.value for c in choices], [b.store.refs[1].id])
        self.assertIn("nitro.png from #help", choices[0].name)


class Health(unittest.IsolatedAsyncioTestCase):
    async def test_hourly_check_reports_only_what_changed(self):
        b = make_bot()
        b.report = mock.AsyncMock()
        guild = SimpleNamespace(id=999)
        problems = ["Missing permissions: Ban Members"]
        b.problems = lambda g: list(problems)
        b.problem_sets[999] = set(problems)
        await b.recheck(guild)
        b.report.assert_not_awaited()
        problems[:] = ["The log channel <#5> was deleted, or I can't see it."]
        await b.recheck(guild)
        lines = b.report.await_args.args[1]
        self.assertIn("⚠ New setup problem: The log channel <#5> was deleted, or I can't see it.", lines)
        self.assertIn("✅ Fixed: Missing permissions: Ban Members", lines)


class Logging(unittest.TestCase):
    def test_routine_lines_go_to_stdout_and_problems_to_stderr(self):
        root = logging.getLogger()
        handlers, level = root.handlers[:], root.level
        out, err = io.StringIO(), io.StringIO()
        try:
            with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
                bot.configure_logging(logging.INFO)
                logging.getLogger("scamguard").info("routine line")
                logging.getLogger("scamguard").warning("a problem")
        finally:
            root.handlers[:] = handlers
            root.setLevel(level)
        self.assertIn("routine line", out.getvalue())
        self.assertNotIn("a problem", out.getvalue())
        self.assertIn("a problem", err.getvalue())
        self.assertNotIn("routine line", err.getvalue())


class Banner(unittest.IsolatedAsyncioTestCase):
    async def test_banner_is_components_v2_with_the_count_button(self):
        b = make_bot()
        b.state.totals["trap"] = 1234
        b._connection.user = SimpleNamespace(display_avatar=SimpleNamespace(
            url="https://cdn.discordapp.com/embed/avatars/0.png"))
        view = b.banner_view()
        self.assertTrue(view.has_components_v2())
        container = view.to_components()[0]
        self.assertEqual(container["type"], 17)  # Container
        section, row = container["components"]
        self.assertEqual(section["type"], 9)      # Section with the avatar thumbnail
        self.assertIn("Do not post in this channel", section["components"][0]["content"])
        button = row["components"][0]
        self.assertEqual((button["custom_id"], button["label"]), ("sg:stats", "Caught: 1,234"))


class Buttons(unittest.TestCase):
    def test_custom_ids_fit_and_round_trip(self):
        big = 2 ** 63 - 1  # largest possible snowflake
        for item in (bot.UnbanButton(big), bot.UntimeoutButton(big), bot.ApplyButton("blast", big, big, big),
                     bot.ApplyButton("image", big, big, big, "softban"), bot.LearnButton(big, big),
                     bot.StatsButton(12345)):
            self.assertLessEqual(len(item.custom_id), 100)
            self.assertIsNotNone(item.template.fullmatch(item.custom_id))

    def test_take_action_carries_its_action_and_still_reads_older_buttons(self):
        new = bot.ApplyButton("image", 1, 2, 3, "kick")
        self.assertEqual(new.custom_id, "sg:apply:image:kick:1:2:3")
        m = new.template.fullmatch(new.custom_id)
        self.assertEqual((m["rule"], m["action"], m["uid"], m["mid"]), ("image", "kick", "1", "3"))
        old = new.template.fullmatch("sg:apply:trap:1:2:3")  # posted by 2.0
        self.assertEqual((old["rule"], old["action"], old["uid"], old["mid"]), ("trap", None, "1", "3"))


if __name__ == "__main__":
    unittest.main()
