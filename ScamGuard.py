"""ScamGuard: removes scam posts, and the accounts posting them, from a Discord server.

Three rules, checked in this order on every message:
  trap   any post by a non-staff member in a trap channel, or in a thread under one
  image  an image whose fingerprint matches a known scam image
  blast  the same post in several channels within seconds, the mark of a hijacked account

Only the bot token comes from .env. Everything else is set in Discord with the
/scamguard commands and saved in data/settings.json. README.md covers setup and
the security model.

Original version by Swampfrog.
"""
from __future__ import annotations

import asyncio
import io
import logging
import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp
import discord
from discord import app_commands
from dotenv import load_dotenv

import rules
import scanner

__version__ = "2.0.1"
log = logging.getLogger("scamguard")
HERE = Path(__file__).resolve().parent
SEED_FILE = HERE / "seed_references.json"

IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".gif")
STAFF_PERMS = ("administrator", "manage_guild", "manage_messages",
               "moderate_members", "kick_members", "ban_members")
MAX_IMAGES_PER_MESSAGE = 10
MAX_DOWNLOAD_BYTES = 15 * 1024 * 1024
SCAN_TIMEOUT = 30        # seconds per image (download + fingerprint)
SCAN_CONCURRENCY = 4     # images processed at once, so a flood can't exhaust memory/CPU
REPEAT_WINDOW = 600      # act on the same member at most once per 10 minutes
CONDEMN_SECONDS = 120    # after a removal, delete anything else the account posts for 2 minutes
QUICK_SWEEP = 120        # seconds of a removed member's recent posts deleted at minimum
NEAR_MISS_MARGIN = 24    # console-log images that came this close to the threshold
DM_TIMEOUT = 2.0         # the DM goes out before the removal, so it can't hold the removal up
FORWARD_TIMEOUT = 5.0
BANNER_INTERVAL = 10.0   # edit trap banners at most this often
CATCHUP_WINDOW = 24 * 3600
MEDIA_HOSTS = frozenset({"cdn.discordapp.com", "media.discordapp.net"})
EXTERNAL_PROXY = re.compile(r"images-ext-\d+\.discordapp\.net")
ACTIONABLE = frozenset({discord.MessageType.default, discord.MessageType.reply,
                        discord.MessageType.chat_input_command, discord.MessageType.context_menu_command})
RULE_NAMES = {"trap": "trap channel", "image": "known scam image", "blast": "same post across channels"}
PERM_FOR_ACTION = {"delete": "manage_messages", "timeout": "moderate_members", "kick": "kick_members",
                   "softban": "ban_members", "ban": "ban_members"}
BANNER_COLOR = 0xF5A623


# ======================================================================= config
class ConfigError(Exception):
    pass


def _env(name: str) -> str:
    return (os.getenv(name) or "").strip()


def data_dir() -> Path:
    return Path(_env("DATA_DIR") or HERE / "data")


def read_token() -> str:
    path = _env("DISCORD_TOKEN_FILE")
    try:
        token = Path(path).read_text(encoding="utf-8").strip() if path else _env("DISCORD_TOKEN")
    except OSError as exc:
        raise ConfigError(f"can't read DISCORD_TOKEN_FILE: {exc.strerror}") from None
    os.environ.pop("DISCORD_TOKEN", None)  # nothing else in this process needs it
    if not token:
        raise ConfigError("set DISCORD_TOKEN, or DISCORD_TOKEN_FILE pointing at a file containing it")
    return token


# =============================================================== image sources
def is_discord_media(url: str | None) -> bool:
    """Only Discord's own CDN and media proxy are ever downloaded from."""
    if not url:
        return False
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    return (u.scheme == "https" and port in (None, 443) and u.username is None
            and (host in MEDIA_HOSTS or EXTERNAL_PROXY.fullmatch(host) is not None))


def rendition_url(proxy_url: str | None, width: int | None, height: int | None) -> str | None:
    """URL of a downscaled copy re-encoded by Discord's media proxy.

    Fetching this instead of the original means less bandwidth (a median of
    53 KB against 1.1 MB on the real scam posts), and the bot decodes bytes
    Discord produced rather than the uploader's.
    """
    if not (width and height) or not is_discord_media(proxy_url):
        return None
    scale = min(1.0, scanner.WORK_SIZE / max(width, height))
    w, h = max(1, round(width * scale)), max(1, round(height * scale))
    parts = urlsplit(proxy_url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k not in ("format", "width", "height", "quality")]
    query += [("format", "webp"), ("width", str(w)), ("height", str(h))]
    return urlunsplit(parts._replace(query=urlencode(query)))


@dataclass(frozen=True)
class ImageSource:
    name: str
    urls: tuple[str, ...]  # tried in order; all Discord-hosted


def attachment_source(att: discord.Attachment) -> ImageSource | None:
    ctype = (att.content_type or "").lower()
    if ctype.startswith(("video/", "audio/")):
        return None
    if not (ctype.startswith("image/") or att.filename.lower().endswith(IMAGE_EXTS) or att.width):
        return None
    urls = [u for u in (rendition_url(att.proxy_url, att.width, att.height),) if u]
    if att.size <= MAX_DOWNLOAD_BYTES and is_discord_media(att.url):
        urls.append(att.url)  # fallback: the original file
    return ImageSource(att.filename, tuple(urls)) if urls else None


def embed_sources(embeds: list[discord.Embed]) -> list[ImageSource]:
    out, seen = [], set()
    for embed in embeds:
        for media in (embed.image, embed.thumbnail):
            url = getattr(media, "proxy_url", None)
            if url and url not in seen and is_discord_media(url):
                seen.add(url)
                out.append(ImageSource(getattr(media, "url", None) or "link preview", (url,)))
    return out


def image_sources(message: discord.Message) -> list[ImageSource]:
    """Images on a message, including forwarded messages and link previews."""
    attachments = list(message.attachments)
    embeds = list(message.embeds)
    for snapshot in getattr(message, "message_snapshots", None) or ():
        attachments += snapshot.attachments
        embeds += snapshot.embeds
    found = [s for s in map(attachment_source, attachments) if s] + embed_sources(embeds)
    return found[:MAX_IMAGES_PER_MESSAGE]


def _analyse(data: bytes, aspects: tuple[float, ...]) -> tuple[scanner.Fingerprint, bool]:
    img = scanner.load_image(data)
    return scanner.fingerprint(img, aspects), scanner.is_informative(img)


def _ext(data: bytes) -> str:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return "bin"


class DownloadError(Exception):
    pass


@dataclass
class Scan:
    source: ImageSource
    fp: scanner.Fingerprint
    data: bytes
    informative: bool


@dataclass
class Outcome:
    text: str
    applied: bool = False   # a timeout, kick or ban actually went through
    banned: bool = False    # they are banned now (ban, or a softban whose unban step failed)
    braked: bool = False    # this punishment engaged the safety brake


# ===================================================================== messages
TRAP_OUTCOME = {
    "softban": "gets the sender removed from the server",
    "kick": "gets the sender removed from the server",
    "ban": "gets the sender banned",
    "timeout": "gets the sender timed out",
    "delete": "is deleted",
}


def banner_text(action: str) -> str:
    return ("## Do not post in this channel\n"
            f"This channel catches spam bots. Anything posted here {TRAP_OUTCOME[action]}.")


def dm_text(guild_name: str, rule: str, action: str, channel_name: str, timeout_hours: int, invite: str) -> str:
    """The DM a member gets just before ScamGuard acts on them."""
    head = {
        "softban": f"**You were removed from {guild_name}.**",
        "kick": f"**You were removed from {guild_name}.**",
        "ban": f"**You were banned from {guild_name}.**",
        "timeout": f"**You were timed out in {guild_name} for {timeout_hours} hours.**",
    }[action]
    why = {
        "trap": f"Your account posted in #{channel_name}, a channel that exists only to catch spam bots.",
        "image": "Your account posted an image from a known scam.",
        "blast": "Your account posted the same message in several channels within seconds.",
    }[rule]
    lines = [head, why, "",
             "If you didn't post it, someone else has access to your account. Change your password, "
             "which signs out every other device, turn on two-factor authentication, and remove any "
             "apps you don't recognize under User Settings → Authorized Apps."]
    if action in ("softban", "kick"):
        lines += ["", f"Once your account is secure, you're welcome back{': ' + invite if invite else '.'}"]
    lines += ["", "-# Automated message from ScamGuard. Replies aren't read."]
    return "\n".join(lines)


# ========================================================================= bot
class ScamGuard(discord.Client):
    def __init__(self, data_dir: Path, settings: rules.Settings, store: scanner.ReferenceStore, state: rules.State):
        intents = discord.Intents.none()
        intents.guilds = True           # servers, channels, roles
        intents.guild_messages = True   # new messages and edits
        intents.message_content = True  # text, attachments and embeds (privileged intent)
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())
        self.data_dir = data_dir
        self.settings = settings
        self.store = store
        self.state = state
        self.tree = app_commands.CommandTree(self)
        self.web: aiohttp.ClientSession | None = None
        self.scan_slots = asyncio.Semaphore(SCAN_CONCURRENCY)
        self.blasts = rules.BlastTracker()
        self.recent = rules.RecentPosts()
        self.handled_at: dict[tuple[int, int], float] = {}  # member -> when ScamGuard last acted on them
        self.condemned: dict[tuple[int, int], float] = {}   # member -> until when new posts are deleted
        self.actions: dict[int, deque[float]] = defaultdict(deque)
        self.braked: set[int] = set()
        self.announced: set[int] = set()
        self.caught_up = False
        self.warned_fallback = False
        self.dm_limit = rules.RateLimit(20, 60)
        self.webhook_alerts: dict[int, float] = {}
        self.banner_task: asyncio.Task | None = None
        self.banner_edited = 0.0
        self.housekeeper: asyncio.Task | None = None
        self._owner_ids: set[int] | None = None
        self.thread_alerts: dict[int, float] = {}

    # ---------------------------------------------------------------- startup
    async def setup_hook(self) -> None:
        self.web = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=SCAN_TIMEOUT, sock_connect=10),
            headers={"User-Agent": f"ScamGuard/{__version__} (Discord moderation bot)"},
        )
        self.add_dynamic_items(UnbanButton, UntimeoutButton, ApplyButton, LearnButton, StatsButton)
        for command in OUR_COMMANDS:
            self.tree.add_command(command)
        # Commands are registered in the bound server only. The application's global command
        # list is never written, so another bot sharing this token keeps its commands.
        try:
            others = [c.name for c in await self.tree.fetch_commands() if c.name not in OUR_COMMAND_NAMES]
        except discord.HTTPException:
            others = []
        if others:
            log.warning("This token belongs to a bot that has other commands (%s). ScamGuard won't touch "
                        "them, but it should run as its own bot application.", ", ".join(others[:5]))
        if self.settings.guild_id:
            await self.sync_commands(self.settings.guild_id)
        self.housekeeper = asyncio.create_task(self.housekeeping())

    async def sync_commands(self, guild_id: int) -> None:
        """Register commands in one server, unless that would overwrite another bot's commands."""
        guild = discord.Object(id=guild_id)
        self.tree.copy_global_to(guild=guild)
        try:
            existing = await self.tree.fetch_commands(guild=guild)
            others = [c.name for c in existing if c.name not in OUR_COMMAND_NAMES]
            if others:
                log.error("Not registering commands in server %s: this bot application already has other "
                          "commands there (%s) and registering would replace them. Give ScamGuard its own "
                          "bot application.", guild_id, ", ".join(others[:5]))
                return
            await self.tree.sync(guild=guild)
        except discord.HTTPException as exc:
            log.error("Couldn't register commands in server %s (HTTP %s). Is the bot in it, invited "
                      "with the applications.commands scope?", guild_id, exc.status)

    async def close(self) -> None:
        if self.housekeeper:
            self.housekeeper.cancel()
        self.save_state()
        if self.web:
            await self.web.close()
        await super().close()

    async def housekeeping(self) -> None:
        """Every minute: stamp the time for downtime catch-up and trim the in-memory trackers."""
        while True:
            await asyncio.sleep(60)
            try:
                now = time.monotonic()
                self.state.last_seen = time.time()
                self.save_state()
                self.blasts.prune(now, self.settings.blast_seconds)
                self.recent.prune(now)
                self.handled_at = {k: t for k, t in self.handled_at.items() if now - t < REPEAT_WINDOW}
                self.condemned = {k: t for k, t in self.condemned.items() if t > now}
            except Exception:  # a failed pass must not end the loop
                log.exception("Housekeeping pass failed")

    def save_settings(self) -> None:
        self.settings.save(self.data_dir / "settings.json")

    def save_state(self) -> None:
        try:
            self.state.save(self.data_dir / "state.json")
        except OSError as exc:
            log.error("Couldn't save state.json: %s", exc)

    def allowed(self, guild_id: int | None) -> bool:
        return guild_id is not None and guild_id == self.settings.guild_id

    async def owner_ids(self) -> set[int]:
        """The application's owner, or its team's members, from Discord."""
        if self._owner_ids is None:
            info = await self.application_info()
            self._owner_ids = {m.id for m in info.team.members} if info.team else {info.owner.id}
        return self._owner_ids

    async def has_owner(self, guild: discord.Guild) -> bool:
        try:
            owners = await self.owner_ids()
        except discord.HTTPException:
            return False
        for uid in owners:
            if guild.owner_id == uid or guild.get_member(uid) is not None:
                return True
            try:
                await guild.fetch_member(uid)  # REST lookup; needs no Server Members intent
                return True
            except discord.NotFound:
                continue
            except discord.HTTPException:
                return False
        return False

    async def bind(self) -> bool:
        """Serve the server ScamGuard was invited to, saved in settings.json the first time.

        Only a server the application's owner belongs to counts, so a server a stranger
        added the bot to is never served. True when it binds now.
        """
        if self.settings.guild_id:
            return False
        candidates = [g for g in list(self.guilds) if await self.has_owner(g)]
        if len(candidates) != 1:
            if len(candidates) > 1:
                log.error("ScamGuard is in %d servers its owner belongs to and serves one. Remove it from "
                          "the others, then restart it.", len(candidates))
            return False
        guild = candidates[0]
        try:
            new = replace(self.settings, guild_id=guild.id)
            new.save(self.data_dir / "settings.json")
        except (ValueError, OSError) as exc:
            log.error("Couldn't save the server binding: %s", exc)
            return False
        self.settings = new
        log.info("Serving %s (%s) from now on", guild.name, guild.id)
        return True

    async def on_ready(self) -> None:
        log.info("Connected as %s (id %s)", self.user, self.user.id if self.user else "?")
        if await self.bind():
            await self.sync_commands(self.settings.guild_id)
        for guild in list(self.guilds):
            # Other servers are ignored, never left: if this token is shared with
            # another bot, leaving would pull that bot out of servers it serves.
            if not self.allowed(guild.id):
                log.warning("Ignoring %s (%s): ScamGuard serves server %s", guild.name, guild.id,
                            self.settings.guild_id or "(none yet)")
            elif guild.id not in self.announced:
                self.announced.add(guild.id)
                await self.announce(guild)
        if not self.caught_up:
            self.caught_up = True
            for guild in list(self.guilds):
                if self.allowed(guild.id):
                    await self.catch_up(guild)

    async def on_guild_join(self, guild: discord.Guild) -> None:
        await self.bind()
        if not self.allowed(guild.id):
            log.warning("Added to %s (%s), but ScamGuard serves server %s; ignoring it", guild.name, guild.id,
                        self.settings.guild_id)
            return
        await self.sync_commands(guild.id)
        self.announced.add(guild.id)
        await self.announce(guild)

    async def on_guild_remove(self, guild: discord.Guild) -> None:
        """Removed from the bound server (an outage arrives as guild_unavailable instead):
        release the binding so the next server the owner invites it to is served."""
        if not self.allowed(guild.id):
            return
        try:
            new = replace(self.settings, guild_id=0)
            new.save(self.data_dir / "settings.json")
        except (ValueError, OSError) as exc:
            log.error("Couldn't release the server binding: %s", exc)
            return
        self.settings = new
        self.announced.discard(guild.id)
        log.warning("Removed from %s (%s). ScamGuard will serve the next server it joins.", guild.name, guild.id)

    def rejoin_link(self, guild: discord.Guild) -> str:
        """The invite in removal DMs: the one set with /scamguard config, else the server's vanity link."""
        invite = self.settings.rejoin_invite
        if invite == "none":
            return ""
        if invite:
            return invite
        code = getattr(guild, "vanity_url_code", None)
        return f"https://discord.gg/{code}" if code else ""

    def out_of_reach(self, guild: discord.Guild) -> list[discord.Role]:
        """Member roles at or above ScamGuard's highest role: it can't act on members holding them."""
        me = guild.me
        if me is None:
            return []
        return sorted((r for r in guild.roles if r >= me.top_role and r not in me.roles and not r.managed
                       and not r.is_default() and not self.staff_role(r)), reverse=True)

    def problems(self, guild: discord.Guild) -> list[str]:
        """Setup problems, shown at startup and in /scamguard status."""
        me, s = guild.me, self.settings
        if me is None:
            return ["My member record isn't cached yet, so setup can't be checked."]
        perms = me.guild_permissions
        out = []
        if perms.administrator:
            out.append("I have **Administrator**. I don't need it: remove it so a leaked token can do less damage.")
        needed = {"view_channel": "View Channels", "send_messages": "Send Messages",
                  "read_message_history": "Read Message History", "manage_messages": "Manage Messages"}
        for act in {s.image_action, s.honeypot_action, s.blast_action}:
            if act in ("softban", "ban"):
                needed["ban_members"] = "Ban Members"
            elif act == "kick":
                needed["kick_members"] = "Kick Members"
            elif act == "timeout":
                needed["moderate_members"] = "Timeout Members"
        missing = [label for attr, label in needed.items() if not getattr(perms, attr)]
        if missing:
            out.append("Missing permissions: " + ", ".join(missing))
        channel = guild.get_channel_or_thread(s.log_channel_id) if s.log_channel_id else None
        if not s.log_channel_id:
            out.append("No log channel is set: run `/scamguard config log_channel:`.")
        elif channel is None:
            out.append(f"Log channel {s.log_channel_id} wasn't found in this server.")
        elif not isinstance(channel, discord.abc.Messageable):
            out.append("The log channel is something I can't post in (a category or forum?).")
        else:
            cp = channel.permissions_for(me)
            if not (cp.view_channel and cp.send_messages and cp.read_message_history):
                out.append(f"I can't post in {channel.mention}.")
            readers = self.log_readers(guild, channel)
            if readers:
                names = ", ".join(discord.utils.escape_markdown(r.name) for r in readers[:5])
                out.append(f"Roles that aren't staff can read {channel.mention}: {names}. Until it's mods-only, "
                           "reports leave out the quoted text, the forwarded post and the images. If only bots "
                           "or staff hold a role, add it with `/scamguard exempt add role:`.")
        if not s.honeypot_channel_ids:
            out.append("No trap channel is set. Add one with `/scamguard honeypot add`.")
        for cid in s.honeypot_channel_ids:
            trap = guild.get_channel_or_thread(cid)
            if trap is None:
                out.append(f"Trap channel {cid} wasn't found.")
                continue
            cp = trap.permissions_for(me)
            if not (cp.view_channel and cp.read_message_history and cp.manage_messages):
                out.append(f"I need View Channel, Read Message History and Manage Messages in {trap.mention}.")
            elif any(trap.permissions_for(r).create_public_threads or trap.permissions_for(r).create_private_threads
                     for r in guild.roles if not r.managed and not self.staff_role(r)):
                out.append(f"Members can create threads in {trap.mention}. A thread there makes easy bait, "
                           "because people who open it from a link never see the warning. Turn off Create Public "
                           "Threads and Create Private Threads for members in that channel.")
            elif not s.dry_run and str(cid) not in self.state.banners:
                out.append(f"{trap.mention} has no ScamGuard warning banner. Run `/scamguard honeypot banner`.")
        member_roles = [r for r in guild.roles if not r.managed and not r.is_default() and not self.staff_role(r)]
        if len(self.out_of_reach(guild)) * 2 > len(member_roles):
            out.append("My highest role is below most member roles, so I can't act on most members. Give me "
                       "a role that sits above the member roles, or drag my role up under the moderator roles.")
        return out

    async def announce(self, guild: discord.Guild) -> None:
        """Post a startup summary and flag setup problems in the log channel."""
        problems = self.problems(guild)
        for line in problems:
            log.warning("[%s] %s", guild.name, line)
        mode = "🧪 DRY RUN: nothing will be deleted" if self.settings.dry_run else "live"
        await self.report(guild, [f"🛡 ScamGuard {__version__} online: {len(self.store.refs)} "
                                  f"fingerprint(s), {mode}.", *(f"⚠ {p}" for p in problems)])

    async def catch_up(self, guild: discord.Guild) -> None:
        """Act on trap posts made while the bot was offline (restart or outage)."""
        since = self.state.last_seen
        if not since:
            return
        after = datetime.fromtimestamp(max(since - 5, time.time() - CATCHUP_WINDOW), timezone.utc)
        for cid in self.settings.honeypot_channel_ids:
            channel = guild.get_channel_or_thread(cid)
            if not hasattr(channel, "history"):
                continue
            try:
                async for msg in channel.history(after=after, limit=50, oldest_first=True):
                    if (msg.id in self.state.handled or msg.webhook_id or msg.author.bot
                            or msg.type not in ACTIONABLE):
                        continue
                    member = await self.resolve_member(guild, msg.author.id)
                    if member is None:
                        if not self.settings.dry_run:
                            await self.delete([msg])
                        continue
                    log.info("Catch-up: trap post %s by %s while offline", msg.id, msg.author.id)
                    await self.inspect(msg, [], member=member)
            except discord.HTTPException as exc:
                log.warning("Catch-up in %s failed (HTTP %s)", cid, exc.status)

    # ------------------------------------------------------------- detection
    def in_trap(self, channel) -> bool:
        where = {getattr(channel, "id", None), getattr(channel, "parent_id", None)}
        return bool(where & set(self.settings.honeypot_channel_ids))

    async def on_message(self, message: discord.Message) -> None:
        guild = message.guild
        if guild is None or not self.allowed(guild.id):
            return
        if message.webhook_id:
            if self.in_trap(message.channel):
                await self.trap_webhook(message)
            return
        if message.author.bot:
            # A bot replying to someone's slash command in a trap channel: the person who ran it posted there.
            meta = message.interaction_metadata
            if meta and self.user and message.author.id != self.user.id and self.in_trap(message.channel):
                member = await self.resolve_member(guild, meta.user.id)
                if member is not None:
                    await self.inspect(message, [], member=member)
            return
        if message.type not in ACTIONABLE or not isinstance(message.author, discord.Member):
            return
        key, now = (guild.id, message.author.id), time.monotonic()
        if self.condemned.get(key, 0) > now:
            await self.delete([message])
            log.info("Deleted a late post %s from %s, who was just removed", message.id, message.author.id)
            return
        self.recent.add(key, now, message.channel.id, message.id)
        await self.inspect(message, image_sources(message))

    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        # Link previews usually arrive in an edit a moment after the message is sent.
        seen = {url for s in image_sources(before) for url in s.urls}
        new = [s for s in image_sources(after) if not seen.intersection(s.urls)]
        if new and after.guild and self.allowed(after.guild.id) and not after.author.bot \
                and not after.webhook_id and isinstance(after.author, discord.Member):
            await self.inspect(after, new, edited=True)

    def staff_role(self, role: discord.Role) -> bool:
        return role.id in self.settings.exempt_role_ids or any(getattr(role.permissions, p) for p in STAFF_PERMS)

    def is_staff(self, member: discord.Member) -> bool:
        perms = member.guild_permissions
        return (member.id == member.guild.owner_id
                or any(getattr(perms, p) for p in STAFF_PERMS)
                or any(r.id in self.settings.exempt_role_ids for r in member.roles))

    async def inspect(self, message: discord.Message, sources: list[ImageSource], *,
                      member: discord.Member | None = None, edited: bool = False) -> None:
        guild, s = message.guild, self.settings
        member = member or message.author  # type: ignore[assignment]
        where = {message.channel.id, getattr(message.channel, "parent_id", None)}
        if where & {*s.exempt_channel_ids, s.log_channel_id}:
            return
        staff = self.is_staff(member)
        if not edited and where & set(s.honeypot_channel_ids):
            channel = message.channel
            in_thread = channel.id not in s.honeypot_channel_ids  # a thread under a trap channel
            if staff:
                log.info("Staff member %s posted in trap channel %s; ignored", member.id, channel.id)
            elif in_thread and getattr(channel, "owner_id", None) != member.id:
                await self.bait_thread(message, member)
            else:
                await self.enforce(message, member, "trap", f"posted in {channel.mention}, a trap channel", [])
            return

        check_blast = not edited and not staff and s.blast_channels >= 2
        text = rules.normalize_text(message.content) if check_blast else ""
        if not sources and not (check_blast and rules.meaningful_text(text)):
            return
        scans = await self.scan_sources(sources)
        for scan in scans:
            hit = self.store.match(scan.fp, s.match_threshold)
            if hit:
                ref, dist = hit
                label = discord.utils.escape_markdown(ref.label or ref.id)  # labels can hold uploader filenames
                await self.enforce(message, member, "image",
                                   f"{label} (distance {dist}/{scanner.HASH_BITS})", [scan])
                return
            near = self.store.nearest(scan.fp)
            if near and near[1] <= s.match_threshold + NEAR_MISS_MARGIN:
                log.info("Near miss in %s: %r scored %d (threshold %d) against %s",
                         guild.name, scan.source.name[:80], near[1], s.match_threshold, near[0].id)
        if check_blast:
            post = rules.Post(time.monotonic(), message.channel.id, message.id, text,
                              tuple(scan.fp.full for scan in scans))
            same = self.blasts.record((guild.id, member.id), post, s.blast_channels, s.blast_seconds)
            if same:
                channels = len({p.channel_id for p in same})
                earlier = [self.partial(guild, p.channel_id, p.message_id) for p in same if p.message_id != message.id]
                await self.enforce(message, member, "blast",
                                   f"the same post in {channels} channels within {s.blast_seconds}s",
                                   scans, [m for m in earlier if m])

    async def bait_thread(self, message: discord.Message, member: discord.Member) -> None:
        """A reply in someone else's thread under a trap channel. A thread can be shared by link, and
        whoever opens it that way never sees the trap's warning, so the reply is never punished.
        The moderators hear about the thread once."""
        thread, now = message.channel, time.monotonic()
        if now - self.thread_alerts.get(thread.id, float("-inf")) < REPEAT_WINDOW:
            return
        self.thread_alerts[thread.id] = now
        owner_id = getattr(thread, "owner_id", None)
        await self.report(message.guild, [
            f"🍯 {member.mention} replied in {thread.mention}, a thread "
            f"{f'<@{owner_id}>' if owner_id else 'someone'} started under a trap channel. Not punished: "
            "people who open a thread from a link never see the trap's warning.",
            "If the thread is bait, delete it and deal with whoever started it."])

    def partial(self, guild: discord.Guild, channel_id: int, message_id: int) -> discord.PartialMessage | None:
        channel = guild.get_channel_or_thread(channel_id)
        getter = getattr(channel, "get_partial_message", None)
        return getter(message_id) if getter else None

    async def resolve_member(self, guild: discord.Guild, user_id: int) -> discord.Member | None:
        member = guild.get_member(user_id)
        if member is not None:
            return member
        try:
            return await guild.fetch_member(user_id)  # REST lookup; needs no Server Members intent
        except discord.HTTPException:
            return None

    async def trap_webhook(self, message: discord.Message) -> None:
        """Webhooks can't be removed like members. Delete the post and tell the mods once per webhook."""
        if not self.settings.dry_run:
            await self.delete([message])
        now = time.monotonic()
        if now - self.webhook_alerts.get(message.webhook_id, float("-inf")) < REPEAT_WINDOW:
            return
        self.webhook_alerts[message.webhook_id] = now
        name = discord.utils.escape_markdown(message.author.display_name)
        done = "Deleted it." if not self.settings.dry_run else "🧪 Dry run: left it in place."
        await self.report(message.guild, [
            f"🪝 A webhook named **{name}** posted in {message.channel.mention}. {done}",
            "If nobody recognizes it, remove it under Server Settings → Integrations → Webhooks."])

    # --------------------------------------------------------------- scanning
    async def scan_sources(self, sources: list[ImageSource]) -> list[Scan]:
        if not sources:
            return []
        try:
            if self.store.refresh():
                log.info("Reloaded %d fingerprint(s) from disk", len(self.store.refs))
        except (ValueError, OSError) as exc:
            log.error("Fingerprint file changed but is invalid (%s); keeping the previous list", exc)
        aspects = tuple(sorted(self.store.aspects()))
        results = await asyncio.gather(*(self.scan_one(s, aspects) for s in sources))
        return [r for r in results if r is not None]

    async def scan_one(self, source: ImageSource, aspects: tuple[float, ...]) -> Scan | None:
        async with self.scan_slots:
            try:
                data = await asyncio.wait_for(self.download(source), SCAN_TIMEOUT)
                fp, informative = await asyncio.wait_for(asyncio.to_thread(_analyse, data, aspects), SCAN_TIMEOUT)
            except (scanner.ImageRejected, DownloadError, TimeoutError) as exc:
                log.info("Skipped image %r: %s", source.name[:80], exc or type(exc).__name__)
                return None
            except Exception:  # one odd image must not stop the others being checked
                log.exception("Unexpected error scanning %r", source.name[:80])
                return None
        return Scan(source, fp, data, informative)

    async def download(self, source: ImageSource) -> bytes:
        error: Exception = DownloadError("no usable URL")
        for i, url in enumerate(source.urls):
            try:
                return await self.fetch(url)
            except DownloadError as exc:
                error = exc
                if i == 0 and len(source.urls) > 1 and not self.warned_fallback:
                    self.warned_fallback = True
                    log.warning("Downscaled copy unavailable (%s); falling back to original files", exc)
        raise error

    async def fetch(self, url: str) -> bytes:
        if not is_discord_media(url) or self.web is None:
            raise DownloadError("refusing non-Discord URL")
        try:
            async with self.web.get(url, allow_redirects=False) as resp:
                if resp.status != 200:
                    raise DownloadError(f"HTTP {resp.status}")
                if (resp.content_length or 0) > MAX_DOWNLOAD_BYTES:
                    raise DownloadError("file too large")
                buf = bytearray()
                async for chunk in resp.content.iter_chunked(1 << 16):
                    buf += chunk
                    if len(buf) > MAX_DOWNLOAD_BYTES:
                        raise DownloadError("file too large")
                return bytes(buf)
        except aiohttp.ClientError as exc:
            raise DownloadError(type(exc).__name__) from None

    # ------------------------------------------------------------ enforcement
    def log_channel(self, guild: discord.Guild | None):
        if guild is None or not self.settings.log_channel_id:
            return None
        channel = guild.get_channel_or_thread(self.settings.log_channel_id)
        return channel if isinstance(channel, discord.abc.Messageable) else None

    def describe(self, message: discord.Message, member: discord.Member, rule: str, detail: str) -> list[str]:
        name = discord.utils.escape_markdown(str(member))
        joined = f", joined {discord.utils.format_dt(member.joined_at, 'R')}" if member.joined_at else ""
        lines = [f"**{RULE_NAMES[rule]}**: {member.mention} ({name}, ID `{member.id}`) in {message.channel.mention}",
                 f"Why: {detail}",
                 f"Account created {discord.utils.format_dt(member.created_at, 'R')}{joined}"]
        excerpt = (message.content or "").replace("`", "'")[:300]
        if excerpt:
            lines.append(f"Text:\n```{excerpt}```")
        return lines

    def log_readers(self, guild: discord.Guild, channel) -> list[discord.Role]:
        """Roles that can read a channel without being staff, exempt or bot-managed. Checked one role at a
        time, so a member role that sees the channel counts even when @everyone can't."""
        return [r for r in guild.roles
                if not r.managed and not self.staff_role(r) and channel.permissions_for(r).view_channel]

    async def forward(self, message: discord.Message, channel) -> discord.Message | None:
        """Forward the original post to the log channel before it is deleted: text and files intact.
        Skipped when members can read the log, or the forward would show them the scam again."""
        if channel is None or message.type not in ACTIONABLE or self.log_readers(message.guild, channel):
            return None
        try:
            return await asyncio.wait_for(message.forward(channel), FORWARD_TIMEOUT)
        except (discord.HTTPException, TimeoutError) as exc:
            log.warning("Couldn't forward message %s to the log channel: %s", message.id, exc)
            return None

    async def enforce(self, message: discord.Message, member: discord.Member, rule: str, detail: str,
                      scans: list[Scan], also_delete: list[discord.PartialMessage] | tuple = ()) -> None:
        guild, s = message.guild, self.settings
        key, now = (guild.id, member.id), time.monotonic()
        staff = self.is_staff(member)
        action = s.action_for(rule)
        if not staff:
            if now - self.handled_at.get(key, float("-inf")) < REPEAT_WINDOW:
                # Another post from someone already handled: clean up quietly, no second report.
                if not s.dry_run:
                    await self.delete([message, *also_delete])
                log.info("Already handled %s; %s post %s", member.id,
                         "would delete" if s.dry_run else "deleted", message.id)
                return
            self.handled_at[key] = now
            if not s.dry_run and action != "delete":
                self.condemned[key] = now + CONDEMN_SECONDS
        if rule == "trap":
            self.state.mark_handled(message.id)

        lines = self.describe(message, member, rule, detail)
        count = 1 + len(also_delete)
        log_channel = self.log_channel(guild)
        if s.dry_run:
            forwarded = await self.forward(message, log_channel)
            lines.append(f"🧪 DRY RUN: would delete {count} message(s) and apply `{action}`"
                         + (" (staff: delete only)" if staff else "") + ".")
            view = None
            if not staff and action != "delete":
                view = discord.ui.View(timeout=None)
                view.add_item(ApplyButton(rule, member.id, message.channel.id, message.id))
            await self.report(guild, lines, self.evidence(scans, forwarded), view)
            self.save_state()
            return

        dm_wanted = s.dm_members and not staff and action != "delete" and self.can_act_on(member)
        forward_task = asyncio.create_task(self.forward(message, log_channel))
        dm_sent = await self.dm(member, rule, action, message.channel) if dm_wanted else None
        forwarded = await forward_task
        deleted = await self.delete([message, *also_delete])
        lines.append(f"Deleted {deleted} of {count} message(s).")
        outcome = await self.punish(member, action, rule)
        lines.append(outcome.text)
        if outcome.applied:
            swept = await self.sweep(guild, member.id, action, {message.id, *(m.id for m in also_delete)})
            if swept:
                lines.append(f"Also deleted {swept} other recent message(s) of theirs.")
        if dm_sent is not None:
            lines.append("They were sent a DM explaining why." if dm_sent else "The DM didn't go through.")
        if forwarded is not None:
            lines.append("The original post is forwarded above.")

        view = discord.ui.View(timeout=None)
        if outcome.banned:
            view.add_item(UnbanButton(member.id))
        if outcome.applied and action == "timeout":
            view.add_item(UntimeoutButton(member.id))
        if rule != "image" and forwarded is not None and image_sources(forwarded):
            view.add_item(LearnButton(forwarded.channel.id, forwarded.id))
        await self.report(guild, lines, self.evidence(scans, forwarded), view if view.children else None,
                          ping=outcome.braked)
        if not staff:
            self.state.record_catch(rule)
        self.save_state()
        if rule == "trap" and not staff:
            self.schedule_banner_update()

    def evidence(self, scans: list[Scan], forwarded: discord.Message | None) -> list[bytes]:
        """Re-upload images only when forwarding failed; a forward already carries them."""
        return [] if forwarded is not None else [scan.data for scan in scans][:4]

    async def dm(self, member: discord.Member, rule: str, action: str, channel) -> bool:
        if not self.dm_limit.allow():
            log.info("DM rate limit reached; not messaging %s", member.id)
            return False
        # Name the parent channel, never a thread: anyone can title a thread, including with a link.
        # Only letters, digits, hyphens and underscores survive, so no name can form a link.
        name = getattr(getattr(channel, "parent", None), "name", None) or getattr(channel, "name", None) or ""
        name = re.sub(r"[^\w-]", "", name).strip("-_") or "trap"
        text = dm_text(member.guild.name, rule, action, discord.utils.escape_markdown(name),
                       self.settings.timeout_hours, self.rejoin_link(member.guild))
        try:
            await asyncio.wait_for(member.send(text), DM_TIMEOUT)
            return True
        except (discord.HTTPException, TimeoutError):
            return False

    async def delete(self, messages: list) -> int:
        done = 0
        for msg in messages:
            try:
                await msg.delete()
                done += 1
            except discord.NotFound:
                done += 1  # already gone
            except discord.HTTPException as exc:
                log.warning("Couldn't delete message %s (HTTP %s)", msg.id, exc.status)
        return done

    async def sweep(self, guild: discord.Guild, member_id: int, action: str, skip: set[int]) -> int:
        """Delete what a removed member posted recently, from IDs seen live. No history scans."""
        window = QUICK_SWEEP
        if action in ("ban", "softban"):
            window = max(QUICK_SWEEP, min(self.settings.purge_hours * 3600, rules.RecentPosts.KEEP))
        posts = self.recent.take((guild.id, member_id), time.monotonic() - window)
        targets = [self.partial(guild, c, m) for c, m in posts if m not in skip]
        return await self.delete([t for t in targets if t])

    def can_act_on(self, member: discord.Member) -> bool:
        me = member.guild.me
        return member.id != member.guild.owner_id and me is not None and me.top_role > member.top_role

    async def punish(self, member: discord.Member, action: str, rule: str) -> Outcome:
        guild = member.guild
        if action == "delete":
            return Outcome("Action: delete only.")
        if self.is_staff(member):
            return Outcome("Not punished: staff or exempt member. If they didn't post this themselves, "
                           "their account may be compromised.")
        # The brake guards against a bad fingerprint or an overeager blast setting. A post in a
        # trap channel is its own evidence, so trap catches keep working through a raid.
        if rule != "trap" and guild.id in self.braked:
            return Outcome("🛑 Safety brake is on, so no punishment. Review recent actions, then `/scamguard resume`.")
        if not self.can_act_on(member):
            return Outcome("Can't punish: their highest role is at or above mine (or they own the server).")
        reason = f"ScamGuard: {RULE_NAMES[rule]}"
        purge = self.settings.purge_hours
        banned = False
        try:
            if action == "timeout":
                await member.timeout(timedelta(hours=self.settings.timeout_hours), reason=reason)
                result = f"Timed out for {self.settings.timeout_hours}h."
            elif action == "kick":
                await member.kick(reason=reason)
                result = "Kicked."
            else:
                await member.ban(reason=reason, delete_message_seconds=purge * 3600)
                banned = True
                result = f"Banned; their last {purge}h of messages purged." if purge else "Banned."
                if action == "softban":
                    await asyncio.sleep(0.25)  # the gap Honeypot leaves between its ban and unban calls
                    try:
                        await guild.unban(member, reason="ScamGuard softban: cleanup done, may rejoin")
                        banned = False
                    except discord.NotFound:
                        banned = False  # Unknown Ban: someone already lifted it
                    except discord.HTTPException as exc:
                        result += f" ⚠ The unban step failed (HTTP {exc.status}), so they are still banned."
                    if not banned:
                        result = (f"Softbanned: removed, last {purge}h of messages purged, free to rejoin."
                                  if purge else "Softbanned: removed, free to rejoin.")
        except discord.Forbidden:
            return Outcome(f"⚠ `{action}` failed: missing permission or my role is too low.")
        except discord.HTTPException as exc:
            return Outcome(f"⚠ `{action}` failed (HTTP {exc.status}).")
        braked = rule != "trap" and self.count_action(guild.id)
        if braked:
            result += (f"\n🛑 **Safety brake engaged**: {self.settings.brake_limit} image or cross-channel "
                       f"removals within {self.settings.brake_minutes} min. Until someone runs "
                       "`/scamguard resume` those rules only delete. Trap channels keep working. If these "
                       "were false positives, `/scamguard remove` the culprit fingerprint.")
        return Outcome(result, applied=True, banned=banned, braked=braked)

    def count_action(self, guild_id: int) -> bool:
        """Record a punishment; True if this one tripped the safety brake."""
        now, window = time.monotonic(), self.settings.brake_minutes * 60
        q = self.actions[guild_id]
        q.append(now)
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= self.settings.brake_limit and guild_id not in self.braked:
            self.braked.add(guild_id)
            return True
        return False

    async def report(self, guild: discord.Guild | None, lines: list[str], evidence: list[bytes] = (),
                     view: discord.ui.View | None = None, ping: bool = False) -> discord.Message | None:
        if guild is None:
            return None
        text = "\n".join(lines)
        # The console log is kept on disk, so it gets the report without the quoted message text.
        logged = " | ".join(line.replace("\n", " ") for line in lines if not line.startswith("Text:\n"))
        log.info("[%s] %s", guild.name, logged)
        channel = self.log_channel(guild)
        if channel is None or guild.me is None:
            return None
        if self.log_readers(guild, channel):  # members can read it: keep the scam itself out
            text = "\n".join(line for line in lines if not line.startswith("Text:\n"))
            evidence = ()
        extra: dict = {}
        if view is not None:
            extra["view"] = view
        if evidence and channel.permissions_for(guild.me).attach_files:
            extra["files"] = [discord.File(io.BytesIO(d), filename=f"SPOILER_evidence_{i + 1}.{_ext(d)}")
                              for i, d in enumerate(evidence)]
        role_id = self.settings.alert_role_id
        if ping and role_id and role_id != guild.id:
            text = f"<@&{role_id}> {text}"
            extra["allowed_mentions"] = discord.AllowedMentions(roles=[discord.Object(id=role_id)])
        try:
            return await channel.send(text[:1990], **extra)
        except discord.HTTPException as exc:
            log.warning("Couldn't post to the log channel (HTTP %s)", exc.status)
            return None

    # ----------------------------------------------------------------- banners
    def banner_view(self) -> discord.ui.LayoutView:
        view = discord.ui.LayoutView(timeout=None)
        text = discord.ui.TextDisplay(banner_text(self.settings.honeypot_action))
        avatar = self.user.display_avatar.url if self.user else None
        top = discord.ui.Section(text, accessory=discord.ui.Thumbnail(avatar)) if avatar else text
        row = discord.ui.ActionRow(StatsButton(self.state.totals.get("trap", 0)))
        view.add_item(discord.ui.Container(top, row, accent_colour=BANNER_COLOR))
        return view

    async def refresh_banners(self, guild: discord.Guild, post_missing: bool) -> list[str]:
        """Edit each trap channel's banner to the current count, posting any that are missing."""
        results = []
        for cid in self.settings.honeypot_channel_ids:
            channel = guild.get_channel_or_thread(cid)
            if not isinstance(channel, discord.abc.Messageable) or not hasattr(channel, "get_partial_message"):
                continue
            mid = self.state.banners.get(str(cid))
            if mid:
                try:
                    await channel.get_partial_message(mid).edit(view=self.banner_view())
                    results.append(f"Updated the banner in {channel.mention}.")
                    continue
                except discord.NotFound:
                    del self.state.banners[str(cid)]
                except discord.HTTPException as exc:
                    results.append(f"Couldn't update the banner in {channel.mention} (HTTP {exc.status}).")
                    continue
            if post_missing:
                try:
                    msg = await channel.send(view=self.banner_view())
                    self.state.banners[str(cid)] = msg.id
                    results.append(f"Posted a banner in {channel.mention}.")
                except discord.HTTPException as exc:
                    results.append(f"Couldn't post in {channel.mention} (HTTP {exc.status}).")
        self.save_state()
        return results

    def schedule_banner_update(self) -> None:
        if self.banner_task is None or self.banner_task.done():
            self.banner_task = asyncio.create_task(self._banner_update())

    async def _banner_update(self) -> None:
        wait = BANNER_INTERVAL - (time.monotonic() - self.banner_edited)
        if wait > 0:
            await asyncio.sleep(wait)  # catches in the meantime share one edit
        self.banner_edited = time.monotonic()
        for guild in list(self.guilds):
            if self.allowed(guild.id):
                try:
                    await self.refresh_banners(guild, post_missing=False)
                except Exception:
                    log.exception("Banner update failed")


# ===================================================================== access
def _bot(interaction: discord.Interaction) -> ScamGuard | None:
    bot = interaction.client
    return bot if isinstance(bot, ScamGuard) and bot.allowed(interaction.guild_id) else None


def has_perm(interaction: discord.Interaction, perm: str) -> bool:
    """The member holds this Discord permission server-wide (Administrator counts)."""
    user = interaction.user
    if _bot(interaction) is None or not isinstance(user, discord.Member):
        return False
    perms = user.guild_permissions
    return perms.administrator or getattr(perms, perm)


def is_moderator(interaction: discord.Interaction) -> bool:
    """Day-to-day use: fingerprints, status, review buttons. Ban Members, Manage Server or a manager role."""
    bot, user = _bot(interaction), interaction.user
    if bot is None or not isinstance(user, discord.Member):
        return False
    return (has_perm(interaction, "ban_members") or has_perm(interaction, "manage_guild")
            or any(r.id in bot.settings.manager_role_ids for r in user.roles))


def is_admin(interaction: discord.Interaction) -> bool:
    """Settings and trap channels: Manage Server."""
    return has_perm(interaction, "manage_guild")


def can_remove(interaction: discord.Interaction) -> bool:
    """Adding a fingerprint or releasing the brake leads to removals, so it takes Ban Members.
    A manager role alone isn't enough."""
    return has_perm(interaction, "ban_members")


async def deny(interaction: discord.Interaction, need: str = "Ban Members (or a ScamGuard manager role)") -> None:
    await interaction.response.send_message(f"You need **{need}** to use this.", ephemeral=True)


async def append_note(interaction: discord.Interaction, item: discord.ui.Item, note: str) -> None:
    """Add a line to the log message and drop the button that was used. Other buttons stay."""
    view = item.view
    if view is not None:
        view.remove_item(item)
    content = ((interaction.message.content if interaction.message else "") or "")[:1900] + f"\n{note}"
    kwargs = {"content": content, "view": view if view is not None and view.children else None}
    if interaction.response.is_done():
        await interaction.edit_original_response(**kwargs)
    else:
        await interaction.response.edit_message(**kwargs)


# ==================================================================== buttons
class UnbanButton(discord.ui.DynamicItem[discord.ui.Button], template=r"sg:unban:(?P<uid>\d+)"):
    def __init__(self, uid: int) -> None:
        super().__init__(discord.ui.Button(label="Unban", style=discord.ButtonStyle.secondary,
                                           custom_id=f"sg:unban:{uid}"))
        self.uid = uid

    @classmethod
    async def from_custom_id(cls, interaction, item, match, /):
        return cls(int(match["uid"]))

    async def callback(self, interaction: discord.Interaction) -> None:
        if not has_perm(interaction, "ban_members"):
            return await deny(interaction, "Ban Members")
        try:
            await interaction.guild.unban(discord.Object(id=self.uid),
                                          reason=f"ScamGuard: unbanned by {interaction.user} ({interaction.user.id})")
            note = f"↩ Unbanned by {interaction.user.mention}."
        except discord.NotFound:
            note = f"↩ {interaction.user.mention} checked: they weren't banned."
        except discord.HTTPException as exc:
            return await interaction.response.send_message(f"Unban failed (HTTP {exc.status}).", ephemeral=True)
        await append_note(interaction, self, note)


class UntimeoutButton(discord.ui.DynamicItem[discord.ui.Button], template=r"sg:untimeout:(?P<uid>\d+)"):
    def __init__(self, uid: int) -> None:
        super().__init__(discord.ui.Button(label="Remove timeout", style=discord.ButtonStyle.secondary,
                                           custom_id=f"sg:untimeout:{uid}"))
        self.uid = uid

    @classmethod
    async def from_custom_id(cls, interaction, item, match, /):
        return cls(int(match["uid"]))

    async def callback(self, interaction: discord.Interaction) -> None:
        bot = _bot(interaction)
        if bot is None or not has_perm(interaction, "moderate_members"):
            return await deny(interaction, "Timeout Members")
        await interaction.response.defer()  # up to two API calls follow; answer within Discord's 3 seconds
        member = await bot.resolve_member(interaction.guild, self.uid)
        if member is None:
            return await append_note(interaction, self, "↩ They have left the server.")
        try:
            await member.timeout(None, reason=f"ScamGuard: timeout removed by {interaction.user} ({interaction.user.id})")
        except discord.HTTPException as exc:
            return await interaction.followup.send(f"That failed (HTTP {exc.status}).", ephemeral=True)
        await append_note(interaction, self, f"↩ Timeout removed by {interaction.user.mention}.")


class ApplyButton(discord.ui.DynamicItem[discord.ui.Button],
                  template=r"sg:apply:(?P<rule>trap|image|blast):(?P<uid>\d+):(?P<cid>\d+):(?P<mid>\d+)"):
    """Dry-run review: a moderator confirms the catch and ScamGuard acts on it."""

    def __init__(self, rule: str, uid: int, cid: int, mid: int) -> None:
        super().__init__(discord.ui.Button(label="Take action", style=discord.ButtonStyle.danger,
                                           custom_id=f"sg:apply:{rule}:{uid}:{cid}:{mid}"))
        self.rule, self.uid, self.cid, self.mid = rule, uid, cid, mid

    @classmethod
    async def from_custom_id(cls, interaction, item, match, /):
        return cls(match["rule"], int(match["uid"]), int(match["cid"]), int(match["mid"]))

    async def callback(self, interaction: discord.Interaction) -> None:
        bot = _bot(interaction)
        if bot is None:
            return await deny(interaction)
        action = bot.settings.action_for(self.rule)
        perm = PERM_FOR_ACTION[action]
        if not is_moderator(interaction) or not has_perm(interaction, perm):
            return await deny(interaction, perm.replace("_", " ").title())
        await interaction.response.defer()
        guild = interaction.guild
        msg = bot.partial(guild, self.cid, self.mid)
        deleted = await bot.delete([msg]) if msg else 0
        member = await bot.resolve_member(guild, self.uid)
        if member is None:
            result = "They have already left the server."
        else:
            staff = bot.is_staff(member)
            if bot.settings.dm_members and action != "delete" and bot.can_act_on(member) and not staff:
                await bot.dm(member, self.rule, action, guild.get_channel_or_thread(self.cid))
            outcome = await bot.punish(member, action, self.rule)
            result = outcome.text
            if outcome.applied:
                await bot.sweep(guild, member.id, action, {self.mid})
            if not staff:  # counted the same way as a live catch in enforce()
                bot.state.record_catch(self.rule)
                bot.save_state()
                if self.rule == "trap":
                    bot.schedule_banner_update()
        await append_note(interaction, self, f"▶ {interaction.user.mention} took action: deleted {deleted} "
                                             f"message(s). {result}")


class LearnButton(discord.ui.DynamicItem[discord.ui.Button], template=r"sg:learn:(?P<cid>\d+):(?P<mid>\d+)"):
    """Fingerprint the images in a forwarded catch, so copies are removed on sight from now on."""

    def __init__(self, cid: int, mid: int) -> None:
        super().__init__(discord.ui.Button(label="Block these images", style=discord.ButtonStyle.primary,
                                           custom_id=f"sg:learn:{cid}:{mid}"))
        self.cid, self.mid = cid, mid

    @classmethod
    async def from_custom_id(cls, interaction, item, match, /):
        return cls(int(match["cid"]), int(match["mid"]))

    async def callback(self, interaction: discord.Interaction) -> None:
        bot = _bot(interaction)
        if bot is None or not can_remove(interaction):
            return await deny(interaction, "Ban Members")
        await interaction.response.defer(ephemeral=True, thinking=True)
        channel = interaction.guild.get_channel_or_thread(self.cid)
        try:
            source = await channel.fetch_message(self.mid)
        except (AttributeError, discord.HTTPException):
            return await interaction.followup.send("The forwarded copy is gone.", ephemeral=True)
        reply, added = await learn_from(interaction, source)
        await interaction.followup.send(reply, ephemeral=True)
        if added:
            view = self.view
            if view is not None:
                view.remove_item(self)
            content = ((interaction.message.content if interaction.message else "") or "")[:1900]
            await interaction.message.edit(content=f"{content}\n🧩 Images blocked by {interaction.user.mention}.",
                                           view=view if view is not None and view.children else None)


class StatsButton(discord.ui.DynamicItem[discord.ui.Button], template=r"sg:stats"):
    """The counter on a trap banner. Anyone can click it."""

    def __init__(self, count: int = 0) -> None:
        super().__init__(discord.ui.Button(label=f"Caught: {count:,}", emoji="🍯",
                                           style=discord.ButtonStyle.secondary, custom_id="sg:stats"))

    @classmethod
    async def from_custom_id(cls, interaction, item, match, /):
        return cls()

    async def callback(self, interaction: discord.Interaction) -> None:
        bot = _bot(interaction)
        if bot is None:
            return
        total, week = bot.state.totals.get("trap", 0), bot.state.count_since(7 * 86400, "trap")
        await interaction.response.send_message(
            f"ScamGuard has caught {total:,} spam account(s) in trap channels, {week:,} in the last 7 days.",
            ephemeral=True)


# ===================================================================== commands
async def learn_from(interaction: discord.Interaction, message: discord.Message) -> tuple[str, bool]:
    """Fingerprint every image on a message (or on the message it forwards)."""
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    scans = await bot.scan_sources(image_sources(message))
    if not scans:
        return "I couldn't find a readable image on that message.", False
    added, known, blank = [], [], 0
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for scan in scans:
        if not scan.informative:
            blank += 1
            continue
        ref = scanner.Reference(hash=scan.fp.full, kind="full",
                                label=f"{scan.source.name[:80]} (message {message.id})",
                                added_by=f"{interaction.user} ({interaction.user.id})", added_at=stamp)
        try:
            (added if bot.store.add(ref) else known).append(ref.id)
        except (ValueError, OSError) as exc:
            log.error("Couldn't save fingerprint: %s", exc)
            return f"Saving failed: {exc}", False
    reply = []
    if added:
        reply.append(f"Added {len(added)} fingerprint(s): " + ", ".join(f"`{i}`" for i in added)
                     + ". Future posts of these images will be removed automatically.")
    if known:
        reply.append("Already known: " + ", ".join(f"`{i}`" for i in known))
    if blank:
        reply.append(f"Skipped {blank} near-blank image(s): too little detail to fingerprint safely.")
    if added:
        await bot.report(interaction.guild, [
            f"🧩 {interaction.user.mention} added {len(added)} scam image fingerprint(s) "
            f"({', '.join(f'`{i}`' for i in added)}) from {message.jump_url}"])
    return "\n".join(reply), bool(added)


@app_commands.context_menu(name="Add scam image")
@app_commands.default_permissions(ban_members=True)
@app_commands.guild_only()
async def add_scam_image(interaction: discord.Interaction, message: discord.Message) -> None:
    if not can_remove(interaction):
        return await deny(interaction, "Ban Members")
    await interaction.response.defer(ephemeral=True, thinking=True)
    reply, _ = await learn_from(interaction, message)
    await interaction.followup.send(reply, ephemeral=True)


@app_commands.context_menu(name="Check scam image")
@app_commands.default_permissions(ban_members=True)
@app_commands.guild_only()
async def check_scam_image(interaction: discord.Interaction, message: discord.Message) -> None:
    if not is_moderator(interaction):
        return await deny(interaction)
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    await interaction.response.defer(ephemeral=True, thinking=True)
    scans = await bot.scan_sources(image_sources(message))
    if not scans:
        await interaction.followup.send("I couldn't find a readable image on that message.", ephemeral=True)
        return
    threshold = bot.settings.match_threshold
    lines = []
    for scan in scans:
        near = bot.store.nearest(scan.fp)
        name = discord.utils.escape_markdown(scan.source.name[:60])
        if near is None:
            lines.append(f"**{name}**: no fingerprints stored yet.")
            continue
        ref, dist = near
        verdict = "✅ **MATCH**" if dist <= threshold else "no match"
        lines.append(f"**{name}**: {verdict}. Closest is `{ref.id}` ({discord.utils.escape_markdown(ref.label[:60])}) "
                     f"at {dist}/{scanner.HASH_BITS}; the threshold is {threshold}.")
    lines.append("-# Copies of the same image score 0-20. Unrelated images scored 92 or more on this server.")
    await interaction.followup.send("\n".join(lines)[:1990], ephemeral=True)


scamguard_group = app_commands.Group(name="scamguard", description="Manage ScamGuard", guild_only=True,
                                     default_permissions=discord.Permissions(ban_members=True))
honeypot_group = app_commands.Group(name="honeypot", description="Trap channels", parent=scamguard_group)


@scamguard_group.command(name="status", description="Show ScamGuard's settings, catches and setup problems")
async def status_cmd(interaction: discord.Interaction) -> None:
    if not is_moderator(interaction):
        return await deny(interaction)
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    s, refs, st = bot.settings, bot.store.refs, bot.state
    full = sum(r.kind == "full" for r in refs)
    brake = ("🛑 ON: run `/scamguard resume` after reviewing" if interaction.guild_id in bot.braked
             else f"off (engages at {s.brake_limit} image or cross-channel removals within {s.brake_minutes} min)")
    blast = (f"same post in {s.blast_channels}+ channels within {s.blast_seconds}s → `{s.blast_action}`"
             if s.blast_channels >= 2 else "off")
    caught = ", ".join(f"{RULE_NAMES[r]} {st.totals.get(r, 0)} ({st.count_since(7 * 86400, r)} this week)"
                       for r in rules.RULES)
    lines = [
        f"**ScamGuard {__version__}**: {'🧪 DRY RUN (nothing is deleted)' if s.dry_run else 'live'}",
        f"Trap channels → `{s.honeypot_action}`: "
        + (", ".join(f"<#{c}>" for c in s.honeypot_channel_ids) or "none"),
        f"Known images → `{s.image_action}`: {len(refs)} fingerprint(s) ({full} from real files), "
        f"threshold {s.match_threshold}/{scanner.HASH_BITS}",
        f"Cross-channel: {blast}",
        f"Timeout {s.timeout_hours}h · ban purge {s.purge_hours}h · DM members {'on' if s.dm_members else 'off'}"
        + f" · rejoin link {bot.rejoin_link(interaction.guild) or 'none'}",
        f"Safety brake: {brake}",
        f"Log channel: {f'<#{s.log_channel_id}>' if s.log_channel_id else 'not set'}"
        + (f" · alert role <@&{s.alert_role_id}>" if s.alert_role_id else ""),
        f"Exempt roles: {', '.join(f'<@&{r}>' for r in s.exempt_role_ids) or 'none'} · exempt channels: "
        f"{', '.join(f'<#{c}>' for c in s.exempt_channel_ids) or 'none'} · manager roles: "
        f"{', '.join(f'<@&{r}>' for r in s.manager_role_ids) or 'none'}",
        f"Caught since install: {caught}",
    ]
    reach = bot.out_of_reach(interaction.guild)
    if reach:
        lines.append(f"Out of reach (at or above my role): {len(reach)} role(s), "
                     + ", ".join(discord.utils.escape_markdown(r.name) for r in reach[:8]))
    problems = bot.problems(interaction.guild)
    if problems:
        lines.append("**Setup problems**")
        lines += [f"⚠ {p}" for p in problems]
    await interaction.response.send_message("\n".join(lines)[:1990], ephemeral=True)


ACTION_CHOICES = [app_commands.Choice(name=a, value=a) for a in rules.ACTIONS]


@scamguard_group.command(name="config", description="Change ScamGuard's settings (Manage Server)")
@app_commands.describe(
    mode="dry run logs what it would do; live acts",
    log_channel="Private, mods-only channel for reports and evidence",
    honeypot_action="What happens to someone who posts in a trap channel",
    image_action="What happens to someone who posts a known scam image",
    blast_action="What happens to someone who posts the same thing across channels",
    blast_channels="Distinct channels that count as a blast (0 turns the rule off)",
    blast_seconds="Window for a blast, in seconds",
    timeout_hours="Length of a timeout",
    purge_hours="Hours of messages deleted on a ban or softban",
    match_threshold="Fingerprint bits (of 256) allowed to differ for a match",
    dm_members="DM members before acting on them, with account-recovery steps",
    rejoin_invite="Invite in the DM after a softban or kick: a discord.gg link, none, or auto (the vanity link)",
    alert_role="Role pinged when the safety brake engages (pick @everyone to turn off)",
    brake_limit="Image or cross-channel removals that engage the safety brake",
    brake_minutes="Window for the safety brake, in minutes",
)
@app_commands.choices(mode=[app_commands.Choice(name="dry run", value="dry"), app_commands.Choice(name="live", value="live")],
                      honeypot_action=ACTION_CHOICES, image_action=ACTION_CHOICES, blast_action=ACTION_CHOICES)
async def config_cmd(
    interaction: discord.Interaction,
    mode: app_commands.Choice[str] | None = None,
    log_channel: discord.TextChannel | None = None,
    honeypot_action: app_commands.Choice[str] | None = None,
    image_action: app_commands.Choice[str] | None = None,
    blast_action: app_commands.Choice[str] | None = None,
    blast_channels: app_commands.Range[int, 0, 10] | None = None,
    blast_seconds: app_commands.Range[int, 2, 120] | None = None,
    timeout_hours: app_commands.Range[int, 1, 672] | None = None,
    purge_hours: app_commands.Range[int, 0, 168] | None = None,
    match_threshold: app_commands.Range[int, 0, 80] | None = None,
    dm_members: bool | None = None,
    rejoin_invite: app_commands.Range[str, 1, 100] | None = None,
    alert_role: discord.Role | None = None,
    brake_limit: app_commands.Range[int, 1, 100] | None = None,
    brake_minutes: app_commands.Range[int, 1, 1440] | None = None,
) -> None:
    if not is_admin(interaction):
        return await deny(interaction, "Manage Server")
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    changes: dict = {}
    if mode is not None:
        changes["dry_run"] = mode.value == "dry"
    if log_channel is not None:
        changes["log_channel_id"] = log_channel.id
    for name, choice in (("honeypot_action", honeypot_action), ("image_action", image_action),
                         ("blast_action", blast_action)):
        if choice is not None:
            changes[name] = choice.value
    for name, value in (("blast_channels", blast_channels), ("blast_seconds", blast_seconds),
                        ("timeout_hours", timeout_hours), ("purge_hours", purge_hours),
                        ("match_threshold", match_threshold), ("dm_members", dm_members),
                        ("brake_limit", brake_limit), ("brake_minutes", brake_minutes)):
        if value is not None:
            changes[name] = value
    if rejoin_invite is not None:
        value = rejoin_invite.strip()
        changes["rejoin_invite"] = {"auto": "", "none": "none"}.get(value.lower(), value)
    if alert_role is not None:
        changes["alert_role_id"] = 0 if alert_role.is_default() else alert_role.id
    if not changes:
        return await interaction.response.send_message("Pick at least one setting to change.", ephemeral=True)
    new = replace(bot.settings, **changes)
    if "dry_run" in changes and not new.dry_run and not new.log_channel_id:
        return await interaction.response.send_message("Set a log channel before going live.", ephemeral=True)
    try:
        new.save(bot.data_dir / "settings.json")
    except ValueError as exc:
        return await interaction.response.send_message(f"Not saved: {exc}", ephemeral=True)
    except OSError as exc:
        return await interaction.response.send_message(f"Couldn't write settings.json: {exc}", ephemeral=True)
    old, bot.settings = bot.settings, new
    summary = [f"`{k}`: {getattr(old, k)!r} → {getattr(new, k)!r}" for k in changes if getattr(old, k) != getattr(new, k)]
    if not summary:
        return await interaction.response.send_message("Nothing changed.", ephemeral=True)
    problems = bot.problems(interaction.guild)
    await interaction.response.send_message(
        "Saved.\n" + "\n".join(summary) + ("\n" + "\n".join(f"⚠ {p}" for p in problems) if problems else ""),
        ephemeral=True)
    await bot.report(interaction.guild, [f"⚙ {interaction.user.mention} changed settings:", *summary])
    if old.dry_run and not new.dry_run:
        posted = await bot.refresh_banners(interaction.guild, post_missing=True)  # going live puts up the warning
        await bot.report(interaction.guild, ["ScamGuard is live.", *posted])
    elif "honeypot_action" in changes:
        bot.schedule_banner_update()


async def recent_posters(channel: discord.TextChannel, bot: ScamGuard) -> int:
    """Distinct non-staff people who posted in a channel in the last 7 days.

    Without the Server Members intent most history authors arrive as plain users, not
    members. Those count too: only an author known to be staff is left out.
    """
    cutoff = discord.utils.utcnow() - timedelta(days=7)
    authors = set()
    async for msg in channel.history(limit=100, after=cutoff):
        if msg.author.bot or msg.webhook_id:
            continue
        if isinstance(msg.author, discord.Member) and bot.is_staff(msg.author):
            continue
        authors.add(msg.author.id)
    return len(authors)


@honeypot_group.command(name="add", description="Make a channel a trap: any member who posts there is acted on")
@app_commands.describe(channel="The trap channel", confirm="Add it even though members posted there recently")
async def honeypot_add(interaction: discord.Interaction, channel: discord.TextChannel, confirm: bool = False) -> None:
    if not is_admin(interaction):
        return await deny(interaction, "Manage Server")
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    s = bot.settings
    if channel.id in s.honeypot_channel_ids:
        return await interaction.response.send_message(f"{channel.mention} is already a trap.", ephemeral=True)
    if channel.id == s.log_channel_id:
        return await interaction.response.send_message("The log channel can't be a trap.", ephemeral=True)
    await interaction.response.defer(ephemeral=True, thinking=True)
    try:
        posters = await recent_posters(channel, bot)
    except discord.HTTPException:
        posters = 0
    if posters >= 3 and not confirm:
        return await interaction.followup.send(
            f"{posters} members posted in {channel.mention} in the last 7 days. Each of them would have been "
            "acted on. If it's really meant to be a trap, run this again with `confirm: True`.", ephemeral=True)
    new = replace(s, honeypot_channel_ids=[*s.honeypot_channel_ids, channel.id])
    try:
        new.save(bot.data_dir / "settings.json")
    except (ValueError, OSError) as exc:
        return await interaction.followup.send(f"Not saved: {exc}", ephemeral=True)
    bot.settings = new
    if new.dry_run:
        posted = ["Its warning banner goes up when you switch to live with `/scamguard config mode:live`."]
    else:
        posted = await bot.refresh_banners(interaction.guild, post_missing=True)
    await interaction.followup.send(f"{channel.mention} is now a trap.\n" + "\n".join(posted), ephemeral=True)
    await bot.report(interaction.guild, [f"🍯 {interaction.user.mention} made {channel.mention} a trap channel."])


@honeypot_group.command(name="remove", description="Stop treating a channel as a trap")
async def honeypot_remove(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
    if not is_admin(interaction):
        return await deny(interaction, "Manage Server")
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    s = bot.settings
    if channel.id not in s.honeypot_channel_ids:
        return await interaction.response.send_message(f"{channel.mention} isn't a trap.", ephemeral=True)
    new = replace(s, honeypot_channel_ids=[c for c in s.honeypot_channel_ids if c != channel.id])
    try:
        new.save(bot.data_dir / "settings.json")
    except (ValueError, OSError) as exc:
        return await interaction.response.send_message(f"Not saved: {exc}", ephemeral=True)
    bot.settings = new
    mid = bot.state.banners.pop(str(channel.id), None)
    bot.save_state()
    await interaction.response.send_message(f"{channel.mention} is no longer a trap.", ephemeral=True)
    if mid:
        await bot.delete([channel.get_partial_message(mid)])
    await bot.report(interaction.guild, [f"🍯 {interaction.user.mention} removed {channel.mention} from the traps."])


@honeypot_group.command(name="banner", description="Post or refresh the warning banner in every trap channel")
async def honeypot_banner(interaction: discord.Interaction) -> None:
    if not is_admin(interaction):
        return await deny(interaction, "Manage Server")
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    if not bot.settings.honeypot_channel_ids:
        return await interaction.response.send_message("No trap channel is set.", ephemeral=True)
    await interaction.response.defer(ephemeral=True, thinking=True)
    results = await bot.refresh_banners(interaction.guild, post_missing=True)
    await interaction.followup.send("\n".join(results) or "Nothing to do.", ephemeral=True)


exempt_group = app_commands.Group(name="exempt", description="Roles never punished and channels ignored",
                                  parent=scamguard_group)
managers_group = app_commands.Group(name="managers", description="Roles that can use ScamGuard without Ban Members",
                                    parent=scamguard_group)
LIST_LABELS = {"exempt_role_ids": "exempt roles", "exempt_channel_ids": "exempt channels",
               "manager_role_ids": "manager roles"}
ListItem = tuple[str, int, str]  # settings field, ID, mention


async def edit_lists(interaction: discord.Interaction, add: bool, items: list[ListItem]) -> None:
    """Add IDs to, or remove them from, the settings lists, then save and log the change."""
    if not is_admin(interaction):
        return await deny(interaction, "Manage Server")
    if not items:
        return await interaction.response.send_message("Pick a role or a channel.", ephemeral=True)
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    new, done, skipped = bot.settings, [], []
    for field, item_id, mention in items:
        ids = getattr(new, field)
        if add == (item_id in ids):
            skipped.append(f"{mention} is {'already' if add else 'not'} in the {LIST_LABELS[field]}.")
            continue
        new = replace(new, **{field: [*ids, item_id] if add else [i for i in ids if i != item_id]})
        done.append(f"{mention} {'added to' if add else 'removed from'} the {LIST_LABELS[field]}.")
    if done:
        try:
            new.save(bot.data_dir / "settings.json")
        except (ValueError, OSError) as exc:
            return await interaction.response.send_message(f"Not saved: {exc}", ephemeral=True)
        bot.settings = new
    await interaction.response.send_message("\n".join(done + skipped), ephemeral=True)
    if done:
        await bot.report(interaction.guild, [f"⚙ {interaction.user.mention}: " + " ".join(done)])


def exempt_items(role: discord.Role | None, channel) -> list[ListItem]:
    items = []
    if role is not None:
        items.append(("exempt_role_ids", role.id, role.mention))
    if channel is not None:
        items.append(("exempt_channel_ids", channel.id, channel.mention))
    return items


@exempt_group.command(name="add", description="Never punish a role, or ignore a channel completely (Manage Server)")
@app_commands.describe(role="Members with this role are never punished (their scam posts are still deleted)",
                       channel="A channel ScamGuard ignores completely")
async def exempt_add(interaction: discord.Interaction, role: discord.Role | None = None,
                     channel: discord.TextChannel | discord.ForumChannel | discord.VoiceChannel | None = None) -> None:
    if role is not None and role.is_default():
        return await interaction.response.send_message("Exempting @everyone would turn ScamGuard off.", ephemeral=True)
    await edit_lists(interaction, True, exempt_items(role, channel))


@exempt_group.command(name="remove", description="Take a role or channel off the exempt lists (Manage Server)")
async def exempt_remove(interaction: discord.Interaction, role: discord.Role | None = None,
                        channel: discord.TextChannel | discord.ForumChannel | discord.VoiceChannel | None = None) -> None:
    await edit_lists(interaction, False, exempt_items(role, channel))


@managers_group.command(name="add", description="Let a role check images, list and remove fingerprints, and see status (Manage Server)")
async def managers_add(interaction: discord.Interaction, role: discord.Role) -> None:
    if role.is_default():
        return await interaction.response.send_message("@everyone can't be a manager role.", ephemeral=True)
    await edit_lists(interaction, True, [("manager_role_ids", role.id, role.mention)])


@managers_group.command(name="remove", description="Take a role off the manager roles (Manage Server)")
async def managers_remove(interaction: discord.Interaction, role: discord.Role) -> None:
    await edit_lists(interaction, False, [("manager_role_ids", role.id, role.mention)])


@scamguard_group.command(name="list", description="List stored scam image fingerprints")
async def list_cmd(interaction: discord.Interaction) -> None:
    if not is_moderator(interaction):
        return await deny(interaction)
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    lines, size = [f"**{len(bot.store.refs)} fingerprint(s)**"], 0
    for ref in reversed(bot.store.refs):  # newest first
        line = f"`{ref.id}` {ref.kind} · {discord.utils.escape_markdown(ref.label[:70])} · {ref.added_at[:10]}"
        size += len(line) + 1
        if size > 1800:
            lines.append("… (older entries not shown)")
            break
        lines.append(line)
    await interaction.response.send_message("\n".join(lines), ephemeral=True)


@scamguard_group.command(name="remove", description="Delete a stored fingerprint")
@app_commands.describe(ref_id="The ID shown by /scamguard list")
async def remove_cmd(interaction: discord.Interaction, ref_id: app_commands.Range[str, 1, 64]) -> None:
    if not is_moderator(interaction):
        return await deny(interaction)
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    try:
        ref = bot.store.remove(ref_id)
    except (ValueError, OSError) as exc:
        await interaction.response.send_message(f"Couldn't update the file: {exc}", ephemeral=True)
        return
    if ref is None:
        await interaction.response.send_message("No fingerprint has that ID.", ephemeral=True)
        return
    await interaction.response.send_message(f"Removed `{ref.id}`.", ephemeral=True)
    await bot.report(interaction.guild, [f"🗑 {interaction.user.mention} removed fingerprint `{ref.id}` "
                                         f"({discord.utils.escape_markdown(ref.label[:80])})"])


@scamguard_group.command(name="resume", description="Release the safety brake after reviewing recent actions")
async def resume_cmd(interaction: discord.Interaction) -> None:
    if not can_remove(interaction):
        return await deny(interaction, "Ban Members")
    bot: ScamGuard = interaction.client  # type: ignore[assignment]
    was_on = interaction.guild_id in bot.braked
    bot.braked.discard(interaction.guild_id)
    bot.actions[interaction.guild_id].clear()
    await interaction.response.send_message(
        "Safety brake released." if was_on else "The safety brake wasn't on.", ephemeral=True)
    if was_on:
        await bot.report(interaction.guild, [f"▶ {interaction.user.mention} released the safety brake."])


OUR_COMMANDS = (add_scam_image, check_scam_image, scamguard_group)
OUR_COMMAND_NAMES = frozenset(c.name for c in OUR_COMMANDS)


# ========================================================================= main
def load_settings(folder: Path) -> rules.Settings:
    path = folder / "settings.json"
    if path.exists():
        return rules.Settings.load(path)
    settings = rules.Settings()
    settings.save(path)
    log.info("First run: saved default settings to %s", path)
    return settings


def main() -> None:
    load_dotenv(HERE / ".env")
    level = getattr(logging, _env("LOG_LEVEL").upper() or "INFO", logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    try:
        folder = data_dir()
        token = read_token()
        settings = load_settings(folder)
        state = rules.State.load(folder / "state.json")
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        raise SystemExit(2) from None
    except (ValueError, OSError) as exc:
        log.error("Can't load settings or state from %s: %s", folder, exc)
        raise SystemExit(2) from None
    store = scanner.ReferenceStore(folder / "references.json")
    try:
        store.load(seed=SEED_FILE)
    except (ValueError, OSError) as exc:
        log.error("Can't load %s: %s", store.path, exc)
        raise SystemExit(2) from None
    log.info("Loaded %d fingerprint(s) from %s", len(store.refs), store.path)
    bot = ScamGuard(folder, settings, store, state)
    try:
        bot.run(token, log_handler=None)
    except discord.PrivilegedIntentsRequired:
        log.error("Turn on 'Message Content Intent' for this bot (Developer Portal > Bot), then restart.")
        raise SystemExit(2) from None
    except discord.LoginFailure:
        log.error("Discord rejected the token. Reset it in the Developer Portal and update .env.")
        raise SystemExit(2) from None
    except (aiohttp.ClientError, OSError) as exc:
        log.error("Can't reach Discord (%s). Check the network; pm2 will retry.", exc)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
