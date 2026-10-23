"""Detection state, settings and saved state for ScamGuard.

No Discord code lives here, so everything in this module is unit-tested
without a bot token.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from collections import deque
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

import scanner

ACTIONS = ("delete", "timeout", "kick", "softban", "ban")
RULES = ("trap", "image", "blast")
SAME_IMAGE_BITS = 16  # two images this close are the same picture (copies measured 0-14 apart)
MIN_TEXT = 12         # shorter text-only posts ("hi", "thanks") never count as a blast


# ------------------------------------------------------------- file helpers
def write_json(path: Path, data: dict) -> None:
    """Atomic write: readers never see a half-written file. Owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:  # mkstemp creates it 0600
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


# ---------------------------------------------------- cross-channel blasts
_MENTION = re.compile(r"<@[!&]?\d+>|<#\d+>|@everyone|@here")
_LINK = re.compile(r"https?://\S+|discord(?:\.gg|(?:app)?\.com/invite)/\S+", re.I)


def normalize_text(content: str | None) -> str:
    """Lowercase, drop mentions, collapse spacing.

    Links are kept on purpose: a link-only blast is still a blast, and a
    signature that strips links would let one through as an empty message.
    """
    return " ".join(_MENTION.sub(" ", (content or "").lower()).split())


def meaningful_text(text: str) -> bool:
    return len(text) >= MIN_TEXT or _LINK.search(text) is not None


@dataclass(frozen=True)
class Post:
    at: float
    channel_id: int
    message_id: int
    text: str
    hashes: tuple[int, ...]

    def comparable(self) -> bool:
        return bool(self.hashes) or meaningful_text(self.text)


def same_post(a: Post, b: Post) -> bool:
    """Same picture (any image pair within SAME_IMAGE_BITS), or the same meaningful text."""
    if any(scanner.distance(x, y) <= SAME_IMAGE_BITS for x in a.hashes for y in b.hashes):
        return True
    return a.text == b.text and meaningful_text(a.text)


class BlastTracker:
    """Each member's recent posts. Fires when one post lands in enough distinct
    channels inside the window, then forgets those posts so a blast fires once."""

    PER_MEMBER = 50

    def __init__(self) -> None:
        self.posts: dict[tuple[int, int], deque[Post]] = {}

    def record(self, key: tuple[int, int], post: Post, channels: int, seconds: float) -> list[Post] | None:
        """Add a post and return the posts that make a blast with it, if any: the same post in
        `channels` distinct channels within `seconds` of it. A post with the message ID of one
        already held is an edit, and replaces it. `at` is Discord's time for the post or edit,
        so posts that reach the bot in a burst, as missed events do after a reconnect, are
        judged by when they were made."""
        if channels < 2 or not post.comparable():
            return None
        held = self.posts.get(key, ())
        newest = max([post.at, *(p.at for p in held)])
        q = deque([p for p in held if p.message_id != post.message_id and newest - p.at <= seconds],
                  maxlen=self.PER_MEMBER)
        q.append(post)
        self.posts[key] = q
        same = [p for p in q if same_post(p, post) and abs(p.at - post.at) <= seconds]
        if len({p.channel_id for p in same}) < channels:
            return None
        rest = [p for p in q if p not in same]
        if rest:
            self.posts[key] = deque(rest, maxlen=self.PER_MEMBER)
        else:
            del self.posts[key]
        return same

    def prune(self, now: float, seconds: float) -> None:
        for key in [k for k, q in self.posts.items() if not q or now - q[-1].at > seconds]:
            del self.posts[key]


class RecentPosts:
    """IDs of what each member posted in the last KEEP seconds.

    When ScamGuard removes someone it deletes exactly these messages, so it
    never has to scan channel history for leftovers. Only IDs and times are
    held, in memory.
    """

    KEEP = 15 * 60
    PER_MEMBER = 100

    def __init__(self) -> None:
        self.by_member: dict[tuple[int, int], deque[tuple[float, int, int]]] = {}
        self._adds = 0

    def add(self, key: tuple[int, int], at: float, channel_id: int, message_id: int) -> None:
        q = self.by_member.setdefault(key, deque(maxlen=self.PER_MEMBER))
        while q and at - q[0][0] > self.KEEP:
            q.popleft()
        q.append((at, channel_id, message_id))
        self._adds += 1
        if self._adds % 1000 == 0:
            self.prune(at)

    def take(self, key: tuple[int, int], since: float) -> list[tuple[int, int]]:
        """Remove and return (channel_id, message_id) for posts at or after `since`."""
        q = self.by_member.pop(key, None) or ()
        return [(c, m) for at, c, m in q if at >= since]

    def prune(self, now: float) -> None:
        for key in [k for k, q in self.by_member.items() if not q or now - q[-1][0] > self.KEEP]:
            del self.by_member[key]


class RateLimit:
    """At most `limit` events per `seconds`."""

    def __init__(self, limit: int, seconds: float) -> None:
        self.limit, self.seconds = limit, seconds
        self.events: deque[float] = deque()

    def allow(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        while self.events and now - self.events[0] > self.seconds:
            self.events.popleft()
        if len(self.events) >= self.limit:
            return False
        self.events.append(now)
        return True


# ------------------------------------------------------------------ settings
INVITE_RE = re.compile(r"https://(?:discord\.gg|discord\.com/invite)/[A-Za-z0-9-]{2,32}")

# name -> (low, high) for whole-number settings
LIMITS = {
    "blast_channels": (0, 10),     # 0 turns the rule off
    "blast_seconds": (2, 120),
    "timeout_hours": (1, 672),     # Discord's maximum timeout is 28 days
    "purge_hours": (0, 168),       # Discord's maximum ban purge is 7 days
    "match_threshold": (0, 80),    # unrelated member images measured 92 or more
    "brake_limit": (1, 100),
    "brake_minutes": (1, 1440),
}


@dataclass
class Settings:
    """Everything ScamGuard is configured with, besides its token. Changed with
    /scamguard commands and saved to settings.json."""

    guild_id: int = 0                     # the one server served; set when the bot first joins it
    dry_run: bool = True
    log_channel_id: int = 0
    honeypot_channel_ids: list[int] = field(default_factory=list)
    exempt_role_ids: list[int] = field(default_factory=list)
    exempt_channel_ids: list[int] = field(default_factory=list)
    manager_role_ids: list[int] = field(default_factory=list)
    image_action: str = "softban"
    honeypot_action: str = "softban"
    blast_action: str = "timeout"
    blast_channels: int = 3
    blast_seconds: int = 10
    timeout_hours: int = 24
    purge_hours: int = 1
    match_threshold: int = 48
    dm_members: bool = True
    rejoin_invite: str = ""               # "" = the server's vanity link, "none" = no link, or an invite URL
    alert_role_id: int = 0
    brake_limit: int = 5
    brake_minutes: int = 10

    def validate(self) -> None:
        for name in ("image_action", "honeypot_action", "blast_action"):
            if getattr(self, name) not in ACTIONS:
                raise ValueError(f"{name} must be one of: {', '.join(ACTIONS)}")
        for name, (lo, hi) in LIMITS.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
                raise ValueError(f"{name} must be a whole number from {lo} to {hi}")
        for name in ("dry_run", "dm_members"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be true or false")
        for name in ("guild_id", "log_channel_id", "alert_role_id"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a Discord ID")
        for name, most in (("honeypot_channel_ids", 10), ("exempt_role_ids", 50),
                           ("exempt_channel_ids", 50), ("manager_role_ids", 25)):
            ids = getattr(self, name)
            if (not isinstance(ids, list) or len(ids) > most or len(set(ids)) != len(ids)
                    or not all(isinstance(i, int) and not isinstance(i, bool) and i > 0 for i in ids)):
                raise ValueError(f"{name} must be a list of up to {most} distinct Discord IDs")
        if self.rejoin_invite not in ("", "none") and not INVITE_RE.fullmatch(self.rejoin_invite):
            raise ValueError("rejoin_invite must be a https://discord.gg/... link, none, or empty for automatic")

    def action_for(self, rule: str) -> str:
        return {"trap": self.honeypot_action, "image": self.image_action, "blast": self.blast_action}[rule]

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> "Settings":
        if not isinstance(data, dict):
            raise ValueError("settings file is not a JSON object")
        known = {f.name for f in fields(cls)}
        settings = cls(**{k: v for k, v in data.items() if k in known})
        settings.validate()
        return settings

    @classmethod
    def load(cls, path: Path) -> "Settings":
        return cls.from_json(json.loads(path.read_text(encoding="utf-8")))

    def save(self, path: Path) -> None:
        self.validate()
        write_json(path, self.to_json())


# --------------------------------------------------------------------- state
@dataclass
class State:
    """Counters and bookkeeping that survive restarts. Saved to state.json.

    Holds no message text. Member IDs stay only as long as they're needed: who
    was reported in the last 10 minutes, and whose cleanup is still due.
    """

    totals: dict[str, int] = field(default_factory=dict)       # rule -> catches since install
    recent: list[list] = field(default_factory=list)           # [unix time, rule], newest last
    banners: dict[str, int] = field(default_factory=dict)      # trap channel ID -> banner message ID
    handled: list[int] = field(default_factory=list)           # trap message IDs already acted on
    last_seen: float = 0.0                                     # unix time, stamped every minute
    cleanups: list[list] = field(default_factory=list)         # [guild, member, caught message, action, due unix time]
    reported: dict[str, float] = field(default_factory=dict)   # "guild:member" -> unix time they were last reported
    braked: list[int] = field(default_factory=list)            # guilds whose safety brake is engaged
    punishments: list[list] = field(default_factory=list)      # [guild, unix time] of image and cross-channel removals

    MAX_RECENT = 2000
    MAX_HANDLED = 500

    def record_catch(self, rule: str, now: float | None = None) -> None:
        self.totals[rule] = self.totals.get(rule, 0) + 1
        self.recent.append([time.time() if now is None else now, rule])
        del self.recent[:-self.MAX_RECENT]

    def mark_handled(self, message_id: int) -> None:
        if message_id not in self.handled:
            self.handled.append(message_id)
            del self.handled[:-self.MAX_HANDLED]

    def count_since(self, seconds: float, rule: str | None = None, now: float | None = None) -> int:
        cutoff = (time.time() if now is None else now) - seconds
        return sum(1 for at, r in self.recent if at >= cutoff and (rule is None or r == rule))

    def to_json(self) -> dict:
        return {"totals": self.totals, "recent": self.recent, "banners": self.banners,
                "handled": self.handled, "last_seen": self.last_seen, "cleanups": self.cleanups,
                "reported": self.reported, "braked": self.braked, "punishments": self.punishments}

    @classmethod
    def load(cls, path: Path) -> "State":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("state file is not a JSON object")
        state = cls(
            totals={str(k): int(v) for k, v in dict(data.get("totals", {})).items()},
            recent=[[float(a), str(r)] for a, r in list(data.get("recent", []))][-cls.MAX_RECENT:],
            banners={str(k): int(v) for k, v in dict(data.get("banners", {})).items()},
            handled=[int(m) for m in list(data.get("handled", []))][-cls.MAX_HANDLED:],
            last_seen=float(data.get("last_seen", 0.0)),
            cleanups=[[int(g), int(u), int(m), str(a), float(d)] for g, u, m, a, d in list(data.get("cleanups", []))],
            reported={str(k): float(v) for k, v in dict(data.get("reported", {})).items()},
            braked=[int(g) for g in list(data.get("braked", []))],
            punishments=[[int(g), float(t)] for g, t in list(data.get("punishments", []))],
        )
        return state

    def save(self, path: Path) -> None:
        write_json(path, self.to_json())
