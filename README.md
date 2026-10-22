# ScamGuard

ScamGuard is a self-hosted Discord bot that removes scam posts, and the accounts posting them, from one server. It catches posts in a trap channel, known scam images, and the same message blasted across channels by a hijacked account. It does no verification or captcha.

It was built for a 43,000-member server to replace two bots, [Honeypot](https://github.com/RiskyMH/honeypot) and [MadHoney](https://github.com/nomadsgalaxy/MadHoney), and its trap-channel and cross-channel rules follow their designs.

## What it catches

Every message runs through three rules, in this order.

| Rule | Catches | Default action |
|---|---|---|
| Trap channel | Any post by a non-staff member in a trap channel, or in a thread under one | softban |
| Known scam image | An image whose fingerprint matches a stored scam image | softban |
| Same post across channels | One post (same picture, or the same text or link) in 3 channels within 10 seconds | 24-hour timeout |

A softban bans and immediately unbans. The member is removed and their last hour of messages is deleted, and they can rejoin once their account is secure.

When ScamGuard acts on someone it:

1. Forwards the original post to the log channel, so the evidence survives the deletion.
2. DMs the member what happened and how to secure the account, with a rejoin link after a softban or kick.
3. Deletes the post, plus any copies in other channels.
4. Applies the action.
5. Deletes anything else that member posted in the last 15 minutes (2 minutes after a timeout or kick), using message IDs it saw live.
6. For two minutes afterward, deletes anything else that account posts.
7. Posts a report with buttons: Unban, Remove timeout, and Block these images, which fingerprints the images in a trap or cross-channel catch.

Staff are never punished. That means anyone with Ban Members, Kick Members, Timeout Members, Manage Messages, Manage Server or Administrator, plus the roles added with `/scamguard exempt add`. A staff post that matches a scam image is still deleted and reported, in case the account was taken over. Staff posts in a trap channel are ignored.

## How it compares

| | Honeypot | MadHoney | ScamGuard |
|---|---|---|---|
| Trap channel | yes | yes | yes, including threads under it |
| Warning banner with catch count | yes | image banner | yes |
| Forwards the spam to the log | optional | re-hosts up to 4 images | always |
| DM with account-recovery steps | yes | only with appeals | yes, with a rejoin link |
| Same message across channels | no | text and file names only (link-only posts slip through) | pictures by fingerprint, text, and links |
| Known scam images | no | no | yes, seeded with 8 real spam files |
| Cleans up the rest of the spammer's posts | only with its search-based cleanup turned on | scans the last 30 messages of every channel | deletes the exact messages it saw them post |
| Trap posts made while the bot was down | no | replays them | replays them |
| Slash command replies in the trap | punishes the person who ran it | ignored | punishes the person who ran it |
| Webhook posts in the trap | ignored | deleted, mods alerted | deleted, mods alerted |
| Staff exemption | owner and Administrator only | Manage Server and chosen roles | any moderation permission and chosen roles |
| Safety brake for bad fingerprints | n/a | no | yes, and trap catches keep working during a raid |
| Test mode with a one-click "Take action" | no | Review mode | Dry run |
| Captcha verification | no | yes | no, by design |
| Cross-server shared ban list | no | yes | no |
| Servers per instance | many | many | one |

## How well the image matching holds up

Each image is reduced to a 256-bit fingerprint of its light and dark structure. Copies of one picture differ by a few bits, and unrelated pictures differ by about half of them. A match is 48 bits or fewer.

The numbers below come from the server ScamGuard was built for, measured in October 2026. The positives are the 84 attachments of a celebrity-casino scam, posted 21 times as 4-image sets between July and October and forwarded to a moderator log by a trap bot. The negatives are 601 recent uploads by members.

| Case | Distance (out of 256) |
|---|---|
| Each spam picture against its stored fingerprint, original file | 14 or less |
| The same, from the downscaled copy ScamGuard fetches first | 14 or less |
| Two different spam pictures | 112 or more |
| Member uploads against the stored fingerprints | 92 or more |
| Fingerprints cut from a screenshot of Discord's 4-image preview grid, against the real files | 106 or more: none matched |

The last row is why the seed in `seed_references.json` holds fingerprints of the real files rather than of a screenshot. When a new scam image appears, right-click the message → Apps → Add scam image, or press Block these images on a report. A fingerprint from the real file matches its copies almost exactly.

## Setting it up

### 1. Create the Discord application

ScamGuard needs its own application. It refuses to overwrite another bot's commands.

At <https://discord.com/developers/applications>, create an application and fill in:

| Page | Field | Value |
|---|---|---|
| General Information | App Icon | `Logo.png` |
| | Name, Description | ScamGuard, and a line about what it does on your server |
| | Privacy Policy URL | your server's policy, if you have one |
| Installation | Installation Contexts | Guild Install only |
| | Install Link | None |
| Bot | Icon, Banner | `Logo.png`, `Banner.png` |
| | Public Bot | off, so only you can add it to a server |
| | Message Content Intent | on |
| | Presence, Server Members | off |
| | Token | Reset Token, then put it in `.env` |

Turn the Message Content intent on before the bot joins your server. Once an app reaches 10,000 users, Discord reviews that toggle, and a single large server can push it past that line on the day it joins.

The account that owns the application needs two-factor authentication if your server requires it for moderation. Without it the bot can't ban, kick, time out or delete.

### 2. Invite it

Replace `APP_ID` with the Application ID from General Information:

```
https://discord.com/oauth2/authorize?client_id=APP_ID&scope=bot+applications.commands&permissions=1099511737350
```

That grants View Channels, Send Messages, Attach Files, Read Message History, Manage Messages, Kick Members, Ban Members and Timeout Members. It does not ask for Administrator.

Then put ScamGuard's highest role above the member roles it should act on and below your moderator roles. Discord only lets a bot act on members whose highest role is below its own. Make sure no autorole or verification bot gives ScamGuard a restricted new-member role.

### 3. Run it

ScamGuard needs Python 3.11 or later. The tests run on 3.13 with discord.py 2.7.1 and Pillow 11.3.

```
python3 -m venv venv
venv/bin/pip install -r requirements.txt
cp .env.example .env
chmod 600 .env          # then put the token after DISCORD_TOKEN=
venv/bin/python ScamGuard.py
```

Keep it running with your process manager of choice. With pm2:

```
pm2 start ScamGuard.py --name ScamGuard --interpreter ./venv/bin/python
pm2 save
```

`.env` holds the bot token and nothing else. Everything else is set in Discord and saved by the bot in `data/`: `settings.json` (every setting below), `references.json` (fingerprints) and `state.json` (catch counts, banner message IDs).

ScamGuard serves one server: the first server it joins that the application's owner belongs to. It saves that server and registers its commands there. In any other server it does nothing, and it never leaves one, so a stranger who adds it gets nothing. If it is removed from its server, it serves the next one its owner invites it to.

### 4. Configure it in Discord and go live

1. It starts in dry run: it forwards and reports what it would do, each report has a Take action button, and nothing is deleted.
2. `/scamguard config log_channel:#your-mod-log`. Use a private, mods-only channel: forwarded evidence lands there.
3. `/scamguard honeypot add channel:#some-channel`. Pick a channel nobody has a reason to post in, and give it a name that doesn't say "trap". Its warning banner waits for live mode.
4. `/scamguard status` lists anything still missing: permissions, role position, channel access.
5. After a day or two of clean reports, `/scamguard config mode:live`. That posts the warning banner in each trap channel.

## Commands

Everything replies only to you. Day-to-day use needs Ban Members or a manager role. Settings, trap channels and the role and channel lists need Manage Server.

| Command | Does |
|---|---|
| Right-click a message → Apps → Add scam image | Fingerprint its images (works on forwarded copies in the log) |
| Right-click a message → Apps → Check scam image | Show the closest match and its distance, no action |
| `/scamguard status` | Mode, rules, counts, lists, out-of-reach roles, and any setup problems |
| `/scamguard config` | Change the settings below (Manage Server) |
| `/scamguard honeypot add / remove / banner` | Manage trap channels and their warning banner (Manage Server) |
| `/scamguard exempt add / remove` | A role whose members are never punished (their scam posts are still deleted), or a channel ScamGuard ignores (Manage Server) |
| `/scamguard managers add / remove` | A role that can use the day-to-day commands and buttons without Ban Members (Manage Server) |
| `/scamguard list` / `remove <id>` | List or delete fingerprints |
| `/scamguard resume` | Release the safety brake |

`/scamguard honeypot add` refuses a channel where 3 or more members posted in the past week, unless you pass `confirm: True`. Every one of them would have been removed.

Members with Ban Members, Kick Members, Timeout Members, Manage Messages, Manage Server or Administrator are always exempt. The log channel is always ignored.

To add image files from disk, for example originals someone sent you:

```
venv/bin/python add_reference.py scam1.png scam2.jpg --label "casino scam v2"
```

A running bot picks up the change without a restart.

## Settings

All of these change with `/scamguard config`.

| Setting | Default | Meaning |
|---|---|---|
| `mode` | dry run | Dry run reports what it would do and changes nothing. Going live needs a log channel |
| `log_channel` | none | Private channel for reports and forwarded evidence |
| `honeypot_action` / `image_action` / `blast_action` | softban / softban / timeout | One of delete, timeout, kick, softban, ban |
| `blast_channels` / `blast_seconds` | 3 / 10 | Same post in this many channels within this many seconds. 0 channels turns the rule off |
| `timeout_hours` / `purge_hours` | 24 / 1 | Timeout length, and hours of messages deleted on a ban or softban |
| `match_threshold` | 48 | Fingerprint bits that may differ (cap 80) |
| `dm_members` | on | DM members before acting on them, with account-recovery steps |
| `rejoin_invite` | auto | The link in that DM after a softban or kick. `auto` uses the server's vanity link if it has one, `none` leaves it out, or give a discord.gg link |
| `alert_role` | none | Pinged when the safety brake engages. Pick @everyone to turn it off |
| `brake_limit` / `brake_minutes` | 5 / 10 | Image or cross-channel removals that pause those two rules until `/scamguard resume` |

The cross-channel window is short because speed is the signal. MadHoney uses 5 seconds for the same check. If blasts start arriving more slowly, raise `blast_seconds`. Text under 12 characters with no link never counts, so "thanks!" in three channels is fine.

## Security

- The token is read from `.env`, removed from the environment after reading, and never logged.
- No Administrator, Manage Roles, Manage Channels or Manage Server. Startup warns if it has Administrator.
- It serves one server that its owner belongs to, registers commands only there, and never leaves other servers, in case the token is ever shared.
- The role and channel lists that decide who is exempt and who manages ScamGuard need Manage Server to change, so a manager can't widen their own access. Every change is posted in the log channel.
- Image files from strangers are the main attack surface. Only PNG, JPEG, WEBP and GIF decoders are reachable. Pixel dimensions are checked before decoding. Downloads are capped at 15 MB, come only from Discord's CDN over HTTPS without following redirects, and four at most are processed at once with a 30-second limit each.
- Startup checks permissions, the log channel's privacy, trap channel access and role position, then posts any problems in the log channel and in `/scamguard status`.
- What it can't protect against: a leaked token (reset it at once), a moderator who fingerprints an innocent image (the log shows who added what, and the brake limits the damage), scams that continue in DMs, and text scams with no trap or cross-channel pattern (keyword filters and AutoMod cover those).

## Privacy

Message text and images are processed in memory and discarded. In `data/`, ScamGuard stores the 256-bit fingerprints of images moderators mark as scams (with the file name and message ID each came from, and which moderator added it), its settings, catch counts with times, and message IDs it has already handled. Its console log records each action, who and where and which rule, but never the text of the message. The quoted text appears only in the report posted to your private log channel.

## Tests

```
python3 -m unittest discover -s tests -v
```

89 tests cover image decoding safety, fingerprints, the reference store, the cross-channel tracker, settings and the commands that change them, binding to one server, the three rules end to end, the DM order, the review button, and shared-token safety.

## Credits

Swampfrog created the original ScamGuard: the image fingerprinting, the hardened image handling, the cross-channel image check, the safety brake and dry run. Hifihedgehog added the trap channel, the cross-channel text and link check, the settings commands and the real-file seed.

## License

MIT. See [LICENSE](LICENSE).
