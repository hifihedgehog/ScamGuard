"""Tests for the cross-channel tracker, recent-post cleanup, settings and saved state.
Run from the project folder:  python3.13 -m unittest discover -s tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rules  # noqa: E402
import scanner  # noqa: E402

KEY = (1, 50)


def post(at, channel, mid, text="", hashes=()):
    return rules.Post(at, channel, mid, rules.normalize_text(text), tuple(hashes))


class Normalize(unittest.TestCase):
    def test_mentions_case_and_spacing(self):
        self.assertEqual(rules.normalize_text("FREE   Nitro <@123> <@&9> <#7> @everyone"), "free nitro")

    def test_links_are_kept(self):
        self.assertEqual(rules.normalize_text("claim https://scam.example/x"), "claim https://scam.example/x")
        self.assertTrue(rules.meaningful_text("https://scam.example/x"))
        self.assertTrue(rules.meaningful_text("discord.gg/abcdef"))

    def test_short_text_is_not_meaningful(self):
        for text in ("hi", "thanks!", "ok", ""):
            self.assertFalse(rules.meaningful_text(text), text)
        self.assertTrue(rules.meaningful_text("check my bio for the deal"))


class Blast(unittest.TestCase):
    def test_trips_on_third_channel_and_fires_once(self):
        t = rules.BlastTracker()
        text = "Free nitro for everyone, claim it here"
        self.assertIsNone(t.record(KEY, post(0, 10, 1, text), 3, 10))
        self.assertIsNone(t.record(KEY, post(1, 11, 2, text), 3, 10))
        same = t.record(KEY, post(2, 12, 3, text), 3, 10)
        self.assertEqual({p.message_id for p in same}, {1, 2, 3})
        self.assertIsNone(t.record(KEY, post(3, 13, 4, text), 3, 10))  # already fired; starts over

    def test_link_only_blast_trips(self):
        t = rules.BlastTracker()
        for i, channel in enumerate((10, 11)):
            self.assertIsNone(t.record(KEY, post(i, channel, i, "https://scam.example/x"), 3, 10))
        self.assertIsNotNone(t.record(KEY, post(2, 12, 2, "<@99> https://scam.example/x"), 3, 10))

    def test_same_image_with_different_text_trips(self):
        t = rules.BlastTracker()
        img = (1 << 255) | 777
        t.record(KEY, post(0, 10, 1, "look", [img]), 3, 10)
        t.record(KEY, post(1, 11, 2, "wow", [img ^ 0b1011]), 3, 10)  # recompressed copy: 3 bits off
        self.assertIsNotNone(t.record(KEY, post(2, 12, 3, "", [img]), 3, 10))

    def test_no_trip_cases(self):
        cases = {
            "same channel repeated": [post(i, 10, i, "the same long message again") for i in range(5)],
            "too slow": [post(i * 11, 10 + i, i, "the same long message again") for i in range(3)],
            "different text": [post(i, 10 + i, i, f"a different long message {i}") for i in range(3)],
            "short text": [post(i, 10 + i, i, "hi all") for i in range(3)],
            "different images": [post(i, 10 + i, i, "", [(2 ** 256 - 1) // (i + 3)]) for i in range(3)],
        }
        for name, posts in cases.items():
            with self.subTest(name):
                t = rules.BlastTracker()
                self.assertTrue(all(t.record(KEY, p, 3, 10) is None for p in posts))

    def test_an_edit_replaces_its_message_instead_of_adding_one(self):
        t = rules.BlastTracker()
        scam = "Free nitro for everyone, claim it here"
        for i in range(5):  # one message edited again and again is one channel
            self.assertIsNone(t.record(KEY, post(i, 10, 1, f"{scam} {'!' * i}"), 3, 10))
        self.assertEqual(len(t.posts[KEY]), 1)
        t.record(KEY, post(5, 11, 2, "a harmless long message, nothing to see"), 3, 10)
        t.record(KEY, post(6, 11, 2, scam), 3, 10)  # message 2 edited into the scam
        self.assertIsNone(t.record(KEY, post(6.5, 10, 1, scam), 3, 10))  # message 1 settles on it too
        same = t.record(KEY, post(7, 12, 3, scam), 3, 10)
        self.assertEqual(sorted(p.message_id for p in same), [1, 2, 3])

    def test_judged_by_discords_times_not_arrival_order(self):
        t = rules.BlastTracker()
        text = "the same long message again"
        # Posted a minute apart, delivered together after a reconnect, newest first.
        for at, channel, mid in ((120, 12, 3), (60, 11, 2), (0, 10, 1)):
            self.assertIsNone(t.record(KEY, post(at, channel, mid, text), 3, 10))

    def test_off_when_channels_below_two(self):
        t = rules.BlastTracker()
        self.assertIsNone(t.record(KEY, post(0, 10, 1, "the same long message again"), 0, 10))
        self.assertEqual(t.posts, {})

    def test_members_are_tracked_separately(self):
        t = rules.BlastTracker()
        text = "the same long message again"
        for i in range(3):
            self.assertIsNone(t.record((1, 100 + i), post(i, 10 + i, i, text), 3, 10))

    def test_prune(self):
        t = rules.BlastTracker()
        t.record(KEY, post(0, 10, 1, "the same long message again"), 3, 10)
        t.prune(100, 10)
        self.assertEqual(t.posts, {})


class Recent(unittest.TestCase):
    def test_take_returns_window_and_forgets(self):
        r = rules.RecentPosts()
        for i in range(5):
            r.add(KEY, 100 + i * 60, 10 + i, i)
        self.assertEqual(r.take(KEY, 100 + 2 * 60), [(12, 2), (13, 3), (14, 4)])
        self.assertEqual(r.take(KEY, 0), [])

    def test_old_posts_drop_off(self):
        r = rules.RecentPosts()
        r.add(KEY, 0, 10, 1)
        r.add(KEY, rules.RecentPosts.KEEP + 1, 11, 2)
        self.assertEqual(r.take(KEY, -1), [(11, 2)])
        r.add((1, 51), 0, 10, 3)
        r.prune(rules.RecentPosts.KEEP + 1)
        self.assertEqual(r.by_member, {})


class Limits(unittest.TestCase):
    def test_rate_limit(self):
        lim = rules.RateLimit(2, 60)
        self.assertEqual([lim.allow(0), lim.allow(1), lim.allow(2), lim.allow(61)], [True, True, False, True])


class SettingsTests(unittest.TestCase):
    def test_defaults_are_valid(self):
        s = rules.Settings()
        s.validate()
        self.assertTrue(s.dry_run)
        self.assertEqual((s.honeypot_action, s.image_action, s.blast_action), ("softban", "softban", "timeout"))
        self.assertEqual(s.action_for("blast"), "timeout")

    def test_rejects_bad_values(self):
        bad = [
            {"image_action": "nuke"}, {"blast_channels": 11}, {"blast_seconds": 1}, {"match_threshold": 81},
            {"timeout_hours": 0}, {"purge_hours": 169}, {"dry_run": "yes"}, {"blast_channels": True},
            {"rejoin_invite": "https://evil.example/x"}, {"rejoin_invite": "http://discord.gg/abc"},
            {"honeypot_channel_ids": list(range(1, 12))}, {"honeypot_channel_ids": ["1"]}, {"log_channel_id": -1},
            {"guild_id": -1}, {"guild_id": True}, {"exempt_role_ids": [5, 5]}, {"manager_role_ids": [True]},
            {"exempt_channel_ids": "5"}, {"rejoin_invite": "off"},
        ]
        for change in bad:
            with self.subTest(change), self.assertRaises(ValueError):
                rules.Settings.from_json({**rules.Settings().to_json(), **change})
        for good in ({"rejoin_invite": "none"}, {"rejoin_invite": ""}, {"exempt_role_ids": [5, 6], "guild_id": 7}):
            with self.subTest(good):
                rules.Settings.from_json({**rules.Settings().to_json(), **good})

    def test_round_trip_and_unknown_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            s = rules.Settings(dry_run=False, log_channel_id=5, honeypot_channel_ids=[7, 8],
                               rejoin_invite="https://discord.gg/example")
            s.save(path)
            data = json.loads(path.read_text())
            data["from_a_future_version"] = 1
            path.write_text(json.dumps(data))
            self.assertEqual(rules.Settings.load(path), s)


class StateTests(unittest.TestCase):
    def test_counts_caps_and_round_trip(self):
        st = rules.State()
        st.record_catch("trap", now=1000)
        st.record_catch("trap", now=10_000)
        st.record_catch("image", now=10_000)
        self.assertEqual(st.totals, {"trap": 2, "image": 1})
        self.assertEqual(st.count_since(100, now=10_050), 2)
        self.assertEqual(st.count_since(100, "trap", now=10_050), 1)
        for mid in range(rules.State.MAX_HANDLED + 10):
            st.mark_handled(mid)
        self.assertEqual(len(st.handled), rules.State.MAX_HANDLED)
        self.assertNotIn(0, st.handled)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            st.banners["7"] = 99
            st.save(path)
            self.assertEqual(rules.State.load(path).to_json(), st.to_json())
            self.assertEqual(rules.State.load(Path(tmp) / "missing.json").totals, {})


class Seed(unittest.TestCase):
    def test_seed_is_eight_distinct_real_files(self):
        store = scanner.ReferenceStore(Path("/nonexistent/refs.json"))
        raw = json.loads((Path(__file__).resolve().parents[1] / "seed_references.json").read_text())
        refs = [scanner.Reference.from_json(e) for e in raw["entries"]]
        store.refs = refs
        self.assertEqual(len(refs), 8)
        self.assertTrue(all(r.kind == "full" for r in refs))
        closest = min(scanner.distance(a.hash, b.hash) for i, a in enumerate(refs) for b in refs[i + 1:])
        self.assertGreater(closest, 100)  # measured 112: no two seeds are near each other


if __name__ == "__main__":
    unittest.main()
