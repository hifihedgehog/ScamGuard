"""Tests for decoding safety, fingerprint behavior and the reference store.
Run from the project folder:  python -m unittest discover -s tests -v
"""
import io
import json
import os
import random
import stat
import struct
import sys
import tempfile
import time
import unittest
import zlib
from pathlib import Path

from PIL import Image, ImageDraw

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scanner  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def scene(seed: int, size=(900, 600), dark=True) -> Image.Image:
    """A synthetic UI-ish picture with random panels, buttons and text."""
    rng = random.Random(seed)
    img = Image.new("RGB", size, (12, 14, 30) if dark else (240, 240, 240))
    d = ImageDraw.Draw(img)
    for _ in range(25):
        x0, y0 = rng.randrange(size[0]), rng.randrange(size[1])
        x1, y1 = x0 + rng.randrange(20, 300), y0 + rng.randrange(10, 160)
        d.rectangle((x0, y0, x1, y1), fill=tuple(rng.randrange(256) for _ in range(3)))
    for _ in range(30):
        d.text((rng.randrange(size[0]), rng.randrange(size[1])), "scam " * rng.randrange(1, 6), fill=(255, 255, 255))
    return img


def encode(img: Image.Image, fmt="PNG", **kw) -> bytes:
    buf = io.BytesIO()
    img.save(buf, fmt, **kw)
    return buf.getvalue()


def png_header_only(width: int, height: int) -> bytes:
    """A tiny PNG that *claims* huge dimensions (decompression-bomb shape)."""
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\x00" * 64)) + chunk(b"IEND", b"")


class DecodingSafety(unittest.TestCase):
    def test_rejects_non_image(self):
        with self.assertRaises(scanner.ImageRejected):
            scanner.load_image(b"definitely not an image")

    def test_rejects_formats_outside_allowlist(self):
        for fmt in ("TIFF", "BMP"):
            with self.subTest(fmt=fmt), self.assertRaises(scanner.ImageRejected):
                scanner.load_image(encode(scene(1, (200, 200)), fmt))

    def test_rejects_decompression_bomb_before_decoding(self):
        for w, h in ((60_000, 60_000), (8_000, 7_000)):  # far over, and just over, the 50 MP limit
            with self.subTest(size=(w, h)):
                start = time.perf_counter()
                with self.assertRaises(scanner.ImageRejected):
                    scanner.load_image(png_header_only(w, h))
                self.assertLess(time.perf_counter() - start, 1.0)

    def test_rejects_truncated_file(self):
        data = encode(scene(2), "PNG")
        with self.assertRaises(scanner.ImageRejected):
            scanner.load_image(data[: len(data) // 3])

    def test_rejects_tiny_images(self):
        with self.assertRaises(scanner.ImageRejected):
            scanner.load_image(encode(Image.new("RGB", (16, 16)), "PNG"))

    def test_accepts_common_formats_and_shrinks(self):
        big = scene(3, (3000, 2000))
        for fmt in ("PNG", "JPEG", "WEBP", "GIF"):
            with self.subTest(fmt=fmt):
                img = scanner.load_image(encode(big if fmt != "GIF" else big.convert("P"), fmt))
                self.assertEqual(img.mode, "L")
                self.assertLessEqual(max(img.size), scanner.WORK_SIZE)

    def test_animated_gif_uses_first_frame(self):
        frames = [scene(10).convert("P"), scene(11).convert("P")]
        buf = io.BytesIO()
        frames[0].save(buf, "GIF", save_all=True, append_images=frames[1:], duration=100)
        first = scanner.phash(scanner.load_image(buf.getvalue()))
        self.assertLessEqual(scanner.distance(first, scanner.phash(scanner.load_image(encode(frames[0], "GIF")))), 4)


class Fingerprints(unittest.TestCase):
    def test_survives_resize_and_recompression(self):
        original = scene(4)
        h0 = scanner.phash(scanner.load_image(encode(original)))
        variants = [
            encode(original.resize((450, 300)), "JPEG", quality=70),
            encode(original.resize((1800, 1200)), "WEBP", quality=60),
            encode(original, "JPEG", quality=40),
        ]
        for data in variants:
            self.assertLessEqual(scanner.distance(h0, scanner.phash(scanner.load_image(data))), 16)

    def test_different_images_are_far_apart(self):
        hashes = [scanner.phash(scanner.load_image(encode(scene(s)))) for s in range(20, 30)]
        closest = min(scanner.distance(a, b) for i, a in enumerate(hashes) for b in hashes[i + 1:])
        self.assertGreater(closest, 80)

    def test_center_crop_matches_css_cover(self):
        tall = Image.new("L", (400, 1000))
        wide = Image.new("L", (2000, 500))
        self.assertEqual(scanner.center_crop(tall, 2.0).size, (400, 200))
        self.assertEqual(scanner.center_crop(wide, 2.0).size, (1000, 500))
        self.assertEqual(scanner.center_crop(wide, 4.0).size, (2000, 500))

    def test_crop_reference_matches_full_original(self):
        """A grid tile (center crop, downscaled, recompressed) still matches the full upload."""
        aspect = 273 / 173
        for seed, size in ((40, (1170, 2532)), (41, (1600, 900)), (42, (1000, 1000))):
            with self.subTest(size=size):
                original = scene(seed, size)
                tile = scanner.center_crop(original, aspect).resize((273, 173), Image.Resampling.LANCZOS)
                ref = scanner.phash(scanner.load_image(encode(tile, "WEBP", quality=70)))
                fp = scanner.fingerprint(scanner.load_image(encode(original, "JPEG", quality=85)), [aspect])
                self.assertLessEqual(scanner.distance(fp.crops[aspect], ref), 24)
                self.assertGreater(scanner.distance(fp.full, ref), 48)  # the uncropped image doesn't

    def test_blank_images_are_not_informative(self):
        self.assertFalse(scanner.is_informative(Image.new("L", (500, 500), 40)))
        noisy_blank = Image.effect_noise((500, 500), 3)
        self.assertFalse(scanner.is_informative(noisy_blank))
        self.assertTrue(scanner.is_informative(scanner.load_image(encode(scene(5)))))


class Store(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "data" / "references.json"

    def tearDown(self):
        self.tmp.cleanup()

    def ref(self, seed: int, **kw) -> scanner.Reference:
        return scanner.Reference(hash=scanner.phash(scanner.load_image(encode(scene(seed)))), **kw)

    def test_roundtrip_add_remove(self):
        store = scanner.ReferenceStore(self.path)
        store.load()
        r = self.ref(1, label="one")
        self.assertTrue(store.add(r))
        self.assertFalse(store.add(r))  # duplicate
        self.assertTrue(store.add(self.ref(2, kind="crop", aspect=1.578)))
        again = scanner.ReferenceStore(self.path)
        again.load()
        self.assertEqual([x.id for x in again.refs], [x.id for x in store.refs])
        self.assertEqual(again.aspects(), {1.578})
        self.assertEqual(again.remove(r.id.upper()).label, "one")
        self.assertIsNone(again.remove("doesnotexist"))

    def test_file_is_private_and_written_atomically(self):
        store = scanner.ReferenceStore(self.path)
        store.load()
        store.add(self.ref(3))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["references.json"])  # no temp files left

    def test_rejects_corrupt_or_tampered_files(self):
        self.path.parent.mkdir(parents=True)
        good = {"version": 1, "hash_bits": scanner.HASH_BITS,
                "entries": [{"hash": "ab" * (scanner.HASH_HEX_LEN // 2), "kind": "full"}]}
        bad_variants = [
            "{not json",
            json.dumps({**good, "version": 2}),
            json.dumps({**good, "hash_bits": 64}),
            json.dumps({**good, "entries": [{"hash": "zz" * 32}]}),
            json.dumps({**good, "entries": [{"hash": "ab" * 32, "kind": "crop", "aspect": 50}]}),
            json.dumps({**good, "entries": [{"hash": "ab" * 32, "kind": "evil"}]}),
            json.dumps({**good, "entries": [{"hash": "ab" * 32, "label": 5}]}),
        ]
        for text in bad_variants:
            with self.subTest(text=text[:40]):
                self.path.write_text(text)
                with self.assertRaises(ValueError):
                    scanner.ReferenceStore(self.path).load()
        self.path.write_text(json.dumps(good))
        scanner.ReferenceStore(self.path).load()

    def test_refresh_picks_up_external_changes_and_survives_bad_ones(self):
        bot_view = scanner.ReferenceStore(self.path)
        bot_view.load()
        cli_view = scanner.ReferenceStore(self.path)
        cli_view.load()
        cli_view.add(self.ref(5))
        os.utime(self.path, ns=(time.time_ns(), time.time_ns() + 1_000_000))
        self.assertTrue(bot_view.refresh())
        self.assertEqual(len(bot_view.refs), 1)
        self.assertFalse(bot_view.refresh())  # unchanged
        bot_view.add(self.ref(6))  # must not drop the CLI's entry
        self.assertEqual(len(bot_view.refs), 2)
        self.path.write_text("{broken")
        os.utime(self.path, ns=(time.time_ns(), time.time_ns() + 2_000_000))
        with self.assertRaises(ValueError):
            bot_view.refresh()
        self.assertEqual(len(bot_view.refs), 2)  # previous list kept
        self.assertFalse(bot_view.refresh())  # and it doesn't retry until the file changes

    def test_match_uses_threshold_and_crop_kind(self):
        store = scanner.ReferenceStore(self.path)
        store.load()
        img = scanner.load_image(encode(scene(7)))
        store.add(scanner.Reference(hash=scanner.phash(scanner.center_crop(img, 1.5)), kind="crop", aspect=1.5))
        fp = scanner.fingerprint(img, store.aspects())
        self.assertIsNotNone(store.match(fp, 10))
        self.assertIsNone(store.match(scanner.fingerprint(img, []), 10))  # crop refs need crop hashes

    def test_seed_file_loads_and_is_copied(self):
        store = scanner.ReferenceStore(self.path)
        store.load(seed=ROOT / "seed_references.json")
        self.assertEqual(len(store.refs), 8)
        self.assertTrue(all(r.kind == "full" for r in store.refs))  # hashes of the real spam files
        self.assertTrue(self.path.exists())


if __name__ == "__main__":
    unittest.main()
