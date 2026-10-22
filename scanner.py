"""Image fingerprinting, matching and the reference store.

No Discord code lives here, so this module can be unit-tested and used by
add_reference.py without a bot token.

How matching works
------------------
Every image is reduced to a 256-bit perceptual hash (pHash): a fingerprint of
its overall light/dark structure. Re-encoding, resizing and mild color or
brightness changes barely move it, so the Hamming distance between the hashes
of two copies of the same picture stays small while unrelated pictures land
far apart.

References come in two kinds:
  * "full": the hash of a whole image (added from a real spam attachment).
  * "crop": the hash of a center crop at a known aspect ratio. Discord's
    multi-image preview grid shows every attachment center-cropped to the same
    tile shape, so a screenshot of a spam message only contains crops. For
    these references the bot center-crops each incoming image to the same
    shape before hashing, which reproduces what the tile showed.

Prefer "full" references. On 2026-10-22, four crop references cut from a
screenshot of the MrBeast casino post missed all 84 real copies of that post
(closest distance 106), while full hashes of the real files matched every copy
within 14.
"""
from __future__ import annotations

import io
import json
import math
import os
import re
import statistics
import tempfile
from dataclasses import dataclass
from operator import mul
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageStat

# --------------------------------------------------------------- decoding
ALLOWED_FORMATS = ("PNG", "JPEG", "WEBP", "GIF")  # everything else is refused
MAX_PIXELS = 50_000_000  # refuse anything above ~50 megapixels before decoding
MIN_SIDE = 32
WORK_SIZE = 1024  # working copies are shrunk to fit inside 1024x1024

Image.MAX_IMAGE_PIXELS = MAX_PIXELS  # Pillow's own decompression-bomb guard


class ImageRejected(ValueError):
    """Raised for anything that is not a sane, decodable image."""


def load_image(data: bytes) -> Image.Image:
    """Decode untrusted bytes into a small grayscale working copy.

    Only PNG/JPEG/WEBP/GIF decoders are reachable (no TIFF, PSD, EPS...),
    dimensions are checked before any pixel data is decoded, and only the
    first frame of an animation is used.
    """
    try:
        with Image.open(io.BytesIO(data), formats=ALLOWED_FORMATS) as im:
            w, h = im.size
            if min(w, h) < MIN_SIDE or w * h > MAX_PIXELS:
                raise ImageRejected(f"refusing {w}x{h} image")
            im.draft("L", (WORK_SIZE, WORK_SIZE))  # JPEG: decode at reduced scale
            gray = im.convert("L")
    except ImageRejected:
        raise
    except Exception as exc:  # malformed input can raise almost anything
        raise ImageRejected(f"undecodable image ({type(exc).__name__})") from None
    gray.thumbnail((WORK_SIZE, WORK_SIZE), Image.Resampling.LANCZOS)
    return gray


# ---------------------------------------------------------------- hashing
HASH_SIDE = 16  # 16x16 low-frequency DCT block -> 256-bit hash
HASH_BITS = HASH_SIDE * HASH_SIDE
HASH_HEX_LEN = HASH_BITS // 4
_SAMPLE = HASH_SIDE * 4  # pHash samples the image at 4x the hash side

# The 16 lowest-frequency rows of the 64-point DCT-II basis: all pHash needs,
# which keeps it fast enough in plain Python (no NumPy dependency).
_BASIS = [[math.cos(math.pi * k * (2 * i + 1) / (2 * _SAMPLE)) for i in range(_SAMPLE)]
          for k in range(HASH_SIDE)]


def phash(img: Image.Image) -> int:
    """DCT perceptual hash. Produces the same bits as imagehash.phash(img, 16)."""
    px = img.convert("L").resize((_SAMPLE, _SAMPLE), Image.Resampling.LANCZOS).tobytes()
    cols = [px[c::_SAMPLE] for c in range(_SAMPLE)]
    rows_dct = [[sum(map(mul, basis, col)) for col in cols] for basis in _BASIS]  # DCT down columns
    low = [sum(map(mul, row, basis)) for row in rows_dct for basis in _BASIS]   # then along rows
    median = statistics.median(low)
    bits = 0
    for value in low:
        bits = (bits << 1) | (value > median)
    return bits


def distance(a: int, b: int) -> int:
    """Number of differing bits (0 = identical, ~128 = unrelated)."""
    return (a ^ b).bit_count()


MIN_CONTRAST = 6.0


def is_informative(img: Image.Image) -> bool:
    """False for (near-)blank images: their fingerprint is mostly noise, so they
    must never become references."""
    return ImageStat.Stat(img.convert("L").resize((64, 64))).stddev[0] >= MIN_CONTRAST


def hash_to_hex(h: int) -> str:
    return format(h, f"0{HASH_HEX_LEN}x")


def center_crop(img: Image.Image, aspect: float) -> Image.Image:
    """Largest centered crop with the given width/height ratio (CSS object-fit: cover)."""
    w, h = img.size
    if w / h > aspect:
        new_w = max(1, round(h * aspect))
        x0 = (w - new_w) // 2
        return img.crop((x0, 0, x0 + new_w, h))
    new_h = max(1, round(w / aspect))
    y0 = (h - new_h) // 2
    return img.crop((0, y0, w, y0 + new_h))


@dataclass
class Fingerprint:
    full: int
    crops: dict[float, int]  # aspect ratio -> hash of the center crop at that ratio


def fingerprint(img: Image.Image, aspects: Iterable[float] = ()) -> Fingerprint:
    return Fingerprint(
        full=phash(img),
        crops={a: phash(center_crop(img, a)) for a in aspects},
    )


# ------------------------------------------------------------ references
KINDS = ("full", "crop")
_HEX_RE = re.compile(rf"^[0-9a-f]{{{HASH_HEX_LEN}}}$")
MAX_LABEL = 200


@dataclass
class Reference:
    hash: int
    kind: str = "full"
    aspect: float | None = None
    label: str = ""
    added_by: str = ""
    added_at: str = ""

    @property
    def id(self) -> str:
        """Short id used by the remove command (first 10 hex digits)."""
        return hash_to_hex(self.hash)[:10]

    def to_json(self) -> dict:
        return {
            "hash": hash_to_hex(self.hash),
            "kind": self.kind,
            "aspect": self.aspect,
            "label": self.label,
            "added_by": self.added_by,
            "added_at": self.added_at,
        }

    @classmethod
    def from_json(cls, d: dict) -> "Reference":
        if not isinstance(d, dict):
            raise ValueError("entry is not an object")
        hx = d.get("hash")
        if not isinstance(hx, str) or not _HEX_RE.match(hx):
            raise ValueError(f"bad hash {hx!r}")
        kind = d.get("kind", "full")
        if kind not in KINDS:
            raise ValueError(f"bad kind {kind!r}")
        aspect = d.get("aspect")
        if kind == "crop":
            if not isinstance(aspect, (int, float)) or not 0.1 <= aspect <= 10:
                raise ValueError(f"bad aspect {aspect!r}")
            aspect = round(float(aspect), 4)
        else:
            aspect = None
        text = {k: d.get(k, "") for k in ("label", "added_by", "added_at")}
        if not all(isinstance(v, str) for v in text.values()):
            raise ValueError("label/added_by/added_at must be strings")
        return cls(
            hash=int(hx, 16),
            kind=kind,
            aspect=aspect,
            label=text["label"][:MAX_LABEL],
            added_by=text["added_by"][:100],
            added_at=text["added_at"][:40],
        )


class ReferenceStore:
    """Known scam-image hashes, persisted as JSON with atomic writes."""

    MAX_ENTRIES = 2000

    def __init__(self, path: Path):
        self.path = Path(path)
        self.refs: list[Reference] = []
        self._mtime: int | None = None

    # -- persistence
    def load(self, seed: Path | None = None) -> None:
        """Load the store. If it doesn't exist yet, start from the seed file.

        A corrupt or tampered file raises instead of being silently ignored.
        """
        src = self.path if self.path.exists() else seed
        if src is None or not Path(src).exists():
            self.refs = []
            return
        mtime = Path(src).stat().st_mtime_ns  # stat before reading: a later edit is never missed
        raw = json.loads(Path(src).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise ValueError(f"{src}: unsupported format")
        if raw.get("hash_bits") != HASH_BITS:
            raise ValueError(f"{src}: made for {raw.get('hash_bits')}-bit hashes, need {HASH_BITS}")
        entries = raw.get("entries")
        if not isinstance(entries, list) or len(entries) > self.MAX_ENTRIES:
            raise ValueError(f"{src}: bad entry list")
        refs: list[Reference] = []
        for i, e in enumerate(entries):
            try:
                refs.append(Reference.from_json(e))
            except ValueError as exc:
                raise ValueError(f"{src}: entry {i}: {exc}") from None
        self.refs = refs
        if Path(src) != self.path:
            self.save()  # copy the seed into the writable store
        else:
            self._mtime = mtime

    def refresh(self) -> bool:
        """Reload if the file changed on disk (e.g. edited by add_reference.py).

        Returns True if it reloaded. If the new file is invalid this raises and
        keeps the previous list; it won't retry until the file changes again.
        """
        try:
            mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            return False
        if mtime == self._mtime:
            return False
        self._mtime = mtime
        self.load()
        return True

    def save(self) -> None:
        data = {
            "version": 1,
            "hash_bits": HASH_BITS,
            "entries": [r.to_json() for r in self.refs],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".refs-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:  # mkstemp creates it 0600
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)  # atomic: readers never see a half-written file
            self._mtime = self.path.stat().st_mtime_ns
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise

    # -- queries
    def aspects(self) -> set[float]:
        return {r.aspect for r in self.refs if r.kind == "crop" and r.aspect}

    def nearest(self, fp: Fingerprint) -> tuple[Reference, int] | None:
        best: tuple[Reference, int] | None = None
        for ref in self.refs:
            h = fp.full if ref.kind == "full" else fp.crops.get(ref.aspect)
            if h is None:
                continue
            d = distance(h, ref.hash)
            if best is None or d < best[1]:
                best = (ref, d)
        return best

    def match(self, fp: Fingerprint, threshold: int) -> tuple[Reference, int] | None:
        best = self.nearest(fp)
        return best if best is not None and best[1] <= threshold else None

    # -- changes
    def add(self, ref: Reference) -> bool:
        """Add and persist a reference. Returns False if it is already stored."""
        self.refresh()  # don't overwrite changes another process just made
        if any(r.id == ref.id for r in self.refs):
            return False
        if len(self.refs) >= self.MAX_ENTRIES:
            raise ValueError("reference store is full")
        self.refs.append(ref)
        self.save()
        return True

    def remove(self, ref_id: str) -> Reference | None:
        self.refresh()
        ref_id = ref_id.strip().lower()
        for i, r in enumerate(self.refs):
            if r.id == ref_id:
                del self.refs[i]
                self.save()
                return r
        return None
