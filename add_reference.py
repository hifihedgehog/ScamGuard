"""Add scam images to ScamGuard's fingerprint file from the command line.

Whole images (best: the actual files the spammers posted):
    python add_reference.py scam1.png scam2.jpg --label "MrBeast casino scam"

Tiles cut from a screenshot of Discord's multi-image grid (x0,y0,x1,y1 in pixels,
one --box per tile, edges exactly on the tile so no background is included):
    python add_reference.py screenshot.png --box 13,28,286,201 --box 290,28,563,201

A running bot picks up the change automatically. The easiest way to add images
is still in Discord: right-click the message > Apps > Add scam image.
"""
from __future__ import annotations

import argparse
import io
import os
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image

import scanner

HERE = Path(__file__).resolve().parent
SEED = HERE / "seed_references.json"


def parse_box(text: str) -> tuple[int, int, int, int]:
    try:
        x0, y0, x1, y1 = (int(v) for v in text.split(","))
    except ValueError:
        raise argparse.ArgumentTypeError("a box is four pixel numbers: x0,y0,x1,y1") from None
    if x1 - x0 < scanner.MIN_SIDE or y1 - y0 < scanner.MIN_SIDE:
        raise argparse.ArgumentTypeError(f"box {text} is too small (min {scanner.MIN_SIDE}px per side)")
    return x0, y0, x1, y1


def crop_bytes(path: Path, box: tuple[int, int, int, int]) -> bytes:
    with Image.open(path, formats=scanner.ALLOWED_FORMATS) as im:
        if not (0 <= box[0] < box[2] <= im.width and 0 <= box[1] < box[3] <= im.height):
            raise SystemExit(f"box {box} is outside the {im.width}x{im.height} image")
        out = io.BytesIO()
        im.convert("RGB").crop(box).save(out, "PNG")
        return out.getvalue()


def main(argv: list[str] | None = None) -> None:
    default_store = Path(os.getenv("DATA_DIR") or HERE / "data") / "references.json"
    ap = argparse.ArgumentParser(description="Add scam images to ScamGuard's fingerprint file.")
    ap.add_argument("images", nargs="+", type=Path, help="image file(s): PNG, JPEG, WEBP or GIF")
    ap.add_argument("--box", action="append", type=parse_box, default=[],
                    help="tile x0,y0,x1,y1 from a screenshot of Discord's image grid (repeatable)")
    ap.add_argument("--label", default="", help="description shown in logs and /scamguard list")
    ap.add_argument("--store", type=Path, default=default_store, help=f"fingerprint file (default {default_store})")
    args = ap.parse_args(argv)
    if args.box and len(args.images) != 1:
        ap.error("--box works with exactly one screenshot")

    store = scanner.ReferenceStore(args.store)
    store.load(seed=None if args.store.resolve() == SEED.resolve() else SEED)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    jobs: list[tuple[str, bytes, float | None]] = []
    if args.box:
        for n, box in enumerate(args.box, 1):
            aspect = round((box[2] - box[0]) / (box[3] - box[1]), 4)
            jobs.append((f"tile {n}", crop_bytes(args.images[0], box), aspect))
    else:
        jobs = [(path.name, path.read_bytes(), None) for path in args.images]

    for name, data, aspect in jobs:
        try:
            img = scanner.load_image(data)
        except scanner.ImageRejected as exc:
            print(f"skip   {name}: {exc}")
            continue
        if not scanner.is_informative(img):
            print(f"skip   {name}: near-blank image, too little detail to fingerprint safely")
            continue
        ref = scanner.Reference(
            hash=scanner.phash(img),
            kind="crop" if aspect else "full",
            aspect=aspect,
            label=f"{args.label} ({name})" if args.label else name,
            added_by="add_reference.py",
            added_at=stamp,
        )
        status = "added " if store.add(ref) else "exists"
        print(f"{status} {ref.id}  {ref.kind:4}  {ref.label}")
    print(f"{len(store.refs)} fingerprint(s) in {store.path}")


if __name__ == "__main__":
    main()
