#!/usr/bin/env python3
"""Compare PROG body[12:0x60] / invariant prefixes across corpus models."""
from __future__ import annotations

import hashlib
import struct
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEARCH = [
    ROOT / "downloads" / "firmware" / "blobs",
    ROOT / "downloads" / "firmware" / "blobs" / "cdn_older",
    ROOT / "downloads" / "firmware" / "corpus",
]
SKIP_PARTS = {".extracted", "binwalk", "period7_templates"}


def iter_djf() -> list[Path]:
    out, seen = [], set()
    for root in SEARCH:
        if not root.exists():
            continue
        for p in root.rglob("*.djf"):
            if any(part in SKIP_PARTS for part in p.parts):
                continue
            try:
                r = p.resolve()
            except OSError:
                continue
            if r in seen:
                continue
            seen.add(r)
            out.append(p)
    return sorted(out, key=lambda x: x.name.lower())


def load(path: Path):
    raw = path.read_bytes()
    i = raw.find(b"DATA=")
    if i < 0:
        return None
    p = raw[i + 5 :]
    tag = next(
        (off for off in (0x18, 0x0C, 0x10, 0x14, 0x20)
         if p[off : off + 4] in (b"PROG", b"ROM2", b"PANL")),
        None,
    )
    if tag is None:
        for off in range(0, min(0x40, len(p) - 4)):
            if p[off : off + 4] in (b"PROG", b"ROM2", b"PANL"):
                tag = off
                break
    if tag is None:
        return None
    tname = p[tag : tag + 4]
    h2len = struct.unpack_from(">I", p, tag + 16)[0]
    if h2len != 0x24:
        return None
    bo = tag + 0x14 + h2len
    pk = p.rfind(b"ProgramOK")
    if pk < 0:
        pk = p.rfind(b"******")
    fs = pk
    while fs > 0 and 0x20 <= p[fs - 1] < 0x7F:
        fs -= 1
    body = p[bo:fs] if fs > bo else p[bo:]
    nul = p.find(b"\x00")
    ident = p[:nul] if 0 < nul < 32 else b""
    return {
        "file": path.name,
        "tag": tname.decode(),
        "ident": ident.decode("ascii", errors="replace"),
        "magic": body[:12],
        "boot": body[12:0x60] if len(body) >= 0x60 else body[12:],
        "b150": body[:150] if len(body) >= 150 else body,
        "body_len": len(body),
    }


def shared_prefix(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


def main() -> None:
    rows = [r for p in iter_djf() if (r := load(p))]
    print(f"loaded {len(rows)} djf")

    by_magic: dict[str, list] = defaultdict(list)
    for r in rows:
        by_magic[r["magic"].hex()].append(r)

    print("\n## magic families / PROG boot[12:0x60] clusters")
    for mag, items in sorted(by_magic.items(), key=lambda x: -len(x[1])):
        progs = [x for x in items if x["tag"] == "PROG" and len(x["boot"]) >= 84]
        print(f"\nmagic {mag[:24]}…  n={len(items)} prog={len(progs)}")
        if not progs:
            continue
        # cluster by sha1 of boot
        clusters: dict[str, list] = defaultdict(list)
        for x in progs:
            clusters[hashlib.sha1(x["boot"]).hexdigest()[:12]].append(x)
        print(f"  distinct boot[12:0x60] digests: {len(clusters)}")
        for dig, xs in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
            ids = sorted({x["ident"] for x in xs})
            files = sorted({x["file"] for x in xs})[:6]
            print(
                f"  {dig} ×{len(xs)} id={ids} "
                f"files={files}{'…' if len({x['file'] for x in xs}) > 6 else ''}"
            )
            print(f"    boot[:16]={xs[0]['boot'][:16].hex()}")

    # pairwise shared prefix among distinct PROG bodies (same magic)
    print("\n## PROG pairwise shared body prefix (same magic, distinct digests)")
    for mag, items in sorted(by_magic.items(), key=lambda x: -len(x[1])):
        progs = [x for x in items if x["tag"] == "PROG" and x["body_len"] > 1000]
        # unique by boot digest
        uniq = {}
        for x in progs:
            uniq[hashlib.sha1(x["b150"]).hexdigest()] = x
        xs = list(uniq.values())
        if len(xs) < 2:
            continue
        print(f"\nmagic {mag[:16]}… representatives={len(xs)}")
        for i in range(len(xs)):
            for j in range(i + 1, len(xs)):
                sp = shared_prefix(xs[i]["b150"], xs[j]["b150"])
                print(
                    f"  {xs[i]['file'][:22]:22s} ↔ {xs[j]['file'][:22]:22s} "
                    f"share {sp}B  ({xs[i]['ident'][:12]} / {xs[j]['ident'][:12]})"
                )


if __name__ == "__main__":
    main()
