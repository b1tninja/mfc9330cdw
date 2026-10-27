#!/usr/bin/env python3
"""Interpret hdr2[1]/hdr2[6] as load/map addresses vs sizes.

MAIN-era packages store a clear address pair:
  hdr2[1] = primary end (or high-water) address
  hdr2[6] = hdr2[1] + 0x10000|0x20000   (sidecar region)

PROG-era reuses hdr2[6] as family magic (*ffe5) but keeps hdr2[1] as a
size-ish value that often sits just under a 16 MiB boundary (~0x00f0xxxx)
for MAIN/PROG images — plausible unpacked flash footprint / load end.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "djf_parse"))
from main_vs_prog import parse, OLDER  # noqa: E402

BLOBS = ROOT / "downloads" / "firmware" / "blobs"


def u32s(h: bytes) -> list[int]:
    return [struct.unpack_from(">I", h, i * 4)[0] for i in range(len(h) // 4)]


def classify(h1: int) -> str:
    notes = []
    if 0x00E00000 <= h1 < 0x01000000:
        notes.append("~16MiB-top")
    if 0x01000000 <= h1 < 0x04000000:
        notes.append("gt16MiB/dram?")
    if h1 < 0x00400000:
        notes.append("lt4MiB")
    return ",".join(notes) or "?"


def main() -> None:
    files = sorted(OLDER.glob("*.djf")) + sorted(BLOBS.glob("LZ426*.djf")) + sorted(
        BLOBS.glob("LZ427*.djf")
    )
    print(
        f"{'file':18s} {'tag':4s} {'h1':>10s} {'h6':>10s} {'h6-h1':>8s} "
        f"{'body':>9s} {'h1/body':>7s} note"
    )
    seen = set()
    for path in files:
        if path.resolve() in seen:
            continue
        seen.add(path.resolve())
        try:
            r = parse(path)
        except Exception as e:
            print(path.name, e)
            continue
        h = u32s(r["hdr2"])
        h1, h6 = h[1], h[6]
        delta = h6 - h1
        ratio = h1 / len(r["body"]) if r["body"] else 0
        pair = f"{delta:#x}" if 0 < delta <= 0x40000 else "n/a"
        print(
            f"{r['file'][:18]:18s} {r['tag']:4s} {h1:#010x} {h6:#010x} {pair:>8s} "
            f"{len(r['body']):9d} {ratio:6.2f}x {classify(h1)}"
        )


if __name__ == "__main__":
    main()
