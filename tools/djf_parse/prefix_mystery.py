#!/usr/bin/env python3
"""Align DJF prefix mystery-6 / memver across corpus."""
from __future__ import annotations

import struct
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "downloads" / "firmware"
SKIP = {".extracted", "binwalk", "period7_templates"}


def main() -> None:
    rows = []
    for p in ROOT.rglob("*.djf"):
        if any(s in p.parts for s in SKIP):
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        i = raw.find(b"DATA=")
        if i < 0:
            continue
        pay = raw[i + 5 :]
        tag = next(
            (o for o in range(0x40) if pay[o : o + 4] in (b"PROG", b"ROM2", b"PANL")),
            None,
        )
        if tag is None:
            continue
        nul = pay.find(b"\x00")
        ident = pay[:nul]
        # typical: ident + NUL pad to 12, memver at 0x0c, mystery at 0x10, 0001 at 0x16
        prefix = pay[:tag]
        rows.append(
            {
                "file": p.name,
                "tag": pay[tag : tag + 4].decode(),
                "ident": ident.decode("ascii", "replace"),
                "tag_off": tag,
                "prefix": prefix,
                "memver": pay[0x0C:0x10] if tag >= 0x18 else b"",
                "mystery6": pay[0x10:0x16] if tag >= 0x18 else pay[nul + 1 : tag][:6],
            }
        )

    print(f"loaded {len(rows)}")
    print(f"\n{'file':24s} {'tag':4s} {'ident':14s} memver mystery6 tag_off")
    # unique by mystery6+ident+tag
    seen = set()
    for r in sorted(rows, key=lambda x: (x["ident"], x["tag"], x["file"])):
        key = (r["ident"], r["tag"], r["mystery6"], r["memver"])
        if key in seen:
            continue
        seen.add(key)
        print(
            f"{r['file'][:24]:24s} {r['tag']:4s} {r['ident'][:14]:14s} "
            f"{r['memver'].hex():8s} {r['mystery6'].hex():12s} @{r['tag_off']}"
        )

    # letter-rev: same ident+tag, compare mystery
    print("\nletter-rev mystery deltas (same ident+tag):")
    by = defaultdict(list)
    for r in rows:
        by[(r["ident"], r["tag"])].append(r)
    for key, xs in sorted(by.items()):
        uniq = {x["mystery6"].hex(): x for x in xs}
        if len(uniq) < 2:
            continue
        print(f"  {key[0]} {key[1]}:")
        for h, x in uniq.items():
            print(f"    {h}  memver={x['memver'].hex()}  e.g. {x['file']}")


if __name__ == "__main__":
    main()
