#!/usr/bin/env python3
"""List 00 00 00 00 12 34 56 78 chunks inside BH13 Rom1 region."""
from __future__ import annotations

import argparse
import struct
from collections import Counter
from pathlib import Path

try:
    from parse_main_upd import parse_djf_body, parse_upd_text
except ImportError:
    from tools.djf_parse.parse_main_upd import parse_djf_body, parse_upd_text


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    import math

    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("djf", type=Path)
    ap.add_argument("--extract-dir", type=Path)
    args = ap.parse_args()
    body = parse_djf_body(args.djf.read_bytes())
    rom1_off = parse_upd_text(body)["UpdRom1Offset"]["value"]
    rom1 = body[rom1_off:]
    magic = b"\x00\x00\x00\x00\x12\x34\x56\x78"
    print(f"{args.djf.name} rom1@{rom1_off:#x} len={len(rom1):#x}")
    start = 0
    n = 0
    while True:
        i = rom1.find(magic, start)
        if i < 0 or i + 16 > len(rom1):
            break
        typ, sz = struct.unpack_from(">II", rom1, i + 8)
        payload = rom1[i + 16 : i + 16 + sz]
        h = entropy(payload[: min(4096, len(payload))])
        print(f"  @{i:#08x} typ={typ:#x} sz={sz:#x} H4k={h:.2f}")
        if args.extract_dir:
            args.extract_dir.mkdir(parents=True, exist_ok=True)
            (args.extract_dir / f"c_{i:06x}_t{typ:02x}.bin").write_bytes(payload)
        n += 1
        start = i + 8
    print(f"{n} chunks")


if __name__ == "__main__":
    main()
