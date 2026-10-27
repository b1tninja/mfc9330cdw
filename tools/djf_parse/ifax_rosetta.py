#!/usr/bin/env python3
"""Full structural map of the tiny IFAX DJF body (Rosetta for PROG-family codec)."""
from __future__ import annotations

import struct
from collections import Counter
from pathlib import Path

BLOBS = Path(__file__).resolve().parents[2] / "downloads" / "firmware" / "blobs"
OUT = BLOBS / "binwalk" / "carved" / "prefix_dissect"


def body_of(path: Path) -> bytes:
    raw = path.read_bytes()
    # IFAX: entire post-DATA= payload — may lack ProgramOK
    return raw[raw.find(b"DATA=") + 5 :]


def main() -> None:
    raw = (BLOBS / "LZ3196_A.djf").read_bytes()
    print("FULL FILE")
    print(raw.decode("latin-1", errors="replace"))
    print("hex file:", raw.hex())
    print()

    # Parse manually
    i = raw.find(b"DATA=") + 5
    payload = raw[i:]
    print(f"payload len={len(payload):#x}")
    print(f"payload hex={payload.hex()}")

    # Tag at 0x0c for IFAX stub
    print(f"tag@0c={payload[0x0c:0x10]!r}")
    print(f"prefix={payload[:0x0c].hex()}")
    hdr = payload[0x0C : 0x0C + 0x14 + 0x24]
    print(f"tag+hdr2={hdr.hex()}")
    body = payload[0x0C + 0x14 + 0x24 :]
    print(f"body len={len(body):#x} hex={body.hex()}")

    # Section body
    magic = body[:12]
    assert magic == bytes.fromhex("61b654adf6da9da6f565803f")
    mid = body[12:]
    # trail
    if mid.endswith(b"\r\n\x0c"):
        mid, trail = mid[:-3], mid[-3:]
    else:
        trail = b""
    stars = 0
    while stars < len(mid) and mid[-(stars + 1) : len(mid) - stars] == b"*" or (
        stars < len(mid) and mid[-1 - stars] == 0x2A
    ):
        # count trailing 0x2a
        break
    # count trailing asterisks
    stars = 0
    while stars < len(mid) and mid[-1 - stars] == 0x2A:
        stars += 1
    core = mid[:-stars] if stars else mid
    star_bytes = mid[-stars:] if stars else b""

    print()
    print(f"magic:     {magic.hex()}")
    print(f"core:      {core.hex()}  ({len(core)}B)")
    print(f"stars:     {star_bytes.hex()}  ({stars} x 0x2a)")
    print(f"trail:     {trail.hex()}")

    # Split core at first 0x7c that starts a run
    idx = core.find(b"\x7c")
    head = core[:idx]
    rest = core[idx:]
    print(f"\nhead after magic ({len(head)}B): {head.hex()}")
    print(f"rest from 7c ({len(rest)}B): {rest.hex()}")

    # Parse 7-byte frames while lane0 in {7c,7d}
    frames = []
    i = 0
    while i + 7 <= len(rest) and rest[i] in (0x7C, 0x7D):
        frames.append(rest[i : i + 7])
        i += 7
    print(f"\nfamily-A frames: {len(frames)}")
    for n, f in enumerate(frames):
        print(f"  [{n}] {f.hex()}")
    if frames:
        print("  lane deltas:")
        for L in range(7):
            diffs = [
                (frames[n + 1][L] - frames[n][L]) & 0xFF for n in range(len(frames) - 1)
            ]
            print(f"    L{L}: {diffs}  mode={Counter(diffs).most_common(1)}")

    tail = rest[i:]
    print(f"\nafter A-frames ({len(tail)}B): {tail.hex()}")

    # The 0a cX table
    # From earlier: 0ac30ab450ac34ab460ac38ab4...
    # Try 5-byte records starting at first 0a
    j = tail.find(b"\x0a")
    print(f"first 0x0a in tail @{j}")
    if j >= 0:
        pre = tail[:j]
        tab = tail[j:]
        print(f"  pre-table ({len(pre)}B): {pre.hex()}")
        print(f"  table ({len(tab)}B): {tab.hex()}")
        # try stride 5: 0a cx ?? ?? ??
        print("  as 5-byte:")
        for k in range(0, len(tab) - 4, 5):
            rec = tab[k : k + 5]
            print(f"    {rec.hex()}  b0={rec[0]:02x} b1={rec[1]:02x}")
        print("  as 4-byte:")
        for k in range(0, len(tab) - 3, 4):
            rec = tab[k : k + 4]
            print(f"    {rec.hex()}")
        print("  as 9-byte (gap was 9 between 0ac3):")
        for k in range(0, len(tab) - 8, 9):
            rec = tab[k : k + 9]
            print(f"    {rec.hex()}")

    # Compare head to PROG invariant[12:12+len(head)]
    prog = body_of_prog_only()
    print(f"\nPROG[12:12+{len(head)}] = {prog[12:12+len(head)].hex()}")
    print(f"IFAX head            = {head.hex()}")
    x = bytes(a ^ b for a, b in zip(head, prog[12 : 12 + len(head)]))
    print(f"XOR                  = {x.hex()} zeros={x.count(0)}/{len(x)}")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "ifax_body.bin").write_bytes(body)
    (OUT / "ifax_core.bin").write_bytes(core)


def body_of_prog_only() -> bytes:
    raw = (BLOBS / "LZ4266_ZC_1.djf").read_bytes()
    p = raw[raw.find(b"DATA=") + 5 :]
    t = 0x18
    h2 = struct.unpack_from(">I", p, t + 16)[0]
    bo = t + 0x14 + h2
    pk = p.rfind(b"ProgramOK")
    fs = pk
    while fs > 0 and 0x20 <= p[fs - 1] < 0x7F:
        fs -= 1
    return p[bo:fs]


if __name__ == "__main__":
    main()
