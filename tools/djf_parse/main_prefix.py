#!/usr/bin/env python3
"""Dissect MAIN-era letter-invariant body prefixes and align to PROG bootstrap."""
from __future__ import annotations

import math
import struct
from collections import Counter
from pathlib import Path

from main_vs_prog import parse, OLDER, ROOT


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def shared_prefix(*bufs: bytes) -> int:
    n = min(map(len, bufs))
    i = 0
    while i < n and all(b[i] == bufs[0][i] for b in bufs):
        i += 1
    return i


def dump(label: str, data: bytes) -> None:
    print(f"\n{label} ({len(data)}B) H={entropy(data):.3f}")
    for off in range(0, len(data), 16):
        print(f"  {off:04x}: {data[off:off+16].hex()}")
    print("  BE u32:")
    for off in range(0, len(data) // 4 * 4, 4):
        print(f"    +{off:02x}: {struct.unpack_from('>I', data, off)[0]:#010x}")


def main() -> None:
    main_b = parse(OLDER / "LZ2350_B.djf")
    main_l = parse(OLDER / "LZ2350_L.djf")
    sp = shared_prefix(main_b["body"], main_l["body"])
    pref = main_b["body"][:sp]
    dump("MAIN LZ2350 B<->L invariant", pref)

    # bytewise diff after shared
    a, b = main_b["body"], main_l["body"]
    print(f"\nFirst 32 diffs after +{sp}:")
    n = 0
    for i in range(sp, min(len(a), len(b), sp + 512)):
        if a[i] != b[i]:
            print(f"  +{i:#x}: {a[i]:02x}→{b[i]:02x} Δ={(b[i]-a[i])&0xff:#x}")
            n += 1
            if n >= 24:
                break

    # Cross-model MAIN heads
    mains = []
    for p in sorted(OLDER.glob("LZ23*.djf")):
        r = parse(p)
        if r["tag"] == "MAIN":
            mains.append(r)
    cross = shared_prefix(*(r["body"] for r in mains))
    print(f"\nCross-model MAIN common: {cross}B = {mains[0]['body'][:cross].hex()}")

    # Field hypotheses after 20B magic
    print("\n=== post-magic field survey (body[20:102] across MAIN models) ===")
    rows = []
    for r in mains:
        rows.append((r["file"], r["ident"], r["body"][20:102], r["hdr2"][8:12].hex()))
    # which offsets are constant across models?
    bufs = [row[2] for row in rows]
    const = []
    for i in range(len(bufs[0])):
        if all(b[i] == bufs[0][i] for b in bufs):
            const.append(i)
    print(f"  constant offs in [20:102] across {len(rows)} models: {const[:40]}{'…' if len(const)>40 else ''} ({len(const)} total)")
    # per-model dump of [20:40]
    for file, ident, chunk, fam in rows:
        print(f"  {file:14s} fam={fam} id={ident:14s} [20:52]={chunk[:32].hex()}")

    # Align a85cacf5 / a953 slots vs early PROG
    prog = parse(OLDER / "LZ2573_B.djf")
    prog2 = parse(OLDER / "LZ2362_A.djf") if (OLDER / "LZ2362_A.djf").exists() else None
    print("\n=== constant slot alignment ===")
    for label, body in [
        ("MAIN2350", main_b["body"]),
        ("PROG2573", prog["body"]),
        ("PROG2362", prog2["body"] if prog2 else b""),
    ]:
        if not body:
            continue
        for name, needle in [
            ("a85cacf5", bytes.fromhex("a85cacf5")),
            ("a953", bytes.fromhex("a953")),
            ("f81983f7", bytes.fromhex("f81983f7")),
            ("ed??01", None),
        ]:
            if needle is None:
                for off in range(12, 40):
                    if body[off] == 0xED and body[off + 2] == 0x01:
                        print(f"  {label:10s} ed??01 @+{off}: {body[off:off+8].hex()}")
                continue
            j = body.find(needle, 0, 128)
            print(f"  {label:10s} {name:10s} @{j if j>=0 else '—'}")

    # Overlay: place MAIN magic and PROG magic on same diagram via a85cacf5 anchor
    print("\n=== a85cacf5-anchored overlay ===")
    for label, body in [("MAIN2350", main_b["body"]), ("PROG2573", prog["body"]), ("PROG2362", prog2["body"] if prog2 else b"")]:
        if not body:
            continue
        j = body.find(bytes.fromhex("a85cacf5"))
        if j < 0:
            print(f"  {label}: no a85cacf5 in head")
            continue
        lo, hi = max(0, j - 16), j + 20
        print(f"  {label} anchor@{j}:")
        print(f"    [{lo}:{hi}] {body[lo:hi].hex()}")
        # mark relative
        rel = body[j - 8 : j + 12] if j >= 8 else body[: j + 12]
        print(f"    -8..+12: {rel.hex()}")

    # Does MAIN [20:] resemble PROG [12:] under XOR with a constant?
    mb, pb = main_b["body"], prog["body"]
    print("\n=== MAIN[0:64] ⊕ PROG[0:64] / shifted ===")
    for shift in range(0, 20):
        x = bytes(a ^ b for a, b in zip(mb[shift : shift + 48], pb[:48]))
        zeros = sum(1 for c in x if c == 0)
        # low Hamming weight?
        hw = sum(bin(c).count("1") for c in x)
        if zeros >= 4 or hw < 48 * 2:
            print(f"  MAIN[{shift}:]⊕PROG[0:48] zeros={zeros} hw={hw} {x.hex()}")
    # try aligning both a85cacf5 then XOR flanks
    jm = mb.find(bytes.fromhex("a85cacf5"))
    jp = pb.find(bytes.fromhex("a85cacf5"))
    print(f"\n  anchors MAIN@{jm} PROG@{jp}")
    for back in (8, 12, 16):
        x = bytes(a ^ b for a, b in zip(mb[jm - back : jm + 16], pb[jp - back : jp + 16]))
        print(f"  flank-{back} XOR: {x.hex()} zeros={sum(1 for c in x if c==0)}")

    # Transition pair hdr2 / prefix
    if prog2:
        print("\n=== transition LZ2350_B (MAIN) vs LZ2362_A (PROG) ===")
        for label, r in [("MAIN2350", main_b), ("PROG2362", prog2)]:
            print(
                f"  {label}: tag={r['tag']}@{r['tag_off']:#x} id={r['ident']!r} "
                f"size_a={r['size_a']:#x} flags={r['flags']:#x}"
            )
            print(f"    prefix: {r['prefix'].hex()}")
            print(f"    hdr2:   {r['hdr2'].hex()}")
            print(f"    magic:  {r['body'][:24].hex()}")


if __name__ == "__main__":
    main()
