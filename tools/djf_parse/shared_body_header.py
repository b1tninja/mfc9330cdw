#!/usr/bin/env python3
"""Dissect shared body-header bytes across DJF letter revisions."""
from __future__ import annotations

import struct
from pathlib import Path

BLOBS = Path(__file__).resolve().parents[2] / "downloads" / "firmware" / "blobs"
OLDER = BLOBS / "cdn_older"


def body_of(path: Path) -> tuple[bytes, bytes]:
    raw = path.read_bytes()
    p = raw[raw.find(b"DATA=") + 5 :]
    for off in (0x18, 0x0C):
        if p[off : off + 4] in (b"PROG", b"ROM2", b"PANL"):
            t = off
            break
    else:
        raise ValueError(path)
    h2 = struct.unpack_from(">I", p, t + 16)[0]
    if not 0 < h2 <= 0x100:
        h2 = 0x24
    bo = t + 0x14 + h2
    pk = p.rfind(b"ProgramOK")
    fs = pk
    while fs > 0 and 0x20 <= p[fs - 1] < 0x7F:
        fs -= 1
    return p[bo : fs if pk >= 0 else None], p[t : t + 4]


def dump_hex(data: bytes, n: int | None = None) -> None:
    data = data if n is None else data[:n]
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        print(f"  {off:04x}: {chunk.hex()}")


def leading_eq(*bufs: bytes) -> int:
    n = min(map(len, bufs))
    i = 0
    while i < n and all(b[i] == bufs[0][i] for b in bufs):
        i += 1
    return i


def main() -> None:
    prog = {}
    for name in ("LZ4266_S.djf", "LZ4266_T.djf", "LZ4266_ZC_1.djf"):
        path = OLDER / name if (OLDER / name).exists() else BLOBS / name
        b, tag = body_of(path)
        prog[name] = b
        print(f"{name}: tag={tag!r} body={len(b):#x}")

    s, t, z = prog["LZ4266_S.djf"], prog["LZ4266_T.djf"], prog["LZ4266_ZC_1.djf"]
    n = leading_eq(s, t, z)
    print(f"\nPROG S/T/ZC identical prefix: {n} bytes ({n:#x})")
    dump_hex(s, n)
    print("BE u32:")
    for off in range(0, n // 4 * 4, 4):
        print(f"  +{off:02x}: {struct.unpack_from('>I', s, off)[0]:#010x}")
    print("LE u32 (first 64):")
    for off in range(0, min(64, n) // 4 * 4, 4):
        print(f"  +{off:02x}: {struct.unpack_from('<I', s, off)[0]:#010x}")

    # S vs T beyond
    st = leading_eq(s, t)
    print(f"\nS==T leading: {st}")
    runs = []
    i = n
    while i < min(len(s), len(t), 0x2000):
        if s[i] == t[i]:
            j = i
            while j < min(len(s), len(t), 0x2000) and s[j] == t[j]:
                j += 1
            if j - i >= 8:
                runs.append((i, j - i))
            i = j
        else:
            i += 1
    print(f"S==T runs >=8 after shared, first 8K: {runs[:20]}")

    ph, _ = body_of(OLDER / "LZ4279_H.djf")
    pr, _ = body_of(BLOBS / "LZ4279_R.djf")
    pn = leading_eq(ph, pr)
    print(f"\nPANL H/R identical prefix: {pn} bytes ({pn:#x})")
    dump_hex(ph, min(pn, 256))
    print(f"PANL[:12]==PROG[:12]? {ph[:12] == s[:12]}")
    print(f"PANL vs PROG-S leading equal: {leading_eq(ph, s)}")

    # annotate known pad magic inside shared regions?
    for label, blob in ("PROG-S", s[:n]), ("PANL-H", ph[:pn]):
        for magic in (b"\x5e\x95", b"\x7c", b"\xf8\xed"):
            print(f"  {label} find {magic.hex()}: {blob.find(magic)}")

    ifax, _ = body_of(BLOBS / "LZ3196_A.djf")
    print(f"\nIFAX len={len(ifax):#x} vs PROG-S leading={leading_eq(ifax, s)}")
    print(f"IFAX vs ZC leading={leading_eq(ifax, z)}")
    dump_hex(ifax)
    # family-A like bytes density
    print(
        f"IFAX 7c/7d ratio={(ifax.count(0x7C) + ifax.count(0x7D)) / len(ifax):.3f}"
    )

    # Compare hdr2[2] across PROG letters (constant 0xa4020000?)
    print("\n--- hdr2[2] / body[12:20] across samples ---")
    for name, path in [
        ("S", OLDER / "LZ4266_S.djf"),
        ("T", OLDER / "LZ4266_T.djf"),
        ("ZC", BLOBS / "LZ4266_ZC_1.djf"),
        ("PANL-H", OLDER / "LZ4279_H.djf"),
        ("PANL-R", BLOBS / "LZ4279_R.djf"),
        ("IFAX", BLOBS / "LZ3196_A.djf"),
    ]:
        raw = path.read_bytes()
        p = raw[raw.find(b"DATA=") + 5 :]
        for off in (0x18, 0x0C):
            if p[off : off + 4] in (b"PROG", b"ROM2", b"PANL"):
                t_off = off
                break
        h2 = p[t_off + 0x14 : t_off + 0x14 + 0x24]
        b, _ = body_of(path)
        print(
            f"  {name:7} hdr2[2]={struct.unpack_from('>I', h2, 8)[0]:#010x}  "
            f"body+12={b[12:28].hex()}"
        )


if __name__ == "__main__":
    main()
