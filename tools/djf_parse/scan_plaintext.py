#!/usr/bin/env python3
"""Hunt for plaintext / low-entropy islands inside DJF payloads.

If the update handler lives in one of these images, we may still find
unencrypted string tables, exception paths, or header stubs.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

BLOBS = Path(__file__).resolve().parents[2] / "downloads" / "firmware" / "blobs"

NEEDLES = [
    b"BRDOWNLOAD",
    b"ProgramOK",
    b"PROGRAMLENG",
    b"BRFIRMMEMVER",
    b"BRFIRMWARE",
    b"PROG",
    b"ROM2",
    b"PANL",
    b"Decrypt",
    b"decrypt",
    b"AES",
    b"SHA1",
    b"SHA256",
    b"RSA",
    b"signature",
    b"Signature",
    b"firmware",
    b"Firmware",
    b"UPDATE",
    b"flash",
    b"FLASH",
    b"MEMORYVERSION",
    b"firmverup",
    b"Brother",
    b"MFC-9130",
    b"MFC-9330",
]


def entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    c = Counter(buf)
    n = len(buf)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def payload_of(path: Path) -> bytes:
    raw = path.read_bytes()
    i = raw.find(b"DATA=")
    return raw if i < 0 else raw[i + 5 :]


def find_ascii_runs(data: bytes, min_len: int = 6) -> list[tuple[int, bytes]]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append((m.start(), m.group()))
    return out


def low_entropy_windows(data: bytes, win: int = 4096, step: int = 2048, thresh: float = 6.0):
    hits = []
    for off in range(0, max(1, len(data) - win), step):
        chunk = data[off : off + win]
        e = entropy(chunk)
        if e < thresh:
            hits.append((off, e))
    return hits


def main() -> None:
    for path in sorted(BLOBS.glob("*.djf")):
        data = payload_of(path)
        print("=" * 72)
        print(path.name, "payload", len(data))

        print("-- needle hits --")
        for n in NEEDLES:
            start = 0
            found = 0
            while found < 8:
                i = data.find(n, start)
                if i < 0:
                    break
                ctx = data[max(0, i - 16) : i + len(n) + 32]
                asc = "".join(chr(b) if 32 <= b < 127 else "." for b in ctx)
                print(f"  {n!r:20} @ {i:#010x}  {asc}")
                start = i + 1
                found += 1

        print("-- low-entropy 4KiB windows (H<6.0) --")
        lows = low_entropy_windows(data)
        print(f"  count={len(lows)}")
        for off, e in lows[:20]:
            print(f"  @ {off:#010x} H={e:.3f}")
        if len(lows) > 20:
            print(f"  … {len(lows) - 20} more")

        # Interesting ASCII near start / end already known; sample longest runs in middle
        runs = find_ascii_runs(data, 8)
        # skip footer identity region (last 64 bytes) and prefix
        mid = [(o, s) for o, s in runs if 0x100 < o < len(data) - 64]
        mid.sort(key=lambda t: len(t[1]), reverse=True)
        print("-- longest mid-file ASCII runs --")
        for off, s in mid[:15]:
            print(f"  @ {off:#010x} ({len(s):4d}) {s[:80]!r}{'…' if len(s) > 80 else ''}")


if __name__ == "__main__":
    main()
