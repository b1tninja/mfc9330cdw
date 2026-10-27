#!/usr/bin/env python3
"""Probe whether mono-laser body[29:32] is a hash/CRC of the packed body."""
from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "downloads" / "firmware"
PAIRS = [
    ("LZ3515_F.djf", "MAIN_LZ3515_M.djf"),
    ("LZ3637_E.djf", "MAIN_LZ3637_K.djf"),
    ("LZ3632_E.djf", "MAIN_LZ3632_M.djf"),
]


def find(name: str) -> Path | None:
    for p in ROOT.rglob(name):
        if ".extracted" in p.parts or "binwalk" in p.parts:
            continue
        try:
            p.stat()
            return p
        except OSError:
            continue
    return None


def load(path: Path):
    raw = path.read_bytes()
    p = raw[raw.find(b"DATA=") + 5 :]
    tag = next(o for o in range(0x40) if p[o : o + 4] == b"PROG")
    pk = p.rfind(b"ProgramOK")
    fs = pk
    while fs > 0 and 0x20 <= p[fs - 1] < 0x7F:
        fs -= 1
    body = p[tag + 0x38 : fs]
    stamp = body[29:32]  # 3 bytes after leading 09
    return body, stamp


def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def main() -> None:
    for a, b in PAIRS:
        pa, pb = find(a), find(b)
        if not pa or not pb:
            print("missing", a, b)
            continue
        ba, sa = load(pa)
        bb, sb = load(pb)
        print(f"\n=== {a} stamp={sa.hex()}  ↔  {b} stamp={sb.hex()} ===")
        regions = {
            "body": None,  # placeholder
            "body[0x60:]": None,
            "body[150:]": None,
            "body[:150]": None,
            "body[12:0x60]": None,
        }
        for label, slice_fn in (
            ("body", lambda x: x),
            ("body[0x60:]", lambda x: x[0x60:]),
            ("body[150:]", lambda x: x[150:]),
            ("body[0x60:0x60+64k]", lambda x: x[0x60 : 0x60 + 65536]),
            ("body[-64k:]", lambda x: x[-65536:]),
        ):
            for name, body, stamp in ((a, ba, sa), (b, bb, sb)):
                data = slice_fn(body)
                hits = []
                # 24-bit truncations
                for alg, dig in (
                    ("sha1", hashlib.sha1(data).digest()),
                    ("md5", hashlib.md5(data).digest()),
                    ("sha256", hashlib.sha256(data).digest()),
                ):
                    if dig[:3] == stamp or dig[-3:] == stamp:
                        hits.append(f"{alg}[:/:]3")
                    if dig[1:4] == stamp:
                        hits.append(f"{alg}[1:4]")
                c32 = zlib.crc32(data) & 0xFFFFFFFF
                if c32.to_bytes(4, "big")[1:] == stamp or c32.to_bytes(4, "little")[1:] == stamp:
                    hits.append("crc32 mid")
                if (c32 & 0xFFFFFF).to_bytes(3, "big") == stamp:
                    hits.append("crc32&ffffff be")
                if (c32 & 0xFFFFFF).to_bytes(3, "little") == stamp:
                    hits.append("crc32&ffffff le")
                c16 = crc16_ccitt(data)
                # stamp as 24-bit int
                s24 = int.from_bytes(stamp, "big")
                if (c32 & 0xFFFFFF) == s24:
                    hits.append("crc32==s24")
                if c16 == (s24 & 0xFFFF) or c16 == (s24 >> 8):
                    hits.append("crc16 relate")
                ad = zlib.adler32(data) & 0xFFFFFFFF
                if (ad & 0xFFFFFF) == s24:
                    hits.append("adler==s24")
                if hits:
                    print(f"  HIT {name} over {label}: {hits}")
            # cross: does stamp_a appear in hash of body_b? (shouldn't)
        print("  (done probes; no-HIT means none of the above matched)")


if __name__ == "__main__":
    main()
