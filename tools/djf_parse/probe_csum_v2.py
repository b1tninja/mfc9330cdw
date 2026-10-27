#!/usr/bin/env python3
"""Broader footer u16 search: Fletcher, more CRC polys, hdr2 mixes, size fields.

Only small/medium regions — full-body CRC16 still deferred.
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BLOBS = ROOT / "downloads" / "firmware" / "blobs"


def be16(b: bytes, o: int = 0) -> int:
    return struct.unpack_from(">H", b, o)[0]


def be32(b: bytes, o: int = 0) -> int:
    return struct.unpack_from(">I", b, o)[0]


def crc16(data: bytes, init: int, poly: int, refin: bool = False, refout: bool = False) -> int:
    crc = init
    for byte in data:
        if refin:
            byte = int(f"{byte:08b}"[::-1], 2)
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    if refout:
        crc = int(f"{crc:016b}"[::-1], 2)
    return crc & 0xFFFF


def fletcher16(data: bytes) -> int:
    s1 = s2 = 0
    for b in data:
        s1 = (s1 + b) % 255
        s2 = (s2 + s1) % 255
    return (s2 << 8) | s1


def parse(path: Path) -> dict:
    raw = path.read_bytes()
    p = raw[raw.find(b"DATA=") + 5 :]
    tag = next(o for o in (0x18, 0x0C, 0x24) if p[o : o + 4] in (b"PROG", b"ROM2", b"PANL", b"MAIN"))
    pok = p.rfind(b"ProgramOK")
    fs = pok
    while fs > 0 and 0x20 <= p[fs - 1] < 0x7F:
        fs -= 1
    ident = p[fs:pok]
    bcd = p[pok + 9 : pok + 14]
    csum = be16(p, pok + 14)
    nul = p[pok + 16 : pok + 17]
    hdr2_len = be32(p, tag + 16)
    hdr2 = p[tag + 0x14 : tag + 0x14 + hdr2_len]
    body = p[tag + 0x14 + hdr2_len : fs]
    size_a = be32(p, tag + 8)
    return {
        "file": path.name,
        "tag": p[tag : tag + 4].decode(),
        "ident": ident,
        "bcd": bcd,
        "csum": csum,
        "nul": nul,
        "hdr2": hdr2,
        "body": body,
        "size_a": size_a,
        "prefix": p[:tag],
        "tag_hdr": p[tag : tag + 0x14],
        "payload_to_pok": p[:pok],
        "id_pok_bcd": ident + b"ProgramOK" + bcd,
        "id_pok_bcd_nul": ident + b"ProgramOK" + bcd + nul,
        "footer_line": p[fs : pok + 17],  # through nul before CRLF?
    }


def algs(data: bytes) -> dict[str, int]:
    s = sum(data) & 0xFFFF
    x = 0
    for i in range(0, len(data), 2):
        chunk = data[i : i + 2].ljust(2, b"\x00")
        x ^= be16(chunk)
    out = {
        "sum16": s,
        "~sum16": (~s) & 0xFFFF,
        "sum16_neg": (-s) & 0xFFFF,
        "xor16": x,
        "fletcher16": fletcher16(data),
        "crc16_ccitt_ffff": crc16(data, 0xFFFF, 0x1021),
        "crc16_ccitt_0000": crc16(data, 0x0000, 0x1021),
        "crc16_ccitt_1d0f": crc16(data, 0x1D0F, 0x1021),
        "crc16_xmodem": crc16(data, 0x0000, 0x1021),
        "crc16_ibm_ffff": crc16(data, 0xFFFF, 0x8005),  # not reflected — approximate
        "crc32_lo": zlib.crc32(data) & 0xFFFF,
        "crc32_hi": (zlib.crc32(data) >> 16) & 0xFFFF,
        "adler_lo": zlib.adler32(data) & 0xFFFF,
        "adler_hi": (zlib.adler32(data) >> 16) & 0xFFFF,
    }
    if len(data) >= 2:
        out["sum_be16"] = sum(be16(data, i) for i in range(0, len(data) - 1, 2)) & 0xFFFF
    return out


def main() -> None:
    files = [
        BLOBS / "LZ4266_ZC_1.djf",
        BLOBS / "LZ4267_H.djf",
        BLOBS / "LZ4279_R.djf",
        BLOBS / "LZ3196_A.djf",
    ]
    parsed = [parse(p) for p in files if p.exists()]
    # also older letter for differential
    older = BLOBS / "cdn_older" / "LZ4266_S.djf"
    if older.exists():
        parsed.append(parse(older))

    # Per-file region probes
    for r in parsed:
        want = r["csum"]
        print(f"\n=== {r['file']} want {want:#06x} tag={r['tag']} ident={r['ident']!r} ===")
        regions = {
            "id+POK+bcd": r["id_pok_bcd"],
            "id+POK+bcd+nul": r["id_pok_bcd_nul"],
            "POK+bcd": b"ProgramOK" + r["bcd"],
            "bcd": r["bcd"],
            "ident": r["ident"],
            "hdr2": r["hdr2"],
            "hdr2_tail8": r["hdr2"][-8:],
            "prefix": r["prefix"],
            "tag_hdr": r["tag_hdr"],
            "size_a_be": struct.pack(">I", r["size_a"]),
            "body_len_be": struct.pack(">I", len(r["body"])),
            "h0_h1": r["hdr2"][0:8],
        }
        # mixes
        regions["id+bcd"] = r["ident"] + r["bcd"]
        regions["hdr2+id+bcd"] = r["hdr2"] + r["ident"] + r["bcd"]
        regions["tag_hdr+hdr2+idpokbcd"] = r["tag_hdr"] + r["hdr2"] + r["id_pok_bcd"]

        hits = []
        for name, data in regions.items():
            if not data:
                continue
            for aname, val in algs(data).items():
                if val == want:
                    hits.append(f"  HIT {name}/{aname}")
        # constant arithmetic with hdr2 words
        h = [be32(r["hdr2"], i * 4) for i in range(9)]
        trials = {
            "h0_lo": h[0] & 0xFFFF,
            "h0_hi": (h[0] >> 16) & 0xFFFF,
            "h1_lo": h[1] & 0xFFFF,
            "h1_hi": (h[1] >> 16) & 0xFFFF,
            "h0_xor_h1_lo": (h[0] ^ h[1]) & 0xFFFF,
            "body_len_lo": len(r["body"]) & 0xFFFF,
            "size_a_lo": r["size_a"] & 0xFFFF,
            "size_a_hi": (r["size_a"] >> 16) & 0xFFFF,
            "len_xor_sizea": (len(r["body"]) ^ r["size_a"]) & 0xFFFF,
            "bcd_as_be_hi": int.from_bytes(r["bcd"][:2], "big"),
            "bcd_as_be_lo": int.from_bytes(r["bcd"][-2:], "big"),
        }
        for name, val in trials.items():
            if val == want:
                hits.append(f"  HIT field/{name}={val:#06x}")

        # sum of first N body bytes (small N only)
        for n in (12, 16, 32, 64, 96, 150, 256, 436):
            if len(r["body"]) < n:
                continue
            for aname, val in algs(r["body"][:n]).items():
                if val == want:
                    hits.append(f"  HIT body[:{n}]/{aname}")

        if hits:
            print("\n".join(hits))
        else:
            print("  (no hits on expanded small regions)")

    # Cross-file: is csum a linear function of size?
    print("\n=== csum vs sizes ===")
    print(f"{'file':18s} {'csum':6s} {'body':>10s} {'size_a':>10s} {'h0':>10s} {'h1':>10s}")
    for r in parsed:
        h0, h1 = be32(r["hdr2"], 0), be32(r["hdr2"], 4)
        print(
            f"{r['file'][:18]:18s} {r['csum']:04x} {len(r['body']):10d} "
            f"{r['size_a']:10d} {h0:10d} {h1:10d}"
        )


if __name__ == "__main__":
    main()
