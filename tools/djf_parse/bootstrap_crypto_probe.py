#!/usr/bin/env python3
"""Probe whether PROG body[12:0x60] is a hash/HMAC/AES of known header fields."""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import struct
from pathlib import Path

BLOBS = Path(__file__).resolve().parents[2] / "downloads" / "firmware" / "blobs"


def load_prog(path: Path):
    raw = path.read_bytes()
    p = raw[raw.find(b"DATA=") + 5 :]
    nul = p.find(b"\x00")
    ident = p[:nul]
    t = 0x18
    h2 = p[t + 0x14 : t + 0x14 + 0x24]
    bo = t + 0x14 + 0x24
    pk = p.rfind(b"ProgramOK")
    fs = pk
    while fs > 0 and 0x20 <= p[fs - 1] < 0x7F:
        fs -= 1
    body = p[bo:fs]
    return ident, h2, body, p[:t], p[t : t + 0x38]


def main() -> None:
    ident, h2, body, prefix, tagreg = load_prog(BLOBS / "LZ4266_ZC_1.djf")
    boot = body[12:0x60]
    print(f"ident={ident!r}")
    print(f"boot[0:20]={boot[:20].hex()}")
    print(f"hdr2_family={h2[-8:].hex()}")

    cands = {
        "ident": ident,
        "ident0": ident + b"\x00",
        "prefix": prefix,
        "hdr2": h2,
        "fam": h2[-8:],
        "tagreg": tagreg,
        "ident+hdr2": ident + h2,
        "magic": body[:12],
        "prefix+tagreg": prefix + tagreg,
    }
    hits = 0
    for name, data in cands.items():
        for algo in (hashlib.sha1, hashlib.md5, hashlib.sha256):
            h = algo(data).digest()
            if boot.startswith(h[:8]) or boot[:16] == h[:16] or boot.find(h[:12]) >= 0:
                print(f"HIT {algo().name}({name})={h.hex()}")
                hits += 1
        h = hmac.new(h2[-8:], data, hashlib.sha1).digest()
        if boot.startswith(h[:8]):
            print(f"HMAC-SHA1 HIT key=fam data={name} {h.hex()}")
            hits += 1
    if not hits:
        print("no hash/HMAC prefix hits against bootstrap")

    # AES via cryptography if present
    if importlib.util.find_spec("cryptography") is None:
        print("cryptography not installed — skip AES key trials")
        return

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def aes_ecb(key: bytes, data: bytes) -> bytes:
        data = data[: len(data) - len(data) % 16]
        d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        return d.update(data) + d.finalize()

    keys = {
        "sha256(ident)[:16]": hashlib.sha256(ident).digest()[:16],
        "sha256(ident)": hashlib.sha256(ident).digest(),
        "md5(ident)": hashlib.md5(ident).digest(),
        "fam*2": h2[-8:] * 2,
        "magic+4": body[:12] + body[:4],
        "sha1(ident)[:16]": hashlib.sha1(ident).digest()[:16],
        "sha256(hdr2)[:16]": hashlib.sha256(h2).digest()[:16],
        "sha256(magic)[:16]": hashlib.sha256(body[:12]).digest()[:16],
    }
    for kn, key in keys.items():
        if len(key) not in (16, 24, 32):
            continue
        pt = aes_ecb(key, boot[:64])
        pr = sum(1 for b in pt if 32 <= b < 127) / len(pt)
        z = pt.count(0) / len(pt)
        flag = " **" if pr > 0.55 or z > 0.15 or pt.startswith(b"\x7fELF") else ""
        print(f"AES-ECB {kn}: pr={pr:.2f} z={z:.2f} head={pt[:12].hex()}{flag}")


if __name__ == "__main__":
    main()
