#!/usr/bin/env python3
"""Deep dive on PROG-family body[12:0x60] bootstrap (before family-A framing)."""
from __future__ import annotations

import math
import struct
import zlib
from collections import Counter
from pathlib import Path

BLOBS = Path(__file__).resolve().parents[2] / "downloads" / "firmware" / "blobs"
OLDER = BLOBS / "cdn_older"
OUT = BLOBS / "binwalk" / "carved" / "prefix_dissect"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def body_after_tag(path: Path) -> tuple[bytes, bytes, bytes]:
    """Return (body, hdr2, tag)."""
    raw = path.read_bytes()
    p = raw[raw.find(b"DATA=") + 5 :]
    for off in (0x18, 0x0C):
        if p[off : off + 4] in (b"PROG", b"ROM2", b"PANL"):
            t = off
            break
    else:
        raise ValueError(path)
    h2len = struct.unpack_from(">I", p, t + 16)[0]
    if not 0 < h2len <= 0x100:
        h2len = 0x24
    hdr2 = p[t + 0x14 : t + 0x14 + h2len]
    bo = t + 0x14 + h2len
    pk = p.rfind(b"ProgramOK")
    fs = pk
    while fs > 0 and 0x20 <= p[fs - 1] < 0x7F:
        fs -= 1
    body = p[bo : fs if pk >= 0 else None]
    return body, hdr2, p[t : t + 4]


def dump(label: str, data: bytes) -> None:
    print(f"  {label} ({len(data)}B) H={entropy(data):.3f}")
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {off:04x}: {chunk.hex():<32} {asc}")


def try_decompress(data: bytes, label: str) -> None:
    for wbits in (15, -15, 31, 47):
        try:
            out = zlib.decompress(data, wbits)
            print(f"  ZLIB HIT {label} wbits={wbits} -> {len(out)}B head={out[:32]!r}")
            return
        except zlib.error:
            pass
    # raw deflate with skipped headers
    for skip in range(0, min(16, len(data))):
        for wbits in (-15, 15):
            try:
                out = zlib.decompress(data[skip:], wbits)
                if len(out) > 16:
                    print(
                        f"  ZLIB HIT {label} skip={skip} wbits={wbits} "
                        f"-> {len(out)}B head={out[:32]!r}"
                    )
                    return
            except zlib.error:
                pass


def bit_planes(data: bytes) -> None:
    print("  bit-plane ones ratios:")
    for bit in range(8):
        ones = sum(1 for b in data if b & (1 << bit)) / len(data)
        print(f"    bit{bit}: {ones:.3f}")


def diff_bytes(a: bytes, b: bytes, label: str) -> None:
    n = min(len(a), len(b))
    diffs = [(i, a[i], b[i]) for i in range(n) if a[i] != b[i]]
    print(f"  {label}: {len(diffs)}/{n} differing")
    for i, xa, xb in diffs[:20]:
        print(f"    @{i:#x}: {xa:02x} -> {xb:02x} (xor {xa^xb:02x})")


def search_u32_candidates(data: bytes, body_len: int) -> None:
    print("  u32 fields that look like sizes:")
    for endian, unpack in (("BE", ">I"), ("LE", "<I")):
        for off in range(0, len(data) - 3):
            v = struct.unpack_from(unpack, data, off)[0]
            if v in (
                body_len,
                body_len - 12,
                body_len - 16,
                len(data),
                150,
                0x96,
                0x60,
                0x54,
            ):
                print(f"    {endian}@{off:#x} = {v:#x}")
            if 0x20 < v < 0x200 and off < 0x20:
                print(f"    {endian}@{off:#x} = {v:#x} (small)")


def main() -> None:
    samples = {}
    for name, path in [
        ("PROG-S", OLDER / "LZ4266_S.djf"),
        ("PROG-T", OLDER / "LZ4266_T.djf"),
        ("PROG-ZC", BLOBS / "LZ4266_ZC_1.djf"),
        ("PANL-H", OLDER / "LZ4279_H.djf"),
        ("PANL-R", BLOBS / "LZ4279_R.djf"),
        ("IFAX", BLOBS / "LZ3196_A.djf"),
        ("ROM2-H", BLOBS / "LZ4267_H.djf"),
        ("ROM2-B", OLDER / "LZ4267_B.djf"),
    ]:
        if path.exists():
            body, hdr2, tag = body_after_tag(path)
            samples[name] = (body, hdr2, tag)

    print("=" * 72)
    print("body[12:0x60] across samples")
    for name, (body, hdr2, tag) in samples.items():
        chunk = body[12:0x60]
        print(f"\n{name} tag={tag!r} body_len={len(body):#x}")
        dump("bootstrap", chunk)
        search_u32_candidates(chunk, len(body))
        try_decompress(chunk, name)
        try_decompress(body[:0x60], name + "-with-magic")

    # PROG bootstrap identical across S/T/ZC?
    ps, pt, pz = (samples[k][0] for k in ("PROG-S", "PROG-T", "PROG-ZC"))
    print("\n" + "=" * 72)
    print("PROG bootstrap identity")
    print(f"  S[12:0x60]==T[12:0x60]: {ps[12:0x60] == pt[12:0x60]}")
    print(f"  S[12:0x60]==ZC[12:0x60]: {ps[12:0x60] == pz[12:0x60]}")
    print(f"  S[12:0x96]==ZC[12:0x96]: {ps[12:0x96] == pz[12:0x96]}")

    boot = ps[12:0x60]
    bit_planes(boot)
    print(f"  bootstrap entropy={entropy(boot):.3f}")

    # byte-wise differential S vs ZC starting at 0x60 (after bootstrap)
    print("\n" + "=" * 72)
    print("After bootstrap: where versions diverge")
    diff_bytes(ps[0x60:0x100], pz[0x60:0x100], "S vs ZC [0x60:0x100]")
    diff_bytes(ps[0x60:0x100], pt[0x60:0x100], "S vs T [0x60:0x100]")

    # PANL bootstrap vs PROG
    print("\n" + "=" * 72)
    print("PANL[12:0x5a] (pre family-B) vs PROG[12:0x5a]")
    panl = samples["PANL-R"][0]
    dump("PANL pre-pad", panl[12:0x5A])
    dump("PROG same span", ps[12:0x5A])
    x = bytes(a ^ b for a, b in zip(panl[12:0x5A], ps[12:0x5A]))
    print(f"  XOR H={entropy(x):.3f} zeros={x.count(0)}/{len(x)}")
    print(f"  XOR: {x.hex()}")

    # IFAX head is only 34B = through 12+34=46 = 0x2e
    ifax = samples["IFAX"][0]
    dump("IFAX[12:0x2e]", ifax[12:0x2E])
    dump("PROG[12:0x2e]", ps[12:0x2E])

    # ROM2 magic region
    print("\n" + "=" * 72)
    print("ROM2 body head (different magic)")
    rom = samples["ROM2-H"][0]
    dump("ROM2[0:0x60]", rom[:0x60])
    dump("ROM2-B[0:0x60]", samples["ROM2-B"][0][:0x60])
    diff_bytes(samples["ROM2-B"][0][:0x40], rom[:0x40], "ROM2 B vs H head")

    # Check if bootstrap looks like ciphertext of zeros under rolling XOR
    print("\n" + "=" * 72)
    print("Transform probes on PROG bootstrap")
    # rolling XOR
    rx = bytes(boot[i] ^ boot[i - 1] for i in range(1, len(boot)))
    print(f"  consecutive XOR H={entropy(rx):.3f} head={rx[:16].hex()}")
    # subtract previous
    sub = bytes((boot[i] - boot[i - 1]) & 0xFF for i in range(1, len(boot)))
    print(f"  consecutive SUB mode={Counter(sub).most_common(5)}")
    # add keystream from hdr2 family magic
    key = samples["PROG-ZC"][1][0x1C:0x24]  # last 8 of hdr2 = family magic
    print(f"  hdr2 family magic key={key.hex()}")
    dec = bytes(boot[i] ^ key[i % len(key)] for i in range(len(boot)))
    print(f"  XOR hdr2-magic H={entropy(dec):.3f} head={dec[:16].hex()} asc={dec[:16]!r}")
    try_decompress(dec, "bootstrap-xored-hdr2magic")

    # XOR with body magic itself
    mag = ps[:12]
    dec2 = bytes(boot[i] ^ mag[i % 12] for i in range(len(boot)))
    print(f"  XOR body-magic H={entropy(dec2):.3f} head={dec2[:16].hex()}")
    try_decompress(dec2, "bootstrap-xored-bodymagic")

    # save
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "prog_bootstrap_12_60.bin").write_bytes(boot)
    (OUT / "panl_prepad_12_5a.bin").write_bytes(panl[12:0x5A])
    (OUT / "rom2_head_60.bin").write_bytes(rom[:0x60])

    # Alignment: does 0x60 == start of something size-related in hdr2[2]?
    print("\n" + "=" * 72)
    print("hdr2[2] byte breakdown")
    for name, (body, hdr2, tag) in samples.items():
        dw = struct.unpack_from(">I", hdr2, 8)[0]
        rawb = hdr2[8:12]
        print(
            f"  {name:8} hdr2[2]={dw:#010x} bytes={rawb.hex()} "
            f"LE={struct.unpack_from('<I', hdr2, 8)[0]:#x} "
            f"body12={body[12:16].hex()}"
        )


if __name__ == "__main__":
    main()
