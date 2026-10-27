#!/usr/bin/env python3
"""Field-level dissection of invariant DJF body prefixes (PROG 150B / PANL 436B)."""
from __future__ import annotations

import struct
from collections import Counter
from pathlib import Path

BLOBS = Path(__file__).resolve().parents[2] / "downloads" / "firmware" / "blobs"
OLDER = BLOBS / "cdn_older"
OUT = BLOBS / "binwalk" / "carved" / "prefix_dissect"


def body_of(path: Path) -> bytes:
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
    return p[bo : fs if pk >= 0 else None]


def be16(b: bytes, o: int) -> int:
    return struct.unpack_from(">H", b, o)[0]


def be32(b: bytes, o: int) -> int:
    return struct.unpack_from(">I", b, o)[0]


def le16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def le32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def bit_runs(data: bytes) -> None:
    """Look for bit-level structure / nibbles."""
    hi = Counter(b >> 4 for b in data)
    lo = Counter(b & 0xF for b in data)
    print(f"  hi-nibble top: {hi.most_common(6)}")
    print(f"  lo-nibble top: {lo.most_common(6)}")


def try_as_records(data: bytes, rec: int, label: str) -> None:
    if len(data) < rec * 2:
        return
    n = len(data) // rec
    print(f"  as {rec}-byte records ({n} full):")
    for i in range(min(n, 12)):
        chunk = data[i * rec : (i + 1) * rec]
        print(f"    [{i:02d}] {chunk.hex()}")
    # lane deltas if record==7
    if rec == 7 and n >= 3:
        for L in range(7):
            diffs = Counter(
                (data[(i + 1) * 7 + L] - data[i * 7 + L]) & 0xFF for i in range(n - 1)
            )
            mode, cnt = diffs.most_common(1)[0]
            print(f"    lane{L} modeΔ={mode:#x} frac={cnt/(n-1):.2f}")


def sliding_self_similarity(data: bytes, win: int = 16) -> None:
    """Find repeated win-byte patterns inside prefix."""
    c = Counter(data[i : i + win] for i in range(0, len(data) - win + 1))
    repeats = [(blk, n) for blk, n in c.most_common(10) if n > 1]
    print(f"  repeated {win}B blocks: {len(repeats)}")
    for blk, n in repeats[:5]:
        print(f"    n={n} {blk.hex()}")


def correlate_with_hdr2(prefix: bytes, hdr2: bytes, label: str) -> None:
    print(f"  hdr2 correlation ({label}):")
    for i in range(0, len(hdr2) - 3, 4):
        dw = hdr2[i : i + 4]
        j = prefix.find(dw)
        print(f"    hdr2[{i//4}] {dw.hex()} in prefix: {j}")


def dissect_prog() -> bytes:
    paths = {
        "S": OLDER / "LZ4266_S.djf",
        "T": OLDER / "LZ4266_T.djf",
        "ZC": BLOBS / "LZ4266_ZC_1.djf",
    }
    bodies = {k: body_of(p) for k, p in paths.items()}
    # 150-byte invariant
    pref = bodies["S"][:150]
    assert bodies["T"][:150] == pref and bodies["ZC"][:150] == pref

    print("=" * 72)
    print("PROG invariant prefix (150 bytes)")
    print(f"  magic[0:12] = {pref[:12].hex()}")
    print(f"  body[12:16] = {pref[12:16].hex()}  BE32={be32(pref,12):#x} LE32={le32(pref,12):#x}")
    print(f"  body[16:20] = {pref[16:20].hex()}  BE={be32(pref,16):#x} LE={le32(pref,16):#x}")

    # Split: magic(12) + rest
    rest = pref[12:]
    print(f"  rest len={len(rest)}")
    bit_runs(rest)
    sliding_self_similarity(pref, 8)
    sliding_self_similarity(pref, 16)

    # Compare S vs T vs ZC immediately after 150
    print("  first divergent bytes:")
    for name in ("S", "T", "ZC"):
        b = bodies[name]
        print(f"    {name} [150:166] {b[150:166].hex()}")

    # Where does S diverge from T / ZC?
    for a, b, lab in (("S", "T", "S/T"), ("S", "ZC", "S/ZC"), ("T", "ZC", "T/ZC")):
        x = bodies[a]
        y = bodies[b]
        i = 0
        while i < min(len(x), len(y)) and x[i] == y[i]:
            i += 1
        print(f"  {lab} first differ @{i:#x}: {x[i:i+8].hex()} vs {y[i:i+8].hex()}")

    # Try 7-byte framing on [12:] and on full prefix
    print("  --- record views on pref[12:] ---")
    for rec in (6, 7, 8, 12, 16):
        try_as_records(rest, rec, "rest")

    # period-7 family-A/B hunt inside prefix
    for phase in range(7):
        fr = [pref[i : i + 7] for i in range(12 + phase, 150 - 6, 7)]
        if len(fr) < 4:
            continue
        # check 5e/de or 7c/7d density in lane
        for L in range(7):
            vals = [f[L] for f in fr]
            c = Counter(vals)
            if c.most_common(1)[0][1] >= len(fr) * 0.8:
                print(
                    f"  pref phase={phase} lane{L} dominated by "
                    f"{c.most_common(2)}"
                )

    # Extract known pad-like subsequence around +0x70
    print("  region +0x60..+0x96:")
    dump = pref[0x60:]
    print(f"    {dump.hex()}")
    try_as_records(dump, 7, "tail")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "prog_invariant_150.bin").write_bytes(pref)
    # also write S-only extension to first ZC diverge
    (OUT / "prog_S_head_512.bin").write_bytes(bodies["S"][:512])
    (OUT / "prog_ZC_head_512.bin").write_bytes(bodies["ZC"][:512])
    return pref


def dissect_panl() -> bytes:
    ph = body_of(OLDER / "LZ4279_H.djf")
    pr = body_of(BLOBS / "LZ4279_R.djf")
    n = 0
    while n < min(len(ph), len(pr)) and ph[n] == pr[n]:
        n += 1
    pref = ph[:n]
    print("=" * 72)
    print(f"PANL invariant prefix ({n} bytes)")
    print(f"  magic[0:12] = {pref[:12].hex()}")
    print(f"  body[12:16] = {pref[12:16].hex()} BE={be32(pref,12):#x} LE={le32(pref,12):#x}")

    # Find where period-7 family B starts inside prefix
    # search for 5e .. de alternating every 7
    best = None
    for start in range(12, min(200, len(pref) - 28)):
        ok = 0
        for k in range(4):
            off = start + k * 7
            if off + 1 > len(pref):
                break
            b0 = pref[off]
            expect = 0x5E if (k % 2 == 0) else 0xDE
            # also allow swapped phase
            if b0 in (0x5E, 0xDE):
                ok += 1
        if ok >= 3:
            # verify stronger
            fr = []
            for k in range((len(pref) - start) // 7):
                fr.append(pref[start + k * 7 : start + (k + 1) * 7])
            if len(fr) >= 4 and all(f[0] in (0x5E, 0xDE) for f in fr[:8] if len(f) == 7):
                # check alternating
                alt = all(
                    fr[k][0] == (0x5E if k % 2 == 0 else 0xDE)
                    or fr[k][0] == (0xDE if k % 2 == 0 else 0x5E)
                    for k in range(min(8, len(fr)))
                )
                if alt and (best is None or start < best[0]):
                    best = (start, fr)

    if best:
        start, fr = best
        print(f"  family-B-like frames start @{start:#x} ({len(fr)} frames in prefix)")
        for i, f in enumerate(fr[:6]):
            print(f"    [{i}] {f.hex()}")
        print(f"  bytes before pad: {start} — dump:")
        for off in range(0, start, 16):
            print(f"    {off:04x}: {pref[off:off+16].hex()}")
    else:
        print("  no clear 5e/de frame start found; scanning denser...")
        for start in range(12, 120):
            if pref[start] in (0x5E, 0xDE) and start + 7 < len(pref) and pref[start + 7] in (
                0x5E,
                0xDE,
            ):
                print(f"    candidate @{start:#x}: {pref[start:start+21].hex()}")

    bit_runs(pref[12:start] if best else pref[12:64])
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "panl_invariant_prefix.bin").write_bytes(pref)
    if best:
        (OUT / "panl_pre_pad.bin").write_bytes(pref[: best[0]])
    return pref


def cross_family(prog: bytes, panl: bytes) -> None:
    print("=" * 72)
    print("PROG vs PANL prefix cross-compare")
    # only 12 shared; what about XOR / nibble patterns after?
    n = min(150, len(panl))
    x = bytes(a ^ b for a, b in zip(prog[:n], panl[:n]))
    print(f"  XOR first {n}: zeros={x.count(0)} H-ish unique={len(set(x))}")
    print(f"  XOR[0:32]={x[:32].hex()}")
    # common subsequences (LCS-lite: matching 4-byte windows)
    prog_set = {prog[i : i + 4] for i in range(12, 146)}
    hits = []
    for i in range(12, min(len(panl) - 3, 200)):
        w = panl[i : i + 4]
        if w in prog_set and w != b"\x00\x00\x00\x00":
            hits.append((i, w.hex()))
    print(f"  shared 4B windows after magic (in first 200 of PANL): {len(hits)}")
    for i, h in hits[:12]:
        print(f"    PANL@{i:#x} = {h}")


def hdr2_link() -> None:
    print("=" * 72)
    print("Link hdr2 fields into body prefix")
    for label, path in [
        ("PROG-ZC", BLOBS / "LZ4266_ZC_1.djf"),
        ("PANL-R", BLOBS / "LZ4279_R.djf"),
        ("IFAX", BLOBS / "LZ3196_A.djf"),
    ]:
        raw = path.read_bytes()
        p = raw[raw.find(b"DATA=") + 5 :]
        for off in (0x18, 0x0C):
            if p[off : off + 4] in (b"PROG", b"ROM2", b"PANL"):
                t = off
                break
        hdr2 = p[t + 0x14 : t + 0x14 + 0x24]
        body = body_of(path)
        print(f"  {label}:")
        correlate_with_hdr2(body[:512], hdr2, label)
        # hdr2[6] low 16 = ffe5; search ffe5 in body
        print(f"    ffe5 in body head: {body[:256].find(bytes.fromhex('ffe5'))}")
        print(f"    894d2ad7 in body: {body.find(bytes.fromhex('894d2ad7'))}")


def ifax_structure() -> None:
    b = body_of(BLOBS / "LZ3196_A.djf")
    print("=" * 72)
    print(f"IFAX full body ({len(b)} bytes) structured view")
    # strip trailing 0d0a0c if present
    core = b
    if core.endswith(b"\r\n\x0c"):
        core = core[:-3]
        print("  stripped trailing CRLF+FF")
    if core.endswith(b"******"):
        print("  ends with six 0x2a '*'")
    # find 7c/7d region
    idx = core.find(b"\x7c")
    print(f"  first 0x7c @{idx}")
    if idx > 0:
        print(f"  pre-7c ({idx}B): {core[:idx].hex()}")
        print(f"  from 7c: {core[idx:].hex()}")
        try_as_records(core[idx:], 7, "ifax-7c")
    # look at repeating 0ac3 pattern near end
    pos = []
    i = 0
    while True:
        j = core.find(bytes.fromhex("0ac3"), i)
        if j < 0:
            break
        pos.append(j)
        i = j + 1
    print(f"  0a c3 positions: {pos}")
    if len(pos) >= 2:
        print(f"  gaps: {[pos[k+1]-pos[k] for k in range(len(pos)-1)]}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    prog = dissect_prog()
    panl = dissect_panl()
    cross_family(prog, panl)
    hdr2_link()
    ifax_structure()


if __name__ == "__main__":
    main()
