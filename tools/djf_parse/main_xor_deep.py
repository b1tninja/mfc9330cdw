#!/usr/bin/env python3
"""Deep sparse-diff / XOR analysis for MAIN-era close letter pairs.

Focus: length fields, post-prefix structure, plaintext islands, codec tables.
"""
from __future__ import annotations

import math
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from main_vs_prog import parse  # noqa: E402
from xor_letter_diff import equal_runs, diff_runs  # noqa: E402

OLDER = ROOT / "downloads" / "firmware" / "blobs" / "cdn_older"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def ascii_islands(data: bytes, minlen: int = 6) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    i = 0
    n = len(data)
    while i < n:
        if 0x20 <= data[i] < 0x7F:
            j = i
            while j < n and 0x20 <= data[j] < 0x7F:
                j += 1
            if j - i >= minlen:
                out.append((i, data[i:j]))
            i = j
        else:
            i += 1
    return out


def length_candidates(body: bytes, target: int, window: int = 0x100) -> list[tuple[int, str, int]]:
    """Find LE/BE u16/u32 near head that equal target (Â±0..8)."""
    hits: list[tuple[int, str, int]] = []
    for off in range(0, min(window, len(body) - 4)):
        for endian, fmt in (("BE", ">"), ("LE", "<")):
            u16 = struct.unpack_from(fmt + "H", body, off)[0]
            u32 = struct.unpack_from(fmt + "I", body, off)[0]
            for name, val in (("u16", u16), ("u32", u32)):
                for delta in range(0, 9):
                    if val == target + delta or val == target - delta:
                        hits.append((off, f"{endian}{name}", val))
    # unique by (off, kind)
    seen = set()
    uniq = []
    for h in hits:
        k = (h[0], h[1])
        if k not in seen:
            seen.add(k)
            uniq.append(h)
    return uniq


def period_hint(data: bytes, max_p: int = 64) -> list[tuple[int, float]]:
    """Autocorr score for small periods on a sample."""
    sample = data[: min(len(data), 65536)]
    if len(sample) < 256:
        return []
    scores = []
    for p in range(2, max_p + 1):
        match = sum(1 for i in range(len(sample) - p) if sample[i] == sample[i + p])
        scores.append((p, 100.0 * match / (len(sample) - p)))
    scores.sort(key=lambda t: -t[1])
    return scores[:8]


def analyze_pair(label: str, pa: Path, pb: Path) -> None:
    print(f"\n{'=' * 72}\n{label}\n{'=' * 72}")
    ra, rb = parse(pa), parse(pb)
    a, b = ra["body"], rb["body"]
    n = min(len(a), len(b))
    delta = len(b) - len(a)
    xors = bytes(x ^ y for x, y in zip(a[:n], b[:n]))

    print(f"files: {pa.name} ({len(a)}) vs {pb.name} ({len(b)})  body_delta={delta:+d}")
    print(f"tag={ra['tag']} ident={ra['ident']!r}")
    ha = [struct.unpack_from(">I", ra["hdr2"], i)[0] for i in range(0, 36, 4)]
    hb = [struct.unpack_from(">I", rb["hdr2"], i)[0] for i in range(0, 36, 4)]
    print("hdr2 B:", " ".join(f"{v:#010x}" for v in ha))
    print("hdr2 L:", " ".join(f"{v:#010x}" for v in hb))
    print(
        f"  h0 Î”={hb[0]-ha[0]:+d}  h1 Î”={hb[1]-ha[1]:+d}  "
        f"h3 Î”={hb[3]-ha[3]:+d}  h6 Î”={hb[6]-ha[6]:+d}"
    )

    eq = sum(1 for i in range(n) if a[i] == b[i])
    print(f"overlap equal={100.0*eq/n:.2f}%  H(bodyB)={entropy(a):.3f}  H(XOR nonzero)={entropy(bytes(c for c in xors if c)):.3f}")

    # head dump with XOR
    print("\n--- body[0:0x80] B / L / XOR ---")
    for off in range(0, 0x80, 16):
        print(f"  {off:04x} B {a[off:off+16].hex()}")
        print(f"       L {b[off:off+16].hex()}")
        print(f"       X {xors[off:off+16].hex()}")

    # length field hunt vs body sizes / delta
    print("\n--- length-field hunt (head 0x100) ---")
    for target_name, target in [
        ("len(B)", len(a)),
        ("len(L)", len(b)),
        ("|delta|", abs(delta)),
        ("h0_B", ha[0]),
        ("h0_L", hb[0]),
        ("h1", ha[1]),
        ("overlap", n),
    ]:
        for which, body in (("B", a), ("L", b)):
            hits = length_candidates(body, target if target < 0x10000 or target_name.startswith("h") or "len" in target_name or target_name == "overlap" else abs(delta), 0x100)
            # tighten: only report if target matches reasonably
            hits = length_candidates(body, target, 0x100)
            if hits:
                print(f"  {which} ~{target_name}={target:#x}/{target}: {hits[:8]}")

    # also check XOR of head for length of changed region
    # first big equal run
    er = equal_runs(a, b, 64)
    dr = diff_runs(xors, 8)
    big_eq = max(er, key=lambda t: t[1]) if er else (0, 0)
    print(f"\nbiggest equal: +{big_eq[0]:#x} Ã- {big_eq[1]} ({big_eq[1]/1024:.1f} KiB)")
    print(f"equal_runsâ‰¥64={len(er)}  diff_runsâ‰¥8={len(dr)}")

    # timeline of coarse segs
    segs: list[tuple[str, int, int]] = []
    i = 0
    while i < n:
        if a[i] == b[i]:
            j = i
            while j < n and a[j] == b[j]:
                j += 1
            if j - i >= 256:
                segs.append(("EQ", i, j - i))
            i = j
        else:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            if j - i >= 16:
                segs.append(("DF", i, j - i))
            i = j
    print(f"\n--- coarse timeline EQâ‰¥256 / DFâ‰¥16 ({len(segs)} segs) ---")
    for kind, o, L in segs[:25]:
        print(f"  {kind} +{o:#x} Ã- {L}")
    if len(segs) > 35:
        print("  ...")
        for kind, o, L in segs[-8:]:
            print(f"  {kind} +{o:#x} Ã- {L}")

    # After the giant equal block: what does the next structure look like?
    eq_end = big_eq[0] + big_eq[1]
    print(f"\n--- after giant equal (+{eq_end:#x}) next 256B ---")
    for off in range(eq_end, min(eq_end + 256, n), 16):
        print(f"  {off:06x} B {a[off:off+16].hex()}")
        print(f"         L {b[off:off+16].hex()}")
        print(f"         X {xors[off:off+16].hex()}")

    # Diff-run size histogram (codec block sizes?)
    print("\n--- diff-run length histogram (top) ---")
    hist = Counter(L for _, L in dr)
    for L, c in hist.most_common(20):
        print(f"  len={L:6d} count={c}")

    # Equal-run length histogram excluding the giant
    print("\n--- equal-run length histogram (â‰¥64, excl. giant) ---")
    hist_e = Counter(L for o, L in er if (o, L) != big_eq)
    for L, c in hist_e.most_common(15):
        print(f"  len={L:6d} count={c}")

    # Periodicity of XOR in sparse-diff zones (concat DF runs sample)
    df_sample = bytearray()
    for o, L in sorted(dr, key=lambda t: -t[1])[:30]:
        df_sample.extend(xors[o : o + min(L, 4096)])
        if len(df_sample) > 200000:
            break
    print(f"\n--- XOR period hint on top diff runs ({len(df_sample)}B sample) ---")
    for p, pct in period_hint(bytes(df_sample)):
        print(f"  period={p:3d} match={pct:.2f}%")

    # Also period on equal plateau (should be whatever body codec left)
    plateau = a[big_eq[0] : big_eq[0] + min(big_eq[1], 65536)]
    print(f"\n--- period hint on equal plateau sample ---")
    for p, pct in period_hint(plateau):
        print(f"  period={p:3d} match={pct:.2f}%")

    # Plaintext islands in bodies / XOR
    print("\n--- ASCII islands â‰¥8 in body B (first 20) ---")
    for off, s in ascii_islands(a, 8)[:20]:
        print(f"  +{off:#x}: {s[:60]!r}")
    print("--- ASCII islands â‰¥6 in XOR (first 20) ---")
    for off, s in ascii_islands(xors, 6)[:20]:
        print(f"  +{off:#x}: {s[:60]!r}")

    # Tail: L-only suffix when L longer
    if len(b) > len(a):
        tail = b[len(a) :]
        print(f"\n--- L-only suffix ({len(tail)}B) H={entropy(tail):.3f} ---")
        print(f"  head: {tail[:64].hex()}")
        print(f"  ASCII: {ascii_islands(tail, 4)[:10]}")
        for p, pct in period_hint(tail, 32):
            print(f"  period={p} match={pct:.2f}%")

    # Sparse head diffs (before giant equal) â€” stamp / codec params
    head_end = big_eq[0]
    print(f"\n--- sparse head diffs before giant equal (0..+{head_end:#x}) ---")
    diffs = [(i, a[i], b[i]) for i in range(head_end) if a[i] != b[i]]
    print(f"  {len(diffs)} differing bytes:")
    for i, xa, xb in diffs:
        print(f"    +{i:#04x}: {xa:02x}â†’{xb:02x}  xor={xa^xb:02x}")

    # Check if head stamp fields encode sizes
    print("\n--- interpret body[0:0x60] as fields ---")
    for body, name in ((a, "B"), (b, "L")):
        print(f"  {name}:")
        for off in range(0, 0x60, 4):
            be = struct.unpack_from(">I", body, off)[0]
            le = struct.unpack_from("<I", body, off)[0]
            mark = ""
            for tname, t in (("lenB", len(a)), ("lenL", len(b)), ("dlt", abs(delta)), ("h0", ha[0]), ("h1", ha[1])):
                if be in (t, t + 6, t + 7, t + 8) or le in (t, t + 6, t + 7, t + 8):
                    mark = f"  <<~{tname}"
            print(f"    +{off:02x}: BE={be:#010x} LE={le:#010x}{mark}")

    # Repeating 4/8-byte patterns after shared prefix in XOR of first 4K diff zone
    print("\n--- repeated 4-byte tiles in XOR of first dense region ---")
    # find first window with >30% diff
    dense_off = None
    for off in range(0, n, 4096):
        end = min(off + 4096, n)
        d = sum(1 for i in range(off, end) if a[i] != b[i])
        if d / (end - off) > 0.3 and off > big_eq[0]:
            dense_off = off
            break
    if dense_off is not None:
        chunk = xors[dense_off : dense_off + 8192]
        c4 = Counter(chunk[i : i + 4] for i in range(0, len(chunk) - 4, 4))
        print(f"  dense@+{dense_off:#x}; top 4B tiles:")
        for tile, c in c4.most_common(8):
            print(f"    {tile.hex()} Ã-{c}")
    else:
        print("  no dense window after giant equal with >30% diff in 4K (very sparse)")

    # 1KiB window equal% map around transition
    print("\n--- 1KiB equal% around giant-equal edges ---")
    for center in [0, big_eq[0], eq_end, eq_end + 0x10000, n // 2, n - 0x10000]:
        if center < 0 or center >= n:
            continue
        off = max(0, center - 512)
        end = min(n, off + 1024)
        eql = sum(1 for i in range(off, end) if a[i] == b[i])
        print(f"  window +{off:#x}..+{end:#x}: equal={100.0*eql/(end-off):.1f}%")


# Period-7 counter families (see decode_period7.py / PANL valleys).
FAMILY_A = frozenset({0x10, 0x40, 0x44})  # lanes typically 6 / 1 / 4
FAMILY_B = frozenset({0x22, 0x88, 0x20, 0x80})


def lane_mode_deltas(
    body: bytes, start: int, end: int
) -> list[tuple[int, int, float]]:
    """Per-lane mode Δ between successive bytes at addr ≡ lane (mod 7)."""
    out: list[tuple[int, int, float]] = []
    for lane in range(7):
        vals: list[int] = []
        addr = start + ((lane - start % 7) % 7)
        while addr < end:
            vals.append(body[addr])
            addr += 7
        if len(vals) < 2:
            out.append((lane, 0, 0.0))
            continue
        diffs = Counter((vals[i + 1] - vals[i]) & 0xFF for i in range(len(vals) - 1))
        mode, cnt = diffs.most_common(1)[0]
        out.append((lane, mode, cnt / (len(vals) - 1)))
    return out


def classify_period7_family(
    body: bytes, start: int, end: int, *, min_frac: float = 0.98
) -> str | None:
    modes = {
        mode
        for _lane, mode, frac in lane_mode_deltas(body, start, end)
        if frac >= min_frac
    }
    if FAMILY_A.issubset(modes):
        return "A"
    if FAMILY_B.issubset(modes):
        return "B"
    return None


def analyze_112_band_period7(body: bytes, band0: int = 0x5F68E2, band1: int = 0x6B8112) -> None:
    """Show that the MAIN 112-byte XOR band is period-7 Family-A framed."""
    print(f"\n--- 112-band period-7 family ({band0:#x}..{band1:#x}) ---")
    if band1 > len(body) or band0 >= band1:
        print("  band out of range")
        return
    deltas = lane_mode_deltas(body, band0, band1)
    fam = classify_period7_family(body, band0, band1)
    for lane, mode, frac in deltas:
        mark = ""
        if mode in FAMILY_A and frac >= 0.98:
            mark = "  <<FamA"
        elif mode in FAMILY_B and frac >= 0.98:
            mark = "  <<FamB"
        print(f"  lane{lane}: Δ={mode:#04x} frac={frac:.3f}{mark}")
    print(f"  classify: Family-{fam}" if fam else "  classify: (none)")
    # Letter-constant XOR on FamA lane1 is 0xb0 across B⊕L — expected if both
    # counters share the same Δ and differ only by a fixed bias.


def scan_period7_windows(body: bytes, window: int = 0x10000, min_frac: float = 0.95) -> None:
    print(f"\n--- period-7 family scan (window={window:#x}, frac≥{min_frac}) ---")
    hits: list[tuple[int, str]] = []
    for off in range(0, max(0, len(body) - window + 1), window):
        fam = classify_period7_family(body, off, off + window, min_frac=min_frac)
        if fam:
            hits.append((off, fam))
    print(f"  hits={len(hits)} A={sum(1 for _, f in hits if f == 'A')} B={sum(1 for _, f in hits if f == 'B')}")
    for off, fam in hits[:24]:
        print(f"  +{off:#x} Family-{fam}")
    if len(hits) > 24:
        print(f"  ... {len(hits) - 24} more")


def inventory() -> None:
    print("=== MAIN-era / close-letter pair inventory ===")
    pairs = [
        ("MAIN LZ2350_Bâ†”L", OLDER / "LZ2350_B.djf", OLDER / "LZ2350_L.djf", "MAIN"),
        ("MAIN LZ2346_Dâ†”P", OLDER / "LZ2346_D.djf", OLDER / "LZ2346_P.djf", "MAIN"),
        ("MAIN LZ2328_Câ†”H", OLDER / "LZ2328_C.djf", OLDER / "LZ2328_H.djf", "MAIN"),
        ("PROG LZ2751_Bâ†”C", OLDER / "LZ2751_B.djf", OLDER / "LZ2751_C.djf", "PROG"),
        (
            "PROG LZ2751_Bâ†”L",
            OLDER / "LZ2751_B.djf",
            ROOT / "downloads/firmware/corpus/MFC-9320CW/MAIN_LZ2751_L.djf",
            "PROG",
        ),
        ("PROG LZ4266_Sâ†”T", OLDER / "LZ4266_S.djf", OLDER / "LZ4266_T.djf", "PROG"),
        (
            "PROG LZ4266_Sâ†”ZC",
            OLDER / "LZ4266_S.djf",
            ROOT / "downloads/firmware/blobs/LZ4266_ZC_1.djf",
            "PROG",
        ),
        (
            "ROM2 LZ4267_Bâ†”H",
            OLDER / "LZ4267_B.djf",
            ROOT / "downloads/firmware/blobs/LZ4267_H.djf",
            "ROM2",
        ),
        (
            "PANL LZ4279_Hâ†”R",
            OLDER / "LZ4279_H.djf",
            ROOT / "downloads/firmware/blobs/LZ4279_R.djf",
            "PANL",
        ),
        (
            "ROM2 LZ4219_Bâ†”F",
            OLDER / "LZ4219_B.wayback.djf",
            OLDER / "LZ4219_F.wayback.djf",
            "ROM2",
        ),
    ]
    # also single MAIN-era files without pair
    singles = sorted(OLDER.glob("LZ23*.djf"))
    print("\ncdn_older LZ23xx:")
    for p in singles:
        r = parse(p)
        print(f"  {p.name:16s} tag={r['tag']:4s} body={len(r['body']):8d} ident={r['ident']!r}")

    print("\npair quick stats:")
    for label, pa, pb, _ in pairs:
        if not pa.exists() or not pb.exists():
            print(f"  {label}: MISSING")
            continue
        ra, rb = parse(pa), parse(pb)
        a, b = ra["body"], rb["body"]
        n = min(len(a), len(b))
        first = next((i for i in range(n) if a[i] != b[i]), n)
        eq = sum(1 for i in range(n) if a[i] == b[i])
        er = equal_runs(a, b, 256)
        big = max(er, key=lambda t: t[1]) if er else (0, 0)
        print(
            f"  {label}: tag={ra['tag']} equal={100*eq/n:.1f}% "
            f"first_diff=+{first:#x} big_eq=+{big[0]:#x}x{big[1]/1024:.0f}KiB "
            f"dbody={len(b)-len(a):+d}"
        )


def main() -> None:
    inventory()
    analyze_pair("LZ2350_B ↔ LZ2350_L (best MAIN)", OLDER / "LZ2350_B.djf", OLDER / "LZ2350_L.djf")
    ra = parse(OLDER / "LZ2350_B.djf")
    analyze_112_band_period7(ra["body"])
    scan_period7_windows(ra["body"])
    zc = ROOT / "downloads" / "firmware" / "blobs" / "LZ4266_ZC_1.djf"
    if zc.exists():
        print(f"\n{'=' * 72}\nLZ4266_ZC_1 PROG period-7 windows\n{'=' * 72}")
        scan_period7_windows(parse(zc)["body"])
    analyze_pair("LZ2346_D ↔ LZ2346_P (2nd MAIN)", OLDER / "LZ2346_D.djf", OLDER / "LZ2346_P.djf")


if __name__ == "__main__":
    main()
