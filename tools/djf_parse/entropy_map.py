#!/usr/bin/env python3
"""Sliding-window entropy / printable / zero map over Brother DJF carved payloads.

Outputs:
  - console summary (low-H valleys, header/footer zones)
  - CSV under binwalk/carved/<name>.entropy.csv
  - ASCII sparkline under binwalk/carved/<name>.entropy.txt
"""
from __future__ import annotations

import argparse
import csv
import math
import struct
from collections import Counter
from pathlib import Path

BLOBS = Path(__file__).resolve().parents[2] / "downloads" / "firmware" / "blobs"
CARVED = BLOBS / "binwalk" / "carved"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def find_tag(payload: bytes) -> int:
    for off in (0x18, 0x0C, 0x10, 0x14, 0x1C):
        if payload[off : off + 4] in (b"PROG", b"ROM2", b"PANL", b"FIRM"):
            return off
    raise ValueError("tag not found")


def body_footer(payload: bytes) -> tuple[int, int, int]:
    """Return (body_off, footer_start, tag_off). footer_start=-1 if none."""
    t = find_tag(payload)
    hdr2_len = struct.unpack_from(">I", payload, t + 16)[0]
    if hdr2_len == 0 or hdr2_len > 0x100:
        hdr2_len = 0x24
    body_off = t + 0x14 + hdr2_len
    pk = payload.rfind(b"ProgramOK")
    if pk < 0:
        return body_off, -1, t
    fs = pk
    while fs > 0 and 0x20 <= payload[fs - 1] < 0x7F:
        fs -= 1
    return body_off, fs, t


def map_file(path: Path, window: int, step: int) -> list[dict]:
    data = path.read_bytes()
    body_off, footer_start, tag_off = body_footer(data)
    rows: list[dict] = []
    for off in range(0, max(0, len(data) - window + 1), step):
        chunk = data[off : off + window]
        h = entropy(chunk)
        zeros = chunk.count(0) / len(chunk)
        printable = sum(1 for b in chunk if 0x20 <= b < 0x7F) / len(chunk)
        zone = "prefix"
        if off >= body_off and (footer_start < 0 or off < footer_start):
            zone = "body"
        elif footer_start >= 0 and off >= footer_start:
            zone = "footer"
        elif off >= tag_off:
            zone = "header"
        rows.append(
            {
                "offset": off,
                "offset_hex": f"{off:#x}",
                "entropy": round(h, 4),
                "zeros": round(zeros, 4),
                "printable": round(printable, 4),
                "zone": zone,
            }
        )
    return rows


def sparkline(rows: list[dict], width: int = 80) -> str:
    if not rows:
        return ""
    # downsample to width
    n = len(rows)
    buckets = []
    for i in range(width):
        a = i * n // width
        b = max(a + 1, (i + 1) * n // width)
        avg = sum(r["entropy"] for r in rows[a:b]) / (b - a)
        buckets.append(avg)
    lo, hi = min(buckets), max(buckets)
    chars = " .:-=+*#%@"
    if hi <= lo:
        return chars[0] * width
    out = []
    for v in buckets:
        idx = int((v - lo) / (hi - lo) * (len(chars) - 1))
        out.append(chars[idx])
    return "".join(out)


def summarize(name: str, rows: list[dict], data_len: int, body_off: int, footer: int) -> None:
    body = [r for r in rows if r["zone"] == "body"]
    low = sorted(rows, key=lambda r: r["entropy"])[:8]
    print("=" * 72)
    print(f"{name}  len={data_len:#x}  body@{body_off:#x}  footer@{footer:#x}")
    print(f"  spark: {sparkline(rows)}")
    if body:
        bh = [r["entropy"] for r in body]
        print(
            f"  body windows: n={len(body)}  H_min={min(bh):.3f}  H_med={sorted(bh)[len(bh)//2]:.3f}  H_max={max(bh):.3f}"
        )
        valleys = [r for r in body if r["entropy"] < 6.5]
        print(f"  body valleys H<6.5: {len(valleys)}")
        for r in valleys[:12]:
            print(f"    {r['offset_hex']:>10}  H={r['entropy']:.3f}  print={r['printable']:.2f}  zero={r['zeros']:.3f}")
        # contiguous valley runs
        runs = []
        cur = None
        for r in body:
            if r["entropy"] < 6.5:
                if cur is None:
                    cur = [r["offset"], r["offset"], r["entropy"]]
                else:
                    cur[1] = r["offset"]
                    cur[2] = min(cur[2], r["entropy"])
            elif cur is not None:
                runs.append(cur)
                cur = None
        if cur:
            runs.append(cur)
        if runs:
            print("  valley runs (start..end, minH):")
            for a, b, mh in runs[:20]:
                print(f"    {a:#x}..{b:#x}  minH={mh:.3f}  span={b - a + 0:#x}")
    print("  lowest-H windows overall:")
    for r in low:
        print(
            f"    {r['offset_hex']:>10}  H={r['entropy']:.3f}  zone={r['zone']:6}  print={r['printable']:.2f}"
        )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--window", type=int, default=4096)
    ap.add_argument("--step", type=int, default=1024)
    args = ap.parse_args()
    files = args.files or sorted(CARVED.glob("*.payload.bin"))
    CARVED.mkdir(parents=True, exist_ok=True)

    for path in files:
        path = Path(path)
        if not path.is_file():
            # allow bare names under carved/
            alt = CARVED / path.name
            path = alt if alt.is_file() else path
        data = path.read_bytes()
        body_off, footer, _ = body_footer(data)
        rows = map_file(path, args.window, args.step)
        summarize(path.name, rows, len(data), body_off, footer)

        csv_path = CARVED / f"{path.stem}.entropy.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(
                f, fieldnames=["offset", "offset_hex", "entropy", "zeros", "printable", "zone"]
            )
            w.writeheader()
            w.writerows(rows)

        txt_path = CARVED / f"{path.stem}.entropy.txt"
        lines = [
            f"# {path.name} window={args.window} step={args.step}",
            f"# body@{body_off:#x} footer@{footer:#x}",
            f"# spark: {sparkline(rows, 100)}",
            "",
        ]
        for r in rows:
            bar = "#" * int(r["entropy"] * 5)  # 0..40-ish
            lines.append(
                f"{r['offset_hex']:>10}  {r['entropy']:5.3f}  {r['zone']:6}  {bar}"
            )
        txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"  wrote {csv_path.name}  {txt_path.name}")


if __name__ == "__main__":
    main()
