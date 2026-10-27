#!/usr/bin/env python3
"""Cross-compare Brother .djf bodies across corpus + local blobs."""
from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.djf_parse.analyze_format import (  # noqa: E402
    be32,
    entropy,
    find_tag,
    footer_region,
    split_djf,
)

SEARCH_ROOTS = [
    ROOT / "downloads" / "firmware" / "blobs",
    ROOT / "downloads" / "firmware" / "blobs" / "cdn_older",
    ROOT / "downloads" / "firmware" / "corpus",
]
OUT_CSV = ROOT / "downloads" / "firmware" / "corpus" / "compare.csv"
OUT_MD = ROOT / "downloads" / "firmware" / "corpus" / "COMPARE.md"


def iter_djf() -> list[Path]:
    files: list[Path] = []
    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        files.extend(root.rglob("*.djf"))
    # de-dupe by resolve
    seen = set()
    out = []
    for p in sorted(files, key=lambda x: str(x).lower()):
        r = p.resolve()
        if r in seen:
            continue
        seen.add(r)
        out.append(p)
    return out


def analyze(path: Path) -> dict | None:
    try:
        raw = path.read_bytes()
        header, payload = split_djf(raw)
    except Exception:
        return None
    try:
        tag_off = find_tag(payload)
    except ValueError:
        return {
            "path": str(path.relative_to(ROOT)),
            "tag": "?",
            "error": "no PROG/ROM2/PANL tag",
            "size": len(raw),
        }
    tag = payload[tag_off : tag_off + 4].decode("ascii", errors="replace")
    hdr2_len = be32(payload, tag_off + 16)
    body_off = tag_off + 0x14 + hdr2_len
    fstart, footer = footer_region(payload)
    body = payload[body_off:fstart] if fstart > body_off else payload[body_off:]
    hdr2 = payload[tag_off + 0x14 : tag_off + 0x14 + hdr2_len]
    pok = footer.find(b"ProgramOK") if footer else -1
    ident = footer[:pok].decode("ascii", errors="replace") if pok > 0 else ""
    bcd = footer[pok + 9 : pok + 14].hex() if pok >= 0 and len(footer) >= pok + 14 else ""
    return {
        "path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "file": path.name,
        "size": len(raw),
        "tag": tag,
        "tag_off": tag_off,
        "ident": ident,
        "bcd": bcd,
        "body_len": len(body),
        "entropy": round(entropy(body), 4) if body else 0.0,
        "magic12": body[:12].hex() if len(body) >= 12 else body.hex(),
        "hdr2_tail8": hdr2[-8:].hex() if len(hdr2) >= 8 else hdr2.hex(),
        "flags": f"{be32(payload, tag_off + 12):#010x}",
    }


def main() -> None:
    rows = []
    for p in iter_djf():
        r = analyze(p)
        if r:
            rows.append(r)
            print(
                f"{r.get('tag','?'):4s} H={r.get('entropy',0):.3f} "
                f"magic={r.get('magic12','')[:24]:24s} "
                f"id={r.get('ident','')[:14]:14s} {r.get('file')}"
            )

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    if rows:
        keys = list(rows[0].keys())
        with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(rows)

    # Group by magic12
    by_magic: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        if r.get("magic12"):
            by_magic[r["magic12"]].append(r)

    lines = [
        "# Brother DJF corpus compare",
        "",
        f"Scanned **{len(rows)}** `.djf` files under blobs/ + corpus/.",
        "",
        "## Body magic families",
        "",
    ]
    for magic, group in sorted(by_magic.items(), key=lambda kv: -len(kv[1])):
        ents = [g["entropy"] for g in group if isinstance(g.get("entropy"), float)]
        tags = sorted({g["tag"] for g in group})
        idents = sorted({g["ident"] for g in group if g.get("ident")})
        lines.append(f"### `{magic}`  ({len(group)} files, tags={tags})")
        lines.append("")
        if ents:
            lines.append(
                f"Entropy min/med/max: **{min(ents):.3f}** / "
                f"**{sorted(ents)[len(ents)//2]:.3f}** / **{max(ents):.3f}**"
            )
            lines.append("")
        if idents:
            lines.append("Identities: " + ", ".join(f"`{i}`" for i in idents[:20]))
            lines.append("")
        lines.append("| File | Tag | Body | H | hdr2 tail8 |")
        lines.append("| --- | --- | ---: | ---: | --- |")
        for g in sorted(group, key=lambda x: x.get("file", "")):
            lines.append(
                f"| `{g['file']}` | {g['tag']} | {g.get('body_len',0)} | "
                f"{g.get('entropy',0):.3f} | `{g.get('hdr2_tail8','')}` |"
            )
        lines.append("")

    # Low-entropy outliers (possible older/plaintext-ish)
    low = [r for r in rows if isinstance(r.get("entropy"), float) and r["entropy"] < 7.0 and r.get("body_len", 0) > 1000]
    lines.append("## Lower-entropy outliers (body >1 KiB, H<7.0)")
    lines.append("")
    if not low:
        lines.append("None in this corpus.")
    else:
        lines.append("| File | Tag | H | magic |")
        lines.append("| --- | --- | ---: | --- |")
        for g in sorted(low, key=lambda x: x["entropy"]):
            lines.append(
                f"| `{g['file']}` | {g['tag']} | {g['entropy']:.3f} | `{g.get('magic12','')}` |"
            )
    lines.append("")
    lines.append(f"CSV: [`compare.csv`](compare.csv)")
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {OUT_CSV}")
    print(f"wrote {OUT_MD}")


if __name__ == "__main__":
    main()
