#!/usr/bin/env python3
"""Parse MAIN-tag 'BH13 Flash Data' Upd* text + labeled binary table.

Used by inkjet-era plaintext MAIN images (e.g. LZ4228_P / MFC-J451USA).
"""
from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path


LABELS = [
    "PrgSize",
    "PrgDivSize",
    "Compress",
    "RamExpansion",
    "Rom0Size",
    "Rom1FlashAdr",
    "ROstart",
    "ROsize",
    "RWstart",
    "RWsize",
    "ZIstart",
    "ZIsize",
    "PrgInfoSize",
    "HTotalRomSize",
    "PrgStart",
]


def parse_djf_body(raw: bytes) -> bytes:
    i = raw.find(b"DATA=")
    if i < 0:
        raise ValueError("no DATA=")
    pay = raw[i + 5 :]
    tag = next(
        o
        for o in (0x18, 0x0C, 0x24)
        if pay[o : o + 4] in (b"PROG", b"ROM2", b"PANL", b"MAIN")
    )
    if pay[tag : tag + 4] != b"MAIN":
        raise ValueError(f"expected MAIN, got {pay[tag:tag+4]!r}")
    hdr2_len = struct.unpack_from(">I", pay, tag + 16)[0]
    return pay[tag + 0x14 + hdr2_len :]


def parse_upd_text(body: bytes) -> dict[str, object]:
    end = body.find(b"UpdHeaderEnd")
    if end < 0:
        raise ValueError("no UpdHeaderEnd")
    text = body[: end + len(b"UpdHeaderEnd")].decode("latin-1", "replace")
    fields: dict[str, object] = {"_raw_text": text}
    for m in re.finditer(
        r"([A-Za-z0-9_]+) = ([0-9a-fA-F]{8})([0-9a-fA-F]{8})", text
    ):
        name, a, b = m.group(1), m.group(2), m.group(3)
        va, vb = int(a, 16), int(b, 16)
        fields[name] = {
            "value": va,
            "inv": vb,
            "not_ok": (va ^ 0xFFFFFFFF) == vb,
        }
    for m in re.finditer(r"(Program\s*:\s*\S+|UpdProgramName\s*=\s*\S+|UpdPrgDlOption\s*=\s*\S+)", text):
        fields.setdefault("_meta_lines", []).append(m.group(1))
    return fields


def parse_label_table(body: bytes) -> dict[str, int]:
    end = body.find(b"UpdHeaderEnd")
    if end < 0:
        raise ValueError("no UpdHeaderEnd")
    tab = body[end + len(b"UpdHeaderEnd") :]
    h = tab.find(b"header")
    if h < 0:
        raise ValueError("no header label")
    tab = tab[h:]
    out: dict[str, int] = {}
    # header slot embeds program name
    if tab.startswith(b"header"):
        name = tab[8:16].split(b"\0", 1)[0].decode("latin-1", "replace")
        out["_header_name"] = name  # type: ignore[assignment]
    for lab in LABELS:
        o = tab.find(lab.encode())
        if o < 0:
            continue
        # values sit at +20 from label start in observed layout
        if o + 24 <= len(tab):
            out[lab] = struct.unpack_from(">I", tab, o + 20)[0]
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("djf", type=Path)
    ap.add_argument("--extract-dir", type=Path, help="write upd_header.txt + summary")
    args = ap.parse_args()
    raw = args.djf.read_bytes()
    body = parse_djf_body(raw)
    upd = parse_upd_text(body)
    labels = parse_label_table(body)
    print(args.djf.name, "body", len(body))
    for k, v in upd.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict):
            print(f"  {k}: {v['value']:#010x}  NOT-ok={v['not_ok']}")
    print("  labels:")
    for k, v in labels.items():
        if isinstance(v, int):
            print(f"    {k}: {v:#010x} ({v})")
        else:
            print(f"    {k}: {v}")
    if args.extract_dir:
        args.extract_dir.mkdir(parents=True, exist_ok=True)
        end = body.find(b"UpdHeaderEnd") + len(b"UpdHeaderEnd")
        (args.extract_dir / "upd_header.txt").write_bytes(body[:end])
        lines = [f"# {args.djf.name}", f"body_len={len(body)}", ""]
        for k, v in upd.items():
            if k.startswith("_"):
                continue
            lines.append(f"{k}={v['value']:#010x}")
        lines.append("")
        for k, v in labels.items():
            lines.append(f"{k}={v:#010x}" if isinstance(v, int) else f"{k}={v}")
        (args.extract_dir / "upd_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("wrote", args.extract_dir)


if __name__ == "__main__":
    main()
