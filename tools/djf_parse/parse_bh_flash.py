#!/usr/bin/env python3
"""Parse Brother plaintext MAIN 'Flash Data' bodies (BH11 PMU / BH13 Upd)."""
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


def parse_body(raw: bytes) -> bytes:
    i = raw.find(b"DATA=")
    if i < 0:
        raise ValueError("no DATA=")
    pay = raw[i + 5 :]
    tag = next(
        o
        for o in (0x18, 0x0C, 0x24)
        if pay[o : o + 4] == b"MAIN"
    )
    hdr2_len = struct.unpack_from(">I", pay, tag + 16)[0]
    return pay[tag + 0x14 + hdr2_len :]


def family(body: bytes) -> str:
    if b"BH13 Flash Data" in body[:0x100]:
        return "BH13"
    if b"BH11" in body[:0x100] and b"FileType : PMU" in body[:0x100]:
        return "BH11-PMU"
    if b"Flash Data" in body[:0x100]:
        return "FlashData-other"
    return "unknown"


def parse_text_fields(body: bytes) -> dict[str, object]:
    # BH13 uses UpdHeaderEnd; BH11 truncates mid-table after PmuProgramFileSize
    end = body.find(b"UpdHeaderEnd")
    if end < 0:
        end = body.find(b"header")
        if end < 0:
            end = min(len(body), 0x200)
    text = body[:end].decode("latin-1", "replace")
    out: dict[str, object] = {"_family": family(body), "_text_len": end}
    for m in re.finditer(
        r"([A-Za-z0-9_]+) = ([0-9a-fA-F]{8})([0-9a-fA-F]{8})", text
    ):
        name, a, b = m.group(1), m.group(2), m.group(3)
        va, vb = int(a, 16), int(b, 16)
        out[name] = {"value": va, "inv": vb, "not_ok": (va ^ 0xFFFFFFFF) == vb}
    for m in re.finditer(
        r"(FileType\s*:\s*\S+|Program\s*:\s*\S+|PmuProgramName\s*=\s*\S+|UpdProgramName\s*=\s*\S+|UpdPrgDlOption\s*=\s*\S+)",
        text,
    ):
        out.setdefault("_meta", []).append(m.group(1))
    return out


def parse_labels(body: bytes) -> dict[str, int | str]:
    h = body.find(b"header")
    if h < 0:
        return {}
    tab = body[h:]
    out: dict[str, int | str] = {}
    if tab.startswith(b"header"):
        out["_header_name"] = tab[8:16].split(b"\0", 1)[0].decode("latin-1", "replace")
    for lab in LABELS:
        o = tab.find(lab.encode())
        if o < 0 or o + 24 > len(tab):
            continue
        out[lab] = struct.unpack_from(">I", tab, o + 20)[0]
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("djf", type=Path)
    args = ap.parse_args()
    body = parse_body(args.djf.read_bytes())
    fields = parse_text_fields(body)
    labels = parse_labels(body)
    print(args.djf.name, "family=", fields["_family"], "body=", len(body))
    for k, v in fields.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict):
            print(f"  {k}: {v['value']:#010x} NOT-ok={v['not_ok']}")
    for k, v in labels.items():
        print(f"  {k}: {v:#010x}" if isinstance(v, int) else f"  {k}: {v}")


if __name__ == "__main__":
    main()
