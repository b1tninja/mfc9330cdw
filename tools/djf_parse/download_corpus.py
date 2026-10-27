#!/usr/bin/env python3
"""Download MAIN (and optional slots) for related Brother models for DJF compare.

Uses local firmverup client. Blobs stay under downloads/firmware/corpus/ — do not
commit them.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.firmverup.client import FirmverupClient
from tools.firmverup.protocol import FileUpdateParams, FirmSlot

# (NAME, SPEC, categories, seed VERSION for MAIN)
# Seed versions force VERSIONCHECK=0 when possible.
TARGETS: list[tuple[str, str, tuple[str, ...], str]] = [
    # Same color-laser generation as 9330 (MAIN identity often MFC-9130USA)
    ("MFC-9330CDW", "0401", ("MAIN", "SUB1", "SUB2", "IFAX"), "B0000000000"),
    ("MFC-9340CDW", "0502", ("MAIN", "SUB1", "SUB2", "IFAX"), "B0000000000"),
    ("MFC-9130CW", "0201", ("MAIN", "SUB1", "SUB2", "IFAX"), "B0000000000"),
    ("MFC-9140CDN", "0001", ("MAIN", "SUB1", "SUB2", "IFAX"), "B0000000000"),
    ("HL-3140CW", "0001", ("MAIN", "SUB1"), "B0000000000"),
    ("HL-3150CDW", "0001", ("MAIN", "SUB1"), "B0000000000"),
    ("HL-3170CDW", "0001", ("MAIN", "PCLPS", "SUB1"), "B0000000000"),
    # Nearby / older color
    ("MFC-9320CW", "0201", ("MAIN", "PCLPS", "IFAX"), "B0000000000"),
    ("MFC-9970CDW", "0001", ("MAIN", "PCLPS", "SUB2"), "B0000000000"),
    ("MFC-L8600CDW", "0001", ("MAIN", "SUB1", "SUB2", "IFAX"), "B0000000000"),
    # Older mono (sometimes clearer / different packaging)
    ("MFC-7860DW", "2248", ("MAIN", "PCLPS", "SUB1", "IFAX"), "B0000000000"),
    ("MFC-7460DN", "0001", ("MAIN", "SUB1", "IFAX"), "B0000000000"),
    ("DCP-7065DN", "3004", ("MAIN", "SUB1"), "B0000000000"),
    ("HL-5470DW", "0101", ("MAIN", "SUB1"), "B0000000000"),
]

# Alternate SPECs to try if primary returns VC=2
ALT_SPECS = ("0001", "0101", "0201", "0401", "0502", "2248", "3004", "0024")

OUT = ROOT / "downloads" / "firmware" / "corpus"
MANIFEST = OUT / "manifest.json"


def filename_from_path(path_url: str) -> str:
    return Path(urlparse(path_url).path).name or "firmware.djf"


def try_file_update(client: FirmverupClient, name: str, spec: str, cat: str, ver: str) -> dict:
    p = FileUpdateParams(
        model_name=name,
        spec=spec,
        firm_category=cat,
        firms=[FirmSlot(cat, ver)],
        need_response=1,
        driver="EWS",
    )
    r = client.file_update(p)
    return r.get("summary") or {}


def resolve_slot(
    client: FirmverupClient, name: str, spec: str, cat: str, seed: str
) -> tuple[str, dict]:
    """Return (working_spec, summary) or ("", {})."""
    for sp in (spec, *[s for s in ALT_SPECS if s != spec]):
        for ver in (seed, "B0000000000", "0", "1.00", "A0000000000"):
            s = try_file_update(client, name, sp, cat, ver)
            vc = s.get("VERSIONCHECK")
            if vc in ("0", "1") and (s.get("PATH") or vc == "1"):
                return sp, s
            if s.get("PATH"):
                return sp, s
    return "", {}


def main() -> None:
    client = FirmverupClient(timeout=60)
    OUT.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []

    for name, spec, cats, seed in TARGETS:
        model_dir = OUT / name.replace(" ", "_")
        model_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n=== {name} (prefer SPEC {spec}) ===", flush=True)
        for cat in cats:
            sp, s = resolve_slot(client, name, spec, cat, seed)
            row = {
                "name": name,
                "spec_tried": spec,
                "spec_used": sp or None,
                "category": cat,
                "VERSIONCHECK": s.get("VERSIONCHECK"),
                "LATESTVERSION": s.get("LATESTVERSION"),
                "PATH": s.get("PATH"),
                "file": None,
                "bytes": None,
            }
            path = s.get("PATH")
            if path:
                fname = filename_from_path(path)
                dest = model_dir / f"{cat}_{fname}"
                if dest.exists() and dest.stat().st_size > 0:
                    print(f"  {cat}: skip existing {dest.name}", flush=True)
                else:
                    print(f"  {cat}: GET {fname} …", flush=True)
                    try:
                        client.download_path(path, dest)
                    except Exception as e:
                        print(f"  {cat}: download failed: {e}", flush=True)
                        row["error"] = str(e)
                        manifest.append(row)
                        continue
                row["file"] = str(dest.relative_to(ROOT))
                row["bytes"] = dest.stat().st_size
                print(
                    f"  {cat}: VC={s.get('VERSIONCHECK')} ver={s.get('LATESTVERSION')} "
                    f"-> {dest.name} ({row['bytes']})",
                    flush=True,
                )
            else:
                print(f"  {cat}: no PATH (VC={s.get('VERSIONCHECK')})", flush=True)
            manifest.append(row)

    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    ok = sum(1 for m in manifest if m.get("file"))
    print(f"\nDone: {ok}/{len(manifest)} blobs → {OUT}\nmanifest → {MANIFEST}")


if __name__ == "__main__":
    main()
