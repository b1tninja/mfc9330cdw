"""Sweep firm versions/categories looking for VERSIONCHECK=1 + PATH."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.firmverup.client import FirmverupClient
from tools.firmverup.protocol import (
    FIRM_CATEGORIES,
    MODEL_LAN,
    MODEL_USB,
    FileUpdateParams,
    FirmSlot,
)


def main() -> None:
    client = FirmverupClient(timeout=45)
    versions = ["", "0", "1", "A", "N", "P", "Q", "Z", "ZA", "ZB", "ZC", "1.00", "1.07", "1.10"]
    models = [MODEL_LAN, MODEL_USB, "MFC-9330CDW", "Brother MFC-9330CDW"]
    rows = []
    for model in models:
        for ver in versions:
            p = FileUpdateParams(
                model_name=model,
                firm_category="MAIN",
                firms=[FirmSlot("MAIN", ver)],
                need_response=1,
                os_version=10,
            )
            r = client.file_update(p)
            s = r.get("summary") or {}
            vc = s.get("VERSIONCHECK")
            interesting = vc != "2" or s.get("PATH") or s.get("LATESTVERSION")
            baseline = ver in ("", "P", "ZA", "ZC") and model == MODEL_LAN
            if interesting or baseline:
                rows.append(
                    {
                        "model": model,
                        "ver": ver,
                        "VERSIONCHECK": vc,
                        "PATH": s.get("PATH"),
                        "LATESTVERSION": s.get("LATESTVERSION"),
                        "FIRMID": s.get("FIRMID"),
                        "MEMORYVERSION": s.get("MEMORYVERSION"),
                        "bytes": r["byte_length"],
                    }
                )

    print("=== version sweep (non-2 / baselines) ===")
    print(json.dumps(rows, indent=2))

    print("\n=== categories @ version P ===")
    cat_rows = []
    for cat in FIRM_CATEGORIES:
        for fid in sorted({cat, "MAIN", "FIRM"}):
            p = FileUpdateParams(
                model_name=MODEL_LAN,
                firm_category=cat,
                firms=[FirmSlot(fid, "P")],
                need_response=1,
            )
            r = client.file_update(p)
            s = r.get("summary") or {}
            cat_rows.append(
                {
                    "cat": cat,
                    "id": fid,
                    "vc": s.get("VERSIONCHECK"),
                    "path": s.get("PATH"),
                    "latest": s.get("LATESTVERSION"),
                }
            )
    print(json.dumps(cat_rows, indent=2))


if __name__ == "__main__":
    main()
