"""One-shot: shared body prefixes across letter revisions."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def body_of(path: Path) -> bytes:
    raw = path.read_bytes()
    p = raw[raw.find(b"DATA=") + 5 :]
    tag_off = next(
        off
        for off in (0x18, 0x0C, 0x10, 0x14, 0x1C)
        if p[off : off + 4] in (b"PROG", b"ROM2", b"PANL", b"FIRM")
    )
    hdr2_len = struct.unpack_from(">I", p, tag_off + 16)[0]
    body_off = tag_off + 0x14 + hdr2_len
    # strip trailing ProgramOK footer if present
    idx = p.rfind(b"ProgramOK")
    end = idx if idx > body_off else len(p)
    return p[body_off:end]


def shared_prefix(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


pairs = [
    ("downloads/firmware/blobs/cdn_older/LZ2751_B.djf", "downloads/firmware/blobs/cdn_older/LZ2751_C.djf"),
    ("downloads/firmware/blobs/cdn_older/LZ2751_B.djf", "downloads/firmware/corpus/MFC-9320CW/MAIN_LZ2751_L.djf"),
    ("downloads/firmware/blobs/cdn_older/LZ4266_D.djf", "downloads/firmware/blobs/LZ4266_ZC_1.djf"),
    ("downloads/firmware/blobs/cdn_older/LZ4266_S.djf", "downloads/firmware/blobs/LZ4266_ZC_1.djf"),
    ("downloads/firmware/blobs/cdn_older/LZ3632_E.djf", "downloads/firmware/corpus/MFC-7860DW/MAIN_LZ3632_M.djf"),
    ("downloads/firmware/blobs/cdn_older/LZ3515_F.djf", "downloads/firmware/corpus/MFC-7460DN/MAIN_LZ3515_M.djf"),
]

for pa, pb in pairs:
    ba = body_of(ROOT / pa)
    bb = body_of(ROOT / pb)
    sp = shared_prefix(ba, bb)
    ha = hashlib.sha256(ba).hexdigest()[:12]
    hb = hashlib.sha256(bb).hexdigest()[:12]
    print(f"{Path(pa).name} vs {Path(pb).name}")
    print(f"  sizes {len(ba)}/{len(bb)} shared_prefix={sp} sha12={ha}/{hb}")
