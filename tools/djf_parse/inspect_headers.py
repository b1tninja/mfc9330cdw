#!/usr/bin/env python3
"""Hex/struct dump of Brother DJF payloads (post-PJL DATA=)."""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

BLOBS = Path(__file__).resolve().parents[2] / "downloads" / "firmware" / "blobs"
CARVED = BLOBS / "binwalk" / "carved"


def load_payload(djf: Path) -> bytes:
    data = djf.read_bytes()
    i = data.find(b"DATA=")
    if i < 0:
        raise ValueError(f"no DATA= in {djf}")
    return data[i + 5 :]


def try_zlib_at(data: bytes, off: int, label: str) -> None:
    for wbits in (15, -15, 31, 47):
        try:
            out = zlib.decompress(data[off:], wbits)
            print(f"  ZLIB HIT {label} off={off:#x} wbits={wbits} -> {len(out)} bytes")
            print(f"    out head: {out[:64]!r}")
            return
        except zlib.error:
            pass


def dump_one(name: str, payload: bytes) -> None:
    print("=" * 72)
    print(f"{name}  len={len(payload)}")
    # Identity: NUL-terminated ASCII at start, padded?
    nul = payload.find(b"\x00")
    ident = payload[:nul] if nul > 0 else payload[:32]
    print(f"ident={ident!r}  nul_at={nul}")

    # Dump first 0x40 as dwords (BE and LE)
    print("first 0x40 hex:")
    for i in range(0, min(0x40, len(payload)), 16):
        chunk = payload[i : i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}: {hexs:<48} {asc}")

    # Look for type tags PROG/ROM2/PANL
    for tag in (b"PROG", b"ROM2", b"PANL", b"FIRM", b"IFAX"):
        off = payload.find(tag)
        if off >= 0:
            region = payload[off : off + 32]
            print(f"tag {tag!r} @ {off:#x}: {region.hex()}")
            # interpret following 4 dwords LE/BE
            if off + 20 <= len(payload):
                after = payload[off + 4 : off + 20]
                le = struct.unpack("<IIII", after) if len(after) == 16 else ()
                be = struct.unpack(">IIII", after) if len(after) == 16 else ()
                print(f"  after LE dwords: {[hex(x) for x in le]}")
                print(f"  after BE dwords: {[hex(x) for x in be]}")

    # Common layout hypothesis: ident[16] + unk[8] + tag[4] + fields...
    if len(payload) >= 0x30:
        # Compare PROGRAMLENG from PJL vs body
        print(f"payload len hex = {len(payload):#x}")

    # Scan for zlib magic 78 01 / 78 9c / 78 da
    for magic in (b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x1f\x8b"):
        start = 0
        hits = 0
        while hits < 5:
            j = payload.find(magic, start)
            if j < 0:
                break
            try_zlib_at(payload, j, magic.hex())
            start = j + 1
            hits += 1

    # Try decompress from after known header sizes
    for off in (0x20, 0x24, 0x28, 0x2c, 0x30, 0x40, 0x100, 0x200):
        if off < len(payload):
            try_zlib_at(payload, off, f"fixed-{off:#x}")


def main() -> None:
    for djf in sorted(BLOBS.glob("*.djf")):
        payload = load_payload(djf)
        # also write carved if missing
        CARVED.mkdir(parents=True, exist_ok=True)
        (CARVED / f"{djf.stem}.payload.bin").write_bytes(payload)
        dump_one(djf.name, payload)


if __name__ == "__main__":
    main()
