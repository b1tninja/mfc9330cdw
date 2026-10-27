"""Read-only LAN probe: CIFS/SMB listen, PJL FS/DINQUIRE/ECHO, mDNS.

Usage:
  python tools/net_surface_smb_pjl.py [host]
Default host: 192.168.1.71

Does not write to the printer (no PJL FSINIT/FSDOWNLOAD/SET, no SMB writes,
no SNMP SET).
"""

from __future__ import annotations

import argparse
import select
import socket
import struct
import sys
import time
from typing import Any

DEFAULT_HOST = "192.168.1.71"
UEL = b"\x1b%-12345X"


def tcp_open(host: str, port: int, timeout: float = 2.0) -> tuple[bool, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True, "open"
    except OSError as e:
        return False, str(e)
    finally:
        s.close()


def smb_probe(host: str) -> None:
    print("=== CIFS/SMB ===")
    open_445, e445 = tcp_open(host, 445)
    open_139, e139 = tcp_open(host, 139)
    print(f"  TCP 445: {'open' if open_445 else 'closed/filtered'} ({e445})")
    print(f"  TCP 139: {'open' if open_139 else 'closed/filtered'} ({e139})")
    if not open_445 and not open_139:
        print("  No SMB listener — anonymous/guest share enum not possible.")
        print(
            "  CFG may still show 'CIFS Enabled' (client for Store Print Log /"
            " logtonet); NetBIOS <20> via UDP 137 does not imply TCP file server."
        )
        return
    print("  Listener present — use smbclient/smbprotocol for guest enum (not implemented here).")


def pjl_exchange(host: str, cmd: str, idle_rounds: int = 8) -> bytes:
    """Send one PJL command; drain until idle. Response ends with form-feed."""
    line = cmd if cmd.startswith("@PJL") else f"@PJL {cmd}"
    payload = UEL + b"@PJL\r\n" + line.encode("ascii", "replace") + b"\r\n" + UEL
    sock = socket.create_connection((host, 9100), timeout=5)
    try:
        sock.sendall(payload)
        time.sleep(0.35)
        chunks: list[bytes] = []
        idle = 0
        while idle < idle_rounds:
            sock.settimeout(0.35)
            try:
                c = sock.recv(8192)
            except socket.timeout:
                idle += 1
                continue
            if not c:
                break
            chunks.append(c)
            idle = 0
            if b"\x0c" in c and len(b"".join(chunks)) > 8:
                # got form-feed; brief extra drain
                idle = max(idle, idle_rounds - 2)
        return b"".join(chunks)
    finally:
        sock.close()


def _preview(data: bytes, limit: int = 900) -> str:
    text = data.decode("latin-1", errors="replace").replace("\x0c", "\\f")
    if len(text) > limit:
        return text[:limit] + f"\n… ({len(text)} chars)"
    return text


def pjl_probe(host: str) -> None:
    print("=== PJL (TCP 9100, read-only) ===")
    probes = [
        "INFO STATUS",
        "ECHO HELLO-RE",
        "DINQUIRE PASSWORD",
        "DINQUIRE TIMEDATE",
        "DINQUIRE COPIES",
        "INFO FILESYS",
        "INFO MEMORY",
        "INFO PAGECOUNT",
        "INFO PRODINFO",
        "INFO DIRTYDISK",
        'FSQUERY NAME="0:\\"',
        'FSQUERY NAME="1:\\"',
        'FSQUERY NAME="2:\\"',
        'FSDIRLIST NAME="0:\\" ENTRY=1 COUNT=20',
        'FSDIRLIST NAME="1:\\" ENTRY=1 COUNT=20',
        r'FSQUERY NAME="0:\..\passwords"',
    ]
    for cmd in probes:
        print(f"--- {cmd} ---")
        try:
            resp = pjl_exchange(host, cmd)
        except OSError as e:
            print(f"  error: {e}")
            continue
        print("  (empty / no reply)" if not resp else _preview(resp))
        time.sleep(0.25)


# --- mDNS --------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    out = b""
    for lab in name.rstrip(".").split("."):
        b = lab.encode("utf-8")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _mdns_query(name: str, qtype: int = 12) -> bytes:
    return (
        struct.pack(">HHHHHH", 0xB00B, 0x0000, 1, 0, 0, 0)
        + _encode_name(name)
        + struct.pack(">HH", qtype, 1)
    )


def _parse_name(data: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = off
    seen: set[int] = set()
    while off < len(data):
        if data[off] == 0:
            if not jumped:
                end = off + 1
            return ".".join(labels), end
        if data[off] & 0xC0 == 0xC0:
            ptr = struct.unpack_from("!H", data, off)[0] & 0x3FFF
            if not jumped:
                end = off + 2
            if ptr in seen:
                return ".".join(labels), end
            seen.add(ptr)
            jumped = True
            off = ptr
            continue
        ln = data[off]
        off += 1
        labels.append(data[off : off + ln].decode("utf-8", "replace"))
        off += ln
    return ".".join(labels), end


def _parse_mdns(data: bytes) -> list[tuple[str, str, int, Any, int]]:
    if len(data) < 12:
        return []
    _tid, _flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", data, 0)
    off = 12
    for _ in range(qd):
        _, off = _parse_name(data, off)
        off += 4
    recs: list[tuple[str, str, int, Any, int]] = []
    for section, count in (("AN", an), ("NS", ns), ("AR", ar)):
        for _ in range(count):
            name, off = _parse_name(data, off)
            if off + 10 > len(data):
                break
            typ, _cls, ttl, rdlen = struct.unpack_from(">HHIH", data, off)
            off += 10
            rdata = data[off : off + rdlen]
            rstart = off
            off += rdlen
            pretty: Any = rdata
            if typ == 12:  # PTR
                pretty, _ = _parse_name(data, rstart)
            elif typ == 1 and rdlen == 4:
                pretty = socket.inet_ntoa(rdata)
            elif typ == 16:  # TXT
                parts: list[str] = []
                i = 0
                while i < len(rdata):
                    ln = rdata[i]
                    i += 1
                    parts.append(rdata[i : i + ln].decode("utf-8", "replace"))
                    i += ln
                pretty = parts
            elif typ == 33 and rdlen >= 6:  # SRV
                prio, wgt, port = struct.unpack_from(">HHH", rdata, 0)
                target, _ = _parse_name(data, rstart + 6)
                pretty = f"{prio}/{wgt} port={port} -> {target}"
            elif typ == 28 and rdlen == 16:  # AAAA
                pretty = socket.inet_ntop(socket.AF_INET6, rdata)
            recs.append((section, name, typ, pretty, ttl))
    return recs


def mdns_probe(host: str, timeout: float = 4.0) -> None:
    print("=== mDNS / Bonjour ===")
    queries = [
        ("_services._dns-sd._udp.local", 12),
        ("_ipp._tcp.local", 12),
        ("_ipps._tcp.local", 12),
        ("_printer._tcp.local", 12),
        ("_pdl-datastream._tcp.local", 12),
        ("_http._tcp.local", 12),
        ("_scanner._tcp.local", 12),
        ("_uscan._tcp.local", 12),
        ("_smb._tcp.local", 12),
        ("_device-info._tcp.local", 12),
        ("Brother MFC-9330CDW._ipp._tcp.local", 33),
        ("Brother MFC-9330CDW._ipp._tcp.local", 16),
        ("Brother MFC-9330CDW._printer._tcp.local", 33),
        ("Brother MFC-9330CDW._pdl-datastream._tcp.local", 33),
        ("Brother MFC-9330CDW._http._tcp.local", 33),
        ("Brother MFC-9330CDW._scanner._tcp.local", 33),
        ("BRN3C2AF435905F.local", 1),
    ]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 0))
    for name, qtype in queries:
        pkt = _mdns_query(name, qtype)
        sock.sendto(pkt, (host, 5353))
        sock.sendto(pkt, ("224.0.0.251", 5353))

    deadline = time.time() + timeout
    seen: set[str] = set()
    service_types: set[str] = set()
    while time.time() < deadline:
        r, _, _ = select.select([sock], [], [], 0.35)
        if not r:
            continue
        data, addr = sock.recvfrom(9000)
        if addr[0] != host:
            continue
        for section, name, typ, pretty, _ttl in _parse_mdns(data):
            key = f"{section}|{typ}|{name}|{pretty}"
            if key in seen:
                continue
            seen.add(key)
            if typ == 12 and isinstance(pretty, str) and pretty.startswith("_"):
                service_types.add(pretty.split(".")[0] if pretty else name)
            if typ == 12 and name == "_services._dns-sd._udp.local":
                service_types.add(str(pretty))
            print(f"  [{section}] type={typ} {name} -> {pretty}")
    if service_types:
        print("  service-type set:", ", ".join(sorted(service_types)))
    if not seen:
        print("  (no replies from printer — check firewall / mDNS)")
    sock.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST)
    ap.add_argument("--skip-smb", action="store_true")
    ap.add_argument("--skip-pjl", action="store_true")
    ap.add_argument("--skip-mdns", action="store_true")
    args = ap.parse_args()
    print(f"Target {args.host} (read-only)\n")
    if not args.skip_smb:
        smb_probe(args.host)
        print()
    if not args.skip_pjl:
        pjl_probe(args.host)
        print()
    if not args.skip_mdns:
        mdns_probe(args.host)
    return 0


if __name__ == "__main__":
    sys.exit(main())
