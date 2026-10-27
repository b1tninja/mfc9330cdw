"""Broader read-only SNMP surface on a Brother printer (snmpy raw UDP)."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(r"d:\code\snmpy")))

from ber.object import Integer, OctetString
from snmp.datagram import SNMPDatagram
from snmp.enums import SNMPVersion
from snmp.pdus import GetRequest, GetNextRequest

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.71"
COMM = "public"

GETS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "hrDeviceDescr": "1.3.6.1.2.1.25.3.2.1.3.1",
    "prtGeneralSerialNumber": "1.3.6.1.2.1.43.5.1.1.17.1",
    "prtMarkerSuppliesDescription": "1.3.6.1.2.1.43.11.1.1.6.1.1",
    "pwd_set": "1.3.6.1.4.1.2435.2.4.3.2435.5.100.1.1.0",
    "challenge": "1.3.6.1.4.1.2435.2.4.3.2435.5.100.10.1.0",
}

WALKS = {
    "mib2_system": "1.3.6.1.2.1.1",
    "host_resources": "1.3.6.1.2.1.25.3.2.1.3",
    "printer_mib_serial": "1.3.6.1.2.1.43.5.1.1.17",
    "printer_supplies_desc": "1.3.6.1.2.1.43.11.1.1.6",
    "printer_supplies_level": "1.3.6.1.2.1.43.11.1.1.9",
    "printer_supplies_max": "1.3.6.1.2.1.43.11.1.1.8",
    "brother_1284": "1.3.6.1.4.1.2435.2.3.9.1.1.7",
    "brother_firm": "1.3.6.1.4.1.2435.2.4.3.99.3.1.6.1.2",
    "brother_trays": "1.3.6.1.4.1.2435.2.4.3.99.3.1.2.1.2",
    "brother_nc8500": "1.3.6.1.4.1.2435.2.4.3.1240.1",
    "brother_admin100": "1.3.6.1.4.1.2435.2.4.3.2435.5.100",
    "brother_ldap_faxattr": "1.3.6.1.4.1.2435.2.4.3.2435.5.19.12.1.11",
}


def encode(pdu, version=SNMPVersion.v2c) -> bytes:
    dg = SNMPDatagram(
        version=Integer.from_int(version.value),
        community=OctetString(COMM.encode()).get_object(),
        pdu=pdu,
    )
    return bytes(dg)


def decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    arcs = [first // 40, first % 40]
    n = 0
    for b in raw[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(n)
            n = 0
    return ".".join(map(str, arcs))


def fmt(val) -> str:
    inner = getattr(val, "value", val)
    if isinstance(inner, (bytes, bytearray)):
        b = bytes(inner)
        if all(32 <= c < 127 or c in (9, 10, 13) for c in b):
            return b.decode("latin-1")
        return f"<{len(b)}B hex={b.hex()}>"
    return str(val)[:200]


def get(oid: str, timeout=2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(encode(GetRequest.from_oid(oid)), (HOST, 161))
        data, _ = sock.recvfrom(65535)
        resp = SNMPDatagram.decode(data)
        for name, value in resp.pdu:
            oid_out = decode_oid(bytes(name)) if isinstance(name, (bytes, bytearray)) else str(name)
            return oid_out, fmt(value), None
        return None, None, "empty"
    except Exception as exc:  # noqa: BLE001
        return None, None, f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()


def walk(start: str, limit=30):
    out = []
    cur = start
    stem = start
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        for _ in range(limit):
            sock.sendto(encode(GetNextRequest.from_oid(cur)), (HOST, 161))
            data, _ = sock.recvfrom(65535)
            resp = SNMPDatagram.decode(data)
            binds = list(resp.pdu)
            if not binds:
                break
            name, value = binds[0]
            oid_out = decode_oid(bytes(name)) if isinstance(name, (bytes, bytearray)) else str(name)
            if not oid_out.startswith(stem):
                break
            out.append((oid_out, fmt(value)))
            if oid_out == cur:
                break
            cur = oid_out
    except Exception:
        pass
    finally:
        sock.close()
    return out


def main():
    print(f"=== SNMP GET {HOST} community={COMM} ===")
    for name, oid in GETS.items():
        o, v, e = get(oid)
        print(f"{name}: {e or v}")

    for name, oid in WALKS.items():
        rows = walk(oid)
        print(f"\n--- walk {name} ({oid}) n={len(rows)} ---")
        for o, v in rows[:25]:
            print(f"  {o} = {v}")


if __name__ == "__main__":
    main()
