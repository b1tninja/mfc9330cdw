"""Debug: encode a GetRequest with snmpy and send raw UDP."""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(r"d:\code\snmpy")))

from ber.object import Integer, OctetString
from snmp.datagram import SNMPDatagram
from snmp.enums import SNMPVersion
from snmp.pdus import GetRequest

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.71"
OID = sys.argv[2] if len(sys.argv) > 2 else "1.3.6.1.2.1.1.1.0"
COMM = sys.argv[3] if len(sys.argv) > 3 else "public"


def encode_get(oid: str, community: str, version: SNMPVersion) -> bytes:
    pdu = GetRequest.from_oid(oid)
    dg = SNMPDatagram(
        version=Integer.from_int(version.value),
        community=OctetString(community.encode()).get_object(),
        pdu=pdu,
    )
    # SNMPDatagram may be BER Object-like
    if hasattr(dg, "encode"):
        out = dg.encode()
        return bytes(out) if not isinstance(out, bytes) else out
    if hasattr(dg, "get_object"):
        obj = dg.get_object()
        return bytes(obj.encode())
    return bytes(dg)


def main() -> None:
    for ver in (SNMPVersion.v1, SNMPVersion.v2c):
        pkt = encode_get(OID, COMM, ver)
        print(f"version={ver.name} pkt_len={len(pkt)} hex={pkt[:40].hex()}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            sock.sendto(pkt, (HOST, 161))
            data, addr = sock.recvfrom(65535)
            print(f"  RESP from {addr} len={len(data)} hex={data[:64].hex()}")
            # decode
            resp = SNMPDatagram.decode(data)
            print(f"  decoded community={resp.community!r} pdu_type={type(resp.pdu)}")
            for item in resp.pdu:
                print(f"  bind={item}")
        except socket.timeout:
            print("  TIMEOUT")
        except Exception as exc:  # noqa: BLE001
            print(f"  EXC {type(exc).__name__}: {exc}")
        finally:
            sock.close()
        time.sleep(0.2)


if __name__ == "__main__":
    main()
