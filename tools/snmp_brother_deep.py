"""Deep read-only SNMP recon of Brother enterprise + Printer-MIB (snmpy raw UDP).

Walks 1.3.6.1.4.1.2435 (esp. 2.4.3), Printer-MIB supplies/levels, and
fax/scan-ish trees. Never sends SetRequest.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(r"d:\code\snmpy")))

from ber.object import Integer, OctetString
from snmp.datagram import SNMPDatagram
from snmp.enums import SNMPVersion
from snmp.pdus import GetRequest, GetNextRequest

# Printer-MIB prtMarkerSuppliesEntry columns (RFC 3805)
SUPPLIES_COLS = {
    1: "prtMarkerSuppliesIndex",
    2: "prtMarkerSuppliesMarkerIndex",
    3: "prtMarkerSuppliesColorantIndex",
    4: "prtMarkerSuppliesClass",
    5: "prtMarkerSuppliesType",
    6: "prtMarkerSuppliesDescription",
    7: "prtMarkerSuppliesSupplyUnit",
    8: "prtMarkerSuppliesMaxCapacity",
    9: "prtMarkerSuppliesLevel",
}

# Heuristic: empty / Null / zero-length on GET often means write-only or SET staging
KNOWN_SET_HINTS = {
    "1.3.6.1.4.1.2435.2.4.3.2435.5.100.10.2.0": "admin confirm SET (FirmwareUpdater)",
}


def encode(pdu, community: str, version=SNMPVersion.v2c) -> bytes:
    dg = SNMPDatagram(
        version=Integer.from_int(version.value),
        community=OctetString(community.encode()).get_object(),
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


def fmt(val, *, prefer_int: bool = False) -> str:
    inner = getattr(val, "value", val)
    name = type(val).__name__
    if name in ("EndOfMibView", "NoSuchObject", "NoSuchInstance"):
        return f"<{name}>"
    if isinstance(inner, (bytes, bytearray)):
        b = bytes(inner)
        if len(b) == 0:
            return "<empty>"
        # Brother often returns small integers as OCTET STRING
        if prefer_int or (1 <= len(b) <= 4 and not all(32 <= c < 127 for c in b)):
            return str(int.from_bytes(b, "big"))
        if all(32 <= c < 127 or c in (9, 10, 13) for c in b):
            # avoid mistaking single control bytes (e.g. 0x09=tab) for text
            if len(b) == 1 and b[0] < 32:
                return str(b[0])
            return b.decode("latin-1")
        if 1 <= len(b) <= 4:
            return f"{int.from_bytes(b, 'big')} (<{len(b)}B hex={b.hex()}>)"
        return f"<{len(b)}B hex={b.hex()}>"
    if hasattr(inner, "to_int"):
        return str(inner.to_int())
    s = str(val)
    if s in ("", "Null", "null"):
        return "<null>"
    return s[:240]


def is_emptyish(s: str) -> bool:
    return s in ("<empty>", "<null>", "Null", "") or s.startswith("<Null")


class SnmpUdp:
    def __init__(self, host: str, community: str, timeout: float = 2.5, pace: float = 0.01):
        self.host = host
        self.community = community
        self.timeout = timeout
        self.pace = pace
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

    def close(self) -> None:
        self.sock.close()

    def _exchange(self, pdu):
        if self.pace:
            time.sleep(self.pace)
        self.sock.sendto(encode(pdu, self.community), (self.host, 161))
        data, _ = self.sock.recvfrom(65535)
        return SNMPDatagram.decode(data)

    def get(self, oid: str) -> tuple[str | None, str | None, str | None]:
        try:
            resp = self._exchange(GetRequest.from_oid(oid))
            for name, value in resp.pdu:
                oid_out = decode_oid(bytes(name)) if isinstance(name, (bytes, bytearray)) else str(name)
                return oid_out, fmt(value), None
            return None, None, "empty"
        except Exception as exc:  # noqa: BLE001
            return None, None, f"{type(exc).__name__}: {exc}"

    def getnext(self, oid: str) -> tuple[str | None, str | None, str | None]:
        try:
            resp = self._exchange(GetNextRequest.from_oid(oid))
            for name, value in resp.pdu:
                oid_out = decode_oid(bytes(name)) if isinstance(name, (bytes, bytearray)) else str(name)
                return oid_out, fmt(value), None
            return None, None, "empty"
        except Exception as exc:  # noqa: BLE001
            return None, None, f"{type(exc).__name__}: {exc}"

    def walk(self, start: str, limit: int = 200) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        cur = start
        stem = start.rstrip(".")
        for _ in range(limit):
            oid_out, val, err = self.getnext(cur)
            if err or not oid_out:
                break
            if not (oid_out == stem or oid_out.startswith(stem + ".")):
                break
            out.append((oid_out, val or ""))
            if oid_out == cur:
                break
            cur = oid_out
        return out

    def discover_children(self, stem: str, max_kids: int = 80) -> list[tuple[str, int, str]]:
        """Return (child_prefix, sample_count_estimate via skip, first_value_sample).

        Skips each subtree by GetNext from stem.(N+1) after seeing first hit under N.
        """
        stem = stem.rstrip(".")
        kids: list[tuple[str, int, str]] = []
        cur = stem
        seen: set[str] = set()
        for _ in range(max_kids):
            oid_out, val, err = self.getnext(cur)
            if err or not oid_out:
                break
            if not oid_out.startswith(stem + "."):
                break
            rel = oid_out[len(stem) + 1 :]
            arc = rel.split(".", 1)[0]
            child = f"{stem}.{arc}"
            if child in seen:
                # stuck — advance past this oid
                cur = oid_out
                continue
            seen.add(child)
            kids.append((child, 0, val or ""))
            # jump toward next sibling: getnext from child + huge last arc won't work;
            # instead start getnext from the numeric next arc as OID prefix.
            try:
                nxt = int(arc) + 1
            except ValueError:
                cur = oid_out
                continue
            cur = f"{stem}.{nxt}"
        return kids

    def count_under(self, stem: str, limit: int = 500) -> tuple[int, list[tuple[str, str]], list[str]]:
        rows = self.walk(stem, limit=limit)
        empty = [o for o, v in rows if is_emptyish(v)]
        return len(rows), rows, empty


def summarize_branch(rows: list[tuple[str, str]], max_show: int = 12) -> None:
    by_sub: dict[str, int] = defaultdict(int)
    strings: list[tuple[str, str]] = []
    for oid, val in rows:
        parts = oid.split(".")
        # group by ~8 arcs after enterprise or first differing
        key = ".".join(parts[: min(14, len(parts))])
        by_sub[key] += 1
        if val and not is_emptyish(val) and not val.startswith("<") and any(c.isalpha() for c in val):
            strings.append((oid, val))
    print(f"  leaf_count={len(rows)} emptyish={sum(1 for _, v in rows if is_emptyish(v))}")
    interesting = sorted(strings, key=lambda x: (-len(x[1]), x[0]))[:max_show]
    for oid, val in interesting:
        print(f"  STR  {oid} = {val}")
    # show a few numeric / hex samples too
    other = [r for r in rows if r not in interesting and not is_emptyish(r[1])][:8]
    for oid, val in other:
        print(f"  VAL  {oid} = {val}")


def print_supplies_table(cli: SnmpUdp) -> None:
    base = "1.3.6.1.2.1.43.11.1.1"
    # discover indices from description column
    descrs = cli.walk(f"{base}.6", limit=40)
    indices: list[str] = []
    for oid, _ in descrs:
        # ...6.1.N
        parts = oid.split(".")
        if len(parts) >= 1:
            indices.append(parts[-1])
    indices = sorted(set(indices), key=lambda x: int(x) if x.isdigit() else x)
    print(f"\n=== Printer-MIB prtMarkerSupplies (indices={indices}) ===")
    print(f"{'idx':>3} {'type':>4} {'class':>5} {'unit':>4} {'max':>6} {'level':>6}  description")
    for idx in indices:
        cells = {}
        for col, _name in SUPPLIES_COLS.items():
            _o, v, e = cli.get(f"{base}.{col}.1.{idx}")
            if e:
                cells[col] = e
            elif col in (4, 5, 7, 8, 9) and v and "hex=" in v:
                # re-get raw via walk-style: parse hex from fmt fallback
                try:
                    h = v.split("hex=")[1].rstrip(">")
                    cells[col] = str(int(h, 16))
                except Exception:
                    cells[col] = v
            else:
                cells[col] = v or "?"
        print(
            f"{idx:>3} {cells.get(5, '?'):>4} {cells.get(4, '?'):>5} {cells.get(7, '?'):>4} "
            f"{cells.get(8, '?'):>6} {cells.get(9, '?'):>6}  {cells.get(6, '')}"
        )


def probe_fax_scan(cli: SnmpUdp) -> None:
    print("\n=== Fax / scan related (presence) ===")
    candidates = {
        "hrDeviceDescr walk": "1.3.6.1.2.1.25.3.2.1.3",
        "hrPrinterStatus": "1.3.6.1.2.1.25.3.5.1.1",
        "prtGeneral": "1.3.6.1.2.1.43.5.1.1",
        "prtAlert": "1.3.6.1.2.1.43.18.1.1.8",
        "prtInputDescr": "1.3.6.1.2.1.43.8.2.1.18",
        # Experimental / uncommon
        "fax-mib (exp)": "1.3.6.1.2.1.14",  # actually egp historically; fax often private
        "mib-2.43 printer": "1.3.6.1.2.1.43",
        # Brother-ish guesses under 2.4.3
        "brother 2.4.3": "1.3.6.1.4.1.2435.2.4.3",
    }
    # Direct GETs that might exist on MFP
    gets = {
        "sysServices": "1.3.6.1.2.1.1.7.0",
        "prtConsoleDisplayBuffer": "1.3.6.1.2.1.43.16.5.1.2.1.1",
        "prtGeneralPrinterName": "1.3.6.1.2.1.43.5.1.1.16.1",
        "prtGeneralSerialNumber": "1.3.6.1.2.1.43.5.1.1.17.1",
    }
    for name, oid in gets.items():
        o, v, e = cli.get(oid)
        print(f"GET {name}: {e or v}")

    # Walk hr devices for scanner wording
    rows = cli.walk("1.3.6.1.2.1.25.3.2.1.3", limit=30)
    print(f"hrDeviceDescr n={len(rows)}")
    for o, v in rows:
        print(f"  {o} = {v}")

    # Search brother tree samples for fax/scan/pcfax strings during deep walk (done in main)
    # Probe a few Brother subtrees often associated with MFP features
    for label, oid in [
        ("brother.2.3.9", "1.3.6.1.4.1.2435.2.3.9"),
        ("brother.2.4.3.1", "1.3.6.1.4.1.2435.2.4.3.1"),
        ("brother.2.4.3.5", "1.3.6.1.4.1.2435.2.4.3.5"),
        ("brother.2.4.3.10", "1.3.6.1.4.1.2435.2.4.3.10"),
        ("brother.2.4.3.20", "1.3.6.1.4.1.2435.2.4.3.20"),
        ("brother.2.4.3.99", "1.3.6.1.4.1.2435.2.4.3.99"),
        ("brother.2.4.3.2435", "1.3.6.1.4.1.2435.2.4.3.2435"),
        ("brother.2.4.3.1240", "1.3.6.1.4.1.2435.2.4.3.1240"),
    ]:
        o, v, e = cli.getnext(oid)
        under = o and o.startswith(oid.rstrip(".") + ".") or o == oid.rstrip(".")
        print(f"NEXT {label}: {'HIT ' + o + ' = ' + (v or '') if under else 'no subtree'} {'' if under else (e or o)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("host", nargs="?", default="192.168.1.71")
    ap.add_argument("-c", "--community", default="public")
    ap.add_argument("--limit", type=int, default=400, help="max leaves per deep walk")
    args = ap.parse_args()

    cli = SnmpUdp(args.host, args.community)
    try:
        print(f"=== Brother deep SNMP {args.host} community={args.community} (GET/GETNEXT only) ===")
        o, v, e = cli.get("1.3.6.1.2.1.1.1.0")
        print(f"sysDescr: {e or v}")

        # Top of enterprise
        print("\n=== enterprise 1.3.6.1.4.1.2435 children ===")
        kids = cli.discover_children("1.3.6.1.4.1.2435", max_kids=40)
        for child, _, sample in kids:
            print(f"  {child}  first~ {sample[:80]}")

        print("\n=== under 1.3.6.1.4.1.2435.2 children ===")
        kids2 = cli.discover_children("1.3.6.1.4.1.2435.2", max_kids=40)
        for child, _, sample in kids2:
            print(f"  {child}  first~ {sample[:80]}")

        stem243 = "1.3.6.1.4.1.2435.2.4.3"
        print(f"\n=== under {stem243} children ===")
        kids3 = cli.discover_children(stem243, max_kids=120)
        for child, _, sample in kids3:
            print(f"  {child}  first~ {sample[:100]}")

        writable_notes: list[tuple[str, str]] = []
        faxish: list[tuple[str, str]] = []

        print(f"\n=== deep walks under each {stem243}.* child (limit={args.limit}) ===")
        for child, _, _ in kids3:
            n, rows, empty = cli.count_under(child, limit=args.limit)
            capped = " (hit limit)" if n >= args.limit else ""
            print(f"\n--- {child} n={n}{capped} ---")
            summarize_branch(rows)
            for oid in empty:
                hint = KNOWN_SET_HINTS.get(oid, "empty on GET — possible write/SET staging")
                writable_notes.append((oid, hint))
            for oid, val in rows:
                low = (val or "").lower()
                if any(k in low for k in ("fax", "scan", "pc-fax", "pcfax", "ifx", "ifax", "adf")):
                    faxish.append((oid, val))
                if oid in KNOWN_SET_HINTS:
                    writable_notes.append((oid, KNOWN_SET_HINTS[oid]))
                # challenge-like changing blobs / confirm siblings
                if oid.endswith(".10.2.0") or "2435.5.100.10.2" in oid:
                    writable_notes.append((oid, "confirm-like SET target"))

        # Also walk admin100 explicitly if not covered
        admin = f"{stem243}.2435.5.100"
        print(f"\n=== admin100 walk {admin} ===")
        rows = cli.walk(admin, limit=80)
        for oid, val in rows:
            print(f"  {oid} = {val}")
            if is_emptyish(val) or oid in KNOWN_SET_HINTS:
                writable_notes.append((oid, KNOWN_SET_HINTS.get(oid, "empty on GET")))

        # Firm tree
        firm = f"{stem243}.99.3.1.6.1.2"
        print(f"\n=== firm walk {firm} ===")
        for oid, val in cli.walk(firm, limit=40):
            print(f"  {oid} = {val}")

        print_supplies_table(cli)

        # Extra Printer-MIB context
        print("\n=== Printer-MIB extras ===")
        for name, oid in [
            ("prtGeneralSerialNumber", "1.3.6.1.2.1.43.5.1.1.17.1"),
            ("prtGeneralPrinterName", "1.3.6.1.2.1.43.5.1.1.16.1"),
            ("prtConsoleDisplay", "1.3.6.1.2.1.43.16.5.1.2.1.1"),
            ("prtMarkerLifeCount", "1.3.6.1.2.1.43.10.2.1.4.1.1"),
            ("prtMarkerPowerOnCount", "1.3.6.1.2.1.43.10.2.1.5.1.1"),
        ]:
            o, v, e = cli.get(oid)
            print(f"{name}: {e or v}")
        alerts = cli.walk("1.3.6.1.2.1.43.18.1.1.8", limit=20)
        print(f"prtAlertDescription n={len(alerts)}")
        for o, v in alerts[:10]:
            print(f"  {o} = {v}")

        probe_fax_scan(cli)

        # Keyword sweep: walk a few more brother roots and collect fax/scan
        print("\n=== keyword sweep (fax|scan|adf|ifx) in walked leaves ===")
        if faxish:
            for oid, val in faxish[:40]:
                print(f"  {oid} = {val}")
        else:
            print("  (none in 2.4.3 child samples — checking broader 2435.2)")

        # Broader shallow keyword hunt under 2435.2 excluding already walked
        for root in ["1.3.6.1.4.1.2435.2.3", "1.3.6.1.4.1.2435.3"]:
            rows = cli.walk(root, limit=150)
            print(f"walk {root} n={len(rows)}")
            hits = [
                (o, v)
                for o, v in rows
                if any(k in (v or "").lower() for k in ("fax", "scan", "adf", "ifx", "pc-fax"))
            ]
            for o, v in hits[:20]:
                print(f"  HIT {o} = {v}")
                faxish.append((o, v))

        print("\n=== writable-looking (heuristic, NO SET performed) ===")
        seen = set()
        for oid, note in writable_notes:
            if oid in seen:
                continue
            seen.add(oid)
            print(f"  {oid}  # {note}")
        # Explicit GET of confirm
        o, v, e = cli.get(f"{stem243}.2435.5.100.10.2.0")
        print(f"  confirm GET: {e or v}")

        # Branch index for doc
        print("\n=== branch index (2.4.3.*) ===")
        for child, _, sample in kids3:
            n, rows, _ = cli.count_under(child, limit=min(80, args.limit))
            # short label from first string
            label = ""
            for _, val in rows:
                if val and any(c.isalpha() for c in val) and not is_emptyish(val) and not val.startswith("<"):
                    label = val[:60]
                    break
            print(f"  {child}  n~{n}+  sample={label or sample[:50]}")

    finally:
        cli.close()


if __name__ == "__main__":
    main()
