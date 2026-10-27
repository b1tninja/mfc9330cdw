r"""Scan the LAN for printers over SNMP, built on snmpy.

Sweeps a subnet with SNMPv2c (optionally SNMPv3), classifies what answers as a
printer, then enriches Brother devices with model / serial / page count / toner
using the OID pack in ``tools/brother_oids.py``.

Read-only by construction: only GET and GETNEXT are ever sent.  Brother's
``admin100`` tree gates writes behind a challenge/confirm handshake, so a stray
SET there can change the device's administrator password — this tool never
issues one.

Usage (from the repo root)::

    .\.venv\Scripts\python.exe tools\snmp_scan_printers.py
    .\.venv\Scripts\python.exe tools\snmp_scan_printers.py --expect MFC-9330CDW
    .\.venv\Scripts\python.exe tools\snmp_scan_printers.py -t 192.168.1.71,192.168.1.67 --json
    .\.venv\Scripts\python.exe tools\snmp_scan_printers.py --subnet 192.168.1.0/24 --community private
    .\.venv\Scripts\python.exe tools\snmp_scan_printers.py --masscan sweep.osb     # masscan -oB file
    .\.venv\Scripts\python.exe tools\snmp_scan_printers.py --v3-probe              # engine ID harvest
    .\.venv\Scripts\python.exe tools\snmp_scan_printers.py --v3-user admin -A SHA -U authpass -x AES128 -X privpass

Exit code is 0 when ``--expect`` matched (or was not given), 1 when it did not —
so the tool doubles as a regression check that a known printer is still on the
network and answering SNMP.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

# snmpy is installed editable into .venv; fall back to a sibling checkout so the
# tool also runs from a bare interpreter.
_TOOLS_DIR = Path(__file__).resolve().parent
for _candidate in (_TOOLS_DIR, Path(r"D:\code\snmpy")):
    if (_candidate / "brother_oids.py").is_file() or (_candidate / "snmp").is_dir():
        if str(_candidate) not in sys.path:
            sys.path.insert(0, str(_candidate))

from snmp import Session  # noqa: E402
from snmp.client import SNMPClientImpl  # noqa: E402
from snmp.enums import SNMPVersion  # noqa: E402
from snmp.exceptions import SNMPError  # noqa: E402
from snmp.mpm import (  # noqa: E402
    AUTH_FLAG,
    PRIV_FLAG,
    MPv3,
    SNMPv3Message,
)
from snmp.oid import resolve_oid  # noqa: E402
from snmp.pdus import GetRequest  # noqa: E402
from snmp.privacy import (  # noqa: E402
    PrivacyContext,
    localize_privacy_key,
    resolve_auth_protocol,
)
from snmp.scoped_pdu import ScopedPDU  # noqa: E402
from snmp.usm import SecurityParameters, localize_passphrase  # noqa: E402
from snmp.values import as_str  # noqa: E402

import brother_oids  # noqa: E402,F401  (registers the "brother" pack with snmpy)
from brother_oids import (  # noqa: E402
    firm_root,
    ieee1284_id,
    prtGeneralPrinterName,
    prtGeneralSerialNumber,
    prtMarkerLifeCount,
    prtMarkerSuppliesDescription,
    prtMarkerSuppliesLevel,
    prtMarkerSuppliesMaxCapacity,
)

# ---------------------------------------------------------------------------
# OIDs
# ---------------------------------------------------------------------------

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYS_SERVICES = "1.3.6.1.2.1.1.7.0"

# The identity a sweep asks every host for.  Two GETs keep the flood small while
# still being enough to tell a printer from a router.
SWEEP_OIDS = (SYS_DESCR, SYS_OBJECT_ID)

# hrDeviceType (RFC 2790) is column 2 of hrDeviceTable, and its SYNTAX is
# AutonomousType: the value is an OID, not an integer.  A print device is
# therefore spotted by the OID it points at — hrDevicePrinter, which is
# { hrDeviceTypes 5 } under hrDevice = { mib-2 25.3 }.
HR_DEVICE_TYPE = "1.3.6.1.2.1.25.3.2.1.2"
HR_DEVICE_TYPES_ROOT = "1.3.6.1.2.1.25.3.1"
HR_DEVICE_PRINTER = "1.3.6.1.2.1.25.3.1.5"

# Printer-MIB (RFC 3812/3813) roots used for classification and enrichment.
PRINTER_MIB_ROOT = "1.3.6.1.2.1.43"

# Column roots for the enrichment walks.  snmpy's Printer-MIB pack registers
# prtGeneralSerialNumber / prtMarkerLifeCount as *instances* (…17.1, …4.1.1),
# and a GETNEXT from an instance leaves its own subtree on the first step, so
# walking an instance root yields nothing.  Direct GETs use the pack leaf;
# subtree walks start at the column.
PRT_GENERAL_SERIAL_COL = "1.3.6.1.2.1.43.5.1.1.17"
PRT_GENERAL_NAME_COL = "1.3.6.1.2.1.43.5.1.1.16"
PRT_MARKER_LIFE_COL = "1.3.6.1.2.1.43.10.2.1.4"

# Partial vendor map — IANA private-enterprise numbers seen on office print
# fleets.  Anything absent prints as "PEN <n>" rather than being guessed at;
# extend from the IANA PEN registry when a new brand shows up.
ENTERPRISE_NAMES = {
    11: "Hewlett-Packard",
    367: "Ricoh",
    641: "Lexmark",
    674: "Dell",
    683: "Xerox",
    858: "Canon",
    2435: "Brother",
}
BROTHER_PEN = 2435

# Ports that identify a print device even when SNMP is disabled.
PRINT_SERVICE_PORTS = {
    9100: "jetdirect",
    515: "lpd",
    631: "ipp",
    80: "http",
    443: "https",
}

# ASCII-ish device strings can arrive with trailing NULs / control bytes.
_CLEAN = re.compile(r"[\x00-\x1f\x7f]+")


def clean(value: object) -> str:
    """Best-effort printable text for an SNMP value.

    RFC 3416 §4.1.6 exception values (``noSuchObject`` / ``noSuchInstance`` /
    ``endOfMibView``) are empty content, and str()-ing their raw content gives
    the literal text ``b''`` — truthy garbage that would otherwise win every
    "first non-empty candidate" race in this tool.  They are empty here.
    """
    from snmp.values import exception_name

    if value is None or exception_name(value) is not None:
        return ""
    try:
        text = as_str(value)
    except Exception:
        text = str(getattr(value, "value", value))
    if isinstance(text, bytes):
        text = text.decode("latin-1")
    return _CLEAN.sub(" ", text).strip()


def enterprise_of(sys_object_id: str) -> Optional[int]:
    """The PEN inside a sysObjectID (``1.3.6.1.4.1.<pen>.…``), if any.

    The full prefix is ``iso.org.dod.internet.private.enterprises`` =
    ``1.3.6.1.4.1``, so the PEN is the seventh arc, not the fifth.
    """
    arcs = sys_object_id.strip().lstrip(".").split(".")
    if len(arcs) >= 7 and arcs[:6] == ["1", "3", "6", "1", "4", "1"]:
        try:
            return int(arcs[6])
        except ValueError:
            return None
    return None


def vendor_label(sys_object_id: str) -> str:
    """Human vendor name for a sysObjectID, or ``PEN <n>`` / ``""``."""
    pen = enterprise_of(sys_object_id)
    if pen is None:
        return ""
    return ENTERPRISE_NAMES.get(pen, f"PEN {pen}")


# ---------------------------------------------------------------------------
# Device record
# ---------------------------------------------------------------------------


@dataclass
class Device:
    """Everything learned about one address, in scan order."""

    address: str
    snmp: bool = False
    version: str = ""
    sys_descr: str = ""
    sys_object_id: str = ""
    sys_name: str = ""
    sys_location: str = ""
    vendor: str = ""
    printer_mib_oid: str = ""
    """First OID the agent returned inside Printer-MIB (``.1.3.6.1.2.1.43``).

    Recorded during the sweep so classification does not depend on the deep
    enrichment pass — see ``_read_sweep``.
    """
    model: str = ""
    serial: str = ""
    page_count: Optional[int] = None
    toner: list[dict] = field(default_factory=list)
    engine_id: str = ""
    is_printer: bool = False
    enriched: bool = False
    """Set once the deep GET/GETNEXT pass has run — see ``run_scan``.

    Scans that add a v3 pass afterwards must not walk the same device through
    enrichment twice: the supply table is appended to, so a second pass shows
    every cartridge twice in the report.
    """
    reasons: list[str] = field(default_factory=list)
    open_ports: list[str] = field(default_factory=list)
    error: str = ""

    def add_reason(self, text: str) -> None:
        """Record why this address was classified as a printer."""
        if text and text not in self.reasons:
            self.reasons.append(text)

    def to_dict(self) -> dict:
        """JSON-safe view for ``--json``."""
        return {
            "address": self.address,
            "snmp": self.snmp,
            "version": self.version,
            "vendor": self.vendor,
            "model": self.model,
            "serial": self.serial,
            "page_count": self.page_count,
            "toner": self.toner,
            "sys_descr": self.sys_descr,
            "sys_object_id": self.sys_object_id,
            "printer_mib_oid": self.printer_mib_oid,
            "sys_name": self.sys_name,
            "sys_location": self.sys_location,
            "engine_id": self.engine_id,
            "is_printer": self.is_printer,
            "reasons": self.reasons,
            "open_ports": self.open_ports,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

# Interfaces that are never the LAN a printer hangs off: APIPA (169.254/16),
# loopback, and Hyper-V / WSL / container virtual switch adapters.
_SKIP_INTERFACE = re.compile(r"vethernet|loopback|wsl|docker|vmnet|virtual", re.I)

# Hard ceiling on one expansion, so a mistyped /8 cannot flood the network.
MAX_EXPANSION = 1024


def local_subnets() -> list[str]:
    """CIDR strings of the real local IPv4 attached networks.

    ``psutil`` is not installed in this venv and snmpy deliberately carries no
    interface-enumeration dependency, so this asks PowerShell — the same data
    ``ipconfig /all`` shows, but machine-readable.
    """
    script = (
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | "
        "ForEach-Object { '{0}|{1}|{2}' -f $_.InterfaceAlias, $_.IPAddress, $_.PrefixLength }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""

    subnets: list[str] = []
    for line in out.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        alias, addr, prefix = (p.strip() for p in parts)
        if _SKIP_INTERFACE.search(alias):
            continue
        try:
            network = ipaddress.ip_interface(f"{addr}/{prefix}").network
        except ValueError:
            continue
        if network.network_address.is_link_local or network.network_address.is_loopback:
            continue
        if str(network) not in subnets:
            subnets.append(str(network))

    if subnets:
        return subnets

    # Fallback when Get-NetIPAddress is unavailable (older Windows, or
    # PowerShell blocked by policy): guess a /24 around the primary address.
    try:
        addr = socket.gethostbyname(socket.gethostname())
        return [str(ipaddress.ip_network(f"{addr}/24", strict=False))]
    except OSError:
        return []


def expand_target(text: str) -> list[str]:
    """Expand one address token: single IP, CIDR, or ``a.b.c.D-R`` range."""
    text = text.strip()
    if not text:
        return []

    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise SystemExit(f"bad CIDR {text!r}: {exc}") from exc
        hosts = list(network.hosts()) or [network.network_address]
        return [str(h) for h in hosts[:MAX_EXPANSION]]

    match = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", text)
    if match:
        base, first, last = match.group(1), int(match.group(2)), int(match.group(3))
        if first > last:
            first, last = last, first
        first, last = max(0, first), min(255, last)
        return [f"{base}{i}" for i in range(first, last + 1)][:MAX_EXPANSION]

    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        raise SystemExit(f"not an IPv4 address, CIDR, or last-octet range: {text!r}")
    return [text]


def targets_from_masscan(path: Path) -> list[str]:
    """IPv4 addresses from a masscan output file.

    Prefers snmpy's bundled ``masscan.readscan`` reader for ``-oB`` binary
    output and falls back to harvesting dotted quads from the file, which
    covers ``-oJ`` / ``-oL`` / ``readscan -c`` text dumps too.
    """
    data = path.read_bytes()
    addresses: list[str] = []
    try:
        from masscan import readscan

        for item in readscan.filter_scan(str(path)):
            found = getattr(item, "ip", None) or getattr(item, "ip_str", None)
            if found:
                addresses.append(str(found))
    except Exception:
        addresses = []

    if not addresses:
        seen: set[str] = set()
        for match in re.finditer(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", data):
            candidate = match.group(0).decode("ascii")
            try:
                ipaddress.IPv4Address(candidate)
            except ValueError:
                continue
            if candidate not in seen:
                seen.add(candidate)
                addresses.append(candidate)
    return addresses


def build_targets(args: argparse.Namespace) -> list[str]:
    """Resolve every addressing option into one de-duplicated probe list."""
    targets: list[str] = []
    for token in args.targets:
        targets.extend(expand_target(token))
    for token in args.subnet:
        targets.extend(expand_target(token))
    for path in args.masscan:
        targets.extend(targets_from_masscan(Path(path)))
    if args.address:
        for cidr in local_subnets():
            targets.extend(expand_target(cidr))

    seen: set[str] = set()
    unique: list[str] = []
    for address in targets:
        if address not in seen:
            seen.add(address)
            unique.append(address)
    return unique


# ---------------------------------------------------------------------------
# SNMPv2c sweep
# ---------------------------------------------------------------------------


def _read_sweep(address: str, args: argparse.Namespace) -> Device:
    """Blocking identity GET + Printer-MIB probe against one address.

    Runs in a thread.  Two GETs (``sysDescr``/``sysObjectID``) identify the
    host; one GETNEXT into ``.1.3.6.1.2.1.43`` decides whether it implements
    Printer-MIB.  That probe is what lets ``--fast`` classify devices whose
    ``sysDescr`` names a print *server* rather than the product — Brother
    answers ``Brother NC-8500h…`` and puts sysObjectID under PEN 2435, so
    neither text nor OID hints match without asking the agent directly.
    """
    device = Device(address=address)
    try:
        with Session(
            address,
            port=args.port,
            community=args.community,
            timeout=args.timeout,
            retries=args.retries,
        ) as snmp:
            values = dict(snmp.get_many(SWEEP_OIDS))
            try:
                successor = snmp.get_next(PRINTER_MIB_ROOT)
            except (SNMPError, OSError):
                # A broken/absent Printer-MIB is a missing signal, not a failed
                # sweep — the host still answered the identity GETs.
                successor = None
    except SNMPError as exc:
        device.error = type(exc).__name__
        return device
    except OSError as exc:
        device.error = type(exc).__name__
        return device

    descr = clean(values.get(SYS_DESCR))
    object_id = clean(values.get(SYS_OBJECT_ID))
    if not descr and not object_id:
        device.error = "no response"
        return device

    device.snmp = True
    device.version = "v2c"
    device.sys_descr = descr
    device.sys_object_id = object_id
    device.vendor = vendor_label(object_id)
    if successor is not None:
        found_oid = successor[0]
        # Only a successor still inside the subtree counts: at the end of the
        # MIB view an agent returns whatever follows it (or nothing).
        if found_oid == PRINTER_MIB_ROOT or found_oid.startswith(PRINTER_MIB_ROOT + "."):
            device.printer_mib_oid = found_oid
    return device


async def sweep_v2c(targets: Sequence[str], args: argparse.Namespace) -> list[Device]:
    """Identify every address that answers SNMPv2c, bounded by a semaphore.

    ``Session`` is snmpy's sanctioned blocking API and keeps one socket per
    host; running it on the default thread executor gives the same concurrency
    the asyncio client would, without a socket-per-request churn over /24s.
    """
    semaphore = asyncio.Semaphore(args.parallel)

    async def one(address: str) -> Device:
        async with semaphore:
            return await asyncio.to_thread(_read_sweep, address, args)

    return list(await asyncio.gather(*(one(a) for a in targets)))


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

# Text markers that only appear in a print device's sysDescr.
_DESCRIPTOR_HINT = re.compile(
    r"print|mfp|multifunction|fax|toner|drum|jetdirect|laserjet|officejet", re.I
)


def classify(device: Device) -> Device:
    """Decide whether an SNMP-speaking host is a print device, and why.

    Several independent signals, so a printer that hides its enterprise OID is
    still found while a NAS running an IPP daemon is not: Printer-MIB objects
    under ``.1.3.6.1.2.1.43``, ``hrDeviceType = printing(13)``, a printer-like
    sysDescr, and the vendor identity strings collected during enrichment.
    Enrichment runs first and records its evidence in ``device.reasons``.
    """
    if not device.snmp:
        return device

    if device.sys_object_id.startswith(PRINTER_MIB_ROOT + "."):
        device.add_reason("sysObjectID in Printer-MIB")
    if device.printer_mib_oid:
        device.add_reason(f"Printer-MIB answered ({device.printer_mib_oid})")
    if _DESCRIPTOR_HINT.search(device.sys_descr):
        device.add_reason("sysDescr mentions printing")

    device.is_printer = bool(device.reasons)
    return device


# ---------------------------------------------------------------------------
# Read-only helpers
# ---------------------------------------------------------------------------


def bounded_walk(snmp: Session, root: str, limit: int = 24) -> list[tuple[str, object]]:
    """GETNEXT a subtree with a hard row cap.

    ``Session.walk`` stops only when the subtree is exhausted; on a printer
    with a large hrDevice or supplies table that is far more traffic than an
    inventory scan needs, so the row count is capped here.
    """
    root = resolve_oid(root)
    rows: list[tuple[str, object]] = []
    current = root
    while len(rows) < limit:
        try:
            nxt = snmp.get_next(current)
        except (SNMPError, OSError):
            break
        if nxt is None:
            break
        oid_str, value = nxt
        if not oid_str.startswith(root) or oid_str == current:
            break
        rows.append((oid_str, value))
        current = oid_str
    return rows


def parse_1284_id(text: str) -> dict[str, str]:
    """Split an IEEE 1284.1 device ID (``MFG:…;CMD:…;MDL:…;SN:…``) into fields.

    Handles the flat form Brother firmware ships.  Length-tagged values
    (``CID16#000D…``) keep their raw text rather than being silently dropped.
    """
    fields: dict[str, str] = {}
    for part in text.split(";"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        key, value = key.strip().upper(), value.strip()
        if key and value:
            fields.setdefault(key, value)
    return fields


def first_text(snmp: Session, oids: Iterable[object]) -> str:
    """First non-empty GET among ``oids``, skipping absent leaves."""
    for oid in oids:
        try:
            text = clean(snmp.get(oid))
        except (SNMPError, OSError):
            continue
        if text:
            return text
    return ""


def as_number(value: object) -> Optional[int]:
    """Coerce an SNMP value to int, or None when it is not numeric.

    Counter32 / Gauge32 / TimeTicks decode to raw content octets (this codec
    has no class for them), which ``as_int`` reads as unsigned big-endian —
    that is how a life count of ``b'b\\xaa'`` becomes 27306.  v2c exception
    values raise ``LookupError`` and are treated as "not numeric".
    """
    from snmp.values import as_int

    if value is None:
        return None
    try:
        return int(as_int(value))
    except (TypeError, ValueError, LookupError):
        return None


def _suffix(oid_str: str, root: str) -> str:
    """The table index part of an OID below a column root (``1.1`` etc.)."""
    return oid_str[len(root) :].lstrip(".")


def collect_supplies(snmp: Session, device: Device) -> None:
    """Merge Printer-MIB prtMarkerSuppliesTable columns into supply entries.

    Description, current level and max capacity are separate columns indexed
    the same way, so they are walked separately and zipped on the index rather
    than assuming the conventional ``1.1`` instance.
    """
    columns = {
        "description": (resolve_oid(prtMarkerSuppliesDescription), clean),
        "level": (resolve_oid(prtMarkerSuppliesLevel), as_number),
        "max_capacity": (resolve_oid(prtMarkerSuppliesMaxCapacity), as_number),
    }
    tables: dict[str, dict[str, object]] = {}
    for name, (root, convert) in columns.items():
        tables[name] = {
            _suffix(oid, root): convert(value)
            for oid, value in bounded_walk(snmp, root, limit=16)
        }

    indexes = sorted(set(tables["description"]) | set(tables["level"]), key=lambda s: [int(x) if x.isdigit() else x for x in s.split(".")])
    for index in indexes:
        entry: dict = {"index": index}
        for name in columns:
            entry[name] = tables[name].get(index)
        if entry.get("description") or entry.get("level") is not None:
            device.toner.append(entry)

    if device.toner:
        device.add_reason("Printer-MIB supplies table")


def device_type_is_printer(value: object) -> bool:
    """True when an hrDeviceType value points at hrDevicePrinter.

    The column is an AutonomousType, so agents return an OID such as
    ``1.3.6.1.2.1.25.3.1.5``; comparing it to an integer would never match.
    Sub-identifiers below hrDevicePrinter are accepted too, since some agents
    append a model subtype.

    ``as_str`` renders a BER ``ObjectIdentifier`` value as dotted text;
    ``snmp.values.oid_string`` is for var-bind *names* and rejects a value
    object outright, so it is only a fallback here.
    """
    from snmp.values import exception_name, oid_string

    if value is None or exception_name(value) is not None:
        return False
    try:
        text = as_str(value).strip()
    except Exception:
        try:
            text = oid_string(value).strip()
        except Exception:
            return False
    return text == HR_DEVICE_PRINTER or text.startswith(HR_DEVICE_PRINTER + ".")


def first_in_column(snmp: Session, leaf: object, column: str, convert) -> object:
    """Read one table leaf: conventional instance first, then the column.

    snmpy registers several Printer-MIB leaves with a baked-in index
    (``prtMarkerLifeCount`` = ``…10.2.1.4.1.1``), which a direct GET handles on
    a single-device agent but a walk does not — GETNEXT from an instance steps
    out of its own subtree immediately.  Agents that index devices differently
    are caught by the column walk that follows.

    ``convert`` decides what counts as an answer (``clean`` for text,
    ``as_number`` for counters); ``None`` / ``""`` mean "keep looking".
    """
    try:
        result = convert(snmp.get(leaf))
    except (SNMPError, OSError):
        result = None
    if result is not None and result != "":
        return result
    for _oid, value in bounded_walk(snmp, column, limit=6):
        result = convert(value)
        if result is not None and result != "":
            return result
    return None


def enrich_printers(device: Device, snmp: Session) -> None:
    """Printer-MIB / HOST-RESOURCES-MIB identity for a print device.

    Runs for every SNMP host, not only known printer vendors: hrDeviceType and
    the supplies table are how a printer with a blanked sysDescr still gets
    identified.
    """
    for _oid, value in bounded_walk(snmp, HR_DEVICE_TYPE, limit=12):
        if device_type_is_printer(value):
            device.add_reason("hrDeviceType = hrDevicePrinter")
            break

    serial = first_in_column(
        snmp, prtGeneralSerialNumber, PRT_GENERAL_SERIAL_COL, clean
    )
    if serial and not device.serial:
        device.serial = str(serial)
        device.add_reason("Printer-MIB serial")

    if not device.model:
        name = first_in_column(
            snmp, prtGeneralPrinterName, PRT_GENERAL_NAME_COL, clean
        )
        if name:
            device.model = str(name)
            device.add_reason("Printer-MIB printer name")

    if device.page_count is None:
        count = first_in_column(snmp, prtMarkerLifeCount, PRT_MARKER_LIFE_COL, as_number)
        if count is not None:
            device.page_count = int(count)
            device.add_reason("Printer-MIB life count")

    collect_supplies(snmp, device)


def enrich_brother(device: Device, snmp: Session) -> None:
    """Brother identity strings: IEEE 1284.1 device ID, then the firm-ID tree.

    The 1284 string is the authoritative ``MFG/MDL/SN`` source on NC-8500h
    firmware; the ``99.3.1.6.1.2`` firm tree is the fallback when a small PDU
    size truncates it.
    """
    device_id = first_text(snmp, [ieee1284_id])
    if not device_id:
        rows = bounded_walk(snmp, resolve_oid(brother_oids.ieee1284), limit=8)
        device_id = " ".join(clean(value) for _oid, value in rows)

    if device_id:
        fields = parse_1284_id(device_id)
        device.model = fields.get("MDL") or device.model
        device.serial = fields.get("SN") or device.serial
        if fields.get("MFG"):
            device.vendor = fields["MFG"]
        device.add_reason("IEEE 1284 device ID")

    if not device.model or not device.serial:
        firm = [
            clean(value)
            for _oid, value in bounded_walk(snmp, resolve_oid(firm_root), limit=12)
        ]
        if not device.model:
            for text in firm:
                if re.search(r"[A-Z]{2,}-\d+", text):
                    device.model = text
                    device.add_reason("Brother firm-ID tree")
                    break
        if not device.serial:
            for text in firm:
                if re.fullmatch(r"[UWA-Z0-9]{10,20}", text):
                    device.serial = text
                    device.add_reason("Brother firm-ID tree serial")
                    break


# ---------------------------------------------------------------------------
# SNMPv3 (RFC 3414)
# ---------------------------------------------------------------------------


class _RawMessage:
    """Pre-encoded message bytes in the shape ``_send_receive`` expects."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def __bytes__(self) -> bytes:
        return self.data


class V3Probe(SNMPClientImpl):
    """SNMPv3 client used for discovery and credentialed identity GETs.

    Subclasses ``SNMPClientImpl`` for its tested UDP transport (ephemeral bind
    on ``0.0.0.0`` so agent replies from a LAN printer are receivable) and
    swaps the message layer: SNMPv3 messages are built and parsed with
    ``MPv3`` rather than ``SNMPDatagram``, which only speaks v1/v2c.

    Discovery (RFC 3414 §4.1) needs no credentials — a message carrying a
    zero-length msgAuthoritativeEngineID and zero-length userName makes the
    engine reply with a Report PDU containing its authoritative engineID,
    boots and time.  That alone proves v3 is enabled, and the engineID is often
    derived from the interface MAC address, which is inventory gold.
    """

    username: str = ""
    auth_passphrase: str = ""
    auth_protocol: str = "SHA"
    priv_passphrase: str = ""
    priv_protocol: str = "AES128"

    def __init__(self, msg_id: int = 0x01020304) -> None:
        """Initialize the probe; ``msg_id`` only needs to vary per request."""
        super().__init__(version=SNMPVersion.v3)
        self._msg_id = msg_id

    def next_msg_id(self) -> int:
        """A fresh msgID (RFC 3412 §6.4: must not repeat within a boot cycle)."""
        self._msg_id = (self._msg_id + 1) & 0x7FFFFFFF
        return self._msg_id

    async def discover(self, host: str, port: int = 161) -> Optional[SecurityParameters]:
        """EngineID discovery; returns the authoritative parameters or None."""
        mpm = MPv3(b"")
        message = SNMPv3Message(msg_id=self.next_msg_id(), reportable=True)
        message.security_parameters = SecurityParameters(engine_id=b"", username="")
        message.scoped_pdu = ScopedPDU(pdu=GetRequest.from_oid(SYS_DESCR))

        raw = await self._send_receive(_RawMessage(mpm.encode(message)), host, port)
        if raw is None:
            return None
        try:
            decoded = mpm.decode(raw)
        except SNMPError:
            return None
        return decoded.security_parameters

    async def get(self, host: str, oid: str, port: int = 161) -> Optional[object]:
        """Authenticated GET after localizing keys to the discovered engine."""
        values = await self.get_many(host, [oid], port)
        return values.get(oid)

    async def get_many(
        self, host: str, oids: Sequence[str], port: int = 161
    ) -> dict[str, object]:
        """Discover once, then send one authenticated GET per OID.

        Re-deriving the engineID per OID would double the traffic and, on a
        /24, double the scan; boots/time from the discovery reply are reused
        for the whole batch (an agent with a strict timewindow can reject a
        later request, which simply shows up as a missing value).
        """
        authority = await self.discover(host, port)
        if authority is None or not authority.engine_id:
            return {}

        mpm, params = self._authorized(authority)
        values: dict[str, object] = {}
        for oid in oids:
            message = SNMPv3Message(
                msg_id=self.next_msg_id(),
                msg_flags=AUTH_FLAG | (PRIV_FLAG if params.privacy_key else 0),
            )
            message.security_parameters = params
            message.scoped_pdu = ScopedPDU(
                context_engine_id=authority.engine_id, pdu=GetRequest.from_oid(oid)
            )
            raw = await self._send_receive(_RawMessage(mpm.encode(message)), host, port)
            if raw is None:
                continue
            value = self._first_value(mpm, raw, params)
            if value is not None:
                values[oid] = value
        return values

    def _authorized(
        self, authority: SecurityParameters
    ) -> tuple[MPv3, SecurityParameters]:
        """Localize both keys to the authoritative engineID (RFC 3414 §2.6)."""
        mpm = MPv3(authority.engine_id)
        auth_protocol = resolve_auth_protocol(self.auth_protocol)
        params = SecurityParameters(
            engine_id=authority.engine_id,
            username=self.username,
            engine_boots=authority.engine_boots,
            engine_time=authority.engine_time,
            authentication_key=localize_passphrase(
                self.auth_passphrase, authority.engine_id, auth_protocol
            ),
            auth_protocol=self.auth_protocol,
        )
        if self.priv_passphrase:
            params.privacy_key = localize_privacy_key(
                self.priv_passphrase, authority.engine_id, self.priv_protocol
            )
            params.priv_protocol = self.priv_protocol
        return mpm, params

    def _first_value(
        self, mpm: MPv3, raw: bytes, params: SecurityParameters
    ) -> Optional[object]:
        """Verify and unwrap the first variable binding of a response.

        A MAC failure means the credentials are wrong (or the datagram is not
        from the peer we addressed), so it is reported as no value rather than
        trusted — an unverified "success" here would silently invent inventory.
        """
        try:
            decoded = mpm.decode(raw)
        except SNMPError:
            return None

        if decoded.security_parameters.mac:
            if not mpm.verify_message_mic(raw, params.authentication_key, self.auth_protocol):
                return None

        pdu = decoded.scoped_pdu.pdu if decoded.scoped_pdu else None
        if pdu is None and decoded.encrypted_data:
            context = PrivacyContext(
                params.priv_protocol,
                params.privacy_key,
                engine_boots=decoded.security_parameters.engine_boots,
                engine_time=decoded.security_parameters.engine_time,
            )
            plaintext = context.decrypt(
                decoded.encrypted_data, decoded.security_parameters.priv_parameters
            )
            scoped = ScopedPDU()
            scoped.decode(plaintext)
            pdu = scoped.pdu

        if pdu is None:
            return None
        for _oid, value in pdu:
            return value
        return None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

# Identity leaves pulled over v3 when credentials were supplied: one discovery
# plus a handful of GETs, enough to name a printer and read its serial.
V3_SERIAL_OID = resolve_oid(prtGeneralSerialNumber.instance(1, 1))
V3_LIFE_OID = resolve_oid(prtMarkerLifeCount.instance(1, 1))
V3_1284_OID = resolve_oid(ieee1284_id)
V3_IDENTITY_OIDS = (
    SYS_DESCR,
    SYS_OBJECT_ID,
    SYS_NAME,
    SYS_LOCATION,
    V3_SERIAL_OID,
    V3_LIFE_OID,
    V3_1284_OID,
)


def enrich_generic(device: Device, snmp: Session) -> None:
    """Host-level scalar identity that any SNMP agent may expose."""
    device.sys_name = device.sys_name or first_text(snmp, [SYS_NAME])
    device.sys_location = device.sys_location or first_text(snmp, [SYS_LOCATION])


def enrich_device(device: Device, args: argparse.Namespace) -> Device:
    """Open one v2c session per device and pull every enrichment in order."""
    is_brother = (
        enterprise_of(device.sys_object_id) == BROTHER_PEN
        or "brother" in device.sys_descr.lower()
    )
    try:
        with Session(
            device.address,
            port=args.port,
            community=args.community,
            timeout=args.timeout,
            retries=args.retries,
        ) as snmp:
            enrich_generic(device, snmp)
            if is_brother:
                enrich_brother(device, snmp)
            enrich_printers(device, snmp)
    except (SNMPError, OSError) as exc:
        device.error = type(exc).__name__
    return device


async def enrich_all(devices: Sequence[Device], args: argparse.Namespace) -> None:
    """Enrich every SNMP-live device, bounded by ``--parallel``."""
    semaphore = asyncio.Semaphore(args.parallel)

    async def one(device: Device) -> None:
        async with semaphore:
            await asyncio.to_thread(enrich_device, device, args)
            device.enriched = True

    await asyncio.gather(*(one(d) for d in devices))


def scan_print_ports(address: str, args: argparse.Namespace) -> list[str]:
    """TCP-connect probe for print services on hosts that ignore SNMP.

    A printer with SNMP disabled is still a printer: 9100 (jetdirect), 515
    (lpd) and 631 (ipp) are printer-specific, so any one of them is enough to
    classify.  80/443 are recorded as supporting evidence only, since routers
    serve those too.
    """
    found: list[str] = []
    for port in sorted(PRINT_SERVICE_PORTS):
        try:
            with socket.create_connection((address, port), timeout=args.connect_timeout):
                found.append(f"{port}/{PRINT_SERVICE_PORTS[port]}")
        except OSError:
            continue
    return found


async def probe_ports_all(devices: Sequence[Device], args: argparse.Namespace) -> None:
    """Port-probe only the hosts that never answered SNMP."""
    silent = [d for d in devices if not d.snmp]
    semaphore = asyncio.Semaphore(args.parallel)

    async def one(device: Device) -> None:
        async with semaphore:
            device.open_ports = await asyncio.to_thread(
                scan_print_ports, device.address, args
            )
            printing = [
                p
                for p in device.open_ports
                if p.split("/")[1] in ("jetdirect", "lpd", "ipp")
            ]
            if printing:
                device.is_printer = True
                device.add_reason("open print port " + ", ".join(printing))

    await asyncio.gather(*(one(d) for d in silent))


def make_v3_probe(args: argparse.Namespace) -> V3Probe:
    """Build a V3Probe from CLI credentials (no user means discovery only)."""
    probe = V3Probe()
    probe.timeout = args.timeout
    probe.username = args.v3_user
    probe.auth_passphrase = args.v3_auth
    probe.auth_protocol = args.v3_auth_type
    probe.priv_passphrase = args.v3_priv
    probe.priv_protocol = args.v3_priv_type
    return probe


async def sweep_v3(devices: list[Device], targets: Sequence[str], args: argparse.Namespace) -> None:
    """EngineID-discover every target and merge results into ``devices``.

    Hosts that already answered v2c get their engineID recorded; hosts that
    answer only v3 become new rows, so a v3-only printer is not lost.  When a
    username was supplied, a credentialed identity pass follows.
    """
    probe = make_v3_probe(args)
    by_address = {device.address: device for device in devices}
    semaphore = asyncio.Semaphore(args.parallel)

    async def discover_one(address: str) -> None:
        async with semaphore:
            try:
                authority = await probe.discover(address, args.port)
            except (SNMPError, OSError):
                return
            if authority is None or not authority.engine_id:
                return
            device = by_address.get(address)
            if device is None:
                device = Device(address=address)
                by_address[address] = device
                devices.append(device)
            device.engine_id = authority.engine_id.hex()
            device.add_reason("SNMPv3 engine ID (discovery)")

    await asyncio.gather(*(discover_one(a) for a in targets))

    if not args.v3_user:
        return

    async def credentialed(device: Device) -> None:
        async with semaphore:
            try:
                values = await probe.get_many(device.address, V3_IDENTITY_OIDS, args.port)
            except (SNMPError, OSError):
                return
            if not values:
                return

            device.snmp = True
            device.version = "v3"
            device.sys_descr = device.sys_descr or clean(values.get(SYS_DESCR))
            device.sys_object_id = device.sys_object_id or clean(values.get(SYS_OBJECT_ID))
            device.sys_name = device.sys_name or clean(values.get(SYS_NAME))
            device.sys_location = device.sys_location or clean(values.get(SYS_LOCATION))
            if device.sys_object_id and not device.vendor:
                device.vendor = vendor_label(device.sys_object_id)

            device_id = clean(values.get(V3_1284_OID))
            if device_id:
                fields = parse_1284_id(device_id)
                device.model = fields.get("MDL") or device.model
                device.serial = fields.get("SN") or device.serial
                if fields.get("MFG"):
                    device.vendor = fields["MFG"]
                device.add_reason("IEEE 1284 device ID")

            serial = clean(values.get(V3_SERIAL_OID))
            if serial and not device.serial:
                device.serial = serial
                device.add_reason("Printer-MIB serial")

            count = as_number(values.get(V3_LIFE_OID))
            if count is not None and device.page_count is None:
                device.page_count = count
                device.add_reason("Printer-MIB life count")

    await asyncio.gather(*(credentialed(d) for d in list(by_address.values())))


async def run_scan(args: argparse.Namespace) -> list[Device]:
    """Full pipeline: sweep, enrich, optional v3, optional ports, classify."""
    devices = await sweep_v2c(args.targets_resolved, args)

    if args.deep:
        await enrich_all([d for d in devices if d.snmp], args)

    if args.v3_probe or args.v3_user:
        await sweep_v3(devices, args.targets_resolved, args)
        if args.deep:
            # Only hosts the v3 pass newly brought to life — re-enriching a
            # v2c row would append its supply table a second time.
            await enrich_all(
                [
                    device
                    for device in devices
                    if device.snmp and not device.enriched and device.version != "v3"
                ],
                args,
            )

    if args.ports:
        await probe_ports_all(devices, args)

    for device in devices:
        classify(device)
    return devices


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


# Distinguishing nouns in a prtMarkerSuppliesDescription.  Taking only the
# first word collides ("Black Toner Cartridge" and "Black Drum Unit" both
# become "Black"), so the kind word is kept with it.
_SUPPLY_KINDS = {
    "toner", "drum", "belt", "fuser", "ink", "waste", "imaging", "transfer",
    "pickup", "maintenance", "staple", "bottle", "cartridge", "wiper",
}


def supply_label(description: str, index: object) -> str:
    """Short but unambiguous supply name: ``Black Toner``, ``Black Drum``, …"""
    words = description.split()
    if not words:
        return str(index or "?")
    if len(words) == 1:
        return words[0]
    kind = next((w for w in words[1:] if w.lower() in _SUPPLY_KINDS), "")
    return f"{words[0]} {kind}" if kind else words[0]


def toner_summary(device: Device) -> str:
    """Compact supply status, e.g. ``Black Toner:42% Black Drum:8%``."""
    parts: list[str] = []
    for supply in device.toner:
        description = str(supply.get("description") or "").strip()
        label = supply_label(description, supply.get("index"))
        level = supply.get("level")
        maximum = supply.get("max_capacity")
        if level is None:
            continue
        if isinstance(maximum, int) and maximum > 0:
            parts.append(f"{label}:{round(level * 100 / maximum)}%")
        else:
            parts.append(f"{label}:{level}")
    return " ".join(parts)


# A host that never answers is the normal outcome of a /24 sweep, not a
# finding — so these never appear in the EVIDENCE column.
_SILENCE = frozenset(
    {"SNMPTimeoutError", "no response", "OSError", "ConnectionRefusedError"}
)


def evidence_text(device: Device) -> str:
    """What the EVIDENCE column shows: classification reasons, else a surprise."""
    if device.reasons:
        return "; ".join(device.reasons)
    if device.error and device.error not in _SILENCE:
        return device.error
    return ""


def format_table(devices: Sequence[Device]) -> str:
    """Fixed-width inventory table."""
    header = ("ADDRESS", "VER", "VENDOR", "MODEL", "SERIAL", "PAGES", "TONER", "EVIDENCE")
    rows = [header]
    for device in devices:
        rows.append(
            (
                device.address,
                device.version or "-",
                device.vendor or "-",
                device.model or "-",
                device.serial or "-",
                "" if device.page_count is None else f"{device.page_count:,}",
                toner_summary(device) or "-",
                evidence_text(device) or "-",
            )
        )

    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    lines = [
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
        for row in rows
    ]
    rule = "  ".join("-" * width for width in widths)
    return "\n".join([lines[0], rule, *lines[1:]])


def format_details(device: Device) -> str:
    """Verbose block for one device, including the raw identity strings."""
    lines = [f"{device.address}  ({device.version or 'no SNMP'})"]
    for label, value in (
        ("vendor", device.vendor),
        ("model", device.model),
        ("serial", device.serial),
        ("pages", "" if device.page_count is None else str(device.page_count)),
        ("sysDescr", device.sys_descr),
        ("sysObjectID", device.sys_object_id),
        ("sysName", device.sys_name),
        ("sysLocation", device.sys_location),
        ("engineID", device.engine_id),
        ("ports", ", ".join(device.open_ports)),
        ("evidence", "; ".join(device.reasons)),
        ("error", device.error),
    ):
        if value:
            lines.append(f"    {label:<12} {value}")
    for supply in device.toner:
        lines.append(f"    {'supply':<12} {supply}")
    return "\n".join(lines)


def expectation_matches(devices: Sequence[Device], needle: str) -> Optional[Device]:
    """First device whose identity contains ``needle`` (case-insensitive)."""
    lowered = needle.lower()
    for device in devices:
        haystack = " ".join(
            (
                device.model,
                device.serial,
                device.sys_descr,
                device.sys_name,
                device.address,
                device.vendor,
            )
        ).lower()
        if lowered in haystack:
            return device
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _split_tokens(values: Sequence[str]) -> list[str]:
    """Let both ``-t a b`` and ``-t a,b`` forms address the same option."""
    tokens: list[str] = []
    for value in values:
        tokens.extend(part.strip() for part in value.split(","))
    return [token for token in tokens if token]


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Command line for the scanner."""
    parser = argparse.ArgumentParser(
        prog="snmp_scan_printers",
        description=(
            "Find printers on the LAN with read-only SNMP (GET/GETNEXT only) "
            "and print an inventory."
        ),
        epilog=(
            "With no target option, every non-virtual local IPv4 subnet is "
            "swept. Exit code 1 means --expect did not match."
        ),
    )

    addressing = parser.add_argument_group("targets")
    addressing.add_argument(
        "-t", "--targets", nargs="+", default=[], metavar="HOST",
        help="IP, CIDR or last-octet range (192.168.1.10-30); commas or spaces",
    )
    addressing.add_argument(
        "-s", "--subnet", nargs="+", default=[], metavar="CIDR",
        help="CIDR to sweep, e.g. 192.168.1.0/24",
    )
    addressing.add_argument(
        "-m", "--masscan", nargs="+", default=[], metavar="FILE",
        help="seed live hosts from a masscan -oB/-oJ output file",
    )
    addressing.add_argument(
        "--local", dest="address", action="store_true",
        help="sweep the local attached subnet(s)",
    )

    v2c = parser.add_argument_group("SNMPv1/v2c sweep")
    v2c.add_argument("-c", "--community", default="public", help="read community")
    v2c.add_argument("-p", "--port", type=int, default=161, help="UDP port")
    v2c.add_argument("--timeout", type=float, default=0.7, help="per-attempt timeout (s)")
    v2c.add_argument("--retries", type=int, default=1, help="attempts per request")
    v2c.add_argument("--parallel", type=int, default=128, help="concurrent probes")

    v3 = parser.add_argument_group("SNMPv3 (RFC 3414 USM)")
    v3.add_argument(
        "--v3-probe", action="store_true",
        help="harvest authoritative engine IDs; needs no credentials",
    )
    v3.add_argument("--v3-user", default="", help="USM username for an authenticated pass")
    v3.add_argument(
        "-A", "--v3-auth-type", default="SHA",
        help="MD5, SHA, SHA224/256/384/512, or a usm*AuthProtocol OID",
    )
    v3.add_argument("-U", "--v3-auth", default="", help="authentication passphrase")
    v3.add_argument(
        "-x", "--v3-priv-type", default="AES128",
        help="DES, AES128/192/256, or a usm*PrivProtocol OID",
    )
    v3.add_argument("-X", "--v3-priv", default="", help="privacy passphrase")

    output = parser.add_argument_group("output")
    output.add_argument(
        "--json", nargs="?", const="-", default=None, metavar="FILE",
        help="emit JSON to stdout, or to FILE",
    )
    output.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="add a detail block per device; -vv keeps non-printers in the table",
    )
    output.add_argument(
        "--all", action="store_true", help="list every answering host, not just printers"
    )
    output.add_argument(
        "--expect", default="", help="exit 1 unless a device matches this text"
    )
    output.add_argument(
        "--fast", dest="deep", action="store_false",
        help="identify only — skip the per-device enrichment walks",
    )
    output.add_argument(
        "--no-ports", dest="ports", action="store_false",
        help="skip TCP print-port probing of SNMP-silent hosts",
    )
    output.add_argument(
        "--connect-timeout", type=float, default=0.35, help="TCP probe timeout (s)"
    )
    parser.set_defaults(deep=True, ports=True)

    args = parser.parse_args(argv)
    args.targets = _split_tokens(args.targets)
    args.subnet = _split_tokens(args.subnet)
    if not (args.targets or args.subnet or args.masscan or args.address):
        args.address = True
    return args


def _address_key(address: str) -> list[int]:
    """Numeric sort key for a dotted quad, tolerating anything else."""
    parts = [int(p) if p.isdigit() else 0 for p in address.split(".")]
    return parts + [0] * (4 - len(parts))


def _has_signal(device: Device) -> bool:
    """A host worth listing: answered SNMP or exposed a service."""
    return bool(device.snmp or device.is_printer or device.open_ports)


def report(devices: Sequence[Device], args: argparse.Namespace) -> None:
    """Print (or write) the inventory in the requested shape."""
    printers = [device for device in devices if device.is_printer]
    seen = [device for device in devices if _has_signal(device)]
    # -vvv is the only mode that lists hosts which answered nothing at all.
    if args.verbose > 2:
        seen = list(devices)
    show_all = args.all or args.verbose > 1
    shown = seen if show_all else printers
    shown.sort(key=lambda d: (not d.is_printer, _address_key(d.address)))

    if args.json is not None:
        payload = {
            "scanned": len(devices),
            "snmp_live": sum(1 for d in devices if d.snmp),
            "printers": len(printers),
            "devices": [device.to_dict() for device in shown],
        }
        text = json.dumps(payload, indent=2)
        if args.json == "-":
            print(text)
            return
        Path(args.json).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {len(shown)} device(s) to {args.json}", file=sys.stderr)
        return

    print(format_table(shown))

    if args.verbose:
        print()
        for device in (printers or shown):
            print(format_details(device))
            print()


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point: resolve targets, scan once, report, apply ``--expect``."""
    args = parse_args(argv)
    args.targets_resolved = build_targets(args)
    if not args.targets_resolved:
        print("no targets resolved — pass -t/--subnet/--masscan", file=sys.stderr)
        return 2

    print(
        f"scanning {len(args.targets_resolved)} address(es) on udp/{args.port}"
        f" (community {args.community!r}) ...",
        file=sys.stderr,
    )
    started = time.monotonic()
    try:
        devices = asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    elapsed = time.monotonic() - started

    live = sum(1 for device in devices if device.snmp)
    printers = [device for device in devices if device.is_printer]
    print(
        f"{live} answered SNMP, {len(printers)} classified as printers"
        f" in {elapsed:.1f}s",
        file=sys.stderr,
    )

    # JSON goes out last so the progress lines on stderr never corrupt it.
    if args.json is None or args.json != "-":
        report(devices, args)

    if args.expect:
        match = expectation_matches(devices, args.expect)
        if match is None:
            print(f"NO MATCH for {args.expect!r}", file=sys.stderr)
            if args.json == "-":
                report(devices, args)
            return 1
        print(
            f"matched {args.expect!r}: {match.address}"
            f" {match.model or match.sys_descr}".rstrip(),
            file=sys.stderr,
        )

    if args.json == "-":
        report(devices, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())





