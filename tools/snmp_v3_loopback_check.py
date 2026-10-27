r"""Loopback validation of the SNMPv3 path in tools\snmp_scan_printers.py.

The MFC-9330CDW only answers SNMPv1/v2c, and turning on USM means changing the
device's configuration, so the scanner's v3 client cannot be proven against the
printer.  This script instead stands up a minimal authoritative engine on
127.0.0.1 using snmpy's own ``MPv3`` and drives the scanner's real code —
``V3Probe`` and ``sweep_v3`` — through the complete RFC 3414 exchange:

    1. engineID discovery with no credentials at all (RFC 3414 §4.1)
    2. an authNoPriv GET   (RFC 3414 §7, HMAC-SHA-96)
    3. an authPriv GET     (RFC 3414 §8 + RFC 3826, AES-128)
    4. a wrong-passphrase GET, which the agent must discard rather than answer
    5. ``sweep_v3`` turning a v3-only host into an identified inventory row

Each check reads what the agent actually observed on the wire, so a value that
arrived without a valid MAC — or without really being encrypted — fails as
loudly as a missing one.  Exit code 0 means all five stages passed.

Usage::

    .\.venv\Scripts\python.exe tools\snmp_v3_loopback_check.py
"""

from __future__ import annotations

import asyncio
import collections
import dataclasses
import importlib.util
import sys
import traceback
from pathlib import Path

# snmpy is installed editable into .venv; fall back to a sibling checkout.
_TOOLS_DIR = Path(__file__).resolve().parent
for _candidate in (_TOOLS_DIR, Path(r"D:\code\snmpy")):
    if (_candidate / "brother_oids.py").is_file() or (_candidate / "snmp").is_dir():
        if str(_candidate) not in sys.path:
            sys.path.insert(0, str(_candidate))

from ber.object import Integer, Null, ObjectIdentifier, OctetString, Sequence  # noqa: E402
from snmp.mpm import AUTH_FLAG, PRIV_FLAG, MPv3, SNMPv3Message  # noqa: E402
from snmp.pdus import GetResponse, Report  # noqa: E402
from snmp.privacy import PrivacyContext, localize_privacy_key  # noqa: E402
from snmp.scoped_pdu import ScopedPDU  # noqa: E402
from snmp.usm import SecurityParameters, localize_passphrase  # noqa: E402

HOST = "127.0.0.1"
ENGINE = bytes.fromhex("800000000400112233445566")  # 12 octets, RFC 3411 §5 format
BOOTS = 1
TIME = 42
USER = "maplesyrup"
AUTH_PASS = "auth-passphrase"
PRIV_PASS = "priv-passphrase"
DEVICE_ID = "MFG:Brother;MDL:MFC-9330CDW;CMD:SBR,MPL;SN:U63480K7J492832"

# usmStatsUnknownEngineIDs (RFC 3414 §14) — what an engine carries in the
# Report PDU that answers an engineID-discovery request.
STATS_UNKNOWN_ENGINE_IDS = "1.3.6.1.6.3.15.1.1.2.0"

@dataclasses.dataclass
class AgentUser:
    """One USM entry, holding keys already localized to ``ENGINE``."""

    name: str
    auth_protocol: str
    auth_key: bytes
    priv_protocol: str = ""
    priv_key: bytes = b""


def build_users() -> list[AgentUser]:
    """The single user this engine knows, with RFC 3414 §2.6 localized keys."""
    from snmp.privacy import resolve_auth_protocol

    return [
        AgentUser(
            name=USER,
            auth_protocol="SHA",
            auth_key=localize_passphrase(
                AUTH_PASS, ENGINE, resolve_auth_protocol("SHA")
            ),
            priv_protocol="AES128",
            priv_key=localize_privacy_key(PRIV_PASS, ENGINE, "AES128"),
        )
    ]


def build_mib(scanner: object) -> dict[str, object]:
    """A tiny static MIB addressed by the OIDs ``sweep_v3`` asks for."""
    return {
        scanner.SYS_DESCR: OctetString(b"Brother NC-8500h (loopback)").get_object(),
        scanner.SYS_OBJECT_ID: ObjectIdentifier.from_string(
            "1.3.6.1.4.1.2435.2"
        ).get_object(),
        scanner.SYS_NAME: OctetString(b"BRW001122334455").get_object(),
        scanner.SYS_LOCATION: OctetString(b"Loopback").get_object(),
        scanner.V3_1284_OID: OctetString(DEVICE_ID.encode()).get_object(),
        scanner.V3_SERIAL_OID: OctetString(b"U63480K7J492832").get_object(),
        scanner.V3_LIFE_OID: Integer.from_int(25258).get_object(),
    }


def _as_object(value: object) -> object:
    """A full BER Object from a helper value, an Object, or a plain Python value.

    ``Integer.from_int(...)`` and friends hand back an ``ObjectValue`` (a bytes
    subclass with ``get_object()``), while ``Object.decode`` hands back a full
    ``Object`` — which has a tag but no ``get_object()`` to call on it.
    """
    if hasattr(value, "get_object"):
        return value.get_object()
    if hasattr(value, "tag"):
        return value
    return OctetString(str(value).encode()).get_object()


def _var_binds(pairs: list[tuple[str, object]]) -> Sequence:
    """A BER varBindList from ``(oid, python-or-BER-Object)`` pairs."""
    entries = []
    for oid, value in pairs:
        entries.append(
            Sequence.from_list(
                [
                    ObjectIdentifier.from_string(oid).get_object(),
                    _as_object(value),
                ]
            )
        )
    return Sequence.from_list(entries)


class LoopAgent(asyncio.DatagramProtocol):
    """A USM engine that answers exactly what ``V3Probe`` sends.

    Deliberately strict: an authenticated request whose MAC does not verify is
    discarded with no reply, which is what RFC 3414 §2.5.2 step 4 permits and
    what makes the wrong-passphrase check meaningful — a lenient agent would let
    a broken client look correct.
    """

    def __init__(self, users: list[AgentUser], mib: dict[str, object]) -> None:
        self.mpm = MPv3(ENGINE)
        self.users = {user.name: user for user in users}
        self.mib = mib
        self.seen: collections.Counter = collections.Counter()
        self.transport = None

    def connection_made(self, transport) -> None:
        """Keep the endpoint so replies can be sent back to the requester."""
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            reply = self.handle(data)
        except Exception:  # noqa: BLE001 - never let a bug kill the event loop
            traceback.print_exc()
            return
        if reply is not None and self.transport is not None:
            self.transport.sendto(reply, addr)

    def handle(self, raw: bytes):
        """Process one request datagram; None means discard it."""
        request = self.mpm.decode(raw)
        params = request.security_parameters
        user = self.users.get(params.username)

        # EngineID discovery, or a message meant for a different engine: answer
        # unauthenticated with our authoritative parameters (RFC 3414 §4.1) so
        # the manager can localize and retry.
        if params.engine_id != ENGINE or user is None:
            self.seen["discovery"] += 1
            return self._report(request)

        if not self.mpm.verify_message_mic(raw, user.auth_key, user.auth_protocol):
            self.seen["rejected"] += 1
            return None

        pdu = self._request_pdu(request, params, user)
        if pdu is None:
            self.seen["undecryptable"] += 1
            return None

        self.seen["authenticated"] += 1
        if request.is_encrypted:
            self.seen["encrypted"] += 1
        return self._response(request, user, pdu)

    def _authority(self) -> SecurityParameters:
        """The authoritative half of the security parameters we hand back."""
        return SecurityParameters(
            engine_id=ENGINE, engine_boots=BOOTS, engine_time=TIME
        )

    def _report(self, request: SNMPv3Message) -> bytes:
        """A Report PDU carrying our authoritative engineID (discovery reply)."""
        params = self._authority()
        params.username = request.security_parameters.username
        report = Report(variable_bindings=_var_binds([(STATS_UNKNOWN_ENGINE_IDS, 1)]))
        message = SNMPv3Message(msg_id=request.msg_id, msg_flags=0, reportable=True)
        message.security_parameters = params
        message.scoped_pdu = ScopedPDU(
            context_engine_id=ENGINE, context_name="", pdu=report
        )
        return self.mpm.encode(message)

    def _request_pdu(self, request, params: SecurityParameters, user: AgentUser):
        """The request PDU, decrypting the msgData of an authPriv message."""
        if request.scoped_pdu is not None:
            return request.scoped_pdu.pdu
        if not request.encrypted_data or not user.priv_key:
            return None
        context = PrivacyContext(
            user.priv_protocol,
            user.priv_key,
            engine_boots=params.engine_boots,
            engine_time=params.engine_time,
        )
        try:
            plaintext = context.decrypt(request.encrypted_data, params.priv_parameters)
        except Exception:  # noqa: BLE001 - any cipher failure means discard
            return None
        scoped = ScopedPDU()
        scoped.decode(plaintext)
        return scoped.pdu

    def _response(self, request, user: AgentUser, pdu) -> bytes:
        """A Response mirroring the request's security level."""
        bindings = [
            (str(oid), self.mib.get(str(oid), Null().get_object()))
            for oid, _value in pdu
        ]
        response = GetResponse(
            request_id=pdu.request_id, variable_bindings=_var_binds(bindings)
        )

        flags = AUTH_FLAG if user.auth_key else 0
        if request.is_encrypted:
            flags |= PRIV_FLAG
        params = self._authority()
        params.username = user.name
        params.authentication_key = user.auth_key
        params.auth_protocol = user.auth_protocol
        params.privacy_key = user.priv_key
        params.priv_protocol = user.priv_protocol

        message = SNMPv3Message(
            msg_id=request.msg_id, msg_flags=flags, reportable=False
        )
        message.security_parameters = params
        message.scoped_pdu = ScopedPDU(
            context_engine_id=ENGINE, context_name="", pdu=response
        )
        return self.mpm.encode(message)


def load_scanner():
    """Import tools/snmp_scan_printers.py as a module — it is a script, not a package."""
    spec = importlib.util.spec_from_file_location(
        "snmp_scan_printers", str(_TOOLS_DIR / "snmp_scan_printers.py")
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def run_checks() -> list:
    """Drive every v3 stage against the loopback engine, collecting verdicts."""
    scanner = load_scanner()
    mib = build_mib(scanner)
    agent = LoopAgent(build_users(), mib)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: agent, local_addr=(HOST, 0)
    )
    port = transport.get_extra_info("sockname")[1]
    results: list = []

    try:
        probe = scanner.V3Probe()
        probe.timeout = 0.8
        probe.retries = 1
        oids = list(mib)

        # 1. Discovery must work with no credentials and yield our engineID.
        authority = await probe.discover(HOST, port)
        got = authority.engine_id.hex() if authority else ""
        results.append(
            (
                "engineID discovery (no credentials)",
                got == ENGINE.hex(),
                f"engineID {got or 'none'}, {agent.seen['discovery']} Report(s) sent",
            )
        )

        # 2. authNoPriv: every OID must come back, and the MAC must have
        #    verified on both sides (probe re-verifies, agent verified inbound).
        probe.username = USER
        probe.auth_protocol = "SHA"
        probe.auth_passphrase = AUTH_PASS
        values = await probe.get_many(HOST, oids, port)
        results.append(
            (
                "authNoPriv GET (HMAC-SHA-96)",
                len(values) == len(oids) and agent.seen["authenticated"] >= len(oids),
                f"{len(values)}/{len(oids)} OIDs,"
                f" {agent.seen['authenticated']} MAC-verified by agent",
            )
        )

        # 3. authPriv: values only count as a pass if they travelled encrypted.
        probe.priv_protocol = "AES128"
        probe.priv_passphrase = PRIV_PASS
        before = agent.seen["encrypted"]
        values = await probe.get_many(HOST, oids, port)
        encrypted = agent.seen["encrypted"] - before
        results.append(
            (
                "authPriv GET (AES-128, RFC 3826)",
                len(values) == len(oids) and encrypted == len(oids),
                f"{len(values)}/{len(oids)} OIDs, {encrypted} encrypted request(s)",
            )
        )
        # 4. A wrong passphrase must produce nothing, not a wrong value.
        probe.auth_passphrase = "not-the-right-passphrase"
        rejected_before = agent.seen["rejected"]
        values = await probe.get_many(HOST, [scanner.SYS_DESCR], port)
        results.append(
            (
                "wrong passphrase is discarded",
                not values and agent.seen["rejected"] > rejected_before,
                f"{len(values)} value(s),"
                f" {agent.seen['rejected'] - rejected_before} MAC rejection(s)",
            )
        )

        # 5. The scanner's own orchestration must build an identified row.
        args = scanner.parse_args(
            [
                "-t", HOST, "--v3-user", USER,
                "-A", "SHA", "-U", AUTH_PASS,
                "-x", "AES128", "-X", PRIV_PASS,
            ]
        )
        args.port = port
        args.timeout = 0.8
        devices: list = []
        await scanner.sweep_v3(devices, [HOST], args)
        device = devices[0] if devices else None
        results.append(
            (
                "sweep_v3 inventory row",
                device is not None
                and device.version == "v3"
                and device.model == "MFC-9330CDW"
                and device.serial == "U63480K7J492832"
                and device.engine_id == ENGINE.hex()
                and device.page_count == 25258,
                (
                    f"{device.version} {device.model} {device.serial}"
                    f" pages={device.page_count}"
                    if device
                    else "no device row"
                ),
            )
        )
    finally:
        transport.close()

    return results


def main() -> int:
    """Run the checks and report; exit 1 if any stage misbehaved."""
    results = asyncio.run(run_checks())
    width = max(len(name) for name, _ok, _detail in results)
    failed = 0
    for name, ok, detail in results:
        if not ok:
            failed += 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
    print()
    print(f"{len(results) - failed}/{len(results)} v3 stages passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
