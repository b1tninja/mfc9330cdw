"""Brother enterprise SNMP OID pack (PEN 2435) for MFC-9330CDW recon.

Lives in this repo — snmpy stays RFC/generic (``mib2-system``, ``printer-mib``).
Importing this module registers pack ``brother`` with snmpy's ``PACKS``.

Usage::

    from snmp import Session
    from brother_oids import BROTHER, challenge, confirm

    with Session(host, community="public", set_community="internal") as snmp:
        nonce = snmp.get_bytes(challenge)

CLI (from repo root, with snmpy on PYTHONPATH)::

    python -m snmpy --import tools.brother_oids packs
    python -m snmpy --import tools.brother_oids get --pack brother --hex HOST challenge
"""

from __future__ import annotations

from snmp.oid import Oid, OidPack, register_pack
from snmp.mib_printer import (  # re-export RFC Printer-MIB for local convenience
    PRINTER,
    printmib,
    prtConsoleDisplayBufferText,
    prtGeneralPrinterName,
    prtGeneralSerialNumber,
    prtMarkerLifeCount,
    prtMarkerSuppliesDescription,
    prtMarkerSuppliesLevel,
    prtMarkerSuppliesMaxCapacity,
)

BROTHER = OidPack(
    name="brother",
    pen=2435,
    doc="Brother Industries enterprise OIDs (PEN 2435) — MFC-9330CDW / NC-8500h",
    oids=[
        Oid(
            "brother",
            "1.3.6.1.4.1.2435",
            doc="IANA private enterprise number 2435 (Brother Industries)",
        ),
        Oid(
            "brother_mfp",
            "1.3.6.1.4.1.2435.2.4.3",
            doc="Main MFP / network tree",
        ),
        Oid(
            "admin100",
            "1.3.6.1.4.1.2435.2.4.3.2435.5.100",
            doc="Admin100 tree — password presence + challenge/confirm",
        ),
        Oid(
            "pwd_set",
            "1.3.6.1.4.1.2435.2.4.3.2435.5.100.1.1.0",
            syntax="OCTET STRING",
            access="ro",
            scalar=True,
            doc="Often b'\\x01' when a password is configured",
        ),
        Oid(
            "challenge",
            "1.3.6.1.4.1.2435.2.4.3.2435.5.100.10.1.0",
            syntax="OCTET STRING",
            access="ro",
            scalar=True,
            doc="20-byte challenge; changes on every GET",
        ),
        Oid(
            "confirm",
            "1.3.6.1.4.1.2435.2.4.3.2435.5.100.10.2.0",
            syntax="OCTET STRING",
            access="wo",
            scalar=True,
            doc="Confirm SET target (empty on GET); write community required",
        ),
        Oid(
            "confirm_sibling",
            "1.3.6.1.4.1.2435.2.4.3.2435.5.100.10.3.0",
            syntax="OCTET STRING",
            access="wo",
            scalar=True,
            doc="Sibling of confirm; empty on GET — treat as write-ish",
        ),
        Oid(
            "fallback_pwd",
            "1.3.6.1.4.1.1240.2.3.4.1.6.0",
            syntax="OCTET STRING",
            access="rw",
            scalar=True,
            doc="Fallback SET password octets (PEN 1240 path)",
        ),
        Oid(
            "firm_root",
            "1.3.6.1.4.1.2435.2.4.3.99.3.1.6.1.2",
            access="ro",
            scalar=False,
            doc="Walk root for MODEL / SPEC / MAIN / SUB1 / SUB2 firm ID strings",
        ),
        Oid(
            "trays",
            "1.3.6.1.4.1.2435.2.4.3.99.3.1.2.1.2",
            access="ro",
            scalar=False,
            doc="Tray / media description table column",
        ),
        Oid(
            "nc8500",
            "1.3.6.1.4.1.2435.2.4.3.1240.1",
            doc="NC-8500h identity tree",
        ),
        Oid(
            "nc8500_community",
            "1.3.6.1.4.1.2435.2.4.3.1240.1.15.0",
            syntax="OCTET STRING",
            access="ro",
            scalar=True,
            doc="NC-8500h community string leaf",
        ),
        Oid(
            "ieee1284",
            "1.3.6.1.4.1.2435.2.3.9.1.1.7",
            access="ro",
            scalar=False,
            doc="IEEE 1284 device ID tree",
        ),
        Oid(
            "ieee1284_id",
            "1.3.6.1.4.1.2435.2.3.9.1.1.7.0",
            syntax="OCTET STRING",
            access="ro",
            scalar=True,
            doc="Full IEEE 1284 device ID string (MFG:Brother;MDL:…)",
        ),
        Oid(
            "ldap_fax_attr",
            "1.3.6.1.4.1.2435.2.4.3.2435.5.19.12.1.11",
            access="ro",
            scalar=False,
            doc="LDAP / addr-book attribute facsimileTelephoneNumber",
        ),
    ],
)
register_pack(BROTHER, replace=True)

brother = BROTHER["brother"]
brother_mfp = BROTHER["brother_mfp"]
admin100 = BROTHER["admin100"]
pwd_set = BROTHER["pwd_set"]
challenge = BROTHER["challenge"]
confirm = BROTHER["confirm"]
confirm_sibling = BROTHER["confirm_sibling"]
fallback_pwd = BROTHER["fallback_pwd"]
firm_root = BROTHER["firm_root"]
trays = BROTHER["trays"]
nc8500 = BROTHER["nc8500"]
nc8500_community = BROTHER["nc8500_community"]
ieee1284 = BROTHER["ieee1284"]
ieee1284_id = BROTHER["ieee1284_id"]
ldap_fax_attr = BROTHER["ldap_fax_attr"]

__all__ = [
    "BROTHER",
    "PRINTER",
    "brother",
    "brother_mfp",
    "admin100",
    "pwd_set",
    "challenge",
    "confirm",
    "confirm_sibling",
    "fallback_pwd",
    "firm_root",
    "trays",
    "nc8500",
    "nc8500_community",
    "ieee1284",
    "ieee1284_id",
    "ldap_fax_attr",
    "printmib",
    "prtGeneralSerialNumber",
    "prtGeneralPrinterName",
    "prtMarkerLifeCount",
    "prtMarkerSuppliesDescription",
    "prtMarkerSuppliesMaxCapacity",
    "prtMarkerSuppliesLevel",
    "prtConsoleDisplayBufferText",
]
