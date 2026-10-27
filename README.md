# MFC-9330CDW — firmware & management-plane reverse engineering

Notes and tooling for the Brother MFC-9330CDW: DJF firmware container format,
the `firmverup` update protocol, SNMP surface (MIB-2 / Printer-MIB / Brother
PEN 2435), the web+telnet management services, and the SPI flash recovery path.

The unit under study sits at `192.168.1.71` (serial `U63480K7J492832`,
`3c:2a:f4:35:90:5f`); those identifiers appear throughout `docs/`.

## Layout

| Path | Contents |
| --- | --- |
| [`docs/`](docs/README.md) | Analysis: device map, hardware/boot model, SPI checklist |
| [`tools/`](tools/) | Analysis scripts (SNMP, DJF parsing, firmverup client, SPI dump aid) |
| [`scripts/`](scripts/) | PowerShell fetchers that rebuild `downloads/` from Brother's site |
| `downloads/` ([notes](downloads/README.md)) | **Untracked** vendor artifacts + our provenance notes |
| `reference/` | **Untracked** nested clone of `b1tninja/010editor-reference` |

## Setup

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

Several tools import [`snmpy`](https://github.com/b1tninja/snmpy) (`snmp`, `ber`)
and add it to `sys.path` from the sibling checkout `d:\code\snmpy`. Keep that
repo next to this one, or adjust the path in the tool you run.

Examples:

```powershell
.\.venv\Scripts\python.exe tools\snmp_scan_printers.py --expect MFC-9330CDW
.\.venv\Scripts\python.exe tools\snmp_v3_loopback_check.py   # offline SNMPv3 check
powershell -ExecutionPolicy Bypass -File scripts\download-all.ps1   # rebuild downloads/
```

## Scope

Research targets a device owned by the author, for interoperability,
recovery, and security analysis. Several tools send authentication challenges
or write to the device (`tools/brcrypt_confirm.py`, `tools/telnet_login_probe.py`,
the `admin100` SNMP tree); they can lock or brick a unit. Keep this repository
private while that tooling and the firmware handling remain under study.

Questions or concerns about material in this repository? Contact
[4584655+b1tninja@users.noreply.github.com](mailto:4584655+b1tninja@users.noreply.github.com)
— contact is checked regularly and legitimate removal requests are actioned
directly and promptly.
