# firmverup

Python client for Brother’s firmware update servlet, reverse-engineered from
`FirmwareUpdater.exe` (`CBrInet::VerCheck` / `CBrInet::FileUpdate`) and
`res/BrUpdSys.xml`.

## How the updater works

`FirmwareUpdater.exe` is a **generic online client** — it does not ship model
firmware. The vendor server resolves download `PATH`s from:

| Field | Working value (MFC-9330CDW) |
| --- | --- |
| `NAME` | `MFC-9330CDW` (not the Windows driver string) |
| `SPEC` | `0401` (region/SKU; from SNMP on a live printer) |
| `DRIVER` | `EWS` |
| `FIRM/ID` + `VERSION` | category + a real-looking older version |
| User-Agent | `BrHttpc/1.00` |

`VERSIONCHECK`: `0` = update available (`PATH` present), `1` = already current,
`2` = rejected model/SPEC/context.

## Setup

```powershell
d:\code\mfc9330cdw\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Usage (from repo root)

```powershell
$py = ".\.venv\Scripts\python.exe"

# Model catalog + firm ID list
& $py -m tools.firmverup ver-check

# fileUpdate metadata for one category
& $py -m tools.firmverup file-update --category MAIN -v

# Download every category that returns a PATH
& $py -m tools.firmverup download-all --skip-existing

# Sweep categories (VERSIONCHECK matrix)
& $py -m tools.firmverup probe
```

Blobs land in `downloads/firmware/blobs/` with `inventory.json`.

## Endpoints (BrUpdSys.xml)

- `verCheck` → `https://firmverup.brother.co.jp/kne_bh7_update_nt_ssl/ifax2.asmx/verCheck`
- `fileUpdate` → `https://firmverup.brother.co.jp/kne_bh7_update_nt_ssl/ifax2.asmx/fileUpdate`
