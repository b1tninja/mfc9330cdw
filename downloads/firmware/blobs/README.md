# MFC-9330CDW firmware blobs

Local copies of firmverup packages for **MFC-9330CDW / SPEC `0401`**, fetched
2026-10-24 from Brother’s update CDN. Device overview:
[`docs/MFC-9330CDW.md`](../../../docs/MFC-9330CDW.md).

Machine-readable catalog: [`inventory.json`](inventory.json).

> **Do not commit these `.djf` files** to a public repository. They are Brother
> firmware redistributed only for local research / backup on owned hardware.

## Available packages

| Category | Latest | File | Size | CDN |
| --- | ---: | --- | ---: | --- |
| MAIN | `ZC2311081154` | [`LZ4266_ZC_1.djf`](LZ4266_ZC_1.djf) | 10 443 294 | `http://update-akamai.brother.co.jp/CS/LZ4266_ZC_1.djf` |
| SUB1 | `1.10` | [`LZ4267_H.djf`](LZ4267_H.djf) | 7 080 286 | `…/LZ4267_H.djf` |
| SUB2 | `R2311081800` | [`LZ4279_R.djf`](LZ4279_R.djf) | 13 111 283 | `…/LZ4279_R.djf` |
| IFAX | `i0801170900` | [`LZ3196_A.djf`](LZ3196_A.djf) | 334 | `…/LZ3196_A.djf` |

### Not offered (SPEC `0401`)

`fileUpdate` returned `VERSIONCHECK=2` (no `PATH`) for:

`PCLPS`, `ENGINE`, `SUB3`, `SUB4`, `SUB5`, `BRNET`

## Container format (`.djf`)

Full write-up: [`FORMAT.md`](FORMAT.md). Short version:

PJL `BRDOWNLOAD` wrapper → identity/`PROG|ROM2|PANL` headers → **opaque high-entropy
body** → plaintext footer `…ProgramOK` + BCD version + checksum.

| File | Tag | Identity | Footer BCD version |
| --- | --- | --- | --- |
| `LZ4266_ZC_1.djf` | `PROG` | `MFC-9130USA` | `2311081154` (= ZC…) |
| `LZ4267_H.djf` | `ROM2` | `DCLFBPCLUSA` | `1803051406` |
| `LZ4279_R.djf` | `PANL` | `PNL-DCLMUSA` | `2311081829` |
| `LZ3196_A.djf` | `PROG` | `X` | (stub) |

PROG/PANL bodies share magic `61b654adf6da9da6f565803f`; ROM2 uses
`XX803ee3129a55af0fc0c0c0` (first byte varies). Multi-model compare:
[`../corpus/COMPARE.md`](../corpus/COMPARE.md). Body not decrypted yet.

## Mapping to Brother’s public changelog

Brother’s Firmware Update Tool page historically lists combined labels such as
**Main ZC / Sub 1.10 / Panel R**. That lines up with:

| Public label | Blob | `LATESTVERSION` |
| --- | --- | --- |
| Main ZC | `LZ4266_ZC_1.djf` | `ZC2311081154` |
| Sub 1.10 | `LZ4267_H.djf` | `1.10` |
| Panel R | `LZ4279_R.djf` | `R2311081800` |

Older Main letters are **not** listed on the support site, but some prior CDN
filenames still 200 (`cdn_older/`, see `cdn_probe.txt`). Sampled S/T (MAIN),
B (SUB1), H (PANL) — still high-entropy with the same PROG magic; not a
plaintext rollback path.

Wayback / CDN extras in `cdn_older/`: truncated `LZ4266_W`; full **`LZ4228_P.djf`**
(live Akamai, inkjet BH13 MAIN with plaintext `Upd*Address` @ `0x08000000` —
see `LZ4228_P_full/GHIDRA.txt`); full `LZ4217_X` (PROG) and `LZ4219_B`/`_F`
(ROM2). Index: [`FORMAT.md`](FORMAT.md), `../corpus/wayback_cdx_akamai.txt`.

This unit’s live ROM (2026-10-25): MAIN **ZC** / SUB1 **1.10** / SUB2
**R2311081800**, Web UI RAM **192 MB** —
[`../meta/live-inventory-2026-10-25.md`](../meta/live-inventory-2026-10-25.md).

## How these were fetched

```powershell
brother-firmware download-all `
  --model MFC-9330CDW --spec 0401 `
  --out-dir d:\code\mfc9330cdw\downloads\firmware\blobs
```

Equivalent firmverup facts:

- Endpoint: `https://firmverup.brother.co.jp/kne_bh7_update_nt_ssl/ifax2.asmx/fileUpdate`
- Successful MAIN probe used `NAME=MFC-9330CDW`, `SPEC=0401`, `DRIVER=EWS`
- Seed / older `VERSION` values force `VERSIONCHECK=0` so the server returns a `PATH`

Per-category XML responses are saved alongside as `fileUpdate-<CATEGORY>.xml`.

## Binwalk

See [`binwalk/README.md`](binwalk/README.md). Short version: stock binwalk only
reliably sees the PJL wrapper; carved payloads are a custom Brother container
(`PROG` / `ROM2` / `PANL`) with ~7.9 entropy (compressed/encrypted). Deep-scan
zlib/GPG/S-record hits are almost certainly false positives.

```powershell
wsl -e bash /mnt/d/code/mfc9330cdw/downloads/firmware/blobs/binwalk-all.sh
wsl -e bash /mnt/d/code/mfc9330cdw/downloads/firmware/blobs/binwalk-carve.sh
```

## Flashing (dangerous)

Uploading a `.djf` to a printer (TCP 9100 raw / FTP / official updater) can
brick the device if interrupted or mismatched. Prefer the official updater for
production units. This tree is for **analysis and backup**, not a flash guide.
