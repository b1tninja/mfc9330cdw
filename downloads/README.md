# MFC-9330CDW support downloads

Catalogued from `support.brother.com.har` (hardly session) and expanded across current Brother OS lists (Windows + Linux). Files live under this tree (~492 MB, 60 artifacts).

## Layout

| Folder | Contents |
|--------|----------|
| `drivers/` | Full package, printer/scanner drivers, XPS, BR-Script, Universal PS |
| `drivers/linux/` | LPR/CUPS/scanner/PC-FAX/rpm+deb (+ CUPS GPL source tarball) |
| `drivers/other-os/` | Win10-32-only extras (BR-Script 32-bit, PaperPort tool) |
| `firmware/` | Firmware Update Tool installer |
| `firmware/blobs/` | Fetched `.djf` packages (MAIN/SUB1/SUB2/IFAX) — see [blobs README](firmware/blobs/README.md) |
| `utilities/` | Wireless helper, net repair, uninstall, SAP, status monitor, etc. |
| `management/` | BRAdmin Light/Professional, BRAgent, Mass Deployment Tool |
| `manuals/` | All PDFs from the Manuals page |
| `meta/` | Catalog, resolved URLs, manifests, scraped HTML, hardly site brief |

## Firmware

Device + firmverup notes: [`docs/MFC-9330CDW.md`](../docs/MFC-9330CDW.md).

The support site still only offers the **Firmware Update Tool** installer
(`BrMain4905.exe`). The actual images are resolved at runtime via firmverup.
Current packages for this unit (**SPEC `0401`**) are mirrored under
[`firmware/blobs/`](firmware/blobs/README.md):

| Public label | File | Version |
| --- | --- | --- |
| Main ZC | `LZ4266_ZC_1.djf` | `ZC2311081154` |
| Sub 1.10 | `LZ4267_H.djf` | `1.10` |
| Panel R | `LZ4279_R.djf` | `R2311081800` |
| IFAX | `LZ3196_A.djf` | `i0801170900` |

### Changelog history (support page)

Brother lists older combined releases on the Firmware Update Tool page, but
those builds are not separate public files:

- 04/30/2026 Main ZC / Sub 1.10 / Panel R
- 09/07/2023 ZB / 1.10 / Q
- 01/10/2019 ZA / 1.10 / Q
- 04/12/2018 Z / 1.10 / N (default web password after network reset)
- … back through Main P (Mopria), 12/04/2014

## Gaps

- **macOS / legacy Windows (Vista/XP/etc.)**: listed under “Older OS Versions”, but the live pages no longer emit download links (product is EOL for those families). Active Mac radio pane is empty; site notes Brother no longer provides new software for some discontinued OS lines.
- **Software User’s Guide**: HTML-only online manual (URL in `meta/catalog.json`), not a PDF.
- **Historical driver versions**: each `dlid` is the current file for that product line, not a full version archive.

## Re-run

```powershell
powershell -File scripts\download-all.ps1
powershell -File scripts\expand-other-os.ps1
```
