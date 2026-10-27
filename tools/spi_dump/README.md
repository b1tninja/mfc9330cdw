# SPI dump helpers

Day-of procedure: [`docs/SPI-DUMP-CHECKLIST.md`](../../docs/SPI-DUMP-CHECKLIST.md).

## Analyze a dump

```powershell
cd d:\code\mfc9330cdw
python tools\spi_dump\analyze_flash.py `
  downloads\hardware\spare-board\spi\flash.bin `
  --out downloads\hardware\spare-board\spi\analysis
```

Writes `REPORT.md`, `entropy_4k.csv`, interesting strings, and any zlib carves.

## flashrom (Linux example)

```bash
# probe
flashrom -p ch341a_spi

# read (chip name from probe)
flashrom -p ch341a_spi -c "W25Q128.V" -r flash.bin
```

Use **3.3 V** signaling. Prefer the spare B57T054 board.

## Place artifacts

```text
downloads/hardware/spare-board/
  photos/
  spi/
    flash.bin          # verified dual-read
    SPI-NOTES.md
    analysis/          # analyze_flash.py output
    binwalk/
```

Keep dumps out of public git (same hygiene as `.djf` blobs).
