# SPI dump day checklist (spare B57T054 board)

Use the **spare** main PCB only. Do not clip the production machine until a
verified dump + restore path exists.

Expected flash class: **16 MiB SPI NOR** (W25Q128 / GD25Q127 family) — matches
MAIN `hdr2[1]≈0x00f0857f`. Confirm with JEDEC ID before assuming.

Related: [`HARDWARE-AND-BOOT.md`](HARDWARE-AND-BOOT.md) · post-dump tool
[`tools/spi_dump/analyze_flash.py`](../tools/spi_dump/analyze_flash.py).

---

## 0. Kit

| Item | Notes |
| --- | --- |
| CH341A (or Bus Pirate / Raspberry Pi SPI) | **3.3 V I/O** — many CH341 boards are 5 V; level-shift or mod |
| SOP8 / WSON clip or soldered wires | CS, MISO, MOSI, SCK, VCC, GND; HOLD/WP → VCC if needed |
| Multimeter | Confirm 3.3 V on flash VCC before powering programmer |
| Camera / phone | Both sides of PCB + close-ups of SoC + flash markings |
| Host with `flashrom` | Linux preferred; Windows WSL or native builds also OK |
| Anti-static mat / wrist strap | CMOS SoC + flash |

Optional: SWD/JTAG leads if pads are labeled (core ID later).

---

## 1. Intake photos (before any clip)

- [ ] Top of PCB, full board  
- [ ] Bottom of PCB, full board  
- [ ] SoC marking (macro)  
- [ ] Flash package marking (macro) — record exact silkscreen / laser ID  
- [ ] EEPROM (if separate 8-pin)  
- [ ] Any unpopulated headers / test pads (SWD: SWDIO/SWCLK/GND/3V3/nRST)  
- [ ] PCB part number silk (`B57T054`, `LT2284…`, `D00EFW…`)

Save under e.g. `downloads/hardware/spare-board/photos/`.

---

## 2. Identify the flash

1. Power the flash from the programmer **only** if the rest of the board is
   isolated / not back-powered through other rails. Prefer removing the flash
   or cutting VCC if the SoC fights the bus.
2. Probe JEDEC ID:

```bash
flashrom -p ch341a_spi -c "GD25Q127C/GD25Q128C"   # or omit -c to probe
# look for: Found ... flash chip "W25Q128..." (16384 kB, SPI)
```

3. Record: manufacturer, part, size (kB), voltage.

If probe fails: check wiring, WP/HOLD, 3.3 V, try `-c` candidates, try lower
clock (`spispeed`).

---

## 3. Dump (read-only first)

```bash
mkdir -p downloads/hardware/spare-board/spi
flashrom -p ch341a_spi -c "<CHIP>" \
  -r downloads/hardware/spare-board/spi/flash_pass1.bin

# Immediate second pass — must match
flashrom -p ch341a_spi -c "<CHIP>" \
  -r downloads/hardware/spare-board/spi/flash_pass2.bin

# Windows PowerShell:
# fc /b flash_pass1.bin flash_pass2.bin
cmp downloads/hardware/spare-board/spi/flash_pass{1,2}.bin \
  && cp downloads/hardware/spare-board/spi/flash_pass1.bin \
        downloads/hardware/spare-board/spi/flash.bin
```

- [ ] Two reads identical  
- [ ] File size == chip size (16 MiB → 16777216 bytes)  
- [ ] SHA256 recorded in `downloads/hardware/spare-board/SPI-NOTES.md`

**Do not** `-w` / erase until a known-good dump is archived off the machine.

---

## 4. Offline analyze (same day)

```powershell
cd d:\code\mfc9330cdw
python tools\spi_dump\analyze_flash.py `
  downloads\hardware\spare-board\spi\flash.bin `
  --out downloads\hardware\spare-board\spi\analysis
```

Check the report for:

- [ ] Entropy valleys (possible uncompressed boot / vectors)  
- [ ] `*Adr` / `Kernel` / `T-Kernel` / `ProgramOK` / DJF magics  
- [ ] zlib/`78 9c`/`78 da` stream hits  
- [ ] Size vs MAIN `hdr2[1]=0x00f0857f` discussion in the report  

Then:

```bash
binwalk -e -C downloads/hardware/spare-board/spi/binwalk flash.bin
```

---

## 5. Ghidra (after carve)

1. Import lowest-entropy / decompressed segments first.  
2. Language: **ARM little-endian 32-bit** (first guess).  
3. Load base: from address table if found; else try `0x00000000` and
   sibling-style `0x40000000+`.  
4. Sanity: MAIN unpacked length ≈ `0x00f0857f` if a full MAIN image is present.  
5. Hunt strings: `BRDOWNLOAD`, `PROGRAMLENG`, `ProgramOK`, `Decrypt`, zlib.

---

## 6. Optional SWD

If pads exist and the board can run:

- Connect under reset; dump ROM table / DPIDR (confirms A9 vs 926 etc.).  
- Watchdog may reset on halt (sibling inkjet) — early halt after nRST.

---

## 7. Stop conditions

| Symptom | Action |
| --- | --- |
| Chip ID unstable / wrong size | Rewire; stop before write |
| Pass1 ≠ Pass2 | Bad clip contact; re-dump |
| SoC gets hot while clipped | Back-power; isolate VCC |
| Only 0xFF / 0x00 dump | Wrong chip selected or held in reset |

---

## Record template (`SPI-NOTES.md`)

```text
Date:
Board PN / silk:
SoC marking:
Flash marking:
flashrom programmer / -c chip:
Size bytes:
SHA256 flash.bin:
Notes (isolation, voltage, SWD pads):
```
