# Binwalk results (MFC-9330CDW `.djf`)

Ran with WSL Arch **binwalk 3.1.0** (`/usr/sbin/binwalk`). Scripts:

- [`../binwalk-all.sh`](../binwalk-all.sh) — scan + extract each `.djf`
- [`../binwalk-carve.sh`](../binwalk-carve.sh) — strip PJL `DATA=` header, rescan payloads
- [`../analyze_payloads.py`](../analyze_payloads.py) — header / entropy summary

Installed helper: `p7zip` (`7z`). `srecord` / `srec2bin` are **not** in Arch repos; not needed after confirming the panel “S-record” hit is a false positive.

## Default scan (no `-a`)

Only the PJL wrapper is recognized:

| File | Hit |
| --- | --- |
| all `*.djf` | `HP Printer Job Language` @ `0x0` (`@PJL EXECUTE BRDOWNLOAD …`) |

## Deep scan (`-a`) / carved payloads

Carved payloads live under [`carved/`](carved/) (`*.payload.bin`).

### Real structure (not a stock filesystem image)

After the 75-byte PJL header, each large blob starts with a **Brother download identity** plus a typed chunk:

| Payload | Identity | Type tag @ `0x18` | Size | Entropy |
| --- | --- | --- | ---: | ---: |
| `LZ4266_ZC_1` | `MFC-9130USA` | `PROG` | 10 943 219 | 7.965 |
| `LZ4267_H` | `DCLFBPCLUSA` | `ROM2` | 7 080 211 | 7.907 |
| `LZ4279_R` | `PNL-DCLMUSA` | `PANL` | 13 111 208 | 7.942 |
| `LZ3196_A` | `X` | `PROG` | 259 | 6.480 |

Example MAIN head:

```text
4d46432d3931333055534100  …  50524f47 00000010 00a6facc …
M F C - 9 1 3 0 U S A \0     P R O G  hdrlen?   size-ish
```

High entropy (~7.9 bits/byte) on MAIN/SUB1/SUB2 means the body is **opaque to stock
signatures** — proprietary pack/transform (not proven AES). See [`../FORMAT.md`](../FORMAT.md)
for entropy maps and the **period-7** framed valleys (PANL / MAIN plateau).

### Signature noise (treat as false positives)

With `-a`, binwalk reports many tiny **zlib** / **GPG signed** / **compress’d** hits inside MAIN and SUB1. Extracted `decompressed.bin` sizes are **1–1634 bytes** (90 files) — consistent with accidental magic matches in high-entropy data, not real embedded archives.

Panel (`LZ4279_R`) reports **Motorola S-record @ `0xC281`**. Inspection shows binary after `S0`, not ASCII hex records (`S0060000…`). Printable ratio ~0.33. **Not a real S-record image**; `srec2bin` extraction fails for the same reason.

## Entropy / deeper passes

Binwalk 3.1 has **no** classic `-A` opcode scan. `-E` (entropy plot) crashes here
(missing `sans-serif` font in the WSL image). Use the Python tools instead:

```powershell
python tools\djf_parse\entropy_map.py    # *.payload.entropy.csv / .txt
python tools\djf_parse\period7_scan.py   # 7-byte framed valleys
wsl -e bash /mnt/d/code/mfc9330cdw/downloads/firmware/blobs/binwalk-entropy.sh  # if fonts fixed
```

| Finding | Detail |
| --- | --- |
| PANL valley ~`0x664000`–`0x72a400` | H≈6.38; **896-byte period-128 pad tile** (~6% of body) |
| MAIN plateau ~`0x9ff000`+ | same family-B pad (~5% of body) |
| SUB1 | no period-7 islands |
| Deep-scan zlib/GPG | still false positives (90 carves ≈ 28 KiB total) |

Tiles/residuals: `carved/period7_templates/` (`decode_period7.py`).

## Takeaways for RE

1. Strip PJL → work on `*.payload.bin`.
2. Parse Brother identity + `PROG` / `ROM2` / `PANL` header (custom format).
3. Body is proprietary-packed; chase period-7 codec before expecting ELF/uImage.
4. Do not trust deep-scan zlib/GPG/S-record hits without validating sizes and ASCII structure.

## Artifact layout

```text
binwalk/
  README.md                 ← this file
  LZ*.djf.binwalk.txt       ← default scan logs
  LZ*.djf.binwalk.json
  LZ*.djf.extract.log
  LZ*.djf.extracted/        ← mostly noise chunks
  carved/
    *.payload.bin           ← PJL-stripped bodies (useful)
    *.payload.entropy.csv   ← sliding-window map (Python)
    *.payload.entropy.txt
    *.binwalk.txt
    *.extract.log
```
