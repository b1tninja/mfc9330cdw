# Brother `.djf` / BRDOWNLOAD format (notes)

Empirical layout from MFC-9330CDW packages (`LZ4266_ZC_1`, `LZ4267_H`,
`LZ4279_R`, `LZ3196_A`). Parser: [`tools/djf_parse/parse_djf.py`](../../../tools/djf_parse/parse_djf.py).

The Windows updater does **not** parse this structure (see
[`docs/MFC-9330CDW.md`](../../../docs/MFC-9330CDW.md)); the printer does.

## Layers

```text
┌─ PJL job wrapper ─────────────────────────────────────────────┐
│  <ESC>%-12345X@PJL EXECUTE BRDOWNLOAD                         │
│  PROGRAM=FIRM | IFAX                                          │
│  PROGRAMLENG=<hex length of following program image>          │
│  DATA=                                                        │
├─ Brother download image ──────────────────────────────────────┤
│  prefix (identity / memver / mystery)                         │
│  tagged record (PROG | ROM2 | PANL) + hdr2                    │
│  opaque body  (proprietary pack; ≈7.9 ent, period-7 islands)  │
│  plaintext footer …ProgramOK + BCD version + csum + CRLF+FF   │
│  optional trailing UEL <ESC>%-12345X                          │
└───────────────────────────────────────────────────────────────┘
```

## PJL wrapper

| Field | Meaning |
| --- | --- |
| `PROGRAM` | Outer job type (`FIRM` for MAIN/SUB1/SUB2, `IFAX` for fax stub) |
| `PROGRAMLENG` | Hex length of the program image after `DATA=` (usually `payload_len - 3`, excluding final `\r\n\x0c` accounting quirks; PANL may also append UEL) |

## Prefix (before tag)

Typical large-image prefix (tag at `0x18`):

| Offset | Size | Content |
| ---: | ---: | --- |
| `0x00` | ≤12 | Identity ASCII + `NUL` (`MFC-9130USA`, `DCLFBPCLUSA`, `PNL-DCLMUSA`) |
| `0x0c` | 4 | **Firm letter** ASCII + NUL pad (`S`/`T`/`Z`/`D`…; ROM2/PANL often `0`) — matches firmverup letter |
| `0x10` | 6 | Per-image stamp (high bytes track size *class* across models; not body length, not CRC/Adler/SHA of body or of image-with-field-zeroed) |
| `0x16` | 2 | `00 01` |

## Tagged record

| Offset (from tag) | Content |
| ---: | --- |
| `+0` | Tag ASCII: `PROG` (MAIN/IFAX), `ROM2` (SUB1), `PANL` (SUB2/panel) |
| `+4` | `u32be` = `0x10` |
| `+8` | `u32be size_a` — for FIRM images, `PROGRAMLENG - 0x24` |
| `+c` | `u32be flags` = `0x00010102` (constant on these samples) |
| `+10` | `u32be` = `0x24` (length of following hdr2) |
| `+14` | `hdr2[0x24]` — sizes + unknown fields + trailing magic |
| `+14+0x24` | **Body** start |

### `hdr2[0x24]` (big-endian dwords, FIRM samples)

| Dword | Role (empirical) |
| ---: | --- |
| `[0]` | ≈ `body_len + 6..8` (packed size; exact on MAIN/SUB1/SUB2; IFAX stub nonsense) |
| `[1]` | **Load/map high-water** (see below) — often ~`0x00f0xxxx` (just under 16 MiB) |
| `[2]` | **Family discriminator**: PROG `0xa4020000`, PANL `0x08020000`, IFAX `0xf8010000`, ROM2 `0xa6000000` |
| `[3]` | ≈ `[0] + 0x24..0x27` |
| `[4]` | `0` |
| `[5]` | Always `0x0000001b` |
| `[6]` | MAIN-era: **`[1] + 0x10000|0x20000`** (sidecar region). PROG-era: family word `????ffe5` |
| `[7]` `[8]` | Family magic: PROG/PANL/IFAX `894d2ad7 8aa5bee9`; ROM2 `a9d56853 18059f17`; MAIN-era `b4596c36 4b2dca01` |

**`hdr2[1]` as address / unpacked footprint** (`hdr2_addrs.py`):

| Observation | Example |
| --- | --- |
| Stable across close letters while packed size grows | `LZ2350_B`/`_L`: **`h1=0x00f092a0` fixed**, body +1798 |
| Clusters under **16 MiB** for MAIN/PROG | `0x00f072b5`…`0x00f54790` (9330 MAIN `LZ4266_*` ≈ `0x00f0857f`) |
| MAIN-era pair | `h6 = h1 + 64 KiB or 128 KiB` (e.g. `0xf092a0` / `0xf292a0`) |
| PANL above 16 MiB | `0x015e84e8` — likely DRAM / larger map, not SPI window |
| `h1/body` | typically **1.2–2.1×** → packed body expands into this footprint |

Best fit: **`hdr2[1]` ≈ end (or size) of the unpacked image in a low 16 MiB window**
(SPI NOR mapped at `0x00000000`, or a shadow copy). That matches sibling Brother
teardowns (e.g. MFC-J1010DW: **16 MiB SPI NOR** + ARM, dump via CH341/`flashrom`)
and this family’s service-manual **StarSapphire 333 MHz / 256 MB RAM**.

Also: for large FIRM images, `size_a - body_len == 0x48` (constant).

FIRM overhead: `PROGRAMLENG - body_len == 0x6c` =
`prefix(0x18) + tag_hdr(0x14) + hdr2(0x24) + footer_wo_CRLF_FF(0x1c)`.
`PROGRAMLENG` excludes final `\r\n\x0c` (image through `FF` = `PROGRAMLENG + 3`).

## Body

Opaque after the tagged record — **not** stock zlib/lzma/bz2, and **not proven
AES**. Entropy ~7.9 but distributions are non-uniform; MAIN/PANL still shrink a
few percent under zlib (unlike solid ciphertext). Treat as proprietary
pack/transform.

| Image | First 12 bytes | Entropy | Notes |
| --- | --- | ---: | --- |
| MAIN `PROG` | `61b654adf6da9da6f565803f` | ~7.93 | end plateau is period-7 |
| SUB2 `PANL` | same magic | ~7.96 | large period-7 valleys |
| IFAX `PROG` | same magic | ~6.6 (tiny) | |
| SUB1 `ROM2` | `dc803ee3129a55af0fc0c0c0` | ~7.87 | no period-7 islands |

**Shared head (cross-family):** PROG/PANL/IFAX share only the first **12** body
bytes (`61b654adf6da9da6f565803f`). `MAIN ⊕ PANL` is 12 zero bytes then
high-entropy XOR — not a shared keystream. ROM2 uses a different 12-byte magic
**and** `hdr2` tail.

**Shared head (same family, letter revisions in `cdn_older/`):**

| Family | Identical body prefix across letters | Notes |
| --- | ---: | --- |
| PROG `LZ4266_S`/`_T`/`_ZC_1` | **150 bytes** (`0x96`) | S↔T share 323 leading; then sparse equal runs |
| PANL `LZ4279_H`/`_R` | **436 bytes** (`0x1b4`) | includes early family-B pad bytes ~`+0x5e` |
| ROM2 `LZ4267_B`/`_H` | ~0 (first byte `0c`↔`dc`) | only short interior equal runs |

So letter rollbacks keep a long **invariant stream prefix** (container/codec
bootstrap), then diverge — still high-H, still not plaintext. Byte-identity of
S vs ZC over the first 512 KiB is ~0.5%.

Body+12 also clusters by family (version-invariant within letter set):

| Family | `body[12:16]` |
| --- | --- |
| PROG S/T/ZC | `edf40182` |
| PANL H/R | `eb01be00` |
| IFAX | `ed7e0181` |

### Invariant-prefix internals (`dissect_prefix.py` / `ifax_rosetta.py`)

**PROG 150B** — no repeated 8/16-byte blocks (looks like packed bootstrap, not a
table). Sharp edge: S/T/ZC identical through `0x96`, then ZC diverges; S↔T stay
together until `0x143` (single-byte flip). The last ~0x36 bytes of the 150B show
**family-A-like** 7-byte lane deltas (`Δ∈{0x01,0x10,0x04,0x40,0x11,0x44}`) —
prefix may *end* by entering the same framing used for pads.

`body[12:0x60]` (84B) is a **structured codec parameter block**, not ciphertext.
Bit-identical across LZ4266 letter revs S/T/ZC/D (H≈6.15). Ruled out as:
SHA1/MD5/SHA256/HMAC of header fields; AES-ECB under obvious header-derived keys;
zlib at small skips. Host `BrCrypt.dll` (OpenSSL AES_*+SHA1) has no DJF magics.

Cross-corpus layout of `body[12:]` (11 distinct boots among 27 PROG files):

| Off | Size | Role |
| ---: | ---: | --- |
| `+0` | 1 | Always `ed` |
| `+1` | 1 | Model/variant id (`7c` mono, `f4` 9130, `f0` 9480, `fc` 9970/9320, `7e` IFAX/HL-3040, `3e`/`40` older 7450/7040…) |
| `+2` | 1 | Always `01` |
| `+3` | 1 | Codec major: **`82` = gen-α**, **`81` = gen-β** |
| `+4` | 12 | Family constant — gen-α `a172b3d4 df50b95d 1ff706c6\|c7`; gen-β `f81983f7 60d9… e0a85cac` |
| `+16` | 4 | Gen-α: `09 ……` stamp (frozen on color lasers; letter-rev on older mono). Gen-β: different layout (`f537d42e…`) |
| `+20` | 12 | Gen-α secondary magic `2a775b13 f0331a0d 92e40acX` |
| `+32…` | … | More params; color PROG includes `a953e9b4` @ body`+0x36` (ROM2/PCLPS `hdr2` tail uses sibling `a953e9b3`) |

**Codec eras (corpus):** gen-β = older PROG (`LZ257x`/`258x`/`2599`/`2751`) + all IFAX stubs;
gen-α = later mono/color (`LZ3515+`, `LZ4266`, `LZ4962`…). Same 12-byte body magic either way;
oldest ~1.9 MiB PROG still H≈7.9 — not a plaintext shortcut. IFAX remains the only fully
mappable gen-β *body* (tiny).

`hdr2[2]` tracks the same split: color PROG `a4020000`, mono PROG `04020000`, IFAX `f8010000`.
Cross-model shared prefix is only **13–29 B** (magic+`ed`±gen-α head) — not the 150B letter-invariant.
Bootstrap u16/u32 fields are **not** body lengths / chunk sizes.

### ROM2 body head (`rom2_head.py`)

Different magic family: `XX803ee3129a55af0fc0c0c0` (`XX`∈{`0c`,`10`,`24`,`44`,`d8`,`dc`}).
Then a structured param block with wide constants across SUB1/PCLPS/GDI:

```text
body[12:]  00 .. .. 5f|df  f1808106 0784 36|56 01  .. .. .. 3f  e0b8be63 …
```

`hdr2` tail `a9d56853…` (DCLFB) vs `a953e9b3…` (older SUB/PCLPS) — same constant family as
PROG bootstrap `a953e9b4`.

After the shared 150B, letter revisions differ in **~99%** of bytes (first 64 KiB)
with no period-7 bias and **no regular equal-run grid** — real packed content change,
not a flag-bit patch or fixed-size chunk table. (S↔T keep a few longer equal runs only
near the invariant edge; PANL H↔R extend equality ~1.9 KiB past the 436B mark, then random.)

**PANL 436B** — after magic+short header, family-B frames (`5e`/`de`) begin
near `body+0x5a` and continue through much of the invariant region (pad baked
into the version-shared prefix).

**IFAX body map** (191B core + `******` + `\r\n\x0c`; no `ProgramOK`):

```text
[12] magic 61b654ad…803f
[34] head   ed7e0181…8f1a          # same slot as PROG body[12:], different bytes
[42] 6 × family-A frames          # 7c/7d; L1 Δ=0x44 exact for 5 steps
[31] opaque bridge
[36] four 9-byte records 0a cX …  # then trailer into ******
[ 6] 2a × 6
[ 3] 0d 0a 0c
```

IFAX head ⊕ PROG[12:46] is near-random (2/34 zero) — not a simple XOR key.
`hdr2[*]` dwords do **not** appear inside the body prefix; family magics
`894d2ad7` / `ffe5` are header-only (deep body hits are coincidence).

### Entropy map (`tools/djf_parse/entropy_map.py`)

4 KiB / 1 KiB step on carved payloads → `binwalk/carved/*.payload.entropy.{csv,txt}`.

| Blob | Body H (min / med / max) | Valleys |
| --- | --- | --- |
| MAIN | 6.53 / 7.89 / 7.95 | plateau ~`0x9ff000`→footer |
| SUB1 | 7.47 / 7.83 / 7.96 | none below ~7.5 |
| PANL | 6.37 / 7.85 / 7.95 | `0xbd000` (~5 KiB); **`0x664000`–`0x72a400` (~800 KiB)** |

### Period-7 framed regions (`period7_scan.py` / `decode_period7.py`)

Low-H islands are **structured pads**, not packed firmware. They use **7-byte
frames** where four lanes are pure counters and the rest repeat with period 128
→ a full **896-byte tile** stamped repeatedly.

```text
; PANL valley B tile (family B) — first frames
5e 95 fa 79 ea 6f ab
de b7 fb 01 ec 8f b4
5e d9 fb 89 ee af bc
…
; repeats every 128 frames (896 bytes); ~911× in PANL ≈ 6.2% of body
```

| Family | Counter-lane Δ set | Where |
| --- | --- | --- |
| **B** | `{0x22, 0x88, 0x20, 0x80}` | PANL valley B; MAIN end plateau (~5% of body) |
| **A** | `{0x10, 0x40, 0x44}` | PANL small valley @ `0xbd000` |

`decode_period7.py` strips free lanes → `binwalk/carved/period7_templates/*`.
Residual of family-B pads is dominated by `{f8,f9,fa,fb}` — no ELF/strings.

**Implication:** the entropy valleys are pads, not firmware. The real payload is
the remaining ~94% high-H body (no counter signature). SUB1/ROM2 has no
period-7 pads.

### Older CDN letter revisions (`cdn_older/`)

Akamai still serves prior letters (`cdn_probe.txt`, `hunt_old_cdn.py`,
`hunt_cdn_ids.py` → `corpus/cdn_id_hits.txt`):

| File | Tag | Body magic | Entropy |
| --- | --- | --- | ---: |
| `LZ2350_B`/`_L` (ident `8CA-F67-001`) | **MAIN** @0x24 | `00a6d06934e7d41f…` | ~7.90 |
| `LZ2573`–`LZ2599` (DCP-7040 / MFC-7450 / HL-3040) | PROG | `61b654ad…` | ~7.87–7.95 |
| `LZ2600_C` | ROM2 | `d8803ee3…` | ~7.87 |
| `LZ2751_B`/`_C` (MFC-9320) | PROG | `61b654ad…` | ~7.94 |
| `LZ3515_F` / `LZ3632_E` / `LZ3637_E` | PROG | same | ~7.92–7.93 |
| `LZ4266_D` / `_S` / `_T` | PROG | same as ZC | ~7.97 |
| `LZ4279_H` | PANL | `61b654ad…` | ~7.94 |
| `LZ4267_B` | ROM2 | `0c803ee3…` (vs H `dc803ee3…`) | ~7.91 |

**Pre-PROG container (`LZ23xx`, e.g. MFC-6890 `LZ2350_*`):** whole CDN band
uses tag ASCII **`MAIN` @ +0x24** (not `PROG` @ +0x18). Identity is a part
number (`8CA-F67-001`, `8CA-G02-001`, …) rather than `MFC-…USA`.

| Field | MAIN-era | PROG-era (contrast) |
| --- | --- | --- |
| Tag | `MAIN` @ `+0x24` | `PROG`/`PANL` @ `+0x18` |
| Body magic | **20 B** frozen `00a6d06934e7d41fc0a85cacf53b4deacafd9013` across models | **12 B** `61b654ad…803f` |
| `hdr2[2]` family | `00010000` / `00020000` | `a4020000` / `f8010000` / … |
| `hdr2[5]` | `0000001b` (same!) | `0000001b` |
| `hdr2[7..8]` | `b4596c36 4b2dca01` | `894d2ad7 8aa5bee9` |
| Letter shared prefix | see below (can be **≫1 MiB**) | ~150 B then ~random (color PROG) |
| Cross-model shared | **20 B** (the magic) | **12 B** |
| Period-7 pads | **none** | PANL valleys + MAIN end plateau |
| Entropy | ~7.90 | ~7.87–7.97 |

**MAIN body head map** (`main_prefix.py`) — cross-model constancy:

```text
[ 0:20] magic20   00a6d06934e7d41fc0a85cacf53b4deacafd9013   # frozen all MAIN
[20:24] stamp4    model/rev                                  # varies
[24:30] sec6      ff1a25a6ec01                                # frozen all MAIN
[30:32] pA        e.g. 6ff8 / 6e00 / 6404
[32:34] pB        e.g. 2a0a / 281a                           # clusters models
[34:44] tert10    1dbedb70b9596e77301b                        # frozen all MAIN
[44:48] tail4     e.g. 20101a95 / 02a0a958
```

**Letter-revision equal runs (deterministic codec signal):** close MAIN letters
keep a short stamp patch then **hundreds of KiB–1 MiB of byte-identical body**:

| Pair | First diff | Biggest equal run | Equal % |
| --- | ---: | ---: | ---: |
| `LZ2350_B`↔`_L` | `+0x66` (17 diffs in first 256B) | **`+0xdc` × 1 099 075** (~1073 KiB) | 14% |
| `LZ2346_D`↔`_P` | `+0x16` | `+0xa8` × 573 733 (~560 KiB) | 6.7% |
| `LZ2328_C`↔`_H` | `+0x16` | only 77 B | 0.5% (large content change) |

PROG `LZ4266_S`↔`ZC` by contrast: ~0.65% equal in first 200 KiB after the 150B
prefix — letters rewrite almost the whole image. MAIN’s long identical spans
imply the body transform is **deterministic** (no per-build random IV), so
unchanged plaintext regions → unchanged ciphertext. Useful for known-plaintext
if a close letter pair’s changelog is known.

Codec continuity: mid-header dword **`a85cacf5`** at MAIN`+9` / early-PROG`+25`
(flanking `c0`→`e0`). Color PROG later gains `a953e9b4` @`+54`; MAIN
letter-head has sibling `a953ee77` @`+82`. `hdr2` dword layout already modern.

CDN: `LZ2300–2450` → 74 hits (`cdn_id_hits_main_era.txt`). MAIN through
`LZ2350_*`; `LZ2362_A` already PROG. Gap `LZ2351–2361` empty on Akamai
(`cdn_id_hits_transition.txt`).

**Wayback (`update-akamai.brother.co.jp/CS/`)** — CDX index:
`corpus/wayback_cdx_akamai.txt`. Captures under `cdn_older/*.wayback.djf`:

| Capture | Size | Status | Content |
| --- | ---: | --- | --- |
| `LZ4266_W` (2021-05-15) | 1 048 151 | **truncated** | 9330 MAIN letter `W`; header OK, `hdr2[1]=0x00f08572` (ZC=`…857f`); shared body prefix w/ ZC = **153 B**; live CDN 404 |
| `LZ4217_X` (2025-03-05) | 7 010 970 | **full** | PROG `HL-3140CUSA` memver `X`; classic `61b654…` magic; `hdr2[1]=0x00747960` |
| `LZ4219_B` / `_F` | ~2.26 / 2.28 MiB | **full** | ROM2 `DCLPRGDIUSA`; magic `38803ee3…` / `54803ee3…`; B↔F equal ≈**0.5%**, shared prefix **0** (byte0 salt); `hdr2[1]≈0x00215xxx` |
| `LZ4228_P` (2021-04-12) | 1 048 576 | **truncated** | Same object as live full file below (Wayback cut at 1 MiB) |

No `*.upd` 200s on that host. Only W among the 9330 `LZ4266_*` letter series.

#### Plaintext MAIN “Flash Data” family (BH11 PMU / BH13 Upd)

Distinct from opaque `LZ23xx` MAIN (`00a6d069…`, hdr2=36 B) and from PROG.
All use **hdr2_len=20**, embed size + start address in hdr2, and so far always
**`Compress=1`**. Parsers: `parse_main_upd.py` (BH13), `parse_bh_flash.py` (both).

| | **BH13 Upd** | **BH11 PMU** | Opaque MAIN `LZ23xx` |
| --- | --- | --- | --- |
| Banner | `brother MFC '12 BH13 Flash Data` | `brother MFC '11 BH11 new Flash Data` | (none) |
| FileType | (implied program) | **`PMU`** | — |
| Address names | `UpdStartAddress` … | `PmuStartAddress` … | — |
| Flash top | **`0x08000000`** | **`0x00000000`** | unknown |
| Flash start ex. | `0x08020000` (`LZ4228_P`) | `0x00010000` (`LZ4220_*`) | — |
| RAM `ROstart` | `0x40037000` | `0x40036000` | — |
| Live samples | `LZ4228_P`, `LZ4227_M` | `LZ4220_B`/`_F`, `LZ4225_D` | `LZ2350_*` |

**BH13 example** (`cdn_older/LZ4228_P.djf`, live Akamai 20 763 055 B):

```text
UpdStartAddress = 08020000 f7fdffff   # value || ~value
UpdTopAddress   = 08000000 f7ffffff
UpdPrgDlOption  = FLSDL
UpdHeaderEnd
```

Scatter labels (u32be @ label+20): `Compress=1`, `Rom0Size=0x009e0ab2`,
`ROstart=0x40037000`, `PrgStart=0x407036e8`, …

**BH11 PMU example** (`LZ4220_B`/`_F`, DCP-J540JPN):

```text
FileType : PMU
PmuStartAddress = 00010000 fffeffff
PmuTopAddress   = 00000000 ffffffff
PmuRom1FlashStart = 00580000 …
```

Same scatter label block (`Compress=1`, `ROstart=0x40036000`, …). Letter pair
`LZ4220_B`↔`_F`: payload equal **~16%**, longest equal run **~928 KiB** (UI),
packed bulk after first H>7.5 equal only **~2.8%** — deterministic codec, not a
shared keystream; still no stock zlib/lzma/lz4 open.

**Rom0 layout (BH13 `LZ4228_P`):**

| Offset in rom0 | Content |
| ---: | --- |
| `0` … `PrgInfoSize` (`0x1c9048`) | UI / PARTS / PNG (H≈1–5) |
| `0x1c9048` … `~0x1ca048` | Low-H structured tail (~4 KiB) |
| **`~0x1ca048` → EOF** | Packed bulk H≈7.94 (~8.5 MiB) |

**Rom1** (`UpdRom1Offset` / `PmuRom1Offset`): archive of chunks
`00 00 00 00 12 34 56 78 | typ | size | payload` — **resources**, not code
(JPEG/Exif, RIFF/WAVE, `LCDDEMO`/`MFC-J4510DW`). Helper:
`bh13_rom1_chunks.py`. Notes: `cdn_older/LZ4228_P_full/`.

**Ghidra:** maps are ARM-shaped (BH13 flash `@0x08…`, both use RAM `@0x40…`),
but **code stays packed** (`Compress=1`). Memory-map oracle only — not a
substitute for 9330 PROG decrypt / SPI dump.

### Cross-model corpus (`../corpus/`)

`download_corpus.py` + `compare_corpus.py` → [`COMPARE.md`](../corpus/COMPARE.md).
Findings so far:

- **PROG family magic** `61b654adf6da9da6f565803f` on PROG/PANL/IFAX from
  DCP-7040 (`LZ2573_*`) through MFC-L8600 (`LZ4962_S`).
- **MAIN-tag family** (`LZ23xx`: DCP-145C…MFC-6890): **20-byte** magic
  `00a6d069…cafd9013`, `hdr2` tail `b4596c364b2dca01`, tag at +0x24, no
  period-7 pads — older container, still H≈7.9.
- **ROM2 family** `XX803ee3129a55af0fc0c0c0` — only byte0 varies across packages
  (incl. early `d8` on `LZ2600_C`).
- **9130CW / 9330CDW / 9340CDW** ship the **identical** `LZ4266_ZC_1` PROG blob.
- Tiny IFAX bodies (`LZ3196_A`, 191 B, H≈6.59) are low-entropy; large PROG/PANL
  stay H≈7.9. Exception: plaintext **BH13 Upd / BH11 PMU** Flash Data mains
  (map + scatter labels); code still `Compress=1`.
- Letter-revision shared prefixes vary by family: color `LZ4266_*` ≈ **150 B**;
  older `LZ2751_B`↔`_C` ≈ **2077 B**, `B`↔`L` ≈ **1755 B**; mono `LZ3515`/`LZ3632`
  letter pairs only ≈ **29 B** (past the 12-byte magic). Longer shared heads are
  still ciphertext — useful for codec framing, not a plaintext leak.

## Footer (plaintext)

Immediately before the terminator:

```text
<identity>ProgramOK <5-byte BCD version> <u16be csum> <00> \r\n \x0c
[optional <ESC>%-12345X]
```

Examples:

| File | Footer version (BCD → decimal digits) | Matches firmverup |
| --- | --- | --- |
| `LZ4266_ZC_1` | `23 11 08 11 54` → `2311081154` | `LATESTVERSION` `ZC2311081154` |
| `LZ4279_R` | `23 11 08 18 29` → `2311081829` | near `R2311081800` |
| `LZ4267_H` | `18 03 05 14 06` → `1803051406` | (SUB1 uses dotted `1.10` publicly; BCD stamp differs) |

Checksum algorithm over the footer fields is **not yet identified**. Probed
(`probe_csum.py`, `probe_csum_body.py`, `probe_csum_v2.py`): Fletcher-16,
more CRC16 inits, hdr2/size field mixes, body[:N] for N≤256 — **still no
multi-file match**. Likely covers packed body (or keyed). Deferred until a
dump exposes the checker.

## What is still unknown

1. Codec for the **high-entropy majority** of the body (after the ~150/436-byte
   family prefixes; period-7 regions are pads only).
2. Prefix mystery-6 (size-class correlated; not length/CRC/SHA of body).
3. Footer `u16` checksum (not CRC/Adler/SHA trunc of footer or full body).
4. Exact meaning of bootstrap variant/`09`-stamp bytes; IFAX `0a cX` records.
5. Printer-side unpacker — **blocking** for Ghidra-loadable code from `.djf` alone.
6. Confirm StarSapphire ISA (likely ARM) and exact SPI part on the 9330 main PCB —
   tracked in [`docs/HARDWARE-AND-BOOT.md`](../../../docs/HARDWARE-AND-BOOT.md).

## Does one of these images contain the update handler?

**Almost certainly yes in principle — but not in a form we can read from the `.djf`.**

The machine that accepts `@PJL EXECUTE BRDOWNLOAD` must already be running code
that parses the prefix/tag, decrypts the body, checks the `ProgramOK` footer, and
flashes segments. That code lives in the **currently executing MAIN (and maybe
bootloader) image on the device**.

What we checked in these packages (`scan_plaintext.py`):

| Check | Result |
| --- | --- |
| Sliding-window entropy | No H≪6 plaintext code; PANL/MAIN have structured H≈6.4 period-7 islands |
| Mid-file ASCII (`BRDOWNLOAD`, `Decrypt`, …) | **Only** header/footer hits |
| Zero-byte density | ~0.45% in high-H body (not sparse RO/code) |

Packages are **fully wrapped**; they do not ship a plaintext updater. Older CDN
`.upd` / early letter revisions (possible clearer bodies) are gone from Akamai;
Wayback was offline when last probed.

### Practical ways to get loadable binaries (Ghidra)

The `.djf` body is still packed/encrypted — **no ELF/uImage/ARM vector table**
survives in the high-H region (sig hits are coincidence). To get machine code:

1. **SPI NOR dump of the live 9330** (highest leverage) — open main PCB, identify
   SOP8/WSON flash (often **16 MiB**, matching `hdr2[1]≈0x00f0xxxx`), read with
   CH341/`flashrom`. Expect bootloader + compressed/packed slots; sibling Brother
   work (MFC-J1010DW) loaded T-Kernel segments into IDA/Ghidra at ROM-table bases.
2. **Use `hdr2[1]` as the unpack size/end hint** once a plaintext/decompressed
   image exists — Ghidra load: base `0x00000000` (or SoC remap), length ≈ `hdr2[1]`
   for MAIN (`LZ4266_ZC_1` → **`0x00f0857f`**). PANL `0x015e84e8` → try as DRAM base.
3. **Letter-revision XOR** (`tools/djf_parse/xor_letter_diff.py` →
   [`corpus/XOR_LETTER_DIFFS.md`](../corpus/XOR_LETTER_DIFFS.md)):
   - **9330 PROG** `LZ4266_S/T/ZC`: after the ~150 B shared prefix, bodies are
     **~0.4 % equal** — XOR is essentially random (not a localized patch map).
   - **MAIN-era close letters** (`LZ2350_B`⊕`_L`): ~1 MiB identical then sparse
     diffs — XOR **does** light up changed regions (`P₁⊕P₂` if stream-like).
     Deeper tile find below.
   - ROM2 `B`↔`H` / PANL `H`↔`R`: same story as PROG (~0.5 % equal).
4. **Logic analyzer on flash lines** while applying a known `.djf` — observe
   plaintext program traffic (heavy).
5. Archives of older `.upd` / pre-crypto builds — still missing from Akamai.

Until one of those yields an unpacked MAIN, the high-H body codec stays closed.
Offline leads now: family prefixes + `hdr2[2]` + structured `body[12:0x60]`
codec params (pads solved) + MAIN-era **112 B / period-7 XOR tiles** (below).
High-H majority still closed without a device dump.

### MAIN-era `LZ2350_B`⊕`_L`: 112-byte (16×7) XOR tiles

Tool: [`tools/djf_parse/main_xor_deep.py`](../../../tools/djf_parse/main_xor_deep.py).
Note: [`corpus/MAIN_XOR_112.md`](../corpus/MAIN_XOR_112.md).

After the shared ~1073 KiB plateau (`+0xdc`…`+0x10c61f`), most of the body is
sparse high-H XOR — except a **solid 774 KiB band** at
`body+0x5f68e2 … +0x6b8112` made of **7077 consecutive 112-byte frames**
(stride exactly 112; starts `≡ 2 (mod 16)`).

Each frame:

| Tile span | XOR behavior |
| --- | --- |
| `+0x00…+0x52` (83 B) | every byte differs (nonzero XOR) |
| `+0x53…+0x6f` (29 B) | period-7 trailer: **lane `addr%7==5` always equal** (XOR 0); the other six lanes differ in 6-byte runs |

So `112 = 16×7`, and the trailer is `4×(stable + 6 changed) + final stable` —
the same **period-7 lane framing** seen in PROG-era pads, now visible inside
MAIN high-H via letter XOR.

Lane constants across 500 sampled frames in that band (absolute `addr%7`):

| Lane | Dominant XOR byte |
| ---: | --- |
| 1 | **always `0xb0`** |
| 3 | ≈`0x40` / `0x41` |
| 5 | zeros only in trailer positions (always 0 there) |

Gap 6-byte XOR groups cycle through only **four** patterns (50/50/50/50 in 200
frames). No plaintext ASCII islands; L-only +1798 B suffix stays H≈7.86.
`hdr2[1]`/`[6]` unchanged (`0xf092a0` / `0xf292a0`); `hdr2[0]` tracks body
(+1795 ≈ +1798).

**Implication:** the 112-band is **period-7 Family-A** (counter lanes 1/4/6 with
Δ `0x40` / `0x44` / `0x10`, frac 1.0) — same family as PANL valley A
(`decode_period7.py`). Letter XOR is a fixed bias on those counters (lane1
always `0xb0`), not an avalanche. Useful framing constraint; free lanes still
not a plaintext unpack. `main_xor_deep.py` prints the family classify + a
64 KiB window scan (also runs on `LZ4266_ZC_1`).

## Tooling

```powershell
python tools\djf_parse\parse_djf.py
python tools\djf_parse\parse_djf.py --json
python tools\djf_parse\inspect_headers.py
python tools\djf_parse\scan_plaintext.py
python tools\djf_parse\analyze_format.py
python tools\djf_parse\body_structure.py
python tools\djf_parse\shared_body_header.py
python tools\djf_parse\dissect_prefix.py
python tools\djf_parse\ifax_rosetta.py
python tools\djf_parse\bootstrap_12_60.py
python tools\djf_parse\bootstrap_crypto_probe.py
python tools\djf_parse\cross_bootstrap.py
python tools\djf_parse\bootstrap_fields.py
python tools\djf_parse\bootstrap_correlate.py
python tools\djf_parse\bootstrap_as_lengths.py
python tools\djf_parse\diff_sparse.py
python tools\djf_parse\xor_letter_diff.py
python tools\djf_parse\main_xor_deep.py
python tools\djf_parse\prefix_mystery.py
python tools\djf_parse\mystery6_correlate.py
python tools\djf_parse\probe_csum_body.py
python tools\djf_parse\rom2_head.py
python tools\djf_parse\old_prog_boot.py
python tools\djf_parse\entropy_map.py
python tools\djf_parse\period7_scan.py
python tools\djf_parse\decode_period7.py --scan
python tools\djf_parse\probe_valleys.py
python tools\djf_parse\probe_csum.py
python tools\djf_parse\hunt_old_cdn.py   # HEAD-scan Akamai for older LZ* names
```

### 010 Editor Binary Template

[`Brother_DJF.bt`](Brother_DJF.bt) (also under `tools/djf_parse/`) — run on a `.djf` in
[010 Editor](https://www.sweetscape.com/010editor/). Written against the
[010editor-reference](https://github.com/b1tninja/010editor-reference) skill
(`BigEndian`, `read=` summaries, `FTell`-style locate via `ReadUByte` peeks).

Template Results outline: `pjl` → `prefix` → `record` (tag/`size_a`/`hdr2`) →
`body` (opaque) → `footer` (`ProgramOK` + BCD version) → optional `trailing_uel`.
