# MAIN-era letter XOR: 112-byte tiles (`LZ2350_B` ⊕ `LZ2350_L`)

Offline follow-up on the best local MAIN-tag close-letter pair
(`cdn_older/LZ2350_{B,L}.djf`, ident `8CA-F67-001`).

## Pair inventory (local)

| Pair | Tag | Equal % | Big equal run | Notes |
| --- | --- | ---: | --- | --- |
| **LZ2350_B↔L** | MAIN | **14.0%** | +0xdc × 1073 KiB | best; same ident |
| LZ2346_D↔P | MAIN | 6.7% | +0xa8 × 560 KiB | same ident; no solid 112-band |
| LZ2328_C↔H | MAIN | 0.5% | — | different idents (G02 vs G31) |
| LZ2751_B↔C / B↔L | PROG | ~0.5–0.6% | ~2–3 KiB | early color PROG |
| LZ4266 S/T/D↔ZC | PROG | ~0.4% | prefix only | 9330 family |
| LZ4267 B↔H / LZ4279 H↔R / LZ4219 B↔F | ROM2/PANL | ~0.5% | — | avalanche |

## Strongest new observation

In `LZ2350_B`⊕`_L`, after the shared plateau, a **774 KiB** region
(`body+0x5f68e2` … `+0x6b8112`) is tiled with **7077 × 112-byte** frames:

- **83 B** fully different + **29 B** period-7 trailer
- Trailer freezes **lane `addr%7 == 5`** (XOR 0); other lanes differ
- Lane 1 XOR is the constant **`0xb0`** across the band
- Frame start alignment `≡ 2 (mod 16)`; stride exactly 112 (= 16×7)

### Period-7 Family-A (same as PANL valley A)

Single-file lane Δ inside the band (`addr%7` step-7):

| Lane | Mode Δ | Frac | Role |
| ---: | ---: | ---: | --- |
| 1 | **`0x40`** | 1.000 | Family-A counter |
| 4 | **`0x44`** | 1.000 | Family-A counter |
| 6 | **`0x10`** | 1.000 | Family-A counter |
| 0 / 2 / 3 / 5 | mixed | <1 | free / residual |

So the 112-tile band is **not** a separate cipher — it is **period-7 Family-A
framing** (deltas `{0x10,0x40,0x44}`, cf. `decode_period7.py`) embedded in the
MAIN high-H stream. Letter B↔L keeps the same Δ on those lanes and only a
**fixed bias** (lane1 XOR always `0xb0`). 64 KiB window scan: Family-A covers
`+0x600000…+0x6a0000` (contains the band). 9330 PROG `LZ4266_ZC_1` also shows
Family-A near `+0x7b0000` and Family-B near `+0xa00000` (pad valleys).

Reproducers: `python tools/djf_parse/main_xor_deep.py`,
`python tools/djf_parse/xor_letter_diff.py` on the B/L paths.

See also `blobs/FORMAT.md` § “MAIN-era LZ2350_B⊕_L: 112-byte (16×7) XOR tiles”.
