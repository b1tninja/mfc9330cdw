# DJF letter-revision XOR diffs

Bodies only (after tag+hdr2, before ProgramOK). `equal%` high + long equal runs ⇒ deterministic codec / unchanged packed regions.

| Pair | Tag | Equal % | First diff | Biggest equal | First dense 4K |
| --- | --- | ---: | ---: | --- | ---: |
| LZ4266 MAIN S↔ZC | PROG | 0.4% | +0x96 | +0x0×0KiB | +0x1000 |
| LZ4266 MAIN T↔ZC | PROG | 0.4% | +0x96 | +0x0×0KiB | +0x1000 |
| LZ4266 MAIN D↔ZC | PROG | 0.4% | +0x97 | +0x0×0KiB | +0x1000 |
| LZ4266 MAIN S↔T | PROG | 0.5% | +0x143 | +0x0×0KiB | +0x1000 |
| LZ4279 PANL H↔R | PANL | 0.5% | +0x1b4 | +0x1bf×2KiB | +0x1000 |
| LZ4267 ROM2 B↔H | ROM2 | 0.5% | +0x0 | +0x0×0KiB | +0x1000 |
| LZ2350 MAIN B↔L | MAIN | 14.0% | +0x66 | +0xdc×1073KiB | +0x10d000 |
| LZ2346 MAIN D↔P | MAIN | 6.7% | +0x16 | +0xa8×560KiB | +0x8c000 |

## Follow-up: LZ2350 112-byte tiles

`LZ2350_B`⊕`_L` has a solid **7077 × 112 B** band at `body+0x5f68e2`
(period-7 lane framing; lane5 frozen in trailers; lane1 XOR=`0xb0`).
Details: [`MAIN_XOR_112.md`](MAIN_XOR_112.md), `blobs/FORMAT.md`.
