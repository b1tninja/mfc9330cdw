# Live unit inventory (2026-10-25)

Source: PJL INFO ID + Web UI /general/information.html?kind=item
Host: 192.168.1.71

| Field | Value |
| --- | --- |
| Model | Brother MFC-9330CDW |
| PJL ID | Brother MFC-9330CDW:8CE-415:Ver.ZC |
| Serial | U63480K7J492832 |
| Main Firmware | ZC |
| Sub1 Firmware | 1.10 |
| Sub2 Firmware | R2311081800 |
| Memory Size (Web UI) | 192 MB |
| PJL INFO MEMORY TOTAL | 66619584 (~63.5 MiB free heap, not DRAM size) |
| Page Counter | 25257 |
| Color pages (approx) | 25161 |
| Status | Sleep / ONLINE |

Notes:
- Live MAIN letter matches CDN blob LZ4266_ZC_1.
- Web UI memory stays at 192 MB vs service-manual 256 MB for 9330 — treat as
  firmware-reported usable size until SPI/DRAM dump reconciles.
- Sub2 public stamp R2311081800 is near PANL footer BCD 2311081829 (FORMAT.md).
