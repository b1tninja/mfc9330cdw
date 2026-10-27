"""Login with initpass and dump key admin/network pages (read-only)."""

from __future__ import annotations

import http.cookiejar
import re
import socket
import struct
import urllib.parse
import urllib.request

HOST = "192.168.1.71"
PWD = "initpass"


def textify(html: str) -> str:
    html = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.I)
    html = re.sub(r"<style[\s\S]*?</style>", " ", html, flags=re.I)
    html = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", html).strip()


def main() -> None:
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.addheaders = [("User-Agent", "brother-re/1")]
    data = urllib.parse.urlencode(
        {"Nfa": PWD, "loginurl": "/net/net/protocol.html"}
    ).encode()
    with op.open(
        urllib.request.Request(f"http://{HOST}/general/status.html", data=data, method="POST"),
        timeout=8,
    ) as r:
        r.read(100)
    print("cookies", {c.name: c.value for c in cj})

    paths = [
        "/net/net/protocol.html",
        "/net/net/snmp.html",
        "/net/net/ftp.html",
        "/net/net/net.html",
        "/admin/password.html",
        "/admin/default.html",
        "/admin/lock.html",
        "/admin/settinglock.html",
        "/admin/logtonet.html",
    ]
    for path in paths:
        try:
            with op.open(f"http://{HOST}{path}", timeout=8) as r:
                body = r.read().decode("latin-1", "replace")
        except Exception as exc:  # noqa: BLE001
            print(f"\n## {path} ERROR {exc}")
            continue
        t = textify(body)
        print(f"\n## {path} ({len(body)}B)")
        print(t[:1200])

    # TFTP: try filename=password patterns with initpass
    print("\n## TFTP WRQ variants")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    variants = [
        (b"test.bin", PWD.encode()),
        (PWD.encode(), b"octet"),
        (b"test.bin", f"octet\0{PWD}".encode()),  # unlikely
    ]
    for fname, mode in variants:
        pkt = struct.pack("!H", 2) + fname + b"\x00" + mode + b"\x00"
        sock.sendto(pkt, (HOST, 69))
        try:
            data, _ = sock.recvfrom(400)
            print(f"  fname={fname!r} mode={mode!r} -> {data[:100]!r}")
        except socket.timeout:
            print(f"  fname={fname!r} mode={mode!r} -> timeout")
    sock.close()


if __name__ == "__main__":
    main()
