"""Brother NC-8500h / MFC Telnet console login (read-only).

Documented dance (NC-8100h / MFC network manuals):
  1. Connect; press RETURN to get the real '#' password prompt
  2. Enter network password (does NOT echo) — this unit: initpass
  3. At 'Enter username>' type anything (empty works)
  4. Expect 'Local>' — HELP / SHOW only; do not SET / INIT

Critical pitfall: the welcome banner contains the substring "at # prompt",
so waiting for b"# " matches the *instructions*, not the prompt. You must
send RETURN first; only then does the printer emit BEL + CRLF + "# ".

Working byte sequence (this unit, 192.168.1.71, NC-8500h Ver.1.22)::

    # after TCP connect + banner (may include IAC WILL ECHO/SGA, DO SGA):
    --> 0d 0a                         # RETURN
    <-- 07 0d 0a 23 20                # BEL CRLF "# "
    --> 69 6e 69 74 70 61 73 73 0d 0a # "initpass" CRLF
    <-- ... console banner ... "Enter username> "   # note: lowercase u
    --> 0d 0a                         # empty username CRLF
    <-- 0d 0a 4c 6f 63 61 6c 3e 20    # CRLF "Local> "

Does not change settings or upload firmware.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from dataclasses import dataclass, field

HOST_DEFAULT = "192.168.1.71"
PORT = 23

IAC, DONT, DO, WONT, WILL = 255, 254, 253, 252, 251
SB, SE = 250, 240
OPT_ECHO, OPT_SGA, OPT_BINARY = 1, 3, 0


def hx(data: bytes, limit: int = 160) -> str:
    body = " ".join(f"{b:02x}" for b in data[:limit])
    return body + (" ..." if len(data) > limit else "")


def visible(data: bytes, limit: int = 240) -> str:
    parts: list[str] = []
    for b in data[:limit]:
        if b == 7:
            parts.append("<BEL>")
        elif b == 13:
            parts.append("<CR>")
        elif b == 10:
            parts.append("<LF>")
        elif 32 <= b < 127:
            parts.append(chr(b))
        else:
            parts.append(f"\\x{b:02x}")
    if len(data) > limit:
        parts.append("...")
    return "".join(parts)


@dataclass
class IacState:
    replies: list[bytes] = field(default_factory=list)

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        i = 0
        n = len(data)
        while i < n:
            if data[i] != IAC:
                out.append(data[i])
                i += 1
                continue
            if i + 1 >= n:
                break
            cmd = data[i + 1]
            if cmd == IAC:
                out.append(IAC)
                i += 2
                continue
            if cmd == SB:
                j = i + 2
                while j + 1 < n:
                    if data[j] == IAC and data[j + 1] == SE:
                        j += 2
                        break
                    j += 1
                i = j
                continue
            if cmd in (WILL, WONT, DO, DONT) and i + 2 < n:
                opt = data[i + 2]
                if cmd == WILL:
                    # Accept ECHO + SGA (password hide / line discipline)
                    if opt in (OPT_ECHO, OPT_SGA, OPT_BINARY):
                        self.replies.append(bytes([IAC, DO, opt]))
                    else:
                        self.replies.append(bytes([IAC, DONT, opt]))
                elif cmd == DO:
                    if opt in (OPT_SGA, OPT_BINARY):
                        self.replies.append(bytes([IAC, WILL, opt]))
                    else:
                        self.replies.append(bytes([IAC, WONT, opt]))
                elif cmd == WONT:
                    self.replies.append(bytes([IAC, DONT, opt]))
                elif cmd == DONT:
                    self.replies.append(bytes([IAC, WONT, opt]))
                i += 3
                continue
            i += 2
        return bytes(out)

    def drain(self) -> bytes:
        blob = b"".join(self.replies)
        self.replies.clear()
        return blob


def recv_some(
    sock: socket.socket,
    iac: IacState,
    timeout: float,
    *,
    stop_when=None,
) -> tuple[bytes, bytes]:
    sock.settimeout(0.3)
    plain = bytearray()
    raw = bytearray()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            if stop_when is not None and stop_when(bytes(plain)):
                break
            continue
        if not chunk:
            break
        raw.extend(chunk)
        plain.extend(iac.feed(chunk))
        rep = iac.drain()
        if rep:
            sock.sendall(rep)
        if stop_when is not None and stop_when(bytes(plain)):
            # short linger
            end = time.time() + 0.2
            while time.time() < end:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                raw.extend(chunk)
                plain.extend(iac.feed(chunk))
                rep = iac.drain()
                if rep:
                    sock.sendall(rep)
            break
    return bytes(plain), bytes(raw)


def real_hash_prompt(plain: bytes) -> bool:
    """True when we have the password prompt, not the banner's 'at # prompt'."""
    # Password prompt arrives as BEL + CRLF + "# " (or just "\r\n# ")
    if b"\x07\r\n# " in plain or plain.endswith(b"\r\n# ") or plain.endswith(b"# "):
        # Exclude banner-only: banner has "at # prompt" but not a trailing "# "
        if plain.rstrip().endswith(b"#"):
            return True
        if b"\x07" in plain and b"# " in plain:
            return True
    return plain.endswith(b"# ")


def login(
    host: str,
    password: str = "initpass",
    username: str = "",
    line_end: bytes = b"\r\n",
    do_help: bool = True,
) -> bool:
    iac = IacState()
    sock = socket.create_connection((host, PORT), timeout=6)
    try:
        banner, raw_b = recv_some(
            sock,
            iac,
            4.0,
            stop_when=lambda p: b"Welcome" in p or b"return" in p.lower(),
        )
        print("banner:", visible(banner))
        print("banner hx:", hx(raw_b))

        # Step 1 — RETURN to solicit the real '#' prompt
        sock.sendall(line_end)
        prompt, raw_p = recv_some(sock, iac, 3.0, stop_when=real_hash_prompt)
        print("after RETURN:", visible(prompt), "| hx:", hx(raw_p))
        if not real_hash_prompt(prompt) and b"# " not in prompt:
            print("FAIL: no '#' password prompt after RETURN")
            return False

        # Step 2 — password (no echo). Console copyright banner is long; wait
        # for Username / Local> / BEL-reject, not the first chunk alone.
        sock.sendall(password.encode("ascii") + line_end)

        def pwd_done(p: bytes) -> bool:
            low = p.lower()
            if b"username>" in low or b"local>" in low:
                return True
            # reject: BEL then fresh "# " without console banner
            if b"\x07" in p and b"Command Console" not in p:
                return True
            return False

        after_pwd, raw_pwd = recv_some(sock, iac, 8.0, stop_when=pwd_done)
        print("after password:", visible(after_pwd, 400))
        print("after password hx:", hx(raw_pwd, 200))
        low_pwd = after_pwd.lower()
        if (
            b"\x07" in after_pwd
            and b"username>" not in low_pwd
            and b"local>" not in low_pwd
            and b"Command Console" not in after_pwd
        ):
            print("FAIL: BEL reject (wrong password or sent before real # prompt)")
            return False

        # Step 3 — username (anything / empty). Prompt is "Enter username> ".
        if b"username>" in low_pwd:
            sock.sendall(username.encode("ascii") + line_end)
            after_user, raw_u = recv_some(
                sock, iac, 3.0, stop_when=lambda p: b"Local>" in p or b"\x07" in p
            )
            print(f"after username={username!r}:", visible(after_user), "| hx:", hx(raw_u))
            if b"Local>" not in after_user:
                print("FAIL: no Local>")
                return False
        elif b"local>" not in low_pwd:
            print("FAIL: neither username> nor Local> (partial banner?)")
            return False

        print("OK: Local> console")
        if do_help:
            sock.sendall(b"HELP" + line_end)
            help_out, _ = recv_some(sock, iac, 2.5, stop_when=lambda p: b"Local>" in p)
            print("HELP:", visible(help_out, 500))
            # read-only SHOW version-ish
            sock.sendall(b"SHOW SERVER" + line_end)
            show_out, _ = recv_some(sock, iac, 2.5, stop_when=lambda p: b"Local>" in p)
            print("SHOW SERVER:", visible(show_out, 500))
        return True
    finally:
        sock.close()


def matrix(host: str) -> int:
    """Reproduce success / failure cells for the report."""
    cases = [
        ("working: RETURN then initpass CRLF, empty user", "initpass", True, b"\r\n"),
        ("broken: initpass without prior RETURN (banner # false match)", "initpass", False, b"\r\n"),
        ("RETURN then access", "access", True, b"\r\n"),
        ("RETURN then initpass CR-only", "initpass", True, b"\r"),
    ]
    ok_any = False
    for label, pwd, ret_first, le in cases:
        print(f"\n=== MATRIX: {label} ===")
        iac = IacState()
        sock = socket.create_connection((host, PORT), timeout=6)
        try:
            banner, _ = recv_some(
                sock, iac, 3.5, stop_when=lambda p: b"Welcome" in p
            )
            # Simulate old bug: treat banner 'at # prompt' as ready
            false_ready = b"# " in banner
            print(f"  banner has '# ' substring (false prompt): {false_ready}")
            if ret_first:
                sock.sendall(le)
                prompt, raw_p = recv_some(sock, iac, 2.5, stop_when=real_hash_prompt)
                print(f"  after RETURN: {visible(prompt)!r} hx={hx(raw_p)}")
            sock.sendall(pwd.encode() + le)

            def done(p: bytes) -> bool:
                low = p.lower()
                if b"username>" in low or b"local>" in low:
                    return True
                if b"\x07" in p and b"Command Console" not in p:
                    return True
                return False

            after, raw_a = recv_some(sock, iac, 8.0, stop_when=done)
            print(f"  after pwd: {visible(after, 220)!r}")
            success = False
            low = after.lower()
            if b"username>" in low:
                sock.sendall(le)
                u, _ = recv_some(sock, iac, 2.5, stop_when=lambda p: b"Local>" in p)
                print(f"  after empty user: {visible(u)!r}")
                success = b"Local>" in u
            elif b"local>" in low:
                success = True
            print(f"  -> {'OK Local>' if success else 'FAIL'}")
            ok_any = ok_any or success
        finally:
            sock.close()
        time.sleep(0.3)
    return 0 if ok_any else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default=HOST_DEFAULT)
    ap.add_argument("--password", default="initpass")
    ap.add_argument("--username", default="")
    ap.add_argument("--cr-only", action="store_true", help="Use CR not CRLF")
    ap.add_argument("--matrix", action="store_true", help="Compare working vs broken")
    ap.add_argument("--no-help", action="store_true")
    args = ap.parse_args()
    le = b"\r" if args.cr_only else b"\r\n"
    if args.matrix:
        return matrix(args.host)
    ok = login(
        args.host,
        password=args.password,
        username=args.username,
        line_end=le,
        do_help=not args.no_help,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
