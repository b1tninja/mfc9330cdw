"""Brother BrCrypt admin confirm (MakeConfirmPasswordValue_ver1).

Offline reconstruction of FirmwareUpdater.exe
``CCryptedPasswd::MakeConfirmPasswordValue_ver1`` @ ``0040c880``.

SNMP:
  GET  …2435.5.100.10.1.0  → 20-byte challenge (rotates)
  SET  …2435.5.100.10.2.0  ← 60-byte confirm

AES (``EncryptAES_ECB``) is resolved from BrCrypt.dll but never called in ver1.
Only ``SHA1(data, len, out)`` is used (standard SHA-1).

Do not SNMP SET unless you have verified a response offline against a captured pair.
"""

from __future__ import annotations

import hashlib
import os
from typing import Optional


CHALLENGE_LEN = 20
CONFIRM_LEN = 60


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def make_confirm_password_value_ver1(
    password: str | bytes,
    challenge: bytes,
    *,
    client_random: Optional[bytes] = None,
) -> bytes:
    """Build the 60-byte confirm value.

    Layout of returned buffer::

        [0:20]  challenge          (echo of SNMP challenge)
        [20:40] R = SHA1(rand20)   (client nonce; rand20 from CryptGenRandom)
        [40:60] M = SHA1(R || challenge || SHA1(password))

    Intermediate 60-byte MAC input (not transmitted) is ``R || challenge || P``
    where ``P = SHA1(password)`` (ASCII / raw bytes, no trailing NUL).

    Args:
        password: Admin password (e.g. ``initpass``). ``str`` is encoded as ASCII.
        challenge: Exactly 20 bytes from OID …10.1.0.
        client_random: Optional 20-byte CryptGenRandom input for reproducible tests.
            If omitted, ``os.urandom(20)`` is used. Only the SHA1 of this value
            appears in the confirm (as bytes [20:40]).
    """
    if isinstance(password, str):
        pwd = password.encode("ascii")
    else:
        pwd = password
    if len(challenge) != CHALLENGE_LEN:
        raise ValueError(f"challenge must be {CHALLENGE_LEN} bytes, got {len(challenge)}")
    if client_random is None:
        client_random = os.urandom(20)
    elif len(client_random) != 20:
        raise ValueError("client_random must be 20 bytes")

    p = sha1(pwd)
    r = sha1(client_random)
    m = sha1(r + challenge + p)
    out = challenge + r + m
    assert len(out) == CONFIRM_LEN
    return out


def verify_confirm_offline(
    password: str | bytes,
    challenge: bytes,
    confirm: bytes,
) -> bool:
    """Check confirm against password+challenge without contacting the printer.

    Recomputes ``M`` from ``confirm[20:40]`` (R) and compares to ``confirm[40:60]``.
    Also requires ``confirm[0:20] == challenge``.
    """
    if len(challenge) != CHALLENGE_LEN or len(confirm) != CONFIRM_LEN:
        return False
    if confirm[:20] != challenge:
        return False
    if isinstance(password, str):
        pwd = password.encode("ascii")
    else:
        pwd = password
    r = confirm[20:40]
    expected_m = sha1(r + challenge + sha1(pwd))
    return confirm[40:60] == expected_m


def _self_test() -> None:
    challenge = bytes(range(20))
    rand = b"\x11" * 20
    confirm = make_confirm_password_value_ver1("initpass", challenge, client_random=rand)
    assert len(confirm) == 60
    assert confirm[:20] == challenge
    assert confirm[20:40] == sha1(rand)
    assert confirm[40:60] == sha1(sha1(rand) + challenge + sha1(b"initpass"))
    assert verify_confirm_offline("initpass", challenge, confirm)
    assert not verify_confirm_offline("wrong", challenge, confirm)
    # Wrong echoed challenge
    bad = bytes(20) + confirm[20:]
    assert not verify_confirm_offline("initpass", challenge, bad)
    print("brcrypt_confirm self-test OK")
    print(f"  example confirm hex: {confirm.hex()}")


if __name__ == "__main__":
    _self_test()
