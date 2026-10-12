"""bcrypt hashes from pyca/bcrypt, an implementation independent of this one.

    python -m venv env && env/bin/pip install bcrypt==4.2.1
    env/bin/python -I scripts/gen_bcrypt_vectors.py > testvectors/bcrypt.json

Each case is a password, a hash string, and whether pyca/bcrypt's own
checkpw accepts the password against it. Covered: the three prefixes in use
($2a$, $2b$, $2y$), costs 4 to 10, the empty password, passwords either side
of bcrypt's 72-byte limit -- past which the key is truncated, so a 73-byte
password and its first 72 bytes verify alike -- non-ASCII, and wrong
passwords. Salts are fixed, derived from labels, so the hashes are
reproducible. pyca/bcrypt 4.x is built on the Rust `bcrypt` crate; the first
case is the classic OpenBSD vector for "U*U", which ties it to OpenBSD's.
"""

import hashlib
import json
import sys

import bcrypt

ALPHABET = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def salt_string(label, prefix, cost):
    """A canonical 22-character salt from a label: 16 bytes, bcrypt base64."""
    raw = hashlib.sha256(label.encode()).digest()[:16]
    bits = int.from_bytes(raw, "big") << 4  # 132 bits, the last four zero
    chars = bytes(ALPHABET[(bits >> (6 * (21 - i))) & 63] for i in range(22))
    return prefix + b"%02d$" % cost + chars


def main():
    cases = []

    def add(password, hashed, verifies):
        assert bcrypt.checkpw(password, hashed) == verifies, (password, hashed)
        cases.append({"password": password.hex(), "hash": hashed.decode().encode().hex(),
                      "verifies": "true" if verifies else "false"})

    classic = bcrypt.hashpw(b"U*U", b"$2a$05$CCCCCCCCCCCCCCCCCCCCC.")
    assert classic == b"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"
    add(b"U*U", classic, True)
    add(b"U*V", classic, False)

    long73 = bytes(range(33, 33 + 73))
    passwords = [b"", b"a", b"password", "pässwörd".encode(), bytes(range(1, 72)),
                 long73[:72], long73, long73 + b"tail"]
    for i, pw in enumerate(passwords):
        for prefix, cost in ((b"$2b$", 4), (b"$2a$", 5), (b"$2y$", 6)):
            if prefix == b"$2y$":
                # pyca writes $2b$; $2y$ is crypt_blowfish's name for the same
                # computation, which pyca also checks. Rename and confirm.
                h = bcrypt.hashpw(pw, salt_string(f"{i}/{cost}", b"$2b$", cost))
                h = b"$2y$" + h[4:]
            else:
                h = bcrypt.hashpw(pw, salt_string(f"{i}/{cost}", prefix, cost))
            add(pw, h, True)
            add(pw + b"!", h, pw[:72] == (pw + b"!")[:72])
    add(b"cost ten", bcrypt.hashpw(b"cost ten", salt_string("ten", b"$2b$", 10)), True)
    from importlib.metadata import version
    json.dump({
        "algorithm": "bcrypt ($2a$, $2b$, $2y$), verification",
        "source": "scripts/gen_bcrypt_vectors.py with pyca/bcrypt " + version("bcrypt") +
                  " (built on the Rust bcrypt crate), run on 2026-10-12. `password` and `hash` are hex; "
                  "`verifies` is pyca/bcrypt's checkpw. Includes the classic OpenBSD vector "
                  "for \"U*U\".",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
