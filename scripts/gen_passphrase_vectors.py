"""Seal reference containers for `ic_kdf::passphrase` with libsodium and the
Argon2 reference implementation, independently of this library.

    python -m venv env && env/bin/pip install argon2-cffi==23.1.0 pynacl==1.5.0
    env/bin/python -I scripts/gen_passphrase_vectors.py > testvectors/passphrase.json

argon2-cffi wraps the Argon2 reference code from the RFC 9106 authors, and
PyNaCl wraps libsodium, whose crypto_aead_xchacha20poly1305_ietf is the
XChaCha20-Poly1305 the draft describes. Neither shares a line with IronCrypto.
This script writes the container format by hand from the description in
`crates/ic-kdf/src/passphrase.rs`, and is the second implementation of it:

    magic "ICPW" | version 1 | kdf 1 (Argon2id) | aead 1 (XChaCha20-Poly1305)
    | memory KiB, passes, lanes (u32 big-endian each) | salt (16) | nonce (24)
    | ciphertext | tag (16)

The 59-byte header is the AEAD's associated data. The key is 32 bytes of
Argon2id, version 0x13, over the passphrase and salt with no secret and no
associated data.

The salts and nonces below are fixed so that the output is reproducible; a
real seal draws both. The first case uses parameters far under the floor the
library enforces, and is only reachable through its internal, test-only path:
it exists so the self-test can afford to run. The others are at the floor and
open through the public API.

As a check on PyNaCl itself, the draft's appendix A.3.1 vector is sealed
first and must come out as the draft prints it.
"""

import hashlib
import json
import struct
import sys

import argon2
from argon2.low_level import Type, hash_secret_raw
import nacl
import nacl.bindings as sodium

MAGIC = b"ICPW"


def seal(passphrase, memory_kib, passes, lanes, salt, nonce, plaintext):
    assert len(salt) == 16 and len(nonce) == 24
    header = MAGIC + bytes([1, 1, 1]) + struct.pack(">III", memory_kib, passes, lanes) \
        + salt + nonce
    assert len(header) == 59
    key = hash_secret_raw(passphrase, salt, time_cost=passes, memory_cost=memory_kib,
                          parallelism=lanes, hash_len=32, type=Type.ID, version=19)
    return header + sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, header,
                                                                     nonce, key)


def label(s, n):
    return hashlib.sha256(s.encode()).digest()[:n]


def main():
    # draft-irtf-cfrg-xchacha-03 A.3.1 through libsodium.
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
          b"for the future, sunscreen would be it.")
    out = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        pt, bytes.fromhex("50515253c0c1c2c3c4c5c6c7"), bytes(range(0x40, 0x58)),
        bytes(range(0x80, 0xa0)))
    assert out.hex().endswith("c0875924c1c7987947deafd8780acf49"), "libsodium disagrees"

    cases = []
    for name, passphrase, (m, t, p), plaintext in [
        ("self-test", b"IronCrypto passphrase self-test", (8, 1, 1), b"self-test plaintext"),
        ("floor, empty", b"correct horse battery staple", (19456, 2, 1), b""),
        ("floor, a CA key", "pässwörd with ünïcode".encode(), (19456, 2, 1),
         label("ca key", 32) + label("ca key 2", 16)),
        ("floor, two lanes", b"x", (19456, 2, 2), b"two lanes"),
    ]:
        salt, nonce = label(name + " salt", 16), label(name + " nonce", 24)
        sealed = seal(passphrase, m, t, p, salt, nonce, plaintext)
        cases.append({"name": name.encode().hex(), "passphrase": passphrase.hex(),
                      "memory_kib": str(m), "passes": str(t), "lanes": str(p),
                      "salt": salt.hex(), "nonce": nonce.hex(), "plaintext": plaintext.hex(),
                      "sealed": sealed.hex()})
    from importlib.metadata import version
    json.dump({
        "algorithm": "Passphrase sealing: Argon2id and XChaCha20-Poly1305, format ICPW v1",
        "source": "scripts/gen_passphrase_vectors.py with argon2-cffi " + version("argon2-cffi")
                  + " (the Argon2 reference implementation) and PyNaCl " + version("pynacl")
                  + " (libsodium), run on 2026-10-12. The container is written by that script "
                  "from the format's description, independently of ic_kdf. Salts and nonces "
                  "are SHA-256 of labels so the output is reproducible; a real seal draws them. "
                  "`name` is hex. The first case is under the library's floor and is for the "
                  "self-test only.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
