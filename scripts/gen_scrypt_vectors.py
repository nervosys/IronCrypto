"""scrypt vectors from OpenSSL, through Python's hashlib.

    python -I scripts/gen_scrypt_vectors.py > testvectors/scrypt-openssl.json

hashlib.scrypt is OpenSSL's EVP_PBE_scrypt, an implementation that shares
nothing with IronCrypto. RFC 7914's four vectors fix four shapes; these vary
N, r and p independently, use salts and passwords of awkward lengths
including empty ones, and ask for outputs shorter than, equal to and longer
than one SHA-256 block of PBKDF2 output. Before writing anything, the script
checks that OpenSSL reproduces RFC 7914's first three vectors.

Inputs are SHA-256 chains over labels, so the file is reproducible.
"""

import hashlib
import json
import ssl
import sys


def label(s, n):
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(f"{s}/{i}".encode()).digest()
        i += 1
    return out[:n]


def main():
    rfc = [
        (b"", b"", 16, 1, 1, "77d6576238657b203b19ca42c18a0497"),
        (b"password", b"NaCl", 1024, 8, 16, "fdbabe1c9d3472007856e7190d01e9fe"),
        (b"pleaseletmein", b"SodiumChloride", 16384, 8, 1, "7023bdcb3afd7348461c06cd81fd38eb"),
    ]
    for pw, salt, n, r, p, prefix in rfc:
        got = hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, dklen=64, maxmem=1 << 30)
        assert got.hex().startswith(prefix), (n, r, p)

    shapes = [
        (2, 1, 1, 1, 0, 0), (4, 1, 3, 16, 1, 7), (8, 2, 1, 31, 16, 32),
        (10, 3, 2, 32, 8, 13), (12, 8, 1, 33, 16, 64), (6, 16, 4, 64, 64, 1),
        (14, 1, 1, 100, 20, 40), (3, 5, 7, 7, 3, 2),
    ]
    cases = []
    for i, (log_n, r, p, outlen, saltlen, pwlen) in enumerate(shapes):
        pw, salt = label(f"pw{i}", pwlen), label(f"salt{i}", saltlen)
        out = hashlib.scrypt(pw, salt=salt, n=1 << log_n, r=r, p=p, dklen=outlen,
                             maxmem=1 << 30)
        cases.append({"log_n": str(log_n), "r": str(r), "p": str(p), "password": pw.hex(),
                      "salt": salt.hex(), "out": out.hex()})
    json.dump({
        "algorithm": "scrypt (RFC 7914)",
        "source": "scripts/gen_scrypt_vectors.py, run on 2026-10-12: Python's hashlib.scrypt, "
                  "which is " + ssl.OPENSSL_VERSION + "'s EVP_PBE_scrypt, after checking it "
                  "against RFC 7914's first three vectors. Inputs are SHA-256 chains over "
                  "labels.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
