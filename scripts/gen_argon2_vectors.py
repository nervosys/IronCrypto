"""Argon2 vectors from the reference implementation, and PHC strings from it
and from libsodium.

    python -m venv env && env/bin/pip install argon2-cffi==23.1.0 pynacl==1.5.0
    env/bin/python -I scripts/gen_argon2_vectors.py > testvectors/argon2-reference.json

argon2-cffi bundles libargon2, the C implementation by Argon2's authors that
RFC 9106 accompanies. Its `argon2_ctx` binding takes the whole context, so
the raw cases below reach what RFC 9106's three vectors do not vary: version
0x10 beside 0x13, every variant under each, one to four lanes, memory sizes
that are not a multiple of four blocks per lane and so get rounded, tag
lengths either side of BLAKE2b's 64 bytes, and the secret and associated
data, empty and not.

The `phc` cases are encoded strings. Those from argon2-cffi are libargon2's
own encoder; those from PyNaCl are libsodium's crypto_pwhash_str, an
independent Argon2id. Each records whether its password verifies. Two have
their `v=` field removed: libargon2's decoder reads a missing version as
0x10, and it is asked to verify them here, so the expectation recorded is
its behaviour, not this script's opinion.

Nothing here computes a value itself: every hash comes from libargon2 or
libsodium.
"""

import hashlib
import json
import sys

from argon2.low_level import Type, ffi, hash_secret, lib, verify_secret
from argon2.exceptions import VerifyMismatchError, VerificationError
import nacl.pwhash.argon2id as sodium_argon2id


TYPES = {"argon2d": Type.D, "argon2i": Type.I, "argon2id": Type.ID}


def label(s, n):
    """n bytes of SHA-256 chain over a label, so inputs are reproducible."""
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{s}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


def raw(variant, version, m, t, p, pwd, salt, secret, ad, outlen):
    """One hash through libargon2's full context."""
    keep = []

    def buf(b):
        c = ffi.new("uint8_t[]", max(len(b), 1))
        ffi.memmove(c, b, len(b))
        keep.append(c)
        return c if b else ffi.NULL

    out = ffi.new("uint8_t[]", outlen)
    ctx = ffi.new("argon2_context *", dict(
        out=out, outlen=outlen, pwd=buf(pwd), pwdlen=len(pwd), salt=buf(salt),
        saltlen=len(salt), secret=buf(secret), secretlen=len(secret), ad=buf(ad),
        adlen=len(ad), t_cost=t, m_cost=m, lanes=p, threads=p, version=version,
        allocate_cbk=ffi.NULL, free_cbk=ffi.NULL, flags=lib.ARGON2_DEFAULT_FLAGS))
    rc = lib.argon2_ctx(ctx, TYPES[variant].value)
    assert rc == lib.ARGON2_OK, ffi.string(lib.argon2_error_message(rc))
    return bytes(ffi.buffer(out, outlen))


def main():
    cases = []
    # (m, t, p, outlen, salt length, secret length, ad length)
    shapes = [
        (8, 1, 1, 32, 8, 0, 0),
        (16, 2, 1, 4, 16, 0, 0),
        (33, 3, 1, 64, 16, 8, 0),      # 33 rounds down to 32 blocks
        (64, 1, 2, 65, 16, 0, 12),     # one byte over BLAKE2b's output
        (37, 2, 3, 100, 31, 16, 7),    # rounds to 36: three lanes of twelve
        (128, 3, 4, 32, 16, 32, 32),
        (256, 1, 4, 128, 20, 0, 0),
    ]
    n = 0
    for version in (0x10, 0x13):
        for variant in ("argon2d", "argon2i", "argon2id"):
            for m, t, p, outlen, saltlen, secretlen, adlen in shapes:
                tag = f"{variant}/{version}/{n}"
                n += 1
                pwd = label(tag + "/pwd", 1 + (n * 7) % 40)
                salt = label(tag + "/salt", saltlen)
                secret = label(tag + "/secret", secretlen)
                ad = label(tag + "/ad", adlen)
                out = raw(variant, version, m, t, p, pwd, salt, secret, ad, outlen)
                cases.append({"kind": "raw", "variant": variant, "version": str(version),
                              "memory_kib": str(m), "passes": str(t), "lanes": str(p),
                              "password": pwd.hex(), "salt": salt.hex(), "secret": secret.hex(),
                              "ad": ad.hex(), "tag": out.hex(), "phc": "", "verifies": ""})

    def phc(string, password, verifies):
        cases.append({"kind": "phc", "variant": "", "version": "", "memory_kib": "",
                      "passes": "", "lanes": "", "password": password.hex(), "salt": "",
                      "secret": "", "ad": "", "tag": "", "phc": string.encode().hex(),
                      "verifies": "true" if verifies else "false"})

    def reference_verifies(string, password, variant):
        try:
            return verify_secret(string.encode(), password, TYPES[variant])
        except (VerifyMismatchError, VerificationError):
            return False

    for variant in ("argon2d", "argon2i", "argon2id"):
        for version, (m, t, p, hashlen) in [(19, (64, 2, 2, 32)), (16, (32, 3, 1, 24))]:
            pw = label(f"phc/{variant}/{version}/pw", 12)
            salt = label(f"phc/{variant}/{version}/salt", 16)
            s = hash_secret(pw, salt, time_cost=t, memory_cost=m, parallelism=p,
                            hash_len=hashlen, type=TYPES[variant], version=version).decode()
            assert reference_verifies(s, pw, variant)
            phc(s, pw, True)
            phc(s, pw + b"!", False)
            if version == 16:
                stripped = s.replace("$v=16$", "$", 1)
                assert stripped != s
                ok = reference_verifies(stripped, pw, variant)
                assert ok, "libargon2 reads a missing version as 0x10"
                phc(stripped, pw, ok)

    # libsodium's Argon2id, its own implementation and encoder.
    for i, (ops, mem) in enumerate([(2, 19 * 1024 * 1024), (3, 8 * 1024 * 1024)]):
        pw = label(f"sodium/{i}", 20)
        s = sodium_argon2id.str(pw, opslimit=ops, memlimit=mem).decode()
        assert sodium_argon2id.verify(s.encode(), pw)
        phc(s, pw, True)
        phc(s, b"not " + pw, False)

    from importlib.metadata import version as v
    json.dump({
        "algorithm": "Argon2 (RFC 9106 and version 0x10) and its PHC string encoding",
        "source": "scripts/gen_argon2_vectors.py, run on 2026-10-12: raw tags from libargon2, "
                  "the Argon2 reference implementation, through argon2-cffi "
                  + v("argon2-cffi") + "'s argon2_ctx binding; PHC strings from libargon2's "
                  "encoder and from libsodium's crypto_pwhash_str through PyNaCl "
                  + v("pynacl") + ". Inputs are SHA-256 chains over labels. libsodium salts are "
                  "its own random draws, so rerunning changes those cases and nothing else.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
