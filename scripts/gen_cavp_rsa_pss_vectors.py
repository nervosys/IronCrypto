"""Convert NIST's CAVP RSASSA-PSS signature-generation examples into this
repository's vector format.

    python scripts/gen_cavp_rsa_pss_vectors.py <SigGenPSS_186-3.txt> \\
        > testvectors/cavp-rsa-pss-sign.json

The input is one file of NIST's "186-3rsatestvectors.zip", from the CAVP's
digital-signature page:

    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip

It is checked against the SHA-256 below. The archive it was taken from had
SHA-256 8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c
when downloaded on 2026-10-10.

A PSS signature is randomized, so a published signature says nothing about a
signer unless the salt is published with it. This file is the one place NIST
does that: its ReadmeRSA.txt says the `.txt` carries "the additional value d
and Saltvalue added to the file for testing purposes". With the key, the
message and the salt, the signature is determined.

NIST chose salt lengths that mostly are not the hash's length. This library
makes and accepts one PSS only, with a salt as long as the hash, so the cases
divide in two:

- `sign`: the salt is as long as the hash -- SHA-256 and SHA-384 at 3072
  bits, ten messages each. The signer must produce the signature given.
- `refuse`: the salt is some other length -- SHA-256, SHA-384 and SHA-512 at
  2048 bits, and SHA-512 at 3072. These are valid signatures of a PSS this
  library does not have, and its verifier must refuse them.

The SHA-224 groups are left out; this library has no SHA-224 signature.
NIST gives the modulus and both exponents and no primes, so these reach the
signer without the CRT and not with it.

Nothing here computes a cryptographic value.
"""

import hashlib
import json
import re
import sys

PINNED = "46de7f2fccb5f89516e64b5bdb1c4fd456a09c9cc680dd64e0756e62ff5000ec"
HASHES = {"SHA256": ("sha256", 32), "SHA384": ("sha384", 48), "SHA512": ("sha512", 64)}


def main():
    with open(sys.argv[1], "rb") as f:
        raw = f.read()
    assert hashlib.sha256(raw).hexdigest() == PINNED, "not the file this was written against"
    text = raw.decode("ascii")

    cases = []
    counts = {}
    sections = re.split(r"\[mod = (\d+)\]", text)[1:]
    for bits, body in zip(sections[0::2], sections[1::2]):
        fields = dict(re.findall(r"^(n|e|d) = ([0-9a-f]+)\s*$", body, re.M))
        assert set(fields) == {"n", "e", "d"} and len(fields["n"]) * 4 == int(bits)
        key = "rsa" + bits
        cases.append({"kind": "key", "key": key, "hash": "", "n": fields["n"],
                      "e": fields["e"].lstrip("0"), "d": fields["d"], "message": "",
                      "salt": "", "signature": ""})
        blocks = re.findall(
            r"SHAAlg = (\S+)\s+Msg = ([0-9a-f]+)\s+S = ([0-9a-f]+)\s+SaltVal = ([0-9a-f]+)", body)
        assert len(blocks) == 40, len(blocks)
        for alg, message, signature, salt in blocks:
            if alg == "SHA224":
                continue
            name, length = HASHES[alg]
            kind = "sign" if len(salt) == 2 * length else "refuse"
            counts[(bits, name, kind)] = counts.get((bits, name, kind), 0) + 1
            cases.append({"kind": kind, "key": key, "hash": name, "n": "", "e": "", "d": "",
                          "message": message, "salt": salt, "signature": signature})
    assert counts == {
        ("2048", "sha256", "refuse"): 10, ("2048", "sha384", "refuse"): 10,
        ("2048", "sha512", "refuse"): 10, ("3072", "sha256", "sign"): 10,
        ("3072", "sha384", "sign"): 10, ("3072", "sha512", "refuse"): 10,
    }, counts

    json.dump({
        "algorithm": "RSASSA-PSS signing with a given salt",
        "source": "NIST CAVP, 186-3rsatestvectors.zip, SigGenPSS_186-3.txt (CAVS 11.4), SHA-256 "
                  + PINNED + ", converted by scripts/gen_cavp_rsa_pss_vectors.py. The file "
                  "gives the private exponent and the salt, so each signature is determined. A "
                  "`key` case gives the modulus and both exponents; the cases after it name it. "
                  "`sign`: the salt is as long as the hash, and the signer must produce "
                  "`signature`. `refuse`: NIST's salt is another length, a PSS this library "
                  "does not have, and the verifier must refuse `signature`. SHA-224 is left out.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
