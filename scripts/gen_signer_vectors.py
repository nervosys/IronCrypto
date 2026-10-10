"""Generate testvectors/openssl-private-keys.json: private keys OpenSSL made,
for `ic_sig::SoftwareSigner`.

    python scripts/gen_signer_vectors.py > testvectors/openssl-private-keys.json

One key per algorithm: ECDSA over P-256, P-384 and P-521, Ed25519, RSA at
2048 and 3072 bits, ML-DSA-44, -65 and -87, and SLH-DSA in all twelve
parameter sets. Each case carries the key as the PKCS#8 OpenSSL wrote and the
SubjectPublicKeyInfo OpenSSL derived from it.

Where the algorithm is deterministic and OpenSSL signs it that way -- Ed25519
and RSA PKCS#1 v1.5 with SHA-256 -- the case also carries OpenSSL's signature
over one message, which this library's must equal byte for byte.

Needs the `openssl` command at 3.5 or later. Keys are generated and discarded,
so no two runs give the same file. **These are test keys in a public
repository and protect nothing.**

Interoperability vectors from an independent implementation, not values from
a standard. What they hold is the reading of the key file: that a PKCS#8 key
another implementation wrote is read as the key it is, and gives the public
key that implementation says it has.
"""

import json
import os
import subprocess
import sys
import tempfile

MESSAGE = b"IronCrypto ic-sig SoftwareSigner interoperability vector"

SLH = ["SHA2-128s", "SHA2-128f", "SHA2-192s", "SHA2-192f", "SHA2-256s", "SHA2-256f",
       "SHAKE-128s", "SHAKE-128f", "SHAKE-192s", "SHAKE-192f", "SHAKE-256s", "SHAKE-256f"]

# (name here, genpkey arguments, deterministic signing arguments or None)
KEYS = [
    ("ecdsa-p256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"], None),
    ("ecdsa-p384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"], None),
    ("ecdsa-p521", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"], None),
    ("ed25519", ["-algorithm", "ED25519"], ["-rawin"]),
    ("rsa-2048", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
     ["-rawin", "-digest", "sha256"]),
    ("rsa-3072", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
     ["-rawin", "-digest", "sha256"]),
    ("ml-dsa-44", ["-algorithm", "ML-DSA-44"], None),
    ("ml-dsa-65", ["-algorithm", "ML-DSA-65"], None),
    ("ml-dsa-87", ["-algorithm", "ML-DSA-87"], None),
] + [("slh-dsa-" + s.lower(), ["-algorithm", "SLH-DSA-" + s], None) for s in SLH]


def run(*args):
    return subprocess.run(args, check=True, capture_output=True).stdout


def main():
    version = run("openssl", "version").decode().strip()
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        pem, msg, sig = (os.path.join(tmp, n) for n in ("key.pem", "msg", "sig"))
        with open(msg, "wb") as f:
            f.write(MESSAGE)
        for name, genpkey, signing in KEYS:
            run("openssl", "genpkey", *genpkey, "-out", pem)
            pkcs8 = run("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", pem, "-outform", "DER")
            spki = run("openssl", "pkey", "-in", pem, "-pubout", "-outform", "DER")
            signature = b""
            if signing is not None:
                run("openssl", "pkeyutl", "-sign", *signing, "-inkey", pem, "-in", msg,
                    "-out", sig)
                with open(sig, "rb") as f:
                    signature = f.read()
            cases.append({"key": name, "pkcs8": pkcs8.hex(), "spki": spki.hex(),
                          "message": MESSAGE.hex(), "signature": signature.hex()})
    json.dump({
        "algorithm": "PKCS#8 private keys, for signing through ic_core::sig::Signer",
        "source": f"scripts/gen_signer_vectors.py with {version}. One key per algorithm, "
                  "generated and discarded: test keys that protect nothing. `spki` is the "
                  "public key OpenSSL derived; `signature`, where present, is OpenSSL's "
                  "deterministic signature over `message` (Ed25519, and RSA PKCS#1 v1.5 with "
                  "SHA-256). Interoperability vectors from an independent implementation, not "
                  "values from a standard.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
