"""Generate testvectors/openssl-slh-dsa.json: SLH-DSA keys and signatures made
by OpenSSL, for `ic_sig::verify`.

    python scripts/gen_slh_dsa_sig_vectors.py > testvectors/openssl-slh-dsa.json

One case per parameter set, all twelve: a key OpenSSL generated, as the
SubjectPublicKeyInfo it wrote, and its signature over one message -- pure
SLH-DSA with an empty context, hedged, which is what RFC 9909 puts in a
certificate.

Needs the `openssl` command at 3.5 or later. Keys are generated and
discarded, and signing is hedged, so no two runs give the same file.

These are interoperability vectors from an independent implementation, not
values from a standard. What they add to NIST's ACVP vectors, which already
hold the algorithm, is the key encoding: that each of RFC 9909's twelve object
identifiers is read as the parameter set OpenSSL meant by it.
"""

import json
import os
import subprocess
import sys
import tempfile

SETS = ["SHA2-128s", "SHA2-128f", "SHA2-192s", "SHA2-192f", "SHA2-256s", "SHA2-256f",
        "SHAKE-128s", "SHAKE-128f", "SHAKE-192s", "SHAKE-192f", "SHAKE-256s", "SHAKE-256f"]

MESSAGE = b"IronCrypto ic-sig SLH-DSA interoperability vector"


def run(*args):
    return subprocess.run(args, check=True, capture_output=True).stdout


def main():
    version = run("openssl", "version").decode().strip()
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        key, msg, sig = (os.path.join(tmp, n) for n in ("key.pem", "msg", "sig"))
        with open(msg, "wb") as f:
            f.write(MESSAGE)
        for name in SETS:
            run("openssl", "genpkey", "-algorithm", "SLH-DSA-" + name, "-out", key)
            spki = run("openssl", "pkey", "-in", key, "-pubout", "-outform", "DER")
            run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", msg, "-out", sig)
            # OpenSSL checks its own work before it is written down.
            run("openssl", "pkeyutl", "-verify", "-rawin", "-inkey", key, "-in", msg,
                "-sigfile", sig)
            with open(sig, "rb") as f:
                signature = f.read()
            cases.append({"algorithm": "slh-dsa-" + name.lower(), "spki": spki.hex(),
                          "message": MESSAGE.hex(), "signature": signature.hex()})
    json.dump({
        "algorithm": "SLH-DSA signature verification over SubjectPublicKeyInfo",
        "source": f"scripts/gen_slh_dsa_sig_vectors.py with {version}. One key per parameter "
                  "set, generated and discarded; pure SLH-DSA, empty context, hedged. "
                  "Interoperability vectors from an independent implementation, not values "
                  "from a standard.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
