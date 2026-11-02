"""Generate testvectors/openssl-ed448.json: Ed448 keys and signatures OpenSSL
made, for `ic_pkix` and `ic_sig`.

    python scripts/gen_ed448_vectors.py > testvectors/openssl-ed448.json

Four keys, three messages each: a case per pair. Each carries the PKCS#8
OpenSSL wrote (RFC 8410: the 57-byte seed in an OCTET STRING), the
SubjectPublicKeyInfo OpenSSL derived from it, the message and OpenSSL's
signature over it. Not the empty one: the
OpenSSL 3.5 command refuses to sign zero bytes, and RFC 8032's "Blank"
vector covers it. Pure Ed448 with the empty context, which is what X.509's
id-Ed448 means; Ed448 is deterministic, so this library's signatures must
equal these byte for byte.

Needs the `openssl` command at 3.0 or later. Keys are generated and
discarded, so no two runs give the same file. **These are test keys in a
public repository and protect nothing.**

Interoperability vectors from an independent implementation, not values from
a standard: RFC 8032 section 7.4 holds the algorithm. What these hold is the
key encodings, and agreement with OpenSSL on keys the RFC did not choose.
"""

import json
import os
import subprocess
import sys
import tempfile

MESSAGES = [b"\x00", b"IronCrypto Ed448 interoperability vector", bytes(range(256)) * 3]
KEYS = 4


def run(*args):
    return subprocess.run(args, check=True, capture_output=True).stdout


def main():
    version = run("openssl", "version").decode().strip()
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        pem, msg, sig = (os.path.join(tmp, n) for n in ("key.pem", "msg", "sig"))
        for _ in range(KEYS):
            run("openssl", "genpkey", "-algorithm", "ED448", "-out", pem)
            pkcs8 = run("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", pem, "-outform", "DER")
            spki = run("openssl", "pkey", "-in", pem, "-pubout", "-outform", "DER")
            for m in MESSAGES:
                with open(msg, "wb") as f:
                    f.write(m)
                run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", pem, "-in", msg,
                    "-out", sig)
                with open(sig, "rb") as f:
                    s = f.read()
                assert len(s) == 114, len(s)
                # OpenSSL verifies its own signature, so a case is never a
                # value OpenSSL itself would refuse.
                pub = os.path.join(tmp, "pub.pem")
                run("openssl", "pkey", "-in", pem, "-pubout", "-out", pub)
                run("openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pub,
                    "-in", msg, "-sigfile", sig)
                cases.append({"pkcs8": pkcs8.hex(), "spki": spki.hex(), "message": m.hex(),
                              "signature": s.hex()})
    json.dump({
        "algorithm": "Ed448 (RFC 8032), keys as PKCS#8 and SubjectPublicKeyInfo (RFC 8410)",
        "source": f"scripts/gen_ed448_vectors.py with {version}. Keys generated and "
                  "discarded: test keys that protect nothing. Pure Ed448, empty context. "
                  "Interoperability vectors from an independent implementation, not values "
                  "from a standard.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
