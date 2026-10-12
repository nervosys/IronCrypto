"""Transcribe OPAQUE's P-256 test vectors from RFC 9807.

    python -I scripts/gen_opaque_vectors.py <dir> > testvectors/rfc9807-p256.json

<dir> holds rfc9807.txt as published at
https://www.rfc-editor.org/rfc/rfc9807.txt, checked against the SHA-256
below. Appendix C.1.5 and C.1.6 are the two real test vectors for the
P256-SHA256 configuration -- the second with client and server identities
-- and C.2.3 the fake one, a login against a client with no record. Every
value under Input Values, Intermediate Values and Output Values is copied,
joined across the RFC's line wraps; nothing is computed. The configuration
block is checked to be the P-256 one, with the Identity KSF and the context
"OPAQUE-POC", before anything is written.
"""

import hashlib
import json
import re
import sys

PINNED = "424103278391d8955713ea8b3a85509e5178fab536be42144b99d298458acc03"
KEY = re.compile(r"^\s{3}([A-Za-z][\w]*):\s?(.*)$")


def main():
    raw = open(sys.argv[1] + "/rfc9807.txt", "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != PINNED:
        raise SystemExit(f"rfc9807.txt: SHA-256 {digest} is not the pinned file")
    lines = raw.decode("utf-8-sig").split("\n")

    def body(start, end):
        a = next(i for i, l in enumerate(lines) if l.startswith(start))
        b = next(i for i, l in enumerate(lines) if i > a and l.startswith(end))
        return lines[a + 1:b]

    cases = []
    for name, start, end, kind in [
        ("C.1.5", "C.1.5.  ", "C.1.6.  ", "real"),
        ("C.1.6", "C.1.6.  ", "C.2.  ", "real"),
        ("C.2.3", "C.2.3.  ", "Acknowledgments", "fake"),
    ]:
        fields = {}
        last = None
        for line in body(start, end):
            if not line.strip() or line.startswith(("RFC ", "Bourdrez")) or "\f" in line \
                    or re.match(r"^C\.\d", line):
                continue
            m = KEY.match(line)
            if m:
                last = m.group(1)
                fields[last] = m.group(2).strip()
            elif last is not None:
                fields[last] += line.strip()
        assert fields["OPRF"] == "P256-SHA256" and fields["KSF"] == "Identity", name
        assert fields["Context"] == b"OPAQUE-POC".hex(), name
        for k in ("OPRF", "Hash", "KSF", "KDF", "MAC", "Group", "Nh", "Npk", "Nsk", "Nm",
                  "Nx", "Nok"):
            fields.pop(k)
        cases.append({"name": name, "kind": kind, **fields})
    json.dump({
        "algorithm": "OPAQUE-3DH with P256-SHA256, HKDF-SHA256, HMAC-SHA256, SHA-256",
        "source": "RFC 9807 appendices C.1.5, C.1.6 and C.2.3, transcribed by "
                  "scripts/gen_opaque_vectors.py from rfc9807.txt (SHA-256 " + PINNED + "). "
                  "All three use the Identity KSF and the context OPAQUE-POC, given hex as "
                  "`Context`.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
