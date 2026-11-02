"""Generate testvectors/composite-mldsa-draft19.json from the text of
draft-ietf-lamps-pq-composite-sigs-19, Appendix E.

    curl -o draft.txt https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-19.txt
    python -I scripts/gen_composite_sig_vectors.py draft.txt > testvectors/composite-mldsa-draft19.json

The appendix is one JSON document, word-wrapped across pages. This drops the
page headers and footers, removes the wrapping -- no value in it contains
whitespace -- parses it, and keeps the three composites this library
implements. Every base64 value is converted to hex; the message and the
context are copied into each case. The draft's digest is checked, so a
different text is refused rather than converted.

Values from the specification's own appendix, which the authors generated
with their reference implementation. An Internet-Draft is not a standard, and
these vectors change with it.
"""

import base64
import hashlib
import json
import re
import sys

DRAFT_SHA256 = "b4ee04416efc26e7d8de7c740dc3848ffe8b8cc9dcd035ad9d4e33e18844ec83"
KEEP = ["id-MLDSA44-Ed25519-SHA512", "id-MLDSA65-Ed25519-SHA512", "id-MLDSA87-Ed448-SHAKE256"]


def tlv(der, at):
    """The tag, and the start and end of the contents, of the DER element at
    `at`; and where the element ends."""
    tag = der[at]
    n = der[at + 1]
    at += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(der[at : at + k], "big")
        at += k
    return tag, at, at + n


def certificate_parts(der):
    """From an X.509 certificate: the DER of its TBSCertificate and of its
    SubjectPublicKeyInfo, its signature algorithm's OID content bytes, and
    the signature."""
    tag, start, end = tlv(der, 0)
    assert tag == 0x30 and end == len(der)
    tag, tbs_start, tbs_end = tlv(der, start)
    assert tag == 0x30
    tbs = der[start:tbs_end]
    # version [0], serialNumber, signature, issuer, validity, subject, then
    # subjectPublicKeyInfo.
    at = tbs_start
    fields = []
    while at < tbs_end:
        tag, _, after = tlv(der, at)
        fields.append((tag, at, after))
        at = after
    assert fields[0][0] == 0xA0
    _, spki_at, spki_end = fields[6]
    spki = der[spki_at:spki_end]
    tag, alg_start, alg_end = tlv(der, tbs_end)
    assert tag == 0x30
    tag, oid_start, oid_end = tlv(der, alg_start)
    assert tag == 0x06 and oid_end == alg_end, "signature algorithm with parameters"
    oid = der[oid_start:oid_end]
    tag, bits_start, bits_end = tlv(der, alg_end)
    assert tag == 0x03 and bits_end == end and der[bits_start] == 0
    return tbs, spki, oid, der[bits_start + 1 : bits_end]


def spki_key(spki):
    """The algorithm OID's content bytes, whether parameters follow it, and
    the key."""
    _, start, end = tlv(spki, 0)
    tag, alg_start, alg_end = tlv(spki, start)
    assert tag == 0x30
    tag, oid_start, oid_end = tlv(spki, alg_start)
    assert tag == 0x06
    tag, bits_start, bits_end = tlv(spki, alg_end)
    assert tag == 0x03 and bits_end == end and spki[bits_start] == 0
    return spki[oid_start:oid_end], oid_end != alg_end, spki[bits_start + 1 : bits_end]


def main():
    raw = open(sys.argv[1], "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != DRAFT_SHA256:
        sys.exit(f"{sys.argv[1]}: SHA-256 {digest}, expected {DRAFT_SHA256}")
    text = raw.decode("utf-8")
    body = text[text.index("\nAppendix E.  Test Vectors\n") : text.index("\nAppendix F.  Contributors")]
    body = re.sub(r"\nOunsworth, et al\.[^\n]*\n\x0c?\nInternet-Draft[^\n]*\n", "\n", body)
    blob = body[body.index("{") : body.rindex("}") + 1]
    assert "Ounsworth" not in blob and "Internet-Draft" not in blob
    data = json.loads(re.sub(r"\s+", "", blob))

    m = base64.b64decode(data["m"]).hex()
    ctx = base64.b64decode(data["ctx"]).hex()
    by_id = {t["tcId"]: t for t in data["tests"]}
    cases = []
    for tc in KEEP:
        t = by_id[tc]
        case = {"tcId": tc, "m": m, "ctx": ctx}
        for k in ("pk", "sk", "sk_pkcs8", "s", "sWithContext"):
            case[k] = base64.b64decode(t[k]).hex()
        # The self-signed certificate: its key must be `pk`, under the
        # algorithm it is signed with, with no parameters.
        tbs, spki, oid, signature = certificate_parts(base64.b64decode(t["x5c"]))
        key_oid, parameters, key = spki_key(spki)
        assert key_oid == oid and not parameters and key.hex() == case["pk"], tc
        case["oid"] = oid.hex()
        case["spki"] = spki.hex()
        case["tbs"] = tbs.hex()
        case["certSignature"] = signature.hex()
        cases.append(case)
    json.dump({
        "algorithm": "Composite ML-DSA: id-MLDSA44-Ed25519-SHA512, id-MLDSA65-Ed25519-SHA512, "
                     "id-MLDSA87-Ed448-SHAKE256",
        "source": "draft-ietf-lamps-pq-composite-sigs-19, Appendix E (text SHA-256 "
                  f"{DRAFT_SHA256}), converted by scripts/gen_composite_sig_vectors.py. "
                  "`s` is over `m` with the empty context, `sWithContext` over `m` with `ctx`. "
                  "`spki`, `tbs` and `certSignature` are from the case's self-signed "
                  "certificate `x5c`: its SubjectPublicKeyInfo, its TBSCertificate, and its "
                  "signature, over `tbs` with the empty context; `oid` is the algorithm's. "
                  "The authors' reference implementation's values, from an Internet-Draft "
                  "rather than a standard.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
