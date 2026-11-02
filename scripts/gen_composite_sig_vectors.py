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
        cases.append(case)
    json.dump({
        "algorithm": "Composite ML-DSA: id-MLDSA44-Ed25519-SHA512, id-MLDSA65-Ed25519-SHA512, "
                     "id-MLDSA87-Ed448-SHAKE256",
        "source": "draft-ietf-lamps-pq-composite-sigs-19, Appendix E (text SHA-256 "
                  f"{DRAFT_SHA256}), converted by scripts/gen_composite_sig_vectors.py. "
                  "`s` is over `m` with the empty context, `sWithContext` over `m` with `ctx`. "
                  "The authors' reference implementation's values, from an Internet-Draft "
                  "rather than a standard.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
