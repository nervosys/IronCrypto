"""Convert IronPrivacyGuard's certificate-signature fixtures into this
repository's vector format, for `ic_sig::verify`.

    git -C ../IronPrivacyGuard show 1ffc55e:tests/vectors/x509-signatures.json \\
        | python scripts/import_x509_signature_vectors.py > testvectors/pyca-x509-signatures.json

The fixtures are 22 self-signed certificates that IronPrivacyGuard generated
with pyca/cryptography (its tests/interop/x509_signature_vectors.py) to test
its own certificate-signature code. That code was removed when
IronPrivacyGuard moved to IronPKI, at the commit after 1ffc55e, and the
fixtures with it. What they exercise is now `ic_sig::verify`, so they are
kept here. The certificates and keys are copied byte for byte. The keys were
generated and discarded, so this file cannot be regenerated from here; the
generator is in IronPrivacyGuard's history at that commit.

Two fields are added, and they are this script's reading, not PyCA's:

- `algorithm`: the `ic_core::sig::SignatureAlgorithm` a certificate's
  signature algorithm names. X.509's ECDSA identifiers name a hash and no
  curve, and this library's ECDSA algorithms fix both, so ecdsa-with-SHA384
  is read as `ecdsa-p384-sha384` whatever key signed.
- `expected`: what `ic_sig::verify` must do, which is not always what
  IronPrivacyGuard did:
    valid              verifies.
    key-mismatch       the key is not one for the algorithm named: a P-256
                       key under ecdsa-with-SHA384, and the reverse.
    invalid-signature  the signature does not verify as that algorithm: an
                       RSA-PSS signature with a salt of another length, or
                       with MGF1 over another hash.
  IronPrivacyGuard refused P-521 by its own policy; this library has it, so
  that case is `valid` here. `ipg_accepted` keeps IronPrivacyGuard's verdict.

Nothing here computes a cryptographic value.
"""

import json
import sys

# name -> (algorithm the certificate names, what ic_sig::verify must do)
READING = {
    "p256_sha256": ("ecdsa-p256-sha256", "valid"),
    "p384_sha384": ("ecdsa-p384-sha384", "valid"),
    "ed25519": ("ed25519", "valid"),
    "unsupported_p256_sha384": ("ecdsa-p384-sha384", "key-mismatch"),
    "unsupported_p384_sha256": ("ecdsa-p256-sha256", "key-mismatch"),
    "unsupported_p521": ("ecdsa-p521-sha512", "valid"),
}
for bits in ("2048", "4096"):
    for sha in ("sha256", "sha384", "sha512"):
        READING[f"rsa{bits}_pkcs1_{sha}"] = (f"rsa-pkcs1-{sha}", "valid")
        READING[f"rsa{bits}_pss_{sha}"] = (f"rsa-pss-{sha}", "valid")
    # Both are signed over SHA-256: one with an empty salt, one with MGF1
    # over SHA-384.
    READING[f"unsupported_rsa{bits}_pss_salt"] = ("rsa-pss-sha256", "invalid-signature")
    READING[f"unsupported_rsa{bits}_pss_mgf"] = ("rsa-pss-sha256", "invalid-signature")


def main():
    source = json.load(sys.stdin)
    assert source["provenance"] == "PyCA; disposable keys; public-only signature fixtures"
    cases = []
    for case in source["cases"]:
        algorithm, expected = READING[case["name"]]
        cases.append({"name": case["name"], "algorithm": algorithm, "expected": expected,
                      "ipg_accepted": "true" if case["accepted"] else "false",
                      "certificate": case["certificate"], "issuer_spki": case["issuer_spki"]})
    assert len(cases) == 22 == len(READING)
    json.dump({
        "algorithm": "X.509 certificate signatures, for ic_sig::verify",
        "source": "IronPrivacyGuard commit 1ffc55e, tests/vectors/x509-signatures.json, generated "
                  "there with pyca/cryptography by tests/interop/x509_signature_vectors.py: 22 "
                  "self-signed certificates under disposable keys. Certificates and keys are "
                  "copied unchanged by scripts/import_x509_signature_vectors.py, which adds "
                  "`algorithm` and `expected`, its own reading. Interoperability vectors from an "
                  "independent implementation, not values from a standard.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
