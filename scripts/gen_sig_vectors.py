"""Generate testvectors/openssl-sig.json: signatures made by OpenSSL, through
pyca/cryptography, for `ic_sig::verify`.

    python scripts/gen_sig_vectors.py > testvectors/openssl-sig.json

Each case is a public key as a DER SubjectPublicKeyInfo, a message, and a
signature in the form X.509 and TLS 1.3 carry -- a DER Ecdsa-Sig-Value for
ECDSA, the algorithm's own bytes otherwise -- which is exactly what
`ic_sig::verify` takes. The keys are generated here and discarded; nothing
depends on which keys they are.

These are interoperability vectors from an independent implementation, not
values from a standard. RSA-PSS uses MGF1 with the same hash and a salt as long
as the hash, which is what the ontology's rsa-pss entries and TLS 1.3 specify.
ML-DSA is not here: `testvectors/openssl-x509.json` already carries
OpenSSL-made ML-DSA signatures, on certificates, and the test reads those.
"""

import json
import sys

import cryptography
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

MESSAGES = [b"", b"IronCrypto ic-sig interoperability vector", bytes(range(256)) * 3]


def spki(key):
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def main():
    cases = []

    def add(algorithm, key, sign):
        for message in MESSAGES:
            cases.append({"algorithm": algorithm, "spki": spki(key).hex(),
                          "message": message.hex(), "signature": sign(message).hex()})

    for name, curve, h in [("ecdsa-p256-sha256", ec.SECP256R1(), hashes.SHA256()),
                           ("ecdsa-p384-sha384", ec.SECP384R1(), hashes.SHA384()),
                           ("ecdsa-p521-sha512", ec.SECP521R1(), hashes.SHA512())]:
        key = ec.generate_private_key(curve)
        add(name, key, lambda m, key=key, h=h: key.sign(m, ec.ECDSA(h)))

    ed = ed25519.Ed25519PrivateKey.generate()
    add("ed25519", ed, ed.sign)

    # One key per size, each signing under all six RSA algorithms: an RSA key
    # serves every one of them.
    for bits in (2048, 3072):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        for tag, h in [("sha256", hashes.SHA256()), ("sha384", hashes.SHA384()),
                       ("sha512", hashes.SHA512())]:
            add(f"rsa-pkcs1-{tag}", key,
                lambda m, key=key, h=h: key.sign(m, padding.PKCS1v15(), h))
            add(f"rsa-pss-{tag}", key,
                lambda m, key=key, h=h: key.sign(
                    m, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h))

    json.dump({
        "algorithm": "signature verification by algorithm over SubjectPublicKeyInfo",
        "source": f"scripts/gen_sig_vectors.py with pyca/cryptography {cryptography.__version__} "
                  f"({backend.openssl_version_text()}). Keys generated and discarded; ECDSA "
                  "signatures are DER Ecdsa-Sig-Value, RSA-PSS uses MGF1 with the same hash and "
                  "a salt as long as the hash. Interoperability vectors from an independent "
                  "implementation, not values from a standard.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
