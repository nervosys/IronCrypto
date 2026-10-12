"""Have OpenSSL issue an Ed25519 certificate carrying a URI subject
alternative name, and write a PKCS#10 request for the same key and names.

    python scripts/gen_x509_uri_csr_vectors.py > testvectors/openssl-x509-uri-csr.json

Ed25519 signs deterministically, so with the keys, serials, names and
validity fixed, a certificate and a request are functions of their inputs,
and ic_pkix must produce OpenSSL's bytes exactly. The keys are made from the
seeds below, which are SHA-256 of a label so that anyone can rebuild them;
they protect nothing.

Run with the `openssl` on PATH, which must be 3.x. The commands are recorded
in the output. Nothing here computes a cryptographic value: OpenSSL does.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

URI = "nanda:ed25519:node-7:worker"
DNS = "agent.example"
CA_CN = "IronCrypto Test CA"
NOT_BEFORE = "20260101000000Z"
NOT_AFTER = "20360101000000Z"
CA_SERIAL = "0x3c1d5a0b9e8f7a61"
LEAF_SERIAL = "0x51e2c3a4b5d6e7f8"

CONFIG = """[req]
distinguished_name = dn
prompt = no
[dn]
[ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = DNS:{dns},URI:{uri}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[request]
subjectAltName = DNS:{dns},URI:{uri}
""".format(dns=DNS, uri=URI)


def seed(label):
    return hashlib.sha256(label.encode()).digest()


def pkcs8(seed_bytes):
    # RFC 8410: a PKCS#8 Ed25519 private key is this prefix and the seed.
    der = bytes.fromhex("302e020100300506032b657004220420") + seed_bytes
    return b"-----BEGIN PRIVATE KEY-----\n" + __import__("base64").encodebytes(der) + \
        b"-----END PRIVATE KEY-----\n"


def run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True)
    return " ".join(cmd)


def main():
    version = subprocess.run(["openssl", "version"], capture_output=True, text=True,
                             check=True).stdout.strip()
    assert version.startswith("OpenSSL 3."), version
    ca_seed, leaf_seed = seed("IronCrypto x509 uri ca"), seed("IronCrypto x509 uri leaf")
    commands = []
    with tempfile.TemporaryDirectory() as d:
        for name, s in (("ca.pem", ca_seed), ("leaf.pem", leaf_seed)):
            with open(os.path.join(d, name), "wb") as f:
                f.write(pkcs8(s))
        with open(os.path.join(d, "x.cnf"), "w") as f:
            f.write(CONFIG)
        commands.append(run(["openssl", "req", "-x509", "-new", "-config", "x.cnf", "-key", "ca.pem",
                             "-subj", "/CN=" + CA_CN, "-set_serial", CA_SERIAL,
                             "-not_before", NOT_BEFORE, "-not_after", NOT_AFTER,
                             "-extensions", "ca", "-outform", "DER", "-out", "ca.der"], d))
        commands.append(run(["openssl", "req", "-new", "-config", "x.cnf", "-key", "leaf.pem",
                             "-subj", "/CN=" + DNS, "-reqexts", "request",
                             "-outform", "DER", "-out", "leaf.csr"], d))
        commands.append(run(["openssl", "req", "-verify", "-noout", "-inform", "DER",
                             "-in", "leaf.csr"], d))
        commands.append(run(["openssl", "x509", "-req", "-inform", "DER", "-in", "leaf.csr",
                             "-CA", "ca.der", "-CAform", "DER", "-CAkey", "ca.pem",
                             "-set_serial", LEAF_SERIAL, "-not_before", NOT_BEFORE,
                             "-not_after", NOT_AFTER, "-extfile", "x.cnf", "-extensions", "leaf",
                             "-outform", "DER", "-out", "leaf.der"], d))
        commands.append(run(["openssl", "x509", "-inform", "DER", "-in", "ca.der", "-out",
                             "ca.crt"], d))
        commands.append(run(["openssl", "x509", "-inform", "DER", "-in", "leaf.der", "-out",
                             "leaf.crt"], d))
        commands.append(run(["openssl", "verify", "-x509_strict", "-CAfile", "ca.crt",
                             "leaf.crt"], d))
        read = lambda n: open(os.path.join(d, n), "rb").read().hex()
        ca_der, leaf_der, csr_der = read("ca.der"), read("leaf.der"), read("leaf.csr")
        ski = lambda n: subprocess.run(
            ["openssl", "x509", "-in", n, "-noout", "-ext", "subjectKeyIdentifier"], cwd=d,
            capture_output=True, text=True, check=True).stdout.split("\n")[1].strip() \
            .replace(":", "").lower()
        ca_ski, leaf_ski = ski("ca.crt"), ski("leaf.crt")
    case = {
        "ca_seed": ca_seed.hex(), "leaf_seed": leaf_seed.hex(),
        "ca_serial": CA_SERIAL[2:], "leaf_serial": LEAF_SERIAL[2:],
        "not_before": "1767225600", "not_after": "2082758400",
        "ca_ski": ca_ski, "leaf_ski": leaf_ski,
        "dns": DNS.encode().hex(), "uri": URI.encode().hex(),
        "ca_der": ca_der, "leaf_der": leaf_der, "csr_der": csr_der,
    }
    json.dump({
        "algorithm": "X.509 issuance with a URI subject alternative name, and PKCS#10 requests",
        "source": version + ", run by scripts/gen_x509_uri_csr_vectors.py on 2026-10-12. Ed25519 "
                  "keys from the seeds given, which are SHA-256 of labels in that script. A CA, "
                  "then a request for the leaf key with CN " + DNS + " and subjectAltName "
                  "DNS:" + DNS + ",URI:" + URI + ", then the leaf issued from that request with "
                  "the profile's extensions, validity 2026-01-01 to 2036-01-01. The request "
                  "passes openssl req -verify and the chain openssl verify -x509_strict. "
                  "Commands, run in that order in a scratch directory: " + " ; ".join(commands)
                  + ". `dns` and `uri` are the names as hex.",
        "cases": [case],
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
