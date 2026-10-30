"""Check the PBES2 self-test's expected encoding, `SELF_TEST_ANSWER` in
crates/ic-pkix/src/pbes2.rs, against a second implementation.

    python scripts/check_pbes2_self_test.py

Computes the encrypted key from the self-test's inputs with pyca
`cryptography` (PBKDF2HMAC over SHA-256, AES-256-CBC, PKCS7 padding), wraps
it in DER written here from RFC 8018 rather than by the Rust writer, compares
the result with the constant, and asks OpenSSL to decrypt it: OpenSSL must
give back the plaintext, RFC 8410 §10.3's example Ed25519 key. Exits non-zero
on any difference.
"""

import os
import re
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SOURCE = os.path.join(ROOT, "crates", "ic-pkix", "src", "pbes2.rs")

PASSPHRASE = b"IronCrypto pbes2 self-test"
# RFC 8410 §10.3: MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
PLAINTEXT = bytes.fromhex(
    "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad"
    "3afe7c28cbf1d4fbe097a88f44755842")
SALT = bytes(range(0x00, 0x10))
IV = bytes(range(0xf0, 0x100))
ITERATIONS = 1000


def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        header = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        header = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + header + content


def seq(*parts):
    return tlv(0x30, b"".join(parts))


def oid(hex_content):
    return tlv(0x06, bytes.fromhex(hex_content))


def integer(value):
    return tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def expected():
    key = PBKDF2HMAC(hashes.SHA256(), 32, SALT, ITERATIONS).derive(PASSPHRASE)
    padder = padding.PKCS7(128).padder()
    data = padder.update(PLAINTEXT) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(IV)).encryptor()
    ct = enc.update(data) + enc.finalize()
    prf = seq(oid("2a864886f70d0209"), tlv(0x05, b""))           # hmacWithSHA256
    kdf = seq(oid("2a864886f70d01050c"),                          # PBKDF2
              seq(tlv(0x04, SALT), integer(ITERATIONS), prf))
    scheme = seq(oid("60864801650304012a"), tlv(0x04, IV))        # aes256-CBC
    alg = seq(oid("2a864886f70d01050d"), seq(kdf, scheme))        # PBES2
    return seq(alg, tlv(0x04, ct))


def constant():
    text = open(SOURCE, encoding="utf-8").read()
    m = re.search(r'const SELF_TEST_ANSWER: &\[u8\] = b"(.*?)";', text, re.S)
    return bytes.fromhex(re.sub(r"[\\\s]", "", m.group(1)))


def main():
    want = expected()
    if constant() != want:
        sys.exit("SELF_TEST_ANSWER differs from the pyca computation:\n" + want.hex())
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cast.der")
        with open(path, "wb") as f:
            f.write(want)
        out = subprocess.run(
            ["openssl", "pkcs8", "-topk8", "-nocrypt", "-inform", "DER", "-in", path,
             "-passin", "pass:" + PASSPHRASE.decode(), "-outform", "DER"],
            capture_output=True, check=True).stdout
    if out != PLAINTEXT:
        sys.exit("OpenSSL did not decrypt the self-test encoding to the RFC 8410 key")
    print(f"ok: {len(want)} bytes; pyca agrees and OpenSSL decrypts to the RFC 8410 key")


if __name__ == "__main__":
    main()
