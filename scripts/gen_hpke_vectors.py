"""Generate testvectors/hpke-x25519.json: HPKE base mode with DHKEM(X25519,
HKDF-SHA256) and HKDF-SHA256, for AES-128-GCM, AES-256-GCM and
ChaCha20-Poly1305.

    python scripts/gen_hpke_vectors.py > testvectors/hpke-x25519.json

This is an implementation of RFC 9180 sections 4, 5.1, 5.2 and 5.3, written
from the specification text and sharing nothing with `ic-hpke`: X25519 and the
AEADs from pyca/cryptography, HKDF from Python's `hmac`. It refuses to run
unless it reproduces the RFC 9180 appendix A.1.1 values below -- the
encapsulation, base nonce, exporter secret and first ciphertext for
AES-128-GCM -- which were transcribed from the RFC for IronSocketLayer's tests.
Two independent paths agreeing on them is what makes either trustworthy: a
transcription error and an implementation error would have to coincide.

The other suites, sequence numbers and exports reuse appendix A.1.1's inputs
and are this implementation's outputs, not published values.
"""

import hashlib
import hmac
import json
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

KEM_ID, KDF_ID = 0x0020, 0x0001
AEADS = {0x0001: ("AES-128-GCM", 16), 0x0002: ("AES-256-GCM", 32), 0x0003: ("ChaCha20-Poly1305", 32)}
NN = 12
MODE_BASE = 0x00

# RFC 9180 appendix A.1.1's inputs.
INFO = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
SK_E = bytes.fromhex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
SK_R = bytes.fromhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
PT = bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479")
# The appendix's encryptions use these sequence numbers, each with aad "Count-<seq>".
SEQS = [0, 1, 2, 4, 255, 256]
EXPORTS = [(b"", 32), (b"\x00", 32), (b"TestContext", 32)]

# RFC 9180 A.1.1's outputs, as transcribed for IronSocketLayer.
A11 = {
    "enc": "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    "base_nonce": "56d890e5accaaf011cff4b7d",
    "exporter_secret": "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
    "ct0": "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
}


def i2osp(n, w):
    return n.to_bytes(w, "big")


def hkdf_extract(salt, ikm):
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def labeled_extract(suite, salt, label, ikm):
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    return hkdf_expand(prk, i2osp(length, 2) + b"HPKE-v1" + suite + label + info, length)


def raw_public(sk):
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def encap(sk_e, pk_r):
    kem_suite = b"KEM" + i2osp(KEM_ID, 2)
    dh = X25519PrivateKey.from_private_bytes(sk_e).exchange(X25519PublicKey.from_public_bytes(pk_r))
    assert dh != b"\x00" * 32
    enc = raw_public(sk_e)
    kem_context = enc + pk_r
    eae_prk = labeled_extract(kem_suite, b"", b"eae_prk", dh)
    return enc, labeled_expand(kem_suite, eae_prk, b"shared_secret", kem_context, 32)


def key_schedule(aead_id, shared_secret, info):
    suite = b"HPKE" + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(aead_id, 2)
    psk_id_hash = labeled_extract(suite, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(suite, b"", b"info_hash", info)
    ksc = bytes([MODE_BASE]) + psk_id_hash + info_hash
    secret = labeled_extract(suite, shared_secret, b"secret", b"")
    nk = AEADS[aead_id][1]
    return {
        "suite": suite,
        "key_schedule_context": ksc,
        "secret": secret,
        "key": labeled_expand(suite, secret, b"key", ksc, nk),
        "base_nonce": labeled_expand(suite, secret, b"base_nonce", ksc, NN),
        "exporter_secret": labeled_expand(suite, secret, b"exp", ksc, 32),
    }


def seal(aead_id, key, nonce, aad, pt):
    cipher = ChaCha20Poly1305(key) if aead_id == 0x0003 else AESGCM(key)
    return cipher.encrypt(nonce, pt, aad)


def main():
    pk_r = raw_public(SK_R)
    enc, shared_secret = encap(SK_E, pk_r)
    # One flat case per setup, encryption and export, every value a string:
    # ic_vectors reads string fields only.
    cases = []
    for aead_id, (name, _) in AEADS.items():
        ks = key_schedule(aead_id, shared_secret, INFO)
        common = {"aead_id": f"{aead_id:04x}", "aead": name}
        encryptions = []
        for seq in SEQS:
            nonce = bytes(a ^ b for a, b in zip(ks["base_nonce"], i2osp(seq, NN)))
            aad = f"Count-{seq}".encode()
            encryptions.append({**common, "kind": "encryption", "seq": str(seq), "aad": aad.hex(),
                                "pt": PT.hex(), "ct": seal(aead_id, ks["key"], nonce, aad, PT).hex()})
        exports = [{**common, "kind": "export", "exporter_context": ctx.hex(), "length": str(n),
                    "value": labeled_expand(ks["suite"], ks["exporter_secret"], b"sec", ctx, n).hex()}
                   for ctx, n in EXPORTS]
        if aead_id == 0x0001:
            got = {"enc": enc.hex(), "base_nonce": ks["base_nonce"].hex(),
                   "exporter_secret": ks["exporter_secret"].hex(), "ct0": encryptions[0]["ct"]}
            if got != A11:
                raise SystemExit(f"does not reproduce RFC 9180 A.1.1: {got}")
        cases.append({
            **common, "kind": "setup", "info": INFO.hex(),
            "sk_em": SK_E.hex(), "pk_em": enc.hex(), "sk_rm": SK_R.hex(), "pk_rm": pk_r.hex(),
            "enc": enc.hex(), "shared_secret": shared_secret.hex(),
            "key_schedule_context": ks["key_schedule_context"].hex(), "secret": ks["secret"].hex(),
            "key": ks["key"].hex(), "base_nonce": ks["base_nonce"].hex(),
            "exporter_secret": ks["exporter_secret"].hex(),
        })
        cases.extend(encryptions)
        cases.extend(exports)
    json.dump({
        "algorithm": "hpke base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256",
        "source": "scripts/gen_hpke_vectors.py, an RFC 9180 implementation written from the "
                  "specification on pyca/cryptography's X25519 and AEADs and Python's hmac. It "
                  "reproduces RFC 9180 appendix A.1.1's enc, base_nonce, exporter_secret and "
                  "first ciphertext before writing anything; every input is A.1.1's. The "
                  "AES-256-GCM and ChaCha20-Poly1305 suites, the later sequence numbers and the "
                  "exports are its outputs, not published values.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
