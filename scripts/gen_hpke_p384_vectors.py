"""Generate testvectors/hpke-p384.json: HPKE base mode with DHKEM(P-384,
HKDF-SHA384) and HKDF-SHA384, for AES-128-GCM, AES-256-GCM and
ChaCha20-Poly1305. KEM 0x0011, KDF 0x0002: with AES-256-GCM, the HPKE suite of
MLS's MLS_256_DHKEMP384_AES256GCM_SHA384_P384 (RFC 9420 suite 7).

    python scripts/gen_hpke_p384_vectors.py test-vectors.json > testvectors/hpke-p384.json

No published HPKE vector uses P-384: RFC 9180's appendix has P-256 and P-521
but not P-384, and so does the CFRG's full test-vectors.json. So this is an
implementation of RFC 9180 sections 4, 5.1, 5.3 and 7.1 for every NIST-curve
DHKEM, written from the specification and sharing nothing with `ic-hpke` --
ECDH from pyca/cryptography, HKDF from Python's `hmac` -- and it refuses to
write anything until two independent checks pass:

1. It reproduces every base-mode case in the CFRG test-vectors.json for
   DHKEM(P-256, HKDF-SHA256) and DHKEM(P-521, HKDF-SHA512): DeriveKeyPair
   from ikmE and ikmR, enc, shared_secret, key schedule, every encryption and
   every export. P-384 differs from those two only in its parameters --
   curve, Nsk, Npk, Nh -- and the code path is the same one.
2. pyca/cryptography's own HPKE (OpenSSL's), an implementation separate from
   this one, opens a single-shot P-384 message this script seals, and this
   script opens one pyca seals.

The file is the CFRG's test-vectors.json, passed as the first argument and
checked against this SHA-256: it was fetched on 2026-10-06 from
https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json.

The P-384 values written are this implementation's outputs, not published
values. The inputs -- ikmE, ikmR -- are SHA-384 of a fixed label, chosen here.
"""

import hashlib
import hmac
import json
import sys

from cryptography.hazmat.primitives import hpke, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

CFRG_SHA256 = "61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6"

HASHES = {0x0001: hashlib.sha256, 0x0002: hashlib.sha384, 0x0003: hashlib.sha512}
# kem_id: (curve, Nsecret, Nsk, bitmask, KDF hash)
KEMS = {
    0x0010: (ec.SECP256R1(), 32, 32, 0xFF, hashlib.sha256),
    0x0011: (ec.SECP384R1(), 48, 48, 0xFF, hashlib.sha384),
    0x0012: (ec.SECP521R1(), 64, 66, 0x01, hashlib.sha512),
}
ORDERS = {
    0x0010: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    0x0011: int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
                "581A0DB248B0A77AECEC196ACCC52973", 16),
    0x0012: int("01" + "F" * 64 + "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
}
AEADS = {0x0001: ("AES-128-GCM", 16), 0x0002: ("AES-256-GCM", 32), 0x0003: ("ChaCha20-Poly1305", 32)}
NN = 12
MODE_BASE = 0x00

# The P-384 inputs. info and the plaintext are RFC 9180 A.1.1's, so the
# files read alike.
KEM, KDF = 0x0011, 0x0002
IKM_E = hashlib.sha384(b"IronCrypto HPKE P-384 ikmE").digest()
IKM_R = hashlib.sha384(b"IronCrypto HPKE P-384 ikmR").digest()
INFO = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
PT = bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479")
SEQS = [0, 1, 2, 4, 255, 256]
EXPORTS = [(b"", 48), (b"\x00", 48), (b"TestContext", 48)]


def check_orders():
    """Each order is the group's: OpenSSL accepts n - 1 as a private key and
    refuses n. A mistyped order would otherwise go unnoticed, since a candidate
    at or above it is all but impossible to draw."""
    for kem_id, n in ORDERS.items():
        curve = KEMS[kem_id][0]
        ec.derive_private_key(n - 1, curve)
        try:
            ec.derive_private_key(n, curve)
        except ValueError:
            continue
        raise SystemExit(f"the order for kem {kem_id:#06x} is wrong")


def i2osp(n, w):
    return n.to_bytes(w, "big")


def hkdf_extract(h, salt, ikm):
    return hmac.new(salt or b"\x00" * h().digest_size, ikm, h).digest()


def hkdf_expand(h, prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        out += t
        i += 1
    return out[:length]


def labeled_extract(h, suite, salt, label, ikm):
    return hkdf_extract(h, salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(h, suite, prk, label, info, length):
    return hkdf_expand(h, prk, i2osp(length, 2) + b"HPKE-v1" + suite + label + info, length)


def derive_key_pair(kem_id, ikm):
    """RFC 9180 section 7.1.3, for the NIST curves."""
    curve, _, nsk, bitmask, h = KEMS[kem_id]
    suite = b"KEM" + i2osp(kem_id, 2)
    dkp_prk = labeled_extract(h, suite, b"", b"dkp_prk", ikm)
    sk, counter = 0, 0
    while sk == 0 or sk >= ORDERS[kem_id]:
        if counter > 255:
            raise ValueError("DeriveKeyPairError")
        candidate = bytearray(labeled_expand(h, suite, dkp_prk, b"candidate", bytes([counter]), nsk))
        candidate[0] &= bitmask
        sk = int.from_bytes(candidate, "big")
        counter += 1
    private = ec.derive_private_key(sk, curve)
    return i2osp(sk, nsk), private


def public_bytes(private):
    return private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def encap(kem_id, private_e, pk_r):
    curve, nsecret, _, _, h = KEMS[kem_id]
    suite = b"KEM" + i2osp(kem_id, 2)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(curve, pk_r)
    dh = private_e.exchange(ec.ECDH(), peer)
    enc = public_bytes(private_e)
    eae_prk = labeled_extract(h, suite, b"", b"eae_prk", dh)
    return enc, labeled_expand(h, suite, eae_prk, b"shared_secret", enc + pk_r, nsecret)


def decap(kem_id, private_r, enc):
    curve, nsecret, _, _, h = KEMS[kem_id]
    suite = b"KEM" + i2osp(kem_id, 2)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(curve, enc)
    dh = private_r.exchange(ec.ECDH(), peer)
    eae_prk = labeled_extract(h, suite, b"", b"eae_prk", dh)
    return labeled_expand(h, suite, eae_prk, b"shared_secret", enc + public_bytes(private_r), nsecret)


def key_schedule(kem_id, kdf_id, aead_id, shared_secret, info):
    h = HASHES[kdf_id]
    nh = h().digest_size
    suite = b"HPKE" + i2osp(kem_id, 2) + i2osp(kdf_id, 2) + i2osp(aead_id, 2)
    psk_id_hash = labeled_extract(h, suite, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(h, suite, b"", b"info_hash", info)
    ksc = bytes([MODE_BASE]) + psk_id_hash + info_hash
    secret = labeled_extract(h, suite, shared_secret, b"secret", b"")
    return {
        "h": h, "suite": suite, "key_schedule_context": ksc, "secret": secret,
        "key": labeled_expand(h, suite, secret, b"key", ksc, AEADS[aead_id][1]),
        "base_nonce": labeled_expand(h, suite, secret, b"base_nonce", ksc, NN),
        "exporter_secret": labeled_expand(h, suite, secret, b"exp", ksc, nh),
    }


def nonce_at(base, seq):
    return bytes(a ^ b for a, b in zip(base, i2osp(seq, NN)))


def cipher(aead_id, key):
    return ChaCha20Poly1305(key) if aead_id == 0x0003 else AESGCM(key)


def check_against_cfrg(path):
    data = open(path, "rb").read()
    if hashlib.sha256(data).hexdigest() != CFRG_SHA256:
        raise SystemExit(f"{path} is not the pinned CFRG test-vectors.json")
    checked = 0
    for t in json.loads(data):
        if t["mode"] != MODE_BASE or t["kem_id"] not in (0x0010, 0x0012) or t["aead_id"] not in AEADS:
            continue
        kem = t["kem_id"]
        sk_e, priv_e = derive_key_pair(kem, bytes.fromhex(t["ikmE"]))
        sk_r, priv_r = derive_key_pair(kem, bytes.fromhex(t["ikmR"]))
        pk_r = public_bytes(priv_r)
        enc, ss = encap(kem, priv_e, pk_r)
        ks = key_schedule(kem, t["kdf_id"], t["aead_id"], ss, bytes.fromhex(t["info"]))
        got = {"skEm": sk_e, "skRm": sk_r, "pkEm": public_bytes(priv_e), "pkRm": pk_r, "enc": enc,
               "shared_secret": ss, "key": ks["key"], "base_nonce": ks["base_nonce"],
               "exporter_secret": ks["exporter_secret"],
               "key_schedule_context": ks["key_schedule_context"], "secret": ks["secret"]}
        for k, v in got.items():
            if v.hex() != t[k]:
                raise SystemExit(f"CFRG kem {kem:#06x} kdf {t['kdf_id']} aead {t['aead_id']}: {k} differs")
        if decap(kem, priv_r, enc) != ss:
            raise SystemExit("decap disagrees with encap")
        for e in t["encryptions"]:
            ct = cipher(t["aead_id"], ks["key"]).encrypt(
                bytes.fromhex(e["nonce"]), bytes.fromhex(e["pt"]), bytes.fromhex(e["aad"]))
            if ct.hex() != e["ct"]:
                raise SystemExit("CFRG encryption differs")
        for x in t["exports"]:
            v = labeled_expand(ks["h"], ks["suite"], ks["exporter_secret"], b"sec",
                               bytes.fromhex(x["exporter_context"]), x["L"])
            if v.hex() != x["exported_value"]:
                raise SystemExit("CFRG export differs")
        checked += 1
    if checked < 6:
        raise SystemExit(f"only {checked} CFRG cases checked")
    return checked


def check_against_pyca():
    """pyca's HPKE opens what this seals, and this opens what pyca seals."""
    suite = hpke.Suite(hpke.KEM.P384, hpke.KDF.HKDF_SHA384, hpke.AEAD.AES_256_GCM)
    _, recipient = derive_key_pair(KEM, IKM_R)
    _, ephemeral = derive_key_pair(KEM, IKM_E)
    enc, ss = encap(KEM, ephemeral, public_bytes(recipient))
    ks = key_schedule(KEM, KDF, 0x0002, ss, INFO)
    ct = AESGCM(ks["key"]).encrypt(ks["base_nonce"], PT, b"")
    if suite.decrypt(enc + ct, recipient, INFO) != PT:
        raise SystemExit("pyca did not open this implementation's P-384 message")
    theirs = suite.encrypt(PT, recipient.public_key(), INFO)
    enc2, ct2 = theirs[:97], theirs[97:]
    ks2 = key_schedule(KEM, KDF, 0x0002, decap(KEM, recipient, enc2), INFO)
    if AESGCM(ks2["key"]).decrypt(ks2["base_nonce"], ct2, b"") != PT:
        raise SystemExit("this implementation did not open pyca's P-384 message")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    check_orders()
    checked = check_against_cfrg(sys.argv[1])
    check_against_pyca()

    sk_e, priv_e = derive_key_pair(KEM, IKM_E)
    sk_r, priv_r = derive_key_pair(KEM, IKM_R)
    pk_e, pk_r = public_bytes(priv_e), public_bytes(priv_r)
    enc, shared_secret = encap(KEM, priv_e, pk_r)
    cases = []
    for aead_id, (name, _) in AEADS.items():
        ks = key_schedule(KEM, KDF, aead_id, shared_secret, INFO)
        common = {"aead_id": f"{aead_id:04x}", "aead": name}
        cases.append({
            **common, "kind": "setup", "info": INFO.hex(),
            "ikm_e": IKM_E.hex(), "ikm_r": IKM_R.hex(),
            "sk_em": sk_e.hex(), "pk_em": pk_e.hex(), "sk_rm": sk_r.hex(), "pk_rm": pk_r.hex(),
            "enc": enc.hex(), "shared_secret": shared_secret.hex(),
            "key_schedule_context": ks["key_schedule_context"].hex(), "secret": ks["secret"].hex(),
            "key": ks["key"].hex(), "base_nonce": ks["base_nonce"].hex(),
            "exporter_secret": ks["exporter_secret"].hex(),
        })
        for seq in SEQS:
            aad = f"Count-{seq}".encode()
            ct = cipher(aead_id, ks["key"]).encrypt(nonce_at(ks["base_nonce"], seq), PT, aad)
            cases.append({**common, "kind": "encryption", "seq": str(seq), "aad": aad.hex(),
                          "pt": PT.hex(), "ct": ct.hex()})
        for ctx, n in EXPORTS:
            cases.append({**common, "kind": "export", "exporter_context": ctx.hex(), "length": str(n),
                          "value": labeled_expand(ks["h"], ks["suite"], ks["exporter_secret"],
                                                  b"sec", ctx, n).hex()})
    json.dump({
        "algorithm": "hpke base mode, DHKEM(P-384, HKDF-SHA384), HKDF-SHA384",
        "source": "scripts/gen_hpke_p384_vectors.py, an RFC 9180 implementation of every "
                  "NIST-curve DHKEM written from the specification on pyca/cryptography's ECDH "
                  "and AEADs and Python's hmac. Before writing, it reproduced all "
                  f"{checked} base-mode P-256 and P-521 cases of the CFRG test-vectors.json "
                  "(SHA-256 " + CFRG_SHA256 + "), and exchanged a P-384 message each way with "
                  "pyca/cryptography's own HPKE. No published vector uses P-384: these values "
                  "are this implementation's outputs, from inputs chosen here.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
