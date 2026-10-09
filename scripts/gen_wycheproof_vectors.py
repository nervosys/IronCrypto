"""Convert Project Wycheproof's test vectors into this repository's format.

    python scripts/gen_wycheproof_vectors.py <dir> testvectors

<dir> holds the files named below, as downloaded from
https://github.com/C2SP/wycheproof at commit 12fd3aaf33eb
(testvectors_v1/<name>_test.json). Each is checked against the SHA-256 below.

Wycheproof is not a standard. It is a collection of cases built to catch
implementation mistakes -- forged padding, points off the curve, edge cases of
the arithmetic -- each marked `valid`, `invalid` or `acceptable`, the last for
inputs a correct implementation may take either way. Those verdicts are kept
as they are.

Five files are written, for what NIST's sample vectors do not reach here:

- wycheproof-rsa.json: RSASSA-PSS verification with MGF1 over the same hash
  and a salt as long as the hash, which is the only PSS this library has --
  all six such files -- and PKCS#1 v1.5 verification: SHA-256, SHA-384 and
  SHA-512 at 2048 bits, and SHA-256 at 3072 and 4096. The other four PKCS#1
  v1.5 files, SHA-384 and SHA-512 at the two larger sizes, repeat the same
  malformations and are left out for size. A `key` case gives a modulus and
  exponent once; the `verify` cases after it name it.
- wycheproof-rsa-sign.json: PKCS#1 v1.5 signing with SHA-256, SHA-384 and
  SHA-512 at 2048, 3072 and 4096 bits: a private key as modulus and
  exponents, a message, and the one signature it has, since PKCS#1 v1.5 is
  deterministic. The SHA-1 and SHA-224 groups are left out; this library
  has neither as a signature hash. Wycheproof gives no primes, so these
  reach the signer without the CRT and not with it.
- wycheproof-ecdh.json: ECDH over P-256, P-384 and P-521 with the peer's key
  as an encoded point, every case.
- wycheproof-kmac.json: KMAC128 and KMAC256 with no customization string,
  every case.
- wycheproof-pbkdf2.json: PBKDF2 with HMAC-SHA-256 and HMAC-SHA-512, every
  case.

Seven more are written for inputs an attacker chooses, where what matters is
less the right answer than the refusal of a wrong one:

- wycheproof-ecdsa.json: ECDSA verification over P-256, P-384 and P-521
  under each curve's own hash, with the key as a SubjectPublicKeyInfo and
  the signature in DER, as a certificate carries them. Most of the invalid
  cases are encodings: a length written the long way, a leading zero too
  many, bytes after the end.
- wycheproof-eddsa.json: Ed25519 verification.
- wycheproof-x25519.json: X25519, where half the cases are public keys a
  careful implementation may refuse -- points of low order, on the twist,
  or not reduced -- and are marked acceptable.
- wycheproof-aead.json: AES-GCM, ChaCha20-Poly1305 and AES-GCM-SIV.
- wycheproof-mac.json: HMAC with SHA-256, SHA-384 and SHA-512, and AES-CMAC.
- wycheproof-hkdf.json: HKDF with SHA-256, SHA-384 and SHA-512.
- wycheproof-keywrap.json: AES Key Wrap, with and without padding.

Nothing here computes a cryptographic value.
"""

import hashlib
import json
import os
import sys

COMMIT = "12fd3aaf33eb"
PINNED = {
    "aes_cmac_test.json": "c1b441008b5355d8070c50e2533f9c1230759015",
    "aes_gcm_siv_test.json": "d96e4f8c0db1a5e3b395907120f9d417d599507e",
    "aes_gcm_test.json": "985e5ecc172e181eaf49e89508b9470dcf478002",
    "aes_kwp_test.json": "e89624734deeba8bb937acba5381a5cb137c7050",
    "aes_wrap_test.json": "2fdb3661fd8823d1ec50e03886b2406641501897",
    "chacha20_poly1305_test.json": "fe61d25f90e1bde4461d00eafe61049e5f29bd99",
    "ecdh_secp256r1_ecpoint_test.json": "648f16d077caf2400d02331ca51f44744c72c799",
    "ecdh_secp384r1_ecpoint_test.json": "ffa7835fe1de359dff762c8f1272b98acebd5578",
    "ecdh_secp521r1_ecpoint_test.json": "87aba8739c96de2bde8c75b60ffea09d0493192c",
    "ecdsa_secp256r1_sha256_test.json": "182db4f3e230f6f9fa9f800d2a614dede30284b8",
    "ecdsa_secp384r1_sha384_test.json": "8a5b3ae1760975143414811f13588c24d951d9d8",
    "ecdsa_secp521r1_sha512_test.json": "0fa3bb09a2319242253028b53d555fb8ec2081d8",
    "ed25519_test.json": "752d2ea7d7c6cf4736381b6cbacb61f8182b126a",
    "hkdf_sha256_test.json": "bb2b462a38b251cb52a2aede706d6d4b62b26864",
    "hkdf_sha384_test.json": "69ff6ea3657bb9c1b8cdffbbb4e7832353d08fd1",
    "hkdf_sha512_test.json": "bb9a21f4e86041caf5d7792b030349f8ff289087",
    "hmac_sha256_test.json": "2d201cfa61d1bf95e6f5d07d96634b4a348b31e8",
    "hmac_sha384_test.json": "28b9776e979dd755d852ca471043ea6cedce8b15",
    "hmac_sha512_test.json": "b6c90477bdb4a6fc8ee3d1f7b2c0b69a8dfffab3",
    "kmac128_no_customization_test.json": "9482c88537dd71fe94048bffc479ce37398bc532",
    "kmac256_no_customization_test.json": "950b9e8f64bd4e614aa3d825f0cd0570ec33c6cd",
    "pbkdf2_hmacsha256_test.json": "1bf37af2cefe40c829ee9ecebb3505bb6424be88",
    "pbkdf2_hmacsha512_test.json": "6a764a448b7a283478340d58f5dc20455524e858",
    "rsa_pkcs1_2048_sig_gen_test.json": "587b3d27d3429f2118cb02818da4d08eb3f36f50",
    "rsa_pkcs1_3072_sig_gen_test.json": "45153219d486fd135d35aa968a957a0c015c7829",
    "rsa_pkcs1_4096_sig_gen_test.json": "f13eadbec6c45291cb33e6b2fa0a0c2b862d0bd2",
    "rsa_pss_2048_sha256_mgf1_32_test.json": "7f6efafc160f4816b96cbf1c12188a31051d7e3f",
    "rsa_pss_2048_sha384_mgf1_48_test.json": "66d464778b0b2f683a1d1a20e94f77e9472b8cc3",
    "rsa_pss_3072_sha256_mgf1_32_test.json": "cca48433e6d1accb57f65b3396c4f4dd93c77646",
    "rsa_pss_4096_sha256_mgf1_32_test.json": "e627cbf5139a01e0a446c4fe15911f6268224fdd",
    "rsa_pss_4096_sha384_mgf1_48_test.json": "d632649a7630f7c267eda576714ca11cf0ff068d",
    "rsa_pss_4096_sha512_mgf1_64_test.json": "c93ceaa56a190c9fd4707441c5c6a75839f10820",
    "rsa_signature_2048_sha256_test.json": "94a917b01ff50fb874cfc05bf29b4af44868d944",
    "rsa_signature_2048_sha384_test.json": "c571c105d261c0ff588a2888a529f152563fb3b7",
    "rsa_signature_2048_sha512_test.json": "16ea24b039905d054bdb6004f5fd179374e150b7",
    "rsa_signature_3072_sha256_test.json": "0f5f18cabfaad3e2792e82f7e9882f8999049b45",
    "rsa_signature_4096_sha256_test.json": "957aca128e30bd02c8982f8ca482d6521d16683f",
    "x25519_test.json": "35c3f5231cf25cc640b524d403461deee9e49441",
}

SOURCE = ("Project Wycheproof, https://github.com/C2SP/wycheproof commit " + COMMIT
          + ", testvectors_v1/{names}, converted by scripts/gen_wycheproof_vectors.py. "
          "`result` is Wycheproof's: valid, invalid, or acceptable for an input a correct "
          "implementation may take either way. ")

PSS = ["rsa_pss_2048_sha256_mgf1_32", "rsa_pss_3072_sha256_mgf1_32",
       "rsa_pss_4096_sha256_mgf1_32", "rsa_pss_2048_sha384_mgf1_48",
       "rsa_pss_4096_sha384_mgf1_48", "rsa_pss_4096_sha512_mgf1_64"]
PKCS1 = ["rsa_signature_2048_sha256", "rsa_signature_2048_sha384", "rsa_signature_2048_sha512",
         "rsa_signature_3072_sha256", "rsa_signature_4096_sha256"]
ECDH = ["ecdh_secp256r1_ecpoint", "ecdh_secp384r1_ecpoint", "ecdh_secp521r1_ecpoint"]
KMAC = ["kmac128_no_customization", "kmac256_no_customization"]
PBKDF2 = ["pbkdf2_hmacsha256", "pbkdf2_hmacsha512"]
ECDSA = ["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512"]
AEAD = ["aes_gcm", "chacha20_poly1305", "aes_gcm_siv"]
MAC = ["hmac_sha256", "hmac_sha384", "hmac_sha512", "aes_cmac"]
HKDF = ["hkdf_sha256", "hkdf_sha384", "hkdf_sha512"]
KEYWRAP = ["aes_wrap", "aes_kwp"]
SIGN = ["rsa_pkcs1_2048_sig_gen", "rsa_pkcs1_3072_sig_gen", "rsa_pkcs1_4096_sig_gen"]


def load(directory, name):
    file = name + "_test.json"
    with open(os.path.join(directory, file), "rb") as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    if "--print-digests" in sys.argv:
        print(f'    "{file}": "{digest[:40]}",', file=sys.stderr)
    elif not digest.startswith(PINNED[file]):
        raise SystemExit(f"{file}: SHA-256 {digest} is not the pinned file")
    doc = json.loads(raw)
    assert doc["numberOfTests"] == sum(len(g["tests"]) for g in doc["testGroups"])
    return doc


def write(out, name, algorithm, source, cases):
    path = os.path.join(out, name + ".json")
    with open(path, "w", newline="\n") as f:
        json.dump({"algorithm": algorithm, "source": source, "cases": cases}, f, indent=1)
        f.write("\n")
    print(f"{path}: {len(cases)} cases, {os.path.getsize(path)} bytes")


def common(test):
    return {"comment": test["comment"], "flags": ",".join(test["flags"]),
            "result": test["result"]}


def rsa(directory, out):
    cases, keys = [], 0
    for scheme, names in (("pss", PSS), ("pkcs1", PKCS1)):
        for name in names:
            doc = load(directory, name)
            for group in doc["testGroups"]:
                sha = group["sha"].lower().replace("-", "")
                if scheme == "pss":
                    assert group["mgf"] == "MGF1" and group["mgfSha"] == group["sha"]
                    assert group["sLen"] * 8 == int(sha[3:]), (name, group["sLen"])
                keys += 1
                key = f"k{keys}"
                cases.append({"kind": "key", "key": key, "scheme": "", "hash": "",
                              "n": group["publicKey"]["modulus"],
                              "e": group["publicKey"]["publicExponent"],
                              "message": "", "signature": "", "comment": "", "flags": "",
                              "result": ""})
                for test in group["tests"]:
                    cases.append({"kind": "verify", "key": key, "scheme": scheme, "hash": sha,
                                  "n": "", "e": "", "message": test["msg"],
                                  "signature": test["sig"], **common(test)})
    write(out, "wycheproof-rsa", "RSASSA-PSS and RSASSA-PKCS1-v1_5 verification",
          SOURCE.format(names="rsa_pss_*_mgf1_* and rsa_signature_*")
          + "PSS with MGF1 over the same hash and a salt as long as the hash, six files; "
          "PKCS#1 v1.5 with SHA-256, SHA-384 and SHA-512 at 2048 bits and SHA-256 at 3072 and "
          "4096. A `key` case gives a modulus and exponent, as big-endian hex that may have "
          "a leading zero byte; the `verify` cases that follow name it.", cases)


def rsa_sign(directory, out):
    cases, keys = [], 0
    for name in SIGN:
        doc = load(directory, name)
        for group in doc["testGroups"]:
            sha = group["sha"].lower().replace("-", "")
            if sha not in ("sha256", "sha384", "sha512"):
                continue
            keys += 1
            key = f"k{keys}"
            private = group["privateKey"]
            cases.append({"kind": "key", "key": key, "hash": "", "n": private["modulus"],
                          "e": private["publicExponent"], "d": private["privateExponent"],
                          "message": "", "signature": "", "comment": "", "flags": "",
                          "result": ""})
            for test in group["tests"]:
                cases.append({"kind": "sign", "key": key, "hash": sha, "n": "", "e": "", "d": "",
                              "message": test["msg"], "signature": test["sig"], **common(test)})
    write(out, "wycheproof-rsa-sign", "RSASSA-PKCS1-v1_5 signing",
          SOURCE.format(names="rsa_pkcs1_*_sig_gen_test.json")
          + "SHA-256, SHA-384 and SHA-512 at 2048, 3072 and 4096 bits. A `key` case gives the "
          "modulus and both exponents; the `sign` cases that follow name it and give the "
          "signature PKCS#1 v1.5 must produce.", cases)


def ecdh(directory, out):
    cases = []
    for name in ECDH:
        doc = load(directory, name)
        for group in doc["testGroups"]:
            assert group["encoding"] == "ecpoint"
            curve = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}[
                group["curve"]]
            for test in group["tests"]:
                cases.append({"curve": curve, "public": test["public"],
                              "private": test["private"], "shared": test["shared"],
                              **common(test)})
    write(out, "wycheproof-ecdh", "ECDH over P-256, P-384 and P-521",
          SOURCE.format(names="ecdh_secp*r1_ecpoint_test.json")
          + "The peer's key is an encoded point; the private key is big-endian hex that may "
          "have a leading zero byte or be short.", cases)


def kmac(directory, out):
    cases = []
    for name in KMAC:
        doc = load(directory, name)
        for group in doc["testGroups"]:
            assert group["tagSize"] % 8 == 0
            for test in group["tests"]:
                assert len(test["tag"]) * 4 == group["tagSize"]
                cases.append({"function": name.split("_")[0], "key": test["key"],
                              "message": test["msg"], "tag": test["tag"], **common(test)})
    write(out, "wycheproof-kmac", "KMAC128 and KMAC256 with no customization string",
          SOURCE.format(names="kmac128_no_customization_test.json and "
                        "kmac256_no_customization_test.json"), cases)


def pbkdf2(directory, out):
    cases = []
    for name in PBKDF2:
        doc = load(directory, name)
        for group in doc["testGroups"]:
            for test in group["tests"]:
                assert len(test["dk"]) == 2 * test["dkLen"]
                cases.append({"prf": "hmac-" + name.split("hmac")[1].replace("sha", "sha2-"),
                              "password": test["password"], "salt": test["salt"],
                              "iterations": str(test["iterationCount"]), "derived": test["dk"],
                              **common(test)})
    write(out, "wycheproof-pbkdf2", "PBKDF2 with HMAC-SHA-256 and HMAC-SHA-512",
          SOURCE.format(names="pbkdf2_hmacsha256_test.json and pbkdf2_hmacsha512_test.json"),
          cases)


def ecdsa(directory, out):
    cases = []
    for name in ECDSA:
        doc = load(directory, name)
        curve = {"256": "p256", "384": "p384", "521": "p521"}[name.split("secp")[1][:3]]
        sha = name.rsplit("_", 1)[1]
        for group in doc["testGroups"]:
            assert group["sha"].lower().replace("-", "") == sha
            for test in group["tests"]:
                cases.append({"algorithm": f"ecdsa-{curve}-{sha}", "spki": group["publicKeyDer"],
                              "message": test["msg"], "signature": test["sig"], **common(test)})
    write(out, "wycheproof-ecdsa", "ECDSA verification over SubjectPublicKeyInfo, DER signatures",
          SOURCE.format(names="ecdsa_secp256r1_sha256_test.json, ecdsa_secp384r1_sha384_test.json "
                        "and ecdsa_secp521r1_sha512_test.json"), cases)


def eddsa(directory, out):
    cases = []
    doc = load(directory, "ed25519")
    for group in doc["testGroups"]:
        for test in group["tests"]:
            cases.append({"public_key": group["publicKey"]["pk"], "message": test["msg"],
                          "signature": test["sig"], **common(test)})
    write(out, "wycheproof-eddsa", "Ed25519 verification",
          SOURCE.format(names="ed25519_test.json"), cases)


def x25519(directory, out):
    cases = []
    doc = load(directory, "x25519")
    for group in doc["testGroups"]:
        assert group["curve"] == "curve25519"
        for test in group["tests"]:
            cases.append({"public": test["public"], "private": test["private"],
                          "shared": test["shared"], **common(test)})
    write(out, "wycheproof-x25519", "X25519", SOURCE.format(names="x25519_test.json"), cases)


def aead(directory, out):
    cases = []
    for name in AEAD:
        doc = load(directory, name)
        for group in doc["testGroups"]:
            for test in group["tests"]:
                cases.append({"cipher": name.replace("_", "-"), "key": test["key"],
                              "nonce": test["iv"], "aad": test["aad"], "plaintext": test["msg"],
                              "ciphertext": test["ct"], "tag": test["tag"], **common(test)})
    write(out, "wycheproof-aead", "AES-GCM, ChaCha20-Poly1305 and AES-GCM-SIV",
          SOURCE.format(names="aes_gcm_test.json, chacha20_poly1305_test.json and "
                        "aes_gcm_siv_test.json"), cases)


def mac(directory, out):
    cases = []
    for name in MAC:
        doc = load(directory, name)
        for group in doc["testGroups"]:
            for test in group["tests"]:
                cases.append({"mac": name.replace("_", "-").replace("sha", "sha2-"),
                              "key": test["key"], "message": test["msg"], "tag": test["tag"],
                              **common(test)})
    write(out, "wycheproof-mac", "HMAC with SHA-256, SHA-384 and SHA-512, and AES-CMAC",
          SOURCE.format(names="hmac_sha256_test.json, hmac_sha384_test.json, "
                        "hmac_sha512_test.json and aes_cmac_test.json")
          + "A tag may be a truncation of the full one.", cases)


def hkdf(directory, out):
    cases = []
    for name in HKDF:
        doc = load(directory, name)
        for group in doc["testGroups"]:
            for test in group["tests"]:
                cases.append({"hash": name.split("_")[1].replace("sha", "sha2-"),
                              "ikm": test["ikm"], "salt": test["salt"], "info": test["info"],
                              "size": str(test["size"]), "okm": test["okm"], **common(test)})
    write(out, "wycheproof-hkdf", "HKDF with SHA-256, SHA-384 and SHA-512",
          SOURCE.format(names="hkdf_sha256_test.json, hkdf_sha384_test.json and "
                        "hkdf_sha512_test.json"), cases)


def keywrap(directory, out):
    cases = []
    for name in KEYWRAP:
        doc = load(directory, name)
        for group in doc["testGroups"]:
            for test in group["tests"]:
                cases.append({"mode": "kw" if name == "aes_wrap" else "kwp", "key": test["key"],
                              "plaintext": test["msg"], "ciphertext": test["ct"],
                              **common(test)})
    write(out, "wycheproof-keywrap", "AES Key Wrap, with and without padding",
          SOURCE.format(names="aes_wrap_test.json and aes_kwp_test.json"), cases)


def main():
    directory, out = sys.argv[1], sys.argv[2]
    rsa(directory, out)
    rsa_sign(directory, out)
    ecdh(directory, out)
    kmac(directory, out)
    pbkdf2(directory, out)
    ecdsa(directory, out)
    eddsa(directory, out)
    x25519(directory, out)
    aead(directory, out)
    mac(directory, out)
    hkdf(directory, out)
    keywrap(directory, out)


if __name__ == "__main__":
    main()
