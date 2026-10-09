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

Four files are written, for what NIST's sample vectors do not reach here:

- wycheproof-rsa.json: RSASSA-PSS verification with MGF1 over the same hash
  and a salt as long as the hash, which is the only PSS this library has --
  all six such files -- and PKCS#1 v1.5 verification: SHA-256, SHA-384 and
  SHA-512 at 2048 bits, and SHA-256 at 3072 and 4096. The other four PKCS#1
  v1.5 files, SHA-384 and SHA-512 at the two larger sizes, repeat the same
  malformations and are left out for size. A `key` case gives a modulus and
  exponent once; the `verify` cases after it name it.
- wycheproof-ecdh.json: ECDH over P-256, P-384 and P-521 with the peer's key
  as an encoded point, every case.
- wycheproof-kmac.json: KMAC128 and KMAC256 with no customization string,
  every case.
- wycheproof-pbkdf2.json: PBKDF2 with HMAC-SHA-256 and HMAC-SHA-512, every
  case.

Nothing here computes a cryptographic value.
"""

import hashlib
import json
import os
import sys

COMMIT = "12fd3aaf33eb"
PINNED = {
    "ecdh_secp256r1_ecpoint_test.json": "648f16d077caf2400d02331ca51f44744c72c799",
    "ecdh_secp384r1_ecpoint_test.json": "ffa7835fe1de359dff762c8f1272b98acebd5578",
    "ecdh_secp521r1_ecpoint_test.json": "87aba8739c96de2bde8c75b60ffea09d0493192c",
    "kmac128_no_customization_test.json": "9482c88537dd71fe94048bffc479ce37398bc532",
    "kmac256_no_customization_test.json": "950b9e8f64bd4e614aa3d825f0cd0570ec33c6cd",
    "pbkdf2_hmacsha256_test.json": "1bf37af2cefe40c829ee9ecebb3505bb6424be88",
    "pbkdf2_hmacsha512_test.json": "6a764a448b7a283478340d58f5dc20455524e858",
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


def main():
    directory, out = sys.argv[1], sys.argv[2]
    rsa(directory, out)
    ecdh(directory, out)
    kmac(directory, out)
    pbkdf2(directory, out)


if __name__ == "__main__":
    main()
