"""Convert NIST's ACVP ECDSA, RSA and cSHAKE files into this repository's
vector format.

    python scripts/gen_acvp_sig_vectors.py <acvp-dir> testvectors

<acvp-dir> holds `<name>-prompt.json`, `<name>-expectedResults.json` and, where
listed below, `<name>-internalProjection.json`, as downloaded from
https://github.com/usnistgov/ACVP-Server at commit 975de31eb83d
(gen-val/json-files/<name>/). Each is checked against the SHA-256 below.

Three files are written.

- acvp-ecdsa.json, from DetECDSA-SigGen-FIPS186-5 and ECDSA-SigVer-FIPS186-5.
  Kept: P-256, P-384 and P-521 with every hash this library has whose digest
  is at least as wide as the curve needs (32, 48 and 64 bytes). Signing
  cases carry the private key, which NIST publishes only in the internal
  projection, and the signature deterministic ECDSA must produce. Dropped:
  P-224 and the binary curves, which are not implemented; SHA-224 and
  SHA-512/224, too narrow for any curve here; the SHAKE groups; for P-384
  and P-521, the hashes narrower than the curve; and every group marked
  `conformance: SP800-106`, half the signing file, whose messages are
  randomized before they are signed. Those do not match plain deterministic
  ECDSA and are not meant to: converting them by mistake is how this script
  first came to report a wrong signer that was not wrong.
- acvp-rsa-sigver.json, from RSA-SigVer-FIPS186-5: the PKCS#1 v1.5 groups,
  which are all SHA-256, at 2048, 3072 and 4096 bits. Dropped: every PSS
  group, because NIST's sample uses SHA-3 and SHAKE there and this library's
  PSS is SHA-2 with MGF1. So this file says nothing about PSS.
- acvp-cshake.json, from cSHAKE-128-1.0 and cSHAKE-256-1.0: the cases whose
  message and output are whole bytes, which is five of two hundred. The rest
  are bit-oriented, and this library hashes bytes.

Nothing here computes a cryptographic value.
"""

import hashlib
import json
import os
import sys

PINNED = {
    "DetECDSA-SigGen-FIPS186-5-expectedResults.json": "db31128abec109cc5cac1dd6dc6a79d5d9d3530a",
    "DetECDSA-SigGen-FIPS186-5-internalProjection.json": "161813f3e67428d2ec656ef63a179efa95cf649d",
    "ECDSA-SigVer-FIPS186-5-expectedResults.json": "c4f2e21e9c6391a5349a81237b5c508466ce05f0",
    "ECDSA-SigVer-FIPS186-5-internalProjection.json": "45f9e9425e68b099d9c029e0e75ec04e9cc5943b",
    "RSA-SigVer-FIPS186-5-expectedResults.json": "42e0afc503304e8a7653328aa917baa77e16e89f",
    "RSA-SigVer-FIPS186-5-internalProjection.json": "86088be5f46b3b10794357495c6d914af4a4c03b",
    "cSHAKE-128-1.0-expectedResults.json": "be71953163ecfae0519ac84bc1851b4f474dd1cf",
    "cSHAKE-128-1.0-prompt.json": "602505b60b9ddeae518887f925c527947af1712a",
    "cSHAKE-256-1.0-expectedResults.json": "decd4148c906a9a8b4084f7c1f1a06f27330535e",
    "cSHAKE-256-1.0-prompt.json": "cf49b691b462032bff9c517f17981b3ec1f8eb5d",
}

SOURCE = ("NIST ACVP-Server, https://github.com/usnistgov/ACVP-Server commit 975de31eb83d, "
          "gen-val/json-files/{names}, converted by scripts/gen_acvp_sig_vectors.py. ")

# Curve -> (coordinate bytes, narrowest digest accepted).
CURVES = {"P-256": (32, 32), "P-384": (48, 48), "P-521": (66, 64)}
# Hash -> digest bytes, for the hashes this library has.
HASHES = {"SHA2-256": 32, "SHA2-384": 48, "SHA2-512": 64, "SHA2-512/256": 32,
          "SHA3-256": 32, "SHA3-384": 48, "SHA3-512": 64}
NATIVE = {"P-256": "SHA2-256", "P-384": "SHA2-384", "P-521": "SHA2-512"}


def load(directory, name, part):
    file = f"{name}-{part}.json"
    with open(os.path.join(directory, file), "rb") as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    if "--print-digests" in sys.argv:
        print(f'    "{file}": "{digest[:40]}",', file=sys.stderr)
    elif not digest.startswith(PINNED[file]):
        raise SystemExit(f"{file}: SHA-256 {digest} is not the pinned file")
    doc = json.loads(raw)
    return doc[1] if isinstance(doc, list) else doc


def write(out, name, algorithm, source, cases):
    path = os.path.join(out, name + ".json")
    with open(path, "w", newline="\n") as f:
        json.dump({"algorithm": algorithm, "source": source, "cases": cases}, f, indent=1)
        f.write("\n")
    print(f"{path}: {len(cases)} cases, {os.path.getsize(path)} bytes")


def pad(value, size):
    """A big-endian integer as exactly `size` bytes of hex."""
    raw = bytes.fromhex(value if len(value) % 2 == 0 else "0" + value).lstrip(b"\0")
    assert len(raw) <= size, (value, size)
    return raw.rjust(size, b"\0").hex()


def kept(group):
    # A group marked with a conformance signs a message randomized per SP
    # 800-106 first, which this library does not do.
    if group.get("conformance"):
        return False
    curve, digest = CURVES.get(group["curve"]), HASHES.get(group["hashAlg"])
    return curve is not None and digest is not None and digest >= curve[1]


def ecdsa(acvp, out):
    cases = []
    # Signing: the private key is in the internal projection only.
    internal = load(acvp, "DetECDSA-SigGen-FIPS186-5", "internalProjection")
    expected = load(acvp, "DetECDSA-SigGen-FIPS186-5", "expectedResults")
    answers = {g["tgId"]: g for g in expected["testGroups"]}
    for group in internal["testGroups"]:
        if not kept(group) or group.get("componentTest"):
            continue
        size = CURVES[group["curve"]][0]
        answer = answers[group["tgId"]]
        assert answer["qx"] == group["qx"] and answer["qy"] == group["qy"]
        signatures = {t["tcId"]: t for t in answer["tests"]}
        for test in group["tests"]:
            published = signatures[test["tcId"]]
            assert published["r"] == test["r"] and published["s"] == test["s"]
            cases.append({
                "kind": "sign", "curve": group["curve"], "hash": group["hashAlg"],
                "native": "true" if NATIVE[group["curve"]] == group["hashAlg"] else "false",
                "d": pad(group["d"], size),
                "public_key": "04" + pad(group["qx"], size) + pad(group["qy"], size),
                "message": test["message"].lower(),
                "signature": pad(test["r"], size) + pad(test["s"], size),
                "valid": "true", "reason": ""})
    # Verification, with NIST's invalid cases and why each is invalid.
    internal = load(acvp, "ECDSA-SigVer-FIPS186-5", "internalProjection")
    expected = load(acvp, "ECDSA-SigVer-FIPS186-5", "expectedResults")
    verdicts = {(g["tgId"], t["tcId"]): t["testPassed"]
                for g in expected["testGroups"] for t in g["tests"]}
    for group in internal["testGroups"]:
        if not kept(group):
            continue
        size = CURVES[group["curve"]][0]
        for test in group["tests"]:
            assert verdicts[(group["tgId"], test["tcId"])] == test["testPassed"]
            cases.append({
                "kind": "verify", "curve": group["curve"], "hash": group["hashAlg"],
                "native": "true" if NATIVE[group["curve"]] == group["hashAlg"] else "false",
                "d": "",
                "public_key": "04" + pad(test["qx"], size) + pad(test["qy"], size),
                "message": test["message"].lower(),
                "signature": pad(test["r"], size) + pad(test["s"], size),
                "valid": "true" if test["testPassed"] else "false",
                "reason": test["reason"]})
    write(out, "acvp-ecdsa", "ECDSA over P-256, P-384 and P-521 (FIPS 186-5)",
          SOURCE.format(names="DetECDSA-SigGen-FIPS186-5 and ECDSA-SigVer-FIPS186-5")
          + "Every case for the three curves under each hash this library has that is wide "
          "enough for the curve. A `sign` case carries the private key from NIST's internal "
          "projection and the signature deterministic ECDSA produces; a `verify` case "
          "carries NIST's verdict and its reason. Signatures are fixed-width r || s and "
          "public keys SEC1 uncompressed.", cases)


def rsa(acvp, out):
    internal = load(acvp, "RSA-SigVer-FIPS186-5", "internalProjection")
    expected = load(acvp, "RSA-SigVer-FIPS186-5", "expectedResults")
    verdicts = {(g["tgId"], t["tcId"]): t["testPassed"]
                for g in expected["testGroups"] for t in g["tests"]}
    cases = []
    for group in internal["testGroups"]:
        if group["sigType"] != "pkcs1v1.5":
            continue
        assert group["hashAlg"] == "SHA2-256", group["hashAlg"]
        for test in group["tests"]:
            assert verdicts[(group["tgId"], test["tcId"])] == test["testPassed"]
            cases.append({
                "modulus_bits": str(group["modulo"]), "n": group["n"].lower(),
                "e": pad(group["e"], 8), "message": test["message"].lower(),
                "signature": test["signature"].lower(),
                "valid": "true" if test["testPassed"] else "false",
                "reason": test["reason"]})
    write(out, "acvp-rsa-sigver", "RSASSA-PKCS1-v1_5 verification with SHA-256 (FIPS 186-5)",
          SOURCE.format(names="RSA-SigVer-FIPS186-5")
          + "Every PKCS#1 v1.5 case, with NIST's verdict and its reason. The PSS groups are "
          "not here: they use SHA-3 and SHAKE, which this library's PSS does not.", cases)


def cshake(acvp, out):
    cases = []
    for bits in ("128", "256"):
        name = f"cSHAKE-{bits}-1.0"
        prompt = load(acvp, name, "prompt")
        expected = load(acvp, name, "expectedResults")
        answers = {(g["tgId"], t["tcId"]): t for g in expected["testGroups"] for t in g["tests"]}
        for group in prompt["testGroups"]:
            if group["testType"] != "AFT":
                continue
            assert not group["hexCustomization"]
            for test in group["tests"]:
                if test["len"] % 8 or test["outLen"] % 8:
                    continue
                answer = answers[(group["tgId"], test["tcId"])]
                assert answer["outLen"] == test["outLen"]
                message = test["msg"][:test["len"] // 4]
                cases.append({
                    "algorithm": "cshake" + bits, "message": message.lower(),
                    "function_name": test["functionName"].encode("ascii").hex(),
                    "customization": test["customization"].encode("ascii").hex(),
                    "output": answer["md"].lower()})
    write(out, "acvp-cshake", "cSHAKE128 and cSHAKE256 (SP 800-185)",
          SOURCE.format(names="cSHAKE-128-1.0 and cSHAKE-256-1.0")
          + "The cases whose message and output are whole bytes: five of two hundred. "
          "Function name and customization are given as the bytes of NIST's ASCII strings.",
          cases)


def main():
    acvp, out = sys.argv[1], sys.argv[2]
    ecdsa(acvp, out)
    rsa(acvp, out)
    cshake(acvp, out)


if __name__ == "__main__":
    main()
