"""Convert NIST's ACVP SLH-DSA files into this repository's vector format.

    python scripts/gen_slh_dsa_vectors.py <acvp-dir> testvectors          # bundled subset
    python scripts/gen_slh_dsa_vectors.py <acvp-dir> <elsewhere> --full   # every case

<acvp-dir> holds, for each of SLH-DSA-keyGen-FIPS205, SLH-DSA-sigGen-FIPS205
and SLH-DSA-sigVer-FIPS205, the files `<name>-prompt.json` and
`<name>-expectedResults.json`, as downloaded from
https://github.com/usnistgov/ACVP-Server at commit 975de31eb83d
(gen-val/json-files/<name>/). Each is checked against the SHA-256 below.

The originals are about 70 MB, almost all of it signatures of up to 49,856
bytes, so the bundled files are a subset, chosen to lose as little as possible:

- slh-dsa-keygen.json: every key-generation case, all 120.
- slh-dsa-siggen.json: for each parameter set and variant (deterministic,
  hedged), the shortest-message case of the pure and internal interfaces and
  two cases of the pre-hash interface, rotated so that all twelve hash
  functions are covered: 96 cases. The expected signature is stored as its
  SHA-256 and its length. Signing is a function of its inputs, so comparing
  digests compares signatures.
- slh-dsa-sigver.json: for the pure interface of the six parameter sets with
  the smallest signatures, both passing cases and the first three failing
  ones; for the pre-hash interface of the two smallest, all fourteen cases,
  which name every hash function: 58 cases, with their signatures.

`--full` writes every case of all three interfaces, with whole signatures,
under the names slh-dsa-*-full.json. `ironcrypto/tests/slh_dsa.rs` runs them
when IC_SLH_DSA_FULL names their directory.

Nothing here computes a cryptographic value except SHA-256 of NIST's
signatures.
"""

import hashlib
import json
import os
import sys

PINNED = {
    "SLH-DSA-keyGen-FIPS205-prompt.json": "bce170976f257ee3",
    "SLH-DSA-keyGen-FIPS205-expectedResults.json": "f35f74b6676d6b36",
    "SLH-DSA-sigGen-FIPS205-prompt.json": "afa673eacdf0aec5",
    "SLH-DSA-sigGen-FIPS205-expectedResults.json": "71e8e0f7e4b0cfd1",
    "SLH-DSA-sigVer-FIPS205-prompt.json": "4e7beb1233e47baa",
    "SLH-DSA-sigVer-FIPS205-expectedResults.json": "259f5e2a0665de0a",
}
SOURCE = ("NIST ACVP-Server, https://github.com/usnistgov/ACVP-Server commit 975de31eb83d, "
          "gen-val/json-files/{name}, converted by scripts/gen_slh_dsa_vectors.py. ")
SMALL = ["SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f",
         "SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s"]


def load(directory, name):
    out = []
    for part in ("prompt", "expectedResults"):
        filename = f"{name}-{part}.json"
        data = open(os.path.join(directory, filename), "rb").read()
        if not hashlib.sha256(data).hexdigest().startswith(PINNED[filename]):
            raise SystemExit(f"{filename} is not the pinned ACVP file")
        out.append(json.loads(data))
    prompt, expected = out
    answers = {}
    for group in expected["testGroups"]:
        for test in group["tests"]:
            answers[(group["tgId"], test["tcId"])] = test
    return prompt, answers


def set_id(name):
    return name.lower()  # SLH-DSA-SHA2-128s -> slh-dsa-sha2-128s


def interface(group):
    """`external` (pure), `prehash` or `internal`."""
    if group.get("signatureInterface") == "internal":
        return "internal"
    if group.get("preHash") == "pure":
        return "external"
    if group.get("preHash") == "preHash":
        return "prehash"
    raise SystemExit(f"unknown interface in group {group['tgId']}")


def bundled_signing(group, kind, rotate):
    """The bundled signing cases of one group."""
    tests = group["tests"]
    if kind != "prehash":
        return [min(tests, key=lambda t: len(t["message"]))]
    # A pre-hash group has one case per hash function. Two per group, at a
    # position that moves from group to group, cover every function several
    # times over without signing 288 messages.
    ordered = sorted(tests, key=lambda t: t["hashAlg"])
    return [ordered[rotate % len(ordered)], ordered[(rotate + 6) % len(ordered)]]


def write(directory, name, algorithm, source, cases):
    path = os.path.join(directory, name + ".json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"algorithm": algorithm, "source": source, "cases": cases}, f, indent=1)
        f.write("\n")
    print(f"{path}: {len(cases)} cases, {os.path.getsize(path)} bytes", file=sys.stderr)


def main():
    args = [a for a in sys.argv[1:] if a != "--full"]
    full = "--full" in sys.argv
    if len(args) != 2:
        raise SystemExit(__doc__)
    acvp, out = args
    suffix = "-full" if full else ""

    # Key generation: all of it, in both modes.
    prompt, answers = load(acvp, "SLH-DSA-keyGen-FIPS205")
    cases = []
    for group in prompt["testGroups"]:
        for test in group["tests"]:
            answer = answers[(group["tgId"], test["tcId"])]
            cases.append({"parameter_set": set_id(group["parameterSet"]),
                          "sk_seed": test["skSeed"].lower(), "sk_prf": test["skPrf"].lower(),
                          "pk_seed": test["pkSeed"].lower(),
                          "sk": answer["sk"].lower(), "pk": answer["pk"].lower()})
    write(out, "slh-dsa-keygen" + suffix, "SLH-DSA key generation (FIPS 205)",
          SOURCE.format(name="SLH-DSA-keyGen-FIPS205") + "Every case.", cases)

    # Signature generation.
    prompt, answers = load(acvp, "SLH-DSA-sigGen-FIPS205")
    cases = []
    rotate = 0
    for group in prompt["testGroups"]:
        kind = interface(group)
        tests = group["tests"] if full else bundled_signing(group, kind, rotate)
        if kind == "prehash":
            rotate += 1
        for test in tests:
            signature = bytes.fromhex(answers[(group["tgId"], test["tcId"])]["signature"])
            case = {"parameter_set": set_id(group["parameterSet"]), "interface": kind,
                    "hash": test.get("hashAlg", ""),
                    "deterministic": "true" if group["deterministic"] else "false",
                    "sk": test["sk"].lower(), "message": test["message"].lower(),
                    "context": test.get("context", "").lower(),
                    "additional_randomness": test.get("additionalRandomness", "").lower(),
                    "signature_len": str(len(signature)),
                    "signature_sha256": hashlib.sha256(signature).hexdigest()}
            if full:
                case["signature"] = signature.hex()
            cases.append(case)
    write(out, "slh-dsa-siggen" + suffix, "SLH-DSA signature generation (FIPS 205)",
          SOURCE.format(name="SLH-DSA-sigGen-FIPS205")
          + ("Every case of the pure, pre-hash and internal interfaces." if full else
             "For each parameter set and variant (deterministic, hedged): the "
             "shortest-message case of the pure and internal interfaces, and two cases of "
             "the pre-hash interface, chosen so that every hash function is covered. The "
             "expected signature is given as its SHA-256 and length."), cases)

    # Signature verification.
    prompt, answers = load(acvp, "SLH-DSA-sigVer-FIPS205")
    cases = []
    for group in prompt["testGroups"]:
        kind = interface(group)
        if not full:
            # Pure for the six smallest sets; pre-hash for the two smallest.
            wanted = SMALL if kind == "external" else SMALL[:2] if kind == "prehash" else []
            if group["parameterSet"] not in wanted:
                continue
        tests = group["tests"]
        # A pre-hash group is kept whole: its fourteen cases name all twelve
        # hash functions between them.
        if not full and kind != "prehash":
            passing = [t for t in tests if answers[(group["tgId"], t["tcId"])]["testPassed"]]
            failing = [t for t in tests if not answers[(group["tgId"], t["tcId"])]["testPassed"]]
            tests = passing + failing[:3]
        for test in tests:
            cases.append({"parameter_set": set_id(group["parameterSet"]), "interface": kind,
                          "hash": test.get("hashAlg", ""),
                          "pk": test["pk"].lower(), "message": test["message"].lower(),
                          "context": test.get("context", "").lower(),
                          "signature": test["signature"].lower(),
                          "valid": "true" if answers[(group["tgId"], test["tcId"])]["testPassed"]
                          else "false"})
    write(out, "slh-dsa-sigver" + suffix, "SLH-DSA signature verification (FIPS 205)",
          SOURCE.format(name="SLH-DSA-sigVer-FIPS205")
          + ("Every case of the pure, pre-hash and internal interfaces." if full else
             "The pure interface of the six parameter sets with the smallest signatures: "
             "each group's passing cases and its first three failing ones. The pre-hash "
             "interface of the two smallest: every case."), cases)


if __name__ == "__main__":
    main()
