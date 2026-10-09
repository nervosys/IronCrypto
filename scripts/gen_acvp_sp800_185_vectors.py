"""Convert NIST's ACVP TupleHash, ParallelHash and KMAC files into this
repository's vector format.

    python scripts/gen_acvp_sp800_185_vectors.py <acvp-dir> > testvectors/acvp-sp800-185.json

<acvp-dir> holds `<name>-internalProjection.json` and
`<name>-expectedResults.json` for TupleHash-128-1.0, TupleHash-256-1.0,
ParallelHash-128-1.0, ParallelHash-256-1.0, KMAC-128-1.0 and KMAC-256-1.0, as
downloaded from https://github.com/usnistgov/ACVP-Server at commit
975de31eb83d (gen-val/json-files/<name>/). Each is checked against the
SHA-256 below. The internal projection is read because it carries inputs and
answers in one place; every answer is checked against the expected results.

NIST's cases are bit-oriented and this library hashes bytes, so a case is
kept only if every length in it is a whole number of bytes. That keeps all of
TupleHash, whose sample happens to be byte-aligned throughout, and little of
the others:

- TupleHash: all 400 functional cases, fixed-length and XOF.
- ParallelHash: 13 of 400.
- KMAC: 3 of 1600, all of them verification cases, where NIST gives a MAC
  and says whether it is right.

The Monte Carlo groups are not converted.

Nothing here computes a cryptographic value.
"""

import hashlib
import json
import os
import sys

PINNED = {
    "KMAC-128-1.0-expectedResults.json": "06e1be237f92995054c475c35b5b11c5637df699",
    "KMAC-128-1.0-internalProjection.json": "43ee39f587abbf5c4ada9236ba0d55fd9f6ea4f0",
    "KMAC-256-1.0-expectedResults.json": "7a54cc6e3899453156acbd73887262d5b1adb979",
    "KMAC-256-1.0-internalProjection.json": "3c64e79297096cca5e69162be42af8d54e516810",
    "ParallelHash-128-1.0-expectedResults.json": "7587f20c11b4f3287fb875d19b804e39561c11a4",
    "ParallelHash-128-1.0-internalProjection.json": "500bc2b62f897622c6f15b12da737e92e67b14cd",
    "ParallelHash-256-1.0-expectedResults.json": "fa30a42f67143f275c45e4b4ea541e6bab597572",
    "ParallelHash-256-1.0-internalProjection.json": "b920dab55ffaccbde2b251c56d92d0ef5cd160b5",
    "TupleHash-128-1.0-expectedResults.json": "c50486f527888605973d747f59399a14562d11c2",
    "TupleHash-128-1.0-internalProjection.json": "31054671778422f19c425585932da30031e42f45",
    "TupleHash-256-1.0-expectedResults.json": "6fb188e85333ec3a2e292b8c521a0b9b793c6e27",
    "TupleHash-256-1.0-internalProjection.json": "6f9710705fcfe06e8b9f5e4cf4b5820434f33401",
}


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


def groups(acvp, name):
    """Each functional group with its tests, answers checked against the
    expected results."""
    internal = load(acvp, name, "internalProjection")
    expected = load(acvp, name, "expectedResults")
    answers = {(g["tgId"], t["tcId"]): t for g in expected["testGroups"] for t in g["tests"]}
    for group in internal["testGroups"]:
        if group["testType"] == "MCT":
            continue
        for test in group["tests"]:
            answer = answers[(group["tgId"], test["tcId"])]
            for field in ("md", "mac", "testPassed"):
                if field in answer:
                    assert answer[field] == test[field], (name, test["tcId"], field)
        yield group


def custom(group, test):
    """The customization string as bytes. NIST gives it as ASCII in
    `customization`, or, in a group marked `hexCustomization`, as hex in a
    field of its own, `customizationHex`, with `customization` left empty.
    Reading the empty one is how this script first made a correct KMAC look
    wrong."""
    if group["hexCustomization"]:
        assert test["customization"] == "", test["tcId"]
        return test["customizationHex"].lower()
    assert "customizationHex" not in test or not test["customizationHex"], test["tcId"]
    return test["customization"].encode("ascii").hex()


def truncated(hex_string, bits):
    assert bits % 8 == 0
    return hex_string[:bits // 4].lower()


def main():
    acvp = sys.argv[1]
    cases = []
    for bits in ("128", "256"):
        for group in groups(acvp, f"TupleHash-{bits}-1.0"):
            for test in group["tests"]:
                if any(n % 8 for n in test["len"]) or test["outLen"] % 8:
                    continue
                elements = [truncated(e, n) for e, n in zip(test["tuple"], test["len"])]
                cases.append({
                    "function": "tuplehash" + bits, "xof": "true" if group["xof"] else "false",
                    "key": "", "block_size": "",
                    # Elements separated by commas; an empty element is the
                    # empty string between two of them.
                    "input": ",".join(elements), "elements": str(len(elements)),
                    "customization": custom(group, test),
                    "output": truncated(test["md"], test["outLen"]), "valid": "true"})
        for group in groups(acvp, f"ParallelHash-{bits}-1.0"):
            for test in group["tests"]:
                if test["len"] % 8 or test["outLen"] % 8:
                    continue
                cases.append({
                    "function": "parallelhash" + bits, "xof": "true" if group["xof"] else "false",
                    "key": "", "block_size": str(test["blockSize"]),
                    "input": truncated(test["msg"], test["len"]), "elements": "",
                    "customization": custom(group, test),
                    "output": truncated(test["md"], test["outLen"]), "valid": "true"})
        for group in groups(acvp, f"KMAC-{bits}-1.0"):
            for test in group["tests"]:
                if test["keyLen"] % 8 or test["msgLen"] % 8 or test["macLen"] % 8:
                    continue
                assert group["testType"] == "MVT", "a functional KMAC case is byte-aligned now"
                cases.append({
                    "function": "kmac" + bits, "xof": "true" if group["xof"] else "false",
                    "key": truncated(test["key"], test["keyLen"]), "block_size": "",
                    "input": truncated(test["msg"], test["msgLen"]), "elements": "",
                    "customization": custom(group, test),
                    "output": truncated(test["mac"], test["macLen"]),
                    "valid": "true" if test["testPassed"] else "false"})
    json.dump({
        "algorithm": "TupleHash, ParallelHash and KMAC (SP 800-185)",
        "source": "NIST ACVP-Server, https://github.com/usnistgov/ACVP-Server commit "
                  "975de31eb83d, gen-val/json-files/TupleHash-*, ParallelHash-* and KMAC-*, "
                  "converted by scripts/gen_acvp_sp800_185_vectors.py. The cases whose every "
                  "length is whole bytes: all of TupleHash, 13 ParallelHash, 3 KMAC. For KMAC "
                  "`output` is a MAC NIST supplies and `valid` says whether it is the right one.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()
    counts = {}
    for case in cases:
        counts[case["function"]] = counts.get(case["function"], 0) + 1
    print(counts, file=sys.stderr)


if __name__ == "__main__":
    main()
