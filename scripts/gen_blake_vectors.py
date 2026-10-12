"""Transcribe the BLAKE2s and BLAKE3 test vectors their authors publish.

    python -I scripts/gen_blake_vectors.py <dir> testvectors

<dir> holds two files, each checked against the SHA-256 below:

- blake2s-kat.txt, from https://github.com/BLAKE2/BLAKE2 at
  ed1974ea83433eba7b2d95c5dcd9ac33cb847913, testvectors/blake2s-kat.txt:
  keyed BLAKE2s-256 of inputs of 0 to 255 bytes under one 32-byte key.
- test_vectors.json, from https://github.com/BLAKE3-team/BLAKE3 at
  f55849f89cd85083c1c9daa2c5de20766f309c00, test_vectors/test_vectors.json:
  the hash, keyed hash and key derivation of 35 input lengths, each to 131
  bytes of extended output.

Two files are written, blake2s-kat.json and blake3.json. Values are copied,
not computed, except that each BLAKE2s line is also checked against
Python's hashlib.blake2s, a second implementation, so that a parse which
pairs the wrong lines fails here.
"""

import hashlib
import json
import os
import sys

PINNED = {
    "blake2s-kat.txt": "a915b96fc07f6ece3b3355a5cbb813dbf9cd0ad37c22a9b89bf11f9c47922418",
    "test_vectors.json": "dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624",
}


def load(directory, name):
    raw = open(os.path.join(directory, name), "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != PINNED[name]:
        raise SystemExit(f"{name}: SHA-256 {digest} is not the pinned file")
    return raw.decode("ascii")


def blake2s(text):
    cases, case = [], {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        name, _, value = line.partition(":")
        case[name.strip()] = value.strip()
        if name.strip() == "hash":
            want = hashlib.blake2s(bytes.fromhex(case["in"]), key=bytes.fromhex(case["key"])).hexdigest()
            assert want == case["hash"], case
            cases.append({"in": case["in"], "key": case["key"], "hash": case["hash"]})
            case = {}
    assert len(cases) == 256 and [len(c["in"]) // 2 for c in cases] == list(range(256))
    return {
        "algorithm": "BLAKE2s-256, keyed",
        "source": "testvectors/blake2s-kat.txt of the BLAKE2 team's repository at "
                  "ed1974ea83433eba7b2d95c5dcd9ac33cb847913 (SHA-256 "
                  + PINNED["blake2s-kat.txt"] + "), transcribed by "
                  "scripts/gen_blake_vectors.py and checked against Python's hashlib.blake2s. "
                  "`in`, `key` and `hash` are hex.",
        "cases": cases,
    }


def blake3(text):
    src = json.loads(text)
    assert len(src["cases"]) == 35
    return {
        "algorithm": "BLAKE3: hash, keyed_hash and derive_key, extended output",
        "source": "test_vectors/test_vectors.json of the BLAKE3 repository at "
                  "f55849f89cd85083c1c9daa2c5de20766f309c00 (SHA-256 "
                  + PINNED["test_vectors.json"] + "), transcribed by "
                  "scripts/gen_blake_vectors.py. " + src["_comment"],
        "cases": [
            {
                "key": src["key"].encode("ascii").hex(),
                "context_string": src["context_string"].encode("ascii").hex(),
                "input_len": str(c["input_len"]),
                "hash": c["hash"],
                "keyed_hash": c["keyed_hash"],
                "derive_key": c["derive_key"],
            }
            for c in src["cases"]
        ],
    }


def main():
    src, out = sys.argv[1], sys.argv[2]
    for name, data in (
        ("blake2s-kat.json", blake2s(load(src, "blake2s-kat.txt"))),
        ("blake3.json", blake3(load(src, "test_vectors.json"))),
    ):
        with open(os.path.join(out, name), "w", newline="\n") as f:
            json.dump(data, f, indent=1)
            f.write("\n")


if __name__ == "__main__":
    main()
