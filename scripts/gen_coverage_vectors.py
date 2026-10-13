"""Convert the suites Graviola runs and this repository did not.

    python scripts/gen_coverage_vectors.py <cavp-dir> <wycheproof-dir> testvectors

<cavp-dir> holds NIST CAVP's byte-oriented response files, extracted from
these archives, each checked against the SHA-256 below:

  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/
    shs/shabytetestvectors.zip      (SHA-2: ShortMsg, LongMsg, Monte)
    sha3/sha-3bytetestvectors.zip   (SHA-3: ShortMsg, LongMsg, Monte)
    sha3/shakebytetestvectors.zip   (SHAKE: ShortMsg, LongMsg, VariableOut, Monte)
    mac/hmactestvectors.zip         (HMAC)

<wycheproof-dir> holds testvectors_v1/<name>.json from
https://github.com/C2SP/wycheproof at commit 12fd3aaf33eb, the commit
scripts/gen_wycheproof_vectors.py already uses, each checked against the
SHA-256 below.

Written:

- cavp-sha2.json: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and
  SHA-512/256, every ShortMsg, LongMsg and Monte case. SHA-1 is left out:
  this library does not implement it.
- cavp-sha3.json: SHA3-224 to SHA3-512 and SHAKE128 and SHAKE256, every
  case of every file, including SHAKE's VariableOut and Monte.
- cavp-hmac.json: HMAC with SHA-256, SHA-384 and SHA-512, with the truncated
  tag lengths CAVP gives. The SHA-1 and SHA-224 groups are left out: this
  library has neither as an HMAC hash.
- wycheproof-mlkem.json: ML-KEM-512, -768 and -1024, the three Wycheproof
  files each: key generation from a 64-byte seed, decapsulation including
  wrong-length inputs and malleated ciphertexts, and encapsulation including
  keys that fail FIPS 203's modulus check.
- wycheproof-ecdsa-extra.json: ECDSA verification with the signature as
  IEEE P1363 r || s over P-256, P-384 and P-521 under each curve's hash, and
  the DER files for the curve/hash pairs wycheproof-ecdsa.json lacks:
  P-256 with SHA-512, P-384 with SHA-256 and SHA-512.
- wycheproof-gmac.json: AES-GMAC, every case.
- wycheproof-primality.json: Wycheproof's primality cases, every case, with
  the value as Wycheproof gives it: a signed big-endian integer, so a
  negative value starts with a byte of 0x80 or more.

Nothing here computes a cryptographic value; Monte tests carry the seed and
NIST's checkpoints, and the test computes the chain.
"""

import hashlib
import json
import os
import re
import sys

ARCHIVES = {
    "shabytetestvectors.zip": "929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8",
    "sha-3bytetestvectors.zip": "cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c",
    "shakebytetestvectors.zip": "debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7",
    "hmactestvectors.zip": "418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd",
}
CAVP_SOURCE = ("NIST CAVP, https://csrc.nist.gov/CSRC/media/Projects/"
               "Cryptographic-Algorithm-Validation-Program/documents/{archive} (SHA-256 {digest}), "
               "{files}, converted by scripts/gen_coverage_vectors.py.")
WP_COMMIT = "12fd3aaf33eb"
WP_SOURCE = ("Project Wycheproof, https://github.com/C2SP/wycheproof commit " + WP_COMMIT
             + ", testvectors_v1/{names}, converted by scripts/gen_coverage_vectors.py. `result` is "
             "Wycheproof's: valid, invalid, or acceptable for an input a correct implementation "
             "may take either way.")

SHA2 = {"SHA224": "sha2-224", "SHA256": "sha2-256", "SHA384": "sha2-384", "SHA512": "sha2-512",
        "SHA512_224": "sha2-512-224", "SHA512_256": "sha2-512-256"}
SHA3 = {"SHA3_224": "sha3-224", "SHA3_256": "sha3-256", "SHA3_384": "sha3-384",
        "SHA3_512": "sha3-512"}
SHAKE = {"SHAKE128": "shake128", "SHAKE256": "shake256"}
HMAC_L = {32: "sha2-256", 48: "sha2-384", 64: "sha2-512"}

MLKEM = [f"mlkem_{n}_{kind}" for n in (512, 768, 1024)
         for kind in ("test", "encaps_test", "keygen_seed_test")]
ECDSA_P1363 = ["ecdsa_secp256r1_sha256_p1363_test", "ecdsa_secp384r1_sha384_p1363_test",
               "ecdsa_secp521r1_sha512_p1363_test"]
ECDSA_DER = ["ecdsa_secp256r1_sha512_test", "ecdsa_secp384r1_sha256_test",
             "ecdsa_secp384r1_sha512_test"]
GMAC = ["aes_gmac_test"]
PRIMALITY = ["primality_test"]
# testvectors_v1/primality_test.json at WP_COMMIT. Unlike the other Wycheproof
# files, which only record their digest, this one is checked.
PRIMALITY_SHA256 = "31ec21fb04bffef38d42a04339932be806d679fbb33714d16c6bed3748dbd8d8"


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def find(root, name):
    for dirpath, _, files in os.walk(root):
        if name in files:
            return os.path.join(dirpath, name)
    raise SystemExit(f"{name} not found under {root}")


def rsp(path):
    """Yield (section, record) from a CAVP response file. A record is the
    key = value lines between blank lines; a section header in brackets
    carries its own key = value."""
    section = {}
    record = {}
    with open(path, encoding="ascii") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                if record:
                    yield dict(section), record
                    record = {}
                continue
            m = re.fullmatch(r"\[(.+?)\s*=\s*(.+?)\]", line)
            if m:
                if record:
                    yield dict(section), record
                    record = {}
                section[m[1].strip()] = m[2].strip()
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                record[k.strip()] = v.strip()
    if record:
        yield dict(section), record


def msg_hex(record):
    """CAVP writes an empty message as Len = 0 and Msg = 00."""
    bits = int(record["Len"])
    if bits % 8:
        raise SystemExit("a bit-oriented message in a byte-oriented file")
    return record["Msg"][: bits // 4] if bits else ""


def write(out, name, algorithm, source, cases):
    with open(os.path.join(out, name), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"algorithm": algorithm, "source": source, "cases": cases}, f, indent=1)
        f.write("\n")
    print(f"{name}: {len(cases)} cases")


def check_archives(cavp):
    for archive, digest in ARCHIVES.items():
        path = os.path.join(cavp, archive)
        got = sha256_file(path)
        if got != digest:
            raise SystemExit(f"{archive}: SHA-256 {got}, expected {digest}")


def cavp_hash(cavp, out):
    sha2, sha3 = [], []
    for prefix, alg in list(SHA2.items()) + list(SHA3.items()):
        target = sha2 if prefix in SHA2 else sha3
        for kind in ("ShortMsg", "LongMsg"):
            for _, r in rsp(find(cavp, f"{prefix}{kind}.rsp")):
                if "Msg" in r:
                    target.append({"kind": "msg", "hash": alg, "msg": msg_hex(r), "md": r["MD"]})
        seed = None
        for _, r in rsp(find(cavp, f"{prefix}Monte.rsp")):
            if "Seed" in r:
                seed = r["Seed"]
            if "MD" in r:
                target.append({"kind": "monte", "hash": alg, "seed": seed, "count": r["COUNT"],
                               "md": r["MD"]})
    for prefix, alg in SHAKE.items():
        for kind in ("ShortMsg", "LongMsg"):
            for _, r in rsp(find(cavp, f"{prefix}{kind}.rsp")):
                if "Msg" in r:
                    sha3.append({"kind": "msg", "hash": alg, "msg": msg_hex(r),
                                 "md": r["Output"]})
        for _, r in rsp(find(cavp, f"{prefix}VariableOut.rsp")):
            if "Msg" in r:
                bits = int(r["Outputlen"])
                sha3.append({"kind": "msg", "hash": alg, "msg": r["Msg"],
                             "md": r["Output"][: bits // 4]})
        msg = None
        for sec, r in rsp(find(cavp, f"{prefix}Monte.rsp")):
            if "Msg" in r:
                msg = r["Msg"]
            if "Output" in r:
                sha3.append({"kind": "shake-monte", "hash": alg, "seed": msg,
                             "count": r["COUNT"], "md": r["Output"], "outlen": r["Outputlen"],
                             "min_bits": sec["Minimum Output Length (bits)"],
                             "max_bits": sec["Maximum Output Length (bits)"]})
    write(out, "cavp-sha2.json", "sha-2",
          CAVP_SOURCE.format(archive="shs/shabytetestvectors.zip",
                             digest=ARCHIVES["shabytetestvectors.zip"],
                             files="SHA{224,256,384,512,512_224,512_256}{ShortMsg,LongMsg,Monte}.rsp"),
          sha2)
    write(out, "cavp-sha3.json", "sha-3",
          CAVP_SOURCE.format(archive="sha3/sha-3bytetestvectors.zip and sha3/shakebytetestvectors.zip",
                             digest=ARCHIVES["sha-3bytetestvectors.zip"] + " and "
                             + ARCHIVES["shakebytetestvectors.zip"],
                             files="SHA3_{224,256,384,512}{ShortMsg,LongMsg,Monte}.rsp and "
                                   "SHAKE{128,256}{ShortMsg,LongMsg,VariableOut,Monte}.rsp"),
          sha3)


def cavp_hmac(cavp, out):
    cases = []
    for sec, r in rsp(find(cavp, "HMAC.rsp")):
        L = int(sec["L"])
        if L not in HMAC_L or "Mac" not in r:
            continue
        key = r["Key"][: 2 * int(r["Klen"])]
        cases.append({"hash": HMAC_L[L], "key": key, "msg": r["Msg"], "tag": r["Mac"],
                      "tlen": r["Tlen"]})
    write(out, "cavp-hmac.json", "hmac",
          CAVP_SOURCE.format(archive="mac/hmactestvectors.zip",
                             digest=ARCHIVES["hmactestvectors.zip"],
                             files="HMAC.rsp, the L=32, 48 and 64 groups"),
          cases)


def wp(directory, name):
    path = os.path.join(directory, name + ".json")
    with open(path, encoding="utf-8") as f:
        return json.load(f), sha256_file(path)


def pin(names, digests):
    return ", ".join(f"{n}.json (SHA-256 {d})" for n, d in zip(names, digests))


def mlkem(directory, out):
    cases, digests = [], []
    for name in MLKEM:
        j, digest = wp(directory, name)
        digests.append(digest)
        for g in j["testGroups"]:
            ps = g["parameterSet"]
            for t in g["tests"]:
                case = {"set": ps, "file": name.split("_", 2)[2], "tcId": str(t["tcId"]),
                        "result": t["result"], "flags": " ".join(t.get("flags", []))}
                for field in ("seed", "ek", "dk", "c", "K", "m"):
                    if field in t:
                        case[field] = t[field]
                cases.append(case)
    write(out, "wycheproof-mlkem.json", "ml-kem",
          WP_SOURCE.format(names=pin(MLKEM, digests)), cases)


def ecdsa_extra(directory, out):
    cases, digests = [], []
    for name in ECDSA_P1363 + ECDSA_DER:
        j, digest = wp(directory, name)
        digests.append(digest)
        encoding = "p1363" if name.endswith("_p1363_test") else "der"
        curve = re.search(r"secp(\d+)r1", name)[1]
        for g in j["testGroups"]:
            hash_name = g["sha"].lower().replace("-", "")
            key = g["publicKey"]["uncompressed"]
            for t in g["tests"]:
                cases.append({"curve": "p" + curve, "hash": hash_name, "encoding": encoding,
                              "key": key, "msg": t["msg"], "sig": t["sig"],
                              "result": t["result"], "tcId": str(t["tcId"]),
                              "comment": t.get("comment", "")})
    write(out, "wycheproof-ecdsa-extra.json", "ecdsa",
          WP_SOURCE.format(names=pin(ECDSA_P1363 + ECDSA_DER, digests)), cases)


def gmac(directory, out):
    cases, digests = [], []
    for name in GMAC:
        j, digest = wp(directory, name)
        digests.append(digest)
        for g in j["testGroups"]:
            for t in g["tests"]:
                cases.append({"key": t["key"], "iv": t["iv"], "msg": t["msg"], "tag": t["tag"],
                              "result": t["result"], "tcId": str(t["tcId"]),
                              "comment": t.get("comment", "")})
    write(out, "wycheproof-gmac.json", "aes-gmac",
          WP_SOURCE.format(names=pin(GMAC, digests)), cases)


def primality(directory, out):
    cases, digests = [], []
    for name in PRIMALITY:
        j, digest = wp(directory, name)
        if digest != PRIMALITY_SHA256:
            raise SystemExit(f"{name}.json: SHA-256 {digest}, expected {PRIMALITY_SHA256}")
        digests.append(digest)
        for g in j["testGroups"]:
            for t in g["tests"]:
                cases.append({"tcId": str(t["tcId"]), "result": t["result"],
                              "flags": " ".join(t.get("flags", [])),
                              "comment": t.get("comment", ""), "value": t["value"]})
    write(out, "wycheproof-primality.json", "primality",
          WP_SOURCE.format(names=pin(PRIMALITY, digests)), cases)


def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    cavp, wycheproof, out = sys.argv[1:]
    check_archives(cavp)
    cavp_hash(cavp, out)
    cavp_hmac(cavp, out)
    mlkem(wycheproof, out)
    ecdsa_extra(wycheproof, out)
    gmac(wycheproof, out)
    primality(wycheproof, out)


if __name__ == "__main__":
    main()
