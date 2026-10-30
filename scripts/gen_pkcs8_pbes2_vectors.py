"""Generate testvectors/openssl-pkcs8-pbes2.json: PKCS#8 keys OpenSSL encrypted
under PBES2 (RFC 8018), for `ic_pkix::pbes2`.

    python scripts/gen_pkcs8_pbes2_vectors.py > testvectors/openssl-pkcs8-pbes2.json

Each case is one fresh key, written by `openssl pkcs8 -topk8` under a
different passphrase, PBKDF2 PRF, iteration count or cipher. The case carries
the EncryptedPrivateKeyInfo DER as OpenSSL wrote it, the unencrypted PKCS#8 of
the same key, the PBKDF2 salt and the CBC IV (both read from the DER by a
strict parser in this script, not by asn1parse), and the iteration count.
`expect` says what the loader must do: accept, or refuse for a reason.

Every field is lowercase hex, text fields included (the hex of their UTF-8
bytes), because the Rust loader decodes every field with hex.

The script checks, before writing anything, that OpenSSL decrypts every
encrypted key back to the plaintext it recorded, and that the parsed
structure matches the parameters it asked for. It also reports whether
OpenSSL writes the PBKDF2 `prf` field for hmacWithSHA1: that algorithm is the
DER DEFAULT, so the field must be absent, and the script fails if it is not.

Needs the `openssl` command at 3.5 or later. Keys are generated and discarded,
so no two runs give the same file. **These are test keys in a public
repository and protect nothing.**

Interoperability vectors from an independent implementation, not values from
a standard. What they hold is the reading of the encrypted key file: that a
PKCS#8 key another implementation encrypted is decrypted, and parsed into the
PBES2 parameters that implementation says it used.
"""

import json
import os
import subprocess
import sys
import tempfile

# (name, genpkey arguments, cipher, PRF, iterations, expect, passphrase)
CASES = [
    ("p256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
     "aes-256-cbc", "hmacWithSHA256", 600000, "accept", "correct horse p256"),
    ("p384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
     "aes-256-cbc", "hmacWithSHA256", 600000, "accept", "correct horse p384"),
    ("ed25519", ["-algorithm", "ED25519"],
     "aes-256-cbc", "hmacWithSHA256", 600000, "accept", "correct horse ed25519"),
    ("p256-high-iter", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
     "aes-256-cbc", "hmacWithSHA256", 1000000, "accept", "correct horse p256 high"),
    ("p256-iter-2048", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
     "aes-256-cbc", "hmacWithSHA256", 2048, "refuse-iterations", "correct horse p256 2048"),
    ("p256-sha1-prf", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
     "aes-256-cbc", "hmacWithSHA1", 600000, "refuse-prf", "correct horse p256 sha1"),
    ("p256-aes128", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
     "aes-128-cbc", "hmacWithSHA256", 600000, "refuse-cipher", "correct horse p256 aes128"),
]

# DER OIDs (dotted form; encoded below).
OID_PBES2 = "1.2.840.113549.1.5.13"
OID_PBKDF2 = "1.2.840.113549.1.5.12"
PRF_OIDS = {"hmacWithSHA256": "1.2.840.113549.2.9", "hmacWithSHA1": "1.2.840.113549.2.7"}
CIPHER_OIDS = {"aes-256-cbc": "2.16.840.1.101.3.4.1.42", "aes-128-cbc": "2.16.840.1.101.3.4.1.2"}

EXPECTS = {"accept", "refuse-iterations", "refuse-prf", "refuse-cipher"}


def run(*args):
    proc = subprocess.run(args, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:2])} failed: {proc.stderr.decode(errors='replace')}")
    return proc.stdout


def oid_encode(dotted):
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        groups = [value & 0x7F]
        value >>= 7
        while value:
            groups.append((value & 0x7F) | 0x80)
            value >>= 7
        body.extend(reversed(groups))
    return bytes(body)


def read_tlv(data, off):
    """One strict DER TLV at `off`: returns (tag, content, next offset)."""
    if off + 2 > len(data):
        raise ValueError("truncated TLV")
    tag = data[off]
    if tag & 0x1F == 0x1F:
        raise ValueError("high-tag-number form not expected here")
    first = data[off + 1]
    if first == 0x80:
        raise ValueError("indefinite length is not DER")
    if first < 0x80:
        length, header = first, 2
    else:
        n = first & 0x7F
        if n > 4 or off + 2 + n > len(data):
            raise ValueError("bad length")
        raw = data[off + 2:off + 2 + n]
        length = int.from_bytes(raw, "big")
        if length < 0x80 or raw[0] == 0:
            raise ValueError("non-minimal length")
        header = 2 + n
    end = off + header + length
    if end > len(data):
        raise ValueError("length runs past the end")
    return tag, data[off + header:end], end


def children(content, expected_tags):
    """Split a constructed content into TLVs, requiring the tags in order."""
    out, off = [], 0
    while off < len(content):
        tag, body, off = read_tlv(content, off)
        out.append((tag, body))
    if [t for t, _ in out] != expected_tags:
        raise ValueError(f"expected tags {expected_tags}, found {[t for t, _ in out]}")
    return out


def oid_text(content):
    parts = [content[0] // 40, content[0] % 40]
    value = 0
    for b in content[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def parse_encrypted_key_info(der):
    """Parse an EncryptedPrivateKeyInfo under PBES2 (RFC 8018 section 6.2)."""
    tag, top, end = read_tlv(der, 0)
    if end != len(der) or tag != 0x30:
        raise ValueError("EncryptedPrivateKeyInfo is not one SEQUENCE")
    alg, enc_data = children(top, [0x30, 0x04])
    alg_oid, params = children(alg[1], [0x06, 0x30])
    if oid_text(alg_oid[1]) != OID_PBES2:
        raise ValueError("not PBES2")
    kdf, scheme = children(params[1], [0x30, 0x30])
    kdf_oid, kdf_params = children(kdf[1], [0x06, 0x30])
    if oid_text(kdf_oid[1]) != OID_PBKDF2:
        raise ValueError("key derivation is not PBKDF2")
    # salt, iterationCount, then optional keyLength and prf (prf must be the last field).
    fields = []
    off = 0
    while off < len(kdf_params[1]):
        tag, body, off = read_tlv(kdf_params[1], off)
        fields.append((tag, body))
    if len(fields) < 2 or fields[0][0] != 0x04 or fields[1][0] != 0x02:
        raise ValueError("PBKDF2 params must start with salt and iterationCount")
    prf = None
    rest = fields[2:]
    if rest and rest[0][0] == 0x02:
        rest = rest[1:]  # keyLength
    if rest:
        if len(rest) != 1 or rest[0][0] != 0x30:
            raise ValueError("unexpected trailing PBKDF2 field")
        # AlgorithmIdentifier: OID, then optional NULL parameters.
        prf_content = rest[0][1]
        tag, oid_body, off = read_tlv(prf_content, 0)
        if tag != 0x06:
            raise ValueError("prf is not an AlgorithmIdentifier")
        if off != len(prf_content) and prf_content[off:] != b"\x05\x00":
            raise ValueError("unexpected prf parameters")
        prf = oid_text(oid_body)
    salt = fields[0][1]
    iter_bytes = fields[1][1]
    if not iter_bytes or iter_bytes[0] & 0x80 or (len(iter_bytes) > 1 and iter_bytes[0] == 0):
        raise ValueError("iterationCount is not a minimal positive INTEGER")
    iterations = int.from_bytes(iter_bytes, "big")
    cipher_oid, iv = children(scheme[1], [0x06, 0x04])
    if len(iv[1]) != 16:
        raise ValueError("CBC IV is not 16 bytes")
    return {
        "salt": salt,
        "iterations": iterations,
        "prf": prf,
        "cipher": oid_text(cipher_oid[1]),
        "iv": iv[1],
        "encrypted_data": enc_data[1],
    }


def main():
    version = run("openssl", "version").decode().strip()
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        pem = os.path.join(tmp, "key.pem")
        enc_path = os.path.join(tmp, "encrypted.der")
        for name, genpkey, cipher, prf, iterations, expect, passphrase in CASES:
            if expect not in EXPECTS:
                raise ValueError(f"{name}: unknown expect {expect!r}")
            run("openssl", "genpkey", *genpkey, "-out", pem)
            plaintext = run("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", pem,
                            "-outform", "DER")
            encrypted = run("openssl", "pkcs8", "-topk8", "-in", pem, "-outform", "DER",
                            "-v2", cipher, "-v2prf", prf, "-iter", str(iterations),
                            "-passout", "pass:" + passphrase)

            info = parse_encrypted_key_info(encrypted)
            if info["iterations"] != iterations:
                raise SystemExit(f"{name}: parsed {info['iterations']} iterations, "
                                 f"asked for {iterations}")
            if info["cipher"] != CIPHER_OIDS[cipher]:
                raise SystemExit(f"{name}: cipher OID {info['cipher']} is not {cipher}")
            if prf == "hmacWithSHA1":
                # RFC 8018 makes hmacWithSHA1 the DEFAULT; DER forbids encoding a default.
                if info["prf"] is not None:
                    raise SystemExit(f"{name}: OpenSSL wrote a prf field for hmacWithSHA1")
                finding = "prf field absent (hmacWithSHA1 is the DEFAULT, as DER requires)"
            else:
                if info["prf"] != PRF_OIDS[prf]:
                    raise SystemExit(f"{name}: prf OID {info['prf']} is not {prf}")
                finding = f"prf field present: {prf}"
            print(f"{name}: iterations={info['iterations']} cipher={cipher} {finding}",
                  file=sys.stderr)

            # Every case must decrypt under OpenSSL to the key it came from, including
            # the refused ones: a refusal must be a policy decision, not a broken file.
            with open(enc_path, "wb") as f:
                f.write(encrypted)
            # -topk8 is needed: without it pkcs8 writes the traditional SEC1 form, not PKCS#8.
            decrypted = run("openssl", "pkcs8", "-topk8", "-nocrypt", "-inform", "DER",
                            "-in", enc_path, "-passin", "pass:" + passphrase,
                            "-outform", "DER")
            if decrypted != plaintext:
                raise SystemExit(f"{name}: OpenSSL did not decrypt to the plaintext key")

            cases.append({
                "name": name.encode().hex(),
                "expect": expect.encode().hex(),
                "passphrase": passphrase.encode().hex(),
                "encrypted": encrypted.hex(),
                "plaintext": plaintext.hex(),
                "salt": info["salt"].hex(),
                "iv": info["iv"].hex(),
                "iterations": iterations.to_bytes(4, "big").hex(),
            })
    json.dump({
        "algorithm": "PKCS#8 EncryptedPrivateKeyInfo under PBES2 (RFC 8018), "
                     "for ic_pkix::pbes2",
        "source": "scripts/gen_pkcs8_pbes2_vectors.py with " + version + ". Keys generated "
                  "and discarded: test keys that protect nothing. Interoperability vectors "
                  "from an independent implementation, not values from a standard.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
