"""Transcribe the hash-to-curve and OPRF test vectors for P-256 from the RFCs.

    python -I scripts/gen_oprf_vectors.py <dir> testvectors

<dir> holds rfc9380.txt and rfc9497.txt as published at
https://www.rfc-editor.org/rfc/rfcNNNN.txt, each checked against the SHA-256
below. Two files are written:

- rfc9380-p256.json: RFC 9380 appendix J.1.1, P256_XMD:SHA-256_SSWU_RO_ --
  for each message, the two field elements u[0] and u[1], the two mapped
  points Q0 and Q1, and the final point P -- and appendix K.1,
  expand_message_xmd with SHA-256, every message and length.
- rfc9497-p256.json: RFC 9497 appendix A.3, the P256-SHA256 suite in all
  three modes, OPRF, VOPRF and POPRF, with the derived keys and every batch.

The values are copied from the text, joined across the RFC's line wraps;
nothing here computes one. Each section is found by its heading and parsed
as `name = value` lines, so a change to the RFC's layout fails here rather
than producing a vector.
"""

import hashlib
import json
import os
import re
import sys

PINNED = {
    "rfc9380.txt": "a2e6ab02b2117d6f52ac293020857752972b2e23ae005c33f612e40436ff4b6d",
    "rfc9497.txt": "95160517617374655fe23af2c6cec311eae326deb7689239f97641fd5a560432",
}
KEY = re.compile(r"^\s+([A-Za-z][\w.\[\]]*)\s+=\s?(.*)$")


def load(directory, name):
    raw = open(os.path.join(directory, name), "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != PINNED[name]:
        raise SystemExit(f"{name}: SHA-256 {digest} is not the pinned file")
    # The RFC Editor's text files begin with a UTF-8 byte-order mark.
    return raw.decode("utf-8-sig").split("\n")


def section(lines, start, end):
    """The lines from the heading `start` up to the heading `end`."""
    a = next(i for i, l in enumerate(lines) if l.startswith(start))
    b = next(i for i, l in enumerate(lines) if i > a and l.startswith(end))
    return lines[a + 1:b]


def pairs(lines):
    """`name = value` pairs in order, with wrapped values joined."""
    out = []
    for line in lines:
        if not line.strip() or line.startswith(("RFC ", "Faz-Hernandez", "Davidson")) \
                or "\f" in line or re.match(r"^[A-Z]\.\d", line):
            continue
        m = KEY.match(line)
        if m:
            out.append([m.group(1), m.group(2).strip()])
        elif out:
            out[-1][1] += line.strip()
        else:
            continue
    return out


def h2c(lines):
    cases = []
    current = None
    for name, value in pairs(section(lines, "J.1.1.", "J.1.2.")):
        if name in ("suite", "dst"):
            continue
        if name == "msg":
            current = {"kind": "h2c", "msg": value.encode().hex()}
            cases.append(current)
        else:
            current[name.replace("[", "").replace("]", "").replace(".", "_")] = value
    assert len(cases) == 5, len(cases)
    xmd = []
    current = None
    for name, value in pairs(section(lines, "K.1.", "K.2.")):
        if name in ("name", "DST", "hash", "k"):
            continue
        if name == "msg":
            current = {"kind": "xmd", "msg": value.encode().hex()}
            xmd.append(current)
        elif name == "len_in_bytes":
            current["len"] = str(int(value, 16))
        elif name == "uniform_bytes":
            current["uniform_bytes"] = value
    assert len(xmd) == 10, len(xmd)
    return cases + xmd


def oprf(lines):
    a = next(i for i, l in enumerate(lines) if l.startswith("A.3.  P256-SHA256"))
    b = next(i for i, l in enumerate(lines) if i > a and re.match(r"^(A\.4\.|Acknowledgements|Authors)", l))
    body = lines[a + 1:b]
    cases = []
    mode = None
    keys = {}
    current = None
    for line in body:
        m = re.match(r"^A\.3\.(\d)\.\s+(OPRF|VOPRF|POPRF) Mode", line)
        if m:
            mode, keys, current = m.group(2), {}, None
            continue
        if re.match(r"^A\.3\.\d\.\d\.\s+Test Vector", line):
            current = {"mode": mode, **keys}
            cases.append(current)
            continue
        if not line.strip() or line.startswith(("RFC ", "Davidson")) or "" in line:
            continue
        target = current if current is not None else keys
        k = KEY.match(line)
        if k:
            target[k.group(1)] = k.group(2).strip()
        elif target:
            last = list(target)[-1]
            target[last] += line.strip()
    assert [c["mode"] for c in cases] == ["OPRF"] * 2 + ["VOPRF"] * 3 + ["POPRF"] * 3, \
        [c["mode"] for c in cases]
    return cases


def main():
    directory, out = sys.argv[1], sys.argv[2]
    l9380, l9497 = load(directory, "rfc9380.txt"), load(directory, "rfc9497.txt")
    files = [
        ("rfc9380-p256", "hash_to_curve P256_XMD:SHA-256_SSWU_RO_ and expand_message_xmd SHA-256",
         "RFC 9380 appendices J.1.1 and K.1, transcribed by scripts/gen_oprf_vectors.py from "
         "rfc9380.txt (SHA-256 " + PINNED["rfc9380.txt"] + "). `msg` is hex. The J.1.1 DST is "
         "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_ and the K.1 DST "
         "QUUX-V01-CS02-with-expander-SHA256-128.", h2c(l9380)),
        ("rfc9497-p256", "OPRF, VOPRF and POPRF with P256-SHA256",
         "RFC 9497 appendix A.3, transcribed by scripts/gen_oprf_vectors.py from rfc9497.txt "
         "(SHA-256 " + PINNED["rfc9497.txt"] + "). Batched values are comma-separated, as "
         "the RFC prints them.", oprf(l9497)),
    ]
    for name, algorithm, source, cases in files:
        path = os.path.join(out, name + ".json")
        with open(path, "w", newline="\n") as f:
            json.dump({"algorithm": algorithm, "source": source, "cases": cases}, f, indent=1)
            f.write("\n")
        print(f"{path}: {len(cases)} cases", file=sys.stderr)


if __name__ == "__main__":
    main()
