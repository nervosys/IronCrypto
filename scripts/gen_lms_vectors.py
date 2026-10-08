"""Generate testvectors/lms.json: HSS/LMS signatures for verification
(RFC 8554, RFC 9858, NIST SP 800-208).

    python scripts/gen_lms_vectors.py rfc8554.txt rfc9858.txt > testvectors/lms.json

Six cases are published: RFC 8554 appendix F's two, and RFC 9858 appendix A's
four. They are read out of the RFCs' own text, passed as arguments and checked
against the SHA-256 digests below (fetched from
https://www.rfc-editor.org/rfc/rfc8554.txt and rfc9858.txt on 2026-10-08), so
no byte of them was typed by hand.

Those six cover W=8 and W=4, H=5 and H=10, one and two levels. They do not
cover W=1 or W=2 for any hash, W=4 for three of the four hashes, or a
hierarchy that mixes hashes. So this file also holds a verifier and a signer
written from the RFCs' pseudocode, sharing nothing with `ic-lms`, and the
remaining cases are that signer's. It writes nothing until:

1. its verifier accepts all six published cases, and rejects each with one
   byte changed in the message;
2. its signer, given the SEED and I that RFC 9858 publishes for all four of
   its cases, and the randomizer C from each published signature, reproduces
   three of the published public keys and signatures byte for byte, and the
   one-time signature of the fourth, whose tree of 2^20 leaves is too large to
   rebuild here. That pins key generation (RFC 8554 appendix A), the
   Winternitz chains, the checksum and the Merkle tree, for the three hash
   functions RFC 9858 adds.

The generated cases are this implementation's outputs, not published values.
"""

import hashlib
import json
import re
import struct
import sys

RFC_SHA256 = {
    "rfc8554.txt": None,  # filled in from the fetched copies below
    "rfc9858.txt": None,
}
RFC_SHA256_PREFIX = {"rfc8554.txt": "d5bfdbd457dfe7bc", "rfc9858.txt": "87562eee1657467b"}

D_PBLC, D_MESG, D_LEAF, D_INTR = 0x8080, 0x8181, 0x8282, 0x8383


def sha256(n):
    return lambda data: hashlib.sha256(data).digest()[:n]


def shake256(n):
    return lambda data: hashlib.shake_256(data).digest(n)


# typecode: (hash family, H, n, w, p, ls)   RFC 8554 table 1, RFC 9858 table 1
LMOTS = {}
for base, family, make, n in [(0x01, "sha256", sha256, 32), (0x05, "sha256/192", sha256, 24),
                              (0x09, "shake256/256", shake256, 32),
                              (0x0D, "shake256/192", shake256, 24)]:
    table = {32: [(1, 265, 7), (2, 133, 6), (4, 67, 4), (8, 34, 0)],
             24: [(1, 200, 8), (2, 101, 6), (4, 51, 4), (8, 26, 0)]}[n]
    for i, (w, p, ls) in enumerate(table):
        LMOTS[base + i] = (family, make(n), n, w, p, ls)

# typecode: (hash family, H, m, h)          RFC 8554 table 2, RFC 9858 table 2
LMS = {}
for base, family, make, m in [(0x05, "sha256", sha256, 32), (0x0A, "sha256/192", sha256, 24),
                              (0x0F, "shake256/256", shake256, 32),
                              (0x14, "shake256/192", shake256, 24)]:
    for i, h in enumerate([5, 10, 15, 20, 25]):
        LMS[base + i] = (family, make(m), m, h)


def u32(x):
    return struct.pack(">I", x)


def u16(x):
    return struct.pack(">H", x)


def coef(s, i, w):
    return ((1 << w) - 1) & (s[(i * w) // 8] >> (8 - (w * (i % (8 // w)) + w)))


def cksm(s, n, w, ls):
    total = sum((1 << w) - 1 - coef(s, i, w) for i in range(n * 8 // w))
    return u16((total << ls) & 0xFFFF)


class Invalid(Exception):
    pass


def lmots_candidate(sig, message, pubtype, I, q):
    """RFC 8554 algorithm 4b."""
    if len(sig) < 4 or struct.unpack(">I", sig[:4])[0] != pubtype:
        raise Invalid
    _, H, n, w, p, ls = LMOTS[pubtype]
    if len(sig) != 4 + n * (p + 1):
        raise Invalid
    C = sig[4:4 + n]
    y = [sig[4 + n * (i + 1):4 + n * (i + 2)] for i in range(p)]
    Q = H(I + u32(q) + u16(D_MESG) + C + message)
    Qc = Q + cksm(Q, n, w, ls)
    z = b""
    for i in range(p):
        tmp = y[i]
        for j in range(coef(Qc, i, w), (1 << w) - 1):
            tmp = H(I + u32(q) + u16(i) + bytes([j]) + tmp)
        z += tmp
    return H(I + u32(q) + u16(D_PBLC) + z)


def lms_public_parts(pub):
    if len(pub) < 8:
        raise Invalid
    pubtype, otstype = struct.unpack(">II", pub[:8])
    if pubtype not in LMS or otstype not in LMOTS:
        raise Invalid
    m = LMS[pubtype][2]
    if len(pub) != 24 + m:
        raise Invalid
    return pubtype, otstype, pub[8:24], pub[24:]


def lms_signature_len(sig):
    """Length of the LMS signature at the front of `sig`."""
    if len(sig) < 8:
        raise Invalid
    otstype = struct.unpack(">I", sig[4:8])[0]
    if otstype not in LMOTS:
        raise Invalid
    _, _, n, _, p, _ = LMOTS[otstype]
    at = 8 + n * (p + 1)
    if len(sig) < at + 4:
        raise Invalid
    sigtype = struct.unpack(">I", sig[at:at + 4])[0]
    if sigtype not in LMS:
        raise Invalid
    return at + 4 + LMS[sigtype][2] * LMS[sigtype][3]


def lms_verify(message, pub, sig):
    """RFC 8554 algorithms 6 and 6a."""
    pubtype, otstype, I, T1 = lms_public_parts(pub)
    _, H, m, h = LMS[pubtype]
    if len(sig) < 8:
        raise Invalid
    q, otssigtype = struct.unpack(">II", sig[:8])
    if otssigtype != otstype:
        raise Invalid
    _, _, n, _, p, _ = LMOTS[otstype]
    if len(sig) < 12 + n * (p + 1):
        raise Invalid
    ots = sig[4:8 + n * (p + 1)]
    if struct.unpack(">I", sig[8 + n * (p + 1):12 + n * (p + 1)])[0] != pubtype:
        raise Invalid
    if q >= (1 << h) or len(sig) != 12 + n * (p + 1) + m * h:
        raise Invalid
    path = sig[12 + n * (p + 1):]
    Kc = lmots_candidate(ots, message, otstype, I, q)
    node = (1 << h) + q
    tmp = H(I + u32(node) + u16(D_LEAF) + Kc)
    for i in range(h):
        sibling = path[i * m:(i + 1) * m]
        if node & 1:
            tmp = H(I + u32(node // 2) + u16(D_INTR) + sibling + tmp)
        else:
            tmp = H(I + u32(node // 2) + u16(D_INTR) + tmp + sibling)
        node //= 2
    if tmp != T1:
        raise Invalid


def hss_verify(message, pub, sig):
    """RFC 8554 section 6.3."""
    if len(pub) < 4 or len(sig) < 4:
        raise Invalid
    L = struct.unpack(">I", pub[:4])[0]
    nspk = struct.unpack(">I", sig[:4])[0]
    if not 1 <= L <= 8 or nspk + 1 != L:
        raise Invalid
    key, rest = pub[4:], sig[4:]
    for _ in range(nspk):
        n = lms_signature_len(rest)
        this, rest = rest[:n], rest[n:]
        if len(rest) < 8:
            raise Invalid
        pubtype = struct.unpack(">I", rest[:4])[0]
        if pubtype not in LMS:
            raise Invalid
        plen = 24 + LMS[pubtype][2]
        nextkey, rest = rest[:plen], rest[plen:]
        lms_verify(nextkey, key, this)
        key = nextkey
    lms_verify(message, key, rest)


def valid(message, pub, sig):
    try:
        hss_verify(message, pub, sig)
        return True
    except Invalid:
        return False


# --- signing, for the cases no RFC publishes --------------------------------

class LmsKey:
    """An LMS private key by RFC 8554 appendix A's pseudorandom process."""

    def __init__(self, lmstype, otstype, seed, I):
        self.lmstype, self.otstype, self.seed, self.I = lmstype, otstype, seed, I
        _, self.H, self.m, self.h = LMS[lmstype]
        _, _, self.n, self.w, self.p, self.ls = LMOTS[otstype]
        self._tree = None

    @property
    def T(self):
        """The Merkle tree, built when first needed: 2^h one-time public keys."""
        if self._tree is None:
            I, leaves = self.I, 1 << self.h
            T = [None] * (2 * leaves)
            for q in range(leaves):
                T[leaves + q] = self.H(I + u32(leaves + q) + u16(D_LEAF) + self.ots_public(q))
            for r in range(leaves - 1, 0, -1):
                T[r] = self.H(I + u32(r) + u16(D_INTR) + T[2 * r] + T[2 * r + 1])
            self._tree = T
        return self._tree

    def x(self, q, i):
        return self.H(self.I + u32(q) + u16(i) + b"\xff" + self.seed)

    def ots_public(self, q):
        y = b""
        for i in range(self.p):
            tmp = self.x(q, i)
            for j in range((1 << self.w) - 1):
                tmp = self.H(self.I + u32(q) + u16(i) + bytes([j]) + tmp)
            y += tmp
        return self.H(self.I + u32(q) + u16(D_PBLC) + y)

    def public(self):
        return u32(self.lmstype) + u32(self.otstype) + self.I + self.T[1]

    def ots_sign(self, message, q, C):
        """The LM-OTS signature at leaf q, which needs no tree."""
        Q = self.H(self.I + u32(q) + u16(D_MESG) + C + message)
        Qc = Q + cksm(Q, self.n, self.w, self.ls)
        y = b""
        for i in range(self.p):
            tmp = self.x(q, i)
            for j in range(coef(Qc, i, self.w)):
                tmp = self.H(self.I + u32(q) + u16(i) + bytes([j]) + tmp)
            y += tmp
        return u32(self.otstype) + C + y

    def sign(self, message, q, C):
        y = self.ots_sign(message, q, C)[4 + self.n:]
        node = (1 << self.h) + q
        path = b""
        while node > 1:
            path += self.T[node ^ 1]
            node //= 2
        return u32(q) + u32(self.otstype) + C + y + u32(self.lmstype) + path


def hss_sign(keys, qs, cs, message):
    """An HSS signature under a chain of LMS keys, top first."""
    out = u32(len(keys) - 1)
    for i in range(len(keys) - 1):
        out += keys[i].sign(keys[i + 1].public(), qs[i], cs[i]) + keys[i + 1].public()
    return out + keys[-1].sign(message, qs[-1], cs[-1])


# --- the published cases, read from the RFCs --------------------------------

HEX = re.compile(r"^[0-9a-f]+$")


def hex_of(block):
    """Concatenate the hex values in a block of an RFC's test-case listing."""
    out = ""
    for line in block.splitlines():
        if "[Page" in line or line.startswith("RFC ") or "Informational" in line:
            continue
        line = line.split("|")[0].split("#")[0]
        for token in line.split():
            # Any even-length hex token: a value's last line can be two digits.
            # No label in these listings is one (C, I, K and q are odd-length).
            if len(token) % 2 == 0 and HEX.match(token):
                out += token
    return bytes.fromhex(out)


def between(text, start, end):
    a = text.index(start) + len(start)
    return text[a:text.index(end, a)]


def published(rfc8554, rfc9858):
    cases = []
    body = rfc8554[rfc8554.index("Appendix F.  Test Cases", rfc8554.index("Test Case 1 Public Key") - 800):]
    ends = {1: "Test Case 2 Private Key", 2: "Acknowledgements"}
    for n in (1, 2):
        cases.append({
            "source": f"RFC 8554 appendix F, test case {n}",
            "public_key": hex_of(between(body, f"Test Case {n} Public Key", f"Test Case {n} Message")),
            "message": hex_of(between(body, f"Test Case {n} Message", f"Test Case {n} Signature")),
            "signature": hex_of(between(body, f"Test Case {n} Signature", ends[n])),
        })
    appendix = rfc9858[rfc9858.index("\nA.1.  Test Case 1 - SHA-256/192\n"):]
    sections = re.split(r"\nA\.\d\.  ", appendix)[1:]
    for n, section in enumerate(sections, 1):
        blocks = re.split(r"\n +Figure \d+:[^\n]*\n", section)
        private = blocks[0]
        seed = hex_of(between(private, "SEED", "\n   I "))
        ident = hex_of(private[private.index("\n   I "):])
        cases.append({
            "source": f"RFC 9858 appendix A.{n}",
            "public_key": hex_of(blocks[1]),
            "message": hex_of(blocks[2]),
            "signature": hex_of(blocks[3]),
            "seed": seed,
            "I": ident,
        })
    return cases


def check_published(cases):
    for c in cases:
        if not valid(c["message"], c["public_key"], c["signature"]):
            raise SystemExit(f"{c['source']}: the published signature does not verify")
        if valid(c["message"] + b"\x00", c["public_key"], c["signature"]):
            raise SystemExit(f"{c['source']}: a changed message verified")
    # RFC 9858 publishes each case's SEED and I: rebuild the key and the
    # signature from them and the signature's own randomizer.
    rebuilt = 0
    for c in cases:
        if "seed" not in c:
            continue
        pub, sig = c["public_key"], c["signature"]
        if struct.unpack(">I", pub[:4])[0] != 1:
            raise SystemExit("an RFC 9858 case with more than one level")
        lmstype, otstype = struct.unpack(">II", pub[4:12])
        key = LmsKey(lmstype, otstype, c["seed"], c["I"])
        q = struct.unpack(">I", sig[4:8])[0]
        n, p_ = LMOTS[otstype][2], LMOTS[otstype][4]
        C = sig[12:12 + n]
        if key.h <= 10:
            if u32(1) + key.public() != pub:
                raise SystemExit(f"{c['source']}: the public key is not reproduced")
            if u32(0) + key.sign(c["message"], q, C) != sig:
                raise SystemExit(f"{c['source']}: the signature is not reproduced")
        else:
            # A tree of 2^20 leaves is out of reach here. Its one-time
            # signature is not: rebuild that from the SEED, and with it this
            # case's Winternitz width. The verifier above already ties the
            # path in the signature to the public key.
            if key.ots_sign(c["message"], q, C) != sig[8:12 + n * (p_ + 1)]:
                raise SystemExit(f"{c['source']}: the one-time signature is not reproduced")
        rebuilt += 1
    if rebuilt != 4:
        raise SystemExit(f"only {rebuilt} RFC 9858 cases rebuilt")


def generated():
    """The parameter sets no RFC publishes a case for."""
    def bytes_of(label, n):
        return hashlib.shake_256(b"IronCrypto lms vectors " + label.encode()).digest(n)

    families = [("sha256", 0x01, 0x05, 32), ("sha256/192", 0x05, 0x0A, 24),
                ("shake256/256", 0x09, 0x0F, 32), ("shake256/192", 0x0D, 0x14, 24)]
    cases = []
    message = b"IronCrypto HSS/LMS verification vector\n"
    # Every Winternitz width for every hash, on the smallest tree, at a leaf
    # that is neither first nor last.
    for name, ots_base, lms_base, n in families:
        for wi, w in enumerate((1, 2, 4, 8)):
            label = f"{name} w{w} h5"
            key = LmsKey(lms_base, ots_base + wi, bytes_of(label + " seed", n), bytes_of(label + " I", 16))
            q = 19
            sig = u32(0) + key.sign(message, q, bytes_of(label + " C", n))
            cases.append({"source": f"generated: LMS {name}, W={w}, H=5, q={q}",
                          "public_key": u32(1) + key.public(), "message": message, "signature": sig})
    # The first and last leaf of a tree, where the authentication path is all
    # right siblings and all left siblings.
    key = LmsKey(0x05, 0x04, bytes_of("edge seed", 32), bytes_of("edge I", 16))
    for q in (0, 31):
        cases.append({"source": f"generated: LMS sha256, W=8, H=5, q={q}",
                      "public_key": u32(1) + key.public(), "message": message,
                      "signature": u32(0) + key.sign(message, q, bytes_of(f"edge C {q}", 32))})
    # H=10, which RFC 8554 covers only as the top of a hierarchy.
    key = LmsKey(0x0B, 0x07, bytes_of("h10 seed", 24), bytes_of("h10 I", 16))
    cases.append({"source": "generated: LMS sha256/192, W=4, H=10, q=777",
                  "public_key": u32(1) + key.public(), "message": message,
                  "signature": u32(0) + key.sign(message, 777, bytes_of("h10 C", 24))})
    # A three-level hierarchy whose levels use three different hashes.
    levels = [LmsKey(0x05, 0x04, bytes_of("l0 seed", 32), bytes_of("l0 I", 16)),
              LmsKey(0x14, 0x10, bytes_of("l1 seed", 24), bytes_of("l1 I", 16)),
              LmsKey(0x0F, 0x0B, bytes_of("l2 seed", 32), bytes_of("l2 I", 16))]
    sig = hss_sign(levels, [3, 30, 11],
                   [bytes_of("l0 C", 32), bytes_of("l1 C", 24), bytes_of("l2 C", 32)], message)
    cases.append({"source": "generated: HSS, 3 levels: sha256 W=8, shake256/192 W=8, shake256/256 W=4",
                  "public_key": u32(3) + levels[0].public(), "message": message, "signature": sig})
    # The empty message.
    key = LmsKey(0x0A, 0x08, bytes_of("empty seed", 24), bytes_of("empty I", 16))
    cases.append({"source": "generated: LMS sha256/192, W=8, H=5, empty message",
                  "public_key": u32(1) + key.public(), "message": b"",
                  "signature": u32(0) + key.sign(b"", 1, bytes_of("empty C", 24))})
    for c in cases:
        if not valid(c["message"], c["public_key"], c["signature"]):
            raise SystemExit(f"{c['source']}: does not verify")
    return cases


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    texts = []
    for path, name in zip(sys.argv[1:], ("rfc8554.txt", "rfc9858.txt")):
        data = open(path, "rb").read()
        if not hashlib.sha256(data).hexdigest().startswith(RFC_SHA256_PREFIX[name]):
            raise SystemExit(f"{path} is not the pinned copy of {name}")
        texts.append(data.decode("utf-8", "replace").replace("\r\n", "\n"))
    cases = published(*texts)
    if len(cases) != 6:
        raise SystemExit(f"{len(cases)} published cases found, expected 6")
    check_published(cases)
    cases += generated()
    json.dump({
        "algorithm": "HSS/LMS signature verification (RFC 8554, RFC 9858, SP 800-208)",
        "source": "scripts/gen_lms_vectors.py. The first six cases are RFC 8554 appendix F's two and "
                  "RFC 9858 appendix A's four, read from the RFCs' text. The rest are from a signer "
                  "written from the RFCs' pseudocode, which first reproduced RFC 9858's public keys and "
                  "signatures from their published SEED and I (the one-time signature only, for its "
                  "H=20 case); they are that implementation's "
                  "outputs, not published values.",
        "cases": [{"source": c["source"], "public_key": c["public_key"].hex(),
                   "message": c["message"].hex(), "signature": c["signature"].hex()} for c in cases],
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
