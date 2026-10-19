#!/usr/bin/env python3
"""Check the twisted-key GHASH reduction against SP 800-38D's own multiply.

The x86-64 AES-GCM kernels (`ic-cipher/src/gcm_x86_asm.rs`, and the 512-bit
loops in `gcm_x86_asm.rs`) multiply each byte-reversed block by a power of H
"twisted" by x^-1 (`gcm_x86::twist`), and reduce the 256-bit carry-less sum
with two more carry-less multiplies by 0xc2000000_00000000. This models that
arithmetic on Python integers -- the twist, the Karatsuba product, the
two-fold reduction, and an eight-block aggregate -- and compares it with
SP 800-38D section 6.3, Algorithm 1, the bit-serial multiply, written here
from the standard and sharing nothing with the Rust code.

A block loaded into a register and byte-reversed is its big-endian integer,
which is the representation Algorithm 1 uses below (bit 0 of the block is
the integer's most significant bit). Run: python scripts/check_gcm_twist.py
"""
import random

M64 = (1 << 64) - 1
M128 = (1 << 128) - 1
R = 0xE1 << 120  # SP 800-38D: R = 11100001 || 0^120
# x^-1 in the field, as the kernels hold it: 0xc2000000_00000000_00000000_00000001.
X_INV = (0xC2 << 120) | 1


def gf_mul_spec(x, y):
    """SP 800-38D, section 6.3, Algorithm 1."""
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R if v & 1 else v >> 1
    return z


def clmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        b >>= 1
    return r


def pclmulqdq(a, b, imm):
    """PCLMULQDQ: imm bit 0 picks a's 64-bit half, bit 4 b's."""
    x = (a >> 64) & M64 if imm & 0x01 else a & M64
    y = (b >> 64) & M64 if imm & 0x10 else b & M64
    return clmul(x, y)


def swap_halves(v):
    return ((v & M64) << 64) | (v >> 64)


def twist(h):
    """`gcm_x86::twist`: shift left one bit; if bit 127 fell out, XOR x^-1."""
    return ((h << 1) & M128) ^ (X_INV if h >> 127 else 0)


def karatsuba(a, b):
    """lo, Karatsuba middle, hi: the three multiplies each kernel makes."""
    lo = pclmulqdq(a, b, 0x00)
    hi = pclmulqdq(a, b, 0x11)
    k = clmul((a & M64) ^ (a >> 64), (b & M64) ^ (b >> 64))
    return lo, k, hi


def reduce_twisted(lo, k, hi):
    """`x8_reduce!`: recover the middle term, fold it in, two folds of lo."""
    mid = k ^ lo ^ hi
    lo ^= (mid << 64) & M128
    hi ^= mid >> 64
    t = pclmulqdq(lo, X_INV, 0x10)
    lo = swap_halves(lo) ^ t
    t = pclmulqdq(lo, X_INV, 0x10)
    return swap_halves(lo) ^ hi ^ t


def main():
    rng = random.Random(0x6763_6d74)
    edge = [0, 1, M128, 1 << 127, (1 << 127) | 1, R, X_INV]
    pairs = [(a, b) for a in edge for b in edge]
    pairs += [(rng.getrandbits(128), rng.getrandbits(128)) for _ in range(5000)]
    for x, h in pairs:
        want = gf_mul_spec(x, h)
        got = reduce_twisted(*karatsuba(x, twist(h)))
        assert got == want, (hex(x), hex(h), hex(got), hex(want))
    # An aggregate: eight products summed unreduced, reduced once, with Y
    # folded into the first block -- a group of the eight-block loop.
    for _ in range(1000):
        y = rng.getrandbits(128)
        h = rng.getrandbits(128)
        powers = [h]
        for _ in range(7):
            powers.append(gf_mul_spec(powers[-1], h))
        blocks = [rng.getrandbits(128) for _ in range(8)]
        want = y
        for b in blocks:
            want = gf_mul_spec(want ^ b, h)
        lo = k = hi = 0
        for j, b in enumerate(blocks):
            a = b ^ y if j == 0 else b
            l, m, u = karatsuba(a, twist(powers[7 - j]))
            lo ^= l
            k ^= m
            hi ^= u
        assert reduce_twisted(lo, k, hi) == want
    print(f"twisted reduction agrees with SP 800-38D Algorithm 1: "
          f"{len(pairs)} products, 1000 eight-block groups")


if __name__ == "__main__":
    main()
