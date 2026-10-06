"""Generate testvectors/shamir-gf256.json: Shamir shares over GF(2^8).

    python scripts/gen_shamir_vectors.py > testvectors/shamir-gf256.json

An implementation written from Shamir's construction ("How to Share a Secret",
1979) and sharing nothing with `ic_cipher::shamir`: multiplication is the
textbook shift-and-add with branches, reduced by x^8 + x^4 + x^3 + x + 1, and
inversion is found by searching all 255 candidates rather than by
exponentiation. Each byte of the secret is the constant term of its own
polynomial of degree threshold - 1, and share i is every polynomial evaluated
at x = i (1-based).

The coefficients come from a deterministic stream, so the shares are fixed and
reproducible: state s, and each byte is s = 29 * s + 7 mod 256, drawn
threshold - 1 at a time per secret byte, lowest-degree coefficient first. A
real split draws them from a random source; this stream exists only so two
implementations can be compared. The generator also recombines every case
from several subsets of shares, so a wrong evaluation would not get out.
"""

import itertools
import json
import sys


def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return p


def gf_inv(a):
    for c in range(1, 256):
        if gf_mul(a, c) == 1:
            return c
    raise ValueError("zero has no inverse")


class Counter:
    def __init__(self, seed):
        self.s = seed

    def take(self, n):
        out = []
        for _ in range(n):
            self.s = (self.s * 29 + 7) & 0xFF
            out.append(self.s)
        return out


def split(secret, k, n, seed):
    rng = Counter(seed)
    shares = [[0] * len(secret) for _ in range(n)]
    for b, s in enumerate(secret):
        coeffs = [s] + rng.take(k - 1)
        for i in range(n):
            x, y, power = i + 1, 0, 1
            for c in coeffs:
                y ^= gf_mul(c, power)
                power = gf_mul(power, x)
            shares[i][b] = y
    return shares


def combine(points):
    length = len(points[0][1])
    out = [0] * length
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = gf_mul(num, xj)
                den = gf_mul(den, xj ^ xi)
        li = gf_mul(num, gf_inv(den))
        for b in range(length):
            out[b] ^= gf_mul(yi[b], li)
    return out


CASES = [
    (bytes(range(32)), 3, 5, 0x11),
    (b"\x00" * 16, 2, 3, 0x42),
    (b"\xff", 2, 2, 0x07),
    (bytes(range(200, 216)), 5, 9, 0xA5),
    (b"IronCrypto", 255, 255, 0x3C),
]


def main():
    cases = []
    for secret, k, n, seed in CASES:
        shares = split(list(secret), k, n, seed)
        for subset in itertools.islice(itertools.combinations(range(n), k), 20):
            points = [(i + 1, shares[i]) for i in subset]
            assert combine(points) == list(secret), (k, n, subset)
        cases.append({
            "secret": secret.hex(),
            "threshold": str(k),
            "share_count": str(n),
            "rng_seed": f"{seed:02x}",
            "shares": "".join(bytes(s).hex() for s in shares),
        })
    json.dump({
        "algorithm": "shamir secret sharing over GF(2^8)",
        "source": "scripts/gen_shamir_vectors.py, an implementation written from Shamir 1979 "
                  "with its own GF(2^8) arithmetic (branching multiply, inverse by search), "
                  "sharing nothing with ic_cipher. Coefficients come from a fixed stream "
                  "(s = 29s + 7 mod 256, threshold - 1 per secret byte, lowest degree first); "
                  "share i is at x = i. Each case was recombined from up to 20 subsets of "
                  "threshold shares before being written. Not published values.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
