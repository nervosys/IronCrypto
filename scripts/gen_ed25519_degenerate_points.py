"""Derive the Ed25519 point encodings a strict verifier refuses, and check
them against libsodium.

    env/bin/python -I scripts/gen_ed25519_degenerate_points.py > testvectors/ed25519-degenerate-points.json

Two kinds, both computed here from the curve equation in RFC 8032 section 5.1
rather than copied from anywhere:

- `small-order`: the eight points whose order divides the cofactor 8, each in
  its canonical encoding. They are found by solving the curve equation at the
  y-coordinates where a point of order 1, 2, 4 or 8 can lie -- 1, -1, 0, and
  the two roots of the order-8 equation -- and each is checked to have order
  dividing 8 by multiplying it out.
- `non-canonical`: encodings whose y-coordinate field is p or more, which
  section 5.1.3 says must fail to decode, and which are curve points once
  reduced. Only y in 0..19 has such an alias below 2^255; every one of those
  on the curve is listed, with both signs where x is not zero.

Each is then given to libsodium's crypto_core_ed25519_is_valid_point, which
refuses small-order and non-canonical encodings, and must be refused there:
a second, independent opinion on every bit of this file.

Needs PyNaCl (libsodium). Nothing else.
"""

import json
import sys

import nacl.bindings as sodium

P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def sqrt(a):
    """A square root mod p, or None."""
    x = pow(a, (P + 3) // 8, P)
    if (x * x - a) % P == 0:
        return x
    x = x * SQRT_M1 % P
    if (x * x - a) % P == 0:
        return x
    return None


def x_for(y):
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    return sqrt(u * pow(v, P - 2, P) % P)


def add(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P
    return (x3, y3)


def times(n, pt):
    acc = (0, 1)
    for _ in range(n):
        acc = add(acc, pt)
    return acc


def encode(x, y_field):
    """The 32-byte encoding with this y field and the sign of x."""
    return (y_field | ((x & 1) << 255)).to_bytes(32, "little")


def main():
    # A point of order dividing 8 has y in {1, -1, 0} (orders 1, 2 and 4),
    # or, for order 8, x^2 = -y^2. Putting that into -x^2 + y^2 = 1 + d*x^2*y^2
    # gives d*y^4 + 2*y^2 - 1 = 0, a quadratic in y^2. Every candidate is kept
    # only if it is on the curve and eight times it is the identity, which is
    # the actual proof; the algebra only says where to look.
    candidates = {1, P - 1, 0}
    for sign in (1, -1):
        disc = sqrt((4 + 4 * D) % P)
        if disc is None:
            continue
        for y2 in ((-2 + sign * disc) * pow(2 * D, P - 2, P) % P,):
            y = sqrt(y2)
            if y is not None:
                candidates.update({y, P - y})
    small = []
    for y in sorted(candidates):
        x = x_for(y)
        if x is None:
            continue
        for xx in sorted({x, (P - x) % P}):
            pt = (xx, y)
            assert (y * y - xx * xx - 1 - D * xx * xx * y * y) % P == 0, "not on the curve"
            if times(8, pt) == (0, 1):
                small.append(encode(xx, y))
    small = sorted(set(small))
    assert len(small) == 8, len(small)

    non_canonical = []
    for y in range(19):
        x = x_for(y)
        if x is None:
            continue
        signs = {0} if x == 0 else {0, 1}
        for s in signs:
            xx = x if (x & 1) == s else (P - x) % P
            non_canonical.append(encode(xx, y + P))
    for e in small + non_canonical:
        assert sodium.crypto_core_ed25519_is_valid_point(e) is False, e.hex()

    cases = [{"kind": "small-order", "point": e.hex()} for e in small] + \
            [{"kind": "non-canonical", "point": e.hex()} for e in non_canonical]
    from importlib.metadata import version
    json.dump({
        "algorithm": "Ed25519 point encodings a strict verifier refuses",
        "source": "Derived by scripts/gen_ed25519_degenerate_points.py from the curve equation "
                  "of RFC 8032 section 5.1, run on 2026-10-12: the 8 small-order points, each "
                  "shown to have order dividing 8, and every encoding whose y field is p or "
                  "more and names a curve point. Each is refused by libsodium's "
                  "crypto_core_ed25519_is_valid_point (PyNaCl " + version("pynacl") + ").",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
