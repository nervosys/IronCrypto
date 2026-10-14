#!/usr/bin/env python3
"""Generate crates/ic-ec/src/nist/ifma_kernels.rs: P-256 and P-384 point
formulas on AVX-512 IFMA, four field elements to a vector, as Rust `asm!`.

    python scripts/gen_nist_ifma.py crates/ic-ec/src/nist/ifma_kernels.rs
    python scripts/gen_nist_ifma.py --check      # simulate only, write nothing

# What this does

A point formula is written below (`KERNELS`) as rounds of lane-parallel field
operations: each round multiplies up to four independent pairs, one per 64-bit
lane of a `ymm` register, and the additions, subtractions and small multiples
between rounds are lane-wise linear combinations. A field element is limb `k`
of the four lanes in one register: five limbs of 52 bits on P-256, eight of
48 on P-384. `VPMADD52LUQ` and `VPMADD52HUQ` multiply limbs below 2^52. The
four-lane formulas (`k_madd4`, `k_to_fp4`) instead hold four points a
coordinate to a vector and run the same formula in every lane.

The generator

1. builds each formula as a graph of single-register instructions, choosing
   for every round which lane each product goes to, and which factor goes on
   which side, so that its operands are cheapest to gather from where their
   sources already are;
2. bounds every value, lane by lane and limb by limb, by interval arithmetic
   from the bounds its inputs are promised, and every value as a whole where
   P-256's Montgomery reduction needs it, and refuses to emit a kernel in
   which a multiplier input could reach 2^52, a value could leave the signed
   64-bit range, or an output could leave the bounds the next kernel is
   promised (`Field.contract`);
3. orders the instructions -- by critical path for the kernels a scalar
   multiplication chains, in the order they were built for the four-lane
   ones and P-384's (`BUILD_ORDER` says why) -- and assigns `ymm0`-`ymm15`,
   spilling to a scratch buffer the value used furthest ahead;
4. runs the emitted instruction list in a simulator on random and extreme
   inputs and compares every output with the formula evaluated on integers
   modulo p, and every output's limbs and value with the bounds claimed for
   them. Nothing is written unless every kernel agrees.

`--check` stops after the simulation; `--mix` adds each kernel's instruction
mix; `estimate` prints a critical path and a port-limited cycle count, an
idealised out-of-order model that guided the choices below, not a
measurement.

# The fields

P-256 is Montgomery arithmetic in radix 2^52 with R = 2^260. The high half of
a limb product lands exactly on the next column, and since p = -1 mod 2^96
the quotient digit of a step is the column's low 52 bits, and
m (p + 1) = m 2^96 + m 2^192 + m (2^32 - 1) 2^224 is, relative to the step's
column, m 2^44 one column up, m 2^36 three up and m (2^32 - 1) 2^16 four up:
each split by a multiply-add by a constant, so a step is five multiply-adds
and three shifts. Radix 2^52 has no spare bits, so every value is carried
through its five limbs before it is multiplied; a product's columns are left
unnormalised until whatever consumes them is, once. Values stay below 2^258,
far enough below R that a product needs no final subtraction.

P-384 is plain arithmetic in radix 2^48: 384 = 8 * 48, and
2^384 = 2^128 + 2^96 - 2^32 + 1 (mod p) folds each of the eight high columns
of a product onto four low ones; the three columns that fold leaves above
2^384 are folded again. The four spare bits per limb let every carry be one
parallel pass: each limb keeps its low 48 bits and gains the signed carry from
below (`VPSRAQ`), the carry out of the top folds back by the same identity,
and a multiple of p chosen for the purpose (the bias) keeps every limb
non-negative and below 2^50.

# What was measured and not kept

All on a Ryzen 9 9900X (Zen 5), against the MULX/ADX formulas in the same
process:

- P-256 in radix 2^48 (six limbs, Montgomery with R = 2^288, every carry one
  parallel pass): 1459 instructions and a 275-cycle critical path for a
  doubling, against 902 and 214 in radix 2^52; slower.
- A look-ahead doubling, each doubling's last product sharing a round with
  the next one's first: three rounds a doubling instead of four, but as many
  instructions, and five of them fused into one kernel came to 27 KB, more
  than the level-one instruction cache holds beside the addition; no faster.
  Two doublings fused into one block measured the same as two calls.
- Fewer, longer accumulator chains (high and low halves together, the
  reduction's terms on the column's own chain): fewer instructions, longer
  critical paths, and slower chained doublings.

# Constant time

Every kernel is one fixed sequence of instructions: no branch, and every
address is a base register plus a constant. Selections between results are
`VPBLENDVB` under masks the caller computes without branching.
"""

import random
import re
import sys
import textwrap

M64 = (1 << 64) - 1
M52 = (1 << 52) - 1
M48 = (1 << 48) - 1
M16 = (1 << 16) - 1
NL = 4  # lanes per vector
NREGS = 16
I64 = (-(1 << 63), (1 << 63) - 1)


def s64(x):
    x &= M64
    return x - (1 << 64) if x >> 63 else x


# ---------------------------------------------------------------------------
# The instruction graph
# ---------------------------------------------------------------------------

# Latency, and the issue class the scheduler limits per cycle; roughly Zen 4
# and Zen 5. The scheduler needs only a sensible order: the out-of-order core
# does the rest.
LAT = {
    "lo": 4, "hi": 4, "mullo": 3,
    "add": 1, "sub": 1, "and": 1, "srl": 1, "sll": 1, "sra": 1,
    "perm": 3, "blend": 1, "blendv": 1,
}
CLASS = {
    "lo": "mul", "hi": "mul", "mullo": "mul",
    "add": "alu", "sub": "alu", "and": "alu", "blend": "alu", "blendv": "alu",
    "srl": "shift", "sll": "shift", "sra": "shift", "perm": "perm",
}
PORTS = {"mul": 2, "alu": 4, "shift": 2, "perm": 2}
# Values that live in memory and are only ever operands, or a register zeroed
# where it is needed: never scheduled as instructions themselves.
MEMORY_OPS = ("load", "bcast", "cvec", "zero", "maskb")


class Node:
    __slots__ = ("id", "op", "args", "imm", "base", "off", "bounds", "users", "height", "dead", "tag")

    def __init__(self, nid, op, args, imm=None, base=None, off=None, bounds=None):
        self.id, self.op, self.args, self.imm = nid, op, list(args), imm
        self.base, self.off = base, off
        self.bounds = bounds
        self.users = []
        self.height = 0
        self.dead = False

    def __repr__(self):
        return f"n{self.id}:{self.op}"


def lanewise(f, *bs):
    out = []
    for l in range(NL):
        parts = [b[l] for b in bs]
        out.append(None if any(p is None for p in parts) else f(*parts))
    return out


def fits(iv, what):
    lo, hi = iv
    if not (I64[0] <= lo <= hi <= I64[1]):
        raise AssertionError(f"{what}: {iv} leaves the signed 64-bit range")
    return iv


class Graph:
    """Instructions on single `ymm` values, with interval bounds per lane."""

    def __init__(self, name):
        self.name = name
        self.nodes = []
        self.outputs = []  # (base, off, node)
        self._mem = {}
        self._const = {}

    tag = "other"

    def _new(self, op, args, **kw):
        n = Node(len(self.nodes), op, args, **kw)
        n.tag = self.tag
        self.nodes.append(n)
        return n

    def load(self, base, off, bounds):
        key = (base, off)
        if key not in self._mem:
            self._mem[key] = self._new("load", [], base=base, off=off, bounds=bounds)
        return self._mem[key]

    def maskb(self, off):
        """A 64-bit mask from the mask buffer, broadcast: all ones or zero."""
        key = ("m", off, "b")
        if key not in self._mem:
            self._mem[key] = self._new("maskb", [], base="m", off=off, bounds=[(-1, 0)] * NL)
        return self._mem[key]

    def zero(self):
        return self._new("zero", [], bounds=[(0, 0)] * NL)

    def const_b(self, v):
        """A 64-bit constant broadcast to every lane, read from the constant
        table as an embedded-broadcast memory operand."""
        v = s64(v)
        key = ("b", v)
        if key not in self._const:
            self._const[key] = self._new("bcast", [], imm=v, bounds=[(v, v)] * NL)
        return self._const[key]

    def const_v(self, vec):
        """A 32-byte constant vector from the constant table."""
        vec = tuple(s64(x) for x in vec)
        key = ("v", vec)
        if key not in self._const:
            self._const[key] = self._new("cvec", [], imm=vec, bounds=[(x, x) for x in vec])
        return self._const[key]

    @staticmethod
    def _ifma_in(v, low52):
        """A multiplier operand's bounds. The instruction reads the low 52
        bits; an operand above that is a bug unless `low52` says the low 52
        bits are what is meant (a Montgomery quotient digit)."""
        if low52:
            if v[0] < 0:
                raise AssertionError(f"multiplier input {v} negative")
            return (0, min(v[1], M52))
        if not (0 <= v[0] and v[1] <= M52):
            raise AssertionError(f"multiplier input {v} not below 2^52")
        return v

    def lo(self, acc, a, b, low52=False):
        def f(c, x, y):
            x = self._ifma_in(x, low52)
            y = self._ifma_in(y, False)
            return fits((c[0], c[1] + min(M52, x[1] * y[1])), "lo")
        return self._new("lo", [acc, a, b], bounds=lanewise(f, acc.bounds, a.bounds, b.bounds))

    def hi(self, acc, a, b, low52=False):
        def f(c, x, y):
            x = self._ifma_in(x, low52)
            y = self._ifma_in(y, False)
            return fits((c[0], c[1] + ((x[1] * y[1]) >> 52)), "hi")
        return self._new("hi", [acc, a, b], bounds=lanewise(f, acc.bounds, a.bounds, b.bounds))

    def add(self, a, b):
        return self._new("add", [a, b], bounds=lanewise(
            lambda x, y: fits((x[0] + y[0], x[1] + y[1]), "add"), a.bounds, b.bounds))

    def sub(self, a, b):
        return self._new("sub", [a, b], bounds=lanewise(
            lambda x, y: fits((x[0] - y[1], x[1] - y[0]), "sub"), a.bounds, b.bounds))

    def mask(self, a, m):
        """`a & m`, for `m = 2^k - 1`."""
        assert m & (m + 1) == 0 and m > 0
        def f(x):
            return x if 0 <= x[0] and x[1] <= m else (0, m)
        return self._new("and", [a, self.const_b(m)], bounds=lanewise(f, a.bounds))

    def srl(self, a, k):
        def f(x):
            if x[0] < 0:
                raise AssertionError(f"logical shift of {x}")
            return (x[0] >> k, x[1] >> k)
        return self._new("srl", [a], imm=k, bounds=lanewise(f, a.bounds))

    def sra(self, a, k):
        return self._new("sra", [a], imm=k, bounds=lanewise(lambda x: (x[0] >> k, x[1] >> k), a.bounds))

    def sll(self, a, k):
        return self._new("sll", [a], imm=k, bounds=lanewise(
            lambda x: fits((x[0] << k, x[1] << k), "sll"), a.bounds))

    def mullo(self, a, coefs):
        """`a` times a constant per lane (signed)."""
        c = self.const_v(coefs)
        def g(l):
            x = a.bounds[l]
            if x is None:
                return None
            ps = (x[0] * coefs[l], x[1] * coefs[l])
            return fits((min(ps), max(ps)), "mullo")
        return self._new("mullo", [a, c], bounds=[g(l) for l in range(NL)])

    def perm(self, a, sel):
        """Lane `l` of the result is lane `sel[l]` of `a`."""
        imm = sel[0] | (sel[1] << 2) | (sel[2] << 4) | (sel[3] << 6)
        return self._new("perm", [a], imm=imm, bounds=[a.bounds[sel[l]] for l in range(NL)])

    def blend(self, a, b, lanes):
        """Lane `l` from `b` where bit `l` of `lanes` is set, else from `a`."""
        imm = 0
        for l in range(NL):
            if lanes >> l & 1:
                imm |= 3 << (2 * l)
        return self._new("blend", [a, b], imm=imm,
                         bounds=[b.bounds[l] if lanes >> l & 1 else a.bounds[l] for l in range(NL)])

    def blendv(self, a, b, m):
        """`b` in lanes where the mask is all ones, `a` where it is zero."""
        def u(x, y):
            return (min(x[0], y[0]), max(x[1], y[1]))
        return self._new("blendv", [a, b, m], bounds=lanewise(u, a.bounds, b.bounds))

    def output(self, base, off, node):
        self.outputs.append((base, off, node))


# ---------------------------------------------------------------------------
# The fields
# ---------------------------------------------------------------------------


def limbs_of(x, n, w=48):
    out = []
    for _ in range(n - 1):
        out.append(x & ((1 << w) - 1))
        x >>= w
    out.append(x)
    return out


def value_of(limbs, w=48):
    return sum(int(v) << (w * i) for i, v in enumerate(limbs))


def collect(g, items):
    """Sum `(node, sign)` items: the positive ones as a balanced tree, then
    the negative ones subtracted."""
    pos = [e for e, s in items if s > 0]
    neg = [e for e, s in items if s < 0]
    if not pos:
        pos = [g.zero()]
    while len(pos) > 1:
        nxt = [g.add(pos[i], pos[i + 1]) for i in range(0, len(pos) - 1, 2)]
        if len(pos) % 2:
            nxt.append(pos[-1])
        pos = nxt
    x = pos[0]
    for e in neg:
        x = g.sub(x, e)
    return x


SPLIT = 4


def product_columns(g, a, b, n, w=48):
    """Columns of `a * b`: column k weighs B^k = 2^(w k). The low half of a
    52-bit product lands at its column; the high half weighs 2^52 above it,
    2^(52 - w) B^(k+1), so in radix 2^48 its accumulator is shifted by four
    before joining. A chain of more than `SPLIT` multiply-adds into one
    accumulator is split in two, each four cycles a step shorter."""
    z = g.zero()
    cols = []
    for k in range(2 * n):
        lo_terms = [(i, k - i) for i in range(n) if 0 <= k - i < n]
        hi_terms = [(i, k - 1 - i) for i in range(n) if 0 <= k - 1 - i < n]
        parts = []
        for terms, op, high in ((lo_terms, g.lo, False), (hi_terms, g.hi, True)):
            if not terms:
                continue
            chains = [terms] if len(terms) <= SPLIT else [terms[0::2], terms[1::2]]
            accs = []
            for chain in chains:
                acc = z
                for (i, j) in chain:
                    acc = op(acc, a[i], b[j])
                accs.append(acc)
            x = accs[0] if len(accs) == 1 else g.add(accs[0], accs[1])
            if high and w != 52:
                x = g.sll(x, 52 - w)
            parts.append(x)
        cols.append(parts[0] if len(parts) == 1 else g.add(parts[0], parts[1]))
    return cols


class Field:
    name = None
    p = None
    n = None
    R = None
    w = 48
    lazy = False

    def mul_value_bound(self, a, b):
        return None

    def mul_ok(self, limbs, used):
        """Whether these limbs may go to a multiplier as they are."""
        for node in limbs:
            for t, b in enumerate(node.bounds):
                if b is None or not used[t]:
                    continue
                if b[0] < 0 or b[1] > M52:
                    return False
        return True

    def bias(self, k, wmin, wtop):
        """`k p` as limbs, limbs 0..n-2 at least `wmin` and the top one at
        least `wtop`."""
        rest = k * self.p - sum(wmin << (48 * i) for i in range(self.n - 1)) - (wtop << (48 * (self.n - 1)))
        if rest < 0:
            return None
        d = limbs_of(rest, self.n)
        if any(x > M48 for x in d[:-1]):
            return None
        d = [x + wmin for x in d[:-1]] + [d[-1] + wtop]
        assert value_of(d) == k * self.p
        return d

    def pass_(self, g, v, used=(True,) * NL, vb=None):
        """Bring the signed limbs `v` into the contract: see the module
        notes. Tries biases from small to large and keeps the first whose
        result the interval arithmetic shows to be within the contract in
        the lanes `used`."""
        last = None
        for k in (1, 2, 4, 8, 16, 32, 64):
            for wmin in (1 << 46, 1 << 47, 1 << 48):
                for wtop in (0, 1 << 15, 1 << 16, 1 << 17):
                    bias = self.bias(k, wmin, wtop)
                    if bias is None:
                        continue
                    try:
                        out = self.carry(g, v, bias)
                    except AssertionError as e:
                        last = e
                        continue
                    if self.within(out, used):
                        return out
        raise AssertionError(f"{self.name}: no bias brings {[x.bounds for x in v]} into the contract ({last})")

    def within(self, vec, used=(True,) * NL):
        for k, node in enumerate(vec):
            for l, b in enumerate(node.bounds):
                if b is None or not used[l]:
                    continue
                if not (self.contract[k][0] <= b[0] and b[1] <= self.contract[k][1]):
                    return False
        return True


class P256(Field):
    """P-256 in radix 2^52, five limbs, Montgomery with R = 2^260.

    The high half of a limb product lands exactly on the next column, and
    every term of a Montgomery step is a multiple-add by a constant below
    2^52: m (p + 1) = m 2^96 + m 2^192 + m (2^32 - 1) 2^224, which relative to
    the step's column is m 2^44 one column up, m 2^36 three up and
    m (2^32 - 1) 2^16 four up, each split by `VPMADD52LUQ`/`VPMADD52HUQ`. What
    radix 2^52 gives up is headroom: a limb must be below 2^52 exactly, so
    every result is normalised by a carry chain through the five limbs."""

    name = "p256"
    p = 2**256 - 2**224 + 2**192 + 2**96 - 1
    n = 5
    w = 52
    R = 2**260
    # Limbs below 2^52, the top one below 2^50: values below 2^258.
    contract = [(0, M52)] * 4 + [(0, (1 << 50) - 1)]

    def mul_ok(self, limbs, used):
        if not Field.mul_ok(self, limbs, used):
            return False
        # Values below 2^258, so that a product's output (below
        # a b / R + p) is in the contract.
        for t, b in enumerate(limbs[-1].bounds):
            if b is not None and used[t] and b[1] >= 1 << 50:
                return False
        return True

    def value_bounds(self, v, used, vb):
        """Per used lane, the value's interval: from the limbs' intervals,
        narrowed by `vb` where the caller knows more."""
        out = []
        for t in range(NL):
            if not used[t] or any(x.bounds[t] is None for x in v):
                continue
            lo = sum(x.bounds[t][0] << (52 * k) for k, x in enumerate(v))
            hi = sum(x.bounds[t][1] << (52 * k) for k, x in enumerate(v))
            if vb is not None and vb[t] is not None:
                lo, hi = max(lo, vb[t][0]), min(hi, vb[t][1])
            out.append((lo, hi))
        return min(x[0] for x in out), max(x[1] for x in out)

    def pass_(self, g, v, used=(True,) * NL, vb=None):
        prev = g.tag
        g.tag = "norm"
        try:
            return self._pass(g, v, used, vb)
        finally:
            g.tag = prev

    def _pass(self, g, v, used=(True,) * NL, vb=None):
        """Fold, bias, normalise, and the value bound of the result.

        What lies at or above 2^256 (the top limb from bit 48) folds by
        2^256 = 2^224 - 2^192 - 2^96 + 1: `t << 16` into limb 4 (2^224 is
        2^16 2^208), `-t << 36` into limb 3, `-t << 44` into limb 1, `t` into
        limb 0; only where the value could reach the contract's 2^258. Then
        the smallest multiple of p that makes the value non-negative, then
        the carry chain, which leaves every limb but the top in [0, 2^52) and
        the top equal to the value over 2^208."""
        v = list(v)
        n = self.n
        lo, hi = self.value_bounds(v, used, vb)

        def make_positive(v, lo, hi):
            if lo >= 0:
                return v, lo, hi
            k = 1
            while k * self.p < -lo:
                k *= 2
            bias = limbs_of(k * self.p, n, 52)
            v = [g.add(x, g.const_b(c)) if c else x for x, c in zip(v, bias)]
            return v, lo + k * self.p, hi + k * self.p

        v, lo, hi = make_positive(v, lo, hi)
        if hi >= 1 << 258:
            t = g.sra(v[n - 1], 48)
            v[n - 1] = g.add(g.mask(v[n - 1], M48), g.sll(t, 16))
            v[3] = g.sub(v[3], g.sll(t, 36))
            v[1] = g.sub(v[1], g.sll(t, 44))
            v[0] = g.add(v[0], t)
            # The fold changes the value; its bounds now come from the limbs.
            lo, hi = self.value_bounds(v, used, None)
            v, lo, hi = make_positive(v, lo, hi)
        assert lo >= 0
        # The chain. The value is non-negative, so every carry out of a limb
        # below the top is the floor of a signed division.
        out = []
        for k in range(n - 1):
            out.append(g.mask(v[k], M52))
            v[k + 1] = g.add(v[k + 1], g.sra(v[k], 52))
        top = v[n - 1]
        # Below the top every limb is in [0, 2^52), so the top limb is the
        # value over 2^208, whatever its interval says.
        top.bounds = [None if b is None else (max(b[0], 0), min(b[1], hi >> 208)) for b in top.bounds]
        out.append(top)
        if not self.within(out, used):
            raise AssertionError(f"p256r52: normalised value outside the contract: {[x.bounds for x in out]}")
        self.last_vb = (lo, hi)
        return out

    def mul(self, g, a, b, used=(True,) * NL):
        n = self.n
        c = product_columns(g, a, b, n, 52)
        z = g.zero()
        # Reduction contributions, each column its own accumulator.
        r = [None] * (2 * n + 1)

        def acc(k, f):
            r[k] = f(r[k] if r[k] is not None else z)

        k44 = g.const_b(1 << 44)
        k36 = g.const_b(1 << 36)
        kk = g.const_b(((1 << 32) - 1) << 16)
        carry = None
        x = None
        low_next = None
        for s in range(n):
            parts = [c[s]]
            if r[s] is not None:
                parts.append(r[s])
            if carry is not None:
                parts.append(carry)
            if low_next is not None:
                parts.append(low_next)
            x = collect(g, [(q, 1) for q in parts])
            carry = g.srl(x, 52)
            # m 2^44 one column up: its low half by shifts, for the chain
            # into the next step; its high half, and the rest, by IFMA. The
            # multiplier reads the low 52 bits of x, which are m.
            low_next = g.sll(g.mask(x, 0xFF), 44)
            acc(s + 2, lambda q: g.hi(q, x, k44, low52=True))
            acc(s + 3, lambda q: g.lo(q, x, k36, low52=True))
            acc(s + 4, lambda q: g.hi(q, x, k36, low52=True))
            acc(s + 4, lambda q: g.lo(q, x, kk, low52=True))
            acc(s + 5, lambda q: g.hi(q, x, kk, low52=True))
        out = []
        for k in range(n):
            parts = [c[n + k]]
            if r[n + k] is not None:
                parts.append(r[n + k])
            if k == 0:
                parts += [carry, low_next]
            out.append(collect(g, [(q, 1) for q in parts]))
        assert r[2 * n] is None
        # Unnormalised: whoever uses the product normalises it, once, with
        # whatever it is combined with.
        return out

    lazy = True

    def mul_value_bound(self, a, b):
        """A Montgomery product's value: (a b + M p) / R < a b / R + p."""
        return (0, a[1] * b[1] // self.R + self.p)

    def value(self, limbs):
        return value_of(limbs, 52) * pow(self.R, -1, self.p) % self.p

    def mulmod(self, a, b):
        return a * b % self.p

    def c_in(self):
        return pow(2, 264, self.p)  # x 2^256 (Fp) to x 2^260

    def c_out(self):
        return pow(2, 256, self.p)  # x 2^260 to x 2^256 (Fp)

    def one(self):
        return self.R % self.p


class P384(Field):
    name = "p384"
    p = 2**384 - 2**128 - 2**96 + 2**32 - 1
    n = 8
    R = 1
    contract = [(0, (1 << 50) - 1)] * 8

    def fold_into(self, g, cols, h, j, signed):
        """Add `h B^j 2^384` as `h B^j (2^128 + 2^96 - 2^32 + 1)`: with
        h 2^32 = (h & M16) 2^32 + (h >> 16) B, and 2^128 = 2^32 B^2."""
        hl32 = g.sll(g.mask(h, M16), 32)
        hh = g.sra(h, 16) if signed else g.srl(h, 16)
        cols[j] += [(h, 1), (hl32, -1)]
        cols[j + 1] += [(hh, -1)]
        cols[j + 2] += [(h, 1), (hl32, 1)]
        cols[j + 3] += [(hh, 1)]

    def mul(self, g, a, b, used=(True,) * NL):
        n = self.n
        c = product_columns(g, a, b, n)
        cols = [[(c[k], 1)] for k in range(n)] + [[] for _ in range(4)]
        for j in range(n):
            self.fold_into(g, cols, c[n + j], j, signed=False)
        sums = [collect(g, cols[k]) for k in range(n + 3)]
        assert not cols[n + 3]
        cols2 = [[(sums[k], 1)] for k in range(n)] + [[] for _ in range(4)]
        for j in range(3):
            self.fold_into(g, cols2, sums[n + j], j, signed=True)
        assert all(not x for x in cols2[n:])
        return self.pass_(g, [collect(g, cols2[k]) for k in range(n)], used)

    def carry(self, g, v, bias):
        """The carry pass; the carry out of the top limb, `t`, weighs 2^384
        and is folded back as `t (1 - 2^32)` into limb 0 and `t (1 + 2^32)`
        into limb 2. Then the bias."""
        n = self.n
        t = g.sra(v[n - 1], 48)
        tl = g.sll(t, 32)
        out = []
        for k in range(n):
            x = g.mask(v[k], M48)
            if k > 0:
                x = g.add(x, g.sra(v[k - 1], 48))
            x = g.add(x, g.const_b(bias[k]))
            if k == 0:
                x = g.sub(g.add(x, t), tl)
            if k == 2:
                x = g.add(g.add(x, t), tl)
            out.append(x)
        return out

    def value(self, limbs):
        return value_of(limbs) % self.p

    def mulmod(self, a, b):
        return a * b % self.p

    def c_in(self):
        return pow(2, -384, self.p)  # x 2^384 (Fp) to x

    def c_out(self):
        return pow(2, 384, self.p)  # x to x 2^384 (Fp)

    def one(self):
        return 1


# ---------------------------------------------------------------------------
# Lane programs
# ---------------------------------------------------------------------------


class Lin:
    """A lane-wise linear combination: {(vector, lane): coefficient}."""

    def __init__(self, terms=None):
        self.terms = dict(terms or {})

    def __add__(self, o):
        t = dict(self.terms)
        for k, v in o.terms.items():
            t[k] = t.get(k, 0) + v
        return Lin({k: v for k, v in t.items() if v})

    def __sub__(self, o):
        return self + (-1) * o

    def __rmul__(self, c):
        return Lin({k: c * v for k, v in self.terms.items() if c * v})

    def __neg__(self):
        return (-1) * self


class Vec:
    """Four lanes of field elements, as the backend holds them."""

    _ids = 0

    def __init__(self, data, vb=None, raw=False):
        Vec._ids += 1
        self.id = Vec._ids
        self.data = data
        # Per lane, the value's interval, where the backend tracks it.
        self.vb = vb
        # An unnormalised product: not a multiplier input or an output as it
        # stands.
        self.raw = raw
        self.norm = None
        # Where each of the formula's products went: the backend may place
        # them in any lanes.
        self.map = [0, 1, 2, 3]

    def __getitem__(self, i):
        return Lin({(self, self.map[i]): 1})


class MathBackend:
    """Evaluates a lane program on the field elements the lanes stand for."""

    def __init__(self, field, inputs, masks):
        self.f = field
        self.inputs = inputs  # name -> [4 field elements or None]
        self.masks = masks  # index -> bool
        self.outs = {}

    def input(self, name, kind):
        return Vec(list(self.inputs[name]))

    def constant(self, lanes):
        f = self.f
        return Vec([None if x is None else f.value(limbs_of(x % f.p, f.n, f.w)) for x in lanes])

    def lin(self, ops):
        out = []
        for e in ops:
            if e is None:
                out.append(None)
                continue
            acc = 0
            for (vec, lane), c in e.terms.items():
                v = vec.data[lane]
                assert v is not None, "a lane nobody computed"
                acc += c * v
            out.append(acc % self.f.p)
        return Vec(out)

    def mul(self, a, b):
        a, b = self.lin(a), self.lin(b)
        return Vec([None if x is None or y is None else self.f.mulmod(x, y) for x, y in zip(a.data, b.data)])

    def select(self, m, if_set, if_clear):
        return if_set if self.masks[m] else if_clear

    def select_lanes(self, m, if_set, if_clear):
        return Vec([if_set.data[l] if self.masks[(m, l)] else if_clear.data[l] for l in range(NL)])

    def output(self, name, vec, lanes, slot=0):
        self.outs[slot] = vec.data[:lanes]


# Inputs by kind: base register, slot (which lane vector from the base),
# lanes used, and whether the lanes are in the contract or the `Fp` form.
KIND = {
    "a": ("a", 0, 3, "lanes"), "b": ("b", 0, 3, "lanes"),
    "a4": ("a", 0, 4, "lanes"), "b4": ("b", 0, 4, "lanes"),
    "q": ("b", 0, 2, "fp"), "j": ("a", 0, 3, "fp"),
    # Four points, a coordinate to a vector: X, Y, Z of four Jacobian points
    # in lanes, and x, y of four affine points in the `Fp` form.
    "c0": ("a", 0, 4, "lanes"), "c1": ("a", 1, 4, "lanes"), "c2": ("a", 2, 4, "lanes"),
    "f0": ("b", 0, 4, "fp"), "f1": ("b", 1, 4, "fp"),
}


class GraphBackend:
    """Lowers a lane program to instructions."""

    def __init__(self, field, graph):
        self.f = field
        self.g = graph

    def input(self, name, kind):
        # Inputs are vectors of n limbs at 32-byte steps from their base
        # register; `kind` says which lanes are used and what they promise.
        f = self.f
        base, slot, lanes, form = KIND[kind]
        nodes = []
        for k in range(f.n):
            b = [f.contract[k] if l < lanes else None for l in range(NL)]
            if form == "fp":
                # An affine point read from the `Fp` form: x 2^256 or x 2^384
                # in radix 2^48, below p, so the top limb is the remainder.
                top = f.p.bit_length() - f.w * (f.n - 1)
                b = [((0, (1 << f.w) - 1) if k < f.n - 1 else (0, (1 << top) - 1)) if l < lanes else None for l in range(NL)]
            nodes.append(self.g.load(base, 32 * (slot * f.n + k), b))
        vb = [None] * NL
        for l in range(lanes):
            if form == "fp":
                vb[l] = (0, f.p - 1)
            else:
                vb[l] = (0, sum(f.contract[k][1] << (f.w * k) for k in range(f.n)))
        for k, node in enumerate(nodes):
            missing = [l for l in range(lanes) if node.bounds[l] is None]
            assert not missing, f"{self.g.name}: input {kind} limb {k} has no bounds in lanes {missing}"
        return Vec(nodes, vb)

    def constant(self, lanes):
        f = self.f
        limbs = [limbs_of(x % f.p, f.n, f.w) if x is not None else [0] * f.n for x in lanes]
        nodes = []
        for k in range(f.n):
            vals = [limbs[l][k] for l in range(NL)]
            node = self.g.const_v(vals)
            node.bounds = [(v, v) if lanes[l] is not None else None for l, v in enumerate(vals)]
            nodes.append(node)
        vb = [None if x is None else (x % f.p, x % f.p) for x in lanes]
        return Vec(nodes, vb)

    def lin(self, ops, for_mul):
        """Materialise four lane expressions as one vector of limbs; the same
        expressions twice (a squaring's two operands) are built once."""
        key = (for_mul, tuple(None if e is None else tuple(sorted((v.id, l, c) for (v, l), c in e.terms.items())) for e in ops))
        memo = self.__dict__.setdefault("memo", {})
        if key not in memo:
            memo[key] = self._lin(ops, for_mul)
        return memo[key]

    def _lin(self, ops, for_mul):
        self.g.tag = "lin"
        try:
            return self._lin_inner(ops, for_mul)
        finally:
            self.g.tag = "other"

    def _lin_inner(self, ops, for_mul):
        g, f = self.g, self.f
        used = [e is not None for e in ops] + [False] * (NL - len(ops))
        ops = list(ops) + [None] * (NL - len(ops))
        # A vector passed through unchanged.
        cands = set()
        for t, e in enumerate(ops):
            if e is not None:
                cands |= {v for (v, _) in e.terms}
        vb = self._lin_vb(ops, used)
        for v in cands:
            if all(e is None or e.terms == {(v, t): 1} for t, e in enumerate(ops)):
                if not v.raw and (f.mul_ok(v.data, used) if for_mul else f.within(v.data, used)):
                    return v
                if v.norm is None:
                    allused = tuple(x is not None for x in v.data[0].bounds)
                    v.norm = Vec(f.pass_(g, v.data, allused, v.vb), self._after_pass(v.vb))
                return v.norm
        # Group into terms: one source vector, at most one lane of it per
        # target lane.
        terms = []  # [vec, sel[4] or None, coef[4]]
        for t, e in enumerate(ops):
            if e is None:
                continue
            for (vec, lane), c in sorted(e.terms.items(), key=lambda kv: (kv[0][0].id, kv[0][1])):
                for term in terms:
                    if term[0] is vec and term[1][t] is None:
                        term[1][t] = lane
                        term[2][t] = c
                        break
                else:
                    sel = [None] * NL
                    coef = [0] * NL
                    sel[t] = lane
                    coef[t] = c
                    terms.append([vec, sel, coef])
        # Every used lane from exactly one term, with coefficient one: a
        # gather, blended rather than summed.
        if all(sum(1 for term in terms if term[1][t] is not None) == 1 for t in range(NL) if used[t]) and all(
            term[2][t] == 1 for term in terms for t in range(NL) if term[1][t] is not None
        ):
            acc = None
            for vec, sel, coef in terms:
                full = [sel[t] if sel[t] is not None else t for t in range(NL)]
                limbs = vec.data if full == [0, 1, 2, 3] else [g.perm(x, full) for x in vec.data]
                if acc is None:
                    acc = limbs
                else:
                    lanes = sum(1 << t for t in range(NL) if sel[t] is not None)
                    acc = [g.blend(x, y, lanes) for x, y in zip(acc, limbs)]
            return self._finish(acc, used, for_mul, vb)
        items = []
        for vec, sel, coef in terms:
            covered = [s is not None for s in sel]
            needzero = any(used[t] and not covered[t] for t in range(NL))
            full = [sel[t] if sel[t] is not None else t for t in range(NL)]
            limbs = vec.data
            if full != [0, 1, 2, 3]:
                limbs = [g.perm(x, full) for x in limbs]
            cs = {coef[t] for t in range(NL) if covered[t]}
            if len(cs) == 1 and not needzero:
                c = cs.pop()
                limbs = [self._scale(x, abs(c)) for x in limbs]
                items.append((limbs, 1 if c > 0 else -1))
            elif len(cs) == 1 and abs(next(iter(cs))) == 1:
                c = cs.pop()
                keep = sum(1 << t for t in range(NL) if covered[t])
                z = g.zero()
                limbs = [g.blend(z, x, keep) for x in limbs]
                items.append((limbs, 1 if c > 0 else -1))
            else:
                cv = [coef[t] if covered[t] else 0 for t in range(NL)]
                limbs = [g.mullo(x, cv) for x in limbs]
                items.append((limbs, 1))
        out = [collect(g, [(it[0][k], it[1]) for it in items]) for k in range(f.n)]
        return self._finish(out, used, for_mul, vb)

    def _lin_vb(self, ops, used):
        """The value interval of each lane of a combination, where every
        source has one."""
        out = [None] * NL
        for t, e in enumerate(ops):
            if e is None:
                continue
            lo = hi = 0
            for (vec, lane), c in e.terms.items():
                if vec.vb is None or vec.vb[lane] is None:
                    return None
                a, b = vec.vb[lane]
                lo += min(c * a, c * b)
                hi += max(c * a, c * b)
            out[t] = (lo, hi)
        return out

    def _after_pass(self, vb):
        f = self.f
        if getattr(f, "last_vb", None) is None:
            return None
        lo, hi = f.last_vb
        f.last_vb = None
        return [(lo, hi)] * NL

    def _finish(self, out, used, for_mul, vb=None):
        f, g = self.f, self.g
        for node in out:
            for t in range(NL):
                if used[t]:
                    assert node.bounds[t] is not None, f"{g.name}: a used lane depends on an unread one"
        if not (f.mul_ok(out, used) if for_mul else f.within(out, used)):
            out = f.pass_(g, out, used, vb)
            vb = self._after_pass(vb) or vb
        if for_mul:
            # Lanes nobody reads still go through the multiplier: zero any
            # whose bounds the multiplier would not accept, so the checks
            # there stay exact.
            bad = 0
            for t in range(NL):
                if not used[t] and any(n.bounds[t] is not None and not (0 <= n.bounds[t][0] and n.bounds[t][1] <= M52) for n in out):
                    bad |= 1 << t
            if bad:
                z = g.zero()
                out = [g.blend(x, z, bad) for x in out]
        v = Vec(out, vb)
        v.used = used
        return v

    def _scale(self, x, c):
        g = self.g
        if c == 1:
            return x
        if c & (c - 1) == 0:
            return g.sll(x, c.bit_length() - 1)
        if c == 3:
            return g.add(g.add(x, x), x)
        if c == 12:
            y = g.add(g.add(x, x), x)
            return g.sll(y, 2)
        if c == 6:
            y = g.add(g.add(x, x), x)
            return g.add(y, y)
        raise AssertionError(f"no scaling for {c}")

    def lin_cost(self, ops):
        """What `_lin` would emit for `ops`, roughly, in instructions."""
        n = self.f.n
        used = [e is not None for e in ops]
        if not any(used):
            return 0
        cands = set()
        for e in ops:
            if e is not None:
                cands |= {v for (v, _) in e.terms}
        for v in cands:
            if all(e is None or e.terms == {(v, t): 1} for t, e in enumerate(ops)):
                return 0 if (not v.raw or v.norm is not None) else 3 * n
        terms = []
        for t, e in enumerate(ops):
            if e is None:
                continue
            for (vec, lane), c in sorted(e.terms.items(), key=lambda kv: (kv[0][0].id, kv[0][1])):
                for term in terms:
                    if term[0] is vec and term[1][t] is None:
                        term[1][t] = lane
                        term[2][t] = c
                        break
                else:
                    sel = [None] * NL
                    coef = [0] * NL
                    sel[t] = lane
                    coef[t] = c
                    terms.append([vec, sel, coef])
        cost = 0
        gather = all(sum(1 for term in terms if term[1][t] is not None) == 1 for t in range(NL) if used[t]) and all(
            term[2][t] == 1 for term in terms for t in range(NL) if term[1][t] is not None)
        for vec, sel, coef in terms:
            full = [sel[t] if sel[t] is not None else t for t in range(NL)]
            if full != [0, 1, 2, 3]:
                cost += n
            if gather:
                continue
            covered = [x is not None for x in sel]
            needzero = any(used[t] and not covered[t] for t in range(NL))
            cs = {coef[t] for t in range(NL) if covered[t]}
            if len(cs) == 1 and not needzero:
                c = abs(next(iter(cs)))
                cost += 0 if c == 1 else n * (1 if c & (c - 1) == 0 else 2)
            else:
                cost += n
        cost += (len(terms) - 1) * n
        if not gather:
            cost += 3 * n
        return cost

    def mul(self, a, b):
        """Products `a[i] * b[i]`, placed in whichever lanes, and with
        whichever factor on which side, makes the operands cheapest to
        build from where their sources already are."""
        import itertools
        k = max(len(a), len(b))
        a = list(a) + [None] * (k - len(a))
        b = list(b) + [None] * (k - len(b))
        best = None
        for place in itertools.permutations(range(NL), k):
            for swap in range(1 << k):
                A = [None] * NL
                B = [None] * NL
                for i in range(k):
                    x, y = (b[i], a[i]) if swap >> i & 1 else (a[i], b[i])
                    A[place[i]] = x
                    B[place[i]] = y
                ca = self.lin_cost(A)
                same = all((x is None and y is None) or (x is not None and y is not None and x.terms == y.terms)
                           for x, y in zip(A, B))
                cost = ca + (0 if same else self.lin_cost(B))
                if best is None or cost < best[0]:
                    best = (cost, place, A, B)
        _, place, a, b = best
        v = self._mul(a, b)
        v.map = list(place) + [t for t in range(NL) if t not in place]
        return v

    def _mul(self, a, b):
        av = self.lin(a, True)
        bv = self.lin(b, True)
        used = tuple(t < len(a) and a[t] is not None and t < len(b) and b[t] is not None for t in range(NL))
        vb = None
        if av.vb is not None and bv.vb is not None:
            vb = [None] * NL
            for t in range(NL):
                if used[t] and av.vb[t] is not None and bv.vb[t] is not None:
                    vb[t] = self.f.mul_value_bound(av.vb[t], bv.vb[t])
            if any(used[t] and vb[t] is None for t in range(NL)):
                vb = None
        self.g.tag = "mul"
        v = Vec(self.f.mul(self.g, av.data, bv.data, used), vb, raw=self.f.lazy)
        self.g.tag = "other"
        v.used = used
        return v

    def select(self, m, if_set, if_clear):
        g = self.g
        mask = g.maskb(8 * m)
        vb = None
        if if_set.vb is not None and if_clear.vb is not None:
            vb = [None if a is None or b is None else (min(a[0], b[0]), max(a[1], b[1]))
                  for a, b in zip(if_set.vb, if_clear.vb)]
        return Vec([g.blendv(x, y, mask) for x, y in zip(if_clear.data, if_set.data)], vb,
                   raw=if_set.raw or if_clear.raw)

    def select_lanes(self, m, if_set, if_clear):
        """Per lane: `if_set` where mask vector `m` is all ones."""
        g = self.g
        mask = g.load("m", 32 * m, [(-1, 0)] * NL)
        vb = None
        if if_set.vb is not None and if_clear.vb is not None:
            vb = [None if a is None or b is None else (min(a[0], b[0]), max(a[1], b[1]))
                  for a, b in zip(if_set.vb, if_clear.vb)]
        return Vec([g.blendv(x, y, mask) for x, y in zip(if_clear.data, if_set.data)], vb,
                   raw=if_set.raw or if_clear.raw)

    def output(self, name, vec, lanes, slot=0):
        f = self.f
        self.__dict__.setdefault("outs", []).append((slot, lanes))
        used = tuple(l < lanes for l in range(NL))
        hi = None
        if vec.raw or not f.within(vec.data, used):
            vec = Vec(f.pass_(self.g, vec.data, used, vec.vb))
            if getattr(f, "last_vb", None) is not None:
                hi = f.last_vb[1]
            f.last_vb = None
        elif vec.vb is not None:
            hi = max(b[1] for t, b in enumerate(vec.vb) if b is not None and used[t])
        if hi is None:
            # From the limbs alone.
            hi = sum(c[1] << (f.w * k) for k, c in enumerate(f.contract))
        self.out_hi = max(getattr(self, "out_hi", 0), hi)
        assert f.within(vec.data, used), f"{self.g.name}: output {name} outside the contract: {[x.bounds for x in vec.data]}"
        for k, node in enumerate(vec.data):
            # A used lane with no bounds is one the contract checks cannot see.
            missing = [t for t in range(NL) if used[t] and node.bounds[t] is None]
            assert not missing, f"{self.g.name}: output {name} limb {k} has no bounds in lanes {missing}"
            self.g.output("o", 32 * (slot * f.n + k), node)


class Program:
    """The face a formula sees: `mul`, `vec`, `select`, inputs and outputs."""

    def __init__(self, backend):
        self.bk = backend

    def input(self, name, kind):
        return self.bk.input(name, kind)

    def constant(self, lanes):
        return self.bk.constant(lanes)

    def mul(self, a, b):
        return self.bk.mul(a, b)

    def vec(self, ops):
        if isinstance(self.bk, MathBackend):
            return self.bk.lin(ops)
        return self.bk.lin(ops, False)

    def select(self, m, if_set, if_clear):
        return self.bk.select(m, if_set, if_clear)

    def select_lanes(self, m, if_set, if_clear):
        return self.bk.select_lanes(m, if_set, if_clear)

    def output(self, name, vec, lanes=3, slot=0):
        self.bk.output(name, vec, lanes, slot)


# ---------------------------------------------------------------------------
# The formulas
# ---------------------------------------------------------------------------
#
# Inputs: `a` a Jacobian point (X, Y, Z) in lanes 0..2; `b` another; `q` an
# affine point (x, y) in lanes 0..1 in the `Fp` form (x 2^256 on P-256,
# x 2^384 on P-384). Masks, by index into the mask buffer, each all ones or
# zero. Output: a Jacobian point in lanes 0..2.


def k_double(pr, f):
    """`dbl-2001-b` for a = -3, as `Point::double_formula`, with two of its
    terms multiplied out: alpha = 3 (X - delta)(X + delta) is computed as
    3 (X^2 - delta^2), and Z3 = (Y + Z)^2 - gamma - delta as 2 Y Z. Each
    trades a sum that would have to be normalised before it could be
    multiplied for a product in a lane the round has free:
    delta = Z^2, gamma = Y^2, beta = X gamma, alpha = 3 (X^2 - delta^2),
    X3 = alpha^2 - 8 beta, Z3 = 2 Y Z, Y3 = alpha (4 beta - X3) - 8 gamma^2."""
    P = pr.input("a", "a")
    X, Y, Z = P[0], P[1], P[2]
    r1 = pr.mul([Y, Z, X], [Y, Z, X])  # gamma, delta, X^2
    gamma, delta = r1[0], r1[1]
    r2 = pr.mul([X, delta, gamma, Y], [gamma, delta, gamma, Z])  # beta, delta^2, gamma^2, Y Z
    beta = r2[0]
    A = pr.vec([3 * (r1[2] - r2[1])])  # alpha, once for both of its uses
    alpha = A[0]
    r3 = pr.mul([alpha], [alpha])
    x3 = r3[0] - 8 * beta
    r4 = pr.mul([alpha], [4 * beta - x3])
    y3 = r4[0] - 8 * r2[2]
    z3 = 2 * r2[3]
    pr.output("o", pr.vec([x3, y3, z3]))


def k_add(pr, f):
    """`add-2007-bl`, as `Point::add_formula`, with Z3 = 2 Z1 Z2 H (the
    formula's ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) H); then the cases by mask:
    mask 0 negates `b` first, mask 1 says `b` is the identity (the result is
    `a`, taking precedence), mask 2 says `a` is (the result is `b`, negated
    or not). For `a` and `b` that are not the same point, as
    `Point::add_unequal`."""
    P = pr.input("a", "a")
    Q0 = pr.input("b", "b")
    Q = pr.select(0, pr.vec([Q0[0], -Q0[1], Q0[2]]), Q0)
    X1, Y1, Z1 = P[0], P[1], P[2]
    X2, Y2, Z2 = Q[0], Q[1], Q[2]
    r1 = pr.mul([Z1, Z2, Y1, Y2], [Z1, Z2, Z2, Z1])  # Z1Z1, Z2Z2, Y1 Z2, Y2 Z1
    z1z1, z2z2 = r1[0], r1[1]
    r2 = pr.mul([X1, X2, r1[2], r1[3]], [z2z2, z1z1, z2z2, z1z1])  # U1, U2, S1, S2
    u1, s1 = r2[0], r2[2]
    h = r2[1] - u1
    r = 2 * (r2[3] - s1)
    r3 = pr.mul([2 * h, r, Z1], [2 * h, r, Z2])  # I, r^2, Z1 Z2
    i = r3[0]
    r4 = pr.mul([h, u1, r3[2]], [i, i, h])  # J, V, Z1 Z2 H
    j, v = r4[0], r4[1]
    x3 = r3[1] - j - 2 * v
    r5 = pr.mul([r, s1], [v - x3, j])
    y3 = r5[0] - 2 * r5[1]
    z3 = 2 * r4[2]
    s = pr.vec([x3, y3, z3])
    pr.output("o", pr.select(1, P, pr.select(2, Q, s)))


def k_madd(pr, f):
    """`madd-2007-bl`, as `Point::add_affine_formula`, with Z3 = 2 Z1 H, the
    affine operand read from the `Fp` form and converted in the first round;
    mask 0 negates it, mask 1 keeps `a` (a zero digit, taking precedence),
    mask 2 says `a` is the identity (the result is the operand, lifted)."""
    P = pr.input("a", "a")
    Qr = pr.input("q", "q")
    c = f.c_in()
    C = pr.select(0, pr.constant([None, c, -c, None]), pr.constant([None, c, c, None]))
    X1, Y1, Z1 = P[0], P[1], P[2]
    r1 = pr.mul([Z1, Qr[0], Qr[1]], [Z1, C[1], C[2]])  # Z1Z1, x2, y2
    z1z1, x2, y2 = r1[0], r1[1], r1[2]
    r2 = pr.mul([x2, Z1], [z1z1, z1z1])  # U2, Z1^3
    h = r2[0] - X1
    r3 = pr.mul([y2, h, Z1], [r2[1], h, h])  # S2, HH, Z1 H
    rr = 2 * (r3[0] - Y1)
    i = 4 * r3[1]
    r4 = pr.mul([h, X1, rr], [i, i, rr])  # J, V, r^2
    j, v = r4[0], r4[1]
    x3 = r4[2] - j - 2 * v
    r5 = pr.mul([rr, Y1], [v - x3, j])
    y3 = r5[0] - 2 * r5[1]
    z3 = 2 * r3[2]
    s = pr.vec([x3, y3, z3])
    one = pr.constant([None, None, f.one(), None])
    lifted = pr.vec([x2, y2, one[2]])
    pr.output("o", pr.select(1, P, pr.select(2, lifted, s)))


def k_to_fp(pr, f):
    """Jacobian lanes to the `Fp` form, not yet reduced below p."""
    P = pr.input("a", "a")
    c = f.c_out()
    C = pr.constant([c, c, c, None])
    pr.output("o", pr.mul([P[0], P[1], P[2]], [C[0], C[1], C[2]]))


def k_from_fp(pr, f):
    """A Jacobian point in the `Fp` form to lanes."""
    P = pr.input("a", "j")
    c = f.c_in()
    C = pr.constant([c, c, c, None])
    pr.output("o", pr.mul([P[0], P[1], P[2]], [C[0], C[1], C[2]]))


def k_madd4(pr, f):
    """Four mixed additions at once, one per lane: `madd-2007-bl`, as
    `Point::add_affine_formula` with Z3 = 2 Z1 H, on four accumulators held
    a coordinate to a vector, each with its own affine operand in the `Fp`
    form. Every lane runs the same formula, so no value moves between lanes
    and every product fills all four. Per lane, mask vector 0 negates the
    operand, 1 keeps the accumulator (a zero digit, taking precedence), 2 says
    the accumulator is the identity (the result is the operand, lifted)."""
    X = pr.input("a", "c0")
    Y = pr.input("a", "c1")
    Z = pr.input("a", "c2")
    qx = pr.input("b", "f0")
    qy = pr.input("b", "f1")
    c = f.c_in()
    C = pr.constant([c] * NL)
    Cy = pr.select_lanes(0, pr.constant([-c] * NL), C)
    L = range(NL)

    def each(v):
        return [v[l] for l in L]

    x2 = pr.mul(each(qx), each(C))
    y2 = pr.mul(each(qy), each(Cy))
    z1z1 = pr.mul(each(Z), each(Z))
    u2 = pr.mul(each(x2), each(z1z1))
    t = pr.mul(each(Z), each(z1z1))
    s2 = pr.mul(each(y2), each(t))
    H = pr.vec([u2[l] - X[l] for l in L])
    hh = pr.mul(each(H), each(H))
    zh = pr.mul(each(Z), each(H))
    R = pr.vec([2 * (s2[l] - Y[l]) for l in L])
    I = pr.vec([4 * hh[l] for l in L])
    j = pr.mul(each(H), each(I))
    v = pr.mul(each(X), each(I))
    rr = pr.mul(each(R), each(R))
    x3 = [rr[l] - j[l] - 2 * v[l] for l in L]
    a = pr.mul(each(R), [v[l] - x3[l] for l in L])
    b = pr.mul(each(Y), each(j))
    one = pr.constant([f.one()] * NL)
    outs = (
        pr.vec(x3),
        pr.vec([a[l] - 2 * b[l] for l in L]),
        pr.vec([2 * zh[l] for l in L]),
    )
    lifted = (pr.vec(each(x2)), pr.vec(each(y2)), one)
    for k, (o, lft, src) in enumerate(zip(outs, lifted, (X, Y, Z))):
        pr.output("o", pr.select_lanes(1, src, pr.select_lanes(2, lft, o)), 4, k)


def k_to_fp4(pr, f):
    """Four points, a coordinate to a vector, to the `Fp` form."""
    c = f.c_out()
    C = pr.constant([c] * NL)
    for k, kind in enumerate(("c0", "c1", "c2")):
        V = pr.input("a", kind)
        pr.output("o", pr.mul([V[l] for l in range(NL)], [C[l] for l in range(NL)]), 4, k)


def k_mul(pr, f):
    """Lane-wise product of `a` and `b`, all four lanes: for the tests."""
    A = pr.input("a", "a4")
    B = pr.input("b", "b4")
    pr.output("o", pr.mul([A[0], A[1], A[2], A[3]], [B[0], B[1], B[2], B[3]]), 4)


def k_lin(pr, f):
    """`(a0 - b0, a1 + b1, 3 a2 - 8 b2, b3 - a3)` lane by lane: the
    subtraction, addition and small multiples, for the tests."""
    A = pr.input("a", "a4")
    B = pr.input("b", "b4")
    pr.output("o", pr.vec([A[0] - B[0], A[1] + B[1], 3 * A[2] - 8 * B[2], B[3] - A[3]]), 4)


# Name, lane program, and the kind of each input: `a` and `b` Jacobian points
# in lanes, `q` an affine point and `j` a Jacobian one in the `Fp` form.
KERNELS = [
    ("double", k_double, ["a"]),
    ("add", k_add, ["a", "b"]),
    ("madd", k_madd, ["a", "q"]),
    ("from_fp", k_from_fp, ["j"]),
    ("to_fp", k_to_fp, ["a"]),
    ("madd4", k_madd4, ["c0", "c1", "c2", "f0", "f1"]),
    ("to_fp4", k_to_fp4, ["c0", "c1", "c2"]),
    ("mul", k_mul, ["a4", "b4"]),
    ("lin", k_lin, ["a4", "b4"]),
]
TEST_ONLY = ("mul", "lin")
# Kernels scheduled in the order their instructions were built rather than
# by critical path, which spills far less. The four-lane ones, whose four
# independent computations keep the core busy whatever the order: P-256's
# measured 1.4 times as fast this way. And every P-384 kernel: by critical
# path its doubling and addition are 33 KB together, more than the 32 KB
# level-one instruction cache the scalar multiplication's loop alternates
# between them in, and in this order 28 KB; its multiplication measured 1.2
# times as fast. P-256's chained kernels are latency-bound and small, and
# measured faster by critical path.
BUILD_ORDER = (("p256", "madd4"), ("p256", "to_fp4"), "p384")
# Kernels whose masks are a vector per mask, one word per lane.
LANE_MASKS = ("madd4",)


# ---------------------------------------------------------------------------
# Scheduling and register allocation
# ---------------------------------------------------------------------------


def live_nodes(g):
    seen = set()
    stack = [n for (_, _, n) in g.outputs]
    while stack:
        n = stack.pop()
        if n.id in seen:
            continue
        seen.add(n.id)
        stack.extend(n.args)
    for n in g.nodes:
        n.dead = n.id not in seen
        n.users = []
    for n in g.nodes:
        if not n.dead:
            for a in n.args:
                a.users.append(n)
    return [n for n in g.nodes if not n.dead]


SCHED = "height"


def schedule(g):
    if SCHED == "id":
        nodes = live_nodes(g)
        return [n for n in nodes if n.op not in MEMORY_OPS]
    nodes = live_nodes(g)
    instrs = [n for n in nodes if n.op not in MEMORY_OPS]
    # Heights: the longest latency path from a node to an output.
    for n in reversed(nodes):
        lat = LAT.get(n.op, 0)
        n.height = lat + max((u.height for u in n.users), default=0)
    ready_at = {n.id: 0 for n in nodes if n.op in MEMORY_OPS}
    remaining = {n.id: sum(1 for a in n.args if a.op not in MEMORY_OPS) for n in instrs}
    users_left = {n.id: len(n.users) for n in nodes}
    order = []
    ready = [n for n in instrs if remaining[n.id] == 0]
    cycle = 0
    live = 0
    LIMIT = 13
    while ready:
        used = {k: 0 for k in PORTS}
        avail = [n for n in ready if all(ready_at.get(a.id, 1 << 30) <= cycle for a in n.args)]
        # Under register pressure prefer what frees registers.
        def prio(n):
            frees = sum(1 for a in n.args if a.op not in MEMORY_OPS and users_left[a.id] == 1)
            if live >= LIMIT:
                return (frees, n.height)
            return (n.height, frees)
        avail.sort(key=prio, reverse=True)
        issued = []
        for n in avail:
            cl = CLASS[n.op]
            if used[cl] < PORTS[cl]:
                used[cl] += 1
                issued.append(n)
        for n in issued:
            ready.remove(n)
            order.append(n)
            ready_at[n.id] = cycle + LAT[n.op]
            live += 1
            for a in n.args:
                users_left[a.id] -= 1
                if a.op not in MEMORY_OPS and users_left[a.id] == 0:
                    live -= 1
            for u in n.users:
                remaining[u.id] -= 1
                if remaining[u.id] == 0:
                    ready.append(u)
        cycle += 1
    assert len(order) == len(instrs), "cycle in the graph"
    return order


# Which operand of each instruction may be a memory operand (the last
# source), and whether the two sources commute.
MEM_POS = {
    "lo": 2, "hi": 2, "mullo": 1, "add": 1, "sub": 1, "and": 1,
    "perm": 0, "srl": 0, "sll": 0, "sra": 0, "blend": 1, "blendv": 1,
}
COMMUTES = {"lo": (1, 2), "hi": (1, 2), "add": (0, 1), "mullo": (0, 1), "and": (0, 1)}
# Instructions that cannot take an embedded broadcast.
NO_BCAST = ("perm", "blend", "blendv")


class Alloc:
    """Linear register allocation over the scheduled order, spilling the
    value used furthest ahead (Belady) when sixteen registers are not
    enough. Emits text and a list the simulator runs."""

    def __init__(self, g, order):
        self.g = g
        self.order = order
        self.reg = {}  # node id -> register
        self.holder = [None] * NREGS  # register -> node
        self.spill = {}  # node id -> scratch offset
        self.nspill = 0
        self.text = []
        self.prog = []  # (op, dst, srcs, imm) for the simulator
        # Positions at which each node is used.
        self.uses = {}
        for i, n in enumerate(order):
            for a in n.args:
                self.uses.setdefault(a.id, []).append(i)
        self.out_of = {}
        for (base, off, n) in g.outputs:
            self.out_of.setdefault(n.id, []).append((base, off))
        self.pos = 0
        self.const_slots = {}

    # Memory homes.
    def home(self, n):
        if n.op == "load":
            return ("mem", n.base, n.off, False)
        if n.op == "maskb":
            return ("mem", "m", n.off, True)
        if n.op == "bcast":
            return ("const_b", n.imm)
        if n.op == "cvec":
            return ("const_v", n.imm)
        if n.id in self.spill:
            return ("mem", "t", self.spill[n.id], False)
        return None

    def next_use(self, n):
        for i in self.uses.get(n.id, []):
            if i >= self.pos:
                return i
        return 1 << 30

    def free_reg(self, keep):
        for r in range(NREGS):
            if self.holder[r] is None:
                return r
        # Evict the value whose next use is furthest away. Weighting that
        # by how critical the use is, or towards values already in memory,
        # measured no different.
        best, far = None, -1
        for r in range(NREGS):
            n = self.holder[r]
            if r in keep:
                continue
            nu = self.next_use(n)
            if nu > far:
                best, far = r, nu
        n = self.holder[best]
        if self.home(n) is None:
            off = 32 * self.nspill
            self.nspill += 1
            self.spill[n.id] = off
            self.emit("store", None, [best], ("t", off))
        del self.reg[n.id]
        self.holder[best] = None
        return best

    def emit(self, op, dst, srcs, imm=None):
        self.prog.append((op, dst, srcs, imm))
        tag = getattr(self, "cur", None)
        if op == "store" and imm and imm[0] == "t":
            tag = "spill"
        elif op in ("load", "bload") and tag is not None:
            tag = "reload"
        self.__dict__.setdefault("tags", []).append(tag)

    def in_reg(self, n, keep):
        """Put `n` in a register, loading or zeroing it if it is not."""
        if n.id in self.reg:
            return self.reg[n.id]
        r = self.free_reg(keep)
        if n.op == "zero":
            self.emit("zero", r, [])
        else:
            h = self.home(n)
            assert h is not None, f"{n} has no home"
            if h[0] == "mem" and h[3]:
                self.emit("bload", r, [h])
            elif h[0] == "const_b":
                self.emit("bload", r, [h])
            else:
                self.emit("load", r, [h])
        if n.op != "zero":
            self.reg[n.id] = r
            self.holder[r] = n
        return r

    def run(self):
        for i, n in enumerate(self.order):
            self.pos = i
            self.cur = n.tag
            args = list(n.args)
            mp = MEM_POS[n.op]
            # Choose which source goes to memory: one not in a register.
            if n.op in COMMUTES:
                x, y = COMMUTES[n.op]
                if args[y].id in self.reg and args[x].id not in self.reg and self.home(args[x]) is not None and args[x].op != "zero":
                    args[x], args[y] = args[y], args[x]
            keep = set()
            srcs = []
            dst = None
            if n.op in ("lo", "hi"):
                acc, a, b = args
                ra = self.in_reg(a, keep)
                keep.add(ra)
                srcb = self.src(b, keep, allow_mem=True, bcast_ok=True)
                if srcb[0] == "reg":
                    keep.add(srcb[1])
                # The accumulator is overwritten: copy it if it is used again.
                if acc.op == "zero":
                    rd = self.free_reg(keep)
                    self.emit("zero", rd, [])
                elif acc.id in self.reg and len([u for u in self.uses.get(acc.id, []) if u > i]) == 0 and acc.id not in self.out_of:
                    rd = self.reg[acc.id]
                    del self.reg[acc.id]
                    self.holder[rd] = None
                else:
                    ro = self.in_reg(acc, keep)
                    keep.add(ro)
                    if len([u for u in self.uses.get(acc.id, []) if u > i]) == 0 and acc.id not in self.out_of:
                        rd = ro
                        del self.reg[acc.id]
                        self.holder[rd] = None
                    else:
                        rd = self.free_reg(keep)
                        self.emit("copy", rd, [("reg", ro)])
                self.emit(n.op, rd, [("reg", ra), srcb])
                dst = rd
            else:
                # Every source in a register but the one that may be a
                # memory operand, which is placed after the others.
                for k, a in enumerate(args):
                    if k == mp:
                        srcs.append(None)
                        continue
                    r = self.in_reg(a, keep)
                    keep.add(r)
                    srcs.append(("reg", r))
                if mp < len(args):
                    a = args[mp]
                    srcs[mp] = self.src(a, keep, allow_mem=True, bcast_ok=n.op not in NO_BCAST)
                    for s in srcs:
                        if s and s[0] == "reg":
                            keep.add(s[1])
                # Free the registers of operands whose last use this is.
                self.pos = i + 1
                for a in args:
                    if a.id in self.reg and self.next_use(a) == 1 << 30 and a.id not in self.out_of:
                        r = self.reg.pop(a.id)
                        self.holder[r] = None
                self.pos = i
                rd = self.free_reg(set())
                self.emit(n.op, rd, srcs, n.imm)
                dst = rd
            self.reg[n.id] = dst
            self.holder[dst] = n
            if n.id in self.out_of:
                for (base, off) in self.out_of[n.id]:
                    self.emit("store", None, [dst], (base, off))
                del self.out_of[n.id]
            # Drop everything with no use left.
            self.pos = i + 1
            for r in range(NREGS):
                m = self.holder[r]
                if m is not None and self.next_use(m) == 1 << 30 and m.id not in self.out_of:
                    del self.reg[m.id]
                    self.holder[r] = None
        assert not self.out_of
        return self.prog

    def src(self, n, keep, allow_mem, bcast_ok):
        if n.id in self.reg:
            return ("reg", self.reg[n.id])
        h = self.home(n)
        if allow_mem and h is not None and n.op != "zero":
            if h[0] == "const_b" and not bcast_ok:
                pass
            elif h[0] == "mem" and h[3] and not bcast_ok:
                pass
            else:
                return h
        r = self.in_reg(n, keep)
        return ("reg", r)


# ---------------------------------------------------------------------------
# Constant table, text, simulation
# ---------------------------------------------------------------------------


class Consts:
    """One table per field: broadcast words first, then 32-byte vectors."""

    def __init__(self):
        self.words = []
        self.vecs = []
        self.wi = {}
        self.vi = {}

    def word(self, v):
        v &= M64
        if v not in self.wi:
            self.wi[v] = len(self.words)
            self.words.append(v)
        return self.wi[v]

    def vec(self, vs):
        vs = tuple(x & M64 for x in vs)
        if vs not in self.vi:
            self.vi[vs] = len(self.vecs)
            self.vecs.append(vs)
        return self.vi[vs]

    def layout(self):
        # Vectors first, at 32-byte alignment, then the words.
        self.voff = {v: 32 * i for v, i in self.vi.items()}
        base = 32 * len(self.vecs)
        self.woff = {v: base + 8 * i for v, i in self.wi.items()}
        return [w for vs in self.vecs for w in vs] + self.words


def operand_text(s, consts):
    kind = s[0]
    if kind == "reg":
        return f"ymm{s[1]}"
    if kind == "mem":
        _, base, off, bc = s
        a = f"[{{{base}}} + {off}]" if off else f"[{{{base}}}]"
        return f"qword ptr {a}{{{{1to4}}}}" if bc else f"ymmword ptr {a}"
    if kind == "const_b":
        off = consts.woff[s[1] & M64]
        return f"qword ptr [{{c}} + {off}]{{{{1to4}}}}"
    if kind == "const_v":
        off = consts.voff[tuple(x & M64 for x in s[1])]
        return f"ymmword ptr [{{c}} + {off}]"
    raise AssertionError(s)


MNEMONIC = {
    "lo": "vpmadd52luq", "hi": "vpmadd52huq", "mullo": "vpmullq",
    "add": "vpaddq", "sub": "vpsubq", "and": "vpandq",
    "srl": "vpsrlq", "sll": "vpsllq", "sra": "vpsraq", "perm": "vpermq",
    "blend": "vpblendd", "blendv": "vpblendvb",
}


def access_extents(text):
    """The bytes from each base register's pointer that the kernel's text
    reads or writes: the furthest byte of any memory operand on it."""
    ext = {}
    for line in text:
        for kind, base, off in re.findall(r"(ymmword|qword) ptr \[\{(\w)\}(?: \+ (\d+))?\]", line):
            width = 32 if kind == "ymmword" else 8
            ext[base] = max(ext.get(base, 0), int(off or 0) + width)
    return ext


def safety_access(ext, up, n):
    """The `# Safety` sentence on the pointers, from `access_extents`: a field
    vector is `n` limb vectors of four lanes, `4 * n` words."""
    def vectors(base):
        k = -(-ext[base] // (32 * n))
        return f"{k} field vector{'s' if k != 1 else ''} of `4 * {up}_LIMBS` words"

    parts = []
    for base in ("a", "b"):
        if base in ext:
            parts.append(f"`{base}` must be readable for {vectors(base)}")
    if "m" in ext:
        parts.append(f"`m` must be readable for {ext['m']} bytes")
    if "o" in ext:
        parts.append(f"`o` must be writable for {vectors('o')}")
    if "t" in ext:
        parts.append(f"`t` must be writable for {ext['t'] // 8} words, within `{up}_SPILL_WORDS`")
    return "; ".join(parts) + "."


def to_text(prog, consts):
    out = []
    for op, dst, srcs, imm in prog:
        if op == "zero":
            out.append(f"vpxor xmm{dst}, xmm{dst}, xmm{dst}")
        elif op == "copy":
            out.append(f"vmovdqa ymm{dst}, {operand_text(srcs[0], consts)}")
        elif op == "load":
            out.append(f"vmovdqu ymm{dst}, {operand_text(srcs[0], consts)}")
        elif op == "bload":
            t = operand_text(srcs[0], consts).replace("{{1to4}}", "")
            out.append(f"vpbroadcastq ymm{dst}, {t}")
        elif op == "store":
            base, off = imm
            a = f"[{{{base}}} + {off}]" if off else f"[{{{base}}}]"
            out.append(f"vmovdqu ymmword ptr {a}, ymm{srcs[0]}")
        elif op in ("lo", "hi"):
            out.append(f"{MNEMONIC[op]} ymm{dst}, {operand_text(srcs[0], consts)}, {operand_text(srcs[1], consts)}")
        elif op in ("srl", "sll", "sra", "perm"):
            out.append(f"{MNEMONIC[op]} ymm{dst}, {operand_text(srcs[0], consts)}, {imm}")
        elif op == "blend":
            out.append(f"vpblendd ymm{dst}, {operand_text(srcs[0], consts)}, {operand_text(srcs[1], consts)}, {imm}")
        elif op == "blendv":
            out.append(f"vpblendvb ymm{dst}, {operand_text(srcs[0], consts)}, {operand_text(srcs[1], consts)}, {operand_text(srcs[2], consts)}")
        else:
            out.append(f"{MNEMONIC[op]} ymm{dst}, {operand_text(srcs[0], consts)}, {operand_text(srcs[1], consts)}")
    return out


def register_consts(prog, consts):
    for op, dst, srcs, imm in prog:
        for s in srcs:
            if isinstance(s, tuple) and s[0] == "const_b":
                consts.word(s[1])
            if isinstance(s, tuple) and s[0] == "const_v":
                consts.vec(s[1])


class Sim:
    """Runs a register program on four-lane 64-bit values."""

    def __init__(self, mem):
        self.mem = mem  # (base, off) -> [4 words]; masks as ("m", off) -> word
        self.r = [[0] * NL for _ in range(NREGS)]

    def read(self, s):
        if s[0] == "reg":
            return list(self.r[s[1]])
        if s[0] == "mem":
            _, base, off, bc = s
            if bc:
                return [self.mem[(base, off)]] * NL
            return list(self.mem[(base, off)])
        if s[0] == "const_b":
            return [s[1] & M64] * NL
        if s[0] == "const_v":
            return [x & M64 for x in s[1]]
        raise AssertionError(s)

    def run(self, prog):
        for op, dst, srcs, imm in prog:
            if op == "zero":
                self.r[dst] = [0] * NL
            elif op in ("copy", "load"):
                self.r[dst] = self.read(srcs[0])
            elif op == "bload":
                v = self.read(srcs[0])
                self.r[dst] = [v[0]] * NL
            elif op == "store":
                base, off = imm
                self.mem[(base, off)] = list(self.r[srcs[0]])
            else:
                vals = [self.read(s) for s in srcs]
                self.r[dst] = [self.lane(op, imm, [v[l] for v in vals], self.r[dst][l]) for l in range(NL)]

    @staticmethod
    def lane(op, imm, v, old):
        if op == "lo":
            a, b = v
            return (old + (((a & M52) * (b & M52)) & M52)) & M64
        if op == "hi":
            a, b = v
            return (old + (((a & M52) * (b & M52)) >> 52)) & M64
        if op == "add":
            return (v[0] + v[1]) & M64
        if op == "sub":
            return (v[0] - v[1]) & M64
        if op == "and":
            return v[0] & v[1]
        if op == "mullo":
            return (v[0] * v[1]) & M64
        if op == "srl":
            return v[0] >> imm
        if op == "sll":
            return (v[0] << imm) & M64
        if op == "sra":
            return (s64(v[0]) >> imm) & M64
        if op == "blendv":
            return v[1] if v[2] >> 63 else v[0]
        raise AssertionError(op)

    def run_lanes(self, prog):
        # perm and blend move lanes: handle them on whole vectors.
        for op, dst, srcs, imm in prog:
            if op == "perm":
                v = self.read(srcs[0])
                self.r[dst] = [v[(imm >> (2 * l)) & 3] for l in range(NL)]
            elif op == "blend":
                a, b = self.read(srcs[0]), self.read(srcs[1])
                self.r[dst] = [b[l] if (imm >> (2 * l)) & 3 else a[l] for l in range(NL)]
            else:
                self.run([(op, dst, srcs, imm)])


def build(field, name, fn):
    g = Graph(f"{field.name}_{name}")
    bk = GraphBackend(field, g)
    pr = Program(bk)
    fn(pr, field)
    order = schedule(g)
    al = Alloc(g, order)
    prog = al.run()
    g.outs = bk.outs
    g.tags = al.tags
    g.out_hi = bk.out_hi
    return g, prog, al.nspill


def random_lane_value(field, rng, kind, extreme):
    """Limbs for one lane within what the input promises."""
    n = field.n
    if kind in ("q", "j"):
        x = rng.randrange(field.p)
        if extreme == 1:
            x = field.p - 1
        elif extreme == 2:
            x = 0
        return limbs_of(x, n, field.w)
    out = []
    for k in range(n):
        lo, hi = field.contract[k]
        if extreme == 1:
            out.append(hi)
        elif extreme == 2:
            out.append(lo)
        elif extreme == 3:
            out.append(rng.choice((lo, hi)))
        else:
            out.append(rng.randrange(lo, hi + 1))
    return out


def check_kernel(field, name, fn, prog, kinds, trials, outs, out_hi=None):
    """Run the emitted program on random and extreme inputs and compare with
    the lane program evaluated on what the lanes stand for."""
    rng = random.Random(sum(map(ord, field.name + name)))
    for t in range(trials):
        extreme = t % 5 if t < 50 else 0
        mem = {}
        meaning = {}
        for kind in kinds:
            base, slot, nlanes, form = KIND[kind]
            rk = "q" if form == "fp" else "a"
            lanes = [random_lane_value(field, rng, rk, (extreme + l) % 5 if extreme else 0) for l in range(NL)]
            for k in range(field.n):
                mem[(base, 32 * (slot * field.n + k))] = [lanes[l][k] & M64 for l in range(NL)]
            meaning[kind] = [field.value(lanes[l]) for l in range(NL)]
        masks = [rng.getrandbits(1) for _ in range(3)]
        lane_masks = [[rng.getrandbits(1) for _ in range(NL)] for _ in range(3)]
        for i, m in enumerate(masks):
            mem[("m", 8 * i)] = M64 if m else 0
        if name in LANE_MASKS:
            for i in range(3):
                mem[("m", 32 * i)] = [M64 if x else 0 for x in lane_masks[i]]
        Sim(mem).run_lanes(prog)
        mm = {i: bool(m) for i, m in enumerate(masks)}
        for i in range(3):
            for l in range(NL):
                mm[(i, l)] = bool(lane_masks[i][l])
        mb = MathBackend(field, {}, mm)
        mb.input = lambda nm, kind: Vec(list(meaning[kind]))
        fn(Program(mb), field)
        for slot, nout in outs:
            got = []
            for l in range(nout):
                limbs = [s64(mem[("o", 32 * (slot * field.n + k))][l]) for k in range(field.n)]
                for k, x in enumerate(limbs):
                    lo, hi = field.contract[k]
                    assert lo <= x <= hi, f"{field.name} {name}: output limb {k} = {x:#x} outside the contract"
                if out_hi is not None:
                    assert value_of(limbs, field.w) <= out_hi, f"{field.name} {name}: output above its claimed bound"
                got.append(field.value(limbs))
            want = mb.outs[slot]
            assert got == want, f"{field.name} {name}: trial {t} slot {slot} differs\n{got}\n{want}"


def affine_math_checks():
    """The formulas against the group law, independently of any lowering:
    each kernel's lane program evaluated on field elements, compared with
    textbook affine arithmetic, on random points and with each mask. A wrong
    formula fails here; a wrong lowering fails in `check_kernel`."""
    curves = (
        (P256(), 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b, 2**256),
        (P384(), 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef, 2**384),
    )
    for field, b, rfp in curves:
        p = field.p
        rng = random.Random(7)

        def point():
            while True:
                x = rng.randrange(p)
                y2 = (x ** 3 - 3 * x + b) % p
                y = pow(y2, (p + 1) // 4, p)
                if y * y % p == y2:
                    return x, y

        def aff_add(P, Q):
            if P is None:
                return Q
            if Q is None:
                return P
            (x1, y1), (x2, y2) = P, Q
            if x1 == x2:
                if (y1 + y2) % p == 0:
                    return None
                lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, p) % p
            else:
                lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
            x3 = (lam * lam - x1 - x2) % p
            return x3, (lam * (x1 - x3) - y1) % p

        def neg(P):
            return (P[0], (-P[1]) % p)

        def jac(P):
            z = rng.randrange(1, p)
            return [P[0] * z * z % p, P[1] * z * z * z % p, z, None]

        def aff(J):
            if J[2] % p == 0:
                return None
            zi = pow(J[2], -1, p)
            return J[0] * zi * zi % p, J[1] * zi * zi * zi % p

        # What a lane of the `q` input stands for, given the affine
        # coordinate: the kernel multiplies it by c_in.
        cin = field.value(limbs_of(field.c_in(), field.n, field.w))

        def run(fn, a, bvec, masks):
            mb = MathBackend(field, {}, dict(enumerate(masks)))

            def inp(nm, kind):
                if kind in ("a", "j"):
                    return Vec(list(a))
                return Vec(list(bvec))
            mb.input = inp
            fn(Program(mb), field)
            return mb.outs[0]

        for _ in range(16):
            P, Q = point(), point()
            JP, JQ = jac(P), jac(Q)
            assert aff(run(k_double, JP, None, [0, 0, 0])) == aff_add(P, P), f"{field.name} double"
            qlanes = [Q[0] * pow(cin, -1, p) % p, Q[1] * pow(cin, -1, p) % p, None, None]
            for m0 in (0, 1):
                q = neg(Q) if m0 else Q
                assert aff(run(k_add, JP, JQ, [m0, 0, 0])) == aff_add(P, q), f"{field.name} add"
                assert aff(run(k_add, JP, JQ, [m0, 1, 0])) == P, f"{field.name} add, b identity"
                assert aff(run(k_add, JP, JQ, [m0, 0, 1])) == q, f"{field.name} add, a identity"
                assert aff(run(k_add, JP, JQ, [m0, 1, 1])) == P, f"{field.name} add, both"
                assert aff(run(k_madd, JP, qlanes, [m0, 0, 0])) == aff_add(P, q), f"{field.name} madd"
                assert aff(run(k_madd, JP, qlanes, [m0, 1, 0])) == P, f"{field.name} madd, keep"
                assert aff(run(k_madd, JP, qlanes, [m0, 0, 1])) == q, f"{field.name} madd, a identity"
                assert aff(run(k_madd, JP, qlanes, [m0, 1, 1])) == P, f"{field.name} madd, keep wins"
            # to_fp: lanes standing for x, times c_out, stand for x 2^256 (or
            # 2^384) as Fp holds it.
            out = run(k_to_fp, JP, None, [0, 0, 0])
            cout = field.value(limbs_of(field.c_out(), field.n, field.w))
            assert out == [x * cout % p for x in JP[:3]], f"{field.name} to_fp"
            # P + (-P) gives the identity (Z = 0), as the incomplete
            # formulas promise.
            JN = jac(neg(P))
            assert aff(run(k_add, JP, JN, [0, 0, 0])) is None
    print("formulas agree with affine arithmetic", file=sys.stderr)


def estimate(prog, ports=True):
    """Cycles for the program on an idealised out-of-order core: every
    instruction starts when its operands are ready and, with `ports`, when
    a pipe of its kind is free. Zen 4/5-like: four vector pipes, two of
    which multiply, shift and shuffle; loads see a stored spill after seven
    cycles. A guide for the generator, not a measurement."""
    LATX = {"lo": 4, "hi": 4, "mullo": 3, "add": 1, "sub": 1, "and": 1,
            "srl": 1, "sll": 1, "sra": 1, "perm": 3, "blend": 1, "blendv": 1,
            "load": 7, "bload": 7, "zero": 0, "copy": 0, "store": 1}
    reg_ready = [0] * NREGS
    mem_ready = {}
    busy = {}

    def take(cls, t):
        if not ports or cls is None:
            return t
        cap = {"mul": 2, "alu": 4, "sp": 2, "store": 2, "load": 3}[cls]
        sub = {"mul": ("mul", "alu"), "sp": ("sp", "alu")}.get(cls, (cls,))
        while True:
            if all(busy.get((c, t), 0) < ({"alu": 4}.get(c, cap)) for c in sub):
                for c in sub:
                    busy[(c, t)] = busy.get((c, t), 0) + 1
                return t
            t += 1

    def src_ready(x):
        if x[0] == "reg":
            return reg_ready[x[1]]
        if x[0] == "mem":
            return mem_ready.get((x[1], x[2]), 0) + 7
        return 0

    end = 0
    for op, dst, srcs, imm in prog:
        if op == "store":
            t = reg_ready[srcs[0]]
            t = take("store", t)
            mem_ready[imm] = t + 1
            end = max(end, t + 1)
            continue
        if op in ("zero",):
            reg_ready[dst] = 0
            continue
        ready = max([src_ready(x) for x in srcs] + [0])
        if op in ("lo", "hi"):
            ready = max(ready, reg_ready[dst])
        cls = {"lo": "mul", "hi": "mul", "mullo": "mul", "srl": "sp", "sll": "sp",
               "sra": "sp", "perm": "sp", "load": "load", "bload": "load", "copy": None}.get(op, "alu")
        t = take(cls, ready)
        reg_ready[dst] = t + LATX[op]
        end = max(end, reg_ready[dst])
    return end


def main():
    global SCHED
    check_only = "--check" in sys.argv
    trials = 300
    for a in sys.argv[1:]:
        if a.startswith("--trials="):
            trials = int(a.split("=")[1])
    affine_math_checks()
    fields = [P256(), P384()]
    results = {}
    for field in fields:
        for name, fn, ins in KERNELS:
            # Throughput-bound kernels in the order they were built, which
            # spills least; latency-bound ones by critical path.
            SCHED = "id" if (field.name, name) in BUILD_ORDER or field.name in BUILD_ORDER else "height"
            g, prog, nspill = build(field, name, fn)
            check_kernel(field, name, fn, prog, ins, trials, g.outs, g.out_hi)
            n_ifma = sum(1 for p in prog if p[0] in ("lo", "hi"))
            mix = {}
            for q in prog:
                mix[q[0]] = mix.get(q[0], 0) + 1
            print(f"{field.name} {name}: {len(prog)} instructions, {n_ifma} IFMA, {nspill} spills, "
                  f"critical path {estimate(prog, False)}, with pipes {estimate(prog)} cycles", file=sys.stderr)
            if "--mix" in sys.argv:
                print(f"    {sorted(mix.items(), key=lambda kv: -kv[1])}", file=sys.stderr)
                by = {}
                for (q, tg) in zip(prog, g.tags):
                    key = (tg, "ifma" if q[0] in ("lo", "hi") else ("zero" if q[0] == "zero" else "op"))
                    by[key] = by.get(key, 0) + 1
                print(f"    {sorted(by.items(), key=lambda kv: -kv[1])}", file=sys.stderr)
            results[(field.name, name)] = (g, prog, nspill)
    print("all kernels agree with the field arithmetic", file=sys.stderr)
    if check_only:
        return
    write_rust(sys.argv[1], fields, results)


FEATURES = "AVX2, AVX-512F, AVX-512VL, AVX-512DQ and AVX-512 IFMA"


def write_rust(path, fields, results):
    out = []
    w = out.append
    w("//! P-256 and P-384 point formulas on AVX-512 IFMA, four field elements")
    w("//! to a vector, each one `asm!` block.")
    w("//!")
    w("//! GENERATED by `scripts/gen_nist_ifma.py`; edit that, not this. The")
    w("//! script's notes say how the formulas are lowered, how every limb is")
    w("//! bounded, and how the emitted instructions are checked before they are")
    w("//! written; `super::ifma` says how they are used.")
    w("//!")
    w("//! A lane vector is `L` registers' worth of 64-bit words, limb `k` of the")
    w("//! four lanes at words `4k..4k + 4`: P-256 has five limbs of 52 bits,")
    w("//! P-384 eight of 48. Every kernel reads its inputs through `a` and `b`,")
    w("//! its masks through `m` (three words, each all ones or zero), writes its")
    w("//! result through `o` and spills through `t`; constants come from the")
    w("//! field's table. Nothing branches, and every address is one of those")
    w("//! registers plus a constant.")
    w("")
    w("#![allow(clippy::missing_safety_doc)]")
    w("")
    w("use core::arch::asm;")
    w("")
    w("/// A field's constants, 32-byte aligned for the vector operands.")
    w("#[repr(C, align(32))]")
    w("pub(crate) struct ConstTable<const N: usize>(pub(crate) [u64; N]);")
    w("")
    for field in fields:
        consts = Consts()
        names = [name for (name, _, _) in KERNELS]
        for name in names:
            register_consts(results[(field.name, name)][1], consts)
        words = consts.layout()
        spill = max(results[(field.name, name)][2] for name in names)
        up = field.name.upper()
        w(f"/// Limbs per element on {up}.")
        w(f"pub(crate) const {up}_LIMBS: usize = {field.n};")
        w(f"/// The largest value each limb of a lane vector may hold: what every")
        w(f"/// kernel promises of its output and assumes of its input.")
        w("#[cfg(test)]")
        w(f"pub(crate) const {up}_CONTRACT: [u64; {field.n}] = [{', '.join(f'0x{c[1]:x}' for c in field.contract)}];")
        # The conversions to the `Fp` form leave values below k p: k - 1
        # masked subtractions bring them below p.
        hi = max(results[(field.name, nm)][0].out_hi for nm in ("to_fp", "to_fp4"))
        mult = -(-(hi + 1) // field.p)
        w(f"/// Masked subtractions of p that bring a `to_fp` or `to_fp4` output below")
        w(f"/// p: its value is below {mult} p, by the generator's bounds.")
        w(f"pub(crate) const {up}_TO_FP_SUBTRACTIONS: usize = {mult - 1};")
        w(f"/// Words of spill space a {up} kernel may use.")
        w(f"pub(crate) const {up}_SPILL_WORDS: usize = {max(4, 4 * spill)};")
        w(f"static {up}_CONSTS: ConstTable<{len(words)}> = ConstTable([")
        for i in range(0, len(words), 4):
            w("    " + ", ".join(f"0x{x:016x}" for x in words[i:i + 4]) + ",")
        w("]);")
        w("")
        for name, fn, kinds in KERNELS:
            g, prog, nspill = results[(field.name, name)]
            text = to_text(prog, consts)
            used = set()
            for line in text:
                for r in ("a", "b", "m", "o", "t", "c"):
                    if "{" + r + "}" in line:
                        used.add(r)
            doc = (fn.__doc__ or "").strip().splitlines()
            for line in doc:
                w(f"/// {line.strip()}" if line.strip() else "///")
            n_ifma = sum(1 for q in prog if q[0] in ("lo", "hi"))
            w("///")
            w(f"/// {len(prog)} instructions, {n_ifma} of them multiply-adds; {nspill} values spilled.")
            w("///")
            w("/// # Safety")
            w("///")
            ext = access_extents(text)
            outs = [f"`{r}`" for r in ("o", "t") if r in ext]
            safety = (f"The CPU must have {FEATURES}. " + safety_access(ext, up, field.n)
                      + f" {' and '.join(outs)} must not overlap the inputs"
                      + (" or each other." if len(outs) > 1 else "."))
            for line in textwrap.wrap(safety, 76):
                w(f"/// {line}")
            if name in TEST_ONLY:
                w("#[cfg(test)]")
            w("#[inline(never)]")
            params = []
            for r in ("a", "b", "m"):
                params.append(f"{'' if r in used else '_'}{r}: *const u64")
            for r in ("o", "t"):
                params.append(f"{'' if r in used else '_'}{r}: *mut u64")
            w(f"pub(crate) unsafe fn {field.name}_{name}({', '.join(params)}) {{")
            w("    // SAFETY: the caller's contract above; every address in the text is")
            w("    // one of the pointer registers plus a constant within the bounds it")
            w("    // states, or the constant table plus an offset inside it. The block")
            w("    // uses `ymm0`-`ymm15` only and declares all sixteen clobbered, pushes")
            w("    // nothing, leaves the flags alone and ends with `vzeroupper`.")
            w("    unsafe {")
            w("        asm!(")
            w('            ".p2align 6",')
            for line in text:
                w(f'            "{line}",')
            w('            "vzeroupper",')
            for r in ("a", "b", "m", "o", "t"):
                if r in used:
                    w(f"            {r} = in(reg) {r},")
            if "c" in used:
                w(f"            c = in(reg) {up}_CONSTS.0.as_ptr(),")
            regs = ", ".join(f'out("xmm{i}") _' for i in range(16))
            w(f"            {regs},")
            w("            options(nostack, preserves_flags),")
            w("        );")
            w("    }")
            w("}")
            w("")
    open(path, "w", newline="\n").write("\n".join(out))
    # The layout `cargo fmt` would give it, so that `--check` passes on what
    # this writes.
    import subprocess
    subprocess.run(["rustfmt", "--edition", "2021", path], check=True)


if __name__ == "__main__":
    main()
