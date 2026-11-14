#!/usr/bin/env python3
"""Generate crates/ic-ec/src/f51x4_kernels.rs: the four-lane GF(2^255 - 19)
operations of `f51x4` on AVX-512 IFMA, each one `asm!` block.

    python scripts/gen_f51x4.py crates/ic-ec/src/f51x4_kernels.rs
    python scripts/gen_f51x4.py --check      # simulate only, write nothing

# Why assembly

`f51x4` was AVX2 intrinsics around one-instruction `asm!` blocks for
`VPMADD52LUQ`, `VPMADD52HUQ` and `VPMULLQ`. LLVM cannot tell the domain of a
value an `asm!` block returns, so it moved, spilled and zeroed those values
with `vmovaps` and `vxorps`, which Intel's list of data-operand-independent
timing instructions does not name: IronProof's constant-time result for the
four-lane ladder step, addition and doubling was `unknown` on them. The
stable intrinsics for IFMA arrived in Rust 1.89, above the crate's minimum.
Here every operation that touches a secret is one block of integer-domain
instructions, all on that list, and values cross between blocks only through
memory the caller provides.

# What this does

Each kernel below is the formula `f51x4` computed, written once against an
abstract backend, step for step as the Rust it replaces. Run on
`GraphBackend` it builds a graph of single-register instructions, each value
bounded lane by lane and limb by limb by interval arithmetic, refusing any
multiplier input that could reach 2^52 or any value that could leave the
signed 64-bit range. The graph is then scheduled, given registers and
spilled, and emitted, by `gen_nist_ifma.py`'s machinery, imported unchanged.
Run on `ModBackend` the same formula is evaluated on integers modulo p. The
emitted instructions are simulated on random and extreme inputs and every
output compared with that evaluation, and every output limb with the
contract. Nothing is written unless every kernel agrees.

That checks the lowering: the limb arithmetic, carries and folds, against
the field operations the formula names. That the formulas are the curve's
is checked in Rust, against the four-limb field and the scalar Edwards and
X25519 code (`f51x4`'s tests and `ed25519`'s).

# The field

Radix 2^51, five limbs, 2^255 = 19: as `f51x4`'s module notes describe. The
contract on every kernel's inputs and outputs is limbs below 2^52.
"""

import os
import random
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_nist_ifma as G  # noqa: E402

M64 = G.M64
M51 = (1 << 51) - 1
M52 = (1 << 52) - 1
NL = G.NL
P = 2**255 - 19
N = 5
P16_0 = 16 * ((1 << 51) - 19)
P16_I = 16 * ((1 << 51) - 1)
CONTRACT = (0, M52)


def sel(l0, l1, l2, l3):
    return (l0, l1, l2, l3)


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


class GraphBackend:
    """Field vectors as lists of five graph nodes."""

    def __init__(self, g):
        self.g = g

    def load(self, base, slot):
        return [self.g.load(base, 32 * (slot * N + k), [CONTRACT] * NL) for k in range(N)]

    def store(self, base, slot, a):
        for k in range(N):
            self.g.output(base, 32 * (slot * N + k), a[k])

    def mask(self, i):
        """The `i`th word of the mask buffer, broadcast."""
        return self.g.maskb(8 * i)

    def zero(self):
        return [self.g.zero() for _ in range(N)]

    def constant(self, lanes):
        """A field vector constant: `lanes[l]` small, in limb 0."""
        return [self.g.const_v(lanes)] + [self.g.zero() for _ in range(N - 1)]

    def times19(self, x):
        return self.g.mullo(x, (19, 19, 19, 19))

    def reduce(self, z):
        g = self.g
        c = [g.srl(z[k], 51) for k in range(N)]
        return [
            g.add(g.mask(z[0], M51), self.times19(c[4])),
            g.add(g.mask(z[1], M51), c[0]),
            g.add(g.mask(z[2], M51), c[1]),
            g.add(g.mask(z[3], M51), c[2]),
            g.add(g.mask(z[4], M51), c[3]),
        ]

    def add_raw(self, a, b):
        return [self.g.add(a[k], b[k]) for k in range(N)]

    def neg16(self, b):
        g = self.g
        return [g.sub(g.const_b(P16_0 if k == 0 else P16_I), b[k]) for k in range(N)]

    def blend(self, a, b, lanes):
        return [self.g.blend(a[k], b[k], lanes) for k in range(N)]

    def permute(self, a, s):
        return [self.g.perm(a[k], s) for k in range(N)]

    def blendv(self, a, b, m):
        return [self.g.blendv(a[k], b[k], m) for k in range(N)]

    def finish(self, lo, hi):
        g = self.g
        t = [lo[0]]
        for k in range(1, 9):
            t.append(g.add(lo[k], g.add(hi[k - 1], hi[k - 1])))
        t.append(g.add(hi[8], hi[8]))
        return self.reduce([g.add(t[k], self.times19(t[k + 5])) for k in range(N)])

    def mul(self, a, b):
        g = self.g
        lo = [g.zero() for _ in range(9)]
        hi = [g.zero() for _ in range(9)]
        for i in range(N):
            for j in range(N):
                lo[i + j] = g.lo(lo[i + j], a[i], b[j])
                hi[i + j] = g.hi(hi[i + j], a[i], b[j])
        return self.finish(lo, hi)

    def square(self, a):
        g = self.g
        lo = [g.zero() for _ in range(9)]
        hi = [g.zero() for _ in range(9)]
        for i in range(N):
            for j in range(i + 1, N):
                lo[i + j] = g.lo(lo[i + j], a[i], a[j])
                hi[i + j] = g.hi(hi[i + j], a[i], a[j])
        for k in range(9):
            if lo[k].op != "zero":
                lo[k] = g.add(lo[k], lo[k])
            if hi[k].op != "zero":
                hi[k] = g.add(hi[k], hi[k])
        for i in range(N):
            lo[2 * i] = g.lo(lo[2 * i], a[i], a[i])
            hi[2 * i] = g.hi(hi[2 * i], a[i], a[i])
        return self.finish(lo, hi)

    def mul121666_add(self, e, d):
        g = self.g
        k = g.const_b(121_666)
        lo = [g.lo(d[i], e[i], k) for i in range(N)]
        hi = [g.hi(g.zero(), e[i], k) for i in range(N)]
        h4 = g.add(hi[4], hi[4])
        return self.reduce([
            g.add(lo[0], self.times19(h4)),
            g.add(lo[1], g.add(hi[0], hi[0])),
            g.add(lo[2], g.add(hi[1], hi[1])),
            g.add(lo[3], g.add(hi[2], hi[2])),
            g.add(lo[4], g.add(hi[3], hi[3])),
        ])


class ModBackend:
    """Field vectors as four integers modulo p, one per lane: what the
    formulas compute, without limbs."""

    def __init__(self, mem, masks):
        self.mem = mem
        self.masks = masks
        self.out = {}

    def load(self, base, slot):
        return list(self.mem[(base, slot)])

    def store(self, base, slot, a):
        self.out[(base, slot)] = [x % P for x in a]

    def mask(self, i):
        return self.masks[i]

    def zero(self):
        return [0] * NL

    def constant(self, lanes):
        return [x % P for x in lanes]

    def reduce(self, z):
        return [x % P for x in z]

    def add_raw(self, a, b):
        return [(x + y) % P for x, y in zip(a, b)]

    def neg16(self, b):
        return [(-x) % P for x in b]

    def blend(self, a, b, lanes):
        return [b[l] if lanes >> l & 1 else a[l] for l in range(NL)]

    def permute(self, a, s):
        return [a[s[l]] for l in range(NL)]

    def blendv(self, a, b, m):
        return list(b) if m else list(a)

    def mul(self, a, b):
        return [x * y % P for x, y in zip(a, b)]

    def square(self, a):
        return [x * x % P for x in a]

    def mul121666_add(self, e, d):
        return [(121_666 * x + y) % P for x, y in zip(e, d)]


# ---------------------------------------------------------------------------
# The formulas, as `f51x4` wrote them
# ---------------------------------------------------------------------------


def negate_lanes(bk, b, lanes):
    return bk.blend(b, bk.neg16(b), lanes)


def add(bk, a, b):
    return bk.reduce(bk.add_raw(a, b))


def completed_to_extended(bk, c):
    left = bk.permute(c, sel(0, 1, 2, 0))  # (X, Y, Z, X)
    right = bk.permute(c, sel(3, 2, 3, 1))  # (T, Z, T, Y)
    return bk.mul(left, right)


def double_formula(bk, p):
    u = bk.permute(p, sel(0, 1, 2, 0))
    w = bk.permute(p, sel(1, 1, 1, 1))
    w = bk.blend(bk.zero(), w, 0b1000)
    v = add(bk, u, w)
    s = bk.square(v)
    a = bk.permute(s, sel(3, 0, 1, 2))
    a = bk.blend(a, bk.add_raw(a, a), 0b1000)
    b = negate_lanes(bk, bk.permute(s, sel(0, 1, 0, 0)), 0b0101)
    c = negate_lanes(bk, bk.permute(s, sel(1, 1, 1, 1)), 0b1001)
    c = bk.blend(c, bk.zero(), 0b0110)
    total = bk.reduce(bk.add_raw(bk.add_raw(a, b), c))
    return completed_to_extended(bk, total)


def add_formula(bk, p, n):
    u = bk.permute(p, sel(1, 1, 3, 2))
    x = bk.permute(p, sel(0, 0, 0, 0))
    x = bk.blend(x, bk.zero(), 0b1100)
    x = negate_lanes(bk, x, 0b0001)
    v = bk.reduce(bk.add_raw(u, x))
    prod = bk.mul(v, n)
    s1 = bk.permute(prod, sel(1, 1, 3, 3))
    s2 = negate_lanes(bk, bk.permute(prod, sel(0, 0, 2, 2)), 0b1001)
    c = bk.reduce(bk.add_raw(s1, s2))
    return completed_to_extended(bk, c)


def negate_formula(bk, n):
    swapped = bk.permute(n, sel(1, 0, 2, 3))
    return bk.reduce(negate_lanes(bk, swapped, 0b0100))


def ladder_formula(bk, state, x1, swap):
    a = bk.permute(state, sel(0, 0, 2, 2))
    b = negate_lanes(bk, bk.permute(state, sel(1, 1, 3, 3)), 0b1010)
    c = bk.reduce(bk.add_raw(a, b))
    l_n = bk.permute(c, sel(1, 0, 3, 2))
    l_m = bk.permute(c, sel(1, 0, 1, 0))
    r_n = bk.permute(c, sel(2, 3, 3, 2))
    r_m = bk.permute(c, sel(2, 3, 1, 0))
    l1 = bk.blendv(l_n, l_m, swap)
    r1 = bk.blendv(r_n, r_m, swap)
    m1 = bk.mul(l1, r1)
    p_ = bk.permute(m1, sel(0, 0, 3, 3))
    q = bk.permute(m1, sel(1, 1, 2, 2))
    q = bk.blend(q, bk.zero(), 0b0100)
    l2 = bk.reduce(bk.add_raw(p_, negate_lanes(bk, q, 0b1001)))
    dd = bk.permute(m1, sel(2, 2, 2, 2))
    e = bk.permute(l2, sel(3, 3, 3, 3))
    t3 = bk.mul121666_add(e, dd)
    r2 = bk.blend(l2, bk.blend(dd, t3, 0b1000), 0b1100)
    m2 = bk.mul(l2, r2)
    m3 = bk.mul(bk.permute(m2, sel(0, 0, 0, 0)), x1)
    s = bk.permute(m2, sel(1, 1, 2, 3))
    return bk.blend(s, m3, 0b0010)


# The kernels: name, documentation, and the formula on the backend. Inputs
# are field vectors at `a` and `b` (slot `i` at word `20 i`), masks words at
# `m`, the result at `o`.

def k_ladder_step(bk):
    """One step of the X25519 ladder, for `ladder_step_into` in `f51x4`: the state
    `(xm, zm, xn, zn)` at `a`, `x1` in every lane at `b`, the swap mask (all
    ones or zero) at `m`, the new state to `o`."""
    bk.store("o", 0, ladder_formula(bk, bk.load("a", 0), bk.load("b", 0), bk.mask(0)))


def k_add(bk):
    """A mixed addition, for `add_into` in `f51x4`: the point at `a`, the operand
    at `b`, the sum to `o`."""
    bk.store("o", 0, add_formula(bk, bk.load("a", 0), bk.load("b", 0)))


def k_double(bk):
    """A doubling, for `double_into` in `f51x4`: the point at `a`, its double to
    `o`."""
    bk.store("o", 0, double_formula(bk, bk.load("a", 0)))


def k_negate(bk):
    """The operand of `-N`, for `Ifma::negate` in `f51x4`: `N` at `a`, the
    result to `o`."""
    bk.store("o", 0, negate_formula(bk, bk.load("a", 0)))


def k_select(bk):
    """The constant-time table selection, for `select_into` in `f51x4`: eight
    operands at `a`, slots 0 to 7; at `m`, eight masks, mask `i` set for the
    entry the digit's magnitude names, and the sign's mask ninth; the
    selected operand, negated under the sign's mask, to `o`. With no entry's
    mask set, the identity's operand `(1, 1, 0, 2)`."""
    out = bk.constant((1, 1, 0, 2))
    for i in range(8):
        out = bk.blendv(out, bk.load("a", i), bk.mask(i))
    neg = negate_formula(bk, out)
    bk.store("o", 0, bk.blendv(out, neg, bk.mask(8)))


def k_mul(bk):
    """Lane-wise `a * b`, for the tests."""
    bk.store("o", 0, bk.mul(bk.load("a", 0), bk.load("b", 0)))


def k_square(bk):
    """Lane-wise `a^2`, for the tests."""
    bk.store("o", 0, bk.square(bk.load("a", 0)))


# name, function, input slots per base, masks, output slots
KERNELS = [
    ("ladder_step", k_ladder_step, {"a": 1, "b": 1}, 1),
    ("add", k_add, {"a": 1, "b": 1}, 0),
    ("double", k_double, {"a": 1}, 0),
    ("negate", k_negate, {"a": 1}, 0),
    ("select", k_select, {"a": 8}, 9),
    ("mul", k_mul, {"a": 1, "b": 1}, 0),
    ("square", k_square, {"a": 1}, 0),
]
TEST_ONLY = {"mul", "square"}
# The Edwards operations serve the `std` tables and the probes; a `no_std`
# build uses only the ladder. Negation serves only `std` verification, which
# no probe reaches.
STD_ONLY = {"add", "double", "select"}
STD_ONLY_NO_PROBE = {"negate"}


# ---------------------------------------------------------------------------
# Build and check
# ---------------------------------------------------------------------------


def build(name, fn):
    g = G.Graph(f"f51x4_{name}")
    fn(GraphBackend(g))
    order = G.schedule(g)
    al = G.Alloc(g, order)
    prog = al.run()
    return g, prog, al.nspill


def value(limbs):
    return sum(int(x) << (51 * k) for k, x in enumerate(limbs))


def random_limbs(rng, extreme):
    if extreme == 1:
        return [M52] * N
    if extreme == 2:
        return [0] * N
    if extreme == 3:
        return [rng.choice((0, M52)) for _ in range(N)]
    return [rng.randrange(M52 + 1) for _ in range(N)]


def check(name, fn, prog, ins, nmasks, trials):
    rng = random.Random(sum(map(ord, name)))
    for t in range(trials):
        extreme = t % 4 if t < 40 else 0
        mem = {}
        meaning = {}
        for base, nslots in ins.items():
            for slot in range(nslots):
                lanes = [random_limbs(rng, (extreme + l) % 4 if extreme else 0) for l in range(NL)]
                for k in range(N):
                    mem[(base, 32 * (slot * N + k))] = [lanes[l][k] for l in range(NL)]
                meaning[(base, slot)] = [value(x) % P for x in lanes]
        masks = [rng.getrandbits(1) for _ in range(nmasks)]
        if name == "select" and t % 3:
            # One entry, or none, as the digit gives.
            hit = rng.randrange(9)
            masks = [int(i == hit) for i in range(8)] + [rng.getrandbits(1)]
        for i, m in enumerate(masks):
            mem[("m", 8 * i)] = M64 if m else 0
        G.Sim(mem).run_lanes(prog)
        mb = ModBackend(meaning, masks)
        fn(mb)
        for (base, slot), want in mb.out.items():
            got = []
            for l in range(NL):
                limbs = [mem[(base, 32 * (slot * N + k))][l] for k in range(N)]
                for k, x in enumerate(limbs):
                    assert 0 <= x <= M52, f"{name}: trial {t} output limb {k} = {x:#x} outside the contract"
                got.append(value(limbs) % P)
            assert got == want, f"{name}: trial {t} differs\n{got}\n{want}"


def main():
    check_only = "--check" in sys.argv
    trials = 400
    for a in sys.argv[1:]:
        if a.startswith("--trials="):
            trials = int(a.split("=")[1])
    G.SCHED = "height"
    results = {}
    for name, fn, ins, nmasks in KERNELS:
        g, prog, nspill = build(name, fn)
        check(name, fn, prog, ins, nmasks, trials)
        n_ifma = sum(1 for q in prog if q[0] in ("lo", "hi"))
        print(f"f51x4 {name}: {len(prog)} instructions, {n_ifma} IFMA, {nspill} spills, "
              f"critical path {G.estimate(prog, False)}, with pipes {G.estimate(prog)} cycles", file=sys.stderr)
        results[name] = (g, prog, nspill)
    print("all kernels agree with the field arithmetic", file=sys.stderr)
    if check_only:
        return
    write_rust(sys.argv[1], results)


FEATURES = "AVX2, AVX-512F, AVX-512VL, AVX-512DQ and AVX-512 IFMA"


def write_rust(path, results):
    out = []
    w = out.append
    w("//! The four-lane GF(2^255 - 19) operations of `super::f51x4` on AVX-512")
    w("//! IFMA, each one `asm!` block.")
    w("//!")
    w("//! GENERATED by `scripts/gen_f51x4.py`; edit that, not this. The script's")
    w("//! notes say why these are assembly, how the formulas are lowered and")
    w("//! bounded, and how the emitted instructions are checked before they are")
    w("//! written.")
    w("//!")
    w("//! A field vector is 20 words, limb `k` of the four lanes at words")
    w("//! `4k..4k + 4`, every limb below 2^52. Every kernel reads its inputs")
    w("//! through `a` and `b`, its masks through `m` (words, each all ones or")
    w("//! zero), writes its result through `o` and spills through `t`; constants")
    w("//! come from the table. Nothing branches, and every address is one of")
    w("//! those registers plus a constant.")
    w("")
    w("#![allow(clippy::missing_safety_doc)]")
    w("")
    w("use core::arch::asm;")
    w("")
    w("/// The constants, 32-byte aligned for the vector operands.")
    w("#[repr(C, align(32))]")
    w("struct ConstTable<const K: usize>([u64; K]);")
    w("")
    consts = G.Consts()
    for name, _, _, _ in KERNELS:
        G.register_consts(results[name][1], consts)
    words = consts.layout()
    spill = max(results[name][2] for name, _, _, _ in KERNELS)
    w("/// Words of spill space a kernel may use.")
    w(f"pub(crate) const SPILL_WORDS: usize = {max(4, 4 * spill)};")
    w(f"static CONSTS: ConstTable<{len(words)}> = ConstTable([")
    for i in range(0, len(words), 4):
        w("    " + ", ".join(f"0x{x:016x}" for x in words[i:i + 4]) + ",")
    w("]);")
    w("")
    for name, fn, ins, nmasks in KERNELS:
        g, prog, nspill = results[name]
        text = G.to_text(prog, consts)
        used = set()
        for line in text:
            for r in ("a", "b", "m", "o", "t", "c"):
                if "{" + r + "}" in line:
                    used.add(r)
        for line in (fn.__doc__ or "").strip().splitlines():
            w(f"/// {line.strip()}" if line.strip() else "///")
        n_ifma = sum(1 for q in prog if q[0] in ("lo", "hi"))
        w("///")
        w(f"/// {len(prog)} instructions, {n_ifma} of them multiply-adds; {nspill} values spilled.")
        w("///")
        w("/// # Safety")
        w("///")
        ext = G.access_extents(text)
        parts = []
        for base in ("a", "b"):
            if base in ext:
                k = -(-ext[base] // 160)
                parts.append(f"`{base}` must be readable for {20 * k} words")
        if "m" in ext:
            nm = ext['m'] // 8
            parts.append(f"`m` must be readable for {nm} word{'s' if nm != 1 else ''}")
        if "o" in ext:
            parts.append(f"`o` must be writable for {20 * -(-ext['o'] // 160)} words")
        if "t" in ext:
            parts.append(f"`t` must be writable for {ext['t'] // 8} words, within `SPILL_WORDS`")
        outs = [f"`{r}`" for r in ("o", "t") if r in ext]
        safety = (f"The CPU must have {FEATURES}. " + "; ".join(parts) + "."
                  + f" {' and '.join(outs)} must not overlap the inputs"
                  + (" or each other." if len(outs) > 1 else "."))
        for line in textwrap.wrap(safety, 76):
            w(f"/// {line}")
        if name in TEST_ONLY:
            w("#[cfg(test)]")
        if name in STD_ONLY:
            w('#[cfg(any(feature = "std", feature = "ct-probes"))]')
        if name in STD_ONLY_NO_PROBE:
            w('#[cfg(feature = "std")]')
        w("#[inline(never)]")
        params = []
        for r in ("a", "b", "m"):
            params.append(f"{'' if r in used else '_'}{r}: *const u64")
        for r in ("o", "t"):
            params.append(f"{'' if r in used else '_'}{r}: *mut u64")
        w(f"pub(crate) unsafe fn {name}({', '.join(params)}) {{")
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
            w("            c = in(reg) CONSTS.0.as_ptr(),")
        regs = ", ".join(f'out("xmm{i}") _' for i in range(16))
        w(f"            {regs},")
        w("            options(nostack, preserves_flags),")
        w("        );")
        w("    }")
        w("}")
        w("")
    open(path, "w", newline="\n").write("\n".join(out))
    import subprocess
    subprocess.run(["rustfmt", "--edition", "2021", path], check=True)


if __name__ == "__main__":
    main()
