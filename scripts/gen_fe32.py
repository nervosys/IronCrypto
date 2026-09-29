"""Generate the straight-line `mul`, `square` and byte packing in
`crates/ic-ec/src/field32.rs`, checking each against integer arithmetic mod
2^255 - 19 on random operands before printing it.

The generated code is pasted in by hand; run this and compare if either the
radix or those functions change. Standard library only.

    python scripts/gen_fe32.py
"""
import random

P = 2**255 - 19
S = [(51 * i + 1) // 2 for i in range(10)]  # ceil(25.5 i)
W = [26 - (i & 1) for i in range(10)]
assert S == [0, 26, 51, 77, 102, 128, 153, 179, 204, 230]
assert all(S[i] + W[i] == (S[i + 1] if i < 9 else 255) for i in range(10))


def mul_terms():
    cols = []
    for k in range(10):
        terms = []
        for i in range(10):
            for j in range(10):
                if (i + j) % 10 != k:
                    continue
                x = f'a2[{i}]' if (i & 1 and j & 1) else f'a[{i}]'
                y = f'b19[{j}]' if i + j >= 10 else f'b[{j}]'
                terms.append((x, y, i, j))
        cols.append(terms)
    return cols


def sq_terms():
    cols = []
    for k in range(10):
        terms = []
        for i in range(10):
            for j in range(i, 10):
                if (i + j) % 10 != k:
                    continue
                shift = (i != j) + (i & j & 1)
                x = [f'a[{i}]', f'd[{i}]', f'q[{i}]'][shift]
                y = f'a19[{j}]' if i + j >= 10 else f'a[{j}]'
                terms.append((x, y, i, j))
        cols.append(terms)
    return cols


def value(limbs):
    return sum(l << S[i] for i, l in enumerate(limbs))


def evaluate(cols, a, b):
    env = {'a': a, 'b': b, 'a2': [x << (i & 1) for i, x in enumerate(a)],
           'b19': [19 * x for x in b], 'a19': [19 * x for x in a],
           'd': [2 * x for x in a], 'q': [4 * x for x in a]}
    z = [sum(eval(x, env) * eval(y, env) for x, y, _, _ in col) for col in cols]
    return value(z) % P


for _ in range(2000):
    a = [random.getrandbits(W[i]) for i in range(10)]
    b = [random.getrandbits(W[i]) for i in range(10)]
    assert evaluate(mul_terms(), a, b) == value(a) * value(b) % P
    assert evaluate(sq_terms(), a, a) == value(a) ** 2 % P
assert sum(len(c) for c in mul_terms()) == 100
assert sum(len(c) for c in sq_terms()) == 55


def emit(cols):
    out = []
    for k, col in enumerate(cols):
        body = ' + '.join(f'm({x}, {y})' for x, y, _, _ in col)
        out.append(f'        let z{k} = {body};')
    out.append('        carry_reduce([z0, z1, z2, z3, z4, z5, z6, z7, z8, z9])')
    return '\n'.join(out)


def pack():
    # Word w holds bits 32w..32w+31 of the 255-bit value.
    out = []
    for w in range(8):
        parts = []
        lo, hi = 32 * w, 32 * w + 32
        for i in range(10):
            a, b = S[i], S[i] + W[i]
            if b <= lo or a >= hi:
                continue
            if a >= lo:
                parts.append(f't[{i}] << {a - lo}' if a > lo else f't[{i}]')
            else:
                parts.append(f't[{i}] >> {lo - a}')
        out.append('            ' + ' | '.join(parts) + ',')
    return out


# The packing, checked the same way.
for _ in range(2000):
    t = [random.getrandbits(W[i]) for i in range(10)]
    words = [eval(e.strip().rstrip(','), {'t': t}) & 0xFFFFFFFF for e in pack()]
    assert sum(x << (32 * i) for i, x in enumerate(words)) == value(t)

print('// mul')
print(emit(mul_terms()))
print('// square')
print(emit(sq_terms()))
print('// pack')
print('\n'.join(pack()))
