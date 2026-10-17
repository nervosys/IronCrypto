"""Generate crates/ic-hash/src/sha3/zmm.rs: Keccak-f[1600] over eight
interleaved states, as one `asm!` block, on thirty-two vector registers.

    python scripts/gen_keccak_x86.py crates/ic-hash/src/sha3/zmm.rs

Why assembly: the 25 lanes of the state do not fit the 16 registers the
compiler may use without AVX-512 enabled, and AVX-512 target features are not
stable at this workspace's minimum Rust version. The block names the
registers itself: `zmm0`..`zmm24` hold the state, `zmm25`..`zmm30` are
temporaries. Registers above 15 are not declared clobbered unless the build
has AVX-512F enabled (then they are), because the compiler cannot have a value
in one otherwise.

A round, in place:

  theta   C[x] = A[x,0] ^ ... ^ A[x,4], by two three-input xors each;
          every lane then takes A ^= C[x-1] ^ rol(C[x+1], 1), one
          `vpternlogq` (0x96 is a three-way xor).
  rho+pi  the 24-lane cycle, as in the scalar reference: a lane's old value is
          saved to a temporary, then overwritten by the rotated previous
          value. The two temporaries alternate roles.
  chi     per row, the first two lanes are copied aside and each lane becomes
          `a ^ (!b & c)` in one `vpternlogq` (0xd2).
  iota    one xor with the round constant broadcast from memory.

The loop runs twelve times over two rounds and reads the constants through a
pointer; nothing is indexed by data and nothing branches on it.
"""
import sys

RHO = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]


def rnd(v, rc_off, bcast):
    r = lambda n: f"{v}{n}"
    a = lambda i: r(i)
    C = [r(25 + x) for x in range(5)]
    D = r(30)
    o = []
    o.append("// theta")
    for x in range(5):
        o.append(f"vmovdqa64 {C[x]}, {a(x)}")
        o.append(f"vpternlogq {C[x]}, {a(x + 5)}, {a(x + 10)}, 0x96")
        o.append(f"vpternlogq {C[x]}, {a(x + 15)}, {a(x + 20)}, 0x96")
    for x in range(5):
        o.append(f"vprolq {D}, {C[(x + 1) % 5]}, 1")
        for y in range(5):
            o.append(f"vpternlogq {a(x + 5 * y)}, {C[(x + 4) % 5]}, {D}, 0x96")
    o.append("// rho and pi")
    t, u = r(1), r(25)
    for i in range(24):
        j = PI[i]
        o.append(f"vmovdqa64 {u}, {a(j)}")
        o.append(f"vprolq {a(j)}, {t}, {RHO[i]}")
        # The old lane j is now in u; the next step rotates it. Lane 1's
        # register is read once, at step 0, and written at step 23.
        t, u = u, (r(26) if u == r(25) else r(25))
    o.append("// chi")
    for y in range(5):
        b = [a(5 * y + x) for x in range(5)]
        s0, s1 = r(27), r(28)
        o.append(f"vmovdqa64 {s0}, {b[0]}")
        o.append(f"vmovdqa64 {s1}, {b[1]}")
        o.append(f"vpternlogq {b[0]}, {b[1]}, {b[2]}, 0xd2")
        o.append(f"vpternlogq {b[1]}, {b[2]}, {b[3]}, 0xd2")
        o.append(f"vpternlogq {b[2]}, {b[3]}, {b[4]}, 0xd2")
        o.append(f"vpternlogq {b[3]}, {b[4]}, {s0}, 0xd2")
        o.append(f"vpternlogq {b[4]}, {s0}, {s1}, 0xd2")
    o.append("// iota")
    off = f" + {rc_off}" if rc_off else ""
    o.append(f"vpxorq {a(0)}, {a(0)}, qword ptr [{{rc}}{off}]{{{{{bcast}}}}}")
    return o


def body(v, width_bytes, bcast):
    lines = []
    word = "zmmword" if v == "zmm" else "ymmword"
    for i in range(25):
        off = f" + {width_bytes * i}" if i else ""
        lines.append(f"vmovdqu64 {v}{i}, {word} ptr [{{state}}{off}]")
    lines.append("2:")
    lines += rnd(v, 0, bcast)
    lines += rnd(v, 8, bcast)
    lines += ["add {rc}, 16", "dec {n}", "jnz 2b"]
    for i in range(25):
        off = f" + {width_bytes * i}" if i else ""
        lines.append(f"vmovdqu64 {word} ptr [{{state}}{off}], {v}{i}")
    for i in range(31):
        lines.append(f"vpxord {v}{i}, {v}{i}, {v}{i}")
    lines.append("vzeroupper")
    return lines


def fn(name, v, lanes, doc, feats):
    width = lanes * 8
    bcast = f"1to{lanes}"
    o = []
    o.append(f"/// {doc}")
    o.append("///")
    o.append("/// `state[w][s]` is word `w` of state `s`.")
    o.append("///")
    o.append("/// # Safety")
    o.append("///")
    o.append(f"/// The CPU must support {feats}.")
    o.append("#[allow(unsafe_code)]")
    o.append(f"pub(super) unsafe fn {name}(state: &mut [[u64; {lanes}]; 25]) {{")
    o.append("    let rc = super::RC.as_ptr();")
    o.append("    // SAFETY: the caller guarantees the instructions exist. The block reads and")
    o.append(f"    // writes the {25 * width} bytes of `state`, a live exclusive reference, and reads the")
    o.append("    // 24 round constants from `RC`, a static; twelve passes of two rounds step `rc` by 16 bytes.")
    o.append("    // It names registers 0 to 30 and wipes them; see the module header for the clobbers.")
    o.append("    macro_rules! run {")
    o.append("        ($($more:tt)*) => {")
    o.append("            asm!(")
    for l in body(v, width, bcast):
        if l.startswith("//"):
            o.append(f"                {l}")
        else:
            o.append(f'                "{l}",')
    o.append("                state = in(reg) state.as_mut_ptr(),")
    o.append("                rc = inout(reg) rc => _,")
    o.append("                n = inout(reg) 12usize => _,")
    o.append("                " + " ".join(f'out("xmm{i}") _,' for i in range(16)))
    o.append("                $($more)*")
    o.append("                options(nostack),")
    o.append("            )")
    o.append("        };")
    o.append("    }")
    o.append('    #[cfg(not(target_feature = "avx512f"))]')
    o.append("    // SAFETY: see the comment above the macro: the block touches `state` and `RC`, and the CPU has the instructions.")
    o.append("    unsafe {")
    o.append("        run!()")
    o.append("    }")
    o.append('    #[cfg(target_feature = "avx512f")]')
    o.append("    // SAFETY: as above.")
    o.append("    unsafe {")
    o.append("        run!(" + " ".join(f'out("xmm{i}") _,' for i in range(16, 31)) + ")")
    o.append("    }")
    o.append("}")
    return "\n".join(o)


HEADER = '''//! Keccak-f[1600] over eight interleaved states, in assembly on thirty-two
//! `zmm` registers.
//!
//! GENERATED by `scripts/gen_keccak_x86.py`; edit that, not this.
//!
//! The twenty-five lanes of the state live in `zmm0`..`zmm24` for all
//! twenty-four rounds, with nothing spilled; the intrinsics form in `x86` has
//! sixteen registers and moves part of the state to the stack and back every
//! round. The same assembly on `ymm`, four states wide, measured no faster
//! than that form (190 ns against 181 ns), so the four-way path was left as
//! it was; the gain is the width: eight states cost 194 ns. See the generator for the round's structure. Each function is the
//! scalar permutation applied to every lane of the state, and the tests in
//! `super` hold both to it, lane by lane, over states that differ in every
//! word.
//!
//! The AVX-512 target features cannot be named at this workspace's minimum
//! Rust version, so the registers above 15 are used without being declared
//! clobbered: the compiler cannot hold a value in one unless the build enables
//! AVX-512F, and then they are declared.
//!
//! Constant time: shifts, rotates and bitwise operations at fixed registers
//! and fixed offsets, and one loop of fixed length. The registers are zeroed
//! before the block ends.

use core::arch::asm;
'''


def main(path):
    out = [HEADER]
    out.append(fn("permute_x8", "zmm", 8,
                  "Apply Keccak-f[1600] to eight interleaved states, on `zmm0`..`zmm30`.",
                  "AVX-512F"))
    open(path, "w", newline="\n").write("\n".join(out) + "\n")


main(sys.argv[1])
