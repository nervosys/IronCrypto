//! The field operations of [`super::Fe64`] as assembly text.
//!
//! Each macro expands to a string literal: a straight-line run of
//! instructions that reads its operands from, and writes its result to,
//! 32-byte slots at fixed offsets from `rdi`. A curve operation is then one
//! `asm!` block made by concatenating these, so its intermediate values move
//! between slots with nothing in between -- no compiler-placed moves, no
//! address arithmetic, no spills. That glue was about a quarter of the
//! instructions in a ladder step written as one block per field operation.
//!
//! Register contract, for every macro: `rdi` is the base and is preserved;
//! `rax`, `rcx`, `rdx`, `rsi` and `r8`-`r15` are clobbered; the flags are
//! clobbered. No macro branches, indexes memory by data, or touches memory
//! outside the slots it names.
//!
//! The arithmetic is exactly that of the methods on `Fe64` -- the same
//! instructions, with memory operands -- and the tests in `super` compare
//! blocks built from these against those methods.

/// `[d] = [a] * [b]`, as [`super::Fe64::mul`].
macro_rules! fe_mul {
    ($d:literal, $a:literal, $b:literal) => {
        concat!(
            // Row 0: a * b0 into r8..r12.
            "mov rdx, qword ptr [rdi + ",
            $b,
            "]\n",
            "mulx r9, r8, qword ptr [rdi + ",
            $a,
            "]\n",
            "mulx r10, rax, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "add r9, rax\n",
            "mulx r11, rax, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "adc r10, rax\n",
            "mulx r12, rax, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "adc r11, rax\n",
            "adc r12, 0\n",
            // Row 1: a * b1 into r9..r13, rsi zero.
            "mov rdx, qword ptr [rdi + ",
            $b,
            " + 8]\n",
            "xor esi, esi\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            "]\n",
            "adcx r9, rax\n",
            "adox r10, rcx\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "adcx r10, rax\n",
            "adox r11, rcx\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx r13, rax, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "adcx r12, rax\n",
            "adox r13, rsi\n",
            "adcx r13, rsi\n",
            // Row 2: a * b2 into r10..r14.
            "mov rdx, qword ptr [rdi + ",
            $b,
            " + 16]\n",
            "xor esi, esi\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            "]\n",
            "adcx r10, rax\n",
            "adox r11, rcx\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "adcx r12, rax\n",
            "adox r13, rcx\n",
            "mulx r14, rax, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "adcx r13, rax\n",
            "adox r14, rsi\n",
            "adcx r14, rsi\n",
            // Row 3: a * b3 into r11..r15.
            "mov rdx, qword ptr [rdi + ",
            $b,
            " + 24]\n",
            "xor esi, esi\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            "]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "adcx r12, rax\n",
            "adox r13, rcx\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "adcx r13, rax\n",
            "adox r14, rcx\n",
            "mulx r15, rax, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "adcx r14, rax\n",
            "adox r15, rsi\n",
            "adcx r15, rsi\n",
            fe_reduce_store!($d),
        )
    };
}

/// `[d] = [a]^2`, as [`super::Fe64::square`].
macro_rules! fe_sqr {
    ($d:literal, $a:literal) => {
        concat!(
            // a0 * (a1, a2, a3) into r9..r12.
            "mov rdx, qword ptr [rdi + ",
            $a,
            "]\n",
            "mulx r10, r9, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "mulx r11, rax, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "add r10, rax\n",
            "mulx r12, rax, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "adc r11, rax\n",
            "adc r12, 0\n",
            // a1 * (a2, a3) into r11..r13, rsi zero.
            "mov rdx, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "xor esi, esi\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx r13, rax, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "adcx r12, rax\n",
            "adox r13, rsi\n",
            "adcx r13, rsi\n",
            // a2 * a3 into r13..r14.
            "mov rdx, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "mulx r14, rax, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "add r13, rax\n",
            "adc r14, rsi\n",
            // Double (CF) and add the squares (OF).
            "mov rdx, qword ptr [rdi + ",
            $a,
            "]\n",
            "mulx rcx, r8, rdx\n",
            "xor r15d, r15d\n",
            "adcx r9, r9\n",
            "adox r9, rcx\n",
            "mov rdx, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "mulx rcx, rax, rdx\n",
            "adcx r10, r10\n",
            "adox r10, rax\n",
            "adcx r11, r11\n",
            "adox r11, rcx\n",
            "mov rdx, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "mulx rcx, rax, rdx\n",
            "adcx r12, r12\n",
            "adox r12, rax\n",
            "adcx r13, r13\n",
            "adox r13, rcx\n",
            "mov rdx, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "mulx rcx, rax, rdx\n",
            "adcx r14, r14\n",
            "adox r14, rax\n",
            "adcx r15, r15\n",
            "adox r15, rcx\n",
            fe_reduce_store!($d),
        )
    };
}

/// Fold the 512-bit `r15..r8` to four limbs and store them at `[d]`: the
/// reduction [`super::Fe64::mul`] and [`super::Fe64::square`] end with.
macro_rules! fe_reduce_store {
    ($d:literal) => {
        concat!(
            "mov edx, 38\n",
            "xor esi, esi\n",
            "mulx rcx, rax, r12\n",
            "adcx r8, rax\n",
            "adox r9, rcx\n",
            "mulx rcx, rax, r13\n",
            "adcx r9, rax\n",
            "adox r10, rcx\n",
            "mulx rcx, rax, r14\n",
            "adcx r10, rax\n",
            "adox r11, rcx\n",
            "mulx r12, rax, r15\n",
            "adcx r11, rax\n",
            "adox r12, rsi\n",
            "adcx r12, rsi\n",
            // Everything from bit 255 up, at most 77, folded as 19 times
            // itself; the sum is below 2^255 + 19 * 77 and cannot carry out.
            "shld r12, r11, 1\n",
            "btr r11, 63\n",
            "imul r12, r12, 19\n",
            "add r8, r12\n",
            "adc r9, rsi\n",
            "adc r10, rsi\n",
            "adc r11, rsi\n",
            "mov qword ptr [rdi + ",
            $d,
            "], r8\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 8], r9\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 16], r10\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 24], r11\n",
        )
    };
}

/// `[d] = [a] + [b]`, as [`super::Fe64::add`].
#[cfg(any(feature = "std", feature = "ct-probes"))]
macro_rules! fe_add {
    ($d:literal, $a:literal, $b:literal) => {
        concat!(
            "mov r8, qword ptr [rdi + ",
            $a,
            "]\n",
            "add r8, qword ptr [rdi + ",
            $b,
            "]\n",
            "mov r9, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "adc r9, qword ptr [rdi + ",
            $b,
            " + 8]\n",
            "mov r10, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "adc r10, qword ptr [rdi + ",
            $b,
            " + 16]\n",
            "mov r11, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "adc r11, qword ptr [rdi + ",
            $b,
            " + 24]\n",
            "sbb rax, rax\n",
            "and eax, 38\n",
            "add r8, rax\n",
            "adc r9, 0\n",
            "adc r10, 0\n",
            "adc r11, 0\n",
            "sbb rax, rax\n",
            "and eax, 38\n",
            "add r8, rax\n",
            "mov qword ptr [rdi + ",
            $d,
            "], r8\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 8], r9\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 16], r10\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 24], r11\n",
        )
    };
}

/// `[d] = [a] - [b]`, as [`super::Fe64::sub`].
#[cfg(any(feature = "std", feature = "ct-probes"))]
macro_rules! fe_sub {
    ($d:literal, $a:literal, $b:literal) => {
        concat!(
            "mov r8, qword ptr [rdi + ",
            $a,
            "]\n",
            "sub r8, qword ptr [rdi + ",
            $b,
            "]\n",
            "mov r9, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "sbb r9, qword ptr [rdi + ",
            $b,
            " + 8]\n",
            "mov r10, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "sbb r10, qword ptr [rdi + ",
            $b,
            " + 16]\n",
            "mov r11, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "sbb r11, qword ptr [rdi + ",
            $b,
            " + 24]\n",
            "sbb rax, rax\n",
            "and eax, 38\n",
            "sub r8, rax\n",
            "sbb r9, 0\n",
            "sbb r10, 0\n",
            "sbb r11, 0\n",
            "sbb rax, rax\n",
            "and eax, 38\n",
            "sub r8, rax\n",
            "mov qword ptr [rdi + ",
            $d,
            "], r8\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 8], r9\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 16], r10\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 24], r11\n",
        )
    };
}

/// `[d] = 121666 * [a] + [b]`: [`super::Fe64::mul121666`] and an addition in
/// one pass, since the Montgomery ladder only ever adds to that product.
macro_rules! fe_mul121666_add {
    ($d:literal, $a:literal, $b:literal) => {
        concat!(
            "mov edx, 121666\n",
            "mulx r9, r8, qword ptr [rdi + ",
            $a,
            "]\n",
            "mulx r10, rax, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "add r9, rax\n",
            "mulx r11, rax, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "adc r10, rax\n",
            "mulx rcx, rax, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "adc r11, rax\n",
            "adc rcx, 0\n",
            "add r8, qword ptr [rdi + ",
            $b,
            "]\n",
            "adc r9, qword ptr [rdi + ",
            $b,
            " + 8]\n",
            "adc r10, qword ptr [rdi + ",
            $b,
            " + 16]\n",
            "adc r11, qword ptr [rdi + ",
            $b,
            " + 24]\n",
            "adc rcx, 0\n",
            // The fifth limb is below 2^17 + 2; fold it as 38 times itself,
            // then once more for the carry that can make.
            "imul rcx, rcx, 38\n",
            "add r8, rcx\n",
            "adc r9, 0\n",
            "adc r10, 0\n",
            "adc r11, 0\n",
            "sbb rax, rax\n",
            "and eax, 38\n",
            "add r8, rax\n",
            "mov qword ptr [rdi + ",
            $d,
            "], r8\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 8], r9\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 16], r10\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 24], r11\n",
        )
    };
}

/// `[d] = [b]` if the flags say not-zero, else `[a]`, by `CMOV`: both are
/// read whichever is chosen. The flags must be set by the caller, and only
/// moves -- which leave them alone -- run in between.
macro_rules! fe_cmovnz {
    ($d:literal, $a:literal, $b:literal) => {
        concat!(
            "mov rax, qword ptr [rdi + ",
            $a,
            "]\n",
            "cmovnz rax, qword ptr [rdi + ",
            $b,
            "]\n",
            "mov qword ptr [rdi + ",
            $d,
            "], rax\n",
            "mov rax, qword ptr [rdi + ",
            $a,
            " + 8]\n",
            "cmovnz rax, qword ptr [rdi + ",
            $b,
            " + 8]\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 8], rax\n",
            "mov rax, qword ptr [rdi + ",
            $a,
            " + 16]\n",
            "cmovnz rax, qword ptr [rdi + ",
            $b,
            " + 16]\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 16], rax\n",
            "mov rax, qword ptr [rdi + ",
            $a,
            " + 24]\n",
            "cmovnz rax, qword ptr [rdi + ",
            $b,
            " + 24]\n",
            "mov qword ptr [rdi + ",
            $d,
            " + 24], rax\n",
        )
    };
}

/// `[d] = [a] + [b]` with one carry fold rather than two.
///
/// Correct when `a + b < 2^257 - 38`, so that folding the carry cannot carry
/// again: true whenever one operand is below `2^256 - 38`, and in particular
/// whenever both are outputs of [`fe_mul!`] or [`fe_sqr!`], which are below
/// `2^255 + 19 * 77`. The ladder step uses it only on such operands.
macro_rules! fe_add_once {
    ($d:literal, $a:literal, $b:literal) => {
        concat!(
            "mov r8, qword ptr [rdi + ",
            $a,
            "]
",
            "add r8, qword ptr [rdi + ",
            $b,
            "]
",
            "mov r9, qword ptr [rdi + ",
            $a,
            " + 8]
",
            "adc r9, qword ptr [rdi + ",
            $b,
            " + 8]
",
            "mov r10, qword ptr [rdi + ",
            $a,
            " + 16]
",
            "adc r10, qword ptr [rdi + ",
            $b,
            " + 16]
",
            "mov r11, qword ptr [rdi + ",
            $a,
            " + 24]
",
            "adc r11, qword ptr [rdi + ",
            $b,
            " + 24]
",
            "sbb rax, rax
",
            "and eax, 38
",
            "add r8, rax
",
            "adc r9, 0
",
            "adc r10, 0
",
            "adc r11, 0
",
            "mov qword ptr [rdi + ",
            $d,
            "], r8
",
            "mov qword ptr [rdi + ",
            $d,
            " + 8], r9
",
            "mov qword ptr [rdi + ",
            $d,
            " + 16], r10
",
            "mov qword ptr [rdi + ",
            $d,
            " + 24], r11
",
        )
    };
}

/// `[d] = [a] - [b]` with one borrow fold rather than two.
///
/// Correct when `b - a < 2^256 - 38`, so that taking the borrow back out
/// cannot borrow again: true whenever `b` is below `2^256 - 38`, and in
/// particular whenever it is an output of [`fe_mul!`] or [`fe_sqr!`].
macro_rules! fe_sub_once {
    ($d:literal, $a:literal, $b:literal) => {
        concat!(
            "mov r8, qword ptr [rdi + ",
            $a,
            "]
",
            "sub r8, qword ptr [rdi + ",
            $b,
            "]
",
            "mov r9, qword ptr [rdi + ",
            $a,
            " + 8]
",
            "sbb r9, qword ptr [rdi + ",
            $b,
            " + 8]
",
            "mov r10, qword ptr [rdi + ",
            $a,
            " + 16]
",
            "sbb r10, qword ptr [rdi + ",
            $b,
            " + 16]
",
            "mov r11, qword ptr [rdi + ",
            $a,
            " + 24]
",
            "sbb r11, qword ptr [rdi + ",
            $b,
            " + 24]
",
            "sbb rax, rax
",
            "and eax, 38
",
            "sub r8, rax
",
            "sbb r9, 0
",
            "sbb r10, 0
",
            "sbb r11, 0
",
            "mov qword ptr [rdi + ",
            $d,
            "], r8
",
            "mov qword ptr [rdi + ",
            $d,
            " + 8], r9
",
            "mov qword ptr [rdi + ",
            $d,
            " + 16], r10
",
            "mov qword ptr [rdi + ",
            $d,
            " + 24], r11
",
        )
    };
}
