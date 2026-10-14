# Secret-dependence under Valgrind

`ctgrind/` drives each public operation of IronCrypto, and the same operations
of Graviola 0.4.1 for comparison, under Valgrind memcheck with the caller's
secrets marked *undefined*. Memcheck then reports every conditional jump and
every memory address that depends on them: the places where control flow or
the access pattern was a function of a secret. It is Adam Langley's ctgrind,
done with memcheck alone and Valgrind client requests written as the
instruction sequence from `valgrind.h`, so the harness has no dependency for
it.

```console
$ scripts/ctgrind.sh            # Linux x86-64; valgrind on PATH
```

Two positive controls run first, a loop whose trip count is a secret and a
table read at a secret index. The script stops if either is not reported,
because a clean run means nothing until the detector has detected something.
The first version of the branch control was an `if` that LLVM turned into a
conditional move, and it was not reported: that is why it is now a loop.

The binary is static (musl): memcheck needs function redirections in the
dynamic loader, and a distribution's stripped `ld.so` stops it at startup.
Valgrind reports CPUID without AVX-512, so paths behind runtime detection of it
are not run; Graviola is built with its own `VALGRIND_BUG_494162` switch,
which lets it start without the ADX bit Valgrind does not report.

## What it is and is not

A report is a branch or address that depends on a secret in the compiled code
of this build. That is strictly more than the source shows -- the first real
finding below is in source that is branch-free -- and less than a timing
proof: variable-latency instructions are invisible to it, and so is anything
the run did not reach. It complements `scripts/check-ct.py`, which gates fixed
probes on four targets, and `ic timing`, which measures.

## Results, 2026-10-13

Branches and addresses reported, IronCrypto at master 5f369cc and again at 89b34c2, with the same counts (after the
Curve25519, P-256 and P-384 work merged), Graviola 0.4.1, both x86-64, rustc
1.99.0, LTO. Both positive controls were reported.

| operation | IronCrypto | Graviola | classification |
|---|---|---|---|
| AES-256-GCM seal | 0 | 0 | |
| AES-256-GCM open | 1 | -- | the tag comparison's verdict: public once decided |
| ChaCha20-Poly1305 seal | 0 | 0 | |
| HMAC-SHA-256 | 0 | 0 | |
| HKDF-SHA-256 | 0 | -- | |
| SHA-256, SHA-512, SHA3-256 | 0 | 0 (SHA-256) | |
| X25519 | 1 | 1 | both: the all-zero shared secret check, a refusal that is public |
| P-256 ECDH | 3 | 3 | both: the private scalar's range check, and the result's identity check; IronCrypto also the zero check |
| P-256 ECDSA sign | 7 (8 before the fix) | 6 | range and zero checks on key and nonce candidates, and r = 0, s = 0, as RFC 6979 and FIPS 186-5 allow; the eighth was in the nonce inversion, below, and is gone |
| P-384 ECDSA sign | 7 | -- | as P-256 |
| Ed25519 sign | 0 (9 before the fix) | 0 | the finding below, fixed |
| ML-KEM-768 key generation | 7 + 6 address | -- | all in `rej_uniform`, sampling the matrix from rho: derived from the secret seed, so marked, but published in the encapsulation key |
| ML-KEM-768 encapsulate, decapsulate | 0, 0 | 45 + 27 address (decapsulate) | Graviola's are the same matrix sampling, reached because its decapsulation key could only be marked through the seed it is made from |
| ML-DSA-65 sign | 11 + 1 address | -- | the rejection loop and the packing of the hint, which FIPS 204 treats as public; sampling the matrix from its public seed; sampling the challenge, which is published in the signature |
| RSA-2048 sign | 1 (315 + 15 address with the whole key marked) | -- | the verdict of the fault check after signing, that the CRT result `m` satisfies `m^e = c` (`ic-rsa/src/key.rs`, `crt_private`, line 432): it decides only whether the signature is released or withheld, which the caller sees, so it is public once decided, like AES-GCM's tag verdict. The case marks `d`, both primes with their Montgomery constants, and dP, dQ and qInv, and leaves n, e and the limb widths defined. Under Valgrind this is the portable exponentiation, since CPUID does not report ADX; the row below forces the ADX path |
| RSA-2048 sign, MULX/ADX path forced (`ic-rsa-2048-sign-adx`) | 1, the same verdict at the same line | -- | the same case and marking, with `ic_rsa::ct_probes::with_forced_adx` taking the `MULX`/`ADCX`/`ADOX` Montgomery product whatever CPUID says. Valgrind executes those instructions. Callgrind counts 2607 calls into `mont_mul_adx` in this case and none in `ic-rsa-2048-sign`, so the path ran. Rerun 2026-10-13 after the backend's rewrite into eight-word blocks and straight-line 1024-bit kernels: the same 1 here and 1 in `ic-rsa-2048-sign`, both controls reported (2 branches, 1 address); Callgrind counts 2054 calls into `mont_sqr_16`, 534 into `mont_mul_16`, and 16 and 3 into `mont_sqr_8n` and `mont_mul_8n` (the 2048-bit check after signing), and none of them in `ic-rsa-2048-sign`. IFMA is not covered here: Valgrind reports no AVX-512. The compiled-code gate reads it instead: the IFMA product (`ct_rsa_ifma_amm_2048`, docs/CONSTANT_TIME.md, "Loops on x86-64") and the IFMA exponentiation as a whole at 1024 and 2048 bits (`ct_rsa_ifma_pow_1024`, `ct_rsa_ifma_pow_2048`, "The IFMA exponentiation") |

### Findings

- **Ed25519: `scalar::conditional_subtract_l` compiled to a branch.** The
  source computes a borrow and turns it into a mask; with LTO, rustc 1.99
  emitted `js` on the borrow's sign instead. So whether a secret scalar
  (the nonce, and S) was at least L decided a jump, in signing. It is the
  pattern the compiled-code gate exists for, in code it did not probe.
- **P-256 and P-384: a report in the scalar inversion's `pow`.** The source
  branches only on the bits of the public exponent n - 2, and Valgrind traces
  the undefined bits to the secret. Either the compiler built the condition
  from secret data or memcheck is imprecise about `bt`; the inversion is to
  be made branch-free by construction either way.

- **Ed25519, fixed 2026-10-13.** The borrow and the mask now pass through
  `black_box`, and the reduction is straight-line; rerun, Ed25519 signing
  reports 0. `scripts/check-ct.py` now probes the reduction on all four
  targets, and fails on them with the barriers removed; see
  docs/CONSTANT_TIME.md. Valgrind runs the portable Curve25519 field only,
  since it hides ADX from CPUID and the MULX/ADX field is chosen by CPUID;
  that field is held by the compiled-code probes instead. That includes its
  signing table read, X25519's doubling step and the packed divstep
  inversion added later the same day (`ct_ed25519_fe64_select`,
  `ct_x25519_fe64_double`, `ct_fe64_invert`; docs/CONSTANT_TIME.md,
  "Curve25519 without AVX-512").
- **P-256 and P-384, fixed.** Exponentiation is now a fixed four-bit window
  whose table is read by masked scan, with no branch on the exponent, and on
  64-bit targets P-256 inverts by branch-free divsteps instead. Rerun on master
  after the merge: P-256 ECDH 3, P-256 signing 7, P-384 signing 7, each
  report one of the classified checks in the table above. One of P-256's
  is in `to_affine_x`, which also inverts; its line is the identity test on
  the result, not the inversion. See `docs/CONSTANT_TIME.md`.
