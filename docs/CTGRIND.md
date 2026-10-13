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

Branches and addresses reported, IronCrypto at the commit this file was
written with, Graviola 0.4.1, both x86-64, rustc 1.99.0, LTO.

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
| P-256 ECDSA sign | 8 | 6 | range and zero checks on key and nonce candidates, and r = 0, s = 0, as RFC 6979 and FIPS 186-5 allow; **and one in the nonce inversion, below** |
| P-384 ECDSA sign | 7 | -- | as P-256 |
| Ed25519 sign | **9** | 0 | **a real finding, below** |
| ML-KEM-768 key generation | 27 | -- | sampling the matrix from its seed, which is public: it is in the encapsulation key |
| ML-KEM-768 encapsulate, decapsulate | 0, 0 | 45 + 27 address (decapsulate) | Graviola's are the same matrix sampling, reached because its decapsulation key could only be marked through the seed it is made from |
| ML-DSA-65 sign | 11 + 1 address | -- | the rejection loop and the packing of the hint, which FIPS 204 treats as public; sampling the matrix from its public seed; sampling the challenge, which is published in the signature |
| RSA-2048 sign | 371 + 59 address | -- | not yet classifiable: the harness can only mark the whole key, public modulus included, and almost all are loops bounded by the modulus length |

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

Both are being fixed in the P-256 and Curve25519 work streams, and this table
is to be rerun when they land.
