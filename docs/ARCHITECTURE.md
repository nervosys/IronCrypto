# Architecture

## Crate graph

```
                      ic-core        (errors, traits, ct, zeroize, entropy, codec)
                         │
        ┌────────┬───────┼───────┬──────────┐
     ic-hash  ic-cipher  │    ic-ontology   │
        │        │       │       (registry, query, select, export)
        ├────────┤       │          │
      ic-mac ────┤       │          │
        │        │       │          │
      ic-kdf  ic-drbg  ic-ec        │
        └────────┴───────┴──────────┤
                                 ic-fips     (policy, self-tests, service indicator)
                                    │
                            iron-crypto   (facade + prelude)
                                    │
                                 ic-cli      (icrypto: CLI + MCP server)
```

No crate depends on anything outside this graph. There are no build scripts and
no C. `cargo tree` is the whole picture.

## Design decisions, and what they cost

### Zero dependencies

Every third-party crate is a supply-chain surface, a `no_std` risk, and a
version-conflict source. A cryptography library is exactly where those costs are
least acceptable, so the workspace has none — not even `serde` or `zeroize`. The
price is that JSON serialization, JSON *parsing* (for the MCP server), hex,
base64, and secret erasure are all implemented here. They total a few hundred
lines and each one is directly tested.

### `no_std` first

Every crate is `#![no_std]` unless the `std` feature is on, and `std` only ever
buys `String`-returning conveniences and the OS entropy backend. CI
cross-compiles `iron-crypto` to `thumbv7em-none-eabihf`, `thumbv6m-none-eabi`,
`riscv32imac-unknown-none-elf`, and `wasm32-unknown-unknown`, because a
`--no-default-features` build on a host with `std` available does not actually
prove anything.

### Nothing panics

Every fallible operation returns `ic_core::Result`. There are no `unwrap`s on
caller-controlled input and no indexing that a caller can drive out of bounds.
An agent driving this library in a sandbox should get an `Err`, not an abort.

`ErrorKind` is small, closed, and mirrored into the ontology's error catalog
with recovery semantics attached, so a caller can distinguish "retry",
"re-parameterize", and "stop" without parsing English.

### Constant time by construction, not by inspection

- **AES** computes its S-box algebraically (`x^254` in GF(2^8), then the affine
  map) instead of reading a 256-byte table. No secret ever reaches an address
  bus.
- **GHASH** multiplies bit by bit rather than using a key-derived table.
- **Curve25519** uses a Montgomery ladder with constant-time conditional swaps,
  and Ed25519 uses the complete `add-2008-hwcd-3` formula, so scalar
  multiplication is a single branch-free loop with no exceptional cases.
- **Scalar reduction mod L** is a fixed 512-iteration shift-and-conditional-
  subtract: slower than Barrett, but with no data-dependent control flow and
  short enough to audit by reading.
- **Tag comparison** goes through `ic_core::ct::verify`, which folds differences
  into an accumulator and passes the result through `black_box`.

The cost is throughput, and it is steep: around 1.4 MiB/s for AES-256.

### ...with an accelerated backend where the CPU offers one

On x86-64 with AES-NI and `PCLMULQDQ`, a second backend is selected at runtime,
which moves raw AES from roughly 1.4 MiB/s to the low GiB/s and AES-256-GCM to
around 0.7 GiB/s. Both
instructions have data-independent latency and touch no tables, so the
constant-time property is preserved rather than traded away.

Two design choices keep this from becoming a second thing to trust:

* **Key expansion is not duplicated.** The accelerated backend loads the
  *portable* key schedule into SIMD registers. Expansion happens once per key
  and is not on the hot path, so a second implementation would buy nothing and
  risk a divergence — notably for AES-192, whose SIMD key schedule is the
  fiddliest part of a typical AES-NI implementation.
* **It is differentially tested, not independently trusted.** Every accelerated
  path is asserted equal to the portable one, block for block, across all key
  lengths and every batch boundary; the portable one is validated against the
  published vectors. The accelerated code is an optimization held to the output
  of something already known correct.

Accelerating AES alone would have been nearly pointless: the portable GHASH
costs 128 iterations per block, so it, not the cipher, dominated AES-GCM. That
is why `PCLMULQDQ` GHASH landed alongside AES-NI rather than after it.

`ic_ontology::runtime::backend()` reports which backend is live, and the
selector consults it — so on a machine with AES instructions `recommend` picks
AES-256-GCM, and on one without it picks ChaCha20-Poly1305. The library tells
you which case you are in rather than assuming.

### Secrets are erased

`Zeroizing<T>` wipes on drop via `write_volatile` plus a `compiler_fence`.
Round-key schedules, DRBG state, sponge state, Poly1305 accumulators, and
intermediate buffers all zeroize. AEAD `open_detached` wipes `in_out` before
returning an authentication error, so a caller that ignores the `Result` still
cannot read unauthenticated plaintext.

### The ontology is a peer, not a doc comment

`ic-ontology` does not depend on the implementation crates, and the
implementation crates do not depend on it. They are joined by string identifiers
(`Algorithm::ID`) and held together by tests in `iron-crypto` and `ic-fips`
that assert the join is intact: sizes match, paths resolve, self-tests exist.

That direction of dependency matters. The ontology can describe algorithms that
are not implemented — which is the whole reason a FIPS-constrained agent gets an
honest "not available here" instead of a substitution.

### One implementation behind two front ends

`ic-cli/src/ops.rs` holds every operation. The CLI and the MCP server are thin
shells over it, so `icrypto ontology show sha2-256 --json` and the MCP
`ontology_show` tool return byte-identical data. A human debugging an agent's
behaviour can reproduce it from a shell.

## Where things live

| crate | contents |
|---|---|
| `ic-core` | `Error`/`ErrorKind`, the algorithm traits, `ct`, `Zeroizing`, OS entropy, CPU detection, hex/base64 |
| `ic-hash` | SHA-2 (two shared cores, six variants), SHA-3/SHAKE (one sponge) |
| `ic-mac` | HMAC generic over `Digest`, CMAC generic over `BlockCipher`, KMAC over cSHAKE |
| `ic-cipher` | GF(2^8) arithmetic, AES (portable + AES-NI), SP 800-38A modes, GCM (portable + PCLMULQDQ GHASH), ChaCha20, Poly1305 |
| `ic-cipher::aes::aarch64` | The ARMv8 AES backend, behind the off-by-default `aarch64-crypto` feature. Written and cross-compiled on x86 and never executed by its author; CI's arm64 macOS runner is what exercises it. AES only - there is no PMULL GHASH, so the ontology keeps reporting portable on ARM |
| `ic-cipher::aes::armv8_model` | A software model of AESE/AESMC/AESD/AESIMC from their FIPS 197 definitions, driven by the same macro the real backend expands. Runs everywhere, and is how the ARM round structure is checked on a host with no ARM hardware. It found a wrong decryption key schedule that review did not |
| `ic-kdf` | HKDF, PBKDF2, SP 800-108 counter mode |
| `ic-drbg` | HMAC_DRBG, CTR_DRBG, and `Rng` (OS-seeded, auto-reseeding) |
| `ic-ec` | GF(2^255-19) field, X25519, Ed25519; a limb-generic Montgomery field, one Jacobian group law, ECDSA and ECDH, instantiated for P-256, P-384 and P-521 |
| `ic-rsa` | fixed-capacity bignums, Montgomery modular exponentiation, CRT private operations with output verification, PKCS#1 v1.5 and PSS signatures, Miller-Rabin key generation |
| `ic-json` | an RFC 8259 reader and writer, extracted from the CLI once the test harness needed it too |
| `ic-vectors` | loads test vectors supplied from outside the repository; test-only |
| `ic-mldsa` | ML-DSA-65: ring arithmetic and NTT, rounding and hints (FIPS 204 alg. 35-40), bit packing (alg. 16-21), samplers (alg. 29-34), and key generation, signing and verification. Checked against ACVP ML-DSA-keyGen-FIPS204 and ML-DSA-sigGen-FIPS204. `tests/robustness.rs` separately establishes that verification is total and sound against hostile input, which is a different question from correctness |
| `ic-mlkem` | ML-KEM-768: the ring Z_q[X]/(X^256+1), NTT, packing, samplers, K-PKE and the FO transform. Checked against ACVP ML-KEM-keyGen-FIPS203 and ML-KEM-encapDecap-FIPS203 |
| `ic-pkix` | strict DER reader and writer, PEM, SubjectPublicKeyInfo, PKCS#8, SEC1, Ecdsa-Sig-Value; depends only on `ic-core` and performs no cryptography |
| `ic-ontology` | vocabulary, registry, query, selector, exports, runtime capabilities |
| `ic-ontology::standards` | The standards knowledgebase: the documents the registry cites, and the obligations they impose. Coupled to the code by tests - a met requirement names a file and a symbol, and both must exist |
| `iron-crypto/tests/hostile_input.rs` | Every public entry point that parses attacker-chosen bytes, held to three properties: total (never panics), sound (never accepts a forgery) and deep (enough input reaches the cryptography for the first two to mean something) |
| `ic-fips` | state machine, approved-mode policy, CAST table, service indicator |
| `iron-crypto` | facade, prelude, and the ontology/implementation agreement tests |
| `ic-cli` | JSON reader/writer, shared ops, CLI, MCP server |

## Testing strategy

Three layers, each catching what the others cannot:

1. **Published vectors.** Every primitive is checked against its standard's
   test vectors. This catches implementation errors.
2. **Properties and edge cases.** Streaming matches one-shot at every buffer
   boundary; encryption inverts decryption; tampering is rejected; wrong lengths
   are refused; counters carry correctly; `[L]B` is the identity. This catches
   the bugs that vectors miss because vectors use convenient sizes.
3. **Differential agreement between backends.** Every accelerated path is
   asserted bit-for-bit equal to the portable one it replaces. This is what
   makes hand-written SIMD safe to add to a cryptography library: the fast code
   is never trusted on its own reading.
4. **Cross-layer agreement.** The ontology's declared sizes must equal the
   implementations' constants; every available entry must have a self-test;
   every relation edge must resolve. This catches documentation drift, which is
   the failure mode a self-describing library is most exposed to.

A deliberate choice in layer 1: where a published vector could not be verified
offline, the test was replaced with something honest — an independent
transcription of the specification's pseudocode (HMAC_DRBG), or a reconstruction
from the construction's definition (PBKDF2) — rather than asserting a constant
that might be wrong. `docs/FIPS.md` lists the provenance of every vector,
including the weak ones.
