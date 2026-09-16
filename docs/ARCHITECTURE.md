# Architecture

## Crate graph

```
                      ac-core        (errors, traits, ct, zeroize, entropy, codec)
                         │
        ┌────────┬───────┼───────┬──────────┐
     ac-hash  ac-cipher  │    ac-ontology   │
        │        │       │       (registry, query, select, export)
        ├────────┤       │          │
      ac-mac ────┤       │          │
        │        │       │          │
      ac-kdf  ac-drbg  ac-ec        │
        └────────┴───────┴──────────┤
                                 ac-fips     (policy, self-tests, service indicator)
                                    │
                            agentic-crypto   (facade + prelude)
                                    │
                                 ac-cli      (acrypto: CLI + MCP server)
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
cross-compiles `agentic-crypto` to `thumbv7em-none-eabihf`, `thumbv6m-none-eabi`,
`riscv32imac-unknown-none-elf`, and `wasm32-unknown-unknown`, because a
`--no-default-features` build on a host with `std` available does not actually
prove anything.

### Nothing panics

Every fallible operation returns `ac_core::Result`. There are no `unwrap`s on
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
- **Tag comparison** goes through `ac_core::ct::verify`, which folds differences
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

`ac_ontology::runtime::backend()` reports which backend is live, and the
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

`ac-ontology` does not depend on the implementation crates, and the
implementation crates do not depend on it. They are joined by string identifiers
(`Algorithm::ID`) and held together by tests in `agentic-crypto` and `ac-fips`
that assert the join is intact: sizes match, paths resolve, self-tests exist.

That direction of dependency matters. The ontology can describe algorithms that
are not implemented — which is the whole reason a FIPS-constrained agent gets an
honest "not available here" instead of a substitution.

### One implementation behind two front ends

`ac-cli/src/ops.rs` holds every operation. The CLI and the MCP server are thin
shells over it, so `acrypto ontology show sha2-256 --json` and the MCP
`ontology_show` tool return byte-identical data. A human debugging an agent's
behaviour can reproduce it from a shell.

## Where things live

| crate | contents |
|---|---|
| `ac-core` | `Error`/`ErrorKind`, the algorithm traits, `ct`, `Zeroizing`, OS entropy, CPU detection, hex/base64 |
| `ac-hash` | SHA-2 (two shared cores, six variants), SHA-3/SHAKE (one sponge) |
| `ac-mac` | HMAC generic over `Digest`, CMAC generic over `BlockCipher`, KMAC over cSHAKE |
| `ac-cipher` | GF(2^8) arithmetic, AES (portable + AES-NI), SP 800-38A modes, GCM (portable + PCLMULQDQ GHASH), ChaCha20, Poly1305 |
| `ac-kdf` | HKDF, PBKDF2, SP 800-108 counter mode |
| `ac-drbg` | HMAC_DRBG, CTR_DRBG, and `Rng` (OS-seeded, auto-reseeding) |
| `ac-ec` | GF(2^255-19) field, X25519, Ed25519; a limb-generic Montgomery field, one Jacobian group law, ECDSA and ECDH, instantiated for P-256, P-384 and P-521 |
| `ac-rsa` | fixed-capacity bignums, Montgomery modular exponentiation, CRT private operations with output verification, PKCS#1 v1.5 and PSS signatures, Miller-Rabin key generation |
| `ac-json` | an RFC 8259 reader and writer, extracted from the CLI once the test harness needed it too |
| `ac-vectors` | loads test vectors supplied from outside the repository; test-only |
| `ac-mldsa` | ML-DSA's ring Z_q[X]/(X^256+1) with q = 8380417, its NTT, the rejection-bound check, the rounding/hint functions (FIPS 204 alg. 35-40) and the bit packing (alg. 16-21). No signature scheme yet |
| `ac-mlkem` | ML-KEM-768: the ring Z_q[X]/(X^256+1), NTT, packing, samplers, K-PKE and the FO transform. Experimental |
| `ac-pkix` | strict DER reader and writer, PEM, SubjectPublicKeyInfo, PKCS#8, SEC1, Ecdsa-Sig-Value; depends only on `ac-core` and performs no cryptography |
| `ac-ontology` | vocabulary, registry, query, selector, exports, runtime capabilities |
| `ac-fips` | state machine, approved-mode policy, CAST table, service indicator |
| `agentic-crypto` | facade, prelude, and the ontology/implementation agreement tests |
| `ac-cli` | JSON reader/writer, shared ops, CLI, MCP server |

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
