# Security policy

## Reporting a vulnerability

Report privately, not as a public issue. Open a GitHub security advisory on
`nervosys/IronCrypto`, or contact the maintainers directly if you cannot.

Useful reports include the version or commit, what you observed, and the
smallest input that shows it. A failing test is the most useful form. If you
believe the finding is exploitable, say what you think an attacker gains — that
is what decides how fast it moves, and it is the part nobody else can supply.

You do not need a working exploit to report something. A convincing argument
that a bound is wrong, a comparison is not constant time, or a validation step
is missing is worth reporting on its own.

## What this project can and cannot claim

**IronCrypto is not FIPS 140-3 validated.** It has no CMVP certificate.
`ic_ontology::runtime::has("fips-validated")` returns `false`, and a test
asserts it keeps returning `false` until a certificate exists. The library
implements FIPS 140-3's *operational discipline* — an approved-mode policy,
self-tests before first use, a latching error state, service indicators — which
is a prerequisite for pursuing validation and is not validation. Do not use it
where a contract requires validated cryptography; CMMC `SC.L2-3.13.11` is
recorded as unmet for exactly this reason.

**The post-quantum schemes are vector-tested.** This section used to say that
ML-KEM-768, ML-DSA-65 and AES-GCM-SIV were experimental and checked against
nothing but themselves. That stopped being true when the vectors went in, and
the wording outlived it:

| | checked against |
|---|---|
| ML-KEM-512, -768, -1024 | for each: 25 key generation and 25 encapsulation cases, NIST ACVP FIPS 203 |
| ML-DSA-44, -65, -87 | for each: 25 key generation and 30 signature cases, NIST ACVP FIPS 204 |
| AES-GCM-SIV | 50 cases, RFC 8452 appendix C |

Every case in each parameter set, not a selection, and the ML-DSA signature
cases cover both the deterministic and the hedged path. `testvectors/` records
the provenance down to the upstream commit. All three are `available` in the
ontology and usable in the approved mode; `ic ontology show <id>` is the
current answer and this file is not.

Interoperability is a separate question: matching NIST's vectors shows the
algorithms are right, not that a handshake with some other implementation
completes. For all six parameter sets there is now evidence of that as well,
checked here against OpenSSL 3.5.7. `iron-crypto/tests/openssl_interop.rs` runs
on every build from fixtures OpenSSL produced
(`testvectors/openssl-ml-kem.json`, `testvectors/openssl-ml-dsa.json`):

- Key generation from OpenSSL's seed reproduces OpenSSL's keys, both halves,
  for every set.
- ML-DSA signatures made deterministically here are byte for byte OpenSSL's,
  with and without a context string, and OpenSSL's hedged signatures verify
  here.
- ML-KEM ciphertexts from OpenSSL decapsulate here to OpenSSL's secret.

Two directions need OpenSSL at test time and were checked once by hand
instead, on 2026-09-29: ML-KEM ciphertexts made here decapsulate in OpenSSL to
the same secret, and hedged ML-DSA signatures made here verify in OpenSSL, for
all six sets. `docs/FIPS.md` records how.

Beyond that, IronSocketLayer, a TLS 1.3 stack built on these crates, reports
against OpenSSL 3.5 (nervosys/IronSocketLayer, commit 692e800):

- ML-KEM-1024 key exchange, alone and hybridised with P-384, interoperates in
  both directions.
- ML-DSA-87 certificate chains signed here verify under OpenSSL with
  `-x509_strict`; handshakes using ML-DSA-87 signatures interoperate in both
  directions; OpenSSL-generated ML-DSA-87 keys regenerate the same public key
  here; and OpenSSL's ML-DSA-87 signatures verify here.

Those two items are reported rather than reproduced here: they involve
certificates and handshakes, which this repository does not build.

**Constant time is a property of the compiled code, and on 32-bit RISC-V it
did not hold for the curves or RSA until they moved to 32-bit words.** The
source is written without branches or table indices on secrets, but a compiler
can put them back: a CPU with no conditional-move instruction gets a branch
wherever the optimiser recognises a choice between two values, and on 32-bit
RISC-V rustc builds every 128-bit carry from 32-bit comparisons joined by
branches. The machine code was examined on 2026-09-29, built with rustc 1.98.1
as a downstream crate builds it (release, overflow checks off). Every
conditional branch in the functions below was traced to its source line:

| target | elliptic-curve and RSA arithmetic on secrets |
|---|---|
| x86-64 | no secret-dependent branches found |
| Cortex-M4 (`thumbv7em`) | none found: conditional execution covers the selects |
| Cortex-M0 (`thumbv6m`) | none found. In 0.2.1 and earlier, NIST field subtraction branched on its borrow: 8 branches per P-256 point addition, 6 per doubling |
| 32-bit RISC-V (`riscv32imac`) | none found, since the change below. Before it: 20 per Curve25519 field multiplication and 120 per Edwards doubling; 100 per P-256 point addition, 184 on P-384 and 248 on P-521; 6 in RSA's Montgomery multiplication |

The change: on `riscv32` no arithmetic on a secret uses `u128`.

- **Ed25519 and X25519** use a field of ten limbs of 26 and 25 bits
  (`crates/ic-ec/src/field32.rs`), every product `u32 * u32 -> u64` and every
  carry a shift. Field multiplication, squaring and encoding, the Edwards point
  operations, the fixed-base and windowed multiplications and the X25519
  ladder have no conditional branches at all.
- **The NIST curves** keep their `[u64; N]` Montgomery representation and run
  its additions, subtractions and multiplication on 32-bit words with `u64`
  accumulators (`narrow` in `crates/ic-ec/src/nist/arith.rs`). Point addition
  and doubling on all three curves have no conditional branches.
- **RSA** builds every loop that touches a secret from three word operations
  (`crates/ic-rsa/src/uint.rs`) whose `riscv32` form uses 32-bit halves.
  Montgomery multiplication, the exponentiation, the CRT reduction and
  recombination -- including `q * h`, which is secret -- branch only on the
  key's width, loop counters and bounds.

What branches remain were each traced to a public value: lengths of caller
buffers; decoding a public key or signature; the variable-time verification
paths over public values; the public exponents of inversion and square roots;
RFC 6979's rejection of a nonce candidate, which reveals how many were drawn
and nothing of the one kept; the zero checks ECDSA and X25519 require; loop
counters and widths. Nothing calls compiler-runtime arithmetic, and `memcmp`
is reached only on public data.

The 32-bit forms compute bit for bit what the 64-bit ones do, and are tested
that way: under ordinary test each is compared with its 64-bit counterpart
directly, and `--cfg ic_limb32` selects them on any host, where every
Curve25519, NIST and RSA vector and the rustls suite pass through them. The
64-bit targets are unchanged, and were measured at parity.

Poly1305 and POLYVAL were checked on both 32-bit targets, and their only
branches are on public lengths and loop indices. AES, ChaCha20, SHA-2, SHA-3,
ML-KEM and ML-DSA were not examined at this level.

**The hex and Base64 codecs branched on secret characters, on every target.**
A PKCS#8 private key in PEM is Base64, and the CLI and MCP server take keys as
hex, so these decode secrets. Their source was branch-free, but each
character's validity was checked at once with an early return, and x86-64,
both Cortex-M cores and 32-bit RISC-V all compiled the OR of the character
classes feeding that check into a chain of short-circuit branches -- which
branch left the chain was the class of the character. The encoders indexed a
64- or 16-entry table with secret bits. Both are the channels Sieck et al.
demonstrated against PEM key decoding ("Util::Lookup", USENIX Security 2021).
Since 2026-09-29 the encoders compute characters arithmetically and the
decoders accumulate validity behind a barrier and reject once, at the end; the
compiled code on all four targets was re-read, and branches only on lengths,
positions, and that final verdict.

The functions examined: NIST field addition, subtraction, Montgomery
multiplication and inversion; point addition and doubling on all three
curves; the windowed scalar multiplication and its table lookup; ECDSA
signing and ECDH; Ed25519's field multiplication, point addition, doubling and
windowed multiplication, signing and X25519; and RSA's Montgomery
multiplication, exponentiation and CRT private operation.
Loop counters with fixed trip counts, and overflow checks that never fire on
valid values, were set aside as not secret-dependent.

**There is no transitive dependency surface.** IronCrypto has zero third-party
dependencies, enforced in CI by a check over `cargo tree`. No advisory against
another crate can apply to it. That is a narrow claim and it is worth being
precise about its limits: it says nothing about defects in IronCrypto's own
code.

**No CVE has been issued against IronCrypto.** At this stage that reflects a
young, privately held project rather than any assurance, and should not be read
as evidence of anything.

## Where the evidence is

Claims in this project are meant to be checkable rather than taken on trust.

| Question | Where it is answered |
|---|---|
| What is verified, and against what oracle? | `docs/FIPS.md` |
| What does a standard require, and does this meet it? | `ic ontology requirements` |
| Which weakness classes and practices does this address? | `ic ontology controls` |
| Why is an algorithm not recommended? | `ic ontology show <id>` |
| Does it match the standard's vectors? | Yes, where vectors exist; see `testvectors/README.md` |
| Does it interoperate with another implementation? | Untested. Vectors are not a handshake |
| What is in the build? | `ic sbom` — CycloneDX, deterministic, regenerate and diff it |

The compliance views are coupled to the code rather than filed beside it: a
control claiming to be met names a file and a symbol, and the tests fail if
either stops existing. That is deliberate — a compliance document that can drift
away from its implementation will, and is then worse than none, because people
believe it.

## Scope

In scope: the algorithms, their encodings, the parsing surface, constant-time
construction, the ontology's accuracy about all of the above.

Also in scope, and newer: `ic-rustls`. It is a rustls `CryptoProvider`, so it
does not implement the TLS or QUIC state machines -- rustls does -- but it does
implement record and packet protection for TLS 1.2, TLS 1.3 and QUIC, and those
are protocol surfaces. Framing bugs there produce records that round-trip
against this crate and interoperate with nothing, or worse, so they are worth
reporting.

Out of scope, because they are not implemented rather than because they do not
matter: certificate path validation, the TLS and QUIC state machines, key
storage, key distribution, and audit logging. If you find that the
documentation implies any of these exist, that is itself a reportable defect.

## Dependencies, and reading a scanner's report about them

The cryptographic crates depend on nothing outside this workspace. `ic-rustls`
is the exception and depends on rustls plus six crates beneath it;
`scripts/no-third-party.sh` asserts that the list is exactly those seven, per
crate, on every build.

`scripts/advisories.sh` pins each of the seven to the version that fixed the
advisories known against it, and runs on every commit. It is offline: it
compares compiled versions against a table, so it gates without reaching the
network. The table carries the date it was last reviewed against RustSec,
because a floor cannot learn about a new advisory by itself.

**A scanner's crate count will not match that seven.** `cargo audit`,
Dependabot and most SCA tools read `Cargo.lock`, which lists what the resolver
considered, not what the compiler builds. A resolved lock file for this
workspace -- generated on demand, not committed, since this is a library --
names eighteen packages that are never compiled: `ring` among them, an
unactivated optional dependency of rustls, along with `cc`, `getrandom`,
`libc`, `wasi` and the `windows-*` family. `cargo tree -i ring` returns
nothing.

So a report listing 43 dependencies is not wrong about the lock file and is not
describing what ships. If one of those eighteen draws an advisory, expect a
finding that does not apply here; confirm it with `cargo tree -i <crate>`
before acting on it, and do not silence it globally, because the same name
would become real if a feature change ever activated it. At the last review
`cargo audit` reported no vulnerabilities at all, so this is a latent reporting
hazard rather than a present one.

## Supported versions

Pre-1.0. Only `master` is supported, and there is no backport policy yet.
