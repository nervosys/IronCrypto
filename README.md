# IronCrypto

**Agentic-first cryptography in pure Rust, with a machine-readable ontology.**

Zero dependencies. No C. No build scripts. `no_std` from the ground up, verified
against ARM Cortex-M, RISC-V, and WebAssembly. Every primitive validated against
its published test vectors. Usable as a [rustls](https://docs.rs/rustls)
provider, so it can carry TLS.

*Zero dependencies* means every crate that implements an algorithm depends on
nothing outside this workspace, checked per crate on each build. The rustls
adapter is the one exception and necessarily so; see
[Supply chain](#supply-chain).

```console
$ icrypto recommend encrypt-message --fips
use: aes-256-gcm
  AES-256-GCM is the approved authenticated cipher and retains 128-bit strength
  against a quantum adversary.
  call: ic_cipher::Aes256Gcm

must observe:
  [critical] Never reuse a (key, nonce) pair.
      Reuse leaks the authentication subkey, allowing forgery of arbitrary
      messages, and XORs the two plaintexts together.
  [serious] Derive the nonce from a strictly increasing counter, or draw 96
      random bits and bound the number of messages per key.
      Random 96-bit nonces collide with meaningful probability past 2^32 messages.

considered and rejected:
  chacha20-poly1305: Not approved for the FIPS approved mode of operation.
  aes-ctr: Unauthenticated; it is the confidentiality half of GCM.
```

---

## Why another crypto library

Most cryptographic failures in production are not broken primitives. They are
*correct primitives used wrongly*: a reused GCM nonce, an unauthenticated CBC
mode, a password fed to a fast hash, a MAC compared with `==`.

Humans learn those rules from documentation. An autonomous agent cannot read
your prose and reliably act on it — so it guesses, and every guess is a chance
to ship something broken.

IronCrypto puts the rules in the same place as the code, as **data**:

```console
$ icrypto ontology show aes-256-gcm --json | jq '.constraints[0]'
{
  "consequence": "Reuse leaks the authentication subkey, allowing forgery of arbitrary messages, and XORs the two plaintexts together.",
  "id": "unique-nonce-per-key",
  "requirement": "Never reuse a (key, nonce) pair.",
  "severity": "critical"
}
```

An agent can refuse to emit code that violates a `critical` constraint. A
reviewer can diff the constraint set. A CI job can assert that nothing in the
codebase uses an algorithm the ontology marks `disallowed`.

### The property that matters most

Never substitute something the caller did not ask for. That has two halves, and
the first is refusing to trade a stated requirement for availability:

```console
$ icrypto recommend sign-data --fips
use: ecdsa-p256-sha256
  ECDSA P-256 is the approved signature scheme. This implementation derives its
  nonce per RFC 6979, so the usual ECDSA nonce-reuse failure cannot occur.
  call: ic_ec::p256::EcdsaP256Sha256

considered and rejected:
  ed25519: Not approved for the FIPS approved mode of operation.
  ml-dsa-65: Post-quantum and implemented, but larger and slower. Pass
    --post-quantum to choose it, and prefer a hybrid with the classical scheme
    over either alone.
  rsa-pss-sha256: Also approved, but slower and far larger at the same strength.
    Choose it only to meet an existing interface.
```

Ed25519 *is* implemented, *is* a signature scheme, and is faster. A library that
optimizes for "always return something" could have returned it, silently missing
the requirement the caller actually stated. Here it is passed over, and named,
so the caller can see the choice rather than infer it.

The second half is refusing outright when nothing fits:

```rust
use ic_ontology::select::{recommend, Intent, NoRecommendation, Policy};

// No hash on offer is this quantum-resistant.
let outcome = recommend(
    Intent::HashData,
    Policy { require_fips: false, min_classical_bits: 0,
             min_quantum_bits: 512, aes_hardware: false },
);
assert_eq!(outcome.unwrap_err(), NoRecommendation::NothingSatisfiesPolicy);
```

An honest "no" is worth more to an autonomous caller than a plausible "yes".

That second example used to be post-quantum key agreement, which was declined
because ML-KEM-768 was implemented and unverified. It is checked against NIST's
ACVP vectors now, so the request has a real answer and the example had to move
to one that still does not.

---

## Install

**IronCrypto is not published.** It is not on crates.io, and this repository is
private, so `iron-crypto = "0.1"` does not resolve — that line used to be here
and it never worked.

Publishing it is an export, and requires notifying BIS and the NSA's ENC
Encryption Request Coordinator first, under 15 CFR 742.15(b). Every crate
carries `publish = false` so that `cargo publish` fails rather than doing it by
accident. See [docs/RELEASING.md](docs/RELEASING.md).

Until then, with access to the repository:

```toml
[dependencies]
iron-crypto = { git = "ssh://git@github.com/nervosys/IronCrypto.git" }
```

Or against a local checkout:

```toml
[dependencies]
iron-crypto = { path = "../IronCrypto/crates/iron-crypto" }
```

```console
$ cargo install --path crates/ic-cli   # the `icrypto` CLI and MCP server
```

## Use

```rust
use iron_crypto::prelude::*;

// Ask what to use, rather than picking a name from memory.
let choice = recommend(Intent::EncryptMessage, Policy::FIPS_APPROVED).unwrap();
assert_eq!(choice.primary.id, "aes-256-gcm");
assert_eq!(choice.primary.rust_path, "ic_cipher::Aes256Gcm");

// Then use it.
let cipher = Aes256Gcm::new(&[0x2a; 32])?;
let mut buf = *b"the payload";
let mut tag = [0u8; 16];
cipher.seal_detached(&nonce, b"context", &mut buf, &mut tag)?;
cipher.open_detached(&nonce, b"context", &mut buf, &tag)?;
# Ok::<(), ic_core::Error>(())
```

## Connect an agent

`icrypto mcp` is a Model Context Protocol server on stdio:

```jsonc
{
  "mcpServers": {
    "iron-crypto": { "command": "icrypto", "args": ["mcp"] }
  }
}
```

| tool | what it answers |
|---|---|
| `crypto_recommend` | "What should I use for X under constraints Y?" |
| `ontology_list` | "What algorithms serve this purpose?" |
| `ontology_show` | "What are the parameter bounds and failure modes?" |
| `ontology_errors` | "What does this error mean and can I retry?" |
| `crypto_capabilities` | "What can this build actually do?" |
| `crypto_selftest` | "Is the module healthy?" |
| `crypto_digest` / `crypto_hmac` / `crypto_seal` / `crypto_random` | primitive operations |

---

## TLS

`ic-rustls` presents IronCrypto to [rustls](https://docs.rs/rustls) as a
`CryptoProvider`:

```rust
let roots = rustls::RootCertStore::empty();
let config = rustls::ClientConfig::builder_with_provider(ic_rustls::arc_provider())
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
# let _ = config;
# Ok::<(), rustls::Error>(())
```

Or `ic_rustls::provider().install_default()` once, for every rustls
configuration in the process.

| | |
|---|---|
| AEAD | AES-128-GCM, AES-256-GCM — TLS 1.3 and TLS 1.2 |
| Hash | SHA-256, SHA-384 |
| MAC | HMAC-SHA256, HMAC-SHA384 |
| KDF | HKDF, as rustls's `HkdfUsingHmac` over the above |
| Signatures | ECDSA P-256/SHA-256, P-384/SHA-384 — verification |
| Key exchange | X25519, ECDH P-256, ECDH P-384 |
| Randomness | SP 800-90A HMAC\_DRBG, OS-seeded |

HKDF is rustls's own extract-and-expand over IronCrypto's HMAC rather than a
second HKDF written for the occasion — HKDF is a construction, HMAC is the
primitive — and the composition is checked against RFC 5869 appendix A.

**It verifies signatures and does not make them.** There is no `KeyProvider`, so
it can authenticate a server and cannot present a certificate of its own.
Loading a private key returns an error saying exactly that, rather than one that
surfaces later somewhere unhelpful.

Also absent: ChaCha20-Poly1305 suites (the cipher exists; the suite is not wired
up), QUIC header protection, and the mismatched ECDSA pairings — a P-256 key
signed with SHA-384, or the reverse. `ic-ec` has no such combination, and
assembling one inside the adapter, out of sight of that crate's vectors, would
be worse than declining the chain.

The record layer is where this crate's own risk lives: the cipher is already
checked against the GCM vectors, and none of that says whether a record is
*framed* right. Wrong additional data, a misplaced tag, a nonce built wrong from
the sequence number — each produces something that round-trips against itself
and interoperates with nothing. So the tests check framing: every single-bit
mutation across a whole record refused, replay at another sequence number
refused, and for TLS 1.2 the content type and version bound into the header.

## What's implemented

Everything below is validated against published test vectors — FIPS 180-4,
FIPS 197, FIPS 202, SP 800-38A/B/D, SP 800-90A, RFC 2104/4231/5869/7748/8032/8439.

| class | algorithms |
|---|---|
| Hashes | SHA-224/256/384/512, SHA-512/224, SHA-512/256, SHA3-224/256/384/512, BLAKE2b |
| SP 800-185 | cSHAKE128/256, KMAC128/256, TupleHash128/256, ParallelHash128/256 |
| XOFs | SHAKE128, SHAKE256 |
| MACs | HMAC (SHA-2 and SHA-3), CMAC-AES-128/192/256, KMAC128/256, Poly1305 |
| Block ciphers | AES-128/192/256 |
| Modes | CBC, CTR, PKCS#7, AES Key Wrap (KW and KWP) |
| AEADs | AES-128/192/256-GCM, ChaCha20-Poly1305, AES-128/256-GCM-SIV (experimental) |
| Post-quantum | ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), both ACVP-checked |
| KDFs | HKDF, PBKDF2, SP 800-108 counter mode, Argon2id/i/d |
| DRBGs | HMAC_DRBG, CTR_DRBG, plus an OS-seeded auto-reseeding `Rng` |
| Curves | P-256, P-384, and P-521 (ECDSA with RFC 6979 nonces, ECDH), X25519, Ed25519 |
| RSA | RSASSA-PSS and PKCS#1 v1.5 over SHA-256/384/512; 2048/3072/4096-bit key generation; CRT private operations |
| Backends | portable constant-time everywhere; AES-NI + PCLMULQDQ on x86-64 |
| Encodings | DER and PEM for SubjectPublicKeyInfo, PKCS#8, SEC1, and ECDSA signatures |
| TLS | a rustls `CryptoProvider`: AES-GCM, SHA-2, HMAC, HKDF, ECDSA, ECDH, X25519 |

## What isn't — and why that's written down

The ontology registers algorithms this library does **not** provide, marked
`planned` or `excluded`, so that querying for them yields an honest answer:

- **RSA encryption** — not offered at all. RSAES-PKCS1-v1_5 is a Bleichenbacher
  oracle waiting to happen, and key transport is better served by ECDH. RSA
  *signatures* are implemented, because certificate chains are made of them.
- **ARMv8 crypto extensions** — implemented, behind the off-by-default
  `aarch64-crypto` feature, and never executed. It compiles for
  `aarch64-apple-darwin` and its round structure is checked against a software
  model of the instructions — which is what caught the decryption key schedule
  being wrong — but no machine has run it. It becomes the default once CI has.
- **X.509 certificate parsing** — out of scope. Names, validity, extensions, and
  path validation are a far larger surface than key encoding, and a partial
  implementation is worse than none. Keys and signatures do parse: hand the
  `SubjectPublicKeyInfo` from any X.509 parser to `ic_pkix::PublicKeyInfo`.
- **AES-GCM-SIV** — `experimental`, and the last algorithm here that is. Its
  components are checked — POLYVAL against the GHASH construction of RFC 8452
  Appendix A, AES against FIPS 197 — and their assembly is not. That is a
  missing *file*, RFC 8452 Appendix C, rather than missing code: see
  `testvectors/README.md`.
- **Other ML-KEM and ML-DSA parameter sets** — only 768 and 65 are implemented.
  That is a decision about surface area, not about confidence.
### Timing

```sh
icrypto timing                      # all targets
icrypto timing ct-verify --iterations 200000
```

A dudect-style leakage detector: two input classes interleaved at random, then
Welch's t-test on the timings. It is a tool, not a gating test — timing needs a
quiet machine, and a test that fails when a laptop indexes its disk teaches
people to ignore failures.

It ships with a **positive control**, a deliberately early-exiting comparison
that must show leakage. A detector that has never detected anything proves
nothing; if the control is quiet, the report says every other result in the run
is meaningless.

A null result means *this run found no evidence on this machine*. That is not a
proof of constant time, and the output says so rather than printing a tick.

### Supply chain

```sh
icrypto sbom > bom.json      # CycloneDX 1.5
```

Deliberately deterministic: no timestamp, no random serial number, so two runs
over identical source produce byte-identical documents and anyone can
regenerate and diff it. A bill of materials you cannot reproduce is one you have
to trust. The component list is checked against the workspace manifest by a
test, so a crate added without being listed fails the build — an SBOM that
quietly omits a component is worse than none, since completeness is its entire
purpose.

It describes the *source*, not a particular binary. Establishing that a binary
came from this source needs a reproducible build pipeline, which `T1195.001`
records as an open gap rather than papering over.

### Security frameworks

The same machinery, applied to the frameworks people are audited against:

```sh
icrypto ontology controls --framework cwe      # weakness classes
icrypto ontology controls --framework attack   # MITRE ATT&CK techniques
icrypto ontology controls --framework cmmc     # CMMC 2.0 practices
icrypto ontology control SC.L2-3.13.11
```

Agents get the same through the `crypto_controls` MCP tool.

**Read this before quoting any of it.** CMMC `SC.L2-3.13.11` requires
FIPS-*validated* cryptography. IronCrypto has no CMVP certificate, so that
practice is **not satisfied**, and no amount of correctness evidence changes
it — validation is a process with a laboratory and a certificate number, not a
property of source code. The summary line names unsatisfied controls
explicitly rather than leaving them to be filtered out, the MCP response carries
`fips_validated: false` as its own field, and tests assert both stay that way.
A compliance view that can be quoted without its gaps is worse than none.

On CVE: a library does not comply with CVE — CVEs are instances, and what an
implementation can do is avoid the weakness classes they belong to, which is
what the CWE entries cover. The other half is supply chain, and there
every crate implementing an algorithm depends on nothing outside this
workspace, so no advisory against another crate can apply to it. That claim is
narrow on purpose and says nothing about defects in IronCrypto's own code.

One crate is outside it. `ic-rustls` implements rustls's traits and so depends
on rustls, which brings five crates with it; anything depending on `ic-rustls`
inherits their advisories, and nothing else here does. `scripts/no-third-party.sh`
enforces both halves: it lists by name what rustls may bring, so that set cannot
grow unnoticed, and it checks every other crate individually rather than looking
at the workspace as a whole — which is what lets the narrower claim still mean
something. `SECURITY.md` has the disclosure process.

### The standards knowledgebase

The registry says what algorithms exist. `ic_ontology::standards` says what
*documents* define them and what those documents require:

```sh
icrypto ontology standards                    # every document, with status
icrypto ontology standard "FIPS 203"          # one document and its obligations
icrypto ontology requirements --state unmet   # the conformance view
icrypto ontology requirements --algorithm ml-kem-768
```

Agents get the same through the `crypto_standard` and `crypto_requirements`
MCP tools.

It is coupled to the code rather than merely filed beside it. A requirement
marked met names a file and a symbol, and the tests check both exist — rename
the function and the knowledgebase fails the build instead of going quietly out
of date. Every document a registry entry cites must be described, and every
document described must be cited or say why not, so neither list can drift from
the other. An algorithm the library offers cannot rest solely on a withdrawn
document.

A met requirement means the code does what the document asks, as far as the
tests can show. It does not mean a laboratory has agreed, and nothing here
claims otherwise — see `has("fips-validated")`, which returns `false`.

- **SHA-1, MD5, Triple DES** — `excluded`, permanently. They are in the registry
  only so that a request for them resolves to a refusal with a reason.

```console
$ icrypto capabilities
  [x] no-std
  [x] zero-dependencies
  [x] constant-time-symmetric
  [x] hardware-acceleration      # on this machine; portable elsewhere
  [ ] fips-validated
  [x] post-quantum
  [x] approved-asymmetric
  [x] tls-provider
  [x] key-encoding
```

---

## Supplying test vectors

An algorithm is `experimental` when it is implemented and nobody has checked it
against values produced by something other than itself. That is a missing
*file*, not missing code: drop an ACVP or RFC vector file into `testvectors/`
and the matching test starts running. Without one it skips and says so.

It worked. ML-KEM-768 and ML-DSA-65 were `experimental` until NIST's published
ACVP vectors were dropped in — 105 cases across key generation, encapsulation
and signing, every case in each parameter set rather than a selection. No code
changed. AES-GCM-SIV is the one still waiting, on RFC 8452 Appendix C.

`testvectors/README.md` has the format, the field names, and `jq` recipes for
converting ACVP output.

## Honest limits

**This is not a CMVP-validated module.** [FIPS.md](docs/FIPS.md) describes what
is implemented (approved-mode policy, pre-operational self-tests, 60 algorithm
known-answer tests, a latching error state, service indicators) and what
validation would still require. `icrypto capabilities` reports
`fips-validated: false` and will keep reporting it until a certificate exists.

**Throughput depends on the CPU, and the library tells you which case you are
in.** On x86-64 with AES-NI and `PCLMULQDQ` the accelerated backend is selected
automatically. Everywhere else — ARM, RISC-V, WebAssembly, any bare-metal target
— AES falls back to the portable path, which computes its S-box algebraically
and multiplies GHASH bit by bit so that neither indexes memory with a secret.
That closes the cache-timing channel table-driven AES leaves open, and it is
slow:

| | portable | AES-NI + PCLMULQDQ |
|---|---|---|
| AES-256, raw blocks | ~1.4 MiB/s | ~1.5–3 GiB/s |
| AES-256-GCM | ~1 MiB/s | ~0.7 GiB/s |
| ChaCha20-Poly1305 | ~0.2–0.4 GiB/s | unchanged (no AES path) |

Indicative figures from a Ryzen 9 9900X, and they move by a factor of two
between runs depending on clocks and load — treat them as orders of magnitude,
not benchmarks. Reproduce with `cargo test --release -p ic-cipher --test
throughput -- --ignored --nocapture`.

This is why `recommend` asks the CPU rather than assuming: without AES
instructions it steers you to ChaCha20-Poly1305, and with them it picks
AES-256-GCM, which is then the faster of the two. `ic_ontology::runtime::backend()`
reports which backend is live.

The accelerated paths are not independently trusted — they are differentially
tested against the portable ones, block for block, and the portable ones are
validated against the FIPS 197, SP 800-38A, and GCM specification vectors.

**This code has not been independently audited.** It is correct against its
test vectors; that is not the same as being reviewed by cryptographers. See
[SECURITY.md](SECURITY.md).

### How this compares

Against aws-lc-rs, BoringSSL, and OpenSSL, IronCrypto leads on portability
(no dependencies in any algorithm crate, no C toolchain, genuine bare-metal
`no_std`) and on the
agent-facing ontology, which none of them has. With the NIST curves and RSA
signatures in place it covers the algorithms most deployments actually reach
for, post-quantum included. It still trails on RSA encryption, on X.509
certificate handling, and — decisively — on validation status. Pick accordingly, and note that the ontology will tell
you which case you're in without your having to read this paragraph.

---

## Docs

| | |
|---|---|
| [ONTOLOGY.md](docs/ONTOLOGY.md) | the vocabulary, the query model, the export formats |
| [FIPS.md](docs/FIPS.md) | what is implemented, what validation would require |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | crate layout and design decisions |
| [AGENTS.md](AGENTS.md) | instructions for agents working in this repo |
| [SECURITY.md](SECURITY.md) | threat model, side-channel posture, reporting |

## Test

```console
$ cargo test --workspace
$ cargo build -p iron-crypto --no-default-features --target thumbv7em-none-eabihf
```

## License

IronCrypto is dual-licensed:

- **[AGPL-3.0-or-later](LICENSE)** for open-source use. Note that the network
  clause has real reach for a crypto library: linking this into a service that
  terminates TLS, signs tokens, or encrypts customer data makes that service a
  derivative work.
- **[Commercial](LICENSE-COMMERCIAL.md)** for proprietary, embedded, or SaaS use
  without AGPL obligations. Contact licensing@nervosys.com.

Contributions require agreement to the [CLA](CLA.md); see
[CONTRIBUTING.md](CONTRIBUTING.md).

Neither license is a statement about cryptographic assurance: there is no CMVP
certificate and no independent audit. See [docs/FIPS.md](docs/FIPS.md) and
[SECURITY.md](SECURITY.md).
