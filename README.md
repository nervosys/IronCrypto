# IronCrypto

**Agentic-first cryptography in pure Rust, with a machine-readable ontology.**

Zero dependencies. No C. No build scripts. `no_std` from the ground up, verified
against ARM Cortex-M, RISC-V, and WebAssembly. Every primitive validated against
its published test vectors.

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

Ask for something this library cannot do, and it says so — instead of handing
back the nearest available substitute:

```console
$ icrypto recommend agree-key --post-quantum
no recommendation.

The correct algorithm for this request is ml-kem-768, which is not implemented
in this build.
Do not substitute a different algorithm to work around this.
```

X25519 *is* implemented and *is* a key agreement scheme. A library that
optimizes for "always return something" would have returned it, silently missing
the requirement the caller actually stated. An honest "no" is worth more to an
autonomous caller than a plausible "yes".

The same discipline applies when an approved option *does* exist — it wins on
the merits, and the one passed over is named:

```console
$ icrypto recommend sign-data --fips
use: ecdsa-p256-sha256
  ECDSA P-256 is the approved signature scheme. This implementation derives its
  nonce per RFC 6979, so the usual ECDSA nonce-reuse failure cannot occur.
  call: ic_ec::p256::EcdsaP256Sha256

considered and rejected:
  ed25519: Not approved for the FIPS approved mode of operation.
```

---

## Install

```toml
[dependencies]
iron-crypto = "0.1"
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
| KDFs | HKDF, PBKDF2, SP 800-108 counter mode, Argon2id/i/d |
| DRBGs | HMAC_DRBG, CTR_DRBG, plus an OS-seeded auto-reseeding `Rng` |
| Curves | P-256, P-384, and P-521 (ECDSA with RFC 6979 nonces, ECDH), X25519, Ed25519 |
| RSA | RSASSA-PSS and PKCS#1 v1.5 over SHA-256/384/512; 2048/3072/4096-bit key generation; CRT private operations |
| Backends | portable constant-time everywhere; AES-NI + PCLMULQDQ on x86-64 |
| Encodings | DER and PEM for SubjectPublicKeyInfo, PKCS#8, SEC1, and ECDSA signatures |

## What isn't — and why that's written down

The ontology registers algorithms this library does **not** provide, marked
`planned` or `excluded`, so that querying for them yields an honest answer:

- **RSA encryption** — not offered at all. RSAES-PKCS1-v1_5 is a Bleichenbacher
  oracle waiting to happen, and key transport is better served by ECDH. RSA
  *signatures* are implemented, because certificate chains are made of them.
- **ARMv8 crypto extensions** — `planned`. Apple Silicon and modern ARM servers
  have AES instructions this build does not yet use.
- **X.509 certificate parsing** — out of scope. Names, validity, extensions, and
  path validation are a far larger surface than key encoding, and a partial
  implementation is worse than none. Keys and signatures do parse: hand the
  `SubjectPublicKeyInfo` from any X.509 parser to `ic_pkix::PublicKeyInfo`.
- **ML-DSA-65** (FIPS 204) — `experimental`, for the same reason as ML-KEM and
  with the same caveat. Every layer is independently checked: the NTT against
  schoolbook multiplication, the packing against a bit-at-a-time reference, the
  rounding and hints against the equations that define them, the samplers
  against the specification's pseudocode, and the key and signature sizes
  against the widths FIPS 204 fixes. The scheme on top of them is checked only
  by signing and verifying — which is not nothing, since signing computes
  `A*y` and verification computes `A*z - c*t1*2^d` and the two must meet through
  the hints, but it cannot catch a convention misread consistently. Only the 65
  parameter set exists, in both the pure and pre-hash variants. ML-KEM-768 is
  `experimental` on the same terms. Both are
  excluded from the approved mode and from `recommend`.
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
  [x] approved-asymmetric
  [x] hardware-acceleration      # on this machine; portable elsewhere
  [x] key-encoding
  [ ] fips-validated
  [ ] post-quantum
```

---

## Supplying test vectors

Two algorithms are `experimental` only because nobody has checked them against
values from another implementation. That is a missing *file*, not missing code:
drop an ACVP or RFC vector file into `testvectors/` and the matching test starts
running. Without one it skips and says so. `testvectors/README.md` has the
format, the field names, and `jq` recipes for converting ACVP output.

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
(zero dependencies, no C toolchain, genuine bare-metal `no_std`) and on the
agent-facing ontology, which none of them has. With the NIST curves and RSA
signatures in place it covers the algorithms most deployments actually reach
for. It still trails on post-quantum schemes, on RSA encryption, on X.509
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
