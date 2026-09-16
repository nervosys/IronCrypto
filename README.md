# AgenticCrypto

**Agentic-first cryptography in pure Rust, with a machine-readable ontology.**

Zero dependencies. No C. No build scripts. `no_std` from the ground up, verified
against ARM Cortex-M, RISC-V, and WebAssembly. Every primitive validated against
its published test vectors.

```console
$ acrypto recommend encrypt-message --fips
use: aes-256-gcm
  AES-256-GCM is the approved authenticated cipher and retains 128-bit strength
  against a quantum adversary.
  call: ac_cipher::Aes256Gcm

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

AgenticCrypto puts the rules in the same place as the code, as **data**:

```console
$ acrypto ontology show aes-256-gcm --json | jq '.constraints[0]'
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
$ acrypto recommend sign-data --fips
no recommendation.

The correct algorithm for this request is ecdsa-p256-sha256, which is not
implemented in this build.
Do not substitute a different algorithm to work around this.
```

Ed25519 *is* implemented and *is* a signature scheme. A library that optimizes
for "always return something" would have returned it, silently breaking the
caller's FIPS requirement. An honest "no" is worth more to an autonomous caller
than a plausible "yes".

---

## Install

```toml
[dependencies]
agentic-crypto = "0.1"
```

```console
$ cargo install --path crates/ac-cli   # the `acrypto` CLI and MCP server
```

## Use

```rust
use agentic_crypto::prelude::*;

// Ask what to use, rather than picking a name from memory.
let choice = recommend(Intent::EncryptMessage, Policy::FIPS_APPROVED).unwrap();
assert_eq!(choice.primary.id, "aes-256-gcm");
assert_eq!(choice.primary.rust_path, "ac_cipher::Aes256Gcm");

// Then use it.
let cipher = Aes256Gcm::new(&[0x2a; 32])?;
let mut buf = *b"the payload";
let mut tag = [0u8; 16];
cipher.seal_detached(&nonce, b"context", &mut buf, &mut tag)?;
cipher.open_detached(&nonce, b"context", &mut buf, &tag)?;
# Ok::<(), ac_core::Error>(())
```

## Connect an agent

`acrypto mcp` is a Model Context Protocol server on stdio:

```jsonc
{
  "mcpServers": {
    "agentic-crypto": { "command": "acrypto", "args": ["mcp"] }
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
| Hashes | SHA-224/256/384/512, SHA-512/224, SHA-512/256, SHA3-224/256/384/512 |
| XOFs | SHAKE128, SHAKE256 |
| MACs | HMAC (SHA-2 and SHA-3), CMAC-AES-128/192/256, Poly1305 |
| Block ciphers | AES-128/192/256 |
| Modes | CBC, CTR, PKCS#7 |
| AEADs | AES-128/192/256-GCM, ChaCha20-Poly1305 |
| KDFs | HKDF, PBKDF2, SP 800-108 counter mode |
| DRBGs | HMAC_DRBG, CTR_DRBG, plus an OS-seeded auto-reseeding `Rng` |
| Curves | X25519, Ed25519 |

## What isn't — and why that's written down

The ontology registers algorithms this library does **not** provide, marked
`planned` or `excluded`, so that querying for them yields an honest answer:

- **ECDSA / ECDH over NIST curves, RSA** — `planned`. These are the FIPS-approved
  asymmetric algorithms. Not having them is the single largest gap; under a FIPS
  requirement, use a validated module for signatures and key agreement.
- **ML-KEM, ML-DSA** (FIPS 203/204) — `planned`. No post-quantum schemes yet.
- **Argon2id** — `planned`. PBKDF2 is available and approved, but it is not
  memory-hard.
- **SHA-1, MD5, Triple DES** — `excluded`, permanently. They are in the registry
  only so that a request for them resolves to a refusal with a reason.

```console
$ acrypto capabilities
  [x] no-std
  [x] zero-dependencies
  [x] constant-time-symmetric
  [ ] hardware-acceleration
  [ ] fips-validated
  [ ] post-quantum
  [ ] approved-asymmetric
```

---

## Honest limits

**This is not a CMVP-validated module.** [FIPS.md](docs/FIPS.md) describes what
is implemented (approved-mode policy, pre-operational self-tests, 34 algorithm
known-answer tests, a latching error state, service indicators) and what
validation would still require. `acrypto capabilities` reports
`fips-validated: false` and will keep reporting it until a certificate exists.

**The portable backend is slow.** AES computes its S-box algebraically and
GHASH multiplies bit by bit, so neither indexes memory with a secret — the
cache-timing channel that table-driven AES leaves open is closed by
construction. The cost is throughput: expect single-digit MB/s for AES, not the
GB/s an AES-NI backend delivers. The ontology marks every AES-based algorithm
`performance: slow`, and `recommend` will steer you to ChaCha20-Poly1305 unless
you pass `--fips` or `--aes-hardware`. If you need bulk AES throughput today,
use a hardware-backed module.

**This code has not been independently audited.** It is correct against its
test vectors; that is not the same as being reviewed by cryptographers. See
[SECURITY.md](SECURITY.md).

### How this compares

Against aws-lc-rs, BoringSSL, and OpenSSL, AgenticCrypto leads on portability
(zero dependencies, no C toolchain, genuine bare-metal `no_std`) and on the
agent-facing ontology, which none of them has. It trails badly on asymmetric
algorithm coverage, on raw throughput, and on validation status. Pick
accordingly — and note that the ontology will tell you which case you're in
without your having to read this paragraph.

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
$ cargo build -p agentic-crypto --no-default-features --target thumbv7em-none-eabihf
```

## License

Apache-2.0 OR MIT, at your option.
