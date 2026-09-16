# The ontology

The ontology is the part of AgenticCrypto that is not a cryptography library.
It is a machine-readable description of what each algorithm is, what it is for,
what it costs, what it guarantees, and what will break if you use it wrongly —
expressed in a closed vocabulary that a program can reason over.

## Why closed terms

Free text is unusable to a caller that cannot read. Every field that an agent
might branch on is an enum with a stable identifier:

| dimension | terms |
|---|---|
| `class` | `hash`, `xof`, `mac`, `block-cipher`, `cipher-mode`, `aead`, `kdf`, `password-kdf`, `drbg`, `key-agreement`, `kem`, `signature` |
| `purpose` | `integrity`, `confidentiality`, `authentication`, `key-derivation`, `password-hashing`, `key-establishment`, `random-generation`, `non-repudiation`, `commitment` |
| `fipsStatus` | `approved`, `allowed-as-component`, `not-approved`, `deprecated`, `disallowed` |
| `implementationStatus` | `available`, `planned`, `excluded` |
| `performance` | `fast`, `moderate`, `slow`, `deliberately-slow` |
| `severity` | `critical`, `serious`, `advisory` |
| `relation` | `built-on`, `supersedes`, `superseded-by`, `pairs-with`, `specializes` |

Prose still exists — `summary`, `notes`, each constraint's `requirement` and
`consequence` — but it is never load-bearing. An agent can act correctly using
only the enums.

## An entry

```console
$ acrypto ontology show aes-256-gcm
AES-256-GCM (aes-256-gcm)
The default choice for authenticated encryption under a FIPS requirement.

  class:      aead
  family:     AES-GCM
  purposes:   confidentiality, authentication, integrity
  strength:   256 bits classical, 128 bits quantum
  fips:       approved
  status:     available
  standards:  SP 800-38D
  call:       ac_cipher::Aes256Gcm

parameters:
  key            32..32 bytes (recommended 32)
      256-bit key.
  nonce          1..64 bytes (recommended 12)
      96-bit nonces are used directly as the counter block; other lengths are
      hashed first.
  tag            16..16 bytes (recommended 16)
      Full-length authentication tag.

constraints:
  [critical] Never reuse a (key, nonce) pair.
      Reuse leaks the authentication subkey, allowing forgery of arbitrary
      messages, and XORs the two plaintexts together.
  [serious] Derive the nonce from a strictly increasing counter, or draw 96
      random bits and bound the number of messages per key.
      Random 96-bit nonces collide with meaningful probability past 2^32 messages.

relations:
  built-on aes-256
```

## Three levels of query

### 1. Filter — "what matches these predicates?"

```rust
use ac_ontology::{Purpose, Query};

let hits: Vec<_> = Query::new()
    .purpose(Purpose::Confidentiality)
    .purpose(Purpose::Authentication)   // both: i.e. an AEAD
    .fips_approved_only()
    .available_only()
    .min_classical_bits(256)
    .run()
    .collect();
```

`Query` is a plain iterator adapter. It allocates nothing and works in `no_std`.

Setting `min_quantum_bits` above zero is the post-quantum migration filter: it
drops every discrete-log and factoring scheme, because their `quantumBits` is
modelled as `0` (Shor), while symmetric strengths are halved (Grover).

### 2. Select — "what should I use, and what will bite me?"

```rust
use ac_ontology::select::{recommend, Intent, Policy};

let r = recommend(Intent::EncryptMessage, Policy::DEFAULT)?;
r.primary;        // the chosen entry
r.rationale;      // why
r.alternative;    // second choice
r.rejected();     // what was passed over, with reasons
r.must_observe;   // constraints the caller has to honour
```

The ranking is context-sensitive. Without AES hardware the portable AES backend
is far slower than ChaCha20, so `EncryptMessage` resolves to
`chacha20-poly1305`; pass `aes_hardware: true` or `require_fips: true` and it
flips to `aes-256-gcm`. The rationale string changes with it, so the reasoning
stays attached to the answer.

When nothing available fits, `recommend` returns an error rather than a
degraded answer:

- `KnownButUnavailable { id }` — the registry knows the right algorithm, this
  build does not have it. Go and get it elsewhere; do not substitute.
- `NothingSatisfiesPolicy` — no algorithm, anywhere in the registry, meets
  these constraints.

### 3. Traverse — "what is this related to?"

```rust
ac_ontology::related("sha2-256")  // finds hmac-sha2-256, hkdf-sha2-256, ...
```

Edges are traversed in both directions. `sha2-256` does not record that HMAC is
built on it, but an agent asking "what depends on SHA-256?" still gets the
answer.

## Exports

```console
$ acrypto ontology export json       # for tool calls, CI, jq
$ acrypto ontology export jsonld     # for a knowledge graph
$ acrypto ontology export turtle     # for SPARQL or an OWL reasoner
$ acrypto ontology export schema     # JSON Schema for the json export
$ acrypto ontology export markdown   # for humans
```

The Turtle export is a real RDF graph: classes are `rdfs:Class` with
`rdfs:subClassOf ac:Algorithm`, purposes are instances of `ac:Purpose`, and the
relation edges become triples, so `built-on` resolves to an edge rather than a
string literal. The vocabulary IRI is
`https://nervosys.github.io/AgenticCrypto/ontology#`.

The writers are hand-rolled, which keeps the workspace dependency-free, and are
tested for well-formedness against every entry — including the entries whose
examples contain newlines and quotes.

## Keeping it honest

An ontology that drifts from the code is worse than none: it lies with
authority. Three test suites hold them together.

**Sizes must match.** `agentic-crypto` asserts that every declared parameter
equals the constant on the implementing type:

```rust
assert_eq!(key_param.recommended as usize, Aes256Gcm::KEY_LEN);
```

**Paths must resolve.** Every `available` entry must name a `rust_path` starting
with a real workspace crate, and carry a non-empty `example`. Every non-available
entry must have an empty path and a non-empty `notes` explaining its absence.

**Tests must exist.** `ac-fips` asserts that every `available` entry has a
known-answer test registered, and that every registered test names a real
ontology entry.

Plus structural invariants: identifiers are unique, every edge target exists,
every AEAD carries the nonce-reuse constraint, every unauthenticated mode
carries the "needs a MAC" constraint, and every broken algorithm is marked
`disallowed` with zero strength.

## Adding an entry

1. Add the `Entry` to `crates/ac-ontology/src/registry.rs`.
2. If it is implemented, implement `SelfTest` and register it in
   `crates/ac-fips/src/selftest.rs`, bumping `TEST_COUNT` and the integrity tag.
3. Run `cargo test --workspace`. The invariant tests will tell you what you
   missed.

If it is *not* implemented, set `status: Planned`, leave `rust_path` and
`example` empty, and write `notes` explaining what a caller should do instead.
That entry is doing real work: it is what stops an agent from substituting
something inappropriate.
