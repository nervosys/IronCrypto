# The ontology

The ontology is the part of IronCrypto that is not a cryptography library.
It is a machine-readable description of what each algorithm is, what it is for,
what it costs, what it guarantees, and what will break if you use it wrongly —
expressed in a closed vocabulary that a program can reason over.

## Why closed terms

Free text is unusable to a caller that cannot read. Every field that an agent
might branch on is an enum with a stable identifier:

| dimension | terms |
|---|---|
| `class` | `hash`, `xof`, `mac`, `block-cipher`, `cipher-mode`, `aead`, `kdf`, `password-kdf`, `drbg`, `key-agreement`, `kem`, `signature`, `secret-sharing` |
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
$ ic ontology show aes-256-gcm
AES-256-GCM (aes-256-gcm)
The default choice for authenticated encryption under a FIPS requirement.

  class:      aead
  family:     AES-GCM
  purposes:   confidentiality, authentication, integrity
  strength:   256 bits classical, 128 bits quantum
  fips:       approved
  status:     available
  standards:  SP 800-38D
  call:       ic_cipher::Aes256Gcm

parameters:
  key            32..32 bytes (recommended 32)
      256-bit key.
  nonce          1..64 bytes (recommended 12)
      96-bit nonces are used directly as the counter block; other lengths are hashed first.
  tag            16..16 bytes (recommended 16)
      Full-length authentication tag.

constraints:
  [critical] Never reuse a (key, nonce) pair.
      Reuse leaks the authentication subkey, allowing forgery of arbitrary messages, and XORs the two plaintexts together.
  [serious] Let ic_cipher::Sealer choose the nonce: a sender tag and a strictly increasing counter, never reused within it. Otherwise derive the nonce from a counter yourself, or draw 96 random bits and bound the number of messages per key.
      Random 96-bit nonces collide with meaningful probability past 2^32 messages.

relations:
  built-on aes-256

example:
  let mut tx = ic_cipher::Sealer::<ic_cipher::Aes256Gcm>::new(key, *b"c->s")?;
  let nonce = tx.seal(aad, &mut buf, &mut tag)?; // send the nonce with the ciphertext

notes:
  Also the choice when a single key must protect data for a long time, since the 256-bit key retains 128-bit strength against Grover.
```

## Three levels of query

### 1. Filter — "what matches these predicates?"

```rust
use ic_ontology::{Purpose, Query};

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
use ic_ontology::select::{recommend, Intent, Policy};

let r = recommend(Intent::EncryptMessage, Policy::DEFAULT).expect("an AEAD is built in");
let _ = r.primary; // the chosen entry
let _ = r.rationale; // why
let _ = r.alternative; // second choice
let _ = r.rejected(); // what was passed over, with reasons
let _ = r.must_observe; // constraints the caller has to honour
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
// Finds hmac-sha2-256, hkdf-sha2-256, ...
let related: Vec<_> = ic_ontology::related("sha2-256").collect();
assert!(related.iter().any(|e| e.id == "hmac-sha2-256"));
```

Edges are traversed in both directions. `sha2-256` does not record that HMAC is
built on it, but an agent asking "what depends on SHA-256?" still gets the
answer.

## Exports

```console
$ ic ontology export json       # for tool calls, CI, jq
$ ic ontology export jsonld     # for a knowledge graph
$ ic ontology export turtle     # for SPARQL or an OWL reasoner
$ ic ontology export schema     # JSON Schema for the json export
$ ic ontology export markdown   # for humans
```

The Turtle export is a real RDF graph: classes are `rdfs:Class` with
`rdfs:subClassOf ac:Algorithm`, purposes are instances of `ac:Purpose`, and the
relation edges become triples, so `built-on` resolves to an edge rather than a
string literal. The vocabulary IRI is
`https://nervosys.github.io/IronCrypto/ontology#`.

The writers are hand-rolled, which keeps the workspace dependency-free, and are
tested for well-formedness against every entry — including the entries whose
examples contain newlines and quotes.

## The controls export

`ic ontology controls --json`, and the MCP tool that returns the same thing,
is read by other tools to build compliance evidence, so its shape is named
and kept: `"schema": "ironcrypto-controls/1"`. Within one number, fields are
only added; a reader that ignores what it does not know keeps working.
Removing or renaming a field, or changing what one means, takes a new number.
`the_controls_export_has_the_shape_its_schema_names` in `ic-cli` fails if the
fields below change without it.

| Field | What it is |
|---|---|
| `schema` | `ironcrypto-controls/1` |
| `version` | the IronCrypto version the mappings were read from |
| `count` | how many controls are in `controls`, after any filter |
| `totals` | `met`, `partial`, `unmet`, `notApplicable`, counted before the state filter |
| `unmet` | the ids of the unmet controls, named so they are not one filter away from being missed |
| `cvePosture` | a sentence on how CVEs bear on this library |
| `fipsValidated` | `false`, until a CMVP certificate exists |
| `controls` | the list |

Each control has `id`, `framework`, `frameworkName`, `title`, `description`,
`bearing`, `algorithms`, `standards` and `compliance`. `compliance.state` is
one of four, and the other fields follow from it:

| `state` | Also present |
|---|---|
| `met` | `file`, `evidence` |
| `partial` | `file`, `evidence`, `gap` |
| `unmet` | `reason` |
| `not-applicable` | `reason` |

Three things a reader must carry over, or it will say more than this does:

- **`met` is about this library's part**, with a file and a symbol a test
  checks exist. It never says a system satisfies the control. `bearing` says
  how the control bears on a library at all, and belongs beside the state
  wherever the state is shown.
- **`partial` without its `gap` is a false statement.**
- **`file` and `evidence` are true for `version` and no other.** They are
  checked at the commit they ship in.

## Keeping it honest

An ontology that drifts from the code is worse than none: it lies with
authority. Three test suites hold them together.

**Sizes must match.** `ironcrypto` asserts that every declared parameter
equals the constant on the implementing type:

```rust
use ic_core::traits::Aead;

let entry = ic_ontology::get("aes-256-gcm").expect("registered");
let key_param = entry.params.iter().find(|p| p.name == "key").expect("a key");
assert_eq!(key_param.recommended as usize, ic_cipher::Aes256Gcm::KEY_LEN);
```

**Paths must resolve.** Every `available` entry must name a `rust_path` starting
with a real workspace crate, and carry a non-empty `example`. Every non-available
entry must have an empty path and a non-empty `notes` explaining its absence.

**Tests must exist.** `ic-fips` asserts that every `available` entry has a
known-answer test registered, and that every registered test names a real
ontology entry.

Plus structural invariants: identifiers are unique, every edge target exists,
every AEAD carries the nonce-reuse constraint, every unauthenticated mode
carries the "needs a MAC" constraint, and every broken algorithm is marked
`disallowed` with zero strength.

## Adding an entry

1. Add the `Entry` to `crates/ic-ontology/src/registry.rs`.
2. If it is implemented, implement `SelfTest` and register it in
   `crates/ic-fips/src/selftest.rs`, bumping `TEST_COUNT` and the integrity tag.
3. Run `cargo test --workspace`. The invariant tests will tell you what you
   missed.

If it is *not* implemented, set `status: Planned`, leave `rust_path` and
`example` empty, and write `notes` explaining what a caller should do instead.
That entry is doing real work: it is what stops an agent from substituting
something inappropriate.
