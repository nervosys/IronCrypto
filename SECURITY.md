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

**Three algorithms are `experimental`**: ML-KEM-768, ML-DSA-65, and
AES-GCM-SIV. Every component of each is checked against an independent oracle,
and the assembled scheme is checked against nothing but itself, because no ACVP
or RFC vector is wired in. They are excluded from the approved mode and from
`recommend`, and each carries a `not-interoperability-tested` constraint at
`Critical` severity. Do not use them to talk to another implementation.

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
| What does a standard require, and does this meet it? | `icrypto ontology requirements` |
| Which weakness classes and practices does this address? | `icrypto ontology controls` |
| Why is an algorithm not recommended? | `icrypto ontology show <id>` |
| Does it interoperate? | Nothing establishes this yet. See `testvectors/README.md` |
| What is in the build? | `icrypto sbom` — CycloneDX, deterministic, regenerate and diff it |

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
