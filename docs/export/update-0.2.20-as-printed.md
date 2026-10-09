# Updated notification for 0.2.20: the text printed, reported sent

The text of an updated notification under 15 CFR §742.15(b) that this agent
printed for the maintainer on 2026-10-09. The maintainer then replied "Sent".
**This is the text as printed, with its blanks, not the message as sent**: the
completed contact fields, the date given for the previous notification, the
sending time and the recipients have not been supplied here.
`docs/export/notification.md` records the exchange.

`docs/EXPORT.md` is left as it was.

## Whether an update is needed

That is the maintainer's determination, not this draft's. What bears on it:

- **No new location.** 0.2.20 adds no package. The twenty-two crates.io
  packages and the GitHub repository are the ones the maintainer reported, on
  2026-10-09, having already notified for.
- **No new algorithm.** Everything 0.2.20 computes was already in 0.2.19.
  What changes is how it is reached and checked:
  - HashSLH-DSA, the pre-hash interface of FIPS 205, in `ic-slhdsa`, which
    already implemented SLH-DSA.
  - `ic-sig` verifies SLH-DSA and HSS/LMS signatures, which `ic-slhdsa` and
    `ic-lms` already did.
  - A correction to Poly1305 (RFC 8439), which was computed wrong for some
    inputs; the algorithm is unchanged.
  - Self-tests, an error state, and test vectors. None is cryptographic
    functionality.

`docs/RELEASING.md` treats every published version as an export in its own
right, and the practice so far has been to notify regardless. The text below
is complete in itself, so it can be sent as it stands if the maintainer
chooses to.

---

**To:** `crypt@bis.doc.gov`, `enc@nsa.gov`
**Subject:** `Updated notification of publicly available encryption source code — 15 CFR 742.15(b) — IronCrypto`

```text
To the Bureau of Industry and Security and the ENC Encryption Request
Coordinator:

This updates a previous notification under 15 CFR 742.15(b) concerning
IronCrypto, to give its complete current set of internet locations and
cryptographic functionality as of version 0.2.20.

SUBMITTER
  Entity:          Nervosys
  Contact:         <name>, <title>
  Email:           <address that will remain monitored>
  Telephone:       <number>
  Postal address:  <address>

PREVIOUS NOTIFICATION
  Sent:            <date of the most recent notification>

ITEM
  Name:            IronCrypto
  Version:         0.2.20
  Description:     An open-source cryptographic library written in Rust,
                   distributed as source code, with a command-line tool.
  Classification:  ECCN 5D002 (encryption source code)
  Licence:         AGPL-3.0-or-later, with a separate commercial option

INTERNET LOCATIONS
  Source repository:
    https://github.com/nervosys/IronCrypto

  Source packages on crates.io, the Rust package registry, each at
  https://crates.io/crates/<name>:
    ironcrypto, ic-core, ic-hash, ic-mac, ic-cipher, ic-kdf, ic-drbg,
    ic-ec, ic-rsa, ic-mlkem, ic-mldsa, ic-slhdsa, ic-lms, ic-sig, ic-hpke,
    ic-pkix, ic-rustls, ic-fips, ic-ontology, ic-json, ic-vectors, ic-cli

  These are the same twenty-two packages and the same repository as in the
  previous notification. No location is added.

  The source code is publicly available at these locations without
  restriction on access and without charge.

CRYPTOGRAPHIC FUNCTIONALITY
  IronCrypto implements published, standardised algorithms only. It contains
  no proprietary or unpublished cryptographic functionality. No algorithm is
  added in version 0.2.20.

    Block cipher and modes   AES-128/192/256 (FIPS 197); CBC, CTR (SP 800-38A);
                             AES Key Wrap and KWP (RFC 3394, RFC 5649)
    AEAD                     AES-GCM (SP 800-38D); AES-GCM-SIV (RFC 8452);
                             ChaCha20-Poly1305 (RFC 8439)
    Hashes and XOFs          SHA-2 family (FIPS 180-4); SHA-3 and SHAKE
                             (FIPS 202); cSHAKE, KMAC, TupleHash,
                             ParallelHash (SP 800-185); BLAKE2b (RFC 7693)
    MACs                     HMAC (FIPS 198-1); CMAC (SP 800-38B);
                             KMAC (SP 800-185); Poly1305 (RFC 8439)
    Key derivation           HKDF (RFC 5869); PBKDF2 (SP 800-132);
                             SP 800-108 counter mode; Argon2 (RFC 9106)
    Random bit generation    HMAC_DRBG and CTR_DRBG (SP 800-90A)
    Public key               ECDSA and ECDH over P-256, P-384, P-521
                             (FIPS 186-5, SP 800-56A, RFC 6979);
                             X25519 (RFC 7748); Ed25519 (RFC 8032);
                             RSA PKCS#1 v1.5 and PSS (FIPS 186-5, RFC 8017)
    Public-key encryption    HPKE base mode (RFC 9180) with DHKEM(X25519,
                             HKDF-SHA256) or DHKEM(P-384, HKDF-SHA384), and
                             AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305
    Post-quantum             ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203);
                             ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204);
                             SLH-DSA, all twelve parameter sets, pure and
                             pre-hash (FIPS 205);
                             HSS/LMS signature verification (RFC 8554,
                             RFC 9858, SP 800-208)
    Secret sharing           Shamir's scheme over GF(2^8)
    Protocol adapter         Record and packet protection for TLS 1.2, TLS 1.3
                             and QUIC (RFC 5288, 5869, 7905, 8446, 9001), as a
                             provider for the rustls library
    Encodings                DER and PEM for public and private keys and
                             signatures (RFC 5280, 5480, 5915, 5958, 7468);
                             X.509 certificate issuance (RFC 5280) for
                             certificates signed with the algorithms above

  IronCrypto is not FIPS 140-3 validated and holds no CMVP certificate. The
  standards above are cited to identify the algorithms implemented, not to
  claim validation.

<name>
<title>, Nervosys
<date>
```

## Checked against

The package list is the `name` of every crate manifest under `crates/` at the
commit that adds this file, less the two that are not packages on crates.io
in their own right (`ic`, the binary inside `ic-cli`, and `cold_tables`, a
test target). The functionality list is the 0.2.5 draft's, with what
`README.md` ("What's implemented") has added since: HPKE, SLH-DSA, HSS/LMS
and Shamir's scheme.

Two things in it were not re-derived for this draft and should be read
before sending: the licence line, which is carried over from the 0.2.5
draft, and the RFC numbers in the protocol adapter and encodings lines,
which are also carried over.
