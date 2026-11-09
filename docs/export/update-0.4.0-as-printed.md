# Updated notification for 0.4.0: the text printed, reported sent

The text of an updated notification under 15 CFR §742.15(b), drafted by this
agent on 2026-11-09 for IronCrypto 0.4.0 and printed for the maintainer that
day. The maintainer asked for it to be printed in the conversation, and
then replied "Sent". **This is the text as printed, with its blanks, not the
message as sent**: the contact fields and the date of the previous notification are the
maintainer's to fill in and are not inferred here. Whether and when it was
sent, and to whom, is recorded in `docs/export/notification.md` only as the
maintainer reports it.

`docs/EXPORT.md` is left as it was.

## Why an update

On 2026-11-09 the maintainer wrote "publish", and asked whether the earlier
notice covers 0.4.0 or an updated one should be printed first, chose "Print
updated notice". What 0.4.0 changes:

- **No new location.** It adds no package. The twenty-two crates.io packages
  and the GitHub repository are the ones in the previous notification.
- **New cryptographic functionality:**
  - **Ed448** (RFC 8032), the EdDSA signature scheme on the edwards448
    curve with SHAKE256, pure form, with contexts. Its keys and signatures
    are read and written in the X.509 and PKCS#8 encodings of RFC 8410.
  - **Composite ML-DSA signatures** from the IETF Internet-Draft
    draft-ietf-lamps-pq-composite-sigs-19: ML-DSA-44 or ML-DSA-65 paired
    with Ed25519 over a SHA-512 pre-hash, and ML-DSA-87 paired with Ed448
    over a SHAKE256 pre-hash. Both halves sign the same message and a
    signature verifies only if both do. It uses only ML-DSA, Ed25519,
    Ed448, SHA-512 and SHAKE256.
  - **Encrypted PKCS#8 private keys** (RFC 5958 `EncryptedPrivateKeyInfo`)
    under PBES2 (RFC 8018), with PBKDF2-HMAC-SHA-256 and AES-256-CBC, read
    and written. It adds no primitive: PBKDF2, HMAC, SHA-256 and AES-CBC
    were already listed.
- **No change in kind:** a breaking change to three key enums' API, which
  is why the version is 0.4.0; faster ML-KEM key generation with the same
  output; a hardness-assumption index in the ontology, which is data; and
  proofs, which do not compile into the crates.

The text below is complete in itself apart from its blanks.

---

**To:** `crypt@bis.doc.gov`, `enc@nsa.gov`
**Subject:** `Updated notification of publicly available encryption source code — 15 CFR 742.15(b) — IronCrypto`

```text
To the Bureau of Industry and Security and the ENC Encryption Request
Coordinator:

This updates a previous notification under 15 CFR 742.15(b) concerning
IronCrypto, to give its complete current set of internet locations and
cryptographic functionality as of version 0.4.0.

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
  Version:         0.4.0
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

CHANGES SINCE THE PREVIOUS NOTIFICATION
  Added since version 0.3.0:
    - Ed448, the EdDSA signature scheme of RFC 8032 on the edwards448
      curve with SHAKE256, and its key and signature encodings in X.509
      and PKCS#8 (RFC 8410).
    - Composite ML-DSA signatures, as specified in the public IETF
      Internet-Draft draft-ietf-lamps-pq-composite-sigs-19: ML-DSA-44 or
      ML-DSA-65 with Ed25519 and SHA-512, and ML-DSA-87 with Ed448 and
      SHAKE256. A signature is valid only if both component signatures
      are. They use only ML-DSA, Ed25519, Ed448, SHA-512 and SHAKE256.
    - Password-based encryption of PKCS#8 private keys (RFC 5958) under
      PBES2 (RFC 8018), with PBKDF2-HMAC-SHA-256 and AES-256-CBC, all
      already listed.

CRYPTOGRAPHIC FUNCTIONALITY
  IronCrypto implements published algorithms only. It contains no
  proprietary or unpublished cryptographic functionality. Most are
  specified in standards. The rest are specified in public documents:
  XChaCha20-Poly1305 and the composite ML-DSA signatures in IETF
  Internet-Drafts; BLAKE3 in its authors' specification; bcrypt in a paper
  (USENIX, 1999), on the Blowfish cipher of another (Fast Software
  Encryption, 1993); and yescrypt, used only to verify existing password
  hashes, in its authors' published reference implementation.

    Block cipher and modes   AES-128/192/256 (FIPS 197); CBC, CTR (SP 800-38A);
                             AES Key Wrap and KWP (RFC 3394, RFC 5649)
    AEAD                     AES-GCM (SP 800-38D); AES-GCM-SIV (RFC 8452);
                             ChaCha20-Poly1305 (RFC 8439);
                             XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03)
    Hashes and XOFs          SHA-2 family (FIPS 180-4); SHA-3 and SHAKE
                             (FIPS 202); cSHAKE, KMAC, TupleHash,
                             ParallelHash (SP 800-185); BLAKE2b and
                             BLAKE2s (RFC 7693); BLAKE3
    MACs                     HMAC (FIPS 198-1); CMAC (SP 800-38B);
                             KMAC (SP 800-185); Poly1305 (RFC 8439)
    Key derivation           HKDF (RFC 5869); PBKDF2 (SP 800-132);
                             SP 800-108 counter mode; scrypt (RFC 7914);
                             Argon2 (RFC 9106, and version 1.0 of the
                             Argon2 specification); verification of
                             bcrypt and yescrypt password hashes
    Passphrase encryption    Argon2id with XChaCha20-Poly1305, in a
                             container format published in the source;
                             encrypted PKCS#8 private keys under PBES2
                             with PBKDF2-HMAC-SHA-256 and AES-256-CBC
                             (RFC 8018, RFC 5958)
    Random bit generation    HMAC_DRBG and CTR_DRBG (SP 800-90A)
    Public key               ECDSA and ECDH over P-256, P-384, P-521
                             (FIPS 186-5, SP 800-56A, RFC 6979);
                             X25519 (RFC 7748); Ed25519 and Ed448
                             (RFC 8032);
                             RSA PKCS#1 v1.5 and PSS (FIPS 186-5, RFC 8017)
    Public-key encryption    HPKE base mode (RFC 9180) with DHKEM(X25519,
                             HKDF-SHA256) or DHKEM(P-384, HKDF-SHA384), and
                             AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305
    Post-quantum             ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203);
                             ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204);
                             SLH-DSA, all twelve parameter sets, pure and
                             pre-hash (FIPS 205);
                             HSS/LMS signature verification (RFC 8554,
                             RFC 9858, SP 800-208);
                             composite ML-DSA signatures, ML-DSA-44 or
                             ML-DSA-65 with Ed25519 and SHA-512, and
                             ML-DSA-87 with Ed448 and SHAKE256
                             (draft-ietf-lamps-pq-composite-sigs-19)
    Oblivious PRFs           OPRF, VOPRF, POPRF over P-256 (RFC 9497);
                             hashing to curves (RFC 9380)
    Password authentication  OPAQUE-3DH over P-256 (RFC 9807)
    Secret sharing           Shamir's scheme over GF(2^8)
    Protocol adapter         Record and packet protection for TLS 1.2, TLS 1.3
                             and QUIC (RFC 5288, 5869, 7905, 8446, 9001), as a
                             provider for the rustls library
    Encodings                DER and PEM for public and private keys and
                             signatures (RFC 5280, 5480, 5915, 5958, 7468);
                             X.509 certificate issuance (RFC 5280) for
                             certificates signed with the algorithms above;
                             PKCS#10 certification requests (RFC 2986)

  IronCrypto is not FIPS 140-3 validated and holds no CMVP certificate. The
  standards above are cited to identify the algorithms implemented, not to
  claim validation.

<name>
<title>, Nervosys
<date>
```

## Checked against

The package list is the twenty-two directories under `crates/` at the commit
that adds this file, the same list the 0.3.0 notice gave. The functionality
list is the 0.3.0 notice's, with the additions above taken from
`CHANGELOG.md` under Unreleased; 0.3.1 and 0.3.2 added no algorithm, as
their release entries in `notification.md` record. The licence line and the
RFC numbers carried over from the 0.3.0 notice were not re-derived.
