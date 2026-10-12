# Updated notification for 0.2.25: draft

The text of an updated notification under 15 CFR §742.15(b), drafted by this
agent on 2026-10-12 for the maintainer to complete and send. The contact
fields and the date of the previous notification are left blank: they are the
maintainer's to fill in, and are not inferred here.
`docs/export/notification.md` records what happens to it.

`docs/EXPORT.md` is left as it was.

## Why an update

The maintainer decided on 2026-10-12 that 0.2.25 is notified before it is
published, rather than relying on the earlier notice. What 0.2.25 changes:

- **No new location.** It adds no package. The twenty-two crates.io packages
  and the GitHub repository are the ones in the previous notification.
- **New cryptographic functionality**, which the four releases since 0.2.20
  did not have:
  - **XChaCha20-Poly1305**, an authenticated cipher: ChaCha20-Poly1305 with
    a 192-bit nonce, through the HChaCha20 subkey derivation. It is
    specified in a public IETF Internet-Draft, draft-irtf-cfrg-xchacha-03,
    which expired in 2020 without becoming an RFC. It introduces no new
    primitive: ChaCha20 and Poly1305 are already in the notified list.
  - **Passphrase sealing**, a file format of this library's own: a secret
    encrypted under a key Argon2id derives from a passphrase, with
    XChaCha20-Poly1305. It composes published algorithms and adds no
    primitive. The format is described in the public source,
    `crates/ic-kdf/src/passphrase.rs`.
- **OPAQUE** (RFC 9807), a password-authenticated key exchange: three
  Diffie-Hellman operations on P-256 and the OPRF below, with HKDF, HMAC
  and SHA-256, and Argon2id or scrypt to stretch the password. It uses
  only primitives already listed.
- **Oblivious pseudorandom functions** (RFC 9497): a server evaluates a
  keyed function on a client's blinded input, with P-256 and SHA-256, in
  its three modes; and **hashing to elliptic curves** (RFC 9380), which it
  is built on. Both use only primitives already listed: P-256, SHA-256.
- **scrypt** (RFC 7914), a published password-based key derivation
  function built from PBKDF2-HMAC-SHA256 and Salsa20/8.
- **bcrypt and yescrypt, verification only**: checking a password against
  a hash made elsewhere, so that it can be replaced. Neither encrypts
  data or makes new hashes. bcrypt (Provos and Mazieres, USENIX 1999) is
  built on the Blowfish block cipher's key schedule (Schneier, FSE 1993),
  which is new to the library; Blowfish is used only inside bcrypt and is
  not offered as a cipher. yescrypt is Openwall's published scrypt
  derivative, the default password hash of current Linux distributions,
  built from scrypt, PBKDF2-HMAC-SHA256 and HMAC-SHA256.
- **Argon2 version 1.0**, the version the Password Hashing Competition
  selected, beside version 1.3 (RFC 9106), which was already listed. It
  differs from 1.3 in one step, and is there so that older password hashes
  verify. Argon2 password hashes can also be written and read in the PHC
  string format, an encoding.
- **Encodings, not cryptography:** X.509 certificates may now carry URI
  alternative names, and the library writes PKCS#10 certification requests
  (RFC 2986).
- **No change in kind:** PBKDF2 is faster with the same output, and Ed25519
  verification refuses degenerate keys and signatures it used to accept.

The text below is complete in itself apart from its blanks.

---

**To:** `crypt@bis.doc.gov`, `enc@nsa.gov`
**Subject:** `Updated notification of publicly available encryption source code — 15 CFR 742.15(b) — IronCrypto`

```text
To the Bureau of Industry and Security and the ENC Encryption Request
Coordinator:

This updates a previous notification under 15 CFR 742.15(b) concerning
IronCrypto, to give its complete current set of internet locations and
cryptographic functionality as of version 0.2.25.

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
  Version:         0.2.25
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
  Added in this version:
    - XChaCha20-Poly1305, an authenticated cipher with a 192-bit nonce,
      as specified in the public IETF Internet-Draft
      draft-irtf-cfrg-xchacha-03. It is built from ChaCha20 and Poly1305,
      which were already listed, through the HChaCha20 subkey derivation
      that draft defines.
    - Passphrase-based encryption of stored secrets: a key derived with
      Argon2id (RFC 9106) encrypts with XChaCha20-Poly1305, in a container
      format whose specification is published in the source code. It adds
      no cryptographic primitive.
    - OPAQUE, the password-authenticated key exchange of RFC 9807, in
      its OPAQUE-3DH form over P-256 with HKDF, HMAC and SHA-256. It
      authenticates a client by password and establishes a shared key;
      it uses only primitives already listed.
    - Oblivious pseudorandom functions (OPRF, VOPRF and POPRF) of RFC
      9497 over P-256 with SHA-256, and hashing to P-256 as RFC 9380
      specifies. They use only P-256 and SHA-256, already listed.
    - scrypt, the password-based key derivation function of RFC 7914,
      built from PBKDF2 with HMAC-SHA-256 and the Salsa20/8 core.
    - Verification of bcrypt and yescrypt password hashes made elsewhere,
      so that they can be replaced; no new hashes are made. bcrypt uses
      the Blowfish key schedule, which is used for nothing else and is not
      offered as a cipher. yescrypt is built from scrypt, PBKDF2 and
      HMAC-SHA-256, all already listed.
    - Argon2 version 1.0, the version selected by the Password Hashing
      Competition in 2015, beside version 1.3 (RFC 9106), which was already
      listed. It is supported so that password hashes made with it can be
      verified.
    - Writing of PKCS#10 certification requests (RFC 2986), and of URI
      subject alternative names in issued X.509 certificates; reading and
      writing of Argon2 password hashes in the PHC string format.

CRYPTOGRAPHIC FUNCTIONALITY
  IronCrypto implements published algorithms only. It contains no
  proprietary or unpublished cryptographic functionality. All but one are
  specified in standards; XChaCha20-Poly1305 is specified in a public IETF
  Internet-Draft.

    Block cipher and modes   AES-128/192/256 (FIPS 197); CBC, CTR (SP 800-38A);
                             AES Key Wrap and KWP (RFC 3394, RFC 5649)
    AEAD                     AES-GCM (SP 800-38D); AES-GCM-SIV (RFC 8452);
                             ChaCha20-Poly1305 (RFC 8439);
                             XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03)
    Hashes and XOFs          SHA-2 family (FIPS 180-4); SHA-3 and SHAKE
                             (FIPS 202); cSHAKE, KMAC, TupleHash,
                             ParallelHash (SP 800-185); BLAKE2b (RFC 7693)
    MACs                     HMAC (FIPS 198-1); CMAC (SP 800-38B);
                             KMAC (SP 800-185); Poly1305 (RFC 8439)
    Key derivation           HKDF (RFC 5869); PBKDF2 (SP 800-132);
                             SP 800-108 counter mode; scrypt (RFC 7914);
                             Argon2 (RFC 9106, and version 1.0 of the
                             Argon2 specification); verification of
                             bcrypt and yescrypt password hashes
    Passphrase encryption    Argon2id with XChaCha20-Poly1305, in a
                             container format published in the source
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
that adds this file, which is the same list the 0.2.20 notice gave. The
functionality list is the 0.2.20 notice's, with the additions above
taken from `CHANGELOG.md` under Unreleased. The licence line is `license` in
the workspace `Cargo.toml`, `AGPL-3.0-or-later`; "with a separate commercial
option" is carried over from the earlier drafts and was not re-derived. The
RFC numbers in the protocol adapter and older encodings lines are also
carried over unchanged.
