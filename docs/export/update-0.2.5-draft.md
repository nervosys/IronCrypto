# Updated notification for 0.2.5: DRAFT, NOT SENT

A draft of an updated notification under 15 CFR §742.15(b), to be reviewed
and sent by the maintainer before 0.2.5 is published. **Nothing in this file
has been sent.** Once it is, record what was actually sent in
`docs/export/notification.md` (the fields in `docs/EXPORT.md` section 3), and
either delete this file or rename it to say it is the text that was sent.

`docs/EXPORT.md` is left as it was: it may be the text of the original
notification, and editing it would lose that.

## Why an update

`docs/RELEASING.md` treats every published version as an export in its own
right. The original draft in `docs/EXPORT.md` is out of date in four ways:

1. **Post-quantum parameter sets.** It lists ML-KEM-768 and ML-DSA-65 only.
   Since 0.2.3 the library also implements ML-KEM-512 and ML-KEM-1024, and
   ML-DSA-44 and ML-DSA-87.
2. **X.509 certificate issuance** (0.2.4), in `ic-pkix`. This encodes
   certificates and does no cryptography itself, since signing is done by the
   caller, but it is new functionality.
3. **Distribution locations.** The draft names only the GitHub repository.
   The code is also published to crates.io as 18 packages. The draft's own
   checklist says to name every location in one notification rather than send
   a second later.
4. **Encodings.** DER and PEM for keys and signatures (`ic-pkix`) are not in
   the draft's inventory.

0.2.5 itself adds no algorithm. It changes how existing ones are computed:
- a faster P-256 generator multiplication;
- 32-bit-word arithmetic on RISC-V for the existing curves and RSA;
- constant-time fixes in hex and Base64, AES key wrap, ML-DSA and ML-KEM.

The inventory below is checked against `README.md` ("What's implemented") and
the crate manifests at the commit that adds this file.

## §742.15(b)(2)

`docs/EXPORT.md` section 1 sets out why the notification may not be required
at all since 29 March 2021: it applies to "non-standard cryptography", and
every algorithm here is from a published standard. That analysis is unchanged
and still unreviewed by counsel. The recommendation there, to notify
regardless, applies to this update for the same reason.

---

**To:** `crypt@bis.doc.gov`, `enc@nsa.gov`
**Subject:** `Updated notification of publicly available encryption source code — 15 CFR 742.15(b) — IronCrypto`

```text
To the Bureau of Industry and Security and the ENC Encryption Request
Coordinator:

This updates a previous notification under 15 CFR 742.15(b) concerning
IronCrypto, to give its complete current set of internet locations and
cryptographic functionality.

SUBMITTER
  Entity:          Nervosys
  Contact:         <name>, <title>
  Email:           <address that will remain monitored>
  Telephone:       <number>
  Postal address:  <address>

PREVIOUS NOTIFICATION
  Sent:            <date of the original notification>

ITEM
  Name:            IronCrypto
  Description:     An open-source cryptographic library written in Rust,
                   distributed as source code, with a command-line tool.
  Classification:  ECCN 5D002 (encryption source code)
  Licence:         AGPL-3.0-or-later, with a separate commercial option

INTERNET LOCATIONS
  Source repository:
    https://github.com/nervosys/IronCrypto

  Source packages on crates.io, the Rust package registry, each at
  https://crates.io/crates/<name>:
    iron-crypto, ic-core, ic-hash, ic-mac, ic-cipher, ic-kdf, ic-drbg,
    ic-ec, ic-rsa, ic-mlkem, ic-mldsa, ic-pkix, ic-rustls, ic-fips,
    ic-ontology, ic-json, ic-vectors, ic-cli

  The source code is publicly available at these locations without
  restriction on access and without charge.

CRYPTOGRAPHIC FUNCTIONALITY
  IronCrypto implements published, standardised algorithms only. It contains
  no proprietary or unpublished cryptographic functionality.

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
    Post-quantum             ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203);
                             ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
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

### Before sending, confirm

- [ ] The date of the original notification is filled in, or the "PREVIOUS
      NOTIFICATION" block is removed if you would rather not cite it. The
      repository does not record it (`docs/export/notification.md`).
- [ ] The inventory still matches `README.md` at the commit you release.
- [ ] The RFC numbers under "Encodings" are the ones you want cited. They
      identify the formats `ic-pkix` reads and writes: SPKI and certificates
      (5280), EC public keys (5480), SEC1 EC private keys (5915), PKCS#8 (5958),
      PEM (7468). The ML-DSA certificate format is RFC 9881, which you may add.
- [ ] Counsel has reviewed, including the §742.15(b)(2) question.
- [ ] The contact address will still be monitored in a year.

Then:
1. Send it.
2. Record what was sent in `docs/export/notification.md`.
3. Only then publish 0.2.5.
