# Export control: the notification, ready to send

`docs/RELEASING.md` says the notification has to happen before anything goes
public, and why. This file is the artefact that document lacks: the text to
send, what to keep afterwards, and the determination behind it.

**This is not legal advice.** It is research a non-lawyer did against the
current regulation text, written down so counsel has something concrete to
correct rather than a blank page. The one instruction that does not depend on
any of it: nothing goes public before the notification is sent and recorded.

---

## 1. The determination, and a finding that may change it

The requirement is **15 CFR §742.15(b)**. Reading the current text, it has two
parts that are easy to run together:

- **§742.15(b)(1)** — publicly available encryption source code is, in general,
  **not subject to the EAR**.
- **§742.15(b)(2)** — headed *"Notification requirement for 'non-standard
  cryptography'"* — imposes the email notification, and its opening words are:

  > "For publicly available encryption source code classified under ECCN 5D002
  > that provides or performs **'non-standard cryptography'** as defined in part
  > 772 of the EAR, you must notify BIS and the ENC Encryption Request
  > Coordinator via email..."

**"Non-standard cryptography"** is defined in part 772 as an implementation
involving

> "proprietary or unpublished cryptographic functionality, including encryption
> algorithms or protocols that have not been adopted or approved by a duly
> recognized international standards body (e.g., IEEE, IETF, ISO, ITU, ETSI,
> 3GPP, TIA, and GSMA) and have not otherwise been published."

**On its face, IronCrypto is standard cryptography.** Every algorithm it
implements comes from a published standard — FIPS 197, 180-4, 202, 198-1,
186-5, 203, 204; SP 800-38A/B/D, 800-56A, 800-90A, 800-108, 800-185; RFC 7748,
8017, 8032, 8439, 8452, 9106, and for the TLS and QUIC adapter RFC 5288, 5869,
7905, 8446 and 9001. There is no proprietary primitive and nothing unpublished.
The list in `README.md` under *What's implemented* is the inventory, and
`icrypto ontology export json` produces it mechanically.

If that reading is right, **§742.15(b)(2) does not apply** and no notification
is required. Two reasons that does not settle it:

- The rule changed on **29 March 2021**. Before then the notification was
  required for publicly available encryption source code generally. Guidance
  written before that date — and some published since, including at least one
  BIS support page — still describes the older, broader requirement. Anyone
  checking this quickly will find both answers.
- A classification question is a legal determination with a one-way failure
  mode. Being wrong in the direction of *not* notifying cannot be corrected
  after publication; being wrong in the direction of notifying costs an email.

**So the recommendation is to send it regardless**, and to have counsel confirm
whether it was required. The conservative action and the cheap action are the
same one here, which is a good reason not to spend judgement on the question.

---

## 2. The notification

Send from an address that will still receive mail in a year, because a reply
may come back to it. Send to both recipients in one message so the record is
one artefact.

**To:** `crypt@bis.doc.gov`, `enc@nsa.gov`
**Subject:** `Notification of publicly available encryption source code — 15 CFR 742.15(b) — IronCrypto`

```text
To the Bureau of Industry and Security and the ENC Encryption Request
Coordinator:

This is a notification under 15 CFR 742.15(b) of the internet location of
publicly available encryption source code.

SUBMITTER
  Entity:          Nervosys
  Contact:         <name>, <title>
  Email:           <address that will remain monitored>
  Telephone:       <number>
  Postal address:  <address>

ITEM
  Name:            IronCrypto
  Description:     An open-source cryptographic library written in Rust,
                   distributed as source code.
  Classification:  ECCN 5D002 (encryption source code)
  Licence:         AGPL-3.0-or-later, with a separate commercial option

INTERNET LOCATION
  https://github.com/nervosys/IronCrypto

  The source code is or will be publicly available at that URL without
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
                             Poly1305 (RFC 8439)
    Key derivation           HKDF (RFC 5869); PBKDF2 (SP 800-132);
                             SP 800-108 counter mode; Argon2 (RFC 9106)
    Random bit generation    HMAC_DRBG and CTR_DRBG (SP 800-90A)
    Public key               ECDSA and ECDH over P-256, P-384, P-521
                             (FIPS 186-5, SP 800-56A, RFC 6979);
                             X25519 (RFC 7748); Ed25519 (RFC 8032);
                             RSA PKCS#1 v1.5 and PSS (FIPS 186-5, RFC 8017)
    Post-quantum             ML-KEM-768 (FIPS 203); ML-DSA-65 (FIPS 204)
    Protocol adapter         Record and packet protection for TLS 1.2, TLS 1.3
                             and QUIC (RFC 5288, 5869, 7905, 8446, 9001), as a
                             provider for the rustls library

  IronCrypto is not FIPS 140-3 validated and holds no CMVP certificate. The
  standards above are cited to identify the algorithms implemented, not to
  claim validation.

This notification is submitted before the source code is made publicly
available.

<name>
<title>, Nervosys
<date>
```

### Before sending, confirm

- [ ] The URL is the one the code will actually live at. If it will also be
      mirrored, or published to crates.io under a different name, say so here
      rather than sending a second notification later.
- [ ] The algorithm inventory above still matches `README.md`. It was accurate
      at the commit that added this file; a new primitive changes it.
- [ ] Counsel has reviewed, including the §742.15(b)(2) question in section 1.
- [ ] The contact address will still be monitored in a year.

---

## 3. What to keep

`docs/RELEASING.md` step 2 says to keep what was sent and when, with the
repository. The point is to be able to answer "was notification given, and
when" years later without depending on one person's mailbox.

Commit a record at `docs/export/` — not in this file, which is a template —
containing:

| field | |
|---|---|
| Date and time sent | with timezone |
| Sent from | the address used |
| Sent to | both recipients, as addressed |
| Subject line | verbatim |
| Body | verbatim, as sent |
| URL notified | exactly as given |
| Commit | the repository state at the time of sending |
| Acknowledgement | any reply, or "none received" with the date checked |
| Counsel | who reviewed, and when |

No acknowledgement is expected. §742.15(b) is a notification, not an
application: nothing has to be approved and there is no waiting period. Silence
is the normal outcome and is not a problem, which is exactly why the sender's
own record is the only evidence that will exist.

---

## 4. Order of operations

From `docs/RELEASING.md`, repeated because getting it wrong is the failure this
whole document exists to prevent:

1. Send the notification to both addresses, with the URL.
2. Commit the record.
3. Only then remove `publish = false`, or change repository visibility.

Steps 1 and 3 cannot be reversed. A crate pulled from crates.io stays in the
index and in every mirror; a repository made public and private again has been
cloned.

And decided in the same change, because publication forces them: the licence,
the absence of an external audit, the absence of FIPS validation, and
`self-hosted.yml` — GitHub advises against self-hosted runners on public
repositories, because a fork's pull request would then run on your hardware.
