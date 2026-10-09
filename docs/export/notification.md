# Export notification record

The record `docs/EXPORT.md` section 3 asks for, of the notification under
15 CFR §742.15(b) to BIS and the NSA's ENC Encryption Request Coordinator.

**This record is incomplete.** It was written on 2026-09-28, after the fact, from
what the repository, crates.io and GitHub can show. The notification itself --
when it was sent, to whom, and what it said -- is in the maintainer's sent mail
and has not been transcribed here. Every field that depends on it says so
rather than guessing: a record with plausible values in those fields would look
like evidence and not be.

To complete it, copy the sent message into the fields below exactly as sent, and
delete this paragraph and the one above.

## The notification

| field | |
|---|---|
| Date and time sent | **Not recorded.** Reported sent no later than 2026-09-22 19:53:17 -0700; see below. |
| Sent from | **Not recorded.** |
| Sent to | **Not recorded.** `docs/EXPORT.md` gives `crypt@bis.doc.gov` and `enc@nsa.gov` as the usual addresses; whether those were the ones used is not recorded. |
| Subject line | **Not recorded.** |
| Body | **Not recorded.** The draft is in `docs/EXPORT.md`; whether it was sent as drafted is not recorded. |
| URL notified | **Not recorded.** |
| Commit | **Not recorded.** |
| Acknowledgement | **Not recorded.** |
| Counsel | **Not recorded.** |

## What the repository and the registries do show

**The report that it was sent.** Commit `332320e`, 2026-09-22 19:53:17 -0700,
"Turn publishing on, the notification having been sent", set `publish = true`.
Its message: "The maintainer reports it sent, so the flag comes off. The record
of what was sent and when still belongs in docs/export/." That report is the
only evidence of the notification in the repository, and it bounds the sending
time from above and not from below.

**Repository visibility.** GitHub's event log for `nervosys/IronCrypto`
records a `PublicEvent` -- the repository changing from private to public -- at
**2026-09-16 00:53:58 UTC** (2026-09-15 17:53:58 -0700), by `admercs`. That is
six days before the commit above. Whether the notification was sent before
this is **not recorded**; only the sent message can settle it.

**Publications to crates.io**, all by `admercs`, times from the crates.io API
for `ic-core`, the first crate of each release to upload:

| version | first upload (UTC) | notes |
|---|---|---|
| 0.1.0 | 2026-09-23 02:56:59 | 13 of the 18 crates; see `CHANGELOG.md` |
| 0.1.1 | 2026-09-23 05:41:27 | first complete release |
| 0.1.2 | 2026-09-23 16:09:34 | |
| 0.1.3 | 2026-09-23 17:01:29 | |
| 0.2.0 | 2026-09-28 22:38:19 | |
| 0.2.1 | 2026-09-29 02:37:52 | published after the maintainer confirmed, when asked, that the notification covers this release |
| 0.2.2 | 2026-09-29 05:23:29 | published after the maintainer confirmed, when asked, that the notification covers this release |
| 0.2.3 | 2026-09-29 15:29:47 | published after the maintainer confirmed, when asked, that the notification covers this release, including the ML-KEM-512/1024 and ML-DSA-44/87 parameter sets it adds; `docs/EXPORT.md`'s draft lists only ML-KEM-768 and ML-DSA-65 |
| 0.2.4 | 2026-09-29 16:42:11 | published after the maintainer confirmed, when asked, that the notification covers this release; adds X.509 certificate issuance |
| 0.2.5 | 2026-09-30 02:08:53 | all eighteen crates published from `e5d759f`, after the maintainer confirmed that the notification covers this release; constant-time fixes and generator-multiplication improvements |
| 0.2.6 | 2026-09-30 14:38:55 | all eighteen crates published from `0adec96`, after the maintainer confirmed that the notification covers this release; LTO mask fixes, compiled-code probes and timing additions |
| 0.2.7 | 2026-09-30 16:44:00 | all eighteen crates published from `85183e5`, after the maintainer reported submitting the updated release notice; core mask fix and nineteen compiled-code probes |
| 0.2.8 | 2026-10-05 21:28:31 | all eighteen crates published from `387e6f5`, after the maintainer reported submitting the updated release notice and confirmed that it covers the facade's new name, `ironcrypto`; stack and allocation reductions |
| 0.2.9 | 2026-10-05 22:31:00 | all eighteen crates published from `7853469`, after the maintainer instructed this agent to proceed when asked to confirm that the notification covers this release; ML-KEM stack reduction |
| 0.2.10 | 2026-10-05 22:59:11 | all eighteen crates published from `66857b2`, after the maintainer answered, when asked, that the notification covers this release; ML-DSA stack reduction |
| 0.2.11 | 2026-10-06 02:51:52 | all nineteen crates published from `d5a8587`, after the maintainer instructed this agent to proceed when told the release needed confirmation that the notification covers it; adds `ic-hpke`, a new location |
| 0.2.12 | 2026-10-06 03:59:47 | all nineteen crates published from `0c945bd`, after the maintainer answered, when asked, that the notification covers this release; HPKE DeriveKeyPair |
| 0.2.13 | 2026-10-06 15:29:21 | all nineteen crates published from `adf1f16` by the maintainer, after instructing this agent to proceed when told the release needed confirmation that the notification covers it; security audit fixes |
| 0.2.14 | 2026-10-06 17:38:05 | all nineteen crates published from `1821d9c` by the maintainer, after instructing this agent to proceed when told the release needed their decision on whether the notification covers it; nonce-managing sealer, shipped rules, MCP tools and `ic lint` |
| 0.2.15 | 2026-10-06 19:39:23 | all nineteen crates published from `a39dfeb` by the maintainer, after instructing this agent to push and publish when told the release adds an algorithm and that whether the notification covers it was their decision; HPKE with DHKEM(P-384, HKDF-SHA384) |
| 0.2.16 | 2026-10-08 18:49:40 | all twenty crates published from `d54aebf` by the maintainer, after replying "then release it" when asked whether to send an updated notice first; adds `ic-sig`, a new location, for which a notice was printed before the publish commands and has not been reported sent |
| 0.2.17 | 2026-10-08 20:05:34 | all twenty-one crates published from `0792efb` by the maintainer, after replying "Proceed" when told the release needed an updated notice; adds `ic-lms`, a new location and a new algorithm (HSS/LMS verification), for which a notice naming it and `ic-sig` was printed before the publish commands and has not been reported sent |
| 0.2.18 | 2026-10-08 22:36:28 | all twenty-one crates published from `eb790c3` by the maintainer, after replying "Proceed" when asked whether to release a data-and-documentation change; CNSA 2.0 profile, no new algorithm or package |
| 0.2.19 | 2026-10-09 01:26:22 | all twenty-two crates published from `8329898` by the maintainer, after replying "Proceed" when told the release needed an updated notice; adds `ic-slhdsa`, a new location and a new algorithm (SLH-DSA, FIPS 205), for which a notice naming it, `ic-sig` and `ic-lms` was printed before the publish commands and has not been reported sent |
| 0.2.20 | 2026-10-09 21:25:24 | all twenty-two crates published from `016aa34` by the maintainer, after replying "Sent. Proceed" when the updated notice printed for them was in front of them; adds no location and no algorithm; corrects Poly1305 (see the CHANGELOG, Security) |

The first upload came 3 minutes 42 seconds after `332320e`.

`docs/RELEASING.md` treats each new version as an export in its own right. No
separate notification for 0.1.1 onward is recorded. For 0.1.1 to 0.2.0,
whether the original one was taken to cover them is not recorded either. For
0.2.1 through 0.2.6 it is: the maintainer was asked before each
publication whether the notification covers the release, and answered that it
does.

## 0.2.5 release authorization

On 2026-09-29 the maintainer instructed this agent to proceed after being
explicitly asked to confirm that the BIS/NSA notification covers 0.2.5.
Publication proceeds on that confirmation, as for 0.2.1 through 0.2.4.
The sent message, its recipients and sending time have not been supplied here.
`update-0.2.5-draft.md` remains a draft, not a record of a sent message.

The crates.io API confirmed all eighteen 0.2.5 packages live and not yanked.
The first upload was `ic-core` at 2026-09-30 02:08:53 UTC; the last was
`ic-cli` at 02:12:32 UTC. The published source commit is `e5d759f`.

All 66 published 0.1.x versions across the eighteen crates were confirmed
yanked against the crates.io API on 2026-09-29, after completing the 65
previously pending yanks. Yanking does not remove their downloadable archives
or prevent existing lock files from using them.

## 0.2.6 release authorization

On 2026-09-30 the maintainer instructed this agent to proceed after being
explicitly asked to confirm that the BIS/NSA notification covers the prepared
0.2.6 release, including its constant-time fixes and timing additions.
Publication proceeds on that confirmation. The sent message, its recipients
and sending time have not been supplied here; this records the maintainer's
confirmation, not evidence of a newly sent notification.

The crates.io API confirmed all eighteen 0.2.6 packages live and not yanked.
The first upload was `ic-core` at 2026-09-30 14:38:55 UTC; the last was
`ic-cli` at 14:39:54 UTC. The published source commit is `0adec96`.
All 66 published 0.1.x versions were also confirmed still yanked.

## 0.2.7 notification submission

On 2026-09-30 the maintainer reported "Submitted" after this agent printed
the updated IronCrypto 0.2.7 release notice addressed to `crypt@bis.doc.gov`
and `enc@nsa.gov`. The notice identified the GitHub repository, all eighteen
crates.io package locations, the core mask fix and expanded compiled-code
probes, and stated that no new algorithms or parameter sets were added.

Publication proceeds on the maintainer's submission report. The actual sent
message, completed contact fields and exact sending time have not been
supplied here. This records the report, not an independently verified mail
delivery or a claim that the draft's placeholders were sent unchanged.

The crates.io API confirmed all eighteen 0.2.7 packages live and not yanked.
The first upload was `ic-core` at 2026-09-30 16:44:00 UTC; the last was
`ic-cli` at 16:45:11 UTC. The published source commit is `85183e5`;
all eighteen verified packages identified that clean commit in their VCS
metadata. All 66 published 0.1.x versions were confirmed still yanked.

The maintainer subsequently created `v0.2.7` at `85183e5` and pushed master
and the tag. The supplied terminal output reported both successful updates
and a passing full pre-push gate, including all 76 compiled-code probe checks.

## 0.2.8 notification submission

On 2026-10-05 the maintainer reported "Submitted" after this agent printed an
updated IronCrypto 0.2.8 release notice addressed to `crypt@bis.doc.gov` and
`enc@nsa.gov`. The notice identified the GitHub repository and eighteen
crates.io package names, including `iron-crypto`, and described the release
as memory-use reductions with no new algorithms or parameter sets.

In the same message the maintainer asked for the facade crate to be renamed
from `iron-crypto` to `ironcrypto`, which publishes it at a crates.io location
the notice does not name. Asked how that location should be covered, the
maintainer answered that the existing notification already covers the
renamed package. Publication proceeds on that answer. This records the
maintainer's report and answer, not the sent message, its completed contact
fields or its sending time, none of which have been supplied here.

`iron-crypto` stays on crates.io at 0.2.7 and receives no further releases.

The crates.io API confirmed all eighteen 0.2.8 packages live and not yanked,
`ironcrypto` among them. The first upload was `ic-core` at 2026-10-05
21:28:31 UTC; the last was `ic-cli` at 21:28:51 UTC. The published source
commit is `387e6f5`; all eighteen packages identified that clean commit in
their VCS metadata.

## 0.2.9 release authorization

On 2026-10-05 this agent printed an updated notice for 0.2.9, naming
`ironcrypto` and recording `iron-crypto` as the earlier name, and asked the
maintainer to confirm before publication that the BIS/NSA notification
covers 0.2.9. The maintainer replied "Proceed". Publication proceeded on that
instruction, as for 0.2.5 and 0.2.6. No submission of the printed notice was
reported, and no sent message, recipients or sending time have been supplied
here; this records the instruction, not a newly sent notification.

The crates.io API confirmed all eighteen 0.2.9 packages live and not yanked.
The first upload was `ic-core` at 2026-10-05 22:31:00 UTC; the last was
`ic-cli` at 22:31:36 UTC. The published source commit is `7853469`; all
eighteen packages identified that clean commit in their VCS metadata. That
commit's message says it adds this section; it does not, because the edit
failed, and this section was written after publication.

## 0.2.10 release authorization

On 2026-10-05 the maintainer was asked whether the BIS/NSA notification
covers 0.2.10, a release that changes only ML-DSA's memory use, adds no
algorithms or parameter sets, and publishes under the same eighteen package
names as 0.2.9. The maintainer answered that it is covered. Publication
proceeds on that answer. No new notice was sent or supplied here; this records
the maintainer's answer, not a newly sent notification.

The crates.io API confirmed all eighteen 0.2.10 packages live and not yanked.
The first upload was `ic-core` at 2026-10-05 22:59:11 UTC; the last was
`ic-cli` at 22:59:30 UTC. The published source commit is `66857b2`; all
eighteen packages identified that clean commit in their VCS metadata.

## 0.2.11 release authorization

0.2.11 adds a nineteenth package, `ic-hpke`, at a crates.io location no
earlier notice named (https://crates.io/crates/ic-hpke), and new cryptographic
functionality: HPKE (RFC 9180), ECDSA verification over a caller-supplied
digest, ML-DSA private-key encoding, and Shamir secret sharing. On 2026-10-05
this agent listed what the release needed from the maintainer -- approval to
push, approval to publish, and confirmation that the BIS/NSA notification
covers the release, `ic-hpke` being a new location -- and the maintainer
replied "Proceed". Publication proceeds on that instruction. No updated
notice naming `ic-hpke` was printed for this release, and no submission was
reported; this records the instruction, not a sent notification.

The crates.io API confirmed all nineteen 0.2.11 packages live and not yanked,
`ic-hpke` among them. The first upload was `ic-core` at 2026-10-06 02:51:52
UTC; the last was `ic-cli` at 02:52:12 UTC. The published source commit is
`d5a8587`; all nineteen packages identified that clean commit in their VCS
metadata.

## 0.2.11 notification submission

After 0.2.11 was published, this agent printed an updated notice addressed to
`crypt@bis.doc.gov` and `enc@nsa.gov`. It names the GitHub repository and all
nineteen crates.io package names, identifies `ic-hpke` as new with 0.2.11
(https://crates.io/crates/ic-hpke), notes `iron-crypto` as the earlier name of
the main package, and lists the release's additions: HPKE (RFC 9180), ECDSA
verification over a caller-supplied digest, ML-DSA private-key encoding, and
Shamir secret sharing. On 2026-10-05 the maintainer reported "Submitted".

This records the report, not the sent message, its completed contact fields
or its sending time, none of which have been supplied here. It also leaves
the order of events as it was: 0.2.11, and with it the `ic-hpke` location,
was published at 2026-10-06 02:51:52 UTC on the instruction recorded above,
before this notice was printed.

## 0.2.12 release authorization

On 2026-10-06 the maintainer was asked whether the BIS/NSA notification covers
0.2.12, which publishes under the same nineteen package names as 0.2.11 and
adds only HPKE's DeriveKeyPair inside the already-notified `ic-hpke`. The
maintainer answered that it is covered. Publication proceeds on that answer;
no new notice was sent or supplied here.

The crates.io API confirmed all nineteen 0.2.12 packages live and not yanked.
The first upload was `ic-core` at 2026-10-06 03:59:47 UTC; the last was
`ic-cli` at 04:00:06 UTC. The published source commit is `0c945bd`; all
nineteen packages identified that clean commit in their VCS metadata.

## 0.2.13 release authorization

On 2026-10-06 this agent told the maintainer that releasing 0.2.13 needed
their go-ahead and confirmation that the BIS/NSA notification covers it. The
release publishes under the same nineteen package names as 0.2.12 and adds
no algorithm: it carries fixes from a security audit, two self-tests for
existing KDFs, and documentation. The maintainer replied "Proceed".
Publication proceeds on that instruction; this records the instruction, not
a statement that the notification covers 0.2.13, and no new notice was sent
or supplied here.

This agent's attempt to push was refused by its own permission checks, so the
maintainer pushed `master` and the `v0.2.13` tag and ran `cargo publish
--workspace` themselves. The crates.io API confirmed all nineteen 0.2.13
packages live and not yanked. The first upload was `ic-core` at 2026-10-06
15:29:21 UTC; the last was `ic-cli` at 15:29:44 UTC. The published source
commit is `adf1f16`; all nineteen packages identified that clean commit in
their VCS metadata.

## 0.2.14 release authorization

On 2026-10-06 this agent told the maintainer that 0.2.14 needed two
decisions of theirs: pushing `master`, which publishes the source since the
repository is public, and whether the BIS/NSA notification covers the
release. The release publishes under the same nineteen package names as
0.2.13. It adds `ic_cipher::Sealer` and `Opener`, SP 800-38D section 8.2.1's
deterministic nonce construction over AEADs already in the library; MCP
tools that open, verify and derive with existing primitives; a source
linter that performs no cryptography; and documentation. The maintainer
replied "Proceed". Publication proceeds on that instruction; this records
the instruction, not a statement that the notification covers 0.2.14, and
no new notice was sent or supplied here.

The maintainer pushed `master` and the `v0.2.14` tag and ran `cargo publish
--workspace` themselves. The crates.io API confirmed all nineteen 0.2.14
packages live and not yanked. The first upload was `ic-core` at 2026-10-06
17:38:05 UTC; the last was `ic-cli` at 17:38:37 UTC. The published source
commit is `1821d9c`; all nineteen packages identified that clean commit in
their VCS metadata.

## 0.2.15 release authorization

On 2026-10-06 this agent told the maintainer that releasing 0.2.15 needed
their go-ahead, and that because it adds an algorithm -- HPKE with
DHKEM(P-384, HKDF-SHA384), inside the already-notified `ic-hpke` package --
whether the BIS/NSA notification covers it, or needs updating first, was
their decision. The release publishes under the same nineteen package names
as 0.2.14; the algorithm is RFC 9180's, a published standard, built from
primitives already in the library. The maintainer replied "Push and
publish". Publication proceeds on that instruction; this records the
instruction, not a statement that the notification covers 0.2.15, and no
new notice was sent or supplied here.

The maintainer pushed `master` and the `v0.2.15` tag, created the GitHub
release, and ran `cargo publish --workspace` themselves. The crates.io API
confirmed all nineteen 0.2.15 packages live and not yanked. The first upload
was `ic-core` at 2026-10-06 19:39:23 UTC; the last was `ic-cli` at 19:40:06
UTC. The published source commit is `a39dfeb`; all nineteen packages
identified that clean commit in their VCS metadata.

## 0.2.16 release authorization

0.2.16 adds a twentieth package, `ic-sig`
(https://crates.io/crates/ic-sig), which is a new location. It verifies
signatures by algorithm over X.509 public keys by calling the schemes in
`ic-ec`, `ic-rsa` and `ic-mldsa`, and implements no cryptographic algorithm of
its own. The release also adds a signing interface to `ic-core` that nothing
implements, and NIST SP 800-53 control mappings.

On 2026-10-08 this agent told the maintainer that the release adds a package
name and no new cryptographic functionality, and asked whether they wanted an
updated notice naming `ic-sig` drafted to send before publication. The
maintainer replied "then release it". Before any publish command was given
to the maintainer, this agent printed an updated notice addressed to
`crypt@bis.doc.gov` and `enc@nsa.gov`, naming the GitHub repository and all
twenty crates.io package names and identifying `ic-sig` as new with 0.2.16,
for the maintainer to send first. Publication proceeds on the maintainer's
instruction; this records that instruction and that the notice was printed,
not that it was sent, which has not been reported here.

The maintainer pushed `master` and the `v0.2.16` tag, created the GitHub
release, and ran `cargo publish --workspace` themselves. This agent reminded
them, before the tag and again before the publish command, that the notice
could still be sent first; no report that it was sent came before
publication. The crates.io API confirmed all twenty 0.2.16 packages live and
not yanked, `ic-sig` among them. The first upload was `ic-core` at 2026-10-08
18:49:40 UTC; `ic-sig` at 18:50:16 UTC; the last was `ic-cli` at 18:50:20
UTC. The published source commit is `d54aebf`; all twenty packages identified
that clean commit in their VCS metadata.

## 0.2.17 release authorization

0.2.17 adds a twenty-first package, `ic-lms`
(https://crates.io/crates/ic-lms), which is a new location, and with it a new
algorithm: verification of HSS/LMS stateful hash-based signatures (RFC 8554,
RFC 9858, NIST SP 800-208). It verifies signatures and does not create them;
it performs no encryption.

On 2026-10-08 this agent told the maintainer that the release adds an
algorithm and a package, that it needs an updated notice naming `ic-lms`,
that the notice would be printed before any publish command, and that it
still did not know whether the notice naming `ic-sig` for 0.2.16 had been
sent. The maintainer replied "Proceed". This agent then printed one notice
addressed to `crypt@bis.doc.gov` and `enc@nsa.gov`, naming the GitHub
repository and all twenty-one crates.io package names and identifying both
`ic-sig` (new with 0.2.16) and `ic-lms` (new with 0.2.17), for the maintainer
to send before publishing. Publication proceeds on the maintainer's
instruction; this records that instruction and that the notice was printed,
not that it or the 0.2.16 notice was sent, neither of which has been reported
here.

The maintainer pushed `master` and the `v0.2.17` tag, created the GitHub
release, and ran `cargo publish --workspace` themselves. This agent reminded
them, before the tag push and again before the publish command, that the
notice could still be sent first; no report that it was sent came before
publication. The crates.io API confirmed all twenty-one 0.2.17 packages live
and not yanked, `ic-lms` among them. The first upload was `ic-core` at
2026-10-08 20:05:34 UTC; `ic-lms` at 20:05:47 UTC; the last was `ic-cli` at
20:06:09 UTC. The published source commit is `0792efb`; all twenty-one
packages identified that clean commit in their VCS metadata.

## 0.2.18 release authorization

0.2.18 publishes under the same twenty-one package names as 0.2.17 and adds
no algorithm and no cryptographic code: a CNSA 2.0 profile in the ontology,
an entry recording that XMSS is not implemented, and a corrected control
mapping.

On 2026-10-08 this agent told the maintainer that the change was data and
documentation only, with no new algorithm and no new package, and asked
whether to release it as 0.2.18 or hold it. The maintainer replied
"Proceed". Publication proceeds on that instruction; no new notice was
printed for this release. The notice naming `ic-sig` and `ic-lms`, printed
for 0.2.17, has still not been reported sent.

The maintainer pushed `master` and the `v0.2.18` tag, created the GitHub
release, and ran `cargo publish --workspace` themselves; a first run that
stalled on a shared build directory uploaded nothing and ended with an
error, and a second, in a separate build directory, published. The crates.io
API confirmed all twenty-one 0.2.18 packages live and not yanked. The first
upload was `ic-core` at 2026-10-08 22:36:28 UTC; the last was `ic-cli` at
22:37:03 UTC. The published source commit is `eb790c3`; all twenty-one
packages identified that clean commit in their VCS metadata.

## 0.2.19 release authorization

0.2.19 adds a twenty-second package, `ic-slhdsa`
(https://crates.io/crates/ic-slhdsa), which is a new location, and with it a
new algorithm: SLH-DSA, the stateless hash-based digital signature standard
of FIPS 205, with key generation, signing and verification. It performs no
encryption.

On 2026-10-08 this agent told the maintainer that the release adds an
algorithm and a package, that it needs an updated notice, that the notice
would be printed before any publish command, and that it had had no report
that the notice naming `ic-sig` and `ic-lms` was sent. The maintainer replied
"Proceed". This agent then printed one notice addressed to
`crypt@bis.doc.gov` and `enc@nsa.gov`, naming the GitHub repository and all
twenty-two crates.io package names and identifying `ic-sig` (new with
0.2.16), `ic-lms` (new with 0.2.17) and `ic-slhdsa` (new with 0.2.19), for
the maintainer to send before publishing. Publication proceeds on the
maintainer's instruction; this records that instruction and that the notice
was printed, not that it or either earlier notice was sent, none of which has
been reported here.

The maintainer pushed `master` and the `v0.2.19` tag and ran `cargo publish
--workspace` themselves. The first push of `master` passed its checks and
failed in transfer with a connection reset, leaving the remote unchanged; a
second succeeded. This agent reminded them, after that push and again before
the publish command, that the notice could still be sent first; no report
that it was sent came before publication. The crates.io API confirmed all
twenty-two 0.2.19 packages live and not yanked, `ic-slhdsa` among them. The
first upload was `ic-core` at 2026-10-09 01:26:22 UTC; `ic-slhdsa` at
01:26:50 UTC; the last was `ic-cli` at 01:27:00 UTC. The published source
commit is `8329898`; all twenty-two packages identified that clean commit in
their VCS metadata.

## Notification submission for `ic-sig`, `ic-lms` and `ic-slhdsa`

On 2026-10-09 (UTC) this agent asked the maintainer whether the export notice
naming `ic-sig`, `ic-lms` and `ic-slhdsa` had been sent to BIS and NSA. The
maintainer answered "Yes, sent".

The notice in question is the one this agent printed for 0.2.19, addressed to
`crypt@bis.doc.gov` and `enc@nsa.gov`, naming the GitHub repository and all
twenty-two crates.io package names and identifying `ic-sig` (new with
0.2.16), `ic-lms` (new with 0.2.17) and `ic-slhdsa` (new with 0.2.19). Earlier
versions of it, naming one and then two of those packages, were printed for
0.2.16 and 0.2.17.

This records the maintainer's report, not the sent message, its completed
contact fields or its sending time, none of which have been supplied here.
Nor does it say which of the three printed texts was sent, or when relative
to each publication: the report came after all three packages were public,
and the release entries above record that no report had come before each was
published.

## 0.2.20 release authorization

0.2.20 adds no package: the locations are the twenty-two already named. It
adds no algorithm. It adds HashSLH-DSA, the pre-hash interface of FIPS 205, to
`ic-slhdsa`, and verification of SLH-DSA and HSS/LMS signatures to `ic-sig`;
both algorithms were already in `ic-slhdsa` and `ic-lms`. It corrects
Poly1305, which was computed wrong for some inputs from 0.2.5 to 0.2.19; the
CHANGELOG has that under Security. The rest is self-tests, an error state and
test vectors.

On 2026-10-09 this agent told the maintainer of the Poly1305 defect and that
a release needed their word and their decision on the notice. The maintainer
replied "Message the other sessions, then prepare the advisory and email for
the release." This agent wrote `docs/export/update-0.2.20-draft.md` (since
renamed `update-0.2.20-as-printed.md`), a
complete updated notice addressed to `crypt@bis.doc.gov` and `enc@nsa.gov`
with the contact fields and the date of the previous notification left
blank, and said that whether to send it was the maintainer's determination,
since the release adds no location and no algorithm. The maintainer asked for
it to be printed, and after it was printed replied "Sent. Proceed".

This records that reply. It does not record the sent message, its completed
fields, its sending time or its recipients, none of which have been supplied
here. Publication proceeds on it.

The maintainer ran `cargo publish --workspace` themselves. The crates.io API
confirmed all twenty-two 0.2.20 packages live and not yanked. The first upload
was `ic-core` at 2026-10-09 21:25:24 UTC and the last `ic-cli` at 21:26:05
UTC. The published source commit is `016aa34`; all twenty-two packages
identified that clean commit in their VCS metadata. At publication the commit
had not been pushed to GitHub, by intent: it describes a defect that no
published version yet corrected.

## Determination

`docs/EXPORT.md` sets out why, since the 2021 amendment, §742.15(b) may not
apply to an implementation of published standards at all, and why that reading
was not relied on without counsel. Nothing here changes that analysis or
substitutes for it. This file records events; it does not assess them.
