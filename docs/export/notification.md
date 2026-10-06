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

## Determination

`docs/EXPORT.md` sets out why, since the 2021 amendment, §742.15(b) may not
apply to an implementation of published standards at all, and why that reading
was not relied on without counsel. Nothing here changes that analysis or
substitutes for it. This file records events; it does not assess them.
