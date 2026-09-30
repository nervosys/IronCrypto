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

## Determination

`docs/EXPORT.md` sets out why, since the 2021 amendment, §742.15(b) may not
apply to an implementation of published standards at all, and why that reading
was not relied on without counsel. Nothing here changes that analysis or
substitutes for it. This file records events; it does not assess them.
