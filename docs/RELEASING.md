# Releasing

**Nothing here may be published or made public without notifying the NSA
first.** That is the whole of this document's reason to exist; the rest is how.

This is not a preference. It is a legal obligation on whoever publishes, and it
binds every route to "public", not just crates.io.

## Why

Publishing cryptographic source code from the United States is an export. Source
code that would be controlled under ECCN 5D002 — which is what a library of AES,
ECDSA, ML-KEM and the rest is — may be made publicly available under the
Export Administration Regulations, but only once a notification has been sent to
both:

- the Bureau of Industry and Security, and
- the NSA's ENC Encryption Request Coordinator,

giving the internet location where the code will be available. The requirement
is at **15 CFR §742.15(b)**. The usual addresses are `crypt@bis.doc.gov` and
`enc@nsa.gov`.

Two things about it are easy to get wrong:

- **It is a notification, not an application.** Nobody has to approve anything
  and there is no waiting period to observe. That makes it tempting to treat as
  a formality, which is the mistake — it is a formality that has to have
  happened.
- **It has to come first.** There is no way to un-publish. A crate pulled from
  crates.io stays in the index and in every mirror; a repository made public and
  private again has been cloned. Sending the notification afterwards does not
  put things back.

This document is not legal advice, and the regulations change. Confirm the
current requirement before relying on the specifics above — the constraint that
does not change is that the notification happens **before** anything goes
public.

## What counts as publishing

All of these, not just the first:

- `cargo publish`, for any crate in this workspace
- changing the GitHub repository from private to public
- pushing a mirror to any public host
- putting a release tarball at a public URL
- a public fork, or granting access broadly enough to amount to one

## What stops it happening by accident

`publish = false` is set in `[workspace.package]` and inherited by all seventeen
crates, so `cargo publish` fails:

```console
$ cargo publish -p iron-crypto --dry-run
error: `iron-crypto` cannot be published.
`package.publish` must be set to `true` or a non-empty list in Cargo.toml to publish.
```

`no_crate_can_be_published_by_accident`, in `crates/ic-cli/src/sbom.rs`, asserts
that every member inherits it and that none overrides it — because a line in a
manifest with nothing watching it is a line someone removes while doing
something else.

Nothing guards repository visibility, which is a GitHub setting rather than
anything in the tree. It is the easier mistake to make: one toggle, no
confirmation of consequence.

## The order, when the time comes

1. Send the notification, to both addresses, with the URL the code will live at.
2. Keep what was sent and when, with the repository.
3. Only then remove `publish = false`, or change visibility.

Reversing steps 1 and 3 cannot be corrected afterwards.

## Not export control, but decide them at the same time

- **Licence.** AGPL-3.0-or-later, with a commercial option. Public availability
  makes the copyleft everyone's problem to reason about rather than yours.
- **Maturity.** No external audit; timing behaviour never measured on quiet
  hardware; four algorithms registered `experimental`, meaning nothing has
  checked them against a second implementation — including both post-quantum
  schemes.
- **No FIPS validation**, and `ic_ontology::runtime::has("fips-validated")`
  returns `false`. Publishing does not change that, and nothing in a release
  announcement should imply otherwise.
- **The self-hosted CI runner.** GitHub advises against self-hosted runners on
  public repositories, because a fork's pull request would then execute on your
  hardware. If this repository ever becomes public, `self-hosted.yml` has to be
  reconsidered in the same change. See `docs/CI.md`.
