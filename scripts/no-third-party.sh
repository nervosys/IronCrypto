#!/usr/bin/env bash
#
# The workspace must depend on nothing outside itself.
#
# This is the claim the SBOM rests on, and CWE-1104 and T1195.001 in the
# compliance model with it. One `cargo add` would end it, so it is asserted
# rather than trusted.
#
# It lives in its own file because there used to be two copies -- one here in
# `check.sh`, one written out again in `.github/workflows/ci.yml` -- and they
# drifted. CI's copy listed ten crates by name, so it was already wrong for
# `rsa`, `pkix`, `mlkem`, `mldsa`, `json` and `vectors`, and after the rename
# from `ac-` to `ic-` it matched none of them: every workspace crate was
# reported as a third-party dependency and the job failed on every push.
#
# The list is no longer written out at all. It is read from the workspace
# manifest, which is the thing that decides what a workspace member is.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Members, from the manifest rather than from memory.
members=$(sed -n '/^members = \[/,/^\]/p' "$root/Cargo.toml" \
    | grep -oE '"crates/[a-z0-9-]+"' \
    | tr -d '"' \
    | sed 's|crates/||' \
    | sort -u)

if [ -z "$members" ]; then
    echo "could not read the workspace members from Cargo.toml" >&2
    exit 1
fi

count=$(echo "$members" | wc -l | tr -d ' ')
if [ "$count" -lt 10 ]; then
    # The parse above is the kind that silently matches nothing. Without this,
    # a reformatted manifest would leave an empty allowlist, every crate would
    # look third-party, and the failure would point at the wrong thing.
    echo "only $count workspace members parsed, which cannot be right" >&2
    exit 1
fi

# `--edges normal,build` because a dev-dependency on something external would
# not ship, and this claim is about what ships.
seen=$(cargo tree --workspace --edges normal,build --prefix none --no-dedupe 2>/dev/null \
    | awk '{print $1}' \
    | grep -v '^$' \
    | sort -u)

external=$(comm -23 <(echo "$seen") <(echo "$members"))

if [ -n "$external" ]; then
    echo "third-party crates found:"
    echo "$external"
    exit 1
fi

# And the tree must actually have contained the workspace, or an empty `seen`
# would pass this having checked nothing.
found=$(comm -12 <(echo "$seen") <(echo "$members") | wc -l | tr -d ' ')
if [ "$found" -lt "$count" ]; then
    echo "cargo tree listed $found of $count workspace crates; the check did not run properly" >&2
    exit 1
fi

echo "none ($found workspace crates, no external)"
