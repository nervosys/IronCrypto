#!/usr/bin/env bash
#
# Every third-party crate that actually ships must be at or above the version
# that fixed the advisories known against it.
#
# This exists because a clean advisory result was, until now, something a human
# produced by hand and nothing preserved. The dependency surface is seven
# crates, so the cost of pinning it is small and the cost of not noticing a
# regression is a downgrade into a known vulnerability.
#
# # Why this reads the build graph and not Cargo.lock
#
# `cargo audit` and most SCA tools read `Cargo.lock`, which lists packages the
# resolver considered, not packages the compiler builds. This workspace's lock
# file contains sixteen such packages, `ring` among them -- an unactivated
# optional dependency of rustls. `cargo tree -i ring` returns nothing: it is
# never compiled and its advisories do not apply here.
#
# A tool reading the lock file cannot tell the difference and will report them.
# That is not a reason to stop scanning; it is a reason for this check to use
# the same source of truth as `no-third-party.sh`, so the floors below apply to
# what ships. Run `cargo audit` as well when it is available -- the tail of this
# script says which of its findings to expect and why.
#
# # Keeping the floors current
#
# A floor is a claim about the world that can go stale in one direction: a new
# advisory raises it. Nothing here can learn that by itself, so the table
# carries the date it was last checked and CI prints it. If that date is old,
# the floors are evidence about a world that has moved on.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Last reviewed against https://rustsec.org/advisories/ on this date.
reviewed="2026-09-22"

# crate<TAB>minimum version<TAB>why that floor
#
# "none known" means the crate had no advisory at the review date; the floor is
# then the version in use, so a downgrade still has to be deliberate.
floors="once_cell	1.21.4	RUSTSEC-2019-0017 fixed in >=1.0.1; floor held at the version in use
rustls	0.23.45	RUSTSEC-2026-0285, TLS 1.3 handshake messages accepted across encryption level boundaries, fixed in >=0.23.45
rustls-pki-types	1.15.1	none known at the review date
rustls-webpki	0.103.15	RUSTSEC-2026-0104 / CVE-2026-93599, reachable panic parsing a CRL, fixed in >=0.103.13
subtle	2.6.1	none known at the review date
untrusted	0.9.0	none known at the review date
zeroize	1.9.0	none known at the review date"

# What is actually compiled, across every target. Same mechanism as
# no-third-party.sh, which is the point: one definition of "ships".
members=$(sed -n '/^members = \[/,/^\]/p' Cargo.toml \
    | grep -oE '"crates/[a-z0-9-]+"' | tr -d '"' | sed 's|crates/||' | sort -u)

compiled=$(cargo tree --workspace --edges normal,build --target all --prefix none --no-dedupe 2>/dev/null \
    | awk 'NF {print $1 "\t" $2}' | sort -u)

third_party=$(echo "$compiled" | grep -vFf <(echo "$members") || true)

if [ -z "$third_party" ]; then
    echo "no third-party crates resolved, which cannot be right" >&2
    exit 1
fi

fail=0
checked=0

while IFS=$'\t' read -r crate version; do
    [ -n "$crate" ] || continue
    version="${version#v}"

    floor_line=$(echo "$floors" | grep -P "^${crate}\t" || true)
    if [ -z "$floor_line" ]; then
        echo "FAIL  $crate $version is compiled but has no advisory floor."
        echo "      Add it to scripts/advisories.sh with the advisories known"
        echo "      against it, or remove the dependency."
        fail=1
        continue
    fi

    floor=$(echo "$floor_line" | cut -f2)
    why=$(echo "$floor_line" | cut -f3)

    # sort -V puts the lower version first; if the floor sorts first and the two
    # differ, the version in use is above the floor.
    lowest=$(printf '%s\n%s\n' "$version" "$floor" | sort -V | head -1)
    if [ "$version" != "$floor" ] && [ "$lowest" = "$version" ]; then
        echo "FAIL  $crate $version is below the floor $floor"
        echo "      $why"
        fail=1
    else
        echo "ok    $crate $version (floor $floor)"
    fi
    checked=$((checked + 1))
done <<< "$third_party"

# A floor table nobody compared against would print nothing and pass. The
# dependency surface is seven crates; anything less means the tree did not load.
expected=$(echo "$floors" | wc -l | tr -d ' ')
if [ "$checked" -lt "$expected" ]; then
    echo "only $checked of $expected third-party crates were examined; the check did not run properly" >&2
    exit 1
fi

if [ "$fail" -ne 0 ]; then
    echo
    echo "Advisory floors are set in scripts/advisories.sh, last reviewed $reviewed."
    exit 1
fi

echo "$checked third-party crates at or above their advisory floors (reviewed $reviewed)"

# `cargo audit` is not required and is not installed by this script: it would be
# a build-time dependency on a tool that fetches a database over the network,
# which is not something a check that gates commits should do silently. When it
# is present its second opinion is worth having.
if command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1; then
    echo
    echo "cargo audit is available; running it for a second opinion."
    echo "Expect findings against packages this workspace never compiles --"
    echo "cargo audit reads Cargo.lock, which lists the resolver's candidates."
    lock_only=$(comm -23 \
        <(grep '^name = ' Cargo.lock | sed 's/name = "//;s/"//' | sort -u) \
        <(echo "$compiled" | cut -f1 | sort -u))
    if [ -n "$lock_only" ]; then
        echo "In Cargo.lock but never compiled:"
        echo "$lock_only" | sed 's/^/  /'
    fi
    cargo audit || true
fi
