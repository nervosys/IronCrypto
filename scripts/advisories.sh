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
# file contains eighteen such packages, `ring` among them -- an unactivated
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

# Last reviewed against the RustSec advisory database on this date (local copy
# updated 2026-10-03; no advisory for these crates since).
reviewed="2026-10-14"

# crate<TAB>minimum version<TAB>why that floor
#
# "none known" means the crate had no advisory at the review date; the floor is
# then the version in use, so a downgrade still has to be deliberate.
floors="once_cell	1.21.4	RUSTSEC-2019-0017 fixed in >=1.0.1; floor held at the version in use
rustls	0.23.46	RUSTSEC-2026-0346 (Debug impls expose client session secrets), -0347 (buffered data sent to the outer server after ECH rejection), -0348 (Brotli certificate decompression allocates up to 1 GiB before authentication) and -0349 (unauthenticated ServerHello downgrades later connections to classical key exchange), fixed in >=0.23.46; RUSTSEC-2026-0285, -2024-0336 and -0399 fixed earlier
rustls-pki-types	1.15.1	none known at the review date
rustls-webpki	0.103.15	RUSTSEC-2026-0104 / CVE-2026-93599, reachable panic parsing a CRL, fixed in >=0.103.13; RUSTSEC-2023-0053, 2026-0049, -0098 and -0099 fixed earlier; floor held at the version in use
subtle	2.6.1	none known at the review date
untrusted	0.9.0	RUSTSEC-2018-0001 fixed in >=0.6.2; floor held at the version in use
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

# `cargo audit` is not required and is not installed by this script. When it is
# present it gates, and it tolerates being offline: it fetches the RustSec
# database over the network, so a database that cannot be loaded is a warning,
# and the offline floors still gate. A vulnerability in a crate this workspace
# compiles fails the script. One in a crate that only Cargo.lock lists is
# printed as a warning, because the lock file names packages the compiler never
# builds (see the header). cargo audit's own configuration (audit.toml or
# .cargo/audit.toml, read from this directory) is the only ignore mechanism;
# this script adds none.
#
# The verdict comes from cargo audit's JSON, not its exit status: it exits
# non-zero both when it finds vulnerabilities and when it cannot load the
# database. The JSON is printed only once the database has loaded, so a
# "database" block with a non-zero advisory-count, plus "vulnerabilities", is
# the proof that the check ran.
#
# This runs before the floor check so that a combined failure shows the audit
# findings first. The floor check exits on its own; audit_fail is applied after it.
audit_fail=0
if command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1; then
    echo
    echo "cargo audit is available; checking the RustSec advisory database."
    echo "It reads Cargo.lock, which also lists packages this workspace never"
    echo "compiles, so a finding can name one of those:"
    lock_only=$(comm -23 \
        <(grep '^name = ' Cargo.lock | sed 's/name = "//;s/"//' | sort -u) \
        <(echo "$compiled" | cut -f1 | sort -u))
    if [ -n "$lock_only" ]; then
        echo "In Cargo.lock but never compiled:"
        echo "$lock_only" | sed 's/^/  /'
    fi

    compiled_names=$(echo "$third_party" | cut -f1)

    py=""
    for candidate in python3 python; do
        if "$candidate" -c 'import json' >/dev/null 2>&1; then
            py=$candidate
            break
        fi
    done

    audit_err=$(mktemp)
    audit_json=$(cargo audit --json 2>"$audit_err" || true)

    # Reads cargo audit's JSON on stdin and prints one tab-separated record per
    # line: DB (database loaded), VULN (a vulnerability), WARN (an unmaintained,
    # unsound or yanked notice, which does not gate), or UNAVAILABLE.
    audit_py='
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    d = {}
db = d.get("database") or {}
v = d.get("vulnerabilities")
if not isinstance(v, dict) or not db.get("advisory-count"):
    print("UNAVAILABLE")
    sys.exit(0)
print("DB\t%s\t%s" % (db["advisory-count"], db.get("last-updated", "?")))
for item in v.get("list") or []:
    a = item.get("advisory", {})
    p = item.get("package", {})
    patched = ", ".join((item.get("versions") or {}).get("patched") or []) or "none listed"
    print("VULN\t%s\t%s\t%s\t%s" % (a.get("id", "?"), p.get("name", "?"), p.get("version", "?"), patched))
for kind, items in (d.get("warnings") or {}).items():
    for w in items:
        a = w.get("advisory", {})
        p = w.get("package", {})
        print("WARN\t%s\t%s\t%s\t%s" % (kind, a.get("id", "?"), p.get("name", "?"), p.get("version", "?")))
'

    audit_read=""
    if [ -z "$py" ]; then
        echo "FAIL  cargo audit is installed, but python is needed to read its output and none was found."
        audit_fail=1
    elif ! audit_read=$(printf '%s' "$audit_json" | "$py" -I -c "$audit_py"); then
        echo "FAIL  could not parse the JSON that cargo audit printed."
        audit_fail=1
    elif ! printf '%s\n' "$audit_read" | grep -q '^DB'; then
        echo "WARNING: the RustSec advisory database could not be loaded (offline, or the fetch failed),"
        echo "         so cargo audit did not check it. The offline floors above still gate."
        if [ -s "$audit_err" ]; then
            tail -n 3 "$audit_err" | sed 's/^/         cargo audit: /'
        fi
    else
        db_line=$(printf '%s\n' "$audit_read" | grep '^DB' | head -1)
        echo "RustSec database: $(echo "$db_line" | cut -f2) advisories, last updated $(echo "$db_line" | cut -f3)"

        warn_lines=$(printf '%s\n' "$audit_read" | grep '^WARN' || true)
        if [ -n "$warn_lines" ]; then
            while IFS=$'\t' read -r _ kind id crate version; do
                echo "warning ($kind) $id: $crate $version; not a vulnerability, does not fail the check"
            done <<< "$warn_lines"
        fi

        vuln_lines=$(printf '%s\n' "$audit_read" | grep '^VULN' || true)
        if [ -n "$vuln_lines" ]; then
            echo
            while IFS=$'\t' read -r _ id crate version patched; do
                if grep -qxF "$crate" <<< "$compiled_names"; then
                    audit_fail=1
                    echo "FAIL  $id: $crate $version is vulnerable; fixed in $patched"
                else
                    echo "warning (lock-only, not compiled) $id: $crate $version; fixed in $patched"
                fi
            done <<< "$vuln_lines"
            if [ "$audit_fail" -ne 0 ]; then
                echo
                echo "      To clear each FAIL: raise that crate's floor in the table in"
                echo "      scripts/advisories.sh to the fixed version, raise its requirement in"
                echo "      the Cargo.toml that names it (crates/ic-rustls/Cargo.toml for rustls"
                echo "      and its dependencies), then run cargo update -p <crate>."
                echo "      A lock-only warning is not in the build; decide what it means with"
                echo "      cargo tree -i <crate>. Do not add an ignore to get past it here."
            fi
        else
            echo "cargo audit: no vulnerabilities found"
        fi
    fi
    rm -f "$audit_err"
fi


if [ "$fail" -ne 0 ]; then
    echo
    echo "Advisory floors are set in scripts/advisories.sh, last reviewed $reviewed."
    exit 1
fi

echo "$checked third-party crates at or above their advisory floors (reviewed $reviewed)"
if [ "$audit_fail" -ne 0 ]; then
    exit 1
fi


# A floor can only go stale in one direction, and nothing here learns that by
# itself, so say so once the review is a month old. A warning rather than a
# failure: a gate that breaks on the calendar teaches people to bump the date
# without reviewing. `date -d` is GNU; elsewhere the age is not computed.
if reviewed_epoch=$(date -d "$reviewed" +%s 2>/dev/null); then
    age_days=$(( ( $(date +%s) - reviewed_epoch ) / 86400 ))
    if [ "$age_days" -gt 30 ]; then
        echo "WARNING: the advisory floors were last reviewed $age_days days ago; check https://rustsec.org/advisories/ for these crates and update \$reviewed."
    fi
fi
