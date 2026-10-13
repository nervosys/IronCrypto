#!/usr/bin/env bash
#
# Run every ctgrind case under Valgrind memcheck and summarise what it found.
#
#   scripts/ctgrind.sh [case ...]
#
# Linux x86-64 only, with valgrind on PATH. Each case is its own process, so a
# report belongs to one operation; see ctgrind/src/main.rs for the technique
# and docs/CTGRIND.md for the classification of what is expected.

set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${CARGO_TARGET_DIR:=$root/ctgrind/target}"
export CARGO_TARGET_DIR
# Static, through musl: memcheck needs redirections in a dynamic loader it
# can read, and a distribution's stripped ld.so stops it at startup. A static
# binary has no loader. `rustup target add x86_64-unknown-linux-musl`.
target=x86_64-unknown-linux-musl
# Valgrind executes ADX instructions but does not report them in CPUID, and
# Graviola refuses to start without that bit unless built with this set: its
# own workaround, which changes the check and nothing else.
VALGRIND_BUG_494162=1 cargo build --release --quiet --target "$target" \
    --manifest-path "$root/ctgrind/Cargo.toml"
bin="$CARGO_TARGET_DIR/$target/release/ic-ctgrind"

cases=("$@")
if [ ${#cases[@]} -eq 0 ]; then
    mapfile -t cases < <("$bin" --list)
fi

log_dir="$(mktemp -d)"
printf '%-36s %8s %8s  %s\n' case branches address "first frame in a library"
for c in "${cases[@]}"; do
    log="$log_dir/$c.log"
    valgrind --tool=memcheck --error-exitcode=0 --num-callers=12 \
        --log-file="$log" "$bin" "$c" >/dev/null
    branches=$(grep -c "Conditional jump or move depends on uninitialised" "$log" || true)
    address=$(grep -c "Use of uninitialised value of size" "$log" || true)
    frame=$(grep -m1 -oE "(ic_[a-z0-9_]+|graviola)::[A-Za-z0-9_:<>]+" "$log" || true)
    printf '%-36s %8s %8s  %s\n' "$c" "$branches" "$address" "${frame:--}"
    # The controls must be caught, or no other row here means anything.
    if [[ "$c" == control-* ]] && [ "$((branches + address))" -eq 0 ]; then
        echo "positive control $c was not reported: the client requests do not reach valgrind" >&2
        exit 1
    fi
done
echo "logs: $log_dir"
