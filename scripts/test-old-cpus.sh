#!/usr/bin/env bash
#
# Run every test binary on emulated older x86-64 CPUs, to show that no
# AVX2, BMI2, ADX, AVX-512, IFMA, VAES, VPCLMULQDQ, SHA-NI or AES-NI code path
# is reached without its runtime CPU check.
#
# The test binaries are built for baseline x86-64 (the musl target), so the
# compiler emits none of those instructions on its own. An instruction that
# runs anyway came from a hand-written path reached without a runtime check,
# and an emulated CPU that lacks the feature raises SIGILL on it. A run with no
# SIGILL shows that no such path was reached on that model. It does not show
# that every path was reached: the output prints each binary's test counts, so
# a suite that silently ran nothing is visible.
#
# Each model is qemu-x86_64 -cpu <model>. The default list names CPUs whose
# feature sets the dispatchers branch on, plus `max` with one feature removed
# at a time, so each gate is exercised on its own. AVX-512 is not in the list:
# QEMU's TCG drops the AVX-512 features from every CPU model, so this cannot
# run that path (docs/CI.md).
#
# Two self-checks fail on purpose on models without the instructions they test,
# and that is not a gating failure. ic-cipher's
# `gcm::fused_tests::every_path_matches_the_reference_at_every_length_to_600`
# asserts that the accelerated AES-GCM path ran, and it fails on models without
# AES-NI or PCLMULQDQ. ic-ec's `fe64::tests::this_machine_runs_the_four_limb_field`
# insists on BMI2 and ADX unless IC_EC_NO_ADX_OK is set, so the script sets it.
#
# Needs:
#   - qemu-x86_64 on PATH, or QEMU_X86_64 naming it. Debian's `qemu-user`
#     package provides one; docs/CI.md has the no-root route.
#   - rustup target add x86_64-unknown-linux-musl
#
# Usage:
#   scripts/test-old-cpus.sh                        # every default model
#   scripts/test-old-cpus.sh Nehalem-v2 'max,-adx'  # named models only
#
# Exits non-zero on any SIGILL, timeout, or run that neither passed nor reported
# test results. Test FAILs are listed by name and do not fail the script.
#
# Not part of scripts/check.sh: every test binary is emulated, so a full run is slow.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

target=x86_64-unknown-linux-musl
qemu="${QEMU_X86_64:-}"
if [ -z "$qemu" ]; then
    for q in qemu-x86_64 qemu-x86_64-static "$HOME/.local/bin/qemu-x86_64"; do
        if command -v "$q" >/dev/null 2>&1; then
            qemu="$q"
            break
        fi
    done
fi
if [ -z "$qemu" ] || ! command -v "$qemu" >/dev/null 2>&1; then
    echo "qemu-x86_64 not found; set QEMU_X86_64 or put it on PATH (docs/CI.md)" >&2
    exit 1
fi
if ! rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    echo "$target not installed; rustup target add $target" >&2
    exit 1
fi

if [ "$#" -gt 0 ]; then
    models=("$@")
else
    models=(
        Nehalem-v2                  # SSE4.2; no AES-NI, no PCLMULQDQ, no AVX
        Westmere-v2                 # adds AES-NI and PCLMULQDQ; no AVX
        SandyBridge-v2              # adds AVX; no AVX2
        Haswell-noTSX               # adds AVX2, BMI1, BMI2; no ADX
        Broadwell-noTSX             # adds ADX
        Skylake-Client-noTSX-IBRS
        'max,-aes'                  # no AES-NI alone
        'max,-pclmulqdq'            # no PCLMULQDQ alone
        'max,-sha-ni'               # no SHA-NI alone
        'max,-vaes'                 # no VAES alone
        'max,-avx2'                 # no AVX2 alone
        'max,-bmi2'                 # no BMI2 alone
        'max,-adx'                  # no ADX alone
    )
fi

: "${CARGO_TARGET_DIR:=target/old-cpus}"
export CARGO_TARGET_DIR

# Test executables with their package directories. cargo sets CARGO_MANIFEST_DIR
# when it runs a test; ic-vectors reads it to find testvectors/, so the binaries
# get it too, and each runs from its package directory as cargo runs it.
list="$(mktemp)"
log="$(mktemp)"
trap 'rm -f "$list" "$log"' EXIT

cargo test --release --target "$target" --workspace --no-run --message-format=json \
    | grep '"reason":"compiler-artifact"' \
    | grep -E '"profile":\{.*"test":true\}' \
    | grep '"executable":"' \
    | sed -n 's/.*"manifest_path":"\([^"]*\)\/Cargo.toml".*"executable":"\([^"]*\)".*/\2\t\1/p' \
    > "$list"

echo "=== $(wc -l < "$list") test executables, ${#models[@]} models ==="

failures=0
for model in "${models[@]}"; do
    echo "--- $model"
    while IFS=$'\t' read -r exe dir; do
        name=$(basename "$exe")
        set +e
        (cd "$dir" && CARGO_MANIFEST_DIR="$dir" IC_EC_NO_ADX_OK=1 \
            timeout 1800 "$qemu" -cpu "$model" "$exe" --test-threads=4 </dev/null) >"$log" 2>&1
        rc=$?
        set -e
        if [ "$rc" -eq 124 ]; then
            status=TIMEOUT
        elif [ "$rc" -eq 132 ] || grep -q "uncaught target signal 4" "$log"; then
            status=SIGILL
        elif [ "$rc" -eq 0 ]; then
            status=PASS
        elif grep -q "test result: FAILED" "$log"; then
            status=FAIL
        else
            status="OTHER($rc)"
        fi
        counts=$(grep -E "^test result:" "$log" \
            | sed -n 's/^test result: [A-Za-z]*\. \([0-9]*\) passed; \([0-9]*\) failed; \([0-9]*\) ignored.*/\1 \2 \3/p' \
            | awk '{p+=$1; f+=$2; i+=$3} END {printf "passed=%d failed=%d ignored=%d", p, f, i}' || true)
        printf '  %-8s %-40s %s\n' "$status" "$name" "$counts"
        case "$status" in
            PASS) ;;
            FAIL)
                grep -E "^---- .* stdout ----$" "$log" | sed 's/^---- /      failed: /; s/ stdout ----$//' || true
                ;;
            *)
                failures=$((failures + 1))
                tail -n 5 "$log" | sed 's/^/      /'
                ;;
        esac
    done < "$list"
done

echo
if [ "$failures" -ne 0 ]; then
    echo "FAILED: $failures run(s) hit SIGILL, a timeout, or reported no results"
    exit 1
fi
echo "no SIGILL, timeout or unreported run across ${#models[@]} models"
