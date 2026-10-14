#!/usr/bin/env bash
#
# Check the polynomial identities behind P-256's schoolbook proofs with every
# SMT solver on PATH (z3, cvc5): each identity must be `unsat` (its negation
# has no solution), each negative control `sat`. Exit non-zero otherwise.
#
#   crates/ic-ec/proofs/smt/run.sh
#
# See docs/PROOFS.md, "The products".

set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
status=0
ran=0
for solver in z3 cvc5; do
    if ! command -v "$solver" > /dev/null; then
        echo "$solver: not on PATH, skipped"
        continue
    fi
    for case in product:unsat square:unsat product-wrong-weight:sat square-undoubled:sat; do
        file="${case%%:*}.smt2"
        want="${case##*:}"
        start=$(date +%s.%N)
        got=$("$solver" "$here/$file" 2>&1 | head -n 1)
        end=$(date +%s.%N)
        secs=$(awk -v s="$start" -v e="$end" 'BEGIN { printf "%.2f", e - s }')
        if [ "$got" = "$want" ]; then
            echo "ok   $solver $file: $got (${secs} s)"
        else
            echo "FAIL $solver $file: got '$got', want '$want'"
            status=1
        fi
        ran=$((ran + 1))
    done
done
if [ "$ran" -eq 0 ]; then
    echo "no solver found"
    exit 1
fi
exit $status
