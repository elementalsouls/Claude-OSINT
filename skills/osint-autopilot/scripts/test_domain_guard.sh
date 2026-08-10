#!/usr/bin/env bash
# Self-check for the domain-argument guard on all three entry points.
# Usage: bash test_domain_guard.sh      (no network, no writes outside a temp HOME)
# Asserts on the guard's own error string, not merely a non-zero exit, so a script
# that dies for some unrelated reason cannot make this pass vacuously.
set -uo pipefail
S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX="$(mktemp -d)"; trap 'rm -rf "$SANDBOX"' EXIT
fail=0

BAD=('..' '.' '../../tmp/pwned' '-rf' '--help' 'a b' 'example.com;id' 'nodot' 'example..com' '-example.com' 'example.com.')
for s in "$S/recon_pipeline.sh" "$S/findings_gen.py" "$S/build_xlsx.py"; do
  runner=bash; [[ "$s" == *.py ]] && runner=python3
  for d in "${BAD[@]}"; do
    out=$(HOME="$SANDBOX" "$runner" "$s" "$d" 2>&1)
    case "$out" in
      *"invalid domain"*) ;;
      *) echo "FAIL: $(basename "$s") did not reject '$d' (got: ${out:-<no output>})"; fail=1;;
    esac
  done
done
# A rejected input must not have created anything.
found=$(find "$SANDBOX" -mindepth 1 2>/dev/null)
[ -z "$found" ] || { echo "FAIL: rejected input still wrote: $found"; fail=1; }

# A real domain must still pass the guard (python entry points only — the shell one starts a live run).
for s in "$S/findings_gen.py" "$S/build_xlsx.py"; do
  out=$(HOME="$SANDBOX" python3 "$s" sub.example.com 2>&1)
  case "$out" in *"invalid domain"*) echo "FAIL: $(basename "$s") rejected sub.example.com"; fail=1;; esac
done

[ $fail -eq 0 ] && echo "PASS: domain guard holds on all three entry points"
exit $fail
