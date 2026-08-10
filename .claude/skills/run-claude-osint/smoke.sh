#!/usr/bin/env bash
# smoke.sh — driver for the claude-osint skills repo.
#
# This repo is a *skills package*, not an app: its product is two SKILL.md
# files plus two runnable Python helpers. "Running" it means validating the
# SKILL.md frontmatter (what Claude loads) and exercising the helpers the
# way CI does. This driver does exactly that, in one shot.
#
# Usage (run from the repo root):
#   .claude/skills/run-claude-osint/smoke.sh           # full smoke (h1 net check is non-fatal)
#   .claude/skills/run-claude-osint/smoke.sh --no-net  # skip the HackerOne live-network check
#
# Exit codes: 0 = all required checks passed; 1 = a required check failed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT" || { echo "FAIL: cannot cd to repo root $REPO_ROOT" >&2; exit 1; }

NO_NET=false
[ "${1:-}" = "--no-net" ] && NO_NET=true

SECRET_SCAN="skills/offensive-osint/scripts/secret_scan.py"
H1="skills/offensive-osint/scripts/h1_reference.py"
fail=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗ %s\033[0m\n' "$1"; fail=1; }

echo "==> claude-osint smoke  (repo: $REPO_ROOT)"

# 1. Both Python helpers compile.
echo "[1] py_compile helpers"
python3 -m py_compile "$SECRET_SCAN" && pass "secret_scan.py compiles" || bad "secret_scan.py syntax error"
python3 -m py_compile "$H1"          && pass "h1_reference.py compiles"  || bad "h1_reference.py syntax error"

# 2. secret_scan.py detects known tokens from stdin (AWS + JWT are the CI canaries).
echo "[2] secret_scan.py stdin detection"
out=$(printf 'AKIAIOSFODNN7EXAMPLE\neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n' | python3 "$SECRET_SCAN")
echo "$out" | grep -q '"AWS_ACCESS_KEY"' && pass "detects AWS_ACCESS_KEY" || bad "missed AWS_ACCESS_KEY"
echo "$out" | grep -q '"JWT"'            && pass "detects JWT"            || bad "missed JWT"

# 3. secret_scan.py recursively scans a directory and emits JSONL.
echo "[3] secret_scan.py directory scan"
n=$(python3 "$SECRET_SCAN" skills/ | wc -l | tr -d ' ')
[ "$n" -gt 0 ] && pass "directory scan emitted $n JSONL findings" || bad "directory scan emitted nothing"

# 4. SKILL.md frontmatter is valid + complete (this is what Claude loads).
echo "[4] SKILL.md frontmatter validation"
for skill in skills/*/SKILL.md; do
  python3 - "$skill" <<'PY'
import sys, yaml
skill = sys.argv[1]
content = open(skill).read()
if not content.startswith("---"):
    print(f"FAIL no-frontmatter {skill}"); sys.exit(1)
data = yaml.safe_load(content[3:content.index("---", 3)])
for r in ("name", "description", "version", "triggers"):
    if r not in data:
        print(f"FAIL missing-{r} {skill}"); sys.exit(1)
if not isinstance(data["triggers"], list) or len(data["triggers"]) < 5:
    print(f"FAIL <5-triggers {skill}"); sys.exit(1)
print(f"OK {data['name']} v{data['version']} triggers={len(data['triggers'])}")
PY
  # shellcheck disable=SC2181
  if [ $? -eq 0 ]; then pass "$skill"; else bad "$skill frontmatter"; fi
done

# 5. sync-skill-content.sh --check runs cleanly (no-op without docs/full-skills/).
echo "[5] sync-skill-content.sh --check"
if ./scripts/sync-skill-content.sh --check >/dev/null 2>&1; then
  pass "sync --check exited 0"
else
  bad "sync --check failed"
fi

# 6. h1_reference.py live network (non-fatal — sandbox may block egress).
echo "[6] h1_reference.py live network (HackerOne GraphQL)"
if [ "$NO_NET" = true ]; then
  printf '  \033[33m~\033[0m skipped (--no-net)\n'
else
  if timeout 40 python3 "$H1" --top-voted --limit 1 2>/dev/null | grep -q 'hackerone.com/reports/'; then
    pass "fetched a live disclosed report"
  else
    printf '  \033[33m~\033[0m no network / HackerOne unreachable (non-fatal)\n'
  fi
fi

echo
if [ "$fail" -eq 0 ]; then echo "==> PASS"; else echo "==> FAIL"; fi
exit "$fail"
