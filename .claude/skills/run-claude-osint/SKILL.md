---
name: run-claude-osint
description: Build, validate, and run the claude-osint skills repo — check SKILL.md frontmatter, run the secret_scan.py and h1_reference.py helpers, run sync-skill-content.sh, run the smoke test. Use when asked to run, build, test, validate, or smoke-test claude-osint or its OSINT skills/scripts.
version: 1.0.0
triggers:
  - run claude-osint
  - build claude-osint
  - test claude-osint
  - validate claude-osint
  - smoke test claude-osint
  - run secret_scan
  - run h1_reference
  - validate SKILL.md frontmatter
  - sync skill content
---

# Run: claude-osint

`claude-osint` is **not an app** — it's a Claude *skills package*. Its product
is two `SKILL.md` files (`skills/offensive-osint/`, `skills/osint-methodology/`)
plus two runnable Python helpers under `skills/offensive-osint/scripts/`. There
is no GUI, server, or TUI. "Running it" means: the SKILL.md frontmatter parses
and is complete (that's what Claude loads), and the helper scripts work.

The driver is **`.claude/skills/run-claude-osint/smoke.sh`** — it does all of
that in one shot. **All paths below are relative to the repo root.**

## Prerequisites

Python 3 with PyYAML (already present on this container). If `import yaml` fails:

```bash
pip install pyyaml    # or: apt-get install -y python3-yaml
```

The helpers are stdlib-only otherwise. `h1_reference.py` needs outbound HTTPS to
`hackerone.com`. No build step, no `npm install` — nothing to compile.

## Run (agent path) — the driver

From the repo root:

```bash
.claude/skills/run-claude-osint/smoke.sh           # full smoke (exits 0 on pass)
.claude/skills/run-claude-osint/smoke.sh --no-net  # skip the HackerOne live check
```

It runs six checks and prints a `==> PASS` / `==> FAIL` line (exit 0 / 1):

1. `py_compile` both helpers.
2. `secret_scan.py` detects AWS key + JWT from stdin (the CI canaries).
3. `secret_scan.py` recursively scans `skills/` and emits JSONL (~11 findings — example tokens in the SKILL.md docs).
4. Every `skills/*/SKILL.md` has valid YAML frontmatter with `name`/`description`/`version`/`triggers` and ≥5 triggers.
5. `sync-skill-content.sh --check` exits 0.
6. `h1_reference.py` fetches one live disclosed report (non-fatal if offline).

## Run individual pieces

Verified this session:

```bash
# Secret scanner — stdin
printf 'AKIAIOSFODNN7EXAMPLE\n' | python3 skills/offensive-osint/scripts/secret_scan.py
# -> {"pattern": "AWS_ACCESS_KEY", "severity": "critical", ...}

# Secret scanner — scan a directory tree (JSONL, one finding per line)
python3 skills/offensive-osint/scripts/secret_scan.py skills/

# HackerOne reference helper (needs network)
python3 skills/offensive-osint/scripts/h1_reference.py --top-voted --limit 3
python3 skills/offensive-osint/scripts/h1_reference.py --top-bounty --limit 3
python3 skills/offensive-osint/scripts/h1_reference.py --top-voted --query "XSS" --pages 3

# Install the skills for Claude to load
cp -r skills/* ~/.claude/skills/
```

## Test

CI (`.github/workflows/lint.yml`) runs four jobs: markdown lint
(`markdownlint-cli2`), the frontmatter check, the `secret_scan.py` smoke, and
`shellcheck ./scripts`. `smoke.sh` covers the latter two plus the helpers
directly. `markdownlint-cli2` and `shellcheck` are **not installed** on this
container; install with `npm i -g markdownlint-cli2` / `apt-get install -y
shellcheck` if you need to reproduce those jobs locally.

## Gotchas

- **`sync-skill-content.sh` is a no-op in a fresh clone.** It copies from
  `docs/full-skills/`, which **is not in the repo** — the script prints
  "⚠ Source missing … Skipping" and exits 0. The `skills/*/SKILL.md` files are
  *already* the full inline content (offensive-osint ≈ 4,200 lines), so you do
  **not** need to run sync after cloning. Don't be alarmed by the warnings.
- **`secret_scan.py` skips its own findings as noise filters.** It excludes
  `.git`, `node_modules`, `__pycache__`, `.venv`, `dist`, `build`, `.cache`
  and any file >10 MB. Scanning `skills/` returns the example/doc tokens (~11),
  not real secrets.
- **`h1_reference.py` hits an undocumented public GraphQL endpoint.** It works
  unauthenticated but is sensitive to HackerOne-side changes and rate limits;
  treat a failure there as environmental, not a repo bug (hence non-fatal in
  the driver). It caps at 50 results/page — use `--pages N` for breadth.
- **No screenshot / no window** — this repo has no visual surface. If a request
  asks to "see it run," that means the `smoke.sh` PASS output, not a GUI.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'yaml'` in check [4] | `pip install pyyaml` (only the frontmatter check needs it). |
| Check [6] shows `~ no network / HackerOne unreachable` | Expected when egress is blocked; run with `--no-net` to silence. Driver still passes. |
| `sync --check` shows "Source missing" | Expected — see Gotchas. Not a failure; exit code is 0. |
