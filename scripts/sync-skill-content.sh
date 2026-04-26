#!/usr/bin/env bash
# sync-skill-content.sh — populate skills/*/SKILL.md with full v2.1 inline content
#                        from the bundled docs/full-skills/ canonical sources.
#
# Run this once after `git clone` to convert the structured-outline SKILL.md files
# into the full inline-content versions that Claude can load directly.
#
# Usage:
#   ./scripts/sync-skill-content.sh             # interactive, prompts before overwrite
#   ./scripts/sync-skill-content.sh --force     # non-interactive overwrite
#   ./scripts/sync-skill-content.sh --check     # verify checksums; no changes

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Mapping: full-skills source → SKILL.md destination
SKILLS=(
  "osint-methodology"
  "offensive-osint"
)

FORCE=false
CHECK_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --force|-f) FORCE=true ;;
    --check|-c) CHECK_ONLY=true ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Run with --help for usage." >&2
      exit 2
      ;;
  esac
done

echo "==> Syncing SKILL.md content from docs/full-skills/"

for skill in "${SKILLS[@]}"; do
  SRC="$REPO_ROOT/docs/full-skills/$skill.SKILL.full.md"
  DST="$REPO_ROOT/skills/$skill/SKILL.md"

  if [ ! -f "$SRC" ]; then
    echo "  ⚠  Source missing: $SRC"
    echo "      (Skipping. The structured-outline SKILL.md will remain in place.)"
    continue
  fi

  if [ "$CHECK_ONLY" = true ]; then
    SRC_HASH=$(sha256sum "$SRC" | awk '{print $1}')
    if [ -f "$DST" ]; then
      DST_HASH=$(sha256sum "$DST" | awk '{print $1}')
      if [ "$SRC_HASH" = "$DST_HASH" ]; then
        echo "  ✓  $skill: in sync"
      else
        echo "  ✗  $skill: DRIFT (run without --check to update)"
      fi
    else
      echo "  ✗  $skill: destination missing (run without --check to populate)"
    fi
    continue
  fi

  if [ -f "$DST" ] && [ "$FORCE" = false ]; then
    echo
    echo "  $skill: existing SKILL.md will be overwritten with full v2.1 content."
    read -p "  Continue? [y/N] " -n 1 -r REPLY
    echo
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
      echo "  Skipping $skill."
      continue
    fi
  fi

  cp "$SRC" "$DST"
  LINES=$(wc -l < "$DST")
  BYTES=$(wc -c < "$DST")
  echo "  ✓  $skill: $LINES lines, $BYTES bytes installed at $DST"
done

if [ "$CHECK_ONLY" = false ]; then
  echo
  echo "==> Done. Skills are ready to load."
  echo "    Verify: head -5 skills/*/SKILL.md"
  echo "    Install: cp -r skills/* ~/.claude/skills/"
fi
