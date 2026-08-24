#!/usr/bin/env python3
"""
check_doc_counts.py — verify skill counts in docs match what's on disk.

Counts drift: the docs advertise an "8-skill library" while skills/ holds 9
directories (osint-autopilot is an orchestration wrapper, excluded from the
marketed count). Add a skill and several hardcoded numbers across README /
CHANGELOG / docs go stale one at a time. This computes the real counts from
skills/ and checks every doc that asserts one.

Count model (derived from disk, not hardcoded):
  total   = every skills/<name>/ directory
  library = total minus the wrapper (osint-autopilot) — the marketed "N-skill library"
  depth   = library minus the two core skills (osint-methodology, offensive-osint)
  core    = 2

Docs write these as digits ("8 skills") or words ("eight skills") — both handled.

Exit 0 = all match, 1 = at least one mismatch. Stdlib only.
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO, "skills")

WRAPPER = {"osint-autopilot"}
CORE = {"osint-methodology", "offensive-osint"}
WORDS = {"two": 2, "six": 6, "eight": 8, "nine": 9, "thirteen": 13}


def counts():
    dirs = {d for d in os.listdir(SKILLS_DIR)
            if os.path.isfile(os.path.join(SKILLS_DIR, d, "SKILL.md"))}
    total = len(dirs)
    library = len(dirs - WRAPPER)
    depth = len(dirs - WRAPPER - CORE)
    return {"total": total, "library": library, "depth": depth, "core": 2}


def read(path):
    with open(os.path.join(REPO, path), encoding="utf-8") as fh:
        return fh.read()


def as_int(token):
    token = token.strip().lower()
    if token in WORDS:
        return WORDS[token]
    if token.isdigit():
        return int(token)
    return None


# (file, regex with ONE capture group holding a digit-or-word, expected key, label)
CHECKS = [
    ("docs/architecture.md", r"library has (\w+) skills", "library", "architecture intro"),
    ("docs/architecture.md", r"Org-grade depth<br/>(\d+) skills", "depth", "architecture depth node"),
    ("CHANGELOG.md", r"2-skill recon pair to an \*\*(\w+)-skill\*\*", "library", "CHANGELOG lift line"),
    ("CHANGELOG.md", r"for the (\w+)-skill library", "library", "CHANGELOG docs-updated line"),
    ("README.md", r"The (\w+) skills that lift", "depth", "README depth section"),
    ("README.md", r"(\w+) skills, thirteen capability domains", "library", "README capability intro"),
    ("README.md", r"Install all (\w+) skills", "library", "README install comment"),
    ("README.md", r"All (\w+) skills include a soft scope-check", "library", "README posture line"),
    ("docs/coverage.md", r"\(56 prompts, (\d+) skills\)", "library", "coverage table row"),
    ("docs/installation.md", r"Copy all (\w+) skills", "library", "installation copy comment"),
    ("docs/installation.md", r"All (\w+) skills together", "library", "installation context line"),
]


def main():
    truth = counts()
    errors = []
    for file, pattern, key, label in CHECKS:
        try:
            text = read(file)
        except FileNotFoundError:
            errors.append(f"{file}: missing (checked for '{label}')")
            continue
        m = re.search(pattern, text)
        if not m:
            errors.append(f"{file}: pattern not found for '{label}' ({pattern}) — "
                          f"doc reworded? update CHECKS.")
            continue
        got = as_int(m.group(1))
        if got is None:
            errors.append(f"{file}: '{label}' captured non-number '{m.group(1)}'")
        elif got != truth[key]:
            errors.append(f"{file}: '{label}' says {m.group(1)} ({got}) but {key} is {truth[key]}")

    print(f"Ground truth: {truth['total']} skill dirs "
          f"({truth['library']}-skill library = {truth['depth']} depth + {truth['core']} core).")
    for e in errors:
        print(f"::error:: {e}" if os.environ.get("GITHUB_ACTIONS") else f"ERROR {e}")
    print(f"Checked {len(CHECKS)} doc assertion(s): {len(errors)} error(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
