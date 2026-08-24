#!/usr/bin/env python3
"""
Capability eval for the osint-autopilot rules engine (findings_gen.py).

Unlike the 56-prompt manual self-eval, this is deterministic and network-free:
it runs the real rules engine over recorded evidence fixtures and asserts the
findings it should (and should NOT) produce. It answers "does the engine still
detect what it claims to?" on every change — the thing structural linting can't.

The `*.example` fixture domains never resolve (RFC 2606), so the engine's one
live WordPress curl fails fast and the run stays deterministic.

Run: python3 tests/test_findings_gen.py     (exit 0 = pass)
Stdlib only.
"""
import csv
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(REPO, "skills", "osint-autopilot", "scripts", "findings_gen.py")
FIX = os.path.join(REPO, "tests", "fixtures", "engagements")

# (severity, title-substring) the vulnerable fixture must yield.
VULN_EXPECT = [
    ("MEDIUM", "Non-production"),
    ("MEDIUM", "bypass CDN/WAF"),
    ("MEDIUM", "Internal RFC1918"),
    ("LOW", "DMARC policy not enforced"),
    ("HIGH", "SPF +all"),
    ("LOW", "/version"),
    ("MEDIUM", "Secret-pattern"),
    ("HIGH", "S3 bucket takeover"),
    ("INFO", "Identity provider"),
    ("CRITICAL", "infostealer/breach"),
    ("HIGH", "Sensitive service ports"),
]


def run_engine(domain, home):
    """Copy the fixture into a temp HOME engagement dir, run the engine, return
    (severity, title) pairs from findings.csv."""
    dst = os.path.join(home, "Research", "engagements", domain)
    # Fixtures store the evidence tree as ev/ (the repo .gitignore excludes any
    # evidence/ dir); the engine reads <engagement>/evidence, so map it back.
    shutil.copytree(os.path.join(FIX, domain, "ev"), os.path.join(dst, "evidence"))
    env = dict(os.environ, HOME=home)
    r = subprocess.run([sys.executable, ENGINE, domain], env=env,
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"{domain}: engine exited {r.returncode}: {r.stderr.strip()}")
    csv_path = os.path.join(dst, "findings", "findings.csv")
    with open(csv_path, newline="") as fh:
        rows = list(csv.reader(fh))[1:]  # drop header
    return [(row[2], row[1]) for row in rows]  # (Severity, Title)


def main():
    fails = []

    # 1. vulnerable fixture — every expected finding must be present.
    with tempfile.TemporaryDirectory() as home:
        got = run_engine("vuln.example", home)
        for sev, sub in VULN_EXPECT:
            if not any(s == sev and sub.lower() in t.lower() for s, t in got):
                fails.append(f"vuln.example: missing expected [{sev}] '...{sub}...'")
        print(f"vuln.example: {len(got)} finding(s), {len(VULN_EXPECT)} checks")

    # 2. clean fixture — no MEDIUM/HIGH/CRITICAL false positives (INFO only OK).
    with tempfile.TemporaryDirectory() as home:
        got = run_engine("clean.example", home)
        noisy = [(s, t) for s, t in got if s in ("CRITICAL", "HIGH", "MEDIUM")]
        if noisy:
            fails.append(f"clean.example: unexpected non-INFO finding(s): {noisy}")
        print(f"clean.example: {len(got)} finding(s) (INFO-only expected)")

    for f in fails:
        print(f"ERROR {f}")
    if fails:
        print(f"\nFAIL: {len(fails)} issue(s).")
        return 1
    print("\nPASS: findings_gen rules engine detects the planted findings and stays clean on benign input.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
