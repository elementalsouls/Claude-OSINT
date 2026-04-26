# How to push this repo to GitHub

This is a one-time setup guide for the maintainer (you).

---

## Prerequisites

- GitHub account
- `git` installed locally
- Optional: `gh` (GitHub CLI) for one-step repo creation

---

## Step 1: Populate the full SKILL.md content

The repo currently ships **structured-outline** SKILL.md files (each ~250 lines). The full v2.1 inline content lives at:

- `L:\Research\Falcon-Recon\docs\skills\osint-methodology.SKILL.md` (1,694 lines)
- `L:\Research\Falcon-Recon\docs\skills\offensive-osint.SKILL.md` (3,828 lines)

Before pushing to GitHub, decide whether to ship the full inline content or keep the outline + sync script.

### Option A (recommended): Ship the full inline SKILL.md files

This makes the repo self-contained — anyone who clones it gets the full skills immediately.

Run from PowerShell or Command Prompt **on Windows side** (not via WSL/bash):

```powershell
# From your Falcon-Recon directory
$repo = "L:\Research\Falcon-Recon\Claude-OSINT"
$src = "L:\Research\Falcon-Recon\docs\skills"

# Bundle the full content into docs/full-skills/ (for the sync script)
mkdir -Force "$repo\docs\full-skills" | Out-Null
Copy-Item "$src\osint-methodology.SKILL.md" "$repo\docs\full-skills\osint-methodology.SKILL.full.md"
Copy-Item "$src\offensive-osint.SKILL.md" "$repo\docs\full-skills\offensive-osint.SKILL.full.md"

# ALSO replace the structured-outline SKILL.md files with the full versions
Copy-Item "$src\osint-methodology.SKILL.md" "$repo\skills\osint-methodology\SKILL.md" -Force
Copy-Item "$src\offensive-osint.SKILL.md" "$repo\skills\offensive-osint\SKILL.md" -Force

# Verify
Get-ChildItem "$repo\skills" -Recurse -Filter "SKILL.md" | ForEach-Object {
  Write-Host "$($_.FullName): $((Get-Content $_).Count) lines"
}
```

Expected output:
```
...\skills\osint-methodology\SKILL.md: ~1694 lines
...\skills\offensive-osint\SKILL.md: ~3828 lines
```

### Option B: Keep the outline + ship the sync script

Smaller repo (~3.7K lines vs ~9.5K lines). Users run `./scripts/sync-skill-content.sh` after cloning.

To prepare:

```powershell
$repo = "L:\Research\Falcon-Recon\Claude-OSINT"
$src = "L:\Research\Falcon-Recon\docs\skills"

mkdir -Force "$repo\docs\full-skills" | Out-Null
Copy-Item "$src\osint-methodology.SKILL.md" "$repo\docs\full-skills\osint-methodology.SKILL.full.md"
Copy-Item "$src\offensive-osint.SKILL.md" "$repo\docs\full-skills\offensive-osint.SKILL.full.md"
```

Leave the `skills/*/SKILL.md` outline files in place. After clone, users run the sync script.

---

## Step 2: Initialize git

```powershell
cd L:\Research\Falcon-Recon\Claude-OSINT

git init -b main
git add .
git status   # verify what's about to be committed
git commit -m "Initial commit: Falcon OSINT Skills v2.1

Two production-ready Claude skills for external red-team OSINT:
- osint-methodology (1.7K lines, 33 sections, 'how to think')
- offensive-osint (3.8K lines, 51 sections, 'what to reach for')

Smoke-test grade: 31/32 PASS (96.9%).
~85-90% coverage of practitioner needs in OSINT/recon phase.

Includes: 5-stage recon pipeline, asset graph (29 types),
findings rubric, identity-fabric mapping (M365 deep), JS deep
analysis, mobile attack surface, cloud attack surface, breach x
identity correlation, WAF/CDN bypass + origin discovery, vuln
prioritization (CVE/EPSS/KEV), phishing infrastructure planning,
bug bounty templates, client deliverable templates, vendor
fingerprints (Citrix/F5/Pulse/Fortinet/PaloAlto/Cisco/VMware),
cloud-native fingerprints, container/K8s exposure, CI/CD exposure,
LinkedIn enum, job posting analysis, Slack/Discord discovery,
package registry leak hunting, sat imagery, sector-specific notes,
48-pattern secret catalog (incl. modern AI APIs), 80+ dork corpus,
9 read-only secret validators, copy-paste curl probes, post-discovery
enumeration workflows."
```

---

## Step 3: Create the GitHub repo

### Via GitHub CLI (one-step)

```powershell
gh auth login   # if not already authenticated
gh repo create Claude-OSINT --public --source=. --remote=origin --push
```

### Via GitHub web UI (manual)

1. Go to https://github.com/new
2. Repository name: `Claude-OSINT`
3. Description: `Production-ready Claude skills for external red-team OSINT and bug-bounty reconnaissance — methodology + arsenal, paired.`
4. Visibility: **Public** (recommended) or Private
5. Do NOT check "Initialize with README" (you have one).
6. Create repository.
7. Then locally:

```powershell
git remote add origin https://github.com/<your-username>/Claude-OSINT.git
git push -u origin main
```

---

## Step 4: Configure repo settings (one-time)

After push, in the GitHub web UI:

### About section (sidebar)

- **Description:** `Production-ready Claude skills for external red-team OSINT — 90+ recon modules, 48 secret patterns, 80+ dorks, identity-fabric mapping, breach correlation, vendor fingerprints, client deliverables`
- **Website:** (leave blank or link to your blog post about this)
- **Topics:** `claude`, `osint`, `red-team`, `bug-bounty`, `attack-surface-management`, `asm`, `reconnaissance`, `claude-code`, `skills`, `security`, `pentesting`, `ai-security`

### Settings → General

- ✅ Allow squash merging
- ✅ Allow rebase merging
- ❌ Allow merge commits (keep history clean)
- ✅ Automatically delete head branches after merge

### Settings → Branches → Branch protection rules

For `main`:
- ✅ Require a pull request before merging (1 approval)
- ✅ Require status checks to pass (after first CI run, select `markdown`, `yaml-frontmatter`, `python-helper`)
- ✅ Require linear history

### Settings → Pages

If you want a project landing page rendered from the README:
- Source: `Deploy from a branch`
- Branch: `main` / `/ (root)`

---

## Step 5: Add release tag

```powershell
git tag -a v2.1.0 -m "Release v2.1.0 — comprehensive expansion"
git push origin v2.1.0
```

Then in GitHub: Releases → Draft a new release → Tag: `v2.1.0` → Title: `v2.1.0 — Comprehensive Expansion` → Description: paste from `CHANGELOG.md`.

---

## Step 6: Announce

Optional. If you want the skills to be discoverable:

- Tweet / X-post linking to the repo.
- Submit to https://www.awesome-claude-skills.com (or similar curated lists).
- Post in r/redteamsec, r/AskNetsec, r/bugbounty (read each subreddit's rules first).
- Submit to Hacker News (Show HN).
- Mention in your own blog / portfolio.

---

## Step 7: Maintain

After the initial push:

- Triage incoming issues + PRs (CONTRIBUTING.md guides contributors).
- Run the smoke test ([`tests/smoke-test-prompts.md`](tests/smoke-test-prompts.md)) after every merge.
- Tag a new release (semver: PATCH for fixes, MINOR for new sections, MAJOR for renumbering) when changes accumulate.
- Update `CHANGELOG.md` with each release.

---

## Verifying the push

After push, test the install path:

```powershell
# In a temporary directory
cd ~\Desktop
git clone https://github.com/<your-username>/Claude-OSINT.git test-clone
cd test-clone

# Verify structure
Get-ChildItem -Recurse -File | Select-Object Name, Length, FullName | Out-Host

# Install in Claude Code
mkdir -Force ~\.claude\skills | Out-Null
Copy-Item -Recurse skills\* ~\.claude\skills\

# Run a test prompt in Claude Code
# "What paths should I probe to find Swagger or OpenAPI specs on a webapp?"
# (Should return the 28-path wordlist from arsenal §16.1)
```

If the test prompt works, you're live. 🚀

---

## Cleanup

Remove the experimental `skills-repo/` directory in your Falcon-Recon project (it was an aborted earlier attempt; the canonical repo is `Claude-OSINT/`):

```powershell
Remove-Item -Recurse -Force L:\Research\Falcon-Recon\skills-repo
```

(Optional. The `skills-repo/` dir doesn't break anything; it's just clutter.)
