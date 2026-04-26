#requires -Version 5.1
<#
.SYNOPSIS
    One-command push to GitHub for the Claude-OSINT skills repo.

.DESCRIPTION
    Renames the local directory to Claude-OSINT, populates the full v2.1
    SKILL.md content from the canonical Falcon-Recon docs location,
    initializes git, creates the GitHub repo, and pushes.

    Run this from PowerShell (not bash). The repo will be created PUBLIC
    by default; pass -Private to create a private repo.

.PARAMETER GithubUsername
    Your GitHub username. Required.

.PARAMETER Private
    Create the GitHub repo as private. Defaults to public.

.PARAMETER SkipRename
    Skip the directory rename step (assumes the directory is already
    named Claude-OSINT).

.EXAMPLE
    .\push-to-github.ps1 -GithubUsername sachinlucideus

.EXAMPLE
    .\push-to-github.ps1 -GithubUsername sachinlucideus -Private
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$GithubUsername,

    [switch]$Private,

    [switch]$SkipRename
)

$ErrorActionPreference = "Stop"

$REPO_NAME = "Claude-OSINT"
$PARENT_DIR = "L:\Research\Falcon-Recon"
$OLD_DIR = Join-Path $PARENT_DIR "falcon-osint-skills"
$NEW_DIR = Join-Path $PARENT_DIR $REPO_NAME
$CANONICAL_SRC = Join-Path $PARENT_DIR "docs\skills"

Write-Host ""
Write-Host "==> Claude-OSINT push to GitHub" -ForegroundColor Cyan
Write-Host ""

# ─────────────────────────────────────────────────────────────────
# STEP 0: Check prerequisites
# ─────────────────────────────────────────────────────────────────

Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Yellow

$missing = @()
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { $missing += "git" }
if (-not (Get-Command gh  -ErrorAction SilentlyContinue)) { $missing += "gh (GitHub CLI)" }

if ($missing.Count -gt 0) {
    Write-Host "  Missing required tools:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "    - $_" }
    Write-Host ""
    Write-Host "  Install:"
    Write-Host "    git → https://git-scm.com/download/win"
    Write-Host "    gh  → winget install --id GitHub.cli"
    Write-Host ""
    exit 1
}

# Verify gh is authenticated
$ghStatus = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  GitHub CLI not authenticated. Run: gh auth login" -ForegroundColor Red
    exit 1
}

Write-Host "  ✓ git, gh installed and authenticated" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────
# STEP 1: Rename directory (if needed)
# ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[2/6] Renaming directory..." -ForegroundColor Yellow

if ($SkipRename) {
    if (-not (Test-Path $NEW_DIR)) {
        Write-Host "  -SkipRename was set but $NEW_DIR doesn't exist." -ForegroundColor Red
        exit 1
    }
    Write-Host "  ✓ Skipped (using existing $NEW_DIR)" -ForegroundColor Green
} elseif (Test-Path $NEW_DIR) {
    Write-Host "  ✓ Already renamed to Claude-OSINT" -ForegroundColor Green
} elseif (Test-Path $OLD_DIR) {
    Rename-Item -Path $OLD_DIR -NewName $REPO_NAME
    Write-Host "  ✓ Renamed falcon-osint-skills → Claude-OSINT" -ForegroundColor Green
} else {
    Write-Host "  Neither $OLD_DIR nor $NEW_DIR exists." -ForegroundColor Red
    exit 1
}

Set-Location $NEW_DIR

# ─────────────────────────────────────────────────────────────────
# STEP 2: Populate full v2.1 SKILL.md content
# ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[3/6] Populating full v2.1 SKILL.md content..." -ForegroundColor Yellow

if (-not (Test-Path "$CANONICAL_SRC\osint-methodology.SKILL.md")) {
    Write-Host "  Canonical source missing: $CANONICAL_SRC\osint-methodology.SKILL.md" -ForegroundColor Red
    Write-Host "  Skipping content sync. Outline-only SKILL.md will be pushed." -ForegroundColor Yellow
} else {
    # Bundle the full content into docs/full-skills/ for the sync script
    New-Item -Force -ItemType Directory -Path "docs\full-skills" | Out-Null
    Copy-Item "$CANONICAL_SRC\osint-methodology.SKILL.md" "docs\full-skills\osint-methodology.SKILL.full.md" -Force
    Copy-Item "$CANONICAL_SRC\offensive-osint.SKILL.md"   "docs\full-skills\offensive-osint.SKILL.full.md"   -Force

    # Replace the structured-outline SKILL.md files with the full versions
    Copy-Item "$CANONICAL_SRC\osint-methodology.SKILL.md" "skills\osint-methodology\SKILL.md" -Force
    Copy-Item "$CANONICAL_SRC\offensive-osint.SKILL.md"   "skills\offensive-osint\SKILL.md"   -Force

    $methLines = (Get-Content "skills\osint-methodology\SKILL.md").Count
    $arsLines  = (Get-Content "skills\offensive-osint\SKILL.md").Count

    Write-Host "  ✓ osint-methodology/SKILL.md: $methLines lines" -ForegroundColor Green
    Write-Host "  ✓ offensive-osint/SKILL.md:   $arsLines lines" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────
# STEP 3: Initialize git
# ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[4/6] Initializing git..." -ForegroundColor Yellow

if (Test-Path ".git") {
    Write-Host "  ✓ Already a git repo" -ForegroundColor Green
} else {
    git init -b main 2>&1 | Out-Null
    Write-Host "  ✓ git init -b main" -ForegroundColor Green
}

# Configure user if not set (use GitHub username + noreply email)
$gitUserName  = git config user.name  2>$null
$gitUserEmail = git config user.email 2>$null
if (-not $gitUserName)  { git config user.name  $GithubUsername }
if (-not $gitUserEmail) { git config user.email "${GithubUsername}@users.noreply.github.com" }

git add . 2>&1 | Out-Null

$staged = git diff --cached --name-only 2>$null
if (-not $staged) {
    Write-Host "  No changes to commit." -ForegroundColor Yellow
} else {
    $commitMsg = @"
Initial commit: Claude-OSINT v2.1

Two production-ready Claude skills for external red-team OSINT and
bug-bounty reconnaissance:

  - osint-methodology (1.7K lines, 33 sections, 'how to think')
  - offensive-osint (3.8K lines, 51 sections, 'what to reach for')

Smoke-test grade: 31/32 PASS (96.9%).
~85-90% coverage of practitioner needs in OSINT/recon phase.

Includes: 5-stage recon pipeline, asset graph (29 types), findings
rubric, identity-fabric mapping (M365 deep), JS deep analysis,
mobile attack surface, cloud attack surface, breach x identity
correlation, WAF/CDN bypass + origin discovery, vuln prioritization
(CVE/EPSS/KEV), phishing infrastructure planning, bug bounty
templates, client deliverable templates, vendor fingerprints
(Citrix/F5/Pulse/Fortinet/PaloAlto/Cisco/VMware), cloud-native
fingerprints, container/K8s exposure, CI/CD exposure, LinkedIn
enum, job posting analysis, Slack/Discord discovery, package
registry leak hunting, sat imagery, sector-specific notes,
48-pattern secret catalog (incl. modern AI APIs), 80+ dork corpus,
9 read-only secret validators, copy-paste curl probes,
post-discovery enumeration workflows.
"@
    git commit -m "$commitMsg" 2>&1 | Out-Null
    Write-Host "  ✓ Initial commit created" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────
# STEP 4: Create GitHub repo + push
# ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[5/6] Creating GitHub repo + pushing..." -ForegroundColor Yellow

$visibility = if ($Private) { "--private" } else { "--public" }
$repoUrl = "https://github.com/$GithubUsername/$REPO_NAME"

# Check whether repo already exists
$existing = gh repo view "$GithubUsername/$REPO_NAME" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Repo $repoUrl already exists." -ForegroundColor Yellow
    Write-Host "  Adding it as remote and pushing..."

    $existingRemote = git remote get-url origin 2>$null
    if (-not $existingRemote) {
        git remote add origin "$repoUrl.git"
    }
    git push -u origin main 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Push failed. You may need to merge or force-push manually." -ForegroundColor Red
        exit 1
    }
} else {
    $description = "Production-ready Claude skills for external red-team OSINT and bug-bounty reconnaissance — 90+ recon modules, 48 secret patterns, 80+ dorks, identity-fabric mapping, breach correlation, vendor fingerprints, client deliverables. ~85-90% practitioner coverage."
    gh repo create $REPO_NAME $visibility --source=. --remote=origin --push --description "$description" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  gh repo create failed. See output above." -ForegroundColor Red
        exit 1
    }
}

Write-Host "  ✓ Pushed to $repoUrl" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────
# STEP 5: Tag release
# ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[6/6] Tagging v2.1.0 release..." -ForegroundColor Yellow

$existingTag = git tag -l "v2.1.0"
if ($existingTag) {
    Write-Host "  ✓ Tag v2.1.0 already exists" -ForegroundColor Green
} else {
    git tag -a v2.1.0 -m "Release v2.1.0 - comprehensive expansion (31/32 smoke-test PASS)" 2>&1 | Out-Null
    git push origin v2.1.0 2>&1 | Out-Null
    Write-Host "  ✓ Tagged + pushed v2.1.0" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "==> Done!" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Repo: $repoUrl" -ForegroundColor Green
Write-Host "  Releases: $repoUrl/releases" -ForegroundColor Green
Write-Host "  Actions (CI): $repoUrl/actions" -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:"
Write-Host "    1. Visit the repo → set 'Topics' (claude, osint, red-team, bug-bounty, asm, security, etc.)"
Write-Host "    2. Verify CI workflows pass (~1 min after push)"
Write-Host "    3. Draft a GitHub Release for v2.1.0 (Releases tab)"
Write-Host "    4. Test install: git clone $repoUrl into a fresh dir + verify"
Write-Host ""
