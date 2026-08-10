---
name: osint-autopilot
description: End-to-end external OSINT engagement autopilot. Run the FULL osint-methodology pipeline to completion in ONE go for an authorized domain — engagement folder, Stages 1-5 (seed, expansion, enrichment, exposure, convergence), multi-agent per-host content+JS fan-out, headline verification, auto-generated findings, and a consolidated multi-tab .xlsx deliverable. Stops ONLY for Stage 6 (active exploitation) arming and out-of-scope sibling assets. Use whenever asked to "run OSINT / recon / attack-surface" on a target — do NOT deliver a thin passive first pass.
---

# OSINT Autopilot

Purpose: eliminate the "thin first pass, then user pushes for more" failure. When the user says *run OSINT/recon on `<domain>`* (authorized), execute the whole pipeline to completion and hand back the consolidated workbook — no stopping to ask except the two hard gates below.

Read the companion `osint-methodology` skill for the framework; this skill is the executable runbook. Feedback memory `osint-full-pipeline-default` governs the default.

## Hard gates (the ONLY reasons to stop and ask)
1. **Authorization** — if not already asserted, ask the one scope question, then proceed. (Here it's typically already signed.)
2. **Stage 6 (active exploitation)** — BOLA/IDOR, credential replay, injection confirmation. Never run under autopilot; present the ranked target queue and wait for arming.
3. **Out-of-scope siblings** — a newly-discovered sibling domain/brand (e.g. `<company>.io` when scope was `.com`). Flag; don't scan until confirmed.

Everything in Stages 1–5 runs without pausing for questions.

## Run sequence

Let `S = ~/.claude/skills/osint-autopilot/scripts`.

### 1. Deterministic recon (Stages 1–3 + harvest + breach + ports)
```
bash $S/recon_pipeline.sh <domain>
```
Creates `~/Research/engagements/<domain>/` and populates evidence (DNS/WHOIS/RDAP/email-sec, subdomain union via subfinder+certspotter+crt.sh, dig-resolve, HTTP probe, identity fabric, /version disclosure, S3 takeover check, gau+wayback+JS harvest, HudsonRock breach, bounded public-IP port scan), hashes everything, and splits responsive hosts into `buckets/bucket-NN`.

Host notes baked in: uses `dig`/`curl` (ProjectDiscovery `dnsx`/`httpx` segfault on this M1 — cgo m1cpu); nmap is time-capped at 10 min so it can't stall.

### 2. Multi-agent per-host fan-out (Stage 4 exposure)
Read `buckets/COUNT` and the `buckets/bucket-*` paths, then launch the workflow (`ffuf` must be on PATH — `go install github.com/ffuf/ffuf/v2@latest` if missing):
```
Workflow({ scriptPath: "<S>/host_enum.workflow.js",
  args: { domain:"<domain>", engDir:"~/Research/engagements/<domain>" (absolute),
          ffuf:"<gopath>/bin/ffuf", wordlist:"<S>/wordlist.txt",
          buckets:[ absolute bucket-00 … bucket-NN ] } })
```
**Pass `args` as a real JSON object, NOT a stringified one** — the harness hands `args` to the script verbatim; a string makes `args.domain`/`args.buckets` undefined and only the synthesize agent runs. The script fails loudly if args are malformed. `engDir` must be absolute. `buckets` = absolute paths of every `buckets/bucket-*` file (read `buckets/COUNT`).

It fans out ffuf content-discovery + JS/endpoint analysis per bucket (agentType general-purpose), then synthesizes a ranked BOLA/IDOR target queue. Save `synthesis` to `evidence/stage6-content/SYNTHESIS.md`.
Optional screenshots: `gowitness scan file -f <urls> --screenshot-path evidence/stage6-screens --write-db` (Chrome required).

### 3. Verify headlines yourself (do NOT trust agent output blindly)
Re-curl every CONFIRMED-worthy claim before reporting it: exposed secrets (fetch the JS/vars file), `/version` disclosures, Cognito/Auth0 config, any "unauth admin 200". Downgrade anything you can't reproduce.

### 4. Auto-findings + workbook
`build_xlsx.py` requires the `openpyxl` pip package (`pip install -r $S/requirements.txt` if missing).
```
python3 $S/findings_gen.py <domain>     # evidence -> findings/findings.csv (rules engine)
python3 $S/build_xlsx.py  <domain>      # findings.csv + evidence -> <domain>-osint-consolidated.xlsx
```
`findings_gen.py` encodes the rubric (non-prod exposure, CDN/WAF-bypass origins, internal-IP leak, DMARC/SPF, /version disclosure, JS secrets, S3 takeover, identity fabric, breach severity, WordPress, port exposure). Hand-add any nuanced findings the rules miss by editing `findings.csv`, then re-run `build_xlsx.py`.

### 5. Report
Give the consolidated `.xlsx` path + a short severity summary, then present the two open gates (Stage 6 queue + any out-of-scope siblings). Offer passive CVE mapping against disclosed versions as a next step.

## Deliverable
`~/Research/engagements/<domain>/`:
- `<domain>-osint-consolidated.xlsx` — 9–10 tabs (Summary, Findings, Subdomains, Live Hosts, API Endpoints, Secrets, Ports, Internal-IP-Leak, Screenshots)
- `findings/findings.csv` · `evidence/**` (+ `.sha256`) · `evidence/stage6-content/SYNTHESIS.md` · `run-log.jsonl`

## Time budget
Small org (<100 hosts): ~15–25 min wall-clock. Medium (100–1K): ~30–60 min, dominated by the fan-out workflow and gau harvest.

## Scale note
The fan-out is ~1 agent per 18 hosts. Keep total agents ≤15 (default guideline); for >270 responsive hosts, raise bucket size in `recon_pipeline.sh` (`split -l`) rather than agent count.
