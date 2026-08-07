# `osint-autopilot` skill

End-to-end external OSINT engagement autopilot. Runs the full `osint-methodology` pipeline to completion in **one** invocation and hands back a consolidated Excel workbook — instead of a thin passive first pass that has to be pushed for more.

| Field | Value |
|---|---|
| Name | `osint-autopilot` |
| Companion skills | [`osint-methodology`](../osint-methodology/) · [`offensive-osint`](../offensive-osint/) |
| Output | `~/Research/engagements/<domain>/<domain>-osint-consolidated.xlsx` + evidence tree |
| Stops only for | Stage 6 (active exploitation) arming · out-of-scope sibling assets |

## When this skill triggers

Use whenever asked to *run OSINT / recon / attack-surface* on an authorized target. It is the executable runbook; `osint-methodology` is the framework it follows.

## What it does

Runs Stages 1–5 of the 6-stage methodology without pausing for questions:

1. **`recon_pipeline.sh <domain>`** — deterministic driver. Creates the engagement folder + chain-of-custody, then: DNS/WHOIS/RDAP/email-security · subdomain union (subfinder + certspotter + crt.sh) · `dig` resolution · parallel HTTP probe · identity fabric (Entra realm / OIDC / Okta) · unauth `/version` disclosure check · S3-website takeover check · endpoint harvest (gau + waybackurls + live JS secret/endpoint sweep) · HudsonRock breach lookup (free) · public-IP port scan (bounded). Hashes every artifact (SHA-256) and splits responsive hosts into buckets.
2. **`host_enum.workflow.js`** — multi-agent fan-out (≈1 agent per 18 hosts). Per host: `ffuf` content discovery + first-party JS/endpoint/secret analysis, then a synthesis agent that produces a ranked BOLA/IDOR "look here next" queue. WAF-block responses are excluded, not counted as exposures.
3. **Headline verification** — every CONFIRMED-worthy claim (exposed secret, `/version`, unauth panel) is re-fetched directly before it is reported. Subagent output is not trusted blind.
4. **`findings_gen.py <domain>`** — rules engine over the evidence → `findings/findings.csv` (non-prod exposure, CDN/WAF-bypass origins, internal-IP leak, DMARC/SPF, `/version` disclosure, JS secrets, S3 takeover, identity fabric, breach severity, WordPress, port exposure).
5. **`build_xlsx.py <domain>`** — consolidated 9-tab workbook: Summary · Findings (severity-colored) · Subdomains · Live Hosts · API Endpoints · Secrets & Keys · Open Ports · Internal-IP-Leak · Screenshots.

## Hard gates (the only reasons it stops)

- **Authorization** not yet asserted → ask once, then proceed.
- **Stage 6** (BOLA/IDOR, credential replay, injection) → never run on autopilot; present the ranked queue and wait for arming.
- **Out-of-scope siblings** (e.g. a `.io` sibling when scope is `.com`) → flag, don't scan until confirmed.

## Usage

```bash
S=~/.claude/skills/osint-autopilot/scripts     # or this repo's skills/osint-autopilot/scripts
bash   $S/recon_pipeline.sh  <domain>
# then launch the fan-out workflow (see SKILL.md — pass args as a real JSON object)
python3 $S/findings_gen.py    <domain>
python3 $S/build_xlsx.py      <domain>
```

Requirements: `subfinder`, `gau`, `waybackurls`, `ffuf`, `nmap`, `dig`, `curl`, `jq`, Python 3 + `openpyxl`; optional `gowitness` (+ Chrome) for screenshots. Uses `dig`/`curl` deliberately (ProjectDiscovery `dnsx`/`httpx` segfault under cgo on some Apple-silicon hosts); `nmap` is time-capped so a run can't stall.

## Design notes

- **No hardcoded findings.** Every finding is derived from collected evidence by the rules engine, so output is target-specific, not templated.
- **False-positive discipline.** Non-prod counts *resolving* hosts (not CT-log cert-noise); WordPress is a live-response check (not archive noise); identity findings require a real Managed/Federated namespace or a discovered Okta org; WAF block pages are excluded from exposures.
- **Chain of custody.** UTC `run-log.jsonl` + a `.sha256` sidecar for every evidence artifact.

## Verification

Validated end-to-end before publishing. The verification run itself surfaced four bugs, all fixed:

| Check | Result |
|---|---|
| `bash -n` / `py_compile` / `node --check` on all scripts | pass |
| `recon_pipeline.sh` full run on a fresh domain | all stages, evidence hashed, buckets built |
| `host_enum.workflow.js` live fan-out | enumerates, runs `ffuf`, returns synthesis |
| `findings_gen.py` + `build_xlsx.py` | `findings.csv` + 9-tab workbook |

Bugs caught and fixed during verification:
1. Non-prod finding counted subdomain *strings* (incl. certificate-transparency noise) instead of *resolving* hosts.
2. Identity finding fired on an "Unknown" namespace — now gated to Managed/Federated / discovered Okta org.
3. WordPress finding fired on archived-URL noise — now a live HTTPS fingerprint check.
4. Workflow `args` passed as a string left `domain`/`buckets` undefined — added string-parse + a fail-loud guard.

## Files

```
osint-autopilot/
  SKILL.md
  README.md
  scripts/
    recon_pipeline.sh        # Stages 1-3 + harvest + breach + ports (deterministic)
    host_enum.workflow.js    # Stage 4 multi-agent per-host content + JS fan-out
    findings_gen.py          # evidence -> findings.csv (rules engine)
    build_xlsx.py            # findings.csv + evidence -> consolidated .xlsx
    wordlist.txt             # 100-path high-signal content-discovery list
```
