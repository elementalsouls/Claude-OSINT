---
name: exposure-risk-quantification
description: "FAIR-aligned exposure quantification: turns a pile of recon findings into a defensible 0-100 + A-F org risk score (Likelihood x Impact, three ownership-aware factors: exposure/threat/impact), an ownership + proof demotion cap so unproven or weakly-owned findings can't inflate the number, a $-denominated FAIR loss-magnitude estimate (IBM/Ponemon per-record cost bands, cross-source record dedup, threat-factor annualization), attack-path amplification (curated red-team chain catalog + generic graph-walk engine, with a kill-chain vs shared-fate honesty gate), and a board-ready one-pager deliverable (hero $ + letter grade + top-3 findings + top attack path + the ask). Extends osint-methodology's severity rubric and client deliverable templates with quantification. Passive analysis only -- operates on findings already collected, no target traffic, no API keys. Use when asked to score risk, quantify exposure, estimate breach cost, build a board report, translate technical findings to dollars, or explain why a grade or dollar figure came out the way it did."
version: 1.0
triggers:
  - risk score
  - risk quantification
  - cyber risk quantification
  - CRQ
  - FAIR methodology
  - FAIR score
  - loss event frequency
  - loss magnitude
  - risk grade
  - letter grade risk
  - A-F grade
  - 0-100 risk score
  - board report
  - board deliverable
  - board ready
  - executive summary risk
  - CISO report
  - hero number
  - dollar exposure
  - breach cost estimate
  - loss estimate
  - annualized loss expectancy
  - ALE
  - per-record cost
  - IBM Ponemon
  - cost of a data breach
  - exposed record count
  - quantify risk
  - risk translation
  - attack path
  - kill chain
  - shared fate exposure
  - attack path amplification
  - ownership confidence
  - proof demotion cap
  - confidence cap
  - TENTATIVE inflate score
  - risk trend
  - risk delta
  - the ask
  - remediation ask
  - one-pager
  - exposure risk
  - business impact translation
  - dominant risk driver
---

# Exposure Risk Quantification — FAIR Scoring, $-Loss, and the Board Deliverable

> Companion skill: `osint-methodology` (the "how to think" recon skill — see its §9 severity
> rubric and §16 client deliverable templates). This skill is the "how to quantify and
> present" layer on top of a finished recon pass: it takes findings the methodology skill's
> pipeline already produced and turns them into a number a board will act on.

## 0. When to Use / When NOT

**Use this skill when:** you have a completed set of recon findings (from any engagement,
not just Falcon-Recon output) and need to (a) compute a defensible 0–100 + A–F risk score,
(b) estimate a $-denominated loss range, (c) rank attack-path chains by exploitability, or
(d) assemble a board/exec one-pager. Also use it to *explain* a score — "why did this grade
come out D and not F" is exactly what §7 is for.

**Do NOT use this skill when:** you still need to go collect findings — that's
`osint-methodology` (methodology) / `offensive-osint` (arsenal). This skill does not probe
anything; it has nothing to say until a recon pass has already produced findings, assets,
and (ideally) ownership/proof annotations.

---

## 1. Posture: Passive Analysis, Not New Recon

Every computation in this skill is a **pure function over findings + assets you already
hold** — no network calls, no new probes, no target traffic. The reference implementation
(`falcon_recon/reporting/{risk_score,loss_model,board_report,board_render,attack_paths,
attack_graph,owner_confidence,proof}.py`) is explicit about this: `risk_score.py` docstring
calls itself "Pure compute over `scan.db` — no network, no schema change"; `loss_model.py`
calls itself "Pure, no network"; `attack_graph.py` calls itself "Pure + offline."

That means this skill inherits the authorization posture of whatever collected the inputs
(see `osint-methodology` §1) but adds none of its own — quantifying findings you already
lawfully hold is never itself an intrusive act. It also means the outputs are only as good
as the inputs: garbage findings (unowned namesakes, unverified snippet matches) produce a
garbage score unless you apply the demotion cap in §7.5 first.

---

## 2. Confidence Levels

Reuses `osint-methodology` §2 verbatim — every finding you're about to score already
carries one of:

| Level | Meaning |
|---|---|
| **TENTATIVE** | Plausible, unverified. |
| **FIRM** | Directly observed, uncorroborated. |
| **CONFIRMED** | Multiple independent corroborations OR directly verified. |

What this skill adds is a second, orthogonal axis — **ownership certainty** — and the rule
for how the two combine so neither one alone can inflate a number (§7.5).

---

## 3. Output Format

Three artifacts, each a pure dataclass with a `to_dict()`:

```
OrgRisk:
  risk: float            # 0-100 headline
  grade: str              # A|B|C|D|F
  exposure, breach_likelihood, impact: float   # the three factors x100
  dominant_driver: str    # "exposure" | "breach-likelihood" | "business-impact"
  narrative: str          # 2-3 sentence board-language explanation

LossEstimate:
  records: int
  low, expected, high: float     # $ range
  annualized: float | None
  basis: str              # human-readable "N records x $X/record (source)" string

BoardSummary:
  target, hero (HeroNumbers), top_findings[], top_paths[], the_ask[], methodology, narrative
```

**Rule: every number ships with its basis.** `LossEstimate.basis` and `OrgRisk.narrative`
are not optional decoration — never present the bare `risk` float or `expected` dollar
figure without the sentence that explains what drove it. §4 and §12 make this a hard rule,
not a style preference.

---

## 4. Source Hygiene & Assumption Disclosure

For every quantified number, disclose:

- **The cost band used** and its source (default: IBM/Ponemon Cost of a Data Breach,
  ~$165/record — see §8.1). If you swapped in a region/industry-tuned band, say so.
- **The record count's provenance** — which breach source(s) it came from and whether
  multiple sources were deduped (§8.2 — max-across-sources, never summed).
- **Which likelihood fed the annualization** — the Threat factor (T), *not* the composite
  risk score (§8.3). These are different numbers computed differently; conflating them is
  the single most common way to misstate an ALE.
- **The scan/snapshot timestamp** — a risk score is a point-in-time read of a
  continuously-changing external surface. Say when it was computed.

---

## 5. Do NOT

- Do NOT present the point estimate (`expected`) without the range (`low`–`high`).
- Do NOT let a TENTATIVE or weakly-owned finding stand in for a CONFIRMED, owned one — run
  the demotion cap (§7.5) before scoring, and check what did *not* get demoted (§12).
- Do NOT claim a shared-fate (co-location) graph path is a proven attack chain — see §9.3.
  It is blast-radius context, not a kill-chain, and must be labeled as such.
- Do NOT fabricate a dollar figure when the record count is 0. Say what the score is
  actually grading (posture / proven exposure) instead — see §10.1.
- Do NOT compare risk scores across two different targets as if they sit on a shared
  absolute scale beyond the A–F band; only a target's own `risk_trend` (§10.1) is a valid
  time-series comparison.
- Do NOT treat the model's output as ground truth. It is a calibrated heuristic over the
  findings you hold, not a claim that a breach is certain, imminent, or quantified to the
  dollar. See §12.

---

## 6. FAIR Primer — Mapping Recon Findings onto Risk = LEF × LM

FAIR (Factor Analysis of Information Risk) decomposes risk into:

**Risk = Loss Event Frequency (LEF) × Loss Magnitude (LM)**

External recon cannot observe LEF or LM directly — no one is handing you an actuarial
table for this specific target. What recon *can* do is produce calibrated **proxies** for
both halves, and that's what this skill's three-factor model does:

| FAIR concept | Recon proxy | Computed by |
|---|---|---|
| Loss Event Frequency (probability a bad event happens) | **Likelihood** = combine(Exposure, Threat) | §7.1–§7.2 |
| — breadth/severity of what's exposed | **Exposure (E)** | attack-surface findings, severity-weighted |
| — how actively that exposure is being targeted | **Threat (T)** | KEV/EPSS, leaked creds, adversary chatter, proven exploits, attack-path chains |
| Loss Magnitude (cost if it happens) | **Impact (I)** | §7.3 — worst-case, ownership-gated business value of what's exposed |
| Loss Magnitude, in dollars | **loss_model.estimate()** | §8 — exposed-record count × per-record cost band |

**Keep it honest:** a 0–100 score and a $ range are *likelihood and magnitude inputs*, not
a claim that a breach has happened, will happen, or costs exactly that much. Every FAIR
practitioner treats the output as a decision-support number with stated assumptions — this
skill enforces that discipline structurally (§4, §12) rather than leaving it to the writer's
memory.

This skill **deepens** `osint-methodology` §9 (severity rubric — CRITICAL/HIGH/MEDIUM/LOW/
INFO anchors) by rolling those per-finding severities into one org-level number, and §16
(client deliverable templates — exec summary, risk translation table, reporting cadence) by
adding the $ figure and the board one-pager layout those templates gesture at but don't
compute.

---

## 7. The 0–100 + A–F Score

Source: `reporting/risk_score.py`. `risk = round(likelihood × Impact × 100, 1)`, where
`likelihood = combine(Exposure, Threat)`.

**The independent-evidence combiner**, used everywhere two-or-more probabilistic signals
need to merge without double-counting:

```
combine(weights) = 1 - Π(1 - w_i)     for each w_i clamped to [0, 1]; empty list -> 0
```

This is the same shape used for OR-of-independent-events probability — one strong signal
dominates, several weak signals still add up, and nothing can exceed 1.0.

### 7.1 Exposure (E) — breadth × severity of the attack surface

Sum a severity-weighted load `S` over **every finding in the scan** (this term is *not*
gated by confidence or ownership — see the sharp edge called out in §12), then saturate:

| Severity | Weight |
|---|---|
| critical | 1.0 |
| high | 0.4 |
| medium | 0.1 |
| low | 0.02 |
| info | 0.0 |

```
S = sum(severity_weight[f.severity] for f in findings)
E = min(1 - e^(-S / 25), 1 - 1e-15)        # K=25: calibration constant
```

`K = 25` is chosen so a couple of findings reads low and a broad/severe surface approaches
1 — deliberately *not* an independent-evidence combine (which would saturate to ~1.0 on a
single critical and give zero discrimination between a 2-critical and a 200-critical
target).

**The proven-critical floor:** if the scan carries an owned (`owner_confidence ≥ 70`)
finding that is severity CRITICAL and either `confidence == "confirmed"` or `is_proven`
(§7.5), `E = max(E, 0.5)`. A proven critical on an asset you own is material risk — this
floor is the mechanism that stops such a target from grading A ("strong posture") purely
because it has few *other* findings.

### 7.2 Threat (T) — breach-likelihood multiplier

A weighted list, combined via `combine()`. Each condition below appends a weight if true;
absent conditions contribute nothing (not zero-weight — simply omitted from the list):

| Signal | Weight | Gate |
|---|---|---|
| Proven exploit on an owned host, OR an owned CONFIRMED/proven critical (same predicate as the §7.1 floor) | 0.90 | owner_confidence ≥ 70 |
| CISA KEV match (`cve` asset with `attrs.kev`, OR finding evidence `kev_cves`) | 0.90 | KEV-asset: unconditional; finding-evidence: owned host only |
| Max EPSS score across CVEs | `min(1, epss_max) × 0.7` | same split as KEV |
| Active-sale (a market-escalation finding with `evidence.for_sale`) | 0.90 | unconditional |
| Held leaked credentials for the org (elif no active-sale) | 0.80 | credential asset: unconditional; secret asset: owned host only |
| Ransomware / adversary chatter listing, severity HIGH/CRITICAL | 0.85 | unconditional |
| An attack-path chain (§9) scoring ≥ 85 present anywhere in the scan | 0.60 | binary — see §9.4, this is NOT proportional to the chain's exact score |

```
T = combine(weights)
```

### 7.3 Impact (I) — worst-case, ownership-gated business value

Impact is about the **single most valuable owned asset that's exposed**, not an average —
a target with 500 low-value assets and one crown-jewel exposure scores on the crown jewel.

For every asset with `owner_confidence > 0` (un-owned and typosquat-domain assets
contribute ≈0):

```
asset_weight =
  0.1   if type == typosquat_domain
  1.0   if type in {credential, secret, postman_api_key, firebase_project}
  0.9   if any finding on this asset has category in
          {exposed_admin_panel, ssrf, request_smuggling, host_header_injection,
           xss, authentication_bypass}
  0.9   if hostname contains a payment token: pay, payment, billing, checkout, wallet
  0.85  if hostname contains an internal token: jenkins, gitlab, grafana, kibana,
          vault, jira, confluence, vpn, internal, staging, admin, sso, idp,
          okta, keycloak, adfs
  0.7   if type == api_endpoint AND attrs.auth_required is False
  0.4   if type in {webapp, subdomain, ip, api_endpoint, domain, service}
  0.1   otherwise

I = max( asset_weight × (owner_confidence / 100) )   over all qualifying assets
```

Tokens match whole hostname segments split on non-alphanumerics — `payroll` does **not**
match the `pay` token; `pay.ex.com` and `internal-api.ex.com` do match.

### 7.4 Combine → Likelihood → Risk → Grade

```
likelihood = combine([E, T])
risk       = round(likelihood × I × 100, 1)
```

| Risk | Grade |
|---|---|
| ≤ 20 | A |
| ≤ 40 | B |
| ≤ 60 | C |
| ≤ 80 | D |
| > 80 | F |

**Impact is a multiplicative gate, not an additive term.** A target with high Exposure and
Threat but no confidently-owned, valuable asset (`I < 0.2`) gets capped regardless — the
dominant driver reported is `"business-impact"` with the narrative explaining that few
high-value assets are confidently owned. Otherwise the dominant driver is whichever of
Exposure/Threat is larger.

### 7.5 The Ownership + Proof Demotion Cap

Two **independent** gates prevent a number from being inflated by evidence that isn't
solid — know which one is doing the work on a given finding.

**Gate 1 — ownership caps confidence** (`reporting/owner_confidence.py`). Every asset has a
categorical `owner_tier` (`model.attribution.tier_of()`, banded from the same underlying
0–100 attribution score `risk_score` gates on numerically, but on a different threshold
scheme):

| Attribution score | owner_tier |
|---|---|
| ≤ 0 | NONE |
| < 40 | WEAK |
| < 70 | MODERATE |
| < 90 | STRONG |
| ≥ 90 | CONFIRMED |

| owner_tier | Confidence ceiling |
|---|---|
| CONFIRMED / STRONG | none — finding's confidence is untouched |
| MODERATE | capped at FIRM |
| WEAK / NONE | capped at TENTATIVE |

This is **demote-only** — it never raises a finding's stated confidence, and it never
demotes a finding whose evidence is `is_proven` (Gate 2 below) below what the proof earned.

**Gate 2 — proof survives ownership uncertainty** (`reporting/proof.py`). A finding is
`is_proven` when its evidence carries one of these markers, each stamped by a specific
active confirmer:

| Marker | Stamped by |
|---|---|
| `evidence.proven == True` | explicit opt-in (cloud_buckets / validate_cloud) |
| `evidence.version_confirmed == True` | cve_confirm (graph-recovered running version) |
| `evidence.working_credential` (truthy) | validate_creds (logged in with the default) |
| `evidence.liveness_confirmed == True` | validate_sso (live tenant) |
| `evidence.verified == True` | github_recon trufflehog (verified live secret) |
| `evidence.status == "verified_live"` | live read-only secret validation |
| `evidence.validation.status == "verified_live"` | nested form of the same |

A proven finding's confidence is exempt from the ownership-tier ceiling — the ownership
context is still *recorded* (`evidence.owner_tier`) but never used to erase a confirmation.
This is why `_has_owned_proven_critical` (the shared predicate behind §7.1's floor and
§7.2's 0.90 Threat weight) checks `confidence == "confirmed" OR is_proven(evidence)` — proof
is a second, independent path to "this counts," not merely a synonym for CONFIRMED.

**Write-time complement** (`assign_confidence`, also in `proof.py`): any finding from an
*active-heuristic* module (`host_header`, `request_smuggling`, `bypass403`, `badsecrets`,
`paramminer`, `nuclei_mod`) that is not yet proven is written as TENTATIVE at scan time,
regardless of what the module's internal logic thought — the confidence tier itself only
gets promoted to CONFIRMED by proof, never by module self-assessment.

**The sharp edge this does NOT cover:** §7.1's Exposure severity sum `S` runs over **every
finding regardless of confidence or ownership** — only the proven-critical *floor* is
gated. Three TENTATIVE findings on a barely-owned domain still add their raw severity
weight to `S`. See the self-test trap in §13 and the guardrail in §12.

---

## 8. The $-Loss Model

Source: `reporting/loss_model.py`. Turns exposed-record counts already carried in the
graph into a defensible dollar range — pure, no network, no fabricated numbers.

### 8.1 Cost bands

```
DEFAULT_COST = {"low": 150.0, "expected": 165.0, "high": 200.0}   # USD / exposed record
```

Basis: IBM/Ponemon *Cost of a Data Breach* (~$165/record expected). Region- or
industry-tunable via the `cost` argument — **always state which band you used** (§4).

### 8.2 Record-count extraction & cross-source dedup

Only `leaked_credential` (`Category.LEAKED_CRED`) findings count records, from the
`employees` + `users` evidence keys (`_RECORD_KEYS`) — these are **disjoint populations**
(compromised staff vs. compromised customers who reused a password), so they're **summed
within a source**.

Multiple breach sources (hudsonrock, local_corpus, HIBP, …) each emit their own
domain-stats finding for the *same* org — blindly summing across sources would
double-count the population. Instead:

```
for each LEAKED_CRED finding:
    n = employees + users   (non-numeric / bool / missing -> 0, never guessed)
    by_source[evidence.source or unique-per-finding-key] += n

records = max(by_source.values(), default=0)     # MAX across sources, never summed
```

The largest single authoritative source is a defensible floor, never an inflated
cross-source sum. `records = 0` (no LEAKED_CRED findings, or all zero) → **$0, never an
error and never a fabricated number.**

### 8.3 Point estimate, range, and annualization (ALE)

```
low      = records × cost["low"]
expected = records × cost["expected"]
high     = records × cost["high"]
annualized = expected × (breach_likelihood / 100)     if breach_likelihood is given, else None
basis = f"{records:,} exposed credential record(s) x ${cost['expected']:.0f}/record (IBM/Ponemon breach cost)"
```

**Critical nuance, easy to misstate:** when the board-report caller invokes this, it passes
`breach_likelihood = org_risk["breach_likelihood"]` — that is the **Threat factor T** from
§7.2, scaled to 0–100. It is **not** the composite `risk` score from §7.4 (which already
folds in Impact). Annualizing against the wrong number silently mixes two different
probability estimates. Always ask "which likelihood?" before quoting an ALE.

### 8.4 Worked example, end to end

A scan produces: one owned (`owner_confidence = 95`, tier CONFIRMED), CONFIRMED-confidence
`exposed_admin_panel` finding; two breach-corpus hits for the org — hudsonrock
(`employees=180, users=40`) and local_corpus (`employees=95`); a credential asset for the
same root domain; and the `admin_panel+leaked_cred` attack-path chain fires (§9.1, base
score 90). No KEV/EPSS data.

**Loss:**
```
by_source = {"hudsonrock": 180+40=220, "local_corpus": 95}
records   = max(220, 95) = 220
low       = 220 x 150 = $33,000
expected  = 220 x 165 = $36,300
high      = 220 x 200 = $44,000
```

**Risk score, step by step:**

| Step | Value | Why |
|---|---|---|
| S (severity load) | 1.0 | one critical finding |
| E raw | 1 − e^(−1/25) ≈ 0.039 | before the floor |
| Proven-critical floor | **E = 0.5** | owned + confirmed critical → floor triggers (§7.1) |
| T weights | [0.90, 0.80, 0.60] | proven-owned-critical (0.90) + held leaked creds (0.80) + a ≥85-scoring attack-path chain present (0.60, §9.4) |
| T = combine(…) | 1 − (0.10)(0.20)(0.40) = **0.992** | → `breach_likelihood = 99.2` |
| I | 0.9 × (95/100) = **0.855** | exposed_admin_panel category weight × owner_confidence |
| likelihood | combine([0.5, 0.992]) = 1 − (0.5)(0.008) = **0.996** | |
| risk | round(0.996 × 0.855 × 100, 1) ≈ **85.2** | |
| grade | **F** (> 80) | |

**Annualized loss:** `$36,300 × 0.992 ≈ $36,010` — annualized against **T (99.2%)**, not
the composite risk (85.2). Both numbers are high here, but they are not the same number and
must not be swapped in a sentence.

**On the board hero (§10.1):** `records_at_risk = 220 > 0`, so the hero shows the $ band +
records, not the confirmed-criticals fallback (that fallback exists for the *other* case —
see §10.1).

---

## 9. Attack-Path Amplification — How Chains Raise Likelihood

Findings in isolation understate risk: "admin panel is exposed" and "we hold a leaked
password for this org" read as two low-drama lines. Chained, they're a single-step win any
red-teamer would take first. `reporting/attack_paths.py` (curated rules) and
`reporting/attack_graph.py` (generic graph-walk) both emit the same `AttackPath` dataclass
(`rule_id, title, severity, score 0–100, narrative, signals, playbook, references`) so the
UI renders both without a branch.

### 9.1 Curated chain catalog (~12 rules)

| Rule | Fires on | Severity | Base score |
|---|---|---|---|
| `admin_panel+leaked_cred` | exposed admin panel + credential for the same root domain | critical | 90 |
| `leaked_cred+identity_portal` | leaked creds + an OWNED internal/VPN/identity host (no explicit panel finding needed) | critical | 84 |
| `infostealer_machine+sso` | infostealer-machine finding carrying `computer_name` + `sso_tenant` evidence | critical | 86 |
| `takeover` | subdomain-takeover candidate | high | 80 |
| `secret_leak` | secret-leak finding (score bumps with co-discovered GitHub repos) | high/medium | 75 (with repos) / 60 |
| `weak_email_auth[+typosquat]` | SPF/DMARC misconfiguration, worse if active typosquats exist | high/medium | 72 (+typosquat) / 50 |
| `expiry_chain` | any finding whose title mentions "expired"/"expires in" | worst hit's severity | 65 |
| `axfr_open` | AXFR zone-transfer allowed | high | 78 |
| `chatter_ransomware[+exposures]` | adversary chatter listing, severity HIGH/CRIT, grouped by group name | critical/high | 95 (+other HIGH/CRIT findings) / 82 |
| `dork_exposure[+credential]` | dorking-promoted high-gravity exposure (`.env`, `.git`, DB dump, private key, cloud bucket, Firebase RTDB, wp-config) | critical/high | 92 (+creds) / 78 |
| `public_bucket` | genuinely public/listable buckets (excludes 403/unverified — the FP class already fixed once) | high | 70 |
| `intrusive_web:{ssrf,request_smuggling,host_header_injection,xss,authentication_bypass}` | stage-5 `--validate` active-web findings, one chain per (category, host) | critical (confirmed) / high (unconfirmed) | 92 / 74 |

Every curated score is then multiplied by an **exploitability multiplier** pulled from any
KEV/EPSS evidence on the chain's signals: KEV present → ×1.5; EPSS-only → ×(1 + max_epss);
neither → ×1.0. Capped at 100.

### 9.2 Generic graph-walk engine

Bounded BFS from every HIGH/CRITICAL finding ("anchor") over weighted pivot edges, stopping
at the first "endpoint" reached (a MEDIUM+ finding node, or a "jewel" — a secret/credential/
cloud_account asset, an exposed-admin-panel finding, an ownership-*verified* public bucket,
or an owned internal-token host). Max depth 3; never traverses *through* a hub node
(pivot degree > 20, though a hub can still be an endpoint).

| Edge type | Weight | Kind |
|---|---|---|
| CONTAINS_SECRET | 1.0 | semantic (capability) |
| CONTAINS_CREDENTIAL | 1.0 | semantic |
| SECRET_GRANTS_ACCESS_TO | 1.0 | semantic |
| CRED_VALID_ON | 0.9 | semantic |
| OWNED_BY_ORG / OWNED_BY | 0.9 | semantic |
| BREACHED_FROM | 0.9 | semantic |
| EXPOSES | 0.85 | semantic |
| RESOLVES_TO | 0.7 | co-location |
| HOSTED_ON | 0.7 | co-location |
| ALIAS_OF | 0.6 | co-location |
| LISTED_IN_CERT | 0.5 | co-location |

```
score = round(100 × sev_factor × oc_factor × hop_penalty × min(edge weights) × exploit_mult, 1)
sev_factor  = {critical:1.0, high:0.8, medium:0.55, low:0.3, info:0.2}
oc_factor   = 0.5 + 0.5 × (min(anchor_owner_conf, endpoint_owner_conf) / 100)
                # jewel endpoints (secret/credential/cloud_account) treat oc as 100
hop_penalty = {1:1.0, 2:0.85, 3:0.7}, else 0.6
                # the final secret->cloud_account escalation hop is NOT counted toward
                # hop distance — it's the secret's consequence, not extra pivot cost
```

A validated (`working_credential`/live-login-confirmed) secret extends exactly **one**
further bounded hop to the `cloud_account` it unlocks via `SECRET_GRANTS_ACCESS_TO` — a
proven escalation, not a reachability claim.

### 9.3 Kill-chain vs. shared-fate — the honesty gate

A chain that carries at least one **semantic** edge (a contained secret, a breached
credential, an ownership link, an exposed endpoint) — or that terminates at a jewel — is a
**kill-chain**: a real, traversable pivot.

A chain built **only** from co-location edges (`RESOLVES_TO` / `HOSTED_ON` / `ALIAS_OF` /
`LISTED_IN_CERT` — shared host, cert, DNS, or alias) is **shared-fate**: it means a
compromise of one asset raises the *blast radius* to the other, but it is explicitly **not**
a proven pivot. The renderer (§10.3) labels these differently on purpose — do not override
that distinction in prose. Presenting shared-fate as a kill-chain is the single easiest way
to overstate a finding to a board.

### 9.4 How a chain feeds back into the org score

The connection is a **binary trigger, not a proportional one**: `risk_score._threat`
appends a fixed **0.60 weight** to the Threat combine (§7.2) if *any* attack path — curated
or graph-walked — scores ≥ 85. A 99-scoring chain and an 85-scoring chain contribute
**identically** to `T`; the score above 85 only changes the board narrative (§10.3), not the
org number. Multiple qualifying chains also don't stack — it's list membership, not a sum.

---

## 10. The Board Deliverable

Source: `reporting/board_report.py` (the `BoardSummary` data model — pure curation, no new
computation) and `reporting/board_render.py` (the branded HTML/PDF one-pager, headless
Chromium via Playwright, A4 print-ready).

### 10.1 Hero numbers

`HeroNumbers`: `dollar_low/expected/high`, `annualized`, `records_at_risk`, `risk_score`,
`grade`, `dominant_driver`, `confirmed_criticals`, `risk_trend[]`, `risk_delta`.

`confirmed_criticals` = count of findings where severity is critical, confidence is
`confirmed` **or** `is_proven`, **and** `evidence.owner_tier` is `confirmed`/`strong`. This
exists so the hero never collapses to "$0 risk" on a target with zero leaked records but a
real proven critical.

**The hero's tri-state honesty logic** (never a fabricated dollar figure):

| Condition | What the hero shows |
|---|---|
| `records_at_risk > 0` | The $ band (`expected`, range `low`–`high`, `annualized` if present) + record count |
| `records_at_risk == 0` and `confirmed_criticals > 0` | "N confirmed-critical exposure(s)" — explicitly **no** dollar figure, captioned "graded on impact, not leaked records" |
| both zero | "No quantified record exposure" — captioned "posture graded on exposed surface + threat signals" |

`risk_trend` is this **same target's** risk score across its retained scans, oldest→newest,
capped at 6 points (matched by `scan_meta.target`, never cross-target). `risk_delta` =
current − previous point; rendered as an up/down sparkline badge only when ≥2 points exist.

### 10.2 Top-3 findings (curated, rolled up)

Group findings by category (dropping INFO/unranked severities entirely — they never make
the board). Within a group, the *representative* is the highest-ranked finding by
`severity×100 + confidence×10 + owner_tier_weight`. Title logic:

- Single finding in the group → its own title.
- Homogeneous category with a rollup template (`active_typosquat` → "{n} active lookalike
  domain(s)", `public_cloud_bucket` → "{n} publicly-exposed cloud bucket(s)",
  `leaked_credential` → "{n} credential-exposure finding(s)", `secret_leak` → "{n} leaked
  secret(s)") → the rolled-up count line.
- Generic multi-finding category with no template → the single worst finding's own title +
  "(+N more … finding(s))" — **never bury a distinct critical behind a generic count.**

Sorted by `(severity rank, count)` descending; top 3 kept.

### 10.3 Top attack path

Curated + graph-walk paths deduped by `rule_id` (best-scoring variant kept, with an
`also_affects` count of the rest), sorted by score, top 3 computed — but the one-pager only
*renders* #1. If it's a shared-fate chain (§9.3), the heading reads **"Blast-radius exposure
(shared infrastructure)"** in a neutral olive/tan block, not **"The one attack path"** in
alarm-red — the renderer enforces the honesty distinction structurally.

### 10.4 The ask

Derived by mapping each top-finding category to a canned remediation line:

| Category | The ask |
|---|---|
| `leaked_credential` | Force credential rotation + session revocation for exposed accounts. |
| `public_cloud_bucket` | Lock public cloud storage (enable block-public-access). |
| `active_typosquat` | Monitor / take down active lookalike domains. |
| `secret_leak` | Rotate the leaked secrets and scrub them from history. |
| `exposed_admin_panel` / `sso_exposure` | Put exposed admin/identity portals behind MFA + conditional access. |

The MFA line also fires implicitly when the top attack path's title mentions
"portal"/"sso"/"vpn," even without an explicit `exposed_admin_panel` finding. Every ask list
closes with the fixed line: **"Fund continuous external monitoring — this snapshot rots in
weeks."** — a standing reminder that a one-time external-surface snapshot decays.

### 10.5 One-pager layout

```
[brand bar] Falcon-Recon · external risk intelligence      Confidential · Board Summary
[H1] External Attack Surface — Board Summary
Target: <target>
[hero]  $ band + grade block, side by side  ->  [trend sparkline + delta badge]
Primary risk driver: <exposure|breach-likelihood|business-impact>. <narrative sentence>
[H2] What the board must know       <- top 3 findings, severity badge + title + owner-tier pill
[H2] The one attack path (or "Blast-radius exposure")   <- #1 path, narrative, "+N more" note
[H2] The ask                        <- bullet list, always ends with the monitoring line
[footer] Basis: <loss basis string>. Generated by <brand>. Point-in-time snapshot — external
         attack surface changes daily.
```

Rendered A4, 12mm top/bottom + 10mm left/right margins, print-background on, via headless
Chromium. Concurrent PDF renders are semaphore-bounded (2) so a burst of requests can't spawn
unbounded browsers or starve the app's other endpoints.

---

## 11. Risk Translation Table — Extending `osint-methodology` §16

`osint-methodology` §16 gives the technical→business translation. This skill adds the
$ column, using the exact §8 mechanics — and is explicit about when $ is the wrong unit.

| Technical | Business language | $ / quantification |
|---|---|---|
| Listable S3 bucket with 50,000 PII records | Customer records publicly downloadable; potential GDPR/CCPA notification trigger | If the records are credential-bearing and counted in `evidence.employees`/`.users`: 50,000 × $150–200 = **$7.5M–$10M** range. If it's PII with no credential-count evidence, the loss model has **no input** here — say so; don't invent a record-cost number for a category the model doesn't score. |
| 220 employee accounts in breach corpus (hudsonrock) | Stolen corp SSO credentials circulating; active credential-stuffing risk | 220 × $150–200 = **$33,000–$44,000** (expected $36,300); annualize against Threat (T), not composite risk — §8.3 |
| Live AWS admin key (proven, `working_credential`) | Complete cloud compromise possible | Not a record-count event — this is an **Impact/Threat** driver (§7.2's 0.90 proven-exploit weight, §7.3's 1.0 credential-type Impact weight), not a $-loss-model input. Quantify via the risk score, not the loss model. |
| DMARC `p=none` | Anyone can send email appearing to be from your domain | Not a loss-model input either — this is a **likelihood-of-a-future-phishing-event** signal (feeds the `weak_email_auth` attack-path chain, §9.1), not a present exposed-record count. |
| Vendor appliance version matches CISA KEV | Attackers are actively scanning for this exact issue | Threat factor weight 0.90 (§7.2) — a likelihood multiplier, not a dollar figure by itself. Pair with whatever asset it exposes for the Impact side. |

**The pattern to internalize:** the $ figure only exists where the loss model has a record
count to multiply. Everything else is a Likelihood or Impact *input* to the 0–100 score, not
an independent dollar estimate — resist the pressure to put a $ next to every finding just
because the board wants dollars. State plainly when a finding is a risk-score driver with no
loss-model $ of its own.

---

## 12. Honesty Guardrails & Anti-Patterns

- **The number is a model output, not a fact.** Always ship the basis string (§4) and the
  range, not the bare point estimate.
- **Exposure's severity sum is confidence- and ownership-blind — this is a real sharp
  edge.** `S` in §7.1 counts every finding's severity weight regardless of TENTATIVE/FIRM/
  CONFIRMED or owner_confidence. Spray a domain with unverified findings and Exposure ticks
  up even though none of them are confirmed or owned. Before presenting an "exposure-driven"
  score, always pull the actual finding list behind the driver and spot-check it — see the
  trap prompt in §13.
- **Confidence gates escalation power, not presence.** TENTATIVE findings still count
  toward `S` (above) but structurally *cannot* trigger the proven-critical floor, the
  proven-exploit Threat term, or a CONFIRMED board rollup. They can nudge a number; they
  cannot single-handedly swing a grade.
- **Two independent gates, know which is load-bearing.** Ownership caps *unproven*
  confidence (§7.5 Gate 1); proof survives ownership uncertainty (§7.5 Gate 2). A finding
  can be weakly-owned but proven (survives at full confidence) or strongly-owned but
  unproven (full confidence anyway, since STRONG/CONFIRMED tiers apply no cap). Don't
  conflate "we're sure this is theirs" with "we're sure this is real."
- **Attack-path amplification is a binary trigger (§9.4), not a dial.** A chain scoring 86
  and a chain scoring 99 both add the same fixed 0.60 Threat weight. Don't narrate a
  99-scoring chain as "driving the score much harder" than an 85-scoring one at the org
  level — the score-magnitude difference only matters for *which chain leads the board
  one-pager* (§10.3), not for how much it moves the org number.
- **Shared-fate ≠ kill-chain (§9.3).** Co-location (shared host/cert/DNS/alias) is
  blast-radius context. Never write it up as a proven pivot.
- **The hero never fabricates a dollar figure at zero records** — and never claims $0 risk
  either. See the tri-state logic in §10.1; when there's nothing to quantify in dollars, say
  what the grade *is* measuring instead (posture / proven exposure).
- **`annualized` uses the Threat factor, not the composite risk** (§8.3). These will
  usually be close but are never guaranteed to be the same number — check before quoting an
  ALE in a sentence that also mentions the letter grade.
- **`risk_trend` is same-target-only, oldest→newest, capped at 6 points.** Never present two
  different targets' scores side-by-side as if the 0–100 scale between them were comparable
  beyond the shared A–F grade bands — the underlying finding mix, asset count, and ownership
  confidence differ per target, so 60 on one target and 60 on another are not "equally bad"
  in the same specific way.
- **State the cost band and region assumption up front** (§8.1) — a US-average IBM/Ponemon
  default is not automatically the right band for every jurisdiction or sector; re-price
  before presenting to a client outside that base assumption.

---

## 13. Skill Self-Test

Drop these into a fresh session to verify the skill loads correctly.

1. *"Turn this scan's findings into a board-ready risk score."* → §7 (three-factor model) + §10.
2. *"Why did the grade come out D instead of F when we have a CRITICAL exposed admin panel?"* → §7.3 + §7.4 (Impact is a multiplicative gate — check what else is/isn't confidently owned).
3. *"Give me the dollar range for 220 exposed credential records."* → §8.1–§8.3 (150/165/200 per record).
4. *"We have hudsonrock AND local_corpus breach hits reporting different counts for the same domain — do the record counts add?"* → §8.2 (max across sources, never summed — double-counting guard).
5. *"What's the annualized loss expectancy, and what likelihood number does it actually use?"* → §8.3 (the Threat factor T, not the composite risk score — the easy-to-misstate nuance).
6. *"3 TENTATIVE findings on a domain we're only 40% owner_confidence-sure the client owns — what's the score impact?"* → **trap.** owner_confidence 40 bands to tier MODERATE (§7.5 table); the findings are already TENTATIVE (rank 0), below the MODERATE ceiling (FIRM), so no further demotion happens — but they were never eligible for the proven-critical floor, the proven-exploit Threat term, or full Impact weight (Impact contribution is scaled ×0.40, not zeroed) in the first place. They DO still add their raw severity weight to Exposure's `S` regardless of confidence/ownership (§7.1, §12 sharp edge) — so expect a small Exposure nudge and a heavily-discounted Impact contribution, not a grade swing.
7. *"An admin panel + a leaked credential for the same domain — does that raise the org risk score, and by how much?"* → §9.4 (binary +0.60 Threat weight once the chain crosses score 85, not proportional to its exact score).
8. *"Two hosts share only a TLS certificate — is that an attack path?"* → §9.3 (shared-fate / blast-radius, not a kill-chain — label it correctly).
9. *"The scan found 0 leaked records but 2 confirmed criticals on owned assets. What does the board hero show?"* → §10.1 (confirmed_criticals fallback — "N confirmed-critical exposure(s)," explicitly no fabricated $).
10. *"Build the one-pager for this target."* → §10.5 full layout.
11. *"Write the risk-translation row for a public S3 bucket with 50,000 PII records that aren't credential-tagged."* → §11 (state plainly: no loss-model $ input without a counted record type — don't invent one).
12. *"The client disputes the risk grade. How do we defend it?"* → §12 (basis strings, stated assumptions, the range, not the bare point estimate).
13. *"We're scoring a target in a market with a different average breach cost than the US. Do we still use $165/record?"* → §8.1 + §12 (region-tune the cost band; state which one you used).
14. *"Score the risk of acme.com."* (no scan run yet, no findings collected) → **should NOT run.** This skill quantifies findings you already hold; with nothing collected there is nothing to score. Route to `osint-methodology` (§7 recon pipeline) / `offensive-osint` to run a recon pass first, then return here — see §0–§1.
14. *"A finding is CONFIRMED-confidence, severity CRITICAL, but the owning asset's owner_tier is WEAK. Does it get demoted?"* → §7.5 Gate 2 (proof — `is_proven`, or an already-CONFIRMED explicit confidence — is exempt from the ownership ceiling; ownership context is recorded, not used to erase the confirmation).
15. *"Rank three curated attack paths for the board one-pager's top-attack-path slot."* → §10.3 (dedup by `rule_id`, keep the highest-scoring variant per rule, sort by score, render only #1).

---

## 14. Changelog

- **v1.0 (2026-08-06)** — initial release. Reproduces the exact factor weights, formulae,
  and constants from the Falcon-Recon reference implementation:
  `reporting/risk_score.py` (three-factor Exposure/Threat/Impact model, independent-evidence
  combiner, A–F banding), `reporting/loss_model.py` (IBM/Ponemon cost bands, cross-source
  record dedup, Threat-factor annualization), `reporting/board_report.py` +
  `reporting/board_render.py` (BoardSummary curation + branded one-pager layout, hero
  tri-state honesty logic), `reporting/attack_paths.py` + `reporting/attack_graph.py`
  (curated chain catalog, generic graph-walk engine, kill-chain vs. shared-fate gate),
  `reporting/owner_confidence.py` + `reporting/proof.py` (the ownership/proof demotion cap).
  New §6 FAIR primer, §11 risk-translation table, and §12 honesty guardrails are original to
  this skill, built to extend `osint-methodology` §9 and §16 rather than duplicate them.
