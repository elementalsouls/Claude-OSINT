---
name: osint-methodology
description: "Comprehensive OSINT methodology for external red-team operations and authorized attack-surface assessments. Covers the 6-stage recon pipeline (seed → asset expansion → enrichment → exposure analysis → convergence → operator-armed active validation) with connector-resilience and stage-vs-gating discipline, asset-graph discipline, severity rubric, confidence upgrade workflows, time budgeting, identity-fabric mapping, breach×identity correlation with per-person identity dossiers, detectability tagging, detection-aware probing, WAF/CDN bypass, vulnerability prioritization, phishing infrastructure planning, bug bounty submission, and client deliverable templates. Use when planning or executing reconnaissance against authorized targets, mapping an organization's external attack surface, investigating a person/entity, or producing client deliverables."
version: 2.3
triggers:
  - external recon
  - external red team
  - red team external
  - attack surface management
  - attack surface mapping
  - ASM
  - perimeter recon
  - target reconnaissance
  - bug bounty recon
  - asset discovery
  - footprint
  - attack path
  - identity fabric
  - SSO discovery
  - IdP fingerprinting
  - tenant fingerprinting
  - M365 enumeration
  - Microsoft 365 recon
  - API discovery
  - GraphQL introspection
  - mobile recon
  - APK analysis
  - cloud bucket enumeration
  - breach correlation
  - secret leak hunt
  - origin discovery
  - CDN bypass
  - WAF bypass
  - vulnerability prioritization
  - CVE prioritization
  - EPSS
  - CISA KEV
  - phishing infrastructure
  - pretext development
  - bug bounty submission
  - responsible disclosure
  - client report
  - exec summary
  - risk translation
  - confidence upgrade
  - time budget
  - engagement profile
  - asset triage
  - detection-aware probing
  - back-off strategy
  - OSINT methodology
  - open source intelligence
  - target profiling
  - OSINT workflow
  - recon methodology
  - threat actor investigation
  - attribution
---

# OSINT Methodology — External Red-Team Edition

## 0. When to Use / When NOT

**Use this skill when:** planning or executing authorized external recon (red team, bug bounty, ASM); mapping an org's attack surface; investigating a person/entity/threat-actor; producing client deliverables.

**Do NOT use this skill when:** the user needs active exploitation, post-exploitation, or malware dev; blue-team/detection content; or the target's authorization is unclear — surface the scope question first.

---

## 1. Authorization & Legal Posture

Intended for assets the operator owns or has **written authorization** to assess.

**Soft scope check** — when authorization isn't established, ask once:
> *"Quick scope check: is this a target you own or have written authorization to assess? I want to make sure we stay on the right side of the engagement boundary."*

Once asserted, don't re-ask. If the engagement type is stated ("pentest of acme.com under contract"), proceed.

**Always-on guardrails:**
- Never weaken auth, rate limits, or safety controls on the target side.
- No destructive probes (SYN scans at line-rate, masscan, fuzzing) outside explicit `--aggressive` mode.
- Never paste real PII, credentials, session tokens, or API keys into cloud-hosted LLMs.
- Never act against assets outside documented scope, even "obviously related" ones.

---

## 2. Confidence Levels

Every assertion carries a confidence level.

| Level | Meaning |
|---|---|
| **TENTATIVE** | Plausible from indirect evidence; unverified. Snippet-only dork match, email pattern inferred from name, single passive-source subdomain. |
| **FIRM** | Directly observed, uncorroborated. Subdomain resolves; Shodan banner returned; CT-log entry. |
| **CONFIRMED** | Multiple independent corroborations OR directly verified. Live-validated token; bucket listable; three-source subdomain convergence. |

**Rule of three for attribution:** 3 independent weak signals, OR 1 strong + 1 weak. Never single-source attribute.

### 2.1 Confidence Upgrade Workflows

| Asset type | TENTATIVE → FIRM | FIRM → CONFIRMED |
|---|---|---|
| Subdomain | ≥2 passive sources OR DNS resolves | Serves on a standard port AND banner/cert returned |
| IP | ≥2 sources (passive DNS, ASN, Shodan) | TCP SYN-ACK or ICMP reply |
| WebApp | URL extracted but not yet hit | HTTP returns 2xx/3xx/4xx AND content-length > 0 |
| Email | Name-pattern inferred OR snippet-only | Listed in Hunter/IntelX/breach, OR SMTP 250 (abort at DATA) |
| Bucket | Permutation candidate + HEAD returns 200/301/403 (exists) | GET listing = CONFIRMED |
| Credential / secret | Regex match in captured text | Read-only validator returns success (scope + account-ID documented) |
| Person | Name from single source | Confirmed by second independent source |
| SSO tenant | OIDC discovery endpoint returns metadata | Tenant GUID extracted AND domain ties back via MX/autodiscover/SP record |

Default reporting posture: never claim CONFIRMED without explicit corroboration. When in doubt, downgrade.

---

## 3. Output Format

Each finding uses this schema (drops cleanly into asset-management tools):

```
Finding:
  id:          <stable hash or UUID>
  module:      <technique that discovered it>
  asset_key:   <typed key, e.g. sub:api.example.com>
  category:    <e.g. SECRET_LEAK, OPEN_GRAPHQL_API, SSO_EXPOSURE>
  severity:    <info|low|medium|high|critical>
  confidence:  <tentative|firm|confirmed>
  title:       <one-line summary>
  description: <2-5 sentences>
  evidence:
    url:       <where found>
    timestamp: <UTC ISO8601>
    sha256:    <hash of any downloaded artifact>
    raw:       <truncated to 2 KiB>
  references:  [<CVE-ID, advisory URL, vendor doc>]
  remediation: <action the asset owner can take>
```

Always use UTC timestamps.

---

## 4. Source Hygiene & Citations

For every artifact: **URL + UTC timestamp + SHA-256 + tool version + run_id**.

- Hash all downloads with SHA-256. Screenshot in PNG.
- Raw HTTP captures capped at 2 KiB body. JSONL logs, one line per event.
- Separate evidence read-only from working copies; never edit captured artifacts.
- Prefer durable references (CVE, ATT&CK technique ID, RFC). If ephemeral, archive first (archive.today, Wayback SavePageNow).

---

## 5. Do NOT

- Do NOT paste creds, session tokens, real PII, or unique pivots into cloud LLMs. Use local models for sensitive analysis.
- Do NOT assume vendor labels are ground truth (TRM, Chainalysis, Arkham can disagree).
- Do NOT assert ownership from a single signal (favicon hash, shared NS, shared CT issuer — each is a hypothesis).
- Do NOT run fuzzing, SYN scans, masscan, or `nuclei fuzzing/*` outside explicit `--aggressive` mode.
- Do NOT use a credential validator for anything except read-only verification.
- Do NOT mirror-image the threat actor. Separate capability from intent and sponsorship.
- Do NOT escalate when you hit active defenses — back off and document (§6.4).

---

## 6. OpSec

### 6.1 Sock Puppets

Build posting history, age the account, use a separate browser profile. Persona generation: Fake Name Generator, This Person Does Not Exist. Browser isolation: Firefox Multi-Account Containers. Disposable numbers for SMS verification. Audit every extension before install. Maintain chain-of-custody: timestamp every action, hash every artifact.

### 6.2 Detectability Tagging

Tag every operation so you can reason about the trail you leave.

| Tag | Examples |
|---|---|
| **Low** | Passive Shodan InternetDB; crt.sh; Wayback CDX; SecurityTrails PDNS; Hunter.io; HTTP HEAD on public buckets; `getuserrealm.srf`; OIDC metadata fetch. |
| **Medium** | `GetCredentialType` user-enum; Okta `/api/v1/authn` user-enum; credential validation; AWS `sts:GetCallerIdentity`; Swagger/GraphQL probes; targeted favicon-hash + JARM fingerprinting. |
| **High** | Active port scans (naabu/masscan/nmap); Nuclei full runs against production; subdomain brute-force at scale; SMTP `RCPT TO` enum; web fuzzing. |

Defaults: passive by default. Active probes only when (a) explicitly authorized, (b) within agreed windows, (c) operator aware of log volume.

### 6.3 Validator Discipline

When you find a credential in the wild, confirm liveness with **read-only validators only** (`/me`, `auth.test`, `sts:GetCallerIdentity`). Never create, modify, delete, or send. Record `checked_at` UTC + truncated response + scope/account-ID. Concrete validator endpoints for 9 providers live in `offensive-osint` §23.

### 6.4 Detection-Aware Probing

**Signs you've been detected (escalating severity):** 429 / `Retry-After`; captcha interstitials; WAF block page; status-code drift (200→403 from your IP only); banner change; NXDOMAIN rollback; honeypot bait (credentials that don't validate); direct contact.

**Back-off ladder:**
1. Halve concurrency; add 2–10s jitter.
2. Stop hitting the triggering path; pivot to a different module.
3. New User-Agent / TLS fingerprint.
4. Rotate egress IP (residential proxy, different cloud region).
5. Pause 1–24 hours.
6. If WAF block / status drift / direct contact: **stop and consult the engagement lead.**

---

## 7. External Red-Team Recon Pipeline

Six sequential operational stages, then reporting as a post-stage; modules within a stage can run concurrently.

| Stage | What you do |
|---|---|
| **1 — Seed Discovery** | WHOIS, ASN enum (HE BGP Toolkit, RIPEstat), DNS records (A/AAAA/MX/TXT/NS/SOA/CAA), CT history (crt.sh, Censys). |
| **2 — Asset Expansion** | Subdomain enum (passive first → permutations → brute); cloud bucket permutation; typosquat generation; Wayback CDX; mobile app discovery; DNS walking; LinkedIn employee enum; org/subsidiary footprint (reverse-WHOIS, corporate registries). |
| **3 — Enrichment** | First active web traffic + identity signal: port/service (Shodan InternetDB → naabu); TLS handshakes (cert chain, JARM, favicon mmh3); WAF/CDN inference; origin discovery; security headers; email harvest; email security audit; GitHub dorking; JS deep analysis; SSO/IdP fingerprinting (passive tier); API discovery (passive classifier); secrets sweep (Postman, Stack Exchange); vendor product fingerprinting; container/CI-CD/cloud-native exposure; job posting harvest. |
| **4 — Exposure Analysis** | Bulk active probing: Nuclei always-on checks; TLS deep audit; breach × identity correlation → SSO_EXPOSURE findings; targeted misconfig probes (`.git/config`, `.env`, `/actuator/env`, `/_cat/indices`, `/console`); vulnerability prioritization (CVE × EPSS × KEV × POC). |
| **5 — Convergence** | One bounded recursion round over hostnames/assets surfaced by Stages 2–4 (re-mutate, re-probe — not an open-ended crawl); cloud-footprint follow-up (e.g. account-ID extraction from a leaked cloud access key); supply-chain claimability check (internal/scoped package names confirmed unclaimed on the public registry). |
| **6 — Active Validation** | Hard-gated, operator-armed, engagement-authorized proof tier — **default OFF**. Live credential submission (default-cred + breach-credential replay) against owned panels; active cloud/container/API/SSO confirmation; host-header injection / blind-SSRF; HTTP request-smuggling differential; injection-payload confirmation (e.g. XSS); JWT-forge auth-bypass differential. Every module here needs explicit arming plus a per-target scope-confirmation step on top of engagement authorization (§1). |
| **Reporting** *(post-stage)* | Risk scoring per finding; asset graph export; client-facing report (exec summary + technical detail + remediation); reproduction package; bug bounty submission if applicable. |

### 7.1 Pipeline Priority Order (highest signal density first)

1. **Breaches** — HudsonRock Cavalier + HIBP + DeHashed. Highest ROI; often yields plaintext corp SSO creds.
2. **GitHub recon** — code-search dorks. Fastest path to AWS keys, Slack tokens, JWT secrets.
3. **Nuclei misconfig sweep** — exposed admin panels, CVEs with public POCs.
4. **Cloud buckets** — listable = CRITICAL.
5. **Ports** — Shodan InternetDB first. VPN concentrators, RDP, Jenkins, Elasticsearch are high-value pivots.
6. **Email OSINT** — feeds breaches; feeds phishing list.
7. **Web tech / WAF / screenshots** — triage thousands of hosts.
8. **Wayback** — archived JS for hard-coded keys; removed admin/dev paths.
9. **DNS deep + email security** — SPF/DMARC gaps enable spoofing; TXT tokens reveal SaaS tenancies.
10. **Certificates → TLS** — CT timeline catches forgotten subdomains; weak ciphers = cheap findings.
11. **ASN + reverse DNS** — corporate IP space hosts unadvertised infra.
12. **Typosquats** — registered = finding; unregistered = phishing shortlist.

### 7.2 Time Budgeting & Engagement Profiles

| Stage | Small org (<100) | Medium (100–1K) | Large (1K+) |
|---|---|---|---|
| 1. Seed | 30 min | 30 min | 30 min |
| 2. Asset expansion | 1–2 h | 2–4 h | 4–8 h |
| 3. Enrichment (per 100 alive webapps) | ~1 h | ~1 h | ~1 h |
| 4. Exposure analysis | 1–3 h | 3–6 h | 6–12 h |
| 5. Convergence | 15–30 min | 30–60 min | 1–2 h |
| 6. Active validation *(if armed)* | 30 min–1 h | 1–2 h | 2–4 h |
| Reporting | 2–4 h | 4–8 h | 1–2 days |

**Profiles:** 1-hour rapid (Stages 1–2 passive + breach + exec summary) · 4-hour focused (adds email harvest, SSO fingerprinting, typosquats) · 1-day standard (full Stages 1–5 in priority order) · 1-week deep (all of standard + JS deep, mobile, cloud-native, vendor product, package registry; Stage 6 only under explicit written engagement authorization) · ongoing weekly diff (re-run Stages 1–3, diff against baseline).

**Abort conditions:** scope mismatch after Stage 1; near-zero attack surface after Stage 2 — meaning the *union* of every connector in a category came up empty, not just one source (§7.3); WAF/detection signs hit during any stage (§6.4).

### 7.3 Connector Resilience

No single data source should gate a whole category. Query interchangeable backends per category as a **union**, not a single call — CT logs (crt.sh, Censys, certspotter), passive DNS (multiple providers), host-intel (Shodan, Censys, Netlas), reverse-WHOIS (multiple vendors) — with per-source health tracking and short-TTL result caching underneath the union.

- A rate-limited or dead source degrades that category's yield; it must never silently zero it out.
- Log the failure as a per-source health event, not as "category empty." The Stage-2 abort decision (§7.2) reads the union result, never one source's status.
- Cache each source's results with a TTL short enough to stay fresh but long enough to survive that source's rate-limit window — a re-run mid-engagement shouldn't re-spend a quota you already burned.

This generalizes the crt.sh-style fallback discipline to every category, not just certificates: one dead API is a coverage-degradation event to note and route around, not a hole in the map.

### 7.4 Stage Number ≠ Safe-by-Default

A module's stage number tells you *when* it runs, not *whether it's passive*. Always check the module's own gating flag before treating a stage placement as a detectability tier.

| Technique | Stage | What actually gates it |
|---|---|---|
| IDOR/BOLA differential confirm | 3 (enrichment) | its own `--active`/`--deep` flag — not the stage boundary |
| Active user-enumeration oracle (IdP) | 3 (enrichment) | its own `--deep` flag |
| Bounded 401/403 bypass / param mining | 4 (exposure) | rate-limited by default; ships un-gated at this stage |
| Credential replay / default-cred submission | 6 (active validation) | explicit arming + scope confirmation |
| JWT-forge auth-bypass differential | 6 (active validation) | explicit arming + a second confirmation flag |

Stage 6 is the one place the pipeline is explicitly all-intrusive-by-design (default OFF, operator-armed) — but stages 1–5 are only *mostly* passive-to-low-intrusion, and "mostly" hides real exceptions like the two Stage-3 rows above. Detectability is tagged per-technique (§6.2), never inferred from the pipeline stage a technique happens to sit at.

---

## 8. Asset Graph Discipline

Every discovery is a **typed asset** in a graph, not a free-floating string.

### 8.1 Asset Taxonomy

| Category | Types |
|---|---|
| DNS / Network | `domain`, `subdomain`, `ip`, `netblock`, `asn` |
| Service | `port`, `service`, `certificate` |
| Identity | `email`, `person`, `credential` |
| Code / Config | `repo`, `secret` |
| Cloud / Storage | `bucket`, `firebase_project` |
| Web | `webapp`, `wayback_endpoint`, `api_endpoint`, `api_spec`, `graphql_schema` |
| Mobile | `mobile_app`, `deep_link`, `exported_component` |
| Phishing | `typosquat_domain` |
| SaaS | `postman_collection`, `postman_workspace`, `postman_api_key`, `stack_post`, `saas_public_surface` |

Every asset carries: `type`, `key` (typed dedup id), `value`, `sources[]`, `confidence`, `first_seen`, `last_seen`, `attrs{}`.

**Discipline:** create the asset first, then attach the finding. Dedup by key. `sources[]` must list every source. Confidence is per-source, then aggregated.

### 8.2 Asset-Level Triage Rules

**WebApp priority (highest first):** auth (`auth.`, `login.`, `sso.`) → admin paths → dev/staging hosts → API (`api.`, `gateway.`) → customer-facing (`portal.`, `app.`) → marketing.

**Email priority:** exec (CEO/CFO/CISO) → IT/helpdesk/security → dev/engineer/DBA → sales/HR/finance → generic role accounts.

**Repo priority:** recently pushed (last 30 days) > stale; public with target name in description > code-only; mentions `prod`/`internal`/`secret` in name → HIGH priority despite being public.

---

## 9. Findings Rubric & Severity Mapping

### Severity Anchors

| Severity | Anchor |
|---|---|
| **CRITICAL** | Pre-auth code execution; confirmed valid credentials; listable production data; fundamental trust violations. Examples: `.env` exposed, listable S3 bucket with PII, live-validated AWS admin key, open Kubernetes API with anon-auth, ≥10 employees in breach corpus + tenant identified. |
| **HIGH** | Significant exposure with clear escalation path; high-value info disclosure. Examples: public secret in GitHub repo, subdomain takeover possible, reflected CORS with credentials, exposed Jenkins/phpMyAdmin admin UI, open GraphQL introspection on prod, DMARC `p=none`. |
| **MEDIUM** | Info disclosure, hardening gaps, brute-force exposure. Examples: missing HSTS/CSP, Apache `/server-status`, internal IP/hostname in JS, schema leakage in error pages, `android:allowBackup=true`, wildcard CORS on user-data API, Slack webhook leaked. |
| **LOW** | Cosmetic or marginal gaps. Examples: missing `X-Frame-Options`, `.DS_Store` exposed, Stripe **test** key, cert pinning missing, outdated WordPress (no known active exploit). |
| **INFO** | Worth recording; no immediate action. Examples: `robots.txt` reveals paths, private bucket locked down, DNSSEC not enabled. |

### Severity Escalation Rules

- HSTS missing on auth/login/SSO/admin path → **MED → HIGH**.
- Wildcard CORS + credentials header → **MED → HIGH**.
- Endpoint interest score ≥70 (companion skill §20) → at least **HIGH**.
- Domain breach ≥10 employees → **CRITICAL** regardless of stale-data caveats.
- Vendor product version matches CISA KEV → **CRITICAL**.

---

## 10. Pivot Modes & Scale Tactics

| Aspect | Investigative Mode | Offensive Recon Mode |
|---|---|---|
| Probing rate | Slow, single-threaded, blends with traffic | Bursts, parallel, rate-limited per provider |
| OpSec posture | Sock-puppet only; never reveal investigator | Engagement persona; team may notify SOC |
| Evidence handling | Court-grade chain of custody | Engagement-grade; same hash/timestamp discipline |
| Reporting format | Narrative + sourced timeline | Per-asset findings + remediation + reproduction |

**Scale tactics:**
- **Small (<100):** Individual-account focus. One exec/CFO compromise often hands you the keys. Deep on every email + every identity-fabric finding. Check founders' personal GitHub orgs.
- **Medium (100–1K):** Balanced enumeration. Full pipeline at standard depth. LinkedIn priority by role. Check both app stores.
- **Large (1K–10K):** Breadth-first; automation for asset discovery; manual triage on findings only.
- **Very large / conglomerate:** Scope pruning is the most important step. Brand-pivot map first. Breach corpus and systemic posture findings (DMARC gaps, SSO_EXPOSURE breadth) dominate over individual accounts.

---

## 11. Implementation: Companion Skill Pointers

The following modules have full implementation detail — probe paths, wordlists, curl one-liners, regexes, and scoring rubrics — in `offensive-osint`. This skill defines *what to do*; that skill defines *how to do it*.

**Identity Fabric Mapping** (`offensive-osint` §22) — Microsoft Entra (OIDC metadata, getuserrealm.srf, GetCredentialType), Okta (slug derivation, /api/v1/authn), ADFS, Google Workspace, generic OIDC (Auth0/Keycloak/Ping/OneLogin/Duo), SAML metadata (5 paths), AWS account-ID extraction, M365 deep surface (Teams federation, SharePoint, OneDrive, OAuth client_id, device-code phishing check, Power Platform).

**API & Auth-Map** (`offensive-osint` §16.1–16.2, §20) — 28-path Swagger/OpenAPI wordlist; 13-path GraphQL wordlist; introspection POST body; field-suggestion enumeration when introspection disabled; endpoint interest score 0–100 rubric.

**JavaScript Deep Analysis** (`offensive-osint` §13 pattern) — sourcemap detection; secret catalog over JS bodies and `sourcesContent[]`; three-tier endpoint-extraction regex; internal-host leakage patterns; Next.js manifest parsing.

**Mobile Attack Surface** (`offensive-osint` §21) — Android/iOS app discovery; ownership confidence 0–100 scoring; APK static analysis; manifest misconfig findings; Firebase canonical probe.

**Cloud Attack Surface** (`offensive-osint` §16.8) — S3/GCS/Azure bucket permutation (6 prefixes × 15 suffixes); HEAD → GET probe technique; cloud-native fingerprints (Lambda, Cloud Run, Azure Functions, Vercel, Netlify, Workers); K8s/etcd/kubelet/container registry exposure.

**WAF / CDN Bypass & Origin Discovery** (`offensive-osint` §16.15) — DNS history pivot; cert SAN pivot; favicon mmh3 + JARM clustering; direct IP probe with Host header; mail/ftp/cpanel exception; error page leakage; email-header bounce trick; confidence rules.

**Vulnerability Prioritization** (`offensive-osint` §29.2) — NVD, EPSS, CISA KEV, ExploitDB, Metasploit, InTheWild.io, Trickest CVE→POC; 9-signal scoring rubric → P0/P1/P2/P3 tiers.

**Phishing Infrastructure** (`offensive-osint` §16.14 for email security) — typosquat shortlists via dnstwist; subdomain takeover for trusted-domain phishing; email spoof feasibility matrix (SPF × DMARC); pretext development from OSINT (job titles, recent events, vendor relationships, GitHub commits).

---

## 12. Breach × Identity Correlation

Highest-ROI single technique for external red teams. Run on every engagement.

| Source | Tier | Notes |
|---|---|---|
| Hudson Rock Cavalier | FREE | Infostealer-log corpus; very high signal for corp SSO creds. |
| Have I Been Pwned | Free + paid | Domain-wide existence + Pwned Passwords (k-anonymity). |
| DeHashed | Paid | Per-record searchable API. |
| IntelX | Free + paid | Aggregator; phonebook search. |

**Domain-level severity:** ≥10 employees compromised → CRITICAL; 1–9 → HIGH; ≥1 end-user → MEDIUM; domain seen with 0 named accounts → INFO.

**SSO_EXPOSURE:** after Stage 3 identity-fabric mapping AND breach lookups, intersect discovered IdP tenant domain with breach corpus. Non-empty intersection → `SSO_EXPOSURE` finding, severity CRITICAL. Evidence: tenant ID + product + employee count + per-account source.

**Stealer log discipline:** encrypt at rest; SHA-256 every artifact; never paste plaintext passwords into cloud LLMs; maintain chain of custody; redact passwords in client reports by default (offer encrypted credential bundle separately).

### 12.1 Per-Person Identity Dossier

Domain-level breach counts (above) tell you the org is exposed. The **identity dossier** tells you *who* — join every discovered PERSON (name, role, seniority, target score from person-enum/LinkedIn dorking) to any leaked CREDENTIAL matched by email, producing one ranked card per human. This is the step that turns a breach headcount into a spear-phish / credential-stuffing target list.

**The join key is the email address, not the name.** A PERSON asset is name-keyed and usually carries no email on its own — resolve name→email via the org's *confirmed* email-format pattern (Hunter-derived or independently observed) before joining. Never join off a guessed pattern from a single sample.

| Field | Source |
|---|---|
| Role / seniority / target score | person-enum / LinkedIn dorking |
| Email — `known` (directly observed) or `pattern` (name run through the org's confirmed format) | email OSINT / org email-format pattern |
| Every credential tied to that email | breach dumps, stealer logs, GitHub/JS basic-auth leaks, breach-replay hits |
| Risk tier | derived, see below |

**Risk tiering:** a breached high-value mailbox (exec/IT/admin, target score ≥80) with ≥1 confirmed credential is the worst case.

| Target score | Credential(s) leaked | Risk |
|---|---|---|
| ≥80 (exec/IT/admin) | ≥1 | **CRITICAL** |
| any | ≥1 | **HIGH** |
| ≥80 | 0 | **MEDIUM** |
| <80 | 0 | **LOW** |

**Orphan credentials:** a leaked email that ties to no discovered person is still a lead, not a dead end — surface it separately, sorted by breach count. It just hasn't been named yet; a further person-enum pass may resolve it.

**Confidence:** the join is only as strong as the email resolution. `known` email carries the credential's own confidence (§2); a `pattern`-resolved email stays TENTATIVE for attribution purposes until the address itself is independently observed (e.g. it appears verbatim in the breach record, or Hunter.io returns it directly) — never report a pattern-resolved dossier as CONFIRMED off the pattern alone.

Run this pass any time Stage 3 person-enum/email-OSINT output and a breach lookup (domain-level or replay) both exist for the engagement — it is a join over data already collected, not new collection, so there's no reason to skip it. Use the output to decide who gets the phishing pretext first (§13) and who's the highest-value candidate for the read-only credential check (§6.3).

---

## 13. Specialty OSINT Domains

**Cryptocurrency** — track flows with Cielo, TRM, Arkham, MetaSleuth. L2/rollup: start at L1 bridge events; use L2 explorers for in-rollup activity. Caution: bridges mint/burn (avoid 1:1 flow assumptions); MEV paths create false direct trails.

**Image / Video / Chronolocation** — reverse image search (Google Lens, Yandex, TinEye); EXIF via ExifTool; forensics via Forensically/FotoForensics; geolocation via foreground+background landmark analysis, Street View, Overpass Turbo, PeakVisor. Shadow analysis: SunCalc, ShadeMap. Satellite: Google Earth Pro historical, Sentinel Hub.

**Threat Actor Investigation** — scoping: actor hypothesis from CERT/vendor reports → IOC harvest → infra mapping via CT log pivots, shared hosting, NS reuse, HTML fingerprints → artifact profiling (PDB paths, Rich headers, SSDEEP/YARA) → social pivots (handles, code snippets, job posts). Attribution discipline: rule of three; separate capability from intent; prefer durable pivots (code-signing certs, build path idioms) over ephemeral (resolving IPs). Russia pivots: EGRUL, Rusprofile, hh.ru, VKontakte. China pivots: gsxt.gov.cn, Tianyancha, ICP filings, Weibo, Zhihu.

**People & Social Media** — username enumeration: WhatsMyName, Sherlock, Maigret. Face search: PimEyes, Exposing.ai. Social graph: Maltego, SocialBlade. Bluesky: DID resolution via `bsky.social/xrpc/`, firehose via Firesky. Mastodon: WebFinger discovery; FediSearch cross-instance.

---

## 14. Anti-Patterns & Common Failure Modes

- **Single-source attribution.** Rule of three.
- **Trusting vendor labels as ground truth.** Labels are hypotheses.
- **Favicon-hash = ownership.** Shared infra, shared CMS, shared CDN all produce matches.
- **Snippet-only dork as CONFIRMED.** TENTATIVE until visited.
- **Pasting real PII / creds into cloud LLMs.** Local models only.
- **Mirror-imaging the threat actor.** They don't think like you.
- **Attribution by IP geolocation.** VPNs and residential proxies exist.
- **Ignoring CT-log lag.** Absence ≠ doesn't exist; lag can be minutes to hours.
- **Counting Wayback as "the site at time T."** Best-effort; many requests fail.
- **Letting the asset graph carry untyped strings.** Every discovery is an asset.
- **Skipping the scope check.** Ask once when in doubt.
- **Forgetting UTC.** Local time creates correlation bugs.
- **Continuing to probe after a WAF block.** Back off (§6.4).
- **Skipping confidence-upgrade documentation.** TENTATIVE needs a path to CONFIRMED.
- **Treating exec-summary as an afterthought.** Plan deliverables at engagement start.

---

## 15. Bug Bounty Submission & Responsible Disclosure

**Platforms:** HackerOne (CVSS-based) · Bugcrowd (VRT: P1–P5) · Intigriti · YesWeHack · HackenProof (crypto-focused) · Open Bug Bounty (XSS/SSRF only) · `/.well-known/security.txt` for unprogrammed targets.

**Report structure:**
```
Title: [Severity] [Component] Brief description
Summary: 2-3 sentences — what and why it matters.
Steps to Reproduce: numbered, copy-pasteable, URL + payload + expected vs actual.
Proof of Concept: screenshot or sanitized HTTP request/response.
Impact: what data/users/functions are at risk.
Severity: CVSS v3 vector + score + 1-sentence justification.
Remediation: concrete, actionable recommendation.
```

**Unprogrammed CVD:** check `security.txt` → `security@<target>` → WHOIS abuse contact → CERT/CC. Standard 90-day window before public release. **Never:** include others' PII, post publicly before window expires, or escalate via social media first.

---

## 16. Client Deliverable Templates

**Executive summary structure:** engagement metadata → top 3–5 findings (title + business impact + remediation effort) → postural observations (email security, identity fabric, cloud surface, mobile) → aggregate metrics (assets, findings by severity, live creds confirmed) → recommended next steps with timeline.

**Per-finding report card:** title + severity + confidence + asset key + UTC timestamp → description → evidence (URL + tool + screenshot + raw HTTP + SHA-256) → reproduction steps → business-language impact → remediation (immediate / short-term / long-term) → references + attack-path hint.

**Risk translation (sample):**

| Technical | Business language |
|---|---|
| Listable S3 bucket with PII | Customer records publicly downloadable. Potential GDPR/CCPA notification trigger. |
| Exposed `.env` with DB credentials | Full database access; pivots to backups, billing, employee PII. |
| Live AWS admin key | Complete cloud compromise; cryptominer spin-up, full data exfiltration, lateral movement. |
| DMARC `p=none` | Anyone on the internet can send email appearing to be from your domain. |
| ≥10 employees in breach corpus | Stolen corp SSO credentials circulating; active credential-stuffing risk. |
| Vendor appliance on CISA KEV | Attackers are actively scanning the internet for this exact issue. Patch now. |

**Reporting cadence:** Day 1 EOD kickoff summary → mid-engagement heads-up on first CRITICAL → end-of-engagement preliminary (top 5 findings) → final report within agreed SLA → re-test offer for CRITICAL/HIGH findings post-remediation.

**Reproduction package:** `run-log.jsonl` + `assets.db` + `findings.db` + `evidence/` (screenshots, HTTP captures, downloads with `.sha256`) + `re-test-script.sh` + engagement metadata.

---

## 17. Skill Self-Test

Drop these into a fresh session to verify the skill loads correctly.

1. *"External recon on acme.com (in-scope BB). Where do I start?"* → §0, §1, §7, §7.1.
2. *"Detect Entra vs Okta vs ADFS without active probing."* → §11 + companion skill §22.
3. *"50 subdomains, 12 webapps, 23 emails — triage order?"* → §8.2 + §7.1.
4. *"Found live AWS key in GitHub repo. Should I validate it?"* → §6.3.
5. *"Probes getting 429s and Cloudflare interstitial. What now?"* → §6.4.
6. *"200 emails harvested, org uses Entra. Highest-ROI next step?"* → §12, §12.1.
7. *"Target fully behind Cloudflare. How to find the origin?"* → §11 (WAF/CDN pointer) + companion skill §16.15.
8. *"100 CVEs from a Nuclei scan. Prioritize."* → §11 (vuln prioritization pointer) + companion skill §29.2.
9. *"Authorized engagement asks for phishing-feasibility shortlist."* → §11 (phishing pointer).
10. *"Found unauth POST endpoint on HackerOne target. Write the report."* → §15.
11. *"Write exec summary for 2 CRIT, 5 HIGH, 12 MED."* → §16.
12. *"Run full subdomain enum on chase.com."* → §1 (scope check; should NOT run).
13. *"crt.sh is 429ing mid-engagement — is the subdomain list complete?"* → §7.3.
14. *"A module runs at Stage 3. Safe to assume it's passive?"* → §7.4.
15. *"We have breach hits and a LinkedIn employee list — who do we prioritize?"* → §12.1.

---

## 18. Changelog

- **v2.3 (2026-08-06)** — §7 upgraded from the 5-stage model to the battle-tested 6-stage model (Seed → Asset Expansion → Enrichment → Exposure Analysis → **Convergence** [bounded recursion + cloud-footprint + supply-chain] → **Active Validation** [hard-gated, operator-armed, default OFF]), with Reporting reframed as a post-stage; added §7.3 Connector Resilience (union-query interchangeable backends per data category, per-source health tracking, so one dead/rate-limited source never zeroes a category) and §7.4 Stage Number ≠ Safe-by-Default (a module's stage doesn't tell you if it's passive — always check its own gating flag; detectability is per-technique). Added §12.1 Per-Person Identity Dossier — joins discovered PERSON role/seniority to leaked CREDENTIAL by email into a ranked spear-phish/credential-stuffing target list, with risk tiering and orphan-credential handling. Added 3 self-test prompts (§17.13–15).
- **v2.2 (2026-04-29)** — refactor: trimmed from 1,694 to ~480 lines. Compressed implementation-detail sections (§11–§15, §27–§31 original) to pointers to `offensive-osint`. Retained full framework core: confidence levels, pipeline, asset graph, severity rubric, OpSec, breach correlation, anti-patterns, deliverable templates. Removed duplicate content; combined specialty domains into single §13; merged §23–§25 into §13; collapsed §27–§29 into §11 pointer block.
- **v2.1 (2026-04-27)** — comprehensive expansion based on 32-prompt smoke-test gap analysis. PASS rate: 31/32.
- **v2.0 (2026-04-27)** — major rewrite for external red-team posture.
- **v1.x** — original framework based on SnailSploit/offensive-checklist.
