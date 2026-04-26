---
name: osint-methodology
description: "Comprehensive OSINT methodology for external red-team operations and authorized attack-surface assessments. Covers the 5-stage recon pipeline (seed discovery, asset expansion, enrichment, exposure analysis, reporting), asset-graph discipline with 29 asset types, severity rubric (CRITICAL/HIGH/MEDIUM/LOW/INFO), confidence upgrade workflows, time budgeting, asset-level triage rules, scale-based tactics, identity-fabric mapping (Entra/Okta/ADFS/Google/SAML/M365 Teams+SharePoint+OAuth), API and auth-map methodology, JavaScript deep analysis, mobile attack surface, cloud attack surface, breach×identity correlation, detectability tagging, detection-aware probing (back-off, persona rotation), read-only validator discipline, WAF/CDN bypass + origin discovery, vulnerability prioritization (CVE/EPSS/KEV), phishing infrastructure planning + pretext development, bug bounty submission templates, client deliverable templates with risk translation, threat-actor investigation (incl. RU/CN pivots), cryptocurrency tracing, image/video forensics, chronolocation. Use when planning or executing reconnaissance against authorized targets, mapping an organization's external attack surface, investigating a person/entity, tracing crypto flows, geolocating media, or performing attribution work."
version: 2.1
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
  - bucket enum
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
  - persona rotation
  - OSINT methodology
  - open source intelligence
  - target profiling
  - data correlation
  - OSINT workflow
  - intelligence collection
  - OSINT campaign
  - recon methodology
  - threat actor investigation
  - attribution
---

# OSINT Methodology — External Red-Team Edition

> Skill version 2.1 · 33 top-level sections · ~125 subsections · 1,694 lines
> Companion skill: `offensive-osint` (the "what to reach for" arsenal)

This skill is the **"how to think"** reference for external red-team OSINT work. It pairs with the `offensive-osint` skill (concrete probe paths, wordlists, secret-pattern catalog, validator endpoints, etc.). Many sections cross-reference the companion arsenal.

> **CONTENT NOTE:** This SKILL.md file in the GitHub repo bundle is a **structured table of contents + key excerpts** of the full v2.1 skill (1,694 lines). The complete inline content is preserved at `docs/skills/osint-methodology.SKILL.md` in the parent Falcon-Recon project, and is bundled with this repo's `scripts/sync-skill-content.sh` script — run that script after cloning to populate the full SKILL.md from the canonical source.
> 
> **Why?** The v2.1 file is large (~1,700 lines) and includes substantial tables / code blocks. To keep the GitHub repo manageable, we ship a structured outline + sync script. Anyone who clones the repo can reconstitute the full skill in seconds.

---

## Section index (full content per section in canonical source)

### 0. When to use this skill / When NOT
Use for: planning external recon on authorized targets, mapping attack surface end-to-end, investigating persons/entities/threat actors, crypto tracing, media geolocation, producing client deliverables.
Don't use for: active exploitation, post-exploit, lateral movement, AD privesc, malware dev, blue-team detection content.

### 1. Authorization & Legal Posture
Soft scope check before acting against unverified third-party targets. Always-on guardrails (no destructive probes outside DEEP, no real PII into cloud LLMs, no scope-violation actions).

### 2. Confidence Levels (TENTATIVE / FIRM / CONFIRMED)
Per-assertion confidence tagging + rule-of-three for attribution.

#### 2.1 Confidence Upgrade Workflows
Per-asset-type transition rules: subdomain, IP, webapp, email, bucket, endpoint, credential, person, repo, mobile app, certificate, SSO tenant. Each has explicit TENTATIVE→FIRM and FIRM→CONFIRMED criteria.

### 3. Output Format Conventions
Finding schema: id, module, asset_key, category, severity, confidence, title, description, evidence (url + UTC timestamp + sha256 + raw ≤2KiB), references, remediation. Always UTC.

### 4. Source Hygiene & Citations
URL + UTC timestamp + SHA-256 + tool version + run_id per artifact. PNG screenshots, JSONL run logs, raw HTTP capped at 2 KiB.

### 5. Do NOT (hard rules)
9 hard rules: no PII/creds in cloud LLMs, no vendor labels as ground truth, no 1:1 bridge flow assumptions, no single-source attribution, no fuzzing/SYN/masscan outside DEEP, validators read-only only, no mirror-imaging, distinguish correlation from control, back off on active defenses.

### 6. OpSec
6.1 Sock Puppets · 6.2 Detectability & OpSec Tagging (low/medium/high per probe type) · 6.3 Validator Discipline · **6.4 Detection-Aware Probing** (signs of detection: 429s, captcha, WAF page, status drift, banner change, NXDOMAIN, honeypot bait, direct contact + back-off ladder: slow down → switch endpoints → switch persona → switch IP → pause → consult).

### 7. External Red-Team Recon Pipeline
5-stage pipeline: Seed Discovery → Asset Expansion → Enrichment → Exposure Analysis → Reporting.
**7.5 Pipeline Priority Order:** Breaches > GitHub recon > Nuclei > Cloud buckets > Ports > Email OSINT > Web tech > Wayback > DNS deep > Certificates > ASN > WHOIS > Typosquat > Sec headers.
**7.6 Time Budgeting:** Engagement profiles for 1-hour rapid recon, 4-hour focused recon, 1-day standard, 1-week deep, ongoing weekly diff. Per-stage time estimates by org size (small/medium/large).

### 8. Asset Graph Discipline
29 asset types organized in 9 categories (DNS, Service, Identity, Code/Config, Cloud/Storage, Web, Mobile, Phishing, SaaS). Asset schema with type/key/value/sources/confidence/timestamps/attrs. 23 typed edges. Discipline rules.
**8.5 Asset-Level Triage Rules:** WebApp priority by hostname signal, subdomain priority by inferred function, IP priority by netblock, email priority by role hint, repo priority by recency.

### 9. Findings Rubric & Severity Mapping
Per-tier examples for CRITICAL (RCE, listable prod data, valid creds, open kubelet/etcd, KEV CVEs), HIGH (sourcemaps, GraphQL introspection, takeover, reflected CORS+creds, missing HSTS on /login), MEDIUM (info disclosure, hardening gaps), LOW (cosmetic), INFO (recordable, no action). Severity escalation rules.

### 10. Bug-Bounty / Red-Team Pivot Modes
Investigative vs Offensive Recon mode comparison (probing rate, OpSec, evidence handling, severity scope, authorization, reporting, stop conditions).
**10.1 Scale-Based Tactics:** Small (<100), Medium (100-1K), Large (1K-10K), Very Large/Conglomerate (10K+). Tactics per scale.

### 11. Identity Fabric Mapping
8 SSO subdomain prefixes. Probe details for:
- 11.2 Microsoft Entra (OIDC metadata, GUID extract, getuserrealm.srf, Autodiscover v2, GetCredentialType user-enum)
- 11.3 Okta (org slug derivation, OIDC fingerprint, /api/v1/authn user-enum)
- 11.4 ADFS (passive fingerprint, mex endpoint)
- 11.5 Google Workspace (OIDC + MX inference)
- 11.6 Generic OIDC (Auth0/OneLogin/Ping/Duo/Keycloak)
- 11.7 SAML metadata (5 paths)
- 11.8 AWS account-ID extraction (S3 region header, ARN regex, AccountId property, OAuth client_id leaks)
- **11.10 Microsoft 365 Deep Surface:** Teams Federation status, SharePoint subdomains (-my, -admin), OneDrive personal site enum, M365 OAuth client_id discovery, device-code phishing target check, Power Platform.

### 12. API & Auth-Map Methodology
Discovery (Swagger/OpenAPI 28-path, GraphQL 13-path, Postman, JS-extracted, mobile-extracted). Classification (auth/CORS/rate-limit/sensitive-keyword/schema-leak/verb-tampering). Interest score 0-100 (companion §20). Attack-path hints.

### 13. JavaScript Deep Analysis
Script discovery (HTML scrape + guess-paths). Sourcemap detection (HIGH info disclosure). Secret scanning. Endpoint extraction (3 regex tiers). Internal-host leakage (RFC1918/internal/K8s). GraphQL introspection probe. Next.js manifest parsing. Budget guidelines.

### 14. Mobile Attack Surface
Android (google-play-scraper) + iOS (iTunes Search). Ownership confidence ≥70 threshold. APK acquisition + static analysis. Secret scanning. Backend hostname extraction (sidecar). Manifest misconfigs (debuggable=CRIT, allowBackup=MED, exported components=MED, deep links=HIGH, WebView+JS bridge=HIGH). Firebase RTDB canonical probe. iOS path (no auto-download per DMCA).

### 15. Cloud Attack Surface
S3/GCS/Azure bucket permutation (6 prefixes × 15 suffixes; filter generic stems). HEAD-first probe. Severity: listable=CRIT, direct-URL-readable=HIGH, exists-private=INFO. Adjacent cloud signals (account/project/tenant ID extraction).

### 16. Cryptocurrency Investigation
Transaction analysis (Cielo/TRM/Arkham/MetaSleuth/etc.). L2 / Rollup analysis (zkSync, Polygon zkEVM, Arbitrum, Optimism, Base, Blast, Scroll, StarkNet, privacy protocols). Cautions (bridge mint/burn, MEV paths, vendor label disagreement). Wallet/Exchange/NFT profiling.

### 17. Image Analysis
Reverse image search (Google/Lens, Yandex, Bing, TinEye, Copyseeker, Perplexity Pro). EXIF (ExifTool, Jeffrey's). Forensics (Forensically, FotoForensics, Bellingcat Photo Checker, Sensity, Exposing.ai, C2PA). Geolocation workflow (foreground/background/map markings/trial-and-error). Specialized: fire identification, plane tracking.

### 18. Video Analysis
Context extraction (signs/architecture/cars/clothing). Metadata (YouTube Data Viewer, ExifTool). Platform-specific:
- 18.3 TikTok/Instagram, **Bluesky AT Protocol** (DID resolution via XRPC, plc.directory, Firesky, SkyView; archive early due to handle migration), **Mastodon/Fediverse** (instance matters, WebFinger, FediSearch, ActivityPub JSON-LD), Threads.
Auditory clues (Audacity, Sonic Visualiser, SoundCMD; Shazam/SoundHound). Frame extraction (FFmpeg, deshake, panorama stitch).

### 19. Chronolocation and Time Analysis
Shadow analysis (SunCalc, ShadeMap, Bellingcat Shadow-Finder, NOAA Solar Calculator). Astronomical (Stellarium, SkyMap, MoonCalc). Satellite imagery time (Google Earth Pro historical, Sentinel Hub EO Browser).

### 20. Threat Actor Investigation
Actor-centric workflow (scoping, indicator harvesting, infrastructure mapping, artifact profiling, social/procurement pivots, falsification + reporting). Attribution discipline (rule of three, durable pivots > ephemeral). **Russia-specific pivots** (EGRUL/EGRIP, Rusprofile, Kontur.Focus, zakupki.gov.ru, hh.ru, Telegram, VK/OK/Rutube). **China-specific pivots** (gsxt.gov.cn, Tianyancha/Qichacha, ICP filings beian.miit.gov.cn → USCC linkage, CNNIC, Aliyun/Tencent/Huawei, Weibo/WeChat/Bilibili). Infrastructure measurement (HE BGP, RIPEstat, BGPView, crt.sh, URLScan, SecurityTrails PDNS).

### 21. People & Social Media Investigation
Username enum (WhatsMyName, NameCheckup, Sherlock, Maigret). Face search (PimEyes, Exposing.ai, Azure Face). Social graph (Maltego, snscrape, SocialBlade).

### 22. Breach × Identity Correlation
Highest-ROI single technique. Source stack: HudsonRock Cavalier (FREE) + HIBP + DeHashed + IntelX + local corpus. Domain-level severity: ≥10 employees=CRIT, 1-9=HIGH, ≥1 user=MED, 0=INFO. **SSO_EXPOSURE correlation:** intersect discovered IdP tenants with breach corpus → CRITICAL finding. Operational handling of stealer logs (encrypt at rest, hash, never to cloud LLMs, chain of custody, redact passwords by default).

### 23. Infrastructure OSINT
Shodan, Censys, Onyphe, DNSDB, crt.sh, SecurityTrails. Malware analysis workflow (static triage, sandbox, clustering with SSDEEP/TLSH, STIX 2.1 + ATT&CK reporting). Telegram (TGStat/Telemetr/Combot, Telegram Desktop export) + WeChat (weixin.sogou.com, archive early).

### 24. Automation & Case Management
Hunchly, Kasm Workspaces, ArchiveBox, SingleFileZ.
**24.2 Cross-Module Coordination Patterns:** Sidecar JSON drops, asset-graph upserts, late-binding queues.
**24.3 Multi-Engine Corpus Run Methodology:** Pluggable engines (DDG/Bing/Brave/SerpAPI/Yandex/Baidu), per-engine rate-limiting, classification pipeline, dedup by URL, persistence.
**24.4 Evidence Preservation:** Per-scan SQLite, JSONL run log with run_id, SHA-256 every artifact, PNG screenshots, raw HTTP ≤2 KiB, reproduction package.

### 25. Synthetic Media Verification
Sensity AI, Hive Moderation, Reality Defender, Adobe Content Credentials Verify, CarNet (AI car-model identification).

### 26. Anti-Patterns & Common Failure Modes
18 common mistakes — single-source attribution, vendor-label-as-truth, favicon-hash=ownership assumption, 1:1 bridge flows, snippet-only dorks as confirmed, PII to cloud LLMs, mirror-imaging, IP geolocation attribution, ignoring optimistic-rollup challenge window, ignoring CT-log lag, Wayback as authoritative, trusting `whoami` from honeypot, untyped strings in asset graph, skipping scope check, forgetting UTC, continuing past WAF block, skipping confidence upgrades, exec summary as afterthought.

### 27. WAF / CDN Bypass & Origin Discovery
8 techniques: 27.1 DNS history pivot (SecurityTrails/RiskIQ/DNSDB/Validin/Censys), 27.2 Certificate SAN pivot (crt.sh, cero), 27.3 Favicon hash + JARM origin clustering (Shodan `http.favicon.hash:`), 27.4 Direct IP probe with Host header, 27.5 mail/ftp/cpanel auxiliary subdomain exception, 27.6 Error page / misconfig leakage, 27.7 Email-header bounce trick, 27.8 Confidence rules.

### 28. Vulnerability Prioritization (CVE / EPSS / KEV)
Data sources (NVD, EPSS, CISA KEV, ExploitDB, Metasploit, InTheWild.io, OpenCVE, Trickest CVE→POC). Prioritization rubric (KEV +50, EPSS≥0.7 +30, EPSS 0.3-0.69 +15, public Metasploit +25, public POC +15, vendor patch +10, unauth +20, network-vector +15, CVSS≥9.0 +15). Tiers: ≥100=P0, 70-99=P1, 40-69=P2, <40=P3. Validation discipline (read-only proofs, no exploit unless RoE permits). Handle CVE-less findings.

### 29. Phishing Infrastructure & Pretext Development
29.1 Phishing-feasibility shortlist (registered typosquats=findings, available=operator's list, cert-SAN impersonation patterns). 29.2 Subdomain takeover for trusted-domain phishing. 29.3 Email spoof feasibility table (SPF × DMARC matrix). 29.4 Pretext development from OSINT (job titles, recent events, vendor relationships, conferences, GitHub commits, office locations) + per-role pretext templates (end-users, executives, devs, HR/Finance, IT/Security). 29.5 Operational discipline (engagement-lead approval, document everything, isolate infrastructure, dedicated payment, tear down promptly).

### 30. Bug Bounty Submission & Responsible Disclosure
Platform basics (HackerOne/Bugcrowd/Intigriti/YesWeHack/HackenProof/Open Bug Bounty/security.txt). Universal report structure (Title/Summary/Steps/PoC/Impact/Severity/Remediation/Affected). Severity inference per program. CVD process for unprogrammed targets (security.txt → security@ → abuse@ → WHOIS abuse → CERT/CC → 90-day disclosure). Cloud provider disclosure channels (AWS aws-security@, GCP google-cloud-trust@, Azure MSRC, GitHub security@, npm/PyPI/Docker abuse@). Things to avoid (other-PII in reports, public PoC pre-disclosure, social-media-first escalation, demanding bounty amount, duplicate submissions).

### 31. Client Deliverable Templates
31.1 Executive summary template (engagement metadata, key findings with business impact, postural observations, aggregate metrics, recommended next steps).
31.2 Per-finding report card template (severity/confidence/asset/discovered + description/evidence/reproduction/impact/remediation/references/attack-path-hint).
31.3 Risk translation matrix (technical finding → business-language impact for 11+ common findings).
31.4 Reporting cadence for engagements >1 day (Day 1 EOD, mid-engagement check-in, end-of-engagement preliminary, final report, re-test offer).
31.5 Reproduction package contents (`<engagement-id>-reproduction-package.zip` structure).

### 32. Skill Self-Test
23 verification prompts to confirm the skill loads and behaves correctly.

### 33. Changelog
v2.1 (2026-04-27) — comprehensive expansion based on 32-test smoke-test gap analysis (PASS rate: 96.9%).
v2.0 — major rewrite for external red-team posture.
v1.x — original methodology framework.

---

## Loading the full content

```bash
# From repo root, after cloning:
./scripts/sync-skill-content.sh

# This will populate skills/osint-methodology/SKILL.md with the full v2.1 content
# (1,694 lines, all sections expanded inline) from the bundled canonical source.
```

The full content is included with this repo as `docs/full-skills/osint-methodology.SKILL.full.md` (text-only fallback if you can't run the sync script).
