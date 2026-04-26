# Changelog

All notable changes to these skills are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1] — 2026-04-27

Comprehensive expansion based on a 32-prompt smoke-test gap analysis. PASS rate moved from C-grade (1 PASS / 9 PARTIAL / 22 FAIL) to A-grade (31 PASS / 1 PARTIAL / 0 FAIL).

### `osint-methodology` — added 11 new sections / subsections

- **§2.1 Confidence Upgrade Workflows** — per-asset-type transition rules (subdomain, IP, webapp, email, bucket, endpoint, credential, person, repo, mobile app, certificate, SSO tenant).
- **§6.4 Detection-Aware Probing** — signs of detection (429s, captcha, WAF page, status drift, banner change, NXDOMAIN, honeypot bait, direct contact) + back-off ladder (slow down → switch endpoints → switch persona → switch IP → pause → consult).
- **§7.6 Time Budgeting & Engagement Profiles** — per-stage time estimates by org size; 1-hour rapid recon, 4-hour focused recon, 1-day standard, 1-week deep, ongoing weekly diff profiles.
- **§8.5 Asset-Level Triage Rules** — WebApp / Subdomain / IP / Email / Repo priority rubrics.
- **§10.1 Scale-Based Tactics** — small (<100), medium (100-1K), large (1K-10K), conglomerate (10K+) tactics.
- **§11.10 Microsoft 365 Deep Surface** — Teams Federation, SharePoint subdomains (-my, -admin), OneDrive personal-site enum, OAuth client_id discovery, device-code phishing target check, Power Platform.
- **§27 WAF / CDN Bypass & Origin Discovery** — DNS history pivot, cert SAN pivot, favicon hash + JARM origin clustering, direct IP probe with Host header, mail/ftp/cpanel exception, error page leakage, email-header bounce trick.
- **§28 Vulnerability Prioritization (CVE / EPSS / KEV)** — data sources + 9-signal rubric → priority tiers.
- **§29 Phishing Infrastructure & Pretext Development** — typosquat shortlists, subdomain takeover for trusted-domain phishing, email spoof feasibility matrix, pretext development from OSINT, per-role pretext templates, operational discipline.
- **§30 Bug Bounty Submission & Responsible Disclosure** — platform basics (HackerOne/Bugcrowd/Intigriti/YesWeHack/HackenProof/Open BB/security.txt), universal report structure, severity inference per program, CVD process, cloud provider disclosure channels.
- **§31 Client Deliverable Templates** — executive summary template, per-finding report card template, risk translation matrix (11+ technical findings → business-language impact), reporting cadence, reproduction package contents.

### `offensive-osint` — added 11 new §16 subsections + 7 new top-level sections + many expansions

#### New §16 subsections (Pre-built Wordlists & Probe Paths)

- **§16.13 Copy-Paste Probes** — curl one-liners for every check (15 always-on HTTP, 8 SSO prefixes, 5 SAML paths, S3/GCS/Azure HEAD+GET, GraphQL introspection POST, all 9 read-only validators, httpx bulk).
- **§16.14 Email Security Analysis** — SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC parsing + SaaS tenant inference table + 25+ TXT verification token patterns.
- **§16.15 Origin Discovery / CDN Bypass** — 8 techniques to find origin behind Cloudflare/Akamai/Fastly/CloudFront.
- **§16.16 Vendor Product Fingerprints** — Citrix Netscaler, F5 BIG-IP, Cisco ASA, Pulse Secure, FortiGate, PaloAlto GlobalProtect, VMware Horizon/vCenter/ESXi, Microsoft Exchange, WatchGuard, SonicWall, Sophos, Check Point, Zoho ManageEngine, Atlassian Confluence/Jira, GitLab self-hosted, Telerik UI, ConnectWise ScreenConnect, SolarWinds, Kaseya — with KEV CVE associations.
- **§16.17 Cloud-Native Service Fingerprints** — AWS Lambda Function URLs, App Runner, API Gateway, CloudFront, ALB; Google Cloud Run, Cloud Functions, App Engine; Azure Functions, Container Apps, Static Web Apps; Vercel, Netlify, Cloudflare Workers/Pages, Heroku, Render, Fly.io, Railway, DigitalOcean App Platform.
- **§16.18 Container & Kubernetes Exposure** — Docker API (2375/2376), Kubernetes API server (6443), kubelet (10250), etcd (2379), dashboard, kube-proxy/controller/scheduler, cAdvisor, Helm Tiller, Docker Hub / Quay / GHCR / ECR Public / GCR registry enum + per-image scan workflow.
- **§16.19 CI/CD Platform Exposure** — Jenkins (deeper), GitLab self-hosted, GitHub Actions secrets-in-workflow patterns, CircleCI, TeamCity (KEV CVE), Bamboo, Drone CI, Travis CI legacy, Argo CD, Tekton, Spinnaker, Buildkite.
- **§16.20 Documentation/Wiki Leak Paths** — Notion, Confluence Cloud, Atlassian Service Desk, Trello, Asana, ReadTheDocs, GitBook, MkDocs/Docusaurus, Slab, Coda, Miro, Lucidchart, Figma, GitHub Wiki, Linear, self-hosted Confluence, Monday.com, Wrike + dork-driven discovery.
- **§16.21 WHOIS / RDAP / Historical** — current WHOIS, RDAP (RFC 7480), historical WHOIS sources (DomainTools, WhoisXML, SecurityTrails, viewdns.info, whoisology.com), reverse-WHOIS pivots.
- **§16.22 DNS Record Catalog** — per-record-type rubric + TXT verification token table mapping ~25 patterns to SaaS tenants (Google Workspace, M365, Atlassian, Adobe, DocuSign, Dropbox, Box, Webex, Zoom, Notion, Slack EG, Asana, MongoDB Atlas, etc.) + CAA + SOA serial pattern analysis.
- **§16.23 Wayback CDX Deep Usage** — full CDX API filter parameters + diff workflow + bulk archived JS extraction.

#### Catalog & corpus expansions

- **§17 Secret-Pattern Catalog** expanded from 29 to **48 patterns**. Added: Anthropic API key (`sk-ant-`), OpenAI legacy + project keys, OpenAI session, HuggingFace (`hf_`), Cloudflare API key (typed + global), DigitalOcean (`dop_v1_`), npm (`npm_`), PyPI (`pypi-`), Docker Hub (`dckr_pat_`), Atlassian (`ATATT3xFfGF0_`), New Relic, DataDog (typed), Sentry DSN, ngrok, Linear, Discord bot token, Telegram bot token.
- **§18 Dork Corpus** expanded from 50+ to **80+ templates** across **9 categories** (added: internal tool exposure, backup/dump file extensions, sector-specific for healthcare/finance/gov).

#### Identity & validators

- **§22.8 Microsoft 365 Deep Enumeration** — Teams federation API, SharePoint subdomain probe (3 patterns), OneDrive personal site enum, M365 OAuth client_id discovery, `device_authorization_endpoint` phishing-target check, Power Platform / Dynamics URLs.
- **§22.9 GraphQL Field-Suggestion Enumeration** — recipe + tooling (clairvoyance, graphql-cop, InQL) + alias batching + query-depth bypass + subscription enumeration + batched-query bypass.
- **§23 Read-Only Secret Validators** expanded from 4 to **9 providers**. Added: Anthropic API key, OpenAI API key, npm token, Atlassian API token, DataDog API+APP key.
- **§23.12 Post-Discovery Enumeration Workflows** — AWS IAM enum (sts → iam → simulate-principal-policy), GitHub PAT scope/repo enum, Slack workspace enum (auth.test → users.identity → conversations.list), JWT full triage (algorithm-confusion + brute-force + none-bypass), Postman PMAK workspace enum, Anthropic + OpenAI usage enum, generic key provenance enum.
- **§24 Postman Endpoint** pinned with verified shape (mid-2025+) + DevTools fallback recipe.

#### Audit / vulnerability / measurement

- **§27.1 Wordlist Sources** — Assetnote, SecLists, jhaddix all.txt, OneListForAll, raft-large-words, fuzzdb, PayloadsAllTheThings + size guidance + tooling examples.
- **§28.4 TLS Deep Audit** — sslyze + testssl.sh + nmap script alternatives + JA3/JA4 reference DBs + 14-row issue table.
- **§28.5 Reverse DNS Sweep + IPv6 Enum + BGP route observation** — within-scope sweep, IPv6 considerations, RouteViews / RIPE RIS, third-party PTR pivots.
- **§29.2 Vulnerability Prioritization Data Sources** — NVD, EPSS, CISA KEV, ExploitDB, Metasploit, InTheWild.io, OpenCVE, Trickest CVE→POC, GitHub Security Advisories, MITRE CVE, OSV.dev, VulnCheck KEV + bulk prioritization workflow.

#### Hints & severity

- **§39 Attack-Path Hint Patterns** expanded with **15 more templates** (open kubelet/etcd, K8s API anonymous, Citrix/F5/vCenter/Cloud Function unauth, npm typosquat, DMARC missing, live AI keys, Slack invite, sourcemap with sourcesContent, etc.).
- **§40 Severity Decision Matrix** expanded with **30 more worked examples** covering Kubernetes/container, vendor products with KEV CVEs, M365/cloud-native, CI/CD misconfig, documentation leaks, email-security gaps, AI/package-registry credentials, TLS issues.

#### New top-level sections

- **§41 LinkedIn Employee Enumeration** — search techniques (free + Sales Navigator), Google dork, tooling, role-tier prioritization (P0–P5), email-pattern derivation cross-reference, sock-puppet considerations, output schema.
- **§42 Job Posting Tech-Stack Analysis** — sources (LinkedIn Jobs / Indeed / Glassdoor / Lever / Greenhouse / Workable / AshbyHQ / AngelList / BuiltIn), what to extract, tooling, output schema.
- **§43 Slack / Discord / Telegram / Mattermost Workspace Discovery** — Slack invite-link enum, Discord server discovery, Telegram, Microsoft Teams federation, Mattermost / Rocket.Chat / self-hosted.
- **§44 Package Registry Leak Hunting** — npm + PyPI + RubyGems + Cargo + Packagist + NuGet + Maven Central + Docker Hub/Quay/GHCR + per-registry workflow + typosquat surveillance.
- **§45 Sat Imagery for Physical Recon** — sources, what to extract for physical recon, OSINT-derived intel beyond satellites (LinkedIn / Glassdoor / Instagram / press releases), vehicle/fleet intel, discipline.
- **§46 Tooling Quick-Install** — 35+ install one-liners across 12 categories.
- **§47 Sector-Specific Recon Notes** — healthcare (DICOM/HL7/FHIR/EHR), finance (SWIFT/FIX/Bloomberg/banking middleware), ICS/SCADA (Modbus/BACnet/S7/DNP3 + caution discipline), IoT (MQTT/CoAP/UPnP), government (FedRAMP/FISMA/USAspending), maritime/aviation/auto.

#### Renumbering

- §41 (Runnable Helper) → **§48**
- §42 (Skill Self-Test) → **§49** (refreshed with v2.1 prompts; expanded to 30 prompts)
- §43 (Changelog) → **§50** (this entry added)

### File-size delta

| File | v2.0 | v2.1 |
|---|---|---|
| `osint-methodology.SKILL.md` | 1,181 lines | **1,694 lines** |
| `offensive-osint.SKILL.md` | 1,698 lines | **3,828 lines** |
| Combined | 2,879 lines | **5,522 lines** |

### Smoke-test re-grade

After v2.1: **31 PASS / 1 PARTIAL / 0 FAIL** out of 32 (was 1/9/22 in v2.0).

---

## [2.0] — 2026-04-27

Major rewrite for external red-team posture. Both skills tagged `version: 2.0`.

### `osint-methodology`

- Added: 5-stage recon pipeline (§7), asset-graph discipline with 29 asset types (§8), findings rubric with severity examples (§9), bug-bounty pivot modes (§10), identity-fabric mapping (§11), API & auth-map methodology (§12), JS deep analysis (§13), mobile attack surface (§14), cloud attack surface (§15), breach × identity correlation (§22), detectability tagging (§6.2), validator discipline (§6.3), cross-module coordination (§24.2), multi-engine corpus run methodology (§24.3), evidence preservation (§24.4), anti-patterns (§26).
- Strengthened: confidence levels (§2), output format (§3), source hygiene (§4), do-not rules (§5), authorization preamble (§1).
- Retained: original methodology content (OpSec, Crypto, Image/Video/Chrono, Threat Actor incl. RU/CN, Synthetic Media).

### `offensive-osint`

- Added: pre-built wordlists & probe paths (§16), 29-pattern secret catalog (§17), 50+ dork corpus (§18), GitHub code-search dorks (§19), endpoint interest score 0-100 rubric (§20), mobile ownership confidence (§21), identity-fabric concrete endpoints (§22), 4 read-only secret validators (§23), Postman workspace search (§24), Stack Exchange sweep (§25), public SaaS dorks (§26), subdomain-source stack (§27), domain-level breach severity (§15.1), L2 explorer table (§30.2), USCC + ICP workflow (§14.2), cross-module sidecar coordination (§36), attack-path hint patterns (§39), severity decision matrix (§40), runnable secret-scan helper (§41).
- Retained: original tool tables (search engines, username/email, people, phone, social, public records, breach, infrastructure, threat intel, crypto, media, geospatial, AI, archiving, automation, regional, telegram).

---

## [1.x] — pre-2026

- `osint-methodology`: original framework based on [SnailSploit/offensive-checklist](https://github.com/SnailSploit/offensive-checklist).
- `offensive-osint`: original tool-reference cheat sheet.
