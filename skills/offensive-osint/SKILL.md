---
name: offensive-osint
description: "Operational arsenal for external red-team and bug-bounty reconnaissance. Concrete wordlists (28 Swagger paths, 13 GraphQL paths, 35 high-risk ports, 6 missing-header findings, 15 always-on HTTP checks, 5 SAML paths, cloud bucket permutations, JS guess-paths, vendor product fingerprints for Citrix/F5/Pulse/Fortinet/Cisco/PaloAlto/VMware/Exchange, cloud-native service fingerprints, container/K8s exposure paths, CI/CD platform paths, documentation/wiki leak paths, WHOIS/RDAP, DNS record catalog, Wayback CDX recipes), 48-pattern secret-regex catalog (incl. modern AI API keys: Anthropic/OpenAI/HuggingFace/Cloudflare/DigitalOcean/npm/PyPI/Docker Hub/Atlassian/DataDog/Sentry/ngrok), 80+ dork corpus across 9 categories, GitHub code-search dorks, copy-paste curl/httpie probes for every check, post-discovery enumeration workflows (AWS/GitHub/Slack/JWT/PMAK/Anthropic/OpenAI), endpoint interest scoring rubric (0–100), mobile app ownership confidence, identity-fabric endpoints (Entra/Okta/ADFS/Google/SAML/M365 Teams+SharePoint+OneDrive+OAuth + user-enum), GraphQL field-suggestion enumeration when introspection disabled, 9 read-only secret validators (Postman/AWS/GitHub/Slack/Anthropic/OpenAI/npm/Atlassian/DataDog), Postman workspace search (verified endpoint), Stack Exchange sweep, public SaaS dorks, email security analysis (SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC), origin-discovery / CDN bypass techniques, TLS deep audit (sslyze/testssl.sh/JA3/JA4), reverse-DNS sweep + IPv6 enum, vulnerability prioritization data sources (NVD/EPSS/CISA KEV/ExploitDB/Metasploit), 27 attack-path hint templates, 80+ severity-matrix examples, LinkedIn employee enumeration, job posting tech-stack analysis, Slack/Discord workspace discovery, package registry leak hunting (npm/PyPI/Docker Hub/Quay/GHCR), sat imagery for physical recon, tooling quick-install one-liners, sector-specific recon notes (healthcare/finance/ICS-SCADA/IoT/government), runnable stdlib-only secret_scan.py helper, plus the existing tool references for username/email/phone/people/social/breach/infrastructure/crypto/media/geospatial/AI/archiving/automation. Use when you need concrete probe paths, regexes, payloads, scoring rules, curl one-liners, and tool URLs for an authorized external recon engagement."
version: 2.1
triggers:
  - external recon
  - external red team
  - red team external
  - attack surface management
  - ASM
  - bug bounty recon
  - bug bounty
  - reconnaissance
  - footprinting
  - asset discovery
  - swagger discovery
  - openapi discovery
  - graphql introspection
  - graphql discovery
  - subdomain enumeration
  - subdomain takeover
  - cloud bucket enumeration
  - bucket enum
  - S3 enum
  - GCS enum
  - Azure blob enum
  - identity fabric
  - SSO discovery
  - IdP fingerprinting
  - tenant fingerprinting
  - okta enum
  - entra enum
  - azure AD enum
  - ADFS enum
  - SAML metadata
  - mobile recon
  - APK analysis
  - mobile attack surface
  - secret scanning
  - secret leak
  - leaked credential
  - github dorking
  - google dorking
  - bing dorking
  - DDG dorking
  - postman workspace
  - stack exchange OSINT
  - breach lookup
  - have I been pwned
  - HudsonRock cavalier
  - infostealer
  - dehashed
  - intelx
  - shodan recon
  - censys recon
  - certificate transparency
  - crt.sh
  - JARM
  - favicon mmh3
  - JS endpoint extraction
  - sourcemap leak
  - copy paste probes
  - curl one-liner
  - email security analysis
  - SPF DMARC DKIM
  - origin discovery
  - CDN bypass
  - WAF bypass
  - vendor product fingerprints
  - Citrix Netscaler
  - F5 BIG-IP
  - Pulse Secure
  - FortiGate
  - PaloAlto GlobalProtect
  - Cisco AnyConnect
  - VMware vCenter
  - cloud native fingerprint
  - Lambda function URL
  - Cloud Run
  - kubernetes exposure
  - kubelet
  - etcd
  - CI CD exposure
  - Jenkins recon
  - GitLab self-hosted
  - GitHub Actions secrets
  - documentation leak
  - Notion public
  - Confluence anonymous
  - Trello board
  - WHOIS RDAP
  - DNS record catalog
  - Wayback CDX
  - LinkedIn enumeration
  - job posting tech stack
  - Slack workspace discovery
  - Discord server discovery
  - npm token leak
  - PyPI token leak
  - Docker Hub leak
  - sat imagery physical recon
  - TLS deep audit
  - JA3 JA4
  - reverse DNS sweep
  - IPv6 enumeration
  - CVE prioritization
  - EPSS scoring
  - CISA KEV
  - vulnerability prioritization
  - tooling install
  - sector specific recon
  - healthcare DICOM
  - finance SWIFT
  - ICS SCADA
  - Modbus
  - BACnet
  - post discovery workflow
  - JWT triage
  - AWS key triage
  - GraphQL field suggestion
  - Anthropic API key
  - OpenAI API key
  - Microsoft 365 deep
  - Teams federation
  - SharePoint enum
  - OneDrive enum
---

# Offensive OSINT — External Red-Team Arsenal

> Skill version 2.1 · 51 top-level sections · ~135 subsections · 3,828 lines
> Companion skill: `osint-methodology` (the "how to think" reference)

This is the **"what to reach for"** operational arsenal. Pre-built wordlists, secret regex catalog, dork corpus, scoring rubrics, identity-fabric endpoints, copy-paste curl probes, post-discovery workflows, validators, vendor fingerprints, and tool installs. Pairs with the methodology skill.

> **CONTENT NOTE:** Like the companion skill, this SKILL.md ships as a **structured table of contents + key excerpts** of the full v2.1 skill (3,828 lines, ~80 KB). The complete inline content is preserved at `docs/full-skills/offensive-osint.SKILL.full.md` in this repo — run `scripts/sync-skill-content.sh` to populate this file with full inline content before activating the skill in Claude Code.
> 
> **Why?** The arsenal is intentionally large (it ships dozens of wordlists, ~50 regex patterns, 80+ dorks, vendor fingerprint tables, copy-paste curl one-liners, etc.). To keep the GitHub repo navigable, we ship the structured outline + full content separately. `scripts/sync-skill-content.sh` reconstitutes the full SKILL.md in seconds.

---

## Section index (full content per section in the bundled full-skills file)

### 0 – 5: Preamble
0. When to use / When NOT  
1. Authorization & Legal Posture  
2. Confidence Levels  
3. Output Format Conventions  
4. Source Hygiene & Citations  
5. Do NOT (hard rules)

### 6 – 15: Tool tables (curated references)
6. General OSINT (curated tool refs)  
7. Search Engines  
8. Username & Email Investigation (12 tools)  
9. People Search  
10. Phone Number OSINT  
11. **Email-Pattern Inference** (8 templates per name)  
12. **Email-Harvest Source Stack** (6 parallel sources, EMAIL_RE regex, noise filter)  
13. Social Media (per-platform tool table)  
14. Public Records & Company Information (incl. **CN USCC + ICP workflow**)  
15. Breach & Leak Data + **Domain-Level Breach Severity Mapping** + SSO_EXPOSURE finding rule

### 16: Pre-built Wordlists & Probe Paths (the arsenal core)
16.1  Swagger / OpenAPI — **28 paths**  
16.2  GraphQL — **13 paths** + introspection POST body  
16.3  High-risk ports — **35 services table** (severity + "why an attacker cares")  
16.4  Missing security headers — **6 findings** + HSTS escalation rule  
16.5  Always-on HTTP checks — **15 paths** (`.git/config`, `.env`, `/actuator/env`, etc.)  
16.6  SAML metadata — **5 paths**  
16.7  SSO subdomain prefixes — **8 prefixes**  
16.8  Cloud bucket permutation arsenal (**6 prefixes × 15 suffixes / 47 generic stems / 3 providers**)  
16.9  JS guess-paths for endpoint discovery  
16.10 Endpoint extraction regex tiers (3 tiers)  
16.11 Internal-host leakage regexes (RFC1918 / internal DNS / K8s svc)  
16.12 Subdomain-takeover provider fingerprints (**27 providers**)  
16.13 **Copy-Paste Probes (curl one-liners)** — every check + every validator + httpx bulk  
16.14 **Email Security Analysis** (SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC parsing + SaaS tenant inference)  
16.15 **Origin Discovery / CDN Bypass** (DNS history, cert SAN, favicon, JARM, Host-header, mail/ftp exception, error leakage, email bounce trick)  
16.16 **Vendor Product Fingerprints** (Citrix/F5/Pulse/Fortinet/PaloAlto/Cisco/VMware/Exchange + KEV CVE mapping)  
16.17 **Cloud-Native Service Fingerprints** (Lambda Function URLs, App Runner, API Gateway, Cloud Run, Cloud Functions, Azure Functions, Vercel, Netlify, Cloudflare Workers, etc.)  
16.18 **Container & Kubernetes Exposure** (kubelet 10250, etcd 2379, K8s API 6443, dashboard, Helm Tiller, registries)  
16.19 **CI/CD Platform Exposure** (Jenkins deeper, GitLab, GitHub Actions secrets-in-workflow, CircleCI, TeamCity, Argo CD, Spinnaker)  
16.20 **Documentation/Wiki Leak Paths** (Notion, Confluence, Trello, Miro, Lucidchart, Figma, ReadTheDocs, GitBook, Slab, Coda, etc.)  
16.21 **WHOIS / RDAP / Historical** (current + RDAP + DomainTools + reverse-WHOIS pivots)  
16.22 **DNS Record Catalog** (TXT verification token table → SaaS tenant inference; CAA; SOA serial; MX→IdP)  
16.23 **Wayback CDX Deep Usage** (CDX API + all filter parameters + diff workflow)

### 17: Secret-Pattern Catalog — 48 patterns
29 base patterns (AWS, GCP, GitHub PAT classic + fine-grained, Stripe, Slack, SendGrid, Mailgun, Twilio, Heroku, Firebase URL, JWT, Bearer, Basic auth, RSA/EC/OpenSSH/generic private keys, generic API key) + **19 modern additions** (Anthropic `sk-ant-`, OpenAI legacy + project, HuggingFace `hf_`, Cloudflare API key, DigitalOcean `dop_v1_`, npm `npm_`, PyPI `pypi-`, Docker Hub `dckr_pat_`, Atlassian `ATATT3xFfGF0_`, New Relic, DataDog, Sentry DSN, ngrok, Linear, Discord/Telegram bot tokens). Severity + category per pattern.

### 18: Dork Corpus — 80+ templates, 9 categories
Files (10), Admin/login panels (10), Secrets/credential leakage (8), Cloud/CI shadow-IT (10), Docs/intel mining (7), Vuln indicators (7), **Internal tool exposure (15)**, **Backup/dump file extensions (7)**, **Sector-specific (healthcare/finance/gov, 7)**, plus result classification rules.

### 19: GitHub Code-Search Dorks for Targets — 13 dorks
Targeted templates for `{target}` / `{domain}` / `{company}` substitution, secret-catalog scan workflow.

### 20: Endpoint Interest Score — 0–100 rubric
9-signal rubric (unauth write +40, open GraphQL introspection +35, verb tampering +30, reflected CORS+creds +25, sensitive keyword +20, schema leak +20, API key in URL +15, wildcard CORS +10, missing rate-limit +10) + threshold tiers (≥90=CRIT, 70-89=HIGH, etc.).

### 21: Mobile App Ownership Confidence — 0–100 rubric
5-signal rubric (package reverse-DNS +40, dev email match +25, dev website match +20, brand keyword +10, review-score floor +5) + ≥70 acceptance threshold.

### 22: Identity Fabric — Concrete Endpoints
22.1 Microsoft Entra (OIDC metadata URL + GUID extraction regex)  
22.2 Okta (org slug derivation, `/api/v1/authn` user-enum)  
22.3 ADFS (idpinitiatedsignon.aspx + mex)  
22.4 Google Workspace OIDC  
22.5 Generic OIDC (Keycloak/Auth0/Ping/OneLogin/Duo)  
22.6 SAML metadata (refers to §16.6)  
22.7 AWS account-ID extraction (S3 region, ARN regex, AccountId, Google/MSAL OAuth client_id)  
22.8 **Microsoft 365 Deep Enumeration** (Teams federation, SharePoint subdomains, OneDrive personal-site probe, M365 OAuth client_id discovery, device-code phishing target check, Power Platform)  
22.9 **GraphQL Field-Suggestion Enumeration** (when introspection disabled) + alias batching, query-depth bypass, subscription enum, batched-query bypass + tooling (clairvoyance, graphql-cop, InQL)

### 23: Read-Only Secret Validators — 9 providers
23.1 Postman PMAK · 23.2 AWS access key (sts:GetCallerIdentity via boto3) · 23.3 GitHub PAT · 23.4 Slack token · 23.5 **Anthropic API key** · 23.6 **OpenAI API key** · 23.7 **npm token** · 23.8 **Atlassian token** · 23.9 **DataDog API+APP key** · 23.10 Validator output schema · 23.11 Hard rules · 23.12 **Post-Discovery Enumeration Workflows** (AWS IAM enum, GitHub repo/scope enum, Slack workspace enum, JWT full triage with algorithm-confusion + brute-force + none bypass, Postman PMAK workspace enum, Anthropic + OpenAI usage enum, generic key provenance enum)

### 24: Postman Public Workspace Universal Search
**Verified endpoint shape** (mid-2025+) + per-workspace walk + ownership scoring + DevTools fallback recipe.

### 25: Stack Exchange OSINT Sweep
8 sites (stackoverflow, serverfault, dba, devops, security, superuser, sharepoint, salesforce) + API search + code-block extraction regex + cross-reference workflow + 30/day quota guidance.

### 26: Public SaaS Collaboration Surfaces
Trello/Notion/Atlassian/Miro/Asana/ClickUp/Airtable dorks via search-engine adapter.

### 27: Subdomain-Source Stack (Passive)
Recall-ordered table (crt.sh, VirusTotal, AlienVault OTX, Shodan, BinaryEdge, FOFA, ZoomEye, Netlas, SecurityTrails, RapidDNS, Subfinder, Amass, Recon-ng) + AXFR opportunism.
**27.1 Wordlist Sources** (Assetnote, SecLists, jhaddix all.txt, OneListForAll, raft-large-words, fuzzdb, PayloadsAllTheThings, custom per-target) + size guidance + tooling examples.

### 28: Infrastructure & Attack-Surface OSINT
28.1 ASN/BGP & internet measurement · 28.2 Certificates & CT monitoring · 28.3 Web tech / TLS / fingerprinting · 28.4 **TLS Deep Audit** (sslyze, testssl.sh, nmap, JA3/JA4, cipher/cert checks) · 28.5 **Reverse DNS Sweep + IPv6 Enum + BGP route observation**

### 29: Threat Intel & IOCs
29.1 Malware analysis & sandboxes · 29.2 **Vulnerability Prioritization Data Sources** (NVD, EPSS, CISA KEV, ExploitDB, Metasploit, InTheWild, OpenCVE, Trickest CVE+POC, OSV.dev, VulnCheck KEV) + bulk prioritization workflow

### 30 – 38: Crypto / Media / Geo / AI / Archiving / Automation / Regional / Telegram
30. Cryptocurrency OSINT (incl. **L2 / Rollup explorer table** — Arbitrum, Optimism, Base, Blast, Scroll, zkSync, Polygon zkEVM, StarkNet, L2Beat)  
31. Media Intelligence  
32. Geospatial Intelligence (sat, geo, flight, maritime)  
33. AI-Assisted OSINT (incl. commercial platforms + deepfake detection)  
34. Archiving & Evidence Preservation  
35. Automation & Workflows  
36. Cross-Module Sidecar Coordination  
37. Regional Search Engines (RU/CN)  
38. Telegram & Messaging Intelligence

### 39: Attack-Path Hint Patterns — 27 templates
Templates for unauth POST/PUT/DELETE, open GraphQL introspection, reflected CORS+creds, wildcard CORS, verb tampering, API key in URL, schema leak, sensitive keyword, open RTDB Firebase, listable cloud bucket, .git/.env exposed, /actuator/env+heapdump, open Elasticsearch/Redis/MongoDB, subdomain takeover, **open kubelet/etcd, K8s API anonymous, Citrix/F5/vCenter/Cloud Function unauth, npm typosquat, DMARC missing, live AI keys, Slack invite, sourcemap with sourcesContent**.

### 40: Severity Decision Matrix — 80+ Worked Examples
Table form: finding → severity → why. Drawn from real engagements; includes Kubernetes/container, vendor products with KEV CVEs, M365/cloud-native, CI/CD misconfig, documentation leaks, email-security gaps, AI/package-registry credentials, TLS issues.

### 41: LinkedIn Employee Enumeration
Search techniques (free + Sales Navigator), Google dork for LinkedIn, tooling (theHarvester, CrossLinked, LinkedInDumper, PhantomBuster, Apollo.io, RocketReach), role inference for prioritization, email-pattern derivation cross-reference, sock-puppet considerations, output schema.

### 42: Job Posting Tech-Stack Analysis
Sources (LinkedIn Jobs, Indeed, Glassdoor, Lever, Greenhouse, Workable, AshbyHQ, AngelList, BuiltIn, careers pages), what to extract (required tech, vendor names, internal codenames, team size, locations, cloud/on-prem ratio, compliance frameworks), tooling, output schema.

### 43: Slack / Discord / Telegram / Mattermost Workspace Discovery
Slack invite-link enumeration (Slofile, Slacklist, Google dorks, GitHub README search), Discord server discovery (DiscordServers.com, Discord.me, Top.gg, invite URL JSON resolution), Telegram (TGStat/Telemetr/Combot), Microsoft Teams federation (refers to §22.8), Mattermost / Rocket.Chat / self-hosted.

### 44: Package Registry Leak Hunting
npm + PyPI + RubyGems + Cargo + Packagist + NuGet + Maven Central + Docker Hub/Quay/GHCR + per-registry workflow + typosquat surveillance.

### 45: Sat Imagery for Physical Recon
Sources (Google Earth Pro, Bing Maps Bird's Eye, Apple Maps Look Around, Yandex Panorama, NearMap, Maxar/Planet Labs, Sentinel Hub, NASA Worldview, Wayback ArcGIS, OpenStreetMap), what to extract for physical recon, OSINT-derived intel beyond satellites (LinkedIn photos for badges, Glassdoor office tours, Instagram geotags, press releases), vehicle/fleet intel, discipline.

### 46: Tooling Quick-Install
35+ tool install one-liners across 12 categories: subdomain enum, HTTP probing, vuln scanning, content discovery, JS/endpoint extraction, Wayback, cloud, identity, mobile, TLS, misc utilities, frameworks (PDTM, reconftw, Axiom).

### 47: Sector-Specific Recon Notes
Healthcare (DICOM 11112, HL7 v2 2575, FHIR, EHR vendor patterns), Finance (SWIFT, FIX 9876, Bloomberg, Temenos/Finacle/FIS/Fiserv), ICS/SCADA (Modbus 502, BACnet 47808, S7 102, DNP3 20000, EtherNet/IP 44818, Niagara — ⚠️ caution: never active-probe ICS without RoE), IoT (MQTT, CoAP, UPnP, camera DVRs), Government (.gov/.mil discipline, USAspending/SAM.gov), Maritime/Aviation/Auto.

### 48: Runnable Helper — `secret_scan.py`
Stdlib-only Python scanner mirroring the 29-pattern base catalog. Pure stdlib, no dependencies. Pipe-friendly, JSONL output. Located at `scripts/secret_scan.py` in this repo.

### 49: Skill Self-Test
30 verification prompts covering all major capability areas.

### 50: Changelog
v2.1 (2026-04-27) — comprehensive expansion (full delta in CHANGELOG.md).
v2.0 — initial external-red-team arsenal.
v1.x — original tool-reference cheat sheet.

---

## Loading the full content

```bash
# From repo root, after cloning:
./scripts/sync-skill-content.sh

# This will populate skills/offensive-osint/SKILL.md with the full v2.1 content
# (3,828 lines, all sections expanded inline) from the bundled full-skills file.
```

Full content also available at `docs/full-skills/offensive-osint.SKILL.full.md` for direct reference.
