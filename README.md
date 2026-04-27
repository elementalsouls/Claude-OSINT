![claude-osint banner](assets/banner.svg)

# claude-osint

> 2 paired Claude skills · **90+ recon modules** · 48 secret-regex patterns · 80+ dorks · 9 read-only credential validators · 27 attack-path templates · 5,500+ lines of structured tradecraft. Drop-in `SKILL.md` files that turn Claude into a god-mode external recon operator for authorized red-team and bug-bounty engagements.

Built by **[ElementalSoul](https://github.com/elementalsouls)** — GenAI Security Research.

---

## What is this?

`claude-osint` is a paired set of skills for the [Claude skills system](https://docs.claude.com/en/docs/claude-code/skills). Each skill is a structured `SKILL.md` file that primes Claude with expert-level methodology for one half of the offensive recon problem:

- **`osint-methodology`** — *how to think.* Strategic + procedural. Asset-graph discipline, severity rubric, time budgeting, identity-fabric mapping, deliverable templates.
- **`offensive-osint`** — *what to reach for.* Tactical arsenal. Probe paths, regexes, payloads, scoring rules, curl one-liners, tool URLs.

Drop both into your Claude environment and it behaves like a senior recon analyst: it knows the techniques, the tooling, the edge cases, and the escalation paths — and it stays in scope.

~5,500 lines of structured tradecraft · 96.9% PASS on a 32-prompt self-evaluation · ~85–90% practitioner coverage for the recon phase of authorized engagements.

---

## Structure

```
claude-osint/
├── skills/
│   ├── osint-methodology/SKILL.md     # how to think  (1,694 lines)
│   └── offensive-osint/
│       ├── SKILL.md                   # what to reach for (4,168 lines)
│       └── scripts/secret_scan.py     # stdlib-only secret scanner
├── docs/                              # architecture · coverage · install · usage
├── examples/                          # 4 end-to-end engagement walk-throughs
├── tests/smoke-test-prompts.md        # 32-prompt self-evaluation
└── assets/banner.svg
```

Each skill directory is self-contained. Drop into `~/.claude/skills/` and Claude auto-triggers on relevant phrases.

---

## Skill Index

90+ capabilities across 12 domains. Categorized like Claude-Red — pick a domain to drill in.

### Reconnaissance & Asset Discovery

| Capability | Reference |
|---|---|
| 5-stage external recon pipeline + time-budget profiles (1h / 4h / 1d / 1w) | methodology §7 |
| Subdomain-source stack (crt.sh + 7-source fallback chain when crt.sh 502s) | arsenal §27, §27.0.1 |
| Common-prefix subdomain sweep (100+ ordered prefixes, PowerShell + bash) | arsenal §16.24 |
| Wayback CDX deep mining + legacy-app pivot (.asp/.php/.jsp/.cfm) | arsenal §16.23 |
| WHOIS / RDAP / historical-WHOIS + reverse-WHOIS pivots | arsenal §16.21 |
| Public records (OpenCorporates · SEC EDGAR · GSXT · Rusprofile · Companies House) | arsenal §14 |
| Bulk IP → ASN (Cymru / RIPEstat / bgp.tools) | arsenal §28.1 |

### Identity & SSO Mapping

| Capability | Reference |
|---|---|
| Microsoft Entra (Azure AD) tenant fingerprint + GUID extraction | arsenal §22.1 |
| M365 deep enum (Teams federation · SharePoint · OneDrive · OAuth · device-code phishing) | arsenal §22.8 |
| Autodiscover IP correlation (passive M365 confirm even when MX wrapped by Mimecast/Proofpoint) | arsenal §22.1, §16.22 |
| Okta tenant slug + `/api/v1/authn` user-enum | arsenal §22.2 |
| ADFS fingerprint + mex endpoint | arsenal §22.3 |
| Google Workspace OIDC discovery | arsenal §22.4 |
| Generic OIDC (Auth0 · Keycloak · Ping · OneLogin · Duo) | arsenal §22.5 |
| SAML metadata (5 paths) | arsenal §16.6, §22.6 |
| AWS account-ID extraction from headers + ARN regex | arsenal §22.7 |

### Web Application Attack Surface

| Capability | Reference |
|---|---|
| Swagger / OpenAPI discovery (28 paths) | arsenal §16.1 |
| GraphQL discovery + introspection POST body (13 paths) | arsenal §16.2 |
| GraphQL field-suggestion enum (when introspection disabled) + alias batching + depth bypass | arsenal §22.9 |
| Always-on HTTP checks (15 paths: .git/.env/actuator/heapdump/etc.) | arsenal §16.5 |
| Missing security header audit (HSTS/CSP/XFO/etc.) | arsenal §16.4 |
| Endpoint extraction regex tiers (3 tiers) | arsenal §16.10 |
| Endpoint interest score (0–100 rubric) | arsenal §20 |
| JS deep analysis · sourcemap leakage · internal-host regex | arsenal §16.9, §16.11 |
| Subdomain takeover fingerprints (27 providers) | arsenal §16.12 |

### Cloud & Container

| Capability | Reference |
|---|---|
| Cloud bucket arsenal (S3 / GCS / Azure · 6 prefixes × 15 suffixes × 47 stems) | arsenal §16.8 |
| Cloud-native fingerprints (Lambda URLs · Cloud Run · Azure Functions · Vercel · Netlify · Workers) | arsenal §16.17 |
| Kubernetes / etcd / kubelet exposure (12 ports + probes) | arsenal §16.18 |
| Container registry leak hunting (Docker Hub · Quay · GHCR · ECR · GCR · ACR) | arsenal §16.18 |
| CI/CD platform exposure (Jenkins · GitLab · TeamCity-KEV · Argo CD · Spinnaker · CircleCI) | arsenal §16.19 |

### Secret & Credential Hunting

| Capability | Reference |
|---|---|
| 48-pattern secret-regex catalog (29 base + 19 modern) | arsenal §17 |
| Modern AI API keys (Anthropic / OpenAI / HuggingFace / Cloudflare) | arsenal §17 (rows 30-36) |
| Package-registry tokens (npm / PyPI / Docker Hub) | arsenal §17 (rows 38-40) |
| GitHub code-search dorks (13 templates) | arsenal §19 |
| 9 read-only credential validators (Postman / AWS / GitHub / Slack / Anthropic / OpenAI / npm / Atlassian / DataDog) | arsenal §23 |
| Post-discovery enumeration workflows (IAM enum · repo enum · workspace enum · JWT triage) | arsenal §23.12 |
| `secret_scan.py` runnable helper (stdlib-only, JSONL output) | arsenal §48 |
| 80+ dork corpus across 9 categories | arsenal §18 |

### Breach Intelligence

| Capability | Reference |
|---|---|
| HudsonRock Cavalier direct API (free; FYI: web-UI wraps a public JSON endpoint) | arsenal §15.0.1 |
| Domain-level breach severity mapping | arsenal §15.1 |
| `SSO_EXPOSURE` finding + legacy-mail-decommissioned escalation pattern | arsenal §15.2 |
| Breach × identity correlation (HudsonRock + HIBP + DeHashed + IntelX) | methodology §22 |

### Vendor & Edge-Appliance Fingerprinting

| Capability | Reference |
|---|---|
| Citrix Netscaler · F5 BIG-IP · Pulse Secure / Ivanti · FortiGate | arsenal §16.16 |
| PaloAlto GlobalProtect · Cisco AnyConnect · VMware vCenter / ESXi / Horizon | arsenal §16.16 |
| Microsoft Exchange OWA (ProxyShell / ProxyLogon / ProxyNotShell) | arsenal §16.16 |
| KEV CVE enrichment + EPSS scoring + Metasploit availability | arsenal §29.2 |
| WAF / CDN bypass + origin discovery (8 techniques) | methodology §27, arsenal §16.15 |

### Email Security

| Capability | Reference |
|---|---|
| SPF / DMARC / DKIM / BIMI / MTA-STS / TLS-RPT / DNSSEC audit (bash + PowerShell) | arsenal §16.14 |
| DMARC reporting-vendor inference (Kratikal / dmarcian / Valimail / Agari / EasyDMARC) | arsenal §16.14 |
| TXT verification token catalog (35+ SaaS tenants) | arsenal §16.22 |
| MX → IdP / mail-host inference | arsenal §16.14 |

### Human Intelligence

| Capability | Reference |
|---|---|
| LinkedIn employee enumeration (P0–P5 role tiers · sock-puppet hygiene) | arsenal §41 |
| Job posting tech-stack analysis (Lever · Greenhouse · AshbyHQ · Workable) | arsenal §42 |
| Slack / Discord / Telegram / Mattermost workspace discovery | arsenal §43 |
| Sat imagery for physical recon (Google Earth · NearMap · Sentinel Hub) | arsenal §45 |
| Email-pattern inference (8 templates) | arsenal §11 |

### Supply Chain

| Capability | Reference |
|---|---|
| Package-registry leak hunting (npm · PyPI · RubyGems · Cargo · Packagist · NuGet · Maven) | arsenal §44 |
| Typosquat surveillance | arsenal §44.10 |
| Postman public-workspace search (verified endpoint) | arsenal §24 |
| Stack Exchange OSINT sweep (8 sites) | arsenal §25 |

### Reporting & Deliverables

| Capability | Reference |
|---|---|
| Findings rubric (CRITICAL/HIGH/MED/LOW/INFO + escalation) | methodology §9 |
| Severity decision matrix (88 worked examples) | arsenal §40 |
| Attack-path hint patterns (27 templates) | arsenal §39 |
| Bug-bounty submission templates (HackerOne / Bugcrowd / Intigriti) | methodology §30 |
| Client deliverable templates (exec summary · risk-translation matrix · cadence) | methodology §31 |
| Reproduction package | methodology §3, §31 |

### Sector-Specific

| Capability | Reference |
|---|---|
| Healthcare (DICOM · HL7 v2 · FHIR · Epic / Cerner / Allscripts) | arsenal §47.1 |
| Finance (SWIFT · FIX · Bloomberg · Temenos / Finacle / FIS / Fiserv) | arsenal §47.2 |
| ICS / SCADA (Modbus · BACnet · Siemens S7 · DNP3 · EtherNet/IP) | arsenal §47.3 |
| IoT (MQTT · CoAP · UPnP · Hikvision / Dahua DVRs) | arsenal §47.4 |
| Government (`.gov` / `.mil` · FedRAMP · FISMA · CUI · SAM.gov) | arsenal §47.5 |

---

## Capability Mindmap

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'primaryColor':'#1e293b','primaryTextColor':'#f1f5f9','primaryBorderColor':'#475569','lineColor':'#94a3b8'}}}%%
mindmap
  root((claude-osint))
    osint-methodology
      Recon Pipeline
        5-stage flow
        Time budgeting (1h/4h/1d/1w)
        Engagement profiles
      Asset Graph
        29 typed asset types
        23 typed edges
        Per-asset triage rules
        Provenance tracking
      Findings Rubric
        CRITICAL/HIGH/MED/LOW/INFO
        88 worked examples
        Escalation rules
      Identity Fabric
        Entra / Okta / ADFS
        Google Workspace
        SAML / OIDC
        M365 deep mapping
      Breach Correlation
        HudsonRock
        HIBP / DeHashed
        IntelX / LeakCheck
        SSO_EXPOSURE finding
      WAF/CDN Bypass
        DNS history
        Cert SAN pivots
        Favicon mmh3
        JARM clustering
      Vuln Prioritization
        CVE / EPSS
        CISA KEV
        Metasploit availability
      Reporting
        Bug bounty templates
        HackerOne / Bugcrowd
        Client exec summary
        Risk translation matrix
        Reproduction package
      OpSec
        Sock puppets
        Persona rotation
        Detectability tagging
        Detection-aware backoff
    offensive-osint
      Probe Wordlists
        28 Swagger paths
        13 GraphQL paths
        35 high-risk ports
        15 always-on HTTP checks
        5 SAML metadata paths
        8 SSO prefixes
        Cloud bucket arsenal
        JS guess-paths
      Vendor Fingerprints
        Citrix Netscaler
        F5 BIG-IP
        Pulse Secure
        FortiGate
        PaloAlto GP
        Cisco AnyConnect
        VMware vCenter
        Exchange OWA
        KEV CVE map
      Cloud Native
        AWS Lambda URLs
        Cloud Run
        Azure Functions
        Vercel / Netlify
        Cloudflare Workers
      Container / K8s
        kubelet
        etcd
        K8s API
        Docker registries
        Helm Tiller
      CI/CD Exposure
        Jenkins script console
        GitLab self-hosted
        TeamCity (KEV)
        Argo CD / Spinnaker
        GitHub Actions leaks
      Secret Catalog (48)
        AWS keys
        AI APIs (Anthropic/OpenAI/HF)
        Package tokens (npm/PyPI/Docker)
        Cloudflare / DigitalOcean
        Atlassian / DataDog
        JWT / Bearer
        Private keys
      Dork Corpus (80+)
        Files / configs
        Admin panels
        Secrets / creds
        Cloud / CI shadow-IT
        Vuln indicators
        Sector-specific
      Read-Only Validators
        Postman PMAK
        AWS sts
        GitHub PAT
        Slack
        Anthropic / OpenAI
        npm / Atlassian / DataDog
      Identity Endpoints
        Entra getuserrealm
        Okta /api/v1/authn
        ADFS mex
        M365 SharePoint probe
        OneDrive personal site
        GraphQL field-suggestion
      Severity Matrix
        88 worked examples
        Attack-path hints
      Human Intel
        LinkedIn enum
        Job posting tech-stack
        Slack/Discord/Teams discovery
      Supply Chain
        npm / PyPI leaks
        Docker Hub / Quay / GHCR
        Typosquat surveillance
      Email Security
        SPF / DMARC / DKIM
        BIMI / MTA-STS
        DNSSEC
        DMARC vendor inference
      Sector Notes
        Healthcare HL7/FHIR
        Finance SWIFT/FIX
        ICS-SCADA Modbus
        IoT MQTT/CoAP
        Government CUI
      Tooling Quick-Install
        35+ tools
        12 categories
```

---

## Engagement Flow

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'primaryColor':'#1e293b','primaryTextColor':'#f1f5f9','primaryBorderColor':'#475569','lineColor':'#94a3b8'}}}%%
flowchart TD
    A["🎯 Target authorized<br/><i>RoE / BB scope / ASM contract</i>"] --> B[methodology §0-1<br/>scope check]
    B --> C[methodology §7<br/>5-stage pipeline]

    C --> D1["🔍 Stage 1<br/>Seed Discovery"]
    C --> D2["🌐 Stage 2<br/>Asset Expansion"]
    C --> D3["📊 Stage 3<br/>Enrichment"]
    C --> D4["⚠️ Stage 4<br/>Exposure Analysis"]
    C --> D5["📋 Stage 5<br/>Reporting"]

    D1 --> E1[arsenal §16.22 DNS catalog<br/>§16.21 WHOIS/RDAP<br/>§14 public records]
    D2 --> E2[arsenal §27 subdomain stack<br/>§16.24 prefix sweep<br/>§16.23 Wayback CDX]
    D3 --> E3[arsenal §16.16 vendor fp<br/>§22 identity fabric<br/>§28 infrastructure OSINT]
    D4 --> E4[arsenal §17 secret catalog<br/>§16.5 always-on checks<br/>§16.18 K8s exposure<br/>§23 read-only validators<br/>§15 breach × identity]
    D5 --> E5[methodology §9 severity rubric<br/>§30 BB submission<br/>§31 client deliverable]

    E1 --> F[methodology §8<br/>asset graph]
    E2 --> F
    E3 --> F
    E4 --> G["📋 Findings<br/>severity + confidence + evidence"]
    E5 --> H["📦 Deliverable<br/>exec summary + repro package"]

    F --> G

    style A fill:#3b82f6,color:#fff
    style B fill:#7c2d12,color:#fef3c7
    style C fill:#1e293b,color:#f1f5f9
    style F fill:#7c3aed,color:#fff
    style G fill:#dc2626,color:#fff
    style H fill:#14532d,color:#dcfce7
```

---

## Usage

### With Claude Code

```bash
# Install both skills (one-time, after clone)
git clone https://github.com/elementalsouls/Claude-OSINT.git
mkdir -p ~/.claude/skills
cp -r Claude-OSINT/skills/* ~/.claude/skills/
```

Then in any Claude Code session, ask an OSINT question — both skills auto-load and trigger on relevant phrases (50+ trigger phrases each).

### With the Claude Skills System

```bash
# Point Claude at a single skill before starting your session
cat skills/offensive-osint/SKILL.md | claude --system-file -
```

### Manual (Claude.ai / Claude API)

Paste the contents of any `SKILL.md` into a Project's system prompt or prepend it to your conversation. Both files are plain Markdown — also usable as a personal cheat-sheet without Claude.

---

## Authorization

These skills are intended for assets you **own** or have **written authorization to assess** (red-team rules of engagement, bug-bounty in-scope assets, ASM contracts).

Both skills include a soft scope-check when you ask Claude to act against an unverified third-party target. They explicitly **exclude** active exploitation, post-exploitation, malware development, and other activities beyond OSINT-driven reconnaissance. See [`SECURITY.md`](SECURITY.md) for the full posture.

---

## Documentation

| Doc | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Design philosophy · asset-graph model · confidence/severity/detectability models · sidecar coordination · diagrams |
| [`docs/coverage.md`](docs/coverage.md) | Honest practitioner-coverage breakdown by archetype + engagement phase |
| [`docs/installation.md`](docs/installation.md) | Symlink installs and multi-environment install patterns |
| [`docs/usage.md`](docs/usage.md) | Trigger-phrase reference and prompt templates |
| [`examples/`](examples/) | 4 end-to-end engagement walk-throughs (quick recon · bug-bounty · M365 deep · secret hunting) |
| [`tests/smoke-test-prompts.md`](tests/smoke-test-prompts.md) | 32-prompt self-evaluation suite (current grade: 31/32 PASS) |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Pull-request guidelines |

---

## About

Operational tradecraft accumulated across external attack-surface engagements, codified into Claude skills. Engagement-platform agnostic — slot into any ASM / ticketing / asset-graph platform you already use, or none.

**Author:** [ElementalSoul](https://github.com/elementalsouls)
**Original framework:** [SnailSploit/offensive-checklist](https://github.com/SnailSploit/offensive-checklist) (v1.x)
**Inspired by:** [Bellingcat's Online Investigations Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/) · [IntelTechniques](https://inteltechniques.com/tools/) · [OSINT Framework](https://osintframework.com/)
**Tool inventory:** [ProjectDiscovery](https://github.com/projectdiscovery) · [Six2dez reconftw](https://github.com/six2dez/reconftw) · [SecLists](https://github.com/danielmiessler/SecLists) · [Assetnote Wordlists](https://wordlists.assetnote.io/)
**License:** [MIT](LICENSE) — use freely, attribution appreciated.

---

> *"Give Claude the right skill and it stops being a chatbot. It becomes an operator."*
