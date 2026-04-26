# Architecture & Design Philosophy

## The two-skill split

The skills are deliberately split into **methodology** ("how to think") and **arsenal** ("what to reach for"). This reflects two different mental modes practitioners use:

- **Methodology mode** — "I have a target. How do I approach this?" → strategic + procedural.
- **Arsenal mode** — "I need a Swagger probe path / secret regex / curl one-liner." → tactical + reference.

A single mega-skill of ~5,500 lines would have noisier triggering and worse retrieval. The split lets each skill have a tight, distinct trigger vocabulary.

```
Most prompts pull both. They're complementary, not overlapping.

  USER ASKS: "How do I find an origin behind Cloudflare?"
       │
       ├── methodology §27 (the technique catalog + confidence rules)
       │
       └── arsenal §16.15 (the actual curl commands)
```

## Confidence model

Every assertion carries a graded confidence level:

```
TENTATIVE  →  FIRM  →  CONFIRMED
   ▲           ▲          ▲
   │           │          │
   1+ source   2+ src.    Verified
   inferred    OR direct  AND multiple
   pattern     observed   independent
                          corroborations
```

Per-asset-type upgrade workflows in `methodology` §2.1 specify exactly what evidence moves an asset between levels.

## Severity model

Severity is **operational**, anchored on examples. The methodology rubric (§9) defines tiers:

```
CRITICAL → Pre-auth RCE / valid creds / listable prod data / fundamental trust violations
HIGH     → Sourcemap, open GraphQL introspection, takeover, reflected CORS+creds, exposed admin UI
MEDIUM   → Missing headers, info disclosure, hardening gaps, brute-force exposure
LOW      → Cosmetic, marginal hardening
INFO     → Recordable, no immediate action
```

The arsenal severity matrix (§40) provides 80+ worked examples for triage. Escalation rules cover special cases (HSTS missing on `/login` → MED→HIGH, etc.).

## Detectability model

Every probe carries a detectability tag:

```
LOW    → Passive sources (CT logs, Wayback, Shodan InternetDB, Hunter.io, etc.)
MEDIUM → Targeted probes (user-enum, validator queries, GraphQL probes, screenshots)
HIGH   → Active scans (port scans, Nuclei full templates, web fuzzing, brute-force)
```

The detection-aware probing section (`methodology` §6.4) provides the back-off ladder for when you start hitting active defenses.

## Asset graph model

```
              ┌──────────┐
              │  Domain  │
              └─────┬────┘
                    │ ALIAS_OF / RESOLVES_TO
              ┌─────▼────┐
              │Subdomain │◀──────HOSTED_ON─────┐
              └─────┬────┘                     │
                    │ RESOLVES_TO              │
              ┌─────▼────┐  IN_NETBLOCK   ┌────┴───┐
              │   IP     ├───────────────▶│  ASN   │
              └─────┬────┘                └────────┘
                    │ EXPOSES
              ┌─────▼────┐    DOCUMENTED_BY  ┌──────────┐
              │  WebApp  ├──────────────────▶│  ApiSpec │
              └─────┬────┘                   └──────────┘
                    │ CONTAINS_SECRET
              ┌─────▼────┐
              │  Secret  │◀──BREACHED_FROM──┐
              └──────────┘                  │
                                       ┌────┴─────┐
                                       │  Email   │◀──EMPLOYED_BY── Person
                                       └──────────┘
```

29 asset types organized in 9 categories. 23 typed edges. Discipline: every discovery is a typed asset (never a free-floating string), with provenance tracked.

## Output schema

Findings are structured for ingestion by asset-management tools:

```yaml
Finding:
  id:           <stable hash or UUID>
  module:       <which technique discovered it>
  asset_key:    <typed asset key, e.g., sub:api.example.com>
  category:     <e.g., SECRET_LEAK, OPEN_GRAPHQL_API, SSO_EXPOSURE>
  severity:     critical | high | medium | low | info
  confidence:   confirmed | firm | tentative
  title:        <one-line summary>
  description:  <2-5 sentences>
  evidence:
    url:        <where it was found>
    timestamp:  <UTC ISO8601>
    sha256:     <hash of any artifact>
    raw:        <truncated to 2 KiB>
  references:
    - <CVE-ID, advisory URL, vendor doc>
  remediation:  <action the asset owner can take>
```

This shape is portable to any asset / findings store (Falcon-Recon, ASM platforms, ticketing systems, custom DBs).

## Cross-module sidecar coordination

When techniques produce outputs that feed other techniques, sidecar JSON files enable late binding:

```
┌──────────────────────┐    writes      ┌──────────────────────┐
│ mobile_attack_surface│───────────────▶│ mobile_endpoints.json│
└──────────────────────┘                └─────────┬────────────┘
                                                  │ reads
                                                  ▼
                                        ┌──────────────────────┐
                                        │   api_discovery      │
                                        └──────────────────────┘
```

Patterns documented in `methodology` §24.2.

## Validator discipline

Credential validators are **read-only by design**. Never destructive.

```
Discovery → Validation → Scope-enum → Attack-path-hint
   (catalog    (read-only    (read-only     (operator
   regex)      /me, /user,   IAM enum,      pivots from
               auth.test)    repo enum,     here)
                             workspace
                             enum)
```

9 providers covered (Postman, AWS, GitHub, Slack, Anthropic, OpenAI, npm, Atlassian, DataDog). Hard rule: never create / delete / send. Tag every validation with detectability + `checked_at`.

## Trigger frontmatter discipline

Each skill declares ~50–110 trigger phrases in YAML frontmatter. Triggers are:

- The exact wording a user would type (`kubelet exposed`, not `Kubernetes Kubelet API exposure on port 10250`).
- Inclusive of common synonyms (`SSO discovery`, `IdP fingerprinting`, `tenant fingerprinting` all map to identity-fabric work).
- Domain-specific jargon (`JARM`, `mmh3`, `BGP`, `KEV`).
- Operator slang (`grease the rails`, `pop the recon`).

## Versioning

Semantic versioning. The `version:` field in YAML frontmatter is authoritative.

- **MAJOR** — section renumbering, breaking trigger changes, schema changes to Finding output.
- **MINOR** — new sections, new techniques, expanded catalogs.
- **PATCH** — typo fixes, link updates, severity-tier corrections.

Current: `2.1`.

## Renumbering policy

When new top-level sections are added in a minor release, existing sections may renumber. The CHANGELOG records mappings (e.g., "v2.0 §27 Self-Test → v2.1 §32 Self-Test").

Subsection numbering is generally additive (§7.6 added without renumbering §7.5).

## What's deliberately excluded

By design, the skills do NOT cover:

- **Active exploitation** (PoC code, exploit chains)
- **Post-exploitation** (lateral movement, privesc, persistence)
- **Active Directory** (BloodHound, Kerberoasting, SMB relay)
- **Malware development** (payload crafting, AV/EDR evasion)
- **C2 frameworks** (Cobalt Strike, Sliver, Mythic, Havoc)
- **Real PII / credentials / breach corpus content** in examples
- **Defensive / blue-team detection** content (different domain)
- **Pricing / NDA / SOW templates** (business operations, not technical)

These exclusions are intentional. A "comprehensive offensive security" skill would be a textbook, not a focused tool. We'd rather do one thing well than many things adequately.

## Why pair with Falcon-Recon?

These skills were extracted from the operational tradecraft of [Falcon-Recon](https://github.com/<your-username>/falcon-recon), an external attack-surface management platform. The 90+ modules in these skills correspond closely to Falcon-Recon's implemented techniques, but generalized so they apply to any OSINT engagement (with or without Falcon-Recon).

Use the skills standalone, or use them alongside Falcon-Recon (or any ASM platform) to drive your engagement.
