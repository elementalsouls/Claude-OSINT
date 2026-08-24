---
name: org-attack-surface
description: "Org-grade attack-surface mapping: given a company's legal identity, discover its ENTIRE owned internet footprint — corporate family -> owned domains -> owned netblocks/ASN -> live assets — with attribution discipline, not just DNS breadth. The org-first attribution pyramid (legal entity -> LEI/registration -> corporate family -> owned domains -> owned netblocks/ASN -> live assets). Corporate-identity resolution via the GLEIF LEI API (legal name -> LEI, exact-LEI direct-children expansion, downward-only depth-capped BFS, NEVER a name re-resolution), SEC-EDGAR full-text search + Exhibit-21 subsidiary entity names, OpenCorporates entity corroboration, Wikidata SPARQL corporate graph (P856/P355/P749/P1830). Domain attribution via reverse-WHOIS (WhoisXML preview-then-purchase quota guard, SecurityTrails associated-domains — both paid), crt.sh O= certificate-transparency organization pivot (keyless), infrastructure correlation (shared NS/MX/SaaS-TXT, netblock membership, reverse-DNS PTR), and the independent-evidence combiner (1-prod(1-w_i), rule of three, OwnerTier NONE/WEAK/MODERATE/STRONG/CONFIRMED) — discover-only `related:` candidates are NEVER auto-scanned. Netblock/ASN attribution via org-first RIR queries (ARIN Whois-RWS org-handle search, RIPE DB organisation + inverse-org search) that recover 'dark netblocks' with no DNS link to the seed, ASN discovery (RIPEstat + BGPView union), the HYPERSCALER-SCOPE GUARD (never attribute a whole AWS/GCP/Azure/Cloudflare announced range to a tenant — keep only the seed-containing block, tag shared_hosting_cdn), and org-identity-seeded internet-scan-index queries (Shodan/Censys/ZoomEye/FOFA/BinaryEdge org: filters + an always-on keyless crt.sh fallback). Promote-to-scan triage ranks forgotten discover-only netblocks by remote-access exposure (gateway-vendor/KEV/control-plane/datastore port scoring) into an operator queue. Attribution confidence rubric + anti-patterns (namesake grafting via GLEIF name re-resolution, single-signal ownership, hyperscaler over-attribution, privacy-WHOIS pivot poisoning, RIR org-name collisions). Passive/keyless-first OSINT only — every paid-key dependency is enrichment on top of a keyless core, never a hard requirement. Use when mapping an organization's full corporate-family internet footprint, resolving a legal entity to its LEI/subsidiaries, discovering domains/netblocks/ASNs an org owns beyond its one seed domain, auditing M&A/shadow-IT sprawl, or scoping an engagement that starts from a company NAME rather than a domain."
version: 1.0
sources: asm_reference_impl, gleif, public_research
triggers:
  - org attack surface
  - organization attack surface
  - org footprint
  - corporate footprint
  - corporate family
  - corporate family mapping
  - corporate family tree
  - subsidiary discovery
  - subsidiary attack surface
  - subsidiary mapping
  - GLEIF
  - LEI lookup
  - legal entity identifier
  - legal name to LEI
  - EDGAR subsidiary
  - SEC EDGAR
  - Exhibit 21
  - 10-K subsidiaries
  - OpenCorporates
  - Wikidata corporate graph
  - reverse WHOIS
  - reverse whois pivot
  - crt.sh organization search
  - crt.sh O=
  - certificate transparency org pivot
  - CT org pivot
  - dark netblock
  - org-first RIR search
  - ARIN Whois-RWS
  - ARIN org search
  - RIPE DB search
  - RIPE organisation search
  - RDAP entity search
  - ASN discovery
  - BGPView
  - RIPEstat
  - hyperscaler scope guard
  - cloud netblock over-attribution
  - shared hosting CDN attribution
  - AWS netblock attribution
  - M&A footprint
  - M&A attack surface
  - shadow IT discovery
  - promote to scan
  - discover-only candidate
  - org identity resolution
  - corporate identity resolution
  - owned netblock discovery
  - owned ASN discovery
  - org index search
  - outward identity search
  - identity-seeded discovery
  - attribution confidence
  - ownership tier
  - owner signal
  - independent evidence combiner
  - rule of three attribution
  - namesake grafting
  - org tree walk
  - subsidiary entity pivot
  - registrant org pivot
  - WHOIS privacy pivot
  - Shodan org filter
  - Censys organization filter
  - company name to attack surface
---

# Org Attack Surface — Corporate-Family Footprint Mapping

> Companion skills: [`osint-methodology`](../osint-methodology/) (the "how to think" 5-stage recon
> pipeline this plugs into) and [`offensive-osint`](../offensive-osint/) (the per-host arsenal you run
> once this skill hands you owned domains/netblocks — see its §14 Public Records and §28 Infrastructure
> OSINT for the tool directory this skill deepens rather than duplicates). This skill answers a
> different, upstream question: **not** "what does `acme.com` expose", but "what does **Acme
> Corporation, the legal entity**, own across every domain, netblock, and subsidiary it has — including
> the parts with no DNS trail back to the seed at all."

## 0. When to Use / When NOT

**Use this skill when:**

- The engagement starts from a **company name or legal entity**, not a domain — you need to derive
  the domain(s) first, not just enumerate one.
- You need to find an org's **subsidiaries, sister brands, or M&A-acquired footprint** that a
  DNS/CT-only sweep of one seed domain would never surface.
- You suspect **"dark" IP space** — netblocks or ASNs registered to the org's legal entity with
  no DNS record pointing at them (forgotten datacenter allocations, un-linked M&A infrastructure,
  IPs that only ever ran raw services).
- You need **attribution discipline**: every candidate domain/netblock/ASN this skill surfaces
  carries an explicit, auditable ownership score — never a bare "looks related."
- You are scoping a large or conglomerate engagement and need to prune scope by real corporate
  ownership before spending recon budget on strangers.

**Do NOT use this skill when:**

- You already have a confirmed, bounded target list and just need per-host recon — go straight to
  `offensive-osint`.
- The target's authorization isn't established — see §1.
- You need active exploitation or post-exploitation — out of scope here and everywhere in this
  skill family.

---

## 1. Authorization & Legal Posture

Same posture as the companion skills: intended for assets the operator owns or has **written
authorization** to assess. This skill is unusually likely to surface entities the operator did NOT
ask about (subsidiaries, sister brands, M&A targets) — that is the point, but it sharpens the scope
question rather than loosening it.

**Soft scope check** — ask once when unclear:
> *"This will surface the target's subsidiaries and related infrastructure, some of which may be
> outside your engagement scope. Should I include the full corporate family, or stay bounded to the
> named entity and its direct domains?"*

**Always-on guardrail specific to this skill:** every asset this skill discovers beyond the seed
domain — related domains, dark netblocks, discover-only ASNs, index-search IPs — is a **lead**, not
a target. See §6.6 and every "discover-only" callout below. Nothing this skill produces is
automatically in scope for active testing; a human confirms ownership first.

---

## 2. Confidence Levels & Ownership Tiers (two axes — do not conflate them)

This skill runs **two separate scoring axes**, and mixing them up is the single most common way to
misreport a finding.

**Axis 1 — Finding confidence** (same as the companion skills): TENTATIVE / FIRM / CONFIRMED.
Answers *"how sure am I this asset/record exists and I read it correctly."*

**Axis 2 — Ownership tier**: answers *"how sure am I this asset belongs to the target
organization."* Computed by combining every `OwnerSignal` that fired for a candidate via an
independent-evidence formula (full mechanics in §8.4):

| Score band | Tier | Meaning |
|---|---|---|
| 0 | `NONE` | No signal fired. |
| 0–39 | `WEAK` | One low-weight signal (e.g. shared nameserver) — a lead, not attribution. |
| 40–69 | `MODERATE` | Multiple weak signals, or one medium signal — worth an operator's eyeball. |
| 70–89 | `STRONG` | Multiple independent signals, or one high-confidence signal — an active-scan-eligible score in a typical ASM promotion gate. |
| 90–100 | `CONFIRMED` | Independent corroboration close to certainty, or a **confirming** signal (e.g. the seed domain itself) that forces 100 directly. |

**A `NOT_OWNED` (stranger-lock) signal caps the score at 20 regardless of how many weak positives
also fired** — so a foreign asset that happens to share a generic nameserver with the seed can never
climb into an owned tier.

**Critical nuance:** ownership tier is advisory, not a gate. Every domain/netblock/ASN/IP this skill
mints beyond the seed carries an explicit **`discover_only=True`** structural flag that keeps it out
of active scanning **independent of its score** — a `related:` domain that happens to score
`STRONG` (85) still does not get auto-scanned. The score tells the operator *which* discover-only
lead to promote first; only an explicit operator action (§10, promote-to-scan) moves an asset into
the active pipeline.

**Rule of three still applies** on top of the numeric score: a single signal type, however
individually weighted, is a lead. Treat anything below `STRONG` as requiring a second, independent
signal class before you say it out loud to a client as "this belongs to them."

---

## 3. Output Format

Every candidate carries the standard finding schema (see companion skill §3) **plus** the
org-attribution evidence block:

```
Finding:
  id:          <stable hash>
  module:      org-attack-surface
  asset_key:   <typed key — e.g. org:acme-corp, related:acmesub.com, net:203.0.113.0/24, asn:64500>
  category:    ORG_FOOTPRINT | RELATED_DOMAIN | DARK_NETBLOCK | PROMOTE_QUEUE
  severity:    info                      # attribution work is discovery, not a vuln — see §6.6
  confidence:  <tentative|firm|confirmed>   # Axis 1 — did I read the record right
  title:       <one-line summary>
  description: <what was found + why it's plausibly the org's>
  attribution:
    owner_score:    <0-100>              # Axis 2 — combine() output
    owner_tier:      <none|weak|moderate|strong|confirmed>
    discover_only:   true                # structural gate; independent of owner_score
    signals:
      - name:       <signal name, e.g. cert_org_match>
        weight:      <0.0-1.0>
        confirming:  <bool>
        detail:      <human-readable evidence, e.g. "crt.sh O= match: Acme Corp">
        source:      <module/connector>
  evidence:
    url:       <where found>
    timestamp: <UTC ISO8601>
    raw:       <truncated to 2 KiB>
  references:  [<registry URL, RFC, etc.>]
  remediation: <"confirm ownership before promoting to active scan" — always the remediation here>
```

UTC timestamps everywhere. Never collapse `attribution.signals` to a bare count — the reviewing
operator (or an auditor asking "why did you attribute this to them") needs to see exactly which
evidence fired, not just how much.

---

## 4. Source Hygiene & Citations

Same discipline as the companion skills: URL + UTC timestamp + tool/API version + run_id on every
artifact. For registry lookups specifically:

- Record the **exact query string** sent to GLEIF/EDGAR/ARIN/RIPE — registry search results are not
  reproducible from a vague "I searched for the company" note months later.
- Cache raw registry JSON responses (GLEIF, ARIN, RIPE, EDGAR) — these APIs change/deprecate fields
  and a re-run six months later may not reproduce the same shape.
- GLEIF LEI records and EDGAR filings are durable references (an LEI or CIK doesn't expire); prefer
  citing those over an ephemeral index-search hit.

---

## 5. Do NOT

- Do NOT auto-scan a `related:` domain, a `discover_only` netblock/ASN, or a `discover_only` IP.
  Ever. That is the entire structural contract of this skill (§2, §6.6).
- Do NOT re-resolve a subsidiary's name against GLEIF/EDGAR/OpenCorporates once you already hold its
  exact LEI or CIK — name search is not unique across jurisdictions and will graft a namesake's
  subtree onto the wrong parent (§7.1, §11.1).
- Do NOT treat a shared nameserver, shared MX, or a brand string in an ASN org field as ownership.
  Each is `WEAK`-tier at best and needs corroboration (§11.1).
- Do NOT attribute an entire hyperscaler-announced ASN range (AWS/GCP/Azure/Cloudflare/Akamai) to a
  tenant because one of the tenant's IPs lives in it (§9.5 — the hyperscaler-scope guard).
- Do NOT pivot on a privacy-masked WHOIS registrant org or a registrar's own name/email — the
  pivotability guards in §8.1/§8.3 exist because these produce thousands of unrelated false
  positives.
- Do NOT treat a fuzzy label match (Wikidata `rdfs:label`, an ASN holder substring match) as
  equivalent evidence to a filed registry record (a GLEIF LEI relationship, an EDGAR Exhibit-21
  entry, an exact RIR org-handle match). Weight them accordingly (§8.4's signal table).
- Do NOT paste real registrant PII, private beneficial-ownership data, or engagement-client identity
  details into cloud LLMs beyond what's needed for the recon task itself.

---

## 6. The Org-First Attribution Pyramid

The mental model for everything in this skill. Most recon starts **bottom-up** from a seed domain
and walks outward (subdomains, then IPs, then maybe an ASN). That misses everything that has no DNS
trail back to the seed. This skill also walks **top-down**, starting from the legal entity itself:

```
                    ┌─────────────────────────┐
                    │   LEGAL ENTITY (name)    │  §7 — the anchor: WHOIS registrant_org,
                    │   → LEI / registration    │        the seed's own TLS cert O=, or a
                    └────────────┬─────────────┘        seed-owned ASN holder string
                                 │
                    ┌────────────▼─────────────┐
                    │    CORPORATE FAMILY        │  §7.1-7.4 — GLEIF direct-child tree,
                    │  (subsidiaries, M&A)       │        EDGAR Exhibit-21, OpenCorporates,
                    └────────────┬─────────────┘        Wikidata P355/P749/P1830
                                 │
              ┌──────────────────┴──────────────────┐
              ▼                                      ▼
  ┌───────────────────────┐            ┌───────────────────────────┐
  │   OWNED DOMAINS         │            │  OWNED NETBLOCKS / ASN      │
  │  (seed + related:)      │            │  (seed-owned + dark)         │
  └───────────┬─────────────┘            └─────────────┬───────────────┘
              │  §8 — reverse-WHOIS, crt.sh O=,          │  §9 — org-first RIR (ARIN/RIPE),
              │  infra correlation, independent-           bottom-up ASN (RIPEstat/BGPView),
              │  evidence combiner                          hyperscaler-scope guard
              └──────────────────┬──────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │       LIVE ASSETS          │  hand off to `offensive-osint` once
                    │  (hosts, services, apps)   │  ownership is operator-confirmed
                    └─────────────────────────┘
```

### 6.1 Why top-down closes gaps bottom-up misses

A DNS/CT-only sweep of `acme.com` will find `mail.acme.com`, `api.acme.com`, subsidiaries that
happen to share the parent's nameservers — and nothing else. It will **never** find:

- A subsidiary acquired in an M&A deal that still runs on its own pre-acquisition domain, nameservers,
  and netblocks, with zero DNS/cert linkage to `acme.com`.
- A netblock registered directly to "Acme Corporation" at ARIN or RIPE that has never had a single A
  record point into it — a forgotten datacenter allocation, or IP space used only for raw
  non-DNS-fronted services.
- A brand's cloud footprint that shows up in Shodan/Censys under `org:"Acme Corp"` with no DNS name at
  all — a bare IP serving a banner with the org string baked into a TLS cert or ASN registration.

Each of these requires **starting from the org identity itself** and querying registries/indexes by
*who owns it*, not *what resolves from the seed*. That is what §7–§9 do.

### 6.2 Discovery direction cheat sheet

| Direction | Seeded from | Finds | Section |
|---|---|---|---|
| Top-down: entity → subsidiaries | Legal name / LEI | Corporate family tree | §7 |
| Top-down: entity → domains | Registrant org / cert O= string | Related root domains | §8 |
| Top-down: entity → netblocks/ASN | Org identity string | Dark netblocks, registered ASNs | §9.1–§9.4 |
| Top-down: entity → live IPs | Org identity string | No-DNS live hosts (index search) | §9.6 |
| Bottom-up: seed IP → ASN | Resolved seed IPs | Announced prefixes, adjacent infra | §9.3 |

Both directions run in the same pipeline and reconcile through the same ownership-scoring axis
(§2, §8.4) — a bottom-up-discovered netblock and a top-down-discovered netblock get scored the same
way and land in the same graph.

---

## 7. Corporate Identity Resolution

### 7.1 GLEIF LEI API — the corporate-family tree

The Global Legal Entity Identifier Foundation publishes, **keyless**, the filed parent/child
relationships between legal entities under ISO 17442 LEIs. This is the highest-precision source in
this entire skill because relationships are *filed*, not inferred.

**Two-hop query pattern:**

1. Resolve a legal name → LEI (only ever done for the **seed** — see why below):

   ```bash
   LEI=$(curl -sk "https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=Acme%20Corporation&page[size]=1" \
     -H "Accept: application/vnd.api+json" | jq -r '.data[0].attributes.lei')
   echo "$LEI"   # capture it — the next step reuses $LEI
   ```

   ```powershell
   $r = Invoke-RestMethod -Uri "https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=Acme%20Corporation&page[size]=1" `
       -Headers @{ Accept = "application/vnd.api+json" }
   $lei = $r.data[0].attributes.lei
   ```

2. Fetch that LEI's **direct children** (one level down, filed relationships only):

   ```bash
   curl -sk "https://api.gleif.org/api/v1/lei-records/$LEI/direct-children?page[size]=100" \
     -H "Accept: application/vnd.api+json" | \
     jq -r '.data[].attributes | .lei + "  " + .entity.legalName.name'
   ```

   ```powershell
   $children = Invoke-RestMethod -Uri "https://api.gleif.org/api/v1/lei-records/$lei/direct-children?page[size]=100" `
       -Headers @{ Accept = "application/vnd.api+json" }
   $children.data | ForEach-Object { "$($_.attributes.lei)  $($_.attributes.entity.legalName.name)" }
   ```

**Recurse for a multi-level tree — but with two non-negotiable rules:**

1. **Downward-only.** Only ever ask for a LEI's direct children — never ascend to the ultimate
   parent and fan into its siblings. Ascending turns "map Acme's subsidiaries" into "map every
   company under Acme's ultimate holding conglomerate," which is a different (much larger, mostly
   irrelevant) question the operator did not ask.
2. **Exact-LEI expansion for every descendant, name resolution ONLY for the seed.** Once you have a
   child's own filed LEI from step 2's response, expand *that entity's* children via
   `/lei-records/<child-LEI>/direct-children` directly — never by searching its **name** again.

   **Why this matters:** `filter[entity.legalName]=` is a name search, and legal names are **not
   unique across jurisdictions**. If entity B (a direct child of your seed) shares a name with an
   unrelated entity B' in another country, re-resolving "B" by name can silently return B' — and
   you then graft B''s entire subsidiary subtree onto your target's corporate family, under an
   authoritative-looking GLEIF badge. Carrying the exact LEI through the recursion makes this
   collision structurally impossible.

**Depth and fan-out caps (recommended, mirrors the production implementation):**

| Cap | Suggested value | Why |
|---|---|---|
| Max recursion depth | operator-set; default OFF, 1 level for a "deep" pass | Depth grows the tree exponentially with fan-out; an unbounded walk on a conglomerate never terminates in a useful time. |
| Max nodes minted total | ~200 | Global budget; a capped tree must be flagged as truncated, never silently rendered as complete. |
| Max direct children expanded per parent | ~50 | A parent with hundreds of filed subsidiaries (a large holding company) would otherwise dominate the whole budget. |

**When either cap is hit, flag the affected parent node (`children_truncated`) rather than silently
dropping the rest of its children** — an operator reading a "complete-looking" corporate tree that
was actually cut off is worse than one that visibly says "and N more, not expanded."

**Cycle safety:** track visited LEIs; a diamond ownership structure (A owns B and C, both B and C own
D) should mint D once, under whichever parent reaches it first — not twice, and not infinitely.

### 7.2 SEC-EDGAR — Exhibit-21 subsidiary lists

US-listed companies' 10-K filings include Exhibit 21, a list of subsidiary entity names. EDGAR's
full-text search surfaces filings; you extract entity names, not domains — EDGAR asserts *"this
subsidiary exists,"* not *"this subsidiary owns this URL."*

```bash
curl -sk 'https://efts.sec.gov/LATEST/search-index?q=%22Acme%20Corporation%22&forms=10-K' \
  -H "User-Agent: YourOrg-Recon research@yourdomain.example" | \
  jq -r '.hits.hits[]._source.display_names[]'
```

```powershell
$headers = @{ "User-Agent" = "YourOrg-Recon research@yourdomain.example" }
$r = Invoke-RestMethod -Uri 'https://efts.sec.gov/LATEST/search-index?q=%22Acme%20Corporation%22&forms=10-K' -Headers $headers
$r.hits.hits | ForEach-Object { $_._source.display_names }
```

**Caveats:**

- **Response shape is documented, not guaranteed** — EFTS full-text search returns *filing-level*
  metadata under `_source` (`display_names`, `ciks`, `form`, …), so `display_names` are the filer /
  co-filer entity names on matching 10-K filings — **corroboration that the entity files with the
  SEC**, not a ready-made subsidiary roster. True subsidiary lists live inside the filing's
  **Exhibit 21** document, which you fetch separately from the filing (not from the search index).
  Verify the field against a live response before trusting a parse.
- SEC requires a **descriptive User-Agent identifying you** (name + contact) on every request — a
  bare `curl` UA gets throttled/blocked. This is SEC's own fair-access policy, not a tooling
  quirk.
- **US-SEC-filer-only.** Empty for any org that doesn't file 10-Ks (non-US, private, or a subsidiary
  itself rather than the filer). Treat a null result as "not applicable," not "no subsidiaries."
- Entity names from EDGAR feed the **depth-1 entity→domain pivot** (§8.5) — you take each returned
  name and pivot it through crt.sh O=, capped, to find candidate domains for that specific
  subsidiary.

### 7.3 OpenCorporates — entity corroboration (not domain discovery)

OpenCorporates confirms *"is this a real registered company, and in what jurisdiction"* — it does
not supply domains at all. Use it to corroborate a candidate subsidiary name found elsewhere (GLEIF,
EDGAR, a press release) before spending a crt.sh pivot on it.

```bash
curl -sk "https://api.opencorporates.com/v0.4/companies/search?q=Acme+Corporation" | \
  jq -r '.results.companies[].company | "\(.jurisdiction_code)  \(.name)"'
```

```powershell
$r = Invoke-RestMethod -Uri "https://api.opencorporates.com/v0.4/companies/search?q=Acme+Corporation"
$r.results.companies | ForEach-Object { "$($_.company.jurisdiction_code)  $($_.company.name)" }
```

**Caveat:** the free/keyless tier is aggressively rate-limited (single-digit requests/day in
practice) — treat it as a spot-check corroboration source, not a bulk enumeration one. A paid
API token raises the quota but is not required for the core workflow.

### 7.4 Wikidata SPARQL — the public corporate graph

Wikidata models corporate relationships as structured properties. Four are relevant:

| Property | Meaning |
|---|---|
| `P856` | official website |
| `P355` | subsidiary (parent → child) |
| `P749` | parent organization (child → parent) |
| `P1830` | owner of / owned by (bidirectional) |

Query: find the seed entity (by official-website URL match or by label), traverse
`P355`/`P749`/`P1830` in both directions to related entities, then read **their** `P856` website —
reduced to a registrable root domain.

```bash
curl -sk -G "https://query.wikidata.org/sparql" \
  -H "Accept: application/sparql-results+json" \
  -H "User-Agent: YourOrg-Recon research@yourdomain.example" \
  --data-urlencode 'query=SELECT DISTINCT ?website WHERE {
    { ?mainEntity wdt:P856 ?siteUrl . FILTER(CONTAINS(STR(?siteUrl), "acme.com")) }
    UNION { ?mainEntity rdfs:label "Acme Corporation"@en . }
    { ?mainEntity wdt:P355 ?related . } UNION { ?mainEntity wdt:P749 ?related . }
    UNION { ?mainEntity wdt:P1830 ?related . } UNION { ?related wdt:P749 ?mainEntity . }
    UNION { ?related wdt:P1830 ?mainEntity . }
    ?related wdt:P856 ?website .
  } LIMIT 50' | jq -r '.results.bindings[].website.value'
```

```powershell
$query = @'
SELECT DISTINCT ?website WHERE {
  { ?mainEntity wdt:P856 ?siteUrl . FILTER(CONTAINS(STR(?siteUrl), "acme.com")) }
  UNION { ?mainEntity rdfs:label "Acme Corporation"@en . }
  { ?mainEntity wdt:P355 ?related . } UNION { ?mainEntity wdt:P749 ?related . }
  UNION { ?mainEntity wdt:P1830 ?related . } UNION { ?related wdt:P749 ?mainEntity . }
  UNION { ?related wdt:P1830 ?mainEntity . }
  ?related wdt:P856 ?website .
} LIMIT 50
'@
$r = Invoke-RestMethod -Uri "https://query.wikidata.org/sparql" -Body @{ format = "json"; query = $query } `
    -Headers @{ Accept = "application/sparql-results+json" }
$r.results.bindings | ForEach-Object { $_.website.value }
```

**Caveat — score this WEAKER than a filed registry record.** A Wikidata label match is a best-effort
fuzzy match (`rdfs:label "X"@en`), not a filed legal assertion. Two unrelated companies sharing a
common name will both match the label filter. In the signal weighting (§8.4), a Wikidata hit is
explicitly non-confirming and weighted below a direct registry-listed match — it corroborates, it
does not confirm alone.

### 7.5 Minting the seed org identity node

Before any of the above is useful, anchor a **seed org identity** — the node every subsidiary and
every scored candidate attaches to. Priority order:

1. **WHOIS `registrant_org`** — but only when it is not privacy-masked (§8.1's `is_pivotable_org`
   guard) and not a registrar's own name ("Domains By Proxy," "WhoisGuard," etc.). A privacy-masked
   WHOIS record is *not* the target's identity — it's the privacy service's — and minting the seed
   org from it would confirm-own the wrong entity for the rest of the walk.
2. **A seed-owned ASN holder string** — from bottom-up ASN discovery (§9.3): if one of the seed's own
   resolved IPs sits in an ASN whose registrant name matches a target brand, that holder string is a
   valid identity source (RIR data, not WHOIS privacy, so it survives even when WHOIS itself is
   masked).
3. **The seed's own leaf TLS certificate `O=` field** — one GET to the seed's own domain (never a
   third party), reading the certificate subject organization. Often the most reliable source in
   practice: WHOIS is frequently redacted, but a company's own production TLS cert commonly still
   carries its legal name in `O=`.

**Do not mint a seed org identity from a bare brand stem alone** (e.g. just `"acme"` from
`acme.com` with no other corroboration) — that is exactly the kind of low-precision namesake risk
this whole skill exists to avoid. If none of the three sources above produce a usable identity
string, degrade gracefully: report "no confirmable legal identity found; corporate-family and
netblock discovery skipped" rather than guessing from the domain name.

Once anchored, keep every alias (WHOIS org string, ASN holder string, cert O= string) attached to
the same node — later stages (§9.1's RIR query, §9.6's index search) query by every alias, not just
the primary name, since a company frequently registers infrastructure under a legal-name variant
that differs from its WHOIS string.

---

## 8. Domain Attribution

### 8.1 reverse-WHOIS — paid, quota-guarded

Reverse-WHOIS ("show me every domain registered by X") is the most direct domain-attribution
technique and the **one part of this skill with no keyless path** — both practical providers
(WhoisXML, SecurityTrails) require a paid key. Treat it as enrichment on top of the keyless core
(§8.2–§8.4), not a hard dependency.

**Pivotability guard — never pivot on generic or privacy-masked terms:**

- Reject registrant org strings under 4 characters, containing a privacy-service token ("privacy,"
  "redacted," "domains by proxy," "withheld for privacy," …) or a registrar's own name (GoDaddy,
  Namecheap, Tucows, MarkMonitor, …), or with no distinctive token once generic corporate suffixes
  (Ltd/LLC/Inc/GmbH/Pvt/Holdings/Group/…) are stripped.
- Reject registrant email pivots on role addresses (`abuse@`, `admin@`, `hostmaster@`, `noreply@`,
  …), privacy-provider domains, and free-mail domains (Gmail, Outlook, etc.).

Pivoting on a rejected term is how reverse-WHOIS turns into a false-positive generator — "privacy
protection LLC" as a registrant org matches tens of thousands of unrelated domains.

**Quota-protection pattern (WhoisXML two-call preview-then-purchase):**

```bash
# 1. PREVIEW — free, returns a count, does not consume a purchase credit
curl -sk -X POST "https://reverse-whois.whoisxmlapi.com/api/v2" \
  -H "Content-Type: application/json" \
  -d '{"apiKey":"'"$WHOISXML_KEY"'","searchType":"current","mode":"preview",
       "basicSearchTerms":{"include":["Acme Corporation"]}}' | jq '.domainsCount'

# 2. Only if 1 <= count < 200, PURCHASE — the real result
curl -sk -X POST "https://reverse-whois.whoisxmlapi.com/api/v2" \
  -H "Content-Type: application/json" \
  -d '{"apiKey":"'"$WHOISXML_KEY"'","searchType":"current","mode":"purchase",
       "basicSearchTerms":{"include":["Acme Corporation"]}}' | jq -r '.domainsList[]'
```

```powershell
$body = @{ apiKey = $env:WHOISXML_KEY; searchType = "current"; mode = "preview";
           basicSearchTerms = @{ include = @("Acme Corporation") } } | ConvertTo-Json
$preview = Invoke-RestMethod -Uri "https://reverse-whois.whoisxmlapi.com/api/v2" -Method Post `
    -ContentType "application/json" -Body $body
if ($preview.domainsCount -ge 1 -and $preview.domainsCount -lt 200) {
    $body2 = @{ apiKey = $env:WHOISXML_KEY; searchType = "current"; mode = "purchase";
                basicSearchTerms = @{ include = @("Acme Corporation") } } | ConvertTo-Json
    $result = Invoke-RestMethod -Uri "https://reverse-whois.whoisxmlapi.com/api/v2" -Method Post `
        -ContentType "application/json" -Body $body2
    $result.domainsList
}
```

Skip the purchase call entirely when the count is 0 (nothing to buy) or ≥ 200 (a hit that broad is a
generic-term false positive, not a real reverse-WHOIS signal — don't burn the credit).

**SecurityTrails' associated-domains endpoint** takes a domain (not an org/email string) and returns
domains SecurityTrails has already associated with it — cheaper conceptually but still key-gated:

```bash
curl -sk "https://api.securitytrails.com/v1/domain/acme.com/associated" -H "APIKEY: $ST_KEY" | \
  jq -r '.records[].hostname'
```

### 8.2 crt.sh O= — the keyless CT-organization pivot

Certificate Transparency logs are public and searchable by certificate subject organization. This
is the **keyless backbone** of domain attribution in this skill — it runs even with zero paid keys.

```bash
curl -sk "https://crt.sh/?O=Acme+Corporation&output=json" -H "User-Agent: Mozilla/5.0" | \
  jq -r '.[].name_value' | tr '\n' ' ' | tr ' ' '\n' | sort -u | grep -v '^\*'
```

```powershell
$r = Invoke-RestMethod -Uri "https://crt.sh/?O=Acme+Corporation&output=json" -Headers @{ "User-Agent" = "Mozilla/5.0" }
$r | Select-Object -ExpandProperty name_value | ForEach-Object { $_ -split "`n" } | Sort-Object -Unique
```

**Parsing discipline:**

- Split multi-value SAN entries on newlines; strip wildcard prefixes (`*.`); lowercase.
- Validate each result actually looks like an FQDN before reducing to a registrable root — CT log
  garbage (malformed subject strings) is common enough to need a sanity filter.
- **Drop the seed's own registrable root and any subdomain of it** — you want cross-root candidates,
  not the seed re-discovering itself.
- Deduplicate by registrable root, not by raw hostname (many subdomains of the same unrelated root
  are one candidate, not many).

**Fallback chain when crt.sh 502s:** Censys Certificates, CertSpotter, Rapid7 Open Data — see
`offensive-osint` §27.0.1 for the full retry/fallback recipe; this skill's org-search variant of
crt.sh (`?O=` instead of the usual `?q=`) hits the same backend and is subject to the same outages.

### 8.3 Infrastructure correlation — cheap, DNS-only signals

Once you have a candidate root domain (from reverse-WHOIS, crt.sh O=, or a registry pivot), enrich
it with keyless DNS lookups and compare against the seed's own DNS footprint:

| Signal | What it checks | Guard |
|---|---|---|
| Shared specific NS | Candidate's NS intersects the seed's NS | Exclude generic providers (Cloudflare, Route53, Azure DNS, Google Domains, …) — their NS records mean nothing about ownership. |
| Shared custom MX | Candidate's MX intersects the seed's MX | Exclude public mail providers (Google Workspace, M365, generic ESPs). |
| Shared SaaS TXT token | Both domains carry the same SaaS-verification TXT prefix (Google Site Verification, Salesforce, etc.) | Token match only — the token *value* usually differs per domain even for the same SaaS tenant, so match on the verification-service prefix. |
| Netblock membership | A resolved IP for the candidate falls inside a netblock already confirmed seed-owned | Root-vs-CIDR containment check, not a substring match. |
| Reverse-DNS (PTR) root match | The PTR record for a candidate's resolved IP has the SAME registrable root as the seed | **Root-vs-root only** — a PTR ending in `evil-acme.com.attacker.com` must not match on a naive `endswith` check; compare registrable roots exactly. |

Each signal that fires becomes one `OwnerSignal` fed into the combiner (§8.4) — never a standalone
verdict.

### 8.4 The independent-evidence combiner

The core scoring math behind every ownership tier in this skill (§2). Every fired signal is a
`(weight, confirming: bool)` pair. Positives combine via:

```
score = 1 - Π(1 - w_i)     for every non-negative signal i
```

...scaled to 0–100, **unless** a `confirming` signal is present, in which case the score is forced
to 100 directly (only a handful of signal types are ever marked confirming — chiefly "this IS the
seed domain itself"). If any `NOT_OWNED` (stranger-lock) signal is present, the score is capped at
20 regardless of what the product formula would otherwise produce.

**Why multiplicative-independent, not additive:** three weak, genuinely independent signals should
combine into something stronger than any one of them, but should not simply sum past 100 the way a
naive additive score would. `1 - Π(1-w_i)` has the right shape — diminishing returns on stacking
correlated-looking weak signals, while still letting three truly independent ~0.5-weight signals
climb into `STRONG` territory (three 0.5 signals: `1 - 0.5³ = 0.875` → 87.5, `STRONG`).

**Signal weight table** (production values — reuse these, don't invent new priors per engagement):

| Signal | Weight | Confirming | Notes |
|---|---|---|---|
| `registry_listed` | 0.95 | yes | A regulatory/government registry explicitly lists this domain as belonging to the org. |
| `reverse_whois_email` | 0.88 | no | WHOIS registrant email matches a pivotable corporate address. |
| `cert_org_match` | 0.85 | no | TLS certificate `O=` matches the seed org directly (crt.sh O= hit on the seed's own identity string). |
| `reverse_whois_org` | 0.80 | no | WHOIS registrant org matches a pivotable org string. |
| `cert_san_cross_root` | 0.80 | no | Candidate and seed share a SAN on a common certificate. |
| `asn_holder_match` | 0.75 | no | Candidate's resolved IP falls in a netblock whose ASN holder matches the org. |
| `securitytrails_associated` | 0.70 | no | SecurityTrails association, not an exact WHOIS-org match. |
| `netblock_reverse_dns` | 0.70 | no | PTR root match against a seed-owned netblock. |
| `entity_cert_org_match` | 0.68 | no | Cert-O= match found by pivoting a **subsidiary entity name** — deliberately weaker than a direct seed-org cert match (§8.5). |
| `registry_wikidata` | 0.60 | no | Fuzzy Wikidata label match — deliberately weaker than a filed registry record (§7.4). |
| `shared_saas_txt` | 0.55 | no | Shared SaaS TXT verification token. |
| `shared_mx_custom` | 0.50 | no | Shared non-public MX host. |
| `shared_ns_specific` | 0.35 | no | Shared organisation-specific nameserver. |
| *(structural: the seed domain itself)* | 1.0 | **yes** | Forces the score to 100 — this is the one confirming signal in normal operation. |

**A single-signal candidate almost never reaches `STRONG` on its own** except `registry_listed` and
`reverse_whois_email` — by design. Everything else needs a second independent signal class to clear
70. This is the mechanical enforcement of "rule of three" for this domain.

### 8.5 Entity → domain pivot (depth-1, from corporate registries)

EDGAR (§7.2), OpenCorporates (§7.3), and Wikidata (§7.4) give you subsidiary **entity names**, not
domains. Pivot each pivotable entity name through crt.sh O= (§8.2) to find its candidate domains,
capped (recommended ≤ 20 entity names per scan — a multinational with hundreds of listed
subsidiaries would otherwise blow the crt.sh call budget), and mint each entity as its own subsidiary
identity node parented to the seed org.

**Score the resulting domain match with `entity_cert_org_match` (0.68), not `cert_org_match`
(0.85).** The extra hop through a registry-pivoted entity name is a weaker link than a direct hit on
the seed's own identity string — a registry-confirmed entity name should not transfer its own
confidence onto whatever crt.sh happens to fuzzy-match for that name. Keep the provenance edge from
the discovered domain back to the specific subsidiary entity that yielded it, so an operator can
trace "why do you think this belongs to them" all the way back to the filed registry record.

### 8.6 The discover-only `related:` namespace

Every candidate domain this skill surfaces — regardless of ownership score — is minted under a
**separate asset namespace** from confirmed in-scope domains (`related:acmesub.com`, never
`domain:` or `sub:`). This is a structural, not a scoring, distinction:

- No module that consumes `domain:`/`sub:` assets to seed active scanning will ever see a `related:`
  asset — they are invisible to the active pipeline by construction, not by a runtime check that
  could be bypassed by a high score.
- Promotion to an actual scan target is a distinct, explicit operator action — never automatic, no
  matter how many independent signals fired or how high the owner_score climbed.
- This is what makes the whole top-down half of this skill safe to run **passively and by default**:
  discovery breadth doesn't translate into scan breadth without a human in the loop.

---

## 9. Netblock & ASN Attribution

### 9.1 Org-first RIR queries — recovering "dark" netblocks

DNS-based discovery only ever finds netblocks a resolved hostname happens to point into. IP space
registered to the org's legal entity with **zero DNS pointing at it** is invisible to every technique
in §8. This is the single highest-value gap this skill closes, and it requires querying the regional
internet registries **by organization name**, not by IP.

**ARIN (Americas) — Whois-RWS, keyless JSON:**

```bash
# 1. Find org handles matching a name (wildcard suffix)
curl -sk "https://whois.arin.net/rest/orgs;name=Acme*" -H "Accept: application/json" | \
  jq -r '.orgs.orgRef[] | "\(."@handle")  \(."@name")"'

# 2. For each matched handle, list its registered nets
curl -sk "https://whois.arin.net/rest/org/ACME-1/nets" -H "Accept: application/json" | \
  jq -r '.nets.netRef[] | "\(."@startAddress") - \(."@endAddress")"'

# 3. And its registered ASNs
curl -sk "https://whois.arin.net/rest/org/ACME-1/asns" -H "Accept: application/json" | \
  jq -r '.asns.asnRef[]."@handle"'
```

```powershell
$orgs = Invoke-RestMethod -Uri "https://whois.arin.net/rest/orgs;name=Acme*" -Headers @{ Accept = "application/json" }
$orgs.orgs.orgRef | ForEach-Object { "$($_.'@handle')  $($_.'@name')" }

$nets = Invoke-RestMethod -Uri "https://whois.arin.net/rest/org/ACME-1/nets" -Headers @{ Accept = "application/json" }
$nets.nets.netRef | ForEach-Object { "$($_.'@startAddress') - $($_.'@endAddress')" }

$asns = Invoke-RestMethod -Uri "https://whois.arin.net/rest/org/ACME-1/asns" -Headers @{ Accept = "application/json" }
$asns.asns.asnRef | ForEach-Object { $_.'@handle' }
```

ARIN returns address **ranges** (`startAddress`/`endAddress`), not CIDRs — convert with a
minimal-CIDR-set summarization (Python's `ipaddress.summarize_address_range`, or equivalent) rather
than assuming a clean CIDR boundary.

**RIPE (EMEA) — RIPE Database REST API, keyless JSON:**

```bash
# 1. Find organisation objects matching a name
curl -sk "https://rest.db.ripe.net/search.json?query-string=Acme%20Corporation&type-filter=organisation&flags=no-referenced" | \
  jq -r '.objects.object[] | select(.type=="organisation") | .["primary-key"].attribute[] | select(.name=="organisation") | .value'

# 2. Inverse-lookup everything registered TO that org handle (inetnum/inet6num/aut-num)
curl -sk "https://rest.db.ripe.net/search.json?query-string=ORG-AC1-RIPE&inverse-attribute=org&type-filter=inetnum&type-filter=inet6num&type-filter=aut-num&flags=no-referenced" | \
  jq -r '.objects.object[] | "\(.type)  " + (.attributes.attribute[] | select(.name=="inetnum" or .name=="inet6num" or .name=="aut-num") | .value)'
```

```powershell
$orgs = Invoke-RestMethod -Uri "https://rest.db.ripe.net/search.json?query-string=Acme%20Corporation&type-filter=organisation&flags=no-referenced"
# extract ORG-* handle(s) from $orgs.objects.object, then:
$inv = Invoke-RestMethod -Uri "https://rest.db.ripe.net/search.json?query-string=ORG-AC1-RIPE&inverse-attribute=org&type-filter=inetnum&type-filter=inet6num&type-filter=aut-num&flags=no-referenced"
```

**Precision gate — non-negotiable:** accept a matched RIR org only when (a) its registered name
passes the same pivotability guard as §8.1 (no privacy/registrar/generic-only strings), **and** (b)
its normalized slug **exactly equals** a known org-identity slug already on your identity list
(§7.5's seed org name/aliases, or a seed-owned ASN holder string) — an **exact normalized match**,
not a loose substring test. Org names collide across unrelated companies constantly ("Acme
Logistics" vs. "Acme Corporation" vs. "Acme Holdings Ltd" in a different country) — substring
matching here is how you attribute a stranger's netblock to your target.

**Coverage caveat:** ARIN + RIPE cover the Americas and EMEA. APNIC, LACNIC, and AFRINIC have no
reliable keyless free-text reverse-org search — report this explicitly as a coverage gap
(`org-registered blocks in APAC/LATAM/Africa not enumerated this pass`), not a silent zero.

**Everything this produces is `discover_only=True`, INERT.** Mint a `REGISTERED_TO_ORG` edge from
the netblock/ASN to the org node and a non-confirming `NETBLOCK_MEMBER`/`ASN_MEMBER`-typed owner
signal — never a `seed_owned` flag. A registry name collision must never silently drag a stranger's
IP space into an active scan queue.

### 9.2 Bound the fan-out

A broad org-name match can explode into hundreds of netblocks/ASNs per matched registry org handle.
Cap defensively: matched org handles per registry per query name (~10), netblocks minted per matched
org (~200), ASNs per matched org (~100). Log — don't silently drop — whatever the cap trims.

### 9.3 Bottom-up ASN discovery (complements, doesn't replace, §9.1)

For every IP already on the graph (seed resolution, subdomain resolution), look up its owning ASN
and that ASN's full announced-prefix list. This is the classic "what else does this datacenter
announce" pivot, and it runs alongside (not instead of) the org-first RIR sweep.

```bash
# IP → ASN (RIPEstat, free, CORS-friendly)
curl -sk "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8" | jq '.data.asns'

# ASN → holder org (RIPEstat whois wrapper)
curl -sk "https://stat.ripe.net/data/whois/data.json?resource=AS15169" | jq '.data.records'

# ASN → announced prefixes (RIPEstat)
curl -sk "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169" | jq -r '.data.prefixes[].prefix'

# ASN → announced prefixes (BGPView — complements RIPEstat, better ARIN/US coverage; keyless, light rate-limit)
curl -sk "https://api.bgpview.io/asn/15169/prefixes" | jq -r '.data.ipv4_prefixes[].prefix, .data.ipv6_prefixes[].prefix'
```

```powershell
$net = Invoke-RestMethod -Uri "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8"
$net.data.asns

$who = Invoke-RestMethod -Uri "https://stat.ripe.net/data/whois/data.json?resource=AS15169"
$who.data.records

$pfx = Invoke-RestMethod -Uri "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169"
$pfx.data.prefixes | ForEach-Object { $_.prefix }

$bgpview = Invoke-RestMethod -Uri "https://api.bgpview.io/asn/15169/prefixes"
$bgpview.data.ipv4_prefixes.prefix + $bgpview.data.ipv6_prefixes.prefix
```

**For bulk IP→ASN (>50 IPs), don't hammer RIPEstat/BGPView per-IP** — use Team Cymru's bulk WHOIS,
which accepts hundreds of IPs in one TCP session (full recipe in `offensive-osint` §28.1):

```bash
echo -e "begin\nverbose\n8.8.8.8\n1.1.1.1\nend" | nc whois.cymru.com 43
```

### 9.4 discover_only netblocks/ASNs are inert until promoted

Mirrors §8.6: both the org-first RIR sweep (§9.1) and bottom-up ASN discovery, when the holder org
doesn't clearly match the seed's own brand, mint their output as `discover_only=True` — inert,
non-scannable, linked by a `REGISTERED_TO_ORG` or `BELONGS_TO_ASN` edge, never `seed_owned`.

### 9.5 THE HYPERSCALER-SCOPE GUARD

**The single most important anti-pattern this section exists to prevent.** When one of the seed's
resolved IPs sits in an ASN whose registrant is a hyperscaler or CDN (AWS, GCP, Azure, Cloudflare,
Akamai, Fastly, …), that ASN can legitimately announce hundreds of prefixes — but they belong to the
**provider**, not the tenant. Materializing all of them as the org's netblocks is pure noise that
inflates the footprint with infrastructure the target does not own (a single-tenant AWS customer
would appear to "hold" ~200 AWS-announced blocks).

**The rule:**

| ASN classification | What gets materialized |
|---|---|
| **Owned** (registrant name matches a target brand — a real corporate-network ASN) | The most-specific announced prefixes, up to a cap (~200), ranked by CIDR specificity (concrete /24s before giant aggregates) — this genuinely is the org's footprint. Flag `seed_owned=True`. |
| **Non-owned / hyperscaler / CDN** (registrant does NOT match a target brand) | **Only** the block(s) the seed's own resolved IPs actually sit in — nothing else from that ASN's announced range. Tag `shared_hosting_cdn=True`. **Never** `seed_owned=True`, regardless of score. |

Classification is a conservative brand-substring match against the ASN holder's registered name —
not a fuzzy match, to avoid the inverse failure (falsely claiming a shared transit/cloud ASN as
"owned" because a brand word happens to appear in a long registrant string).

**Why this matters beyond graph tidiness:** `seed_owned`/`discover_only` gates elsewhere in this
pipeline (and in the active-scan pipeline downstream) key off exactly this flag. Get the hyperscaler
guard wrong and a non-owned CDN range becomes eligible for active port-scanning against
infrastructure you have no authorization to touch — this is a scope-authorization control, not just
a cosmetic one.

### 9.6 Org-identity-seeded internet-scan-index search

The complement to §9.1's registry-based dark-netblock recovery: query **internet-scan indexes**
(Shodan, Censys, ZoomEye, FOFA, BinaryEdge, Netlas) directly by the org's identity string, to find
live hosts with **no DNS trail at all** — not even a registry record, just a banner or a TLS cert
that carries the org's name.

**Identity tokens to query with** (collected from the graph, not guessed): WHOIS `registrant_org`,
the apex brand stem (first label of the seed domain, ≥ 3 characters — shorter stems produce
unusable noise), and any TLS certificate `O=` values already observed (including the seed's own, per
§7.5).

**Provider-native query templates:**

| Provider | Org-identity query |
|---|---|
| Shodan | `org:"Acme Corp"` and `ssl.cert.subject.O:"Acme Corp"` |
| Censys | `services.tls.certificates.leaf_data.subject.organization:"Acme Corp"` and `autonomous_system.name:"Acme Corp"` |
| ZoomEye | `org:"Acme Corp"` |
| FOFA | `org="Acme Corp"` and `cert.subject.org="Acme Corp"` |
| BinaryEdge | `"Acme Corp"` |
| Netlas | `certificate.subject.organization:"Acme Corp"` |

**Keyless always-on fallback — crt.sh O=** (§8.2's same recipe): even with zero paid index keys
configured, this half still runs and yields cross-root candidate domains from CT history.

**Attribution gating (critical — do not skip):** every hit from this technique carries only a
`BRAND_MATCH` signal at weight **0.40, non-confirming**. That is intentionally weak: a brand string
in a stranger's index banner (a reseller quoting "Acme" in a product description, a customer
running Acme-branded software) is not evidence of ownership on its own, and — per the combiner math
in §8.4 — a single 0.40 signal produces a score of 40 (the floor of the `MODERATE` tier, still
well below the 70-point active-scan-eligible threshold). **A brand string appearing in a stranger's banner must never
auto-promote that host into scope.** Every IP and cross-root domain from this technique is minted
`discover_only=True`.

---

## 10. Promote-to-Scan Triage

Once §9.1/§9.4 have surfaced a pile of `discover_only` dark netblocks, an operator needs to know
*which one to confirm-and-scan first*. This is a **passive triage**, not a scan: it reads a
third-party IP-intelligence cache (Shodan InternetDB) for hosts inside each discover-only block,
scores what it sees, and ranks the blocks — it mints **no new IP assets** and emits **no per-host
finding**, only one ranked queue entry per exposed block.

**Exposure scoring — presence-based triage priority, never an exploitability or ownership claim:**

| Signal | Weight | Cap |
|---|---|---|
| Remote-access gateway vendor present (Fortinet/Citrix/Pulse/GlobalProtect/Cisco AnyConnect/SonicWall/…) | 40 | — |
| Each CISA-KEV CVE (confirmed in-the-wild exploitation) | 25 | 75 total |
| Each non-KEV known CVE | 8 | 24 total |
| Each exposed control-plane port (Docker API 2375/2376, Kubernetes API 6443, kubelet 10250, etcd 2379) | 25/port | — |
| Each exposed remote-access port (RDP 3389, SSH 22, Telnet 23, SMB 445, WinRM 5985/5986, VNC 5900, IPsec/OpenVPN/PPTP/SSL-VPN ports) | 15/port | — |
| Each exposed datastore port (MySQL/Postgres/MSSQL/Oracle/Mongo/Redis/Elasticsearch/Memcached/CouchDB/InfluxDB/Kafka) | 10/port | — |

Rank blocks by their highest-scoring host; surface the top reasons in the finding title (e.g. *"top
host: remote-access gateway vendor: fortinet; 2 KEV CVE(s)"*). Severity of the resulting finding
stays **INFO / TENTATIVE** — ownership and exploitability are both still unconfirmed; the score is
purely "which forgotten block would an initial-access broker triage first."

**Bound the InternetDB read itself:** cap per-block host probes (a /24 max — skip giant ranges
entirely) and cap the total across all discover-only blocks in one pass, so a conglomerate with
dozens of dark netblocks doesn't turn triage into an unbounded IP sweep.

**The operator's actual next step:** confirm ownership of the top-ranked block through an
independent channel (a direct registrant contact, an internal asset inventory, a second registry
cross-check), then explicitly re-run discovery treating that range as owned/in-scope — at which
point it gets the full active-scan treatment through `offensive-osint`. This triage never performs
that promotion itself.

---

## 11. Attribution Confidence Rubric & Anti-Patterns

### 11.1 Anti-patterns specific to org-first attribution

- **Namesake grafting via GLEIF name re-resolution.** Re-searching a subsidiary's name instead of
  expanding its exact filed LEI (§7.1) — the single highest-risk mistake in this skill, because it
  happens silently and produces output that *looks* authoritative (a real GLEIF badge on the wrong
  entity's subtree).
- **Single-signal ownership.** Reporting "this belongs to them" off one `shared_ns_specific` (0.35)
  or `BRAND_MATCH` (0.40) hit. Rule of three — always require a second, independent signal class
  before treating something as more than a lead (§2, §8.4).
- **Hyperscaler over-attribution.** Materializing a CDN/cloud provider's entire announced range as
  the tenant's netblocks (§9.5). The most common way a first attempt at this skill produces a
  wildly inflated, useless footprint.
- **RIR org-name collision.** Matching "Acme Logistics Ltd" (unrelated) to your target "Acme
  Corporation" via a loose substring test instead of an exact normalized-slug match (§9.1). Org
  names collide across jurisdictions constantly — treat every RIR match as a candidate requiring
  the exact-slug gate, not a free-text "close enough."
- **Privacy-WHOIS pivot poisoning.** Pivoting reverse-WHOIS or crt.sh O= on a privacy-service or
  registrar string that WHOIS returned instead of the org's real registrant data (§8.1). Produces
  thousands of unrelated domains that all happen to share the same privacy provider.
  Structurally impossible when the seed's own WHOIS is privacy-masked: skip **all** org/email
  pivots for that seed rather than silently pivoting on the privacy provider's own name.
- **Treating a fuzzy corroboration as a filed record.** Scoring a Wikidata label match or an
  entity-pivoted crt.sh hit the same as a direct registry-listed or direct-cert-O= match (§8.4's
  weight table exists specifically to prevent this).
- **Discover-only score creep.** Assuming a `STRONG`/`CONFIRMED`-tier related domain or netblock is
  therefore safe to actively scan. It is not — `discover_only` is a structural gate independent of
  score (§2, §6.6, §8.6). Score informs promotion priority; it never substitutes for the operator's
  explicit promotion action.
- **Silent truncation.** Any of this skill's caps (GLEIF tree depth/fan-out, entity-pivot count,
  RIR matched-org/netblock/ASN counts, promote-triage host budget) being hit without a visible flag
  on the affected node/report. A capped result rendered as if it were complete is a worse failure
  mode than an honestly-incomplete one.

### 11.2 Confidence rubric summary

| You want to say... | Minimum bar |
|---|---|
| "X is a subsidiary of the target" | A filed GLEIF direct-child relationship (exact LEI) OR an EDGAR Exhibit-21 listing OR two independent corroborating signals (e.g. OpenCorporates entity match + Wikidata P355). |
| "domain D belongs to the target" | `owner_score ≥ 70` (STRONG) from §8.4's combiner, from at least two independent signal classes — never one. |
| "netblock N belongs to the target" | Exact-slug RIR org match (§9.1) AND/OR a seed-resolved IP actually inside N — a name match alone on a broad wildcard org search is not sufficient. |
| "this ASN is the org's, materialize its full range" | Registrant name passes the conservative brand-substring test (§9.5) — anything else gets the seed-containing-block-only treatment. |
| "promote this discover-only lead to active scope" | An operator's explicit, out-of-band ownership confirmation — never automatic, regardless of score (§6.6, §10). |

---

## 12. End-to-End Workflow

A concrete run-order tying §7–§10 together, for a fresh engagement that starts from a company name
or a single seed domain:

1. **Anchor the seed org identity** (§7.5): WHOIS `registrant_org` (if not privacy-masked) → own
   leaf cert `O=` → seed-owned ASN holder string. If none produce a usable string, stop the
   top-down half here and report the gap rather than guessing.
2. **GLEIF name→LEI, then direct-children** (§7.1), depth-capped and downward-only. This is your
   corporate-family skeleton.
3. **EDGAR / OpenCorporates / Wikidata corroboration** (§7.2–§7.4) for additional subsidiary entity
   names GLEIF's filed-relationship data doesn't cover (private companies, non-EU/US jurisdictions
   with thin GLEIF coverage).
4. **Entity → domain pivot** (§8.5): each pivotable subsidiary entity name → crt.sh O=, capped,
   weighted at `entity_cert_org_match` (0.68).
5. **Direct seed-identity domain pivots**: crt.sh O= on the seed's own identity strings (§8.2,
   `cert_org_match` 0.85) + reverse-WHOIS if a paid key is available (§8.1).
6. **Infra-correlate every candidate** (§8.3): NS/MX/SaaS-TXT/netblock/PTR against the seed's own
   DNS footprint, capped per scan.
7. **Score every candidate** through the independent-evidence combiner (§8.4) → mint as
   `related:`, discover-only, never auto-scanned (§8.6).
8. **Org-first RIR sweep** (§9.1): ARIN + RIPE, seeded from every org-identity alias collected so
   far (seed + every minted subsidiary org node) → dark netblocks/ASNs, exact-slug gated,
   `discover_only=True`.
9. **Bottom-up ASN cross-check** (§9.3) on every already-resolved seed/related IP, reconciled
   through the **same** hyperscaler-scope guard (§9.5).
10. **Org-identity-seeded index search** (§9.6): paid-index org: filters if keys are configured,
    always-on keyless crt.sh O= fallback regardless.
11. **Promote-to-scan triage** (§10) ranks every discover-only netblock by remote-access exposure
    into an operator queue.
12. **Hand off** — an operator reviews the ranked queue and the scored `related:`/dark-netblock
    list, confirms ownership out-of-band for whatever they want to pursue, and only THEN feeds the
    confirmed domains/ranges into `offensive-osint` for per-host recon.

**Rough time/complexity budget** (keyless core; scale with corporate complexity, not target size):
a single legal entity with no filed subsidiaries resolves in minutes (steps 1–2 short-circuit).
A regional group with a handful of GLEIF-filed subsidiaries: well under an hour. A multinational
conglomerate with a deep GLEIF tree, dozens of jurisdictions, and heavy RIR fan-out: budget a
half-day, driven mostly by registry rate limits (ARIN/RIPE/GLEIF/EDGAR are all keyless and
correspondingly modestly rate-limited) rather than compute.

---

## 13. Skill Self-Test

Drop these into a fresh session to verify the skill loads correctly.

1. *"I only have a company name, not a domain. Map its internet footprint."* → §6, §7.5, §12.
2. *"Resolve 'Acme Corporation' to its LEI and list its direct subsidiaries."* → §7.1.
3. *"Found subsidiary 'Acme Payments GmbH' via GLEIF. Get ITS subsidiaries."* → §7.1 (exact-LEI
   expansion — should NOT re-search by name).
4. *"Pull Exhibit-21 subsidiary names for a US-listed company from EDGAR."* → §7.2.
5. *"Corroborate that 'Acme Logistics Pty Ltd' is a real registered entity before I pivot on it."*
   → §7.3.
6. *"crt.sh O= search for 'Acme Corp' returned 40 cross-root domains. How do I score them?"* → §8.2,
   §8.4.
7. *"WHOIS on the seed shows 'Domains By Proxy' as the registrant. Can I reverse-WHOIS pivot on
   that?"* → §8.1, §11.1 (no — privacy-service string, structurally reject).
8. *"I found a netblock registered to 'Acme Corporation' at ARIN with zero DNS pointing at it. What
   is this and how confident should I be?"* → §9.1 (the dark-netblock gap) + §2 ownership tier.
9. *"One of the target's IPs resolves inside an AWS-announced /16. Do I attribute the whole /16 to
   them?"* → §9.5 (no — hyperscaler-scope guard; seed-containing block only).
10. *"Shodan `org:"Acme Corp"` turned up 200 IPs with no DNS. Should these go straight into the
    active port scan?"* → §9.6, §2 (no — discover_only, BRAND_MATCH weight 0.40 only; needs
    operator confirmation).
11. *"Rank my 6 discover-only dark netblocks by which to confirm-and-scan first."* → §10.
12. *"I have a related domain scoring 85 (STRONG). Can I scan it now?"* → §2, §6.6, §8.6, §11.1
    (no — discover_only is structural, independent of score; still needs explicit promotion).
13. *"RIPE org search for 'Acme' matched three different organisation handles across three
    countries. Which do I use?"* → §9.1 (exact-slug match against known identity aliases only, not
    "the first result").
14. *"How do I combine a cert_org_match signal and a shared_mx_custom signal into one confidence
    score?"* → §8.4 (the `1-Π(1-w_i)` formula + weight table).
15. *"Give me the ARIN and RIPE curl recipes for org-first netblock discovery."* → §9.1.
16. *"Full external recon on a company name — where does this skill end and `offensive-osint`
    begin?"* → §12 step 12; companion-skill note at the top of this file.

---

## 14. Changelog

- **v1.0 (2026-08-06)** — initial release. Org-first attribution pyramid (§6); corporate-identity
  resolution via GLEIF (downward-only, exact-LEI recursion, depth/fan-out caps), EDGAR Exhibit-21,
  OpenCorporates, Wikidata SPARQL (§7); domain attribution via reverse-WHOIS (quota-guarded, paid),
  crt.sh O= (keyless), infra correlation, and the independent-evidence combiner with full signal
  weight table (§8); netblock/ASN attribution via org-first RIR (ARIN Whois-RWS + RIPE DB,
  exact-slug gated, "dark netblock" recovery), bottom-up ASN discovery, the hyperscaler-scope guard,
  and org-identity-seeded internet-scan-index search (§9); promote-to-scan exposure triage (§10);
  attribution confidence rubric + anti-pattern catalog (§11); end-to-end workflow with time budget
  (§12); 16-prompt self-test (§13). Grounded directly in the reference production implementation
  (`modules/subsidiary.py`, `modules/rir_org.py`, `modules/org_index_search.py`, `modules/asn.py`,
  `modules/promote_triage.py`, `connectors/gleif.py`, `connectors/org_registry/*`,
  `connectors/ct_org/crtsh_org.py`, `connectors/reverse_whois/*`, `model/attribution.py`,
  `data/remote_access_signals.py`) — every weight, cap, and gate value in this skill matches a
  shipped, tested value, not an invented placeholder.
