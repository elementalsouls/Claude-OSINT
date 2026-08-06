# `org-attack-surface` skill

The "start from a company, not a domain" skill — org-first attribution: legal entity → corporate
family → owned domains → owned netblocks/ASN → live assets, with attribution discipline at every
hop.

| Field | Value |
|---|---|
| Name | `org-attack-surface` |
| Version | 1.0 |
| Lines | ~1,045 |
| Top-level sections | 15 |
| Companion skills | [`osint-methodology`](../osint-methodology/) (the pipeline this plugs into), [`offensive-osint`](../offensive-osint/) (the per-host arsenal you run once ownership is confirmed) |

## When this skill triggers

Auto-triggers on prompts containing any of ~50 trigger phrases. Common ones:

- `org attack surface`, `org footprint`, `corporate family`, `corporate family mapping`
- `subsidiary discovery`, `subsidiary attack surface`, `M&A footprint`, `shadow IT discovery`
- `GLEIF`, `LEI lookup`, `legal entity identifier`, `legal name to LEI`
- `SEC EDGAR`, `EDGAR subsidiary`, `Exhibit 21`, `10-K subsidiaries`
- `OpenCorporates`, `Wikidata corporate graph`
- `reverse WHOIS`, `crt.sh organization search`, `crt.sh O=`, `certificate transparency org pivot`
- `dark netblock`, `org-first RIR search`, `ARIN Whois-RWS`, `RIPE DB search`, `RDAP entity search`
- `ASN discovery`, `BGPView`, `RIPEstat`
- `hyperscaler scope guard`, `cloud netblock over-attribution`, `AWS netblock attribution`
- `promote to scan`, `discover-only candidate`
- `org identity resolution`, `corporate identity resolution`, `owned netblock discovery`
- `org index search`, `outward identity search`, `Shodan org filter`, `Censys organization filter`
- `attribution confidence`, `ownership tier`, `independent evidence combiner`, `rule of three attribution`
- `namesake grafting`, `org tree walk`, `company name to attack surface`

Full trigger list in the SKILL.md frontmatter.

## What's in it

- **§2 — Confidence Levels & Ownership Tiers.** The two-axis model this whole skill runs on: finding
  confidence (TENTATIVE/FIRM/CONFIRMED) vs. ownership tier (NONE/WEAK/MODERATE/STRONG/CONFIRMED,
  computed by the independent-evidence combiner) — and why `discover_only` is a structural gate
  independent of either.
- **§6 — The org-first attribution pyramid.** Legal entity → corporate family → owned domains →
  owned netblocks/ASN → live assets, with a discovery-direction cheat sheet (top-down vs. bottom-up)
  and why DNS-only recon structurally cannot find dark netblocks or no-DNS-linked subsidiaries.
- **§7 — Corporate identity resolution.** GLEIF LEI API (name→LEI, exact-LEI direct-children
  recursion, downward-only depth/fan-out caps, the namesake-grafting trap), SEC-EDGAR Exhibit-21,
  OpenCorporates entity corroboration, Wikidata SPARQL (P856/P355/P749/P1830), and the seed-org
  identity-anchoring priority order.
- **§8 — Domain attribution.** Reverse-WHOIS (quota-guarded preview-then-purchase, paid), crt.sh O=
  (keyless), infrastructure correlation (NS/MX/SaaS-TXT/netblock/PTR), the full independent-evidence
  signal weight table (13 signal types, 0.35–1.0), the depth-1 entity→domain pivot, and the
  discover-only `related:` namespace contract.
- **§9 — Netblock & ASN attribution.** Org-first RIR queries (ARIN Whois-RWS + RIPE DB, exact-slug
  gated) that recover "dark netblocks," bottom-up ASN discovery (RIPEstat + BGPView), **the
  hyperscaler-scope guard** (never attribute a whole AWS/GCP/Azure/Cloudflare range to a tenant),
  and org-identity-seeded internet-scan-index search (Shodan/Censys/ZoomEye/FOFA/BinaryEdge +
  always-on keyless crt.sh fallback).
- **§10 — Promote-to-scan triage.** Remote-access exposure scoring (gateway-vendor/KEV/control-plane/
  datastore weights) ranking forgotten dark netblocks into an operator queue — passive, mints no new
  assets, confirms nothing.
- **§11 — Attribution confidence rubric + anti-pattern catalog.** Namesake grafting, single-signal
  ownership, hyperscaler over-attribution, RIR org-name collisions, privacy-WHOIS pivot poisoning,
  discover-only score creep.
- **§12 — End-to-end workflow** tying §7–§10 into one run order, with a rough time budget.
- **§13 — 16-prompt self-test** including a negative case (a `STRONG`-scoring related domain should
  NOT be auto-scanned).

Every recipe (GLEIF, EDGAR, OpenCorporates, Wikidata, crt.sh O=, ARIN Whois-RWS, RIPE DB, RIPEstat,
BGPView) ships as copy-paste `curl` **and** PowerShell.

## Keyless-first

The corporate-identity and dark-netblock core of this skill runs with **zero API keys**: GLEIF,
SEC-EDGAR, OpenCorporates, Wikidata, crt.sh O=, ARIN Whois-RWS, RIPE DB, RIPEstat, and BGPView are
all keyless. Only two things are paid enrichment on top of that core:

- **Reverse-WHOIS** (§8.1) — WhoisXML and SecurityTrails both require a key; there is no keyless
  reverse-WHOIS path. The keyless core (crt.sh O= + registry entity pivots + infra correlation)
  covers domain attribution without it.
- **Internet-scan-index org search** (§9.6) — Shodan/Censys/ZoomEye/FOFA/BinaryEdge/Netlas org:
  filters are key-gated; the crt.sh O= fallback for cross-root domains always runs regardless.

## Grounded in production, not invented

Every weight, cap, threshold, and gate rule in this skill (the `1-Π(1-w_i)` combiner, the 13-row
signal weight table, GLEIF's 200-node/50-fan-out caps, the ARIN/RIPE exact-slug match gate, the
hyperscaler-scope guard, the remote-access exposure score) is transcribed from a shipped, tested
implementation — not invented for the skill. See the Changelog in SKILL.md §14 for the exact source
files.

## Loading

```bash
# Local Claude Code install
cp SKILL.md ~/.claude/skills/org-attack-surface/SKILL.md

# Or attach to a Claude.ai project / Claude API system prompt
# (paste contents of SKILL.md as project knowledge)
```

## Self-test

Run the 16 prompts in SKILL.md §13 against a fresh session to verify the skill loads and routes
correctly — including prompt 12, the negative case that a high ownership score does not authorize
active scanning.

## License

MIT — see [LICENSE](../../LICENSE).
