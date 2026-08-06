# `osint-methodology` skill

The "how to think" reference for external red-team OSINT and bug-bounty reconnaissance.

| Field | Value |
|---|---|
| Name | `osint-methodology` |
| Version | 2.3 |
| Lines | ~515 |
| Top-level sections | 19 |
| Subsections | 12 |
| Companion skill | [`offensive-osint`](../offensive-osint/) |

## When this skill triggers

Auto-triggers on prompts containing any of ~52 trigger phrases. Common ones:

- `external recon`, `external red team`, `bug bounty recon`, `attack surface management`, `ASM`, `perimeter recon`
- `OSINT methodology`, `recon methodology`, `target reconnaissance`, `asset discovery`, `attack path`
- `identity fabric`, `SSO discovery`, `IdP fingerprinting`, `M365 enumeration`
- `phishing infrastructure`, `pretext development`, `bug bounty submission`, `responsible disclosure`
- `client report`, `exec summary`, `risk translation`
- `confidence upgrade`, `time budget`, `engagement profile`, `asset triage`
- `detection-aware probing`, `back-off strategy`, `persona rotation`
- `WAF bypass`, `CDN bypass`, `origin discovery`
- `vulnerability prioritization`, `CVE prioritization`, `EPSS`, `CISA KEV`
- `threat actor investigation`, `attribution`

Full trigger list in the SKILL.md frontmatter.

## What's in it

See the parent [README's "What's in the box" table](../../README.md#whats-in-the-box) for the full §-by-§ breakdown.

Highlights:

- **§7 — 6-stage recon pipeline** (seed → asset expansion → enrichment → exposure analysis → convergence → operator-armed active validation) + priority order + time budgeting (1h / 4h / 1d / 1w profiles) + connector resilience (§7.3) + stage-vs-gating discipline (§7.4)
- **§8 — Asset graph discipline** with 29 typed asset types across 9 categories + per-asset-type triage rules
- **§9 — Findings rubric** anchored on examples (CRITICAL → INFO + escalation rules)
- **§10 — Pivot modes & scale tactics** (scope-sized tactics for <100 vs. large surfaces)
- **§11 — Companion-skill pointers** — the "what to do here / how in `offensive-osint`" hub: identity-fabric mapping (Entra, Okta, ADFS, Google, SAML, AWS acct-id, M365 deep), API & auth-map, JavaScript deep analysis, mobile & cloud attack surface, WAF/CDN bypass + origin discovery, vulnerability prioritization (CVE × EPSS × KEV), phishing infrastructure
- **§12 — Breach × identity correlation** (HudsonRock + HIBP + DeHashed + IntelX → SSO_EXPOSURE finding) + **§12.1 — per-person identity dossier** (PERSON × CREDENTIAL join by email, ranked spear-phish/credential-stuffing target list)
- **§13 — Specialty OSINT domains** (cryptocurrency, image/chronolocation, threat-actor investigation, people & social)
- **§15 — Bug bounty submission & responsible disclosure** (HackerOne, Bugcrowd, Intigriti, etc.)
- **§16 — Client deliverable templates** (exec summary + risk-translation matrix + reporting cadence)

## Loading

```bash
# Local Claude Code install
cp SKILL.md ~/.claude/skills/osint-methodology/SKILL.md

# Or attach to a Claude.ai project / Claude API system prompt
# (paste contents of SKILL.md as project knowledge)
```

The full content lives in this `SKILL.md` (or in `docs/full-skills/osint-methodology.SKILL.full.md` if this file is the structured-outline variant — see repo root for sync instructions).

## Self-test

Run the prompts in [`../../tests/smoke-test-prompts.md`](../../tests/smoke-test-prompts.md) to verify skill behavior after install. Methodology-targeted prompts are tagged in the test file.

## License

MIT — see [LICENSE](../../LICENSE).
