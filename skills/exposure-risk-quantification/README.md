# `exposure-risk-quantification` skill

The "turn findings into a number the board will act on" layer — FAIR-aligned risk scoring,
$-denominated loss estimation, attack-path amplification, and a board-ready one-pager.

| Field | Value |
|---|---|
| Name | `exposure-risk-quantification` |
| Version | 1.0 |
| Lines | ~750 |
| Top-level sections | 15 (§0–§14) |
| Subsections | ~18 |
| Companion skill | [`osint-methodology`](../osint-methodology/) (deepens its §9 severity rubric + §16 client deliverable templates) |

## When this skill triggers

Auto-triggers on prompts containing any of ~40 trigger phrases. Common ones:

- `risk score`, `risk quantification`, `cyber risk quantification`, `CRQ`, `FAIR methodology`, `FAIR score`
- `0-100 risk score`, `risk grade`, `A-F grade`, `letter grade risk`
- `board report`, `board deliverable`, `board ready`, `executive summary risk`, `CISO report`, `one-pager`
- `hero number`, `dollar exposure`, `breach cost estimate`, `loss estimate`, `annualized loss expectancy`, `ALE`
- `per-record cost`, `IBM Ponemon`, `cost of a data breach`, `exposed record count`
- `attack path`, `kill chain`, `shared fate exposure`, `attack path amplification`
- `ownership confidence`, `proof demotion cap`, `confidence cap`
- `risk translation`, `business impact translation`, `dominant risk driver`
- `risk trend`, `risk delta`, `the ask`, `remediation ask`

Full trigger list in the SKILL.md frontmatter.

## What's in it

- **§6 — FAIR primer.** Risk = Loss Event Frequency × Loss Magnitude, and exactly how
  external-recon findings map onto the two halves (Exposure/Threat → LEF proxy; Impact →
  LM proxy). States plainly that recon gives you likelihood *inputs*, not a certainty claim.
- **§7 — The 0–100 + A–F score.** The exact three-factor model (Exposure, Threat, Impact),
  the independent-evidence combiner, every severity weight and calibration constant, and
  the **ownership + proof demotion cap** (§7.5) — two independent gates that stop a
  TENTATIVE or weakly-owned finding from swinging the grade.
- **§8 — The $-loss model.** IBM/Ponemon per-record cost bands ($150/$165/$200), the
  cross-source record-count dedup rule (max, never summed — avoids double-counting the same
  breached population across sources), and the annualization nuance most likely to be
  misstated (it uses the Threat factor, not the composite risk score). Full worked example
  end to end in §8.4.
- **§9 — Attack-path amplification.** The ~12-rule curated red-team chain catalog + the
  generic graph-walk engine, and the **kill-chain vs. shared-fate honesty gate** — a chain
  built only from co-location edges (shared host/cert/DNS/alias) is blast-radius context,
  never a proven pivot. §9.4 spells out the exact (binary, not proportional) mechanism by
  which a chain feeds back into the org score.
- **§10 — The board deliverable.** Hero-number tri-state logic (never fabricates a dollar
  figure at zero records, never claims $0 risk either), top-3 finding curation/rollup rules,
  top-attack-path selection, "the ask" derivation, and the full one-pager layout.
- **§11 — Risk translation table.** Extends `osint-methodology` §16 with a $ column — and
  is explicit about which findings the loss model has no dollar input for at all.
- **§12 — Honesty guardrails.** The sharp edges to know before presenting a number: Exposure
  is confidence/ownership-blind by design; attack-path amplification is a binary trigger;
  `risk_trend` is same-target-only.

## Loading

```bash
# Local Claude Code install
cp SKILL.md ~/.claude/skills/exposure-risk-quantification/SKILL.md

# Or attach to a Claude.ai project / Claude API system prompt
# (paste the contents of SKILL.md as project knowledge)
```

## Grounding

Every formula, weight, and constant in this skill is reproduced from a real, shipped
implementation — not invented — so a score computed by hand from this skill's tables
should match `compute_org_risk()` / `loss_model.estimate()` on the same inputs:

- `reporting/risk_score.py` — three-factor org risk score
- `reporting/loss_model.py` — $-loss estimation
- `reporting/board_report.py` + `reporting/board_render.py` — board deliverable
- `reporting/attack_paths.py` + `reporting/attack_graph.py` — attack-path catalog + graph walk
- `reporting/owner_confidence.py` + `reporting/proof.py` — the demotion cap

## Self-test

Run the 15 prompts in this skill's own §13 Skill Self-Test (including a deliberate trap on
TENTATIVE findings + partial ownership confidence) to verify the skill loads and routes
correctly.

## License

MIT — see [LICENSE](../../LICENSE).
