# `continuous-exposure-monitoring` skill

The "turn one-shot recon into a program" layer — scheduled re-scan-and-diff loops, adversary CTI/
chatter monitoring, infrastructure-tracking-over-time, and finding-lifecycle discipline so a client
gets told about *new* exposure instead of re-reading yesterday's report.

| Field | Value |
|---|---|
| Name | `continuous-exposure-monitoring` |
| Version | 1.0 |
| Lines | ~810 |
| Top-level sections | 14 (§0–§13) |
| Companion skills | [`osint-methodology`](../osint-methodology/) (the 5-stage pipeline this skill loops on a schedule), [`offensive-osint`](../offensive-osint/) (§29 Threat Intel & IOCs — this skill deepens the continuous-monitoring/CTI-cadence gap that section explicitly lacks), [`org-attack-surface`](../org-attack-surface/) (the org-first discovery re-run each cycle), [`exposure-risk-quantification`](../exposure-risk-quantification/) (reads this skill's lifecycle suppression state for the FAIR score and `risk_trend`) |

## When this skill triggers

Auto-triggers on prompts containing any of ~55 trigger phrases. Common ones:

- `continuous monitoring`, `continuous exposure monitoring`, `retainer monitoring`, `MSSP monitoring`
- `scheduled rescan`, `scheduled scan`, `scan diff`, `monitor a target`, `delta alert`, `drift detection`, `attack surface drift`, `what changed since last scan`
- `ransomware leak site monitoring`, `adversary chatter`, `dark web monitoring`, `brand mention monitoring`, `IAB monitoring`, `telegram brand monitoring`, `CTI feed`, `watchlist rescan`, `retroactive rescan`
- `infrastructure tracking`, `CT log monitoring`, `passive DNS deltas`, `new subdomain alert`, `typosquat monitoring`
- `finding lifecycle`, `false positive triage`, `risk accepted`, `finding suppression`, `alert fatigue`, `finding SLA`, `overdue finding`
- `alert outbox`, `durable alert delivery`, `retry backoff`, `queued vs delivered`
- `cron recon`, `scheduled task recon`, `monitoring cadence`

Full trigger list in the SKILL.md frontmatter.

## What's in it

- **§6 — The monitoring loop model.** The canonical five-step loop (baseline → sleep → re-scan → diff
  → threshold-gated alert), the two native implementations (`falcon-recon monitor` single-target CLI
  daemon vs. the dashboard's multi-target job scheduler — including why only the latter can reach
  the `--validate` tier), the diff engine's tracked-attribute table (what counts as a meaningful
  "changed" asset vs. noise), a stage-by-stage re-scan cadence guide, and the exact hot-asset-type
  rule that alerts regardless of severity threshold.
- **§7 — CTI / adversary chatter monitoring.** All six shipped public sources with real endpoints and
  cadences (ransomwatch, ransomware.live, HackerNews Algolia search, Reddit RSS, GitHub Gist code
  search, public Telegram channel scraping), the literal/glob/regex watchlist matcher, the full
  source-kind-aware severity rubric (leak-site/forum/telegram/paste tiers, with the IAB-phrase and
  ransomware-group-name catalogs that drive it), retroactive rescan-on-new-watchlist-entry (so a
  brand added today instantly surfaces an 18-month-old historical hit without an alert storm), and
  the ambient-hit promotion gate that keeps un-targeted chatter out of client deliverables.
- **§8 — Infrastructure tracking over time.** What "CT-log/passive-DNS/port/typosquat monitoring"
  actually is in this platform (poll + diff, not a push stream) — mapped module-by-module to the
  exact tracked-attribute signal each produces, plus a worked weekly diff-report recipe.
- **§9 — Finding lifecycle & false-positive discipline.** The five-state machine
  (open/triaged/risk_accepted/resolved/false_positive), the exact fingerprint formula (with the
  digit-normalization rationale for cross-scan title drift), auto-resolve/reopen reconciliation, the
  per-severity SLA table, and — the skill's sharpest original finding — **why `findings_watchlist`
  rules are not lifecycle-aware while `monitor`'s fingerprint-diff alerting structurally is**, traced
  directly from each subsystem's dedup key, with the practical fix for a rule that keeps re-firing on
  an already-triaged finding.
- **§10 — Alert delivery reliability.** The "queued is not delivered" distinction (every sender
  enqueues into a durable outbox; the caller's own success bookkeeping reflects enqueue, not
  delivery), the exact backoff/dead-letter numbers, the dedup key, retention, and a per-subsystem
  threshold-tuning table for avoiding alert fatigue.
- **§11 — Scheduler recipes.** When to prefer the native daemons over a bare loop, copy-paste bash
  cron **and** PowerShell Scheduled Task recipes for a weekly re-scan+diff job, and the
  Slack-compatible webhook payload shape shared (with small per-subsystem variations) across all
  three alert senders.
- **§12 — 16-prompt self-test** including a negative case on whether a `risk_accepted` finding should
  re-alert — with the honest, subsystem-dependent answer instead of a flat yes/no.

## Grounded in production, not invented

Every endpoint, cadence, severity rule, fingerprint formula, SLA day-count, and backoff number in
this skill is transcribed from a shipped, tested implementation:

- `chatter/matching.py`, `chatter/classifier.py`, `chatter/runner.py`, `chatter/daemon.py`,
  `chatter/promote.py`, `chatter/targets.py`, `chatter/sources/*.py` — the adversary-chatter subsystem
- `monitor.py`, `web/monitor_scheduler.py` — the scheduled re-scan-and-diff loop
- `reporting/diff.py` — the scan-to-scan delta engine
- `fleet/store.py`, `fleet/promote.py`, `fleet/sla.py` — cross-scan finding lifecycle
- `findings_watchlist/daemon.py`, `findings_watchlist/runner.py`, `findings_watchlist/store.py` —
  rule-based alerting on raw scan findings
- `alerts/store.py`, `alerts/worker.py` — the durable retry/backoff outbox
- `model/findings.py::compute_fingerprint` — the cross-scan finding identity key

See the Changelog in SKILL.md §13 for the full source list.

## Passive / analysis only

This skill schedules re-runs of recon that is already authorized, reads public CTI feeds, and diffs
scan output. It introduces no new active-intrusion technique — see SKILL.md §5 for the explicit
Do-NOT list, including the standing-authorization nuance for recurring `--validate` jobs (§1).

## Loading

```bash
# Local Claude Code install
cp SKILL.md ~/.claude/skills/continuous-exposure-monitoring/SKILL.md

# Or attach to a Claude.ai project / Claude API system prompt
# (paste the contents of SKILL.md as project knowledge)
```

## Self-test

Run the 16 prompts in SKILL.md §12 against a fresh session to verify the skill loads and routes
correctly — including prompt 10, the negative case on re-alerting a `risk_accepted` finding, and
prompt 15, the standing-authorization trap on a dashboard job silently carrying `--validate`.

## License

MIT — see [LICENSE](../../LICENSE).
