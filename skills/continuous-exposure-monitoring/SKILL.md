---
name: continuous-exposure-monitoring
description: "Turns one-shot external recon into a continuous monitoring program. Covers the scheduled re-scan-and-diff loop (baseline snapshot -> interval sleep -> re-scan -> asset/finding delta -> threshold-gated webhook alert), the scan-to-scan diff engine (new/removed/changed assets by a tracked-attribute table, new/resolved findings by a stable cross-scan fingerprint), adversary CTI / chatter monitoring across six public feeds (ransomwatch, ransomware.live, HackerNews Algolia search, Reddit security-subreddit RSS, GitHub Gist code-search, public Telegram channel scraping) with a source-kind-aware severity engine (leak-site/forum/telegram/paste tiers, CRITICAL through INFO), literal/glob/regex watchlist pattern matching, full-corpus capture with retroactive rescan on new watchlist entries, infrastructure-tracking-over-time discipline (certificate-transparency, passive-DNS, port/service, and typosquat re-enumeration cadence, and what a genuine 'perimeter drift' event looks like in the diff output), a five-state finding-lifecycle state machine (open/triaged/risk_accepted/resolved/false_positive) with per-severity SLA and fingerprint-based cross-scan dedup and auto-resolve/reopen rules, the alert-fatigue trap where a lifecycle-unaware rule re-fires on an already-accepted finding, a durable retry/backoff alert-outbox pattern ('queued is not delivered'), and copy-paste bash-cron plus PowerShell-Scheduled-Task recipes for a re-scan+diff loop with the Slack-compatible webhook payload shape. Passive OSINT and analysis only -- no new active-intrusion technique. Use when setting up ongoing monitoring for a retainer or MSSP engagement, tuning alert thresholds to avoid fatigue, triaging a finding's lifecycle status, investigating adversary chatter about a brand, building a 'what changed on the perimeter since last week' report, or deciding whether a persisting finding should re-alert."
version: 1.0
triggers:
  - continuous monitoring
  - continuous exposure monitoring
  - retainer monitoring
  - MSSP monitoring
  - scheduled rescan
  - scheduled scan
  - scan diff
  - diff scans
  - monitor a target
  - monitor continuously
  - re-scan and diff
  - delta alert
  - alert on delta
  - drift detection
  - attack surface drift
  - perimeter drift
  - what changed since last scan
  - ransomware leak site monitoring
  - leak site monitoring
  - adversary chatter
  - dark web monitoring
  - brand mention monitoring
  - IAB monitoring
  - paste site monitoring
  - telegram brand monitoring
  - CTI feed
  - threat intel feed
  - chatter watchlist
  - retroactive rescan
  - infrastructure tracking over time
  - certificate transparency monitoring
  - CT log monitoring
  - passive DNS deltas
  - new subdomain alert
  - typosquat monitoring
  - typosquat surveillance
  - finding lifecycle
  - false positive triage
  - risk accepted
  - finding suppression
  - alert fatigue
  - durable alert delivery
  - alert outbox
  - retry backoff
  - finding SLA
  - overdue finding
  - cron recon
  - scheduled task recon
  - monitoring cadence
  - fleet monitoring
  - cross-scan tracking
  - queued vs delivered
---

# Continuous Exposure Monitoring — Loop, Diff, Chatter, Lifecycle

> Companion skills: [`osint-methodology`](../osint-methodology/) (the 5-stage pipeline this skill
> loops — see its §7.2 "ongoing weekly diff" profile, which this skill fills in with concrete
> mechanics), [`offensive-osint`](../offensive-osint/) (§29 Threat Intel & IOCs — this skill
> **deepens** that section's advisory/IOC-feed directory with the continuous adversary-chatter
> watch loop and CTI-feed cadence it explicitly lacks; use §29 for indicator enrichment and
> vulnerability-prioritization data sources, this skill for the standing collection loop),
> [`org-attack-surface`](../org-attack-surface/) (the org-first discovery this skill's re-scans
> re-run on a schedule), [`exposure-risk-quantification`](../exposure-risk-quantification/) (reads
> this skill's finding-lifecycle suppression state to compute `risk_trend` and the FAIR score — see
> its risk-score model). This skill answers a different question than all four: not "what does the
> target expose right now," but **"is what the target exposes changing, and should anyone be told."**

## 0. When to Use / When NOT

**Use this skill when:**
- Standing up ongoing monitoring for a retainer, MSSP, or bug-bounty program instead of a one-shot
  engagement — the client wants to know about *new* exposure, not to re-read yesterday's report.
- Deciding how often to re-run which recon stage (daily vs. weekly vs. monthly) without either
  wasting API quota / detection budget on cheap-to-skip stages or missing real drift.
- Building or tuning adversary-chatter monitoring (ransomware leak sites, forum/paste mentions,
  Telegram brand mentions) for a target's brand/domain.
- Deciding whether a finding that keeps showing up in every re-scan should keep alerting, or has
  already been triaged/accepted and should go quiet.
- Debugging "the webhook never fired" or "the webhook fired twice" — alert delivery reliability,
  dedup, and backoff behavior.
- Writing a "what changed on the perimeter since last week" deliverable.

**Do NOT use this skill when:**
- You need the one-shot discovery methodology itself — that's `osint-methodology` (5-stage
  pipeline) and `offensive-osint` (the per-technique arsenal). This skill assumes discovery already
  happened at least once and is about the *second and every subsequent* run.
- You need a new active-intrusion technique. This skill is a scheduling, diffing, and alerting
  layer over recon that is already authorized and already running — see §5.
- The target's authorization isn't established, or a **recurring** cadence hasn't been explicitly
  agreed — see §1's monitoring-specific authorization note.

---

## 1. Authorization & Legal Posture

Same base posture as the companion skills: intended for assets the operator owns or has **written
authorization** to assess — see `osint-methodology` §1 for the full soft-scope-check script.

**The monitoring-specific nuance:** a point-in-time engagement authorization does not automatically
cover an indefinite recurring cadence. Before standing up a `monitor`/`chatter watch` daemon or a
dashboard-scheduled job against a target, confirm the authorization window explicitly covers the
monitoring period (retainer end date, RoE renewal terms), not just "the engagement." A scheduled job
that outlives its authorization is a standing violation, not a one-off mistake — it fires every
interval until someone notices and tears it down.

**Always-on guardrail specific to this skill:** a monitoring loop must never silently escalate its
own authorization tier. The `monitor` CLI command's flag surface only exposes `--only`/`--exclude`
module filters — it has no path to enable `--validate` (the credential/token-submission tier), so a
scheduled `asm-cli monitor` loop cannot accidentally re-arm that tier. The dashboard job
scheduler is different: a job's `flags` field accepts the same flags a manual scan does, so an
operator *can* configure a recurring job with `--validate`/`--validate-creds` set. Treat that as a
standing-authorization decision that needs its own explicit sign-off, not a monitoring-cadence
decision — see §5.

---

## 2. Confidence Levels

Same three-tier scale as the companion skills — **TENTATIVE / FIRM / CONFIRMED** — answers "how sure
am I this is real." This skill adds one axis that is easy to conflate with confidence and must not
be:

**Confidence is not lifecycle status.** A chatter hit can be HIGH severity and still TENTATIVE
confidence (adversary-controlled content is always TENTATIVE by design — see §7.6). A finding can be
CONFIRMED confidence and still be `risk_accepted` in the lifecycle (§9) — the client acknowledged a
*real* exposure and chose to keep it. Never let a severity or confidence label imply anything about
whether a human has already triaged the finding, and never let a lifecycle status imply anything
about whether the underlying evidence was independently verified. They are orthogonal axes recorded
in different places (the Finding's `confidence` field vs. `finding_lifecycle.status`).

---

## 3. Output Format

Three schemas this skill's outputs use. All timestamps UTC ISO-8601.

**Finding** — same schema as the companion skills (see `osint-methodology` §3); chatter-sourced
findings always carry `confidence: tentative` (§7.6).

**Delta event** — what a monitoring cycle reports:

```
DeltaEvent:
  scan_a_id / scan_b_id:   older / newer scan
  scan_a_time / scan_b_time
  kind:          new_asset | removed_asset | changed_asset | new_finding | resolved_finding
  asset_or_finding_key:    the asset key, or the finding's fingerprint::asset_key::title
  type_or_category:        asset type, or finding category
  severity:                info|low|medium|high|critical  (findings only)
  changes:                 {attr: [old, new]}              (changed_asset only)
  alert_fired:              bool — did this event cross the configured threshold
```

**Lifecycle record** — cross-scan identity for one finding at one target (see §9):

```
LifecycleRecord:
  target:              lowercased registrable domain
  fingerprint:          16-hex sha1, stable across scans (§9.2)
  status:               open | triaged | risk_accepted | resolved | false_positive
  first_seen_ever:      UTC, earliest scan_started_at this fingerprint appeared in
  last_present_scan/at: most recent scan that reproduced this fingerprint
  age_scans:            count of scans this fingerprint has appeared in
  sla_due:              UTC, computed from severity at first insert (§9.4)
  triaged_by/at, resolved_by/at, notes
```

---

## 4. Source Hygiene & Citations

Same discipline as the companion skills: URL + UTC timestamp + SHA-256 + tool version + run_id per
artifact. One monitoring-specific addition: **the chatter corpus tables (`ransomware_corpus`) persist
every observed row regardless of whether it currently matches a watchlist, precisely so retroactive
analysis (§7.4) has real historical data to search rather than needing to re-fetch a since-rotated
feed.** Treat that corpus as an evidence store in its own right — dedup on the natural key
(source/group/victim), never delete rows to "clean up," and cite `corpus_id` alongside the hit id
when a finding traces back to a retroactive match.

---

## 5. Do NOT

- Do **not** treat a scheduled job's "queued" status as "delivered" — see §10.1. Confirm delivery by
  querying the outbox, not by the enqueue call succeeding.
- Do **not** re-alert on a finding whose lifecycle status is `resolved`, `false_positive`, or
  `risk_accepted` just because a re-scan rediscovered it — see §9.6 for the exact mechanics and which
  alerting subsystem actually protects against this (only one of the two does, natively).
- Do **not** let a recurring monitoring job silently carry `--validate`/`--validate-creds` unless
  that specific standing authorization was explicitly confirmed — see §1.
- Do **not** open a chatter-sourced URL (leak site, paste, Telegram post) directly in your working
  browser. Adversary-controlled content is TENTATIVE by definition (§2, §7.6) — open only in an
  isolated browser/VM/Tails, exactly as `osint-methodology` §6.1 (OpSec) requires generally.
- Do **not** invent an SLA day-count, backoff schedule, or poll interval. This skill's numbers (§9.4,
  §10.2) are transcribed from the shipped defaults; if an operator wants different numbers, say so
  explicitly rather than presenting a made-up default as authoritative.
- Do **not** widen a `findings_watchlist` rule's `severity_min` or drop its `category`/`module`
  filters to "catch more" without first reading §9.6 and §10.5 — an unscoped rule on this subsystem
  re-fires every re-scan on a persisting issue, unlike the fingerprint-diff alerting in §6.
- Do **not** introduce a new active-intrusion technique to "monitor better." Every module a
  monitoring loop re-runs is a technique that was already authorized for the one-shot engagement;
  this skill only adds cadence, diffing, and alerting around it.

---

## 6. The Monitoring Loop Model

### 6.1 The five-step loop

The canonical pattern (`monitor.py`):

1. **On startup**, run a scan immediately — establishes a baseline if none exists.
2. **Sleep** `interval` seconds.
3. **Run** a new scan.
4. **Diff** the latest two scans for the target (§6.3 / §7).
5. **If** the delta crosses the alert threshold, POST a webhook (§10). Otherwise log and continue.
6. Go to 2.

A first run against a fresh target has no prior scan to diff against — the loop logs "first scan —
no prior baseline to diff against; skipping alert" and simply establishes the baseline. Nothing
alerts on run #1 by design.

### 6.2 Two implementations

A mature ASM implementation ships two ways to run this loop — pick based on scope:

| | CLI foreground daemon | Dashboard job scheduler |
|---|---|---|
| Entry point | `asm-cli monitor <target> ...` | `monitor_scheduler.scheduler_daemon_loop` |
| Scope | one target per process | many jobs, persisted in `MonitorJobStore` |
| Visibility | own stdout only | dispatched via `ScanManager.launch()` — appears in the live dashboard scan list |
| Poll/dispatch cadence | the loop's own `--interval` | polls for due jobs every 30s (`_POLL_SECONDS`) |
| Per-run safety cap | none — interval only | 7200s (2h) `_SCAN_MAX_SECONDS`; a wedged scan is cancelled and the loop moves on (already rescheduled) |
| Disable | Ctrl-C | `ASM_DISABLE_MONITOR_SCHEDULER=1` |
| `--validate` reachable? | **No** — the CLI's flag surface is `--only`/`--exclude` only | **Yes** — job `flags` accepts the same flags a manual scan does; see §1 |

Both funnel through the same diff-and-alert logic (`monitor._maybe_alert`) — the scheduler literally
imports and calls it, so §6.5's alert-worthy rule is identical either way.

### 6.3 What "diff" means

The diff engine (`reporting/diff.py`) compares two `scan.db` files and produces:

- **New / removed assets** — pure set difference on asset `key`.
- **Changed assets** — for keys present in both scans, a per-type **tracked-attribute** table decides
  what counts as a meaningful change (deliberately narrow — noise like response time or timestamp
  casing would otherwise drown the real signal):

| Asset type | Tracked attrs | Asset type | Tracked attrs |
|---|---|---|---|
| `webapp` | `status`, `title`, `server`, `tech`, `waf`, `cdn_name`, `jarm`, `favicon_hash`, `content_hash`, `redirect_off_scope` | `certificate` | `not_after`, `issuer`, `self_signed` |
| `port` | `ip`, `port`, `transport` | `bucket` | `provider`, `listable`, `public` |
| `service` | `ip`, `port`, `product` | `credential` | `email`, `breach` |
| `subdomain`, `ip`, `email`, `person`, `repo`, `domain`, `typosquat_domain`, `wayback_endpoint`, `asn`, `netblock` | existence-only — no attrs tracked | | |

  A note on existence-only types: since an asset's `key` typically embeds its `value` (e.g.
  `ip:1.2.3.4`), a subdomain re-pointing to a new IP does **not** surface as a "changed" event — it
  surfaces as a paired `removed_asset` (old IP) + `new_asset` (new IP), because the key itself
  changed. Read a re-point out of the new/removed pairing, not out of `changed_assets`.

- **New / resolved findings** — keyed by the finding's persisted **fingerprint** (v6+ scan.db; older
  DBs fall back to a synthetic `asset_key::title` key). A finding present in scan B but not scan A is
  "new"; present in A but not B is "resolved." Fingerprint mechanics — including why a resolved
  finding reappearing is *not* silently treated as fine — are in §9.

### 6.4 Cadence guidance

Not every stage is worth re-running on the same schedule. Passive re-enum is cheap; active probing
costs quota, time, and detection budget (`osint-methodology` §6.4 back-off ladder still applies to
every active re-run).

| Stage (orchestrator numbering) | What's in it | Cost profile | Suggested cadence |
|---|---|---|---|
| 1 — Seed discovery | `whois_mod`, `asn`, `dns_deep`, `certs`, `pdns` | Cheap, keyless, passive | Daily is fine |
| 2 — Asset expansion | `subdomain` (brute-force component), `cloud_buckets`, `wayback`, `typosquat`, `mobile_attack_surface` | Moderate; some active probing (bucket HEAD/GET, DNS resolution of typosquat candidates) | Daily-to-weekly |
| 3 — Enrichment | `ports`, `host_intel`, `web_probe`, `email_osint`, `github_recon`, `sso_idp`, `api_discovery` | First real active web traffic; cost scales with alive-host count | Weekly |
| 4 — Exposure analysis | `nuclei_mod`, `path_fuzz`, `param_discovery`, `screenshots`, `bypass403`, `paramminer` | Heaviest active probing in the default-on tier | Weekly, or slower on a large asset count — detection-aware back-off still governs |
| 5 — Recursion + supply-chain | `recon_recurse`, `aws_account_enum`, `dependency_confusion` | Pairs with whatever cadence you picked for a full re-scan | Same as the full-scan cadence |
| 6 — `--validate` tier | credential/token-submission modules | Highest authorization tier | **Never on an unattended schedule** without a human re-confirming scope each run — see §1 |

Rule of thumb: if the client's driver is "tell me about new subdomains, certs, buckets, and
ransomware chatter," a **daily** stage-1/2-only loop plus the chatter daemon (§7) covers it cheaply.
If the driver is "tell me about new exposed misconfigurations," you need stage 4, and weekly is the
realistic floor once asset count is non-trivial.

### 6.5 What's alert-worthy

`monitor._maybe_alert` fires when **either**:
- A new finding's severity rank is at or above the configured `--threshold` (default **medium**), or
- A new asset's type is in the hot-asset-type set: `credential`, `typosquat_domain`, `bucket`,
  `repo` — these fire **regardless of severity threshold**, because a brand-new credential leak,
  lookalike domain, exposed bucket, or newly-discovered repo is always worth a look even before
  triage assigns it a severity.

Nothing else in the diff — resolved findings, changed assets, new low-severity findings outside the
hot-asset types — triggers a webhook on its own. It's still in the diff output and the Markdown
report (§6.3), just not pushed.

---

## 7. CTI / Adversary Chatter Monitoring

The `chatter/` subsystem is the standing adversary-side watch: six public sources polled on their own
cadence, matched against an operator watchlist, classified into severity, and (above threshold)
pushed to a webhook.

### 7.1 The six sources

| Source | Kind | Endpoint | Cadence | Key |
|---|---|---|---|---|
| `ransomwatch` | leak_site | `https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json` | 300s (5 min) | none |
| `ransomware_live` | leak_site | `https://api.ransomware.live/v2/recentvictims` | 300s | none |
| `hackernews` | forum | `https://hn.algolia.com/api/v1/search` (Algolia HN search) | 600s (10 min) | none |
| `reddit` | forum | `https://www.reddit.com/r/<sub>/.rss` across `cybersecurity`, `netsec`, `InfoSecNews`, `blueteamsec`, `Pwned`, `AskNetsec`, `sysadmin` | 600s | none |
| `paste:gist` | paste | `https://api.github.com/search/code` (filtered to `gist.github.com` results) | 900s (15 min) | `GITHUB_TOKEN` |
| `telegram` | telegram | `https://t.me/s/<channel>` public web preview | 1800s (30 min) | none, but needs channels configured under `market_intel.telegram.channels` (seed with `asm-cli breach discover --kind telegram`) |

The two leak-site sources (`ransomwatch`, `ransomware_live`) each poll their full feed on **every**
cycle and persist **every** row to a local `ransomware_corpus` table — not just watchlist matches.
That full-corpus capture is what makes §7.4's retroactive rescan possible.

`hackernews` and `reddit` always inject a set of generic seed keywords (`data breach`, `ransomware`,
`0day`, `supply chain attack`, `vulnerability`, `CVE` for HN; a broader breach/leak/exploit list for
Reddit) alongside the operator's watchlist, so the chatter dashboard shows ambient threat-landscape
chatter even before a watchlist exists — those hits are tagged `relevance: ambient` and are excluded
from client-facing promotion (§7.6).

### 7.2 Watchlist pattern types

Every source routes matching through a shared compiler (`chatter/matching.py`). Three pattern types,
all case-insensitive:

| Type | Semantics | Default |
|---|---|---|
| `literal` | substring match | yes |
| `glob` | fnmatch wildcards (`*`, `?`, `[seq]`) | |
| `regex` | full Python regex, search-mode | |

A glob or regex pattern that fails to compile falls back to literal match with a logged warning — one
bad pattern can never wedge the whole collection cycle. Add a pattern:

```bash
asm-cli chatter watchlist add "acme*.com" --kind domain --pattern-type glob \
  --priority high --notes "primary + all TLD variants"
```

```powershell
asm-cli chatter watchlist add "acme*.com" --kind domain --pattern-type glob `
  --priority high --notes "primary + all TLD variants"
```

`--kind` is one of `domain | brand | keyword | email` — it feeds the severity engine below (a
`domain`-kind match ranks higher than a `brand`/`keyword` match at the same source).

### 7.3 The severity engine

`chatter/classifier.py::classify()` — never raises, always returns a `(severity, category,
classification, reason)` tuple. The rubric is source-kind-aware, not a flat rule:

| Source kind | Signal | Severity |
|---|---|---|
| `leak_site` | domain-kind match + a named ransomware group recognized in the text | **CRITICAL** |
| `leak_site` | any other match on a leak-site listing | **HIGH** |
| `forum` | IAB-style phrase (see below) + domain match + a price/currency marker in the excerpt | **HIGH** |
| `forum` | IAB phrase + domain match, no price | **MEDIUM** |
| `forum` | domain match, no IAB phrase | **MEDIUM** |
| `forum` | brand/keyword match | **LOW** |
| `telegram` | secret-regex hit in the post text | **HIGH** |
| `telegram` | domain match + IAB phrase | **CRITICAL** |
| `telegram` | domain match, no IAB phrase | **HIGH** |
| `telegram` | email match | **HIGH** |
| `telegram` | brand/keyword match | **MEDIUM** |
| `telegram` | any other match | **MEDIUM** (floor — adversary channels never rank below this) |
| paste / other | secret-regex hit in the excerpt | **HIGH** |
| paste / other | domain match + IAB phrase | **HIGH** |
| paste / other | domain match, no IAB phrase | **MEDIUM** |
| paste / other | brand/keyword match | **LOW** |
| paste / other | email match | **MEDIUM** |
| paste / other | no rule fired | **INFO** |

Note the telegram tier floors one step above the equivalent paste-site tier for every pattern kind —
an adversary-run channel is treated as inherently higher-signal than an ambient paste dump.

**IAB-style phrases** (substring, lowercased): `access `, `rdp `, `vpn`, `domain admin`, `citrix`,
`esxi`, `netscaler`, `admin panel`, `exchange server`, `initial access`, `shell`/`reverse shell`/
`webshell`, `privileged account`, `oauth token`.

**Recognized ransomware groups** (partial — checked case-insensitively against the post text):
`lockbit`, `akira`, `cl0p`/`clop`, `ransomhub`, `play`, `blacksuit`, `medusa`, `qilin`, `rhysida`,
`8base`, `cactus`, `inc ransom`, `hunters international`, `darkvault`, `embargo`, `dragonforce`,
`kasseika`, plus legacy names still seen on mirrors: `revil`, `conti`, `alphv`/`blackcat`,
`blackbyte`, `royal`, `vice society`, `bianlian`, `snatch`.

A hit's severity can also be **promoted** — never demoted — by a source-supplied `severity_hint`
(HackerNews/Reddit infer high/medium/low/info from title keywords like "leak"/"breach"/"CVE"/
"advisory" before the classifier even runs) when the hint outranks the classifier's own verdict.

### 7.4 Retroactive rescan on new watchlist entries

Adding a watchlist entry (`chatter watchlist add`, default `rescan=True`) doesn't just start matching
future chatter — it immediately searches the **full historical `ransomware_corpus`** for matches
already sitting in the corpus:

- Literal patterns use an indexed `LIKE` search (fast, unbounded).
- Glob/regex patterns pull the most recent 10,000 corpus rows and filter in Python via the shared
  matcher (bounded so a pathological pattern can't stall the CLI/daemon).

Matches found this way are inserted as normal `chatter_hits` rows but are pre-marked `alerted=1` —
the daemon will **not** webhook-spam the operator with 18-month-old news the moment a new watchlist
entry is added. This is what solves "the client was hit by this group over a year ago and we only
just started watching for them" — the historical hit shows up in the dashboard and the hit-detail
view, silently, without an alert storm.

### 7.5 Full-corpus capture

Both leak-site sources persist every row they see on every poll to `ransomware_corpus`, dedup'd on a
natural key, **regardless of whether anything currently on the watchlist matches**. This is the
precondition for §7.4 and for any later trend-tracking query ("how many of our client's peers in this
sector have appeared on a leak site in the last 90 days") — without full-corpus capture, a watchlist
added today can only ever see chatter from today forward.

### 7.6 Promotion to scan.db

`chatter/promote.py::promote_hit()` — a one-way copy of a chatter hit into a scan's asset+finding
tables, mirroring the dorking-results promotion pattern:

- **Asset:** `AssetType.WAYBACK` (the existing "externally-harvested URL" type), tagged
  `sources=["chatter:<source>"]`.
- **Finding:** `Category.INFO_DISCLOSURE`, severity from the classifier, **confidence always
  `TENTATIVE`** — chatter is adversary-controlled content by definition, and the description text
  explicitly instructs: *"Open the URL ONLY in an isolated browser / VM / Tails. Validate
  authenticity before escalating."*
- Only fires for hits at/above `min_finding_severity` (default **medium**) — low/info hits stay
  asset-only, visible in the dashboard, not promoted as a finding.
- **Ambient hits are hard-blocked from promotion.** A hit whose `relevance` is `ambient` (matched only
  a generic seed keyword, no watchlist pattern behind it — §7.1) returns `PromotionResult(ok=False,
  ...)` unconditionally. There is no client-specific signal behind an ambient hit, so it must never
  reach the client-facing deliverable or scan.db findings — only a genuine watchlist match can.

### 7.7 Running it

```bash
asm-cli chatter watch --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ \
  --threshold high --tick 30
```

```powershell
asm-cli chatter watch --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ `
  --threshold high --tick 30
```

`--threshold` (default **high**) is the severity floor for the webhook, independent of §6.5's
`monitor` threshold — they're two separate daemons with two separate knobs (§10.5). `--tick` is how
often the daemon checks whether any source's per-source cadence (the table in §7.1) has elapsed; it
does not itself poll every tick.

---

## 8. Infrastructure Tracking Over Time

This methodology assumes no push/streaming CT-log feed — every signal in this section is **poll +
diff**: re-run the relevant module on the loop's cadence (§6.4) and read the delta out of §6.3's
asset diff. What follows is which module produces which tracked-attribute signal, and what it means
when it fires.

| Signal | Module (re-run cadence from §6.4) | Where it shows up in the diff |
|---|---|---|
| New certificate | `certs` (stage 1, cheap, safe daily) — crt.sh + certspotter + leakix union | New `certificate` asset; tracked attrs `not_after`/`issuer`/`self_signed` on the existing cert if reissued |
| New subdomain | `subdomain`, `certs`, `pdns`, `wayback` (any of these can surface a new hostname) | New `subdomain` asset (existence-only — presence is the signal) |
| Passive-DNS delta / IP re-point | `pdns` (stage 1, HackerTarget keyless + optional OTX) | A subdomain's IP changing shows as a **paired removed+new `ip` asset** (§6.3's existence-only-type note), not a "changed" event |
| New open port / service change | `ports` (stage 3 — Shodan InternetDB passive, or `--probe` active native scan) | New `port` asset (tracked `ip`/`port`/`transport`); a fingerprint/product change on an existing port is a `changed_assets` entry (tracked `ip`/`port`/`product` on `service`) |
| New typosquat / lookalike domain | `typosquat` (stage 2 — dnstwist permutations + DNS resolution of candidates) | New `typosquat_domain` asset — **always** fires the webhook per §6.5's hot-asset-type rule, regardless of severity threshold; a mail-capable lookalike is escalated to HIGH by the module itself |

**The single highest-signal "perimeter drift" event class** this platform ships is a new
`typosquat_domain`, `credential`, `bucket`, or `repo` asset — all four are in `monitor.py`'s
hot-asset-type override (§6.5), meaning they alert regardless of the configured severity threshold.
If a client asks "what's the one thing I should never have muted," it's these four asset types.

### 8.1 A worked weekly recipe

Either let the loop do it automatically (§6, §11) or run it by hand:

```bash
# Last week's scan id vs. this week's, most-recent-first in scans/
asm-cli diff acme_com_20260730 acme_com_20260806 \
  --scans-root scans --out reports/weekly-diff.md --json reports/weekly-diff.json
```

```powershell
asm-cli diff acme_com_20260730 acme_com_20260806 `
  --scans-root scans --out reports/weekly-diff.md --json reports/weekly-diff.json
```

The Markdown report (`reporting/diff.py::render_markdown`) sections, in order: Summary counts → 🆕
NEW findings (sorted highest severity first) → ✅ RESOLVED findings → 🆕 NEW assets (grouped by type)
→ ➖ REMOVED assets (grouped by type) → 🔄 CHANGED assets (with the old→new value for every changed
attr). Each section caps at 50 items with a `…N more` ellipsis so a noisy diff doesn't blow out the
report.

---

## 9. Finding Lifecycle & False-Positive Discipline

The `fleet/` subsystem is what lets a finding have a *state* that persists across scans, instead of
every re-scan treating every finding as new.

### 9.1 The five states

```
open  →  triaged  →  {risk_accepted | resolved | false_positive}
  ↑____________________________|  (resolved can REOPEN to open — see §9.3)
```

`open`, `triaged`, `risk_accepted`, `resolved`, `false_positive` — enforced enum
(`_LIFECYCLE_STATUSES`). Two of the five are **suppressed** — excluded from dashboard counters, the
FAIR risk grade, and attack-path chains: `false_positive` and `resolved`.

**`risk_accepted` is deliberately *not* suppressed.** It's a real, acknowledged exposure the client
chose to keep — it must still count toward the risk grade and still appear in attack-path reasoning.
This is the single most common lifecycle mistake to correct: "the client accepted the risk" does not
mean "this finding no longer matters for scoring," it means "the client made an informed decision
about a finding that is still real."

### 9.2 Fingerprint — the cross-scan identity key

```
fingerprint = sha1(f"{module}\x1f{asset_key}\x1f{category.value}\x1f{normalized_title}")[:16]
```

`normalized_title` = lowercased, all digit runs replaced with `#`, whitespace collapsed. The
digit-normalization is deliberate: a title like "Open port 8080 exposed" and "Open port 9090 exposed"
both normalize to the same string (`open port # exposed`), so the same underlying misconfiguration
type on the same asset stays one lifecycle identity even as incidental digits in the title drift
between scans. The `\x1f` (ASCII unit separator) between fields avoids cross-field collisions from
any field that happens to contain a more common delimiter.

Two related-but-different keys exist — do not conflate them:
- `fleet_findings` is keyed `(scan_id, fingerprint)` — one row **per scan**, the per-scan snapshot.
- `finding_lifecycle` is keyed `(target, fingerprint)` — one row **per target**, the cross-scan
  identity that actually carries the state machine.

### 9.3 Reconciliation — auto-resolve and reopen

Runs automatically at the end of every scan (`fleet.promote.promote_scan_into_fleet` →
`FleetStore.reconcile_lifecycle`), given the full set of fingerprints present in the just-completed
scan:

- **New fingerprint** (never seen for this target) → `INSERT status='open'`, `age_scans=1`, `sla_due`
  computed from severity (§9.4).
- **Fingerprint reappears** in a newer scan → `age_scans += 1`, `last_present_scan/at` bumped. If its
  status was `resolved`, it is **reopened to `open`** — a resolved issue coming back is a real
  regression and must not be silently treated as still-fine.
- **Fingerprint absent** from the new scan, and its status was `open` or `triaged`, and it was last
  present in a *strictly earlier* scan (same-scan idempotence guard) → **auto-resolved**
  (`resolved_by='auto'`).

`risk_accepted` and `false_positive` fingerprints are untouched by reconciliation either way — they
don't auto-resolve when absent (nothing to resolve, the operator already made a call) and they don't
silently flip back to `open` on reappearance the way `resolved` does; they stay exactly as the
operator left them unless a human changes the status.

### 9.4 SLA

`sla_due` is computed once, at first insert, from the finding's severity:

| Severity | SLA (days) |
|---|---|
| critical | 7 |
| high | 14 |
| medium | 30 |
| low | 90 |
| info | none |

`fleet/sla.py::sla_state()` classifies a lifecycle row against `now`: `overdue` (active status, past
`sla_due`), `due_soon` (within 3 days of due), `on_track`, or `none` (closed status, or an
info-severity finding with no SLA at all). Only `open`/`triaged` rows can be `overdue` or
`due_soon` — a `risk_accepted`/`resolved`/`false_positive` row is never flagged against the SLA clock
regardless of how old it is.

### 9.5 Suppression feeds risk scoring

`fleet.store.suppressed_fingerprints(target)` — the single source of the suppression rule — is
consumed by `reporting/risk_score.py` and `reporting/attack_paths.py`. A `false_positive` or
`resolved` fingerprint is invisible to both; a `risk_accepted` one is visible to both (§9.1). See
`exposure-risk-quantification` for how that feeds the FAIR score and `risk_trend`.

### 9.6 The alert-fatigue trap — which subsystem actually protects you

This is the answer to the recurring question "why did I get alerted again on a finding we already
marked risk-accepted / false-positive":

**Two separate alerting subsystems exist, and only one of them is lifecycle-aware:**

| Subsystem | Dedup key | Lifecycle-aware? |
|---|---|---|
| `monitor` / `monitor_scheduler` diff alerting (§6) | the finding's **fingerprint** — a re-scan that reproduces the same fingerprint is not a "new" finding, full stop | Yes, **structurally** — same fingerprint can never appear in `new_findings` twice |
| `findings_watchlist` rule matching | `(rule_id, finding_id)` where `finding_id` is the **per-scan** database row id, freshly generated by every scan | **No** — `_matches_rule()` checks severity/category/module/target-pattern/title-regex/KEV/EPSS only; it never reads `finding_lifecycle`. A fresh scan produces a fresh `finding_id` for the same underlying fingerprint, so the `(rule_id, finding_id)` dedup key does not recognize it as a repeat |

The practical consequence: a `risk_accepted` finding that keeps reappearing in every re-scan will
**not** re-trigger a `monitor` webhook (its fingerprint isn't "new"), but a broad
`findings_watchlist` rule with a low `severity_min` and no `category`/`module` narrowing **will**
re-fire on it every single time the daemon's cursor sees a scan that reproduces it — because from
that rule's point of view, it's a fresh finding row it hasn't alerted on before.

Recommendations, in priority order:
1. Prefer `monitor`'s fingerprint-diff alerting for "tell me about *new* things" — it's the only one
   with lifecycle-equivalent protection built in.
2. If you need `findings_watchlist` rules (they're the tool for "alert on any finding matching X,
   in any scan," which diff alerting can't express), narrow them hard — specific `category` +
   `module`, or `require_kev`/`epss_min` — rather than a blanket `severity_min=medium` catch-all.
3. If a `findings_watchlist` rule keeps re-firing on a triaged issue, the fix is upstream: mark the
   fingerprint's lifecycle status in fleet (§9.1) and, if the rule is too broad to respect that
   automatically, tighten the rule rather than muting the whole webhook.

---

## 10. Alert Delivery Reliability

### 10.1 "Queued is not delivered"

Every alert sender in this platform (`monitor`, `chatter` daemon — which literally imports and reuses
`monitor.py`'s `_post_webhook`, so its outbox rows show up tagged `kind="monitor"`, not
`kind="chatter"` — and `findings_watchlist`, tagged `kind="watchlist"`) **enqueues** into a durable
outbox (`alerts/store.py`) instead of POSTing inline. The sender's own success/`notified` bookkeeping
reflects **enqueue succeeding**, not delivery. `findings_watchlist._post_alert` says so explicitly in
its docstring — *"returns (True,'') on enqueue (queued = success for the caller's notified
bookkeeping)"* — and `monitor._post_webhook` behaves identically (it enqueues and returns without
confirming delivery). To know whether a webhook
actually reached its destination, query the outbox itself — never infer it from the caller's log
line.

### 10.2 Backoff and dead-letter

```
compute_backoff(attempts) = min(60 * 2**attempts, 21600)   # base=60s, cap=21600s (6h)
```

Delivery attempts back off 120s → 240s → 480s → 960s → 1920s → 3840s → 7680s (the `min(…, 21600)`
6h cap is a theoretical ceiling the default `max_attempts=8` never reaches — 7680s is the last backoff
actually scheduled). After **8** attempts (`max_attempts`, default), the row's status flips to `dead` — a literal dead-letter
state, visible in the outbox for manual retry, not silently dropped.

### 10.3 Dedup

```
dedup_key = f"{kind}:" + sha1(url + json.dumps(payload, sort_keys=True))[:16]
```

`enqueue()` skips inserting a new row if a row with the same `dedup_key` is still `pending` —
duplicate-suppression only against *not-yet-delivered* duplicates, not against history (a genuinely
repeated event after the first one delivered will enqueue again, correctly).

### 10.4 Delivery worker and retention

`alert_worker_loop` runs every **30s** (`alert_worker_interval`), delivers due rows, and — roughly
once per day — purges `delivered` rows older than **14 days** (`alert_retention_days`) so the outbox
doesn't grow unbounded on an unattended box. Manual controls: `retry(id)` and `retry_all_failed()`
reset attempts to 0 and status back to `pending` (available from the dashboard's outbox page).

### 10.5 Threshold tuning per subsystem — avoid alert fatigue

| Subsystem | Threshold knob | Default | What it gates |
|---|---|---|---|
| `monitor` (CLI) | `--threshold` | `medium` | New-finding severity floor; hot-asset types (§6.5) always fire regardless |
| `monitor_scheduler` (dashboard job) | job's `alert_threshold` field | `medium` | Same `_maybe_alert()` logic, per job |
| `chatter watch` | `--threshold` | `high` | Chatter-hit severity floor for the webhook |
| `findings_watchlist` rule | `severity_min` field, plus `category`/`module`/`target_pattern`/`title_regex`/`require_kev`/`epss_min` | `high` | Per-rule; narrow with the extra filters rather than relying on severity alone (§9.6) |

Start conservative (high-severity-only, plus the always-on hot-asset types) and widen only after
confirming the loop is quiet at the tighter setting — it's far easier to notice "I'm not getting
enough signal" and loosen a threshold than to diagnose alert fatigue after a client starts ignoring
the channel.

---

## 11. Scheduler Recipes

A mature ASM implementation ships three native alternatives to a bare cron loop — prefer these where they fit
before reaching for external scheduling:

- **`asm-cli monitor <target> --interval N --webhook <url> --threshold <sev>`** — single-target
  foreground daemon; does baseline + loop + diff + alert natively (§6).
- **Dashboard job scheduler** — multi-target, appears in the live dashboard, has the 2h per-run
  safety cap (§6.2); configure through the dashboard's monitoring page.
- **`asm-cli chatter watch --webhook <url> --threshold high`** — the adversary-chatter daemon
  (§7.7).

A bare cron/Task-Scheduler loop is still the right call for: ad-hoc periodic reports without wanting
a standing foreground process, wrapping scan+diff+report inside an existing ops pipeline, or a shared
box where a long-running unsupervised Python daemon isn't operationally convenient.

### 11.1 bash cron — weekly re-scan + diff

```bash
# crontab -e  (or drop a file under /etc/cron.d/)
# Every Monday 03:00 — re-scan, diff against last week's scan, write both Markdown + JSON.
0 3 * * 1 cd /opt/asm-cli && \
  OLD_SCAN=$(ls -1t scans | grep '^acme_com_' | sed -n 1p) && \   # newest EXISTING dir = last run; captured before the new scan below is created
  NEW_SCAN="acme_com_$(date +%Y%m%d)" && \
  asm-cli scan acme.com --scan-id "$NEW_SCAN" --scans-root scans \
    >> logs/weekly.log 2>&1 && \
  asm-cli diff "$OLD_SCAN" "$NEW_SCAN" --scans-root scans \
    --out "reports/diff_$(date +%F).md" --json "reports/diff_$(date +%F).json" \
    >> logs/weekly.log 2>&1
```

Adjust `--only`/`--exclude` on the `scan` line per §6.4's cadence table if you want a cheap daily
stage-1/2-only cron alongside a heavier weekly full re-scan (two separate cron lines, two separate
scan-id prefixes).

### 11.2 PowerShell Scheduled Task — same recipe on Windows

```powershell
# Register once (run as the service account that owns the asm-cli install):
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument `
  '-NoProfile -ExecutionPolicy Bypass -File C:\asm-cli\weekly-diff.ps1'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 3am
Register-ScheduledTask -TaskName "AsmWeeklyDiff" -Action $action -Trigger $trigger
```

```powershell
# C:\asm-cli\weekly-diff.ps1
Set-Location C:\asm-cli
$old = (Get-ChildItem scans -Directory | Where-Object Name -like "acme_com_*" |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1).Name  # newest EXISTING = last run; captured before $new is created
$new = "acme_com_$(Get-Date -Format yyyyMMdd)"
asm-cli scan acme.com --scan-id $new --scans-root scans *>> logs\weekly.log
asm-cli diff $old $new --scans-root scans `
  --out "reports\diff_$(Get-Date -Format yyyy-MM-dd).md" `
  --json "reports\diff_$(Get-Date -Format yyyy-MM-dd).json" *>> logs\weekly.log
```

### 11.3 Webhook payload shape

All three alert senders (`monitor`, `chatter`, `findings_watchlist`) emit a **Slack-compatible**
payload — a `text` field (Slack Incoming Webhooks render it directly) plus a structured envelope any
generic JSON-accepting webhook handler can read. The `monitor` shape:

```json
{
  "text": ":rotating_light: *ASM monitor: delta on acme.com*\n_scan-A_ `acme_com_20260730` → _scan-B_ `acme_com_20260806`\n\n*NEW FINDINGS ≥ MEDIUM: 3*\n• `HIGH` — Exposed .git/config _(asset: webapp:dev.acme.com)_\n\nTotals: +4 assets, +3 findings, -1 resolved.",
  "target": "acme.com",
  "scan_a": {"id": "acme_com_20260730", "target": "acme.com", "time": "2026-07-30T03:00:04+00:00"},
  "scan_b": {"id": "acme_com_20260806", "target": "acme.com", "time": "2026-08-06T03:00:11+00:00"},
  "new_findings_total": 3,
  "new_findings_hot": [
    {"severity": "high", "title": "Exposed .git/config", "asset_key": "webapp:dev.acme.com"}
  ],
  "new_assets_hot": [
    {"type": "typosquat_domain", "value": "acrne.com"}
  ]
}
```

The `chatter` shape swaps the summary block for a single-hit envelope (`severity`, `category`,
`classification`, `target`, `source`, `group_name`, `title`, `url`, `hit_id`, `first_seen_at`,
`posted_at`); the `findings_watchlist` shape nests `alert.rule` and `alert.finding` (including
`evidence`, so a KEV/EPSS-gated rule's payload carries the CTI context that triggered it) instead of a
scan-pair summary. All three keep the plain-text `text` field first so a handler that ignores
everything else still renders something legible.

---

## 12. Skill Self-Test

Drop these into a fresh session to verify the skill loads and routes correctly.

1. *"Set up ongoing monitoring for acme.com — new subdomains, certs, and ransomware chatter, cheaply."* → §6.4 (stage 1/2 daily), §7.7.
2. *"What's the difference between `asm-cli monitor` and the dashboard job scheduler?"* → §6.2.
3. *"A subdomain's IP address changed between two scans. Does the diff show that as 'changed'?"* → §6.3 (no — paired removed+new `ip` asset, existence-only types don't track attrs).
4. *"Which asset types alert regardless of severity threshold?"* → §6.5, §8 (credential, typosquat_domain, bucket, repo).
5. *"What real endpoint does the ransomware.live source hit, and how often?"* → §7.1.
6. *"I just added a watchlist entry for a brand we were breached under 18 months ago. Will this spam our webhook with old news?"* → §7.4 (no — retroactive hits pre-marked alerted).
7. *"A Telegram post mentions our domain plus 'RDP access' — what severity?"* → §7.3 (CRITICAL — domain + IAB phrase on telegram).
8. *"Should an ambient HackerNews hit about 'ransomware' with no watchlist match get promoted into the client's scan.db?"* → §7.6 (no — ambient hits are hard-blocked from promotion).
9. *"A finding we marked `risk_accepted` a month ago still shows up in every weekly re-scan. Is it counted in the FAIR risk grade?"* → §9.1, §9.5 (yes — risk_accepted is not suppressed).
10. **Negative test:** *"We marked a finding `risk_accepted`. Should it re-alert the next time the monitor loop diffs a re-scan that still contains it?"* → §9.6 (no, for `monitor`'s fingerprint-diff alerting — same fingerprint isn't 'new'. But flag the caveat: a broad `findings_watchlist` rule with no category/module narrowing WILL re-fire, because it dedups on the per-scan finding_id, not the fingerprint.)
11. *"A resolved finding just reappeared in this week's scan. What happens to its lifecycle status?"* → §9.3 (reopened to `open` — a regression, not silently ignored).
12. *"Our webhook sender logged 'alert fired' but the client says they never got a Slack message. How do I check what actually happened?"* → §10.1 (query the outbox — queued ≠ delivered).
13. *"What's the retry schedule before an alert is marked dead?"* → §10.2 (60s base, ×2 each attempt, capped 6h, dead after 8 attempts).
14. *"Give me a weekly cron job that re-scans and diffs a target, PowerShell version too."* → §11.1, §11.2.
15. *"Can I set a monitoring job on the dashboard to include `--validate` so it re-runs credential testing every week automatically?"* → §1, §6.2 (technically reachable via job flags — but treat it as a standing-authorization decision, not a cadence decision, and confirm sign-off first).
16. *"Show me the webhook payload shape for a monitor delta alert."* → §11.3.

---

## 13. Changelog

- **v1.0 (2026-08-06)** — initial release. The five-step monitoring loop and its two native
  implementations — CLI foreground daemon vs. dashboard job scheduler (§6); the scan-to-scan diff
  engine's tracked-attribute table and alert-worthy delta rule (§6.3–§6.5); a stage-by-stage
  re-scan cadence guide (§6.4); adversary-chatter monitoring across all six shipped public sources
  with exact endpoints/cadences, the source-kind-aware severity engine, retroactive rescan-on-new-
  watchlist-entry, full-corpus capture, and the ambient-hit promotion gate (§7); infrastructure-
  tracking-over-time mapped to the concrete module + tracked-attribute signal behind each drift
  event (§8); the five-state finding-lifecycle machine, fingerprint mechanics (including the
  digit-normalization rationale), auto-resolve/reopen reconciliation, SLA table, and — the
  highest-value original finding in this skill — the precise reason `findings_watchlist` rules are
  NOT lifecycle-aware while `monitor`'s fingerprint-diff alerting structurally is, and what that
  means for avoiding re-alerts on triaged findings (§9); the durable alert-outbox pattern including
  the "queued is not delivered" distinction, backoff/dead-letter numbers, dedup key, and retention
  (§10); and copy-paste bash-cron + PowerShell-Scheduled-Task recipes plus the Slack-compatible
  webhook payload shape for all three alert senders (§11). Every number, endpoint, cadence, and
  rule in this skill is transcribed from a production ASM implementation's shipped monitoring,
  chatter, scan-diff, fleet, findings-watchlist, and alert-outbox modules — not invented.
