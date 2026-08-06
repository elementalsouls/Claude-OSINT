# `email-domain-security` skill

The "how to reason about it" companion to `offensive-osint` §16.14: a rigorous, defensible email-spoofability verdict and SPF supply-chain risk analysis, computed entirely from published DNS.

| Field | Value |
|---|---|
| Name | `email-domain-security` |
| Version | 1.0 |
| Lines | ~590 |
| Top-level sections | 17 (§0–§16) |
| Companion skills | [`offensive-osint`](../offensive-osint/) §16.14 (record-fetch recipes), [`osint-methodology`](../osint-methodology/) (confidence levels, output format, severity rubric) |

## Why this skill exists

`offensive-osint` §16.14 tells you *what* SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC records look like and how to fetch them. It doesn't tell you whether the domain is actually spoofable, or by which vector — that requires reasoning about the *combination* of records, not any one of them in isolation. This skill is that reasoning layer:

- The single most-misunderstood distinction in email security: SPF authenticates the invisible envelope `MAIL FROM`; only DMARC governs the visible header `From:` the recipient reads. `-all`/`~all` alone never touches that second axis.
- A priority-ordered composite spoofability verdict — duplicate DMARC → SPF `+all` → no/weak DMARC → `p=quarantine` → `p=reject` at `pct<100` → `p=reject` with a weak subdomain policy → fully enforced — with the exact condition and severity for each rung, not a vague "check your records" gesture.
- SPF supply-chain analysis: the RFC 7208 §4.6.4 10-lookup / 2-void-lookup PermError fail-open condition, and the SPF-include-takeover vector (a dead `include:` an attacker can re-register to inherit SPF-pass authority over the victim domain) — with strict discipline for telling a real dead reference apart from a transient DNS hiccup, so the finding never becomes a false-positive machine.

Fully passive: DNS TXT reads only. No mail sent, no `RCPT TO` probe, no API keys.

## When this skill triggers

Auto-triggers on prompts about email spoofability, spoof feasibility, DMARC enforcement/alignment, SPF supply-chain issues, SPF PermError, SPF-include takeover, or "is this domain spoofable." Common ones:

- `email spoofability`, `is this domain spoofable`, `spoof feasibility`, `header from spoofing`
- `envelope from vs header from`, `BEC feasibility`, `business email compromise feasibility`
- `SPF DMARC verdict`, `DMARC enforcement`, `DMARC alignment`, `duplicate DMARC record`
- `SPF supply chain`, `SPF PermError`, `SPF lookup limit`, `10 DNS lookup limit`, `SPF void lookup`
- `SPF include takeover`, `dead SPF include`, `SPF +all`
- `DMARC p=none`, `DMARC p=reject`, `DMARC subdomain policy`
- `email domain security`, `email authentication audit`, `phishing feasibility domain`, `spoof proof domain`

Full trigger list in the SKILL.md frontmatter.

## What's in it

- **§6 — The mental model.** Envelope vs header, laid out as a table plus a worked two-path attack diagram (exact-domain header spoof vs the SPF `+all` bypass), ending in a one-line rule of thumb to hand a pushing-back client.
- **§7 — The composite spoofability verdict.** The exact priority-ordered decision tree (7 spoofable conditions + 1 not-spoofable terminal state), each with its precise triggering condition, severity, and vector label — plus the `sp=` inheritance trap that reads as protected but isn't.
- **§8 — SPF supply-chain analysis.** RFC 7208 §4.6.4's lookup/void-lookup budget, the full mechanism-cost table, the dead-include takeover vector, and — the part that keeps this from being a false-positive generator — the exact discipline for telling NXDOMAIN (dead) apart from SERVFAIL/timeout (transient, inconclusive) apart from NoAnswer (void but not dead) apart from a macro-expanded target (uncountable, don't try).
- **§9 — Recipes.** What's new beyond `offensive-osint` §16.14: duplicate-record detection, subdomain-policy-inheritance checks, and a manual mechanism-inventory one-liner.
- **§10 — Runnable helper.** A stdlib-only Python SPF lookup-counter (shells out to `dig`, no pip installs) that walks the include chain and reproduces the exact 4-state per-hop classification from §8.
- **§11 — Severity mapping** with business-language risk translation for every condition in §7 and §8.
- **§12 — Five worked examples**, including the classic "we have SPF `-all`" false-sense-of-security case walked through step by step.
- **§13 — Anti-patterns** — nine specific misreadings this skill exists to correct.
- **§14 — Active-verification boundary.** Explicit statement of what this skill does not do (send test mail, RCPT TO probes) and what an authorized next step looks like.
- **§15 — Self-test** — 16 prompts including the mandated `-all`-without-DMARC trap and five additional traps (explicit `sp=none` override, NXDOMAIN-isn't-automatically-takeover, transient-isn't-dead, redirect-after-`all`, void-lookup-cap-independent-of-total-cap).

## Loading

```bash
# Local Claude Code install
cp SKILL.md ~/.claude/skills/email-domain-security/SKILL.md

# Or attach to a Claude.ai project / Claude API system prompt
# (paste contents of SKILL.md as project knowledge)
```

Use alongside `offensive-osint` §16.14 for the record-fetch step — this skill picks up once you have the raw SPF/DMARC TXT text in hand.

## Helper script

§10 embeds a runnable, stdlib-only SPF lookup-counter directly in `SKILL.md` (no separate `scripts/` file for this skill). Copy it out and run standalone:

```bash
python3 spf_lookup_count.py target.example
```

Output: a plain key/value summary — lookup count, void count, dead includes (leads, not findings — verify registration status separately), skipped-transient hosts (re-check later), and whether the PermError condition is met.

## Self-test

Run the 16 prompts in SKILL.md §15 directly — this skill doesn't yet have an entry in a shared `tests/smoke-test-prompts.md` file; its self-test lives inline.

## License

MIT — see [LICENSE](../../LICENSE).
