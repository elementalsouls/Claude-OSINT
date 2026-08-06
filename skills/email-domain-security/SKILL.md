---
name: email-domain-security
description: "Rigorous, defensible email-spoofability verdict and SPF supply-chain risk analysis computed from published DNS alone. Deepens the record-level SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC fetch recipes in the offensive-osint arsenal (§16.14) with the reasoning that section doesn't do: a priority-ordered composite verdict for whether an attacker can actually land header-From-spoofed mail in an inbox, and by which vector (exact-domain vs subdomain) — grounded in the single most-misunderstood distinction in email security: the envelope MAIL FROM that SPF authenticates vs the visible header From: that only DMARC governs. Explains precisely why SPF -all/~all alone is NOT spoof-proof without DMARC enforcement, and why SPF +all bypasses DMARC even under p=reject pct=100. Covers RFC 7208 §4.6.4's 10-DNS-lookup / 2-void-lookup PermError fail-open condition with a runnable stdlib-only lookup-counter script, plus the SPF-include-takeover supply-chain vector (an attacker re-registering a dead include inherits SPF-pass authority over the victim domain) with strict transient-vs-NXDOMAIN discrimination discipline so a temporary SERVFAIL is never mistaken for a takeover lead. Fully passive: DNS TXT reads only, no mail sent, no RCPT TO probe, no API keys. Use when auditing a domain's real spoofing resistance (not just its published records), explaining to a client why 'we have SPF -all' does not mean they're covered, investigating an SPF PermError or an unusually long include chain, evaluating a dead SPF include as a takeover lead, or writing a defensible spoofability finding for a deliverable."
version: 1.0
triggers:
  - email spoofability
  - email spoofing verdict
  - is this domain spoofable
  - spoof feasibility
  - header from spoofing
  - envelope from vs header from
  - BEC feasibility
  - business email compromise feasibility
  - SPF DMARC verdict
  - DMARC enforcement
  - DMARC alignment
  - SPF supply chain
  - SPF PermError
  - SPF lookup limit
  - 10 DNS lookup limit
  - SPF void lookup
  - SPF include takeover
  - dead SPF include
  - SPF +all
  - DMARC p=none
  - DMARC p=reject
  - DMARC subdomain policy
  - duplicate DMARC record
  - email domain security
  - email authentication audit
  - phishing feasibility domain
  - spoof proof domain
---

# Email Domain Security — Spoofability Verdict & SPF Supply-Chain Analysis

> Companion skills: **`offensive-osint` §16.14** (raw record-fetch recipes — dig/PowerShell one-liners for SPF/DMARC/DKIM/BIMI/MTA-STS/TLS-RPT/DNSSEC/CAA, the MX→IdP inference table, the DMARC reporting-vendor table). **`osint-methodology`** (confidence levels, output format, severity rubric this skill inherits). Fetch the records with §16.14 first; bring the raw TXT text here for the verdict. This skill does not re-list what a record *is* — it reasons about what a domain's *combination* of records actually lets an attacker do.

## 0. When to Use / When NOT

**Use this skill when:**
- Asked to audit spoof feasibility, produce an email-spoofability verdict, or explain "is domain X spoofable."
- You already have raw SPF/DMARC TXT text (via `offensive-osint` §16.14 or your own `dig`) and need the *verdict*, not just the record dump.
- Investigating an SPF PermError, a long or unusual include chain, or a dead `include:` target.
- Writing a client-facing finding that has to survive the pushback "we have SPF `-all`, why is this flagged?"
- Reasoning about DMARC subdomain policy inheritance, `pct=` partial enforcement, or duplicate-record handling.

**Do NOT use this skill when:**
- You haven't fetched the raw records yet. Run `offensive-osint` §16.14's dig/PowerShell recipes first, then bring the text here.
- You want to actually *send* a spoofed test message or run an SMTP `RCPT TO` liveness check. That is active engagement work requiring explicit authorization and is out of scope for this passive-DNS skill — see §14.
- You're auditing TLS/cert posture rather than email auth — that's `offensive-osint` §16.15 / TLS deep audit territory.
- You need AXFR / zone-transfer analysis. `dns_deep`-class modules run that check alongside the email-auth sweep, but it's a distinct DNS finding (open zone transfer, unrelated to spoofability) — see the note in §9.

---

## 1. Scope & Authorization Posture

Same posture as the companion skills: assets you own or have written authorization to assess. Everything in this skill is **passive** — reading published, public DNS TXT records that any resolver on the internet can already see — so it carries essentially zero detectability risk on its own.

But the *verdict* this skill produces is the input to a decision someone downstream might act on (an authorized phishing-simulation send, a client remediation ticket, a bug bounty report). Flag the boundary explicitly: a passive verdict of "spoofable" is a strong, defensible claim about DNS-published policy — it is not itself proof that a spoofed message was delivered. See §14.

---

## 2. Confidence Levels

Inherits `osint-methodology` §2's three-tier scale, mapped onto email-auth assertions specifically:

| Level | Meaning here |
|---|---|
| **TENTATIVE** | A mechanism in the SPF chain could not be resolved (timeout / SERVFAIL / no nameservers) — the verdict for *that mechanism* is inconclusive. See §8's transient-vs-dead discipline; never silently upgrade this to FIRM. |
| **FIRM** | Record(s) present, parsed under RFC 7208 (SPF) / RFC 7489 (DMARC) grammar, verdict computed purely from directly observed TXT text. This is the ceiling for everything this skill produces on its own. |
| **CONFIRMED** | The verdict was cross-checked against actual mail-flow behavior (an authorized send-and-verify test). Outside this skill's passive scope — only ever assigned after an active test someone else ran. |

**Default posture:** everything this skill outputs is at most FIRM. Never claim CONFIRMED spoofability from DNS reading alone, no matter how conclusive the record combination looks.

---

## 3. Output Format

Same finding schema as the companion skills, with the fields this domain actually populates in practice:

```
Finding:
  module:      email_spoof   # or dns_deep / email-domain-security, depending on your pipeline
  asset_key:   domain:<target>
  category:    DNS_MISCONFIG   # the real implementation groups ALL email-auth findings under
                                # this one category — these are DNS record misconfigurations,
                                # not mail-server misconfigurations. Don't invent a separate
                                # EMAIL_SECURITY category unless your own schema needs one.
  severity:    <high|medium|low|info>     # see §7 / §8 for exact per-condition mapping
  confidence:  <tentative|firm|confirmed> # see §2 — almost always FIRM
  title:       "Email spoofable — <vector>"   # or the specific SPF supply-chain title
  description: <cite the exact reasons — see the "reasons" convention below>
  evidence:
    spf:                          <raw SPF TXT, or "(none)">
    dmarc:                        <raw DMARC TXT, or "(none)">
    vector:                       <e.g. "header-From spoof (exact domain, SPF +all bypasses DMARC)">
    effective_subdomain_policy:   <sp= value or the inherited p= value>
    reasons:                      [<ordered list of full-sentence reasons — see below>]
  dedup_key:   "emailspoof:<target>"   # or "spfsupply:<target>:<kind>", "spfmulti:<target>",
                                        # "dmarcmulti:<target>" — stable across re-scans so the
                                        # same finding doesn't duplicate on the next audit
  remediation: <the specific DMARC/SPF ratchet needed to close the exact vector found>
```

**The `reasons` convention:** the verdict logic (§7) doesn't just return a label — it builds an ordered list of full, client-report-ready sentences explaining *why* the domain is spoofable by that vector. Quote them directly in a deliverable rather than re-writing the explanation from scratch; they're already written in the right register (e.g. *"SPF terminates in `+all` (or bare `all`), returning an SPF pass for any sender IP. An attacker aligns the envelope sender to the target domain, so DMARC passes on the SPF leg and the spoofed message is delivered even if DMARC is set to reject."*).

---

## 4. Source Hygiene & Citations

For every record pulled: **FQDN queried + record type + UTC timestamp + resolver used + raw text verbatim**.

- Query against public resolvers (1.1.1.1 / 8.8.8.8 / 9.9.9.9), not local/system DNS — an operator's local resolver may be split-horizon or stale, masking what the internet actually sees. This matters more here than almost anywhere else in the arsenal: the whole verdict depends on seeing exactly what a real mail receiver's resolver sees.
- Capture the raw TXT text verbatim, not a paraphrase — SPF/DMARC grammar is unforgiving (a missing `;`, a `pct=` typo, a duplicate record) and the raw text is the only thing that lets someone else verify your parse.
- If you walked an SPF include chain, log every hop (host → TXT-or-NXDOMAIN-or-transient) — the walk itself is evidence, not just the final lookup count.

---

## 5. Do NOT

- **Do NOT treat SPF `-all`/`~all` as spoof-proof by itself.** This is the single misconception this skill exists to correct — see §6. SPF governs the invisible envelope return-path; the visible header From: is governed only by DMARC.
- **Do NOT assert CONFIRMED spoofability from DNS reading alone.** Passive analysis caps at FIRM (§2). CONFIRMED requires an authorized send-and-verify test — out of this skill's scope (§14).
- **Do NOT send actual spoofed test mail, or run an SMTP `RCPT TO`/`MAIL FROM` probe, as "confirmation."** That's active engagement work requiring explicit authorization; this skill is DNS-reads-only.
- **Do NOT flag a transient DNS failure (SERVFAIL / timeout / no-nameservers) on an SPF include as "dead" or a takeover lead.** Only an explicit NXDOMAIN qualifies — see §8's transient-vs-dead discipline. A dead-include false-positive is the kind of finding that gets a report laughed out of a client review.
- **Do NOT count a macro-expanded SPF target (`%{d}`, `%{i}`, `%{s}`, …) as a resolvable takeover candidate.** The mechanism still costs a DNS lookup toward the RFC 7208 budget, but you cannot passively resolve the literal macro string — doing so will NXDOMAIN and produce a false takeover claim.
- **Do NOT ignore a `redirect=` modifier that sits after a terminal `all` mechanism** — per RFC 7208 §6.1 it is never reached (SPF evaluation stops at `all`), so don't count it toward the lookup budget or walk it.
- **Do NOT assert an SPF-include-takeover finding from NXDOMAIN alone.** NXDOMAIN is necessary but not sufficient — you still have to check whether the registrable domain is actually available for an attacker to register (WHOIS/RDAP). NXDOMAIN + confirmed-available = takeover lead; NXDOMAIN + still-registered-to-someone = just a dead reference.

---

## 6. The Mental Model — Envelope vs Header (read this first)

This is the distinction operators get wrong more than any other single thing in email security, and it's the reasoning gap §16.14's record catalog doesn't close on its own.

| | **Envelope** (`MAIL FROM` / SMTP `Return-Path`) | **Header** (`From:`) |
|---|---|---|
| Who authenticates it | **SPF** — an IP allow-list check against the envelope-sender domain's own SPF record | Nothing directly. Only **DMARC** governs it, indirectly, via *alignment* |
| Does the recipient ever see it | No — buried in the SMTP transaction / bounce headers; essentially invisible in every common mail client UI | **Yes** — this is the line the user reads, trusts, and hits "Reply" on |
| What actually makes it spoof-proof | N/A on its own | DMARC `p=reject` at `pct=100`, with SPF-alignment or DKIM-alignment holding for legitimate mail |
| The operator's misconception | "We have SPF `-all`, we're covered" | (the axis they're actually *not* covering) |

```
Two independent attack paths land a spoofed header From: <ceo@target.com>
in an inbox. Neither one requires cracking any cryptography.

── Path A — exact-domain header spoof (works whenever DMARC isn't fully enforced) ──

  MAIL FROM: attacker@evil-throwaway.tld     <- SPF checks THIS domain's record —
                                                 target.com's SPF is NEVER CONSULTED,
                                                 because the envelope sender isn't
                                                 target.com. Its `-all` never even runs.
  From: ceo@target.com                       <- the user sees THIS

  DMARC then asks: does the header-From domain (target.com) ALIGN with the domain
  that just passed SPF (evil-throwaway.tld)? No. SPF-alignment fails, DKIM-alignment
  fails (attacker can't sign as target.com), so DMARC falls through to its published
  policy for target.com:
    p=reject, pct=100, sp= enforced  -> blocked
    p=none / p=quarantine / absent / pct<100 / weak sp=  -> delivered (or spam-foldered,
                                                             which many users still open)

  target.com's SPF record — `-all` or otherwise — is IRRELEVANT to this path. This is
  why "we have SPF -all" is not an answer to a DMARC-enforcement gap.

── Path B — SPF +all bypass (works even under DMARC p=reject, pct=100) ──

  MAIL FROM: anything@target.com             <- attacker aligns the envelope domain
                                                 to the TARGET this time
  From: ceo@target.com

  target.com's SPF record ends in `+all` (or bare `all`, which means the same thing):
  an explicit PASS for any sending IP whatsoever. SPF passes. SPF-alignment holds
  (envelope domain == header-From domain). DMARC passes on the SPF leg. Delivered —
  even with p=reject at pct=100, because DMARC has nothing left to reject.
```

**The rule of thumb to give a client:** *SPF `-all` alone stops nothing you can see in your inbox. DMARC `p=reject` at `pct=100` stops Path A. Neither one alone stops Path B — an `+all` SPF record actively defeats even a fully-enforced DMARC policy.*

**DKIM's role — an explicit scope note:** the composite verdict in §7 reasons about SPF and DMARC only, mirroring the real engine this skill is grounded in. DKIM alignment is tracked as a separate posture control (§9's scorecard), not folded into the priority chain. This isn't an oversight: an attacker who cannot produce a valid DKIM signature for the target domain (they don't have the private key) cannot achieve DKIM-alignment regardless of what the target's DKIM record says, so SPF+DMARC reasoning is sufficient to establish the *attacker's* available spoofing vectors. DKIM matters for whether the *defender's own legitimate mail* achieves alignment — a separate, defensive-posture question, not an extra bar the attacker has to clear.

---

## 7. The Composite Spoofability Verdict — Priority-Ordered Decision Tree

This is the exact order a rigorous engine evaluates in — priorities are not arbitrary; earlier conditions **short-circuit** later ones (a duplicate-DMARC domain is spoofable regardless of what either individual record says; an `+all` SPF domain is spoofable regardless of DMARC policy).

Before any branch runs, two **context reasons** are always evaluated and prepended to the eventual verdict's reasoning (informational — they explain *why*, they don't by themselves decide *whether*):
- No SPF record present → *"the envelope return-path is unauthenticated."*
- SPF present but its terminal qualifier is `+all` / bare `all` / absent entirely → *"the envelope accepts any sender."*

Then, in strict priority order:

| Pri | Condition | Human label | Severity | Vector (exact wording) |
|---|---|---|---|---|
| **1** | More than one DMARC record published at `_dmarc.<domain>` (RFC 7489 §6.6.3: receivers must ignore the **entire set**) | SPOOFABLE | **HIGH** | header-From spoof (exact domain, duplicate DMARC ignored) |
| **2** | SPF present AND its terminal qualifier is `+all` (or bare `all`, which means the same thing) — *wins over every DMARC branch below* | SPOOFABLE | **HIGH** | header-From spoof (exact domain, SPF `+all` bypasses DMARC) |
| **3** | No DMARC record at all | SPOOFABLE | **HIGH** | header-From spoof (exact domain) |
| **4** | DMARC present but `p=none`, or `p=` missing/malformed (unparseable) | SPOOFABLE | **HIGH** | header-From spoof (exact domain) |
| **5** | `p=quarantine` | SPOOFABLE | **MEDIUM** | header-From spoof (exact domain, quarantined) |
| **6** | `p=reject` but `pct` < 100 | SPOOFABLE | **MEDIUM** | header-From spoof (pct=N, ~(100−N)% not rejected) |
| **7** | `p=reject`, `pct=100`, but the *effective* subdomain policy is not `quarantine`/`reject` | SPOOFABLE | **MEDIUM** | header-From spoof (subdomain) |
| — | `p=reject`, `pct=100`, effective subdomain policy also enforced | **NOT SPOOFABLE** | INFO | not spoofable (DMARC reject enforced) |

**"Effective subdomain policy"** = the explicit `sp=` tag if present, otherwise it **inherits** the apex `p=` value (RFC 7489 §6.3). This is a common source of false findings both directions:
- **False "protected":** don't assume an *absent* `sp=` is a gap — it inherits `p=reject` and subdomains ARE covered.
- **True gap:** an *explicit* `sp=none` (or `sp=quarantine`) alongside `p=reject` overrides the inheritance — apex is enforced, subdomains are not. This is priority 7, and it's easy to miss on a quick read because the apex line looks fully hardened.

**Severity ceiling:** the real engine this skill is grounded in caps every one of these verdicts at **HIGH** — never CRITICAL, even for priorities 1–4 (the worst case). Preserve that ceiling; don't invent a CRITICAL tier for the composite verdict. If your own engagement's severity rubric wants to escalate a HIGH email-spoof finding to CRITICAL contextually (e.g. it's a domain with a finance/CEO-fraud history), do that as a documented escalation rule, not as this module's native output.

**Worked micro-example (priority 2 firing over what looks like a hardened domain):**

```
SPF:   v=spf1 include:_spf.google.com ~all       <- wait, this record ends -all/~all, no +all here
DMARC: v=DMARC1; p=reject; pct=100; sp=reject    <- looks fully enforced at first glance
```
If instead the SPF record actually reads `v=spf1 include:_spf.google.com +all` (a copy-paste error appending `+all` after a legitimate include list is a real, observed misconfiguration — someone meant to add a permissive fallback and instead nullified the whole record), priority 2 fires and the domain is spoofable **despite** a textbook-perfect DMARC record. This is exactly the kind of finding that a records-only read (§16.14) would miss if the auditor's eye jumps straight to the DMARC line and calls it done.

---

## 8. SPF Supply-Chain Analysis (RFC 7208 §4.6.4)

The composite verdict in §7 answers "is the domain spoofable." This section answers a different question: **can the SPF record itself be turned into a weapon, or can it silently stop working?**

### 8.1 The 10-lookup / 2-void-lookup budget

RFC 7208 §4.6.4 caps SPF evaluation at:
- **10** DNS-lookup-costing mechanisms (counted across the *entire* recursive chain, not per-record)
- **2** void lookups (a mechanism that resolves to nothing)

Exceed either cap → the evaluating receiver returns **PermError**. Conformant receivers treat PermError as **no SPF at all** — this is a **fail-open** condition: the domain silently loses envelope-sender protection, and nobody publishing the record gets an error telling them so. It just quietly stops working the day someone's 11th SaaS `include:` gets added.

**Mechanisms that cost one lookup each** (count every one, across every hop of the recursive walk):

| Mechanism | Costs a lookup? | Notes |
|---|---|---|
| `include:` | **Yes (1)** | Also recurses — walk its own SPF record and count *its* mechanisms too |
| `a`, `a:host`, `a/24` | **Yes (1)** | |
| `mx`, `mx:host` | **Yes (1)** | Each MX lookup for the target implicitly costs additional A/AAAA lookups too, but the RFC counts the `mx` mechanism itself as 1 for this cap |
| `ptr`, `ptr:host` | **Yes (1)** | Also deprecated — see §8.4 |
| `exists:` | **Yes (1)** | |
| `redirect=` (modifier) | **Yes (1)** | Also recurses — **unless** the record contains a terminal `all` mechanism, in which case RFC 7208 §6.1 means processing stops at `all` and the redirect is **never reached** — don't count it or walk it in that case |
| `ip4:`, `ip6:` | **No (0)** | Static, no DNS query needed |
| `all` | **No (0)** | Terminal, no query |
| `v=spf1` tag itself | **No (0)** | |

### 8.2 What counts as a "void" lookup

A void lookup is any lookup-costing mechanism that resolves to **nothing usable** — this is a distinct cap from the 10-lookup total, and it's the one people forget: *you can be well under 10 total lookups and still PermError on void lookups alone.*

- **NXDOMAIN** (the queried name doesn't exist) → void. **Also** flag as a dead-include lead (§8.3).
- **NOERROR with no TXT / no SPF-shaped TXT** (the name is registered, it just doesn't have an SPF record there) → void, but this is **not** a dead-include / takeover candidate — the domain is registered and owned by someone; there's simply no SPF policy published at that name.

### 8.3 Dead-include takeover — and the discipline that keeps it from being an FP machine

If an `include:` target NXDOMAINs, its registrable domain may be **available for an attacker to register**. If they do, and publish their own permissive SPF record there, they inherit SPF-pass authority for the *victim* domain's SPF chain — an attacker sending mail whose envelope aligns to the victim domain can now pass SPF via a supply-chain link the victim forgot to remove (a decommissioned vendor, a renamed SaaS product, a typo in the include target that happened to look plausible).

**The discipline, stated precisely — this is the part that separates a real finding from an embarrassing FP:**

| DNS outcome for the include target | Classification | Action |
|---|---|---|
| **NXDOMAIN** | Dead — takeover *lead* | Verify registration status via WHOIS/RDAP before calling it a finding. NXDOMAIN alone is necessary but not sufficient. |
| **NOERROR, no TXT (NoAnswer)** | Void, **not** dead | The domain is registered and presumably owned by the original vendor. It's a stale reference costing a void lookup — a hygiene finding, not a takeover lead. |
| **Timeout / SERVFAIL / no nameservers reachable** | **Transient — inconclusive** | **Skip judging entirely.** Do not count it as void, do not count it as dead, do not report a takeover lead. Re-query later if it matters. Crying takeover on a temporary resolver hiccup is the single most common way this class of finding loses credibility with a client. |
| Contains a macro (`%{d}`, `%{i}`, `%{s}`, …) | N/A — can't be resolved literally | The mechanism still costs a lookup toward the budget (§8.1), but do not attempt to resolve the literal macro string — it will spuriously NXDOMAIN and produce a false takeover claim. Skip judgment on that specific host. |

### 8.4 The deprecated `ptr` mechanism

RFC 7208 §5.5 explicitly deprecates `ptr`: it's slow, DNS-load-heavy, and its authorization basis (reverse DNS) is attacker-influenceable in ways `ip4`/`ip6`/`include` are not. Low-severity finding on its own; the fix is a straight swap to explicit `ip4`/`ip6`/`include` mechanisms.

### 8.5 Severity mapping for supply-chain issues

| Issue | Severity | Trigger |
|---|---|---|
| Lookup-count overflow (PermError) | **MEDIUM** | Recursive lookup-costing mechanism count > 10 |
| Void-lookup overflow (PermError) | **MEDIUM** | Void lookups > 2 |
| Dead include (NXDOMAIN) | **MEDIUM** (base) | Every confirmed-NXDOMAIN include, regardless of whether it's later confirmed registerable |
| Deprecated `ptr` mechanism | **LOW** | Any `ptr`/`ptr:` mechanism present |

**These are the base engine's severities — they intentionally score the *posture gap*, not the *exploited outcome*.** A dead include is MEDIUM the moment it's detected (you don't yet know if it's registerable). Once you separately confirm via WHOIS/RDAP that the registrable domain is actually available, that's an *earned* escalation for the deliverable narrative — write it up as HIGH/CRITICAL in the client-facing framing with the registration-availability evidence attached, while keeping the underlying engine's MEDIUM as the honest "what we know from DNS alone" baseline. Don't silently inflate the base severity; document the escalation and why.

---

## 9. Recipes — Fetching the Records

The raw fetch commands for SPF / DMARC / DKIM / BIMI / MTA-STS / TLS-RPT / DNSSEC / CAA, plus the MX→IdP inference table and the DMARC reporting-vendor table, live in `offensive-osint` §16.14 — use those verbatim, bash and PowerShell both included there.

**What this skill adds on top** (not duplicated in §16.14):

**Duplicate-record detection** (feeds §7 priority 1 / the SPF-multiple check):
```bash
D="target.example"
echo "SPF records:";   dig +short TXT "$D"          | grep -ic 'v=spf1'
echo "DMARC records:"; dig +short TXT "_dmarc.$D"    | grep -ic 'v=DMARC1'
# either count > 1 -> the entire record set for that mechanism is ignored (§7 pri 1 / §8.1)
```
```powershell
$D = "target.example"
$spfCount   = (Resolve-DnsName $D -Type TXT -EA SilentlyContinue | ? { $_.Strings -match 'v=spf1' }).Count
$dmarcCount = (Resolve-DnsName "_dmarc.$D" -Type TXT -EA SilentlyContinue | ? { $_.Strings -match 'v=DMARC1' }).Count
"SPF records: $spfCount | DMARC records: $dmarcCount"
```

**Subdomain-policy inheritance check** (feeds §7 priority 7 — is `sp=` explicit or inherited?):
```bash
dig +short TXT "_dmarc.$D" | grep -oE 'sp=[a-z]+'
# no match -> sp= is ABSENT -> inherits p= (protected if p=reject)
# match     -> sp= is EXPLICIT -> use its value, do NOT assume inheritance
```

**SPF mechanism inventory for one record** (manual pre-count before running the full recursive walker in §10):
```bash
dig +short TXT "$D" | grep 'v=spf1' | tr ' ' '\n' | grep -E '^[+\-~?]?(include:|a[:/]?|mx[:/]?|ptr:?|exists:|redirect=)'
```

**AXFR note:** the real-world module this skill's logic is grounded in runs an AXFR (zone-transfer) attempt against every authoritative NS alongside its email-auth sweep — that's a distinct finding (open zone transfer, HIGH/CONFIRMED if it succeeds) unrelated to spoofability. Out of scope here; see `offensive-osint`'s DNS record catalog / §16.14 area for that check if you need it.

---

## 10. Runnable Helper — SPF Lookup Counter

stdlib-only Python (no `pip install`) — shells out to `dig`, the same tool §16.14's recipes already assume is available (Git Bash / WSL / macOS / Linux all ship it; on stock Windows without Git Bash, adapt `fetch_txt()` to shell out to `nslookup -type=TXT` instead — output parsing will differ). It reproduces the exact walker discipline from §8: a **4-state** classification per hop (SPF text to recurse / empty-but-registered / NXDOMAIN-dead / transient-inconclusive), never collapsing the transient case into a false void-or-dead verdict.

```python
#!/usr/bin/env python3
"""spf_lookup_count.py — RFC 7208 SS4.6.4 SPF DNS-lookup counter.

Recursively walks a domain's SPF include:/redirect= chain, counts every DNS-lookup-costing
mechanism (include / a / mx / ptr / exists / redirect), counts void lookups (NXDOMAIN or
NOERROR-with-no-SPF-TXT), and separately reports dead includes (NXDOMAIN -- SPF-include-
takeover LEADS, not confirmed findings -- verify registration status separately) vs
transient failures (SERVFAIL/timeout -- inconclusive, deliberately never counted as void
or dead). Flags >10 total lookups / >2 void lookups as the PermError fail-open condition.

stdlib only -- shells out to `dig` (ships with Git Bash / WSL / macOS / Linux; on stock
Windows without Git Bash, swap fetch_txt() for an `nslookup -type=TXT` call instead).

Usage: python3 spf_lookup_count.py target.example
"""
from __future__ import annotations
import re
import subprocess
import sys

MAX_LOOKUPS = 10
MAX_VOID = 2
MAX_DEPTH = 5

TRANSIENT = object()  # timeout / SERVFAIL / dig missing -- inconclusive, never void or dead


def fetch_txt(name: str) -> list[str] | None | object:
    """Returns TXT strings for `name`; [] if NOERROR/no-TXT-answer; None if NXDOMAIN;
    TRANSIENT if the query itself was inconclusive (timeout/SERVFAIL/tool missing)."""
    try:
        out = subprocess.run(
            ["dig", "+noall", "+answer", "+comments", "TXT", name],
            capture_output=True, text=True, timeout=8,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return TRANSIENT
    stdout = out.stdout
    if re.search(r"status:\s*NXDOMAIN", stdout):
        return None
    if re.search(r"status:\s*SERVFAIL", stdout):
        return TRANSIENT
    txts = re.findall(r'"((?:[^"\\]|\\.)*)"', stdout)
    if not txts and not re.search(r"status:\s*NOERROR", stdout):
        # couldn't positively confirm a clean NOERROR-empty answer -- be conservative
        return TRANSIENT
    return [t.replace('\\"', '"') for t in txts]


def spf_mechanisms(txt: str) -> tuple[list[str], list[str], int, bool]:
    """Parse ONE SPF record's lookup-costing mechanisms (no recursion).
    Returns (includes, redirects, direct_lookup_count, has_ptr)."""
    includes: list[str] = []
    redirects: list[str] = []
    direct = 0
    has_ptr = False
    has_all = False
    for raw in txt.split():
        tok = raw.strip('"')
        if not tok or tok.lower().startswith("v=spf1"):
            continue
        if tok[0] in "+-~?":
            tok = tok[1:]
        low = tok.lower()
        if low == "all":
            has_all = True
        elif low.startswith("include:"):
            includes.append(tok.split(":", 1)[1].rstrip("."))
        elif low.startswith("redirect="):
            redirects.append(tok.split("=", 1)[1].rstrip("."))
        elif low == "a" or low.startswith(("a:", "a/")):
            direct += 1
        elif low == "mx" or low.startswith(("mx:", "mx/")):
            direct += 1
        elif low == "ptr" or low.startswith("ptr:"):
            direct += 1
            has_ptr = True
        elif low.startswith("exists:"):
            direct += 1
    if has_all:
        # RFC 7208 SS6.1: processing terminates at `all`; a trailing redirect= is
        # never reached -- don't count it toward the budget or walk it.
        redirects = []
    return includes, redirects, direct, has_ptr


def walk(root_domain: str) -> dict:
    root_txts = fetch_txt(root_domain)
    root_txts = root_txts if isinstance(root_txts, list) else []
    root_spf = next((t for t in root_txts if "v=spf1" in t.lower()), None)
    if not root_spf:
        return {"error": f"no SPF record found on {root_domain}"}

    lookups = 0
    void = 0
    dead: list[str] = []
    skipped_transient: list[str] = []
    skipped_macro: list[str] = []
    expanded: set[str] = set()

    def expand(spf_text: str, depth: int) -> None:
        nonlocal lookups, void
        if depth > MAX_DEPTH:
            return
        includes, redirects, direct, _ = spf_mechanisms(spf_text)
        lookups += direct
        for host in includes + redirects:
            lookups += 1
            h = host.lower()
            if not h or h in expanded:
                continue
            expanded.add(h)
            if "%" in h:
                skipped_macro.append(h)
                continue  # macro-expanded target -- cost counted, resolution skipped
            sub = fetch_txt(h)
            if sub is None:                       # NXDOMAIN -- dead / takeover LEAD
                void += 1
                dead.append(h)
            elif sub is TRANSIENT:                 # inconclusive -- skip, don't judge
                skipped_transient.append(h)
                continue
            elif sub == []:                        # registered, no TXT -- void, NOT dead
                void += 1
            else:
                spf_sub = next((t for t in sub if "v=spf1" in t.lower()), None)
                if spf_sub:
                    expand(spf_sub, depth + 1)

    expand(root_spf, 0)
    return {
        "root_spf": root_spf,
        "lookup_count": lookups,
        "void_count": void,
        "dead_includes": sorted(set(dead)),
        "skipped_transient (re-check these, not judged)": sorted(set(skipped_transient)),
        "skipped_macro (cost counted, not resolved)": sorted(set(skipped_macro)),
        "perm_error": lookups > MAX_LOOKUPS or void > MAX_VOID,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: spf_lookup_count.py <domain>")
    result = walk(sys.argv[1])
    for k, v in result.items():
        print(f"{k}: {v}")
    if result.get("perm_error"):
        print("\n>>> PermError condition: lookups >10 or void >2. Conformant receivers")
        print(">>> treat this domain as having NO SPF at all (fail-open).")
    for h in result.get("dead_includes", []):
        print(f">>> Dead include '{h}' -- LEAD only. Verify registration status (WHOIS/RDAP)")
        print(f">>>   before calling it an SPF-include-takeover finding.")
```

**Reading the output:** `perm_error: True` is the fail-open condition (§8.1). Every entry under `dead_includes` is a **lead**, not a finding — cross-check registration status before writing it up (§8.3). Every entry under `skipped_transient` deserves a re-run later, not a report line now.

---

## 11. Severity Mapping & Business-Language Risk Translation

| Technical condition | Severity | Business-language translation |
|---|---|---|
| Duplicate DMARC records | HIGH | Your "reject spoofed mail" policy is silently void — the receiving mail server can't even tell which of your two conflicting policies to trust, so it honors neither. |
| SPF `+all` | HIGH | Your own DNS explicitly tells every mail server on the internet "trust any sender claiming to be us" — this defeats even a perfect DMARC policy. |
| No DMARC published | HIGH | Anyone can send email that displays your domain in the From: line, and nothing on the receiving end enforces a rejection. |
| DMARC `p=none` | HIGH | Same as above — you're only collecting reports about the spoofing, not stopping it. |
| DMARC `p=quarantine` | MEDIUM | Spoofed mail lands in spam/junk — meaningfully better, but a fraction of recipients still open and act on quarantined mail. |
| DMARC `p=reject`, `pct<100` | MEDIUM | You're rejecting spoofed mail, but only for a percentage of attempts — a persistent attacker who simply resends lands some fraction in the inbox. |
| DMARC `p=reject`, weak/absent-override `sp=` | MEDIUM | Your main domain is protected, but any made-up subdomain (`invoices.yourcompany.com`) is not — attackers pivot there instead. |
| SPF absent | MEDIUM (context) | Your outbound mail servers aren't authenticated to receivers — not itself the exploit primitive, but it removes one of the two authentication legs DMARC alignment can use. |
| SPF lookup-count / void-lookup PermError | MEDIUM (base) → escalates once confirmed exploitable | Your SPF record has grown too complex to evaluate — receivers silently stop checking it at all, on a date you don't control and won't be notified about. |
| Dead SPF include | MEDIUM (base) → HIGH/CRITICAL once registration-availability confirmed | A forgotten vendor reference in your SPF record could let an attacker who notices it re-register the old vendor's domain name and inherit the ability to send mail that authenticates as you. |
| Deprecated `ptr` mechanism | LOW | A legacy, slow, and weaker authentication method is still in use — hardening gap, not itself exploitable. |
| Fully enforced (`p=reject`, `pct=100`, `sp=` enforced, `-all`) | INFO | Header-From spoofing of this domain is not feasible via SPF/DMARC. Worth confirming DKIM alignment separately for completeness (§6). |

---

## 12. Worked Examples

**Example A — the classic false sense of security (the mandated trap, worked through):**
```
SPF:   v=spf1 include:_spf.google.com -all
DMARC: (no record)
```
*Verdict:* **SPOOFABLE, HIGH** — §7 priority 3 (no DMARC at all). The SPF `-all` is real and hardfails envelope spoofs of `target.com`'s own return-path — but per §6 Path A, an attacker doesn't need to pass `target.com`'s SPF at all. They send from an envelope domain they control, forge the header From: to `target.com`, and since there's no DMARC to check alignment, the mail is delivered with `target.com` visible to the recipient. **`-all` protects a channel the recipient never looks at.**

**Example B — the +all bypass over a "hardened" DMARC:**
```
SPF:   v=spf1 include:_spf.google.com include:mailgun.org +all
DMARC: v=DMARC1; p=reject; pct=100; sp=reject
```
*Verdict:* **SPOOFABLE, HIGH** — §7 priority 2, which wins over the DMARC branches entirely. The `+all` at the end (likely a copy-paste accident when someone added the `mailgun.org` include) makes SPF pass for literally any sending IP. An attacker aligns the envelope to `target.com` directly, SPF passes, DMARC's SPF-alignment leg is satisfied, and the reject policy never triggers.

**Example C — dead include, correctly held as a lead, not a finding, until verified:**
```
SPF:   v=spf1 include:_spf.oldvendor-2019.com -all
```
`dig TXT _spf.oldvendor-2019.com` → NXDOMAIN. This is a **lead**: void lookup, dead include, §8.3 table row 1. Before writing "SPF-include takeover" in a report, run a WHOIS/RDAP check on `oldvendor-2019.com`. If it's genuinely unregistered → escalate to HIGH/CRITICAL takeover finding with the registration-availability evidence attached (§8.5). If it's still registered to someone (even a defunct-looking parked page) → it's a stale-reference hygiene finding at the base MEDIUM, not a takeover.

**Example D — transient failure correctly NOT flagged:**
Same record as Example C, but the `dig` query times out (upstream resolver had a bad moment). §8.3 row 3: **skip judging this hop entirely.** It is neither void nor dead. Re-run later. Reporting a takeover lead off a single timed-out query is exactly the FP class this skill's discipline exists to prevent.

**Example E — lookup-count overflow with no single obviously "bad" record:**
```
SPF: v=spf1 include:_spf.google.com include:mailgun.org include:sendgrid.net
     include:spf.protection.outlook.com include:_spf.salesforce.com
     include:mktomail.com include:spf.mandrillapp.com a mx ptr -all
```
Seven `include:` mechanisms + `a` (1) + `mx` (1) + `ptr` (1) = **10 lookup-costing mechanisms at the top level** — already sitting exactly on the RFC 7208 §4.6.4 ceiling (PermError triggers at **>10**, §8.1), and that's *before a single recursion*. Each `include:` then pulls its own record and several expand into multiples (`_spf.google.com` alone chains into `_netblocks*.google.com`), so the true resolved total blows well past 10. **PermError** — receivers treat this domain as having no SPF, and every legitimate `-all` intent is void. This is a realistic pattern: each individual `include:` was added for a good reason (a real SaaS migration) by someone who never counted the running total. (Counting rule: §8.1. Note the ceiling is *>10*, not ≥10 — a record that lands on exactly 10 is at the edge but not yet a PermError; this one overflows only once the includes recurse.)

---

## 13. Anti-Patterns & Common Misreadings

- **"SPF `-all` means we're covered."** No — see §6. It protects the envelope, not the header the user reads.
- **"DMARC `p=quarantine` is basically the same as `p=reject`."** No — quarantined mail still gets delivered to spam, and a non-trivial fraction of users still open and act on it. It's MEDIUM, not INFO.
- **"No `sp=` means subdomains are unprotected."** No — absent `sp=` **inherits** the apex `p=`. The actual gap is an *explicit* `sp=none`/`sp=quarantine` sitting under a `p=reject` apex.
- **"Any SPF include that NXDOMAINs is a takeover finding."** No — it's a lead. Verify the registrable domain is actually available before calling it a finding (§8.3).
- **"A dig timeout on an include means it's dead."** No — transient failures are inconclusive by design; never treat them as void or dead (§8.3 row 3, §5).
- **"We're under 10 total `include:` mechanisms, so we're fine on lookups."** No — count *every* lookup-costing mechanism (`a`/`mx`/`ptr`/`exists`/`redirect` too), across the *entire recursive chain*, not just the top-level include count. Also check the *void*-lookup cap (2) separately — you can PermError on void lookups alone while nowhere near 10 total.
- **"A `redirect=` after `all` still needs to be walked and counted."** No — RFC 7208 §6.1 means it's dead code; SPF evaluation stops at `all`.
- **"DKIM passing means the domain isn't spoofable."** Only relevant if the attacker can produce a valid DKIM signature for your domain, which they can't without your private key. DKIM protects your own legitimate mail's alignment; it isn't a bar the attacker has to clear (§6).
- **"This module's HIGH severity should really be CRITICAL — it's a full account-takeover-adjacent primitive."** Preserve the engine's HIGH ceiling for the composite verdict (§7) — don't invent a CRITICAL tier here. Escalate in your own engagement's contextual rubric if warranted, and document that it's a deliberate escalation, not the base tool's native output.

---

## 14. Active-Verification Boundary

This skill's output is a **passive DNS verdict**: given the published SPF/DMARC text, is the domain spoofable, and by which vector. It is deliberately bounded there. What it explicitly does **not** do:

- Send a spoofed test message to a mailbox you control to confirm delivery.
- Run an SMTP `RCPT TO` / `MAIL FROM` liveness probe against the target's mail infrastructure.
- Attempt to actually register a dead SPF-include domain to prove the takeover (that's a real acquisition with legal/financial implications, not a recon step).

If a finding from this skill needs to graduate from FIRM to CONFIRMED (§2), the natural next step is an authorized send-and-verify test: from an engagement-approved sending platform, send a message with the target domain in the header From: (and, for the exact-domain vectors in §7, an envelope domain you control) to a mailbox you control, and observe whether it lands in inbox/spam/rejected. That is active engagement work — it requires the same explicit authorization posture as any other active probe in the companion skills (`osint-methodology` §1), and it is out of scope for this skill to execute. Hand the passive verdict + the specific vector off to whoever owns that authorization decision.

---

## 15. Skill Self-Test

Drop these into a fresh session to verify the skill loads and reasons correctly.

1. *"target.com has SPF `-all` and no DMARC record. Is it spoof-proof?"* → **No.** §6 Path A + §7 priority 3 — no DMARC means the exact-domain header spoof succeeds regardless of SPF. [the mandated trap]
2. *"SPF ends in `+all`, DMARC is `p=reject` at `pct=100`. Are we safe?"* → **No.** §7 priority 2 — `+all` bypasses DMARC entirely, wins over every DMARC branch.
3. *"We found two DMARC records at `_dmarc.target.com` — one says `p=reject`, one says `p=none`. Which one applies?"* → **Neither.** §7 priority 1 / RFC 7489 §6.6.3 — the whole set is ignored by conformant receivers.
4. *"DMARC is `p=reject` at `pct=100`, and `sp=none` is explicitly set. Are subdomains protected?"* → **No.** §7 priority 7 — an explicit `sp=` overrides inheritance; the apex is enforced but subdomains are not.
5. *"An SPF record has 12 `include:` mechanisms. What happens at evaluation time?"* → PermError, fail-open, treated as no SPF at all. §8.1.
6. *"An SPF include target NXDOMAINs. Is that automatically an SPF-include-takeover finding?"* → **No** — it's a lead. Verify registrable-domain availability via WHOIS/RDAP first. §8.3.
7. *"`dig` on an SPF include times out (SERVFAIL). Should I flag it as a dead include?"* → **No** — transient failure, inconclusive, skip judging entirely. §8.3, §5.
8. *"SPF record has `redirect=_spf.vendor.com` after a terminal `-all`. Does the redirect get evaluated?"* → **No** — RFC 7208 §6.1, unreachable once `all` terminates; don't count or walk it. §8.1, §9.
9. *"What raw DNS records do I need before I can run this skill's verdict?"* → SPF TXT + `_dmarc` TXT at minimum; for the full posture also DKIM selectors / BIMI / MTA-STS / DNSSEC — fetch via `offensive-osint` §16.14. §0, §9.
10. *"List the RFC 7208 §4.6.4 lookup-costing mechanisms."* → `include`, `a`, `mx`, `ptr`, `exists`, `redirect=`. §8.1.
11. *"Run the SPF lookup counter against a target and tell me if it PermErrors."* → §10 helper script.
12. *"A client pushes back: 'we have SPF `-all`, why is this HIGH?'"* → §6 mental model — walk them through the envelope-vs-header distinction and the exact-domain Path A that `-all` doesn't touch.
13. *"We want to actually send a spoofed test email to prove it."* → Out of scope for this passive skill — that's an authorized active send-and-verify test. §14.
14. *"An SPF record has a void-lookup count of 3, but the total lookup count is only 6 — well under 10. Still an issue?"* → **Yes** — the void-lookup cap (2) is a separate PermError trigger from the total-lookup cap. §8.1, §8.2.
15. *"DMARC is `p=reject` with `pct=50`. What fraction of spoofed mail actually gets through?"* → ~50% falls through to the next-lower policy (quarantine) rather than being rejected. §7 priority 6.
16. *"What severity should a dead SPF include get once I've confirmed the domain is actually available to register?"* → Base engine scores MEDIUM on detection; escalate to HIGH/CRITICAL in the deliverable once registration-availability is independently confirmed — document the escalation. §8.5, §12 Example C.

---

## 16. Changelog

- **v1.0 (2026-08-06)** — initial release. Grounded in the real composite-spoofability-verdict and SPF-supply-chain decision logic (priority-ordered verdict chain; RFC 7208 §4.6.4 lookup/void-lookup accounting; transient-vs-NXDOMAIN discrimination; macro-expansion and redirect-after-`all` handling). Companion to `offensive-osint` §16.14 (record-fetch recipes) — this skill adds the reasoning layer §16.14 does not cover: the envelope-vs-header mental model, the exact priority-ordered verdict conditions, and the SPF-include-takeover supply-chain vector with its FP-discipline. Includes a runnable stdlib-only SPF lookup-counter script (§10) and a 16-prompt self-test including the mandated `-all`-without-DMARC trap.
