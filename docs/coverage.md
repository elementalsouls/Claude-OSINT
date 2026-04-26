# Coverage Analysis

Honest assessment of what these skills cover vs. what real practitioners need.

## Headline number

**~85–90% coverage** of what an experienced practitioner would reach for during the **OSINT/recon phase** of an authorized external red-team engagement.

**~35–45% coverage** of what a full external red-team operator does in their job (because most red-team work is exploitation + post-exploit, intentionally out of scope).

## By practitioner archetype

| Archetype | Coverage of their needs | Why |
|---|---|---|
| **Pure OSINT analyst** | **~90%** | Skills are built for this. |
| **External attack-surface analyst (CyCognito-style)** | **~85–90%** | Direct overlap with the methodology. |
| **Bug bounty hunter** | **~75–80%** | Strong on recon; thin on exploit techniques. |
| **Threat intel investigator** | **~70%** | RU/CN pivots, attribution discipline, malware basics — but no infrastructure-tracking-over-time. |
| **External red teamer (recon phase)** | **~85–90%** | The OSINT phase is well-covered. |
| **External red teamer (full engagement)** | **~35–45%** | Recon is ~30–40% of a full engagement; rest (exploitation, post-exploit, lateral, reporting) is mostly out of scope. |
| **Internal red teamer (assumed-breach)** | **~10%** | Almost entirely out of scope. |
| **Adversary emulation / TTP-driven** | **~25%** | Threat-actor section exists; specific TTP playbooks per APT don't. |
| **Physical pentester** | **~25%** | Sat imagery + LinkedIn intel cover scouting; physical execution doesn't. |
| **Social engineer** | **~50%** | Pretext development covered; payload crafting + voice tradecraft not. |
| **Purple teamer** | **~30%** | No SOC-coordination guidance. |

## By engagement phase

| Phase | Coverage |
|---|---|
| Pre-engagement (RoE, scoping, NDAs, SOW, pricing) | ~10% |
| **External OSINT / passive recon** | **~85–90%** |
| **External active recon (light probing)** | **~75–85%** |
| Phishing payload crafting + delivery | 0% (out of scope) |
| Initial access (exploit execution) | ~5% (we identify, don't exploit) |
| Foothold / persistence | 0% (out of scope) |
| Privilege escalation (local + AD) | 0% (out of scope) |
| Lateral movement | 0% (out of scope) |
| C2 infrastructure | 0% (out of scope) |
| AV/EDR evasion | 0% (out of scope) |
| Domain dominance | 0% (out of scope) |
| Data exfiltration tradecraft | 0% (out of scope) |
| Cleanup / artifact removal | 0% (out of scope) |
| **Reporting (technical + exec)** | **~75%** |
| Disclosure / vendor coordination | ~60% |
| Re-test / continuous monitoring | ~30% |
| Purple-team / SOC-coordination | 0% |
| Lessons-learned / engagement retrospective | ~20% |

## What's deliberately out of scope (and why)

- **Active exploitation, post-exploitation, malware** — operational tradecraft, different domain, safety posture concerns.
- **C2 frameworks, AV/EDR evasion** — operational tradecraft, large body of separate knowledge.
- **AD attacks, BloodHound, Kerberos** — internal recon, not external.
- **Specific client-portal report formats** — too company-specific to template usefully.
- **Pricing, NDA, SOW templates** — business operations, not technical.
- **Real PII / breach corpus content** — privacy + opsec.

## Smoke-test results (32 prompts)

The repo ships 32 self-test prompts ([`tests/smoke-test-prompts.md`](../tests/smoke-test-prompts.md)) covering the major capability areas.

| Run | PASS | PARTIAL | FAIL | Grade |
|---|---|---|---|---|
| v2.0 (initial) | 1 | 9 | 22 | C |
| **v2.1 (current)** | **31** | **1** | **0** | **A** |

The single PARTIAL is Test 5 (cloud-bucket combinatorial generation) — acceptable; the inputs + technique are documented, runtime synthesis is appropriate.

## Caveats

The smoke-test number (96.9% PASS) is **Claude grading itself on tests Claude designed**. It's a useful signal for tracking gaps but not an objective measure of real-world coverage. A real practitioner would find more gaps. Treat it as "the skills now answer the obvious questions"; non-obvious questions may need a follow-on iteration.

## What experienced practitioners would say is still missing (within OSINT scope)

If a senior offensive consultant reviewed v2.1 and stayed within OSINT scope, here's what they'd flag as still missing:

1. **Specific tool-chaining recipes** — "use spiderfoot → export CSV → maltego transforms → asset graph" workflows. We name tools; we don't compose them step-by-step.
2. **Recon-ng / SpiderFoot / Maltego module-by-module configuration** — these are full ecosystems; we treat them as pointers.
3. **Custom Burp Suite / OWASP ZAP setup for engagements** — the "configure your active proxy for an engagement" guide.
4. **OPSEC infrastructure as code** — Terraform/Ansible to spin up clean engagement infrastructure (proxy stacks, redirectors).
5. **Sector-specific deep dives** — §47 is a starting point, not a deep dive (real healthcare RT specialists know HL7 trafficking like a second language).
6. **Adversary-emulation playbooks per APT** — "to simulate APT29's external recon, use these specific tools/techniques."
7. **Continuous-monitoring orchestration** — daily diff scripts, alert pipelines, false-positive tuning.
8. **Multi-tenant engagement workflow** — how an MSSP runs 30 concurrent ASM engagements without crossing wires.
9. **Client-specific report styling** — every Big-4 consultancy has their own template.
10. **Tool failure recovery** — when Shodan rate-limits during a critical phase, what's plan B/C/D?

These would push coverage to ~95% of OSINT-phase work. Each would add 200–500 lines and approach the limits of what a single skill can usefully encode.

## Roadmap

| Phase | Status | Description |
|---|---|---|
| v1.0 | ✅ Done | Original framework |
| v2.0 | ✅ Done | External-red-team posture rewrite |
| **v2.1** | ✅ Current | Comprehensive expansion (this version) |
| v2.2 | 🔜 | Continuous-monitoring playbook + multi-tenant workflow + Burp extension recipes |
| v3.0 | 🔜 | Plugin manifest for one-click Claude Code install + optional MCP server companion |

## Bottom line

For "external OSINT for authorized red-team operations": **~85–90% coverage** of what an experienced practitioner reaches for.
For "everything a full red-team operator does in their job": **~35–45%** — the gap is mostly intentional (out of scope).

The skills are production-ready for OSINT-phase work. They are **not** a replacement for a senior red teamer on a full engagement.
