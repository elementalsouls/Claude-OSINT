# Security Policy

## Scope of these skills

These skills are intended for **external OSINT-driven reconnaissance against authorized targets**. They explicitly **exclude**:

- Active exploitation, post-exploitation, lateral movement
- Active Directory attacks, Kerberoasting, BloodHound queries
- Malware development, payload crafting, AV/EDR evasion
- C2 framework usage (Cobalt Strike, Sliver, Mythic, Havoc, etc.)
- Real PII / credentials / breach corpus content in examples
- Defensive / blue-team detection content (separate domain)

## Responsible-use posture

The skills include a **soft scope-check** that triggers when a user asks Claude to act against an unverified third-party target:

> *"Quick scope check: is this a target you own or have written authorization to assess (e.g., a red-team engagement, in-scope bug-bounty asset, or your own infrastructure)?"*

Skill content also includes:

- An "Authorization & Legal Posture" section at the top of each SKILL.md.
- Hard "Do NOT" rules covering destructive probes, credential-validator misuse, scope violations.
- Detection-aware guidance encouraging back-off rather than evasion when active defenses are detected.
- Validator discipline — only read-only credential verification; never destructive.

## Reporting a security issue with the skills themselves

If you find:

- A trigger phrase that causes Claude to attempt active exploitation despite the OSINT-only scope.
- A copy-paste curl probe that has unintended destructive side effects.
- Validator endpoints that aren't actually read-only.
- Any pattern that could enable unauthorized access if misused.

**Please report it privately:**

1. Open a GitHub issue with title `SECURITY:` (no details) AND request privacy.
2. Or email the maintainer (see repo profile).
3. Do **not** post the details in a public issue / PR / discussion.

We aim to respond within **5 business days** and resolve within **30 days** for substantive issues.

## Reporting a finding discovered using these skills

If you used these skills during an authorized engagement and found a vulnerability in someone else's product / service:

- Use the responsible-disclosure templates in `osint-methodology` §30.
- For bug-bounty programs: follow the program's submission process.
- For unprogrammed targets: follow the CVD process in §30.4.

## Supported versions

| Version | Support status |
|---|---|
| 2.1.x (current) | ✅ Active |
| 2.0.x | ⚠️ Bug fixes only |
| 1.x | ❌ End of life |

## Security best practices for users

- Pin the skill version (`v2.1`) in any production deployment.
- Run `scripts/sync-skill-content.sh` (or manual cp) only against this repo's bundled `docs/full-skills/` files; don't fetch from arbitrary sources.
- Verify SHA-256 of any binary helper scripts before execution.
- Don't commit your engagement-specific notes into a fork of this repo.
- Use sock-puppet GitHub accounts when contributing if your engagement persona shouldn't be linked to your contributor identity.
