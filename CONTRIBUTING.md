# Contributing to Claude-OSINT

Thanks for considering a contribution. These skills are battle-tested but always improvable. Below is what's most welcome and how to submit changes.

## Most-needed contributions

| Priority | Type | Examples |
|---|---|---|
| **HIGH** | Vendor product fingerprints we missed | `Cisco Meraki`, `Palo Alto Prisma`, `Zscaler`, `Cato Networks`, `Cloudflare One`, `Tailscale Funnel`, `VPN appliances` |
| **HIGH** | Modern secret patterns | New API key formats from any service (Linear, Loops, Resend, Anthropic Workspace, Vercel deployment tokens, etc.) |
| **HIGH** | Real-world examples for `examples/` | End-to-end engagement walk-throughs (anonymized) |
| **HIGH** | Bug reports | Prompts that don't trigger the right skill section, or trigger the wrong one |
| MEDIUM | Sector-specific deep dives | Healthcare practitioners, finance practitioners, ICS specialists know their domain better than the starter notes in §47 |
| MEDIUM | Wordlist refreshes | New paths discovered in the wild |
| MEDIUM | Tooling install one-liners | When new tools mature |
| LOW | Translations | Non-English versions for international red-team teams |
| LOW | Typo / formatting fixes | Always welcome |

## What we won't accept

- Active exploitation tradecraft (PoC code, exploit chains, malware, C2 framework guides). These are out of scope for the OSINT-only posture.
- Internal-network recon (AD, BloodHound, Kerberos). Different domain.
- Defensive / blue-team detection content (SIEM rules, EDR signatures). Different audience.
- Anything that could enable unauthorized access (credential lists, harvested PII, real breach corpus content).
- Sector-specific content that crosses into sensitive operational tradecraft (e.g., specific ICS exploitation techniques).

## How to submit changes

1. **Fork** the repo on GitHub.
2. **Create a feature branch:** `git checkout -b feat/add-vendor-fingerprint-zscaler`
3. **Make your changes:**
   - Edit the relevant `SKILL.md` file in `skills/<skill-name>/SKILL.md`.
   - Update `CHANGELOG.md` under an `[Unreleased]` heading at the top.
   - If you're adding a new section, also update the README's "What's in the box" tables.
   - If you're adding a new triggerable concept, add a trigger phrase to the YAML frontmatter.
4. **Run the smoke tests** locally:
   - Install the modified skill in Claude Code or attach to a Claude.ai project.
   - Run any relevant prompt from `tests/smoke-test-prompts.md` and verify behavior.
   - If you added a new section, add at least one self-test prompt for it.
5. **Commit with a clear message:**
   - Format: `<type>(<scope>): <subject>`
   - Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`
   - Examples: `feat(arsenal): add Zscaler vendor fingerprint to §16.16`, `fix(methodology): correct EPSS threshold tier in §28.2`, `docs(readme): update coverage table for v2.2`
6. **Push and open a PR** with:
   - Clear description of what changed and why.
   - Reference any related issues.
   - Note any breaking changes (rare; mostly section renumbering).

## Style guide

### Markdown conventions

- Use `##` for top-level sections (numbered: `## 16. Pre-built Wordlists`).
- Use `###` for subsections (numbered: `### 16.13 Copy-Paste Probes`).
- Code blocks must specify language: ```` ```bash ````, ```` ```python ````, ```` ```regex ```` etc.
- Tables for structured data; bulleted lists for unordered enumerations.
- Bold for emphasis on first mention of a key concept; avoid otherwise.
- Sentence case for headings (not Title Case).

### Voice

- **Direct.** "Probe the path." not "You should probably consider probing the path."
- **Operator-facing.** Assume the reader is an experienced practitioner; don't over-explain basics.
- **Detectability-aware.** When introducing a probe technique, tag its detectability (low/medium/high).
- **Confidence-aware.** When introducing a finding pattern, tag its confidence level (TENTATIVE/FIRM/CONFIRMED).
- **Severity-anchored.** New finding categories should map to the §9 / §40 severity rubric.

### Trigger discipline

When you add a new capability, add at least one trigger phrase to the YAML frontmatter `triggers:` list. Trigger phrases should be the exact wording a user would type, not the formal name. E.g., `kubelet exposed` is a better trigger than `Kubernetes Kubelet API exposure on port 10250`.

## Reviewing other PRs

If you have OSINT experience, please review open PRs. Specifically:

- **Vendor fingerprint accuracy** — confirm the path / fingerprint pattern works against a real (authorized) target.
- **Severity assignment** — does the proposed severity match the §9 rubric and §40 worked examples?
- **Detectability tag** — accurate? Conservative?
- **Cross-skill consistency** — does a methodology change have a corresponding arsenal reference and vice versa?

## License

By contributing, you agree your contributions are released under the [MIT License](LICENSE).

## Code of conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Briefly: be excellent to each other.
