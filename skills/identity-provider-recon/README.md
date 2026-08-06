# `identity-provider-recon` skill

Tenant, federation, and user-enumeration-oracle mapping for an organization's identity fabric —
enumeration and fingerprint only, never credential submission.

| Field | Value |
|---|---|
| Name | `identity-provider-recon` |
| Version | 1.0 |
| Lines | ~965 |
| Top-level sections | 18 |
| Companion skills | [`osint-methodology`](../osint-methodology/) (§6.2 detectability tagging, §11 identity-fabric pointer), [`offensive-osint`](../offensive-osint/) (§22 Identity Fabric — the concrete endpoint reference this skill builds a workflow on top of) |

## When this skill triggers

Auto-triggers on prompts containing any of ~50 trigger phrases. Common ones:

- `identity fabric`, `identity provider recon`, `IdP recon`, `IdP fingerprinting`, `tenant fingerprinting`, `tenant recon`
- `SSO discovery`, `SSO fingerprinting`, `federation mapping`, `federation boundary`, `tenant federation map`
- `GetFederationInformation`, `M365 tenant federation`, `domain to tenant resolution`, `getuserrealm`, `Managed vs Federated namespace`
- `Entra tenant recon`, `Azure AD tenant recon`, `entra enum`, `okta enum`, `Okta org slug`, `Okta governed domains`, `Okta OIE vs Classic`
- `ADFS enum`, `ADFS version fingerprint`, `ADFS mex endpoint`, `Google Workspace enum`
- `SAML metadata discovery`, `generic OIDC discovery`, `Auth0 fingerprint`, `Keycloak fingerprint`, `tenant GUID extraction`
- `Seamless SSO detection`, `Azure AD Seamless SSO`, `AZUREADSSOACC`, `MDI presence`, `Defender for Identity detection`
- `user enumeration oracle`, `account existence enumeration`, `pre-auth user enum`, `GetCredentialType`, `IfExistsResult`
- `Okta authn enum`, `authn endpoint enumeration`, `credential type endpoint`, `user enum detectability`
- `email pattern synthesis`, `login candidate synthesis`, `login candidate list`, `name to email pattern`, `fail closed synthesis`
- `sibling tenant domains`, `federated sibling domain`

Full trigger list in the SKILL.md frontmatter.

## What's in it

- **§1 — Authorization posture with a sharp internal boundary.** §7–§10 (domain/tenant/federation/
  posture fingerprinting) are Low detectability. §11 (the user-enumeration oracle) is Medium —
  logged in the tenant's own audit trail. The skill treats these as two separate authorization tiers
  within one engagement, not one blanket "recon is fine" posture.
- **§6 — The identity-fabric mental model.** Domain→tenant→federation-map→IdP-posture→candidate-
  synthesis→user-enum-oracle, with the hard boundary drawn explicitly at the bottom of the diagram —
  everything below it (spray, credential submission, auth bypass) is a different skill/authorization
  tier entirely.
- **§7 — Domain→tenant resolution.** Six concurrent probes: Microsoft `getuserrealm.srf`
  (Managed/Federated), Entra OIDC metadata (tenant-GUID extraction), Autodiscover v2, Okta
  org-slug derivation + OIDC fingerprint + `/api/v1/domains` governed-domain enumeration, ADFS
  passive fingerprint + version inference + mex endpoint, Google Workspace MX correlation, generic
  OIDC (Auth0/Keycloak/Ping/OneLogin/Duo), and SAML metadata (5 paths).
- **§8 — Federation mapping.** The one keyless, unauthenticated `GetFederationInformation` SOAP
  endpoint that maps every domain sharing the same M365/Azure AD tenant trust as the seed — emitted
  discover-only, with the `FEDERATED_WITH` provenance edge deliberately held out of any attack-path
  pivot-weight table. Explicit honesty that no equivalent keyless surface exists for Okta/Google/SAML.
- **§9 — Cross-provider distinguishing-signal table.** The "which IdP am I actually looking at"
  quick-reference tying §7's endpoints together.
- **§10 — Seamless-SSO + MDI presence detection.** The Negotiate-challenge oracle for Azure AD
  Seamless SSO, and the MDI sensor-API DNS presence check — explicitly framed as a
  defensive-posture signal, not a weakness.
- **§11 — The user-enumeration oracle methodology.** Microsoft `GetCredentialType`
  (`IfExistsResult` semantics: exists / federated-elsewhere / throttled) and Okta `/api/v1/authn`
  (`errorCode` differential) — the oracle mechanics, the 20-candidate-per-tenant cap, Medium-
  detectability discipline, and the explicit rationale for why a CONFIRMED-confidence enumeration
  hit still reports as only LOW severity (existence ≠ compromise).
- **§12 — Name×pattern login-candidate synthesis**, with the **fail-closed rule** as the load-bearing
  precision decision: zero synthesized candidates when no org email pattern is confirmed — never a
  best-effort 8-permutation fallback fed into a live, logged oracle.
- **§13 — End-to-end workflow** tying §7–§12 into one run order, with the re-authorization checkpoint
  called out explicitly between the passive and active halves.
- **§14 — The hard boundary.** A dedicated section enumerating exactly what's OUT of scope: password
  spray, credential submission, token forge/replay, auth-bypass confirmation — and Falcon-Recon's own
  stage-6 `--validate` tier as the concrete analog for "this belongs to a different authorization
  phase."
- **§16 — 16-prompt self-test** including two explicit negatives (synthesizing without a confirmed
  pattern; spraying enumerated accounts).

Every recipe (`getuserrealm.srf`, Entra OIDC metadata, Autodiscover v2, Okta OIDC + governed domains,
ADFS, `GetFederationInformation` SOAP, Seamless SSO, MDI DNS check, `GetCredentialType`, Okta
`/api/v1/authn`) ships as copy-paste `curl` **and** PowerShell.

## Enumeration only — never credential submission

This skill's single hardest rule, repeated at every layer (§1, §5, §11, §14): **no step in this
skill ever submits a real, guessed, or breach-sourced password to any login endpoint.** The
user-enumeration oracles in §11 work by reading the *shape* of a rejection from a fixed,
non-functional placeholder request — not by attempting to succeed. Every oracle result carries an
explicit `credential_submitted: false` marker in its evidence block (§3) precisely so a downstream
reader can never mistake "we confirmed this account exists" for "we obtained access to it."

Password spray, credential replay, token forgery, and auth-bypass confirmation are explicitly
out of scope (§14) — they belong to a separately-authorized, authenticated-testing phase of an
engagement, not to this skill.

## Grounded in production, not invented

Every endpoint, response-field semantic (`NameSpaceType`, `IfExistsResult`, Okta `errorCode`
values), cap (20 candidates/tenant, 40-candidate synthesis ceiling), and severity/confidence choice
in this skill is transcribed from a shipped, tested implementation:

- `falcon_recon/modules/sso_idp.py` — IdP/federation fingerprint across Entra, Okta, ADFS, Google
  Workspace, generic OIDC, SAML metadata; the `--deep` active user-enumeration oracle
  (`GetCredentialType` / Okta `/api/v1/authn`); interest-based candidate ranking and the 20/tenant
  cap.
- `falcon_recon/modules/tenant_recon.py` — keyless `GetFederationInformation` federation mapping,
  Seamless-SSO Negotiate check, MDI presence detection; the discover-only ROE and
  `FEDERATED_WITH` pivot-exclusion.
- `falcon_recon/core/email_patterns.py` — the passive 8-permutation enrichment helper vs. the
  pattern-required, fail-closed `synthesize_login_candidates` used to feed the oracle.

Nothing here is invented for the skill — see the Changelog in SKILL.md §17 for the exact source
files.

## Loading

```bash
# Local Claude Code install
cp SKILL.md ~/.claude/skills/identity-provider-recon/SKILL.md

# Or attach to a Claude.ai project / Claude API system prompt
# (paste contents of SKILL.md as project knowledge)
```

## Self-test

Run the 16 prompts in SKILL.md §16 against a fresh session to verify the skill loads and routes
correctly — including prompt 10 (fail-closed synthesis with no confirmed pattern) and prompt 12
(spraying enumerated accounts is out of scope), the two negative cases.

## License

MIT — see [LICENSE](../../LICENSE).
