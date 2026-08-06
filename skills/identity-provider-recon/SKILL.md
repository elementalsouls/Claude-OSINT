---
name: identity-provider-recon
description: "Organization-grade identity-fabric mapping: tenant/federation fingerprinting and the pre-auth user-ENUMERATION oracle methodology — enumeration and fingerprint only, never credential submission. Covers domain-to-tenant resolution (Microsoft getuserrealm.srf Managed/Federated namespace check, Entra OIDC metadata tenant-GUID extraction, Autodiscover v2), keyless Microsoft tenant-federation mapping (GetFederationInformation SOAP -> sibling-domain discovery, discover-only ROE, FEDERATED_WITH provenance edge held out of attack-path pivoting), Okta org-slug derivation + OIDC fingerprint + governed custom-domain enumeration, ADFS passive/active fingerprint + version inference, Google Workspace MX-correlated detection, generic OIDC (Auth0/Keycloak/Ping Identity/OneLogin/Duo) discovery, SAML metadata (5 paths), Azure AD Seamless-SSO Negotiate-challenge detection, Microsoft Defender for Identity (MDI) sensor-API presence check, the user-enumeration oracle methodology for Microsoft GetCredentialType (IfExistsResult semantics: exists / doesn't-exist / exists-in-federated-tenant / throttled) and Okta /api/v1/authn (errorCode differential), Medium-detectability discipline with a hard 20-candidate-per-tenant cap and admin/role interest-based ranking, and name x confirmed-email-pattern login-candidate synthesis that FAILS CLOSED with zero output when no org pattern is confirmed. Grounded directly in a production ASM implementation's sso_idp.py, tenant_recon.py, and core/email_patterns.py modules. Deepens — does not duplicate — offensive-osint skill's Identity Fabric endpoint reference with the tenant-federation MAP, the oracle WORKFLOW, and the candidate-SYNTHESIS methodology that reference lacks. Use when fingerprinting an organization's identity provider, mapping its tenant/federation boundary, running an authorized pre-auth user-enumeration pass, or synthesizing login candidates from harvested names to feed that oracle — never for password spray, credential submission, or auth bypass."
version: 1.0
triggers:
  - identity fabric
  - identity provider recon
  - IdP recon
  - IdP fingerprinting
  - tenant fingerprinting
  - tenant recon
  - SSO discovery
  - SSO fingerprinting
  - federation mapping
  - federation boundary
  - tenant federation map
  - domain to tenant resolution
  - GetFederationInformation
  - M365 tenant federation
  - Entra tenant recon
  - Azure AD tenant recon
  - Azure AD enum
  - entra enum
  - getuserrealm
  - Managed vs Federated namespace
  - okta enum
  - Okta org slug
  - Okta governed domains
  - Okta OIE vs Classic
  - ADFS enum
  - ADFS version fingerprint
  - ADFS mex endpoint
  - Google Workspace enum
  - SAML metadata discovery
  - generic OIDC discovery
  - Auth0 fingerprint
  - Keycloak fingerprint
  - tenant GUID extraction
  - Seamless SSO detection
  - Azure AD Seamless SSO
  - AZUREADSSOACC
  - MDI presence
  - Defender for Identity detection
  - user enumeration oracle
  - account existence enumeration
  - pre-auth user enum
  - GetCredentialType
  - IfExistsResult
  - Okta authn enum
  - authn endpoint enumeration
  - credential type endpoint
  - user enum detectability
  - email pattern synthesis
  - login candidate synthesis
  - login candidate list
  - name to email pattern
  - sibling tenant domains
  - federated sibling domain
  - fail closed synthesis
  - identity fabric mapping
---

# Identity-Provider Recon — Tenant, Federation & User-Enumeration Oracle Mapping

> Companion skills: [`osint-methodology`](../osint-methodology/) (§6.2 detectability tagging, §11
> identity-fabric pointer — the "how to think" skill this plugs into) and
> [`offensive-osint`](../offensive-osint/) (§22 Identity Fabric — the concrete endpoint/payload
> reference this skill builds a workflow on top of, rather than re-listing). This skill answers the
> question those two don't: **how do the tenant, its federation partners, its IdP, and its
> user-enumeration oracle fit together as one map** — and where exactly enumeration stops and
> credential submission begins.

## 0. When to Use / When NOT

**Use this skill when:**
- You need to resolve a domain to its identity tenant (Entra/Okta/ADFS/Google Workspace) and
  determine whether auth is Managed or Federated.
- You need to map an org's **federation boundary** — every sibling domain that shares the same
  M365/Azure AD tenant trust, not just the seed.
- You need to distinguish Entra vs. Okta vs. ADFS vs. Google Workspace vs. a generic OIDC IdP from
  passive/low-detectability signals.
- You need to detect Seamless SSO or Microsoft Defender for Identity (MDI) presence — both change
  the risk calculus of anything downstream.
- You have **authorization for a Medium-detectability, log-generating pass** and need to run a
  pre-auth user-enumeration oracle (GetCredentialType / Okta `/api/v1/authn`) to build a valid-account
  list — **without ever submitting a password**.
- You have harvested employee names and a **confirmed** org email-format pattern and need to
  synthesize ranked login candidates to feed that oracle.

**Do NOT use this skill when:**
- You need to submit credentials, replay breach creds, forge/replay a token, or confirm an
  auth-bypass — that is a different, higher-authorization tier. See §14.
- The target's authorization for **active, logged** probing isn't established — the passive half of
  this skill (§7–§10) needs the same soft-scope posture as every companion skill; the active half
  (§11) needs it explicitly, because it generates tenant-side audit-log events (§1, §11.4).
- You already have concrete endpoints and just need the reference table — go straight to
  `offensive-osint` §22.

---

## 1. Authorization & Legal Posture

Same base posture as `osint-methodology` §1: intended for assets the operator owns or has **written
authorization** to assess.

**This skill carries a sharper posture than most of the pack because §11 is not passive.** Every
domain-resolution, federation, IdP-fingerprint, Seamless-SSO, and MDI probe in §7–§10 is Low
detectability (a metadata GET/POST that any browser makes) — but the user-enumeration oracle in §11
is **Medium detectability**: it is a targeted, per-account POST against a live authentication
endpoint, and both Microsoft and Okta log it in the tenant's own sign-in/audit trail. Treat §7–§10
and §11 as two separate authorization tiers even within one engagement.

**Soft scope check** — ask once before running §11:
> *"I can build a valid-account list by probing Microsoft/Okta's pre-auth user-existence oracle. This
> never submits a password, but it IS logged in the tenant's own audit trail and is rate-limited on
> my end to stay under the radar. Confirm you want me to run this active pass?"*

**Always-on guardrails specific to this skill:**
- Never submit a real password, a guessed password, or any credential to any login endpoint. §11's
  oracles work by reading the *shape* of a rejection (§11.2, §11.3), not by trying to succeed.
- Cap user-enumeration at 20 candidates per tenant (§11.4) — this is not a suggestion, it is the
  production cap in the module this skill is grounded in.
- A `discover_only` federated sibling domain (§8) is a lead, never a target. Confirm ownership before
  extending §7–§11 to it.
- Nothing in this skill authorizes §14's excluded techniques, no matter how interesting the oracle
  results look.

---

## 2. Confidence Levels

Same three-tier model as the companion skills, applied to identity-fabric assertions:

| Level | Meaning | Identity-fabric example |
|---|---|---|
| **TENTATIVE** | Plausible, unverified. | Okta org-slug guess (`{stem}-prod.okta.com`) not yet confirmed by a live OIDC response; an 8-permutation passive email guess (`core/email_patterns.infer_patterns_for_name`) for enrichment only. |
| **FIRM** | Directly observed, single probe. | `getuserrealm.srf` returns `NameSpaceType=Federated`; ADFS `idpinitiatedsignon.aspx` returns a version-identifiable body; Seamless-SSO Negotiate 401 observed once. |
| **CONFIRMED** | Independently corroborated or an oracle differential fired. | Entra tenant GUID extracted from OIDC `issuer` AND matched by a second probe (getuserrealm/autodiscover); an Okta org's OIDC `issuer` contains `okta.com` (self-corroborating — the provider's own metadata endpoint answered); a GetCredentialType/Okta-authn oracle differential fired for a specific address (§11) — direct verification, not inference. |

**Rule of three still applies** to anything you'd report as organizational fact ("this org uses
Entra") beyond a single tenant-level metadata hit — a single OIDC response is enough to say "an Entra
tenant answers for this domain," but attributing that tenant to a *specific subsidiary* or brand
needs the same corroboration discipline as `org-attack-surface` §2.

---

## 3. Output Format

Standard Finding schema (companion skill §3), with `category: SSO_EXPOSURE` for every identity-fabric
finding in this skill — that is the category the reference implementation this skill is grounded
in uses uniformly, from an INFO tenant-identified breadcrumb through a LOW confirmed-user-enumeration
result:

```
Finding:
  id:          <stable hash>
  module:      identity-provider-recon
  asset_key:   svc:0.0.0.0:443:<product>      # tenant SERVICE asset key pattern — see §7.9
  category:    SSO_EXPOSURE
  severity:    <info|low|medium|high|critical>   # see per-section severity notes below
  confidence:  <tentative|firm|confirmed>
  title:       <one-line summary>
  description: <2-5 sentences>
  evidence:
    url:               <probe endpoint hit>
    timestamp:         <UTC ISO8601>
    discovery_method:  <oidc_metadata|getuserrealm|autodiscover|okta_oidc|adfs|saml_metadata|
                         workspace_mx|mx_inference|tenant_federation|seamless_sso|mdi_presence|
                         user_enum_microsoft|user_enum_okta>
    tenant_id:         <GUID / org slug / entity_id, when known>
  references:  [<AADInternals, MITRE ATT&CK technique, vendor doc>]
  remediation: <action the tenant owner can take>
```

UTC timestamps everywhere. For §11 oracle results specifically, the evidence block MUST carry
`probed_count`, the enumerated address list(s) split by outcome, and — critically — a
`credential_submitted: false` marker, so a downstream reader (or auditor) can never mistake an
enumeration result for a proven-live credential.

---

## 4. Source Hygiene & Citations

Same discipline as the companion skills: URL + UTC timestamp + tool version + run_id on every
artifact.

- Record the **exact request body** sent to GetCredentialType / Okta authn, not just "I probed the
  endpoint" — the oracle's entire evidentiary value is in the response differential, which is
  worthless without the paired request.
- Cache raw SOAP/JSON responses from GetFederationInformation, OIDC metadata, and getuserrealm.srf —
  these are the primary evidence for the tenant-federation map and should survive a re-run months
  later even if the live tenant configuration has since changed.
- Never log a probed password value in any artifact, even the fixed placeholder Okta's authn oracle
  requires (§11.3) — redact it in stored evidence as `<oracle-placeholder>`.

---

## 5. Do NOT

- Do NOT submit a real, guessed, or breach-sourced password to any login endpoint under this skill.
  §11's oracles are read-only-by-design: Microsoft's `GetCredentialType` and Okta's `/api/v1/authn`
  both reveal account existence from the **shape of a rejection**, never from a successful login.
- Do NOT exceed the 20-candidate-per-tenant cap on user enumeration (§11.4).
- Do NOT auto-promote a `discover_only` federated sibling domain (§8) into active scope. Confirm
  ownership first.
- Do NOT treat a `STRONG`-looking Okta-org-slug guess as confirmed until its own OIDC metadata
  answers and its `issuer` field actually contains `okta.com` (§7.4) — a guessed slug that happens to
  resolve to *someone else's* Okta org is a namesake collision, not a hit.
- Do NOT synthesize login candidates from names without a **confirmed** org email pattern (§12.2) —
  return nothing rather than spray 8 unverified permutations per name at a live oracle.
- Do NOT run §11 (the active oracle) without the sharper authorization posture in §1.
- Do NOT proceed past §11 into password spray, credential replay, or auth-bypass confirmation — that
  is explicitly out of scope everywhere in this skill (§14).

---

## 6. The Identity-Fabric Map — Mental Model

Most identity recon stops at "what login page does this domain redirect to." That single fact
misses everything this skill is built to surface: the tenant boundary, who else federates into it,
what defensive posture it runs, and — under explicit authorization — which specific accounts on it
are real.

```
        ┌─────────────────────────────┐
        │   DOMAIN → TENANT             │   §7 — getuserrealm.srf, Entra OIDC metadata,
        │   (who owns the login?)        │        Autodiscover v2, Okta org-slug + OIDC,
        └──────────────┬───────────────┘        ADFS fingerprint, Google Workspace MX,
                        │                        generic OIDC, SAML metadata
                        ▼
        ┌─────────────────────────────┐
        │   FEDERATION MAP               │   §8 — GetFederationInformation SOAP:
        │   (who else shares this trust?)│        every sibling domain in the SAME
        └──────────────┬───────────────┘        M365/Azure AD tenant, discover-only
                        │
                        ▼
        ┌─────────────────────────────┐
        │   IdP POSTURE                  │   §9 distinguishing signals + §10 —
        │   (Managed/Federated, Seamless │        Seamless SSO Negotiate challenge,
        │   SSO, MDI monitoring)         │        MDI sensor-API presence
        └──────────────┬───────────────┘
                        │  authorization gate — §1 tightens here
                        ▼
        ┌─────────────────────────────┐
        │   CANDIDATE SYNTHESIS          │   §12 — harvested names x CONFIRMED org
        │   (who do we probe?)           │        pattern → ranked login candidates,
        └──────────────┬───────────────┘        fail-closed with no pattern
                        │
                        ▼
        ┌─────────────────────────────┐
        │   USER-ENUMERATION ORACLE      │   §11 — GetCredentialType / Okta authn,
        │   (which accounts are real?)   │        valid-account list OUTPUT, capped
        └──────────────┬───────────────┘        at 20/tenant, never a password sent
                        │
                        ▼            ← THE HARD BOUNDARY (§14) —
              [ everything below      spray / credential submission / auth bypass
                this line is OUT      is a different authorization tier entirely
                of this skill's       and lives in the engagement's authenticated-
                scope ]               testing phase, not here.
```

Every stage feeds the next. A tenant you can't resolve (§7) has no federation map to walk (§8). A
federation map with no confirmed tenant SERVICE asset gives §11 nothing to enumerate against — the
production implementation this skill is grounded in gates the oracle specifically on tenants that
were resolved via `oidc_metadata`, `getuserrealm`, `autodiscover`, or `okta_oidc` (§7.9), not on a
bare domain guess.

---

## 7. Domain → Tenant Resolution

Six independent probes, all Low detectability, run concurrently against the same seed domain. Any
one confirms tenant existence; running all of them cross-corroborates and often fills in fields a
single probe leaves blank (e.g. getuserrealm confirms Federated but not the tenant GUID; OIDC
metadata fills that in separately).

### 7.1 Microsoft — `getuserrealm.srf` (Managed vs. Federated)

```
GET https://login.microsoftonline.com/getuserrealm.srf?login={probe-user}@{domain}&xml=1
```

Needs one plausible username local-part — use a harvested email if you have one, else a synthetic
`admin@{domain}` seed (this is a Microsoft-side probe; it never touches the client's own infra).
Cheap regex-extract the response fields rather than pulling in a full XML parser:

```bash
D="target.example"; U="admin"
curl -sk -m 15 "https://login.microsoftonline.com/getuserrealm.srf?login=${U}@${D}&xml=1"
```
```powershell
$D = "target.example"; $U = "admin"
Invoke-RestMethod -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$U@$D&xml=1"
```

Response fields: `NameSpaceType` (`Managed` / `Federated` / `Unknown` — `Unknown` means Microsoft has
no record of the domain, stop here), `FederationBrandName`, `AuthURL` (present only when Federated —
the upstream ADFS/IdP URL), `CloudInstanceName`.

**Why `Managed` vs. `Federated` matters for everything downstream:** `Managed` means authentication
terminates directly at `login.microsoftonline.com` — no on-prem ADFS proxy sits in front of it, so
§11's GetCredentialType oracle and any later authenticated-testing phase hit Entra's own (more
permissive) IP-based throttling with no ADFS Extranet Lockout buffer. `Federated` routes through
whatever `AuthURL` points to (usually ADFS — cross-reference §7.5). **Severity note:** a `Managed`
namespace on its own is a MEDIUM SSO_EXPOSURE finding (spray/MFA-fatigue hits Entra with no ADFS
buffer), FIRM confidence — it is a posture fact, not a vulnerability, but it changes risk on
everything that follows.

### 7.2 Microsoft Entra (Azure AD) — OIDC metadata + tenant GUID

```
GET https://login.microsoftonline.com/{domain}/.well-known/openid-configuration
```

`issuer` (and `token_endpoint`) contain the tenant GUID:
```regex
\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b
```

A hit here is CONFIRMED confidence, INFO severity — it's the federation root every downstream SaaS
integration trusts, not a weakness by itself, but the single most valuable pivot anchor in the whole
identity fabric (a leaked credential + this tenant GUID = a pre-auth pivot into every federated
SaaS).

### 7.3 Autodiscover v2 (Exchange Online / M365 mailbox confirmation)

```
GET https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/{email}?Protocol=Autodiscoverv1
```

Needs a probe email (harvested, or synthetic `admin@{domain}`). A response containing a `Protocol` or
`Url` field confirms the mailbox — and therefore the M365 tenant — exists. FIRM confidence, no
finding by itself (feeds the tenant SERVICE node); this is a corroboration probe, not a standalone
signal.

*Autodiscover IP correlation* (companion skill `offensive-osint` §22.1) is a complementary passive
check when MX is masked by an inbound filter (Mimecast/Proofpoint/Barracuda) — resolve
`autodiscover.{domain}` and check whether it lands in Exchange Online IP space. Use it alongside this
probe, not instead of it.

### 7.4 Okta — org-slug derivation + OIDC fingerprint + governed domains

Okta has no domain-keyed discovery endpoint the way Microsoft does — you derive candidate org slugs
and confirm each by fetching its OIDC config.

**Candidate derivation** (from the target's own domain stem + any subdomain that is literally an
`*.okta.com` host already in your graph):
```
candidates = { stem, stem-prod, stem-dev, stemcorp, stem-corp } ∪ { okta-slug matches in known subdomains }
```
```regex
[a-z0-9][a-z0-9-]{1,40}\.okta\.com
```

**Confirmation probe** (Low detectability — Okta's own public metadata endpoint):
```
GET https://{slug}.okta.com/.well-known/openid-configuration
```
Only treat a slug as CONFIRMED when `issuer` actually contains `okta.com` — a slug guess that
resolves to a *different* company's Okta org (namesake collision) is common with short/generic
stems; don't attribute it without this check (§5). Distinguish **Classic vs. OIE** (Okta Identity
Engine) by whether the issuer contains `/oauth2/` — this affects which downstream endpoints and
policies apply.

**Governed custom domains** (call ONLY after the org slug is confirmed real — never on a guess):
```
GET https://{slug}.okta.com/api/v1/domains
```
Returns every custom domain the org has verified as an identity-provider surface
(`{"domain": "...", "validationStatus": "VERIFIED"}`). This is the Okta equivalent of §8's federation
map — it reveals which branded login portals (`login.acmecorp.com`, `sso.subsidiary.com`) all route
into the same Okta tenant, closing the "co-federation via a non-Microsoft IdP" gap that §8's
Microsoft-only federation probe structurally cannot see. Each verified domain is a genuine tenant-map
node, not a guess — emit it as its own domain asset governed by this Okta org.

### 7.5 ADFS — passive fingerprint + version + mex (active)

**Passive fingerprint:**
```
GET https://adfs.{domain}/adfs/ls/idpinitiatedsignon.aspx
```
A response body is version-fingerprintable from resource-reference strings: `adfs/portal/css/style.css`
+ `2012` → ADFS 2012 R2 (3.0); `adfs/portal/illustration/illustration.png` → ADFS 2016/2019 (4.x/5.x);
bare `federation service` string with neither marker → ADFS confirmed, version unknown. **Severity:**
2012 R2/3.0 → MEDIUM (weak-crypto defaults, historical golden-SAML entry point); newer/unknown →
INFO.

**Mex endpoint (active — this one logs on the target side, unlike the fingerprint GET above):**
```
GET https://adfs.{domain}/adfs/services/trust/mex
```
A response containing `wsdl:definitions` confirms the mex endpoint is live and leaks federation
metadata (endpoint URLs, signing certs, supported claim types). Gate this probe on the passive
fingerprint already having confirmed ADFS — don't fire it speculatively.

### 7.6 Google Workspace — MX-correlated detection

Google Workspace has **no per-tenant OIDC endpoint** — `accounts.google.com`'s
`/.well-known/openid-configuration` is provider-wide, not tenant-specific, so it cannot confirm *this
specific domain* is a Workspace customer on its own. Detection therefore hinges on MX:
```bash
dig +short MX target.example
```
```powershell
Resolve-DnsName -Name target.example -Type MX
```
Any MX host containing `aspmx.l.google.com` or `googlemail.com` confirms Google Workspace. Emit the
tenant node with `tenant_id = domain` (there is no separate tenant GUID to extract) and
`issuer = https://accounts.google.com` for consistency with the other tenant nodes, but be explicit
in the evidence block that the corroborating signal is MX, not a tenant-scoped metadata response.

### 7.7 Generic OIDC — Auth0 / Keycloak / Ping Identity / OneLogin / Duo

Probe `/.well-known/openid-configuration` on the target apex and on subdomains matching the common
IdP-prefix set (`auth`, `login`, `sso`, `idp`, `iam`, `identity`, `accounts`, `oauth`) — both
discovered subdomains that match and the fixed prefix list applied directly to the root domain, capped
around 40 candidate hosts. Skip any hit already attributed to Microsoft/Okta/Google (issuer contains
`microsoftonline`, `okta.com`, or `accounts.google.com`) — those are covered by the dedicated probes
above.

| Product | Signal in `issuer` |
|---|---|
| Auth0 | `auth0.com` |
| Keycloak | `keycloak` or `/realms/<realm>` present anywhere in the issuer URL |
| Ping Identity | `pingidentity` or `pingone` |
| OneLogin | `onelogin.com` |
| Duo SSO | `duosecurity.com` |
| (unclassified) | falls back to "Generic OIDC IdP" — still a valid tenant node, just unbranded |

### 7.8 SAML metadata discovery

Same host candidate set as §7.7 (apex + IdP-prefix subdomains), probed against 5 conventional metadata
paths:

```
/saml/metadata
/FederationMetadata/2007-06/FederationMetadata.xml
/federationmetadata/2007-06/federationmetadata.xml
/simplesaml/saml2/idp/metadata.php
/auth/saml2/metadata
```

Structural confirmation (don't bother parsing full XML): body contains `entitydescriptor` or
`entitiesdescriptor` (case-insensitive). Extract `entityID` via a simple attribute regex:
```regex
entityid=["']([^"']+)["']
```
**Severity note:** public SAML metadata is INFO, CONFIRMED — and the remediation is explicitly *not*
"block this." Publishing SP↔IdP trust metadata is conventional; the risk is entirely in signing-key
compromise, which this passive probe cannot assess. Don't over-call a routine metadata endpoint as a
finding worth escalating.

### 7.9 Assembling the tenant SERVICE node

Every probe above upserts into the **same** tenant node when they resolve to the same product —
merge, don't fragment, on `(placeholder-IP, port 443, product)` so "Microsoft Entra (Azure AD)"
discovered via OIDC metadata AND via getuserrealm.srf AND via MX inference lands as one node with
accumulating `attrs` and `sources`, not three disconnected fragments. Attach a `domain OWNED_BY
tenant` edge. Track which `discovery_method` values are considered strong enough to gate §11's oracle
downstream: `oidc_metadata`, `getuserrealm`, `autodiscover`, `okta_oidc` — a tenant node that only
ever got an `mx_inference` hit (Google Workspace's usual path, or a weak Microsoft breadcrumb) should
not, by itself, authorize spending oracle budget against it without at least one of the four
stronger methods also confirming.

---

## 8. Federation Mapping — the Tenant Boundary

Domain resolution (§7) tells you *a* tenant exists. It says nothing about who else shares that same
trust. This is the highest-value, most commonly skipped step in identity-fabric recon: an attacker
who compromises credentials on **any** domain inside the federation boundary can pivot across all of
them, because they share one authentication trust — but inward DNS/CT enumeration of the seed alone
never surfaces sibling roots with no DNS trail back to it.

### 8.1 GetFederationInformation — the one keyless, Microsoft-only federation-map endpoint

A single unauthenticated SOAP POST to Microsoft's own infrastructure returns every domain federated
into the same Azure AD / M365 tenant as the seed:

```
POST https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc
SOAPAction: "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"
Content-Type: text/xml; charset=utf-8
```

Body (only `{domain}` varies):
```xml
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:a="http://www.w3.org/2005/08/addressing"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:autodiscover="http://schemas.microsoft.com/exchange/2010/Autodiscover">
  <soap:Header>
    <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
    <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <autodiscover:GetFederationInformationRequestMessage>
      <autodiscover:Request>
        <autodiscover:Domain>{domain}</autodiscover:Domain>
      </autodiscover:Request>
    </autodiscover:GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>
```

```bash
D="target.example"
BODY="<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:autodiscover=\"http://schemas.microsoft.com/exchange/2010/Autodiscover\"><soap:Header><a:Action soap:mustUnderstand=\"1\">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action><a:To soap:mustUnderstand=\"1\">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo></soap:Header><soap:Body><autodiscover:GetFederationInformationRequestMessage><autodiscover:Request><autodiscover:Domain>${D}</autodiscover:Domain></autodiscover:Request></autodiscover:GetFederationInformationRequestMessage></soap:Body></soap:Envelope>"
curl -sk -m 20 -X POST "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc" \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"' \
  -H 'User-Agent: AutodiscoverClient' \
  --data "$BODY"
```
```powershell
$D = "target.example"
$body = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:autodiscover="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<soap:Header><a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo></soap:Header>
<soap:Body><autodiscover:GetFederationInformationRequestMessage><autodiscover:Request>
<autodiscover:Domain>$D</autodiscover:Domain></autodiscover:Request></autodiscover:GetFederationInformationRequestMessage></soap:Body></soap:Envelope>
"@
Invoke-RestMethod -Uri "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc" -Method Post `
  -Headers @{ SOAPAction = '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"'; "User-Agent" = "AutodiscoverClient" } `
  -ContentType "text/xml; charset=utf-8" -Body $body
```

### 8.2 Parsing the response into a sibling-domain list

Extract every `<Domain>` value namespace-agnostically (SOAP prefixes vary by server):
```regex
<(?:\w+:)?Domain>\s*([^<\s][^<]*?)\s*</(?:\w+:)?Domain>
```
Lowercase, de-duplicate, strip trailing dots. Two derived facts matter:

- **Canonical tenant name** — the one domain ending `.onmicrosoft.com` (but NOT
  `.mail.onmicrosoft.com`, a routing variant) gives you `<prefix>.onmicrosoft.com`; strip the suffix
  for the bare tenant prefix. You need this prefix for §10.2's MDI presence check.
- **Sibling roots worth surfacing** — every returned domain that is NOT the seed apex, NOT a
  subdomain of the seed, and NOT a `*.onmicrosoft.com` Microsoft-owned routing domain. These are the
  external co-federated brands/subsidiaries.

### 8.3 ROE — discover-only, never auto-scope

Emit each sibling root as a **discover-only** `related_domain` asset, exactly like `org-attack-surface`
treats every candidate beyond the seed:
- Attach a `BRAND_MATCH` owner-signal, weight **0.40**, `confirming: false` — co-federation is a
  strong lead, not proof of common ownership, and should never be scored as if it were.
- Tie it to the seed with a `FEDERATED_WITH` provenance edge — but **hold that edge type out of any
  attack-path pivot-weight table**. It exists to close the graph for reporting ("here's who shares
  this trust"), never to let an automated pivot walker treat co-federation as a live reachability
  path into the sibling.
- Promotion to active scope is a distinct, explicit operator action. A co-federation hit — however
  many siblings it surfaces — never auto-extends §7–§11 onto them.

**Attacker framing worth stating explicitly in the finding description:** every federated domain
shares one authentication trust, so a credential or MFA-bypass foothold gained against *any one* of
them pivots across all of them. That is the entire reason this map is worth building even when every
individual sibling looks unremarkable on its own. **Severity:** INFO, FIRM confidence (an
unauthenticated Microsoft-side response, not yet independently corroborated per-sibling) — the value
is informational/structural, not itself a vulnerability.

### 8.4 Honest scope: this is Microsoft-only

There is **no equivalent keyless, unauthenticated federation-info surface for Okta, Google
Workspace, or a generic SAML IdP**. Say so explicitly rather than silently only covering Microsoft
tenants — §7.4's Okta governed-domains endpoint (`/api/v1/domains`) is the closest analog for Okta
(it maps custom-domain trust, not sibling-tenant federation), and no analog exists at all for generic
OIDC/SAML. Report a federation-map pass as "Microsoft tenant federation mapped; no equivalent surface
available for {other confirmed IdP}" rather than implying completeness that isn't there.

---

## 9. IdP Fingerprint — Distinguishing Signals at a Glance

Consolidated cross-provider comparison (endpoint detail lives in §7 above and in `offensive-osint`
§22 — this table is the "which one am I looking at" quick-reference):

| Provider | Confirming endpoint | Tenant identifier | Distinguishing string |
|---|---|---|---|
| Microsoft Entra | `login.microsoftonline.com/{domain}/.well-known/openid-configuration` | Tenant GUID (in `issuer`) | GUID regex match in `issuer`/`token_endpoint` |
| Microsoft (namespace) | `login.microsoftonline.com/getuserrealm.srf` | — | `NameSpaceType` = Managed/Federated |
| Okta | `{slug}.okta.com/.well-known/openid-configuration` | Org slug | `issuer` contains `okta.com`; `/oauth2/` present → OIE, absent → Classic |
| ADFS | `{domain-or-adfs-host}/adfs/ls/idpinitiatedsignon.aspx` | — | Resource-string markers (§7.5) |
| Google Workspace | (no tenant-scoped endpoint) | Domain itself | MX contains `aspmx.l.google.com` / `googlemail.com` |
| Auth0 | `/.well-known/openid-configuration` on any alive host | Auth0 tenant subdomain | `issuer` contains `auth0.com` |
| Keycloak | same | Realm name | `issuer` contains `keycloak` or `/realms/<realm>` |
| Ping Identity | same | Ping environment | `issuer` contains `pingidentity`/`pingone` |
| OneLogin | same | OneLogin subdomain | `issuer` contains `onelogin.com` |
| Duo SSO | same | Duo tenant | `issuer` contains `duosecurity.com` |
| Generic SAML | one of 5 metadata paths (§7.8) | `entityID` | `EntityDescriptor`/`EntitiesDescriptor` present |

**Priority order when multiple signals fire** (an org can legitimately run more than one — e.g. Okta
as the primary IdP federated into Entra for M365 specifically): trust the most tenant-specific signal
(a GUID or org slug beats an MX correlation), and emit **every** confirmed IdP as its own SERVICE
node rather than collapsing to "the" IdP — a hybrid identity fabric is common and each node is a
distinct pivot surface downstream.

---

## 10. Seamless-SSO & MDI Presence Detection

Both probes below touch **only Microsoft-owned infrastructure** — zero packets to the client's own
domain — so, unlike §7.5's ADFS mex probe or a client-hosted OIDC fingerprint, they carry no
passive-mode gate. They are Low detectability by construction: the client never sees the request.

### 10.1 Azure AD Seamless SSO — the Negotiate challenge

```
GET https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/usernamemixed
```
```bash
D="target.example"
curl -sk -m 15 -D - -o /dev/null "https://autologon.microsoftazuread-sso.com/${D}/winauth/trust/2005/usernamemixed"
```
```powershell
$D = "target.example"
try { Invoke-WebRequest -Uri "https://autologon.microsoftazuread-sso.com/$D/winauth/trust/2005/usernamemixed" -UseBasicParsing }
catch { $_.Exception.Response.Headers["WWW-Authenticate"] }
```

**Detection rule:** Seamless SSO is enabled when the response is `401` **and** its
`WWW-Authenticate` header contains `Negotiate` (case-insensitive substring match — that's the whole
oracle, no body parsing needed).

**What it means:** Seamless SSO relies on the on-prem `AZUREADSSOACC$` computer account. If its
Kerberos key never rotates, it's a known silver-ticket-forging vector against Azure AD, and the
endpoint itself is a documented password-spray target — this leg of auth has no on-prem lockout and
no MFA. **Severity:** LOW, FIRM confidence (single-probe direct observation) — a posture fact that
sharpens risk on any later spray/credential-testing phase, not a vulnerability in isolation.

### 10.2 Microsoft Defender for Identity (MDI) presence

Requires the canonical tenant prefix from §8.2 (the `.onmicrosoft.com` name, suffix stripped) — this
probe only runs once §8 has resolved it.

```
<tenant-prefix>sensorapi.atp.azure.com   — resolve for an A record
```
```bash
PREFIX="acme"
dig +short A "${PREFIX}sensorapi.atp.azure.com"
```
```powershell
$PREFIX = "acme"
Resolve-DnsName -Name "${PREFIX}sensorapi.atp.azure.com" -Type A -ErrorAction SilentlyContinue
```

If it resolves, MDI is deployed. **This is a defensive-posture signal, not a weakness** — say so
explicitly in the finding, INFO severity, FIRM confidence. What it tells an attacker: on-prem
identity activity (DCSync attempts, lateral-movement reconnaissance, Kerberoasting) is
sensor-monitored, so noisy on-prem AD attacks against this tenant are more likely to be detected.
This is genuinely useful recon output — it should inform how loud any later authorized on-prem phase
is willing to be — but report it for what it is, not as a finding "against" the client.

---

## 11. The User-Enumeration Oracle Methodology

This is the one active, Medium-detectability technique in this skill. Read §1 again before running
it. **The output of this section is a list of email addresses confirmed to exist as accounts. It is
never a list of working passwords, and no password is ever submitted to produce it.**

### 11.1 Oracle mechanics — the shared pattern

Both Microsoft's and Okta's endpoints are, structurally, the same trick: a pre-auth endpoint that
must answer *something* different for "this account doesn't exist" vs. "this account exists but you
got the credential wrong" — because a real login flow needs to tell a real user "no such account" vs.
"wrong password" before MFA. That necessary UX distinction is the oracle. Feed it a candidate address
(never a real password — Okta's endpoint requires *some* password value in the request shape, so a
fixed non-functional placeholder is used, §11.3), read which of the two response shapes came back,
and you've confirmed account existence without ever attempting to authenticate.

**This is exactly why it's Medium, not Low, detectability**: every probe is a real per-account
authentication attempt as far as the tenant's audit log is concerned, even though it never succeeds
and never even tries a real password. Microsoft and Okta both log it (§11.4).

### 11.2 Microsoft — GetCredentialType

```
POST https://login.microsoftonline.com/common/GetCredentialType
Content-Type: application/json; charset=UTF-8
Body: {"Username": "<email>", "isOtherIdpSupported": true}
```
```bash
curl -sk -m 15 -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -d '{"Username":"alice@target.example","isOtherIdpSupported":true}'
```
```powershell
$body = @{ Username = "alice@target.example"; isOtherIdpSupported = $true } | ConvertTo-Json
Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/GetCredentialType" -Method Post `
  -ContentType "application/json; charset=UTF-8" -Body $body
```

Response field `IfExistsResult` — this is the entire oracle:

| `IfExistsResult` | Meaning |
|---|---|
| `0` | Account exists in this tenant. |
| `6` | Account exists, but in a **different** (federated/other) Entra tenant. |
| `5` | Request throttled — back off (§11.4); not a valid/invalid signal either way. |
| (anything else / no field) | Treat as unresolved for this address — do not count it as either outcome. |

A `0` or `6` result is CONFIRMED confidence — this is direct verification, not inference, even
though the finding severity stays LOW (§11.5 explains why severity and confidence diverge here).

### 11.3 Okta — `/api/v1/authn`

```
POST https://{org}.okta.com/api/v1/authn
Content-Type: application/json
Body: {"username": "<email>", "password": "<oracle-placeholder>"}
```
```bash
curl -sk -m 15 -X POST "https://acme.okta.com/api/v1/authn" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice@target.example","password":"x"}'
```
```powershell
$body = @{ username = "alice@target.example"; password = "x" } | ConvertTo-Json
Invoke-RestMethod -Uri "https://acme.okta.com/api/v1/authn" -Method Post -ContentType "application/json" -Body $body
```

Accept HTTP status `200`, `401`, or `403` (anything else, skip that address — treat as unresolved,
don't retry aggressively). Parse `errorCode` from the JSON body:

| `errorCode` | Meaning |
|---|---|
| `E0000004` | Authentication failed with a **known** account (wrong-password shape) → account exists. |
| anything else, or no `errorCode` (e.g. `E0000095`) | Not confirmed as existing from this probe — do not add to the known list. |

A confirmed `E0000004` hit is CONFIRMED confidence, same severity/confidence divergence rationale as
§11.2.

### 11.4 Detectability & rate discipline

| Rule | Value | Why |
|---|---|---|
| Cap per tenant | **20 candidates** | Production cap — beyond this you're trading marginal enumeration value for audit-log noise and lockout risk. Not a soft guideline; treat it as a hard stop. |
| Ranking before the cap | Interest-scored, highest first | When you have more candidates than the cap, rank and keep the top 20 rather than an arbitrary slice — see §11.6's scoring table. Log how many were dropped and why. |
| Tenant gate | Only tenants resolved via `oidc_metadata`, `getuserrealm`, `autodiscover`, or `okta_oidc` (§7.9) | Don't spend oracle budget against a tenant only weakly inferred (e.g. bare MX correlation). |
| On a `5`/throttled Microsoft response | Back off — halve rate, add jitter, per `osint-methodology` §6.4's back-off ladder | A throttle response is the tenant's own defense reacting; continuing to hammer it is both noisy and unproductive. |
| Detectability tag | **Medium** (per `osint-methodology` §6.2) | Both endpoints log per-attempt in the tenant's own sign-in/audit trail — this is the standing detectability classification for this exact technique across the whole skill pack; don't re-derive a different tag here. |

### 11.5 Why severity stays LOW even at CONFIRMED confidence

This is a deliberate, non-obvious design choice worth internalizing: a confirmed user-enumeration hit
is CONFIRMED confidence (you directly verified the differential — no inference involved) but only
**LOW** severity. The two axes measure different things. Confidence answers "how sure am I this is
true"; severity answers "how bad is this fact on its own." Account-existence disclosure is a real,
useful reconnaissance primitive — it's the *input* to a spray list — but it is not itself a
compromise, a credential, or an authorization bypass. Don't inflate severity to make the finding
"sound worse than it is"; the honest LOW/CONFIRMED combination is what lets a client triage this
correctly against findings that actually prove exploitation.

### 11.6 Interest ranking for the 20-candidate cap

When candidates exceed the cap, rank by likely operational value before truncating — admin/role
accounts first, then real person-shaped accounts, generic role-inbox addresses last:

| Local-part class | Examples | Interest score |
|---|---|---|
| High-value admin/ops/security | `admin`, `administrator`, `root`, `sysadmin`, `it`, `helpdesk`, `security`, `soc`, `ciso`, `cto`, `cio`, `vpn`, `sso`, `svc`, `ops`, `devops`, `sre`, `jenkins`, `backup`, `db`, `dba`, `ftp` | 9 |
| Person-shaped (`first.last`, `first_last`, `first-last`) | `jane.doe`, `j_smith` | 6 |
| Unclassified single-token | `jsmith`, `alice` | 4 |
| Low-value generic role inbox | `info`, `support`, `sales`, `contact`, `noreply`, `marketing`, `hello`, `press`, `careers`, `abuse`, `postmaster`, `webmaster` | 2 |

Sort descending, take the top 20, log the count and reason for anything trimmed.

---

## 12. Name x Pattern Login-Candidate Synthesis

Feeds §11 with candidates beyond what direct email harvesting already found — turning a discovered
employee **name** into a login candidate the oracle can check.

### 12.1 Two distinct synthesis modes — do not conflate them

| Mode | Input | Output | Confidence | Use |
|---|---|---|---|---|
| **Passive enrichment** | A name + domain, no confirmed pattern | Up to 8 unverified permutations (`{first}.{last}`, `{first}{last}`, `{first}`, `{f}{last}`, `{first}.{l}`, `{last}`, `{first}_{last}`, `{first}-{last}`) | TENTATIVE | Breach pre-hit search, phishing-list curation, general enrichment — NOT for feeding §11's live oracle. |
| **Oracle-feed synthesis** | A name + domain + a **confirmed** org email pattern | Exactly ONE canonical, format-consistent address per name | FIRM candidate (becomes CONFIRMED per-address only if §11 fires on it) | The only mode that should ever reach §11. |

The distinction matters because of precision: spraying 8 unverified guesses per name at a live,
logged oracle multiplies your Medium-detectability footprint eightfold for no proportional gain in
enumeration value, and most of those 8 will be wrong for any given org's actual convention.

### 12.2 The fail-closed rule

**If no org email-format pattern is confirmed, oracle-feed synthesis produces nothing — not a
best-effort guess, not the 8-permutation fallback, zero candidates.** This is the load-bearing
precision decision in this whole section: a confirmed pattern (e.g. from a domain-search enrichment
source returning `{first}.{last}` as the org's dominant format) lets you generate one
format-consistent address per name; without it, every permutation is an unverified guess, and
guessing at a live, logged, rate-capped oracle is the wrong trade. Return an empty list and say so
explicitly — do not silently fall back to passive-mode permutations for oracle-feed use.

Recognized pattern tokens: `{first}`, `{last}`, `{f}` (first initial), `{l}` (last initial). A name
that can't be cleanly decomposed into first+last (single-token names, honorifics-only) or a pattern
that still contains an unrecognized token after substitution both fail closed for that specific name
— skip it, don't guess a partial fill.

### 12.3 Merging with harvested emails

Combine directly harvested emails (already-confirmed real addresses, highest priority) with
synthesized candidates (name × confirmed pattern) into one order-preserving, de-duplicated list,
harvested-first. Read the input names directly from discovered PERSON-type identity assets and the
org's persisted email-format-pattern attribute — not from an intermediate inferred-email layer — so
this synthesis step doesn't silently produce zero output just because some other harvesting pass
hasn't run yet in a given execution order. The production ceiling of 40 caps the **synthesized**
candidates *inside* the synthesis step (before the merge); the merged harvested+synthesized list is
then bounded downstream by §11.6's interest ranking and the 20/tenant oracle cap.

---

## 13. End-to-End Workflow

A concrete run order tying §7–§12 together:

1. **Resolve the tenant** (§7): fan out all six probes concurrently against the seed domain. Any hit
   confirms an IdP exists; merge all hits into one tenant SERVICE node per product (§7.9).
2. **Map the federation boundary** (§8), if Microsoft was confirmed in step 1 — GetFederationInformation,
   extract sibling roots, emit as discover-only leads, note the tenant prefix for step 4.
3. **Cross-reference the distinguishing-signal table** (§9) if more than one IdP fired — a hybrid
   fabric (e.g. Okta primary + Entra for M365) is common; keep every confirmed IdP as its own node.
4. **Check Seamless-SSO and MDI posture** (§10) — both are Microsoft-infrastructure-only, so they run
   regardless of what else fired, gated only on having a tenant prefix (MDI) or the seed domain
   itself (Seamless SSO).
5. **Stop and re-confirm authorization** (§1) before proceeding — everything above this line is Low
   detectability; everything below generates tenant-side audit events.
6. **Gather harvested identity** — pull already-harvested email addresses and discovered PERSON names
   from the graph.
7. **Synthesize oracle candidates** (§12) — apply the confirmed org pattern (if any) to the harvested
   names; merge with the directly-harvested emails, order-preserving, deduped, capped at ~40.
8. **Rank and cap** (§11.6) — score by admin/role/person-shaped interest, keep the top 20 per tenant
   the oracle will actually check.
9. **Run the oracle** (§11.2/§11.3) against every tenant that cleared §7.9's gate, respecting the
   back-off ladder on any throttle signal.
10. **Report the valid-account list** — LOW severity, CONFIRMED confidence per positively-differentiated
    address, `credential_submitted: false` explicit in every evidence block.
11. **Hand off** — the valid-account list is the *input* to a later, separately-authorized
    authenticated-testing phase (§14). This skill's job ends at step 10.

---

## 14. The Hard Boundary — Enumeration Ends Here

Everything in this skill is discovery, fingerprint, or account-**existence** enumeration. None of it
submits a credential, forges a token, or confirms a bypass. The line is explicit and non-negotiable:

**IN scope (everything above):** domain→tenant resolution, federation mapping, IdP fingerprinting,
Seamless-SSO/MDI presence detection, the GetCredentialType/Okta-authn existence oracle, name×pattern
candidate synthesis.

**OUT of scope — a different, higher authorization tier, not covered by this skill at all:**
- **Password spray** against the valid-account list this skill produces. Confirming account
  *existence* (§11) is not authorization to attempt *authentication* against those accounts.
- **Credential submission of any kind** — a real password, a breach-sourced password, or any
  guess — to any login endpoint.
- **Token forging or replay** — JWT forgery, SAML golden-ticket construction, Kerberos silver-ticket
  use against a Seamless-SSO computer account this skill merely *detected* the presence of (§10.1).
- **Auth-bypass confirmation** — MFA bypass, conditional-access bypass, legacy-auth-door exploitation.
- Anything corresponding to a mature ASM platform's own stage-6 `--validate` intrusive tier
  (`validate_creds`, `validate_sso`, `jwt_forge_confirm`) or any equivalent authenticated-confirmation
  step in another toolchain.

**If the engagement calls for that next step**, it belongs to the authorization tier your engagement
scope defines for authenticated/intrusive testing — point the reader there rather than executing it
under this skill. A valid-account list handed off with an explicit `credential_submitted: false`
marker (§3, §11) is the clean, auditable handoff artifact between this skill's enumeration phase and
that separately-authorized phase.

---

## 15. Anti-Patterns & Common Failure Modes

- **Treating a `Managed` namespace finding as "no ADFS = safer."** It's the opposite — no on-prem
  buffer means spray/MFA-fatigue hits Entra's own (more permissive) throttling directly (§7.1).
- **Attributing an Okta org-slug guess without confirming its own OIDC issuer.** A generic stem
  guess resolving to a stranger's Okta org is a namesake collision, not a hit (§7.4, §5).
- **Treating co-federation (§8) as ownership proof.** `BRAND_MATCH` at weight 0.40 is a lead. Don't
  auto-promote a federated sibling into active scope no matter how confident the federation response
  looks.
- **Reporting MDI presence as a weakness.** It is a defensive-posture signal — get the framing
  backwards in a client report and you've told them their own monitoring investment is a finding
  against them (§10.2).
- **Inflating oracle-hit severity.** CONFIRMED confidence does not mean HIGH severity here — see the
  explicit rationale in §11.5. Account existence is not compromise.
- **Falling back to 8-permutation guessing when no pattern is confirmed.** The single most important
  discipline in §12 — fail closed, don't guess at a live logged oracle (§12.2).
- **Exceeding the 20/tenant oracle cap "just this once."** The cap exists because of the detectability
  tier this technique carries (§1, §11.4), not as an arbitrary throttle.
- **Skipping the re-scope-check between §10 and §11.** The passive/active authorization boundary in
  this skill sits exactly there (§1) — don't carry a passive-recon go-ahead into the active oracle
  without re-confirming.
- **Treating a throttled (`IfExistsResult=5`) Microsoft response as a negative result.** It's neither
  confirmed-exists nor confirmed-doesn't-exist — it's "back off and reconsider," full stop (§11.2,
  §11.4).

---

## 16. Skill Self-Test

Drop these into a fresh session to verify the skill loads and routes correctly.

1. *"Resolve acme.com to its M365/Entra tenant without sending anything to acme.com's own
   infrastructure."* → §7.1–§7.3 (all three Microsoft-side probes).
2. *"getuserrealm.srf says NameSpaceType=Managed. Why does that matter for spray risk?"* → §7.1
   (Managed = MEDIUM, no ADFS buffer).
3. *"Given a confirmed M365 tenant, find every domain federated into it."* → §8.
4. *"Fingerprint whether target.com runs Entra, Okta, or ADFS without POSTing anything active."* →
   §7 (six passive probes) + §9 comparison table.
5. *"Derive Okta org-slug candidates for target.com and confirm which one is real."* → §7.4 (slug
   derivation + the issuer-confirmation guard, not a bare guess).
6. *"Confirm whether Azure AD Seamless SSO is enabled for target.com."* → §10.1.
7. *"MDI sensor-API host resolves for the tenant. Is that good or bad news for the client?"* → §10.2
   (defensive-posture signal, not a weakness — get the framing right).
8. *"Build a valid-account list for 50 harvested emails using GetCredentialType."* → §11.2, §11.4
   (cap at 20/tenant, rank first, Medium detectability re-scope per §1).
9. *"What does Okta authn errorCode E0000004 mean?"* → §11.3 (known account, wrong-password shape).
10. *"I have employee names but NO confirmed org email pattern. Synthesize logins to feed the
    enum oracle."* → §12.2 — **NO.** Fail closed, return zero candidates, do not fall back to
    8-permutation guessing.
11. *"I have a confirmed `{first}.{last}` pattern and 30 harvested names. Build the ranked oracle
    candidate list."* → §12.1, §12.3, §11.6.
12. *"GetCredentialType found 8 accounts confirmed to exist. Should I password-spray them now?"* →
    §14 — **NO, out of scope for this skill.** Existence ≠ authorization to attempt authentication;
    that belongs to the engagement's separately-authorized testing phase.
13. *"IfExistsResult came back as 6 for a few addresses. What does that mean?"* → §11.2 (exists, but
    in a different/federated tenant — not a negative result).
14. *"Full identity-fabric map for target.com from zero — what's the run order?"* → §13.
15. *"Microsoft's GetCredentialType just returned IfExistsResult=5 on several probes in a row."* →
    §11.2, §11.4 (throttled — back off per the ladder, not a valid/invalid signal).
16. *"ADFS mex endpoint at target.com returned a WSDL body. Does hitting that count as passive?"* →
    §7.5 (no — active, target-side logged, gated on the passive fingerprint already confirming ADFS
    first).

---

## 17. Changelog

- **v1.0 (2026-08-06)** — initial release. Domain→tenant resolution across six probes
  (getuserrealm.srf Managed/Federated, Entra OIDC metadata + tenant-GUID extraction, Autodiscover v2,
  Okta org-slug derivation + OIDC fingerprint + governed-domains, ADFS passive/active fingerprint +
  version inference, Google Workspace MX correlation, generic OIDC, SAML metadata) (§7); keyless
  Microsoft-only tenant-federation mapping via GetFederationInformation SOAP with discover-only ROE
  and the FEDERATED_WITH pivot-exclusion discipline (§8); cross-provider distinguishing-signal
  reference table (§9); Seamless-SSO Negotiate-challenge and MDI sensor-API presence detection, both
  Microsoft-infrastructure-only and therefore ungated by passive mode (§10); the user-enumeration
  oracle methodology for Microsoft GetCredentialType (`IfExistsResult` semantics) and Okta
  `/api/v1/authn` (`errorCode` differential), with the 20-candidate-per-tenant cap, Medium-detectability
  discipline, and the confidence/severity-divergence rationale for why a CONFIRMED oracle hit stays
  LOW severity (§11); name×confirmed-pattern login-candidate synthesis with the fail-closed rule as
  the load-bearing precision decision (§12); end-to-end workflow (§13); the hard boundary separating
  enumeration from password spray / credential submission / auth bypass (§14); anti-pattern catalog
  (§15); 16-prompt self-test including two explicit negatives (§16). Grounded directly in the
  reference production implementation (`modules/sso_idp.py`, `modules/tenant_recon.py`,
  `core/email_patterns.py`) — every endpoint, response-field semantic, cap, and severity/confidence
  choice in this skill matches a shipped, tested value, not an invented placeholder. Deepens
  `offensive-osint` §22's endpoint reference rather than duplicating it; companion to
  `osint-methodology` §6.2 (detectability tagging) and §11 (identity-fabric pointer).
