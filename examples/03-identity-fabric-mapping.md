# Example 03: Identity Fabric Mapping (Microsoft 365 Deep)

> Engagement type: external red-team, identity-focused
> Time budget: 2–3 hours
> Authorization: written ROE, in-scope `acme.example` and identity infrastructure
> Target: `acme.example` — confirmed M365 shop

Walk-through of mapping a target's Microsoft 365 identity surface end-to-end.

---

## Why identity fabric matters

Compromise the identity fabric and you don't need to break into individual apps. Most organizations consolidate auth on one IdP — find it, map its tenants, and you've found the central trust anchor.

For an M365 shop, the identity fabric includes:
- Microsoft Entra (Azure AD) tenant
- Teams Federation posture
- SharePoint + OneDrive provisioning
- M365 OAuth applications
- Power Platform / Dynamics presence
- Guest user federation

---

## Step 1: Confirm M365 tenancy

**Prompt:**

> Confirm acme.example is on Microsoft 365 and extract the tenant GUID.

**Claude pulls:** `osint-methodology` §11.2 + `offensive-osint` §22.1.

**Run:**

```bash
T="acme.example"

# OIDC metadata — extracts tenant GUID
curl -sk "https://login.microsoftonline.com/${T}/.well-known/openid-configuration" \
  | jq -r '.issuer'
# Output: https://login.microsoftonline.com/<8-4-4-4-12-GUID>/v2.0

# Pull just the GUID
TENANT=$(curl -sk "https://login.microsoftonline.com/${T}/.well-known/openid-configuration" \
  | jq -r '.issuer' | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
echo "Tenant GUID: $TENANT"
```

**Capture:** Tenant GUID + domain. This is your stable identifier.

---

## Step 2: Determine federation status

**Run:**

```bash
# getuserrealm.srf — Managed vs Federated
curl -sk "https://login.microsoftonline.com/getuserrealm.srf?login=admin@${T}" | jq .
```

Look for:
- `NameSpaceType: "Managed"` → cloud-native (Entra is the IdP).
- `NameSpaceType: "Federated"` → on-prem ADFS or external IdP. Check `AuthURL` for the upstream.
- `FederationBrandName` → reveals the upstream IdP (e.g., "ADFS" or "Okta").

**Detectability:** low.

---

## Step 3: Check Teams federation

**Prompt:**

> Is Teams federation enabled? What's the impact?

**Claude pulls:** `osint-methodology` §11.10 + `offensive-osint` §22.8.

**Run:**

```bash
# Probe Teams Federation API (this requires a federated-tenant authenticated request;
# if you have an external M365 account, you can confirm via the Teams web client)
# Without authenticated access, infer from getuserrealm output + DNS records:
dig +short MX ${T}
# If MX = *.mail.protection.outlook.com → M365 confirmed
```

**Implications:**

- **Open Federation** (default) — anyone in any tenant can chat your users via `<email>@${T}` lookup. Soft-attack surface for vishing-via-Teams, smishing-equivalent, "from-IT" pretexts.
- **Restricted Federation** — only specific tenants can chat. Better posture; smaller attack surface.

If unrestricted: note as MEDIUM finding (operational risk; not directly exploitable but enables attack).

---

## Step 4: Enumerate SharePoint subdomains

**Run:**

```bash
# Derive tenant stem (often the company name without TLD)
STEM="acme"

# Probe the 3 SharePoint subdomain patterns
for sub in "" "-my" "-admin"; do
  HOST="${STEM}${sub}.sharepoint.com"
  echo "=== ${HOST} ==="
  curl -sk -m 10 -I "https://${HOST}/" -w 'STATUS:%{http_code}\n' | head -10
done
```

Expected:
- `acme.sharepoint.com` → main tenant SharePoint (auth-required, but presence confirms tenancy).
- `acme-my.sharepoint.com` → OneDrive-for-Business URLs.
- `acme-admin.sharepoint.com` → SharePoint admin center.

If the tenant uses a non-standard stem (sometimes companies pick a different name), test variants.

---

## Step 5: OneDrive personal site enumeration

**Run** (requires harvested employee emails):

```bash
# For each known employee email, derive the OneDrive personal-site URL
for email in alice@acme.example bob@acme.example; do
  USER_TOKEN=$(echo "$email" | tr '@.' '_')
  URL="https://${STEM}-my.sharepoint.com/personal/${USER_TOKEN}/Documents/"
  STATUS=$(curl -sk -m 10 -I "$URL" -w '%{http_code}' -o /dev/null)
  echo "$email → $URL → HTTP $STATUS"
done
```

Status meaning:
- 401 → personal site provisioned (user exists, OneDrive enabled).
- 404 → not provisioned (user doesn't exist OR OneDrive disabled per user).

This is a **presence indicator** for user enumeration. Detectability: low (requests don't trigger sign-in alerts, but logged in tenant audit).

---

## Step 6: M365 OAuth client_id discovery

**Run:**

```bash
# Pull every JS bundle from app.acme.example (or wherever the M365-integrated apps live)
# and grep for clientId GUID patterns
for js in $(curl -sk https://app.acme.example/ | grep -oE 'src="[^"]*\.js"' | tr -d '"' | sed 's/src=//'); do
  curl -sk "https://app.acme.example/$js" 2>/dev/null \
    | grep -oE 'clientId["'"'"' :=]+["'"'"']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    | sort -u
done | tee evidence/m365-clientids.txt
```

**Look for:**
- Microsoft well-known first-party client_ids (Office, Graph) — expected.
- Custom GUIDs → custom internal apps. **High-value finding** if their permissions include sensitive Graph scopes.

---

## Step 7: Check device-code phishing target posture

**Run:**

```bash
curl -sk "https://login.microsoftonline.com/${T}/v2.0/.well-known/openid-configuration" \
  | jq '.device_authorization_endpoint'
```

If non-null AND tenant doesn't restrict device-code grant flow → **MEDIUM** finding (device-code phishing feasible).

Modern Entra defaults often allow device-code flow per-app rather than tenant-wide; check Conditional Access policies aren't blocking it (you can't see CA policies from outside, but the endpoint presence is the prerequisite).

---

## Step 8: Power Platform / Dynamics presence

**Run:**

```bash
# Check for Dynamics tenant URLs (per-region: crm, crm2-15)
for region in crm crm2 crm3 crm4 crm5 crm6 crm7 crm8 crm9 crm10 crm11 crm12 crm15; do
  HOST="${STEM}.${region}.dynamics.com"
  STATUS=$(dig +short A $HOST | head -1)
  [ -n "$STATUS" ] && echo "$HOST → $STATUS"
done

# Power Platform make portal (auth-required; presence-only check)
curl -sk -m 10 -I "https://make.powerapps.com/environments" -w '%{http_code}\n'
```

---

## Step 9: Cross-correlate with breach data

**Prompt:**

> Tenant GUID confirmed (12345678-1234-1234-1234-123456789012). I have 30 employee emails from Hunter.io. Cross-reference for SSO_EXPOSURE.

**Claude pulls:** `osint-methodology` §22 (breach × identity correlation).

**Run:**

```bash
# HudsonRock Cavalier on each email
for email in $(cat evidence/employee-emails.txt); do
  curl -sk "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=$email" \
    | jq --arg e "$email" -c '{email: $e, total: .total_corporate_services, stealers: .stealers}'
done | tee evidence/breach-by-email.jsonl

# Count compromised employees
grep -c '"total":[1-9]' evidence/breach-by-email.jsonl
```

**Severity:**
- ≥10 employees compromised → **CRITICAL** SSO_EXPOSURE finding (entire tenant at elevated risk).
- 1–9 employees → **HIGH** SSO_EXPOSURE.
- 0 → INFO (posture tracking).

---

## Step 10: Compile findings

**Prompt:**

> Compile identity-fabric findings from this engagement: tenant confirmed, Teams federation open, 8 employees in HudsonRock corpus, 2 custom OAuth client_ids found in JS bundles, device-code endpoint enabled.

**Claude pulls:** `osint-methodology` §31.2 (per-finding report card).

**Output (per finding):**

1. **[CRITICAL] SSO_EXPOSURE — 8 employees compromised in Entra tenant `<GUID>`** — see report card with per-account source attribution.
2. **[MEDIUM] Teams Federation Open** — soft-attack surface for vishing/smishing-equivalent + IT-pretext attacks.
3. **[MEDIUM] Device-code authentication endpoint enabled** — device-code phishing target.
4. **[INFO] Custom OAuth client_ids identified** — `<GUID-1>` (app.acme.example), `<GUID-2>` (admin.acme.example) — note for permissions audit.

---

## Citation

This example follows:
- `osint-methodology` §11.2 (Microsoft Entra fingerprinting)
- `osint-methodology` §11.10 (Microsoft 365 deep surface)
- `osint-methodology` §22 (Breach × identity correlation)
- `osint-methodology` §31.2 (per-finding report card)
- `offensive-osint` §22.1 (Entra concrete endpoints)
- `offensive-osint` §22.8 (M365 deep enumeration)
- `offensive-osint` §16.13 (curl probes)
- `offensive-osint` §15.1 (breach severity mapping)
- `offensive-osint` §15.2 (SSO_EXPOSURE finding)
