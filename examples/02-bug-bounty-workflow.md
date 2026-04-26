# Example 02: Bug Bounty Workflow (HackerOne)

> Engagement type: HackerOne in-scope program
> Time budget: open-ended (a few hours per session)
> Authorization: program scope (always re-check before each probe set)
> Target: `acme.example` with HackerOne program

End-to-end walkthrough from program selection through report submission.

---

## Step 1: Program selection + scope analysis

**Prompt to Claude:**

> I'm picking a new HackerOne program. Walk me through how to read the scope quickly to find the highest-value attack surface.

**Claude pulls:** `osint-methodology` §10 (bug-bounty pivot mode) + §30.1 (HackerOne basics).

**Process:**

1. Read **program scope** (in-scope assets, out-of-scope assets, severity criteria, special restrictions).
2. Note **rewards table** (per-severity payouts; some programs pay flat, others CVSS-multiplied).
3. Note **special rules** (no automated scanning, no DoS, no social engineering, no physical, etc.).
4. Note **excluded vulnerabilities** (clickjacking on non-sensitive pages, missing best-practices headers without exploit, etc.).

**Severity inference for this program:**
- HackerOne uses CVSS v3 base + program multiplier.
- Conservative scoring → trust → repeat awards.

---

## Step 2: Initial passive recon

**Prompt:**

> Authorized H1 program: scope is `*.acme.example` excluding `legacy.acme.example` and `*.staff-only.acme.example`. Plan a 1-day standard recon with H1 reporting in mind.

**Claude pulls:** `osint-methodology` §7.6 (1-day standard profile) + §7.5 (priority order) + §10.1 (medium-org tactics).

**Run:** Stage 1–3 of the standard pipeline (see [`01-quick-recon.md`](01-quick-recon.md) for the rapid version; expand scope here).

---

## Step 3: Asset triage

After enumeration, you have:

```
Asset graph:
  - 200 subdomains
  - 80 alive webapps
  - 25 IPs
  - 5 mobile apps (Android + iOS)
  - 1 confirmed Entra tenant
  - 1 GitHub org with 30 public repos
  - 100 emails from Hunter.io
```

**Prompt:**

> Triage these assets for highest-ROI bug-bounty value. Show priority order.

**Claude pulls:** `osint-methodology` §8.5 (asset-level triage rules) + §7.5 (priority order).

**Output:**

1. Breach lookup on 100 emails (HudsonRock free).
2. GitHub recon on the org's 30 public repos (`offensive-osint` §19 dorks + secret catalog).
3. Triage 80 webapps: dev/staging hosts first (lower defenses), then admin/dashboard paths.
4. Probe 80 webapps for Swagger/OpenAPI (`offensive-osint` §16.1 28-path wordlist).
5. Probe for GraphQL (§16.2 13-path).
6. Run §16.5 always-on HTTP checks against every alive webapp.
7. JS deep analysis on ~40 webapps (sourcemaps, secrets, endpoints).
8. SSO mapping (Entra tenant already confirmed; deep enum via §22.8).
9. Mobile attack surface on 5 apps (ownership-confidence + APK static analysis).

---

## Step 4: Find a vulnerability

Suppose you find: **Unauthenticated POST `/api/v1/users` on `api.acme.example` returns 200 with user creation confirmation.**

**Prompt:**

> Found unauth POST /api/v1/users on api.acme.example returning 200 with new user data. How serious is this and what should I check next?

**Claude pulls:** `offensive-osint` §20 (endpoint interest score), §39 (attack-path hints), §40 (severity matrix).

**Score evaluation:**
- Unauth write → +40
- Sensitive keyword `users` → +20
- = 60 base

If verb tampering or schema leak adds → could push to ≥70 → HIGH/CRITICAL.

**Attack-path hint** (§39):
> *"Unauthenticated POST `/api/v1/users` — try IDOR + privilege escalation; check whether numeric IDs are sequential or guessable."*

**Next probes:**
1. Confirm reproducibility (3 distinct test runs, different IDs).
2. Check whether returned IDs are sequential (IDOR potential).
3. Check role escalation: can the created user be made admin via parameter pollution?
4. Test rate-limiting (does it auto-block after N requests?).
5. Test field manipulation (mass-assignment).

**Document each test.** Capture: request, response, screenshot, UTC timestamp, SHA-256 of artifact.

---

## Step 5: Validate impact (read-only)

**Prompt:**

> The endpoint creates real users in production. What's the safe way to confirm impact without doing damage?

**Claude pulls:** `osint-methodology` §6.3 (validator discipline) + §28.3 (validation discipline for vuln finds).

**Approach:**
- Create ONE user with a sock-puppet email (e.g., `bb-test-<random>@<your-private-domain>`).
- Confirm the user appears in any public surface (e.g., GET `/api/v1/users` shows your created user).
- DO NOT mass-create.
- DO NOT delete other users.
- DO NOT escalate the test user to admin to "prove" it.
- Document timing + recipient details for the program team.

If the program forbids creating real records, document the request shape + response shape only — do not actually create.

---

## Step 6: Write the H1 report

**Prompt:**

> Write the H1 report for: unauth POST /api/v1/users on api.acme.example creates accounts without authorization. Reproduced 3x. Created users are visible via GET /api/v1/users. CVSS-base estimate AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.4.

**Claude pulls:** `osint-methodology` §30.2 (report structure) + §30.3 (severity inference).

**Output:**

```
Title: [CRITICAL] [api.acme.example] Unauthenticated user creation via POST /api/v1/users

Summary
The /api/v1/users endpoint accepts POST requests without authentication
and creates user accounts. An attacker can mass-create accounts, potentially
leading to spam, abuse of free-tier features, account squatting on chosen
usernames, and phishing infrastructure (account names like 'admin' or
'support').

Steps to Reproduce
1. Send: POST https://api.acme.example/api/v1/users
   Headers: Content-Type: application/json
   Body: {"email":"bb-test-<random>@<private-domain>","username":"bbtest1","name":"BB Test"}
2. Expected: 401 Unauthorized OR 403 Forbidden
3. Actual: 200 OK with response body containing user_id, email, username
4. Confirm: GET https://api.acme.example/api/v1/users — created user present in list.
5. Reproducible 3x with different sock-puppet emails (timestamps in attached evidence).

Proof of Concept
- Screenshot: see h1-poc-1.png (attached)
- HTTP capture: see h1-poc-request.txt + h1-poc-response.txt
- All three test runs use sock-puppet emails on a domain I own.
- No other users were modified or deleted.

Impact
- Unauthenticated account creation enables: spam, phishing-username squatting,
  free-tier abuse, account-enumeration via predictable IDs (sequential, see
  ID 1247291 → 1247292 → 1247293 across my 3 test runs), potential business-
  logic abuse if accounts get any default permissions or trial credit.
- Affected component: api.acme.example/api/v1/users (POST)
- Affected user populations: all of acme.example's user base (account-hijack
  via name collision possible).

Severity (per H1 / CVSS criteria)
- CVSS v3 vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
- Score: 9.4 (Critical)
- Justification: Network-vector, low complexity, no privileges, no UI;
  scope unchanged; high impact on confidentiality (account enumeration via
  sequential IDs reveals user base size + naming patterns) and integrity
  (account hijack via name collision); no DoS impact in our test.

Remediation
- Immediate: require authentication on POST /api/v1/users.
- Short-term: implement registration via signed-link email confirmation, not
  direct API call.
- Long-term: rate-limit registration per IP, per email-domain, and per
  client_id; consider CAPTCHA on the registration UI.

Affected component
- URL: https://api.acme.example/api/v1/users
- Method: HTTP POST
- Date discovered: 2026-04-27 14:23 UTC
- Date confirmed: 2026-04-27 14:31 UTC
- Tools used: curl 8.5.0, Burp Suite Pro 2025.4
```

---

## Step 7: Submit + monitor

1. Submit via H1 web UI.
2. Attach screenshots + HTTP captures (sanitize anything that's not your own data).
3. Set severity to your conservative estimate.
4. Wait for triage.
5. Respond to questions promptly.
6. **Don't escalate publicly** before the disclosure window.

## Step 8: Post-payout

- Wait for resolution + payout.
- Get permission to publicly disclose (if you want to write it up).
- Add to your portfolio.
- Note any tool / technique gaps for next engagement.

## Citation

This example follows:
- `osint-methodology` §7.5, §7.6 (pipeline + 1-day profile)
- `osint-methodology` §8.5 (asset triage)
- `osint-methodology` §10 (bug-bounty pivot mode)
- `osint-methodology` §22.8 (M365 deep — if relevant for the target)
- `osint-methodology` §28.3 (validation discipline)
- `osint-methodology` §30.1, §30.2, §30.3 (HackerOne report structure)
- `offensive-osint` §16.1, §16.2, §16.5 (Swagger / GraphQL / always-on probes)
- `offensive-osint` §19 (GitHub dorks)
- `offensive-osint` §20 (endpoint interest score)
- `offensive-osint` §39 (attack-path hints)
- `offensive-osint` §40 (severity matrix)
