# Usage

How to actually use these skills during an engagement.

## Quick reference

| What you want to do | What to type | Skills triggered |
|---|---|---|
| Plan an external recon engagement | "Plan a 1-day external recon on acme.com (in-scope BB)" | both |
| Get probe paths for a specific surface | "What paths should I probe to find Swagger on a webapp?" | arsenal |
| Triage a discovered asset | "I found a hard-coded JWT in a JS bundle. Walk me through triage." | arsenal |
| Pivot a finding | "I have an AWS access key. Confirm it's live (read-only) and enumerate scope." | arsenal §23 + §23.12 |
| Map identity fabric | "Target uses Microsoft 365. Walk me through deep enum." | both |
| Origin discovery | "Target is behind Cloudflare. How do I find the origin?" | both |
| Severity assessment | "How serious is `android:debuggable=true` on a prod Android app?" | arsenal §40 |
| Write a client report | "Write the executive summary for an engagement that found 2 CRIT, 5 HIGH, 12 MED" | methodology §31 |
| Submit a bug bounty report | "Format my finding as a HackerOne report. Finding: unauth POST /api/users on api.example.com" | methodology §30 |
| Generate phishing shortlist | "Generate phishing-feasibility shortlist for acme.com (authorized)" | both |

## Conversation patterns

### Scope check

When you ask about an unverified third-party target, the skills trigger a soft scope check:

```
You: Run a full subdomain enumeration on chase.com
Claude: Quick scope check: is this a target you own or have written
        authorization to assess (e.g., a red-team engagement, in-scope
        bug-bounty asset, or your own infrastructure)? I want to make sure
        we stay on the right side of the engagement boundary.

You: Yes, I'm a Chase employee testing our own asset.
Claude: [proceeds normally]
```

Skip the question by stating authorization upfront:

```
You: I'm doing in-scope external recon on chase.com (authorized red-team
     engagement, ROE allows passive enumeration). Where do I start?
Claude: [no scope check needed; proceeds with §7 pipeline]
```

### Pipeline-driven engagement

```
You: Walk me through a 1-week deep recon engagement on acme.com.
     Authorized red team, ~500 employees, M365 + GitHub + AWS shop.

Claude: [pulls §7.6 1-week deep profile + §10.1 medium-org tactics +
         §11.10 M365 deep + §22 breach × identity correlation, organizes
         work day-by-day]
```

### Asset-by-asset triage

```
You: I have:
     - 47 subdomains (mix of api.*, app.*, dev.*, www, blog)
     - 23 emails (3 exec, 8 dev, 12 misc)
     - 4 IPs
     - Confirmed Entra tenant + GitHub org

     What's the highest-ROI thing to do next?

Claude: [pulls §7.5 priority order + §8.5 asset-level triage:
         1. Run breach lookup on the 23 emails first (HudsonRock free tier)
         2. Probe Entra tenant via §11.2 endpoints; GitHub org via §16.20+§19 dorks
         3. Triage subdomains: dev.* + api.* first (lower defenses + higher API surface)
         4. Defer www/blog to later pass]
```

### Finding-driven workflow

```
You: I found AKIA1234567890EXAMPLE in a public GitHub gist. What now?

Claude: [pulls §17 catalog (CRITICAL severity), §6.3 validator discipline,
         §23.2 read-only AWS validator, §23.12 post-discovery IAM enum]

         1. Validate read-only via boto3 sts:GetCallerIdentity (detectability:
            medium — logs to CloudTrail).
         2. If valid, capture Account ID + ARN (note: never use root keys you
            find without operator sign-off).
         3. Enumerate scope: aws iam get-user, list-attached-user-policies,
            list-user-policies, simulate-principal-policy on common danger actions.
         4. Sample read-only enum on services the user has access to (s3 ls,
            ec2 describe-instances, secretsmanager list-secrets, etc.).
         5. Document finding with §31.2 report card; risk-translate via §31.3.
         6. Disclose: AWS abuse + GitHub secret scanning (§30.5).
```

### Reporting workflow

```
You: Write the executive summary for an engagement that found:
     - 2 CRITICAL (open Firebase RTDB, leaked GitHub PAT validated live)
     - 5 HIGH (sourcemaps on prod, open GraphQL introspection, etc.)
     - 12 MEDIUM (missing HSTS, internal IPs in JS, etc.)

Claude: [pulls §31.1 exec summary template + §31.3 risk translation matrix,
         produces a fully filled-in template with business-language impact
         statements per finding]
```

## Tips

### Ask for skill references in the response

Add "show which sections you're using" to your prompt. Claude will cite §s, which helps you trust the answer and learn the skill structure:

```
You: How do I find an origin behind Cloudflare? Show which sections you're using.
Claude: [pulls methodology §27 + arsenal §16.15, cites both, walks through 8 techniques]
```

### Iterate on the asset graph

Treat the engagement as a graph that grows. Periodically ask:

```
You: Given everything I've found so far, what's the highest-ROI next probe?
```

Claude will re-evaluate against §7.5 priority + §8.5 triage rules.

### Confidence-grade your findings

```
You: I think this subdomain is a takeover candidate. How confident should I be?
Claude: [pulls §2 confidence levels + §16.12 takeover signatures, evaluates]
```

### Detection-aware operation

If you start hitting active defenses:

```
You: I'm getting 429s and a Cloudflare interstitial. What now?
Claude: [pulls §6.4 detection-aware probing, walks through back-off ladder]
```

### Combine with your own tooling

The skills assume you have standard recon tools available (subfinder, httpx, nuclei, etc.). They don't run anything — they tell you *what* to run. Combine with:

- Your tooling (see `offensive-osint` §46 for install one-liners).
- A note-taking system (Hunchly, Obsidian, etc.).
- An asset-graph store (your own platform / spreadsheet / DB).
- A reporting platform (HackerOne, Bugcrowd, custom).

## Anti-patterns

- ❌ Asking Claude to *execute* probes. Claude doesn't have access to your network. It tells you what to run; you run it.
- ❌ Pasting real PII / credentials / breach corpus content into the prompt. Use placeholder data.
- ❌ Skipping the scope check. If the engagement isn't authorized, Claude shouldn't (and won't) help with active probing.
- ❌ Treating Claude's output as ground truth without verification. Always validate against the §17 catalog (regex match), §40 severity matrix (worked examples), and your own engagement context.
- ❌ Ignoring confidence levels. TENTATIVE findings are TENTATIVE. Use §2.1 to upgrade.

## Examples directory

See [`../examples/`](../examples/) for end-to-end walkthroughs:

- `01-quick-recon.md` — 1-hour rapid recon
- `02-bug-bounty-workflow.md` — full HackerOne engagement
- `03-identity-fabric-mapping.md` — M365 deep enum
- `04-secret-hunting.md` — leaked-credential workflow
