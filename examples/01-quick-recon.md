# Example 01: 1-Hour Quick Recon

> Engagement type: rapid posture check ("how exposed is X?")
> Time budget: 60 minutes
> Authorization: in-scope bug-bounty asset
> Target: `acme.example` (fictional)

This walk-through follows `osint-methodology` §7.6 → 1-hour rapid recon profile.

## Hour breakdown

| Minutes | Phase | What you do |
|---|---|---|
| 0:00 – 0:15 | Stage 1 — Seed Discovery | WHOIS + ASN + DNS records + CT history |
| 0:15 – 0:25 | Passive subdomain enum | crt.sh + Subfinder |
| 0:25 – 0:30 | Port discovery | Shodan InternetDB on resolved IPs |
| 0:30 – 0:40 | Email harvest | Hunter.io + IntelX |
| 0:40 – 0:50 | Breach lookup | HudsonRock Cavalier (free) on harvested emails |
| 0:50 – 1:00 | Executive summary | One-page output |

---

## 0:00 – 0:15 — Seed discovery

**Prompt to Claude:**

> Authorized in-scope BB engagement on acme.example. Walk me through Stage 1 seed discovery in 15 min.

**Claude pulls:** `osint-methodology` §7 Stage 1 + arsenal §16.21 (WHOIS) + §16.22 (DNS) + §28.1 (BGP).

**You run:**

```bash
T="acme.example"

# WHOIS
whois $T > evidence/whois.txt
curl -sk "https://rdap.org/domain/$T" | jq . > evidence/rdap.json

# ASN lookup
whois -h whois.cymru.com " -v $T" > evidence/asn.txt
# Or: curl -sk "https://api.bgpview.io/ip/<resolved-ip>" | jq .

# DNS records (all common types)
for rt in A AAAA MX TXT NS SOA CAA; do
  echo "=== $rt ==="
  dig +short $T $rt
done > evidence/dns.txt

# CT history
curl -sk "https://crt.sh/?q=%25.${T}&output=json" | jq -r '.[].name_value' | sort -u > evidence/ct-subdomains.txt
```

**Capture:** WHOIS registrant + dates + nameservers; ASN + prefix; A/AAAA/MX/TXT/NS records; CT-derived subdomains.

---

## 0:15 – 0:25 — Subdomain enumeration

**You run:**

```bash
subfinder -d $T -all -recursive -silent | tee evidence/subfinder.txt
sort -u evidence/ct-subdomains.txt evidence/subfinder.txt > evidence/all-subs.txt
wc -l evidence/all-subs.txt
```

Typical output: 30–200 subdomains for a small SaaS company.

---

## 0:25 – 0:30 — Port discovery

**You run:**

```bash
# Resolve all subs to IPs
dnsx -l evidence/all-subs.txt -a -resp-only -silent | sort -u > evidence/ips.txt

# Shodan InternetDB (free, 1 req/sec, no key needed)
for ip in $(cat evidence/ips.txt); do
  curl -sk "https://internetdb.shodan.io/$ip" | jq -c "{ip, ports, hostnames, vulns: .vulns[:3]}"
  sleep 1
done | tee evidence/internetdb.jsonl
```

**Look for:** open ports per `osint-methodology` §7.5 priority — RDP/3389, SMB/445, Redis/6379, ES/9200, Mongo/27017, kubelet/10250, etcd/2379.

---

## 0:30 – 0:40 — Email harvest

**You run:**

```bash
# Hunter.io (25 free/month)
curl -sk -H "X-Api-Key: $HUNTER_KEY" "https://api.hunter.io/v2/domain-search?domain=$T" \
  | jq -r '.data.emails[] | .value' > evidence/emails-hunter.txt

# IntelX phonebook (free tier)
# (web UI for free tier; CLI tools require paid API)
# Manual: visit intelx.io → phonebook search → "@acme.example"

# Cross-reference with crt.sh SANs (some certs include admin emails)
grep -oE "[a-zA-Z0-9._%+-]+@${T}" evidence/ct-subdomains.txt | sort -u >> evidence/emails-misc.txt

cat evidence/emails-*.txt | sort -u > evidence/all-emails.txt
```

---

## 0:40 – 0:50 — Breach lookup (HIGHEST ROI step)

**Prompt to Claude:**

> I have 23 emails for acme.example. Highest-ROI next step?

**Claude pulls:** `osint-methodology` §7.5 priority order + §22 breach × identity correlation + arsenal §15.

**You run:**

```bash
# HudsonRock Cavalier (FREE — infostealer logs)
for email in $(cat evidence/all-emails.txt); do
  curl -sk "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=$email" \
    | jq -c "{email: \"$email\", stealers: .stealers, total: .total_corporate_services}"
done > evidence/hudsonrock.jsonl

# HIBP (paid; or use Pwned Passwords API with k-anonymity for password-hash check)
for email in $(cat evidence/all-emails.txt); do
  curl -sk -H "hibp-api-key: $HIBP_KEY" "https://haveibeenpwned.com/api/v3/breachedaccount/$email"
done > evidence/hibp.jsonl 2>/dev/null
```

**Severity mapping** (per arsenal §15.1):
- ≥10 employees in breach corpus → CRITICAL `SSO_EXPOSURE` candidate
- 1–9 employees → HIGH
- ≥1 user → MEDIUM
- 0 → INFO

---

## 0:50 – 1:00 — Executive summary

**Prompt to Claude:**

> Write a 1-page executive summary for an authorized 1-hour quick-recon engagement on acme.example. Findings:
> - 47 subdomains discovered
> - 3 open Elasticsearch instances on standard port (CRITICAL)
> - 1 leaked GitHub PAT in public gist (validated live, scope: repo) (CRITICAL)
> - 2 employees in HudsonRock infostealer corpus with cleartext passwords (HIGH)
> - DMARC `p=none` (MEDIUM)
> - Sourcemaps accessible on app.acme.example (HIGH)

**Claude pulls:** `osint-methodology` §31.1 exec summary template + §31.3 risk translation matrix.

**Output:** Filled-in 1-page exec summary with business-language impact statements + recommended next steps + reporting cadence note.

---

## What you did NOT do (deferred to longer engagements)

- Active port scans (only Shodan InternetDB passive)
- Subdomain bruteforce (only passive sources)
- LinkedIn employee enumeration (defer to 4-hour profile)
- JS deep analysis (defer to 1-day profile)
- Mobile attack surface (defer to 1-week profile)
- Vulnerability prioritization for any CVEs found (defer to 1-day profile)

## Scaling up

If your 1-hour quick recon found enough to warrant deeper work, propose to the engagement lead:

- **Upgrade to 4-hour focused recon** if findings suggest phishing-feasibility risk (DMARC gap + breached employees + identity-fabric mapped).
- **Upgrade to 1-day standard recon** if you found 2+ CRITICAL or 5+ HIGH severity findings.
- **Upgrade to 1-week deep recon** if the org is medium+ size (>100 employees) AND has mobile + cloud-native presence.

## Citation

This example follows the methodology defined in:
- `osint-methodology` §7.6 (1-hour rapid recon engagement profile)
- `osint-methodology` §7.5 (pipeline priority order)
- `osint-methodology` §22 (breach × identity correlation)
- `osint-methodology` §31.1 (executive summary template)
- `offensive-osint` §16.13 (curl probes), §16.21 (WHOIS), §16.22 (DNS catalog), §15.1 (breach severity)
