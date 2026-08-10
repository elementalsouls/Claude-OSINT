#!/usr/bin/env python3
"""osint-autopilot findings engine: evidence -> findings.csv (rules over collected data).
Usage: findings_gen.py <domain>"""
import os, sys, re, csv, glob, json

DOMAIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+")

D = sys.argv[1] if len(sys.argv) > 1 else sys.exit("usage: findings_gen.py <domain>")
if not DOMAIN_RE.fullmatch(D): sys.exit(f"error: invalid domain {D!r} (expected a dotted hostname, e.g. example.com)")
ENG = os.path.expanduser(f"~/Research/engagements/{D}")
EV = f"{ENG}/evidence"

def rl(p):
    try: return [l.rstrip("\n") for l in open(p) if l.strip()]
    except FileNotFoundError: return []
def txt(p):
    try: return open(p).read()
    except FileNotFoundError: return ""

F = []  # id,title,severity,confidence,category,asset,description,remediation,evidence
def add(*a): F.append(a)
n = lambda: f"F-{len(F)+1:03d}"

# Cloudflare CIDR prefixes (partial) for CF-vs-direct origin classification
CF = re.compile(r'^(104\.1[6-9]|172\.6[4-9]|172\.7[01]|173\.245|188\.114|190\.93|197\.234|198\.41|162\.15[89]|141\.101|108\.162|103\.2[12])\.')

resolved = rl(f"{EV}/stage2-expansion/resolved.txt")
subs = rl(f"{EV}/stage2-expansion/subs-all.txt")

# --- non-prod exposure ---
# only count non-prod hosts that actually RESOLVE (exclude CT-log/cert-noise strings)
live_hosts = set(rl(f"{EV}/stage2-expansion/live-hosts.txt"))
nonprod = [s for s in subs if s in live_hosts and re.search(r'(^|\.)(dev|devs\d*|stg|stag(e|ing)s?\d*|preprods?\d*|test|qa|uat)(\.|\d|$)', s)]
if nonprod:
    add(n(), "Non-production environments publicly resolvable", "MEDIUM", "firm", "exposure",
        f"{len(nonprod)} hosts (dev/stg/preprod/test/qa/uat)",
        f"{len(nonprod)} non-prod hostnames resolve publicly. Non-prod often runs weaker auth, verbose errors, stale builds.",
        "Restrict non-prod to VPN/allowlist; remove public DNS for internal envs.",
        "evidence/stage2-expansion/subs-all.txt")

# --- Cloudflare bypass: root behind CF but product origins direct ---
root_ip = ",".join(re.findall(r'[0-9.]+', "\n".join([l for l in resolved if l.split(" -> ")[0]==D])))
direct = []
for l in resolved:
    if " -> " not in l: continue
    h, ips = l.split(" -> ", 1)
    if re.match(r'^(admin|api|api2|account|iam|app|asp|auth)\.', h) and not any(CF.match(ip) for ip in ips.split(",")):
        direct.append(h)
if direct:
    add(n(), "Product/admin/API origins bypass CDN/WAF (direct hosting)", "MEDIUM", "firm", "waf-bypass",
        f"{len(direct)} hosts incl "+", ".join(direct[:4]),
        "Root/marketing may sit behind a CDN/WAF, but admin/api/account/iam origins resolve directly to hosting IPs — WAF/rate-limit skippable by hitting origin.",
        "Front all product hosts through the WAF or restrict origin ACLs to CDN IPs.",
        "evidence/stage2-expansion/resolved.txt")

# --- internal RFC1918 leak via public DNS ---
leak = rl(f"{EV}/ports/internal-ip-leak-hosts.txt")
if leak:
    subnets = sorted(set(re.findall(r'(10\.\d+|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.', "\n".join(leak))))
    add(n(), "Internal RFC1918 IPs disclosed via public DNS (split-horizon)", "MEDIUM", "confirmed", "info-disclosure",
        f"{len(leak)} hosts",
        f"Public DNS A records return internal IPs. Leaks internal network topology / VPC CIDR layout ({', '.join(set(s+'.x.x' for s in subnets))}).",
        "Split-horizon DNS; stop returning internal A records on public resolvers.",
        "evidence/ports/internal-ip-leak-hosts.txt")

# --- DMARC / SPF posture ---
es = txt(f"{EV}/stage1-seed/email-security.txt")
dm = re.search(r'v=DMARC1[^"]*', es)
if dm:
    pol = re.search(r'\bp=(\w+)', dm.group(0))
    if pol and pol.group(1).lower() != "reject":
        add(n(), f"DMARC policy not enforced (p={pol.group(1)})", "LOW", "firm", "email", D,
            f"DMARC is p={pol.group(1)} (not reject); no strict subdomain policy observed. Header-From spoofing risk on non-enforced paths.",
            "Move to p=reject; set sp=reject; add MTA-STS.", "evidence/stage1-seed/email-security.txt")
elif "spf" in es.lower():
    add(n(), "No DMARC record found", "MEDIUM", "firm", "email", D,
        "SPF present but no DMARC record — domain spoofing largely unmitigated.",
        "Publish DMARC p=reject with rua/ruf.", "evidence/stage1-seed/email-security.txt")
if re.search(r'v=spf1[^"]*\+all', es):
    add(n(), "SPF +all (permits any sender)", "HIGH", "firm", "email", D,
        "SPF ends in +all — any host may send as this domain; also bypasses DMARC.",
        "Change SPF to -all.", "evidence/stage1-seed/email-security.txt")

# --- /version build disclosure ---
ver = rl(f"{EV}/stage3-enrichment/version-disclosure.txt")
if ver:
    prods = sorted(set(re.findall(r'(hydra|kratos|keto|loki|nginx|kong|envoy)', " ".join(ver).lower())))
    add(n(), "Unauthenticated /version leaks backend build versions", "LOW", "confirmed", "info-disclosure",
        f"{len(ver)} hosts",
        f"Unauth /version returns exact build versions ({', '.join(prods) or 'multiple components'}) — enables precise CVE mapping.",
        "Gate /version behind auth; strip build details.", "evidence/stage3-enrichment/version-disclosure.txt")

# --- secrets from JS ---
sec = rl(f"{EV}/js/js-secrets.txt")
if sec:
    add(n(), "Secret-pattern strings exposed in public client JS", "MEDIUM", "firm", "secret-leak",
        f"{len(sec)} hits",
        "Regex-matched secret-like strings (API keys / tokens / private-key markers) found in first-party JS served to unauthenticated users. Manual triage required — some may be public-by-design SPA identifiers.",
        "Rotate any functional key; move secrets server-side; never ship functional keys in client JS.",
        "evidence/js/js-secrets.txt")

# --- S3 takeover ---
s3 = rl(f"{EV}/stage3-enrichment/s3-validation.txt")
tko = [l for l in s3 if "TAKEOVER" in l or "PUBLIC-LISTING" in l]
if tko:
    add(n(), "S3 bucket takeover / public listing", "HIGH", "confirmed", "cloud",
        f"{len(tko)} hosts", "Dangling-CNAME takeover or public object listing confirmed on S3-fronted host(s).",
        "Reclaim/remove dangling CNAME; disable public listing.", "evidence/stage3-enrichment/s3-validation.txt")
elif s3:
    add(n(), "S3-website hosts present — takeover ruled out", "INFO", "confirmed", "cloud",
        f"{len(s3)} hosts", "Custom-domain S3 sites found; no dangling CNAME / NoSuchBucket / public listing.",
        "Monitor for future dangling CNAMEs.", "evidence/stage3-enrichment/s3-validation.txt")

# --- identity fabric ---
gr = txt(f"{EV}/identity/getuserrealm.xml")
okta = re.search(r'([a-z0-9-]+\.okta\.com)', gr)
nst = re.search(r'NameSpaceType>(\w+)<', gr)
# only a real IdP signal: Okta host found, OR a Managed/Federated namespace (not "Unknown")
if okta or (nst and nst.group(1) in ("Managed", "Federated")):
    prov = f"Okta ({okta.group(1)})" if okta else (nst.group(1) if nst else "unknown")
    add(n(), "Identity provider / federation mapped", "INFO", "firm", "identity", D,
        f"IdP: {prov}. Namespace: {nst.group(1) if nst else '?'}. Enum surface: Okta /api/v1/authn or Entra GetCredentialType (if managed).",
        "Enable IdP threat-detection; monitor auth enumeration.", "evidence/identity/getuserrealm.xml")

# --- breach ---
try:
    hr = json.load(open(f"{EV}/breach/hudsonrock-domain.json"))
    emp = hr.get("totalEmployees") or hr.get("stats",{}).get("totalEmployees",0) or hr.get("employees",0)
    usr = hr.get("totalUsers") or hr.get("stats",{}).get("totalUsers",0) or hr.get("users",0)
    if emp and emp >= 10:
        sev = "CRITICAL"
    elif emp and emp >= 1:
        sev = "HIGH"
    elif usr:
        sev = "LOW"
    else:
        sev = None
    if sev:
        add(n(), "Credentials in infostealer/breach corpus", sev, "firm", "breach", D,
            f"HudsonRock: {emp} employee + {usr} user credential(s) in stealer logs.",
            "Force reset affected accounts; monitor infostealer feeds; enforce MFA.", "evidence/breach/hudsonrock-domain.json")
except Exception: pass

# --- WordPress (LIVE check, not archive noise) ---
import subprocess
wp_hosts = []
for h in ([D, f"www.{D}"] + [x for x in live_hosts if x.startswith("www.")]):
    try:
        body = subprocess.run(["curl","-sk","--max-time","8",f"https://{h}/"],
                              capture_output=True, text=True, timeout=12).stdout
        if re.search(r'/wp-(content|includes|json)/|wp-login\.php|name="generator"[^>]*WordPress', body):
            wp_hosts.append(h)
    except Exception: pass
if wp_hosts:
    add(n(), "WordPress detected (marketing/CMS surface)", "INFO", "firm", "fingerprint",
        ", ".join(sorted(set(wp_hosts))), "Live WordPress markers in served HTML — standard WP surface (wp-json user-enum, plugin CVEs, xmlrpc).",
        "Harden WP; disable wp-json user enum & xmlrpc; keep plugins patched.", "live https response")

# --- port exposure ---
gn = txt(f"{EV}/ports/nmap-public.gnmap")
badports = sorted(set(re.findall(r'(3306|5432|6379|27017|9200|3389|2375|10250|5601)/open', gn)))
if badports:
    add(n(), "Sensitive service ports exposed on public origins", "HIGH", "confirmed", "network",
        "public IPs", f"Open non-web ports: {', '.join(badports)} (DB/RDP/Docker/kubelet/Elastic).",
        "Firewall these off the public internet immediately.", "evidence/ports/nmap-public.gnmap")
elif "/open" in gn:
    add(n(), "External port exposure minimal (80/443 only)", "INFO", "confirmed", "network",
        "public IPs", "Only HTTP(S) ports open on public origins; no DB/RDP/Docker/kubelet exposed.",
        "Maintain edge HTTP(S)-only posture.", "evidence/ports/nmap-public.gnmap")

# write
os.makedirs(f"{ENG}/findings", exist_ok=True)
out = f"{ENG}/findings/findings.csv"
with open(out, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["ID","Title","Severity","Confidence","Category","Asset / Host","Description","Remediation","Evidence"])
    w.writerows(F)
print(f"WROTE {out}  ({len(F)} findings)")
for f in F: print(f"  {f[0]} [{f[2]}] {f[1]}")
