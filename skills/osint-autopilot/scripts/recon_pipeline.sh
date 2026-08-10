#!/usr/bin/env bash
# osint-autopilot deterministic driver — Stages 1-3 + endpoint harvest + breach + ports.
# Usage: recon_pipeline.sh <domain>
# Host-specific: uses dig/curl (dnsx + pd-httpx segfault on m1cpu); nmap kept bounded.
set -uo pipefail
D="${1:?usage: recon_pipeline.sh <domain>}"
[[ "$D" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "error: invalid domain '$D' (letters, digits, '.', '-' only)" >&2; exit 1; }
ENG="$HOME/Research/engagements/$D"
TS(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log(){ echo "$(TS) $*" >> "$ENG/run-log.jsonl"; }
mkdir -p "$ENG"/{evidence/{stage1-seed,stage2-expansion,stage3-enrichment,breach,identity,ports,js},assets,findings,notes,buckets}
S1="$ENG/evidence/stage1-seed"; S2="$ENG/evidence/stage2-expansion"; S3="$ENG/evidence/stage3-enrichment"
BR="$ENG/evidence/breach"; ID="$ENG/evidence/identity"; PT="$ENG/evidence/ports"; JS="$ENG/evidence/js"
echo "[*] engagement dir: $ENG"
[ -f "$ENG/README.md" ] || cat > "$ENG/README.md" <<EOF
# Engagement: $D
- Type: External red-team OSINT
- Kickoff (UTC): $(TS)
- Posture: passive-first; active phases under authorization. Stage 6 (exploitation) NOT run by autopilot.
- Layout: evidence/ (per-stage, +sha256) · assets/ · findings/ · buckets/ · run-log.jsonl
EOF
log "autopilot_start $D"

echo "[1] Seed: DNS / WHOIS / RDAP / email-security"
{ for r in A AAAA MX NS SOA TXT CAA; do echo "=== $r ==="; dig +noall +answer "$D" $r; done; } > "$S1/dns-records.txt" 2>&1
whois "$D" > "$S1/whois.txt" 2>&1
curl -s --max-time 20 "https://rdap.org/domain/$D" -o "$S1/rdap.json" 2>/dev/null
{ echo "=== SPF ==="; dig +short "$D" TXT | grep -i spf
  echo "=== DMARC ==="; dig +short "_dmarc.$D" TXT
  echo "=== MTA-STS ==="; dig +short "_mta-sts.$D" TXT; } > "$S1/email-security.txt" 2>&1
log "stage1_done"

echo "[2] Expansion: subfinder + certspotter + crt.sh (union), resolve, permutation"
subfinder -d "$D" -silent -all 2>/dev/null | sort -u > "$S2/subs-subfinder.txt"
curl -s --max-time 30 "https://api.certspotter.com/v1/issuances?domain=$D&include_subdomains=true&expand=dns_names" \
  | jq -r '.[].dns_names[]?' 2>/dev/null | tr 'A-Z' 'a-z' | sed 's/\*\.//g' | grep "$D\$" | sort -u > "$S2/subs-certspotter.txt"
curl -s --max-time 40 "https://crt.sh/?q=%25.$D&output=json" | jq -r '.[].name_value' 2>/dev/null \
  | tr 'A-Z' 'a-z' | sed 's/\*\.//g' | grep "$D\$" | sort -u > "$S2/subs-crtsh.txt"
cat "$S2"/subs-*.txt 2>/dev/null | grep -iE "^[a-z0-9._-]+\.$D\$" | sort -u > "$S2/subs-all.txt"
echo "    subdomains(union): $(wc -l < "$S2/subs-all.txt")"
# resolve via dig, parallel
: > "$S2/resolved.txt"
cat "$S2/subs-all.txt" | xargs -P30 -I{} sh -c 'ip=$(dig +short "{}" A | grep -E "^[0-9]" | paste -sd, -); [ -n "$ip" ] && echo "{} -> $ip"' >> "$S2/resolved.txt"
echo "    resolved: $(wc -l < "$S2/resolved.txt")"
awk '{print $1}' "$S2/resolved.txt" | sort -u > "$S2/live-hosts.txt"
log "stage2_done subs=$(wc -l < "$S2/subs-all.txt") resolved=$(wc -l < "$S2/resolved.txt")"

echo "[3] Enrichment: HTTP probe (parallel curl)"
probe(){ h="$1"; o=$(curl -skI --max-time 6 -w 'HTTPCODE=%{http_code}' "https://$h/" 2>/dev/null)
  c=$(printf '%s' "$o"|sed -n 's/.*HTTPCODE=//p'|tail -1)
  s=$(printf '%s' "$o"|awk -F': ' 'tolower($1)=="server"{print $2}'|tr -d '\r'|head -1)
  l=$(printf '%s' "$o"|awk -F': ' 'tolower($1)=="location"{print $2}'|tr -d '\r'|head -1)
  printf '%s|%s|%s|%s\n' "$h" "$c" "$s" "$l"; }
export -f probe
echo "host|code|server|location" > "$S3/http-probe.txt"
cat "$S2/live-hosts.txt" | xargs -P25 -I{} bash -c 'probe "$@"' _ {} >> "$S3/http-probe.txt" 2>/dev/null
echo "    probed: $(( $(wc -l < "$S3/http-probe.txt") - 1 ))"

echo "[3b] Identity fabric (Entra realm / OIDC / Okta)"
curl -s --max-time 15 "https://login.microsoftonline.com/getuserrealm.srf?login=user@$D&xml=1" -o "$ID/getuserrealm.xml" 2>/dev/null
curl -s --max-time 15 "https://login.microsoftonline.com/$D/.well-known/openid-configuration" -o "$ID/oidc-config.json" 2>/dev/null
OKTA=$(grep -oE '[a-z0-9-]+\.okta\.com' "$ID/getuserrealm.xml" 2>/dev/null | head -1)
[ -n "$OKTA" ] && curl -s --max-time 12 "https://$OKTA/.well-known/okta-organization" -o "$ID/okta-org.json" 2>/dev/null

echo "[3c] /version probe on auth/iam hosts (unauth build disclosure)"
: > "$S3/version-disclosure.txt"
grep -iE '^(auth|iam)\.' "$S2/live-hosts.txt" | while read -r h; do
  v=$(curl -sk --max-time 6 "https://$h/version" 2>/dev/null | head -c 400)
  echo "$v" | grep -qiE 'version|revision|hydra|kratos|keto|loki' && echo "$h :: $v" >> "$S3/version-disclosure.txt"
done

echo "[3d] S3-website host takeover check"
: > "$S3/s3-validation.txt"
awk -F'|' '$3=="AmazonS3"{print $1}' "$S3/http-probe.txt" | while read -r h; do
  cn=$(dig +short "$h" CNAME | paste -sd, -); b=$(curl -sk --max-time 8 "https://$h/" 2>/dev/null | head -c 400)
  t="-"; echo "$b" | grep -qi 'NoSuchBucket' && t="TAKEOVER:NoSuchBucket"; echo "$b" | grep -qi 'ListBucketResult' && t="PUBLIC-LISTING"
  echo "$h | cname=$cn | $t" >> "$S3/s3-validation.txt"
done
log "stage3_done"

echo "[3e] Endpoint harvest: gau + waybackurls + homepage JS secret sweep"
gau --subs --threads 5 "$D" > "$S3/gau-all.txt" 2>/dev/null
: > "$S3/wayback-all.txt"
cat "$S2/live-hosts.txt" | xargs -P10 -I{} sh -c 'echo "{}" | waybackurls 2>/dev/null' >> "$S3/wayback-all.txt"
grep -viE '\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|pdf|zip|map)(\?|$)' "$S3/gau-all.txt" 2>/dev/null | sort -u > "$S3/urls-clean.txt"
# grab first-party JS from live 200 hosts, extract endpoints + secrets
: > "$JS/js-endpoints.txt"; : > "$JS/js-secrets.txt"
SECRE='(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|xox[baprs]-[0-9a-zA-Z-]+|ghp_[0-9A-Za-z]{36}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+|-----BEGIN [A-Z ]+PRIVATE KEY-----|[A-Z_]*API_KEY["'"'"' ]*[:=]["'"'"' ]*[A-Za-z0-9_-]{12,})'
awk -F'|' '$2==200{print $1}' "$S3/http-probe.txt" | head -60 | while read -r h; do
  html=$(curl -sk --max-time 8 "https://$h/" 2>/dev/null)
  echo "$html" | grep -oE '(src|href)="[^"]+\.js[^"]*"' | sed -E 's/(src|href)="//;s/"//' | while read -r j; do
    case "$j" in http*) u="$j";; /*) u="https://$h$j";; *) u="https://$h/$j";; esac
    echo "$j" | grep -qiE 'fontawesome|googletagmanager|google-analytics|gstatic|jquery|cloudflareinsights' && continue
    body=$(curl -sk --max-time 15 "$u" 2>/dev/null | head -c 6000000)
    echo "$body" | grep -oE '"/(api|v[0-9]|iam-api|graphql|auth|users?|account|copilot|configservice)[A-Za-z0-9_./{}:-]*"' | tr -d '"' >> "$JS/js-endpoints.txt"
    echo "$body" | grep -oE "$SECRE" | sed "s#^#$h :: #" >> "$JS/js-secrets.txt"
  done
done
sort -u "$JS/js-endpoints.txt" -o "$JS/js-endpoints.txt"; sort -u "$JS/js-secrets.txt" -o "$JS/js-secrets.txt"
echo "    js endpoints: $(wc -l < "$JS/js-endpoints.txt") | js secret-hits: $(wc -l < "$JS/js-secrets.txt")"
log "endpoint_harvest_done gau=$(wc -l < "$S3/gau-all.txt")"

echo "[4] Breach (HudsonRock free)"
curl -s --max-time 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=$D" -o "$BR/hudsonrock-domain.json" 2>/dev/null

echo "[5] Ports: split public/private, bounded nmap on public"
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$S2/resolved.txt" | sort -u > "$PT/all-ips.txt"
grep -E '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' "$PT/all-ips.txt" > "$PT/private-ips.txt"
grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' "$PT/all-ips.txt" > "$PT/public-ips.txt"
echo "    private(internal-leak): $(wc -l < "$PT/private-ips.txt") public: $(wc -l < "$PT/public-ips.txt")"
grep -E '10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.' "$S2/resolved.txt" > "$PT/internal-ip-leak-hosts.txt" 2>/dev/null
if [ -s "$PT/public-ips.txt" ]; then
  nmap -Pn -T4 -p 22,80,443,3389,8080,8443,9200,6379,27017,5432,3306,5601,9000,2375,10250 \
    --max-retries 1 --host-timeout 20s --min-parallelism 20 -iL "$PT/public-ips.txt" \
    -oG "$PT/nmap-public.gnmap" -oN "$PT/nmap-public.txt" >"$PT/nmap-public.log" 2>&1 &
  NMAP_PID=$!
  # cap total nmap time at 10 min so autopilot never stalls
  ( sleep 600; kill $NMAP_PID 2>/dev/null ) & WATCH=$!
  wait $NMAP_PID 2>/dev/null; kill $WATCH 2>/dev/null
fi
log "ports_done"

echo "[*] Hashing evidence (chain-of-custody)"
find "$ENG/evidence" -type f ! -name '*.sha256' | while read -r f; do [ -f "$f.sha256" ] || shasum -a 256 "$f" > "$f.sha256"; done
# build host buckets for the Stage-4 fan-out workflow (18/bucket)
awk -F'|' '$2!="000" && $2!=""{print $1}' "$S3/http-probe.txt" | tail -n +2 | sort -u > "$ENG/buckets/responsive-hosts.txt"
split -d -l 18 "$ENG/buckets/responsive-hosts.txt" "$ENG/buckets/bucket-"
echo "$(ls "$ENG/buckets"/bucket-* 2>/dev/null | wc -l | tr -d ' ')" > "$ENG/buckets/COUNT"
log "autopilot_recon_done buckets=$(cat "$ENG/buckets/COUNT")"
echo "[+] Deterministic recon complete. Buckets: $(cat "$ENG/buckets/COUNT"). Next: run host-enum workflow, then findings_gen + build_xlsx."
echo "ENG=$ENG"
