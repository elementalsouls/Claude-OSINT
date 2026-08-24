---
name: cloud-saas-exposure
description: "Organization-grade cloud and supply-chain attack-surface discovery: S3/GCS/Azure Blob bucket discovery via observed-name mining (CNAME/cert-SAN/Wayback) and bounded two-class permutation (6 prefixes x 15 suffixes on trusted tokens, bounded target-bound expansion on subdomain stems), existence (HEAD/GET) vs public-listing confirmation, object-key triage into 9 value tiers (database dumps, credentials, IaC state, kubeconfig, VCS dirs, config, archives, PII, logs), dangling-CNAME bucket-takeover detection, and the ownership-gated severity model that stops an unattributable public bucket from becoming a false CRITICAL; the fully offline AWS-account-ID recovery from a leaked AKIA/ASIA/AROA access key (base32 decode, runnable stdlib Python, canonical test vector, AWS-documentation-example-ID screening); dependency-confusion confirmation for npm/PyPI (internal-signal classifier -- private-registry binding vs org-namespace match -- paired with a read-only public-registry 404 check and the npm scope-claimability nuance the public search API misses); and passive cloud-native/container/Kubernetes/CI control-plane fingerprinting (Lambda URLs, API Gateway, Cloud Run, App Service, kubelet/etcd/K8s API/dashboard, Jenkins/GitLab/Argo CD) as an org-attribution and exposure surface. Passive/discovery only -- no exploitation, no credential submission, no active control-plane confirmation (a stage-6 validate_cloud active tier is described but out of scope). Use when enumerating a target's cloud storage footprint, recovering an AWS account ID from a leaked key, confirming a supply-chain dependency-confusion vector, or fingerprinting cloud-native/K8s/CI infrastructure for an authorized external recon engagement."
version: 1.0
sources: asm_reference_impl, public_research
triggers:
  - cloud attack surface
  - cloud exposure
  - SaaS exposure
  - cloud bucket enumeration
  - S3 bucket enum
  - GCS bucket enum
  - Azure blob enum
  - bucket takeover
  - dangling CNAME bucket
  - public cloud bucket
  - listable bucket
  - bucket ownership
  - object storage exposure
  - bucket permutation
  - AWS account ID
  - AWS account ID from access key
  - AKIA decode
  - access key account ID
  - offline AWS decode
  - base32 AWS account
  - AWS account enumeration
  - cross-account trust
  - IAM role phishing
  - sts assume role
  - dependency confusion
  - npm dependency confusion
  - PyPI dependency confusion
  - supply chain attack surface
  - unclaimed package
  - internal package registry
  - private npm registry
  - scoped npm package
  - npm scope claimability
  - package registry leak
  - cloud native fingerprint
  - Lambda function URL
  - API Gateway exposure
  - Cloud Run exposure
  - App Service exposure
  - serverless exposure
  - Kubernetes exposure
  - K8s exposure
  - kubelet exposure
  - etcd exposure
  - Docker API exposure
  - CI CD exposure
  - Jenkins exposure
  - GitLab exposure
  - control plane exposure
  - cloud footprint
  - cloud account attribution
---

# Cloud & SaaS Exposure — Buckets, Offline AWS Account-ID Recovery, Dependency Confusion, and Cloud-Native/K8s Fingerprinting

> Companion skills: `osint-methodology` (the pipeline this plugs into — Stage 2 asset
> expansion, Stage 4 exposure analysis, Stage 5 supply-chain confirmation). `offensive-osint`
> §16.8 (bucket-permutation raw wordlist), §16.17 (cloud-native URL pattern table), §16.18–
> §16.19 (container/K8s/CI paths + active curl recipes), §44 (package-registry search). This
> skill does not repeat those lists — it builds the reasoning layer on top: the
> ownership-gated bucket severity model, the offline AKIA→account-ID decode, the
> dependency-confusion two-part confirmation contract, and cloud-native/K8s as an
> org-attribution surface, not just another probe list.

## 0. When to Use / When NOT

**Use this skill when:** you're mapping an authorized target's cloud and supply-chain
footprint — enumerating storage buckets and judging whether a hit is actually the target's
risk (not a stranger's public bucket that happens to match a permutation); recovering the
AWS account ID behind a leaked access key you already hold (dead or live); confirming
whether an internal-looking npm/PyPI dependency is a registerable supply-chain vector; or
fingerprinting cloud-native (Lambda/Cloud Run/App Service/…) and container/K8s/CI
control-plane surface for org attribution and exposure triage.

**Do NOT use this skill when:** you just need the raw bucket-permutation wordlist,
cloud-native URL pattern table, or container/K8s/CI path list with no reasoning layer — go
straight to `offensive-osint` §16.8/§16.17–16.19/§44. Do NOT use it for anything past
discovery/confirmation: registering an unclaimed package, submitting AWS credentials,
authenticating to a Kubernetes API, or confirming a fingerprinted control plane actually
answers unauthenticated (that's a stage-6 `--validate --validate-cloud` active tier —
described, never performed, §5/§9.4).

---

## 1. Authorization & Legal Posture

Reuses `osint-methodology` §1 — assets you own or have written authorization to assess.
Three of this skill's four subsystems carry a distinct authorization shape, worth being
explicit about before you run any of them:

- **Bucket probing (§6)** is a real HTTP GET against bucket infrastructure that may or may
  not be the target's — the same "active but low-intrusion" tier as any other GET against
  target-adjacent infra. Standard engagement authorization applies.
- **AWS account-ID decode (§7)** is fully offline. No authorization question beyond already
  lawfully holding the leaked key.
- **Dependency-confusion confirmation (§8)** issues live GETs, but only against the public
  npm/PyPI registries — **zero packets to the target**. This is why it's explicitly in scope
  even though it's "active."
- **Cloud-native/K8s/CI fingerprinting (§9)** is pattern-matching over hostnames and ports
  already resolved by earlier recon — no new network traffic of its own.

---

## 2. Confidence Levels

Reuses `osint-methodology` §2. Domain-specific anchors:

| Level | Cloud/SaaS example |
|---|---|
| **TENTATIVE** | Org-namespace-matched dependency name (medium strength) with no private-registry binding — namesake-prone. |
| **FIRM** | Bucket exists (403/private) and is name-tied or CNAME/SAN/Wayback-observed; AWS account ID offline-decoded from a leaked key with no live validation; cloud-native endpoint pattern-matched via an owned CNAME/cert-SAN/subdomain FQDN; a container/K8s orchestration port is open (directly observed — its auth posture is not). |
| **CONFIRMED** | Bucket is publicly listable/readable **and** ownership-verified; AWS account ID corroborated by a live STS-validated key; dependency-confusion "strong" signal (private-registry binding) confirmed unclaimed via the public-registry 404 + scope-claimability check. |

An **unattributable** public bucket hit does not get a confidence label at all — it never
reaches the finding stream (§6.3).

---

## 3. Output Format

```
Finding:
  id:          <stable hash or UUID>
  module:      <technique that discovered it>
  asset_key:   <typed key, e.g. bucket:s3:acme-backup, account:aws:609629065308>
  category:    <PUBLIC_BUCKET | INFO_DISCLOSURE | TAKEOVER | DEPENDENCY_CONFUSION | MISCONFIG | OPEN_SERVICE | EXPOSED_PANEL>
  severity:    <info|low|medium|high|critical>
  confidence:  <tentative|firm|confirmed>
  title:       <one-line summary>
  description: <2-5 sentences — issue + attacker impact, not a terse restatement of the title>
  evidence:
    url:       <where found>
    timestamp: <UTC ISO8601>
    sha256:    <hash of any downloaded artifact — never an object body, see §5>
    raw:       <truncated to 2 KiB>
  references:  [<advisory URL, vendor doc>]
  remediation: <action the asset owner can take>
```

UTC timestamps everywhere.

---

## 4. Source Hygiene & Citations

URL + UTC timestamp + SHA-256 + tool version + run_id, every artifact. For bucket listings,
hash the **listing response** (the XML/JSON), never an object's contents — this skill never
fetches an object body (§5). For a decoded AWS account ID, cite the key string it was
derived from (redacted to first/last 4 chars in client-facing output) and the algorithm
version. For a dependency-confusion hit, cite both registry-check timestamps (the package
404 and, for scoped npm, the scope-ownership 404) — claimability is a point-in-time fact
that can flip the moment someone else registers the name.

---

## 5. Do NOT

- Do NOT fetch or download the contents of any object inside a bucket. Listing keys /
  sampling object names from the listing response is in scope (§6.3); retrieving an object's
  body is not — the reference implementation gates raw object reads behind `--validate`.
- Do NOT claim CRITICAL severity for a bucket, endpoint, or account hit that isn't
  ownership-verified. An unattributable public hit is not the client's risk — see the
  ownership-gated model, §6.3.
- Do NOT register, reserve, or publish a package name found unclaimed by the
  dependency-confusion check. Confirmation only — §8.7.
- Do NOT use a decoded/derived AWS account ID to call AWS APIs (`sts:AssumeRole`,
  `GetCallerIdentity`) against real infrastructure, with your own or the target's
  credentials. That reverse step needs the operator's own AWS credentials against a third
  party's account, is CloudTrail-logged on the target's side, and is out of this skill's
  scope entirely — describe the pivot value (§7.1), never perform it.
- Do NOT actively probe or authenticate against a fingerprinted Kubernetes API, etcd,
  kubelet, or Docker daemon endpoint to confirm its auth posture. Passive fingerprint only —
  live confirmation is a stage-6 `--validate --validate-cloud` active tier, out of scope.
- Do NOT single-source attribute a bucket/account/dependency/endpoint to the target — apply
  the rule of three (`osint-methodology` §2) or the explicit ownership signals in §6.3/§7.7/§9.1.

---

## 6. Storage Bucket Discovery — Candidate Generation, Existence vs. Listing, and the Ownership-Gated Severity Model

### 6.1 Two-class candidate generation

Two distinct expansion classes — mixing them either misses brand buckets or produces a
candidate storm (an unconstrained full-expansion-per-subdomain-stem approach measured at
~95k candidates on a large-subdomain target).

**Class A — trusted tokens** (apex root, the domain with dots replaced by hyphens, the
domain with dots stripped, and a sanitized `--company` token if supplied): full
prefix × suffix expansion.

**6 prefixes:** `""` (bare) `backup-` `assets-` `static-` `dev-` `prod-`

**15 suffixes:** `""` (bare) `-backup` `-assets` `-static` `-media` `-data` `-uploads`
`-dev` `-prod` `-staging` `-logs` `-private` `-public` `-dump` `-archive`

→ up to 90 candidates per trusted token.

**Class B — subdomain stems** (the first label of every discovered subdomain, excluding
`www`/`mail`/`ns1`/`ns2`): bounded and target-bound only —

- **Bare probe**, but only when the stem is distinctive: not in the broad (~90-entry)
  generic-stem filter (`api`, `admin`, `backup`, `dev`, `staging`, `mail`, `data`, `docs`,
  `internal`, `vault`, `secure`, `sandbox`, `preprod`, … — a stricter, larger list than the
  47-word variant in `offensive-osint` §16.8) and longer than 3 characters — **or** the stem
  already contains a trusted token.
- **Target-bound permutation only**: `{apex_root|company}-{stem}` and
  `{stem}-{apex_root|company}` (hyphen joiner, both orders).

No standalone prefix/suffix expansion is ever applied to a subdomain stem. Every candidate
must satisfy the bucket-name shape `^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$` (3–63 characters).

**Observed-name mining bypasses the filter entirely.** A bucket name mined from the target's
own DNS, certificate, or archived pages is near-certain to be theirs, so it's probed
regardless of the rules above:

- subdomain CNAME chains resolving to `*.s3(.<region>).amazonaws.com`,
  `*.storage.googleapis.com`, or `*.blob.core.windows.net`
- certificate SANs matching the same three host patterns
- archived (Wayback) URLs, path- or vhost-style, referencing an S3/GCS/Azure Blob host

### 6.2 Probe technique — existence vs. listing

One GET per candidate per provider — no separate HEAD, since the GET body is needed anyway
to classify listing:

| Provider | URL | Listing marker (200) | Exists, no listing | Not found |
|---|---|---|---|---|
| S3 | `GET https://{name}.s3.amazonaws.com/` | `<ListBucketResult` → **LISTABLE** | 200/301/307 (no marker) or 403 → exists (403 = private; parse `<Code>` for the deny reason) | `NoSuchBucket` (404) → absent |
| GCS | `GET https://storage.googleapis.com/{name}` | `<ListBucketResult` → **LISTABLE** | 403 → exists, private | 404 → absent |
| Azure Blob | `GET https://{name}.blob.core.windows.net/?comp=list` | `<EnumerationResults` → **LISTABLE** | 400/403 → account exists, private | 404 → absent |

S3 region redirects (301/307) are followed once before final classification. On a listable
hit, sample up to 200 object keys straight out of the listing body already returned
(`<Key>…</Key>` for S3/GCS, `<Blob><Name>…</Name>` for Azure) — never a second request per
object, never a fetch of an object's contents.

### 6.3 The ownership-gated severity model

This is the discipline that stops a permutation hit on a stranger's globally-registered
bucket from becoming a false CRITICAL — the exact class of false positive an earlier,
unconstrained version of this logic produced: unverified public/listable hits emitted at
MEDIUM/LOW severity were the documented source of a 171-finding false-positive flood before
this gate was added. (A related, separate incident — filing a merely-exists-but-private
403/400 bucket as a `PUBLIC_BUCKET` exposure — produced a "33 listable buckets" false read on
a fully-private estate; §6.2's reachability classification is what fixed that one.) Two
independent axes decide the outcome — **what's reachable** and **whether ownership is
verified** — and the outcome is **no finding at all**, not a downgraded severity, whenever
the second axis fails.

**Ownership verified** means at least one of:

- **name-tied** — the candidate name contains a trusted token (apex root / domain variant /
  `--company`)
- **observed** — the name was mined from the target's own CNAME, cert SAN, or archived URL
  (§6.1)
- **branded object key** — on a listable bucket, at least one returned object key itself
  names the target (checked after listing, so this can promote an otherwise-generic name)

| Reachability | Ownership unverified | Ownership verified |
|---|---|---|
| Listable (public listing) | **No finding.** Recorded as a `Bucket` asset only. | `PUBLIC_BUCKET`, **CRITICAL**, CONFIRMED |
| Public-read, not listable | **No finding.** Asset only. | `PUBLIC_BUCKET`, **MEDIUM**, CONFIRMED |
| Exists, access denied (403/400) | **No finding.** Asset only. | `INFO_DISCLOSURE`, **INFO**, FIRM |
| Not found (404) | Nothing — unless a live subdomain CNAME still points at the absent name (§6.4) | — |

The unverified rows are a deliberate **zero**, not a soft downgrade to LOW/INFO. A generic
permutation like `static-delivery` or `logs-archive` matches thousands of unrelated
companies' real, live buckets globally; surfacing every one as the client's finding is
exactly what this model exists to prevent. The candidate is still recorded as a graph asset
for correlation and re-probe on a future scan — it simply never enters the finding stream
unattributed.

**Object-key triage on a listable bucket** — classify the exposed keys into value tiers so
the write-up states *what* is exposed, not merely that listing is open. Pure filename-pattern
match over the listing already returned — no object body is ever fetched:

| Category | Severity tier | Pattern examples |
|---|---|---|
| Database dump | critical | `*.sql[.gz\|.bz2\|.zip]`, `*dump*`, `*-backup*`/`*_backup*`, `*.bak`, `*.mdb`, `*.sqlite[3]`, `*.dmp` |
| Credentials | critical | `.env*`, `id_rsa`, `id_ed25519`, `*.pem`, `*.p12`, `*.pfx`, `*.kdbx`, `*.ppk`, `*.jks`, `*credential*` |
| IaC state | critical | `*.tfstate[.backup]`, `terraform.tfvars` |
| Kubeconfig | critical | `*kubeconfig*`, `.kube/config` |
| VCS directory | high | `.git/`, `.svn/`, `.hg/` |
| Config | high | `config.yml`/`.json`, `settings.py`, `database.yml`, `wp-config.php`, `.npmrc`, `.dockercfg`, `appsettings*.json` |
| Archive | high | `*.zip`/`.tar`/`.tar.gz`/`.tgz`/`.7z`/`.rar` |
| PII | high | `employee`, `customer`, `passport`, `aadhar`/`aadhaar`, `ssn`, `salary`, `payroll`, `kyc` (substring match) |
| Logs | medium | `*.log`, `access[-_.]log`, `error[-_.]log`, `audit[-_.]log` |

Lead the finding title with the highest tier present (e.g. *"publicly listable — credentials
exposed"*) — that one line is what turns a generic bucket finding into something the client
acts on immediately.

### 6.4 Dangling-CNAME bucket takeover — a bonus lead, always in scope

A candidate that returns 404/`NoSuchBucket` but is still the live target of a subdomain's
CNAME is a **claimable takeover**, independent of the ownership-gating table above — the
live CNAME *is* the ownership evidence (a stranger's dangling bucket doesn't happen to have
the target's subdomain pointed at it). Detection only: never register the bucket to prove
it. Category `TAKEOVER`, **HIGH**, CONFIRMED — the 404-plus-dangling-CNAME combination is
unambiguous.

### 6.5 Recipes

**Probe (bash):**

```bash
NAME="acme-backup"
for url in \
  "https://${NAME}.s3.amazonaws.com/" \
  "https://storage.googleapis.com/${NAME}" \
  "https://${NAME}.blob.core.windows.net/?comp=list"; do
  echo "== $url =="
  curl -sk -m 8 -o /tmp/body.xml -w 'status=%{http_code}\n' "$url"
  grep -oE '<(ListBucketResult|EnumerationResults)|<Key>[^<]+</Key>|<Code>[A-Za-z]+</Code>' /tmp/body.xml | head -20
done
```

**Probe (PowerShell):**

```powershell
$Name = "acme-backup"
$Targets = @(
  "https://$Name.s3.amazonaws.com/",
  "https://storage.googleapis.com/$Name",
  "https://$Name.blob.core.windows.net/?comp=list"
)
foreach ($u in $Targets) {
  try {
    $r = Invoke-WebRequest -Uri $u -TimeoutSec 8 -SkipHttpErrorCheck   # -SkipHttpErrorCheck is PS7+; on PS 5.1 read $_.Exception.Response in the catch
    "{0,-70} status={1}" -f $u, $r.StatusCode
    if ($r.Content -match '<ListBucketResult|<EnumerationResults') {
      [regex]::Matches($r.Content, '<Key>([^<]+)</Key>|<Name>([^<]+)</Name>') |
        Select-Object -First 15 |
        ForEach-Object { $_.Groups[1].Value + $_.Groups[2].Value }
    }
  } catch { "$u -> error: $($_.Exception.Message)" }
}
```

**Candidate generation — apex + full prefix/suffix expansion (bash):**

```bash
APEX="acme"
PREFIXES=("" "backup-" "assets-" "static-" "dev-" "prod-")
SUFFIXES=("" "-backup" "-assets" "-static" "-media" "-data" "-uploads" "-dev" "-prod" "-staging" "-logs" "-private" "-public" "-dump" "-archive")
for p in "${PREFIXES[@]}"; do
  for s in "${SUFFIXES[@]}"; do
    echo "${p}${APEX}${s}"
  done
done
```

**Candidate generation (PowerShell):**

```powershell
$Apex = "acme"
$Prefixes = @("", "backup-", "assets-", "static-", "dev-", "prod-")
$Suffixes = @("", "-backup", "-assets", "-static", "-media", "-data", "-uploads", "-dev", "-prod", "-staging", "-logs", "-private", "-public", "-dump", "-archive")
foreach ($p in $Prefixes) { foreach ($s in $Suffixes) { "$p$Apex$s" } }
```

---

## 7. AWS Account-ID Recovery from a Leaked Access Key (Offline Decode)

Every AWS access key ID has the 12-digit owning account number encoded inside the key
string itself — recoverable by a deterministic base32 decode with **no secret key, no
network call, and no live AWS credential**. A single leaked `AKIA…`/`ASIA…`/`AROA…` string
already in hand — even one that's long dead or rotated — discloses the org's AWS account
number. This is genuinely offline OSINT (no authorization concern beyond already lawfully
holding the key, §1), and it's a real gap in the general arsenal: `offensive-osint` §22.7
covers ARN-regex extraction and `accountId` JSON-field scraping, but not this decode.

### 7.1 Why the account ID matters

- **Cross-account trust-policy abuse** — target trust policies that reference the account by
  number.
- **IAM role/principal enumeration** — an `sts:AssumeRole` error-message differential ("not
  authorized" vs. "does not exist") distinguishes real principals from guesses. This reverse
  step needs the *operator's own* AWS credentials against the target account and is
  intrusive/CloudTrail-logged on the target's side — **out of scope for this skill**,
  described here only.
- **Targeted IAM-role phishing** — a real account number lends legitimacy to a
  role-assumption pretext.

### 7.2 Key prefixes → entity type

The decode is identical across every prefix; the prefix only tells you which IAM entity type
the key belongs to.

| Prefix | Entity |
|---|---|
| `AKIA` | IAM user long-term access key |
| `ASIA` | Temporary (STS) credentials |
| `AROA` | IAM role |
| `AIDA` | IAM user |
| `AGPA` | IAM user group |
| `AIPA` | EC2 instance profile |
| `ANPA` | Managed policy |
| `ANVA` | Managed policy version |
| `ABIA` | AWS STS service bearer token |
| `ACCA` | Context-specific credential |

Shape: 4-character prefix + exactly 16 base32 characters (`A–Z`, `2–7`) = 20 characters total.

### 7.3 The algorithm

1. Uppercase the string; take the first 20 characters.
2. Confirm the first 4 characters are a valid prefix (§7.2) and the remaining 16 match
   `[A-Z2-7]{16}`.
3. Base32-decode those 16 characters → 10 raw bytes.
4. Take the first 6 bytes, interpret as a big-endian integer `z`.
5. `account = (z & 0x7FFFFFFFFF80) >> 7`
6. Zero-pad to 12 digits. If the result exceeds 999,999,999,999, the input wasn't really a
   key (reject).

Published by Aidan Steele / Tenable; reference implementation credit to A. Frichetten
([hackingthe.cloud](https://hackingthe.cloud/aws/enumeration/account_id_from_keys/)).

### 7.4 Runnable — stdlib-only Python

```python
#!/usr/bin/env python3
"""Offline AWS account-ID decode. No secret, no network, no live key needed.
Mirrors core/aws_account.py's account_id_from_access_key(). Stdlib only.

Usage:
  echo "ASIAY34FZKBOKMUTVV7A" | python3 aws_account_decode.py
  python3 aws_account_decode.py AKIA... ASIA...
  python3 aws_account_decode.py < file_with_keys.txt
"""
import base64
import re
import sys

_VALID_PREFIXES = {"AKIA", "ASIA", "AROA", "AIDA", "AGPA", "AIPA",
                    "ANPA", "ANVA", "ABIA", "ACCA"}
_KEY_RE = re.compile(r"\b(A[A-Z0-9]{3}[A-Z2-7]{16})\b")
_MASK = 0x7FFFFFFFFF80
_MAX_ACCOUNT = 999_999_999_999

# AWS documentation / reserved example account IDs — never report these as a
# real disclosure; they pervade IAM policy docs, Terraform tutorials, SDK samples.
EXAMPLE_ACCOUNT_IDS = {
    "123456789012", "111122223333", "222233334444", "333344445555",
    "444455556666", "555566667777", "666677778888", "777788889999",
    "888899990000", "999900001111", "012345678901", "000000000000",
    "123412341234", "101010101010",
}


def account_id_from_access_key(key: str):
    k = (key or "").strip().upper()[:20]
    if len(k) != 20 or k[:4] not in _VALID_PREFIXES:
        return None
    body = k[4:]
    if not re.fullmatch(r"[A-Z2-7]{16}", body):
        return None
    try:
        decoded = base64.b32decode(body)
    except Exception:
        return None
    z = int.from_bytes(decoded[:6], "big")
    account = (z & _MASK) >> 7
    if account > _MAX_ACCOUNT:
        return None
    return f"{account:012d}"


def main() -> int:
    text = " ".join(sys.argv[1:]) or sys.stdin.read()
    seen = set()
    for m in _KEY_RE.finditer(text):
        key = m.group(1)
        if key in seen:
            continue
        seen.add(key)
        acct = account_id_from_access_key(key)
        if acct is None:
            continue
        flag = " (AWS EXAMPLE ID -- not a real disclosure)" if acct in EXAMPLE_ACCOUNT_IDS else ""
        print(f"{key} -> {acct}{flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

### 7.5 Test vector

```
ASIAY34FZKBOKMUTVV7A -> 609629065308
```

Verify any reimplementation against this before trusting its output.

### 7.6 Example-account screening

Screen every decoded (and every ARN-extracted) account ID against the 14 documented AWS
example account IDs above — `123456789012` chief among them, present in nearly every AWS IAM
policy doc, Terraform tutorial, and SDK sample. Skip this check and a plain documentation
page in the response corpus mints a false "owned AWS account" finding.

Two complementary offline extraction paths, in addition to the decode:

- **ARN regex** (any JSON/HTML/JS body): `arn:aws[a-z0-9\-]*:[a-z0-9\-]*:[a-z0-9\-]*:(\d{12}):`
- **AWS-qualified `accountId` field only** — deliberately requires the `aws` qualifier
  (`aws[_-]?account[_-]?id`), never a bare `"accountId":"…"`, since a bare field is just as
  likely an internal billing/customer record that happens to be 12 digits.

### 7.7 Ownership + severity/confidence

Decode every access key found in the corpus, plus pull account IDs from ARNs and
AWS-qualified `accountId` fields. Ownership is structural, not scored:

| Disclosure path | Ownership | Severity | Confidence |
|---|---|---|---|
| Key/ARN found on an in-scope host (the subdomain equals the target, or is a subdomain of it) | **Owned** | MEDIUM | FIRM |
| Key/ARN found on an out-of-scope/third-party host that merely references the account | **Referenced** | INFO | FIRM |
| Either of the above, additionally corroborated by a live STS-validated key (read-only `GetCallerIdentity`, `offensive-osint` §23.2) | Owned | MEDIUM | **CONFIRMED** |

Every leaking page emits a `DISCLOSES_ACCOUNT` edge to the account it references — for **owned and
referenced accounts alike**. An **owned** account additionally earns an `OWNED_BY`-target edge — a
legitimate attack-path pivot. A **referenced-only** account has just the `DISCLOSES_ACCOUNT` edge and
is never treated as the org's own escalation target — it's a third party's account, though still
worth recording.

Note the deliberate severity ceiling: MEDIUM even for an owned account, because the finding
itself is "your account number is now public" — real but modest on its own (rotate the leaked
key; the number can't be un-disclosed). Severity escalates only through what an attacker
*does* with the number next (§7.1), which this skill does not perform.

---

## 8. Dependency Confusion — Internal Signal + Public-Registry Unclaimed Confirmation

`offensive-osint` §44 covers registry search and secret hunting *inside* packages the target
published. This is the opposite direction: what does the target's own manifests
*reference*? A dependency name that carries an internal signal and is unclaimed on the
public registry is a name an attacker can register today and have pulled into the target's
build the next time a resolver falls back to the public index.

### 8.1 Manifest mining (read the target's own captured corpus — never re-fetch for this)

| File | What it yields |
|---|---|
| `package.json` (`dependencies`/`devDependencies`/`peerDependencies`/`optionalDependencies`) | npm package names |
| `package-lock.json` (v1 nested `dependencies`; v2/v3 `packages` keyed by `node_modules/…`) | npm package names — richest source, includes transitive/scoped deps |
| `.npmrc` | `{scope}:registry=` bindings + a bare default `registry=` — the **private-registry signal** |
| `requirements.txt` | PyPI names + `--index-url`/`--extra-index-url`; screens out `-e`/local-path/`git+`/direct-URL deps (never a confusion vector) |
| `pyproject.toml` | PEP 621 `project.dependencies` + Poetry `tool.poetry.dependencies`/`group.*.dependencies`, plus `[[tool.poetry.source]]` private-index URLs; a Poetry dep carrying an explicit `git`/`url`/`path`/`file` key is direct-source and screened out |
| `pip.conf` / `pip.ini` | `index-url`/`extra-index-url` → private pip index signal |
| Any `.js`/`.mjs`/`.cjs`/`.map` body | scoped npm specifiers (`@scope/name`) referenced in bundled/sourcemap code |

### 8.2 The internal-signal classifier (zero I/O — pure text logic)

A dependency name is a candidate only when it carries one of these signals:

| Ecosystem | Signal | Strength |
|---|---|---|
| npm, scoped (`@scope/pkg`) | the scope is bound to a private registry in `.npmrc` | **strong** |
| npm, scoped or unscoped | `.npmrc` sets a private *default* registry | **strong** |
| npm, scoped or unscoped | package name/scope matches an org-namespace token (≥4 chars, not a generic corporate word — `corp`, `solutions`, `technologies`, `holdings`, …) | medium |
| PyPI | a private index (`--index-url` / Poetry source / `pip.conf`) is configured anywhere in the corpus | **strong** |
| PyPI | package name matches an org-namespace token | medium |

Org-namespace tokens come from the target's **registrable brand label** — never the leftmost
DNS label; a target reached via `staging.acme.com` yields the token `acme`, never `staging`
— plus any `ORG`-typed asset already in the graph. A bare unscoped name with no
private-registry binding and no namespace match carries no signal — indistinguishable from a
typo or a yanked release — and is dropped, never emitted as a candidate.

### 8.3 The two-part confirmation contract — neither half alone is a finding

An internal signal alone is not proof the name is available — plenty of internal packages
are also correctly published privately-but-globally-unique. A public-registry 404 alone is
meaningless — a typo, an unpublished/yanked version, or a local-only dep all 404 too.
**Both** must hold:

1. **Internal signal** (§8.2) — screens out ordinary public dependencies and unknown bare names.
2. **Public-registry existence check returns 404** — a read-only GET against the real
   `registry.npmjs.org` / `pypi.org`, never the target. This is exactly why it's in scope
   under the pack's "public-registry 404 checks" line even though it's a live network call:
   the traffic lands entirely on a third-party public registry, zero packets to the client.

Fail **closed** on any ambiguity — a 200 (published), 403, 5xx, or timeout never emits a
finding. Uncertainty is not evidence of claimability.

### 8.4 npm scope claimability — the nuance a bare-package check misses

For a scoped name (`@scope/pkg`), the package 404ing isn't the interesting fact — the whole
**scope** must be unclaimed for the name to be squattable. Check the scope's org and user
profile pages, not the public search API:

```
GET https://www.npmjs.com/org/{scope}    -> 200 = scope owned as an org
GET https://www.npmjs.com/~{scope}       -> 200 = scope owned as a user
```

The name is registerable only if **both** 404. The npm *search* API is deliberately not used
for this: it returns `total:0` for a scope that is privately owned but hosts no public
packages, which would falsely read as "unclaimed." The org/user profile pages return a real
404 only when the scope genuinely doesn't exist, regardless of what it might privately host.

### 8.5 Severity / confidence

| Signal strength | Severity | Confidence |
|---|---|---|
| strong (private-registry binding) | **HIGH** | FIRM |
| medium (org-namespace match only) | MEDIUM | **TENTATIVE** — namespace matching alone is namesake-prone |

Never CONFIRMED — this is static manifest analysis over a captured corpus, not a live
resolver-fallback observation. There is no "the build actually pulled the malicious package"
event to point at.

### 8.6 Recipes

**bash:**

```bash
# unscoped npm
curl -sk -m 15 -o /dev/null -w '%{http_code}\n' "https://registry.npmjs.org/acme-internal-utils"
# scoped npm -- package + both scope-ownership pages
curl -sk -m 15 -o /dev/null -w '%{http_code}\n' "https://registry.npmjs.org/@acme%2Fdesign-system"
curl -sk -m 15 -o /dev/null -w '%{http_code}\n' "https://www.npmjs.com/org/acme"
curl -sk -m 15 -o /dev/null -w '%{http_code}\n' "https://www.npmjs.com/~acme"
# PyPI
curl -sk -m 15 -o /dev/null -w '%{http_code}\n' "https://pypi.org/pypi/acme-internal-tools/json"
```

**PowerShell:**

```powershell
function Test-RegistryStatus {
  param([string]$Url)
  try {
    $r = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 15 -SkipHttpErrorCheck   # PS7+; on PS 5.1 read $_.Exception.Response in the catch
    return $r.StatusCode
  } catch { return "error" }
}
Test-RegistryStatus "https://registry.npmjs.org/acme-internal-utils"
Test-RegistryStatus "https://www.npmjs.com/org/acme"
Test-RegistryStatus "https://www.npmjs.com/~acme"
Test-RegistryStatus "https://pypi.org/pypi/acme-internal-tools/json"
```

Bound the check volume — filter to internal-signalled candidates *before* hitting the
registry (hundreds, not thousands, per engagement) and cache scope-ownership lookups (one
org/user check per distinct scope, never per package under that scope).

### 8.7 Out of scope

Reserving the name — publishing a stub the org controls — is a remediation the **client**
performs, not a step this skill takes. This skill's ceiling is: *"this name is
internal-signalled and currently unclaimed."* Confirming that a live resolver fallback
actually pulls a planted package, or registering anything under the discovered name, is
active supply-chain interference and out of scope regardless of authorization — hand it to
the client as the remediation action (§8.5 evidence + §10 business translation).

---

## 9. Cloud-Native & Container/K8s/CI Control-Plane Fingerprinting — an Org-Attribution Surface

Modern infrastructure increasingly *is* the org-attribution signal: a Lambda Function URL, a
`*.run.app` Cloud Run service, or an exposed kubelet is both an exposure and a fingerprint of
which cloud account/cluster belongs to the target. Everything in this section is **passive**
— pattern-matching over hostnames and ports already resolved by earlier recon, zero new
network calls of this skill's own. `offensive-osint` §16.17–§16.19 carries the fuller
URL-pattern and active-probe tables (20 cloud-native providers, the full container-registry
search list, 11 CI/CD platforms with active curl recipes); this section is the reasoning
layer that decides what a hit is *worth* and whether it's the target's.

### 9.1 Cloud-native endpoint fingerprint

Match already-resolved hostnames — subdomain CNAME targets, certificate SANs, subdomain
FQDNs themselves, and webapp URLs — against provider URL patterns:

| Provider | Pattern | Service |
|---|---|---|
| AWS | `*.execute-api.<region>.amazonaws.com` | API Gateway |
| AWS | `*.lambda-url.<region>.on.aws` | Lambda Function URL |
| AWS | `*.<region>.elasticbeanstalk.com` | Elastic Beanstalk |
| Azure | `*.azurewebsites.net` | App Service |
| Azure | `*.azurecontainerapps.io` | Container Apps |
| Azure | `*.file\|queue\|table.core.windows.net` | Storage (Blob object storage is handled by bucket discovery, §6 — not duplicated here) |
| GCP | `*.run.app` | Cloud Run |
| GCP | `*.appspot.com` | App Engine |
| GCP | `*.cloudfunctions.net` | Cloud Function |

(`offensive-osint` §16.17 extends this to 20 providers — App Runner, CloudFront, ALB/ELB,
Amplify, Static Web Apps, Vercel, Netlify, Cloudflare Workers/Pages, Heroku, Render, Fly.io,
Railway, DigitalOcean App Platform.)

**Ownership gating is structural, not scored** — the same discipline as §6.3's bucket model,
applied to endpoints:

| Provenance of the match | Ownership |
|---|---|
| A subdomain CNAME points at the pattern | **Owned** |
| A certificate SAN names the pattern | **Owned** |
| The subdomain's own FQDN matches the pattern (it *is* the cloud-native host) | **Owned** |
| A webapp URL matches the pattern with no independent tie to the target from the above | Unverified |

Owned → **MEDIUM**/FIRM. Unverified (a bare pattern match with no corroborating tie) →
**LOW**/TENTATIVE. Confirming whether the endpoint is actually invocable without
authentication is the stage-6 `--validate --validate-cloud` step — out of scope; this
section only says "this cloud-native surface exists and appears to belong to the target,"
never "it's exploitable."

### 9.2 Container / Kubernetes control-plane exposure — passive flag, not active probe

Rather than issuing new probes, treat orchestration control-plane ports **already discovered**
by port/service enumeration as a likely-exposed control plane. All five carry **HIGH**
severity, FIRM confidence once flagged — the port being open is directly observed; the auth
posture behind it is not, which is exactly why confirmation is gated separately:

| Port | Service | Why it matters if unauthenticated |
|---|---|---|
| 2375 | Docker API (plain HTTP, no TLS) | Anyone who reaches it controls the daemon — launch a host-mounting container, escape to root on the host. |
| 2376 | Docker API (TLS) | Equivalent to 2375 unless client-cert auth is strictly enforced. |
| 2379 | etcd client API | Holds the entire cluster state — every Secret, in plaintext. Read = full credential harvest; write = cluster tampering. |
| 6443 | Kubernetes API server | The cluster's control plane — a valid token, leaked kubeconfig, or anonymous-auth misconfig creates privileged pods and reads every Secret. |
| 10250 | kubelet | No auth required = pod exec on the node. |

(`offensive-osint` §16.18 has the fuller table — kube-proxy/controller-manager/scheduler
health/metrics endpoints, cAdvisor, Helm Tiller — plus the active curl recipe for each and
the public-container-registry search list across Docker Hub/Quay/GHCR/ECR Public.)

The port being open says nothing about its auth posture. Flag it; do not connect to it to
find out. A live GET/HEAD against the endpoint to confirm whether it answers unauthenticated
is exactly the line this skill stops at.

### 9.3 CI/CD platform surface

Fingerprint from tech strings already collected by passive web/HTTP enumeration — Jenkins,
GitLab (self-hosted), Argo CD, Harbor, TeamCity, Drone. **MEDIUM**/TENTATIVE — a tech-string
match is a weaker signal than a resolved hostname pattern, hence TENTATIVE rather than FIRM.
A CI/CD console or API, when reachable unauthenticated, exposes build pipelines, stored
credentials, and artifact registries — a supply-chain foothold. `offensive-osint` §16.19 has
the per-platform active probe paths (`/script`, `/api/v4/version`, `/gate/info`, …) and the
GitHub Actions secret-leak anti-pattern catalog (workflows that echo `${{ secrets.* }}` to
logs, or check out fork-PR code under `pull_request_target`) for an operator who chooses to
go further under their own authority.

### 9.4 What's out of scope here

Any GET/HEAD issued specifically to confirm a fingerprinted cloud-native endpoint or
control-plane port is reachable/unauthenticated is a stage-6
`--validate --validate-cloud` active tier — hard-gated behind explicit `--validate` plus per-target
scope confirmation, default OFF. This skill's ceiling is the passive fingerprint and the
"likely exposed, auth posture unconfirmed" flag; describe the confirmation step, never
perform it.

---

## 10. Severity & Business Translation

| Technical finding | Business language | Severity |
|---|---|---|
| Publicly listable bucket, ownership-verified, credentials/db-dump objects present | Customer/internal data — including live credentials — is downloadable by anyone on the internet right now. | CRITICAL |
| Same listable bucket, but the name can't be tied to the client | Someone's bucket is open; not provably this client's exposure. Logged for the graph, not reported as their risk. | No finding (§6.3) |
| AWS account ID recovered from a dead/rotated key, owned host | The org's cloud account number is now public. Not itself a breach, but every cross-account trust policy referencing that number needs review. | MEDIUM |
| Dependency-confusion vector, strong signal (private-registry binding), unclaimed on npm | An attacker can publish a package under this exact internal name today; the next CI run with a misconfigured registry fallback pulls it and runs arbitrary code in the build. | HIGH |
| Cloud-native endpoint (Lambda URL / Cloud Run), owned, auth posture unconfirmed | A managed-service endpoint is reachable; whether it's invocable without authentication is not yet proven — an open question requiring confirmation, not an assumed breach. | MEDIUM |
| Kubernetes API / etcd / kubelet port open, passively flagged | The cluster's control plane appears internet-reachable; authentication enforcement is unconfirmed. If it isn't enforced, this is a path to full cluster compromise. | HIGH (unconfirmed auth) |

---

## 11. Skill Self-Test

Drop these into a fresh session to verify the skill loads and routes correctly.

1. *"Generate S3/GCS/Azure bucket candidates for `acme.com` with subdomains api/billing/hr and probe them."* → §6.1–§6.2, §6.5.
2. *"We found a listable S3 bucket named `marketplace-media` from a permutation guess — can't tie it to the client. Is that CRITICAL?"* → **negative.** §6.3 — no; an unverified public/listable hit produces **no finding at all** (not even INFO); it's recorded as an asset only.
3. *"Same bucket, but its object listing includes `acme-employee-payroll.csv`."* → §6.3 branded-object-key ownership signal — now verified, promote to CRITICAL.
4. *"What's exposed inside a listable bucket, without downloading any object?"* → §6.3 object-key triage table (filename-pattern classification of the listing body only).
5. *"A subdomain has a live CNAME to a bucket that returns 404 NoSuchBucket. What's the finding?"* → §6.4 — dangling-CNAME takeover, HIGH, CONFIRMED, independent of the ownership-gating table.
6. *"Decode the AWS account ID from `ASIAY34FZKBOKMUTVV7A`."* → §7.3–§7.5, test vector `609629065308`.
7. *"We found `123456789012` as an `accountId` in a Terraform snippet on the target's site. Real disclosure?"* → §7.6 — no; that's a documented AWS example account ID, screen it out.
8. *"Should I use the decoded account ID to enumerate IAM roles via `sts:AssumeRole`?"* → **negative.** §7.1/§5 — out of scope; needs the operator's own AWS credentials against the target account and is CloudTrail-logged; describe the pivot value, don't perform it.
9. *"`package.json` references `@acme/design-system`, and `.npmrc` binds `@acme` to a private registry. Is that a finding by itself?"* → §8.2–§8.3 — internal signal only; still needs the public-registry 404 (and scope-claimability, §8.4) check before it's a finding.
10. *"npm's public search API returns `total:0` for `@acme`. Is the scope claimable?"* → §8.4 — no; the search API is blind to privately-owned scopes. Use the org/user profile-page 404 check instead.
11. *"Confirmed unclaimed dependency-confusion vector. Should we reserve the package name to protect the client?"* → **negative.** §8.7 — out of scope; that's a client remediation action, not this skill's step.
12. *"A subdomain CNAMEs to `*.run.app`. Is that Cloud Run endpoint owned or unverified?"* → §9.1 — CNAME provenance = owned.
13. *"Port 6443 is open per a prior port scan. What do I do next?"* → §9.2/§9.4 — flag as a likely-exposed Kubernetes API control plane (passive, HIGH/FIRM); do **not** curl `/api` to confirm auth posture — that's stage-6 `--validate --validate-cloud`.
14. *"Write the business-translation line for a HIGH-signal dependency-confusion finding."* → §10.

---

## 12. Changelog

- **v1.0 (2026-08-06)** — initial release. Reproduces exact logic from the
  reference implementation: `modules/cloud_buckets.py` (two-class candidate generation,
  HEAD/GET→listing probe technique, the ownership-gated severity model, 9-tier object-key
  triage, dangling-CNAME takeover), `core/aws_account.py` + `modules/aws_account_enum.py`
  (offline AKIA/ASIA/AROA→account-ID base32 decode, canonical test vector, AWS
  documentation-example-ID screening, ownership/severity/confidence mapping),
  `core/dep_confusion.py` + `modules/dependency_confusion.py` (manifest mining across 7 file
  types, the internal-signal classifier, the two-part confirmation contract, the npm
  scope-claimability nuance), and `modules/cloud_exposure.py` (cloud-native endpoint
  fingerprint with structural ownership gating, passive container/K8s/CI exposure flags).
  Deepens `offensive-osint` §16.8/§16.17–16.19/§44 rather than duplicating their wordlists.
