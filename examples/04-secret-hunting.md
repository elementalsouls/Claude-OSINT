# Example 04: Leaked-Credential Workflow

> Engagement type: external red-team OR bug-bounty research
> Time budget: 1–2 hours per credential found
> Authorization: in-scope target + ROE-permitted read-only validation
> Target: `acme.example`

End-to-end walk-through from secret discovery → validation → scope enumeration → disclosure.

---

## Step 1: Discovery

Several techniques surface credentials:

**A. GitHub code search (companion `offensive-osint` §19):**

```bash
T="acme.example"          # full domain
TS="acme"                 # stem

# Run all 13 dorks
for q in "filename:.env" "filename:.env.example" "filename:config" \
         "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "password" \
         "api_key" "secret" 'authorization: Bearer' \
         "filename:id_rsa" "filename:.git-credentials" "filename:wp-config.php"; do
  echo "=== ${TS} ${q} ==="
  curl -sk -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/code?q=${TS}+${q// /+}&per_page=20" \
    | jq -r '.items[] | .html_url'
done
```

**B. JS deep scan (`osint-methodology` §13 + companion `offensive-osint` §17):**

```bash
# Pull every JS from app.acme.example and scan
for js in $(curl -sk https://app.acme.example/ | grep -oE 'src="[^"]*\.js"' | tr -d '"' | sed 's/src=//'); do
  curl -sk "https://app.acme.example/${js}" | python3 scripts/secret_scan.py | head -50
done
```

**C. Sourcemap leak:**

```bash
# Test for .js.map alongside each found .js
for js in $(echo $JS_LIST); do
  MAP_URL="${js}.map"
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "$MAP_URL")
  [ "$STATUS" = "200" ] && echo "SOURCEMAP: $MAP_URL"
done
```

If sourcemap exists, parse `sourcesContent[]` and run secret-scan over each.

**D. Postman public workspace search (companion §24):**

```bash
curl -sk "https://www.postman.com/_api/ws/proxy" \
  -H 'Content-Type: application/json' \
  -d "{\"service\":\"search\",\"method\":\"POST\",\"path\":\"/search-all\",\"body\":{\"queryIndices\":[\"collaboration.workspace\",\"runtime.collection\",\"runtime.request\"],\"queryText\":\"${T}\",\"size\":100,\"from\":0,\"clientTraceId\":\"\",\"queryAllIndices\":false,\"domain\":\"public\"}}" | jq .
```

Then walk each matching workspace; extract requests + env vars; run secret-scan.

---

## Step 2: Initial classification

You found: `AKIAIOSFODNN7EXAMPLE` paired with a 40-char secret in a public GitHub gist.

**Prompt:**

> Found AKIAIOSFODNN7EXAMPLE + secret in a public GitHub gist. What's the classification?

**Claude pulls:** `offensive-osint` §17 (catalog row 1 — AWS_ACCESS_KEY) + `osint-methodology` §6.3 (validator discipline).

**Classification:**
- Pattern: AWS Access Key → severity **CRITICAL** (per catalog).
- Confidence: **FIRM** (matches catalog regex; not yet validated).
- Detectability of validation: **medium** (CloudTrail logs).

---

## Step 3: Read-only validation

**Prompt:**

> Validate the AWS key read-only. ROE permits validation but not exploitation.

**Claude pulls:** `offensive-osint` §23.2 (AWS validator) + `osint-methodology` §6.3 (validator discipline).

**Run:**

```python
import boto3

# READ-ONLY: sts:GetCallerIdentity confirms the key without using any service
sts = boto3.client(
    'sts',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='<the-paired-40-char-secret>',
    region_name='us-east-1'
)

try:
    ident = sts.get_caller_identity()
    print(f"VALID")
    print(f"Account: {ident['Account']}")
    print(f"ARN:     {ident['Arn']}")
    print(f"UserId:  {ident['UserId']}")
except Exception as e:
    print(f"INVALID or expired: {type(e).__name__}: {e}")
```

**Expected output (valid key):**
```
VALID
Account: 123456789012
ARN:     arn:aws:iam::123456789012:user/deploy-bot
UserId:  AIDAEXAMPLE12345
```

**ARN scope reading:**
- `arn:aws:iam::*:user/...` → IAM user (broad scope possible).
- `arn:aws:sts::*:assumed-role/...` → temp role (narrower scope).
- `arn:aws:iam::*:root` → **DO NOT VALIDATE** root keys without explicit operator approval. Mark as `validation_skipped_by_policy` and consult.

**Tag the validation:**
- `status: verified_live`
- `provider: aws`
- `account_id: 123456789012`
- `arn: arn:aws:iam::123456789012:user/deploy-bot`
- `detectability: medium`
- `checked_at: 2026-04-27T15:42:00Z`

---

## Step 4: Confirm ownership

Account ID `123456789012` — does it belong to your target?

**Prompt:**

> AWS account 123456789012 returned. Confirm it belongs to acme.example.

**Claude pulls:** `osint-methodology` §11.8 + `offensive-osint` §22.7 (AWS account-ID extraction).

**Cross-reference:**
- HEAD known target S3 buckets — does `x-amz-bucket-region` correlate with this account's likely region?
- Search for the account ID in target's public docs / GitHub / docs subdomains: `"123456789012"` site:acme.example
- Check known SaaS-vendor public account-ID lists (some vendors publish theirs).

If the account ID matches a known target asset → **ownership CONFIRMED**.
If ambiguous → mark TENTATIVE and document the uncertainty in the finding.

---

## Step 5: Read-only IAM enumeration

**Prompt:**

> Confirmed AWS account belongs to target. ROE permits read-only enum. Walk me through.

**Claude pulls:** `offensive-osint` §23.12 (post-discovery enumeration workflows — AWS).

**Run:**

```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="<secret>"

# Already done in step 3
aws sts get-caller-identity

# IAM user details (only if ARN was :user/)
USER=$(aws sts get-caller-identity --query 'Arn' --output text | awk -F'/' '{print $NF}')
aws iam get-user --user-name "$USER"

# Attached + inline policies
aws iam list-attached-user-policies --user-name "$USER"
aws iam list-user-policies --user-name "$USER"
aws iam list-groups-for-user --user-name "$USER"

# What can I actually do? (simulate-principal-policy for common dangerous actions)
ARN=$(aws sts get-caller-identity --query 'Arn' --output text)
aws iam simulate-principal-policy \
  --policy-source-arn "$ARN" \
  --action-names s3:ListAllMyBuckets ec2:DescribeInstances iam:ListUsers \
                 secretsmanager:ListSecrets ssm:DescribeParameters \
                 lambda:ListFunctions rds:DescribeDBInstances

# Read-only enum on services where we have access (DO NOT WRITE)
aws s3 ls
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,Tags[?Key==`Name`].Value|[0]]' --output table
aws secretsmanager list-secrets --query 'SecretList[*].[Name,Description]' --output table
aws ssm describe-parameters --query 'Parameters[*].Name'
aws lambda list-functions --query 'Functions[*].FunctionName'
aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'

# Posture check — is MFA enforced?
aws iam list-mfa-devices --user-name "$USER"
aws iam get-account-summary | jq '.SummaryMap.AccountMFAEnabled'

# Logging check
aws cloudtrail describe-trails
```

**Document each command + output. Don't run anything destructive.**

---

## Step 6: Severity assessment

Score the finding using `offensive-osint` §40 + impact context:

- **Validated live AWS IAM-user key in public GitHub repo.** Per §40: HIGH base.
- **Scope: deploy-bot user with attached ManagedDevOpsPolicy** (via `iam:ListAttachedUserPolicies`) → likely write access to S3, Lambda, ECR, CodeBuild → **CRITICAL** (escalated).
- **MFA not enforced on user** → CRITICAL holds.

**Final severity: CRITICAL.**

---

## Step 7: Write the finding

**Prompt:**

> Write the per-finding report card.

**Claude pulls:** `osint-methodology` §31.2 (per-finding template).

```
═══════════════════════════════════════════════════════════
FINDING #1: Live AWS access key for IAM user `deploy-bot` exposed in public GitHub gist
SEVERITY: CRITICAL
CONFIDENCE: CONFIRMED
ASSET: aws_account:123456789012 / iam_user:deploy-bot
DISCOVERED: 2026-04-27T15:30:00Z
═══════════════════════════════════════════════════════════

DESCRIPTION
A long-lived AWS access key for IAM user `deploy-bot` in account 123456789012
(target's production AWS) was found in a public GitHub gist authored by what
appears to be a target employee (gist URL omitted in this template; see Evidence).
The key is currently valid and grants write access to S3, Lambda, ECR, and
CodeBuild via the attached ManagedDevOpsPolicy. MFA is not enforced on the
user. This represents an immediate path to full DevOps-tier compromise of
the target's AWS environment.

EVIDENCE
- Gist URL:        [redacted; provided to engagement lead privately]
- Discovered via:  GitHub code-search dork `"acme" filename:.env`
- Validation:      sts:GetCallerIdentity returned valid response at 2026-04-27T15:42:00Z
- Hash (SHA-256):  <of the .env file contents>
- Detectability:   medium (CloudTrail logs the validation event)

REPRODUCTION
Step 1: Visit https://gist.github.com/<redacted>
  Expected: page returns 200
Step 2: Extract `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from the .env block.
Step 3: Run `aws sts get-caller-identity` with extracted credentials.
  Expected: returns Account 123456789012, ARN arn:aws:iam::123456789012:user/deploy-bot
Step 4: Run `aws iam list-attached-user-policies --user-name deploy-bot`
  Expected: returns `ManagedDevOpsPolicy`
(Reproduction steps available in private operator-only annex; not in client report.)

IMPACT
Full DevOps-tier compromise of acme.example's production AWS account. Attacker
can: deploy malicious Lambda functions, exfiltrate any S3 data the policy
permits, push tampered container images to ECR (supply-chain compromise of
deployment pipeline), modify CodeBuild jobs (CI compromise). Combined with
absent MFA, no out-of-band confirmation prevents this.

REMEDIATION
Immediate (within hours):
  - Rotate the exposed access key (AWS console: IAM → Users → deploy-bot → Security credentials → Make Inactive, then Delete).
  - Audit CloudTrail for unauthorized API calls between key-leak time and rotation time.
Short-term (within days):
  - Remove the gist or take it down via GitHub abuse process.
  - Enforce MFA on all IAM users with write permissions.
  - Review the ManagedDevOpsPolicy for over-broad permissions.
Long-term (within weeks):
  - Migrate from long-lived IAM-user keys to short-lived role-assumption (e.g., aws-vault, OIDC federation from CI).
  - Enable AWS GuardDuty if not already.
  - Set up CloudTrail alerts for `iam:CreateAccessKey` events.

REFERENCES
  - AWS IAM best practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
  - GitHub secret scanning partner program: https://docs.github.com/en/code-security/secret-scanning

ATTACK PATH HINT
Validated AWS IAM-user key with DevOps-tier scope — pivot via Lambda function
deployment OR S3 data exfil OR ECR image tampering for supply-chain compromise.
Post-rotation, search target's CI/CD logs for the same key pattern (rotation
might miss other leak locations).
```

---

## Step 8: Disclosure

**Path A — bug-bounty program in scope:**
- Submit to the program (HackerOne / Bugcrowd / etc.) using `osint-methodology` §30.2 report structure.
- Severity: per program's CVSS-mapping (likely CRITICAL).

**Path B — no program but ROE includes responsible disclosure:**
- Notify target's security@ (or use security.txt contact).
- Cc AWS abuse: `aws-security@amazon.com` (AWS will partner-revoke the key via their secret-scanning program; usually faster than waiting for the customer).
- For GitHub-hosted gist: report via `https://github.com/contact` (abuse) — GitHub auto-revokes most published AWS keys via their partner program.

**Documentation:**
- Engagement-private annex includes the gist URL + secret values (encrypted at rest).
- Client-facing report redacts secret values (last 4 chars only); references the annex.

---

## Step 9: Post-disclosure

- Wait for confirmation of rotation + acknowledgment from program.
- Do not re-validate after rotation (creates noise).
- If the gist isn't taken down within 7 days, escalate.
- Add to lessons-learned: which dork found it? Could the dork find similar leaks?

---

## Citation

This example follows:
- `osint-methodology` §6.3 (validator discipline)
- `osint-methodology` §11.8 (AWS account-ID extraction)
- `osint-methodology` §22 (breach × identity correlation)
- `osint-methodology` §28.3 (validation discipline)
- `osint-methodology` §30.5 (cloud provider disclosure channels)
- `osint-methodology` §31.2 (per-finding report card)
- `offensive-osint` §17 row 1 (AWS_ACCESS_KEY pattern)
- `offensive-osint` §19 (GitHub code-search dorks)
- `offensive-osint` §23.2 (AWS validator)
- `offensive-osint` §23.12 (post-discovery AWS enumeration)
- `offensive-osint` §40 (severity matrix — live AWS IAM-user key)
- `offensive-osint` §39 (attack-path hints — live AI/cloud key)
