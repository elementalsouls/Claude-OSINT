# `cloud-saas-exposure` skill

The "is this actually the client's cloud risk" layer — bucket discovery with an
ownership-gated severity model, offline AWS-account-ID recovery from a leaked access key,
dependency-confusion confirmation for npm/PyPI, and passive cloud-native/container/K8s/CI
control-plane fingerprinting.

| Field | Value |
|---|---|
| Name | `cloud-saas-exposure` |
| Version | 1.0 |
| Lines | ~800 |
| Top-level sections | 13 (§0–§12) |
| Companion skills | [`osint-methodology`](../osint-methodology/) (the pipeline this plugs into), [`offensive-osint`](../offensive-osint/) §16.8/§16.17–16.19/§44 (the raw wordlists this skill deepens, not duplicates) |

## When this skill triggers

Auto-triggers on prompts containing any of ~55 trigger phrases. Common ones:

- `cloud attack surface`, `cloud exposure`, `SaaS exposure`, `cloud footprint`
- `S3 bucket enum`, `GCS bucket enum`, `Azure blob enum`, `bucket permutation`, `bucket takeover`, `dangling CNAME bucket`, `public cloud bucket`, `listable bucket`
- `AWS account ID`, `AKIA decode`, `offline AWS decode`, `base32 AWS account`, `AWS account enumeration`, `cross-account trust`, `sts assume role`
- `dependency confusion`, `npm dependency confusion`, `PyPI dependency confusion`, `supply chain attack surface`, `unclaimed package`, `npm scope claimability`, `private npm registry`
- `cloud native fingerprint`, `Lambda function URL`, `Cloud Run exposure`, `App Service exposure`, `serverless exposure`
- `Kubernetes exposure`, `K8s exposure`, `kubelet exposure`, `etcd exposure`, `Docker API exposure`, `control plane exposure`
- `CI CD exposure`, `Jenkins exposure`, `GitLab exposure`
- `cloud account attribution`, `org attribution cloud`

Full trigger list in the SKILL.md frontmatter.

## What's in it

- **§6 — Storage bucket discovery.** The two-class candidate-generation split (full
  prefix × suffix expansion on trusted brand tokens vs. bounded target-bound permutation on
  subdomain stems — the fix for a documented ~95k-candidate storm), the HEAD/GET-vs-listing
  probe technique across S3/GCS/Azure, the 9-tier object-key triage (database dumps,
  credentials, IaC state, kubeconfig, VCS dirs, config, archives, PII, logs), dangling-CNAME
  bucket takeover, and **the ownership-gated severity model** — the core of this section: an
  unattributable public/listable bucket gets **no finding at all**, not a downgraded
  severity, closing off a documented 171-phantom-finding false-positive class.
- **§7 — Offline AWS account-ID recovery.** The full base32-decode walkthrough from a leaked
  `AKIA`/`ASIA`/`AROA` access key ID (works even on a dead/rotated key, zero network, zero
  secret needed), a runnable stdlib-only Python implementation, the canonical test vector
  (`ASIAY34FZKBOKMUTVV7A` → `609629065308`), the 14-entry AWS documentation-example-ID screen
  (`123456789012` and friends), and the owned-vs-referenced ownership/severity/confidence
  mapping. Explicitly marks the *active* IAM-role reverse-enumeration step out of scope.
- **§8 — Dependency confusion.** Manifest mining across 7 file types (`package.json`,
  `package-lock.json`, `.npmrc`, `requirements.txt`, `pyproject.toml`, `pip.conf`, bundled JS),
  the internal-signal classifier (private-registry binding = strong, org-namespace match =
  medium), the **two-part confirmation contract** (internal signal AND public-registry 404 —
  neither alone is a finding, fail-closed on any ambiguity), and the npm scope-claimability
  nuance the public search API gets wrong (it reports `total:0` for a privately-owned scope,
  which reads as falsely claimable).
- **§9 — Cloud-native & K8s/CI control-plane fingerprinting.** Passive-only pattern matching
  over already-resolved hostnames and already-discovered ports — structural ownership gating
  (CNAME/cert-SAN/subdomain-FQDN provenance = owned; bare pattern match = unverified) for
  cloud-native endpoints (Lambda URL, API Gateway, Cloud Run, App Service, …), and a passive
  flag (never an active probe) for container/K8s orchestration ports (Docker API, etcd,
  Kubernetes API, kubelet) and CI/CD tech fingerprints.
- **§10 — Severity & business translation table** spanning all four subsystems.

## Grounded in production, not invented

Every candidate-generation rule, probe-response classification, severity/confidence weight,
and algorithm constant in this skill is reproduced from a shipped, tested implementation —
not invented for the skill:

- `falcon_recon/modules/cloud_buckets.py` — bucket candidate generation, probe technique,
  ownership-gated severity model, object-key triage, dangling-CNAME takeover
- `falcon_recon/core/aws_account.py` + `falcon_recon/modules/aws_account_enum.py` — offline
  AWS account-ID decode, test vector, example-ID screening, ownership mapping
- `falcon_recon/core/dep_confusion.py` + `falcon_recon/modules/dependency_confusion.py` —
  manifest parsing, internal-signal classifier, two-part confirmation contract
- `falcon_recon/modules/cloud_exposure.py` — cloud-native endpoint fingerprint, passive
  container/K8s/CI exposure flags

A hand-computed result from this skill's tables (a candidate list, a decoded account ID, a
claimability verdict) should match what the reference implementation produces on the same
input.

## Deepens, does not duplicate

`offensive-osint` §16.8 (bucket permutation raw lists), §16.17 (cloud-native URL patterns),
§16.18–§16.19 (container/K8s/CI paths + active probe recipes), and §44 (package registry
search) already carry the wordlists and curl one-liners. This skill is the reasoning layer on
top: which bucket hit is actually the client's risk, how to recover an account ID with zero
network traffic, what makes a dependency name a *confirmed* confusion vector rather than a
bare 404, and how to read cloud-native/K8s infrastructure as an org-attribution surface
rather than just another probe target.

## Scope discipline

Passive/discovery only. In scope: bucket HEAD/GET existence and listing checks, offline
AKIA→account-ID decoding, read-only public-registry 404 checks (npm/PyPI — zero target
traffic), and passive cloud-native/K8s/CI fingerprinting from already-collected signals. Out
of scope, described but never performed: submitting AWS credentials or calling AWS APIs with
a decoded account ID, registering an unclaimed dependency name, and confirming a
fingerprinted cloud-native endpoint or control-plane port actually answers unauthenticated
(Falcon-Recon's stage-6 `--validate --validate-cloud` tier).

## Loading

```bash
# Local Claude Code install
cp SKILL.md ~/.claude/skills/cloud-saas-exposure/SKILL.md

# Or attach to a Claude.ai project / Claude API system prompt
# (paste the contents of SKILL.md as project knowledge)
```

## Self-test

Run the 14 prompts in this skill's own §11 Skill Self-Test (including three negative cases —
an unattributable listable bucket is not CRITICAL, an active `sts:AssumeRole` reverse-enum is
out of scope, and reserving an unclaimed dependency name is a client action, not this skill's
step) to verify the skill loads and routes correctly.

## License

MIT — see [LICENSE](../../LICENSE).
