---
name: New technique / vendor / pattern
about: Add a new vendor product fingerprint, secret pattern, dork, or wordlist entry
title: '[NEW] '
labels: enhancement, technique
assignees: ''
---

## Type of addition

- [ ] Vendor product fingerprint (target arsenal §16.16)
- [ ] Secret pattern (target arsenal §17)
- [ ] Dork template (target arsenal §18)
- [ ] Wordlist entry (target arsenal §16.x)
- [ ] Cloud-native service fingerprint (target arsenal §16.17)
- [ ] Identity-fabric endpoint (target arsenal §22 or methodology §11)
- [ ] Validator (target arsenal §23)
- [ ] Attack-path hint template (target arsenal §39)
- [ ] Severity-matrix worked example (target arsenal §40)
- [ ] Other: ___________

## Concrete addition

Paste the exact content to add. Examples:

**For a vendor fingerprint:**
```
| Vendor | Fingerprint paths | Notes |
|---|---|---|
| **<Product Name>** | `/path/to/version-disclosure`, `/api/v1/info` | CVE-XXXX-XXXX (KEV-listed). |
```

**For a secret pattern:**
```
| <#> | <Pattern Name> | `<regex>` | <SEVERITY> | <category> |
```

**For a dork:**
```
site:{domain} <dork-content>
```

## Validation

- [ ] Tested against a real (authorized) target — does the fingerprint actually work?
- [ ] False-positive rate considered? (For regex patterns.)
- [ ] CVE associations included where relevant?

## Source / attribution

Where did you find this? (Vendor docs, CVE advisory, your own research, etc.)

## Severity / detectability proposal

What severity should findings of this pattern carry? What's the detectability?

## Self-test prompt

Paste a sample prompt that should now trigger the new content.
