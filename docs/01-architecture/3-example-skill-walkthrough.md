# 3. Example Skill Walkthrough: Acme Mobile Shop

This document illustrates how an `AI-Skills` bundle operates during a real-world assessment.

---

## The Scenario
A customer ("Acme Corp", `org_acme_123`) runs an SCA scan against their mobile app backend:
- Target: `https://api.acme-shop.com`
- Authentication: Phone number + SMS OTP token (`phone: "+1-555-0199"`)
- Codebase: `https://github.com/acme-corp/shop-api.git`
- Target Type: `code-sca`

---

## How `sca-skill` Executes Inside HermesAgent

### 1. Ingestion of Candidate Finding
Before Hermes is invoked, `ScaAgent` runs Trivy against `shop-api/package.json`. Trivy reports:
```json
{
  "PkgName": "jsonwebtoken",
  "InstalledVersion": "8.5.1",
  "VulnerabilityID": "CVE-2022-23529",
  "Severity": "HIGH"
}
```

### 2. Loading Directives from `sca-skill/SKILL.md`
`HermesAgent` receives the candidate finding and the prompt from [`sca-skill/SKILL.md`](../sca-skill/SKILL.md):
```text
Directive: Verify reachability of CVE-2022-23529 in target repository source code.
1. Cross-reference sca-skill/resources/sca_reachability_criteria.md.
2. Inspect codebase call chains. If the vulnerable method (jwt.verify) is never invoked, downgrade finding to 'unreachable'.
3. If reachable from public HTTP handlers, confirm severity and generate proof of reachability.
```

### 3. LLM Code Inspection
Acting on the skill instructions, the LLM executes shell inspection tools in the cloned repo:
```bash
grep -rn "jsonwebtoken" source_code/
```
The LLM finds:
```text
source_code/routes/api/v1/auth/phone-verify.js:14: const jwt = require('jsonwebtoken');
source_code/routes/api/v1/auth/phone-verify.js:42: const decoded = jwt.verify(req.headers['x-phone-token'], secret);
```

### 4. Reasoning via `sca_reachability_criteria.md`
The LLM reads the reachability matrix:
- Is `jsonwebtoken` in `dependencies`? **Yes**.
- Is it imported in production code (not tests)? **Yes** (`routes/api/v1/auth/phone-verify.js`).
- Can external users supply data to the call? **Yes** (via HTTP header `x-phone-token` during SMS login).

### 5. Schema Validation & Output
The LLM structures the final verified finding matching [`sca-skill/schema/sca_vulnerability_schema.json`](../sca-skill/schema/sca_vulnerability_schema.json):
```json
{
  "cve_id": "CVE-2022-23529",
  "package_name": "jsonwebtoken",
  "installed_version": "8.5.1",
  "fixed_version": "9.0.0",
  "reachability": "reachable",
  "severity": "high",
  "affected_file": "routes/api/v1/auth/phone-verify.js",
  "remediation": "Upgrade jsonwebtoken to version 9.0.0 or higher in package.json."
}
```

This verified payload is written to the artifacts directory and transmitted back to [auto-pentest](https://github.com/snapsechq/auto-pentest) for display on Acme Corp's dashboard.

---
[⬅️ Previous: 2. Manifest & Skill Folder Hierarchy](./2-manifest-and-skill-structure.md) | [Next: 4. Authoring & Testing Skills Guide ➡️](./4-authoring-and-testing-skills.md)

