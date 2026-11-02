# SCA Planning and Verification Checklist Templates

## 1. Test Plan Template (`session-<runId>/sca_test_plan.md`)

```markdown
# SCA Dependency Security Audit Plan

- **Repository**: <repo_url>
- **Branch / Commit**: <branch> (<commit>)
- **Run ID**: <runId>
- **Total Initial Vulnerabilities Ingested (Trivy)**: <count>

## Identified Dependency Manifests
- Node.js: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Python: `requirements.txt`, `Pipfile.lock`, `poetry.lock`
- Java: `pom.xml`, `build.gradle`
- Go: `go.mod`, `go.sum`
- Container: `Dockerfile`

## Audit Strategy
1. **Critical & High Priority**: Triage and verify all CVEs with severity critical/high.
2. **Direct vs Transitive**: Identify which vulnerable packages are direct project dependencies vs sub-dependencies.
3. **Reachability Analysis**: Grep the source code for imports and invocations of the vulnerable methods.
4. **DevDependency Filter**: Demote or exclude vulnerabilities existing solely in build/test dependencies.
5. **Remediation**: Determine minimal non-breaking upgrade paths (`fixed_version`).
```

---

## 2. Verification Checklist Template (`session-<runId>/sca_test_checklist.md`)

```markdown
# SCA Verification Checklist

| # | CVE ID | Package@Version | Target Manifest | Ingested Sev | Reachable in Code? | Fix Version | Status |
|---|---|---|---|---|---|---|---|
| 1 | CVE-2021-23337 | `lodash@4.17.20` | `package-lock.json` | HIGH | YES (`src/utils/templater.js`) | `4.17.21` | CONFIRMED |
| 2 | CVE-2022-25883 | `semver@7.3.5` | `package-lock.json` | MEDIUM | NO (Used only by Jest) | `7.3.8` | FALSE POSITIVE (Dev Only) |
```

