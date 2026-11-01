# SAST Planning and Verification Checklist Templates

## 1. Test Plan Template (`session-<runId>/sast_test_plan.md`)

```markdown
# SAST Code Security Audit Plan

- **Repository**: <repo_url>
- **Branch / Commit**: <branch> (<commit>)
- **Run ID**: <runId>
- **Total Initial Findings Ingested**: <count>

## Scope & Target Languages
- Identified Languages: (e.g. JavaScript/TypeScript, Python, Go, Java)
- Primary Frameworks: (e.g. Express, Django, Spring Boot, Gin)
- High-Value Attack Surfaces: (e.g. Authentication routes, API controllers, File processors)

## Audit Strategy
1. **Critical & High Priority**: Triage and verify all scanner findings with severity critical/high.
2. **Taint Flow Analysis**: Trace inputs from HTTP route handlers down to database queries, shell execs, and file operations.
3. **Defense-in-Depth Verification**: Verify ORM protections, parameterized queries, and output encoding.
4. **False Positive Elimination**: Document discarded findings with reasoning.
```

---

## 2. Verification Checklist Template (`session-<runId>/sast_test_checklist.md`)

```markdown
# SAST Verification Checklist

| # | Rule ID / Title | File:Line | Ingested Severity | Taint Source | Confirmed / FP | Reason & Remediation |
|---|---|---|---|---|---|---|
| 1 | javascript.express.security.audit.sqli | `src/controllers/user.js:45` | HIGH | `req.query.id` | CONFIRMED | Direct SQL string concatenation |
| 2 | generic.secrets.security.detected-jwt-token | `test/fixtures/token.js:12` | MEDIUM | N/A (Test mock) | FALSE POSITIVE | Test fixture, not loaded in production |
```

