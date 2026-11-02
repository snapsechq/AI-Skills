# Web Application Security Assessment Plan & Checklist

When starting an assessment on a web application, formulate an active test plan (`was_test_plan.md`) and execution checklist (`was_test_checklist.md`) in your working directory.

## 1. Web Application Assessment Plan Template (`was_test_plan.md`)

```markdown
# Web Application Security Test Plan

## 1. Target Scope
- Target URL: <TARGET_URL>
- In-Scope Origins: <ALLOWED_ORIGINS>
- Authentication Method: <FORM / TOKEN / NONE>
- Login Endpoint: <LOGIN_URL>

## 2. Assessment Objectives
1. **Reconnaissance & Surface Mapping**:
   - Discover routes, navigation links, forms, and client-side routes.
   - Intercept XHR/Fetch API endpoints via `agent-browser network requests`.
2. **Authentication & Session Analysis**:
   - Verify cookie flags (`HttpOnly`, `Secure`, `SameSite`).
   - Test session termination and logout invalidation.
3. **Input Validation & Injection Verification**:
   - Identify input fields (search, comments, user profile, query params).
   - Test reflection and verify proper encoding or sanitization.
4. **CORS & HTTP Security Headers**:
   - Check `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`.
   - Test CORS Origin reflection.
5. **Vulnerability Synthesis**:
   - Validate findings and output strictly to `artifacts/results.json`.
```

## 2. Web Application Execution Checklist (`was_test_checklist.md`)

```markdown
# Web Application Assessment Checklist

- [ ] Target Accessibility: Confirm `agent-browser open <TARGET_URL>` renders successfully.
- [ ] Authentication: Log in if credentials are provided and verify authenticated session state.
- [ ] Route Discovery: Explore primary navigation bars, footers, buttons, and dashboard menus.
- [ ] API Endpoint Enumeration: Review `agent-browser network requests` for hidden REST/GraphQL endpoints.
- [ ] Form Testing:
  - [ ] Inspect form inputs via `agent-browser snapshot -i`.
  - [ ] Test reflected inputs for XSS indicators.
  - [ ] Test form submission without CSRF tokens.
- [ ] Security Headers & Cookies:
  - [ ] Verify `agent-browser cookies get` for `HttpOnly` and `Secure`.
  - [ ] Inspect response headers for missing anti-clickjacking (`X-Frame-Options` / CSP).
- [ ] Nuclei Automated Scan (if applicable): Run `nuclei -u <TARGET_URL> -jsonl` and triage findings.
- [ ] Reporting: Format all verified findings into `artifacts/results.json` and validate using `python3 scripts/validate_results.py`.
```

