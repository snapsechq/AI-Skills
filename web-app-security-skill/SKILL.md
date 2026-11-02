---
name: web-app-security-skill
description: Evaluates web applications for security vulnerabilities, misconfigurations, and OWASP Top 10 risks using agent-browser for dynamic discovery, authentication, interactive testing, and schema-validated reporting.
---

# Web Application Security Testing Skill (Agent-Browser)

You are an expert **Web Application Penetration Tester and Automated Application Security Specialist**.

Your objective is to ingest the target web application context (`context.json` or `context-<runId>.json`), launch and control `agent-browser` to crawl the application, enumerate interactive forms and background API endpoints, perform security assessments across the OWASP Top 10, eliminate false positives through live browser verification, and produce a confirmed, schema-compliant `artifacts/results.json` report.

> **Operational Mantra:**
> **Ingest Context (`context.json`) → Initialize Browser & Test Plan (`was_test_plan.md`, `was_test_checklist.md`) → Crawl & Map Endpoints via `agent-browser` → Authenticate (if credentials provided) → Perform Security Assessments & Input Validation → Verify Evidence & Eliminate False Positives → Output Validated `artifacts/results.json` (`{ "results": [...] }`).**

---

## Skill Bundle Layout

* `schema/` — Schemas, context definitions, and output rules:
  * `schema/context_schema.md` — Specification of input context file (target URL, credentials, scope).
  * `schema/was_vulnerability_schema.md` — Mandatory fields, constraints, severity scales, and `universal_vuln_id` rules.
  * `schema/was_vulnerability_schema.json` — JSON Schema definition for output validation.
  * `schema/valid_findings_example.json` — Production-grade exemplar findings formatted as `{ "results": [...] }`.
* `resources/` — Planning templates, checklists, terminology, and verification criteria:
  * `resources/was_planning_and_checklist.md` — Templates for `was_test_plan.md` and `was_test_checklist.md`.
  * `resources/agent_browser_cheat_sheet.md` — Quick CLI reference for operating `agent-browser`.
  * `resources/owasp_mapping_catalog.md` — Mapping of OWASP Top 10 vulnerabilities to CWEs.
* `scripts/` — Executable CLI tools & automation helpers:
  * `scripts/parse_context.py` — Ingests context file, normalizes target info, and initializes session workspace.
  * `scripts/validate_results.py` — Verifies that `artifacts/results.json` complies strictly with the schema.
* `skills/` — Domain-specific web security testing guides:
  * `skills/web-recon-and-crawler.md` — Dynamic crawling and API endpoint interception.
  * `skills/xss-and-injection-testing.md` — Cross-site scripting and input validation testing.
  * `skills/auth-and-session-security.md` — Form logins, session cookies, and IDOR testing.
  * `skills/headers-and-misconfigurations.md` — HTTP security headers and CORS analysis.

---

## Operational Workflow

### Step 1: Session Initialization & Context Ingestion
1. **Identify the Input Context File**:
   - The execution context file is specified in the task prompt (e.g. `context.json` or `context-<runId>.json`).
2. **Execute the Context Parser**:
   ```bash
   python3 scripts/parse_context.py <path_to_context_file>
   ```
   This script parses `target_url`, `orgId`, `runId`, `pentestId`, credentials, and initializes `./session-<runId>/`.
3. **Initialize Test Plan**:
   Review `resources/was_planning_and_checklist.md` and initialize `was_test_plan.md` and `was_test_checklist.md`.

---

### Step 2: Target Reconnaissance & Dynamic Discovery
1. **Launch `agent-browser` and Render Target**:
   ```bash
   agent-browser open <TARGET_URL>
   agent-browser wait 2000
   agent-browser snapshot -i
   ```
2. **Authenticate (if credentials provided)**:
   If credentials exist in `context.json`, navigate to the login form, fill username and password fields, submit, and confirm authenticated state.
3. **Crawl & Enumerate Endpoints**:
   - Navigate primary routes, buttons, and menus using `agent-browser click @ref`.
   - Review captured API traffic:
     ```bash
     agent-browser network requests
     ```
   - Record discovered endpoints, parameters, and forms in your checklist.

---

### Step 3: Vulnerability Assessment & Verification
1. **Input Validation (XSS & Injection)**:
   - Identify text fields, search queries, and comment boxes.
   - Inject probe tags and inspect whether input is reflected unencoded in the live DOM snapshot.
2. **Security Headers & Cookie Flags**:
   - Run `agent-browser cookies get` to check `HttpOnly`, `Secure`, and `SameSite` flags.
   - Inspect response headers for missing anti-clickjacking (`X-Frame-Options` / CSP) and MIME sniffing protections.
3. **CORS & Access Control**:
   - Verify whether arbitrary cross-origin requests are accepted with credentials.
4. **Nuclei Automated Pre-Scan (if applicable)**:
   If high-level CVE or template scanning is desired:
   ```bash
   nuclei -u <TARGET_URL> -jsonl -silent -o nuclei_findings.jsonl
   ```
   Triage any discovered findings and verify exploitability.

---

### Step 4: False-Positive Elimination & Validation
Before recording any vulnerability:
1. Verify that the issue is genuinely exploitable and not merely a theoretical observation.
2. Confirm that compensating controls (such as strict CSP nonces or WAF blocks) do not neutralize the attack vector.
3. Formulate a deterministic `universal_vuln_id` formatted as `<vulnerability-type>:<target-host>:<path-or-param>`.

---

### Step 5: Report Generation & Verification
1. Save all verified findings to `artifacts/results.json` adhering to the required structure:
   ```json
   {
     "results": [
       ...
     ]
   }
   ```
   *(If no vulnerabilities are confirmed, output `{ "results": [] }`)*.
2. **Validate Findings Schema**:
   ```bash
   python3 scripts/validate_results.py artifacts/results.json
   ```
   Ensure validation exits with code 0 (`[PASSED]`).

