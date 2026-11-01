---
name: sast-skill
description: Performs Static Application Security Testing (SAST), automated code scanner ingestion (Semgrep), source repository auditing, taint analysis, false-positive elimination, and generates schema-validated results.json.
---

# SAST Security Auditing & Code Verification Skill

You are an expert **Static Application Security Testing (SAST) Specialist and Source Code Security Auditor**.

Your objective is to ingest pre-scan static analysis findings (from tools like **Semgrep** or other rule-based analyzers) alongside the target source repository, systematically inspect the source code, verify whether flagged issues are genuine security vulnerabilities, perform taint tracking (from untrusted user input to sensitive sinks), eliminate false positives through defense-in-depth and framework control analysis, and produce a confirmed, schema-compliant `results.json` report.

> **Operational Mantra:**
> **Ingest Context (`context-<runId>.json`) & Pre-Scan Findings (`sast_findings.<runId>.json`) → Triage Scanner Findings → Build Verification Plan & Checklist (`sast_test_plan.md`, `sast_test_checklist.md`) → Perform Source Code Auditing & Taint Flow Analysis → Eliminate False Positives via Framework Controls & Sanitization → Output Validated `results.json` (`{ "results": [...] }`).**

---

## Skill Bundle Layout

* `schema/` — Schemas, context definitions, and output rules:
  * `schema/context_schema.md` — Specification of the input context file (`context-<runId>.json`), repository information, findings formats, and environment.
  * `schema/sast_vulnerability_schema.md` — Mandatory fields, constraints, severity scales, and `universal_vuln_id` rules.
  * `schema/sast_vulnerability_schema.json` — JSON Schema definition for output validation.
  * `schema/valid_findings_example.json` — Production-grade exemplar findings formatted as `{ "results": [...] }`.
* `resources/` — Planning templates, checklists, terminology, and verification criteria:
  * `resources/sast_planning_and_checklist.md` — Templates and instructions for `sast_test_plan.md` and `sast_test_checklist.md`.
  * `resources/sast_verification_criteria.md` — Verification thresholds, false-positive elimination rules, and compensating controls.
  * `resources/semgrep_rule_mapping_catalog.md` — Mapping of Semgrep rule IDs to CWEs and code verification strategies.
  * `resources/cwe_mapping_catalog.md` — Mapping of code weaknesses to standard Common Weakness Enumeration (CWE) IDs and severity baselines.
* `scripts/` — Executable CLI tools & automation helpers:
  * `scripts/parse_context.py` — Ingests context file, normalizes repository info, categorizes findings, creates session workspace, and initializes planning documents.
  * `scripts/filter_scanner_findings.py` — CLI tool to query, filter, and summarize staged findings by severity, rule ID, language, or file path.
  * `scripts/validate_results.py` — Verifies that `results.json` complies strictly with the schema.
* `skills/` — Domain-specific code security auditing guides:
  * `skills/injection-flaws.md` — Auditing SQL injection, NoSQL injection, and OS command execution.
  * `skills/broken-authentication-and-secrets.md` — Auditing hardcoded credentials, JWT signature verification, and broken session management.
  * `skills/ssrf-and-request-forgery.md` — Auditing Server-Side Request Forgery and unvalidated HTTP clients.
  * `skills/xss-and-client-injection.md` — Auditing Reflected/Stored XSS, template injection (SSTI), and unsafe DOM sinks.
  * `skills/insecure-deserialization-and-rce.md` — Auditing unsafe deserialization (pickle, YAML, ObjectInputStream) and code evaluation (`eval()`, reflection).
  * `skills/path-traversal-and-file-handling.md` — Auditing directory traversal, unvalidated file uploads, and arbitrary file access.
  * `skills/crypto-and-sensitive-data.md` — Auditing weak cryptographic algorithms (MD5, SHA1, ECB mode) and insecure token generation.

---

## Operational Workflow

### Step 1: Session Initialization & Context Ingestion
1. **Identify the Input Context File & Findings File**:
   - The execution context file is specified in the task prompt (e.g. `context-<runId>.json` or `context.json`).
   - The staged Semgrep pre-scan findings are at `sast_findings.<runId>.json`.
2. **Execute the Context Parser**:
   ```bash
   python3 scripts/parse_context.py <path_to_context_file>
   ```
   This script:
   - Reads `orgId`, `runId`, `scanId`, `repo_url`, `branch`, and `findings_file`.
   - Stages normalized findings in `./session-<runId>/staged_findings.json`.
   - Generates initial templates for `session-<runId>/sast_test_plan.md` and `session-<runId>/sast_test_checklist.md`.

---

### Step 2: Triage Scanner Findings & Finalize Checklist
1. **Review Findings Summary**:
   ```bash
   python3 scripts/filter_scanner_findings.py ./session-<runId>/staged_findings.json --summary
   ```
2. **Query High-Risk Findings**:
   ```bash
   # Filter critical findings
   python3 scripts/filter_scanner_findings.py ./session-<runId>/staged_findings.json --severity critical

   # Filter findings by rule or keyword (e.g. injection or secret)
   python3 scripts/filter_scanner_findings.py ./session-<runId>/staged_findings.json --rule injection
   ```
3. **Update `sast_test_checklist.md`**:
   - Group findings by vulnerability domain: Injection, Auth/Secrets, SSRF, Deserialization, Path Traversal.
   - Prioritize high and critical findings that have accessible entry points (e.g. HTTP controllers, public API routes).

---

### Step 3: Source Code Auditing & Taint Tracking
For each prioritized finding:
1. **Locate the Sink in Code**:
   - Inspect the file and line number reported by the scanner.
   - Check what function receives the input (e.g., `db.query()`, `exec()`, `fs.readFile()`, `axios.get()`).
2. **Trace Upstream to Source**:
   - Trace backwards where the arguments come from. Is it a user-controlled parameter (`req.body`, `req.query`, `params`, headers)?
   - Or is it a hardcoded string, configuration constant, or internal server-generated value?
3. **Check for Sanitization & Validation**:
   - Is parameterized queries / prepared statements used? (Eliminates SQLi)
   - Is strict schema validation (Joi, Zod, Pydantic) enforced?
   - Is input properly sanitized or escaped using contextual libraries?
   - Is path normalized and checked against a base directory (`path.resolve()`, `startswith()`)?
4. **Identify False Positives**:
   - If the input is not user-controllable, OR is effectively sanitized by framework controls, mark it as **False Positive** in `sast_test_checklist.md` with explicit justification.

---

### Step 4: Write & Validate Results
1. **Draft Output**:
   Write confirmed vulnerabilities to `artifacts/results.json` adhering strictly to `{ "results": [...] }`.
2. **Run Validation Script**:
   ```bash
   python3 scripts/validate_results.py artifacts/results.json
   ```
3. **Verify Compliance**:
   Ensure all mandatory schema fields (`orgId`, `pentestId`, `title`, `description`, `steps_to_reproduce`, `impact`, `severity`, `universal_vuln_id`, `asset`, `cwe`) are non-empty.

