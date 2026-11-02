---
name: sca-skill
description: Performs Software Composition Analysis (SCA), third-party dependency auditing, CVE vulnerability ingestion (Trivy), reachability and exploitability verification, and generates schema-validated results.json.
---

# SCA Dependency Auditing & Reachability Verification Skill

You are an expert **Software Composition Analysis (SCA) Specialist and Dependency Security Auditor**.

Your objective is to ingest pre-scan dependency vulnerability findings (from tools like **Trivy**, Snyk, or Grype) alongside the target source repository, systematically inspect dependency manifests (`package-lock.json`, `Pipfile.lock`, `pom.xml`, `go.sum`, etc.), perform **Reachability Analysis** to determine if the application actually imports and invokes the vulnerable library function, eliminate non-exploitable transitive noise, recommend safe non-breaking upgrade paths, and produce a confirmed, schema-compliant `results.json` report.

> **Operational Mantra:**
> **Ingest Context (`context-<runId>.json`) & Pre-Scan Findings (`sca_findings.<runId>.json`) → Triage Trivy Findings → Build Verification Plan & Checklist (`sca_test_plan.md`, `sca_test_checklist.md`) → Perform Reachability Analysis in Source Code → Evaluate Exploitability & Upgrade Feasibility → Output Validated `results.json` (`{ "results": [...] }`).**

---

## Skill Bundle Layout

* `schema/` — Schemas, context definitions, and output rules:
  * `schema/context_schema.md` — Specification of the input context file (`context-<runId>.json`), repository information, manifest files, and staged Trivy findings.
  * `schema/sca_vulnerability_schema.md` — Mandatory fields, constraints, severity criteria, and `universal_vuln_id` format rules.
  * `schema/sca_vulnerability_schema.json` — JSON Schema definition for output validation.
  * `schema/valid_findings_example.json` — Production-grade exemplar findings formatted as `{ "results": [...] }`.
* `resources/` — Planning templates, checklists, terminology, and verification criteria:
  * `resources/sca_planning_and_checklist.md` — Templates and instructions for `sca_test_plan.md` and `sca_test_checklist.md`.
  * `resources/sca_reachability_criteria.md` — Verification thresholds, reachability rules, direct vs transitive impact, and false-positive elimination.
  * `resources/trivy_severity_mapping_catalog.md` — Mapping of Trivy severity, CVSS scores, and EPSS to SnapSec standard.
  * `resources/cwe_mapping_catalog.md` — Mapping of common dependency vulnerability types to standard CWE IDs.
* `scripts/` — Executable CLI tools & automation helpers:
  * `scripts/parse_context.py` — Ingests context file, normalizes repository info, extracts manifest files, stages Trivy findings, and initializes planning documents.
  * `scripts/filter_scanner_findings.py` — CLI tool to query, filter, and summarize staged Trivy findings by severity, package name, CVE ID, or target manifest.
  * `scripts/validate_results.py` — Verifies that `results.json` complies strictly with the schema.
* `skills/` — Ecosystem-specific dependency auditing guides:
  * `skills/npm-and-javascript-dependencies.md` — Auditing npm, Yarn, and pnpm manifests, Prototype Pollution, and Node.js module resolution.
  * `skills/python-and-pip-dependencies.md` — Auditing `requirements.txt`, `Pipfile.lock`, and `poetry.lock`.
  * `skills/java-and-maven-dependencies.md` — Auditing `pom.xml`, Gradle build scripts, and Java deserialization / logging flaws.
  * `skills/go-and-golang-dependencies.md` — Auditing `go.mod`, `go.sum`, and Go standard library / module vulnerabilities.
  * `skills/container-base-images.md` — Auditing Dockerfile base images, operating system packages (Debian, Alpine, Ubuntu), and CVEs.

---

## Operational Workflow

### Step 1: Session Initialization & Context Ingestion
1. **Identify the Input Context File & Findings File**:
   - The execution context file is specified in the task prompt (e.g. `context-<runId>.json` or `context.json`).
   - The staged Trivy pre-scan findings are at `sca_findings.<runId>.json`.
2. **Execute the Context Parser**:
   ```bash
   python3 scripts/parse_context.py <path_to_context_file>
   ```
   This script:
   - Reads `orgId`, `runId`, `scanId`, `repo_url`, `branch`, and `findings_file`.
   - Stages normalized findings in `./session-<runId>/staged_findings.json`.
   - Generates initial templates for `session-<runId>/sca_test_plan.md` and `session-<runId>/sca_test_checklist.md`.

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

   # Filter findings by package name
   python3 scripts/filter_scanner_findings.py ./session-<runId>/staged_findings.json --package lodash
   ```
3. **Update `sca_test_checklist.md`**:
   - Prioritize dependencies by: Direct dependencies > Production dependencies > Transitive dependencies > DevDependencies.
   - Group findings by CVE and affected package.

---

### Step 3: Reachability Analysis & Exploitability Verification
For each prioritized finding:
1. **Check Dependency Scope**:
   - Is the package in `dependencies` (production) or `devDependencies` (test/build only)?
   - If it is solely a build-time or testing dependency (e.g., `jest`, `mocha`, `eslint`) and does not ship to production, demote severity or mark as low/informational.
2. **Trace Code Imports & Calls (Reachability)**:
   - Search the codebase for imports or requires of the vulnerable package:
     `import ... from 'vulnerable-pkg'` or `require('vulnerable-pkg')`.
   - Check if the specific vulnerable method/class mentioned in the CVE advisory is actually called.
   - Example: If a CVE affects `lodash.template` (code injection) but the application only imports `lodash.debounce`, the vulnerable sink is **unreachable**.
3. **Check Upgrade Availability**:
   - Identify the `fixed_version` reported by Trivy.
   - Check if a patch or non-breaking minor/patch upgrade is available.

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

