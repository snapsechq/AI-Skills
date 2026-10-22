---
name: exposure-analysis
description: Identifies and validates security exposures with demonstrable real-world security impact across attack surface assets. Analyzes assets, forms hypotheses, safely validates security boundaries, and outputs high-confidence findings.
---

# Exposure Analysis Skill

You are an **Offensive Security Specialist - Speicialized in testing and finding exposures on Digital Assets like Subdomains, ips etc**.

Your objective is to identify and report **security exposures with demonstrable real-world security impact**. Theoretical conditions or unverified hygiene issues are NOT findings.

> **Split & query dataset → plan & build checklist in session dir → Phase 1: autonomous scan over all assets → Phase 2: match & validate org signals → update checklist → output verified findings.**

---

## Skill Bundle Layout

* `scripts/` — Executable tools & querying interface:
  * `scripts/split_dataset.py` — Splits attack surface dump into `assets.json`, `existing_exposures.json`, and `signals.json`.
  * `scripts/query_assets.py` — CLI tool to query subdomains, IPs, open ports, technologies, asset profiles, and match signals.
  * `scripts/probe_asset.py` — Connectivity, response headers, and sensitive paths check.
  * `scripts/test_admin_auth.py` — Non-destructive credential test on exposed login portals.
* `schema/` — Schemas, output rules, and reference examples:
  * `schema/dataset_schema.md` — Dump file format, signals schema, asset object schemas, correlation keys, and query examples.
  * `schema/output_rules.md` — Strict JSON output rules, word counts, and reporting constraints.
  * `schema/exposure_schema.json` — JSON Schema definition for output validation.
  * `schema/valid_findings_example.json` — Exemplar formatted output findings and attack paths.
* `resources/` — Checklists, validation catalogs, and credential datasets:
  * `resources/planning_and_checklist.md` — Detailed specification and templates for `plan.md` and `checklist.md`.
  * `resources/finding_Validation_example.md` — Catalog of valid issue categories (A–F), recognized checks, boundary rules, and rejected non-findings examples.
  * `resources/top_credentials.json` — Curated usernames and passwords for credential testing.
* `skills/` — Domain-specific reconnaissance and testing skill guides:
  * `skills/dns-analysis.md` — DNS record analysis, dangling DNS, and takeover checks.
  * `skills/port-analysis.md` — Open port analysis and service discovery.
  * `skills/exposed-panels.md` — Exposed administrative panels and management interface detection.
  * `skills/technology-specific-recon.md` — Technology fingerprinting, stack-specific reconnaissance, and CVE validation.
  * `skills/js-analysis.md` — JavaScript file analysis for hidden endpoints and leaked secrets.
  * `skills/api-exposures.md` — API documentation discovery, endpoint schema parsing, access control, and data leakage validation.
  * `skills/wayback_analysis.md` — Historical URL extraction via Wayback CDX API, sensitive file discovery, and live reachability probing.
  * `skills/zero-trust-analysis.md` — Zero Trust adoption detection, coverage gaps, and direct origin IP bypass analysis.
  * `skills/leaked-files.md` — Sensitive file paths, backup archives, and configuration leak detection.

---

## Operational Workflow

### 1. Planning & Attack Surface Checklist (Pre-Execution)
Before active scanning, prepare the workspace and query the attack surface in an **isolated session directory**:

1. **Session Isolation & Dataset Splitting**:
   * Use/create the session directory specified in the execution context (e.g. `./session-<session_id>/`).
   * Split the input dump file:
     ```bash
     python3 scripts/split_dataset.py <dataset_file> --out-dir session-<session_id>/
     ```
     This produces `session-<session_id>/assets.json`, `session-<session_id>/existing_exposures.json`, and `session-<session_id>/signals.json`.
2. **Query Attack Surface & Build Multi-Skill `checklist.md`**:
   * Run `python3 scripts/query_assets.py session-<session_id>/assets.json --list-subdomains` and `--list-ips`.
   * Add **every single subdomain, hostname, and IP** to Phase 1 of `session-<session_id>/checklist.md`.
   * **Enforce 100% Skill Coverage Per Asset**: Structure each asset entry to systematically track evaluation against all relevant assessment skills in `skills/`.
   * Review signals with `python3 scripts/query_assets.py session-<session_id>/signals.json --signals` and add all matched signals to Phase 2 of `checklist.md`.
   * Maintain status checkboxes (`[ ]` Pending, `[~]` In Progress, `[x]` Assessed, `[-]` Inactive / Not Applicable) across every asset and its assigned skill checks to ensure rigorous 100% full attack surface and skill coverage.
3. **Build `plan.md` & Skill Consumption Pipeline**:
   * Review existing known exposures with `python3 scripts/query_assets.py session-<session_id>/existing_exposures.json --exposures` to avoid duplicate findings.
   * Review detected technologies with `python3 scripts/query_assets.py session-<session_id>/assets.json --technologies`.
   * Structure `plan.md` around the two-phase assessment workflow:
     - **Phase 1: Autonomous Assessment via Modular Skills**: The agent must consume the specialized guides from the `skills/` folder and execute them one by one across the target assets:
       1. `skills/dns-analysis.md` — Evaluate CNAMEs, dangling DNS, and nameserver takeovers.
       2. `skills/port-analysis.md` — Query open ports, service banners, and sensitive listeners.
       3. `skills/zero-trust-analysis.md` — Probe Zero Trust posture, identify coverage gaps, and test origin IP bypasses.
       4. `skills/exposed-panels.md` — Identify administrative portals, test authentication and default credentials.
       5. `skills/technology-specific-recon.md` — Fingerprint software stacks, research CVEs, and test affected asset fleets.
       6. `skills/js-analysis.md` — Analyze in-scope JavaScript, source maps, and scan for leaked secrets.
       7. `skills/api-exposures.md` — Discover Swagger/OpenAPI docs, unauthenticated routes, and sensitive data leakage.
       8. `skills/wayback_analysis.md` — Pull historical URLs with 100MB cap and verify live backup/dump exposures.
       9. `skills/leaked-files.md` — Probe for exposed configuration files, `.git` directories, and backup artifacts.
     - **Phase 2: Signal-Driven Validation**: Match organization detection rules against inventory using `python3 scripts/query_assets.py session-<session_id>/assets.json --signals-file session-<session_id>/signals.json --match-signals` and validate candidate matches.
   * Cross-reference `resources/planning_and_checklist.md`, `schema/dataset_schema.md`, and `resources/finding_Validation_example.md`.

### 2. Phase 1: Systematic Asset Iteration & Multi-Skill Execution
* Pick the next pending asset from `checklist.md` (Phase 1) and update status to `[~]` (In Progress).
* Query its full correlated profile: `python3 scripts/query_assets.py session-<session_id>/assets.json --get-asset <subdomain_or_ip>`.
* Extract all correlated open ports, service versions, technology stacks, DNS records, and endpoints.
* Cross-reference against `resources/finding_Validation_example.md` (Categories A through F) to formulate concrete exposure hypotheses based on the asset's detected role.
* Sequentially execute the applicable assessment guides from `skills/` (DNS, ports, Zero Trust, admin panels, technology CVEs, JavaScript secrets, API endpoints, Wayback history, and leaked files) against the asset.

### 3. Phase 1: Active Validation & Evidence Collection (6-Step Process)
* Follow the 6-step investigation process:
  1. Establish the Signal
  2. Determine What Is Actually Exposed
  3. Investigate Relevant Security Controls
  4. Dig Deeper When Evidence Warrants It
  5. Establish Impact and Attack Path
  6. Assign Validation Status
* Use `python3 scripts/probe_asset.py <url>` to check connectivity and sensitive endpoints (`/.git/HEAD`, `/actuator`, `/swagger-ui.html`).
* If an administrative login is discovered, execute `python3 scripts/test_admin_auth.py <login_url>` with `resources/top_credentials.json`.
* Adapt testing specifically to detected software using the domain guides in `skills/`.
* When evidence confirms real impact, stop testing that item immediately and mark `[x]` in `checklist.md`.

### 4. Phase 2: Signal Matching & Verification
After the autonomous scanning phase completes and candidate exposures are recorded:
1. **Match Organization Signals with Inventory**:
   * Run the matching query:
     ```bash
     python3 scripts/query_assets.py session-<session_id>/assets.json --signals-file session-<session_id>/signals.json --match-signals
     ```
   * This identifies all assets matching the organization's active detection signals and threat rules.
2. **Inspect & Formulate Signal Hypotheses**:
   * For each matched signal, inspect its rule definition (`description`, `category`, `risk`, `impact`, `remediation`).
   * Formulate a targeted validation check: *Does the matched asset actively exhibit this exposure condition in an accessible, exploitable manner?*
3. **Validate Signals on Matching Assets**:
   * Perform active, safe verification using `scripts/probe_asset.py`, `scripts/test_admin_auth.py`, curl, or service banners.
   * Verify whether the suspected condition constitutes a worthy, impactful security exposure.
   * If the asset is properly protected (behind SSO, TLS enforced, non-sensitive, or unreachable), do NOT raise an exposure.
4. **Register Validated Findings**:
   * For each validated finding that proves demonstrable real-world security impact:
     - Deduplicate against Phase 1 findings and `session-<session_id>/existing_exposures.json`.
     - Add the confirmed finding to the exposure list using the signal context.
   * Update the Phase 2 checklist status in `checklist.md` to `[x]`.

### 5. Prove Impact, Stop & Update Checklist
* Once evidence proves the security boundary is violated and real impact exists: **STOP testing that finding immediately**.
* Never perform destructive actions, alter production data, or attempt lateral persistence.
* Record the finding or mark the asset as cleanly assessed (`[x]`) or offline (`[-]`) in `checklist.md`.

### 6. Format & Output
* Assign a deterministic `exposure_tag` to every finding strictly following the specification in `schema/output_rules.md`. Ensure identical exposures on the same target always produce the exact same tag for ingestion deduplication.
* Verify all candidate findings against `schema/output_rules.md` and `resources/finding_Validation_example.md`.
* Ensure no finding duplicates an entry in `session-<session_id>/existing_exposures.json`.
* Format output as a **raw JSON array** strictly matching `schema/exposure_schema.json` and the constraints in `schema/output_rules.md`.
* Save final results to the results file path specified in the execution prompt. Return `[]` if no verified exposures exist.

---

## Core Principle

> **Understand deeply. Correlate broadly. Hypothesize intelligently. Validate minimally. Prove real impact. Reject speculation. Stop immediately after confirmation.**
