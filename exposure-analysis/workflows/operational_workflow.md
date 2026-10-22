
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


2. **Query Attack Surface & Build `checklist.md`**:
   * Run `python3 scripts/query_assets.py session-<session_id>/assets.json --list-subdomains` and `--list-ips`.
   * Add **every single subdomain, hostname, and IP** to Phase 1 of `session-<session_id>/checklist.md`.
   * Review signals with `python3 scripts/query_assets.py session-<session_id>/signals.json --signals` and add matching signals to Phase 2 of `checklist.md`.
   * Maintain status checkboxes (`[ ]` Pending, `[~]` In Progress, `[x]` Assessed, `[-]` Inactive) to ensure 100% full attack surface and signal coverage.


3. **Build `plan.md`**:
   * Review existing known exposures with `python3 scripts/query_assets.py session-<session_id>/existing_exposures.json --exposures` to avoid duplicate findings.
   * Review detected technologies with `python3 scripts/query_assets.py session-<session_id>/assets.json --technologies`.
   * Layout the two-phase testing workflow:
     - **Phase 1**: Autonomous attack surface scanning across all assets using `resources/methodology.md` and `resources/accepted_issues.md`.
     - **Phase 2**: Signal-driven validation matching organization signals against inventory using `query_assets.py --match-signals`.
   * Consult `resources/planning_and_checklist.md` and `resources/dataset_schema.md`.



### 2. Phase 1: Systematic Asset Iteration & Hypothesis Formulation
* Pick the next pending item from `checklist.md` (Phase 1).
* Query its full profile: `python3 scripts/query_assets.py session-<session_id>/assets.json --get-asset <subdomain_or_ip>`.
* Extract correlated open ports, service versions, tech stack, and endpoints.
* Cross-reference against `resources/accepted_issues.md` (Categories A through F: Zero Trust, Internet Exposure, Auth/Access, Backend Services, Boundaries, Info Disclosure).
* Formulate concrete attack hypotheses tailored to the detected asset role.

### 3. Phase 1: Active Validation & Evidence Collection (6-Step Process)
* Follow the 6-step investigation process defined in `resources/methodology.md`:
  1. Establish the Signal
  2. Determine What Is Actually Exposed
  3. Investigate Relevant Security Controls
  4. Dig Deeper When Evidence Warrants It
  5. Establish Impact and Attack Path
  6. Assign Validation Status
* Use `python3 scripts/probe_asset.py <url>` to check connectivity and sensitive endpoints (`/.git/HEAD`, `/actuator`, `/swagger-ui.html`).
* If an administrative login is discovered, execute `python3 scripts/test_admin_auth.py <login_url>` with `resources/top_credentials.json`.
* Adapt testing specifically to detected software (see `resources/testing_guide.md`).
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
* Assign a deterministic `exposure_tag` to every finding strictly following the specification in `resources/exposure-tags.md`. Ensure identical exposures on the same target always produce the exact same tag for ingestion deduplication.
* Verify all candidate findings against `resources/output_rules.md`, `resources/methodology.md`, and `examples/rejected_findings.md`.
* Ensure no finding duplicates an entry in `session-<session_id>/existing_exposures.json`.
* Format output as a **raw JSON array** strictly matching `resources/exposure_schema.json` and the constraints in `resources/output_rules.md`.
* Save final results to the results file path specified in the execution prompt. Return `[]` if no verified exposures exist.

---

## Core Principle

> **Understand deeply. Correlate broadly. Hypothesize intelligently. Validate minimally. Prove real impact. Reject speculation. Stop immediately after confirmation.**
