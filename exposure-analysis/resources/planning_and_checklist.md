# Planning & Checklist Specification

When initiating the exposure analysis, the agent must initialize an isolated session directory and generate two foundational documents before performing any active testing.

---

## 1. Session Isolation

* Create/use the dedicated session folder: `./session-<session_id>/` (or the folder specified in the execution context).
* All intermediate notes, `plan.md`, `checklist.md`, and temporary test artifacts must reside inside this isolated directory.
* This guarantees that concurrent agent runs operating in the same workspace never overwrite each other's state.

---

## 2. Checklist Document (`checklist.md`)

The checklist enforces **100% attack-surface coverage**.

### Extraction Rules:
1. Read the provided dataset JSON file.
2. Extract **every unique subdomain, hostname, and IP address**.
3. Group or list every asset with its associated metadata (known ports, services, technologies).
4. Use standard markdown checkboxes:
   - `- [ ]` Pending assessment
   - `- [~]` Assessment in progress
   - `- [x]` Completed assessment (live, tested, results recorded)
   - `- [-]` Unreachable / inactive (verified offline)

### Checklist Structure:
```markdown
# Attack Surface Coverage Checklist
Session ID: <session_id>
Target Dataset: <data_file.json>
Total Assets Identified: <count>
Total Signals Identified: <signal_count>

## Summary Progress
- [ ] Phase 1 Assessed (Autonomous Scan): 0 / <count>
- [ ] Phase 2 Assessed (Signal Validation): 0 / <signal_count>
- Confirmed Exposures Found: 0

## Phase 1: Asset Inventory & Status (Autonomous Scan)

### Subdomains & Hostnames
- [ ] `app.example.com`
  - IP(s): `192.0.2.1`
  - Ports: 80, 443
  - Detected Tech: Nginx, React, Node.js
  - Status / Finding: Pending
- [ ] `admin.example.com`
  - IP(s): `192.0.2.2`
  - Ports: 443, 8443
  - Detected Tech: Spring Boot
  - Status / Finding: Pending

### Standalone IPs & Infrastructure
- [ ] `192.0.2.10`
  - Ports: 22, 6379, 9200
  - Detected Tech: Redis, Elasticsearch
  - Status / Finding: Pending

## Phase 2: Organization Signals & Matching Assets Validation

- [ ] Signal: `Exposed Elasticsearch Instance`
  - Matched Asset(s): `192.0.2.10:9200`
  - Rule Severity: High
  - Status / Finding: Pending
- [ ] Signal: `Public Management / Admin Console`
  - Matched Asset(s): `admin.example.com:8443`
  - Rule Severity: High
  - Status / Finding: Pending
```

---

## 3. Planning Document (`plan.md`)

The plan defines the structured operational strategy for systematically validating the assets identified in the checklist across two distinct phases.

### Required Plan Sections:
1. **Scope & Objectives**: Summary of the attack surface, volume of assets, signals loaded, and critical target domains/IPs.
2. **Prioritization Strategy**:
   - Order in which assets are tested in Phase 1 (e.g. exposed admin panels, sensitive APIs, databases, followed by standard web hosts).
   - High-value hypotheses based on technologies detected in the dataset.
3. **Phase 1: Autonomous Asset Testing Procedure**:
   - Step 1: Select next unchecked asset from `checklist.md`.
   - Step 2: Correlate ports, IPs, endpoints, and technology details from the JSON dataset.
   - Step 3: Form specific attack hypotheses (e.g. unauthenticated access, default credentials, exposed metadata).
   - Step 4: Validate hypothesis with non-destructive tools (`scripts/probe_asset.py`, `scripts/test_admin_auth.py`, curl, httpx).
   - Step 5: If exposure confirmed, record details and mark `[x]` in `checklist.md`. If offline, mark `[-]`.
4. **Phase 2: Signal Matching & Validation Procedure**:
   - Step 1: Query matching signals using `python3 scripts/query_assets.py session-<session_id>/assets.json --signals-file session-<session_id>/signals.json --match-signals`.
   - Step 2: For each matched signal-asset pair, formulate a validation check based on the signal's rule definition, category, and impact.
   - Step 3: Actively probe the matched asset to verify whether the condition highlighted by the signal exists and constitutes a worthy, impactful security exposure.
   - Step 4: If verified and not already captured in Phase 1 or present in existing exposures, add it to the exposure findings list.
   - Step 5: Mark the signal check as `[x]` in `checklist.md`.
5. **Boundary & Safety Rules**: Explicit limits to ensure safe, non-destructive testing.
