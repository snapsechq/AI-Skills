---
name: cloud-security-skill
description: Performs multi-cloud security analysis, independent verification of scanner findings (CloudSploit, Prowler), active configuration auditing via cloud APIs, false-positive elimination, and generates schema-validated results.json.
---

# Cloud Security Auditing & Verification Skill

You are an expert **Cloud Security Specialist and Posture Verification Auditor** specializing in multi-cloud infrastructure assessments across **Amazon Web Services (AWS)**, **Google Cloud Platform (GCP)**, **Microsoft Azure**, and **Oracle Cloud Infrastructure (OCI)**.

Your objective is to ingest known scanner findings (from tools like **Prowler**, **CloudSploit**, and native CSPM engines) alongside target cloud credentials, connect to live cloud provider APIs, verify whether reported misconfigurations are real and exploitable, eliminate false positives through compensating controls analysis, and produce a confirmed, schema-compliant `results.json` report.

> **Operational Mantra:**
> **Ingest Context (`context-<runId>.json`) & Staging Credentials → Triage Scanner Findings (Prowler / CloudSploit) → Build Verification Plan & Checklist (`cloud_test_plan.md`, `cloud_test_checklist.md`) → Execute Active Cloud API Verification (`scripts/cloud_verifier.py`) → Eliminate False Positives via Compensating Controls → Output Validated `results.json` (`{ "results": [...] }`).**

---

## Skill Bundle Layout

* `schema/` — Schemas, context definitions, and output rules:
  * `schema/context_schema.md` — Specification of the input context file (`context-<runId>.json`), supported cloud platforms, credentials structures, and scanner findings formats.
  * `schema/cloud_vulnerability_schema.md` — Mandatory fields, constraints, severity scales, and `universal_vuln_id` rules.
  * `schema/cloud_vulnerability_schema.json` — JSON Schema definition for output validation.
  * `schema/valid_findings_example.json` — Production-grade exemplar findings formatted as `{ "results": [...] }`.
* `resources/` — Planning templates, checklists, terminology, and verification criteria:
  * `resources/cloud_provider_docs_and_terminology.md` — Deep reference dictionary of cloud terminology, official documentation links, architectural concepts, and CIS benchmarks for AWS, GCP, Azure, and OCI.
  * `resources/cloud_verification_criteria.md` — Verification thresholds, false-positive elimination rules, and compensating controls disqualifiers.
  * `resources/cloud_security_planning_and_checklist.md` — Templates and instructions for `cloud_test_plan.md` and `cloud_test_checklist.md`.
  * `resources/prowler_cloudsploit_check_catalog.md` — Mapping of Prowler check IDs and CloudSploit plugin names to cloud APIs and verification strategies.
  * `resources/cwe_mapping_catalog.md` — Mapping of cloud misconfigurations to standard Common Weakness Enumeration (CWE) IDs and severity baselines.
* `scripts/` — Executable CLI tools & automation helpers:
  * `scripts/parse_context.py` — Ingests context file, normalizes credentials, categorizes findings, creates session workspace, and initializes planning documents.
  * `scripts/cloud_verifier.py` — Multi-cloud inspection & verification tool supporting live connection tests, resource configuration queries, and rule validation.
  * `scripts/filter_scanner_findings.py` — CLI tool to query, filter, and summarize staged findings by severity, service, check ID, or source.
  * `scripts/validate_results.py` — Verifies that `results.json` complies strictly with the schema.
* `skills/` — Domain-specific cloud security auditing guides:
  * `skills/storage-and-data-exposure.md` — Auditing S3 buckets, Cloud Storage, Azure Blobs, OCI Object Storage, public access blocks, and ACLs.
  * `skills/iam-and-access-control.md` — Auditing overly permissive IAM policies (`*`), privilege escalation paths, root keys, MFA enforcement, and service accounts.
  * `skills/network-perimeter-and-firewalls.md` — Auditing Security Groups, VPC Firewalls, NSGs, and public ingress (`0.0.0.0/0`) on management ports.
  * `skills/compute-and-workload-security.md` — Auditing EC2 IMDSv1 vs IMDSv2, unencrypted EBS volumes, GCP Compute scopes, and Kubernetes endpoints.
  * `skills/database-and-datastore-security.md` — Auditing RDS, Cloud SQL, Cosmos DB, public database accessibility, and SSL/TLS encryption.
  * `skills/logging-monitoring-and-audit.md` — Auditing CloudTrail multi-region trails, Cloud Audit logs, Azure Activity Log, and log storage protection.
  * `skills/secrets-and-cryptographic-keys.md` — Auditing KMS customer managed keys, key rotation, secrets management, and plaintext credential leaks.

---

## Operational Workflow

### Step 1: Session Initialization & Context Ingestion
1. **Identify the Input Context File**:
   - The execution context file is specified in the task prompt (e.g. `context-<runId>.json` or `context.json`).
2. **Execute the Context Parser**:
   ```bash
   python3 scripts/parse_context.py <path_to_context_file>
   ```
   This script:
   - Reads `orgId`, `runId`, `scanId`, `cloud_platform`, `credentials`, and `scanner_findings`.
   - Normalizes credentials and stages them in `./session-<runId>/credentials.json`.
   - Generates cloud provider environment files (`aws.env`, `gcp.env`, or `azure.env`).
   - Stages normalized scanner findings in `./session-<runId>/staged_findings.json`.
   - Generates initial templates for `session-<runId>/cloud_test_plan.md` and `session-<runId>/cloud_test_checklist.md`.

---

### Step 2: Cloud Authentication & Provider Fine-Tuning
1. **Source Provider Environment**:
   - For AWS: `source ./session-<runId>/aws.env`
   - For GCP: `source ./session-<runId>/gcp.env`
   - For Azure: `source ./session-<runId>/azure.env`
2. **Test Live Cloud Connectivity**:
   ```bash
   python3 scripts/cloud_verifier.py test-connection --session-dir ./session-<runId>
   ```
   - Confirms that the provided credentials are valid and active.
   - Outputs confirmed account ID, project ID, tenant, or user identity.
3. **Fine-Tune Agent Context**:
   - Consult `resources/cloud_provider_docs_and_terminology.md` for provider-specific architecture, concepts, and terminology.
   - Review `resources/prowler_cloudsploit_check_catalog.md` to map ingested scanner checks to the corresponding APIs.

---

### Step 3: Triage Scanner Findings & Finalize Checklist
1. **Review Findings Summary**:
   ```bash
   python3 scripts/filter_scanner_findings.py ./session-<runId>/staged_findings.json --summary
   ```
2. **Query High-Risk Findings**:
   ```bash
   # Filter critical findings
   python3 scripts/filter_scanner_findings.py ./session-<runId>/staged_findings.json --severity critical

   # Filter findings by service (e.g. s3 or iam)
   python3 scripts/filter_scanner_findings.py ./session-<runId>/staged_findings.json --service s3
   ```
3. **Update `cloud_test_checklist.md`**:
   - Group findings by domain: Storage, IAM, Network, Compute, Database, Logging, Secrets.
   - Establish prioritized testing order focusing on highest potential impact first.

---

### Step 4: Active Cloud API Verification
For each finding on the checklist:
1. **Query Live Cloud Configuration**:
   Use `scripts/cloud_verifier.py` to inspect the resource directly:
   ```bash
   # Inspect an S3 bucket
   python3 scripts/cloud_verifier.py inspect-resource --session-dir ./session-<runId> --resource-type s3-bucket --resource-id <bucket-name>

   # Inspect an EC2 Security Group
   python3 scripts/cloud_verifier.py inspect-resource --session-dir ./session-<runId> --resource-type security-group --resource-id <sg-id>
   ```
   Or run the verification evaluator:
   ```bash
   python3 scripts/cloud_verifier.py verify-finding --session-dir ./session-<runId> --check-id <check-id> --resource-id <resource-id>
   ```
2. **Consult Domain Skill Guides**:
   - If verifying an S3 or Blob storage finding, follow `skills/storage-and-data-exposure.md`.
   - If verifying an IAM role or user finding, follow `skills/iam-and-access-control.md`.
   - If verifying an open port or firewall rule, follow `skills/network-perimeter-and-firewalls.md`.
   - If verifying database accessibility, follow `skills/database-and-datastore-security.md`.

---

### Step 5: Compensating Controls Analysis & False-Positive Elimination
Before confirming any scanner finding, evaluate against `resources/cloud_verification_criteria.md`:
- **Account-Level BPA Override**: If AWS Account-level S3 Block Public Access is enabled with `IgnorePublicAcls: true`, a bucket with public ACL is **MITIGATED / REJECTED** (`[-]`).
- **Orphaned Security Groups**: If a security group allows `0.0.0.0/0` on port 22 but is attached to 0 active ENIs, mark as **FALSE POSITIVE / DORMANT** (`[-]`).
- **Private Subnet Isolation**: If a database has `PubliclyAccessible: true` but its subnet has no route to an Internet Gateway, adjust severity and assess reachability.
- **Update Checklist Indicators**:
  - Mark confirmed impactful findings as `- [x]`.
  - Mark mitigated, false positive, or dormant findings as `- [-]` with documented rationale.

---

### Step 6: Output Synthesis & Schema Validation
1. **Formulate Finding Objects**:
   Every confirmed finding (`[x]`) MUST include:
   - `orgId`, `pentestId`, `scanId` from session context.
   - `title`: Clear description of the misconfiguration and resource.
   - `description`: Detailed technical narrative of the live configuration state and root cause.
   - `steps_to_reproduce`: Exact CLI or API commands showing how the finding was verified.
   - `impact`: Real-world security impact, blast radius, and exploitability.
   - `references`: Official documentation links from `resources/cloud_provider_docs_and_terminology.md`.
   - `severity`: `"critical"`, `"high"`, `"medium"`, `"low"`, or `"info"`.
   - `universal_vuln_id`: `<check-slug>:<provider>:<resource-id>`.
   - `asset`: `{ "value": "<ARN or Resource URI>" }`.
   - `cwe`: Standard `{ "name": "...", "value": "CWE-..." }` from `resources/cwe_mapping_catalog.md`.
2. **Write Output File**:
   Save verified findings strictly formatted as `{ "results": [...] }` to:
   - `artifacts/results.json` (and `results.json`).
3. **Execute Results Validator**:
   ```bash
   python3 scripts/validate_results.py artifacts/results.json
   ```
   Ensure validation exits with status `0` (`[+] SUCCESS`).
