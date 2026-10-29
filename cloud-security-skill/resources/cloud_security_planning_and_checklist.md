# Cloud Security Planning and Checklist Specification

The Cloud Security Agent operates deterministically through isolated session planning documents:
- `session-<runId>/cloud_test_plan.md`
- `session-<runId>/cloud_test_checklist.md`

These documents guarantee 100% audit coverage of all ingested scanner findings and provide an auditable record of verification decisions.

---

## 1. Cloud Test Plan Template (`cloud_test_plan.md`)

```markdown
# Cloud Security Verification Plan

## Session Overview
- **Run ID**: {runId}
- **Org ID**: {orgId}
- **Cloud Provider**: {cloud_platform} (AWS / GCP / Azure / OCI)
- **Target Scope**: Account/Project {accountId_or_projectId}, Regions: {regions}
- **Total Ingested Scanner Findings**: {count}

## Testing Objectives
1. Verify credentials and establish live read-only cloud API session.
2. Triage scanner findings (Prowler / CloudSploit) into domain categories:
   - Storage & Data Exposure (S3, GCS, Azure Blobs, OCI Buckets)
   - Identity & Access Management (IAM Policies, Service Accounts, MFA, Keys)
   - Network Perimeter & Firewalls (Security Groups, Firewalls, NSGs)
   - Compute & Workloads (EC2, VMs, Kubernetes, IMDS)
   - Databases & Data Stores (RDS, CloudSQL, Cosmos, DynamoDB)
   - Logging, Monitoring & Audit (CloudTrail, Cloud Audit, Activity Logs)
   - Cryptographic Keys & Secrets (KMS, Key Vault, Secrets Manager)
3. Execute active API queries using `scripts/cloud_verifier.py` to inspect resource configuration.
4. Eliminate false positives via Compensating Controls analysis.
5. Generate verified `results.json` adhering to the vulnerability schema.

## Verification Order & Prioritization
1. **Critical Storage & Data Exposure** (immediate public data leaks)
2. **Critical Network Listeners** (administrative ports open to 0.0.0.0/0)
3. **High-Privilege IAM Anomalies** (unrestricted AdministratorAccess, root keys)
4. **Database Public Exposure** (database endpoints accessible from internet)
5. **Compute & Workload Misconfigurations** (legacy IMDSv1, unencrypted disks)
6. **Logging & Cryptographic Hygiene** (disabled trails, unrotated keys)
```

---

## 2. Cloud Test Checklist Template (`cloud_test_checklist.md`)

Every finding ingested from the context file MUST have a corresponding entry in `cloud_test_checklist.md`.

### Status Indicators
- `- [ ]` **Pending**: Finding queued for verification.
- `- [~]` **In Progress**: Active API inspection and rule evaluation ongoing.
- `- [x]` **Confirmed Finding**: Verified misconfiguration with real-world security impact. Transcribed to `results.json`.
- `- [-]` **Rejected / False Positive**: Mitigated by compensating controls, dormant resource, or scanner error. Document rejection rationale.

### Template Structure
```markdown
# Cloud Security Verification Checklist

## Phase 1: Authentication & Scope Verification
- [ ] Verify cloud credentials via STS GetCallerIdentity / GCP OAuth / Azure ARM / OCI GetTenancy.
- [ ] Enumerate active regions and confirmed account boundary.

## Phase 2: Storage & Data Exposure Verification
- [ ] [Prowler-s3-01] S3 Bucket 'customer-export-bucket' - Public Read ACL & Block Public Access
  - Resource: `arn:aws:s3:::customer-export-bucket`
  - Verification API: `s3api get-public-access-block`, `s3api get-bucket-acl`
  - Result: Confirmed (All BlockPublic settings false, AllUsers READ granted) -> [x]
- [ ] [CloudSploit-S3-04] S3 Bucket 'internal-ci-cache' - Missing Object Encryption
  - Resource: `arn:aws:s3:::internal-ci-cache`
  - Verification API: `s3api get-bucket-encryption`
  - Result: Rejected (SSE-S3 default active, no sensitive compliance requirement) -> [-]

## Phase 3: Network Perimeter & Security Groups
- [ ] [Prowler-ec2-02] Security Group 'sg-0a1b2c3d4e5f67890' - Inbound 0.0.0.0/0 on port 22
  - Resource: `sg-0a1b2c3d4e5f67890`
  - Verification API: `ec2 describe-security-groups`, `ec2 describe-instances`
  - Result: Confirmed (Attached to active bastion with public IP) -> [x]
- [ ] [CloudSploit-EC2-12] Security Group 'sg-deadbeef' - Inbound 0.0.0.0/0 on port 3389
  - Resource: `sg-deadbeef`
  - Verification API: `ec2 describe-network-interfaces --filters Name=group-id,Values=sg-deadbeef`
  - Result: Rejected (0 ENIs attached, orphaned test security group) -> [-]

## Phase 4: Identity & Access Management (IAM)
- [ ] [Prowler-iam-01] IAM User 'deployer' - Missing MFA
- [ ] [Prowler-iam-08] Root Account Access Key Active

## Phase 5: Results Synthesis & Schema Validation
- [ ] Compile confirmed findings into `session-<runId>/staged_results.json`.
- [ ] Run `python3 scripts/validate_results.py artifacts/results.json`.
- [ ] Verify 100% of checklist items are marked either `[x]` or `[-]`.
```
