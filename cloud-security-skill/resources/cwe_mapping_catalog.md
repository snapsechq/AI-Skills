# Cloud Misconfiguration to CWE Mapping Catalog

Every finding in `results.json` MUST contain an accurate `cwe` object with valid `name` and `value` (`CWE-<number>`). Use this catalog to map cloud findings to their standard Common Weakness Enumeration identifiers.

---

## Mapping Catalog

| Cloud Finding Category | CWE ID | CWE Standard Name | Typical Severity | Examples |
| :--- | :--- | :--- | :--- | :--- |
| **Public Object Storage** | `CWE-284` | Improper Access Control | Critical / High | S3 Bucket ACL AllUsers READ, GCS allUsers roles/storage.objectViewer, Azure Blob public access enabled, OCI public bucket. |
| **Overly Permissive IAM Policy** | `CWE-732` | Incorrect Permission Assignment for Critical Resource | High | IAM policy with `Action: "*"` and `Resource: "*"`, GCP roles/owner assigned to external user, Azure Owner role at subscription root. |
| **Missing Multi-Factor Auth** | `CWE-308` | Use of Single-factor Authentication | High / Medium | Console user password login enabled without MFA device registered, root user lacking hardware MFA. |
| **Unrestricted Management Ports** | `CWE-1008`| Architectural Compliance Failure | High / Medium | Security Group / NSG / Firewall rule opening port 22 (SSH) or 3389 (RDP) to `0.0.0.0/0`. |
| **Unrestricted Database Port** | `CWE-284` | Improper Access Control | Critical / High | RDS / CloudSQL / Azure SQL listening on public IP with ingress from `0.0.0.0/0`. |
| **Hard-coded Secrets / Keys** | `CWE-798` | Use of Hard-coded Credentials | Critical / High | Plaintext AWS access keys, GCP service account JSON, or database passwords in EC2 user-data or Lambda environment variables. |
| **Disabled Audit Logging** | `CWE-778` | Insufficient Logging | Medium / Low | CloudTrail disabled, CloudTrail single-region only, Cloud Audit data access logs disabled, Azure Activity Log export missing. |
| **Unencrypted Data Storage** | `CWE-311` | Missing Encryption of Sensitive Data | Medium / Low | Unencrypted EBS volume, RDS unencrypted storage, CloudSQL unencrypted instance. |
| **Cleartext Data Transmission**| `CWE-319` | Cleartext Transmission of Sensitive Information | High / Medium | RDS instance without SSL enforcement (`rds.force_ssl=0`), S3 bucket policy lacking `aws:SecureTransport` requirement. |
| **Privilege Escalation Vector** | `CWE-269` | Improper Privilege Management | Critical / High | IAM user permissions allowing `iam:CreateAccessKey` on admin user, or `iam:PassRole` to EC2/Lambda with Administrator access. |
| **Legacy Metadata Service** | `CWE-918` | Server-Side Request Forgery (SSRF) | High | EC2 instance configured with `HttpTokens=optional` (IMDSv1 enabled), exposing metadata to SSRF. |
| **Weak Key Rotation Policy** | `CWE-320` | Key Management Errors | Low / Info | KMS Customer Managed Key without automatic yearly key rotation enabled. |

---

## Strict Schema Construction

In `results.json`, format the `cwe` property as follows:

```json
"cwe": {
  "name": "Improper Access Control",
  "value": "CWE-284"
}
```

Do NOT output plain strings like `"cwe": "CWE-284"`. It MUST be an object containing `name` and `value`.
