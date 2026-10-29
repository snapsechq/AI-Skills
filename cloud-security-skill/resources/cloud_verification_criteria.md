# Cloud Finding Verification & False-Positive Elimination Criteria

Automated CSPM scanners (e.g., Prowler, CloudSploit) identify potential configuration violations, but frequently produce **false positives** or flag compliance hygiene issues that have zero real-world exploitability.

The Cloud Security Agent MUST independently verify every finding against live cloud configuration before reporting it in `results.json`.

---

## 1. Finding Evaluation Hierarchy

Every finding is evaluated across four stages:

```
[Scanner Finding]
       │
       ▼
1. Resource Existence Verification (Does the resource currently exist in the cloud account?)
       │
       ▼
2. Direct Misconfiguration Verification (Is the specific setting active on the resource?)
       │
       ▼
3. Compensating Control Analysis (Do higher-level controls neutralize the issue?)
       │
       ▼
4. Real-World Attack Path & Impact Validation (Can an attacker exploit this boundary?)
       │
       ├─► CONFIRMED & IMPACTFUL ──► Include in results.json
       └─► REJECTED / MITIGATED ───► Exclude (Document in cloud_test_checklist.md as [-])
```

---

## 2. Compensating Controls Matrix (False Positive Triggers)

A scanner alert MUST be marked as a **False Positive** or **Compensated** if any of the following guardrails are active:

### A. Storage / S3 / Blob Scenarios
| Scanner Finding | Compensating Guardrail (Disqualifier) | Outcome |
| :--- | :--- | :--- |
| S3 Bucket ACL grants Read to AllUsers | AWS Account-level S3 Block Public Access has `IgnorePublicAcls=true` and `BlockPublicAcls=true`. | **REJECTED**: AWS completely ignores the bucket ACL at the service boundary. |
| S3 Bucket has public bucket policy | AWS Account-level S3 Block Public Access has `RestrictPublicBuckets=true` and `BlockPublicPolicy=true`. | **REJECTED**: Public policy evaluation is blocked at the account perimeter. |
| GCP Storage bucket lacks IAM binding | GCP Organization Policy `constraints/storage.publicAccessPrevention` is enforced. | **REJECTED**: Cloud Storage denies all public access requests regardless of bucket ACL. |
| Azure Storage container public access level set to 'Blob' | Azure Storage Account has `allowBlobPublicAccess=false`. | **REJECTED**: Storage account setting overrides container-level permission. |
| S3 Bucket unencrypted | AWS S3 defaults to SSE-S3 (AES-256) encryption automatically for all objects since January 2023. | **REJECTED** unless custom KMS CMK or client encryption requirement was mandated. |

### B. Network / Security Group Scenarios
| Scanner Finding | Compensating Guardrail (Disqualifier) | Outcome |
| :--- | :--- | :--- |
| Security Group allows `0.0.0.0/0` on port 22/3389 | Security Group is unattached to any active Network Interface (ENI), Instance, or Load Balancer. | **REJECTED**: Dead security group cannot be reached or exploited. |
| Security Group allows `0.0.0.0/0` on port 22 | Attached instance is deployed in an isolated private subnet with NO Internet Gateway (IGW) route and NO public IP assigned. | **DOWNGRADE TO LOW / REJECT**: Unreachable from external internet. |
| GCP Firewall rule allows `0.0.0.0/0` on port 22 | Rule has a target tag that matches zero compute engine instances in the VPC. | **REJECTED**: Firewall rule is dormant and inactive. |
| Security Group allows `0.0.0.0/0` on port 80/443 | Port is serving public web application behind an AWS WAF and Application Load Balancer. | **REJECTED**: Intended public ingress with protective controls. |

### C. IAM / Identity Scenarios
| Scanner Finding | Compensating Guardrail (Disqualifier) | Outcome |
| :--- | :--- | :--- |
| IAM User has `AdministratorAccess` policy | User is bound by an IAM Permission Boundary or AWS Organization SCP denying critical actions. | **ADJUST SCOPE**: Impact is bounded by SCP ceiling. |
| IAM User missing MFA | User has NO console password (`PasswordLastUsed=null`) and has NO access keys created (`AccessKeyMetadata=[]`). | **REJECTED**: Inactive, dormant placeholder account without credentials. |
| GCP Service Account has Editor role | GCP Organization Policy `constraints/iam.disableServiceAccountKeyCreation` prevents external key export. | **REDUCE SEVERITY**: Key cannot be exfiltrated off-cloud. |

---

## 3. Strict Rejection Criteria (What is NOT a Finding)

The following conditions MUST NOT be reported as vulnerabilities:
1. **Dormant / Unused Resources**: Orphaned security groups with no instances, empty test S3 buckets with no files or traffic, terminated EC2 instances.
2. **Standard Cloud Default Behavior Without Exposure**: AWS default VPC present without any launched instances; EBS default encryption status if all actual active volumes are KMS-encrypted.
3. **Intentional Public Architecture**: Public website buckets hosting static documentation (`index.html`), public API gateway endpoints designed for unauthenticated user onboarding.
4. **Theoretical Compliance Flags Without Threat Vector**: A CloudTrail trail that logs 98% of services but misses a non-critical event; absence of tag policies.
5. **Scanner Check Mismatches**: Tool flagged resource X because of an outdated API version or failure to parse newer IAM condition operators (`StringEquals`, `aws:PrincipalArn`).
