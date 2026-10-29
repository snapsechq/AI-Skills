# Cloud Provider Documentation & Terminology Reference

This guide provides the Cloud Security Agent with the official documentation links, architectural concepts, API references, and terminology needed to navigate and audit AWS, GCP, Microsoft Azure, and Oracle Cloud Infrastructure (OCI).

---

## 1. Amazon Web Services (AWS)

### Core Architecture & Terminology
- **ARN (Amazon Resource Name)**: Unique resource identifier formatted as `arn:partition:service:region:account-id:resource-id`.
- **IAM Policies**: JSON identity or resource-based policies defining `Effect` (`Allow`/`Deny`), `Action` (e.g. `s3:GetObject`), `Resource`, and `Condition`.
- **Service Control Policies (SCPs)**: Guardrails set at the AWS Organizations level that define the maximum permissions for member accounts.
- **Permission Boundaries**: Advanced IAM feature that limits the maximum permissions an identity-based policy can grant to a principal.
- **Security Groups (SG)**: Stateful virtual firewalls controlling inbound and outbound traffic at the ENI (Elastic Network Interface) level. Default rule allows all outbound, blocks all inbound.
- **Network ACLs (NACL)**: Stateless subnet-level firewalls processed in numbered rule order before traffic reaches security groups.
- **S3 Block Public Access (BPA)**: Four-tier control (at account or bucket level) that prevents public ACLs and public bucket policies regardless of IAM rules.
- **IMDSv2 (Instance Metadata Service Version 2)**: Session-oriented metadata retrieval service mitigating SSRF attacks on EC2 by requiring a `PUT` token before metadata access.
- **KMS (Key Management Service)**: Managed cryptographic service providing Customer Managed Keys (CMKs) and AWS Managed Keys with automatic rotation.

### Authoritative AWS Documentation Links
| Service / Area | Documentation Link |
| :--- | :--- |
| **AWS Security Hub & CIS** | https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-gems.html |
| **AWS Well-Architected Security** | https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html |
| **AWS S3 Security & Public Access** | https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html |
| **AWS IAM Best Practices & Policies** | https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html |
| **AWS EC2 Security Groups Reference** | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html |
| **AWS CloudTrail Multi-Region Logging**| https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html |
| **AWS KMS Key Policies & Rotation** | https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html |
| **AWS RDS Security & Encryption** | https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.html |

---

## 2. Google Cloud Platform (GCP)

### Core Architecture & Terminology
- **Resource Hierarchy**: Organization &rarr; Folders &rarr; Projects &rarr; Resources. Permissions inherit downward.
- **Cloud IAM**: Bindings between `members` (`user:`, `serviceAccount:`, `group:`, `domain:`, `allUsers`, `allAuthenticatedUsers`) and predefined/custom `roles` containing permissions.
- **Primitive Roles**: Legacy roles (`roles/owner`, `roles/editor`, `roles/viewer`) with broad privileges across all project resources. Considered an anti-pattern.
- **Organization Policies**: Centralized constraints enforced across the hierarchy (e.g. `constraints/compute.restrictPublicIp`, `constraints/iam.disableServiceAccountKeyCreation`).
- **Uniform Bucket-Level Access (UBLA)**: Disables legacy object-level ACLs, unifying access control under Cloud IAM exclusively.
- **VPC Service Controls (VPC SC)**: Creates security perimeters around multi-tenant Google APIs (Cloud Storage, BigQuery) to prevent data exfiltration.
- **VPC Firewall Rules**: Global rules evaluated by priority (0–65535) with direction (INGRESS/EGRESS), target tags, service accounts, and IP ranges.
- **Cloud Audit Logs**: Admin Activity logs (enabled by default) and Data Access logs (disabled by default due to volume).

### Authoritative GCP Documentation Links
| Service / Area | Documentation Link |
| :--- | :--- |
| **GCP Security Foundations Guide** | https://cloud.google.com/architecture/security-foundations |
| **GCP CIS Foundations Benchmark** | https://cloud.google.com/security/compliance/cis-gcp-foundation-benchmark |
| **Cloud IAM Roles & Permissions** | https://cloud.google.com/iam/docs/understanding-roles |
| **Cloud Storage Access Control** | https://cloud.google.com/storage/docs/access-control |
| **VPC Firewall Rules Overview** | https://cloud.google.com/firewall/docs/firewalls-overview |
| **Cloud Audit Logs Overview** | https://cloud.google.com/logging/docs/audit |
| **Cloud KMS Key Management** | https://cloud.google.com/kms/docs/overview |
| **Cloud SQL Security & Encryption** | https://cloud.google.com/sql/docs/mysql/security |

---

## 3. Microsoft Azure

### Core Architecture & Terminology
- **Azure Management Hierarchy**: Management Groups &rarr; Subscriptions &rarr; Resource Groups &rarr; Resources.
- **Microsoft Entra ID (Azure AD)**: Identity provider managing users, groups, service principals, managed identities, and app registrations.
- **Azure RBAC**: Role definitions (`Reader`, `Contributor`, `Owner`, or Custom) assigned to principals over a specific `Scope` (Subscription, RG, or Resource).
- **Network Security Groups (NSG)**: Stateful packet filtering containing prioritized Security Rules (100–4096) attached to subnets or individual NICs.
- **Azure Storage `allowBlobPublicAccess`**: Account-level toggle controlling whether anonymous public read requests are accepted by any container in the storage account.
- **Azure Key Vault**: Hardware security module (HSM) backed store for Keys, Secrets, and Certificates with Access Policies or RBAC permissions.
- **Azure Activity Log & Diagnostic Settings**: Platform-level event audit stream recording ARM management operations.

### Authoritative Azure Documentation Links
| Service / Area | Documentation Link |
| :--- | :--- |
| **Microsoft Cloud Security Benchmark** | https://learn.microsoft.com/en-us/security/benchmark/azure/introduction |
| **Azure Storage Anonymous Access** | https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure |
| **Azure RBAC Built-in Roles** | https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles |
| **Network Security Groups (NSG)** | https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview |
| **Azure Key Vault Best Practices** | https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices |
| **Azure Monitor & Activity Log** | https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log |
| **Azure SQL Database Security** | https://learn.microsoft.com/en-us/azure/azure-sql/database/security-overview |

---

## 4. Oracle Cloud Infrastructure (OCI)

### Core Architecture & Terminology
- **Tenancy**: Root partition assigned to an organization representing the entire cloud footprint.
- **Compartments**: Logical containers for organizing and isolating cloud resources; policies define access per compartment.
- **OCI IAM Policies**: Declarative statements syntax: `Allow <subject> to <verb> <resource-type> in <location> where <conditions>`. Verbs: `inspect`, `read`, `use`, `manage`.
- **Security Lists & Network Security Groups**: Virtual firewall rules for VCN subnets (Security Lists) or specific VNICs (NSGs).
- **Object Storage Bucket Visibility**: `Public` (anonymous GET/LIST permitted) vs `Private` (authenticated requests only).
- **OCI Vault**: Key Management Service providing envelope encryption with AES, RSA, and ECDSA Master Encryption Keys (MEKs).

### Authoritative OCI Documentation Links
| Service / Area | Documentation Link |
| :--- | :--- |
| **OCI CIS Benchmark Overview** | https://docs.oracle.com/en-us/iaas/Content/Security/Reference/cis_benchmark.htm |
| **OCI IAM Policy Reference** | https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/policyreference.htm |
| **OCI Object Storage Security** | https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm |
| **OCI Security Lists & NSGs** | https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm |
| **OCI Audit Service Overview** | https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/auditoverview.htm |
