# Identity and Access Management (IAM) Auditing Skill

## Objective
Audit and verify permissions, identity hygiene, privilege escalation paths, and access boundaries across:
- **AWS IAM**
- **GCP Cloud IAM**
- **Azure Role-Based Access Control (RBAC) & Entra ID**
- **Oracle Cloud Infrastructure (OCI) IAM**

---

## 1. Amazon Web Services (AWS) IAM

### Key Threat Vectors
- **Root Account Hygiene**: Root access keys active (`AccountAccessKeysPresent > 0`); root login without hardware MFA.
- **Console Access Without MFA**: IAM users with `PasswordLastUsed` populated but 0 registered MFA devices.
- **Overly Permissive Policies**: Managed or inline policies containing `Action: "*"` and `Resource: "*"` (e.g. `AdministratorAccess`) attached to standard developers or workloads.
- **Privilege Escalation Combinations**:
  - `iam:CreatePolicyVersion` & `iam:SetDefaultPolicyVersion` (rewrite policy to allow all).
  - `iam:AttachUserPolicy` / `iam:AttachRolePolicy` (attach admin policy to self).
  - `iam:PutUserPolicy` / `iam:PutRolePolicy` (inject inline admin policy).
  - `iam:PassRole` combined with `lambda:CreateFunction` / `ec2:RunInstances` (escalate via high-privilege service role).
  - `iam:UpdateAssumeRolePolicy` / `sts:AssumeRole`.
- **Dormant Credentials**: Access keys unused for > 90 days.

### Verification Commands & APIs
```bash
# 1. Account Summary & Root Check
aws iam get-account-summary

# 2. List Console Users & MFA Status
aws iam list-users --query "Users[*].[UserName,PasswordLastUsed]"
aws iam list-mfa-devices --user-name <username>

# 3. Check User Access Keys & Last Used
aws iam list-access-keys --user-name <username>
aws iam get-access-key-last-used --access-key-id <key-id>

# 4. Inspect Attached Policies & Policy Versions
aws iam list-attached-user-policies --user-name <username>
aws iam get-policy-version --policy-arn <arn> --version-id <version>
```

---

## 2. Google Cloud Platform (GCP) IAM

### Key Threat Vectors
- **Primitive Roles**: `roles/owner` or `roles/editor` granted to personal Gmail accounts (`@gmail.com`) or standard service accounts.
- **Service Account Key Export**: Unmonitored, long-lived JSON keys exported to developer machines.
- **Service Account Impersonation**: `iam.serviceAccounts.actAs` or `roles/iam.serviceAccountTokenCreator` granted on high-privilege service accounts.
- **Service Account User**: `roles/iam.serviceAccountUser` combined with `compute.instances.create`.

### Verification Commands & APIs
```bash
# 1. Project-level IAM Policy
gcloud projects get-iam-policy <project-id> --format=json

# 2. Inspect Service Account Keys
gcloud iam service-accounts keys list --iam-account=<sa-email>

# 3. Check Organization Policies on Key Creation
gcloud resource-manager org-policies describe constraints/iam.disableServiceAccountKeyCreation --project=<project-id>
```

---

## 3. Microsoft Azure RBAC & Entra ID

### Key Threat Vectors
- **Owner Role at Root/Subscription Scope**: Users or Service Principals possessing `Owner` or `Contributor` across entire subscription.
- **Service Principal Credential Expiry**: Client secrets set with excessive or no expiration.
- **Global Administrator Proliferation**: More than 5 Global Admins in tenant.

### Verification Commands & APIs
```bash
# 1. List Role Assignments for Subscription
az role assignment list --all --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'].{principal:principalName, role:roleDefinitionName, scope:scope}"

# 2. Check Service Principal Password Expiration
az ad app credential list --id <app-id>
```

---

## 4. Oracle Cloud Infrastructure (OCI) IAM

### Key Threat Vectors
- **Tenant-Wide Manage Permissions**: Policies with `Allow group <group> to manage all-resources in tenancy`.
- **API Key Age & Hygiene**: Inactive user API keys.

### Verification Commands & APIs
```bash
# 1. List Tenancy IAM Policies
oci iam policy list --compartment-id <tenancy-ocid>

# 2. Inspect User API Keys
oci iam user api-key list --user-id <user-ocid>
```
