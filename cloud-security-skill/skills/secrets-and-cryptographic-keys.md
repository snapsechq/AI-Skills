# Cryptographic Keys and Secrets Auditing Skill

## Objective
Audit and verify cryptographic key management, automated key rotation, key policies, secrets management, and plain-text credential leaks across:
- **AWS KMS & Secrets Manager**
- **GCP Cloud KMS & Secret Manager**
- **Azure Key Vault**
- **Oracle Cloud Infrastructure (OCI) Vault**

---

## 1. Amazon Web Services (AWS) KMS & Secrets

### Key Threat Vectors
- **Disabled Automatic Key Rotation**: Customer Managed Keys (CMKs) without yearly rotation (`KeyRotationEnabled: false`).
- **Overly Permissive Key Policy**: Key policy granting `Principal: "*"` full KMS actions without `Condition` blocks.
- **Plaintext Secrets in VM User Data**: EC2 Launch Templates or instances with database passwords, API tokens, or private keys written into `UserData`.
- **Unencrypted Secrets Manager Secrets**: Secrets encrypted with default KMS key instead of dedicated CMK.

### Verification Commands & APIs
```bash
# 1. Inspect Key Rotation Status
aws kms get-key-rotation-status --key-id <key-id>

# 2. Inspect KMS Key Policy
aws kms get-key-policy --key-id <key-id> --policy-name default --output text | jq .

# 3. Check for Plaintext Secrets in EC2 User Data
aws ec2 describe-instance-attribute --instance-id <instance-id> --attribute userData --query "UserData.Value" --output text | base64 -d
```

---

## 2. Google Cloud Platform (GCP) Cloud KMS

### Key Threat Vectors
- **Public Key Ring IAM Policy**: `allUsers` or `allAuthenticatedUsers` granted `roles/cloudkms.cryptoKeyEncrypterDecrypter`.
- **Excessive Key Rotation Period**: Rotation period set to > 90 or 365 days.

### Verification Commands & APIs
```bash
# 1. Inspect Key IAM Policy
gcloud kms keys get-iam-policy <key-name> --keyring=<keyring> --location=<location>

# 2. Check Key Rotation Schedule
gcloud kms keys describe <key-name> --keyring=<keyring> --location=<location> --format="json(rotationPeriod,nextRotationTime)"
```

---

## 3. Microsoft Azure Key Vault

### Key Threat Vectors
- **Key Vault Public Network Access**: `publicNetworkAccess: "Enabled"` without IP network rules or Private Endpoints.
- **Purge Protection Disabled**: Soft-delete enabled but `enablePurgeProtection` is false, allowing immediate irrevocable destruction of keys.

### Verification Commands & APIs
```bash
# 1. Inspect Key Vault Network ACLs
az keyvault show --name <vault-name> --query "properties.networkAcls"

# 2. Check Soft Delete and Purge Protection
az keyvault show --name <vault-name> --query "properties.[enableSoftDelete,enablePurgeProtection]"
```
