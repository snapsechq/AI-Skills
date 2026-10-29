# Storage and Data Exposure Auditing Skill

## Objective
Audit and verify public access, authorization policies, encryption, and logging configurations across cloud object storage services:
- **AWS S3**
- **GCP Cloud Storage (GCS)**
- **Azure Blob Storage**
- **Oracle Cloud Infrastructure (OCI) Object Storage**

---

## 1. Amazon Web Services (AWS) S3

### Key Threat Vectors
- **Public ACLs**: Grants to `AllUsers` (`http://acs.amazonaws.com/groups/global/AllUsers`) or `AuthenticatedUsers`.
- **Public Bucket Policies**: Statements with `Effect: "Allow"`, `Principal: "*"`, and `Action: ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]` lacking IP or VPC conditions.
- **Disabled Block Public Access (BPA)**: Missing at the bucket or account level.
- **CORS Misconfiguration**: `AllowedOrigins: ["*"]` combined with `AllowedMethods: ["PUT", "DELETE"]`.

### Verification Commands & APIs
```bash
# 1. Check Bucket Public Access Block
aws s3api get-public-access-block --bucket <bucket-name>

# 2. Check Account-level Public Access Block (Compensating Control)
aws s3control get-public-access-block --account-id <account-id>

# 3. Check Bucket ACL
aws s3api get-bucket-acl --bucket <bucket-name>

# 4. Check Bucket Policy
aws s3api get-bucket-policy --bucket <bucket-name> --output text | jq .

# 5. Anonymous External Probe
curl -I https://<bucket-name>.s3.<region>.amazonaws.com/
```

### Compensating Controls Check
- If Account-level BPA has `IgnorePublicAcls: true` and `RestrictPublicBuckets: true`, bucket-level ACL and policy findings are **neutralized**.

---

## 2. Google Cloud Platform (GCP) Cloud Storage

### Key Threat Vectors
- **Public IAM Bindings**: Granting `allUsers` or `allAuthenticatedUsers` roles such as `roles/storage.objectViewer`, `roles/storage.objectAdmin`, or `roles/storage.legacyBucketReader`.
- **Disabled Uniform Bucket-Level Access (UBLA)**: Allows legacy ACLs on individual objects.

### Verification Commands & APIs
```bash
# 1. Fetch Bucket IAM Policy
gcloud storage buckets get-iam-policy gs://<bucket-name> --format=json

# 2. Check Uniform Bucket-Level Access
gcloud storage buckets describe gs://<bucket-name> --format="json(iamConfiguration.uniformBucketLevelAccess)"

# 3. Check Organization Policy Constraints
gcloud resource-manager org-policies describe constraints/storage.publicAccessPrevention --project=<project-id>

# 4. Anonymous External Probe
curl -s https://storage.googleapis.com/storage/v1/b/<bucket-name>/o
```

---

## 3. Microsoft Azure Blob Storage

### Key Threat Vectors
- **Storage Account `allowBlobPublicAccess`**: Enabled (`true`), allowing containers to opt-in to public access.
- **Container Public Access Level**: Configured to `Blob` (anonymous read for blobs) or `Container` (anonymous list and read).

### Verification Commands & APIs
```bash
# 1. Inspect Storage Account Setting
az storage account show --name <account-name> --query allowBlobPublicAccess

# 2. Inspect Container Access Level
az storage container show --name <container-name> --account-name <account-name> --query properties.publicAccess

# 3. Anonymous External Probe
curl -I https://<account-name>.blob.core.windows.net/<container-name>/<file-name>
```

---

## 4. Oracle Cloud Infrastructure (OCI) Object Storage

### Key Threat Vectors
- **Public Bucket Visibility**: `public-access-type` set to `ObjectRead` (read objects anonymously) or `ObjectReadWithoutList`.

### Verification Commands & APIs
```bash
# 1. Inspect Bucket Configuration
oci os bucket get --bucket-name <bucket-name> --query 'data."public-access-type"'

# 2. Anonymous External Probe
curl -I https://objectstorage.<region>.oraclecloud.com/n/<namespace>/b/<bucket-name>/o/<file>
```
