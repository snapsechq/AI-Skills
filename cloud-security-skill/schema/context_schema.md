# Cloud Security Context File Specification

The Cloud Security Agent receives an execution context file (e.g. `context-<runId>.json` or `context.json`) staged in the execution directory. This document defines the expected schema, supported cloud providers, credentials structures, and scanner findings formats.

---

## 1. Top-Level Context Structure

```json
{
  "orgId": "org-98765",
  "runId": "run_cloud_sec_1730000000",
  "pentestId": "pen_65b2a1c0e4b023f0a1b2c3d4",
  "scanId": "scan_65b2a1c0e4b023f0a1b2c3d5",
  "cloud_platform": "aws",
  "credentials": {
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "sessionToken": "",
    "region": "us-east-1"
  },
  "scope": {
    "regions": ["us-east-1", "us-west-2"],
    "account_id": "123456789012",
    "excluded_resources": []
  },
  "scanner_findings": [
    {
      "source": "prowler",
      "check_id": "s3_bucket_public_access",
      "service": "s3",
      "severity": "critical",
      "status": "FAIL",
      "resource_id": "arn:aws:s3:::customer-export-bucket",
      "resource_name": "customer-export-bucket",
      "region": "us-east-1",
      "description": "S3 Bucket customer-export-bucket has public access enabled."
    }
  ]
}
```

---

## 2. Cloud Provider Credentials Schemas

The context supports four primary cloud providers via `cloud_platform` (or `provider` / `adapter`):

### A. Amazon Web Services (`aws`)
```json
"credentials": {
  "accessKeyId": "AKIA...",
  "secretAccessKey": "...",
  "sessionToken": "optional-sts-session-token",
  "region": "us-east-1"
}
```

### B. Google Cloud Platform (`gcp`)
```json
"credentials": {
  "projectId": "my-gcp-production-project",
  "serviceAccountKey": "{\"type\": \"service_account\", \"project_id\": \"...\", \"private_key\": \"...\", \"client_email\": \"...\"}"
}
```
*Note: `serviceAccountKey` may be supplied as a raw JSON string or as a parsed JSON object.*

### C. Microsoft Azure (`azure`)
```json
"credentials": {
  "ApplicationID": "00000000-0000-0000-0000-000000000000",
  "KeyValue": "client_secret_value",
  "DirectoryID": "00000000-0000-0000-0000-000000000000",
  "SubscriptionID": "00000000-0000-0000-0000-000000000000"
}
```

### D. Oracle Cloud Infrastructure (`oracle`)
```json
"credentials": {
  "tenancyId": "ocid1.tenancy.oc1..aaaaaaa...",
  "userId": "ocid1.user.oc1..aaaaaaa...",
  "keyFingerprint": "20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34",
  "keyValue": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
  "region": "us-ashburn-1"
}
```

---

## 3. Scanner Findings Formats (`scanner_findings` / `findings`)

The context file contains findings ingested from CSPM scanners:

### Prowler Output Format
```json
{
  "source": "prowler",
  "check_id": "s3_bucket_public_access",
  "check_title": "Check if S3 buckets have public access block enabled",
  "service": "s3",
  "status": "FAIL",
  "severity": "critical",
  "resource_id": "arn:aws:s3:::my-public-bucket",
  "resource_arn": "arn:aws:s3:::my-public-bucket",
  "region": "us-east-1",
  "account_id": "123456789012",
  "description": "Bucket my-public-bucket does not have block public access enabled.",
  "risk": "Public data leakage",
  "remediation": "Enable Account or Bucket-level Block Public Access."
}
```

### CloudSploit Output Format
```json
{
  "source": "cloudsploit",
  "plugin": "s3PublicAccessBlock",
  "category": "S3",
  "status": "FAIL",
  "message": "S3 Block Public Access is disabled for bucket: client-uploads",
  "resource": "arn:aws:s3:::client-uploads",
  "region": "us-west-2"
}
```

### Generic / Unified Format
```json
{
  "id": "finding-101",
  "rule_id": "open-security-group-ssh",
  "service": "ec2",
  "resource_id": "sg-0123456789abcdef0",
  "severity": "high",
  "status": "FAIL",
  "title": "Security Group allows unrestricted ingress to port 22",
  "description": "Port 22 (SSH) open to 0.0.0.0/0",
  "region": "us-east-1"
}
```
