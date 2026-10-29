# Logging, Monitoring, and Audit Auditing Skill

## Objective
Audit and verify cloud audit trails, activity logging, integrity validation, log retention, and storage security across:
- **AWS CloudTrail**
- **GCP Cloud Audit Logs & Log Sinks**
- **Azure Monitor Activity Log & Diagnostic Settings**
- **Oracle Cloud Infrastructure (OCI) Audit Service**

---

## 1. Amazon Web Services (AWS) CloudTrail

### Key Threat Vectors
- **CloudTrail Disabled**: No active trail running in account (`IsLogging: false`).
- **Single-Region Trail**: Trail is restricted to a single region (`IsMultiRegionTrail: false`), allowing attackers to operate undetected in unmonitored regions.
- **Disabled Log File Validation**: `LogFileValidationEnabled: false` allows attackers to tamper with or truncate historical S3 log archives without detection.
- **Log S3 Bucket Vulnerabilities**: Target S3 bucket lacks access logging, object versioning, or allows public access.

### Verification Commands & APIs
```bash
# 1. Describe All Account Trails
aws cloudtrail describe-trails --query "trailList[*].[Name,IsMultiRegionTrail,LogFileValidationEnabled,S3BucketName,KmsKeyId]"

# 2. Check Logging Status of Trail
aws cloudtrail get-trail-status --name <trail-name> --query "IsLogging"

# 3. Check Log Storage S3 Bucket Protection
aws s3api get-bucket-versioning --bucket <trail-s3-bucket>
aws s3api get-public-access-block --bucket <trail-s3-bucket>
```

---

## 2. Google Cloud Platform (GCP) Cloud Audit Logs

### Key Threat Vectors
- **Data Access Logs Disabled**: `DATA_READ` and `DATA_WRITE` logs are disabled by default for Cloud Storage, BigQuery, and IAM.
- **Missing Centralized Sink**: No export sink to BigQuery or Cloud Storage for compliance retention.

### Verification Commands & APIs
```bash
# 1. Inspect Project Audit Config
gcloud projects get-iam-policy <project-id> --format="json(auditConfigs)"

# 2. List Log Sinks
gcloud logging sinks list --format="table(name,destination,filter)"
```

---

## 3. Microsoft Azure Activity Log

### Key Threat Vectors
- **Missing Diagnostic Settings**: Activity Log has no Diagnostic Setting configured to route audit events to Log Analytics Workspace or Event Hub.
- **Short Log Retention**: Retention period configured under 90 days.

### Verification Commands & APIs
```bash
# 1. List Diagnostic Settings on Activity Log
az monitor diagnostic-settings list --resource "/subscriptions/<sub-id>"
```
