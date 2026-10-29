# Prowler and CloudSploit Check ID Mapping Catalog

This catalog maps known scanner check identifiers from **Prowler** and **CloudSploit** to their corresponding cloud provider APIs, CLI commands, and active verification strategies.

---

## 1. Amazon Web Services (AWS)

| Scanner Check Identifier | Cloud Service | Verification CLI / API Call | Verification Strategy |
| :--- | :--- | :--- | :--- |
| **`s3_bucket_public_access`** (Prowler)<br>**`s3PublicAccessBlock`** (CloudSploit) | S3 | `aws s3api get-public-access-block --bucket <bucket>`<br>`aws s3control get-public-access-block --account-id <acc>` | Check if all 4 settings (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) are `true`. If false, inspect bucket ACL and policy. |
| **`s3_bucket_acl_prohibited`** (Prowler)<br>**`bucketAllUsersRead`** (CloudSploit) | S3 | `aws s3api get-bucket-acl --bucket <bucket>` | Look for `Grantee.URI` containing `AllUsers` or `AuthenticatedUsers` with `READ` / `WRITE` permissions. |
| **`s3_bucket_policy_public_write_access`** (Prowler)<br>**`bucketPolicyPublicWrite`** (CloudSploit) | S3 | `aws s3api get-bucket-policy --bucket <bucket>` | Parse Policy JSON. Check `Principal: "*"` or `Principal: { "AWS": "*" }` with `Effect: "Allow"` and write actions (`s3:PutObject`) without `Condition` restrictions. |
| **`ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`** (Prowler)<br>**`openSSH`** (CloudSploit) | EC2 | `aws ec2 describe-security-groups --group-ids <sg-id>` | Inspect `IpPermissions`. Check for `FromPort <= 22 <= ToPort` with `CidrIp: "0.0.0.0/0"` or `CidrIpv6: "::/0"`. Check if SG is attached to running instances with public IPs. |
| **`ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389`** (Prowler)<br>**`openRDP`** (CloudSploit) | EC2 | `aws ec2 describe-security-groups --group-ids <sg-id>` | Check for Port 3389 open to `0.0.0.0/0`. Verify active instance attachment. |
| **`ec2_securitygroup_allow_ingress_from_internet_to_all_ports`** (Prowler)<br>**`openAllPortsProtocols`** (CloudSploit) | EC2 | `aws ec2 describe-security-groups --group-ids <sg-id>` | Look for `IpProtocol: "-1"` with `CidrIp: "0.0.0.0/0"`. |
| **`iam_root_access_key_check`** (Prowler)<br>**`rootAccountInUse`** (CloudSploit) | IAM | `aws iam get-account-summary`<br>`aws iam list-access-keys` | Check `AccountAccessKeysPresent > 0`. Root account must not possess active access keys. |
| **`iam_user_mfa_enabled_console_access`** (Prowler)<br>**`passwordRequiresMFA`** (CloudSploit) | IAM | `aws iam list-mfa-devices --user-name <user>`<br>`aws iam get-login-profile --user-name <user>` | If console login is enabled (`get-login-profile` succeeds), verify `list-mfa-devices` returns >= 1 device. |
| **`iam_policy_allows_privilege_escalation`** (Prowler)<br>**`iamPrivilegeEscalation`** (CloudSploit) | IAM | `aws iam get-policy-version --policy-arn <arn> --version-id <v>` | Search for dangerous action combinations: `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:PassRole` + `lambda:CreateFunction`, `iam:AttachUserPolicy`. |
| **`cloudtrail_multi_region_enabled`** (Prowler)<br>**`cloudtrailMultiRegion`** (CloudSploit) | CloudTrail | `aws cloudtrail describe-trails`<br>`aws cloudtrail get-trail-status --name <trail>` | Verify `IsMultiRegionTrail: true`, `IncludeGlobalServiceEvents: true`, and `IsLogging: true`. |
| **`rds_instance_publicly_accessible`** (Prowler)<br>**`rdsPubliclyAccessible`** (CloudSploit) | RDS | `aws rds describe-db-instances --db-instance-identifier <id>` | Check `PubliclyAccessible: true` AND check associated VPC Security Groups for external ingress. |

---

## 2. Google Cloud Platform (GCP)

| Scanner Check Identifier | Cloud Service | Verification CLI / API Call | Verification Strategy |
| :--- | :--- | :--- | :--- |
| **`storage_bucket_public_access`** (Prowler)<br>**`bucketPublicAccess`** (CloudSploit) | Cloud Storage | `gcloud storage buckets get-iam-policy gs://<bucket>` | Check IAM bindings for `allUsers` or `allAuthenticatedUsers` with `roles/storage.objectViewer` or `roles/storage.admin`. Verify Org Policy `publicAccessPrevention`. |
| **`iam_service_account_user_role`** (Prowler)<br>**`serviceAccountKeyRotation`** (CloudSploit) | Cloud IAM | `gcloud iam service-accounts keys list --iam-account <sa>` | Inspect `validBeforeTime`. Keys older than 90 days should be rotated or removed. |
| **`compute_firewall_open_ssh`** (Prowler)<br>**`openSSH`** (CloudSploit) | Compute Engine | `gcloud compute firewall-rules list --filter="allowed.ports:22"` | Inspect `sourceRanges: ["0.0.0.0/0"]`, `direction: "INGRESS"`, and `targetTags` against active instances. |
| **`sql_instance_public_ip`** (Prowler)<br>**`cloudSqlPubliclyAccessible`** (CloudSploit) | Cloud SQL | `gcloud sql instances describe <instance>` | Check `settings.ipConfiguration.ipv4Enabled: true` and `authorizedNetworks` containing `0.0.0.0/0`. |

---

## 3. Microsoft Azure

| Scanner Check Identifier | Cloud Service | Verification CLI / API Call | Verification Strategy |
| :--- | :--- | :--- | :--- |
| **`storage_ensure_blob_public_access_is_disabled`** (Prowler)<br>**`blobPublicAccess`** (CloudSploit) | Blob Storage | `az storage account show --name <account> --query allowBlobPublicAccess` | Verify return value. If `true`, inspect container public access settings. |
| **`network_nsg_open_port_22`** (Prowler)<br>**`openSSH`** (CloudSploit) | Virtual Network | `az network nsg rule list --nsg-name <nsg> --resource-group <rg>` | Inspect rules with `access: "Allow"`, `direction: "Inbound"`, `sourceAddressPrefix: "*"`, and `destinationPortRange: "22"`. |
| **`sql_server_firewall_rule_open_to_internet`** (Prowler)<br>**`sqlPublicAccess`** (CloudSploit) | Azure SQL | `az sql server firewall-rule list --server <server> --resource-group <rg>` | Look for rule with `startIpAddress: "0.0.0.0"` and `endIpAddress: "255.255.255.255"` (or `0.0.0.0` for Azure internal bypass). |

---

## 4. Oracle Cloud Infrastructure (OCI)

| Scanner Check Identifier | Cloud Service | Verification CLI / API Call | Verification Strategy |
| :--- | :--- | :--- | :--- |
| **`object_storage_bucket_public_access`** | Object Storage | `oci os bucket get --bucket-name <bucket>` | Check `public-access-type`. Values `ObjectRead` or `ObjectReadWithoutList` mean public exposure. |
| **`security_list_ingress_rules_open_ssh`** | Networking | `oci network security-list get --security-list-id <id>` | Inspect `ingress-security-rules` for `source: "0.0.0.0/0"` with `destination-port-range` covering 22. |
