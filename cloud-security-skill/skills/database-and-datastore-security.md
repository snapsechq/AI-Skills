# Database and Datastore Security Auditing Skill

## Objective
Audit and verify cloud-managed database instances, public accessibility, network isolation, encryption in transit, encryption at rest, and backup configurations across:
- **AWS RDS, Aurora, DynamoDB**
- **GCP Cloud SQL & BigQuery**
- **Azure SQL Database & Cosmos DB**
- **Oracle Cloud Infrastructure (OCI) Database Systems**

---

## 1. Amazon Web Services (AWS) RDS

### Key Threat Vectors
- **Public Accessibility**: RDS instance configured with `PubliclyAccessible: true` having a public DNS hostname resolving to an external IP.
- **Permissive Security Groups**: Associated VPC security group contains rules allowing port 3306 (MySQL), 5432 (Postgres), 1433 (MSSQL), or 1521 (Oracle) from `0.0.0.0/0`.
- **Disabled Encryption at Rest**: `StorageEncrypted: false`.
- **Missing SSL/TLS Enforcement**: Parameter group allows plaintext connections (`rds.force_ssl = 0`).

### Verification Commands & APIs
```bash
# 1. Inspect RDS Instance Public Status and Encryption
aws rds describe-db-instances --db-instance-identifier <instance-id> \
  --query "DBInstances[0].[DBInstanceIdentifier,PubliclyAccessible,StorageEncrypted,Endpoint.Address,VpcSecurityGroups]"

# 2. Inspect Associated Security Group Inbound Rules
aws ec2 describe-security-groups --group-ids <sg-id> --query "SecurityGroups[0].IpPermissions"

# 3. Check Parameter Group SSL Settings (e.g. Postgres)
aws rds describe-db-parameters --db-parameter-group-name <group-name> --query "Parameters[?ParameterName=='rds.force_ssl']"
```

---

## 2. Google Cloud Platform (GCP) Cloud SQL

### Key Threat Vectors
- **Public IPv4 Enabled**: Instance configured with public IP address.
- **Authorized Networks Open to All**: `authorizedNetworks` contains CIDR block `0.0.0.0/0` or broad external IP ranges.
- **SSL / TLS Encryption**: `requireSsl` is `false`.

### Verification Commands & APIs
```bash
# 1. Inspect Cloud SQL IP Configuration & Authorized Networks
gcloud sql instances describe <instance-id> \
  --format="json(settings.ipConfiguration.ipv4Enabled,settings.ipConfiguration.authorizedNetworks,settings.ipConfiguration.requireSsl)"
```

---

## 3. Microsoft Azure SQL Database

### Key Threat Vectors
- **Firewall Rule Open to 0.0.0.0/0**: Explicit firewall rule allowing all public IPs (`0.0.0.0` to `255.255.255.255`).
- **Allow Azure Services Bypass**: Special firewall rule `startIpAddress=0.0.0.0` and `endIpAddress=0.0.0.0` that permits **any** tenant in Azure (including malicious third-party Azure subscriptions) to attempt logins.
- **Transparent Data Encryption (TDE)**: Disabled.

### Verification Commands & APIs
```bash
# 1. Inspect Azure SQL Server Firewall Rules
az sql server firewall-rule list --server <server-name> --resource-group <rg-name> --output table

# 2. Check Transparent Data Encryption
az sql db tde show --server <server-name> --database <db-name> --resource-group <rg-name>
```
