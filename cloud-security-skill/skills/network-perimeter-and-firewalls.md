# Network Perimeter and Firewalls Auditing Skill

## Objective
Audit and verify network ingress rules, virtual firewalls, exposed management interfaces, and perimeter boundaries across:
- **AWS Security Groups & Network ACLs**
- **GCP VPC Firewall Rules**
- **Azure Network Security Groups (NSGs)**
- **Oracle Cloud Infrastructure (OCI) Security Lists**

---

## 1. High-Risk Ingress Ports (Must NOT be open to 0.0.0.0/0 or ::/0)

| Port | Protocol / Service | Real-World Attack Vector | Typical Severity |
| :--- | :--- | :--- | :--- |
| **22** | SSH (Secure Shell) | Automated brute-forcing, credential stuffing, SSH daemon exploits. | High |
| **3389** | RDP (Remote Desktop Protocol) | BlueKeep (CVE-2019-0708), ransomware entry point, brute force. | Critical / High |
| **3306** | MySQL Database | Direct unauthenticated network connection, brute-force root access. | Critical |
| **5432** | PostgreSQL Database | Remote authentication attempts, database enumeration. | Critical |
| **27017** | MongoDB | Unauthenticated datastore exposure, ransomware wiping. | Critical |
| **6379** | Redis In-Memory Cache | Remote code execution via unauthorized write (authorized_keys). | Critical |
| **9200** | Elasticsearch REST API | Direct cluster indices extraction and unauthenticated deletion. | Critical |
| **8080 / 8443** | Management Panels (Jenkins, Tomcat) | Web application panel takeover, unauthenticated admin API. | High |
| **All / -1** | Any Protocol / Any Port | Complete bypass of host firewall protection. | Critical |

---

## 2. Amazon Web Services (AWS) Security Groups

### Verification Protocol
1. **Locate Security Group**: Inspect rules for `IpProtocol == "-1"` or target port with `CidrIp: "0.0.0.0/0"` or `CidrIpv6: "::/0"`.
2. **Check Active ENI Attachment**: An unattached security group is a **False Positive / Dormant** finding.
3. **Check Routing & Public Reachability**:
   - Check if attached instance has a `PublicIpAddress` or Elastic IP.
   - Check if instance subnet has a Route Table entry to an Internet Gateway (`igw-xxxx`).

### Commands & APIs
```bash
# 1. Inspect Security Group Inbound Permissions
aws ec2 describe-security-groups --group-ids <sg-id> --query "SecurityGroups[0].IpPermissions"

# 2. Check Attached Network Interfaces (ENIs)
aws ec2 describe-network-interfaces --filters "Name=group-id,Values=<sg-id>" --query "NetworkInterfaces[*].[NetworkInterfaceId,Association.PublicIp,PrivateIpAddress]"

# 3. Check Subnet Routing (Internet Gateway verification)
aws ec2 describe-route-tables --filters "Name=association.subnet-id,Values=<subnet-id>" --query "RouteTables[*].Routes[?GatewayId!=null]"
```

---

## 3. Google Cloud Platform (GCP) VPC Firewall Rules

### Verification Protocol
1. Filter rules with `direction: "INGRESS"`, `action: "ALLOW"`, and `sourceRanges` containing `0.0.0.0/0`.
2. Check `targetTags` or `targetServiceAccounts`:
   - If target tags exist, verify if any active Compute Engine instances have those tags.
   - If no target tags exist, the rule applies to **all instances** in the VPC network!

### Commands & APIs
```bash
# 1. Query Inbound 0.0.0.0/0 Rules
gcloud compute firewall-rules list --filter="direction=INGRESS AND allowed.ports:(22 OR 3389 OR 3306 OR 5432 OR 27017) AND sourceRanges:0.0.0.0/0" --format=json

# 2. Verify Target Instances with Matching Tags
gcloud compute instances list --filter="tags.items:<target-tag>" --format="table(name,networkInterfaces[0].accessConfigs[0].natIP)"
```

---

## 4. Microsoft Azure Network Security Groups (NSGs)

### Verification Protocol
1. Review inbound rules with `access: "Allow"`, `direction: "Inbound"`, and `sourceAddressPrefix: "*"`.
2. Check NSG association: attached to Subnet vs Network Interface (NIC).
3. Check Public IP address assigned to associated VM NICs.

### Commands & APIs
```bash
# 1. List Inbound Allow Rules
az network nsg rule list --nsg-name <nsg-name> --resource-group <rg-name> --query "[?access=='Allow' && direction=='Inbound' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet')]"

# 2. Check Attached Subnets and NICs
az network nsg show --name <nsg-name> --resource-group <rg-name> --query "{subnets:subnets[*].id, nics:networkInterfaces[*].id}"
```
