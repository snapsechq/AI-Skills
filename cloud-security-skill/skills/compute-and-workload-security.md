# Compute and Workload Security Auditing Skill

## Objective
Audit and verify virtual machine instances, metadata services, volume encryption, and managed Kubernetes clusters across:
- **AWS EC2 & EKS**
- **GCP Compute Engine & GKE**
- **Azure Virtual Machines & AKS**
- **Oracle Cloud Infrastructure (OCI) Compute & OKE**

---

## 1. Instance Metadata Service (IMDS) Auditing

### Attack Vector: IMDSv1 SSRF Vulnerability
On cloud virtual machines, the Instance Metadata Service (at `169.254.169.254`) allows software on the instance to query temporary credentials (IAM role credentials).
- **IMDSv1**: Accessible via simple unauthenticated HTTP `GET` requests (`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`). A single Server-Side Request Forgery (SSRF) flaw in a web application hosted on the VM allows external attackers to steal the instance IAM role!
- **IMDSv2**: Session-oriented. Requires an HTTP `PUT` request with a specific header (`X-aws-ec2-metadata-token-ttl-seconds`) to generate a secret token before querying metadata. Defends against SSRF.

### AWS Verification
```bash
# Check if IMDSv2 is enforced on EC2 Instance
aws ec2 describe-instances --instance-ids <instance-id> --query "Reservations[0].Instances[0].MetadataOptions"
# Finding confirmed if: HttpTokens == "optional" and HttpEndpoint == "enabled"
# Remediated if: HttpTokens == "required"
```

### GCP Verification
```bash
# Check if legacy metadata endpoints are disabled
gcloud compute project-info describe --format="json(commonInstanceMetadata)"
# Finding confirmed if disable-legacy-endpoints != "true"
```

---

## 2. Block Storage (EBS / Persistent Disk) Encryption

### AWS EBS Encryption
```bash
# Check if EBS default encryption is enabled for region
aws ec2 get-ebs-encryption-by-default

# Check individual volume encryption status
aws ec2 describe-volumes --volume-ids <volume-id> --query "Volumes[0].[Encrypted,KmsKeyId]"
```

### GCP Persistent Disk Encryption
```bash
# Verify disk encryption type (Google-managed vs Customer-managed KMS)
gcloud compute disks describe <disk-name> --zone=<zone> --format="json(diskEncryptionKey)"
```

---

## 3. Managed Kubernetes Cluster API Endpoint Exposure

### AWS EKS Endpoint Security
- **Threat Vector**: EKS API server endpoint open to public internet (`endpointPublicAccess=true`) with unrestricted CIDRs (`publicAccessCidrs=["0.0.0.0/0"]`).
```bash
aws eks describe-cluster --name <cluster-name> --query "cluster.resourcesVpcConfig.[endpointPublicAccess,endpointPrivateAccess,publicAccessCidrs]"
# Finding confirmed if endpointPublicAccess == true and publicAccessCidrs contains "0.0.0.0/0"
```

### GCP GKE Control Plane Exposure
```bash
gcloud container clusters describe <cluster-name> --format="json(privateClusterConfig,masterAuthorizedNetworksConfig)"
# Finding confirmed if privateClusterConfig.enablePrivateEndpoint == false and masterAuthorizedNetworksConfig.enabled == false
```
