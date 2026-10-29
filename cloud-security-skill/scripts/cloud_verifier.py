#!/usr/bin/env python3
"""
Multi-Cloud Security Verifier CLI
Connects to AWS, GCP, Azure, and Oracle OCI using supplied credentials
to inspect live cloud resource configurations and verify security findings.
"""

import sys
import os
import json
import argparse
import subprocess
import urllib.request
import urllib.error
import hmac
import hashlib
import datetime
import re

# ==============================================================================
# Helper & Credential Loader
# ==============================================================================

def load_session_credentials(session_dir=None):
    """Loads staged credentials from session-dir/credentials.json or environment."""
    creds_file = None
    if session_dir and os.path.exists(os.path.join(session_dir, "credentials.json")):
        creds_file = os.path.join(session_dir, "credentials.json")
    else:
        # Search current or parent directory for session-*
        for item in os.listdir("."):
            if item.startswith("session-") and os.path.isdir(item):
                candidate = os.path.join(item, "credentials.json")
                if os.path.exists(candidate):
                    creds_file = candidate
                    break

    if creds_file and os.path.exists(creds_file):
        with open(creds_file, "r", encoding="utf-8") as f:
            return json.load(f)

    # Fallback to environment
    platform = os.environ.get("CLOUD_PLATFORM") or ("aws" if os.environ.get("AWS_ACCESS_KEY_ID") else "gcp" if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") else "unknown")
    return {
        "cloud_platform": platform,
        "credentials": {
            "accessKeyId": os.environ.get("AWS_ACCESS_KEY_ID"),
            "secretAccessKey": os.environ.get("AWS_SECRET_ACCESS_KEY"),
            "sessionToken": os.environ.get("AWS_SESSION_TOKEN"),
            "region": os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        }
    }

def run_cmd(cmd_list, env=None):
    """Executes a subprocess command safely and returns (stdout, stderr, exit_code)."""
    try:
        proc = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            env=env or os.environ.copy()
        )
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except FileNotFoundError:
        return "", f"Command not found: {cmd_list[0]}", 127
    except Exception as e:
        return "", str(e), 1

# ==============================================================================
# AWS Provider Engine
# ==============================================================================

class AwsVerifier:
    def __init__(self, creds):
        self.access_key = creds.get("accessKeyId") or creds.get("access_key") or os.environ.get("AWS_ACCESS_KEY_ID")
        self.secret_key = creds.get("secretAccessKey") or creds.get("secret_key") or os.environ.get("AWS_SECRET_ACCESS_KEY")
        self.session_token = creds.get("sessionToken") or os.environ.get("AWS_SESSION_TOKEN")
        self.region = creds.get("region") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"

    def get_env(self):
        env = os.environ.copy()
        if self.access_key: env["AWS_ACCESS_KEY_ID"] = self.access_key
        if self.secret_key: env["AWS_SECRET_ACCESS_KEY"] = self.secret_key
        if self.session_token: env["AWS_SESSION_TOKEN"] = self.session_token
        env["AWS_DEFAULT_REGION"] = self.region
        env["AWS_REGION"] = self.region
        return env

    def test_connection(self):
        # 1. Try AWS CLI if available
        out, err, code = run_cmd(["aws", "sts", "get-caller-identity", "--output", "json"], env=self.get_env())
        if code == 0 and out:
            try:
                data = json.loads(out)
                return True, {
                    "provider": "aws",
                    "account": data.get("Account"),
                    "arn": data.get("Arn"),
                    "userId": data.get("UserId"),
                    "method": "aws-cli"
                }
            except Exception:
                pass

        # 2. Try boto3 if available
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                aws_session_token=self.session_token,
                region_name=self.region
            )
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            return True, {
                "provider": "aws",
                "account": identity.get("Account"),
                "arn": identity.get("Arn"),
                "userId": identity.get("UserId"),
                "method": "boto3"
            }
        except ImportError:
            pass
        except Exception as e:
            return False, {"provider": "aws", "error": str(e)}

        # 3. Pure Python SigV4 STS request (zero dependencies fallback)
        try:
            return self._sigv4_sts_caller_identity()
        except Exception as e:
            return False, {"provider": "aws", "error": f"Credentials validation error: {e}"}

    def _sigv4_sts_caller_identity(self):
        if not self.access_key or not self.secret_key:
            return False, {"provider": "aws", "error": "Missing AWS accessKeyId or secretAccessKey"}

        host = f"sts.{self.region}.amazonaws.com"
        endpoint = f"https://{host}/"
        body = "Action=GetCallerIdentity&Version=2011-06-15"
        t = datetime.datetime.now(datetime.timezone.utc)
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')

        canonical_uri = '/'
        canonical_querystring = ''
        canonical_headers = f'content-type:application/x-www-form-urlencoded\nhost:{host}\nx-amz-date:{amzdate}\n'
        signed_headers = 'content-type;host;x-amz-date'
        payload_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()
        canonical_request = f"POST\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{datestamp}/{self.region}/sts/aws4_request"
        string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        kDate = sign(('AWS4' + self.secret_key).encode('utf-8'), datestamp)
        kRegion = sign(kDate, self.region)
        kService = sign(kRegion, 'sts')
        kSigning = sign(kService, 'aws4_request')
        signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        auth_header = f"{algorithm} Credential={self.access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': host,
            'x-amz-date': amzdate,
            'Authorization': auth_header
        }
        if self.session_token:
            headers['x-amz-security-token'] = self.session_token

        req = urllib.request.Request(endpoint, data=body.encode('utf-8'), headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8')
            acc_match = re.search(r'<Account>(\d+)</Account>', content)
            arn_match = re.search(r'<Arn>(.+?)</Arn>', content)
            userId_match = re.search(r'<UserId>(.+?)</UserId>', content)
            return True, {
                "provider": "aws",
                "account": acc_match.group(1) if acc_match else "unknown",
                "arn": arn_match.group(1) if arn_match else "unknown",
                "userId": userId_match.group(1) if userId_match else "unknown",
                "method": "sigv4-native"
            }

    def inspect_s3_bucket(self, bucket_name):
        bucket_name = bucket_name.replace("arn:aws:s3:::", "").strip()
        env = self.get_env()
        # 1. Block Public Access
        out_bpa, _, code_bpa = run_cmd(["aws", "s3api", "get-public-access-block", "--bucket", bucket_name, "--output", "json"], env=env)
        # 2. Bucket ACL
        out_acl, _, _ = run_cmd(["aws", "s3api", "get-bucket-acl", "--bucket", bucket_name, "--output", "json"], env=env)
        # 3. Bucket Policy
        out_pol, _, _ = run_cmd(["aws", "s3api", "get-bucket-policy", "--bucket", bucket_name, "--output", "json"], env=env)

        # Parse or default
        bpa_config = json.loads(out_bpa) if code_bpa == 0 and out_bpa else {"PublicAccessBlockConfiguration": "Disabled/Missing"}
        acl_config = json.loads(out_acl) if out_acl else {}
        policy_config = json.loads(out_pol) if out_pol else {}

        # Anonymous probe check
        is_publicly_readable = False
        try:
            probe_url = f"https://{bucket_name}.s3.{self.region}.amazonaws.com/"
            req = urllib.request.Request(probe_url, headers={"User-Agent": "SnapSecCloudProbe/1.0"})
            with urllib.request.urlopen(req, timeout=5) as res:
                if res.status in [200, 204]:
                    is_publicly_readable = True
        except urllib.error.HTTPError as e:
            if e.code == 403:
                is_publicly_readable = False
        except Exception:
            pass

        return {
            "bucket": bucket_name,
            "public_access_block": bpa_config,
            "acl": acl_config,
            "policy": policy_config,
            "anonymous_probe_readable": is_publicly_readable
        }

    def inspect_security_group(self, sg_id):
        env = self.get_env()
        out, err, code = run_cmd(["aws", "ec2", "describe-security-groups", "--group-ids", sg_id, "--output", "json"], env=env)
        if code != 0 or not out:
            return {"error": err or f"Cannot describe security group {sg_id}"}
        data = json.loads(out)
        sgs = data.get("SecurityGroups", [])
        if not sgs:
            return {"error": f"Security group {sg_id} not found"}

        # Also check attached network interfaces
        out_eni, _, _ = run_cmd(["aws", "ec2", "describe-network-interfaces", "--filters", f"Name=group-id,Values={sg_id}", "--output", "json"], env=env)
        enis = json.loads(out_eni).get("NetworkInterfaces", []) if out_eni else []

        return {
            "security_group": sgs[0],
            "attached_interfaces_count": len(enis),
            "attached_interfaces": [{"id": e.get("NetworkInterfaceId"), "public_ip": e.get("Association", {}).get("PublicIp")} for e in enis]
        }

# ==============================================================================
# GCP Provider Engine
# ==============================================================================

class GcpVerifier:
    def __init__(self, creds):
        self.project_id = creds.get("projectId") or creds.get("project_id") or os.environ.get("CLOUDSDK_CORE_PROJECT")
        self.sa_key = creds.get("serviceAccountKey")

    def test_connection(self):
        if not self.sa_key and not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            return False, {"provider": "gcp", "error": "Missing serviceAccountKey or GOOGLE_APPLICATION_CREDENTIALS"}

        # 1. Try gcloud CLI
        out, err, code = run_cmd(["gcloud", "auth", "list", "--format=json"])
        if code == 0 and out:
            try:
                accounts = json.loads(out)
                active = [a for a in accounts if a.get("status") == "ACTIVE"]
                return True, {
                    "provider": "gcp",
                    "project": self.project_id,
                    "active_account": active[0].get("account") if active else "unknown",
                    "method": "gcloud-cli"
                }
            except Exception:
                pass

        # 2. Try google-auth / googleapiclient
        try:
            from google.oauth2 import service_account
            from google.auth.transport.requests import Request
            key_dict = self.sa_key if isinstance(self.sa_key, dict) else json.loads(self.sa_key) if isinstance(self.sa_key, str) else {}
            credentials = service_account.Credentials.from_service_account_info(
                key_dict,
                scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
            )
            credentials.refresh(Request())
            return True, {
                "provider": "gcp",
                "project": self.project_id or key_dict.get("project_id"),
                "client_email": key_dict.get("client_email"),
                "token_valid": credentials.valid,
                "method": "google-auth"
            }
        except ImportError:
            pass
        except Exception as e:
            return False, {"provider": "gcp", "error": str(e)}

        # 3. Structural validation fallback
        if self.sa_key:
            try:
                key_dict = self.sa_key if isinstance(self.sa_key, dict) else json.loads(self.sa_key)
                if key_dict.get("client_email") and key_dict.get("private_key"):
                    return True, {
                        "provider": "gcp",
                        "project": self.project_id or key_dict.get("project_id"),
                        "client_email": key_dict.get("client_email"),
                        "method": "structural-validation"
                    }
            except Exception as e:
                return False, {"provider": "gcp", "error": f"Invalid GCP key JSON: {e}"}

        return False, {"provider": "gcp", "error": "Unable to verify GCP credentials"}

    def inspect_storage_bucket(self, bucket_name):
        bucket_name = bucket_name.replace("gs://", "").strip()
        out, err, code = run_cmd(["gcloud", "storage", "buckets", "get-iam-policy", f"gs://{bucket_name}", "--format=json"])
        if code == 0 and out:
            try:
                policy = json.loads(out)
                bindings = policy.get("bindings", [])
                public_bindings = [b for b in bindings if "allUsers" in b.get("members", []) or "allAuthenticatedUsers" in b.get("members", [])]
                return {
                    "bucket": bucket_name,
                    "iam_policy": policy,
                    "has_public_bindings": len(public_bindings) > 0,
                    "public_bindings": public_bindings
                }
            except Exception:
                pass

        # Anonymous probe check
        probe_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o"
        try:
            req = urllib.request.Request(probe_url, headers={"User-Agent": "SnapSecCloudProbe/1.0"})
            with urllib.request.urlopen(req, timeout=5) as res:
                return {"bucket": bucket_name, "anonymous_probe_readable": res.status == 200}
        except urllib.error.HTTPError as e:
            return {"bucket": bucket_name, "anonymous_probe_readable": False, "http_status": e.code}
        except Exception as e:
            return {"bucket": bucket_name, "error": str(e)}

# ==============================================================================
# Azure Provider Engine
# ==============================================================================

class AzureVerifier:
    def __init__(self, creds):
        self.app_id = creds.get("ApplicationID") or creds.get("clientId")
        self.secret = creds.get("KeyValue") or creds.get("clientSecret")
        self.tenant_id = creds.get("DirectoryID") or creds.get("tenantId")
        self.sub_id = creds.get("SubscriptionID") or creds.get("subscriptionId")

    def test_connection(self):
        if not self.app_id or not self.secret or not self.tenant_id:
            return False, {"provider": "azure", "error": "Missing ApplicationID, KeyValue, or DirectoryID"}

        # 1. Try Azure CLI login
        login_cmd = [
            "az", "login", "--service-principal",
            "-u", self.app_id, "-p", self.secret, "--tenant", self.tenant_id,
            "--output", "json"
        ]
        out, err, code = run_cmd(login_cmd)
        if code == 0 and out:
            try:
                subs = json.loads(out)
                return True, {
                    "provider": "azure",
                    "tenant_id": self.tenant_id,
                    "subscriptions": [s.get("id") for s in subs],
                    "method": "az-cli"
                }
            except Exception:
                pass

        # 2. Pure Python OAuth token acquisition via Azure Entra ID token endpoint
        try:
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            payload = urllib.parse.urlencode({
                "grant_type": "client_credentials",
                "client_id": self.app_id,
                "client_secret": self.secret,
                "scope": "https://management.azure.com/.default"
            }).encode("utf-8")

            req = urllib.request.Request(token_url, data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                token_data = json.loads(resp.read().decode("utf-8"))
                return True, {
                    "provider": "azure",
                    "tenant_id": self.tenant_id,
                    "token_type": token_data.get("token_type"),
                    "expires_in": token_data.get("expires_in"),
                    "method": "azure-oauth-token"
                }
        except urllib.error.HTTPError as e:
            return False, {"provider": "azure", "error": f"Azure authentication failed (HTTP {e.code}): {e.read().decode('utf-8')}"}
        except Exception as e:
            return False, {"provider": "azure", "error": str(e)}

# ==============================================================================
# Oracle Provider Engine
# ==============================================================================

class OracleVerifier:
    def __init__(self, creds):
        self.tenancy_id = creds.get("tenancyId")
        self.user_id = creds.get("userId")
        self.key_fingerprint = creds.get("keyFingerprint")
        self.key_value = creds.get("keyValue")
        self.region = creds.get("region", "us-ashburn-1")

    def test_connection(self):
        if not self.tenancy_id or not self.user_id or not self.key_fingerprint or not self.key_value:
            return False, {"provider": "oracle", "error": "Missing Oracle OCI tenancyId, userId, keyFingerprint, or keyValue"}

        # Try OCI Python SDK if available
        try:
            import oci
            config = {
                "user": self.user_id,
                "key_file": None,
                "fingerprint": self.key_fingerprint,
                "tenancy": self.tenancy_id,
                "region": self.region
            }
            # Normalize private key
            pem = self.key_value.replace("\\n", "\n") if isinstance(self.key_value, str) else self.key_value
            signer = oci.signer.Signer(
                tenancy=self.tenancy_id,
                user=self.user_id,
                fingerprint=self.key_fingerprint,
                private_key_content=pem
            )
            identity = oci.identity.IdentityClient(config={}, signer=signer)
            tenancy = identity.get_tenancy(self.tenancy_id)
            return True, {
                "provider": "oracle",
                "tenancy_id": tenancy.data.id,
                "tenancy_name": tenancy.data.name,
                "method": "oci-sdk"
            }
        except ImportError:
            # Structural validation
            if "BEGIN RSA PRIVATE KEY" in self.key_value or "BEGIN PRIVATE KEY" in self.key_value:
                return True, {
                    "provider": "oracle",
                    "tenancy_id": self.tenancy_id,
                    "user_id": self.user_id,
                    "method": "structural-validation"
                }
        except Exception as e:
            return False, {"provider": "oracle", "error": str(e)}

        return False, {"provider": "oracle", "error": "Unable to verify Oracle OCI credentials"}

# ==============================================================================
# CLI Entrypoint
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Multi-Cloud Security Verifier CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: test-connection
    p_conn = subparsers.add_parser("test-connection", help="Test live connection to cloud provider")
    p_conn.add_argument("--session-dir", help="Path to session directory containing credentials.json")

    # Subcommand: inspect-resource
    p_insp = subparsers.add_parser("inspect-resource", help="Inspect cloud resource configuration")
    p_insp.add_argument("--session-dir", help="Path to session directory")
    p_insp.add_argument("--resource-type", required=True, choices=["s3-bucket", "security-group", "gcs-bucket", "azure-storage", "raw"])
    p_insp.add_argument("--resource-id", required=True, help="Resource identifier (bucket name, SG ID, etc.)")

    # Subcommand: verify-finding
    p_ver = subparsers.add_parser("verify-finding", help="Verify a specific scanner finding against cloud state")
    p_ver.add_argument("--session-dir", help="Path to session directory")
    p_ver.add_argument("--check-id", required=True, help="Check ID (e.g. s3_bucket_public_access)")
    p_ver.add_argument("--resource-id", required=True, help="Resource ID")
    p_ver.add_argument("--service", default="general", help="Service name")

    # Subcommand: batch-verify
    p_batch = subparsers.add_parser("batch-verify", help="Batch verify all staged findings in session directory")
    p_batch.add_argument("--session-dir", help="Path to session directory")
    p_batch.add_argument("--output", default=None, help="Output JSON report path")

    args = parser.parse_args()

    session_data = load_session_credentials(getattr(args, "session_dir", None))
    platform = session_data.get("cloud_platform", "aws").lower()
    credentials = session_data.get("credentials", {})

    # Select provider
    verifier = None
    if platform == "aws":
        verifier = AwsVerifier(credentials)
    elif platform == "gcp":
        verifier = GcpVerifier(credentials)
    elif platform == "azure":
        verifier = AzureVerifier(credentials)
    elif platform == "oracle":
        verifier = OracleVerifier(credentials)
    else:
        print(f"[!] Unsupported cloud platform: '{platform}'")
        sys.exit(1)

    # Dispatch Command
    if args.command == "test-connection":
        ok, res = verifier.test_connection()
        if ok:
            print("[+] Connection SUCCESSFUL:")
            print(json.dumps(res, indent=2))
            sys.exit(0)
        else:
            print("[!] Connection FAILED:")
            print(json.dumps(res, indent=2))
            sys.exit(1)

    elif args.command == "inspect-resource":
        res_type = args.resource_type
        res_id = args.resource_id
        print(f"[*] Inspecting {res_type}: {res_id} on {platform.upper()}...")

        if platform == "aws":
            if res_type == "s3-bucket":
                res = verifier.inspect_s3_bucket(res_id)
            elif res_type == "security-group":
                res = verifier.inspect_security_group(res_id)
            else:
                res = {"error": f"Unsupported resource type {res_type} for AWS"}
        elif platform == "gcp":
            if res_type in ["gcs-bucket", "s3-bucket"]:
                res = verifier.inspect_storage_bucket(res_id)
            else:
                res = {"error": f"Unsupported resource type {res_type} for GCP"}
        else:
            res = {"status": "unsupported_platform_inspection", "platform": platform}

        print(json.dumps(res, indent=2))

    elif args.command == "verify-finding":
        chk = args.check_id.lower()
        res_id = args.resource_id
        print(f"[*] Verifying check '{chk}' on resource '{res_id}'...")

        result = {
            "check_id": chk,
            "resource_id": res_id,
            "status": "UNVERIFIED",
            "evidence": "",
            "compensating_controls": []
        }

        if platform == "aws":
            if "s3" in chk or "bucket" in chk:
                s3_info = verifier.inspect_s3_bucket(res_id)
                bpa = s3_info.get("public_access_block", {}).get("PublicAccessBlockConfiguration", {})
                is_bpa_enabled = (bpa.get("BlockPublicAcls") is True and bpa.get("IgnorePublicAcls") is True and bpa.get("BlockPublicPolicy") is True and bpa.get("RestrictPublicBuckets") is True)

                if is_bpa_enabled:
                    result["status"] = "COMPENSATED"
                    result["evidence"] = "S3 Block Public Access is strictly enabled on the bucket."
                    result["compensating_controls"].append("Bucket-level Block Public Access (All 4 settings True)")
                elif s3_info.get("anonymous_probe_readable"):
                    result["status"] = "CONFIRMED"
                    result["evidence"] = "Bucket verified publicly readable via anonymous HTTP GET requests."
                else:
                    result["status"] = "CONFIRMED"
                    result["evidence"] = f"Bucket Block Public Access is disabled. Current configuration: {bpa}"

            elif "securitygroup" in chk or "sg" in chk or "ssh" in chk or "rdp" in chk:
                sg_info = verifier.inspect_security_group(res_id)
                if sg_info.get("attached_interfaces_count", 0) == 0:
                    result["status"] = "FALSE_POSITIVE"
                    result["evidence"] = "Security Group is orphaned (0 active network interfaces attached)."
                else:
                    result["status"] = "CONFIRMED"
                    result["evidence"] = f"Security Group is attached to {sg_info['attached_interfaces_count']} active network interfaces with ingress rules."

        print(json.dumps(result, indent=2))

    elif args.command == "batch-verify":
        session_dir = args.session_dir or "."
        findings_path = os.path.join(session_dir, "staged_findings.json")
        if not os.path.exists(findings_path):
            print(f"[!] Staged findings file not found at: {findings_path}")
            sys.exit(1)

        with open(findings_path, "r", encoding="utf-8") as f:
            findings = json.load(f)

        print(f"[*] Starting batch verification of {len(findings)} findings...")
        verification_report = []

        for f in findings:
            item_res = {
                "finding_id": f.get("id"),
                "check_id": f.get("check_id"),
                "resource_id": f.get("resource_id"),
                "original_severity": f.get("severity"),
                "triage_recommendation": "VERIFY_FURTHER"
            }
            # Simple heuristic baseline
            chk = f.get("check_id", "").lower()
            if "default" in f.get("resource_id", "").lower() and "vpc" in chk:
                item_res["triage_recommendation"] = "LIKELY_FALSE_POSITIVE_DEFAULT_VPC"
            elif "public" in chk or "open" in chk or "0.0.0.0" in chk:
                item_res["triage_recommendation"] = "HIGH_PRIORITY_VERIFICATION"
            verification_report.append(item_res)

        out_path = args.output or os.path.join(session_dir, "batch_verification_summary.json")
        with open(out_path, "w", encoding="utf-8") as out_f:
            json.dump(verification_report, out_f, indent=2)
        print(f"[+] Batch verification summary saved to {out_path}")

if __name__ == "__main__":
    main()
