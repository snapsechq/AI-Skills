#!/usr/bin/env python3
"""
Context Parser & Session Initializer for Cloud Security Skill
Ingests context-<runId>.json, normalizes cloud credentials, stages findings,
and initializes session planning files (cloud_test_plan.md, cloud_test_checklist.md).
"""

import os
import sys
import json
import argparse
import stat

def parse_args():
    parser = argparse.ArgumentParser(description="Parse cloud security context file and prepare session workspace.")
    parser.add_argument("context_file", help="Path to context-<runId>.json")
    parser.add_argument("--session-dir", default=None, help="Optional custom session directory path")
    return parser.parse_args()

def normalize_cloud_platform(data):
    platform = data.get("cloud_platform") or data.get("platform") or data.get("provider") or data.get("adapter") or ""
    platform = str(platform).strip().lower()
    if platform in ["aws", "amazon", "amazon web services"]:
        return "aws"
    if platform in ["gcp", "google", "google cloud", "google cloud platform"]:
        return "gcp"
    if platform in ["azure", "microsoft", "microsoft azure"]:
        return "azure"
    if platform in ["oracle", "oci", "oracle cloud", "oracle cloud infrastructure"]:
        return "oracle"
    # Auto-detect from credentials keys if missing
    creds = data.get("credentials") or {}
    if "accessKeyId" in creds or "aws_access_key_id" in creds:
        return "aws"
    if "serviceAccountKey" in creds or "project_id" in creds:
        return "gcp"
    if "ApplicationID" in creds or "SubscriptionID" in creds:
        return "azure"
    if "tenancyId" in creds or "keyFingerprint" in creds:
        return "oracle"
    return platform or "unknown"

def extract_findings(data):
    findings = []
    # Check common keys: scanner_findings, findings, prowler, cloudsploit, results
    candidates = [
        data.get("scanner_findings"),
        data.get("findings"),
        data.get("prowler_findings"),
        data.get("cloudsploit_findings"),
        data.get("issues"),
        data.get("misconfigurations")
    ]
    for c in candidates:
        if isinstance(c, list):
            findings.extend(c)
        elif isinstance(c, dict):
            # If nested under categories
            for k, v in c.items():
                if isinstance(v, list):
                    findings.extend(v)

    # Normalize finding objects
    normalized = []
    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            continue

        finding_id = f.get("id") or f.get("finding_id") or f.get("check_id") or f.get("plugin") or f"finding-{idx+1}"
        source = f.get("source") or ("prowler" if "check_id" in f else "cloudsploit" if "plugin" in f else "generic")
        check_id = f.get("check_id") or f.get("plugin") or f.get("rule_id") or "custom-rule"
        service = f.get("service") or f.get("category") or "general"
        severity = str(f.get("severity") or "medium").lower()
        status = str(f.get("status") or "FAIL").upper()
        resource_id = f.get("resource_id") or f.get("resource") or f.get("resource_arn") or f.get("asset") or "unspecified-resource"
        title = f.get("title") or f.get("check_title") or f.get("message") or f.get("description") or f"Cloud misconfiguration in {service}"
        desc = f.get("description") or f.get("message") or f.get("risk") or title
        region = f.get("region") or data.get("credentials", {}).get("region") or "global"

        normalized.append({
            "index": idx + 1,
            "id": str(finding_id),
            "source": str(source).lower(),
            "check_id": str(check_id),
            "service": str(service).lower(),
            "severity": severity,
            "status": status,
            "resource_id": str(resource_id),
            "title": str(title).strip(),
            "description": str(desc).strip(),
            "region": str(region),
            "raw": f
        })

    return normalized

def main():
    args = parse_args()
    if not os.path.exists(args.context_file):
        print(f"[!] Error: Context file does not exist: {args.context_file}")
        sys.exit(1)

    try:
        with open(args.context_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error reading JSON context: {e}")
        sys.exit(1)

    org_id = data.get("orgId") or "default-org"
    run_id = data.get("runId") or data.get("scanId") or data.get("pentestId") or "session-default"
    pentest_id = data.get("pentestId") or run_id
    scan_id = data.get("scanId") or run_id
    cloud_platform = normalize_cloud_platform(data)
    credentials = data.get("credentials") or {}

    session_dir = args.session_dir or f"./session-{run_id}"
    os.makedirs(session_dir, exist_ok=True)

    print(f"[*] Initialized Cloud Security session directory: {session_dir}")
    print(f"[*] Org ID: {org_id}")
    print(f"[*] Run ID: {run_id}")
    print(f"[*] Cloud Platform: {cloud_platform.upper()}")

    # Stage credentials
    staged_creds = {
        "cloud_platform": cloud_platform,
        "credentials": credentials
    }
    with open(os.path.join(session_dir, "credentials.json"), "w", encoding="utf-8") as f:
        json.dump(staged_creds, f, indent=2)

    # Export specific cloud provider config files
    if cloud_platform == "aws":
        env_lines = [
            f"export AWS_ACCESS_KEY_ID='{credentials.get('accessKeyId', credentials.get('access_key', ''))}'",
            f"export AWS_SECRET_ACCESS_KEY='{credentials.get('secretAccessKey', credentials.get('secret_key', ''))}'",
            f"export AWS_DEFAULT_REGION='{credentials.get('region', 'us-east-1')}'",
            f"export AWS_REGION='{credentials.get('region', 'us-east-1')}'"
        ]
        if credentials.get("sessionToken"):
            env_lines.append(f"export AWS_SESSION_TOKEN='{credentials.get('sessionToken')}'")
        with open(os.path.join(session_dir, "aws.env"), "w", encoding="utf-8") as f:
            f.write("\n".join(env_lines) + "\n")
        print("    -> Generated aws.env")

    elif cloud_platform == "gcp":
        sa_key = credentials.get("serviceAccountKey")
        if sa_key:
            key_content = sa_key if isinstance(sa_key, dict) else json.loads(sa_key) if isinstance(sa_key, str) else {}
            key_path = os.path.join(session_dir, "gcp_service_account.json")
            with open(key_path, "w", encoding="utf-8") as f:
                json.dump(key_content, f, indent=2)
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
            with open(os.path.join(session_dir, "gcp.env"), "w", encoding="utf-8") as f:
                f.write(f"export GOOGLE_APPLICATION_CREDENTIALS='{os.path.abspath(key_path)}'\n")
                if credentials.get("projectId"):
                    f.write(f"export CLOUDSDK_CORE_PROJECT='{credentials.get('projectId')}'\n")
            print("    -> Generated gcp_service_account.json and gcp.env")

    elif cloud_platform == "azure":
        env_lines = [
            f"export AZURE_CLIENT_ID='{credentials.get('ApplicationID', credentials.get('clientId', ''))}'",
            f"export AZURE_CLIENT_SECRET='{credentials.get('KeyValue', credentials.get('clientSecret', ''))}'",
            f"export AZURE_TENANT_ID='{credentials.get('DirectoryID', credentials.get('tenantId', ''))}'",
            f"export AZURE_SUBSCRIPTION_ID='{credentials.get('SubscriptionID', credentials.get('subscriptionId', ''))}'"
        ]
        with open(os.path.join(session_dir, "azure.env"), "w", encoding="utf-8") as f:
            f.write("\n".join(env_lines) + "\n")
        print("    -> Generated azure.env")

    elif cloud_platform == "oracle":
        key_val = credentials.get("keyValue") or ""
        if key_val:
            key_path = os.path.join(session_dir, "oci_api_key.pem")
            normalized_key = key_val.replace("\\n", "\n") if isinstance(key_val, str) else key_val
            with open(key_path, "w", encoding="utf-8") as f:
                f.write(normalized_key.strip() + "\n")
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
            print("    -> Generated oci_api_key.pem (mode 0600)")

    # Extract and stage findings
    findings = extract_findings(data)
    print(f"[*] Ingested {len(findings)} scanner finding(s) from context.")

    with open(os.path.join(session_dir, "staged_findings.json"), "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    # Generate initial cloud_test_plan.md
    plan_content = f"""# Cloud Security Verification Plan

## Session Overview
- **Run ID**: {run_id}
- **Org ID**: {org_id}
- **Pentest ID**: {pentest_id}
- **Scan ID**: {scan_id}
- **Cloud Platform**: {cloud_platform.upper()}
- **Total Ingested Findings**: {len(findings)}

## Objectives
1. Verify live credentials using `python3 scripts/cloud_verifier.py test-connection --session-dir {session_dir}`.
2. Triage findings into risk categories (Storage, IAM, Network, Compute, Database, Logging, Secrets).
3. Validate each finding by querying live cloud configurations with `python3 scripts/cloud_verifier.py inspect-resource`.
4. Disqualify false positives using compensating controls analysis (e.g. Account-level BPA, isolated subnets).
5. Output verified high-impact findings to `artifacts/results.json` adhering to the vulnerability schema.
"""
    with open(os.path.join(session_dir, "cloud_test_plan.md"), "w", encoding="utf-8") as f:
        f.write(plan_content)

    # Generate initial cloud_test_checklist.md
    checklist_lines = [
        "# Cloud Security Verification Checklist",
        "",
        "## Phase 1: Authentication & Scope Verification",
        f"- [ ] Test cloud authentication & verify account context for {cloud_platform.upper()}",
        "",
        "## Phase 2: Ingested Scanner Findings Verification"
    ]

    for item in findings:
        idx = item["index"]
        chk = item["check_id"]
        res = item["resource_id"]
        sev = item["severity"].upper()
        title = item["title"]
        checklist_lines.append(f"- [ ] [{idx}] [{sev}] [{chk}] {title}")
        checklist_lines.append(f"  - Resource: `{res}`")
        checklist_lines.append(f"  - Service: `{item['service']}` | Region: `{item['region']}`")

    checklist_lines.extend([
        "",
        "## Phase 3: Results Synthesis & Schema Validation",
        f"- [ ] Compile confirmed findings to `results.json` (`{{ \"results\": [...] }}`)",
        "- [ ] Run `python3 scripts/validate_results.py results.json`",
        "- [ ] Verify all checklist items are marked either `[x]` (confirmed) or `[-]` (rejected/mitigated)"
    ])

    with open(os.path.join(session_dir, "cloud_test_checklist.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(checklist_lines) + "\n")

    print(f"[*] Generated {session_dir}/cloud_test_plan.md and {session_dir}/cloud_test_checklist.md")
    print("[+] Context parsing complete.")

if __name__ == "__main__":
    main()
