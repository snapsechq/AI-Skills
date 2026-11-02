#!/usr/bin/env python3
"""
Context Parser & Session Initializer for SCA Security Skill
Ingests context-<runId>.json, extracts repository info and staged Trivy findings,
and initializes session planning files (sca_test_plan.md, sca_test_checklist.md).
"""

import os
import sys
import json
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Parse SCA context file and initialize session workspace.")
    parser.add_argument("context_file", help="Path to context-<runId>.json")
    parser.add_argument("--session-dir", default=None, help="Optional custom session directory path")
    return parser.parse_args()

def extract_findings(data):
    findings = []
    candidates = [
        data.get("scanner_findings"),
        data.get("findings"),
        data.get("trivy_findings"),
        data.get("sca_findings"),
        data.get("results"),
        data.get("vulnerabilities")
    ]
    for c in candidates:
        if isinstance(c, list):
            findings.extend(c)
        elif isinstance(c, dict):
            if "results" in c and isinstance(c["results"], list):
                findings.extend(c["results"])
            else:
                for k, v in c.items():
                    if isinstance(v, list):
                        findings.extend(v)
    return findings

def main():
    args = parse_args()
    context_path = os.path.abspath(args.context_file)

    if not os.path.exists(context_path):
        print(f"[!] Error: Context file does not exist: {context_path}")
        sys.exit(1)

    try:
        with open(context_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error reading context JSON: {e}")
        sys.exit(1)

    run_id = data.get("runId") or "default_run"
    org_id = data.get("orgId") or "unknown_org"
    repo_url = data.get("repo_url") or data.get("projectUrl") or data.get("repo") or "unknown_repo"
    branch = data.get("branch") or data.get("branch_name") or "main"
    repo_dir = data.get("repo_dir") or "./source_code"

    session_dir = os.path.abspath(args.session_dir) if args.session_dir else os.path.abspath(f"./session-{run_id}")
    os.makedirs(session_dir, exist_ok=True)

    findings = extract_findings(data)
    findings_file = data.get("findings_file")
    if not findings and findings_file and os.path.exists(findings_file):
        try:
            with open(findings_file, "r", encoding="utf-8") as ff:
                raw_findings = json.load(ff)
                if isinstance(raw_findings, list):
                    findings = raw_findings
                elif isinstance(raw_findings, dict) and "results" in raw_findings:
                    findings = raw_findings["results"]
        except Exception as fe:
            print(f"[-] Warning: Failed to load external findings file {findings_file}: {fe}")

    # Stage normalized findings
    staged_findings_path = os.path.join(session_dir, "staged_findings.json")
    with open(staged_findings_path, "w", encoding="utf-8") as sf:
        json.dump(findings, sf, indent=2)

    # Initialize sca_test_plan.md
    plan_path = os.path.join(session_dir, "sca_test_plan.md")
    with open(plan_path, "w", encoding="utf-8") as pf:
        pf.write(f"""# SCA Dependency Audit Plan for {repo_url}

- **Organization ID**: `{org_id}`
- **Run ID**: `{run_id}`
- **Repository**: `{repo_url}`
- **Branch**: `{branch}`
- **Local Source Code Path**: `{repo_dir}`
- **Total Initial Vulnerabilities Ingested**: {len(findings)}

## Objectives
1. Verify high and critical dependency CVEs reported by Trivy against project manifests.
2. Perform reachability analysis: trace imports in application code to identify reachable vulnerable functions.
3. Determine if findings belong to production dependencies or build-time devDependencies.
4. Recommend non-breaking patch and upgrade versions.
""")

    # Initialize sca_test_checklist.md
    checklist_path = os.path.join(session_dir, "sca_test_checklist.md")
    with open(checklist_path, "w", encoding="utf-8") as cf:
        cf.write(f"""# SCA Verification Checklist

| # | CVE ID | Package@Version | Target Manifest | Sev | Reachable? | Fixed Version | Status |
|---|---|---|---|---|---|---|---|
""")
        for idx, finding in enumerate(findings[:50], 1):
            cve_id = finding.get("cve") or finding.get("vulnerability_id") or finding.get("VulnerabilityID") or "CVE-UNKNOWN"
            pkg_name = finding.get("package_name") or finding.get("PkgName") or "package"
            inst_ver = finding.get("installed_version") or finding.get("InstalledVersion") or "?"
            target = finding.get("target") or finding.get("Target") or "manifest"
            sev = finding.get("severity") or finding.get("Severity") or "MEDIUM"
            fix_ver = finding.get("fixed_version") or finding.get("FixedVersion") or "N/A"
            cf.write(f"| {idx} | `{cve_id}` | `{pkg_name}@{inst_ver}` | `{target}` | {sev} | PENDING | `{fix_ver}` | PENDING |\n")

    print(f"[+] SCA session initialized at: {session_dir}")
    print(f"[+] Staged {len(findings)} findings to {staged_findings_path}")
    print(f"[+] Initialized {plan_path} and {checklist_path}")

if __name__ == "__main__":
    main()

