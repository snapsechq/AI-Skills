#!/usr/bin/env python3
"""
Context Parser & Session Initializer for SAST Security Skill
Ingests context-<runId>.json, extracts repository info and staged scanner findings,
and initializes session planning files (sast_test_plan.md, sast_test_checklist.md).
"""

import os
import sys
import json
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Parse SAST context file and initialize session workspace.")
    parser.add_argument("context_file", help="Path to context-<runId>.json")
    parser.add_argument("--session-dir", default=None, help="Optional custom session directory path")
    return parser.parse_args()

def extract_findings(data):
    findings = []
    candidates = [
        data.get("scanner_findings"),
        data.get("findings"),
        data.get("semgrep_findings"),
        data.get("sast_findings"),
        data.get("results"),
        data.get("issues")
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

    # If findings_file is referenced in context, load findings from there if not directly embedded
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

    # Initialize sast_test_plan.md
    plan_path = os.path.join(session_dir, "sast_test_plan.md")
    with open(plan_path, "w", encoding="utf-8") as pf:
        pf.write(f"""# SAST Audit Plan for {repo_url}

- **Organization ID**: `{org_id}`
- **Run ID**: `{run_id}`
- **Repository**: `{repo_url}`
- **Branch**: `{branch}`
- **Local Source Code Path**: `{repo_dir}`
- **Total Initial Findings Ingested**: {len(findings)}

## Objectives
1. Verify high/critical static scanner leads against the cloned source code.
2. Trace user input taint flows from controllers/routes to sinks.
3. Validate sanitization, escaping, and parameterized abstractions.
4. Mark confirmed vulnerabilities and discard false positives with justifications.
""")

    # Initialize sast_test_checklist.md
    checklist_path = os.path.join(session_dir, "sast_test_checklist.md")
    with open(checklist_path, "w", encoding="utf-8") as cf:
        cf.write(f"""# SAST Verification Checklist

| # | Rule ID | File:Line | Ingested Sev | Confirmed / FP | Notes / Root Cause |
|---|---|---|---|---|---|
""")
        for idx, finding in enumerate(findings[:50], 1):
            rule_id = finding.get("rule_id") or finding.get("check_id") or "custom-rule"
            file_path = finding.get("file_path") or finding.get("path") or "unknown"
            line = finding.get("start_line") or finding.get("start", {}).get("line") or "?"
            sev = finding.get("severity") or "MEDIUM"
            cf.write(f"| {idx} | `{rule_id}` | `{file_path}:{line}` | {sev} | PENDING | | \n")

    print(f"[+] SAST session initialized at: {session_dir}")
    print(f"[+] Staged {len(findings)} findings to {staged_findings_path}")
    print(f"[+] Initialized {plan_path} and {checklist_path}")

if __name__ == "__main__":
    main()

