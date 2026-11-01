#!/usr/bin/env python3
"""
Scanner Findings Filter & Query Tool for SAST Security Skill
Allows filtering and querying staged Semgrep/SAST findings by severity, rule ID, file, or keyword.
"""

import sys
import os
import json
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Query and filter staged SAST findings.")
    parser.add_argument("findings_file", help="Path to staged_findings.json")
    parser.add_argument("--severity", help="Filter by severity: critical, high, medium, low, info")
    parser.add_argument("--rule", help="Filter by rule ID substring")
    parser.add_argument("--file", help="Filter by file path substring")
    parser.add_argument("--summary", action="store_true", help="Display summary matrix of findings")
    return parser.parse_args()

def main():
    args = parse_args()
    if not os.path.exists(args.findings_file):
        print(f"[!] Error: Findings file not found: {args.findings_file}")
        sys.exit(1)

    with open(args.findings_file, "r", encoding="utf-8") as f:
        findings = json.load(f)

    if isinstance(findings, dict):
        if "results" in findings and isinstance(findings["results"], list):
            findings = findings["results"]
        elif "findings" in findings and isinstance(findings["findings"], list):
            findings = findings["findings"]

    if not isinstance(findings, list):
        print("[!] Error: Expected a JSON array of findings or an object containing 'results' or 'findings'.")
        sys.exit(1)

    if args.summary:
        print(f"=== Total Ingested SAST Findings: {len(findings)} ===")
        sev_counts = {}
        rule_counts = {}
        for f in findings:
            sev = str(f.get("severity") or "unknown").lower()
            rule = f.get("rule_id") or f.get("check_id") or "other"
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            rule_counts[rule] = rule_counts.get(rule, 0) + 1

        print("\nBy Severity:")
        for k in ["critical", "high", "medium", "low", "info"]:
            if k in sev_counts:
                print(f"  - {k.upper():<10}: {sev_counts[k]}")

        print("\nTop Flagged Rules:")
        for k, v in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  - {k:<40}: {v}")
        return

    filtered = findings
    if args.severity:
        target_sev = args.severity.strip().lower()
        filtered = [f for f in filtered if str(f.get("severity", "")).lower() == target_sev]

    if args.rule:
        kw = args.rule.strip().lower()
        filtered = [f for f in filtered if kw in str(f.get("rule_id") or f.get("check_id") or "").lower()]

    if args.file:
        kw = args.file.strip().lower()
        filtered = [f for f in filtered if kw in str(f.get("file_path") or f.get("path") or "").lower()]

    print(f"Matched {len(filtered)} / {len(findings)} findings:\n")
    for idx, f in enumerate(filtered, 1):
        rule = f.get("rule_id") or f.get("check_id")
        path = f.get("file_path") or f.get("path")
        line = f.get("start_line") or f.get("start", {}).get("line") or "?"
        sev = str(f.get("severity") or "").upper()
        msg = f.get("message") or f.get("extra", {}).get("message") or ""
        print(f"[{idx}] [{sev}] {rule}")
        print(f"    Location: {path}:{line}")
        if msg:
            print(f"    Message:  {msg.strip()[:140]}")
        print()

if __name__ == "__main__":
    main()
