#!/usr/bin/env python3
"""
Scanner Findings Filter & Query Tool for Cloud Security Skill
Allows filtering and querying staged findings by severity, service, check ID, or status.
"""

import sys
import os
import json
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Query and filter staged scanner findings.")
    parser.add_argument("findings_file", help="Path to staged_findings.json")
    parser.add_argument("--severity", help="Filter by severity: critical, high, medium, low, info")
    parser.add_argument("--service", help="Filter by cloud service (e.g. s3, iam, ec2, storage)")
    parser.add_argument("--check-id", help="Filter by scanner check/rule ID")
    parser.add_argument("--source", help="Filter by scanner source (prowler, cloudsploit)")
    parser.add_argument("--status", help="Filter by scanner status (FAIL, PASS)")
    parser.add_argument("--summary", action="store_true", help="Display summary matrix of findings")
    return parser.parse_args()

def main():
    args = parse_args()
    if not os.path.exists(args.findings_file):
        print(f"[!] Error: Findings file not found: {args.findings_file}")
        sys.exit(1)

    with open(args.findings_file, "r", encoding="utf-8") as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        print("[!] Error: Expected a JSON array of findings.")
        sys.exit(1)

    if args.summary:
        print(f"=== Total Ingested Findings: {len(findings)} ===")
        sev_counts = {}
        svc_counts = {}
        src_counts = {}
        for f in findings:
            sev = f.get("severity", "unknown").lower()
            svc = f.get("service", "unknown").lower()
            src = f.get("source", "unknown").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            svc_counts[svc] = svc_counts.get(svc, 0) + 1
            src_counts[src] = src_counts.get(src, 0) + 1

        print("\nBy Severity:")
        for k in ["critical", "high", "medium", "low", "info"]:
            if k in sev_counts:
                print(f"  - {k.upper():<10}: {sev_counts[k]}")

        print("\nBy Service:")
        for k, v in sorted(svc_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {k:<15}: {v}")

        print("\nBy Scanner Source:")
        for k, v in src_counts.items():
            print(f"  - {k:<15}: {v}")
        return

    filtered = findings
    if args.severity:
        filtered = [f for f in filtered if f.get("severity", "").lower() == args.severity.lower()]
    if args.service:
        filtered = [f for f in filtered if args.service.lower() in f.get("service", "").lower()]
    if args.check_id:
        filtered = [f for f in filtered if args.check_id.lower() in f.get("check_id", "").lower()]
    if args.source:
        filtered = [f for f in filtered if f.get("source", "").lower() == args.source.lower()]
    if args.status:
        filtered = [f for f in filtered if f.get("status", "").upper() == args.status.upper()]

    print(f"Found {len(filtered)} matching finding(s):\n")
    for f in filtered:
        idx = f.get("index")
        sev = f.get("severity", "").upper()
        svc = f.get("service", "")
        chk = f.get("check_id", "")
        res = f.get("resource_id", "")
        title = f.get("title", "")
        print(f"[{idx}] [{sev}] [{svc.upper()}] ({chk})")
        print(f"    Title:    {title}")
        print(f"    Resource: {res}")
        print(f"    Region:   {f.get('region', 'global')}\n")

if __name__ == "__main__":
    main()
