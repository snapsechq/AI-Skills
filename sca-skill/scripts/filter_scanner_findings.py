#!/usr/bin/env python3
"""
Scanner Findings Filter & Query Tool for SCA Security Skill
Allows filtering and querying staged Trivy findings by severity, package name, CVE, or manifest.
"""

import sys
import os
import json
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Query and filter staged SCA findings.")
    parser.add_argument("findings_file", help="Path to staged_findings.json")
    parser.add_argument("--severity", help="Filter by severity: critical, high, medium, low, info")
    parser.add_argument("--package", help="Filter by package name substring")
    parser.add_argument("--cve", help="Filter by CVE or GHSA ID")
    parser.add_argument("--manifest", help="Filter by manifest target file")
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
        print(f"=== Total Ingested SCA Findings: {len(findings)} ===")
        sev_counts = {}
        pkg_counts = {}
        for f in findings:
            sev = str(f.get("severity") or f.get("Severity") or "unknown").lower()
            pkg = f.get("package_name") or f.get("PkgName") or "other"
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            pkg_counts[pkg] = pkg_counts.get(pkg, 0) + 1

        print("\nBy Severity:")
        for k in ["critical", "high", "medium", "low", "info"]:
            if k in sev_counts:
                print(f"  - {k.upper():<10}: {sev_counts[k]}")

        print("\nTop Affected Packages:")
        for k, v in sorted(pkg_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  - {k:<30}: {v}")
        return

    filtered = findings
    if args.severity:
        target_sev = args.severity.strip().lower()
        filtered = [f for f in filtered if str(f.get("severity") or f.get("Severity") or "").lower() == target_sev]

    if args.package:
        kw = args.package.strip().lower()
        filtered = [f for f in filtered if kw in str(f.get("package_name") or f.get("PkgName") or "").lower()]

    if args.cve:
        kw = args.cve.strip().lower()
        filtered = [f for f in filtered if kw in str(f.get("cve") or f.get("vulnerability_id") or f.get("VulnerabilityID") or "").lower()]

    if args.manifest:
        kw = args.manifest.strip().lower()
        filtered = [f for f in filtered if kw in str(f.get("target") or f.get("Target") or "").lower()]

    print(f"Matched {len(filtered)} / {len(findings)} findings:\n")
    for idx, f in enumerate(filtered, 1):
        cve = f.get("cve") or f.get("vulnerability_id") or f.get("VulnerabilityID")
        pkg = f.get("package_name") or f.get("PkgName")
        inst = f.get("installed_version") or f.get("InstalledVersion")
        fixed = f.get("fixed_version") or f.get("FixedVersion") or "None"
        target = f.get("target") or f.get("Target") or "Unknown"
        sev = str(f.get("severity") or f.get("Severity") or "").upper()
        title = f.get("title") or f.get("Title") or ""
        print(f"[{idx}] [{sev}] {cve} in {pkg}@{inst} (Fix: {fixed})")
        print(f"    Manifest: {target}")
        if title:
            print(f"    Title:    {title.strip()[:140]}")
        print()

if __name__ == "__main__":
    main()

