#!/usr/bin/env python3
"""
Context File Parser for Infrastructure & Network Security Skill
Parses pentest-<orgId>-<runId>.json, extracts target metadata, and initializes
the session directory with recon_plan.md and recon_checklist.md.
"""

import sys
import os
import json
import argparse
import ipaddress
import socket

def parse_args():
    parser = argparse.ArgumentParser(description="Parse pentest context file and prepare session workspace.")
    parser.add_argument("context_file", help="Path to the pentest context JSON file.")
    parser.add_argument("--session-dir", default=None, help="Optional custom session directory path.")
    return parser.parse_args()

def resolve_target(url_or_host):
    try:
        clean = url_or_host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ip = socket.gethostbyname(clean)
        return clean, ip
    except Exception:
        return url_or_host, None

def main():
    args = parse_args()
    if not os.path.exists(args.context_file):
        print(f"[!] Error: Context file '{args.context_file}' does not exist.")
        sys.exit(1)

    try:
        with open(args.context_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error reading JSON: {e}")
        sys.exit(1)

    org_id = data.get("orgId")
    pentest_id = data.get("pentestId", "")
    scan_id = data.get("scanId", "")
    name = data.get("name", "Infrastructure Assessment")
    pentest_config = data.get("pentest_config", {})
    target_type = pentest_config.get("target_type", "black-box")
    target_ip = pentest_config.get("ip", "").strip()
    target_url = pentest_config.get("url", "").strip()

    run_id = scan_id or pentest_id or "session-default"
    session_dir = args.session_dir or f"./session-{run_id}"
    os.makedirs(session_dir, exist_ok=True)

    print(f"[*] Initialized session directory: {session_dir}")
    print(f"[*] Organization ID: {org_id}")
    print(f"[*] Pentest ID: {pentest_id}")
    print(f"[*] Scan ID: {scan_id}")
    print(f"[*] Target Type: {target_type}")
    print(f"[*] Target IP: {target_ip or 'None specified'}")
    print(f"[*] Target URL: {target_url or 'None specified'}")

    # Determine in-scope targets
    targets = []
    if target_ip:
        if "/" in target_ip:
            try:
                net = ipaddress.ip_network(target_ip, strict=False)
                for ip in net.hosts():
                    targets.append(str(ip))
            except Exception:
                targets.append(target_ip)
        else:
            for ip in target_ip.split(","):
                if ip.strip():
                    targets.append(ip.strip())

    resolved_host = None
    if target_url:
        host, resolved_ip = resolve_target(target_url)
        resolved_host = host
        if resolved_ip and resolved_ip not in targets:
            targets.append(resolved_ip)

    # Generate initial recon_plan.md
    plan_path = os.path.join(session_dir, "recon_plan.md")
    with open(plan_path, "w", encoding="utf-8") as pf:
        pf.write(f"""# Reconnaissance Plan
**Target Assessment**: {name}
**Target Posture**: {target_type}
**Scope Targets**: {', '.join(targets) if targets else target_url or 'Unspecified'}
**Target URL**: {target_url}

## Reconnaissance Objectives
1. Perform host discovery and confirm live network reachability.
2. Probe top TCP ports (top 1000 + critical infrastructure ports) and critical UDP services (53, 69, 123, 161).
3. Grab service banners and identify exact daemon versions.
4. Detect operating system, perimeter controls, and firewall behavior.
5. Record all findings into `recon_knowledge.json`.
""")
    print(f"[+] Created {plan_path}")

    # Generate initial recon_checklist.md
    checklist_path = os.path.join(session_dir, "recon_checklist.md")
    with open(checklist_path, "w", encoding="utf-8") as cf:
        cf.write(f"""# Reconnaissance Checklist
Session ID: {run_id}
Target Posture: {target_type}

## 1. Scope & DNS Enumeration
- [ ] Parse target IPs and CIDR blocks
- [ ] Resolve URL '{target_url}' (Resolved: {resolved_host or 'N/A'})
- [ ] Determine reverse DNS (PTR) records

## 2. Host Reachability & Alive Checks
""")
        if targets:
            for t in targets:
                cf.write(f"- [ ] Host `{t}`: ICMP Echo / TCP SYN Ping\n")
        else:
            cf.write("- [ ] Verify target host reachability\n")

        cf.write("""
## 3. Port & Service Discovery
""")
        if targets:
            for t in targets:
                cf.write(f"""### Host: `{t}`
- [ ] Top 1000 TCP Port Scan
- [ ] Infrastructure Service Ports (21, 22, 23, 25, 53, 80, 111, 135, 139, 161, 443, 445, 1433, 1521, 2049, 2375, 2376, 2379, 3306, 3389, 5432, 6379, 6443, 8080, 8443, 9200, 10250, 11211, 27017)
- [ ] Critical UDP Ports (53 DNS, 69 TFTP, 123 NTP, 161 SNMP)
- [ ] Service Banner Grabbing & Protocol Handshake
- [ ] OS & Perimeter Device Identification
""")
        cf.write("""
## 4. Knowledge Consolidation
- [ ] Compile open ports, services, and banners into `recon_knowledge.json`
""")
    print(f"[+] Created {checklist_path}")

if __name__ == "__main__":
    main()
