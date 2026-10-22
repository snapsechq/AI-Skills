#!/usr/bin/env python3
"""
query_assets.py
CLI interface tool to query, filter, correlate assets, existing exposures, and signals/rules from ASM dump data.
"""

import sys
import os
import re
import json
import argparse
from pathlib import Path

def load_data(file_path):
    p = Path(file_path)
    if not p.exists():
        print(f"[-] Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)
    with open(p, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # If it's a combined dump dict
    if isinstance(raw, dict):
        assets = raw.get("assets", [])
        exposures = raw.get("existing_exposures", [])
        signals = raw.get("signals", []) or raw.get("rules", [])
        return assets, exposures, signals
    
    # If it's a list (e.g. split assets.json, signals.json, or exposures.json)
    if isinstance(raw, list):
        # Infer if this list is signals or assets
        if raw and isinstance(raw[0], dict) and ("parsed_yaml" in raw[0] or ("name" in raw[0] and "match" in raw[0])):
            return [], [], raw
        elif raw and isinstance(raw[0], dict) and ("associatedAsset" in raw[0] and "title" in raw[0]):
            return [], raw, []
        return raw, [], []

    return [], [], []

def get_nested_val(obj, key_path):
    parts = key_path.split(".")
    curr = obj
    for p in parts:
        if isinstance(curr, dict) and p in curr:
            curr = curr[p]
        else:
            return None
    return curr

def record_matches_rule_query(record, match_query):
    if not match_query or not isinstance(match_query, (dict, list)):
        return False

    if isinstance(match_query, list):
        if len(match_query) == 0: return False
        return all(record_matches_rule_query(record, m) for m in match_query)

    for k, v in match_query.items():
        if k == "$and" and isinstance(v, list):
            if not all(record_matches_rule_query(record, item) for item in v):
                return False
            continue
        if k == "$or" and isinstance(v, list):
            if not any(record_matches_rule_query(record, item) for item in v):
                return False
            continue

        actual_val = get_nested_val(record, k)

        if isinstance(v, dict):
            for op, op_val in v.items():
                if op == "$eq" and actual_val != op_val:
                    return False
                if op == "$ne" and actual_val == op_val:
                    return False
                if op == "$in" and (not isinstance(op_val, list) or actual_val not in op_val):
                    return False
                if op == "$nin" and isinstance(op_val, list) and actual_val in op_val:
                    return False
                if op == "$regex":
                    flags = re.IGNORECASE if v.get("$options", "").lower() == "i" else 0
                    if not actual_val or not re.search(str(op_val), str(actual_val), flags):
                        return False
        else:
            if actual_val != v:
                return False

    return True

def match_signals_against_assets(assets, signals, target_signal_name=None):
    results = []
    for s in signals:
        s_name = s.get("name", "Unknown Signal")
        if target_signal_name and s_name.lower() != target_signal_name.lower():
            continue

        match_query = (s.get("parsed_yaml") or {}).get("match") or s.get("match") or {}
        matched_assets = []

        if match_query:
            for a in assets:
                if record_matches_rule_query(a, match_query):
                    matched_assets.append({
                        "id": str(a.get("_id", "")),
                        "type": a.get("type"),
                        "value": a.get("value"),
                        "subdomain": a.get("subdomain"),
                        "ip": a.get("ip"),
                        "properties": a.get("properties")
                    })

        results.append({
            "signal_name": s_name,
            "risk": s.get("risk", "info"),
            "category": s.get("category", "General"),
            "description": s.get("description", ""),
            "remediation": s.get("remediation", ""),
            "impact": s.get("impact", ""),
            "match_query": match_query,
            "match_count": len(matched_assets),
            "matched_assets": matched_assets
        })
    return results

def list_subdomains(assets):
    subdomains = {}
    for a in assets:
        sub = a.get("subdomain") or (a.get("value") if a.get("type") == "subdomain" else None)
        if not sub:
            continue
        if sub not in subdomains:
            subdomains[sub] = {
                "subdomain": sub,
                "domain": a.get("domain"),
                "status": "unknown",
                "ips": set(),
                "ports": set(),
                "technologies": set()
            }
        
        props = a.get("properties") or {}
        if a.get("type") == "subdomain":
            subdomains[sub]["status"] = props.get("subdomain_status", "live")
            if props.get("subdomain_title"):
                subdomains[sub]["title"] = props.get("subdomain_title")
        
        if a.get("ip"):
            subdomains[sub]["ips"].add(a.get("ip"))
        
        if a.get("type") == "port":
            port_val = a.get("value")
            service = props.get("port_service", "")
            subdomains[sub]["ports"].add(f"{port_val}/{service}" if service else str(port_val))
            
        if a.get("type") == "technology":
            subdomains[sub]["technologies"].add(a.get("value"))

    result = []
    for s in sorted(subdomains.keys()):
        item = subdomains[s]
        item["ips"] = sorted(list(item["ips"]))
        item["ports"] = sorted(list(item["ports"]))
        item["technologies"] = sorted(list(item["technologies"]))
        result.append(item)
    return result

def list_ips(assets):
    ips = {}
    for a in assets:
        ip = a.get("ip") or (a.get("value") if a.get("type") == "ip" else None)
        if not ip:
            continue
        if ip not in ips:
            ips[ip] = {
                "ip": ip,
                "location": "unknown",
                "associated_subdomains": set(),
                "ports": set()
            }
        props = a.get("properties") or {}
        if a.get("type") == "ip":
            loc_parts = [props.get("ip_city"), props.get("ip_country"), props.get("ip_org")]
            ips[ip]["location"] = ", ".join([p for p in loc_parts if p]) or "unknown"
        
        sub = a.get("subdomain")
        if sub:
            ips[ip]["associated_subdomains"].add(sub)
        
        if a.get("type") == "port":
            port_val = a.get("value")
            service = props.get("port_service", "")
            ips[ip]["ports"].add(f"{port_val}/{service}" if service else str(port_val))

    result = []
    for i in sorted(ips.keys()):
        item = ips[i]
        item["associated_subdomains"] = sorted(list(item["associated_subdomains"]))
        item["ports"] = sorted(list(item["ports"]))
        result.append(item)
    return result

def get_asset_details(assets, target):
    target_clean = target.strip().lower()
    matches = []
    correlated_ports = []
    correlated_tech = []
    correlated_ips = set()
    correlated_subdomains = set()

    for a in assets:
        val = str(a.get("value", "")).lower()
        sub = str(a.get("subdomain", "")).lower()
        ip = str(a.get("ip", "")).lower()

        if target_clean in (val, sub, ip):
            matches.append(a)
            if a.get("type") == "port":
                props = a.get("properties") or {}
                correlated_ports.append({
                    "port": a.get("value"),
                    "service": props.get("port_service"),
                    "version": props.get("port_service_version"),
                    "status": props.get("port_status")
                })
            elif a.get("type") == "technology":
                correlated_tech.append(a.get("value"))
            if a.get("ip"):
                correlated_ips.add(a.get("ip"))
            if a.get("subdomain"):
                correlated_subdomains.add(a.get("subdomain"))

    return {
        "target": target,
        "match_count": len(matches),
        "associated_ips": sorted(list(correlated_ips)),
        "associated_subdomains": sorted(list(correlated_subdomains)),
        "open_ports": correlated_ports,
        "technologies": sorted(list(set(correlated_tech))),
        "raw_records": matches
    }

def list_open_ports(assets):
    ports = []
    for a in assets:
        if a.get("type") == "port":
            props = a.get("properties") or {}
            ports.append({
                "port": a.get("value"),
                "service": props.get("port_service"),
                "version": props.get("port_service_version"),
                "status": props.get("port_status", "open"),
                "subdomain": a.get("subdomain"),
                "ip": a.get("ip")
            })
    return ports

def list_technologies(assets):
    tech_map = {}
    for a in assets:
        if a.get("type") == "technology":
            tech = a.get("value")
            if not tech: continue
            if tech not in tech_map:
                tech_map[tech] = []
            sub = a.get("subdomain") or a.get("ip")
            if sub and sub not in tech_map[tech]:
                tech_map[tech].append(sub)
    return [{"technology": k, "affected_assets": sorted(v)} for k, v in sorted(tech_map.items())]

def main():
    parser = argparse.ArgumentParser(description="Query and correlate ASM attack surface data, exposures, and signals")
    parser.add_argument("dataset", help="Path to assets JSON file (or combined dump)")
    parser.add_argument("--signals-file", help="Optional path to signals.json file if dataset only contains assets")
    parser.add_argument("--list-subdomains", action="store_true", help="List all unique subdomains with status, IPs, and ports")
    parser.add_argument("--list-ips", action="store_true", help="List all unique IPs with hostnames and ports")
    parser.add_argument("--get-asset", metavar="TARGET", help="Get full correlated profile for a subdomain or IP")
    parser.add_argument("--type", metavar="TYPE", help="Filter assets by type (subdomain, ip, port, technology, web_server, etc.)")
    parser.add_argument("--open-ports", action="store_true", help="List all discovered open ports with service and version info")
    parser.add_argument("--technologies", action="store_true", help="List all detected technologies and corresponding assets")
    parser.add_argument("--exposures", action="store_true", help="List existing known exposures to prevent duplication")
    parser.add_argument("--signals", action="store_true", help="List available signals/rules for the organization")
    parser.add_argument("--match-signals", action="store_true", help="Evaluate signals against assets and list all matching assets")
    parser.add_argument("--match-signal", metavar="NAME", help="Find all assets matching a specific signal name")
    parser.add_argument("--summary", action="store_true", help="Print overall statistics of assets, exposures, and signals")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()
    assets, exposures, signals = load_data(args.dataset)

    # If signals-file is explicitly provided, load signals from it
    if args.signals_file:
        _, _, file_signals = load_data(args.signals_file)
        if file_signals:
            signals = file_signals

    output = None

    if args.list_subdomains:
        output = list_subdomains(assets)
        if not args.json:
            print(f"[+] Found {len(output)} unique subdomains:")
            for s in output:
                ports_str = ", ".join(s["ports"]) if s["ports"] else "none"
                ips_str = ", ".join(s["ips"]) if s["ips"] else "none"
                tech_str = ", ".join(s["technologies"]) if s["technologies"] else "none"
                print(f"  - {s['subdomain']} [{s['status']}] (IPs: {ips_str} | Ports: {ports_str} | Tech: {tech_str})")
            return

    elif args.list_ips:
        output = list_ips(assets)
        if not args.json:
            print(f"[+] Found {len(output)} unique IPs:")
            for i in output:
                ports_str = ", ".join(i["ports"]) if i["ports"] else "none"
                subs_str = ", ".join(i["associated_subdomains"]) if i["associated_subdomains"] else "none"
                print(f"  - {i['ip']} ({i['location']}) | Subdomains: {subs_str} | Ports: {ports_str}")
            return

    elif args.get_asset:
        output = get_asset_details(assets, args.get_asset)
        if not args.json:
            print(f"[+] Asset Profile: {output['target']}")
            print(f"  - Associated IPs: {', '.join(output['associated_ips']) or 'none'}")
            print(f"  - Associated Subdomains: {', '.join(output['associated_subdomains']) or 'none'}")
            print(f"  - Technologies: {', '.join(output['technologies']) or 'none'}")
            print(f"  - Open Ports:")
            for p in output['open_ports']:
                ver = f" ({p['version']})" if p.get('version') else ""
                print(f"      * {p['port']} - {p.get('service', 'unknown')}{ver}")
            return

    elif args.type:
        output = [a for a in assets if a.get("type") == args.type]
        if not args.json:
            print(f"[+] Assets of type '{args.type}' ({len(output)} total):")
            for a in output:
                print(f"  - {a.get('value')} (Subdomain: {a.get('subdomain')}, IP: {a.get('ip')})")
            return

    elif args.open_ports:
        output = list_open_ports(assets)
        if not args.json:
            print(f"[+] Found {len(output)} open port records:")
            for p in output:
                host = p.get('subdomain') or p.get('ip') or 'unknown'
                ver = f" ({p['version']})" if p.get('version') else ""
                print(f"  - {host}:{p['port']} [{p.get('service', 'unknown')}{ver}]")
            return

    elif args.technologies:
        output = list_technologies(assets)
        if not args.json:
            print(f"[+] Detected {len(output)} technologies:")
            for t in output:
                print(f"  - {t['technology']}: {', '.join(t['affected_assets'])}")
            return

    elif args.exposures:
        output = exposures
        if not args.json:
            print(f"[+] {len(exposures)} Existing Exposures in dataset (DO NOT DUPLICATE):")
            for e in exposures:
                target = (e.get('associatedAsset') or {}).get('value', 'unknown')
                print(f"  - [{e.get('severity', 'info')}] {e.get('title')} on {target}")
            return

    elif args.signals:
        output = signals
        if not args.json:
            print(f"[+] {len(signals)} Signals/Rules Available in dataset:")
            for s in signals:
                print(f"  - [{s.get('risk', 'info')}] {s.get('name')} (Category: {s.get('category', 'General')})")
            return

    elif args.match_signals or args.match_signal:
        target_name = args.match_signal
        output = match_signals_against_assets(assets, signals, target_name)
        if not args.json:
            matched_total = sum(item["match_count"] for item in output)
            print(f"[+] Signal Matching Evaluation ({len(output)} signals evaluated, {matched_total} asset matches):")
            for item in output:
                if item["match_count"] > 0:
                    print(f"\n  🎯 [{item['risk'].upper()}] {item['signal_name']} ({item['match_count']} matching assets)")
                    print(f"     Description: {item['description']}")
                    for m in item["matched_assets"]:
                        target_disp = m["subdomain"] or m["ip"] or m["value"]
                        print(f"     -> Match: {m['type']} '{m['value']}' on {target_disp}")
            return

    else:
        # Default summary
        counts = {}
        for a in assets:
            t = a.get("type", "unknown")
            counts[t] = counts.get(t, 0) + 1
        output = {
            "total_assets": len(assets),
            "asset_types": counts,
            "existing_exposures_count": len(exposures),
            "available_signals_count": len(signals)
        }
        if not args.json:
            print(f"[+] Attack Surface Dump Summary:")
            print(f"    - Total Asset Records: {len(assets)}")
            print(f"    - Existing Exposures: {len(exposures)}")
            print(f"    - Organization Signals/Rules: {len(signals)}")
            for t, c in sorted(counts.items()):
                print(f"    - {t}: {c}")
            return

    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
