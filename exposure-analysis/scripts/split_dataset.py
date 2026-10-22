#!/usr/bin/env python3
"""
split_dataset.py
Splits an ASM attack surface dump file into separate assets.json and existing_exposures.json files.
Outputs summary statistics for planning.
"""

import sys
import os
import json
import argparse
from pathlib import Path

def split_dataset(input_path, out_dir=None):
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"[-] Error: File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if not out_dir:
        out_dir = input_file.parent
    else:
        out_dir = Path(out_dir)
    
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Reading dataset: {input_file}")
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assets = data.get("assets", [])
    existing_exposures = data.get("existing_exposures", [])
    signals = data.get("signals", []) or data.get("rules", [])

    assets_file = out_dir / "assets.json"
    exposures_file = out_dir / "existing_exposures.json"
    signals_file = out_dir / "signals.json"

    with open(assets_file, "w", encoding="utf-8") as f:
        json.dump(assets, f, indent=2)

    with open(exposures_file, "w", encoding="utf-8") as f:
        json.dump(existing_exposures, f, indent=2)

    with open(signals_file, "w", encoding="utf-8") as f:
        json.dump(signals, f, indent=2)

    # Compute breakdown by type
    type_counts = {}
    for a in assets:
        t = a.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    subdomains = set()
    ips = set()
    for a in assets:
        if a.get("type") == "subdomain" and a.get("value"):
            subdomains.add(a.get("value"))
        elif a.get("subdomain"):
            subdomains.add(a.get("subdomain"))
        if a.get("type") == "ip" and a.get("value"):
            ips.add(a.get("value"))
        elif a.get("ip"):
            ips.add(a.get("ip"))

    print(f"[+] Successfully split dataset:")
    print(f"    - Assets file: {assets_file} ({len(assets)} items)")
    print(f"    - Existing Exposures file: {exposures_file} ({len(existing_exposures)} items)")
    print(f"    - Signals/Rules file: {signals_file} ({len(signals)} items)")
    print(f"[+] Attack Surface Summary:")
    print(f"    - Unique Subdomains: {len(subdomains)}")
    print(f"    - Unique IPs: {len(ips)}")
    print(f"    - Available Signals to Validate: {len(signals)}")
    for t, count in sorted(type_counts.items()):
        print(f"    - Type '{t}': {count}")

    return {
        "assets_file": str(assets_file),
        "exposures_file": str(exposures_file),
        "signals_file": str(signals_file),
        "total_assets": len(assets),
        "total_exposures": len(existing_exposures),
        "total_signals": len(signals),
        "subdomains_count": len(subdomains),
        "ips_count": len(ips)
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Split ASM dataset dump into assets.json, existing_exposures.json, and signals.json")
    parser.add_argument("dataset", help="Path to the combined assets-<orgId>-<runId>.json dump file")
    parser.add_argument("--out-dir", "-o", help="Output directory to save split files (defaults to same folder as dataset)")
    args = parser.parse_args()

    split_dataset(args.dataset, args.out_dir)
