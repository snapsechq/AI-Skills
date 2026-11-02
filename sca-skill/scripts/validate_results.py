#!/usr/bin/env python3
"""
Results Validator for SCA Security Skill
Validates that results.json complies strictly with the SnapSec vulnerability schema
and format: { "results": [...] }.
"""

import sys
import os
import json
import re

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

def validate_results_file(file_path):
    if not os.path.exists(file_path):
        return False, [f"File not found: {file_path}"]

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            # Clean markdown code fences if present
            if content.startswith("```"):
                content = re.sub(r"^```(?:json)?\s*", "", content, flags=re.I)
                content = re.sub(r"\s*```$", "", content).strip()
            data = json.loads(content)
    except Exception as e:
        return False, [f"JSON parsing error: {e}"]

    if not isinstance(data, dict):
        return False, [f"Root of results must be a JSON object, got {type(data).__name__}"]

    if "results" not in data:
        return False, ["Missing mandatory top-level key 'results'. Format must be { \"results\": [...] }."]

    results = data["results"]
    if not isinstance(results, list):
        return False, [f"'results' must be a JSON array, got {type(results).__name__}"]

    if len(results) == 0:
        return True, ["Zero findings reported. Output schema is valid (empty array)."]

    errors = []
    seen_ids = set()

    for idx, item in enumerate(results):
        prefix = f"Finding [{idx}] ({item.get('title', 'Untitled')}):"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be a JSON object")
            continue

        # Check required fields
        required_fields = [
            "orgId",
            "pentestId",
            "title",
            "description",
            "steps_to_reproduce",
            "impact",
            "severity",
            "universal_vuln_id",
            "asset",
            "cwe"
        ]
        for rf in required_fields:
            if rf not in item or item[rf] is None or item[rf] == "":
                errors.append(f"{prefix} missing or empty required field '{rf}'")

        # Severity check
        sev = str(item.get("severity") or "").lower()
        if sev not in VALID_SEVERITIES:
            errors.append(f"{prefix} invalid severity '{sev}'. Must be one of: {sorted(VALID_SEVERITIES)}")

        # Asset check
        asset = item.get("asset")
        if not isinstance(asset, dict) or not asset.get("value"):
            errors.append(f"{prefix} 'asset' must be an object containing non-empty 'value' field (e.g. package-lock.json:pkg@ver)")

        # CWE check
        cwe = item.get("cwe")
        if not isinstance(cwe, dict) or not cwe.get("name") or not cwe.get("value"):
            errors.append(f"{prefix} 'cwe' must be an object with 'name' and 'value' (e.g. CWE-1321)")

        # universal_vuln_id uniqueness
        uv_id = item.get("universal_vuln_id")
        if uv_id:
            if uv_id in seen_ids:
                errors.append(f"{prefix} duplicate universal_vuln_id '{uv_id}'")
            seen_ids.add(uv_id)

    if errors:
        return False, errors
    return True, [f"Validation successful! {len(results)} finding(s) passed all schema constraints."]

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 validate_results.py <path_to_results.json>")
        sys.exit(1)

    file_path = sys.argv[1]
    is_valid, messages = validate_results_file(file_path)

    for msg in messages:
        if is_valid:
            print(f"[+] {msg}")
        else:
            print(f"[-] {msg}")

    sys.exit(0 if is_valid else 1)

if __name__ == "__main__":
    main()

