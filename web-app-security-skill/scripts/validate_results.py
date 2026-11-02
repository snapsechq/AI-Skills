#!/usr/bin/env python3
"""
Results Validator for Web Application Security Skill
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

        for req in required_fields:
            if req not in item or item[req] is None:
                errors.append(f"{prefix} missing required field '{req}'")

        severity = str(item.get("severity", "")).lower()
        if severity not in VALID_SEVERITIES:
            errors.append(f"{prefix} invalid severity '{severity}'. Must be one of {VALID_SEVERITIES}")

        # Validate universal_vuln_id
        uvid = item.get("universal_vuln_id")
        if not isinstance(uvid, str) or len(uvid.strip()) < 3:
            errors.append(f"{prefix} universal_vuln_id must be a non-empty string of >= 3 chars")
        elif uvid in seen_ids:
            errors.append(f"{prefix} duplicate universal_vuln_id '{uvid}'")
        else:
            seen_ids.add(uvid)

        # Validate asset object
        asset = item.get("asset")
        if not isinstance(asset, dict) or not asset.get("value"):
            errors.append(f"{prefix} 'asset' must be an object with non-empty 'value' field (e.g. target URL or endpoint)")

        # Validate CWE object
        cwe = item.get("cwe")
        if not isinstance(cwe, dict) or not cwe.get("name") or not cwe.get("value"):
            errors.append(f"{prefix} 'cwe' must be an object with 'name' and 'value' (e.g. {{ 'name': 'Cross-site Scripting', 'value': 'CWE-79' }})")
        elif not re.match(r"^CWE-\d+$", str(cwe.get("value", ""))):
            errors.append(f"{prefix} cwe.value must match pattern '^CWE-\\d+$' (got '{cwe.get('value')}')")

    if errors:
        return False, errors
    return True, [f"Validation successful: {len(results)} finding(s) passed all schema constraints."]

if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "artifacts/results.json"
    is_valid, messages = validate_results_file(target_file)
    for msg in messages:
        print(("[PASSED] " if is_valid else "[FAILED] ") + msg)
    sys.exit(0 if is_valid else 1)

