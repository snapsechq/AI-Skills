#!/usr/bin/env python3
"""
Results Validator for Cloud Security Skill
Validates that results.json complies strictly with the cloud vulnerability schema
and top-level { "results": [...] } format.
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
            errors.append(f"{prefix} invalid severity '{sev}'. Must be one of {VALID_SEVERITIES}")

        # Asset check
        asset = item.get("asset")
        if not isinstance(asset, dict) or "value" not in asset or not str(asset["value"]).strip():
            errors.append(f"{prefix} 'asset' must be an object with non-empty string 'value'")

        # Universal Vuln ID check
        uvid = str(item.get("universal_vuln_id") or "").strip()
        if not uvid:
            errors.append(f"{prefix} 'universal_vuln_id' cannot be empty")
        elif uvid in seen_ids:
            errors.append(f"{prefix} duplicate 'universal_vuln_id' detected: '{uvid}'")
        seen_ids.add(uvid)

        # CWE check
        cwe = item.get("cwe")
        if not isinstance(cwe, dict):
            errors.append(f"{prefix} 'cwe' must be an object with 'name' and 'value'")
        else:
            if not cwe.get("name") or not str(cwe.get("name")).strip():
                errors.append(f"{prefix} 'cwe.name' cannot be empty")
            val = str(cwe.get("value") or "").strip()
            if not val or not re.match(r"^CWE-\d+$", val):
                errors.append(f"{prefix} 'cwe.value' must match pattern 'CWE-<number>' (e.g. CWE-284), got '{val}'")

        # References check
        refs = item.get("references")
        if refs is not None:
            if not isinstance(refs, list):
                errors.append(f"{prefix} 'references' must be a list of URL strings")
            else:
                for ref in refs:
                    if not isinstance(ref, str) or not ref.startswith("http"):
                        errors.append(f"{prefix} invalid reference URL '{ref}'. Must start with http:// or https://")

    if errors:
        return False, errors
    return True, [f"Successfully validated {len(results)} findings."]

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        print(f"Usage: {sys.argv[0]} <path_to_results.json>")
        sys.exit(1)

    file_path = sys.argv[1]
    is_valid, messages = validate_results_file(file_path)

    if is_valid:
        print("[+] SUCCESS: Results file passed schema validation.")
        for msg in messages:
            print(f"    - {msg}")
        sys.exit(0)
    else:
        print("[!] FAILURE: Results file failed validation:")
        for err in messages:
            print(f"    - {err}")
        sys.exit(1)

if __name__ == "__main__":
    main()
