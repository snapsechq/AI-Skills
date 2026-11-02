#!/usr/bin/env python3
"""
Context Parser for Web Application Security Skill
Reads execution context (context.json or context-<runId>.json), normalizes target URL,
scope, credentials, and initializes session workspace.
"""

import sys
import os
import json
import re

def parse_context(context_path):
    if not os.path.exists(context_path):
        print(f"[parse_context] Error: Context file not found at {context_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(context_path, "r", encoding="utf-8") as f:
            ctx = json.load(f)
    except Exception as e:
        print(f"[parse_context] Error parsing context JSON: {e}", file=sys.stderr)
        sys.exit(1)

    org_id = ctx.get("orgId") or ctx.get("org_id") or "default_org"
    run_id = ctx.get("runId") or ctx.get("run_id") or "manual_run"
    pentest_id = ctx.get("pentestId") or ctx.get("pentest_id") or "default_pentest"
    scan_id = ctx.get("scanId") or ctx.get("scan_id") or run_id

    # Extract target URL
    target_url = ctx.get("target_url") or ctx.get("targetUrl") or ctx.get("url") or ctx.get("domain") or ""
    
    # Check context.text if target_url not in standard fields
    if not target_url and isinstance(ctx.get("text"), str):
        url_match = re.search(r"https?://[^\s,]+", ctx["text"])
        if url_match:
            target_url = url_match.group(0).rstrip("/")

    # Check pentest_config if available
    pentest_config = ctx.get("pentest_config") or {}
    if not target_url and isinstance(pentest_config, dict):
        target_url = pentest_config.get("target_url") or pentest_config.get("url") or pentest_config.get("domain") or ""

    if not target_url:
        print("[parse_context] Warning: No target URL identified in context.", file=sys.stderr)

    credentials = ctx.get("credentials") or pentest_config.get("credentials") or {}
    scope = ctx.get("scope") or [target_url] if target_url else []

    session_dir = f"./session-{run_id}"
    os.makedirs(session_dir, exist_ok=True)
    os.makedirs("./artifacts", exist_ok=True)

    normalized_info = {
        "orgId": org_id,
        "runId": run_id,
        "pentestId": pentest_id,
        "scanId": scan_id,
        "target_url": target_url,
        "credentials": credentials,
        "scope": scope,
        "session_dir": session_dir
    }

    staged_context_file = os.path.join(session_dir, "normalized_context.json")
    with open(staged_context_file, "w", encoding="utf-8") as f:
        json.dump(normalized_info, f, indent=2)

    print(f"[parse_context] Staged normalized context to {staged_context_file}")
    print(f"[parse_context] Target URL: {target_url}")
    print(f"[parse_context] Run ID: {run_id} | Pentest ID: {pentest_id}")
    return normalized_info

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parse_context.py <path_to_context.json>", file=sys.stderr)
        sys.exit(1)

    parse_context(sys.argv[1])

