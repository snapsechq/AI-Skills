#!/usr/bin/env python3
"""
probe_asset.py
Safely probes an asset URL for connectivity, headers, status codes, and common critical sensitive paths.
"""

import sys
import json
import urllib.request
import urllib.error
import urllib.parse
import ssl

SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/actuator/health",
    "/actuator/env",
    "/swagger-ui.html",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/metrics",
    "/phpinfo.php",
    "/debug"
]

def probe(base_url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    results = {
        "url": base_url,
        "live": False,
        "status_code": None,
        "headers": {},
        "interesting_endpoints": []
    }

    try:
        req = urllib.request.Request(
            base_url,
            headers={"User-Agent": "ASM-Validation-Agent/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            results["live"] = True
            results["status_code"] = resp.getcode()
            results["headers"] = dict(resp.headers)
    except urllib.error.HTTPError as e:
        results["live"] = True
        results["status_code"] = e.code
        results["headers"] = dict(e.headers)
    except Exception as e:
        results["error"] = str(e)
        return results

    # Probe sensitive paths
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in SENSITIVE_PATHS:
        check_url = origin + path
        try:
            req = urllib.request.Request(
                check_url,
                headers={"User-Agent": "ASM-Validation-Agent/1.0"}
            )
            with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
                if r.getcode() == 200:
                    results["interesting_endpoints"].append({
                        "path": path,
                        "url": check_url,
                        "status": 200,
                        "content_length": r.headers.get("Content-Length")
                    })
        except Exception:
            continue

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python3 probe_asset.py <url>")
        sys.exit(0)

    res = probe(sys.argv[1])
    print(json.dumps(res, indent=2))
