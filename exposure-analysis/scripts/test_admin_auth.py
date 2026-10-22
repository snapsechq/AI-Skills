#!/usr/bin/env python3
"""
test_admin_auth.py
Safely probes an identified authentication endpoint with common default credentials.
Designed to be non-destructive and stops immediately upon identifying valid credentials.
"""

import sys
import json
import time
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path

def load_credentials(creds_file=None):
    if not creds_file:
        creds_file = Path(__file__).resolve().parent.parent / "resources" / "top_credentials.json"
    if Path(creds_file).exists():
        with open(creds_file, "r") as f:
            return json.load(f)
    return {
        "usernames": ["admin", "administrator", "root", "user"],
        "passwords": ["admin", "admin123", "password", "root", "123456"]
    }

def test_login(url, username_field="username", password_field="password", creds_file=None):
    creds = load_credentials(creds_file)
    usernames = creds.get("usernames", [])[:10]
    passwords = creds.get("passwords", [])[:10]

    print(f"[*] Testing {len(usernames)}x{len(passwords)} top credentials on {url}")
    headers = {"User-Agent": "ASM-Validation-Agent/1.0", "Content-Type": "application/x-www-form-urlencoded"}

    for u in usernames:
        for p in passwords:
            data = urllib.parse.urlencode({username_field: u, password_field: p}).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    code = response.getcode()
                    body = response.read().decode("utf-8", errors="ignore")
                    if code in (200, 302) and ("dashboard" in body.lower() or "logout" in body.lower() or "token" in body.lower()):
                        print(f"[!] SUCCESS: Valid credentials found for {url}: {u}:{p}")
                        return {"success": True, "username": u, "password": p, "status_code": code}
            except urllib.error.HTTPError as e:
                # 401/403 expected on failed login
                pass
            except Exception as e:
                print(f"[-] Connection error on {url}: {e}")
                return {"success": False, "error": str(e)}
            time.sleep(0.2)

    print(f"[-] No common credentials succeeded on {url}")
    return {"success": False, "reason": "No common default credentials matched"}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python3 test_admin_auth.py <login_url> [user_field] [pass_field]")
        sys.exit(0)

    target_url = sys.argv[1]
    u_field = sys.argv[2] if len(sys.argv) > 2 else "username"
    p_field = sys.argv[3] if len(sys.argv) > 3 else "password"

    result = test_login(target_url, u_field, p_field)
    print(json.dumps(result, indent=2))
