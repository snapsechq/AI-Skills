# HTTP Security Headers & Cross-Origin Configuration

This guide details inspecting HTTP response headers and CORS configurations.

## 1. Inspecting HTTP Response Headers
Inspect server responses captured during navigation:
```bash
agent-browser network requests
```
Verify the presence and configuration of key security headers:
* **`Content-Security-Policy` (CSP)**: Restricts sources for scripts, styles, and frames.
* **`X-Frame-Options`**: Prevents clickjacking (`DENY` or `SAMEORIGIN`).
* **`X-Content-Type-Options`**: Must be set to `nosniff` to avoid MIME sniffing attacks.
* **`Strict-Transport-Security` (HSTS)**: Ensures browsers only use HTTPS (`max-age=31536000; includeSubDomains`).

## 2. Cross-Origin Resource Sharing (CORS) Verification
Test how the server responds to arbitrary cross-origin requests:
* Send a request with `Origin: https://attacker.example.com`.
* Check if the server responds with:
  * `Access-Control-Allow-Origin: https://attacker.example.com`
  * `Access-Control-Allow-Credentials: true`
* This combination allows an attacker's domain to read private response data from the user's session.

