# Auditing Server-Side Request Forgery (SSRF - CWE-918)

## 1. Untrusted URL Fetching
### Vulnerable Patterns:
- Application accepts a target URL or IP address from an HTTP request and fetches it directly:
  ```javascript
  const response = await axios.get(req.query.avatarUrl);
  ```
- Webhook endpoints that trigger HTTP POST callbacks to user-supplied endpoints without IP validation.

## 2. Exploitation Scenarios
- Accessing internal cloud metadata endpoints: `http://169.254.169.254/latest/meta-data/`
- Probing internal VPC infrastructure (e.g. `http://10.0.0.5:6379` Redis, internal Elasticsearch, Consul).

## 3. Verification & Remediation:
- **Remediation**:
  - Implement DNS pre-resolution and validate that the resolved IP address does NOT belong to RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), or loopback (`127.0.0.0/8`).
  - Restrict URL schemes to `http` and `https` (prevent `file://`, `gopher://`, `dict://`).
  - Disable automatic HTTP redirect following or re-verify destination on redirect.
- **False Positive Elimination**:
  - If the outbound request URL is constructed with a hardcoded trusted host (e.g. `https://api.github.com/users/${encodeURIComponent(username)}`), SSRF is not possible.

