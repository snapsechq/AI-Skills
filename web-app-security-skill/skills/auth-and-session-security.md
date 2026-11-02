# Authentication, Session Management, & Access Control Testing

This guide details testing authentication mechanisms, session tokens, and access control boundaries.

## 1. Automated Login via agent-browser
When authentication credentials are provided in `context.json`:
```bash
# 1. Navigate to login page
agent-browser open <LOGIN_URL>
agent-browser wait 1500
agent-browser snapshot -i

# 2. Fill credentials and submit
agent-browser fill @e1 "<USERNAME>" && \
agent-browser fill @e2 "<PASSWORD>" && \
agent-browser click @e3 && \
agent-browser wait 2000

# 3. Confirm login success
agent-browser snapshot -i
```

## 2. Cookie Security Flags
Inspect all session tokens and cookies set by the application:
```bash
agent-browser cookies get
```
Verify the following flags:
* **`HttpOnly`**: Must be set for session/auth tokens (prevents access via JavaScript `document.cookie`, mitigating XSS credential theft).
* **`Secure`**: Must be set to ensure cookies are only transmitted over TLS/HTTPS.
* **`SameSite`**: Should be `Lax` or `Strict` to defend against Cross-Site Request Forgery (CSRF).

## 3. Insecure Direct Object References (IDOR)
* Capture authenticated requests to user resources (e.g. `/api/v1/user/101/invoices`).
* Observe if incrementing/altering the resource identifier grants unauthorized access to other tenants' objects.

