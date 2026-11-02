# OWASP Top 10 to CWE Mapping Catalog

Standard mappings for Web Application Security assessments:

| Vulnerability Category | OWASP 2021 Reference | Primary CWE | Severity Baseline | Common Evidence / Indicators |
|---|---|---|---|---|
| Reflected Cross-Site Scripting (XSS) | A03:2021-Injection | CWE-79 | High | Unescaped HTML/JS payload reflected in DOM snapshot or alert/script execution. |
| Stored Cross-Site Scripting (XSS) | A03:2021-Injection | CWE-79 | High / Critical | Injected payload persists in database and executes on subsequent page loads. |
| Cross-Site Request Forgery (CSRF) | A01:2021-Broken Access Control | CWE-352 | Medium | State-changing POST/PUT requests accepted without anti-CSRF token or `SameSite` cookies. |
| Missing Security Headers (CSP, HSTS) | A05:2021-Security Misconfiguration | CWE-693 | Low / Info | Missing `Content-Security-Policy`, `Strict-Transport-Security`, or `X-Content-Type-Options`. |
| Missing Anti-Clickjacking Header | A05:2021-Security Misconfiguration | CWE-1021 | Medium | Missing `X-Frame-Options` and `frame-ancestors` directive in CSP. |
| Permissive CORS Policy | A05:2021-Security Misconfiguration | CWE-942 | Medium / High | Reflects arbitrary `Origin` header alongside `Access-Control-Allow-Credentials: true`. |
| Sensitive Cookie without Flags | A07:2021-Identification & Auth Failures | CWE-614 / CWE-1004 | Medium / Low | Session/auth cookie lacks `HttpOnly`, `Secure`, or has `SameSite=None`. |
| Insecure Direct Object References (IDOR)| A01:2021-Broken Access Control | CWE-639 | High / Critical | Sequential or predictable ID in URL path/parameter accesses another user's private data. |
| Open URL Redirect | A01:2021-Broken Access Control | CWE-601 | Medium / Low | User-supplied redirect parameter sends user to untrusted external domain. |
| Information Disclosure / Verbose Errors | A05:2021-Security Misconfiguration | CWE-209 | Low / Info | Stack traces, server version banners, or sensitive internal paths returned in HTTP response. |

