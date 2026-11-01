# SAST Verification Criteria & False-Positive Elimination Rules

When auditing static scanner findings (such as Semgrep), use the following criteria to confirm real vulnerabilities vs. eliminate false positives:

## 1. Taint Tracking Criteria (Source to Sink)
A finding is **CONFIRMED** only if:
1. **Source**: An untrusted external input exists (e.g. `req.body`, `req.query`, URL parameters, HTTP headers, unauthenticated message queue payloads).
2. **Sink**: The untrusted input reaches a sensitive function without effective sanitization (e.g. SQL query, system shell execution, file system read/write, template engine rendering, SSRF HTTP client).
3. **Control Gap**: No sanitization, strong type-casting (e.g. `parseInt()`), or parameterization intervenes between source and sink.

## 2. False Positive Disqualifiers
Discard findings as **FALSE POSITIVE** if any of the following apply:
1. **Parameterized Queries / Prepared Statements**: The database driver or ORM (e.g., Prisma, Sequelize, Mongoose, SQLAlchemy) automatically parameterizes the values.
2. **Input Strictly Hardcoded or Constant**: The value originates from a configuration file, environment constant, or internal enum rather than user input.
3. **Test Code & Mock Fixtures**: Findings located in `test/`, `tests/`, `spec/`, or mock fixture files that are never deployed in production.
4. **Strong Schema Validation / Whitelisting**: The parameter has been validated against an allowlist enum or strict regex prior to reaching the sink.
5. **Contextual Escaping**: Output is encoded using a framework-native contextual escaping mechanism (e.g. React JSX auto-escaping, Jinja2 autoescape).

## 3. Severity Assignment Rules
- **CRITICAL**: Remote Code Execution (RCE), unauthenticated SQL Injection leading to data dump, hardcoded production master credentials, unauthenticated SSRF reaching cloud metadata.
- **HIGH**: Authenticated SQLi, Stored XSS in admin portals, Path Traversal permitting arbitrary file read, broken access control in core business logic.
- **MEDIUM**: Reflected XSS requiring complex social engineering, weak hashing algorithms on non-critical data, missing rate limiting.
- **LOW**: Information disclosure via verbose error messages, missing security headers.

