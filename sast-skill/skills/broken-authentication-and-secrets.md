# Auditing Authentication, Authorization, and Hardcoded Secrets

## 1. Hardcoded Credentials & API Keys (CWE-798)
### Vulnerable Patterns:
- Hardcoded API keys, JWT secrets, database connection strings containing passwords:
  ```javascript
  const JWT_SECRET = "production_super_secret_key_123!";
  ```
- Storing unencrypted RSA private keys or cloud credentials in repo files.

### Verification & Remediation:
- **Remediation**: Ingest credentials from environment variables (`process.env.SECRET_KEY`) or secret managers (HashiCorp Vault, AWS Secrets Manager).
- **False Positive Elimination**: If the file is a unit test mock (e.g. `tests/mockData.js`), documentation example, or contains obvious dummy text (`"your-api-key-here"`), discard as false positive.

---

## 2. Broken JWT Verification (CWE-287)
### Vulnerable Patterns:
- Using `jwt.decode()` instead of `jwt.verify()` when authorizing API requests.
- Specifying `algorithms: ['none']` or failing to enforce strict algorithm checking.
- Using symmetric HMAC secrets with asymmetric RSA public key endpoints.

