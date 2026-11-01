# Auditing Cryptography (CWE-327) and Sensitive Data Exposure

## 1. Broken / Weak Algorithms
### Vulnerable Patterns:
- Using MD5 or SHA1 for password hashing or integrity checks:
  ```javascript
  const hash = crypto.createHash("md5").update(password).digest("hex");
  ```
- Using AES in ECB mode (`aes-128-ecb` or `aes-256-ecb`), which leaks structural patterns in ciphertext.
- Using `Math.random()` or Python `random` for cryptographic tokens, passwords, or session IDs.

## 2. Verification & Remediation:
- **Remediation**:
  - For passwords, use modern memory-hard key derivation functions: Argon2id, bcrypt, or scrypt.
  - For symmetric encryption, use authenticated modes: AES-256-GCM or ChaCha20-Poly1305.
  - For random tokens, use cryptographically secure pseudorandom number generators (CSPRNG): `crypto.randomBytes()`, `secrets.token_hex()`.
- **False Positive Elimination**:
  - If MD5/SHA1 is used solely as a cache key or non-security checksum for static assets (e.g. webpack bundle hash), it is not a cryptographic vulnerability.

