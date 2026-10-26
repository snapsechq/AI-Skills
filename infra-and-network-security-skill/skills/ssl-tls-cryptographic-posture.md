# SSL/TLS Cryptographic Posture Auditing Guide

## Objective
Act as a **Cryptographic & Transport Security Auditor**. Assess SSL/TLS configurations across all encrypted endpoints (HTTPS, SMTPS, LDAPS, FTPS, VPNs) to identify obsolete protocols, weak cipher suites, certificate validation defects, and cryptographic vulnerabilities.

---

## 1. Deprecated Protocol Evaluation (SSLv2, SSLv3, TLS 1.0, TLS 1.1)

### Testing Procedure:
1. **Protocol Handshake Probing**:
   - Use `python3 scripts/service_prober.py tls <target_ip> <port>` or `openssl`:
     ```bash
     openssl s_client -connect <target_ip>:<port> -tls1
     openssl s_client -connect <target_ip>:<port> -tls1_1
     ```
   - Alternatively:
     ```bash
     nmap -p <port> --script ssl-enum-ciphers <target_ip>
     ```
2. **Evaluate Results**:
   - If SSLv2 or SSLv3 connects -> **HIGH VULNERABILITY** (`CWE-326`).
   - If TLS 1.0 or TLS 1.1 connects -> **LOW VULNERABILITY** (`CWE-326`). Deprecated by RFC 8996 and prohibited by PCI-DSS v4.0.

---

## 2. Weak & Insecure Cipher Suites

### Testing Procedure:
1. **Identify Negotiated Ciphers**:
   - Check if the server negotiates any of the following weak ciphers:
     - **RC4 (Stream Cipher)**: `RC4-SHA`, `RC4-MD5` (Vulnerable to Bar Mitzvah and NOMORE attacks).
     - **3DES / DES**: `DES-CBC3-SHA` (Vulnerable to Sweet32 64-bit block collision).
     - **Export / Null Ciphers**: `EXP-` or `NULL` (Zero or intentionally broken encryption).
     - **CBC Mode with TLS 1.0**: Vulnerable to BEAST.
2. **Finding Classification**:
   - Support for RC4 or 3DES: **Medium** severity (`CWE-326`).
   - Support for NULL or EXPORT ciphers: **Critical/High** severity (`CWE-326`).

---

## 3. SSL/TLS Certificate Validation

### Testing Procedure:
1. **Query Peer Certificate**:
   ```bash
   openssl s_client -connect <target_ip>:<port> -servername <target_hostname> < /dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer
   ```
2. **Evaluate Defects**:
   - **Expired Certificate**: Certificate `notAfter` date is in the past -> **Medium** severity (`CWE-295`).
   - **Domain Name Mismatch**: Subject CN and Subject Alternative Names (SAN) do not match the target hostname -> **Low** severity (`CWE-295`).
   - **Untrusted Self-Signed Certificate on Public Service**: Service handles client data with an untrusted root -> **Low** severity (`CWE-295`).
   - Note: If testing a raw IP address without a domain name, do NOT flag domain mismatch as an issue if it is intended for direct internal routing.

---

## 4. Known Cryptographic Protocol Vulnerabilities

### Target Checks:
1. **Heartbleed (CVE-2014-0160)**:
   - Check if OpenSSL version on port 443 is vulnerable to heartbeat memory leakage:
     `nmap -p <port> --script ssl-heartbleed <target_ip>`
   - Only report if the vulnerability script actively confirms memory leakage (`Critical`, `CWE-200`).
2. **Diffie-Hellman Weak Key Exchange (Logjam CVE-2015-4000)**:
   - Check if DH parameters are smaller than 2048 bits:
     `nmap -p <port> --script ssl-dh-params <target_ip>`
