# CWE & CVE Mapping Catalog for Infrastructure and Network Security

This catalog provides standardized Common Weakness Enumeration (CWE) mappings and CVE correlation guidelines for network, perimeter infrastructure, and white-box internal host security findings.

---

## 1. Standard CWE Mapping Matrix

| Finding Type | CWE ID | CWE Title | Typical Affected Services / Scenarios |
|---|---|---|---|
| Unauthenticated Database / Cache | `CWE-306` | Missing Authentication for Critical Function | Redis (6379), MongoDB (27017), Elasticsearch (9200), Memcached (11211) (External or Localhost) |
| Insecure Sudo Privilege Escalation | `CWE-269` | Improper Privilege Management | Sudoers NOPASSWD wildcard or GTFOBins executable accessible to standard user |
| Exposed Docker Daemon Socket | `CWE-250` | Execution with Unnecessary Privileges | `/var/run/docker.sock` accessible by non-root user enabling container breakout |
| Insecure File Permissions on Root Scripts | `CWE-732` | Incorrect Permission Assignment for Critical Resource | World-writable cron script or systemd service unit executed as root |
| Plaintext Credentials in Configuration | `CWE-522` | Insufficiently Protected Credentials | World-readable `.env`, database configuration, or unencrypted private keys on filesystem |
| Insecure SSH Daemon Hardening | `CWE-16` | Configuration | `PermitRootLogin yes`, `PermitEmptyPasswords yes`, or weak ciphers in `sshd_config` |
| Anonymous Container / Orchestrator API | `CWE-287` | Improper Authentication | Kubernetes Kubelet (10250), Docker API (2375), etcd (2379) |
| Default Community String / Credentials | `CWE-798` | Use of Hard-coded Credentials | SNMP (`public`/`private` on 161), default router/switch web logins |
| Cleartext Protocol Transmission | `CWE-319` | Cleartext Transmission of Sensitive Information | Telnet (23), FTP (21), HTTP (80) transmitting credentials |
| Deprecated TLS / Weak Cipher Suites | `CWE-326` | Inadequate Encryption Strength | HTTPS (443), LDAPS (636), SMTPS with TLS 1.0, 1.1, RC4, 3DES, EXPORT |
| Improper Access Control / Share Exposure | `CWE-284` | Improper Access Control | Open SMB shares (445), NFS exports with `no_root_squash` (2049) |
| System / Version Information Leakage | `CWE-200` | Exposure of Sensitive Information to an Unauthorized Actor | SNMP MIB leakage, verbose HTTP/SSH banners, NTP monlist |
| Anonymous File Transfer Access | `CWE-287` | Improper Authentication | FTP anonymous login enabled with access to filesystem |
| Open Mail Relay | `CWE-284` | Improper Access Control | SMTP (25, 587) accepting external outbound relays |
| DNS Zone Transfer Accessible | `CWE-200` | Exposure of Sensitive Information to an Unauthorized Actor | DNS (53) AXFR query allowed to untrusted external clients |
| Insecure Management Interface Exposed | `CWE-16` | Configuration | Publicly exposed IPMI (623), iLO, ESXi management consoles |
| Expired / Invalid SSL Certificate | `CWE-295` | Improper Certificate Validation | Expired, revoked, or untrusted TLS certificates on public interfaces |

---

## 2. CVE Attribution Rules

When attributing a CVE to an infrastructure or internal host finding, adhere strictly to these rules:

1. **Exact Version Requirement**:
   - Only assign a CVE if the service banner, handshake, or local package manager query provides the **exact software version** (e.g. `OpenSSH 7.2p2`, `Apache 2.4.49`, or `kernel 5.10.0-8`).
   - Do NOT guess or infer a CVE based purely on a generic product name without version confirmation.
2. **Precondition Verification**:
   - Verify whether the target's operating system backports patches (e.g. Debian, Ubuntu, Red Hat backport security fixes while keeping the upstream package version unchanged).
   - If backporting is likely (e.g. `Debian-10+deb10u2`), verify whether the specific vulnerable function or directive is actively exposed before asserting high severity.
3. **Non-CVE Misconfigurations**:
   - If an issue stems from configuration error (e.g. Redis without password on 127.0.0.1 or 0.0.0.0, SNMP community `public`, anonymous SMB share, weak TLS ciphers, sudoers NOPASSWD, world-writable cron script), set `"cve": ""` (empty string). Do NOT force a CVE onto configuration weaknesses.
