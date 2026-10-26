# Finding Validation Criteria & Rejection Guidelines

To maintain highest reporting quality and eliminate false positives, all candidate findings must satisfy the validation criteria below before inclusion in `results.json`.

---

## 1. Mandatory Thresholds for Valid Findings

Every accepted infrastructure finding must meet ALL of the following criteria:

1. **Reachable & Confirmed Active**:
   - The port and service were verified open and responsive during the current scan session.
   - Closed, filtered, or timeout responses must never be reported as vulnerabilities.
2. **Demonstrated Security Boundary Violation**:
   - For missing authentication (Redis, MongoDB, Kubelet): An actual command, query, or API request was answered without requiring credentials.
   - For weak credentials / community strings: The service accepted the credential (e.g. `public` for SNMP) and returned protected data.
   - For cryptographic weaknesses: The cipher or protocol was successfully negotiated during a live handshake.
3. **Plausible Real-World Impact**:
   - The issue presents a demonstrable attack vector (e.g. credential theft, remote access, data exfiltration, architectural reconnaissance).
4. **Reproducible Proof**:
   - The finding includes concrete reproduction steps (`steps_to_reproduce`) with exact commands and expected responses.

---

## 2. Catalog of Rejected Non-Findings

The agent must REJECT and omit any of the following non-findings:

| Category | Reason for Rejection | Action |
|---|---|---|
| **Speculative CVE from Generic Banner** | Merely detecting `Apache` or `OpenSSH` without exact version or proof that vulnerable module is enabled. | **Omit**. Do not report speculative CVEs. |
| **Filtered or Closed Port Warnings** | Informing the client that a port is closed or filtered is not a vulnerability. | **Omit**. Only report actual exposures on open ports. |
| **Standard Open Ports without Misconfiguration** | Port 80, 443, or 22 open with standard authentication and modern cryptography is expected network operations. | **Omit**. An open port alone is not a vulnerability. |
| **Self-Signed Certificate on Dedicated Internal IP** | Self-signed certificates on an internal or non-domain direct IP address without sensitive data exposure or MITM context. | **Downgrade to Low or Omit** unless it handles sensitive external user traffic. |
| **Missing HTTP Security Headers on Network Device** | Complaining about missing `X-Frame-Options` or `HSTS` on a network appliance login page that has no iframe usage or web application context. | **Omit** unless accompanied by a validated exploit scenario. |
| **Destructive or DoS Vulnerabilities** | Claiming a system is vulnerable to DoS (e.g. ping of death, Slowloris) without safe verification. | **Omit**. DoS attacks are out of scope. |
| **Theoretical Linux Distribution Version CVEs** | Reporting upstream CVEs on Debian/Ubuntu/RHEL packages where the vendor has backported security fixes without changing upstream version. | **Omit** unless backport status is verified or active proof of concept succeeds non-destructively. |
