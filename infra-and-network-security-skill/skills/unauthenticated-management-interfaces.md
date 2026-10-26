# Management Interface & Remote Access Security Guide

## Objective
Act as an **Appliance & Remote Management Auditor**. Systematically assess out-of-band management controllers, hardware BMCs, hypervisors, and network appliance administration consoles to detect unintended exposure, authentication bypasses, and default credentials.

---

## 1. IPMI / BMC (Port 623/udp)

### Testing Procedure:
1. **RMCP Ping & Channel Detection**:
   - Probe IPMI server version and capabilities:
     `nmap -sU -p 623 --script ipmi-version <target_ip>`
2. **Cipher 0 Authentication Bypass Check**:
   - Check if RMCP+ allows Cipher 0 (no encryption, no authentication hash verification):
     `nmap -sU -p 623 --script ipmi-cipher-zero <target_ip>`
   - **Finding**: Critical severity if Cipher 0 allows administrative BMC console takeover (`CWE-287`).
3. **RAKP Hash Extraction Vulnerability**:
   - IPMI 2.0 RAKP protocol transmits HMAC password hashes for requested usernames (e.g. `admin`, `ADMIN`).
   - If IPMI is exposed to the public internet, report **High Severity** (`CWE-306` / `CWE-200`) due to offline hash cracking risk.

---

## 2. Server Management Consoles (HP iLO, Dell iDRAC)

### Testing Procedure:
1. **Identify Console Service**:
   - Ports 443, 8443, 17988: check SSL certificate and title banner:
     `curl -k -sI https://<target_ip>/ | grep -iE 'iLO|iDRAC|Integrated Lights-Out'`
2. **Default Credential Check**:
   - Test standard manufacturer defaults (`Administrator:admin`, `root:calvin`, `admin:admin`) using non-destructive single attempts.
3. **Exposure Finding**:
   - Hardware management consoles MUST NEVER be directly routable on the public internet.
   - **Finding**: High severity (`CWE-16` / `CWE-284`) even if login prompt is presented, as firmware vulnerabilities allow full baseboard takeover.

---

## 3. Hypervisor & Virtualization Management (VMware ESXi, vCenter, Proxmox)

### Testing Procedure:
1. **ESXi Host Client (Port 443/tcp, Port 902/tcp)**:
   - Request HTTP banner: `curl -k -s https://<target_ip>/ | grep -i 'VMware ESXi'`
   - Query version string: `curl -k -s https://<target_ip>/mob/` (Managed Object Browser).
   - Port 902: `nc -nv <target_ip> 902` returns VMware authentication daemon string.
2. **Finding Classification**:
   - Publicly exposed ESXi management interface represents **High Severity** (`CWE-16` Security Misconfiguration) due to recurring high-impact zero-day and unauthenticated heap overflow CVEs (e.g. SLP daemon CVE-2021-21974).

---

## 4. Network Appliance Consoles (Firewalls, Routers, VPN Gateways)

### Testing Procedure:
1. **Appliance Fingerprinting**:
   - Detect web interfaces for Cisco ASDM, Fortinet FortiGate, SonicWall, pfSense, Palo Alto GlobalProtect, Citrix NetScaler.
2. **Known Authentication Flaws & Path Traversals**:
   - Inspect exact version against known remote pre-auth CVEs (e.g. Citrix Bleed CVE-2023-4966, FortiOS pre-auth bypass CVE-2022-40684).
   - Only report if specific pre-auth endpoint is responsive and verifies the vulnerable version condition.
