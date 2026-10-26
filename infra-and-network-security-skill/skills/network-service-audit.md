# Network Service & Protocol Auditing Guide

## Objective
Act as a **Network Protocol Auditor**. Systematically evaluate standard network services discovered during reconnaissance to identify improper access controls, default credentials, legacy unencrypted protocols, and configuration exposures.

---

## 1. SSH (Port 22/tcp)

### Checks to Perform:
1. **Authentication Policy**:
   - Determine whether password authentication is permitted or if public key authentication is strictly enforced.
   - Command: `ssh -o PreferredAuthentications=none -o StrictHostKeyChecking=no target@<target_ip>`
   - If the server responds with `Permission denied (publickey,password)`, password authentication is enabled.
2. **Weak Cryptographic Ciphers & Key Exchange**:
   - Check if weak ciphers (e.g. `3des-cbc`, `arcfour`, `aes128-cbc`) or weak MACs (`hmac-md5`, `hmac-sha1-96`) are accepted.
   - Command: `nmap -p 22 --script ssh2-enum-algos <target_ip>`
   - **Finding**: High/Medium if deprecated ciphers like `arcfour` or `3des-cbc` are enabled (`CWE-326`).
3. **Known Version Vulnerabilities**:
   - Check banner against OpenSSH CVE databases (e.g. Terrapin CVE-2023-48795, regreSSHion CVE-2024-6387).
   - Verify OS distribution backporting before declaring severity.

---

## 2. FTP & TFTP (Ports 21/tcp, 69/udp)

### Checks to Perform:
1. **Anonymous Authentication**:
   - Test anonymous login: `ftp -n <target_ip>` with user `anonymous` and password `anonymous@example.com`.
   - Alternatively: `nmap -p 21 --script ftp-anon <target_ip>`.
   - **Finding**: If anonymous login grants access to read internal files or write permissions (`CWE-287`).
2. **Cleartext Protocol Transmission**:
   - FTP transmits credentials in plaintext across the wire.
   - If public FTP is used without TLS (`AUTH TLS`), report `CWE-319` (Cleartext Transmission of Sensitive Information).
3. **TFTP Unauthenticated Probing**:
   - For port 69/udp: test reading standard configuration files without authentication:
     `tftp <target_ip> -c get /etc/passwd` or `get startup-config`.

---

## 3. SMB / Samba (Ports 445/tcp, 139/tcp)

### Checks to Perform:
1. **Null Session & Guest Access**:
   - Probe if null sessions (anonymous username and blank password) are accepted:
     `smbclient -L //<target_ip> -N` or `nmap -p 445 --script smb-enum-shares,smb-security-mode <target_ip>`.
   - **Finding**: High severity if null session permits browsing shares or enumerating local users (`CWE-284`).
2. **Legacy SMBv1 Dialect Enabled**:
   - Check if SMBv1 (NT LM 0.12) is supported:
     `nmap -p 445 --script smb-protocols <target_ip>`.
   - **Finding**: Medium severity (`CWE-326` / `CWE-16`) due to lack of encryption and vulnerability to legacy relay attacks.

---

## 4. NFS (Port 2049/tcp, Port 111 rpcbind)

### Checks to Perform:
1. **Showmount Export Enumeration**:
   - Query exported file systems: `showmount -e <target_ip>`.
2. **Unrestricted Network Access & No Root Squash**:
   - Check export list permissions: if exports show `*` or wide CIDR masks without client authentication.
   - **Finding**: Critical/High if an export allows anonymous mounting with `no_root_squash` (`CWE-284`).

---

## 5. SNMP (Port 161/udp)

### Checks to Perform:
1. **Default Community Strings**:
   - Probe SNMPv1 and SNMPv2c using default community string `public`:
     `snmpwalk -v 2c -c public <target_ip> 1.3.6.1.2.1.1`
   - Test write access with community string `private`:
     `snmpwalk -v 2c -c private <target_ip> 1.3.6.1.2.1.1`
2. **Information Leakage**:
   - Extract `sysDescr` (operating system build, kernel, device type).
   - Extract network interfaces (`1.3.6.1.2.1.4.20`) and active processes.
   - **Finding**: Medium severity for read-only `public` community (`CWE-798` / `CWE-200`); Critical/High if write access is enabled.

---

## 6. SMTP (Ports 25/tcp, 587/tcp)

### Checks to Perform:
1. **Open Mail Relay**:
   - Check if the mail server accepts relaying email between arbitrary external domains:
     `nmap -p 25 --script smtp-open-relay <target_ip>`
   - **Finding**: High severity if an external attacker can abuse the server for phishing/spam campaigns (`CWE-284`).
2. **User Enumeration**:
   - Test `VRFY` and `EXPN` commands to determine if internal system usernames can be confirmed without credentials.

---

## 7. DNS (Port 53/tcp, 53/udp)

### Checks to Perform:
1. **Zone Transfer (AXFR)**:
   - Query DNS server for full zone transfer:
     `dig @<target_ip> <domain> AXFR`
   - **Finding**: Medium severity if full zone records are disclosed to unauthorized clients (`CWE-200`).
2. **Open DNS Recursion**:
   - Probe if external DNS queries for arbitrary domains (e.g. `google.com`) are answered:
     `dig @<target_ip> google.com A +recurse`
   - **Finding**: Medium/Low severity if DNS server operates as an open resolver vulnerable to DDoS amplification (`CWE-400`).
