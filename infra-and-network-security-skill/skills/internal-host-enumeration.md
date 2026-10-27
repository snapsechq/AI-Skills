# White-Box Internal Host Security Enumeration Guide

## Objective
Act as a **White-Box Internal Host Security Auditor**. When white-box testing is selected and SSH credentials are provided (`pentest_config.ssh`), leverage authorized host access to systematically evaluate the host from the inside. Identify privilege escalation boundaries, unauthenticated localhost-only listeners, insecure file permissions, exposed credentials, and daemon configuration weaknesses.

---

## 1. SSH Session Establishment & Safe Execution

### Connection Procedure:
1. Ingest SSH configuration from `session-<runId>/ssh_target.json` or the context file.
2. If `auth_method` is `key`, use the key written to `session-<runId>/ssh_key` (ensuring `0600` permissions):
   ```bash
   ssh -i session-<runId>/ssh_key -p <port> -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes <username>@<host> "<command>"
   ```
3. If `auth_method` is `password`, utilize SSH password authentication:
   ```bash
   sshpass -p "<secret>" ssh -p <port> -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null <username>@<host> "<command>"
   ```
4. **Non-Destructive Execution Principle**:
   - Only execute non-destructive, read-only inspection commands.
   - **Never** add user accounts, modify `/etc/passwd`, alter `/etc/shadow`, overwrite binaries, modify crontabs, or reboot services.

---

## 2. Localhost & Loopback Service Auditing (127.0.0.1)

Services bound solely to `127.0.0.1` or internal virtual interfaces are hidden from external network scans but are accessible to any local process or compromised service.

### Testing Procedure:
1. **Enumerate Local Listeners**:
   Execute inside the target host:
   ```bash
   ss -tulpn || netstat -tulpn
   ```
2. **Identify Loopback Listeners**:
   Inspect ports listening on `127.0.0.1:<port>` or `[::1]:<port>`:
   - Port 6379 (Redis)
   - Port 27017 (MongoDB)
   - Port 9200 (Elasticsearch)
   - Port 11211 (Memcached)
   - Port 3306 / 5432 (MySQL / PostgreSQL)
   - High ports: 8080, 8081, 8888, 9090 (Internal microservices, Prometheus, admin APIs)
3. **Verify Boundary Violation**:
   - **Local Redis**: Probe without password:
     `redis-cli -p 6379 ping` or `nc 127.0.0.1 6379 <<< "INFO"`
     If response contains `redis_version` without `NOAUTH` -> **VULNERABILITY**.
   - **Local Elasticsearch**: Probe without authentication:
     `curl -s http://127.0.0.1:9200/_cat/indices`
     If index metadata is returned -> **VULNERABILITY**.
   - **Internal Management API**: Test if administrative endpoints on localhost return sensitive metrics, internal routes, or permit unauthenticated commands.
4. **Finding Classification**:
   - **Title**: Unauthenticated Internal Datastore Service Accessible on Local Loopback Interface
   - **Severity**: `high`
   - **CWE**: `CWE-306` (Missing Authentication for Critical Function)
   - **Asset**: `<target_host>:<local_port>`
   - **Universal Vuln ID**: `local-unauth-listener:<target_host>:<local_port>`

---

## 3. Privilege Escalation & Sudo Rights Auditing

Evaluate whether standard user accounts can execute privileged commands without proper authentication or restrictions.

### Testing Procedure:
1. **Check User Identity & Declared Privilege**:
   ```bash
   id; whoami
   ```
   Compare observed groups (`sudo`, `wheel`, `docker`, `lxd`) against `pentest_config.ssh.privilege`.
2. **Audit Sudo Privileges Non-Interactively**:
   ```bash
   sudo -l -n
   ```
3. **Identify High-Risk Sudo Misconfigurations**:
   - **Wildcard NOPASSWD**:
     `(ALL : ALL) NOPASSWD: ALL` or `(root) NOPASSWD: /bin/bash`
   - **GTFOBins Executables with NOPASSWD**:
     Binaries permitting shell breakouts (e.g. `vim`, `find`, `less`, `awk`, `python`, `perl`, `bash`, `env`, `systemctl`) executable without password.
   - **Insecure Environment Inheritance**:
     `env_keep += "LD_PRELOAD"` or `env_keep += "LD_LIBRARY_PATH"` in sudoers.
4. **Finding Classification**:
   - **Title**: Insecure Sudo Configuration Permits Unrestricted Privilege Escalation
   - **Severity**: `critical` (if standard user has NOPASSWD wildcard or GTFOBins shell escape) or `high`
   - **CWE**: `CWE-269` (Improper Privilege Management)
   - **Asset**: `<target_host>:ssh-internal`
   - **Universal Vuln ID**: `sudo-privilege-escalation:<target_host>`

---

## 4. Scheduled Tasks & Process Hygiene

Inspect automated tasks executed under root privileges to identify insecure script execution.

### Testing Procedure:
1. **Audit System Cron Configurations**:
   ```bash
   ls -la /etc/cron* /etc/crontab /var/spool/cron/crontabs/
   cat /etc/crontab 2>/dev/null
   cat /etc/cron.d/* 2>/dev/null
   ```
2. **Check File Permissions of Cron Targets**:
   For any script invoked by cron jobs running as `root`:
   ```bash
   ls -la <path_to_cron_script>
   ```
   If a script executed by root is **world-writable** (`-rwxrwxrwx`) or writable by standard users -> **CRITICAL VULNERABILITY**.
3. **Inspect Systemd Timers**:
   ```bash
   systemctl list-timers --all
   ```
4. **Finding Classification**:
   - **Title**: World-Writable Root Cron Script Permits Privilege Escalation
   - **Severity**: `critical`
   - **CWE**: `CWE-732` (Incorrect Permission Assignment for Critical Resource)
   - **Asset**: `<target_host>:cron`
   - **Universal Vuln ID**: `writable-cron-script:<target_host>`

---

## 5. Filesystem Permissions & Credential Exposure

Inspect sensitive filesystem paths for excessive read or write permissions that leak secrets or allow tampering.

### Testing Procedure:
1. **Sensitive File Read Permissions**:
   - `/etc/shadow`: Check if readable by unprivileged users (`ls -la /etc/shadow`).
   - Private Keys: Search for unencrypted SSH private keys in common directory trees:
     `grep -rnwl "BEGIN OPENSSH PRIVATE KEY" /home/ /var/ /etc/ 2>/dev/null`
   - Application configuration and environment files: Check `.env` files in web roots or service directories readable by standard users:
     `find /var/www /opt /etc -name ".env" -perm -o+r 2>/dev/null`
2. **World-Writable Critical Directories**:
   Check if shared library paths or system PATH directories are world-writable:
   ```bash
   find /usr/bin /usr/local/bin /etc -maxdepth 2 -type d -perm -0002 2>/dev/null
   ```
3. **Finding Classification**:
   - **Title**: Unprotected Sensitive Configuration Leaks Plaintext Credentials
   - **Severity**: `high`
   - **CWE**: `CWE-522` (Insufficiently Protected Credentials)
   - **Asset**: `<target_host>:filesystem`
   - **Universal Vuln ID**: `exposed-plaintext-secrets:<target_host>`

---

## 6. SSH Daemon Hardening Posture (`sshd_config`)

Review the internal configuration of the OpenSSH daemon to verify alignment with security baseline standards.

### Testing Procedure:
1. **Inspect SSH Configuration**:
   ```bash
   cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | grep -E "^(PermitRootLogin|PasswordAuthentication|X11Forwarding|PermitEmptyPasswords|MaxAuthTries)"
   ```
2. **Evaluate Against Hardening Benchmarks**:
   - `PermitRootLogin yes`: Permits direct root logins over SSH. High risk if passwords are used.
   - `PermitEmptyPasswords yes`: Critical risk permitting login with blank passwords.
   - `PasswordAuthentication yes` without rate limiting or MFA on internet-facing servers.
   - `X11Forwarding yes`: Risk of X11 authorization hijacking if untrusted users log in.
3. **Finding Classification**:
   - **Title**: SSH Daemon Configuration Permits Direct Root Login over Network
   - **Severity**: `medium` (or `high` if combined with password authentication on perimeter)
   - **CWE**: `CWE-16` (Configuration)
   - **Asset**: `<target_host>:22`
   - **Universal Vuln ID**: `sshd-insecure-root-login:<target_host>:22`

---

## 7. Container Daemon & Socket Exposure

Inspect local container runtime sockets to verify socket permissions.

### Testing Procedure:
1. **Check Docker Socket Permissions**:
   ```bash
   ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null
   ```
2. **Evaluate Access**:
   - If `/var/run/docker.sock` is world-readable/writable (`srw-rw-rw-`) or accessible by the standard user:
     A local user can interact with the Docker daemon API to spawn a container with `--volume /:/host` and achieve root privileges.
3. **Finding Classification**:
   - **Title**: Exposed Docker Daemon Socket Permits Local Privilege Escalation
   - **Severity**: `critical`
   - **CWE**: `CWE-250` (Execution with Unnecessary Privileges)
   - **Asset**: `<target_host>:/var/run/docker.sock`
   - **Universal Vuln ID**: `docker-socket-privilege-escalation:<target_host>`

---

## 8. Summary of White-Box Internal Host Findings

| Sub-Area | Typical Finding Title | Severity | CWE |
|---|---|---|---|
| **Loopback Listeners** | Unauthenticated Internal Datastore Service Accessible on Local Loopback Interface | `high` | `CWE-306` |
| **Sudo Privileges** | Insecure Sudo Configuration Permits Unrestricted Privilege Escalation | `critical` / `high` | `CWE-269` |
| **Scheduled Tasks** | World-Writable Root Cron Script Permits Privilege Escalation | `critical` | `CWE-732` |
| **Secrets Exposure** | Unprotected Sensitive Configuration Leaks Plaintext Credentials | `high` | `CWE-522` |
| **SSH Daemon** | SSH Daemon Configuration Permits Direct Root Login over Network | `medium` | `CWE-16` |
| **Container Sockets** | Exposed Docker Daemon Socket Permits Local Privilege Escalation | `critical` | `CWE-250` |
