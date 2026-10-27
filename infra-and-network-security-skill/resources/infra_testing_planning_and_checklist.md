# Infrastructure Security Testing: Planning & Checklist Specification

Once reconnaissance is finalized and `recon_knowledge.json` is compiled, the agent transitions to **Infrastructure Security Testing**. In this phase, the agent must formulate an Infrastructure Test Plan (`infra_test_plan.md`), generate an actionable Testing Checklist (`infra_test_checklist.md`), and systematically audit every discovered listener, network service, and—when white-box testing is selected with SSH credentials—internal host security controls.

---

## 1. Transitioning from Reconnaissance to Testing

1. Ingest `session-<runId>/recon_knowledge.json`.
2. Extract all live hosts, open ports, identified protocols, software products, version strings, and internal host posture.
3. Classify discovered listeners and attack surfaces into security testing categories:
   - **Category A: Remote Access & Administration** (SSH, Telnet, RDP, VNC, IPMI, appliance web UIs)
   - **Category B: Exposed Databases & Datastores** (Redis, MongoDB, Elasticsearch, Memcached, MySQL, Postgres, MSSQL)
   - **Category C: Cloud & Container Daemons** (Docker API 2375, Kubelet 10250, Kubernetes API 6443, etcd 2379)
   - **Category D: Core Network Infrastructure & Directory Services** (DNS, SNMP, SMB, NFS, RPC, LDAP)
   - **Category E: Transport Layer & Cryptographic Posture** (TLS/SSL protocols, ciphers, certificates)
   - **Category F: Software Version & Known CVE Auditing** (Vulnerable daemons with verified preconditions)
   - **Category G: White-Box Internal Host Security (SSH)** (Local loopback listeners on 127.0.0.1, sudo/privilege boundaries, cron jobs, secrets exposure, sshd hardening)

---

## 2. Infrastructure Test Plan (`infra_test_plan.md`)

The agent must create `session-<runId>/infra_test_plan.md` defining the targeted testing campaign:

### Required Sections of `infra_test_plan.md`:
1. **Target Surface Summary**: Total live hosts, count of open ports, and classification of critical vs. non-critical listeners (plus internal host credentials status).
2. **High-Risk Hypotheses**:
   - Hypotheses based on exposed ports and internal posture:
     - "Port 6379 may allow unauthenticated Redis commands; Port 161 may respond to default SNMP community string 'public'."
     - "White-box internal inspection may reveal unauthenticated local listeners on 127.0.0.1, misconfigured sudo permissions, or world-writable cron scripts."
3. **Execution Sequencing**:
   - Priority 1: Unauthenticated external & internal loopback databases (Redis, MongoDB, Elasticsearch, Memcached).
   - Priority 2: Insecure legacy protocols and credential exposure (Telnet, FTP, SMB, SNMP).
   - Priority 3: White-box privilege escalation checks (`sudo -l`, SUID, root cron scripts) and Docker socket permissions.
   - Priority 4: Container and orchestration daemon APIs (Docker 2375, Kubelet 10250).
   - Priority 5: TLS/SSL cryptographic configuration across web and encrypted ports.
   - Priority 6: SSH daemon configuration hardening (`sshd_config`) and known CVE verification.
4. **Safety & Non-Destructive Testing Boundaries**:
   - Prohibit Denial-of-Service attacks, brute-force floods, buffer overflow crashing, and persistent file modification.
   - Follow the principle of **minimal validation**: prove that the security boundary is crossed, verify access or capability, and immediately stop.

---

## 3. Infrastructure Testing Checklist (`infra_test_checklist.md`)

The checklist enforces **100% test coverage** for all discovered ports across all live hosts, plus internal host enumeration if white-box SSH access is provided.

### Checklist Template:

```markdown
# Infrastructure Security Testing Checklist
Session ID: <runId>
Target Posture: <black-box | gray-box | white-box>
Total Live Hosts: <count>
Total Discovered Ports: <port_count>

## Host: 198.51.100.20 (vpn.example.com)

### Port 22/tcp (OpenSSH 7.4p1)
- [ ] Check supported authentication methods (password vs publickey)
- [ ] Audit SSH cryptographic ciphers (weak CBC, diffie-hellman-group1-sha1)
- [ ] Check for high-severity known CVEs (CVE-2023-38408, CVE-2024-6387) and verify preconditions
- [ ] Status: Pending

### White-Box Internal Host Enumeration (SSH Access: audituser@198.51.100.20:22)
*Guide: `skills/internal-host-enumeration.md`*
- [ ] Audit local loopback listeners (`ss -tulpn` for 127.0.0.1 ports: Redis, MongoDB, internal APIs)
- [ ] Probe localhost services for missing authentication (e.g. `redis-cli -p 6379 ping`, local HTTP APIs)
- [ ] Check sudo privilege escalation vectors (`sudo -l -n` for NOPASSWD or GTFOBins binaries)
- [ ] Audit scheduled cron scripts and root-executed timers for world-writable permissions
- [ ] Inspect sensitive files for excessive permissions (`/etc/shadow`, world-readable `.env` or keys)
- [ ] Inspect SSH daemon configuration (`/etc/ssh/sshd_config` for PermitRootLogin, weak ciphers)
- [ ] Check Docker socket permissions (`/var/run/docker.sock`)
- [ ] Status: Pending

### Port 161/udp (Net-SNMP 5.7.3)
- [ ] Test default SNMPv1/v2c community string `public`
- [ ] Test default SNMP community string `private`
- [ ] Check for system MIB information leakage (sysDescr, network interfaces, route table)
- [ ] Status: Pending

### Port 443/tcp (HTTPS / Nginx 1.18.0)
- [ ] Inspect SSL/TLS protocols (check support for SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- [ ] Check for weak ciphers (RC4, 3DES, EXPORT, NULL)
- [ ] Validate SSL certificate (expiration, CN/SAN domain match, self-signed status)
- [ ] Probe administrative endpoints and exposed reverse proxy paths
- [ ] Status: Pending

### Port 6379/tcp (Redis 6.0.9)
- [ ] Test unauthenticated TCP connection and execute `INFO` command
- [ ] Check if `requirepass` is enforced or missing
- [ ] Test read access to keyspace summary
- [ ] Status: Pending
```

---

## 4. Execution Workflow & Checklist Updates

For each item in `infra_test_checklist.md`:
1. Mark the item as `[~]` (In Progress).
2. Execute the corresponding testing procedure from the sub-skill guides in `skills/`:
   - For perimeter ports: `skills/network-service-audit.md`, `skills/database-and-datastore-exposure.md`, `skills/cloud-and-container-infrastructure.md`, etc.
   - For internal host checks: `skills/internal-host-enumeration.md`.
3. If an exposure is confirmed:
   - Collect raw evidence (banners, response output, command transcripts).
   - Formulate reproduction steps, severity, CWE, CVE, and impact.
   - Record finding in intermediate candidate list.
   - Mark checklist item as `[x]` (Assessed - Vulnerability Found).
4. If testing reveals the service or configuration is properly secured:
   - Mark checklist item as `[x]` (Assessed - Clean / Secure).
5. If the port became unreachable or filtered during test:
   - Mark checklist item as `[-]` (Filtered / Offline).

---

## 5. Transition to Results

Once all checklist items are evaluated and marked as `[x]` or `[-]`:
- Run `python3 scripts/validate_results.py` against candidate findings.
- Emit final output to `results.json` adhering strictly to `{ "results": [ ... ] }`.
