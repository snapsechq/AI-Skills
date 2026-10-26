# Infrastructure Security Testing: Planning & Checklist Specification

Once reconnaissance is finalized and `recon_knowledge.json` is compiled, the agent transitions to **Infrastructure Security Testing**. In this phase, the agent must formulate an Infrastructure Test Plan (`infra_test_plan.md`), generate an actionable Testing Checklist (`infra_test_checklist.md`), and systematically audit every discovered listener and service.

---

## 1. Transitioning from Reconnaissance to Testing

1. Ingest `session-<runId>/recon_knowledge.json`.
2. Extract all live hosts, open ports, identified protocols, software products, and version strings.
3. Classify discovered listeners into security testing categories:
   - **Category A: Remote Access & Administration** (SSH, Telnet, RDP, VNC, IPMI, appliance web UIs)
   - **Category B: Exposed Databases & Datastores** (Redis, MongoDB, Elasticsearch, Memcached, MySQL, Postgres, MSSQL)
   - **Category C: Cloud & Container Daemons** (Docker API 2375, Kubelet 10250, Kubernetes API 6443, etcd 2379)
   - **Category D: Core Network Infrastructure & Directory Services** (DNS, SNMP, SMB, NFS, RPC, LDAP)
   - **Category E: Transport Layer & Cryptographic Posture** (TLS/SSL protocols, ciphers, certificates)
   - **Category F: Software Version & Known CVE Auditing** (Vulnerable daemons with verified preconditions)

---

## 2. Infrastructure Test Plan (`infra_test_plan.md`)

The agent must create `session-<runId>/infra_test_plan.md` defining the targeted testing campaign:

### Required Sections of `infra_test_plan.md`:
1. **Target Surface Summary**: Total live hosts, count of open ports, and classification of critical vs. non-critical listeners.
2. **High-Risk Hypotheses**:
   - Hypotheses based on exposed ports (e.g. "Port 6379 may allow unauthenticated Redis commands; Port 161 may respond to default SNMP community string 'public'; Port 10250 may permit anonymous pod listing").
3. **Execution Sequencing**:
   - Priority 1: Unauthenticated databases and management ports (highest potential for critical impact).
   - Priority 2: Insecure legacy protocols and credential exposure (Telnet, FTP, SMB, SNMP).
   - Priority 3: Container and orchestration daemon APIs.
   - Priority 4: TLS/SSL cryptographic configuration across web and encrypted ports.
   - Priority 5: Known CVE verification for matched daemon versions.
4. **Safety & Non-Destructive Testing Boundaries**:
   - Prohibit Denial-of-Service attacks, brute-force floods, buffer overflow crashing, and persistent file modification.
   - Follow the principle of **minimal validation**: prove that the security boundary is crossed, verify access or capability, and immediately stop.

---

## 3. Infrastructure Testing Checklist (`infra_test_checklist.md`)

The checklist enforces **100% test coverage** for all discovered ports across all live hosts. Every port must be systematically audited against its applicable sub-skills.

### Checklist Template:

```markdown
# Infrastructure Security Testing Checklist
Session ID: <runId>
Total Live Hosts: <count>
Total Discovered Ports: <port_count>

## Host: 198.51.100.20 (vpn.example.com)

### Port 22/tcp (OpenSSH 7.4p1)
- [ ] Check supported authentication methods (password vs publickey)
- [ ] Audit SSH cryptographic ciphers (weak CBC, diffie-hellman-group1-sha1)
- [ ] Check for high-severity known CVEs (CVE-2023-38408, CVE-2024-6387) and verify preconditions
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
2. Execute the corresponding testing procedure from the sub-skill guides in `skills/`.
3. If an exposure is confirmed:
   - Collect raw evidence (banners, response output, command transcripts).
   - Formulate reproduction steps, severity, CWE, CVE, and impact.
   - Record finding in intermediate candidate list.
   - Mark checklist item as `[x]` (Assessed - Vulnerability Found).
4. If testing reveals the service is properly secured (e.g. authentication strictly enforced, TLS 1.3 enforced, strong credentials):
   - Mark checklist item as `[x]` (Assessed - Clean / Secure).
5. If the port became unreachable or filtered during test:
   - Mark checklist item as `[-]` (Filtered / Offline).

---

## 5. Transition to Results

Once all checklist items are evaluated and marked as `[x]` or `[-]`:
- Run `python3 scripts/validate_results.py` against candidate findings.
- Emit the final output to `results.json` adhering strictly to `{ "results": [ ... ] }`.
