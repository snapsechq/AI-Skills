# Reconnaissance Planning & Checklist Specification

Before conducting any active infrastructure security testing, the agent must perform structured reconnaissance. This begins by establishing an isolated session workspace, formulating a reconnaissance plan (`recon_plan.md`), and building a comprehensive reconnaissance checklist (`recon_checklist.md`).

---

## 1. Session Workspace Setup

1. Locate or create the session directory for the current scan:
   ```bash
   mkdir -p ./session-<runId>/
   ```
   All intermediate reconnaissance notes, command logs, scan files, `recon_plan.md`, `recon_checklist.md`, and raw tool outputs must reside in this directory.

---

## 2. Reconnaissance Planning (`recon_plan.md`)

The agent must create `session-<runId>/recon_plan.md` summarizing the reconnaissance strategy based on the context file:

### Key Sections of `recon_plan.md`:
1. **Target Identification**:
   - Target IPs, ranges/CIDRs (`pentest_config.ip`).
   - Hostnames/URLs (`pentest_config.url`).
   - Assessment Type (`pentest_config.target_type`: `black-box`, `gray-box`, or `white-box`).
2. **Reconnaissance Objectives**:
   - Verify host reachability and identify alive systems.
   - Discover open TCP and high-priority UDP ports.
   - Grab service banners and identify application software versions.
   - Identify underlying operating system and perimeter devices (WAF, firewall, load balancer).
   - Perform reverse DNS lookups, ASN / subnet correlation, and subdomain reachability.
3. **Execution Tactics & Safety Limits**:
   - Port scanning scope: Start with top 1000 TCP ports + sensitive infrastructure ports (21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 123, 135, 139, 143, 161, 389, 443, 445, 514, 636, 873, 1080, 1433, 1521, 2049, 2375, 2376, 2379, 3306, 3389, 5000, 5432, 5900, 6379, 6443, 8080, 8443, 8888, 9200, 10250, 11211, 27017).
   - Pacing and rate limits: Use `-T3` or `-T4` in nmap to prevent flooding or triggering aggressive network rate-limits.
   - UDP probing: Focus strictly on critical UDP services (53 DNS, 69 TFTP, 123 NTP, 161 SNMP, 500/4500 IKE VPN).

---

## 3. Reconnaissance Checklist (`recon_checklist.md`)

The agent must create and maintain `session-<runId>/recon_checklist.md` to track 100% coverage across all target hosts and discovery steps.

### Status Indicators:
- `[ ]` Pending
- `[~]` In Progress
- `[x]` Completed
- `[-]` Offline / Unreachable / Not Applicable

### Template for `recon_checklist.md`:

```markdown
# Reconnaissance Checklist
Session ID: <runId>
Target IP / Host: <ip_or_url>
Target Posture: <black-box | gray-box | white-box>

## 1. Target Scope Enumeration
- [ ] Parse target IPs and CIDR blocks
- [ ] Resolve target URL and check DNS records (A, AAAA, CNAME, MX, TXT)
- [ ] Determine ASN, network owner, and reverse DNS (PTR)

## 2. Host Discovery & Pings
- [ ] Target Host: <Target_IP_1>
  - [ ] ICMP Echo / TCP SYN Ping probe
  - [ ] Status: Pending
- [ ] Target Host: <Target_IP_2>
  - [ ] ICMP Echo / TCP SYN Ping probe
  - [ ] Status: Pending

## 3. Port & Service Discovery
- [ ] Target Host: <Target_IP_1>
  - [ ] Top 1000 TCP Port Scan
  - [ ] Sensitive Infrastructure Port Probes (Databases, Management, Cloud daemons)
  - [ ] Critical UDP Port Probes (53 DNS, 69 TFTP, 123 NTP, 161 SNMP)
  - [ ] Service Banner Grabbing & Protocol Handshake
  - [ ] OS & Perimeter Detection (Firewall / WAF / Reverse Proxy)

## 4. Knowledge Consolidation
- [ ] Compile all open ports, services, banners, and versions into `recon_knowledge.json`
- [ ] Verify all hosts are categorized as either Live (`[x]`) or Inactive (`[-]`)
```

---

## 4. Consolidating Reconnaissance Knowledge (`recon_knowledge.json`)

Once reconnaissance tasks are complete, the agent must compile the discovered intelligence into `session-<runId>/recon_knowledge.json`. This structured document serves as the foundation for the Infrastructure Security Testing Phase.

### Schema of `recon_knowledge.json`:

```json
{
  "scan_metadata": {
    "target_ip": "198.51.100.20",
    "target_url": "https://vpn.example.com",
    "alive_hosts_count": 1
  },
  "hosts": [
    {
      "ip": "198.51.100.20",
      "hostname": "vpn.example.com",
      "status": "up",
      "os": "Linux 5.x",
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "service": "ssh",
          "product": "OpenSSH",
          "version": "7.4p1",
          "banner": "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb10u2"
        },
        {
          "port": 443,
          "protocol": "tcp",
          "service": "https",
          "product": "nginx",
          "version": "1.18.0",
          "banner": "nginx/1.18.0"
        },
        {
          "port": 6379,
          "protocol": "tcp",
          "service": "redis",
          "product": "Redis key-value store",
          "version": "6.0.9",
          "banner": "Redis 6.0.9"
        },
        {
          "port": 161,
          "protocol": "udp",
          "service": "snmp",
          "product": "Net-SNMP",
          "version": "5.7.3",
          "banner": "Linux vpn 5.10.0 #1 SMP"
        }
      ]
    }
  ]
}
```
