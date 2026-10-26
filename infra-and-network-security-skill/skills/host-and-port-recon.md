# Host & Port Reconnaissance Guide

## Objective
Act as a **Network Reconnaissance Specialist**. Systematically identify live network hosts, open TCP and critical UDP ports, service banners, and perimeter topology for all targets defined in the pentest context.

---

## 1. Scope Parsing & Target Extraction

1. Read the input context file using `python3 scripts/parse_context.py <context_file>`.
2. Extract target IP addresses, CIDR blocks, and hostnames:
   - Single IP (e.g. `198.51.100.20`)
   - IP Range or Subnet (e.g. `198.51.100.0/24`)
   - Target URL / Domain (e.g. `https://vpn.example.com`)
3. For target hostnames:
   - Perform DNS resolution (`A`, `AAAA`, `CNAME`, `MX`, `TXT`).
   - Identify whether the IP belongs to a CDN/WAF (Cloudflare, CloudFront, Akamai) or points directly to customer-owned IP space.
   - Query Reverse DNS (PTR) for discovered IP addresses.

---

## 2. Host Discovery & Alive Probing

For single IPs or IP subnets:
* Run fast host discovery to identify alive systems without port scanning all 65,535 ports:
  ```bash
  # ICMP Echo + TCP SYN probe on common ports (80, 443, 22, 445)
  nmap -sn -PE -PS22,80,443,445 <target_ip_or_cidr> -oG session-<runId>/alive_hosts.txt
  ```
* For targets that drop ICMP (common on cloud hosting like AWS/GCP):
  - Treat target IP as alive if explicitly provided in `pentest_config.ip`.

---

## 3. TCP Port Scanning Methodology

Execute structured, rate-controlled port discovery:

1. **Top TCP Ports & Infrastructure Listeners**:
   - Scan top 1000 ports plus critical infrastructure listeners:
     ```bash
     nmap -sS -Pn -T4 --open -p 21,22,23,25,53,80,88,110,111,123,135,139,143,161,389,443,445,514,636,873,1080,1433,1521,2049,2375,2376,2379,3306,3389,5000,5432,5900,6379,6443,8080,8443,8888,9200,10250,11211,27017 <target_ip> -oN session-<runId>/nmap_tcp_<target>.txt
     ```
2. **Service Version & Banner Grabbing**:
   - For all identified open ports, execute banner grabbing and version detection:
     ```bash
     nmap -sV --version-intensity 5 -Pn -p <open_ports> <target_ip> -oN session-<runId>/nmap_versions_<target>.txt
     ```
   - Execute Nmap service probe and parse directly to JSON:
     ```bash
     python3 scripts/service_prober.py nmap-probe <target_ip> -p <open_ports> --to-recon-format -o session-<runId>/recon_knowledge.json
     ```

---

## 4. Critical UDP Port Probing

UDP scanning is slower and prone to packet drops. **Do NOT run full UDP scans**. Target only critical UDP infrastructure services:
- **Port 53 (DNS)**: Test DNS queries.
- **Port 69 (TFTP)**: Probe unauthenticated file transfers.
- **Port 123 (NTP)**: Check `ntpd` version and monlist.
- **Port 161 (SNMP)**: Check SNMP community strings.
- **Port 500 / 4500 (IKE VPN)**: Identify IPsec VPN responders.

```bash
nmap -sU -sV -Pn -p 53,69,123,161,500 <target_ip> -oN session-<runId>/nmap_udp_<target>.txt
```

---

## 5. Knowledge Synthesis into `recon_knowledge.json`

Compile all results into `session-<runId>/recon_knowledge.json`:
- Each alive host must list all verified open ports, transport protocol, service name, product, version, and raw banner string.
- Update `session-<runId>/recon_checklist.md`: mark completed items with `[x]` and offline/filtered ports with `[-]`.
