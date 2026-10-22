# Port & Service Exposure Analysis Skill

## Objective

Act as a **Network & Port Exposure Specialist**. Systematically analyze network ports and service listeners on in-scope assets to detect **unintended public exposures, unauthenticated backend services, outdated software with high-severity known CVEs, and insecure administrative interfaces**.

---

## Methodology

### Step 1: Query Correlated Asset Ports
For each in-scope subdomain or IP in `checklist.md`:
* Extract known open ports and services from the inventory dataset:
  ```bash
  python3 scripts/query_assets.py session-<session_id>/assets.json --get-asset <subdomain_or_ip>
  ```
* Identify exposed port numbers, transport protocols (TCP/UDP), service banners, and software versions already recorded.

### Step 2: Targeted Fast Verification (When Context Warrants)
If the asset name, tech stack, or operational role suggests sensitive services (e.g., `db.*`, `vpn.*`, `redis.*`, `k8s.*`, `staging.*`), conduct **lightweight, fast port probes** only on high-value ports.

* **Strict Rule**: Avoid broad or slow 65,535-port scans. Keep scans fast, targeted, and focused on sensitive ports.
* **Targeted Fast Probe Command**:
  ```bash
  # Fast scan restricted to sensitive service ports with banner grabbing
  nmap -sV -Pn --version-light -T4 --open -p <target revelant ports> <target_ip> -oN session-<session_id>/ports_<target>.txt
  ```

### Step 3: Classify Service Sensitivity & Boundary Violations
Differentiate standard public listeners from sensitive internal services exposed unintentionally:

| Risk Tier | Service Types & Sensitive Ports | Exposure Condition |
|---|---|---|
| **Critical / High** | Databases & Caches (3306, 5432, 6379, 27017, 9200, 11211) | Direct external listener reachable over public IP |
| **Critical / High** | Orchestration & Containers (2375 Docker, 6443 / 10250 K8s, 2379 etcd) | Exposed daemon API without mutual TLS or authentication |
| **High** | Remote Access & Management (23 Telnet, 445 SMB, 3389 RDP, 5900 VNC) | Exposed to the internet without VPN or zero-trust gateway |
| **Medium / High** | Legacy Protocols (21 FTP plaintext, unencrypted management interfaces) | Plaintext transmission of credentials across public network |
| **Standard** | Web Services (80 HTTP, 443 HTTPS, standard CDNs) | Expected public service unless exposing admin UI or dev endpoints |

### Step 4: Non-Destructive Deep Investigation
When a sensitive service listener is detected:
1. **Verify Live Reachability**: Check if the port actively accepts connections or if traffic is filtered.
2. **Assess Authentication Enforcement**:
   * **Databases / Caches**: Test if the listener allows unauthenticated handshake (e.g., Redis `PING` / `INFO`, Elasticsearch `/_cat/indices`, MongoDB unauthenticated connection).
   * **Management Interfaces**: Test if standard authentication prompts or SSO boundaries are missing.
   * **Web & Administrative Portals**: Use `scripts/probe_asset.py` to identify unauthenticated administrative consoles.
3. **Boundary Verification**: Verify whether the asset represents an unintended exposure bypassing network segmentation (e.g., origin server exposed directly while the hostname sits behind a CDN/WAF).

### Step 5: Version Fingerprinting & Known CVE Correlation
Identify exact software versions running on open ports and evaluate whether known public CVEs apply:
1. **Extract Exact Version**: Read full banners from HTTP headers (`Server`, `X-Powered-By`), SSH banners, or service strings.
2. **Cross-Reference Public CVEs**:
   * Check for high-confidence CVEs with public functional impact (e.g., remote unauthenticated command execution, authentication bypass).
   * Confirm version matches the vulnerable range without speculative guesswork.
   * Only report CVEs where the vulnerable component is actively exposed and reachable on that port.

### Step 6: Non-Findings vs. Real Exposures
Follow the strict validation constraints in `resources/finding_Validation_example.md`:

* **Reject (Non-Findings)**:
  * An open port alone (e.g., "Port 8080 is open") without an identified insecure service, unauthenticated portal, or vulnerable component.
  * Properly authenticated services (e.g., SSH port 22 enforcing key/password auth or database listeners enforcing TLS + strong credentials).
  * Informational version banners on standard web services without confirmed exploitable CVEs.
* **Report (Confirmed Exposures)**:
  * Unauthenticated database, cache, or message queue reachable from the public internet.
  * Direct access to backend origin IP that bypasses edge WAF / CDN access controls.
  * Exposed administrative or remote management service (Telnet, unauthenticated RDP/VNC, open Docker daemon).

---

## End Goal

Deliver verified, actionable findings for network-level exposures that:
1. Expose private internal data or infrastructure components without authentication.
2. Allow unauthorized external access or bypass organizational network boundaries.
3. Violate Zero Trust principles with demonstrable, evidence-backed security impact.
