# Technology-Specific Reconnaissance & Vulnerability Analysis Skill

## Objective

Act as a **Technology Stack & Vulnerability Assessment Specialist**. Systematically analyze software technologies, frameworks, CMS platforms, and middleware running across target assets to identify **inherently sensitive software exposed to the public internet, outdated versions with known critical CVEs, and technology-specific misconfigurations**.

---

## Methodology

### Step 1: Query Technologies & Affected Assets
Extract all detected technologies across the target organization:
```bash
python3 scripts/query_assets.py session-<session_id>/assets.json --technologies
```
* Group assets by technology to conduct efficient, stack-specific assessments across the entire inventory.
* Query specific asset profiles for deeper version and header context:
  ```bash
  python3 scripts/query_assets.py session-<session_id>/assets.json --get-asset <subdomain_or_ip>
  ```

---

### Step 2: Identify Inherently Sensitive Software
Certain technologies are designed strictly for internal or backend use. When exposed to the public internet, they represent immediate high-risk exposures regardless of version:

| Technology Category | Sensitive Software Examples | High-Risk Indicators |
|---|---|---|
| **Monitoring & Metrics** | Spring Boot Actuator, Prometheus, Grafana, Kibana | Unauthenticated `/actuator/env`, `/metrics`, or anonymous admin |
| **Data & Caches** | Redis, Elasticsearch, MongoDB, Memcached, CouchDB | Public listeners on 6379, 9200, 27017, 11211 |
| **DevOps & CI/CD** | Jenkins, GitLab, ArgoCD, Airflow, TeamCity, SonarQube | Public pipelines, unprotected webhook or build console |
| **Container & Orchestration** | Kubernetes API, Kubelet, Docker Engine, etcd, Consul | Unauthenticated ports 2375, 2379, 6443, 8500, 10250 |
| **Message Brokers** | RabbitMQ Management, Apache Kafka, ActiveMQ | Management consoles exposed on ports 15672, 8161 |
| **Debug & Development** | Laravel Ignition, Werkzeug, Django Debug Toolbar, PHP info | Exposed interactive debuggers (`APP_DEBUG=true`, `phpinfo.php`) |

---

### Step 3: Precise Software Version Fingerprinting
Avoid guessing or relying on rough heuristics; establish the exact version running on each target:
1. **HTTP Headers**: Inspect `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`.
2. **Framework Metadata & Probing**:
   * Use `scripts/probe_asset.py https://<subdomain>` to probe known version disclosure endpoints:
     - WordPress: `/wp-links-opml.php`, `readme.html`, meta generator tags.
     - Drupal: `/core/CHANGELOG.txt`.
     - Apache Tomcat: `/RELEASE-NOTES.txt`, default 404 error page banners.
     - Spring Boot: `/actuator/info`, `/actuator/health`.
     - Swagger / OpenAPI: `/swagger/v1/swagger.json`, `/api-docs`.

---

### Step 4: Research Public CVEs & Known Misconfigurations
For every identified software version, research documented public vulnerabilities and common misconfigurations:
1. **High-Severity Public CVE Checks**:
   * Pre-auth Remote Code Execution (RCE)
   * Pre-auth Authentication Bypass or Privilege Escalation
   * Arbitrary File Read / Path Traversal
   * Server-Side Request Forgery (SSRF)
2. **Match Version Boundaries**:
   * Ensure the observed version falls squarely within the confirmed vulnerable release range.
   * Account for potential OS vendor backports where applicable.
3. **Verify Configuration Vulnerabilities**:
   * Check if standard security controls are disabled (e.g., exposed API keys in Swagger docs, unauthenticated actuators, default encryption keys).

---

### Step 5: Systematic Multi-Asset Verification
When a sensitive technology, vulnerable version, or misconfiguration pattern is identified on one asset, **systematically verify all other assets in the inventory running the same technology**:

* **Safe Probing Process**:
  * Send non-destructive HTTP requests to verify whether the vulnerable endpoint or sensitive functionality is accessible.
  * *Example (Spring Boot Actuator)*: Test whether `/actuator/env` returns environment variables or `/actuator/heapdump` is downloadable.
  * *Example (Laravel Ignition)*: Test if triggering an error exposes the interactive Ignition debug console.
* **Safety Rule**: Stop testing immediately once reachability and exposure are verified. Never attempt destructive payload execution, remote code execution, or mass data exfiltration.

---

### Step 6: Non-Findings vs. Real Exposures
Follow the strict validation constraints in `resources/finding_Validation_example.md`:

* **Reject (Non-Findings)**:
  * Informational version banners (e.g., "Apache 2.4.41 detected") without proof of an actively vulnerable, unpatched, and reachable component.
  * Speculative CVE claims where the vulnerable feature or endpoint is disabled, unreachable, or behind authentication.
  * Generic browser hygiene or missing security headers.
* **Report (Confirmed Exposures)**:
  * Production services exposing unauthenticated debug interfaces (Laravel Ignition debugger, Werkzeug console, Spring Boot `/actuator/env`).
  * Sensitive internal infrastructure (Elasticsearch, Kibana, Redis, RabbitMQ, Docker daemon) exposed directly to the internet.
  * Exact software version matching a known, high-confidence public CVE with verifiable access to the vulnerable endpoint.

---

## End Goal

Deliver validated, technology-driven findings that:
1. Detail the exact technology, component name, and detected version.
2. Provide direct proof of the exposed endpoint, sensitive configuration, or confirmed CVE condition.
3. List all affected assets across the organization's attack surface.
4. Demonstrate undeniable, real-world security impact.
