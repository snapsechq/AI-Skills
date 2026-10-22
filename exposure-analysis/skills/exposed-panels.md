# Exposed Administrative Panels & Management Interfaces Skill

## Objective

Act as an **Administrative Panel & Interface Specialist**. Systematically discover, probe, and validate publicly accessible administrative panels, orchestration dashboards, DevOps pipelines, database managers, and sensitive internal management portals.

---

## Methodology

### Step 1: Subdomain Extraction & Role Heuristics
Extract all in-scope subdomains and hostnames from `checklist.md` / `assets.json`:
```bash
python3 scripts/query_assets.py session-<session_id>/assets.json --list-subdomains
```
Identify target hostnames whose names indicate administrative, infrastructure, or internal management roles:

| Category | High-Risk Subdomain Keywords |
|---|---|
| **Generic Admin** | `admin.*`, `panel.*`, `dashboard.*`, `manage.*`, `console.*`, `portal.*`, `control.*` |
| **DevOps & CI/CD** | `jenkins.*`, `gitlab.*`, `git.*`, `argocd.*`, `airflow.*`, `teamcity.*`, `bamboo.*`, `nexus.*` |
| **Monitoring & Telemetry** | `grafana.*`, `kibana.*`, `prometheus.*`, `jaeger.*`, `zabbix.*`, `nagios.*`, `datadog.*` |
| **Containers & Orchestration**| `k8s.*`, `kube.*`, `portainer.*`, `rancher.*`, `nomad.*`, `consul.*`, `swarm.*` |
| **Databases & Messaging** | `phpmyadmin.*`, `pma.*`, `pgadmin.*`, `rabbitmq.*`, `activemq.*`, `kafka.*`, `redis.*` |
| **Hosting & Hypervisors** | `cpanel.*`, `whm.*`, `plesk.*`, `webmin.*`, `proxmox.*`, `esxi.*`, `vcenter.*` |
| **Pre-Production Environments**| `stage-admin.*`, `dev-panel.*`, `qa-portal.*`, `internal-tools.*` |

### Step 2: Port & Protocol Correlation
Administrative interfaces frequently run on non-standard ports. Query correlated ports for each target:
```bash
python3 scripts/query_assets.py session-<session_id>/assets.json --get-asset <subdomain>
```
* **Common Admin Ports**:
  * Monitoring / Metrics: `3000` (Grafana), `5601` (Kibana), `9090` (Prometheus)
  * Containers & DevOps: `8080`, `8443`, `8888`, `9000` (Portainer), `8006` (Proxmox)
  * Message Brokers: `15672` (RabbitMQ Management), `8161` (ActiveMQ)
  * Web Hosting: `2083` / `2087` (cPanel / WHM), `8443` (Plesk), `10000` (Webmin)
* Test both **HTTPS** and **HTTP** schemes across all open web listener ports.

### Step 3: Targeted Admin Path Probing
Even on standard hostnames, probe for hidden or unlinked administrative endpoints using `scripts/probe_asset.py`:
```bash
python3 scripts/probe_asset.py https://<subdomain>
```
Check targeted paths based on detected technologies:
* **Framework & CMS Admin**: `/admin`, `/admin/login`, `/administrator`, `/wp-admin`, `/wp-login.php`, `/user/login` (Drupal), `/strapi/admin`, `/ghost`
* **Application Management**: `/dashboard`, `/console`, `/manager/html` (Apache Tomcat), `/management`
* **Database Web Managers**: `/phpmyadmin/`, `/pma/`, `/pgadmin4/`, `/adminer.php`
* **API Documentation & Introspection**: `/swagger-ui.html`, `/swagger/index.html`, `/v2/api-docs`, `/openapi.json`, `/actuator`, `/actuator/env`

### Step 4: Access Boundary & Authentication Evaluation
For every discovered panel, evaluate the security boundary:
1. **Check for Unauthenticated Access (Critical)**:
   * Does the dashboard load directly without requesting authentication?
   * *Examples*: Unauthenticated Kubernetes Dashboard, Grafana with anonymous admin role enabled, open Prometheus query console, or unprotected Spring Boot Actuator endpoints.
2. **Check for Default / Weak Credentials (High / Critical)**:
   * If a login form is present, run a non-destructive credential check with `scripts/test_admin_auth.py` using `resources/top_credentials.json`:
     ```bash
     python3 scripts/test_admin_auth.py https://<subdomain>/admin/login
     ```
   * *Rule*: Stop testing immediately once a valid login is proven. Never modify settings or production state.
3. **Verify Zero Trust / Network Isolation (High / Medium)**:
   * Determine if an internal infrastructure tool (Jenkins, ArgoCD, RabbitMQ) is exposed directly to the public internet rather than restricted behind corporate SSO (Okta, Google IAP) or a VPN.

### Step 5: Non-Findings vs. Real Exposures
Follow the strict validation constraints in `resources/finding_Validation_example.md`:

* **Reject (Non-Findings)**:
  * Public consumer/customer authentication portals (e.g., customer sign-in on `shop.example.com/login` or `app.example.com/login`).
  * Admin panels properly protected behind MFA or corporate Zero Trust (Cloudflare Access, Okta, Azure AD).
  * Standard 401 Unauthorized / 403 Forbidden responses with no information leakage or functional bypass.
* **Report (Confirmed Exposures)**:
  * Any administrative or orchestration panel accessible with **no authentication**.
  * Administrative portals functional with **default or factory credentials** (`admin:admin`, `guest:guest`).
  * Privileged infrastructure panels (cPanel, Proxmox, Webmin, Kubernetes, RabbitMQ) exposed publicly without IP whitelisting or corporate identity proxies.

---

## End Goal

Deliver confirmed findings for exposed administrative interfaces that:
1. Allow unauthenticated or weakly authenticated administrative control over systems.
2. Expose internal business logic, telemetry, or deployment pipelines to the public internet.
3. Violate access control boundaries with clear, reproducible evidence.
