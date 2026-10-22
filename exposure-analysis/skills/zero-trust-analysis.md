# Zero Trust Access & Boundary Gap Analysis Skill

## Objective

Act as a **Zero Trust Architecture & Access Boundary Specialist**. Systematically evaluate external web assets to determine whether Zero Trust Network Access (ZTNA) and Identity-Aware Proxy (IAP) controls are implemented across corporate services, and uncover **critical implementation gaps, unprotected internal domains, and direct origin IP bypasses**.

---

## Methodology

### Step 1: Probe Subdomains for Response HTML & Titles
Iterate over all active subdomains and hosts identified in `checklist.md`:
* Use `scripts/probe_asset.py` or `curl` to fetch the base HTTP/HTTPS responses.
* Record HTTP status codes, redirection locations, response headers, and HTML page titles (`<title>...</title>`).
* Store probed responses in the session directory for fingerprinting and correlation.

### Step 2: Detect Zero Trust / Identity-Aware Proxy Adoption
Analyze headers, redirects, and authentication gateways to establish if the organization employs a Zero Trust architecture:

| Gateway / Solution | Fingerprint & Detection Indicators |
|---|---|
| **Cloudflare Access / Zero Trust** | Redirect to `*.cloudflareaccess.com`, headers: `cf-access-jwt-assertion`, `cf-access-authenticated-user-email`, `cf-ray` |
| **Google Cloud IAP** | Redirect to `accounts.google.com/o/oauth2/v2/auth`, headers: `x-goog-iap-jwt-assertion` |
| **Okta / Enterprise SSO** | Redirects to `*.okta.com`, `login.microsoftonline.com`, `auth0.com`, Ping Identity login |
| **Zscaler / Prisma / Teleport** | ZPA custom challenge headers, Palo Alto GlobalProtect portal titles, Teleport auth redirects |

* **Establish the Security Baseline**: If key corporate assets (e.g. `vpn.*`, `corp.*`, `portal.*`) enforce Zero Trust / IAP, the organization has a defined Zero Trust boundary. Any internal service lacking this control represents a coverage gap.

### Step 3: Identify Coverage Gaps (Unprotected Internal Services)
Identify internal tools, staging environments, and administrative portals that are accessible from the public internet without passing through corporate Zero Trust controls:
1. **Target Sensitive Naming Patterns**:
   * Internal tooling: `jira.*`, `gitlab.*`, `confluence.*`, `jenkins.*`, `grafana.*`, `kibana.*`, `argocd.*`.
   * Administrative & staging: `admin.*`, `corp.*`, `internal.*`, `dev.*`, `staging.*`, `uat.*`, `api-internal.*`.
2. **Evaluate Access Boundary**:
   * Does the service present an unauthenticated dashboard or a direct native login prompt instead of the organization's Zero Trust / SSO gateway?
   * If an internal-only system is reachable by any public client without identity verification at the network edge, flag it as a **Zero Trust Coverage Gap**.

### Step 4: Identify Direct Origin IP Bypasses (Security Gateway Bypass)
Zero Trust proxies (e.g. Cloudflare Access) rely on traffic flowing strictly through their edge. If the underlying origin server is exposed directly to the public internet, attackers can bypass the access boundary entirely:

1. **Identify Suspected Origin IPs**:
   * Query asset profiles via `python3 scripts/query_assets.py session-<session_id>/assets.json --get-asset <subdomain>` to retrieve correlated backend IPs.
   * Check DNS historical records or SSL/TLS certificate subject alternative names (SANs) on exposed IPs.
2. **Test Direct Origin Connection**:
   * Send HTTP/HTTPS requests directly to the candidate origin IP, passing the protected hostname in the `Host:` header and TLS SNI:
     ```bash
     curl -k -v -H "Host: protected-app.corp.example.com" https://<candidate_origin_ip>/
     ```
3. **Compare Responses**:
   * **Protected Path (via Domain)**: Returns 302/403 redirect to Cloudflare Access / Okta SSO login.
   * **Bypassed Path (via Direct IP)**: Returns HTTP 200 / application content or native login screen directly.
4. **Confirm the Boundary Violation**: If the origin server accepts direct internet traffic without enforcing mutual TLS (mTLS) or restricting ingress exclusively to proxy IP ranges, an **Origin Server Gateway Bypass** is confirmed.

### Step 5: Detect Inconsistent Split Routing & Alternate Endpoints
Check for configuration oversights that inadvertently leave backdoors into protected applications:
* **Alternate & Legacy Subdomains**: Check for unmanaged records like `app-backup.*`, `origin-app.*`, `app.dev.*` pointing to the same backend application without Zero Trust proxy rules attached.
* **Path-Level Bypass Rules**: Test if specific path prefixes (e.g., `/api/`, `/healthz`, `/metrics`, `/webhook/`) are configured with proxy bypass rules that unintentionally expose sensitive application logic without authentication.

### Step 6: Non-Findings vs. Real Exposures
Follow the strict validation constraints in `resources/finding_Validation_example.md`:

* **Reject (Non-Findings)**:
  * Public-facing marketing sites or customer portals designed for open access (e.g., `www.example.com`, `careers.example.com`).
  * Direct IP connections that return `403 Forbidden`, `502 Bad Gateway`, connection timeouts, or TLS handshakes that strictly require client certificates (mTLS properly enforced).
  * Speculative bypasses where no actual application response can be retrieved directly from the IP.
* **Report (Confirmed Exposures)**:
  * Direct IP access that successfully serves the protected application, bypassing the Zero Trust / Cloudflare Access gateway.
  * Sensitive internal infrastructure (CI/CD, internal wikis, telemetry dashboards) exposed to the public internet without corporate SSO / Zero Trust authentication.
  * Inconsistent routing or unauthenticated API routes on an otherwise Zero Trust protected asset.

---

## End Goal

Deliver validated findings documenting verifiable breakdowns in the organization's Zero Trust implementation that:
1. Allow public or unauthenticated traffic to reach internal applications.
2. Permit direct IP communication that circumvents edge security gateways and identity enforcement.
3. Violate Zero Trust access boundaries with demonstrable, high-confidence evidence.
