# Attack Surface Management (ASM) Exposure Analysis Methodology

For every relevant potential issue, follow this 6-step validation process:

### Step 1: Establish the Signal
Identify the observable condition suggesting a security issue:
- An administrative interface responds from the public internet.
- A database or cache listener is reachable externally.
- A protected hostname is behind a WAF, but its suspected origin IP also responds directly.
- A service exposes sensitive information or endpoints without authentication.
- A DNS record points to a potentially unclaimed third-party resource.
*Record the exact asset, observation, source, and response details.*

### Step 2: Determine What Is Actually Exposed
Perform the minimum authorized checks necessary to understand the exposure:
- Whether the asset is live.
- Which service or functionality is accessible.
- Whether authentication is required.
- Whether the observed response contains sensitive information.
- Whether the access restriction is missing or ineffective.
- Whether the exposure is consistent with the asset's apparent role.
*Always distinguish between a service merely being reachable and a security weakness being confirmed.*

### Step 3: Investigate Relevant Security Controls
Assess whether expected controls are present:
- Check whether a public service enforces authentication or authorization.
- Compare the public application endpoint with a suspected origin endpoint.
- Inspect whether an administrative interface exposes privileged functionality.
- Examine TLS protocol and certificate configuration.
- Check whether sensitive API endpoints enforce authorization.
- For issues requiring internal evidence, identify the precise evidence needed (firewall rules, security group configs, mTLS policies, IdP policies, architecture diagrams).

### Step 4: Dig Deeper When Evidence Warrants It
If an observation reveals an interesting or high-impact exposure, investigate its immediate security implications safely:
- **Grafana/Kibana**: Inspect accessible login and configuration interfaces, anonymous access, and public dashboards.
- **Database/Cache**: Determine whether the listener is externally reachable and whether authentication is enforced without dumping data.
- **Origin / WAF Bypass**: Compare responses between CDN/WAF and direct IP to confirm if the origin provides an alternate unprotected access path.
- **API**: Inspect documented endpoints (`/v2/api-docs`, `/openapi.json`) and test access controls using authorized test identities.
- **Kubernetes/Docker**: Identify the exposed management API without attempting unauthorized administrative operations.
- **Exposed Secret**: Establish whether it is a genuine credential, verify non-destructively, and redact in reports.

### Step 5: Establish Impact and Attack Path
Explain what an attacker could realistically achieve if the exposure is confirmed. Connect the observed weakness to a plausible security consequence:

$$\text{Attacker Entry Point} \rightarrow \text{Missing Control / Weakness} \rightarrow \text{Direct Exposure} \rightarrow \text{Demonstrated Impact}$$

* **Confirmed vs Inferred**: Clearly distinguish verified steps from hypothetical downstream outcomes.
* **Prohibited Claims**: Do not claim access to data, privilege escalation, lateral movement, or system compromise unless direct evidence supports it.

### Step 6: Assign Validation Status
Classify the outcome as one of:
* **Confirmed Exposure**: Evidence demonstrates the stated security weakness and violated boundary.
* **Potential Exposure**: Evidence indicates a credible risk, but a necessary condition remains unverified.
* **Informational Observation**: A relevant asset or configuration has been observed, but no security weakness has been established.
* **Not Observed**: The defined check did not identify the issue under tested conditions.
* **Requires Internal Validation**: Confirmation requires internal visibility, configuration evidence, or authorized access not currently available.

---

## 4. Signal-Driven Validation Methodology (Phase 2)

Following autonomous scanning (Phase 1), the agent processes organization-specific detection signals and threat rules dumped from the database (`signals.json`). These signals define organizational risk criteria, exposed technology patterns, and compliance rules.

### Signal Validation Workflow:
1. **Match Signals against Inventory**:
   Run `python3 scripts/query_assets.py session-<session_id>/assets.json --signals-file session-<session_id>/signals.json --match-signals` to identify which assets satisfy the rule's criteria.
2. **Inspect Signal Definition**:
   Review the rule's `name`, `category`, `description`, `impact`, and `match` filter. Understand the exact exposure condition the rule warns against.
3. **Formulate Active Test**:
   Formulate a focused hypothesis: *Does the matched asset actively exhibit this exposure condition in a live, reachable, and exploitable manner?*
4. **Validate Safely**:
   - For exposed datastores/services: Verify service banner and unauthenticated access non-destructively without extracting data.
   - For administrative interfaces: Verify login page accessibility, missing MFA or default credentials.
   - For debugging/info endpoints: Test endpoint responsiveness and check for sensitive leakage.
5. **Evaluate Real-World Impact**:
   - A matched signal is only an **exposure** if active validation confirms a security boundary breach or actionable risk.
   - If the service is properly secured, behind SSO, unreachable, or returns a 401/403 with no sensitive data disclosure, do not raise an exposure.
6. **Register Validated Exposure**:
   When confirmed:
   - Check against Phase 1 findings and `existing_exposures.json` to prevent duplicates.
   - Construct the exposure object incorporating the signal's context, affected host/port, concrete evidence, impact, and remediation.

---

## 5. Finding Deduplication and Correlation

Correlate related observations before creating findings:
* **Root-Cause Grouping**: Group duplicate observations relating to the same underlying weakness. Link multiple affected assets to a common root cause.
* **Direct Origin vs WAF Bypass**: A directly reachable origin server and a potential WAF bypass describe the same underlying exposure—correlate them.
* **Distinct Asset References**: Preserve individual asset references and affected endpoints while explaining the shared root cause.
* **Multi-Port / Multi-Hostname**: Avoid creating separate findings for the same exposed service solely because it has multiple ports or hostnames.
* **Existing Exposures**: Check `existing_exposures` in the dataset to prevent duplicating known issues.

---

## 6. Severity Assessment

Assess severity based on actual exposure, accessibility, authentication requirements, and demonstrated impact:

| Severity | Criteria |
|---|---|
| **Critical** | Direct compromise of critical systems, identity infrastructure, sensitive financial operations, major data access, or remote code execution. |
| **High** | Significant unauthorized access, account takeover, administrative compromise, meaningful privilege escalation, or full gateway bypass. |
| **Medium** | Limited unauthorized access, data exposure, security boundary bypass with moderate impact. |
| **Low** | Genuine real-world security impact, but impact is strictly limited. |
| **Informational** | Observed configuration context without actionable vulnerability or direct risk. |

> Do not assign High or Critical severity merely because a service is publicly accessible, an IP address is discoverable, or a Zero Trust control cannot be verified externally.

---

## 7. Remediation Guidance Principles

Provide actionable, specific recommendations tailored to the detected weakness:
* Restrict administrative and infrastructure interfaces to approved management networks or VPNs.
* Remove unnecessary public exposure of databases, caches, message brokers, and orchestration services.
* Enforce authentication and least-privilege authorization on sensitive services and APIs.
* Restrict direct backend access to intended gateways and approved callers.
* Implement network segmentation and explicit allowlists for service-to-service communication.
* Enforce mutual TLS (mTLS) where required by the security architecture.
* Remove or secure unnecessary development, staging, and diagnostic endpoints.
* Correct dangling DNS records and verify third-party resource ownership.
* Rotate exposed secrets and remove them from public repositories and client-side code.
* Harden TLS configurations and eliminate unnecessary information disclosure.
