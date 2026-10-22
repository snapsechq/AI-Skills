# VALID & INVALID ISSUE EXAMPLE


## INVALID ISSUES/EXPOSURES EXAMPLES

This document demonstrates examples of findings that **MUST BE REJECTED** and never reported in the final output unless independently demonstrated to have high-confidence, real-world security impact.

---

### 1. Missing Security Headers
* **Rejected:** "Missing HTTP Strict-Transport-Security (HSTS) header on https://example.com"
* **Reason:** Missing HSTS is a hygiene observation. Unless a realistic downgrade attack can be actively triggered on sensitive communication, it does not represent an actionable exposure.
* **Rejected:** "Missing X-Content-Type-Options or Referrer-Policy"
* **Reason:** General browser hardening baseline, no demonstrable attacker consequence by itself.

---

### 2. Non-Sensitive Cookie Flags
* **Rejected:** "Cookie `locale=en_US` is missing `Secure` or `HttpOnly` flag"
* **Reason:** Preference or UI state cookies do not control session identity or authorization. Missing flags on non-sensitive cookies pose no demonstrable threat.

---

### 3. Open Port Without Vulnerable Service
* **Rejected:** "Port 8080 is open on host 192.0.2.1"
* **Reason:** An open port is merely attack-surface context. Unless a specific unauthenticated service, administrative dashboard, or vulnerable version is proven, it cannot be reported as an exposure.

---

### 4. Speculative / Hypothetical Attack Chains
* **Rejected:** "Webhook endpoint accepts POST requests; an attacker could hypothetically forge payments if internal verification fails."
* **Reason:** Pure speculation without validation evidence. Only report if test payloads demonstrated the security boundary was violated.


## VALID ISSUES/EXPOSURES EXAMPLES

This catalog specifies the recognized issue categories, accepted checks, validation criteria, and boundary conditions for ASM exposure analysis. Only report findings that fall under these accepted categories and meet the validation standards.

---

### Category A: Zero Trust and Network Trust

Identify potential gaps in how systems authenticate, authorize, and trust other systems.

#### Recognized Checks:
1. **Direct IP-to-IP Communication**: Traffic routes directly between backend hosts without going through inspection or proxy layers.
2. **Excessive Trust Between Systems**: Systems trusting peers implicitly without re-authenticating or validating tokens.
3. **Implicit Trust in Internal Assets**: Services assuming all traffic from internal or VPN ranges is authorized.
4. **Missing Network Segmentation**: Databases, caches, and application tiers residing on flat, unsegmented network spaces.
5. **Unrestricted East-West Traffic**: Internal lateral traffic allowed unrestricted without firewall filtering or service mesh policies.
6. **Public Access to Internal Services**: Internal microservices, registries, or tools directly accessible from the public internet.
7. **Exposed Management Interface**: Administrative consoles (SSH, RDP, IPMI, Proxmox, vSphere) reachable over the public internet.
8. **Direct Backend Access**: Backend API or database listeners exposed directly, bypassing reverse proxies or API gateways.
9. **Security Gateway Bypass**: Direct IP access allowing attackers to bypass CDN, WAF, Cloudflare, or edge authentication rules.
10. **Unrestricted Service-to-Service Access**: Unauthenticated microservice endpoints callable by any internal caller.
11. **Missing Mutual TLS (mTLS)**: Sensitive service-to-service communication plaintext or unauthenticated at transport layer.
12. **Overly Permissive Firewall Rules**: Any-to-any ingress routing rules to sensitive service ports.

> **Validation Constraints**: Do not conclude that two IP addresses communicate directly merely because both have open ports. Direct connectivity, excessive trust, and missing segmentation require evidence of actual traffic paths, access policies, service behavior, or equivalent technical observations.

---

### Category B: Internet Exposure and Attack Surface

Identify assets and services exposed beyond their intended audience.

#### Recognized Checks:
1. **Unintended Public Asset Exposure**: Services intended solely for internal staff or corporate networks exposed to the world.
2. **Exposed Development Environment**: Dev instances containing experimental features, mock auth, or debug tools exposed publicly.
3. **Exposed Staging Environment**: UAT or staging environments mirroring production configurations accessible without restrictions.
4. **Publicly Accessible Admin Panel**: Administrative web interfaces (WordPress `/wp-admin`, Django admin, phpMyAdmin, custom dashboards).
5. **Unrestricted Open Port**: Sensitive listener ports (e.g. 21, 23, 445, 1433, 1521, 27017, 3306, 5432, 6379, 9200) open to the internet.
6. **Exposed Internal IP or Infrastructure Details**: Server headers, stack traces, or error pages disclosing private RFC 1918 IPs or VPC topology.
7. **Origin Server IP Disclosure**: Resolving the real backend origin IP of an asset protected behind a CDN or Cloudflare.
8. **CDN or WAF Bypass Exposure**: Validating that sending requests directly to the origin IP bypasses edge WAF inspection rules.
9. **Exposed Remote Access Service**: Unprotected or weakly authenticated VPN gateways, Citrix, AnyDesk, TeamViewer, or Bastion endpoints.
10. **Shadow IT Exposure**: Uncataloged, unmanaged infrastructure spun up outside official cloud organization guardrails.
11. **Orphaned DNS Record**: Active DNS records pointing to defunct, unallocated, or third-party cloud infrastructure.
12. **Dangling Subdomain / Subdomain Takeover Risk**: Subdomain CNAME pointing to an unclaimed cloud resource (S3 bucket, GitHub Pages, Azure App Service, Heroku).

> **Validation Constraints**: For suspected orphaned DNS or subdomain takeovers, establish whether the referenced resource is genuinely unclaimed. A third-party CNAME or an error page alone is insufficient evidence of takeover vulnerability.

---

### Category C: Authentication and Access Control

Identify weaknesses in access enforcement and authentication.

#### Recognized Checks:
1. **Service Accessible Without Authentication**: Sensitive administrative, operational, or customer data views available anonymously.
2. **Missing MFA on Administrative Access**: Critical administrative portals (cloud consoles, SSO portals, admin dashboards) lacking multi-factor auth.
3. **Weak or Missing Authorization**: Endpoints allowing lower-privileged users to invoke administrative or privileged actions.
4. **Anonymous Access to Sensitive Resources**: Public read access to private storage buckets, document repositories, or user files.
5. **Unrestricted API Access**: Private API endpoints functioning without API keys, bearer tokens, or session headers.
6. **Excessive Privileges**: User or service roles granting broad, unconstrained permissions beyond operational necessity.
7. **Shared Administrative Access**: Shared root/admin accounts used across multiple administrative tiers.
8. **Insecure Direct Object Reference (IDOR) Risk**: Predictable identifiers in URLs/APIs allowing access to other tenants' data without authorization validation.
9. **Missing Session Security Controls**: Session tokens without expiration, invalidation on logout, or rotation on privilege changes.
10. **Exposed Default Credentials Risk**: Portals or services functioning with factory or default credentials (`admin:admin`, `root:root`).

> **Validation Constraints**: Use only authorized test identities and accounts. Compare permitted and denied operations using controlled test resources. Do not claim MFA is absent solely because an external login page does not visibly request a second factor upfront. Do not attempt brute-forcing.

---

### Category D: Service-to-Service and Backend Exposure

Identify infrastructure services and internal dependencies exposed beyond their intended trust boundaries.

#### Recognized Checks:
1. **Direct Backend-to-Backend Communication**: Unencrypted, unauthenticated communication between backend application nodes.
2. **Database Directly Exposed to Internet**: MySQL (3306), PostgreSQL (5432), MongoDB (27017), Oracle (1521), MSSQL (1433) reachable over public IPs.
3. **Cache Service Exposure**: Redis (6379), Memcached (11211) accessible without authentication over public networks.
4. **Message Broker Exposure**: RabbitMQ (5672/15672), Apache Kafka (9092), ActiveMQ (61616) listeners exposed without ACLs.
5. **Unprotected Internal API**: Microservices or gRPC listeners designed for cluster-internal communication answering external requests.
6. **Exposed Service Discovery Interface**: Consul (8500), Eureka (8761), etcd (2379) exposed with registered service maps and secrets.
7. **Unrestricted Container Service Access**: Docker Engine daemon socket (`2375/2376`) exposed without client certificates.
8. **Kubernetes API Exposure**: Kube-apiserver (6443) or kubelet (10250) reachable with anonymous access enabled.
9. **Exposed Orchestration Dashboard**: Kubernetes Dashboard, Portainer, Nomad, or Rancher UI accessible without authentication.
10. **Unrestricted RPC or Internal Protocol Access**: gRPC, RMI, Hessian, or Thrift services answering over public internet.

> **Validation Constraints**: A reachable database or cache port is evidence of network exposure, but not automatically evidence of unauthenticated access, data compromise, or remote code execution. Verify whether authentication is enforced before claiming data exposure.

---

### Category E: Security Boundaries and Architecture

Identify possible weaknesses in the enforcement of security boundaries.

#### Recognized Checks:
1. **Single Security Boundary Dependency**: System security relying on a single control (e.g. only IP whitelisting with no auth).
2. **Missing Defense in Depth**: Compromise of one peripheral service granting immediate access to entire internal core.
3. **Inconsistent Security Policies**: Discrepancies where one subdomain enforces WAF/MFA while a sibling subdomain on same backend does not.
4. **Trust Boundary Violation**: High-trust environments blindly consuming unvalidated data from untrusted public web services.
5. **Publicly Reachable Internal Dependency**: Backend payment, billing, or identity microservices reachable from untrusted ingress networks.
6. **Unrestricted Ingress Traffic**: Network perimeter lacking rate limiting, GeoIP blocking, or connection throttling on sensitive interfaces.
7. **Unrestricted Egress Traffic**: Internal servers capable of initiating arbitrary outbound internet connections.
8. **Unrestricted Administrative Path**: Management traffic routed over the same public network interface as customer traffic.
9. **Missing Centralized Access Enforcement**: Decentralized access control configurations leading to inconsistent enforcement.
10. **Insecure Direct Connectivity**: Hybrid cloud or partner connections lacking transit filtering or boundary firewalls.

> **Validation Constraints**: Do not infer firewall permissiveness or missing centralized enforcement solely from public HTTP responses. Request configuration evidence or report as requiring internal validation.

---

### Category F: Information Disclosure and Configuration

Identify publicly accessible information and insecure service configurations.

#### Recognized Checks:
1. **Exposed Secrets or API Keys**: Hardcoded cloud keys, JWT secrets, private keys, database passwords in client scripts or public files.
2. **Internal Hostname Disclosure**: HTTP headers (`X-Backend-Server`, `X-Origin-IP`) or SSL certificates leaking private hostnames.
3. **Sensitive File Exposure**: Configuration files (`.env`, `web.config`), repository metadata (`/.git/HEAD`), backups (`.bak`, `.zip`), or logs.
4. **Verbose Error Disclosure**: Detailed stack traces revealing database schemas, source code paths, or framework versions.
5. **Missing or Weak TLS Configuration**: Deprecated TLS 1.0/1.1 protocols, expired certificates, self-signed certs on public hosts, null ciphers.
6. **Insecure HTTP Service**: Sensitive authentication portals or checkout flows served over unencrypted HTTP (port 80) without redirection.
7. **Exposed Debug Endpoint**: Spring Boot Actuator (`/actuator/env`, `/heapdump`), Django `DEBUG=True`, Symfony profiler.
8. **Unrestricted Monitoring Endpoint**: Prometheus metrics (`/metrics`), health checks leaking system topology, cAdvisor.
9. **Software Version Disclosure**: Outdated software banners disclosing known critically vulnerable versions (CPE).

> **Validation Constraints**: Do not reproduce, use, or disclose live credentials unnecessarily. Redact all secret values in evidence and findings. Do not report generic hygiene headers unless an exploitable consequence is demonstrated.
