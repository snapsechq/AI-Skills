# API Security & Exposure Analysis Skill

## Objective

Act as an **API Security & Exposure Specialist**. Systematically discover, map, and assess public API surfaces across in-scope assets to detect **unprotected API documentation, unauthenticated sensitive endpoints, excessive data exposure (PII and credentials), and broken authorization boundaries**.

---

## Methodology

### Step 1: Subdomain Enumeration & API Host Identification
Query all in-scope assets using `scripts/query_assets.py`:
```bash
python3 scripts/query_assets.py session-<session_id>/assets.json --list-subdomains
```
Identify dedicated API gateways and services using common naming patterns:
* `api.*`, `rest.*`, `v1.*`, `v2.*`, `gateway.*`, `service.*`, `backend.*`, `graphql.*`, `api-stage.*`, `api-dev.*`

---

### Step 2: API Documentation & Schema Discovery
Actively probe target subdomains for exposed OpenAPI specifications, Swagger interfaces, and GraphQL endpoints using `scripts/probe_asset.py` or `curl`:

| API Technology | Standard Documentation & Specification Paths |
|---|---|
| **Swagger / OpenAPI** | `/swagger-ui.html`, `/swagger/index.html`, `/swagger-ui/index.html`, `/v2/api-docs`, `/v3/api-docs`, `/openapi.json`, `/openapi.yaml` |
| **FastAPI / ReDoc** | `/docs`, `/redoc`, `/openapi.json` |
| **Spring Boot / Actuator** | `/actuator/mappings`, `/actuator/beans`, `/api/swagger-ui.html` |
| **GraphQL Consoles** | `/graphql`, `/graphiql`, `/altair`, `/playground`, `/api/graphql` |
| **Postman / Raw Specs** | `/api/v1/swagger`, `/schema/`, `/api-docs` |

* **Fetch and Store Schemas**: When an API specification is found, download the JSON/YAML schema to the session directory (e.g. `session-<session_id>/api/<subdomain>_openapi.json`).

---

### Step 3: Parse Schema & Endpoint Inventory
Extract and categorize all declared paths from the retrieved OpenAPI/Swagger specification:
1. **Authentication Scopes**: Inspect the `security` and `securityDefinitions` tags to identify which endpoints require authorization (`Bearer`, `ApiKey`, `OAuth2`) vs. which are declared public.
2. **High-Risk Functionality**: Prioritize routes involving:
   * Administrative & Management: `/admin/*`, `/internal/*`, `/management/*`, `/debug/*`
   * User & Identity: `/users`, `/accounts`, `/profiles`, `/auth`, `/roles`
   * Financial & Sensitive Data: `/billing`, `/payments`, `/orders`, `/tokens`, `/keys`
   * Export & Bulk Operations: `/export`, `/dump`, `/backup`, `/reports`

---

### Step 4: Access Boundary & Authentication Testing
Test discovered endpoints safely to determine whether access controls are enforced:

1. **Unauthenticated Access to Protected Endpoints**:
   * Send HTTP requests (`GET`, `OPTIONS`, `HEAD`) without authentication headers to endpoints declared as sensitive or protected.
   * If the endpoint responds with `HTTP 200 OK` and returns application data instead of `HTTP 401 Unauthorized` or `403 Forbidden`, confirm an **Unauthenticated Sensitive API Exposure**.
2. **Broken Object Level Authorization (BOLA/IDOR)**:
   * Evaluate whether object identifiers (e.g., `/api/v1/users/{id}`, `/api/orders/{id}`) return records across tenants or unauthenticated callers.
3. **GraphQL Introspection**:
   * For GraphQL endpoints, test whether schema introspection is enabled (`{"query": "{__schema{types{name}}}"}`).
   * If enabled, check if hidden administrative mutations or internal models are exposed.

---

### Step 5: Detect Excessive Data Exposure
Inspect response payloads for sensitive information that should not be returned to client-side consumers:
* **PII Leakage**: Full names, plain-text email addresses, telephone numbers, national IDs, or physical addresses returned in mass object responses.
* **Leaked Credentials & Tokens**: Hardcoded JWTs, third-party API keys (Stripe, AWS, Twilio), or password hashes included in JSON serialization.
* **Verbose Server & Database Traces**: Unhandled exceptions leaking SQL queries, database server versions, or backend microservice routing topology.

---

### Step 6: Non-Findings vs. Real Exposures
Follow the strict validation constraints in `resources/finding_Validation_example.md`:

* **Reject (Non-Findings)**:
  * Public consumer APIs functioning as intended (e.g., public catalog items `/api/v1/products` or public store listings `/api/stores`) returning general marketing data.
  * Properly secured endpoints that reject unauthenticated calls with standard `401 Unauthorized` or `403 Forbidden`.
  * Swagger UI pages that only document public endpoints and enforce strict authentication on all interactive test calls.
  * Hypothetical injection claims without verified boundary violation evidence.
* **Report (Confirmed Exposures)**:
  * Unauthenticated API endpoint returning customer PII, internal records, or administrative control actions.
  * Publicly reachable Swagger / OpenAPI UI exposing unpublished internal, staging, or management microservice endpoints.
  * Production GraphQL endpoint with full introspection exposing sensitive internal queries and administrative mutations.
  * Verbose error responses leaking internal database architecture or private infrastructure configuration.

---

## End Goal

Deliver confirmed, evidence-backed findings for API exposures that:
1. Identify the full API endpoint URL, HTTP method, and exposed parameters.
2. Provide direct proof of missing authentication or excessive data returned.
3. Document clear security impact (unauthorized data leakage, tenant isolation breach, or administrative bypass).
