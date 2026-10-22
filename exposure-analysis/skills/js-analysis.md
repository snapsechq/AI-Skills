# JavaScript Analysis & Secret Detection Skill

## Objective

Act as an **Expert JS Security Analyst** specialized in client-side code analysis. Systematically inspect frontend JavaScript assets across target subdomains to discover and safely validate **exposed secrets, sensitive configuration, source code leaks, and hidden administrative endpoints**.

---

## Methodology

### Step 1: Subdomain-by-Subdomain Enumeration
Iterate through all active subdomains and target hosts identified in `checklist.md`:
* Query asset profile: `python3 scripts/query_assets.py session-<session_id>/assets.json --get-asset <subdomain>`
* Fetch live web responses for HTTP/HTTPS endpoints.

### Step 2: JS Asset Extraction
Extract both referenced and embedded JavaScript from the page:
1. **External Scripts**:
   * Parse `<script src="...">` and `<link rel="preload" as="script">` tags.
   * Extract bundle chunks from Webpack runtimes, Vite manifests, or Next.js `_buildManifest.js` / `_ssgManifest.js`.
2. **Inline Scripts**:
   * Extract all inline `<script>...</script>` blocks directly from the HTML source.
   * Check for inline global configs (e.g. `window.__INITIAL_STATE__`, `window.ENV`, `window.__CONFIG__`).

### Step 3: Build & Source Map Leak Detection
Check if production deployments leak unminified original source code:
* **Source Maps**:
  * Check for source map declarations (`//# sourceMappingURL=...`).
  * Test appending `.map` to JS URLs (e.g., `https://app.example.com/static/js/main.chunk.js.map`).
  * If accessible, unpack sources to inspect raw backend logic and unminified configuration.
* **Build Artifacts & Dev Modes**:
  * Identify debug modes (`debug: true`, `env: "development"`).
  * Check for exposed `.env` files or exposed frontend environment variables containing backend secrets (`REACT_APP_*`, `NEXT_PUBLIC_*`, `VITE_*`).

### Step 4: Strict Scope Filtering & Ignore External Scripts
**STRICT SCOPE CONSTRAINT: Never scan anything that does not belong to the target scope.**
* **In-Scope Assets Only**: Only download and analyze first-party JavaScript hosted directly on in-scope subdomains, target domains, or organization-owned asset buckets.
* **Exclude All External & Third-Party References**: Immediately discard all external vendor libraries, analytics, and third-party CDNs. **Do NOT download, scan, or report findings on**:
  * Public Library CDNs: `cdnjs.cloudflare.com`, `cdn.jsdelivr.net`, `unpkg.com`, `ajax.googleapis.com`, `code.jquery.com`.
  * Analytics & Tag Managers: `googletagmanager.com`, `google-analytics.com`, `segment.io`, `mixpanel.com`, `hotjar.com`.
  * Support & SaaS Widgets: `intercom.io`, `zendesk.com`, `sentry.io`, `crisp.chat`, `recaptcha.net`.
  * Social & Ad Trackers: `connect.facebook.net`, `static.ads-twitter.com`, `snap.licdn.com`.
* **Normalize Relative URLs**: Resolve relative paths (e.g. `/static/js/bundle.js`) against the current in-scope subdomain origin before fetching.

### Step 5: Historical In-Scope JS Discovery (Wayback / CDX API)
Discover older or deprecated first-party JS files that may still exist on the server or leak legacy secrets:
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.<target_domain>/*&output=json&fl=original&collapse=urlkey&filter=mimetype:application/javascript" | jq -r '.[1:][] | .[0]' | sort -u
```
* Test if historical JS paths still resolve live on the server (often forgotten during releases). Filter results to ensure only in-scope target domains are tested.

### Step 6: Download & Secret Scanning
Download in-scope scripts to the session directory (e.g. `session-<session_id>/js/`) and scan for high-risk patterns:

#### Critical Secret Categories:
| Category | Indicators & Patterns |
|---|---|
| **Cloud Providers** | AWS (`AKIA[0-9A-Z]{16}`), Google Cloud API keys (`AIza[0-9A-Za-z\\-_]{35}`), Azure Storage connection strings |
| **SaaS & Payment** | Stripe Secret Keys (`sk_live_...`), SendGrid (`SG\....`), Twilio, Mailgun, Slack Webhooks |
| **Private Keys & Auth** | `-----BEGIN RSA PRIVATE KEY-----`, JWT tokens with signing secrets, OAuth client secrets |
| **Database & Caches** | `mongodb+srv://`, `postgres://`, `redis://`, MySQL connection strings with credentials |
| **Internal Endpoints** | Internal routing (`*.internal.*`, `*.corp.*`, `*.dev.*`, RFC 1918 IPs), `/admin/*`, `/actuator/*`, GraphQL mutations |

#### Fast CLI Scanning Command:
```bash
grep -EnoI "(AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24}|AIza[0-9A-Za-z\\-_]{35}|ghp_[0-9a-zA-Z]{36})" session-<session_id>/js/
```

### Step 7: Validation & Distinguishing Non-Findings
Never report client-side identifiers that are intentionally public by design:

* **Reject (Non-Findings)**:
  * Public client IDs (Google OAuth Client ID, Mixpanel / Segment write keys).
  * Placeholder strings, mock credentials, or `test` tokens in dummy data.
* **Validate Impact Non-Destructively**:
  * Non-destructively probe genuine secrets (e.g., query read-only user/profile endpoint) to confirm the key is live and active.
  * Stop testing immediately once validity is confirmed.

---

## End Goal

Identify and deliver verified findings where exposed JavaScript contains sensitive data or credentials that:
1. Allow **unauthorized access** to internal services, cloud backends, databases, or third-party APIs.
2. Expose **confidential internal infrastructure details** or unpublished management endpoints.
3. Violate security boundaries with **demonstrable, high-confidence real-world impact**.
