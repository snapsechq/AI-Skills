# Wayback Machine & Historical URL Analysis Skill

## Objective

Act as a **Historical Attack Surface & Archive Reconnaissance Specialist**. Systematically extract and analyze historical URLs from public web archives (Wayback Machine CDX API) across the target organization's domains, filter for **exposed database dumps, sensitive archive files, legacy API routes, and hidden administrative interfaces**, and safely verify if they remain accessible on live systems.

---

## Methodology

### Step 1: Identify In-Scope Root Domains
Extract target subdomains and resolve base apex domains from the dataset:
```bash
python3 scripts/query_assets.py session-<session_id>/assets.json --list-subdomains
```
Identify primary organization root domains (e.g. `example.com`, `example.io`) to query the web archive.

---

### Step 2: Query Wayback CDX API with Size Guardrail (100MB Cap)
Archive dumps for active domains can be massive. Enforce a strict **100 MB file limit** and timeout to avoid disk exhaustion and long stalls:

```bash
mkdir -p session-<session_id>/wayback

# Stream historical URLs for the target domain and enforce a 100MB cap
curl -s --max-time 60 --max-filesize 104857600 \
  "http://web.archive.org/cdx/search/cdx?url=*.<target_domain>/*&output=text&fl=original&collapse=urlkey" \
  | head -c 104857600 > session-<session_id>/wayback/<target_domain>_raw_urls.txt

# Deduplicate and sort extracted URLs
sort -u session-<session_id>/wayback/<target_domain>_raw_urls.txt -o session-<session_id>/wayback/<target_domain>_urls.txt
```

---

### Step 3: Filter for High-Value & Sensitive File Patterns
Parse the extracted URLs to isolate high-risk files, sensitive extensions, and privileged application routes:

#### Key Sensitive Patterns:
| Category | File Extensions & URL Signatures |
|---|---|
| **Compressed Backups** | `\.zip$`, `\.rar$`, `\.tar\.gz$`, `\.tgz$`, `\.7z$`, `\.bak$`, `\.old$`, `\.backup$` |
| **Data & Dumps** | `\.sql$`, `\.dump$`, `\.db$`, `\.sqlite$`, `users\.json$`, `export\.(csv\|json\|xlsx)$` |
| **Configs & Keys** | `\.env$`, `config\.json$`, `settings\.py$`, `web\.config$`, `\.pem$`, `id_rsa$` |
| **Privileged Panels** | `/admin/`, `/administrator/`, `/manage/`, `/dashboard/`, `/control/`, `/cpanel/` |
| **Sensitive APIs** | `/api/v[0-9]+/`, `/users/[0-9]+`, `/account/`, `/order/`, `/token/`, `/debug/`, `/metrics` |

#### Fast Extraction Command:
```bash
grep -Ei "(\.(zip|rar|tar\.gz|tgz|7z|sql|dump|db|sqlite|bak|old|backup|env|pem)|users\.json|export\.(csv|xlsx|json)|/(admin|administrator|manage|dashboard|api/v[0-9]+|debug|metrics)/)" \
  session-<session_id>/wayback/<target_domain>_urls.txt | head -n 500 > session-<session_id>/wayback/interesting_urls.txt
```

---

### Step 4: Live Verification & Reachability Probing
Historical URLs represent past states. Probe candidate URLs against live servers to establish whether the files or routes are actively exposed:

1. **Check Live HTTP Response**:
   ```bash
   curl -s -I -L --max-time 5 -A "ASM-Validation-Agent/1.0" "<candidate_url>"
   ```
2. **Inspect Response Headers & Status**:
   * Confirm status code `200 OK` (not `404 Not Found`, `410 Gone`, or redirect to root `/`).
   * Check `Content-Type` and `Content-Length`:
     - For archives: `Content-Type: application/zip`, `application/x-tar`, `application/octet-stream`.
     - For data files: `application/json`, `text/csv`, `text/plain` (containing actual records).
3. **Guard Against SPA Soft-404s**:
   * Single Page Applications (React, Vue, Angular) often return `HTTP 200` with the standard `index.html` shell for any requested non-existent URL.
   * Verify that the response content matches the expected file type, not generic HTML containing `<div id="root">`.

---

### Step 5: Safe Validation (No Bulk Data Exfiltration)
* **Never download entire database dumps or bulk archives**:
  * Verify existence by reading only the first 1KB of the file using HTTP range requests:
    ```bash
    curl -s -r 0-1024 -A "ASM-Validation-Agent/1.0" "<candidate_url>" | head -c 256
    ```
  * Confirm file magic bytes (e.g. `PK\x03\x04` for ZIP, `SQLite format 3`, SQL `CREATE TABLE` / `INSERT INTO` statements).
* Stop testing immediately once exposure is proven.

---

### Step 6: Non-Findings vs. Real Exposures
Follow the strict validation constraints in `resources/finding_Validation_example.md`:

* **Reject (Non-Findings)**:
  * Inactive historical URLs returning `404 Not Found`, `410 Gone`, or connection timeouts.
  * Soft-404 responses returning the main homepage HTML with status 200.
  * Standard public marketing pages, documentation, or public media assets (`.png`, `.jpg`, `.svg`).
* **Report (Confirmed Exposures)**:
  * Live, downloadable backup archive files (`.zip`, `.tar.gz`, `.bak`) containing source code or configurations.
  * Live database dumps (`.sql`, `.dump`, `users.json`) accessible without authentication.
  * Exposed production configuration files (`.env`, `config.json`) leaking API tokens or database credentials.
  * Unauthenticated legacy admin portals or debug endpoints discovered through historical records.

---

## End Goal

Deliver validated findings for historical URL exposures that:
1. Provide the exact live URL and confirmed HTTP response headers (`Content-Type`, `Content-Length`).
2. Demonstrate that the sensitive file or route is actively accessible on current infrastructure.
3. Prove severe security impact (source code disclosure, credential leak, or unauthenticated admin access).
