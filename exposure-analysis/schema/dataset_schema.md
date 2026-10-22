# Attack Surface Dataset Schema & Querying Guide

The ASM attack surface dump file provided in the execution context contains all discovered assets, existing findings, and organization signals/rules.

---

## 1. Top-Level Structure

The input file (`assets-<orgId>-<runId>.json`) contains three primary arrays:

```json
{
  "assets": [
    /* Array of all discovered attack surface asset objects */
  ],
  "existing_exposures": [
    /* Array of previously identified exposures (DO NOT DUPLICATE) */
  ],
  "signals": [
    /* Array of active organization detection rules/signals to validate on matching assets */
  ]
}
```

---

## 2. Splitting the Dataset

Before testing, split the dump file into separate files inside your session directory:

```bash
python3 scripts/split_dataset.py <path_to_dump_file> --out-dir session-<session_id>/
```

This generates:
* `session-<session_id>/assets.json`: Clean array of asset records.
* `session-<session_id>/existing_exposures.json`: Array of known exposures.
* `session-<session_id>/signals.json`: Array of organization rules/signals to match and validate.
* Summary statistics (subdomain count, IP count, available signals, breakdown by type).

---

## 3. Asset Object Schema

Each asset in `assets` belongs to a specific `type`:

| Type | `value` Example | Description | Key `properties` Fields |
|---|---|---|---|
| `subdomain` | `api.example.com` | DNS hostname / subdomain | `subdomain_status` (`live`\|`dead`), `subdomain_status_code`, `subdomain_title`, `subdomain_full_url`, `subdomain_headers` |
| `ip` | `192.0.2.1` | Network IP address | `ip_country`, `ip_city`, `ip_org`, `ip_location` |
| `port` | `443` | Open port on host/IP | `port_service` (e.g. `http`, `ssh`, `redis`), `port_service_version`, `port_status` (`open`), `port_protocol` (`tcp`) |
| `technology` | `WordPress` | Identified stack / library | `technology_description`, `technology_cpe`, `technology_website`, `technology_categories` |
| `web_server` | `https://api.example.com` | Web server instance | Associated subdomain, headers, WAF data |
| `certificate` | `*.example.com` | SSL/TLS Certificate | `certificate_common_name`, `certificate_valid_to`, `certificate_is_expired`, `certificate_tls_version` |
| `dns` | `example.com` | DNS Record | `dns_class`, `dns_ttl` |
| `api` | `/v1/users` | Discovered API endpoint | `api_status_code`, `api_headers`, `api_technique` |

### Core Correlation Attributes:
Assets are linked by common fields:
* `domain`: Base registered domain (e.g. `example.com`).
* `subdomain`: Hostname that the asset belongs to (e.g. a port or technology record will have `subdomain: "admin.example.com"`).
* `ip`: IP address associated with the asset (e.g. `ip: "192.0.2.1"`).
* `externally_reachable`: Boolean indicating public accessibility.

---

## 4. Signals / Rules Schema

Each item in `signals` represents a detection rule configured for the organization:

```json
{
  "_id": "670...",
  "name": "Exposed MySQL Database",
  "category": "Database Exposure",
  "risk": "high",
  "description": "MySQL database listener port is exposed to the public internet.",
  "impact": "Potential brute-force attack or exploitation of unauthenticated access.",
  "remediation": "Restrict port 3306 behind VPN or firewall allowlist.",
  "references": ["https://cwe.mitre.org/data/definitions/284.html"],
  "match": {
    "type": "port",
    "properties.port_service": "mysql"
  }
}
```

### Signal Structure & Attributes:
* `name`: Rule/signal name (e.g., "Exposed Git Repository", "MySQL Exposed to Internet").
* `risk`: Suggested severity (`critical`, `high`, `medium`, `low`, `info`).
* `category`: Broad issue category.
* `description`, `impact`, `remediation`: Context and remediation guidance.
* `match`: Query condition used to identify matching assets across the attack surface.

---

## 5. Existing Exposures Schema

Each item in `existing_exposures` represents a previously reported exposure:
```json
{
  "_id": "670...",
  "associatedAsset": {
    "type": "subdomain",
    "value": "portal.example.com",
    "subdomain": "portal.example.com"
  },
  "title": "Exposed Git Repository Metadata",
  "severity": "high",
  "state": "In Review"
}
```

> **CRITICAL RULE**: Any finding already listed in `existing_exposures` is an already known issue. Do NOT report it again in your final output, as doing so creates duplicate vulnerabilities.

---

## 6. Querying Assets & Matching Signals with `scripts/query_assets.py`

Use the dedicated querying interface to inspect assets and correlate signals:

```bash
# 1. Summary of all asset types, exposures, and signals
python3 scripts/query_assets.py <assets_file> --summary

# 2. List all unique subdomains with their status, resolved IPs, and open ports
python3 scripts/query_assets.py <assets_file> --list-subdomains

# 3. List all unique IPs with geolocation and open ports
python3 scripts/query_assets.py <assets_file> --list-ips

# 4. Get complete correlated profile for an asset (ports, services, tech)
python3 scripts/query_assets.py <assets_file> --get-asset admin.example.com

# 5. List all open ports with service banners and versions
python3 scripts/query_assets.py <assets_file> --open-ports

# 6. List all identified technologies and which assets use them
python3 scripts/query_assets.py <assets_file> --technologies

# 7. List existing exposures to avoid reporting duplicates
python3 scripts/query_assets.py <dump_or_exposures_file> --exposures

# 8. List all organization signals/rules
python3 scripts/query_assets.py <dump_or_signals_file> --signals

# 9. Evaluate and match signals against assets to find targets for signal validation
python3 scripts/query_assets.py session-<session_id>/assets.json --signals-file session-<session_id>/signals.json --match-signals

# 10. Match assets for a specific signal
python3 scripts/query_assets.py session-<session_id>/assets.json --signals-file session-<session_id>/signals.json --match-signal "Exposed MySQL Database"

# Append --json to any command to receive raw JSON for scripting/piping
python3 scripts/query_assets.py session-<session_id>/assets.json --signals-file session-<session_id>/signals.json --match-signals --json
```
