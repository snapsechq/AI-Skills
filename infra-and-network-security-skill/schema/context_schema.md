# Context File Schema Specification

When an infrastructure or network penetration test scan is triggered, the orchestrator provides the agent with an isolated execution context file (e.g. `pentest-<orgId>-<runId>.json`). This file contains the complete target configuration and metadata originating from the backend `Pentest` database model.

---

## 1. Context File Structure

The JSON context file contains the following top-level properties:

```json
{
  "orgId": "org-67890",
  "pentestId": "65b2a1c0e4b023f0a1b2c3d4",
  "scanId": "65b2a1c0e4b023f0a1b2c3d5",
  "name": "Corporate DMZ & Perimeter Infrastructure Assessment",
  "description": "Black-box network penetration test targeting DMZ edge routers, public services, and VPN gateways.",
  "type": "network",
  "pentest_config": {
    "target_type": "black-box",
    "ip": "198.51.100.20",
    "url": "https://vpn.example.com"
  },
  "scan_config": {
    "frequency": "once",
    "start_at_time": "14:00",
    "start_at_date": "2026-10-25"
  },
  "vm_config": {
    "assessmentId": "vm-assess-1042"
  },
  "last_scan_status": "running"
}
```

---

## 2. Field Definitions

| Field | Type | Description |
|---|---|---|
| `orgId` | String (Required) | Multi-tenant organization identifier. Must be propagated into all output findings in `results.json`. |
| `pentestId` | String / ObjectId (Required) | MongoDB ID of the parent Pentest configuration. Must be attached to every finding. |
| `scanId` | String / ObjectId (Optional) | MongoDB ID of the current scan execution instance. Must be attached to findings when present. |
| `name` | String | Human-readable title of the assessment campaign. |
| `description` | String | Scope narrative or operational guidelines provided by the administrator. |
| `type` | String (`"web"` \| `"network"`) | Assessment category. For this skill, this will predominantly be `"network"`. |
| `pentest_config` | Object | Target specification detailing what network assets are in scope. |
| `pentest_config.target_type` | String (`"black-box"` \| `"gray-box"` \| `"white-box"`) | Assessment posture: <br>• `black-box`: Zero internal knowledge, zero credentials. Test from external attacker perspective.<br>• `gray-box`: Partial architecture knowledge or standard user role context provided.<br>• `white-box`: Full configuration or internal architecture details provided. |
| `pentest_config.ip` | String | Target IP address, comma-separated IPs, or CIDR block (e.g., `198.51.100.20` or `198.51.100.0/28`). |
| `pentest_config.url` | String | Target URL, domain name, or hostname resolving to the target infrastructure (e.g., `https://vpn.example.com`). |
| `scan_config` | Object | Scheduling parameters (`frequency`: `"once"`, `"weekly"`, `"monthly"`, start times). |
| `vm_config` | Object | Vulnerability Management synchronization configuration (e.g. `assessmentId`). |

---

## 3. Context Ingestion Rules for the Agent

1. **Extract Targets**:
   - The primary targets are extracted from `pentest_config.ip` and `pentest_config.url`.
   - If both `ip` and `url` are supplied, the agent must correlate both: verify DNS resolution of the URL and determine if the IP matches the resolved address.
   - If `ip` is a CIDR notation (e.g. `198.51.100.0/24`), all IPs within the CIDR are considered in-scope targets for Phase 1 host discovery.
2. **Context Persistence**:
   - Retain `orgId`, `pentestId`, and `scanId` in memory throughout the session to populate the mandatory fields in every reported vulnerability object.
3. **Target Type Adaptation**:
   - For `black-box`, do not assume any internal credentials or trusted network access; verify reachability solely from external vantage points.
   - For `gray-box`, check if auxiliary credentials or endpoint lists are provided in `description` or accompanying workspace files.
