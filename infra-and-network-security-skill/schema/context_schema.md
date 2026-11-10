# Context File Schema Specification

When an infrastructure or network security scan is triggered, the orchestrator provides the agent with an isolated execution context file (e.g. `project-<orgId>-<runId>.json`). This file contains the complete target configuration and metadata originating from the backend `Project` database model.

---

## 1. Context File Structure

The JSON context file contains the following top-level properties:

```json
{
  "orgId": "org-67890",
  "projectId": "65b2a1c0e4b023f0a1b2c3d4",
  "scanId": "65b2a1c0e4b023f0a1b2c3d5",
  "name": "Corporate DMZ & Internal Host Security Assessment",
  "description": "White-box infrastructure assessment with authorized SSH credentials for internal host auditing.",
  "type": "host-scan",
  "scan_type": "network",
  "project_config": {
    "engagement_type": "white-box",
    "targets": [
      "198.51.100.20",
      "198.51.100.21"
    ],
    "out_of_scope": [
      "198.51.100.254"
    ],
    "ssh": {
      "host": "198.51.100.20",
      "port": 22,
      "username": "audituser",
      "auth_method": "key",
      "secret": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"
    }
  },
  "scan_config": {
    "frequency": "once",
    "next_run_at": "2026-10-25T14:00:00.000Z"
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
| `projectId` | String / ObjectId (Required) | MongoDB ID of the parent Project configuration. Must be attached to every finding. |
| `scanId` | String / ObjectId (Optional) | MongoDB ID of the current scan execution instance. Must be attached to findings when present. |
| `name` | String | Human-readable title of the assessment campaign. |
| `description` | String | Scope narrative or operational guidelines provided by the administrator. |
| `type` | String | Assessment product type (e.g. `"host-scan"`, `"pentest"`). |
| `scan_type` | String (`"network"` \| `"infra"`) | Assessment category. For this skill, this is `"network"` or `"infra"`. |
| `project_config` | Object | Target specification detailing network assets, posture, and credentials. |
| `project_config.engagement_type` | String (`"black-box"` \| `"gray-box"` \| `"white-box"`) | Assessment posture: <br>• `black-box`: Zero internal credentials. Test strictly from external network perspective.<br>• `gray-box`: Partial architecture knowledge or limited role context provided.<br>• `white-box`: Full target visibility; when SSH configuration is provided, permits internal host auditing. |
| `project_config.targets` | Array of Strings | Complete array of target IP addresses, hostnames, or CIDR subnets in scope. |
| `project_config.out_of_scope` | Array of Strings | List of IP addresses, hostnames, or subnets explicitly excluded from scanning. |
| `project_config.ssh` | Object | **SSH Host Access Configuration for White-Box Auditing** (see sub-fields below). |
| `project_config.ssh.host` | String | Hostname or IP address for SSH authentication. |
| `project_config.ssh.port` | Number | SSH port (default: `22`). |
| `project_config.ssh.username` | String | SSH user account name. |
| `project_config.ssh.auth_method` | String (`"key"` \| `"password"`) | Authentication method: `"key"` (private key string) or `"password"`. |
| `project_config.ssh.secret` | String | Private key contents (PEM/OpenSSH format) or password string. |
| `scan_config` | Object | Scheduling parameters (`frequency`: `"once"`, `"daily"`, `"weekly"`, `"monthly"`). |
| `vm_config` | Object | Vulnerability Management synchronization configuration (`assessmentId`). |

---

## 3. Context Ingestion Rules for the Agent

1. **Extract Targets & Exclusions**:
   - The primary targets are extracted from `project_config.targets`.
   - Excluded IPs defined in `project_config.out_of_scope` must be strictly omitted from all active scans.
   - If CIDR notation is used (e.g. `198.51.100.0/24`), enumerate all individual host IPs for phase 1 reachability probes.
2. **Context Persistence**:
   - Retain `orgId`, `projectId`, and `scanId` in memory throughout the session to populate mandatory fields in every reported vulnerability object.
3. **Target Type Adaptation & White-Box SSH Configuration**:
   - **`black-box`**: Do not assume any internal credentials or trusted network access; verify reachability solely from external network vantage points.
   - **`gray-box`**: Check if auxiliary credentials or endpoint lists are provided in `description` or accompanying workspace files.
   - **`white-box`**:
     - **Check for SSH Configuration**: The agent MUST inspect `project_config.ssh`.
     - **Internal Host Enumeration Skill Activation**: If `project_config.ssh` is provided with `host`, `username`, and `secret`:
       - The agent recognizes that authorized credentials exist to evaluate the host from the inside.
       - The agent activates `skills/internal-host-enumeration.md` to conduct internal auditing alongside external reconnaissance.
       - Internal enumeration encompasses: auditing localhost-only listeners (`127.0.0.1`), privilege escalation boundaries, `sudo` permissions (`sudo -l`), running background services, file permissions on sensitive configs, cron jobs, environment secrets, and SSH daemon hardening (`sshd_config`).
     - **Missing SSH Configuration in White-Box**: If `engagement_type` is `white-box` but `ssh` is omitted, blank, or lacks authentication secrets, the agent documents that SSH access was not supplied and proceeds with white-box network testing using provided architecture notes and IP scope.
