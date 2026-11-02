# Web Application Security Agent Context Schema

The Web Application Security Agent receives a runtime execution context (e.g. `context-<runId>.json` or `context.json`) formulated by `automation-service`.

## Context Structure

```json
{
  "orgId": "660e1234567890abcdef1234",
  "runId": "run_was_6ae829054b68a1348c034f6b",
  "scanId": "scan_was_001",
  "pentestId": "6ae8515a861760b4f1e400e0",
  "target_url": "https://example.com",
  "domain": "example.com",
  "scope": [
    "https://example.com"
  ],
  "credentials": {
    "username": "user@example.com",
    "password": "SecretPassword123"
  },
  "auth_type": "form",
  "login_url": "https://example.com/login",
  "nuclei_enabled": true
}
```

## Field Descriptions

| Field | Type | Required | Description |
|---|---|---|---|
| `orgId` | String | Yes | MongoDB Organization ID |
| `runId` | String | Yes | Unique ID of current agent run |
| `pentestId` | String | Yes | Identifier of the pentest / assessment |
| `target_url` | String | Yes | Base URL of web application to test |
| `domain` | String | No | Target host or domain |
| `scope` | Array[String]| No | Allowed hostnames/origins in-scope |
| `credentials` | Object | No | Login credentials (username/password or token) |
| `auth_type` | String | No | Authentication type: `form`, `basic`, `bearer`, or `none` |
| `login_url` | String | No | Path or URL for authentication form |
| `nuclei_enabled` | Boolean | No | Whether to execute Nuclei pre-scan |

