# SCA Context Schema Specification

The context file (typically named `context-<runId>.json` or `context.json`) provides the execution parameters for a software composition analysis run.

## Structure

```json
{
  "orgId": "org_1234567890",
  "pentestId": "pentest_abcdef1234",
  "scanId": "scan_9876543210",
  "runId": "run_sca_001",
  "repo_url": "https://github.com/organization/target-repo",
  "repo_dir": "/app/work/source_code",
  "branch": "main",
  "commit": "b2c3d4e5f6a1",
  "findings_file": "/app/work/sca_findings.run_sca_001.json",
  "scanner_findings_count": 8,
  "scanner_summary": {
    "total": 8,
    "critical": 1,
    "high": 3,
    "medium": 3,
    "low": 1
  }
}
```

## Field Descriptions

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `orgId` | `string` | Yes | Organization identifier |
| `pentestId` | `string` | Yes | Pentest / Assessment identifier |
| `scanId` | `string` | No | Active scan run ID |
| `runId` | `string` | Yes | Unique execution run ID |
| `repo_url` | `string` | Yes | Git clone URL for target repository |
| `repo_dir` | `string` | Yes | Absolute path on disk where repo is cloned |
| `branch` | `string` | No | Branch checked out for testing |
| `findings_file` | `string` | Yes | Path to staged Trivy pre-scan findings |
| `scanner_summary`| `object` | No | Summary statistics of pre-scan findings |

