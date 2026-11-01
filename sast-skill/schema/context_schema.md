# SAST Context Schema Specification

The context file (typically named `context-<runId>.json` or `context.json`) provides the execution parameters for a static application security testing run.

## Structure

```json
{
  "orgId": "org_1234567890",
  "pentestId": "pentest_abcdef1234",
  "scanId": "scan_9876543210",
  "runId": "run_test_001",
  "repo_url": "https://github.com/organization/target-repo",
  "repo_dir": "/app/work/source_code",
  "branch": "main",
  "commit": "a1b2c3d4e5f6",
  "findings_file": "/app/work/sast_findings.run_test_001.json",
  "scanner_findings_count": 14,
  "scanner_summary": {
    "total": 14,
    "critical": 1,
    "high": 4,
    "medium": 7,
    "low": 2
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
| `findings_file` | `string` | Yes | Path to staged Semgrep/pre-scan findings |
| `scanner_summary`| `object` | No | Summary statistics of pre-scan findings |

