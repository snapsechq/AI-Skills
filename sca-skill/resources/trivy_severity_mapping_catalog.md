# Trivy Severity Mapping Catalog

Trivy outputs severities based on vendor definitions, NVD CVSS scores, and GitHub Security Advisories. This catalog maps Trivy ratings to SnapSec's standard scale:

| Trivy Severity | CVSS v3 Range | SnapSec Severity | Reachability Impact |
|---|---|---|---|
| **CRITICAL** | 9.0 – 10.0 | `critical` | If reachable $\rightarrow$ critical. If unreachable $\rightarrow$ downgrade to high/medium. |
| **HIGH** | 7.0 – 8.9 | `high` | If reachable $\rightarrow$ high. If unreachable $\rightarrow$ downgrade to low. |
| **MEDIUM** | 4.0 – 6.9 | `medium` | Standard medium impact. |
| **LOW** | 0.1 – 3.9 | `low` | Minimal real-world impact. |
| **UNKNOWN** | N/A | `info` | Informational audit note. |

