# 2. Manifest & Skill Folder Hierarchy

Every skill in `AI-Skills` adheres to a clean directory structure that enables reliable parsing by both [migration-service](https://github.com/snapsechq/migration-service) and [automation-service](https://github.com/snapsechq/automation-service).

---

## 1. The Platform Manifest (`agents.json`)
The root file [`agents.json`](file:///C:/Users/Alpha/Desktop/Active%20Projects/SnapSec/working/dev-setup/backend/AI-Skills/agents.json) is the definitive registry linking platform agents to skill bundles:

```json
{
  "agents": [
    {
      "name": "Web Application Security Agent",
      "value": "web-app-security-agent",
      "agent_backend": "web-app-security-agent",
      "description": "Evaluates web applications for vulnerabilities using an agentic browser.",
      "skill_folder": "web-app-security-skill"
    },
    {
      "name": "SCA Security Agent",
      "value": "sca-agent",
      "agent_backend": "sca-agent",
      "description": "Performs Software Composition Analysis (SCA) and reachability analysis.",
      "skill_folder": "sca-skill"
    }
  ]
}
```

- `value`: Stored as `agent_type` in MongoDB.
- `agent_backend`: Maps to a class in `AGENT_REGISTRY` in `automation-service`.
- `skill_folder`: Name of the directory containing the skill bundle.

---

## 2. Skill Folder Structure

```text
<skill-folder>/
├── SKILL.md                 # Primary system instructions with YAML frontmatter
├── resources/               # Catalogs, checklists, and evaluation criteria (Markdown)
│   ├── sca_reachability_criteria.md
│   └── cwe_mapping_catalog.md
├── schema/                  # Input/output schemas and examples
│   ├── context_schema.md
│   ├── sca_vulnerability_schema.json
│   └── valid_findings_example.json
├── scripts/                 # Standalone helper utilities (Python / Node)
│   ├── parse_context.py
│   ├── filter_scanner_findings.py
│   └── validate_results.py
└── skills/                  # Domain-specific sub-instructions
    ├── npm-and-javascript-dependencies.md
    └── python-and-pip-dependencies.md
```

### `SKILL.md` Specification
Every `SKILL.md` must start with valid YAML frontmatter:
```markdown
---
name: sca-skill
description: Performs Software Composition Analysis, CVE verification, and reachability analysis.
version: 1.0.0
---

# Instructions for HermesAgent
...
```

---
[⬅️ Previous: 1. Overview & Skill Architecture](./1-overview.md) | [Next: 3. Example Skill Walkthrough: Acme Mobile Shop ➡️](./3-example-skill-walkthrough.md)

