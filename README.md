# Snapsec AI-Skills

[![Repository](https://img.shields.io/badge/Repository-AI--Skills-blue.svg)](https://github.com/snapsechq/AI-Skills)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](./LICENSING.md)

## 1. Project Overview

**Snapsec AI-Skills (`AI-Skills`)** is the centralized repository for AI prompts, instructions, and security evaluation rules for the Snapsec platform. 

It defines:
1. **Agent Skill Bundles**: Clear prompts and reasoning steps for automated security tasks (Web App Security, Cloud Security, SAST, SCA, Network & Infrastructure, Exposure Analysis).
2. **Platform Agent Catalog (`agents.json`)**: The official list mapping security agents to their backend classes and skill folders.
3. **Evaluation Schemas & Checklists**: JSON schemas and reachability checklists used by `HermesAgent` to remove false positives and output structured security reports.

---

## 2. Architectural Big Picture: The "AI Centralization" Ecosystem

In Snapsec's decentralized microservice architecture, `AI-Skills` acts as the single source of truth for all AI agent behaviors:

```text
               +--------------------------------------------+
               |              auto-pentest                  |
               | - Defines pentest target configurations    | [STAGE 2]
               | - Manages host detector agents & telemetry |
               | - Dumps execution context to disk          |
               +---------------------+----------------------+
                                     |
                                     | publishes 'agentexecutor.execute'
                                     v
               +--------------------------------------------+
               |           automation-service               |
               | - Central AI Orchestration Engine          | [STAGE 3]
               | - Mounts skills from AI-Skills repo        | <=== CONSUMES SKILLS
               | - Tool runners (Trivy, Semgrep, Playwright)|
               +---------------------+----------------------+
                                     |
              +----------------------+----------------------+
              |                                             |
   (fetch git/cloud credentials)               (seeds default platform agents
              |                                 & pulls AI-Skills repo)
              v                                             v
+---------------------------+                 +---------------------------+
|    integration-service    |                 |     migration-service     |
| - OAuth / Vault / Keys    | [STAGE 1]       | - Clones & syncs AI-Skills| [STAGE 0]
| - GitHub, GitLab, AWS     |                 |   repo to local disk      | <=== SYNCS REPOSITORY
| - Client via @core adapter|                 | - Org creation seeds      |
+---------------------------+                 +---------------------------+
```

### How `AI-Skills` Interacts Across Services
- **Provisioned by [migration-service](https://github.com/snapsechq/migration-service) (Stage 0)**:
  Clones this repository into `/data/skills-repo` and parses [`agents.json`](./agents.json) to seed default platform agents into MongoDB `automations.agents` whenever an organization registers.
- **Executed by [automation-service](https://github.com/snapsechq/automation-service) (Stage 3)**:
  When an autonomous scan triggers, `automation-service` mounts the relevant skill folder from disk into the agent workspace (`/data/agentruntime/agents/<orgId>/<runId>/.skills/`), loading prompt instructions and Python evaluation scripts directly into the Hermes LLM context.

---

## 3. End-to-End Real-World Example: "Acme Mobile Shop" Security Audit

To understand how prompt instructions guide security audits, follow the Acme Corp mobile audit:

```text
Target: "Acme Mobile Shop"
Mobile App: iOS / Android e-commerce client
API Target: https://api.acme-shop.com (backend mobile API)
Authentication: Mobile phone SMS login (phone: "+1-555-0199", test token: "otp_live_test")
Source Code: https://github.com/acme-corp/shop-api.git (private repository)
Organization: org_acme_123
Agent: sca-agent
Skill Bundle: sca-skill/
```

### Step 1: Upstream Context Preparation
- **Stage 0 ([migration-service](https://github.com/snapsechq/migration-service))**: Synced `AI-Skills` and initialized `sca-agent` for `org_acme_123`.
- **Stage 1 ([integration-service](https://github.com/snapsechq/integration-service))**: Supplied the decrypted GitHub token for `acme-corp/shop-api`.
- **Stage 2 ([auto-pentest](https://github.com/snapsechq/auto-pentest))**: Created target, dumped context JSON, and dispatched `agentexecutor.execute`.
- **Stage 3 ([automation-service](https://github.com/snapsechq/automation-service))**: Cloned `shop-api` and ran Trivy on `package.json`, discovering an unpatched vulnerability in `jsonwebtoken` (CVE-2022-23529).

### Step 2: What Happens HERE in `AI-Skills` (Execution within HermesAgent)
1. **Loading Instructions**:
   `HermesAgent` loads [`sca-skill/SKILL.md`](./sca-skill/SKILL.md) and [`sca-skill/resources/sca_reachability_criteria.md`](./sca-skill/resources/sca_reachability_criteria.md).
2. **Executing the Reachability Audit**:
   Following the checklist in `SKILL.md`, the LLM executes helper tools to trace imports:
   ```bash
   grep -rn "jsonwebtoken" source_code/
   ```
   It confirms that `jsonwebtoken` is imported in `routes/api/v1/auth/phone-verify.js` and called directly during user phone OTP verification.
3. **Structuring Verified Findings**:
   The LLM formats the result according to [`sca-skill/schema/sca_vulnerability_schema.json`](./sca-skill/schema/sca_vulnerability_schema.json), outputting a verified vulnerability with severity `high` and concrete remediation instructions.

---

## 4. Related Services (Cross-Repository Links)

- 🎯 **[auto-pentest](https://github.com/snapsechq/auto-pentest)**: Automated penetration testing targets, scan dispatching, and host agent detector telemetry.
- 🤖 **[automation-service](https://github.com/snapsechq/automation-service)**: The central AI execution engine running Hermes, Web App Security, Cloud, SCA, and SAST agents.
- 🔗 **[integration-service](https://github.com/snapsechq/integration-service)**: Centralized credential vault and third-party provider manager (GitHub, GitLab, AWS, Jira, Slack).
- 📦 **[migration-service](https://github.com/snapsechq/migration-service)**: Database schema migration runner, AI-Skills git repository synchronizer, and organization seed worker.
- 🧠 **[AI-Skills](https://github.com/snapsechq/AI-Skills)**: This repository.

---

## 5. Documentation Structure

Technical architecture documentation is maintained in [`docs/01-architecture/`](./docs/01-architecture/) following the Snapsec paginated documentation standard:

* 📖 **[0. Table of Contents](./docs/01-architecture/0-table-of-contents.md)**
* 🧭 **[1. Overview & Skill Architecture](./docs/01-architecture/1-overview.md)**
* 📁 **[2. Manifest & Skill Folder Hierarchy](./docs/01-architecture/2-manifest-and-skill-structure.md)**
* 📱 **[3. Example Skill Walkthrough: Acme Mobile Shop](./docs/01-architecture/3-example-skill-walkthrough.md)**
* ✍️ **[4. Authoring & Testing Skills Guide](./docs/01-architecture/4-authoring-and-testing-skills.md)**

---

## 6. Repository Layout

```text
.
├── agents.json                      # Master platform agent manifest
├── web-app-security-skill/          # DAST testing directives & checklists
├── cloud-security-skill/            # Cloud configuration evaluation criteria
├── sast-skill/                      # Static code pattern rules & taint tracking
├── sca-skill/                       # Dependency reachability criteria & schemas
├── network-infra-security-skill/    # Host and port scanning evaluation guidelines
└── exposure-analysis-skill/         # External attack surface discovery instructions
```

---

## 7. License

This repository is proprietary and confidential to **Snapsec Inc.** See [LICENSING.md](./LICENSING.md) for full terms.
