# 1. Overview & Skill Architecture

## The "Prompt-as-Code" Philosophy
Hardcoding large prompt strings directly into service application logic leads to fragile systems, no version history, and hard-to-test prompts.

**Snapsec treats AI skills as code (`AI-Skills`)**:
- **Versioned & Audited**: Changes to how an agent reasons about reachability or verifies an SQL injection are tracked as Git commits.
- **Dynamic Updates**: Updating an assessment guideline or adding a CWE checklist does not require redeploying [automation-service](https://github.com/snapsechq/automation-service). [migration-service](https://github.com/snapsechq/migration-service) synchronizes changes live via Git.
- **Works with Any LLM**: Prompts and checklists in this repository are structured so that underlying LLM engines (DeepSeek, Claude, GPT-4o) interpret them uniformly.

---

## Role in the AI Centralization Ecosystem

```text
[Stage 0: migration-service] ---> Syncs AI-Skills repo from GitHub to /data/skills-repo
[Stage 1: integration-service] -> Manages repository credentials and cloud keys
[Stage 2: auto-pentest] --------> Configures targets and initiates scan
[Stage 3: automation-service] --> Mounts /data/skills-repo/<skill> into agent workspace
```

When an agent executes in [automation-service](https://github.com/snapsechq/automation-service), the orchestrator creates an isolated directory:
```text
/data/agentruntime/agents/<orgId>/<runId>/.skills/<skill-folder>/
```
`HermesAgent` reads `SKILL.md` as its primary system prompt, uses Python scripts in `scripts/` to parse context, and cross-references criteria in `resources/` before finalizing output.

---
[⬅️ Previous: 0. Table of Contents](./0-table-of-contents.md) | [Next: 2. Manifest & Skill Folder Hierarchy ➡️](./2-manifest-and-skill-structure.md)

