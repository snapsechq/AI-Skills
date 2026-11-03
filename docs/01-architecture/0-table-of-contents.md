# AI-Skills Architecture Documentation

Welcome to the technical architecture guide for **Snapsec AI-Skills (`AI-Skills`)**. This repository houses the operational intelligence, reasoning prompts, evaluation checklists, and schema definitions that power Snapsec autonomous security agents.

### Architectural Big Picture: The "AI Centralization" Ecosystem
Within the Snapsec platform, `AI-Skills` is the centralized knowledge base:
- **Synchronized by [migration-service](https://github.com/snapsechq/migration-service) (Stage 0)**: Cloned to local storage and used to bootstrap platform agents.
- **Executed by [automation-service](https://github.com/snapsechq/automation-service) (Stage 3)**: Mounted into Hermes agent sandboxes to guide LLM reasoning, code analysis, and finding verification.

---

### Navigation Index

1. [Overview & Skill Architecture](./1-overview.md)
   * The "Prompt-as-Code" philosophy and role in agentic execution.
2. [Manifest & Skill Folder Hierarchy](./2-manifest-and-skill-structure.md)
   * `agents.json` schema, `SKILL.md` frontmatter, schema validation, and script helpers.
3. [Example Skill Walkthrough: Acme Mobile Shop](./3-example-skill-walkthrough.md)
   * Detailed data walkthrough of `sca-skill` during an automated mobile backend security audit.
4. [Authoring & Testing Skills Guide](./4-authoring-and-testing-skills.md)
   * Step-by-step developer tutorial for creating, testing, and registering a new skill bundle.

---
[Next: 1. Overview & Skill Architecture ➡️](./1-overview.md)

