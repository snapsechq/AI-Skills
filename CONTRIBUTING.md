# Contributing to Snapsec AI-Skills

Welcome to the **Snapsec AI-Skills** repository. This repository houses the operational intelligence, reasoning instructions, and evaluation guidelines consumed by Snapsec autonomous AI agents (`HermesAgent`).

---

## 1. Skill Architecture Standards

Every skill folder in this repository corresponds to a specialized security assessment capability. Skills must adhere to the standardized directory layout:

```text
<skill-name>/
├── SKILL.md                 # Primary instruction prompt with YAML frontmatter
├── resources/               # Catalogs, checklists, and evaluation criteria (Markdown)
├── schema/                  # JSON Schemas and Markdown specifications for inputs/outputs
├── scripts/                 # Standalone Python/Node utility scripts for data filtering
└── skills/                  # Domain-specific deep dives (e.g., Python, Go, Java)
```

### Frontmatter Requirements in `SKILL.md`
Every `SKILL.md` file must begin with YAML frontmatter containing:
```yaml
---
name: sca-skill
description: Performs Software Composition Analysis, dependency auditing, and reachability analysis.
version: 1.0.0
---
```

---

## 2. Registering in `agents.json`

If your skill powers a platform security agent, it **must** be declared in [`agents.json`](./agents.json):

```json
{
  "name": "SCA Security Agent",
  "value": "sca-agent",
  "agent_backend": "sca-agent",
  "description": "Performs Software Composition Analysis (SCA) and reachability analysis.",
  "skill_folder": "sca-skill"
}
```

> [!IMPORTANT]
> When `agents.json` is modified and merged to `main`, [migration-service](https://github.com/snapsechq/migration-service) automatically syncs the changes to MongoDB `automations.agents` across all tenant organizations.

---

## 3. Git & Branching Workflow

```text
main (production skill trees)
  ^
feature/<skill-name>  or  fix/<prompt-tweak>
```

### Commit Message Guidelines (Conventional Commits)
Format: `<type>(<skill-name>): <short description>`
- `feat(sca)`: Add Go vulnerability reachability heuristics
- `fix(was)`: Refine phone authentication prompt instructions
- `docs(skills)`: Add architecture guide for authoring skills

*Example:*
```bash
git commit -m "feat(sast): add taint verification rules for python flask endpoints"
```

---

## 4. Testing Your Skills Locally

Skills are tested in conjunction with [automation-service](https://github.com/snapsechq/automation-service):

1. **Local Linking**:
   Configure `automation-service` environment to read your local `AI-Skills` repository path:
   ```bash
   AI_SKILLS_LOCAL_PATH=/path/to/dev-setup/backend/AI-Skills
   ```
2. **Run Playground Test**:
   Execute the skill in the `automation-service` playground:
   ```bash
   node test/sca.agent.test.js
   node test/web-app-security.agent.test.js
   ```
3. **Verify Schema Conformance**:
   Ensure agent outputs validate strictly against the JSON schema in `<skill-folder>/schema/`.

---

## 5. Pull Request (PR) Checklist

Before submitting a PR:
- [ ] `SKILL.md` has valid YAML frontmatter (`name`, `description`).
- [ ] No proprietary customer data, hardcoded passwords, or unredacted tokens are in test fixtures.
- [ ] New agents are registered in `agents.json`.
- [ ] Output schema JSON files are validated with `validate_results.py`.

