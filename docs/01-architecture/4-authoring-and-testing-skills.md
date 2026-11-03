# 4. Authoring & Testing Skills Guide

This guide walks developers through creating, structuring, and testing a new skill bundle in `AI-Skills`.

---

## Step 1: Create the Skill Directory
Create a folder for your new skill:
```bash
mkdir -p backend/AI-Skills/mobile-api-security-skill/{resources,schema,scripts,skills}
```

---

## Step 2: Write `SKILL.md`
Create `mobile-api-security-skill/SKILL.md` with valid YAML frontmatter:

```markdown
---
name: mobile-api-security-skill
description: Tests mobile-specific REST APIs for broken object level authorization (BOLA) and SMS/phone OTP bypasses.
version: 1.0.0
---

# Mobile API Security Testing Directives

When auditing mobile application APIs:
1. Identify all authentication endpoints that accept phone numbers, SMS tokens, or biometric signatures.
2. Validate whether OTP verification endpoints enforce rate limiting (anti-brute force).
3. Test for Object-Level Authorization flaws where changing a phone parameter grants access to another user's session.
```

---

## Step 3: Define Output Schema
Create `mobile-api-security-skill/schema/finding_schema.json`:
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "MobileApiFinding",
  "type": "object",
  "required": ["title", "endpoint", "severity", "remediation"],
  "properties": {
    "title": { "type": "string" },
    "endpoint": { "type": "string" },
    "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
    "remediation": { "type": "string" }
  }
}
```

---

## Step 4: Register in `agents.json`
If this skill powers an agent, add an entry to [`agents.json`](file:///C:/Users/Alpha/Desktop/Active%20Projects/SnapSec/working/dev-setup/backend/AI-Skills/agents.json):

```json
{
  "name": "Mobile API Security Agent",
  "value": "mobile-api-security-agent",
  "agent_backend": "hermes",
  "description": "Tests mobile backend endpoints and phone authentication workflows.",
  "skill_folder": "mobile-api-security-skill"
}
```

---

## Step 5: Test Locally with `automation-service` Playground
1. In `automation-service/.env`, point `AI_SKILLS_LOCAL_PATH` to your local `AI-Skills` directory.
2. Trigger a test run using the playground API or an agent unit test:
   ```bash
   cd backend/automation-service
   node test/web-app-security.agent.test.js
   ```
3. Inspect generated artifacts in `/data/agentruntime/agents/<orgId>/<runId>/artifacts/` to verify finding schema compliance.

---
[⬅️ Previous: 3. Example Skill Walkthrough](./3-example-skill-walkthrough.md) | [Back to Start: 0. Table of Contents ➡️](./0-table-of-contents.md)

