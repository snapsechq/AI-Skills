# Web Application Reconnaissance & Dynamic Discovery

This guide covers discovering the application attack surface using `agent-browser`.

## 1. Initial Access & DOM Rendering
```bash
# Open root application URL
agent-browser open <TARGET_URL>

# Wait for dynamic JS frameworks (React, Vue, Angular) to settle
agent-browser wait 2000

# Inspect the interactive accessibility tree
agent-browser snapshot -i
```

## 2. Dynamic Crawling & Link Traversal
* **Locate Navigation Bars**: Look for links such as `Dashboard`, `Settings`, `Profile`, `Admin`, `Docs`, `Search`.
* **Click Interactive Elements**: Use `agent-browser click @ref` to navigate into nested views.
* **Inspect URL Changes**: As you click, single-page applications will change routes (e.g. `/#/settings` or `/account`).
* **Handle Pagination and Modals**: Click "Next", "View All", or trigger modal dialogues and observe DOM modifications.

## 3. Network Traffic & API Interception
Modern web applications interact heavily with background REST or GraphQL APIs.
```bash
# Review all intercepted HTTP traffic triggered during browser interactions
agent-browser network requests

# Identify API patterns:
# Look for /api/, /v1/, /graphql, /auth/, /user/
```
Record all discovered API endpoints and their HTTP methods (`GET`, `POST`, `PUT`, `DELETE`) in `was_test_checklist.md`.

