# agent-browser CLI Quick Reference for AI Agents

`agent-browser` is a fast browser automation CLI purpose-built for AI agents. It runs Chromium in the background, preserves sessions across command invocations, and maps interactive elements to AI-friendly `@refs`.

## 1. Navigation & DOM Inspection
```bash
# Open target page
agent-browser open https://example.com

# Take interactive accessibility snapshot with element refs (@e1, @e2...)
agent-browser snapshot -i

# Take visual screenshot
agent-browser screenshot

# Read agent-friendly text representation of page
agent-browser read
```

## 2. Element Interactions
```bash
# Click an element by reference ID from snapshot
agent-browser click @e1

# Fill text into an input field (clears existing content first)
agent-browser fill @e2 "test@example.com"

# Type into element without clearing
agent-browser type @e2 "additional text"

# Select dropdown option by visible text or value
agent-browser select @e4 "Admin"

# Submit form by pressing Enter
agent-browser press Enter

# Wait for element or timeout (milliseconds)
agent-browser wait @e5
agent-browser wait 2000
```

## 3. Network Traffic & API Discovery
```bash
# View network requests made by the page (XHR, Fetch, REST)
agent-browser network requests

# Clear captured network log
agent-browser network requests --clear

# Filter network requests by URL pattern
agent-browser network requests --filter "/api/"

# Capture full HAR archive for offline inspection
agent-browser network har start ./traffic.har
# ... perform user interactions ...
agent-browser network har stop
```

## 4. Cookies, Storage, & Console
```bash
# Inspect all active cookies
agent-browser cookies get

# Inspect localStorage / sessionStorage
agent-browser storage local
agent-browser storage session

# Inspect browser console errors
agent-browser console
agent-browser errors

# Run custom JavaScript in the active page context
agent-browser eval "document.title"
agent-browser eval "window.__INITIAL_STATE__"
```

## 5. Chaining Commands (Single-Turn Execution)
To perform multiple steps in a single shell command without closing the browser daemon:
```bash
agent-browser open https://example.com/login && \
agent-browser snapshot -i && \
agent-browser fill @e1 "admin" && \
agent-browser fill @e2 "password123" && \
agent-browser click @e3 && \
agent-browser wait 2000 && \
agent-browser snapshot -i
```

