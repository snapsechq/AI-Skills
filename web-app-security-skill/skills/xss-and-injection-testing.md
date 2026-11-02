# Cross-Site Scripting (XSS) & Input Validation Testing

This guide details testing web applications for reflected and stored XSS using `agent-browser`.

## 1. Input Field Discovery
1. Run `agent-browser snapshot -i` on each page with forms (e.g. search bars, comment fields, profile update forms, contact forms).
2. Note input field `@refs` (e.g. `@e3`, `@e7`).

## 2. Testing for Reflection & HTML Context
1. Submit unique, traceable probe strings (e.g. `probe123<testTag>`):
   ```bash
   agent-browser fill @e3 "probe123<testTag>" && agent-browser press Enter
   agent-browser wait 1500
   ```
2. Verify DOM Reflection:
   ```bash
   agent-browser eval "document.body.innerHTML.includes('probe123<testTag>')"
   ```
   * If the tags are escaped as `&lt;testTag&gt;`, contextual entity encoding is active (Safe).
   * If literal `<testTag>` appears in raw HTML, the input is unescaped.

## 3. False-Positive Elimination
* **Verify Context**: If the reflection is inside an existing text node with encoding, it is not exploitable.
* **Inspect CSP**: Check if a strong `Content-Security-Policy` with nonces or `script-src 'self'` prevents inline execution. If CSP completely blocks inline scripts, lower severity or document compensating controls.

