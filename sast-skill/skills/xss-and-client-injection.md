# Auditing Cross-Site Scripting (XSS - CWE-79) and Client Injections

## 1. Reflected & Stored XSS
### Vulnerable Patterns:
- Interpolating unescaped user input into HTML response bodies or SSR views:
  ```javascript
  res.send(`<h1>Welcome, ${req.query.name}</h1>`);
  ```
- React / Vue unsafe HTML rendering:
  ```javascript
  <div dangerouslySetInnerHTML={{ __html: userBio }} />
  ```

## 2. Server-Side Template Injection (SSTI)
### Vulnerable Patterns:
- Passing user input directly into template compiler engines:
  ```python
  jinja2.Template(f"Hello {user_input}").render()
  ```

## 3. Verification & Remediation:
- **Remediation**: Use context-aware output encoding, sanitize HTML using vetted libraries like DOMPurify, and enforce a strict Content Security Policy (CSP).
- **False Positive Elimination**: In modern frontend frameworks (React, Angular), variables inside JSX (e.g. `<div>{name}</div>`) are automatically HTML-escaped. Discard as false positive unless `dangerouslySetInnerHTML` is explicitly used.

