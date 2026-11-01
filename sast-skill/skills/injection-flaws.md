# Auditing Injection Flaws (SQLi, NoSQLi, Command Injection)

## 1. SQL Injection (CWE-89)
### Vulnerable Patterns:
- String concatenation or template literals constructing raw SQL queries:
  ```javascript
  const query = `SELECT * FROM accounts WHERE id = '${req.query.id}'`;
  db.query(query);
  ```
- Unescaped `ORDER BY` or table name interpolation (which cannot be parameterized in standard SQL drivers):
  ```python
  cursor.execute(f"SELECT * FROM users ORDER BY {sort_column}")
  ```

### Verification & Remediation:
- **Remediation**: Use parameterized query placeholders (`$1, $2` in Postgres, `?` in MySQL/SQLite) or ORM abstractions.
- **False Positive Elimination**: If `sort_column` is checked against an allowlist array (e.g. `['name', 'date', 'id'].includes(col)`), mark as false positive.

---

## 2. OS Command Injection (CWE-78)
### Vulnerable Patterns:
- Passing user input directly to shell execution functions:
  ```javascript
  exec(`ping -c 4 ${req.body.ip}`);
  ```
  ```python
  subprocess.Popen(f"tar -czf backup.tar.gz {user_path}", shell=True)
  ```

### Verification & Remediation:
- **Remediation**: Avoid `shell=True` or `exec()`. Use `execFile()`, `spawn()` with an argument array without a subshell, or native API bindings.
- **False Positive Elimination**: If arguments are split into an array without shell invocation (e.g. `spawn('ping', ['-c', '4', sanitizedIp])`), shell metacharacters like `&`, `;`, `|` cannot trigger command injection.

