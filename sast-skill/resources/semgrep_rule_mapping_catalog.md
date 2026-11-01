# Semgrep Rule Mapping Catalog

This reference maps common Semgrep rule patterns to corresponding CWEs, risk profiles, and verification guidance.

| Semgrep Rule Prefix / Pattern | CWE | Typical Severity | Verification Steps |
|---|---|---|---|
| `*sqli*` / `*sql-injection*` | CWE-89 | Critical / High | Trace user parameters into query builder or raw string. Check if `$1`, `?`, or parameterized array is used. |
| `*rce*` / `*command-injection*` | CWE-78 | Critical | Inspect `exec()`, `spawn()`, `subprocess.Popen()`, `os.system()`. Check if `shell: true` is passed with user variables. |
| `*ssrf*` | CWE-918 | High | Inspect HTTP client calls (`axios`, `fetch`, `requests.get`). Check for destination IP/URL validation and private range blocks. |
| `*xss*` | CWE-79 | High / Medium | Inspect HTML responses, `dangerouslySetInnerHTML`, template renders. Verify if auto-escaping is bypassed. |
| `*path-traversal*` / `*tainted-path*` | CWE-22 | High | Inspect `fs.readFile()`, `open()`, `send_file()`. Check if `path.resolve()` with prefix check is implemented. |
| `*hardcoded-secret*` / `*jwt*` | CWE-798 | Critical / High | Verify entropy and ensure secret is not a dummy/mock value used for local unit tests. |
| `*deserialization*` / `*pickle*` | CWE-502 | Critical | Inspect `pickle.loads()`, `yaml.load()` without SafeLoader, `JSON.parse` reviver abuse, or Java ObjectInputStream. |

