# Auditing Python & Pip Dependencies (pip, Poetry, Pipenv)

## 1. Key Manifests
- `requirements.txt`: Standard list of packages and version pins.
- `Pipfile` / `Pipfile.lock`: Pipenv environment lockfiles.
- `pyproject.toml` / `poetry.lock`: Modern Poetry dependency specifications.

## 2. Common Python Vulnerability Classes
- **Insecure Deserialization**: PyYAML (`yaml.load`), Pickle wrappers, or XML parsers (`lxml`, `defusedxml`).
- **Command Injection / Path Traversal**: Archive extraction (`tarfile`, `zipfile`), subprocess helpers.
- **SSRF**: Unvalidated HTTP clients (`requests`, `urllib3`, `aiohttp`).

## 3. Reachability Verification
- Check if package is imported in Python files (`import requests`, `from flask import ...`).
- Trace whether untrusted user parameters reach the vulnerable function or if default safe settings are active.

