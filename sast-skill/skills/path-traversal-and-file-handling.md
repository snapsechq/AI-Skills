# Auditing Path Traversal (CWE-22) and Insecure File Operations

## 1. Path Traversal
### Vulnerable Patterns:
- Concatenating user input into filesystem operations:
  ```javascript
  const filePath = path.join("/var/data/uploads", req.query.filename);
  fs.createReadStream(filePath).pipe(res);
  ```
  If `filename` is `../../../../etc/passwd`, it traverses out of `/var/data/uploads`.

## 2. Unrestricted File Upload
### Vulnerable Patterns:
- Saving user uploads directly with the original client-provided filename:
  ```javascript
  file.mv(`/public/uploads/${file.name}`);
  ```
  Allows overwriting critical application files or uploading executable scripts (`.php`, `.jsp`, `.phtml`).

## 3. Verification & Remediation:
- **Remediation**:
  - Always resolve the absolute path and verify that it starts with the intended base directory:
    ```javascript
    const safePath = path.resolve(baseDir, filename);
    if (!safePath.startsWith(baseDir + path.sep)) {
        throw new Error("Access denied");
    }
    ```
  - Generate random UUIDs for uploaded filenames rather than using client-supplied names.
- **False Positive Elimination**:
  - If `path.basename()` is applied or a strict whitelist regex (e.g. `/^[a-zA-Z0-9_-]+\.png$/`) is enforced, directory traversal sequences (`../`) are neutralized.

