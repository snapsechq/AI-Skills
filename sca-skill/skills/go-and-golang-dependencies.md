# Auditing Go Dependencies (go.mod, go.sum)

## 1. Key Manifests & Dependency Management
- `go.mod`: Declares the module path, minimum Go language version, and direct/indirect module requirements (`require (...)`).
- `go.sum`: Cryptographic checksums of specific module versions. Note that `go.sum` contains both direct and transitive module checksums, including past versions.
- Vendor directory (`vendor/`): If vendoring is used (`go mod vendor`), inspect actual source files bundled within the repository.

## 2. Common Go Vulnerability Classes
- **Path Traversal & Zip Slip (CWE-22)**: Archive extraction packages (`archive/tar`, `mholt/archiver`, `xi2/xz`) lacking path sanitization.
- **Server-Side Request Forgery / HTTP Smuggling (CWE-918, CWE-444)**: Malformed headers or redirects in HTTP clients or reverse proxies.
- **Denial of Service (CWE-400)**: Unbounded memory allocation or CPU consumption in parsers (XML, JSON, YAML, JWT).
- **Arbitrary Code Execution / Command Injection (CWE-78)**: Wrappers around system binaries (e.g. `os/exec` wrappers, Git CLI wrappers).

## 3. Reachability Analysis in Go
- **Package Import Verification**:
  Search for import statements across the `.go` source files:
  ```go
  import (
      "github.com/gin-gonic/gin"
      "github.com/golang-jwt/jwt/v4"
  )
  ```
- **Call-Site & Function Analysis**:
  - Determine whether the vulnerable exported function or method is invoked.
  - For example, if a vulnerability affects `jwt.ParseWithClaims` with unvalidated key algorithms, check if user-controlled tokens reach this function without `jwt.WithValidMethods`.
- **Indirect Dependencies (`// indirect`)**:
  - If marked `// indirect` in `go.mod`, trace whether direct dependencies import and call the affected module.
- **Test-Only Dependencies**:
  - Check if the package is only imported in `*_test.go` files or `tools.go` build tags (`//go:build tools`). If so, flag as non-reachable in production runtime.

