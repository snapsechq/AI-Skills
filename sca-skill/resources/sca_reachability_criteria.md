# SCA Reachability Criteria & Exploitability Rules

When auditing dependency vulnerabilities flagged by Trivy, use the following criteria to determine reachability and eliminate false alarms:

## 1. Reachability Levels
1. **Directly Reachable (Highest Risk)**:
   - The vulnerable package is a direct dependency.
   - The application source code explicitly imports the library and calls the specific function, class, or method identified in the CVE advisory.
2. **Indirectly Reachable (Medium-High Risk)**:
   - The vulnerable package is a transitive dependency used by a top-level library.
   - The application calls methods in the top-level library that trigger the vulnerable transitive code path.
3. **Unreachable (Low / Non-Exploitable)**:
   - The vulnerable package is present in the lockfile, but the application never imports it, or never calls the vulnerable function/option.
   - Example: A CVE in an image-rendering sub-module of a utility library, but the app only uses text manipulation functions.
4. **Development Only (Context Dependent)**:
   - The dependency is listed in `devDependencies` (e.g., webpack, eslint, jest, ts-node).
   - These tools run during development/CI and do not execute in the production runtime container.

## 2. False Positive Disqualifiers
Discard or demote findings if:
1. **No Production Exposure**: The vulnerable library is strictly confined to test suites, mock servers, or local linting.
2. **Vulnerable Feature Disabled**: The vulnerability requires a specific configuration flag that is explicitly disabled in the application.
3. **Compensating Controls**: Input validation or WAF rules prevent the malicious payload from ever reaching the library call.

## 3. Severity Calibration
- **CRITICAL**: Remote Code Execution (RCE) in a public-facing direct dependency with no authentication required (e.g. Log4Shell).
- **HIGH**: SQLi, SSRF, or Path Traversal in direct dependencies reachable from user input.
- **MEDIUM**: Denial of Service (ReDoS) or Information Disclosure requiring complex preconditions.
- **LOW**: Vulnerabilities in build tools or unreachable transitive libraries.

