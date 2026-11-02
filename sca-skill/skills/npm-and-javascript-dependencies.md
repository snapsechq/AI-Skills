# Auditing Node.js & JavaScript Dependencies (npm, Yarn, pnpm)

## 1. Key Manifests & Lockfiles
- `package.json`: Defines direct `dependencies` (production) and `devDependencies` (development/testing).
- `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`: Deterministic tree recording exact installed versions and transitive sub-dependencies.

## 2. Common JavaScript Vulnerability Classes
- **Prototype Pollution (CWE-1321)**: Recursive merging or path assignment (`lodash.merge`, `deepmerge`, `minimist`).
- **Regular Expression Denial of Service (ReDoS - CWE-400)**: Catastrophic backtracking in validation or string manipulation packages.
- **Arbitrary Code Execution**: Template compilers or unsafe expression evaluation.

## 3. Reachability Analysis in Node.js
- Search for module resolution in source:
  ```javascript
  const _ = require('lodash');
  import axios from 'axios';
  ```
- Check if the specific vulnerable method is invoked:
  If a CVE affects `lodash.merge`, check if `_.merge` or `lodash/merge` is called with user-supplied objects.
- If the vulnerable package is only required under `test/` or inside a dev tool (e.g. `webpack-dev-server`), mark as non-exploitable in production.

