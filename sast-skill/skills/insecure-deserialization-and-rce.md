# Auditing Insecure Deserialization (CWE-502) and Code Execution (CWE-94)

## 1. Unsafe Deserialization
### Vulnerable Patterns:
- Python: `pickle.loads(user_data)` on untrusted data.
- Python PyYAML: `yaml.load(data)` without specifying `Loader=yaml.SafeLoader`.
- Node.js: `node-serialize` or `eval()` based deserialization.
- Java: `ObjectInputStream.readObject()` without object filtering.

## 2. Dynamic Code Evaluation
### Vulnerable Patterns:
- `eval(req.body.expression)`
- `new Function(req.body.code)()`
- `vm.runInContext()` without strict sandbox escapes mitigation.

## 3. Verification & Remediation:
- **Remediation**: Use safe, standard data formats such as JSON or Protocol Buffers. Never deserialize arbitrary binary objects from untrusted sources.
- **False Positive Elimination**: If YAML is parsed with `yaml.safe_load()`, discard as false positive.

