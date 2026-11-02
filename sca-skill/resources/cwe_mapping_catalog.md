# Common Weakness Enumeration (CWE) Mapping Catalog for SCA

| CWE ID | Name | Common In Packages |
|---|---|---|
| **CWE-1321**| Improperly Controlled Modification of Dynamically-Determined Object Attributes ('Prototype Pollution') | JavaScript (`lodash`, `minimist`, `merge-deep`) |
| **CWE-94**  | Improper Control of Generation of Code ('Code Injection') | Template engines, dynamic compilers |
| **CWE-502** | Deserialization of Untrusted Data | Serialization libraries, Java ObjectInputStream, Python pickle |
| **CWE-400** | Uncontrolled Resource Consumption ('ReDoS') | Regex-based validation libraries, parsers |
| **CWE-918** | Server-Side Request Forgery (SSRF) | HTTP client libraries (`axios`, `request`, `urllib`) |
| **CWE-22**  | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Archive extractors (`tar`, `unzip`), static file servers |
| **CWE-287** | Improper Authentication | JWT libraries, session middleware |

