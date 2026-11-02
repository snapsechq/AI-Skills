# Auditing Java & JVM Dependencies (Maven, Gradle)

## 1. Key Manifests
- `pom.xml`: Maven Project Object Model detailing `groupId`, `artifactId`, `version`, and `scope` (`compile`, `test`, `provided`).
- `build.gradle` / `build.gradle.kts`: Gradle build configuration.

## 2. Common Java Vulnerability Classes
- **Remote Code Execution via JNDI / Deserialization**: Log4j (Log4Shell), Spring Framework (Spring4Shell), Jackson Databind gadget chains.
- **Path Traversal / Zip Slip**: Commons-compress, archive extraction.
- **XML External Entity (XXE)**: DOM / SAX parsers without `disallow-doctype-decl`.

## 3. Reachability Verification
- Verify scope: Dependencies with `<scope>test</scope>` are test-only.
- Verify classloader reachability: Confirm the vulnerable Java class is referenced in compiled classes or Spring configuration beans.

