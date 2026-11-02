# Auditing Container Base Images & OS Packages

## 1. Key Manifests & Targets
- `Dockerfile` / `Containerfile`: Base image instructions (`FROM node:18-alpine`, `FROM python:3.10-slim`, `FROM ubuntu:22.04`).
- Multi-stage builds: `FROM ... AS builder` vs runtime `FROM ... AS runner`.
- OS package managers: `apt-get`, `apk`, `yum`, `dnf` installing packages inside the container image.

## 2. Common Container OS Vulnerabilities
- **System Libraries (CWE-119, CWE-787)**: Memory corruption or buffer overflows in `glibc`, `openssl`, `libxml2`, `curl`, `busybox`.
- **Privilege Escalation (CWE-269)**: SUID/SGID binaries or kernel vulnerabilities if container runs with elevated capabilities or without `--user`.
- **Network / Transport Exploits (CWE-319, CWE-295)**: Outdated TLS/SSL certificates or missing certificate validation in base utilities.

## 3. Reachability & Impact Triage
- **Multi-Stage Build Filtering**:
  - Distinguish between builder stages and final deployable stages.
  - If a vulnerability exists in an OS package installed exclusively in a builder stage (e.g. `gcc`, `make`, build headers) that is discarded before the final production image, the exploitability in runtime is eliminated or mitigated.
- **Service Exposure & Network Attack Surface**:
  - Check whether the affected utility or library is exposed to external requests or used to process untrusted data (e.g. `curl` executed against user-supplied URLs vs internal startup scripts).
- **Remediation**:
  - Recommend updating the base image tag to a patched minor/patch version (e.g., `FROM node:18.20.4-alpine3.20` or using minimal distroless / scratch images).

