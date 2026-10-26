# Cloud & Container Infrastructure Auditing Guide

## Objective
Act as a **Cloud & Container Infrastructure Auditor**. Detect exposed orchestration endpoints, container daemon APIs, cluster datastores, and cloud metadata access vectors that bypass network isolation and security boundaries.

---

## 1. Docker Daemon API (Port 2375/tcp, Port 2376/tcp)

### Testing Procedure:
1. **Unauthenticated REST API Probe**:
   - Query Docker version and container list:
     `curl -s http://<target_ip>:2375/version`
     `curl -s http://<target_ip>:2375/containers/json`
2. **Evaluate Response**:
   - If response returns `ApiVersion`, `DockerRootDir`, and container IDs -> **CRITICAL VULNERABILITY**.
   - An attacker can create a container mounting host `/` to gain root access on the underlying node.
3. **Finding Classification**:
   - **Title**: Unauthenticated Docker Daemon Engine API Exposed on Port 2375
   - **Severity**: `critical`
   - **CWE**: `CWE-306`
   - **Universal Vuln ID**: `docker-daemon-unauth-api:<target_ip>:2375`

---

## 2. Kubernetes Kubelet API (Port 10250/tcp)

### Testing Procedure:
1. **Anonymous Mode Probe**:
   - Query `/pods` over HTTPS without client certificates:
     `curl -k -s https://<target_ip>:10250/pods`
   - Alternatively: `python3 scripts/service_prober.py kubelet <target_ip> 10250`
2. **Evaluate Response**:
   - If HTTP 401 Unauthorized or 403 Forbidden is returned -> Pass (Kubelet requires webhook authentication).
   - If HTTP 200 OK is returned with JSON containing pod items, namespaces, and volumes -> **CRITICAL VULNERABILITY**.
3. **Finding Classification**:
   - **Title**: Kubernetes Kubelet Daemon Permits Unauthenticated Anonymous Requests on Port 10250
   - **Severity**: `critical`
   - **CWE**: `CWE-287` (Improper Authentication)
   - **Universal Vuln ID**: `k8s-kubelet-anonymous-access:<target_ip>:10250`

---

## 3. Kubernetes API Server (Port 6443/tcp, Port 8080/tcp)

### Testing Procedure:
1. **Public API Probe**:
   - Query root API endpoint:
     `curl -k -s https://<target_ip>:6443/api/v1/namespaces`
2. **Evaluate Response**:
   - If response returns `Unauthorized` or `Anonymous users cannot list resource namespaces` -> Pass.
   - If response lists active cluster namespaces and service accounts -> **CRITICAL VULNERABILITY**.

---

## 4. etcd Key-Value Store (Port 2379/tcp)

### Testing Procedure:
1. **Unauthenticated etcd Probe**:
   - Query cluster members or key listing via HTTP v2/v3:
     `curl -s http://<target_ip>:2379/v2/keys/` or `curl -s http://<target_ip>:2379/health`
2. **Evaluate Response**:
   - If response returns `{"health": "true"}` and permits reading keys -> **CRITICAL VULNERABILITY**.
   - etcd contains plain-text Kubernetes secrets, service tokens, and configuration data.
3. **Finding Classification**:
   - **Title**: Unauthenticated etcd Distributed Datastore API Exposed on Port 2379
   - **Severity**: `critical`
   - **CWE**: `CWE-306`
   - **Universal Vuln ID**: `etcd-unauthenticated-access:<target_ip>:2379`
