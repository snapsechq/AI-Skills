# Database & Datastore Exposure Auditing Guide

## Objective
Act as a **Datastore Security Auditor**. Identify publicly exposed or network-accessible databases, in-memory caches, and message queues that lack authentication, utilize default credentials, or bypass network isolation boundaries.

---

## 1. Redis (Port 6379/tcp)

### Testing Procedure:
1. **Unauthenticated Connection Probe**:
   - Use `python3 scripts/service_prober.py redis <target_ip> 6379` or `nc -nv <target_ip> 6379`.
   - Send `INFO\r\n`.
2. **Evaluate Response**:
   - If response is `-NOAUTH Authentication required.` -> Pass (Authentication is properly enforced).
   - If response starts with `+OK` or `# Server` and returns `redis_version` -> **CRITICAL VULNERABILITY**.
3. **Verify Read / Write Boundary Safely**:
   - Send `CONFIG GET requirepass\r\n`.
   - Verify keyspace metrics (`db0:keys=...`). Do NOT delete or tamper with live data.
4. **Finding Classification**:
   - **Title**: Unauthenticated Redis In-Memory Datastore Exposed to Public Network
   - **Severity**: `critical`
   - **CWE**: `CWE-306` (Missing Authentication for Critical Function)
   - **Universal Vuln ID**: `redis-unauthenticated-access:<target_ip>:6379`

---

## 2. MongoDB (Port 27017/tcp)

### Testing Procedure:
1. **Unauthenticated Wire Protocol Handshake**:
   - Execute lightweight client probe:
     `mongosh --host <target_ip> --port 27017 --eval "db.adminCommand('listDatabases')"` or `curl -s http://<target_ip>:27017`
2. **Evaluate Response**:
   - If response prompts for SASL authentication or returns `command listDatabases requires authentication` -> Pass.
   - If response returns database names (`admin`, `config`, `local`, production databases) -> **CRITICAL VULNERABILITY**.
3. **Finding Classification**:
   - **Title**: Unauthenticated MongoDB Database Service Exposed to Public Network
   - **Severity**: `critical`
   - **CWE**: `CWE-306`
   - **Universal Vuln ID**: `mongodb-unauthenticated-access:<target_ip>:27017`

---

## 3. Elasticsearch (Port 9200/tcp)

### Testing Procedure:
1. **HTTP Cluster Probe**:
   - Send GET request to cluster root and indices endpoint:
     `curl -s -i http://<target_ip>:9200/`
     `curl -s -i http://<target_ip>:9200/_cat/indices?v`
2. **Evaluate Response**:
   - If HTTP 401 Unauthorized or 403 Forbidden is returned -> Pass.
   - If HTTP 200 OK is returned with cluster name, version, and indices list -> **CRITICAL/HIGH VULNERABILITY**.
3. **Finding Classification**:
   - **Title**: Unauthenticated Elasticsearch Cluster REST API Exposed to Public Network
   - **Severity**: `critical`
   - **CWE**: `CWE-306`
   - **Universal Vuln ID**: `elasticsearch-unauthenticated-api:<target_ip>:9200`

---

## 4. Memcached (Port 11211/tcp, Port 11211/udp)

### Testing Procedure:
1. **TCP Stats Command**:
   - Send `stats\r\n` to port 11211:
     `echo "stats" | nc -nv -w 3 <target_ip> 11211`
2. **Evaluate Response**:
   - If response returns `STAT pid ... STAT version ... STAT bytes ...` -> **HIGH VULNERABILITY**.
3. **UDP Amplification Check**:
   - Check if UDP listener is responsive (amplification risk).
4. **Finding Classification**:
   - **Title**: Unauthenticated Memcached Caching Service Exposed to Public Network
   - **Severity**: `high`
   - **CWE**: `CWE-306`
   - **Universal Vuln ID**: `memcached-unauthenticated-access:<target_ip>:11211`

---

## 5. Relational Databases (MySQL 3306, PostgreSQL 5432, MSSQL 1433)

### Testing Procedure:
1. **Verify Network Boundary Exposure**:
   - Confirm whether production database port is directly accessible over external/public IP.
   - Publicly accessible relational database ports without network filtering represent high architectural risk.
2. **Non-Destructive Default Credential Testing**:
   - MySQL: test if `root` has blank password (`mysql -h <target_ip> -u root --password=""`).
   - PostgreSQL: test if `postgres` user connects without password (`psql -h <target_ip> -U postgres`).
   - MSSQL: test `sa` account with blank or `sa` password.
3. **Finding Classification**:
   - If default password allows access: **Critical** (`CWE-798` / `CWE-287`).
   - If accessible on public internet with password required: **Medium** (`CWE-16` Security Misconfiguration - Database Listener Exposed to Public Internet).
