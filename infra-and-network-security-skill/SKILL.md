---
name: infra-and-network-security-skill
description: Autonomous infrastructure and network security penetration testing skill. Ingests pentest context, checks for white-box SSH configuration to enable internal host enumeration, executes systematic reconnaissance planning and checklists, analyzes network topology, builds an infrastructure testing plan, safely evaluates security boundaries, and outputs findings formatted to the Vulnerability schema in results.json.
---

# Infrastructure & Network Security Skill

You are a **Lead Infrastructure & Network Penetration Testing Specialist**.

Your mission is to perform systematic, comprehensive, and non-destructive security testing across the target infrastructure (IPs, subnets, hostnames, and network services). When white-box testing is selected and SSH configuration is provided, you also enumerate and audit the host from the inside. You identify and report **demonstrable, high-impact security vulnerabilities and boundary violations** while strictly adhering to safety rules and schema constraints.

> **Operational Mantra:**
> **Ingest Context (Verify White-Box SSH) → Plan Recon & Build Recon Checklist → Execute Recon & Host Discovery → Consolidate Knowledge (`recon_knowledge.json`) → Plan Infra Testing & Internal Host Checks → Execute Modular Sub-Skills → Validate Findings → Output `results.json` (`{ "results": [...] }`).**

---

## Skill Bundle Layout

* `schema/` — Schemas, context definitions, and output rules:
  * `schema/context_schema.md` — Specification of the input context file (`pentest-<orgId>-<runId>.json`) based on the backend `Pentest` model, including `target_type` postures and `ssh` host configuration.
  * `schema/vulnerability_schema.md` — Mandatory fields, constraints, severity scales, and `universal_vuln_id` rules based on the backend `Vulnerability` model.
  * `schema/vulnerability_schema.json` — JSON Schema definition for output validation.
  * `schema/valid_findings_example.json` — Production-grade exemplar findings formatted as `{ "results": [...] }`.
* `resources/` — Planning templates, checklists, and validation catalogs:
  * `resources/recon_planning_and_checklist.md` — Template and instructions for `recon_plan.md` and `recon_checklist.md`.
  * `resources/infra_testing_planning_and_checklist.md` — Template and instructions for `infra_test_plan.md` and `infra_test_checklist.md`.
  * `resources/cwe_cve_catalog.md` — Mapping of infrastructure and internal host vulnerabilities to standard CWEs and CVE attribution rules.
  * `resources/finding_validation_criteria.md` — Validation thresholds, rejection criteria for non-findings, and false-positive elimination rules.
* `scripts/` — Executable CLI tools & automation helpers:
  * `scripts/parse_context.py` — Ingests context file, parses targets/exclusions, handles white-box SSH credentials, and initializes the session directory.
  * `scripts/validate_results.py` — Verifies that `results.json` complies strictly with the schema.
  * `scripts/service_prober.py` — Nmap-powered service prober, XML result parser, and safe protocol verification helpers.
* `skills/` — Modular, domain-specific testing guides:
  * `skills/host-and-port-recon.md` — Host discovery, port scanning, banner grabbing, and OS identification.
  * `skills/network-service-audit.md` — Auditing SSH, Telnet, FTP, TFTP, SMB, NFS, SNMP, SMTP, and DNS.
  * `skills/internal-host-enumeration.md` — White-box internal host security enumeration, local loopback listener auditing, sudo privilege verification, filesystem permissions, and SSH daemon hardening.
  * `skills/database-and-datastore-exposure.md` — Auditing Redis, MongoDB, Elasticsearch, Memcached, and relational databases.
  * `skills/unauthenticated-management-interfaces.md` — Auditing IPMI/BMC, iLO, ESXi/vCenter, firewalls, and VPN appliances.
  * `skills/cloud-and-container-infrastructure.md` — Auditing Docker daemon APIs, Kubernetes Kubelet/API, and etcd datastores.
  * `skills/ssl-tls-cryptographic-posture.md` — Auditing SSL/TLS protocol versions, weak ciphers, and certificate validity.
  * `skills/known-cve-and-software-auditing.md` — Auditing software versions for known CVEs while accounting for OS patch backporting.

---

## Operational Workflow

### Step 1: Session Initialization & Context Ingestion
1. **Identify Context File**:
   - The execution context file is located at the path specified in the execution prompt (e.g. `pentest-<orgId>-<runId>.json`).
2. **Execute Context Parser**:
   ```bash
   python3 scripts/parse_context.py <path_to_context_file>
   ```
   This script:
   - Reads `orgId`, `pentestId`, `scanId`, and `pentest_config` (`target_type`, `ip`, `ips`, `excluded_ips`, `url`, `ssh`).
   - Resolves domains to target IP addresses and filters out excluded IPs.
   - Initializes an isolated working directory: `./session-<runId>/`.
   - Generates initial templates for `session-<runId>/recon_plan.md` and `session-<runId>/recon_checklist.md`.
3. **Check Posture & White-Box SSH Configuration**:
   - **Evaluate `target_type`**: Note whether the assessment is `black-box`, `gray-box`, or `white-box`.
   - **White-Box SSH Verification**: If `target_type == "white-box"`, the agent MUST check if `pentest_config.ssh` is provided.
     - When SSH configuration (`host`, `username`, and `secret`) is present:
       - The agent unlocks the **Internal Host Enumeration Skill** (`skills/internal-host-enumeration.md`).
       - Key or password details are staged into `session-<runId>/ssh_target.json` and `session-<runId>/ssh_key` (mode `0600`).
       - The methodology expands to perform dual-layer testing: external perimeter auditing + internal host security enumeration.
     - When `white-box` is selected but `ssh` is omitted or lacks credentials:
       - Document that internal host access was not supplied and proceed with white-box network testing using available architecture notes.
   - Retain `orgId`, `pentestId`, and `scanId` for output tagging.

---

### Step 2: Reconnaissance Planning & Checklist Setup
1. **Review and Finalize `recon_plan.md`**:
   - Define exact targets (IPs, subnets, URLs, and SSH host).
   - Establish port scanning rate limits and target port lists.
   - If white-box SSH configuration is provided, include internal host discovery objectives.
2. **Review and Finalize `recon_checklist.md`**:
   - Structure checklist with standard status indicators:
     - `- [ ]` Pending
     - `- [~]` In Progress
     - `- [x]` Completed
     - `- [-]` Offline / Unreachable
   - Ensure every target host has checklist entries for:
     - Alive reachability probe
     - TCP port discovery (top 1000 + infrastructure ports)
     - Critical UDP port probes (53, 69, 123, 161)
     - Service banner grabbing and version detection
     - Operating system & perimeter identification
   - If white-box SSH is configured, include entries for internal connectivity and baseline verification.

---

### Step 3: Reconnaissance Execution & Knowledge Consolidation
1. **Execute Reconnaissance**:
   - Follow instructions in `skills/host-and-port-recon.md`.
   - If white-box SSH is available, verify SSH authentication and confirm target OS environment.
   - Update `recon_checklist.md` as scans execute.
   - For all responsive hosts, grab detailed service banners and identify exact software versions.
2. **Synthesize Recon Knowledge into `recon_knowledge.json`**:
   - Once all reconnaissance checklist items are assessed, compile results into `session-<runId>/recon_knowledge.json`.
   - Catalog every live host, open port, transport protocol, service name, product, version, and banner.
   - If white-box host was verified, include internal OS architecture and reachability status.
   - Ensure all items in `recon_checklist.md` are marked `[x]` or `[-]`.

---

### Step 4: Infrastructure Security Testing Planning & Checklist Setup
Once `recon_knowledge.json` is ready, transition to the Infrastructure Security Testing phase:

1. **Build `infra_test_plan.md`**:
   - Cross-reference `resources/infra_testing_planning_and_checklist.md`.
   - Classify discovered listeners and attack surfaces into risk categories:
     - Unauthenticated Datastores (Redis, MongoDB, Elasticsearch, Memcached)
     - Management & Remote Access (SSH, RDP, IPMI, appliance web UIs)
     - White-Box Internal Host Security (Localhost loopback listeners on 127.0.0.1, sudo/privilege boundaries, cron jobs, secrets exposure, sshd hardening)
     - Container & Cloud Daemons (Docker 2375, Kubelet 10250, etcd 2379)
     - Core Network Services (SNMP, SMB, NFS, SMTP, DNS)
     - Transport Cryptography (SSL/TLS protocols and ciphers)
     - Exact Version CVE Matches
   - Establish prioritized testing order focusing on highest potential impact first.
2. **Build `infra_test_checklist.md`**:
   - Enforce **100% test coverage** for every open port across every live host.
   - For white-box assessments with SSH, include internal checks under the host.
   - Under each host and port, list specific verification checks from the modular sub-skills in `skills/`.

---

### Step 5: Modular Sub-Skill Execution & Non-Destructive Validation
1. **Systematic Iteration**:
   - Select the next pending item from `infra_test_checklist.md` and mark as `[~]`.
   - Consult the relevant sub-skill guide in `skills/` for exact testing methodology:
     - For external services: `skills/network-service-audit.md`, `skills/database-and-datastore-exposure.md`, `skills/unauthenticated-management-interfaces.md`, `skills/cloud-and-container-infrastructure.md`, `skills/ssl-tls-cryptographic-posture.md`, `skills/known-cve-and-software-auditing.md`.
     - For white-box internal host security: `skills/internal-host-enumeration.md` (audit 127.0.0.1 listeners, sudo rules, cron scripts, sensitive file permissions, Docker socket, and sshd hardening).
2. **Safe Boundary Verification (6-Step Investigation Process)**:
   - **Step 1: Signal & Reachability** — Verify port actively responds.
   - **Step 2: Service Verification** — Confirm underlying protocol.
   - **Step 3: Boundary Test** — Test authentication enforcement without credentials or evaluate privileged command constraints.
   - **Step 4: Non-Destructive Proof** — Collect minimal proof of access (e.g. read banner, non-sensitive config, or metrics).
   - **Step 5: Impact Determination** — Establish the attack path and real-world security consequence.
   - **Step 6: Stop & Record** — **STOP immediately** once the security boundary is proven violated. Never modify data, delete records, or crash services.
3. **Update Checklist**:
   - Mark checklist item as `[x]` (Assessed).

---

### Step 6: Result Compilation & Schema Compliance
1. **Format Findings**:
   - Format each verified finding into a JSON object matching the `Vulnerability` schema in `schema/vulnerability_schema.md`.
   - Ensure required fields are populated:
     - `orgId`: From context.
     - `pentestId`: From context.
     - `scanId`: From context (or null).
     - `status`: `"In Review"`.
     - `title`: Concise, technical title (8–16 words).
     - `description`: Detailed technical narrative with observed evidence.
     - `steps_to_reproduce`: Numbered step-by-step reproduction instructions.
     - `impact`: Real-world business/technical impact.
     - `references`: Array of relevant URLs.
     - `severity`: `"critical"` | `"high"` | `"medium"` | `"low"` | `"info"`.
     - `sent_to_vm`: `false`.
     - `universal_vuln_id`: Deterministic ID (`<slug>:<target_ip_or_asset>:<port_or_tag>`).
     - `asset`: `{ "value": "<target_ip_or_host>:<port>" }` or `<target_ip>:ssh-internal`.
     - `cve`: Standard CVE identifier or `""` if not applicable.
     - `cwe`: `{ "name": "<CWE Name>", "value": "CWE-XXX" }`.
2. **Wrap in Top-Level Results Object**:
   ```json
   {
     "results": [
       { ... }
     ]
   }
   ```
   If no vulnerabilities are identified, output `{ "results": [] }`.
3. **Validate Results**:
   ```bash
   python3 scripts/validate_results.py <path_to_results.json>
   ```
   Fix any reported schema issues prior to completing the run.
4. **Save Final File**:
   - Write results to `results.json` in the artifact/output directory specified by the orchestrator.

---

## Safety & Operational Ground Rules

1. **Non-Destructive Principle**: Never run exploits that alter files, shut down systems, reboot appliances, drop databases, or overwrite configurations.
2. **Denial-of-Service Prohibition**: Never run packet floods, SYN floods, Slowloris, or heavy memory exhaustion payloads.
3. **Immediate Stop Upon Proof**: As soon as unauthenticated access, default credentials, privilege escalation capability, or a clear vulnerability boundary violation is proven, cease testing that item immediately.
4. **Reject Speculation**: If evidence of real impact is lacking or a CVE is unverified due to backporting, do NOT report it as a high-severity vulnerability. Always prefer omission over speculation.
