import sys, os, json, argparse, ipaddress, socket, stat

def parse_args():
    parser = argparse.ArgumentParser(description="Parse pentest context file and prepare session workspace.")
    parser.add_argument("context_file", help="Path to the pentest context JSON file.")
    parser.add_argument("--session-dir", default=None, help="Optional custom session directory path.")
    return parser.parse_args()

def resolve_target(url_or_host):
    try:
        clean = url_or_host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ip = socket.gethostbyname(clean)
        return clean, ip
    except Exception:
        return url_or_host, None

def to_list(val):
    if not val:
        return []
    if isinstance(val, list):
        return [str(v).strip() for v in val if str(v).strip()]
    if isinstance(val, str):
        return [v.strip() for v in val.split(",") if v.strip()]
    return []

def main():
    args = parse_args()
    if not os.path.exists(args.context_file):
        print("[!] Error: Context file does not exist: " + args.context_file)
        sys.exit(1)

    try:
        with open(args.context_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print("[!] Error reading JSON: " + str(e))
        sys.exit(1)

    org_id = data.get("orgId")
    pentest_id = data.get("pentestId", "")
    scan_id = data.get("scanId", "")
    name = data.get("name", "Infrastructure Assessment")
    pentest_config = data.get("pentest_config", {})
    target_type = (pentest_config.get("target_type") or "black-box").strip().lower()
    target_ip = pentest_config.get("ip", "").strip()
    target_ips = to_list(pentest_config.get("ips"))
    target_url = pentest_config.get("url", "").strip()
    notes = pentest_config.get("notes", "").strip()

    excluded_raw = to_list(pentest_config.get("excluded_ips") or pentest_config.get("excluded"))
    excluded_ips = set(excluded_raw)

    ssh_raw = pentest_config.get("ssh") or {}
    ssh_host = str(ssh_raw.get("host") or "").strip()
    try:
        ssh_port = int(ssh_raw.get("port") or 22)
    except (ValueError, TypeError):
        ssh_port = 22
    ssh_user = str(ssh_raw.get("username") or "").strip()
    ssh_auth = str(ssh_raw.get("auth_method") or "key").strip().lower()
    if ssh_auth not in ["key", "password"]:
        ssh_auth = "key"
    ssh_secret = str(ssh_raw.get("secret") or "")
    ssh_privilege = str(ssh_raw.get("privilege") or "standard").strip().lower()
    if ssh_privilege not in ["standard", "sudo", "root"]:
        ssh_privilege = "standard"

    has_ssh_config = bool(ssh_host and ssh_user and ssh_secret)

    run_id = scan_id or pentest_id or "session-default"
    session_dir = args.session_dir or ("./session-" + run_id)
    os.makedirs(session_dir, exist_ok=True)

    print("[*] Initialized session directory: " + session_dir)
    print("[*] Organization ID: " + str(org_id))
    print("[*] Pentest ID: " + str(pentest_id))
    print("[*] Scan ID: " + str(scan_id))
    print("[*] Assessment Posture: " + target_type)
    print("[*] Target IP: " + (target_ip or "None specified"))
    if target_ips:
        print("[*] Target IPs list: " + ", ".join(target_ips))
    if excluded_ips:
        print("[*] Excluded IPs: " + ", ".join(excluded_ips))
    print("[*] Target URL: " + (target_url or "None specified"))

    targets = []
    raw_ip_sources = []
    if target_ip:
        raw_ip_sources.append(target_ip)
    for tip in target_ips:
        if tip not in raw_ip_sources:
            raw_ip_sources.append(tip)

    for item in raw_ip_sources:
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
                for ip in net.hosts():
                    ip_str = str(ip)
                    if ip_str not in targets and ip_str not in excluded_ips:
                        targets.append(ip_str)
            except Exception:
                if item not in targets and item not in excluded_ips:
                    targets.append(item)
        else:
            for ip in item.split(","):
                ip_clean = ip.strip()
                if ip_clean and ip_clean not in targets and ip_clean not in excluded_ips:
                    targets.append(ip_clean)

    resolved_host = None
    if target_url:
        host, resolved_ip = resolve_target(target_url)
        resolved_host = host
        if resolved_ip and resolved_ip not in targets and resolved_ip not in excluded_ips:
            targets.append(resolved_ip)

    ssh_key_path = None
    if target_type == "white-box":
        if has_ssh_config:
            print("[+] White-Box Testing detected with SSH host configuration:")
            print("    - Host: " + ssh_host + ":" + str(ssh_port))
            print("    - Username: " + ssh_user)
            print("    - Auth Method: " + ssh_auth)
            print("    - Privilege Level: " + ssh_privilege)
            print("    - Internal Host Enumeration: ENABLED")

            if ssh_host not in targets and ssh_host not in excluded_ips:
                targets.append(ssh_host)

            if ssh_auth == "key" and ssh_secret:
                ssh_key_path = os.path.join(session_dir, "ssh_key")
                try:
                    formatted_key = ssh_secret.replace("\\n", chr(10)).strip() + chr(10)
                    with open(ssh_key_path, "w", encoding="utf-8") as kf:
                        kf.write(formatted_key)
                    os.chmod(ssh_key_path, stat.S_IRUSR | stat.S_IWUSR)
                    print("[+] Written SSH private key to: " + ssh_key_path + " (mode 0600)")
                except Exception as e:
                    print("[!] Warning: Could not write SSH key file: " + str(e))

            ssh_target_info = {
                "host": ssh_host,
                "port": ssh_port,
                "username": ssh_user,
                "auth_method": ssh_auth,
                "privilege": ssh_privilege,
                "key_file": ssh_key_path if ssh_auth == "key" else None,
                "has_password": bool(ssh_auth == "password" and ssh_secret)
            }
            ssh_info_path = os.path.join(session_dir, "ssh_target.json")
            with open(ssh_info_path, "w", encoding="utf-8") as sf:
                json.dump(ssh_target_info, sf, indent=2)
            print("[+] Saved SSH target details to: " + ssh_info_path)
        else:
            print("[*] White-Box Testing selected; no SSH host credentials provided in pentest_config.ssh.")

    plan_path = os.path.join(session_dir, "recon_plan.md")
    targets_str = ", ".join(targets) if targets else (target_url or "Unspecified")
    exclusions_str = ", ".join(excluded_ips) if excluded_ips else "None"

    with open(plan_path, "w", encoding="utf-8") as pf:
        pf.write("# Reconnaissance Plan\n")
        pf.write("**Target Assessment**: " + str(name) + "\n")
        pf.write("**Target Posture**: " + str(target_type) + "\n")
        pf.write("**Scope Targets**: " + targets_str + "\n")
        pf.write("**Target URL**: " + (target_url or "N/A") + "\n")
        pf.write("**Exclusions**: " + exclusions_str + "\n")
        if notes:
            pf.write("**Scope Notes**: " + notes + "\n")

        pf.write("\n## Reconnaissance Objectives\n")
        pf.write("1. Perform host discovery and confirm live network reachability across external scope.\n")
        pf.write("2. Probe top TCP ports (top 1000 + critical infrastructure ports) and critical UDP services (53, 69, 123, 161).\n")
        pf.write("3. Grab service banners and identify exact daemon versions.\n")
        pf.write("4. Detect operating system, perimeter controls, and firewall behavior.\n")
        pf.write("5. Record all network reconnaissance findings into `recon_knowledge.json`.\n")

        if target_type == "white-box" and has_ssh_config:
            pf.write("\n## White-Box Internal Host Security Objectives (Host: `" + ssh_host + ":" + str(ssh_port) + "`)\n")
            pf.write("SSH credentials are provided for internal host security auditing (`username: " + ssh_user + "`, `privilege: " + ssh_privilege + "`).\n")
            pf.write("1. Verify SSH connectivity and validate declared access privilege tier.\n")
            pf.write("2. Enumerate internal/loopback network listeners (`127.0.0.1` / local sockets) using `skills/internal-host-enumeration.md`.\n")
            pf.write("3. Check for unauthenticated internal services (local Redis, local databases, internal HTTP APIs).\n")
            pf.write("4. Audit local privilege escalation boundaries, `sudo -l` permissions, and SUID/SGID binaries.\n")
            pf.write("5. Inspect running services, background daemons, and scheduled cron jobs.\n")
            pf.write("6. Audit filesystem permissions on sensitive configurations (`/etc/shadow`, credentials in configuration/history).\n")
            pf.write("7. Review SSH daemon configuration (`/etc/ssh/sshd_config`) from the inside for hardening posture.\n")
    print("[+] Created " + plan_path)

    checklist_path = os.path.join(session_dir, "recon_checklist.md")
    with open(checklist_path, "w", encoding="utf-8") as cf:
        cf.write("# Reconnaissance Checklist\n")
        cf.write("Session ID: " + str(run_id) + "\n")
        cf.write("Target Posture: " + str(target_type) + "\n\n")

        cf.write("## 1. Scope & DNS Enumeration\n")
        cf.write("- [ ] Parse target IPs and CIDR blocks (Total Targets: " + str(len(targets)) + ")\n")
        if excluded_ips:
            cf.write("- [ ] Verify exclusions filtered out: " + exclusions_str + "\n")
        cf.write(f"- [ ] Resolve URL '{target_url or 'N/A'}' (Resolved: {resolved_host or 'N/A'})\n")
        cf.write("- [ ] Determine reverse DNS (PTR) records\n\n")

        cf.write("## 2. Host Reachability & Alive Checks\n")
        if targets:
            for t in targets:
                cf.write("- [ ] Host `" + str(t) + "`: ICMP Echo / TCP SYN Ping probe\n")
        else:
            cf.write("- [ ] Verify target host reachability\n")

        cf.write("\n## 3. Port & Service Discovery (Perimeter)\n")
        if targets:
            for t in targets:
                cf.write("### Host: `" + str(t) + "`\n")
                cf.write("- [ ] Top 1000 TCP Port Scan\n")
                cf.write("- [ ] Infrastructure Service Ports (21, 22, 23, 25, 53, 80, 111, 135, 139, 161, 443, 445, 1433, 1521, 2049, 2375, 2376, 2379, 3306, 3389, 5432, 6379, 6443, 8080, 8443, 9200, 10250, 11211, 27017)\n")
                cf.write("- [ ] Critical UDP Ports (53 DNS, 69 TFTP, 123 NTP, 161 SNMP)\n")
                cf.write("- [ ] Service Banner Grabbing & Protocol Handshake\n")
                cf.write("- [ ] OS & Perimeter Device Identification\n")

        if target_type == "white-box" and has_ssh_config:
            cf.write("\n## 4. White-Box Internal Host Enumeration (Host: `" + ssh_host + ":" + str(ssh_port) + "`)\n")
            cf.write("*Reference Guide: `skills/internal-host-enumeration.md`*\n")
            cf.write("- [ ] Verify SSH access using provided credentials (`" + ssh_user + "`, method: `" + ssh_auth + "`)\n")
            cf.write("- [ ] Verify user identity and validate declared privilege tier (`id`, `whoami`, declared: `" + ssh_privilege + "`)\n")
            cf.write("- [ ] Audit sudo permissions and privilege escalation vectors (`sudo -l`)\n")
            cf.write("- [ ] Enumerate internal network listeners (`ss -tulpn` / `netstat -tulpn` on 127.0.0.1)\n")
            cf.write("- [ ] Probe internal-only services without authentication (local Redis, local databases, internal management APIs)\n")
            cf.write("- [ ] Audit running background processes and systemd services (`ps aux`, `systemctl list-units`)\n")
            cf.write("- [ ] Audit scheduled tasks and cron jobs (`/etc/cron*`, `/etc/crontab`, `/var/spool/cron/crontabs`)\n")
            cf.write("- [ ] Audit filesystem permissions on sensitive configurations (`/etc/shadow`, `/etc/sudoers`, world-writable scripts)\n")
            cf.write("- [ ] Inspect SSH daemon configuration (`/etc/ssh/sshd_config` for PermitRootLogin, weak ciphers, password auth)\n")
            cf.write("- [ ] Check container runtime and Docker daemon socket exposure (`/var/run/docker.sock`)\n")
            cf.write("- [ ] Audit OS release, kernel version, and installed packages for critical local CVEs\n")

        cf.write("\n## 5. Knowledge Consolidation\n")
        cf.write("- [ ] Compile open ports, services, banners, and internal host details into `recon_knowledge.json`\n")

    print("[+] Created " + checklist_path)

if __name__ == "__main__":
    main()
