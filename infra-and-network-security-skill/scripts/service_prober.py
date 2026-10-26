#!/usr/bin/env python3
"""
Service Prober Helper for Infrastructure & Network Security Skill
Uses Nmap for comprehensive service & banner probing and parses XML results
into clean, structured JSON compatible with recon_knowledge.json.
Also includes specialized non-destructive protocol boundary verification helpers.
"""

import sys
import os
import socket
import ssl
import json
import argparse
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import urllib.request
import urllib.error

# Common infrastructure ports used as default when no ports are specified
DEFAULT_INFRA_PORTS = (
    "21,22,23,25,53,80,88,110,111,123,135,139,143,161,389,443,445,514,636,"
    "873,1080,1433,1521,2049,2375,2376,2379,3306,3389,5000,5432,5900,6379,"
    "6443,8080,8443,8888,9200,10250,11211,27017"
)

# ---------------------------------------------------------------------------
# Nmap XML Parsing Engine
# ---------------------------------------------------------------------------

def parse_xml_node(element):
    """
    Recursively parse an XML element containing nmap script <table> and <elem> tags
    into Python dictionaries and lists.
    """
    tables = element.findall("table")
    elems = element.findall("elem")

    if not tables and not elems:
        return element.text or element.attrib.get("value") or ""

    if tables and any("key" in t.attrib for t in tables):
        result = {}
        for t in tables:
            key = t.attrib.get("key", "unnamed")
            result[key] = parse_xml_node(t)
        for e in elems:
            key = e.attrib.get("key")
            val = e.text or ""
            if key:
                result[key] = val
            else:
                if "items" not in result:
                    result["items"] = []
                result["items"].append(val)
        return result
    elif tables:
        return [parse_xml_node(t) for t in tables]
    elif elems:
        if any("key" in e.attrib for e in elems):
            res = {}
            for e in elems:
                k = e.attrib.get("key")
                v = e.text or ""
                if k:
                    res[k] = v
                else:
                    if "items" not in res:
                        res["items"] = []
                    res["items"].append(v)
            return res
        return [e.text or "" for e in elems]

    return element.text or ""

def parse_script_element(script_elem):
    """Extract output and structured data from an NSE script tag."""
    script_id = script_elem.attrib.get("id", "")
    raw_output = script_elem.attrib.get("output", "")

    parsed_data = {}
    tables = script_elem.findall("table")
    elems = script_elem.findall("elem")
    if tables or elems:
        parsed_data = parse_xml_node(script_elem)

    return {
        "id": script_id,
        "output": raw_output.strip(),
        "data": parsed_data if parsed_data else None
    }

def parse_nmap_xml(xml_content_or_path, open_only=True):
    """
    Parses Nmap XML output into a structured dictionary.
    Supports both raw XML string content and file paths.
    """
    try:
        if os.path.exists(xml_content_or_path):
            tree = ET.parse(xml_content_or_path)
            root = tree.getroot()
        else:
            root = ET.fromstring(xml_content_or_path)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to parse Nmap XML: {e}",
            "hosts": []
        }

    scan_info = {
        "scanner": root.attrib.get("scanner", "nmap"),
        "version": root.attrib.get("version", ""),
        "args": root.attrib.get("args", ""),
        "start_str": root.attrib.get("startstr", ""),
        "hosts": []
    }

    # Summary
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            scan_info["summary"] = finished.attrib.get("summary", "")
            scan_info["elapsed"] = finished.attrib.get("elapsed", "")
            scan_info["exit_status"] = finished.attrib.get("exit", "")

    for host_elem in root.findall("host"):
        # Host Status
        status_elem = host_elem.find("status")
        host_status = status_elem.attrib.get("state", "unknown") if status_elem is not None else "unknown"
        status_reason = status_elem.attrib.get("reason", "") if status_elem is not None else ""

        # Addresses
        ip_addr = ""
        ipv6_addr = ""
        mac_addr = ""
        for addr in host_elem.findall("address"):
            atype = addr.attrib.get("addrtype", "")
            if atype == "ipv4":
                ip_addr = addr.attrib.get("addr", "")
            elif atype == "ipv6":
                ipv6_addr = addr.attrib.get("addr", "")
            elif atype == "mac":
                mac_addr = addr.attrib.get("addr", "")

        # Hostnames
        hostnames = []
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                hostnames.append({
                    "name": hn.attrib.get("name", ""),
                    "type": hn.attrib.get("type", "")
                })

        primary_hostname = hostnames[0]["name"] if hostnames else ""

        # Ports & Services
        ports_list = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                proto = port_elem.attrib.get("protocol", "tcp")
                port_id = int(port_elem.attrib.get("portid", 0))

                state_elem = port_elem.find("state")
                port_state = state_elem.attrib.get("state", "unknown") if state_elem is not None else "unknown"
                state_reason = state_elem.attrib.get("reason", "") if state_elem is not None else ""

                if open_only and port_state != "open":
                    continue

                # Service details
                service_dict = {
                    "name": "",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "ostype": "",
                    "cpes": []
                }

                srv_elem = port_elem.find("service")
                if srv_elem is not None:
                    service_dict["name"] = srv_elem.attrib.get("name", "")
                    service_dict["product"] = srv_elem.attrib.get("product", "")
                    service_dict["version"] = srv_elem.attrib.get("version", "")
                    service_dict["extrainfo"] = srv_elem.attrib.get("extrainfo", "")
                    service_dict["ostype"] = srv_elem.attrib.get("ostype", "")
                    service_dict["tunnel"] = srv_elem.attrib.get("tunnel", "")
                    service_dict["method"] = srv_elem.attrib.get("method", "")
                    service_dict["conf"] = srv_elem.attrib.get("conf", "")

                    for cpe in srv_elem.findall("cpe"):
                        if cpe.text:
                            service_dict["cpes"].append(cpe.text.strip())

                # Scripts
                scripts_dict = {}
                banner_text = ""
                for script_elem in port_elem.findall("script"):
                    script_info = parse_script_element(script_elem)
                    scripts_dict[script_info["id"]] = script_info["output"]
                    if script_info["id"] == "banner":
                        banner_text = script_info["output"]

                # Synthesize banner if not explicitly extracted by banner script
                if not banner_text:
                    parts = []
                    if service_dict["product"]:
                        parts.append(service_dict["product"])
                    if service_dict["version"]:
                        parts.append(service_dict["version"])
                    if service_dict["extrainfo"]:
                        parts.append(f"({service_dict['extrainfo']})")
                    banner_text = " ".join(parts).strip() or service_dict["name"]

                ports_list.append({
                    "port": port_id,
                    "protocol": proto,
                    "state": port_state,
                    "state_reason": state_reason,
                    "service": service_dict,
                    "banner": banner_text,
                    "scripts": scripts_dict
                })

        # OS matches
        os_matches = []
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osm in os_elem.findall("osmatch"):
                os_matches.append({
                    "name": osm.attrib.get("name", ""),
                    "accuracy": osm.attrib.get("accuracy", "")
                })

        detected_os = os_matches[0]["name"] if os_matches else ""

        scan_info["hosts"].append({
            "ip": ip_addr or ipv6_addr,
            "ipv6": ipv6_addr,
            "mac": mac_addr,
            "hostname": primary_hostname,
            "hostnames": hostnames,
            "status": host_status,
            "status_reason": status_reason,
            "os": detected_os,
            "os_matches": os_matches,
            "ports": ports_list
        })

    scan_info["success"] = True
    return scan_info

def format_as_recon_knowledge(parsed_scan, target_str=""):
    """
    Transforms parsed Nmap scan output into the recon_knowledge.json structure
    expected by the Infrastructure & Network Security Skill.
    """
    alive_hosts = [h for h in parsed_scan.get("hosts", []) if h.get("status") == "up"]

    hosts_output = []
    for h in alive_hosts:
        ports_output = []
        for p in h.get("ports", []):
            srv = p.get("service", {})
            ports_output.append({
                "port": p["port"],
                "protocol": p["protocol"],
                "service": srv.get("name", ""),
                "product": srv.get("product", ""),
                "version": srv.get("version", ""),
                "banner": p.get("banner", "")
            })

        hosts_output.append({
            "ip": h.get("ip", ""),
            "hostname": h.get("hostname", ""),
            "status": h.get("status", "up"),
            "os": h.get("os", ""),
            "ports": ports_output
        })

    return {
        "scan_metadata": {
            "target": target_str,
            "scanner": parsed_scan.get("scanner", "nmap"),
            "alive_hosts_count": len(alive_hosts),
            "summary": parsed_scan.get("summary", "")
        },
        "hosts": hosts_output
    }

# ---------------------------------------------------------------------------
# Nmap Execution Wrapper
# ---------------------------------------------------------------------------

def run_nmap_probe(
    target,
    ports=None,
    udp=False,
    version_intensity=5,
    scripts=None,
    timing=4,
    host_timeout="120s",
    max_retries=2,
    open_only=True,
    extra_args=None
):
    """
    Executes Nmap with service probing (-sV) and XML output,
    then automatically parses the XML output into structured data.
    """
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0

    cmd = ["nmap", "-Pn"]

    # Select scan type: unprivileged connect scan for non-root TCP, -sU for UDP
    if udp:
        if not is_root:
            print("[!] Warning: UDP scans require root privileges. Executing may fail or prompt.", file=sys.stderr)
        cmd.append("-sU")
    else:
        cmd.append("-sS" if is_root else "-sT")

    # Service detection
    cmd.extend(["-sV", f"--version-intensity={version_intensity}"])

    # Timing & retries
    cmd.extend([f"-T{timing}", f"--max-retries={max_retries}", f"--host-timeout={host_timeout}"])

    if open_only:
        cmd.append("--open")

    # Ports
    if ports:
        cmd.extend(["-p", str(ports)])
    else:
        cmd.extend(["-p", DEFAULT_INFRA_PORTS])

    # NSE Scripts
    if scripts:
        cmd.extend(["--script", scripts])

    # Extra arguments
    if extra_args:
        if isinstance(extra_args, list):
            cmd.extend(extra_args)
        elif isinstance(extra_args, str):
            cmd.extend(extra_args.split())

    # Direct XML to stdout
    cmd.extend(["-oX", "-"])
    cmd.append(target)

    cmd_str = " ".join(cmd)
    print(f"[*] Executing Nmap probe: {cmd_str}", file=sys.stderr)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0 and not proc.stdout:
            return {
                "success": False,
                "error": f"Nmap exited with code {proc.returncode}: {proc.stderr.strip()}",
                "cmd": cmd_str,
                "hosts": []
            }

        parsed = parse_nmap_xml(proc.stdout, open_only=open_only)
        parsed["command"] = cmd_str
        return parsed

    except FileNotFoundError:
        return {
            "success": False,
            "error": "Nmap binary not found on system PATH. Please ensure nmap is installed.",
            "hosts": []
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Exception while executing nmap: {e}",
            "hosts": []
        }

# ---------------------------------------------------------------------------
# Auxiliary Protocol Helpers (Safe Non-Destructive Boundary Probes)
# ---------------------------------------------------------------------------

def grab_banner(host, port, timeout=4.0):
    """Simple raw TCP banner grabber."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                if int(port) in [80, 8080, 8888, 8000]:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                elif int(port) in [21, 22, 25, 110, 143]:
                    pass
                else:
                    s.sendall(b"\r\n\r\n")
                banner = s.recv(1024)
                return True, banner.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                return True, "(Connected, but no initial banner sent within timeout)"
    except Exception as e:
        return False, str(e)

def check_tls(host, port, timeout=5.0):
    """Check supported TLS protocols and peer certificate."""
    results = {}
    protocols = [
        ("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None)),
        ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None)),
    ]

    for name, proto in protocols:
        if proto is None:
            continue
        try:
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, int(port)), timeout=timeout) as sock:
                with ctx.wrap_socket(sock) as ssock:
                    cipher = ssock.cipher()
                    results[name] = {"supported": True, "cipher": cipher[0] if cipher else "Unknown"}
        except Exception:
            results[name] = {"supported": False}

    try:
        ctx_default = ssl.create_default_context()
        ctx_default.check_hostname = False
        ctx_default.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            with ctx_default.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                results["certificate"] = cert
    except Exception as e:
        results["certificate_error"] = str(e)

    return results

def probe_redis(host, port=6379, timeout=4.0):
    """Safe non-destructive probe to check if Redis allows unauthenticated INFO."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"INFO\r\n")
            resp = s.recv(2048).decode("utf-8", errors="replace")
            if "NOAUTH" in resp:
                return True, {"auth_required": True, "details": "Authentication required (requirepass enabled)"}
            elif "redis_version" in resp:
                lines = [line.strip() for line in resp.split("\n") if ":" in line]
                metrics = {l.split(":")[0]: l.split(":")[1] for l in lines[:10]}
                return True, {"auth_required": False, "details": "Unauthenticated access allowed", "metrics": metrics}
            else:
                return False, {"details": f"Unexpected response: {resp[:100]}"}
    except Exception as e:
        return False, {"error": str(e)}

def probe_kubelet(host, port=10250, timeout=5.0):
    """Safe probe checking for unauthenticated /pods access on Kubernetes Kubelet."""
    url = f"https://{host}:{port}/pods"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecAudit/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            if resp.status == 200:
                body = resp.read(2048).decode("utf-8", errors="replace")
                return True, {"status": 200, "anonymous_auth": True, "snippet": body[:300]}
            return True, {"status": resp.status, "anonymous_auth": False}
    except urllib.error.HTTPError as he:
        return True, {"status": he.code, "anonymous_auth": False, "reason": he.reason}
    except Exception as e:
        return False, {"error": str(e)}

# ---------------------------------------------------------------------------
# CLI Argument Dispatcher
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Nmap-Powered Service Prober and Result Parser for Infrastructure Security"
    )
    subparsers = parser.add_subparsers(dest="action")

    # 1. nmap-probe (or probe)
    probe_p = subparsers.add_parser("nmap-probe", aliases=["probe", "scan"], help="Execute Nmap service probe and parse output to JSON")
    probe_p.add_argument("target", help="Target IP address, hostname, or subnet")
    probe_p.add_argument("-p", "--ports", default=None, help=f"Ports to scan (default: top infra ports)")
    probe_p.add_argument("--scripts", default=None, help="Comma-separated NSE scripts (e.g. banner,ssh2-enum-algos,ssl-enum-ciphers)")
    probe_p.add_argument("--udp", action="store_true", help="Perform UDP probe (-sU) instead of TCP")
    probe_p.add_argument("--intensity", type=int, default=5, help="Nmap version intensity (0-9, default: 5)")
    probe_p.add_argument("-T", "--timing", type=int, default=4, help="Nmap timing template (0-5, default: 4)")
    probe_p.add_argument("--host-timeout", default="120s", help="Max time per host (default: 120s)")
    probe_p.add_argument("--all-ports", action="store_true", help="Include closed/filtered ports in output")
    probe_p.add_argument("--to-recon-format", action="store_true", help="Format directly as recon_knowledge.json structure")
    probe_p.add_argument("-o", "--output", default=None, help="Save parsed JSON result to output file path")

    # 2. parse-xml
    parse_p = subparsers.add_parser("parse-xml", help="Parse an existing Nmap XML file into structured JSON")
    parse_p.add_argument("xml_file", help="Path to Nmap XML output file")
    parse_p.add_argument("--all-ports", action="store_true", help="Include closed/filtered ports in output")
    parse_p.add_argument("--to-recon-format", action="store_true", help="Format directly as recon_knowledge.json structure")
    parse_p.add_argument("-o", "--output", default=None, help="Save parsed JSON result to output file path")

    # 3. Auxiliary commands
    banner_p = subparsers.add_parser("banner", help="Raw socket banner grabber")
    banner_p.add_argument("host")
    banner_p.add_argument("port", type=int)

    tls_p = subparsers.add_parser("tls", help="TLS cipher and certificate checker")
    tls_p.add_argument("host")
    tls_p.add_argument("port", type=int, default=443, nargs="?")

    redis_p = subparsers.add_parser("redis", help="Check unauthenticated Redis INFO access")
    redis_p.add_argument("host")
    redis_p.add_argument("port", type=int, default=6379, nargs="?")

    kubelet_p = subparsers.add_parser("kubelet", help="Check anonymous Kubernetes Kubelet /pods access")
    kubelet_p.add_argument("host")
    kubelet_p.add_argument("port", type=int, default=10250, nargs="?")

    # If executed without arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Allow running: service_prober.py <target> as a shortcut to nmap-probe <target>
    if len(sys.argv) >= 2 and sys.argv[1] not in ["nmap-probe", "probe", "scan", "parse-xml", "banner", "tls", "redis", "kubelet", "-h", "--help"]:
        sys.argv.insert(1, "nmap-probe")

    args = parser.parse_args()

    if args.action in ["nmap-probe", "probe", "scan"]:
        results = run_nmap_probe(
            target=args.target,
            ports=args.ports,
            udp=args.udp,
            version_intensity=args.intensity,
            scripts=args.scripts,
            timing=args.timing,
            host_timeout=args.host_timeout,
            open_only=not args.all_ports
        )

        output_data = results
        if args.to_recon_format:
            output_data = format_as_recon_knowledge(results, target_str=args.target)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2)
            print(f"[+] Results saved to {args.output}", file=sys.stderr)
        else:
            print(json.dumps(output_data, indent=2))

    elif args.action == "parse-xml":
        if not os.path.exists(args.xml_file):
            print(f"[!] Error: File '{args.xml_file}' does not exist.", file=sys.stderr)
            sys.exit(1)

        results = parse_nmap_xml(args.xml_file, open_only=not args.all_ports)
        output_data = results
        if args.to_recon_format:
            output_data = format_as_recon_knowledge(results, target_str=args.xml_file)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2)
            print(f"[+] Results saved to {args.output}", file=sys.stderr)
        else:
            print(json.dumps(output_data, indent=2))

    elif args.action == "banner":
        ok, res = grab_banner(args.host, args.port)
        print(json.dumps({"success": ok, "output": res}, indent=2))

    elif args.action == "tls":
        res = check_tls(args.host, args.port)
        print(json.dumps(res, indent=2, default=str))

    elif args.action == "redis":
        ok, res = probe_redis(args.host, args.port)
        print(json.dumps({"success": ok, "result": res}, indent=2))

    elif args.action == "kubelet":
        ok, res = probe_kubelet(args.host, args.port)
        print(json.dumps({"success": ok, "result": res}, indent=2))

if __name__ == "__main__":
    main()
