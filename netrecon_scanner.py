#!/usr/bin/env python3
"""
=============================================================
  NetRecon — Automated Vulnerability Assessment Scanner
  Author : [Armaan]
  Version: 1.0
  Purpose: Automates host discovery, port scanning, service
           fingerprinting, and CVE lookup for VA engagements.
=============================================================
"""

import subprocess   # Lets Python run system commands (like nmap)
import xml.etree.ElementTree as ET  # Parses nmap's XML output
import json         # For reading/writing data in JSON format
import urllib.request  # Makes HTTP requests to CVE APIs
import urllib.parse    # Encodes text safely for URLs
import datetime     # Gets current date/time for the report
import sys          # Handles command-line arguments
import os           # File and path operations


# ─────────────────────────────────────────────
#  STEP 1 — Run Nmap and save XML output
# ─────────────────────────────────────────────

def run_nmap_scan(target, output_file="scan_results"):
    """
    Runs a professional Nmap scan against the target.
    Flags used:
      -sS  : SYN stealth scan (requires root)
      -sV  : Detect service versions
      -sC  : Run default safe NSE scripts
      -O   : OS detection
      -p-  : Scan ALL 65535 ports (not just top 1000)
      --min-rate 3000 : Speed up scan (3000 packets/sec)
      -oX  : Save output as XML (our script reads this)
    """
    print(f"\n[*] Starting Nmap scan on target: {target}")
    print("[*] This may take a few minutes...\n")

    xml_output = f"{output_file}.xml"

    nmap_command = [
        "nmap",
        "-sS",               # SYN stealth scan
        "-sV",               # Version detection
        "-sC",               # Default NSE scripts
        "-O",                # OS detection
        "-p-",               # All ports
        "--min-rate", "3000",
        "-oX", xml_output,   # Save as XML
        target
    ]

    try:
        # Run the nmap command, capture any errors
        result = subprocess.run(
            nmap_command,
            capture_output=True,
            text=True,
            timeout=300        # 5-minute timeout
        )

        if result.returncode == 0:
            print(f"[+] Scan complete. XML saved to: {xml_output}")
            return xml_output
        else:
            print(f"[-] Nmap error: {result.stderr}")
            return None

    except FileNotFoundError:
        print("[-] ERROR: Nmap is not installed. Install with: sudo apt install nmap")
        return None
    except subprocess.TimeoutExpired:
        print("[-] ERROR: Scan timed out after 5 minutes.")
        return None


# ─────────────────────────────────────────────
#  STEP 2 — Parse the Nmap XML output
# ─────────────────────────────────────────────

def parse_nmap_xml(xml_file):
    """
    Reads the Nmap XML file and extracts:
      - Host IP addresses
      - Hostnames
      - Operating system guess
      - Open ports with service names and versions

    Returns a list of host dictionaries.
    """
    print(f"\n[*] Parsing scan results from: {xml_file}")

    # Check the file actually exists
    if not os.path.exists(xml_file):
        print(f"[-] ERROR: File not found: {xml_file}")
        return []

    # Parse the XML file into a tree structure
    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts = []  # We'll build a list of host data here

    # Loop through every <host> element in the XML
    for host in root.findall("host"):

        # Only process hosts that are online
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        # ── Get IP address ──
        ip = "Unknown"
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "Unknown")

        # ── Get hostname if available ──
        hostname = "N/A"
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "N/A")

        # ── Get OS guess ──
        os_guess = "Unknown"
        os_el = host.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "Unknown")
                os_acc  = osmatch.get("accuracy", "?")
                os_guess = f"{os_name} ({os_acc}% confidence)"

        # ── Get all open ports and services ──
        open_ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")

                # Only care about open ports
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_num  = port.get("portid", "?")
                protocol  = port.get("protocol", "tcp")

                service_el = port.find("service")
                if service_el is not None:
                    svc_name    = service_el.get("name", "unknown")
                    svc_product = service_el.get("product", "")
                    svc_version = service_el.get("version", "")
                    svc_extra   = service_el.get("extrainfo", "")
                    # Combine product + version + extra into one string
                    full_version = " ".join(
                        filter(None, [svc_product, svc_version, svc_extra])
                    ).strip() or "N/A"
                else:
                    svc_name    = "unknown"
                    full_version = "N/A"

                open_ports.append({
                    "port"     : port_num,
                    "protocol" : protocol,
                    "service"  : svc_name,
                    "version"  : full_version
                })

        # Build the host record
        host_data = {
            "ip"        : ip,
            "hostname"  : hostname,
            "os"        : os_guess,
            "open_ports": open_ports
        }
        hosts.append(host_data)
        print(f"[+] Found host: {ip} ({hostname}) — {len(open_ports)} open port(s)")

    print(f"[*] Total live hosts found: {len(hosts)}")
    return hosts


# ─────────────────────────────────────────────
#  STEP 3 — CVE Lookup via NVD API
# ─────────────────────────────────────────────

def lookup_cves(service_name, version_string, max_results=3):
    """
    Searches NIST's National Vulnerability Database (NVD)
    for known CVEs matching the service and version.

    NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
    Returns a list of CVE dictionaries.
    """
    if not service_name or service_name == "unknown":
        return []

    # Build a search query: e.g. "apache 2.4.18" or just "openssh"
    query = service_name
    if version_string and version_string != "N/A":
        # Take only the version number part (first token)
        ver_token = version_string.split()[0]
        query = f"{service_name} {ver_token}"

    # URL-encode the query for safe HTTP transmission
    encoded_query = urllib.parse.quote(query)
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={encoded_query}&resultsPerPage={max_results}"
    )

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetRecon-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id  = cve_obj.get("id", "N/A")

            # Get description (English preferred)
            descriptions = cve_obj.get("descriptions", [])
            desc = "No description available."
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", desc)
                    break

            # Get CVSS v3 score if available
            cvss_score    = "N/A"
            cvss_severity = "N/A"
            metrics = cve_obj.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_source = cvss_v31 if cvss_v31 else cvss_v30
            if cvss_source:
                cvss_data     = cvss_source[0].get("cvssData", {})
                cvss_score    = cvss_data.get("baseScore", "N/A")
                cvss_severity = cvss_source[0].get("baseSeverity", "N/A")

            cves.append({
                "id"      : cve_id,
                "score"   : cvss_score,
                "severity": cvss_severity,
                "desc"    : desc[:200] + "..." if len(desc) > 200 else desc
            })

        return cves

    except Exception:
        # If the API is unreachable or rate-limited, return empty
        return []


# ─────────────────────────────────────────────
#  STEP 4 — Flag dangerous services
# ─────────────────────────────────────────────

# Known insecure services that should raise immediate flags
INSECURE_SERVICES = {
    "ftp"     : "FTP transmits credentials and data in plaintext. Replace with SFTP/SCP.",
    "telnet"  : "Telnet transmits all data including passwords in plaintext. Replace with SSH.",
    "http"    : "Unencrypted web traffic. Consider enforcing HTTPS (TLS) only.",
    "rsh"     : "Remote Shell — no encryption or strong authentication. Disable immediately.",
    "rlogin"  : "Remote Login — no encryption. Disable immediately.",
    "rexec"   : "Remote Exec — no encryption. Disable immediately.",
    "snmp"    : "SNMP v1/v2 uses community strings in plaintext. Upgrade to SNMPv3.",
    "vnc"     : "VNC often has weak authentication and no encryption. Restrict access.",
    "rdp"     : "RDP exposed to internet is high-risk. Restrict to VPN access only.",
}

def check_insecure_service(service_name):
    """Returns a warning string if the service is known-insecure, else None."""
    return INSECURE_SERVICES.get(service_name.lower(), None)


# ─────────────────────────────────────────────
#  STEP 5 — Generate a text findings report
# ─────────────────────────────────────────────

def generate_report(hosts, target, output_file="va_findings.txt"):
    """
    Writes a structured findings report to a text file.
    Format mirrors a professional VA report's findings section.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    lines.append("=" * 65)
    lines.append("   VULNERABILITY ASSESSMENT — AUTOMATED FINDINGS REPORT")
    lines.append("=" * 65)
    lines.append(f"  Target        : {target}")
    lines.append(f"  Scan Date     : {now}")
    lines.append(f"  Tool          : NetRecon v1.0 (Nmap + NVD API)")
    lines.append(f"  Total Hosts   : {len(hosts)}")
    lines.append("=" * 65)
    lines.append("")

    if not hosts:
        lines.append("  No live hosts discovered.")
    else:
        for idx, host in enumerate(hosts, 1):
            lines.append(f"HOST {idx}: {host['ip']}  ({host['hostname']})")
            lines.append(f"  OS Guess : {host['os']}")
            lines.append(f"  Open Ports: {len(host['open_ports'])}")
            lines.append("")

            if not host["open_ports"]:
                lines.append("  No open ports found.")
                lines.append("")
                continue

            for p in host["open_ports"]:
                lines.append(f"  [{p['port']}/{p['protocol']}]  {p['service'].upper()}  —  {p['version']}")

                # Check for known-insecure service
                warning = check_insecure_service(p["service"])
                if warning:
                    lines.append(f"  ⚠  INSECURE SERVICE: {warning}")

                # CVE lookup
                print(f"    [*] Looking up CVEs for: {p['service']} {p['version']}")
                cves = lookup_cves(p["service"], p["version"])
                if cves:
                    lines.append(f"  CVEs found ({len(cves)} shown):")
                    for cve in cves:
                        lines.append(f"    • {cve['id']}  |  CVSS: {cve['score']} ({cve['severity']})")
                        lines.append(f"      {cve['desc']}")
                else:
                    lines.append("  CVEs: None found via NVD API (verify manually)")
                lines.append("")

            lines.append("-" * 65)
            lines.append("")

    lines.append("=" * 65)
    lines.append("  END OF AUTOMATED FINDINGS — Manual verification required")
    lines.append("  for all findings before inclusion in final VA report.")
    lines.append("=" * 65)

    report_text = "\n".join(lines)

    with open(output_file, "w") as f:
        f.write(report_text)

    print(f"\n[+] Findings report saved to: {output_file}")
    return report_text


# ─────────────────────────────────────────────
#  MAIN — Tie everything together
# ─────────────────────────────────────────────

def main():
    print("""
╔══════════════════════════════════════════════╗
║   NetRecon — Automated VA Scanner v1.0       ║
║   For authorized assessments only            ║
╚══════════════════════════════════════════════╝
    """)

    # Get target from command line or ask interactively
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target IP or subnet (e.g. 192.168.1.0/24): ").strip()

    if not target:
        print("[-] No target provided. Exiting.")
        sys.exit(1)

    # ── Run the 4-step pipeline ──
    xml_file = run_nmap_scan(target)           # Step 1: Scan
    if not xml_file:
        sys.exit(1)

    hosts = parse_nmap_xml(xml_file)           # Step 2: Parse
    if not hosts:
        print("[-] No live hosts found. Exiting.")
        sys.exit(0)

    report = generate_report(hosts, target)    # Steps 3+4: CVEs + Report

    # Print summary to terminal
    print("\n" + "=" * 65)
    print(report)


if __name__ == "__main__":
    main()
