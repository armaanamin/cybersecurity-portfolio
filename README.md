# Cybersecurity Portfolio — Shah Armaan Amin

Vulnerability research, CVE analysis, and penetration testing projects.

📧 armaanamin0602@gmail.com | 📍 Karachi, Pakistan

---

## 🔍 Projects

### 1. NetRecon — Automated Vulnerability Scanner
**[`netrecon_scanner.py`](./netrecon_scanner.py)**

A Python tool that automates the full vulnerability assessment pipeline:
- Runs an Nmap scan (SYN stealth, version detection, OS fingerprinting, NSE scripts)
- Parses the Nmap XML output programmatically
- Cross-references discovered service versions against the NIST NVD API for real CVEs
- Flags known-insecure protocols (Telnet, FTP, RDP, etc.)
- Generates a structured findings report

**Tech stack:** Python, `subprocess`, `xml.etree.ElementTree`, NIST NVD REST API

```bash
sudo python3 netrecon_scanner.py 192.168.1.0/24
```

---

### 2. Log4Shell (CVE-2021-44228) — CVE Research Report
**[`log4shell-research/`](./log4shell-research)**

A 10-section technical research report on Log4Shell, the highest-severity Java vulnerability of the last decade (CVSS 10.0).

Covers:
- Full attack chain: JNDI injection → LDAP callback → remote class loading → RCE
- CVSS v3.1 scoring breakdown (all 8 base metrics explained)
- Confirmed affected systems (Apple, Cisco, VMware, IBM, NSA) — sourced from TechCrunch, SecurityWeek, BleepingComputer
- Nation-state exploitation activity (Iran, China, North Korea, Russia) — sourced from CISA, FBI, Mandiant
- MITRE ATT&CK mapping across 7 techniques
- Detection IOCs and SIEM-ready indicators
- Full remediation guidance with exact patch versions

All data verified against primary sources: NIST NVD, CISA, US Cyber Safety Review Board, Tenable, Mandiant.

---

### 3. Metasploitable2 — vsftpd 2.3.4 Backdoor Exploitation
**[`metasploitable2-exploitation/`](./metasploitable2-exploitation)**

Hands-on exploitation walkthrough demonstrating the complete attack chain against a known-vulnerable lab target:

- Reconnaissance with Nmap (`-sV` service detection)
- Identified `vsftpd 2.3.4` running on port 21 — a version with a known backdoor (CVE-2011-2523)
- Exploited via Metasploit Framework (`exploit/unix/ftp/vsftpd_234_backdoor`)
- Obtained unauthenticated remote root shell (`uid=0(root) gid=0(root)`)
- Verified system access and documented the full process

**Tools:** Kali Linux, Metasploit Framework, Nmap, VirtualBox

> ⚠️ All exploitation performed in an isolated, intentionally vulnerable lab environment (Metasploitable2) for educational and skill-development purposes only.

---

## 🛠️ Skills Demonstrated

| Category | Tools / Concepts |
|---|---|
| Vulnerability Assessment | Nmap, NSE scripts, CVE/CVSS scoring, NIST NVD |
| Penetration Testing | Metasploit Framework, exploit identification & execution |
| Security Research | CVE analysis, MITRE ATT&CK, threat intelligence |
| Scripting | Python (automation, API integration, XML parsing) |
| Lab Environment | Kali Linux, VirtualBox, Metasploitable2 |

---

## 📚 Background

Final-year Computer Science student at SZABIST Karachi. FYP focused on AI-driven cyberattack detection (GAT-LSTM hybrid model) for smart grid infrastructure — 93.46% accuracy, ranked 3rd at EFEST FYP Expo 2026.

ISC2 Certified in Cybersecurity (CC) — in progress.
