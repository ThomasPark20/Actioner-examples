# Technical Analysis Report: Collibra Platform Agent Unauthenticated RCE — CVE-2026-10621, CVE-2026-10622 (2026-06-08)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-08
Version: 1.1 (revised)

<!-- revision log v1.1:
  - Sigma Rule 1: title fixed from "Unauthenticated REST API Access" to "POST to /rest/restore Exploit Endpoint"; confidence downgraded high→medium (no port constraint in Sigma logsource).
  - Sigma Rules 2+3 (JSP Windows/Linux): ATT&CK tag corrected T1105→T1505.003; confidence downgraded medium→low (fires on legitimate JSP deployments); level downgraded high→medium.
  - Suricata SID 2200011 (recon): DROPPED — matches legitimate Console-to-Agent traffic.
  - Snort SID 2100011 (recon): DROPPED — same reason.
  - Added Splunk SPL and CrowdStrike LogScale conversions for all three Sigma rules.
  - Removed empty defanging convention block (no network IOCs requiring defanging).
  - Removed duplicate T1105 row from ATT&CK mapping table (consolidated under T1505.003).
  - Added non-default port caveat to Suricata and Snort network rules.
  - Status format normalized to "compile ✅ compiles · confidence: X".
-->

## Executive Summary

Two vulnerabilities in the Collibra Platform Agent (CVE-2026-10621, CVE-2026-10622) chain together to enable **unauthenticated remote code execution** on both SaaS and self-hosted Collibra deployments. CVE-2026-10622 (CVSS 3.1: **8.2 HIGH**) exposes privileged REST API endpoints under `/rest/*` without authentication or authorization enforcement, while CVE-2026-10621 (CVSS 3.1: **7.5 HIGH**) is a Zip Slip path traversal vulnerability in the `POST /rest/restore` endpoint that allows arbitrary file writes via crafted ZIP archives containing directory traversal sequences. When chained, an unauthenticated attacker uploads a malicious ZIP archive through the unprotected restore endpoint, writes a JSP webshell to a web-accessible directory, and achieves arbitrary code execution -- potentially running under root context.

The Collibra Agent is an independent service that listens on **TCP port 4401** (default), separate from the main DGC web interface (port 4400) and Console (port 4402). The vulnerable web service binds to **all network interfaces** regardless of installer configuration, meaning deployments reachable from the public internet are at significant risk. Collibra was notified on 2026-03-06 and published patches across multiple SaaS and self-hosted release trains. No public proof-of-concept exploit code has been published, but the exploitation chain is straightforward and well-documented in the CERT/CC advisory.

## Background: Collibra Platform Agent

Collibra is a leading data governance and data catalog platform used by large enterprises to manage data assets, quality, lineage, and compliance. The Collibra Platform Agent is an independent background service installed on host systems that:

- Executes Data Quality (DQ) jobs by polling a PostgreSQL-backed queue (`agent_q` table) every 5 seconds
- Exposes a REST API on **TCP port 4401** for management operations including backup/restore functionality
- Communicates with the Collibra Console (port 4402) and Repository (port 4403) services
- Supports both Windows and Linux deployments with default installation under `/home/<user>/collibra/` (Linux) or customizable paths

The Agent runs as a Java-based web application (supporting JSP execution) and is deployed in enterprise environments often containing sensitive data governance metadata, database credentials, and connections to production data stores.

### Default Collibra TCP Ports

| Port | Service | Purpose |
|------|---------|---------|
| 4400 | DGC | Main web interface |
| 4401 | Agent | Agent REST API (vulnerable) |
| 4402 | Console | Administration interface |
| 4403 | Repository | Internal data store |
| 4404 | Jobserver | Job execution service |

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-03-06 | Vendor (Collibra) notified of vulnerabilities |
| 2026-04-28 | Collibra responds requesting reproduction steps |
| 2026-06-02 | CERT/CC publishes VU#873170; CVEs assigned and published to NVD |
| 2026-06-08 | SecurityOnline publishes technical coverage |

## Technical Analysis

### 1. Unauthenticated REST API Access (CVE-2026-10622)

The Collibra Agent exposes privileged REST endpoints under the `/rest/*` URI namespace that **do not enforce authentication or authorization**. Any remote attacker with network access to the Agent service (default TCP 4401) can interact with sensitive application functionality without credentials.

Key characteristics:
- **All endpoints** under `/rest/*` are affected
- The web service hosting these endpoints **binds to all available network interfaces** (`0.0.0.0`) regardless of configuration passed to the installer script
- This enables an attacker to enumerate filesystem locations, application paths, and internal configuration -- information critical for staging the subsequent Zip Slip attack
- CVSS 3.1 Vector: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` (8.2 HIGH)

### 2. Zip Slip Path Traversal via /rest/restore (CVE-2026-10621)

The `POST /rest/restore` endpoint accepts ZIP archive uploads for backup restoration. The extraction routine **fails to validate or canonicalize file paths** within the archive, allowing entries with directory traversal sequences (e.g., `../../../`) to write files outside the intended extraction directory.

Exploitation mechanism:
1. Attacker crafts a ZIP archive containing entries with path traversal prefixes (e.g., `../../../webapps/ROOT/shell.jsp`)
2. The archive is uploaded via `POST /rest/restore` (no authentication required per CVE-2026-10622)
3. During extraction, the traversal sequences are honored, writing the attacker's file to an arbitrary location on the filesystem
4. A **malicious JSP file** placed in a web-accessible directory enables remote code execution when subsequently requested via HTTP
5. Execution occurs under the Agent service's process context, which may be **root** depending on deployment configuration

CVSS 3.1 Vector: `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` (7.5 HIGH)

### 3. Chained Exploitation Flow

```
Attacker                          Collibra Agent (TCP 4401)
   |                                        |
   |--- GET /rest/* (enumerate paths) ----->|  [CVE-2026-10622: No auth]
   |<--- 200 OK (config/path info) ---------|
   |                                        |
   |--- POST /rest/restore               ->|  [CVE-2026-10622: No auth]
   |    Body: crafted ZIP with ../../*.jsp  |  [CVE-2026-10621: Zip Slip]
   |<--- 200 OK (restore complete) ---------|
   |                                        |
   |--- GET /shell.jsp?cmd=whoami --------->|  [RCE achieved]
   |<--- 200 OK (root) --------------------|
```

### 4. Post-Exploitation Impact

An attacker who successfully exploits these vulnerabilities may:
- **Install persistent web shells** for ongoing remote access
- **Read, modify, or delete** application data including data governance metadata, database connection strings, and compliance records
- **Disrupt system availability** by corrupting configuration or data
- **Pivot further** into the surrounding enterprise environment, particularly to connected data sources and databases managed by Collibra

## Indicators of Compromise (IOCs)

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| Port | TCP 4401 | Default Collibra Agent port; unauthenticated REST API |
| URI Pattern | `POST /rest/restore` | Zip Slip exploitation endpoint |
| URI Pattern | `/rest/*` | Unauthenticated privileged REST API namespace |
| Content-Type | `application/zip` or `multipart/form-data` | ZIP archive upload to /rest/restore |

### File System Indicators

| Indicator | Description |
|-----------|-------------|
| Unexpected `.jsp` files in Collibra web-accessible directories | Webshell deployment via Zip Slip |
| ZIP files containing `../` path traversal in entry names | Malicious restore archives |
| New or modified files outside Collibra data/backup directories after restore operations | Arbitrary file write evidence |

### Behavioral Indicators

- Unauthenticated HTTP POST requests to `/rest/restore` on port 4401 from external or unexpected source IPs
- HTTP GET/POST requests to newly created `.jsp` files in Collibra web directories
- Unexpected child processes spawned by the Collibra Agent Java process (e.g., `/bin/sh`, `/bin/bash`, `cmd.exe`)
- Network connections originating from the Collibra Agent process to unexpected external destinations (C2 callbacks from webshell)

### Package / Software Level

| Package / Component | Vulnerable Versions | Fixed Versions |
|---------------------|---------------------|----------------|
| Collibra Platform (SaaS) | Prior to patch trains | 2026.05, 2026.04.5, 2026.03.4, 2026.02.6, 2025.11.7, 2025.10.9 |
| Collibra Platform Self Hosted | Prior to patch builds | 2026.03 (Build 2026.03.356), 2025.10 (Build 2025.10.399) |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated exploitation of Collibra Agent REST API on internet-exposed deployments |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Post-exploitation command execution via deployed JSP webshell |
| T1505.003 | Server Software Component: Web Shell | JSP webshell written to web-accessible directory via Zip Slip path traversal for persistent access and code execution |

## Detection & Remediation

### Immediate Detection

**Check Collibra Agent version:**
```bash
# Check installed Collibra version
# Linux:
cat /opt/collibra/version.txt 2>/dev/null || ls -la /home/*/collibra/
# Or via Console UI: Settings > System > About
```

**Search web server / proxy logs for exploitation attempts:**
```bash
# Look for POST requests to /rest/restore on Agent port
grep -E 'POST.*/rest/restore' /var/log/collibra/*.log /var/log/httpd/*access* /var/log/nginx/*access* 2>/dev/null

# Look for unexpected JSP file access
grep -E '\.jsp' /var/log/collibra/*.log 2>/dev/null | grep -v known_legitimate_jsps
```

**Check for unexpected JSP files:**
```bash
# Find recently created JSP files in Collibra directories
find /opt/collibra /home/*/collibra -name "*.jsp" -mtime -30 -ls 2>/dev/null
```

**Check for the Agent binding to all interfaces:**
```bash
# Verify Agent listening scope
ss -tlnp | grep 4401
# If bound to 0.0.0.0:4401, the Agent is exposed on all interfaces
```

### Remediation

1. **Immediately update** Collibra Platform to the latest patched version (SaaS: 2026.05+; Self-Hosted: 2026.03 Build 2026.03.356+ or 2025.10 Build 2025.10.399+)
2. **Restrict network access** to the Agent port (TCP 4401) -- firewall it to only allow connections from the Collibra Console and DGC services, never from the internet or untrusted networks
3. **Review access logs** for historical POST requests to `/rest/restore` from unexpected source IPs
4. **Hunt for webshells** -- search for unexpected `.jsp` files created after the deployment date in Collibra web-accessible directories
5. **Audit for compromise** -- if running a vulnerable version exposed to untrusted networks, check for unauthorized processes, unusual outbound connections, and unexpected file modifications
6. **Rotate credentials** for any Collibra service accounts, database connections, or API keys on potentially compromised deployments

### Long-Term Hardening

- Enforce network segmentation: Collibra Agent (4401), Console (4402), Repository (4403) should only be accessible from designated management networks
- Deploy a reverse proxy with authentication in front of Collibra Agent endpoints
- Implement file integrity monitoring (FIM) on Collibra web application directories to detect unauthorized JSP file creation
- Monitor for unusual process spawning from Java/Tomcat service processes

## Detection Rules

These detections target the specific exploitation artifacts of the CVE-2026-10621/CVE-2026-10622 chain: unauthenticated access to the `/rest/restore` endpoint and JSP webshell creation in Collibra directories. Sigma rules convert to Splunk SPL and CrowdStrike LogScale (conversions included below each rule). Network rules (Suricata/Snort) target the HTTP exploitation traffic on the default Agent port (TCP 4401). Two reconnaissance rules (Suricata SID 2200011, Snort SID 2100011) were dropped during review because `GET /rest/` on port 4401 matches legitimate Console-to-Agent API traffic with no exploit-specific artifact. Note: compiles does not equal fires -- verify in your log pipeline against Collibra Agent web server logs or inline network inspection.

### Sigma: Collibra Agent POST to /rest/restore Exploit Endpoint

Detects HTTP POST requests to the `/rest/restore` endpoint, the specific exploitation vector for the CVE-2026-10621 Zip Slip vulnerability, accessed without authentication via CVE-2026-10622.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: title fixed to match detection scope (POST /rest/restore, not all REST API access); confidence downgraded from high to medium — fires on any POST to /rest/restore without port constraint in the Sigma rule itself, legitimate admin restore operations are possible. -->
<!-- audit: sigma check 0 errors 0 issues; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Keys on cs-uri-stem containing /rest/restore combined with POST method. FP risk low-to-medium: restore operations are infrequent administrative actions that should correlate with authorized change windows, but no port filter narrows scope. -->
```yaml
title: Collibra Agent POST to /rest/restore Exploit Endpoint
id: 3a7f1c4e-9b2d-4e8a-a5f6-2d1c0e3b4a7f
status: experimental
description: >
    Detects HTTP POST requests to the Collibra Platform Agent /rest/restore endpoint,
    the primary exploitation vector for the CVE-2026-10621 Zip Slip path traversal
    vulnerability, accessed without authentication via CVE-2026-10622. The restore
    endpoint accepts ZIP archive uploads whose extraction routine fails to validate
    file paths, enabling arbitrary file writes.
references:
    - https://kb.cert.org/vuls/id/873170
    - https://securityonline.info/collibra-platform-agent-flaw-rce/
    - https://nvd.nist.gov/vuln/detail/CVE-2026-10622
author: Actioner
date: 2026/06/08
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_restore:
        cs-uri-stem|contains: '/rest/restore'
    selection_method:
        cs-method: 'POST'
    condition: selection_restore and selection_method
falsepositives:
    - Legitimate authenticated backup restore operations by Collibra administrators
level: high
```

**Splunk SPL:**
```spl
"cs-uri-stem"="*/rest/restore*" "cs-method"="POST"
```

**CrowdStrike LogScale:**
```
"cs-uri-stem"=/\/rest\/restore/i "cs-method"=/^POST$/i
```

### Sigma: Collibra Agent Zip Slip JSP Webshell Write (Windows)

Detects creation of JSP files in Collibra installation directories on Windows systems, indicating potential exploitation of CVE-2026-10621 Zip Slip to deploy a webshell.
**Status:** compile ✅ compiles · confidence: low
<!-- revision: confidence downgraded from medium to low — fires on any JSP written under any path containing "collibra", including legitimate deployments and updates. ATT&CK tag fixed: replaced T1105 (Ingress Tool Transfer) with T1505.003 (Web Shell) to match the actual detection target. Level downgraded from high to medium. -->
<!-- audit: sigma check 0 errors 0 issues; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Keys on TargetFilename containing 'collibra' and ending with '.jsp'. Confidence low: legitimate Collibra updates deploy JSP files during patching and upgrades, making this rule noisy without baseline tuning. Requires file_event logging (Sysmon EventID 11 or equivalent). -->
```yaml
title: Collibra Agent Zip Slip JSP Webshell Write via Path Traversal (Windows)
id: 7c2e4b8a-1d3f-4a6e-b9c5-8f0d2e1a3b5c
status: experimental
description: >
    Detects file creation events for JSP files in web-accessible directories that
    may indicate successful exploitation of the Collibra Agent Zip Slip vulnerability
    (CVE-2026-10621). The attack chain writes malicious JSP webshells to arbitrary
    locations via crafted ZIP archives uploaded through the unauthenticated
    /rest/restore endpoint.
references:
    - https://kb.cert.org/vuls/id/873170
    - https://securityonline.info/collibra-platform-agent-flaw-rce/
    - https://nvd.nist.gov/vuln/detail/CVE-2026-10621
author: Actioner
date: 2026/06/08
tags:
    - attack.t1190
    - attack.t1505.003
logsource:
    category: file_event
    product: windows
detection:
    selection_path:
        TargetFilename|contains: 'collibra'
    selection_extension:
        TargetFilename|endswith: '.jsp'
    condition: selection_path and selection_extension
falsepositives:
    - Legitimate Collibra application updates that deploy JSP files
level: medium
```

**Splunk SPL:**
```spl
TargetFilename="*collibra*" TargetFilename="*.jsp"
```

**CrowdStrike LogScale:**
```
TargetFilename=/collibra/i TargetFilename=/\.jsp$/i
```

### Sigma: Collibra Agent Zip Slip JSP Webshell Write (Linux)

Detects creation of JSP files under Collibra installation directories on Linux systems, indicating potential exploitation of CVE-2026-10621 Zip Slip to deploy a webshell.
**Status:** compile ✅ compiles · confidence: low
<!-- revision: confidence downgraded from medium to low — fires on any JSP written under any path containing "/collibra", including legitimate deployments and updates. ATT&CK tag fixed: replaced T1105 (Ingress Tool Transfer) with T1505.003 (Web Shell). Level downgraded from high to medium. -->
<!-- audit: sigma check 0 errors 0 issues; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Same logic as Windows variant but scoped to Linux file_event. Requires auditd or equivalent file creation monitoring. -->
```yaml
title: Collibra Agent Zip Slip JSP Webshell Creation on Linux
id: 5e8d2f1a-3c4b-4a7e-9d6f-0b1c2e3a4d5f
status: experimental
description: >
    Detects creation of JSP files under Collibra installation directories on Linux
    systems, indicating potential exploitation of the Collibra Agent Zip Slip
    vulnerability (CVE-2026-10621). Attackers use crafted ZIP archives with path
    traversal sequences to write JSP webshells to web-accessible directories.
references:
    - https://kb.cert.org/vuls/id/873170
    - https://securityonline.info/collibra-platform-agent-flaw-rce/
    - https://nvd.nist.gov/vuln/detail/CVE-2026-10621
author: Actioner
date: 2026/06/08
tags:
    - attack.t1190
    - attack.t1505.003
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|contains: '/collibra'
    selection_extension:
        TargetFilename|endswith: '.jsp'
    condition: selection_path and selection_extension
falsepositives:
    - Legitimate Collibra application updates that deploy JSP files
level: medium
```

**Splunk SPL:**
```spl
TargetFilename="*/collibra*" TargetFilename="*.jsp"
```

**CrowdStrike LogScale:**
```
TargetFilename=/\/collibra/i TargetFilename=/\.jsp$/i
```

### Suricata: Collibra Agent Unauthenticated POST to /rest/restore

Detects HTTP POST requests to the Collibra Agent `/rest/restore` endpoint on the default Agent port (4401), the primary exploitation vector for the CVE-2026-10621/CVE-2026-10622 chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Uses http.method + http.uri content match. Scoped to port 4401 (default Agent port). fast_pattern on /rest/restore. -->

> **Note:** This rule targets port 4401 (default Collibra Agent port). If the Agent is deployed on a non-default port, update the destination port accordingly.

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET 4401 (msg:"Actioner - Collibra Agent Unauthenticated POST to /rest/restore Zip Slip RCE (CVE-2026-10621/CVE-2026-10622)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/rest/restore"; fast_pattern; classtype:web-application-attack; reference:cve,2026-10621; reference:cve,2026-10622; reference:url,kb.cert.org/vuls/id/873170; metadata:author Actioner, created_at 2026-06-08; sid:2200010; rev:1;)
```

### ~~Suricata: Collibra Agent Unauthenticated REST API Reconnaissance~~ (DROPPED)

<!-- revision: dropped — fires on legitimate Console-to-Agent API traffic. GET /rest/ on port 4401 matches all routine API communication between Collibra Console and Agent, producing unacceptable false-positive volume with no specific exploit artifact to anchor on. SID 2200011 removed from shipped rule file. -->

### Snort: Collibra Agent Unauthenticated POST to /rest/restore

Detects HTTP POST requests to the Collibra Agent `/rest/restore` endpoint on the default Agent port (4401), targeting the Zip Slip exploitation vector.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0. Snort 2.9 syntax with http_method and http_uri buffers. Scoped to port 4401. -->

> **Note:** This rule targets port 4401 (default Collibra Agent port). If the Agent is deployed on a non-default port, update the destination port accordingly.

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 4401 (msg:"Actioner - Collibra Agent Unauthenticated POST to /rest/restore Zip Slip RCE (CVE-2026-10621/CVE-2026-10622)"; flow:established,to_server; content:"POST"; http_method; content:"/rest/restore"; http_uri; fast_pattern; sid:2100010; rev:1; classtype:web-application-attack; reference:cve,2026-10621; reference:cve,2026-10622; reference:url,kb.cert.org/vuls/id/873170;)
```

### ~~Snort: Collibra Agent Unauthenticated REST API Reconnaissance~~ (DROPPED)

<!-- revision: dropped — fires on legitimate Console-to-Agent API traffic. GET /rest/ on port 4401 matches all routine API communication between Collibra Console and Agent, producing unacceptable false-positive volume with no specific exploit artifact to anchor on. SID 2100011 removed from shipped rule file. -->

### YARA: N/A

No file-level indicators suitable for YARA detection have been published for this vulnerability. The exploitation chain is network-based (HTTP ZIP upload + path traversal) with no specific malware hashes, unique strings, or distinctive binary artifacts disclosed in the advisory. If JSP webshell samples are obtained from incident response, YARA rules targeting specific webshell content would be appropriate but cannot be generated from currently available intelligence.

## Lessons Learned

1. **Backup/restore endpoints are high-value attack surface.** The `/rest/restore` endpoint combines file upload, archive extraction, and filesystem write operations -- a trifecta of dangerous capabilities. When exposed without authentication, it provides a direct path to arbitrary file write. All backup/restore functionality should require strong authentication and be network-restricted to authorized management stations.

2. **Zip Slip remains a persistent vulnerability class.** Despite being well-documented since Snyk's 2018 disclosure, path traversal during archive extraction continues to appear in enterprise software. Developers must canonicalize and validate all extracted file paths against the intended output directory before writing. Libraries and frameworks should provide safe extraction APIs by default.

3. **Service binding to 0.0.0.0 is a dangerous default.** The Collibra Agent web service binding to all network interfaces regardless of installer configuration dramatically increases attack surface. Services should bind to localhost by default and require explicit configuration to expose on external interfaces.

## Sources

- [CERT/CC VU#873170 - Collibra Agent contains improper authentication and path traversal vulnerabilities](https://kb.cert.org/vuls/id/873170) -- primary advisory with vulnerability details, exploitation chain, and affected versions
- [SecurityOnline - Collibra Platform Agent Flaw RCE](https://securityonline.info/collibra-platform-agent-flaw-rce/) -- news coverage with technical analysis
- [NVD - CVE-2026-10621](https://nvd.nist.gov/vuln/detail/CVE-2026-10621) -- CVSS 7.5 HIGH, path traversal via ZIP extraction
- [NVD - CVE-2026-10622](https://nvd.nist.gov/vuln/detail/CVE-2026-10622) -- CVSS 8.2 HIGH, improper authentication in REST API
- [Collibra Trust Center](https://www.collibra.com/company/trust-center) -- vendor security and compliance portal
- [Collibra Default TCP Ports Documentation](https://productresources.collibra.com/docs/collibra/2021.10/Content/Appendices/ref_default-tcp-ports.htm) -- port reference (4400-4434)

---
*Report generated by Actioner*
