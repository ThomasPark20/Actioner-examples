# Technical Analysis Report: PaperCut NG/MF Zero-Day Exploitation — CVE-2026-82078 & CVE-2026-81578 (2026-08-30)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-30
Version: 1.0 (DRAFT)

## Executive Summary

Attackers are actively exploiting a chain of two zero-day vulnerabilities in PaperCut NG and PaperCut MF print management software to achieve unauthenticated remote code execution. CVE-2026-81578 (CVSS 8.8) is an improper access control flaw in the web management interface that allows unauthenticated modification of server configuration, and CVE-2026-82078 (CVSS 9.4) is an unsafe dynamic class-loading vulnerability in database connection utilities that enables arbitrary Java bytecode execution. Chained together, they grant a remote, unauthenticated attacker full code execution under the PaperCut server process (SYSTEM on Windows).

Exploitation was confirmed in at least two customer environments as of August 27, 2026, with activity limited to short-duration reconnaissance (under two minutes). Attackers executed base64-encoded `whoami & ver` and `whoami & ver & tasklist` commands and deployed OS-agnostic Java `.class` files for fingerprinting. PaperCut released emergency patches on August 27-28, but security firm watchTowr identified bypasses of the initial patch, prompting a second emergency release. All PaperCut NG and MF versions 24, 25, and 26 are affected; version 23 and earlier have no patch and require upgrade. Any internet-facing PaperCut Application Server should be treated as at immediate risk.

## Background: PaperCut NG/MF Print Management

PaperCut NG (Network Gateway) and PaperCut MF (Multifunction) are enterprise print management solutions deployed in over 100 countries across education, healthcare, government, and corporate environments. The software provides centralized print tracking, cost accounting, job routing, and user authentication for network printing infrastructure. The PaperCut Application Server exposes a web-based management interface (typically on port 9191/9192) built on the Apache Tapestry web framework, with an embedded Apache Derby database for internal state management.

PaperCut servers frequently run with elevated privileges (SYSTEM on Windows, root on Linux) to manage print queues and device integrations. The web management interface is often exposed to internal networks and, in some deployments, to the internet — making it a high-value target for initial access. PaperCut has been targeted by threat actors before: in 2023, the Cl0p ransomware group exploited CVE-2023-27350 (a similar authentication bypass) to compromise print servers at scale.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-08-26 | Earliest observed exploitation activity in customer environments |
| 2026-08-27 | PaperCut discloses CVE-2026-82078 and CVE-2026-81578; emergency patch released for versions 25 and 26 |
| 2026-08-27 | Huntress confirms active exploitation in two customer environments |
| 2026-08-27 | Rapid7, BleepingComputer, THN, SecurityWeek, and The Register publish advisories |
| 2026-08-28 | watchTowr identifies patch bypasses; PaperCut releases Emergency Patch Release 2 with additional hardening |
| 2026-08-28 | Emergency patch extended to version 24 |
| 2026-08-30 | watchTowr reports additional bypasses affecting fully patched versions (details withheld) |

## Root Cause: Apache Tapestry Service Request Misrouting + Unvalidated Class Loading

The exploit chain targets two distinct architectural weaknesses:

**CVE-2026-81578 — Authentication Bypass via Tapestry Direct Service Requests:** PaperCut's web management interface uses Apache Tapestry's "complex direct" request format. The authentication layer validates access based on the *rendered page* name in the URL but executes *components* referenced by a different page. By crafting URLs that reference the `Error` (or `Exception` or `Home`) page while targeting components from `ConfigEditor` or `UserList`, an unauthenticated attacker bypasses access control and reaches administrative functionality. The three known exploit URIs are:

- `/app?service=direct/1/Error/ConfigEditor/quickFindForm`
- `/app?service=direct/1/Error/ConfigEditor/$Form`
- `/app?service=direct/1/Error/UserList/$QuickFind.$Form`

**CVE-2026-82078 — Unsafe Dynamic Class Loading in Database Connection Utilities:** The PaperCut application instantiates database driver classes from configuration values (`user-lookup.db-driver`, `user-lookup.db-url`, etc.) via Java reflection without validating them against an allowlist. An attacker who can modify these configuration values can force the server to load and instantiate arbitrary Java classes present on the application classpath.

## Technical Analysis of the Malicious Payload

### 1. Authentication Bypass (CVE-2026-81578)

The attacker sends unauthenticated HTTP POST requests to the PaperCut Application Server targeting the Tapestry direct service endpoints. The URL structure exploits a discrepancy between Tapestry's page-level access control and component-level action dispatch:

```
POST /app?service=direct/1/Error/ConfigEditor/$Form HTTP/1.1
```

Here `Error` is the page name (accessible without authentication), but `ConfigEditor/$Form` targets the configuration editor component that normally requires admin access. The access validator checks permissions for the `Error` page (which requires none) while the request handler processes the `ConfigEditor` form submission.

### 2. Configuration Poisoning and Code Execution (CVE-2026-82078)

Via the bypassed ConfigEditor, the attacker modifies four critical database configuration parameters:

| Parameter | Purpose |
|-----------|---------|
| `user-lookup.db-driver` | Database driver class name — replaced with attacker-controlled class |
| `user-lookup.db-url` | JDBC connection URL — set to malicious Derby/H2 connection string |
| `user-lookup.id-to-username-sql` | SQL query — set to trigger malicious database actions |
| `user-lookup.enabled` | Enables the external user lookup — activates the poisoned configuration |

### 3. JDBC-Based Code Execution Chain

The exploit leverages a sophisticated chain through PaperCut's bundled database engines:

1. **Derby `foreignViews` feature** opens attacker-controlled H2 JDBC URLs (`jdbc:derby:memory:pwn`)
2. **H2 processes inline INIT statements** that create JavaScript-backed database triggers
3. **PaperCut's bundled Nashorn JavaScript engine** executes OS commands via the trigger
4. The attacker then triggers a **UserList search** (via the `$QuickFind.$Form` endpoint), which activates the malicious external lookup and executes the payload

### 4. Observed Post-Exploitation Activity

In the two confirmed incidents, attackers performed brief reconnaissance operations:

**Base64-Encoded Commands:**
- `d2hvYW1pICYgdmVy` decodes to `whoami & ver` — user and OS identification
- `d2hvYW1pICYgdmVyICYgdGFza2xpc3Q=` decodes to `whoami & ver & tasklist` — adds running process enumeration

**Malicious Java .class Payloads:**
- `Udydn.class` and `Moo97.class` — OS-agnostic Java classes dropped into `server/lib/`
- These classes decode data from relative folder paths, execute system commands, and write output to designated files
- Output written to `Udydn.out` and `Udydn.cmd` in `server/data/content/`

**Code executed as SYSTEM** within the `pc-app.exe` process context on Windows. Huntress observed `charmap.exe` spawned as a proof-of-concept indicator. No secondary malware deployment, C2 communication, or persistence mechanisms were observed — activity was consistent with early-stage validation and fingerprinting.

### 5. Anti-Forensics / Evasion Techniques

Post-exploitation, attackers deleted key log files to cover their tracks:

- **`server.log`** — the primary PaperCut application log, which records the characteristic `Database error looking up cardID: VALUES CAST` error
- **`/data/internal/derby.log`** — the Apache Derby database log, which records the malicious JDBC connections including `jdbc:derby:memory:pwn`

Missing or truncated log files at these paths is itself an indicator of compromise.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Versions | Description |
|---------------------|-------------------|-------------|
| PaperCut NG | All versions 24.x, 25.x, 26.x prior to Emergency Patch Release 2 | Auth bypass + unsafe class loading |
| PaperCut MF | All versions 24.x, 25.x, 26.x prior to Emergency Patch Release 2 | Auth bypass + unsafe class loading |
| PaperCut NG/MF | Versions 23.x and earlier | No patch available; upgrade required |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Cross-platform | `server/lib/Udydn.class` | Malicious Java class payload — command execution |
| Cross-platform | `server/lib/Moo97.class` | Malicious Java class payload — fingerprinting |
| Cross-platform | `server/data/content/Udydn.out` | Command output file from exploit payload |
| Cross-platform | `server/data/content/Udydn.cmd` | Command file from exploit payload |
| Windows | `C:\Program Files\PaperCut MF\server\` or `C:\Program Files\PaperCut NG\server\` | Default installation path |
| Linux | `/opt/papercut/server/` or `/home/papercut/server/` | Common installation paths |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | `/app?service=direct/1/Error/ConfigEditor/quickFindForm` | Auth bypass exploit endpoint |
| URL Pattern | `/app?service=direct/1/Error/ConfigEditor/$Form` | Auth bypass exploit endpoint |
| URL Pattern | `/app?service=direct/1/Error/UserList/$QuickFind.$Form` | Auth bypass exploit endpoint (triggers payload) |
| Port | 9191 (HTTP), 9192 (HTTPS) | Default PaperCut Application Server ports |

### Behavioral

- `pc-app.exe` (Windows) or `pc-app` (Linux) spawning `cmd.exe`, `powershell.exe`, `whoami.exe`, `tasklist.exe`, `charmap.exe`, or shell processes
- Application log entries containing `Database error looking up cardID: VALUES CAST`
- Application log entries containing `No suitable driver found for jdbc:no:x`
- Application log entries containing `jdbc:derby:memory:pwn` or `memory:C:\Program Files\PaperCut MF\server\data\internal\pwn`
- Unexpected `.class` files appearing in `server/lib/` (particularly with short, 5-character names)
- Matching `.out` or `.cmd` files in `server/data/content/`
- Missing, truncated, or recently deleted `server.log` or `derby.log`
- Changes to external user-lookup configuration (`user-lookup.db-driver`, `user-lookup.db-url`, `user-lookup.id-to-username-sql`, `user-lookup.enabled`)
- HTTP POST requests to `/app?service=direct/` referencing `ConfigEditor` or `UserList` components from unauthorized pages

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Chained CVE-2026-81578 + CVE-2026-82078 for unauthenticated RCE against internet-facing PaperCut servers |
| T1059.003 | Windows Command Shell | Base64-encoded `cmd.exe` commands (`whoami & ver & tasklist`) executed post-exploitation |
| T1059.007 | JavaScript | Nashorn JavaScript engine triggered via H2 database triggers to execute OS commands |
| T1033 | System Owner/User Discovery | `whoami` command executed to identify running user context |
| T1082 | System Information Discovery | `ver` command executed to identify Windows version |
| T1057 | Process Discovery | `tasklist` command executed to enumerate running processes |
| T1083 | File and Directory Discovery | Java .class payload performed directory listing operations |
| T1070.004 | Indicator Removal: File Deletion | Deletion of `server.log` and `derby.log` to destroy forensic evidence |

## Impact Assessment

**Breadth:** All PaperCut NG and MF versions 24, 25, and 26 on Windows, Linux, and macOS are affected. PaperCut claims "hundreds of millions" of users across 100+ countries. Any instance with the web management interface reachable by an attacker is exploitable without credentials.

**Depth:** Exploitation achieves arbitrary code execution as the PaperCut server process — typically SYSTEM on Windows and root on Linux. This provides full server compromise, access to all managed print data, credentials stored in PaperCut, and a pivot point into the internal network.

**Stealth:** The exploit leaves log artifacts (`Database error looking up cardID: VALUES CAST`), but the attackers actively deleted these logs post-exploitation. The entire exploitation window in observed incidents was under two minutes.

**Current Status:** Exploitation is confirmed in the wild but appears limited to a small number of incidents (2 confirmed by Huntress). Activity has been reconnaissance-only so far, suggesting early-stage capability validation. However, with public advisories and the Rapid7 writeup detailing the exact exploit URIs, broader exploitation is expected imminently.

## Detection & Remediation

### Immediate Detection

**1. Check PaperCut application logs for exploit signatures:**
```bash
# Linux
grep -r "Database error looking up cardID" /opt/papercut/server/logs/
grep -r "No suitable driver found for jdbc:no:x" /opt/papercut/server/logs/
grep -r "jdbc:derby:memory:pwn" /opt/papercut/server/logs/

# Windows (PowerShell)
Select-String -Path "C:\Program Files\PaperCut MF\server\logs\*" -Pattern "Database error looking up cardID"
Select-String -Path "C:\Program Files\PaperCut MF\server\logs\*" -Pattern "No suitable driver found for jdbc:no:x"
Select-String -Path "C:\Program Files\PaperCut MF\server\logs\*" -Pattern "jdbc:derby:memory:pwn"
```

**2. Check for malicious file artifacts:**
```bash
# Linux
find /opt/papercut/server/lib/ -name "*.class" -newer /opt/papercut/server/lib/papercut*.jar
ls -la /opt/papercut/server/data/content/Udydn.*

# Windows (PowerShell)
Get-ChildItem "C:\Program Files\PaperCut MF\server\lib\*.class" | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
Test-Path "C:\Program Files\PaperCut MF\server\data\content\Udydn.*"
```

**3. Check for log deletion (anti-forensics):**
```bash
# Linux — check if logs are suspiciously empty or recently modified
ls -la /opt/papercut/server/logs/server.log
ls -la /opt/papercut/server/data/internal/derby.log

# Windows
Get-ItemProperty "C:\Program Files\PaperCut MF\server\logs\server.log" | Select-Object Length,LastWriteTime
```

**4. Check web server access logs for exploit URIs:**
```bash
grep "service=direct" /var/log/nginx/access.log | grep -E "(ConfigEditor|UserList)"
```

### Remediation

1. **Apply Emergency Patch Release 2 immediately** — even if Release 1 was already applied. Patched builds: NG 25.0.12.76497, MF 25.0.12.76496 (verify your specific version's patch build number on PaperCut's advisory)
2. **Restrict web interface access** — firewall the management interface (ports 9191/9192) to trusted administrator IPs only; do not expose to the internet
3. **Check for compromise indicators** — run the detection commands above before and after patching
4. **Review configuration** — verify `user-lookup.db-driver`, `user-lookup.db-url`, `user-lookup.id-to-username-sql`, and `user-lookup.enabled` settings have not been tampered with
5. **Rotate credentials** — if compromise is confirmed, rotate all credentials accessible to the PaperCut server, including database passwords, LDAP/AD bind accounts, and SMTP credentials
6. **Preserve evidence** — if log deletion is detected, capture disk images before remediation; deleted logs may be recoverable from disk

### Long-Term Hardening

1. **Network segmentation** — PaperCut Application Servers should never be directly internet-facing; place behind VPN or zero-trust access controls
2. **Principle of least privilege** — run PaperCut services under a dedicated low-privilege account rather than SYSTEM/root where possible
3. **Log forwarding** — forward PaperCut application logs to a central SIEM in real-time to prevent evidence destruction via log deletion
4. **Web application firewall** — deploy a WAF in front of the PaperCut management interface to block unexpected Tapestry direct service requests
5. **Version management** — PaperCut versions 23 and earlier are end-of-life with no security patches; upgrade to a supported version

## Detection Rules

Six Sigma rules cover the application-log, process-level, file-system, and anti-forensics indicators. Four Suricata rules target the HTTP-level exploit patterns. Two YARA rules match the malicious Java .class payloads and output files. One Snort rule set (4 rules) mirrors the Suricata HTTP detections in Snort 2 syntax. All rules are PoC/advisory-specific. The primary caveat: the application-log Sigma rules require PaperCut logs to be forwarded to a SIEM with a `papercut` product mapping, which is not a default configuration.

### Sigma: PaperCut Application Log — Database Error Indicating Exploit Attempt

Detects the characteristic `Database error looking up cardID: VALUES CAST` error string emitted during CVE-2026-82078 exploitation, the single highest-confidence log-based indicator per PaperCut's own advisory.
Compile: pass | Confidence: high

<!-- Audit: sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk: message="*Database error looking up cardID*" message="*VALUES CAST*". sigma convert --without-pipeline -t log_scale: message=/Database error looking up cardID/i message=/VALUES CAST/i. Requires PaperCut server.log forwarded to SIEM with category:application product:papercut mapping. -->

```yaml
title: PaperCut Application Log - Database Error Indicating Exploit Attempt
id: c7a3e1b9-4d2f-48a6-9f1c-3e5b7d0a2c8f
status: experimental
description: >
    Detects the characteristic error message written to PaperCut server.log when
    CVE-2026-82078 is exploited. The string "Database error looking up cardID:
    VALUES CAST" is emitted when the attacker's malicious JDBC connection string
    triggers an error in the card-lookup path during exploitation.
references:
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/
    - https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/
author: Actioner
date: 2026/08/30
tags:
    - attack.t1190
    - attack.t1059.007
logsource:
    category: application
    product: papercut
detection:
    selection:
        message|contains|all:
            - 'Database error looking up cardID'
            - 'VALUES CAST'
    condition: selection
falsepositives:
    - Legitimate database driver misconfiguration causing similar error strings
level: critical
```

### Sigma: PaperCut Application Log — Suspicious JDBC Driver Error

Detects the `No suitable driver found for jdbc:no:x` error, a side-effect artifact produced during the exploit's class-loading sequence before the actual payload executes.
Compile: pass | Confidence: high

<!-- Audit: sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk: message="*No suitable driver found for jdbc:no:x*". sigma convert --without-pipeline -t log_scale: message=/No suitable driver found for jdbc:no:x/i. Same log-forwarding dependency as above. -->

```yaml
title: PaperCut Application Log - Suspicious JDBC Driver Error Post-Exploitation
id: d8b4f2ca-5e3a-49b7-a02d-4f6c8e1b3d9a
status: experimental
description: >
    Detects the JDBC driver error "No suitable driver found for jdbc:no:x" in
    PaperCut application logs. This error is emitted as a side effect during
    exploitation of CVE-2026-82078 when the attacker's malicious class-loading
    sequence produces an invalid JDBC URL before the actual payload executes.
references:
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/
author: Actioner
date: 2026/08/30
tags:
    - attack.t1190
    - attack.t1059.007
logsource:
    category: application
    product: papercut
detection:
    selection:
        message|contains: 'No suitable driver found for jdbc:no:x'
    condition: selection
falsepositives:
    - Misconfigured database connection settings referencing invalid JDBC URLs
level: high
```

### Sigma: PaperCut Server Process Spawning Suspicious Child Process

Detects `pc-app.exe` spawning command shells or discovery utilities, matching observed post-exploitation behavior including `whoami`, `tasklist`, and `charmap.exe`.
Compile: pass | Confidence: high

<!-- Audit: sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk succeeds. sigma convert --without-pipeline -t log_scale succeeds. Requires Sysmon or Windows Security 4688 with command-line auditing. charmap.exe inclusion based on Huntress PoC observation. -->

```yaml
title: PaperCut Server Process Spawning Suspicious Child Process
id: e9c5a3db-6f4b-5ac8-b13e-5a7d9f2c4eab
status: experimental
description: >
    Detects the PaperCut application server process (pc-app.exe on Windows or
    pc-app on Linux) spawning command shells or discovery utilities, consistent
    with post-exploitation behavior observed in CVE-2026-82078 / CVE-2026-81578
    chained attacks where attackers executed base64-encoded reconnaissance commands.
references:
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/
author: Actioner
date: 2026/08/30
tags:
    - attack.t1190
    - attack.t1059.003
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\pc-app.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\whoami.exe'
            - '\tasklist.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\ipconfig.exe'
            - '\systeminfo.exe'
            - '\charmap.exe'
    condition: selection_parent and selection_child
falsepositives:
    - PaperCut server legitimately invoking system utilities during maintenance
level: high
```

### Sigma: PaperCut Exploit Output File Creation — Udydn.out

Detects creation of the `Udydn.out` or `Udydn.cmd` files, the specific output filenames used by the observed exploit payload.
Compile: pass | Confidence: high

<!-- Audit: sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk succeeds. sigma convert --without-pipeline -t log_scale succeeds. Requires Sysmon EventID 11 (FileCreate) or equivalent file monitoring. Filename is attacker-specific and highly unlikely in legitimate use. -->

```yaml
title: PaperCut Exploit Output File Creation - Udydn.out
id: fab6b4ec-7a5c-6bd9-c24f-6b8eaf3d5fbc
status: experimental
description: >
    Detects creation of the file "Udydn.out" in PaperCut data directories,
    which was observed as the output file used by the malicious Java .class
    payload during exploitation of CVE-2026-82078 / CVE-2026-81578. The
    attacker's Java class writes command output to this specific filename.
references:
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/
author: Actioner
date: 2026/08/30
tags:
    - attack.t1190
    - attack.t1059.007
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '\Udydn.out'
            - '/Udydn.out'
            - '\Udydn.cmd'
            - '/Udydn.cmd'
    condition: selection
falsepositives:
    - Extremely unlikely in legitimate environments
level: critical
```

### Sigma: Suspicious Java Class File in PaperCut Server Library Directory

Detects new `.class` files dropped into the PaperCut `server/lib/` directory, the classpath location used by attackers to stage their malicious Java payloads.
Compile: pass | Confidence: medium

<!-- Audit: sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk succeeds. sigma convert --without-pipeline -t log_scale succeeds. Legitimate PaperCut updates could deploy .class files to this path; correlate with maintenance windows. -->

```yaml
title: Suspicious Java Class File in PaperCut Server Library Directory
id: 0ac7c5fd-8b6d-7ce0-d35a-7c9fba4e6acd
status: experimental
description: >
    Detects creation of Java .class files in the PaperCut server/lib directory.
    Attackers exploiting CVE-2026-82078 drop malicious .class files (observed
    names: Udydn.class, Moo97.class) into the server classpath to achieve
    arbitrary code execution via unsafe dynamic class loading.
references:
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/
author: Actioner
date: 2026/08/30
tags:
    - attack.t1190
    - attack.t1059.007
logsource:
    category: file_event
detection:
    selection_path:
        TargetFilename|contains:
            - 'PaperCut'
            - 'papercut'
    selection_dir:
        TargetFilename|contains:
            - '\server\lib\'
            - '/server/lib/'
    selection_ext:
        TargetFilename|endswith: '.class'
    condition: selection_path and selection_dir and selection_ext
falsepositives:
    - Legitimate PaperCut software updates deploying new .class files
level: high
```

### Sigma: PaperCut Anti-Forensics — Server Log or Derby Log Deletion

Detects deletion of `server.log` or `derby.log` files within PaperCut installation directories, observed as anti-forensics behavior during exploitation.
Compile: pass | Confidence: high

<!-- Audit: sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk succeeds. sigma convert --without-pipeline -t log_scale succeeds. Requires Sysmon EventID 23/26 (FileDelete) or equivalent. Log rotation may trigger false positives — correlate with rotation schedules. -->

```yaml
title: PaperCut Anti-Forensics - Server Log or Derby Log Deletion
id: 1bd8d6ae-9c7e-8df1-e46b-8dafcb5f7bde
status: experimental
description: >
    Detects deletion of PaperCut server.log or derby.log files, which was
    observed as anti-forensics activity during exploitation of CVE-2026-82078 /
    CVE-2026-81578. Attackers deleted server.log and /data/internal/derby.log
    to cover evidence of exploitation.
references:
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/
author: Actioner
date: 2026/08/30
tags:
    - attack.t1070.004
logsource:
    category: file_delete
detection:
    selection:
        TargetFilename|endswith:
            - '\server.log'
            - '/server.log'
            - '\derby.log'
            - '/derby.log'
    filter_path:
        TargetFilename|contains:
            - 'PaperCut'
            - 'papercut'
    condition: selection and filter_path
falsepositives:
    - Log rotation scripts deleting old PaperCut log files
level: high
```

### Suricata: PaperCut Tapestry Auth Bypass and Exploit Payload Detection

Four Suricata rules detecting the HTTP-level exploit patterns: two target the authentication bypass URIs (ConfigEditor and UserList endpoints), and two target the exploit payload content (JDBC driver configuration and Derby memory database strings in POST bodies).
Compile: pass (Suricata 7.0.3, 0 warnings) | Confidence: high

<!-- Audit: suricata -T -S exit 0 with Suricata 7.0.3. All rules use dot-notation sticky buffers (http.uri, http.request_body). distance:0 used within same buffer instead of duplicate buffer declarations. Requires Suricata positioned to inspect traffic to PaperCut server on ports 9191/9192 (add to $HTTP_PORTS or use 'any'). -->

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut Auth Bypass via Tapestry Direct Service Request (CVE-2026-81578)"; flow:established,to_server; http.uri; content:"/app?service=direct/"; fast_pattern; content:"ConfigEditor"; distance:0; classtype:web-application-attack; reference:cve,2026-81578; reference:cve,2026-82078; reference:url,www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/; metadata:author Actioner, created_at 2026-08-30; sid:2100070; rev:2;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut Config Modification via UserList QuickFind Bypass (CVE-2026-81578)"; flow:established,to_server; http.uri; content:"/app?service=direct/"; fast_pattern; content:"UserList"; distance:0; content:"QuickFind"; distance:0; classtype:web-application-attack; reference:cve,2026-81578; reference:cve,2026-82078; reference:url,www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/; metadata:author Actioner, created_at 2026-08-30; sid:2100071; rev:2;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut Exploit Payload - Malicious JDBC Driver Configuration (CVE-2026-82078)"; flow:established,to_server; http.uri; content:"/app"; http.request_body; content:"user-lookup.db-driver"; fast_pattern; classtype:web-application-attack; reference:cve,2026-82078; reference:url,www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/; metadata:author Actioner, created_at 2026-08-30; sid:2100072; rev:2;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut Exploit Payload - Derby Memory Database in Request (CVE-2026-82078)"; flow:established,to_server; http.uri; content:"/app"; http.request_body; content:"jdbc:derby:memory"; fast_pattern; classtype:web-application-attack; reference:cve,2026-82078; reference:url,www.huntress.com/blog/papercut-actively-exploited; metadata:author Actioner, created_at 2026-08-30; sid:2100073; rev:2;)
```

### Snort: PaperCut Tapestry Auth Bypass and Exploit Payload Detection

Four Snort 2 rules mirroring the Suricata detections using underscore-notation HTTP modifiers.
Compile: uncompiled (snort not installed) | Confidence: high

<!-- Audit: Snort not installed in environment. Structural check only: semicolons terminate all options, parentheses balanced, http_uri/http_client_body modifiers used (Snort 2 syntax), msg/sid/rev present. These are UNCOMPILED — validate with snort -T before deployment. -->

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - PaperCut Auth Bypass via Tapestry Direct Service ConfigEditor (CVE-2026-81578)"; flow:established,to_server; content:"/app?service=direct/"; http_uri; content:"ConfigEditor"; http_uri; classtype:web-application-attack; reference:cve,2026-81578; reference:cve,2026-82078; metadata:author Actioner, created 2026-08-30; sid:2100080; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - PaperCut Config Modification via UserList QuickFind Bypass (CVE-2026-81578)"; flow:established,to_server; content:"/app?service=direct/"; http_uri; content:"UserList"; http_uri; content:"QuickFind"; http_uri; classtype:web-application-attack; reference:cve,2026-81578; reference:cve,2026-82078; metadata:author Actioner, created 2026-08-30; sid:2100081; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - PaperCut Exploit Payload - Malicious JDBC Driver Configuration (CVE-2026-82078)"; flow:established,to_server; content:"/app"; http_uri; content:"user-lookup.db-driver"; http_client_body; classtype:web-application-attack; reference:cve,2026-82078; metadata:author Actioner, created 2026-08-30; sid:2100082; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - PaperCut Exploit Payload - Derby Memory Database in Request (CVE-2026-82078)"; flow:established,to_server; content:"/app"; http_uri; content:"jdbc:derby:memory"; http_client_body; classtype:web-application-attack; reference:cve,2026-82078; metadata:author Actioner, created 2026-08-30; sid:2100083; rev:1;)
```

### YARA: PaperCut Exploit Java Class Payload

Detects the malicious Java `.class` files observed in the exploitation campaign, matching the specific payload filenames (Udydn, Moo97), output file patterns, and behavioral signatures of classes that execute OS commands and write output to PaperCut data directories.
Compile: pass (yarac 4.5.0) | Confidence: high

<!-- Audit: yarac exit 0. Matches Java class files (CA FE BA BE magic) under 100KB containing exploit-specific names (Udydn, Moo97), output file patterns, or command-execution APIs combined with PaperCut path references and recon commands. 100KB size cap limits FP scope. -->

```yara
rule PaperCut_Exploit_Java_Class_Payload
{
    meta:
        description = "Detects malicious Java .class files used in PaperCut CVE-2026-82078 / CVE-2026-81578 exploitation. Matches the observed payload filenames (Udydn, Moo97) and behavioral patterns of the exploit classes that execute OS commands and write output to files."
        author = "Actioner"
        date = "2026-08-30"
        reference = "https://www.huntress.com/blog/papercut-actively-exploited"
        cve = "CVE-2026-82078"
        severity = "critical"

    strings:
        $java_magic = { CA FE BA BE }

        $name_udydn = "Udydn" ascii
        $name_moo97 = "Moo97" ascii

        $output_udydn = "Udydn.out" ascii
        $output_cmd = "Udydn.cmd" ascii

        $path_data_content = "/data/content/" ascii
        $path_server_lib = "server/lib/" ascii

        $cmd_exec1 = "Runtime" ascii
        $cmd_exec2 = "getRuntime" ascii
        $cmd_exec3 = "exec" ascii
        $cmd_exec4 = "ProcessBuilder" ascii

        $recon1 = "whoami" ascii
        $recon2 = "tasklist" ascii

    condition:
        $java_magic at 0 and filesize < 100KB and (
            (1 of ($name_*)) or
            (1 of ($output_*)) or
            ($path_data_content and 1 of ($cmd_exec*)) or
            ($path_server_lib and 1 of ($cmd_exec*)) or
            (2 of ($cmd_exec*) and 1 of ($recon*) and 1 of ($path_*))
        )
}
```

### YARA: PaperCut Exploit Output File

Detects the output file (`Udydn.out`) created by the exploit payload, containing command output from the reconnaissance phase.
Compile: pass (yarac 4.5.0) | Confidence: medium

<!-- Audit: yarac exit 0. Matches small files (<1MB) containing combinations of reconnaissance output markers (whoami output, Windows version strings, tasklist headers). May match benign system info dumps — medium confidence. -->

```yara
rule PaperCut_Exploit_Output_File
{
    meta:
        description = "Detects the output file (Udydn.out) created by the malicious Java class payload during PaperCut CVE-2026-82078 exploitation. The file contains command output from reconnaissance activity."
        author = "Actioner"
        date = "2026-08-30"
        reference = "https://www.huntress.com/blog/papercut-actively-exploited"
        cve = "CVE-2026-82078"
        severity = "high"

    strings:
        $whoami_ver = "whoami" ascii nocase
        $ver_cmd = /Microsoft Windows \[Version \d+\.\d+/ ascii
        $tasklist_header = "Image Name" ascii

    condition:
        filesize < 1MB and 2 of them
}
```

## Lessons Learned

This exploitation chain demonstrates a pattern increasingly common in enterprise web applications: an authentication bypass enabling access to administrative configuration interfaces, chained with an unsafe deserialization or class-loading primitive that converts configuration access into code execution. The specific mechanism — abusing JDBC driver class loading via Derby's `foreignViews` feature and H2's INIT statements — is a creative twist on the well-known JDBC attack surface that has been documented in Java security research for years.

For defenders, this incident reinforces several critical lessons:

1. **Attack surface reduction for management interfaces** — PaperCut's web management interface should never be directly internet-facing, yet many deployments expose it. The same lesson from CVE-2023-27350 in 2023 went unheeded by many organizations.

2. **Log integrity and forwarding** — the attackers' deletion of `server.log` and `derby.log` is a reminder that local log files are trivially destroyed post-compromise. Real-time forwarding to a central SIEM is the only way to preserve forensic evidence against an attacker who achieves code execution.

3. **Patch verification** — the initial emergency patch (Release 1) was bypassed by watchTowr within a day, leading to Release 2. Organizations that patched once and assumed safety were still vulnerable. Patch verification through independent testing, not just version checking, is essential for critical vulnerabilities.

4. **Apache Tapestry authorization model** — the root cause of the auth bypass is a fundamental architectural issue in how Tapestry's "direct service" requests map between page-level authorization and component-level action dispatch. Applications built on Tapestry should audit their authorization enforcement to ensure it operates at the component level, not just the page level.

## Sources

- [The Hacker News — Attackers Chain Two PaperCut Flaws to Execute Code Without Authentication](https://thehackernews.com/2026/08/attackers-chain-two-papercut-flaws-to.html) — primary reporting on the vulnerability chain and exploitation timeline
- [Rapid7 — PaperCut NG/MF Critical Zero-Day Exploited in the Wild](https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/) — detailed technical analysis including exploit URIs, configuration parameters, and JDBC attack chain
- [Huntress — PaperCut Zero-Day: Active Exploitation and Pre-Auth RCE](https://www.huntress.com/blog/papercut-actively-exploited) — incident response findings including malicious .class file analysis, base64 commands, and post-exploitation artifacts
- [BleepingComputer — PaperCut Releases Second Emergency Patch for Exploited Flaws](https://www.bleepingcomputer.com/news/security/papercut-releases-second-emergency-patch-for-exploited-flaws/) — patch timeline, watchTowr bypass details, and remediation guidance
- [PaperCut — URGENT Security Advisory: Security Bulletin 27 Aug 2026](https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/) — vendor advisory with patch download links
- [eSentire — PaperCut Discloses Zero-Day Vulnerabilities (CVE-2026-82078 and CVE-2026-81578)](https://www.esentire.com/security-advisories/apercut-discloses-zero-day-vulnerabilities-cve-2026-82078-and-cve-2026-81578) — MSSP advisory with IOC summary and remediation steps
- [Help Net Security — PaperCut NG/MF Vulnerabilities Exploited in Zero-Day Attacks](https://www.helpnetsecurity.com/2026/08/27/papercut-ng-mf-vulnerability-attack/) — additional reporting on scope and impact
- [SecurityWeek — PaperCut Releases Emergency Patch for Exploited Zero-Day](https://www.securityweek.com/papercut-releases-emergency-patch-for-exploited-zero-day/) — coverage of vendor response and patch availability

---
*Report generated by Actioner*
