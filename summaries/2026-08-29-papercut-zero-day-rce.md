# Technical Analysis Report: PaperCut NG/MF Zero-Day RCE (2026-08-29)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-29
Version: 1.0 DRAFT

## Executive Summary

PaperCut NG and MF print management software is under active zero-day exploitation via two chained vulnerabilities: CVE-2026-81578 (CVSS 8.8, improper access control) and CVE-2026-82078 (CVSS 9.4, unsafe dynamic class loading). Attackers exploit the authentication bypass to modify server configuration, then abuse the JDBC driver class loading flaw to achieve unauthenticated remote code execution. Emergency patches have been released for v25 and v26. Approximately 1,000 PaperCut instances remain internet-exposed, primarily in North America and Europe.

Huntress confirmed exploitation affecting at least two customer environments. Post-exploitation activity includes system reconnaissance (whoami, ver, tasklist), creation of the artifact file `Udydn.out`, and anti-forensic log deletion. No CVE was assigned at the time of initial disclosure; both CVE IDs were subsequently assigned. Historical PaperCut vulnerabilities were previously exploited by ransomware groups Bl00dy, Clop, Lace Tempest, and Iranian state-backed actors, making rapid patching critical.

## Background: PaperCut NG/MF Print Management

PaperCut NG and MF are widely deployed print management solutions used across universities, corporations, and government entities to manage printers from Canon, Epson, Xerox, Brother, and other manufacturers. The Application Server component exposes a web management interface for administrative functions. PaperCut NG serves small-to-medium environments while MF targets enterprise and managed-print-services deployments. The software's privileged position -- internet-facing, integrated with Active Directory, and capable of storing printed documents -- makes it a high-value target for attackers seeking both network pivots and sensitive data exfiltration.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-27 (approx.) | Earliest observed exploitation activity against PaperCut NG/MF customer environments |
| 2026-08-28 (Thu) | PaperCut publishes urgent security advisory (PO-1216 and PO-1219) warning of active exploitation; initial patch released |
| 2026-08-28 | Huntress confirms exploitation impacting at least two customer environments |
| 2026-08-28 | watchTowr and Huntress collaborate with PaperCut on analysis |
| 2026-08-29 (Fri) | PaperCut releases improved emergency patch following collaboration with Huntress and watchTowr |

## Root Cause: Chained Authentication Bypass and Unsafe Class Loading

Two vulnerabilities are chained sequentially for unauthenticated remote code execution:

**CVE-2026-81578 (CVSS 8.8) -- Improper Access Control:** Unauthenticated remote requests targeting administrative functions can trigger backend actions prior to access validation completion. This allows an unauthenticated request to make changes to the server configuration and access sensitive endpoints that can trigger unsafe actions.

**CVE-2026-82078 (CVSS 9.4) -- Unsafe Dynamic Class Loading:** The PaperCut application instantiates database driver classes based on configurable names without allowlist validation. Once configuration is modified via CVE-2026-81578, the attacker specifies an arbitrary Java class name as the JDBC driver, causing the application to load and instantiate it, achieving arbitrary Java code execution within the application process (pc-app.exe).

## Technical Analysis of the Malicious Payload

### 1. Initial Access -- Authentication Bypass (CVE-2026-81578)

The attacker sends unauthenticated HTTP requests to the PaperCut web management interface targeting administrative functions. Due to the improper access control flaw, backend actions are triggered before the access validation logic completes. This allows the attacker to modify the server's database connection configuration without any credentials. The specific administrative endpoints exploited have not been publicly disclosed.

### 2. Code Execution -- JDBC Driver Class Loading Abuse (CVE-2026-82078)

After modifying the database configuration, the attacker sets the JDBC driver class name to a malicious or gadget class. When PaperCut attempts to establish a database connection using the modified configuration, it instantiates the attacker-controlled class. This results in arbitrary Java code execution running inside the pc-app.exe (Application Server) process context. The payloads observed are Java .class files, making the attack OS-agnostic. Base64-encoded commands have been observed in payload delivery.

### 3. Post-Exploitation Reconnaissance

Observed post-exploitation commands executed through the compromised PaperCut process:
- `whoami & ver` -- User account identification and OS version enumeration
- `whoami & ver & tasklist` -- Extended reconnaissance including running process enumeration

These commands are consistent with early-stage reconnaissance, suggesting the attackers were fingerprinting compromised environments before deploying further payloads.

### 4. Anti-Forensic Activity

Attackers engaged in log tampering to cover their tracks:
- Deletion or unexpected truncation of `server.log` (PaperCut main application log)
- Deletion of `/data/internal/derby.log` (embedded database log)
- File `Udydn.out` created in the `/data/content/` directory relative to the PaperCut installation

### 5. Platform-Specific Behavior

#### Windows
- Primary exploitation target with `pc-app.exe` as the parent process for post-exploitation commands
- Java .class payloads executed within the Application Server JVM context
- Reconnaissance via `cmd.exe` spawned from `pc-app.exe`

#### Linux
- The JDBC class loading vulnerability is platform-agnostic (Java-based)
- Linux installations are equally vulnerable; exploitation artifacts would appear under the PaperCut installation directory
- Reconnaissance commands would differ (e.g., `id`, `uname -a` instead of `whoami & ver`)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows/Linux | `<install>/data/content/Udydn.out` | Not published | Exploitation artifact file created during CVE-2026-82078 exploitation |
| Windows/Linux | `<install>/server.log` | N/A | May be deleted, truncated, or tampered with post-exploitation |
| Windows/Linux | `<install>/data/internal/derby.log` | N/A | May be deleted post-exploitation |

### Network

No concrete network IOCs (IP addresses, domains, URLs, C2 infrastructure) have been published in the analyzed sources as of this report.

### Behavioral

**Process Execution Chain (Windows):**
- `pc-app.exe` spawning `cmd.exe` with command-line arguments containing `whoami`, `ver`, and/or `tasklist`
- This parent-child relationship is highly anomalous for PaperCut Application Server

**Log File Indicators:**
- Error string in server.log: `ERROR No suitable driver found for jdbc:no:x`
- Error string in server.log: `ERROR DatabaseUtils - Database error looking up cardID: VALUES CAST`
- Missing or unexpectedly truncated server.log files
- Missing derby.log from the data/internal directory

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of internet-exposed PaperCut NG/MF web management interface via CVE-2026-81578 and CVE-2026-82078 |
| T1059.003 | Windows Command Shell | Post-exploitation commands executed via cmd.exe spawned from pc-app.exe |
| T1082 | System Information Discovery | OS enumeration via `ver` command |
| T1033 | System Owner/User Discovery | User identification via `whoami` command |
| T1057 | Process Discovery | Running process enumeration via `tasklist` command |
| T1070 | Indicator Removal | Deletion and truncation of server.log and derby.log to cover exploitation traces |

## Impact Assessment

**Breadth:** Approximately 1,000 PaperCut NG/MF instances are exposed to the internet, primarily in North America and Europe. All unpatched versions of both NG and MF are affected. The software is widely deployed across universities, corporations, and government entities.

**Depth:** The vulnerability chain provides unauthenticated remote code execution at the privilege level of the PaperCut Application Server process. This grants access to the server's file system, network position (often internal), Active Directory integration, and potentially stored print job data.

**Stealth:** Attackers actively delete and truncate log files to hinder forensic analysis. The exploitation artifacts (JDBC error messages) may blend with legitimate database errors if not specifically monitored.

**Historical Precedent:** Prior PaperCut vulnerabilities (CVE-2023-27350, CVSS 9.8) were exploited by Russian threat actors and financially motivated groups including Lace Tempest (deploying Cl0p and LockBit ransomware) and the Bl00dy ransomware gang. CISA's Known Exploited Vulnerabilities catalog includes previous PaperCut entries. This represents at least the fourth exploited PaperCut vulnerability.

## Detection & Remediation

### Immediate Detection

Defenders should check for these indicators immediately:

1. **Check for exploitation artifact:**
   ```
   # Windows
   dir /s /b "C:\Program Files\PaperCut*\data\content\Udydn.out"
   
   # Linux
   find /opt/papercut* /usr/local/papercut* -name "Udydn.out" 2>/dev/null
   ```

2. **Check for JDBC exploitation errors in server.log:**
   ```
   # Windows
   findstr /i "jdbc:no:x" "C:\Program Files\PaperCut*\server\logs\server.log"
   findstr /i "cardID: VALUES CAST" "C:\Program Files\PaperCut*\server\logs\server.log"
   
   # Linux
   grep -r "jdbc:no:x\|cardID: VALUES CAST" /opt/papercut*/server/logs/server.log
   ```

3. **Check for missing/truncated logs:**
   ```
   # Check if server.log is unusually small or missing
   # Check if data/internal/derby.log has been deleted
   ```

4. **Review process execution history for suspicious pc-app.exe child processes** (requires Sysmon or EDR telemetry)

### Remediation

1. **Immediate:** Apply the emergency patch for your PaperCut version (v25 or v26). The improved patch released 2026-08-29 should be preferred over the initial 2026-08-28 patch.
2. **Urgent:** Remove PaperCut Application Server from direct internet exposure. Place behind a VPN or reverse proxy with IP allowlisting.
3. **Restrict:** Block untrusted internet addresses from reaching the web management interface, even if no suspicious activity has been observed.
4. **Investigate:** Review server.log and derby.log for exploitation indicators. Check for the Udydn.out artifact file.
5. **Monitor:** Deploy the detection rules below and monitor for suspicious pc-app.exe child process activity.

### Long-Term Hardening

- Never expose PaperCut Application Server directly to the internet
- Restrict the web management interface to trusted internal IP ranges or VPN-only access
- Implement application allowlisting to prevent unexpected processes from being spawned by pc-app.exe
- Enable comprehensive logging (Sysmon on Windows, auditd on Linux) with centralized log collection to prevent anti-forensic log deletion
- Maintain rapid patching cadence for PaperCut -- this is the fourth exploited vulnerability in the product

## Detection Rules

These detections target the specific artifacts and behaviors observed during CVE-2026-81578/CVE-2026-82078 chained exploitation of PaperCut NG/MF. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles != fires -- verify in your SIEM pipeline.

### Sigma: PaperCut Application Server Spawning Reconnaissance Commands
Detects pc-app.exe spawning command shells with whoami/tasklist reconnaissance commands, the specific post-exploitation pattern observed in the wild.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (excluding attacktag — MITRE data unreachable in build env); splunk convert 0; log_scale convert 0. Keys on ParentImage=pc-app.exe + CommandLine whoami/tasklist — tight, distinctive parent-child relationship. FP: legitimate PaperCut maintenance scripts spawning system commands (rare). Evasion: attacker uses a different parent process name or encoded commands. -->
```yaml
title: PaperCut Application Server Spawning Reconnaissance Commands
id: 7f3a1b2c-9d4e-4f5a-8b6c-1e2d3f4a5b6c
status: experimental
description: >
    Detects PaperCut Application Server process (pc-app.exe) spawning command
    shell processes executing reconnaissance commands such as whoami, ver, and
    tasklist, consistent with post-exploitation activity observed during
    CVE-2026-81578 and CVE-2026-82078 chained exploitation.
references:
    - https://www.papercut.com/kb/Main/PO-1216-and-PO-1219
    - https://thehackernews.com/2026/08/attackers-chain-two-papercut-flaws-to.html
    - https://www.securityweek.com/papercut-releases-emergency-patch-for-exploited-zero-day/
author: Actioner
date: 2026/08/29
tags:
    - attack.t1190
    - attack.t1059.003
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\pc-app.exe'
    selection_cmd:
        CommandLine|contains:
            - 'whoami'
            - 'tasklist'
    condition: selection_parent and selection_cmd
falsepositives:
    - Legitimate PaperCut maintenance scripts that invoke system enumeration commands
level: high
```

### Sigma: PaperCut Exploitation Artifact File Creation - Udydn.out
Detects creation of Udydn.out, the distinctive file artifact dropped during CVE-2026-82078 JDBC class loading exploitation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk convert 0; log_scale convert 0. Keys on TargetFilename ending in \Udydn.out — highly distinctive filename with no known benign use. Requires Sysmon EID 11 or equivalent file creation telemetry. -->
```yaml
title: PaperCut Exploitation Artifact File Creation - Udydn.out
id: 9a8b7c6d-5e4f-3a2b-1c0d-ef9a8b7c6d5e
status: experimental
description: >
    Detects creation of the file Udydn.out, a known artifact dropped during
    exploitation of PaperCut NG/MF via CVE-2026-82078 unsafe dynamic class
    loading. The file is created in the PaperCut data/content directory.
references:
    - https://thehackernews.com/2026/08/attackers-chain-two-papercut-flaws-to.html
    - https://www.papercut.com/kb/Main/PO-1216-and-PO-1219
author: Actioner
date: 2026/08/29
tags:
    - attack.t1190
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\Udydn.out'
    condition: selection
falsepositives:
    - Unknown
level: critical
```

### Sigma: PaperCut Server Log File Deletion
Detects deletion of PaperCut server.log or derby.log files within a PaperCut installation directory, the anti-forensic log tampering observed during exploitation.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk convert 0; log_scale convert 0. Requires Sysmon EID 23/26 file deletion telemetry. Medium confidence: server.log/derby.log are common names; the PaperCut/papercut path filter reduces FP but legitimate log rotation could match. -->
```yaml
title: PaperCut Server Log File Deletion
id: 4b5c6d7e-8f9a-0b1c-2d3e-4f5a6b7c8d9e
status: experimental
description: >
    Detects deletion of PaperCut server.log or derby.log files within a
    PaperCut installation directory, consistent with anti-forensic log
    tampering observed during CVE-2026-81578/CVE-2026-82078 exploitation.
references:
    - https://www.securityweek.com/papercut-releases-emergency-patch-for-exploited-zero-day/
    - https://thehackernews.com/2026/08/attackers-chain-two-papercut-flaws-to.html
author: Actioner
date: 2026/08/29
tags:
    - attack.t1070
logsource:
    category: file_delete
    product: windows
detection:
    selection_file:
        TargetFilename|endswith:
            - '\server.log'
            - '\derby.log'
    selection_path:
        TargetFilename|contains:
            - 'PaperCut'
            - 'papercut'
    condition: selection_file and selection_path
falsepositives:
    - Legitimate PaperCut log rotation or maintenance operations
level: high
```

### Sigma: PaperCut JDBC Driver Exploitation Indicators in Application Logs
Detects the specific JDBC error strings produced when CVE-2026-82078 is exploited to load arbitrary driver classes. Scope to PaperCut application log ingestion.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk convert 0; log_scale convert 0. Custom logsource category:application — requires mapping to whatever index/source ingests PaperCut server.log. Keywords are highly distinctive error strings directly from exploitation. -->
```yaml
title: PaperCut JDBC Driver Exploitation Indicators in Application Logs
id: 2c3d4e5f-6a7b-8c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: >
    Detects specific error strings in PaperCut application logs indicative of
    CVE-2026-82078 exploitation through unsafe JDBC driver class loading.
    These error patterns appear when an attacker manipulates the database
    driver configuration to trigger arbitrary class instantiation.
references:
    - https://thehackernews.com/2026/08/papercut-zero-day-exploited-in-attacks.html
    - https://thehackernews.com/2026/08/attackers-chain-two-papercut-flaws-to.html
    - https://www.papercut.com/kb/Main/PO-1216-and-PO-1219
author: Actioner
date: 2026/08/29
tags:
    - attack.t1190
logsource:
    category: application
detection:
    selection:
        - 'No suitable driver found for jdbc:no:x'
        - 'Database error looking up cardID: VALUES CAST'
    condition: selection
falsepositives:
    - Legitimate database driver misconfiguration generating similar error text
level: critical
```

### Snort: N/A
No concrete network indicators (IPs, domains, URLs, C2 infrastructure, or HTTP request patterns) have been published for this campaign. The exploitation occurs over the PaperCut web management interface but specific URI paths and request structures have not been disclosed.

### Suricata: N/A
No concrete network indicators (IPs, domains, URLs, JA3 hashes, TLS fingerprints) have been published for this campaign.

### YARA: PaperCut CVE-2026-82078 Exploitation Artifacts
Detects files containing the distinctive JDBC error strings and reconnaissance command patterns associated with CVE-2026-82078 exploitation.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive sample: file with published error strings "Database error looking up cardID: VALUES CAST" and "No suitable driver found for jdbc:no:x" — fired. Negative sample: benign PaperCut log messages — quiet. Strings are from published advisory IOCs (The Hacker News / Huntress). -->
```yara
rule PaperCut_CVE_2026_82078_Exploitation_Artifacts
{
    meta:
        description = "Detects artifacts associated with PaperCut NG/MF CVE-2026-82078 exploitation including the Udydn.out payload marker and JDBC exploitation error strings"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://thehackernews.com/2026/08/attackers-chain-two-papercut-flaws-to.html"

    strings:
        $jdbc_error = "No suitable driver found for jdbc:no:x" ascii wide
        $db_error = "Database error looking up cardID: VALUES CAST" ascii wide
        $recon_cmd1 = "whoami & ver" ascii
        $recon_cmd2 = "whoami & ver & tasklist" ascii

    condition:
        any of them
}

rule PaperCut_Udydn_Payload_File
{
    meta:
        description = "Detects the Udydn.out file dropped by PaperCut CVE-2026-82078 exploitation in the data/content directory"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://thehackernews.com/2026/08/attackers-chain-two-papercut-flaws-to.html"

    strings:
        $path_marker1 = "data/content/Udydn.out" ascii wide nocase
        $path_marker2 = "data\\content\\Udydn.out" ascii wide nocase

    condition:
        any of them
}
```

## Lessons Learned

This incident reinforces several recurring themes in enterprise security:

1. **Print management is critical infrastructure.** PaperCut's position as an internet-facing pivot into corporate environments with access to printed documents and Active Directory integration makes it a high-value target. This is the fourth exploited PaperCut vulnerability, following exploitation by nation-state actors and ransomware groups.

2. **Authentication bypass + class loading = classic RCE chain.** The pattern of chaining an authentication bypass with an unsafe deserialization or class loading vulnerability to achieve RCE without credentials is well-established (cf. Exchange ProxyShell, MOVEit). Java applications that dynamically load classes based on configuration values are particularly susceptible.

3. **Anti-forensics start immediately.** Attackers deleted server.log and derby.log before conducting further operations, emphasizing the need for centralized, append-only log collection that cannot be tampered with from the application host.

4. **Initial patches may be insufficient.** The first patch on August 28 proved inadequate, requiring a revised patch on August 29. Organizations should monitor for patch revisions and not assume the first fix is complete.

## Sources

- [PaperCut Security Advisory PO-1216 and PO-1219](https://www.papercut.com/kb/Main/PO-1216-and-PO-1219) — Vendor security bulletin with patch information and urgent advisory
- [The Record: PaperCut warns of hackers using printer management vulnerabilities](https://therecord.media/papercut-warns-of-hackers-using-printer-management-vulnerabilities) — CVE details, Huntress/watchTowr attribution, patch timeline, and historical context
- [SecurityWeek: PaperCut Releases Emergency Patch for Exploited Zero-Day](https://www.securityweek.com/papercut-releases-emergency-patch-for-exploited-zero-day/) — Huntress analysis details, IOC indicators, exposure statistics
- [The Hacker News: PaperCut Zero-Day Exploited in Attacks](https://thehackernews.com/2026/08/papercut-zero-day-exploited-in-attacks.html) — Log-based IOCs, detection error strings, patching guidance
- [The Hacker News: Attackers Chain Two PaperCut Flaws to Execute Code](https://thehackernews.com/2026/08/attackers-chain-two-papercut-flaws-to.html) — Technical attack chain details, CVE descriptions, file artifacts, post-exploitation commands

---
*Report generated by Actioner*
