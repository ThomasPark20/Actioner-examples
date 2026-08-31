# Technical Analysis Report: HOOKEDGE Backdoor — APT28/BlueDelta (2026-08-31)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-31
Version: 1.1 (REVISED)

## Executive Summary

HOOKEDGE is a lightweight backdoor attributed with moderate confidence to APT28/BlueDelta (Recorded Future) that targets European government and diplomatic organizations in Romania, Spain, and Turkiye. The campaign was active from September 2025 through April 2026, with public documentation by Recorded Future on August 28, 2026. HOOKEDGE is delivered via spear-phishing with macro-enabled Microsoft Word documents using diplomatic-themed lures impersonating the Spanish government. The backdoor abuses webhook[.]site -- a legitimate shared webhook testing service -- for command-and-control, payload staging, and exfiltration, making network-level detection inherently high in false positives. A distinguishing tradecraft feature is the use of Microsoft Edge in headless/hidden mode to perform HTTP requests to webhook[.]site endpoints, avoiding the need for custom HTTP client code. HOOKEDGE shares significant code and tradecraft overlap with HEADLACE, a previously documented APT28 backdoor, including the shared abuse of webhook[.]site infrastructure. The execution chain establishes persistence via Windows scheduled tasks with 30-minute (Stage 1) and 5-minute (Stage 2) recurrence intervals, uses .cmd batch payloads for command execution, and performs cleanup by deleting task definition files and temporary output files after each cycle.

## Background: Targeted Organizations

APT28 (also tracked as Fancy Bear, Forest Blizzard, Sofacy, Pawn Storm, and BlueDelta) is a Russian military intelligence (GRU Unit 26165) cyber espionage group that has been active since at least 2004. HOOKEDGE targets European government and diplomatic entities -- specifically in Romania, Spain, and Turkiye -- consistent with Russia's strategic intelligence collection priorities related to NATO and EU geopolitical dynamics. The use of diplomatic-themed lures impersonating the Spanish government indicates targeting of diplomatic personnel and government officials with access to sensitive policy communications. This targeting pattern aligns with APT28's documented history of operations against European government institutions.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| September 2025 | Earliest observed HOOKEDGE campaign activity |
| September 2025 -- April 2026 | Active campaign period targeting Romania, Spain, Turkiye |
| April 2026 | Last observed HOOKEDGE activity |
| August 28, 2026 | [Recorded Future publishes HOOKEDGE analysis](https://thehackernews.com/2026/08/apt28-linked-hookedge-backdoor-targets.html) with APT28/BlueDelta attribution |

## Technical Analysis of the Malicious Payload

### 1. Initial Access: Spear-Phishing with Macro-Enabled Documents (T1566.001)

HOOKEDGE delivery begins with spear-phishing emails carrying macro-enabled Microsoft Word documents (.docm) with diplomatic-themed lure content impersonating the Spanish government. The lures are designed to appear as legitimate diplomatic correspondence or policy documents, enticing the target to enable macros (T1204.002).

### 2. Macro Execution and File Staging

Upon enabling macros, the embedded VBA code writes six files to the `%userprofile%` directory. These files constitute the HOOKEDGE backdoor components, including batch scripts (.cmd) that will be executed by scheduled tasks for C2 communication and command execution.

### 3. Persistence via Scheduled Tasks (T1053.005)

The macro creates two scheduled tasks with distinct recurrence intervals:

- **Stage 1 task**: Runs every 30 minutes -- serves as the initial C2 beacon and payload retrieval mechanism
- **Stage 2 task**: Runs every 5 minutes -- provides more frequent communication for active command execution

After task creation, the task definition files are deleted to reduce forensic artifacts on disk.

### 4. C2 Communication via Edge Headless Mode

HOOKEDGE launches Microsoft Edge (`msedge.exe`) in headless or hidden mode to perform HTTP requests to webhook[.]site endpoints. This technique:

- **Avoids custom HTTP client code** that might be flagged by endpoint detection
- **Blends with legitimate browser traffic** at the process level
- **Leverages Edge's TLS implementation** for encrypted communications
- **Avoids dropping additional binaries** -- the entire C2 stack uses native Windows components and the pre-installed Edge browser

The Edge process fetches .cmd payload files from webhook[.]site, which contain commands to execute on the target system.

### 5. Command Execution and Output Exfiltration

Retrieved .cmd payloads are executed on the target host, with output captured to an HTML file. The output is then exfiltrated back to webhook[.]site via another Edge headless request. After transmission, the temporary HTML output file and .cmd payload file are deleted from disk, leaving minimal forensic trace.

### 6. Process Cleanup

After each execution cycle, HOOKEDGE terminates processes matching the task identifier to prevent process accumulation and reduce detection surface.

### 7. Anti-Forensics / Evasion Techniques

- **Task definition deletion**: Scheduled task XML files deleted after creation
- **Temporary file cleanup**: .cmd payloads and HTML output files deleted post-execution
- **Process termination**: Active cleanup of identifiable processes
- **Legitimate service abuse**: webhook[.]site is a widely used legitimate service, making domain/URL blocking impractical
- **Living-off-the-land**: Uses cmd.exe, schtasks.exe, and msedge.exe -- all legitimate Windows binaries
- **Obfuscation**: Files/commands employ deobfuscation techniques at runtime (T1140, T1027)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots

### Infrastructure

| Type | Value | Context |
|------|-------|---------|
| C2 Domain | `webhook[.]site` | Shared legitimate service abused for C2, staging, and exfiltration -- **do not block without careful impact assessment** |

> **IMPORTANT**: webhook[.]site is a legitimate shared web service used by developers worldwide for webhook testing. It is not attacker-controlled infrastructure. Blocking this domain will cause collateral impact on legitimate development and QA workflows. Network detections against this domain carry extremely high false-positive risk.

### Behavioral

- **Macro-enabled Word documents** (.docm) with diplomatic-themed content impersonating the Spanish government
- **Six files written to `%userprofile%`** upon macro execution, including .cmd batch files
- **Scheduled task creation** with 30-minute (Stage 1) and 5-minute (Stage 2) recurrence intervals
- **Microsoft Edge (`msedge.exe`) launched in headless/hidden mode** without user interaction, particularly when spawned by `cmd.exe` or a scheduled task
- **Edge making HTTP requests to `webhook[.]site`** endpoints -- unusual for non-interactive Edge sessions
- **Orphaned scheduled tasks** referencing batch files in `%userprofile%` after task definition files are deleted

### File Artifacts

| Artifact | Location | Context |
|----------|----------|---------|
| Macro-enabled .docm lure | Email attachment | Initial delivery vector |
| .cmd batch files | `%userprofile%\` | C2 payload scripts fetched from webhook[.]site |
| HTML output file | `%userprofile%\` (temporary) | Command output staging before exfiltration |
| Six staged files | `%userprofile%\` | Backdoor components written by macro |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.001 | Phishing: Spearphishing Attachment | Macro-enabled Word documents with diplomatic lures delivered via email |
| T1204.002 | User Execution: Malicious File | Target must enable macros to initiate HOOKEDGE deployment |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence via two scheduled tasks (30-min and 5-min intervals) |
| T1140 | Deobfuscate/Decode Files or Information | Runtime deobfuscation of staged files and commands |
| T1027 | Obfuscated Files or Information | Obfuscation of dropped files and macro content |
| T1567 | Exfiltration Over Web Service | Command output exfiltrated via webhook[.]site |
| T1005 | Data from Local System | Collection of local system data via executed commands |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | .cmd batch file execution for command delivery |

## Impact Assessment

**Breadth**: HOOKEDGE targets a specific set of European diplomatic and government organizations (Romania, Spain, Turkiye). The campaign appears tightly scoped rather than opportunistic, consistent with APT28's strategic intelligence collection mandate.

**Depth**: Full command execution capability on compromised hosts via the scheduled task and Edge headless C2 loop. The 5-minute polling interval for Stage 2 provides near-real-time interactive access for the operators. Data from local systems can be collected and exfiltrated through the same channel.

**Stealth**: The combination of living-off-the-land binaries (cmd.exe, schtasks.exe, msedge.exe), legitimate C2 infrastructure (webhook[.]site), and aggressive file cleanup makes HOOKEDGE difficult to detect through traditional IOC-based methods. Detection requires behavioral analysis of process relationships and scheduled task patterns.

**Attribution**: Moderate confidence link to APT28/BlueDelta per Recorded Future, based on significant code and tradecraft overlap with the HEADLACE backdoor and shared abuse of webhook[.]site for C2 communications. HEADLACE was previously attributed to APT28 with high confidence.

## Detection & Remediation

### Immediate Detection

1. **Search for Edge headless processes** spawned by non-interactive parents:
   ```powershell
   Get-WmiObject Win32_Process -Filter "Name='msedge.exe'" | ForEach-Object { $parent = Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue; if ($parent.Name -ne 'msedge') { $_ | Select ProcessId, CommandLine, ParentProcessId } }
   ```
2. **Audit scheduled tasks** for entries referencing .cmd/.bat files in `%userprofile%` with short recurrence intervals:
   ```powershell
   Get-ScheduledTask | Where-Object { $_.Actions.Execute -like "*\Users\*" -and ($_.Actions.Execute -like "*.cmd" -or $_.Actions.Execute -like "*.bat") }
   ```
3. **Review user profile directories** for unexpected .cmd files or recently created batches of files:
   ```powershell
   Get-ChildItem "$env:USERPROFILE\*.cmd" -ErrorAction SilentlyContinue
   ```
4. **Check for orphaned scheduled tasks** whose task definition XML files no longer exist on disk

### Remediation

1. **Remove malicious scheduled tasks** and all associated files from `%userprofile%`
2. **Terminate any Edge headless processes** spawned by non-interactive sessions
3. **Block macro execution** in Microsoft Word documents from external/untrusted sources via Group Policy
4. **Network monitoring**: While blocking webhook[.]site is impractical due to legitimate use, monitor for Edge headless processes making requests to webhook[.]site endpoints as a high-fidelity behavioral indicator
5. **Credential rotation**: Assume credentials cached on compromised endpoints are compromised
6. **Hunt across the environment** for the behavioral patterns described above, not just specific file hashes

### Long-Term Hardening

- Disable macros for documents originating from the internet (Mark of the Web enforcement)
- Implement application control policies that alert on Edge headless mode invocations outside of approved CI/CD contexts
- Deploy Sysmon with process creation logging to capture parent-child process relationships
- Monitor scheduled task creation events (Windows Event ID 4698) for batch files in user profile directories
- Consider webhook[.]site traffic monitoring as a supplementary indicator when correlated with other HOOKEDGE behavioral patterns

## Detection Rules

Three Sigma rules at medium level cover HOOKEDGE behavioral indicators: Edge headless process spawning (low confidence -- generic behavioral), scheduled task creation with short recurrence (medium confidence), and a parent-child correlation for cmd.exe-spawned Edge headless from user profile batch scripts (medium confidence). Network rules (Snort/Suricata) and file-level rules (YARA) are not applicable because webhook[.]site is legitimate shared infrastructure (network rules would produce unacceptable false positives) and no file-level indicators with distinct strings were provided in the source reporting. All three Sigma rules target Windows process creation events; Rules 1 and 2 work with Sysmon EID 1 or Windows 4688 with command-line auditing, while Rule 3 requires Sysmon EID 1 (ParentCommandLine is not available in 4688).

### Sigma Rule 1 -- Microsoft Edge Headless Mode Spawned Without User Interaction

Detects Microsoft Edge launched in headless or hidden mode, matching the HOOKEDGE C2 communication technique. Legitimate Edge headless usage in CI/CD or automated testing should be baselined and excluded.
**Status**: `sigma check` pass (0 errors) | `sigma convert` pass (Splunk, LogScale) | Confidence: low (generic behavioral rule with no HOOKEDGE-distinguishing element)

<!-- audit:
sigma check: pass (0 errors, 0 issues; attacktag validator excluded due to network restriction in validation environment - does not affect rule correctness)
sigma convert --without-pipeline -t splunk: Image IN ("*\\msedge.exe", "*\\msedge_proxy.exe") CommandLine IN ("*--headless*", "*--window-position=-32000*", "*--window-size=1,1*") NOT ParentImage="*\\msedge.exe"
sigma convert --without-pipeline -t log_scale: Image=/\\msedge\.exe$/i or Image=/\\msedge_proxy\.exe$/i CommandLine=/--headless/i or CommandLine=/--window-position=-32000/i or CommandLine=/--window-size=1,1/i not ParentImage=/\\msedge\.exe$/i
logsource: process_creation/windows; Sysmon EID 1 or Windows 4688 with command-line auditing
FP: CI/CD systems, automated testing frameworks, RPA tools using Edge headless; filter by ParentImage or environment
revision: removed attack.t1218 (Edge is not a T1218 sub-technique), downgraded level high→medium, confidence low
-->

```yaml
title: Microsoft Edge Headless Mode Spawned Without User Interaction (HOOKEDGE)
id: a1c3e5f7-2b4d-4a6c-8e0f-1d3b5c7a9e2f
status: experimental
description: >
    Detects Microsoft Edge launched in headless or hidden mode, a technique
    used by the HOOKEDGE backdoor (APT28/BlueDelta) to silently communicate
    with webhook[.]site C2 infrastructure. Legitimate Edge headless usage
    (CI/CD, automated testing) should be baselined and excluded.
references:
    - https://thehackernews.com/2026/08/apt28-linked-hookedge-backdoor-targets.html
author: Actioner
date: 2026/08/31
tags:
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_edge:
        Image|endswith:
            - '\msedge.exe'
            - '\msedge_proxy.exe'
    selection_headless:
        CommandLine|contains:
            - '--headless'
            - '--window-position=-32000'
            - '--window-size=1,1'
    filter_parent_edge:
        ParentImage|endswith: '\msedge.exe'
    condition: selection_edge and selection_headless and not filter_parent_edge
falsepositives:
    - Legitimate automated testing frameworks using Edge in headless mode
    - CI/CD pipelines invoking headless Edge for rendering or screenshot tasks
level: medium
```

### Sigma Rule 2 -- Scheduled Task With Short Recurrence From User Profile Script

Detects scheduled task creation with 5-minute or 30-minute recurrence intervals referencing batch files in user profile directories, matching HOOKEDGE persistence. Higher FP risk in environments with administrative scripts stored in user profiles.
**Status**: `sigma check` pass (0 errors) | `sigma convert` pass (Splunk, LogScale) | Confidence: medium

<!-- audit:
sigma check: pass (0 errors, 0 issues; attacktag excluded)
sigma convert --without-pipeline -t splunk: Image="*\\schtasks.exe" CommandLine="*/create*" CommandLine IN ("*/mo 5 *", "*/mo 30 *") CommandLine IN ("*%userprofile%*", "*\\Users\\*") CommandLine IN ("*.cmd*", "*.bat*")
sigma convert --without-pipeline -t log_scale: Image=/\\schtasks\.exe$/i CommandLine=/\/create/i CommandLine=/\/mo 5 /i or CommandLine=/\/mo 30 /i CommandLine=/%userprofile%/i or CommandLine=/\\Users\\/i CommandLine=/\.cmd/i or CommandLine=/\.bat/i
logsource: process_creation/windows; Sysmon EID 1 or Windows 4688
FP: Legitimate admin scripts using schtasks with short intervals from user directories; tune with environment-specific exclusions
revision: fixed /mo 5 substring match (added trailing space to prevent matching /mo 50, /mo 55 etc.), downgraded level high→medium
-->

```yaml
title: Scheduled Task With Short Recurrence From User Profile Script (HOOKEDGE)
id: b2d4f6a8-3c5e-4b7d-9f1a-2e4c6d8b0a3f
status: experimental
description: >
    Detects scheduled task creation with 5-minute or 30-minute recurrence
    intervals that reference batch files in the user profile directory,
    matching the HOOKEDGE backdoor persistence mechanism used by
    APT28/BlueDelta.
references:
    - https://thehackernews.com/2026/08/apt28-linked-hookedge-backdoor-targets.html
author: Actioner
date: 2026/08/31
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    selection_recurrence:
        CommandLine|contains:
            - '/mo 5 '
            - '/mo 30 '
    selection_userprofile:
        CommandLine|contains:
            - '%userprofile%'
            - '\Users\'
    selection_script:
        CommandLine|contains:
            - '.cmd'
            - '.bat'
    condition: selection_schtasks and selection_recurrence and selection_userprofile and selection_script
falsepositives:
    - Legitimate administrative scripts using schtasks with short recurrence from user directories
    - Software update mechanisms running from user profile paths
level: medium
```

### Sigma Rule 3 -- Edge Headless Spawned by Batch Script From User Profile

Detects msedge.exe launched in headless mode as a child of cmd.exe executing a batch script from the user profile directory, matching the HOOKEDGE parent-child execution chain. Caveat: requires Sysmon EID 1 (Windows 4688 does not populate ParentCommandLine).
**Status**: `sigma check` pass (0 errors) | `sigma convert` pass (Splunk, LogScale) | Confidence: medium

<!-- audit:
sigma check: pass (0 errors, 0 issues; attacktag excluded)
sigma convert --without-pipeline -t splunk: Image IN ("*\\msedge.exe", "*\\msedge_proxy.exe") CommandLine IN ("*--headless*", "*--window-position=-32000*", "*--window-size=1,1*") ParentImage="*\\cmd.exe" ParentCommandLine IN ("*%userprofile%*", "*\\Users\\*") ParentCommandLine IN ("*.cmd*", "*.bat*")
sigma convert --without-pipeline -t log_scale: Image=/\\msedge\.exe$/i or Image=/\\msedge_proxy\.exe$/i CommandLine=/--headless/i or CommandLine=/--window-position=-32000/i or CommandLine=/--window-size=1,1/i ParentImage=/\\cmd\.exe$/i ParentCommandLine=/%userprofile%/i or ParentCommandLine=/\\Users\\/i ParentCommandLine=/\.cmd/i or ParentCommandLine=/\.bat/i
logsource: process_creation/windows; Sysmon EID 1 (ParentCommandLine not available in Windows 4688)
FP: Developer workflows invoking Edge headless from batch scripts in user directories — uncommon but possible
revision: restructured from cmd.exe CommandLine containing "msedge"/"headless" (detection gap — those strings are inside the batch file, not on the cmd.exe command line) to parent-child correlation (cmd.exe parent → msedge.exe child); downgraded level high→medium
-->

```yaml
title: Edge Headless Spawned by Batch Script From User Profile (HOOKEDGE)
id: c3e5a7b9-4d6f-4c8e-a0b2-3f5d7e9c1b4a
status: experimental
description: >
    Detects Microsoft Edge launched in headless mode as a child of cmd.exe,
    where the parent command line references a batch script in the user
    profile directory. This parent-child pattern matches the HOOKEDGE
    backdoor execution chain used by APT28/BlueDelta.
references:
    - https://thehackernews.com/2026/08/apt28-linked-hookedge-backdoor-targets.html
author: Actioner
date: 2026/08/31
tags:
    - attack.t1059.003
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_child:
        Image|endswith:
            - '\msedge.exe'
            - '\msedge_proxy.exe'
        CommandLine|contains:
            - '--headless'
            - '--window-position=-32000'
            - '--window-size=1,1'
    selection_parent:
        ParentImage|endswith: '\cmd.exe'
        ParentCommandLine|contains:
            - '%userprofile%'
            - '\Users\'
    selection_parent_script:
        ParentCommandLine|contains:
            - '.cmd'
            - '.bat'
    condition: selection_child and selection_parent and selection_parent_script
falsepositives:
    - Developer scripts that invoke Edge headless from user profile directories
    - Automated testing frameworks stored in user directories
level: medium
```

### Snort/Suricata Rules

**N/A** -- webhook[.]site is a shared legitimate service used by developers worldwide. Network-level rules matching traffic to/from webhook[.]site would produce unacceptable false positive rates and are not recommended. The domain cannot be treated as malicious infrastructure. Behavioral detection at the endpoint level (Sigma rules above) is the appropriate detection layer for HOOKEDGE.

### YARA Rules

**N/A** -- The source reporting does not provide file-level indicators with distinct byte patterns, string constants, or structural characteristics sufficient for YARA rule authoring. The malware uses batch scripts (.cmd) and relies on living-off-the-land binaries, making file-level signatures impractical without access to specific samples. YARA rules should be developed if/when malware samples or detailed file-level IOCs become available.

## Lessons Learned

1. **Legitimate service abuse defeats domain-based detection.** HOOKEDGE's use of webhook[.]site for C2 renders traditional IOC blocklists and network signatures ineffective. Organizations must invest in behavioral detection -- particularly process creation monitoring and scheduled task auditing -- rather than relying on domain/IP reputation feeds for threats that abuse shared infrastructure.

2. **Living-off-the-land browser abuse is expanding.** The use of Microsoft Edge in headless mode for C2 communication represents an evolution beyond traditional LOLBin abuse (certutil, bitsadmin, mshta). Organizations should monitor for non-interactive browser invocations, particularly when spawned by scripts or scheduled tasks rather than user-initiated sessions.

3. **Macro-based delivery persists against targeted organizations.** Despite years of hardening guidance, macro-enabled documents remain effective against government and diplomatic targets. Organizations handling sensitive correspondence should enforce Mark-of-the-Web macro blocking and consider application-level sandboxing for documents from external sources.

## Sources

- [The Hacker News -- APT28-Linked HOOKEDGE Backdoor Targets European Government Organizations](https://thehackernews.com/2026/08/apt28-linked-hookedge-backdoor-targets.html) -- primary source article documenting the HOOKEDGE campaign, execution chain, and APT28/BlueDelta attribution
- Recorded Future -- BlueDelta HOOKEDGE Analysis (August 2026) -- underlying research by Recorded Future referenced via the THN article above; documents tradecraft overlap with HEADLACE and webhook[.]site abuse methodology (no separate public URL available at time of writing)

<!-- revision: v1.1 2026-08-31 — (1) Rule 1: removed wrong attack.t1218 tag, level high→medium, confidence noted as low. (2) Rule 2: fixed /mo 5 substring overmatch by adding trailing space, level high→medium. (3) Rule 3: restructured from single-process cmd.exe CommandLine match to parent-child correlation (ParentImage cmd.exe → Image msedge.exe, ParentCommandLine contains userprofile path), level high→medium. (4) Fixed duplicate source URL (Recorded Future entry was identical to THN link). (5) Aligned level/confidence between report prose and YAML. -->

---
*Report generated by Actioner*
