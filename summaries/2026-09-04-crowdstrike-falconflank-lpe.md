# Technical Analysis Report: FalconFlank -- CrowdStrike Falcon Zero-Day Local Privilege Escalation (2026-09-04)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-04
Version: DRAFT 1.0

## Executive Summary

FalconFlank is a publicly disclosed zero-day local privilege escalation (LPE) vulnerability affecting CrowdStrike Falcon Sensor on Windows. Published on approximately 2026-08-26 by security researcher "Chaotic Eclipse" (also known as Nightmare Eclipse, INFINITE NIGHTMARE, MSNightmare), the exploit abuses Falcon's automated "Microsoft Office file malicious macro removal" remediation feature. Because this remediation workflow operates with SYSTEM-level privileges, the exploit tricks it into performing privileged file operations on attacker-controlled content, escalating a standard local user to SYSTEM. The PoC works against fully updated Windows 11 25H2 and Windows Server 2025 systems running CrowdStrike Falcon with Phase 3 Optimal Protection. As of 2026-09-04, CrowdStrike has not confirmed the flaw, assigned a CVE, published a CVSS score, or shipped a patch. No confirmed in-the-wild exploitation has been reported. CrowdStrike has advised customers to disable the "Microsoft Office File Suspicious Macro Removal Windows" policy setting as an interim mitigation, noting that "Cloud Anti-malware for Microsoft Office Files" protection remains active.

FalconFlank is part of a series of antivirus/EDR privilege escalation exploits from the same researcher, including HardBreacher (Kaspersky Endpoint Security), PrettyPrague (Avast Antivirus), and ShieldBreak (Microsoft Defender, bypassing CVE-2026-50656).

## Background: CrowdStrike Falcon Office Macro Remediation

CrowdStrike Falcon Sensor is a widely deployed endpoint detection and response (EDR) platform. Among its automated response capabilities is "Microsoft Office file malicious macro removal," which inspects Office documents for harmful VBA macros and strips suspect code to prevent execution. This remediation runs under the Falcon Sensor service context (SYSTEM privileges) and involves file I/O operations on potentially attacker-controlled Office documents. The feature must be explicitly enabled and is part of Phase 3 Optimal Protection policy configurations. CrowdStrike Falcon is used by hundreds of thousands of organizations globally, making this a high-impact attack surface.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-08-26 | Researcher "Chaotic Eclipse" publishes FalconFlank PoC to GitHub (MSNightmare/FalconFlank) |
| ~2026-08-26 | Researcher also publishes HardBreacher (Kaspersky) and PrettyPrague (Avast) PoCs |
| 2026-09-02 | Blackswan Cybersecurity publishes threat advisory for FalconFlank |
| 2026-09-03 | Multiple security news outlets cover the disclosure (The Hacker News, The Register, Security Affairs, SOCRadar, CybersecurityNews) |
| 2026-09-03 | CrowdStrike advises disabling the macro removal policy setting; references FalconFlank Tech Alert in support portal |
| 2026-09-04 | No CVE assigned; no patch released; no confirmed in-the-wild exploitation |

## Root Cause: Privileged File Operation Abuse in Macro Remediation

The vulnerability stems from CrowdStrike Falcon's macro remediation feature performing privileged file I/O operations that can be redirected by a local attacker. The exploit uses a combination of NTFS junction points (reparse points), opportunistic locks (oplocks), and Windows transactional file operations (TxF) to achieve a race condition that tricks the SYSTEM-privileged Falcon service into writing attacker-controlled content to a protected system directory. This is a variant of the well-known "privileged file operation abuse" class of Windows LPE vulnerabilities, where security software's own remediation actions become the escalation vector.

## Technical Analysis of the Malicious Payload

### 1. Staging: Temporary Directory and Named Pipe Setup

The PoC binary (FalconFlank.cpp, compiled as a C++ PE executable) first creates a temporary staging directory with the prefix `Flanker_` appended with a GUID under the user's `%TEMP%` directory. It creates a named pipe `\\?\pipe\FALCONFLANK` for inter-process synchronization during the race condition exploit. The process is elevated to `HIGH_PRIORITY_CLASS` with threads set to `THREAD_PRIORITY_TIME_CRITICAL` to win the race.

Key API calls in this stage:
- `CreateNamedPipe()` -- IPC pipe for exploit synchronization
- `NtCreateFile()` -- Native API file operations for precise control
- `CreateTransaction()` / `CreateFileTransacted()` / `CommitTransaction()` -- Windows TxF for atomic file operations

### 2. Junction Point and Oplock Race Condition

The exploit creates an NTFS directory junction (mount point reparse point) using `DeviceIoControl()` with `FSCTL_SET_REPARSE_POINT_EX` (control code 259) and `IO_REPARSE_TAG_MOUNT_POINT` (0xA0000003). This junction redirects Falcon's remediation file operations from the expected location to a target system directory. An opportunistic lock (`FSCTL_REQUEST_OPLOCK` with `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE`) is placed on the target to detect when Falcon accesses the file, allowing precise timing of the junction swap.

### 3. Privileged DLL Replacement

When Falcon's remediation workflow processes the crafted Office document, the junction redirection causes the SYSTEM-privileged service to write the attacker's payload DLL to `C:\Windows\System32\WindowsPowerShell\v1.0\bcrypt.dll`. The exploit uses `NtSetInformationFile()`, `CreateFileMapping()`, `MapViewOfFile()`, `SetEndOfFile()`, and `WriteFile()` to replace the legitimate `bcrypt.dll` with a malicious payload embedded in the `FlankerDll` buffer. The PoC also creates `C:\Windows\System32\MY_SNAKE_IS_SOLID.dll` as a verification artifact (confirming SYSTEM-level write access was achieved).

### 4. Privilege Escalation via Scheduled Task

The exploit triggers code execution with the planted DLL by abusing the Windows Task Scheduler. It instantiates `CLSID_TaskScheduler`, accesses the `\Microsoft\Windows\Application Experience` task folder, and runs a scheduled task named `MareBackup`. When this task executes, it loads the replaced `bcrypt.dll` from the PowerShell directory, executing the attacker's payload as SYSTEM.

### 5. Anti-Forensics / Evasion Techniques

The researcher noted that CrowdStrike would likely have detections for the PoC by the time of publication, advising testers to "add it to the exclusions or obfuscate the PoC and change the DLL load technique." This indicates:
- The PoC's current DLL sideloading path (`bcrypt.dll` in the PowerShell directory) is one of potentially many viable targets
- The junction + oplock race condition is the core primitive; the specific DLL target and task scheduler abuse are interchangeable components
- Variants using different DLL targets, different scheduled tasks, or alternative code execution triggers should be anticipated

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | C:\Windows\System32\MY_SNAKE_IS_SOLID.dll | N/A (payload-dependent) | Verification DLL dropped by PoC to confirm SYSTEM write |
| Windows | C:\Windows\System32\WindowsPowerShell\v1.0\bcrypt.dll | N/A (replaced with payload) | Legitimate DLL replaced by exploit payload |
| Windows | %TEMP%\Flanker_\{GUID\} | N/A | Temporary staging directory created by PoC |

### Network

| Type | Value | Context |
|------|-------|---------|
| GitHub Repo | hxxps://github[.]com/MSNightmare/FalconFlank | PoC source code repository |

### Behavioral

- **Named pipe creation:** Process creates named pipe `\\?\pipe\FALCONFLANK` -- distinctive PoC synchronization artifact
- **NTFS junction manipulation:** Low-privileged process creates directory junctions pointing into `C:\Windows\System32\` via `FSCTL_SET_REPARSE_POINT_EX`
- **Oplock race:** Opportunistic locks placed on files in user-controlled directories with `FSCTL_REQUEST_OPLOCK`
- **Transactional NTFS:** Use of `CreateTransaction()` / `CreateFileTransacted()` / `CommitTransaction()` by non-installer processes
- **Task Scheduler abuse:** Programmatic instantiation of `CLSID_TaskScheduler` to run `MareBackup` task under `\Microsoft\Windows\Application Experience`
- **DLL written to System32 by non-system process:** Any process writing DLLs to protected system directories, particularly `bcrypt.dll` in the PowerShell subdirectory
- **SYSTEM process spawned from Falcon services:** Unexpected child processes of CSFalconService or related Falcon sensor processes

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | Core exploit: abusing Falcon's privileged remediation workflow to escalate from standard user to SYSTEM |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Replacing bcrypt.dll in the PowerShell directory to hijack DLL loading by a scheduled task |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Triggering the MareBackup scheduled task to execute the planted DLL as SYSTEM |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Exploiting the security product's own remediation feature as the escalation vector |
| T1106 | Native API | Extensive use of NtCreateFile, NtSetInformationFile, DeviceIoControl for low-level file manipulation |

## Impact Assessment

**Scope:** All organizations running CrowdStrike Falcon Sensor on Windows with the "Microsoft Office file malicious macro removal" feature enabled (Phase 3 Optimal Protection). CrowdStrike Falcon is deployed across hundreds of thousands of organizations globally.

**Severity:** High. Local privilege escalation from standard user to SYSTEM on fully patched Windows 11 25H2 and Windows Server 2025. Requires local code execution (not remotely exploitable). Public PoC code is available.

**Risk factors:**
- Public PoC lowers the barrier to exploitation
- No vendor patch available (zero-day)
- Affects fully updated systems
- Part of a broader pattern of AV/EDR privilege escalation research by the same actor (Kaspersky, Avast, Defender)
- CrowdStrike has not confirmed the vulnerability

## Detection & Remediation

### Immediate Detection

Defenders should monitor for the following on systems running CrowdStrike Falcon:

```powershell
# Check for the PoC verification DLL
Get-Item "C:\Windows\System32\MY_SNAKE_IS_SOLID.dll" -ErrorAction SilentlyContinue

# Check for replaced bcrypt.dll (compare hash to known-good)
Get-FileHash "C:\Windows\System32\WindowsPowerShell\v1.0\bcrypt.dll" -Algorithm SHA256

# Check for Flanker_ temp directories
Get-ChildItem $env:TEMP -Filter "Flanker_*" -Directory -ErrorAction SilentlyContinue

# Check for MareBackup scheduled task
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" | Where-Object {$_.TaskName -eq "MareBackup"}
```

### Remediation

1. **Disable the vulnerable feature (interim mitigation):** In the CrowdStrike Falcon console, disable the "Microsoft Office File Suspicious Macro Removal Windows" policy setting as CrowdStrike has advised. Note: CrowdStrike states "Cloud Anti-malware for Microsoft Office Files" protection remains active.
2. **Review the FalconFlank Tech Alert** in the CrowdStrike support portal for vendor-specific guidance.
3. **Monitor for variants:** The core technique (junction + oplock race against privileged file operations) is reusable; the specific DLL target and execution trigger are interchangeable.
4. **Audit for exploitation artifacts:** Check for the IOCs listed above, particularly `MY_SNAKE_IS_SOLID.dll` and unexplained `bcrypt.dll` modifications.
5. **Await vendor patch:** Monitor CrowdStrike advisories for a formal fix. No CVE has been assigned as of 2026-09-04.

### Long-Term Hardening

- **Least-privilege remediation design:** Security products performing automated file remediation should minimize the privilege level of file I/O operations and validate target paths against junction/symlink redirection.
- **Reparse point monitoring:** Deploy detection for unexpected NTFS junction creation in user-writable directories pointing to protected system paths.
- **DLL integrity monitoring:** Baseline and alert on changes to critical system DLLs in `C:\Windows\System32\` and subdirectories.
- **Principle of least privilege:** Limit local user accounts that could serve as the initial foothold for LPE exploitation.

## Detection Rules

These detections target the distinctive artifacts of the FalconFlank PoC exploit -- named pipe, DLL drop paths, staging directory, and scheduled task abuse. All rules are PoC/advisory-specific (default altitude, strict leniency). Sigma rules convert cleanly to both Splunk SPL and CrowdStrike LogScale; `sigma check` could not be run due to MITRE ATT&CK data fetch being blocked in this environment, but syntactic validity is proven by successful conversion. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: FalconFlank Named Pipe Creation
Detects creation of the `\FALCONFLANK` named pipe used by the PoC for exploit synchronization.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (MITRE ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0. Pipe name is a hardcoded, distinctive PoC artifact with near-zero benign overlap. Requires Sysmon EID 17/18 or equivalent pipe monitoring. -->
```yaml
title: FalconFlank Exploit Named Pipe Creation
id: 7a3c1d8e-4f2b-4e9a-b6d5-8c1f3a2e7b09
status: experimental
description: >
    Detects creation of the named pipe used by the FalconFlank privilege escalation
    PoC targeting CrowdStrike Falcon's Office macro remediation feature.
references:
    - https://github.com/MSNightmare/FalconFlank
    - https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html
author: Actioner
date: 2026/09/04
tags:
    - attack.t1068
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName: '\FALCONFLANK'
    condition: selection
falsepositives:
    - Unlikely - this is a distinctive PoC artifact name
level: critical
```

### Sigma: FalconFlank Suspicious DLL Write to System32
Detects creation of `MY_SNAKE_IS_SOLID.dll` (PoC verification artifact) or writes to the PowerShell `bcrypt.dll` path targeted by the exploit.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (MITRE ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0. MY_SNAKE_IS_SOLID.dll is a unique PoC string. bcrypt.dll write in PS dir is legitimate only during Windows servicing (rare). Requires Sysmon EID 11 or equivalent file-create monitoring. -->
```yaml
title: FalconFlank Suspicious DLL Write to System32
id: 2b4e6f8a-1c3d-5e7f-9a0b-4d6c8e2f1a3b
status: experimental
description: >
    Detects the creation of MY_SNAKE_IS_SOLID.dll in System32 or suspicious DLL writes
    to the PowerShell bcrypt.dll path, both artifacts of the FalconFlank privilege
    escalation exploit against CrowdStrike Falcon.
references:
    - https://github.com/MSNightmare/FalconFlank
    - https://blackswan-cybersecurity.com/threat-advisory-crowdstrike-falcon-sensor-local-privilege-escalation-zero-day-falconflank-august-26-2026/
author: Actioner
date: 2026/09/04
tags:
    - attack.t1068
    - attack.t1574.001
logsource:
    category: file_event
    product: windows
detection:
    selection_snake:
        TargetFilename|endswith: '\MY_SNAKE_IS_SOLID.dll'
    selection_bcrypt:
        TargetFilename: 'C:\Windows\System32\WindowsPowerShell\v1.0\bcrypt.dll'
    condition: selection_snake or selection_bcrypt
falsepositives:
    - Legitimate Windows updates modifying bcrypt.dll in the PowerShell directory (rare)
level: high
```

### Sigma: FalconFlank Exploit Temporary Directory Creation
Detects creation of the `Flanker_` prefixed temporary directory used by the PoC during its exploitation chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (MITRE ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0. "Flanker_" is a distinctive PoC prefix. Potential FP from unrelated software using this prefix (low probability). Requires file event monitoring in user temp directories. -->
```yaml
title: FalconFlank Exploit Temporary Directory Creation
id: 9d1e3f5a-7b2c-4d6e-8f0a-1c3b5d7e9f2a
status: experimental
description: >
    Detects creation of the Flanker_ prefixed temporary directory used by the
    FalconFlank PoC exploit during its privilege escalation chain.
references:
    - https://github.com/MSNightmare/FalconFlank
    - https://socradar.io/blog/falconflank-crowdstrike-falcon-0day-poc/
author: Actioner
date: 2026/09/04
tags:
    - attack.t1068
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Flanker_'
    condition: selection
falsepositives:
    - Software using Flanker_ as a directory or filename prefix
level: high
```

### Sigma: FalconFlank Scheduled Task Abuse
Detects command-line references to the `MareBackup` scheduled task abused by the FalconFlank PoC for SYSTEM code execution.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (MITRE ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0. "MareBackup" is a distinctive PoC task name under Application Experience. Requires process creation logging (Sysmon EID 1 or Windows 4688 with command-line auditing). -->
```yaml
title: FalconFlank Exploit Scheduled Task Abuse
id: 4c6e8a0b-2d4f-6a8c-1e3b-5f7d9a1c3e5b
status: experimental
description: >
    Detects interaction with the MareBackup scheduled task under Application Experience,
    a distinctive artifact of the FalconFlank privilege escalation exploit.
references:
    - https://github.com/MSNightmare/FalconFlank
    - https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html
author: Actioner
date: 2026/09/04
tags:
    - attack.t1068
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'MareBackup'
    condition: selection
falsepositives:
    - Legitimate software using a scheduled task named MareBackup (unlikely)
level: high
```

### YARA: FalconFlank PoC Binary Detection
Detects the compiled FalconFlank PoC binary via distinctive embedded strings (named pipe, DLL targets, task name).
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: yarac not available in this environment. Structural check: valid PE condition, 7 strings with appropriate modifiers, logical condition requiring $pipe AND 3-of-6 supporting strings. Highly distinctive string combination; near-zero FP on benign PE files. -->
```yara
rule Exploit_FalconFlank_PoC
{
    meta:
        description = "Detects FalconFlank PoC exploit binary targeting CrowdStrike Falcon privilege escalation"
        author = "Actioner"
        date = "2026-09-04"
        reference = "https://github.com/MSNightmare/FalconFlank"
        severity = "critical"

    strings:
        $pipe = "FALCONFLANK" ascii wide
        $dll_target = "bcrypt.dll" ascii wide
        $ps_path = "WindowsPowerShell\\v1.0" ascii wide
        $snake = "MY_SNAKE_IS_SOLID" ascii wide
        $flanker = "Flanker_" ascii wide
        $task = "MareBackup" ascii wide
        $task_path = "\\Microsoft\\Windows\\Application Experience" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $pipe and
        3 of ($dll_target, $ps_path, $snake, $flanker, $task, $task_path)
}
```

### Snort: N/A
No network-level indicators suitable for Snort detection. FalconFlank is a local privilege escalation exploit that does not generate distinctive network traffic.

### Suricata: N/A
No network-level indicators suitable for Suricata detection. FalconFlank is a local privilege escalation exploit with no C2 or network communication component.

## Lessons Learned

1. **Security products as attack surface:** Endpoint security tools running with SYSTEM privileges introduce a high-value LPE attack surface. Automated remediation features that perform privileged file I/O on potentially attacker-influenced content are a recurring vulnerability class (see also: Kaspersky HardBreacher, Avast PrettyPrague, Microsoft Defender ShieldBreak from the same researcher).

2. **Race conditions in privileged file operations remain evergreen:** The junction + oplock + TxF technique used by FalconFlank is a well-established Windows LPE primitive. The novelty is the target (CrowdStrike Falcon's macro remediation) rather than the technique itself. Defenders should anticipate variants targeting other remediation or quarantine features.

3. **Uncoordinated disclosure risk:** The researcher published working PoC code without apparent coordinated disclosure, creating an exposure window with no vendor patch available. Organizations dependent on the affected feature face a choice between disabling a security capability (the interim mitigation) and accepting the risk of a public zero-day.

4. **Cross-vendor pattern:** The same researcher systematically targeting CrowdStrike, Kaspersky, Avast, and Microsoft Defender suggests a deliberate research focus on security product privilege escalation. Defenders should review whether their EDR/AV products perform similar privileged remediation workflows that could be vulnerable to the same class of attack.

## Sources

- [The Hacker News - Researcher Releases FalconFlank PoC](https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html) -- Primary news coverage with researcher quotes and CrowdStrike response
- [Security Affairs - Chaotic Eclipse Releases CrowdStrike Falcon ZeroDay FalconFlank](https://securityaffairs.com/198342/hacking/chaotic-eclipse-releases-crowdstrike-falcon-zeroday-falconflank.html) -- Coverage with technical context on affected configurations
- [The Register - Prolific Microsoft 0-day hunter drops CrowdStrike Falcon exploit PoC](https://www.theregister.com/security/2026/09/03/prolific-microsoft-0-day-hunter-drops-crowdstrike-falcon-exploit-poc/5294318) -- Coverage with CrowdStrike mitigation guidance and researcher background
- [SOCRadar - FalconFlank: CrowdStrike Falcon 0-Day PoC](https://socradar.io/blog/falconflank-crowdstrike-falcon-0day-poc/) -- Technical analysis of exploitation prerequisites and named pipe artifact
- [Blackswan Cybersecurity - Threat Advisory: CrowdStrike Falcon Sensor LPE Zero-Day](https://blackswan-cybersecurity.com/threat-advisory-crowdstrike-falcon-sensor-local-privilege-escalation-zero-day-falconflank-august-26-2026/) -- Third-party advisory with MITRE ATT&CK mapping, IOCs, and detection guidance
- [GitHub - MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank) -- PoC source code repository (FalconFlank.cpp)
- [GitHub - MSNightmare/FalconFlank/FalconFlank.cpp](https://github.com/MSNightmare/FalconFlank/blob/main/FalconFlank.cpp) -- PoC source code with API calls, file paths, and exploitation technique details

---
*Report generated by Actioner*
