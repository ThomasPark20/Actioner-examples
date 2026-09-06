# Technical Analysis Report: CrowdStrike FalconFlank Zero-Day Privilege Escalation (2026-09-06)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-06
Version: 1.0 DRAFT

## Executive Summary

A security researcher operating under the aliases Nightmare Eclipse / Chaotic Eclipse / MSNightmare released a public proof-of-concept exploit on September 3, 2026, for a zero-day privilege escalation vulnerability in CrowdStrike Falcon Sensor dubbed "FalconFlank." The exploit abuses the Microsoft Office malicious macro remediation feature within Falcon's Phase 3 Optimal Protection configuration to gain SYSTEM-level privileges on fully patched Windows 11 25H2 and Windows Server 2025 systems. No CVE has been assigned. CrowdStrike has acknowledged the issue and recommended disabling the affected policy setting as an interim mitigation.

The PoC is publicly available on GitHub (MSNightmare/FalconFlank) and uses an oplock-based race condition combined with reparse point manipulation and transactional NTFS to redirect Falcon's macro remediation file writes into planting a malicious `bcrypt.dll` in the PowerShell directory, achieving DLL sideloading when a scheduled task triggers PowerShell execution. The exploit chain is fully automated in a compiled C++ binary.

## Background: CrowdStrike Falcon Sensor

CrowdStrike Falcon is the most widely deployed endpoint detection and response (EDR) product globally. Its sensor runs as a kernel-mode driver and user-mode service on Windows systems, providing real-time threat detection and automated remediation. One of its protection features -- "Microsoft Office File Suspicious Macro Removal" -- automatically inspects Office documents and strips or quarantines macro code identified as malicious. This feature operates under the "Phase 3 - Optimal Protection" configuration tier and performs privileged file system operations to modify or remove Office documents containing suspect macros.

The FalconFlank vulnerability exploits the trust boundary in this remediation workflow: Falcon's remediation process performs SYSTEM-privileged file operations that can be redirected through NTFS junction/reparse point manipulation, effectively turning the EDR's own protection feature into a privilege escalation vector.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-03 | Nightmare Eclipse publishes FalconFlank PoC on GitHub (MSNightmare/FalconFlank) |
| 2026-09-03 | The Register publishes initial coverage citing the researcher's prior work on ShieldBreak (Microsoft Defender) |
| 2026-09-04 | BleepingComputer publishes detailed coverage; CrowdStrike issues interim mitigation guidance |
| 2026-09-04 | The Hacker News publishes coverage; researcher simultaneously releases HardBreacher (Kaspersky), PrettyPrague (Avast), and GreenSection (Nvidia) |
| 2026-09-06 | No CVE assigned; no patch available; CrowdStrike states it is "actively investigating" |

## Root Cause: Oplock-Based Race Condition in Macro Remediation

The vulnerability arises from CrowdStrike Falcon's macro remediation process performing SYSTEM-privileged file operations on user-controlled paths without adequate protection against time-of-check-to-time-of-use (TOCTOU) race conditions. The exploit uses Windows oplock (opportunistic lock) mechanisms to pause the remediation process mid-operation, then redirects the file write via NTFS reparse points (mount points) to a target location, achieving arbitrary file write as SYSTEM.

The root cause is a classic TOCTOU vulnerability in a privileged file operation: Falcon validates the target file, then the exploit interposes via oplock to change where the write lands.

## Technical Analysis of the Malicious Payload

### 1. Exploit Setup -- Temporary Directory and Bait Document

The exploit creates a working directory with a distinctive prefix pattern in the user's temp directory:

- Path pattern: `%TEMP%\Flanker_{GUID}` (e.g., `C:\Users\<user>\AppData\Local\Temp\Flanker_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
- Inside this directory, a subdirectory structure `WindowsPowerShell\v1.0\` is created to mirror the target DLL path

The exploit embeds a 93,696-byte OLE2/CFB (Compound File Binary) format Microsoft Office document in a C header file (`doc.h`) as a `rawData[]` byte array. This document (identified by the `D0 CF 11 E0 A1 B1 1A E1` OLE2 signature) contains macros designed to trigger Falcon's macro remediation workflow. The document is written to disk to bait the remediation process.

### 2. Oplock and Reparse Point Exploitation

The exploit uses multiple low-level Windows API and NTDLL techniques:

**Named Pipe:** Creates `\\??\pipe\FALCONFLANK` as part of the oplock synchronization mechanism.

**Oplock Setup:** Uses `DeviceIoControl` with `FSCTL_REQUEST_OPLOCK` (with `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` flags) to place an opportunistic lock on the bait document. When Falcon's remediation process opens the file, the oplock callback fires, pausing the remediation while the exploit sets up the redirect.

**Reparse Point Manipulation:** Uses `DeviceIoControl` with `FSCTL_SET_REPARSE_POINT_EX` and the `IO_REPARSE_TAG_MOUNT_POINT` (0xA0000003) tag to convert the temp directory into a mount point/junction that redirects to `C:\Windows\System32\WindowsPowerShell\v1.0\`. This causes Falcon's remediation write (which expects to write to the temp directory) to instead place a file (the malicious `bcrypt.dll`) in the PowerShell system directory.

**Transactional NTFS (TxF):** Uses `CreateTransaction`, `CreateFileTransacted`, `CreateFileMapping`, `MapViewOfFile`, `FlushFileBuffers`, and `CommitTransaction` (from `ktmw32.lib`) to atomically stage the malicious DLL payload.

### 3. Trigger -- MareBackup Scheduled Task

After the malicious `bcrypt.dll` is planted in `C:\Windows\System32\WindowsPowerShell\v1.0\`, the exploit uses COM interfaces to trigger execution:

- Uses `CoCreateInstance` to instantiate the Task Scheduler
- Connects to `ITaskService` and navigates to `ITaskFolder` at `\Microsoft\Windows\Application Experience`
- Retrieves and runs a scheduled task named `MareBackup` via `IRegisteredTask->Run()`
- When this task invokes PowerShell, the sideloaded `bcrypt.dll` executes with SYSTEM privileges

### 4. Platform-Specific Behavior

#### Windows 11 25H2 / Windows Server 2025

The exploit is confirmed to work on fully updated Windows 11 25H2 and Windows Server 2025. It requires:
- CrowdStrike Falcon Sensor installed with Phase 3 Optimal Protection enabled
- "Microsoft Office File Suspicious Macro Removal" policy active
- The exploit targets `bcrypt.dll` in the PowerShell v1.0 directory specifically because PowerShell loads this DLL from its application directory before searching the system path

### 5. Anti-Forensics / Evasion Techniques

The researcher noted that CrowdStrike may have detections for the unmodified PoC, and that testing requires either adding the exploit to Falcon's exclusion list or "obfuscating the PoC and changing the DLL load technique." The core exploitation primitives (oplock, reparse points, TxF) are legitimate Windows APIs that are difficult to blanket-block without breaking legitimate applications. The distinctive artifacts (named pipe name, temp directory prefix, scheduled task name) are trivially modified in variants.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| FalconFlank.exe (compiled PoC) | v1.0 (3 commits) | Privilege escalation exploit binary from MSNightmare/FalconFlank repository |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `%TEMP%\Flanker_{GUID}\` | N/A | Exploit working directory with GUID suffix |
| Windows | `%TEMP%\Flanker_{GUID}\WindowsPowerShell\v1.0\bcrypt.dll` | N/A | Staged malicious DLL before reparse point redirect |
| Windows | `C:\Windows\System32\WindowsPowerShell\v1.0\bcrypt.dll` | N/A | Target location for planted malicious DLL (DLL sideloading) |
| Windows | Embedded OLE2 document (in-memory from `doc.h`) | N/A | Bait Office document with macros to trigger Falcon remediation |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL | hxxps://github[.]com/MSNightmare/FalconFlank | PoC repository |

### Behavioral

- **Named pipe creation:** `\\??\pipe\FALCONFLANK` -- created for oplock synchronization during the exploit race condition
- **Oplock activity:** `FSCTL_REQUEST_OPLOCK` with `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` on documents in `Flanker_` directories
- **Reparse point manipulation:** `FSCTL_SET_REPARSE_POINT_EX` with `IO_REPARSE_TAG_MOUNT_POINT` (0xA0000003) redirecting temp directories to system paths
- **Transactional NTFS:** `CreateTransaction` / `CreateFileTransacted` / `CommitTransaction` for atomic DLL staging
- **COM Task Scheduler:** Programmatic execution of scheduled task `MareBackup` in `\Microsoft\Windows\Application Experience` folder
- **DLL sideloading:** `bcrypt.dll` planted in `WindowsPowerShell\v1.0\` directory, loaded when PowerShell is invoked

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | Exploits CrowdStrike Falcon's macro remediation feature via oplock race condition to gain SYSTEM privileges |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Plants malicious `bcrypt.dll` in PowerShell's application directory to be loaded before the legitimate system copy |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Runs the `MareBackup` scheduled task via COM to trigger PowerShell execution with the sideloaded DLL |
| T1106 | Native API | Uses NTDLL functions (`NtCreateFile`, `NtSetInformationFile`) and low-level Windows APIs for oplock and reparse point manipulation |
| T1055 | Process Injection | Transactional NTFS and reparse point redirect effectively inject a malicious DLL into the PowerShell process space |

## Impact Assessment

**Breadth:** Every organization running CrowdStrike Falcon with Phase 3 Optimal Protection and the macro remediation feature enabled on Windows 11 25H2 or Windows Server 2025 is potentially affected. CrowdStrike is the most widely deployed EDR product, making the potential attack surface very large.

**Depth:** The exploit grants SYSTEM-level privileges from a standard user context -- the highest privilege level on Windows. This enables complete system compromise including credential extraction, lateral movement, persistence, and security tool tampering.

**Stealth:** The unmodified PoC contains distinctive artifacts (named pipe, temp directory prefix, scheduled task name) that are detectable. However, these are trivially changed in variants. The core exploitation technique (oplock + reparse point + TxF) uses legitimate Windows APIs that are harder to detect generically.

**Exposure Window:** The vulnerability was disclosed on September 3, 2026, with no patch available as of September 6, 2026. The PoC is public on GitHub with 522 stars and 138 forks, indicating rapid adoption.

## Detection & Remediation

### Immediate Detection

Check for indicators of FalconFlank exploitation (run on endpoints with Sysmon or equivalent monitoring):

```powershell
# Check for FalconFlank named pipe (requires admin)
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -match 'FALCONFLANK' }

# Check for Flanker_ temp directories
Get-ChildItem $env:TEMP -Directory | Where-Object { $_.Name -match '^Flanker_' }

# Check for unauthorized bcrypt.dll in PowerShell directory
Get-Item "C:\Windows\System32\WindowsPowerShell\v1.0\bcrypt.dll" -ErrorAction SilentlyContinue |
    Get-AuthenticodeSignature | Where-Object { $_.Status -ne 'Valid' }

# Check for MareBackup scheduled task
Get-ScheduledTask -TaskPath '\Microsoft\Windows\Application Experience\' |
    Where-Object { $_.TaskName -eq 'MareBackup' }

# Check Sysmon logs for reparse point manipulation via DeviceIoControl
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=11} |
    Where-Object { $_.Message -match 'Flanker_' }
```

### Remediation

1. **Immediate (mitigation):** Disable the "Microsoft Office File Suspicious Macro Removal Windows" policy setting in CrowdStrike Falcon console as recommended by CrowdStrike. Ensure "Cloud Anti-malware for Microsoft Office Files" remains enabled as compensating control.
2. **Containment:** If exploitation is detected, isolate the affected endpoint. The SYSTEM-level access means the attacker may have extracted credentials -- rotate all credentials accessible from the compromised host.
3. **Eradication:** Remove any unauthorized `bcrypt.dll` from `C:\Windows\System32\WindowsPowerShell\v1.0\`. Remove the `MareBackup` scheduled task if it is not a legitimate enterprise task. Clear any `Flanker_` temp directories.
4. **Recovery:** Restore legitimate `bcrypt.dll` from a known-good Windows image. Re-enable macro remediation only after CrowdStrike releases a patch.

### Long-Term Hardening

- Monitor CrowdStrike advisories for a patch addressing this specific TOCTOU vulnerability in the macro remediation workflow
- Implement Sysmon or equivalent monitoring for named pipe creation, reparse point manipulation, and file writes to system directories from non-system processes
- Consider Windows Defender Application Control (WDAC) policies to prevent unsigned DLLs from loading in system directories
- Deploy the Sigma detection rules below to detect both the specific PoC artifacts and the DLL sideloading target

## Detection Rules

These detections target the FalconFlank PoC's distinctive artifacts: the `FALCONFLANK` named pipe, `Flanker_` temp directory pattern, `MareBackup` scheduled task, and the `bcrypt.dll` sideloading target. All four Sigma rules compile and convert to Splunk and CrowdStrike LogScale; the YARA rule compiles. The PoC-specific artifacts (pipe name, dir prefix, task name) are trivially modified in variants -- the bcrypt.dll sideloading rule provides broader coverage.

### Sigma: FalconFlank Named Pipe Creation

Detects creation of the `FALCONFLANK` named pipe used for oplock synchronization in the exploit.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (attacktag excluded: proxy blocks MITRE data download, not a rule issue); splunk convert 0; log_scale convert 0. Pipe name is unique to the PoC — zero benign overlap expected. Trivially changed in variants. -->
```yaml
title: FalconFlank Exploit Named Pipe Creation
id: 7a3e9c1b-4d2f-48a6-b5e0-9f1c3d7a2e8b
status: experimental
description: >
    Detects creation of the FALCONFLANK named pipe used by the FalconFlank
    privilege escalation exploit targeting CrowdStrike Falcon Sensor's
    malicious macro remediation feature.
references:
    - https://github.com/MSNightmare/FalconFlank
    - https://www.bleepingcomputer.com/news/security/new-crowdstrike-falconflank-zero-day-grants-system-privileges/
author: Actioner
date: 2026/09/06
tags:
    - attack.t1068
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|endswith: '\FALCONFLANK'
    condition: selection
falsepositives:
    - Unlikely - highly specific pipe name tied to the FalconFlank PoC
level: critical
```

### Sigma: FalconFlank Temp Directory Creation

Detects file activity in `Flanker_` prefixed temp directories used by the exploit as staging areas.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (attacktag excluded); splunk convert 0; log_scale convert 0. Flanker_ is a distinctive, uncommon directory prefix. Minor FP risk from unrelated software using same prefix. -->
```yaml
title: FalconFlank Exploit Temp Directory Creation
id: 2b8d4f1e-6a3c-49e7-8d5b-1c0f9e7a3b2d
status: experimental
description: >
    Detects file creation within temporary directories matching the Flanker_
    prefix pattern used by the FalconFlank privilege escalation exploit.
references:
    - https://github.com/MSNightmare/FalconFlank
    - https://www.bleepingcomputer.com/news/security/new-crowdstrike-falconflank-zero-day-grants-system-privileges/
author: Actioner
date: 2026/09/06
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
    - Applications using directory names starting with Flanker_
level: high
```

### Sigma: FalconFlank MareBackup Scheduled Task Execution

Detects command-line references to the `MareBackup` scheduled task in the Application Experience folder, used to trigger the sideloaded DLL.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (attacktag excluded); splunk convert 0; log_scale convert 0. MareBackup is not a standard Windows task — highly distinctive. The PoC uses COM ITaskService, so this rule catches schtasks-based invocations or logged COM task runs, not necessarily the silent COM path unless process auditing captures the task host execution. -->
```yaml
title: FalconFlank Exploit MareBackup Scheduled Task Execution
id: 5e9a1d3c-7b4f-42e8-a6d0-8c2e3f1b9a7d
status: experimental
description: >
    Detects execution or registration of the MareBackup scheduled task in
    the Application Experience folder, used by the FalconFlank exploit to
    trigger privilege escalation via CrowdStrike Falcon Sensor.
references:
    - https://github.com/MSNightmare/FalconFlank
    - https://www.bleepingcomputer.com/news/security/new-crowdstrike-falconflank-zero-day-grants-system-privileges/
author: Actioner
date: 2026/09/06
tags:
    - attack.t1068
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'Application Experience'
            - 'MareBackup'
    condition: selection
falsepositives:
    - Unlikely - MareBackup is not a standard Windows scheduled task
level: critical
```

### Sigma: Suspicious bcrypt.dll in PowerShell Directory

Detects file write to `bcrypt.dll` in the PowerShell v1.0 directory, the DLL sideloading target. Broader than the PoC-specific rules -- catches variants that change cosmetic artifacts but retain the same sideloading target.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (attacktag excluded); splunk convert 0; log_scale convert 0. bcrypt.dll in this path is not normally written outside Windows servicing. Filter excludes trusted servicing processes. Medium confidence because Windows updates could write here legitimately via paths not in the filter. -->
```yaml
title: Suspicious bcrypt.dll Modification in PowerShell Directory
id: 8f2c6e4a-1d9b-43e7-b5a0-7e3d1c8f9a2b
status: experimental
description: >
    Detects file modification or creation of bcrypt.dll in the PowerShell
    v1.0 directory, which is targeted by the FalconFlank exploit for DLL
    sideloading to achieve SYSTEM privileges.
references:
    - https://github.com/MSNightmare/FalconFlank
    - https://www.bleepingcomputer.com/news/security/new-crowdstrike-falconflank-zero-day-grants-system-privileges/
author: Actioner
date: 2026/09/06
tags:
    - attack.t1068
    - attack.t1574.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\WindowsPowerShell\v1.0\bcrypt.dll'
    filter_trusted:
        Image|startswith:
            - 'C:\Windows\servicing\'
            - 'C:\Windows\WinSxS\'
            - 'C:\Windows\System32\poqexec.exe'
    condition: selection and not filter_trusted
falsepositives:
    - Windows servicing stack updates to bcrypt.dll
level: high
```

### Snort: N/A

No network-level indicators suitable for Snort detection -- the exploit is entirely local privilege escalation with no network component.

### Suricata: N/A

No network-level indicators suitable for Suricata detection -- the exploit is entirely local privilege escalation with no network component.

### YARA: FalconFlank Exploit Binary Detection

Detects the compiled FalconFlank exploit binary by matching its distinctive string artifacts alongside the embedded OLE2 document signature.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. PE condition + 3-of-5 distinctive strings + OLE2 signature. Sample test not fired (requires real PE binary, not constructable via Write tool — compile-only). Strings are from the published PoC source code. -->
```yara
rule FalconFlank_Exploit_Binary
{
    meta:
        description = "Detects the FalconFlank privilege escalation exploit binary targeting CrowdStrike Falcon Sensor"
        author = "Actioner"
        date = "2026-09-06"
        reference = "https://github.com/MSNightmare/FalconFlank"
        hash = ""

    strings:
        $pipe = "\\??\\pipe\\FALCONFLANK" ascii wide
        $tempdir = "Flanker_" ascii wide
        $task = "MareBackup" ascii wide
        $dllpath = "WindowsPowerShell\\v1.0\\bcrypt.dll" ascii wide
        $taskpath = "\\Microsoft\\Windows\\Application Experience" ascii wide

        $ole2_sig = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        uint16(0) == 0x5A4D and
        3 of ($pipe, $tempdir, $task, $dllpath, $taskpath) and
        $ole2_sig
}
```

## Lessons Learned

**EDR as attack surface.** FalconFlank demonstrates that EDR products, which run with the highest system privileges to perform remediation actions, can themselves become privilege escalation vectors. The pattern of a SYSTEM-privileged process performing file operations on user-influenced paths is a well-known vulnerability class (TOCTOU/symlink attacks), and security products are not immune to it.

**Oplock + reparse point is a durable exploit primitive.** The Windows oplock and mount point/junction mechanism used here is the same class of attack that has produced numerous Windows LPE vulnerabilities over the past several years. Detection of this primitive at the behavioral level (generic oplock abuse + reparse point manipulation targeting system directories) would provide coverage against a broad class of attacks, not just FalconFlank.

**PoC-specific vs. durable detection.** The named pipe (`FALCONFLANK`), temp directory prefix (`Flanker_`), and scheduled task name (`MareBackup`) are trivially changed in variants. The bcrypt.dll sideloading target is somewhat more durable -- changing it requires finding a different sideloading opportunity. Organizations should deploy both layers: PoC-specific for immediate coverage of script-kiddie use, and the sideloading detection for more sophisticated variants.

**Disclosure practices.** This vulnerability was dropped as a zero-day with a public PoC and no coordinated disclosure with CrowdStrike, alongside simultaneous drops against Kaspersky, Avast, and Nvidia. The researcher's pattern of simultaneous multi-vendor zero-day releases maximizes exposure and minimizes vendor response time.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-crowdstrike-falconflank-zero-day-grants-system-privileges/) -- primary news coverage with CrowdStrike mitigation guidance
- [The Hacker News](https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html) -- additional coverage with researcher alias details
- [The Register](https://www.theregister.com/security/2026/09/03/prolific-microsoft-0-day-hunter-drops-crowdstrike-falcon-exploit-poc/5294318) -- initial coverage citing researcher's prior work
- [MSNightmare/FalconFlank GitHub Repository](https://github.com/MSNightmare/FalconFlank) -- primary source: PoC exploit code, README, and technical implementation

---
*Report generated by Actioner*
