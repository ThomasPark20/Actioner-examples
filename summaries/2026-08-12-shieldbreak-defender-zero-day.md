# Technical Analysis Report: ShieldBreak Microsoft Defender Zero-Day Bypass (2026-08-12)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-12
Version: 1.1 (FINAL)

## Executive Summary

On August 11-12, 2026, security researcher Nightmare Eclipse (also tracked as Chaotic Eclipse / INFINITE NIGHTMARE / MSNightmare) publicly released "ShieldBreak," a proof-of-concept exploit that fully bypasses Microsoft's July 2026 patch for CVE-2026-50656 (RoguePlanet, CVSS 7.8) in the Microsoft Malware Protection Engine (mpengine.dll). ShieldBreak achieves a claimed 100% success rate for local privilege escalation to NT AUTHORITY\SYSTEM on fully patched Windows 11 25H2 (including Canary channel) and Windows Server 2025 systems. Windows 10 and corresponding server editions are noted as vulnerable but are not currently supported by the PoC code.

Unlike the original RoguePlanet exploit, which relied on VHD/VHDX mounting and had inconsistent success rates across machines, ShieldBreak uses a fundamentally reworked exploit chain built on the Windows Cloud Files API (CldApi), CLFS logs, NTFS alternate data streams, NT Object Manager symbolic links, and the Windows Error Reporting (WER) QueueReporting scheduled task. This rework transforms the previously temperamental race condition into a deterministic privilege escalation, and critically extends the attack surface to Windows Server 2025 -- pulling domain controllers and session hosts into scope for the first time.

ShieldBreak was released after Microsoft's August 2026 Patch Tuesday updates failed to address the bypass. No patch or CVE has been assigned for ShieldBreak specifically. No vendor has publicly reproduced the exploit as of August 12, 2026.

## Background

### CVE-2026-50656 (RoguePlanet) Timeline

| Date | Event |
|------|-------|
| June 2026 | Nightmare Eclipse discloses RoguePlanet zero-day targeting a race condition in Microsoft Defender's Malware Protection Engine |
| June 18, 2026 | Microsoft confirms CVE-2026-50656 (CVSS 7.8); patch "in development" |
| July 9, 2026 | Microsoft releases security update; patched engine build 1.1.26060.3008 |
| Post-July 2026 | Nightmare Eclipse identifies that the "defense-in-depth updates" introduced by Microsoft can cause Defender to leak 8 bytes of data when attempting to open files in certain scenarios |
| August 11, 2026 | ShieldBreak PoC released on GitHub (MSNightmare/ShieldBreak) and git.projectnightcrawler.dev |
| August 12, 2026 | Microsoft August Patch Tuesday ships without addressing ShieldBreak; BleepingComputer, The Hacker News, Security Affairs publish coverage |

### Researcher Profile

Nightmare Eclipse has disclosed at least eight Defender/Windows privilege escalation vulnerabilities in 2026:

- **BlueHammer** (CVE-2026-33825) -- Defender TOCTOU, patched April 2026
- **RedSun** (CVE-2026-41091) -- Defender privilege escalation, patched May 2026
- **UnDefend** (CVE-2026-45498) -- Defender bypass, patched May 2026
- **YellowKey** (CVE-2026-45585) -- BitLocker bypass
- **GreenPlasma** -- CTFMON privilege escalation
- **MiniPlasma** -- Related to GreenPlasma
- **RoguePlanet** (CVE-2026-50656) -- Defender race condition, patched July 2026
- **LegacyHive** -- User Profile Service (ProfSvc) privilege escalation, July 2026
- **ShieldBreak** -- RoguePlanet patch bypass, August 2026 (NO PATCH)

## Technical Analysis

### Vulnerability Root Cause

The root cause remains the same race condition in Microsoft Defender's Malware Protection Engine (mpengine.dll) identified by CVE-2026-50656 (CWE-59: Improper Link Resolution Before File Access). When Defender detects a file requiring remediation, it performs privileged file operations as SYSTEM. The timing gap between path validation and the privileged operation allows an attacker to redirect the file path using NTFS junctions and symbolic links, causing Defender to operate on an attacker-chosen target with SYSTEM privileges.

Microsoft's July 2026 patch hardened the original RoguePlanet attack path but failed to address the fundamental race condition. ShieldBreak approaches the same vulnerability through an entirely different set of Windows primitives, bypassing the patch completely.

### ShieldBreak Exploit Chain (7 Stages)

**Stage 1: Working Directory Initialization**

The exploit creates a hidden working directory at `C:\ShieldBreak_<GUID>` (with the hidden file attribute set). Inside this directory, it creates a placeholder file named `BERLIN` and an NTFS Alternate Data Stream `BERLIN:stream`. The GUID is generated at runtime and varies per execution.

**Stage 2: Cloud Files API Sync Root Registration**

ShieldBreak registers a Cloud Files sync root using the Windows Cloud Files API (CldApi.lib). Functions used include `CfRegisterSyncRoot`, `CfConnectSyncRoot`, and `CfCreatePlaceholders`. A callback function (`CLBK()`) is registered for data transfer interception via `CfHydratePlaceholder` and `CfGetTransferKey`. This mechanism replaces RoguePlanet's VHD/VHDX-based trigger and provides deterministic control over Defender's file access timing.

**Stage 3: Defender API Invocation**

The exploit loads `MpClient.dll` from the Defender installation directory (resolved via `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\InstallLocation`). It resolves and invokes internal Defender APIs: `MpManagerOpen`, `MpScanStart`, `MpThreatOpen`, and `MpCleanOpen` to programmatically trigger Defender scanning and remediation on the EICAR test file (`eicar_com.zip`), initiating the race condition window.

**Stage 4: NT Object Manager Symlink Chain**

The exploit creates Object Manager directory objects at `\BaseNamedObjects\Restricted\WD_TARGET_<GUID>` and `\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>`, with a symbolic link named `WD_SCAN` to redirect file path resolution. CLFS (Common Log File System) log paths at `\CLFS\??\C:\ShieldBreak_<GUID>` are used as an intermediate redirection layer. Key NT APIs used: `NtCreateSection`, `NtCreateSymbolicLinkObject`, `NtCreateDirectoryObjectEx`.

**Stage 5: Race Condition Exploitation and File Replacement**

Using the oplock on the alternate data stream and the Cloud Files callback to freeze Defender mid-operation, the exploit wins the race condition. It then writes the payload (`Warden.dll`) to `C:\Windows\System32\phoneinfo.dll` via a UNC loopback path (`\\127[.]0[.]0[.]1\C$\Windows\System32\phoneinfo.dll`), bypassing direct path-based protections.

**Stage 6: WER Report Staging and QueueReporting Trigger**

The exploit creates a crafted Windows Error Reporting directory at `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\Kernel_<GUID>` and stages a `Report.wer` file within it. It then uses the COM Task Scheduler interface (`CoCreateInstance`) to manually trigger the `\Microsoft\Windows\Windows Error Reporting\QueueReporting` scheduled task, which runs as SYSTEM and loads the compromised `phoneinfo.dll`.

**Stage 7: SYSTEM Payload Execution**

The QueueReporting task executes `wermgr.exe` as SYSTEM. Due to the DLL search order and the overwritten `phoneinfo.dll`, the payload executes with SYSTEM privileges. The named pipe `\\?\pipe\SHIELDBREAK` is used for inter-process communication between the unprivileged orchestrator and the SYSTEM-level payload, signaling successful exploitation and enabling the spawning of a SYSTEM-level command shell.

### Key Differences from RoguePlanet

| Aspect | RoguePlanet | ShieldBreak |
|--------|-------------|-------------|
| Trigger mechanism | VHD/VHDX virtual disk mounting | Cloud Files API sync root |
| Working directory | `%TEMP%\RP_<UUID>` | `C:\ShieldBreak_<GUID>` |
| Named pipe | `\\.\pipe\RoguePlanet` | `\\?\pipe\SHIELDBREAK` |
| Target file | `wermgr.exe` direct replacement | `phoneinfo.dll` via UNC loopback |
| Path redirection | NTFS junctions + VSS enumeration | NT Object Manager symlinks + CLFS |
| Success rate | Variable (inconsistent across hardware) | Claimed 100% |
| Server support | No (standard users cannot mount ISOs) | Yes (Windows Server 2025) |
| ADS name | `:WDFOO` | `:stream` (on `BERLIN` file) |

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in report prose use defanged notation. Detection rules use real (non-defanged) values.

### File System

| Artifact | Path / Value | Description |
|----------|-------------|-------------|
| Working directory | `C:\ShieldBreak_<GUID>\` | Hidden directory created by exploit |
| Placeholder file | `C:\ShieldBreak_<GUID>\BERLIN` | Exploit staging file with ADS `:stream` |
| Payload DLL | `Warden.dll` | Compiled payload in PoC repository |
| Target DLL | `C:\Windows\System32\phoneinfo.dll` | Overwritten with payload via UNC loopback |
| WER staging | `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\Kernel_<GUID>\Report.wer` | Crafted WER report to trigger QueueReporting |
| EICAR trigger | `eicar_com.zip` | Test malware file to trigger Defender scanning |
| PoC binary | `ShieldBreak.exe` | Compiled exploit (~C++ Visual Studio project) |
| PoC source | `ShieldBreak.cpp` | Primary exploit source code |

### Named Pipes

| Pipe Name | Context |
|-----------|---------|
| `\\?\pipe\SHIELDBREAK` | ShieldBreak exploit IPC (orchestrator to SYSTEM payload) |
| `\\.\pipe\RoguePlanet` | Original RoguePlanet exploit IPC |

### NT Object Manager

| Object Path | Description |
|-------------|-------------|
| `\BaseNamedObjects\Restricted\WD_TARGET_<GUID>` | Object directory for path redirection |
| `\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>` | Shadow object directory |
| `WD_SCAN` | Symbolic link within object directories |
| `\CLFS\??\C:\ShieldBreak_<GUID>` | CLFS log target for intermediate redirection |

### Registry

| Key | Value | Context |
|-----|-------|---------|
| `HKLM\SOFTWARE\Microsoft\Windows Defender` | `InstallLocation` | Queried to locate MpClient.dll |

### Network / Hosting

| Type | Value | Context |
|------|-------|---------|
| URL | `hxxps://github[.]com/MSNightmare/ShieldBreak` | PoC repository |
| URL | `hxxps://git[.]projectnightcrawler[.]dev/NightmareEclipse/ShieldBreak` | Mirror repository |
| URL | `hxxps://blog[.]projectnightcrawler[.]dev/posts/2026-08-11-shieldbreak-august-2026-disclosure/` | Researcher disclosure blog post |
| Loopback UNC | `\\127[.]0[.]0[.]1\C$\Windows\System32\phoneinfo.dll` | Used internally by exploit for path bypass |

### Behavioral Indicators

- Creation of directories matching `C:\ShieldBreak_*` with hidden attribute
- Named pipe `\\?\pipe\SHIELDBREAK` created by non-system processes
- `MpClient.dll` loaded by processes outside the Defender installation directory
- `phoneinfo.dll` written or modified in `C:\Windows\System32\` by non-servicing processes
- WER ReportQueue directories with `Kernel_` prefix created by non-WER processes
- Manual triggering of `\Microsoft\Windows\Windows Error Reporting\QueueReporting` scheduled task
- Cloud Files sync root registration (`CfRegisterSyncRoot`) from user-mode exploit processes
- NTFS Alternate Data Streams created on files in `C:\ShieldBreak_*` directories
- UNC path access to `\\127[.]0[.]0[.]1\C$\Windows\System32\` from non-administrative processes
- Defender detection: `Exploit:Win32/DfndrRugPlnt.BB` (RoguePlanet signature; may or may not trigger on ShieldBreak)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | Race condition in Defender Malware Protection Engine exploited for SYSTEM privileges |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | phoneinfo.dll overwritten in System32 to be loaded by wermgr.exe via QueueReporting task |
| T1053.005 | Scheduled Task/Job: Scheduled Task | QueueReporting scheduled task manually triggered via COM to execute payload as SYSTEM |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Payload staged as phoneinfo.dll in System32; WER report mimics legitimate crash data |
| T1106 | Native API | Extensive use of NT Native APIs (NtCreateSection, NtCreateSymbolicLinkObject, NtCreateDirectoryObjectEx) |

## Detection Rules

These detections target the ShieldBreak exploit chain at PoC/advisory-specific altitude with strict leniency. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. `sigma check` could not validate MITRE ATT&CK tags due to network restrictions in the build environment; all rules parse, convert, and produce correct query output.

### Sigma: ShieldBreak Exploit Working Directory Creation
Detects creation of the `C:\ShieldBreak_<GUID>` working directory, the distinctive first-stage artifact of the ShieldBreak exploit.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. PoC-specific directory name makes this extremely high-fidelity. Evasion: trivial rename in modified PoC variants. -->
**Status:** compile ✅ compiles · confidence: high
```yaml
title: ShieldBreak Exploit Working Directory Creation
id: a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: >
    Detects creation of the ShieldBreak exploit's characteristic working directory
    C:\ShieldBreak_<GUID>, which is created with a hidden attribute as the first
    stage of the CVE-2026-50656 patch bypass exploit chain targeting Microsoft
    Defender's Malware Protection Engine (mpengine.dll).
references:
    - https://github.com/MSNightmare/ShieldBreak
    - https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/
    - https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html
author: Actioner
date: 2026/08/12
tags:
    - attack.t1068
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\ShieldBreak_'
        TargetFilename|startswith: 'C:\'
    condition: selection
falsepositives:
    - Unlikely - ShieldBreak is a specific exploit tool name
level: critical
```

### Sigma: ShieldBreak Named Pipe Creation
Detects creation of the `\\?\pipe\SHIELDBREAK` named pipe used for IPC between the exploit orchestrator and the SYSTEM-level payload.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. Pipe name is hardcoded in the PoC and highly distinctive. -->
**Status:** compile ✅ compiles · confidence: high
```yaml
title: ShieldBreak Named Pipe Creation
id: b2c3d4e5-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: >
    Detects creation of the named pipe \\.\pipe\SHIELDBREAK used by the ShieldBreak
    exploit for inter-process communication between the unprivileged orchestrator and
    the SYSTEM-level payload. This pipe signals successful privilege escalation in the
    CVE-2026-50656 patch bypass chain.
references:
    - https://github.com/MSNightmare/ShieldBreak
    - https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/
author: Actioner
date: 2026/08/12
tags:
    - attack.t1068
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|endswith: '\SHIELDBREAK'
    condition: selection
falsepositives:
    - Unlikely - SHIELDBREAK is a specific exploit artifact name
level: critical
```

<!-- revision: DROPPED "Sigma: MpClient.dll Loaded by Non-Defender Process" — altitude violation; generic TTP detection (DLL loading from non-standard path) with zero ShieldBreak-specific artifacts; not valid at PoC-specific altitude. -->

<!-- revision: DROPPED "Sigma: WER QueueReporting Scheduled Task Manual Trigger" — does not detect PoC behavior; ShieldBreak triggers QueueReporting via COM (ITaskService), not schtasks.exe process creation. -->

### Sigma: Suspicious phoneinfo.dll Write to System32
Detects writes to `C:\Windows\System32\phoneinfo.dll` by non-servicing processes, the DLL overwrite target in the ShieldBreak exploit chain.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. phoneinfo.dll is a rarely-touched system DLL; writes by non-servicing processes are highly anomalous. FP: Windows Update servicing stack. -->
**Status:** compile ✅ compiles · confidence: high
```yaml
title: Suspicious phoneinfo.dll Write to System32
id: e5f6a7b8-9c0d-1e2f-3a4b-5c6d7e8f9a0b
status: experimental
description: >
    Detects writes to C:\Windows\System32\phoneinfo.dll by non-system processes.
    The ShieldBreak exploit targets phoneinfo.dll as the DLL to overwrite via the
    NTFS junction and UNC loopback path (\\127.0.0.1\C$\Windows\System32\phoneinfo.dll),
    replacing it with the Warden.dll payload that executes as SYSTEM when the WER
    QueueReporting task runs.
references:
    - https://github.com/MSNightmare/ShieldBreak
    - https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/
author: Actioner
date: 2026/08/12
tags:
    - attack.t1068
    - attack.t1574.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\System32\phoneinfo.dll'
    filter_trusted:
        Image|startswith:
            - 'C:\Windows\servicing\'
            - 'C:\Windows\WinSxS\'
            - 'C:\Windows\System32\poqexec.exe'
    filter_tiworker:
        Image|endswith: '\TiWorker.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Windows servicing operations replacing phoneinfo.dll during updates
level: high
```

### Sigma: ShieldBreak or Nightmare Eclipse Exploit Binary Execution
Detects execution of known Nightmare Eclipse exploit binaries by filename. Trivially evaded by rename but catches unmodified PoC deployment.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. Simple filename match; pair with YARA for content-based detection. -->
**Status:** compile ✅ compiles · confidence: high
```yaml
title: ShieldBreak or Nightmare Eclipse Exploit Binary Execution
id: f6a7b8c9-0d1e-2f3a-4b5c-6d7e8f9a0b1c
status: experimental
description: >
    Detects execution of known Nightmare Eclipse exploit binaries by filename,
    covering the ShieldBreak bypass and the full exploit family. Trivially evaded
    by rename but catches unmodified PoC deployment.
references:
    - https://github.com/MSNightmare/ShieldBreak
    - https://github.com/MSNightmare/RoguePlanet
    - https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/
author: Actioner
date: 2026/08/12
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection_shieldbreak:
        Image|endswith:
            - '\ShieldBreak.exe'
    selection_family:
        Image|endswith:
            - '\RoguePlanet.exe'
            - '\BlueHammer.exe'
            - '\RedSun.exe'
            - '\undef.exe'
            - '\GreenPlasma.exe'
            - '\MiniPlasma.exe'
            - '\YellowKey.exe'
            - '\LegacyHive.exe'
    condition: selection_shieldbreak or selection_family
falsepositives:
    - Unlikely - these are known exploit tool names
level: critical
```

### Sigma: Suspicious WER ReportQueue Kernel Directory Creation
Detects creation of WER ReportQueue directories with a `Kernel_` prefix by non-WER processes, used by ShieldBreak to stage the crafted `Report.wer` that triggers SYSTEM execution.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. revision: tightened filter_system — replaced overly broad C:\Windows\System32\*.exe exclusion with specific WER service host and kernel crash-dump processes. -->
**Status:** compile ✅ compiles · confidence: medium
```yaml
title: Suspicious WER ReportQueue Kernel Directory Creation
id: a7b8c9d0-1e2f-3a4b-5c6d-7e8f9a0b1c2d
status: experimental
description: >
    Detects creation of WER report directories under C:\ProgramData\Microsoft\Windows\WER\ReportQueue\
    with a Kernel_ prefix by non-WER processes. The ShieldBreak exploit stages a crafted Report.wer
    file in this location to trigger the QueueReporting scheduled task, which then executes the
    injected payload as SYSTEM.
references:
    - https://github.com/MSNightmare/ShieldBreak
    - https://www.cyberkendra.com/2026/08/shieldbreak-poc-bypasses-microsofts.html
author: Actioner
date: 2026/08/12
tags:
    - attack.t1068
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\WER\ReportQueue\Kernel_'
    filter_wer:
        Image|endswith:
            - '\WerFault.exe'
            - '\wermgr.exe'
            - '\WerFaultSecure.exe'
    filter_svchost:
        Image|endswith: '\svchost.exe'
    filter_crashdump:
        Image|endswith:
            - '\WerFaultHost.exe'
            - '\crashpad_handler.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Third-party crash reporting tools that write to the WER ReportQueue
level: high
```

### YARA: ShieldBreak Exploit Tool Detection
Detects PE files containing the combination of ShieldBreak-specific strings, Cloud Files API imports, NT Object Manager API calls, and Defender API references characteristic of the ShieldBreak exploit binary.
<!-- audit: yarac exit 0. revision: fixed $pipe2 to match \\?\pipe\SHIELDBREAK (the format used by the PoC), added $pipe3 for NT \??\pipe\ variant; tightened condition to require at least one pipe or ShieldBreak-specific directory string in every branch. -->
**Status:** compile ✅ compiles · confidence: high
```yara
rule Exploit_ShieldBreak_Defender_LPE
{
    meta:
        description = "Detects the ShieldBreak exploit tool that bypasses the CVE-2026-50656 (RoguePlanet) patch in Microsoft Defender for SYSTEM privilege escalation via Cloud Files API, CLFS logs, and WER QueueReporting task abuse"
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://github.com/MSNightmare/ShieldBreak"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pipe1 = "\\\\.\\pipe\\SHIELDBREAK" ascii wide
        $pipe2 = "\\\\?\\pipe\\SHIELDBREAK" ascii wide
        $pipe3 = "\\??\\pipe\\SHIELDBREAK" ascii wide

        $dir1 = "ShieldBreak_" ascii wide
        $dir2 = "WD_TARGET_" ascii wide
        $dir3 = "WD_SHADOW_" ascii wide
        $dir4 = "WD_SCAN" ascii wide

        $file1 = "phoneinfo.dll" ascii wide
        $file2 = "Warden.dll" ascii wide
        $file3 = "Report.wer" ascii wide
        $file4 = "eicar_com.zip" ascii wide

        $api1 = "NtCreateSymbolicLinkObject" ascii fullword
        $api2 = "NtCreateDirectoryObjectEx" ascii fullword
        $api3 = "NtCreateSection" ascii fullword
        $api4 = "CfRegisterSyncRoot" ascii fullword
        $api5 = "CfConnectSyncRoot" ascii fullword
        $api6 = "CfCreatePlaceholders" ascii fullword
        $api7 = "CfHydratePlaceholder" ascii fullword

        $mp1 = "MpManagerOpen" ascii fullword
        $mp2 = "MpScanStart" ascii fullword
        $mp3 = "MpThreatOpen" ascii fullword
        $mp4 = "MpCleanOpen" ascii fullword
        $mp5 = "MpClient.dll" ascii wide nocase

        $path1 = "\\BaseNamedObjects\\Restricted\\" ascii wide
        $path2 = "\\CLFS\\??\\" ascii wide
        $path3 = "\\127.0.0.1\\C$\\Windows\\System32\\phoneinfo.dll" ascii wide
        $path4 = "ReportQueue\\Kernel_" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (1 of ($pipe*) and 2 of ($dir*)) or
            (1 of ($pipe*) and 2 of ($api*)) or
            ($dir1 and $dir2 and $dir3) or
            ($file1 and 1 of ($mp*) and 1 of ($api4, $api5, $api6, $api7)) or
            ($path3 and 1 of ($mp*)) or
            ($dir1 and 2 of ($mp*) and 1 of ($api*)) or
            (1 of ($pipe*) and $file1 and 1 of ($path*)) or
            ($file2 and $dir1 and 1 of ($mp*)) or
            (3 of ($file*) and $dir1)
        )
}

rule Exploit_Warden_Payload_DLL
{
    meta:
        description = "Detects Warden.dll payload used by the ShieldBreak exploit for SYSTEM privilege escalation via the WER QueueReporting scheduled task"
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://github.com/MSNightmare/ShieldBreak"
        severity = "high"
        tlp = "WHITE"

    strings:
        $s1 = "SHIELDBREAK" ascii wide
        $s2 = "ShieldBreak" ascii wide
        $s3 = "WD_TARGET" ascii wide
        $s4 = "WD_SHADOW" ascii wide
        $s5 = "phoneinfo.dll" ascii wide
        $s6 = "Warden" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        3 of them
}
```

### Snort / Suricata: Not Generated

ShieldBreak is a local privilege escalation exploit with no outbound network indicators. The UNC loopback path (`\\127.0.0.1\C$\...`) is internal SMB traffic on localhost. No C2 infrastructure specific to ShieldBreak has been identified. Network-level detection rules are not applicable for this exploit chain. For C2 infrastructure associated with the broader Nightmare Eclipse campaign (BeigeBurrow), refer to the [RoguePlanet report (2026-06-10)](https://github.com/ThomasPark20/Actioner-examples/blob/main/summaries/2026-06-10-defender-rogueplanet-zero-day.md).

## Remediation

### Immediate Actions

1. **Deploy application allowlisting** (ThreatLocker, AppLocker, WDAC) to prevent untrusted executables from user-writable locations -- this blocks the PoC from executing
2. **Monitor for Defender detection** `Exploit:Win32/DfndrRugPlnt.BB` which may trigger on ShieldBreak variants
3. **Hunt for ShieldBreak artifacts** using the detection rules above; priority indicators:
   - Directories matching `C:\ShieldBreak_*`
   - Named pipe `SHIELDBREAK`
   - Non-Defender processes loading `MpClient.dll`
   - Unexpected writes to `C:\Windows\System32\phoneinfo.dll`

### Pending Vendor Response

- No CVE assigned for ShieldBreak
- No patch available as of August 12, 2026
- Microsoft's August Patch Tuesday did not address this bypass
- Apply Microsoft Defender engine updates as soon as a fix is released

### Long-Term Hardening

- Enable Sysmon with comprehensive configuration (Events 1, 7, 11, 17/18 for named pipes)
- Monitor for anomalous Cloud Files API usage (`CfRegisterSyncRoot` calls from non-OneDrive processes)
- Restrict write access to `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\` via ACLs where feasible
- Audit scheduled task execution, particularly `QueueReporting`, for unexpected triggers
- Monitor for NTFS junction and reparse point creation in user-writable directories targeting system paths

## Sources

- [BleepingComputer - New Microsoft Defender ShieldBreak zero-day grants SYSTEM privileges](https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/) -- primary news coverage with researcher quotes and exploit context
- [The Hacker News - ShieldBreak Zero-Day PoC Claims Microsoft Defender Patch Bypass With SYSTEM Access](https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html) -- news coverage with CVE context and researcher background
- [Security Affairs - ShieldBreak: New Windows Zero-Day Bypasses Microsoft's RoguePlanet Patch](https://securityaffairs.com/197063/hacking/shieldbreak-new-windows-zero-day-bypasses-microsofts-rogueplanet-patch.html) -- news coverage with related vulnerability history
- [GitHub - MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak) -- PoC source code repository (C++, MIT license)
- [Cyber Kendra - ShieldBreak PoC Bypasses Microsoft's RoguePlanet Defender Fix](https://www.cyberkendra.com/2026/08/shieldbreak-poc-bypasses-microsofts.html) -- technical analysis of attack chain components
- [Cyderes - RoguePlanet: Windows Zero-Day Weaponizes Defender Quarantine Pipeline](https://www.cyderes.com/howler-cell/rogueplanet-windows-zero-day) -- detailed technical analysis of the original RoguePlanet exploit chain
- [ThreatLocker - Microsoft Defender Zero-Day RoguePlanet Grants SYSTEM Privileges](https://www.threatlocker.com/blog/microsoft-defender-zero-day-rogueplanet-grants-system-privileges) -- technical breakdown of RoguePlanet exploit stages and IOCs
- [Morphisec - Microsoft Defender Zero-Day RoguePlanet: When Your Detector Becomes the Attack Surface](https://www.morphisec.com/blog/microsoft-defender-zero-day-rogueplanet-when-your-detector-becomes-the-attack-surface/) -- vendor analysis and mitigation guidance
- [Kudelski Security - RoguePlanet Zero-Day MS Defender Privilege Escalation](https://kudelskisecurity.com/research/rogueplanet-zero-day-ms-defender-privilege-escalation) -- advisory with CWE-59 classification
- [OP Innovate - Microsoft Defender RoguePlanet Zero-Day (CVE-2026-50656)](https://op-c.net/blog/microsoft-defender-rogueplanet-zero-day-cve-2026-50656/) -- advisory and remediation guidance

---
*Report generated by Actioner*
