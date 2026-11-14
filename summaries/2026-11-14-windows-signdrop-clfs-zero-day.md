# Technical Analysis Report: SignDrop Windows CLFS Zero-Day Privilege Escalation (2026-11-14)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-14
Version: 0.1 (DRAFT)

## Executive Summary

On November 10, 2026, security researcher Nightmare Eclipse (Abdelhamid Naceri, also tracked as Chaotic Eclipse / INFINITE NIGHTMARE / MSNightmare) publicly released "SignDrop," a proof-of-concept exploit targeting the Windows Common Log File System (CLFS) driver (`clfs.sys`). SignDrop achieves local privilege escalation from a standard user to NT AUTHORITY\SYSTEM by abusing the CLFS logfile authentication mechanism that Microsoft introduced in October 2025 as a defense-in-depth mitigation against CLFS memory corruption vulnerabilities.

The exploit forces a privileged process -- specifically the Microsoft Defender antimalware engine -- to open a crafted CLFS log file, causing the kernel driver to create an authentication file (`.cnpf`) at an attacker-controlled location with SYSTEM privileges via Object Manager symbolic link redirection. This planted file is then leveraged through a DLL hijack (consent.exe loading a malicious `hid.dll` from the Windows Ink directory) to spawn a SYSTEM-level shell on the interactive desktop.

No CVE has been assigned. No patch exists as of November 14, 2026. Microsoft has stated it is investigating and that Defender detects and blocks exploitation attempts. No in-the-wild exploitation has been confirmed. Independent testing by Heewon Song (PurpleHound) confirmed the exploit works but reported it does not run reliably enough for operational use.

## Background

### CLFS Authentication Timeline

| Date | Event |
|------|-------|
| October 28, 2025 | Microsoft ships CLFS logfile authentication mitigation in KB5056852, adding HMAC-based integrity checking to CLFS log files via companion `.cnpf` files |
| October 2025 -- present | Mitigation rolls out in 90-day learning mode (Mode 1) before transitioning to enforcement (Mode 0) |
| July 2026 | Nightmare Eclipse discloses RoguePlanet (CVE-2026-50656), a Defender race condition patched by Microsoft |
| August 2026 | Nightmare Eclipse releases ShieldBreak (CVE-2026-69414), bypassing the RoguePlanet patch |
| November 10, 2026 | SignDrop PoC released on GitHub targeting the CLFS authentication mechanism itself |
| November 12, 2026 | BleepingComputer, The Hacker News, Security Affairs, SecurityWeek publish coverage; Microsoft states it is investigating |
| November 12, 2026 | November 2026 Patch Tuesday ships without addressing SignDrop |

### Researcher Profile

Nightmare Eclipse has disclosed at least sixteen zero-day exploits across seven months targeting Windows security components:

- **BlueHammer** (CVE-2026-33825) -- Defender TOCTOU, patched April 2026
- **RedSun** (CVE-2026-41091) -- Defender privilege escalation, patched May 2026
- **UnDefend** (CVE-2026-45498) -- Defender bypass, patched May 2026
- **RoguePlanet** (CVE-2026-50656) -- Defender race condition, patched July 2026
- **ShieldBreak** (CVE-2026-69414) -- RoguePlanet patch bypass, August 2026
- **ShieldCrash** -- Defender bypass, September 2026
- **HardBreacher** -- Kaspersky privilege escalation
- **PrettyPrague** -- Avast privilege escalation
- **FalconFlank** -- CrowdStrike Falcon privilege escalation
- **BigDiskBuster** -- Defender update denial of service
- **GreenSection** -- Nvidia privilege escalation
- **SignDrop** -- CLFS authentication abuse, November 2026 (NO PATCH)

## Technical Analysis

### Vulnerability Root Cause

The root cause is a logic flaw in how `clfs.sys` creates the CLFS authentication file (`.cnpf`) when handling log containers. The CLFS authentication mitigation (shipped in KB5056852, October 2025) attaches an HMAC derived from log data and a per-machine key to each log file via a companion `.cnpf` file. When a log file's associated container is opened and found to be empty (unsigned), `clfs.sys` unconditionally creates the signature file -- even if one does not yet exist -- using the security context of the opening process rather than the user who originally created the log.

This creates a CWE-59 (Improper Link Resolution Before File Access) condition: the access check passes because the privileged process has the right to create files, but the target path can be redirected via Object Manager symbolic links to an attacker-controlled location. The `.cnpf` file inherits the DACL of the original log file, so a SYSTEM-created file remains writable by the standard user who created the log.

As the researcher stated: "Everything is done properly by Microsoft here but the logic allows abuse."

### Affected Configuration

The vulnerability affects systems where the CLFS authentication mitigation is active:

- **Registry path:** `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication\Mode`
- **Value 0 (enforcement):** Vulnerable
- **Value 1 (learning):** Vulnerable
- **Value 2 (admin-disabled):** Not vulnerable to SignDrop, but re-exposes CLFS memory corruption risks
- **Value 3 (system-disabled):** Not vulnerable to SignDrop, but re-exposes CLFS memory corruption risks
- **Key absent:** Build lacks the feature; not vulnerable

Additional registry values of note:
- `EnforcementTransitionPeriod` -- controls the learning-to-enforcement window
- `LearningModeStartTime` -- timestamp of when learning mode began

**Group Policy:** Computer Configuration > Administrative Templates > System > Filesystem > "Enable / disable CLFS logfile authentication"

### Tested Platforms

- Windows 11 26H2
- Windows 11 26H2 Experimental
- Windows Server 2025 Experimental

The researcher estimates approximately 80% of Windows installations are vulnerable. Systems installed more than 90 days ago have typically transitioned from learning to enforcement and remain in scope. This estimate is unverified.

### SignDrop Exploit Chain (5 Stages)

**Stage 1: Working Directory Setup**

The exploit creates a temporary working directory at `%TEMP%\SigDrop_<GUID>` and stages the attack artifacts. A CLFS base log file (`.blf`) and container are created in this user-writable path. A bait `MpEngine.dll` is placed in the working directory and held with an oplock. The embedded PE resource `IDR_DLL1` contains the payload DLL.

**Stage 2: Object Manager Symbolic Link Chain**

The exploit creates symbolic links under `\BaseNamedObjects\Restricted\`, including one named `mpasbase.vdm` and GUID-named links. These links form a redirection chain that will cause the CLFS `.cnpf` file creation to resolve to the Windows Ink directory (`C:\Program Files\Common Files\microsoft shared\ink\`) instead of the expected log path. The CLFS container creation uses IOCTL `0x8007A808` (DeviceIoControl to the `\\CLFS` device).

**Stage 3: Defender Trigger**

The exploit calls `Proc42_ServerMpUpdateEngineSignature` via Defender's RPC interface to trigger a signature update operation. This causes the Defender antimalware engine (MsMpEng.exe) to open the crafted CLFS log as a SYSTEM-privileged process, breaking the oplock on the bait file.

**Stage 4: Path Redirect and Privileged File Creation**

When the oplock breaks, the exploit repoints the symbolic links. The Defender engine follows the container's path to the associated file. Because the container is empty (unsigned), `clfs.sys` creates the `.cnpf` authentication file. Due to the symbolic link redirection, this file is created at `C:\Program Files\Common Files\microsoft shared\ink\hid.dll` with SYSTEM privileges but user-writable DACL. The exploit overwrites this file with the payload DLL.

**Stage 5: Privilege Escalation via DLL Hijack**

The exploit terminates `osk.exe` (On-Screen Keyboard) and relaunches it hidden, then triggers a "runas" elevation request via the AppInfo service. This causes `consent.exe` (the UAC consent dialog) to start as SYSTEM on the secure desktop and load the planted `hid.dll` from the Ink directory. The payload spawns `conhost.exe` as SYSTEM on `WinSta0\Default` (the interactive user desktop), then terminates `consent.exe`. The planted `hid.dll` is subsequently deleted via a transacted delete to remove forensic evidence.

### Key Technical Primitives

| Primitive | Implementation |
|-----------|---------------|
| CLFS log/container creation | `AddLogContainer` API, IOCTL `0x8007A808` |
| Path redirection | Object Manager symbolic links under `\BaseNamedObjects\Restricted\` |
| Privileged trigger | `ServerMpUpdateEngineSignature` (Defender RPC `Proc42`) |
| Timing control | Oplock on bait `MpEngine.dll` |
| DLL hijack target | `consent.exe` loading `hid.dll` from Ink directory |
| Privilege boundary crossing | SYSTEM file creation by `clfs.sys` in Defender process context |

### Prerequisites

- Standard (non-admin) local user account
- Microsoft Defender enabled (required for the published chain)
- CLFS authentication Mode 0 or 1 (default on systems with the mitigation installed)
- Windows 11 25H2/26H1/26H2 or Windows Server 2025

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in report prose use defanged notation. Detection rules use real (non-defanged) values.

### File System

| Artifact | Path / Value | Description |
|----------|-------------|-------------|
| Working directory | `%TEMP%\SigDrop_<GUID>\` | Temporary staging directory, auto-deleted after execution |
| Bait DLL | `%TEMP%\SigDrop_<GUID>\MpEngine.dll` | Staged bait file held with oplock |
| Planted DLL | `C:\Program Files\Common Files\microsoft shared\ink\hid.dll` | Payload DLL created via CLFS authentication abuse; deleted after use |
| CLFS log | `%TEMP%\SigDrop_<GUID>\*.blf` | Base log file created by the exploit |
| Authentication file | `*.cnpf` | CLFS signature file, created at redirected path |
| PoC binary | `SigDrop.exe` | Compiled exploit (Visual Studio C++ project) |
| PoC source | `SigDrop.cpp` | Primary exploit source code |
| RPC stubs | `windefend.idl`, `windefend_c.c`, `windefend_h.h`, `windefend_s.c` | Defender RPC interface definitions |
| Embedded resource | `IDR_DLL1` | PE resource containing the payload DLL |

### NT Object Manager

| Object Path | Description |
|-------------|-------------|
| `\BaseNamedObjects\Restricted\mpasbase.vdm` | Symbolic link for path redirection |
| `\BaseNamedObjects\Restricted\<GUID>` | GUID-named symbolic links for redirection chain |

### Registry

| Key | Value | Context |
|-----|-------|---------|
| `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication` | `Mode` | Values 0 or 1 indicate exposure to SignDrop |
| `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication` | `EnforcementTransitionPeriod` | Learning-to-enforcement transition period |
| `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication` | `LearningModeStartTime` | Timestamp of learning mode start |

### Network / Hosting

| Type | Value | Context |
|------|-------|---------|
| URL | `hxxps://github[.]com/MSNightmare/SignDrop` | PoC repository |

### Process Behavior

- Creation of directories matching `%TEMP%\SigDrop_*`
- `MpEngine.dll` created outside Defender installation directories
- `hid.dll` created in `C:\Program Files\Common Files\microsoft shared\ink\`
- `consent.exe` loading DLLs from the Ink directory
- `conhost.exe` spawned as SYSTEM on user desktop (`WinSta0\Default`)
- `osk.exe` terminated and relaunched hidden
- Defender RPC signature update triggered by non-Defender processes
- `consent.exe` terminated unexpectedly (not by user dismissal)
- Transacted file deletion in the Ink directory
- `.cnpf` files created outside expected CLFS log paths
- CLFS IOCTL `0x8007A808` issued from user-mode exploit processes

### Windows Event Indicators

- **Event ID 4663** (object access attempt) targeting `.cnpf` files under non-standard paths
- **Defender Event ID 2001** -- definition update failure (spurious update trigger)
- **Defender Event ID 5001** -- real-time protection disabled
- **Defender Event ID 5013** -- tampering blocked
- **Integrity level SID `S-1-16-16384`** (SYSTEM) on file creation from security product processes to unexpected paths

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | CLFS authentication logic flaw exploited for SYSTEM privileges via forced privileged file creation |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Malicious hid.dll planted in Ink directory for consent.exe to load as SYSTEM |
| T1070.004 | Indicator Removal: File Deletion | Planted hid.dll removed via transacted delete after execution; working directory auto-deleted |
| T1106 | Native API | Extensive use of NT APIs (NtCreateFile, DeviceIoControl IOCTL 0x8007A808), Object Manager symbolic link creation, CLFS AddLogContainer |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Technique can potentially disable antivirus/EDR tamper protection by executing as the security product's own process context |

## Detection Rules

These detections target the SignDrop exploit chain at PoC/advisory-specific altitude with strict leniency. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. `sigma check` could not validate MITRE ATT&CK tags due to network restrictions in the build environment; all rules parse, convert, and produce correct query output.

### Sigma: Suspicious hid.dll Creation in Ink Directory
Detects creation of `hid.dll` in the Windows Ink directory (`C:\Program Files\Common Files\microsoft shared\ink\`). This file does not ship with Windows at that location. The SignDrop exploit plants a payload here via CLFS authentication redirection.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. hid.dll does not exist in the Ink directory on any stock Windows build. Extremely high fidelity. -->
**Status:** compile pass (sigma convert, yarac n/a) · confidence: high
```yaml
title: Suspicious hid.dll Creation in Ink Directory
id: d1e2f3a4-b5c6-7d8e-9f0a-1b2c3d4e5f6a
status: experimental
description: >
    Detects creation of hid.dll in the Windows Ink directory
    (C:\Program Files\Common Files\microsoft shared\ink\). This file
    does not ship with Windows at that location. The SignDrop exploit
    plants a malicious hid.dll there via CLFS authentication file
    redirection so that consent.exe loads it on the secure desktop,
    granting SYSTEM privileges.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://www.bleepingcomputer.com/news/security/new-windows-signdrop-zero-day-gives-hackers-system-privileges/
    - https://www.cyderes.com/howler-cell/signdrop-zero-day
author: Actioner
date: 2026/11/14
tags:
    - attack.t1068
    - attack.t1574.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\microsoft shared\ink\hid.dll'
    condition: selection
falsepositives:
    - Unlikely - hid.dll does not ship in this directory
level: critical
```

### Sigma: SignDrop Exploit Working Directory Creation
Detects file creation in the `%TEMP%\SigDrop_<GUID>` working directory, the distinctive first-stage artifact of the SignDrop exploit.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. PoC-specific directory name makes this extremely high-fidelity. Evasion: trivial rename in modified PoC variants. -->
**Status:** compile pass (sigma convert, yarac n/a) · confidence: high
```yaml
title: SignDrop Exploit Working Directory Creation
id: e2f3a4b5-c6d7-8e9f-0a1b-2c3d4e5f6a7b
status: experimental
description: >
    Detects creation of files in the SignDrop exploit working directory
    %TEMP%\SigDrop_<GUID>. This is the staging directory created by
    the SignDrop zero-day that exploits CLFS authentication to escalate
    to SYSTEM via path redirection and Defender abuse.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://www.bleepingcomputer.com/news/security/new-windows-signdrop-zero-day-gives-hackers-system-privileges/
    - https://www.cyderes.com/howler-cell/signdrop-zero-day
author: Actioner
date: 2026/11/14
tags:
    - attack.t1068
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\SigDrop_'
    condition: selection
falsepositives:
    - Unlikely - SigDrop is a specific exploit tool name
level: critical
```

### Sigma: Consent.exe Loading DLL from Ink Directory
Detects `consent.exe` loading a DLL from the Windows Ink directory. The SignDrop exploit plants a payload DLL there and triggers a UAC prompt so that consent.exe loads it as SYSTEM on the secure desktop.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. consent.exe should never load DLLs from the Ink directory in normal operation. -->
**Status:** compile pass (sigma convert, yarac n/a) · confidence: high
```yaml
title: Consent.exe Loading DLL from Ink Directory
id: f3a4b5c6-d7e8-9f0a-1b2c-3d4e5f6a7b8c
status: experimental
description: >
    Detects consent.exe loading a DLL from the Windows Ink directory
    (C:\Program Files\Common Files\microsoft shared\ink\). The SignDrop
    exploit plants a payload DLL in this path and triggers a UAC prompt
    so that consent.exe loads the DLL as SYSTEM on the secure desktop.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://www.cyderes.com/howler-cell/signdrop-zero-day
author: Actioner
date: 2026/11/14
tags:
    - attack.t1068
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\consent.exe'
        ImageLoaded|contains: '\microsoft shared\ink\'
    condition: selection
falsepositives:
    - Legitimate DLL loads from the ink directory by consent.exe are not expected
level: critical
```

### Sigma: SYSTEM conhost.exe Spawned on User Desktop
Detects `conhost.exe` spawned with SYSTEM integrity by a non-expected parent process. This is the outcome stage of the SignDrop exploit where a SYSTEM shell is opened on the user desktop.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. revision: filters for known legitimate SYSTEM conhost parents. FP: some service-spawned console applications. -->
**Status:** compile pass (sigma convert, yarac n/a) · confidence: medium
```yaml
title: SYSTEM conhost.exe Spawned on User Desktop
id: a4b5c6d7-e8f9-0a1b-2c3d-4e5f6a7b8c9d
status: experimental
description: >
    Detects conhost.exe spawned with SYSTEM integrity on the interactive
    user desktop (WinSta0\Default). This is the outcome stage of the
    SignDrop exploit chain where a SYSTEM shell is opened on the user
    desktop after the privilege escalation succeeds.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://www.cyderes.com/howler-cell/signdrop-zero-day
author: Actioner
date: 2026/11/14
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\conhost.exe'
        IntegrityLevel: System
    filter_expected_parents:
        ParentImage|endswith:
            - '\csrss.exe'
            - '\services.exe'
            - '\smss.exe'
            - '\wininit.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Some service-spawned console applications may create SYSTEM conhost instances
level: high
```

### Sigma: SignDrop or Nightmare Eclipse Exploit Binary Execution
Detects execution of known Nightmare Eclipse exploit binaries by filename. Trivially evaded by rename but catches unmodified PoC deployment.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. Simple filename match; pair with YARA for content-based detection. -->
**Status:** compile pass (sigma convert, yarac n/a) · confidence: high
```yaml
title: SignDrop or Nightmare Eclipse Exploit Binary Execution
id: b5c6d7e8-f9a0-1b2c-3d4e-5f6a7b8c9d0e
status: experimental
description: >
    Detects execution of known Nightmare Eclipse exploit binaries by
    filename. Covers SignDrop and the broader family of zero-day exploits
    released by this researcher. Trivially evaded by rename but catches
    unmodified PoC deployment.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://www.bleepingcomputer.com/news/security/new-windows-signdrop-zero-day-gives-hackers-system-privileges/
author: Actioner
date: 2026/11/14
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection_signdrop:
        Image|endswith:
            - '\SigDrop.exe'
            - '\SignDrop.exe'
    selection_family:
        Image|endswith:
            - '\ShieldBreak.exe'
            - '\ShieldCrash.exe'
            - '\RoguePlanet.exe'
            - '\BlueHammer.exe'
            - '\RedSun.exe'
            - '\HardBreacher.exe'
            - '\FalconFlank.exe'
            - '\PrettyPrague.exe'
            - '\BigDiskBuster.exe'
            - '\GreenSection.exe'
    condition: selection_signdrop or selection_family
falsepositives:
    - Unlikely - these are known exploit tool names
level: critical
```

### Sigma: CLFS Authentication Mode Registry Modification
Detects modifications to the CLFS Authentication Mode registry value. Monitors for both attacker manipulation and inadvertent disablement of the mitigation in response to SignDrop.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. FP: legitimate 90-day learning-to-enforcement transitions; Group Policy updates. -->
**Status:** compile pass (sigma convert, yarac n/a) · confidence: medium
```yaml
title: CLFS Authentication Mode Registry Modification
id: c6d7e8f9-a0b1-2c3d-4e5f-6a7b8c9d0e1f
status: experimental
description: >
    Detects modifications to the CLFS Authentication Mode registry value
    at HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication. An
    attacker may change Mode from 0 (enforcement) or 1 (learning) to
    2 or 3 (disabled) to re-expose the system to CLFS memory corruption
    vulnerabilities as part of an attack chain, or defenders may
    inadvertently disable the mitigation in response to SignDrop.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://threatdefence.com/article/windows-signdrop-clfs-zero-day-privilege-escalation-hunting
author: Actioner
date: 2026/11/14
tags:
    - attack.t1562.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Services\CLFS\Authentication'
        TargetObject|endswith: '\Mode'
    condition: selection
falsepositives:
    - Legitimate CLFS authentication mode transitions (learning to enforcement after 90-day period)
    - Group Policy updates modifying CLFS logfile authentication settings
level: high
```

### Sigma: MpEngine.dll Created Outside Defender Installation Path
Detects creation of `MpEngine.dll` outside legitimate Defender directories. The SignDrop exploit stages a bait MpEngine.dll in a temp directory to lure the Defender engine process into a CLFS log open.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. FP: security tools copying Defender DLLs for analysis. -->
**Status:** compile pass (sigma convert, yarac n/a) · confidence: medium
```yaml
title: MpEngine.dll Created Outside Defender Installation Path
id: d7e8f9a0-b1c2-3d4e-5f6a-7b8c9d0e1f2a
status: experimental
description: >
    Detects creation of MpEngine.dll outside of the legitimate Windows
    Defender installation directories. The SignDrop exploit stages a bait
    MpEngine.dll in a user-controlled temp directory to lure the Defender
    engine process into opening a CLFS log, triggering the authentication
    file creation as SYSTEM.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://www.cyderes.com/howler-cell/signdrop-zero-day
author: Actioner
date: 2026/11/14
tags:
    - attack.t1068
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\MpEngine.dll'
    filter_defender:
        TargetFilename|contains:
            - '\Windows Defender\'
            - '\Windows Defender Advanced Threat Protection\'
            - '\Microsoft\Windows Defender\'
            - '\Microsoft Antimalware\'
    filter_winsxs:
        TargetFilename|contains: '\WinSxS\'
    condition: selection and not 1 of filter_*
falsepositives:
    - Security tools that copy Defender DLLs for analysis
level: high
```

### Sigma: Anomalous CLFS Authentication File Creation
Detects creation of CLFS authentication (`.cnpf`) files outside expected CLFS log directories. The core observable of the SignDrop attack -- the `.cnpf` file created at a redirected path.
<!-- audit: sigma convert splunk 0; sigma convert log_scale 0. FP: application-created CLFS logs in non-standard directories. Broader detection that covers variants beyond the PoC. -->
**Status:** compile pass (sigma convert, yarac n/a) · confidence: medium
```yaml
title: Anomalous CLFS Authentication File Creation
id: e8f9a0b1-c2d3-4e5f-6a7b-8c9d0e1f2a3b
status: experimental
description: >
    Detects creation of CLFS authentication (.cnpf) files outside of
    expected CLFS log directories. The SignDrop exploit uses Object
    Manager symbolic link redirection to cause clfs.sys to create the
    .cnpf file at an attacker-chosen location with SYSTEM privileges.
    Legitimate .cnpf files are normally co-located with their .blf log
    files in system or application log directories.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://thehackernews.com/2026/11/new-signdrop-zero-day-exploit-turns.html
    - https://threatdefence.com/article/windows-signdrop-clfs-zero-day-privilege-escalation-hunting
author: Actioner
date: 2026/11/14
tags:
    - attack.t1068
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '.cnpf'
    filter_system_logs:
        TargetFilename|contains:
            - '\System32\config\'
            - '\System32\LogFiles\'
            - '\ServiceProfiles\'
    condition: selection and not 1 of filter_*
falsepositives:
    - Application-created CLFS logs in non-standard directories
level: medium
```

### YARA: SignDrop Exploit Tool Detection
Detects PE files containing the combination of SignDrop-specific strings, CLFS API references, Defender RPC interface stubs, and NT Object Manager paths characteristic of the SignDrop exploit binary.
<!-- audit: yarac exit 0. Condition requires multiple independent string clusters to reduce false positives. -->
**Status:** compile pass (yarac) · confidence: high
```yara
rule Exploit_SignDrop_CLFS_LPE
{
    meta:
        description = "Detects the SignDrop exploit tool that abuses CLFS logfile authentication for SYSTEM privilege escalation via path redirection and Defender signature update abuse"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://github.com/MSNightmare/SignDrop"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $name1 = "SigDrop" ascii wide
        $name2 = "SignDrop" ascii wide

        $dir1 = "SigDrop_" ascii wide
        $dir2 = "\\microsoft shared\\ink\\hid.dll" ascii wide

        $api1 = "ServerMpUpdateEngineSignature" ascii wide
        $api2 = "AddLogContainer" ascii fullword
        $api3 = "NtCreateFile" ascii fullword
        $api4 = "DeviceIoControl" ascii fullword

        $rpc1 = "windefend" ascii wide nocase
        $rpc2 = "Proc42" ascii wide

        $file1 = "hid.dll" ascii wide
        $file2 = "MpEngine.dll" ascii wide
        $file3 = ".cnpf" ascii wide
        $file4 = ".blf" ascii wide

        $path1 = "\\BaseNamedObjects\\Restricted\\" ascii wide
        $path2 = "mpasbase.vdm" ascii wide
        $path3 = "WinSta0\\Default" ascii wide

        $ioctl1 = { 08 A8 07 80 }

        $res1 = "IDR_DLL1" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (1 of ($name*) and 1 of ($api1, $api2) and 1 of ($file*)) or
            ($dir1 and $dir2) or
            ($api1 and 1 of ($path*)) or
            ($dir1 and $api1) or
            ($dir1 and 2 of ($file*) and 1 of ($api*)) or
            (1 of ($name*) and $ioctl1 and 1 of ($path*)) or
            ($res1 and $dir1 and 1 of ($file*)) or
            ($dir2 and $api1) or
            (1 of ($rpc*) and $dir1 and 1 of ($file*))
        )
}

rule Exploit_SignDrop_Planted_HID_DLL
{
    meta:
        description = "Detects a planted hid.dll payload potentially associated with the SignDrop exploit chain, which places a malicious DLL in the Ink directory for consent.exe to load"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://github.com/MSNightmare/SignDrop"
        severity = "high"
        tlp = "WHITE"

    strings:
        $s1 = "SigDrop" ascii wide
        $s2 = "SignDrop" ascii wide
        $s3 = "conhost" ascii wide
        $s4 = "WinSta0" ascii wide
        $s5 = "consent" ascii wide
        $s6 = "IDR_DLL1" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        3 of them
}
```

### Snort / Suricata: Not Generated

SignDrop is a local privilege escalation exploit with no outbound network indicators. All exploitation activity occurs locally via kernel driver interaction, Object Manager operations, and RPC calls to the Defender service. No C2 infrastructure specific to SignDrop has been identified. Network-level detection rules are not applicable for this exploit chain.

## Threat Hunting Queries

### Hunt 1: Fleet Exposure Inventory
Query the CLFS Authentication Mode registry value across all endpoints. Prioritize Windows 11 26H2 and Windows Server 2025 systems.

**Defender XDR (KQL):**
```kql
DeviceRegistryEvents
| where RegistryKey has "CLFS\\Authentication"
| where RegistryValueName == "Mode"
| summarize arg_max(Timestamp, RegistryValueData) by DeviceName
| extend ModeValue = toint(RegistryValueData)
| extend ExposureStatus = case(
    ModeValue == 0, "Enforcement - Vulnerable",
    ModeValue == 1, "Learning - Vulnerable",
    ModeValue == 2, "Admin-Disabled - Not Vulnerable (CLFS unprotected)",
    ModeValue == 3, "System-Disabled - Not Vulnerable (CLFS unprotected)",
    "Unknown")
```

### Hunt 2: Anomalous .cnpf Files
Search for `.cnpf` files created outside expected CLFS log directories, particularly by security product processes.

### Hunt 3: SYSTEM Shells from User Processes
Flag SYSTEM-integrity shell processes whose parent runs at Medium or Low integrity:
- `cmd.exe`, `powershell.exe`, `pwsh.exe`, `conhost.exe`, `wt.exe`
- `rundll32.exe`, `regsvr32.exe`, `mshta.exe`

### Hunt 4: Defender Anomalies
Correlate unscheduled Defender signature update failures (Event ID 2001) with subsequent protection state changes (Event ID 5001, 5013).

### Hunt 5: Named Artifact Search
Search file, process, and command-line telemetry for "SigDrop" or "SignDrop" strings, plus `hid.dll` loaded from non-standard paths (outside `System32`, `SysWOW64`, or `WinSxS`).

## Remediation

### Immediate Actions

1. **Deploy application allowlisting** (AppLocker, WDAC, ThreatLocker) to prevent untrusted executables from user-writable locations -- this blocks the PoC from executing
2. **Do NOT disable CLFS authentication** -- this removes the SignDrop attack path but re-exposes systems to CLFS memory corruption vulnerabilities (CVE-2022-24521, CVE-2023-23376, CVE-2023-28252, and others historically exploited in the wild by ransomware operators)
3. **Inventory fleet exposure** using the registry query in Hunt 1; prioritize Windows 11 26H2 and Windows Server 2025 systems
4. **Deploy all detection rules** from this report; priority indicators:
   - `hid.dll` created in the Ink directory (Stage 4)
   - `consent.exe` loading DLLs from the Ink directory (Stage 5)
   - `SigDrop_*` working directory creation (Stage 1)
5. **Enable and retain file creation and image load telemetry** for the Ink directory, as the planted file is deleted after execution
6. **Restrict untrusted local code execution** through script control and application control policies
7. **Enable Defender ASR rule** that blocks untrusted executables from running

### Pending Vendor Response

- No CVE assigned for SignDrop
- No patch available as of November 14, 2026
- November 2026 Patch Tuesday did not address this vulnerability
- Microsoft states Defender "detects and blocks exploitation of this vulnerability"
- Watch for a fix in Microsoft's December 10, 2026 updates or an earlier out-of-band release

### Long-Term Hardening

- Enable Sysmon with comprehensive configuration (Events 1, 7, 11 for process creation, image loads, file creation)
- Monitor for symbolic link creation and repointing under `\BaseNamedObjects\Restricted\`
- Restrict write access to `C:\Program Files\Common Files\microsoft shared\ink\` via ACLs where feasible
- Audit CLFS IOCTL usage from non-system user processes
- Monitor for Defender RPC calls (ServerMpUpdateEngineSignature) from outside the Defender service tree
- Layer telemetry with WEF, Sysmon, and EDR

## Sources

- [BleepingComputer - New Windows SignDrop zero-day gives hackers SYSTEM privileges](https://www.bleepingcomputer.com/news/security/new-windows-signdrop-zero-day-gives-hackers-system-privileges/) -- primary news coverage with researcher quotes and exploit context
- [The Hacker News - New SignDrop Zero-Day Exploit Turns Windows CLFS Defense Into Path to SYSTEM](https://thehackernews.com/2026/11/new-signdrop-zero-day-exploit-turns.html) -- news coverage with independent testing notes and CVE context
- [Security Affairs - New SignDrop Exploit Can Abuse Windows Defender to Bypass Security Protections](https://securityaffairs.com/202968/hacking/new-signdrop-exploit-can-abuse-windows-defender-to-bypass-security-protections.html) -- news coverage with Defender abuse details and researcher background
- [SecurityWeek - Nightmare Eclipse Drops Windows Zero-Day Exploit SignDrop](https://www.securityweek.com/nightmare-eclipse-drops-windows-zero-day-exploit-signdrop/) -- news coverage with Cyderes independent verification and Microsoft response
- [Cyderes - SignDrop Zero-Day Turns Windows CLFS Defense Into Privilege Escalation](https://www.cyderes.com/howler-cell/signdrop-zero-day) -- detailed technical analysis with IOCs, attack chain stages, IOCTL codes, and detection logic
- [ThreatDefence - Windows SignDrop CLFS Zero-Day: Mitigation and Hunting](https://threatdefence.com/article/windows-signdrop-clfs-zero-day-privilege-escalation-hunting) -- hunting queries, registry values, Defender telemetry event IDs, and mitigation guidance
- [Shield53 - SignDrop Zero-Day Turns Windows CLFS Mitigation Against EDR](https://news.shield53.com/signdrop-zero-day-turns-windows-clfs-mitigation-against-edr-shield53-analysis/) -- event ID 4663 guidance and integrity level indicators
- [GitHub - MSNightmare/SignDrop](https://github.com/MSNightmare/SignDrop) -- PoC source code repository (C++, Visual Studio project)
- [Microsoft - CLFS Logfile Authentication](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/clfs-authentication) -- official documentation on the CLFS authentication mitigation
- [Microsoft - CLFS Authentication Mitigation Guidance](https://support.microsoft.com/en-us/servicing/os/windows/2025/03/common-log-file-system-clfs-authentication-mitigation) -- Microsoft support article on CLFS authentication configuration

---
*Report generated by Actioner (DRAFT -- pending peer review and editorial pass)*
