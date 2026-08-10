# Technical Analysis Report: LegacyHive Windows Zero-Day LPE (2026-07-20)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-20
Version: DRAFT 1.0

## Executive Summary

LegacyHive is an unpatched zero-day local privilege escalation vulnerability in the Windows User Profile Service (ProfSvc) disclosed publicly on July 15, 2026 by the researcher "Nightmare Eclipse" (a.k.a. Chaotic Eclipse). The exploit enables a standard user with credentials for a second standard account to mount a target user's (including administrator) `UsrClass.dat` registry hive into the attacker's `HKU\<SID>_Classes` namespace, granting the ability to modify the administrator's class registry -- for example, redirecting file associations (`.txt` opens `calc.exe`) to achieve arbitrary code execution when the admin next logs in. The public PoC was released hours after the July 2026 Patch Tuesday, ensuring all fully updated Windows systems are affected. No CVE has been assigned and no patch is available; detection is currently the only defense.

The exploit uses an oplock-based race condition combined with Object Manager symbolic link redirection and offline registry editing (via `offreg.dll`) to atomically swap a modified `NTUSER.dat` during profile loading. Independent validation was provided by Will Dormann (Tharros) and Kevin Beaumont, with Beaumont publishing KQL detection queries for Microsoft Defender for Endpoint.

## Background: Windows User Profile Service

The Windows User Profile Service (`ProfSvc`) manages loading and unloading of user registry hives (`NTUSER.dat` and `UsrClass.dat`) during logon and logoff. These hives are mapped into the `HKU` registry namespace: `NTUSER.dat` provides the user's main `HKCU` tree, while `UsrClass.dat` provides `HKCU\Software\Classes` (file associations, COM registrations, shell extensions). The service trusts the `User Shell Folders` registry values (particularly `Local AppData`) to locate `UsrClass.dat` on disk. LegacyHive exploits this trust by redirecting `Local AppData` to an Object Manager namespace path, causing the profile service to load an attacker-controlled hive.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04 | Conflict between Nightmare Eclipse and Microsoft begins; researcher starts public disclosure campaign |
| 2026-07-15 | Microsoft releases July 2026 Patch Tuesday updates |
| 2026-07-15 | Nightmare Eclipse publicly releases LegacyHive PoC on GitHub, hours after Patch Tuesday |
| 2026-07-17 | Will Dormann (Tharros) independently confirms exploit functionality |
| 2026-07-18 | Kevin Beaumont confirms exploit and publishes KQL detection queries for MDE |
| 2026-07-18 | Microsoft issues statement: "aware of the reported vulnerability and is actively investigating" |

## Root Cause: User Profile Service Trust in Registry-Controlled Paths

The vulnerability exists because the User Profile Service uses the `Local AppData` value from `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` to locate `UsrClass.dat` without adequately validating the path. An attacker who can modify a user's `NTUSER.dat` (offline, using `offreg.dll`) can redirect this value to an Object Manager namespace path (`\\.\globalroot\BaseNamedObjects\Restricted`), where attacker-controlled symbolic links point to arbitrary locations on disk. Combined with an oplock-based race condition for timing synchronization, the attacker achieves atomic hive replacement during the profile loading window.

## Technical Analysis of the Malicious Payload

### 1. Preparation Phase: Staging Directory and Object Namespace Setup

The exploit binary (`LegacyHive.exe`) accepts three command-line arguments: `<username> <password> <target_user_hive>`. On launch it:

- Generates a random GUID using `UuidCreate()` / `UuidToStringW()`
- Creates a permissive working directory at the drive root: `C:\<GUID>\` with a DACL granting `Everyone` `GENERIC_ALL` access
- Constructs Object Manager symbolic links:
  - `\BaseNamedObjects\Restricted\<GUID>` -- work directory object
  - `\BaseNamedObjects\Restricted\Microsoft` -- subdirectory object
  - `\BaseNamedObjects\Restricted\Microsoft\Windows` --> `\??\C:\<GUID>` (redirect)
  - `\BaseNamedObjects\Restricted\<GUID>\Windows` --> `\??\C:\Users\<target>\AppData\Local\Microsoft\Windows`

These links are created via native NT APIs: `NtCreateDirectoryObjectEx()` and `NtCreateSymbolicLinkObject()`.

### 2. Offline Hive Modification via Offreg.dll

Using `LogonUser()` and `ImpersonateLoggedOnUser()` to authenticate as the target user, the exploit:

- Reads the target user's `NTUSER.dat` and `UsrClass.dat` from `C:\Users\<username>\`
- Opens `NTUSER.dat` using the Offline Registry Library (`offreg.dll`) via `OROpenHiveByHandle()`
- Navigates to `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` using `OROpenKey()`
- Overwrites the `Local AppData` value (type `REG_EXPAND_SZ`) with: `\\.\globalroot\BaseNamedObjects\Restricted`
- Saves the modified hive to the staging directory via `ORSaveHive()`
- Copies the target's `UsrClass.dat` to `C:\<GUID>\UsrClass.dat`

### 3. Oplock-Based Race Condition

The timing-critical exploitation phase uses a batch oplock for synchronization:

- Requests a `FSCTL_REQUEST_BATCH_OPLOCK` on `UsrClass.dat` via `DeviceIoControl()` with an overlapped I/O handle
- Spawns `notepad.exe` with the target user's credentials on a separate thread via `CreateProcessWithLogonW()`
- When `notepad.exe` triggers profile loading (which accesses `UsrClass.dat`), the batch oplock breaks
- The oplock callback signals the exploit, which immediately performs `MoveFileEx()` with `MOVEFILE_REPLACE_EXISTING` to swap the original `NTUSER.dat` with the modified version
- The profile service continues loading with the attacker-modified `Local AppData` path, causing it to resolve the Object Manager symbolic links and load the attacker-controlled `UsrClass.dat` into `HKU\<SID>_Classes`

### 4. Validation and Cleanup

- Calls `RegOpenUserClassesRoot()` to verify the target hive is successfully mounted
- Terminates the spawned `notepad.exe` process and helper threads
- Restores the original `NTUSER.dat` from a backup buffer
- Deletes temporary files in `C:\<GUID>\` and removes the staging directory
- Reverts security impersonation via `RevertToSelf()`

### 5. Anti-Forensics / Evasion Techniques

- The exploit restores the original `NTUSER.dat` after exploitation, leaving minimal file-level evidence
- The staging directory is GUID-named (random per execution) and cleaned up
- The public PoC is deliberately limited -- the unrestricted version does not require additional credentials and can load any hive type, not just `UsrClass.dat`
- Object Manager namespace artifacts are ephemeral and do not persist across reboots

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation where applicable.

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `C:\<GUID>\ntuser.dat` | N/A (dynamic) | Modified NTUSER.dat staged in GUID-named directory at drive root |
| Windows | `C:\<GUID>\UsrClass.dat` | N/A (dynamic) | Copied target UsrClass.dat staged in GUID-named directory at drive root |
| Windows | `LegacyHive.exe` | Not publicly hashed | PoC exploit binary (C++, MIT-licensed) |

### Behavioral

- **GUID directory at drive root**: Creation of a directory directly under a drive root matching `[A-Z]:\{8hex}-{4hex}-{4hex}-{4hex}-{12hex}` containing `ntuser.dat` or `usrclass.dat`
- **User Shell Folders redirect**: `HKCU\...\User Shell Folders\Local AppData` value changed to contain `\\.\globalroot` or `\BaseNamedObjects`
- **Offreg.dll loaded by non-system process**: `offreg.dll` loaded by a process outside `System32`, `SysWOW64`, or `WinSxS` directories
- **CreateProcessWithLogonW spawning notepad.exe**: Unusual parent-child relationship where a non-standard process spawns `notepad.exe` with alternate credentials
- **Batch oplock on UsrClass.dat**: `FSCTL_REQUEST_BATCH_OPLOCK` issued against a user profile hive file from a non-system process
- **Object Manager symbolic links in BaseNamedObjects**: Creation of symbolic links under `\BaseNamedObjects\Restricted` pointing to user profile paths

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | Core exploit: abuses User Profile Service race condition to load arbitrary registry hive with elevated context |
| T1112 | Modify Registry | Offline modification of NTUSER.dat to redirect User Shell Folders\Local AppData to Object Manager namespace |
| T1546.001 | Change Default File Association | Demonstrated impact: modifying admin's UsrClass.dat to redirect .txt file association to calc.exe for code execution on admin logon |
| T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Uses LogonUser() and ImpersonateLoggedOnUser() to access target user's hive files |

## Impact Assessment

**Breadth**: All currently supported Windows desktop and server installations, including systems fully patched through July 2026 Patch Tuesday. Every multi-user Windows system with at least two standard user accounts plus an administrator account is potentially exploitable.

**Depth**: Full administrative privilege escalation. An attacker gains the ability to modify the classes registry hive of any user, including administrators. This enables arbitrary code execution the next time the target user logs in -- effectively a one-shot path from standard user to SYSTEM.

**Stealth**: The exploit cleans up after itself, restoring the original NTUSER.dat and removing staging files. Detection requires real-time monitoring of registry modifications, file events in GUID-named directories, or offreg.dll loading patterns. Post-exploitation forensic evidence is minimal.

**Exploit availability**: Public PoC is available on GitHub (252 stars, 69 forks as of reporting). The released PoC is deliberately limited; the full version requires no additional credentials and can target any hive.

## Detection & Remediation

### Immediate Detection

**Microsoft Defender for Endpoint (KQL)** -- Kevin Beaumont's published queries:

```kql
// Detection 1 - GUID directories with registry hive files at drive root
DeviceFileEvents
| where FolderPath matches regex @"^[a-zA-Z]:\\[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
| where FileName in~ ("ntuser.dat", "usrclass.dat")

// Detection 2 - User Shell Folders redirected to virtual device path
DeviceRegistryEvents
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
| where RegistryValueName in~ ("Local AppData", "AppData", "Cache", "Cookies", "History")
| where RegistryValueData has @"\\.\globalroot" or RegistryValueData has @"\BaseNamedObjects"

// Detection 3 - Offreg.dll loaded outside system paths
DeviceImageLoadEvents
| where FileName =~ "offreg.dll"
| where not(InitiatingProcessFolderPath has_any(@"\System32\", @"\SysWOW64\", @"\WinSxS\"))
```

### Remediation

1. **Monitor**: Deploy the detection rules in this report and the KQL queries above immediately
2. **Reduce attack surface**: Audit and minimize the number of standard user accounts on critical systems; LegacyHive requires credentials for a second standard account
3. **Restrict logon**: Use Group Policy to restrict interactive logon rights on sensitive servers (`Allow log on locally`)
4. **Monitor for patch**: Microsoft is investigating; apply the patch immediately when released

### Long-Term Hardening

- Enable Sysmon with configuration covering Event IDs 1 (process creation), 7 (image load), 11 (file create), and 13 (registry value set)
- Implement least-privilege access policies to minimize the number of accounts with interactive logon rights
- Consider application control (WDAC/AppLocker) to block unauthorized binaries from loading `offreg.dll`

## Detection Rules

Four Sigma rules and one YARA rule cover the LegacyHive exploit's distinctive artifacts: registry redirection via User Shell Folders, GUID-named staging directories containing hive files, non-system loading of the offline registry library, and the PoC binary itself. The primary gap is that post-exploitation cleanup by the PoC may remove file and registry evidence before periodic log collection captures it -- real-time Sysmon or EDR telemetry is essential.

### Sigma: User Shell Folders Redirected to Object Namespace

Detects the hallmark registry modification where User Shell Folders values are redirected to `\\.\globalroot\BaseNamedObjects` paths.

**compile: PASS (Splunk + LogScale) | confidence: high**

<!-- audit: sigma convert --without-pipeline -t splunk PASS; sigma convert --without-pipeline -t log_scale PASS; sigma check skipped (MITRE ATT&CK data fetch blocked by proxy 403); field names TargetObject/Details match Sysmon EID 13 schema for registry_set; values are real (not defanged); detection logic mirrors Beaumont KQL Detection 2 -->

```yaml
title: LegacyHive Exploit - User Shell Folders Redirected to Object Namespace
id: 7a3e1f8b-4c2d-4e9a-b5f6-8d1c0e3a7b2f
status: experimental
description: >
    Detects modification of User Shell Folders registry values to point to
    virtual device paths such as globalroot or BaseNamedObjects. This is a
    hallmark of the LegacyHive zero-day exploit which redirects Local AppData
    to the Object Manager namespace to hijack registry hive loading during
    user profile initialization.
references:
    - https://www.bleepingcomputer.com/news/security/new-windows-legacyhive-zero-day-exploit-grants-hackers-admin-access/
    - https://thehackernews.com/2026/07/researcher-drops-new-windows-zero-day.html
    - https://github.com/MSNightmare/LegacyHive
    - https://github.com/GossiTheDog/ThreatHunting/blob/master/AdvancedHuntingQueries/LegacyHive.kql
author: Actioner
date: 2026-07-20
tags:
    - attack.t1068
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    selection_value:
        TargetObject|endswith:
            - '\Local AppData'
            - '\AppData'
            - '\Cache'
            - '\Cookies'
            - '\History'
    selection_data:
        Details|contains:
            - '\\.\globalroot'
            - '\BaseNamedObjects'
    condition: selection_key and selection_value and selection_data
falsepositives:
    - No known legitimate use of globalroot or BaseNamedObjects paths in User Shell Folders
level: critical
```

### Sigma: Registry Hive File in GUID-Named Root Directory

Detects creation of ntuser.dat or usrclass.dat in a GUID-named directory at the drive root, matching the LegacyHive staging pattern.

**compile: PASS (Splunk + LogScale) | confidence: high**

<!-- audit: sigma convert --without-pipeline -t splunk PASS; sigma convert --without-pipeline -t log_scale PASS; field names TargetFilename match Sysmon EID 11 schema for file_event; regex matches Beaumont KQL Detection 1 GUID pattern; values are real -->

```yaml
title: LegacyHive Exploit - Registry Hive File in GUID-Named Root Directory
id: 2b8d4e6f-1a3c-4d7e-9f0b-5c2a8e1d6f4b
status: experimental
description: >
    Detects creation of ntuser.dat or usrclass.dat files inside GUID-named
    directories at the root of a drive. The LegacyHive exploit stages modified
    registry hive files in a temporary directory named with a random GUID
    directly under the drive root (e.g., C:\{GUID}\ntuser.dat) before using
    an oplock-based race condition to swap them into the target profile.
references:
    - https://www.bleepingcomputer.com/news/security/new-windows-legacyhive-zero-day-exploit-grants-hackers-admin-access/
    - https://thehackernews.com/2026/07/researcher-drops-new-windows-zero-day.html
    - https://github.com/MSNightmare/LegacyHive
    - https://github.com/GossiTheDog/ThreatHunting/blob/master/AdvancedHuntingQueries/LegacyHive.kql
author: Actioner
date: 2026-07-20
tags:
    - attack.t1068
logsource:
    category: file_event
    product: windows
detection:
    selection_filename:
        TargetFilename|endswith:
            - '\ntuser.dat'
            - '\usrclass.dat'
    selection_path:
        TargetFilename|re: '^[a-zA-Z]:\\[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\'
    condition: selection_filename and selection_path
falsepositives:
    - System deployment or imaging tools that stage registry hives in temporary GUID directories at the drive root
level: high
```

### Sigma: Offreg.dll Loaded From Non-System Path

Detects the Offline Registry Library being loaded by a process outside standard system directories, indicating potential offline hive manipulation.

**compile: PASS (Splunk + LogScale) | confidence: medium**

<!-- audit: sigma convert --without-pipeline -t splunk PASS; sigma convert --without-pipeline -t log_scale PASS; field names ImageLoaded/Image match Sysmon EID 7 schema for image_load; filter paths mirror Beaumont KQL Detection 3 exclusions; medium confidence because legitimate deployment/imaging tools may trigger -->

```yaml
title: LegacyHive Exploit - Offreg.dll Loaded From Non-System Path
id: 9c5f2a1d-8b3e-4f7a-d6c0-1e4b7d3a9f5c
status: experimental
description: >
    Detects loading of offreg.dll (Offline Registry Library) by a process
    outside of standard system directories. The LegacyHive exploit uses
    offreg.dll functions (OROpenHiveByHandle, ORSetValue, ORSaveHive) to
    parse and modify ntuser.dat hive files offline. Legitimate use of this
    DLL is limited to Windows setup, deployment, and system configuration tools.
references:
    - https://www.bleepingcomputer.com/news/security/new-windows-legacyhive-zero-day-exploit-grants-hackers-admin-access/
    - https://thehackernews.com/2026/07/researcher-drops-new-windows-zero-day.html
    - https://github.com/MSNightmare/LegacyHive
    - https://github.com/GossiTheDog/ThreatHunting/blob/master/AdvancedHuntingQueries/LegacyHive.kql
author: Actioner
date: 2026-07-20
tags:
    - attack.t1068
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\offreg.dll'
    filter_system:
        Image|contains:
            - '\System32\'
            - '\SysWOW64\'
            - '\WinSxS\'
    filter_defender:
        Image|startswith: 'C:\ProgramData\Microsoft\Windows Defender'
    condition: selection and not filter_system and not filter_defender
falsepositives:
    - Windows deployment tools (DISM, MDT) or system imaging software that use offline registry editing
    - Third-party registry backup or migration utilities
level: high
```

### Sigma: Known LegacyHive PoC Binary Execution

Detects execution of the LegacyHive PoC binary by original filename or image path; trivially evaded by renaming.

**compile: PASS (Splunk + LogScale) | confidence: high (but trivially evadable)**

<!-- audit: sigma convert --without-pipeline -t splunk PASS; sigma convert --without-pipeline -t log_scale PASS; field OriginalFileName from PE metadata is rename-resistant; Image path is not; rule useful for catching unmodified PoC only -->

```yaml
title: LegacyHive Exploit - Known PoC Binary Execution
id: 4e7b1d3a-6c9f-4a2e-8d5b-0f3c7a1e9d6b
status: experimental
description: >
    Detects execution of the LegacyHive proof-of-concept exploit binary by
    matching against the known original filename or image path. The PoC binary
    accepts three arguments (username, password, target user) and abuses the
    Windows User Profile Service to mount a target user's registry hive.
    Note that this rule is trivially evaded by renaming the binary.
references:
    - https://www.bleepingcomputer.com/news/security/new-windows-legacyhive-zero-day-exploit-grants-hackers-admin-access/
    - https://github.com/MSNightmare/LegacyHive
author: Actioner
date: 2026-07-20
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection_name:
        OriginalFileName|contains: 'LegacyHive'
    selection_image:
        Image|endswith: '\LegacyHive.exe'
    condition: selection_name or selection_image
falsepositives:
    - Unlikely in production environments
level: critical
```

### YARA: LegacyHive PoC Exploit Binary

Detects the compiled LegacyHive exploit binary by matching characteristic strings including offreg.dll API imports, Object Manager namespace paths, and NT native API names.

**compile: PASS (yarac) | confidence: high**

<!-- audit: yarac exit code 0; rule targets PE files under 5MB; condition requires 3+ offreg API strings OR the globalroot+shell-folders path combo OR NT API + offreg combo; strings sourced from PoC source code review; no unreferenced strings -->

```yara
rule Exploit_LegacyHive_PoC
{
    meta:
        description = "Detects the LegacyHive PoC exploit binary targeting Windows User Profile Service for privilege escalation via arbitrary registry hive loading"
        author = "Actioner"
        date = "2026-07-20"
        reference = "https://github.com/MSNightmare/LegacyHive"
        severity = "critical"

    strings:
        $api1 = "OROpenHiveByHandle" ascii fullword
        $api2 = "ORSetValue" ascii fullword
        $api3 = "ORSaveHive" ascii fullword
        $api4 = "OROpenKey" ascii fullword
        $api5 = "ORCloseHive" ascii fullword

        $path1 = "\\.\\.\\globalroot\\BaseNamedObjects\\Restricted" wide
        $path2 = "User Shell Folders" wide
        $path3 = "Local AppData" wide

        $nt1 = "NtCreateDirectoryObjectEx" ascii fullword
        $nt2 = "NtCreateSymbolicLinkObject" ascii fullword

        $file1 = "ntuser.dat" wide nocase
        $file2 = "UsrClass.dat" wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (3 of ($api*)) or
            ($path1 and $path2 and $path3) or
            (2 of ($nt*) and 2 of ($api*)) or
            ($path1 and 1 of ($nt*) and 1 of ($file*))
        )
}
```

## Lessons Learned

1. **Coordinated disclosure breakdown**: This is the ninth public zero-day from Nightmare Eclipse in three months, stemming from a dispute with Microsoft's vulnerability disclosure process. The pattern underscores that vendor-researcher relationships directly affect the threat landscape -- when coordinated disclosure fails, defenders lose the patch window entirely.

2. **Profile service trust boundaries**: The User Profile Service's reliance on registry values within the user's own hive to determine file system paths creates a circular trust problem. The service trusts paths stored in a hive that can be modified offline by any process with access to the user's profile directory. This class of vulnerability -- where a privileged service trusts user-writable configuration to locate security-sensitive resources -- likely extends beyond ProfSvc.

3. **Detection-first posture for unpatched zero-days**: With no patch available, the only defense is real-time behavioral detection. Organizations without Sysmon or EDR telemetry covering registry modifications, file events, and image loads have a significant blind spot. The distinctive artifacts of this exploit (GUID staging directories, globalroot registry redirects, offreg.dll loading) make detection feasible -- but only if the telemetry pipeline is in place.

## Sources

- [BleepingComputer: New Windows LegacyHive zero-day exploit grants hackers admin access](https://www.bleepingcomputer.com/news/security/new-windows-legacyhive-zero-day-exploit-grants-hackers-admin-access/) -- first coverage with researcher confirmation timeline and Microsoft statement
- [The Hacker News: Researcher Drops New Windows Zero-Day](https://thehackernews.com/2026/07/researcher-drops-new-windows-zero-day.html) -- detailed technical analysis referencing Cyderes, ThreatLocker, and Rapid7 assessments
- [Nightmare Eclipse LegacyHive PoC (GitHub)](https://github.com/MSNightmare/LegacyHive) -- public PoC source code (C++) with README describing vulnerability scope and PoC limitations
- [Kevin Beaumont LegacyHive KQL Detections (GitHub)](https://github.com/GossiTheDog/ThreatHunting/blob/master/AdvancedHuntingQueries/LegacyHive.kql) -- three MDE advanced hunting queries for file, registry, and image load detection
- [Nightmare Eclipse Blog: LegacyHive Public Disclosure](https://blog.projectnightcrawler.dev/posts/2026-07-14-legacyhive-public-disclosure/) -- researcher's primary disclosure post (403 at time of fetch; referenced by secondary sources)

---
*Report generated by Actioner*
