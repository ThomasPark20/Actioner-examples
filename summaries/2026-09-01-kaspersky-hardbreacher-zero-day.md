# Technical Analysis Report: HardBreacher -- Kaspersky Endpoint Security Zero-Day Privilege Escalation

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-01
Version: 0.1 (DRAFT)

## Executive Summary

HardBreacher is a publicly disclosed zero-day elevation-of-privilege exploit targeting Kaspersky Endpoint Security v14.0.0.504 on fully patched Windows 11 25H2 systems. The proof-of-concept was released on August 31, 2026, by a researcher operating under the aliases "Chaotic Eclipse," "Nightmare Eclipse," and "INFINITE NIGHTMARE" (GitHub: [MSNightmare](https://github.com/MSNightmare/HardBreacher)). This is the same researcher responsible for the BlueHammer (CVE-2026-33825), RedSun (CVE-2026-41091), and UnDefend (CVE-2026-45498) Microsoft Defender zero-days earlier in 2026.

The exploit manipulates the Kaspersky Endpoint Security UI process (`avpui.exe`) through parent PID spoofing, symbolic link creation, and reparse point manipulation to write a DLL (`MY_SNAKE_IS_SOLID.dll`) into `C:\Windows\System32` with full user permissions -- a location normally protected from unprivileged writes. Successful exploitation can also disrupt antivirus functionality and interfere with file-access controls.

No CVE has been assigned. Kaspersky has confirmed the vulnerability is patched via database update. The PoC is described by its author as unstable, requiring multiple execution attempts. No in-the-wild exploitation has been publicly confirmed. The PoC source code also contains file encryption routines with `.WNCRY` extension targeting office documents and certificates, suggesting ransomware-adjacent capability beyond the core privilege escalation.

## Threat Actor Profile

| Attribute | Value |
|-----------|-------|
| Primary Alias | Chaotic Eclipse |
| Also Known As | Nightmare Eclipse, INFINITE NIGHTMARE, MSNightmare |
| GitHub | [MSNightmare](https://github.com/MSNightmare) |
| Track Record | BlueHammer (CVE-2026-33825), RedSun (CVE-2026-41091), UnDefend (CVE-2026-45498) -- all Microsoft Defender zero-days |
| Motivation | Protest against vendor vulnerability handling; public PoC disclosure prior to or without coordinated patching |

## Attack Timeline

| Timestamp | Event |
|-----------|-------|
| 2026-08-31 | HardBreacher PoC publicly released on GitHub ([MSNightmare/HardBreacher](https://github.com/MSNightmare/HardBreacher)) |
| 2026-08-31 | [SecurityWeek](https://www.securityweek.com/nightmare-eclipse-drops-hardbreacher-kaspersky-product-exploit/) publishes initial coverage |
| 2026-09-01 | [Security Affairs](https://securityaffairs.com/198214/hacking/chaotic-eclipse-releases-kaspersky-zero-day-hardbreacher.html) and multiple outlets report on the exploit |
| 2026-09-01 | Kaspersky confirms the vulnerability is patched via database update |
| As of 2026-09-01 | No CVE assigned; no in-the-wild exploitation confirmed |

## Affected Systems

| Component | Version | Notes |
|-----------|---------|-------|
| Kaspersky Endpoint Security for Windows | v14.0.0.504 | Confirmed vulnerable; other versions unverified |
| Windows 11 | 25H2 (fully patched) | Tested platform |
| Architecture | x64 host / x86 DLL payload | SolidSnake DLL must be compiled for x86 |

## Technical Analysis

### Repository Structure

The [HardBreacher repository](https://github.com/MSNightmare/HardBreacher) ships two Visual Studio C++ projects:

- **HardBreacher/** -- The main exploit binary (x64). Performs privilege escalation via the Kaspersky UI process.
- **SolidSnake/** -- A companion DLL payload (x86). Suppresses Kaspersky notification windows and terminates `avpui.exe`.

### Exploitation Mechanism

The exploit targets the interaction between a local user and the Kaspersky Endpoint Security UI process (`avpui.exe`). The mechanism chains several Windows primitives:

1. **Registry Reconnaissance:** Queries `HKLM\SOFTWARE\WOW6432Node\KasperskyLab\protected\KES` to locate the Kaspersky installation directory (`C:\Program Files (x86)\Kaspersky Lab\KES.14.0.0\`).

2. **Parent PID Spoofing:** Uses `NtCreateUserProcess` with `PS_ATTRIBUTE_PARENT_PROCESS` to create processes under `avpui.exe`'s context, inheriting its elevated token.

3. **Symbolic Link and Reparse Point Manipulation:** Creates Object Manager symbolic links (`NtCreateSymbolicLinkObject`) and directory objects (`NtCreateDirectoryObject`). Manipulates DOS device mappings (`DefineDosDevice` with `DDD_RAW_TARGET_PATH`) and sets file reparse points (`FSCTL_SET_REPARSE_POINT`) targeting `C:\Windows` to redirect file operations.

4. **DLL Staging:** Stages a payload DLL via a temporary path `%TEMP%\[UUID]_avpui.dll`, then leverages the redirected file operations to write `MY_SNAKE_IS_SOLID.dll` to `C:\Windows\System32` with full user permissions.

5. **AV Disruption (SolidSnake):** The companion DLL enumerates windows matching `"Notification from Kaspersky Endpoint Security"`, suppresses them, enumerates processes to find `avpui.exe`, and terminates it. Uses the named event `Local\HardBreacher-SolidSnake-Sync-Event` for synchronization with the main exploit.

6. **Post-Exploitation:** The PoC source contains AES-128-CBC file encryption routines with BCrypt API, file hardlinks (`FileLinkInformation`), and file renaming with `.WNCRY` extension, targeting file extensions including `.docx`, `.xlsx`, `.pptx`, `.mdb`, `.accdb`, `.jpg`, `.psd`, `.raw`, `.pfx`, and `.pem`. The exploit's author suggests a "stable silent one click exploit" is achievable with further development. A system reboot may be required for full effects.

### Stability and Reliability

The author explicitly notes the PoC is unstable: "The PoC is not in the best shape at all, it is basically duct taped." Multiple execution attempts may be required, and it may terminate with errors. The exploit requires local access with a standard (non-admin) user account. No network access, social engineering, or administrative foothold is needed.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** Network indicators use `hxxps://` and `[.]` where applicable. No network IOCs were identified for this PoC (local exploitation only).

### File System

| Artifact | Path / Value | Description |
|----------|-------------|-------------|
| DLL Drop | `C:\Windows\System32\MY_SNAKE_IS_SOLID.dll` | Primary artifact: DLL created with full user permissions in System32 |
| Exploit Binary | `HardBreacher.exe` | Main exploit executable (no hash available; source-only PoC) |
| Payload DLL | `SolidSnake.dll` | Companion x86 DLL for AV disruption |
| Staging Path | `%TEMP%\[UUID]_avpui.dll` | Temporary DLL staging location |
| Working Directory | `%USERPROFILE%\Desktop\Kaspy` | PoC working directory |
| Decoy File | `Windows\Globalization\Sorting\SortDefault.nls` | File used in reparse point chain |

### Registry

| Key | Description |
|-----|-------------|
| `HKLM\SOFTWARE\WOW6432Node\KasperskyLab\protected\KES` | Queried to locate Kaspersky installation path |

### Behavioral

| Indicator | Description |
|-----------|-------------|
| Named Event | `Local\HardBreacher-SolidSnake-Sync-Event` -- inter-process synchronization between exploit and payload |
| Window Title | `Notification from Kaspersky Endpoint Security` -- targeted for suppression by SolidSnake |
| DLL Export | `MySnakeIsSolid()` -- exported function in SolidSnake DLL |
| Target Process | `avpui.exe` -- Kaspersky Endpoint Security UI process (enumerated, spoofed, terminated) |
| Target Process | `explorer.exe` -- referenced in exploit code |
| API Indicators | `NtCreateSymbolicLinkObject`, `NtCreateDirectoryObject`, `NtCreateUserProcess`, `DefineDosDevice`, `FSCTL_SET_REPARSE_POINT` -- NT native API usage pattern |
| File Extension | `.WNCRY` -- encrypted file extension (post-exploitation ransomware capability) |

### Process Chain (Expected)

```
[user process] -> HardBreacher.exe
    -> NtCreateUserProcess (parent PID spoofed to avpui.exe)
    -> SolidSnake.dll loaded (x86)
        -> EnumWindows (find Kaspersky notifications)
        -> TerminateProcess (avpui.exe)
        -> SetEvent (HardBreacher-SolidSnake-Sync-Event)
    -> MY_SNAKE_IS_SOLID.dll written to System32
```

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | Exploits Kaspersky Endpoint Security UI process interaction to gain write access to System32 from unprivileged user context |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Places attacker-controlled DLL (`MY_SNAKE_IS_SOLID.dll`) in `C:\Windows\System32` to be loaded by system processes |
| T1134.004 | Access Token Manipulation: Parent PID Spoofing | Uses `NtCreateUserProcess` with `PS_ATTRIBUTE_PARENT_PROCESS` to create processes under `avpui.exe`'s token |
| T1562.001 | Impair Defenses: Disable or Modify Tools | SolidSnake DLL terminates `avpui.exe` and suppresses Kaspersky notification windows, disrupting endpoint protection |
| T1106 | Native API | Extensive use of NT native APIs (`NtCreateSymbolicLinkObject`, `NtCreateDirectoryObject`, `NtCreateUserProcess`, `NtSetInformationFile`) |
| T1012 | Query Registry | Queries `HKLM\SOFTWARE\WOW6432Node\KasperskyLab\protected\KES` to locate installation path |
| T1036.005 | Masquerading: Match Legitimate Name or Location | DLL planted in System32 to blend with legitimate system libraries |

## Impact Assessment

**Breadth:** All Windows systems running Kaspersky Endpoint Security v14.0.0.504 are potentially vulnerable. Other Kaspersky versions have not been tested or confirmed. The scope is narrower than the BlueHammer Defender series, as Kaspersky's enterprise endpoint market share is smaller than Microsoft Defender's.

**Depth:** Local privilege escalation from standard user to write access in `C:\Windows\System32`. Combined with the AV disruption capability, an attacker gains both elevated file system access and defense evasion. The ransomware-like encryption routines in the PoC suggest the author envisions weaponization beyond the privilege escalation primitive.

**Active Exploitation:** None confirmed as of 2026-09-01. The PoC's instability and requirement for multiple attempts reduces immediate weaponization risk, but the public availability of source code and the researcher's track record of releasing exploits that are subsequently weaponized (BlueHammer was exploited by ransomware gangs within 8 days of PoC release) elevate the urgency.

**Vendor Response:** Kaspersky states the fix is delivered via automatic database update, not an application version patch. Protection depends on update status rather than application version alone. Organizations must verify their Kaspersky database definitions are current.

## Detection & Remediation

### Immediate Detection

**Check for HardBreacher artifacts:**
```powershell
# Search for the primary DLL artifact
Get-ChildItem -Path "C:\Windows\System32" -Filter "MY_SNAKE_IS_SOLID.dll" -ErrorAction SilentlyContinue

# Search for exploit binaries and working directory
Get-ChildItem -Path C:\Users -Recurse -Include "HardBreacher.exe","SolidSnake.dll" -ErrorAction SilentlyContinue
Test-Path "$env:USERPROFILE\Desktop\Kaspy"

# Check for staged DLLs in TEMP
Get-ChildItem -Path $env:TEMP -Filter "*_avpui.dll" -ErrorAction SilentlyContinue

# Search for encrypted files (post-exploitation indicator)
Get-ChildItem -Path C:\Users -Recurse -Include "*.WNCRY" -ErrorAction SilentlyContinue
```

**Verify Kaspersky update status:**
Ensure Kaspersky Endpoint Security database definitions are up to date. The fix is delivered via database update, not application patch. Trigger a manual database update if automatic updates are delayed.

### Remediation

1. **Immediate:** Force Kaspersky database update on all endpoints running Kaspersky Endpoint Security for Windows. Kaspersky confirms the fix is delivered via database update.
2. **Immediate:** Search for `MY_SNAKE_IS_SOLID.dll` in `C:\Windows\System32` across all managed endpoints. If found, isolate the host and initiate incident response.
3. **Short-term:** Deploy Sigma and YARA detection rules from this report to SIEM and endpoint detection platforms.
4. **Short-term:** Monitor Kaspersky's official advisories for CVE assignment and formal security bulletin.
5. **If compromised:** Reimage the affected system. The exploit can create arbitrary DLLs in System32 and disrupt AV functionality; the extent of post-exploitation activity may not be fully visible.

### Long-Term Hardening

- Deploy Sysmon with file create (Event 11), process access (Event 10), and image load (Event 7) monitoring targeting `avpui.exe` and System32 writes.
- Monitor for DLL creation in `C:\Windows\System32` by non-system processes (anomalous writes to protected directories).
- Implement application allowlisting to prevent execution of unknown binaries.
- Restrict local user accounts to least-privilege configurations.

## Detection Rules

These detections target the HardBreacher PoC at the advisory-specific altitude, covering the primary DLL artifact, the hardcoded synchronization event, suspicious process interaction with `avpui.exe`, and file-level binary signatures. All Sigma rules convert cleanly to both Splunk SPL and CrowdStrike LogScale. The YARA rules compile without error under yarac 4.5.0.

### Sigma: HardBreacher DLL Drop in System32
Detects creation of `MY_SNAKE_IS_SOLID.dll` in System32 -- the definitive artifact of successful HardBreacher exploitation.
**Status:** compile pass (Splunk, LogScale) | confidence: high

```yaml
title: HardBreacher DLL Drop in System32
id: a1f4c9e2-7b3d-4a8e-9c1f-5d2e0b8a3f6c
status: experimental
description: >
    Detects creation of the MY_SNAKE_IS_SOLID.dll file in System32, the primary
    artifact produced by the HardBreacher PoC exploit targeting Kaspersky Endpoint
    Security v14.0.0.504. Successful exploitation writes this DLL with full user
    permissions to a directory normally protected from unprivileged writes.
references:
    - https://securityaffairs.com/198214/hacking/chaotic-eclipse-releases-kaspersky-zero-day-hardbreacher.html
    - https://www.securityweek.com/nightmare-eclipse-drops-hardbreacher-kaspersky-product-exploit/
    - https://github.com/MSNightmare/HardBreacher
author: Actioner
date: 2026/09/01
tags:
    - attack.t1068
    - attack.t1574.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\MY_SNAKE_IS_SOLID.dll'
    condition: selection
falsepositives:
    - Unlikely in production environments; this filename is unique to the HardBreacher PoC
level: critical
```

### Sigma: HardBreacher Named Event Synchronization
Detects command lines containing the hardcoded synchronization event name used between the HardBreacher exploit binary and its SolidSnake DLL payload.
**Status:** compile pass (Splunk, LogScale) | confidence: high

```yaml
title: HardBreacher Named Event Synchronization
id: b2e5d0f3-8c4e-4b9f-ad20-6e3f1c9b4a7d
status: experimental
description: >
    Detects creation of the named synchronization event
    "Local\HardBreacher-SolidSnake-Sync-Event" used for inter-process
    coordination between the HardBreacher exploit binary and its SolidSnake
    DLL payload. This event name is hardcoded in the PoC source.
references:
    - https://securityaffairs.com/198214/hacking/chaotic-eclipse-releases-kaspersky-zero-day-hardbreacher.html
    - https://www.securityweek.com/nightmare-eclipse-drops-hardbreacher-kaspersky-product-exploit/
    - https://github.com/MSNightmare/HardBreacher
author: Actioner
date: 2026/09/01
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'HardBreacher-SolidSnake-Sync-Event'
    condition: selection
falsepositives:
    - None expected; this is a unique hardcoded string from the HardBreacher PoC
level: critical
```

### Sigma: Suspicious Process Targeting Kaspersky avpui.exe
Detects non-Kaspersky processes requesting full access to `avpui.exe`, consistent with the HardBreacher exploit's process enumeration, parent PID spoofing, and termination of the Kaspersky UI process.
**Status:** compile pass (Splunk, LogScale) | confidence: medium

```yaml
title: Suspicious Process Targeting Kaspersky avpui.exe
id: c3f6e1a4-9d5f-4c0a-be31-7f4a2d0c5b8e
status: experimental
description: >
    Detects non-Kaspersky processes enumerating or interacting with avpui.exe,
    the Kaspersky Endpoint Security UI process. The HardBreacher exploit
    manipulates avpui.exe via parent PID spoofing and process enumeration to
    gain elevated privileges and disrupt antivirus functionality.
references:
    - https://securityaffairs.com/198214/hacking/chaotic-eclipse-releases-kaspersky-zero-day-hardbreacher.html
    - https://www.securityweek.com/nightmare-eclipse-drops-hardbreacher-kaspersky-product-exploit/
    - https://github.com/MSNightmare/HardBreacher
author: Actioner
date: 2026/09/01
tags:
    - attack.t1134.004
    - attack.t1562.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\avpui.exe'
        GrantedAccess|contains:
            - '0x1F0FFF'
            - '0x1FFFFF'
            - '0x001F0FFF'
    filter_kaspersky:
        SourceImage|contains: '\Kaspersky Lab\'
    condition: selection and not filter_kaspersky
falsepositives:
    - Security scanning tools auditing running processes
    - System management software inspecting endpoint protection status
level: high
```

### YARA: HardBreacher Exploit Binary and SolidSnake DLL Payload
Detects both the HardBreacher exploit binary and its SolidSnake DLL companion through hardcoded strings, registry paths, NT API references, and DLL export names extracted from the PoC source code.
**Status:** compile pass (yarac 4.5.0) | confidence: high

```yara
rule HardBreacher_Exploit_Binary
{
    meta:
        description = "Detects HardBreacher PoC exploit binary or SolidSnake DLL payload targeting Kaspersky Endpoint Security"
        author = "Actioner"
        date = "2026-09-01"
        reference = "https://github.com/MSNightmare/HardBreacher"
        reference2 = "https://securityaffairs.com/198214/hacking/chaotic-eclipse-releases-kaspersky-zero-day-hardbreacher.html"

    strings:
        $s1 = "MY_SNAKE_IS_SOLID.dll" ascii wide
        $s2 = "HardBreacher-SolidSnake-Sync-Event" ascii wide
        $s3 = "MySnakeIsSolid" ascii wide
        $s4 = "SolidSnake" ascii wide
        $s5 = "avpui.exe" ascii wide
        $s6 = "Notification from Kaspersky Endpoint Security" ascii wide

        $reg1 = "SOFTWARE\\WOW6432Node\\KasperskyLab\\protected\\KES" ascii wide
        $reg2 = "Kaspersky Lab\\KES.14.0.0" ascii wide

        $path1 = "\\Desktop\\Kaspy" ascii wide
        $path2 = "_avpui.dll" ascii wide

        $api1 = "NtCreateSymbolicLinkObject" ascii
        $api2 = "NtCreateDirectoryObject" ascii
        $api3 = "NtCreateUserProcess" ascii
        $api4 = "DefineDosDevice" ascii
        $api5 = "FSCTL_SET_REPARSE_POINT" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($s1 and $s2) or
            ($s2 and $s3) or
            ($s1 and any of ($api*)) or
            (3 of ($s*) and any of ($reg*)) or
            ($s6 and $s5 and any of ($api*)) or
            (any of ($path*) and $s2 and any of ($reg*))
        )
}

rule SolidSnake_DLL_Payload
{
    meta:
        description = "Detects SolidSnake DLL component of HardBreacher exploit - suppresses Kaspersky UI notifications and terminates avpui.exe"
        author = "Actioner"
        date = "2026-09-01"
        reference = "https://github.com/MSNightmare/HardBreacher/tree/main/SolidSnake"

    strings:
        $export = "MySnakeIsSolid" ascii
        $event = "HardBreacher-SolidSnake-Sync-Event" ascii wide
        $target = "avpui.exe" ascii wide
        $window = "Notification from Kaspersky Endpoint Security" ascii wide
        $comment = "ALWAYS COMPILE FOR X86" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $export and
        any of ($event, $target, $window, $comment)
}
```

## Sources

1. [Security Affairs -- Chaotic Eclipse Releases Kaspersky Zero-Day HardBreacher](https://securityaffairs.com/198214/hacking/chaotic-eclipse-releases-kaspersky-zero-day-hardbreacher.html) (Pierluigi Paganini, 2026-09-01) -- Confirmed accessible 2026-09-01
2. [SecurityWeek -- Nightmare Eclipse Drops 'HardBreacher' Kaspersky Product Exploit](https://www.securityweek.com/nightmare-eclipse-drops-hardbreacher-kaspersky-product-exploit/) (Eduard Kovacs, 2026-08-31) -- Confirmed accessible 2026-09-01
3. [GitHub -- MSNightmare/HardBreacher](https://github.com/MSNightmare/HardBreacher) -- PoC repository; 226 stars, 55 forks, MIT license. Source code analyzed for IOCs.
4. [BlackTree -- The Security Product Became the Privilege-Escalation Primitive](https://blacktree.nl/2026/09/01/the-security-product-became-the-privilege-escalation-primitive) -- Independent technical analysis confirming exploit mechanism and vendor response

---

*DRAFT -- This report has not undergone peer review. Detection rules require environment-specific tuning before production deployment. The PoC's ransomware-adjacent capabilities (AES-128-CBC encryption, .WNCRY extension) were identified through automated source code analysis and require independent verification. Monitor Kaspersky advisories for CVE assignment and formal security bulletin.*
