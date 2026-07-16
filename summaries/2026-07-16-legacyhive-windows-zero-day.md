# Technical Analysis Report: LegacyHive Windows Zero-Day (2026-07-16)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-16
Version: 1.1 FINAL

## Executive Summary

LegacyHive is an unpatched local privilege escalation zero-day vulnerability in the Windows User Profile Service (ProfSvc), publicly disclosed by security researcher Nightmare Eclipse (Chaotic Eclipse) on July 15, 2026 -- hours after Microsoft's July 2026 Patch Tuesday. The vulnerability allows a standard user with local code execution to mount another user's registry hive (including administrators') under their own profile, enabling arbitrary registry modifications with elevated privileges. The stripped proof-of-concept exploit code is publicly available on GitHub and works on all currently supported Windows desktop and server installations with the July 2026 patch applied. No CVE has been assigned, no Microsoft advisory has been issued, and no security update exists. Security researcher Will Dormann characterized the primitive as "pretty powerful," noting it enables registry modifications without admin privileges -- for example, associating file types with arbitrary executables.

The timing of disclosure was deliberately adversarial: release immediately post-Patch Tuesday ensures maximum exposure window before the next scheduled update cycle. This is part of an ongoing pattern from the same researcher, who has released multiple zero-days (BlueHammer, RoguePlanet, GreatXML/UnDefend) targeting Microsoft products since April 2026 without coordinated disclosure.

## Background: Windows User Profile Service (ProfSvc)

The Windows User Profile Service (`ProfSvc`) is a critical system service responsible for loading and unloading user registry hives (`ntuser.dat`, `UsrClass.dat`) during sign-in and sign-out. It manages user-specific settings, application preferences, and environment configurations stored in the Windows Registry. The service runs as `svchost.exe` under the SYSTEM context and handles the mapping of user hive files on disk to the `HKEY_CURRENT_USER` and `HKEY_CLASSES_ROOT` registry subtrees for each logged-on user.

The `UsrClass.dat` hive specifically stores per-user COM class registrations and file type associations under `HKEY_CURRENT_USER\Software\Classes` (aliased as `HKEY_CLASSES_ROOT` for the user). Control over this hive allows an attacker to hijack file associations, COM object instantiation, and other class-registration-dependent behaviors for the target user.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-15 (Patch Tuesday) | Microsoft releases July 2026 security updates |
| 2026-07-15 (hours later) | Nightmare Eclipse publishes LegacyHive PoC on GitHub |
| 2026-07-15 | SecurityWeek, Security Affairs, The Hacker News, The Register publish coverage |
| 2026-07-16 | No CVE assigned; no Microsoft advisory or patch available |

## Root Cause: Arbitrary Hive Load via User Profile Service Abuse

The vulnerability allows a low-privileged user to manipulate the User Profile Service's hive-loading mechanism by combining several techniques: offline registry hive modification, kernel object namespace manipulation (symbolic links and directory objects), path redirection via `User Shell Folders` registry values, and batch opportunistic locks (oplocks) for timing control. The core issue is that the User Profile Service can be tricked into loading a modified hive that redirects the user's `Local AppData` path through the kernel object namespace to an attacker-controlled location, ultimately mounting an arbitrary user's hive under the attacker's `HKEY_CLASSES_ROOT`.

## Technical Analysis of the Malicious Payload

### 1. Offline Registry Hive Manipulation (Stage 1)

The exploit accepts three arguments: a second standard user's credentials (`<username>` / `<password>`) and a target username whose hive will be mounted (`<target_user_hive>`, which can be an administrator). The tool authenticates using the second user's credentials via `LogonUser()` and then reads the target user's registry hive files from disk:

- `C:\Users\<target_user>\ntuser.dat` -- the main user registry hive
- `C:\Users\<target_user>\AppData\Local\Microsoft\Windows\UsrClass.dat` -- the user classes hive

Using the Windows Offline Registry Library (`offreg.dll`), the exploit opens the hive with `OROpenHiveByHandle()`, navigates to `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, and modifies the `Local AppData` value to redirect it to `\\.\globalroot\BaseNamedObjects\Restricted`. The modified hive is saved with `ORSaveHive()` and written back to disk via `MoveFileEx()`, replacing the original.

### 2. Kernel Object Namespace Setup (Stage 2)

The exploit creates a hierarchy of directory objects and symbolic links in the Windows kernel object namespace using `NtCreateDirectoryObjectEx()` and `NtCreateSymbolicLinkObject()`:

- Creates `\BaseNamedObjects\Restricted\<GUID>` -- a directory object with a permissive DACL (Everyone: GENERIC_ALL)
- Creates `\BaseNamedObjects\Restricted\Microsoft` -- a directory object
- Symbolic link: `\BaseNamedObjects\Restricted\<GUID>\Windows` points to `C:\<GUID>` (a temporary working directory on the filesystem)
- Symbolic link: `\BaseNamedObjects\Restricted\Microsoft\Windows` points to `C:\Users\<target_user>\AppData\Local\Microsoft\Windows`

This namespace redirection is the mechanism by which the modified `Local AppData` path (`\\.\globalroot\BaseNamedObjects\Restricted`) ultimately resolves to the target user's actual `AppData\Local\Microsoft\Windows` directory, causing the User Profile Service to load the target's `UsrClass.dat` instead of the expected hive.

### 3. Oplock-Based Timing Control (Stage 3)

The exploit places a batch opportunistic lock on `UsrClass.dat` using `DeviceIoControl()` and waits for the I/O trigger via `GetOverlappedResult()`. It then spawns `notepad.exe` as the second user via `CreateProcessWithLogonW()`. When the User Profile Service loads this user's profile, it accesses `UsrClass.dat`, triggering the oplock callback. This gives the exploit precise timing control to ensure the modified hive (with the redirected `Local AppData` path) is loaded during profile initialization.

### 4. Verification and Cleanup

After the oplock fires and the hive is loaded, the exploit verifies success by calling `RegOpenUserClassesRoot()` to confirm the target user's classes hive is now mounted under the current user's `HKEY_CLASSES_ROOT`. On completion, the exploit restores the original hive content, removes the temporary `C:\<GUID>` directory, and cleans up the kernel object namespace entries.

### 5. Anti-Forensics / Evasion Techniques

The PoC includes self-cleanup: original hive content is restored after exploitation, temporary directories and kernel objects are removed. The stripped public version is intentionally limited -- the original PoC reportedly did not require additional credentials and could load any hive (not just `UsrClass.dat`), making the full vulnerability significantly more powerful than the released code demonstrates.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)

### Package / Software Level

| Package / Component | Version | Description |
|---------------------|---------|-------------|
| LegacyHive (PoC exploit) | Commit as of 2026-07-15 | C++ exploit tool targeting Windows User Profile Service; compiled from `LegacyHive.cpp` |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | N/A (system file, modified in-place) | Target registry hive manipulated by the exploit |
| Windows | `C:\Users\<user>\ntuser.dat` | N/A (system file, read by exploit) | User registry hive read and modified offline |
| Windows | `C:\<GUID>\` | N/A (temporary directory) | GUID-named directory at drive root created as symlink target |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL | `hxxps://github[.]com/MSNightmare/LegacyHive` | PoC source code repository |
| Domain | `blog[.]projectnightcrawler[.]dev` | Researcher's blog (not accessible at time of analysis) |

### Behavioral

- **Offline registry manipulation:** A non-system process opens, reads, modifies, and writes back `UsrClass.dat` or `ntuser.dat` files belonging to other user profiles using `OROpenHiveByHandle()` / `ORSaveHive()` from the offline registry library (`offreg.dll`)
- **Kernel object namespace abuse:** Creation of directory objects and symbolic links under `\BaseNamedObjects\Restricted\` using `NtCreateDirectoryObjectEx()` and `NtCreateSymbolicLinkObject()`, with permissive DACLs (Everyone: GENERIC_ALL)
- **User Shell Folders path redirection:** The `Local AppData` value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` is modified to `\\.\globalroot\BaseNamedObjects\Restricted` -- an object namespace path instead of a filesystem path
- **Batch oplock on UsrClass.dat:** A batch opportunistic lock is placed on a `UsrClass.dat` file via `DeviceIoControl()` to gain timing control over profile loading
- **Cross-user process creation:** `notepad.exe` is spawned as a different user via `CreateProcessWithLogonW()` to trigger User Profile Service hive loading
- **GUID-named directory at drive root:** A directory with a GUID name (e.g., `C:\{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`) is created at the filesystem root as the target of a kernel object namespace symbolic link

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | Core technique: exploiting a flaw in the User Profile Service to gain access to administrator registry hives from a standard user context |
| T1112 | Modify Registry | Offline modification of `ntuser.dat` hive to redirect `Local AppData` path in User Shell Folders; post-exploitation modification of target user's classes root |
| T1106 | Native API | Direct use of `NtCreateDirectoryObjectEx()` and `NtCreateSymbolicLinkObject()` to create kernel object namespace entries for path redirection |
| T1134.002 | Access Token Manipulation: Create Process with Token | `LogonUser()` + `CreateProcessWithLogonW()` to create a process under a second user's token, triggering User Profile Service hive loading |

## Impact Assessment

**Scope:** All currently supported Windows desktop and server installations with the July 2026 patch are affected. This includes Windows 10, Windows 11, and all supported Windows Server versions.

**Severity:** The vulnerability provides a standard user with the ability to read and write to an administrator's registry hive. While the stripped PoC is limited to `UsrClass.dat` (file associations and COM registrations), the researcher states the full vulnerability allows loading any hive. Registry write access to an administrator's hive enables:
- Hijacking file type associations to execute arbitrary code when the admin opens files
- COM object hijacking for code execution in the admin's context
- Persistence via registry-based autorun mechanisms under the admin's profile
- Potential full privilege escalation when combined with other techniques

**Exposure window:** No patch exists. The next scheduled Patch Tuesday is August 2026, leaving a minimum 30-day exposure window. Microsoft has not publicly acknowledged the vulnerability.

**Prerequisites:** The attacker needs local code execution as a standard user and valid credentials for a second standard user account on the system. The full (unreleased) vulnerability reportedly has no credential requirement.

## Detection & Remediation

### Immediate Detection

Check for anomalous `User Shell Folders` values containing `globalroot` or `BaseNamedObjects`:

```powershell
# Check all user profiles for redirected Local AppData paths
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | ForEach-Object {
    $sid = $_.PSChildName
    $profilePath = (Get-ItemProperty $_.PSPath).ProfileImagePath
    try {
        $hive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $env:COMPUTERNAME)
        $shellFolders = $hive.OpenSubKey("$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        if ($shellFolders) {
            $localAppData = $shellFolders.GetValue("Local AppData")
            if ($localAppData -match "globalroot|BaseNamedObjects") {
                Write-Warning "SUSPICIOUS: User $profilePath ($sid) has redirected Local AppData: $localAppData"
            }
        }
    } catch {}
}
```

Check for GUID-named directories at the drive root:

```powershell
Get-ChildItem "C:\" -Directory | Where-Object { $_.Name -match '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$' }
```

### Remediation

1. **Monitor for exploitation artifacts:** Deploy the detection rules below and monitor for alerts
2. **Restrict secondary logon:** Consider disabling the Secondary Logon service (`seclogon`) where not required, as the exploit uses `CreateProcessWithLogonW()` which depends on it
3. **Harden UsrClass.dat permissions:** Audit and restrict file-level ACLs on user hive files to prevent cross-user access
4. **Apply Microsoft patch when available:** Monitor Microsoft Security Response Center for an advisory and patch
5. **Credential hygiene:** Reduce the number of accounts with known credentials on shared systems, as the stripped PoC requires a second user's credentials

### Long-Term Hardening

- Implement application whitelisting to control which executables can use offline registry APIs (`offreg.dll`)
- Deploy Sysmon with configuration covering registry events (EID 13), file events (EID 11), and process creation (EID 1) for comprehensive visibility
- Segment privileged accounts: avoid having administrator-level accounts log on to shared workstations where standard users operate
- Monitor for future disclosures from this researcher (MSNightmare / Nightmare Eclipse), who has an established pattern of dropping zero-days targeting Microsoft products

## Detection Rules

These detections target the distinctive artifacts of the LegacyHive PoC exploit chain: `User Shell Folders` path redirection to the kernel object namespace, suspicious cross-user `UsrClass.dat` access, process creation patterns consistent with the oplock trigger, and GUID-named root directories. All Sigma rules convert to Splunk and CrowdStrike LogScale; `sigma check` could not run due to an environment proxy issue blocking MITRE ATT&CK data downloads (not a rule defect).

### Sigma: LegacyHive - User Shell Folders Local AppData Redirected to Globalroot

Detects modification of `User Shell Folders\Local AppData` to a `\\.\globalroot\BaseNamedObjects` path -- the distinctive registry manipulation at the heart of the LegacyHive exploit.
**Status:** compile ✅ compiles -- confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); sigma convert --without-pipeline splunk exit 0; sigma convert --without-pipeline log_scale exit 0; sigma convert -p splunk_windows splunk exit 0. Globalroot + BaseNamedObjects in User Shell Folders is a near-zero benign baseline; FP risk negligible. Evasion: attacker could modify User Shell Folders via a different key path or use a different redirection target, but the PoC specifically uses this path. -->
```yaml
title: LegacyHive - User Shell Folders Local AppData Redirected to Globalroot
id: 01e1778b-5afd-413c-8316-90985e278cdd
status: experimental
description: >
    Detects modification of the User Shell Folders "Local AppData" registry value
    to point to a globalroot object namespace path, a technique used by the
    LegacyHive exploit to redirect profile loading and mount another user's
    registry hive under the current user's classes root.
references:
    - https://github.com/MSNightmare/LegacyHive
    - https://www.securityweek.com/nightmare-eclipse-drops-legacyhive-windows-zero-day/
    - https://securityaffairs.com/195418/hacking/chaotic-eclipse-unveils-legacyhive-exploit-affecting-fully-patched-windows-systems.html
author: Actioner
date: 2026/07/16
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
        Details|contains: '\globalroot\BaseNamedObjects'
    condition: selection_key and selection_value
falsepositives:
    - Unknown - globalroot paths in User Shell Folders are highly anomalous
level: critical
```

### Sigma: LegacyHive - Suspicious UsrClass.dat Access by Non-System Process

Detects a non-system process accessing `UsrClass.dat` hive files, consistent with the LegacyHive offline registry manipulation stage.
**Status:** compile ✅ compiles -- confidence: medium
<!-- audit: sigma check blocked by proxy; splunk exit 0; log_scale exit 0; splunk_windows exit 0. Filter list covers known system processes; backup/forensic tools may trigger FPs. Confidence medium rather than high because file_event telemetry varies by EDR and legitimate tools (backup agents, AV scanners) may access UsrClass.dat. -->
```yaml
title: LegacyHive - Suspicious UsrClass.dat Access by Non-System Process
id: 98167032-1389-4caa-a6dd-1067d2daba67
status: experimental
description: >
    Detects a non-system process accessing or copying UsrClass.dat hive files
    from another user's profile directory. The LegacyHive exploit reads and
    modifies UsrClass.dat files of other users using the offline registry
    library to manipulate the hive while unmounted.
references:
    - https://github.com/MSNightmare/LegacyHive
    - https://www.securityweek.com/nightmare-eclipse-drops-legacyhive-windows-zero-day/
    - https://securityaffairs.com/195418/hacking/chaotic-eclipse-unveils-legacyhive-exploit-affecting-fully-patched-windows-systems.html
author: Actioner
date: 2026/07/16
tags:
    - attack.t1068
    - attack.t1112
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\UsrClass.dat'
    filter_system:
        Image|endswith:
            - '\svchost.exe'
            - '\lsass.exe'
            - '\services.exe'
            - '\smss.exe'
            - '\csrss.exe'
            - '\winlogon.exe'
            - '\wininit.exe'
            - '\RuntimeBroker.exe'
            - '\SearchProtocolHost.exe'
            - '\TiWorker.exe'
    filter_system_path:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\servicing\'
    condition: selection and not (filter_system or filter_system_path)
falsepositives:
    - Backup software accessing user registry hives
    - System administration tools performing registry hive operations
    - Forensic analysis tools
level: high
```

### Sigma: LegacyHive - Notepad Spawned via Secondary Logon as Different User

Detects `notepad.exe` spawned by `svchost.exe` (Secondary Logon service) under a non-service user context, consistent with the LegacyHive oplock trigger stage using `CreateProcessWithLogonW`.
**Status:** compile ✅ compiles -- confidence: medium
<!-- audit: sigma check blocked by proxy; splunk exit 0; log_scale exit 0; splunk_windows exit 0. The PoC specifically spawns notepad.exe via CreateProcessWithLogonW (which routes through svchost.exe hosting seclogon). Legitimate runas usage with notepad is possible but uncommon. Confidence medium because any runas notepad.exe triggers this. Best paired with the registry-globalroot anchor rule. -->
```yaml
title: LegacyHive - Notepad Spawned via Secondary Logon as Different User
id: a0eb7d2d-bd90-4db8-9990-9508ddc58968
status: experimental
description: >
    Detects notepad.exe being spawned under a different user context than the
    parent process, consistent with the LegacyHive exploit which uses
    CreateProcessWithLogonW to launch notepad.exe as a target user to trigger
    the User Profile Service to load the manipulated registry hive.
references:
    - https://github.com/MSNightmare/LegacyHive
    - https://www.securityweek.com/nightmare-eclipse-drops-legacyhive-windows-zero-day/
    - https://securityaffairs.com/195418/hacking/chaotic-eclipse-unveils-legacyhive-exploit-affecting-fully-patched-windows-systems.html
author: Actioner
date: 2026/07/16
tags:
    - attack.t1068
    - attack.t1134.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\notepad.exe'
        ParentImage|endswith: '\svchost.exe'
    filter_interactive:
        User|contains:
            - 'SYSTEM'
            - 'LOCAL SERVICE'
            - 'NETWORK SERVICE'
    condition: selection and not filter_interactive
falsepositives:
    - Legitimate use of runas to open notepad as a different user
    - Administrative scripting that spawns notepad under alternate credentials
level: medium
```

### Sigma: LegacyHive - GUID-Named Directory Created at Drive Root

Detects creation of a GUID-named directory directly under a drive root (e.g., `C:\{xxxxxxxx-...}`), used by the LegacyHive exploit as a symlink target for object namespace redirection.
**Status:** compile ✅ compiles -- confidence: medium
<!-- audit: sigma check blocked by proxy; splunk exit 0; log_scale exit 0; splunk_windows exit 0. Uses |re modifier which generates a regex-based Splunk search (| regex ...). Some installers create GUID dirs at root but this is uncommon. Confidence medium due to potential installer FPs. -->
```yaml
title: LegacyHive - GUID-Named Directory Created at Drive Root
id: fce24a01-645e-4309-a999-2910b98c9207
status: experimental
description: >
    Detects creation of a directory with a GUID-like name directly under the
    system drive root (e.g. C:\{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}). The
    LegacyHive exploit creates such a directory as a temporary working directory
    that is the target of a symbolic link from the kernel object namespace.
references:
    - https://github.com/MSNightmare/LegacyHive
    - https://www.securityweek.com/nightmare-eclipse-drops-legacyhive-windows-zero-day/
    - https://securityaffairs.com/195418/hacking/chaotic-eclipse-unveils-legacyhive-exploit-affecting-fully-patched-windows-systems.html
author: Actioner
date: 2026/07/16
tags:
    - attack.t1068
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|re: '^[A-Z]:\\\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}\\'
    condition: selection
falsepositives:
    - Software installers using GUID-named temporary directories at drive root
    - Windows Update operations creating temporary GUID directories
level: medium
```

### Snort: N/A

No network-level indicators suitable for Snort detection -- LegacyHive is a local privilege escalation exploit with no network communication component.

### Suricata: N/A

No network-level indicators suitable for Suricata detection -- LegacyHive is a local privilege escalation exploit with no network communication component.

### YARA: LegacyHive Exploit Tool Binary

Detects compiled LegacyHive exploit binaries by matching the combination of offline registry API imports (`OROpenHiveByHandle`, `ORSaveHive`), kernel object namespace APIs (`NtCreateSymbolicLinkObject`, `NtCreateDirectoryObjectEx`), and distinctive strings (`User Shell Folders`, `globalroot`, `BaseNamedObjects`, `UsrClass.dat`).
**Status:** compile ✅ compiles -- confidence: high
<!-- audit: yarac exit 0. Keys on the intersection of offline registry library imports (uncommon in legitimate software) + NT object namespace APIs + specific path strings from the exploit. Recompilation would retain most of these strings since they are API names and registry paths required by the technique. No sample hash available for the compiled binary. -->
```yara
import "pe"

rule Exploit_LegacyHive_ProfileService_HiveLoad
{
    meta:
        description = "Detects the LegacyHive exploit tool targeting Windows User Profile Service for arbitrary hive load privilege escalation"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://github.com/MSNightmare/LegacyHive"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $s1 = "User Shell Folders" ascii wide
        $s2 = "Local AppData" ascii wide
        $s3 = "globalroot" ascii wide nocase
        $s4 = "BaseNamedObjects" ascii wide
        $s5 = "UsrClass.dat" ascii wide nocase
        $s6 = "ntuser.dat" ascii wide nocase

        $api1 = "OROpenHiveByHandle" ascii fullword
        $api2 = "ORSaveHive" ascii fullword
        $api3 = "OROpenKey" ascii fullword
        $api4 = "ORSetValue" ascii fullword
        $api5 = "RegOpenUserClassesRoot" ascii fullword
        $api6 = "CreateProcessWithLogonW" ascii fullword
        $api7 = "NtCreateSymbolicLinkObject" ascii fullword
        $api8 = "NtCreateDirectoryObjectEx" ascii fullword
        $api9 = "ImpersonateLoggedOnUser" ascii fullword
        $api10 = "LogonUserW" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (3 of ($s*) and 3 of ($api*))
}
```

## Lessons Learned

1. **Coordinated disclosure remains fragile.** Nightmare Eclipse's pattern of dropping zero-days immediately post-Patch Tuesday -- with public PoC code -- highlights the ongoing tension between researcher frustration with vendor response timelines and the security of end users. Organizations must plan for zero-day exposure windows that vendor patch cycles cannot close.

2. **User Profile Service is an undermonitored attack surface.** Registry hive loading is a fundamental Windows operation that most security tools trust implicitly. The combination of offline registry manipulation, kernel object namespace abuse, and oplock-based timing creates a sophisticated attack chain that operates below the visibility of many EDR solutions. Defenders should ensure Sysmon or equivalent telemetry covers registry set events on `User Shell Folders` and file events on hive files.

3. **The stripped PoC understates the vulnerability.** The researcher explicitly states the full vulnerability requires no additional credentials and can load any hive -- not just `UsrClass.dat`. The public PoC is deliberately weakened, meaning the actual attack primitive is more powerful than what detection rules can currently target. Detection engineering should anticipate variants that do not match the specific artifacts of the stripped PoC.

4. **Defense in depth matters.** The exploit chain requires multiple preconditions (second user credentials in the stripped version, local code execution) and touches multiple observable surfaces (registry, file system, process creation, kernel objects). Layered detection across these surfaces provides the best coverage, even if individual rules have medium confidence.

## Sources

- [SecurityWeek - Nightmare Eclipse Drops LegacyHive Windows Zero-Day](https://www.securityweek.com/nightmare-eclipse-drops-legacyhive-windows-zero-day/) -- primary news coverage of the disclosure
- [Security Affairs - Chaotic Eclipse Unveils LegacyHive Exploit Affecting Fully Patched Windows Systems](https://securityaffairs.com/195418/hacking/chaotic-eclipse-unveils-legacyhive-exploit-affecting-fully-patched-windows-systems.html) -- additional news coverage with ProfSvc details
- [GitHub - MSNightmare/LegacyHive](https://github.com/MSNightmare/LegacyHive) -- proof-of-concept source code repository (C++, MIT license)
- [The Hacker News - Researcher Drops New Windows Zero-Day PoC Hours After Microsoft Patch Tuesday](https://thehackernews.com/2026/07/researcher-drops-new-windows-zero-day.html) -- coverage including Will Dormann's assessment
- [The Register - LegacyHive: 'Bone-shattering' zero-day from Microsoft's serial tormentor](https://www.theregister.com/security/2026/07/15/microsofts-serial-tormentor-drops-legacyhive-0-day/5271723) -- contextual coverage of researcher's disclosure history
- [Cybernews - Nightmare Eclipse drops new Windows privilege escalation vulnerability](https://cybernews.com/security/nightmare-eclipse-windows-legacyhive-privilege-escalation-bug/) -- additional coverage
- [GitHub - MSNightmare Profile](https://github.com/MSNightmare) -- researcher profile with related repositories (RoguePlanet, GreatXML)

---
## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-07-16 | Initial draft |
| 1.1 | 2026-07-16 | REVISE pass: Sigma Rule 3 (Notepad Secondary Logon) -- removed dead-code `LogonId|startswith: '0x'` filter (always true for Sysmon hex LogonIds), corrected MITRE tag from T1134.001 (Token Impersonation) to T1134.002 (Create Process with Token) to match `CreateProcessWithLogonW` behavior. MITRE table -- dropped T1574 (Hijack Execution Flow) row as no sub-technique fits; replaced T1134.001 with T1134.002. Re-validated changed rule via sigma convert. |

---
*Report generated by Actioner*
