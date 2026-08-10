# Technical Analysis Report: LegacyHive -- Windows User Profile Service Privilege Escalation Zero-Day (2026-07-17)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-17
Version: 1.1 (FINAL)
<!-- revision: v1.1 — applied critic READY verdict. Fixed "compiles does not equal fires" phrasing. Added T1574 approximate-mapping caveat. All 3 rules KEEP (2 high, 1 medium). Standalone rule files written to rules/sigma/ and rules/yara/. -->

## Executive Summary

On July 14, 2026, security researcher Nightmare Eclipse (also tracked as Chaotic Eclipse, GitHub: MSNightmare, git: NightmareEclipse) publicly released "LegacyHive," a proof-of-concept local privilege escalation exploit targeting the Windows User Profile Service (ProfSvc). The PoC was dropped hours after Microsoft's July 2026 Patch Tuesday update and works on fully patched systems. No CVE has been assigned and no patch is available.

LegacyHive exploits a logic flaw in how ProfSvc loads user registry hives during logon. By chaining offline registry hive modification, NT Object Manager symbolic link redirection, and an oplock-synchronized race condition, a standard user can force ProfSvc to mount a target user's `UsrClass.dat` (including an administrator's) into the attacker's own `HKU\<SID>_Classes` registry namespace, granting read-write access to the target's application data, shell configuration, and forensic artifacts.

The public PoC is deliberately stripped down: it requires a second standard user's credentials and is limited to `UsrClass.dat`. The researcher has stated the original, unreleased version requires no additional credentials and can load arbitrary hives. Huntress warned that capable actors will reverse-engineer the missing components to build fully weaponized versions in short order. This is the ninth public exploit from this researcher in an escalating campaign against Microsoft components since April 2026, following BlueHammer (CVE-2026-33825), RedSun, UnDefend, YellowKey, RoguePlanet, GreenPlasma, MiniPlasma, and GreatXML (see prior Actioner coverage: [BlueHammer](2026-07-02-bluehammer-cve-2026-33825-defender-lpe.md), [RoguePlanet](2026-06-10-defender-rogueplanet-zero-day.md), [GreatXML](2026-06-11-greatxml-bitlocker-bypass.md)).

## Background: Windows User Profile Service (ProfSvc)

The Windows User Profile Service (ProfSvc) is a core system component that manages user accounts and environments. During user logon, ProfSvc loads registry hives (`NTUSER.DAT` and `UsrClass.dat`) from the user's profile directory into the registry namespace under `HKEY_USERS\<SID>`. The `UsrClass.dat` hive is mounted at `HKU\<SID>_Classes` and contains per-user COM class registrations, file type associations, shell extension settings, and application compatibility data.

ProfSvc resolves the hive file paths using values stored in the user's own `NTUSER.DAT`, specifically the `Local AppData` value under `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`. The service trusts these path values during profile initialization without verifying that the resolved path actually belongs to the authenticating user. LegacyHive exploits this trust boundary: by modifying the path value in an offline hive to point through the NT Object Manager namespace, the attacker redirects ProfSvc's hive load to a different user's files.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-02 | BlueHammer (CVE-2026-33825) PoC released; first in series from Nightmare Eclipse |
| 2026-04 through 2026-06 | Seven additional exploits released: RedSun, UnDefend, YellowKey, GreenPlasma, MiniPlasma, RoguePlanet, GreatXML |
| 2026-07-08 | Microsoft July 2026 Patch Tuesday released (621 CVEs fixed) |
| 2026-07-14 | LegacyHive PoC publicly released on git.projectnightcrawler[.]dev and mirrored to GitHub (MSNightmare/LegacyHive) |
| 2026-07-15 | Security Affairs, The Hacker News, The Register publish coverage; Cyderes and ThreatLocker publish technical analyses |
| 2026-07-16 | Microsoft states it is "aware of the reported vulnerability and is actively investigating" |

## Root Cause: Logic Flaw in ProfSvc Hive Path Resolution

The root cause is a path trust vulnerability in ProfSvc's profile initialization routine. When loading a user's registry hives, ProfSvc reads the `Local AppData` path from the user's `NTUSER.DAT` hive and uses it to locate `UsrClass.dat`. The service does not validate that the resolved path points to a location within the authenticating user's profile directory. An attacker who can modify the `Local AppData` value in an offline `NTUSER.DAT` file can redirect ProfSvc's hive load through NT Object Manager symbolic links to any accessible hive file on the system, including an administrator's `UsrClass.dat`.

This is not a memory corruption vulnerability. It is a logic flaw in path resolution that chains three primitives: offline hive editing, Object Manager namespace redirection, and oplock-based race condition synchronization.

## Technical Analysis of the Malicious Payload

### 1. Environment Setup and Staging

The exploit binary (`LegacyHive.cpp`) accepts three command-line arguments: a secondary standard user's username, their password, and the target user whose hive will be loaded (typically an administrator).

The exploit performs the following setup:
- Generates a random GUID using `UuidCreate()` / `UuidToStringW()`
- Creates a staging directory at `C:\<GUID>\` with a permissive DACL granting `GENERIC_ALL` to Everyone (`SECURITY_WORLD_RID`) with `SUB_CONTAINERS_AND_OBJECTS_INHERIT`
- Authenticates as the secondary standard user via `LogonUserW` and impersonates them with `ImpersonateLoggedOnUser`

### 2. Offline NTUSER.DAT Modification

Using the Windows Offline Registry Library (`offreg.dll`), the exploit:
- Opens the secondary user's `NTUSER.DAT` via `OROpenHiveByHandle()`
- Navigates to `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` via `OROpenKey()`
- Modifies the `Local AppData` value to `\\.\globalroot\BaseNamedObjects\Restricted` using `ORSetValue()`
- Saves the modified hive via `ORSaveHive()`

This redirects the profile loading path through the NT Object Manager namespace instead of the filesystem.

### 3. Object Manager Namespace Construction

The exploit dynamically resolves `NtCreateSymbolicLinkObject` and `NtCreateDirectoryObjectEx` from `ntdll.dll` and constructs the following namespace:

- `\BaseNamedObjects\Restricted\<GUID>` -- directory object
- `\BaseNamedObjects\Restricted\Microsoft` -- shadow directory object
- `\BaseNamedObjects\Restricted\Microsoft\Windows` -- symbolic link, initially pointing to `\\??\C:\<GUID>` (the staging directory)

This namespace mirrors the path structure that ProfSvc will follow when resolving `\\.\globalroot\BaseNamedObjects\Restricted\Microsoft\Windows\UsrClass.dat`.

### 4. Oplock-Synchronized Race Condition

The exploit copies the target user's `UsrClass.dat` into the staging directory, then:
- Requests a batch opportunistic lock (`FSCTL_REQUEST_BATCH_OPLOCK`) via `DeviceIoControl` on the staged `UsrClass.dat`
- Spawns a helper thread that calls `CreateProcessWithLogonW` with the secondary user's credentials, `LOGON_WITH_PROFILE` and `CREATE_SUSPENDED` flags, launching `C:\Windows\notepad.exe`

When ProfSvc initializes the secondary user's profile during the logon triggered by `CreateProcessWithLogonW`:
1. ProfSvc follows the modified `Local AppData` path through the Object Manager namespace
2. The symbolic link initially resolves to the staging directory containing the attacker's `UsrClass.dat` copy
3. Accessing the staged `UsrClass.dat` triggers the batch oplock
4. The oplock callback closes the `Windows` symbolic link and recreates it pointing to `\\??\C:\Users\<TARGET>\AppData\Local\Microsoft\Windows` (the target user's real profile path)
5. The oplock is released; ProfSvc continues and now resolves the path to the target user's actual `UsrClass.dat`
6. The target user's `UsrClass.dat` is mounted into `HKU\<SID>_Classes` of the secondary user

### 5. Exploitation Result

The exploit calls `RegOpenUserClassesRoot` to verify access to the redirected hive. The attacker now has read-write access to the target user's `UsrClass.dat` contents, including:
- File type associations (the PoC demonstrates associating `.txt` files with `calc.exe` as proof)
- COM class registrations
- Windows Explorer history and shell settings
- Application compatibility data and forensic artifacts

The exploit displays "Hive loaded, press any key to unload and exit." and waits for operator input before cleanup.

### 6. Anti-Forensics / Evasion Techniques

The public PoC includes thread manipulation for cleanup: it retrieves the current thread handle, suspends it, and modifies `CONTEXT.Rip` to point to a `ThrowFunc()` that raises an exception, enabling structured exception-based cleanup flow. The staging directory and its contents are created with randomized GUID names, making path-based static detection impractical without behavioral monitoring.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `C:\<GUID>\` | N/A | Staging directory with Everyone:GENERIC_ALL DACL; GUID is randomly generated per execution |
| Windows | `C:\<GUID>\UsrClass.dat` | Varies | Copy of target user's UsrClass.dat placed in staging directory |
| Windows | `C:\<GUID>\ntuser.dat` | Varies | Modified copy of secondary user's NTUSER.DAT with redirected Local AppData value |
| Windows | `C:\Users\<target>\AppData\Local\Microsoft\Windows\UsrClass.dat` | N/A | Target hive file accessed during exploitation |

### Network

No network indicators. LegacyHive is a purely local privilege escalation exploit with no C2, staging, or exfiltration component.

### Behavioral

- **Registry modification:** `Local AppData` value under `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` set to `\\.\globalroot\BaseNamedObjects\Restricted` (or similar Object Manager path)
- **Object Manager namespace creation:** Directory objects and symbolic links created under `\BaseNamedObjects\Restricted` by a user-mode process
- **Cross-user hive access:** `UsrClass.dat` of one user mounted into another user's `HKU\<SID>_Classes` namespace
- **Oplock activity:** Batch opportunistic lock placed on a `UsrClass.dat` file in an unusual location (outside `C:\Users\`)
- **Suspended process creation:** `CreateProcessWithLogonW` with `LOGON_WITH_PROFILE` + `CREATE_SUSPENDED` spawning `notepad.exe` with explicit credentials
- **Offline hive manipulation:** `NTUSER.DAT` opened and modified using Offline Registry Library APIs (`OROpenHiveByHandle`, `ORSetValue`, `ORSaveHive`) outside of normal profile provisioning
- **GUID-named directories under C:\:** Directories with world-writable DACLs created at the root of the system drive

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1574 | Hijack Execution Flow | Object Manager symbolic link redirection forces ProfSvc to load an unintended registry hive by hijacking the path resolution during profile initialization. Note: T1574 is an approximate mapping -- no ATT&CK technique precisely captures service-level path trust abuse for registry hive redirection. |
| T1112 | Modify Registry | Offline modification of NTUSER.DAT to redirect Local AppData path; resulting read-write access to target user's UsrClass.dat enables arbitrary registry manipulation |
| T1134.001 | Access Token Manipulation: Token Impersonation/Theft | LogonUserW + ImpersonateLoggedOnUser used to authenticate as the secondary standard user and trigger profile loading |
| T1068 | Exploitation for Privilege Escalation | Exploits a logic flaw in ProfSvc's hive loading to escalate from standard user to administrator-level registry access |

## Impact Assessment

**Scope:** All supported versions of Windows 10, Windows 11, and Windows Server (2016, 2019, 2022), including systems with the July 2026 Patch Tuesday update applied.

**Severity:** The public PoC grants read-write access to an administrator's `UsrClass.dat` hive, enabling modification of file associations, COM registrations, and shell settings. While this is not direct code execution as SYSTEM, it provides a powerful primitive: an attacker could modify file associations to redirect program launches through a malicious payload, effectively achieving code execution in the administrator's context upon their next interactive logon. Security researcher Will Dormann characterized it as a "pretty powerful primitive."

**Limitations of public PoC:** Requires credentials for a second standard user and is limited to `UsrClass.dat`. The researcher claims the full exploit (not released) requires no additional credentials and can load any hive.

**Weaponization risk:** Huntress warned that capable actors will reverse-engineer the missing components in short order, citing rapid weaponization timelines observed with prior Nightmare Eclipse releases (BlueHammer was observed in active exploitation within 8 days of PoC release).

## Detection & Remediation

### Immediate Detection

Defenders can check for indicators of LegacyHive exploitation:

```powershell
# Check for Object Manager path in Local AppData registry values across all user profiles
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" |
  ForEach-Object { $sid = $_.PSChildName; reg query "HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Local AppData" 2>$null } |
  Select-String -Pattern "BaseNamedObjects"

# Check for GUID-named directories at C:\ root containing hive files
Get-ChildItem C:\ -Directory |
  Where-Object { $_.Name -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' } |
  ForEach-Object { Get-ChildItem $_.FullName -Filter "*.dat" -ErrorAction SilentlyContinue }

# Review Windows Security Event Log for explicit credential logon (4648) spawning notepad.exe
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4648} -MaxEvents 100 |
  Where-Object { $_.Message -match 'notepad' }
```

### Remediation

No patch is available as of July 17, 2026. Microsoft is investigating.

1. **Monitor aggressively:** Deploy detection rules (see below) to alert on the specific behavioral chain
2. **Audit explicit-credential logon events:** Review Event ID 4648 for suspicious patterns, particularly standard users creating processes with other users' credentials
3. **Restrict multi-account environments:** Where operationally feasible, limit the number of standard user accounts on sensitive systems to reduce the attack surface (the PoC requires a second standard user's credentials)
4. **Harden file system permissions:** Consider restricting standard user write access to `C:\` root to prevent staging directory creation (note: this may break some applications that rely on the default DACL)

### Long-Term Hardening

- **Path validation in ProfSvc:** Microsoft should validate that `Local AppData` and other shell folder paths in `NTUSER.DAT` resolve to locations within the authenticating user's profile directory before using them for hive loading
- **Object Manager namespace restrictions:** Restrict standard user ability to create symbolic links under `\BaseNamedObjects\Restricted` that mirror the profile path structure
- **Enhanced audit logging:** Windows should generate specific audit events when cross-user hive loading occurs

## Detection Rules

These detections target the LegacyHive PoC's distinctive artifacts: the Object Manager namespace path redirection in User Shell Folders (Sigma #1), registry hive file staging outside profile directories (Sigma #2), and the PoC binary's unique string constellation (YARA). No network rules apply -- this is a purely local exploit. All Sigma rules convert cleanly to Splunk and CrowdStrike; compile success does not equal detection fires -- verify in your pipeline.

### Sigma: Registry Set - Local AppData Redirection to Object Manager Namespace (LegacyHive)

Detects the core exploitation primitive: modification of Local AppData in User Shell Folders to point through `BaseNamedObjects\Restricted`, the Object Manager redirection path used by LegacyHive.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to network error (MITRE ATT&CK data download blocked by proxy), NOT a rule issue. sigma convert --without-pipeline splunk exit 0; log_scale exit 0. sigma convert -p splunk_windows -t splunk exit 0 (schema-mapped). No legitimate reason for Local AppData to point to an Object Manager namespace; extremely low FP risk. Evasion: attacker could use a different Object Manager path or modify a different shell folder value — this rule keys on the PoC's specific path. -->
```yaml
title: Registry Set - Local AppData Redirection to Object Manager Namespace (LegacyHive)
id: f79767cc-7071-4ea1-8e65-f53123ade73a
status: experimental
description: >
    Detects modification of the Local AppData value in User Shell Folders to point to
    the Object Manager namespace (BaseNamedObjects), a key step in the LegacyHive
    Windows User Profile Service privilege escalation exploit that enables cross-user
    registry hive redirection.
references:
    - https://www.cyderes.com/howler-cell/legacyhive-windows-user-profile-loading-vulnerability
    - https://thehackernews.com/2026/07/researcher-drops-new-windows-zero-day.html
author: Actioner
date: 2026/07/17
tags:
    - attack.t1112
    - attack.t1574
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|endswith: '\Explorer\User Shell Folders\Local AppData'
    selection_value:
        Details|contains: 'BaseNamedObjects\Restricted'
    condition: selection_key and selection_value
falsepositives:
    - None known - this registry value should never point to an Object Manager namespace path
level: critical
```

### Sigma: Registry Hive File Created Outside User Profile Directory (LegacyHive Staging)

Detects `ntuser.dat` or `UsrClass.dat` files created outside `C:\Users\` or `C:\Windows\`, indicating potential staging of registry hive files for LegacyHive exploitation.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. sigma convert -p splunk_windows -t splunk exit 0 (schema-mapped). FP surface: MDT/SCCM/OSD imaging tools may create hive files in staging locations during profile provisioning; USMT migration scenarios. Filter on environment. Evasion: attacker could stage hive files under C:\Users\ in a decoy profile directory — this rule would not catch that case. -->
```yaml
title: Registry Hive File Created Outside User Profile Directory (LegacyHive Staging)
id: 5c4b0764-b5a9-45dd-97e9-b91f1cefe3bf
status: experimental
description: >
    Detects creation of Windows registry hive files (ntuser.dat, UsrClass.dat) outside
    the normal user profile directory, which may indicate staging for the LegacyHive
    privilege escalation exploit that copies and modifies hive files in attacker-controlled
    directories.
references:
    - https://www.cyderes.com/howler-cell/legacyhive-windows-user-profile-loading-vulnerability
    - https://thehackernews.com/2026/07/researcher-drops-new-windows-zero-day.html
author: Actioner
date: 2026/07/17
tags:
    - attack.t1574
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\ntuser.dat'
            - '\UsrClass.dat'
    filter_normal_paths:
        TargetFilename|startswith:
            - 'C:\Users\'
            - 'C:\Windows\'
    condition: selection and not filter_normal_paths
falsepositives:
    - System provisioning or imaging tools that create user profiles outside default locations
    - MDT or SCCM offline profile operations
level: high
```

### Snort: N/A

No network indicators. LegacyHive is a purely local privilege escalation exploit with no network communication component.

### Suricata: N/A

No network indicators. LegacyHive is a purely local privilege escalation exploit with no network communication component.

### YARA: LegacyHive PoC Binary Detection

Detects the compiled LegacyHive PoC binary by matching its distinctive output strings, Object Manager namespace paths, and Offline Registry Library API imports.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: positive (constructed MZ + PoC strings from published source) fired, negative (benign MZ) quiet. Strings sourced from published LegacyHive.cpp on git.projectnightcrawler.dev and GitHub mirror MSNightmare/LegacyHive: "oplock triggered", "Hive loaded", "globalroot\BaseNamedObjects\Restricted" are verbatim PoC output/path strings. API names (NtCreateSymbolicLinkObject, NtCreateDirectoryObjectEx, OROpenHiveByHandle, RegOpenUserClassesRoot, ORSetValue) resolved dynamically in the PoC via GetProcAddress. Condition requires PE header + size cap + multiple string-class matches to avoid single-string FPs. Evasion: recompilation with modified output strings or stripped symbols defeats this rule — it is PoC-specific, not technique-durable. -->
```yara
rule Exploit_LegacyHive_ProfSvc_PoC
{
    meta:
        description = "Detects the LegacyHive PoC exploit binary targeting Windows User Profile Service for privilege escalation via registry hive redirection"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://www.cyderes.com/howler-cell/legacyhive-windows-user-profile-loading-vulnerability"
        severity = "critical"

    strings:
        $poc1 = "oplock triggered" wide ascii
        $poc2 = "Hive loaded" wide ascii
        $poc3 = "press any key to unload and exit" wide ascii

        $path1 = "globalroot\\BaseNamedObjects\\Restricted" wide ascii
        $path2 = "BaseNamedObjects\\Restricted\\Microsoft" wide ascii

        $reg1 = "User Shell Folders" wide ascii
        $reg2 = "Local AppData" wide ascii

        $api1 = "NtCreateSymbolicLinkObject" ascii
        $api2 = "NtCreateDirectoryObjectEx" ascii
        $api3 = "OROpenHiveByHandle" ascii
        $api4 = "RegOpenUserClassesRoot" ascii
        $api5 = "ORSetValue" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($poc*) and 1 of ($path*)) or
            (2 of ($path*) and 2 of ($api*)) or
            (1 of ($poc*) and 2 of ($api*) and 1 of ($reg*))
        )
}
```

## Lessons Learned

LegacyHive demonstrates that trusted system services which resolve user-controlled paths without validation remain a fertile attack surface on Windows. The exploit requires no memory corruption -- it chains three well-understood primitives (offline hive editing, Object Manager symbolic links, and oplocks) into a novel escalation path. This is the same architectural pattern (user-redirectable paths + SYSTEM-privileged file operations) that Nightmare Eclipse has exploited across nine different vulnerabilities since April 2026, suggesting that a systemic hardening pass on Windows profile and service path resolution is overdue.

The deliberately stripped-down public PoC lowers the immediate risk but creates a ticking clock: the core technique is fully documented, and the missing components (removing the credential requirement, extending beyond `UsrClass.dat`) are straightforward for skilled attackers to reconstruct. Organizations should prioritize deploying the behavioral detections above and monitoring for signs of hive-based privilege escalation rather than waiting for a patch.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Security Affairs - Chaotic Eclipse Unveils LegacyHive](https://securityaffairs.com/195418/hacking/chaotic-eclipse-unveils-legacyhive-exploit-affecting-fully-patched-windows-systems.html) -- initial coverage of PoC release and researcher background
- [The Hacker News - Researcher Drops New Windows Zero-Day PoC](https://thehackernews.com/2026/07/researcher-drops-new-windows-zero-day.html) -- detailed technical analysis citing Cyderes breakdown of exploitation chain
- [The Register - LegacyHive Zero-Day](https://www.theregister.com/security/2026/07/15/microsofts-serial-tormentor-drops-legacyhive-0-day/5271723) -- researcher background, Huntress and Will Dormann commentary on weaponization risk
- [Cyderes - LegacyHive Windows User Profile Loading Vulnerability](https://www.cyderes.com/howler-cell/legacyhive-windows-user-profile-loading-vulnerability) -- primary technical analysis of exploitation chain and detection artifacts
- [ThreatLocker - LegacyHive Video Demo and Analysis](https://www.threatlocker.com/blog/legacyhive-video-demo-and-analysis-of-windows-0-day-from-nightmareeclipse) -- detailed API-level analysis including Object Manager namespace construction and oplock mechanism
- [Rescana - Critical Windows Zero-Day LegacyHive Analysis](https://www.rescana.com/post/critical-windows-10-11-and-server-zero-day-legacyhive-exploit-enables-privilege-escalation-via-user-profile-service-vuln) -- event ID detection guidance and observable indicators
- [GitHub Mirror - MSNightmare/LegacyHive (LegacyHive.cpp)](https://github.com/MSNightmare/LegacyHive/blob/main/LegacyHive.cpp) -- PoC source code providing API calls, string constants, and exploitation logic

---
*Report generated by Actioner*
