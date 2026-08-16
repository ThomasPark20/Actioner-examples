# Technical Analysis Report: ShieldBreak — Microsoft Defender CVE-2026-50656 Patch Bypass (2026-08-16)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-16
Version: 0.1 (DRAFT)

## Executive Summary

On August 11-12, 2026, security researcher Chaotic Eclipse (also tracked as INFINITE NIGHTMARE, MSNightmare, Nightmare Eclipse) publicly released "ShieldBreak," a proof-of-concept exploit that bypasses Microsoft's July 2026 patch for CVE-2026-50656 (RoguePlanet) in the Microsoft Defender Malware Protection Engine (mpengine.dll). ShieldBreak achieves NT AUTHORITY\SYSTEM privileges from an unprivileged user account with a claimed 100% success rate on Windows 11 25H2 (including Canary channel) and Windows Server 2025. Unlike RoguePlanet, which used VHD/VHDX virtual disk mounting and NT Native API race conditions, ShieldBreak employs a fundamentally different technique: it registers a rogue cloud storage provider via the Cloud Filter API (cfapi), plants an EICAR test file to trigger Defender scanning, then uses CLFS (Common Log File System) log manipulation combined with Object Manager symbolic links to redirect Defender's SYSTEM-privileged remediation into writing an attacker-controlled payload (Warden.dll) as phoneinfo.dll in System32. The Windows Error Reporting process (wermgr.exe) then loads the planted DLL, spawning conhost.exe with SYSTEM privileges. The exploit coordinates token duplication through a named pipe (`\\.\pipe\SHIELDBREAK`). ShieldBreak expands the attack surface to Windows Server 2025, including domain controllers and session hosts, which were not previously targetable by RoguePlanet. Microsoft stated on August 13, 2026 that it is "investigating the validity and potential applicability of these claims." No patch is available as of August 16, 2026. Multiple independent analysts (Kevin Beaumont, Will Dormann of Tharros) have validated the exploit's functionality. This is the eighth public exploit in the Nightmare Eclipse campaign against Microsoft Defender.

## Background: CVE-2026-50656 (RoguePlanet) and Its Patch

CVE-2026-50656 (CVSS 7.8, CWE-59: Improper Link Resolution Before File Access) is a privilege escalation vulnerability in the Microsoft Defender Malware Protection Engine that was originally disclosed as "RoguePlanet" in June 2026 by the same researcher. The vulnerability exploits the fact that MsMpEng.exe runs under NT AUTHORITY\SYSTEM and performs file remediation operations at that privilege level. By manipulating the file path between Defender's check and its remediation action (a TOCTOU race condition), an attacker can redirect SYSTEM-privileged writes to arbitrary locations. Microsoft released a patch in the Malware Protection Engine update v1.1.26060.3008 on July 9, 2026. That patch hardened the `mpengine!SysIO*` API to block junction/symlink attacks used by RoguePlanet and earlier exploits in the family (BlueHammer CVE-2026-33825, RedSun CVE-2026-41091, UnDefend CVE-2026-45498). ShieldBreak demonstrates that the July patch is insufficient: it attacks a different code path in the same engine, using cloud-hydration scanning rather than the junction/VHD-based path that was patched.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-02 | BlueHammer (CVE-2026-33825) PoC publicly released |
| 2026-05-20 | Microsoft patches CVE-2026-41091 (RedSun) and CVE-2026-45498 (UnDefend) |
| 2026-06-09 | RoguePlanet PoC released on GitHub; subsequently mirrored to projectnightcrawler[.]dev |
| 2026-06-16 | Microsoft acknowledges RoguePlanet zero-day |
| 2026-07-09 | Microsoft releases CVE-2026-50656 patch (Engine v1.1.26060.3008) |
| 2026-07-16 | LegacyHive exploit released by same researcher (separate vulnerability) |
| 2026-08-11 | ShieldBreak PoC released on researcher's blog (blog[.]projectnightcrawler[.]dev) |
| 2026-08-12 | ShieldBreak source code published on GitHub (MSNightmare/ShieldBreak) and mirrored to git[.]projectnightcrawler[.]dev |
| 2026-08-12 | The Hacker News, BleepingComputer, SecurityWeek, Security Affairs publish coverage |
| 2026-08-13 | Microsoft states it is "investigating the validity and potential applicability of these claims" |
| 2026-08-13 | Kevin Beaumont publishes three detection queries for Defender for Endpoint |
| 2026-08-13 | Tanium publishes mitigation guidance (0-byte phoneinfo.dll placeholder) |
| 2026-08-16 | No Microsoft patch available; no CVE assigned for ShieldBreak specifically |

## Root Cause: Cloud Filter API Abuse + CLFS Log Manipulation in Defender Scanning

The root cause is the same underlying weakness as CVE-2026-50656: CWE-59 (Improper Link Resolution Before File Access) in Microsoft Defender's file remediation pipeline. However, ShieldBreak attacks a different entry point that was not addressed by the July 2026 patch. Where RoguePlanet used VHD/VHDX mounting and NT Native API race conditions with oplocks and NTFS junctions, ShieldBreak uses a user-mode callback hook to change file contents during a Defender cloud-hydration scan via the Cloud Filter API (cfapi). The exploit combines CLFS log manipulation with Object Manager symbolic links to trick Defender's scanning pipeline into locking a legitimate system file while a malicious substitute is swapped underneath it. Security analyst Will Dormann noted that ShieldBreak does not use anything from the RoguePlanet technique (no cloud providers, CLFS, hydration, or phoneinfo.dll were involved in RoguePlanet), and unlike RoguePlanet, ShieldBreak requires Defender to be actively enabled. Despite this, both exploit the same fundamental weakness (CWE-59) in the same component (mpengine.dll), and the researcher classifies ShieldBreak as a bypass of the CVE-2026-50656 patch.

## Technical Analysis of the Malicious Payload

### 1. Rogue Cloud Sync Provider Registration (Initial Setup)

The exploit creates a working directory `C:\ShieldBreak_<GUID>` and registers it with the Windows Cloud Files platform as a sync root. This registration creates a cloud storage provider context that enables the exploit to control file hydration callbacks via the Cloud Filter API (cfapi). The exploit places a placeholder file named "BERLIN" in this directory, sized to match the EICAR test file (eicar_com.zip). The BERLIN placeholder serves as the bait that will be manipulated through the exploit chain.

### 2. Object Manager Directory Configuration

The exploit establishes two Object Manager symbolic link paths for Defender resolution:

- **Direct entry:** `\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN` pointing to `\??\C:\ShieldBreak_<GUID>`
- **Fallback:** `\\.\globalroot\BaseNamedObjects\Restricted\WD_TARGET_<GUID>\WD_SCAN` pointing to `\CLFS\??\C:\ShieldBreak_<GUID>`

This dual-path setup is critical: the exploit first uses the direct path, then at the key moment deletes it to force Defender to fall back to the CLFS-mediated path, enabling the file swap.

### 3. Alternate Data Stream Preparation and Defender Trigger

The exploit fills `BERLIN:stream` (an NTFS Alternate Data Stream) with a byte-for-byte copy of ntdll.dll to prevent Defender from deleting the file during remediation. It then resolves Windows Defender APIs dynamically via MpClient.dll and triggers a scan pointing to the BERLIN placeholder. When Defender begins scanning, the exploit hydrates the placeholder with eicar_com.zip contents, triggering a malware detection and initiating Defender's SYSTEM-privileged remediation sequence.

### 4. CLFS Log Manipulation and File Swap

The exploit watches for `.blf` (CLFS base log file) creation, which signals that Defender's remediation has begun. At this point, the exploit:

1. Deletes the direct Object Manager symlink, forcing Defender's fallback to the CLFS-mediated path
2. Recreates the direct link with a new target: `\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll`
3. Modifies BERLIN's unnamed data stream with the embedded Warden.dll payload
4. Rehydrates the file, causing Defender's SYSTEM-privileged remediation to write the malicious payload as phoneinfo.dll in System32

The key insight is that phoneinfo.dll does not exist by default on Windows, making this a clean DLL planting attack rather than a DLL replacement.

### 5. SYSTEM Privilege Achievement via Windows Error Reporting

After phoneinfo.dll is planted in System32, the exploit triggers the QueueReporting scheduled task, which runs `wermgr.exe -upload` as SYSTEM. In the wer.dll code, there is an explicit code path that loads phoneinfo.dll. Because the attacker-controlled Warden.dll now exists at that path, wer.dll loads it. Warden.dll duplicates the SYSTEM token and communicates back to the user-level exploit process via the `\\.\pipe\SHIELDBREAK` named pipe, then spawns conhost.exe with the duplicated SYSTEM token, granting the attacker an interactive SYSTEM-level shell.

### 6. Anti-Forensics / Evasion Techniques

- Cloud sync provider registration is transient and cleaned up after exploitation
- The exploit requires Defender to be actively enabled (ironic: the security product is the attack vector)
- CLFS log manipulation is a novel technique not commonly monitored by forensic tooling
- The fabricated Report.wer file masks the activity as a normal Windows Error Reporting crash event
- Object Manager symbolic links exist only in the kernel namespace and are not visible in standard file system forensics
- 100% success rate (per researcher claim) eliminates the forensic ambiguity of race condition failures seen with RoguePlanet

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Microsoft Malware Protection Engine (mpengine.dll) | v1.1.26060.3008 (July 2026 patch applied) | Vulnerable to ShieldBreak bypass despite CVE-2026-50656 patch |
| Microsoft Defender Antimalware Platform | Current August 2026 builds | Vulnerable on Windows 11 25H2 and Server 2025 |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | ShieldBreak.exe | 4e3146d667812ace49638e15f9dbb37b9e13f7222ed4984e065723715c692338 | PoC exploit binary (C++ compiled, Visual Studio project) |
| Windows | Warden.dll | 691857f3f28049a7e33f5767d4e4eb3d739e1aa76c2a43c8cccadf871cfa7c1a | Payload DLL for SYSTEM token duplication and shell spawning |
| Windows | eicar_com.zip | 87cc7ad5f7e8d70250bff5c92c8316f3a508c089eb81e9921c8941eca5a741d6 | EICAR test file used to trigger Defender detection |
| Windows | C:\Windows\System32\phoneinfo.dll | (matches Warden.dll hash after planting) | DLL planting target; does not exist by default |
| Windows | C:\ShieldBreak_\<GUID\>\ | N/A | Exploit working directory (transient) |
| Windows | C:\ShieldBreak_\<GUID\>\BERLIN | N/A | Cloud Files placeholder used in the exploit chain |
| Windows | Report.wer | N/A | Fabricated APPCRASH event for WER abuse |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | blog[.]projectnightcrawler[.]dev | Researcher blog; ShieldBreak disclosure post |
| Domain | git[.]projectnightcrawler[.]dev | Mirror of exploit source code |
| URL | hxxps://github[.]com/MSNightmare/ShieldBreak | PoC source code repository |
| URL | hxxps://blog[.]projectnightcrawler[.]dev/posts/2026-08-11-shieldbreak-august-2026-disclosure/ | Original disclosure post |

Note: ShieldBreak is a purely local privilege escalation exploit. There are no C2, staging, or exfiltration network indicators associated with the PoC itself. The network IOCs above are hosting infrastructure only.

### Behavioral

- Non-Defender processes loading both MpClient.dll and cldapi.dll (Cloud Filter API)
- Creation of phoneinfo.dll in `C:\Windows\System32\` (does not exist by default)
- Working directories matching pattern `C:\ShieldBreak_<GUID>\`
- Cloud Files sync root registration from non-standard processes
- CLFS `.blf` log file creation in exploit working directories
- Object Manager symlinks created under `\BaseNamedObjects\Restricted\` with `WD_SHADOW` or `WD_TARGET` prefixes
- Named pipe creation: `\\.\pipe\SHIELDBREAK`
- wermgr.exe spawning conhost.exe, cmd.exe, or powershell.exe as child processes
- Placeholder file named "BERLIN" with EICAR content and ntdll.dll in alternate data stream
- Fabricated Report.wer files written by non-SYSTEM user processes
- QueueReporting scheduled task execution following suspicious file system activity
- SYSTEM token duplication via DuplicateTokenEx / CreateProcessAsUser from wer.dll context

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | TOCTOU / improper link resolution (CWE-59) in Defender's cloud-hydration scanning exploited for SYSTEM privileges |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Planting phoneinfo.dll in System32 to be loaded by wer.dll during Windows Error Reporting |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Warden.dll loaded as phoneinfo.dll by wer.dll / wermgr.exe to execute attacker code as SYSTEM |
| T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Warden.dll duplicates SYSTEM token via DuplicateTokenEx and CreateProcessAsUser to spawn elevated shell |
| T1053.005 | Scheduled Task/Job: Scheduled Task | QueueReporting scheduled task abused to trigger wermgr.exe -upload, loading the planted DLL |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Exploit abuses Defender's own remediation engine as the privilege escalation vector |

## Impact Assessment

**Breadth:** All Windows 11 25H2 systems (including Canary channel) and Windows Server 2025 running Microsoft Defender with the July 2026 CVE-2026-50656 patch applied are confirmed vulnerable. Windows 10 is likely affected but the PoC has not been tested on those editions. The expansion to Windows Server 2025 is significant: unlike RoguePlanet, ShieldBreak can target domain controllers and Remote Desktop session hosts, substantially increasing the blast radius in enterprise environments.

**Depth:** The vulnerability grants full SYSTEM privileges from an unprivileged user account with a claimed 100% success rate. This represents maximum local impact and enables complete system compromise including credential extraction, persistence installation, and lateral movement. The deterministic success rate makes ShieldBreak more operationally reliable than RoguePlanet, which had a variable success rate dependent on race condition timing.

**Stealth:** Unlike RoguePlanet's non-deterministic race condition, ShieldBreak's deterministic technique leaves a more consistent (and detectable) footprint: the SHIELDBREAK named pipe, phoneinfo.dll creation, cloud provider registration, and CLFS log manipulation are all observable artifacts. However, the use of legitimate Windows mechanisms (Cloud Filter API, Windows Error Reporting, scheduled tasks) provides strong cover within normal system activity.

**Patch Status:** No Microsoft patch is available as of August 16, 2026. Microsoft is "investigating the validity and potential applicability of these claims."

## Detection & Remediation

### Immediate Detection

**Check for ShieldBreak exploit artifacts:**
```powershell
# Search for ShieldBreak exploit binary and Warden.dll payload
Get-ChildItem -Path C:\Users,C:\ProgramData,C:\Temp -Recurse -Include "ShieldBreak.exe","Warden.dll" -ErrorAction SilentlyContinue

# Check for phoneinfo.dll in System32 (should NOT exist by default)
Test-Path "C:\Windows\System32\phoneinfo.dll"

# Search for ShieldBreak working directories
Get-ChildItem -Path C:\ -Directory -Filter "ShieldBreak_*" -ErrorAction SilentlyContinue

# Check for the SHIELDBREAK named pipe
Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "SHIELDBREAK" }

# Look for suspicious wermgr.exe child processes
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1 -and $_.Properties[20].Value -match "wermgr" -and $_.Properties[4].Value -match "conhost|cmd|powershell" }

# Search for fabricated Report.wer files created by non-SYSTEM users
Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\WER\ReportQueue" -Recurse -Filter "Report.wer" -ErrorAction SilentlyContinue
```

**Kevin Beaumont's Defender for Endpoint (MDE) hunting queries** (from [GossiTheDog/ThreatHunting](https://github.com/GossiTheDog/ThreatHunting/blob/master/AdvancedHuntingQueries/ShieldBreak.kql)):
```kql
// Detection 1 - Non-Defender processes loading MpClient.dll
DeviceImageLoadEvents
| where ActionType == "ImageLoaded"
| where FileName == "MpClient.dll"
| where not(
    InitiatingProcessFolderPath startswith @"C:\Program Files\Windows Defender\"
    or InitiatingProcessFolderPath startswith @"C:\ProgramData\Microsoft\Windows Defender\"
    or InitiatingProcessFolderPath startswith @"C:\Windows\System32\"
)

// Detection 2 - Unvetted processes loading Cloud Filter API
DeviceImageLoadEvents
| where ActionType == "ImageLoaded"
| where FileName == "cldapi.dll"
| where not(
    InitiatingProcessFolderPath startswith @"C:\Windows\System32\"
    or InitiatingProcessFolderPath startswith @"C:\Program Files\"
    or InitiatingProcessFolderPath startswith @"C:\Program Files (x86)\"
)

// Detection 3 - Process loading BOTH MpClient and Cloud API within 5 minutes
let mp_loads = DeviceImageLoadEvents | where FileName == "MpClient.dll";
let cld_loads = DeviceImageLoadEvents | where FileName == "cldapi.dll";
mp_loads | join kind=inner cld_loads on DeviceName, InitiatingProcessId
| where abs(datetime_diff('minute', MpTime, CldTime)) < 5
```

### Remediation

1. **Immediate (workaround):** Deploy a 0-byte phoneinfo.dll placeholder file to `C:\Windows\System32\phoneinfo.dll` to block the DLL planting attack. Tanium has published a deployment and rollback package for this mitigation. Test on limited endpoints first due to potential side effects.
2. **Immediate:** Deploy application allowlisting (ThreatLocker, AppLocker, or similar) to prevent unknown executables from running. ThreatLocker has published detection rules TL.SC.1855 and TL.EV.1856 for ShieldBreak.
3. **Short-term:** Enable Sysmon with image load logging (Event ID 7) to detect MpClient.dll and cldapi.dll loading by non-standard processes.
4. **Short-term:** Monitor for phoneinfo.dll creation in System32 and alert immediately.
5. **Short-term:** Hunt for the SHIELDBREAK named pipe and ShieldBreak working directories.
6. **Pending patch:** Apply Microsoft Defender engine update as soon as a patch is released.
7. **If compromised:** Rotate all local account passwords; check for SYSTEM-level persistence (services, scheduled tasks, WMI subscriptions); verify integrity of System32 DLLs.

### Long-Term Hardening

- Enable Sysmon with comprehensive process creation (EID 1), image load (EID 7), file creation (EID 11), pipe creation (EID 17/18), and named pipe events
- Implement application allowlisting to prevent unauthorized binary execution
- Monitor Cloud Files sync root registration for anomalous providers
- Monitor CLFS log file creation outside normal database/transactional contexts
- Monitor wermgr.exe child process creation (should not spawn interactive shells)
- Consider pre-planting a signed, benign phoneinfo.dll as a defensive measure until Microsoft patches
- Restrict QueueReporting scheduled task permissions where feasible

## Detection Rules

These detections target the ShieldBreak exploit chain at the PoC/advisory-specific altitude. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. ShieldBreak is a purely local privilege escalation exploit with no network indicators, so Snort and Suricata rules are not applicable.

### Sigma: ShieldBreak Cloud Filter API Abuse for Defender Bypass
Detects a non-standard process loading both MpClient.dll and cldapi.dll, the signature behavior of the ShieldBreak exploit's cloud-hydration scan manipulation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0; log_scale 0; splunk_windows pipeline 0. Mirrors Kevin Beaumont's Detection 3 KQL query logic. image_load category on Windows. Filters Defender paths and standard Program Files/System32. FP: third-party EDR or cloud sync clients that also interact with Defender APIs (rare). Evasion: loading from a whitelisted path — mitigated by the path filter being inclusive of standard install locations only. -->
```yaml
title: ShieldBreak Cloud Filter API Abuse for Defender Bypass
id: 8f4e2c1a-3b7d-4e9a-a6c5-2d1f0e8b7a3c
status: experimental
description: >
    Detects a non-standard process loading both MpClient.dll (Windows Defender API)
    and cldapi.dll (Cloud Filter API) — the core technique in the ShieldBreak exploit
    which registers a rogue cloud sync provider and abuses Defender's cloud-hydration
    scan path to achieve SYSTEM privilege escalation via CVE-2026-50656 bypass.
references:
    - https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html
    - https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/
    - https://github.com/MSNightmare/ShieldBreak
    - https://github.com/GossiTheDog/ThreatHunting/blob/master/AdvancedHuntingQueries/ShieldBreak.kql
author: Actioner
date: 2026/08/16
tags:
    - attack.t1068
    - attack.t1574
logsource:
    category: image_load
    product: windows
detection:
    selection_mpclient:
        ImageLoaded|endswith: '\MpClient.dll'
    selection_cldapi:
        ImageLoaded|endswith: '\cldapi.dll'
    filter_defender:
        Image|startswith:
            - 'C:\Program Files\Windows Defender\'
            - 'C:\ProgramData\Microsoft\Windows Defender\'
    filter_system:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection_mpclient and selection_cldapi and not filter_defender and not filter_system
falsepositives:
    - Third-party EDR or security tools loading both Defender and Cloud Filter APIs
    - Cloud storage sync clients that also interact with Defender APIs
level: high
```

### Sigma: Suspicious phoneinfo.dll Creation in System32
Detects creation of phoneinfo.dll in System32, the DLL planting target that does not exist by default on Windows.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0; log_scale 0; splunk_windows pipeline 0. phoneinfo.dll does not exist on clean Windows installations. Any creation is anomalous and warrants immediate investigation. Near-zero FP expected. -->
```yaml
title: Suspicious phoneinfo.dll Creation in System32
id: 1a3c5e7f-9b2d-4f6a-8c1e-0d3f5a7b9c2e
status: experimental
description: >
    Detects creation of phoneinfo.dll in the System32 directory, the key payload
    delivery step in the ShieldBreak exploit. The exploit uses Defender's SYSTEM-level
    file remediation to write an attacker-controlled Warden.dll payload as
    phoneinfo.dll in System32, which is then loaded by wer.dll (Windows Error
    Reporting) to spawn conhost.exe with SYSTEM privileges.
references:
    - https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html
    - https://www.securityweek.com/nightmare-eclipse-drops-windows-zero-day-exploit-shieldbreak/
    - https://www.tanium.com/blog/shieldbreak-mitigation
    - https://github.com/MSNightmare/ShieldBreak
author: Actioner
date: 2026/08/16
tags:
    - attack.t1068
    - attack.t1574.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\System32\phoneinfo.dll'
    condition: selection
falsepositives:
    - Legitimate Windows updates installing phoneinfo.dll (not present by default)
level: critical
```

### Sigma: Suspicious Child Process Spawned by Windows Error Reporting Manager
Detects wermgr.exe spawning interactive shell processes, which is the final privilege escalation step in ShieldBreak.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0; log_scale 0; splunk_windows pipeline 0. wermgr.exe should not spawn conhost.exe, cmd.exe, or powershell.exe in normal operation. FP: extremely rare — WER crash reporting may invoke conhost for console output but not interactive shells. -->
```yaml
title: Suspicious Child Process Spawned by Windows Error Reporting Manager
id: 5c7a9e1b-3d2f-4b6c-8e0a-1f4d7b9c3e5a
status: experimental
description: >
    Detects wermgr.exe spawning conhost.exe or cmd.exe as a child process, which
    is the final privilege escalation step in the ShieldBreak exploit. After
    phoneinfo.dll is planted in System32, the QueueReporting scheduled task runs
    wermgr.exe -upload, which loads wer.dll, which in turn loads the attacker-
    controlled phoneinfo.dll, spawning a SYSTEM-level shell via conhost.exe.
references:
    - https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html
    - https://www.securityweek.com/nightmare-eclipse-drops-windows-zero-day-exploit-shieldbreak/
    - https://www.tanium.com/blog/shieldbreak-mitigation
    - https://github.com/MSNightmare/ShieldBreak
author: Actioner
date: 2026/08/16
tags:
    - attack.t1068
    - attack.t1574.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\wermgr.exe'
    selection_child:
        Image|endswith:
            - '\conhost.exe'
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Windows Error Reporting spawning conhost.exe for console output during crash reporting (rare)
level: high
```

### Sigma: ShieldBreak Named Pipe Creation
Detects creation of the SHIELDBREAK named pipe used for SYSTEM token duplication coordination.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0; log_scale 0; splunk_windows pipeline 0. SHIELDBREAK is a distinctive, hardcoded exploit artifact. Trivially evaded by rename, but catches unmodified PoC usage. Near-zero FP. -->
```yaml
title: ShieldBreak Named Pipe Creation
id: 2b4d6f8a-1c3e-5a7b-9d0f-4e6c8a2b1d3f
status: experimental
description: >
    Detects creation of the SHIELDBREAK named pipe used by the ShieldBreak exploit
    for inter-process coordination during the privilege escalation sequence. The
    exploit creates \\.\pipe\SHIELDBREAK to synchronize the token duplication
    between the Warden.dll payload running as SYSTEM and the user-level exploit process.
references:
    - https://www.threatlocker.com/blog/nightmareeclipse-releases-new-poc-shieldbreak-exploits-same-weakness-as-rogueplanet
    - https://github.com/MSNightmare/ShieldBreak
author: Actioner
date: 2026/08/16
tags:
    - attack.t1068
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName: '\SHIELDBREAK'
    condition: selection
falsepositives:
    - Unlikely - SHIELDBREAK is a distinctive exploit artifact name
level: critical
```

### Snort: N/A
ShieldBreak is a purely local privilege escalation exploit with no network communication component. No network-based detection is applicable.

### Suricata: N/A
ShieldBreak is a purely local privilege escalation exploit with no network communication component. No network-based detection is applicable.

### YARA: ShieldBreak / Warden.dll Exploit Tool Detection
Detects the ShieldBreak.exe exploit binary and Warden.dll payload via distinctive strings: named pipe, cloud provider artifacts, Object Manager path prefixes, and Defender API references.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos_shieldbreak.bin: MATCH (Exploit_ShieldBreak_Defender_LPE). yara neg_shieldbreak.bin: no match. Positive sample constructed from published source code strings (SHIELDBREAK pipe, ShieldBreak, phoneinfo.dll, Warden.dll, BERLIN, WD_SHADOW, WD_TARGET, WD_SCAN, MpClient.dll, cldapi.dll, NtSetInformationFile, NtDeleteFile, NtOpenDirectoryObject). Condition: PE + size<10MB + (pipe name + ShieldBreak string) OR (3+ distinctive strings + 1 API) OR (phoneinfo + Warden + ShieldBreak). Second rule targets Warden.dll payload specifically via token duplication APIs + SHIELDBREAK pipe + conhost/phoneinfo strings. -->
```yara
rule Exploit_ShieldBreak_Defender_LPE
{
    meta:
        description = "Detects the ShieldBreak exploit tool that bypasses the CVE-2026-50656 patch in Microsoft Defender to achieve SYSTEM privilege escalation via Cloud Filter API abuse and CLFS log manipulation"
        author = "Actioner"
        date = "2026-08-16"
        reference = "https://github.com/MSNightmare/ShieldBreak"
        hash = "4e3146d667812ace49638e15f9dbb37b9e13f7222ed4984e065723715c692338"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pipe1 = "\\\\.\\pipe\\SHIELDBREAK" ascii wide
        $pipe2 = "SHIELDBREAK" ascii wide fullword

        $str1 = "ShieldBreak" ascii wide
        $str2 = "phoneinfo.dll" ascii wide nocase
        $str3 = "Warden.dll" ascii wide nocase
        $str4 = "BERLIN" ascii wide fullword
        $str5 = "WD_SHADOW" ascii wide
        $str6 = "WD_TARGET" ascii wide
        $str7 = "WD_SCAN" ascii wide
        $str8 = "QueueReporting" ascii wide

        $api1 = "MpClient.dll" ascii nocase
        $api2 = "cldapi.dll" ascii nocase
        $api3 = "NtSetInformationFile" ascii fullword
        $api4 = "NtDeleteFile" ascii fullword
        $api5 = "NtOpenDirectoryObject" ascii fullword

        $path1 = "BaseNamedObjects\\Restricted" ascii wide
        $path2 = "eicar_com.zip" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($pipe1 or ($pipe2 and $str1)) or
            (3 of ($str*) and 1 of ($api*)) or
            ($str2 and $str3 and $str1) or
            ($str5 and $str6 and $str7 and 1 of ($api*)) or
            (1 of ($path*) and 2 of ($str*) and 1 of ($api*))
        )
}

rule Payload_Warden_DLL_ShieldBreak
{
    meta:
        description = "Detects the Warden.dll payload used by the ShieldBreak exploit to duplicate the SYSTEM token and spawn a privileged shell"
        author = "Actioner"
        date = "2026-08-16"
        reference = "https://github.com/MSNightmare/ShieldBreak"
        hash = "691857f3f28049a7e33f5767d4e4eb3d739e1aa76c2a43c8cccadf871cfa7c1a"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pipe = "SHIELDBREAK" ascii wide fullword
        $str1 = "conhost.exe" ascii wide nocase
        $str2 = "phoneinfo" ascii wide nocase
        $api1 = "DuplicateTokenEx" ascii fullword
        $api2 = "CreateProcessAsUser" ascii fullword
        $api3 = "ImpersonateNamedPipeClient" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $pipe and
        2 of ($api*) and
        1 of ($str*)
}
```

## Lessons Learned

1. **Patching one attack path does not close the underlying weakness.** Microsoft's July 2026 patch addressed the specific VHD/junction-based exploitation path of CVE-2026-50656 but did not resolve the underlying CWE-59 (Improper Link Resolution Before File Access) across all of Defender's file handling code paths. ShieldBreak demonstrates that the same fundamental flaw can be reached through a completely different entry point (Cloud Filter API cloud-hydration scanning), rendering the patch insufficient.

2. **SYSTEM-level antimalware processes remain a systemic privilege escalation target.** The Nightmare Eclipse campaign has now produced eight public exploits against Microsoft Defender in five months (BlueHammer, RedSun, UnDefend, YellowKey, GreenPlasma, MiniPlasma, RoguePlanet, ShieldBreak, plus LegacyHive), all leveraging the same architectural pattern: Defender runs as SYSTEM, performs file operations triggered by user-controlled input, and the path resolution can be manipulated. This is an architectural weakness, not a series of independent bugs.

3. **Deterministic exploits demand faster response.** ShieldBreak's claimed 100% success rate and expansion to Windows Server 2025 (including domain controllers) raises the operational risk from "probabilistic local escalation" to "reliable infrastructure compromise." The absence of a patch four days after disclosure underscores the need for pre-positioned mitigations (application allowlisting, DLL pre-planting, behavioral monitoring) that do not depend on vendor patch cycles.

## Sources

- [The Hacker News - ShieldBreak Zero-Day PoC Claims Microsoft Defender Patch Bypass With SYSTEM Access](https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html) — primary news coverage with researcher quotes, Microsoft response, and independent analyst validation
- [BleepingComputer - New Microsoft Defender 'ShieldBreak' zero-day grants SYSTEM privileges](https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/) — news coverage with technical comparison to RoguePlanet and expert analysis
- [SecurityWeek - Nightmare Eclipse Drops Windows Zero-Day Exploit 'ShieldBreak'](https://www.securityweek.com/nightmare-eclipse-drops-windows-zero-day-exploit-shieldbreak/) — news coverage with Will Dormann's technical chain analysis
- [Security Affairs - ShieldBreak: New Windows Zero-Day Bypasses Microsoft's RoguePlanet Patch](https://securityaffairs.com/197063/hacking/shieldbreak-new-windows-zero-day-bypasses-microsofts-rogueplanet-patch.html) — news coverage with additional timeline context
- [Arctic Wolf - CVE-2026-50656/RoguePlanet, ShieldBreak](https://arcticwolf.com/resources/blog/cve-2026-50656-rogueplanet-shieldbreak/) — vendor advisory with detection guidance and version-specific impact assessment
- [ThreatLocker - NightmareEclipse releases new PoC, ShieldBreak](https://www.threatlocker.com/blog/nightmareeclipse-releases-new-poc-shieldbreak-exploits-same-weakness-as-rogueplanet) — detailed technical analysis with exploit chain walkthrough, file hashes, and named pipe details
- [Tanium - ShieldBreak: The Windows Defender 0-Day with No Patch](https://www.tanium.com/blog/shieldbreak-mitigation) — mitigation guidance with phoneinfo.dll placeholder deployment and detection signals
- [Cybersecurity News - Nightmare-Eclipse Drops ShieldBreak Windows Defender 0-day](https://cybersecuritynews.com/nightmare-eclipse-drops-shieldbreak-0-day/) — news coverage with cloud provider registration and CLFS manipulation details
- [GitHub - MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak) — PoC source code repository (C++, MIT license)
- [GitHub - GossiTheDog/ThreatHunting - ShieldBreak.kql](https://github.com/GossiTheDog/ThreatHunting/blob/master/AdvancedHuntingQueries/ShieldBreak.kql) — Kevin Beaumont's three detection queries for Microsoft Defender for Endpoint
- [The Register - Microsoft-vendetta hacker has a new zero day](https://www.theregister.com/cyber-crime/2026/08/12/microsoft-vendetta-hacker-has-a-new-zero-day-that-gives-system-privileges-on-fully-patched-windows/5286889) — news coverage with broader campaign context
- [Cyber Kendra - ShieldBreak PoC Bypasses Microsoft's RoguePlanet Defender Fix](https://www.cyberkendra.com/2026/08/shieldbreak-poc-bypasses-microsofts.html) — news coverage with Windows Server impact analysis
- [Project Nightcrawler Blog - ShieldBreak August 2026 Disclosure](https://blog.projectnightcrawler.dev/posts/2026-08-11-shieldbreak-august-2026-disclosure/) — researcher's original disclosure post
- [Actioner - Microsoft Defender RoguePlanet Zero-Day (2026-06-10)](2026-06-10-defender-rogueplanet-zero-day.md) — prior Actioner report on the original RoguePlanet/CVE-2026-50656 vulnerability

---
*Report generated by Actioner*
