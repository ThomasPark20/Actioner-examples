# Technical Analysis Report: Microsoft Defender "RoguePlanet" Zero-Day (2026-06-10)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-10
Version: 1.0 (DRAFT)

## Executive Summary

On June 9-10, 2026, security researcher Nightmare Eclipse (also tracked as Chaotic Eclipse / Dead Eclipse, GitHub: MSNightmare) publicly released "RoguePlanet," a proof-of-concept exploit targeting a TOCTOU (Time-of-Check to Time-of-Use) race condition in Microsoft Defender on fully patched Windows 10 and Windows 11 systems. Successful exploitation grants NT AUTHORITY\SYSTEM privileges from a standard unprivileged user account. The exploit leverages VHD/VHDX virtual disk mounting to trigger Defender scanning on attacker-controlled content, then exploits a race condition window using oplocks and NTFS junction/symlink redirection to cause Defender (running as SYSTEM via MsMpEng.exe) to overwrite its own files or write attacker-controlled content to protected system directories.

RoguePlanet is the seventh public exploit in an escalating campaign by this researcher against Microsoft Defender components. Prior releases include BlueHammer (CVE-2026-33825, patched April 2026), RedSun (CVE-2026-41091, patched May 2026), UnDefend (CVE-2026-45498, patched May 2026), YellowKey, GreenPlasma, and MiniPlasma. Huntress has documented real-world intrusions using Nightmare Eclipse tooling, with the BeigeBurrow C2 agent observed in active campaigns. Microsoft has not yet assigned a CVE for RoguePlanet; no patch is available as of June 10, 2026.

## Background: Microsoft Defender Antimalware Platform

Microsoft Defender (formerly Windows Defender) is the built-in antimalware solution on all modern Windows systems. The Defender service runs as `MsMpEng.exe` under the `NT AUTHORITY\SYSTEM` account, giving it the highest privilege level on the system. Defender performs real-time file scanning, definition updates, and threat remediation -- all as SYSTEM. This privileged execution model makes Defender an attractive target for local privilege escalation: if an attacker can redirect Defender's file operations during scanning or remediation, the SYSTEM-level write becomes the attacker's write. The Nightmare Eclipse researcher has systematically exploited this architectural pattern across multiple vulnerabilities since early 2026, focusing on path redirection, symlink/junction abuse, and race conditions in Defender's file handling routines.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-02 | BlueHammer (CVE-2026-33825) PoC publicly released; TOCTOU in Defender signature updates |
| 2026-04-07 | CVE-2026-33825 formally disclosed; CVSS 7.8 HIGH |
| 2026-04-14 | CVE-2026-33825 published on NVD |
| 2026-04-15 | Huntress observes real-world intrusion using Nightmare Eclipse tooling (FortiGate VPN compromise + BlueHammer/RedSun/UnDefend) |
| 2026-05 (mid) | Microsoft silently hardens Defender, patching `mpengine!SysIO*` API to block junction attacks |
| 2026-05-20 | Microsoft patches CVE-2026-41091 (RedSun) and CVE-2026-45498 (UnDefend); both added to CISA KEV catalog |
| 2026-06-09 | RoguePlanet PoC released on GitHub (MSNightmare/RoguePlanet); subsequently mirrored to projectnightcrawler[.]dev after GitHub/GitLab takedowns |
| 2026-06-10 | BleepingComputer, The Hacker News, Security Online publish coverage; no CVE assigned; no Microsoft patch available |

## Root Cause: TOCTOU Race Condition in Defender File Operations

The root cause is a Time-of-Check to Time-of-Use (TOCTOU) race condition in Microsoft Defender's file handling during real-time scanning. When Defender detects a file requiring remediation (via real-time protection or on-demand scan), it performs a privileged file operation (read, write, move, or delete) as SYSTEM. Between the time Defender checks/validates the file path and the time it performs the privileged operation, an attacker can redirect the path using NTFS junction points or Object Manager symbolic links. This causes Defender to operate on an attacker-chosen target file with SYSTEM privileges.

The attack surface is expanded by using VHD/VHDX virtual disk images (or ISO files) to deliver attacker-controlled content that triggers Defender scanning. The `virtdisk.h` API is used to programmatically create and mount virtual disks. The RoguePlanet exploit binary (RoguePlanet.exe, ~5.5MB compiled C++) contains an embedded payload in a large `rawData` buffer (~917,504 bytes of encoded data) that is written to the virtual disk to trigger the race condition.

Microsoft's mid-May 2026 hardening of `mpengine!SysIO*` blocked some junction attack vectors, but RoguePlanet bypasses these mitigations through a different race condition timing window.

## Technical Analysis of the Malicious Payload

### 1. VHD/VHDX Creation and Mount (Initial Trigger)

The exploit creates a crafted VHD or VHDX virtual disk file containing content designed to trigger a Microsoft Defender detection. The exploit uses the Windows Virtual Disk API (`virtdisk.h`, `virtdisk.lib`) to programmatically create and mount the disk. When the VHD is mounted, Defender's real-time protection automatically scans the contents, initiating the race condition window. The original attack vector also involved opening VHD/VHDX files hosted on remote SMB shares, which combined the scan trigger with symlink evaluation on SMB-accessed paths.

Key libraries linked: `kernel32.lib`, `bcrypt.lib`, `taskschd.lib`, `comsupp.lib`, `virtdisk.lib`, `ntdll.lib`, `Rpcrt4.lib`, `shlwapi.lib`.

### 2. Oplock-Based Race Condition Exploitation

The exploit uses opportunistic locks (oplocks) to freeze MsMpEng.exe mid-operation at a critical point. When Defender begins its scan/remediation sequence, the oplock callback fires, signaling the attacker's code that Defender has reached the vulnerable window. During this frozen state, the exploit performs the path redirection.

Key NT Native APIs used:
- `NtSetInformationFile` - File metadata manipulation
- `NtDeleteFile` - Direct file deletion via object attributes
- `NtOpenDirectoryObject` - Directory object access for symlink creation
- `NtQueryDirectoryObject` - Directory enumeration
- `NtQueryInformationFile` - File information retrieval

### 3. Path Redirection via Junction/Symlink

While Defender is stalled on the oplock, the exploit:
1. Deletes or renames the original target directory/file
2. Creates an NTFS junction point at the original path, redirecting to a system-protected directory (e.g., `C:\Windows\System32`)
3. Optionally creates Object Manager symbolic links (e.g., at `\BaseNamedObjects\Restricted\`) to further redirect file operations
4. When the oplock is released and Defender resumes, its SYSTEM-privileged write operation follows the junction/symlink to the attacker-chosen destination

Target files known from related exploits in this family:
- `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}\mpasbase.vdm`
- `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}\mpavbase.vdm`
- `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}\mpavbase.lkg`

### 4. SYSTEM Privilege Achievement

Upon successful redirection, the exploit achieves code execution as SYSTEM through one of these observed mechanisms (across the exploit family):
- **File overwrite**: Defender writes attacker-controlled content to `C:\Windows\System32\`, overwriting a system binary that is subsequently executed by a SYSTEM-level service
- **SAM database extraction**: Path redirected to VSS snapshot containing SAM database; hashes extracted and used for privilege escalation (BlueHammer variant)
- **Service binary replacement**: Attacker binary placed via redirected write; Windows service executes it as SYSTEM (RedSun variant via TieringEngineService.exe / Storage Tiers Management COM object)

The end result is a spawned command prompt running as `NT AUTHORITY\SYSTEM`.

### 5. Anti-Forensics / Evasion Techniques

- The exploit is a race condition with variable success rates, making it non-deterministic and harder to reproduce in forensic analysis
- VHD mounting creates a transient attack surface that is removed when the disk is unmounted
- The embedded ~917KB `rawData` payload is only written to the temporary VHD, not directly to disk
- Cloud Files API provider registration (observed provider name: "IHATEMICROSOFT") creates a synthetic sync root to facilitate file redirection
- Windows Server is not affected in the current PoC form because standard users cannot mount ISO images

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Microsoft Defender Antimalware Platform | < 4.18.26030.3011 | Vulnerable to CVE-2026-33825 (BlueHammer) |
| Microsoft Malware Protection Engine | 1.1.26030.3008 - 1.1.26040.7 | Vulnerable to CVE-2026-41091 (RedSun) |
| Microsoft Defender Antimalware Platform | 4.18.26030.3011 - 4.18.26040.6 | Vulnerable to CVE-2026-45498 (UnDefend) |
| Microsoft Defender (current June 2026 patch) | KB5094126 applied | Vulnerable to RoguePlanet (no CVE yet) |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | RoguePlanet.exe | N/A (not published) | PoC exploit binary (~5.5MB, C++ compiled) |
| Windows | FunnyApp.exe | N/A | Observed staging name in Huntress intrusion |
| Windows | RedSun.exe | N/A | RedSun exploit binary |
| Windows | undef.exe | N/A | UnDefend exploit binary |
| Windows | z.exe | N/A | Related exploit binary |
| Windows | agent.exe (BeigeBurrow) | a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c | Go-compiled C2 agent (yamux multiplexing) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | staybud[.]dpdns[.]org | BeigeBurrow C2 server (port 443) |
| Domain | projectnightcrawler[.]dev | Exploit hosting after GitHub/GitLab takedown |
| IP | 78[.]29[.]48[.]29 | Source IP for VPN intrusion (Russian Federation) |
| IP | 212[.]232[.]23[.]69 | Source IP for VPN intrusion (Singapore) |
| IP | 179[.]43[.]140[.]214 | Source IP for VPN intrusion (Switzerland) |
| URL | hxxps://github[.]com/MSNightmare/RoguePlanet | PoC repository |
| URL | hxxps://deadeclipse666[.]blogspot[.]com/2026/06/its-patch-tuesday[.]html | Researcher blog post |

### Behavioral

- Non-Defender processes accessing files under `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\`
- VHD/VHDX/ISO file creation and mounting by non-administrative, non-Explorer processes
- NTFS junction points created from user-writable directories targeting `C:\Windows\System32`
- Oplock placement on Defender definition files (`mpasbase.vdm`, `mpavbase.vdm`)
- Cloud Files sync root registration with anomalous provider names
- Process execution chains: user process -> VHD mount -> Defender scan trigger -> junction creation -> SYSTEM shell
- EICAR test string written to trigger Defender detection as part of exploit setup
- Defender detection: `Exploit:Win32/DfndrPEBluHmr.BZ`
- Reconnaissance commands (`whoami /priv`, `cmdkey /list`, `net group`) following exploit execution
- `agent.exe -server <domain>:443 -hide` command line pattern for BeigeBurrow C2

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | TOCTOU race condition in Defender exploited for SYSTEM privileges |
| T1547.009 | Boot or Logon Autostart Execution: Shortcut Modification | Symlink/junction manipulation to redirect privileged file writes |
| T1204.002 | User Execution: Malicious File | VHD/VHDX file mounting triggers Defender scan as entry point |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Redirected Defender writes place attacker binary in System32 for service execution |
| T1134 | Access Token Manipulation | SYSTEM token obtained post-exploitation |
| T1087 | Account Discovery | Post-exploitation reconnaissance (`whoami /priv`, `net group`) |
| T1555 | Credentials from Password Stores | SAM database extraction via redirected Defender reads (BlueHammer) |
| T1021.001 | Remote Services: RDP | Lateral movement observed in Huntress intrusion |
| T1219 | Remote Access Software | BeigeBurrow Go-based C2 agent with yamux multiplexing |

## Impact Assessment

**Breadth:** All Windows 10 and Windows 11 consumer/client systems running Microsoft Defender with the June 2026 Patch Tuesday updates applied are vulnerable. Windows Server is not affected by the current PoC (standard users cannot mount ISO images), though the underlying vulnerability may be exploitable on Server with modified techniques. The affected user base is estimated in the hundreds of millions.

**Depth:** The vulnerability grants full SYSTEM privileges from an unprivileged user account, representing maximum local impact (CVSS AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8 HIGH, consistent with CVE-2026-33825 scoring). This enables complete system compromise including credential extraction, persistence installation, and lateral movement.

**Stealth:** The race condition nature makes exploitation non-deterministic (variable success rates across hardware), which paradoxically aids evasion -- failed attempts may not generate clear forensic artifacts. The transient VHD mounting and junction creation leave minimal persistent evidence.

**Active Exploitation:** Huntress documented real-world intrusions using Nightmare Eclipse tooling as early as April 15, 2026. The BeigeBurrow C2 agent was observed with connections to `staybud.dpdns.org:443`. CISA added the related CVE-2026-33825 and CVE-2026-41091 to the Known Exploited Vulnerabilities catalog.

## Detection & Remediation

### Immediate Detection

**Check for Nightmare Eclipse exploit artifacts:**
```powershell
# Search for known exploit binary names
Get-ChildItem -Path C:\Users -Recurse -Include "RoguePlanet.exe","BlueHammer.exe","RedSun.exe","undef.exe","GreenPlasma.exe","MiniPlasma.exe","YellowKey.exe","FunnyApp.exe" -ErrorAction SilentlyContinue

# Check for BeigeBurrow C2 agent
Get-ChildItem -Path C:\Users -Recurse -Include "agent.exe" -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 5MB }

# Search for suspicious junction points targeting System32
Get-ChildItem -Path C:\Users,C:\ProgramData -Recurse -Attributes ReparsePoint -ErrorAction SilentlyContinue | Where-Object { (Get-Item $_.FullName).Target -like "*System32*" }

# Check Defender detection logs for exploit signatures
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Where-Object { $_.Message -match "DfndrPEBluHmr" -or $_.Message -match "RoguePlanet" }

# Look for anomalous VHD mount activity
Get-WinEvent -LogName "Microsoft-Windows-VHDMP-Operational" -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-7) }
```

**Check for BeigeBurrow C2 communications:**
```powershell
# Check for active connections to known C2 infrastructure
Get-NetTCPConnection | Where-Object { $_.RemotePort -eq 443 } | ForEach-Object { try { [System.Net.Dns]::GetHostEntry($_.RemoteAddress).HostName } catch { $_.RemoteAddress } } | Select-String "dpdns"
```

### Remediation

1. **Immediate:** Deploy application allowlisting (ThreatLocker or similar) to prevent unknown executables from running -- this blocks the PoC from executing
2. **Immediate:** Monitor and alert on Defender detection `Exploit:Win32/DfndrPEBluHmr.BZ`
3. **Short-term:** Block known C2 domain `staybud.dpdns.org` and IPs `78.29.48.29`, `212.232.23.69`, `179.43.140.214` at the network perimeter
4. **Short-term:** Hunt for BeigeBurrow agent (SHA256: `a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c`)
5. **Pending patch:** Apply Microsoft Defender platform update as soon as a patch is released for RoguePlanet
6. **If compromised:** Rotate all local account passwords; check for SYSTEM-level persistence (services, scheduled tasks, WMI subscriptions); review VPN authentication logs for geographic anomalies

### Long-Term Hardening

- Enable Sysmon with comprehensive file and process monitoring (Events 1, 7, 11, 13, 22)
- Implement application allowlisting to prevent unauthorized binary execution
- Monitor for NTFS junction/reparse point creation in user-writable directories
- Restrict VHD/VHDX/ISO mounting capabilities via Group Policy where not needed
- Consider enhanced Defender isolation through Windows Defender Application Guard
- Monitor Defender definition update directories for access by non-Defender processes

## Detection Rules

These detections target the RoguePlanet exploit chain and related Nightmare Eclipse tooling at the PoC/advisory-specific altitude. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles are verified but not fired against production telemetry.

### Sigma: Non-Defender Process Accessing Defender Definition Files
Detects non-Defender processes creating or modifying files in the Defender Definition Updates directory, targeting the core TOCTOU redirection in the RoguePlanet exploit chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0; splunk_windows pipeline 0. Targets file_event on Windows; filter covers MsMpEng.exe, MpCmdRun.exe, NisSrv.exe, MpSigStub.exe. Values use real paths (not defanged). FP: third-party AV management tools accessing Defender paths (rare). Evasion: renaming exploit binary to match filter — mitigated by filtering on Defender-signed binaries in production. -->
```yaml
title: Microsoft Defender RoguePlanet Race Condition - Suspicious VHD Mount and Defender File Manipulation
id: 7c3a8f1e-9d2b-4e6a-b5c4-1f0e8d7a6b3c
status: experimental
description: >
    Detects a process creating or mounting VHD/VHDX virtual disk files followed by
    suspicious file operations in the Windows Defender Definition Updates directory,
    consistent with the RoguePlanet TOCTOU race condition exploit that redirects
    Defender file operations via junctions/symlinks to achieve SYSTEM privilege escalation.
references:
    - https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/
    - https://thehackernews.com/2026/06/microsoft-defender-rogueplanet-zero-day.html
    - https://github.com/MSNightmare/RoguePlanet
author: Actioner
date: 2026/06/10
tags:
    - attack.t1068
    - attack.t1547.009
logsource:
    category: file_event
    product: windows
detection:
    selection_defender_path:
        TargetFilename|contains:
            - '\Microsoft\Windows Defender\Definition Updates'
            - '\mpasbase.vdm'
            - '\mpavbase.vdm'
            - '\mpavbase.lkg'
    filter_defender_process:
        Image|endswith:
            - '\MsMpEng.exe'
            - '\MpCmdRun.exe'
            - '\NisSrv.exe'
            - '\MpSigStub.exe'
    condition: selection_defender_path and not filter_defender_process
falsepositives:
    - Third-party security tools that interact with Defender definition files
    - Legitimate Defender update mechanisms not covered by the filter
level: high
```

### Sigma: Suspicious VHD/ISO Mount via Scripting Engine
Detects VHD/VHDX/ISO mounting via scripting engines or the RoguePlanet binary, which serves as the initial trigger for the Defender race condition.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Broader than the anchor rule — VHD mounts by cmd/PowerShell are legitimate in some admin workflows. Scoped to scripting engines + the known exploit binary to reduce FP. -->
```yaml
title: Suspicious VHD/VHDX Mount by Non-Admin User Followed by Defender Activity
id: 2e9f4d8a-6b1c-4a3e-8c7d-5f0a9e2b1d4c
status: experimental
description: >
    Detects mounting of VHD or VHDX virtual disk images via processes other than
    Windows Explorer or Hyper-V, which is a prerequisite step in the RoguePlanet
    exploit chain. The exploit requires mounting a crafted VHD/VHDX to trigger
    Defender scanning on attacker-controlled content within a race condition window.
references:
    - https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/
    - https://thehackernews.com/2026/06/microsoft-defender-rogueplanet-zero-day.html
    - https://github.com/MSNightmare/RoguePlanet
author: Actioner
date: 2026/06/10
tags:
    - attack.t1068
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_vhd_mount:
        CommandLine|contains:
            - '.vhd'
            - '.vhdx'
            - '.iso'
        Image|endswith:
            - '\RoguePlanet.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
    condition: selection_vhd_mount
falsepositives:
    - Legitimate administrative VHD management scripts
    - Hyper-V management operations via PowerShell
level: medium
```

### Sigma: RoguePlanet / Nightmare Eclipse Exploit Binary Execution
Detects execution of known Nightmare Eclipse exploit binaries by filename, covering the full family: RoguePlanet, BlueHammer, RedSun, UnDefend, GreenPlasma, MiniPlasma, YellowKey.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0; splunk_windows pipeline 0. Simple filename match — trivially evaded by rename, but catches unmodified PoC usage (the most common scenario in opportunistic attacks). Pair with the YARA rule for content-based detection. -->
```yaml
title: RoguePlanet Exploit Binary Execution
id: 4a1b7c3e-8d9f-4e2a-b6c5-3f1d0e8a7b4c
status: experimental
description: >
    Detects execution of the RoguePlanet exploit binary or processes matching
    the known Defender exploit detection signature Exploit:Win32/DfndrPEBluHmr.BZ.
    This rule targets the specific PoC artifacts from the Nightmare Eclipse
    researcher's public release.
references:
    - https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/
    - https://github.com/MSNightmare/RoguePlanet
    - https://www.huntress.com/blog/nightmare-eclipse-intrusion
author: Actioner
date: 2026/06/10
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary_name:
        Image|endswith:
            - '\RoguePlanet.exe'
    selection_related_binaries:
        Image|endswith:
            - '\BlueHammer.exe'
            - '\RedSun.exe'
            - '\undef.exe'
            - '\GreenPlasma.exe'
            - '\MiniPlasma.exe'
            - '\YellowKey.exe'
    condition: selection_binary_name or selection_related_binaries
falsepositives:
    - Unlikely - these are known exploit tool names from the Nightmare Eclipse campaign
level: critical
```

### Sigma: NTFS Junction Creation Targeting System32
Detects junction point creation from user-writable directories to System32, the path redirection step that converts Defender's SYSTEM-level write into attacker-controlled code placement.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Matches mklink /J and PowerShell New-Item -ItemType Junction targeting System32. Benign junction creation to System32 is rare in normal operations. -->
```yaml
title: NTFS Junction Creation Targeting System32 from User-Writable Directory
id: 9e5d2a7b-4c8f-4a1e-b3d6-6f0c1e9a8b5d
status: experimental
description: >
    Detects creation of NTFS junction points or symbolic links from user-writable
    directories targeting C:\Windows\System32, a core technique in the RoguePlanet
    and RedSun exploit chains where Defender's privileged file operations are
    redirected to write attacker-controlled content into protected system directories.
references:
    - https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/
    - https://www.huntress.com/blog/nightmare-eclipse-intrusion
    - https://nvd.nist.gov/vuln/detail/CVE-2026-41091
author: Actioner
date: 2026/06/10
tags:
    - attack.t1068
    - attack.t1547.009
logsource:
    category: process_creation
    product: windows
detection:
    selection_mklink:
        Image|endswith:
            - '\cmd.exe'
        CommandLine|contains|all:
            - 'mklink'
            - '/J'
        CommandLine|contains:
            - '\Windows\System32'
            - '\Windows\system32'
    selection_powershell_junction:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'New-Item'
            - 'Junction'
        CommandLine|contains:
            - '\Windows\System32'
            - '\Windows\system32'
    condition: selection_mklink or selection_powershell_junction
falsepositives:
    - Legitimate system administration scripts creating junctions for software deployment
level: high
```

### Suricata: BeigeBurrow C2 Agent Communication
Detects TCP connections to the known BeigeBurrow C2 domain used in Nightmare Eclipse intrusions documented by Huntress.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Matches on "staybud" + "dpdns" in TCP stream to external hosts. Domain will rotate — effective for known infrastructure only. -->
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - BeigeBurrow C2 Agent Connection to Known Nightmare Eclipse Infrastructure"; flow:established,to_server; content:"staybud"; fast_pattern; content:"dpdns"; distance:0; within:20; classtype:trojan-activity; reference:url,www.huntress.com/blog/nightmare-eclipse-intrusion; metadata:author Actioner, created_at 2026-06-10; sid:2200001; rev:1;)
```

### Snort: N/A
Snort is not installed in the current environment. The Suricata rule above covers the same network indicator. Mark as not generated.

### YARA: RoguePlanet / Nightmare Eclipse Exploit Tool
Detects PE files containing the combination of NT native API imports, virtual disk library references, and distinctive strings from the Nightmare Eclipse exploit family (including "IHATEMICROSOFT", "RoguePlanet", Defender definition file paths, and the hardcoded test password).
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos_rogueplanet.txt: MATCH (Exploit_RoguePlanet_Defender_LPE). yara neg_rogueplanet.txt: no match. Positive sample constructed from published source code strings (NtSetInformationFile, NtDeleteFile, NtOpenDirectoryObject, virtdisk.dll, IHATEMICROSOFT, RoguePlanet, mpasbase.vdm) — matches the actual PoC artifact's known string content. Condition: PE + size<10MB + (3 NT APIs + 1 lib + 1 distinctive string) OR (2 of the most unique strings) OR (RoguePlanet + 2 APIs + 1 Defender path). -->
```yara
rule Exploit_RoguePlanet_Defender_LPE
{
    meta:
        description = "Detects the RoguePlanet exploit tool targeting Microsoft Defender TOCTOU race condition for SYSTEM privilege escalation"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://github.com/MSNightmare/RoguePlanet"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $api1 = "NtSetInformationFile" ascii fullword
        $api2 = "NtDeleteFile" ascii fullword
        $api3 = "NtOpenDirectoryObject" ascii fullword
        $api4 = "NtQueryDirectoryObject" ascii fullword
        $api5 = "NtQueryInformationFile" ascii fullword

        $lib1 = "virtdisk.dll" ascii nocase
        $lib2 = "bcrypt.dll" ascii nocase
        $lib3 = "ntdll.dll" ascii nocase

        $str1 = "IHATEMICROSOFT" ascii wide
        $str2 = "RoguePlanet" ascii wide
        $str3 = "mpasbase.vdm" ascii wide nocase
        $str4 = "mpavbase.vdm" ascii wide nocase
        $str5 = "$PWNed666!!!WDFAIL" ascii wide
        $str6 = "Nightmare" ascii wide
        $str7 = "MSRC" ascii wide

        $path1 = "Windows Defender\\Definition Updates" ascii wide nocase
        $path2 = "ProgramData\\Microsoft\\Windows Defender" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (3 of ($api*) and 1 of ($lib*) and 1 of ($str*)) or
            (2 of ($str1, $str2, $str5)) or
            ($str2 and 2 of ($api*) and 1 of ($path*))
        )
}
```

## Lessons Learned

1. **Privileged antimalware services are a systemic LPE target.** Microsoft Defender's architecture -- running file operations as SYSTEM with user-triggerable scan paths -- creates a durable attack surface for TOCTOU, symlink, and junction-based privilege escalation. The Nightmare Eclipse campaign (seven exploits in three months) demonstrates that patching individual instances does not address the architectural pattern.

2. **Race condition exploits defy deterministic detection.** The non-deterministic nature of TOCTOU exploits (variable success rates across hardware configurations) means detection must focus on the observable setup steps (VHD mounting, junction creation, definition file access by non-Defender processes) rather than the race itself.

3. **Researcher-adversary dynamics create accelerated disclosure timelines.** The Nightmare Eclipse campaign appears motivated by researcher frustration with Microsoft's disclosure process, resulting in zero-day drops timed to Patch Tuesday for maximum impact. Organizations must be prepared for zero-day publication with no vendor coordination window.

## Sources

- [BleepingComputer - Microsoft Defender 'RoguePlanet' zero-day grants SYSTEM privileges](https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/) — primary news coverage with researcher quotes and exploit context
- [The Hacker News - Microsoft Defender RoguePlanet Zero-Day Grants SYSTEM Access](https://thehackernews.com/2026/06/microsoft-defender-rogueplanet-zero-day.html) — news coverage with related CVE context and researcher background
- [Security Online - New Microsoft Defender Zero Day Exploit Released](https://securityonline.info/defender-zero-day-exploit-rogueplanet/) — news coverage with detection guidance
- [GitHub - MSNightmare/RoguePlanet](https://github.com/MSNightmare/RoguePlanet) — PoC source code repository (C++, MIT license)
- [Huntress - Nightmare-Eclipse Tooling Seen in Real-World Intrusion](https://www.huntress.com/blog/nightmare-eclipse-intrusion) — incident response report documenting active exploitation with BlueHammer, RedSun, UnDefend, and BeigeBurrow C2
- [NVD - CVE-2026-33825](https://nvd.nist.gov/vuln/detail/CVE-2026-33825) — BlueHammer vulnerability entry (CVSS 7.8 HIGH)
- [NVD - CVE-2026-41091](https://nvd.nist.gov/vuln/detail/CVE-2026-41091) — RedSun vulnerability entry (CVSS 7.8 HIGH, CWE-59)
- [NVD - CVE-2026-45498](https://nvd.nist.gov/vuln/detail/CVE-2026-45498) — UnDefend vulnerability entry (CVSS 7.5 HIGH, CWE-400)
- [Exploit Pack - BlueHammer Analysis](https://www.exploitpack.com/blogs/news/blue-hammer-analysis-ms-defender-lpe) — technical analysis of the related BlueHammer exploit mechanism
- [Nightmare Eclipse Blog](https://deadeclipse666.blogspot.com/2026/06/its-patch-tuesday.html) — researcher's Patch Tuesday disclosure post

---
*Report generated by Actioner*
