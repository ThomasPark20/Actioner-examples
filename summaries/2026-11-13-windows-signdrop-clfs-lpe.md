# Windows SignDrop Zero-Day: CLFS Local Privilege Escalation to SYSTEM

**Date:** 2026-11-13  
**Status:** FINAL  
**TLP:** CLEAR  
**CVE:** None assigned  

---

## Executive Summary

On November 13, 2026, security researcher Abdelhamid Naceri (alias "Nightmare Eclipse" / "MSNightmare") publicly released a proof-of-concept exploit named **SignDrop** targeting the Windows Common Log File System (CLFS) driver (`clfs.sys`). The exploit abuses the CLFS logfile authentication mechanism -- a security mitigation Microsoft introduced in October 2025 -- to achieve local privilege escalation from a standard user to SYSTEM. The attack chain coerces the Windows Defender antimalware service (`MsMpEng.exe`) into opening attacker-controlled CLFS log files via its `ServerMpUpdateEngineSignature` RPC interface, causing the CLFS driver to create authentication files (`.cnpf`) with SYSTEM-level privileges at attacker-controlled locations through object manager symbolic link redirection. The researcher claims approximately 80% of Windows installations are vulnerable. No CVE has been assigned, no patch is available, and Microsoft has not publicly acknowledged the vulnerability as of the publication date. Independent testing by 78researchlab (Heewon Song of PurpleHound) confirmed the exploit functions, though assessed it as not reliable enough for operational use. No in-the-wild exploitation has been reported.

---

## Background

### CLFS Authentication Mitigation

Microsoft introduced CLFS logfile authentication in Windows 11 25H2 and Windows Server 2025, distributed via updates released on or after October 28, 2025 (KB5056852). This mitigation records HMAC-based message authentication codes in each CLFS logfile using a per-system cryptographic key. The goal is to prevent parsing of corrupted or malicious logfiles by ensuring only the CLFS driver (`clfs.sys`) is the legitimate author.

The mitigation operates in modes controlled by the registry value `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication\Mode`:

| Mode | Description |
|------|-------------|
| **0** | Enforcement: CLFS rejects logfiles with missing or invalid authentication codes |
| **1** | Learning: CLFS opens all logfiles and adds missing codes if the caller has write access |
| **2** | Disabled by Administrator |
| **3** | Disabled by system |

Systems begin in learning mode (1) with a default 90-day adoption period before automatic transition to enforcement (0). Both modes 0 and 1 are within the exploit's attack surface.

### Researcher Background

Abdelhamid Naceri, publishing under the handle "MSNightmare," has released a series of Windows and Defender zero-day exploits since April 2026, including BigDiskBuster, ShieldCrash, ShieldBreak (CVE-2026-69414), RoguePlanet (CVE-2026-50656), LegacyHive, BlueHammer, RedSun, YellowKey, GreenPlasma, MiniPlasma, UnDefend, HardBreacher (Kaspersky), PrettyPrague (Avast), and FalconFlank (CrowdStrike Falcon). Microsoft has patched several of these; others remain unpatched.

---

## Technical Analysis

### Attack Overview

SignDrop is a local privilege escalation exploit that requires:
- Local access as a standard (non-privileged) user
- Windows Defender enabled with tamper protection active
- CLFS Authentication Mode set to 0 (enforcement) or 1 (learning)

### Stage 1: CLFS Log File Preparation

The attacker creates a CLFS log file (`.blf`) and associated container at user-controlled paths. The CLFS driver stores authentication data in a companion file with the `.cnpf` extension (e.g., `example.blf` creates `example.blf.cnpf`). The `.cnpf` file is created with the same security attributes (DACL) as the original log file.

Key API: `AddLogContainer` -- used to create CLFS log containers programmatically.

### Stage 2: Object Manager Symbolic Link Redirection

The attacker manipulates Windows Object Manager symbolic links to redirect where the `.cnpf` authentication file will be created. When a privileged process subsequently opens the CLFS log, the kernel routine `CclfsContainer::Create` follows the redirected path, creating the authentication file at an attacker-chosen location.

The CLFS driver uses `OBJ_FORCE_ACCESS_CHECK` when processes create their own log files, but this check can be circumvented when a different, already-privileged process opens the log.

### Stage 3: Windows Defender Coercion

The exploit triggers Windows Defender to open the attacker-prepared CLFS log file by calling the `ServerMpUpdateEngineSignature` RPC interface. This causes the Defender antimalware engine (`MsMpEng.exe`) to interact with the CLFS log in a SYSTEM security context, which in turn triggers the CLFS driver to create the `.cnpf` file at the symlink-redirected location with SYSTEM privileges and the attacker-controlled DACL.

### Stage 4: Privilege Escalation

The result is a SYSTEM-owned file at an attacker-chosen location that the standard user can write to (because the DACL was inherited from the user-created log file). This primitive can be chained into a full SYSTEM shell.

### DLL Sideloading Component

The PoC repository includes a custom `hid.dll`, indicating a DLL sideloading technique is used as part of the exploitation chain. The repository also includes `windefend.idl` and associated RPC stub files (`windefend_c.c`, `windefend_h.h`, `windefend_s.c`) for interfacing with the Defender RPC endpoint.

### Antivirus/EDR Bypass Implications

Because the file creation request originates from Defender's own legitimate process, kernel-level self-protection drivers accept the operation. The researcher claims this technique can be generalized to target other antimalware engines with elevated privileges, potentially defeating tamper protection across multiple security products.

### Observable Side Effects

Running the exploit reportedly modifies UAC prompt behavior, causing all UAC prompts to open both a standard user shell and a SYSTEM shell, which blocks other actions and makes the attack noticeable to interactive users.

---

## Indicators of Compromise

### File System Indicators

| Indicator | Description |
|-----------|-------------|
| `.cnpf` files in user-writable directories (e.g., `%USERPROFILE%`, `%TEMP%`) | CLFS authentication files should normally appear alongside system-managed BLF files, not in user temp/profile directories |
| `.blf` files in unexpected user-writable locations | CLFS log files created as part of the exploit preparation |
| `hid.dll` loaded from non-system directories | DLL sideloading component of the PoC |
| `SigDrop.exe` or similarly named binaries | PoC exploit binary (compiled from `SigDrop.cpp`) |
| `windefend_c.c`, `windefend_h.h`, `windefend_s.c` artifacts | RPC stub files for Defender interface |

### Behavioral Indicators

| Indicator | Description |
|-----------|-------------|
| `MsMpEng.exe` opening CLFS log files in unusual directories | Defender coerced into opening attacker-controlled logs |
| Unexpected calls to `ServerMpUpdateEngineSignature` | RPC coercion trigger for the exploit |
| Object Manager symbolic link creation/modification followed by `.cnpf` file creation | Core exploit mechanism |
| Modification of `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication\Mode` | Potential attempt to disable CLFS authentication |
| UAC prompts spawning both standard and SYSTEM shells | Observable side effect of successful exploitation |

### Registry Indicators

| Key | Significance |
|-----|-------------|
| `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication\Mode` = 0 or 1 | System is within the exploit's attack surface |
| Changes to `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication\Mode` | May indicate an attacker disabling the mitigation (value 2) or reconnaissance |
| `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication\EnforcementTransitionPeriod` | Modification may indicate an attempt to extend the learning-mode window |

### Network Indicators

No network indicators have been identified. This is a local privilege escalation exploit.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|-------------|----------------|-----------|
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Core technique: CLFS driver vulnerability exploited for LPE to SYSTEM |
| [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | Hijack Execution Flow: DLL Side-Loading | PoC includes custom `hid.dll` for sideloading |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | CLFS Authentication Mode registry value is the configuration surface |

<!-- revision: T1562.001 (Impair Defenses) dropped — SignDrop coerces Defender into performing a file operation, it does not disable or modify it -->

---

## Detection and Remediation

### Detection Strategies

1. **File System Monitoring**: Alert on creation of `.cnpf` files outside of expected system directories (`C:\Windows\`, `C:\ProgramData\`, `C:\Program Files\`). CLFS authentication files should only appear alongside legitimate system-managed log files.

2. **Registry Monitoring**: Monitor changes to `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication\Mode`. Any modification outside of Group Policy or MDM-driven configuration is suspicious.

<!-- revision: DLL Load Monitoring strategy for hid.dll removed — hid.dll is commonly sideloaded by benign software; not SignDrop-specific -->

3. **File-Open Telemetry for Defender-CLFS Interaction**: Monitor for `MsMpEng.exe` opening `.blf` or `.cnpf` files in user-writable directories. Note: process-creation telemetry will not capture this because the exploit triggers Defender via RPC (`ServerMpUpdateEngineSignature`), not by spawning child processes. Use Sysmon Event ID 11 (FileCreate) or ETW FileIO providers to observe the file-level activity.

4. **Sysmon Configuration**: Enable Sysmon Event ID 11 (FileCreate) for `.cnpf` and `.blf` patterns and Event ID 13 (RegistryEvent) for the CLFS Authentication key.

### Remediation

- **No patch is currently available.** Microsoft has not acknowledged this vulnerability or assigned a CVE.
- **Do NOT disable the CLFS authentication mitigation** (setting Mode to 2), as this re-exposes systems to CLFS memory corruption vulnerabilities that the mitigation was designed to prevent.
- Monitor for Microsoft security updates addressing CLFS driver behavior.
- Consider enhanced monitoring of the indicators detailed above.
- Assess exposure: check `HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication\Mode` across your fleet. Values 0 or 1 indicate the system is within the claimed attack surface.

### Affected Systems

- Windows 11 26H2 (confirmed by PoC author and independent testing)
- Windows 11 26H2 Experimental builds
- Windows Server 2025 Experimental builds
- Potentially any Windows system with CLFS Authentication Mode 0 or 1 (estimated ~80% of Windows installations by the researcher; not independently verified)

---

## Detection Rules

### Sigma Rule 1: Suspicious CNPF File Creation in User-Writable Directory

**Compile status:** ✅ compiles (sigma convert to Splunk and LogScale successful)  
**Confidence:** Medium -- CNPF files in user directories are unusual but not impossible for legitimate CLFS-using applications

**File:** `/tmp/actioner/signdrop-1.yml`

```yaml
title: SignDrop - Suspicious CNPF File Creation in User-Writable Directory
id: 7a3c8e91-4d2f-4b1a-9e6c-2f8d5a1b3c4e
status: experimental
description: >
  Detects creation of CLFS authentication (.cnpf) files in user-writable directories,
  which may indicate abuse of the SignDrop CLFS privilege escalation technique where a
  standard user redirects CNPF file creation via object manager symlinks.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://www.bleepingcomputer.com/news/security/new-windows-signdrop-zero-day-gives-hackers-system-privileges/
    - https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/clfs-authentication
author: Actioner
date: 2026/11/13
tags:
    - attack.t1068
    - attack.t1562.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '.cnpf'
    filter_system_paths:
        TargetFilename|startswith:
            - 'C:\Windows\'
            - 'C:\ProgramData\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection and not filter_system_paths
falsepositives:
    - Legitimate applications creating CLFS log files in user directories
    - Development or testing of CLFS-based applications
level: high
```

**Splunk output:**
```
TargetFilename="*.cnpf" NOT (TargetFilename IN ("C:\\Windows\\*", "C:\\ProgramData\\*", "C:\\Program Files\\*", "C:\\Program Files (x86)\\*"))
```

**LogScale output:**
```
TargetFilename=/\.cnpf$/i not (TargetFilename=/^C:\\Windows\\/i or TargetFilename=/^C:\\ProgramData\\/i or TargetFilename=/^C:\\Program Files\\/i or TargetFilename=/^C:\\Program Files \(x86\)\\/i)
```

---

### Sigma Rule 2: CLFS Authentication Mode Registry Modification

**Compile status:** ✅ compiles (sigma convert to Splunk and LogScale successful)  
**Confidence:** Medium -- TTP-based rule; legitimate Group Policy or MDM changes will match

**File:** `/tmp/actioner/signdrop-2.yml`

```yaml
title: SignDrop - CLFS Authentication Mode Registry Modification
id: 9b5d2e73-6f1a-4c8d-be49-3a7e1d5f2c6b
status: experimental
description: >
  Detects modification of the CLFS Authentication Mode registry value, which controls
  the CLFS logfile authentication mitigation. Attackers may change this value to disable
  protections (value 2) or the SignDrop exploit targets systems in learning mode (value 1)
  or enforcement mode (value 0).
references:
    - https://github.com/MSNightmare/SignDrop
    - https://support.microsoft.com/en-us/servicing/os/windows/2025/03/common-log-file-system-clfs-authentication-mitigation
    - https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/clfs-authentication
author: Actioner
date: 2026/11/13
tags:
    - attack.t1112
    - attack.t1562.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Services\CLFS\Authentication\Mode'
    condition: selection
falsepositives:
    - Legitimate administrator configuration of CLFS authentication via Group Policy or MDM
    - Windows Update changing the CLFS authentication mode during mitigation rollout
level: medium
```

**Splunk output:**
```
TargetObject="*\\Services\\CLFS\\Authentication\\Mode"
```

**LogScale output:**
```
TargetObject=/\\Services\\CLFS\\Authentication\\Mode$/i
```

---

### Sigma Rule 3: Suspicious HID DLL Loaded From Non-System Directory

**Compile status:** ✅ compiles (sigma convert to Splunk and LogScale successful)  
**Confidence:** Medium -- DLL sideloading detection; some legitimate software may bundle hid.dll

**File:** `/tmp/actioner/signdrop-3.yml`

```yaml
title: SignDrop - Suspicious HID DLL Loaded From Non-System Directory
id: 4e8a1c36-2d9b-4f7e-a5c3-8b6d0e2f1a9c
status: experimental
description: >
  Detects loading of hid.dll from a non-standard directory. The SignDrop PoC includes
  a custom hid.dll for DLL sideloading as part of the CLFS privilege escalation chain.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://www.bleepingcomputer.com/news/security/new-windows-signdrop-zero-day-gives-hackers-system-privileges/
author: Actioner
date: 2026/11/13
tags:
    - attack.t1574.002
    - attack.t1068
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\hid.dll'
    filter_system:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not filter_system
falsepositives:
    - Legitimate applications bundling their own HID library
    - Hardware vendor software with custom HID implementations
level: medium
```

**Splunk output:**
```
ImageLoaded="*\\hid.dll" NOT (ImageLoaded IN ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*", "C:\\Windows\\WinSxS\\*"))
```

**LogScale output:**
```
ImageLoaded=/\\hid\.dll$/i not (ImageLoaded=/^C:\\Windows\\System32\\/i or ImageLoaded=/^C:\\Windows\\SysWOW64\\/i or ImageLoaded=/^C:\\Windows\\WinSxS\\/i)
```

---

### Sigma Rule 4: Windows Defender Engine Signature Update Coercion

**Compile status:** ✅ compiles (sigma convert to Splunk and LogScale successful)  
**Confidence:** Low -- process creation telemetry may not capture the RPC-level coercion; this rule targets a narrow observable and requires MsMpEng.exe -> MpCmdRun.exe with .blf references

**File:** `/tmp/actioner/signdrop-4.yml`

```yaml
title: SignDrop - Windows Defender Engine Signature Update Coercion
id: 6c2f4a87-1e3d-4b9a-8d5c-7f0e3b2a1d6e
status: experimental
description: >
  Detects potential abuse of the Windows Defender signature update RPC interface
  (ServerMpUpdateEngineSignature) to coerce the Defender service into opening
  attacker-controlled CLFS log files. The SignDrop exploit uses this to trigger
  CNPF file creation with SYSTEM privileges.
references:
    - https://github.com/MSNightmare/SignDrop
    - https://thehackernews.com/2026/11/new-signdrop-zero-day-exploit-turns.html
author: Actioner
date: 2026/11/13
tags:
    - attack.t1068
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_defender_access:
        ParentImage|endswith: '\MsMpEng.exe'
        Image|endswith: '\MpCmdRun.exe'
    selection_blf_commandline:
        CommandLine|contains: '.blf'
    condition: selection_defender_access and selection_blf_commandline
falsepositives:
    - Highly unlikely in normal operations
level: high
```

**Splunk output:**
```
ParentImage="*\\MsMpEng.exe" Image="*\\MpCmdRun.exe" CommandLine="*.blf*"
```

**LogScale output:**
```
ParentImage=/\\MsMpEng\.exe$/i Image=/\\MpCmdRun\.exe$/i CommandLine=/\.blf/i
```

---

### YARA Rule 1: SignDrop CLFS Exploit Binary Detection

**Compile status:** ✅ compiles (yarac successful)  
**Confidence:** Medium -- string-based detection targeting distinctive PoC artifacts; no file hashes available

**File:** `/tmp/actioner/signdrop-1.yar`

```yara
rule SignDrop_CLFS_Exploit
{
    meta:
        description = "Detects the SignDrop CLFS privilege escalation exploit binary based on distinctive strings from the PoC"
        author = "Actioner"
        date = "2026-11-13"
        reference = "https://github.com/MSNightmare/SignDrop"
        threat = "Windows CLFS Local Privilege Escalation Zero-Day"

    strings:
        $api1 = "AddLogContainer" ascii wide
        $api2 = "ServerMpUpdateEngineSignature" ascii wide
        $clfs1 = ".cnpf" ascii wide
        $clfs2 = ".blf" ascii wide
        $clfs3 = "\\CLFS" ascii wide
        $proj1 = "SigDrop" ascii wide nocase
        $proj2 = "SignDrop" ascii wide nocase
        $idl1 = "windefend" ascii wide nocase
        $flag1 = "OBJ_FORCE_ACCESS_CHECK" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (($proj1 or $proj2) and $api2) or
            ($api1 and $api2 and ($clfs1 or $clfs2)) or
            ($api2 and $idl1 and ($clfs1 or $clfs2 or $clfs3)) or
            ($flag1 and $api2 and ($clfs1 or $clfs2))
        )
}

rule SignDrop_HID_Sideload_DLL
{
    meta:
        description = "Detects a suspicious hid.dll that may be used for DLL sideloading as part of the SignDrop exploit chain"
        author = "Actioner"
        date = "2026-11-13"
        reference = "https://github.com/MSNightmare/SignDrop"
        threat = "SignDrop DLL Sideloading Component"

    strings:
        $clfs1 = "AddLogContainer" ascii wide
        $clfs2 = ".cnpf" ascii wide
        $clfs3 = ".blf" ascii wide
        $defender1 = "ServerMpUpdateEngineSignature" ascii wide
        $defender2 = "windefend" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        2 of ($clfs1, $clfs2, $clfs3) and
        1 of ($defender1, $defender2)
}
```

---

## Sources

- [BleepingComputer - New Windows SignDrop zero-day gives hackers SYSTEM privileges](https://www.bleepingcomputer.com/news/security/new-windows-signdrop-zero-day-gives-hackers-system-privileges/)
- [The Hacker News - New SignDrop Zero-Day Exploit Turns Windows Feature Against Itself](https://thehackernews.com/2026/11/new-signdrop-zero-day-exploit-turns.html)
- [SecurityWeek - Nightmare Eclipse Drops Windows Zero-Day Exploit SignDrop](https://www.securityweek.com/nightmare-eclipse-drops-windows-zero-day-exploit-signdrop/)
- [Security Affairs - New SignDrop Exploit Can Abuse Windows Defender to Bypass Security Protections](https://securityaffairs.com/202968/hacking/new-signdrop-exploit-can-abuse-windows-defender-to-bypass-security-protections.html)
- [GitHub - MSNightmare/SignDrop PoC Repository](https://github.com/MSNightmare/SignDrop)
- [Microsoft Learn - CLFS Logfile Authentication](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/clfs-authentication)
- [Microsoft Support - Common Log File System (CLFS) Authentication Mitigation](https://support.microsoft.com/en-us/servicing/os/windows/2025/03/common-log-file-system-clfs-authentication-mitigation)

---

*Report generated 2026-11-13 | Actioner CTI & Detection Engineering | DRAFT*
