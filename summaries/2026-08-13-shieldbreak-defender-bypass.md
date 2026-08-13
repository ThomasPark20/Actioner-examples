# Technical Analysis Report: ShieldBreak -- Microsoft Defender CVE-2026-50656 Patch Bypass (2026-08-13)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-13
Version: 1.1 (FINAL)

## Executive Summary

On August 11-12, 2026, security researcher Chaotic Eclipse (also tracked as Nightmare Eclipse / INFINITE NIGHTMARE / MSNightmare) publicly released "ShieldBreak," a proof-of-concept exploit that fully bypasses Microsoft's July 2026 patch for CVE-2026-50656 (RoguePlanet, CVSS 7.8) in the Microsoft Malware Protection Engine (mpengine.dll). ShieldBreak achieves NT AUTHORITY\SYSTEM privileges from a standard user account with a claimed 100% success rate on Windows 11 25H2 (including Canary channel) and Windows Server 2025. Windows 10 and its server editions are described as vulnerable but are not yet supported by the current PoC.

Unlike RoguePlanet, which exploited a filesystem race condition using virtual disk mounting and NT native file manipulation, ShieldBreak employs a fundamentally different attack vector: it abuses the Cloud Filter API (cfapi) user-mode callback hooks to manipulate file contents during a Defender cloud-hydration scan. The exploit combines CLFS (Common Log File System) log manipulation with Object Manager symbolic links to redirect Defender's scanning pipeline, ultimately causing the SYSTEM-privileged wermgr.exe process to load an attacker-controlled DLL (phoneinfo.dll) placed in System32. This is the eighth public exploit in an escalating campaign by this researcher against Microsoft Defender. No patch is available as of August 13, 2026.

**Prior Actioner Coverage:** This report builds on the [RoguePlanet Zero-Day Analysis (2026-06-10)](summaries/2026-06-10-defender-rogueplanet-zero-day.md) (internal Actioner report), which covers the original RoguePlanet exploit (CVE-2026-50656) and the broader Nightmare Eclipse campaign history.

## Background: CVE-2026-50656 and the RoguePlanet Patch

CVE-2026-50656 (RoguePlanet) is a privilege escalation vulnerability in the Microsoft Malware Protection Engine (mpengine.dll), the core scanning component of Microsoft Defender that runs as NT AUTHORITY\SYSTEM. The original RoguePlanet exploit, disclosed on June 9, 2026, used a TOCTOU race condition involving VHD/VHDX virtual disk mounting, opportunistic locks, and NTFS junction/symlink redirection to cause Defender to perform SYSTEM-privileged file operations at attacker-chosen locations.

Microsoft released a patch in the July 2026 Defender engine update (version 1.1.26060.3008), which included defense-in-depth hardening. However, the researcher reported that the patch was incomplete and introduced a secondary issue -- Defender could leak 8 bytes of data through Zone.Identifier ADS file handling during SMB operations. ShieldBreak demonstrates a complete bypass of the July patch using an entirely different attack chain.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-09 | RoguePlanet PoC released on GitHub (MSNightmare/RoguePlanet) |
| 2026-06-10 | Major security outlets publish RoguePlanet coverage; no CVE assigned |
| Mid-June 2026 | Microsoft acknowledges RoguePlanet zero-day |
| 2026-07-09 | Microsoft releases CVE-2026-50656 patch in Defender engine v1.1.26060.3008 |
| 2026-08-11 | ShieldBreak PoC released on blog.projectnightcrawler[.]dev and GitHub (MSNightmare/ShieldBreak) |
| 2026-08-12 | August 2026 Patch Tuesday; ShieldBreak coverage by BleepingComputer, The Hacker News, SecurityWeek, Security Affairs |
| 2026-08-12 | Kevin Beaumont validates exploit, publishes MDE detection queries; Will Dormann (Tharros) validates exploit and details attack sequence |
| 2026-08-13 | Microsoft responds: "aware of the reported vulnerability and is actively investigating" |

## Root Cause: Cloud Filter API Abuse in Defender's Hydration Scan

ShieldBreak exploits a design weakness in how Microsoft Defender interacts with the Windows Cloud Filter API (cfapi, implemented in cldapi.dll). When Defender performs a cloud-hydration scan on a file registered as a cloud placeholder, the exploit intercepts the callback mechanism to swap file contents mid-scan.

The core bypass technique: rather than racing Defender with filesystem-level TOCTOU manipulation (as RoguePlanet did), ShieldBreak registers a rogue cloud sync provider and uses a user-mode callback hook to deterministically change file contents during the Defender scan. This eliminates the race condition's inherent non-determinism, accounting for the claimed 100% success rate.

As independent researcher Will Dormann (Tharros) noted, despite both exploiting Defender, the attack vectors share little similarity -- ShieldBreak uses Cloud Filter API and CLFS manipulation rather than virtual disks and NT native file manipulation.

## Technical Analysis of the Malicious Payload

### 1. Rogue Cloud Sync Provider Registration (Setup)

The exploit creates a temporary directory and registers it as a Cloud Sync provider using the Cloud Filter API (cfapi). This provider is linked to a specially crafted placeholder file. The registration allows the exploit to intercept Defender's file access callbacks during cloud-hydration scans.

Key API: `CfRegisterSyncRoot`, `CfConnectSyncRoot`, `CfCreatePlaceholders` (from cldapi.dll)

### 2. EICAR Trigger and Defender Scan Initiation

The exploit plants an EICAR antivirus test file (included as eicar_com.zip in the repository) to trigger a Defender detection. When Defender's real-time protection detects the EICAR content, it initiates a cloud-hydration scan on the placeholder file, entering the exploit's callback-controlled code path.

### 3. CLFS Log Manipulation and Object Manager Symlinks

During the Defender scan, the exploit uses CLFS (Common Log File System) log manipulation alongside Object Manager symbolic links to redirect Defender's scan path toward System32. This causes Defender to lock a legitimate system file while the exploit swaps in attacker-controlled content. The symlinks are used to control the path resolution that Defender follows, causing it to operate on `C:\Windows\System32\phoneinfo.dll` -- a file that does not exist by default in Windows.

Key component: Warden.dll (included in the repository) serves as the malicious payload DLL.

### 4. SYSTEM Privilege Achievement via QueueReporting

The exploit triggers the `QueueReporting` Windows scheduled task, which runs `wermgr.exe -upload` with highest privileges. The Windows Error Reporting process (wermgr.exe) loads wer.dll, which contains explicit code to load phoneinfo.dll from System32. Because the attacker has placed their malicious DLL (Warden.dll content) at `C:\Windows\System32\phoneinfo.dll`, the load succeeds and spawns conhost.exe with NT AUTHORITY\SYSTEM privileges.

Process chain: QueueReporting scheduled task -> wermgr.exe (SYSTEM) -> wer.dll -> phoneinfo.dll (attacker) -> conhost.exe (SYSTEM shell)

### 5. Anti-Forensics / Evasion Techniques

- The exploit uses deterministic callback manipulation rather than a race condition, leaving fewer timing-related forensic artifacts
- Cloud Sync provider registration is transient and can be cleaned up post-exploitation
- phoneinfo.dll does not exist by default in Windows, making its presence a clean indicator but also meaning no legitimate file is overwritten (no integrity monitoring trigger for "modified" files)
- The exploit requires Defender to be enabled -- counterintuitively, disabling Defender is the only immediate mitigation but removes endpoint protection

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Microsoft Malware Protection Engine (mpengine.dll) | 1.1.26060.3008 (patched for CVE-2026-50656 but vulnerable to ShieldBreak bypass) | Engine version released in July 2026 patch; ShieldBreak fully bypasses it |
| Microsoft Malware Protection Engine (mpengine.dll) | All current versions as of August 13, 2026 | No patch available for ShieldBreak |

### File System

> **Note:** SHA256 hashes are N/A because the ShieldBreak PoC is distributed as source code (C++ Visual Studio project); no pre-built binaries are published. Each compilation produces unique hashes. Warden.dll is the only pre-built binary in the repository but its hash varies across commits.

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | ShieldBreak.exe | N/A (compile-from-source PoC) | ShieldBreak exploit binary (C++, Visual Studio project) |
| Windows | Warden.dll | N/A (binary varies across repo commits) | Malicious DLL payload dropped as phoneinfo.dll in System32 |
| Windows | C:\Windows\System32\phoneinfo.dll | N/A (attacker-compiled artifact) | Attacker-placed DLL; file does not exist by default in Windows |
| Windows | Report.wer | N/A | Windows Error Reporting artifact included in PoC repository |
| Windows | eicar_com.zip | N/A | EICAR antivirus test file used to trigger Defender scan |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | projectnightcrawler[.]dev | Exploit hosting and researcher blog (blog.projectnightcrawler[.]dev, git.projectnightcrawler[.]dev) |
| Domain | staybud[.]dpdns[.]org | BeigeBurrow C2 server from prior Nightmare Eclipse intrusions (port 443) |
| URL | hxxps://github[.]com/MSNightmare/ShieldBreak | PoC repository |
| URL | hxxps://blog[.]projectnightcrawler[.]dev/posts/2026-08-11-shieldbreak-august-2026-disclosure/ | Researcher disclosure blog post |

### Behavioral

- Creation of phoneinfo.dll in `C:\Windows\System32\` (this file does not exist by default)
- Non-standard processes loading both MpClient.dll (Defender library) and cldapi.dll (Cloud Filter API) -- the combination is abnormal and indicates ShieldBreak-style exploitation
- Cloud Sync provider registration from non-standard paths (outside System32, Program Files)
- CLFS log file manipulation in conjunction with Object Manager symlink creation
- QueueReporting scheduled task execution followed by wermgr.exe spawning unexpected child processes
- wermgr.exe spawning conhost.exe (abnormal process lineage)
- EICAR test file creation by non-security-testing processes
- Interactive shell or scripting host running as SYSTEM with MsMpEng.exe in the parent process chain

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | Cloud Filter API callback abuse in Defender to achieve SYSTEM via phoneinfo.dll DLL side-loading |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Attacker-controlled phoneinfo.dll placed in System32 is loaded by wer.dll during QueueReporting task execution |
| T1053.005 | Scheduled Task/Job: Scheduled Task | QueueReporting scheduled task abused to trigger wermgr.exe execution with highest privileges |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Exploit leverages Defender's own scanning pipeline as the attack vector; Defender must be enabled for exploitation |

## Impact Assessment

**Breadth:** All Windows 10, Windows 11 (including 25H2 and Canary), and Windows Server 2025 systems running Microsoft Defender with the latest patches applied are vulnerable. The affected user base is estimated in the hundreds of millions. The July 2026 patch for CVE-2026-50656 does not protect against ShieldBreak.

**Depth:** Full SYSTEM privileges from an unprivileged user account (CVSS AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8 HIGH). The 100% success rate claim (validated by Kevin Beaumont and Will Dormann) represents a significant escalation over RoguePlanet's non-deterministic race condition approach.

**Stealth:** The deterministic exploitation path (no race condition timing artifacts) and the use of a legitimate Windows subsystem (Cloud Filter API, Windows Error Reporting) make ShieldBreak harder to detect through traditional behavioral analysis. The exploit abuses trusted Windows components throughout the chain.

**Active Exploitation:** No in-the-wild exploitation documented yet (August 13, 2026), but the PoC is public and fully functional, and the Nightmare Eclipse tooling family has documented real-world use (Huntress incident from April 2026 involving prior exploits in this series).

## Detection & Remediation

### Immediate Detection

**Check for ShieldBreak exploitation artifacts:**
```powershell
# Check for phoneinfo.dll in System32 (does not exist by default)
Test-Path "C:\Windows\System32\phoneinfo.dll"

# Search for ShieldBreak / Warden.dll exploit artifacts
Get-ChildItem -Path C:\Users -Recurse -Include "ShieldBreak.exe","Warden.dll" -ErrorAction SilentlyContinue

# Check for anomalous Cloud Sync provider registrations
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager" -ErrorAction SilentlyContinue

# Look for wermgr.exe spawning unexpected processes
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{Id=1} -ErrorAction SilentlyContinue | Where-Object { $_.Properties[20].Value -match "wermgr\.exe" -and $_.Properties[4].Value -match "conhost\.exe" }
```

**Kevin Beaumont's MDE Advanced Hunting queries** (published at github.com/GossiTheDog/ThreatHunting):
- Detection 1: Non-Defender processes loading MpClient.dll
- Detection 2: Non-standard processes loading cldapi.dll
- Detection 3: Correlated MpClient.dll + cldapi.dll loading within 5-minute window on same device/process

### Remediation

1. **Immediate -- Monitor:** Deploy the detection rules below and Kevin Beaumont's MDE hunting queries to detect exploitation attempts
2. **Immediate -- Hunt:** Check all Windows endpoints for the presence of `C:\Windows\System32\phoneinfo.dll` (should not exist)
3. **Advisory -- Disable Defender (risk tradeoff):** Disabling Defender prevents ShieldBreak exploitation but removes endpoint protection; only consider this in environments with alternative EDR coverage
4. **Short-term:** Block known Nightmare Eclipse infrastructure at the network perimeter: `projectnightcrawler[.]dev`, `staybud[.]dpdns[.]org`
5. **Pending patch:** Apply Microsoft Defender engine update as soon as a fix for ShieldBreak is released
6. **If compromised:** Investigate for SYSTEM-level persistence (services, scheduled tasks, WMI subscriptions); rotate local account credentials; check for lateral movement indicators

### Long-Term Hardening

- Deploy application allowlisting (AppLocker, WDAC, or third-party) to prevent unauthorized binary execution
- Enable Sysmon with image_load (Event 7) monitoring to detect anomalous DLL loads by Defender and WER processes
- Monitor Cloud Filter API registrations for unauthorized cloud sync providers
- Restrict QueueReporting scheduled task permissions where Windows Error Reporting upload functionality is not required
- Monitor `C:\Windows\System32\` for creation of new DLL files, especially phoneinfo.dll

## Detection Rules

These detections target the ShieldBreak exploit chain at PoC/advisory-specific altitude, covering DLL placement, process chain, DLL loading anomaly, binary execution, and infrastructure indicators. Compiles does not mean fires -- verify in your pipeline. `sigma check` is unavailable (MITRE ATT&CK data fetch blocked by proxy); portability proven via `sigma convert` to Splunk and CrowdStrike LogScale.

### Sigma: ShieldBreak - phoneinfo.dll Dropped in System32
Detects creation of phoneinfo.dll in System32 -- a file that does not exist by default in Windows, making its presence a definitive ShieldBreak indicator.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check unavailable (MITRE data fetch 403); splunk 0; log_scale 0; splunk_windows 0. phoneinfo.dll does not exist by default in any Windows version, so any creation is anomalous. Zero expected FP. Evasion: attacker could rename the target DLL, but this requires modifying the PoC to target a different wer.dll load path. -->
```yaml
title: ShieldBreak Exploit - phoneinfo.dll Dropped in System32
id: 8f4e2a1b-3c7d-4e9a-b6f5-2d0a1e8c7b4f
status: experimental
description: >
    Detects creation of phoneinfo.dll in System32, a file that does not exist
    by default in Windows. The ShieldBreak exploit abuses Defender's cloud
    hydration scan via Cloud Filter API to swap a malicious phoneinfo.dll into
    System32, which is subsequently loaded by wer.dll during QueueReporting
    scheduled task execution to achieve SYSTEM privileges.
references:
    - https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html
    - https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/
    - https://github.com/MSNightmare/ShieldBreak
author: Actioner
date: 2026/08/13
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
    - Unlikely - phoneinfo.dll does not exist by default in Windows
level: critical
```

### Sigma: ShieldBreak - wermgr.exe Spawning conhost.exe
Detects wermgr.exe spawning conhost.exe outside normal console host inheritance, the final exploitation step where the attacker-planted phoneinfo.dll executes. No User/IntegrityLevel filter -- pair with host context to confirm SYSTEM.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check unavailable (MITRE data fetch 403); splunk 0; log_scale 0; splunk_windows 0. Filter excludes normal conhost inheritance (0xffffffff). wermgr.exe spawning conhost.exe without the standard console inheritance parameter is uncommon but not impossible in legitimate WER edge cases. Downgraded from high to medium: title "as SYSTEM" removed because the rule has no User or IntegrityLevel condition to enforce that claim. -->
<!-- revision: retitled (removed "as SYSTEM" — no User/IntegrityLevel filter); confidence high→medium per critic. -->
```yaml
title: ShieldBreak Exploit - wermgr.exe Spawning conhost.exe
id: 5a2b9c3d-7e8f-4d1a-b0c6-4f3e2d1a8b7c
status: experimental
description: >
    Detects wermgr.exe spawning conhost.exe outside normal console host
    inheritance (0xffffffff). This is the final step of the ShieldBreak exploit
    where wer.dll loads attacker-planted phoneinfo.dll, which spawns conhost.exe.
    Pair with host context to confirm SYSTEM privilege level.
references:
    - https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html
    - https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/
    - https://github.com/MSNightmare/ShieldBreak
author: Actioner
date: 2026/08/13
tags:
    - attack.t1068
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\wermgr.exe'
        Image|endswith: '\conhost.exe'
    filter_normal_conhost:
        CommandLine|contains: '0xffffffff'
    condition: selection and not filter_normal_conhost
falsepositives:
    - Legitimate Windows Error Reporting edge cases spawning conhost
level: high
```

### Sigma: ShieldBreak - Non-Standard Process Loading MpClient.dll or cldapi.dll
Detects a non-standard process loading MpClient.dll or cldapi.dll individually. Sigma cannot replicate Beaumont's KQL temporal join (both DLLs by same PID within 5 min); treat as hunt-only and pair with additional context.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check unavailable (MITRE data fetch 403); splunk 0; log_scale 0; splunk_windows 0. CRITICAL FIX: title previously said "Both" but condition is OR — fires on EITHER DLL loaded by non-standard process. cldapi.dll is loaded by OneDrive, backup tools, cloud sync apps — high FP on cldapi.dll alone. Sigma has no temporal-join primitive, so the KQL co-loading correlation cannot be replicated. Confidence downgraded to low. -->
<!-- revision: retitled ("Both"→"or") to match OR condition; confidence medium→low; caveat added re Sigma temporal-join limitation vs KQL per critic. -->
```yaml
title: ShieldBreak Exploit - Non-Standard Process Loading MpClient.dll or cldapi.dll
id: 1e7f3a2b-9c4d-4b8e-a5d6-6f0c3e2d1a9b
status: experimental
description: >
    Detects a non-standard process (outside Defender/System32/Program Files)
    loading MpClient.dll or cldapi.dll. The OR condition is an approximation
    of Kevin Beaumont's MDE co-loading detection — Sigma cannot express the
    temporal join. High FP expected on cldapi.dll alone (OneDrive, cloud sync).
    Hunt-only; pair with additional context.
references:
    - https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html
    - https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/
    - https://github.com/GossiTheDog/ThreatHunting/blob/master/AdvancedHuntingQueries/ShieldBreak.kql
author: Actioner
date: 2026/08/13
tags:
    - attack.t1068
    - attack.t1562.001
logsource:
    category: image_load
    product: windows
detection:
    selection_mpclient:
        ImageLoaded|endswith: '\MpClient.dll'
    selection_cldapi:
        ImageLoaded|endswith: '\cldapi.dll'
    filter_defender:
        Image|contains:
            - '\Windows Defender\'
            - '\Microsoft\Windows Defender\'
    filter_system:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: (selection_mpclient or selection_cldapi) and not filter_defender and not filter_system
falsepositives:
    - OneDrive, backup tools, and cloud sync applications loading cldapi.dll
    - Third-party security tools loading MpClient.dll
level: medium
```

### Sigma: ShieldBreak / Nightmare Eclipse Exploit Binary Execution
Detects execution of ShieldBreak or related Nightmare Eclipse exploit tools by filename. Trivially evaded by rename; pair with the YARA rule for content-based detection.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check unavailable (MITRE data fetch 403); splunk 0; log_scale 0; splunk_windows 0. Simple filename match — trivially evaded by rename. Family names like undef.exe could collide with unrelated binaries. Confidence downgraded from high to medium. -->
<!-- revision: confidence high→medium per critic (rename evasion + undef.exe collision risk). -->
```yaml
title: ShieldBreak Exploit Binary Execution
id: 3d8e5f2a-1b4c-4a7d-9e6f-0c3a2b1d8e5f
status: experimental
description: >
    Detects execution of the ShieldBreak exploit binary or related Nightmare
    Eclipse exploit tools by process name. The ShieldBreak PoC repository
    includes ShieldBreak.exe and Warden.dll as key components of the exploit.
references:
    - https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html
    - https://github.com/MSNightmare/ShieldBreak
author: Actioner
date: 2026/08/13
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
    condition: selection_shieldbreak or selection_family
falsepositives:
    - Unlikely - these are known exploit tool names from the Nightmare Eclipse campaign
level: critical
```

### Suricata: HTTP Request to Nightmare Eclipse Project Nightcrawler Infrastructure
Detects HTTP requests to the projectnightcrawler[.]dev domain. The .dev TLD is HSTS-preloaded so browsers enforce HTTPS; the http.host rule catches non-browser tools and the tls.sni companion below covers browser/HTTPS traffic.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Matches HTTP host header containing "projectnightcrawler.dev". Domain is researcher-controlled infrastructure used for exploit distribution. .dev TLD is HSTS-preloaded so browsers will use HTTPS — http.host won't match HTTPS traffic. The tls.sni companion rule (sid:2200011) covers that case. Will rotate if researcher changes infrastructure. -->
<!-- revision: added tls.sni companion rule (sid:2200011) per critic advisory; added .dev HSTS caveat. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to Nightmare Eclipse Project Nightcrawler Infrastructure"; flow:established,to_server; http.host; content:"projectnightcrawler.dev"; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html; metadata:author Actioner, created_at 2026-08-13; sid:2200010; rev:1;)
```

### Suricata: TLS SNI to Nightmare Eclipse Project Nightcrawler Infrastructure
Detects TLS connections with SNI matching the projectnightcrawler[.]dev domain, covering HTTPS traffic that the HTTP host rule cannot see.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Companion to sid:2200010 — covers HTTPS/TLS traffic via SNI inspection. Required because .dev is HSTS-preloaded and browsers enforce HTTPS. -->
<!-- revision: new rule added per critic advisory (tls.sni companion for .dev HSTS). -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to Nightmare Eclipse Project Nightcrawler Infrastructure"; flow:established,to_server; tls.sni; content:"projectnightcrawler.dev"; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html; metadata:author Actioner, created_at 2026-08-13; sid:2200011; rev:1;)
```

### Snort: N/A
ShieldBreak is a local privilege escalation exploit with no distinctive network-level payload signature. The Suricata rule above covers the known infrastructure indicator. Snort is not installed in this environment.

### YARA: ShieldBreak Exploit Tool
Detects PE files containing Cloud Filter API imports, ShieldBreak-specific strings, and Defender/WER target paths characteristic of the ShieldBreak exploit tool.
**Status:** compile ✅ compiles · confidence: medium · sample: constructed
<!-- audit: yarac exit 0. yara pos_shieldbreak.txt: MATCH (Exploit_ShieldBreak_Defender_LPE). yara neg_shieldbreak.txt: no match. Positive sample constructed (not a confirmed upstream binary — PoC is source-only) from published PoC repository strings. First condition branch tightened: now requires 2 cfapi APIs + 1 lib + 1 DISTINCTIVE string ($str1-$str5 only, excluding common $str6/$str7) to avoid FP from generic "wermgr" or "QueueReporting" matches combined with common ntdll.dll. -->
<!-- revision: sample label "fired"→"constructed" (synthetic sample, not upstream binary); confidence high→medium; first condition branch tightened to require distinctive $str* only per critic. -->
```yara
rule Exploit_ShieldBreak_Defender_LPE
{
    meta:
        description = "Detects the ShieldBreak exploit tool targeting Microsoft Defender CVE-2026-50656 patch bypass via Cloud Filter API abuse for SYSTEM privilege escalation"
        author = "Actioner"
        date = "2026-08-13"
        reference = "https://github.com/MSNightmare/ShieldBreak"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $api1 = "CfRegisterSyncRoot" ascii fullword
        $api2 = "CfConnectSyncRoot" ascii fullword
        $api3 = "CfCreatePlaceholders" ascii fullword
        $api4 = "CfUpdatePlaceholder" ascii fullword
        $api5 = "CfHydratePlaceholder" ascii fullword

        $lib1 = "cldapi.dll" ascii nocase
        $lib2 = "ntdll.dll" ascii nocase
        $lib3 = "clfsw32.dll" ascii nocase

        $str1 = "ShieldBreak" ascii wide
        $str2 = "phoneinfo.dll" ascii wide nocase
        $str3 = "Warden.dll" ascii wide nocase
        $str4 = "Nightmare" ascii wide
        $str5 = "IHATEMICROSOFT" ascii wide

        $path1 = "Windows\\system32\\phoneinfo.dll" ascii wide nocase
        $path2 = "ProgramData\\Microsoft\\Windows Defender" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (2 of ($api*) and 1 of ($lib*) and 1 of ($str1, $str2, $str3, $str4, $str5)) or
            ($str1 and 1 of ($path*)) or
            ($str2 and 2 of ($api*)) or
            (3 of ($str1, $str2, $str3, $str5))
        )
}
```

## Lessons Learned

1. **Patch bypass is the new norm for high-value targets.** Microsoft's July 2026 patch for CVE-2026-50656 was bypassed within five weeks using an entirely different attack vector. The ShieldBreak bypass demonstrates that patching a specific exploitation path (filesystem race conditions) does not address the underlying architectural issue -- Defender's SYSTEM-privileged scanning pipeline can be abused through multiple independent mechanisms (VHD TOCTOU, Cloud Filter API callbacks).

2. **Cloud Filter API is an emerging attack surface.** ShieldBreak's use of cfapi user-mode callback hooks to manipulate file contents during Defender scans represents a novel privilege escalation vector. The Windows Cloud Files Mini Filter (cldflt.sys) has prior CVE history (2025 Exodus Intelligence TOCTOU disclosure), and ShieldBreak demonstrates its continued exploitation potential in combination with Defender's privileged scanning context.

3. **Deterministic exploitation changes the risk calculus.** RoguePlanet's race condition had variable success rates across hardware configurations. ShieldBreak's callback-based approach eliminates timing dependencies, achieving claimed 100% reliability. This significantly lowers the exploitation barrier and increases the likelihood of weaponization by less sophisticated actors.

## Sources

- [The Hacker News - ShieldBreak Zero-Day PoC Claims Microsoft Defender Patch Bypass With SYSTEM Access](https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html) -- primary news coverage with Will Dormann analysis, Kevin Beaumont validation, and detailed exploit chain description
- [BleepingComputer - New Microsoft Defender 'ShieldBreak' zero-day grants SYSTEM privileges](https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/) -- news coverage with Kevin Beaumont and Brian Levine quotes, GitHub repository details
- [SecurityWeek - Nightmare Eclipse Drops Windows Zero-Day Exploit 'ShieldBreak'](https://www.securityweek.com/nightmare-eclipse-drops-windows-zero-day-exploit-shieldbreak/) -- news coverage with independent validation details
- [Security Affairs - ShieldBreak: New Windows Zero-Day Bypasses Microsoft's RoguePlanet Patch](https://securityaffairs.com/197063/hacking/shieldbreak-new-windows-zero-day-bypasses-microsofts-rogueplanet-patch.html) -- news coverage with mpengine.dll and CVSS details
- [Arctic Wolf - CVE-2026-50656/RoguePlanet, ShieldBreak](https://arcticwolf.com/resources/blog/cve-2026-50656-rogueplanet-shieldbreak/) -- security bulletin with engine version details and detection guidance
- [GitHub - MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak) -- PoC source code repository (C++, includes ShieldBreak.cpp, Warden.dll, eicar_com.zip, Report.wer)
- [GitHub - GossiTheDog/ThreatHunting - ShieldBreak.kql](https://github.com/GossiTheDog/ThreatHunting/blob/master/AdvancedHuntingQueries/ShieldBreak.kql) -- Kevin Beaumont's MDE detection queries (MpClient.dll, cldapi.dll co-loading detection)
- [The Hacker News - Microsoft Patches RoguePlanet Defender Flaw](https://thehackernews.com/2026/07/microsoft-patches-rogueplanet-defender.html) -- July 2026 CVE-2026-50656 patch details (engine v1.1.26060.3008)
- [CSO Online - Researcher bypasses Microsoft Defender patch](https://www.csoonline.com/article/4208760/researcher-bypasses-microsoft-defender-security-patch-seizing-control.html) -- Brian Levine analysis on SYSTEM shell detection
- [Cyber Kendra - ShieldBreak PoC Bypasses Microsoft's RoguePlanet Defender Fix](https://www.cyberkendra.com/2026/08/shieldbreak-poc-bypasses-microsofts.html) -- repository file inventory (Warden.dll, Report.wer, eicar_com.zip) and QueueReporting scheduled task details
- [Actioner - RoguePlanet Zero-Day Analysis (2026-06-10)](summaries/2026-06-10-defender-rogueplanet-zero-day.md) -- prior Actioner coverage of the original CVE-2026-50656 exploit and Nightmare Eclipse campaign history (internal report; link is repo-relative)

---
*Report generated by Actioner*
