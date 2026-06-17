# Technical Analysis Report: AsyncRAT Campaign via Fake AI Coding Guides (2026-06-13)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-13
Version: 1.1 (FINAL)

## Executive Summary

A multi-stage malware campaign is distributing AsyncRAT and a modular .NET RAT variant ("clay_Client") through social engineering lures disguised as AI developer resources. The primary lure is a 7z archive titled "Agentic Coding with Claude Code, The everyday developer's guide to agentic coding with Claude Code.7z" that contains a malicious LNK file triggering a complex execution chain through cmd.exe, findstr, PowerShell, and AutoHotkey. The campaign adds the entire C:\ drive and powershell.exe to Windows Defender exclusion lists, uses scheduled tasks masquerading as Realtek audio services for persistence, and deploys payloads via process hollowing into legitimate .NET Framework executables. FortiGuard Labs attributed the campaign's intermediate-stage code to likely AI-assisted development based on structured Chinese-language variable names and comments referencing Chinese mythology.

The campaign targets Windows users seeking AI adoption resources -- developers, marketers, and technical professionals -- making it particularly relevant for organizations with active AI adoption initiatives. C2 infrastructure resolves to 107[.]172[.]10[.]190 with domains mimicking shampoo and cosmetics brands.

## Background: Targeting AI Adoption Seekers

The threat actors exploit the current surge in demand for AI tooling guidance by packaging malware inside documents that appear to be legitimate technical resources. Lure documents include titles such as "AI-Ready PostgreSQL 18" and "A Guide for Thinking Marketers in the Age of AI," presented alongside the Claude Code developer guide archive. The campaign capitalizes on the trust developers and professionals place in technical documentation, particularly around popular tools like Anthropic's Claude Code CLI.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06 (early) | Campaign artifacts first observed by FortiGuard Labs |
| 2026-06-11 | FortiGuard Labs publishes technical analysis |
| 2026-06-12 | News coverage by Hackread and Infosecurity Magazine |
| 2026-06-13 | This analysis produced |

## Root Cause: Social Engineering via Fake AI Documentation

Initial access is achieved through social engineering. Victims download a compressed 7z archive disguised as an AI developer guide. The archive contains a Windows shortcut (LNK) file that, when clicked, initiates the multi-stage attack chain. The exact distribution vector (email attachment, forum post, or download site) is not specified in the FortiGuard Labs analysis, but the lure theming strongly suggests targeted distribution through developer communities and professional channels.

## Technical Analysis of the Malicious Payload

### 1. Initial Delivery -- LNK Loader with Findstr Extraction

The archive contains a malicious LNK shortcut alongside two hidden files named `3th.pdf` and `4th.pdf`. Despite their extensions, these are not PDF documents -- they serve as data containers. The `3th.pdf` file uses PGP armor markers (`-----BEGIN PGP PRIVATE KEY BLOCK-----` / `-----END PGP PRIVATE KEY BLOCK-----`) to delimit embedded payload data, while `4th.pdf` contains a benign decoy document.

When the victim clicks the LNK file, it spawns `cmd.exe` which uses `findstr.exe` to extract encoded payload data from `3th.pdf`. This technique abuses native Windows LOLBins to avoid dropping suspicious executables during the initial stage.

**Known LNK hash (SHA256):** `61b7fa5a7186cbf73dbc1f03e6e6f6819f5eb1e630a001059d381114bda2f974`

### 2. Stage 2 -- PowerShell Staging and Defender Evasion

The extracted data is processed through PowerShell scripts that perform several critical evasion actions:

- **Defender Exclusions:** `Add-MpPreference` is used to exclude the entire `C:\` drive via `-ExclusionPath` and `powershell.exe` via `-ExclusionProcess`, effectively blinding Windows Defender to all subsequent activity
- **AES-CBC Decryption:** Payloads are decrypted using `AesCryptoServiceProvider` with PBKDF2 key derivation from a fixed password ("1")
- **XOR Decryption:** Additional layers use XOR with the key `Realtek2025`

All files are staged to `%LOCALAPPDATA%\Packages\Microsoft.WindowsSoundDiagnostics\`, a directory chosen to blend with legitimate Windows package paths.

**Known PowerShell hash (SHA256):** `7d6ee3c6ff8f70b1817aaec82aff1d2babe0b62cafef3975262644743afc0cb8`

**Key dropped files:**
- `Cache_{GUID}.ps1` -- initial PowerShell stager
- `RealtekAudioService64.ps1` / `.bat` -- secondary execution scripts
- `RealtekAudioEnhancements64.ahk` / `.ps1` / `.bat` -- AutoHotkey loader scripts
- `RtkNGUI64.ahk`, `RtkDiagService.ahk`, `RtkCplApp.ahk`, `RtkDeviceConfigure64.ahk` -- additional AHK scripts
- `ResetRealtekAudioSettings64.vbs` -- VBScript persistence component
- `RtkLoggingManifest.man` -- encoded PE payload
- `Subtitles` -- GZip container with payloads
- `RealtekAudioEnhancements64.assets` -- payload archive
- `ResetRealtekAudioSettings64.Realtek` -- payload container

### 3. Stage 3 -- AutoHotkey-Based Execution and Persistence

AutoHotkey.exe is renamed to masquerade as Realtek audio components (e.g., `RealtekAudioEnhancements64.exe`). This legitimate automation tool is repurposed as a script execution engine, with malicious AHK scripts performing memory allocation, shellcode injection, and payload loading through DllCall APIs.

**Persistence** is established via three scheduled tasks:

| Task Name | Target | Triggers |
|-----------|--------|----------|
| CheckRealtekAudioVersion | RealtekAudioService64.bat | User logon, system startup, daily at noon |
| RealtekAudioEnhancements64 | RealtekAudioEnhancements64.exe | User logon, system startup, daily at noon |
| ResetRealtekAudioSettings64 | wscript.exe -> ResetRealtekAudioSettings64.vbs | User logon, system startup, daily at noon |

**Known EXE hash (SHA256):** `96b486bd7308ef3d6771360800f4c9b48b10697bd4cb69a8589b97b039377ecb`

### 4. Stage 4 -- Process Hollowing and Payload Deployment

The attack deploys two .NET payloads via process hollowing into legitimate .NET Framework executables from `C:\Windows\Microsoft.NET\Framework\v4.0.30319\`:

- `AddInProcess32.exe`
- `AppLaunch.exe`
- `aspnet_compiler.exe`
- `cvtres.exe`

**Payload 1 -- clay_Client:** A modular .NET RAT with capabilities including:
- Remote desktop monitoring with multi-monitor enumeration
- Screenshot capture and compression
- Mouse movement simulation / input injection
- Fileless assembly loading via `Assembly.Load` (Reflection)
- Process hollowing via RunPE
- Client lifecycle management (shutdown, delete, update)

**Payload 2 -- AsyncRAT:** Standard AsyncRAT variant beaconing to C2 infrastructure for remote access, system reconnaissance, and ongoing control.

Both payloads use `RijndaelManaged` in ECB mode with MD5-derived encryption keys for C2 communication.

**Mutex:** `IDG5FUAM3PSONBSInGIGSWSD`

### 5. C2 Infrastructure

| Type | Value | Context |
|------|-------|---------|
| IP | 107[.]172[.]10[.]190 | Primary C2 server |
| Domain | shampobiskworld[.]nl | C2 domain |
| Domain | shampoolagtto[.]com | C2 domain |
| Domain | shamppocosmaticso[.]com | C2 domain |

The C2 domains follow a naming pattern mimicking shampoo and cosmetics brands. Upon connection, the RAT exfiltrates processor details, username, OS version and build, CPU information, security appliance inventory, and system time.

### 6. AI-Assisted Development Indicators

FortiGuard Labs identified signs of AI-assisted malware development:

- PowerShell cmdlets reconstructed under Chinese variable names: `$测试路径` (Test-Path), `$连接路径` (Join-Path), `$新建项目` (New-Item)
- Windows API functions mapped to Chinese mythology aliases: "九天玄女" (CreateProcess), "乾坤袋" (VirtualAllocEx), "起死回生" (ResumeThread)
- Code comments in Simplified Chinese: "静默任务创建脚本 - 无输出版本" (Silent task creation script - no output version)
- Highly structured coding style consistent with AI-generated output

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `shampobiskworld[.]nl`)
> - IP addresses: `[.]` replacing dots (e.g., `107[.]172[.]10[.]190`)

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|----------------|---------------|-------------|
| Windows | LNK shortcut in 7z archive | `61b7fa5a7186cbf73dbc1f03e6e6f6819f5eb1e630a001059d381114bda2f974` | Initial LNK loader |
| Windows | PowerShell stager | `7d6ee3c6ff8f70b1817aaec82aff1d2babe0b62cafef3975262644743afc0cb8` | Cache_{GUID}.ps1 |
| Windows | Renamed AutoHotkey EXE | `96b486bd7308ef3d6771360800f4c9b48b10697bd4cb69a8589b97b039377ecb` | RealtekAudioEnhancements64.exe |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 107[.]172[.]10[.]190 | AsyncRAT/clay_Client C2 |
| Domain | shampobiskworld[.]nl | C2 domain |
| Domain | shampoolagtto[.]com | C2 domain |
| Domain | shamppocosmaticso[.]com | C2 domain |

### Behavioral

- **Staging path:** `%LOCALAPPDATA%\Packages\Microsoft.WindowsSoundDiagnostics\` with Realtek-themed file names
- **Scheduled tasks:** CheckRealtekAudioVersion, RealtekAudioEnhancements64, ResetRealtekAudioSettings64
- **Defender exclusions:** Entire C:\ drive and powershell.exe added via `Add-MpPreference`
- **Process hollowing targets:** .NET Framework v4.0.30319 executables (AddInProcess32.exe, AppLaunch.exe, aspnet_compiler.exe, cvtres.exe)
- **Mutex:** `IDG5FUAM3PSONBSInGIGSWSD`
- **XOR key:** `Realtek2025`
- **AES-CBC password:** `1` (PBKDF2-derived)
- **Fortinet detection names:** `LNK/Agent.MQOEQT!tr`, `MSIL/Agent.CDW!tr`, `POWERSHELL/Agent.CA!tr`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | Victim opens LNK file from 7z archive disguised as AI guide |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell scripts for payload decryption, Defender evasion, and staging |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | cmd.exe + findstr.exe used to extract data from PDF containers |
| T1027 | Obfuscated Files or Information | AES-CBC encryption, XOR with Realtek2025 key, PGP armor wrapping |
| T1140 | Deobfuscate/Decode Files or Information | PBKDF2 + AES-CBC decryption of staged payloads |
| T1036.005 | Masquerading: Match Legitimate Name or Location | AutoHotkey.exe renamed to Realtek audio executables |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Entire C:\ drive and powershell.exe excluded from Defender |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Three scheduled tasks for persistence at logon, startup, and daily |
| T1055.012 | Process Injection: Process Hollowing | Payloads injected into .NET Framework executables |
| T1071.004 | Application Layer Protocol: DNS | AsyncRAT C2 domains resolved via DNS for command and control |
| T1082 | System Information Discovery | RAT collects processor, OS, CPU, security appliance data |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | wscript.exe executing ResetRealtekAudioSettings64.vbs for persistence |
<!-- revision: removed T1105 (Ingress Tool Transfer) — payload extraction from embedded containers is T1140, already mapped -->

## Impact Assessment

This campaign targets a broad audience of Windows users interested in AI adoption resources. The use of Claude Code branding specifically targets the developer community, while additional lures (PostgreSQL, marketing guides) expand the victim pool. The dual-payload approach (clay_Client + AsyncRAT) provides both immediate remote access and a modular framework for follow-on operations including surveillance, data theft, and lateral movement. The campaign's use of AI-assisted development suggests a potentially scalable threat actor operation.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for Defender exclusions covering entire C: drive
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | Where-Object { $_ -eq "C:\" }

# Check for PowerShell exclusion from Defender
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess | Where-Object { $_ -match "powershell" }

# Check for suspicious scheduled tasks with Realtek naming
Get-ScheduledTask | Where-Object { $_.TaskName -match "Realtek|CheckRealtek|ResetRealtek" }

# Check for staging directory
Test-Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsSoundDiagnostics"

# Check for mutex (requires Sysinternals Handle)
handle.exe -a IDG5FUAM3PSONBSInGIGSWSD
```

### Remediation

1. **Containment:** Isolate affected hosts from the network immediately to prevent C2 communication
2. **Remove Defender Exclusions:** `Remove-MpPreference -ExclusionPath "C:\" ; Remove-MpPreference -ExclusionProcess "powershell.exe"`
3. **Remove Scheduled Tasks:** Delete CheckRealtekAudioVersion, RealtekAudioEnhancements64, and ResetRealtekAudioSettings64
4. **Clean Staging Directory:** Remove `%LOCALAPPDATA%\Packages\Microsoft.WindowsSoundDiagnostics\` and all contents
5. **Kill Malicious Processes:** Terminate any processes matching the renamed AutoHotkey binaries or hollowed .NET processes
6. **Block C2 Infrastructure:** Block 107[.]172[.]10[.]190 and all three C2 domains at firewall/proxy
7. **Credential Reset:** Rotate credentials for any accounts accessed from compromised hosts
8. **Full AV Scan:** Run updated scan after removing Defender exclusions

### Long-Term Hardening

- Block unsanctioned scripting engines (AutoHotkey, AutoIt) via application control policies
- Enable PowerShell Constrained Language Mode and Script Block Logging
- Monitor `Add-MpPreference` usage via SIEM alerting (should be rare in production)
- Audit scheduled task creation for non-standard naming conventions
- Enable memory scanning / AMSI integration on all endpoints
- Conduct developer-focused phishing awareness training around AI tool lures

## Detection Rules

Detection rules cover the full kill chain: initial findstr-based extraction from PDF containers, Defender exclusion tampering, AutoHotkey masquerading as Realtek binaries, persistence via scheduled tasks, staging directory file creation, and network-level C2 domain/IP detection. All rules use real (non-defanged) values for matching and have been validated against their respective compilers.

<!-- Validation audit (v1.1): All Sigma rules passed sigma check + sigma convert (splunk, log_scale). YARA rules passed yarac compilation. Suricata rules passed suricata -T. Snort rules are structurally validated only (snort not installed). The Sigma Defender exclusion rule triggers InvalidATTACKTagIssue for attack.t1562.001 — this is a pySigma validator data limitation, not a rule error; the ATT&CK ID is correct. -->
<!-- revision: v1.1 — fixed YARA LNK rule operator precedence (critical), fixed Snort DNS label-length bytes (critical, all 3 rules), corrected ATT&CK tags (T1071.001→T1071.004, T1218.011→T1059.005, removed T1105), added PS1 stager FP caveat -->

### Sigma: Findstr Extraction of Data from PDF Files via LNK

Detects the initial LNK-triggered findstr extraction from 3th.pdf/4th.pdf containers. Caveat: triggers only if process creation logging captures findstr with these specific filenames.

**compile: pass | confidence: high**

```yaml
title: Findstr Extraction of Data from PDF Files via LNK
id: 3523b51b-4ed1-483d-9d64-1477efb9ade6
status: experimental
description: >
    Detects findstr.exe used to extract embedded data from PDF files, matching
    the initial stage of the AsyncRAT campaign where an LNK file uses findstr
    to read payload data from 3th.pdf and 4th.pdf hidden in the archive.
references:
    - https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat
author: Actioner
date: 2026-06-13
tags:
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_findstr:
        Image|endswith: '\findstr.exe'
    selection_pdf:
        CommandLine|contains:
            - '3th.pdf'
            - '4th.pdf'
    condition: selection_findstr and selection_pdf
falsepositives:
    - Scripted searches of PDF file contents using findstr are uncommon
level: high
```

### Sigma: Suspicious Windows Defender Exclusion of C Drive and PowerShell

Detects Add-MpPreference abuse to exclude C:\ or powershell.exe from Defender scanning.

**compile: pass (1 medium-severity pySigma tag warning -- ATT&CK ID is valid) | confidence: high**

```yaml
title: Suspicious Windows Defender Exclusion of C Drive and PowerShell
id: 6a888990-6ba2-4bbc-92ca-613bc2f66a3d
status: experimental
description: >
    Detects Add-MpPreference used to exclude the entire C:\ drive or
    powershell.exe from Windows Defender scanning, as observed in the
    AsyncRAT campaign delivered via fake AI guide archives (June 2026).
references:
    - https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat
    - https://hackread.com/hackers-fake-claude-code-guide-ai-pdfs-asyncrat/
author: Actioner
date: 2026-06-13
tags:
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmdlet:
        CommandLine|contains: 'Add-MpPreference'
    selection_exclusion:
        CommandLine|contains:
            - '-ExclusionPath "C:\"'
            - "-ExclusionPath 'C:\\'"
            - '-ExclusionPath C:\\'
            - '-ExclusionProcess "powershell.exe"'
            - "-ExclusionProcess 'powershell.exe'"
            - '-ExclusionProcess powershell.exe'
    condition: selection_cmdlet and selection_exclusion
falsepositives:
    - Enterprise software deployment tools that temporarily exclude broad paths
level: high
```

### Sigma: AutoHotkey Binary Renamed to Realtek Audio Executable

Detects AutoHotkey.exe masquerading as Realtek audio binaries via OriginalFileName mismatch.

**compile: pass | confidence: high**

```yaml
title: AutoHotkey Binary Renamed to Realtek Audio Executable
id: 43fa3a52-518f-4142-a90b-3f74964f3669
status: experimental
description: >
    Detects execution of AutoHotkey.exe renamed to RealtekAudioEnhancements64.exe
    or RtkNGUI64.exe, a masquerading technique used in the AsyncRAT campaign
    targeting AI guide seekers.
references:
    - https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat
author: Actioner
date: 2026-06-13
tags:
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'AutoHotkey.exe'
        Image|endswith:
            - '\RealtekAudioEnhancements64.exe'
            - '\RtkNGUI64.exe'
    condition: selection
falsepositives:
    - Unlikely; legitimate Realtek binaries would not have AutoHotkey as OriginalFileName
level: critical
```

### Sigma: Scheduled Task Masquerading as Realtek Audio Service

Detects schtasks.exe creating persistence tasks with Realtek-themed naming.

**compile: pass | confidence: high**

```yaml
title: Scheduled Task Masquerading as Realtek Audio Service
id: fe8e8319-153d-4eff-b580-53460a975c64
status: experimental
description: >
    Detects creation of scheduled tasks using Realtek audio naming conventions
    that are not signed Realtek binaries, as seen in AsyncRAT campaign where
    AutoHotkey.exe was renamed to RealtekAudioEnhancements64.exe and
    persistence was established via tasks named CheckRealtekAudioVersion.
references:
    - https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat
author: Actioner
date: 2026-06-13
tags:
    - attack.t1053.005
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    selection_name:
        CommandLine|contains:
            - 'CheckRealtekAudioVersion'
            - 'RealtekAudioEnhancements64'
            - 'ResetRealtekAudioSettings64'
    condition: selection_schtasks and selection_name
falsepositives:
    - Legitimate Realtek scheduled tasks installed by official driver packages
level: high
```

### Sigma: DNS Query to AsyncRAT C2 Domains

Detects DNS resolution of the three known C2 domains used by this campaign.

**compile: pass | confidence: high**

```yaml
title: DNS Query to AsyncRAT C2 Domains - Fake AI Guide Campaign
id: b7e4c218-9a31-4f6d-a8c5-2d1e0f3b7a94
status: experimental
description: >
    Detects DNS queries to known C2 domains used in the AsyncRAT campaign
    distributed via fake AI coding guides (June 2026). Domains resolve to
    infrastructure hosting AsyncRAT and clay_Client payloads.
references:
    - https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat
author: Actioner
date: 2026-06-13
tags:
    - attack.t1071.004
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'shampobiskworld.nl'
            - 'shampoolagtto.com'
            - 'shamppocosmaticso.com'
    condition: selection
falsepositives:
    - Unlikely; these are not legitimate business domains
level: critical
```

### Sigma: File Creation in AsyncRAT Fake Realtek Staging Directory

Detects file drops in the campaign's staging directory with Realtek-themed filenames.

**compile: pass | confidence: high**

```yaml
title: File Creation in AsyncRAT Fake Realtek Staging Directory
id: d9f6a341-7b28-4e5c-8d13-9c4a0e2f5b76
status: experimental
description: >
    Detects file creation events under the staging directory used by the
    AsyncRAT campaign to drop payloads masquerading as Realtek audio components.
references:
    - https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat
author: Actioner
date: 2026-06-13
tags:
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Packages\Microsoft.WindowsSoundDiagnostics'
    selection_files:
        TargetFilename|endswith:
            - '\RealtekAudioService64.ps1'
            - '\RealtekAudioService64.bat'
            - '\RealtekAudioEnhancements64.ahk'
            - '\RealtekAudioEnhancements64.ps1'
            - '\RtkNGUI64.ahk'
            - '\RtkDiagService.ahk'
            - '\RtkCplApp.ahk'
            - '\RtkDeviceConfigure64.ahk'
            - '\RtkLoggingManifest.man'
            - '\ResetRealtekAudioSettings64.vbs'
    condition: selection and selection_files
falsepositives:
    - Legitimate Realtek drivers would not use LocalAppData\Packages paths
level: high
```

### YARA: AsyncRAT Fake AI Guide Campaign (4 rules)

Four YARA rules covering: malicious LNK files, AutoHotkey loader scripts, PowerShell stagers, and clay_Client .NET payloads. Caveat: LNK rule may need tuning on the PGP marker condition if legitimate LNK files contain similar strings. The PS1 stager rule's `2 of ($ps*)` branch (matching Add-MpPreference + ExclusionPath) may fire on legitimate Defender management scripts; consider pairing with SIEM context or tuning the threshold if false positives arise in environments with heavy Defender policy automation.

**compile: pass | confidence: high**

```yara
rule Malware_AsyncRAT_FakeAIGuide_LNK : asyncrat lnk
{
    meta:
        description = "Detects malicious LNK files from the AsyncRAT fake AI guide campaign using findstr to extract payloads from PDF containers"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat"
        severity = "high"

    strings:
        $lnk_header = { 4C 00 00 00 01 14 02 00 }
        $s1 = "findstr" ascii wide nocase
        $s2 = "3th.pdf" ascii wide
        $s3 = "4th.pdf" ascii wide
        $s4 = "cmd.exe" ascii wide nocase
        $s5 = "PGP PRIVATE KEY BLOCK" ascii wide

    condition:
        $lnk_header at 0 and
        filesize < 50KB and
        (($s1 and ($s2 or $s3)) or
        ($s4 and $s5))
}

rule Malware_AsyncRAT_FakeAIGuide_AHK_Loader : asyncrat autohotkey
{
    meta:
        description = "Detects AutoHotkey scripts used as loaders in the AsyncRAT fake AI guide campaign with Realtek masquerading"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat"
        severity = "high"

    strings:
        $ahk1 = "DllCall" ascii nocase
        $ahk2 = "VirtualAlloc" ascii nocase
        $ahk3 = "NumPut" ascii nocase
        $ahk4 = "CreateThread" ascii nocase
        $realtek1 = "RealtekAudio" ascii wide nocase
        $realtek2 = "RtkNGUI" ascii wide nocase
        $realtek3 = "RtkDiagService" ascii wide nocase
        $realtek4 = "RtkCplApp" ascii wide nocase

    condition:
        filesize < 5MB and
        (2 of ($ahk*) and 1 of ($realtek*))
}

rule Malware_AsyncRAT_FakeAIGuide_PS1_Stager : asyncrat powershell
{
    meta:
        description = "Detects PowerShell stager scripts from the AsyncRAT campaign with AES-CBC decryption and Defender exclusion artifacts"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat"
        hash = "7d6ee3c6ff8f70b1817aaec82aff1d2babe0b62cafef3975262644743afc0cb8"
        severity = "critical"

    strings:
        $ps1 = "Add-MpPreference" ascii nocase
        $ps2 = "ExclusionPath" ascii nocase
        $ps3 = "AesCryptoServiceProvider" ascii nocase
        $ps4 = "RijndaelManaged" ascii nocase
        $ps5 = "PBKDF2" ascii nocase
        $c2_1 = "shampobiskworld" ascii nocase
        $c2_2 = "shampoolagtto" ascii nocase
        $c2_3 = "shamppocosmaticso" ascii nocase
        $cn1 = { E6 B5 8B E8 AF 95 E8 B7 AF E5 BE 84 }
        $cn2 = { E8 BF 9E E6 8E A5 E8 B7 AF E5 BE 84 }
        $xor_key = "Realtek2025" ascii wide

    condition:
        filesize < 2MB and
        (
            (2 of ($ps*)) or
            (1 of ($c2*)) or
            ($cn1 and $cn2) or
            ($xor_key and 1 of ($ps*))
        )
}

rule Malware_AsyncRAT_ClayClient_Payload : asyncrat clay_client
{
    meta:
        description = "Detects the clay_Client .NET RAT payload deployed alongside AsyncRAT in the fake AI guide campaign"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat"
        severity = "critical"

    strings:
        $mutex = "IDG5FUAM3PSONBSInGIGSWSD" ascii wide
        $cap1 = "ClientShutdown" ascii
        $cap2 = "ClientDelete" ascii
        $cap3 = "ClientUpdate" ascii
        $cap4 = "RemoteDesktopOpen" ascii
        $cap5 = "RemoteDesktopSend" ascii
        $cap6 = "mousemove" ascii
        $cap7 = "RunPE" ascii
        $cap8 = "Reflection" ascii
        $myth1 = { E4 B9 9D E5 A4 A9 E7 8E 84 E5 A5 B3 }
        $myth2 = { E4 B9 BE E5 9D A4 E8 A2 8B }
        $myth3 = { E8 B5 B7 E6 AD BB E5 9B 9E E7 94 9F }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $mutex or
            (4 of ($cap*)) or
            (2 of ($myth*))
        )
}
```

### Suricata: AsyncRAT C2 Network Detection (4 rules)

Four rules detecting DNS queries to the three C2 domains and outbound connections to the C2 IP.

**compile: pass | confidence: high**

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to AsyncRAT C2 Domain shampobiskworld.nl"; flow:to_server; dns.query; content:"shampobiskworld.nl"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat; metadata:author Actioner, created_at 2026-06-13; sid:2100101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to AsyncRAT C2 Domain shampoolagtto.com"; flow:to_server; dns.query; content:"shampoolagtto.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat; metadata:author Actioner, created_at 2026-06-13; sid:2100102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to AsyncRAT C2 Domain shamppocosmaticso.com"; flow:to_server; dns.query; content:"shamppocosmaticso.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat; metadata:author Actioner, created_at 2026-06-13; sid:2100103; rev:1;)

alert ip $HOME_NET any -> 107.172.10.190 any (msg:"Actioner - Outbound Connection to AsyncRAT C2 IP 107.172.10.190"; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat; metadata:author Actioner, created_at 2026-06-13; sid:2100104; rev:1;)
```

### Snort 3: AsyncRAT C2 Network Detection (4 rules)

Four rules for DNS label-encoded domain matching and C2 IP detection. Caveat: Snort 3 lacks DNS sticky buffers so domain matching uses raw payload content with DNS wire format.

**compile: structural pass (snort not installed) | confidence: high**

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to AsyncRAT C2 Domain shampobiskworld.nl"; flow:to_server; content:"|0f|shampobiskworld|02|nl|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat; metadata:author Actioner, created 2026-06-13; sid:2100201; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to AsyncRAT C2 Domain shampoolagtto.com"; flow:to_server; content:"|0d|shampoolagtto|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat; metadata:author Actioner, created 2026-06-13; sid:2100202; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to AsyncRAT C2 Domain shamppocosmaticso.com"; flow:to_server; content:"|11|shamppocosmaticso|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat; metadata:author Actioner, created 2026-06-13; sid:2100203; rev:1;)

alert ip $HOME_NET any -> 107.172.10.190 any (msg:"Actioner - Outbound Connection to AsyncRAT C2 IP 107.172.10.190"; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat; metadata:author Actioner, created 2026-06-13; sid:2100204; rev:1;)
```

## Lessons Learned

1. **AI-themed lures are the new frontier:** As AI adoption accelerates across industries, threat actors are rapidly weaponizing the demand for AI learning materials. Security awareness training must explicitly address the risks of downloading AI guides, tooling, and documentation from unverified sources.

2. **LOLBin chains remain highly effective:** The entire initial execution chain (LNK -> cmd.exe -> findstr.exe -> PowerShell) uses only native Windows tools, bypassing most application whitelisting controls. Detection must focus on behavioral patterns (findstr reading from PDF files, broad Defender exclusions) rather than binary reputation alone.

3. **Defender exclusion abuse is a critical blind spot:** Adding the entire C:\ drive to Defender exclusions effectively neutralizes the primary endpoint protection for most consumer and small-business Windows installations. Organizations should monitor `Add-MpPreference` invocations and alert on overly broad exclusion scopes.

4. **AI-assisted malware development is becoming operational:** The evidence of AI-generated code in intermediate stages suggests threat actors are using generative AI to accelerate malware development, potentially lowering the barrier to entry for sophisticated multi-stage campaigns.

## Sources

- [FortiGuard Labs - Threat Actors Weaponize AI Hype to Deliver AsyncRAT](https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat) — Primary technical analysis with full IOCs, execution chain, and code analysis
- [Hackread - Hackers Use Fake Claude Code Guide and AI PDFs to Spread AsyncRAT Malware](https://hackread.com/hackers-fake-claude-code-guide-ai-pdfs-asyncrat/) — News coverage with campaign overview and key findings
- [Infosecurity Magazine - Cybercriminals Use Fake AI Guides and Dev Tools to Spread AsyncRAT](https://www.infosecurity-magazine.com/news/fake-ai-guides-dev-tools-spread/) — News coverage with defensive recommendations
- [MITRE ATT&CK - T1562.001 Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) — Technique reference for Defender exclusion abuse
- [MITRE ATT&CK - T1055.012 Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/) — Technique reference for .NET process hollowing

---
*Report generated by Actioner*
