# Technical Analysis Report: ScarCruft APT37 NarwhalRAT Campaign (2026-06-16)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-16
Version: 1.0 (DRAFT)

---

## Executive Summary

North Korean state-sponsored threat actor **ScarCruft (APT37)** is conducting an active spear-phishing campaign targeting South Korean individuals and organizations using fraudulent Microsoft Account security alert emails. The campaign delivers a previously undocumented remote access trojan (RAT) dubbed **NarwhalRAT** -- a compiled Python-based multi-stage malware with extensive intelligence collection capabilities including keylogging, screen capture, audio recording, and USB media harvesting.

The attack chain begins with a phishing email impersonating a Microsoft Account security notification warning of "abnormal activity" related to one-time password abuse. The email attachment is a ZIP archive containing a malicious LNK file (disguised as an HWP document). Execution triggers an obfuscated batch-script chain that downloads a legitimate Python runtime, renames it, establishes persistence via a scheduled task, and ultimately loads an encrypted Python bytecode payload directly into memory -- avoiding disk-based detection.

NarwhalRAT employs a dual C2 architecture: compromised Korean web servers serve as primary relays, while the **pCloud** cloud storage API functions as a dead-drop resolver for fallback communication. The malware's working directory (`%APPDATA%\naverwhale`) mimics the legitimate Naver Whale browser to evade casual inspection.

**Viability Gate: PASS** -- The source material from Genians Security Center provides concrete file hashes, C2 infrastructure, file paths, scheduled task names, mutex values, encryption keys, and distinctive command strings suitable for high-confidence detection rule development.

---

## Background: Microsoft Account Security Alert Phishing Lure

ScarCruft (also tracked as APT37, InkySquid, Reaper, Group123, TEMP.Reaper) is a North Korean threat actor operating under the Reconnaissance General Bureau (RGB). The group primarily targets South Korean government entities, journalists, defectors, and cybersecurity professionals.

This campaign leverages the trust associated with Microsoft Account security notifications -- emails that users routinely receive and act upon. The lure text claims abnormal OTP generation activity on the victim's account, creating urgency to open the attached "security advisory" document. The attached ZIP archive contains a malicious LNK file rather than the promised HWP (Hangul Word Processor) document commonly used in South Korean organizations.

---

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-30 09:07:49 UTC | PE compile timestamp of NarwhalRAT payload (18:07:49 KST) |
| 2026-05 to 2026-06 | Active distribution campaign observed |
| 2026-06-15 | Genians Security Center (GSC) publishes technical analysis |
| 2026-06-16 | Public reporting by The Hacker News and multiple outlets |

---

## Root Cause: Spear-Phishing with Weaponized LNK File (T1566.001 / T1204.002)

The initial access vector is a spear-phishing email impersonating the Microsoft Account team. The email warns of unusual one-time password activity and instructs the victim to review an attached security advisory. The attachment is a ZIP archive containing:

1. A **malicious LNK shortcut file** masquerading as an HWP document
2. When executed, the LNK triggers `cmd.exe /k` to launch obfuscated batch scripts
3. A decoy HWP document (`Cybersecurity Advisory Notice (Regarding One-Time Password Abuse).hwp`) is dropped to `%TEMP%` to maintain the deception

---

## Technical Analysis of the Malicious Payload

### Stage 1: LNK Execution and Batch Script Chain

The malicious LNK file invokes `cmd.exe` with the `/k` parameter, executing an obfuscated batch script (`KHjWFcsE.bat`). The batch scripts employ extensive **CMD environment variable substring substitution** (`%variable:~position,1%`) to reconstruct commands character-by-character, evading static signature detection.

Key Stage 1 activities:
- Downloads content to `C:\Users\Public\temp012.zip`
- Uses `curl.exe` (copied and renamed to `C:\Users\<USER>\AppData\Local\TempuARKK20.exe`) to fetch payloads
- Downloads the official `Python-3.10.0-embed-amd64.zip` from legitimate sources
- Extracts Python runtime using `tar` to `C:\Users\Public\AccountPictures\UserInerfacePicture\`
- Renames `Pythonw.exe` to `userscreen.exe`
- Downloads encrypted payload as `config.cat` (Windows security catalog file extension)

### Stage 2: Persistence Establishment

Persistence is achieved through a **Windows Scheduled Task**:
- **Task Name:** `MicrosoftUserInterfacePicturesUpdateTackMachine`
- **Execution Interval:** Every one minute
- **Action:** Executes `userscreen.exe` (renamed Pythonw.exe) with `config.cat` as argument
- **Location:** `C:\Users\Public\AccountPictures\UserInerfacePicture\`

A secondary payload path is also utilized:
- `C:\ProgramData\GoogleDriveUpdateCheck\AccountConfig.cat`

### Stage 3: In-Memory Payload Execution

The `config.cat` file contains AES-128 encrypted Python bytecode:

- **Python Bytecode Magic Bytes:** `6F 0D 0D 0A` (Python 3.10)
- **Encryption:** AES-128 with key derived from hardcoded string `!221aeAescde##2aefseseppl^12` via SHA-256 hash through `CryptDeriveKey()`
- **KDF Salt:** First 16 bytes of Base64-decoded payload
- **Decryption Method:** Counter-based keystream generation with XOR
- **Execution:** Uses Python `ctypes` module to call `VirtualAlloc()` with `PAGE_EXECUTE_READWRITE`, copies decrypted code via `RtlMoveMemory()`, and executes via `ctypes.CFUNCTYPE()`

The loader uses indirect imports via `getattr(__builtins__, "__import__")` to evade import-based detection.

### Stage 4: NarwhalRAT Capabilities

NarwhalRAT establishes a working directory at `%APPDATA%\naverwhale` with Hidden and System file attributes. The directory name mimics the legitimate **Naver Whale** browser popular in South Korea.

**Mutex:** `i5zJH9FL10cVd3sSW9eyWWErPJ`

**RAT Command Set (30+ functions):**

| Command Prefix | Function |
|----------------|----------|
| `startkcap:` / `endkcap:` | Keylogging control |
| `startscap:` / `endscap:` | Screen capture |
| `startscaph:` / `endscaph:` | High-frequency screen capture |
| `startlcap:` / `endlcap:` | Additional capture mode |
| `usb2local:` | USB removable media collection |
| `cmd:` / `cmdadm:` | Remote command execution (standard/admin) |
| `cmserver:` | Change C2 server (main) |
| `caserver:` | Change C2 server (alternate) |
| `cdserver:` | Change C2 server (dead-drop) |
| `chcommpwd:` | Change communication password |

**Data Collection:**
- Keystroke logging
- Screenshot capture (including high-resolution mode)
- Ambient audio recording via microphone
- Directory content enumeration and upload
- Active window title and details collection
- USB removable media data harvesting (via `xcopy /s /e /y /c /q /h /b`)

**Window Filtering Exclusions** (windows not captured):
- `KakaoTalkEdgeWnd`, `KakaoTalkShadowWnd`
- `Program Manager`
- `Microsoft Text Input Application`
- `MSCTFIME UI`
- `ApplicationFrameHost.exe`
- `TextInputHost.exe`

### Anti-Analysis / Evasion

**Hypervisor Detection** via CPUID instruction checking for:
- `VMwareVMware` (VMware)
- `VBoxVBoxVBox` (VirtualBox)
- ` lrpepyh vr` (Parallels Desktop)

### C2 Architecture

**Dual C2 Structure:**

1. **Primary Relays** -- Compromised Korean web servers:
   - `hxxp://www[.]daehoat[.]com/wp-content/uploads/2017/02/member.php`
   - `hxxp://www[.]novel21[.]co[.]kr/data/editor/2110/index.php`

2. **Dead-Drop Resolver** -- pCloud cloud storage API:
   - `api[.]pcloud[.]com` with `folderid` and `auth` parameters
   - Provides resilient fallback C2 channel via legitimate cloud service

**Additional Infrastructure Domains:**
- `crwellfood[.]com`
- `fe01[.]co[.]kr`
- `webhostingkorea[.]com`

---

## Indicators of Compromise (IOCs)

### File Hashes (MD5)

| MD5 Hash | Description |
|----------|-------------|
| `3715092aa00f380cefe8b4d2eddb7d08` | NarwhalRAT component |
| `7cef19f9c4480adac0cd4702ff98f46c` | NarwhalRAT component |
| `7eb9cee1f696727752169f25cf79a338` | NarwhalRAT component |
| `b6b0602310bb2d4360c52685119aac1b` | NarwhalRAT component |

### Network Indicators

**C2 Domains (defanged):**
- `daehoat[.]com`
- `novel21[.]co[.]kr`
- `crwellfood[.]com`
- `fe01[.]co[.]kr`
- `webhostingkorea[.]com`

**C2 IP Addresses (defanged):**
- `121.254.222[.]10`
- `121.254.222[.]80`
- `211.239.157[.]126`
- `218.150.78[.]198`
- `218.150.78[.]231`
- `61.100.9[.]206`

**C2 URLs (defanged):**
- `hxxp://www[.]daehoat[.]com/wp-content/uploads/2017/02/member.php`
- `hxxp://www[.]novel21[.]co[.]kr/data/editor/2110/index.php`

**Dead-Drop Resolver:**
- `api[.]pcloud[.]com` (with `folderid=` and `auth=` parameters)

### Host-Based Indicators

**File Paths:**
- `%APPDATA%\naverwhale\` (working directory, Hidden+System attributes)
- `C:\Users\Public\temp012.zip`
- `C:\Users\Public\AccountPictures\UserInerfacePicture\userscreen.exe`
- `C:\Users\Public\AccountPictures\UserInerfacePicture\config.cat`
- `C:\ProgramData\GoogleDriveUpdateCheck\AccountConfig.cat`
- `%LOCALAPPDATA%\Microsoft\Internet Explorer\<random>.ent`
- `%TEMP%\Cybersecurity Advisory Notice (Regarding One-Time Password Abuse).hwp`
- `%TEMP%\KHjWFcsE.bat`
- `C:\Users\<USER>\AppData\Local\TempuARKK20.exe` (renamed curl.exe)

**Scheduled Task:**
- Name: `MicrosoftUserInterfacePicturesUpdateTackMachine`

**Mutex:**
- `i5zJH9FL10cVd3sSW9eyWWErPJ`

**Decoy Document Metadata:**
- Author field: `Lailey`

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | NarwhalRAT Usage |
|--------|-------------|----------------|------------------|
| Reconnaissance | T1598.002 | Phishing for Information: Spearphishing Link | MS Account-themed phishing emails |
| Initial Access | T1566.002 | Phishing: Spearphishing Attachment | ZIP archive with malicious LNK |
| Execution | T1204.002 | User Execution: Malicious File | Victim opens LNK file |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | cmd.exe /k with obfuscated batch scripts |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell execution policy bypass |
| Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation | CMD environment variable substring substitution |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | AES-128 decryption of Python bytecode |
| Defense Evasion | T1564.001 | Hide Artifacts: Hidden Files and Directories | Hidden+System attributes on naverwhale directory |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | userscreen.exe (renamed Pythonw.exe), naverwhale directory |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | MicrosoftUserInterfacePicturesUpdateTackMachine |
| Collection | T1056.004 | Input Capture: Credential API Hooking / Keylogging | Keystroke logging |
| Collection | T1113 | Screen Capture | Screenshot capture (including high-frequency) |
| Collection | T1123 | Audio Capture | Ambient audio recording |
| Collection | T1025 | Data from Removable Media | USB media harvesting |
| Collection | T1005 | Data from Local System | Directory enumeration and upload |
| Collection | T1074.001 | Data Staged: Local Data Staging | naverwhale working directory |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP to compromised Korean web servers |
| Command and Control | T1102.001 | Web Service: Dead Drop Resolver | pCloud API as fallback C2 |
| Command and Control | T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-128 encrypted C2 communication |
| Command and Control | T1105 | Ingress Tool Transfer | Download of Python runtime and payloads |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Data exfiltration through C2 relays |

---

## Impact Assessment

**Severity: HIGH**

- **Targeted Sector:** South Korean government, media, cybersecurity professionals, and North Korean defectors
- **Data at Risk:** Keystrokes (including credentials), screen content, audio conversations, USB documents, system information
- **Attribution Confidence:** HIGH -- Campaign shares code-level similarities with prior ScarCruft Python-based operations, including LNK delivery mechanisms and scheduled task naming conventions (e.g., `MicrosoftMusicLibrariesPackageTaskMachine` from related campaigns)
- **Campaign Status:** Active as of June 2026
- **Geographic Scope:** Primarily South Korea, with potential expansion to other targets of North Korean intelligence interest

---

## Detection & Remediation

### Immediate Response Actions

1. **Search for scheduled task** `MicrosoftUserInterfacePicturesUpdateTackMachine` across all endpoints
2. **Scan for mutex** `i5zJH9FL10cVd3sSW9eyWWErPJ` in running processes
3. **Check for** `%APPDATA%\naverwhale\` directory (with Hidden+System attributes) -- distinguish from legitimate Naver Whale browser installations
4. **Check for** `C:\Users\Public\AccountPictures\UserInerfacePicture\` directory containing `userscreen.exe` and `config.cat`
5. **Block C2 domains and IPs** listed in the IOC section at the network perimeter
6. **Search proxy/DNS logs** for connections to the listed C2 infrastructure
7. **Search email gateway logs** for Microsoft Account-themed phishing with ZIP attachments containing LNK files

### Remediation

1. Isolate affected hosts and preserve forensic evidence
2. Remove the scheduled task and all associated files
3. Reset credentials for any accounts accessed from compromised hosts
4. Review USB device connection logs for data exfiltration assessment
5. Monitor for reinfection attempts via alternative C2 channels (pCloud dead-drop)

---

## Detection Rules

### Sigma Rules

All Sigma rules validated with `sigma check` (0 errors, 0 condition errors, 0 issues) and successfully converted to Splunk SPL and CrowdStrike LogScale query formats.

#### Rule 1: Suspicious LNK Spawning Batch Scripts

```yaml
title: ScarCruft NarwhalRAT - Suspicious LNK Spawning PowerShell and Batch Scripts
id: a1f3c8e2-7b4d-4a9e-b6c1-2d5e8f0a3b7c
status: experimental
description: >
  Detects the initial execution chain where a malicious LNK file spawns
  PowerShell or cmd.exe to execute obfuscated batch scripts, consistent
  with ScarCruft APT37 NarwhalRAT delivery.
references:
    - https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat
    - https://thehackernews.com/2026/06/fake-microsoft-alerts-used-to-deploy.html
author: Actioner
date: 2026-06-16
tags:
    - attack.execution
    - attack.t1204.002
    - attack.t1059.001
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\explorer.exe'
    selection_child:
        CommandLine|contains|all:
            - 'cmd'
            - '/k'
        CommandLine|contains:
            - 'KHjWFcsE.bat'
            - '%TEMP%'
            - 'temp012.zip'
    condition: selection_parent and selection_child
falsepositives:
    - Unlikely in legitimate environments
level: high
```

**Compile Status:** PASS (sigma check: 0 errors, 0 issues) | **Confidence:** HIGH

---

#### Rule 2: Persistence via Scheduled Task

```yaml
title: ScarCruft NarwhalRAT - Persistence via Scheduled Task
id: b2e4d9f3-8c5e-4b0a-c7d2-3e6f9a1b4c8d
status: experimental
description: >
  Detects creation of scheduled task named
  MicrosoftUserInterfacePicturesUpdateTackMachine used by NarwhalRAT
  for persistence, executing renamed Python at one-minute intervals.
references:
    - https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat
    - https://thehackernews.com/2026/06/fake-microsoft-alerts-used-to-deploy.html
author: Actioner
date: 2026-06-16
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: 'MicrosoftUserInterfacePicturesUpdateTackMachine'
    condition: selection_schtasks
falsepositives:
    - None expected - highly specific task name
level: critical
```

**Compile Status:** PASS (sigma check: 0 errors, 0 issues) | **Confidence:** CRITICAL/HIGH

---

#### Rule 3: Staging Directory and Renamed Python Execution

```yaml
title: ScarCruft NarwhalRAT - Staging Directory and Renamed Python Execution
id: c3f5ea04-9d6f-4c1b-d8e3-4f7a0b2c5d9e
status: experimental
description: >
  Detects execution of renamed Python binary (userscreen.exe) from the
  NarwhalRAT staging path under Public\AccountPictures, or creation
  of files in the naverwhale AppData directory.
references:
    - https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat
    - https://thehackernews.com/2026/06/fake-microsoft-alerts-used-to-deploy.html
author: Actioner
date: 2026-06-16
tags:
    - attack.execution
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_userscreen:
        Image|endswith: '\userscreen.exe'
        Image|contains: '\AccountPictures\UserInerfacePicture\'
    selection_config_cat:
        CommandLine|contains|all:
            - 'userscreen.exe'
            - 'config.cat'
    condition: selection_userscreen or selection_config_cat
falsepositives:
    - None expected - specific file path and binary name combination
level: critical
```

**Compile Status:** PASS (sigma check: 0 errors, 0 issues) | **Confidence:** CRITICAL/HIGH

---

#### Rule 4: pCloud Dead Drop Resolver Communication

```yaml
title: ScarCruft NarwhalRAT - pCloud Dead Drop Resolver Communication
id: d4a6fb15-ae70-4d2c-e9f4-5a8b1c3d6e0f
status: experimental
description: >
  Detects network connections or process command lines referencing pCloud
  API endpoints with folderid and auth parameters, consistent with
  NarwhalRAT dead drop resolver C2 communication.
references:
    - https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat
    - https://thehackernews.com/2026/06/fake-microsoft-alerts-used-to-deploy.html
author: Actioner
date: 2026-06-16
tags:
    - attack.command-and-control
    - attack.t1102.001
    - attack.t1071.001
logsource:
    category: proxy
    product: windows
detection:
    selection_pcloud:
        c-uri|contains:
            - 'api.pcloud.com'
        c-uri|contains|all:
            - 'folderid'
            - 'auth'
    condition: selection_pcloud
falsepositives:
    - Legitimate pCloud usage - requires tuning for environments using pCloud
level: medium
```

**Compile Status:** PASS (sigma check: 0 errors, 0 issues) | **Confidence:** MEDIUM (legitimate pCloud use possible)

---

#### Rule 5: Known C2 Domain Communication

```yaml
title: ScarCruft NarwhalRAT - Known C2 Domain Communication
id: e5b7ac26-bf81-4e3d-fa05-6b9c2d4e7f1a
status: experimental
description: >
  Detects DNS queries or HTTP connections to known NarwhalRAT C2 relay
  domains used by ScarCruft APT37.
references:
    - https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat
    - https://thehackernews.com/2026/06/fake-microsoft-alerts-used-to-deploy.html
author: Actioner
date: 2026-06-16
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: dns
    product: windows
detection:
    selection_domains:
        query|contains:
            - 'daehoat.com'
            - 'novel21.co.kr'
            - 'crwellfood.com'
            - 'fe01.co.kr'
    condition: selection_domains
falsepositives:
    - Legitimate access to these Korean websites (unlikely outside Korea)
level: high
```

**Compile Status:** PASS (sigma check: 0 errors, 0 issues) | **Confidence:** HIGH

---

#### Rule 6: Naverwhale Working Directory Creation

```yaml
title: ScarCruft NarwhalRAT - Naverwhale Working Directory Creation
id: f6c8bd37-ca92-4f4e-ab16-7cad3e5f8a2b
status: experimental
description: >
  Detects file operations in the AppData naverwhale directory used by
  NarwhalRAT to stage harvested data, mimicking the legitimate Naver
  Whale browser.
references:
    - https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat
    - https://thehackernews.com/2026/06/fake-microsoft-alerts-used-to-deploy.html
author: Actioner
date: 2026-06-16
tags:
    - attack.collection
    - attack.t1074.001
    - attack.t1564.001
logsource:
    category: file_event
    product: windows
detection:
    selection_naverwhale:
        TargetFilename|contains: '\AppData\Roaming\naverwhale\'
    filter_legitimate:
        Image|contains: '\Naver\Whale\'
    condition: selection_naverwhale and not filter_legitimate
falsepositives:
    - Legitimate Naver Whale browser portable installations using non-standard paths
level: high
```

**Compile Status:** PASS (sigma check: 0 errors, 0 issues) | **Confidence:** HIGH

---

#### Rule 7: CMD Environment Variable Substring Obfuscation

```yaml
title: ScarCruft NarwhalRAT - CMD Environment Variable Substring Obfuscation
id: a7d9ce48-db03-4a5f-bc27-8dbe4f6a9b3c
status: experimental
description: >
  Detects heavy use of CMD environment variable substring substitution
  technique used by NarwhalRAT batch scripts for command obfuscation.
references:
    - https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat
    - https://thehackernews.com/2026/06/fake-microsoft-alerts-used-to-deploy.html
author: Actioner
date: 2026-06-16
tags:
    - attack.t1027.010
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\cmd.exe'
    selection_obfuscation:
        CommandLine|re: '(%\w+:~\d+,\d+%){5,}'
    condition: selection_cmd and selection_obfuscation
falsepositives:
    - Rare legitimate scripts using extensive environment variable substring operations
level: high
```

**Compile Status:** PASS (sigma check: 0 errors, 0 issues) | **Confidence:** HIGH

---

### YARA Rules

#### Rule 1: NarwhalRAT Python Payload Detection

```yara
rule APT37_NarwhalRAT_Python_Payload
{
    meta:
        description = "Detects NarwhalRAT compiled Python payload used by ScarCruft APT37"
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat"
        hash_md5_1 = "3715092aa00f380cefe8b4d2eddb7d08"
        hash_md5_2 = "7cef19f9c4480adac0cd4702ff98f46c"
        hash_md5_3 = "7eb9cee1f696727752169f25cf79a338"
        hash_md5_4 = "b6b0602310bb2d4360c52685119aac1b"
        tlp = "WHITE"
        confidence = "high"

    strings:
        $cmd_startkcap = "startkcap:" ascii
        $cmd_endkcap = "endkcap:" ascii
        $cmd_startscap = "startscap:" ascii
        $cmd_endscap = "endscap:" ascii
        $cmd_startscaph = "startscaph:" ascii
        $cmd_endscaph = "endscaph:" ascii
        $cmd_startlcap = "startlcap:" ascii
        $cmd_endlcap = "endlcap:" ascii
        $cmd_usb2local = "usb2local:" ascii
        $cmd_cmserver = "cmserver:" ascii
        $cmd_caserver = "caserver:" ascii
        $cmd_cdserver = "cdserver:" ascii
        $cmd_chcommpwd = "chcommpwd:" ascii
        $cmd_cmdadm = "cmdadm:" ascii
        $dir_naverwhale = "naverwhale" ascii wide
        $mutex = "i5zJH9FL10cVd3sSW9eyWWErPJ" ascii wide
        $aes_key = "!221aeAescde##2aefseseppl^12" ascii
        $pcloud_folderid = "folderid=" ascii
        $pcloud_auth = "auth=" ascii

    condition:
        (3 of ($cmd_*)) or
        ($mutex) or
        ($aes_key) or
        ($dir_naverwhale and 2 of ($cmd_*)) or
        (5 of them)
}
```

**Compile Status:** PASS (yarac: compiled successfully) | **Confidence:** HIGH

---

#### Rule 2: NarwhalRAT LNK Dropper Detection

```yara
rule APT37_NarwhalRAT_LNK_Dropper
{
    meta:
        description = "Detects malicious LNK files used to deliver NarwhalRAT by ScarCruft APT37"
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat"
        tlp = "WHITE"
        confidence = "high"

    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $cmd_pattern1 = "cmd /k" ascii nocase
        $bat_name = "KHjWFcsE.bat" ascii
        $temp_zip = "temp012.zip" ascii
        $task_name = "MicrosoftUserInterfacePicturesUpdateTackMachine" ascii
        $userscreen = "userscreen.exe" ascii
        $config_cat = "config.cat" ascii
        $decoy_hwp = "Cybersecurity Advisory Notice" ascii wide
        $path_public = "C:\\Users\\Public\\AccountPictures\\UserInerfacePicture" ascii nocase
        $path_appdata = "naverwhale" ascii

    condition:
        $lnk_magic at 0 and
        (
            ($bat_name) or
            ($temp_zip and $cmd_pattern1) or
            ($task_name) or
            ($userscreen and $config_cat) or
            ($path_public) or
            (3 of them)
        )
}
```

**Compile Status:** PASS (yarac: compiled successfully) | **Confidence:** HIGH

---

#### Rule 3: NarwhalRAT Encrypted Config/Payload Detection

```yara
rule APT37_NarwhalRAT_Config_CAT
{
    meta:
        description = "Detects NarwhalRAT config.cat payload file containing encrypted Python bytecode"
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat"
        tlp = "WHITE"
        confidence = "medium"

    strings:
        $pyc_magic = { 6F 0D 0D 0A }
        $code_obj = { E3 }
        $import1 = "__import__" ascii
        $import2 = "getattr" ascii
        $import3 = "__builtins__" ascii
        $import4 = "ctypes" ascii
        $import5 = "CFUNCTYPE" ascii
        $api_virtualalloc = "VirtualAlloc" ascii
        $api_rtlmovemem = "RtlMoveMemory" ascii
        $api_createmutex = "CreateMutexW" ascii

    condition:
        ($pyc_magic at 0 and $code_obj and 2 of ($import*)) or
        (3 of ($api_*) and 2 of ($import*)) or
        ($import3 and $import4 and $import5 and 2 of ($api_*))
}
```

**Compile Status:** PASS (yarac: compiled with performance warning on $code_obj -- acceptable) | **Confidence:** MEDIUM

---

### Snort/Suricata Rules

> **Note:** Snort/Suricata is not installed in the validation environment. All network rules below are structurally validated only.

#### Rule 1: C2 Relay - daehoat.com

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"APT37 NarwhalRAT C2 - daehoat.com relay"; flow:established,to_server; http.host; content:"daehoat.com"; http.uri; content:"/wp-content/uploads/2017/02/member.php"; classtype:trojan-activity; sid:2026061601; rev:1; metadata:created_at 2026_06_16, confidence high;)
```

**Compile Status:** UNCOMPILED (structural check only) | **Confidence:** HIGH

#### Rule 2: C2 Relay - novel21.co.kr

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"APT37 NarwhalRAT C2 - novel21.co.kr relay"; flow:established,to_server; http.host; content:"novel21.co.kr"; http.uri; content:"/data/editor/2110/index.php"; classtype:trojan-activity; sid:2026061602; rev:1; metadata:created_at 2026_06_16, confidence high;)
```

**Compile Status:** UNCOMPILED (structural check only) | **Confidence:** HIGH

#### Rule 3: pCloud Dead Drop Resolver

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"APT37 NarwhalRAT pCloud Dead Drop Resolver"; flow:established,to_server; http.host; content:"api.pcloud.com"; http.uri; content:"folderid"; http.uri; content:"auth"; classtype:trojan-activity; sid:2026061603; rev:1; metadata:created_at 2026_06_16, confidence medium;)
```

**Compile Status:** UNCOMPILED (structural check only) | **Confidence:** MEDIUM

#### Rule 4: Known C2 IP Communication

```
alert ip $HOME_NET any -> [121.254.222.10,121.254.222.80,211.239.157.126,218.150.78.198,218.150.78.231,61.100.9.206] any (msg:"APT37 NarwhalRAT Known C2 IP Communication"; classtype:trojan-activity; sid:2026061604; rev:1; metadata:created_at 2026_06_16, confidence high;)
```

**Compile Status:** UNCOMPILED (structural check only) | **Confidence:** HIGH

#### Rules 5-8: C2 DNS Lookups

```
alert dns $HOME_NET any -> any any (msg:"APT37 NarwhalRAT C2 DNS Lookup - daehoat.com"; dns.query; content:"daehoat.com"; nocase; classtype:trojan-activity; sid:2026061605; rev:1;)
alert dns $HOME_NET any -> any any (msg:"APT37 NarwhalRAT C2 DNS Lookup - novel21.co.kr"; dns.query; content:"novel21.co.kr"; nocase; classtype:trojan-activity; sid:2026061606; rev:1;)
alert dns $HOME_NET any -> any any (msg:"APT37 NarwhalRAT C2 DNS Lookup - crwellfood.com"; dns.query; content:"crwellfood.com"; nocase; classtype:trojan-activity; sid:2026061607; rev:1;)
alert dns $HOME_NET any -> any any (msg:"APT37 NarwhalRAT C2 DNS Lookup - fe01.co.kr"; dns.query; content:"fe01.co.kr"; nocase; classtype:trojan-activity; sid:2026061608; rev:1;)
```

**Compile Status:** UNCOMPILED (structural check only) | **Confidence:** HIGH

---

## Lessons Learned

1. **Email security controls must be tuned to detect LNK files within ZIP attachments** -- even when the email appears to originate from a trusted brand like Microsoft. Organizations should consider blocking or quarantining ZIP archives containing LNK shortcut files at the email gateway.

2. **Living-off-the-land techniques with legitimate Python runtimes** pose a significant detection challenge. Security teams should monitor for unexpected Python installations in non-standard directories (e.g., `C:\Users\Public\AccountPictures\`) and renamed Python binaries.

3. **Scheduled task naming conventions** can serve as a detection anchor. ScarCruft uses long, Microsoft-mimicking names (`MicrosoftUserInterfacePicturesUpdateTackMachine`) -- baseline legitimate scheduled tasks and alert on new tasks matching this pattern.

4. **Dual C2 architectures using legitimate cloud services** (pCloud in this case) as dead-drop resolvers require defenders to implement behavior-based detection that correlates process creation, network activity, and file system events rather than relying solely on IOC-based blocking.

5. **CMD environment variable substring substitution** is an increasingly common obfuscation technique among APT groups. EDR solutions should be configured to log and alert on command lines exhibiting heavy use of the `%variable:~offset,length%` pattern.

6. **Regional brand mimicry** (using "naverwhale" to mimic Naver Whale browser) demonstrates threat actors' targeting sophistication. Defense teams in targeted regions should be aware of locally popular applications that may be impersonated.

---

## Sources

- [Genians Security Center - Analysis of APT37 NarwhalRAT Leveraging MS-Themed Phishing and Dead-drop C2](https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat) -- Primary technical source
- [The Hacker News - Fake Microsoft Alerts Used to Deploy North Korean NarwhalRAT Malware](https://thehackernews.com/2026/06/fake-microsoft-alerts-used-to-deploy.html)
- [GBHackers - APT37 Hackers Use NarwhalRAT Malware With MS-Themed Phishing and Dead-Drop C2](https://gbhackers.com/apt37-hackers-use-narwhalrat-malware/)
- [CyberPress - Hackers Use Microsoft Account Security Alert Lures to Deliver NarwhalRAT Malware](https://cyberpress.org/microsoft-alert-spreads-narwhalrat/)
- [Seqrite - Operation HanKook Phantom: North Korean APT37 targeting South Korea](https://www.seqrite.com/blog/operation-hankook-phantom-north-korean-apt37-targeting-south-korea/)
- [MITRE ATT&CK - Group G0067: APT37](https://attack.mitre.org/groups/G0067/)
