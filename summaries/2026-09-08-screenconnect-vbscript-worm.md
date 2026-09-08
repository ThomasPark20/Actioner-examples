# Technical Analysis Report: ScreenConnect VBScript Worm Campaign (2026-09-08)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-09-08
Version: 1.0 (DRAFT)

## Executive Summary

On 2026-09-07, Huntress disclosed a worm-like campaign abusing **ConnectWise ScreenConnect** remote management software. Threat actors deliver **rogue ScreenConnect client installers** via social engineering (Quick Assist tech-support scams, phishing, fake Geek Squad refund lures) and then use ScreenConnect's built-in file-transfer mechanism to automatically deploy a **four-stage VBScript payload chain** (`1.vbs` through `4.vbs`) to connected hosts. The campaign is self-propagating: modified ScreenConnect clients monitor for newly connected Host sessions and queue the infection payload via ScreenConnect's file-transfer protocol with the action set to "Run," creating **worm-like lateral spread** across all systems managed through the compromised ScreenConnect instance.

The VBScript chain profiles the target (RAM, installed security products, existing ScreenConnect presence), downloads encrypted payloads from **Dropbox** staging, and decrypts them using **XOR (single-byte key 90)** and **AES-128-CBC/PKCS#7**. Depending on the host profile, the final payload delivers one of three variants: a **user-level ScreenConnect backdoor** (state 000/001), **UAC bypass tooling with persistence** (state 010), or **tunneling utilities with an XMRig cryptocurrency miner** (state 011). Persistence is achieved through a **Registry Run key** (`WindowsServiceHost`) pointing to a VBScript file. The `PyTorchFix.ps1` PowerShell payload performs **AMSI bypass**, **Defender exclusion**, **UAC bypass via ms-settings protocol handler hijack**, and installs a concealed ScreenConnect instance with ID `7a4d7d66502d4260`. C2 infrastructure spans five IP addresses across domains `tele-sync[.]opik[.]net`, `borertors92[.]anondns[.]net`, and `homehub[.]opik[.]net`.

ConnectWise issued an advisory on 2026-09-03 acknowledging the file-transfer behavior issue and committed to a CVE and patch within one week.

Severity: **High** (active, self-propagating worm leveraging legitimate RMM infrastructure with multi-stage payloads).

## Background: ConnectWise ScreenConnect

ConnectWise ScreenConnect (formerly ConnectWise Control) is a widely-used remote monitoring and management (RMM) tool deployed in both cloud-hosted and on-premises configurations. It provides remote access, support sessions, and file-transfer capabilities between technicians and managed endpoints. The file-transfer feature allows transferring files to connected hosts and executing them — a capability that this campaign weaponizes for self-propagation. ScreenConnect is heavily used by MSPs (Managed Service Providers), making it a high-value target for supply-chain and lateral-movement attacks.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026 (exact date unclear) | Initial social engineering campaigns begin: Quick Assist tech-support scam, phishing-delivered MSI installers, fake Geek Squad refund lures |
| 2026-09-02 | Dropbox staging URL observed to go offline |
| 2026-09-03 | ConnectWise issues security advisory acknowledging file-transfer behavior issue; recommends disabling TransferFiles permissions |
| 2026-09-07 | Huntress publishes detailed technical analysis; The Hacker News and SecurityWeek report on the campaign |
| 2026-09-08 | This report published |

## Root Cause: ScreenConnect File-Transfer Behavior Abuse

The attack exploits ScreenConnect's built-in file-transfer mechanism, which allows a connected client to transfer files to Host sessions and set their execution action to "Run." The rogue ScreenConnect client monitors the `EndPointStatusMessage.Connections` collection to detect newly connected Host sessions and automatically queues the VBScript infection chain for each new host, creating self-propagating worm behavior. This is not a traditional software vulnerability but an **abuse of legitimate product functionality** — the file-transfer feature works as designed but lacks sufficient guardrails against automated, programmatic abuse by a malicious client.

## Technical Analysis of the Malicious Payload

### 1. Initial Access — Social Engineering & Rogue ScreenConnect Client

Three initial access vectors were observed:
- **Quick Assist tech-support scam**: Victim is socially engineered into launching Windows Quick Assist, then directed to install a rogue ScreenConnect client
- **Phishing-delivered MSI installer**: `ScreenConnect.ClientSetup.msi` sent via phishing email
- **Fake Geek Squad refund form lure**: Victims directed to a fake refund page that delivers the rogue client

The rogue ScreenConnect client connects back to attacker-controlled infrastructure and immediately begins spawning `wscript.exe` child processes to execute the VBScript payload chain.

### 2. Stage 1 — Host Profiling (1.vbs)

**SHA256:** `08bc4e82883eb42fc5219b206555b7a02a879860c76b4a12b2f82a64f6cc9020`

The first VBScript performs host reconnaissance:
- Checks if ScreenConnect is already installed (if present, writes "abort" and halts)
- Enumerates installed security products: Cisco AMP, CrowdStrike, Huntress, Malwarebytes, SentinelOne, Sophos, Symantec Endpoint Protection, Microsoft Defender
- Checks system resources (RAM > 5 GB threshold)
- Generates a **three-bit state variable** written to `%TEMP%\value.txt`:
  - **Bit 1**: 0 if ScreenConnect absent; writes "abort" if present
  - **Bit 2**: 0 if enterprise EDR detected; 1 if only Microsoft Defender
  - **Bit 3**: 1 if no ScreenConnect in Program Files

### 3. Stage 2 — Payload Retrieval Configuration (2.vbs)

**SHA256:** `de3b6836a88ae4b117e3b6de0e9cce3cd56a2b27b462d69e50c2fcac4089a457` and `19a3534da9f60c726be426ec5cc2b72c2d1254fefa0782bd2f08ef08117f3260` (two variants observed)

Waits for `value.txt` to be created, checks for the "abort" keyword, then:
- Downloads a file from **Dropbox** (specific URLs not disclosed; observed offline as of 2026-09-02)
- Decodes the content from **Base64** encoding
- Performs a **single-byte XOR** with key **90** (decimal)
- Writes the decoded output to `%TEMP%\map.txt`

The `map.txt` format: `"011=http://url.com/combo.enc|AES_KEY"` — state variable mapped to payload URL and AES decryption key, pipe-delimited.

### 4. Stage 3 — Encrypted Payload Download (3.vbs)

**SHA256:** `110fffc85370bb7cc60fa023447165c7e99175473d76bc5ffb2abecaa3a41d66`

Monitors `map.txt`, matches the system state variable to the appropriate payload variant:
- **000/001** → `user.enc` (user-level ScreenConnect backdoor)
- **010** → `acc.enc` (UAC bypass tooling and persistence mechanisms)
- **011** → `combo.enc` (tunneling utilities and XMRig cryptocurrency miner)

Downloads the encrypted payload from the Dropbox URL specified in `map.txt` and writes it to `%TEMP%\out.enc`.

### 5. Stage 4 — Decryption & Execution (4.vbs)

**SHA256:** `de89d560fc8302c778d88e3938327b240fa0db9a64fc1d5643067eedcbd2aede`

Windows Defender detection: `Trojan:Script/Wacatac.H!ml`

Waits for `out.enc`, then:
- Creates `%TEMP%\runner.ps1` — a PowerShell script that decrypts `out.enc` using **AES-CBC with PKCS#7 padding**; the first 16 bytes of the encrypted file serve as the **AES IV**, and the key comes from `map.txt`
- Executes `runner.ps1`, which decrypts and launches `PyTorchFix.ps1`
- Terminates all `wscript.exe` and `cscript.exe` processes
- Deletes the staging directory

### 6. Final Payload — PyTorchFix.ps1

The second-stage PowerShell payload varies by state:

**State 010 (acc.enc) — UAC Bypass & Persistence:**
- Inline C# compilation of `Password.exe` for **UAC bypass** via hijacked `ms-settings:` protocol handler and `ComputerDefaults.exe`
- **AMSI bypass**: Sets `AmsiUtils.amsiInitFailed = true`
- **Defender exclusion**: Adds all `C:\Users` to Windows Defender exclusion paths via `Add-MpPreference -ExclusionPath`
- **Power plan configuration**: Enables high-performance, disables sleep/hibernation
- Installs a **concealed ScreenConnect instance** with ID `7a4d7d66502d4260`
- Removes the Windows Registry Uninstall entry for ScreenConnect
- Applies restrictive service security descriptor to hide the ScreenConnect service

**State 011 (combo.enc) — Mining & Tunneling:**
- All of the above, plus:
- Disables Microsoft Defender reporting and notifications
- Disables **Hypervisor-Protected Code Integrity (HVCI)**
- Deploys `Themes.exe` (masqueraded **wstunnel** tunneling utility) connecting to `homehub[.]opik[.]net:443`
- Deploys `SearchIndex.exe` (masqueraded **XMRig** cryptocurrency miner)
- Drops `svcdrv64.sys` (vulnerable **WinRing0** driver for ring-0 access)

### 7. Persistence

- **Registry Run Key**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `WindowsServiceHost` → points to `WindowsServiceHost.vbs` in user's AppData directory
- **WindowsServiceHost.vbs** (SHA256: `ffd6d23f579571cc61936145791975da78b6ae914d780a9447a8f53c3688a0de`) executes `WindowsServiceHost.bat`

### 8. C2 Infrastructure

| Domain/IP | Port | Role |
|-----------|------|------|
| tele-sync[.]opik[.]net (45[.]13[.]237[.]190) | — | Primary C2 |
| borertors92[.]anondns[.]net | — | Secondary C2 |
| homehub[.]opik[.]net | 443 | Wstunnel tunneling endpoint |
| 131[.]123[.]40[.]98 | 8041 | C2 infrastructure |
| 146[.]59[.]55[.]107 | — | C2 infrastructure |
| 45[.]32[.]192[.]150 | — | C2 infrastructure |
| 15[.]204[.]185[.]204 | — | C2 infrastructure |

### 9. Worm Propagation Mechanism

The modified ScreenConnect client monitors the `EndPointStatusMessage.Connections` collection for newly connected Host sessions. When a new host appears, the client:
1. Packages the VBScript stagers (1.vbs through 4.vbs) into a ScreenConnect file-transfer message
2. Sets the transfer action to "Run"
3. Queues the payload for the connected Host
4. The Host session automatically executes the received VBScript, restarting the infection chain

This creates fully automated worm-like propagation across all systems accessible through the compromised ScreenConnect instance.

### 10. Anti-Forensics / Evasion Techniques

- Stage 4 terminates all `wscript.exe`/`cscript.exe` processes after payload execution
- Staging directory and temporary files are deleted after execution
- ScreenConnect Uninstall registry entry removed to hide installation
- Restrictive service security descriptor applied to ScreenConnect service
- AMSI bypass prevents PowerShell script inspection
- Defender exclusion path covers `C:\Users` entirely
- HVCI disabled to facilitate ring-0 driver loading
- Secondary RMM tool (UltraViewer) deployed as backup access

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs use `hxxps://` or `hxxp://`; domains/IPs use `[.]`; hashes/paths/filenames are not defanged.

### File System

| File | Hash (SHA256) | Description |
|------|---------------|-------------|
| 1.vbs | `08bc4e82883eb42fc5219b206555b7a02a879860c76b4a12b2f82a64f6cc9020` | Stage 1 — host profiler |
| 2.vbs (variant 1) | `de3b6836a88ae4b117e3b6de0e9cce3cd56a2b27b462d69e50c2fcac4089a457` | Stage 2 — Dropbox downloader |
| 2.vbs (variant 2) | `19a3534da9f60c726be426ec5cc2b72c2d1254fefa0782bd2f08ef08117f3260` | Stage 2 — Dropbox downloader (alternate) |
| 3.vbs | `110fffc85370bb7cc60fa023447165c7e99175473d76bc5ffb2abecaa3a41d66` | Stage 3 — payload selector/downloader |
| 4.vbs | `de89d560fc8302c778d88e3938327b240fa0db9a64fc1d5643067eedcbd2aede` | Stage 4 — decryptor/launcher |
| WindowsServiceHost.vbs | `ffd6d23f579571cc61936145791975da78b6ae914d780a9447a8f53c3688a0de` | Persistence VBScript |

### File Paths

| Path | Description |
|------|-------------|
| `%TEMP%\value.txt` | State variable (three-bit host profile) |
| `%TEMP%\map.txt` | Payload configuration (state→URL\|key mapping) |
| `%TEMP%\out.enc` | Downloaded encrypted payload |
| `%TEMP%\runner.ps1` | PowerShell AES decryption script |
| `%APPDATA%\Microsoft\Windows\Templates\Classic\sys_cache.zip` | Final staged payload archive |
| `C:\Users\Public\Libraries\Default\Lib\Lib1` | Secondary staging directory |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | tele-sync[.]opik[.]net | Primary C2 domain |
| Domain | borertors92[.]anondns[.]net | Secondary C2 domain |
| Domain | homehub[.]opik[.]net | Wstunnel tunneling endpoint (port 443) |
| IP | 45[.]13[.]237[.]190 | C2 — resolves from tele-sync[.]opik[.]net |
| IP | 131[.]123[.]40[.]98:8041 | C2 infrastructure |
| IP | 146[.]59[.]55[.]107 | C2 infrastructure |
| IP | 45[.]32[.]192[.]150 | C2 infrastructure |
| IP | 15[.]204[.]185[.]204 | C2 infrastructure |

### Registry

| Key | Value | Data | Description |
|-----|-------|------|-------------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `WindowsServiceHost` | Path to `WindowsServiceHost.vbs` | Persistence |

### Behavioral

- `ScreenConnect.ClientService.exe` or `ScreenConnect.WindowsClient.exe` spawning `wscript.exe`/`cscript.exe` child processes
- Sequential creation of `value.txt`, `map.txt`, `out.enc`, `runner.ps1` in `%TEMP%`
- PowerShell execution of `PyTorchFix.ps1` with AMSI bypass patterns
- Masqueraded binaries `Themes.exe` (wstunnel) and `SearchIndex.exe` (XMRig) in `C:\Users\Public\Libraries\Default\Lib\`
- ScreenConnect instance ID `7a4d7d66502d4260` in concealed installation
- UAC bypass via `ms-settings:` protocol handler and `ComputerDefaults.exe`
- Defender exclusion path addition covering `C:\Users`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.002 | Phishing: Spearphishing Link | Phishing emails delivering rogue ScreenConnect MSI installer |
| T1204.002 | User Execution: Malicious File | Victim executes rogue ScreenConnect.ClientSetup.msi |
| T1219 | Remote Access Software | Abuse of ScreenConnect RMM for C2 and lateral movement |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | Four-stage VBScript payload chain (1.vbs-4.vbs) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | runner.ps1 and PyTorchFix.ps1 execution |
| T1027 | Obfuscated Files or Information | Base64 + XOR encoding (key 90) for map.txt; AES-CBC encryption for payloads |
| T1140 | Deobfuscate/Decode Files or Information | Runtime decryption of out.enc using AES-CBC/PKCS#7 |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | WindowsServiceHost Run key persistence |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | ms-settings protocol handler hijack via ComputerDefaults.exe |
| T1562.001 | Impair Defenses: Disable or Modify Tools | AMSI bypass, Defender exclusion paths, HVCI disable |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Themes.exe (wstunnel), SearchIndex.exe (XMRig) |
| T1570 | Lateral Tool Transfer | ScreenConnect file-transfer mechanism propagates VBScript chain |
| T1105 | Ingress Tool Transfer | Payloads downloaded from Dropbox staging |
| T1496 | Resource Hijacking | XMRig cryptocurrency miner deployment |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over HTTPS (homehub[.]opik[.]net:443) |

## Impact Assessment

The campaign's worm-like propagation mechanism makes it particularly dangerous for organizations using ScreenConnect for managed services. A single compromised endpoint can automatically infect all other hosts connected through the same ScreenConnect instance, potentially compromising entire MSP customer bases. The three-variant payload system (backdoor, persistence/escalation, mining/tunneling) indicates a sophisticated operator adapting the final payload to each target's defensive posture. The use of legitimate Dropbox for payload staging and ScreenConnect's own file-transfer mechanism for propagation makes network-based detection challenging.

## Detection & Remediation

### Immediate Detection

Check for the persistence mechanism:
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsServiceHost
```

Check for staging files:
```cmd
dir %TEMP%\value.txt %TEMP%\map.txt %TEMP%\out.enc %TEMP%\runner.ps1
```

Check for secondary staging directory:
```cmd
dir "C:\Users\Public\Libraries\Default\Lib\Lib1"
```

Check for concealed ScreenConnect installation with known malicious ID:
```cmd
sc query "ScreenConnect Client (7a4d7d66502d4260)"
```

Check for masqueraded binaries:
```cmd
dir "C:\Users\Public\Libraries\Default\Lib\Themes.exe"
dir "C:\Users\Public\Libraries\Default\Lib\SearchIndex.exe"
```

### Remediation

1. **Contain**: Immediately isolate any host showing the persistence indicators above; disconnect from ScreenConnect
2. **Disable file transfer**: Follow ConnectWise interim guidance — disable `TransferFiles` permission (or `TransferFilesInSession` in legacy versions) on all ScreenConnect instances
3. **Hunt for IOCs**: Search EDR/SIEM for the C2 domains and IPs listed above; search for the SHA256 hashes of the VBScript files
4. **Remove persistence**: Delete the `WindowsServiceHost` Run key value and associated VBScript/batch files
5. **Remove concealed ScreenConnect**: Uninstall any ScreenConnect instance with ID `7a4d7d66502d4260`
6. **Remove masqueraded binaries**: Delete `Themes.exe`, `SearchIndex.exe`, and `svcdrv64.sys` from staging directories
7. **Re-enable defenses**: Verify AMSI is functional, remove `C:\Users` from Defender exclusion paths, re-enable HVCI
8. **Rotate credentials**: Assume any credentials on compromised hosts are exposed

### Long-Term Hardening

- Monitor ScreenConnect client behavior for anomalous `wscript.exe`/`cscript.exe` child process creation
- Implement application whitelisting to prevent execution of VBScript from ScreenConnect directories
- Apply ConnectWise patch when available (expected within one week of 2026-09-03 advisory)
- Consider restricting ScreenConnect file-transfer capabilities to only explicitly authorized use cases
- Deploy Sigma rules from this report to SIEM for ongoing detection

## Detection Rules

Eight Sigma rules cover the endpoint behavioral chain (ScreenConnect spawning script hosts, VBScript execution from ScreenConnect directories, staging file creation, PyTorchFix payload execution, persistence via Run key, masqueraded binaries) plus network IOCs (C2 domains and IPs). Three YARA rules target the VBScript stager files, WindowsServiceHost persistence payload, and PyTorchFix PowerShell payload. Snort and Suricata rules cover DNS queries to C2 domains and TCP connections to C2 IP addresses. All rules are anchored to campaign-specific IOCs; the staging-file Sigma rule (`medium` level) has the broadest FP surface due to generic filenames.

<!-- Validation audit: sigma check unavailable (MITRE ATT&CK data fetch blocked by proxy); sigma convert --without-pipeline -t splunk and -t log_scale passed for all 8 rules; yarac compiled 3 YARA rules after 1 fix (unreferenced string removed); Snort 2.9.20 validated via snort -T; Suricata 7.0.3 validated via suricata -T. All encoding follows logsource-encoding.md: values are real (not defanged), field names match Sysmon/Windows schema. -->

### Sigma Rules

#### 1. ScreenConnect Client Spawns Windows Script Host

Detects ScreenConnect client processes spawning wscript.exe or cscript.exe, the initial execution vector for the VBScript payload chain.
**Compile: Splunk ✅ LogScale ✅ | Confidence: high**

```yaml
title: ScreenConnect Client Spawns Windows Script Host
id: ad08c954-2171-4873-a24f-fb7312e5c25b
status: experimental
description: >
    Detects ScreenConnect client processes spawning wscript.exe or cscript.exe,
    a behavior observed in the September 2026 worm-like campaign where rogue
    ScreenConnect clients delivered multi-stage VBScript payloads.
references:
    - https://www.huntress.com/blog/rogue-screenconnect-installations
    - https://thehackernews.com/2026/09/rogue-screenconnect-clients-spread-four.html
author: Actioner
date: 2026/09/08
tags:
    - attack.t1059.005
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\ScreenConnect.ClientService.exe'
            - '\ScreenConnect.WindowsClient.exe'
    selection_child:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate ScreenConnect automation scripts deployed by IT administrators
level: high
```

#### 2. VBScript Execution From ScreenConnect Temporary Directory

Detects wscript.exe or cscript.exe executing VBS files from ScreenConnect file staging directories.
**Compile: Splunk ✅ LogScale ✅ | Confidence: high**

```yaml
title: VBScript Execution From ScreenConnect Temporary Directory
id: 8d3d9df8-c7da-4405-95c6-06b0313281ce
status: experimental
description: >
    Detects wscript.exe or cscript.exe executing VBS files from ScreenConnect
    file staging directories, consistent with the multi-stage VBScript payload
    chain observed in the September 2026 rogue ScreenConnect worm campaign.
references:
    - https://www.huntress.com/blog/rogue-screenconnect-installations
    - https://thehackernews.com/2026/09/rogue-screenconnect-clients-spread-four.html
author: Actioner
date: 2026/09/08
tags:
    - attack.t1059.005
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
    selection_path:
        CommandLine|contains:
            - '\ScreenConnect\Files\'
            - '\ScreenConnect Client\'
    selection_ext:
        CommandLine|endswith:
            - '.vbs'
            - '.vbe'
    condition: selection_process and selection_path and selection_ext
falsepositives:
    - Legitimate ScreenConnect file transfer of VBScript automation scripts
level: high
```

#### 3. WindowsServiceHost VBScript Persistence Via Run Key

Detects the specific Registry Run key persistence mechanism used by this campaign.
**Compile: Splunk ✅ LogScale ✅ | Confidence: high**

```yaml
title: WindowsServiceHost VBScript Persistence Via Run Key
id: e406c654-b5d8-4529-befc-46246ac02076
status: experimental
description: >
    Detects creation of a Registry Run key value named WindowsServiceHost
    pointing to a VBScript file, matching the persistence mechanism used
    by the September 2026 ScreenConnect worm campaign.
references:
    - https://www.huntress.com/blog/rogue-screenconnect-installations
    - https://thehackernews.com/2026/09/rogue-screenconnect-clients-spread-four.html
author: Actioner
date: 2026/09/08
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|endswith: '\Software\Microsoft\Windows\CurrentVersion\Run\WindowsServiceHost'
    selection_value:
        Details|endswith: 'WindowsServiceHost.vbs'
    condition: selection_key and selection_value
falsepositives:
    - Unknown
level: critical
```

#### 4. ScreenConnect Worm Staging File Creation

Detects creation of the campaign's characteristic staging files in the user TEMP directory.
**Compile: Splunk ✅ LogScale ✅ | Confidence: medium**

```yaml
title: ScreenConnect Worm Staging File Creation
id: 8937b675-1df3-43f8-8b40-7d7254b99460
status: experimental
description: >
    Detects creation of staging files (value.txt, map.txt, out.enc, runner.ps1)
    in the user TEMP directory, consistent with the multi-stage payload delivery
    observed in the September 2026 ScreenConnect worm campaign.
references:
    - https://www.huntress.com/blog/rogue-screenconnect-installations
    - https://thehackernews.com/2026/09/rogue-screenconnect-clients-spread-four.html
author: Actioner
date: 2026/09/08
tags:
    - attack.t1059.005
    - attack.t1027
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\value.txt'
            - '\map.txt'
            - '\out.enc'
            - '\runner.ps1'
        TargetFilename|contains: '\Temp\'
    condition: selection
falsepositives:
    - Generic filenames may appear in unrelated legitimate software
level: medium
```

#### 5. PyTorchFix PowerShell Payload Execution

Detects execution of the PyTorchFix.ps1 payload, a distinctive campaign artifact.
**Compile: Splunk ✅ LogScale ✅ | Confidence: high**

```yaml
title: PyTorchFix PowerShell Payload Execution
id: bb3631ea-3113-4e76-b3ac-5400992e6af8
status: experimental
description: >
    Detects execution of PyTorchFix.ps1, the second-stage PowerShell payload
    used in the September 2026 ScreenConnect worm campaign to perform UAC
    bypass, AMSI bypass, and install concealed ScreenConnect backdoors.
references:
    - https://www.huntress.com/blog/rogue-screenconnect-installations
    - https://thehackernews.com/2026/09/rogue-screenconnect-clients-spread-four.html
author: Actioner
date: 2026/09/08
tags:
    - attack.t1059.001
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'PyTorchFix.ps1'
    condition: selection
falsepositives:
    - Unlikely - PyTorchFix.ps1 is a distinctive payload filename
level: critical
```

#### 6. DNS Query to ScreenConnect Worm C2 Infrastructure

Detects DNS resolution of campaign C2 domains.
**Compile: Splunk ✅ LogScale ✅ | Confidence: high**

```yaml
title: DNS Query to ScreenConnect Worm C2 Infrastructure
id: 65b09020-d603-4210-ae04-c1d46a4de419
status: experimental
description: >
    Detects DNS queries to domains associated with the September 2026
    ScreenConnect worm campaign C2 infrastructure, including tele-sync.opik.net,
    borertors92.anondns.net, and homehub.opik.net.
references:
    - https://www.huntress.com/blog/rogue-screenconnect-installations
    - https://thehackernews.com/2026/09/rogue-screenconnect-clients-spread-four.html
author: Actioner
date: 2026/09/08
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'tele-sync.opik.net'
            - 'borertors92.anondns.net'
            - 'homehub.opik.net'
    condition: selection
falsepositives:
    - Unknown
level: critical
```

#### 7. Network Connection to ScreenConnect Worm C2 IP Addresses

Detects outbound connections to the five known C2 IP addresses.
**Compile: Splunk ✅ LogScale ✅ | Confidence: high**

```yaml
title: Network Connection to ScreenConnect Worm C2 IP Addresses
id: 03cfcd5f-af7e-4d31-a863-7267539b2a31
status: experimental
description: >
    Detects outbound network connections to IP addresses associated with the
    September 2026 ScreenConnect worm campaign C2 infrastructure.
references:
    - https://www.huntress.com/blog/rogue-screenconnect-installations
    - https://thehackernews.com/2026/09/rogue-screenconnect-clients-spread-four.html
author: Actioner
date: 2026/09/08
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '45.13.237.190'
            - '131.123.40.98'
            - '146.59.55.107'
            - '45.32.192.150'
            - '15.204.185.204'
    condition: selection
falsepositives:
    - Shared hosting may lead to false positives for some IPs
level: high
```

#### 8. Masqueraded Binaries in ScreenConnect Worm Campaign

Detects execution of Themes.exe (wstunnel) or SearchIndex.exe (XMRig) from the campaign staging directory.
**Compile: Splunk ✅ LogScale ✅ | Confidence: high**

```yaml
title: Masqueraded Binaries in ScreenConnect Worm Campaign
id: 8bf9ff6f-1acd-4784-a2cb-ac6be18d38c5
status: experimental
description: >
    Detects execution of masqueraded binaries (Themes.exe as wstunnel,
    SearchIndex.exe as XMRig miner) from the staging path used by the
    September 2026 ScreenConnect worm campaign.
references:
    - https://www.huntress.com/blog/rogue-screenconnect-installations
    - https://thehackernews.com/2026/09/rogue-screenconnect-clients-spread-four.html
author: Actioner
date: 2026/09/08
tags:
    - attack.t1036.005
    - attack.t1496
logsource:
    category: process_creation
    product: windows
detection:
    selection_staging_path:
        Image|contains: '\Users\Public\Libraries\Default\Lib\'
    selection_binaries:
        Image|endswith:
            - '\Themes.exe'
            - '\SearchIndex.exe'
    condition: selection_staging_path or selection_binaries
falsepositives:
    - Legitimate software named Themes.exe or SearchIndex.exe in non-standard paths
level: high
```

### YARA Rules

#### 9. ScreenConnect Worm VBScript Stager

Detects VBScript stager files (1.vbs through 4.vbs) based on staging file references and scripting patterns.
**Compile: yarac ✅ | Confidence: medium**

```yara
rule ScreenConnect_Worm_VBScript_Stager
{
    meta:
        description = "Detects VBScript stager files (1.vbs through 4.vbs) used in the September 2026 ScreenConnect worm campaign, based on unique string patterns and staging file references"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://www.huntress.com/blog/rogue-screenconnect-installations"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $staging_value = "value.txt" ascii wide
        $staging_map = "map.txt" ascii wide
        $staging_out = "out.enc" ascii wide
        $staging_runner = "runner.ps1" ascii wide

        $payload_pytorchfix = "PyTorchFix.ps1" ascii wide
        $payload_windowsservicehost = "WindowsServiceHost.vbs" ascii wide

        $wscript_shell = "WScript.Shell" ascii wide
        $createobject = "CreateObject" ascii wide
        $scripting_fso = "Scripting.FileSystemObject" ascii wide

        $abort_check = "abort" ascii wide

    condition:
        filesize < 500KB and
        2 of ($staging*) and
        1 of ($payload*) and
        $wscript_shell and
        $createobject and
        ($scripting_fso or $abort_check)
}
```

#### 10. ScreenConnect Worm WindowsServiceHost VBS

Detects the WindowsServiceHost.vbs persistence payload (SHA256: ffd6d23f...).
**Compile: yarac ✅ | Confidence: high**

```yara
rule ScreenConnect_Worm_WindowsServiceHost_VBS
{
    meta:
        description = "Detects the WindowsServiceHost.vbs persistence payload used in the September 2026 ScreenConnect worm campaign"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://www.huntress.com/blog/rogue-screenconnect-installations"
        hash = "ffd6d23f579571cc61936145791975da78b6ae914d780a9447a8f53c3688a0de"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $name = "WindowsServiceHost" ascii wide
        $vbs_ext = ".vbs" ascii wide
        $bat_ext = ".bat" ascii wide
        $run_key = "CurrentVersion\\Run" ascii wide
        $wscript = "WScript" ascii wide
        $shell = "Shell" ascii wide

    condition:
        filesize < 100KB and
        $name and
        $run_key and
        $wscript and
        ($bat_ext or $vbs_ext) and
        $shell
}
```

#### 11. ScreenConnect Worm PyTorchFix PowerShell Payload

Detects the PyTorchFix.ps1 payload by its UAC bypass, AMSI bypass, and Defender exclusion patterns or the campaign-specific ScreenConnect instance ID.
**Compile: yarac ✅ | Confidence: high**

```yara
rule ScreenConnect_Worm_PyTorchFix_PS1
{
    meta:
        description = "Detects the PyTorchFix.ps1 PowerShell payload used in the September 2026 ScreenConnect worm campaign, which performs UAC bypass, AMSI bypass, Defender exclusion, and concealed ScreenConnect installation"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://www.huntress.com/blog/rogue-screenconnect-installations"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $amsi_bypass = "amsiInitFailed" ascii wide nocase
        $uac_bypass_settings = "ms-settings" ascii wide
        $uac_bypass_exe = "ComputerDefaults.exe" ascii wide nocase
        $defender_exclusion = "Add-MpPreference" ascii wide nocase
        $exclusion_path = "ExclusionPath" ascii wide nocase
        $screenconnect_id = "7a4d7d66502d4260" ascii wide
        $password_exe = "Password.exe" ascii wide
        $sys_cache = "sys_cache.zip" ascii wide
        $svcdrv = "svcdrv64.sys" ascii wide
        $hvci_disable = "HypervisorEnforcedCodeIntegrity" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            $screenconnect_id or
            ($amsi_bypass and ($uac_bypass_settings or $uac_bypass_exe)) or
            ($defender_exclusion and $exclusion_path and 1 of ($sys_cache, $svcdrv, $password_exe)) or
            4 of them
        )
}
```

### Snort Rules

#### 12-19. ScreenConnect Worm C2 Network Detection (Snort)

Eight rules covering TCP connections to the five C2 IPs and DNS queries for the three C2 domains.
**Compile: snort -T ✅ | Confidence: high (IP/domain IOC rules)**

```
alert tcp $HOME_NET any -> 45.13.237.190 any (msg:"Actioner - ScreenConnect Worm C2 Connection to 45.13.237.190 (tele-sync.opik.net)"; flow:established, to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created 2026-09-08; sid:2100001; rev:1;)

alert tcp $HOME_NET any -> 131.123.40.98 8041 (msg:"Actioner - ScreenConnect Worm C2 Connection to 131.123.40.98:8041"; flow:established, to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created 2026-09-08; sid:2100002; rev:1;)

alert tcp $HOME_NET any -> 146.59.55.107 any (msg:"Actioner - ScreenConnect Worm C2 Connection to 146.59.55.107"; flow:established, to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created 2026-09-08; sid:2100003; rev:1;)

alert tcp $HOME_NET any -> 45.32.192.150 any (msg:"Actioner - ScreenConnect Worm C2 Connection to 45.32.192.150"; flow:established, to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created 2026-09-08; sid:2100004; rev:1;)

alert tcp $HOME_NET any -> 15.204.185.204 any (msg:"Actioner - ScreenConnect Worm C2 Connection to 15.204.185.204"; flow:established, to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created 2026-09-08; sid:2100005; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to ScreenConnect Worm C2 Domain tele-sync.opik.net"; flow:to_server; content:"|09|tele-sync|04|opik|03|net|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created 2026-09-08; sid:2100006; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to ScreenConnect Worm C2 Domain borertors92.anondns.net"; flow:to_server; content:"|0b|borertors92|07|anondns|03|net|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created 2026-09-08; sid:2100007; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to ScreenConnect Worm C2 Domain homehub.opik.net"; flow:to_server; content:"|07|homehub|04|opik|03|net|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created 2026-09-08; sid:2100008; rev:1;)
```

### Suricata Rules

#### 20-28. ScreenConnect Worm C2 Network Detection (Suricata)

Nine rules covering DNS queries (with dns.query sticky buffer), TCP connections to C2 IPs, and TLS SNI detection for the tunneling domain.
**Compile: suricata -T ✅ | Confidence: high (IOC-based rules)**

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ScreenConnect Worm C2 Domain tele-sync.opik.net"; flow:to_server; dns.query; content:"tele-sync.opik.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created_at 2026-09-08; sid:2200001; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ScreenConnect Worm C2 Domain borertors92.anondns.net"; flow:to_server; dns.query; content:"borertors92.anondns.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created_at 2026-09-08; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ScreenConnect Worm C2 Domain homehub.opik.net"; flow:to_server; dns.query; content:"homehub.opik.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created_at 2026-09-08; sid:2200003; rev:1;)

alert tcp $HOME_NET any -> 45.13.237.190 any (msg:"Actioner - ScreenConnect Worm C2 Connection to 45.13.237.190"; flow:established,to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created_at 2026-09-08; sid:2200004; rev:1;)

alert tcp $HOME_NET any -> 131.123.40.98 8041 (msg:"Actioner - ScreenConnect Worm C2 Connection to 131.123.40.98 Port 8041"; flow:established,to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created_at 2026-09-08; sid:2200005; rev:1;)

alert tcp $HOME_NET any -> 146.59.55.107 any (msg:"Actioner - ScreenConnect Worm C2 Connection to 146.59.55.107"; flow:established,to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created_at 2026-09-08; sid:2200006; rev:1;)

alert tcp $HOME_NET any -> 45.32.192.150 any (msg:"Actioner - ScreenConnect Worm C2 Connection to 45.32.192.150"; flow:established,to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created_at 2026-09-08; sid:2200007; rev:1;)

alert tcp $HOME_NET any -> 15.204.185.204 any (msg:"Actioner - ScreenConnect Worm C2 Connection to 15.204.185.204"; flow:established,to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created_at 2026-09-08; sid:2200008; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS Connection to ScreenConnect Worm C2 Domain homehub.opik.net"; flow:established,to_server; tls.sni; content:"homehub.opik.net"; nocase; classtype:trojan-activity; reference:url,www.huntress.com/blog/rogue-screenconnect-installations; metadata:author Actioner, created_at 2026-09-08; sid:2200009; rev:1;)
```

## Lessons Learned

1. **RMM tools as attack surface**: Legitimate remote management software continues to be a high-value target. The ScreenConnect file-transfer feature worked as designed but enabled automated worm propagation when controlled by an attacker. Vendors must implement rate limiting, behavioral analysis, and consent mechanisms for automated file execution.

2. **Defense-aware payloads**: The three-bit state variable system demonstrates increasing sophistication in adversary tooling — the payload adapts based on the detected security posture, deploying different tools depending on whether enterprise EDR or only Defender is present. Detection strategies must account for multiple payload variants from a single campaign.

3. **MSP supply-chain risk**: A single compromised ScreenConnect instance can cascade across all managed endpoints. MSPs should implement least-privilege access controls, disable unnecessary features like file-transfer-and-execute, and monitor for anomalous child processes from RMM agents.

## Sources

- [Huntress Blog: Rogue ScreenConnect Installations](https://www.huntress.com/blog/rogue-screenconnect-installations) — primary technical analysis with IOCs, infection chain, and payload details
- [The Hacker News: Rogue ScreenConnect Clients Spread Four-Stage VBScript Payloads](https://thehackernews.com/2026/09/rogue-screenconnect-clients-spread-four.html) — summary coverage with additional context on initial access vectors and payload variants
- [SecurityWeek: Modified ScreenConnect Clients Used in Worm-Like Campaign](https://www.securityweek.com/modified-screenconnect-clients-used-in-worm-like-campaign/) — summary coverage noting ConnectWise advisory response
- [ConnectWise Security Bulletins](https://www.connectwise.com/company/trust/security-bulletins) — vendor advisory acknowledging file-transfer behavior issue (September 3, 2026)

---
*Report generated by Actioner*
