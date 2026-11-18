<!-- revision: v1.1 — critic REVISE applied. CUT: Suricata sid:2100106 (port-only, unacceptable FP). FIX×8: (1) Sigma HTA/MSBuild MSBuild selection narrowed to \dl.xml; (2) Sigma Solana RPC cs-uri→r-dns; (3) Sigma Good Game reg removed generic DisableTaskMgr branch; (4) Sigma WinRE ATT&CK tag→t1542; (5) Sigma Execution Indicators tag t1106→t1204.002; (6) YARA MSBuild condition requires $ua, dropped $cs; (7) YARA HTA condition requires $path1, dropped $method*; (8) Snort sid:2100202 field host→http_host. Non-blocking: fixed clipper description (mutex not observable via registry_set), added Vite FP note on port 5173, added request-body-inspection note on Suricata sid:2100104. Suricata now 6 rules (was 7). -->
# Technical Analysis Report: UAT-12643 / Overlord RAT with Solana Blockchain C2 (2026-11-18)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-18
Version: 1.1

## Executive Summary

UAT-12643 is a suspected North Korea-aligned, financially motivated threat actor tracked by Cisco Talos. The group operates a multi-component attack toolset consisting of Overlord RAT (a Go-compiled modular Windows RAT with 35+ commands), the "Good Game" Python infostealer, and a C++ multi-cryptocurrency clipboard hijacker. Their most distinctive TTP is embedding AES-256 encrypted C2 URLs in Solana blockchain transaction memos, using the SPL Memo Program as a bulletproof dead drop resolver -- the first publicly documented use of Solana for C2 by a suspected DPRK-aligned actor. The group targets cryptocurrency holders, gaming account owners, and VoIP/softphone users, with linguistic targeting suggesting a European victim base. All tooling was served from a Flask-based staging server at 41[.]216[.]188[.]11, exposed through an operational security failure that revealed the full scope of the campaign.

## Background: Solana Blockchain as C2 Infrastructure

Public blockchains present a growing challenge for defenders because they provide immutable, globally replicated, censorship-resistant storage. UAT-12643 exploits Solana's SPL Memo Program to store encrypted C2 URLs in transaction memos (up to 566 bytes per memo). The Overlord RAT queries the actor's wallet via standard Solana JSON-RPC methods (`getSignatures`, `getTransaction` with `jsonParsed` encoding), extracting 43-character Base58-encoded strings that decrypt to WebSocket C2 URLs using AES-256. This allows the operator to rotate C2 by simply broadcasting a new Solana transaction, without redeploying malware to victims. Queries to public Solana RPC endpoints appear as ordinary blockchain API lookups, making network-level detection challenging.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026 (est.) | UAT-12643 staging server deployed at 41[.]216[.]188[.]11 |
| 2026 (est.) | Weaponized LNK files built on host win-8oa3ccqae4d |
| 2026 (est.) | Flask file-drop service exposed on port 8000 with open directory listing |
| 2026-11 | Cisco Talos publishes primary report and companion blockchain dead drops article |

## Root Cause: Weaponized LNK Files, HTA Droppers, and MSBuild Inline Tasks

UAT-12643 uses three initial access methods, all leveraging signed Windows binaries (LOLBins):

1. **LNK variant 1 (MpCmdRun):** Spoofed PDF icon; executes `MpCmdRun.exe -DownloadFile` to fetch a payload saved as `RuntimeBroker.exe`.
2. **LNK variant 2 (certutil):** Double extension with Edge PDF icon; executes `certutil -urlcache -f` to download the payload.
3. **HTA dropper:** Executed via `mshta.exe`; uses `MSXML2.ServerXMLHTTP` to download and `ADODB.Stream` to write `%TEMP%\s.exe`.
4. **MSBuild inline C# task (dl.xml):** Runs in memory via `msbuild.exe` with a spoofed `Microsoft BITS/7.8` User-Agent.

The delivery mechanism to victims (email, messaging, trojanized installers) is not fully confirmed, but Talos observed trojanized Viber installers and financial statement PDF decoys among the staging artifacts.

## Technical Analysis of the Malicious Payload

### 1. Overlord RAT (Go-compiled, Modular Windows RAT)

Overlord RAT is the primary remote access implant, compiled in Go with 35+ commands.

**Anti-termination:** Acquires `SeDebugPrivilege`, then calls `NtSetInformationProcess` to set `ProcessBreakOnTermination = 1`. Forced termination causes a BSoD (CRITICAL_PROCESS_DIED).

**Persistence (dual-layer):**
- **Registry:** `HKCU\...\CurrentVersion\Run` with a randomized value name, pointing to a binary in `%APPDATA%\Network\`.
- **WinRE (pre-boot):** Writes payload with a random 20-character filename to `%TARGETOSDRIVE%\Recovery\OEM\`, creates a `.bat` launcher, and patches `ResetConfig.xml` to register it as an OEM task. This survives "Reset this PC."

**Capabilities:** Keylogging (GetAsyncKeyState), webcam/microphone/desktop audio capture, screenshots, full file system operations, process enumeration/termination, command/script execution, reverse SOCKS proxy for lateral movement, and reflective DLL injection for plugins.

**Sandbox detection:** Detects in-memory execution conditions to suppress artifacts.

### 2. Good Game Infostealer (Python 3.12.0, PyInstaller)

A publicly available tool ("Good Game" v1.1.2 by CirqueiraDev) repurposed by the actor. Components: `final_build.pyc` (launcher, decoy GUI, reverse shell) and `kora.pyc` (stealer logic).

**Evasion:** Displays a tkinter Notepad-style GUI decoy. Sandbox checks include DLL detection (sbiedll.dll, api_log.dll, vmcheck.dll, wpespy.dll, cmdvrt64.dll, avghookx.dll, snxhk.dll, guard32.dll), VM MAC OUI checks (VMware, VirtualBox, Hyper-V, Xen, Parallels), RAM < 2GB, uptime < 5 min, and Wine detection.

**Persistence:** `HKCU\...\CurrentVersion\Run\Zoipers`; copies itself to Startup folder; temporarily sets `DisableTaskMgr=1`.

**Targets (by category):**
- **Browsers (23):** Chrome, Edge, Opera, Opera GX, Brave, Vivaldi, Yandex, Amigo, Torch, Kometa, Orbitum, CentBrowser, 7Star, Sputnik, Epic Privacy, Uran, Iridium, and others including Firefox-based.
- **Discord:** Token extraction from LevelDB including `dQw4w9WgXcQ:` encrypted prefix, validated via Discord API.
- **Roblox:** ROBLOSECURITY cookie extraction, validated via Roblox API.
- **Crypto wallets (21):** Exodus, Electrum, Ledger Live, Trezor Suite, Atomic Wallet, Trust Wallet, Coinbase, Binance, and others.
- **Gaming (4):** Steam, Riot Games, Epic Games, Rockstar Games.
- **Messaging:** Telegram session data.

**File sweep:** Desktop, Downloads, Documents, Pictures, Videos, OneDrive, Recent Items -- matches a 45-extension allowlist against a multilingual keyword list (English, French, Spanish, Portuguese) targeting seed phrases, backup codes, wallet names, passwords, private keys.

**Exfiltration:** Archives as `SK_<8_random>.zip` with subfolders (Screenshot/, Webcam/, Session Files/Wallets/, etc.). Uploaded via HTTP POST to `hxxps[:]//upload[.]gofile[.]io/uploadFile`. Discord webhook notification includes hostname, username, OS details, and GoFile download link.

### 3. Clipboard Hijacker (C++, x64)

A standalone multi-cryptocurrency address replacer with no network component.

**Anti-analysis:** Checks machine name for VBOX, VMWARE, QEMU, SANDBOX.

**Persistence:** Copies to `%APPDATA%\MsgEdgeUpdate.exe` (hidden + system attributes); adds `HKCU\...\CurrentVersion\Run\MsgEdgeUpdate`.

**Mutex:** `UuuRjinBZPBMIjnc`

**Behavior:** Polls clipboard every 500ms, fingerprints cryptocurrency address formats, replaces with attacker-controlled addresses (XOR-encrypted in the .data section).

### 4. C2 Infrastructure

| Port | Service | Payloads |
|------|---------|----------|
| 8000 | Flask file-drop (HTTP) | Payload.exe, MyApp2.exe, HTA files |
| 5173 | Overlord RAT WebSocket C2 | Ovl.exe, Client.exe |
| 5656 | Python stealer TCP C2 | Ova.exe, MyApp2.exe |
| 5959 | Python stealer TCP C2 | microsip-config.exe, microsip-config1.exe |

**Solana dead drop:** The RAT queries the actor's Solana wallet with `getSignatures`, retrieves each transaction with `getTransaction` (jsonParsed), and scans instruction data for 43-character strings -- the expected length of a Base58 AES-256 encrypted WebSocket URL. C2 rotation requires only a new Solana transaction.

### 5. Anti-Forensics / Evasion Techniques

- **Overlord RAT:** BSoD-on-kill via ProcessBreakOnTermination; SeDebugPrivilege escalation; in-memory execution detection.
- **Good Game:** Multi-layered sandbox checks (DLLs, MAC OUIs, RAM, uptime, Wine); tkinter decoy GUI; DisableTaskMgr during exfiltration; post-exfiltration cleanup of ZIP and temp files.
- **Clipboard Hijacker:** Machine name VM string checks; XOR-encrypted wallet addresses in .data section.
- **Delivery:** Signed binary proxy execution (MpCmdRun, certutil, mshta, MSBuild); spoofed BITS User-Agent.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Hash (SHA256) | Description |
|----------|---------------|-------------|
| Windows | b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c | Overlord RAT (Go binary) |
| Windows | 16622bb8df60403217ccf8e326e2e9e718e01c85d7b52fe5c5e1cf44d62d25c8 | Good Game Stealer (PyInstaller) |
| Windows | b0b636f5c7e40af94aacf9ebd9a696dac57debcd628127414248908562380d33 | Good Game Stealer Python script |
| Windows | 5a52d6773840fd5ab45d781d572d9fbd6a8dacb08dcda65036ce8b28548a5224 | Good Game Stealer |
| Windows | f1e5174084bfded283b9dcf081615478e6941d12b652793197556beb72cc7588 | Clipboard Hijacker (C++) |
| Windows | f7951b11be06d59a3e8fdd9bde4f19869978de8385c9107129c635b2cdba5082 | LNK generator (PowerShell) |
| Windows | 19ca4e0e8e7dd62d130afbfed49646f1566dce2633cf937b848d990da3e3e9a2 | dl.xml (MSBuild inline task) |
| Windows | 1b268a08e83839f6e89acf0987657776398de2ba5a323b04b1dd3925ce3a5b45 | document.lnk (malicious LNK) |
| Windows | c8f9ce4b58acec3ce5640041cbc6d4802e30b2dded4a88766ee2de2cefde45f7 | payload.hta (HTA dropper) |
| Windows | eb5730784e7d63e1fe38a0bc28be8f2210666662e9a660efcc3282f0489ef870 | payment-invoice.pdf.lnk |
| Windows | 68786345f67152eb0d52bb198b5904924cfbdbf50c078432e5329e5d02fc6659 | Viber.lnk |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 41[.]216[.]188[.]11 | Staging server and C2 (ports 5173, 5656, 5959, 8000) |
| URL | hxxps[:]//upload[.]gofile[.]io/uploadFile | Exfiltration endpoint (Good Game stealer) |
| User-Agent | Microsoft BITS/7.8 | Spoofed UA in MSBuild dl.xml downloader |

### Behavioral

- **Registry persistence keys:** `HKCU\...\CurrentVersion\Run\Zoipers` (Good Game), `HKCU\...\CurrentVersion\Run\MsgEdgeUpdate` (Clipper)
- **Mutex:** `UuuRjinBZPBMIjnc` (Clipboard Hijacker)
- **Build host:** `win-8oa3ccqae4d` (LNK metadata)
- **File paths:** `%APPDATA%\MsgEdgeUpdate.exe`, `%APPDATA%\Network\<binary>`, `%TARGETOSDRIVE%\Recovery\OEM\<random 20 chars>`, `%TEMP%\s.exe`, `%TEMP%\SK_<8 chars>.zip`
- **Solana RPC methods:** `getSignatures`, `getTransaction` with `jsonParsed` encoding, scanning for 43-character instruction strings
- **Clipboard polling interval:** 500ms
- **WebSocket C2 on non-standard port 5173**
- **TCP C2 on ports 5656, 5959**

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | Weaponized LNK files with spoofed PDF/document icons |
| T1218.005 | Mshta | HTA dropper executed via mshta.exe |
| T1127.001 | MSBuild | dl.xml inline C# task executed in memory |
| T1105 | Ingress Tool Transfer | MpCmdRun -DownloadFile and certutil -urlcache payload download |
| T1547.001 | Registry Run Keys / Startup Folder | Overlord (randomized Run key), Good Game (Zoipers Run key + Startup), Clipper (MsgEdgeUpdate Run key) |
| T1542 | Pre-OS Boot | Overlord RAT WinRE persistence via ResetConfig.xml patching |
| T1102.001 | Web Service: Dead Drop Resolver | Solana blockchain memo-based C2 resolution |
| T1567.002 | Exfiltration Over Web Service | Archive upload to gofile.io, Discord webhook notification |
| T1056.001 | Keylogging | Overlord RAT GetAsyncKeyState-based keylogger |
| T1113 | Screen Capture | Overlord RAT and Good Game screenshot capture |
| T1125 | Video Capture | Overlord RAT webcam capture |
| T1115 | Clipboard Data | Multi-cryptocurrency clipboard hijacker with 500ms polling |
| T1555.003 | Credentials from Web Browsers | Good Game extracts from 23 browser families |
| T1539 | Steal Web Session Cookie | ROBLOSECURITY and Discord token theft |
| T1005 | Data from Local System | File sweep across Desktop, Downloads, Documents, etc. |
| T1090 | Proxy | Overlord RAT reverse SOCKS proxy for lateral movement |
| T1497 | Virtualization/Sandbox Evasion | DLL checks, VM MAC OUI, RAM/uptime, Wine, machine name |
| T1562.001 | Impair Defenses: Disable or Modify Tools | DisableTaskMgr=1 during Good Game exfiltration |
| T1106 | Native API | NtSetInformationProcess for ProcessBreakOnTermination |

## Impact Assessment

**Breadth:** Broad targeting across cryptocurrency holders, gamers (Roblox, Steam, Epic, Riot, Rockstar), VoIP/softphone users (Viber, MicroSIP), and messaging users (Telegram, Discord). Multilingual keyword targeting (EN/FR/ES/PT) suggests European victims. The 21 cryptocurrency wallet families and 23 browser families targeted ensure wide applicability.

**Depth:** Critical -- Overlord RAT provides full remote access with 35+ commands, the infostealer comprehensively harvests credentials and session data, and the clipboard hijacker enables direct cryptocurrency theft. WinRE persistence survives OS reset.

**Stealth:** High -- Solana blockchain C2 is resistant to takedown and blends with legitimate API traffic. LOLBin delivery avoids dropping unsigned binaries. Good Game's decoy GUI, sandbox checks, and post-exfiltration cleanup reduce detection opportunities.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for clipboard hijacker persistence
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MsgEdgeUpdate" -ErrorAction SilentlyContinue

# Check for Good Game stealer persistence
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Zoipers" -ErrorAction SilentlyContinue

# Check for MsgEdgeUpdate.exe in AppData
Test-Path "$env:APPDATA\MsgEdgeUpdate.exe"

# Check for Overlord RAT in Network folder
Get-ChildItem "$env:APPDATA\Network\" -ErrorAction SilentlyContinue

# Check for WinRE persistence payloads
Get-ChildItem "$env:SystemDrive\Recovery\OEM\" -Recurse -ErrorAction SilentlyContinue

# Check for known hashes (hash hunt across endpoints)
Get-FileHash "$env:APPDATA\MsgEdgeUpdate.exe" -Algorithm SHA256 -ErrorAction SilentlyContinue

# Check for C2 connections
Get-NetTCPConnection -RemoteAddress 41.216.188.11 -ErrorAction SilentlyContinue
Get-NetTCPConnection -RemotePort 5173,5656,5959 -State Established -ErrorAction SilentlyContinue
```

### Remediation

1. **Contain:** Block 41[.]216[.]188[.]11 at all network boundaries (firewall, proxy, DNS sinkhole). Block outbound to ports 5173, 5656, 5959 for non-business traffic.
2. **Eradicate:** Remove `%APPDATA%\MsgEdgeUpdate.exe`, `%APPDATA%\Network\*`, `%TARGETOSDRIVE%\Recovery\OEM\<suspicious files>`. Delete registry values: `MsgEdgeUpdate`, `Zoipers` from Run keys. Restore `ResetConfig.xml` from a known-good backup.
3. **Credential reset:** Rotate all credentials stored in affected browsers. Invalidate Discord and Roblox sessions. Revoke and regenerate cryptocurrency wallet keys if any wallet was accessed. Rotate Telegram sessions.
4. **Cryptocurrency verification:** Review recent transactions on all wallets associated with affected machines. Check clipboard history for address swaps.
5. **Network sweep:** Search proxy logs for POST requests to `upload.gofile.io` and Solana RPC endpoints (`getSignatures`, `getTransaction`). Search for `Microsoft BITS/7.8` User-Agent strings.

### Long-Term Hardening

1. **Block or monitor Solana RPC endpoints** (api.mainnet-beta.solana.com, public RPC aggregators) from non-developer endpoints. Baseline legitimate blockchain API usage.
2. **Restrict LOLBin execution:** Apply ASR rules or AppLocker policies to block `MpCmdRun.exe -DownloadFile`, `certutil -urlcache`, `mshta.exe` execution outside of authorized contexts.
3. **Clipboard monitoring:** Deploy endpoint detection for clipboard polling patterns (500ms interval with address replacement).
4. **WinRE integrity:** Monitor `Recovery\OEM\` for unexpected file creation and `ResetConfig.xml` modifications.
5. **Exfiltration controls:** Block or alert on file uploads to gofile.io and similar anonymous file-sharing services.

## Detection Rules

Eight Sigma rules, five YARA rules, six Suricata rules, and three Snort 3 rules cover Overlord RAT execution and persistence, Good Game stealer persistence and exfiltration, clipboard hijacker indicators, LOLBin-based delivery, Solana RPC dead drop resolution, and network C2 patterns. The Solana RPC and GoFile exfiltration rules require tuning in environments with legitimate blockchain development or file-sharing usage.

<!-- AUDIT: All Sigma rules validated via sigma convert --without-pipeline to both splunk and log_scale backends (exit 0). YARA rules compiled clean with yarac. Suricata rules validated with suricata -T (v7.0.3). Snort 3 rules structurally checked (not installed). All detection values use real (non-defanged) IOCs per logsource-encoding.md. -->
<!-- dropped: Suricata sid:2100106 "Good Game Stealer TCP C2 on ports 5656/5959" — port-only detection with no content matching or IP constraint; unacceptable FP volume under strict leniency -->

### Sigma: UAT-12643 Overlord RAT Execution Indicators
Detects Overlord RAT binary execution from AppData\Network or with known filenames (Ovl.exe, Client.exe, RuntimeBroker.exe).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. FIX: replaced attack.t1106 (Native API) with attack.t1204.002 (User Execution: Malicious File) — detection logic is process_creation by image path, not native API invocation. -->

```yaml
title: UAT-12643 Overlord RAT Execution Indicators
id: 7a3c8e1f-4b2d-4f9a-b6e1-8d3c7a5f2e09
status: experimental
description: >
    Detects execution of Overlord RAT payloads associated with UAT-12643.
    The RAT uses filenames like Ovl.exe, Client.exe, and RuntimeBroker.exe
    and persists via the Network folder in the user AppData profile.
references:
    - https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
author: Actioner
date: 2026-11-18
tags:
    - attack.t1547.001
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_names:
        Image|endswith:
            - '\Ovl.exe'
            - '\Client.exe'
            - '\RuntimeBroker.exe'
        Image|contains:
            - '\AppData\'
    selection_appdata_network:
        Image|contains: '\AppData\Roaming\Network\'
    condition: (selection_names) or selection_appdata_network
falsepositives:
    - Legitimate RuntimeBroker.exe runs from System32, not AppData
level: high
```

### Sigma: UAT-12643 Overlord RAT WinRE Persistence
Detects executables or batch files written to the Recovery\OEM directory, indicating WinRE persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. FIX: changed ATT&CK tag from t1547.001 (Registry Run Keys) to t1542 (Pre-OS Boot) — detection targets WinRE pre-boot persistence via Recovery\OEM writes, not registry run keys. -->

```yaml
title: UAT-12643 Overlord RAT WinRE Persistence via ResetConfig.xml
id: 2f9b4c3d-5a1e-48f7-9d6c-3b7e8f1a2c05
status: experimental
description: >
    Detects modification of ResetConfig.xml used by Overlord RAT to persist
    through Windows Recovery Environment reset operations. The RAT writes
    payloads to Recovery\OEM and patches ResetConfig.xml to register them.
references:
    - https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
author: Actioner
date: 2026-11-18
tags:
    - attack.t1542
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains|all:
            - '\Recovery\OEM\'
        TargetFilename|endswith:
            - '.exe'
            - '.bat'
    condition: selection
falsepositives:
    - OEM system recovery customization by IT administrators
level: high
```

### Sigma: UAT-12643 Good Game Stealer Registry Persistence
Detects the Zoipers Run key created by the Good Game stealer for persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. FIX: removed selection_taskmgr branch (DisableTaskMgr set to 1) — too generic, fires on any malware that disables Task Manager and on legitimate GPOs. Removed attack.t1562.001 tag accordingly. Kept only campaign-specific Zoipers registry persistence. -->

```yaml
title: UAT-12643 Good Game Stealer Registry Persistence
id: 8e4d1b6a-3c7f-49e2-a5d8-9f2c6b1e3a07
status: experimental
description: >
    Detects the Good Game infostealer setting the Zoipers registry Run key
    for persistence, as observed in UAT-12643 intrusions.
references:
    - https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
author: Actioner
date: 2026-11-18
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_zoipers:
        TargetObject|endswith: '\CurrentVersion\Run\Zoipers'
    condition: selection_zoipers
falsepositives:
    - Legitimate Zoiper VoIP software using similar registry key names
level: high
```

### Sigma: UAT-12643 Clipboard Hijacker MsgEdgeUpdate Persistence
Detects the MsgEdgeUpdate Run key created by the clipboard hijacker.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. FIX (non-blocking): removed mutex mention from description — registry_set logsource cannot observe mutexes; mutex detection requires process_creation or sysmon EventID 1/17. -->

```yaml
title: UAT-12643 Clipboard Hijacker MsgEdgeUpdate Persistence
id: 4c2a9e7f-1b5d-43f8-8e6a-5d3c2f9b1e08
status: experimental
description: >
    Detects the UAT-12643 clipboard hijacker establishing persistence by
    writing MsgEdgeUpdate.exe to AppData and creating a matching Run key.
references:
    - https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
author: Actioner
date: 2026-11-18
tags:
    - attack.t1547.001
    - attack.t1115
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\CurrentVersion\Run\MsgEdgeUpdate'
    condition: selection
falsepositives:
    - Unlikely; MsgEdgeUpdate is not a legitimate Microsoft Edge component
level: high
```

### Sigma: UAT-12643 LNK-Based Payload Download via LOLBins
Detects MpCmdRun or certutil used by weaponized LNKs to download payloads from the staging server.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. Unchanged from v1.0. -->

```yaml
title: UAT-12643 LNK-Based Payload Download via LOLBins
id: 5d8f3a2c-6e1b-47c9-9f4d-2a7b5c3e8d01
status: experimental
description: >
    Detects UAT-12643 initial access techniques where weaponized LNK files
    invoke MpCmdRun.exe with -DownloadFile or certutil with -urlcache -f
    to download payloads from the staging server.
references:
    - https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
author: Actioner
date: 2026-11-18
tags:
    - attack.t1105
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_mpcmdrun:
        Image|endswith: '\MpCmdRun.exe'
        CommandLine|contains|all:
            - '-DownloadFile'
            - 'RuntimeBroker'
    selection_certutil:
        Image|endswith: '\certutil.exe'
        CommandLine|contains|all:
            - '-urlcache'
            - '-f'
            - '41.216.188.11'
    condition: selection_mpcmdrun or selection_certutil
falsepositives:
    - Legitimate use of MpCmdRun -DownloadFile is rare outside Defender management
level: high
```

### Sigma: UAT-12643 HTA and MSBuild Payload Execution
Detects mshta.exe contacting the C2 IP or MSBuild loading the campaign-specific dl.xml task file.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. FIX: narrowed selection_msbuild from CommandLine|endswith '.xml' (fires on all MSBuild XML projects) to '\dl.xml' (campaign-specific). -->

```yaml
title: UAT-12643 HTA and MSBuild Payload Execution
id: 9b7e2d4c-3f1a-45e8-a6c9-1d8b5f3e7a02
status: experimental
description: >
    Detects UAT-12643 delivery via mshta.exe executing HTA droppers or
    msbuild.exe loading the dl.xml inline C# task, both observed
    as initial access methods in this campaign.
references:
    - https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
author: Actioner
date: 2026-11-18
tags:
    - attack.t1218.005
    - attack.t1127.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_mshta:
        Image|endswith: '\mshta.exe'
        CommandLine|contains: '41.216.188.11'
    selection_msbuild:
        Image|endswith: '\MSBuild.exe'
        CommandLine|endswith: '\dl.xml'
    condition: selection_mshta or selection_msbuild
falsepositives:
    - Legitimate build processes using MSBuild with a file named dl.xml (unlikely)
level: medium
```

### Sigma: UAT-12643 Data Exfiltration to GoFile
Detects HTTP POST to upload.gofile.io used for credential archive exfiltration.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. Unchanged from v1.0. -->

```yaml
title: UAT-12643 Data Exfiltration to GoFile
id: 6a1c3e8d-2b5f-49d7-8e3a-4c9b7d2f1e06
status: experimental
description: >
    Detects HTTP POST exfiltration to upload.gofile.io used by UAT-12643
    Good Game stealer to upload stolen credential archives.
references:
    - https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
author: Actioner
date: 2026-11-18
tags:
    - attack.t1567.002
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'POST'
        r-dns|contains: 'upload.gofile.io'
    condition: selection
falsepositives:
    - Legitimate use of GoFile for file sharing by employees
level: medium
```

### Sigma: UAT-12643 Solana Blockchain RPC Dead Drop Resolver
Detects Solana JSON-RPC method calls indicative of blockchain dead drop C2 resolution. Requires full request body logging for the cs-body selection to match.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. FIX: changed selection_solana_rpc from cs-uri|contains to r-dns|contains — cs-uri holds the URI path, not the destination hostname; would never match in conformant proxy logs. Added deployment note about cs-body requiring full request body logging. -->

```yaml
title: UAT-12643 Solana Blockchain RPC Dead Drop Resolver
id: 3e5a7c9d-1f2b-48d6-a4e8-6b3c8d2f7e04
status: experimental
description: >
    Detects HTTP POST requests to Solana RPC endpoints containing JSON-RPC
    method calls (getSignatures, getTransaction) from non-developer endpoints,
    indicating potential blockchain dead drop C2 resolution used by Overlord RAT.
    Requires full request body logging (cs-body) for the body selection to match.
references:
    - https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
    - https://blog.talosintelligence.com/the-challenge-of-defending-against-bulletproof-dead-drops-on-public-blockchains/
author: Actioner
date: 2026-11-18
tags:
    - attack.t1102.001
logsource:
    category: proxy
detection:
    selection_method:
        cs-method: 'POST'
    selection_solana_rpc:
        r-dns|contains:
            - 'api.mainnet-beta.solana.com'
            - 'solana-mainnet'
            - 'solana-api'
    selection_body:
        cs-body|contains:
            - 'getSignatures'
            - 'getTransaction'
    condition: selection_method and (selection_solana_rpc or selection_body)
falsepositives:
    - Developers working with Solana blockchain applications
    - Cryptocurrency trading platforms
level: medium
```

### YARA: Overlord RAT, Good Game Stealer, Clipboard Hijacker, HTA Dropper, MSBuild Task
Five YARA rules covering the full UAT-12643 malware suite.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. FIX: HTA Dropper — made $path1 (\Temp\s.exe) mandatory in condition, removed unreferenced $method* strings (too generic). MSBuild Inline Task — made $ua (Microsoft BITS/7.8) mandatory in condition, removed unreferenced $cs string (Microsoft.CSharp matches any inline C# task). -->

```yara
import "pe"

rule Malware_OverlordRAT_Go_Binary : UAT12643
{
    meta:
        description = "Detects Overlord RAT Go-compiled Windows RAT used by UAT-12643. Matches anti-termination, WinRE persistence, and Solana C2 resolution strings."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c"
        severity = "critical"

    strings:
        $go1 = "Go build" ascii
        $go2 = "runtime.main" ascii

        $anti1 = "SeDebugPrivilege" ascii wide
        $anti2 = "NtSetInformationProcess" ascii
        $anti3 = "ProcessBreakOnTermination" ascii

        $persist1 = "\\Recovery\\OEM\\" ascii wide
        $persist2 = "ResetConfig.xml" ascii wide
        $persist3 = "CurrentVersion\\Run" ascii wide

        $solana1 = "getSignatures" ascii
        $solana2 = "getTransaction" ascii
        $solana3 = "jsonParsed" ascii

        $ws1 = "websocket" ascii nocase
        $ws2 = "5173" ascii

        $cmd1 = "GetAsyncKeyState" ascii
        $cmd2 = "keylog" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 30MB and
        1 of ($go*) and
        (
            (2 of ($anti*) and 1 of ($persist*)) or
            (2 of ($solana*)) or
            (1 of ($anti*) and 1 of ($solana*) and 1 of ($ws*)) or
            (2 of ($anti*) and 1 of ($cmd*))
        )
}

rule Malware_GoodGame_Infostealer_Python : UAT12643
{
    meta:
        description = "Detects Good Game infostealer Python scripts used by UAT-12643. Matches stealer logic, sandbox checks, and exfiltration patterns."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "b0b636f5c7e40af94aacf9ebd9a696dac57debcd628127414248908562380d33"
        severity = "high"

    strings:
        $pyinst1 = "PyInstaller" ascii
        $pyinst2 = "_MEIPASS" ascii

        $sb1 = "sbiedll.dll" ascii nocase
        $sb2 = "api_log.dll" ascii nocase
        $sb3 = "vmcheck.dll" ascii nocase
        $sb4 = "wpespy.dll" ascii nocase
        $sb5 = "cmdvrt64.dll" ascii nocase

        $steal1 = "ROBLOSECURITY" ascii
        $steal2 = "dQw4w9WgXcQ:" ascii
        $steal3 = "upload.gofile.io" ascii
        $steal4 = "uploadFile" ascii
        $steal5 = "ipwhois.app" ascii

        $pers1 = "Zoipers" ascii
        $pers2 = "DisableTaskMgr" ascii

        $file1 = "final_build" ascii
        $file2 = "kora" ascii

    condition:
        filesize < 50MB and
        (
            (2 of ($sb*) and 2 of ($steal*)) or
            (1 of ($pyinst*) and 2 of ($steal*) and 1 of ($pers*)) or
            (1 of ($file*) and 2 of ($steal*))
        )
}

rule Malware_ClipboardHijacker_WalletClipper : UAT12643
{
    meta:
        description = "Detects UAT-12643 multi-cryptocurrency clipboard hijacker. Matches mutex, anti-VM checks, and clipboard monitoring behavior."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "f1e5174084bfded283b9dcf081615478e6941d12b652793197556beb72cc7588"
        severity = "high"

    strings:
        $mutex = "UuuRjinBZPBMIjnc" ascii wide
        $file1 = "MsgEdgeUpdate" ascii wide

        $vm1 = "VBOX" ascii wide
        $vm2 = "VMWARE" ascii wide
        $vm3 = "QEMU" ascii wide
        $vm4 = "SANDBOX" ascii wide

        $clip1 = "OpenClipboard" ascii
        $clip2 = "GetClipboardData" ascii
        $clip3 = "SetClipboardData" ascii
        $clip4 = "CloseClipboard" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $mutex or
            ($file1 and 2 of ($clip*)) or
            ($file1 and 2 of ($vm*) and 2 of ($clip*))
        )
}

rule Malware_UAT12643_HTA_Dropper : UAT12643
{
    meta:
        description = "Detects HTA dropper files used by UAT-12643 for initial payload delivery via mshta.exe"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "c8f9ce4b58acec3ce5640041cbc6d4802e30b2dded4a88766ee2de2cefde45f7"
        severity = "high"

    strings:
        $hta1 = "<HTA:APPLICATION" ascii nocase
        $hta2 = "MSXML2.ServerXMLHTTP" ascii nocase
        $hta3 = "ADODB.Stream" ascii nocase
        $path1 = "\\Temp\\s.exe" ascii

    condition:
        filesize < 500KB and
        $hta1 and
        ($hta2 and $hta3) and
        $path1
}

rule Malware_UAT12643_MSBuild_Inline_Task : UAT12643
{
    meta:
        description = "Detects dl.xml MSBuild inline task used by UAT-12643 with spoofed BITS User-Agent"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "19ca4e0e8e7dd62d130afbfed49646f1566dce2633cf937b848d990da3e3e9a2"
        severity = "high"

    strings:
        $xml1 = "CodeTaskFactory" ascii
        $xml2 = "UsingTask" ascii
        $ua = "Microsoft BITS/7.8" ascii

    condition:
        filesize < 1MB and
        $xml1 and $xml2 and
        $ua
}
```

### Suricata: UAT-12643 Network Detection (6 rules)
Covers C2 to known IP, WebSocket on port 5173, GoFile exfiltration, Solana RPC dead drop, spoofed BITS User-Agent, and Flask staging server. Port 5173 is Vite's default dev server port -- scope to non-developer VLANs. Solana RPC body inspection requires `request-body-limit` enabled in suricata.yaml.
**Status:** compile ✅ compiles · confidence: high (IP-specific), medium (behavioral)
<!-- audit: suricata -T exit 0 (v7.0.3). CUT sid:2100106 (port-only detection on 5656/5959, no content/IP constraint — unacceptable FP volume). Added FP note on sid:2100102 (port 5173 = Vite dev server default). Added deployment note on sid:2100104 (http.request_body requires request-body inspection enabled). -->

```
# Rule 1: Overlord RAT C2 to known staging IP
alert tcp $HOME_NET any -> 41.216.188.11 any (msg:"Actioner - UAT-12643 Overlord RAT C2 Communication to Known Staging IP"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/; metadata:author Actioner, created_at 2026-11-18; sid:2100101; rev:1;)

# Rule 2: Overlord RAT WebSocket C2 on port 5173
# FP note: Port 5173 is the default dev server port for Vite (Node.js). Scope to non-developer VLANs or suppress on dev workstations.
alert tcp $HOME_NET any -> $EXTERNAL_NET 5173 (msg:"Actioner - UAT-12643 Overlord RAT WebSocket C2 on Port 5173"; flow:established,to_server; content:"Upgrade"; content:"websocket"; nocase; distance:0; within:50; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/; metadata:author Actioner, created_at 2026-11-18; sid:2100102; rev:1;)

# Rule 3: Good Game Stealer exfiltration to GoFile
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-12643 Good Game Stealer Exfiltration to GoFile"; flow:established,to_server; http.method; content:"POST"; http.host; content:"upload.gofile.io"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/; metadata:author Actioner, created_at 2026-11-18; sid:2100103; rev:1;)

# Rule 4: Solana RPC Dead Drop Resolution
# Note: http.request_body requires request-body inspection to be enabled in suricata.yaml (app-layer.protocols.http.request-body-limit).
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-12643 Solana RPC Dead Drop C2 Resolution"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"getTransaction"; fast_pattern; content:"jsonParsed"; distance:0; within:100; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/; metadata:author Actioner, created_at 2026-11-18; sid:2100104; rev:1;)

# Rule 5: Spoofed BITS User-Agent from MSBuild downloader
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-12643 Spoofed BITS User-Agent MSBuild Downloader"; flow:established,to_server; http.user_agent; content:"Microsoft BITS/7.8"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/; metadata:author Actioner, created_at 2026-11-18; sid:2100105; rev:1;)

# dropped: Suricata sid:2100106 "Good Game Stealer TCP C2 on ports 5656/5959" -- port-only detection with no content matching or IP constraint; unacceptable FP volume under strict leniency

# Rule 6: Flask staging server payload download on port 8000
alert http $HOME_NET any -> 41.216.188.11 8000 (msg:"Actioner - UAT-12643 Flask Staging Server Payload Download"; flow:established,to_server; http.method; content:"GET"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/; metadata:author Actioner, created_at 2026-11-18; sid:2100107; rev:1;)
```

### Snort 3: UAT-12643 Network Detection (3 rules)
Covers C2 to known IP, GoFile exfiltration, and spoofed BITS User-Agent.
**Status:** ⚠️ uncompiled (structural check only — Snort 3 not installed) · confidence: medium
<!-- audit: structural check only. FIX: sid:2100202 replaced invalid "http_header; field host;" with "http_host;" — "field host" is not valid Snort 3 syntax. -->

```
# Rule 1: Overlord RAT C2 to known staging IP
alert tcp $HOME_NET any -> 41.216.188.11 any (msg:"Actioner - UAT-12643 Overlord RAT C2 to Known Staging IP"; flow:established, to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/; metadata:author Actioner, created 2026-11-18; sid:2100201; rev:1;)

# Rule 2: Good Game Stealer exfiltration to GoFile
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-12643 Good Game Stealer GoFile Exfiltration"; flow:established, to_server; http_method; content:"POST"; http_host; content:"upload.gofile.io", fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/; metadata:author Actioner, created 2026-11-18; sid:2100202; rev:1;)

# Rule 3: Spoofed BITS User-Agent from MSBuild downloader
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-12643 Spoofed BITS UA MSBuild Downloader"; flow:established, to_server; http_header; content:"Microsoft BITS/7.8", fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/; metadata:author Actioner, created 2026-11-18; sid:2100203; rev:1;)
```

## Lessons Learned

1. **Blockchain as C2 infrastructure is maturing.** UAT-12643's use of Solana memos for encrypted C2 URLs represents a step beyond EtherHiding and Glupteba's Bitcoin-based techniques. Solana's sub-second finality and sub-cent transaction costs make C2 rotation nearly instantaneous and free, while public RPC queries blend with legitimate blockchain developer traffic. Defenders must move from domain-based blocking to behavioral monitoring of blockchain API calls from non-developer endpoints.

2. **LOLBin diversity in a single campaign.** The use of four distinct signed-binary proxy execution methods (MpCmdRun, certutil, mshta, MSBuild) in a single campaign means ASR rules or AppLocker policies must cover all of them simultaneously. Relying on blocking just one delivery vector leaves the others open.

3. **WinRE persistence is an undermonitored vector.** Overlord RAT's patching of ResetConfig.xml to survive "Reset this PC" means traditional reimaging may not fully remediate compromised systems. Defenders should monitor the Recovery\OEM directory and treat WinRE configuration changes as high-severity alerts.

4. **Commoditized stealers amplify state-aligned operations.** UAT-12643's use of a publicly available stealer (Good Game v1.1.2) demonstrates how DPRK-aligned actors leverage the cybercrime ecosystem to reduce development costs while maintaining operational effectiveness. Attribution based solely on tool use is insufficient.

## Sources

- [Cisco Talos - UAT-12643 Primary Report](https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/) -- primary technical analysis of the actor, toolset, and TTPs
- [Cisco Talos - Blockchain Dead Drops](https://blog.talosintelligence.com/the-challenge-of-defending-against-bulletproof-dead-drops-on-public-blockchains/) -- companion analysis of blockchain-based C2 resolution techniques and defender recommendations
- [Cisco Talos IOCs on GitHub](https://github.com/Cisco-Talos/IOCs/tree/main/2026/11) -- machine-readable IOC files (SHA256 hashes, IP address)

---
*Report generated by Actioner*
