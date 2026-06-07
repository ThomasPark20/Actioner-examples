# Technical Analysis Report: PHANTOMPULSE RAT — Blockchain-Based C2 via Obsidian Plugin Abuse (2026-06-07)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-07
Version: 0.1 (DRAFT)

## Executive Summary

PHANTOMPULSE is an AI-assisted Windows remote access trojan (RAT) discovered by Elastic Security Labs in their tracking of activity cluster REF6598. The malware implements a novel decentralized command-and-control (C2) resolution mechanism that queries Ethereum, Base, and Optimism blockchain transactions via public Blockscout APIs to dynamically resolve its C2 server address. The C2 URL is XOR-encrypted within on-chain transaction input data tied to a hardcoded wallet address (`0xc117688c530b660e15085bF3A2B664117d8672aA`). The campaign targets individuals in the financial and cryptocurrency sectors through elaborate social engineering via LinkedIn and Telegram, delivering the payload through trojanized Obsidian note-taking application plugins (Shell Commands and Hider).

PHANTOMPULSE capabilities include process injection (module stomping, manual DLL mapping, debug-driven execution), keylogging, screenshot capture, file upload/download, UAC bypass via COM elevation moniker, and comprehensive defense evasion through AMSI/ETW/WLDP bypass using hardware breakpoints. The intermediate loader (PHANTOMPULL, `syncobs.exe`) establishes persistence via scheduled tasks (`DotNetSvcUpdateTask`, `DotNetSvcCoreTask`, `DotNetSvcUserTask`) and drops `svcagent.dll` to `%ProgramData%\AssetMon\`. The threat cluster aligns closely with DPRK-linked groups including Lazarus, BlueNoroff, UNC5342 (Contagious Interview), and APT38. A critical design flaw in the blockchain C2 resolver — no sender verification — makes the implant hijackable by any party who knows the wallet address and XOR key, both recoverable from the binary.

## Background: Obsidian Plugin Ecosystem as Attack Vector

Obsidian is a cross-platform Markdown-based note-taking application with an extensive community plugin ecosystem. The Shell Commands plugin allows arbitrary shell execution from within Obsidian, and the Hider plugin can conceal UI elements including the settings panel. REF6598 abuses these legitimate plugins by distributing cloud-hosted Obsidian vaults with malicious JSON configuration files that automatically trigger code execution when the victim enables vault synchronization. The attack chain begins with social engineering on LinkedIn (posing as a venture capital firm) followed by migration to Telegram, where the victim is directed to open a shared vault.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-02 | C2 infrastructure `panel[.]fefea22134[.]net` provisioned with Let's Encrypt certificate (valid 2026-02-19 to 2026-05-20) |
| ~2026-03 | Social engineering campaigns initiated via LinkedIn targeting crypto/finance sector professionals |
| 2026-04-13 | Elastic Security Labs creates YARA signature `Windows.Trojan.PhantomPulse` |
| 2026-04-16 | Elastic Security Labs publishes initial analysis ("Phantom in the vault") |
| 2026-05-05 | Elastic updates YARA rule; publishes blockchain C2 sinkhole research |
| 2026-06-06 | SecurityOnline publishes PHANTOMPULSE analysis summary |

## Root Cause: Social Engineering via LinkedIn and Telegram

The attackers approach targets on LinkedIn posing as representatives of a venture capital firm, then migrate the conversation to a Telegram group. The victim is directed to clone or sync a cloud-hosted Obsidian vault containing pre-configured malicious plugins. When the vault is opened with community plugins enabled, the Shell Commands plugin's `data.json` configuration triggers automatic execution of a PowerShell download cradle that fetches `script1.ps1` from the staging server `195.3.222[.]251`, which in turn downloads and executes the PHANTOMPULL loader (`syncobs.exe`).

## Technical Analysis of the Malicious Payload

### 1. Initial Access — Obsidian Plugin Abuse

The malicious Obsidian vault contains a pre-configured `.obsidian/plugins/obsidian-shellcommands/data.json` that invokes shell commands on vault open. The Shell Commands plugin executes PowerShell (Windows) or bash/zsh/osascript (macOS) to download the next stage. The Hider plugin conceals evidence of the malicious configuration from the user interface.

**Windows execution chain:** `Obsidian.exe` -> `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden` -> downloads `script1.ps1` from `hxxp://195.3.222[.]251/script1.ps1` -> downloads and executes `syncobs.exe`.

**macOS variant:** Uses obfuscated AppleScript character ID encoding with domain list iteration and Telegram dead drop (`t[.]me/ax03bot`) as fallback C2 resolver; persistence via LaunchAgent `com.vfrfeufhtjpwgray.plist`.

### 2. PHANTOMPULL Loader (syncobs.exe)

The loader (`SHA256: 70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980`) establishes persistence through three scheduled tasks:
- `DotNetSvcUpdateTask` — user logon trigger + 3-minute interval, Standard RunLevel
- `DotNetSvcCoreTask` — boot trigger + 15-minute interval, HighestAvailable + Hidden (path: `\Microsoft\Windows\NetFramework\DotNetSvcCoreTask`)
- `DotNetSvcUserTask` — user logon trigger, Standard RunLevel

The payload `svcagent.dll` is dropped to `%ProgramData%\AssetMon\svcagent.dll` (primary), with fallback paths `%APPDATA%\AssetMon\svcagent.dll` and `%TEMP%\svcagent.dll`. A mutex `hVNBUORXNiFLhYYh` prevents multiple instances.

### 3. C2 Infrastructure — Blockchain Resolution

PHANTOMPULSE resolves its C2 endpoint through a three-chain blockchain dead drop mechanism:

1. Queries Blockscout APIs at `eth.blockscout.com`, `base.blockscout.com`, and `optimism.blockscout.com` using the endpoint pattern: `/api?module=account&action=txlist&address=<wallet>&page=1&offset=1&sort=desc`
2. Retrieves the latest transaction for wallet `0xc117688c530b660e15085bF3A2B664117d8672aA`
3. Extracts the transaction input data, verifies it starts with the 2-byte signature `580c` (hex)
4. XOR-decrypts the payload using a key derived from the wallet address bytes to obtain the C2 URL
5. Falls back to the hardcoded domain `panel.fefea22134.net` if blockchain resolution fails

**C2 API Endpoints:**
- `/v1/telemetry/report` (POST, application/json) — heartbeat with system telemetry
- `/v1/telemetry/tasks/<machine_id>` (GET) — command fetch
- `/v1/telemetry/upload/` (POST, image/bmp) — screenshot/file upload
- `/v1/telemetry/result` (POST, application/json) — command result delivery
- `/v1/telemetry/keylog/` (POST, text/plain) — keylog data upload
- `/v1/updates/check?build=payloads` — loader C2 endpoint

**User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`

**Vulnerability:** The resolver does not verify the sender of the transaction — it only checks that the decoded input starts with `http`. Any third party who knows the wallet address and XOR key (both recoverable from the binary) can craft a competing transaction to redirect all implants.

### 4. PHANTOMPULSE RAT Capabilities

**Command Dispatcher** (via djb2 hashing with seed `0x4E67C6A7`):

| djb2 Hash | Command | Function |
|-----------|---------|----------|
| `0x04CF1142` | `inject` | Process injection (shellcode/DLL/EXE) |
| `0x7C95D91A` | `drop` | File drop and execute |
| `0x9A37F083` | `screenshot` | Screenshot capture |
| `0x08DEDEF0` | `keylog` | Keylogger control |
| `0x4EE251FF` | `uninstall` | Persistence removal and cleanup |
| `0x65CCC50B` | `elevate` | UAC bypass via COM elevation moniker |
| `0xB3B5B880` | `downgrade` | Privilege downgrade |
| `0x20CE3BC8` | (unresolved) | Self-termination |

**Injection Methods:**
- **PhantomInject** — module stomping into legitimate DLLs (e.g., `dbghelp.dll`) for shellcode routing
- **ManualMap** — manual DLL mapping into remote processes
- **DbgNexum** — debug-driven EXE injection using Windows debugging interface

**Injection Targets:** `sihost.exe`, `taskhostw.exe`, `backgroundTaskHost.exe`, `RuntimeBroker.exe`, `dllhost.exe`, `ctfmon.exe`, `explorer.exe` (fallback: `cmd.exe`, `notepad.exe`)

**UAC Bypass:** COM elevation moniker `Elevation:Administrator!new:{A6BFEA43-501F-456F-A845-983D3AD7B8F0}`

### 5. Defense Evasion Techniques

- **AMSI bypass:** Hardware breakpoint on `AmsiScanBuffer` entry, spoofs return value `0x80070057` (E_INVALIDARG)
- **WLDP bypass:** Hardware breakpoint on `WldpQueryDynamicCodeTrust`, spoofs return `0`
- **ETW bypass:** Hardware breakpoint on `EtwEventWrite`, spoofs return `0`
- **Syscall evasion:** Constructs private syscall structures dynamically, bypassing user-mode API hooking
- **API hashing:** djb2 algorithm with custom seed for command dispatch
- **Encryption:** AES-256-CBC for payload encryption (key: `6a85736b64761a8b2aaeadc1c0087e1897d16cc5a9d49c6a6ea1164233bad206`, IV: `A6FA4ADFC20E8E6B77E2DD631DC8FF18`); XOR for string/URL obfuscation
- **Anti-tamper:** Dead code functions for anti-analysis
- **Timer queue callbacks:** 50ms delay execution to evade sandbox analysis
- **IP resolution:** Queries `api4.ipify[.]org`, `ipv4.icanhazip[.]com`, `checkip.amazonaws[.]com` for public IP; connectivity checks via `microsoft[.]com`, `google[.]com`, `cloudflare[.]com`, `github[.]com`

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs `hxxps://` or `hxxp://`; domains/IPs `[.]`; emails `[at]`.

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `syncobs.exe` | `70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980` | PHANTOMPULL loader |
| Windows | (in-memory) | `33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f` | PHANTOMPULSE RAT final payload |
| Windows | (reference sample) | `9e3890d43366faec26523edaf91712640056ea2481cdefe2f5dfa6b2b642085d` | PHANTOMPULSE reference sample |
| Windows | (Go beacon) | `def66275fa3baffb16e6e4ae0297861d9790ae7161fbc271a2ba05d121f13c70` | Go-based beacon component |
| Windows | `%ProgramData%\AssetMon\svcagent.dll` | — | Primary payload drop path |
| Windows | `%APPDATA%\AssetMon\svcagent.dll` | — | Fallback payload drop path |
| Windows | `%TEMP%\svcagent.dll` | — | Fallback payload drop path |
| Windows | `%TEMP%\tt.ps1` | — | Temporary PowerShell stage |
| Windows | `healthmon.exe` | — | Dropper executable |
| Windows | `diagcore.dll` | — | Legacy sideload DLL |
| Cross-platform | `.obsidian/plugins/obsidian-shellcommands/data.json` | — | Malicious plugin configuration |
| macOS | `~/Library/LaunchAgents/com.vfrfeufhtjpwgray.plist` | — | macOS persistence LaunchAgent |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `panel[.]fefea22134[.]net` | PHANTOMPULSE C2 panel (hardcoded fallback) |
| Domain | `fefea22134[.]net` | C2 domain (encrypted in binary) |
| Domain | `0x666[.]info` | macOS dropper C2 |
| Domain | `thoroughly-publisher-troy-clara[.]trycloudflare[.]com` | Prior C2 (Cloudflare Tunnel) |
| IP | `195.3.222[.]251` | Staging/payload delivery server (AS 201814, MEVSPACE, Poland) |
| URL | `hxxp://195.3.222[.]251/script1.ps1` | Stage 2 PowerShell download |
| URL | `hxxp://195.3.222[.]251/syncobs.exe` | Loader delivery |
| URL | `hxxp://195.3.222[.]251/stuk-phase` | Status reporting endpoint |
| Blockchain API | `eth[.]blockscout[.]com` | Ethereum L1 blockchain explorer (C2 resolution) |
| Blockchain API | `base[.]blockscout[.]com` | Base L2 blockchain explorer (C2 resolution) |
| Blockchain API | `optimism[.]blockscout[.]com` | Optimism L2 blockchain explorer (C2 resolution) |
| Telegram | `t[.]me/ax03bot` | macOS Telegram fallback C2 |
| Ethereum Wallet | `0xc117688c530b660e15085bF3A2B664117d8672aA` | C2 resolution wallet |
| Ethereum Wallet | `0x38796B8479fDAE0A72e5E7e326c87a637D0Cbc0E` | Funding wallet |

### Behavioral

- **Mutex:** `hVNBUORXNiFLhYYh` (single-instance check)
- **Scheduled Tasks:** `DotNetSvcUpdateTask`, `DotNetSvcCoreTask` (hidden, under `\Microsoft\Windows\NetFramework\`), `DotNetSvcUserTask`
- **Process Chain:** `Obsidian.exe` -> `powershell.exe` (`-ExecutionPolicy Bypass -WindowStyle Hidden`) -> `syncobs.exe` -> injection into system processes
- **Hardware Breakpoints:** DR0 on `WldpQueryDynamicCodeTrust`, DR1 on `AmsiScanBuffer`, DR2 on `EtwEventWrite`
- **COM Moniker:** `Elevation:Administrator!new:{A6BFEA43-501F-456F-A845-983D3AD7B8F0}` (UAC bypass)
- **C2 Protocol:** WinHTTP with Chrome/120 User-Agent; JSON telemetry on `/v1/telemetry/*` endpoints
- **Debug Strings:** `[HEIS] encrypt_text_only ENTER/DONE`, `PhantomInject: host PID=%lu`, `DbgNexumLoop64: stage 6 -> stub`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.003 | Phishing: Spearphishing via Service | LinkedIn/Telegram social engineering to deliver malicious Obsidian vault |
| T1204.002 | User Execution: Malicious File | Victim opens Obsidian vault triggering Shell Commands plugin |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell download cradle (`-ExecutionPolicy Bypass -WindowStyle Hidden`) |
| T1059.002 | Command and Scripting Interpreter: AppleScript | macOS variant uses obfuscated AppleScript |
| T1105 | Ingress Tool Transfer | Downloads `syncobs.exe` and `script1.ps1` from staging server |
| T1053.005 | Scheduled Task/Job: Scheduled Task | `DotNetSvcUpdateTask`, `DotNetSvcCoreTask`, `DotNetSvcUserTask` for persistence |
| T1547.011 | Boot or Logon Autostart Execution: Plist Modification | macOS persistence via LaunchAgent plist |
| T1055 | Process Injection | Module stomping, manual DLL mapping, DbgNexum debug injection |
| T1055.001 | Process Injection: DLL Injection | ManualMap DLL injection into remote processes |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | `diagcore.dll` sideloading |
| T1548.002 | Abuse Elevation Control: Bypass UAC | COM elevation moniker for privilege escalation |
| T1562.001 | Impair Defenses: Disable or Modify Tools | AMSI, ETW, WLDP bypass via hardware breakpoints |
| T1027 | Obfuscated Files or Information | XOR/AES encryption, API hashing, dead code |
| T1140 | Deobfuscate/Decode Files or Information | XOR decryption of C2 URLs, AES-256-CBC payload decryption |
| T1620 | Reflective Code Loading | In-memory PE execution, reflective loading |
| T1106 | Native API | Private syscall stubs bypassing user-mode hooks |
| T1497.003 | Virtualization/Sandbox Evasion: Time Based Evasion | 50ms timer queue callback delay |
| T1082 | System Information Discovery | System telemetry collection for C2 heartbeat |
| T1033 | System Owner/User Discovery | User information collected in telemetry |
| T1057 | Process Discovery | Enumerates processes for injection targets |
| T1518.001 | Software Discovery: Security Software Discovery | Identifies security tools for evasion |
| T1056.001 | Input Capture: Keylogging | Keylogger module (`keylog` command) |
| T1113 | Screen Capture | Screenshot capture and upload (`screenshot` command) |
| T1071.001 | Application Layer Protocol: Web Protocols | WinHTTP C2 over HTTPS with JSON/BMP payloads |
| T1102 | Web Service | Blockchain explorers (Blockscout) as dead drop for C2 resolution |
| T1573 | Encrypted Channel | AES-256-CBC encrypted C2 communications |
| T1041 | Exfiltration Over C2 Channel | Data exfiltration via same C2 HTTP endpoints |

## Impact Assessment

PHANTOMPULSE targets the financial and cryptocurrency sectors, with primary goals of cryptocurrency wallet theft, messaging database exfiltration, and persistent access for intelligence collection. The blockchain-based C2 mechanism provides resilience against takedown — shutting down the hardcoded C2 domain does not sever command capability as long as the attacker can post new transactions to the monitored wallet. The use of three independent blockchains (Ethereum, Base, Optimism) adds redundancy. However, the lack of sender verification in the blockchain resolver is a critical design flaw that enables defensive sinkholing by anyone who can submit a competing transaction with a researcher-controlled URL. Infrastructure is hosted at MEVSPACE (AS 201814, Poland) with Cloudflare proxying.

## Detection & Remediation

### Immediate Detection

1. **Search for PHANTOMPULSE artifacts:**
   - Check for scheduled tasks: `schtasks /query /tn DotNetSvcUpdateTask`, `schtasks /query /tn DotNetSvcCoreTask`, `schtasks /query /tn DotNetSvcUserTask`
   - Check for payload drops: `dir /s "%ProgramData%\AssetMon\svcagent.dll"` and `dir /s "%APPDATA%\AssetMon\svcagent.dll"`
   - Search for mutex: tools like Process Explorer for handle `hVNBUORXNiFLhYYh`
2. **Network monitoring:** Alert on DNS queries to `fefea22134.net`, `0x666.info`, and HTTP(S) traffic to `195.3.222.251`
3. **Obsidian vault inspection:** Check `.obsidian/plugins/obsidian-shellcommands/data.json` for suspicious shell commands

### Remediation

1. **Containment:** Isolate affected hosts; block C2 domains and staging IP at perimeter
2. **Eradication:** Remove scheduled tasks (`DotNetSvcUpdateTask`, `DotNetSvcCoreTask`, `DotNetSvcUserTask`); delete `svcagent.dll` from all drop paths; remove malicious Obsidian plugins
3. **Credential rotation:** Rotate all credentials accessible from compromised hosts; revoke cryptocurrency wallet keys
4. **macOS:** Remove `~/Library/LaunchAgents/com.vfrfeufhtjpwgray.plist`

### Long-Term Hardening

1. Restrict Obsidian community plugin installation to vetted plugins only; disable automatic plugin sync from untrusted vaults
2. Monitor for unusual DNS queries to blockchain explorer APIs from non-developer endpoints
3. Deploy endpoint detection for hardware breakpoint abuse (DR0-DR3 modifications across processes)
4. Block or alert on PowerShell execution with `-ExecutionPolicy Bypass -WindowStyle Hidden` spawned from non-standard parent processes

## Detection Rules

These detections target PHANTOMPULSE RAT artifacts at the PoC/advisory-specific altitude: known file paths, scheduled task names, C2 domains/endpoints, and malware debug strings. Compiles does not equal fires — verify each rule against your telemetry pipeline before production deployment.

### Sigma: PHANTOMPULSE Loader via Obsidian Plugin

Detects PowerShell or cmd.exe spawned by Obsidian.exe with command-line arguments consistent with the REF6598 PHANTOMPULSE delivery chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on ParentImage Obsidian.exe + child powershell/cmd with syncobs/script1/tt.ps1/-ExecutionPolicy Bypass. FP: legitimate Shell Commands plugin users — low volume, easy to triage. -->
```yaml
title: PHANTOMPULSE RAT Loader Execution via Obsidian Plugin Abuse
id: 8c3f2e1a-7b4d-4a9e-b6c5-d1e2f3a4b5c6
status: experimental
description: >
    Detects the PHANTOMPULSE loader (syncobs.exe) spawned as a child of Obsidian.exe,
    consistent with REF6598 campaign abusing Obsidian Shell Commands plugin for initial
    code execution.
references:
    - https://www.elastic.co/security-labs/phantom-in-the-vault
    - https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole
author: Actioner
date: 2026/06/07
tags:
    - attack.t1059.001
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\Obsidian.exe'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
        CommandLine|contains:
            - 'syncobs'
            - 'script1.ps1'
            - 'tt.ps1'
            - '-ExecutionPolicy Bypass'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Obsidian Shell Commands plugin usage by developers
level: high
```

### Sigma: PHANTOMPULSE Scheduled Task Persistence

Detects creation of the specific scheduled task names (`DotNetSvcUpdateTask`, `DotNetSvcCoreTask`, `DotNetSvcUserTask`) used by PHANTOMPULSE for persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Task names are campaign-specific; no known benign use. -->
```yaml
title: PHANTOMPULSE Persistence via DotNetSvc Scheduled Tasks
id: 4a2b1c3d-5e6f-7a8b-9c0d-e1f2a3b4c5d6
status: experimental
description: >
    Detects creation of scheduled tasks with names used by PHANTOMPULSE for persistence,
    including DotNetSvcUpdateTask, DotNetSvcCoreTask, and DotNetSvcUserTask.
references:
    - https://www.elastic.co/security-labs/phantom-in-the-vault
    - https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole
author: Actioner
date: 2026/06/07
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - 'DotNetSvcUpdateTask'
            - 'DotNetSvcCoreTask'
            - 'DotNetSvcUserTask'
    condition: selection_schtasks
falsepositives:
    - Unlikely - these task names are specific to PHANTOMPULSE
level: high
```

### Sigma: PHANTOMPULSE Payload Drop to AssetMon Directory

Detects file creation of `svcagent.dll` in the `AssetMon` directory, the primary payload staging path used by PHANTOMPULSE.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Path AssetMon\svcagent.dll is campaign-unique. No benign software uses this path. -->
```yaml
title: PHANTOMPULSE RAT Payload Drop to AssetMon Directory
id: 7f8e9d0c-1b2a-3c4d-5e6f-a7b8c9d0e1f2
status: experimental
description: >
    Detects file creation of svcagent.dll in the AssetMon directory paths used by
    PHANTOMPULSE for persistence and payload staging.
references:
    - https://www.elastic.co/security-labs/phantom-in-the-vault
    - https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole
author: Actioner
date: 2026/06/07
tags:
    - attack.t1027
    - attack.t1105
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\AssetMon\svcagent.dll'
    condition: selection
falsepositives:
    - Unlikely - AssetMon\svcagent.dll is a PHANTOMPULSE-specific artifact
level: critical
```

### Sigma: PHANTOMPULSE Blockchain C2 Resolution via Blockscout

Detects DNS queries to Blockscout blockchain explorer domains used by PHANTOMPULSE for decentralized C2 address resolution. Scope to non-developer endpoints to reduce false positives from legitimate blockchain researchers.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Blockscout domains are legitimate services; FP from blockchain developers/researchers. Medium confidence due to benign overlap — pair with other PHANTOMPULSE indicators for higher fidelity. -->
```yaml
title: PHANTOMPULSE Blockchain C2 Resolution via Blockscout API
id: 3e4d5c6b-7a8f-9e0d-1c2b-a3b4c5d6e7f8
status: experimental
description: >
    Detects DNS queries to Blockscout blockchain explorer domains used by PHANTOMPULSE
    for decentralized C2 resolution across Ethereum, Base, and Optimism chains.
references:
    - https://www.elastic.co/security-labs/phantom-in-the-vault
    - https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole
author: Actioner
date: 2026/06/07
tags:
    - attack.t1102
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName:
            - 'eth.blockscout.com'
            - 'base.blockscout.com'
            - 'optimism.blockscout.com'
    condition: selection
falsepositives:
    - Legitimate blockchain developers and researchers using Blockscout APIs
    - Cryptocurrency portfolio tracking applications
level: medium
```

### Sigma: PHANTOMPULSE Known C2 Domain

Detects DNS resolution of the known PHANTOMPULSE C2 panel domain `fefea22134.net`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Domain is campaign-specific, no benign use. endswith catches panel.fefea22134.net and any subdomain. -->
```yaml
title: PHANTOMPULSE C2 Domain DNS Query
id: 9a0b1c2d-3e4f-5a6b-7c8d-e9f0a1b2c3d4
status: experimental
description: >
    Detects DNS queries to the known PHANTOMPULSE C2 panel domain panel.fefea22134.net,
    used for command retrieval and telemetry exfiltration.
references:
    - https://www.elastic.co/security-labs/phantom-in-the-vault
    - https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole
author: Actioner
date: 2026/06/07
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'fefea22134.net'
    condition: selection
falsepositives:
    - None expected
level: critical
```

### Snort: PHANTOMPULSE C2 HTTP Telemetry

Detects outbound HTTP POST to the PHANTOMPULSE C2 telemetry report endpoint (`/v1/telemetry/report`), task fetch (`/v1/telemetry/tasks/`), and keylog upload (`/v1/telemetry/keylog/`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c snort.conf -R pp.rules -T exit 0 (Snort 2.9.20). Three rules covering telemetry beacon, task fetch, and keylog upload. URI paths are campaign-specific. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - PHANTOMPULSE C2 Telemetry Report Beacon"; flow:established,to_server; content:"/v1/telemetry/report"; http_uri; fast_pattern; content:"application/json"; http_header; sid:2100001; rev:1; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/phantom-in-the-vault;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - PHANTOMPULSE C2 Task Fetch"; flow:established,to_server; content:"GET"; http_method; content:"/v1/telemetry/tasks/"; http_uri; fast_pattern; sid:2100002; rev:1; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/phantom-in-the-vault;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - PHANTOMPULSE C2 Keylog Upload"; flow:established,to_server; content:"/v1/telemetry/keylog/"; http_uri; fast_pattern; content:"text/plain"; http_header; sid:2100003; rev:1; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/phantom-in-the-vault;)
```

### Suricata: PHANTOMPULSE C2 HTTP and DNS

Detects PHANTOMPULSE C2 traffic patterns: HTTP POST to telemetry endpoints, GET for task fetch, keylog uploads, and DNS resolution of the known C2 domain `fefea22134.net`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S phantompulse-suricata.rules -l /tmp/actioner exit 0 (Suricata 7.0.3). Four rules: telemetry beacon, task fetch, keylog upload, C2 domain DNS. dot-notation buffers throughout. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PHANTOMPULSE C2 Telemetry Report Beacon"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/v1/telemetry/report"; fast_pattern; http.content_type; content:"application/json"; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/phantom-in-the-vault; metadata:author Actioner, created_at 2026-06-07; sid:2200001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PHANTOMPULSE C2 Task Fetch"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/v1/telemetry/tasks/"; fast_pattern; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/phantom-in-the-vault; metadata:author Actioner, created_at 2026-06-07; sid:2200002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PHANTOMPULSE C2 Keylog Upload"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/v1/telemetry/keylog/"; fast_pattern; http.content_type; content:"text/plain"; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/phantom-in-the-vault; metadata:author Actioner, created_at 2026-06-07; sid:2200003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - PHANTOMPULSE Known C2 Domain fefea22134.net"; dns.query; content:"fefea22134.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/phantom-in-the-vault; metadata:author Actioner, created_at 2026-06-07; sid:2200004; rev:1;)
```

### YARA: PHANTOMPULSE RAT Debug Strings

Detects PHANTOMPULSE RAT PE binaries via characteristic AI-generated debug strings including injection method identifiers, uninstall step markers, and module names. Published strings sourced from Elastic Security Labs analysis.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos.txt matched Malware_PHANTOMPULSE_RAT_Strings; neg.txt silent. Strings from Elastic's published analysis and YARA rule (eaaa34fb). 3-of-8 threshold balances coverage across variants while maintaining specificity. -->
```yara
rule Malware_PHANTOMPULSE_RAT_Strings
{
    meta:
        description = "Detects PHANTOMPULSE RAT via characteristic debug strings found in samples"
        author = "Actioner"
        date = "2026-06-07"
        reference = "https://www.elastic.co/security-labs/phantom-in-the-vault"
        hash = "33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f"
        hash2 = "9e3890d43366faec26523edaf91712640056ea2481cdefe2f5dfa6b2b642085d"
        severity = "critical"

    strings:
        $a = "[UNINSTALL 2/6] Removing Scheduled Task..." ascii fullword
        $b = "PhantomInject: host PID=%lu" ascii fullword
        $c = "inject: shellcode detected -> InjectShellcodePhantom" ascii fullword
        $d = "inject: shellcode detected, using phantom section hijack" ascii fullword
        $e = "[HEIS] encrypt_text_only ENTER" ascii
        $f = "DbgNexumLoop64: stage 6 -> stub" ascii
        $g = "ManualMap: thread hijacked and resumed" ascii
        $h = "UnhookNtdll: ntdll base = %p" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        3 of them
}

rule Malware_PHANTOMPULSE_Loader_SyncObs
{
    meta:
        description = "Detects PHANTOMPULL loader (syncobs.exe) used in REF6598 campaign"
        author = "Actioner"
        date = "2026-06-07"
        reference = "https://www.elastic.co/security-labs/phantom-in-the-vault"
        hash = "70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980"
        severity = "high"

    strings:
        $mutex = "hVNBUORXNiFLhYYh" ascii fullword
        $task1 = "DotNetSvcUpdateTask" ascii fullword
        $task2 = "DotNetSvcCoreTask" ascii fullword
        $task3 = "DotNetSvcUserTask" ascii fullword
        $path = "\\AssetMon\\svcagent.dll" ascii
        $api1 = "/v1/telemetry/report" ascii
        $api2 = "/v1/telemetry/tasks/" ascii
        $api3 = "/v1/updates/check?build=payloads" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($mutex or 2 of ($task*) or ($path and 1 of ($api*)))
}
```

## Lessons Learned

1. **Blockchain as C2 infrastructure is a growing trend.** Public, immutable, censorship-resistant ledgers provide ideal dead-drop infrastructure for malware C2 resolution. Traditional domain takedown is ineffective; defenders must monitor for anomalous blockchain API queries from non-developer endpoints.

2. **Legitimate application plugin ecosystems are expanding the attack surface.** Obsidian's community plugin model — like VS Code extensions, browser extensions, and IDE plugins before it — allows code execution with the user's full permissions. Organizations should audit and restrict plugin installations in productivity tools.

3. **AI-assisted malware development lowers the barrier.** The verbose debug strings and code structure in PHANTOMPULSE suggest AI-assisted development, enabling threat actors to produce sophisticated capability (hardware breakpoint AMSI bypass, multi-chain blockchain resolution, multiple injection techniques) more rapidly.

4. **Design flaws enable defensive opportunity.** The lack of sender verification in the blockchain C2 resolver is a significant design weakness that enables defensive sinkholing — a single transaction can redirect all implants to a researcher-controlled server.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Elastic Security Labs — Phantom in the vault: Obsidian abused to deliver PhantomPulse RAT](https://www.elastic.co/security-labs/phantom-in-the-vault) — primary technical analysis of REF6598 campaign, IOCs, MITRE mapping, YARA rules
- [Elastic Security Labs — PHANTOMPULSE: anatomy of a hijackable blockchain-C2 RAT](https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole) — blockchain C2 mechanism deep-dive, sinkhole research, additional IOCs
- [The Hacker News — Obsidian Plugin Abuse Delivers PHANTOMPULSE RAT](https://thehackernews.com/2026/04/obsidian-plugin-abuse-delivers.html) — news coverage of the campaign
- [SecurityOnline — PHANTOMPULSE Malware Analysis](https://securityonline.info/obsidian-phantompulse-malware-blockchain-c2-ref6598/) — supplementary analysis of blockchain C2 and evasion techniques
- [CybersecurityNews — PHANTOMPULSE RAT Uses Process Injection and UAC Bypass](https://cybersecuritynews.com/phantompulse-rat-uses-process-injection-and-uac-bypass/) — coverage of injection and privilege escalation techniques

---
*Report generated by Actioner*
