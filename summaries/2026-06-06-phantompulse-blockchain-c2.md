# Technical Analysis Report: PHANTOMPULSE Blockchain-C2 RAT (2026-06-06)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-06
Version: 1.1 (FINAL)

## Executive Summary

PHANTOMPULSE is an advanced Remote Access Trojan attributed to DPRK-aligned threat clusters (Lazarus, BlueNoroff, UNC5342/Contagious Interview, APT38) that employs a novel blockchain-based command-and-control resolver, three process injection techniques, and hardware-breakpoint-based AMSI/WLDP/ETW bypass. Delivered through the REF6598 campaign, which abuses the Obsidian note-taking application's community plugin ecosystem via social engineering on LinkedIn and Telegram, PHANTOMPULSE targets individuals in the financial and cryptocurrency sectors. The malware demonstrates indicators of AI-assisted development including structured debug strings and verbose function tracing patterns.

A critical design flaw in the blockchain C2 resolver -- the absence of sender verification for transactions -- allows defenders to redirect the entire botnet to a sinkhole by posting a single on-chain transaction with a more recent timestamp containing a sinkhole URL.

## Background: REF6598 Campaign

The REF6598 intrusion set targets cryptocurrency and financial sector personnel through elaborate social engineering. Threat actors impersonate venture capital firms on LinkedIn and Telegram, directing victims to open attacker-controlled Obsidian vaults with the Shell Commands community plugin enabled. The plugin silently executes base64-encoded PowerShell (Windows) or AppleScript (macOS) to download and execute the PHANTOMPULL loader (`syncobs.exe`), which stages the PHANTOMPULSE RAT payload in memory via reflective PE loading. The campaign is cross-platform, with parallel macOS tooling using LaunchAgent persistence and a Telegram-channel-based fallback C2.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-02-19 | Let's Encrypt certificate issued for C2 infrastructure (serial: `5130b76e63cd41f11e6b7c2a77f203f72b4`) |
| 2026-04 (est.) | Social engineering campaign begins targeting crypto/finance individuals via LinkedIn and Telegram |
| 2026-04-16 | Elastic Security Labs publishes initial REF6598 delivery analysis ("Phantom in the vault") |
| 2026-04 (est.) | Elastic Security Labs publishes PHANTOMPULSE deep-dive ("anatomy of a hijackable blockchain-C2 RAT") |

## Root Cause: Social Engineering via Obsidian Plugin Abuse

Threat actors exploit the trust model of Obsidian's community plugin ecosystem. Victims receive a shared vault URL containing two pre-configured plugins: **Shell Commands** (`obsidian-shellcommands`) which enables arbitrary command execution, and **Hider** (`obsidian-hider` v1.6.1) which conceals UI elements indicating plugin activity. When the victim enables community plugins and synchronizes the vault, the Shell Commands plugin executes a base64-encoded payload that downloads the loader via `BitsTransfer` (Windows) or `curl`/`osascript` (macOS).

## Technical Analysis of the Malicious Payload

### 1. Initial Loader (PHANTOMPULL / syncobs.exe)

The PHANTOMPULL loader (`SHA256: 70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980`) is downloaded to `%TEMP%\syncobs.exe`. It uses a timer queue callback with a 50ms delay to evade sandbox detection, employs DJB2 hashing (seed `0x4E67C6A7`) for dynamic API resolution, and includes dead code guards comparing `GetTickCount()` to `0xFFFFFFFE` as anti-analysis. The loader fetches the PHANTOMPULSE payload from `/v1/updates/check?build=payloads`, decrypts it using AES-256-CBC (key: `6a85736b64761a8b2aaeadc1c0087e1897d16cc5a9d49c6a6ea1164233bad206`, IV: `A6FA4ADFC20E8E6B77E2DD631DC8FF18`), and reflectively loads the PE in memory without writing to disk.

### 2. PHANTOMPULSE RAT Core

The final payload (`SHA256: 33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f`) implements an 8-command dispatch table routed by DJB2 hash values:

| Hash | Command | Behavior |
|------|---------|----------|
| `0x04CF1142` | inject | Shellcode via PhantomInject, DLLs via ManualMap, EXEs via DbgNexum |
| `0x7C95D91A` | drop | File-to-disk execution (DLL, EXE, shellcode via APC, MSI) |
| `0x9A37F083` | screenshot | GDI capture, downscale to 960px, upload as BMP |
| `0x08DEDEF0` | keylog | Start/stop inline keylogger |
| `0x4EE251FF` | uninstall | 6-step cleanup and self-deletion |
| `0x65CCC50B` | elevate | UAC bypass via schuac technique |
| `0xB3B5B880` | downgrade | SYSTEM to elevated admin transition |
| `0x20CE3BC8` | (unnamed) | Self-restart via `NtTerminateProcess(-1, 0)` |

**Persistence** is achieved via three scheduled tasks registered through COM `ITaskService`:
- `DotNetSvcUpdateTask` (3-min interval, user logon trigger)
- `DotNetSvcCoreTask` (15-min interval, boot trigger, hidden, under `\Microsoft\Windows\NetFramework\`)
- `DotNetSvcUserTask` (user logon trigger)

All tasks execute `rundll32.exe "<stub_dll>",DllRegisterServer` where the stub DLL (`svcagent.dll`) is dropped to `%ProgramData%\AssetMon\`, `%APPDATA%\AssetMon\`, or `%TEMP%\`.

**Process Injection** ships three variants:
- **PhantomInject**: Module stomping -- maps `dbghelp.dll` as `SEC_IMAGE` into target processes (`sihost.exe`, `taskhostw.exe`, `backgroundTaskHost.exe`, `RuntimeBroker.exe`, `dllhost.exe`, `ctfmon.exe`, `explorer.exe`), overwrites `.text` section with shellcode, hijacks thread via context manipulation.
- **DbgNexum**: Verbatim from public PoC (`dis0rder0x00/DbgNexum`). Drives execution through Windows Debug API exception interception; no direct memory writes to target.
- **ManualMap**: Classic PE manual mapping with base relocation, import resolution, header wiping, and per-section memory protection.

### 3. C2 Infrastructure

**Blockchain C2 Resolution**: PHANTOMPULSE queries three Blockscout API instances:
- `eth[.]blockscout[.]com` (Ethereum L1)
- `base[.]blockscout[.]com` (Base L2)
- `optimism[.]blockscout[.]com` (Optimism L2)

The query pattern is `GET /api?module=account&action=txlist&address=<wallet>&page=1&offset=1&sort=desc`. The `input` field of the latest transaction is hex-decoded, XOR-decrypted using the wallet address bytes as key, and validated to begin with `http`. The C2 resolver wallet is `0xc117688c530b660e15085bF3A2B664117d8672aA`, funded from `0x38796B8479fDAE0A72e5E7e326c87a637D0Cbc0E`.

**Cryptographic hunting signature**: XOR-ing `ht` (start of `http`) against `0x` (start of wallet address) always yields `\x58\x0c`, so all encrypted transaction inputs begin with hex `580c`.

**Fallback C2**: Hardcoded domain `panel[.]fefea22134[.]net` (Cloudflare-proxied).

**API Endpoints** (5 paths, re-encrypted per session):
- `/v1/telemetry/report` (POST, `application/json`) -- heartbeat
- `/v1/telemetry/tasks/<machine_id>` (GET) -- command fetch
- `/v1/telemetry/upload/` (POST, `image/bmp`) -- screenshot/file upload
- `/v1/telemetry/result` (POST, `application/json`) -- result delivery
- `/v1/telemetry/keylog/` (POST, `text/plain`) -- keylog exfiltration

**Loop cadence**: Random sleep [20, 40] seconds between iterations; 10 consecutive heartbeat failures trigger self-restart; blockchain re-resolution on failure.

### 4. Platform-Specific Behavior

#### Windows
- Full-featured RAT with 8 commands, 3 injection techniques, scheduled task persistence
- UAC bypass via schuac technique using COM elevation moniker (`CLSID {A6BFEA43-501F-456F-A845-983D3AD7B8F0}`)
- DLL sideload migration: hunts running processes for `diagcore.dll` and overwrites

#### macOS
- Go-based beacon (GTESTIC_WIN, `SHA256: def66275fa3baffb16e6e4ae0297861d9790ae7161fbc271a2ba05d121f13c70`)
- LaunchAgent persistence at `~/Library/LaunchAgents/com.vfrfeufhtjpwgray.plist`
- Fallback C2 via Telegram channel `t[.]me/ax03bot`
- C2 domain: `0x666[.]info`

### 5. Anti-Forensics / Evasion Techniques

**Hardware Breakpoint AMSI/WLDP/ETW Bypass** -- a single shared primitive using DR0-DR3 debug registers:
- **DR0**: `WldpQueryDynamicCodeTrust` -- spoofed return `0` (S_OK)
- **DR1**: `AmsiScanBuffer` -- spoofed return `0x80070057` (E_INVALIDARG)
- **DR2**: `EtwEventWrite` -- spoofed return `0` (STATUS_SUCCESS)

A helper thread suspends the target, programs DR registers via `NtGetContextThread`/`NtSetContextThread`, and a vectored exception handler intercepts `Debug Exception` on API entry, modifying `CONTEXT.Rax` to the spoofed value and redirecting `CONTEXT.Rip` past the thunk. The handler is registered via a runtime-allocated `MEM_PRIVATE` page with `FF 25 00 00 00 00` indirect jump to avoid prologue signatures.

**Direct Syscalls**: Extracts System Service Numbers from ntdll function prologues via PEB walk with DJB2 hashing, wrapping `NtCreateFile`, `NtWriteFile`, `NtClose`, `NtCreateSection`, `NtMapViewOfSection`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`.

**String Obfuscation**: Four XOR encryption layers with rotating keys including a 16-byte key `F7 7C 8E 40 DF C1 7B E5 E7 4D 86 79 D5 B3 53 41` for C2 fallback/mutex/filenames, and an 8-byte key `5A 3C 7E 1D 9F 2B 4E 8A` for blockchain hostnames (UTF-16 LE).

**Sandbox Detection**: DJB2-hash table brute-forced against sandbox persona names including `WDAGUtilityAccount`, Joe Sandbox personas (`abby`, `patex`, `george`, `john`, `lisa`, `frank`, `RDhJ0CNFevzX`), and VM default names.

**Self-Healing**: Iteration-based persistence verification (iteration 2, then every 10th) re-checks registry artifacts, scheduled tasks, and AV inventory.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation: URLs use `hxxps://`, domains use `[.]`, IP addresses use `[.]`.

### File System

| Platform | Path / Name | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | syncobs.exe | `70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980` | PHANTOMPULL loader |
| Windows | (in-memory) | `33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f` | PHANTOMPULSE RAT payload |
| Windows/macOS | (Go beacon) | `def66275fa3baffb16e6e4ae0297861d9790ae7161fbc271a2ba05d121f13c70` | GTESTIC_WIN check-in |
| Windows | `%ProgramData%\AssetMon\svcagent.dll` | -- | Persistence stub DLL |
| Windows | `%APPDATA%\AssetMon\svcagent.dll` | -- | Alternate persistence stub |
| macOS | `~/Library/LaunchAgents/com.vfrfeufhtjpwgray.plist` | -- | LaunchAgent persistence |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `panel[.]fefea22134[.]net` | Primary C2 panel (hardcoded fallback) |
| Domain | `fefea22134[.]net` | C2 domain (encrypted in binary) |
| Domain | `0x666[.]info` | macOS C2 |
| Domain | `thoroughly-publisher-troy-clara[.]trycloudflare[.]com` | Previous C2 (Cloudflare Tunnel) |
| IP | `195[.]3[.]222[.]251` | Staging server (AS 201814, Polish hosting) |
| URL Pattern | `/v1/telemetry/report` | Heartbeat endpoint |
| URL Pattern | `/v1/telemetry/tasks/<id>` | Command fetch |
| URL Pattern | `/v1/telemetry/upload/` | Screenshot/file upload |
| URL Pattern | `/v1/telemetry/keylog/` | Keylog exfiltration |
| URL Pattern | `/v1/updates/check?build=payloads` | Loader payload fetch |
| Telegram | `t[.]me/ax03bot` | macOS fallback C2 channel |

### Blockchain

| Type | Value | Context |
|------|-------|---------|
| Ethereum Wallet | `0xc117688c530b660e15085bF3A2B664117d8672aA` | C2 resolver wallet |
| Ethereum Wallet | `0x38796B8479fDAE0A72e5E7e326c87a637D0Cbc0E` | Funding wallet |
| Blockchain API | `eth[.]blockscout[.]com` | Ethereum L1 C2 resolver |
| Blockchain API | `base[.]blockscout[.]com` | Base L2 C2 resolver |
| Blockchain API | `optimism[.]blockscout[.]com` | Optimism L2 C2 resolver |
| Tx Input Signature | `580c` (hex prefix) | All encrypted C2 URLs start with this |

### Behavioral

- Mutex: `hVNBUORXNiFLhYYh` (XOR-decrypted single-instance check)
- Scheduled Tasks: `DotNetSvcUpdateTask`, `DotNetSvcCoreTask`, `DotNetSvcUserTask`
- Scheduled Task Path: `\Microsoft\Windows\NetFramework\DotNetSvcCoreTask`
- Elevation marker: `.elevate` file in working directory
- Rundll32 invocation: `rundll32.exe "<path>\svcagent.dll",DllRegisterServer`
- COM elevation moniker: `Elevation:Administrator!new:{A6BFEA43-501F-456F-A845-983D3AD7B8F0}`
- Debug register programming: DR0-DR3 writes via `NtSetContextThread`
- Module stomping: `dbghelp.dll` mapped as `SEC_IMAGE` into host processes
- Named section literal: `"MZ"` (two-byte string, DbgNexum technique)
- XOR encryption key: `F7 7C 8E 40 DF C1 7B E5 E7 4D 86 79 D5 B3 53 41`
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`

### Encryption Keys

| Key | Value | Usage |
|-----|-------|-------|
| AES-256-CBC Key | `6a85736b64761a8b2aaeadc1c0087e1897d16cc5a9d49c6a6ea1164233bad206` | Loader payload decryption |
| AES IV | `A6FA4ADFC20E8E6B77E2DD631DC8FF18` | Loader payload decryption |
| XOR Key (16-byte) | `F7 7C 8E 40 DF C1 7B E5 E7 4D 86 79 D5 B3 53 41` | C2 fallback, mutex, filenames |
| XOR Key (8-byte) | `5A 3C 7E 1D 9F 2B 4E 8A` | Blockchain hostnames (UTF-16 LE) |
| XOR Payload Key | `dcf5a9b27cbeedb769ccc8635d204af9` | Payload encryption |
| Keylog XOR Seed | `0xE95CA237` | Keylog file encryption |

### TLS Certificate

| Field | Value |
|-------|-------|
| Serial | `5130b76e63cd41f11e6b7c2a77f203f72b4` |
| Thumbprint | `6c0a1da746438d68f6c4ffbf9a10e873f3cf0499` |
| Validity | 2026-02-19 to 2026-05-20 |
| Issuer | Let's Encrypt |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.003 | Spearphishing via Service | Social engineering on LinkedIn and Telegram impersonating VC firms |
| T1204.002 | User Execution: Malicious File | Victims enable Obsidian community plugins loading malicious vault |
| T1059.001 | PowerShell | Base64-encoded PowerShell via Shell Commands plugin |
| T1059.002 | AppleScript | macOS payload delivery via osascript |
| T1055.001 | DLL Injection | PhantomInject module stomping, ManualMap PE injection |
| T1055 | Process Injection | Three injection techniques: PhantomInject, DbgNexum, ManualMap |
| T1053.005 | Scheduled Task/Job | Three persistent scheduled tasks via COM ITaskService |
| T1218.011 | Rundll32 | Persistence via `rundll32.exe svcagent.dll,DllRegisterServer` |
| T1548.002 | Bypass UAC | schuac technique via COM elevation moniker |
| T1562.001 | Disable or Modify Tools | AMSI, WLDP, ETW bypass via hardware breakpoints |
| T1106 | Native API | Direct syscalls bypassing ntdll hooks |
| T1620 | Reflective Code Loading | In-memory PE loading without disk writes |
| T1102 | Web Service | Blockchain (Blockscout) used as dead-drop C2 resolver |
| T1071.001 | Web Protocols | HTTPS C2 with JSON/BMP/plaintext payloads |
| T1573 | Encrypted Channel | XOR and AES-encrypted C2 communications |
| T1027 | Obfuscated Files | Four-layer XOR string encryption, DJB2 API hashing |
| T1056.001 | Keylogging | Inline keylogger via `GetAsyncKeyState` |
| T1115 | Clipboard Data | Clipboard monitoring via `GetClipboardData` (CF_UNICODETEXT) |
| T1113 | Screen Capture | GDI-based screenshot capture, BMP upload |
| T1082 | System Information Discovery | CPU, GPU, RAM, OS, username, privilege enumeration |
| T1518.001 | Security Software Discovery | AV product detection against 25-30 vendor process names |
| T1497.003 | Time Based Evasion | GetTickCount dead code guards, timer queue delayed execution |
| T1574.002 | DLL Side-Loading | Hunts for `diagcore.dll` in running process directories to overwrite |
| T1070.004 | File Deletion | 6-step uninstall with artifact cleanup |

## Impact Assessment

PHANTOMPULSE presents a significant threat to the cryptocurrency and financial sectors. The malware's cross-platform capabilities (Windows full RAT, macOS Go beacon), combined with sophisticated social engineering through professional networking platforms and the novel blockchain C2 resolver, make detection challenging. The presence of cryptocurrency wallet enumeration (Ledger, Trezor, Bitcoin Core, Electrum, Exodus, Atomic, Guarda) and messenger application targeting (Telegram, Discord, Signal) aligns with DPRK financial theft operations. The blockchain C2 mechanism provides resilience against domain takedowns but introduces a critical vulnerability: the absence of sender verification allows defenders to hijack the botnet via a single on-chain transaction.

## Detection & Remediation

### Immediate Detection

```
# Check for PHANTOMPULSE scheduled tasks
schtasks /query /tn "DotNetSvcUpdateTask" 2>nul
schtasks /query /tn "DotNetSvcCoreTask" 2>nul
schtasks /query /tn "DotNetSvcUserTask" 2>nul
schtasks /query /tn "\Microsoft\Windows\NetFramework\DotNetSvcCoreTask" 2>nul

# Check for persistence DLL
dir /s "%ProgramData%\AssetMon\svcagent.dll" 2>nul
dir /s "%APPDATA%\AssetMon\svcagent.dll" 2>nul

# Check for elevation marker
dir /s ".elevate" 2>nul

# Check for mutex (via handle.exe from Sysinternals)
handle.exe -a "hVNBUORXNiFLhYYh" 2>nul

# Check for Obsidian Shell Commands plugin abuse
dir /s "%APPDATA%\obsidian\*obsidian-shellcommands*" 2>nul

# macOS: Check for LaunchAgent
ls -la ~/Library/LaunchAgents/com.vfrfeufhtjpwgray.plist 2>/dev/null
```

### Remediation

1. **Containment**: Isolate affected hosts; block C2 domains (`fefea22134[.]net`, `0x666[.]info`) and IP (`195[.]3[.]222[.]251`) at perimeter
2. **Eradication**: Remove scheduled tasks (`DotNetSvcUpdateTask`, `DotNetSvcCoreTask`, `DotNetSvcUserTask`), delete `svcagent.dll` from AssetMon directories, remove `.elevate` marker, kill `healthmon.exe` and `rundll32.exe` hosting `svcagent.dll`
3. **Recovery**: Rotate all credentials accessed from affected hosts; revoke and regenerate cryptocurrency wallet keys; audit blockchain transactions from compromised systems
4. **Secret Rotation**: Assume all credentials, API keys, and wallet seed phrases on affected systems are compromised

### Long-Term Hardening

- Disable or restrict Obsidian community plugins in enterprise environments; enforce plugin allowlisting
- Monitor for hardware breakpoint manipulation (DR register writes) via kernel-level telemetry
- Implement network monitoring for Blockscout API queries from non-developer endpoints
- Deploy application control policies to prevent unsigned DLL loading in system process directories
- Consider blockchain transaction monitoring for the known resolver wallet address

## Detection Rules

The following rules target PHANTOMPULSE IOCs and behavioral patterns at host, file, and network layers. Sigma rules cover persistence via scheduled tasks, known C2 domains, and Obsidian plugin abuse. YARA rules detect the RAT and loader by characteristic debug strings, C2 API paths, encryption keys, and byte patterns. Suricata rules identify C2 HTTP traffic patterns including telemetry heartbeats, command fetch, screenshot upload, keylog exfiltration, Blockscout API queries, and known C2 domain DNS. The C2 endpoint rules (SIDs 2100101-2100105) carry medium confidence because `/v1/telemetry/*` is a generic API pattern also used by legitimate observability agents; the C2 domain DNS rules carry high confidence.

### Sigma: PHANTOMPULSE Scheduled Task Persistence via Rundll32
Detects rundll32 execution with the PHANTOMPULSE persistence DLL `svcagent.dll` and `DllRegisterServer` export.
**compile: sigma check pass** | **sigma convert splunk pass** | **confidence: high**

```yaml
title: PHANTOMPULSE Scheduled Task Persistence via Rundll32
id: e69d7b21-6963-4056-a358-88e59b20dc47
status: experimental
description: >
    Detects creation of scheduled tasks matching PHANTOMPULSE RAT persistence
    pattern using DotNetSvc naming convention with rundll32 DllRegisterServer
    execution. The malware creates three scheduled tasks for persistence via
    COM ITaskService interface.
references:
    - https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole
    - https://www.elastic.co/security-labs/phantom-in-the-vault
author: Actioner
date: 2026-06-06
tags:
    - attack.t1053.005
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_rundll32:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains|all:
            - 'svcagent.dll'
            - 'DllRegisterServer'
    condition: selection_rundll32
falsepositives:
    - Legitimate DLL registration via rundll32 using similarly named DLLs
level: high
```

<!-- AUDIT: IOC-anchored rule. "svcagent.dll" + "DllRegisterServer" is the exact persistence invocation documented by Elastic. Validated: sigma check 0 errors, sigma convert --without-pipeline -t splunk pass, sigma convert --without-pipeline -t log_scale pass. Field names match Sysmon EID 1 schema. No defanged values in detection. -->

### Dropped: Sigma: PHANTOMPULSE Blockchain C2 Resolution via Blockscout API
**DROPPED** -- Blockscout is a legitimate open-source block explorer queried routinely by Web3/DeFi tooling; DNS-only detection without process context is not actionable. The more specific HTTP pattern is covered by Suricata SID 2100103.

### Dropped: Sigma: PHANTOMPULSE PhantomInject Module Stomping Target Process
**DROPPED** -- `dbghelp.dll` is loaded by Windows Error Reporting, Visual Studio JIT debugger, and crash handlers into exactly these host processes during normal crashes, producing constant noise with no practical tuning path in Sigma alone.

### Sigma: PHANTOMPULSE C2 Domain DNS Query
Detects DNS queries to known PHANTOMPULSE hardcoded C2 domains.
**compile: sigma check pass** | **sigma convert splunk pass** | **confidence: high**

```yaml
title: PHANTOMPULSE C2 Domain DNS Query
id: ceae41a0-bdea-4ffa-ba68-21d2423085b0
status: experimental
description: >
    Detects DNS queries to known PHANTOMPULSE C2 domains. These domains were
    identified in the REF6598 campaign targeting cryptocurrency and financial
    sector organizations.
references:
    - https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole
    - https://www.elastic.co/security-labs/phantom-in-the-vault
author: Actioner
date: 2026-06-06
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'fefea22134.net'
            - '0x666.info'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```

<!-- AUDIT: IOC-anchored domain rule. Domains from Elastic report, not defanged in detection. Validated: sigma check 0 errors, sigma convert pass. Critical level appropriate for known C2 infrastructure. -->

### Sigma: Suspicious Child Process from Obsidian
Detects scripting interpreter spawned by Obsidian, consistent with Shell Commands plugin abuse in REF6598.
**compile: sigma check pass** | **sigma convert splunk pass** | **sigma convert log_scale pass** | **confidence: medium** (TTP-level; legitimate Shell Commands plugin use possible)

```yaml
title: PHANTOMPULSE Suspicious Child Process from Obsidian
id: d7d79fe1-c284-470a-95ef-4a026f26bf00
status: experimental
description: >
    Detects suspicious child process spawned from Obsidian note-taking
    application, consistent with the REF6598 campaign delivery mechanism
    that abuses the Shell Commands community plugin to execute PowerShell
    or shell interpreters.
references:
    - https://www.elastic.co/security-labs/phantom-in-the-vault
author: Actioner
date: 2026-06-06
tags:
    - attack.t1059.001
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\Obsidian.exe'
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
    condition: selection
falsepositives:
    - Legitimate use of Obsidian Shell Commands plugin by developers
level: medium
```

<!-- AUDIT: TTP-level rule, level capped at medium per TTP altitude guidance. Obsidian spawning PowerShell/cmd is abnormal for typical note-taking use but Shell Commands plugin is a legitimate community plugin. Validated: sigma check 0 errors, sigma convert --without-pipeline -t splunk pass, sigma convert --without-pipeline -t log_scale pass. -->

### YARA: PHANTOMPULSE RAT, PHANTOMPULL Loader, and Blockchain C2 Config
Three YARA rules targeting the RAT payload (debug strings, C2 API paths, task names), the loader (update check path, DJB2 seed byte pattern, GetTickCount guard), and the blockchain C2 configuration (wallet address, Blockscout hostnames, XOR key).
**compile: yarac pass** | **confidence: high** (RAT strings), **high** (loader), **high** (C2 config)

```yara
rule Malware_PHANTOMPULSE_RAT_Strings
{
    meta:
        description = "Detects PHANTOMPULSE RAT via characteristic debug strings and C2 API paths observed in the REF6598 campaign"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole"
        hash = "33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f"
        severity = "critical"

    strings:
        $api1 = "/v1/telemetry/report" ascii wide
        $api2 = "/v1/telemetry/tasks/" ascii wide
        $api3 = "/v1/telemetry/upload/" ascii wide
        $api4 = "/v1/telemetry/result" ascii wide
        $api5 = "/v1/telemetry/keylog/" ascii wide

        $dbg1 = "PhantomInject: host PID=%lu" ascii
        $dbg2 = "[UNINSTALL 2/6]" ascii
        $dbg3 = "inject: shellcode detected" ascii
        $dbg4 = "ManualMap: thread hijacked and resumed" ascii
        $dbg5 = "FindHostProcessEx: scan stats" ascii
        $dbg6 = "KeylogResolveAPIs: ENTER" ascii

        $task1 = "DotNetSvcUpdateTask" ascii wide
        $task2 = "DotNetSvcCoreTask" ascii wide
        $task3 = "DotNetSvcUserTask" ascii wide

        $mutex = "hVNBUORXNiFLhYYh" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            3 of ($api*) or
            2 of ($dbg*) or
            (2 of ($task*) and $mutex)
        )
}

rule Malware_PHANTOMPULL_Loader
{
    meta:
        description = "Detects PHANTOMPULL loader (syncobs.exe) used in the REF6598 campaign to stage PHANTOMPULSE RAT"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://www.elastic.co/security-labs/phantom-in-the-vault"
        hash = "70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980"
        severity = "high"

    strings:
        $s1 = "/v1/updates/check?build=payloads" ascii wide
        $s2 = "svcagent.dll" ascii wide
        $s3 = "DllRegisterServer" ascii wide
        $s4 = "AssetMon" ascii wide

        $tick = { 48 83 C4 80 FF 15 ?? ?? ?? ?? 83 F8 FE 75 }
        $djb2 = { 45 8B 0C 83 41 BA A7 C6 67 4E 49 01 C9 45 8A 01 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 3MB and
        (
            ($s1 and 1 of ($s2, $s3, $s4)) or
            ($tick and $djb2) or
            (3 of ($s*))
        )
}

rule Malware_PHANTOMPULSE_Blockchain_C2_Config
{
    meta:
        description = "Detects PHANTOMPULSE RAT via embedded blockchain C2 resolver configuration including Blockscout hostnames and wallet address"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole"
        severity = "high"

    strings:
        $wallet = "0xc117688c530b660e15085bF3A2B664117d8672aA" ascii wide
        $bs1 = "eth.blockscout.com" ascii wide
        $bs2 = "base.blockscout.com" ascii wide
        $bs3 = "optimism.blockscout.com" ascii wide
        $api = "module=account&action=txlist" ascii wide

        $xor_key = { F7 7C 8E 40 DF C1 7B E5 E7 4D 86 79 D5 B3 53 41 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $wallet or
            (2 of ($bs*) and $api) or
            ($xor_key and 1 of ($bs*))
        )
}
```

<!-- AUDIT: Three YARA rules compiled clean via yarac. Strings sourced from Elastic report debug output and binary analysis. Hash meta from published SHA256. Byte patterns for GetTickCount guard and DJB2 seed from Elastic's disassembly. XOR key from .rdata section. All string values are real (not defanged). -->

### Suricata: PHANTOMPULSE Network Detection (7 rules)
Seven Suricata rules covering C2 heartbeat POST, command fetch GET, Blockscout API query, screenshot BMP upload, keylog exfiltration, and known C2 domain DNS queries (Windows + macOS domains).
**compile: suricata -T pass** | **confidence: medium** (C2 endpoint rules SIDs 2100101-2100105 -- `/v1/telemetry/*` is a generic API pattern used by legitimate observability agents), **high** (C2 domain DNS SIDs 2100106-2100107)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PHANTOMPULSE C2 Heartbeat Telemetry Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/v1/telemetry/report"; fast_pattern; http.content_type; content:"application/json"; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole; metadata:author Actioner, created_at 2026-06-06; sid:2100101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PHANTOMPULSE C2 Command Fetch"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/v1/telemetry/tasks/"; fast_pattern; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole; metadata:author Actioner, created_at 2026-06-06; sid:2100102; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PHANTOMPULSE Blockchain C2 Resolution via Blockscout API"; flow:established,to_server; http.host; content:"blockscout.com"; http.uri; content:"module=account"; content:"action=txlist"; content:"sort=desc"; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole; metadata:author Actioner, created_at 2026-06-06; sid:2100103; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PHANTOMPULSE Screenshot Upload via BMP"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/v1/telemetry/upload/"; fast_pattern; http.content_type; content:"image/bmp"; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole; metadata:author Actioner, created_at 2026-06-06; sid:2100104; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PHANTOMPULSE Keylog Data Exfiltration"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/v1/telemetry/keylog/"; fast_pattern; http.content_type; content:"text/plain"; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole; metadata:author Actioner, created_at 2026-06-06; sid:2100105; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - PHANTOMPULSE Known C2 Domain fefea22134.net"; dns.query; content:"fefea22134.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole; metadata:author Actioner, created_at 2026-06-06; sid:2100106; rev:2;)

alert dns $HOME_NET any -> any any (msg:"Actioner - PHANTOMPULSE Known C2 Domain 0x666.info"; dns.query; content:"0x666.info"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole; metadata:author Actioner, created_at 2026-06-06; sid:2100107; rev:1;)
```

<!-- AUDIT: All 7 Suricata rules validated via suricata -T -S. Dot-notation sticky buffers used (http.uri, http.method, http.host, http.content_type, dns.query). All options semicolon-terminated. Flow established for HTTP. URI paths from Elastic report. No defanged values. SIDs in custom 2100000+ range. SID 2100107 adds macOS C2 domain for parity with Sigma domain rule. -->

## Lessons Learned

1. **Plugin ecosystem trust**: Obsidian's community plugin model provides no sandboxing or code-signing for plugins, allowing arbitrary command execution when community plugins are enabled. This pattern applies broadly to any extensible application with user-contributed plugins (VS Code extensions, browser extensions, IDE plugins).

2. **Blockchain as C2 infrastructure**: Public blockchains provide censorship-resistant, highly available infrastructure for C2 resolution. However, the absence of sender verification in PHANTOMPULSE's resolver creates a sinkhole opportunity -- the same property that makes blockchains permissionless also means defenders can post competing transactions to redirect the botnet.

3. **Hardware breakpoint evasion maturity**: The shared HWBP primitive for bypassing AMSI, WLDP, and ETW simultaneously without inline patching represents an evolution in evasion that defeats memory-scanning-based detection. Defenders need kernel-level telemetry (e.g., debug register monitoring) to detect this technique.

4. **AI-assisted malware development**: The structured debug strings, verbose function tracing, and em-dash usage in C strings indicate AI coding assistance. This lowers the barrier for developing sophisticated implants while paradoxically providing defenders with more detection surface through verbose logging.

## Sources

- [Elastic Security Labs - PHANTOMPULSE: anatomy of a hijackable blockchain-C2 RAT](https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole) -- primary technical deep-dive of PHANTOMPULSE RAT internals, injection techniques, and blockchain C2 mechanism
- [Elastic Security Labs - Phantom in the vault: Obsidian abused to deliver PhantomPulse RAT](https://www.elastic.co/security-labs/phantom-in-the-vault) -- REF6598 campaign delivery chain analysis via Obsidian plugin abuse
- [Security Online - PHANTOMPULSE Malware Analysis](https://securityonline.info/phantompulse-malware-analysis-blockchain-c2/) -- secondary reporting summarizing Elastic findings
- [The Hacker News - Obsidian Plugin Abuse Delivers PHANTOMPULSE RAT](https://thehackernews.com/2026/04/obsidian-plugin-abuse-delivers.html) -- news coverage of REF6598 campaign
- [CyberSecurityNews - PHANTOMPULSE RAT Uses Process Injection and UAC Bypass](https://cybersecuritynews.com/phantompulse-rat-uses-process-injection-and-uac-bypass/) -- additional technical coverage

<!-- revision: v1.1 2026-06-06 REVISE pass. DROPPED 2 Sigma rules (Blockscout DNS -- legitimate block explorer, not actionable without process context; Module Stomping -- dbghelp.dll loaded by WER/VS JIT into same hosts, constant noise). FIXED: Obsidian Sigma level high->medium (TTP altitude cap). Suricata endpoint rules confidence high->medium in prose (/v1/telemetry/* generic pattern). Added SID 2100107 for macOS C2 domain 0x666.info. Removed unused pe import from YARA. Removed DotNetSvcElevateTask from IOCs (not in Technical Analysis). Final: 3 Sigma, 3 YARA, 7 Suricata rules. -->

---
*Report generated by Actioner*
