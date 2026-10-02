# Technical Analysis Report: MALFEX npm Supply-Chain Campaign (2026-10-02)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-02
Version: 1.0

## Executive Summary

MALFEX is a long-running npm supply-chain campaign, active since at least August 2023, attributed to a Portuguese-speaking threat actor operating under the handle "Murizada." The campaign uses seven malicious npm packages to deploy two distinct payloads on Windows systems: (1) the Overlord RAT, an open-source Go-based remote access trojan with Solana blockchain-based C2 resolution, and (2) "movinlike," a 64 MB Node.js credential stealer bundle that exfiltrates Discord authentication tokens, browser cookies/credentials, cryptocurrency wallet data, and Telegram session files via Discord webhooks. The campaign was publicly disclosed by CloudSEK on 30 September 2026, with one package (`function-flag`) evading advisory detection for 14 months. Two packages remain installable at the time of writing. Any system that installed one of these packages should be considered fully compromised.

## Background: npm Package Ecosystem

npm (Node Package Manager) is the world's largest software registry, serving over 2.1 million packages to millions of JavaScript/TypeScript developers. npm packages support lifecycle scripts -- including `postinstall` -- that execute arbitrary code at installation time. This mechanism is regularly abused by threat actors for supply-chain compromise. The MALFEX campaign exploits this by using `postinstall` hooks to download, decrypt, and execute Windows-targeted malware payloads.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~August 2023 | Earliest known MALFEX operator activity begins |
| 18 July 2025 | `function-flag` postinstall becomes malicious |
| 22-28 Sep 2026 | Amazon Inspector issues OSV advisories for five of eight packages |
| 28 Sep 2026 | GHSA-pv7p-ghgv-268x published for `img-to-native` |
| 30 Sep 2026 | CloudSEK publishes MALFEX research; Hackread reports on the campaign |
| 02 Oct 2026 | This analysis drafted; `cdn-img-fetch` and `function-flag` still installable |

## Root Cause: Malicious npm postinstall Scripts

Initial access occurs when a developer installs one of the seven MALFEX packages. The `postinstall` lifecycle script in each package executes immediately after installation, requiring no user interaction beyond `npm install`. The packages use dependency chains (e.g., `function-color` pulls `function-flag` as a dependency) to extend reach. Once the postinstall hook fires, it downloads a PNG polyglot file from GitHub (`raw.githubusercontent[.]com/cavecrew/proj`) or `api.imghippo[.]com`, extracts an encrypted payload appended after the PNG IEND marker, decrypts it, and executes the resulting Windows binary.

## Technical Analysis of the Malicious Payload

### 1. Malicious npm Package Delivery (Arm A & Arm B)

Seven malicious packages have been identified across multiple npm publisher accounts:

| Package | Role | Status |
|---------|------|--------|
| `tlxbnhd` | Arm A dropper | Advisory issued |
| `tldriver` | Arm A dropper | Advisory issued |
| `mxdriver` | Arm A dropper | Advisory issued |
| `img-to-native` | Arm A dropper (MAL-2026-17216) | Seized |
| `cdn-img-fetch` | Arm B stealer loader | Still installable |
| `function-flag` | Arm B stealer loader (14-month dwell) | Still installable |
| `function-color` | Wrapper (depends on function-flag) | Advisory issued |

The postinstall scripts use two distinct decryption approaches:
- **Arm A (Overlord RAT):** Downloads a Windows PE disguised as PNG from `api.imghippo.com`, then uses an IExpress cabinet containing a signed AutoIt3 interpreter that loads EA06-encrypted `.a3x` scripts. String obfuscation uses cycled-XOR; RC4 key `8448433`; LZNT1 compression.
- **Arm B (movinlike stealer):** Dependencies fetch a PNG polyglot from `raw.githubusercontent[.]com/cavecrew/proj`, decrypt the payload using AES-256-CBC with key derived from `nif-runtime-2027` (img-to-native) or `malfexteam2027` (other packages), then fetch a 64 MB Node.js bundle from `104.234.65[.]75:700`.

### 2. Overlord RAT (Arm A)

Overlord is an open-source, cross-platform Go-based RAT previously documented by Jamf Labs (August 2026) and Proofpoint (June 2026, UNK_DeadDrop campaign). Key capabilities:

- **Remote shell access** via encrypted WebSocket connection (TLS validation disabled)
- **Keystroke logging** (keylogger module)
- **Screen capture** and **desktop streaming**
- **Webcam** and **audio** access
- **Filesystem manipulation**
- **Solana blockchain C2 resolution:** The RAT contains a resolver capable of retrieving C2 server addresses from Solana blockchain transaction memo fields. CloudSEK reports this was active in MALFEX samples -- a previously undocumented operational use of this mechanism.

The loader chain for Overlord is: `postinstall script` -> `PNG polyglot download` -> `decrypt/extract PE` -> dropped as `gldriver_pre_core.exe` / `gldriver_pre_asset.exe` -> `IExpress cabinet` -> signed `AutoIt3.exe` copied to `%LOCALAPPDATA%\ScopeSmart Technologies Inc\` -> executes encrypted `.a3x` script -> Overlord RAT loads.

### 3. C2 Infrastructure

| Component | Infrastructure | Purpose |
|-----------|---------------|---------|
| Payload hosting | `raw.githubusercontent[.]com/cavecrew/proj` | PNG polyglot delivery |
| Payload hosting | `api.imghippo[.]com` | PE disguised as image/png |
| Stealer bundle | `104.234.65[.]75:700` | 64 MB movinlike Node.js bundle |
| Exfiltration | Discord webhook (live, URL undisclosed) | Stolen credential exfiltration |
| C2 resolution | Solana blockchain memo channel | Dynamic C2 address retrieval |

### 4. movinlike Credential Stealer (Arm B)

The movinlike stealer is a large Node.js bundle (~64 MB) that performs:

- **Discord client injection:** Modifies the Discord desktop client to intercept authentication tokens at runtime
- **Browser credential harvesting:** Targets Chromium-based browser data stores (`Login Data`, `Cookies`, `Web Data` SQLite databases) and `leveldb`/`Local Storage` for session tokens
- **Cryptocurrency wallet theft:** Extracts wallet data from browser extensions and local wallet applications
- **Telegram session theft:** Copies `tdata` directory containing Telegram Desktop session data
- **Exfiltration:** All stolen data is sent to an attacker-controlled Discord webhook

### 5. Persistence & Anti-Forensics

- **Scheduled task:** Creates `\Maiden` scheduled task for persistence
- **Persistence directory:** `%LOCALAPPDATA%\ScopeSmart Technologies Inc\AutoIt3.exe`
- **Legitimate tool abuse:** Uses a legitimately signed AutoIt3 interpreter to execute malicious scripts, evading signature-based AV
- **PNG polyglot:** Payloads are appended after the PNG IEND marker, making the files appear as valid images to cursory inspection
- **IExpress cabinet:** Uses Microsoft's legitimate IExpress packaging tool to wrap the loader

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Package / Software Level

| Package | Malicious Versions | SHA256 (Package Archive) |
|---------|-------------------|--------------------------|
| img-to-native | 1.0.0 | `018b3c7012386feefe215ffbc12d9d27228cd4ced623cb568e5ca24746a08d63` |
| img-to-native | 1.0.1 | `0958774b99a66f77dcdc9730f565a259d419d9e863315e10160960c538377717` |
| img-to-native | 1.0.2 | `7676788d88c2194b8d5c048decfbe06550798ce342af54f8975bc26422d10c53` |
| img-to-native | 1.0.3 | `1ddf674c8a1cd844ed91fb0fbba7e61a80210cb11dea1833b57d9cc225a4977c` |
| img-to-native (index.js) | all | `15f332a308dfb89eef2a220b5d0cdd9fc962ec5eef5d685b2345957563c10e6e` |

### File System

| Platform | Path / Filename | Description |
|----------|----------------|-------------|
| Windows | `%LOCALAPPDATA%\ScopeSmart Technologies Inc\AutoIt3.exe` | Persistence-adjacent AutoIt3 loader |
| Windows | `%LOCALAPPDATA%\Programs\NodeRuntime\node_runtime_helper.exe` | Dropped executable (img-to-native) |
| Windows | `gldriver_pre_core.exe` | Arm A dropper executable |
| Windows | `gldriver_pre_asset.exe` | Arm A dropper executable |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `raw.githubusercontent[.]com/cavecrew/proj` | PNG polyglot payload hosting (GitHub) |
| Domain | `api.imghippo[.]com` | PE disguised as PNG hosting |
| IP:Port | `104.234.65[.]75:700` | movinlike Node.js stealer bundle distribution |
| Domain | `discordapp[.]com/api/webhooks/` | Exfiltration channel (Discord webhook) |

### Behavioral

- Scheduled task creation named `\Maiden`
- AutoIt3.exe executing from `ScopeSmart Technologies Inc` directory under LocalAppData
- Node.js process making outbound connections to Discord webhook endpoints with POST requests containing Base64-encoded credential data
- DNS queries resolving Solana RPC endpoints from processes not associated with cryptocurrency applications

### Attribution Indicators

| Indicator | Value |
|-----------|-------|
| Operator key-derivation constant | `malfexteam2027` |
| npm publisher handles | `malfexkkj`, `malfex_user`, `malfexteste2`, `malfexteste3`, `malfexteste4` |
| GitHub account | `cavecrew` (display name: muriel, timezone UTC-0300/Brazil) |
| README attribution | "criado pela equipe Malfex, cujo dono e Murizada" |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious npm packages with postinstall hooks |
| T1204.002 | User Execution: Malicious File | Developers install packages triggering payload execution |
| T1059.010 | Command and Scripting Interpreter: AutoHotKey & AutoIT | AutoIt3 interpreter executes encrypted .a3x scripts |
| T1036.008 | Masquerading: Masquerade File Type | Windows PE disguised as PNG image |
| T1027.009 | Obfuscated Files or Information: Embedded Payloads | Payload appended after PNG IEND marker |
| T1140 | Deobfuscate/Decode Files or Information | AES-256-CBC and cycled-XOR decryption of payloads |
| T1105 | Ingress Tool Transfer | Download of RAT and stealer from remote infrastructure |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Maiden scheduled task for persistence |
| T1608.001 | Stage Capabilities: Upload Malware | Payloads hosted on GitHub and imghippo |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS used for C2 and exfiltration |
| T1567 | Exfiltration Over Web Service | Discord webhook used for data exfiltration |
| T1539 | Steal Web Session Cookie | Browser cookie and session token theft |
| T1528 | Steal Application Access Token | Discord authentication token theft |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chromium Login Data, Cookies, Web Data extraction |
| T1102 | Web Service | Solana blockchain used for C2 address resolution |

## Impact Assessment

The campaign has been active for over three years (since August 2023). While download counts are not publicly disclosed, the 14-month dwell time of `function-flag` with no advisory is significant -- packages with functional-sounding names like `function-flag` and `function-color` are more likely to be adopted than randomly-named typosquats. The dual-payload architecture (RAT + stealer) means compromised systems face both persistent remote access and immediate credential exfiltration. Any organization using one of these packages should assume full compromise of developer workstations, CI/CD pipelines, and all secrets accessible from those systems.

## Detection & Remediation

### Immediate Detection

```bash
# Check for malicious packages in any package-lock.json or node_modules
grep -rE "(tlxbnhd|tldriver|mxdriver|img-to-native|cdn-img-fetch|function-flag|function-color)" package-lock.json node_modules/*/package.json 2>/dev/null

# Check for MALFEX persistence artifacts on Windows
dir /s /b "%LOCALAPPDATA%\ScopeSmart Technologies Inc" 2>nul
dir /s /b "%LOCALAPPDATA%\Programs\NodeRuntime\node_runtime_helper.exe" 2>nul
schtasks /query /tn "\Maiden" 2>nul

# Check for dropped executables
dir /s /b "%TEMP%\gldriver_pre_core.exe" "%TEMP%\gldriver_pre_asset.exe" 2>nul

# Check for network IOCs in DNS logs or proxy logs
# Look for connections to 104.234.65.75:700
```

### Remediation

1. **Containment:** Immediately isolate any system that has installed one of the seven MALFEX packages. Disconnect from network.
2. **Eradication (preferred -- reimage):** Full reimaging of the compromised system is the recommended response. The dual-payload architecture (persistent RAT + credential stealer) means the system has been under full remote access and all local secrets should be considered exfiltrated. Reimaging eliminates any unknown persistence mechanisms.
3. **Eradication (fallback -- file-level cleanup):** If reimaging is not immediately feasible, remove the scheduled task `\Maiden`. Delete `%LOCALAPPDATA%\ScopeSmart Technologies Inc\` and `%LOCALAPPDATA%\Programs\NodeRuntime\` directories. Remove the malicious npm packages. Note: file-level cleanup may miss undocumented persistence mechanisms deployed via the RAT.
4. **Credential Rotation:** Rotate ALL credentials and tokens accessible from the compromised system, including: Discord tokens, browser-saved passwords, cryptocurrency wallet keys, Telegram sessions, SSH keys, API keys, cloud credentials, and CI/CD secrets.
5. **Audit npm Dependencies:** Run `npm audit` and review all postinstall scripts in dependencies. Consider using `--ignore-scripts` for untrusted packages.
6. **Monitor Exfiltration:** Review proxy/firewall logs for connections to `104.234.65[.]75:700` and Discord webhook POST requests originating from server infrastructure.

### Long-Term Hardening

- Implement npm package allow-listing or use tools like Socket.dev to detect suspicious postinstall scripts
- Enforce `--ignore-scripts` by default in CI/CD pipelines and use explicit script allow-lists
- Deploy egress filtering to detect anomalous outbound connections from developer workstations
- Monitor for Solana RPC endpoint connections from non-cryptocurrency development environments
- Implement lockfile integrity checking (e.g., `npm ci` instead of `npm install`)

## Detection Rules

The following detection rules cover the MALFEX campaign's key stages: payload delivery, dropper execution, persistence, and C2 communication. Rules use real (non-defanged) IOC values as required for detection. The imghippo rules (sid:2200004, sid:2200005) target a legitimate image hosting service abused by MALFEX -- see tuning guidance in each rule's notes.

### Sigma Rules

#### 1. MALFEX ScopeSmart AutoIt3 Persistence File Creation

Detects file creation in the ScopeSmart Technologies persistence directory.

- Compile: Splunk + LogScale conversion pass
- Confidence: high

```yaml
title: MALFEX Malicious npm Postinstall Drops Executable to LocalAppData
id: 6bff86ba-782a-4c16-87de-4a616905bdc1
status: experimental
description: >
    Detects creation of executable files in the ScopeSmart Technologies
    persistence directory used by the MALFEX npm supply-chain campaign
    to stage AutoIt3-based loaders that deliver Overlord RAT.
references:
    - https://hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/
    - https://www.cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign
author: Actioner
date: 2026/10/02
tags:
    - attack.t1204.002
    - attack.t1059.010
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\ScopeSmart Technologies Inc\'
        TargetFilename|endswith:
            - '\AutoIt3.exe'
            - '.a3x'
    condition: selection
falsepositives:
    - Legitimate ScopeSmart Technologies software installation
level: critical
```

<!-- AUDIT: Sigma rule 6bff86ba. Validated via sigma convert --without-pipeline -t splunk and -t log_scale. sigma check skipped due to MITRE ATT&CK data fetch blocked by proxy (HTTP 403). File path derived from CloudSEK report: %LOCALAPPDATA%\ScopeSmart Technologies Inc\AutoIt3.exe. Real path separators used (backslash). No defanged values. -->

#### 2. MALFEX gldriver Dropper Process Execution

Detects execution of MALFEX-specific dropper executables.

- Compile: Splunk + LogScale conversion pass
- Confidence: high

```yaml
title: MALFEX Dropper Executable gldriver Process Creation
id: 43415693-4a5c-454c-ae1d-f819d7b4ab7a
status: experimental
description: >
    Detects execution of gldriver_pre_core.exe or gldriver_pre_asset.exe,
    dropper executables used by the MALFEX campaign delivered through
    malicious npm packages disguised as PNG files.
references:
    - https://hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/
    - https://www.cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign
author: Actioner
date: 2026/10/02
tags:
    - attack.t1204.002
    - attack.t1036.008
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\gldriver_pre_core.exe'
            - '\gldriver_pre_asset.exe'
    condition: selection
falsepositives:
    - Unlikely, these file names are specific to the MALFEX campaign
level: critical
```

<!-- AUDIT: Sigma rule 43415693. File names from CloudSEK analysis. Validated via Splunk and LogScale conversion. No known legitimate software uses these exact filenames. -->

#### 3. MALFEX Maiden Scheduled Task Persistence

Detects creation of the Maiden scheduled task used for persistence.

- Compile: Splunk + LogScale conversion pass
- Confidence: high

```yaml
title: MALFEX Persistence via Maiden Scheduled Task
id: 125fd762-d58c-40fe-92e7-e476f4e9b931
status: experimental
description: >
    Detects creation of the scheduled task named Maiden used by the MALFEX
    campaign for persistence. The task executes the AutoIt3 loader that
    deploys the Overlord RAT.
references:
    - https://hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/
    - https://www.cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign
author: Actioner
date: 2026/10/02
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_tool:
        Image|endswith:
            - '\schtasks.exe'
    selection_args:
        CommandLine|contains|all:
            - '/create'
            - 'Maiden'
    condition: selection_tool and selection_args
falsepositives:
    - Legitimate software using a task named Maiden
level: high
```

<!-- AUDIT: Sigma rule 125fd762. Task name "\Maiden" from CloudSEK report. schtasks /create detection pattern. Low FP risk due to unique task name. Validated Splunk+LogScale. -->

#### 4. MALFEX img-to-native NodeRuntime Payload Drop

Detects the node_runtime_helper.exe file written to the NodeRuntime directory.

- Compile: Splunk + LogScale conversion pass
- Confidence: high

```yaml
title: MALFEX img-to-native Drops node_runtime_helper Executable
id: 095dd939-2769-409d-9c0b-db086ddf3ee0
status: experimental
description: >
    Detects creation or execution of node_runtime_helper.exe dropped by the
    img-to-native malicious npm package into the NodeRuntime directory
    under LocalAppData. The payload is extracted from a PNG polyglot
    and decrypted with AES-256-CBC.
references:
    - https://hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/
    - https://osv.dev/vulnerability/MAL-2026-17216
author: Actioner
date: 2026/10/02
tags:
    - attack.t1204.002
    - attack.t1027.009
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Programs\NodeRuntime\'
        TargetFilename|endswith: '\node_runtime_helper.exe'
    condition: selection
falsepositives:
    - Unlikely, specific file path associated with MALFEX campaign
level: critical
```

<!-- AUDIT: Sigma rule 095dd939. Path from OSV MAL-2026-17216: %LOCALAPPDATA%\Programs\NodeRuntime\node_runtime_helper.exe. Validated via Splunk+LogScale. -->

#### 5. MALFEX Payload Fetch from GitHub cavecrew Repository

Detects proxy/web traffic to the payload hosting repository.

- Compile: Splunk + LogScale conversion pass
- Confidence: high

```yaml
title: MALFEX PNG Polyglot Payload Fetch from GitHub cavecrew Repository
id: 9974f8d8-d465-4ca9-861f-9f57847df573
status: experimental
description: >
    Detects proxy or web-gateway log entries where the request URI
    contains raw.githubusercontent.com/cavecrew/proj, used by
    MALFEX to host PNG polyglot payloads containing encrypted
    executables. Matches on the proxy category c-uri field.
references:
    - https://hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/
    - https://www.cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign
author: Actioner
date: 2026/10/02
tags:
    - attack.t1608.001
    - attack.t1105
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains|all:
            - 'raw.githubusercontent.com'
            - 'cavecrew/proj'
    condition: selection
falsepositives:
    - Developer access to this specific GitHub repository for analysis
level: critical
```

<!-- AUDIT: Sigma rule 9974f8d8. GitHub URL from CloudSEK report. Proxy logsource for URL inspection. Real URL used (not defanged). -->

#### 6. MALFEX movinlike Stealer C2 Connection

Detects network connections to the movinlike stealer distribution server.

- Compile: Splunk + LogScale conversion pass
- Confidence: high

```yaml
title: MALFEX movinlike Stealer C2 Connection to Payload Server
id: fb71516a-210e-4c43-9f89-80acd2b2bb92
status: experimental
description: >
    Detects outbound network connection to 104.234.65.75 on port 700,
    used by the MALFEX campaign to serve the movinlike Node.js stealer
    bundle (64 MB). This IP delivers the second-stage credential
    stealer that targets Discord, browsers, and Telegram.
references:
    - https://hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/
    - https://www.cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign
author: Actioner
date: 2026/10/02
tags:
    - attack.t1105
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '104.234.65.75'
        DestinationPort: 700
    condition: selection
falsepositives:
    - Legitimate traffic to this IP on port 700 is highly unlikely
level: critical
```

<!-- AUDIT: Sigma rule fb71516a. IP:port from CloudSEK report. Real IP used (not defanged). Sysmon EID 3 network_connection logsource. -->

### YARA Rules

#### 1. MALFEX Overlord RAT Go Binary Detection

Detects Overlord RAT by Go build artifacts, Solana resolver strings, and RAT capability strings.

- Compile: yarac pass
- Confidence: medium (generic Go RAT strings; requires Solana + WebSocket + capability intersection to reduce FPs)

```yara
rule MALFEX_Overlord_RAT_Strings
{
    meta:
        description = "Detects Overlord RAT deployed by the MALFEX npm supply-chain campaign via characteristic Go binary strings and Solana blockchain C2 resolver"
        author = "Actioner"
        date = "2026-10-02"
        reference = "https://hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/"
        severity = "critical"

    strings:
        $go_build = "go.buildid" ascii
        $sol1 = "solana" ascii nocase
        $sol2 = "GetTransaction" ascii
        $sol3 = "rpc" ascii
        $rat1 = "keylogger" ascii nocase
        $rat2 = "screenshot" ascii nocase
        $rat3 = "remoteshell" ascii nocase
        $rat4 = "webcam" ascii nocase
        $ws1 = "websocket" ascii nocase
        $ws2 = "gorilla/websocket" ascii
        $malfex1 = "ScopeSmart" ascii wide
        $malfex2 = "malfexteam2027" ascii
        $malfex3 = "cavecrew" ascii

    condition:
        filesize < 100MB and
        $go_build and
        (1 of ($sol*)) and
        (2 of ($rat*)) and
        (1 of ($ws*)) and
        (1 of ($malfex*))
}
```

<!-- AUDIT: YARA rule MALFEX_Overlord_RAT_Strings. yarac compile pass. Condition requires intersection of Go build marker + Solana strings + RAT capabilities + WebSocket library to reduce false positives against legitimate Go binaries. Capability strings derived from Hackread/CloudSEK/Malpedia reporting. No specific sample hash available for MALFEX variant. -->

#### 2. MALFEX AutoIt3 IExpress Loader

Detects the IExpress-packaged AutoIt3 loader with MALFEX-specific artifacts.

- Compile: yarac pass
- Confidence: medium (AutoIt + .a3x is common in legitimate installers; campaign-specific string anchors required)

```yara
rule MALFEX_AutoIt_Loader_IExpress
{
    meta:
        description = "Detects Microsoft IExpress cabinet containing AutoIt3 loader used by MALFEX campaign to deliver Overlord RAT with EA06 encrypted a3x scripts"
        author = "Actioner"
        date = "2026-10-02"
        reference = "https://www.cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign"
        severity = "high"

    strings:
        $mz = { 4D 5A }
        $autoit = "AutoIt" ascii wide
        $a3x_magic = ".a3x" ascii
        $scope = "ScopeSmart" ascii wide
        $key1 = "malfexteam2027" ascii wide
        $cab = "MSCF" ascii

    condition:
        ($mz at 0 or $cab at 0) and
        filesize < 50MB and
        (
            ($autoit and ($scope or $key1)) or
            ($autoit and $a3x_magic and ($scope or $key1))
        )
}
```

<!-- AUDIT: YARA rule MALFEX_AutoIt_Loader_IExpress. yarac compile pass. "malfexteam2027" and "ScopeSmart" are campaign-unique strings from CloudSEK. MZ or MSCF header check limits scope to PE/cab files. -->

#### 3. MALFEX npm Postinstall Script Detection

Detects the malicious postinstall scripts by key-derivation constants and payload paths.

- Compile: yarac pass
- Confidence: high

```yara
rule MALFEX_NPM_Postinstall_Script
{
    meta:
        description = "Detects malicious npm postinstall scripts from MALFEX campaign that extract payloads from PNG polyglots using AES-256-CBC decryption"
        author = "Actioner"
        date = "2026-10-02"
        reference = "https://osv.dev/vulnerability/MAL-2026-17216"
        severity = "high"

    strings:
        $key1 = "malfexteam2027" ascii
        $key2 = "nif-runtime-2027" ascii
        $aes = "aes-256-cbc" ascii
        $iend = "IEND" ascii
        $path1 = "node_runtime_helper" ascii
        $path2 = "NodeRuntime" ascii
        $path3 = "gldriver_pre" ascii
        $gh = "cavecrew" ascii

    condition:
        filesize < 5MB and
        (
            ($key1 or $key2) or
            ($aes and $iend and 1 of ($path*)) or
            ($gh and 1 of ($path*))
        )
}
```

<!-- AUDIT: YARA rule MALFEX_NPM_Postinstall_Script. yarac compile pass. "malfexteam2027" and "nif-runtime-2027" are campaign-unique key-derivation constants. Alternative condition matches AES+IEND polyglot pattern with MALFEX-specific paths. 5MB size limit scoped to script/package files. -->

#### 4. MALFEX movinlike Node.js Stealer Bundle

Detects the credential stealer by combination of Discord, browser, and Telegram targeting strings.

- Compile: yarac pass
- Confidence: low (browser credential path strings are common in both malware and legitimate tools; without a MALFEX-unique anchor this rule matches generic Node.js stealers with similar capabilities)

```yara
rule MALFEX_movinlike_Stealer_Bundle
{
    meta:
        description = "Detects Node.js credential stealer bundles with characteristics matching the movinlike stealer deployed by the MALFEX campaign. Note: this rule may also match other Node.js stealers with similar Discord/browser/Telegram targeting."
        author = "Actioner"
        date = "2026-10-02"
        reference = "https://www.cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign"
        severity = "high"

    strings:
        $discord1 = "discord" ascii nocase
        $discord2 = "discordapp.com/api/webhooks" ascii
        $token1 = "leveldb" ascii
        $token2 = "Local Storage" ascii
        $browser1 = "Login Data" ascii
        $browser2 = "Cookies" ascii
        $browser3 = "Web Data" ascii
        $tg = "tdata" ascii
        $crypto1 = "wallet" ascii nocase
        $node = "node_modules" ascii
        $malfex1 = "malfexteam2027" ascii
        $malfex2 = "movinlike" ascii
        $c2 = "104.234.65.75" ascii

    condition:
        filesize < 100MB and
        $node and
        (1 of ($discord*)) and
        (1 of ($token*)) and
        (2 of ($browser*)) and
        ($tg or $crypto1) and
        (1 of ($malfex*) or $c2)
}
```

<!-- AUDIT: YARA rule MALFEX_movinlike_Stealer_Bundle. yarac compile pass. Condition requires intersection of node_modules marker + Discord targeting + browser credential paths + Telegram/crypto stealing. May match other Node.js stealers with similar capabilities -- acceptable for advisory-specific altitude. -->

#### 5. MALFEX img-to-native Package String Match

Detects the specific malicious img-to-native package by unique string combination.

- Compile: yarac pass
- Confidence: high

```yara
rule MALFEX_img_to_native_Package
{
    meta:
        description = "Detects known malicious img-to-native npm package files by string combination (package name + key-derivation constant), part of the MALFEX supply-chain campaign"
        author = "Actioner"
        date = "2026-10-02"
        reference = "https://osv.dev/vulnerability/MAL-2026-17216"
        hash1 = "018b3c7012386feefe215ffbc12d9d27228cd4ced623cb568e5ca24746a08d63"
        hash2 = "0958774b99a66f77dcdc9730f565a259d419d9e863315e10160960c538377717"
        hash3 = "7676788d88c2194b8d5c048decfbe06550798ce342af54f8975bc26422d10c53"
        hash4 = "1ddf674c8a1cd844ed91fb0fbba7e61a80210cb11dea1833b57d9cc225a4977c"
        severity = "critical"

    strings:
        $pkg = "img-to-native" ascii
        $key = "nif-runtime-2027" ascii

    condition:
        filesize < 5MB and
        $pkg and $key
}
```

<!-- AUDIT: YARA rule MALFEX_img_to_native_Package. yarac compile pass. Known hashes from OSV MAL-2026-17216 documented in meta. String-based match for scanning npm caches/registries. -->

### Suricata Rules

#### 1. GitHub cavecrew Payload Fetch

Detects HTTP requests to the payload hosting repository on GitHub.

- Compile: suricata -T pass
- Confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - MALFEX PNG Polyglot Payload Fetch from GitHub cavecrew Repository"; flow:established,to_server; http.host; content:"raw.githubusercontent.com"; http.uri; content:"/cavecrew/proj"; fast_pattern; classtype:trojan-activity; reference:url,hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/; metadata:author Actioner, created_at 2026-10-02, campaign MALFEX; sid:2200001; rev:1;)
```

<!-- AUDIT: Suricata sid:2200001. suricata -T pass. Dot-notation sticky buffers. GitHub raw URL is the real payload host per CloudSEK. -->

#### 2. movinlike C2 Connection

Detects TCP connections to the stealer bundle distribution server.

- Compile: suricata -T pass
- Confidence: high

```
alert tcp $HOME_NET any -> 104.234.65.75 700 (msg:"Actioner - MALFEX movinlike Stealer C2 Connection to Payload Server"; flow:established,to_server; classtype:trojan-activity; reference:url,cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign; metadata:author Actioner, created_at 2026-10-02, campaign MALFEX; sid:2200002; rev:1;)
```

<!-- AUDIT: Suricata sid:2200002. suricata -T pass. IP and port from CloudSEK report. Real IP used. -->

#### 3. imghippo Payload Hosting Request

Detects HTTP requests to api.imghippo.com for PNG-disguised PE download.

- Compile: suricata -T pass
- Confidence: medium
- **Caveat:** api.imghippo.com is a legitimate image hosting service. This rule will fire on any .png fetch from that API. Deploy with suppression for known legitimate users or scope to high-risk network segments. Investigate hits by checking whether the downloaded PNG contains appended data after the IEND marker.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - MALFEX PE Disguised as PNG Fetched from imghippo Hosting"; flow:established,to_server; http.host; content:"api.imghippo.com"; fast_pattern; http.uri; content:".png"; endswith; classtype:trojan-activity; reference:url,cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign; metadata:author Actioner, created_at 2026-10-02, campaign MALFEX; sid:2200004; rev:1;)
```

<!-- AUDIT: Suricata sid:2200004. suricata -T pass. imghippo.com is a legitimate image host abused by MALFEX. Confidence lowered to medium due to FP risk on legitimate traffic. -->

#### 4. imghippo DNS Query

Detects DNS queries to the payload hosting domain.

- Compile: suricata -T pass
- Confidence: medium
- **Tuning:** api.imghippo.com is a legitimate image hosting service. Suppress by source IP for known legitimate users (e.g., `suppress gen_id 1, sig_id 2200005, track by_src, ip <legitimate_user_ip>`). Consider deploying only in segments where image hosting traffic is unexpected.

```
alert dns $HOME_NET any -> any any (msg:"Actioner - MALFEX DNS Query to imghippo Payload Hosting"; dns.query; content:"api.imghippo.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign; metadata:author Actioner, created_at 2026-10-02, campaign MALFEX; sid:2200005; rev:1;)
```

<!-- AUDIT: Suricata sid:2200005. suricata -T pass. DNS query for payload hosting domain. Confidence lowered to medium -- api.imghippo.com is a legitimate service. Tuning guidance added for suppression by src IP. -->

### Snort 3 Rules (Structural Check Only -- snort not installed)

#### 1. GitHub cavecrew Payload Fetch

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - MALFEX PNG Polyglot Payload Fetch from GitHub cavecrew Repository"; flow:established, to_server; http_uri; content:"/cavecrew/proj", fast_pattern; http_host; content:"raw.githubusercontent.com"; classtype:trojan-activity; reference:url,hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/; metadata:author Actioner, created 2026-10-02, campaign MALFEX; sid:2200101; rev:1;)
```

<!-- AUDIT: Snort 3 sid:2200101. Structural check only (snort not installed). Uses http_host sticky buffer per Snort 3 syntax. -->

#### 2. movinlike C2 Connection

```
alert tcp $HOME_NET any -> 104.234.65.75 700 (msg:"Actioner - MALFEX movinlike Stealer C2 Connection to Payload Server"; flow:established, to_server; classtype:trojan-activity; reference:url,cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign; metadata:author Actioner, created 2026-10-02, campaign MALFEX; sid:2200102; rev:1;)
```

<!-- AUDIT: Snort 3 sid:2200102. Structural check only. IP-based rule with port constraint. -->

## Lessons Learned

1. **Postinstall scripts remain the primary npm supply-chain attack vector.** The MALFEX campaign demonstrates that even packages with generic, functional-sounding names (not obvious typosquats) can carry malicious postinstall hooks for over 14 months without detection. Organizations must implement systematic auditing of lifecycle scripts in dependencies.

2. **Blockchain-based C2 resolution is now operationally deployed.** While Solana-based C2 resolution was previously identified in Overlord RAT source code as a dormant capability, MALFEX represents confirmed active use. This technique makes C2 takedown significantly harder since blockchain transactions are immutable and decentralized.

3. **Multi-stage, dual-payload architectures increase impact.** The separation of remote access (Overlord RAT) and credential theft (movinlike stealer) into distinct arms means a compromised system faces both persistent access and immediate data exfiltration, requiring more extensive remediation than either threat alone.

4. **Advisory coverage has blind spots.** Five of eight packages received OSV advisories only in September 2026, despite `function-flag` being malicious since July 2025. Community-driven advisory systems need faster feedback loops, particularly for packages using dependency chains to distribute malicious code.

## Sources

- [Hackread: MALFEX npm Windows RAT Steals Discord & Browser Data](https://hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/) -- initial public reporting on the campaign
- [CloudSEK: MALFEX - A malicious npm postinstall no advisory has caught for fourteen months](https://www.cloudsek.com/blog/malfex-malicious-npm-postinstall-supply-chain-campaign) -- original research and technical analysis
- [OSV: MAL-2026-17216 (img-to-native)](https://osv.dev/vulnerability/MAL-2026-17216) -- OSV advisory with package hashes
- [GitHub Advisory: GHSA-pv7p-ghgv-268x](https://github.com/advisories/GHSA-pv7p-ghgv-268x) -- GitHub Security Advisory for img-to-native
- [Malpedia: win.overlord](https://malpedia.caad.fkie.fraunhofer.de/details/win.overlord) -- Overlord RAT malware family entry with YARA signature
- [Hackread: Fake Zoom Installer Targets Mac and Windows with Overlord RAT](https://hackread.com/fake-zoom-installer-mac-windows-overlord-rat/) -- prior Overlord RAT campaign analysis
- [MalwareBazaar: OverlordRAT Samples](https://bazaar.abuse.ch/browse/signature/OverlordRAT/) -- Overlord RAT sample repository (46 samples cataloged)

---
*Report generated by Actioner*
