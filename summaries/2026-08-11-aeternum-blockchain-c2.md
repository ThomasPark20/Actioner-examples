# Technical Analysis Report: Aeternum Blockchain C2 (2026-08-11)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-11
Version: 1.1 (REVISED)

## Executive Summary

Aeternum is a commercially sold C++ botnet loader that uses Polygon blockchain smart contracts as its sole command-and-control infrastructure, making traditional server-based takedowns impossible. Operators write encrypted commands to immutable smart contracts via standard `eth_call` JSON-RPC requests; infected hosts query public Polygon RPC endpoints to retrieve and execute those commands. Unit 42 identified three distinct samples -- a C++ loader, a PyInstaller-packed XWorm/XMRig dropper, and a Python infostealer variant -- all sharing the blockchain-based C2 architecture. As of June 4, 2026, Palo Alto Networks' Advanced Threat Prevention recorded over 29,000 detection events.

The operator behind Aeternum uses the alias "LenAI" and sells panel access for $200 USD or full C++ source code for $4,000-$10,000 USD. The operational cost is minimal: approximately $1 in MATIC (Polygon's native token) funds 100-150 command transactions. The malware delivers stealers, clippers, RATs, and miners, with targeting controlled via hardware ID and HTTP fingerprint filtering.

## Background: Polygon Blockchain as C2 Infrastructure

The Polygon blockchain is an Ethereum-compatible Layer 2 network used for decentralized applications and smart contracts. Aeternum exploits this legitimate infrastructure by deploying smart contracts that store encrypted C2 domains and commands. Because blockchain data is immutable and publicly accessible via numerous free RPC endpoints, the C2 channel cannot be taken down through traditional means -- there are no servers to seize, no domains to sinkhole, and no single point of failure. This represents an evolution beyond predecessors like Glupteba, which used blockchain only as a fallback; Aeternum makes it the primary and sole C2 mechanism.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| October 2025 | Malicious DLL first observed in GitHub commit (lencod/Mash3Do accounts) |
| February 2026 | Early public reporting of Aeternum C2 botnet activity |
| June 2026 | XMRig configuration variations observed in the wild |
| June 4, 2026 | 29,000+ detection events recorded by Palo Alto Networks ATP |
| August 10, 2026 | Unit 42 publishes comprehensive technical analysis |

## Root Cause: Social Engineering and Trojanized Software

Initial access is achieved through social engineering lures including trojanized software installers (e.g., fake DBeaver database management tool installer in Sample 3) and malicious executables distributed through underground forums. The operator uses a Next.js-based web panel to deploy smart contracts, manage encrypted command execution, and target specific endpoints.

## Technical Analysis of the Malicious Payload

### 1. Sample 1: C++ Loader (Aeternum Core)

The primary loader is a 32-bit UPX-packed PE binary written in C++. Upon execution, it performs a multi-stage self-unpacking sequence, creates a folder in `AppData\Local`, copies itself there, and establishes persistence via a Windows Startup folder shortcut named `Wmi_Framework_APIKEY_wmsnet_<random_value>.lnk`. It then executes supporting binaries (`wmiframework.exe`, `ZrvEsJQzWQ.exe`, `STAAAAAS.exe`).

The loader issues JSON-RPC `eth_call` requests to Polygon RPC endpoints, invoking the `getDomain()` function (selector `0xb68d1809`) on deployed smart contracts. The response contains AES-256-GCM encrypted domain data using PBKDF2HMAC key stretching (SHA256, with a cryptographic flaw: the password is used as its own salt). The obfuscation pattern in the binary follows: `\x00\x00\x00[ENC bytes]\x00[KEY bytes]\x00\x00\x00`.

After decryption, the loader downloads payloads from GitHub repositories (`github[.]com/lencod/`, `github[.]com/Mash3Do/`), including a malicious `DotNetZip.dll` and a legitimate `putty.exe` (v0.83) used as a decoy. The DLL contains a hardcoded Telegram bot token (`8305917772:AAHAou...`) and chat ID (`-4991861036`) for exfiltrating system information (CPU, RAM, disk, GPU, admin rights, UAC status) via the Telegram Bot API `sendDocument` endpoint with the User-Agent `SystemInfo Bot/2.0` and multipart boundary `systeminfoboundary`.

22 distinct smart contract addresses were identified for Sample 1, compiled with Solidity versions 0.8.0 through 0.8.30.

### 2. Sample 2: XWorm + XMRig Dropper

A 64-bit PyInstaller-packed PE binary (Python 3.14 embedded) that uses a triple-layer decryption chain: ChaCha20 (outer), AES-CTR (middle), AES-CBC (inner). After decryption, it writes `esewurmgvbqt.exe` to the temp directory and executes it with a hidden window.

The sample performs VM detection and debugger presence checks before querying the Polygon blockchain (contract `0x75cD25791A60ab3451E2d2feB5ec46c6f541C2B8`) for C2 configuration. It retrieves XMRig mining configuration from Pastebin and drops XWorm v7.4 RAT (`XWormclient.exe`) and XMRig miner (`miner.exe`).

XMRig is configured with stealth options: `stealth-target` blocks Process Hacker and monitoring utilities by suspending them, and `kill-targets` terminates endpoint security software. The mining pool is `gulf.moneroocean[.]stream` with a hardcoded Monero wallet address.

Data exfiltration uses HTTP POST to `193.221.200[.]219` with JSON payloads containing `uqhash` (Base64-encoded AES-128 key) and `data` (Base64-encoded AES-128-ECB encrypted data with zero-padding).

### 3. Sample 3: Python Infostealer Variant

A Python-based variant distributed as a fake DBeaver installer using `XBinderOutput_protected.exe` (PyInstaller-packed). It performs anti-analysis checks: block-listed usernames, block-listed machine names, minimum 8 GB RAM requirement, and Zone.Identifier alternate data stream validation to confirm the system is not a pristine VM.

Persistence is established via `PythonLauncher-*.lnk` in the Startup folder. The malware uses Early Bird APC injection, spawning the signed binary `dpapimig.exe` in a suspended state, injecting shellcode, and executing it before security hooks engage.

C2 domains are resolved via the blockchain (contract `0xb0874252a7359AA701F3F144A1f03A6e0DA8aE6D`), with fallback domains including `download.sftp-api-group-wechat[.]com`, `update.constant-path[.]xyz`, `update-launcher[.]xyz`, `test-steve[.]cyou`, and `cdnjsdelivr[.]beer`. XOR keys `helo1` and `$m7*rYpry3` are used for payload obfuscation.

The infostealer targets over 55 cryptocurrency browser extensions and 10 desktop wallets. Exfiltration uses Telegram (bot token `7356125890:AAF5ncBIc2pJrEfYPAmy2g9YS7B5NjmtwTc`, chat IDs `-1002535992165` and `-1002144122983`) and HTTP POST to `sekirolegion.duckdns[.]org/api/endpoint.php`.

### 4. Smart Contract Architecture

All three samples share a common smart contract structure:
- **Slot 0**: Admin (deployer's wallet) address
- **Slot 1**: Encrypted domain data
- **Function selectors**: `0xb68d1809` (`getDomain()`), `0xb249cd2d` (`updateDomain()`), `0xf851a440` (`admin()`)

The operator address `0xcaf2c54e400437da717cf215181b170f65187abf` is associated with the LenAI alias. Gas optimization techniques are employed across contracts.

### 5. Anti-Forensics / Evasion Techniques

- UPX packing (Sample 1) and PyInstaller packing (Samples 2, 3)
- VM and debugger detection
- AV evasion testing via Kleenscan API (37 engines; only 12/37 detection rate at analysis time)
- Triple-layer encryption (ChaCha20/AES-CTR/AES-CBC)
- Early Bird APC injection into signed system binaries
- Zone.Identifier validation for sandbox evasion
- XMRig stealth process suspension and security tool termination
- Blockchain-based C2 inherently evades domain/IP-based blocking

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|----------------|---------------|-------------|
| Windows | Build.exe | 5bfb25b8255b61e5ffdf6804451534bcfa9f1dfd225e6c8cdcefb5f50d846898 | Aeternum C++ loader (UPX-packed) |
| Windows | DotNetZip.dll | 1505eda3da68e2ff9919b55a31018bd30a991236f041aee835f3bc4e430ce505 | Malicious DLL payload (Telegram exfil) |
| Windows | putty.exe | 12498d4e4bf07747a9a52d6803d3211fd731ded6473b41cf4795ac56947d0366 | Legitimate PuTTY v0.83 (decoy) |
| Windows | XBinderOutput_protected.exe | f2a326cff405299e4ebdfaac955c52fc7e496544eaa0921ecad4816cb3ae3a27 | PyInstaller XWorm/XMRig dropper |
| Windows | XWormclient.exe | 4e24bbd0fabac6c3efcec943046afbfd332b2c0108a13becfda23a0e26f9ff5f | XWorm RAT v7.4 client |
| Windows | miner.exe | 81bb80d9c5a97dc41b65f6248c131963c91346eb4fb672836b3d53ae67564d9f | XMRig cryptocurrency miner |
| Cross-platform | Python source | ea1b6ff3a0c1a749b9f09d66789973321d63d8896b48f7345193bdad512950a2 | Python infostealer variant |
| Windows | Wmi_Framework_APIKEY_wmsnet_*.lnk | -- | Startup persistence shortcut (Sample 1) |
| Windows | PythonLauncher-*.lnk | -- | Startup persistence shortcut (Sample 3) |
| Windows | wmiframework.exe | -- | Supporting binary (Sample 1) |
| Windows | esewurmgvbqt.exe | -- | Dropped executable (Sample 2) |
| Windows | dpapimig.exe | -- | Signed binary targeted for APC injection |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 193.221.200[.]219 | HTTP C2 exfiltration server (Sample 2) |
| Domain | download.sftp-api-group-wechat[.]com | C2 staging domain (Sample 3) |
| Domain | update.constant-path[.]xyz | C2 domain (Sample 3) |
| Domain | update-launcher[.]xyz | C2 domain (Sample 3) |
| Domain | test-steve[.]cyou | C2 domain (Sample 3) |
| Domain | cdnjsdelivr[.]beer | Payload hosting (Sample 3, typosquatting cdnjs) |
| Domain | sekirolegion.duckdns[.]org | HTTP exfiltration endpoint (Sample 3) |
| Domain | gulf.moneroocean[.]stream | XMRig mining pool (Sample 2) |
| Domain | api[.]telegram[.]org | Telegram Bot API exfiltration |
| URL Pattern | hxxps://github[.]com/lencod/ | Payload hosting GitHub account |
| URL Pattern | hxxps://github[.]com/Mash3Do/ | Payload hosting GitHub account |
| URL Pattern | hxxp://sekirolegion.duckdns[.]org/api/endpoint.php | HTTP exfiltration endpoint |

### Blockchain / Smart Contract IOCs

| Type | Value | Context |
|------|-------|---------|
| Operator Wallet | 0xcaf2c54e400437da717cf215181b170f65187abf | LenAI operator address |
| Contract (Sample 1) | 0x04E25a563f159308FC3E15fE9Ccc9D2CF623D0cc | One of 22 C2 contracts |
| Contract (Sample 1) | 0xC37fB924cF5996C9e676BBA399bDfc5F936B3572 | One of 22 C2 contracts |
| Contract (Sample 1) | 0xFDB8b139EeacD17ea7c10c256eA77Ba6Dff18D7d | One of 22 C2 contracts |
| Contract (Sample 2) | 0x75cD25791A60ab3451E2d2feB5ec46c6f541C2B8 | XWorm/XMRig C2 contract |
| Contract (Sample 3) | 0xb0874252a7359AA701F3F144A1f03A6e0DA8aE6D | Python variant C2 contract |
| Function Selector | 0xb68d1809 | getDomain() -- retrieves C2 domains |
| Function Selector | 0xb249cd2d | updateDomain() -- admin domain update |
| Function Selector | 0xf851a440 | admin() -- admin wallet getter |
| Crypto Wallet | 82pNS8tBnvZ5cmV1iU9cXdQmhGz95P18fZpASBrxtaSF1ToTmZtf3HGHrdXMt1Znuu8BLU17koPs2hTXxTajdTviLcgbbAi | Monero mining wallet |

### Behavioral

- Outbound JSON-RPC `POST` requests to Polygon RPC endpoints containing `eth_call` with function selector `0xb68d1809`
- HTTP POST to Telegram API `/bot<token>/sendDocument` with User-Agent `SystemInfo Bot/2.0` or `cpp-httplib/0.18.3`
- Multipart form data with boundary `systeminfoboundary`
- Creation of `.lnk` files matching `Wmi_Framework_APIKEY_wmsnet_*.lnk` in Startup folder
- Early Bird APC injection: `dpapimig.exe` spawned in suspended state with shellcode injection
- AES-128-ECB encrypted data exfiltration with JSON fields `uqhash` and `data`
- XMRig miner with process suspension of security tools via `stealth-target`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1059.006 | Python | Python-based infostealer variant (Sample 3) |
| T1106 | Native API | Process injection via APC calls |
| T1547.001 | Registry Run Keys / Startup Folder | LNK files in Startup folder for persistence |
| T1140 | Deobfuscate/Decode Files or Information | XOR deobfuscation, multi-layer AES/ChaCha20 decryption |
| T1497 | Virtualization/Sandbox Evasion | VM detection, debugger checks, Zone.Identifier validation |
| T1027 | Obfuscated Files or Information | UPX packing, PyInstaller packing, encrypted payloads |
| T1055.004 | Asynchronous Procedure Call | Early Bird APC injection into dpapimig.exe |
| T1105 | Ingress Tool Transfer | Payload download from GitHub repositories |
| T1041 | Exfiltration Over C2 Channel | Data exfiltration via Telegram Bot API and HTTP POST |
| T1071.001 | Web Protocols | JSON-RPC over HTTPS for C2, HTTP POST for exfiltration |
| T1102.002 | Bidirectional Communication | Blockchain smart contracts as C2 dead-drop resolver |
| T1496 | Resource Hijacking | XMRig cryptocurrency mining |
| T1005 | Data from Local System | Cryptocurrency wallet and browser extension credential theft |

## Impact Assessment

Aeternum represents a significant evolution in botnet C2 architecture. Its blockchain-based infrastructure eliminates single points of failure, making traditional takedown operations ineffective. The commercial availability ($200-$10,000) lowers the barrier for adoption by various threat actors. With over 29,000 detection events recorded, the malware has achieved meaningful scale. The multi-payload capability (stealers, RATs, miners, clippers) enables diverse monetization strategies. The low operational cost ($1 per 100-150 commands) makes sustained campaigns economically viable. At time of analysis, AV detection rates were poor (12/37 engines).

## Detection & Remediation

### Immediate Detection

- Search proxy/web logs for HTTP POST requests to known Polygon RPC endpoints containing `0xb68d1809` in the request body
- Search for User-Agent strings `SystemInfo Bot/2.0` or `cpp-httplib/0.18.3` in proxy logs
- Check Startup folders for LNK files matching `Wmi_Framework_APIKEY_wmsnet_*` or `PythonLauncher-*`
- Search for outbound connections to `193.221.200[.]219`, `sekirolegion.duckdns[.]org`, or the C2 domains listed above
- Hash-check binaries against the SHA256 IOCs provided

### Remediation

1. **Containment**: Block outbound connections to identified C2 domains/IPs and Polygon RPC endpoints at the proxy/firewall level
2. **Eradication**: Remove persistence mechanisms (Startup folder LNK files), quarantine identified malware samples, terminate mining processes
3. **Recovery**: Rotate all credentials on affected systems, particularly cryptocurrency wallet keys and browser-stored credentials
4. **Monitoring**: Deploy the detection rules below and monitor for blockchain RPC traffic patterns

### Long-Term Hardening

- Application allowlisting to prevent execution of unauthorized binaries from `AppData\Local` and temp directories
- Monitor and restrict outbound HTTPS to cryptocurrency RPC endpoints (advisory: blocking all Polygon RPC traffic may impact legitimate DeFi/Web3 operations)
- Implement EDR-level monitoring for Early Bird APC injection patterns (suspended process creation followed by memory writes)
- Deploy endpoint detection for XMRig mining indicators (CPU utilization anomalies, mining pool connections)

## Detection Rules

These detections target Aeternum's distinctive artifacts: the blockchain RPC `getDomain()` function selector, unique User-Agent strings, Startup folder persistence naming conventions, and known C2 infrastructure. PoC/advisory-specific altitude; Sigma rules convert cleanly to Splunk and CrowdStrike.

> **Caveat:** `sigma check` validation was blocked by the proxy (MITRE ATT&CK data fetch fails). Sigma rules below are compile-validated and convert-validated only; full `sigma check` results (tag validity, field name compliance) are pending manual verification.

<!-- revision: dropped by critic — Fires on any HTTP POST to common Polygon RPC endpoints. MetaMask, DeFi users, Web3 dapps generate these routinely. Not Aeternum-specific. -->

### Sigma: Aeternum Botnet Startup Folder Persistence via WMI Framework Shortcut
Detects creation of LNK files in the Windows Startup folder matching Aeternum's distinctive `Wmi_Framework_APIKEY_wmsnet_*` naming convention.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check fails (proxy blocks MITRE ATT&CK data fetch); splunk convert 0; log_scale convert 0. High confidence: the three-part naming pattern (Wmi_Framework + APIKEY + wmsnet) is highly distinctive and unlikely in legitimate software. Requires Sysmon EID 11 or equivalent file creation logging. -->
```yaml
title: Aeternum Botnet Startup Folder Persistence via WMI Framework Shortcut
id: 3b8d2e5f-1a4c-4f9e-a6b7-d8e9f0c1a2b3
status: experimental
description: >
    Detects creation of suspicious LNK files in the Windows Startup folder matching
    the Aeternum botnet naming convention (Wmi_Framework_APIKEY_wmsnet_*.lnk)
    used for persistence after initial infection.
references:
    - https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1547.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Start Menu\Programs\Startup\'
        TargetFilename|endswith: '.lnk'
        TargetFilename|contains|all:
            - 'Wmi_Framework'
            - 'APIKEY'
            - 'wmsnet'
    condition: selection
falsepositives:
    - Unlikely - highly specific naming convention
level: high
```

### Sigma: Aeternum Botnet System Info Exfiltration via Custom User-Agent
Detects HTTP POST requests using the distinctive `SystemInfo Bot/2.0` User-Agent unique to the Aeternum DLL.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check fails (proxy); splunk convert 0; log_scale convert 0. High confidence: "SystemInfo Bot/2.0" is a unique, non-standard UA string with no known legitimate use. -->
<!-- revision: dropped selection_boundary arm (cs-body is non-standard Sigma proxy field; won't auto-convert). selection_ua matching SystemInfo Bot/2.0 alone is distinctive and sufficient. -->
```yaml
title: Aeternum Botnet System Info Exfiltration via Custom User-Agent
id: 9c4f6a8b-2d5e-4f1a-b3c7-e8d9f0a1b2c3
status: experimental
description: >
    Detects HTTP POST requests using the distinctive User-Agent string
    'SystemInfo Bot/2.0' used by the Aeternum botnet DLL to exfiltrate
    system information to Telegram.
references:
    - https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: proxy
detection:
    selection_ua:
        c-useragent|contains: 'SystemInfo Bot/2.0'
    condition: selection_ua
falsepositives:
    - Unlikely - highly distinctive User-Agent string
level: high
```

### Sigma: Aeternum Botnet Telegram Bot API Exfiltration
Detects outbound POST requests to Telegram Bot API sendDocument endpoint using Aeternum's known User-Agent strings (`SystemInfo Bot/2.0`, `cpp-httplib/0.18.3`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check fails (proxy); splunk convert 0; log_scale convert 0. High confidence: combining Telegram sendDocument with specific UAs is highly distinctive. The cpp-httplib UA alone is somewhat common; the AND with Telegram sendDocument narrows significantly. -->
```yaml
title: Aeternum Botnet Telegram Bot API Exfiltration
id: 5e7a9c1d-3b6f-4d2e-a8c0-f1e2d3b4a5c6
status: experimental
description: >
    Detects outbound HTTP POST requests to the Telegram Bot API sendDocument
    endpoint using User-Agent strings associated with the Aeternum botnet
    (SystemInfo Bot/2.0 or cpp-httplib/0.18.3) for data exfiltration.
references:
    - https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_telegram:
        cs-uri|contains: '/bot'
        cs-host: 'api.telegram.org'
        cs-uri|endswith: '/sendDocument'
    selection_ua:
        c-useragent|contains:
            - 'SystemInfo Bot/2.0'
            - 'cpp-httplib/0.18.3'
    condition: selection_telegram and selection_ua
falsepositives:
    - Legitimate applications using Telegram Bot API with matching User-Agent strings
level: high
```

### Sigma: Aeternum Botnet GitHub Payload Download from Known Operator Accounts
Detects outbound connections to GitHub repositories associated with the Aeternum operator accounts (`lencod`, `Mash3Do`) used for payload delivery.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check fails (proxy); splunk convert 0; log_scale convert 0. High confidence: the specific GitHub account names are IOC-level indicators directly from Unit 42 analysis. Will become stale if accounts are burned/renamed. -->
```yaml
title: Aeternum Botnet GitHub Payload Download from Known Operator Accounts
id: 2f8b4d6e-7c9a-4e3f-b1d5-a0c2e3f4d5e6
status: experimental
description: >
    Detects outbound connections to GitHub repositories associated with the
    Aeternum botnet operator (lencod, Mash3Do) used for hosting and delivering
    malicious payloads after C2 domain resolution via blockchain.
references:
    - https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1105
logsource:
    category: proxy
detection:
    selection:
        cs-host: 'github.com'
        cs-uri|contains:
            - '/lencod/'
            - '/Mash3Do/'
    condition: selection
falsepositives:
    - Legitimate use of these GitHub accounts, though both are associated with malicious activity
level: high
```

### Snort: Aeternum C2 SystemInfo Bot User-Agent Exfiltration
Detects outbound HTTP POST with the distinctive `SystemInfo Bot/2.0` User-Agent and `systeminfoboundary` multipart boundary used by Aeternum for Telegram exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9 validated via local.rules include, exit 0. Rule uses http_header sticky buffers (Snort 2.9 compatible). fast_pattern on the unique UA string. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Aeternum C2 SystemInfo Bot User-Agent Exfiltration"; flow:established,to_server; content:"SystemInfo Bot/2.0"; http_header; fast_pattern; content:"systeminfoboundary"; http_header; content:"POST"; http_method; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis; sid:2100101; rev:1;)
```

### Snort: Aeternum C2 Blockchain RPC getDomain Function Selector
Detects outbound HTTP POST with the `0xb68d1809` function selector and `eth_call` in the request body, indicating blockchain-based C2 domain resolution.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort 2.9 validated via local.rules include, exit 0. Medium confidence: eth_call is a generic JSON-RPC method; the function selector narrows it but could theoretically appear in legitimate smart contract interactions. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Aeternum C2 Blockchain RPC getDomain Function Selector"; flow:established,to_server; content:"POST"; http_method; content:"0xb68d1809"; http_client_body; fast_pattern; content:"eth_call"; http_client_body; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis; sid:2100102; rev:1;)
```

### Snort: Aeternum C2 Known Exfiltration Server
Detects outbound HTTP POST to the known Aeternum exfiltration server `193.221.200[.]219` with the distinctive `uqhash` JSON field used for AES-128-ECB key exchange.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9 validated via local.rules include, exit 0. High confidence: IP + uqhash field name combination is highly specific. IP is IOC-level; rule will become stale if IP rotates. -->
```snort
alert tcp $HOME_NET any -> 193.221.200.219 any (msg:"Actioner - Aeternum C2 Known Exfiltration Server"; flow:established,to_server; content:"POST"; http_method; content:"uqhash"; http_client_body; fast_pattern; content:"data"; http_client_body; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis; sid:2100103; rev:1;)
```

### Suricata: Aeternum C2 SystemInfo Bot User-Agent Exfiltration
Detects outbound HTTP POST with `SystemInfo Bot/2.0` User-Agent and multipart/form-data content type used by Aeternum for Telegram exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0, no warnings. Dot-notation sticky buffers. fast_pattern on unique UA string. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Aeternum C2 SystemInfo Bot User-Agent Exfiltration"; flow:established,to_server; http.method; content:"POST"; http.user_agent; content:"SystemInfo Bot/2.0"; fast_pattern; http.content_type; content:"multipart/form-data"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis; metadata:author Actioner, created_at 2026-08-11; sid:2200101; rev:1;)
```

### Suricata: Aeternum C2 Blockchain RPC getDomain Function Selector
Detects outbound HTTP POST with `0xb68d1809` and `eth_call` in the request body, indicating Aeternum's blockchain-based C2 domain resolution.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0 (after fixing duplicate http.request_body instance). Medium confidence: function selector is specific but could appear in legitimate contract interactions. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Aeternum C2 Blockchain RPC getDomain Function Selector"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"0xb68d1809"; fast_pattern; content:"eth_call"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis; metadata:author Actioner, created_at 2026-08-11; sid:2200102; rev:1;)
```

### Suricata: Aeternum C2 Known Malicious Domain sftp-api-group-wechat
Detects DNS queries for `sftp-api-group-wechat[.]com`, a known Aeternum C2 staging domain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. IOC-level domain indicator from Unit 42. Will become stale if domain is burned. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - Aeternum C2 Known Malicious Domain sftp-api-group-wechat"; flow:to_server; dns.query; content:"sftp-api-group-wechat.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis; metadata:author Actioner, created_at 2026-08-11; sid:2200103; rev:1;)
```

### Suricata: Aeternum C2 Known Malicious Domain update-launcher
Detects DNS queries for `update-launcher[.]xyz`, a known Aeternum C2 domain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. IOC-level domain indicator from Unit 42. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - Aeternum C2 Known Malicious Domain update-launcher"; flow:to_server; dns.query; content:"update-launcher.xyz"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis; metadata:author Actioner, created_at 2026-08-11; sid:2200104; rev:1;)
```

### Suricata: Aeternum C2 Telegram Bot sendDocument Exfiltration
Detects outbound HTTP POST to Telegram Bot API sendDocument endpoint with `cpp-httplib/0.18.3` User-Agent, matching the specific version observed in Aeternum exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Combines Telegram API host + bot URI pattern + specific UA version. -->
<!-- revision: narrowed UA match from "cpp-httplib" (popular C++ library) to "cpp-httplib/0.18.3" (Aeternum-observed version) to reduce FPs. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Aeternum C2 Telegram Bot sendDocument Exfiltration"; flow:established,to_server; http.method; content:"POST"; http.host; content:"api.telegram.org"; http.uri; content:"/bot"; startswith; content:"/sendDocument"; endswith; fast_pattern; http.user_agent; content:"cpp-httplib/0.18.3"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis; metadata:author Actioner, created_at 2026-08-11; sid:2200105; rev:2;)
```

### Suricata: Aeternum C2 Known Exfiltration Server AES-128 ECB Data
Detects outbound HTTP POST to `193.221.200[.]219` with `uqhash` in the request body, indicating AES-128-ECB encrypted exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. IP + distinctive JSON field name. IOC-level. -->
```suricata
alert http $HOME_NET any -> 193.221.200.219 any (msg:"Actioner - Aeternum C2 Known Exfiltration Server AES-128 ECB Data"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"uqhash"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis; metadata:author Actioner, created_at 2026-08-11; sid:2200106; rev:1;)
```

### YARA: Aeternum Loader Strings
Detects Aeternum C++ loader via distinctive strings including the `0xb68d1809` blockchain function selector, `SystemInfo Bot/2.0` User-Agent, and `Wmi_Framework` persistence artifacts.
**Status:** compile ✅ compiles · confidence: high · sample: synthetic ✓
<!-- audit: yarac exit 0. YARA positive test: Malware_Aeternum_Loader_Strings fired on constructed positive with published strings (func_selector + rpc endpoint). Quiet on negative (benign text). Strings sourced from Unit 42 analysis of SHA256 5bfb25b8...6898. PE header check + filesize < 10MB + logical OR across string clusters. Tested against synthetic sample, not real sample SHA256 5bfb25b8...6898. -->
```yara
rule Malware_Aeternum_Loader_Strings
{
    meta:
        description = "Detects Aeternum botnet loader via distinctive strings including blockchain RPC function selector, User-Agent, and multipart boundary"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/"
        hash = "5bfb25b8255b61e5ffdf6804451534bcfa9f1dfd225e6c8cdcefb5f50d846898"
        severity = "high"

    strings:
        $func_selector = "0xb68d1809" ascii wide
        $ua1 = "SystemInfo Bot/2.0" ascii wide
        $ua2 = "cpp-httplib/0.18.3" ascii wide
        $boundary = "systeminfoboundary" ascii wide
        $persist1 = "Wmi_Framework_APIKEY_wmsnet" ascii wide
        $persist2 = "wmiframework.exe" ascii wide nocase
        $rpc1 = "eth_call" ascii wide
        $rpc2 = "polygon.rpc.hypersync.xyz" ascii wide
        $rpc3 = "polygon-mumbai.g.alchemy.com" ascii wide
        $contract1 = "0x04E25a563f159308FC3E15fE9Ccc9D2CF623D0cc" ascii
        $contract2 = "0x16dA95799CB8aB203f83e01AFC030B1217198Da4" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($func_selector and 1 of ($rpc*)) or
            ($ua1 and $boundary) or
            (2 of ($persist*)) or
            (1 of ($contract*) and $func_selector) or
            (3 of them)
        )
}
```

### YARA: Aeternum Python Variant
Detects the Aeternum Python-based infostealer variant via distinctive XOR keys, C2 domains, and function names.
**Status:** compile ✅ compiles · confidence: high · sample: synthetic ✓
<!-- audit: yarac exit 0. YARA positive test: Malware_Aeternum_Python_Variant fired on constructed positive with published C2 domains. Quiet on negative. No PE header check (Python source/PyInstaller). Strings sourced from Unit 42 SHA256 ea1b6ff3...50a2. Tested against synthetic sample, not real sample. -->
```yara
rule Malware_Aeternum_Python_Variant
{
    meta:
        description = "Detects Aeternum Python-based variant via distinctive XOR keys, C2 domains, and function patterns"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/"
        hash = "ea1b6ff3a0c1a749b9f09d66789973321d63d8896b48f7345193bdad512950a2"
        severity = "high"

    strings:
        $xor1 = "helo1" ascii
        $xor2 = "$m7*rYpry3" ascii
        $c2_1 = "sftp-api-group-wechat.com" ascii
        $c2_2 = "constant-path.xyz" ascii
        $c2_3 = "update-launcher.xyz" ascii
        $c2_4 = "test-steve.cyou" ascii
        $c2_5 = "cdnjsdelivr.beer" ascii
        $func1 = "get_domain" ascii
        $func2 = "send_tg" ascii
        $contract = "0xb0874252a7359AA701F3F144A1f03A6e0DA8aE6D" ascii
        $persist = "PythonLauncher-" ascii

    condition:
        filesize < 5MB and
        (
            (2 of ($c2_*)) or
            ($xor2 and 1 of ($func*)) or
            ($contract and 1 of ($func*)) or
            (3 of them)
        )
}
```

## Lessons Learned

Aeternum demonstrates that blockchain-based C2 infrastructure has matured from a theoretical concern to a practical, commercially available capability. Traditional domain/IP-based blocking and takedown operations are ineffective against this architecture. Defenders need to shift toward behavioral detection: monitoring for `eth_call` JSON-RPC patterns with specific function selectors, anomalous outbound connections to public blockchain RPC endpoints from non-development workstations, and the distinctive persistence and exfiltration patterns documented above. Organizations with no legitimate blockchain/Web3 activity can block Polygon RPC endpoints at the proxy level; those with legitimate use must rely on request-body inspection and endpoint-level detection. The low detection rate (12/37 AV engines) underscores the need for network and behavioral telemetry beyond signature-based file scanning.

## Sources

- [Unit 42 - The Permanent Threat: Analyzing Aeternum's Blockchain-Based C2 Operations and Communications](https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/) — primary technical analysis with IOCs, smart contract details, and three sample breakdowns
- [Security Affairs - Aeternum botnet hides commands in Polygon smart contracts](https://securityaffairs.com/188627/mobile-2/aeternum-botnet-hides-commands-in-polygon-smart-contracts.html) — supplementary reporting on AV detection rates and Kleenscan integration
- [The Hacker News - Aeternum C2 Botnet Stores Encrypted Commands on Polygon Blockchain](https://thehackernews.com/2026/02/aeternum-c2-botnet-stores-encrypted.html) — early reporting with commercial pricing and operator details
- [Ctrl-Alt-Intel Intelligence Repository](https://github.com/ctrlaltint3l/intelligence) — Aeternum decryption scripts and smart contract analysis tools
- [Hackread - New Aeternum C2 Botnet Evades Takedowns via Polygon Blockchain](https://hackread.com/aeternum-c2-botnet-polygon-blockchain/) — additional coverage on operational model and ErrTraffic toolkit association

---
*Report generated by Actioner*
