# Technical Analysis Report: GoCaracal Malware -- Dark Caracal APT (2026-08-28)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-28
Version: 1.1

## Executive Summary

Arctic Wolf Labs has identified GoCaracal, a previously undocumented Go-based malware framework, deployed by threat actors linked with medium confidence to Dark Caracal during a June 2026 intrusion at a communications organization in Venezuela. The framework operates in two build profiles -- a lightweight variant providing encrypted C2, shell access, and shellcode injection, and an extended variant adding browser credential theft, keylogging, WebRTC remote desktop, SOCKS5 proxying, and a novel Ethereum smart-contract-based C2 fallback mechanism. The Ethereum fallback uses a custom Solidity contract named "BulletproofC2" to store mutable C2 addresses on the Ethereum mainnet, allowing operators to rotate infrastructure without redeploying the malware. Arctic Wolf linked 249 related samples (January--July 2026) to this campaign, with C2 infrastructure predominantly hosted on AEZA Group networks, alongside an updated Bandook backdoor hosted on AlexHost. The campaign targets Latin American organizations with Spanish-language financial and tax-themed phishing lures delivered via malicious SVG attachments.

## Background: Dark Caracal APT

Dark Caracal is a long-running cyber-espionage group previously associated with Lebanon's General Directorate of General Security. The group is known for targeting governments, businesses, journalists, activists, and organizations, with a historical focus on Latin America and the Middle East. Their traditional toolset centers on the Bandook backdoor, a Delphi-based RAT, delivered through document-themed phishing infrastructure. The introduction of GoCaracal represents a significant evolution in their capabilities, adding a modern Go-based framework with blockchain-backed resilience to their operational toolkit.

## Attack Timeline (All Times UTC)

| Timeframe | Event |
|-----------|-------|
| January 2026 | GoCaracal Phase 1 development begins: core communications, host profiling |
| February--April 2026 | Phase 2: modularization, antivirus discovery, interactive shell |
| May 2026 | Phase 3: broad post-compromise functionality added |
| May 20, 2026 | Primary BulletproofC2 Ethereum smart contract deployed on mainnet |
| June 2026 | Phase 4: Ethereum-based C2 fallback implemented; intrusion at Venezuelan comms organization |
| June--July 2026 | Continued development; 249 total samples identified |
| July 2026 | One new staging domain registered; Sepolia testnet activity observed |
| August 27, 2026 | Arctic Wolf Labs publishes research |

## Root Cause: Spearphishing with Malicious SVG Attachments

Initial access was achieved through spearphishing emails with financial and tax-themed lures in Spanish. The emails contained weaponized SVG file attachments that, when opened, contained a Base64-encoded shortened URL. This URL redirected the victim through an intermediate redirector to an attacker-controlled staging site (e.g., `getpdfdigital[.]cloud`), which served a 7-Zip archive containing the lightweight GoCaracal implant.

## Technical Analysis of the Malicious Payload

### 1. Delivery Chain: SVG Phishing to Implant Deployment

The infection chain follows a multi-stage delivery process:

1. **Phishing email** with Spanish-language financial/tax lure containing an SVG attachment
2. **SVG attachment** contains a Base64-encoded shortened URL that auto-redirects
3. **URL shortener** redirects to an intermediate redirector
4. **Redirector** sends the victim to the attacker staging site (seven identified staging domains)
5. **Staging site** serves a **7-Zip archive** containing the GoCaracal lightweight implant
6. **Lightweight implant** establishes initial C2 and pulls the second stage
7. **Delphi loader** delivers both the Bandook backdoor and the extended GoCaracal build

### 2. GoCaracal Framework

GoCaracal is a modular Go-based malware framework with two operational profiles:

**Lightweight Build** -- initial foothold:
- Host profiling and system information discovery
- Encrypted C2 channel (AES-GCM)
- Interactive remote shell
- Payload download and execution
- Shellcode loading and injection (including WoW64 injection for 32-bit processes)
- Antivirus detection and enumeration
- File operations (save, open)
- Smart sleep / jitter mechanisms

**Extended Build** -- full post-compromise (34 command handlers):
- All lightweight capabilities plus:
- File management and targeted file search
- Browser credential and cookie collection (Chrome, Brave, Firefox)
- Keylogging
- Process enumeration
- WebRTC-based remote desktop access
- Hidden VNC behavior
- Cloned Chrome profile sessions (hidden browser)
- SOCKS5 proxy tunneling
- Persistence via registry-hive manipulation and NTUSER.MAN Run-key workflow
- Ethereum smart-contract C2 fallback (BulletproofC2)

Development occurred in four phases from January to July 2026, with command identifiers evolving from the Bandook-style `@0001`--`@0136` format to randomized strings, and plugin export names obfuscated with generic labels.

### 3. C2 Infrastructure

**GoCaracal C2:** 24 unique C2 IP addresses were extracted from analyzed samples, with 23 of 24 hosted on AEZA Group-operated networks. Communications use AES-GCM encrypted channels.

**Bandook C2:** Hosted separately on AlexHost infrastructure (5 identified IPs).

**Ethereum BulletproofC2 Fallback:** After primary C2 failures, the extended GoCaracal build sends an `eth_getStorageAt` request to a public Ethereum JSON-RPC endpoint to retrieve a replacement C2 address stored in a custom Solidity smart contract named "BulletproofC2." The contract stores one mutable C2 value and restricts updates to the deploying wallet owner. This mechanism allows operators to rotate C2 infrastructure without shipping a new binary. Transaction history confirmed the configured value was changed to a public IP address, indicating operational use rather than dormant code. Additional identical contracts were deployed and tested on the Ethereum Sepolia testnet before mainnet deployment.

### 4. Platform-Specific Behavior

#### Windows

GoCaracal targets Windows systems exclusively based on observed samples:
- Uses WoW64 shellcode injection for 32-bit process compatibility
- Persistence via registry Run-key manipulation and NTUSER.MAN artifacts
- Persistence paths observed: `%AppData%\Roaming\d30547514515\91ed375e.exe` and `%AppData%\Roaming\e1d58f51c58a\5c0416e4.exe`
- Browser credential theft targets Chrome, Brave, and Firefox data stores
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`

### 5. Anti-Forensics / Evasion Techniques

- Randomized command identifiers replacing sequential Bandook-style format
- Plugin export names obfuscated with generic labels
- Smart sleep / jitter mechanism to evade beacon-interval detection
- AES-GCM encrypted C2 communications
- Blockchain-based C2 fallback resistant to domain takedowns and IP blocking
- Use of URL shorteners and multi-stage redirectors in delivery chain

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path / Filename | Hash (SHA-256) | Description |
|----------|----------------|----------------|-------------|
| Windows | TF-OFICINA004A9.exe | `1e499c815146124c4a6d2b48c99068b980ad74e1a2cfd16013f8d75a9425a0ca` | GoCaracal Lightweight variant |
| Windows | TF-OFICINA004A9.exe | `77f7ad29f4a8037ee5f38d3d87fb91cfd97cb8f7fa7883edf3fce506df5200c0` | GoCaracal Lightweight variant |
| Windows | TF-OFICINA004A9.exe | `c9da1b08a39491dfdbede6ff4c1a2d383f57cb29e2d3532aee08d6e0a5c1dda6` | GoCaracal Lightweight variant (YARA ref sample) |
| Windows | VRJDL_21812.exe | `8c03d072df2e1bf14b0c00a8ab99834138c8b69f301849bf09cb44394e916015` | GoCaracal Extended variant |
| Windows | 7676230602QQ.exe | `0a6da70548f14834acb8960689a589b48ff422f8385ae445a281aab77045fe22` | Delphi Loader |
| Windows | (decrypted payload) | `a2cdf2fe741de4b13ad2298b387a6c32da4a94da180ae75bf8547386aee7376b` | Bandook backdoor payload |
| Windows | `%AppData%\Roaming\d30547514515\91ed375e.exe` | -- | GoCaracal persistence path |
| Windows | `%AppData%\Roaming\e1d58f51c58a\5c0416e4.exe` | -- | GoCaracal persistence path |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `getpdfdigital[.]cloud` | Staging / payload delivery |
| Domain | `getpdf[.]digital` | Staging / payload delivery |
| Domain | `visualizarpdf[.]online` | Staging / payload delivery |
| Domain | `contabilidad[.]icu` | Staging / payload delivery |
| Domain | `soportedigital[.]cloud` | Staging / payload delivery |
| Domain | `documentodigital[.]cloud` | Staging / payload delivery |
| Domain | `gestionadocs[.]me` | Staging / payload delivery (new, July 2026) |
| IP | `109.120.187[.]217` | GoCaracal C2 (AEZA Group) |
| IP | `109.172.95[.]121` | GoCaracal C2 (AEZA Group) |
| IP | `138.124.112[.]213` | GoCaracal C2 (AEZA Group) |
| IP | `138.124.14[.]130` | GoCaracal C2 (AEZA Group) |
| IP | `176.124.220[.]153` | GoCaracal C2 (AEZA Group) |
| IP | `185.125.101[.]181` | GoCaracal C2 (AEZA Group) |
| IP | `185.96.80[.]110` | GoCaracal C2 (AEZA Group) |
| IP | `185.96.80[.]54` | GoCaracal C2 (AEZA Group) |
| IP | `193.233.245[.]52` | GoCaracal C2 (AEZA Group) |
| IP | `62.60.237[.]22` | GoCaracal C2 (AEZA Group) |
| IP | `77.110.104[.]98` | GoCaracal C2 (AEZA Group) |
| IP | `77.110.105[.]244` | GoCaracal C2 (AEZA Group) |
| IP | `77.110.105[.]56` | GoCaracal C2 (AEZA Group) |
| IP | `77.110.105[.]59` | GoCaracal C2 (AEZA Group) |
| IP | `77.110.98[.]66` | GoCaracal C2 (AEZA Group) |
| IP | `80.71.224[.]30` | GoCaracal C2 (AEZA Group) |
| IP | `82.117.87[.]138` | GoCaracal C2 (AEZA Group) |
| IP | `82.117.87[.]192` | GoCaracal C2 (AEZA Group) |
| IP | `85.192.30[.]211` | GoCaracal C2 (AEZA Group) |
| IP | `79.137.192[.]38` | GoCaracal C2 (AEZA Group) |
| IP | `193.233.245[.]0` | GoCaracal C2 (AEZA Group) |
| IP | `193.233.245[.]45` | GoCaracal C2 (AEZA Group) |
| IP | `46.226.162[.]68` | GoCaracal C2 (AEZA Group) |
| IP | `45.152.198[.]108` | GoCaracal C2 |
| IP | `91.208.197[.]80` | Bandook C2 (AlexHost) |
| IP | `91.208.184[.]45` | Bandook C2 (AlexHost) |
| IP | `91.208.206[.]88` | Bandook C2 (AlexHost) |
| IP | `91.208.184[.]130` | Bandook C2 (AlexHost) |
| IP | `176.123.1[.]174` | Bandook C2 (AlexHost) |

### Blockchain

| Type | Value | Context |
|------|-------|---------|
| Ethereum Contract | `0x03D605f13A74Bfb6149078122FcF62BD6d8799d8` | BulletproofC2 primary (mainnet, deployed May 20, 2026) |
| Ethereum Contract | `0x04aB453494381E60171BE04Ea6BE6E7C44EafAfd` | BulletproofC2 additional deployment |
| Ethereum Contract | `0xD7635f31620772882a6712472a6278c53247Bc44` | BulletproofC2 additional deployment |
| Ethereum Contract | `0xf165F26300BF65DFaC78BC9557326bDbB3C6d33C` | BulletproofC2 additional deployment |
| Ethereum Wallet | `0x7D321FE277f8c25aaC14aF1BA3Fc34953242052F` | Deployer wallet (Sepolia testnet + mainnet) |

### Behavioral

- Process execution from `%AppData%\Roaming\<12-char-hex>\<8-char-hex>.exe` persistence paths
- Outbound HTTP POST requests containing `eth_getStorageAt` JSON-RPC method targeting Ethereum endpoints
- Encrypted C2 beaconing with smart-sleep jitter to AEZA Group-hosted infrastructure
- Browser data exfiltration targeting Chrome, Brave, and Firefox credential stores
- SVG file attachments containing Base64-encoded shortened URLs in phishing emails

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.001 | Spearphishing Attachment | SVG attachments with embedded Base64-encoded URLs in financial/tax lure emails |
| T1204.002 | User Execution: Malicious File | Victim opens SVG triggering redirect chain to 7-Zip archive download |
| T1105 | Ingress Tool Transfer | Lightweight implant downloads Delphi loader with Bandook + extended GoCaracal |
| T1547.001 | Registry Run Keys / Startup Folder | Registry-hive manipulation and NTUSER.MAN Run-key persistence |
| T1059 | Command and Scripting Interpreter | Interactive remote shell execution |
| T1055 | Process Injection | Shellcode injection including WoW64 variant for 32-bit processes |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 communications with AES-GCM encryption |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-GCM encrypted C2 channel |
| T1102.002 | Web Service: Bidirectional Communication | Ethereum smart contract used as C2 address fallback via eth_getStorageAt |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome, Brave, Firefox credential and cookie collection |
| T1056.001 | Input Capture: Keylogging | Keylogger in extended GoCaracal build |
| T1090.001 | Proxy: Internal Proxy | SOCKS5 proxy tunneling capability |
| T1518.001 | Software Discovery: Security Software Discovery | Antivirus product enumeration (detectAntivirus, AntivirusProduct) |
| T1082 | System Information Discovery | Host profiling and OS version detection |
| T1083 | File and Directory Discovery | Targeted file search capability |

## Impact Assessment

Arctic Wolf identified 249 related GoCaracal samples spanning January to July 2026, indicating sustained and scaled operations. The primary target was a communications organization in Venezuela, with broader assessed targeting across Brazil, Ecuador, Chile, Colombia, El Salvador, and Uruguay. The Ethereum smart-contract C2 fallback represents a significant escalation in operational resilience -- domain takedowns and IP blocking alone are insufficient to disrupt command-and-control, as the operator can atomically update the fallback address on an immutable, publicly accessible blockchain without victim-side binary updates. The combination of GoCaracal with the legacy Bandook backdoor provides redundant access, complicating complete eradication.

## Detection & Remediation

### Immediate Detection

- Search proxy/web logs for outbound HTTP POST requests containing `eth_getStorageAt` -- this is the Ethereum JSON-RPC method GoCaracal uses for C2 fallback
- Search DNS logs for queries to the seven identified staging domains
- Search network flow data for connections to the 24 GoCaracal C2 IPs and 5 Bandook C2 IPs
- Search endpoint telemetry for processes executing from `%AppData%\Roaming\<hex-string>\<hex-string>.exe` paths
- Scan file systems with the YARA rules below against PE executables under 30 MB

### Remediation

1. **Contain:** Isolate affected hosts; block all identified C2 IPs and staging domains at the firewall/proxy
2. **Eradicate:** Remove GoCaracal persistence entries from registry Run keys and associated NTUSER.MAN artifacts; delete implant binaries from `%AppData%\Roaming` persistence paths
3. **Credential rotation:** Force password resets for all accounts on affected systems; invalidate browser-stored credentials for Chrome, Brave, and Firefox
4. **Network:** Block Ethereum JSON-RPC traffic from non-approved hosts if no legitimate Web3 use exists; monitor for connections to AEZA Group and AlexHost IP ranges
5. **Recover:** Reimage affected systems from known-good backups; verify integrity of restored systems before reconnection

### Long-Term Hardening

- Implement SVG attachment filtering at the email gateway (block or sandbox SVG files)
- Deploy DNS sinkholing for document-themed domains with `.cloud`, `.digital`, `.online`, `.icu`, `.me` TLDs from unknown registrants
- Monitor for Ethereum JSON-RPC traffic patterns from endpoints that should not interact with blockchain infrastructure
- Ensure Sysmon or equivalent telemetry captures process creation, network connections, and registry modifications
- Consider blocking outbound access to public Ethereum JSON-RPC endpoints from general-purpose workstations

## Detection Rules

These detections target GoCaracal/Dark Caracal campaign-specific indicators: staging domains, C2 IPs, persistence paths, the BulletproofC2 Ethereum fallback mechanism, and GoCaracal binary strings. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; YARA rules compile; Snort/Suricata rules are structurally validated (compilers not installed). Compiles does not equal fires -- verify in your pipeline with the IOCs above.

### Sigma: DNS Query to GoCaracal Staging Domains

Detects DNS resolution of the seven known Dark Caracal staging domains used for GoCaracal payload delivery.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (tag validators excluded - proxy blocks MITRE ATT&CK data fetch); splunk 0; log_scale 0. IOC-anchored on 7 attacker-registered domains. FP: effectively zero unless domains are re-registered post-takedown. -->

```yaml
title: DNS Query to GoCaracal Dark Caracal Staging Domain
id: 7c3a1b4e-9f82-4d6a-b5e1-2c8d7f0a3e9b
status: experimental
description: >
    Detects DNS queries to known Dark Caracal staging domains used for GoCaracal
    malware delivery via phishing campaigns targeting Latin American organizations.
references:
    - https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/
    - https://thehackernews.com/2026/08/gocaracal-malware-uses-ethereum-smart.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1566.001
    - attack.t1105
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'getpdfdigital.cloud'
            - 'getpdf.digital'
            - 'visualizarpdf.online'
            - 'contabilidad.icu'
            - 'soportedigital.cloud'
            - 'documentodigital.cloud'
            - 'gestionadocs.me'
    condition: selection
falsepositives:
    - Unlikely - these are attacker-registered domains
level: high
```

### Sigma: Network Connection to GoCaracal C2 IPs

Detects outbound connections to the 24 known GoCaracal C2 addresses, predominantly on AEZA Group networks.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. 24 IPs from Arctic Wolf's published IOC list. FP risk: post-rotation IP reuse by legitimate tenants on AEZA Group shared hosting. Time-bound indicator. -->

```yaml
title: Network Connection to GoCaracal C2 Infrastructure
id: a4f28e51-3b7c-4d19-8e6a-1f5c9d0b2a7e
status: experimental
description: >
    Detects outbound network connections to known GoCaracal C2 IP addresses hosted
    on AEZA Group networks, linked to Dark Caracal operations targeting LATAM.
references:
    - https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/
    - https://thehackernews.com/2026/08/gocaracal-malware-uses-ethereum-smart.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '109.120.187.217'
            - '109.172.95.121'
            - '138.124.112.213'
            - '138.124.14.130'
            - '176.124.220.153'
            - '185.125.101.181'
            - '185.96.80.110'
            - '185.96.80.54'
            - '193.233.245.52'
            - '62.60.237.22'
            - '77.110.104.98'
            - '77.110.105.244'
            - '77.110.105.56'
            - '77.110.105.59'
            - '77.110.98.66'
            - '80.71.224.30'
            - '82.117.87.138'
            - '82.117.87.192'
            - '85.192.30.211'
            - '79.137.192.38'
            - '193.233.245.0'
            - '193.233.245.45'
            - '46.226.162.68'
            - '45.152.198.108'
    condition: selection
falsepositives:
    - Legitimate services hosted on the same IPs after infrastructure rotation
level: high
```

### Sigma: Network Connection to Bandook C2 IPs

Detects outbound connections to the 5 known Bandook C2 addresses on AlexHost infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. 5 IPs from Arctic Wolf's published IOC list. Same FP caveat as GoCaracal C2 rule. -->

```yaml
title: Network Connection to Dark Caracal Bandook C2 Infrastructure
id: d9e72f13-6a4b-4c85-9d31-8b0e5f2a1c6d
status: experimental
description: >
    Detects outbound network connections to known Bandook backdoor C2 IP addresses
    hosted on AlexHost, associated with Dark Caracal operations in LATAM.
references:
    - https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/
author: Actioner
date: 2026-08-28
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '91.208.197.80'
            - '91.208.184.45'
            - '91.208.206.88'
            - '91.208.184.130'
            - '176.123.1.174'
    condition: selection
falsepositives:
    - Legitimate services hosted on the same IPs after infrastructure rotation
level: high
```

### Sigma: GoCaracal Execution from Persistence Path

Detects process execution from the specific `%AppData%\Roaming` persistence paths used by GoCaracal implants.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keyed on two known persistence paths with hex-randomized directory/file names. FP: effectively zero -- patterns are campaign-specific. -->

```yaml
title: GoCaracal Execution from Known Persistence Path
id: b5c83d29-1e4f-4a7b-9c62-3d8a0f7e5b14
status: experimental
description: >
    Detects process execution from AppData persistence paths matching the naming
    pattern used by GoCaracal implants deployed by Dark Caracal.
references:
    - https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/
author: Actioner
date: 2026-08-28
tags:
    - attack.t1547.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '\d30547514515\91ed375e.exe'
            - '\e1d58f51c58a\5c0416e4.exe'
    condition: selection
falsepositives:
    - Unlikely - paths use randomized directory and file naming specific to this campaign
level: critical
```

### Sigma: Ethereum JSON-RPC eth_getStorageAt in Proxy Logs

Detects HTTP POST requests containing the `eth_getStorageAt` method in proxy logs, used by GoCaracal's BulletproofC2 fallback mechanism. Scope to non-Web3 endpoints to reduce false positives.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. cs-body field requires proxy that logs request body content. The eth_getStorageAt method alone is not malicious (legitimate Ethereum queries use it), so this is medium confidence and should be scoped to endpoints without legitimate Web3/DeFi activity. -->

```yaml
title: Ethereum JSON-RPC eth_getStorageAt Request via Proxy
id: e6f91a48-2c5d-4b73-a8d4-7e0f3c1b9a25
status: experimental
description: >
    Detects HTTP POST requests containing the eth_getStorageAt Ethereum JSON-RPC
    method in proxy logs, which GoCaracal uses as a C2 fallback mechanism to
    retrieve replacement C2 addresses from a smart contract.
references:
    - https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/
author: Actioner
date: 2026-08-28
tags:
    - attack.t1102.002
logsource:
    category: proxy
detection:
    selection_method:
        cs-method: 'POST'
    selection_body:
        cs-body|contains: 'eth_getStorageAt'
    condition: selection_method and selection_body
falsepositives:
    - Legitimate Ethereum node queries or Web3 applications
    - Cryptocurrency trading platforms and DeFi applications
level: medium
```

### Snort: DNS Query to GoCaracal Staging Domains

Detects DNS queries for three primary GoCaracal staging domains using label-length-encoded matching.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed. Structural check: semicolons, flow, content with label-length encoding, classtype, sid, rev all present. One rule per domain due to DNS wire-format encoding. -->

```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to GoCaracal Staging Domain getpdfdigital.cloud"; flow:to_server; content:"|0e|getpdfdigital|05|cloud|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created 2026-08-28; sid:2100010; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to GoCaracal Staging Domain getpdf.digital"; flow:to_server; content:"|06|getpdf|07|digital|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created 2026-08-28; sid:2100011; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to GoCaracal Staging Domain visualizarpdf.online"; flow:to_server; content:"|0d|visualizarpdf|06|online|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created 2026-08-28; sid:2100012; rev:1;)
```

### Snort: Ethereum JSON-RPC GoCaracal BulletproofC2 Fallback

Detects HTTP POST requests containing `eth_getStorageAt` targeting the primary BulletproofC2 contract address.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed. Structural check: http protocol, flow established+to_server, http_method/http_client_body sticky buffers, dual content match (method + contract address), classtype, sid, rev. High confidence because it keys on both the RPC method AND the specific contract address. -->

```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Ethereum JSON-RPC eth_getStorageAt GoCaracal C2 Fallback"; flow:established,to_server; http_method; content:"POST"; http_client_body; content:"eth_getStorageAt"; fast_pattern; content:"0x03D605f13A74Bfb6149078122FcF62BD6d8799d8"; nocase; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created 2026-08-28; sid:2100013; rev:1;)
```

### Suricata: DNS Query to GoCaracal Staging Domains

Detects DNS queries for all seven known GoCaracal staging domains using Suricata's `dns.query` buffer.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed. Structural check: dns protocol, dns.query sticky buffer (dot notation), flow to_server, content nocase+fast_pattern, classtype, metadata, sid in 2200000+ range, rev. -->

```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to GoCaracal Staging Domain getpdfdigital.cloud"; flow:to_server; dns.query; content:"getpdfdigital.cloud"; nocase; fast_pattern; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created_at 2026-08-28; sid:2200010; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to GoCaracal Staging Domain getpdf.digital"; flow:to_server; dns.query; content:"getpdf.digital"; nocase; fast_pattern; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created_at 2026-08-28; sid:2200011; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to GoCaracal Staging Domain visualizarpdf.online"; flow:to_server; dns.query; content:"visualizarpdf.online"; nocase; fast_pattern; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created_at 2026-08-28; sid:2200012; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to GoCaracal Staging Domain contabilidad.icu"; flow:to_server; dns.query; content:"contabilidad.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created_at 2026-08-28; sid:2200013; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to GoCaracal Staging Domain soportedigital.cloud"; flow:to_server; dns.query; content:"soportedigital.cloud"; nocase; fast_pattern; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created_at 2026-08-28; sid:2200014; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to GoCaracal Staging Domain documentodigital.cloud"; flow:to_server; dns.query; content:"documentodigital.cloud"; nocase; fast_pattern; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created_at 2026-08-28; sid:2200015; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to GoCaracal Staging Domain gestionadocs.me"; flow:to_server; dns.query; content:"gestionadocs.me"; nocase; fast_pattern; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created_at 2026-08-28; sid:2200016; rev:1;)
```

### Suricata: Ethereum JSON-RPC GoCaracal BulletproofC2 Fallback

Detects HTTP POST requests containing `eth_getStorageAt` targeting the primary BulletproofC2 contract address using Suricata dot-notation buffers.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed. Structural check: http protocol, flow established+to_server, http.method + http.request_body dot-notation sticky buffers, dual content (method + contract address), classtype, metadata, sid 2200000+, rev. -->

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Ethereum JSON-RPC eth_getStorageAt GoCaracal BulletproofC2 Fallback"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"eth_getStorageAt"; fast_pattern; content:"0x03D605f13A74Bfb6149078122FcF62BD6d8799d8"; nocase; classtype:trojan-activity; reference:url,arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/; metadata:author Actioner, created_at 2026-08-28; sid:2200017; rev:1;)
```

### YARA: GoCaracal Lightweight RAT

Detects the GoCaracal lightweight variant via Go function names and internal strings (`main.InjectShellcode`, `RPCFallback`, `insensate`, etc.) identified by Arctic Wolf Labs.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. 18 strings from Arctic Wolf's published YARA rule and blog post analysis. Condition: 5-of-18 threshold balances detection breadth (stripped/partial builds) with precision. filesize < 30MB scopes to plausible Go binary size. Arctic Wolf's original rule uses identical strings with same 5-of threshold. -->

```yara
rule APT_DarkCaracal_GoCaracal_Lightweight_RAT
{
    meta:
        description = "Detects GoCaracal lightweight RAT variant deployed by Dark Caracal, based on Go function names and internal strings identified by Arctic Wolf Labs"
        author = "Actioner"
        date = "2026-08-28"
        reference = "https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/"
        hash = "1e499c815146124c4a6d2b48c99068b980ad74e1a2cfd16013f8d75a9425a0ca"
        hash2 = "77f7ad29f4a8037ee5f38d3d87fb91cfd97cb8f7fa7883edf3fce506df5200c0"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $fn1 = "main.cleanupShell" ascii
        $fn2 = "main.handleConnection" ascii
        $fn3 = "main.detectAntivirus" ascii
        $fn4 = "main.saveFile" ascii
        $fn5 = "main.openUrl" ascii
        $fn6 = "main.smartSleep" ascii
        $fn7 = "main.runModule" ascii
        $fn8 = "main.InjectShellcode" ascii
        $fn9 = "main.injectShellcodeWoW64" ascii
        $fn10 = "main.handlePipeClient" ascii
        $fn11 = "main.loadAPIs" ascii
        $fn12 = "main.AntivirusProduct" ascii
        $fn13 = "main.lastInputInfo" ascii

        $s1 = "insensate" ascii
        $s2 = "readSecurePacket" ascii
        $s3 = "SendSecurePacket" ascii
        $s4 = "getRawOSVersion" ascii
        $s5 = "RPCFallback" ascii

    condition:
        filesize < 30MB and
        5 of them
}
```

### YARA: GoCaracal Extended RAT with BulletproofC2

Detects the GoCaracal extended variant by combining Go function names, BulletproofC2/Ethereum strings, and known contract addresses.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Condition: (3 function names + 2 internal strings) OR (any Ethereum contract address + 1 internal string). The Ethereum contract addresses are campaign-unique, so their presence with any GoCaracal string is high-signal. -->

```yara
rule APT_DarkCaracal_GoCaracal_Extended_RAT
{
    meta:
        description = "Detects GoCaracal extended RAT variant with Ethereum C2 fallback and post-compromise capabilities deployed by Dark Caracal"
        author = "Actioner"
        date = "2026-08-28"
        reference = "https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/"
        hash = "8c03d072df2e1bf14b0c00a8ab99834138c8b69f301849bf09cb44394e916015"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $fn1 = "main.InjectShellcode" ascii
        $fn2 = "main.smartSleep" ascii
        $fn3 = "main.detectAntivirus" ascii
        $fn4 = "main.handleConnection" ascii
        $fn5 = "main.loadAPIs" ascii

        $s1 = "RPCFallback" ascii
        $s2 = "SendSecurePacket" ascii
        $s3 = "readSecurePacket" ascii
        $s4 = "BulletproofC2" ascii
        $s5 = "eth_getStorageAt" ascii
        $s6 = "getRawOSVersion" ascii

        $eth1 = "0x03D605f13A74Bfb6149078122FcF62BD6d8799d8" ascii nocase
        $eth2 = "0x04aB453494381E60171BE04Ea6BE6E7C44EafAfd" ascii nocase
        $eth3 = "0xD7635f31620772882a6712472a6278c53247Bc44" ascii nocase
        $eth4 = "0xf165F26300BF65DFaC78BC9557326bDbB3C6d33C" ascii nocase

    condition:
        filesize < 30MB and
        (
            (3 of ($fn*) and 2 of ($s*)) or
            (any of ($eth*) and 1 of ($s*))
        )
}
```

## Lessons Learned

1. **Blockchain-backed C2 resilience is operational, not theoretical.** Dark Caracal's BulletproofC2 smart contract was tested on the Sepolia testnet and deployed to mainnet with observed C2 address updates. Defenders relying solely on domain and IP blocking must now account for adversaries who can atomically rotate infrastructure via immutable public blockchains.

2. **Legacy and modern tooling coexist.** The simultaneous deployment of the aging Bandook backdoor alongside the new GoCaracal framework demonstrates that APT groups layer redundant access -- eradicating one tool does not guarantee the other is absent. Detection strategies must cover both.

3. **SVG phishing attachments bypass traditional document filters.** SVG files are not commonly blocked by email gateways but can execute JavaScript and embed redirect URLs, making them an effective delivery vector that warrants explicit policy attention.

4. **Go-based malware retains function symbols.** The 18 distinct `main.*` function strings in unstripped GoCaracal binaries provide strong detection signatures, but defenders should prepare for stripped builds that eliminate these names.

## Sources

- [Arctic Wolf Labs - Dark Caracal Reloaded: New Malware, Same Hunting Grounds](https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/) -- primary technical research, IOCs, YARA rule, and campaign analysis
- [The Hacker News - GoCaracal Malware Uses Ethereum Smart Contract to Fetch Replacement C2 Address](https://thehackernews.com/2026/08/gocaracal-malware-uses-ethereum-smart.html) -- secondary reporting with additional context
- [Security Affairs - Dark Caracal Deploys New Go Malware with Ethereum-Based C2 Fallback](https://securityaffairs.com/197948/apt/dark-caracal-deploys-new-go-malware-with-ethereum-based-c2-fallback.html) -- secondary reporting with infrastructure details

---
*Report generated by Actioner*
