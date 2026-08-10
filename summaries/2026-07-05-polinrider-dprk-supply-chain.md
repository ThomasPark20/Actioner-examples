# PolinRider Campaign -- DPRK Supply Chain Attack Across npm, Packagist, Go, and Chrome

**Date:** 2026-07-05
**Status:** FINAL
**Threat Actor:** Contagious Interview (G1052) / Lazarus / Famous Chollima / DPRK-attributed
**Campaign:** PolinRider

---

## Executive Summary

North Korean threat actors operating under the Contagious Interview umbrella (MITRE ATT&CK G1052) have published 108 malicious packages across 162 release artifacts spanning npm (19 packages), Packagist/Composer (10 packages), Go modules (61+ packages), and one Google Chrome extension. The campaign, tracked as PolinRider, uses compromised maintainer accounts and expired domain takeovers to inject obfuscated JavaScript loaders into legitimate repositories. These loaders retrieve encrypted second-stage payloads from blockchain infrastructure (TRON, Aptos, BNB Smart Chain), ultimately deploying DEV#POPPER RAT and OmniStealer for credential theft, cryptocurrency wallet exfiltration, and persistent remote access. A parallel sub-campaign published six npm packages mimicking Rollup polyfill utilities that communicate with a C2 server at 216[.]126[.]236[.]244 and use JSONKeeper for payload staging. As of April 2026, 1,951 public GitHub repositories belonging to 1,047 owners have been compromised, with activity ongoing.

---

## Background

Contagious Interview is a North Korea-aligned threat group active since at least 2023, conducting both cyberespionage and financially motivated operations. The group targets software developers through fake job interviews, supply chain compromise, and social engineering on platforms like LinkedIn, GitHub, and freelance websites. The PolinRider campaign represents the latest evolution of this operation, merging with the TaskJacker cluster (malicious VS Code task file injection) and the Fake Font variant (JavaScript payloads disguised as .woff2 font files). The campaign exploits developer tooling ecosystems at scale, with Git history rewriting (force pushes and anti-dated commits) used to obscure the timing of malicious modifications.

---

## Technical Analysis

### Attack Chain

1. **Initial Access**: Threat actors compromise npm/GitHub maintainer accounts or exploit expired domain takeovers to gain publish access to legitimate packages
2. **Code Injection**: Obfuscated JavaScript payloads are appended to developer configuration files (postcss.config.mjs, tailwind.config.js, eslint.config.mjs, next.config.mjs, vite.config.js) or concealed in fake .woff2 font files
3. **Concealment**: Whitespace padding hides malicious code beyond default screen width; Git history is rewritten with anti-dated commits to disguise injection timing
4. **Execution Trigger**: VS Code task files (`.vscode/tasks.json`) with `runOn: folderOpen` auto-execute on project open; npm install scripts execute during package installation
5. **Sandbox Evasion**: Environment variable checks (CODESPACE_NAME, CODESANDBOX_HOST, VERCEL, AWS_LAMBDA_FUNCTION_NAME, GOOGLE_CLOUD_PROJECT, AZURE_FUNCTIONS_ENVIRONMENT, SOCKET_DEV, DOCKER, RENDER) prevent execution in analysis environments
6. **Payload Retrieval**: Stage 1 loader contacts blockchain RPC services (TronGrid, Aptos, BSC) to retrieve XOR-encrypted payloads, or retrieves JavaScript from JSONKeeper URLs
7. **Decryption**: XOR keys (`2[gWfGj;<:-93Z^C`, `m6:tTh^D)cBz?NM]`) and AES-256-CBC with scrypt derivation (salt: `98cb54c0b4ac259d30c9c1ca1ae87c68`) decrypt staged payloads
8. **RAT Deployment**: DEV#POPPER RAT establishes socket.io-based C2 backdoor for shell access, screenshot capture, file operations, and input device control
9. **Credential Theft**: OmniStealer harvests browser credentials, cryptocurrency wallets (MetaMask, Phantom, TronLink, Trust, Binance, Coinbase, OKX), developer artifacts (.aws, .azure, .ssh, .gnupg, .claude, .vscode), and monitors clipboard

### Rollup Polyfill Sub-Campaign

Six npm packages masquerade as Rollup polyfill utilities. `rollup-packages-polyfill-core` installs `swift-parse-stream` and `rollup-runtime-polyfill-core` installs `quirky-token` via base64-encoded npm install commands. The second-stage packages disguise themselves as SVG sanitization utilities (functions: `ValidateSvgModule`, `checkPlugin`, `getPlugin`) while fetching JavaScript from JSONKeeper and executing via `eval()`. The payload connects to C2 at 216[.]126[.]236[.]244 across multiple ports for backdoor communication and data exfiltration.

### PolinRider Config Injection

The primary campaign variant uses two obfuscator strains:
- **Original variant**: Marker string `rmcej%otb%`, decoder function `_$_1e42`, shuffle seeds `2857687`/`2667686`, global injection via `global['!']`
- **New variant**: Marker string `Cot%3t=shtP`, decoder function `MDy`, shuffle seeds `1111436`/`3896884`, global injection via `global['_V']`

PostCSS config files account for approximately 62% of infected repositories.

---

## Indicators of Compromise

### Malicious npm Packages

| Package | Context |
|---|---|
| rollup-packages-polyfill-core | Rollup polyfill mimic; installs swift-parse-stream |
| rollup-runtime-polyfill-core | Rollup polyfill mimic; installs quirky-token |
| swift-parse-stream | Second-stage SVG utility disguise |
| quirky-token | Second-stage SVG utility disguise |
| react-icon-svgs | Malicious Rollup-adjacent package |
| rollup-plugin-polyfill-connect | Malicious Rollup-adjacent package |
| tailwindcss-style-animate (v1.1.6) | PostCSS/Tailwind impersonation |
| tailwind-mainanimation (v2.3.3) | PostCSS/Tailwind impersonation |
| tailwind-autoanimation (v2.3.6) | PostCSS/Tailwind impersonation |
| tailwind-animationbased | PostCSS/Tailwind impersonation |
| tailwindcss-typography-style (v0.8.2) | PostCSS/Tailwind impersonation |
| tailwindcss-style-modify (v0.8.3) | PostCSS/Tailwind impersonation |
| tailwindcss-animate-style (v1.2.5) | PostCSS/Tailwind impersonation |
| @common-stack/generate-plugin (v9.0.2-alpha.21, .22) | Hijacked legitimate package |

### Compromised npm Accounts

| Account | Status |
|---|---|
| allavin | Deleted |
| blackedward | Deleted |

### Compromised GitHub Accounts/Organizations

| Account | Context |
|---|---|
| Xpos587 | Compromised maintainer |
| 7span | GitHub organization |
| Artiffusion-Inc | GitHub organization |

### Network Indicators

| Type | Indicator (Defanged) | Context |
|---|---|---|
| IP | 216[.]126[.]236[.]244 | Primary C2 server |
| URL | hxxps://www[.]jsonkeeper[.]com/b/3P9BF | JSONKeeper payload host |
| URL | hxxp://216[.]126[.]236[.]244/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68 | Payload retrieval |
| URL | hxxp://216[.]126[.]236[.]244/api/service/makelog | C2 beacon |
| URL | hxxp://216[.]126[.]236[.]244/api/service/process/ | Process control |
| Port | 216[.]126[.]236[.]244:4801 | Socket.IO backdoor |
| Port | 216[.]126[.]236[.]244:4806 | Upload/exfiltration |
| Port | 216[.]126[.]236[.]244:4809 | Upload/exfiltration |
| URL | hxxp://216[.]126[.]236[.]244:4809/cldbs | Cloud DB exfil |

### Vercel C2 Subdomains (Defanged)

| Subdomain | Purpose |
|---|---|
| 260120[.]vercel[.]app | C2 staging |
| default-configuration[.]vercel[.]app | C2 staging |
| vscode-settings-bootstrap[.]vercel[.]app | VS Code bootstrap |
| vscode-settings-config[.]vercel[.]app | VS Code config |
| vscode-bootstrapper[.]vercel[.]app | VS Code bootstrap |
| vscode-load-config[.]vercel[.]app | VS Code config |

### Blockchain Dead-Drop Infrastructure

| Blockchain | Address |
|---|---|
| Tron | TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP |
| Tron | TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG |
| Aptos | 0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e |
| Aptos | 0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3 |

### Obfuscator Signature Strings

| Variant | Marker | Decoder | Seeds | Global |
|---|---|---|---|---|
| Original | rmcej%otb% | _$_1e42 | 2857687 / 2667686 | global['!'] |
| New | Cot%3t=shtP | MDy | 1111436 / 3896884 | global['_V'] |

### Cryptographic Artifacts

| Type | Value | Context |
|---|---|---|
| XOR Key | 2[gWfGj;<:-93Z^C | Payload decryption |
| XOR Key | m6:tTh^D)cBz?NM] | Payload decryption |
| AES Salt | 98cb54c0b4ac259d30c9c1ca1ae87c68 | scrypt-derived AES-256-CBC |
| Decoder Seed | rmcej%otb% | Shuffle cipher marker |

### File Artifacts

| Path | Description |
|---|---|
| postcss.config.mjs | Primary injection target (~62% of infections) |
| tailwind.config.js | Injection target |
| eslint.config.mjs | Injection target |
| next.config.mjs | Injection target |
| vite.config.js / vite.config.mjs | Injection target |
| webpack.config.js | Injection target |
| .vscode/tasks.json | VS Code auto-run task (runOn: folderOpen) |
| public/fonts/fa-solid-400.woff2 | JavaScript disguised as font file |
| <tmp>/pack | AES-wrapped loader |
| <tmp>/scdata | Remote access component |
| <tmp>/ldata | Browser/wallet data stealer |
| <tmp>/.npm/vhost.ctl | Process marker |
| temp_auto_push.bat | Git history rewriting script |

### Targeted Directories (Data Theft)

.aws, .azure, .ssh, .gnupg, .config, .foundry, .vscode, .cursor, .windsurf, .claude, Code/User/History, Windsurf/User/History

### Targeted Wallet Extensions (Chrome IDs)

| Extension | ID |
|---|---|
| MetaMask | nkbihfbeogaeaoehlefnkodbefgpgknn |
| MetaMask (variant) | bfnaelmomeimhlpmgjnjophhpkkoljpa |
| MetaMask (variant) | fhbohimaelbohpjbbldcngcnapndodjf |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Campaign Usage |
|---|---|---|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Publishing malicious packages across npm, Packagist, Go modules, and Chrome extensions |
| T1204.005 | User Execution: Malicious Library | Developers install trojanized packages via npm/composer/go get |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Obfuscated JavaScript loaders in config files and fake font files |
| T1059.006 | Command and Scripting Interpreter: Python | InvisibleFerret/OmniStealer Python payloads |
| T1027.010 | Obfuscated Files or Information: Command Obfuscation | Base64-encoded install commands, shuffle-cipher obfuscation |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | XOR and AES-256-CBC encrypted payloads |
| T1036.008 | Masquerading: Masquerade File Type | JavaScript code disguised as .woff2 font files |
| T1102.001 | Web Service: Dead Drop Resolver | Blockchain transactions (TRON/Aptos/BSC) as encrypted payload hosts |
| T1105 | Ingress Tool Transfer | Downloading second-stage payloads from JSONKeeper and C2 |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 communication with specific API paths |
| T1497 | Virtualization/Sandbox Evasion | Environment variable checks to avoid analysis environments |
| T1583.006 | Acquire Infrastructure: Web Services | Vercel subdomains and JSONKeeper for C2/payload hosting |
| T1041 | Exfiltration Over C2 Channel | Data upload to C2 /upload and /cldbs endpoints |
| T1005 | Data from Local System | Harvesting credentials, wallets, SSH keys, cloud configs |
| T1555 | Credentials from Password Stores | Browser credential theft (Chrome, Firefox, Brave, Edge) |
| T1074.001 | Data Staged: Local Data Staging | Staging in tmp/pack, tmp/scdata, tmp/ldata |
| T1070 | Indicator Removal | Git history rewriting with force pushes and anti-dated commits to obscure injection timing |
| T1219 | Remote Access Tools | DEV#POPPER RAT via socket.io backdoor |
| T1657 | Financial Theft | Cryptocurrency wallet theft and seed phrase harvesting |

---

## Detection Rules

### Sigma Rules

#### 1. Obfuscated npm Package Install via Base64 - PolinRider Campaign

Detects Node.js or npm processes executing known PolinRider malicious package names or their base64-encoded variants.

```yaml
title: Obfuscated npm Package Install via Base64 - PolinRider Campaign
id: f1a2b3c4-5d6e-7f8a-9b0c-1d2e3f4a5b6c
status: experimental
description: >
    Detects Node.js or npm processes executing base64-encoded install commands
    for known PolinRider malicious packages (swift-parse-stream, quirky-token).
    These packages masquerade as Rollup polyfill utilities and deliver a RAT
    via JSONKeeper payload retrieval.
references:
    - https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
author: Actioner
date: 2026-07-05
tags:
    - attack.t1059.007
    - attack.t1204.005
    - attack.t1027.010
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\node.exe'
            - '\npm.cmd'
    selection_cmdline:
        CommandLine|contains:
            - 'swift-parse-stream'
            - 'quirky-token'
            - 'c3dpZnQtcGFyc2Utc3RyZWFt'
            - 'rollup-packages-polyfill-core'
            - 'rollup-runtime-polyfill-core'
    condition: selection_parent and selection_cmdline
falsepositives:
    - Legitimate use of identically named packages is extremely unlikely
level: critical
```

<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0; yaml schema valid -->
**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** HIGH
**Coverage Note:** Windows process telemetry only. Linux/macOS coverage requires equivalent Sysmon-for-Linux or Endpoint agent rules.

---

#### 2. Node.js DNS Query to JSONKeeper Payload Host - PolinRider

Detects Node.js resolving jsonkeeper.com, the payload staging service used by PolinRider Rollup polyfill packages.

```yaml
title: Node.js Outbound Connection to JSONKeeper Payload Host - PolinRider
id: a2b3c4d5-6e7f-8a9b-0c1d-2e3f4a5b6c7d
status: experimental
description: >
    Detects Node.js or npm processes making outbound HTTP connections to
    jsonkeeper.com, which the PolinRider campaign uses to host second-stage
    JavaScript payloads retrieved via eval() of the JSON model field.
references:
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
    - https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html
author: Actioner
date: 2026-07-05
tags:
    - attack.t1105
    - attack.t1059.007
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.jsonkeeper.com'
            - 'jsonkeeper.com'
        Image|endswith:
            - '\node.exe'
            - '/node'
    condition: selection
falsepositives:
    - Developers using JSONKeeper as a legitimate JSON hosting service
    - Development environments where JSONKeeper is used for JSON mocking or prototyping
level: medium
```

<!-- revision: Added bare 'jsonkeeper.com' to QueryName endswith list. Added dev environment false positive caveat. -->
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0; yaml schema valid -->
**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** MEDIUM

---

#### 3. Outbound Connection to PolinRider C2 Server

Detects any outbound connection to the known PolinRider C2 IP 216.126.236.244.

```yaml
title: Outbound Connection to PolinRider C2 Server 216.126.236.244
id: b3c4d5e6-7f8a-9b0c-1d2e-3f4a5b6c7d8e
status: experimental
description: >
    Detects network connections to the known PolinRider C2 server at
    216.126.236.244, used for payload delivery, socket.io backdoor
    communication, and data exfiltration across multiple ports.
references:
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
    - https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html
author: Actioner
date: 2026-07-05
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '216.126.236.244'
        Initiated: 'true'
    condition: selection
falsepositives:
    - Legitimate traffic to this IP is unlikely in most environments
level: critical
```

<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0; yaml schema valid -->
**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** HIGH
**Coverage Note:** Windows network telemetry only. Linux/macOS coverage requires equivalent network connection logging rules.

---

<!-- revision: dropped -- Normal build behavior (PostCSS, Tailwind, Vite all write config files during compilation). The TTP operates at a higher altitude than file_change telemetry can distinguish without unacceptable false positives. -->

#### 5. DNS Query to PolinRider Vercel C2 Subdomains

Detects DNS resolution of known PolinRider Vercel-hosted C2 subdomains.

```yaml
title: DNS Query to PolinRider Vercel C2 Subdomains
id: d5e6f7a8-9b0c-1d2e-3f4a-5b6c7d8e9f0a
status: experimental
description: >
    Detects DNS queries to known PolinRider Vercel-hosted C2 subdomains used
    for payload staging and VS Code settings bootstrapping in the campaign.
references:
    - https://github.com/OpenSourceMalware/PolinRider
    - https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
author: Actioner
date: 2026-07-05
tags:
    - attack.t1583.006
    - attack.t1105
logsource:
    category: dns_query
detection:
    selection:
        QueryName:
            - '260120.vercel.app'
            - 'default-configuration.vercel.app'
            - 'vscode-settings-bootstrap.vercel.app'
            - 'vscode-settings-config.vercel.app'
            - 'vscode-bootstrapper.vercel.app'
            - 'vscode-load-config.vercel.app'
    condition: selection
falsepositives:
    - Legitimate use of these specific Vercel subdomains is extremely unlikely
level: critical
```

<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0; yaml schema valid -->
**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** HIGH

---

#### 6. PolinRider Staging File Creation in Temp Directory

Detects creation of known PolinRider staging artifacts (scdata, .npm/vhost.ctl).

```yaml
title: PolinRider Staging File Creation in Temp Directory
id: e6f7a8b9-0c1d-2e3f-4a5b-6c7d8e9f0a1b
status: experimental
description: >
    Detects creation of PolinRider staging artifacts in temporary
    directories: the remote access component (scdata) and the npm
    process marker (.npm/vhost.ctl).
references:
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
    - https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html
author: Actioner
date: 2026-07-05
tags:
    - attack.t1074.001
    - attack.t1059.007
logsource:
    category: file_event
    product: windows
detection:
    selection_scdata:
        TargetFilename|endswith:
            - '\scdata'
    selection_vhost:
        TargetFilename|contains:
            - '\.npm\vhost.ctl'
    condition: selection_scdata or selection_vhost
falsepositives:
    - Legitimate software creating files named scdata in temp directories
level: low
```

<!-- revision: Removed \pack and \ldata patterns (too generic, high false-positive risk). Switched \scdata to endswith. Kept \.npm\vhost.ctl with contains. Downgraded to LOW. -->
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0; yaml schema valid -->
**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** LOW
**Coverage Note:** Windows file event telemetry only. Linux/macOS coverage requires equivalent file monitoring rules.

---

### YARA Rules

#### 7. PolinRider JS Obfuscator Variants

Detects both the original (`rmcej%otb%`) and new (`Cot%3t=shtP`) shuffle-cipher JavaScript payload variants, plus campaign-specific XOR keys and AES salts.

```yara
rule PolinRider_JS_Obfuscator_Variants
{
    meta:
        description = "Detects PolinRider shuffle-cipher JavaScript payloads injected into developer config files. Covers both the original and new obfuscator variants."
        author = "Actioner"
        date = "2026-07-05"
        reference = "https://github.com/OpenSourceMalware/PolinRider"
        reference2 = "https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands"
        threat_actor = "Contagious Interview / Lazarus"
        severity = "critical"

    strings:
        $orig_marker = "rmcej%otb%" ascii
        $orig_decoder = "_$_1e42" ascii
        $orig_seed1 = "2857687" ascii
        $orig_seed2 = "2667686" ascii
        $orig_global = "global['!']" ascii
        $new_marker = "Cot%3t=shtP" ascii
        $new_decoder = "MDy" ascii
        $new_seed1 = "1111436" ascii
        $new_seed2 = "3896884" ascii
        $new_global = "global['_V']" ascii
        $eval_exec = "eval(" ascii
        $config_target1 = "postcss.config" ascii
        $config_target2 = "tailwind.config" ascii
        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "m6:tTh^D)cBz?NM]" ascii
        $aes_salt = "98cb54c0b4ac259d30c9c1ca1ae87c68" ascii

    condition:
        filesize < 5MB and
        (
            ($orig_marker and ($orig_decoder or $orig_seed1 or $orig_seed2 or $orig_global))
            or
            ($new_marker and ($new_decoder or $new_seed1 or $new_seed2 or $new_global))
            or
            (($orig_global or $new_global) and $eval_exec and ($config_target1 or $config_target2))
            or
            ($xor_key1 or $xor_key2 or $aes_salt)
        )
}
```

<!-- audit: yarac exit 0 -->
**Compile Status:** PASSED (yarac) | **Confidence:** HIGH

---

#### 8. PolinRider Rollup Polyfill Malware

Detects the Rollup polyfill npm packages by their function names, sandbox evasion patterns, and JSONKeeper payload retrieval.

```yara
rule PolinRider_Rollup_Polyfill_Malware
{
    meta:
        description = "Detects malicious npm packages masquerading as Rollup polyfill utilities. Identifies the obfuscated loader, sandbox evasion checks, and JSONKeeper payload retrieval pattern used by PolinRider Rollup packages."
        author = "Actioner"
        date = "2026-07-05"
        reference = "https://research.jfrog.com/post/rollup-polyfill-masquerading/"
        threat_actor = "Contagious Interview / Lazarus"
        severity = "critical"

    strings:
        $func1 = "ValidateSvgModule" ascii
        $func2 = "checkPlugin" ascii
        $func3 = "getPlugin" ascii
        $b64_pkg = "c3dpZnQtcGFyc2Utc3RyZWFt" ascii
        $env_codespace = "CODESPACE_NAME" ascii
        $env_codesandbox = "CODESANDBOX_HOST" ascii
        $env_vercel = "VERCEL" ascii
        $env_lambda = "AWS_LAMBDA_FUNCTION_NAME" ascii
        $env_gcloud = "GOOGLE_CLOUD_PROJECT" ascii
        $env_azure = "AZURE_FUNCTIONS_ENVIRONMENT" ascii
        $env_socket = "SOCKET_DEV" ascii
        $jsonkeeper = "jsonkeeper.com" ascii
        $wallet1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $wallet2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii
        $search1 = "*.env*" ascii
        $search2 = "*.pem" ascii
        $search3 = "*private key*" ascii
        $search4 = "*secret phrase*" ascii

    condition:
        filesize < 2MB and
        (
            ($b64_pkg and any of ($func*))
            or
            ($jsonkeeper and 3 of ($env_*))
            or
            (any of ($wallet*) and 2 of ($search*) and any of ($env_*))
        )
}
```

<!-- audit: yarac exit 0 -->
**Compile Status:** PASSED (yarac) | **Confidence:** HIGH

---

#### 9. PolinRider Weaponized VSCode Task File

Detects VS Code tasks.json files configured for auto-execution with indicators of malicious content.

```yara
rule PolinRider_VSCode_Task_Weaponized
{
    meta:
        description = "Detects weaponized .vscode/tasks.json files with runOn folderOpen auto-execution combined with indicators of malicious content such as woff2 font execution or obfuscated commands, as used in PolinRider/TaskJacker campaigns."
        author = "Actioner"
        date = "2026-07-05"
        reference = "https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands"
        threat_actor = "Contagious Interview / Lazarus"
        severity = "high"

    strings:
        $auto_run = "folderOpen" ascii
        $run_on = "runOn" ascii
        $task_label = "eslint-check" ascii
        $woff2_exec = ".woff2" ascii
        $node_cmd = "node" ascii

    condition:
        filesize < 50KB and
        $auto_run and $run_on and
        ($task_label or ($woff2_exec and $node_cmd))
}
```

<!-- revision: Removed $hide_task from OR condition -- "hide" is a standard VS Code tasks.json presentation value, too broad for detection. -->
<!-- audit: yarac exit 0 -->
**Compile Status:** PASSED (yarac) | **Confidence:** MEDIUM

---

### Snort/Suricata Rules

#### 10. PolinRider C2 Server Connection

```
alert tcp $HOME_NET any -> 216.126.236.244 any (msg:"POLINRIDER C2 Connection to 216.126.236.244"; flow:to_server,established; sid:2026070501; rev:1; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/;)
```

**Compile Status:** Uncompiled (structural check only) | **Confidence:** HIGH

---

#### 11. PolinRider C2 API Payload Retrieval

```
alert http $HOME_NET any -> any any (msg:"POLINRIDER C2 API Path /api/service/ Payload Retrieval"; flow:to_server,established; content:"/api/service/"; http_uri; content:"98cb54c0b4ac259d30c9c1ca1ae87c68"; http_uri; sid:2026070502; rev:1; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/;)
```

**Compile Status:** Uncompiled (structural check only) | **Confidence:** HIGH

---

#### 12. PolinRider C2 Beacon Makelog

```
alert http $HOME_NET any -> 216.126.236.244 any (msg:"POLINRIDER C2 Beacon /api/service/makelog"; flow:to_server,established; content:"/api/service/makelog"; http_uri; sid:2026070503; rev:2; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/;)
```

<!-- revision: Added 216.126.236.244 destination constraint to reduce false positives from generic /api/service/makelog paths. Bumped rev to 2. -->
**Compile Status:** Uncompiled (structural check only) | **Confidence:** MEDIUM

---

#### 13. PolinRider Socket.IO Backdoor Port 4801

```
alert tcp $HOME_NET any -> 216.126.236.244 4801 (msg:"POLINRIDER Socket.IO Backdoor Connection Port 4801"; flow:to_server,established; sid:2026070504; rev:1; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/;)
```

**Compile Status:** Uncompiled (structural check only) | **Confidence:** HIGH

---

#### 14. PolinRider JSONKeeper Payload Retrieval

```
alert http $HOME_NET any -> any any (msg:"POLINRIDER JSONKeeper Payload Retrieval"; flow:to_server,established; content:"jsonkeeper.com"; http_host; content:"/b/3P9BF"; http_uri; sid:2026070506; rev:1; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/;)
```

**Compile Status:** Uncompiled (structural check only) | **Confidence:** HIGH

---

#### 15. PolinRider Vercel C2 DNS Query

```
alert dns $HOME_NET any -> any any (msg:"POLINRIDER Vercel C2 Subdomain DNS Query"; content:"vscode-settings"; nocase; content:"vercel"; nocase; sid:2026070507; rev:1; classtype:trojan-activity; reference:url,github.com/OpenSourceMalware/PolinRider;)
```

**Compile Status:** Uncompiled (structural check only) | **Confidence:** MEDIUM

---

## Sources

- [The Hacker News - North Korean Hackers Publish 108 Malicious Packages and Extensions in PolinRider Campaign](https://thehackernews.com/2026/07/north-korean-hackers-publish-108.html)
- [The Hacker News - North Korea-Linked npm Packages Mimic Rollup Polyfills to Steal Developer Secrets](https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html)
- [Socket Security - PolinRider: North Korea-Linked Supply Chain Campaign Expands](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands)
- [JFrog Security Research - Lazarus-Linked npm Malware Masquerades as Rollup Polyfills](https://research.jfrog.com/post/rollup-polyfill-masquerading/)
- [Sonatype - Hijacked npm Package Attempts to Deliver PolinRider-Linked RAT](https://www.sonatype.com/blog/hijacked-npm-package-attempts-to-deliver-polinrider-linked-rat)
- [OpenSourceMalware/PolinRider - GitHub Technical Dossier](https://github.com/OpenSourceMalware/PolinRider)
- [MITRE ATT&CK - Contagious Interview G1052](https://attack.mitre.org/groups/G1052/)
- [CyberPress - North Korea-Linked PolinRider Campaign Hits 108 Open Source Packages](https://cyberpress.org/polinrider-supply-chain-attack/)
