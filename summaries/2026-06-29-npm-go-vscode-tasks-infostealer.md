# Hijacked npm and Go Packages Using VS Code Tasks to Deploy Python Infostealer

**Date:** 2026-06-29
**Status:** DRAFT
**Threat Actor:** Contagious Interview (G1052) / DPRK-attributed
**Campaign Variant:** Fake Font

---

## Executive Summary

Two hijacked npm packages (`html-to-gutenberg` v4.2.11 and `fetch-page-assets` v1.2.9) and 16 compromised Go packages were weaponized to deliver the InvisibleFerret Python infostealer across Windows, Linux, and macOS. The attack abuses VS Code's `tasks.json` auto-execution feature (`runOn: folderOpen`) to trigger a multi-stage payload chain that retrieves encrypted JavaScript from blockchain transaction data (TronGrid/Aptos/BSC), establishes a socket.io backdoor, and deploys a comprehensive credential-stealing Python payload. The npm packages were uploaded on May 25, 2026 and have been removed from the registry. This campaign is attributed to North Korea's Contagious Interview group (MITRE ATT&CK G1052), which has been active since 2023 targeting software developers through supply chain compromise and fake job interviews.

---

## Technical Analysis

### Attack Chain

1. **Initial Access**: Developer installs compromised npm/Go package containing a hidden `.vscode/tasks.json` with `runOn: folderOpen` auto-execution configured
2. **Execution Trigger**: When the package directory is opened in VS Code and trusted, the hidden task labeled `eslint-check` auto-executes
3. **Payload Disguise**: The task runs Node.js against `public/fonts/fa-solid-400.woff2`, a JavaScript payload masquerading as a font file
4. **Blockchain Dead-Drop**: Stage 1 retrieves XOR-encrypted payloads from blockchain transaction data via TronGrid, Aptos, and BSC RPC endpoints
5. **Decryption & Execution**: Payloads are XOR-decoded (keys: `2[gWfGj;<:-93Z^C` and `ThZG+0jfXE6VAGOJ`) and executed via `eval()`
6. **C2 Selection**: Stage 2 uses a victim marker (`_V = "A8-**"`) sent via `Sec-V` HTTP header to select C2 infrastructure
7. **Socket.io Backdoor**: Stage 3 establishes a persistent socket.io-based backdoor with capabilities for shell execution, clipboard harvesting, file operations, and arbitrary JavaScript execution
8. **Python Bootstrap**: Stage 4 downloads and installs Python runtime and pip from C2 endpoints (`/d/python.zip`, `/d/python.7z`, `/d/7zr.exe`)
9. **InvisibleFerret Deployment**: Stage 5 deploys the Python infostealer that harvests credentials, wallets, and developer artifacts

### VS Code Task Configuration

The malicious `tasks.json` structure:

```json
{
  "label": "eslint-check",
  "type": "shell",
  "command": "(command -v node >/dev/null 2>&1 && node ./public/fonts/fa-solid-400.woff2) || ...",
  "hide": true,
  "runOn": "folderOpen"
}
```

### InvisibleFerret Capabilities

- **Browser Credentials**: Chrome, Chromium, Opera, Brave, Edge, Arc, Firefox (Login Data, Cookies, logins.json)
- **Cryptocurrency Wallets**: MetaMask, Phantom, TronLink, Trust Wallet, Binance, Coinbase, OKX, Rabby, Exodus, Atomic, Electrum
- **OS Credential Stores**: Windows Credential Manager, Linux Secret Service, KDE Wallet, macOS Keychain
- **Developer Artifacts**: Git credentials, GitHub CLI hosts.yml, GitHub Desktop logs, VS Code globalStorage
- **Cloud Storage Metadata**: Dropbox, Google Drive, OneDrive, iCloud, Box, Mega, pCloud
- **Exfiltration**: ZIP archive creation, HTTP POST to C2 `/u/f` endpoint, Telegram bot API (token prefix: `7870147428:AAGbYG...`, chat ID: `7699029999`)

---

## Indicators of Compromise

### Compromised Packages

| Package | Version | Ecosystem | JFrog ID |
|---|---|---|---|
| html-to-gutenberg | 4.2.11 | npm | XRAY-1008590 |
| fetch-page-assets | 1.2.9 | npm | XRAY-1008535 |
| github[.]com/lambda-platform/lambda | - | Go | - |
| github[.]com/reauheau/goaubio | - | Go | - |
| github[.]com/glacialspring/go-winsparkle | - | Go | - |
| github[.]com/bm-197/chill | - | Go | - |
| github[.]com/naol7/dist-task-scheduler | - | Go | - |
| github[.]com/anatoli-derese/a2sv-excercise | - | Go | - |
| github[.]com/amantsehay/a2sv-go-course | - | Go | - |
| github[.]com/dexbotsdev/uniswap-v2-v3-arbitrage | - | Go | - |
| github[.]com/lambda-platform/ebarimt-rest-api | - | Go | - |
| github[.]com/lambda-platform/dan | - | Go | - |
| github[.]com/zainirfan13/graphql-client | - | Go | - |
| github[.]com/hngi/team-fierce-backend-golang | - | Go | - |
| github[.]com/glacialspring/static | - | Go | - |
| github[.]com/rickt/slack-weather-bot | - | Go | - |
| github[.]com/Barsu5489/commerce | - | Go | - |
| github[.]com/Setsu548/Logistic | - | Go | - |

### Network Indicators

| Type | Indicator (Defanged) | Context |
|---|---|---|
| IP | 166[.]88[.]134[.]62 | C2 server |
| IP | 198[.]105[.]127[.]210 | C2 server |
| IP | 23[.]27[.]202[.]27 | C2 server (also port 27017) |
| IP | 146[.]70[.]41[.]188 | C2 server (port 1224, M247 New York) |

### C2 URI Paths

| Path | Purpose |
|---|---|
| `/$/boot` | Bootstrap / initial check-in |
| `/$/{id}` | Payload delivery |
| `/verify-human/{channel}` | Victim verification callback |
| `/snv` | Environment data upload |
| `/u/e` | Data exfiltration |
| `/u/f` | File exfiltration |
| `/d/python.zip` | Python runtime download |
| `/d/python.7z` | Python runtime download (compressed) |
| `/d/7zr.exe` | 7-Zip extractor download |

### Blockchain Dead-Drop Addresses

| Blockchain | Address (Defanged) |
|---|---|
| Tron | TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP |
| Tron | TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG |
| Tron | TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v |
| Aptos | 0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e |
| Aptos | 0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3 |
| Aptos | 0x533b2dbcaeff19cd1f799234a27b578d713d8fcaa341b7501e4526106483e0b1 |

### Legitimate Services Abused

| Domain (Defanged) | Purpose |
|---|---|
| api[.]trongrid[.]io | Blockchain dead-drop resolver |
| fullnode[.]mainnet[.]aptoslabs[.]com | Blockchain dead-drop resolver (fallback) |
| bsc-dataseed[.]binance[.]org | Blockchain dead-drop resolver (fallback) |
| bsc-rpc[.]publicnode[.]com | Blockchain dead-drop resolver (fallback) |
| bootstrap[.]pypa[.]io/get-pip.py | Python pip bootstrap |

### File Artifacts

| Path | Description |
|---|---|
| `.vscode/tasks.json` | Malicious auto-run task configuration |
| `public/fonts/fa-solid-400.woff2` | JavaScript payload disguised as font |
| `public/fonts/fa-brands-regular.woff2` | JavaScript payload (variant) |
| `~/.node_modules/` | User-level Node modules staging |
| `%LOCALAPPDATA%\Programs\Python\Python3127\` | Python runtime (Windows) |
| `%USERPROFILE%\.npm\` | Data staging directory (Windows) |
| `/tmp/.npm` | Data staging directory (Linux/macOS) |
| `/tmp/get-pip.py` | Pip bootstrap script (Linux/macOS) |
| `~/.n2/` | Hidden malware directory |

### File Hashes

| Hash (SHA256) | Description |
|---|---|
| 87e7f4ac95f090f9965175935955fdc02bee4b1bf417855bc65ff4bde9f271e5 | BeaverTail loader variant |
| 54a5c5cb16bdd482bd4147200557d3a94e413f9e9aebbf4818e76f16331bc6dc | BeaverTail loader variant |
| 869bce2efa60b60dab1e0fe8c9d94cfbd6476f4393f79564c4de26ec689dc64d | BeaverTail loader variant |
| ebfaff5c2e9b709c1337e06a756f7ee69fc29d319a27adaafe73eb84d8a43b61 | BeaverTail loader variant |
| ef12b15466255fafda6225a557cce780baa6b1c98adcf111f5564e7b3ecc0e14 | InvisibleFerret Python infostealer |

### HTTP Indicators

| Header/Value | Context |
|---|---|
| `Sec-V: A8-**` | Victim marker header used for C2 selection |

### Exfiltration Channels

| Channel | Detail |
|---|---|
| Telegram Bot | Token prefix: `7870147428:AAGbYG...` |
| Telegram Chat | ID: `7699029999` |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Campaign Usage |
|---|---|---|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Hijacking legitimate npm and Go packages to deliver malware |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Node.js execution of disguised JavaScript payload (fa-solid-400.woff2) |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | curl/wget piped to shell interpreter via VS Code tasks |
| T1059.006 | Command and Scripting Interpreter: Python | InvisibleFerret Python infostealer execution |
| T1036.008 | Masquerading: Masquerade File Type | JavaScript code disguised as .woff2 font file |
| T1105 | Ingress Tool Transfer | Downloading Python runtime and infostealer from C2 |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 communication with specific URI patterns |
| T1041 | Exfiltration Over C2 Channel | Data exfiltration via HTTP POST to /u/f and /u/e endpoints |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltration via Telegram bot API |
| T1074.001 | Data Staged: Local Data Staging | Staging stolen data in .npm directories and ZIP archives |
| T1005 | Data from Local System | Harvesting credentials from browsers, wallets, and OS credential stores |
| T1102.001 | Web Service: Dead Drop Resolver | Using blockchain transactions (TronGrid/Aptos/BSC) to retrieve encrypted C2 payloads |
| T1204.002 | User Execution: Malicious File | Victim must open project in VS Code and accept trust prompt |

---

## Detection Rules

### Sigma Rules

#### 1. VSCode Task Auto-Execution via folderOpen - Suspicious Child Process

```yaml
title: VSCode Task Auto-Execution via folderOpen - Suspicious Child Process
id: 8a3c1f7e-2b4d-4e9a-bf6c-5d8e0f1a2c3b
status: experimental
description: >
    Detects VS Code spawning suspicious child processes via the tasks.json
    folderOpen auto-run mechanism. The Contagious Interview campaign abuses
    this to execute shell commands that retrieve and run malicious JavaScript
    disguised as font files, deploying InvisibleFerret infostealer.
references:
    - https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/
    - https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html
author: Actioner
date: 2026-06-29
tags:
    - attack.t1059.007
    - attack.t1195.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\Code.exe'
            - '\Code - Insiders.exe'
    selection_child:
        Image|endswith:
            - '\node.exe'
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_cmdline:
        CommandLine|contains:
            - 'fa-solid-400.woff2'
            - 'fa-brands-regular.woff2'
            - '.woff2'
            - 'eslint-check'
    condition: selection_parent and selection_child and selection_cmdline
falsepositives:
    - Legitimate VS Code tasks that reference font files in command lines
level: high
```

**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** HIGH

---

#### 2. Node.js Execution of Disguised Font File - Fake Font Campaign

```yaml
title: Node.js Execution of Disguised Font File - Fake Font Campaign
id: 9b4d2e8f-3c5e-4f0b-a07d-6e9f1a2b3d4c
status: experimental
description: >
    Detects Node.js executing a file with a .woff2 extension, characteristic of
    the Contagious Interview Fake Font variant where malicious JavaScript is
    disguised as public/fonts/fa-solid-400.woff2 or similar font files. This is
    the initial execution vector triggered by malicious VS Code tasks.
references:
    - https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/
    - https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html
author: Actioner
date: 2026-06-29
tags:
    - attack.t1059.007
    - attack.t1036.008
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'node'
            - '.woff2'
    condition: selection
falsepositives:
    - Legitimate build tools that process font files through Node.js are unlikely to execute them directly
level: critical
```

**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** HIGH

---

#### 3. Suspicious VSCode tasks.json File Creation in Package Directory

```yaml
title: Suspicious VSCode tasks.json File Creation in Package Directory
id: a1c5e3f9-4d6a-5b1c-b28e-7f0a2b3c4d5e
status: experimental
description: >
    Detects creation of .vscode/tasks.json files within npm package or Go module
    directories. The Contagious Interview campaign plants malicious tasks.json
    files with runOn folderOpen configuration inside hijacked packages to achieve
    automatic code execution when developers open the project in VS Code.
references:
    - https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/
    - https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html
author: Actioner
date: 2026-06-29
tags:
    - attack.t1195.001
    - attack.t1059.007
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains: '.vscode'
        TargetFilename|endswith: '\tasks.json'
    filter_vscode:
        Image|endswith:
            - '\Code.exe'
            - '\Code - Insiders.exe'
    condition: selection and not filter_vscode
falsepositives:
    - Developers manually creating VS Code task configurations
    - IDE plugins that generate tasks.json files
level: medium
```

**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** MEDIUM

---

#### 4. InvisibleFerret Python Infostealer Staging Activity

```yaml
title: InvisibleFerret Python Infostealer Staging Activity
id: b2d6f4a0-5e7b-6c2d-c39f-8a1b3c4d5e6f
status: experimental
description: >
    Detects file creation in staging directories used by the InvisibleFerret
    Python infostealer deployed through the Contagious Interview campaign.
    The malware stages stolen data in .npm directories and downloads Python
    runtime to specific paths before exfiltrating credentials.
references:
    - https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/
    - https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html
author: Actioner
date: 2026-06-29
tags:
    - attack.t1074.001
    - attack.t1005
logsource:
    category: file_event
    product: windows
detection:
    selection_staging:
        TargetFilename|contains:
            - '\AppData\Local\Programs\Python\Python3127\'
            - '\.npm\'
    selection_process:
        Image|endswith:
            - '\python.exe'
            - '\python3.exe'
            - '\node.exe'
    condition: selection_staging and selection_process
falsepositives:
    - Legitimate Python installations via official installer
    - Normal npm cache operations
level: medium
```

**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** MEDIUM

---

#### 5. Contagious Interview C2 Network Connection to Known Infrastructure

```yaml
title: Contagious Interview C2 Network Connection to Known Infrastructure
id: c3e7a5b1-6f8c-7d3e-d40a-9b2c4d5e6f70
status: experimental
description: >
    Detects network connections to known C2 IP addresses associated with the
    Contagious Interview campaign that delivers InvisibleFerret infostealer
    through hijacked npm and Go packages. These IPs serve as command-and-control
    for the socket.io backdoor and data exfiltration endpoints.
references:
    - https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/
    - https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html
author: Actioner
date: 2026-06-29
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '166.88.134.62'
            - '198.105.127.210'
            - '23.27.202.27'
    condition: selection
falsepositives:
    - Unlikely; these IPs are associated with confirmed malicious infrastructure
level: critical
```

**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** HIGH

---

#### 6. VSCode Task Spawning Curl or Wget Piped to Shell Interpreter

```yaml
title: VSCode Task Spawning Curl or Wget Piped to Shell Interpreter
id: d4f8b6c2-7a9d-8e4f-e51b-0c3d5e6f7a81
status: experimental
description: >
    Detects VS Code spawning curl or wget commands that pipe output to a shell
    interpreter. This pattern is used by the Contagious Interview campaign where
    malicious VS Code tasks download and execute remote payloads through shell
    piping on macOS and Linux systems.
references:
    - https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/
    - https://opensourcemalware.com/blog/contagious-interview-vscode
author: Actioner
date: 2026-06-29
tags:
    - attack.t1059.004
    - attack.t1105
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '/code'
            - '/code-insiders'
            - '\Code.exe'
            - '\Code - Insiders.exe'
    selection_cmdline_download:
        CommandLine|contains:
            - 'curl '
            - 'wget '
    selection_cmdline_pipe:
        CommandLine|contains:
            - '| sh'
            - '| bash'
            - '| cmd'
            - '|sh'
            - '|bash'
            - '|cmd'
    condition: selection_parent and selection_cmdline_download and selection_cmdline_pipe
falsepositives:
    - Developers using VS Code tasks to run legitimate deployment scripts that pipe from curl
level: high
```

**Compile Status:** PASSED (Splunk + LogScale) | **Confidence:** HIGH

---

### YARA Rules

#### 7. Malicious VS Code tasks.json with folderOpen Auto-Execution

```yara
rule Malware_ContagiousInterview_VSCode_Tasks_FolderOpen
{
    meta:
        description = "Detects malicious VS Code tasks.json with folderOpen auto-execution used by Contagious Interview campaign to deploy InvisibleFerret"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $tasks_ver = "\"version\"" ascii
        $run_on = "folderOpen" ascii
        $run_opts = "runOptions" ascii

        $cmd_woff2 = ".woff2" ascii
        $cmd_curl_sh = "| sh" ascii
        $cmd_wget = "wget" ascii
        $cmd_curl = "curl" ascii
        $cmd_node = "node " ascii

        $label_eslint = "eslint-check" ascii
        $label_env = "\"label\": \"env\"" ascii nocase

        $font_fa_solid = "fa-solid-400.woff2" ascii
        $font_fa_brands = "fa-brands-regular.woff2" ascii

    condition:
        filesize < 10KB and
        $tasks_ver and $run_on and $run_opts and
        (
            ($cmd_woff2 and ($cmd_node or $cmd_curl)) or
            ($cmd_curl_sh or ($cmd_wget and $cmd_curl)) or
            $label_eslint or
            $label_env or
            1 of ($font_fa*)
        )
}
```

**Compile Status:** PASSED (yarac) | **Confidence:** HIGH

---

#### 8. InvisibleFerret Python Infostealer

```yara
rule Malware_InvisibleFerret_Python_Infostealer
{
    meta:
        description = "Detects the InvisibleFerret Python infostealer deployed by Contagious Interview campaign via hijacked npm/Go packages"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/"
        hash = "ef12b15466255fafda6225a557cce780baa6b1c98adcf111f5564e7b3ecc0e14"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $s_chrome_login = "Login Data" ascii wide
        $s_chrome_cookies = "Cookies" ascii wide
        $s_firefox_logins = "logins.json" ascii wide
        $s_keychain = "security find-generic-password" ascii
        $s_credential_mgr = "Windows Credential Manager" ascii wide
        $s_secret_service = "Secret Service" ascii
        $s_kde_wallet = "KDE Wallet" ascii

        $wallet_metamask = "MetaMask" ascii wide
        $wallet_phantom = "Phantom" ascii wide
        $wallet_tronlink = "TronLink" ascii wide
        $wallet_exodus = "Exodus" ascii wide

        $dev_git_cred = ".git-credentials" ascii
        $dev_gh_hosts = "hosts.yml" ascii
        $dev_gh_desktop = "GitHub Desktop" ascii wide
        $dev_vscode = "globalStorage" ascii

        $cloud_dropbox = "Dropbox" ascii wide
        $cloud_gdrive = "Google Drive" ascii wide
        $cloud_onedrive = "OneDrive" ascii wide
        $cloud_icloud = "iCloud" ascii wide

        $exfil_telegram = "api.telegram.org" ascii
        $exfil_zip = "zipfile" ascii
        $exfil_upload = "/u/f" ascii
        $exfil_env = "/snv" ascii

    condition:
        filesize < 5MB and
        (
            (3 of ($s_*) and 2 of ($wallet_*) and 1 of ($dev_*)) or
            (2 of ($s_*) and 1 of ($cloud_*) and $exfil_telegram) or
            (4 of ($s_*) and ($exfil_upload or $exfil_env)) or
            ($exfil_zip and $exfil_telegram and 2 of ($s_*))
        )
}
```

**Compile Status:** PASSED (yarac) | **Confidence:** MEDIUM

---

#### 9. Fake Font JavaScript Payload with Blockchain Dead-Drop

```yara
rule Malware_ContagiousInterview_FakeFont_JS_Payload
{
    meta:
        description = "Detects JavaScript payload disguised as font file (.woff2) used by Contagious Interview Fake Font variant to bootstrap blockchain dead-drop resolver"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $trongrid = "api.trongrid.io" ascii
        $aptos = "aptoslabs.com" ascii
        $bsc_data = "bsc-dataseed.binance.org" ascii
        $bsc_rpc = "bsc-rpc.publicnode.com" ascii

        $tron_addr1 = "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP" ascii
        $tron_addr2 = "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG" ascii
        $tron_addr3 = "TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v" ascii

        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "ThZG+0jfXE6VAGOJ" ascii

        $eval_call = "eval(" ascii
        $socket_io = "socket.io" ascii
        $sec_v = "Sec-V" ascii

    condition:
        filesize < 1MB and
        (
            (1 of ($trongrid, $aptos, $bsc_data, $bsc_rpc) and 1 of ($tron_addr*)) or
            (1 of ($xor_key*) and $eval_call) or
            (1 of ($trongrid, $aptos) and $socket_io) or
            (1 of ($tron_addr*) and $sec_v)
        )
}
```

**Compile Status:** PASSED (yarac) | **Confidence:** HIGH

---

### Snort Rules

#### 10-14. Contagious Interview C2 Communication (Snort 2)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Contagious Interview C2 Bootstrap Request to /$/boot"; flow:established,to_server; content:"/$/boot"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created 2026-06-29, attack_id T1071.001; sid:2100101; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Contagious Interview C2 Data Exfiltration to /u/f"; flow:established,to_server; content:"POST"; http_method; content:"/u/f"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created 2026-06-29, attack_id T1041; sid:2100102; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Contagious Interview C2 Environment Upload to /snv"; flow:established,to_server; content:"POST"; http_method; content:"/snv"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created 2026-06-29, attack_id T1041; sid:2100103; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Contagious Interview C2 Python Tooling Download"; flow:established,to_server; content:"/d/python"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created 2026-06-29, attack_id T1105; sid:2100104; rev:1;)

alert tcp $HOME_NET any -> [166.88.134.62,198.105.127.210,23.27.202.27] $HTTP_PORTS (msg:"Actioner - Contagious Interview Known C2 IP with Sec-V Header"; flow:established,to_server; content:"Sec-V"; http_header; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created 2026-06-29, attack_id T1071.001; sid:2100105; rev:1;)
```

**Compile Status:** PASSED (Snort 2.9.20) | **Confidence:** HIGH

---

### Suricata Rules

#### 15-20. Contagious Interview C2 Communication (Suricata 7.x)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Contagious Interview C2 Bootstrap Request to /$/boot"; flow:established,to_server; http.uri; content:"/$/boot"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created_at 2026-06-29, attack_id T1071.001; sid:2100201; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Contagious Interview C2 Data Exfiltration via /u/f"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/u/f"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created_at 2026-06-29, attack_id T1041; sid:2100202; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Contagious Interview C2 Environment Upload via /snv"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/snv"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created_at 2026-06-29, attack_id T1041; sid:2100203; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Contagious Interview C2 Python Runtime Download"; flow:established,to_server; http.uri; content:"/d/python"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created_at 2026-06-29, attack_id T1105; sid:2100204; rev:1;)

alert http $HOME_NET any -> [166.88.134.62,198.105.127.210,23.27.202.27] any (msg:"Actioner - Contagious Interview Known C2 IP with Sec-V Header"; flow:established,to_server; http.header; content:"Sec-V"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created_at 2026-06-29, attack_id T1071.001; sid:2100205; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Contagious Interview Verify Human Channel Callback"; flow:established,to_server; http.uri; content:"/verify-human/"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/; metadata:author Actioner, created_at 2026-06-29, attack_id T1071.001; sid:2100206; rev:1;)
```

**Compile Status:** PASSED (Suricata 7.0.3) | **Confidence:** HIGH

---

## Recommendations

1. **Immediate**: Audit all developer machines for the listed compromised npm and Go packages; remove immediately if found
2. **Immediate**: Search for `.vscode/tasks.json` files containing `folderOpen` in `runOn` configuration across all repositories and developer workstations
3. **Credential Rotation**: Rotate all browser-stored credentials, Git tokens, GitHub CLI tokens, cloud API keys, and cryptocurrency wallet keys on any machine where compromised packages were installed
4. **VS Code Hardening**: Configure VS Code to prompt before executing automatic tasks (`task.allowAutomaticTasks: "off"` in settings)
5. **Supply Chain Controls**: Implement package pinning, lockfile integrity checks, and automated scanning for known malicious packages via JFrog Xray or similar SCA tooling
6. **Network Monitoring**: Deploy the provided Snort/Suricata rules to detect C2 communication patterns and known infrastructure

---

## Sources

- [JFrog Security Research - Hijacked npm Packages Use Novel VSCode Autorun and Blockchain Dead Drops](https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/)
- [The Hacker News - Hijacked npm and Go Packages Use VS Code Tasks to Deploy Python Infostealer](https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html)
- [OpenSourceMalware - Latest Contagious Interview malware campaign abuses Microsoft VSCode Tasks](https://opensourcemalware.com/blog/contagious-interview-vscode)
- [Abstract Security - Contagious Interview: Tracking the VS Code Tasks Infection Vector](https://www.abstract.security/blog/contagious-interview-tracking-the-vs-code-tasks-infection-vector)
- [MITRE ATT&CK - Contagious Interview Group G1052](https://attack.mitre.org/groups/G1052/)
