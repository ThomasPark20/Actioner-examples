# Mastra npm Supply Chain Attack ("easy-day-js")

**Date:** 2026-06-17
**TLP:** CLEAR
**Status:** DRAFT
**Sector:** Software Development / AI / Open Source

---

## Executive Summary

On June 17, 2026, attackers compromised 144 npm packages within the `@mastra` namespace -- a popular open-source JavaScript/TypeScript AI framework with over 1.1 million combined weekly downloads. The attack was executed by hijacking the dormant npm account `ehindero`, a former Mastra contributor whose scope access was never revoked. The attacker injected a typosquatted dependency called `easy-day-js` (mimicking the legitimate `dayjs` library) into all compromised packages. This dependency contained an obfuscated postinstall dropper that downloads and executes a cross-platform cryptocurrency-stealing Remote Access Trojan (RAT). Security firm Socket detected the malicious `easy-day-js` package within 6 minutes of publication.

---

## Background

[Mastra](https://mastra.ai) is an open-source TypeScript framework for building AI applications, agents, and workflows. Its core package `@mastra/core` alone receives over 918,000 weekly downloads. The framework is widely used across the JavaScript AI ecosystem.

The attack follows a pattern similar to the [Axios npm compromise attributed to Sapphire Sleet (BlueNoroff)](https://socradar.io/blog/axios-npm-supply-chain-attack-2026-ciso-guide/) earlier in 2026, though attribution for this incident remains unconfirmed.

---

## Attack Timeline

| Timestamp (UTC) | Event |
|---|---|
| 2026-06-16 07:05 | npm user `sergey2016` publishes `easy-day-js@1.11.21` -- a clean, functional clone of the legitimate `dayjs` library with no malicious code |
| 2026-06-17 01:01 | Malicious version `easy-day-js@1.11.22` published with obfuscated postinstall dropper |
| 2026-06-17 01:12 | Compromised `ehindero` account begins mass-republishing @mastra packages with `easy-day-js` dependency injected |
| 2026-06-17 02:36 | Final malicious package published (88-minute automated publishing window, 141+ packages) |
| 2026-06-17 ~01:07 | Socket flags `easy-day-js` within approximately 6 minutes of malicious version publication |
| 2026-06-17 | npm removes compromised packages; Mastra team begins remediation |

---

## Root Cause

The attack exploited two compounding security gaps:

1. **Dormant Contributor Account Takeover:** The npm account `ehindero` (a legitimate former contributor inactive for 16 months) retained full publish access to the @mastra scope. The account was taken over by the attacker (email changed from legitimate `ehindero[at]hotmail[.]com` to attacker-controlled `ehindeero[at]hotmail[.]com`).

2. **Missing Provenance Enforcement:** Mastra generated SLSA provenance attestations on CI publishes but did **not** require them. A standard npm token could publish without attestations, meaning `npm audit signatures` or signature-verifying install policies would have rejected every package in this wave.

---

## Technical Analysis

### Attack Chain

```
1. Account Takeover (ehindero) --> 2. Dependency Injection (easy-day-js ^1.11.21) -->
3. Caret Range Resolution (1.11.22) --> 4. Postinstall Hook (setup.cjs) -->
5. TLS Bypass --> 6. Stage-2 Download --> 7. RAT Execution -->
8. Persistence + Credential Theft + C2 Beacon
```

### Stage 1: Dropper (`setup.cjs`, 4,572 bytes)

The `easy-day-js@1.11.22` package includes a `postinstall` hook:

```json
"postinstall": "node setup.cjs --no-warnings"
```

The dropper performs the following actions:
- Disables TLS certificate verification: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`
- Downloads stage-2 payload from `https://23.254.164[.]92:8000/update/49890878`
- Writes installation beacon to `<tmpdir>/.pkg_history` (absolute install path) and `<tmpdir>/.pkg_logs` (XOR-encoded package name)
- Saves payload to randomly named temp file (`<tmpdir>/<24-hex-chars>.js`)
- Spawns detached background process with `stdio: 'ignore'` and `windowsHide: true`
- Self-deletes via `fs.rmSync(__filename, { force: true })`

**Obfuscation techniques:**
- Custom-alphabet Base64 (shuffled lowercase, uppercase, digits)
- 40-element string array rotated 34 positions with arithmetic integrity check (sum equals `0x4c11d` / 311,581)
- XOR-encoded strings (package name encoded as `[0xe5, 0xe1, 0xf3, 0xf9, 0xad, 0xe4, 0xe1, 0xf9, 0xad, 0xea, 0xf3]`)

### Stage 2: RAT Payload (41 KB obfuscated)

**SHA256:** `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`

The second-stage payload is a full-featured cross-platform RAT:

**Information Theft:**
- Browser history harvesting (Chrome, Brave, Edge profiles)
- Cryptocurrency wallet extension extraction (166 hardcoded targets: MetaMask, Phantom, Solflare, Coinbase, OKX, Keplr, and others)
- Environment variable harvesting and exfiltration
- LLM API key theft (OpenAI, Anthropic, Google credentials)
- Cloud provider credential extraction (AWS, Azure tokens)
- Database connection string and CI/CD secret harvesting
- VCS token theft (GitHub tokens, npm tokens)
- System profiling: username, hostname, OS/arch, Node version, installed apps, running processes

**C2 Beacon Protocol:**
- HTTPS POST to `23.254.164[.]123:443/49890878`
- Initial beacon JSON structure: `{"type":"prepare","targetId":"<uid>","info":{"common":{...},"appInfo":[],"extInfo":[]}}`
- Beacon interval: 10 minutes (configurable)
- Command tag: `tpcsr`, Response tag: `r0`
- Fallback C2 via XOR-ing primary IP with counter
- TLS certificate: `CN=www.wolfssl.com` (expired January 2018)
- Secondary User-Agent for payload fetch: `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`

**Cross-Platform Persistence:**

| Platform | Persistence Location | Disguise |
|---|---|---|
| macOS | `~/Library/LaunchAgents/com.nvm.protocal.plist` | Node Version Manager |
| macOS | `~/Library/NodePackages/protocal.cjs` | Payload location |
| Linux | `~/.config/systemd/user/nvmconf.service` | NVM config service |
| Linux | `~/.config/NodePackages/` | Payload directory |
| Windows | `C:\ProgramData\NodePackages\` | PowerShell `-ExecutionPolicy Bypass` |

A `config.json` file is written alongside the payload storing the victim ID, C2 address, and beacon interval.

---

## Indicators of Compromise

### Network IOCs

| Indicator | Type | Context |
|---|---|---|
| `23[.]254[.]164[.]92` | IPv4 | Stage-2 payload dropper server (Port 8000) |
| `23[.]254[.]164[.]123` | IPv4 | RAT C2 server (Port 443) |
| `hxxps://23[.]254[.]164[.]92:8000/update/49890878` | URL | Stage-2 payload download URL |
| `hwsrv-1327786` | Hostname | Hostwinds server hosting dropper |
| `hwsrv-1327785[.]hostwindsdns[.]com` | Hostname | Hostwinds server hosting RAT C2 |

### File Hashes

| Hash (SHA256) | Description |
|---|---|
| `4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417` | `easy-day-js@1.11.22` tarball |
| `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf` | Stage-2 RAT payload |

### Host Artifacts

| Artifact | Location | Description |
|---|---|---|
| `.pkg_history` | `<tmpdir>/` | Installation path beacon |
| `.pkg_logs` | `<tmpdir>/` | XOR-encoded package name marker |
| `<24-hex-chars>.js` | `<tmpdir>/` | Stage-2 payload (pre-execution) |
| `com.nvm.protocal.plist` | `~/Library/LaunchAgents/` | macOS persistence (note misspelling of "protocol") |
| `protocal.cjs` | `~/Library/NodePackages/` | macOS payload |
| `nvmconf.service` | `~/.config/systemd/user/` | Linux persistence |
| `config.json` | `NodePackages/` | Victim config (ID, C2, interval) |

### Compromised Packages (Key Examples)

| Package | Malicious Version |
|---|---|
| `@mastra/core` | 1.42.1 |
| `mastra` | 1.13.1 |
| `create-mastra` | 1.13.1 |
| `@mastra/memory` | 1.20.4 |
| `@mastra/server` | 2.1.1 |
| `@mastra/pg` | 1.13.1 |
| `@mastra/mcp` | 1.10.1 |
| `@mastra/libsql` | 1.13.1 |
| `@mastra/rag` | 2.2.2 |
| `@mastra/schema-compat` | 1.2.12 |
| `@mastra/auth` | 1.0.3 |
| `@mastra/agent-browser` | 0.3.2 |
| `easy-day-js` | 1.11.22 |

### Attacker Accounts

| Account | Email | Role |
|---|---|---|
| `ehindero` | `ehindeero[at]hotmail[.]com` (attacker) | Hijacked Mastra contributor |
| `sergey2016` | `sergey2016[at]tutamail[.]com` | Published easy-day-js |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|---|---|---|---|
| Initial Access | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | T1195.002 | Malicious dependency injected into @mastra packages via hijacked account |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | Postinstall hook executes obfuscated Node.js dropper |
| Persistence | Create or Modify System Process: Launch Agent (macOS) | T1543.001 | LaunchAgent plist disguised as NVM |
| Persistence | Create or Modify System Process: Systemd Service (Linux) | T1543.002 | Systemd user service disguised as NVM config |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | Dropper self-deletes after execution |
| Defense Evasion | Subvert Trust Controls: Install Root Certificate | T1553.004 | TLS certificate validation disabled |
| Defense Evasion | Obfuscated Files or Information | T1027 | Custom Base64, array rotation, XOR encoding |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 | Harvesting API keys, cloud creds, tokens from env/files |
| Collection | Data from Local System | T1005 | Browser history, wallet extensions, system profiling |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS POST beacons to C2 on port 443 |
| Command and Control | Ingress Tool Transfer | T1105 | Stage-2 payload downloaded from remote server |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Stolen data exfiltrated via C2 beacon |

---

## Impact

- **144 packages** in the `@mastra/*` namespace compromised
- **1.1 million+ weekly downloads** exposed to the malicious payload
- **Credential theft scope:** npm tokens, GitHub tokens, AWS/Azure/GCP credentials, LLM API keys (OpenAI, Anthropic, Google), database connection strings, CI/CD secrets
- **Cryptocurrency theft risk:** 166 browser wallet extensions targeted
- **Cross-platform persistence:** macOS, Linux, and Windows systems affected
- **AI/ML ecosystem impact:** Mastra is specifically used for building AI applications, meaning compromised environments likely contain high-value API keys and model access credentials

---

## Detection & Remediation

### Immediate Remediation Steps

1. **Check for compromised packages:** Run `npm ls easy-day-js` in all projects; any result indicates compromise
2. **Remove affected versions:** Delete `node_modules/`, clear npm cache, reinstall from known-good prior versions
3. **Check for persistence:** Search for `com.nvm.protocal.plist`, `nvmconf.service`, and `NodePackages` directories
4. **Rotate ALL credentials:** npm tokens, GitHub tokens, cloud provider keys (AWS, Azure, GCP), LLM API keys, database credentials, SSH keys, CI/CD secrets
5. **Audit npm provenance:** Run `npm audit signatures` and consider requiring SLSA provenance attestations
6. **Scan for IOCs:** Check for outbound connections to `23[.]254[.]164[.]92` and `23[.]254[.]164[.]123`
7. **Review temp directories:** Check for `.pkg_history`, `.pkg_logs`, and randomly-named `.js` files

### Preventive Measures

- Enforce npm provenance attestation requirements for all package publishes
- Audit and revoke scope access for inactive contributors
- Implement network egress monitoring for CI/CD and development environments
- Use tools like Socket, StepSecurity Harden Runner, or SafeDep for real-time supply chain monitoring
- Pin dependency versions instead of using caret (`^`) ranges for critical dependencies

---

## Detection Rules

### Sigma Rule 1: easy-day-js Postinstall Dropper Execution

Detects Node.js process creation patterns consistent with the easy-day-js postinstall hook executing `setup.cjs` with the `--no-warnings` flag. Compile status: PASS (sigma check: 0 errors, 0 issues; converts to Splunk and LogScale).

```yaml
title: Mastra NPM Supply Chain Attack - easy-day-js Postinstall Dropper Execution
id: a7e3c1d4-8f2b-4e6a-9d1c-5b8f7e2a3c4d
status: experimental
description: >
    Detects execution patterns associated with the easy-day-js npm supply chain attack targeting
    the @mastra namespace. The malicious package uses a postinstall hook to execute setup.cjs,
    which disables TLS verification, downloads a second-stage RAT payload, and self-deletes.
references:
    - https://thehackernews.com/2026/06/144-mastra-npm-packages-compromised-via.html
    - https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js
    - https://safedep.io/mastra-npm-scope-takeover-supply-chain-attack/
author: Actioner CTI
date: 2026-06-17
tags:
    - attack.t1195.002
    - attack.t1059.007
    - attack.t1070.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent_npm:
        ParentImage|endswith:
            - '\node.exe'
            - '/node'
        ParentCommandLine|contains:
            - 'npm'
            - 'postinstall'
    selection_dropper:
        CommandLine|contains:
            - 'setup.cjs'
            - '--no-warnings'
    selection_easy_day_js_path:
        CommandLine|contains:
            - 'easy-day-js'
    condition: selection_parent_npm and (selection_dropper or selection_easy_day_js_path)
falsepositives:
    - Legitimate packages using setup.cjs with --no-warnings flag during postinstall
level: high
```

### Sigma Rule 2: Malicious Persistence via LaunchAgent or Systemd

Detects file creation at persistence paths used by the easy-day-js RAT, including the distinctive misspelling of "protocol" as "protocal." Compile status: PASS.

```yaml
title: Mastra NPM Supply Chain Attack - Malicious Persistence via LaunchAgent or Systemd
id: b8f4d2e5-9a3c-4f7b-ae2d-6c9f8e3b4d5e
status: experimental
description: >
    Detects persistence mechanisms deployed by the easy-day-js RAT payload, including
    macOS LaunchAgent with misspelled NVM disguise or Linux systemd user service.
references:
    - https://safedep.io/mastra-npm-scope-takeover-supply-chain-attack/
    - https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js
author: Actioner CTI
date: 2026-06-17
tags:
    - attack.t1543.001
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection_macos_plist:
        TargetFilename|contains: 'com.nvm.protocal.plist'
    selection_macos_payload:
        TargetFilename|contains: 'Library/NodePackages/protocal.cjs'
    selection_linux_service:
        TargetFilename|contains: 'systemd/user/nvmconf.service'
    selection_linux_payload:
        TargetFilename|contains: '.config/NodePackages'
    selection_windows_payload:
        TargetFilename|contains: 'ProgramData\NodePackages'
    condition: 1 of selection_*
falsepositives:
    - Unlikely due to distinctive misspelling of protocol as protocal
level: high
```

### Sigma Rule 3: TLS Rejection Disabled by Node.js Process

Detects Node.js processes with `NODE_TLS_REJECT_UNAUTHORIZED` in the command line, used by the dropper to bypass certificate validation. Compile status: PASS.

```yaml
title: Mastra NPM Supply Chain Attack - TLS Rejection Disabled and Outbound Connection to C2
id: c9a5e3f6-ab4d-4a8c-bf3e-7d0a9f4c5e6f
status: experimental
description: >
    Detects Node.js processes setting NODE_TLS_REJECT_UNAUTHORIZED=0 environment variable,
    which is used by the easy-day-js dropper to bypass TLS certificate validation before
    connecting to the C2 server.
references:
    - https://thehackernews.com/2026/06/144-mastra-npm-packages-compromised-via.html
    - https://safedep.io/mastra-npm-scope-takeover-supply-chain-attack/
author: Actioner CTI
date: 2026-06-17
tags:
    - attack.t1553.004
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_node:
        Image|endswith:
            - '\node.exe'
            - '/node'
    selection_tls_disable:
        CommandLine|contains: 'NODE_TLS_REJECT_UNAUTHORIZED'
    condition: selection_node and selection_tls_disable
falsepositives:
    - Development environments that intentionally disable TLS verification
    - CI/CD pipelines with self-signed certificates
level: medium
```

### YARA Rule 1: easy-day-js Stage-1 Dropper

Detects the `setup.cjs` dropper file based on C2 IPs, XOR-encoded package name bytes, and behavioral string combinations unique to the dropper. Compile status: PASS (yarac exit 0).

```yara
rule easy_day_js_stage1_dropper {
    meta:
        description = "Detects the easy-day-js stage-1 dropper (setup.cjs) used in the Mastra npm supply chain attack"
        author = "Actioner CTI"
        date = "2026-06-17"
        reference = "https://safedep.io/mastra-npm-scope-takeover-supply-chain-attack/"
        hash = "4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417"
        severity = "critical"

    strings:
        $postinstall = "postinstall" ascii
        $setup_cjs = "setup.cjs" ascii
        $tls_disable = "NODE_TLS_REJECT_UNAUTHORIZED" ascii
        $self_delete = "rmSync(__filename" ascii
        $detach = "\"detached\":true" ascii nocase
        $detach2 = "detached: true" ascii nocase
        $stdio_ignore = "stdio" ascii
        $windows_hide = "windowsHide" ascii
        $c2_ip1 = "23.254.164.92" ascii
        $c2_ip2 = "23.254.164.123" ascii
        $campaign_id = "49890878" ascii
        $update_path = "/update/49890878" ascii
        $xor_bytes = { e5 e1 f3 f9 ad e4 e1 f9 ad ea f3 }
        $pkg_history = ".pkg_history" ascii
        $pkg_logs = ".pkg_logs" ascii

    condition:
        filesize < 50KB and (
            ($c2_ip1 or $c2_ip2 or $update_path) or
            ($xor_bytes) or
            ($tls_disable and $self_delete and ($detach or $detach2)) or
            ($pkg_history and $pkg_logs and $setup_cjs) or
            (4 of ($postinstall, $setup_cjs, $self_delete, $stdio_ignore, $windows_hide, $campaign_id))
        )
}
```

### YARA Rule 2: easy-day-js Stage-2 RAT

Detects the 41 KB obfuscated RAT payload based on C2 infrastructure strings, beacon protocol artifacts, and persistence path indicators. Compile status: PASS (yarac exit 0).

```yara
rule easy_day_js_stage2_rat {
    meta:
        description = "Detects the easy-day-js stage-2 RAT payload used in the Mastra npm supply chain attack"
        author = "Actioner CTI"
        date = "2026-06-17"
        reference = "https://safedep.io/mastra-npm-scope-takeover-supply-chain-attack/"
        hash = "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf"
        severity = "critical"

    strings:
        $c2_ip = "23.254.164.123" ascii
        $campaign_id = "49890878" ascii
        $beacon_type = "\"type\":\"prepare\"" ascii nocase
        $beacon_type2 = "\"type\": \"prepare\"" ascii nocase
        $target_id = "targetId" ascii
        $common_info = "\"common\"" ascii
        $app_info = "\"appInfo\"" ascii
        $ext_info = "\"extInfo\"" ascii
        $cmd_tag = "tpcsr" ascii
        $resp_tag = "\"r0\"" ascii
        $plist_persist = "com.nvm.protocal.plist" ascii
        $protocal_cjs = "protocal.cjs" ascii
        $nvmconf_service = "nvmconf.service" ascii
        $node_packages = "NodePackages" ascii
        $metamask = "MetaMask" ascii
        $phantom = "Phantom" ascii
        $solflare = "Solflare" ascii
        $wolfssl_cn = "www.wolfssl.com" ascii

    condition:
        filesize < 500KB and (
            ($c2_ip and $campaign_id) or
            ($plist_persist or $nvmconf_service) or
            ($cmd_tag and $resp_tag) or
            ($beacon_type or $beacon_type2) and ($target_id and $common_info and $app_info and $ext_info) or
            (3 of ($protocal_cjs, $node_packages, $metamask, $phantom, $solflare, $wolfssl_cn))
        )
}
```

### YARA Rule 3: easy-day-js Persistence Artifacts

Detects on-disk persistence artifacts written by the RAT, particularly the misspelled "protocal" path and NodePackages directories. Compile status: PASS (yarac exit 0).

```yara
rule easy_day_js_persistence_artifacts {
    meta:
        description = "Detects persistence artifacts written by the easy-day-js RAT on disk"
        author = "Actioner CTI"
        date = "2026-06-17"
        reference = "https://safedep.io/mastra-npm-scope-takeover-supply-chain-attack/"
        severity = "high"

    strings:
        $plist_name = "com.nvm.protocal" ascii
        $protocal_path = "Library/NodePackages/protocal.cjs" ascii
        $systemd_name = "nvmconf.service" ascii
        $config_node = "NodePackages/config.json" ascii
        $execution_bypass = "ExecutionPolicy Bypass" ascii nocase

    condition:
        2 of them
}
```

### Suricata Rule 1: Stage-2 Payload Download

Detects HTTP requests to the stage-2 payload URL at `23.254.164.92:8000/update/49890878`. Compile status: PASS (Suricata -T exit 0).

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE easy-day-js Stage-2 Payload Download from C2 23.254.164.92"; flow:established,to_server; http.uri; content:"/update/49890878"; http.host; content:"23.254.164.92"; classtype:trojan-activity; sid:2026061701; rev:1;)
```

### Suricata Rule 2: RAT Beacon TLS Certificate Detection

Detects TLS connections to the RAT C2 server using the expired wolfssl.com certificate. Compile status: PASS.

```
alert tls $HOME_NET any -> 23.254.164.123 443 (msg:"MALWARE easy-day-js RAT Beacon to C2 23.254.164.123"; flow:established,to_server; tls.cert_subject; content:"CN=www.wolfssl.com"; classtype:trojan-activity; sid:2026061702; rev:1;)
```

### Suricata Rule 3: Dropper C2 Connection

Detects TCP connections to the dropper C2 IP on port 8000. Compile status: PASS.

```
alert tcp $HOME_NET any -> 23.254.164.92 8000 (msg:"MALWARE easy-day-js Dropper C2 Connection to 23.254.164.92:8000"; flow:established,to_server; classtype:trojan-activity; sid:2026061703; rev:1;)
```

### Suricata Rule 4: RAT C2 Connection

Detects TCP connections to the RAT C2 IP on port 443. Compile status: PASS.

```
alert tcp $HOME_NET any -> 23.254.164.123 443 (msg:"MALWARE easy-day-js RAT C2 Connection to 23.254.164.123:443"; flow:established,to_server; classtype:trojan-activity; sid:2026061704; rev:1;)
```

### Suricata Rule 5: Campaign ID in HTTP URI

Detects the campaign identifier `/49890878` in HTTP URIs, which may indicate C2 communication even if the IP changes. Compile status: PASS.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE easy-day-js Campaign ID in HTTP URI"; flow:established,to_server; http.uri; content:"/49890878"; classtype:trojan-activity; sid:2026061705; rev:1;)
```

### Suricata Rule 6: Legacy IE8 User-Agent

Detects the anomalous Internet Explorer 8 User-Agent string used by the payload fetch mechanism. Compile status: PASS.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SUSPICIOUS Legacy IE8 User-Agent Potentially Used by easy-day-js Payload"; flow:established,to_server; http.user_agent; content:"mozilla/4.0 (compatible|3b| msie 8.0|3b| windows nt 5.1|3b| trident/4.0)"; classtype:trojan-activity; sid:2026061706; rev:1;)
```

---

## Sources

- [The Hacker News - 144 Mastra npm Packages Compromised via Hijacked Contributor Account](https://thehackernews.com/2026/06/144-mastra-npm-packages-compromised-via.html)
- [Security Online - Mastra Supply Chain Attack](https://securityonline.info/mastra-supply-chain-attack/)
- [StepSecurity - Mastra npm Supply Chain Attack: 140+ Packages Backdoored via easy-day-js Typosquat](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)
- [SafeDep - Mastra npm Scope Takeover: 141 Packages Drop a RAT](https://safedep.io/mastra-npm-scope-takeover-supply-chain-attack/)
- [Microsoft Threat Intelligence on X (Mastra-AI npm ecosystem compromise)](https://x.com/MsftSecIntel/status/2067099387101335909)
- [Socket.dev - @mastra/toolsets Package Security Analysis](https://socket.dev/npm/package/@mastra/toolsets)
