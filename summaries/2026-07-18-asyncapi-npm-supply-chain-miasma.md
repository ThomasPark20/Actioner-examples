# Technical Analysis Report: AsyncAPI npm Supply Chain Compromise - Miasma Runtime (2026-07-18)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-18
Version: 1.1 (REVISED)

## Executive Summary

On July 14, 2026, threat actors compromised five @asyncapi npm packages through a vulnerable GitHub Actions workflow (`pull_request_target`) in the asyncapi/generator repository. Pull request #2155 exposed the asyncapi-bot personal access token (PAT), which was subsequently used to publish malicious package versions via npm OIDC trusted publishing. The malicious code executes at module import time, bypassing npm's install-script protections entirely. Upon import, an obfuscated loader spawns a detached Node.js child process that fetches the "Miasma" modular runtime from IPFS, decrypts it via HKDF-SHA256/AES-256-GCM, and establishes C2 communication with 85.137.53[.]71 on ports 8080/8081/8091. The runtime (self-identified as "M-RED-TEAM v6.4", campaign "miasma-train-p1") supports persistence via Windows Registry Run keys, Linux systemd units, and macOS rc injection. Credential-harvesting modules targeting GitHub, GitLab, npm, AWS, Azure, OpenAI, Docker, SSH, and Kubernetes secrets are present but currently disabled. Fallback C2 channels include Nostr, Ethereum, BitTorrent DHT, libp2p, and IPFS.

## Background: npm Supply Chain via Import-Time Execution

Traditional npm supply chain attacks have relied on install scripts (`preinstall`/`postinstall` hooks in package.json) for code execution. Package managers and security tooling have increasingly blocked or audited these scripts. The AsyncAPI compromise represents an evolution: malicious code placed inside module source files executes at `require()`/`import` time, meaning any downstream project that imports the compromised package triggers the payload without any install-script interaction. This bypasses `--ignore-scripts` defenses and most static auditing of package.json hooks. The attack leveraged the `pull_request_target` GitHub Actions workflow vulnerability -- a known dangerous pattern where workflows triggered by PRs from forks run with elevated repository secrets access.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-14 (est.) | Threat actor submits PR #2155 to asyncapi/generator exploiting `pull_request_target` workflow |
| 2026-07-14 | asyncapi-bot PAT exposed via workflow execution in PR context |
| 2026-07-14 | Malicious versions published via npm OIDC trusted publishing: @asyncapi/specs 6.11.2-alpha.1, @asyncapi/specs 6.11.2, @asyncapi/generator 3.3.1, @asyncapi/generator-components 0.7.1, @asyncapi/generator-helpers 1.1.1 |
| 2026-07-15 | Microsoft Security Blog publishes technical analysis |
| 2026-07-15 | Microsoft Defender signatures deployed: Trojan:JS/MiasmStealer.SC, Trojan:Script/Supychain.A, Trojan:JS/VaultLoader.MJZ!MTB, Trojan:JS/SpawnLoader.MKV!MTB |

## Root Cause: Vulnerable GitHub Actions `pull_request_target` Workflow

The `pull_request_target` event in GitHub Actions runs workflows in the context of the base repository rather than the forked PR branch, granting access to repository secrets. The asyncapi/generator repository contained a workflow that, when triggered by PR #2155, exposed the asyncapi-bot PAT. This token had sufficient permissions to perform npm OIDC trusted publishing, allowing the attacker to publish malicious versions of five @asyncapi packages without needing direct npm credentials.

## Technical Analysis of the Malicious Payload

### 1. Compromised Packages

| Package | Version | SHA-256 |
|---------|---------|---------|
| @asyncapi/specs | 6.11.2-alpha.1 | d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7 |
| @asyncapi/specs | 6.11.2 | 9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b |
| @asyncapi/generator | 3.3.1 | bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4 |
| @asyncapi/generator-components | 0.7.1 | 082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab |
| @asyncapi/generator-helpers | 1.1.1 | 34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1 |

### 2. Injected Files

Malicious code was injected into the following module source files (executes on `require()`/`import`):
- `index.js`
- `lib/templates/config/validator.js`
- `lib/utils/ErrorHandling.js`
- `src/utils.js`

### 3. Execution Flow

```
Import triggered (require/import)
  -> Obfuscated loader (ROT-94de encoding + eval())
    -> Detached Node.js child spawned (stdio: 'ignore', windowsHide: true, .unref())
      -> IPFS fetch of sync.js via gateway
        -> HKDF-SHA256 key derivation (master: "rt-vault-master-key-32b-aaaaaaaa", info: "rt-file-key")
          -> AES-256-GCM decryption (IV: first 12 bytes, auth tag: last 16 bytes)
            -> Miasma runtime initialization (M-RED-TEAM v6.4)
```

**Process spawn pattern:**
```javascript
spawn('node', [payloadPath], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
```

### 4. Persistence Mechanisms

**Payload drop locations (sync.js):**
| Platform | Path |
|----------|------|
| Windows | `%LOCALAPPDATA%\NodeJS\sync.js` |
| Linux | `~/.local/share/NodeJS/sync.js` |
| macOS | `~/Library/Application Support/NodeJS/sync.js` |
| Fallback | `~/.config/NodeJS/sync.js` |
| Lock file | `~/.config/.miasma/run/node.lock` |

**OS-specific persistence:**
| Platform | Mechanism |
|----------|-----------|
| Windows | HKCU Registry Run key: `miasma-monitor` |
| Linux | systemd user unit: `miasma-monitor.service` |
| macOS | rc injection (shell profile modification) |

### 5. Cryptography

- **Key derivation**: HKDF-SHA256 with master key `rt-vault-master-key-32b-aaaaaaaa` and info string `rt-file-key`
- **Payload encryption**: AES-256-GCM; IV is first 12 bytes of ciphertext, auth tag is last 16 bytes
- **Loader obfuscation**: ROT-94de encoding followed by `eval()`

### 6. Command and Control

**Primary C2 infrastructure:**
| Function | Endpoint |
|----------|----------|
| Primary C2 | 85.137.53[.]71:8080 |
| Upload channel | 85.137.53[.]71:8081 |
| Management | 85.137.53[.]71:8091 |

**IPFS payload delivery:**
- Gateway: `ipfs[.]io/ipfs/`
- CID 1: `Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf`
- CID 2: `QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9`

**Fallback C2 channels:** Nostr, Ethereum smart contracts, BitTorrent DHT, libp2p, IPFS pubsub

### 7. Credential Targets (Currently Disabled)

The Miasma runtime contains credential-harvesting modules targeting:
- **Tokens**: GITHUB_TOKEN, GITLAB_TOKEN, NPM_TOKEN, AWS_ACCESS_KEY, AZURE_CLIENT_SECRET, OPENAI_API_KEY, DOCKER_TOKEN
- **Files**: `~/.npmrc`, `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.docker/config.json`, kubeconfig

These modules are present in the code but currently disabled (not executing).

### 8. Runtime Identification

- **Version string**: M-RED-TEAM v6.4
- **Campaign ID**: miasma-train-p1

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: URLs use `hxxps://`, dots in IPs/domains use `[.]`, @ uses `[at]`.

### Package Level

| Package | Malicious Version | SHA-256 |
|---------|-------------------|---------|
| `@asyncapi/specs` | 6.11.2-alpha.1 | `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7` |
| `@asyncapi/specs` | 6.11.2 | `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b` |
| `@asyncapi/generator` | 3.3.1 | `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4` |
| `@asyncapi/generator-components` | 0.7.1 | `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab` |
| `@asyncapi/generator-helpers` | 1.1.1 | `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1` |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Windows | `%LOCALAPPDATA%\NodeJS\sync.js` | Miasma runtime payload |
| Linux | `~/.local/share/NodeJS/sync.js` | Miasma runtime payload |
| macOS | `~/Library/Application Support/NodeJS/sync.js` | Miasma runtime payload |
| Any | `~/.config/NodeJS/sync.js` | Fallback payload location |
| Any | `~/.config/.miasma/run/node.lock` | Runtime lock file |
| npm | `index.js` (injected) | Import-time loader |
| npm | `lib/templates/config/validator.js` (injected) | Import-time loader |
| npm | `lib/utils/ErrorHandling.js` (injected) | Import-time loader |
| npm | `src/utils.js` (injected) | Import-time loader |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `85[.]137[.]53[.]71` | C2 server |
| Port | 8080 | Primary C2 |
| Port | 8081 | Upload/exfiltration |
| Port | 8091 | Management channel |
| URL | `hxxps://ipfs[.]io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` | IPFS payload CID 1 |
| URL | `hxxps://ipfs[.]io/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9` | IPFS payload CID 2 |

### Behavioral

- Node.js process spawning detached child with `sync.js` argument, stdio ignored
- IPFS gateway requests for specific CIDs (46-character base58 strings starting with `Qm`)
- Registry key creation at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\miasma-monitor`
- systemd unit file creation: `miasma-monitor.service`
- Lock file creation at `~/.config/.miasma/run/node.lock`
- Network connections to 85.137.53[.]71 on ports 8080, 8081, 8091

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.003 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Malicious @asyncapi npm packages published via compromised OIDC trust |
| T1129 | Shared Modules | Payload executes at module import time via `require()`/`import` |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Obfuscated JavaScript loader with ROT-94de encoding and eval() |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Windows HKCU Run key "miasma-monitor" |
| T1547.004 | Boot or Logon Autostart Execution: Unix Shell Configuration Modification | macOS rc/shell profile injection |
| T1543.002 | Create or Modify System Process: Systemd Service | Systemd unit miasma-monitor.service on Linux |
| T1027 | Obfuscated Files or Information | ROT-94de encoding, HKDF-SHA256/AES-256-GCM encryption chain |
| T1552 | Unsecured Credentials | Credential-harvesting modules targeting tokens/files (present but disabled) |
| T1555 | Credentials from Password Stores | Targets ~/.npmrc, ~/.aws/credentials, ~/.ssh/id_rsa, kubeconfig |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP C2 to 85.137.53.71:8080; IPFS gateway for payload delivery |
| T1008 | Fallback Channels | Nostr, Ethereum, BitTorrent DHT, libp2p, IPFS as backup C2 |
| T1105 | Ingress Tool Transfer | IPFS fetch of sync.js runtime payload |

## Impact Assessment

**Breadth**: Five packages in the @asyncapi namespace, which is widely used for event-driven API development. The `@asyncapi/generator` package alone has significant weekly download counts across enterprise consumers building event-driven architectures.

**Depth**: Import-time execution means any project that `require()`s or `import`s a compromised package version is affected -- no explicit install-script execution required. The Miasma runtime establishes persistent C2 access with multi-channel fallback resilience.

**Stealth**: The import-time execution vector evades `--ignore-scripts` protections and most npm audit tooling focused on install hooks. The detached child process with ignored stdio leaves minimal process tree evidence. IPFS delivery provides content-addressed, decentralized payload hosting resistant to takedown.

**Mitigation factor**: Credential-harvesting modules are currently disabled, limiting immediate data theft impact. However, the persistent C2 channel means the threat actor retains the ability to activate these modules remotely at any time.

## Detection & Remediation

### Immediate Detection

**Check for compromised package versions:**
```bash
# Check package-lock.json / yarn.lock for affected versions
grep -rE '"@asyncapi/(specs|generator|generator-components|generator-helpers)"' package-lock.json yarn.lock 2>/dev/null | grep -E '(6\.11\.2|3\.3\.1|0\.7\.1|1\.1\.1)'
```

**Scan for persistence artifacts:**
```bash
# Linux/macOS
find ~ -path "*/NodeJS/sync.js" 2>/dev/null
find ~ -path "*/.miasma/run/node.lock" 2>/dev/null
systemctl --user list-units 2>/dev/null | grep miasma-monitor
find ~/.config/systemd -name "miasma-monitor*" 2>/dev/null
```

**Windows (PowerShell):**
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "miasma-monitor" -ErrorAction SilentlyContinue
Test-Path "$env:LOCALAPPDATA\NodeJS\sync.js"
Test-Path "$env:USERPROFILE\.config\.miasma\run\node.lock"
```

**Network detection:**
```bash
# Check for active connections to C2
ss -tnp | grep -E '85\.137\.53\.71:(8080|8081|8091)'
netstat -tn | grep -E '85\.137\.53\.71'
```

### Remediation

1. **Immediately update or remove** compromised @asyncapi package versions; pin to verified clean versions
2. **Kill persistence**: Remove `miasma-monitor` registry key (Windows), disable/remove `miasma-monitor.service` (Linux), check shell profiles for injected rc entries (macOS)
3. **Delete payload files**: Remove `sync.js` from all NodeJS directories and `.miasma/run/node.lock`
4. **Block C2**: Firewall block 85.137.53[.]71 on all ports; block IPFS CIDs at gateway/proxy level
5. **Credential rotation**: If compromised packages were imported, rotate all credentials accessible to the affected environment (even though harvesting modules are currently disabled, the C2 channel could activate them)
6. **Audit GitHub Actions workflows**: Review all `pull_request_target` workflows for secret exposure; migrate to `pull_request` event where possible

### Long-Term Hardening

1. **Use lockfiles with integrity hashes** (`npm ci` with `package-lock.json` integrity fields)
2. **Audit `pull_request_target` workflows** across all repositories; prefer `pull_request` + `workflow_run` pattern
3. **Implement import-time execution monitoring** beyond install-script auditing
4. **Deploy network segmentation** blocking developer workstations from reaching arbitrary IPs on high ports
5. **Monitor IPFS gateway access** from CI/CD and developer environments

## Detection Rules

These detections target the AsyncAPI Miasma compromise's distinctive artifacts: the specific C2 IP 85.137.53[.]71 on ports 8080/8081/8091, persistence file paths (NodeJS/sync.js, .miasma/run/node.lock), the detached Node.js spawn pattern, the systemd unit "miasma-monitor.service", the registry key "miasma-monitor", and IPFS CIDs used for payload delivery. All rules are PoC/advisory-specific (strict leniency); compile status verified via sigma convert and suricata -T.

### Sigma: AsyncAPI Miasma C2 IP Communication (85.137.53.71)
Detects network connections to the Miasma runtime C2 server at 85.137.53[.]71 on ports 8080 (primary C2), 8081 (upload), or 8091 (management).
**Status:** compile PASS (splunk, log_scale) | confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. High confidence: specific IP + specific ports combination is highly distinctive. -->
```yaml
title: AsyncAPI Miasma C2 IP Communication (85.137.53.71)
id: 72f8d355-3883-4877-b565-e2d808f8d963
status: experimental
description: >
    Detects network connections to the Miasma runtime C2 server at
    85.137.53.71 on ports 8080 (primary C2), 8081 (upload), or 8091
    (management). This IP was used as the command-and-control server for
    the AsyncAPI npm supply chain compromise discovered July 14, 2026.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/18
tags:
    - attack.t1071.001
    - attack.t1008
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '85.137.53.71'
        DestinationPort:
            - 8080
            - 8081
            - 8091
    condition: selection
falsepositives:
    - Legitimate services hosted on this IP (verify context before blocking)
level: critical
```

### Sigma: AsyncAPI Miasma sync.js Persistence File Creation (Windows)
Detects creation of the Miasma runtime persistence file `sync.js` in the Windows `%LOCALAPPDATA%\NodeJS\` directory or the `.miasma` lock file directory.
**Status:** compile PASS (splunk, log_scale) | confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. High confidence: %LOCALAPPDATA%\NodeJS\sync.js is not a legitimate Windows path used by Node.js or npm. -->
```yaml
title: AsyncAPI Miasma sync.js Persistence File Creation
id: a9045293-14a0-4799-8ed0-a060570375b1
status: experimental
description: >
    Detects creation of the Miasma runtime persistence file sync.js in
    OS-specific application data directories. The AsyncAPI npm supply chain
    compromise drops sync.js to %LOCALAPPDATA%\NodeJS\sync.js (Windows),
    ~/.local/share/NodeJS/sync.js (Linux), ~/Library/Application Support/NodeJS/sync.js
    (macOS), or ~/.config/NodeJS/sync.js (fallback). Also detects the lock file
    at ~/.config/.miasma/run/node.lock.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/18
tags:
    - attack.t1547.001
    - attack.t1547.004
logsource:
    category: file_event
    product: windows
detection:
    selection_windows:
        TargetFilename|contains: '\NodeJS\sync.js'
    selection_lock:
        TargetFilename|contains: '.miasma'
        TargetFilename|endswith: 'node.lock'
    condition: 1 of selection_*
falsepositives:
    - Legitimate Node.js tooling creating sync.js in NodeJS directories (unlikely with this exact path pattern)
level: critical
```

### Sigma: AsyncAPI Miasma sync.js Persistence File Creation (Linux/macOS)
Detects creation of the Miasma runtime persistence file `sync.js` in Linux/macOS application data directories or the `.miasma` lock file.
**Status:** compile PASS (splunk, log_scale) | confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. High confidence: ~/.local/share/NodeJS/sync.js and ~/Library/Application Support/NodeJS/sync.js are not legitimate paths. -->
```yaml
title: AsyncAPI Miasma sync.js Persistence File Creation (Linux/macOS)
id: 4e708640-f71e-4cd1-a13c-50510d6edb70
status: experimental
description: >
    Detects creation of the Miasma runtime persistence file sync.js in Linux
    and macOS application data directories. The AsyncAPI npm supply chain
    compromise drops sync.js to ~/.local/share/NodeJS/sync.js (Linux),
    ~/Library/Application Support/NodeJS/sync.js (macOS), or
    ~/.config/NodeJS/sync.js (fallback). Also detects the lock file
    at ~/.config/.miasma/run/node.lock.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/18
tags:
    - attack.t1547.004
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection_linux_share:
        TargetFilename|endswith: '/.local/share/NodeJS/sync.js'
    selection_macos:
        TargetFilename|contains: '/Library/Application Support/NodeJS/sync.js'
    selection_config:
        TargetFilename|endswith: '/.config/NodeJS/sync.js'
    selection_lock:
        TargetFilename|contains: '/.config/.miasma/run/node.lock'
    condition: 1 of selection_*
falsepositives:
    - Legitimate Node.js tooling creating sync.js in these specific paths (highly unlikely)
level: critical
```

### Sigma: AsyncAPI Miasma Detached Node.js Child Process Spawn
Detects Node.js spawning a detached child Node.js process executing `sync.js` -- the Miasma runtime's characteristic import-time payload delivery pattern.
**Status:** compile PASS (splunk, log_scale) | confidence: medium
<!-- audit: sigma convert splunk 0; log_scale 0. Medium confidence: node spawning node with sync.js is specific but legitimate Node.js file-sync tools could match; filter reduces FPs. -->
```yaml
title: AsyncAPI Miasma Detached Node.js Child Process Spawn
id: b633749c-bbaf-4524-9011-fec0843bcf7f
status: experimental
description: >
    Detects the Miasma runtime's characteristic detached Node.js child process
    spawn pattern. The malicious code executes at import time and spawns a
    detached Node.js process running sync.js payload with stdio ignored and
    windowsHide enabled, then unreferences the child to prevent the parent
    from waiting.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/18
tags:
    - attack.t1059.007
    - attack.t1129
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\node.exe'
        Image|endswith: '\node.exe'
        CommandLine|contains:
            - '\NodeJS\sync.js'
            - '.local/share/NodeJS/sync.js'
            - 'Library/Application Support/NodeJS/sync.js'
            - '.config/NodeJS/sync.js'
    condition: selection
falsepositives:
    - Legitimate Node.js applications using identical NodeJS/sync.js payload paths (highly unlikely)
level: high
```

### Sigma: AsyncAPI Miasma Systemd Persistence Unit Installation
Detects creation of the `miasma-monitor.service` systemd unit file used for Linux persistence.
**Status:** compile PASS (splunk, log_scale) | confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. High confidence: "miasma-monitor" is a unique malicious service name with no legitimate software equivalent. -->
```yaml
title: AsyncAPI Miasma Systemd Persistence Unit Installation
id: 8a896e11-e24c-427e-aa7e-5ed284e717c6
status: experimental
description: >
    Detects creation of the miasma-monitor.service systemd unit file used by
    the Miasma runtime for persistence on Linux systems. The AsyncAPI npm
    supply chain compromise installs this service to maintain persistence
    across reboots.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/18
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains: 'miasma-monitor'
        TargetFilename|endswith: '.service'
    condition: selection
falsepositives:
    - None expected; miasma-monitor is a unique malicious service name
level: critical
```

### Sigma: AsyncAPI Miasma Windows Registry Run Key Persistence
Detects creation of the `miasma-monitor` Windows Registry Run key for boot persistence.
**Status:** compile PASS (splunk, log_scale) | confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. High confidence: "miasma-monitor" registry value name is unique to this malware family. -->
```yaml
title: AsyncAPI Miasma Windows Registry Run Key Persistence
id: e87de041-d567-49b6-855b-12cda563eccc
status: experimental
description: >
    Detects the Miasma runtime setting the "miasma-monitor" Windows registry
    Run key for persistence. The AsyncAPI npm supply chain compromise creates
    an HKCU Run key named "miasma-monitor" to execute the payload at user logon.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/18
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\CurrentVersion\Run\'
        TargetObject|endswith: 'miasma-monitor'
    condition: selection
falsepositives:
    - None expected; miasma-monitor is a unique malicious registry value name
level: critical
```

### Sigma: AsyncAPI Miasma IPFS Payload Download via Known CIDs
Detects proxy/web log evidence of IPFS gateway requests fetching the specific content identifiers (CIDs) used to deliver the Miasma runtime payload.
**Status:** compile PASS (splunk, log_scale) | confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. High confidence: IPFS CIDs are content-addressed hashes unique to the malicious payload. -->
```yaml
title: AsyncAPI Miasma IPFS Payload Download via Known CIDs
id: 7358cb78-b72e-4c7c-8ce6-32a9e7a0b862
status: experimental
description: >
    Detects HTTP requests to IPFS gateways fetching the specific CIDs used by
    the AsyncAPI npm supply chain compromise to download the Miasma runtime
    payload. The malware fetches sync.js via IPFS with CIDs
    Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf and
    QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/18
tags:
    - attack.t1105
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_ipfs_gateway:
        cs-uri|contains: '/ipfs/'
    selection_cids:
        cs-uri|contains:
            - 'Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf'
            - 'QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9'
    condition: selection_ipfs_gateway and selection_cids
falsepositives:
    - Security researchers investigating these specific IPFS CIDs
level: critical
```

### Suricata: AsyncAPI Miasma C2 and IPFS Payload Delivery
Detects network traffic to the Miasma C2 IP on specific ports and IPFS gateway requests for the malicious payload CIDs.
**Status:** compile PASS (suricata -T exit 0) | confidence: high
<!-- audit: suricata -T exit 0. Six rules: 1x IP-based multi-port, 2x IPFS CID HTTP URI, 3x per-port HTTP. All validated against Suricata 7.0.3. -->
```suricata
alert tcp $HOME_NET any -> 85.137.53.71 [8080,8081,8091] (msg:"Actioner - AsyncAPI Miasma C2 Communication to 85.137.53.71"; flow:to_server,established; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-18, campaign miasma-train-p1; sid:2300001; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AsyncAPI Miasma IPFS Payload Download CID Qmet4fhs"; flow:established,to_server; http.uri; content:"/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-18, campaign miasma-train-p1; sid:2300002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AsyncAPI Miasma IPFS Payload Download CID QmQobZSp"; flow:established,to_server; http.uri; content:"/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-18, campaign miasma-train-p1; sid:2300003; rev:1;)

alert http $HOME_NET any -> 85.137.53.71 8080 (msg:"Actioner - AsyncAPI Miasma C2 HTTP Beacon to Port 8080"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-18, campaign miasma-train-p1; sid:2300004; rev:1;)

alert http $HOME_NET any -> 85.137.53.71 8081 (msg:"Actioner - AsyncAPI Miasma Data Upload to Port 8081"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-18, campaign miasma-train-p1; sid:2300005; rev:1;)

alert http $HOME_NET any -> 85.137.53.71 8091 (msg:"Actioner - AsyncAPI Miasma Management Port 8091 Communication"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-18, campaign miasma-train-p1; sid:2300006; rev:1;)
```

## Microsoft Detections

The following Microsoft Defender signatures detect components of this attack:

| Signature | Component |
|-----------|-----------|
| Trojan:JS/MiasmStealer.SC | Miasma credential stealer module |
| Trojan:Script/Supychain.A | Supply chain compromise payload |
| Trojan:JS/VaultLoader.MJZ!MTB | HKDF/AES vault decryption loader |
| Trojan:JS/SpawnLoader.MKV!MTB | Detached process spawn loader |

## Sources

- [Microsoft Security Blog: Unpacking AsyncAPI npm Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/)
- [Miasma Worm Technical Analysis (prior campaign)](https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents)
- [MITRE ATT&CK: Supply Chain Compromise T1195.003](https://attack.mitre.org/techniques/T1195/003/)
- [GitHub Actions Security: pull_request_target](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)

<!-- revision: v1.1 2026-07-18 — Fixed: Sigma Rule 4 CommandLine constrained to distinctive paths (\NodeJS\sync.js, .local/share/NodeJS/sync.js, Library/Application Support/NodeJS/sync.js); Suricata SID 2300001 changed from alert ip to alert tcp with flow:to_server,established; MITRE T1547.015 corrected to T1543.002 (Systemd Service); T1110 corrected to T1552 (Unsecured Credentials); Sigma Rule 5 tag corrected to attack.t1543.002; all Sigma rule UUIDs regenerated as proper random UUIDv4. -->
