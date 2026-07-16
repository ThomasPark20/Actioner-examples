# Technical Analysis Report: AsyncAPI npm Supply Chain Compromise (2026-07-16)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-16
Version: DRAFT 1.0

## Executive Summary

On July 14, 2026, an attacker exploited a vulnerable GitHub Actions workflow (`pull_request_target` with untrusted checkout) in the AsyncAPI `generator` repository to steal the `asyncapi-bot` personal access token. Within approximately 90 minutes, the attacker leveraged this token to inject obfuscated malware loaders into five npm package versions across four packages in the `@asyncapi` scope -- collectively exceeding 2 million weekly downloads. The malicious code executed at **import time** (not install time), bypassing the standard `--ignore-scripts` mitigation, and delivered the **Miasma** RAT framework (self-identified as "M-RED-TEAM v6.4") via IPFS-hosted encrypted payloads. The malware established persistence across Windows, Linux, and macOS and contained modules for credential harvesting, browser password theft, supply-chain propagation, and remote shell access, though several destructive modules were flagged as disabled in this build.

The compromised packages were published through legitimate GitHub Actions OIDC release workflows, generating valid provenance signatures despite unauthorized source commits. Microsoft Threat Intelligence identified and reported the compromise on July 15, 2026. The exposure window was approximately 1-2 hours before detection of the first downstream fetch.

## Background: AsyncAPI Ecosystem

AsyncAPI is a widely adopted open-source specification and tooling ecosystem for defining, building, and documenting event-driven APIs. The `@asyncapi/specs` package is a foundational transitive dependency pulled in by numerous AsyncAPI tools and framework integrations. With combined weekly downloads exceeding 2 million, compromise of these packages posed a significant risk to developer workstations, CI/CD pipelines, container builds, and production services globally. The project uses automated GitHub Actions workflows for npm publishing, with OIDC-based provenance attestation.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-29 | Proof-of-concept identifying `pull_request_target` vulnerability submitted |
| 2026-05-17 | Proposal to separate untrusted builds from secret-receiving steps filed (still pending review at time of compromise) |
| 2026-07-14 05:08:58 | Malicious commit `47be388` created targeting `manual-netlify-preview.yml` workflow |
| 2026-07-14 05:11:05 | Docs Preview workflow starts in base repo security context |
| 2026-07-14 ~06:58:42 | Malicious commit `3eab3ec` timestamped -- injected loaders into package source |
| 2026-07-14 ~07:05:42 | Push-triggered release workflow starts for generator-family packages |
| 2026-07-14 ~07:10 | Three generator-family packages (`@asyncapi/generator@3.3.1`, `@asyncapi/generator-components@0.7.1`, `@asyncapi/generator-helpers@1.1.1`) published with injected loaders |
| 2026-07-14 07:56-08:04 | Malicious workflows triggered for `@asyncapi/specs` on alpha branch |
| 2026-07-14 08:06:20 | `@asyncapi/specs@6.11.2-alpha.1` published to npm |
| 2026-07-14 08:14:00 | Malicious commit pushed to master branch |
| 2026-07-14 08:28:00 | Child commit created on master |
| 2026-07-14 08:30:09 | `@asyncapi/specs@6.11.2` stable version published |
| 2026-07-14 08:49:22 | First observed downstream fetch into Yarn cache |
| 2026-07-15 | Microsoft Threat Intelligence identifies and reports the compromise |

## Root Cause: GitHub Actions `pull_request_target` Workflow Abuse

The attacker submitted PR #2155 to the `asyncapi/generator` repository, targeting the `manual-netlify-preview.yml` workflow. This workflow used the `pull_request_target` trigger with an untrusted checkout -- a known dangerous pattern that runs workflow code from the pull request in the context of the base repository, granting access to the repository's secrets including the `GITHUB_TOKEN` and the `asyncapi-bot` personal access token (PAT).

The vulnerable workflow ran in the base repository's security context with a broad `GITHUB_TOKEN`, allowing the attacker to extract the `asyncapi-bot` PAT. The attacker also attempted credential theft from `rentry[.]co/elzotebo999`. With the stolen PAT, the attacker pushed malicious commits to auto-publish branches, which triggered the legitimate OIDC-based release workflows to publish the compromised packages with valid provenance signatures.

A proof-of-concept identifying this exact vulnerability had been submitted on April 29, 2026, and a remediation proposal was filed on May 17, 2026 -- but was still pending review at the time of the attack.

## Technical Analysis of the Malicious Payload

### 1. Stage 0: Import-Time Trigger (No Lifecycle Hooks)

The attack deliberately avoided declaring any npm lifecycle hooks (`preinstall`, `install`, `postinstall`) in `package.json`. This design choice defeated the common mitigation of running `npm install --ignore-scripts`. Instead, the malicious code executed immediately upon module **import** via `require()` or `import`, triggered during normal application startup, test execution, or CI/CD build steps.

Injection points per package:
- `@asyncapi/specs` -- `index.js`
- `@asyncapi/generator` -- `lib/templates/config/validator.js`
- `@asyncapi/generator-components` -- `lib/utils/ErrorHandling.js`
- `@asyncapi/generator-helpers` -- `src/utils.js`

All four injected files carried byte-identical payloads (SHA256: `8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c` for specs; unique hashes for each generator-family file). The loader spawned a detached, hidden child process:

```javascript
spawn('node', [payloadPath], {
   detached: true,
   stdio: 'ignore',
   windowsHide: true,
}).unref();
```

### 2. Stage 1b: IPFS Second-Stage Fetch

The spawned child process reconstructed an IPFS transport routine at runtime and fetched the second-stage payload using hard-coded Content Identifiers (CIDs):
- Primary CID (specs): `Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf`
- Generator-family CID: `QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9`

The fetched payload (`sync.js`, approximately 8.2 MB encrypted bundle) was written to an OS-specific directory masquerading as a legitimate Node.js installation:

| Platform | Drop Path |
|----------|-----------|
| Windows | `%LOCALAPPDATA%\NodeJS\sync.js` |
| Linux | `~/.local/share/NodeJS/sync.js` |
| macOS | `~/Library/Application Support/NodeJS/sync.js` |
| Fallback | `~/.config/NodeJS/sync.js` |

### 3. Stage 2: Three-Layer Encrypted Payload

The `sync.js` payload employed three layers of cryptographic protection:
1. **HKDF-SHA256** key derivation using master string `rt-vault-master-key-32b-aaaaaaaa` with info string `rt-file-key`
2. **AES-256-GCM** authenticated decryption with IV (first 12 bytes) and auth tag (last 16 bytes) extracted from the payload
3. **ROT-94de rotation** applied to the decrypted string as a final deobfuscation step
4. The resulting plaintext was executed via `eval()`

All key material was embedded statically within the loader.

### 4. Stage 3: Miasma RAT Activation

The decrypted payload activated the Miasma runtime with the following campaign identifiers:
- **Framework**: M-RED-TEAM v6.4
- **Campaign**: miasma-train-p1
- **Organization**: miasma-test-org

Core RAT capabilities included:
- Directory listing and file system traversal
- File retrieval and upload
- Remote shell execution
- Network proxying
- Data exfiltration
- mDNS service advertisement (`_miasma._tcp`)

### 5. C2 Infrastructure

**Primary C2 server**: `85.137.53[.]71`

| Service | Port | Function |
|---------|------|----------|
| C2 Command | 8080 | Beacon check-ins, command dispatch |
| File Upload | 8081 | Exfiltration of stolen data |
| Management | 8091 | Configuration and control |

**HTTP API endpoints observed:**
- `/api/v1/beacon`
- `/api/v1/file-result`
- `/api/v1/file-content/<cid>`

**Decentralized fallback channels:**
- Nostr protocol
- Ethereum blockchain (contract address: `0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710`)
- BitTorrent DHT (bootstrap nodes: `router.bittorrent[.]com`, `router.utorrent[.]com`, `dht.transmissionbt[.]com`)
- libp2p network
- IPFS network

### 6. Platform-Specific Persistence

#### Windows
- **Mechanism**: Registry Run key
- **Path**: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\miasma-monitor`
- **Process hiding**: `windowsHide: true` flag on spawned process

#### Linux
- **Mechanism**: systemd user unit
- **Service name**: `miasma-monitor.service`
- **Lock file**: `~/.config/.miasma/run/node.lock`

#### macOS
- **Mechanism**: Shell RC file injection
- **Targets**: `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`

### 7. Anti-Forensics / Evasion Techniques

- **No lifecycle hooks**: Bypasses `--ignore-scripts` and hook-focused security scanners
- **Import-time execution**: Triggers on module load rather than package installation
- **Detached process with stdio ignored**: Hides parent-child process relationship
- **windowsHide flag**: Prevents console window from appearing on Windows
- **Runtime IPFS transport reconstruction**: Avoids static analysis of download routines
- **Three-layer encryption**: Prevents static analysis of the second-stage payload
- **ROT-94de string rotation**: Additional obfuscation layer after decryption
- **Anti-analysis features**: VM detection, endpoint detection tool detection, Russian locale detection
- **Valid provenance signatures**: Published through legitimate OIDC workflows, generating trustworthy attestations
- **91,973 lines of obfuscated code**: Massive payload size complicates manual analysis

### 8. Credential Harvesting (Disabled in This Build)

Though flagged as disabled, the malware contained complete modules targeting:

**Environment variables (100+ names):**
- Source control: `GITHUB_TOKEN`, `GITLAB_TOKEN`
- npm/package managers: `NPM_TOKEN`, `NODE_AUTH_TOKEN`
- Cloud providers: `AWS_ACCESS_KEY`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, `GCLOUD_SERVICE_KEY`
- Container/K8s: `DOCKER_TOKEN`, `K8S_AUTH_TOKEN`
- Secrets managers: `DOPPLER_TOKEN`, `VAULT_TOKEN`
- AI platforms: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`

**Credential files:**
- `~/.npmrc`, `~/.aws/credentials`, `~/.kube/config`
- `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`
- `~/.vault-token`, `~/.netrc`
- `~/.docker/config.json`, `google_credentials.json`

**Additional disabled modules:** supply-chain propagation (self-spreading via stolen tokens), metamorphic generation, AI-tool poisoning, sandbox evasion, and browser password harvesting.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `85.137.53[.]71`)

### Package / Software Level

| Package / Component | Malicious Version | SHA256 | Description |
|---------------------|-------------------|--------|-------------|
| @asyncapi/specs | 6.11.2-alpha.1 | d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7 | Alpha pre-release with injected loader in `index.js` |
| @asyncapi/specs | 6.11.2 | 9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b | Stable release with byte-identical payload |
| @asyncapi/generator | 3.3.1 | bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4 | Loader in `lib/templates/config/validator.js` |
| @asyncapi/generator-components | 0.7.1 | 082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab | Loader in `lib/utils/ErrorHandling.js` |
| @asyncapi/generator-helpers | 1.1.1 | 34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1 | Loader in `src/utils.js` |

**Safe versions to pin:** `@asyncapi/specs` 6.11.1 or earlier, `@asyncapi/generator` 3.3.0, `@asyncapi/generator-components` 0.7.0, `@asyncapi/generator-helpers` 1.1.0.

### File System

| Platform | Path | SHA256 | Description |
|----------|------|--------|-------------|
| All | (injected index.js in specs) | 8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c | Obfuscated loader (specs both versions) |
| All | (injected validator.js in generator) | b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a | Obfuscated loader (generator) |
| All | (injected ErrorHandling.js in generator-components) | b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292 | Obfuscated loader (generator-components) |
| All | (injected utils.js in generator-helpers) | 6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71 | Obfuscated loader (generator-helpers) |
| All | sync.js wrapper | 24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168 | Encrypted Miasma runtime (~8.2 MB) |
| Windows | %LOCALAPPDATA%\NodeJS\sync.js | -- | Dropped Miasma payload |
| Linux | ~/.local/share/NodeJS/sync.js | -- | Dropped Miasma payload |
| macOS | ~/Library/Application Support/NodeJS/sync.js | -- | Dropped Miasma payload |
| All | ~/.config/NodeJS/sync.js | -- | Fallback drop location |
| All | ~/.config/.miasma/run/node.lock | -- | Runtime lock file |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 85.137.53[.]71:8080 | Primary C2 command/beacon server |
| IP | 85.137.53[.]71:8081 | File upload/exfiltration service |
| IP | 85.137.53[.]71:8091 | Management/configuration service |
| URL | hxxps://ipfs[.]io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf | IPFS second-stage payload (specs) |
| IPFS CID | Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf | Primary payload CID |
| IPFS CID | QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9 | Generator-family payload CID |
| Ethereum | 0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710 | Fallback C2 contract address |
| Domain | router.bittorrent[.]com | BitTorrent DHT bootstrap node |
| Domain | router.utorrent[.]com | BitTorrent DHT bootstrap node |
| Domain | dht.transmissionbt[.]com | BitTorrent DHT bootstrap node |
| URL | rentry[.]co/elzotebo999 | Credential theft staging URL |
| Email | npm-oidc-no-reply[at]github[.]com | Abused OIDC publisher identity |

### Behavioral

- Detached Node.js child processes spawned with `stdio: 'ignore'` and `windowsHide: true`, executing from `NodeJS/sync.js` paths
- mDNS service advertisements for `_miasma._tcp`
- IPFS gateway fetches for specific CIDs during package import
- Registry Run key creation for `miasma-monitor` on Windows
- systemd user service `miasma-monitor.service` creation on Linux
- Shell RC file modification (`~/.zshrc`, `~/.bashrc`, `~/.bash_profile`) on macOS
- HTTP beacon traffic to `/api/v1/beacon` endpoint
- Obfuscated JavaScript patterns containing `const _0x5af5e1`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Malicious code injected into five @asyncapi npm packages via stolen PAT |
| T1199 | Trusted Relationship | Exploited `pull_request_target` workflow to gain access to repository secrets |
| T1059.007 | JavaScript | Import-time execution of obfuscated JS loaders; `eval()` of decrypted payload |
| T1105 | Ingress Tool Transfer | Second-stage payload fetched from IPFS using hard-coded CIDs |
| T1547.001 | Registry Run Keys / Startup Folder | Windows persistence via `HKCU\...\Run\miasma-monitor` |
| T1543.002 | Systemd Service | Linux persistence via `miasma-monitor.service` user unit |
| T1546.004 | Unix Shell Configuration Modification | macOS persistence via `.zshrc`/`.bashrc`/`.bash_profile` injection |
| T1027 | Obfuscated Files or Information | Three-layer encryption (HKDF + AES-256-GCM + ROT-94de) and heavy JS obfuscation |
| T1036.005 | Match Legitimate Name or Location | Payload dropped in `NodeJS/` directory masquerading as legitimate Node.js |
| T1564.001 | Hidden Artifacts | Detached processes with ignored stdio, hidden windows |
| T1552.001 | Credentials In Files | Targeting of `.npmrc`, `.aws/credentials`, SSH keys, kubeconfig, etc. |
| T1552.007 | Container API | Targeting of Docker and Kubernetes credential files |
| T1555 | Credentials from Password Stores | Browser password harvesting module (disabled) |
| T1041 | Exfiltration Over C2 Channel | Data upload via port 8081 to C2 IP |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-GCM encrypted C2 communications |
| T1008 | Fallback Channels | Multiple decentralized fallback: Nostr, Ethereum, BitTorrent DHT, libp2p, IPFS |
| T1071.001 | Web Protocols | HTTP-based C2 beacon via `/api/v1/beacon` endpoint |

## Impact Assessment

- **Breadth**: Five malicious package versions across four packages with 2M+ combined weekly downloads; `@asyncapi/specs` is a transitive dependency of numerous downstream AsyncAPI tools
- **Depth**: Full RAT capabilities including remote shell, file exfiltration, credential harvesting (disabled in this build), and self-propagation modules
- **Exposure window**: Approximately 1-2 hours (first downstream fetch at 08:49:22 UTC, ~90 minutes after initial package publication)
- **Affected surfaces**: Developer workstations, CI/CD pipelines (including GitHub Actions runners), Docker/container builds, and any production services that resolved and imported compromised versions
- **Supply chain amplification**: Valid provenance signatures were generated, meaning provenance-checking tools would not have flagged the packages
- **Credential risk**: Any environment that imported the compromised packages should assume credential exposure

## Detection & Remediation

### Immediate Detection

```bash
# Check npm cache for compromised package hashes
find ~/.npm _cacache -name "*.tgz" 2>/dev/null | xargs sha256sum 2>/dev/null | grep -E "(d425e458|9b2e65db|bfaeb987|082d733d|34014776)"

# Check yarn cache
find ~/.cache/yarn -name "*.tgz" 2>/dev/null | xargs sha256sum 2>/dev/null | grep -E "(d425e458|9b2e65db|bfaeb987|082d733d|34014776)"

# Hunt for Miasma payload drop locations
ls -la "$LOCALAPPDATA/NodeJS/sync.js" 2>/dev/null
ls -la ~/.local/share/NodeJS/sync.js 2>/dev/null
ls -la ~/Library/Application\ Support/NodeJS/sync.js 2>/dev/null
ls -la ~/.config/NodeJS/sync.js 2>/dev/null
ls -la ~/.config/.miasma/ 2>/dev/null

# Check for persistence artifacts
# Windows: reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v miasma-monitor
# Linux:
systemctl --user status miasma-monitor.service 2>/dev/null
# macOS: grep -l "miasma\|NodeJS/sync" ~/.zshrc ~/.bashrc ~/.bash_profile 2>/dev/null

# Check for active C2 connections
ss -tnp | grep "85.137.53.71" 2>/dev/null
netstat -tn | grep "85.137.53.71" 2>/dev/null

# Check lockfiles for compromised versions
grep -rn '"@asyncapi/specs": "6.11.2"' package-lock.json yarn.lock 2>/dev/null
grep -rn '"@asyncapi/generator": "3.3.1"' package-lock.json yarn.lock 2>/dev/null
```

### Remediation

1. **Containment**: Block outbound connections to `85.137.53.71` on ports 8080, 8081, 8091 at the network perimeter
2. **Containment**: Block public IPFS gateways (`ipfs.io`, `dweb.link`, `cloudflare-ipfs.com`) if IPFS is not a business requirement
3. **Eradication**: Remove `sync.js` from all NodeJS masquerade directories and delete `~/.config/.miasma/`
4. **Eradication**: Remove persistence artifacts -- Windows Run key, Linux systemd service, macOS shell RC injections
5. **Eradication**: Pin to safe versions: `@asyncapi/specs@6.11.1`, `@asyncapi/generator@3.3.0`, `@asyncapi/generator-components@0.7.0`, `@asyncapi/generator-helpers@1.1.0`
6. **Eradication**: Purge npm and Yarn caches on all affected developer endpoints and build hosts
7. **Recovery**: Rotate ALL credentials from environments that imported compromised packages -- npm tokens, AWS keys, SSH keys, kubeconfig, Docker registry tokens, CI/CD secrets, API keys
8. **Recovery**: Rebuild affected CI/CD runners, Docker base images, and golden build environments from known-good baselines
9. **Recovery**: Rebuild affected projects from known-good dependency baselines

### Long-Term Hardening

- Update to npm CLI v11.10.0+ and enable the `min-release-age` feature to delay fetching freshly published versions
- Audit all GitHub Actions workflows for `pull_request_target` with untrusted checkout patterns
- Implement workflow approvals and protected environments for package publishing
- Monitor npm release provenance for anomalies in automated publication
- Enforce lockfile pinning and hash verification in CI/CD pipelines
- Consider dependency review tools that detect import-time code execution, not just lifecycle hooks

## Detection Rules

These detections target the AsyncAPI/Miasma supply chain compromise at the PoC/advisory-specific altitude. Sigma rules convert cleanly to both Splunk and CrowdStrike LogScale; Suricata rules compile; YARA rules compile and fire on source-published strings. Compiles does not equal fires -- verify each rule against your telemetry pipeline before production deployment.

### Sigma: Miasma sync.js Payload Drop

Detects creation of `sync.js` in `NodeJS` masquerade directories -- the distinctive drop path used by the Miasma malware across all platforms.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Field TargetFilename endswith is standard file_event. No encoding concerns (path strings, not hex). FP risk minimal: NodeJS/sync.js is a malware-specific masquerade path unlikely in legitimate use. Evasion: attacker could change drop path in future builds. -->
```yaml
title: AsyncAPI Supply Chain - Miasma sync.js Payload Drop
id: 8c1f4a2e-3b7d-4e9f-a5c6-1d8e0f2b3a4c
status: experimental
description: >
    Detects creation of sync.js in NodeJS masquerade directories used by the
    Miasma malware dropped via compromised AsyncAPI npm packages. The malware
    writes an encrypted payload to OS-specific paths under a NodeJS directory.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://securityaffairs.com/195395/security/asyncapi-npm-supply-chain-attack-malware-injected-into-packages-with-2-million-weekly-downloads.html
author: Actioner
date: 2026-07-16
tags:
    - attack.t1195.002
    - attack.t1105
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '\NodeJS\sync.js'
            - '/NodeJS/sync.js'
    condition: selection
falsepositives:
    - Legitimate applications creating files in a NodeJS directory with the exact name sync.js
level: high
```

### Sigma: Miasma C2 Connection to Known IP

Detects outbound network connections to the known Miasma C2 server `85.137.53[.]71` on ports 8080, 8081, or 8091.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. IP and port values are real (not defanged) in the rule. FP: extremely unlikely -- specific IP+port combination. IOC will age out if attacker rotates infrastructure. -->
```yaml
title: AsyncAPI Supply Chain - Miasma C2 Connection to Known IP
id: 7d2e5b3f-4c8a-4f1e-b6d7-2e9f0a1c3b5d
status: experimental
description: >
    Detects outbound network connections to the known Miasma C2 server IP
    85.137.53.71 used in the AsyncAPI npm supply chain compromise. The malware
    communicates on ports 8080 (C2), 8081 (upload), and 8091 (management).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://securityaffairs.com/195395/security/asyncapi-npm-supply-chain-attack-malware-injected-into-packages-with-2-million-weekly-downloads.html
author: Actioner
date: 2026-07-16
tags:
    - attack.t1071.001
    - attack.t1573.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '85.137.53.71'
        DestinationPort:
            - 8080
            - 8081
            - 8091
    condition: selection
falsepositives:
    - Unlikely - this is a known malicious C2 IP specific to this campaign
level: critical
```

### Sigma: Miasma Registry Persistence (Windows)

Detects creation of the `miasma-monitor` Run key used for Windows persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Registry path uses standard registry_set field TargetObject. FP: zero -- miasma-monitor is a unique malware identifier. -->
```yaml
title: AsyncAPI Supply Chain - Miasma Registry Persistence
id: 6e3f4c1d-5a9b-4d2e-c7e8-3f0a1b2c4d6e
status: experimental
description: >
    Detects creation of the miasma-monitor Run key used by the Miasma malware
    for persistence on Windows systems. The malware sets a registry value under
    HKCU Run to execute its payload on user logon.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026-07-16
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\CurrentVersion\Run\miasma-monitor'
    condition: selection
falsepositives:
    - Unlikely - miasma-monitor is a distinctive malware-specific registry value name
level: critical
```

### Sigma: Node.js Spawning Miasma Payload

Detects Node.js process execution with command-line references to the Miasma payload path or the distinctive obfuscated loader variable `_0x5af5e1`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Anchors on node binary + distinctive cmd args. _0x5af5e1 is a source-published obfuscation variable name. FP: near-zero for the path match; the obfuscation variable could theoretically appear in other obfuscated JS but is distinctive enough. -->
```yaml
title: AsyncAPI Supply Chain - Node.js Spawning Miasma Payload
id: 5f4a3d2c-6b8e-4c1f-d9a0-4e1b2c3d5f7a
status: experimental
description: >
    Detects Node.js process execution with command-line references to the Miasma
    payload sync.js in NodeJS masquerade directories, or the distinctive
    obfuscated loader pattern observed in the AsyncAPI supply chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026-07-16
tags:
    - attack.t1059.007
    - attack.t1036.005
logsource:
    category: process_creation
detection:
    selection_binary:
        Image|endswith:
            - '\node.exe'
            - '/node'
    selection_payload:
        CommandLine|contains:
            - 'NodeJS\sync.js'
            - 'NodeJS/sync.js'
            - 'const _0x5af5e1'
    condition: selection_binary and selection_payload
falsepositives:
    - Unlikely - the combination of node executing sync.js from a NodeJS masquerade path is highly specific
level: high
```

### Suricata: Miasma C2 Beacon and File Upload

Detects HTTP connections to the known Miasma C2 IP `85.137.53[.]71` targeting the `/api/v1/beacon` and `/api/v1/file-result` endpoints.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 "Configuration provided was successfully loaded." Dot-notation sticky buffers used (http.uri). Protocol http matches buffers. FP: extremely low -- specific IP + URI path. -->
```suricata
alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma C2 Beacon to Known IP"; flow:established,to_server; http.uri; content:"/api/v1/beacon"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-16; sid:2200001; rev:1;)

alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma File Upload to Known IP"; flow:established,to_server; http.uri; content:"/api/v1/file-result"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-16; sid:2200002; rev:1;)
```

### Snort: Miasma C2 Beacon and File Upload

Detects HTTP connections to the known Miasma C2 IP targeting the `/api/v1/beacon` and `/api/v1/file-result` endpoints.
**Status:** compile ⚠️ uncompiled (structural check only -- snort not installed) · confidence: high
<!-- audit: snort binary not available; structural check passed (underscore sticky buffers, semicolons, flow, sid/rev/classtype present, http protocol with http_uri buffer). -->
```snort
alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma C2 Beacon to Known IP"; flow:established, to_server; http_uri; content:"/api/v1/beacon", fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created 2026-07-16; sid:2100001; rev:1;)

alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma File Upload to Known IP"; flow:established, to_server; http_uri; content:"/api/v1/file-result", fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created 2026-07-16; sid:2100002; rev:1;)
```

### YARA: Miasma Loader Strings

Detects the Miasma malware loader by matching distinctive encryption key material (`rt-vault-master-key-32b-aaaaaaaa`), campaign identifiers (`miasma-train-p1`, `miasma-test-org`), IPFS CIDs, and payload path patterns.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos.txt fired SupplyChain_AsyncAPI_Miasma_Loader (matched $key1, $campaign1, $campaign2, $ipfs1). yara neg.txt silent. Positive constructed from source-published strings (HKDF master key, campaign names, IPFS CID). FP: near-zero -- HKDF master key string is 32 chars and campaign-specific. -->
```yara
rule SupplyChain_AsyncAPI_Miasma_Loader
{
    meta:
        description = "Detects Miasma malware loader injected into AsyncAPI npm packages via distinctive encryption key material, campaign identifiers, and IPFS CIDs"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "critical"

    strings:
        $key1 = "rt-vault-master-key-32b-aaaaaaaa" ascii
        $key2 = "rt-file-key" ascii
        $campaign1 = "miasma-train-p1" ascii
        $campaign2 = "miasma-test-org" ascii
        $campaign3 = "M-RED-TEAM" ascii
        $ipfs1 = "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf" ascii
        $ipfs2 = "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9" ascii
        $path_win = "NodeJS\\sync.js" ascii
        $path_unix = "NodeJS/sync.js" ascii
        $lock = ".miasma/run/node.lock" ascii
        $obf = "const _0x5af5e1" ascii

    condition:
        filesize < 10MB and (
            any of ($key*) or
            2 of ($campaign*) or
            any of ($ipfs*) or
            ($obf and any of ($path*)) or
            ($lock and any of ($path*))
        )
}

rule SupplyChain_AsyncAPI_Miasma_Payload_Hashes
{
    meta:
        description = "Detects known SHA256 injected file content from the AsyncAPI npm supply chain compromise by matching distinctive loader strings"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        hash1 = "8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c"
        hash2 = "b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a"
        hash3 = "b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292"
        hash4 = "6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71"
        hash5 = "24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168"
        severity = "critical"

    strings:
        $mdns = "_miasma._tcp" ascii
        $svc = "miasma-monitor" ascii
        $vault = "rt-vault-master" ascii
        $spawn = "windowsHide" ascii
        $detach = "detached" ascii

    condition:
        filesize < 10MB and
        $svc and $vault and
        ($spawn or $detach or $mdns)
}
```

## Microsoft Defender Detections

Microsoft has published the following detection names for this threat:

**Antivirus signatures:**
- `Trojan:JS/MiasmStealer.SC`
- `Trojan:Script/Supychain.A`
- `Trojan:JS/SpawnLoader.MKV!MTB`
- `Trojan:JS/VaultLoader.MJZ!MTB`

**Behavioral detections:**
- Suspicious Node.js process behavior
- Suspicious Node.js script execution
- Anomaly detected in ASEP registry
- Suspicious modification of shell profile
- Suspicious Linux service created
- Suspicious detached Node.js process spawn
- IPFS retrieval activity

## Lessons Learned

1. **Import-time execution is the new install-time execution.** The `--ignore-scripts` mitigation and hook-focused scanners are insufficient when malicious code executes at `require()`/`import` time. Security tooling must evolve to detect suspicious code patterns in module entry points, not just lifecycle hooks.

2. **`pull_request_target` remains a critical GitHub Actions anti-pattern.** Despite years of documented risk, this workflow trigger with untrusted checkout continues to create exploitable attack surfaces. Organizations must audit all workflows for this pattern and implement separation of untrusted builds from secret-receiving steps.

3. **Valid provenance does not equal trusted provenance.** The attacker published packages through legitimate OIDC-based release workflows, generating valid provenance signatures. Provenance attestation alone is insufficient -- organizations need anomaly detection around publication timing, commit authorship, and release patterns.

4. **Decentralized fallback C2 raises the bar for takedown.** The use of Nostr, Ethereum, BitTorrent DHT, libp2p, and IPFS as fallback communication channels means that taking down a single C2 IP is insufficient to fully disrupt the malware's connectivity.

5. **Disabled modules are a staging indicator.** The presence of complete but disabled credential harvesting, supply-chain propagation, and AI-tool poisoning modules suggests this was either a test deployment or the attacker intended to enable these capabilities after establishing a broader foothold.

## Sources

- [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/) -- Primary technical analysis with full attack chain, IOCs, MITRE mappings, and remediation guidance
- [Hackread / Upwind Research](https://hackread.com/upwind-supply-chain-compromise-asyncapi-npm-packages/) -- Limited additional context; references OX Security disclosure and Miasma string analysis
- [Security Affairs](https://securityaffairs.com/195395/security/asyncapi-npm-supply-chain-attack-malware-injected-into-packages-with-2-million-weekly-downloads.html) -- Supplementary details including Ethereum contract address, BitTorrent DHT bootstrap nodes, and 2M+ weekly download impact figure
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/-asyncapi-npm-packages-infected-with-credential-stealing-malware/) -- Source returned HTTP 403; could not be verified at time of analysis

---
*Report generated by Actioner*
