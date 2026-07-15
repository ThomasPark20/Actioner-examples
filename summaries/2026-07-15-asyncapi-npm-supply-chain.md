# Technical Analysis Report: Compromised AsyncAPI npm Packages (2026-07-15)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-15
Version: DRAFT

## Executive Summary

On July 14, 2026, an attacker compromised two repositories in the AsyncAPI GitHub organization and published five backdoored npm package versions under the `@asyncapi` namespace, collectively accounting for over 2 million weekly downloads. The attacker exploited a misconfigured `pull_request_target` GitHub Actions workflow to steal a privileged Personal Access Token (PAT) belonging to `asyncapi-bot`, then used it to push malicious commits that triggered the project's own legitimate release pipelines. The resulting packages carried valid OIDC provenance attestations, bypassing standard supply chain verification. The payload is a multi-stage loader that ultimately delivers the **Miasma RAT** (campaign `miasma-train-p1`), a 744-module command framework with six independent C2 channels (HTTP, Nostr, IPFS, BitTorrent DHT, libp2p, Ethereum smart contract), credential harvesting for 300+ file types, AI tool poisoning capabilities, and systemd/launchd/crontab/Registry persistence. All five malicious versions were unpublished within 2-4 hours of publication.

## Background: AsyncAPI and npm Trusted Publishing

AsyncAPI is a widely adopted open-source specification and tooling ecosystem for event-driven APIs. The `@asyncapi` npm namespace packages (`generator`, `generator-helpers`, `generator-components`, `specs`) are foundational dependencies pulled into build pipelines and developer workstations across the Node.js ecosystem. npm's GitHub OIDC "trusted publisher" integration allows GitHub Actions workflows to publish packages with cryptographically signed provenance attestations, establishing a chain of trust from source commit to published artifact. This attack subverted that chain at the source repository level, producing packages that appeared legitimate under provenance verification.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-14 ~06:30 | Attacker opens 37 pull requests to asyncapi/generator; PR #2155 exploits a misconfigured `pull_request_target` workflow to exfiltrate the `asyncapi-bot` PAT |
| 2026-07-14 06:58:42 | Malicious commit `3eab3ec9304aa26081358330491d3cfeb55cc245` pushed to `next` branch of asyncapi/generator under identity "Your Name \<you@example.com\>" |
| 2026-07-14 07:10:42 | `@asyncapi/generator-helpers@1.1.1` published via `release-with-changesets.yml` |
| 2026-07-14 07:10:44 | `@asyncapi/generator-components@0.7.1` published |
| 2026-07-14 07:10:48 | `@asyncapi/generator@3.3.1` published |
| 2026-07-14 07:04-07:56 | Attacker pushes malicious commits to asyncapi/spec-json-schemas `master` branch (commits `61a930fca724`, `36269ce81837`) |
| 2026-07-14 08:06:20 | `@asyncapi/specs@6.11.2-alpha.1` published via `if-nodejs-release.yml` |
| 2026-07-14 08:28:02 | Final malicious commit `689f5b96693ab1f82a825b6d7c4ee566b0afc4c6` pushed |
| 2026-07-14 08:30:09 | `@asyncapi/specs@6.11.2` published |
| 2026-07-14 11:12-11:18 | All five malicious versions unpublished (exposure window: 2h 48m to 4h 2m) |

## Root Cause: GitHub Actions `pull_request_target` Misconfiguration

The attacker exploited a known class of GitHub Actions vulnerability -- a `pull_request_target`-triggered workflow that checks out and executes code from the untrusted pull request head. This is the same vulnerability pattern behind the March 2025 `tj-actions/changed-files` incident. By opening 37 pull requests as noise camouflage, the attacker embedded PR #2155 which triggered the vulnerable workflow, exfiltrating the `asyncapi-bot` PAT -- a service account with push access across the AsyncAPI organization. The vulnerable workflow pattern had been internally flagged 58 days prior, with a fix sitting unmerged. No npm token was stolen; the attacker leveraged legitimate CI/CD pipelines to publish with valid OIDC provenance.

## Technical Analysis of the Malicious Payload

### 1. Stage 1: Obfuscated Dropper (Embedded in Package Source)

The attacker injected obfuscated JavaScript into core library files within each package. Unlike typical npm supply chain attacks, no `preinstall`/`postinstall` hooks were used -- the code executes when the module is `require()`'d during normal usage, bypassing npm v12 install-script restrictions.

**Infected files:**
- `packages/helpers/src/utils.js` (generator-helpers)
- `packages/components/src/utils/ErrorHandling.js` (generator-components)
- `apps/generator/lib/templates/config/validator.js` (generator)
- `index.js` (specs)

The dropper uses obfuscator.io-style obfuscation with hex-prefixed variable names (`_0x1dd48b`, `_0x2d89`), a base64 string table with `decodeURIComponent`, and an array-rotation cipher. In the `@asyncapi/specs` variant, the payload was concealed with ~1000 leading spaces to hide it in diffs. The deobfuscated code spawns a detached, hidden Node.js process:

```javascript
spawn("node", ["-e", stage2], {
  detached: true,
  stdio: "ignore",
  windowsHide: true
})
child.unref()
```

### 2. Stage 2: IPFS Downloader

The detached process downloads an encrypted payload from IPFS gateways. Two IPFS CIDs were used across the two repository attacks:

- Generator packages: `QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9`
- Specs package: `Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf`

The payload is written to platform-specific directories as `sync.js`:

| Platform | Drop Path |
|----------|-----------|
| Windows | `%LOCALAPPDATA%\NodeJS\sync.js` |
| macOS | `~/Library/Application Support/NodeJS/sync.js` |
| Linux | `~/.local/share/NodeJS/sync.js` |
| Fallback | `~/.config/node/sync.js` |

### 3. Stage 3: Encrypted Miasma RAT Loader (sync.js)

The downloaded `sync.js` file (8.25 MB, SHA-256: `24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168`) is an AES-256-GCM encrypted JavaScript bundle. The decryption chain uses HKDF-SHA256 with hardcoded key material:

- Master key label: `rt-vault-master-key-32b-aaaaaaaa`
- Baked key derivation: HKDF(sha256, master, "", `rt-baked-key`, 32)
- File key derivation: HKDF(sha256, master, `rt-file-key-material-v1`, `rt-file-key`, 32)
- Additional obfuscation: ROT94 character shift (delta=4, range 33-126)

The decrypted payload is 3.09 MB of JavaScript (SHA-256: `9e214f38537e69bf51c7fa1ddd35ae495e9cb897231ec010baf9e4f29407ee9a`) containing 744 modules forming the Miasma tasking framework, identified by campaign name `miasma-train-p1`.

### 4. C2 Infrastructure

The Miasma RAT implements six independent C2 channels for resilience:

| Channel | Endpoint | Purpose |
|---------|----------|---------|
| HTTP REST | `85.137.53.71:8080` (AS43641, Netherlands) | Primary command beacon (`/api/v1/beacon`) |
| HTTP Upload | `85.137.53.71:8081` | Credential exfiltration (`/api/v1/upload`) |
| HTTP Proxy | `85.137.53.71:8091` | Proxy management |
| Nostr Relay | `wss://relay.damus.io`, `wss://relay.nostr.com/` | Decentralized C2 fallback |
| BitTorrent DHT | `router.bittorrent.com:6881`, `dht.transmissionbt.com:6881` | P2P rendezvous |
| Ethereum | Contract `0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710` | Blockchain dead-drop |

Additional channels include IPFS, libp2p GossipSub mesh, and LAN mDNS discovery. The HTTP C2 exposes endpoints at `/api/v1/beacon`, `/api/v1/file-result`, and `/api/v1/file-content/<cid>`.

### 5. RAT Capabilities and Command Table

The Miasma framework supports the following commands: Propagate, CollectData, UpdateMutationSeed, UpdatePayload, ManualSelfDestruct, BatchDispatch, FileList/FileGet/FilePut/FileDelete, ShellExec, and UpdateBeaconInterval.

**Credential harvesting** targets 300+ file types including: npm tokens (`~/.npmrc`), GitHub tokens (`GITHUB_TOKEN`, `~/.config/gh`), PyPI tokens, SSH keys, AWS credentials (`~/.aws/credentials`), Docker/Kubernetes credentials, browser saved passwords and cookies (Chrome, Brave, Firefox, Edge), macOS Keychain entries, and cryptocurrency wallets (Bitcoin, Electrum, Ethereum, Solana).

**AI tool poisoning** (marked simulation-only in this deployment): targets Claude Code (SessionStart hook), VS Code tasks, Gemini CLI, and Cursor via injected configuration files.

**Worm propagation** modules exist for npm, PyPI, RubyGems, and Cargo but are disabled in this deployment (`propagate: false`, `npm: false`). The configuration shows `maxGen: 4` and a `CANARY` deployment strategy (5% initial, then waves of 100).

### 6. Anti-Forensics / Evasion Techniques

- **EDR detection**: Terminates on systems running CrowdStrike, SentinelOne, Microsoft Defender, CarbonBlack, Cylance, Osquery, Tanium, or Qualys
- **Locale check**: Aborts on Russian-language systems
- **Sandbox evasion**: Detects virtual environments and sandboxes
- **Dead man's switch**: The `safe-wipe.js` module monitors stolen tokens and triggers directory wipe if revoked (disabled in this deployment)
- **State concealment**: Uses `.cache/mesa_shader_cache/` for encrypted state files, mimicking GPU shader cache

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `85[.]137[.]53[.]71`)

### Package / Software Level

| Package / Component | Malicious Version | SHA-256 |
|---------------------|-------------------|---------|
| @asyncapi/generator-helpers | 1.1.1 | 34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1 |
| @asyncapi/generator-components | 0.7.1 | 082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab |
| @asyncapi/generator | 3.3.1 | bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4 |
| @asyncapi/specs | 6.11.2-alpha.1 | d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7 |
| @asyncapi/specs | 6.11.2 | 9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | (infected source) `src/utils.js` | 6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71 | Dropper in generator-helpers |
| All | (infected source) `lib/utils/ErrorHandling.js` | b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292 | Dropper in generator-components |
| All | (infected source) `lib/templates/config/validator.js` | b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a | Dropper in generator |
| All | (infected source) `index.js` | 8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c | Dropper in specs |
| All | Stage 2 downloader (decoded) | 550af477c12192a22f5c9edb9c8081c0a789b3a1a2992a7ecb157cca1c975e10 | Deobfuscated IPFS downloader |
| All | sync.js (encrypted) | 24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168 | Encrypted Miasma loader (8.25 MB) |
| All | Miasma payload (decrypted) | 9e214f38537e69bf51c7fa1ddd35ae495e9cb897231ec010baf9e4f29407ee9a | Decrypted RAT framework (3.09 MB) |
| All | Baked configuration | 9f1a709310824f9110c6203d861a721ebefba8b204a8657057fe57efb961c850 | Miasma RAT configuration blob |
| Windows | `%LOCALAPPDATA%\NodeJS\sync.js` | (see above) | Stage 2 drop path |
| macOS | `~/Library/Application Support/NodeJS/sync.js` | (see above) | Stage 2 drop path |
| Linux | `~/.local/share/NodeJS/sync.js` | (see above) | Stage 2 drop path |
| Linux | `~/.config/systemd/user/miasma-monitor.service` | -- | Systemd persistence unit |
| Linux | `~/.config/.miasma/run/node.lock` | -- | Runtime lock file |
| Linux | `~/.cache/mesa_shader_cache/gl_cache.bin` | -- | Encrypted state (disguised as shader cache) |
| Linux | `~/.cache/.sys_cache/.diag.enc` | -- | Encrypted diagnostic/state file |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `85[.]137[.]53[.]71:8080` | Primary C2 beacon (HTTP REST) |
| IP | `85[.]137[.]53[.]71:8081` | Credential exfiltration upload |
| IP | `85[.]137[.]53[.]71:8091` | C2 proxy management |
| URL | `hxxps://ipfs[.]io/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9` | Stage 2 payload (generator packages) |
| URL | `hxxps://ipfs[.]io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` | Stage 2 payload (specs package) |
| Domain | `relay[.]damus[.]io` | Nostr C2 relay |
| Domain | `relay[.]nostr[.]com` | Nostr C2 relay |
| Domain | `router[.]bittorrent[.]com:6881` | BitTorrent DHT rendezvous |
| Domain | `dht[.]transmissionbt[.]com:6881` | BitTorrent DHT rendezvous |
| Domain | `ethereum-rpc[.]publicnode[.]com` | Ethereum RPC for smart contract C2 |
| Ethereum | `0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710` | Smart contract dead-drop |

### Behavioral

- Detached `node -e` child process with suppressed stdio and `windowsHide:true`, launched during module `require()` (not install)
- IPFS gateway HTTPS requests during npm package load (anomalous in build/dev context)
- Nostr WebSocket connections and BitTorrent DHT bootstrap traffic from Node.js processes in development/build environments
- Systemd user service `miasma-monitor.service` with `Restart=always` and nohup-wrapped Node.js execution
- File writes to `~/.cache/mesa_shader_cache/` from Node.js processes (GPU shader cache path used for state concealment)
- Git commits from identity `Your Name <you@example.com>` with GitHub user `invalid-email-address`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Backdoored official @asyncapi npm packages via compromised CI/CD pipeline |
| T1078.004 | Valid Accounts: Cloud Accounts | Stole asyncapi-bot PAT via GitHub Actions exploit to push commits |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Multi-stage JavaScript payload execution via Node.js |
| T1027 | Obfuscated Files or Information | obfuscator.io string arrays, AES-256-GCM encryption, ROT94 cipher |
| T1105 | Ingress Tool Transfer | Second-stage payload downloaded from IPFS gateway |
| T1543.002 | Create or Modify System Process: Systemd Service | miasma-monitor.service for Linux persistence |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Windows Registry autostart persistence |
| T1547.011 | Boot or Logon Autostart Execution: Plist Modification | macOS launchd plist persistence |
| T1053.003 | Scheduled Task/Job: Cron | Crontab-based persistence on Linux |
| T1555 | Credentials from Password Stores | Browser credential extraction (Chrome, Brave, Firefox, Edge) |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvesting SSH keys, npm/GitHub/AWS tokens, kubeconfig |
| T1539 | Steal Web Session Cookie | Browser cookie extraction across profiles |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP C2 beacon to 85.137.53.71:8080 |
| T1571 | Non-Standard Port | C2 on ports 8080, 8081, 8091 |
| T1102 | Web Service | Nostr relays, IPFS, Ethereum smart contract as alternative C2 |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | VM detection, EDR detection, Russian locale check |
| T1041 | Exfiltration Over C2 Channel | Credential upload to 85.137.53.71:8081 |

## Impact Assessment

**Breadth:** The five compromised package versions see over 2 million combined weekly downloads across `@asyncapi/generator`, `@asyncapi/generator-helpers`, `@asyncapi/generator-components`, and `@asyncapi/specs`. However, the short exposure window (2h 48m to 4h 2m) limits actual installation counts. The malware executes on `require()` rather than install, meaning only systems that actually loaded the modules during the exposure window are affected -- downstream consumers with lockfiles pinned to safe versions were not impacted.

**Depth:** The Miasma RAT's credential harvesting scope (300+ file types) and persistence mechanisms make compromised systems a severe risk for lateral movement, credential reuse, and ongoing access. The AI tool poisoning capabilities (though marked simulation-only) represent an emerging threat vector.

**Stealth:** Valid OIDC provenance attestations on the malicious packages defeat standard supply chain verification. Execution on `require()` rather than install bypasses npm install-script monitoring. The use of `mesa_shader_cache` paths for state storage and six independent C2 channels (including blockchain and P2P) adds resilience against takedown.

## Detection & Remediation

### Immediate Detection

Check for the presence of Miasma drop files:

```bash
# Linux
ls -la ~/.local/share/NodeJS/sync.js 2>/dev/null
ls -la ~/.config/systemd/user/miasma-monitor.service 2>/dev/null
ls -la ~/.config/.miasma/ 2>/dev/null
ls -la ~/.cache/mesa_shader_cache/gl_cache.bin 2>/dev/null

# macOS
ls -la ~/Library/Application\ Support/NodeJS/sync.js 2>/dev/null

# Windows (PowerShell)
Test-Path "$env:LOCALAPPDATA\NodeJS\sync.js"
```

Check lockfiles for compromised versions:

```bash
grep -rE '@asyncapi/(generator|generator-helpers|generator-components|specs)' package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null | grep -E '(3\.3\.1|1\.1\.1|0\.7\.1|6\.11\.2)'
```

Check network logs for C2 connections:

```bash
# Check DNS/netflow for the C2 IP
grep '85.137.53.71' /var/log/syslog /var/log/messages 2>/dev/null
```

### Remediation

1. **Delete compromised packages and lockfiles**: Remove `node_modules/`, regenerate lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) pinned to safe versions (`@asyncapi/generator@3.3.0`, `@asyncapi/generator-helpers@1.1.0`, `@asyncapi/generator-components@0.7.0`, `@asyncapi/specs@6.11.1`)
2. **Remove Miasma artifacts**: Delete sync.js drop files, miasma-monitor.service, `.miasma/` directories, and `mesa_shader_cache` state files from all affected systems
3. **Rotate ALL credentials**: npm tokens, GitHub PATs, SSH keys, AWS credentials, Docker/Kubernetes configs, browser passwords -- any credential accessible from affected workstations or CI/CD runners
4. **Audit CI/CD runners**: Treat any GitHub Actions runner or build system that imported affected packages during the exposure window as compromised; rebuild from clean images
5. **Review AI tool configurations**: Check for injected hooks in `.claude/settings.json`, `.vscode/tasks.json`, `.cursor/rules/`, `.gemini/settings.json`

### Long-Term Hardening

- Audit `pull_request_target` workflows for untrusted code checkout patterns; use `workflow_run` or restrict checkout to the base branch
- Pin GitHub Actions to full commit SHAs, not tags
- Monitor npm package provenance attestations for anomalous commit authors or unexpected branch sources
- Deploy runtime egress controls on CI/CD runners to detect unexpected network connections (IPFS gateways, Nostr relays, BitTorrent DHT)
- Use tools like StepSecurity Harden-Runner to monitor and restrict outbound network access from GitHub Actions workflows

## Detection Rules

These detections target the specific infrastructure, file artifacts, and persistence mechanisms of the AsyncAPI Miasma RAT campaign. PoC/advisory-specific altitude (default); Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Snort and Suricata compilers are not installed in this environment -- those rules received structural review only.

### Sigma: Network Connection to AsyncAPI Miasma C2 Server

Detects outbound connections to the primary Miasma C2 IP `85.137.53.71` used for beacon, exfiltration, and proxy management.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to proxy blocking MITRE ATT&CK data fetch (network issue, not rule syntax). sigma convert splunk exit 0, log_scale exit 0. IP is a dedicated C2 with no known legitimate services (AS43641 NL). FP risk minimal. Evasion: attacker rotates IP — pair with file/persistence rules. -->
```yaml
title: Network Connection to AsyncAPI Miasma C2 Server
id: cb58f8c3-832d-4fc4-836f-de2294d02c77
status: experimental
description: Detects outbound network connections to IP 85.137.53.71 used as the primary C2 server in the AsyncAPI npm supply chain attack delivering the Miasma RAT framework.
references:
    - https://socket.dev/blog/asyncapi-supply-chain-attack
    - https://www.stepsecurity.io/blog/compromised-next-branch-pushes-malicious-asyncapi-generator-generator-helpers-and-generator-components-to-npm
author: Actioner
date: 2026/07/15
tags:
    - attack.t1071.001
    - attack.t1571
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '85.137.53.71'
    condition: selection
falsepositives:
    - Unlikely - dedicated C2 infrastructure with no known legitimate services
level: critical
```

### Sigma: Miasma RAT sync.js Payload File Drop

Detects creation of `sync.js` in the Windows `NodeJS` AppData directory, the Miasma stage-2 drop path.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0, log_scale exit 0. Path pattern \NodeJS\sync.js is highly specific — no known legitimate software uses this exact convention. Linux/macOS variants use different paths (see IOC table); additional platform-specific rules could be added. -->
```yaml
title: Miasma RAT sync.js Payload File Drop
id: 6a5ab0e0-f62d-4bb6-8147-5e79d771d41f
status: experimental
description: Detects creation of the sync.js payload file in the NodeJS application data directory, a hallmark of the AsyncAPI Miasma RAT second-stage loader.
references:
    - https://socket.dev/blog/asyncapi-supply-chain-attack
    - https://www.stepsecurity.io/blog/compromised-next-branch-pushes-malicious-asyncapi-generator-generator-helpers-and-generator-components-to-npm
author: Actioner
date: 2026/07/15
tags:
    - attack.t1105
    - attack.t1059.007
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\NodeJS\sync.js'
    condition: selection
falsepositives:
    - Custom Node.js applications using a directory named NodeJS in AppData (unlikely)
level: high
```

### Sigma: Miasma RAT Systemd Persistence Service Creation

Detects creation of the `miasma-monitor.service` systemd user unit used for persistence on Linux.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0, log_scale exit 0. Service name "miasma-monitor" is unique to this malware with no known benign software using it. Requires file event telemetry on Linux (e.g., auditd with file watches or Sysmon for Linux). -->
```yaml
title: Miasma RAT Systemd Persistence Service Creation
id: 9a655001-3e44-4606-8cc8-d636e6242287
status: experimental
description: Detects creation of the miasma-monitor.service systemd user service file used for persistence by the Miasma RAT delivered via compromised AsyncAPI npm packages.
references:
    - https://socket.dev/blog/asyncapi-supply-chain-attack
    - https://www.stepsecurity.io/blog/compromised-next-branch-pushes-malicious-asyncapi-generator-generator-helpers-and-generator-components-to-npm
author: Actioner
date: 2026/07/15
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/miasma-monitor.service'
    condition: selection
falsepositives:
    - Legitimate software named miasma-monitor (none known)
level: critical
```

### Snort: AsyncAPI Miasma RAT HTTP C2 Beacon

Detects HTTP requests to the Miasma C2 beacon endpoint at `85.137.53.71/api/v1/beacon` and upload endpoint.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural check passed (http service, flow established, http_uri sticky buffer, fast_pattern set, valid SID range 2100xxx, semicolons terminate all options). Install via /actioner:setup for full compile check. -->
```snort
alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma RAT HTTP C2 Beacon"; flow:established,to_server; http_uri; content:"/api/v1/beacon", fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/asyncapi-supply-chain-attack; metadata:author Actioner, created 2026-07-15; sid:2100101; rev:1;)
alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma RAT HTTP C2 Upload"; flow:established,to_server; http_uri; content:"/api/v1/upload", fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/asyncapi-supply-chain-attack; metadata:author Actioner, created 2026-07-15; sid:2100102; rev:1;)
```

### Suricata: AsyncAPI Miasma RAT HTTP C2 Beacon

Detects HTTP requests to the Miasma C2 beacon and upload endpoints using Suricata dot-notation buffers.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural check passed (http protocol, dot-notation http.uri buffer, flow established, fast_pattern, valid SID range 2200xxx, metadata with author and created_at, semicolons terminate all options). Install via /actioner:setup for full compile check. -->
```suricata
alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma RAT HTTP C2 Beacon"; flow:established,to_server; http.uri; content:"/api/v1/beacon"; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/asyncapi-supply-chain-attack; metadata:author Actioner, created_at 2026-07-15; sid:2200101; rev:1;)
alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma RAT HTTP C2 Upload"; flow:established,to_server; http.uri; content:"/api/v1/upload"; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/asyncapi-supply-chain-attack; metadata:author Actioner, created_at 2026-07-15; sid:2200102; rev:1;)
```

### YARA: Miasma RAT Decrypted Payload

Detects the decrypted Miasma RAT payload via campaign identifier (`miasma-train-p1`), hardcoded HKDF key material, and command table strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Fired on positive sample containing published campaign ID and key material strings; quiet on benign Node.js file. Strings sourced from Socket.dev deobfuscation of the decrypted 3.09MB payload (SHA-256 9e214f38...). Campaign name + key material combination is unique to Miasma. FP: near-zero — these strings do not appear in any legitimate software. Evasion: attacker changes key labels in future variants, but campaign ID and command table provide secondary anchors. -->
```yara
rule Malware_Miasma_RAT_AsyncAPI_Payload
{
    meta:
        description = "Detects the Miasma RAT payload delivered via compromised AsyncAPI npm packages, based on campaign identifiers and cryptographic key material"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://socket.dev/blog/asyncapi-supply-chain-attack"
        hash = "9e214f38537e69bf51c7fa1ddd35ae495e9cb897231ec010baf9e4f29407ee9a"
        severity = "critical"

    strings:
        $campaign = "miasma-train-p1" ascii
        $key1 = "rt-vault-master-key-32b-aaaaaaaa" ascii
        $key2 = "rt-baked-key" ascii
        $key3 = "rt-file-key-material-v1" ascii
        $key4 = "rt-file-key" ascii
        $svc = "miasma-monitor" ascii
        $cmd1 = "CollectData" ascii
        $cmd2 = "ManualSelfDestruct" ascii
        $cmd3 = "BatchDispatch" ascii
        $cmd4 = "UpdateBeaconInterval" ascii

    condition:
        filesize < 10MB and
        ($campaign or 2 of ($key*)) and
        (1 of ($cmd*) or $svc)
}
```

### YARA: AsyncAPI Malicious Dropper (IPFS CID)

Detects the first-stage dropper injected into AsyncAPI packages via the hardcoded IPFS content identifiers used for payload delivery.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Fired on positive sample containing published IPFS CID; quiet on benign JS file. CIDs QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9 and Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf are unique to this campaign's IPFS-hosted payloads. The alternative condition ($ipfs + $unref + spawn/detach/hide) catches variants with different CIDs using the same dropper pattern. FP: CID match is near-zero; pattern match slightly broader but still very specific to malicious spawn patterns. -->
```yara
rule Malware_Miasma_AsyncAPI_Dropper
{
    meta:
        description = "Detects the obfuscated first-stage dropper injected into compromised AsyncAPI npm packages"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://socket.dev/blog/asyncapi-supply-chain-attack"
        hash = "6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71"
        severity = "high"

    strings:
        $spawn = "spawn(\"node\",[" ascii
        $detach = "detached:true" ascii nocase
        $hide = "windowsHide:true" ascii nocase
        $unref = ".unref()" ascii
        $ipfs = "ipfs.io/ipfs/Qm" ascii
        $cid1 = "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9" ascii
        $cid2 = "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf" ascii

    condition:
        filesize < 500KB and
        (any of ($cid*)) or
        ($ipfs and $unref and ($spawn or $detach or $hide))
}
```

## Lessons Learned

1. **Trusted publishing is only as strong as repository access controls.** The npm OIDC provenance model trusts the source repository. When an attacker gains push access, the entire trust chain is compromised -- published packages carry valid, verifiable provenance attestations that defeat existing verification tooling.

2. **`pull_request_target` remains a systemic risk in the GitHub Actions ecosystem.** This is the same vulnerability class that enabled the `tj-actions/changed-files` compromise in March 2025. The pattern of checking out and executing untrusted PR code with access to repository secrets continues to create high-impact attack surfaces. The vulnerable workflow had been flagged 58 days prior with a fix unmerged.

3. **Execution-on-import bypasses install-script monitoring.** By embedding malicious code in library source files rather than `preinstall`/`postinstall` hooks, the attacker evaded npm v12 install-script restrictions and most supply chain security tools that focus on lifecycle scripts. Security tooling must expand to cover runtime import-time behavior.

4. **Multi-channel C2 with blockchain and P2P fallbacks creates resilience against takedown.** The Miasma framework's use of Nostr relays, BitTorrent DHT, Ethereum smart contracts, and IPFS alongside traditional HTTP C2 means that disrupting any single channel does not neutralize the implant. Defenders should monitor for anomalous protocol usage (Nostr WebSocket, BitTorrent DHT) from development and build environments.

## Sources

- [Socket.dev - Compromised npm Packages in the AsyncAPI Namespace](https://socket.dev/blog/asyncapi-supply-chain-attack) — Primary technical analysis with full IOC set, deobfuscated code, and Miasma framework internals
- [StepSecurity - Coordinated AsyncAPI Supply Chain Attack: Miasma RAT](https://www.stepsecurity.io/blog/compromised-next-branch-pushes-malicious-asyncapi-generator-generator-helpers-and-generator-components-to-npm) — Detailed timeline, malicious commit SHAs, Harden-Runner network observations, and OIDC provenance analysis
- [Chainguard - AsyncAPI Supply Chain Compromise via GitHub Actions "pwn request"](https://www.chainguard.dev/unchained/asyncapi-supply-chain-compromise-npm-packages-backdoored-via-github-actions) — Analysis of the pull_request_target exploitation and PAT theft mechanism
- [OX Security - AsyncAPI npm Organization Compromised](https://www.ox.security/blog/asyncapi-npm-organization-compromised-2m-weekly-downloads-affected/) — Impact assessment and credential harvesting scope
- [SafeDep - AsyncAPI Packages Compromised with Miasma RAT](https://safedep.io/asyncapi-generator-supply-chain-attack-miasma-rat/) — Dead man's switch analysis, AI tool poisoning details, and worm configuration
- [The Hacker News - Compromised AsyncAPI npm Packages](https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html) — Initial reporting with C2 channel overview
- [HackRead - Upwind Supply Chain Compromise AsyncAPI](https://hackread.com/upwind-supply-chain-compromise-asyncapi-npm-packages/) — Upwind research summary and initial discovery attribution

---
*Report generated by Actioner*
