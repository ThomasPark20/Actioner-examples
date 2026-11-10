# bee-js / Swarm Desktop Supply Chain Compromise

**Date:** 2026-11-10
**Status:** FINAL
**TLP:** CLEAR
**Severity:** Critical

---

## Executive Summary

On November 9, 2026 (00:09 UTC), threat actors abused Ethersphere's own CI/CD release automation to publish a malicious version of the `@ethersphere/bee-js` npm package (v13.3.0) and a trojanized Swarm Desktop application (v0.56.2). The attack leveraged compromised maintainer accounts (`bee-worker` and `nugaon`) to create unsigned commits and trigger legitimate publishing workflows, resulting in artifacts carrying valid SLSA provenance and Apple notarization. The malicious code steals Swarm node wallet keys and passwords and installs platform-specific backdoors: a Go-based remote shell (`evjawbreaker`) on Linux/macOS, and a weaponized ScreenConnect client on Windows. The C2 infrastructure uses an Ethereum smart contract as a dead-drop resolver, allowing the attacker to rotate hub addresses without updating the implant. Socket attributes this campaign with high confidence to the SleepyDuck/EtherDuck threat group previously observed targeting Open VSX extensions. The malicious bee-js version was live for approximately 75 minutes and Swarm Desktop 0.56.2 was available for approximately 8.5 hours before removal.

---

## Background

### Ethersphere and Swarm

[Ethersphere](https://github.com/ethersphere) maintains the Swarm decentralized storage network. The `@ethersphere/bee-js` package is the primary JavaScript client library for interacting with Swarm nodes, used by Swarm Desktop, swarm-cli, bee-dashboard, and third-party projects. Swarm Desktop is an Electron application that manages a local Bee node, including its wallet and staking operations.

### Timeline (UTC, November 2026)

| Time | Event |
|------|-------|
| Nov 6, 17:06 | Failed secret-harvesting probes begin on swarm-desktop and swarm-cli repositories |
| Nov 6, ~19:55 | Secret exfiltration attempts end; Socket assesses with moderate confidence no secrets were exfiltrated via these attempts |
| Nov 8, 23:30:47 | Ethereum contract updated: C2 hub set to `193[.]57[.]9[.]155:4912` |
| Nov 9, 00:06:01 | GitHub release `v13.3.0` created for bee-js |
| Nov 9, 00:09:50 | `@ethersphere/bee-js@13.3.0` published to npm via automated workflow |
| Nov 9, 00:36 | Swarm Desktop v0.56.2 GitHub release published |
| Nov 9, 00:43-00:45 | Auto-updater begins delivering 0.56.2 to Windows x64 and Apple Silicon |
| Nov 9, 01:24:58 | bee-js 13.3.0 superseded (~75 minutes as latest) |
| Nov 9, ~08:30 | Swarm Desktop 0.56.2 withdrawn (65 downloads recorded) |
| Nov 9, same day | Clean Swarm Desktop 0.56.3 released |

---

## Technical Analysis

### Initial Access: CI/CD Pipeline Abuse

The attack exploited two compromised GitHub accounts: `bee-worker` (release automation bot, ID 70210089) and `nugaon` (a long-time maintainer). The origin of credential compromise is undetermined. A failed secret-harvesting attempt on November 6 serialized `${{ toJSON(secrets) }}` and `vars` to `webhook[.]site` collectors and `pastebin[.]com`, but Socket assesses these attempts yielded empty payloads.

The release pipeline had critical weaknesses:
- The `Publish on npm` workflow accepted release events **without verifying the commit was on a protected branch**
- The `publish` environment had **no reviewers or tag policy**
- Signing and notarization credentials were accessible from **manually dispatched, branch-arbitrary workflows**
- The workflow completed in **73 seconds**, leaving minimal window for human review

### bee-js 13.3.0 Payload (npm postinstall)

The unsigned commit `de2f74e` modified `package.json` to add a `postinstall` hook calling `node scripts/generate-version.cjs`. This was the **first install-time hook in the package's 177 prior versions**. The injected loader:

1. Sends HTTPS GET to `hxxps://api[.]frameworkmetrics[.]xyz/v1/analytics` with header `X-Ethersphere: 1` and `User-Agent: <process.platform>`
2. Executes the response body via `new Function('require', 'console', 'process', body)(require, console, process)`
3. Silently swallows all errors
4. Logs `[FrameworkMetrics] analytics v2.3.1 is up to date` to appear benign

The 331 `dist/` files were byte-identical to the legitimate build. Only `package.json` and the loader script differed. The package carried **valid SLSA provenance** because it was built by the real workflow.

### Swarm Desktop 0.56.2 Payload (Electron main process)

A 731-byte insertion in `dist/desktop/src/index.js` within `app.asar` runs as the first action of `main()` on every application launch. It fetches `hxxps://api[.]frameworkmetrics[.]xyz/v1/electron` with identical headers and uses the same `new Function` execution sink. The macOS build was signed with Developer ID team `9J9SPHU9RP` and Apple-notarized, so Gatekeeper showed only the normal first-launch prompt.

### Stage 2: Credential Theft

The second-stage payload (served only when the `X-Ethersphere: 1` header is present; a decoy is served otherwise):

1. Locates the Swarm Desktop data directory:
   - Linux: `~/.local/share/Swarm Desktop` (or `$XDG_DATA_HOME/Swarm Desktop`)
   - macOS: `~/Library/Application Support/Swarm Desktop`
   - Windows: `%LOCALAPPDATA%\Swarm Desktop\Data`
2. Reads `config.yaml` (contains the **node password in plaintext**) and `data-dir/keys/swarm.key` (encrypted keystore)
3. POSTs both to `hxxps://api[.]frameworkmetrics[.]xyz/v1/swarm/report`
4. Downloads OS-specific Stage 3 from `/v1/assets/`

With both files, the attacker can decrypt the node wallet and steal xDAI, xBZZ, chequebook funds, and staked tokens.

### Stage 3a: Linux/macOS Backdoor (evjawbreaker)

A Go-based remote shell binary written to `~/.solidity/`:

- **Filenames:** `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64`
- **Launchers:** `.run.py` (Linux/macOS), `.run.cjs` (macOS with Node.js)
- **Persistence:**
  - Linux: systemd user service `solidity-langsupport-runner.service` (repairs itself if modified)
  - macOS: LaunchAgent `com.solidity.langsupport.runner` (quarantine attribute cleared via `xattr -c`)
- **C2 resolution:** Calls `param1()` (selector `0x02d91518`) on Ethereum contract `0xf8a900Db50b3331be6B768bA460BB59f3E40C344` via public RPC (`rpc[.]ankr[.]com`, `cloudflare-eth[.]com`)
- **Behavior:** Connects to hub over TLS (no certificate validation), spawns `sh` in a pseudo-terminal, executes operator commands
- **Anti-analysis:** Exits if debugger or VM detected

### Stage 3b: Windows Backdoor (ScreenConnect)

- Stages files as `%TEMP%\.stuffed-*`
- Runs obfuscated PowerShell loader `invoke.ps1`
- **Privilege escalation:** UACME method 39 (COR_PROFILER hijack on `mmc.exe`) if admin; repeated UAC prompts otherwise
- **Defense evasion:** Adds then removes Microsoft Defender exclusion
- **Persistence:** Installs ConnectWise-signed ScreenConnect 25.4.3 as SYSTEM service `ScreenConnect Client (5cbe79c9c25524df)` connecting to relay `185[.]232[.]84[.]169:8041`
- UI hidden, consent prompts disabled

### Ethereum Dead-Drop Resolver

The contract `0xf8a900Db50b3331be6B768bA460BB59f3E40C344` (deployed March 14, 2026) stores the current C2 hub address and payload URL as on-chain state. The operator wallet `0xFd3fc58bcbd8ccc77b6000201438eDfc636E7cA7` has rotated the hub address through seven IPs since deployment. A second contract (`0x6a82595EEea0f4FDFB3aE13A2687BcbBE626e94B`) uses the same getter selectors with a per-slot substitution cipher.

### Attribution

[Socket](https://socket.dev/blog/bee-js-compromise) links this campaign's infrastructure with high confidence to the SleepyDuck/EtherDuck group previously reported by [Pluto Security](https://pluto.security/blog/sleepyduck-malware-open-vsx-extensions/) in their analysis of malicious Solidity-themed Open VSX extensions (September 2026). Shared indicators include:
- Identical Ethereum contract and on-chain timeline
- Same ScreenConnect relay `185[.]232[.]84[.]169:8041` and instance ID `5cbe79c9c25524df`
- Identical Go backdoor builds and persistence naming
- Six of seven file hashes from the Pluto report match
- Operator wallets funded by the same high-volume payout wallet

---

## Indicators of Compromise

> All indicators are defanged. Replace `[.]` with `.` and `hxxp/hxxps` with `http/https` for operational use.

### Network Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `api[.]frameworkmetrics[.]xyz` | C2 and payload delivery host |
| Domain | `frameworkmetrics[.]xyz` | Parent domain (registered Nov 6, 2026) |
| URL | `hxxps://api[.]frameworkmetrics[.]xyz/v1/analytics` | bee-js loader endpoint |
| URL | `hxxps://api[.]frameworkmetrics[.]xyz/v1/electron` | Swarm Desktop loader endpoint |
| URL | `hxxps://api[.]frameworkmetrics[.]xyz/v1/swarm/report` | Wallet file exfiltration endpoint |
| URL | `hxxps://api[.]frameworkmetrics[.]xyz/v1/assets/` | Stage 3 payload delivery |
| URL | `hxxp://107[.]189[.]27[.]46:3000/app[.]js` | Historical payload URL (still in contract) |
| IP:Port | `193[.]57[.]9[.]155:4912` | Current evjawbreaker C2 hub |
| IP:Port | `193[.]57[.]9[.]17:4912` | Previous C2 hub |
| IP:Port | `178[.]16[.]54[.]222:4912` | Previous C2 hub |
| IP:Port | `107[.]189[.]27[.]223:4912` | Previous C2 hub |
| IP:Port | `107[.]189[.]27[.]46:4912` | Previous C2 hub |
| IP:Port | `91[.]108[.]240[.]156:4912` | Previous C2 hub |
| IP:Port | `107[.]189[.]16[.]215:4912` | Previous C2 hub |
| IP:Port | `185[.]232[.]84[.]169:8041` | ScreenConnect relay |
| HTTP Header | `X-Ethersphere: 1` | Required to receive malicious payload |

### Secret Harvesting Infrastructure (Nov 6 probes)

| Type | Indicator | Context |
|------|-----------|---------|
| URL | `hxxps://webhook[.]site/fdc222d5-2e6c-4122-801d-93099f3fe827` | Secret exfiltration collector |
| URL | `hxxps://webhook[.]site/46358b99-9cff-4f14-97bc-4a436086e826` | Secret exfiltration collector |
| URL | `hxxps://webhook[.]site/c05b53d9-c3b6-4a90-94dc-b86a0a4e905f` | Secret exfiltration collector |
| URL | `hxxps://pastebin[.]com/raw/q1p9qH2w` | Secret exfiltration staging |

### Blockchain Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| Ethereum Contract | `0xf8a900Db50b3331be6B768bA460BB59f3E40C344` | C2 dead-drop resolver (primary) |
| Ethereum Contract | `0x6a82595EEea0f4FDFB3aE13A2687BcbBE626e94B` | C2 dead-drop resolver (secondary) |
| Ethereum Wallet | `0xFd3fc58bcbd8ccc77b6000201438eDfc636E7cA7` | Contract 1 operator |
| Ethereum Wallet | `0xA7B15A2B5F6992DC3BabB946375d6895fF1171BF` | Contract 2 deployer |
| Getter Selector | `0x02d91518` | `param1()` - returns hub address |
| Getter Selector | `0x1f049b68` | `param2()` - returns payload URL |

### File Hashes (SHA-256)

#### Packages and Loaders

| Hash | File |
|------|------|
| `d01fdf241aa9e0a1ba6ebc19f8f667af1bf652745021c5050126cb7036f7ce58` | `bee-js-13.3.0.tgz` |
| `ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f` | `scripts/generate-version.cjs` (malicious loader) |
| `f81315968e679b48f6bdff1c9b928bb223230d07f44d7948412c2250c2a14deb` | `dist/desktop/src/index.js` (Swarm Desktop loader, all platforms) |

#### Swarm Desktop 0.56.2 Installers

| Hash | File |
|------|------|
| `94df8933a57cb9962a312a79c079fd0d43706a45066cda1f1b2322f403ad9217` | `Swarm.Desktop-0.56.2-arm64.dmg` |
| `718ae6ac77e119568dff50a6409996bd649c8e9daf7c8a5616856ff1909a916f` | `Swarm.Desktop-darwin-arm64-0.56.2.zip` |
| `0ef1fbe5db17ec0ebd3bcac576f0f0f351a5ef5da67d5e45a9817e7a224acc5d` | `Swarm.Desktop-0.56.2.Setup.exe` |
| `6a37ce783e406f135ed8b60e0897e0e1146a9fa220c2e6c5ce4118fff967f395` | `Swarm.Desktop-win32-x64-0.56.2.zip` |
| `14f23342f4292ede4546070e0e3e1cacd06fa781a2937ac374d2b47dbaf77666` | `swarm-desktop_0.56.2_amd64.deb` |
| `23f2d944a0dfa60df493667428d9304cfc1961270b6c68f8d0f38df7fe0e2d31` | `swarm-desktop_0.56.2_arm64.deb` |
| `aed930fbf5993df4ce9bb5951a4092da8a28a12fb45a81ad9715c7b029606fd0` | `swarm-desktop-0.56.2-1.x86_64.rpm` |
| `e0304260dcf2f29d1b4690dc46e9ceb35d5554a79ea749cd913687288d6e228b` | `swarm-desktop-0.56.2-1.arm64.rpm` |

#### Swarm Desktop 0.56.2 app.asar Files

| Hash | Platform |
|------|----------|
| `92c6eb24f9910b3577d5939a8686f9bf6e52f1bdd5872bf96cab0132b4558025` | Linux |
| `e49afac84dbb6d5a5d101f87754575024b078d67a7ab9e767ff0f7b5b4368069` | macOS |
| `40a45d68aa49e9e6233c4eb6bb2eb2e92525deea5d17863f6910fc24b06ff20e` | Windows |

#### Stage 3 Payloads

| Hash | File |
|------|------|
| `9b73e7cd4e1425e770392549d8df46c706139ef476f4f7b9ac405165dc8d9696` | `linux_amd64` (evjawbreaker) |
| `b601776817363b96295119f7221338a122d5247a35a77a64b04f286e1bbcc565` | `linux_arm64` (evjawbreaker) |
| `80d2672e2599732d3c0ae2a4cd0d1e3fe4d555a60273ce33feb99db3f34d250f` | `darwin_amd64` (evjawbreaker) |
| `fae61f31f00988fdc5cc9e7272b51e08af2e245d81003237875415930fd27358` | `darwin_arm64` (evjawbreaker) |
| `37d14bff30762ca701e9c1f8bc6c57c065bb20ae3a2208cb7411a6530610f08e` | `invoke.ps1` (Windows PowerShell loader) |
| `7527e86d70e7c9493db4356f1c3775380431b310000f2602c1e993cf435d01da` | `app.msi` (modified ScreenConnect installer) |

### Host Artifacts

| Platform | Indicator | Type |
|----------|-----------|------|
| All | `~/.solidity/` directory | Staging/persistence directory |
| Linux | `solidity-langsupport-runner.service` | systemd user service |
| macOS | `com.solidity.langsupport.runner` (plist) | LaunchAgent |
| Windows | `ScreenConnect Client (5cbe79c9c25524df)` | Windows SYSTEM service |
| Windows | `%TEMP%\.stuffed-*` | Staging files |
| All | `bee-desktop.log` containing `Bee Desktop version: 0.56.2 (production)` | Log indicator |

### Log File Paths for Swarm Desktop

| Platform | Path |
|----------|------|
| macOS | `~/Library/Logs/Swarm Desktop/` |
| Windows | `%LOCALAPPDATA%\Swarm Desktop\Log\` |
| Linux | `~/.local/state/Swarm Desktop/` |

### Package Identifiers

| Type | Value |
|------|-------|
| npm package | `@ethersphere/bee-js@13.3.0` |
| npm integrity | `sha512-ltkrphoNy7TBIjCICDW7y3qa+j8yljt3+ohPRSM+id1rK2NaOgm5H5V/FioTQ0rEJ5IJ+Zj1micbAdQCqqc8iw==` |
| GitHub Advisory | [GHSA-hh7j-5m3j-23pf](https://github.com/advisories/GHSA-hh7j-5m3j-23pf) |
| CWE | CWE-506 (Embedded Malicious Code) |
| Git commit (bee-js) | `de2f74e784b2eafa0d66fbb6d88b42ea11ee34cf` |
| Git tag | `v13.3.0` (tag object `f112f36110ef51ae91aa814596621c2eafd99d1b`) |
| Git commit (Swarm Desktop) | `2de727046706062d38edfbbf8340f32d1eb2bdfb` |
| Git commit (Swarm Desktop fix) | `dc7d7455c95b3092eb14bff2bd93315b84b066fa` |
| Actions run (npm publish) | `42538346313` |
| GitHub account | `bee-worker` (ID 70210089) |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed Behavior |
|--------|-----------|-----|-------------------|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Malicious npm release and Electron app via compromised CI/CD bot |
| Initial Access | Valid Accounts | T1078 | Compromised `bee-worker` and `nugaon` GitHub accounts |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | `new Function` execution of remote code in postinstall and Electron main |
| Execution | User Execution: Malicious File | T1204.002 | Triggered by `npm install` or Swarm Desktop launch |
| Persistence | Create or Modify System Process: Launch Agent | T1543.001 | `com.solidity.langsupport.runner` plist |
| Persistence | Create or Modify System Process: Systemd Service | T1543.002 | `solidity-langsupport-runner.service` |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | ScreenConnect SYSTEM service |
| Privilege Escalation | Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 | UACME method 39 (COR_PROFILER) |
| Defense Evasion | Subvert Trust Controls: Code Signing | T1553.002 | Legitimate Apple Developer ID and notarization |
| Defense Evasion | Subvert Trust Controls: Gatekeeper Bypass | T1553.001 | `xattr -c` on macOS implant |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Temporary Defender exclusion |
| Defense Evasion | Obfuscated Files or Information | T1027 | Obfuscated `invoke.ps1` |
| Defense Evasion | Masquerading | T1036 | Loader disguised as analytics/versioning script |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | Debugger and VM checks |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 | `swarm.key` and plaintext password from `config.yaml` |
| Collection | Data from Local System | T1005 | Wallet files collected from Swarm Desktop data directory |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS to `api[.]frameworkmetrics[.]xyz` |
| Command and Control | Web Service: Dead Drop Resolver | T1102.001 | Ethereum smart contract stores C2 hub address |
| Command and Control | Encrypted Channel | T1573 | TLS to C2 hub (no cert validation) |
| Command and Control | Remote Access Software | T1219 | ScreenConnect client |
| Command and Control | Ingress Tool Transfer | T1105 | Multi-stage payload download |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | POST wallet files to `/v1/swarm/report` |

---

## Detection and Remediation

### Detection Priorities

1. **Immediate:** Search all lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`), caches, registries, and CI logs for `@ethersphere/bee-js@13.3.0` or integrity hash `sha512-ltkrphoNy7TBIjCICDW7y3...`
2. **Immediate:** Check Swarm Desktop logs for `Bee Desktop version: 0.56.2 (production)`
3. **Network:** Hunt for DNS queries to `frameworkmetrics[.]xyz` and connections to the listed C2 hub and relay IPs
4. **Host:** Search for `~/.solidity/` directory, `solidity-langsupport-runner.service`, `com.solidity.langsupport.runner.plist`, and `ScreenConnect Client (5cbe79c9c25524df)` service
5. **Ethereum RPC:** Where visible, hunt for `eth_call` to contract `0xf8a900Db50b3331be6B768bA460BB59f3E40C344` with data `0x02d91518`

### Remediation

**For projects and CI pipelines:**
- Pin `@ethersphere/bee-js` to `13.2.0` or a later clean version
- Treat any machine that installed 13.3.0 with install scripts enabled as compromised
- Rotate all credentials, tokens, and secrets accessible from compromised environments from a clean machine
- Review npm mirror caches (e.g., Huawei Cloud mirror was still serving 13.3.0 post-removal)

**For Swarm Desktop users:**
- Uninstall 0.56.2 and install 0.56.3 (or later)
- **Treat the node key and password as stolen** -- move all funds, chequebook balance, and stake to a new key from a clean machine
- Remove persistence artifacts (updating/reinstalling does not remove them):
  - Linux: `rm -rf ~/.solidity/` and `systemctl --user disable --now solidity-langsupport-runner.service`
  - macOS: Remove `~/Library/LaunchAgents/com.solidity.langsupport.runner.plist` and `rm -rf ~/.solidity/`
  - Windows: Remove `ScreenConnect Client (5cbe79c9c25524df)` service and delete staging files at `%TEMP%\.stuffed-*`
- Rebuilding from a trusted image is preferred over manual cleanup

---

## Detection Rules

### Sigma Rules

7 Sigma rules, 8 YARA rules, and 6 Snort/Suricata rules. All Sigma rules validated via `sigma convert --without-pipeline -t splunk` and `-t log_scale`. All YARA rules compiled with `yarac` (exit 0). Snort/Suricata rules are structurally reviewed but uncompiled (no engine available in this environment). Sigma #4 uses only CommandLine matching (process_creation logsource). All YARA rules use `severity = "high"` in meta.

#### 1. Frameworkmetrics C2 DNS Query

Detects DNS resolution of the attacker-controlled C2 domain `frameworkmetrics.xyz`, which has no legitimate use.

**Status:** Validated (Splunk + LogScale conversion successful)

```yaml
title: BeeJS/Swarm Supply Chain - Frameworkmetrics C2 DNS Query
id: a7c3e1f0-9d4b-4e8a-b2f1-3c5d7e9f0a1b
status: experimental
description: Detects DNS resolution of api.frameworkmetrics.xyz, the C2 domain used by the malicious bee-js 13.3.0 and Swarm Desktop 0.56.2 loader.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://github.com/advisories/GHSA-hh7j-5m3j-23pf
    - https://thehackernews.com/2026/11/hackers-compromise-etherspheres-bee-js.html
author: CTI Analyst (Actioner)
date: 2026-11-10
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1105
logsource:
    category: dns
detection:
    selection:
        query|endswith:
            - 'frameworkmetrics.xyz'
    condition: selection
falsepositives:
    - Unlikely; this is an attacker-registered domain with no legitimate use
level: high
```

**Audit:** IOC-based rule targeting a known-malicious, attacker-registered domain. High confidence due to domain specificity. No legitimate services use this domain.

#### 2. Evjawbreaker Systemd Persistence (Linux)

Detects creation of the systemd user service used by the evjawbreaker Go backdoor for Linux persistence.

**Status:** Validated (Splunk + LogScale conversion successful)

```yaml
title: BeeJS/Swarm Supply Chain - Evjawbreaker Systemd Persistence
id: b8d4f2a1-0e5c-5f9b-c3a2-4d6e8f0b1c2d
status: experimental
description: Detects creation or modification of the systemd user service used by the evjawbreaker Go backdoor deployed via the compromised bee-js/Swarm Desktop supply chain.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: CTI Analyst (Actioner)
date: 2026-11-10
tags:
    - attack.persistence
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection_unit:
        TargetFilename|endswith:
            - '/solidity-langsupport-runner.service'
    condition: selection_unit
falsepositives:
    - Legitimate Solidity development tooling is unlikely to use this exact service name
level: high
```

**Audit:** IOC-based rule targeting a distinctive persistence artifact name. High confidence -- this exact service name is unique to the threat actor.

#### 3. Evjawbreaker macOS LaunchAgent Persistence

Detects creation of the LaunchAgent plist used by the evjawbreaker backdoor on macOS.

**Status:** Validated (Splunk + LogScale conversion successful)

```yaml
title: BeeJS/Swarm Supply Chain - Evjawbreaker macOS LaunchAgent Persistence
id: c9e5a3b2-1f6d-6a0c-d4b3-5e7f9a1c2d3e
status: experimental
description: Detects creation of the LaunchAgent plist used by the evjawbreaker backdoor on macOS, installed by the compromised bee-js/Swarm Desktop supply chain.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: CTI Analyst (Actioner)
date: 2026-11-10
tags:
    - attack.persistence
    - attack.t1543.001
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|endswith:
            - '/com.solidity.langsupport.runner.plist'
    condition: selection
falsepositives:
    - No known legitimate software uses this LaunchAgent identifier
level: high
```

**Audit:** IOC-based rule targeting a distinctive LaunchAgent label. High confidence -- this label is unique to the threat actor.

#### 4. Malicious ScreenConnect Service Installation (Windows)

Detects creation of the specific ScreenConnect service instance deployed by the Windows payload, identified by its unique instance ID.

**Status:** Validated (Splunk + LogScale conversion successful)

```yaml
title: BeeJS/Swarm Supply Chain - Malicious ScreenConnect Service Installation
id: daf6b4c3-2a7e-7b1d-e5c4-6f8a0b2d3e4f
status: experimental
description: Detects creation of the specific ScreenConnect service instance deployed by the Windows payload of the bee-js/Swarm Desktop supply chain attack. The instance ID 5cbe79c9c25524df is unique to this threat actor.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://thehackernews.com/2026/11/hackers-compromise-etherspheres-bee-js.html
author: CTI Analyst (Actioner)
date: 2026-11-10
tags:
    - attack.persistence
    - attack.t1543.003
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_service:
        CommandLine|contains:
            - '5cbe79c9c25524df'
    condition: selection_service
falsepositives:
    - A legitimate ScreenConnect deployment would not use this specific instance ID
level: high
```

**Audit:** IOC-based rule targeting a unique ScreenConnect instance ID. High confidence -- this ID is shared with the SleepyDuck/EtherDuck campaign and unique to this threat actor.

#### 5. Dotsolidity Hidden Directory Creation

Detects file creation in the `~/.solidity/` directory used as the staging and persistence directory for the evjawbreaker backdoor.

**Status:** Validated (Splunk + LogScale conversion successful)

```yaml
title: BeeJS/Swarm Supply Chain - Dotsolidity Hidden Directory Creation
id: ebf7c5d4-3b8f-8c2e-f6d5-7a9b1c3e4f5a
status: experimental
description: Detects file creation events inside the ~/.solidity/ hidden directory, which is used as the staging and persistence directory for the evjawbreaker Go backdoor.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: CTI Analyst (Actioner)
date: 2026-11-10
tags:
    - attack.execution
    - attack.t1105
    - attack.persistence
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - '/.solidity/'
    condition: selection
falsepositives:
    - Custom Solidity development environments may use this path, but it is uncommon
level: medium
```

**Audit:** TTP-adjacent rule with advisory-specific path. Medium confidence -- while `.solidity/` is distinctive for malware staging, some Solidity development tooling could theoretically create similarly-named directories, hence medium level.

#### 6. ScreenConnect Relay Network Connection

Detects outbound connections to the specific ScreenConnect relay IP and port used by this threat actor.

**Status:** Validated (Splunk + LogScale conversion successful)

```yaml
title: BeeJS/Swarm Supply Chain - ScreenConnect Relay Network Connection
id: fc08d6e5-4c9a-9d3f-a7e6-8bac2d4f5a6b
status: experimental
description: Detects outbound network connections to the ScreenConnect relay IP used by the threat actor in the bee-js/Swarm Desktop supply chain attack.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://thehackernews.com/2026/11/hackers-compromise-etherspheres-bee-js.html
author: CTI Analyst (Actioner)
date: 2026-11-10
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '185.232.84.169'
        DestinationPort: 8041
    condition: selection
falsepositives:
    - Unlikely; this IP and port combination is specific to the attacker's relay
level: high
```

**Audit:** IOC-based rule targeting a specific IP:port combination. High confidence -- this relay is unique to the threat actor infrastructure.

#### 7. Evjawbreaker C2 Hub Connections

Detects outbound connections to the known C2 hub IPs (historical and current) used by the evjawbreaker backdoor on port 4912.

**Status:** Validated (Splunk + LogScale conversion successful)

```yaml
title: BeeJS/Swarm Supply Chain - Evjawbreaker C2 Hub Connection
id: ad19e7f6-5dab-ae4a-b8f7-9cbd3e5a6b7c
status: experimental
description: Detects outbound network connections to the known C2 hub IPs used by the evjawbreaker backdoor. These IPs have been rotated over time via the Ethereum dead-drop resolver contract.
references:
    - https://socket.dev/blog/bee-js-compromise
author: CTI Analyst (Actioner)
date: 2026-11-10
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1102.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '193.57.9.155'
            - '193.57.9.17'
            - '178.16.54.222'
            - '107.189.27.223'
            - '107.189.27.46'
            - '91.108.240.156'
            - '107.189.16.215'
        DestinationPort: 4912
    condition: selection
falsepositives:
    - These IPs on port 4912 are specific to this threat actor's infrastructure; false positives are unlikely
level: high
```

**Audit:** IOC-based rule combining IP addresses with a distinctive non-standard port. High confidence -- port 4912 is not a commonly used service port, and the IP list is specific to the decoded Ethereum contract history.

### YARA Rules

Compiled and validated with `yarac` (exit code 0, no errors).

#### 1. beejs_malicious_loader_generate_version_cjs

Detects the malicious loader injected into bee-js 13.3.0's `generate-version.cjs` by matching the C2 domain, API paths, custom HTTP header, and the `new Function` execution pattern.

**Status:** Compiled successfully (`yarac` exit 0)

```yara
rule beejs_malicious_loader_generate_version_cjs {
    meta:
        description = "Detects the malicious loader injected into bee-js 13.3.0 scripts/generate-version.cjs"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f"
        severity = "high"
    strings:
        $url = "api.frameworkmetrics.xyz" ascii wide
        $path1 = "/v1/analytics" ascii wide
        $path2 = "/v1/electron" ascii wide
        $header = "X-Ethersphere" ascii wide
        $exec = "new Function('require', 'console', 'process'" ascii wide
        $log = "[FrameworkMetrics] analytics" ascii wide
    condition:
        $url or ($exec and ($header or $path1 or $path2)) or $log
}
```

**Audit:** Matches on the C2 domain (any occurrence) or the distinctive code-execution pattern combined with known API paths/headers. The `[FrameworkMetrics]` log string is a standalone match because it is unique to this malware and appeared in the CI job output.

#### 2. beejs_malicious_package_tgz

Detects the malicious bee-js 13.3.0 npm tarball by matching the package name, version, and injected postinstall hook.

**Status:** Compiled successfully (`yarac` exit 0)

```yara
rule beejs_malicious_package_tgz {
    meta:
        description = "Detects the malicious bee-js 13.3.0 npm tarball by package name, version, and injected postinstall hook"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "d01fdf241aa9e0a1ba6ebc19f8f667af1bf652745021c5050126cb7036f7ce58"
        severity = "high"
    strings:
        $pkg = "@ethersphere/bee-js" ascii
        $ver = "13.3.0" ascii
        $postinstall = "node scripts/generate-version.cjs" ascii
    condition:
        all of them
}
```

**Audit:** Requires all three strings, reducing false positives. Earlier bee-js versions do not contain a postinstall hook, so the combination is specific to the malicious version.

#### 3. evjawbreaker_staging_directory

Detects launcher scripts associated with the evjawbreaker backdoor's `.solidity` staging directory.

**Status:** Compiled successfully (`yarac` exit 0)

```yara
rule evjawbreaker_staging_directory {
    meta:
        description = "Detects scripts associated with the evjawbreaker Go backdoor staging directory (.solidity)"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        severity = "high"
    strings:
        $dir1 = ".solidity/" ascii wide
        $runner_py = ".run.py" ascii wide
        $runner_cjs = ".run.cjs" ascii wide
        $service = "solidity-langsupport-runner" ascii wide
        $launchagent = "com.solidity.langsupport.runner" ascii wide
    condition:
        $dir1 and ($runner_py or $runner_cjs or $service or $launchagent)
}
```

**Audit:** Requires the staging directory path combined with at least one known launcher or persistence artifact name. The combination is distinctive to this threat.

#### 4. evjawbreaker_go_backdoor

Detects the evjawbreaker Go binary by its module name, embedded Ethereum contract address, and RPC gateway references.

**Status:** Compiled successfully (`yarac` exit 0)

```yara
rule evjawbreaker_go_backdoor {
    meta:
        description = "Detects the evjawbreaker Go remote shell backdoor binary by embedded strings"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        severity = "high"
    strings:
        $mod = "evjawbreaker" ascii wide
        $contract = "0xf8a900Db50b3331be6B768bA460BB59f3E40C344" ascii wide nocase
        $selector = "0x02d91518" ascii wide
        $ankr = "rpc.ankr.com" ascii wide
        $cfeth = "cloudflare-eth.com" ascii wide
    condition:
        $mod or ($contract and $selector) or ($contract and ($ankr or $cfeth))
}
```

**Audit:** The Go module name `evjawbreaker` is a standalone match. Contract address combined with the getter selector or public RPC references catches variants that may strip the module name. The contract address alone is not sufficient to avoid false positives on blockchain analysis tools.

#### 5. screenconnect_malicious_instance

Detects the weaponized ScreenConnect installer by matching the threat-actor-specific instance ID combined with the relay IP.

**Status:** Compiled successfully (`yarac` exit 0)

```yara
rule screenconnect_malicious_instance {
    meta:
        description = "Detects the specific ScreenConnect instance ID used in the bee-js supply chain attack Windows payload"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash_msi = "7527e86d70e7c9493db4356f1c3775380431b310000f2602c1e993cf435d01da"
        severity = "high"
    strings:
        $instance_id = "5cbe79c9c25524df" ascii wide nocase
        $relay = "185.232.84.169" ascii wide
    condition:
        $instance_id and $relay
}
```

**Audit:** Requires both the unique instance ID and relay IP to avoid matching on legitimate ScreenConnect installations. The ScreenConnect binary itself is legitimately signed, so this rule targets the threat-actor-specific configuration.

#### 6. invoke_ps1_swarm_attack

Detects the obfuscated PowerShell loader used in the Windows stage, matching staging file patterns combined with privilege escalation or defense evasion indicators.

**Status:** Compiled successfully (`yarac` exit 0)

```yara
rule invoke_ps1_swarm_attack {
    meta:
        description = "Detects the obfuscated PowerShell loader used in the Windows stage of the bee-js supply chain attack"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "37d14bff30762ca701e9c1f8bc6c57c065bb20ae3a2208cb7411a6530610f08e"
        severity = "high"
    strings:
        $stuffed = ".stuffed-" ascii wide
        $defender_excl = "Add-MpPreference" ascii wide
        $cor_profiler = "COR_PROFILER" ascii wide
        $mmc = "mmc.exe" ascii wide
    condition:
        $stuffed and ($defender_excl or ($cor_profiler and $mmc))
}
```

**Audit:** The `.stuffed-` staging file pattern is distinctive to this threat. Combined with Defender exclusion manipulation or the COR_PROFILER UAC bypass targeting mmc.exe, this minimizes false positives while catching the loader even if partially deobfuscated.

#### 7. swarm_desktop_malicious_index_js

Detects the malicious `index.js` injected into Swarm Desktop 0.56.2's `app.asar` by matching the C2 domain, Electron-specific API path, and custom header.

**Status:** Compiled successfully (`yarac` exit 0)

```yara
rule swarm_desktop_malicious_index_js {
    meta:
        description = "Detects the malicious index.js injected into Swarm Desktop 0.56.2 app.asar"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "f81315968e679b48f6bdff1c9b928bb223230d07f44d7948412c2250c2a14deb"
        severity = "high"
    strings:
        $url = "api.frameworkmetrics.xyz" ascii wide
        $path = "/v1/electron" ascii wide
        $header = "X-Ethersphere" ascii wide
    condition:
        all of them
}
```

**Audit:** Requires all three strings, specific to the Swarm Desktop variant of the loader. The `/v1/electron` path is not used by the npm package variant.

#### 8. swarm_wallet_exfiltration_endpoint

Detects references to the wallet exfiltration endpoint used to steal Swarm node keys and passwords.

**Status:** Compiled successfully (`yarac` exit 0)

```yara
rule swarm_wallet_exfiltration_endpoint {
    meta:
        description = "Detects references to the wallet exfiltration endpoint used in the bee-js supply chain attack"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        severity = "high"
    strings:
        $exfil = "/v1/swarm/report" ascii wide
        $domain = "frameworkmetrics" ascii wide
    condition:
        all of them
}
```

**Audit:** Requires both the exfiltration path and the domain name. The path is distinctive and not used by any known legitimate API.

### Snort/Suricata Rules

**Status:** All rules are structurally reviewed but **uncompiled** -- no Snort/Suricata engine is available in this environment for compilation testing.

#### 1. Frameworkmetrics C2 DNS Lookup

Detects DNS queries for the attacker's C2 domain.

**Status:** Structurally reviewed, uncompiled

```
alert dns $HOME_NET any -> any 53 (msg:"BEEJS-SUPPLY-CHAIN Frameworkmetrics C2 DNS Lookup"; dns.query; content:"frameworkmetrics.xyz"; nocase; classtype:trojan-activity; sid:2026111001; rev:1; metadata:created_at 2026_11_10, updated_at 2026_11_10;)
```

**Audit:** Uses Suricata `dns.query` keyword for DNS payload inspection. High confidence on the domain indicator.

#### 2. TLS SNI to frameworkmetrics.xyz

Detects TLS connections with SNI matching the C2 domain.

**Status:** Structurally reviewed, uncompiled

```
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"BEEJS-SUPPLY-CHAIN TLS SNI to frameworkmetrics.xyz"; tls.sni; content:"api.frameworkmetrics.xyz"; classtype:trojan-activity; sid:2026111002; rev:1; metadata:created_at 2026_11_10, updated_at 2026_11_10;)
```

**Audit:** Uses Suricata `tls.sni` keyword. Catches HTTPS connections to the C2 even when DNS resolution is not visible.

#### 3. Evjawbreaker C2 Hub Connection

Detects TCP connections to known C2 hub IPs on port 4912.

**Status:** Structurally reviewed, uncompiled

```
alert tcp $HOME_NET any -> [193.57.9.155,193.57.9.17,178.16.54.222,107.189.27.223,107.189.27.46,91.108.240.156,107.189.16.215] 4912 (msg:"BEEJS-SUPPLY-CHAIN Evjawbreaker C2 Hub Connection"; flow:to_server,established; classtype:trojan-activity; sid:2026111003; rev:1; metadata:created_at 2026_11_10, updated_at 2026_11_10;)
```

**Audit:** IOC-based rule on non-standard port 4912. The IP list should be updated if new hub addresses are decoded from the Ethereum contract.

#### 4. Malicious ScreenConnect Relay Connection

Detects TCP connections to the attacker's ScreenConnect relay.

**Status:** Structurally reviewed, uncompiled

```
alert tcp $HOME_NET any -> 185.232.84.169 8041 (msg:"BEEJS-SUPPLY-CHAIN Malicious ScreenConnect Relay Connection"; flow:to_server,established; classtype:trojan-activity; sid:2026111004; rev:1; metadata:created_at 2026_11_10, updated_at 2026_11_10;)
```

**Audit:** Tight IOC-based rule. ScreenConnect uses TCP on various ports; port 8041 combined with this specific IP is unique to the threat actor.

#### 5. Wallet Exfiltration POST

Detects HTTP POST to the `/v1/swarm/report` exfiltration endpoint with the `X-Ethersphere` header.

**Status:** Structurally reviewed, uncompiled

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"BEEJS-SUPPLY-CHAIN Wallet Exfiltration POST to /v1/swarm/report"; http.method; content:"POST"; http.uri; content:"/v1/swarm/report"; http.header; content:"X-Ethersphere"; classtype:trojan-activity; sid:2026111005; rev:1; metadata:created_at 2026_11_10, updated_at 2026_11_10;)
```

**Audit:** Combines the exfiltration URI with the custom header and POST method. Will only fire on decrypted traffic (requires TLS inspection).

#### 6. Stage 3 Payload Download

Detects HTTP requests to the `/v1/assets/` payload delivery path on the `frameworkmetrics.xyz` host.

**Status:** Structurally reviewed, uncompiled

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"BEEJS-SUPPLY-CHAIN Stage 3 Payload Download from /v1/assets/"; http.uri; content:"/v1/assets/"; http.host; content:"frameworkmetrics.xyz"; classtype:trojan-activity; sid:2026111006; rev:1; metadata:created_at 2026_11_10, updated_at 2026_11_10;)
```

**Audit:** Targets the Stage 3 download path on the attacker's host. Will only fire on decrypted traffic (requires TLS inspection).

---

## Sources

- [The Hacker News: Hackers Compromise Ethersphere's bee-js and Swarm Desktop](https://thehackernews.com/2026/11/hackers-compromise-etherspheres-bee-js.html)
- [Socket: Malicious bee-js npm Release and Swarm Desktop Releases Deliver SleepyDuck Ethereum C2 Backdoor](https://socket.dev/blog/bee-js-compromise)
- [SafeDep: Compromised bee-js and Swarm Desktop Steal Swarm Wallet Keys](https://safedep.io/blog/ethersphere-bee-js-npm-compromise)
- [GitHub Advisory: GHSA-hh7j-5m3j-23pf](https://github.com/advisories/GHSA-hh7j-5m3j-23pf)
- [StepSecurity: @ethersphere/bee-js 13.3.0 Compromised](https://www.stepsecurity.io/blog/ethersphere-bee-js-13-3-0-compromise)
- [OX Security: Ethersphere Hijacked With Crypto Stealing Malware](https://www.ox.security/blog/ethersphere-hijacked-with-crypto-stealing-malware-via-github-npm/)
- [Pluto Security: SleepyDuck Malware - Open VSX Extensions](https://pluto.security/blog/sleepyduck-malware-open-vsx-extensions/)
- [Ethersphere Maintainer Incident Note (PR #582)](https://github.com/ethersphere/swarm-desktop/pull/582)
- [Swarm Desktop v0.56.3 Clean Release](https://github.com/ethersphere/swarm-desktop/releases/tag/v0.56.3)
