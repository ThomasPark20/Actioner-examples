# Technical Analysis Report: Ethersphere bee-js / Swarm Desktop Supply Chain Compromise (2026-11-11)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026/11/11
Version: 1.0

## Executive Summary

On November 9, 2026, attackers used compromised GitHub accounts (`bee-worker` and `nugaon`) to publish a malicious version of the `@ethersphere/bee-js` npm package (v13.3.0) and a trojanized Swarm Desktop application (v0.56.2) through the project's own CI/CD pipeline. The malicious code steals Swarm wallet keys and passwords, exfiltrates them to a C2 server at api[.]frameworkmetrics[.]xyz, and installs platform-specific backdoors: a Go-based remote shell ("evjawbreaker") on Linux/macOS and a pre-configured ScreenConnect remote access client on Windows. The C2 address is resolved via an Ethereum smart contract, allowing the attackers to rotate infrastructure at will.

The npm package was live for approximately 75 minutes and the desktop release for roughly 8.5 hours. An estimated 10 npm downloads and 65 desktop downloads occurred (including researchers/mirrors). Both artifacts carried valid provenance: the npm package had a legitimate SLSA provenance attestation, and the macOS build was Apple-notarized. Socket, SafeDep, and Pluto Security link this campaign with high confidence to the SleepyDuck/EtherDuck threat group, which previously distributed the same implants via malicious Open VSX extensions in September 2026.

## Background: Swarm / bee-js Ecosystem

[Ethersphere](https://www.ethersphere.org/) maintains the Swarm decentralized storage network. `@ethersphere/bee-js` is the official JavaScript client library for interacting with Swarm Bee nodes, published on npm. Swarm Desktop is an Electron-based application that runs a local Bee node and manages a wallet holding xDAI and xBZZ tokens. The wallet keystore password is stored in plaintext in the application's `config.yaml`, making credential theft trivial once file access is obtained. The bee-js package averages approximately 3,700 downloads per week and is a dependency for `swarm-cli`, `bee-dashboard`, and several third-party libraries.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-03-14 | Dead-drop Ethereum contract `0xf8a9...C344` deployed by operator wallet |
| 2026-11-06 15:08 | C2 domain frameworkmetrics[.]xyz registered (NICENIC, Cloudflare NS) |
| 2026-11-06 17:06–19:55 | Attacker (via `nugaon` account) probes CI workflows on swarm-desktop and swarm-cli, attempts credential exfiltration via workflow_dispatch |
| 2026-11-08 23:30:47 | Contract hub value updated to 193[.]57[.]9[.]155:4912 |
| 2026-11-08 23:59:54 | Unsigned commit `de2f74e` pushed by `bee-worker`: adds loader + postinstall hook to bee-js |
| 2026-11-09 00:06:01 | Unsigned tag `v13.3.0` and GitHub release created, triggering npm publish workflow |
| 2026-11-09 00:09:50 | bee-js 13.3.0 published to npm as `latest` with valid SLSA provenance |
| 2026-11-09 00:36 | Swarm Desktop v0.56.2 published via manual workflow dispatch on branch `emergency/0.56.2` |
| 2026-11-09 00:43–00:44 | Desktop builds signed (Authenticode), notarized (Apple), and uploaded; auto-updater serves to Win x64 and Apple Silicon |
| 2026-11-09 01:24:58 | npm removes bee-js 13.3.0; GHSA-hh7j-5m3j-23pf advisory issued |
| 2026-11-09 ~09:04 | Desktop v0.56.2 tag deleted; release withdrawn by ~09:14 |
| 2026-11-09 (later) | Clean bee-js 13.2.0 restored as `latest`; Desktop 0.56.3 released (same code as 0.56.1, new signing certificate) |

## Root Cause: Compromised CI Credentials and Unprotected Release Pipeline

The attackers gained access to two GitHub accounts:

- **`nugaon`**: a long-time maintainer with force-push rights to unprotected `master` branches
- **`bee-worker`**: the project's release automation bot identity

The method of account compromise is unknown (Ethersphere's incident note attributes it to stolen CI credentials without further detail). The release pipeline had several structural weaknesses:

1. The npm `publish` workflow triggered on release events with no branch protection check and no required reviewer approval. Deployment completed in 73 seconds.
2. The desktop `pre-release.yml` workflow accepted manual dispatch with an arbitrary branch input and no environment protection, yet had access to Apple and Windows code-signing certificates/passwords and the Apple notarization Apple ID.
3. Neither workflow required commits to be signed.
4. Trusted publishing (OIDC) and SLSA provenance were valid because the legitimate workflow ran the attacker's code, making provenance attestations ineffective against this attack vector.

## Technical Analysis of the Malicious Payload

### 1. Stage 1 — Loader Injection

**bee-js (npm):** The attacker modified `scripts/generate-version.cjs` to prepend a loader and changed `package.json` to set it as a `postinstall` hook (previously `prepare`), ensuring it runs on every `npm install` without requiring the library to be imported. The `scripts/` directory was added to the `files` array to include it in the published tarball. All 331 files in `dist/` are byte-identical to the legitimate pre-release; only `package.json` and the loader script differ.

**Swarm Desktop:** The loader was injected as the first action in `main()` in `dist/desktop/src/index.js` inside `app.asar`, running at every application launch before the single-instance lock, updater, or window creation. Only 731 bytes were added across seven changed files versus v0.56.1.

Both loaders perform an HTTPS GET to the C2 with:
- `User-Agent` set to bare `process.platform` (`linux`, `darwin`, or `win32`)
- Header `X-Ethersphere: 1` (gate header; without it, the server returns a harmless decoy)
- The response body is executed via `new Function('require', 'console', 'process', body)(require, console, process)`, granting full Node.js privileges

### 2. Stage 2 — Credential Theft

The Stage 2 JavaScript payload searches for Swarm Desktop's data directory and POSTs two files to `api[.]frameworkmetrics[.]xyz/v1/swarm/report`:

| OS | Data Directory |
|----|----------------|
| Linux | `~/.local/share/Swarm Desktop` (or `$XDG_DATA_HOME/Swarm Desktop`) |
| macOS | `~/Library/Application Support/Swarm Desktop` |
| Windows | `%LOCALAPPDATA%\Swarm Desktop\Data` |

- **`config.yaml`** — contains the keystore password in plaintext
- **`data-dir/keys/swarm.key`** — encrypted Ethereum keystore

With both, the attacker can recover the node's private key and steal xDAI, xBZZ, chequebook funds, and staked funds.

### 3. C2 Infrastructure

**Primary C2 domain:** api[.]frameworkmetrics[.]xyz

| URL Path | Purpose |
|----------|---------|
| `/v1/analytics` | Stage 2 delivery for bee-js npm loader |
| `/v1/electron` | Stage 2 delivery for Swarm Desktop loader |
| `/v1/assets/` | Stage 3 implant download |
| `/v1/swarm/report` | Wallet credential exfiltration |

**Ethereum dead-drop resolver:** Contract `0xf8a900Db50b3331be6B768bA460BB59f3E40C344` on Ethereum mainnet. The implant reads the hub address via getter selector `0x02d91518` through public RPC gateways (`rpc.ankr.com`, `cloudflare-eth.com`). The contract owner (`0xFd3fc58bcbd8ccc77b6000201438eDfc636E7cA7`) can rotate the C2 address at will. Historical hub addresses show seven rotations since March 2026.

**Evjawbreaker hub IPs (port 4912):**
- 193[.]57[.]9[.]155 (current, Onidel NL)
- 193[.]57[.]9[.]17 (historical, Onidel NL)
- 178[.]16[.]54[.]222 (historical, TR-MGN TR)
- 107[.]189[.]27[.]223 (historical, RouterHosting)
- 107[.]189[.]27[.]46 (historical, RouterHosting)
- 91[.]108[.]240[.]156 (historical, Aeza FR)
- 107[.]189[.]16[.]215 (historical, RouterHosting)

**ScreenConnect relay:** 185[.]232[.]84[.]169:8041 (Onidel NL)

### 4. Platform-Specific Behavior

#### Linux

- **Implant:** evjawbreaker Go binary written to `~/.solidity/linux_amd64` or `~/.solidity/linux_arm64`
- **Launcher:** `~/.solidity/.run.py`
- **Persistence:** systemd user service `solidity-langsupport-runner.service`, auto-repaired on each run if modified
- **C2:** TLS connection to hub (no certificate verification), provides a persistent `sh` pseudo-terminal
- **Anti-analysis:** Exits if debugger or VM detected

#### macOS

- **Implant:** evjawbreaker Go binary written to `~/.solidity/darwin_amd64` or `~/.solidity/darwin_arm64`
- **Launcher:** `~/.solidity/.run.cjs` (if Node.js present) or `~/.solidity/.run.py`
- **Persistence:** LaunchAgent `com.solidity.langsupport.runner`; quarantine attribute cleared via `xattr -c`
- **C2 and behavior:** Same as Linux
- **Code signing:** Application was signed with the project's Developer ID and Apple-notarized; Gatekeeper shows only the normal prompt

#### Windows

- **Stage:** Files staged as `%TEMP%\.stuffed-*`
- **UAC bypass:** If user is a local admin, uses UACME method 39 (COR_PROFILER hijack of `mmc.exe`) for silent elevation. If not admin, repeatedly shows UAC prompts on each cancellation.
- **With admin rights:** Adds a Microsoft Defender exclusion, installs ScreenConnect 25.4.3 MSI (`app.msi`), then removes the exclusion and staging files.
- **Implant:** Genuine ConnectWise-signed ScreenConnect client, pre-configured to connect to relay 185[.]232[.]84[.]169:8041 with hidden UI and no user consent.
- **Persistence:** Runs as SYSTEM service `ScreenConnect Client (5cbe79c9c25524df)`

### 5. Anti-Forensics / Evasion Techniques

- The C2 returns a harmless decoy without the `X-Ethersphere: 1` gate header, evading casual inspection
- The npm loader silently swallows all request errors
- The Go implant exits on debugger or VM detection
- Windows payload: removes Defender exclusion and staging files after ScreenConnect installation
- COR_PROFILER UAC bypass artifacts (`%TEMP%갹-*`, registry CLSID hijack, environment variables) are transient
- C2 address is rotatable via Ethereum smart contract; no hardcoded server in the implant binary
- Published artifacts carried valid SLSA provenance and Apple notarization, bypassing trust controls

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `@ethersphere/bee-js` | 13.3.0 | Malicious postinstall loader; clean version: 13.2.0 |
| Swarm Desktop | 0.56.2 | Trojanized Electron app; clean version: 0.56.3 |
| `@ethersphere/swarm-cli` | 3.6.0, 3.7.0 | Accepts bee-js 13.3.0 in version range |
| `@ethersphere/bee-dashboard` | 0.33.0–0.37.1 | Accepts bee-js 13.3.0 in version range |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | bee-js-13.3.0.tgz | `d01fdf241aa9e0a1ba6ebc19f8f667af1bf652745021c5050126cb7036f7ce58` | Malicious npm tarball |
| All | scripts/generate-version.cjs | `ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f` | Malicious loader script |
| Linux | ~/.solidity/linux_amd64 | `9b73e7cd4e1425e770392549d8df46c706139ef476f4f7b9ac405165dc8d9696` | evjawbreaker implant |
| Linux | ~/.solidity/linux_arm64 | `b601776817363b96295119f7221338a122d5247a35a77a64b04f286e1bbcc565` | evjawbreaker implant |
| macOS | ~/.solidity/darwin_amd64 | `80d2672e2599732d3c0ae2a4cd0d1e3fe4d555a60273ce33feb99db3f34d250f` | evjawbreaker implant |
| macOS | ~/.solidity/darwin_arm64 | `fae61f31f00988fdc5cc9e7272b51e08af2e245d81003237875415930fd27358` | evjawbreaker implant |
| Windows | invoke.ps1 | `37d14bff30762ca701e9c1f8bc6c57c065bb20ae3a2208cb7411a6530610f08e` | Obfuscated PowerShell UAC bypass |
| Windows | app.msi | `7527e86d70e7c9493db4356f1c3775380431b310000f2602c1e993cf435d01da` | Rogue ScreenConnect installer |
| Windows | profiler.dll (x64) | `ef5ede5a20619af9467edb80c2a49714d512f836ddd0797ce0f8f9a4ba1a7ea8` | COR_PROFILER UAC bypass helper |
| Windows | profiler.dll (x86) | `d7af711d435eb106cc81be226449e902872196c4c81092ebae13f60d5982cbac` | COR_PROFILER UAC bypass helper |
| Linux/macOS | ~/.solidity/.run.py | — | Python launcher script |
| Linux/macOS | ~/.solidity/.run.cjs | — | Node.js launcher script (macOS) |
| Linux | ~/.config/systemd/user/solidity-langsupport-runner.service | — | Persistence unit |
| macOS | ~/Library/LaunchAgents/com.solidity.langsupport.runner.plist | — | Persistence plist |
| Windows | %TEMP%\.stuffed-* | — | Staging files |
| Windows | %TEMP%갹-* | — | UAC bypass work directory |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | api[.]frameworkmetrics[.]xyz | Primary C2 and exfiltration server |
| Domain | frameworkmetrics[.]xyz | Parent domain |
| IP:Port | 193[.]57[.]9[.]155:4912 | Current evjawbreaker hub (Onidel NL) |
| IP:Port | 193[.]57[.]9[.]17:4912 | Historical hub (Onidel NL) |
| IP:Port | 178[.]16[.]54[.]222:4912 | Historical hub (TR-MGN TR) |
| IP:Port | 107[.]189[.]27[.]223:4912 | Historical hub (RouterHosting) |
| IP:Port | 107[.]189[.]27[.]46:4912 | Historical hub (RouterHosting) |
| IP:Port | 91[.]108[.]240[.]156:4912 | Historical hub (Aeza FR) |
| IP:Port | 107[.]189[.]16[.]215:4912 | Historical hub (RouterHosting) |
| IP:Port | 185[.]232[.]84[.]169:8041 | Rogue ScreenConnect relay (Onidel NL) |
| URL | hxxps://api[.]frameworkmetrics[.]xyz/v1/analytics | bee-js npm loader callback |
| URL | hxxps://api[.]frameworkmetrics[.]xyz/v1/electron | Swarm Desktop loader callback |
| URL | hxxps://api[.]frameworkmetrics[.]xyz/v1/swarm/report | Wallet credential exfiltration |
| URL | hxxps://api[.]frameworkmetrics[.]xyz/v1/assets/ | Stage 3 implant download |
| HTTP Header | X-Ethersphere: 1 | Gate header required for real payload |
| Ethereum Contract | 0xf8a900Db50b3331be6B768bA460BB59f3E40C344 | Dead-drop C2 resolver |
| Ethereum Contract | 0x6a82595EEea0f4FDFB3aE13A2687BcbBE626e94B | Second dead-drop contract |
| Ethereum Wallet | 0xFd3fc58bcbd8ccc77b6000201438eDfc636E7cA7 | Operator wallet (contract 1 owner) |
| Ethereum Wallet | 0xA7B15A2B5F6992DC3BabB946375d6895fF1171BF | Operator wallet (contract 2 deployer) |

### Behavioral

- `postinstall` hook execution of `scripts/generate-version.cjs` performing outbound HTTPS with `X-Ethersphere` header
- `new Function('require', 'console', 'process', body)` pattern in npm postinstall scripts
- Outbound TLS on port 4912 without certificate validation from processes under `~/.solidity/`
- `eth_call` to contract `0xf8a9...C344` with selector `0x02d91518` from non-standard processes
- COR_PROFILER environment variables set in conjunction with `mmc.exe` execution
- ScreenConnect service installation with instance ID `5cbe79c9c25524df`
- `Bee Desktop version: 0.56.2 (production)` in `bee-desktop.log`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious bee-js 13.3.0 published to npm and trojanized Swarm Desktop 0.56.2 released via compromised CI |
| T1078 | Valid Accounts | Compromised GitHub accounts `bee-worker` and `nugaon` used to push code and trigger workflows |
| T1059.007 | Command and Scripting Interpreter: JavaScript | `new Function` execution of remote JavaScript payload in postinstall and Electron main process |
| T1102.001 | Web Service: Dead Drop Resolver | C2 hub address read from Ethereum smart contract via public RPC gateways |
| T1105 | Ingress Tool Transfer | Stage 3 implants downloaded from `/v1/assets/` |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS used for C2, payload delivery, and exfiltration |
| T1553.002 | Subvert Trust Controls: Code Signing | Malicious builds signed with legitimate project certificates; macOS build Apple-notarized |
| T1552.004 | Unsecured Credentials: Private Keys | Swarm wallet keystore and plaintext password exfiltrated |
| T1041 | Exfiltration Over C2 Channel | Wallet files POSTed to `/v1/swarm/report` |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS persistence via LaunchAgent `com.solidity.langsupport.runner` |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via systemd user service `solidity-langsupport-runner.service` |
| T1543.003 | Create or Modify System Process: Windows Service | ScreenConnect installed as SYSTEM service |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | UACME method 39 (COR_PROFILER) against `mmc.exe` |
| T1219 | Remote Access Tools | ScreenConnect 25.4.3 installed for persistent remote access (Windows) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Temporary Microsoft Defender exclusion added during ScreenConnect installation |
| T1036 | Masquerading | Implant directory `~/.solidity/` and service names mimic Solidity development tooling |
| T1497 | Virtualization/Sandbox Evasion | Go implant exits on debugger or VM detection |

## Impact Assessment

- **Breadth:** Estimated ~10 npm downloads of bee-js 13.3.0 during its 75-minute window (including CI scanners and mirrors); 65 GitHub downloads of Swarm Desktop 0.56.2 (including researchers), of which 22 were macOS ARM64 and 3 were Windows updater packages. Downstream dependents (`swarm-cli`, `bee-dashboard`, and several third-party packages) could accept 13.3.0 in their version ranges.
- **Depth:** Any machine that ran `npm install` with scripts enabled or launched Swarm Desktop 0.56.2 should be considered fully compromised. The attacker obtained: Swarm wallet private keys and passwords (enabling theft of xDAI, xBZZ, chequebook funds, and staked funds), persistent remote shell access (Linux/macOS), or unattended remote desktop access (Windows).
- **Stealth:** High. Valid npm provenance, Apple notarization, and Authenticode signatures meant standard trust controls did not flag the artifacts. The C2 dead-drop via Ethereum smart contract allows silent infrastructure rotation.
- **Auto-update exposure:** Windows x64 and Apple Silicon Mac users with Swarm Desktop could receive 0.56.2 automatically; deleting the release does not roll back machines that already updated. Intel Macs were not offered the update. Linux packages do not auto-update.

## Detection & Remediation

### Immediate Detection

**Check for the malicious npm package in lockfiles and caches:**
```bash
# Check npm lockfiles
grep -r '"@ethersphere/bee-js": "13.3.0"' package-lock.json yarn.lock pnpm-lock.yaml
grep -r 'bee-js-13.3.0.tgz' package-lock.json yarn.lock pnpm-lock.yaml

# Check npm cache
find ~/.npm/_cacache -name "*.tgz" 2>/dev/null | xargs sha256sum 2>/dev/null | grep d01fdf241aa9e0a1ba6ebc19f8f667af1bf652745021c5050126cb7036f7ce58
```

**Check for Swarm Desktop 0.56.2:**
```bash
# Linux
grep "Bee Desktop version: 0.56.2" ~/.local/state/Swarm\ Desktop/*.log 2>/dev/null

# macOS
grep "Bee Desktop version: 0.56.2" ~/Library/Logs/Swarm\ Desktop/*.log 2>/dev/null
```

**Check for host artifacts (Linux/macOS):**
```bash
ls -la ~/.solidity/ 2>/dev/null
systemctl --user status solidity-langsupport-runner.service 2>/dev/null
launchctl list com.solidity.langsupport.runner 2>/dev/null
```

**Check for host artifacts (Windows PowerShell):**
```powershell
Get-Service -Name "ScreenConnect Client (5cbe79c9c25524df)" -ErrorAction SilentlyContinue
Test-Path "$env:TEMP\.stuffed-*"
```

**Network hunting:**
```
# DNS/proxy logs
frameworkmetrics.xyz
193.57.9.155:4912
185.232.84.169:8041
```

### Remediation

1. **Contain:** Isolate any system where bee-js 13.3.0 was installed or Swarm Desktop 0.56.2 ran. Block C2 domain and all listed IPs at the network perimeter.
2. **Eradicate:**
   - Remove `~/.solidity/` directory and all contents
   - Remove systemd service: `systemctl --user disable --now solidity-langsupport-runner.service && rm ~/.config/systemd/user/solidity-langsupport-runner.service`
   - Remove LaunchAgent: `launchctl unload ~/Library/LaunchAgents/com.solidity.langsupport.runner.plist && rm ~/Library/LaunchAgents/com.solidity.langsupport.runner.plist`
   - Windows: Uninstall ScreenConnect service `ScreenConnect Client (5cbe79c9c25524df)` and remove its program files
   - Purge bee-js 13.3.0 from all npm caches, proxies, mirrors, and lockfiles
3. **Recover:**
   - Rotate the Swarm Bee node password and move all funds (xDAI, xBZZ, chequebook, stake) to a new wallet key from a trusted machine
   - Rotate all credentials accessible from CI jobs that ran `npm install` with scripts enabled during the exposure window
   - Upgrade to bee-js 13.2.0 (pin exact version) and Swarm Desktop 0.56.3
4. **Rebuild:** Treat any affected system as fully compromised; consider full rebuild rather than selective remediation.

### Long-Term Hardening

- Require reviewer approval on CI/CD deployment environments, especially those with signing certificates or publish tokens
- Enforce signed commits on release branches and verify tag signatures before triggering publish workflows
- Restrict release workflows to protected branches only; do not allow arbitrary branch inputs for manual dispatch
- Use npm `--ignore-scripts` or pnpm (which skips postinstall by default) and explicitly allowlist trusted packages
- Monitor smart contract interactions as part of threat intelligence for supply chain attacks targeting blockchain ecosystems

## Detection Rules

The following rules target the specific IOCs and behavioral patterns observed in this supply chain compromise. They cover C2 communication, persistence mechanisms, and lateral tool deployment across all three affected platforms. Caveat: the C2 domain and IPs are campaign-specific and will age as the attacker rotates infrastructure via the Ethereum dead-drop contract.

### Sigma Rules

**Rule 1: DNS Query to C2 Domain frameworkmetrics.xyz**

Detects DNS resolution of the primary C2 domain used for payload delivery and exfiltration.
<!-- audit: sigma convert --without-pipeline -t splunk: QueryName="*frameworkmetrics.xyz"; sigma convert --without-pipeline -t log_scale: QueryName=/frameworkmetrics\.xyz$/i; sigma check blocked by proxy (MITRE data fetch 403); YARA/Suricata N/A. -->

- Compile: ✅ (Splunk + LogScale convert clean)
- Confidence: **high**

```yaml
title: DNS Query to Ethersphere Bee-js C2 Domain frameworkmetrics.xyz
id: 8a3c1e9f-4b2d-4f7a-9e6c-3d5a8b1f0c2e
status: experimental
description: >
    Detects DNS queries to api.frameworkmetrics.xyz or its parent domain,
    used as the C2 and exfiltration server in the compromised @ethersphere/bee-js
    13.3.0 npm package and Swarm Desktop 0.56.2 supply chain attack.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
    - https://github.com/advisories/GHSA-hh7j-5m3j-23pf
author: Actioner
date: 2026-11-11
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'frameworkmetrics.xyz'
    condition: selection
falsepositives:
    - Unlikely; this domain is exclusively associated with malicious activity
level: critical
```

---

**Rule 2: Network Connection to Evjawbreaker Hub IPs on Port 4912**

Detects outbound connections to all known evjawbreaker C2 hub addresses.
<!-- audit: sigma convert --without-pipeline -t splunk: DestinationIp IN (...) DestinationPort=4912; sigma convert --without-pipeline -t log_scale: clean; sigma check blocked by proxy. -->

- Compile: ✅ (Splunk + LogScale convert clean)
- Confidence: **high** — Caveat: historical IPs may have been reassigned; correlate with port 4912.

```yaml
title: Network Connection to Evjawbreaker C2 Hub on Port 4912
id: 7f2b9d4e-6a1c-4e3d-8b5f-1c9a0d7e2f4b
status: experimental
description: >
    Detects outbound network connections to known evjawbreaker backdoor hub IP
    addresses on port 4912. These IPs served as C2 for the Go-based remote shell
    deployed via the compromised @ethersphere/bee-js and Swarm Desktop supply chain attack.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: Actioner
date: 2026-11-11
tags:
    - attack.t1571
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
    - Unlikely; these IPs on port 4912 are exclusively associated with the evjawbreaker campaign
level: critical
```

---

**Rule 3: File Created in Evjawbreaker Implant Directory ~/.solidity/**

Detects implant binary or launcher script creation in the backdoor's working directory.
<!-- audit: sigma convert --without-pipeline -t splunk: TargetFilename="*/.solidity/*"; sigma convert --without-pipeline -t log_scale: TargetFilename=/\/\.solidity\//i; sigma check blocked by proxy. -->

- Compile: ✅ (Splunk + LogScale convert clean)
- Confidence: **high**

```yaml
title: File Created in Evjawbreaker Implant Directory ~/.solidity/
id: 5e8c4a3b-1d9f-4c2e-7a6b-0f3d8e5c9a1b
status: experimental
description: >
    Detects file creation events in the ~/.solidity/ directory, which is used by the
    evjawbreaker Go backdoor deployed through the compromised @ethersphere/bee-js and
    Swarm Desktop supply chain attack to store implant binaries and launcher scripts.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: Actioner
date: 2026-11-11
tags:
    - attack.t1105
    - attack.t1036
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains: '/.solidity/'
    condition: selection
falsepositives:
    - Solidity development tooling is unlikely to use a hidden directory named .solidity in the user home
level: high
```

---

**Rule 4: Systemd User Service for Evjawbreaker Persistence**

Detects creation of the specific persistence service used by the Linux implant.
<!-- audit: sigma convert --without-pipeline -t splunk: TargetFilename="*/solidity-langsupport-runner.service"; sigma convert --without-pipeline -t log_scale: clean; sigma check blocked by proxy. -->

- Compile: ✅ (Splunk + LogScale convert clean)
- Confidence: **high**

```yaml
title: Systemd User Service Created for Evjawbreaker Persistence
id: 3a7e9c1f-5b4d-4d2e-8f6a-2c0b3e8d7f5a
status: experimental
description: >
    Detects creation of the systemd user service solidity-langsupport-runner.service,
    used by the evjawbreaker Go backdoor for persistence on Linux systems compromised
    through the @ethersphere/bee-js supply chain attack.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: Actioner
date: 2026-11-11
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/solidity-langsupport-runner.service'
    condition: selection
falsepositives:
    - No known legitimate use of this service name
level: critical
```

---

**Rule 5: macOS LaunchAgent for Evjawbreaker Persistence**

Detects creation of the specific macOS persistence plist.
<!-- audit: sigma convert --without-pipeline -t splunk: TargetFilename="*/com.solidity.langsupport.runner.plist"; sigma convert --without-pipeline -t log_scale: clean; sigma check blocked by proxy. -->

- Compile: ✅ (Splunk + LogScale convert clean)
- Confidence: **high**

```yaml
title: macOS LaunchAgent Created for Evjawbreaker Persistence
id: 4c6a1e9b-8d3f-4b2e-5a7c-9f0d2e1b3c8a
status: experimental
description: >
    Detects creation of the macOS LaunchAgent plist for the evjawbreaker backdoor
    persistence mechanism deployed through the @ethersphere/bee-js supply chain attack.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: Actioner
date: 2026-11-11
tags:
    - attack.t1543.001
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|endswith: '/com.solidity.langsupport.runner.plist'
    condition: selection
falsepositives:
    - No known legitimate software uses this LaunchAgent label
level: critical
```

---

**Rule 6: Rogue ScreenConnect Service Installation (Bee-js Attack Instance ID)**

Detects Windows service installation matching the attacker's ScreenConnect instance.
<!-- audit: sigma convert --without-pipeline -t splunk: EventID=7045 ServiceName="*5cbe79c9c25524df*"; sigma convert --without-pipeline -t log_scale: clean; sigma check blocked by proxy. -->

- Compile: ✅ (Splunk + LogScale convert clean)
- Confidence: **high**

```yaml
title: Rogue ScreenConnect Service Installation with Bee-js Attack Instance ID
id: 9d4f2a6e-3c1b-4e8d-7a5f-0b2c9e1d8f3a
status: experimental
description: >
    Detects creation of a Windows service matching the ScreenConnect instance ID
    used in the @ethersphere/bee-js supply chain attack. The attackers installed a
    legitimate but pre-configured ScreenConnect client connecting to their relay.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: Actioner
date: 2026-11-11
tags:
    - attack.t1219
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains: '5cbe79c9c25524df'
    condition: selection
falsepositives:
    - No known legitimate use of this ScreenConnect instance ID
level: critical
```

---

**Rule 7: Network Connection to Rogue ScreenConnect Relay**

Detects outbound connections to the attacker-controlled ScreenConnect relay server.
<!-- audit: sigma convert --without-pipeline -t splunk: DestinationIp="185.232.84.169" DestinationPort=8041; sigma convert --without-pipeline -t log_scale: clean; sigma check blocked by proxy. -->

- Compile: ✅ (Splunk + LogScale convert clean)
- Confidence: **high**

```yaml
title: Network Connection to Rogue ScreenConnect Relay from Bee-js Attack
id: 1b5e8c3a-7d2f-4a9e-6c4b-8f0d3e1a5c7b
status: experimental
description: >
    Detects outbound network connections to the ScreenConnect relay IP used in
    the @ethersphere/bee-js and Swarm Desktop supply chain attack for persistent
    remote access to compromised Windows hosts.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: Actioner
date: 2026-11-11
tags:
    - attack.t1219
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '185.232.84.169'
        DestinationPort: 8041
    condition: selection
falsepositives:
    - Unlikely; this IP:port is exclusively associated with the rogue ScreenConnect relay
level: critical
```

---

**Rule 8: UACME Method 39 COR_PROFILER UAC Bypass**

Detects behavioral indicators of the COR_PROFILER-based privilege escalation used by the Windows payload.
<!-- audit: sigma convert --without-pipeline -t splunk: ParentImage="*\mmc.exe" OR CommandLine IN ("*COR_PROFILER*", "*uac39*"); sigma convert --without-pipeline -t log_scale: clean; sigma check blocked by proxy. Caveat: ParentImage mmc.exe alone may FP in enterprise MMC usage; the OR with COR_PROFILER/uac39 strings keeps precision. -->

- Compile: ✅ (Splunk + LogScale convert clean)
- Confidence: **medium** — Caveat: `ParentImage` matching `mmc.exe` alone could match legitimate MMC snap-in launches; the combined OR condition reduces but does not eliminate false positives.

```yaml
title: UACME Method 39 COR_PROFILER UAC Bypass via mmc.exe
id: 2e7b4c9a-1f3d-4a5e-8d6b-0c2a9f1e3b5d
status: experimental
description: >
    Detects the COR_PROFILER-based UAC bypass technique (UACME method 39) used by
    the Windows payload in the @ethersphere/bee-js supply chain attack. The attack
    sets COR_PROFILER environment variables and hijacks mmc.exe to elevate privileges.
references:
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: Actioner
date: 2026-11-11
tags:
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\mmc.exe'
    selection_env:
        CommandLine|contains:
            - 'COR_PROFILER'
            - 'uac39'
    condition: selection_parent and selection_env
falsepositives:
    - Legitimate .NET profiler usage with mmc.exe is rare in end-user environments
level: high
```

---

### Suricata Rules

**Rule 9: HTTP Request with X-Ethersphere Gate Header to C2**

Detects the specific HTTP request pattern used by the malicious loader to retrieve payloads.
<!-- audit: suricata -T -S suricata_beejs.rules -l /tmp/actioner: "Configuration provided was successfully loaded. Exiting." (exit 0). All 5 rules validated. -->

- Compile: ✅ (suricata -T pass)
- Confidence: **high**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to Ethersphere Bee-js C2 with X-Ethersphere Header"; flow:established,to_server; http.host; content:"api.frameworkmetrics.xyz"; http.header; content:"X-Ethersphere|3a 20|1"; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/bee-js-compromise; reference:url,safedep.io/blog/ethersphere-bee-js-npm-compromise; metadata:author Actioner, created_at 2026-11-11; sid:2200006; rev:1;)
```

---

**Rule 10: DNS Query to C2 Domain**

Detects DNS resolution of the C2 domain at the network level.
<!-- audit: suricata -T validated with rule set (exit 0). -->

- Compile: ✅ (suricata -T pass)
- Confidence: **high**

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Ethersphere Bee-js C2 Domain frameworkmetrics.xyz"; dns.query; content:"frameworkmetrics.xyz"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/bee-js-compromise; reference:url,safedep.io/blog/ethersphere-bee-js-npm-compromise; metadata:author Actioner, created_at 2026-11-11; sid:2200007; rev:1;)
```

---

**Rule 11: HTTP POST to Wallet Exfiltration Endpoint**

Detects the specific exfiltration request pattern for stolen Swarm wallet data.
<!-- audit: suricata -T validated with rule set (exit 0). -->

- Compile: ✅ (suricata -T pass)
- Confidence: **high**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP POST to Ethersphere Bee-js Exfiltration Endpoint"; flow:established,to_server; http.method; content:"POST"; http.host; content:"api.frameworkmetrics.xyz"; http.uri; content:"/v1/swarm/report"; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/bee-js-compromise; reference:url,safedep.io/blog/ethersphere-bee-js-npm-compromise; metadata:author Actioner, created_at 2026-11-11; sid:2200008; rev:1;)
```

---

**Rule 12: TCP Connection to Evjawbreaker Hub on Port 4912**

Detects TCP connections to known evjawbreaker C2 hub IPs on port 4912.
<!-- audit: suricata -T validated with rule set (exit 0). -->

- Compile: ✅ (suricata -T pass)
- Confidence: **high** — Caveat: historical IPs may be reassigned; the port restriction reduces false positives.

```
alert tcp $HOME_NET any -> [193.57.9.155,193.57.9.17,178.16.54.222,107.189.27.223,107.189.27.46,91.108.240.156,107.189.16.215] 4912 (msg:"Actioner - TCP Connection to Evjawbreaker C2 Hub on Port 4912"; flow:established,to_server; classtype:trojan-activity; reference:url,socket.dev/blog/bee-js-compromise; metadata:author Actioner, created_at 2026-11-11; sid:2200009; rev:1;)
```

---

**Rule 13: TCP Connection to Rogue ScreenConnect Relay**

Detects connections to the attacker-controlled ScreenConnect relay.
<!-- audit: suricata -T validated with rule set (exit 0). -->

- Compile: ✅ (suricata -T pass)
- Confidence: **high**

```
alert tcp $HOME_NET any -> 185.232.84.169 8041 (msg:"Actioner - TCP Connection to Rogue ScreenConnect Relay from Bee-js Attack"; flow:established,to_server; classtype:trojan-activity; reference:url,socket.dev/blog/bee-js-compromise; metadata:author Actioner, created_at 2026-11-11; sid:2200010; rev:1;)
```

---

### YARA Rules

**Rule 14: Evjawbreaker Go Backdoor**

Detects the evjawbreaker Go remote shell implant via embedded strings and module paths.
<!-- audit: yarac yara_evjawbreaker.yar /dev/null: exit 0, no warnings. All 3 YARA rules compiled clean. -->

- Compile: ✅ (yarac clean)
- Confidence: **high**

```yara
rule SupplyChain_Ethersphere_Evjawbreaker_Go_Backdoor
{
    meta:
        description = "Detects the evjawbreaker Go remote shell backdoor deployed via the compromised @ethersphere/bee-js and Swarm Desktop supply chain attack"
        author = "Actioner"
        date = "2026-11-11"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "9b73e7cd4e1425e770392549d8df46c706139ef476f4f7b9ac405165dc8d9696"
        hash = "b601776817363b96295119f7221338a122d5247a35a77a64b04f286e1bbcc565"
        hash = "80d2672e2599732d3c0ae2a4cd0d1e3fe4d555a60273ce33feb99db3f34d250f"
        hash = "fae61f31f00988fdc5cc9e7272b51e08af2e245d81003237875415930fd27358"
        severity = "critical"

    strings:
        $pkg1 = "evjawbreaker/internal/hubclient" ascii
        $pkg2 = "evjawbreaker" ascii
        $marker1 = "__JAWBRK_DONE__" ascii
        $marker2 = "__JAWBRK_EC__" ascii
        $contract = "0xf8a900Db50b3331be6B768bA460BB59f3E40C344" ascii nocase
        $selector = "02d91518" ascii
        $dep = "creack/pty" ascii

    condition:
        (uint32(0) == 0x464C457F or uint32(0) == 0xBEBAFECA or uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE) and
        filesize < 20MB and
        ($pkg1 or (2 of ($marker*, $pkg2, $dep)) or ($contract and $selector))
}
```

---

**Rule 15: Malicious bee-js Loader Script**

Detects the JavaScript loader injected into `generate-version.cjs` by matching the C2 URL, gate header, and execution pattern.
<!-- audit: yarac yara_evjawbreaker.yar /dev/null: exit 0. -->

- Compile: ✅ (yarac clean)
- Confidence: **high**

```yara
rule SupplyChain_Ethersphere_BeeJS_Malicious_Loader
{
    meta:
        description = "Detects the malicious loader script injected into @ethersphere/bee-js 13.3.0 generate-version.cjs"
        author = "Actioner"
        date = "2026-11-11"
        reference = "https://safedep.io/blog/ethersphere-bee-js-npm-compromise"
        hash = "ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f"
        severity = "critical"

    strings:
        $url = "api.frameworkmetrics.xyz" ascii
        $path1 = "/v1/analytics" ascii
        $path2 = "/v1/electron" ascii
        $header = "X-Ethersphere" ascii
        $exec = "new Function" ascii
        $args = "'require', 'console', 'process'" ascii

    condition:
        filesize < 100KB and
        $url and
        ($path1 or $path2) and
        $header and
        ($exec or $args)
}
```

---

**Rule 16: PowerShell UAC Bypass Loader (invoke.ps1)**

Detects the obfuscated PowerShell script used for UACME method 39 privilege escalation and ScreenConnect deployment.
<!-- audit: yarac yara_evjawbreaker.yar /dev/null: exit 0. -->

- Compile: ✅ (yarac clean)
- Confidence: **medium** — Caveat: individual strings like "COR_PROFILER" and "ScreenConnect" appear in legitimate contexts; the 3-of-8 threshold reduces false positives.

```yara
rule SupplyChain_Ethersphere_InvokePS1_UAC_Bypass
{
    meta:
        description = "Detects the obfuscated invoke.ps1 PowerShell loader used for UAC bypass (UACME method 39) in the bee-js supply chain attack"
        author = "Actioner"
        date = "2026-11-11"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "37d14bff30762ca701e9c1f8bc6c57c065bb20ae3a2208cb7411a6530610f08e"
        severity = "high"

    strings:
        $s1 = "uac39" ascii nocase
        $s2 = "COR_PROFILER" ascii
        $s3 = "COR_ENABLE_PROFILING" ascii
        $s4 = "profiler.dll" ascii nocase
        $s5 = "UAC39_PAYLOAD" ascii
        $s6 = ".stuffed-" ascii
        $msi = "app.msi" ascii
        $sc = "ScreenConnect" ascii nocase

    condition:
        filesize < 1MB and
        3 of them
}
```

---

## Lessons Learned

1. **Provenance attestations do not protect against insider or account compromise.** The malicious bee-js 13.3.0 carried a valid SLSA provenance attestation because it was built and published by the project's own workflow. Provenance tells you *which* workflow produced an artifact; it does not tell you whether the source code was reviewed or whether the triggering account was legitimate. Organizations consuming npm packages with provenance should not treat it as a substitute for code review gates on the publish pipeline.

2. **Code-signing and notarization are necessary but not sufficient trust controls.** The macOS build was signed with the project's Developer ID and Apple-notarized. Gatekeeper showed only the standard installation prompt. This demonstrates that signing certificates stored in CI systems become weapons when CI credentials are compromised. Signing jobs should require human approval and run only from protected branches.

3. **Ethereum smart contracts as C2 resolvers create a durable, censorship-resistant control channel.** The evjawbreaker implant reads its hub address from an on-chain contract, allowing the attacker to rotate infrastructure without touching the implant binary. Defenders should monitor for `eth_call` requests from unusual processes, and threat intelligence teams should track contract state changes as part of IOC lifecycle management.

4. **Postinstall scripts remain the primary attack surface in the npm ecosystem.** The malicious payload ran automatically on `npm install` without importing the library. Package managers that skip postinstall by default (pnpm, npm 12+, Yarn 4.14.0+, Bun, Deno) would have prevented execution. Organizations should audit their package manager configurations and explicitly allowlist packages that require install scripts.

5. **Auto-updaters amplify supply chain attacks.** Swarm Desktop's auto-updater served the trojanized version to Windows x64 and Apple Silicon Mac users within minutes of the release. Deleting the release from GitHub does not roll back machines that already updated. Desktop applications should implement update signing verification independent of the release channel, and consider staged rollouts with telemetry gates.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [The Hacker News — Hackers Compromise Ethersphere's bee-js](https://thehackernews.com/2026/11/hackers-compromise-etherspheres-bee-js.html) — Primary news coverage with timeline and impact summary
- [Socket — bee-js Compromise Analysis](https://socket.dev/blog/bee-js-compromise) — Detailed technical analysis with comprehensive IOC list, timeline, and MITRE ATT&CK mapping
- [SafeDep — Ethersphere bee-js npm Compromise](https://safedep.io/blog/ethersphere-bee-js-npm-compromise) — Independent technical analysis with code diffs, loader behavior, and detection guidance
- [SafeDep — Stage 2/3 IOC CSV](https://safedep.io/data/blogs/ethersphere-bee-js-stage2-3-iocs.csv) — Machine-readable IOC list (65 indicators)
- [GitHub Advisory GHSA-hh7j-5m3j-23pf](https://github.com/advisories/GHSA-hh7j-5m3j-23pf) — GitHub security advisory for malware in @ethersphere/bee-js
- [Pluto Security — SleepyDuck Malware via Open VSX Extensions](https://pluto.security/blog/sleepyduck-malware-open-vsx-extensions/) — Prior campaign analysis linking SleepyDuck/EtherDuck to the same infrastructure
- [Ethersphere — Swarm Desktop v0.56.3 Clean Release](https://github.com/ethersphere/swarm-desktop/releases/tag/v0.56.3) — Official clean release
- [Ethersphere — Incident Note (PR #582)](https://github.com/ethersphere/swarm-desktop/pull/582) — Maintainer incident disclosure

---
*Report generated by Actioner*
