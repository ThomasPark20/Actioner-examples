# Technical Analysis Report: Ethersphere bee-js / Swarm Desktop Supply Chain Compromise (2026-11-12)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-11-12
Version: 1.0-DRAFT

## Executive Summary

On November 9, 2026, attackers compromised Ethersphere's release automation to publish malicious versions of the `@ethersphere/bee-js` npm package (v13.3.0) and the Swarm Desktop application (v0.56.2). The attack leveraged stolen CI credentials to trigger legitimate build and publish workflows, resulting in signed, notarized, and provenance-attested releases that passed npm's supply chain integrity checks. The malicious code steals Swarm node wallet keys and passwords, then installs a persistent backdoor: a custom Go reverse shell ("evjawbreaker") on Linux/macOS, or a ScreenConnect remote access client on Windows. The C2 infrastructure uses an Ethereum smart contract for dynamic hub resolution, allowing the attackers to rotate addresses at will. The malicious bee-js was live on npm for approximately 75 minutes; Swarm Desktop 0.56.2 was available for approximately 8.5 hours. The attack has been attributed with high confidence to the SleepyDuck/EtherDuck group, previously linked to malicious Open VSX extensions. No confirmed financial losses have been reported, but any machine that installed the affected versions should be treated as fully compromised.

## Background: Ethersphere / Swarm Ecosystem

[Ethersphere](https://www.ethswarm.org/) develops the Swarm decentralized storage network. `bee-js` is the official JavaScript client library for interacting with the Swarm Bee node, published on npm as `@ethersphere/bee-js`. Swarm Desktop is an Electron-based application that bundles a Bee node for end users, distributed as signed builds for Windows, macOS, and Linux. The ecosystem includes dependent packages such as `swarm-cli`, `bee-dashboard`, and several third-party libraries that consume `bee-js` via semver ranges.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-03-14 | Ethereum C2 contract `0xf8a900...C344` deployed |
| 2026-07-31 | Secondary contract `0x6a8259...94B` deployed |
| 2026-11-06 | Domain `frameworkmetrics[.]xyz` registered (15:08 UTC) |
| 2026-11-06 | ~13 pushes from compromised `nugaon` account; attempted CI credential exfiltration via check.yaml workflow injection |
| 2026-11-08 23:30:47 | C2 hub address updated in Ethereum contract to `193[.]57[.]9[.]155` (29 min before malicious code push) |
| 2026-11-09 00:06:01 | GitHub release `v13.3.0` published via compromised `bee-worker` account |
| 2026-11-09 00:09 | bee-js 13.3.0 becomes npm `latest` (Actions run `42538346313`) |
| 2026-11-09 ~00:36 | Swarm Desktop 0.56.2 released on GitHub |
| 2026-11-09 ~00:46 | Auto-updater begins offering 0.56.2 to users |
| 2026-11-09 01:25 | bee-js 13.3.0 superseded on npm (~75 min exposure) |
| 2026-11-09 08:27 | Swarm Desktop 0.56.2 download count reaches ~65 |
| 2026-11-09 ~09:04 | Swarm Desktop 0.56.2 withdrawn from GitHub (~8.5 hr exposure) |
| 2026-11-09 (later) | Swarm Desktop 0.56.3 released (clean rebuild of 0.56.1, re-signed) |

## Root Cause: Compromised Release Automation Credentials

The attacker gained control of two GitHub accounts: `nugaon` (a long-time maintainer with force-push rights) and `bee-worker` (the release automation bot, GitHub ID `70210089`). The maintainer's incident note blames stolen CI credentials and secrets; the exact theft mechanism remains unknown.

The attack exploited the `publish_npmjs.yaml` GitHub Actions workflow, which accepted release events and ran the `publish` job in the `publish` environment with no required reviewers, no branch restrictions, and no tag policy. Because the real workflow built the release, the resulting npm package carried valid SLSA provenance and Fulcio/Rekor attestations, and the Swarm Desktop builds were properly code-signed (Apple Developer ID "Swarm Association (9J9SPHU9RP)") and notarized. The malicious commit (`de2f74e784b2eafa0d66fbb6d88b42ea11ee34cf`) was unsigned, placed on no branch, and never submitted as a pull request.

Post-incident, Ethersphere added approval gates to signing jobs and restricted workflows to the main branch.

## Technical Analysis of the Malicious Payload

### 1. Loader Stage: Postinstall Script / Electron Main Process

**bee-js loader** (`scripts/generate-version.cjs`, SHA-256: `ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f`):
- Runs as a `postinstall` hook -- executes on `npm install` before any code import is needed
- Sends HTTPS GET to `hxxps://api[.]frameworkmetrics[.]xyz/v1/analytics` with 3-second timeout
- Headers: `User-Agent: <process.platform>` (OS fingerprint), `X-Ethersphere: 1` (gate header)
- Response body executed via `new Function('require', 'console', 'process', body)`, granting full Node.js access
- Errors silently swallowed; decoy log output: `[FrameworkMetrics] analytics v2.3.1 is up to date`
- Without the `X-Ethersphere` header, the server returns harmless content (anti-analysis gate)

**Swarm Desktop loader** (`dist/desktop/src/index.js`, SHA-256: `f81315968e679b48f6bdff1c9b928bb223230d07f44d7948412c2250c2a14deb`):
- 731-byte insertion at the beginning of `main()`, before single-instance lock and updater
- Fetches from `/v1/electron` endpoint with identical header scheme
- Runs on every application launch

Modified files in bee-js: `package.json` (added `scripts` to `files`, renamed `prepare` to `postinstall`), `scripts/generate-version.cjs`, `CHANGELOG.md`, `package-lock.json`.

### 2. Wallet Theft Stage

The second-stage payload reads two files from the Swarm Desktop data directory and POSTs them to `hxxps://api[.]frameworkmetrics[.]xyz/v1/swarm/report`:
- `config.yaml` -- contains the Bee node keystore password in **plain text**
- `data-dir/keys/swarm.key` -- encrypted Ethereum keystore

Together these give the attacker the node's private key, enabling theft of xDAI, xBZZ tokens, chequebook funds, and staking deposits.

| OS | Data Directory |
|----|----------------|
| Linux | `~/.local/share/Swarm Desktop` (or `$XDG_DATA_HOME/Swarm Desktop`) |
| macOS | `~/Library/Application Support/Swarm Desktop` |
| Windows | `%LOCALAPPDATA%\Swarm Desktop\Data` |

### 3. C2 Infrastructure

The malware uses an Ethereum smart contract for dynamic C2 resolution, making traditional domain/IP blocking insufficient as the sole countermeasure.

**Primary C2 contract:** `0xf8a900Db50b3331be6B768bA460BB59f3E40C344`
- Selector `0x02d91518` (`param1()`) returns the current hub address
- Selector `0x1f049b68` (`param2()`) returns a payload URL
- Owner-only setters; no events emitted (harder to monitor)
- Public RPC gateways used: `rpc[.]ankr[.]com`, `cloudflare-eth[.]com`

**Secondary contract:** `0x6a82595EEea0f4FDFB3aE13A2687BcbBE626e94B` (values reportedly encoded with per-slot substitution cipher)

**Historical hub addresses (port 4912):**
- `193[.]57[.]9[.]155` (current as of Nov 8)
- `193[.]57[.]9[.]17`
- `178[.]16[.]54[.]222`
- `107[.]189[.]27[.]223`
- `107[.]189[.]27[.]46`
- `91[.]108[.]240[.]156`
- `107[.]189[.]16[.]215`

**Operator wallets:**
- `0xFd3fc58bcbd8ccc77b6000201438eDfc636E7cA7`
- `0xA7B15A2B5F6992DC3BabB946375d6895fF1171BF`

### 4. Platform-Specific Behavior

#### Linux / macOS: evjawbreaker Go Backdoor

- Go module name: `evjawbreaker`
- Install path: `~/.solidity/` with platform-named binaries (`linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64`)
- Launcher scripts: `~/.solidity/.run.py`; `~/.solidity/.run.cjs` on macOS when Node.js is present
- Reads C2 hub address from Ethereum contract via `evjawbreaker/internal/eth.ethCallWithFallback` and `ParseABIString`
- Connects over TLS **without certificate validation**
- Provides a persistent `sh` pseudo-terminal
- Exits if a debugger or VM is detected (anti-analysis)

**Persistence:**
- Linux: systemd user unit `solidity-langsupport-runner.service` (re-applied on each run if modified)
- macOS: LaunchAgent `com.solidity.langsupport.runner` (quarantine attribute cleared via `xattr -c`)

#### Windows: ScreenConnect Remote Access

- Staging directory: `%TEMP%\.stuffed-*`
- Loader: obfuscated PowerShell `invoke.ps1` (SHA-256: `37d14bff30762ca701e9c1f8bc6c57c065bb20ae3a2208cb7411a6530610f08e`)
- Privilege escalation: UACME method 39 (COR_PROFILER hijack against `mmc.exe`) for admin users; repeated UAC prompt for non-admins
- Defense evasion: adds a Microsoft Defender exclusion, installs ScreenConnect, then removes the exclusion and staging files
- Remote access: genuine ConnectWise-signed ScreenConnect 25.4.3 client (`app.msi`, SHA-256: `7527e86d70e7c9493db4356f1c3775380431b310000f2602c1e993cf435d01da`)
- Service name: `ScreenConnect Client (5cbe79c9c25524df)` running as SYSTEM
- Relay: `185[.]232[.]84[.]169:8041`
- Tray icon and connection banners hidden; unattended session start

### 5. Anti-Forensics / Evasion Techniques

- Commits authored as `lab-bot` (fabricated) and `bee-worker` (copied from public history); commits unsigned
- Malicious code placed in release commit with title copied from an unsubmitted release-please PR
- Loader hidden in a file following semicolon-free Prettier style; the `new Function` line is the only semicolon-terminated statement
- Comments framing the code as "analytics ping" and "code generation"
- Remote code executed in-memory via `new Function`, never written to disk by the loader
- Gate header `X-Ethersphere: 1` serves decoy content to non-targeted requests
- Signed/notarized builds with valid SLSA provenance and Fulcio/Rekor attestations
- `ElectronAsarIntegrity` in `Info.plist` matches the malicious archive
- evjawbreaker exits on debugger/VM detection
- Windows staging files self-delete after installation

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `@ethersphere/bee-js` | 13.3.0 | npm package with malicious postinstall loader |
| Swarm Desktop | 0.56.2 | Electron app with malicious main process loader |
| `@ethersphere/swarm-cli` | 3.6.0, 3.7.0 | Accepts bee-js 13.3.0 via semver range |
| `@ethersphere/bee-dashboard` | 0.33.0-0.37.1 | Accepts bee-js 13.3.0 directly or transitively |

### File System

| Platform | Artifact | Hash (SHA-256) | Description |
|----------|----------|----------------|-------------|
| All | `bee-js-13.3.0.tgz` | `d01fdf241aa9e0a1ba6ebc19f8f667af1bf652745021c5050126cb7036f7ce58` | Malicious npm tarball |
| All | `generate-version.cjs` | `ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f` | Malicious postinstall script |
| All | `dist/desktop/src/index.js` | `f81315968e679b48f6bdff1c9b928bb223230d07f44d7948412c2250c2a14deb` | Malicious Electron main |
| Linux | `app.asar` | `92c6eb24f9910b3577d5939a8686f9bf6e52f1bdd5872bf96cab0132b4558025` | Linux Electron archive |
| macOS | `app.asar` | `e49afac84dbb6d5a5d101f87754575024b078d67a7ab9e767ff0f7b5b4368069` | macOS Electron archive |
| Windows | `app.asar` | `40a45d68aa49e9e6233c4eb6bb2eb2e92525deea5d17863f6910fc24b06ff20e` | Windows Electron archive |
| Linux | `swarm-desktop_0.56.2_amd64.deb` | `14f23342f4292ede4546070e0e3e1cacd06fa781a2937ac374d2b47dbaf77666` | Malicious Debian package (amd64) |
| Linux | `swarm-desktop_0.56.2_arm64.deb` | `23f2d944a0dfa60df493667428d9304cfc1961270b6c68f8d0f38df7fe0e2d31` | Malicious Debian package (arm64) |
| Linux | `swarm-desktop-0.56.2-1.x86_64.rpm` | `aed930fbf5993df4ce9bb5951a4092da8a28a12fb45a81ad9715c7b029606fd0` | Malicious RPM (x86_64) |
| Linux | `swarm-desktop-0.56.2-1.arm64.rpm` | `e0304260dcf2f29d1b4690dc46e9ceb35d5554a79ea749cd913687288d6e228b` | Malicious RPM (arm64) |
| macOS | `Swarm.Desktop-0.56.2-arm64.dmg` | `94df8933a57cb9962a312a79c079fd0d43706a45066cda1f1b2322f403ad9217` | Malicious macOS DMG (arm64) |
| macOS | `Swarm.Desktop-darwin-arm64-0.56.2.zip` | `718ae6ac77e119568dff50a6409996bd649c8e9daf7c8a5616856ff1909a916f` | Malicious macOS zip (arm64) |
| Windows | `Swarm.Desktop-0.56.2.Setup.exe` | `0ef1fbe5db17ec0ebd3bcac576f0f0f351a5ef5da67d5e45a9817e7a224acc5d` | Malicious Windows installer |
| Windows | `swarm-desktop-0.56.2-full.nupkg` | `ffd280b8ff519b647041b7453754bfd35d341bbd26bce02cb325c512c8976645` | Malicious Squirrel update |
| Windows | `Swarm.Desktop-win32-x64-0.56.2.zip` | `6a37ce783e406f135ed8b60e0897e0e1146a9fa220c2e6c5ce4118fff967f395` | Malicious Windows zip |
| Linux | `evjawbreaker linux_amd64` | `9b73e7cd4e1425e770392549d8df46c706139ef476f4f7b9ac405165dc8d9696` | Go backdoor (Linux amd64) |
| Linux | `evjawbreaker linux_arm64` | `b601776817363b96295119f7221338a122d5247a35a77a64b04f286e1bbcc565` | Go backdoor (Linux arm64) |
| macOS | `evjawbreaker darwin_amd64` | `80d2672e2599732d3c0ae2a4cd0d1e3fe4d555a60273ce33feb99db3f34d250f` | Go backdoor (macOS Intel) |
| macOS | `evjawbreaker darwin_arm64` | `fae61f31f00988fdc5cc9e7272b51e08af2e245d81003237875415930fd27358` | Go backdoor (macOS Apple Silicon) |
| Windows | `invoke.ps1` | `37d14bff30762ca701e9c1f8bc6c57c065bb20ae3a2208cb7411a6530610f08e` | Obfuscated PowerShell loader |
| Windows | `app.msi` | `7527e86d70e7c9493db4356f1c3775380431b310000f2602c1e993cf435d01da` | ScreenConnect 25.4.3 installer |

**npm integrity hash:** `sha512-ltkrphoNy7TBIjCICDW7y3qa+j8yljt3+ohPRSM+id1rK2NaOgm5H5V/FioTQ0rEJ5IJ+Zj1micbAdQCqqc8iw==`

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `api[.]frameworkmetrics[.]xyz` | Primary C2 and payload delivery |
| Domain | `frameworkmetrics[.]xyz` | C2 apex domain (registered Nov 6 2026, NICENIC, Cloudflare NS) |
| URL | `hxxps://api[.]frameworkmetrics[.]xyz/v1/analytics` | bee-js stage 1 loader endpoint |
| URL | `hxxps://api[.]frameworkmetrics[.]xyz/v1/electron` | Swarm Desktop stage 1 loader endpoint |
| URL | `hxxps://api[.]frameworkmetrics[.]xyz/v1/swarm/report` | Wallet exfiltration endpoint (POST) |
| URL | `hxxps://api[.]frameworkmetrics[.]xyz/v1/assets/` | Stage 3 payload download |
| URL | `hxxp://107[.]189[.]27[.]46:3000/app[.]js` | Payload URL in contract param2 |
| URL | `hxxps://pastebin[.]com/raw/q1p9qH2w` | Second stage in check.yaml injection |
| IP | `193[.]57[.]9[.]155:4912` | Current evjawbreaker hub (set Nov 8) |
| IP | `193[.]57[.]9[.]17:4912` | Historical evjawbreaker hub |
| IP | `178[.]16[.]54[.]222:4912` | Historical evjawbreaker hub |
| IP | `107[.]189[.]27[.]223:4912` | Historical evjawbreaker hub |
| IP | `107[.]189[.]27[.]46:4912` | Historical evjawbreaker hub |
| IP | `91[.]108[.]240[.]156:4912` | Historical evjawbreaker hub |
| IP | `107[.]189[.]16[.]215:4912` | Historical evjawbreaker hub |
| IP | `185[.]232[.]84[.]169:8041` | ScreenConnect relay |
| HTTP Header | `X-Ethersphere: 1` | Gate header required to receive malicious payload |
| HTTP Header | `User-Agent: linux` / `darwin` / `win32` | Platform fingerprint (bare `process.platform`) |
| Webhook | `webhook[.]site` collectors: `fdc222d5-...`, `46358b99-...`, `c05b53d9-...` | CI credential exfiltration attempts |

### Behavioral

- Bee Desktop log line `Bee Desktop version: 0.56.2 (production)` in `bee-desktop.log` (macOS: `~/Library/Logs/Swarm Desktop/`, Windows: `%LOCALAPPDATA%\Swarm Desktop\Log\`, Linux: `~/.local/state/Swarm Desktop/`)
- npm install log showing `@ethersphere/bee-js@13.3.0 (postinstall: node scripts/generate-version.cjs)`
- File creation in `~/.solidity/` directory
- systemd user unit `solidity-langsupport-runner.service`
- macOS LaunchAgent `com.solidity.langsupport.runner`
- Windows service `ScreenConnect Client (5cbe79c9c25524df)` running as SYSTEM
- `eth_call` to contract `0xf8a900Db50b3331be6B768bA460BB59f3E40C344` with data `0x02d91518`

### Blockchain

| Type | Value | Context |
|------|-------|---------|
| Contract | `0xf8a900Db50b3331be6B768bA460BB59f3E40C344` | Primary C2 hub resolver |
| Contract | `0x6a82595EEea0f4FDFB3aE13A2687BcbBE626e94B` | Secondary contract (encoded values) |
| Wallet | `0xFd3fc58bcbd8ccc77b6000201438eDfc636E7cA7` | Operator wallet 1 |
| Wallet | `0xA7B15A2B5F6992DC3BabB946375d6895fF1171BF` | Operator wallet 2 |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected via compromised release automation into legitimate npm package and signed desktop application |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Postinstall script executes remote code via `new Function()` |
| T1059.001 | Command and Scripting Interpreter: PowerShell | `invoke.ps1` obfuscated PowerShell loader on Windows |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS used for C2 communication and wallet exfiltration |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via systemd user unit |
| T1547.011 | Boot or Logon Autostart Execution: XDG Autostart Entries | macOS persistence via LaunchAgent |
| T1219 | Remote Access Software | ScreenConnect installed as SYSTEM service for Windows remote access |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | UACME method 39 (COR_PROFILER) used for privilege escalation |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Microsoft Defender exclusion added before ScreenConnect installation |
| T1041 | Exfiltration Over C2 Channel | Wallet credentials exfiltrated to `/v1/swarm/report` |
| T1102 | Web Service | Ethereum smart contract used for dynamic C2 resolution |

## Impact Assessment

- **Breadth:** bee-js 13.3.0 was downloaded approximately 10 times (including scanners/mirrors). Swarm Desktop 0.56.2 reached ~65 downloads (including researchers). Dependent packages (`swarm-cli`, `bee-dashboard`, and others) that accepted 13.3.0 via semver ranges expanded the potential exposure window.
- **Depth:** Complete compromise of affected machines -- wallet keys stolen, persistent backdoor installed with root/SYSTEM privileges.
- **Stealth:** Signed and notarized releases with valid SLSA provenance; passed npm's supply chain integrity checks. Ethereum-based C2 resolution makes infrastructure harder to sinkhole.
- **Financial:** No confirmed fund losses as of reporting. However, any node that ran the affected code should treat its wallet key as compromised.

## Detection & Remediation

### Immediate Detection

```bash
# Check npm lockfiles and caches for the malicious version
grep -r '@ethersphere/bee-js.*13\.3\.0' package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
find ~/.npm ~/.cache/yarn ~/.local/share/pnpm -name 'bee-js-13.3.0.tgz' 2>/dev/null

# Check Swarm Desktop logs for the affected version
grep -r 'Bee Desktop version: 0.56.2' ~/Library/Logs/Swarm\ Desktop/ ~/.local/state/Swarm\ Desktop/ "$LOCALAPPDATA/Swarm Desktop/Log/" 2>/dev/null

# Check for evjawbreaker backdoor
ls -la ~/.solidity/ 2>/dev/null
systemctl --user status solidity-langsupport-runner.service 2>/dev/null
launchctl list com.solidity.langsupport.runner 2>/dev/null

# Check for ScreenConnect backdoor (Windows, run as admin)
# sc query "ScreenConnect Client (5cbe79c9c25524df)"
```

### Remediation

1. **Containment:** Isolate affected machines immediately. Do not trust them for secret management.
2. **Eradication:**
   - Remove `~/.solidity/` directory and all contents
   - Remove systemd unit: `systemctl --user disable --now solidity-langsupport-runner.service && rm ~/.config/systemd/user/solidity-langsupport-runner.service`
   - Remove LaunchAgent: `launchctl unload ~/Library/LaunchAgents/com.solidity.langsupport.runner.plist && rm ~/Library/LaunchAgents/com.solidity.langsupport.runner.plist`
   - Remove ScreenConnect service (Windows): stop and delete `ScreenConnect Client (5cbe79c9c25524df)` service
   - Reinstalling or uninstalling Swarm Desktop does NOT remove these components
3. **Secret rotation (from a clean machine):**
   - Generate new Swarm node keys and move all funds (xDAI, xBZZ, chequebook, stake) to the new address
   - Rotate all passwords, tokens, and keys accessible to the compromised user or CI job
   - Revoke and reissue any npm tokens, GitHub PATs, and code-signing certificates used in affected CI
4. **Recovery:**
   - Pin bee-js to 13.2.0; purge 13.3.0 from all internal registries, mirrors, and caches
   - Install Swarm Desktop 0.56.3 (Linux packages must be replaced manually)
   - Where possible, rebuild from a trusted image rather than cleaning in place

### Long-Term Hardening

- Require pull request review and approval for all release workflows
- Restrict workflow dispatch to protected branches only
- Implement mandatory code signing verification independent of CI
- Add branch protection rules preventing direct pushes, even from automation accounts
- Monitor release automation accounts for anomalous activity
- Consider npm `--ignore-scripts` by default and explicitly allowlisting postinstall scripts

## Detection Rules

These detections target the specific indicators from the Ethersphere bee-js / Swarm Desktop supply chain compromise at PoC/advisory-specific altitude. Compiles does not equal fires -- verify in your pipeline with representative telemetry before deploying to production.

### Sigma: DNS Query to bee-js C2 Domain frameworkmetrics.xyz

Detects DNS resolution of the `frameworkmetrics[.]xyz` domain used for C2 and payload delivery in this campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to environment issue (MITRE ATT&CK data fetch 403, not a rule defect). splunk convert 0, log_scale convert 0. Domain registered Nov 6 2026 specifically for this campaign — no legitimate use known. -->
```yaml
title: DNS Query to Ethersphere bee-js C2 Domain frameworkmetrics.xyz
id: 8a3c1f2e-7b4d-4e6a-9f01-2c3d5e8a7b9c
status: experimental
description: >
    Detects DNS resolution of api.frameworkmetrics.xyz, the C2 domain used by the
    malicious bee-js 13.3.0 and Swarm Desktop 0.56.2 supply chain compromise to
    download second-stage payloads and exfiltrate stolen wallet credentials.
references:
    - https://thehackernews.com/2026/11/hackers-compromise-etherspheres-bee-js.html
    - https://socket.dev/blog/bee-js-compromise
    - https://github.com/advisories/GHSA-hh7j-5m3j-23pf
author: Actioner
date: 2026/11/12
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'frameworkmetrics.xyz'
    condition: selection
falsepositives:
    - Unlikely - domain registered specifically for this campaign on Nov 6 2026
level: critical
```

### Sigma: evjawbreaker Backdoor Persistence Artifacts

Detects file creation in `~/.solidity/` or creation of the `solidity-langsupport-runner` systemd unit / LaunchAgent used by the evjawbreaker Go backdoor.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (env issue, not rule). splunk convert 0, log_scale convert 0. Paths are highly distinctive to this campaign. A legitimate Solidity dev tool would not use a hidden .solidity directory in user home with these service names. -->
```yaml
title: Ethersphere Supply Chain evjawbreaker Backdoor Persistence
id: 1d4e6f8a-2b3c-4d5e-9a7b-0c1d2e3f4a5b
status: experimental
description: >
    Detects file creation in the ~/.solidity/ directory or creation of the systemd
    user service or macOS LaunchAgent used by the evjawbreaker Go backdoor deployed
    via the compromised bee-js 13.3.0 / Swarm Desktop 0.56.2 supply chain attack.
references:
    - https://thehackernews.com/2026/11/hackers-compromise-etherspheres-bee-js.html
    - https://socket.dev/blog/bee-js-compromise
    - https://safedep.io/blog/ethersphere-bee-js-npm-compromise
author: Actioner
date: 2026/11/12
tags:
    - attack.t1543.002
    - attack.t1547.011
logsource:
    category: file_event
detection:
    selection_solidity_dir:
        TargetFilename|contains: '/.solidity/'
    selection_systemd:
        TargetFilename|endswith: '/solidity-langsupport-runner.service'
    selection_launchagent:
        TargetFilename|contains: 'com.solidity.langsupport.runner'
    condition: 1 of selection_*
falsepositives:
    - Solidity development tools are unlikely to use a hidden .solidity directory in the user home
level: critical
```

### Sigma: ScreenConnect Backdoor with Attacker Instance ID

Detects the ScreenConnect client service with instance ID `5cbe79c9c25524df` or connecting to the attacker relay at `185[.]232[.]84[.]169`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (env issue). splunk convert 0, log_scale convert 0. Instance ID and relay IP are highly specific to this campaign. Legitimate ScreenConnect uses different instance IDs. -->
```yaml
title: Ethersphere Supply Chain ScreenConnect Backdoor Service
id: 3f5a7c9e-1b2d-4e6f-8a0c-2d4e6f8a1b3c
status: experimental
description: >
    Detects installation of the ScreenConnect client service with the specific instance
    ID 5cbe79c9c25524df used in the Ethersphere bee-js / Swarm Desktop supply chain attack
    for persistent Windows remote access.
references:
    - https://thehackernews.com/2026/11/hackers-compromise-etherspheres-bee-js.html
    - https://socket.dev/blog/bee-js-compromise
author: Actioner
date: 2026/11/12
tags:
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_service:
        CommandLine|contains: '5cbe79c9c25524df'
    selection_image:
        Image|contains: 'ScreenConnect'
        CommandLine|contains: '185.232.84.169'
    condition: selection_service or selection_image
falsepositives:
    - Legitimate ScreenConnect installations will not reference this specific instance ID or relay IP
level: critical
```

### Snort: HTTP C2 Beacon to frameworkmetrics.xyz

Detects outbound HTTP requests to `api[.]frameworkmetrics[.]xyz` with the campaign's `X-Ethersphere` gate header.
**Status:** compile ⚠️ uncompiled (structural check only -- snort not installed) · confidence: high
<!-- audit: snort not installed in this environment. Structural check: correct http service, http_header sticky buffer, fast_pattern on domain, flow established/to_server, sid in 2100000+ range. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Actioner - Ethersphere bee-js C2 HTTP to frameworkmetrics.xyz";
    flow:established,to_server;
    http_header;
    content:"api.frameworkmetrics.xyz", fast_pattern;
    content:"X-Ethersphere";
    classtype:trojan-activity;
    reference:url,socket.dev/blog/bee-js-compromise;
    reference:url,github.com/advisories/GHSA-hh7j-5m3j-23pf;
    metadata:author Actioner, created 2026-11-12;
    sid:2100001;
    rev:1;
)
```

### Suricata: HTTP C2 Request to frameworkmetrics.xyz with X-Ethersphere Header

Detects outbound HTTP to `api[.]frameworkmetrics[.]xyz` with the `X-Ethersphere` gate header characteristic of the bee-js supply chain loader.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Uses dot-notation sticky buffers (http.host, http.header). Domain + custom header combination is highly distinctive. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Ethersphere bee-js C2 HTTP Request to frameworkmetrics.xyz"; flow:established,to_server; http.host; content:"api.frameworkmetrics.xyz"; fast_pattern; http.header; content:"X-Ethersphere"; classtype:trojan-activity; reference:url,socket.dev/blog/bee-js-compromise; reference:url,github.com/advisories/GHSA-hh7j-5m3j-23pf; metadata:author Actioner, created_at 2026-11-12; sid:2200001; rev:1;)
```

### Suricata: DNS Query for frameworkmetrics.xyz

Detects DNS queries for the `frameworkmetrics[.]xyz` C2 domain used throughout the attack chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Uses dns.query sticky buffer. Campaign-specific domain with no legitimate use. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - Ethersphere bee-js C2 DNS Query for frameworkmetrics.xyz"; flow:to_server; dns.query; content:"frameworkmetrics.xyz"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/bee-js-compromise; reference:url,github.com/advisories/GHSA-hh7j-5m3j-23pf; metadata:author Actioner, created_at 2026-11-12; sid:2200002; rev:1;)
```

### Suricata: evjawbreaker Backdoor C2 Connection on Port 4912

Detects outbound TLS connections to port 4912, the characteristic port used by the evjawbreaker backdoor for hub communication. Scope to monitored developer/node-operator segments to reduce false positives.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0. Port 4912 is uncommon but not unique to this campaign -- medium confidence because other services may use this port. TLS handshake byte check adds specificity. -->
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 4912 (msg:"Actioner - Ethersphere evjawbreaker Backdoor C2 Connection on Port 4912"; flow:established,to_server; content:"|16 03|"; depth:2; classtype:trojan-activity; reference:url,socket.dev/blog/bee-js-compromise; metadata:author Actioner, created_at 2026-11-12; sid:2200003; rev:1;)
```

### YARA: Malicious bee-js Loader (generate-version.cjs)

Detects the malicious `generate-version.cjs` postinstall loader from bee-js 13.3.0 by matching the distinctive code sink, C2 endpoints, and decoy strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive test fired on constructed sample containing published source strings (domain, Function sink, header, decoy log). Negative test on clean generate-version.cjs was quiet. Strings sourced from Socket.dev analysis of the actual malicious file. -->
```yara
rule Supply_Chain_BeeJS_Malicious_Loader
{
    meta:
        description = "Detects the malicious generate-version.cjs loader from bee-js 13.3.0 supply chain compromise"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f"
        severity = "critical"

    strings:
        $func_sink = "new Function('require', 'console', 'process', body)" ascii
        $c2_path1 = "/v1/analytics" ascii
        $c2_path2 = "/v1/electron" ascii
        $header = "X-Ethersphere" ascii
        $domain = "api.frameworkmetrics.xyz" ascii
        $log_decoy = "[FrameworkMetrics] analytics" ascii

    condition:
        filesize < 50KB and
        $domain and
        (2 of ($func_sink, $header, $log_decoy, $c2_path1, $c2_path2))
}
```

### YARA: evjawbreaker Go Backdoor Binary

Detects the evjawbreaker Go backdoor by matching its module path, Ethereum contract interaction functions, and persistence artifact names.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. No sample available for fire test -- compile-only validation. Go module name "evjawbreaker" and internal package paths are highly distinctive. Contract address provides strong anchoring. -->
```yara
rule Supply_Chain_BeeJS_Evjawbreaker_Backdoor
{
    meta:
        description = "Detects the evjawbreaker Go backdoor deployed by the compromised bee-js / Swarm Desktop supply chain attack"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "9b73e7cd4e1425e770392549d8df46c706139ef476f4f7b9ac405165dc8d9696"
        severity = "critical"

    strings:
        $go_mod = "evjawbreaker" ascii fullword
        $eth_func = "evjawbreaker/internal/eth" ascii
        $parse_abi = "ParseABIString" ascii fullword
        $contract = "0xf8a900Db50b3331be6B768bA460BB59f3E40C344" ascii nocase
        $selector1 = "0x02d91518" ascii
        $selector2 = "0x1f049b68" ascii
        $persist_linux = "solidity-langsupport-runner" ascii
        $persist_macos = "com.solidity.langsupport.runner" ascii

    condition:
        filesize < 20MB and
        (
            ($go_mod and 2 of ($eth_func, $parse_abi, $contract, $selector1, $selector2)) or
            ($contract and 1 of ($persist_linux, $persist_macos) and 1 of ($go_mod, $eth_func))
        )
}
```

## Lessons Learned

1. **Valid provenance does not guarantee safety.** The malicious npm release carried valid SLSA provenance and Fulcio/Rekor attestations because the legitimate CI workflow built it. Provenance proves *which workflow built it*, not that the code is safe. Organizations relying on npm provenance for trust decisions must also enforce branch protection, approval gates, and code review requirements on the workflows themselves.

2. **Release automation accounts need the same controls as human maintainers.** The `bee-worker` automation account could trigger builds, sign code, and publish to npm without any approval. Automation accounts with publishing rights should require multi-party approval, restricted branch policies, and activity monitoring.

3. **Ethereum-based C2 resolution is an emerging evasion technique.** By storing hub addresses in a smart contract, the attackers can rotate C2 infrastructure without updating any malware, making traditional domain/IP blocklists insufficient as the sole network defense. Defenders should monitor for `eth_call` patterns to known malicious contracts.

4. **Postinstall scripts remain a critical npm attack surface.** The malicious code executed on `npm install` before any project code imported the library. The `--ignore-scripts` flag and tools like Socket's install-time analysis provide defense in depth but are not yet the default developer workflow.

## Sources

- [The Hacker News: Hackers Compromise Ethersphere's bee-js and Swarm Desktop](https://thehackernews.com/2026/11/hackers-compromise-etherspheres-bee-js.html) -- primary coverage with timeline, IOCs, and remediation guidance
- [Socket.dev: Malicious bee-js npm Release and Swarm Desktop](https://socket.dev/blog/bee-js-compromise) -- detailed technical analysis with file hashes, code patterns, contract analysis, and attribution
- [SafeDep: Ethersphere bee-js npm Compromise](https://safedep.io/blog/ethersphere-bee-js-npm-compromise) -- independent technical analysis with affected dependent package enumeration
- [GitHub Advisory GHSA-hh7j-5m3j-23pf](https://github.com/advisories/GHSA-hh7j-5m3j-23pf) -- official GitHub security advisory for malicious bee-js 13.3.0
- [Ethersphere Swarm Desktop Incident PR #582](https://github.com/ethersphere/swarm-desktop/pull/582) -- maintainer incident note
- [Swarm Desktop v0.56.3 Release](https://github.com/ethersphere/swarm-desktop/releases/tag/v0.56.3) -- clean replacement release
- [Pluto Security: SleepyDuck/EtherDuck Analysis](https://pluto.security/blog/sleepyduck-malware-open-vsx-extensions/) -- attribution linking to prior Open VSX campaign

---
*Report generated by Actioner*
