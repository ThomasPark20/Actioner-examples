# Technical Analysis Report: Rust Crate Supply-Chain Attack (arrayref / proc-macro1) (2026-08-24)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-24
Version: 1.0

## Executive Summary

On August 20, 2026, attackers compromised the crates.io account of a long-standing Rust package maintainer (user `droundy`, registered since 2009) and used it to publish poisoned versions of three popular crates: `arrayref` (0.3.10), `internment` (0.8.7), and `append-only-vec` (0.1.9). The malicious releases injected a dependency on a typosquatted crate, `proc-macro1` (mimicking the legitimate `proc-macro2`), whose build script downloaded and executed platform-specific infostealer malware at compile time via `cargo build`, `cargo check`, or `cargo test`. The payload targeted cryptocurrency wallets and browser-stored credentials (Chrome, Brave, Edge). The attack was discovered and contained within 86-107 minutes. `arrayref` alone has 245 million cumulative downloads and is a dependency in over 35% of Rust environments.

Infrastructure analysis by Wiz reveals significant overlap with previous DPRK (North Korea) supply-chain campaigns, including the Mastra and axios npm attacks attributed to Sapphire Sleet. No formal attribution has been assigned.

## Background: Rust Crate Ecosystem (crates.io)

Crates.io is the official package registry for the Rust programming language, analogous to npm for JavaScript or PyPI for Python. Rust's build system (`cargo`) supports build scripts (`build.rs`) that execute arbitrary code at compile time -- a powerful feature that the attackers exploited as the initial execution vector. Unlike runtime dependencies, build-time code runs with the developer's full privileges during compilation, making it an attractive target for supply-chain attacks. The `arrayref` crate provides a macro for converting slices to fixed-size array references and is embedded deep in the Rust dependency tree, appearing in 403 distinct crate dependency chains and approximately 75% of all environments where Rust is used.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-18 | `arone` and `aronenao` reach final publishes with malicious build scripts (attacker infrastructure staging) |
| 2026-08-20 01:17:36 | GitHub account `dtolney` created (impersonating David Tolnay, prominent Rust developer) |
| 2026-08-20 01:25:58 | crates.io account `dtolney` (ID 438608) created |
| 2026-08-20 01:55:34 | `proc-macro1@1.0.106` published (clean decoy -- genuine copy of proc-macro2) |
| 2026-08-20 07:11:15 | `proc-macro1@1.0.107` published (weaponized: malicious `build.rs` added) |
| 2026-08-20 07:15:00 | `arrayref@0.3.10` published via compromised `droundy` account; versions 0.3.5-0.3.9 yanked in scripted burst |
| 2026-08-20 07:15:24 | Rust Security Response Team receives first report |
| 2026-08-20 07:34:07 | `internment@0.8.7` published |
| 2026-08-20 07:37:49 | `append-only-vec@0.1.9` published |
| 2026-08-20 07:54:11 | Reported to RustSec and security@rust-lang.org |
| 2026-08-20 08:03:09 | `proc-macro1` deleted from crates.io registry |
| 2026-08-20 08:41:40 | `arrayref@0.3.10` deleted (86-minute exposure window) |
| 2026-08-20 09:04:11 | `internment@0.8.7` deleted (90-minute exposure window) |
| 2026-08-20 09:25:24 | `append-only-vec@0.1.9` deleted (107-minute exposure window) |

## Root Cause: Compromised Maintainer Credentials

The attacker gained control of crates.io user `droundy` (user ID 2402, registered October 2009), the legitimate maintainer of `arrayref`, `internment`, and `append-only-vec`. The Rust Security Response Team assessed this as a credential compromise (not a malicious insider). The attacker also created a fraudulent impersonation account `dtolney` (mimicking David Tolnay, author of the legitimate `proc-macro2`) and published the typosquatted `proc-macro1` crate from it. Forged metadata used the email `rchaitm[at]gmail[.]com`.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection (Build-Time Trojan)

The compromised crate releases added a single line to their `Cargo.toml`: a dependency on `proc-macro1`. Because `proc-macro1` was a near-perfect copy of the legitimate `proc-macro2` (same library source), builds completed normally and no functionality tests would have flagged the change. The key addition was a malicious `build.rs` script and three new build dependencies: `base64 ^0.22`, `rustls ^0.23`, and `ureq ^2`.

The attacker also yanked `arrayref` versions 0.3.5 through 0.3.9, leaving 0.3.10 as the only available non-yanked version, forcing any fresh `cargo update` to resolve to the poisoned release.

### 2. Build Script Dropper (build.rs)

The malicious `build.rs` (SHA256: `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568`) reconstructed the C2 URL from base64-encoded fragments at build time:

- `aHR0cHM6Ly8=` -> `https://`
- `MjMuMjU0Lg==` -> `23.254.`
- `MTY1Lg==` -> `165.`
- `MTEyOg==` -> `112:`
- `OTA4OS8=` -> `9089/`

The script implemented a custom TLS certificate verifier (`AcceptAll`) that unconditionally returned success for all three verification methods, bypassing certificate validation. It then downloaded a platform-specific binary:

- Linux x86-64: `hxxps://23.254.165[.]112:9089/rust-crate_0.1.0`
- Windows x86-64: `hxxps://23.254.165[.]112:9089/rust-crate_0.2.0`
- macOS x86-64: `hxxps://23.254.165[.]112:9089/rust-crate_0.3.0`
- macOS ARM64: `hxxps://23.254.165[.]112:9089/rust-crate_0.4.0`

**Unix execution:** Payload written to `/tmp/rust-setup`, marked executable, launched as a detached process with the C2 address as an argument. Parent process abandoned via `std::mem::forget(child)` to escape the Cargo job object.

**Windows execution:** Payload written as `%TEMP%\rust-setup.ps1` (PowerShell script), launched via `%TEMP%\rust-setup-launch.vbs` under `wscript.exe` with a hidden window to avoid console visibility.

### 3. C2 Infrastructure

| Component | Value | Role |
|-----------|-------|------|
| Primary payload host | 23.254.165[.]112:9089 | Stage-2 binary download (TLS, no cert validation) |
| Primary C2 | 23.254.165[.]112:443 | Command-and-control beacon endpoint |
| Secondary C2 | 23.254.167[.]107:443 | Reported active at time of publication |
| Tertiary C2 | 23.254.167[.]216 | Observed in victim traffic on Linux systems |
| C2 hostname | hwsrv-798836[.]hostwindsdns[.]com | Hostwinds VPS hostname |
| C2 beacon path | `/49890878` (HTTPS POST) | Used in Mastra campaign attributed to DPRK |
| SSL issuer | `WIN-A6QF8AHPQH1\Administrator@WIN-A6QF8AHPQH1` | Self-signed certificate; shared with Mastra infrastructure |
| Encryption | AES-128-GCM, hardcoded key `i am botking` | C2 comms encryption |
| Authentication | RSA-2048 private key | Embedded in payload |

The stage-2 implant supports four commands: `kill` (self-terminate), `minicfg` (C2 reconfiguration), `startup` (install persistence), and `runscript` (download and execute additional scripts).

A domain generation algorithm (DGA) produces 10 `.com` domains every 5 days as fallback C2 channels. Reported DGA domains for Aug 20-24, 2026: `rasGThauFD[.]com`, `feVVKIiEiU[.]com`, `phrpjTNckF[.]com`, `PrOkXLgfjW[.]com`, `ackeoTaWtl[.]com`, `GAFWVCMAja[.]com`, `RNSsddnEgK[.]com`, `pfHlVOqEeg[.]com`, `aBEcOrkups[.]com`, `epOdIaTMaM[.]com`.

### 4. Platform-Specific Behavior

#### Linux

- **Dropper path:** `/tmp/rust-setup`
- **Persistence:** systemd user service (auto-restart configured)
- **Persistence directories:** `$HOME/.config/AzureKits/`, `$HOME/.config/ServiceKit/`
- **Executables:** `MonoService`, `MonoXpc`
- **C2:** Connects to secondary C2 at 23.254.167[.]216

#### Windows

- **Dropper paths:** `%TEMP%\rust-setup.ps1`, `%TEMP%\rust-setup-launch.vbs`, `%TEMP%\rust-setup.ps1.cfg`
- **Launcher:** `wscript.exe` executes VBS to launch PowerShell with hidden window
- **Persistence:** Registry Run key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
- **Credential theft:** Downloads SQLite tools (`%TEMP%\sqlite_<GUID>\sqlite-tools.zip`), copies browser Login Data databases (`%TEMP%\login_<GUID>\Login Data`), queries credentials from Chrome, Brave, and Edge
- **Additional scripts:** `%TEMP%\ps-<GUID>.ps1`, `%APPDATA%\<operator-controlled folder>\<name>.ps1`

#### macOS

- **Dropper path:** `/tmp/rust-setup`
- **Persistence:** LaunchAgent

### 5. Anti-Forensics / Evasion Techniques

- **TLS certificate validation bypass:** Custom `AcceptAll` verifier prevents certificate-based detection
- **Base64 fragmentation:** C2 URL split across multiple encoded strings to evade static analysis
- **Process abandonment:** `std::mem::forget(child)` detaches the payload process from the cargo build process tree
- **Version yanking:** Legitimate versions yanked to force dependency resolution to the poisoned release
- **Clean decoy:** `proc-macro1@1.0.106` published as a genuine copy of `proc-macro2` before the weaponized 1.0.107, establishing a benign publishing history
- **Hidden window:** Windows variant uses `wscript.exe` + VBS to launch PowerShell without a console window

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `23.254.165[.]112`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Clean Version | Description |
|---------------------|-------------------|---------------|-------------|
| arrayref | 0.3.10 | 0.3.9 | Added `proc-macro1` dependency; versions 0.3.5-0.3.9 yanked |
| internment | 0.8.7 | 0.8.6 | Added `proc-macro1` dependency |
| append-only-vec | 0.1.9 | 0.1.8 | Added `proc-macro1` dependency |
| proc-macro1 | 1.0.107 (malicious), 1.0.106 (decoy) | N/A (typosquat) | Weaponized build.rs dropper |
| proc-macro-en | all versions | N/A (typosquat) | Attacker-owned dropper crate |
| aovine | all versions | N/A | Attacker-owned crate |
| arone | all versions (7 versions) | N/A | Attacker-owned, malicious build scripts |
| aronenao | all versions (11 versions) | N/A | Attacker-owned, malicious build scripts |
| tinymember | all versions (2 versions) | N/A | Same owner, no malicious payload confirmed |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | arrayref-0.3.10.crate | 25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae | Poisoned crate archive |
| All | proc-macro1-1.0.107.crate | 61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4 | Weaponized dropper crate |
| All | proc-macro1-1.0.106.crate | b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436 | Clean decoy crate |
| All | proc-macro-en-1.0.10.crate | 8ed7d2d62d283a7701213e7a07191ebf5ab4d4862a0272b6ecda1209f6e0b93a | Attacker crate |
| All | build.rs (shared) | cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568 | Malicious build script |
| Linux | /tmp/rust-setup (stage-2) | 408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434 | Linux x86-64 payload |
| Windows | %TEMP%\rust-setup.ps1 (stage-2) | 492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391 | Windows x86-64 payload (SHA1: fc0fdb978eac72f4484b48db058e4473f1bc516e, MD5: 0ea14afc05408181cf65195a6eeede04) |
| macOS | /tmp/rust-setup (stage-2, x64) | c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848 | macOS x86-64 payload |
| macOS | /tmp/rust-setup (stage-2, arm64) | 74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306 | macOS ARM64 payload |
| Unix/macOS | /tmp/rust-setup | (see above per platform) | Stage-1 dropped executable |
| Windows | %TEMP%\rust-setup.ps1 | (see above) | Stage-1 PowerShell dropper |
| Windows | %TEMP%\rust-setup-launch.vbs | -- | VBScript launcher |
| Windows | %TEMP%\rust-setup.ps1.cfg | -- | Configuration file |
| Linux | $HOME/.config/AzureKits/ | -- | Stage-2 persistence directory |
| Linux | $HOME/.config/ServiceKit/ | -- | Stage-2 persistence directory |
| Linux | MonoService, MonoXpc | -- | Stage-2 persistence executables |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 23.254.165[.]112:9089 | Primary payload delivery host (TLS) |
| IP | 23.254.165[.]112:443 | Primary C2 server |
| IP | 23.254.167[.]107:443 | Secondary C2 server |
| IP | 23.254.167[.]216 | Tertiary C2 (victim-reported) |
| Domain | hwsrv-798836[.]hostwindsdns[.]com | Hostwinds VPS hostname |
| URL Pattern | hxxps://23.254.165[.]112:9089/rust-crate_0.[1-4].0 | Platform-specific payload download |
| URL Pattern | hxxps://23.254.165[.]112:443/49890878 | C2 beacon POST endpoint |
| DGA | rasGThauFD[.]com, feVVKIiEiU[.]com, phrpjTNckF[.]com, PrOkXLgfjW[.]com, ackeoTaWtl[.]com | DGA fallback C2 domains (Aug 20-24) |
| DGA | GAFWVCMAja[.]com, RNSsddnEgK[.]com, pfHlVOqEeg[.]com, aBEcOrkups[.]com, epOdIaTMaM[.]com | DGA fallback C2 domains (Aug 20-24) |
| Email | rchaitm[at]gmail[.]com | Forged author metadata on proc-macro1 |

### Behavioral

- **Build-time execution:** `cargo build`/`check`/`test` triggers `build.rs` which downloads and executes a binary -- any network connection during Rust compilation to IP ranges 23.254.164.0/23 or 23.254.167.0/24 is suspicious
- **Process tree anomaly:** Cargo-spawned detached child process persisting after build completion (parent abandonment via `std::mem::forget`)
- **Windows execution chain:** `cargo.exe` -> `build.rs` -> writes `rust-setup.ps1` + `rust-setup-launch.vbs` -> `wscript.exe` -> `powershell.exe` (hidden window)
- **Browser credential access:** SQLite queries against Chrome/Brave/Edge `Login Data` databases from non-browser processes
- **DGA pattern:** 10-character mixed-case alphanumeric `.com` domains queried every 5 days

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Compromised maintainer account used to inject malicious dependency into popular Rust crates |
<!-- revision: removed T1199 (Trusted Relationship describes third-party org access, not package registry trust; T1195.002 already covers the supply-chain vector) -->
| T1059.001 | Command and Scripting Interpreter: PowerShell | Windows payload delivered as PowerShell script (`rust-setup.ps1`) |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | VBScript launcher (`rust-setup-launch.vbs`) used to execute PowerShell hidden |
| T1105 | Ingress Tool Transfer | Build script downloads stage-2 payload from C2 over TLS |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Windows persistence via `HKCU\...\CurrentVersion\Run` |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via systemd user service |
| T1547.011 | Boot or Logon Autostart Execution: Plist Modification | macOS persistence via LaunchAgent |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | SQLite queries against Chrome/Brave/Edge Login Data databases |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST beaconing to `/49890878` endpoint |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | 10 `.com` domains generated every 5 days as fallback C2 |
<!-- revision: removed T1553.004 (attack uses in-code AcceptAll TLS verifier bypass, does NOT install a root certificate on the host) -->
| T1036.005 | Masquerading: Match Legitimate Name or Location | `proc-macro1` typosquats `proc-macro2`; persistence dirs named `AzureKits`, `ServiceKit` |

## Impact Assessment

- **arrayref:** 245,385,500 all-time downloads; 53,905,601 downloads in the 90 days preceding the attack; 403 dependent crate versions
- **Combined reach:** ~264 million downloads across the three poisoned crates
- **Dependency chains affected:** blake3, blake2b_simd, blake2s_simd, winit (49.8M downloads), egui, Solana tooling, Ethereum infrastructure
- **Exposure window:** 86-107 minutes per poisoned crate
- **RustSec assessment:** "No evidence of actual usage" of malicious versions during the window, though build-time execution may not have generated registry-level telemetry

## Detection & Remediation

### Immediate Detection

Check for cached malicious crates on developer workstations and CI/CD systems:

```bash
# Search for poisoned crates in Cargo cache
find ~/.cargo/registry/cache -type f \( \
    -name 'arrayref-0.3.10.crate' -o \
    -name 'append-only-vec-0.1.9.crate' -o \
    -name 'internment-0.8.7.crate' -o \
    -name 'proc-macro1-*' -o \
    -name 'proc-macro-en-*' -o \
    -name 'aovine-*' -o \
    -name 'arone-*' -o \
    -name 'aronenao-*' \
\) 2>/dev/null

# Check Cargo.lock for malicious versions
grep -rn 'arrayref.*0\.3\.10\|proc-macro1\|proc-macro-en\|aovine\|arone\|aronenao' Cargo.lock

# Check for stage-1 dropper artifacts
ls -la /tmp/rust-setup 2>/dev/null
ls -la "$TEMP/rust-setup.ps1" "$TEMP/rust-setup-launch.vbs" 2>/dev/null

# Check for stage-2 persistence (Linux)
ls -la ~/.config/AzureKits/ ~/.config/ServiceKit/ 2>/dev/null
systemctl --user list-units | grep -i 'mono\|azure\|service'

# Check for network connections to known C2
ss -tnp | grep -E '23\.254\.165\.112|23\.254\.167\.(107|216)'
```

### Remediation

1. **Containment:** Isolate any build system that downloaded the affected crate versions. Treat the build host as compromised.
2. **Eradication:** Remove cached `.crate` files, delete `/tmp/rust-setup` or `%TEMP%\rust-setup*` artifacts, remove persistence mechanisms (systemd units, LaunchAgents, Registry Run keys, `AzureKits`/`ServiceKit` directories).
3. **Credential rotation:** Rotate all browser-stored passwords and any secrets accessible from the compromised host. Revoke and reissue API keys, tokens, and certificates.
4. **Dependency lock:** Pin `arrayref` to 0.3.9, `internment` to 0.8.6, `append-only-vec` to 0.1.8. Run `cargo update` and verify `Cargo.lock` contains no reference to `proc-macro1` or the other attacker crates.
5. **Vendor audit:** If using `cargo vendor`, audit the vendor directory for the poisoned crate archives.

### Long-Term Hardening

- Enable network egress controls on CI/CD runners to detect and block unexpected connections during builds
- Monitor `build.rs` dependencies for unexpected additions of network-capable crates (`ureq`, `reqwest`, `hyper`, `rustls`)
- Consider using `cargo-vet` or `cargo-deny` to audit new dependencies before adoption
- Enable MFA on crates.io accounts and rotate API tokens regularly
- Implement build-time network monitoring (e.g., StepSecurity Harden-Runner) to detect anomalous outbound connections

## Detection Rules

These detections cover the Rust arrayref supply-chain attack across host (Sigma), file (YARA), and network (Snort, Suricata) layers at the specific/advisory altitude. Sigma rules convert to Splunk and CrowdStrike LogScale; `sigma check` could not be verified due to a proxy-blocked MITRE ATT&CK data dependency.

### Sigma: Network Connection to Arrayref C2 Infrastructure

Detects outbound connections to the three C2 IPs (23.254.165.112, 23.254.167.107, 23.254.167.216) used for payload delivery and beaconing.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (proxy blocked MITRE ATT&CK URL fetch, not a rule error); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Values are real IPs (not defanged). Sysmon network_connection logsource, Initiated=true filters to outbound only. FP: legitimate Hostwinds traffic to these exact IPs is theoretically possible but improbable. -->
```yaml
title: Network Connection to Rust Arrayref Supply Chain C2 Infrastructure
id: 8a3c1e7d-4f2b-4e9a-b6d8-1c5f3a9e7b2d
status: experimental
description: >
    Detects outbound network connections to the C2 IP addresses used in the
    August 2026 Rust crate supply-chain attack targeting arrayref, internment,
    and append-only-vec packages. The attacker used 23.254.165.112 (ports 9089
    and 443) for payload delivery and C2, with secondary C2 at 23.254.167.107
    and 23.254.167.216.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/24
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationIp:
            - '23.254.165.112'
            - '23.254.167.107'
            - '23.254.167.216'
    condition: selection
falsepositives:
    - Legitimate traffic to Hostwinds infrastructure at these specific IPs is unlikely but possible
level: critical
```

### Sigma: WScript VBS Launcher for Rust-Setup Payload

Detects `wscript.exe` launching `rust-setup-launch.vbs`, the Windows execution chain used by the build-time dropper.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Highly specific filename match. Zero expected false positives from legitimate Rust tooling. -->
```yaml
title: Rust Arrayref Supply Chain Attack - WScript VBS Launcher
id: 2b4d6f8a-1c3e-5a7b-9d0f-4e6c8b2a1d3f
status: experimental
description: >
    Detects the Windows execution chain used by the Rust crate supply-chain
    attack where wscript.exe launches a VBScript file named rust-setup-launch.vbs
    from the user temp directory to execute a hidden PowerShell payload.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/
    - https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
    - https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack
author: Actioner
date: 2026/08/24
tags:
    - attack.t1059.005
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wscript.exe'
        CommandLine|contains: 'rust-setup-launch.vbs'
    condition: selection
falsepositives:
    - Legitimate Rust tooling does not use wscript.exe or VBS launchers
level: critical
```

### Sigma: Rust-Setup Payload File Creation (Windows)

Detects creation of the stage-1 dropper files (`rust-setup.ps1`, `rust-setup-launch.vbs`, `rust-setup.ps1.cfg`) in the Windows temp directory.
**Status:** compile ✅ compiles · confidence: high
<!-- revision: replaced attack.t1204.002 (User Execution: Malicious File) with attack.t1105 (Ingress Tool Transfer) — build script creates files automatically, no user interaction required -->
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. File names are unique to this campaign. -->
```yaml
title: Rust Arrayref Supply Chain Attack - Payload File Creation
id: 5e7a9c1b-3d2f-4b6e-8a0c-6f4d2e1b9a3c
status: experimental
description: >
    Detects creation of the stage-1 dropper files associated with the Rust
    crate supply-chain attack. The malicious build script writes rust-setup
    to /tmp on Unix or rust-setup.ps1 and rust-setup-launch.vbs to the Windows
    temp directory.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/
    - https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
    - https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack
author: Actioner
date: 2026/08/24
tags:
    - attack.t1105
    - attack.t1059.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\rust-setup.ps1'
            - '\rust-setup-launch.vbs'
            - '\rust-setup.ps1.cfg'
    condition: selection
falsepositives:
    - No legitimate Rust tooling creates files with these exact names
level: critical
```

### Sigma: Stage-2 Persistence Directories (Linux)

Detects creation of `AzureKits` or `ServiceKit` directories under `$HOME/.config/` and `MonoService`/`MonoXpc` executables used for Linux persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- revision: removed attack.t1547.001 (Registry Run Keys is Windows-only, this is a Linux rule); kept attack.t1543.002 (systemd service) -->
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Directories and binary names are distinctive to this campaign. Possible FP from legitimate Azure/Mono tooling is low given the specific path combination. -->
```yaml
title: Rust Arrayref Supply Chain Attack - Stage-2 Persistence Directories
id: 7c9b1d3e-5f4a-2b6d-8e0c-4a2f6d8b1e3c
status: experimental
description: >
    Detects creation of persistence directories used by the stage-2 implant
    from the Rust crate supply-chain attack. The malware creates AzureKits
    and ServiceKit directories under the user config directory on Linux and
    drops MonoService or MonoXpc executables.
references:
    - https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/24
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection_dirs:
        TargetFilename|contains:
            - '/.config/AzureKits/'
            - '/.config/ServiceKit/'
    selection_binaries:
        TargetFilename|endswith:
            - '/MonoService'
            - '/MonoXpc'
    condition: selection_dirs or selection_binaries
falsepositives:
    - Legitimate Azure or Mono framework installations creating similarly named directories
level: high
```

### Snort: Arrayref C2 Beacon and Payload Download

Detects TCP connections to the primary C2 IP carrying the beacon path `/49890878` or payload download URI `rust-crate_0`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c snort-test.conf (with classification.config) -T exit 0. IP-pinned rules with distinctive content matches. Snort 2.9.20 validated. -->
```snort
alert tcp $HOME_NET any -> 23.254.165.112 any (msg:"Actioner - Rust Arrayref Supply Chain C2 Connection to Primary Payload Host"; flow:established,to_server; content:"/49890878"; fast_pattern; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; metadata:author Actioner, created 2026-08-24; sid:2100050; rev:1;)
alert tcp $HOME_NET any -> 23.254.165.112 9089 (msg:"Actioner - Rust Arrayref Supply Chain Payload Download from Port 9089"; flow:established,to_server; content:"rust-crate_0"; fast_pattern; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/; metadata:author Actioner, created 2026-08-24; sid:2100051; rev:1;)
```

### Suricata: TLS C2 Connection and DNS Query

Detects TLS connections to the primary C2 IP, DNS queries for the C2 hostname, and TCP connections carrying the C2 beacon path to any of the three known C2 IPs.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0 (Suricata 7.0.3). IP-pinned TLS and DNS rules. Bracket group [ip1,ip2,ip3] for multi-IP matching on beacon path rule. -->
```suricata
alert tls $HOME_NET any -> 23.254.165.112 any (msg:"Actioner - Rust Arrayref Supply Chain TLS Connection to C2"; flow:established,to_server; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; metadata:author Actioner, created_at 2026-08-24; sid:2200050; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - Rust Arrayref Supply Chain DNS Query for C2 Hostname"; dns.query; content:"hwsrv-798836.hostwindsdns.com"; nocase; fast_pattern; flow:to_server; classtype:trojan-activity; reference:url,www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack; metadata:author Actioner, created_at 2026-08-24; sid:2200051; rev:1;)
alert tcp $HOME_NET any -> [23.254.165.112,23.254.167.107,23.254.167.216] any (msg:"Actioner - Rust Arrayref Supply Chain C2 Beacon Path"; flow:established,to_server; content:"/49890878"; fast_pattern; classtype:trojan-activity; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; metadata:author Actioner, created_at 2026-08-24; sid:2200052; rev:1;)
```

### YARA: Malicious Build Script (proc-macro1 build.rs)

Detects the malicious `build.rs` via base64-encoded C2 URL fragments and the `AcceptAll` TLS verifier pattern characteristic of the proc-macro1 dropper.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- revision: changed sample status from "fired ✓" to "constructed" — positive was fabricated from published strings, not the actual malicious build.rs -->
<!-- audit: yarac exit 0. yara pos.txt matched SupplyChain_Rust_Arrayref_Malicious_BuildScript; yara neg.txt no match. Positive sample constructed from published base64 fragments (aHR0cHM6Ly8=, MjMuMjU0Lg==, MTY1Lg==, MTEyOg==, OTA4OS8=) and AcceptAll/verify_server_cert/rust-setup/std::mem::forget strings documented in multiple sources. -->
```yara
rule SupplyChain_Rust_Arrayref_Malicious_BuildScript
{
    meta:
        description = "Detects the malicious build.rs script used in the Rust arrayref/proc-macro1 supply chain attack. Keys on the base64-encoded C2 URL fragments and the AcceptAll TLS verifier pattern."
        author = "Actioner"
        date = "2026-08-24"
        reference = "https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/"
        hash = "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568"
        severity = "critical"

    strings:
        $b64_1 = "aHR0cHM6Ly8=" ascii
        $b64_2 = "MjMuMjU0Lg==" ascii
        $b64_3 = "MTY1Lg==" ascii
        $b64_4 = "MTEyOg==" ascii
        $b64_5 = "OTA4OS8=" ascii
        $accept_all = "AcceptAll" ascii
        $verify_server = "verify_server_cert" ascii
        $rust_setup = "rust-setup" ascii
        $forget = "std::mem::forget" ascii

    condition:
        filesize < 50KB and
        (3 of ($b64_*) or ($accept_all and $verify_server and $rust_setup) or ($rust_setup and $forget and 2 of ($b64_*)))
}
```

### YARA: Stage-2 Infostealer Payload

Detects the stage-2 implant via the hardcoded AES key `i am botking`, C2 beacon path `/49890878`, and command strings (`kill`, `minicfg`, `startup`, `runscript`).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. No sample available for fire test; condition combines distinctive strings (hardcoded AES key, beacon path, command set, persistence binary names) that are individually less unique but collectively discriminating. Confidence medium because no sample-based validation. -->
```yara
rule SupplyChain_Rust_Arrayref_Stage2_Payload
{
    meta:
        description = "Detects the stage-2 infostealer payload from the Rust arrayref supply chain attack via hardcoded encryption key and C2 beacon path."
        author = "Actioner"
        date = "2026-08-24"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        hash = "492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391"
        severity = "critical"

    strings:
        $key = "i am botking" ascii wide
        $beacon = "/49890878" ascii
        $cmd_kill = "kill" ascii fullword
        $cmd_minicfg = "minicfg" ascii fullword
        $cmd_startup = "startup" ascii fullword
        $cmd_runscript = "runscript" ascii fullword
        $login_data = "Login Data" ascii wide
        $mono_svc = "MonoService" ascii
        $mono_xpc = "MonoXpc" ascii

    condition:
        filesize < 20MB and
        ($key or ($beacon and 2 of ($cmd_*)) or (3 of ($cmd_*) and $login_data) or ($mono_svc and $mono_xpc))
}
```

## Lessons Learned

1. **Build-time code is an underdefended attack surface.** Rust's `build.rs` mechanism (like npm `postinstall` scripts or Python `setup.py`) executes arbitrary code with full developer privileges at compile time. The security community has focused heavily on runtime dependency risks but build-time execution remains largely unmonitored.

2. **Account compromise remains the most effective supply-chain vector.** Despite 2FA availability, a single compromised maintainer credential enabled poisoning of three packages with a combined 264 million downloads. Package registries should consider mandatory MFA, publish-time anomaly detection (new dependencies, version yanking patterns), and time-delayed publishing for high-impact packages.

3. **Typosquatting continues to evade detection.** `proc-macro1` mimicking `proc-macro2` is a trivial substitution that nonetheless passed initial scrutiny because the library source was a genuine copy. The clean decoy version (1.0.106) further established legitimacy before the weaponized 1.0.107 was deployed.

4. **Rapid response limited impact.** The 86-107 minute exposure window, while non-zero, demonstrates the value of community reporting and responsive registry operations. RustSec's assessment of "no evidence of actual usage" suggests that short exposure windows can meaningfully reduce real-world impact.

5. **DPRK-linked actors are diversifying across ecosystems.** The infrastructure overlap with Mastra (npm) and axios attacks suggests the same operational group is targeting multiple package ecosystems (npm, PyPI, and now Rust), adapting their tradecraft to each platform's build system conventions.

## Sources

- [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/) -- primary reporting with technical details on malware behavior, timeline, and IOCs
- [The Hacker News](https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html) -- detailed technical analysis including hashes, exposure windows, and dependency chain impact
- [Rust Blog](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/) -- official Rust Security Response Team incident disclosure and timeline
- [Wiz Blog](https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns) -- DPRK infrastructure overlap analysis, additional C2 IPs, SSL certificate forensics, and DGA details
- [StepSecurity Blog](https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack) -- comprehensive IOC list, stage-2 persistence analysis, compromised account details, and Harden-Runner detection telemetry
- [Marius Benthin GitHub Gist](https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf) -- exhaustive hash inventory for malicious crate archives, build scripts, and platform-specific payloads including DGA domain list

---
*Report generated by Actioner*
