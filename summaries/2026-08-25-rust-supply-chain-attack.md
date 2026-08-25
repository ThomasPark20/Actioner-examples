# Technical Analysis Report: Rust Crate Supply Chain Attack via proc-macro1 (2026-08-25)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-25
Version: 1.0 DRAFT

## Executive Summary

On August 20, 2026, a coordinated supply chain attack compromised three widely used Rust crates on crates.io --- `arrayref` (245M+ lifetime downloads), `internment`, and `append-only-vec` --- through a hijacked maintainer account. The attacker published malicious versions of these crates that injected a dependency on `proc-macro1`, a typosquat of the ubiquitous `proc-macro2` crate. The malicious `proc-macro1` package contained a `build.rs` script that silently downloaded and executed platform-specific backdoors (Linux, Windows, macOS Intel, macOS ARM64) during `cargo build`, `cargo check`, or `cargo test`. The backdoor profiled infected hosts, harvested Chromium browser credentials, established persistent C2 communication, and supported remote command execution. All malicious versions were removed within 86--107 minutes of publication, but any developer or CI system that built affected dependencies during the exposure window should be considered compromised. Wiz Research identified significant infrastructure overlap with DPRK-attributed campaigns (Mastra npm attack, axios compromise), though no vendor has issued formal attribution.

## Background: Rust Crate Ecosystem and crates.io

Crates.io is the official package registry for the Rust programming language, serving as the primary distribution channel for reusable Rust libraries ("crates"). The Rust build system, Cargo, automatically resolves and downloads dependencies from crates.io during compilation. Critically, Cargo executes `build.rs` build scripts at compile time with full system privileges, providing an attack surface equivalent to running arbitrary code on the developer's machine. The `arrayref` crate, which provides macros for creating arrays from slices, is present in over 35% of all monitored environments and in 75% of environments where Rust is used. It is a transitive dependency for 403+ other crates including cryptographic libraries, Solana/Ethereum blockchain tooling, and the `winit` windowing library (49.8M downloads).

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-18 | Attacker publishes early test crates `arone` and `aronenao` to crates.io |
| 2026-08-20 01:17:36 | GitHub account `dtolney` created (impersonating David Tolnay, `proc-macro2` author) |
| 2026-08-20 01:25:58 | crates.io account `dtolney` registered (user ID 438608) |
| 2026-08-20 01:55:34 | Clean decoy `proc-macro1@1.0.106` published (benign copy of proc-macro2) |
| 2026-08-20 07:11:15 | Weaponized `proc-macro1@1.0.107` published with malicious `build.rs` |
| 2026-08-20 07:15:00 | Compromised `arrayref@0.3.10` published with proc-macro1 dependency |
| 2026-08-20 07:15:24--07:15:40 | Five prior arrayref versions (0.3.5--0.3.9) yanked in scripted 4-second burst |
| 2026-08-20 07:29:50 | Socket AI Scanner independently detects malicious `proc-macro1` |
| 2026-08-20 07:34:07 | Compromised `internment@0.8.7` published |
| 2026-08-20 07:37:49 | Compromised `append-only-vec@0.1.9` published |
| 2026-08-20 07:54:11 | Reported to RustSec |
| 2026-08-20 08:03:09 | `proc-macro1` crate deleted (~52 minutes after weaponized publish) |
| 2026-08-20 08:41:40 | `arrayref@0.3.10` deleted (86-minute exposure window) |
| 2026-08-20 09:04:11 | `internment@0.8.7` deleted (90-minute exposure window) |
| 2026-08-20 09:25:24 | `append-only-vec@0.1.9` deleted (107-minute exposure window) |

## Root Cause: Compromised Maintainer Credentials

The attacker gained access to the crates.io publishing credentials of the legitimate maintainer of `arrayref`, `internment`, and `append-only-vec`. The Rust Security Response Team confirmed the account was compromised (the maintainer did not act maliciously) and locked it as a precaution. The exact credential compromise vector has not been publicly disclosed --- possibilities include credential theft from a compromised machine, phishing, or token leakage. Simultaneously, the attacker created a separate impersonation account (`dtolney`, mimicking David Tolnay who maintains `proc-macro2`) to publish the typosquatted `proc-macro1` crate with forged author metadata using the email `rchaitm[at]gmail[.]com`.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection (Stage 0)

Each compromised crate release added a single line to its `Cargo.toml` manifest: a dependency on `proc-macro1 ^1.0.107`. The library source code of `proc-macro1` was a genuine copy of the real `proc-macro2`, so all builds completed normally and downstream code functioned correctly. The malicious logic resided entirely in the `build.rs` build script, which Cargo executes automatically during compilation. This separation ensured that static analysis of the library code would find nothing suspicious.

Additional attacker-controlled crates (`proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember`) were published as spare droppers or test packages with identical build script payloads.

### 2. Build Script Dropper (Stage 1)

**SHA-256:** `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568`

The `build.rs` dropper in `proc-macro1@1.0.107` implemented the following attack chain:

1. **Obfuscated C2 reconstruction**: Reassembled the payload delivery URL and C2 address from Base64-encoded fragments stored in constants (`SRC_URL_PARTS` and `END_URL_PARTS`), decoding to `https://23.254.165[.]112:9089/` and `23.254.165[.]112:443` respectively.

2. **TLS validation bypass**: Added build dependencies on `base64 ^0.22`, `rustls ^0.23`, and `ureq ^2`, then implemented a custom `ServerCertVerifier` named `AcceptAll` that disabled all TLS certificate validation.

3. **Platform detection and payload selection**: Detected the target OS and architecture to select the appropriate binary:
   - `rust-crate_0.1.0` --- Linux x86_64
   - `rust-crate_0.2.0` --- Windows x86_64
   - `rust-crate_0.3.0` --- macOS x86_64
   - `rust-crate_0.4.0` --- macOS ARM64

4. **Payload delivery and execution** (platform-specific):
   - **Unix/macOS**: Downloaded binary to `/tmp/rust-setup`, set executable permission, spawned detached process with stdio nulled, used `std::mem::forget(child)` to escape Cargo's job object and survive build completion.
   - **Windows**: Wrote `rust-setup.ps1` (PowerShell payload) and `rust-setup-launch.vbs` (VBScript launcher) to `%TEMP%`, executed via `wscript.exe` with `-ExecutionPolicy Bypass` to avoid console window.

### 3. C2 Infrastructure

| Component | Value | Role |
|-----------|-------|------|
| Primary payload host | `23.254.165[.]112:9089` | Stage-2 binary download over TLS |
| Primary C2 | `23.254.165[.]112:443` | Passed as argv[1] to backdoor |
| Secondary C2 | `23.254.167[.]107:443` | Stage-2 C2 (live at time of analysis) |
| Victim-reported C2 | `23.254.167[.]216` | Additional C2 traffic observed |
| Related infrastructure | `23.254.167[.]13` | Shares SSL issuer with primary C2 |
| Hostname | `hwsrv-798836[.]hostwindsdns[.]com` | Hostwinds VPS reverse DNS |
| C2 beacon endpoint | `POST /49890878` | HTTPS POST beacon path |
| SSL certificate issuer | `WIN-A6QF8AHPQH1\Administrator@WIN-A6QF8AHPQH1` | Self-signed cert |
| Hosting provider | Hostwinds LLC | IP range `23.254.164.0/23` |
| Encryption | AES-128-GCM | Hardcoded key: `i am botking` |
| Command auth | RSA-2048 | Shared private key across all variants |
| DGA fallback | 10 `.com` domains every 5 days | Examples: `rasGThauFD[.]com`, `feVVKIiEiU[.]com`, `phrpjTNckF[.]com` |

### 4. Platform-Specific Behavior

#### Linux

- **Payload**: Downloaded to `/tmp/rust-setup`, executed detached
- **Persistence**: systemd user service with automatic restart
- **Persistence directory**: `$HOME/.config/ServiceKit/`
- **Persistence binary**: `MonoService`

#### Windows

- **Payload**: `%TEMP%\rust-setup.ps1` launched via `%TEMP%\rust-setup-launch.vbs` through `wscript.exe`
- **Persistence**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` registry key
- **Execution**: PowerShell with `-ExecutionPolicy Bypass`

#### macOS (Intel and ARM64)

- **Payload**: Downloaded to `/tmp/rust-setup`, executed detached
- **Persistence**: LaunchAgent plist
- **Persistence directory**: `$HOME/.config/AzureKits/`
- **Persistence binary**: `MonoXpc`

### 5. Stage-2 Backdoor Capabilities

The cross-platform backdoor performs:

- **System profiling**: Hostname, username, OS, architecture, privilege level, installed applications
- **Browser credential harvesting**: Queries Chromium-based browsers (Chrome, Brave, Edge) SQLite databases for login origins, usernames, and extension data (does not decrypt stored passwords)
- **HTTPS beaconing**: POST requests to `/49890878` endpoint
- **Remote command execution**: Supports four commands: `kill` (self-terminate), `minicfg` (configuration change), `startup` (establish/modify persistence), `runscript` (execute arbitrary script/command)
- **DGA fallback**: Generates 10 `.com` domains every 5 days for resilient C2 resolution

### 6. Anti-Forensics / Evasion Techniques

- **Build-time execution**: Payload runs during compilation, not at application runtime, evading runtime-focused security tools
- **TLS bypass**: Disabled certificate validation to communicate with self-signed C2
- **Base64 fragmentation**: C2 addresses split across multiple base64-encoded constants to evade static string scanning
- **Process orphaning**: Used `std::mem::forget(child)` to detach payload process from Cargo's process group
- **Typosquatting decoy**: Published a clean `proc-macro1@1.0.106` first as a benign decoy before the weaponized `1.0.107`
- **Version yanking**: Yanked arrayref versions 0.3.5--0.3.9 to force dependency resolution to the malicious 0.3.10
- **Clean library code**: Malicious logic only in `build.rs`, not in the library source, defeating code-level audits

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots
> - Email addresses: `[at]` replacing @

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `arrayref` | `0.3.10` | Injected `proc-macro1` dependency; 245M+ lifetime downloads |
| `internment` | `0.8.7` | Injected `proc-macro1` dependency; 14.4M downloads |
| `append-only-vec` | `0.1.9` | Injected `proc-macro1` dependency; 4.5M downloads |
| `proc-macro1` | `1.0.107` (weaponized), `1.0.106` (decoy) | Typosquat of `proc-macro2`; malicious build.rs dropper |
| `proc-macro-en` | `1.0.10` | Spare dropper crate, identical build script |
| `aovine` | all versions | Attacker-controlled test crate |
| `arone` | all versions | Attacker-controlled test crate |
| `aronenao` | all versions | Attacker-controlled test crate |
| `tinymember` | all versions | Attacker-controlled test crate |

### File System

| Platform | Path | Hash (SHA-256) | Description |
|----------|------|---------------|-------------|
| All | build.rs (in proc-macro1) | `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568` | Malicious build script dropper |
| All | arrayref-0.3.10.crate | `25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae` | Compromised crate archive |
| All | proc-macro1-1.0.107.crate | `61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4` | Weaponized typosquat crate |
| All | proc-macro1-1.0.106.crate | `b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436` | Benign decoy crate |
| Linux | `/tmp/rust-setup` | `408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434` | Stage-2 Linux backdoor (x86_64) |
| Windows | `%TEMP%\rust-setup.ps1` | `492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391` | Stage-2 Windows backdoor (x86_64) |
| Windows | `%TEMP%\rust-setup-launch.vbs` | N/A | VBScript launcher for PowerShell payload |
| macOS | `/tmp/rust-setup` | `c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848` | Stage-2 macOS backdoor (x86_64) |
| macOS | `/tmp/rust-setup` | `74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306` | Stage-2 macOS backdoor (ARM64) |
| Linux | `$HOME/.config/ServiceKit/MonoService` | N/A | Linux persistence binary |
| macOS | `$HOME/.config/AzureKits/MonoXpc` | N/A | macOS persistence binary |

**SHA-1 Hashes (supplementary):**

| File | SHA-1 |
|------|-------|
| proc-macro1-1.0.107.crate | `f22e3e01e38bcdf001f0d15a2dbfdec5a1cf8eff` |
| Linux stage-2 | `f4767ad92cb61401fd69139cade563501c39b991` |
| Windows stage-2 | `fc0fdb978eac72f4484b48db058e4473f1bc516e` |
| macOS ARM64 stage-2 | `ff7e20cf642346bf893f1eca808df82035bb53d0` |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `23.254.165[.]112:9089` | Payload delivery (HTTPS with disabled cert validation) |
| IP | `23.254.165[.]112:443` | Primary C2 beacon endpoint |
| IP | `23.254.167[.]107:443` | Secondary C2 (live at publication) |
| IP | `23.254.167[.]216` | Victim-reported C2 traffic |
| IP | `23.254.167[.]13` | Related infrastructure (shared SSL cert issuer) |
| Domain | `hwsrv-798836[.]hostwindsdns[.]com` | Hostwinds VPS reverse DNS for C2 |
| URL Pattern | `hxxps://23.254.165[.]112:9089/rust-crate_0.[1-4].0` | Platform-specific payload download |
| URL Pattern | `POST /49890878` | C2 beacon endpoint |
| DGA Domains | `rasGThauFD[.]com`, `feVVKIiEiU[.]com`, `phrpjTNckF[.]com` | DGA fallback domains (August 20--24 window) |
| Email | `rchaitm[at]gmail[.]com` | Forged author metadata in malicious crates |
| Account | `dtolney` (crates.io ID 438608) | Impersonation account for proc-macro1 |

### Behavioral

- Cargo/rustc build process spawning network-connected child processes (curl, wget, or direct HTTP download)
- File creation of `/tmp/rust-setup` during Cargo build operations
- `wscript.exe` launching PowerShell with `-ExecutionPolicy Bypass` and `rust-setup` in arguments
- HTTPS POST beacons to `/49890878` endpoint at regular intervals
- Creation of `.config/AzureKits/` or `.config/ServiceKit/` directories under user home
- systemd user service or LaunchAgent plist creation from a build process context
- Presence of `proc-macro1` in `Cargo.lock` or `~/.cargo/registry/cache/`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Injected malicious `proc-macro1` dependency into three legitimate crates via compromised maintainer account |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Windows variant executes PowerShell with `-ExecutionPolicy Bypass` via VBScript launcher |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Unix variants spawn shell processes to execute downloaded payload |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | Windows variant uses VBScript (`rust-setup-launch.vbs`) to launch PowerShell without console window |
| T1105 | Ingress Tool Transfer | Downloads platform-specific stage-2 backdoor from C2 during build |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST beacons to `/49890878` endpoint for C2 |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA-2048 command authentication and AES-128-GCM encrypted C2 |
| T1547.001 | Boot or Logon Autostart: Registry Run Keys | Windows persistence via `HKCU\...\CurrentVersion\Run` |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via systemd user service |
| T1547.011 | Boot or Logon Autostart: Plist Modification | macOS persistence via LaunchAgent plist |
| T1555.003 | Credentials from Password Stores: Web Browsers | Harvests Chromium browser credential store (Chrome, Brave, Edge) |
| T1082 | System Information Discovery | Profiles hostname, OS, architecture, privilege level |
| T1033 | System Owner/User Discovery | Enumerates username and account context |
| T1518 | Software Discovery | Inventories installed applications and browser extensions |
| T1140 | Deobfuscate/Decode Files or Information | Base64-fragmented C2 addresses reassembled at build time |
| T1553.004 | Subvert Trust Controls: Install Root Certificate | Disabled TLS certificate validation via custom `AcceptAll` verifier |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | 10 `.com` DGA domains generated every 5 days as C2 fallback |

## Impact Assessment

**Breadth**: `arrayref` has 245 million lifetime downloads and is a transitive dependency for 403+ crate versions. Wiz Research found it present in over 35% of all monitored environments and in 75% of Rust-using environments. The 90-day download window preceding the attack saw 53.9 million downloads. However, the malicious version was only available for 86 minutes, substantially limiting the blast radius compared to the theoretical maximum.

**Depth**: Any system that resolved the malicious dependency during the 86--107 minute window and executed `cargo build`, `cargo check`, or `cargo test` would have had a persistent backdoor installed with browser credential harvesting, remote command execution, and established persistence. CI/CD pipelines with uncached dependencies are at highest risk.

**Stealth**: The attack exploited build-time execution, a phase often not monitored by endpoint security tools. The clean library code, benign decoy version, and version yanking to force resolution to the malicious release demonstrate operational sophistication.

**Attribution indicators**: Wiz Research identified significant overlap with DPRK-attributed campaigns including the identical C2 endpoint path `/49890878` used in the Microsoft-attributed Mastra npm attack, shared SSL certificate issuers, and predominantly Hostwinds IP infrastructure in the `23.254.164.0/23` range.

## Detection & Remediation

### Immediate Detection

Check if your local Cargo cache contains any of the malicious crate versions:

```bash
# Search local Cargo registry cache for malicious versions
find ~/.cargo/registry/cache -name "arrayref-0.3.10.crate" \
  -o -name "internment-0.8.7.crate" \
  -o -name "append-only-vec-0.1.9.crate" \
  -o -name "proc-macro1-*.crate" 2>/dev/null

# Check Cargo.lock files in all projects for proc-macro1 dependency
grep -r "proc-macro1" ~/projects/*/Cargo.lock 2>/dev/null

# Check for stage-2 payload artifacts
ls -la /tmp/rust-setup 2>/dev/null
ls -la "$HOME/.config/AzureKits/" "$HOME/.config/ServiceKit/" 2>/dev/null

# Check for persistence (Linux)
systemctl --user list-units | grep -i "mono\|rust\|azure\|service.kit"

# Check for persistence (macOS)
ls ~/Library/LaunchAgents/ | grep -i "mono\|rust\|azure"
```

```powershell
# Windows: Check for payload artifacts
Get-Item "$env:TEMP\rust-setup*" -ErrorAction SilentlyContinue

# Check for Run key persistence
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | 
  Select-String -Pattern "rust-setup|MonoService|AzureKits|ServiceKit"
```

### Remediation

1. **Containment**: Isolate any host confirmed to have built the malicious dependency versions. Disconnect from network to prevent further C2 communication.

2. **Eradication**:
   - Remove payload artifacts: `/tmp/rust-setup`, `%TEMP%\rust-setup*`
   - Remove persistence directories: `$HOME/.config/AzureKits/`, `$HOME/.config/ServiceKit/`
   - Remove persistence binaries: `MonoService`, `MonoXpc`
   - Remove persistence mechanisms: systemd user services, LaunchAgent plists, Run registry keys
   - Purge malicious crate versions from local Cargo cache

3. **Credential rotation**: Treat the affected host as fully compromised:
   - Rotate all credentials stored on or accessible from the host
   - Reset all browser-stored passwords (Chrome, Brave, Edge)
   - Revoke and regenerate CI/CD secrets, API tokens, SSH keys, signing keys
   - Review and revoke any crates.io, npm, PyPI, or other package registry tokens

4. **Forensic analysis**: Examine build logs for the 07:11--09:25 UTC window on August 20, 2026, focusing on dependency resolution events that pulled `proc-macro1`.

### Long-Term Hardening

- **Lock dependency versions**: Use `Cargo.lock` in version control and audit dependency changes in code review
- **Verify checksums**: Enable `cargo-audit` and integrate `cargo-deny` in CI to catch typosquat and advisory violations
- **Restrict build-time network access**: Run builds in sandboxed environments that block outbound network connections
- **Monitor build processes**: Alert on build tool processes (cargo, rustc) spawning network-connected children
- **Enable 2FA on package registries**: Require multi-factor authentication for all crate publishing accounts
- **Adopt sigstore/signing**: Use cryptographic signing for crate releases once available

## Detection Rules

Five Sigma rules, three YARA rules, and four Suricata rules target the concrete IOCs and behavioral patterns from this attack: C2 infrastructure, payload file paths, build-time process anomalies, registry persistence, and network beaconing. Sigma check could not run (MITRE ATT&CK data download blocked by environment proxy), so Sigma validation relied on successful `sigma convert` to Splunk and LogScale backends.

### Sigma: Cargo Build Process Spawning Suspicious Payload Execution

Detects cargo/rustc build processes spawning child processes that reference the known payload paths or filenames.

compile: sigma convert to splunk/log_scale -- PASS | confidence: medium

<!--
VALIDATION: sigma convert --without-pipeline -t splunk PASS. sigma convert -t log_scale PASS. sigma check blocked (HTTP 403 on MITRE ATT&CK data download via proxy). Fields use Sysmon process_creation schema (ParentImage, Image, CommandLine). Values are not defanged per logsource-encoding rules. Medium confidence: pattern depends on ParentImage matching cargo/rustc which varies by installation path.
-->

```yaml
title: Cargo Build Process Spawning Suspicious Payload Execution
id: 7c3e8a1f-4b2d-4e9a-b6f5-1d8c0a3e7f2b
status: experimental
description: >
    Detects cargo or rustc build processes spawning suspicious child processes
    that write or execute payloads in temporary directories. This pattern was
    observed in the proc-macro1 supply chain attack where a malicious build.rs
    script downloaded and executed platform-specific backdoors during compilation.
references:
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
    - https://socket.dev/blog/popular-rust-crates-compromised
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/25
tags:
    - attack.t1195.001
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/cargo'
            - '/rustc'
    selection_child:
        Image|endswith:
            - '/curl'
            - '/wget'
            - '/sh'
            - '/bash'
        CommandLine|contains:
            - '/tmp/rust-setup'
            - 'rust-crate_'
            - 'rust-setup'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate build scripts that download dependencies at build time
    - Custom Rust build scripts with atypical network activity
level: high
```

### Sigma: Rust Supply Chain Attack Payload File Creation

Detects creation of payload artifacts and persistence directories specific to this attack across all platforms.

compile: sigma convert to splunk/log_scale -- PASS | confidence: high

<!--
VALIDATION: sigma convert --without-pipeline -t splunk PASS. sigma convert -t log_scale PASS. High confidence: file paths /tmp/rust-setup, rust-setup.ps1, rust-setup-launch.vbs, .config/AzureKits, .config/ServiceKit, MonoService, MonoXpc are specific IOCs from the attack with low false positive risk. Uses file_event category with TargetFilename field.
-->

```yaml
title: Rust Supply Chain Attack Payload File Creation
id: a9d4f2b8-1c6e-4a3d-8e7f-5b0c9d2a1e3f
status: experimental
description: >
    Detects creation of payload files associated with the proc-macro1 Rust supply
    chain attack. The malicious build.rs downloads platform-specific binaries and
    writes them to /tmp/rust-setup (Unix) or %TEMP%\rust-setup.ps1 and
    rust-setup-launch.vbs (Windows). Also detects creation of persistence artifacts
    in .config/AzureKits and .config/ServiceKit directories.
references:
    - https://socket.dev/blog/popular-rust-crates-compromised
    - https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack
author: Actioner
date: 2026/08/25
tags:
    - attack.t1195.001
    - attack.t1105
logsource:
    category: file_event
detection:
    selection_unix:
        TargetFilename|contains:
            - '/tmp/rust-setup'
    selection_windows:
        TargetFilename|endswith:
            - '\rust-setup.ps1'
            - '\rust-setup-launch.vbs'
    selection_persistence:
        TargetFilename|contains:
            - '.config/AzureKits'
            - '.config/ServiceKit'
            - '/MonoService'
            - '/MonoXpc'
    condition: selection_unix or selection_windows or selection_persistence
falsepositives:
    - Legitimate software using similar naming conventions in temp directories
level: critical
```

### Sigma: Rust Supply Chain Attack Windows Payload Execution via WScript

Detects the specific Windows execution chain: wscript.exe launching PowerShell with ExecutionPolicy Bypass referencing rust-setup.

compile: sigma convert to splunk/log_scale -- PASS | confidence: high

<!--
VALIDATION: sigma convert --without-pipeline -t splunk PASS. sigma convert -t log_scale PASS. High confidence: the three-condition AND (ParentImage wscript.exe + Image powershell + CommandLine contains ExecutionPolicy+Bypass+rust-setup) is highly specific to this attack chain with minimal FP surface.
-->

```yaml
title: Rust Supply Chain Attack Windows Payload Execution via WScript
id: b5e7c3d1-2f8a-4b6e-9d0c-4a1f3e8b7c2d
status: experimental
description: >
    Detects wscript.exe launching a VBScript that executes a PowerShell payload
    with ExecutionPolicy Bypass, as observed in the Windows variant of the
    proc-macro1 Rust supply chain attack. The build.rs dropper writes a .vbs
    launcher and .ps1 payload to %TEMP% and executes via wscript.
references:
    - https://socket.dev/blog/popular-rust-crates-compromised
    - https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack
author: Actioner
date: 2026/08/25
tags:
    - attack.t1059.001
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_wscript:
        ParentImage|endswith: '\wscript.exe'
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'ExecutionPolicy'
            - 'Bypass'
            - 'rust-setup'
    condition: selection_wscript and selection_powershell
falsepositives:
    - Legitimate software installers using similar execution chains
level: critical
```

### Sigma: Network Connection to Rust Supply Chain Attack C2 Infrastructure

Detects outbound connections to the known C2 IP addresses and Hostwinds hostname used in this campaign.

compile: sigma convert to splunk/log_scale -- PASS | confidence: high

<!--
VALIDATION: sigma convert --without-pipeline -t splunk PASS. sigma convert -t log_scale PASS. High confidence: IP addresses are confirmed C2 infrastructure from Wiz and Socket research. Risk of FP only after IP reassignment by Hostwinds. DestinationIp and DestinationHostname are standard network_connection fields.
-->

```yaml
title: Network Connection to Rust Supply Chain Attack C2 Infrastructure
id: c8f1d4e6-3a9b-4c7e-8f2d-6b5a0e3c1d9f
status: experimental
description: >
    Detects outbound network connections to IP addresses and domains used by
    the proc-macro1 Rust supply chain attack C2 infrastructure hosted on
    Hostwinds VPS. The attacker used 23.254.165.112 for payload delivery
    (port 9089) and C2 (port 443), with additional C2 nodes at
    23.254.167.107, 23.254.167.216, and 23.254.167.13.
references:
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
    - https://socket.dev/blog/popular-rust-crates-compromised
author: Actioner
date: 2026/08/25
tags:
    - attack.t1071.001
    - attack.t1573.002
logsource:
    category: network_connection
detection:
    selection_ip:
        DestinationIp:
            - '23.254.165.112'
            - '23.254.167.107'
            - '23.254.167.216'
            - '23.254.167.13'
    selection_domain:
        DestinationHostname|contains: 'hwsrv-798836.hostwindsdns.com'
    condition: selection_ip or selection_domain
falsepositives:
    - Legitimate services hosted on the same Hostwinds IP addresses after infrastructure turnover
level: critical
```

### Sigma: Rust Supply Chain Attack Windows Registry Persistence

Detects Run key persistence entries containing known payload and persistence binary names.

compile: sigma convert to splunk/log_scale -- PASS | confidence: high

<!--
VALIDATION: sigma convert --without-pipeline -t splunk PASS. sigma convert -t log_scale PASS. High confidence: targets Run key writes containing attack-specific strings (rust-setup, MonoService, AzureKits, ServiceKit). Uses registry_set category with TargetObject and Details fields per Sysmon EID 13 schema.
-->

```yaml
title: Rust Supply Chain Attack Windows Registry Persistence
id: d2a5b8c7-4e1f-4d3a-9c6b-7f0e8d1a2b5c
status: experimental
description: >
    Detects the Windows persistence mechanism used by the proc-macro1 Rust
    supply chain backdoor, which creates a Run registry key for automatic
    execution at user logon. The malware establishes persistence under
    HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
references:
    - https://socket.dev/blog/popular-rust-crates-compromised
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/25
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\CurrentVersion\Run'
        Details|contains:
            - 'rust-setup'
            - 'MonoService'
            - 'AzureKits'
            - 'ServiceKit'
    condition: selection
falsepositives:
    - Legitimate software using similar binary names for auto-start entries
level: critical
```

### YARA: Supply Chain Rust Crate proc-macro1 Build Script Dropper

Detects the malicious `build.rs` dropper by matching characteristic string combinations (URL fragment constants, payload names, drop paths, TLS bypass).

compile: yarac -- PASS | confidence: high

<!--
VALIDATION: yarac /tmp/actioner/rust-sc-yara.yar /dev/null exit 0. High confidence: condition requires 2+ of 5 unique dropper artifacts (SRC_URL_PARTS, END_URL_PARTS, AcceptAll, std::mem::forget, ureq) or 2+ payload version strings, or a drop path + payload name combination. filesize < 100KB bounds scan scope. All strings are ascii non-defanged per logsource-encoding rules.
-->

```yara
rule SupplyChain_RustCrate_ProcMacro1_BuildScript
{
    meta:
        description = "Detects the malicious build.rs dropper from the proc-macro1 Rust supply chain attack that downloads and executes platform-specific backdoors during cargo build"
        author = "Actioner"
        date = "2026-08-25"
        reference = "https://socket.dev/blog/popular-rust-crates-compromised"
        hash = "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568"
        severity = "critical"

    strings:
        $src_url = "SRC_URL_PARTS" ascii
        $end_url = "END_URL_PARTS" ascii
        $payload1 = "rust-crate_0.1.0" ascii
        $payload2 = "rust-crate_0.2.0" ascii
        $payload3 = "rust-crate_0.3.0" ascii
        $payload4 = "rust-crate_0.4.0" ascii
        $drop_unix = "/tmp/rust-setup" ascii
        $drop_win = "rust-setup.ps1" ascii
        $drop_vbs = "rust-setup-launch.vbs" ascii
        $tls_bypass = "AcceptAll" ascii
        $forget = "std::mem::forget" ascii
        $dep_ureq = "ureq" ascii

    condition:
        filesize < 100KB and
        (
            (2 of ($src_url, $end_url, $tls_bypass, $forget, $dep_ureq)) or
            (2 of ($payload*)) or
            (1 of ($drop_unix, $drop_win, $drop_vbs) and 1 of ($payload*))
        )
}
```

### YARA: Supply Chain Rust Crate Stage-2 Backdoor

Detects the cross-platform backdoor binary by matching the C2 beacon path, encryption key, command strings, and persistence artifacts.

compile: yarac -- PASS | confidence: high

<!--
VALIDATION: yarac exit 0. High confidence: condition requires the unique C2 path "/49890878" combined with the hardcoded AES key "i am botking", or the AES key + 2 command strings, or 2 persistence artifacts + C2 path. These are forensically confirmed strings from analyzed samples with SHA-256 hashes in meta.
-->

```yara
rule SupplyChain_RustCrate_Stage2_Backdoor
{
    meta:
        description = "Detects the stage-2 cross-platform backdoor dropped by the proc-macro1 Rust supply chain attack, targeting browser credentials and establishing persistent C2"
        author = "Actioner"
        date = "2026-08-25"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        hash = "408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434"
        severity = "critical"

    strings:
        $c2_path = "/49890878" ascii
        $enc_key = "i am botking" ascii wide
        $cmd1 = "minicfg" ascii
        $cmd2 = "runscript" ascii
        $cmd3 = "startup" ascii
        $persist_dir1 = "AzureKits" ascii
        $persist_dir2 = "ServiceKit" ascii
        $persist_bin1 = "MonoService" ascii
        $persist_bin2 = "MonoXpc" ascii
        $browser1 = "Login Data" ascii wide
        $browser2 = "Web Data" ascii wide

    condition:
        filesize < 20MB and
        (
            ($c2_path and $enc_key) or
            ($enc_key and 2 of ($cmd*)) or
            (2 of ($persist_dir*, $persist_bin*) and $c2_path) or
            ($c2_path and 1 of ($cmd*) and 1 of ($browser*))
        )
}
```

### YARA: Malicious Crate Archive Detection

Detects known malicious `.crate` archive files by matching package name and version identifiers.

compile: yarac -- PASS | confidence: medium

<!--
VALIDATION: yarac exit 0. Medium confidence: condition matches on package name + version strings within archives, which could theoretically match discussion/analysis documents. The filesize < 5MB constraint and requirement for build.rs + proc-macro1 + version combinations reduces FP risk. Lower confidence than the other YARA rules due to string generality.
-->

```yara
rule SupplyChain_RustCrate_Malicious_Crate_Archive
{
    meta:
        description = "Detects known malicious .crate archive files from the proc-macro1 supply chain attack by matching unique content patterns"
        author = "Actioner"
        date = "2026-08-25"
        reference = "https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack"
        hash = "61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4"
        severity = "critical"

    strings:
        $crate_name = "proc-macro1" ascii
        $version107 = "1.0.107" ascii
        $build_rs = "build.rs" ascii
        $dep_inject = "proc-macro1" ascii
        $arrayref_mal = "arrayref" ascii
        $version310 = "0.3.10" ascii

    condition:
        filesize < 5MB and
        $build_rs and
        (
            ($crate_name and $version107) or
            ($dep_inject and ($arrayref_mal and $version310))
        )
}
```

### Suricata: C2 Beacon POST to /49890878

Detects HTTPS POST requests to the `/49890878` C2 beacon endpoint used by both this campaign and the DPRK-attributed Mastra attack.

compile: suricata -T -- PASS | confidence: high

<!--
VALIDATION: suricata -T -S /tmp/actioner/rust-sc-suricata.rules -l /tmp/actioner exit 0 ("Configuration provided was successfully loaded"). High confidence: /49890878 is a unique C2 endpoint path confirmed by Wiz and Socket research, also observed in DPRK Mastra campaign. HTTP POST + specific URI is precise. Requires TLS inspection/decryption to see HTTPS content.
-->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Rust Supply Chain Attack C2 Beacon POST to /49890878"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/49890878"; startswith; fast_pattern; classtype:trojan-activity; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; metadata:author Actioner, created_at 2026-08-25; sid:2100101; rev:1;)
```

### Suricata: Payload Download from C2 Host

Detects HTTP requests to the primary C2 IP for platform-specific payload files matching the `rust-crate_0.` naming pattern.

compile: suricata -T -- PASS | confidence: high

<!--
VALIDATION: suricata -T exit 0. High confidence: combines specific destination IP (23.254.165.112) with URI pattern matching the four payload download paths. Requires TLS inspection to see URI in HTTPS traffic.
-->

```
alert http $HOME_NET any -> 23.254.165.112 any (msg:"Actioner - Rust Supply Chain Attack Payload Download from C2 Host"; flow:established,to_server; http.uri; content:"/rust-crate_0."; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/popular-rust-crates-compromised; metadata:author Actioner, created_at 2026-08-25; sid:2100102; rev:1;)
```

### Suricata: TLS Connection to C2 Infrastructure IPs

Detects TLS connections to the four confirmed C2 IP addresses on port 443.

compile: suricata -T -- PASS | confidence: high

<!--
VALIDATION: suricata -T exit 0. High confidence: IP addresses are confirmed C2 from Wiz/Socket research. No TLS inspection needed - matches on connection metadata. FP risk only after IP reassignment by Hostwinds.
-->

```
alert tls $HOME_NET any -> [23.254.165.112,23.254.167.107,23.254.167.216,23.254.167.13] 443 (msg:"Actioner - TLS Connection to Rust Supply Chain Attack C2 Infrastructure"; flow:established,to_server; classtype:trojan-activity; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; metadata:author Actioner, created_at 2026-08-25; sid:2100103; rev:1;)
```

### Suricata: DNS Query for C2 Domain

Detects DNS queries for the Hostwinds reverse DNS hostname associated with the C2 infrastructure.

compile: suricata -T -- PASS | confidence: high

<!--
VALIDATION: suricata -T exit 0. High confidence: hwsrv-798836.hostwindsdns.com is the confirmed reverse DNS for the C2 VPS. DNS query matching does not require TLS inspection.
-->

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query for Rust Supply Chain Attack C2 Domain"; dns.query; content:"hwsrv-798836.hostwindsdns.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/popular-rust-crates-compromised; metadata:author Actioner, created_at 2026-08-25; sid:2100104; rev:1;)
```

### Snort (uninstalled -- rules uncompiled)

Snort 3 is not installed in this environment. The following rules are structurally validated but could not be compile-tested.

compile: NOT installed | confidence: medium

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Rust Supply Chain C2 Beacon POST to /49890878"; flow:established, to_server; http_method; content:"POST"; http_uri; content:"/49890878", fast_pattern; classtype:trojan-activity; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; metadata:author Actioner, created 2026-08-25; sid:2100201; rev:1;)
```

```
alert http $HOME_NET any -> 23.254.165.112 any (msg:"Actioner - Rust Supply Chain Payload Download from C2 Host"; flow:established, to_server; http_uri; content:"/rust-crate_0.", fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/popular-rust-crates-compromised; metadata:author Actioner, created 2026-08-25; sid:2100202; rev:1;)
```

## Lessons Learned

1. **Build-time execution is an undermonitored attack surface.** Cargo's `build.rs` scripts run with full system privileges during compilation. Most endpoint detection tools focus on runtime execution, leaving build-time code execution as a blind spot. Organizations should sandbox build environments and restrict outbound network access from build processes.

2. **Typosquatting remains devastatingly effective.** The `proc-macro1`/`proc-macro2` typosquat exploited developer trust in a nearly-identically-named package. The clean decoy version (1.0.106) published before the weaponized version (1.0.107) added another layer of plausible legitimacy.

3. **Account compromise amplifies supply chain risk.** A single compromised maintainer account enabled the attacker to inject malicious dependencies into three legitimate crates simultaneously. The version-yanking tactic (removing 0.3.5--0.3.9 to force resolution to 0.3.10) demonstrates sophisticated package registry manipulation.

4. **Rapid response limits blast radius but cannot eliminate it.** Despite detection within 45 minutes and full remediation within 2 hours, the 86--107 minute exposure window was sufficient to compromise any uncached CI/CD pipeline or developer workstation that built during that period.

5. **Infrastructure reuse enables attribution.** The overlapping C2 endpoint path (`/49890878`), SSL certificate issuers, and Hostwinds IP ranges across this attack and prior DPRK-attributed campaigns illustrate how threat actor infrastructure patterns enable cross-campaign correlation.

## Sources

- [Rust Project Blog - Supply Chain Attack on Arrayref](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/) -- official Rust Security Response Team advisory with timeline and remediation guidance
- [Socket Research - Popular Rust Crates Compromised](https://socket.dev/blog/popular-rust-crates-compromised) -- primary technical analysis with build.rs code breakdown, hashes, C2 infrastructure details, and stage-2 backdoor analysis
- [Wiz Blog - Rust Supply Chain Attack: Significant Overlap with DPRK Campaigns](https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns) -- infrastructure attribution analysis, additional C2 IPs, SSL certificate correlations, and DPRK campaign overlap
- [StepSecurity - arrayref Rust Crate Supply Chain Attack](https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack) -- detailed timeline, crate hashes, blast radius analysis, and build.rs code annotation
- [The Hacker News - Rust Supply Chain Attack Puts Build-Time Malware in Crates](https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html) -- news coverage with download statistics and discovery timeline
- [The Register - Hackers Poison Popular Rust Crates](https://www.theregister.com/security/2026/08/21/hackers-poison-popular-rust-crates-to-steal-developers-credentials/5291075) -- news coverage with stage-2 capability summary
- [Aikido Security - Rust Crates Compromised](https://www.aikido.dev/blog/two-popular-rust-crates-arrayref-and-append-only-vec-compromised-in-supply-chain-attack) -- additional vendor analysis

---
*Report generated by Actioner*
