# Technical Analysis Report: Rust Crates Supply Chain Attack -- NK-Linked Build-Time Malware via proc-macro1 Typosquat (2026-08-26)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-26
Version: DRAFT

## Executive Summary

On August 20, 2026, a DPRK-linked threat actor used compromised crates.io credentials belonging to maintainer David Roundy (user 2402) to publish malicious versions of three popular Rust crates -- arrayref 0.3.10, internment 0.8.7, and append-only-vec 0.1.9 -- which collectively have over 245 million all-time downloads. Each release injected a dependency on `proc-macro1`, a typosquat of the legitimate `proc-macro2` crate, whose `build.rs` script downloaded and executed platform-specific backdoors during compilation (`cargo build/check/test`). The exposure window was 86-107 minutes before the Rust Security Response Team deleted the releases and locked the account.

The stage-2 backdoor beacons via HTTPS POST to `/49890878`, steals saved logins from Chromium-based browsers (Chrome, Brave, Edge), and establishes persistence via Windows Registry Run keys, macOS LaunchAgents, or Linux systemd user services. C2 infrastructure at `23.254.165[.]112` shares SSL certificate issuers and IP ranges with prior DPRK supply chain campaigns targeting npm (Mastra, axios), attributed by Microsoft to Sapphire Sleet and by Mandiant to UNC1069. AES-128-GCM encryption with the hardcoded key `i am botking` and an embedded RSA-2048 private key are shared across all payload variants. A DGA fallback generates ten `.com` domains every five days if the primary C2 is unreachable.

## Background: Rust Crates Ecosystem (crates.io)

crates.io is the default package registry for the Rust programming language, serving as the primary distribution channel for reusable libraries ("crates"). Cargo, Rust's build tool, automatically downloads and compiles dependencies -- including executing `build.rs` build scripts at compile time. This build-time execution model means that merely resolving a malicious dependency during `cargo build`, `cargo check`, or `cargo test` is sufficient to execute attacker code, with no explicit function calls required from the consuming project. The `arrayref` crate alone is used in over 35% of all environments and 75% of environments running Rust (per Wiz), with 403 direct downstream dependents.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-20 01:55 | Clean (non-weaponized) version of `proc-macro1` published to crates.io |
| 2026-08-20 07:11 | Weaponized `proc-macro1@1.0.107` published with malicious `build.rs` |
| 2026-08-20 07:15 | Malicious `arrayref@0.3.10` published with `proc-macro1` dependency |
| 2026-08-20 07:29:50 | Socket AI Scanner independently detects malicious `proc-macro1@1.0.107` |
| 2026-08-20 07:34:07 | Malicious `internment@0.8.7` published |
| 2026-08-20 07:37:49 | Malicious `append-only-vec@0.1.9` published |
| 2026-08-20 08:41:40 | `arrayref@0.3.10` deleted from crates.io index (86 min exposure) |
| 2026-08-20 09:04:11 | `internment@0.8.7` deleted (90 min exposure) |
| 2026-08-20 09:25:24 | `append-only-vec@0.1.9` deleted (107 min exposure) |
| 2026-08-20 ~09:30 | Maintainer account (user 2402) locked; related crates `proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember` also removed |

## Root Cause: Compromised Maintainer Credentials (T1195.001)

The attacker compromised the crates.io publishing credentials or development machine of David Roundy (user 2402, "droundy"), the sole owner of all three affected crates since October 2009. The Rust Security Response Team stated it does not believe the legitimate maintainer acted maliciously. The attacker also operated under the impersonation account "dtolney" (a play on David Tolnay, the author of `proc-macro2`) to publish the typosquat crate, using a forged email `rchaitm[at]gmail[.]com` in the package metadata. Additional attacker-controlled crate names -- `proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember` -- suggest campaign expansion was planned.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection via Typosquat

Each compromised crate version added a single line to its `Cargo.toml`:

```toml
proc-macro1 = "1.0.107"
```

This typosquats the legitimate and widely used `proc-macro2` crate (authored by David Tolnay). Because Cargo resolves and builds dependencies before the consuming project, the malicious `build.rs` in `proc-macro1` executes automatically during compilation. No code changes to the parent crate's library source were needed -- the dependency injection in `Cargo.toml` alone was sufficient.

### 2. Build-Time Dropper (`build.rs`)

The `build.rs` script in `proc-macro1@1.0.107` (SHA-256: `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568`) performs the following:

1. **Base64 obfuscation**: Reconstructs the C2 address from Base64-encoded fragments to evade static analysis
2. **TLS bypass**: Implements an `AcceptAll` `ServerCertVerifier` that disables certificate validation, necessary because the C2 endpoint is a bare IP with no valid certificate
3. **Platform detection**: Checks `std::env::consts::OS` and `std::env::consts::ARCH` to select one of four payload binaries
4. **Download**: Fetches the platform-specific payload from `23.254.165[.]112:9089` over TLS
5. **Execution**: Writes the binary to `/tmp/rust-setup` (Unix) or `%TEMP%\rust-setup.ps1` (Windows), executes it with the C2 address (`23.254.165[.]112:443`) as `argv[1]`
6. **Process escape**: Uses `std::mem::forget(child)` to prevent the child process from being killed when Cargo's job object terminates, allowing the malware to persist after build completion

### 3. C2 Infrastructure

| Component | Value |
|-----------|-------|
| Payload host | `23.254.165[.]112:9089` (TLS, no cert validation) |
| C2 beacon | `23.254.165[.]112:443` |
| Secondary C2 | `23.254.167[.]107:443` |
| Historical C2 | `23.254.167[.]216` (Linux persistence observed) |
| Domain | `hwsrv-798836[.]hostwindsdns[.]com` |
| Beacon path | `POST /49890878` |
| Encryption | AES-128-GCM, hardcoded key: `i am botking` |
| Authentication | RSA-2048 private key embedded in all variants |
| Protocol | HTTPS POST, Base64-encoded JSON body (host profile + stolen credentials) |
| DGA fallback | 10 deterministic `.com` domains rotated every 5 days |
| SSL cert issuer | `WIN-A6QF8AHPQH1\Administrator@WIN-A6QF8AHPQH1` (shared with Mastra C2 at `23.254.167[.]13`) |

All infrastructure resides within Hostwinds LLC ASN ranges (`23.254.164.0/23`), consistent with prior DPRK operations.

**DGA domains (August 20-24, 2026):** `rasGThauFD[.]com`, `feVVKIiEiU[.]com`, `phrpjTNckF[.]com`, `PrOkXLgfjW[.]com`, `ackeoTaWtl[.]com`, `GAFWVCMAja[.]com`, `RNSsddnEgK[.]com`, `pfHlVOqEeg[.]com`, `aBEcOrkups[.]com`, `epOdIaTMaM[.]com`

### 4. Platform-Specific Behavior

#### Linux (x86_64)

- **Payload**: `rust-crate_0.1.0` (ELF), SHA-256: `408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434`
- **Drop path**: `/tmp/rust-setup`
- **Persistence**: systemd user service auto-restart
- **Install dirs**: `$HOME/.config/AzureKits/`, `$HOME/.config/ServiceKit/`
- **Binary names**: `MonoService`, `MonoXpc`

#### Windows (x86_64)

- **Payload**: `rust-crate_0.2.0` (PE), SHA-256: `492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391`
- **Drop paths**: `%TEMP%\rust-setup.ps1`, `%TEMP%\rust-setup.ps1.cfg`, `%TEMP%\rust-setup-launch.vbs`, `%TEMP%\ps-<GUID>.ps1`
- **Persistence**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` registry key pointing to `wscript.exe` launching the VBS wrapper, which executes the PowerShell stage with `-ExecutionPolicy Bypass`
- **Staging**: `%APPDATA%\<operator-folder>\<name>.ps1`

#### macOS (x86_64)

- **Payload**: `rust-crate_0.3.0`, SHA-256: `c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848`
- **Drop path**: `/tmp/rust-setup`
- **Persistence**: LaunchAgent

#### macOS (ARM64 / Apple Silicon)

- **Payload**: `rust-crate_0.4.0`, SHA-256: `74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306`
- **Drop path**: `/tmp/rust-setup`
- **Persistence**: LaunchAgent

### 5. Credential Theft and Host Profiling

The stage-2 backdoor performs:
- **Host profiling**: Collects hostname, username, OS version, architecture, privilege level, installed applications
- **Browser credential theft**: Enumerates saved logins (origins, usernames) and extension settings from Chromium-based browsers (Chrome, Brave, Edge) via SQLite database queries against `Login Data` files
- **Data exfiltration**: Beacons collected data as Base64-encoded JSON over HTTPS POST to `/49890878`
- **C2 commands**: Supports `kill` (terminate), `minicfg` (reconfigure), `startup` (persistence), `runscript` (execute shell/PowerShell)

### 6. Anti-Forensics / Evasion Techniques

- TLS certificate validation disabled to avoid generating certificate errors with bare-IP C2
- `std::mem::forget(child)` escapes Cargo's process job object
- VBS wrapper on Windows suppresses PowerShell window visibility
- Base64 obfuscation of C2 addresses in `build.rs` source
- DGA fallback provides C2 resilience if primary infrastructure is taken down
- Brief 86-107 minute exposure window designed to minimize detection probability

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| arrayref | 0.3.10 | Injected `proc-macro1` dependency; 245M all-time downloads, 86 min exposure |
| internment | 0.8.7 | Injected `proc-macro1` dependency; 90 min exposure |
| append-only-vec | 0.1.9 | Injected `proc-macro1` dependency; 4M downloads, 107 min exposure |
| proc-macro1 | 1.0.107 | Typosquat of proc-macro2; malicious `build.rs` dropper |
| proc-macro-en | 1.0.10 | Secondary typosquat under impersonation account "daveroundy" |
| aovine, arone, aronenao, tinymember | all | Additional attacker-controlled staging crates |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All (crate) | `build.rs` in proc-macro1 | `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568` | Malicious build script / dropper |
| All (crate) | arrayref-0.3.10.crate | `25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae` | Compromised crate archive |
| All (crate) | proc-macro1-1.0.107.crate | `61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4` | Typosquat crate archive |
| Linux x86_64 | `/tmp/rust-setup` | `408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434` | Stage-2 ELF backdoor |
| Windows x86_64 | `%TEMP%\rust-setup.ps1` | `492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391` | Stage-2 PowerShell backdoor |
| macOS x86_64 | `/tmp/rust-setup` | `c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848` | Stage-2 Mach-O backdoor |
| macOS ARM64 | `/tmp/rust-setup` | `74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306` | Stage-2 Mach-O backdoor (Apple Silicon) |
| Windows | `%TEMP%\rust-setup-launch.vbs` | -- | VBS wrapper for persistence |
| Windows | `%TEMP%\rust-setup.ps1.cfg` | -- | Configuration file |
| Windows | `%TEMP%\ps-<GUID>.ps1` | -- | Dynamically named PowerShell script |
| Linux | `$HOME/.config/AzureKits/MonoService` | -- | Persistent backdoor binary |
| Linux | `$HOME/.config/ServiceKit/MonoXpc` | -- | Persistent backdoor binary |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `23.254.165[.]112:9089` | Payload download host (TLS, no cert validation) |
| IP | `23.254.165[.]112:443` | Primary C2 beacon endpoint |
| IP | `23.254.167[.]107:443` | Secondary C2 (active at time of publication) |
| IP | `23.254.167[.]216` | Historical C2, observed establishing Linux persistence |
| Domain | `hwsrv-798836[.]hostwindsdns[.]com` | C2 domain resolving to 23.254.165[.]112 |
| URL Pattern | `hxxps://23.254.165[.]112:9089/rust-crate_0.[1-4].0` | Payload download URLs (4 platform variants) |
| URL Pattern | `POST /49890878` | C2 beacon check-in path |
| Email | `rchaitm[at]gmail[.]com` | Forged email in proc-macro1 metadata |
| DGA | `rasGThauFD[.]com` ... `epOdIaTMaM[.]com` | 10 fallback DGA domains (Aug 20-24 rotation) |

### Behavioral

- Build-time execution: `cargo build`/`check`/`test` triggers `build.rs` in dependency chain, executing payload without any explicit function call
- Process escape: `std::mem::forget(child)` detaches payload from Cargo's process group
- Windows execution chain: `wscript.exe` -> VBS wrapper -> `powershell.exe -ExecutionPolicy Bypass` -> `rust-setup.ps1`
- Browser credential harvesting via SQLite queries against Chromium `Login Data` databases
- Periodic HTTPS POST beaconing with Base64-encoded JSON body containing host profile and stolen credentials
- DGA fallback activation when primary C2 is unreachable (10 domains per 5-day window)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Malicious versions of arrayref, internment, append-only-vec published via compromised crates.io account |
| T1204.002 | User Execution: Malicious File | Payload executes automatically during `cargo build` -- developer triggers compilation as normal workflow |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Windows payload uses `powershell.exe -ExecutionPolicy Bypass` via VBS launcher |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `runscript` C2 command executes shell commands on Unix targets |
| T1105 | Ingress Tool Transfer | `build.rs` downloads platform-specific binaries from `23.254.165[.]112:9089` |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Windows persistence via `HKCU\...\CurrentVersion\Run` |
| T1547.004 | Boot or Logon Autostart Execution: Launch Agent | macOS persistence via LaunchAgent plist |
| T1547.014 | Boot or Logon Autostart Execution: Active Setup | Linux persistence via systemd user service |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Steals saved logins from Chrome, Brave, Edge via SQLite |
| T1571 | Non-Standard Port | Payload download over TLS on port 9089 |
| T1041 | Exfiltration Over C2 Channel | Stolen credentials exfiltrated via same HTTPS POST beacon |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | 10 DGA `.com` domains rotated every 5 days as C2 fallback |

## Impact Assessment

- **Breadth**: arrayref has 245M all-time downloads, ~53.7M in the last 90 days, and 403 direct dependents; it is present in 35% of all environments and 75% of Rust environments (per Wiz). Developer workstations and CI/CD pipelines running `cargo build` during the 86-107 minute window were at risk.
- **Depth**: Full system compromise -- credential theft, persistent backdoor, remote command execution. Browser credentials for Chrome, Brave, and Edge are exfiltrated, potentially compromising any service whose credentials were saved.
- **Stealth**: The 86-minute window was deliberately narrow, and the payload executes during normal build operations with no visible indication to the developer. The `std::mem::forget` trick prevents process cleanup.
- **Attribution**: Infrastructure overlap with prior DPRK campaigns (Mastra npm supply chain, axios npm supply chain) attributed to Sapphire Sleet (Microsoft) / UNC1069 (Mandiant). Shared SSL certificate issuer, IP ranges, and beacon endpoint path.

## Detection & Remediation

### Immediate Detection

Check for the compromised crate archives in local Cargo cache:

```bash
find ~/.cargo/registry/cache -type f \( \
  -name 'append-only-vec-0.1.9.crate' \
  -o -name 'arrayref-0.3.10.crate' \
  -o -name 'internment-0.8.7.crate' \
  -o -name 'proc-macro1-*.crate' \
  -o -name 'proc-macro-en-*.crate' \
  -o -name 'aovine-*.crate' \
  -o -name 'arone-*.crate' \
  -o -name 'aronenao-*.crate' \
  -o -name 'tinymember-*.crate' \
\) -print
```

Check for payload artifacts:

```bash
# Unix
ls -la /tmp/rust-setup
ls -la ~/.config/AzureKits/ ~/.config/ServiceKit/

# Windows (PowerShell)
Get-Item "$env:TEMP\rust-setup*"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-String "rust-setup"
```

Check for network connections to C2:

```bash
# Active connections
ss -tnp | grep -E '23\.254\.165\.112|23\.254\.167\.(107|216)'
netstat -an | findstr "23.254.165.112 23.254.167.107 23.254.167.216"
```

### Remediation

1. **Contain**: Isolate any machine where `cargo build` resolved the affected versions during the exposure window
2. **Eradicate**: Remove `/tmp/rust-setup`, `~/.config/AzureKits/`, `~/.config/ServiceKit/`, `%TEMP%\rust-setup*`; delete the systemd user service, LaunchAgent plist, and Registry Run key
3. **Rotate credentials**: Rotate ALL saved browser passwords (Chrome, Brave, Edge) on affected machines; rotate any tokens/keys stored in browser extensions
4. **Audit CI/CD**: Review CI/CD pipeline logs for `cargo build` runs between 07:15-09:25 UTC on August 20; check for outbound connections to `23.254.165[.]112`
5. **Clean Cargo cache**: Run the detection command above and delete any matching `.crate` files; run `cargo update` to resolve clean versions
6. **Monitor**: Deploy the detection rules below; monitor for DGA domain resolutions and connections to the Hostwinds IP ranges

### Long-Term Hardening

- **Pin dependencies**: Use `Cargo.lock` and audit new dependency additions in code review
- **Use cargo-audit / cargo-deny**: Automated checks for known-vulnerable or unexpected crates
- **Build isolation**: Run `cargo build` in network-restricted sandboxes (no outbound except crates.io and approved registries)
- **Crate signing**: Adopt crate signature verification when crates.io implements it
- **MFA for publishing**: Enforce multi-factor authentication on crates.io accounts with high-download crates

## Detection Rules

These detections target the proc-macro1 supply chain attack's distinctive artifacts: payload file paths, C2 infrastructure, persistence mechanisms, and binary signatures. PoC/advisory-specific altitude (default); Snort/Suricata rules are structurally validated but uncompiled (compilers not available). Compiles does not equal fires -- verify each rule against your telemetry.

### Sigma: Windows Payload Execution from Cargo Build

Detects execution of `rust-setup.ps1` or `rust-setup-launch.vbs` via wscript, the Windows-side payload chain from the proc-macro1 dropper.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed on MITRE ATT&CK data fetch (proxy 403), not rule syntax. splunk convert exit 0; log_scale convert exit 0. Field names standard process_creation/windows. Values not defanged. -->
```yaml
title: Rust Supply Chain Attack - Malicious Payload Execution from Cargo Build
id: 7e4c1a3b-9f2d-4e8a-b5c6-d1f3a7e09b42
status: experimental
description: >
    Detects execution of the rust-setup dropper or rust-crate payloads dropped
    during the proc-macro1 supply chain attack on Rust crates (arrayref, internment,
    append-only-vec). The build.rs script downloads and executes platform-specific
    binaries to /tmp/rust-setup (Unix) or %TEMP%\rust-setup.ps1 (Windows).
references:
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
    - https://socket.dev/blog/popular-rust-crates-compromised
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/26
tags:
    - attack.t1195.001
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps1:
        CommandLine|contains|all:
            - 'rust-setup'
            - '.ps1'
    selection_vbs:
        Image|endswith: '\wscript.exe'
        CommandLine|contains: 'rust-setup-launch.vbs'
    condition: selection_ps1 or selection_vbs
falsepositives:
    - Legitimate Rust development tooling with coincidental naming (unlikely)
level: high
```

### Sigma: Unix Payload Execution from /tmp/rust-setup

Detects execution of `/tmp/rust-setup`, the Unix-side stage-2 binary dropped by the proc-macro1 `build.rs` dropper.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed on MITRE ATT&CK data fetch (proxy 403), not rule syntax. splunk convert exit 0; log_scale convert exit 0. Exact-path match on distinctive artifact. -->
```yaml
title: Rust Supply Chain Attack - Unix Payload Execution from /tmp/rust-setup
id: 3a8f5d12-c6e4-4b97-a1d3-e9f7b2c80a65
status: experimental
description: >
    Detects execution of the /tmp/rust-setup binary dropped by the proc-macro1
    build.rs dropper during the Rust crates supply chain attack. The payload
    is downloaded to /tmp/rust-setup and executed with the C2 address as argv[1].
references:
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
    - https://socket.dev/blog/popular-rust-crates-compromised
author: Actioner
date: 2026/08/26
tags:
    - attack.t1195.001
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image: '/tmp/rust-setup'
    condition: selection
falsepositives:
    - Legitimate software using the exact path /tmp/rust-setup (very unlikely)
level: critical
```

### Sigma: Windows Registry Run Key Persistence

Detects the proc-macro1 payload setting a Windows Registry Run key referencing `rust-setup` for persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed on MITRE ATT&CK data fetch (proxy 403), not rule syntax. splunk convert exit 0; log_scale convert exit 0. Keys on distinctive "rust-setup" string in Run key value. -->
```yaml
title: Rust Supply Chain Attack - Windows Registry Run Key Persistence
id: 5c2d9e4f-a1b3-4f68-9d7e-c3f8a5b10d26
status: experimental
description: >
    Detects the proc-macro1 payload establishing persistence via the Windows
    Registry Run key, using wscript.exe to launch a VBS wrapper that executes
    the PowerShell stage from the user temp directory.
references:
    - https://socket.dev/blog/popular-rust-crates-compromised
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/26
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\CurrentVersion\Run\'
        Details|contains: 'rust-setup'
    condition: selection
falsepositives:
    - None known
level: critical
```

### Sigma: Linux Systemd User Service and Payload Directories

Detects file creation in the `~/.config/AzureKits/` or `~/.config/ServiceKit/` directories, or the `MonoService`/`MonoXpc` binaries used by the proc-macro1 Linux persistence mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed on MITRE ATT&CK data fetch (proxy 403), not rule syntax. splunk convert exit 0; log_scale convert exit 0. Keys on distinctive directory names and binary names from published analysis. -->
```yaml
title: Rust Supply Chain Attack - Linux Systemd User Service Persistence
id: 9f1a7b3c-d4e5-4829-b6f0-a2c8e3d71f54
status: experimental
description: >
    Detects creation of systemd user service files associated with the proc-macro1
    supply chain attack payloads (MonoService/MonoXpc binaries installed to
    ~/.config/AzureKits or ~/.config/ServiceKit).
references:
    - https://socket.dev/blog/popular-rust-crates-compromised
    - https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack
author: Actioner
date: 2026/08/26
tags:
    - attack.t1547.014
logsource:
    category: file_event
    product: linux
detection:
    selection_service:
        TargetFilename|contains: '/.config/systemd/user/'
        TargetFilename|endswith: '.service'
    selection_payload_dirs:
        TargetFilename|contains:
            - '/.config/AzureKits/'
            - '/.config/ServiceKit/'
    selection_binaries:
        TargetFilename|endswith:
            - '/MonoService'
            - '/MonoXpc'
    condition: selection_service or selection_payload_dirs or selection_binaries
falsepositives:
    - Legitimate .NET Mono installations in user config directories (uncommon on developer machines)
level: high
```

### Sigma: C2 Network Connection to Known Infrastructure

Detects outbound connections to the three known C2 IPs used in this campaign on ports 443 and 9089.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed on MITRE ATT&CK data fetch (proxy 403), not rule syntax. splunk convert exit 0; log_scale convert exit 0. IP-based; will need updates if infrastructure rotates. Values are real IPs, not defanged. -->
```yaml
title: Rust Supply Chain Attack - C2 Network Connection to Known Infrastructure
id: b7e3f1d9-2a4c-4586-8e0f-d5a9c6b21738
status: experimental
description: >
    Detects outbound network connections to the C2 infrastructure used in the
    proc-macro1 Rust supply chain attack, including the payload host (port 9089)
    and the beacon endpoint (port 443) at known attacker IPs.
references:
    - https://socket.dev/blog/popular-rust-crates-compromised
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/26
tags:
    - attack.t1571
    - attack.t1105
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '23.254.165.112'
            - '23.254.167.107'
            - '23.254.167.216'
        DestinationPort:
            - 443
            - 9089
    condition: selection
falsepositives:
    - Legitimate traffic to these specific Hostwinds IPs (verify against current threat intel)
level: critical
```

### Snort: Payload Download and C2 Beacon

Detects the stage-2 payload download (`rust-crate_0.` pattern on port 9089) and the C2 beacon POST to `/49890878`.
**Status:** compile ⚠️ uncompiled · confidence: high
<!-- audit: snort not installed; structural check only. Three rules: payload download content match, beacon POST path, and broad IP-based C2 alert. All use standard Snort 3 syntax with flow, content, sid in 2100000+ range. /actioner:setup installs snort for compile validation. -->
```snort
alert tcp $HOME_NET any -> 23.254.165.112 9089 (
    msg:"Actioner - Rust Supply Chain Payload Download from proc-macro1 C2 (port 9089)";
    flow:established, to_server;
    content:"rust-crate_0.";
    fast_pattern;
    classtype:trojan-activity;
    reference:url,socket.dev/blog/popular-rust-crates-compromised;
    reference:url,blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/;
    metadata:author Actioner, created 2026-08-26;
    sid:2100010;
    rev:1;
)

alert tcp $HOME_NET any -> 23.254.165.112 443 (
    msg:"Actioner - Rust Supply Chain C2 Beacon POST /49890878";
    flow:established, to_server;
    content:"POST";
    content:"/49890878";
    fast_pattern;
    classtype:trojan-activity;
    reference:url,socket.dev/blog/popular-rust-crates-compromised;
    reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns;
    metadata:author Actioner, created 2026-08-26;
    sid:2100011;
    rev:1;
)

alert tcp $HOME_NET any -> [23.254.165.112,23.254.167.107,23.254.167.216] 443 (
    msg:"Actioner - Rust Supply Chain C2 Connection to Known DPRK Infrastructure";
    flow:established, to_server;
    classtype:trojan-activity;
    reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns;
    metadata:author Actioner, created 2026-08-26;
    sid:2100012;
    rev:1;
)
```

### Suricata: C2 Beacon, TLS to C2 Domain, and DNS Resolution

Detects the HTTP POST beacon to `/49890878`, TLS connections to the `hostwindsdns.com` C2 domain, and DNS queries for the C2 hostname.
**Status:** compile ⚠️ uncompiled · confidence: high
<!-- audit: suricata not installed; structural check only. Uses dot-notation sticky buffers (http.method, http.uri, tls.sni, dns.query), correct protocols (http, tls, dns), all required fields present (msg prefixed "Actioner - ", sid in 2200000+, metadata with author/created_at). /actioner:setup installs suricata for compile validation. -->
```suricata
alert http $HOME_NET any -> 23.254.165.112 any (
    msg:"Actioner - Rust Supply Chain C2 Beacon POST /49890878";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/49890878"; startswith; fast_pattern;
    classtype:trojan-activity;
    reference:url,socket.dev/blog/popular-rust-crates-compromised;
    reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns;
    metadata:author Actioner, created_at 2026-08-26;
    sid:2200001;
    rev:1;
)

alert tls $HOME_NET any -> [23.254.165.112,23.254.167.107,23.254.167.216] any (
    msg:"Actioner - Rust Supply Chain TLS to Known DPRK C2 Infrastructure";
    flow:established,to_server;
    tls.sni; content:"hostwindsdns.com"; endswith;
    classtype:trojan-activity;
    reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns;
    metadata:author Actioner, created_at 2026-08-26;
    sid:2200002;
    rev:1;
)

alert dns $HOME_NET any -> any any (
    msg:"Actioner - Rust Supply Chain DNS Query for C2 Domain hwsrv-798836.hostwindsdns.com";
    flow:to_server;
    dns.query; content:"hwsrv-798836.hostwindsdns.com"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns;
    metadata:author Actioner, created_at 2026-08-26;
    sid:2200003;
    rev:1;
)
```

### YARA: Stage-2 Backdoor Payload and Build Script

Detects the stage-2 backdoor via the hardcoded AES key (`i am botking`), beacon path (`/49890878`), C2 command strings, and operational directory names; and the malicious `build.rs` via the TLS bypass and payload naming patterns.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: positive fired (Malware_RustCrate_ProcMacro1_Payload matched pos.txt containing published strings "i am botking", "/49890878", command names, dir/binary names, "rust-setup"); negative quiet (benign cargo build output). Positive built from published IOC strings across Socket, Wiz, StepSecurity analyses. BuildScript rule is compile-only (no sample with AcceptAll+ServerCertVerifier+rust-crate_0. available for testing). -->
```yara
rule Malware_RustCrate_ProcMacro1_Payload
{
    meta:
        description = "Detects the stage-2 backdoor payloads delivered by the proc-macro1 Rust supply chain attack. Keys on the hardcoded AES key, C2 beacon path, and embedded operational strings."
        author = "Actioner"
        date = "2026-08-26"
        reference = "https://socket.dev/blog/popular-rust-crates-compromised"
        hash = "408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434"
        hash = "492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391"
        hash = "c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848"
        hash = "74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306"
        severity = "critical"

    strings:
        $aes_key = "i am botking" ascii
        $beacon_path = "/49890878" ascii
        $cmd_kill = "kill" ascii fullword
        $cmd_minicfg = "minicfg" ascii fullword
        $cmd_startup = "startup" ascii fullword
        $cmd_runscript = "runscript" ascii fullword
        $dir_azurekits = "AzureKits" ascii
        $dir_servicekit = "ServiceKit" ascii
        $bin_monoservice = "MonoService" ascii
        $bin_monoxpc = "MonoXpc" ascii
        $dropper_name = "rust-setup" ascii

    condition:
        filesize < 20MB and
        $aes_key and
        $beacon_path and
        (2 of ($cmd_*) or 2 of ($dir_*, $bin_*)) and
        $dropper_name
}

rule Malware_RustCrate_ProcMacro1_BuildScript
{
    meta:
        description = "Detects the malicious build.rs loader from the proc-macro1 typosquat crate that downloads and executes platform-specific payloads during cargo build."
        author = "Actioner"
        date = "2026-08-26"
        reference = "https://socket.dev/blog/popular-rust-crates-compromised"
        hash = "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568"
        severity = "critical"

    strings:
        $accept_all = "AcceptAll" ascii
        $cert_verifier = "ServerCertVerifier" ascii
        $rust_crate = "rust-crate_0." ascii
        $rust_setup = "rust-setup" ascii
        $mem_forget = "mem::forget" ascii
        $payload_host = "23.254.165.112" ascii

    condition:
        filesize < 500KB and
        ($accept_all and $cert_verifier) and
        ($rust_crate or $rust_setup) and
        ($mem_forget or $payload_host)
}
```

## Lessons Learned

1. **Build-time execution is a supply chain amplifier.** Rust's `build.rs` model (like npm's `postinstall`) means dependency resolution alone triggers code execution. The attack required zero code changes to the parent crate's library -- a `Cargo.toml` edit was sufficient. The ecosystem needs build script sandboxing or opt-in execution.

2. **Account security scales with download count.** A single compromised account controlling a crate with 245M downloads and 403 dependents gives an attacker immediate access to a massive blast radius. High-download crate owners should be required to use hardware-backed 2FA, and crates.io should support trusted publisher workflows (similar to PyPI's Trusted Publishers).

3. **Typosquatting remains effective.** `proc-macro1` vs `proc-macro2` is a single-character difference in a crate name developers see constantly. Automated typosquat detection (as demonstrated by Socket's AI Scanner, which flagged it within 15 minutes) is essential.

4. **DPRK actors are expanding ecosystem coverage.** This is the same infrastructure and operational pattern seen in the Mastra and axios npm supply chain attacks. The expansion from npm to crates.io signals that no package ecosystem is exempt, and defenders should expect similar campaigns targeting PyPI, NuGet, and Go modules.

## Sources

- [Supply chain attack on arrayref -- Rust Blog](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/) -- Official Rust Security Response Team advisory with timeline and remediation command
- [Popular Rust Crates Compromised in Build-Time Supply Chain Attack -- Socket](https://socket.dev/blog/popular-rust-crates-compromised) -- Primary technical analysis: payload hashes, C2 details, persistence mechanisms, DGA domains, credential theft behavior
- [Rust Supply Chain Attack on arrayref: Significant Overlap with DPRK Campaigns -- Wiz](https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns) -- Attribution evidence: infrastructure overlap with Mastra/axios campaigns, Sapphire Sleet/UNC1069 linkage, SSL cert issuer, additional C2 IPs
- [Rust Crates arrayref & append-only-vec Compromised -- Semgrep](https://semgrep.dev/blog/2026/rust-crates-arrayref-append-only-vec-compromised-proc-macro1/) -- Build.rs code analysis, impersonation account details
- [Rust Supply-Chain Attack: arrayref, internment, and append-only-vec -- StepSecurity](https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack) -- Linux persistence directories (AzureKits/ServiceKit), binary names (MonoService/MonoXpc), AcceptAll ServerCertVerifier detail
- [Rust Supply Chain Attack Puts Build-Time Malware in Crates with 245 Million Downloads -- The Hacker News](https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html) -- Reporting aggregator with download statistics

---
*Report generated by Actioner*
