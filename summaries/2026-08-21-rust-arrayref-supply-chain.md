# Technical Analysis Report: Rust arrayref / proc-macro1 Supply Chain Attack (DPRK-linked build-time malware campaign) (2026-08-21)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-08-21
Version: 1.1 (REVISED)

## Executive Summary

<!-- revision: attribution corrected — droundy is David Roundy, not Andrew Gallant/BurntSushi; fixed throughout per critic -->
On August 20, 2026, beginning at 07:15 UTC, an attacker who had compromised the crates.io credentials of Rust developer David Roundy (`droundy`) published malicious versions of three popular crates: `arrayref` 0.3.10 (~245 million total downloads, ~54 million in the prior 90 days), `internment` 0.8.7, and `append-only-vec` 0.1.9. The actual library code was not modified; the only change was a single dependency line added to each crate's `Cargo.toml` pointing to `proc-macro1`, a typosquat of the legitimate `proc-macro2` crate. The attacker simultaneously yanked legitimate versions (0.3.5 through 0.3.9) of arrayref, forcing any new resolution to land on the compromised 0.3.10 release.

The malicious `proc-macro1` crate's `build.rs` script -- which Cargo automatically compiles and executes during dependency resolution -- decoded base64-obfuscated URLs, disabled TLS certificate validation, downloaded a platform-specific payload (Linux, Windows, macOS x86_64, macOS ARM64) from `23.254.165[.]112:9089`, and executed it detached. The stage-2 implant is a featureful backdoor supporting HTTPS POST beaconing to `/49890878`, browser credential theft (Chrome, Brave, Edge), host enumeration, persistence (Registry Run key / LaunchAgent / systemd), DGA fallback with 10 algorithmic `.com` domains every 5 days, and remote script execution. AES-128-GCM encryption uses the hardcoded passphrase "i am botking."

Wiz researchers identified significant infrastructure overlap with DPRK (North Korean) supply chain campaigns, specifically the Mastra npm compromise attributed to Sapphire Sleet and the axios npm attack linked to UNC1069. Both campaigns share the `23.254.164.0/23` Hostwinds LLC IP range and the same SSL issuer string. The Rust Security Response Team removed the malicious versions within 86 to 107 minutes of publication.

A related but separate Rust supply chain attack compromised the `onering` crate (v1.4.1, ~18K downloads) on June 10, 2026, using a malicious `build.rs` that exfiltrated git commit metadata and source code diffs to an attacker-controlled Sentry endpoint. This report covers both incidents with primary focus on the arrayref campaign.

This report carries concrete, durable IOCs (file hashes, IP addresses, C2 paths, DGA domains, staging paths, base64 fragments, AES key material) corroborated across the official Rust blog, Wiz, Semgrep, Aikido, BleepingComputer, The Hacker News, and a community IOC Gist. The viability gate **passes** and detection rules are emitted across Sigma, YARA, and Suricata formats.

## Background: Rust Crates Ecosystem and Build-Time Execution

Rust's package manager Cargo resolves dependencies from the crates.io registry. A critical feature -- and attack surface -- is the `build.rs` build script: any crate can include one, and Cargo **automatically compiles and executes it** before the crate's library code is compiled. This execution happens with the full privileges of the developer workstation or CI runner, without any user interaction or confirmation prompt. The mechanism is analogous to npm install scripts but runs at compile time rather than install time, meaning even `cargo build` or `cargo check` on a workspace that transitively depends on a malicious crate triggers arbitrary code execution.

The `arrayref` crate is a foundational Rust utility that provides macros for creating array references from slices. It is depended upon by 403 distinct crates on crates.io, including tools for the Solana and Ethereum blockchain ecosystems, making it a high-value supply chain target.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-20 (prior) | Attacker creates GitHub account `dtolney` impersonating David Tolnay (legitimate prominent Rust developer) and a corresponding crates.io account |
| 2026-08-20 (prior) | Attacker publishes `proc-macro1` v1.0.106 (clean copy of proc-macro2 source, staging version) followed by v1.0.107 (containing malicious build.rs) |
| 2026-08-20 (prior) | Attacker publishes related typosquats: `proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember` |
| 2026-08-20 07:15 | `arrayref` 0.3.10 published via compromised `droundy` (David Roundy) account; legitimate versions 0.3.5-0.3.9 yanked simultaneously |
| 2026-08-20 07:34 | `internment` 0.8.7 published via same account |
| 2026-08-20 07:37 | `append-only-vec` 0.1.9 published via same account |
| 2026-08-20 ~07:15 | Malicious builds begin executing on developer workstations and CI runners worldwide |
| 2026-08-20 ~08:41 | `arrayref` 0.3.10 removed from crates.io index (86 minutes exposure) |
| 2026-08-20 ~09:04 | `internment` 0.8.7 removed (90 minutes exposure) |
| 2026-08-20 ~09:25 | `append-only-vec` 0.1.9 removed (107 minutes exposure) |
| 2026-08-20 (post) | All malicious crate versions permanently deleted; previously yanked legitimate versions unyanked; compromised account locked |
| 2026-06-10 (related) | `onering` v1.4.1 malicious version detected (separate code exfiltration campaign) |

## Root Cause: Initial Access Vector

The attack exploited compromised credentials of the `droundy` crates.io account belonging to David Roundy, maintainer of arrayref, internment, and append-only-vec. The Rust Security Response Team stated that the author was not acting maliciously but that their credentials or computer were likely compromised. The attacker combined this credential access with a prepared typosquatting infrastructure: the malicious dependency `proc-macro1` was already published under an impersonation account (`dtolney`, mimicking `dtolnay` -- David Tolnay) before the hijacked crate releases were pushed.

## Technical Analysis of the Malicious Payload

### 1. Stage 0 -- Dependency Injection (Cargo.toml modification)

The attacker added a single line to each compromised crate's `Cargo.toml`:

```toml
[dependencies]
proc-macro1 = "1.0.107"
```

The library source code of arrayref, internment, and append-only-vec was not modified. The `proc-macro1` crate's library source was an exact copy of the legitimate `proc-macro2`, so normal compilation succeeded. All malicious logic was confined to `proc-macro1`'s `build.rs`.

### 2. Stage 1 -- Build Script Execution (build.rs)

The `build.rs` in `proc-macro1` v1.0.107 (SHA-256: `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568`) performed the following:

**Base64 URL Reconstruction:** The payload host and C2 addresses were concealed as base64 fragments:
```
const SRC_URL_PARTS: &[&str] = &["aHR0cHM6Ly8=", "MjMuMjU0Lg==", "MTY1Lg==", "MTEyOi", "OTA4OS8="];
```
Decoded: `https://23.254.165.112:9089/`

C2 address fragments decoded to: `23.254.165.112:443`

**TLS Bypass:** Implemented a custom `AcceptAll` certificate verifier for rustls that returns success from every certificate and signature verification method unconditionally, disabling all TLS validation. This permits HTTPS connections to raw IP addresses with self-signed certificates.

**Platform Detection and Payload Selection:**
```
("linux", "x86_64")  => "rust-crate_0.1.0"
("windows", "x86_64") => "rust-crate_0.2.0"
("macos", "x86_64")  => "rust-crate_0.3.0"
("macos", "aarch64") => "rust-crate_0.4.0"
```

**Payload Staging and Execution:**
- **Unix/macOS:** Downloads binary to `/tmp/rust-setup`, sets executable permissions with `chmod +x`, launches as a detached process with the C2 address passed as the first argument, and uses `std::mem::forget()` to prevent cleanup
- **Windows:** Downloads PowerShell script to `%TEMP%\rust-setup.ps1`, creates a VBScript launcher at `%TEMP%\rust-setup-launch.vbs` that executes the PowerShell script hidden, and launches it via `wscript.exe` to escape Cargo's job object

### 3. Stage 2 -- Backdoor Implant Capabilities

The stage-2 payload is a featureful cross-platform implant:

**C2 Communication:** HTTPS POST beaconing to the path `/49890878`. Registration check-in transmits host identification fields: `os_type`, `os_ver`, `os_arch`, `platform_ver`. Encryption uses AES-128-GCM with the hardcoded passphrase "i am botking". Command authentication via an embedded RSA-2048 private key.

**Supported Commands:**
| Command | Function |
|---------|----------|
| `kill` | Self-terminate |
| `minicfg` | Reconfigure C2 address |
| `startup` | Install persistence |
| `runscript` | Download and execute arbitrary scripts |
| `Shell` / `ShellX` | Interactive shell execution |

**Browser Credential Theft:** Extracts stored credentials from Chromium-derivative browsers by querying SQLite login databases:
- `%LOCALAPPDATA%\Google\Chrome\User Data`
- `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`
- `%LOCALAPPDATA%\Microsoft\Edge\User Data`

Also targets browser extension storage for cryptocurrency wallet data. Downloads SQLite tools from `sqlite[.]org` for Windows credential extraction.

**Persistence Mechanisms:**
- **Windows:** Registry Run key at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **macOS:** LaunchAgent in `~/Library/LaunchAgents/` with `RunAtLoad` enabled, executing via `/bin/zsh -c`
- **Linux:** systemd user service

**DGA Fallback:** When the primary C2 is unreachable, the implant generates 10 algorithmic `.com` domains every 5 days. DGA domains for the initial infection window (Aug 20-24, 2026 UTC): `rasGThauFD[.]com`, `feVVKIiEiU[.]com`, `phrpjTNckF[.]com`, `PrOkXLgfjW[.]com`, `ackeoTaWtl[.]com`, `GAFWVCMAja[.]com`, `RNSsddnEgK[.]com`, `pfHlVOqEeg[.]com`, `aBEcOrkups[.]com`, `epOdIaTMaM[.]com`.

### 4. Related Campaign: onering Crate Code Exfiltration

The `onering` crate v1.4.1 (detected June 10, 2026) used a separate but thematically similar attack vector:
- **Build.rs** traversed upward from `OUT_DIR` to locate the consuming project's root
- Executed `git log -n 1` to harvest commit metadata (hash, author, email, date, subject)
- Executed `git diff HEAD^ HEAD` to extract the full source diff of the latest commit
- Exfiltrated data via HTTP POST to `https://o4511539639222272.ingest.de.sentry[.]io/api/4511539669368912/envelope/`, disguised as Sentry telemetry
- Sentry DSN key: `8197ee42c4f59c83f4cc6d48f5bae821`

### 5. Anti-Forensics and Evasion Techniques

- **Typosquatting:** `proc-macro1` mimics the ubiquitous `proc-macro2` crate name
- **Impersonation:** The `dtolney` account mimics `dtolnay` (David Tolnay), a highly trusted Rust ecosystem figure
- **Version yanking:** Yanking legitimate arrayref versions 0.3.5-0.3.9 forced dependency resolution to the malicious 0.3.10
- **Base64 fragmentation:** C2 addresses split across multiple base64 fragments defeat static string scanning
- **TLS bypass:** Custom certificate verifier eliminates certificate warnings
- **Job object escape:** Windows VBS launcher via wscript.exe and `std::mem::forget()` prevent build-process cleanup from terminating the payload
- **DGA fallback:** Algorithmic domain generation provides C2 resilience against IP-based blocking
- **Legitimate library code:** proc-macro1 ships real proc-macro2 library source, so compilation succeeds normally

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs `hxxps://`; domains/IPs `[.]`; emails `[at]`. Hashes, file paths, and package names are not network-resolvable and are shown un-defanged for matching.

### Malicious Crate Archives

| Package | Version | SHA-256 |
|---------|---------|---------|
| arrayref | 0.3.10 | `25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae` |
| proc-macro1 | 1.0.107 | `61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4` |
| proc-macro1 | 1.0.106 | `b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436` |
| proc-macro-en | 1.0.10 | `8ed7d2d62d283a7701213e7a07191ebf5ab4d4862a0272b6ecda1209f6e0b93a` |

### Malicious Build Script

| File | SHA-256 |
|------|---------|
| build.rs (shared loader) | `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568` |

### Stage-2 Payload Binaries

| Platform | Filename | SHA-256 | SHA-1 |
|----------|----------|---------|-------|
| Linux x86_64 | rust-crate_0.1.0 | `408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434` | `f4767ad92cb61401fd69139cade563501c39b991` |
| Windows x86_64 | rust-crate_0.2.0 | `492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391` | `fc0fdb978eac72f4484b48db058e4473f1bc516e` |
| macOS x86_64 | rust-crate_0.3.0 | `c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848` | -- |
| macOS ARM64 | rust-crate_0.4.0 | `74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306` | `ff7e20cf642346bf893f1eca808df82035bb53d0` |

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| IP:Port | `23.254.165[.]112:9089` | Stage-2 payload download host |
| IP:Port | `23.254.165[.]112:443` | Primary C2 address (passed as argument to payload) |
| IP:Port | `23.254.167[.]107:443` | Secondary C2 observed live at time of publication |
| IP | `23.254.167[.]216` | Victim-reported C2 traffic |
| URL Path | `/49890878` | Stage-2 C2 beacon endpoint |
| URL Path | `/rust-crate_0.1.0` through `/rust-crate_0.4.0` | Payload download paths |
| Hostname | `hwsrv-798836.hostwindsdns[.]com` | Attacker infrastructure hostname |
| URL | `hxxps://sqlite[.]org/2026/sqlite-tools-win-x64-3530400.zip` | Secondary SQLite download for credential extraction |
| IP Range | `23.254.164[.]0/23` | Hostwinds LLC range shared with DPRK campaigns (Mastra, axios) |

### DGA Domains (Aug 20-24, 2026 rotation)

| Domain |
|--------|
| `rasGThauFD[.]com` |
| `feVVKIiEiU[.]com` |
| `phrpjTNckF[.]com` |
| `PrOkXLgfjW[.]com` |
| `ackeoTaWtl[.]com` |
| `GAFWVCMAja[.]com` |
| `RNSsddnEgK[.]com` |
| `pfHlVOqEeg[.]com` |
| `aBEcOrkups[.]com` |
| `epOdIaTMaM[.]com` |

### File System Artifacts

| Platform | Path | Description |
|----------|------|-------------|
| Linux/macOS | `/tmp/rust-setup` | Stage-2 binary dropped by build.rs |
| Windows | `%TEMP%\rust-setup.ps1` | Stage-2 PowerShell script |
| Windows | `%TEMP%\rust-setup.ps1.cfg` | Implant configuration file |
| Windows | `%TEMP%\rust-setup-launch.vbs` | VBS launcher for job object escape |
| Windows | `%TEMP%\ps-<GUID>.ps1` | Temporary execution scripts |
| Windows | `%TEMP%\sqlite_<GUID>\` | SQLite tools for credential extraction |
| Windows | `%TEMP%\login_<GUID>\Login Data` | Copied browser credential database |
| Windows | `%APPDATA%\<operator-folder>\<name>.ps1` | Persistent implant location |

### Registry Keys (Windows)

| Key | Purpose |
|-----|---------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Persistence via Run key |

### Attacker Accounts

| Platform | Account | Notes |
|----------|---------|-------|
| crates.io | `droundy` | Compromised legitimate maintainer (David Roundy) |
| crates.io/GitHub | `dtolney` | Impersonation of David Tolnay (`dtolnay`); published proc-macro1 |
| crates.io | `daveroundy` | Impersonation of droundy; published proc-macro-en |
| Email | `rchaitm[at]gmail[.]com` | Forged author metadata |

### Attacker-Controlled Crate Names

`proc-macro1`, `proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember`

### Cryptographic Material

| Type | Value |
|------|-------|
| AES passphrase | `i am botking` |
| AES passphrase (alt) | `test` |
| RSA-2048 private key | Embedded in implant binary (used for command authentication) |
| SSL Issuer (infra) | `WIN-A6QF8AHPQH1\Administrator@WIN-A6QF8AHPQH1` |

### onering Code Exfiltration IOCs

| Type | Value |
|------|-------|
| Crate | `onering` v1.4.1 |
| Exfil endpoint | `hxxps://o4511539639222272.ingest.de.sentry[.]io/api/4511539669368912/envelope/` |
| Sentry DSN key | `8197ee42c4f59c83f4cc6d48f5bae821` |
| Sentry Org ID | `o4511539639222272` |
| Sentry Project ID | `4511539669368912` |

### Behavioral Indicators

- Cargo/rustc build process spawning unexpected child processes (especially `/tmp/rust-setup` or `wscript.exe`)
- Outbound HTTPS connections during `cargo build` to IP addresses (not domains) in the `23.254.164.0/23` range
- File creation of `/tmp/rust-setup` or `%TEMP%\rust-setup*` during Rust compilation
- POST requests to URI path `/49890878`
- DNS queries for `hwsrv-798836.hostwindsdns[.]com` or any DGA domain matching the pattern of 10 mixed-case alphanumeric characters followed by `.com`
- SQLite tools downloaded to `%TEMP%\sqlite_<GUID>\` outside of expected database development workflows
- Browser credential database files copied to `%TEMP%\login_<GUID>\`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Compromised maintainer account used to inject malicious dependency into arrayref, internment, append-only-vec |
<!-- revision: T1036.004 changed to T1036.005 — Match Legitimate Name or Location is more accurate for package name typosquatting -->
| T1036.005 | Masquerading: Match Legitimate Name or Location | proc-macro1 typosquats legitimate proc-macro2; dtolney impersonates dtolnay |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Windows payload delivered as PowerShell script, launched via VBS |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | VBS launcher (`rust-setup-launch.vbs`) used to escape Cargo's job object |
| T1105 | Ingress Tool Transfer | build.rs downloads platform-specific stage-2 payload from remote host |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Windows persistence via HKCU Run key |
| T1547.011 | Boot or Logon Autostart Execution: Plist Modification | macOS persistence via LaunchAgent |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via systemd user service |
| T1005 | Data from Local System | Host enumeration; browser credential extraction from SQLite stores |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome, Brave, Edge login database theft |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST beaconing to C2 |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-128-GCM encrypted C2 communications |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | 10-domain DGA fallback rotating every 5 days |
| T1027 | Obfuscated Files or Information | Base64-fragmented URLs in build.rs |

## Impact Assessment

**Breadth:** arrayref has 245 million total downloads and 403 direct reverse dependencies on crates.io. The 86-minute exposure window during active development hours meant any `cargo build`, `cargo check`, or CI pipeline that resolved arrayref dependencies during that window was vulnerable. The additional affected crates (internment, append-only-vec) broaden the exposure surface.

**Depth:** The stage-2 implant provides full remote access including arbitrary script execution, browser credential theft, cryptocurrency wallet data theft, and cross-platform persistence. Developer workstations and CI runners typically hold credentials for source repositories, cloud infrastructure, package registries, and production systems.

**Attribution:** Wiz's analysis identifies significant infrastructure overlap with DPRK/Sapphire Sleet supply chain operations. The shared C2 path `/49890878`, the `23.254.164.0/23` Hostwinds IP range, and the SSL issuer fingerprint link this campaign to the Mastra npm compromise (attributed by Microsoft to DPRK) and the axios npm attack (linked by Google Cloud/Mandiant to UNC1069).

**Ecosystem Impact:** This is the most significant supply chain attack against the Rust crates.io ecosystem to date. It demonstrates that the build.rs mechanism presents a comparable attack surface to npm install scripts and PyPI setup.py, and that credential compromise of a single high-value maintainer can cascade across hundreds of transitive dependents.

## Detection & Remediation

### Immediate Detection

**Check local Cargo cache for compromised crates:**
```bash
find ~/.cargo/registry/cache -name "proc-macro1-*" -o -name "proc-macro-en-*" -o -name "arrayref-0.3.10*" -o -name "append-only-vec-0.1.9*" -o -name "internment-0.8.7*"
```

**Check for staging artifacts:**
```bash
# Unix/macOS
ls -la /tmp/rust-setup
# Windows (PowerShell)
Get-Item "$env:TEMP\rust-setup*"
```

**Network hunt:**
- Search firewall/proxy logs for connections to `23.254.165.112` (ports 9089, 443), `23.254.167.107:443`, `23.254.167.216`
- Search HTTP logs for POST requests to URI path `/49890878`
- Search DNS logs for `hwsrv-798836.hostwindsdns.com`

**Process hunt:**
- Search EDR/process creation logs for `/tmp/rust-setup` executions
- Search for `wscript.exe` executing `rust-setup-launch.vbs`
- Search for `cargo` or `rustc` spawning unexpected network-connected child processes

### Remediation

1. **Remove compromised dependencies:** Ensure `Cargo.lock` pins arrayref to 0.3.9 or earlier (0.3.10 is deleted); remove any reference to `proc-macro1`, `proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember`
2. **Scan for persistence:** Check Windows Registry Run keys, macOS LaunchAgents, and Linux systemd user services for entries installed by the implant
3. **Rotate credentials:** On any system that built during the exposure window, rotate all credentials accessible from that system (crates.io tokens, GitHub tokens, cloud provider keys, SSH keys, browser-stored passwords)
4. **Block IOCs:** Add the network IOCs to firewall/proxy block lists; add file hashes to EDR block lists
5. **Rebuild CI/CD:** If CI runners built during the window, consider them compromised; rebuild from clean images

### Long-Term Hardening

- Audit `Cargo.lock` files for unexpected new dependencies; integrate SCA tooling that flags typosquat-adjacent names
- Monitor for build.rs scripts in dependencies that perform network I/O or execute external commands
- Consider `cargo vet` or `cargo crev` for supply chain audit workflows
- Implement egress filtering on build hosts to block unexpected outbound connections during compilation
- Enable crates.io two-factor authentication and credential rotation policies
- Use `[build] build-dir` sandboxing where available; evaluate build isolation tooling

## Detection Rules

These detections cover the campaign's durable artifacts: staging file paths and process names (Sigma), malicious crate content and implant strings (YARA), and C2 network indicators (Suricata). Sigma `check` fails only because the pySigma D3FEND tag validator cannot reach the MITRE ATT&CK data endpoint in this sandbox (HTTP 403) -- not a rule defect; all four Sigma rules convert cleanly to Splunk and LogScale.

### Sigma: Unix rust-setup payload execution from /tmp
Detects execution of the `/tmp/rust-setup` binary dropped by the malicious proc-macro1 build script during Rust crate compilation.
**Status:** compile ✅ parses (sigma check blocked by offline D3FEND fetch only; splunk/log_scale convert exit 0) · confidence: high
<!-- audit: altitude=advisory-specific (unique filename + path). `sigma check` exits 1 ONLY because pySigma D3FEND tag-validator tries to fetch external data and gets HTTP 403 in this sandbox — NOT a rule defect. `sigma convert --without-pipeline -t splunk` exit 0 => Image="*/rust-setup" Image="/tmp/*". `-t log_scale` exit 0 => Image=/\/rust-setup$/i Image=/^\/tmp\//i. The /tmp/rust-setup path is distinctive to this campaign. product:linux chosen. -->
```yaml
title: Suspicious rust-setup payload execution from temp directory
id: 7a2e1d4f-9c3b-4e8a-b5f1-6d2c8a3e7b90
status: experimental
description: >-
  Detects execution of the rust-setup payload dropped by the malicious proc-macro1
  build.rs script during Rust crate compilation. The arrayref/append-only-vec supply
  chain attack (August 2026) writes a binary to /tmp/rust-setup on Unix or launches
  rust-setup.ps1 via wscript.exe on Windows.
references:
  - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
  - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/21
tags:
  - attack.t1195.001
  - attack.t1059.001
  - attack.t1204.002
logsource:
  category: process_creation
  product: linux
detection:
  selection_unix:
    Image|endswith: '/rust-setup'
    Image|startswith: '/tmp/'
  condition: selection_unix
falsepositives:
  - Legitimate Rust toolchain installer scripts (unlikely to use /tmp/rust-setup path)
level: high
```

### Sigma: Wscript launching rust-setup VBS launcher (Windows)
Detects wscript.exe executing the rust-setup-launch.vbs file that starts the rust-setup.ps1 PowerShell backdoor on Windows.
**Status:** compile ✅ parses (sigma check blocked by offline D3FEND fetch only; splunk/log_scale convert exit 0) · confidence: high
<!-- audit: altitude=advisory-specific (unique VBS filename). `sigma convert --without-pipeline -t splunk` exit 0 => Image="*\wscript.exe" CommandLine="*rust-setup-launch.vbs*". `-t log_scale` exit 0 => Image=/\\wscript\.exe$/i CommandLine=/rust-setup-launch\.vbs/i. Filename rust-setup-launch.vbs is unique to this campaign. -->
```yaml
title: Wscript launching rust-setup VBS launcher (arrayref supply chain)
id: 3b8f2c6e-1d5a-4e9b-a7f0-2c4d6e8a1b3f
status: experimental
description: >-
  Detects wscript.exe executing a VBScript launcher that starts the rust-setup.ps1
  PowerShell backdoor. The arrayref/append-only-vec supply chain attack (August 2026)
  writes rust-setup-launch.vbs to %TEMP% and spawns it via wscript.exe to escape
  Cargo's job object.
references:
  - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
  - https://semgrep.dev/blog/2026/rust-crates-arrayref-append-only-vec-compromised-proc-macro1/
author: Actioner
date: 2026/08/21
tags:
  - attack.t1195.001
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
  - Very unlikely - the filename rust-setup-launch.vbs is unique to this campaign
level: critical
```

### Sigma: Rust-setup payload file creation in temp directory
Detects creation of the `/tmp/rust-setup` file on Linux/macOS, indicating the build.rs dropper has staged the payload.
**Status:** compile ✅ parses (sigma check blocked by offline D3FEND fetch only; splunk/log_scale convert exit 0) · confidence: high
<!-- audit: altitude=advisory-specific (unique filename). `sigma convert --without-pipeline -t splunk` exit 0 => TargetFilename="/tmp/rust-setup". `-t log_scale` exit 0 => TargetFilename=/^\/tmp\/rust-setup$/i. file_event category; the exact path is distinctive. -->
<!-- revision: description narrowed to Unix/Linux only — rule logsource is product:linux, Windows paths not applicable here -->
```yaml
title: Rust-setup payload file creation in temp directory
id: 9e4c7b1a-5d8f-4a2e-b3c6-1f7d9a0e4b52
status: experimental
description: >-
  Detects creation of the /tmp/rust-setup file on Unix/Linux, indicating the malicious
  proc-macro1 build.rs dropper has staged the arrayref/append-only-vec supply chain
  attack payload.
references:
  - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
  - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/21
tags:
  - attack.t1195.001
  - attack.t1105
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename:
      - '/tmp/rust-setup'
  condition: selection
falsepositives:
  - Legitimate Rust toolchain operations using a similarly named file (unlikely)
level: high
```

### Sigma: Network connection to arrayref supply chain C2 infrastructure
Detects outbound network connections to the three C2 IP addresses used in the arrayref supply chain attack.
**Status:** compile ✅ parses (sigma check blocked by offline D3FEND fetch only; splunk/log_scale convert exit 0) · confidence: high
<!-- audit: altitude=advisory-specific (published IOC IPs). `sigma convert --without-pipeline -t splunk` exit 0 => DestinationIp IN ("23.254.165.112", "23.254.167.107", "23.254.167.216"). `-t log_scale` exit 0 => DestinationIp=/^23\.254\.165\.112$/i or ... . IPs are real published IOCs from Wiz/Semgrep/Aikido; Hostwinds LLC hosting may rotate but these specific IPs are confirmed campaign infrastructure. -->
<!-- revision: removed attack.t1102 (Web Service — incorrect for attacker-controlled infra); removed product:linux to make platform-agnostic network IOC rule -->
```yaml
title: Network connection to arrayref supply chain C2 infrastructure
id: 4f1a9c7e-2b3d-4e6f-8a5c-9d0e1b7f2c4a
status: experimental
description: >-
  Detects outbound network connections to the C2 infrastructure used in the
  arrayref/append-only-vec Rust supply chain attack (August 2026). The primary
  payload host and C2 server reside at 23.254.165.112.
references:
  - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
  - https://semgrep.dev/blog/2026/rust-crates-arrayref-append-only-vec-compromised-proc-macro1/
author: Actioner
date: 2026/08/21
tags:
  - attack.t1071.001
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp:
      - '23.254.165.112'
      - '23.254.167.107'
      - '23.254.167.216'
  condition: selection
falsepositives:
  - Legitimate traffic to Hostwinds LLC infrastructure at these IPs (unlikely for developer workstations)
level: high
```

### YARA: Malicious proc-macro1 build script detection
Detects the malicious build.rs from proc-macro1 by matching base64-encoded C2 fragments and payload staging paths. Also detects the stage-2 implant via hardcoded AES passphrase and C2 path, and Cargo.toml manifests declaring typosquatted dependency names.
**Status:** compile ✅ yarac exit 0 · confidence: high
<!-- audit: `yarac arrayref_malicious_crate.yar /dev/null` exit 0. Three rules: (1) rust_proc_macro1_malicious_build_script targets base64 fragments from the published IOC Gist — 3 of 5 required to fire; (2) rust_proc_macro1_stage2_implant targets AES key "i am botking" + C2 path or 3 of 4 command strings — these are unique to this campaign; (3) rust_arrayref_malicious_crate_manifest targets Cargo.toml with proc-macro1 or proc-macro-en dependency names under [dependencies] — filesize < 64KB scopes to manifests. -->
```yara
rule rust_proc_macro1_malicious_build_script
{
    meta:
        description = "Detects the malicious build.rs from proc-macro1 typosquat crate used in the arrayref supply chain attack (August 2026). Matches base64-encoded C2 fragments and staging path."
        author = "Actioner"
        date = "2026-08-21"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        hash = "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568"

    strings:
        $b64_1 = "aHR0cHM6Ly8=" ascii
        $b64_2 = "MjMuMjU0Lg==" ascii
        $b64_3 = "MTY1Lg==" ascii
        $b64_4 = "OTA4OS8=" ascii
        $b64_5 = "NDQz" ascii
        $staging = "/tmp/rust-setup" ascii
        $staging_win = "rust-setup.ps1" ascii
        $crate_01 = "rust-crate_0.1.0" ascii
        $crate_02 = "rust-crate_0.2.0" ascii
        $crate_04 = "rust-crate_0.4.0" ascii

    condition:
        3 of ($b64_*) or ($staging and 1 of ($crate_*)) or ($staging_win and 1 of ($crate_*))
}

rule rust_proc_macro1_stage2_implant
{
    meta:
        description = "Detects the stage-2 implant delivered by the arrayref supply chain attack. Matches the hardcoded AES passphrase, C2 path, and command strings."
        author = "Actioner"
        date = "2026-08-21"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        hash_linux = "408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434"
        hash_macos = "74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306"

    strings:
        $aes_key = "i am botking" ascii wide
        $c2_path = "/49890878" ascii
        $cmd_kill = "kill" ascii
        $cmd_minicfg = "minicfg" ascii
        $cmd_startup = "startup" ascii
        $cmd_runscript = "runscript" ascii
        $vbs_launcher = "rust-setup-launch.vbs" ascii

    condition:
        ($aes_key and $c2_path) or ($c2_path and 3 of ($cmd_*)) or ($vbs_launcher and $c2_path)
}

rule rust_arrayref_malicious_crate_manifest
{
    meta:
        description = "Detects Cargo.toml manifests that declare a dependency on the typosquatted proc-macro1 crate, as used in the arrayref supply chain attack."
        author = "Actioner"
        date = "2026-08-21"
        reference = "https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/"
        hash = "25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae"

    strings:
        $dep1 = "proc-macro1" ascii nocase
        $dep2 = "proc-macro-en" ascii nocase
        $cargo = "[dependencies]" ascii nocase

    condition:
        filesize < 64KB and $cargo and ($dep1 or $dep2)
}
```

### Suricata: arrayref supply chain C2 infrastructure and beacon detection
Alerts on contact with the three published C2 IPs, the stage-2 beacon path `/49890878`, payload download URIs, and DNS resolution of the attacker hostname.
**Status:** compile ✅ suricata -T exit 0 · confidence: high
<!-- audit: `suricata -T -S arrayref_c2.rules -l /tmp/actioner` on Suricata 7.0.3 -> exit 0, "Configuration provided was successfully loaded. Exiting." No rule load errors. sid 2200901: IP-based alert for all 3 C2 IPs. sid 2200902: HTTP URI match for /49890878 beacon path (unique, not a common URI). sid 2200903: HTTP URI match for /rust-crate_0. payload download prefix. sid 2200904: DNS query for hwsrv-798836.hostwindsdns.com. All use dot-notation sticky buffers, msg prefix "Actioner -", metadata present, sids in 2200000+ range. -->
```suricata
alert ip $HOME_NET any -> [23.254.165.112,23.254.167.107,23.254.167.216] any (msg:"Actioner - arrayref supply chain C2 infrastructure contact"; flow:to_server; reference:url,blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/; classtype:trojan-activity; sid:2200901; rev:1; metadata:author Actioner, created_at 2026-08-21;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - arrayref supply chain stage-2 C2 beacon path /49890878"; flow:established,to_server; http.uri; content:"/49890878"; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; classtype:trojan-activity; sid:2200902; rev:1; metadata:author Actioner, created_at 2026-08-21;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - arrayref supply chain stage-2 payload download (rust-crate)"; flow:established,to_server; http.uri; content:"/rust-crate_0."; reference:url,semgrep.dev/blog/2026/rust-crates-arrayref-append-only-vec-compromised-proc-macro1/; classtype:trojan-activity; sid:2200903; rev:1; metadata:author Actioner, created_at 2026-08-21;)

alert dns $HOME_NET any -> any any (msg:"Actioner - arrayref supply chain attacker hostname resolution"; dns.query; content:"hwsrv-798836.hostwindsdns.com"; nocase; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; classtype:trojan-activity; sid:2200904; rev:1; metadata:author Actioner, created_at 2026-08-21;)
```

## Sources

- [Rust Blog -- Supply Chain Attack on arrayref](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/) -- official Rust Security Response Team advisory; affected versions, timeline, remediation
- [Wiz Blog -- Rust Supply Chain Attack on arrayref: Significant Overlap with DPRK Campaigns](https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns) -- DPRK attribution, infrastructure overlaps, comprehensive IOC table, implant capabilities
- [Semgrep -- Rust Crates arrayref & append-only-vec Compromised](https://semgrep.dev/blog/2026/rust-crates-arrayref-append-only-vec-compromised-proc-macro1/) -- build.rs analysis, payload hashes, C2 infrastructure, staging paths
- [Aikido -- Two popular Rust crates arrayref and append-only-vec compromised](https://www.aikido.dev/blog/two-popular-rust-crates-arrayref-and-append-only-vec-compromised-in-supply-chain-attack) -- base64 fragment details, obfuscated URL reconstruction, platform-specific execution, implant commands
- [BleepingComputer -- Hackers poison arrayref Rust crate to push infostealer malware](https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/) -- staging paths, credential theft details, persistence mechanisms
- [The Hacker News -- Rust Supply Chain Attack Puts Build-Time Malware in Crates with 245 Million Downloads](https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html) -- TLS bypass, platform-specific execution, DGA fallback, DPRK attribution summary
- [GitHub Gist (marius-benthin) -- Malicious Rust crates proc-macro1 and proc-macro-en: Analysis and IOCs](https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf) -- comprehensive IOC table including all SHA-256 hashes, DGA domains, file paths, registry keys, crypto material
- [RustSec Advisory Database -- Issue #3161](https://github.com/rustsec/advisory-db/issues/3161) -- advisory tracking, affected versions, remediation commands
- [SafeDep -- Malicious Rust Crate arrayref Runs a Build-Time Payload](https://safedep.io/arrayref-proc-macro1-rust-build-time-malware/) -- TLS bypass analysis, AcceptAll verifier, base64 fragment code, platform selection logic
- [Aikido -- Compromised Rust crate onering performs code exfiltration](https://www.aikido.dev/blog/compromised-rust-crate-onering-performs-code-exfiltration) -- onering v1.4.1 analysis, Sentry-based exfiltration mechanism, git data harvesting
- [Cryptopolitan -- Did North Korean hackers launch the supply chain attack on arrayref?](https://www.cryptopolitan.com/did-north-korea-hackers-attack-arrayref/) -- Sapphire Sleet attribution, Mastra/axios campaign links
- [TuxCare -- Inside the arrayref Supply Chain Attack](https://tuxcare.com/blog/rust-attack-arrayref/) -- base64 URL parts, AcceptAll TLS verifier, build.rs execution flow

---
*Report generated by Actioner*
