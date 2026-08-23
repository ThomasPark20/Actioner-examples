# Technical Analysis Report: Rust Crates Supply Chain Attack (North Korea-linked) (2026-08-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-23
Version: DRAFT

## Executive Summary

On August 20, 2026, malicious versions of three popular Rust crates -- arrayref (0.3.10), internment (0.8.7), and append-only-vec (0.1.9) -- were published to crates.io after the legitimate maintainer's credentials were likely compromised. The poisoned releases injected a typosquatted dependency `proc-macro1` (mimicking the legitimate `proc-macro2`) whose build script downloaded and executed OS-specific infostealer malware targeting Chromium browser credentials and cryptocurrency wallet data. The malicious packages were live for 86-107 minutes before the Rust Security Response Team removed them, during which approximately 2,285 downloads of the malicious arrayref version occurred. The attack infrastructure, hosted on Hostwinds (23.254.165[.]112), shows "substantial overlap" with prior North Korean supply chain operations targeting the npm ecosystem (Mastra, Axios), with Wiz linking it to Sapphire Sleet (Microsoft designation) / MIDNIGHT NEPTUNE (Google GTIG designation).

## Background: Rust Crate Ecosystem (crates.io)

Crates.io is the official package registry for the Rust programming language, serving as the primary distribution channel for Rust libraries. The `arrayref` crate alone had over 245 million total downloads and was present in approximately 75% of Rust environments running in cloud infrastructure, with 403 distinct crates depending on it through the dependency chain (e.g., winit -> sctk-adwaita -> tiny-skia -> arrayref). The Rust build system, Cargo, automatically executes `build.rs` build scripts during `cargo build`, `cargo check`, or `cargo test`, making build script injection a potent attack vector -- code executes at compile time, before any application deployment or execution.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-20 ~07:00 | Attacker gains access to maintainer's crates.io credentials (method undisclosed) |
| 2026-08-20 07:15 | `arrayref@0.3.10` published with `proc-macro1` dependency; versions 0.3.5-0.3.9 maliciously yanked |
| 2026-08-20 07:34 | `internment@0.8.7` published with same malicious dependency |
| 2026-08-20 07:37 | `append-only-vec@0.1.9` published with same malicious dependency |
| 2026-08-20 08:41 | Rust Security Response Team removes `arrayref@0.3.10` (86 min exposure) |
| 2026-08-20 09:04 | `internment@0.8.7` removed (90 min exposure) |
| 2026-08-20 09:25 | `append-only-vec@0.1.9` removed (107 min exposure) |
| 2026-08-20 ~09:30 | Maliciously yanked versions unyanked; maintainer account locked; all versions of `proc-macro1`, `proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember` deleted |
| 2026-08-21 | RUSTSEC-2026-0260 advisory published; Nextron Systems publishes initial analysis |
| 2026-08-21 | Wiz publishes infrastructure analysis linking attack to North Korean operations |

## Root Cause: Credential Compromise and Dependency Injection

The attacker compromised the legitimate maintainer's crates.io credentials (the Rust Security Response Team stated they suspected "the developer's computer or credentials were compromised" rather than intentional malicious contribution). With access to the account, the attacker:

1. **Yanked versions 0.3.5-0.3.9** of `arrayref`, making 0.3.10 appear as the only non-yanked recent version, triggering Cargo's update warnings for developers pinned to those versions
2. **Published 0.3.10** with an added dependency on the typosquatted `proc-macro1` crate
3. **Replicated the attack** across `internment` and `append-only-vec` within 22 minutes

The dependency injection was subtle -- the `proc-macro1` name closely resembles the widely-used `proc-macro2` crate, and the malicious code resided entirely in the dependency's build script rather than in the visible library code.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection via proc-macro1

The poisoned crate versions added `proc-macro1` as a build dependency. This crate, along with related attacker-controlled crates (`proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember`), contained a malicious `build.rs` file. Cargo automatically executes build scripts during compilation, so any developer running `cargo build`, `cargo check`, or `cargo test` on an affected project would trigger the payload without any explicit execution step.

### 2. Build Script Payload Delivery

The `build.rs` file performed the following sequence:

- **Reassembled C2 infrastructure addresses** from base64-encoded fragments, obscuring the payload host and C2 address from simple string scanning
- **Installed a custom TLS certificate verifier** that disabled certificate validation, enabling man-in-the-middle-resistant communication with attacker infrastructure without legitimate certificates
- **Detected the target OS and CPU architecture** to select the appropriate platform-specific payload
- **Downloaded the matching payload** from the delivery server (23.254.165[.]112:9089)
- **Executed the payload** as a detached process with the C2 address passed as a command-line argument

### 3. Platform-Specific Execution

#### Unix/macOS
- Payload written to `/tmp/rust-setup`
- Spawned as a detached process with the C2 address (23.254.165[.]112:443) as argument
- Built separately for Linux, Intel macOS, and Apple Silicon macOS

#### Windows
- PowerShell script written to `%TEMP%\rust-setup.ps1`
- A VBScript launcher written to `%TEMP%\rust-setup-launch.vbs`
- Executed via `wscript.exe` launching the VBS file, which in turn executed the PowerShell script
- The VBScript indirection was specifically designed to escape Cargo's Windows job object, allowing the child process to survive after the build completed

### 4. Stage-2 Infostealer Capabilities

The downloaded stage-2 implant (named `rust-crate_0.1.0` through `rust-crate_0.4.0`) operated as an infostealer targeting:

- **Browser credentials**: Queried SQLite login databases from Chromium-based browsers (Google Chrome, Brave, Microsoft Edge), extracting `origin_url` and `username_value` columns
- **Cryptocurrency wallets**: Targeted browser extension storage for crypto wallet extensions
- **Developer environment secrets**: Harvested environment variables and configuration files

### 5. C2 Infrastructure and Persistence

**C2 communication** used HTTPS to 23.254.165[.]112:443 with the domain hwsrv-798836[.]hostwindsdns[.]com, hosted on Hostwinds LLC infrastructure.

**Persistence mechanisms** varied by platform:
- **Windows**: Registry Run key
- **macOS**: LaunchAgent
- **Linux**: systemd user service

### 6. Anti-Forensics / Evasion Techniques

- Base64 fragment reassembly for C2 addresses to evade static string scanning
- Custom TLS certificate verifier to avoid reliance on legitimate CA infrastructure
- VBScript indirection on Windows to escape Cargo's job object process tree
- Typosquatting (`proc-macro1` vs `proc-macro2`) to avoid visual inspection
- Version yanking to force upgrades to the malicious version

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| arrayref | 0.3.10 | Added `proc-macro1` dependency; versions 0.3.5-0.3.9 maliciously yanked |
| internment | 0.8.7 | Added `proc-macro1` dependency |
| append-only-vec | 0.1.9 | Added `proc-macro1` dependency |
| proc-macro1 | all | Typosquatted crate; malicious build.rs downloads/executes infostealer |
| proc-macro-en | all | Related attacker-controlled crate |
| aovine | all | Related attacker-controlled crate |
| arone | all | Related attacker-controlled crate |
| aronenao | all | Related attacker-controlled crate |
| tinymember | all | Related attacker-controlled crate |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux/macOS | /tmp/rust-setup | Not disclosed | Stage-1 payload binary |
| Windows | %TEMP%\rust-setup.ps1 | Not disclosed | Stage-1 PowerShell payload |
| Windows | %TEMP%\rust-setup-launch.vbs | Not disclosed | VBScript launcher to escape Cargo job object |
| Cross-platform | rust-crate_0.1.0 - rust-crate_0.4.0 | Not disclosed | Stage-2 infostealer binaries |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 23.254.165[.]112 | C2 server (port 443) and payload delivery (port 9089) |
| Domain | hwsrv-798836[.]hostwindsdns[.]com | C2 domain, resolving to the above IP |
| Port | 443 | C2 communication port |
| Port | 9089 | Payload delivery port |
| Hosting | Hostwinds LLC | Infrastructure provider |

### Behavioral

- Build script (`build.rs`) in Cargo dependency executes during `cargo build`/`cargo check`/`cargo test`
- Base64 fragment reassembly of C2/payload host addresses at build time
- Custom TLS certificate verifier disabling validation
- OS/architecture detection for platform-specific payload selection
- Detached process spawning with C2 address as command-line argument
- On Windows: `wscript.exe` launching VBScript to escape job object
- SQLite queries against Chromium browser login databases (`origin_url`, `username_value` columns)
- Persistence via platform-native mechanisms (Registry Run key / LaunchAgent / systemd)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Poisoned versions of legitimate Rust crates with malicious dependency |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Windows payload delivered as PowerShell script (rust-setup.ps1) |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | VBScript launcher (rust-setup-launch.vbs) to escape Cargo job object |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Unix payload spawned as detached process from /tmp/rust-setup |
| T1105 | Ingress Tool Transfer | Build script downloads OS-specific stage-2 payload from 23.254.165[.]112:9089 |
| T1553.004 | Subvert Trust Controls: Install Root Certificate | Custom TLS certificate verifier disabling validation |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Stage-2 extracts Chrome/Brave/Edge login database credentials |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Windows persistence via Registry Run key |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS persistence via LaunchAgent |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via systemd user service |
| T1036.001 | Masquerading: Invalid Code Signature | Typosquatted package name (proc-macro1 vs proc-macro2) |
| T1082 | System Information Discovery | OS and CPU architecture detection for payload selection |

## Impact Assessment

- **Breadth**: arrayref has 245+ million total downloads and is present in ~75% of Rust cloud environments. The dependency chain (winit -> sctk-adwaita -> tiny-skia -> arrayref) affects a large subset of the Rust GUI and graphics ecosystem. However, only 2,285 downloads of the malicious version occurred during the 86-minute window.
- **Depth**: The infostealer targets browser credentials and cryptocurrency wallets, enabling credential theft, financial theft, and potential lateral movement. The persistence mechanisms ensure continued access beyond the initial compromise.
- **Stealth**: The attack was sophisticated -- build-time execution, typosquatted dependency naming, base64 fragment reassembly, and version yanking all contributed to evasion. The short exposure window (86-107 minutes) limited but did not eliminate impact.
- **Attribution overlap**: Infrastructure shares patterns with previous North Korean operations targeting npm (Mastra compromise, Axios compromise), representing the first known extension of this NK supply chain campaign to the Rust ecosystem.

## Detection & Remediation

### Immediate Detection

Check for the presence of the malicious dependency in local Cargo caches and lock files:

```bash
# Check for proc-macro1 in Cargo.lock files
grep -r "proc-macro1" ~/.cargo/registry/ /path/to/projects/*/Cargo.lock

# Check for the malicious versions specifically
grep -rE "(arrayref.*0\.3\.10|internment.*0\.8\.7|append-only-vec.*0\.1\.9)" ~/.cargo/registry/ /path/to/projects/*/Cargo.lock

# Check for payload artifacts
ls -la /tmp/rust-setup 2>/dev/null
ls -la "$TEMP/rust-setup.ps1" "$TEMP/rust-setup-launch.vbs" 2>/dev/null

# Check for C2 connections
ss -tnp | grep "23.254.165.112"
```

```powershell
# Windows: Check for payload artifacts
Get-Item "$env:TEMP\rust-setup.ps1", "$env:TEMP\rust-setup-launch.vbs" -ErrorAction SilentlyContinue

# Windows: Check Registry Run key persistence
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-String "rust"
```

### Remediation

1. **Verify Cargo.lock**: Confirm no reference to `proc-macro1`, `arrayref 0.3.10`, `internment 0.8.7`, or `append-only-vec 0.1.9` in any Cargo.lock file
2. **Pin known-good versions**: Use `arrayref <= 0.3.9`, `internment <= 0.8.6`, `append-only-vec <= 0.1.8`
3. **Remove payload artifacts**: Delete `/tmp/rust-setup`, `%TEMP%\rust-setup.ps1`, `%TEMP%\rust-setup-launch.vbs`
4. **Remove persistence**: Check and remove Registry Run keys, LaunchAgents, and systemd user services referencing rust-related binaries
5. **Rotate credentials**: If compromised, rotate all browser-stored passwords for Chrome, Brave, and Edge; revoke and rotate cryptocurrency wallet keys
6. **Audit network logs**: Review connections to 23.254.165[.]112 (ports 443 and 9089) and DNS queries for hwsrv-798836[.]hostwindsdns[.]com
7. **Clear Cargo cache**: Run `cargo cache --autoclean` or manually purge `~/.cargo/registry/cache/` and `~/.cargo/registry/src/` for the affected crates

### Long-Term Hardening

- **Use `cargo-vet` or `cargo-crev`** to audit crate dependencies and build scripts before adoption
- **Pin dependencies** with exact versions in `Cargo.lock` and review all dependency updates
- **Monitor for build script changes** in dependency updates, particularly new `build.rs` files or new build dependencies
- **Network segmentation** for build environments to restrict outbound connections during compilation
- **Enable crates.io publishing notifications** for critical dependencies

## Detection Rules

These detections target the specific artifacts and infrastructure from the proc-macro1 Rust crate supply chain attack. Sigma rules cover host-level payload execution and C2 connections; YARA covers file-level indicators in the malicious crate and payload binaries; Snort/Suricata cover network indicators. Compiles does not equal fires -- verify in your pipeline.

### Sigma: Execution of Rust Supply Chain Payload on Linux

Detects execution of the `/tmp/rust-setup` payload binary dropped by the malicious proc-macro1 build script on Linux/macOS.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE ATT&CK data fetch 403 (proxy); splunk convert exit 0; log_scale convert exit 0. Values are real paths, not defanged. High confidence: /tmp/rust-setup is a highly distinctive path unlikely in benign activity. -->
```yaml
title: Execution of Rust Supply Chain Payload - rust-setup
id: 8c3f2a1e-5b7d-4e9a-af12-3c6d8e0b1f4a
status: experimental
description: >
    Detects execution of the rust-setup payload dropped by the malicious proc-macro1
    Rust crate build script, which downloads and runs an OS-specific infostealer.
references:
    - https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref
    - https://rustsec.org/advisories/RUSTSEC-2026-0260.html
author: Actioner
date: 2026/08/23
tags:
    - attack.t1195.002
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/rust-setup'
        Image|startswith: '/tmp/'
    condition: selection
falsepositives:
    - Legitimate Rust toolchain installers using similar naming (unlikely in /tmp/)
level: high
```

### Sigma: Rust Supply Chain VBScript Payload Launcher (Windows)

Detects `wscript.exe` launching `rust-setup-launch.vbs` -- the Windows-specific execution chain used to escape Cargo's job object.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE ATT&CK data fetch 403 (proxy); splunk convert exit 0; log_scale convert exit 0. CommandLine contains the exact distinctive VBS filename. No known benign use of rust-setup-launch.vbs. -->
```yaml
title: Rust Supply Chain VBScript Payload Launcher
id: 1a4e7c9b-3d2f-48a6-b5e1-7f0c6d8a2e3b
status: experimental
description: >
    Detects wscript.exe launching the rust-setup-launch.vbs script dropped
    by the malicious proc-macro1 build script to escape Cargo's job object
    and execute the PowerShell infostealer payload on Windows.
references:
    - https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref
author: Actioner
date: 2026/08/23
tags:
    - attack.t1195.002
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wscript.exe'
        CommandLine|contains: 'rust-setup-launch.vbs'
    condition: selection
falsepositives:
    - None expected
level: critical
```

### Sigma: Rust Supply Chain Payload File Creation

Detects creation of the distinctive payload files (rust-setup.ps1, rust-setup-launch.vbs, /tmp/rust-setup) dropped by the proc-macro1 build script.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE ATT&CK data fetch 403 (proxy); splunk convert exit 0; log_scale convert exit 0. File names are specific to this campaign. Cross-platform rule (no product specified). -->
```yaml
title: Rust Supply Chain Payload File Creation
id: 5d9e3b7a-1c4f-42e8-a6d0-8b2f7e1c3a5d
status: experimental
description: >
    Detects creation of rust-setup payload files (PowerShell script, VBScript launcher,
    or Unix binary) in temporary directories, as dropped by the malicious proc-macro1
    Rust crate build script.
references:
    - https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref
author: Actioner
date: 2026/08/23
tags:
    - attack.t1195.002
    - attack.t1105
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - 'rust-setup.ps1'
            - 'rust-setup-launch.vbs'
            - '/tmp/rust-setup'
    condition: selection
falsepositives:
    - Legitimate Rust toolchain setup scripts with similar naming
level: high
```

### Sigma: Network Connection to Rust Crate Supply Chain C2

Detects outbound connections to the known C2/payload IP 23.254.165.112 used in this campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE ATT&CK data fetch 403 (proxy); splunk convert exit 0; log_scale convert exit 0. IP-based IOC detection; rotates if actor changes infra but high-value for retrospective hunting. -->
```yaml
title: Network Connection to Rust Crate Supply Chain C2 Infrastructure
id: 2e6f4a8c-9d1b-43e7-b5c0-7a3e2f1d6b8c
status: experimental
description: >
    Detects outbound network connections to the known C2 and payload delivery IP
    address (23.254.165.112) used by the malicious proc-macro1 Rust crate supply
    chain attack infrastructure hosted on Hostwinds.
references:
    - https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
    - https://www.securityweek.com/rust-supply-chain-attack-linked-to-north-korean-hackers/
author: Actioner
date: 2026/08/23
tags:
    - attack.t1195.002
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '23.254.165.112'
    condition: selection
falsepositives:
    - Legitimate services hosted on the same Hostwinds IP (unlikely given malicious indicators)
level: critical
```

### Snort: Rust Crate Supply Chain C2 Connection

Detects outbound TCP connections to the known C2 IP 23.254.165.112 and to the payload delivery port 9089.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c (minimal config with classification) -T exit 0. Two rules: C2 IP any port + payload delivery port 9089. IP-based; will rotate. -->
```snort
alert tcp $HOME_NET any -> 23.254.165.112 any (msg:"Actioner - Rust Crate Supply Chain C2 Connection to 23.254.165.112"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html; metadata:author Actioner, created 2026-08-23; sid:2100101; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 9089 (msg:"Actioner - Rust Crate Supply Chain Payload Download on Port 9089"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html; metadata:author Actioner, created 2026-08-23; sid:2100102; rev:1;)
```

### Suricata: DNS Query and C2 Connection for Rust Crate Supply Chain

Detects DNS queries for the C2 domain hwsrv-798836.hostwindsdns.com and TCP connections to the C2 IP.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. DNS query rule uses dns.query sticky buffer (Suricata-native). IP rule is a direct IOC match. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Rust Crate Supply Chain C2 Domain"; flow:to_server; dns.query; content:"hwsrv-798836.hostwindsdns.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html; metadata:author Actioner, created_at 2026-08-23; sid:2200101; rev:1;)
alert tcp $HOME_NET any -> 23.254.165.112 any (msg:"Actioner - Connection to Rust Crate Supply Chain C2 IP"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html; metadata:author Actioner, created_at 2026-08-23; sid:2200102; rev:1;)
```

### YARA: Malicious proc-macro1 Build Script and Infostealer Payload

Detects the malicious proc-macro1 crate content (build script strings, payload paths, C2 indicators) and the stage-2 infostealer payload binaries.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: fired on positive (proc-macro1 + payload paths + C2 IP), quiet on negative (proc-macro2 + benign paths). Two rules: BuildScript (crate/source level) and InfoStealer (binary level). Strings are published source indicators. -->
```yara
rule Malware_RustCrate_ProcMacro1_BuildScript
{
    meta:
        description = "Detects malicious build.rs content from the proc-macro1 typosquatted Rust crate used in the August 2026 supply chain attack on arrayref, internment, and append-only-vec"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html"
        severity = "critical"

    strings:
        $dep_name = "proc-macro1" ascii
        $payload_unix = "/tmp/rust-setup" ascii
        $payload_win_ps = "rust-setup.ps1" ascii
        $payload_win_vbs = "rust-setup-launch.vbs" ascii
        $c2_ip = "23.254.165.112" ascii
        $c2_domain = "hwsrv-798836.hostwindsdns.com" ascii
        $binary_prefix = "rust-crate_0." ascii

    condition:
        filesize < 5MB and
        (
            ($dep_name and 2 of ($payload_*)) or
            ($c2_ip or $c2_domain) and 1 of ($payload_*) or
            3 of them
        )
}

rule Malware_RustCrate_InfoStealer_Payload
{
    meta:
        description = "Detects the infostealer payload binary (rust-crate_0.x.0) dropped by the proc-macro1 supply chain attack, targeting Chromium browser credentials and crypto wallets"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html"
        severity = "critical"

    strings:
        $name1 = "rust-crate_0.1.0" ascii fullword
        $name2 = "rust-crate_0.2.0" ascii fullword
        $name3 = "rust-crate_0.3.0" ascii fullword
        $name4 = "rust-crate_0.4.0" ascii fullword
        $steal1 = "origin_url" ascii
        $steal2 = "username_value" ascii
        $c2 = "23.254.165.112" ascii
        $host = "hwsrv-798836.hostwindsdns.com" ascii

    condition:
        filesize < 10MB and
        (
            any of ($name*) and (1 of ($steal*) or $c2 or $host) or
            all of ($steal*) and ($c2 or $host)
        )
}
```

## Lessons Learned

1. **Build-time execution is a first-class attack surface**: Rust's `build.rs` scripts (like npm's `postinstall` scripts) execute arbitrary code during compilation. Unlike runtime dependencies, build dependencies run code before any application security review or deployment gate. The ecosystem needs stronger controls on build script capabilities -- such as sandboxed builds or explicit opt-in for network access during compilation.

2. **Typosquatting extends to build dependencies**: The `proc-macro1` vs `proc-macro2` naming was specifically chosen for plausible visual similarity. Automated dependency auditing tools should flag new build dependencies whose names have low edit distance from popular crates.

3. **North Korean supply chain operations are expanding across ecosystems**: This attack demonstrates the extension of known NK supply chain TTPs (previously observed in npm with Mastra and Axios) to the Rust ecosystem. The shared infrastructure patterns suggest a systematic campaign rather than opportunistic targeting. Organizations should apply the same supply chain security posture to Rust crates as they do to npm/PyPI packages.

4. **Version yanking as an attack amplifier**: The deliberate yanking of versions 0.3.5-0.3.9 to funnel users toward the malicious 0.3.10 is a novel amplification technique. Registries should consider rate-limiting or flagging mass version yanking followed by a new publish.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [The Hacker News](https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html) — Detailed technical analysis including C2 infrastructure, platform-specific payload behavior, file paths, and binary names
- [SecurityWeek](https://www.securityweek.com/rust-supply-chain-attack-linked-to-north-korean-hackers/) — Attribution analysis linking to Sapphire Sleet and prior NK npm campaigns (Mastra, Axios)
- [The Register](https://www.theregister.com/security/2026/08/21/hackers-poison-popular-rust-crates-to-steal-developers-credentials/5291075) — Attack timeline, Nextron Systems and Aikido discovery details, download metrics
- [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/north-korean-rust-supply-chain/) — Download counts for all three crates, attribution to Sapphire Sleet, C2 infrastructure overlap analysis
- [Rust Blog](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref) — Official Rust Security Response Team incident timeline and response actions
- [RustSec Advisory RUSTSEC-2026-0260](https://rustsec.org/advisories/RUSTSEC-2026-0260.html) — Official advisory for arrayref; confirmed 2,285 downloads of malicious version

---
*Report generated by Actioner*
