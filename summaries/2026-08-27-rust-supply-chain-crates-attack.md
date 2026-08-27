# Technical Analysis Report: Rust Crates Supply Chain Attack (2026-08-27)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-27
Version: 1.1

## Executive Summary

On August 20, 2026, compromised maintainer credentials were used to publish malicious versions of three widely-used Rust crates on crates.io: `arrayref` (0.3.10), `internment` (0.8.7), and `append-only-vec` (0.1.9). With a combined 245+ million lifetime downloads, these crates are present in over 35% of all environments and 75% of environments where Rust is used. The poisoned releases injected a typosquatted dependency -- `proc-macro1` (mimicking the legitimate `proc-macro2`) -- whose build script downloaded and executed platform-specific infostealer malware at compile time.

The Rust Security Response Team removed all malicious versions within 86-107 minutes of publication. The stage-2 implant supports Windows, macOS (Intel and Apple Silicon), and Linux, stealing Chromium-based browser credentials (Chrome, Brave, Edge), establishing persistence via platform-native mechanisms (Registry Run keys, LaunchAgents, systemd user services), and communicating with C2 infrastructure at 23.254.165[.]112 via HTTPS POST to `/49890878`. Wiz Research identified significant infrastructure overlap with DPRK-attributed operations (UNC1069/Sapphire Sleet), including shared C2 endpoints and Hostwinds LLC IP ranges used in prior North Korean campaigns.

## Background: Rust Crates Ecosystem

Rust's package manager, Cargo, fetches dependencies from crates.io and executes build scripts (`build.rs`) during compilation. This build-time execution model means that adding a malicious dependency is sufficient to achieve code execution on any machine that compiles a project -- no user interaction or function call required. The `arrayref` crate, with approximately 245 million lifetime downloads and 53.7 million downloads in the past 90 days, serves as a foundational dependency for 403 direct dependent crates. The `proc-macro2` crate -- which `proc-macro1` typosquats -- is one of the most downloaded crates in the Rust ecosystem, making its near-homonym an effective social engineering vector.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-20 07:15:00 | Malicious `arrayref@0.3.10` published to crates.io from compromised account |
| 2026-08-20 07:15:00 | Rust Security Response Team receives initial report |
| 2026-08-20 07:34:07 | Malicious `internment@0.8.7` published |
| 2026-08-20 07:37:49 | Malicious `append-only-vec@0.1.9` published |
| 2026-08-20 08:41:40 | `arrayref@0.3.10` deleted by Rust team (86 minutes online) |
| 2026-08-20 09:04:11 | `internment@0.8.7` deleted (90 minutes online) |
| 2026-08-20 09:25:24 | `append-only-vec@0.1.9` deleted (107 minutes online) |
| 2026-08-20 | Legitimate owner account (User 2402, David Roundy) locked as precaution |
| 2026-08-21 | Nextron Systems publishes initial discovery; public disclosure |
| 2026-08-21 | Wiz Research publishes DPRK attribution analysis |

## Root Cause: Compromised Maintainer Account Credentials

The attacker compromised the crates.io credentials of User 2402 (David Roundy), the legitimate maintainer of `arrayref`, `internment`, and `append-only-vec` (registered October 2009). An impersonator account "dtolney" (crates.io id 438608, email `rchaitm[at]gmail[.]com`) was also created. A secondary impersonation account "daveroundy" published `proc-macro-en@1.0.10`, mimicking the legitimate maintainer's username "droundy." The Rust Security Response Team stated: "We do not believe the author of arrayref to be acting maliciously, but their computer or credentials are likely compromised."

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection via Typosquatted Crate

Each compromised crate version added a single dependency line to its `Cargo.toml` manifest, pointing to `proc-macro1` -- a typosquat of the ubiquitous `proc-macro2` crate. The library source of `proc-macro1` was a genuine copy of `proc-macro2`, so builds completed normally and produced correct output. The malicious logic resided entirely in `proc-macro1`'s `build.rs` file.

**Malicious crates published by the attacker:**
- `proc-macro1` (versions 1.0.106, 1.0.107)
- `proc-macro-en` (version 1.0.10)
- `aovine`
- `arone`
- `aronenao`
- `tinymember`

### 2. Build Script Payload Delivery (build.rs)

The malicious `build.rs` script executes the following chain at compile time:

1. **URL Reassembly:** Reconstructs the payload host and C2 address from Base64-encoded fragments, evading static string detection
2. **TLS Bypass:** Installs a custom certificate verifier whose three verification methods return success unconditionally, disabling all TLS validation
3. **Platform Detection:** Identifies the operating system and processor architecture of the build machine
4. **Payload Download:** Downloads a platform-specific binary from the payload host at `23.254.165[.]112:9089`
5. **Execution:**
   - **Unix/macOS:** Writes payload to `/tmp/rust-setup`, marks executable, spawns detached process with C2 address as argument
   - **Windows:** Writes PowerShell script to `%TEMP%\rust-setup.ps1`, creates VBScript launcher at `%TEMP%\rust-setup-launch.vbs`, executes hidden via `wscript.exe`

### 3. C2 Infrastructure

| Component | Value | Role |
|-----------|-------|------|
| IP | 23.254.165[.]112:9089 | Payload download host |
| IP | 23.254.165[.]112:443 | Primary C2 address |
| IP | 23.254.167[.]107:443 | Live C2 server |
| IP | 23.254.167[.]216 | Victim-reported C2 |
| Domain | hwsrv-798836[.]hostwindsdns[.]com | C2 domain (Hostwinds LLC) |
| Endpoint | POST /49890878 | C2 beacon path (HTTPS) |
| Provider | Hostwinds LLC | 23.254.164.0/23 range |

The C2 beacon exfiltrates host information (hostname, username, OS, installed applications) and stolen credentials via HTTPS POST. Configuration is encrypted with AES-128-GCM using the key `"i am botking"`. Commands are authenticated via an embedded RSA-2048 private key.

**DGA Fallback:** The implant generates 10 `.com` domains every 5 days as a fallback resolution mechanism if the primary C2 is unreachable.

### 4. Platform-Specific Behavior

#### Windows
- **Delivery:** PowerShell script (`%TEMP%\rust-setup.ps1`) launched hidden via VBScript (`%TEMP%\rust-setup-launch.vbs`) through `wscript.exe`
- **Persistence:** Registry Run key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
- **Credential Theft:** Reads Chrome, Brave, and Edge SQLite profile databases for saved logins

#### macOS (Intel x86_64 and Apple Silicon aarch64)
- **Delivery:** Binary written to `/tmp/rust-setup`, marked executable, spawned detached
- **Persistence:** LaunchAgent plist installation
- **Credential Theft:** Same Chromium browser credential harvesting

#### Linux (x86_64)
- **Delivery:** Binary written to `/tmp/rust-setup`, marked executable, spawned detached
- **Persistence:** systemd user service creation
- **Credential Theft:** Same Chromium browser credential harvesting

### 5. Stage-2 Implant Capabilities

The stage-2 backdoor supports four commands:

| Command | Function |
|---------|----------|
| `kill` | Self-terminate |
| `minicfg` | Reconfigure C2 address |
| `startup` | Install persistence mechanism |
| `runscript` | Download and execute arbitrary script |

Additional capabilities include:
- Host reconnaissance (hostname, username, OS version, installed applications)
- Enumeration of cryptocurrency wallet browser extensions
- Chromium-based browser credential extraction via SQLite database queries

### 6. Anti-Forensics / Evasion Techniques

- Base64 fragment reassembly prevents static detection of C2 URLs in the build script
- Custom TLS certificate verifier bypasses certificate pinning and validation
- `proc-macro1` library code is a legitimate copy of `proc-macro2`, producing normal build output
- Windows payload launches hidden (no visible window) via VBScript intermediary
- Build-time execution leaves no trace in the application's final binary

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `23.254.165[.]112`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| arrayref | 0.3.10 | Injected `proc-macro1` dependency |
| internment | 0.8.7 | Injected `proc-macro1` dependency |
| append-only-vec | 0.1.9 | Injected `proc-macro1` dependency |
| proc-macro1 | 1.0.106, 1.0.107 | Typosquat of `proc-macro2`; contains malicious `build.rs` |
| proc-macro-en | 1.0.10 | Impersonation crate published by "daveroundy" |
| aovine | — | Attacker-controlled crate |
| arone | — | Attacker-controlled crate |
| aronenao | — | Attacker-controlled crate |
| tinymember | — | Attacker-controlled crate |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | (crate archive) | `25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae` | arrayref-0.3.10.crate |
| All | (crate archive) | `61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4` | proc-macro1-1.0.107.crate |
| All | (crate archive) | `b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436` | proc-macro1-1.0.106.crate |
| Linux | `/tmp/rust-setup` | SHA1: `f4767ad92cb61401fd69139cade563501c39b991` | Stage-2 Linux payload |
| Windows | `%TEMP%\rust-setup.ps1` | SHA1: `fc0fdb978eac72f4484b48db058e4473f1bc516e` | Stage-2 Windows payload |
| macOS | `/tmp/rust-setup` | SHA1: `ff7e20cf642346bf893f1eca808df82035bb53d0` | Stage-2 macOS arm64 payload |
| Windows | `%TEMP%\rust-setup-launch.vbs` | — | VBScript launcher for hidden PowerShell execution |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 23.254.165[.]112:9089 | Payload download host |
| IP | 23.254.165[.]112:443 | Primary C2 server |
| IP | 23.254.167[.]107:443 | Live C2 server |
| IP | 23.254.167[.]216 | Victim-reported C2 |
| Domain | hwsrv-798836[.]hostwindsdns[.]com | C2 domain resolution |
| URL Pattern | `POST /49890878` | C2 beacon endpoint |
| Email | rchaitm[at]gmail[.]com | Impersonator account email |

### Behavioral

- Cargo build process (`build.rs`) downloads and executes external binaries during compilation
- Base64-encoded URL fragments reassembled at runtime to construct C2 addresses
- Custom TLS certificate verifier that unconditionally returns success (all three verification methods)
- Detached process spawned from build context with C2 address as command-line argument
- `wscript.exe` → VBScript → hidden PowerShell execution chain on Windows
- HTTPS POST beaconing to `/49890878` with exfiltrated host info and credentials
- SQLite queries against Chromium browser profile databases (Chrome, Brave, Edge)
- DGA generating 10 `.com` domains every 5 days as fallback C2

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Injected malicious `proc-macro1` dependency into legitimate crates |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Windows payload delivered as `rust-setup.ps1` PowerShell script |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | VBScript launcher (`rust-setup-launch.vbs`) used to execute payload hidden |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Unix/macOS payload written and executed as `/tmp/rust-setup` |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome, Brave, Edge credential extraction via SQLite queries |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Windows persistence via HKCU Run key |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS persistence via LaunchAgent |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via systemd user service |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication via HTTPS POST to /49890878 |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | DGA fallback generating 10 .com domains every 5 days |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-128-GCM encrypted C2 configuration |
| T1027 | Obfuscated Files or Information | Base64 fragment reassembly to hide C2 URLs in build script |
| T1105 | Ingress Tool Transfer | Stage-2 payload downloaded from 23.254.165[.]112:9089 |

## Impact Assessment

**Breadth:** `arrayref` has 245 million lifetime downloads, approximately 53.7 million in the last 90 days, with 403 direct dependents. It is present in over 35% of all environments and ~75% of environments using Rust. `append-only-vec` has over 4 million lifetime downloads. The attack window was narrow (86-107 minutes), limiting the number of developers who actually compiled the malicious versions. The actual number of compromised systems has not been disclosed.

**Depth:** Systems that compiled the malicious crate versions during the exposure window would have executed the build-time payload automatically, resulting in credential theft (browser-stored passwords), persistent backdoor access, and potential cryptocurrency wallet compromise. The attacker gains remote command execution capabilities via the `runscript` command.

**Attribution:** Wiz Research identified significant overlap with DPRK state-sponsored operations: the C2 endpoint `/49890878` was shared with the Mastra campaign attributed to "Sapphire Sleet," the SSL issuer matched IP 23.254.167[.]13 from that campaign, and victim-reported IP 23.254.167[.]216 appears in Google Cloud analysis of UNC1069's axios npm attack linked to North Korea.

## Detection & Remediation

### Immediate Detection

Check for locally cached malicious crate versions:

```bash
# Check Cargo registry cache for malicious versions
find ~/.cargo/registry/cache -name "arrayref-0.3.10.crate" -o -name "internment-0.8.7.crate" -o -name "append-only-vec-0.1.9.crate" 2>/dev/null

# Check for proc-macro1 dependency in any Cargo.lock
grep -r "proc-macro1" ~/.cargo/registry/src/ ~/projects/ 2>/dev/null

# Check for dropped payload files
ls -la /tmp/rust-setup 2>/dev/null
ls -la "$TEMP/rust-setup.ps1" "$TEMP/rust-setup-launch.vbs" 2>/dev/null

# Check for C2 connections (Linux)
ss -tnp | grep -E "23\.254\.165\.112|23\.254\.167\.107|23\.254\.167\.216"

# Check for persistence artifacts
# macOS LaunchAgents
ls ~/Library/LaunchAgents/ | grep -i rust 2>/dev/null
# Linux systemd user services
systemctl --user list-unit-files | grep -i rust 2>/dev/null
# Windows Registry (PowerShell)
# Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-String "rust"
```

### Remediation

1. **Containment:** Block C2 IPs at the firewall: `23.254.165[.]112`, `23.254.167[.]107`, `23.254.167[.]216`. Block DNS resolution of `hwsrv-798836[.]hostwindsdns[.]com`.
2. **Eradication:** Delete cached malicious crate versions from `~/.cargo/registry/cache/` and `~/.cargo/registry/src/`. Remove `/tmp/rust-setup` and `%TEMP%\rust-setup*` files. Remove persistence mechanisms (LaunchAgent, systemd service, Registry Run key).
3. **Credential Rotation:** If a build was performed during the exposure window, rotate all credentials stored in Chromium-based browsers (Chrome, Brave, Edge). Revoke and regenerate any API keys, tokens, or passwords that may have been cached in those browsers.
4. **Dependency Audit:** Run `cargo audit` and review `Cargo.lock` for any reference to `proc-macro1`, `proc-macro-en`, `aovine`, `arone`, `aronenao`, or `tinymember`.

### Long-Term Hardening

- **Pin dependencies** in `Cargo.lock` and review all dependency updates before merging
- **Enable `cargo-vet`** or `cargo-crev` for auditing third-party dependencies
- **Restrict build-time network access** in CI/CD pipelines to prevent build scripts from downloading arbitrary payloads
- **Monitor for typosquatted crate names** in dependency trees using automated tooling
- **Implement crates.io two-factor authentication** for all publishing accounts

## Detection Rules

These detections target the specific artifacts from the Rust crates supply chain attack -- dropped payload files, C2 infrastructure, and malware strings. All rules are PoC/advisory-specific (default altitude, strict leniency) and key on distinctive indicators unlikely to produce false positives. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: Malicious rust-setup Payload File Creation (Windows)
Detects creation of the `rust-setup.ps1` or `rust-setup-launch.vbs` payload files in `%TEMP%`, dropped by the malicious `proc-macro1` build script.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch blocked by proxy, not a rule issue); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Field names: TargetFilename standard for file_event/windows (Sysmon EID 11). Values not defanged. -->
```yaml
title: Rust Supply Chain Attack - Malicious rust-setup Payload File Creation
id: 8c4e2a1b-3f7d-4e9a-b5c6-d8e0f1a2b3c4
status: experimental
description: >
    Detects creation of the rust-setup payload files dropped by the malicious
    proc-macro1 build script during compilation of compromised Rust crates
    (arrayref 0.3.10, internment 0.8.7, append-only-vec 0.1.9).
references:
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/27
tags:
    - attack.t1195.001
    - attack.t1105
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\rust-setup.ps1'
            - '\rust-setup-launch.vbs'
    condition: selection
falsepositives:
    - Unlikely - these filenames are specific to this attack
level: high
```

### Sigma: wscript.exe Launching rust-setup VBS Launcher
Detects `wscript.exe` executing the `rust-setup-launch.vbs` script, the Windows execution mechanism for the stage-2 payload.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Process creation fields Image/CommandLine standard for Sysmon EID 1 / Windows 4688. -->
```yaml
title: Rust Supply Chain Attack - wscript.exe Launching rust-setup VBS Launcher
id: 7b3d1e0f-2a6c-4d8b-9e5f-c7a4b6d3e2f1
status: experimental
description: >
    Detects wscript.exe executing the rust-setup-launch.vbs script, which is
    the Windows execution stage of the malicious proc-macro1 payload from the
    compromised Rust crates supply chain attack (August 2026).
references:
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/27
tags:
    - attack.t1059.005
    - attack.t1195.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wscript.exe'
        CommandLine|contains: 'rust-setup-launch.vbs'
    condition: selection
falsepositives:
    - Unlikely - this specific VBS filename is unique to this attack
level: critical
```

### Sigma: Network Connection to Known C2 Infrastructure
Detects outbound connections to the Hostwinds LLC IP addresses used as C2 and payload delivery servers in this campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. DestinationIp/Initiated fields standard for network_connection (Sysmon EID 3). IPs are real (not defanged) in the detection. -->
```yaml
title: Rust Supply Chain Attack - Network Connection to Known C2 Infrastructure
id: 9d5f3b2a-1e8c-4a7d-b6e0-f2c4d9a8b7e3
status: experimental
description: >
    Detects outbound network connections to the C2 and payload delivery
    infrastructure used in the compromised Rust crates supply chain attack
    (arrayref, internment, append-only-vec). IPs belong to Hostwinds LLC
    range linked to DPRK-attributed operations.
references:
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
author: Actioner
date: 2026/08/27
tags:
    - attack.t1071.001
    - attack.t1195.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '23.254.165.112'
            - '23.254.167.107'
            - '23.254.167.216'
        Initiated: 'true'
    condition: selection
falsepositives:
    - Legitimate traffic to Hostwinds LLC IP addresses (unlikely for these specific IPs)
level: critical
```

### Sigma: Linux rust-setup Payload File Creation
Detects creation of `/tmp/rust-setup` on Linux, the payload drop path used by the malicious build script.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. TargetFilename for file_event/linux. Exact path match minimizes FP. macOS uses a different product and field names — not covered by this rule. -->
```yaml
title: Rust Supply Chain Attack - Linux rust-setup Payload Creation
id: 6a2e4c1d-8b3f-4d7e-a9c5-e1b0d6f3a2c8
status: experimental
description: >
    Detects creation of /tmp/rust-setup on Linux, the payload drop path
    used by the malicious proc-macro1 build script in the compromised
    Rust crates supply chain attack (August 2026).
references:
    - https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026/08/27
tags:
    - attack.t1195.001
    - attack.t1105
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename: '/tmp/rust-setup'
    condition: selection
falsepositives:
    - Legitimate Rust toolchain setup scripts (unlikely to use this exact path)
level: high
```

### Snort: Rust Supply Chain C2 HTTP Beacon
Detects outbound traffic containing the C2 beacon path `/49890878`. Requires TLS decryption (SSL inspection proxy or MITM appliance) since the C2 communicates over HTTPS.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c /etc/snort/snort.lua -R rules -T exit 0. content:/49890878 matches the specific C2 beacon URI over port 443. Confidence medium: efficacy depends on TLS decryption being in place — without it, the encrypted payload is opaque to the sensor. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - Rust Supply Chain C2 Beacon to /49890878 Endpoint"; flow:established,to_server; content:"/49890878"; fast_pattern; classtype:trojan-activity; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; sid:2100101; rev:1;)
```

### Snort: Rust Supply Chain C2 Payload Host Connection
Detects any established outbound connection to the payload delivery IP `23.254.165[.]112`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.lua -R rules -T exit 0. IP-level match — no TLS dependency. -->
```snort
alert tcp $HOME_NET any -> 23.254.165.112 any (msg:"Actioner - Rust Supply Chain Payload Host Connection 23.254.165.112"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/; sid:2100102; rev:1;)
```

### Suricata: Rust Supply Chain C2 DNS Query
Detects DNS queries to the C2 domain `hwsrv-798836[.]hostwindsdns[.]com`. DNS is unencrypted by default, so no TLS decryption is needed.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S rules -l /tmp/actioner exit 0. dns.query buffer for domain match. DNS is cleartext — high confidence. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - Rust Supply Chain C2 DNS Query to hostwindsdns.com"; flow:to_server; dns.query; content:"hwsrv-798836.hostwindsdns.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; metadata:author Actioner, created_at 2026-08-27; sid:2200101; rev:1;)
```

### Suricata: Rust Supply Chain C2 HTTP Beacon
Detects HTTP POST to the C2 beacon endpoint `/49890878`. Requires TLS decryption (SSL inspection proxy or MITM appliance) since the C2 communicates over HTTPS.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S rules -l /tmp/actioner exit 0. http.method + http.uri for beacon POST. Confidence medium: efficacy depends on TLS decryption being in place — without it, Suricata cannot parse the HTTP layer inside TLS. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Rust Supply Chain C2 Beacon POST to /49890878"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/49890878"; fast_pattern; classtype:trojan-activity; reference:url,www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns; metadata:author Actioner, created_at 2026-08-27; sid:2200102; rev:1;)
```

### Suricata: Rust Supply Chain C2 TLS Connection
Detects TLS connections to the primary C2 IP `23.254.165[.]112`. SNI is visible pre-decryption.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S rules -l /tmp/actioner exit 0. tls protocol for IP-based TLS detection. No TLS decryption needed — IP match is at the network layer. -->
```suricata
alert tls $HOME_NET any -> 23.254.165.112 any (msg:"Actioner - Rust Supply Chain TLS Connection to C2 IP 23.254.165.112"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/; metadata:author Actioner, created_at 2026-08-27; sid:2200103; rev:1;)
```

### YARA: Malicious proc-macro1 Build Script and Stage-2 Payload
Detects the malicious build script and stage-2 implant via distinctive strings: the AES-128-GCM configuration key (`i am botking`), C2 beacon path (`/49890878`), payload drop filenames, and implant command names.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: pos.txt (containing published strings "i am botking", "/49890878", "/tmp/rust-setup", "minicfg", "runscript", "startup") fired both rules; neg.txt (benign Rust build text) quiet. Strings sourced from Wiz Research analysis. "i am botking" is the AES-128-GCM key from the implant config — highly distinctive. -->
```yara
rule Malware_Rust_Supply_Chain_Proc_Macro1_BuildScript
{
    meta:
        description = "Detects the malicious proc-macro1 build script used in the Rust crates supply chain attack (arrayref, internment, append-only-vec). Keys on distinctive strings: AES-128-GCM config key, C2 beacon path, and payload file names."
        author = "Actioner"
        date = "2026-08-27"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        hash = "61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4"
        severity = "critical"

    strings:
        $key = "i am botking" ascii wide
        $beacon = "/49890878" ascii wide
        $drop_unix = "/tmp/rust-setup" ascii
        $drop_win1 = "rust-setup.ps1" ascii wide
        $drop_win2 = "rust-setup-launch.vbs" ascii wide
        $cmd1 = "minicfg" ascii
        $cmd2 = "runscript" ascii
        $cmd3 = "startup" ascii

    condition:
        filesize < 10MB and
        (
            $key or
            ($beacon and 1 of ($drop*)) or
            (2 of ($drop*) and 1 of ($cmd*)) or
            (3 of ($cmd*) and 1 of ($drop*))
        )
}

rule Malware_Rust_Supply_Chain_Stage2_Payload
{
    meta:
        description = "Detects the stage-2 implant payload from the Rust crates supply chain attack via distinctive command strings and configuration key."
        author = "Actioner"
        date = "2026-08-27"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        severity = "critical"

    strings:
        $key = "i am botking" ascii
        $cmd_kill = "kill" ascii fullword
        $cmd_minicfg = "minicfg" ascii fullword
        $cmd_startup = "startup" ascii fullword
        $cmd_runscript = "runscript" ascii fullword
        $c2_path = "/49890878" ascii
        $host = "hostwindsdns.com" ascii

    condition:
        filesize < 10MB and
        $key and
        (2 of ($cmd*) or $c2_path or $host)
}
```

## Lessons Learned

1. **Build-time execution is a systemic risk.** Cargo's `build.rs` mechanism -- like npm's lifecycle hooks and PyPI's `setup.py` -- creates an attack surface where dependency installation alone achieves code execution. Ecosystems must consider restricting or sandboxing build-time scripts, as Deno and Bun have done for runtime code.

2. **Typosquatting remains effective even in curated registries.** The proximity of `proc-macro1` to the ubiquitous `proc-macro2` made the malicious dependency easy to overlook in code review. Automated tools that flag near-homonym dependencies at publish time or in CI would significantly reduce this class of attack.

3. **Supply chain attacks can move fast but defenders can too.** The 86-107 minute exposure window demonstrates that rapid response can limit blast radius. However, even this narrow window was sufficient for potential compromise of developer machines that happened to build during that period. Detection of build-time anomalies (unexpected network connections, file writes to `/tmp` during compilation) should be prioritized.

4. **Nation-state actors target developer supply chains.** The DPRK attribution (overlapping infrastructure with UNC1069/Sapphire Sleet) confirms that software supply chain attacks are a strategic tool for state-sponsored threat actors seeking credentials, cryptocurrency, and access to downstream organizations.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Rust Blog - Supply Chain Attack on arrayref](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/) -- official Rust Security Response Team advisory with timeline and remediation guidance
- [Wiz Research - DPRK Campaign Overlap Analysis](https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns) -- primary technical analysis with C2 infrastructure details, malware capabilities, hashes, and DPRK attribution
- [The Hacker News - Rust Supply Chain Attack](https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html) -- summary reporting with timeline and payload behavior details
- [The Register - Hackers Poison Popular Rust Crates](https://www.theregister.com/security/2026/08/21/hackers-poison-popular-rust-crates-to-steal-developers-credentials/5291075) -- reporting on impact scope and platform coverage
- [Semgrep - Rust Crates Compromised Analysis](https://semgrep.dev/blog/2026/rust-crates-arrayref-append-only-vec-compromised-proc-macro1/) -- technical analysis of build script behavior and payload delivery mechanism
- [Aikido - Popular Rust Crates Compromised](https://www.aikido.dev/blog/two-popular-rust-crates-arrayref-and-append-only-vec-compromised-in-supply-chain-attack) -- additional coverage of the supply chain compromise

---
*Report generated by Actioner*
