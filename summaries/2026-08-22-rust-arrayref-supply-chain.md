# Technical Analysis Report: Rust crates.io Supply Chain Attack — arrayref, internment, append-only-vec (2026-08-22)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-22
Version: 1.0 DRAFT

## Executive Summary

On August 20, 2026, a threat actor compromised the crates.io accounts of a trusted Rust package maintainer and published malicious versions of three popular crates: **arrayref** (v0.3.10, 245M+ lifetime downloads), **internment** (v0.8.7, 14M+ downloads), and **append-only-vec** (v0.1.9, 4.5M+ downloads). The poisoned packages injected a dependency on `proc-macro1`, a typosquat of the legitimate `proc-macro2` crate, which contained a malicious `build.rs` script. During compilation, this script downloaded platform-specific infostealer implants from a Hostwinds-hosted server at `23.254.165[.]112`, targeting Linux, Windows, and macOS (x86-64 and ARM64). The implant steals browser credentials from Chrome, Brave, and Edge, establishes persistence via OS-native mechanisms (Registry Run key, LaunchAgent, systemd), and communicates with its C2 over HTTPS to `/49890878`. The Rust Security Response Team removed all malicious versions within 86-107 minutes of detection. Wiz researchers identified substantial infrastructure overlap with prior DPRK-linked supply chain campaigns (Mastra npm, Axios npm), attributing the activity to **Sapphire Sleet**. The RustSec Advisory is tracked as **RUSTSEC-2026-0260**.

## Background: Rust crates.io Ecosystem

Crates.io is the official package registry for the Rust programming language, serving as the primary distribution point for Rust libraries ("crates"). The arrayref crate alone had over 245 million lifetime downloads and was present in approximately 75% of cloud Rust environments via transitive dependency chains (e.g., blake3, winit, sctk-adwaita, tiny-skia). Unlike npm or PyPI, Rust's Cargo build system automatically executes `build.rs` build scripts during compilation, providing a pre-runtime code execution vector that fires in CI/CD pipelines and developer workstations before any application code runs. The compromised maintainer account, `droundy` (user 2402, registered October 2009), belonged to David Roundy, the original author of all three crates. The attacker also created an impersonator account `dtolney` (crates.io id 438608) mimicking prominent Rust maintainer David Tolnay.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-20 01:17 | GitHub account impersonating David Tolnay created |
| 2026-08-20 01:55 | `proc-macro1@1.0.106` published (benign seed version) |
| 2026-08-20 07:11 | `proc-macro1@1.0.107` published (malicious payload) |
| 2026-08-20 07:15 | `arrayref@0.3.10` published; versions 0.3.5-0.3.9 yanked simultaneously |
| 2026-08-20 07:15 | Rust Security Response Team receives initial report from Nextron Systems GmbH |
| 2026-08-20 07:34 | `internment@0.8.7` published |
| 2026-08-20 07:37 | `append-only-vec@0.1.9` published |
| 2026-08-20 07:54 | Incident publicly reported |
| 2026-08-20 08:03 | `proc-macro1` deleted from crates.io |
| 2026-08-20 08:41 | `arrayref@0.3.10` removed from index (86 min online) |
| 2026-08-20 09:04 | `internment@0.8.7` removed (90 min online) |
| 2026-08-20 09:09 | `blake3@1.8.7` drops arrayref dependency |
| 2026-08-20 09:25 | `append-only-vec@0.1.9` removed (107 min online) |
| 2026-08-20 09:25-09:26 | `blake2b_simd` and `blake2s_simd` remove arrayref dependency |

## Root Cause: Compromised Maintainer Account

The attacker gained control of the `droundy` crates.io account (David Roundy, registered October 2009) and used it to publish malicious versions of three crates he maintained. The attack was methodical: the attacker first seeded a benign version of `proc-macro1` (v1.0.106) at 01:55 UTC, then published the malicious version (v1.0.107) at 07:11, and began publishing poisoned crate versions starting at 07:15. Simultaneously, versions 0.3.5 through 0.3.9 of arrayref were yanked, forcing `cargo update` to resolve to the malicious 0.3.10 and leveraging Cargo's yanked-version warnings as a psychological lure for developers to "upgrade." A separate impersonator account `dtolney` was created on GitHub, forging the identity of prominent Rust developer David Tolnay, with a forged email of `rchaitm[at]gmail[.]com`.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection via Typosquat

Each compromised crate received a single-line manifest change:

```toml
[dependencies]
proc-macro1 = "1.0.107"
```

The `proc-macro1` crate was a functional copy of the legitimate `proc-macro2` crate's source code, ensuring builds completed normally and API compatibility was preserved. The only addition was a malicious `build.rs` script that executed during compilation.

Additional malicious typosquat crates were also published: `proc-macro-en`, `aovine`, `arone`, `aronenao`, and `tinymember`.

### 2. Build Script Payload Execution

The malicious `build.rs` (SHA256: `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568`) reconstructed its C2 infrastructure from base64-encoded fragments during compilation. It installed a custom TLS certificate verifier (`AcceptAll`) that returns success unconditionally, disabling TLS validation for the download. The script then selected and downloaded a platform-specific payload:

| Platform | Payload URL | Binary Name |
|----------|-------------|-------------|
| Linux x86-64 | `hxxps://23.254.165[.]112:9089/rust-crate_0.1.0` | `rust-crate_0.1.0` |
| Windows x86-64 | `hxxps://23.254.165[.]112:9089/rust-crate_0.2.0` | `rust-crate_0.2.0` |
| macOS x86-64 | `hxxps://23.254.165[.]112:9089/rust-crate_0.3.0` | `rust-crate_0.3.0` |
| macOS ARM64 | `hxxps://23.254.165[.]112:9089/rust-crate_0.4.0` | `rust-crate_0.4.0` |

**Unix/macOS execution:** Writes payload to `/tmp/rust-setup`, marks executable, spawns as a detached process with the C2 address as its first argument.

**Windows execution:** Writes PowerShell script to `%TEMP%\rust-setup.ps1`, creates a VBScript launcher (`%TEMP%\rust-setup-launch.vbs`), executes it via `wscript.exe` to escape Cargo's job object and run the PowerShell payload hidden.

### 3. C2 Infrastructure

| Component | Value |
|-----------|-------|
| Primary C2 IP | `23.254.165[.]112` |
| Secondary C2 IP | `23.254.167[.]107` |
| Payload port | TCP 9089 |
| C2 port | TCP 443 |
| Beacon endpoint | `POST /49890878` |
| Hosting provider | Hostwinds LLC |
| Reverse DNS | `hwsrv-798836[.]hostwindsdns[.]com` |
| IP range | `23.254.164.0/23` |
| Encryption | AES-128-GCM, hardcoded key: `i am botking` |
| Command auth | Embedded RSA-2048 private key |

The implant beacons via HTTPS POST with Base64-encoded JSON exfiltration data. It supports four commands:
- **kill** — terminate the implant
- **minicfg** — reconfigure C2 address/beacon interval (AES key: `test`)
- **startup** — install OS persistence
- **runscript** — download and execute PowerShell (Windows) or shell scripts (Unix)

**DGA Fallback:** The implant generates ten-character mixed-case `.com` domains every 5 days as C2 fallback. Known domains for August 20-24, 2026:

`rasGThauFD[.]com`, `feVVKIiEiU[.]com`, `phrpjTNckF[.]com`, `PrOkXLgfjW[.]com`, `ackeoTaWtl[.]com`, `GAFWVCMAja[.]com`, `RNSsddnEgK[.]com`, `pfHlVOqEeg[.]com`, `aBEcOrkups[.]com`, `epOdIaTMaM[.]com`

### 4. Platform-Specific Behavior

#### Linux
- **Payload path:** `/tmp/rust-setup`
- **Persistence:** Systemd user service
- **Capabilities:** Credential harvesting, remote script execution

#### Windows
- **Payload path:** `%TEMP%\rust-setup.ps1` (35,578 bytes, PowerShell 5.1+)
- **Launcher:** `%TEMP%\rust-setup-launch.vbs` via `wscript.exe`
- **Config:** `%TEMP%\rust-setup.ps1.cfg`
- **Persistence:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with value `powershell -ep bypass -w h -File "<payload path>"`
- **Backdoor copy:** `%APPDATA%\<operator-folder>\<name>.ps1` with `.cfg`
- **Command scripts:** `%TEMP%\ps-<GUID>.ps1`
- **SQLite toolkit:** `%TEMP%\sqlite_<GUID>\sqlite-tools.zip`
- **Browser credential harvesting:** Queries SQLite `Login Data` databases for Chrome, Brave, Edge

#### macOS
- **Payload path:** `/tmp/rust-setup`
- **Persistence:** LaunchAgent
- **Capabilities:** Same as Linux; ARM64 and x86-64 variants

### 5. Anti-Forensics / Evasion Techniques

- Custom TLS certificate verifier (`AcceptAll`) disables certificate validation for payload downloads
- Base64-encoded infrastructure fragments in build.rs prevent static string matching on the source
- VBScript wrapper on Windows escapes Cargo's job object to survive build process termination
- Hidden PowerShell window (`-w h`) and execution policy bypass (`-ep bypass`)
- DGA fallback provides C2 resilience if primary infrastructure is taken down
- AES-128-GCM encryption on C2 communications
- RSA-2048 command authentication prevents unauthorized control
- Yanking clean versions 0.3.5-0.3.9 forces dependency resolution to the malicious version

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots
> - Email addresses: `[at]` replacing @

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| arrayref | 0.3.10 | Legitimate crate poisoned with proc-macro1 dependency |
| internment | 0.8.7 | Legitimate crate poisoned with proc-macro1 dependency |
| append-only-vec | 0.1.9 | Legitimate crate poisoned with proc-macro1 dependency |
| proc-macro1 | 1.0.107 | Typosquat of proc-macro2; contains malicious build.rs |
| proc-macro1 | 1.0.106 | Benign seed version published before malicious version |
| proc-macro-en | 1.0.10 | Additional malicious typosquat crate |
| aovine | all | Attacker-owned malicious crate |
| arone | all | Attacker-owned malicious crate |
| aronenao | all | Attacker-owned malicious crate |
| tinymember | all | Attacker-owned malicious crate |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | build.rs | `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568` | Shared malicious build script |
| All | proc-macro1-1.0.107.crate | `61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4` | Malicious proc-macro1 package |
| All | proc-macro-en-1.0.10.crate | `8ed7d2d62d283a7701213e7a07191ebf5ab4d4862a0272b6ecda1209f6e0b93a` | Malicious proc-macro-en package |
| All | arrayref-0.3.10.crate | `25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae` | Poisoned arrayref package |
| Linux x86-64 | /tmp/rust-setup | `408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434` | Stage-2 implant binary |
| Windows x86-64 | %TEMP%\rust-setup.ps1 | `492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391` | Stage-2 PowerShell implant |
| macOS x86-64 | /tmp/rust-setup | `c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848` | Stage-2 implant binary |
| macOS ARM64 | /tmp/rust-setup | `74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306` | Stage-2 implant binary |

**Additional Windows hashes:**
- SHA1: `fc0fdb978eac72f4484b48db058e4473f1bc516e`
- MD5: `0ea14afc05408181cf65195a6eeede04`

**Additional SHA1 hashes:**
- proc-macro1-1.0.107: `f22e3e01e38bcdf001f0d15a2dbfdec5a1cf8eff`
- Linux stage-2: `f4767ad92cb61401fd69139cade563501c39b991`
- macOS ARM64 stage-2: `ff7e20cf642346bf893f1eca808df82035bb53d0`

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `23.254.165[.]112:9089` | Payload delivery server |
| IP | `23.254.165[.]112:443` | Primary C2 server |
| IP | `23.254.167[.]107:443` | Secondary C2 server (live) |
| IP | `23.254.167[.]216` | Victim-reported infrastructure |
| Domain | `hwsrv-798836[.]hostwindsdns[.]com` | Reverse DNS of primary C2 |
| URL Pattern | `hxxps://23.254.165[.]112:9089/rust-crate_0.{1-4}.0` | Platform-specific payload downloads |
| URL Pattern | `hxxps://23.254.165[.]112:443/49890878` | C2 beacon endpoint |
| DGA Domain | `rasGThauFD[.]com` | DGA fallback (Aug 20-24) |
| DGA Domain | `feVVKIiEiU[.]com` | DGA fallback (Aug 20-24) |
| DGA Domain | `phrpjTNckF[.]com` | DGA fallback (Aug 20-24) |
| DGA Domain | `PrOkXLgfjW[.]com` | DGA fallback (Aug 20-24) |
| DGA Domain | `ackeoTaWtl[.]com` | DGA fallback (Aug 20-24) |
| DGA Domain | `GAFWVCMAja[.]com` | DGA fallback (Aug 20-24) |
| DGA Domain | `RNSsddnEgK[.]com` | DGA fallback (Aug 20-24) |
| DGA Domain | `pfHlVOqEeg[.]com` | DGA fallback (Aug 20-24) |
| DGA Domain | `aBEcOrkups[.]com` | DGA fallback (Aug 20-24) |
| DGA Domain | `epOdIaTMaM[.]com` | DGA fallback (Aug 20-24) |
| CIDR | `23.254.164.0/23` | Hostwinds LLC range used across campaigns |

### Behavioral

- Build process (`cargo build`) spawning network connections to external IPs during compilation
- `wscript.exe` launching VBS files from `%TEMP%` directory that execute hidden PowerShell
- PowerShell processes with `-ep bypass -w h -File` arguments persisted via Registry Run key
- SQLite database queries against browser `Login Data` files for credential harvesting
- HTTPS POST beaconing to numeric URI path `/49890878` at regular intervals
- Detached process creation from `/tmp/rust-setup` on Unix systems

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Supply Chain | Compromised maintainer account used to publish malicious crate versions |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Typosquatting proc-macro2 as proc-macro1; impersonating dtolnay |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Hidden PowerShell with -ep bypass for payload execution on Windows |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | VBScript launcher (rust-setup-launch.vbs) to escape job object |
| T1105 | Ingress Tool Transfer | Build script downloads platform-specific stage-2 binaries over HTTPS |
| T1218.011 | Signed Binary Proxy Execution: Rundll32 / wscript | wscript.exe used to launch VBS payload launcher |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Windows persistence via HKCU Run key |
| T1547.011 | Boot or Logon Autostart Execution: Plist Modification | macOS persistence via LaunchAgent |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via systemd user service |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | SQLite queries against Chrome, Brave, Edge Login Data |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST beaconing to C2 |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | DGA fallback producing ten-character .com domains every 5 days |
| T1041 | Exfiltration Over C2 Channel | Base64-encoded JSON credential exfiltration over HTTPS |
| T1553.004 | Subvert Trust Controls: Install Root Certificate | Custom AcceptAll TLS verifier disables certificate validation |

## Impact Assessment

- **arrayref** had 245,385,500 lifetime downloads and 53,905,601 downloads in the 90 days ending August 20, reaching approximately 75% of cloud Rust environments
- 403 distinct crates depend directly on arrayref (transitive impact far larger)
- **internment** had 14,432,082 downloads; **append-only-vec** had 4,503,638 downloads
- Notable dependency chains: `winit` -> `sctk-adwaita` -> `tiny-skia` -> `arrayref`; `blake3`, `blake2b_simd`, `blake2s_simd`
- Exposure window was 86-107 minutes; the Rust Security Response Team reported no evidence of actual malicious crate usage during the window
- All affected developers, CI/CD systems, and build servers that pulled and compiled these versions during the window may have been compromised

## Detection & Remediation

### Immediate Detection

Check if compromised versions were pulled into any project:

```bash
# Check Cargo.lock for malicious versions
grep -rn 'arrayref.*0\.3\.10\|internment.*0\.8\.7\|append-only-vec.*0\.1\.9\|proc-macro1' Cargo.lock

# Check for payload artifacts on Unix
ls -la /tmp/rust-setup 2>/dev/null

# Check for payload artifacts on Windows (PowerShell)
Test-Path "$env:TEMP\rust-setup.ps1"
Test-Path "$env:TEMP\rust-setup-launch.vbs"

# Check Windows Registry for persistence
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul | findstr /i "powershell.*-ep bypass"

# Check for network connections to C2
netstat -an | grep -E "23\.254\.165\.112|23\.254\.167\.107"

# Check Cargo cache for malicious crates
find ~/.cargo/registry/cache -name "proc-macro1-*" -o -name "arrayref-0.3.10*" 2>/dev/null
```

### Remediation

1. **Immediate:** If `Cargo.lock` contains any malicious version, assume compromise. Isolate affected systems.
2. **Clean Cargo cache:** Remove `~/.cargo/registry/cache/*/proc-macro1-*` and related entries.
3. **Update dependencies:** Run `cargo update` to pull clean versions; arrayref 0.3.9 or earlier is safe (yanks have been reversed).
4. **Rotate credentials:** Rotate all browser-stored credentials for Chrome, Brave, Edge on affected systems.
5. **Rotate developer secrets:** API keys, SSH keys, tokens accessible from affected build environments.
6. **Remove persistence:** Check and clean Registry Run keys (Windows), LaunchAgents (macOS), systemd user services (Linux).
7. **Block IOCs:** Block `23.254.165[.]112`, `23.254.167[.]107`, and the DGA domains at the network perimeter.

### Long-Term Hardening

- Enable two-factor authentication on all crates.io accounts
- Pin dependency versions in `Cargo.lock` and review diffs on updates
- Audit `build.rs` scripts in dependencies before compilation
- Consider using `cargo-vet` or `cargo-crev` for supply chain trust verification
- Monitor `cargo build` processes for unexpected network connections
- Implement network egress controls on CI/CD build systems

## Detection Rules

These detections target the specific infrastructure, file artifacts, and persistence mechanisms from the compromised Rust crate supply chain attack. All Sigma rules convert cleanly to Splunk SPL and CrowdStrike LogScale; compiles = validated via `sigma convert` (the `sigma check` validator could not reach the MITRE ATT&CK data endpoint in this environment). YARA rules are compiled with `yarac` and sample-tested.

### Sigma: Network Connection to Known C2 Infrastructure

Detects outbound connections to the primary and secondary C2 IP addresses (`23.254.165[.]112` and `23.254.167[.]107`) used for payload delivery and beacon communication.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to proxy blocking MITRE ATT&CK data fetch (environmental, not rule defect). sigma convert splunk exit 0; sigma convert log_scale exit 0. IP-based IOC rule; high precision for the specific campaign but IPs may be reused by Hostwinds. -->

```yaml
title: Rust Crate Supply Chain Attack - Network Connection to Known C2 Infrastructure
id: 7a3e1f8d-4b2c-4e9a-b5d6-8c1f0a3e7b9d
status: experimental
description: >
    Detects outbound network connections to IP address 23.254.165.112 used as
    C2 and payload delivery infrastructure in the compromised Rust crates
    (arrayref, internment, append-only-vec) supply chain attack linked to
    North Korean threat actors (Sapphire Sleet).
references:
    - https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/
    - https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026-08-22
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: network_connection
detection:
    selection_primary_c2:
        DestinationIp: '23.254.165.112'
    selection_secondary_c2:
        DestinationIp: '23.254.167.107'
    condition: selection_primary_c2 or selection_secondary_c2
falsepositives:
    - Legitimate traffic to Hostwinds LLC infrastructure at this IP (unlikely for most environments)
level: high
```

### Sigma: Payload File Creation (rust-setup)

Detects creation of the `rust-setup` payload files dropped by the malicious build script on Unix (`/tmp/rust-setup`) and Windows (`%TEMP%\rust-setup.ps1`, `rust-setup-launch.vbs`, `rust-setup.ps1.cfg`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. File path-based IOC; highly distinctive filenames with no known legitimate use. -->

```yaml
title: Rust Crate Supply Chain Attack - Payload File Creation and Execution
id: 2d8f6a1c-9e4b-4d3a-b7c5-1f0e8a2d6c9b
status: experimental
description: >
    Detects creation or execution of the rust-setup payload files dropped by
    the compromised Rust crates (arrayref, internment, append-only-vec)
    build script during compilation. The malicious build.rs writes payloads
    to /tmp/rust-setup (Unix) or %TEMP%\rust-setup.ps1 (Windows).
references:
    - https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/
    - https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf
author: Actioner
date: 2026-08-22
tags:
    - attack.t1195.001
    - attack.t1059.001
logsource:
    category: file_event
detection:
    selection_unix:
        TargetFilename: '/tmp/rust-setup'
    selection_windows_ps1:
        TargetFilename|endswith: '\rust-setup.ps1'
    selection_windows_vbs:
        TargetFilename|endswith: '\rust-setup-launch.vbs'
    selection_windows_cfg:
        TargetFilename|endswith: '\rust-setup.ps1.cfg'
    condition: selection_unix or selection_windows_ps1 or selection_windows_vbs or selection_windows_cfg
falsepositives:
    - Custom Rust build scripts legitimately named rust-setup (very unlikely)
level: high
```

### Sigma: Windows Registry Persistence via PowerShell

Detects the implant's Windows persistence mechanism: a Registry Run key executing PowerShell with `-ep bypass -w h -File` arguments.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Matches the specific persistence command line pattern. The combination of all four fragments (-ep bypass, -w h, -File, powershell) in a Run key is distinctive enough for high confidence. -->

```yaml
title: Rust Crate Supply Chain Attack - Windows Registry Persistence via PowerShell
id: 5c9d2e7f-1a3b-4f8e-9d6c-0b4a8e3f7d1c
status: experimental
description: >
    Detects the Windows persistence mechanism used by the Rust crate supply
    chain attack implant, which sets a Registry Run key to execute a hidden
    PowerShell script with execution policy bypass.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/
    - https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf
author: Actioner
date: 2026-08-22
tags:
    - attack.t1547.001
    - attack.t1059.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Microsoft\Windows\CurrentVersion\Run'
        Details|contains|all:
            - 'powershell'
            - '-ep bypass'
            - '-w h'
            - '-File'
    condition: selection
falsepositives:
    - Legitimate software using hidden PowerShell with execution policy bypass in a Run key (uncommon but possible)
level: high
```

### Sigma: WScript VBS Launcher for PowerShell Payload

Detects `wscript.exe` executing `rust-setup-launch.vbs`, the technique used to escape Cargo's job object on Windows and launch the hidden PowerShell payload.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Process creation with exact artifact filename; zero expected FP. -->

```yaml
title: Rust Crate Supply Chain Attack - WScript VBS Launcher for PowerShell Payload
id: 8b4c1d6e-3f7a-4e2d-a9c8-5d0b7f1a2e3c
status: experimental
description: >
    Detects wscript.exe executing a VBS launcher script named rust-setup-launch.vbs,
    the technique used by the compromised Rust crate implant to escape Cargo's
    job object on Windows and launch the PowerShell payload hidden.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/
    - https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf
author: Actioner
date: 2026-08-22
tags:
    - attack.t1218.011
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
level: high
```

### Sigma: DNS Query to Known DGA Fallback Domains

Detects DNS queries to the ten known DGA-generated fallback domains used by the implant for C2 resilience (ten-character mixed-case `.com` domains for August 20-24, 2026).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Exact domain match against published DGA output; zero FP expected. Time-bound to the Aug 20-24 DGA window; future DGA output would require rule updates. -->

```yaml
title: Rust Crate Supply Chain Attack - DNS Query to Known DGA Fallback Domains
id: 1e5f8a9b-2c3d-4b7e-a6d1-9f0c8e4a3b2d
status: experimental
description: >
    Detects DNS queries to the known DGA-generated fallback domains used by
    the Rust crate supply chain attack implant for C2 resilience. These are
    ten-character mixed-case .com domains generated for the attack period.
references:
    - https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf
    - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
author: Actioner
date: 2026-08-22
tags:
    - attack.t1568.002
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName:
            - 'rasGThauFD.com'
            - 'feVVKIiEiU.com'
            - 'phrpjTNckF.com'
            - 'PrOkXLgfjW.com'
            - 'ackeoTaWtl.com'
            - 'GAFWVCMAja.com'
            - 'RNSsddnEgK.com'
            - 'pfHlVOqEeg.com'
            - 'aBEcOrkups.com'
            - 'epOdIaTMaM.com'
    condition: selection
falsepositives:
    - None expected; these are randomly generated domain names
level: high
```

### Sigma: DNS Query to Hostwinds C2 Domain

Detects DNS queries to the Hostwinds reverse DNS hostname associated with the primary C2 server.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Exact domain substring match; distinctive Hostwinds hostname. -->

```yaml
title: Rust Crate Supply Chain Attack - DNS Query to Hostwinds C2 Domain
id: 3f2a7c8d-6e1b-4d9a-c5f4-0a8b3e7d1c2f
status: experimental
description: >
    Detects DNS queries to hwsrv-798836.hostwindsdns.com, the Hostwinds
    reverse DNS hostname associated with the primary C2 server used in
    the compromised Rust crates supply chain attack.
references:
    - https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
    - https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf
author: Actioner
date: 2026-08-22
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|contains: 'hwsrv-798836.hostwindsdns.com'
    condition: selection
falsepositives:
    - Legitimate use of Hostwinds VPS with this specific hostname (unlikely)
level: high
```

### Snort: C2 Communication Rules

Detects TCP connections to the primary and secondary C2 IPs, and HTTP POST beaconing to the `/49890878` endpoint.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural validation only. Rules use standard Snort 3 syntax: tcp with IP/port destination, http service with method+URI sticky buffers. -->

```snort
alert tcp $HOME_NET any -> 23.254.165.112 [9089,443] (msg:"Actioner - Rust Crate Supply Chain Attack C2 Communication to 23.254.165.112"; flow:established,to_server; classtype:trojan-activity; reference:url,gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf; sid:2100101; rev:1;)

alert tcp $HOME_NET any -> 23.254.167.107 443 (msg:"Actioner - Rust Crate Supply Chain Attack Secondary C2 to 23.254.167.107"; flow:established,to_server; classtype:trojan-activity; reference:url,gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf; sid:2100102; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Rust Crate Supply Chain Attack C2 Beacon to /49890878"; flow:established,to_server; http_method; content:"POST"; http_uri; content:"/49890878"; fast_pattern; classtype:trojan-activity; reference:url,gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf; sid:2100103; rev:1;)
```

### Suricata: C2 Communication and DNS Rules

Detects TCP connections to C2 IPs, HTTP POST beaconing to `/49890878`, and DNS queries to the Hostwinds C2 domain. Uses Suricata dot-notation sticky buffers.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural validation only. Rules use dot-notation buffers (http.method, http.uri, dns.query), correct protocol keywords (http, dns, tcp), and all required fields (msg, sid, rev, metadata). -->

```suricata
alert tcp $HOME_NET any -> 23.254.165.112 [9089,443] (msg:"Actioner - Rust Crate Supply Chain Attack C2 to 23.254.165.112"; flow:established,to_server; classtype:trojan-activity; reference:url,gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf; metadata:author Actioner, created_at 2026-08-22; sid:2200101; rev:1;)

alert tcp $HOME_NET any -> 23.254.167.107 443 (msg:"Actioner - Rust Crate Supply Chain Attack Secondary C2 to 23.254.167.107"; flow:established,to_server; classtype:trojan-activity; reference:url,gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf; metadata:author Actioner, created_at 2026-08-22; sid:2200102; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Rust Crate Supply Chain Attack C2 Beacon POST /49890878"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/49890878"; fast_pattern; classtype:trojan-activity; reference:url,gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf; metadata:author Actioner, created_at 2026-08-22; sid:2200103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Rust Crate Supply Chain Attack DNS Query to Hostwinds C2 Domain"; flow:to_server; dns.query; content:"hwsrv-798836.hostwindsdns.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf; metadata:author Actioner, created_at 2026-08-22; sid:2200104; rev:1;)
```

### YARA: Malicious Build Script and Windows Implant

Detects the malicious `build.rs` build script artifacts and the Windows PowerShell implant via distinctive strings including the hardcoded AES key `i am botking`, C2 endpoint `/49890878`, payload filenames, and browser credential targeting.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: pos.txt with published strings (i am botking, /tmp/rust-setup, rust-crate_0.2.0, /49890878) matched SupplyChain_Rust_Arrayref_Malicious_BuildScript; neg.txt (benign build.rs) did not match. Rule 2 not sample-tested (requires real PS1 sample). -->

```yara
rule SupplyChain_Rust_Arrayref_Malicious_BuildScript
{
    meta:
        description = "Detects the malicious build.rs script or payload artifacts from the compromised Rust crates (arrayref, internment, append-only-vec) supply chain attack"
        author = "Actioner"
        date = "2026-08-22"
        reference = "https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf"
        hash = "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568"
        severity = "critical"

    strings:
        $key1 = "i am botking" ascii
        $key2 = "AcceptAll" ascii
        $payload_name1 = "rust-crate_0.1.0" ascii
        $payload_name2 = "rust-crate_0.2.0" ascii
        $payload_name3 = "rust-crate_0.3.0" ascii
        $payload_name4 = "rust-crate_0.4.0" ascii
        $path1 = "/tmp/rust-setup" ascii
        $path2 = "rust-setup.ps1" ascii
        $path3 = "rust-setup-launch.vbs" ascii
        $c2_endpoint = "/49890878" ascii
        $dep = "proc-macro1" ascii

    condition:
        3 of them
}

rule SupplyChain_Rust_Arrayref_Windows_Implant
{
    meta:
        description = "Detects the Windows PowerShell implant dropped by the compromised Rust crate supply chain attack based on known hashes and strings"
        author = "Actioner"
        date = "2026-08-22"
        reference = "https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf"
        hash = "492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391"
        severity = "critical"

    strings:
        $key = "i am botking" ascii wide
        $cmd_kill = "kill" ascii wide
        $cmd_minicfg = "minicfg" ascii wide
        $cmd_startup = "startup" ascii wide
        $cmd_runscript = "runscript" ascii wide
        $c2_path = "/49890878" ascii wide
        $browser_chrome = "Google\\Chrome\\User Data" ascii wide nocase
        $browser_brave = "BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
        $browser_edge = "Microsoft\\Edge\\User Data" ascii wide nocase
        $sqlite_tool = "sqlite-tools.zip" ascii wide

    condition:
        $key and $c2_path and (2 of ($cmd_*) or 2 of ($browser_*) or $sqlite_tool)
}
```

## Lessons Learned

1. **Build-time execution is a potent attack surface.** Rust's `build.rs` scripts execute arbitrary code during compilation with no sandboxing, making them a pre-runtime attack vector that fires in CI/CD pipelines before any application code runs. The ecosystem should consider sandboxing or restricting build script capabilities.

2. **Maintainer account security is a single point of failure.** The entire attack hinged on compromising one maintainer account. Mandatory multi-factor authentication and token scoping for publishing would have prevented this. The crates.io registry has since begun evaluating mandatory 2FA for accounts with high-download packages.

3. **Yanking as a social engineering vector.** The attacker's simultaneous yanking of versions 0.3.5-0.3.9 was a sophisticated social engineering technique that weaponized Cargo's warning messages to push developers toward the malicious version.

4. **DPRK supply chain operations are expanding across ecosystems.** The infrastructure overlap with prior npm attacks (Mastra, Axios) demonstrates that North Korean threat actors are systematically targeting developer supply chains across multiple package ecosystems (npm, PyPI, and now crates.io), reusing infrastructure but adapting techniques to each ecosystem's build system.

5. **Detection latency matters.** The 86-107 minute exposure window, combined with automated CI/CD pipelines, means that even brief compromises of popular packages can have wide impact. Real-time monitoring of package registry changes for high-download packages is essential.

## Sources

- [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/) -- primary reporting on the attack timeline, technical details, and impact assessment
- [The Hacker News](https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html) -- detailed technical analysis including exposure windows, crate download statistics, and dependency chain impact
- [SecurityWeek](https://www.securityweek.com/rust-supply-chain-attack-linked-to-north-korean-hackers/) -- attribution details and Wiz infrastructure overlap analysis with DPRK campaigns
- [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/north-korean-rust-supply-chain/) -- Sapphire Sleet attribution context and campaign infrastructure patterns
- [Nextron Systems GmbH Analysis (Marius Benthin)](https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf) -- primary IOC source: file hashes, C2 infrastructure, DGA domains, payload analysis, persistence mechanisms
- [Wiz Blog](https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns) -- DPRK infrastructure overlap analysis, secondary C2 IPs, DGA details, and Sapphire Sleet attribution
- [RustSec Advisory RUSTSEC-2026-0260](https://github.com/rustsec/advisory-db/issues/3161) -- official Rust security advisory

---
*Report generated by Actioner*
