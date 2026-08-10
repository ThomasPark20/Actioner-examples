# Technical Analysis Report: Jscrambler npm Supply Chain Attack (2026-07-12)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-12
Version: 1.0

## Executive Summary

On July 11, 2026, the official `jscrambler` npm package -- a JavaScript obfuscation CLI client with approximately 15,800 weekly downloads -- was compromised through a hijacked npm publishing credential. Over a three-hour window, an attacker published five malicious versions (8.14.0, 8.16.0, 8.17.0, 8.18.0, 8.20.0) that dropped a cross-platform Rust-compiled infostealer onto developer workstations and CI/CD runners. The payload targets cloud provider credentials (AWS/Azure/GCP), cryptocurrency wallet seed phrases (MetaMask, Phantom, Exodus), password managers (Bitwarden), browser-stored credentials, messaging platform sessions (Discord, Slack, Telegram, Steam), and -- notably -- AI developer tool configurations including API keys from Claude Desktop, Cursor, Windsurf, VS Code, and Zed. Socket detected the first malicious release within six minutes of publication.

The attack evolved in real time: early versions used npm preinstall lifecycle hooks, while later versions embedded the dropper directly into the module's require-time code path, bypassing `--ignore-scripts` protections. The infostealer employs ChaCha20-Poly1305 encrypted string obfuscation, per-platform persistence (Windows scheduled tasks, macOS LaunchAgents, Linux eBPF kernel modules), and TLS-encrypted exfiltration via the rustls library. This incident is especially significant given that npm 12 -- released three days earlier on July 8 -- disables install scripts by default, meaning the attacker's pivot to runtime injection (v8.18.0+) was likely a deliberate countermeasure.

## Background: Jscrambler

Jscrambler is a commercial JavaScript protection platform that provides code obfuscation, code integrity, and anti-tampering capabilities. The `jscrambler` npm package is the official CLI client used by developers and CI/CD pipelines to interact with the Jscrambler API for protecting JavaScript and web applications. The package integrates with webpack, gulp, Metro, and grunt via separate plugin packages. With approximately 15,800 weekly downloads and broad integration into enterprise JavaScript build pipelines, a compromise of this package has significant supply chain implications. Only the main `jscrambler` CLI package was affected; the webpack, gulp, Metro, and grunt integration plugins remained clean.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-08 | npm 12 released, disabling install scripts by default |
| 2026-07-11 15:12 | `jscrambler@8.14.0` published -- preinstall hook dropper via `dist/setup.js` |
| 2026-07-11 ~15:18 | Socket flags 8.14.0 as malicious (6 minutes after publication) |
| 2026-07-11 17:07 | `jscrambler@8.15.0` published -- clean (maintainer remediation attempt) |
| 2026-07-11 17:26 | `jscrambler@8.16.0` published -- preinstall hook reintroduced by attacker |
| 2026-07-11 17:41 | `jscrambler@8.17.0` published -- preinstall hook + pnpm `allowScripts` bypass |
| 2026-07-11 17:46 | `jscrambler@8.18.0` published -- runtime injection into `dist/index.js` and `dist/bin/jscrambler.js` (bypasses `--ignore-scripts`) |
| 2026-07-11 17:53 | `jscrambler@8.20.0` published -- identical runtime dropper re-publish |
| 2026-07-11 18:12 | `jscrambler@8.22.0` published -- clean (maintainer account recovered) |
| 2026-07-11 | Versions 8.14.0, 8.16.0, 8.17.0 deprecated on npm as compromised |

## Root Cause: Compromised npm Publishing Credential

The attacker gained access to a legitimate npm publishing credential associated with the `jscrambler_` npm account. The malicious versions appeared "nowhere in jscrambler's public source" -- no matching commits, tags, or pull requests exist in the GitHub repository (`jscrambler/jscrambler`), confirming a compromised npm account or build pipeline rather than a source code repository breach. The official Jscrambler advisory (GitHub issue `jscrambler/jscrambler#322`) attributes the incident to a compromised npm publishing credential.

## Technical Analysis of the Malicious Payload

### 1. Stage 1: Delivery and Dropper

**Generation 1 -- Preinstall Hook (versions 8.14.0, 8.16.0, 8.17.0):**

The `package.json` contained:
```json
"scripts": {
  "preinstall": "node dist/setup.js"
}
```

The `dist/setup.js` loader (SHA-256: `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`) performs these operations:

1. Reads `dist/intro.js` (7,837,238 bytes), a binary container disguised with a `.js` extension
2. Parses a custom "CSI" container format with magic bytes `1B 43 53 49 01`
3. Selects the OS-appropriate gzip-compressed native binary (Linux ELF x86-64, Windows PE32+, macOS arm64 Mach-O)
4. Decompresses the payload to a randomly-named hidden dotfile in the system temp directory (e.g., `/tmp/.a8f3e2c1b9` on Linux, `%TEMP%\.x7k9m2n4.exe` on Windows)
5. Marks the file executable (`chmod +x`) on Unix systems
6. Spawns the binary detached and unreferenced: `spawn(path, { detached: true, stdio: 'ignore', windowsHide: true })` followed by `unref()`

Version 8.17.0 additionally added pnpm `allowScripts` configuration to whitelist itself for execution under pnpm's stricter default policy.

**Generation 2 -- Runtime Injection (versions 8.18.0, 8.20.0):**

The dropper code was restructured as a self-executing IIFE injected at the top of both `dist/index.js` and `dist/bin/jscrambler.js`. This approach triggers on `require("jscrambler")` or CLI invocation, completely bypassing `npm install --ignore-scripts` and install-hook scanners. Versions 8.18.0 and 8.20.0 also added a self-referential dependency (`"jscrambler": "^8.17.0"`) to their own `package.json`, potentially enabling cross-version cascading installation attacks.

### 2. Stage 2: Binary Container Format

The `dist/intro.js` file (SHA-256: `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`) is a 7.8 MB custom binary container with:

- **5-byte magic header:** `1B 43 53 49 01` (custom "CSI" format)
- **Platform identifier byte** for OS selection
- **8-byte size fields** with compressed/uncompressed size metadata
- **Three gzip-compressed native binaries:** Linux ELF x86-64, Windows PE32+ x86-64, macOS Mach-O arm64

### 3. Stage 3: Rust Infostealer Payload

**Compiler fingerprint:** `rustc 1.98.0-nightly (e7815e522 2026-06-04)`
**Windows PDB GUID:** `6976bd1e56f6b4214c4c44205044422e`
**Linux Build ID:** `c05bf7dc45672d7a59cbd5e300f586482da14d00`

The payload is a comprehensive cross-platform Rust infostealer with the following capabilities:

**Credential and Secret Theft:**

| Target Category | Specific Targets |
|-----------------|-----------------|
| Cloud Credentials | AWS (ECS task-metadata, Secrets Manager, SSM Parameter Store with `WithDecryption: true`), Azure (IMDS endpoint, management API), GCP (metadata service tokens, `GOOGLE_APPLICATION_CREDENTIALS`, Secret Manager) |
| Cryptocurrency Wallets | MetaMask, Phantom, Trust Wallet, Coinbase Wallet, Exodus -- targets `mnemonic`, `seedPhrase`, `recoveryPhrase`, `seed` keys; includes Scrypt KDF parameters for vault decryption |
| Password Managers | Bitwarden browser extension (ID: `nngceckbapebfimnlniiiahkandclblb`) via LevelDB local storage extraction |
| Browsers | Chrome, Chromium, Brave, Edge, Vivaldi, Opera (Login Data, Cookies, Web Data via SQLite), Firefox (`profiles.ini`, `cookies.sqlite`, `key4.db`) |
| Messaging | Discord, Slack, Telegram Desktop (via ASAR archive parsing for Electron apps), Steam (`steamLoginSecure`, `sessionid`, `loginusers.vdf`) |
| AI/Developer Tools | Claude Desktop (`.config/Claude/claude_desktop_config.json`), Cursor (`.cursor/mcp.json`), Windsurf (`.codeium/windsurf/mcp_config.json`), VS Code (`settings.json`, `.mcp.json`), Zed API keys, Hashicorp Vault (`v1/secret/data/`) |
| System | KDE KWallet |

**String Obfuscation:**

All sensitive strings (~2,421 total) are encrypted with ChaCha20-Poly1305 (IETF variant, 12-byte nonce):
- Per-string 32-byte key stored in `.rodata` section
- 12-byte nonce materialized from immediates at call site
- Ciphertext with 16-byte Poly1305 authentication tag
- Empty AAD (Additional Authenticated Data)
- Linux binary decrypt helper at offset `0x1782f9`, ChaCha20 core at `0x425340`

**Encrypted Configuration:**

The Windows PE contains an 80KB encrypted blob in the `.rdata` section at offset `0x326400`, with each 4KB block exceeding 7.9 bits entropy. Decryption uses AES-NI, PBKDF2, or Scrypt key derivation.

### 4. C2 Infrastructure

**Known C2 IP addresses:**
- `37.27.122[.]124`
- `57.128.246[.]79`

**Tor infrastructure:**
- `check.torproject[.]org/api/ip` -- Tor connectivity check
- `archive.torproject[.]org` -- Tor binary download

**Communication protocol:**
- Exfiltration via multipart/form-data POST requests over TLS (rustls library)
- Bidirectional RAT protocol with JSON message structure:
  - `{"t":"out","id":"...","data":...,"progress":true}` (streaming output)
  - `{"t":"done","id":"..."}` (completion signal)
- HTTP templates include `Authorization: Bearer` headers
- Constructs API queries against cloud services using harvested credentials

### 5. Platform-Specific Behavior

#### Windows
- **Anti-debugging:** `IsDebuggerPresent` check
- **Network reconnaissance:** `GetExtendedTcpTable` from `iphlpapi.dll` for process enumeration and browser detection
- **Persistence:** Task Scheduler XML with `<Hidden>true</Hidden>`, restart interval `PT1M` (every minute), count 999, execution via `cmd.exe` with unlimited time limits
- **Payload hash:** `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`

#### macOS
- **Anti-debugging:** `sysctl` / `sysctlbyname` for debugger detection via `P_TRACED` flag
- **Persistence:** LaunchAgent plist in `~/Library/LaunchAgents/` with `RunAtLoad` and `KeepAlive` flags, 30-second `StartInterval` for automatic respawn
- **Payload hash:** `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd`

#### Linux
- **eBPF integration:** Dynamically links `libbpf.so.1`; imports `bpf_object__open_mem`, `bpf_object__load`, `bpf_program__attach`, `bpf_map__fd`; embeds eBPF bytecode in-memory without filesystem artifacts
- **Evasion:** Uses generic `syscall()` function rather than named wrappers to evade library-level monitoring
- **Environment detection:** Reads `/proc/self/mountinfo` and `/proc/self/cgroup` for container/VM awareness
- **Machine fingerprinting:** `/etc/machine-id`, `/var/lib/dbus/machine-id`, `/sys/class/dmi/id/board_serial`
- **Privilege escalation:** `sudo -S -p` (password via stdin), `systemd-run --system --no-ask-password`
- **Additional persistence:** Systemd user/system units, crontab
- **Payload hash:** `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`

### 6. Anti-Forensics / Evasion Techniques

- Randomly-named hidden dotfiles in temp directories to avoid casual discovery
- `windowsHide: true` and detached process spawning to avoid visible windows
- ChaCha20-Poly1305 encryption of all sensitive strings to defeat static analysis
- eBPF kernel-level persistence on Linux (no filesystem artifacts for the eBPF program)
- Container and VM detection via cgroup and mountinfo inspection
- Generic `syscall()` usage on Linux to bypass library-level monitoring
- Anti-debugging checks on all platforms
- Self-referential dependency to enable cascading re-infection

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `37.27.122[.]124`)
> - Domains: `[.]` replacing dots (e.g., `check.torproject[.]org`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| jscrambler | 8.14.0 | Preinstall hook dropper |
| jscrambler | 8.16.0 | Preinstall hook dropper (reintroduced after 8.15.0 remediation) |
| jscrambler | 8.17.0 | Preinstall hook + pnpm allowScripts bypass |
| jscrambler | 8.18.0 | Runtime injection dropper (bypasses --ignore-scripts) |
| jscrambler | 8.20.0 | Runtime injection dropper (re-publish) |

### File System

| Platform | Path / Artifact | Hash (SHA-256) | Description |
|----------|----------------|----------------|-------------|
| All | `dist/setup.js` | `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60` | Preinstall hook loader |
| All | `dist/intro.js` (7,837,238 bytes) | `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86` | Binary container with CSI magic `1B 43 53 49 01` |
| Linux | Dropped ELF x86-64 | `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd` | Rust infostealer (Build ID: `c05bf7dc45672d7a59cbd5e300f586482da14d00`) |
| Windows | Dropped PE32+ x86-64 | `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903` | Rust infostealer (PDB GUID: `6976bd1e56f6b4214c4c44205044422e`) |
| Windows | Embedded hash | `9eeffcb5c3445ef9512f7776045f99ea23f9ebed989f8570bc4634b4e340de5d` | Additional PE artifact |
| macOS | Dropped Mach-O arm64 | `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd` | Rust infostealer |
| Windows | `%TEMP%\.<random>.exe` | -- | Dropped payload (hidden dotfile) |
| Linux | `/tmp/.<random>` | -- | Dropped payload (hidden dotfile) |
| macOS | `/var/folders/.../<random>/.<random>` | -- | Dropped payload (hidden dotfile) |
| macOS | `~/Library/LaunchAgents/<unknown>.plist` | -- | Persistence LaunchAgent |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `37.27.122[.]124` | C2 / exfiltration server |
| IP | `57.128.246[.]79` | C2 / exfiltration server |
| Domain | `check.torproject[.]org` | Tor connectivity check (`/api/ip` endpoint) |
| Domain | `archive.torproject[.]org` | Tor binary download |

### Behavioral

- Node.js (`node`) spawning hidden executables from system temp directories during `npm install`
- 7.8 MB `dist/intro.js` file with binary magic header `1B 43 53 49 01` in `node_modules/jscrambler/`
- Hidden Windows scheduled tasks with one-minute restart intervals
- Unfamiliar LaunchAgent plists in `~/Library/LaunchAgents/` with `KeepAlive` and 30-second intervals
- Processes loading `libbpf.so.1` and calling eBPF attachment functions
- Multipart/form-data POST exfiltration over TLS to known C2 IPs

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Hijacked npm publishing credential to publish trojanized jscrambler package versions |
| T1059.007 | Command and Scripting Interpreter: JavaScript | npm preinstall hook executes `dist/setup.js` to extract and launch binary payload |
| T1204.002 | User Execution: Malicious File | Runtime injection variant (8.18.0+) triggers on `require("jscrambler")` |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | ChaCha20-Poly1305 encryption of ~2,421 strings; AES-encrypted config blob |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows persistence via hidden scheduled task (PT1M interval, count 999) |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS persistence via LaunchAgent with RunAtLoad and KeepAlive |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Linux: `sudo -S -p` and `systemd-run --system --no-ask-password` |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | SQLite/LevelDB access to Chrome, Brave, Edge, Firefox credential stores |
| T1555 | Credentials from Password Stores | Bitwarden vault extraction via browser extension LevelDB |
| T1539 | Steal Web Session Cookie | Browser cookie theft, Discord/Slack/Telegram/Steam session token theft |
| T1552.001 | Unsecured Credentials: Credentials In Files | Cloud credential files, AI tool config files with API keys |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | AWS ECS metadata, Azure IMDS, GCP metadata service token harvesting |
| T1041 | Exfiltration Over C2 Channel | TLS-encrypted multipart/form-data POST to C2 servers |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/TLS-based C2 with JSON message protocol |
| T1082 | System Information Discovery | Machine ID, board serial, cgroup, and mountinfo fingerprinting |
| T1622 | Debugger Evasion | IsDebuggerPresent (Windows), P_TRACED sysctl (macOS) |
| T1014 | Rootkit | Linux eBPF kernel module persistence and evasion |

## Impact Assessment

**Breadth:** The `jscrambler` package receives ~15,800 weekly downloads. npm reports zero downloads of the malicious versions, though the count lags by hours and was still being verified at time of publication. The package is primarily used in enterprise JavaScript build pipelines, meaning affected installations could expose cloud provider credentials, CI/CD secrets, and developer workstation data at scale.

**Depth:** Critical. The infostealer targets the full spectrum of developer and enterprise secrets: cloud provider credentials enabling infrastructure access, cryptocurrency wallet seed phrases enabling irreversible fund theft, password manager vaults, messaging platform sessions, and AI tool API keys. The bidirectional RAT protocol and eBPF kernel persistence on Linux suggest capabilities beyond simple credential theft.

**Stealth:** High. ChaCha20-Poly1305 string encryption defeats static analysis, eBPF kernel persistence leaves no filesystem artifacts on Linux, and the Generation 2 delivery mechanism (runtime injection) bypasses the primary defensive control (`--ignore-scripts`).

**Exposure Window:** Approximately 3 hours (15:12 to 18:12 UTC on July 11, 2026). Socket detection occurred within 6 minutes, but notification propagation and user action would have lagged.

## Detection & Remediation

### Immediate Detection

Check if any compromised version was installed:

```bash
# Check lockfiles for compromised versions
grep -rE '"jscrambler".*"(8\.14\.0|8\.16\.0|8\.17\.0|8\.18\.0|8\.20\.0)"' \
  package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Check npm cache
npm cache ls jscrambler 2>/dev/null | grep -E '8\.(14|16|17|18|20)\.0'

# Check for dropped payloads (Linux/macOS)
find /tmp /var/folders -name '.*' -type f -executable -newer /tmp -mtime -7 2>/dev/null
ls -la /tmp/.* 2>/dev/null | grep -v '^\.\.\?$'

# Check for dropped payloads (Windows PowerShell)
# Get-ChildItem -Path $env:TEMP -Filter ".*" -Hidden -Force | Where-Object { $_.Extension -eq ".exe" }

# Check for suspicious LaunchAgents (macOS)
ls -la ~/Library/LaunchAgents/ | grep -v com.apple

# Check for suspicious scheduled tasks (Windows PowerShell)
# Get-ScheduledTask | Where-Object { $_.Settings.Hidden -eq $true -and $_.Triggers.Repetition.Interval -eq "PT1M" }

# Hash check against known payload hashes
sha256sum /tmp/.* 2>/dev/null
```

### Remediation

1. **Upgrade immediately:** Pin to `jscrambler@8.22.0` (confirmed clean) or revert to `jscrambler@8.13.0` (pre-compromise)
2. **Treat affected hosts as fully compromised:** If any malicious version was installed, assume all accessible credentials were exfiltrated
3. **Rotate all credentials:**
   - AWS/Azure/GCP access keys, service account credentials, and secrets
   - npm tokens, GitHub tokens, and CI/CD pipeline secrets
   - AI tool API keys (Claude, Cursor, Windsurf, VS Code extensions, Zed)
   - Discord, Slack, and Telegram session tokens
   - Browser-stored passwords (all sites)
   - Bitwarden master password and vault
4. **Move cryptocurrency assets:** Transfer funds from any wallets accessible from affected machines to new wallets generated on verified-clean devices
5. **Block C2 infrastructure:** Add `37.27.122[.]124` and `57.128.246[.]79` to firewall/proxy blocklists
6. **Hunt for persistence artifacts:**
   - Windows: Remove hidden scheduled tasks
   - macOS: Remove suspicious LaunchAgent plists from `~/Library/LaunchAgents/`
   - Linux: Check for unknown eBPF programs (`bpftool prog list`), suspicious systemd units, crontab entries
7. **Audit CI/CD runners:** Any runner that installed a compromised version should be rebuilt from a clean image

### Long-Term Hardening

- **Enable npm lockfile verification:** Use `npm ci` instead of `npm install` in CI/CD pipelines
- **Pin exact versions:** Avoid semver ranges for critical dependencies
- **Use `--ignore-scripts`:** Set `ignore-scripts=true` globally (note: this does NOT protect against v8.18.0+ runtime injection)
- **Adopt npm 12:** Upgrade to npm 12+ which disables install scripts by default
- **Deploy software composition analysis:** Use Socket, Snyk, or equivalent tools for real-time package monitoring
- **Implement least-privilege CI/CD:** Limit secrets available to build processes; use short-lived credentials
- **Monitor for supply chain indicators:** Alert on unexpected package version changes and large binary files in npm packages

## Detection Rules

These rules cover the jscrambler supply chain attack across four detection surfaces: host-level process/file telemetry (Sigma), file-based payload identification (YARA), and network-level C2 communication (Snort, Suricata).

**Encryption caveat:** The Rust infostealer encrypts all ~2,421 sensitive strings with ChaCha20-Poly1305. YARA rules targeting the Linux and Windows binaries (rules 3-4 below) rely partly on strings that may be encrypted in at-rest binaries; those rules may require memory-scanning deployment for reliable detection. The eBPF dynamic-linker imports (Linux) and Windows API imports survive encryption, anchoring the rules, but runtime string matches are not guaranteed on disk.

**Dropped rules:** Seven candidate rules were evaluated and excluded from this report during review: a Windows scheduled-task Sigma rule (the task is likely created via COM API or Task Scheduler XML import rather than `schtasks /SC MINUTE` CLI flags, making process_creation detection unreliable); a generic browser-credential-access Sigma rule (purely behavioral with no jscrambler-specific markers, high FP rate from password managers, backup tools, and forensic utilities); a generic cross-platform YARA rule (all matched strings are ChaCha20-encrypted at rest, yielding near-zero match probability); a Snort multipart-exfiltration rule (exfiltration uses TLS, so cleartext content matches never fire); and three Suricata rules for Tor-related TLS SNI/DNS (not jscrambler-specific, massive false-positive rate from legitimate Tor users).

The primary caveat for the surviving rules is that the C2 IP-based rules have a limited shelf life as infrastructure rotates; the behavioral Sigma rules and YARA file signatures provide more durable detection. All YARA and Suricata rules compiled successfully; Sigma rules validated via backend conversion to Splunk and LogScale.

### Sigma Rules

#### 1. Suspicious NPM Preinstall Hook Executing Hidden Binary From Temp Directory

Detects Node.js spawning a hidden executable from a temp directory -- the core dropper behavior.

**Compile:** validated via `sigma convert` to Splunk + LogScale | **Confidence:** high

```yaml
title: Suspicious NPM Preinstall Hook Executing Hidden Binary From Temp Directory
id: 7a2c8f41-3e9d-4b6a-a1c5-d0f8e2b94a37
status: experimental
description: >
    Detects Node.js spawning a hidden executable from a system temp directory,
    consistent with the jscrambler npm supply chain attack where dist/setup.js
    drops and executes a Rust infostealer as a randomly-named dotfile.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
    - https://socket.dev/blog/jscrambler-supply-chain-attack
author: Actioner
date: 2026-07-12
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\node.exe'
            - '/node'
            - '/bin/node'
    selection_child_linux:
        Image|re: '^/tmp/\.[a-z0-9]{6,}$'
    selection_child_windows:
        Image|re: '(?i)\\(Temp|tmp)\\\.[a-z0-9]{6,}\.exe$'
    selection_child_macos:
        Image|re: '^/var/folders/.*/\.[a-z0-9]{6,}$'
    condition: selection_parent and (selection_child_linux or selection_child_windows or selection_child_macos)
falsepositives:
    - Legitimate npm packages that extract and execute native binaries from temp directories during install
level: high
```

<!-- audit: Validated via sigma convert --without-pipeline -t splunk and -t log_scale. sigma check fails due to unreachable MITRE ATT&CK API (environment issue, not rule issue). Regex patterns match the documented dropper behavior of writing hidden dotfiles to temp directories. No defanged values in detection fields. Field names (ParentImage, Image) are standard process_creation schema. -->

#### 2. Suspicious LaunchAgent Creation From Node Process

Detects Node.js writing a LaunchAgent plist -- the macOS persistence mechanism.

**Compile:** validated via `sigma convert` to Splunk + LogScale | **Confidence:** medium

```yaml
title: Suspicious LaunchAgent Creation From Node Process
id: 8b4e6a13-7c2d-49f5-a3d8-1e0f5c9b27a4
status: experimental
description: >
    Detects a Node.js process creating a LaunchAgent plist file in the user
    LaunchAgents directory, consistent with the macOS persistence mechanism
    used by the jscrambler npm supply chain infostealer.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
    - https://socket.dev/blog/jscrambler-supply-chain-attack
author: Actioner
date: 2026-07-12
tags:
    - attack.t1543.001
logsource:
    category: file_event
    product: macos
detection:
    selection:
        Image|endswith:
            - '/node'
            - '/bin/node'
        TargetFilename|contains: '/Library/LaunchAgents/'
        TargetFilename|endswith: '.plist'
    condition: selection
falsepositives:
    - Legitimate Node.js applications that install macOS LaunchAgents
    - Electron-based applications such as VS Code update helpers and nw.js apps
level: medium
```

<!-- audit: Validated via sigma convert --without-pipeline -t splunk and -t log_scale. Downgraded from high to medium confidence due to Electron-based false positives. Targets file_event category with macOS product. Uses Image and TargetFilename fields consistent with Sysmon-for-macOS and Endpoint Security Framework telemetry. -->

#### 3. Network Connection to Jscrambler Infostealer C2 Infrastructure

Detects outbound connections to known C2 IPs.

**Compile:** validated via `sigma convert` to Splunk + LogScale | **Confidence:** high (IP-specific, short shelf life)

```yaml
title: Network Connection to Jscrambler Infostealer C2 Infrastructure
id: 3c7f2d95-6a1e-4b8c-9d0f-e5a4b3c81f26
status: experimental
description: >
    Detects outbound network connections to known C2 IP addresses used by the
    jscrambler npm supply chain infostealer for credential exfiltration.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
    - https://socket.dev/blog/jscrambler-supply-chain-attack
author: Actioner
date: 2026-07-12
tags:
    - attack.t1041
logsource:
    category: network_connection
detection:
    selection:
        Initiated: 'true'
        DestinationIp:
            - '37.27.122.124'
            - '57.128.246.79'
    condition: selection
falsepositives:
    - Legitimate services hosted on these IP addresses
level: critical
```

<!-- audit: Validated via sigma convert. IOC values are real (not defanged) per logsource-encoding guidance. DestinationIp field is standard Sysmon EID 3 / network_connection schema. Limited shelf life as C2 infrastructure rotates. -->

### YARA Rules

**Important:** The Rust infostealer uses ChaCha20-Poly1305 to encrypt all ~2,421 runtime strings. Rules 3 and 4 below anchor on OS-level API imports and dynamic-linker symbols that survive encryption, but some matched strings (`$mid*`, `$rustls`, `$tor` in rule 3; `$cred*`, `$wallet`, `$steam`, `$sched1` in rule 4) are runtime strings that may be encrypted in at-rest binaries. These rules compiled successfully via `yarac` but have not been validated against known samples; memory-scanning deployment is recommended for reliable detection of the platform-specific payloads.

#### 1. Jscrambler Binary Container (dist/intro.js)

Detects the custom CSI binary container by its magic header and size characteristics.

**Compile:** yarac validated | **Confidence:** high

#### 2. Jscrambler Setup.js Dropper

Detects the dropper script via characteristic string combination.

**Compile:** yarac validated | **Confidence:** high

#### 3. Jscrambler Rust Infostealer -- Linux ELF

Detects the Linux payload via eBPF imports, machine fingerprinting, and rustls strings.

**Compile:** yarac validated | **Confidence:** medium (some target strings may be encrypted at rest; recommended for memory scanning)

#### 4. Jscrambler Rust Infostealer -- Windows PE

Detects the Windows payload via anti-debug APIs, credential theft, and scheduler strings.

**Compile:** yarac validated | **Confidence:** medium (some target strings may be encrypted at rest; recommended for memory scanning)

```yara
rule SupplyChain_Jscrambler_IntroJS_Container
{
    meta:
        description = "Detects the jscrambler malicious binary container file (dist/intro.js) by its custom CSI magic header and large file size"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86"
        severity = "critical"

    strings:
        $magic = { 1B 43 53 49 01 }

    condition:
        $magic at 0 and filesize > 5MB and filesize < 10MB
}

rule SupplyChain_Jscrambler_SetupJS_Dropper
{
    meta:
        description = "Detects the jscrambler malicious setup.js dropper script that extracts and executes platform-specific binaries from the intro.js container"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60"
        severity = "critical"

    strings:
        $s1 = "dist/intro.js" ascii
        $s2 = "detached" ascii
        $s3 = "windowsHide" ascii
        $s4 = "unref" ascii
        $s5 = ".exe" ascii
        $s6 = "spawn" ascii
        $s7 = "gunzip" ascii wide nocase
        $s8 = "tmpdir" ascii

    condition:
        filesize < 100KB and 6 of ($s*)
}

rule Malware_Jscrambler_Rust_Infostealer_Linux
{
    meta:
        description = "Detects the Linux ELF payload of the jscrambler Rust infostealer via eBPF dynamic imports and machine fingerprinting paths. Note: $mid* and $rustls/$tor strings may be ChaCha20-Poly1305 encrypted in at-rest binaries; consider memory-scanning deployment for reliable detection."
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd"
        severity = "high"

    strings:
        $elf = { 7F 45 4C 46 }
        $bpf1 = "bpf_object__open_mem" ascii fullword
        $bpf2 = "bpf_object__load" ascii fullword
        $bpf3 = "bpf_program__attach" ascii fullword
        $bpf4 = "bpf_map__fd" ascii fullword
        $libbpf = "libbpf.so.1" ascii
        $mid1 = "/etc/machine-id" ascii
        $mid2 = "/var/lib/dbus/machine-id" ascii
        $mid3 = "/sys/class/dmi/id/board_serial" ascii
        $rustls = "rustls" ascii
        $tor = "check.torproject.org" ascii

    condition:
        $elf at 0 and
        filesize < 20MB and
        (3 of ($bpf*) or $libbpf) and
        1 of ($mid*) and
        ($rustls or $tor)
}

rule Malware_Jscrambler_Rust_Infostealer_Windows
{
    meta:
        description = "Detects the Windows PE payload of the jscrambler Rust infostealer via anti-debug APIs and credential-theft indicators. Note: $cred*, $wallet, $steam, and $sched1 are runtime strings likely encrypted by ChaCha20-Poly1305 in at-rest binaries; consider memory-scanning deployment for reliable detection."
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903"
        severity = "high"

    strings:
        $mz = { 4D 5A }
        $api1 = "IsDebuggerPresent" ascii fullword
        $api2 = "GetExtendedTcpTable" ascii fullword
        $rust = "rustls" ascii
        $sched1 = "schtasks" ascii nocase
        $cred1 = "Login Data" ascii
        $cred2 = "Cookies" ascii
        $wallet = "nngceckbapebfimnlniiiahkandclblb" ascii
        $steam = "steamLoginSecure" ascii

    condition:
        $mz at 0 and
        filesize < 20MB and
        $api1 and $api2 and
        $rust and
        2 of ($cred*, $wallet, $steam, $sched1)
}
```

<!-- audit: All 4 YARA rules compiled successfully via yarac (exit code 0). Rules have NOT been validated against known samples (no sample access in this environment). Rules use real domain/string values per logsource-encoding guidance. CSI container rule uses magic-at-0 anchor for precision. Linux rule anchors on eBPF dynamic-linker imports (survive encryption) plus machine fingerprinting paths and rustls/tor strings (may be encrypted). Windows rule anchors on Windows API imports (survive encryption) plus credential-theft strings (may be encrypted). Rules 3-4 downgraded to medium confidence and severity high due to ChaCha20-Poly1305 string encryption; memory-scanning deployment recommended. -->

### Snort Rules

#### 1. Jscrambler C2 Communication to 37.27.122[.]124

IP-based C2 detection for the first known exfiltration server.

**Compile:** uncompiled (structural check only) | **Confidence:** high (IP-specific, short shelf life)

#### 2. Jscrambler C2 Communication to 57.128.246[.]79

IP-based C2 detection for the second known exfiltration server.

**Compile:** uncompiled (structural check only) | **Confidence:** high (IP-specific, short shelf life)

```
alert ip $HOME_NET any -> 37.27.122.124 any (msg:"Actioner - Jscrambler Infostealer C2 Communication to 37.27.122[.]124"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; metadata:author Actioner, created 2026-07-12; sid:2100101; rev:1;)

alert ip $HOME_NET any -> 57.128.246.79 any (msg:"Actioner - Jscrambler Infostealer C2 Communication to 57.128.246[.]79"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; metadata:author Actioner, created 2026-07-12; sid:2100102; rev:1;)
```

<!-- audit: Structural check only -- snort binary not installed in this environment. Rules use ip protocol for IP-based C2 detection (no app-layer buffers needed). All rules have msg, sid, rev, classtype, flow with correct syntax (no space after comma in flow keyword). SID range 2100101-2100102 avoids conflicts. Dropped rule 2100103 (multipart exfil via TLS) -- content matches cannot fire inside TLS-encrypted traffic. -->

### Suricata Rules

#### 1. Jscrambler C2 to 37.27.122[.]124

IP-based C2 detection.

**Compile:** suricata -T validated | **Confidence:** high (IP-specific, short shelf life)

#### 2. Jscrambler C2 to 57.128.246[.]79

IP-based C2 detection.

**Compile:** suricata -T validated | **Confidence:** high (IP-specific, short shelf life)

```
alert ip $HOME_NET any -> 37.27.122.124 any (msg:"Actioner - Jscrambler Infostealer C2 to 37.27.122[.]124"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; metadata:author Actioner, created_at 2026-07-12; sid:2100201; rev:1;)

alert ip $HOME_NET any -> 57.128.246.79 any (msg:"Actioner - Jscrambler Infostealer C2 to 57.128.246[.]79"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; metadata:author Actioner, created_at 2026-07-12; sid:2100202; rev:1;)
```

<!-- audit: Both Suricata rules validated via suricata -T -S (exit code 0, "Configuration provided was successfully loaded"). Rules use ip protocol for raw IP matching. SID range 2100201-2100202. Dropped rules 2100203-2100205 (TLS SNI to check/archive.torproject.org and DNS query for check.torproject.org) -- not jscrambler-specific, massive false-positive rate from legitimate Tor users. -->

## Lessons Learned

1. **Install script protections are necessary but insufficient.** The attacker's rapid pivot from preinstall hooks (v8.14.0-8.17.0) to runtime injection (v8.18.0+) within a single three-hour window demonstrates that `--ignore-scripts` and npm 12's default script disabling are single-layer defenses that sophisticated attackers will route around. Defense-in-depth must include runtime behavioral monitoring, not just install-time controls.

2. **npm credential security is a systemic risk.** A single compromised publishing credential enabled full supply chain compromise without any trace in the source repository. The npm ecosystem lacks mandatory multi-factor authentication for publishing, and there is no universal mechanism to verify that a published package matches its public source code. Organizations should treat npm credentials as Tier 1 secrets, require hardware security keys for publishing, and implement provenance verification (npm's `--provenance` flag or Sigstore-based attestations).

3. **AI developer tools are now high-value targets.** The explicit targeting of Claude Desktop, Cursor, Windsurf, VS Code, and Zed configurations for API keys and MCP server credentials represents a new category of supply chain exfiltration target. AI tool API keys often provide access to powerful capabilities and may lack the same rotation and monitoring practices applied to cloud credentials. Development teams should treat AI tool configurations with the same security rigor as cloud provider credentials.

4. **eBPF as a persistence mechanism raises the bar for detection.** The Linux payload's use of in-memory eBPF programs for kernel-level persistence without filesystem artifacts represents a significant escalation in infostealer sophistication. Traditional file-based detection (including YARA scanning) will not identify active eBPF persistence. Defenders need `bpftool prog list` in their incident response playbooks and continuous monitoring of eBPF program loading events.

## Sources

- [The Hacker News - Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install](https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html) -- primary source with attack overview, IOCs, and timeline
- [Socket - jscrambler npm Package Compromised in Supply Chain Attack](https://socket.dev/blog/jscrambler-supply-chain-attack) -- detailed technical analysis including ChaCha20 string encryption, eBPF details, RAT protocol, and binary reverse engineering
- [SafeDep - Official jscrambler npm Package Compromised Across Multiple Releases](https://safedep.io/jscrambler-npm-supply-chain-compromise/) -- additional IOCs, build fingerprints, compiler metadata, container format analysis, and encrypted configuration blob details
- [StepSecurity - jscrambler npm package publishes malicious preinstall binary](https://www.stepsecurity.io/blog/jscrambler-npm-package-publishes-malicious-preinstall-binary) -- BIP39 wordlist and anti-analysis technique details

---
*Report generated by Actioner*
