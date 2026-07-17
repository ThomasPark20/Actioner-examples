# Technical Analysis Report: Jscrambler 8.14.0 npm Supply Chain Compromise -- IronWorm Rust Infostealer (2026-07-17)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-17
Version: 2.0 (FINAL)
<!-- revision: v2.0 — applied critic verdicts: fixed Hidden Binary Sigma (relabeled behavioral/low, removed |re:, fixed ATT&CK tag), fixed CSI Container YARA (removed cross-file JS strings, added binary structural markers), fixed IronWorm YARA (removed dishonest sample label, added encryption caveat, downgraded to medium, added PE/ELF structural markers), downgraded temp.sh Snort/Suricata rules to medium confidence, defanged behavioral IOCs. -->

## Executive Summary

On July 11, 2026, five malicious versions of the official `jscrambler` npm package (8.14.0, 8.16.0, 8.17.0, 8.18.0, 8.20.0) were published within a three-hour window using compromised npm publishing credentials. The compromised versions embed a cross-platform Rust infostealer identified by JFrog as **IronWorm** (tied to the Shai-Hulud malware lineage previously documented in the Arweave/WeaveDB supply chain attack -- see `summaries/2026-06-05-npm-ironworm-supply-chain.md`) inside a custom 7.8 MB binary container with a `\x1bCSI\x01` magic header. The payload is delivered via a `preinstall` hook (versions 8.14.0--8.17.0) or injected as a self-executing function in main package files (versions 8.18.0--8.20.0 to bypass `--ignore-scripts`).

The IronWorm infostealer uses ChaCha20-Poly1305 per-string encryption (~2,421 encrypted strings), communicates over Tor via SOCKS5 proxy to C2 servers at `37.27.122[.]124` and `57.128.246[.]79`, and exfiltrates bulk stolen data to the public file host `temp[.]sh` via multipart HTTPS POST. It targets cloud credentials (AWS, Azure, GCP), cryptocurrency wallets (MetaMask, Phantom, Exodus, Trust Wallet, Coinbase), AI coding tools (Claude Desktop, Cursor, Windsurf, Zed, VS Code), browser data, messaging platforms (Discord, Slack, Telegram), VPN configs, password managers (Bitwarden, 1Password), and offensive security frameworks (Metasploit, Sliver, Havoc). The binary includes eBPF rootkit capabilities on Linux and an npm worm propagation routine that steals npm tokens and publishes trojanized versions of other packages via raw HTTP PUT to the npm registry.

Socket detected the compromise within 6 minutes of publication. The `jscrambler` package has approximately 15,800 weekly downloads; an estimated 1,479 downloads occurred during the ~2-hour active window before deprecation. Four dependent packages (`jscrambler-webpack-plugin` 8.6.2, `gulp-jscrambler` 8.6.2, `grunt-jscrambler` 8.5.2, `jscrambler-metro-plugin` 9.0.2) were also affected. Version 8.22.0 is the verified clean replacement.

Severity: **Critical** (active cross-platform infostealer with self-propagation capability deployed via a legitimate, widely-used package).

## Background: Jscrambler npm Package

Jscrambler is a commercial JavaScript protection and obfuscation platform. The `jscrambler` npm package is the official CLI and SDK for integrating Jscrambler's code protection into build pipelines. It is used by enterprise development teams to apply code obfuscation, anti-tampering, and anti-debugging protections. Compromise of this package is particularly ironic -- a security vendor's own tooling became the attack vector -- and high-impact because it executes in CI/CD environments where ambient cloud credentials, registry tokens, and secrets are readily available.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-08 | npm 12 released with install scripts disabled by default |
| 2026-07-11 ~T1 | Malicious jscrambler 8.14.0 published via compromised npm credentials |
| 2026-07-11 ~T1+6min | Socket flags the package within 6 minutes of publication |
| 2026-07-11 ~T1+19min | Clean 8.15.0 published (legitimate release squeezed in) |
| 2026-07-11 ~T1+19min+ | 8.16.0 published (malicious, preinstall hook, re-published after 8.15.0) |
| 2026-07-11 ~T1+~2h | 8.17.0 published (malicious, preinstall hook + pnpm allowScripts whitelist) |
| 2026-07-11 ~T1+~2.5h | 8.18.0 published (malicious, switched to runtime injection in dist/index.js) |
| 2026-07-11 ~T1+~3h | 8.20.0 published (malicious, runtime injection, final attempt) |
| 2026-07-11 ~T1+~3h | All malicious versions deprecated/removed from npm |
| 2026-07-11 (post) | Jscrambler confirms compromised npm credential, revokes tokens |
| 2026-07-11 (post) | 8.22.0 published as verified clean replacement |

## Root Cause: Compromised npm Publishing Credentials

The attacker gained access to a legitimate Jscrambler npm publishing credential. The exact method of credential compromise has not been disclosed. The attacker used this credential to publish malicious versions directly to npm, bypassing the project's normal CI/CD release pipeline. Jscrambler has confirmed credential compromise and implemented additional security controls for the publishing pipeline.

## Technical Analysis of the Malicious Payload

### 1. Initial Delivery: Preinstall Hook (Versions 8.14.0--8.17.0)

The `package.json` includes a `preinstall` script:

```json
"preinstall": "node dist/setup.js"
```

Version 8.17.0 additionally adds a pnpm `allowScripts` whitelist entry:

```json
"allowScripts": ["jscrambler"]
```

The `dist/setup.js` (SHA256: `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`) reads a custom binary container from `dist/intro.js`, selects the OS-appropriate payload based on `process.platform`, decompresses it via gzip, writes it to a randomly-named hidden file in the system temp directory (`.{random}` on Linux/macOS, `.{random}.exe` on Windows), marks it executable, and launches it detached with `spawn(..., { detached: true, stdio: 'ignore', windowsHide: true })` followed by `unref()` to orphan from the npm install process tree.

### 2. Evolved Delivery: Runtime Injection (Versions 8.18.0--8.20.0)

After defenders began flagging preinstall hooks, the attacker pivoted. Versions 8.18.0 and 8.20.0 remove the preinstall hook and instead inject a self-executing function (IIFE) at the top of `dist/index.js` and `dist/bin/jscrambler.js`. This executes when the package is `require()`d or the CLI is invoked, bypassing `npm install --ignore-scripts` and security tools that only scan install scripts. These versions also add a self-referential dependency (`"jscrambler": "^8.17.0"`) to pull a compromised release transitively.

### 3. Binary Container Format (CSI)

The `dist/intro.js` file (SHA256: `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`, size: 7,837,238 bytes) is a custom binary container disguised as JavaScript. Its format:

- **Header:** 5-byte magic `\x1bCSI\x01` followed by platform count byte
- **Per-entry:** 1 byte platform ID (0=Linux, 1=Windows, 2=macOS) + 8 bytes LE decompressed size + 8 bytes LE compressed size + gzip data
- **Contents:** Three gzip-compressed platform-specific executables

### 4. IronWorm Rust Infostealer

The payload is compiled with `rustc 1.98.0-nightly (e7815e522 2026-06-04)` and uses the Tokio async runtime with rustls for TLS. Key characteristics:

**String Encryption:** ChaCha20-Poly1305 per-call-site encryption with distinct 32-byte keys and 12-byte IETF nonces per string. Approximately 2,421 encrypted strings recovered across samples. An 80 KB (81,920 bytes, 16-byte aligned) encrypted configuration blob is embedded.

**Credential Harvesting:**
- **Cloud:** AWS credentials, ECS endpoint (`169.254.170.2`), Secrets Manager, SSM Parameter Store; GCP `metadata.google.internal`, `credentials.db`, `access_tokens.db`, `application_default_credentials.json`, Secret Manager; Azure IMDS (`169.254.169.254`), `management.azure.com`; HashiCorp Vault (`v1/secret/data/`)
- **Crypto Wallets:** MetaMask (`nkbihfbeogaeaoehlefnkodbefgpgknn`), Trust Wallet (`egjidjbpglichdcondbcbdnbeeppgdph`), Coinbase Wallet (`hnfanknocfeofbddgcijnmhnfnkdnaad`), Phantom (`bfnaelmomeimhlpmgjnjophhpkkoljpa`), Exodus (`server.exodus.io`); extracts HD Key Tree, mnemonic, seedPhrase, recoveryPhrase; parses BIP-39 English wordlist
- **AI Tools:** Claude Desktop (`.config/Claude/claude_desktop_config.json`, `.claude.json`), Cursor (`.cursor/mcp.json`), Windsurf (`.codeium/windsurf/mcp_config.json`), Factory (`.factory/mcp.json`), Zed (`.config/zed/settings.json`), VS Code/Insiders (`settings.json`, `.mcp.json`, `mcpServers`)
- **Browsers:** Chrome, Chromium, Edge, Brave, Vivaldi, Opera (LevelDB, SQLite: Login Data, Cookies, Web Data); Firefox (`profiles.ini`, `cookies.sqlite`, `prefs.js`, `key4.db`)
- **Messaging:** Discord (`/api/v9/users/@me`, guild enumeration), Slack (`.slack.com`, `/api/auth.test`), Telegram Desktop (`tdata`, `key_datas`)
- **Gaming:** Steam (`steamLoginSecure`, `loginusers.vdf`, `ConnectCache`)
- **Password Managers:** Bitwarden extension (`nngceckbapebfimnlniiiahkandclblb`), 1Password vaults, KDE KWallet (D-Bus `org.kde.KWallet`)
- **VPN/Network:** WireGuard (`/etc/wireguard/*.conf`), OpenVPN (`/etc/openvpn`), IPsec (`/etc/ipsec.secrets`)
- **npm Tokens:** `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `NPM_CONFIG__AUTHTOKEN`, `NPM_CONFIG_TOKEN`, `NPM_AUTH_TOKEN` environment variables; `.npmrc` and `/etc/npmrc`
- **Offensive Frameworks:** Metasploit, Sliver, Havoc, Mythic, Covenant, AdaptixC2, Shad0w
- **Tor:** Hidden service keys (`hs_ed25519_secret_key`, `hs_ed25519_public_key`, `private_key_ed25519`)

### 5. C2 Infrastructure

**Tor Integration:**
- Probes localhost for an existing SOCKS proxy
- Downloads Tor Expert Bundle from `archive.torproject.org:443` if unavailable
- Launches Tor as a child process, monitors stderr for `"Bootstrapped 100%"`
- Routes C2 through the local Tor SOCKS5 proxy (auth: `05 01 00`, expected: `05 00`)
- OPSEC weakness: Queries `check.torproject.org/api/ip` over cleartext TLS before Tor is established, exposing real IP

**Two C2 Routes:**
- **Route 1 (HTTP Bootstrap):** SOCKS connects to C2 on port 80, sends POST to `/` with 32-byte X25519 client public key
- **Route 2 (Raw Stream):** SOCKS connects to port 8080, raw TCP channel bypassing HTTP

**Encryption:** X25519 key exchange with HKDF directional expansion into `csi-a2s` (client-to-server) and `csi-s2a` (server-to-client) key spaces. ChaCha20-Poly1305 framing: 4-byte big-endian length + 12-byte nonce + authenticated ciphertext. Empty AAD.

**Initial Beacon:** JSON `hello` message containing CPU cores, system locale, active users, environment info, hardware ID.

**Message Protocol:**
- Progress: `{"t":"out","id":"...","data":...,"progress":true}`
- Completion: `{"t":"done","id":"..."}`

### 6. Data Exfiltration

- **Control/metadata:** Over encrypted Tor SOCKS5 channel to C2 IPs
- **Bulk data:** Direct unproxied HTTPS POST to `temp.sh` using rustls, `multipart/form-data` body (`POST /upload HTTP/1.1`). Resulting URL transmitted back over Tor C2
- **Additional exfil:** POST/PUT to cloud APIs (Kubernetes `/api/v1/namespaces`, AWS Secrets Manager, SSM) using stolen credentials

### 7. Platform-Specific Behavior

#### Linux
- **Payload:** ELF x86-64 PIE (SHA256: `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`)
- **Build ID:** `c05bf7dc45672d7a59cbd5e300f586482da14d00`
- **Persistence:** systemd system service (`/etc/systemd/system` with `Restart=always`), fallback to user-level systemd (`~/.config/systemd/user`), fallback to cron (`/etc/cron.d` or user crontab)
- **Privilege escalation:** `sudo -S -p` (password via stdin), `systemd-run --system --no-ask-password`
- **eBPF rootkit:** Imports `bpf_object__open_mem`, `bpf_object__load`, `bpf_program__attach`, `bpf_map__fd` from libbpf.so.1 for process/connection hiding
- **Fingerprinting:** `/etc/machine-id`, `/var/lib/dbus/machine-id`, `/sys/class/dmi/id/board_serial`
- **Container detection:** Monitors `/proc/self/mountinfo` and `/proc/self/cgroup`

#### Windows
- **Payload:** PE32+ x86-64 (SHA256: `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`)
- **PDB GUID:** `6976bd1e56f6b4214c4c44205044422e`
- **PDB path:** `agent.pdb` (relative only)
- **Persistence:** Task Scheduler XML with `<Hidden>true</Hidden>`, restart interval PT1M, retry count 999, no execution time limit
- **Anti-analysis:** `IsDebuggerPresent` check, `GetExtendedTcpTable` for network enumeration
- **OPSEC:** Zeroed PE timestamp and checksum, removed Rich header (lld-link confirmed)
- **Startup folder:** `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

#### macOS
- **Payload:** Mach-O arm64 (SHA256: `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd`)
- **Persistence:** LaunchAgent plist with `RunAtLoad` and `KeepAlive`, 30-second `StartInterval` restart policy
- **System info:** `sysctl` and `sysctlbyname` for hardware enumeration

### 8. npm Worm Propagation Routine

The IronWorm binary contains a self-propagation mechanism:

1. Scans for npm tokens in environment variables (`NPM_TOKEN`, `NODE_AUTH_TOKEN`, `NPM_CONFIG__AUTHTOKEN`, `NPM_CONFIG_TOKEN`, `NPM_AUTH_TOKEN`) and `.npmrc` files
2. Validates tokens via `registry.npmjs.org/-/whoami`
3. Enumerates accessible packages via `/-/orgs` and `/-/v1/user/<user>/packages`
4. Prioritizes targets by download count via `api.npmjs.org/downloads/point/last-month`
5. Downloads latest `.tgz` archives
6. Injects malicious `setup.mjs` preinstall script
7. Rewrites `package.json` to add `scripts.preinstall`
8. Publishes via raw HTTP `PUT` to `registry.npmjs.org:443` using stolen bearer tokens (bypasses `npm publish` CLI)
9. Contains tokenized JavaScript template for generating fresh variable names and cross-project injection

### 9. Anti-Forensics / Evasion Techniques

- Stripped panic source locations in all binaries
- No Cargo metadata or `.cargo/registry` paths leaked
- Zeroed PE timestamp and checksum (Windows)
- Removed Rich header (Windows)
- Relative PDB path only (`agent.pdb`)
- Per-call-site ChaCha20-Poly1305 string encryption (~2,421 strings)
- Detached process execution with hidden window (`windowsHide: true`)
- eBPF process/connection hiding (Linux)
- `IsDebuggerPresent` anti-debug (Windows)
- Embedded SQLite/LevelDB engines for direct browser data access (no external tools needed)
- ASAR archive parser for Electron app trojanization (Discord, VS Code, Slack)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| jscrambler | 8.14.0, 8.16.0, 8.17.0, 8.18.0, 8.20.0 | Core compromised package with IronWorm infostealer |
| jscrambler-webpack-plugin | 8.6.2 | Dependent package, pulled compromised jscrambler |
| gulp-jscrambler | 8.6.2 | Dependent package, pulled compromised jscrambler |
| grunt-jscrambler | 8.5.2 | Dependent package, pulled compromised jscrambler |
| jscrambler-metro-plugin | 9.0.2 | Dependent package, pulled compromised jscrambler |

### File System

| Platform | Path / Artifact | Hash (SHA256) | Description |
|----------|----------------|---------------|-------------|
| All | dist/setup.js | `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60` | Dropper script (preinstall hook) |
| All | dist/intro.js | `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86` | CSI binary container (7.8 MB) |
| All | package.json | `bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0` | Modified package.json (8.14.0) |
| Linux | `.{random}` in temp dir | `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd` | ELF x86-64 infostealer |
| Windows | `.{random}.exe` in temp dir | `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903` | PE32+ x86-64 infostealer |
| macOS | `.{random}` in temp dir | `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd` | Mach-O arm64 infostealer |
| Windows | (embedded hash) | `9eeffcb5c3445ef9512f7776045f99ea23f9ebed989f8570bc4634b4e340de5d` | Embedded Windows hash reference |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `37[.]27[.]122[.]124` | C2 server (ports 80, 8080) |
| IP | `57[.]128[.]246[.]79` | C2 server (ports 80, 8080) |
| Domain | `temp[.]sh` | Bulk data exfiltration host (HTTPS POST) |
| Domain | `check[.]torproject[.]org` | IP verification (`/api/ip` endpoint) |
| Domain | `archive[.]torproject[.]org` | Tor Expert Bundle download |
| Domain | `registry[.]npmjs[.]org` | npm registry (token validation, worm propagation) |
| Domain | `api[.]npmjs[.]org` | npm API (download stats for target selection) |
| URL Pattern | `hxxps://temp[.]sh/upload` | Multipart file upload exfiltration |
| URL Pattern | `hxxp://37[.]27[.]122[.]124/` | C2 HTTP bootstrap (POST with X25519 key) |
| URL Pattern | `hxxps://check[.]torproject[.]org/api/ip` | Pre-C2 IP check (OPSEC leak) |

### Behavioral

- Node.js spawns hidden randomly-named binary from temp directory via `spawn(..., { detached: true, stdio: 'ignore', windowsHide: true })`
- Binary queries `check[.]torproject[.]org/api/ip` before establishing Tor connectivity
- Downloads Tor Expert Bundle from `archive[.]torproject[.]org` if local Tor not available
- Establishes SOCKS5 proxy through local Tor, routes C2 through it
- X25519 key exchange followed by ChaCha20-Poly1305 encrypted channel
- Bulk uploads to `temp[.]sh` via multipart/form-data POST outside of Tor
- Creates hidden Windows scheduled tasks (PT1M restart, 999 retries)
- Creates macOS LaunchAgents with RunAtLoad and KeepAlive
- Creates Linux systemd services or cron jobs
- Enumerates and validates npm tokens, publishes trojanized packages via raw HTTP PUT
- eBPF program loading for process/connection hiding (Linux)
- Container magic bytes: `\x1bCSI\x01` (5-byte header)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Compromised npm publishing credentials used to publish trojanized jscrambler versions |
| T1059.007 | JavaScript | Preinstall hook executes setup.js via Node.js; IIFE injection in dist/index.js |
| T1027.013 | Encrypted/Encoded File | ChaCha20-Poly1305 per-call-site string encryption (~2,421 strings) |
| T1555.003 | Credentials from Web Browsers | Harvests Chrome, Firefox, Edge, Brave credential stores via embedded SQLite/LevelDB |
| T1555 | Credentials from Password Stores | Targets Bitwarden, 1Password, KDE KWallet |
| T1528 | Steal Application Access Token | Steals npm tokens, cloud API keys, AI tool API keys, Discord/Slack tokens |
| T1005 | Data from Local System | Harvests SSH keys, VPN configs, crypto wallet data, Tor hidden service keys |
| T1041 | Exfiltration Over C2 Channel | Control data exfiltrated over encrypted Tor SOCKS5 channel |
| T1567 | Exfiltration Over Web Service | Bulk data uploaded to temp.sh via HTTPS POST |
| T1053.005 | Scheduled Task | Windows: hidden scheduled task with PT1M restart interval |
| T1543.001 | Launch Agent | macOS: LaunchAgent with RunAtLoad and KeepAlive |
| T1543.002 | Systemd Service | Linux: systemd system/user services with Restart=always |
| T1014 | Rootkit | eBPF kernel module for process/connection hiding (Linux) |
| T1497.001 | System Checks | IsDebuggerPresent anti-debug check (Windows) |
| T1572 | Protocol Tunneling | C2 routed through Tor SOCKS5 proxy |

## Impact Assessment

- **Breadth:** ~15,800 weekly downloads; 1,479 estimated downloads during ~2-hour active compromise window. Four dependent packages also affected.
- **Depth:** Critical -- full credential theft across cloud providers, crypto wallets, AI tools, browsers, messaging apps, and password managers. Self-propagation via stolen npm tokens amplifies reach.
- **Stealth:** High -- ChaCha20-Poly1305 string encryption, eBPF rootkit, Tor C2 routing, detached process execution, anti-debug checks.
- **Attribution:** JFrog ties the payload to the IronWorm family and Shai-Hulud lineage, previously seen in the Arweave/WeaveDB supply chain attack (June 2026). The actor adapted delivery method three times in three hours in response to defender actions.

## Detection & Remediation

### Immediate Detection

Check if compromised versions were installed:

```bash
# Check package-lock.json / yarn.lock for affected versions
grep -rE '"jscrambler":\s*"(8\.14\.0|8\.16\.0|8\.17\.0|8\.18\.0|8\.20\.0)"' package-lock.json yarn.lock 2>/dev/null

# Check npm cache
npm cache ls jscrambler 2>/dev/null | grep -E '8\.(14|16|17|18|20)\.0'

# Check for CSI container magic bytes in node_modules
find node_modules -name 'intro.js' -size +5M -exec xxd -l 5 {} \; 2>/dev/null | grep '1b43 5349 01'

# Check for hidden binaries in temp directories
ls -la /tmp/.* "$TMPDIR"/.* 2>/dev/null | grep -E '\.[a-zA-Z0-9]{6,}'

# Check for persistence (Linux)
systemctl list-units --type=service | grep -v known-services
crontab -l 2>/dev/null

# Check for persistence (macOS)
ls ~/Library/LaunchAgents/ /Library/LaunchAgents/ 2>/dev/null

# Check for persistence (Windows - PowerShell)
# Get-ScheduledTask | Where-Object {$_.Settings.Hidden -eq $true}
```

### Remediation

1. **Immediately** remove jscrambler 8.14.0, 8.16.0, 8.17.0, 8.18.0, 8.20.0 and upgrade to 8.22.0
2. **Rotate all credentials** -- npm tokens, cloud API keys (AWS, Azure, GCP), SSH keys, VPN configs, AI tool API keys, messaging tokens (Discord, Slack, Telegram), cryptocurrency wallet recovery phrases
3. **Revoke and regenerate** any npm publishing tokens that may have been exposed
4. **Audit npm packages** you maintain for unauthorized version publications
5. **Check CI/CD logs** for unusual npm publish activity or network connections to `37.27.122[.]124`, `57.128.246[.]79`, or `temp[.]sh`
6. **Kill persistent processes** -- remove hidden scheduled tasks (Windows), LaunchAgents (macOS), systemd services/cron jobs (Linux)
7. **Check for eBPF programs** (Linux): `bpftool prog list` and inspect for unexpected BPF programs

### Long-Term Hardening

- Enable npm install script restrictions: `npm config set ignore-scripts true` or use npm 12+ defaults
- Use `npm audit signatures` to verify package provenance
- Implement lockfile-based dependency pinning
- Monitor for unexpected preinstall/postinstall hooks in dependencies
- Use network monitoring to detect connections to known file-hosting services from CI/CD
- Consider runtime security monitoring (e.g., StepSecurity Harden-Runner) for CI/CD workflows

## Detection Rules

These detections target the jscrambler IronWorm supply chain compromise at the PoC/advisory-specific altitude. Rules key on distinctive artifacts: specific file hashes, C2 IPs, the CSI container format, and characteristic IronWorm binary strings. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: Jscrambler Malicious Preinstall Hook Execution
Detects Node.js executing `dist/setup.js` via npm preinstall hook, the specific delivery mechanism used by compromised jscrambler versions 8.14.0--8.17.0.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 — network issue, not rule error); splunk convert 0; log_scale convert 0. Fields are standard process_creation. Scoped to Windows; Linux/macOS equivalent requires separate logsource. -->
```yaml
title: Jscrambler NPM Supply Chain - Malicious Preinstall Hook Execution
id: 7c3e1a4f-8b2d-4e6a-9f0c-d5a7b3e2c1f8
status: experimental
description: >
    Detects Node.js executing dist/setup.js via npm preinstall hook, consistent with
    the compromised jscrambler 8.14.0 supply chain attack that drops a Rust infostealer.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
    - https://socket.dev/blog/jscrambler-supply-chain-attack
    - https://research.jfrog.com/post/ironworm-returns-rustier-than-ever/
author: Actioner
date: 2026/07/17
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\node.exe'
            - '\npm.cmd'
    selection_cmdline:
        CommandLine|contains|all:
            - 'node'
            - 'dist/setup.js'
    condition: selection_parent and selection_cmdline
falsepositives:
    - Legitimate jscrambler package versions prior to compromise (check version)
level: high
```

### Sigma: Hidden Binary Spawned from Node.js in Temp Directory (Behavioral)
Detects Node.js spawning a hidden dotfile executable from a temp directory, a behavioral pattern consistent with the IronWorm payload delivery. This is a TTP-altitude rule -- it will match any Node.js-to-hidden-temp-binary chain, not just IronWorm.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check pass (structural); splunk convert 0; log_scale convert 0. Behavioral/TTP altitude — detects the delivery pattern, not the specific payload. Removed |re: modifier (inconsistent backend support). Replaced with |endswith and |contains chains for portability. Fixed ATT&CK tag: T1204.002 (User Execution) was inaccurate — the user does not execute the binary; replaced with T1564.001 (Hidden Files and Directories). Low confidence due to broad behavioral pattern — legitimate Node.js native addon builders may extract to temp. -->
<!-- revision: relabeled from specific/medium to behavioral/low per critic; removed |re: modifier for backend portability; replaced T1204.002 with T1564.001; replaced regex with endswith/contains chains -->
```yaml
title: Jscrambler NPM Supply Chain - Hidden Binary Spawned from Node.js in Temp Directory
id: 9a2f5b8e-3c4d-4a7e-b1d6-e8f0c9a3b2d7
status: experimental
description: >
    Behavioral detection for Node.js spawning a hidden randomly-named dotfile executable
    from the system temp directory. Consistent with the jscrambler 8.14.0 IronWorm payload
    delivery pattern but will match other Node.js-to-hidden-temp-binary chains.
    TTP altitude — use alongside specific IOC-based rules for triage context.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
    - https://socket.dev/blog/jscrambler-supply-chain-attack
    - https://research.jfrog.com/post/ironworm-returns-rustier-than-ever/
author: Actioner
date: 2026/07/17
tags:
    - attack.t1059.007
    - attack.t1564.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\node.exe'
    selection_temp:
        Image|contains:
            - '\Temp\'
            - '\tmp\'
            - '\AppData\Local\Temp\'
    selection_hidden:
        Image|endswith: '.exe'
        Image|contains: '\.'
    condition: selection_parent and selection_temp and selection_hidden
falsepositives:
    - Legitimate Node.js applications extracting and executing native binaries from temp directories
    - Node.js native addon build tools (node-gyp, prebuild) that stage binaries in temp
level: medium
```

### Snort: Jscrambler IronWorm C2 Communication
Detects outbound TCP connections to known IronWorm C2 IP addresses on ports 80 and 8080 (high confidence), and multipart POST exfiltration to temp.sh (medium confidence -- legitimate temp.sh usage possible). Snort not installed -- structural check only.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high (C2 IP rules), medium (temp.sh exfil rule)
<!-- audit: snort not installed; structural check passes (valid header, semicolons, sid range, flow, classtype). C2 IPs are campaign-specific, high precision. temp.sh exfil rule downgraded to medium — temp.sh is a legitimate public file-sharing service with benign usage. -->
<!-- revision: split confidence — C2 IP rules remain high; temp.sh exfil rule downgraded to medium per critic (legitimate usage possible) -->
```snort
alert tcp $HOME_NET any -> 37.27.122.124 [80,8080] (msg:"Actioner - Jscrambler IronWorm C2 Communication to 37.27.122.124"; flow:established, to_server; classtype:trojan-activity; reference:url,research.jfrog.com/post/ironworm-returns-rustier-than-ever/; metadata:author Actioner, created 2026-07-17; sid:2100001; rev:1;)

alert tcp $HOME_NET any -> 57.128.246.79 [80,8080] (msg:"Actioner - Jscrambler IronWorm C2 Communication to 57.128.246.79"; flow:established, to_server; classtype:trojan-activity; reference:url,research.jfrog.com/post/ironworm-returns-rustier-than-ever/; metadata:author Actioner, created 2026-07-17; sid:2100002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Jscrambler IronWorm Exfiltration to temp.sh"; flow:established, to_server; http_header; content:"Host|3a 20|temp.sh"; fast_pattern; http_method; content:"POST"; http_header; content:"multipart/form-data"; classtype:trojan-activity; reference:url,socket.dev/blog/jscrambler-supply-chain-attack; metadata:author Actioner, created 2026-07-17; sid:2100003; rev:1;)
```

### Suricata: Jscrambler IronWorm C2 and Exfiltration
Detects outbound connections to IronWorm C2 IPs (high confidence) and multipart POST exfiltration to temp.sh (medium confidence -- legitimate temp.sh usage possible).
**Status:** compile ✅ compiles · confidence: high (C2 IP rules), medium (temp.sh exfil rule)
<!-- audit: suricata -T exit 0. C2 IP rules are campaign-specific anchors. temp.sh exfil rule keys on host + method + content-type triple for precision but temp.sh has legitimate usage. -->
<!-- revision: split confidence — C2 IP rules remain high; temp.sh exfil rule downgraded to medium per critic (legitimate usage possible) -->
```suricata
alert tcp $HOME_NET any -> 37.27.122.124 [80,8080] (msg:"Actioner - Jscrambler IronWorm C2 to 37.27.122.124"; flow:established,to_server; classtype:trojan-activity; reference:url,research.jfrog.com/post/ironworm-returns-rustier-than-ever/; metadata:author Actioner, created_at 2026-07-17; sid:2200001; rev:1;)

alert tcp $HOME_NET any -> 57.128.246.79 [80,8080] (msg:"Actioner - Jscrambler IronWorm C2 to 57.128.246.79"; flow:established,to_server; classtype:trojan-activity; reference:url,research.jfrog.com/post/ironworm-returns-rustier-than-ever/; metadata:author Actioner, created_at 2026-07-17; sid:2200002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Jscrambler IronWorm Exfil to temp.sh via Multipart POST"; flow:established,to_server; http.method; content:"POST"; http.host; content:"temp.sh"; http.content_type; content:"multipart/form-data"; classtype:trojan-activity; reference:url,socket.dev/blog/jscrambler-supply-chain-attack; metadata:author Actioner, created_at 2026-07-17; sid:2200003; rev:1;)
```

### YARA: Jscrambler CSI Binary Container
Detects the custom CSI container format (`\x1bCSI\x01` magic header) used to bundle platform-specific IronWorm payloads within the disguised intro.js file. Keys on the magic header at offset 0, filesize constraints, and embedded gzip stream structural markers.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Prior version required JS strings (windowsHide, detached, process.platform) that exist in setup.js, NOT in intro.js — condition was unsatisfiable against the actual CSI container. Fixed: removed cross-file JS strings, added gzip magic (0x1f8b08) and platform ID byte patterns that ARE present in the binary blob per the CSI format spec (header + per-entry platform_id + gzip data). -->
<!-- revision: removed JS strings from separate file (setup.js); replaced with binary structural markers from intro.js itself (gzip magic, platform ID bytes); condition now satisfiable against actual CSI container -->
```yara
rule Supply_Chain_Jscrambler_CSI_Container
{
    meta:
        description = "Detects the custom CSI binary container format used by the compromised jscrambler npm package to bundle platform-specific IronWorm Rust infostealer payloads"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86"
        severity = "critical"

    strings:
        $magic = { 1B 43 53 49 01 }
        // Gzip magic (0x1f 0x8b 0x08) — appears in each platform's compressed payload
        $gzip_magic = { 1F 8B 08 }

    condition:
        $magic at 0 and
        filesize > 5MB and filesize < 15MB and
        #gzip_magic >= 2
}
```

### YARA: IronWorm Rust Infostealer Binary
Detects the IronWorm Rust infostealer binary via C2 protocol identifiers, dynamic imports, and PE/ELF structural markers. Caveat: IronWorm uses ChaCha20-Poly1305 per-call-site encryption for ~2,421 strings; most target strings (extension IDs, paths, config filenames) are encrypted at rest and will NOT match as plaintext. Strings retained here are those likely to survive in cleartext: PDB paths, dynamic symbol imports, protocol constants, and HTTP library strings. Effectiveness depends on which strings the compiler/linker leaves unencrypted.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. Downgraded from high to medium: most strings are ChaCha20-Poly1305 encrypted in the actual binary and won't match plaintext scans. Retained strings are those plausibly cleartext (PDB path in PE debug dir, ELF .dynsym imports, protocol/HTTP constants). Added PE/ELF structural markers to anchor on executable format. 4-of threshold accounts for platform variance (agent.pdb only in PE, bpf_object__open_mem only in ELF). No real sample available for validation. -->
<!-- revision: removed dishonest "sample: fired" label (was constructed sample); added encryption caveat; downgraded confidence high->medium; added PE/ELF structural markers ($pe_magic, $elf_magic); adjusted threshold to 4-of accounting for platform-specific string presence -->
```yara
rule Malware_IronWorm_Jscrambler_Rust_Infostealer
{
    meta:
        description = "Detects the IronWorm Rust infostealer binary deployed via the compromised jscrambler npm package. NOTE: ~2,421 strings are ChaCha20-Poly1305 encrypted at rest; this rule keys on strings expected to survive in cleartext (PDB paths, dynamic imports, protocol constants). Effectiveness varies by sample."
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://research.jfrog.com/post/ironworm-returns-rustier-than-ever/"
        hash = "fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd"
        severity = "high"

    strings:
        // PE/ELF structural markers
        $pe_magic = "MZ" ascii
        $elf_magic = { 7F 45 4C 46 }

        // PDB path (cleartext in PE debug directory)
        $s1 = "agent.pdb" ascii

        // C2 protocol direction constants (likely cleartext — used in HKDF key derivation)
        $s2 = "csi-a2s" ascii
        $s3 = "csi-s2a" ascii

        // libbpf dynamic import (cleartext in ELF .dynsym / .dynstr)
        $s4 = "bpf_object__open_mem" ascii
        $s5 = "bpf_program__attach" ascii

        // HTTP library / protocol strings (often unencrypted in Rust HTTP crates)
        $s6 = "multipart/form-data" ascii

        // Tor bootstrap detection string
        $s7 = "Bootstrapped 100%" ascii

        // SOCKS5 auth pattern (binary, not string-encrypted)
        $socks5_auth = { 05 01 00 }

    condition:
        filesize < 25MB and
        ($pe_magic at 0 or $elf_magic at 0) and
        4 of ($s*)
}
```

## Lessons Learned

1. **Security vendors are supply chain targets too.** Jscrambler -- a JavaScript security company -- had its own npm publishing credentials compromised, demonstrating that security tooling is not immune to supply chain attacks.

2. **Attackers adapt in real time.** The attacker published five versions in three hours, evolving from preinstall hooks to runtime injection (IIFE in index.js) to bypass defender countermeasures and the `--ignore-scripts` flag. This shows sophisticated operational awareness.

3. **npm 12 defaults help but aren't sufficient.** npm 12 (released July 8) disables install scripts by default, which would have blocked the preinstall hook delivery. However, versions 8.18.0+ bypassed this by injecting into main package code. Defense in depth remains essential.

4. **IronWorm represents an escalating threat.** This is the second major deployment of the IronWorm/Shai-Hulud malware family (after the Arweave/WeaveDB attack in June 2026), now with cross-platform support, expanded credential targets (AI tools, offensive frameworks), and eBPF rootkit capabilities.

5. **The targeting of AI tool configurations is notable.** Harvesting MCP configs, Claude Desktop settings, and Cursor/Windsurf credentials represents a new dimension in developer-targeting infostealers, potentially enabling further supply chain attacks via compromised AI assistant integrations.

## Sources

- [The Hacker News](https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html) -- primary news coverage with timeline, IOCs, and scope assessment
- [Socket.dev Analysis](https://socket.dev/blog/jscrambler-supply-chain-attack) -- initial detection (6 minutes post-publish), CSI container format analysis, ChaCha20-Poly1305 string encryption details, binary offset analysis, full credential target enumeration
- [JFrog Research](https://research.jfrog.com/post/ironworm-returns-rustier-than-ever/) -- IronWorm identification, Shai-Hulud lineage connection, C2 protocol analysis (X25519/HKDF/ChaCha20), Tor integration details, npm worm propagation routine, XRAY-1025905
- [StepSecurity Blog](https://www.stepsecurity.io/blog/jscrambler-npm-package-publishes-malicious-preinstall-binary) -- runtime monitoring via Harden-Runner, eBPF analysis, binary import analysis (libbpf, IsDebuggerPresent), embedded database engine identification
- [SafeDep Analysis](https://safedep.io/jscrambler-npm-supply-chain-compromise/) -- build fingerprints (PDB GUID, Build ID, rustc version), binary compilation details, persistence mechanism specifics (Task Scheduler XML, LaunchAgent plist parameters), OPSEC analysis
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-backdoor-jscrambler-npm-package-with-infostealer-malware/) -- dependent package details, download count during compromise window, remediation guidance

---
*Report generated by Actioner*
