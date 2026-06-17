# Technical Analysis Report: Atomic Arch AUR Supply-Chain Attack (2026-06-13)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-13
Version: 1.2 FINAL

## Executive Summary

A large-scale supply-chain campaign dubbed "Atomic Arch" compromised over 400 (and potentially up to 1,500) community-maintained packages in the Arch User Repository (AUR) beginning around June 11, 2026. Threat actors systematically adopted orphaned AUR packages and injected malicious PKGBUILD post-install hooks that silently fetch and execute rogue npm packages (`atomic-lockfile@1.4.2` in wave 1, `js-digest` in wave 2). The payloads are Rust-compiled Linux ELF binaries that deploy a full-spectrum credential stealer targeting browser data, SSH keys, GitHub/npm tokens, HashiCorp Vault secrets, Discord/Slack/Teams sessions, and OpenAI API keys. When run as root, an optional eBPF rootkit component hides processes, files, and network sockets from standard inspection tools. C2 communication is routed through a Tor onion service, and exfiltrated data is uploaded via `temp[.]sh`. The official Arch Linux repositories were not affected; only AUR packages built by users were compromised. Sonatype tracks this campaign as Sonatype-2026-003775 (CVSS 8.7).

## Background: Arch User Repository (AUR)

The AUR is a community-driven package repository for Arch Linux where users submit PKGBUILD scripts -- shell-based build instructions that package helpers like `yay` and `paru` execute to compile and install software. Unlike official Arch repositories, AUR packages are not vetted by Arch maintainers; users are expected to review PKGBUILDs before building. Packages whose maintainers have left are marked "orphaned" and can be adopted by any registered AUR user through a simple request process. This adoption mechanism, designed for community stewardship, was the primary attack vector. A similar but smaller-scale attack compromised a single AUR PDF-viewer package in 2018; the 2026 campaign represents a 200x+ escalation.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-06-09 | Earliest estimated attack preparation; threat actor accounts begin adopting orphaned packages |
| 2026-06-11 | First wave becomes active; PKGBUILD modifications inject `npm install atomic-lockfile minimist chalk` via preinstall/post-install hooks |
| 2026-06-11 | Sonatype researcher Eyad Hasan identifies initial set of ~20 compromised packages |
| 2026-06-12 | Second wave deploys using `bun install js-digest` via different attacker accounts (`custodiatovar`, `veramagalhaes`) |
| 2026-06-12 | Community grepping of AUR git mirror identifies 408+ compromised packages; number grows to ~588 confirmed |
| 2026-06-12 | Security researcher Whanos publishes preliminary binary analysis at ioctl[.]fail |
| 2026-06-12 | Community detection tools published on GitHub (lenucksi/aur-malware-check) |
| 2026-06-12 | Estimated scope revised upward to ~1,500 packages across both waves |
| 2026-06-13 | Multiple security news outlets report on the campaign; malicious npm packages removed |

## Root Cause: Orphaned Package Adoption Abuse

The attackers exploited AUR's permissive package adoption model. When a package is orphaned (its maintainer abandons it), any registered user can request ownership. The threat actors created multiple AUR accounts and systematically adopted orphaned-but-still-popular packages. They then modified the PKGBUILD files to add post-install hooks that download malicious npm packages as dependencies. Critically, they forged git commit metadata to impersonate the established maintainer `arojas` (an Arch Linux Trusted User whose account was never actually compromised), lending credibility to the modified packages. The legitimate package source code was left intact; only the build instructions changed, making detection through source code review alone insufficient.

## Technical Analysis of the Malicious Payload

### 1. PKGBUILD Injection (Initial Access)

Compromised PKGBUILDs were modified to include post-install hooks executing:

**Wave 1:** `npm install atomic-lockfile minimist chalk`
**Wave 2:** `bun install js-digest`

The inclusion of legitimate packages (`minimist`, `chalk`) alongside the malicious dependency was designed to make the installation command appear routine. The malicious npm package `atomic-lockfile@1.4.2` (publisher: `herbsobering`) contained a lifecycle hook: `"preinstall": "./src/hooks/deps"` which executed a bundled Linux ELF binary at `src/hooks/deps`.

### 2. Credential Stealer (Primary Payload)

The `deps` binary is a Rust-compiled, stripped, dynamically linked ELF64 (x86-64 PIE), 3,040,376 bytes. It uses async state machines for concurrent credential harvesting across the following targets:

**Browsers (20+ Chromium variants):** Chrome, Edge, Brave, Vivaldi, Opera, Yandex, Epic, Iridium, plus Flatpak variants. Targets `Local Storage/leveldb`, `Network/Cookies`, `Cookies`, `Default/Cookies` with encrypted cookie decryption capability.

**Developer credentials:**
- GitHub tokens (queries `api[.]github[.]com /user` and `/user/repos`)
- npm registry tokens (queries `registry[.]npmjs[.]org /-/whoami` and `/-/v1/search`)
- SSH keys and `known_hosts` from `~/.ssh`
- HashiCorp Vault tokens from `~/.vault-token` and `~/.vault/token`
- Docker/Podman authentication credentials
- OpenAI/ChatGPT bearer tokens (queries `api[.]openai[.]com`)

**Collaboration platforms:**
- Slack cookies/sessions (`.config/Slack`, Flatpak, Snap paths)
- Microsoft Teams (queries `authsvc[.]teams[.]microsoft[.]com`, `teams[.]microsoft[.]com`)
- Discord (including PTB, Canary, Vesktop, Legcord, WebCord, Vencord variants; queries `/api/v9/users/@me`)
- Telegram data stores

**System artifacts:**
- Shell histories (`~/.bash_history`, `~/.zsh_history`, `~/.local/share/fish/fish_history`)
- VPN profiles (`~/.ovpn` files)
- Machine identity (`/etc/machine-id`)

### 3. C2 Infrastructure

**Primary C2 (Tor onion):** `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid[.]onion`

The onion address is obfuscated in the binary via repeating XOR encryption (32-byte key at offset `0x1AA60`, 62-byte ciphertext at `0x2DA96`, decode loop at `0x1209f2`). Communication uses a local SOCKS5 proxy (`127.0.0.1:<runtime-port>`) to reach the onion service on TCP/80 or TCP/8080.

**C2 endpoints:**
- `POST /api/agent` -- command/result channel for agent check-in
- `/bin/linux` -- secondary payload staging
- `/bin/sha256/linux` -- integrity-verified payload staging

**Data exfiltration:** `POST /upload` to `temp[.]sh` using multipart form-data with support for multi-part file archiving.

### 4. eBPF Rootkit (Optional, Root-Only)

When executed with root privileges and sufficient Linux capabilities (`CapEff` check), the malware deploys an eBPF rootkit referenced internally as `scales.bpf.c`. The rootkit pins three BPF maps to the filesystem:

- `/sys/fs/bpf/hidden_pids` -- hides processes by PID
- `/sys/fs/bpf/hidden_names` -- hides processes by name
- `/sys/fs/bpf/hidden_inodes` -- hides network sockets by inode

The rootkit hides the malware from `ps`, `htop`, `netstat`, `ss`, and `/proc/net/tcp` inspection. It also prevents debugger attachment via `PTRACE_ATTACH` and `PTRACE_SEIZE` interception.

### 5. Persistence Mechanisms

**Root-level persistence:**
- Binary copied to `/var/lib/<generated_name>`
- systemd service created at `/etc/systemd/system/<generated_name>.service` with `Restart=always` and `RestartSec=30`

**User-level persistence:**
- Binary placed in user home/config directory
- systemd user service at `~/.config/systemd/user/<generated_name>.service` with same restart directives

### 6. Secondary Payload / Cryptominer

The binary contains the string `/usr/bin/monero-wallet-gui`, suggesting a secondary cryptomining payload that was not fully analyzed at time of discovery.

### 7. Anti-Forensics / Evasion Techniques

- **Trust inheritance:** Maintained established package names, histories, and reputation scores
- **Git metadata forgery:** Commit metadata spoofed to appear from legitimate Trusted User `arojas`
- **Legitimate dependency bundling:** Included real packages (`minimist`, `chalk`) alongside malicious payload
- **eBPF rootkit:** Hides process, file, and network artifacts from userspace tools
- **Tor anonymization:** C2 routed through onion service via local SOCKS5 proxy
- **Build-time execution:** Payload runs during package build, not at application runtime
- **XOR obfuscation:** C2 address encrypted within binary

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `atomic-lockfile` (npm) | 1.4.2 | Wave 1 malicious npm package; publisher `herbsobering` |
| `js-digest` (npm/bun) | unknown | Wave 2 malicious package; same publisher |
| `lockfile-js` (npm) | unknown | Additional malicious package in campaign |
| `alvr` (AUR) | compromised | Confirmed compromised AUR package |
| `premake-git` (AUR) | compromised | Confirmed compromised AUR package |
| `guiscrcpy` (AUR) | compromised | Confirmed compromised AUR package |
| `netmon-git` (AUR) | compromised | Confirmed compromised AUR package |
| `inadyn-mt` (AUR) | compromised | Confirmed compromised AUR package |
| `nodejs-elm` (AUR) | compromised | Confirmed compromised AUR package |
| `keepassx2` (AUR) | compromised | Confirmed compromised AUR package |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `src/hooks/deps` (in npm tarball) | `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b` | Wave 1 Rust credential stealer ELF64 (MD5: `42b59fdbe1b72895b2951412222ebf40`) |
| Linux | embedded in `js-digest` | `7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316` | Wave 2 payload ELF binary |
| Linux | `/var/lib/<generated_name>` | -- | Root persistence binary location |
| Linux | `/etc/systemd/system/<generated_name>.service` | -- | Root persistence service unit |
| Linux | `~/.config/systemd/user/<generated_name>.service` | -- | User persistence service unit |
| Linux | `/sys/fs/bpf/hidden_pids` | -- | eBPF rootkit pinned map |
| Linux | `/sys/fs/bpf/hidden_names` | -- | eBPF rootkit pinned map |
| Linux | `/sys/fs/bpf/hidden_inodes` | -- | eBPF rootkit pinned map |

### Network

| Type | Value | Context |
|------|-------|---------|
| Onion | `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid[.]onion` | Primary C2 via Tor |
| Domain | `temp[.]sh` | Data exfiltration upload service |
| URI Pattern | `POST /api/agent` | C2 command/control callback |
| URI Pattern | `POST /upload` | Exfiltration upload endpoint |
| URI Pattern | `GET /bin/linux` | Secondary payload staging |
| URI Pattern | `GET /bin/sha256/linux` | Integrity-verified payload staging |
| Domain | `api[.]github[.]com` | Credential validation (GET /user) |
| Domain | `registry[.]npmjs[.]org` | Credential validation (GET /-/whoami) |
| Domain | `api[.]openai[.]com` | Token validation |
| Domain | `discord[.]com` | Token validation (/api/v9/users/@me) |
| GitHub | `github[.]com/fardewoak/nodejs-argo` | Attacker infrastructure repository |

### Attacker Accounts

| Platform | Account | Role |
|----------|---------|------|
| AUR | `arojas` (impersonated) | Legitimate Trusted User; git metadata forged, account not compromised |
| AUR | `custodiatovar` | Wave 2 attacker; adopted 13 packages |
| AUR | `veramagalhaes` | Wave 2 attacker; adopted 13 packages |
| AUR | `krisztinavarga` | Wave 1 attacker account |
| npm | `herbsobering` | npm publisher for both `atomic-lockfile` and `js-digest` |

### Behavioral

- SOCKS5 proxy listener on `127.0.0.1` with runtime-selected port
- systemd services with `Restart=always` and `RestartSec=30` for binaries under `/var/lib/` or user config directories
- Queries to `api[.]github[.]com/user`, `registry[.]npmjs[.]org/-/whoami`, and `discord[.]com/api/v9/users/@me` from unexpected processes (note: these domains are legitimate services; alert only in correlation with other Atomic Arch indicators)
- eBPF maps pinned under `/sys/fs/bpf/hidden_*`
- Processes masquerading as kernel threads to evade `ps`/`htop`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Hijacked orphaned AUR packages by adopting them and injecting malicious PKGBUILD hooks |
| T1059.004 | Unix Shell | Post-install hooks execute shell commands to run npm/bun install |
| T1204.002 | Malicious File | Users build and execute compromised AUR packages via yay/paru |
| T1543.002 | Systemd Service | Persistence via systemd service units with Restart=always in both system and user directories |
| T1014 | Rootkit | eBPF rootkit hides processes, files, and network connections from userspace tools |
| T1555.003 | Credentials from Web Browsers | Harvests cookies, tokens, and local storage from 20+ Chromium-family browsers |
| T1552.001 | Credentials In Files | Steals SSH keys, Vault tokens, shell histories, VPN profiles |
| T1071.001 | Web Protocols | C2 communication via HTTP POST to /api/agent |
| T1090.003 | Multi-hop Proxy | C2 traffic routed through Tor onion service via local SOCKS5 proxy |
| T1567.002 | Exfiltration to Cloud Storage | Data uploaded via POST /upload to temp.sh (a file-sharing service, not the C2 channel) |
| T1036 | Masquerading | Git commit metadata forged to impersonate trusted maintainer; processes disguised as kernel threads |
| T1562.001 | Disable or Modify Tools | eBPF rootkit prevents debugger attachment via PTRACE interception |
| T1082 | System Information Discovery | Reads /etc/machine-id and checks CapEff for privilege assessment |

## Impact Assessment

**Breadth:** 400-1,500 AUR packages compromised across two waves, potentially affecting thousands of Arch Linux users and developer workstations. The AUR is used extensively by the Arch Linux community (including derivatives like Manjaro and EndeavourOS).

**Depth:** Full credential compromise -- browser sessions, SSH keys, API tokens for GitHub/npm/OpenAI, cloud provider credentials, CI/CD secrets. If rootkit deployed (root execution), complete system compromise requiring reinstallation from trusted media.

**Stealth:** High. The eBPF rootkit hides from standard inspection tools, Tor routing obscures C2 traffic, and git metadata forgery defeated reputation-based trust signals. Build-time execution means standard runtime monitoring may miss the initial infection.

**Economic impact:** Potential downstream supply-chain amplification -- compromised developer credentials (GitHub tokens, npm tokens) could enable further package repository attacks.

## Detection & Remediation

### Immediate Detection

```bash
# Check for known malicious npm packages in cache
find ~/.npm -name "atomic-lockfile" -o -name "js-digest" -o -name "lockfile-js" 2>/dev/null

# Check bun cache
find ~/.bun -name "js-digest" 2>/dev/null

# Check for eBPF rootkit maps
ls -la /sys/fs/bpf/hidden_pids /sys/fs/bpf/hidden_names /sys/fs/bpf/hidden_inodes 2>/dev/null

# Check for suspicious systemd services (system-wide)
grep -rl "Restart=always" /etc/systemd/system/*.service 2>/dev/null | xargs grep -l "RestartSec=30"

# Check for suspicious systemd services (user-level)
grep -rl "Restart=always" ~/.config/systemd/user/*.service 2>/dev/null | xargs grep -l "RestartSec=30"

# Check pacman log for recent AUR installations (June 9-12 window)
grep -E "2026-06-0[9]|2026-06-1[0-2]" /var/log/pacman.log | grep -i "install"

# Compare installed AUR packages against known-bad list
pacman -Qmq | sort > /tmp/installed_aur.txt
# Cross-reference with community package list from github.com/lenucksi/aur-malware-check

# Check for payload hash on disk
find / -type f -size 3040376c 2>/dev/null | xargs sha256sum 2>/dev/null | grep -i "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
```

### Remediation

1. **Containment:** Immediately disconnect affected systems from the network. Kill any suspicious processes and disable suspicious systemd services.

2. **Eradication -- non-root execution:** Remove the malicious binary from user directories, delete `~/.config/systemd/user/<name>.service`, and run `systemctl --user daemon-reload`. Clear npm and bun caches.

3. **Eradication -- root execution (rootkit deployed):** If the malware ran as root, **assume the rootkit is present and reinstall from trusted media.** There is no reliable way to trust a system after eBPF rootkit deployment.

4. **Credential rotation (CRITICAL):** Rotate ALL credentials on affected systems:
   - SSH keys (generate new keypairs, update authorized_keys on all servers)
   - GitHub personal access tokens
   - npm registry tokens
   - HashiCorp Vault tokens
   - Docker/Podman credentials
   - OpenAI API keys
   - Browser sessions (invalidate all active sessions)
   - Slack, Discord, Teams sessions
   - VPN certificates and profiles
   - Any passwords stored in browser password managers

5. **Downstream audit:** Check GitHub and npm accounts for unauthorized activity (new repositories, published packages, modified secrets).

6. **Recovery:** Rebuild from known-good Arch installation media. Reinstall only verified packages from official repositories. For AUR packages, manually audit PKGBUILD files before building.

### Long-Term Hardening

- **Review PKGBUILDs before building.** Always inspect install hooks, especially for packages recently adopted by new maintainers.
- **Pin trusted AUR package versions** and monitor for PKGBUILD changes using `git diff` before updates.
- **Build AUR packages in sandboxed environments** (containers, VMs) to limit credential exposure.
- **Advocate for AUR governance changes:** Require vetting period or community review for orphaned package adoptions.
- **Deploy file integrity monitoring** on `/sys/fs/bpf/`, `/etc/systemd/system/`, and `~/.config/systemd/user/`.
- **Monitor outbound Tor connections** from developer workstations.

## Detection Rules

These rules target the distinctive artifacts of the Atomic Arch campaign: malicious package installation commands, eBPF rootkit map creation, systemd persistence, C2 callback patterns, and payload file characteristics. Key caveats: (1) the systemd persistence rule is a generic TTP corroborator (low confidence) that fires on any .service file creation outside package manager control; (2) network rules for /api/agent and /bin/linux URIs are medium confidence due to generic paths; (3) C2 traffic routes through a Tor onion service, so cleartext HTTP IDS rules catch only non-Tor fallback scenarios; (4) the npm registry DNS rule (SID:2100104) was dropped for zero signal.

### Sigma: Malicious npm Install via PKGBUILD

Detects npm or bun installing the known-malicious packages `atomic-lockfile`, `js-digest`, or `lockfile-js` as observed in the Atomic Arch campaign.

- **Compile:** ✅ compiles (sigma check + splunk/logscale convert pass)
- **Confidence:** high

```yaml
title: Atomic Arch - Malicious npm Install via PKGBUILD
id: a1c3e5f7-9b2d-4f6a-8e0c-2d4f6a8b0c1e
status: experimental
description: >
    Detects npm or bun installing the known-malicious packages atomic-lockfile
    or js-digest, as observed in the Atomic Arch AUR supply-chain campaign
    (Sonatype-2026-003775).
references:
    - https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency
    - https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html
author: Actioner
date: 2026-06-13
tags:
    - attack.t1195.002
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_npm:
        Image|endswith:
            - '/npm'
            - '/npx'
            - '/bun'
        CommandLine|contains:
            - 'atomic-lockfile'
            - 'js-digest'
            - 'lockfile-js'
    selection_shell:
        Image|endswith:
            - '/bash'
            - '/sh'
            - '/zsh'
        CommandLine|contains|all:
            - 'npm install'
            - 'atomic-lockfile'
    condition: selection_npm or selection_shell
falsepositives:
    - Legitimate use of an unrelated package coincidentally named atomic-lockfile is extremely unlikely
level: critical
```

<!-- audit: sigma check 0 errors 0 issues; sigma convert --without-pipeline -t splunk OK; sigma convert --without-pipeline -t log_scale OK. Field names (Image, CommandLine) match linux process_creation schema. Values are real (not defanged). -->

### Sigma: eBPF Rootkit BPF Map Pinning

Detects creation of BPF map files named `hidden_pids`, `hidden_names`, or `hidden_inodes` under `/sys/fs/bpf/`, the hallmark of the Atomic Arch eBPF rootkit. Caveat: this rule requires Sysmon-for-Linux generating file_event telemetry; BPF map pinning may not produce a file_event in all audit configurations.

- **Compile:** ✅ compiles (sigma check + splunk/logscale convert pass)
- **Confidence:** high

```yaml
title: Atomic Arch - eBPF Rootkit BPF Map Pinning
id: b2d4f6a8-0c1e-3f5a-7b9d-4e6f8a0b2c3d
status: experimental
description: >
    Detects creation of BPF map files associated with the Atomic Arch eBPF
    rootkit (hidden_pids, hidden_names, hidden_inodes) pinned under /sys/fs/bpf/.
    Note: this rule requires Sysmon-for-Linux generating file_event telemetry;
    BPF map pinning may not produce a file_event in all audit configurations.
references:
    - https://thecybersecguru.com/news/atomic-arch-aur-supply-chain-attack-ebpf-rootkit/
    - https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html
author: Actioner
date: 2026-06-13
tags:
    - attack.t1014
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|startswith: '/sys/fs/bpf/'
        TargetFilename|endswith:
            - '/hidden_pids'
            - '/hidden_names'
            - '/hidden_inodes'
    condition: selection
falsepositives:
    - Custom security tooling or research projects using identically named BPF maps
level: critical
```

<!-- audit: sigma check 0 errors 0 issues; sigma convert --without-pipeline -t splunk OK; sigma convert --without-pipeline -t log_scale OK. TargetFilename matches Sysmon-for-Linux file_event schema. -->
<!-- revision: v1.2 — removed T1564.001 tag (BPF map pinning is rootkit behavior, not hidden files; T1014 already covers it); added Sysmon-for-Linux dependency caveat to description. -->

### Sigma: Systemd Service File Creation in Persistence Paths (Generic TTP Corroborator)

Detects systemd service file creation in persistence paths outside package manager control. This is a generic TTP corroborator -- it does not key on campaign-specific artifacts and will fire on any .service file creation in systemd paths. Correlate with other Atomic Arch indicators for campaign attribution. Note: file_event telemetry cannot inspect file content, so Restart=always / RestartSec=30 directives are not selectable at this layer.

- **Compile:** ✅ compiles (sigma check + splunk/logscale convert pass)
- **Confidence:** low

```yaml
title: Atomic Arch - Systemd Service File Creation in Persistence Paths
id: c3e5f7a9-1d2f-4b6c-8e0a-3f5d7b9c1e2f
status: experimental
description: >
    Detects systemd service file creation in paths used by the Atomic Arch
    malware for persistence. This is a generic TTP corroborator that fires
    on any .service file creation in systemd paths outside package manager
    control; correlate with other Atomic Arch indicators for campaign
    attribution.
references:
    - https://thecybersecguru.com/news/atomic-arch-aur-supply-chain-attack-ebpf-rootkit/
    - https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency
author: Actioner
date: 2026-06-13
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|endswith: '.service'
        TargetFilename|contains:
            - '/etc/systemd/system/'
            - '/.config/systemd/user/'
    filter_known:
        Image|startswith:
            - '/usr/lib/systemd/'
            - '/usr/bin/systemctl'
    condition: selection_path and not filter_known
falsepositives:
    - Legitimate software installation creating systemd units outside of package manager control
    - Container runtimes, configuration management tools, and CI/CD agents creating service units
level: low
```

<!-- audit: sigma check 0 errors 0 issues; sigma convert --without-pipeline -t splunk OK; sigma convert --without-pipeline -t log_scale OK. Low confidence due to generic systemd service creation pattern; combine with other Atomic Arch indicators for high-confidence triage. -->
<!-- revision: v1.2 — relabeled as generic TTP corroborator; downgraded from medium to low; removed Restart=always/RestartSec=30 claim from description (file_event cannot check file content); added container/CI false positive entry. -->

### YARA: Atomic Arch Infostealer Payload

Detects the Rust-compiled credential stealer ELF binary via characteristic strings (eBPF map names, SOCKS5 transport, C2 endpoints, credential targets).

- **Compile:** ✅ compiles (yarac exit 0)
- **Confidence:** high

```yara
rule Malware_AtomicArch_Infostealer_Deps
{
    meta:
        description = "Detects the Atomic Arch Rust-compiled credential stealer payload (deps binary) via characteristic strings from the AUR supply-chain campaign"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://ioctl.fail/preliminary-analysis-of-aur-malware/"
        hash1 = "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
        hash2 = "7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $bpf1 = "hidden_pids" ascii fullword
        $bpf2 = "hidden_names" ascii fullword
        $bpf3 = "hidden_inodes" ascii fullword
        $socks1 = "socks greeting write" ascii
        $socks2 = "socks greeting read" ascii
        $socks3 = "socks CONNECT write" ascii
        $socks4 = "socks5 auth rejected" ascii
        $c2_1 = "/api/agent" ascii
        $c2_2 = "/bin/linux" ascii
        $c2_3 = "/bin/sha256/linux" ascii
        $c2_4 = "server returned empty binary" ascii
        $cred1 = ".vault-token" ascii
        $cred2 = "Local Storage/leveldb" ascii
        $cred3 = "/usr/bin/monero-wallet-gui" ascii
        $cap1 = "CapEff:" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            (2 of ($bpf*)) or
            (2 of ($socks*) and 1 of ($c2*)) or
            ($c2_4 and 2 of ($c2*) and 1 of ($cred*)) or
            (3 of ($socks*)) or
            ($cap1 and 3 of ($c2*)) or
            ($cap1 and 2 of ($c2*) and 1 of ($socks*))
        )
}

rule Malware_AtomicArch_ScalesBPF
{
    meta:
        description = "Detects the eBPF rootkit component (scales.bpf.c reference) associated with the Atomic Arch campaign"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency"
        hash1 = "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
        hash2 = "7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $scales = "scales.bpf.c" ascii
        $map1 = "hidden_pids" ascii fullword
        $map2 = "hidden_names" ascii fullword
        $map3 = "hidden_inodes" ascii fullword
        $ptrace1 = "PTRACE_ATTACH" ascii
        $ptrace2 = "PTRACE_SEIZE" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        $scales and 2 of ($map*) and 1 of ($ptrace*)
}
```

<!-- audit: yarac exit 0. Both rules gate on ELF magic (0x7F454C46 little-endian = 0x464C457F). String combinations require multiple campaign-specific artifacts to reduce FP risk. Hashes for both Wave 1 and Wave 2 samples included in meta. -->
<!-- revision: v1.2 — tightened Infostealer_Deps condition: (2 of ($c2*) and 1 of ($cred*)) now requires $c2_4 as mandatory anchor since /bin/linux and /api/agent are individually common; ($cap1 and 2 of ($c2*)) tightened to require 3 of ($c2*) or fallback with $socks* anchor; added hash2 (Wave 2: 7883bda1...) to both rule metas. -->

### Suricata: Atomic Arch C2 and Exfiltration

Three rules covering C2 callback to `/api/agent`, data exfiltration via `temp.sh`, and secondary payload staging. SID:2100104 (npm registry DNS) was dropped -- alerting on DNS for registry[.]npmjs[.]org fires on every legitimate npm install with zero signal. Fundamental detection gap: the actual C2 is a Tor onion service routed via local SOCKS5 proxy, so cleartext HTTP patterns will not match on-wire C2 traffic; these rules catch only non-Tor fallback or misconfigured infections.

- **Compile:** ✅ compiles (suricata -T exit 0)
- **Confidence:** high (SID:2100102 temp.sh exfil), medium (SID:2100101 /api/agent -- too generic without host constraint), medium (SID:2100103 /bin/linux -- too generic)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Atomic Arch C2 Callback POST to /api/agent [medium confidence]"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/agent"; fast_pattern; classtype:trojan-activity; reference:url,ioctl.fail/preliminary-analysis-of-aur-malware/; metadata:author Actioner, created_at 2026-06-13, campaign Atomic_Arch, confidence medium; sid:2100101; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Atomic Arch Data Exfiltration via temp.sh Upload"; flow:established,to_server; http.method; content:"POST"; http.host; content:"temp.sh"; fast_pattern; http.uri; content:"/upload"; classtype:trojan-activity; reference:url,ioctl.fail/preliminary-analysis-of-aur-malware/; metadata:author Actioner, created_at 2026-06-13, campaign Atomic_Arch, confidence high; sid:2100102; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Atomic Arch Secondary Payload Staging Request /bin/linux [medium confidence]"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/bin/linux"; fast_pattern; classtype:trojan-activity; reference:url,ioctl.fail/preliminary-analysis-of-aur-malware/; metadata:author Actioner, created_at 2026-06-13, campaign Atomic_Arch, confidence medium; sid:2100103; rev:2;)
```

<!-- audit: suricata -T -S exit 0. Rules use dot-notation sticky buffers (http.method, http.uri, http.host). SID 2100104 (npm registry DNS) DROPPED — fires on every legitimate npm install, zero signal. SID:2100101 and SID:2100103 downgraded to medium confidence due to generic URI patterns. All values are real (not defanged). -->
<!-- revision: v1.2 — dropped SID:2100104 (npm DNS, zero signal); downgraded SID:2100101/2100103 to medium confidence; added Tor encryption caveat noting fundamental detection gap for onion-routed C2; bumped rev on modified SIDs. -->

### Snort 3: Atomic Arch C2 and Exfiltration

Three rules covering the same C2 and exfiltration patterns using Snort 3 underscore-notation sticky buffers. Same Tor detection gap caveat applies. Snort 3 is not installed in this environment; rules are structurally validated only.

- **Compile:** ⚠️ uncompiled (Snort 3 not available for validation)
- **Confidence:** medium (SID:2100201 /api/agent -- generic), medium (SID:2100202 temp.sh exfil), medium (SID:2100203 /bin/linux -- generic)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Atomic Arch C2 Callback POST to /api/agent [medium confidence]"; flow:established,to_server; http_method; content:"POST"; http_uri; content:"/api/agent",fast_pattern; classtype:trojan-activity; reference:url,ioctl.fail/preliminary-analysis-of-aur-malware/; metadata:author Actioner, created 2026-06-13, campaign Atomic_Arch, confidence medium; sid:2100201; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Atomic Arch Data Exfiltration via temp.sh Upload"; flow:established,to_server; http_method; content:"POST"; http_header; content:"Host: temp.sh",fast_pattern; http_uri; content:"/upload"; classtype:trojan-activity; reference:url,ioctl.fail/preliminary-analysis-of-aur-malware/; metadata:author Actioner, created 2026-06-13, campaign Atomic_Arch, confidence medium; sid:2100202; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Atomic Arch Secondary Payload Staging /bin/linux [medium confidence]"; flow:established,to_server; http_method; content:"GET"; http_uri; content:"/bin/linux",fast_pattern; classtype:trojan-activity; reference:url,ioctl.fail/preliminary-analysis-of-aur-malware/; metadata:author Actioner, created 2026-06-13, campaign Atomic_Arch, confidence medium; sid:2100203; rev:2;)
```

<!-- audit: Structural check only; Snort 3 not installed. Rules use underscore-notation sticky buffers (http_method, http_uri, http_header). Comma-separated content modifiers per Snort 3 convention. SIDs in 2100200 range to avoid collision with Suricata rules. -->
<!-- revision: v1.2 — fixed flow option spacing (removed space after comma in all rules); SID:2100202 now uses content:"Host: temp.sh" for precise Host header matching; downgraded all to medium confidence; bumped rev on modified SIDs. -->

## Lessons Learned

1. **Orphaned package adoption is a scalable attack vector.** The AUR's open adoption model, designed for community stewardship, was weaponized to hijack hundreds of trusted packages simultaneously. This is not unique to AUR -- any package ecosystem with permissive ownership transfer (PyPI, npm, RubyGems) faces the same structural risk.

2. **Build-time execution defeats runtime detection.** Traditional endpoint security monitors process creation and network connections at runtime. Malicious PKGBUILD hooks execute during the build phase, which is often performed in trusted contexts (user shells, CI pipelines) where monitoring is less rigorous.

3. **Trust signals can be forged.** Git commit metadata forgery allowed the attackers to impersonate a Trusted User, defeating the primary reputation signal AUR users rely on when evaluating packages. Cryptographic commit signing (GPG/SSH-signed commits) would have prevented this specific forgery.

4. **eBPF is a double-edged capability.** While eBPF enables powerful observability and security tooling, it also provides attackers with kernel-level stealth that is extremely difficult to detect or remediate without full system reinstallation.

5. **Developer workstations are high-value targets.** The stealer's focus on GitHub tokens, npm credentials, SSH keys, and CI/CD secrets indicates the attackers understand that compromising a single developer machine can cascade into downstream supply-chain attacks on the projects those developers maintain.

## Sources

- [BleepingComputer - Over 400 Arch Linux packages compromised](https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/) -- initial reporting with attack overview and remediation guidance
- [The Hacker News - Over 400 Arch Linux AUR Packages Hijacked](https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html) -- detailed technical analysis with SHA256 hashes, C2 details, and persistence mechanisms
- [HackRead - Atomic Arch Hijacks Linux AUR Packages](https://hackread.com/atomic-arch-hijacks-linux-aur-packages-malware/) -- Sonatype researcher attribution and CVSS scoring
- [Sonatype Blog - Atomic Arch npm Campaign](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency) -- primary vendor research with Sonatype-2026-003775 tracking
- [ioctl.fail - Preliminary Analysis of AUR Malware](https://ioctl.fail/preliminary-analysis-of-aur-malware/) -- primary technical reverse engineering analysis with comprehensive IOCs
- [GitHub - lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) -- community detection tools with 588+ compromised package list
- [Privacy Guides - Around 1,500 AUR Packages Compromised](https://www.privacyguides.org/news/2026/06/12/around-1-500-aur-packages-compromised-with-rootkit-like-malware/) -- updated scope assessment
- [The CyberSec Guru - Atomic Arch 900+ AUR Packages Backdoored](https://thecybersecguru.com/news/atomic-arch-aur-supply-chain-attack-ebpf-rootkit/) -- consolidated IOC summary with both wave hashes
- [CyberSecurityNews - 400+ Arch Linux AUR Packages Compromised](https://cybersecuritynews.com/arch-linux-aur-packages-compromised/) -- additional reporting

---
*Report generated by Actioner*
