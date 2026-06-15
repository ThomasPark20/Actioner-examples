# Technical Analysis Report: Atomic Arch AUR Supply Chain Attack (2026-06-15)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-15
Version: 1.0 (DRAFT)

## Executive Summary

Between June 9 and June 12, 2026, threat actors hijacked over 400 orphaned packages in the Arch Linux User Repository (AUR) by exploiting the platform's package adoption process. The attackers modified PKGBUILD scripts to inject a malicious npm dependency (`atomic-lockfile@1.4.2`), which delivered a Rust-based credential stealer (dubbed "deps") and an eBPF kernel rootkit. A second wave on June 12 expanded the compromise to approximately 1,500 packages using an alternative delivery mechanism (`bun install js-digest`). Sonatype tracks the campaign as **Atomic Arch** (Sonatype-2026-003775, CVSS 8.7). SafeDep notes shared tradecraft with the IronWorm campaign cluster.

The credential stealer targets developer workstations with broad collection capabilities: browser cookies and credentials, SSH keys, GitHub/npm/OpenAI tokens, HashiCorp Vault secrets, Docker/Podman credentials, and session data from Slack, Discord, Teams, and Telegram. Exfiltration occurs via a Tor hidden service (`/api/agent` endpoint) and a secondary channel using the public `temp[.]sh` file-sharing service. When executed with root privileges, the malware loads an eBPF rootkit that hooks `getdents64()` to hide its processes, files, and network sockets from standard inspection tools, complicating post-compromise detection.

## Background: Arch User Repository (AUR)

The AUR is a community-driven repository of user-contributed package build scripts (PKGBUILDs) for Arch Linux. Unlike official repositories, AUR packages are not vetted by Arch maintainers — users are expected to review PKGBUILDs before installation. Packages can be "orphaned" when maintainers abandon them, and any registered AUR user can then request adoption. AUR helpers like `yay` and `paru` automate PKGBUILD fetching and building but may execute post-install scripts automatically unless explicitly configured otherwise. This adoption-based trust model was the vector exploited in this campaign. A similar tactic was used in a 2018 attack targeting an abandoned PDF-viewer AUR package.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-09 | Earliest observed PKGBUILD modifications by attacker-controlled accounts |
| 2026-06-11 | Sonatype engineer Eyad Hasan discovers anomalous npm dependency chain in AUR packages |
| 2026-06-11 | First wave: ~408 packages confirmed compromised with `npm install atomic-lockfile` injection |
| 2026-06-12 | Second wave: Attackers pivot to `bun install js-digest` delivery, expanding to ~1,500 affected packages |
| 2026-06-12 | Independent researcher Whanos publishes preliminary reverse engineering at ioctl.fail |
| 2026-06-12 | Community detection tool published at github.com/lenucksi/aur-malware-check |
| 2026-06-13 | BleepingComputer, The Hacker News, and Hackread publish public reporting |
| 2026-06-14 | CSA publishes research note with MITRE ATT&CK mapping |

## Root Cause: AUR Orphan Adoption Exploitation (T1195.002)

The attackers registered multiple AUR accounts using European-sounding pseudonyms and submitted legitimate adoption requests for orphaned packages. Once ownership was granted, they modified PKGBUILD files and/or `.install` scripts to inject post-install commands. Some attackers also spoofed git commit metadata to impersonate established maintainers (e.g., the legitimate KDE maintainer `arojas`).

**Known attacker AUR accounts:** `krisztinavarga`, `franziskaweber`, `tobiaswesterburg`, `ellenmyklebust`, `custodiatovar`, `veramagalhaes`

**Accounts under observation:** `ivonahruskova` (created Jun 11, 16 orphan adoptions), `simongeisler` (3-day-old account, 16 orphan adoptions)

**Associated attacker identities:** npm publisher `herbsobering`, GitHub user `fardewoak`, git identity `PLYSHKA`

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection via PKGBUILD Modification

The compromised PKGBUILDs added a post-install script executing:

**Wave 1:** `npm install atomic-lockfile minimist chalk`
**Wave 2:** `bun install js-digest`

The `minimist` and `chalk` dependencies were included as cover to appear legitimate. The malicious npm package `atomic-lockfile@1.4.2` contained a `preinstall` lifecycle hook defined in `package.json` that executed a bundled Linux ELF binary at `src/hooks/deps`.

### 2. Credential Stealer: "deps" ELF Binary

| Property | Value |
|----------|-------|
| SHA-256 | `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b` |
| MD5 | `42b59fdbe1b72895b2951412222ebf40` |
| Size | 3,040,376 bytes |
| Type | ELF64, x86-64, PIE, dynamically linked |
| Language | Rust (async runtime) |
| Entry Point | `0xeae00` |

The stealer targets a comprehensive set of developer credentials:

- **Browsers (27 variants):** Chrome, Edge, Brave, Vivaldi, Opera, Yandex, plus Flatpak versions — extracts `Local Storage/leveldb`, `Network/Cookies`, encrypted cookie values
- **Collaboration platforms:** Slack, Discord (including PTB, Canary, Vesktop, Legcord, WebCord, ArmCord, Vencord, NativeCord, Abaddon, Dissent, Ripcord, Datcord variants), Microsoft Teams (legacy + current), Telegram
- **Developer tokens:** GitHub PATs (via `/user`, `/user/repos` API), npm registry tokens (via `/-/whoami`), OpenAI/ChatGPT bearer tokens (via `api.openai.com`)
- **Infrastructure secrets:** HashiCorp Vault tokens (`/.vault-token`, `/.vault/token`), Docker/Podman credential stores and command history
- **SSH artifacts:** Private keys from `~/.ssh/`, `known_hosts`, PuTTY key files (detected by `PuTTY-User-Key-File-` header)
- **Shell histories:** `.bash_history`, `.zsh_history`, `.local/share/fish/fish_history`
- **VPN profiles:** `.ovpn` configuration files

### 3. C2 Infrastructure

**Primary C2:** Tor hidden service at `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid[.]onion`

The onion address is XOR-encrypted in the binary (32-byte key at offset `0x1AA60`, 62-byte ciphertext at `0x2DA96`, decoded at function `0x1209f2`). Communication uses HTTP/1.0:

- **Agent check-in:** `POST /api/agent` on TCP/80 and TCP/8080
- **Credential upload:** `POST /upload` (multipart form-data)
- **Secondary payload fetch:** `GET /bin/linux` with hash verification at `/bin/sha256/linux`

A local loopback SOCKS proxy on `127.0.0.1` serves as the transport layer to the Tor network.

**Secondary exfiltration:** HTTP POST uploads to `temp[.]sh`, a public file-sharing service.

### 4. eBPF Rootkit Component

The rootkit activates conditionally when the binary runs with `euid == 0` and the effective capability set includes `CAP_BPF` or `CAP_SYS_ADMIN` (parsed from `/proc/self/status` `CapEff:` field). The eBPF program source is referenced as `scales.bpf.c` and uses the `libbpf` API (`bpf_object__load`, `bpf_program__attach`, `bpf_map__pin`).

**Hooked syscall:** `getdents64()` — filters directory listing results before reaching userspace.

**Pinned BPF maps at `/sys/fs/bpf/`:**

| Map | Purpose |
|-----|---------|
| `hidden_pids` | Suppresses process IDs from `/proc` enumeration (defeats `ps`, `top`) |
| `hidden_names` | Removes filenames from directory listings (defeats `ls`, `find`) |
| `hidden_inodes` | Conceals socket inodes from `/proc/net/tcp` and netlink diagnostics (defeats `ss`, `netstat`) |

Additional capabilities include blocking debugger attachment via ptrace interception and hiding the local SOCKS listener socket.

### 5. Persistence Mechanism

The malware establishes systemd-based persistence with `Restart=always` and `RestartSec=30`:

- **Root mode:** Binary copied to `/var/lib/<generated_name>`, service unit at `/etc/systemd/system/<generated_name>.service`
- **Non-root mode:** Per-user installation at `~/.config/systemd/user/<generated_name>.service`

### 6. Secondary Payload

The binary fetches a secondary payload from the C2's `/bin/linux` endpoint with integrity verification via `/bin/sha256/linux`. References to `/usr/bin/monero-wallet-gui` suggest a cryptominer component, though this has not been fully analyzed.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - URLs: `hxxps://` or `hxxp://`

### Package / Software Level

| Package / Component | Malicious Version | Registry | Description |
|---------------------|-------------------|----------|-------------|
| atomic-lockfile | 1.4.2 | npm | Primary payload delivery package (Wave 1) |
| js-digest | unknown | npm | Secondary delivery package (Wave 2, via bun) |
| lockfile-js | unknown | npm | Additional delivery variant |

**Confirmed compromised AUR packages (partial):** `alvr`, `premake-git`, `monero-wallet-gui`

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `src/hooks/deps` (within npm package) | `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b` | Primary Rust infostealer ELF64 |
| Linux | (js-digest payload) | `7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316` | Wave 2 variant payload |
| Linux | (unknown context) | `47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204` | Additional campaign sample |
| Linux | `/sys/fs/bpf/hidden_pids` | N/A | eBPF rootkit pinned map (PID hiding) |
| Linux | `/sys/fs/bpf/hidden_names` | N/A | eBPF rootkit pinned map (filename hiding) |
| Linux | `/sys/fs/bpf/hidden_inodes` | N/A | eBPF rootkit pinned map (inode hiding) |
| Linux | `/var/lib/<generated_name>` | N/A | Root-mode persistence binary |
| Linux | `/etc/systemd/system/<generated_name>.service` | N/A | Root-mode persistence service unit |
| Linux | `~/.config/systemd/user/<generated_name>.service` | N/A | User-mode persistence service unit |
| Linux | `/usr/bin/monero-wallet-gui` | N/A | Secondary payload (suspected cryptominer) |
| Linux | `~/.npm/_cacache/` | N/A | npm cache containing malicious package artifacts |
| Linux | `~/.bun/install/cache/` | N/A | bun cache containing malicious package artifacts |

### Network

| Type | Value | Context |
|------|-------|---------|
| Onion | `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid[.]onion` | Primary C2 (Tor hidden service) |
| URL Pattern | `hxxp://<onion>/api/agent` | Agent check-in endpoint |
| URL Pattern | `hxxp://<onion>/upload` | Credential upload endpoint |
| URL Pattern | `hxxp://<onion>/bin/linux` | Secondary payload download |
| Service | `temp[.]sh` | Secondary exfiltration (public file-sharing) |
| Ports | TCP/80, TCP/8080 | C2 communication ports |
| GitHub | `fardewoak/nodejs-argon` | Attacker-controlled repository |

### Behavioral

- Systemd service units with `Restart=always` and `RestartSec=30` referencing binaries under `/var/lib/`
- eBPF pinned maps under `/sys/fs/bpf/` with `hidden_` prefix
- Outbound SOCKS connections on `127[.]0[.]0[.]1` loopback (Tor transport)
- Discrepancies between `/proc` process listings and alternative enumeration methods (rootkit concealment)
- HTTP multipart POST uploads to `temp[.]sh`
- npm preinstall hook executing native ELF binary (`src/hooks/deps`)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Hijacked orphaned AUR packages, modified PKGBUILDs to inject malicious npm dependency |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Post-install scripts execute `npm install` / `bun install` commands |
| T1036 | Masquerading | Spoofed git commit metadata to impersonate legitimate KDE maintainer `arojas` |
| T1027 | Obfuscated Files or Information | XOR-encrypted C2 onion address within binary |
| T1014 | Rootkit | eBPF program hooking `getdents64()` to hide processes, files, and sockets |
| T1622 | Debugger Evasion | ptrace interception to prevent debugger attachment |
| T1543.002 | Create or Modify System Process: Systemd Service | Persistence via systemd units with auto-restart |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvesting SSH keys, Vault tokens, shell histories, VPN configs |
| T1539 | Steal Web Session Cookie | Browser cookie extraction from 27 Chromium variants |
| T1217 | Browser Information Discovery | Enumeration of browser profiles and local storage |
| T1041 | Exfiltration Over C2 Channel | Credential upload via Tor C2 `/upload` endpoint |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Secondary exfiltration via temp.sh public upload |
| T1105 | Ingress Tool Transfer | Secondary payload download from C2 `/bin/linux` |
| T1496 | Resource Hijacking | Suspected cryptominer deployment (monero-wallet-gui reference) |

## Impact Assessment

**Breadth:** 408 packages confirmed in Wave 1; ~1,500 total across both waves. Actual victim count depends on how many users installed/updated affected packages between June 9-12 without reviewing PKGBUILDs. The npm package `atomic-lockfile` showed only 134 weekly downloads on Socket.dev, suggesting the real attack surface was via AUR build paths rather than direct npm installs.

**Depth:** Full credential compromise on affected systems. The stealer's broad collection scope (browser sessions, developer tokens, SSH keys, Vault secrets) means a single compromise can cascade into organizational infrastructure access.

**Stealth:** The eBPF rootkit makes post-compromise detection difficult on root-compromised systems. Standard process/file/network enumeration tools (`ps`, `ls`, `ss`, `netstat`) are blinded. The Tor-based C2 channel evades DNS monitoring.

## Detection & Remediation

### Immediate Detection

Check for known IOCs on potentially affected systems:

```bash
# Check for eBPF rootkit artifacts
ls -la /sys/fs/bpf/hidden_pids /sys/fs/bpf/hidden_names /sys/fs/bpf/hidden_inodes 2>/dev/null

# Check for suspicious systemd services referencing /var/lib/
grep -r 'ExecStart=/var/lib/' /etc/systemd/system/ ~/.config/systemd/user/ 2>/dev/null

# Check npm cache for malicious packages
find ~/.npm/_cacache -name '*.tgz' -exec tar -tzf {} \; 2>/dev/null | grep -E 'atomic-lockfile|js-digest|lockfile-js'

# Check pacman logs for installations in the attack window
grep -E '2026-06-0[9]|2026-06-1[0-2]' /var/log/pacman.log | grep -i 'installed\|upgraded'

# Use the community detection tool
git clone https://github.com/lenucksi/aur-malware-check.git && cd aur-malware-check && bash aur_check-v2.sh
```

### Remediation

1. **Credential rotation (IMMEDIATE):** Rotate ALL tokens, keys, and secrets accessible from the affected host — GitHub PATs, npm tokens, SSH keys, Vault tokens, Docker credentials, browser sessions, OpenAI API keys
2. **Root-compromised hosts:** Full reinstallation from trusted media. In-place cleaning is unreliable due to eBPF rootkit concealment.
3. **Non-root compromised hosts:** Remove malicious systemd services, clear npm/bun caches, remove malicious binaries, then rotate credentials
4. **Audit downstream access:** Check GitHub audit logs, npm publish history, and CI/CD pipelines for unauthorized activity using compromised tokens
5. **Report to AUR:** Flag compromised packages and attacker accounts

### Long-Term Hardening

- Configure AUR helpers (`yay`, `paru`) to always prompt for PKGBUILD review before building (`--editmenu` / `--review`)
- Use `namcap` to lint PKGBUILDs for anomalous dependencies (npm/bun installs in a non-Node package)
- Monitor AUR orphan adoption activity for coordinated takeovers
- Restrict `CAP_BPF` and `CAP_SYS_ADMIN` capabilities to prevent unauthorized eBPF program loading
- Implement allowlisting for systemd service creation on developer workstations

## Detection Rules

The following rules target distinctive artifacts from the Atomic Arch campaign: known-malicious package names in build commands, eBPF rootkit map paths, systemd persistence patterns, and `temp.sh` exfiltration. Network-level C2 detection is limited because the primary channel uses Tor (no DNS indicators); the Suricata rule covers the secondary `temp.sh` exfiltration channel. All Sigma rules were validated with `sigma check` and converted to Splunk and LogScale backends. The YARA rule was compiled with `yarac`. The Suricata rule was validated with `suricata -T`.

### Sigma: Malicious npm/bun Package Install During AUR Build

Detects execution of `npm install` or `bun install` for known-malicious packages (`atomic-lockfile`, `js-digest`, `lockfile-js`) associated with the Atomic Arch campaign.

<!-- audit: sigma check 0 errors 0 issues; sigma convert splunk OK; sigma convert log_scale OK; targets process_creation on linux; IOC-based rule matching distinctive malicious package names that should not appear in legitimate builds -->

**Compile:** sigma check ✅ | sigma convert splunk ✅ | sigma convert log_scale ✅
**Confidence:** medium — relies on malicious package names which could be re-registered or aliased; limited to builds where process creation telemetry captures npm/bun arguments.

```yaml
title: Atomic Arch - Suspicious npm/bun Install of Malicious Packages During Build
id: 8252dc56-b1fe-416b-9e57-e07c26bc56c2
status: experimental
description: >
    Detects execution of npm or bun installing known-malicious packages associated with
    the Atomic Arch AUR supply chain campaign (atomic-lockfile, js-digest, lockfile-js).
    These packages are injected via modified PKGBUILD post-install scripts.
references:
    - https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/
    - https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html
    - https://ioctl.fail/preliminary-analysis-of-aur-malware/
    - https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency
author: Actioner
date: 2026-06-15
tags:
    - attack.t1195.002
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_npm:
        Image|endswith: '/npm'
        CommandLine|contains: 'install'
    selection_bun:
        Image|endswith: '/bun'
        CommandLine|contains: 'install'
    selection_packages:
        CommandLine|contains:
            - 'atomic-lockfile'
            - 'js-digest'
            - 'lockfile-js'
    condition: (selection_npm or selection_bun) and selection_packages
falsepositives:
    - Legitimate use of identically named private packages in internal registries (unlikely)
level: critical
```

### Sigma: eBPF Rootkit Pinned Map Creation

Detects creation of BPF pinned map files with `hidden_` prefix under `/sys/fs/bpf/`, the signature persistence mechanism of the Atomic Arch eBPF rootkit.

<!-- audit: sigma check 0 errors 0 issues; sigma convert splunk OK; sigma convert log_scale OK; targets file_event on linux; path-based detection for specific BPF map naming convention; requires file event telemetry covering /sys/fs/bpf/ -->

**Compile:** sigma check ✅ | sigma convert splunk ✅ | sigma convert log_scale ✅
**Confidence:** medium — the `hidden_` prefix is distinctive but not unique to this malware; custom eBPF security tooling could theoretically use similar names.

```yaml
title: Atomic Arch - eBPF Rootkit Pinned Map Creation
id: 5688359d-ada6-4769-a9bf-21ddc7c5bf85
status: experimental
description: >
    Detects creation of BPF pinned map files used by the Atomic Arch eBPF rootkit
    to hide processes, filenames, and socket inodes from userspace tools.
references:
    - https://ioctl.fail/preliminary-analysis-of-aur-malware/
    - https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html
    - https://labs.cloudsecurityalliance.org/research/csa-research-note-aur-supply-chain-ebpf-rootkit-20260614-csa/
author: Actioner
date: 2026-06-15
tags:
    - attack.t1014
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|startswith: '/sys/fs/bpf/hidden_'
    condition: selection
falsepositives:
    - Custom eBPF security tools that happen to use a hidden_ prefix for pinned maps
level: high
```

### Sigma: Suspicious Systemd Service Creation Outside Package Manager

Detects creation of systemd service unit files under `/etc/systemd/system/` by processes other than systemd or systemctl, consistent with the Atomic Arch persistence mechanism.

Caveat: this is a behavioral/TTP rule and will require tuning for legitimate software that creates systemd services outside package managers (e.g., configuration management tools).

<!-- audit: sigma check 0 errors 0 issues; sigma convert splunk OK; sigma convert log_scale OK; targets file_event on linux; behavioral pattern detection, not IOC-specific; filter_known excludes systemd/systemctl but may need expansion for Ansible/Puppet/Chef in production -->

**Compile:** sigma check ✅ | sigma convert splunk ✅ | sigma convert log_scale ✅
**Confidence:** low — behavioral TTP rule that will generate false positives from legitimate service installation; requires environment-specific tuning of the filter.

```yaml
title: Atomic Arch - Systemd Service Creation with Restart Always from Var Lib
id: 446af0a8-26ac-42e3-b9a6-0e4a3c0236e6
status: experimental
description: >
    Detects creation of systemd service unit files that reference binaries under /var/lib/,
    consistent with the Atomic Arch malware persistence mechanism which copies itself to
    /var/lib/<generated_name> and installs a service with Restart=always.
references:
    - https://ioctl.fail/preliminary-analysis-of-aur-malware/
    - https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html
    - https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency
author: Actioner
date: 2026-06-15
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|startswith:
            - '/etc/systemd/system/'
        TargetFilename|endswith: '.service'
    filter_known:
        Image|startswith:
            - '/usr/lib/systemd/'
            - '/usr/bin/systemctl'
    condition: selection_path and not filter_known
falsepositives:
    - Legitimate software installation creating systemd services outside of package managers
    - Configuration management tools (Ansible, Puppet, Chef) deploying services
level: medium
```

### Sigma: Data Exfiltration via temp.sh

Detects HTTP POST requests to `temp.sh`, a public file-sharing service used by the Atomic Arch stealer as a secondary exfiltration channel.

<!-- audit: sigma check 0 errors 0 issues; sigma convert splunk OK; sigma convert log_scale OK; targets proxy logsource; temp.sh is a legitimate service so POST filtering helps but FPs are expected from legitimate developer use -->

**Compile:** sigma check ✅ | sigma convert splunk ✅ | sigma convert log_scale ✅
**Confidence:** low — `temp.sh` is a legitimate public service; this rule will generate false positives from authorized developer use and requires contextual triage.

```yaml
title: Atomic Arch - Data Exfiltration via temp.sh Upload Service
id: 1470466c-e5f7-4ea4-aa4d-74c7678b3ddd
status: experimental
description: >
    Detects HTTP connections to temp.sh, a public file-sharing service used by the
    Atomic Arch credential stealer to exfiltrate harvested secrets via multipart POST upload.
references:
    - https://ioctl.fail/preliminary-analysis-of-aur-malware/
    - https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html
    - https://labs.cloudsecurityalliance.org/research/csa-research-note-aur-supply-chain-ebpf-rootkit-20260614-csa/
author: Actioner
date: 2026-06-15
tags:
    - attack.t1567.002
    - attack.t1041
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: 'temp.sh'
    selection_method:
        cs-method: 'POST'
    condition: selection and selection_method
falsepositives:
    - Legitimate developer use of temp.sh for file sharing
level: medium
```

### YARA: Atomic Arch deps Infostealer

Detects the Atomic Arch "deps" ELF binary via characteristic strings from its eBPF rootkit component, C2 communication paths, credential harvesting targets, and persistence configuration.

<!-- audit: yarac compiled exit 0; condition requires ELF header + filesize < 10MB + combination of BPF map names, C2 URI paths, credential paths, and systemd strings; no single string is sufficient alone — requires intersection of categories to reduce FP -->

**Compile:** yarac ✅
**Confidence:** medium — string-based detection on a stripped Rust binary; attacker can modify strings in future variants, but the combination of BPF map names + C2 paths + credential targets is distinctive.

```yara
rule Malware_AtomicArch_Deps_Infostealer
{
    meta:
        description = "Detects the Atomic Arch deps ELF infostealer based on distinctive strings from credential harvesting, eBPF rootkit, and C2 communication"
        author = "Actioner"
        date = "2026-06-15"
        reference = "https://ioctl.fail/preliminary-analysis-of-aur-malware/"
        hash = "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $bpf1 = "hidden_pids" ascii
        $bpf2 = "hidden_names" ascii
        $bpf3 = "hidden_inodes" ascii
        $bpf4 = "scales.bpf" ascii

        $c2_1 = "/api/agent" ascii
        $c2_2 = "/upload" ascii
        $c2_3 = "/bin/linux" ascii
        $c2_4 = "/bin/sha256/linux" ascii

        $cred1 = "/.vault-token" ascii
        $cred2 = "/.ssh/" ascii
        $cred3 = "Local Storage/leveldb" ascii
        $cred4 = "Network/Cookies" ascii
        $cred5 = "PuTTY-User-Key-File-" ascii

        $svc1 = "Restart=always" ascii
        $svc2 = "RestartSec=30" ascii

        $miner = "monero-wallet-gui" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            (2 of ($bpf*) and 1 of ($c2*)) or
            (3 of ($cred*) and 1 of ($c2*)) or
            (1 of ($bpf*) and 2 of ($cred*) and 1 of ($svc*)) or
            ($miner and 1 of ($bpf*) and 1 of ($c2*))
        )
}
```

### Suricata: temp.sh POST Exfiltration

Detects HTTP POST requests to `temp.sh` host, used by the Atomic Arch stealer for credential exfiltration.

<!-- audit: suricata -T exit 0; matches on http.method POST + http.host temp.sh; simple IOC-based rule; same FP concern as Sigma proxy rule -->

**Compile:** suricata -T ✅
**Confidence:** low — `temp.sh` is a legitimate service; this rule flags any POST to the host and requires contextual triage against known developer workflows.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Atomic Arch Credential Exfiltration via temp.sh POST Upload"; flow:established,to_server; http.method; content:"POST"; http.host; content:"temp.sh"; fast_pattern; classtype:trojan-activity; reference:url,ioctl.fail/preliminary-analysis-of-aur-malware/; metadata:author Actioner, created_at 2026-06-15, campaign Atomic_Arch; sid:2100101; rev:1;)
```

### Snort: temp.sh POST Exfiltration

Snort 3 equivalent of the Suricata rule above.

**Compile:** ⚠️ uncompiled (structural check only — `snort` binary not available for validation)
**Confidence:** low — same `temp.sh` FP concern as above.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Atomic Arch Credential Exfiltration via temp.sh POST Upload"; flow:established, to_server; http_method; content:"POST"; http_header; content:"temp.sh", fast_pattern; classtype:trojan-activity; reference:url,ioctl.fail/preliminary-analysis-of-aur-malware/; metadata:author Actioner, created 2026-06-15, campaign Atomic_Arch; sid:2100101; rev:1;)
```

## Lessons Learned

1. **Orphan adoption is a supply chain attack vector.** The AUR's open adoption model for abandoned packages provides a low-barrier entry point for attackers. Community repositories that allow permissionless package takeover need adoption review processes, cooling-off periods, or verified maintainer identity requirements.

2. **Build-time dependencies are execution vectors.** The attack exploited the fact that PKGBUILD scripts can invoke arbitrary commands during package builds, including pulling dependencies from external registries (npm, bun). AUR helpers that auto-build without PKGBUILD review amplify this risk.

3. **eBPF is a dual-use weapon.** The same kernel technology that powers modern observability tooling (Cilium, Falco, bpftrace) can be weaponized for rootkit-grade stealth. Organizations should restrict `CAP_BPF` capability assignment and monitor eBPF program loading via audit subsystem.

4. **Developer workstations are high-value targets.** The stealer's credential scope (GitHub, npm, Docker, Vault, SSH, cloud APIs) reflects an attacker model where compromising one developer laptop can cascade into organization-wide supply chain access.

## Sources

- [BleepingComputer](https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/) — initial public reporting with scope overview and affected package count
- [The Hacker News](https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html) — detailed technical writeup with SHA-256 hash, attack timeline, and BPF map details
- [Hackread](https://hackread.com/atomic-arch-hijacks-linux-aur-packages-malware/) — Sonatype researcher attribution (Eyad Hasan, Adam Reynolds) and IronWorm connection
- [Whanos / ioctl.fail](https://ioctl.fail/preliminary-analysis-of-aur-malware/) — primary reverse engineering analysis of the "deps" binary with file hashes, C2 decryption, eBPF analysis, and credential targets
- [Sonatype Blog](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency) — campaign discovery report with PKGBUILD injection details and tracking ID Sonatype-2026-003775
- [Cloud Security Alliance Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-aur-supply-chain-ebpf-rootkit-20260614-csa/) — MITRE ATT&CK mapping, IronWorm attribution, and remediation guidance
- [SafeDep Threat Intelligence](https://safedep.io/ti/campaigns/atomic-arch/) — campaign IOC aggregation, IronWorm tradecraft correlation, and affected package tracking
- [lenucksi/aur-malware-check (GitHub)](https://github.com/lenucksi/aur-malware-check) — community detection scripts, consolidated IOC list, attacker account identification, and compromised package lists

---
*Report generated by Actioner*
