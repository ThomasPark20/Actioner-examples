# Technical Analysis Report: Atomic Arch AUR Supply Chain Attack (2026-06-16)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-16
Version: 1.0 (DRAFT)

## Executive Summary

A large-scale supply chain attack dubbed "Atomic Arch" (Sonatype-2026-003775, CVSS 8.7) compromised over 1,600 Arch User Repository (AUR) packages between June 9-12, 2026, deploying a Rust-based credential stealer and an eBPF kernel rootkit. The attackers systematically adopted orphaned AUR packages through the platform's standard adoption process and injected malicious build instructions into PKGBUILD and `.install` scripts. Rather than modifying application source code, the poisoned build scripts executed `npm install atomic-lockfile` or `bun install js-digest`, pulling malicious npm packages that delivered a Linux ELF binary (`deps`) via a preinstall lifecycle hook.

The credential stealer targets an extensive range of developer secrets: browser session data from 20+ Chromium variants, collaboration platform tokens (Slack, Discord, Teams, Telegram), developer credentials (GitHub, npm, HashiCorp Vault, OpenAI), SSH keys, Docker/Podman credentials, VPN profiles, and shell histories. The eBPF rootkit component, which activates only with root privileges or `CAP_BPF`/`CAP_SYS_ADMIN` capabilities, hides malware processes, file names, and socket inodes from standard system tools by hooking `getdents64` and related syscalls. Data exfiltration occurs via `temp[.]sh` uploads and a Tor-based C2 channel through an onion service. Persistence is achieved through systemd services with `Restart=always` at both system and user levels.

The attack was first identified by Sonatype researcher Eyad Hasan, with independent reverse engineering of the `deps` binary performed by the researcher "Whanos" on ioctl.fail. The official Arch Linux repositories were not affected; only the community-maintained AUR was compromised.

## Background: Arch User Repository (AUR)

The Arch User Repository (AUR) is a community-driven repository for Arch Linux users. Unlike official Arch repositories, AUR packages are user-submitted PKGBUILD scripts that build packages from source. Key characteristics relevant to this attack:

- **Trust model**: AUR packages are not vetted by Arch Linux maintainers. Users are expected to review PKGBUILDs before building.
- **Orphan adoption**: When a package maintainer departs, the package becomes "orphaned" and any registered AUR user can adopt it through a standard request process with minimal verification.
- **Build execution**: Building an AUR package executes the PKGBUILD script and any `.install` hooks with the privileges of the invoking user. AUR helpers (yay, paru, pikaur) automate this process, further reducing manual review.
- **Historical precedent**: In 2018, an orphaned PDF-viewer AUR package was similarly adopted and backdoored, though at a much smaller scale.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-09 (approx.) | Earliest malicious commits pushed to AUR packages |
| 2026-06-11 | Sonatype researcher Eyad Hasan identifies initial batch of ~20 compromised AUR packages; campaign designated "Atomic Arch" (Sonatype-2026-003775) |
| 2026-06-11 | Malicious npm package `atomic-lockfile@1.4.2` published by npm account `herbsobering` |
| 2026-06-11 | AUR accounts `krisztinavarga`, `franziskaweber`, `tobiaswesterburg`, `ellenmyklebust` adopt orphaned packages en masse |
| 2026-06-11 | Suspicious monitoring accounts created: `ivonahruskova` (16 adoptions), `simongeisler` (16 orphan adoptions, 3-day-old account) |
| 2026-06-12 | Second wave begins: npm packages `js-digest@4.2.2` (created 10:21 UTC, unpublished 11:53 UTC) and `lockfile-js@1.4.2` (created 13:01 UTC, unpublished 16:29 UTC) deployed |
| 2026-06-12 | Second wave uses `bun install js-digest` as injection vector; AUR accounts `custodiatovar` (13 packages) and `veramagalhaes` (13 packages) involved |
| 2026-06-12 | Community trackers catalog 400+ hijacked packages; PrivacyGuides reports ~1,500 affected |
| 2026-06-12 | Independent researcher "Whanos" publishes reverse engineering analysis of `deps` binary on ioctl.fail |
| 2026-06-12 | Verified unique affected package count reaches 1,619 across both waves |
| 2026-06-13+ | Community detection tools published (lenucksi/aur-malware-check, A1RM4X/AUR-Malware-2026.06-Check) |

## Root Cause: Orphaned Package Adoption Abuse

The initial access vector was not a software vulnerability but an abuse of the AUR's trust model. The attackers:

1. **Identified orphaned packages**: Systematically cataloged AUR packages whose maintainers had departed, leaving them available for adoption.
2. **Adopted packages at scale**: Using freshly created or purpose-built AUR accounts, adopted hundreds of orphaned packages through the platform's standard adoption process.
3. **Spoofed git commit metadata**: Forged git commit author information to impersonate legitimate maintainers. Notably, the attacker impersonated `arojas`, a well-known KDE maintainer, to reduce suspicion.
4. **Modified build instructions only**: Rather than altering application source code, the attackers rewrote PKGBUILD files and `.install` scripts to inject a single malicious dependency installation command during the build process.

This approach is particularly insidious because:
- The package names, version histories, and community trust scores remained unchanged.
- The malicious modification was a single line in the build script, easily overlooked.
- AUR helpers automate builds, meaning many users never manually reviewed the modified PKGBUILDs.

## Technical Analysis of the Malicious Payload

### 1. Supply Chain Injection Mechanism

**Wave 1** (June 9-11): Modified PKGBUILDs and post-install scripts to execute:
```bash
npm install atomic-lockfile minimist chalk
```
The legitimate packages `minimist` and `chalk` served as camouflage.

**Wave 2** (June 12): Switched to Bun-based installation:
```bash
bun install js-digest
```

In both cases, the malicious npm package contained a preinstall lifecycle hook:
```json
"preinstall": "./src/hooks/deps"
```

This triggered execution of the `deps` ELF binary during package installation, before the user's intended build process even began.

### 2. Payload Binary: `deps` (Rust Credential Stealer)

| Attribute | Value |
|-----------|-------|
| File | `src/hooks/deps` |
| Type | Linux ELF64, x86-64, PIE, dynamically linked |
| Size | 3,040,376 bytes |
| SHA-256 | `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b` |
| MD5 | `42b59fdbe1b72895b2951412222ebf40` |
| Language | Rust (async runtime) |
| Entry Point | `0xeae00` |

The binary uses XOR encoding to obfuscate the C2 onion address:
- **XOR key location**: `0x1AA60` (32-byte repeating key)
- **Ciphertext location**: `0x2DA96` (62-byte obfuscated host)
- **Decode loop**: `0x1209f2`

### 3. Credential Harvesting

The infostealer targets an extensive range of developer secrets:

**Browsers** (20+ Chromium variants including Flatpak versions):
Chrome, Edge, Brave, Opera, Vivaldi, and variants -- cookies, tokens, local storage, and saved credentials.

**Collaboration Platforms**:
- **Slack**: Session cookies (`d` cookies), API calls to `/api/auth.test`, `/api/users.info`
- **Microsoft Teams**: Authentication tokens and tenant metadata
- **Discord**: User metadata, guild info; API calls to `/api/v9/users/@me` (including PTB, Canary, Flatpak, Snap, and third-party clients Vesktop, WebCord, Abaddon)
- **Telegram**: Session data

**Developer Credentials**:
- GitHub tokens and repository metadata (`api.github.com`)
- npm registry credentials (`registry.npmjs.org`)
- HashiCorp Vault tokens (`~/.vault-token`)
- OpenAI/ChatGPT bearer tokens
- Docker/Podman credentials (`~/.docker/config.json`)

**System Access**:
- SSH keys and `known_hosts` from `~/.ssh/`
- VPN configuration files (`.ovpn`)
- Shell histories (bash, zsh, fish)

### 4. Command and Control

| Component | Detail |
|-----------|--------|
| C2 Onion Address | `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid[.]onion` |
| C2 Endpoint | `POST /api/agent HTTP/1.0` |
| Upload Service | `temp[.]sh` via `POST /upload HTTP/1.1` |
| Transport | Local SOCKS-style proxying through `127.0.0.1` on runtime-selected ports |
| Ports | TCP/80 and TCP/8080 |

The malware establishes a local loopback proxy to route traffic through Tor to the onion C2 service. The `/api/agent` endpoint serves as the command/result channel, while `temp[.]sh` is used for bulk data exfiltration.

### 5. Persistence Mechanism

The malware installs a systemd service with `Restart=always` and `RestartSec=30`:

**With root privileges**:
- Binary copied to `/var/lib/<generated_name>`
- Service unit written to `/etc/systemd/system/<generated_name>.service`

**Without root (user-level)**:
- Binary copied to `~/.config/<generated_path>`
- Service unit written to `~/.config/systemd/user/<generated_name>.service`

The service name is dynamically generated, making static detection by service name infeasible. Detection must focus on behavioral patterns (e.g., `Restart=always` with binary paths under `/var/lib/` or user config directories).

### 6. eBPF Rootkit

The eBPF rootkit component activates conditionally when `geteuid() == 0` or the process possesses `CAP_BPF`/`CAP_SYS_ADMIN` capabilities (checked by parsing `CapEff:` from `/proc/self/status`).

**eBPF Program**: Compiled from source named `scales.bpf.c`
**Loader functions**: `bpf_object__load`, `bpf_program__attach`, `bpf_map__pin`

**Pinned BPF Maps** (persisted at):
- `/sys/fs/bpf/hidden_pids` -- hides process IDs from `ps`, `/proc`
- `/sys/fs/bpf/hidden_names` -- hides process names from listing tools
- `/sys/fs/bpf/hidden_inodes` -- hides socket inodes from `ss`, `netstat`, `NETLINK_SOCK_DIAG`

**Hooked Syscalls**: `getdents64` (directory listing interception)

**Anti-Debugging**: Blocks `PTRACE_ATTACH` and `PTRACE_SEIZE` attempts against hidden processes.

**Important limitation**: The eBPF rootkit does not escalate privileges. It requires pre-existing root access or BPF capabilities. However, when active, it renders the malware invisible to standard forensic tools, necessitating offline analysis from clean media.

### 7. Second Wave Payload

A second ELF binary was delivered via the `js-digest` package:
- **SHA-256**: `7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316`
- Community analysis linked this to the same npm publisher as `atomic-lockfile`
- Full reverse engineering of this binary has not been publicly released

### 8. Possible Cryptominer Component

A staged file linked to `monero-wallet-gui` was flagged by community analysts. A string reference to `/usr/bin/monero-wallet-gui` appears in the primary payload. This component has not been fully analyzed.

## Indicators of Compromise (IOCs)

### File Hashes

| Hash Type | Value | Description |
|-----------|-------|-------------|
| SHA-256 | `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b` | Primary `deps` ELF binary (Wave 1) |
| SHA-256 | `7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316` | Secondary ELF payload (Wave 2, js-digest) |
| SHA-256 | `47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204` | Additional payload variant |
| MD5 | `42b59fdbe1b72895b2951412222ebf40` | Primary `deps` ELF binary |

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid[.]onion` | C2 Domain | Tor hidden service C2 |
| `temp[.]sh` | Exfiltration | Data upload service |
| `POST /api/agent` | URI | C2 polling endpoint |
| `POST /upload` | URI | Data exfiltration endpoint |

### Malicious npm Packages

| Package | Version | npm Account |
|---------|---------|-------------|
| `atomic-lockfile` | 1.4.2 | `herbsobering` |
| `js-digest` | 4.2.2 | (same publisher cluster) |
| `lockfile-js` | 1.4.2 | (same publisher cluster) |

### Malicious AUR Accounts

**Wave 1**: `krisztinavarga`, `franziskaweber`, `tobiaswesterburg`, `ellenmyklebust`
**Wave 2**: `custodiatovar`, `veramagalhaes`
**Monitoring/Suspicious**: `ivonahruskova`, `simongeisler`
**Impersonated**: `arojas` (legitimate KDE maintainer, impersonated via git commit forgery)

### GitHub Infrastructure

| Indicator | Context |
|-----------|---------|
| `fardewoak/nodejs-argo` | Malicious GitHub repository |
| `herbsobering430` | Suspected reverse shell/proxy container image account |

### File System Indicators

| Path | Description |
|------|-------------|
| `src/hooks/deps` | Payload path within npm package |
| `/var/lib/<generated>` | Root-level persistence binary |
| `/etc/systemd/system/<generated>.service` | Root-level persistence unit |
| `~/.config/systemd/user/<generated>.service` | User-level persistence unit |
| `/sys/fs/bpf/hidden_pids` | eBPF rootkit pinned map |
| `/sys/fs/bpf/hidden_names` | eBPF rootkit pinned map |
| `/sys/fs/bpf/hidden_inodes` | eBPF rootkit pinned map |
| `scales.bpf.c` | eBPF rootkit source reference |

### Build Script Indicators (Strings in PKGBUILD/.install files)

```
npm install atomic-lockfile
npm install atomic-lockfile minimist chalk
bun install js-digest
src/hooks/deps
```

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Context |
|-------------|---------------|---------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Hijacking orphaned AUR packages to inject malicious dependencies |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | PKGBUILD script execution during package build |
| T1059.007 | Command and Scripting Interpreter: JavaScript | npm/Bun preinstall hook execution |
| T1547.004 | Boot or Logon Autostart Execution: Systemd Service | Persistence via dynamically generated systemd units |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Harvesting browser cookies, tokens, saved credentials |
| T1539 | Steal Web Session Cookie | Theft of Slack `d` cookies, Discord tokens, Teams sessions |
| T1552.001 | Unsecured Credentials: Credentials in Files | SSH keys, Vault tokens, Docker config, shell histories |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 via `/api/agent` and `/upload` endpoints |
| T1090.003 | Proxy: Multi-hop Proxy | Tor onion service C2 via local SOCKS proxy |
| T1041 | Exfiltration Over C2 Channel | Data upload to temp[.]sh and via C2 channel |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | eBPF rootkit hiding processes, files, and socket inodes |
| T1014 | Rootkit | eBPF kernel rootkit with pinned BPF maps |
| T1622 | Debugger Evasion | Anti-ptrace via PTRACE_ATTACH/PTRACE_SEIZE blocking |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Git commit author spoofing to impersonate `arojas` |

## Impact Assessment

### Scope
- **1,619 verified unique AUR package names** compromised across two waves (June 9-12, 2026)
- Only the community-maintained AUR was affected; official Arch Linux repositories were not compromised
- Any system that built a compromised AUR package on or after June 9, 2026 should be considered potentially compromised

### Credential Impact
- Full developer credential compromise: SSH keys, GitHub/npm tokens, cloud credentials, API keys
- Session hijacking for collaboration platforms (Slack, Discord, Teams, Telegram)
- Potential lateral movement via stolen SSH keys and cloud credentials
- Cryptocurrency theft risk via stolen wallet-adjacent credentials

### Stealth Impact
- Systems compromised with root privileges may have active eBPF rootkit rendering malware invisible to standard tools
- Offline forensic analysis from clean boot media required for rootkit-affected systems

### Historical Comparison
The Atomic Arch campaign is significantly larger than the 2018 AUR orphan adoption attack and shows methodological similarities to the IronWorm npm campaign (June 2026), suggesting possible shared tooling or operator overlap.

## Detection & Remediation

### Immediate Detection Steps

**1. Check AUR build caches for malicious packages:**
```bash
rg -n 'atomic-lockfile|js-digest|lockfile-js|npm install|bun install|src/hooks/deps' \
  ~/.cache/yay ~/.cache/paru ~/.cache/pikaur /var/cache /tmp
```

**2. Check pacman logs for affected date window:**
```bash
grep -E '2026-06-0[9]|2026-06-1[012]' /var/log/pacman.log | grep -E 'installed|upgraded'
```

**3. Hunt for systemd persistence:**
```bash
grep -r "Restart=always" /etc/systemd/system/
find /home -path "*/.config/systemd/user/*.service" -exec grep -l "Restart=always" {} \;
```

**4. Check for eBPF rootkit artifacts:**
```bash
ls -la /sys/fs/bpf/hidden_*
bpftool prog list
bpftool map list
```

**5. Verify binary hashes:**
```bash
find / -type f -size 3040376c -exec sha256sum {} \; 2>/dev/null
```

### Remediation

1. **If eBPF rootkit is suspected (ran as root)**: Boot from clean Arch ISO, mount filesystem externally. Do not trust tools running on the compromised system.
2. **Remove persistence**: Delete malicious systemd units and binaries from `/etc/systemd/system/`, `~/.config/systemd/user/`, `/var/lib/`, and `~/.config/`.
3. **Rotate ALL credentials**: SSH keys, GitHub PATs, npm tokens, API keys, Docker credentials, Vault tokens, VPN certificates, browser-saved passwords.
4. **Invalidate sessions**: Revoke active sessions on Slack, Discord, Teams, Telegram, GitHub.
5. **Audit downstream**: Check for lateral movement via stolen SSH keys or cloud credentials.
6. **Consider full reinstall**: If rootkit was active, a full system reinstall from trusted media is recommended.

## Detection Rules

### Sigma Rules

All Sigma rules are provided in `/tmp/actioner/` and have been validated with `sigma check` and converted to Splunk and LogScale backends.

#### 1. Atomic Arch PKGBUILD Injection Detection
Detects malicious npm/bun install commands in AUR package build processes.

**File**: `/tmp/actioner/sigma_atomic_arch_pkgbuild_injection.yml`

#### 2. Atomic Arch Systemd Persistence Detection
Detects creation of systemd service units with characteristics matching the Atomic Arch persistence mechanism.

**File**: `/tmp/actioner/sigma_atomic_arch_systemd_persistence.yml`

#### 3. Atomic Arch eBPF Rootkit Map Detection
Detects access to or creation of pinned BPF maps used by the Atomic Arch rootkit.

**File**: `/tmp/actioner/sigma_atomic_arch_ebpf_rootkit.yml`

#### 4. Atomic Arch Credential Exfiltration via temp.sh
Detects HTTP uploads to temp[.]sh used for data exfiltration.

**File**: `/tmp/actioner/sigma_atomic_arch_exfil_tempsh.yml`

#### 5. Atomic Arch Tor C2 Loopback Proxy Detection
Detects process creation patterns consistent with Tor-based C2 via local loopback.

**File**: `/tmp/actioner/sigma_atomic_arch_tor_c2.yml`

### YARA Rules

#### 6. Atomic Arch deps ELF Infostealer
Detects the Rust-based `deps` ELF binary by hash and string patterns.

**File**: `/tmp/actioner/yara_atomic_arch_deps.yar`

#### 7. Atomic Arch eBPF Rootkit Component
Detects eBPF rootkit artifacts by characteristic strings.

**File**: `/tmp/actioner/yara_atomic_arch_ebpf_rootkit.yar`

#### 8. Atomic Arch Malicious PKGBUILD
Detects AUR PKGBUILD files containing malicious injection commands.

**File**: `/tmp/actioner/yara_atomic_arch_pkgbuild.yar`

### Snort/Suricata Rules

#### 9. Atomic Arch C2 Beacon
Detects HTTP POST to `/api/agent` endpoint characteristic of Atomic Arch C2.

**File**: `/tmp/actioner/suricata_atomic_arch_c2.rules`

#### 10. Atomic Arch temp.sh Exfiltration
Detects HTTP POST to temp[.]sh `/upload` endpoint.

**File**: `/tmp/actioner/suricata_atomic_arch_exfil.rules`

## Lessons Learned

1. **Trust inheritance is a vulnerability**: The AUR's orphan adoption model allows attackers to inherit trust built by legitimate maintainers. This "trust acquisition" strategy (vs. building trust from scratch) is increasingly common in supply chain attacks.

2. **Build-time execution is an underappreciated attack surface**: npm preinstall hooks, PKGBUILD scripts, and similar build-time execution vectors continue to be exploited. Users and organizations should sandbox build processes and audit build scripts before execution.

3. **Community repositories require stronger adoption controls**: The ease with which hundreds of orphaned packages were adopted by fresh accounts highlights the need for adoption verification mechanisms (e.g., mandatory review periods, maintainer history requirements, multi-party approval).

4. **eBPF rootkits raise the forensic bar**: The use of eBPF for process and connection hiding means standard on-host detection tools may be insufficient. Detection strategies must account for kernel-level evasion and include offline analysis capabilities.

5. **Developer workstations are high-value targets**: The credential harvesting scope (SSH, cloud, API keys, collaboration platforms) demonstrates that compromising developer machines yields broad organizational access.

6. **Multi-wave attacks complicate response**: The rapid pivot from `atomic-lockfile` to `js-digest` and `lockfile-js` within 24 hours shows attackers are prepared to iterate when initial vectors are detected.

## Sources

- [The Hacker News: Over 400 Arch Linux AUR Packages Hijacked to Deploy Infostealer and eBPF Rootkit](https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html)
- [HackRead: Atomic Arch Campaign Hijacks 20+ Linux AUR Packages to Deliver Malware](https://hackread.com/atomic-arch-hijacks-linux-aur-packages-malware/)
- [Sonatype Blog: Atomic Arch - npm Campaign Adds Malicious Dependency](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency)
- [ioctl.fail: Preliminary Analysis of AUR Malware](https://ioctl.fail/preliminary-analysis-of-aur-malware/)
- [Corgea: Atomic Arch - AUR Supply Chain Attack Deploys eBPF Rootkit](https://corgea.com/research/atomic-arch-aur-atomic-lockfile-js-digest-ebpf-rootkit)
- [SafeDep Threat Intelligence: Atomic Arch Campaign](https://safedep.io/ti/campaigns/atomic-arch/)
- [GitHub: lenucksi/aur-malware-check - Detection Tools](https://github.com/lenucksi/aur-malware-check)
- [GitHub: A1RM4X/AUR-Malware-2026.06-Check](https://github.com/A1RM4X/AUR-Malware-2026.06-Check)
- [PrivacyGuides: Around 1,500 AUR Packages Compromised](https://www.privacyguides.org/news/2026/06/12/around-1-500-aur-packages-compromised-with-rootkit-like-malware/)
- [The CyberSec Guru: Atomic Arch - 900+ AUR Packages Backdoored](https://thecybersecguru.com/news/atomic-arch-aur-supply-chain-attack-ebpf-rootkit/)
- [Breached.Company: Atomic Arch AUR Supply Chain Attack](https://breached.company/atomic-arch-aur-supply-chain-attack-rootkit-infostealer-2026/)
- [StepSecurity: 400+ AUR Packages Hijacked](https://www.stepsecurity.io/blog/400-aur-packages-hijacked-atomic-arch-campaign)
- [CSA Labs: AUR Supply Chain Attack Deploys eBPF Rootkit](https://labs.cloudsecurityalliance.org/research/csa-research-note-aur-supply-chain-ebpf-rootkit-20260614-csa/)
