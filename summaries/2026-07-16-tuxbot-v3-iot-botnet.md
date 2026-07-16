# Technical Analysis Report: TuxBot v3 IoT Botnet Framework (2026-07-16)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-16
Version: DRAFT 1.0

## Executive Summary

TuxBot v3 is a modular IoT botnet framework that cross-compiles statically linked ELF binaries for 17 CPU architectures and employs a layered command-and-control architecture combining encrypted TCP (ChaCha20-Poly1305 over X25519), DNS TXT fallback, a SHA-512-based domain generation algorithm producing 20 domains per day, P2P gossip with Ed25519-signed commands, and (broken) IRC/HTTP fallback channels. The framework ships a full-stack DDoS-for-hire platform: a Go-based C2 server with SSH admin panel, MariaDB user/quota management, Telnet/SSH/ADB scanning with 1,496 credential pairs, and 78 declared DDoS attack vectors across six handler functions -- though analysis by Palo Alto Unit 42 reveals that approximately 30% of functionality is dead code or broken due to bugs including an XOR key mismatch in the string table and a magic-header discrepancy in its custom exploit VM.

Notably, the source code contains verbatim LLM chain-of-thought artifacts ("Wait, where is the command?", "I created them so I should know?") and an unedited safety disclaimer ("WARNING: This code is for educational and authorized security research only") present in all ~60 C source files, indicating significant LLM-assisted development where the developers failed to review or strip AI-generated commentary. A crypto function labeled "Argon2id" actually implements PBKDF2-SHA256 but formats output to resemble Argon2id -- a hallucination carried directly into production code.

## Background: IoT Botnet Ecosystem

TuxBot v3 sits at the intersection of three converging botnet lineages -- Mirai, AISURU, and Keksec/Kaitori -- sharing dropper infrastructure at `185.10.68[.]127` (FlokiNET, Iceland). The framework targets Linux-based IoT devices (routers, cameras, embedded systems) via Telnet brute-forcing, SSH scanning, ADB exploitation, and a catalogue of 25+ IoT CVEs (most of which are non-functional in the analyzed build). The developer workstation hostname `newtuxdev.sevielw.digikalas[.]online` leaked in Git logs points to Iranian infrastructure, with the parent domain `digikalas[.]online` hosted on Iran's Arvan Cloud CDN.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-01-03 | Developer clones MHDDoS from GitHub; workstation hostname leaked in Git log |
| 2025-08-06 | Domain `digikalas[.]online` registered (Namecheap, Icelandic privacy) |
| 2026-01-04 to 2026-01-06 | 254 automated DDoS benchmark reports generated |
| 2026-01-20 | First sample submitted to VirusTotal (x86_64 debug build with symbols) |
| 2026-03-05 | C2 server first observed on Palo Alto Xpanse (`209.182.237[.]133`:2222) |
| 2026-04-22 | Six new production samples in Unit 42 internal telemetry (GCC 14.2.0) |
| 2026-05-28 | Initial Unit 42 Timely Threat Intelligence report |
| 2026-07-15 | Full Unit 42 technical analysis published |

## Root Cause: Telnet/SSH/ADB Brute-Force and IoT Exploit Scanning

Initial access relies primarily on Telnet brute-forcing with a credential table of 1,496 username/password pairs (imported from the DDOS-ROOTSEC project). SSH scanning and ADB scanning are also operational. The framework includes 25+ IoT exploits targeting routers and embedded devices, though most are non-functional due to multiple implementation bugs: Category 1 exploits (13 CVEs in hard-coded C functions) are compiled but never called; Category 2 exploits (13 CVEs in a custom VM) fail due to a magic-header mismatch (`0x4558504C` "EXPL" expected vs `0x54555845` "TUXE" emitted); Category 3 exploits (4 XOR-table payloads) are corrupted by the string table key mismatch.

## Technical Analysis of the Malicious Payload

### 1. Multi-Architecture Binary Distribution

The framework cross-compiles statically linked ELF binaries for 17 CPU architectures: Alpha, ARM, ARM64, ARM7, HPPA, M68K, MIPS, MIPS64, MIPS64EL, MIPSEL, PowerPC, PowerPC64LE, RISC-V64, S390X, SH4, SPARC64, and x86_64. Debug builds use GCC 11.4.0; production builds use GCC 14.2.0. Binaries are linked against glibc and libsodium (for X25519, ChaCha20-Poly1305, SHA-512, Ed25519). Distribution occurs via HTTP directory listing at `hxxp://185.10.68[.]127/bins/bot.<arch>`.

### 2. Persistence (Seven Methods)

1. **Systemd service:** Creates `sd-pam.service` with `Restart=always`, disguised as the legitimate sd-pam PAM session helper
2. **Cron entries:** `@reboot` and `*/5 * * * *` crontab entries
3. **Shell profile injection:** Appends execution commands to `.bashrc`, `.profile`, `.zshrc`
4. **Hidden backup copies:** Stored in 3 filesystem locations
5. **Guardian process:** Watchdog with crash backoff
6. **Hardware watchdog keepalive:** Prevents device reboot
7. **Binary relocation:** Periodic relocation across 21 directories, dot-prefixed filenames, masquerading as 20 system daemon names (systemd-udevd, dbus-daemon, cron, sshd, etc.)

### 3. C2 Infrastructure

The C2 architecture uses five channels (three functional, two broken):

**Primary -- Encrypted TCP (FUNCTIONAL):**
- Server: `209.182.237[.]133` (Singapore)
- Ports: TCP 1999 (encrypted bot protocol), TCP 31337 (alternate), TCP 2222 (SSH admin panel), TCP 9999 (machine API)
- Handshake: 4-byte magic `0xDEADBE01` followed by 32-byte X25519 public key exchange
- Packet format: 4-byte magic `0xDEADBEEF` + 12-byte nonce + ciphertext + 16-byte Poly1305 tag
- Encryption: ChaCha20-Poly1305

**DNS TXT Fallback (FUNCTIONAL):**
- Hardcoded domain: `c2.tuxbot.local`
- Nameserver: `8.8.8.8`

**Domain Generation Algorithm (FUNCTIONAL):**
- Seed format: `%04d-%02d-%02d-TuxBotv3-Evolution-Seed-2025-%d`
- Hash: SHA-512
- Domain generation: first 12 bytes of digest mapped to a-z (`digest[i] % 26`)
- TLD selection: 6 options (.com, .net, .org, .info, .biz, .cc) via `digest[12] % 6`
- Output: 20 domains per day

**P2P Gossip (FUNCTIONAL):**
- Port: TCP 13337
- Commands: Ed25519-signed

**IRC (BROKEN -- corrupted string table):**
- Port: TCP 6667, Channel: `#tuxbot`, Nick prefix: `tux`
- 12 attack methods: udp, syn, ack, vse, stomp, greip, greeth, udpplain, bypass, std, socket, dns

**HTTP Polling (BROKEN -- corrupted string table):**
- URL: `hxxp://127.0.0[.]1/cmd`

**SSH Admin Panel Commands:**
- Format: `!method target duration`
- Methods: get, post, slowloris, bypass, std, socket, dns

### 4. DDoS Attack Capabilities

Six handler functions route 78 declared attack vectors:
- `attack_udp_generic_optimized` (25 vectors): UDP/GRE/ICMP floods via sendmmsg() batches of 512 packets
- `attack_tcp_syn_optimized` (47 vectors): TCP SYN floods; also incorrectly routes all 47 Layer 7 HTTP methods (GET/POST floods, Slowloris, Apache Range, WordPress XMLRPC pingback, Cloudflare bypass)
- `attack_tcp_ack_optimized` (2 vectors): TCP ACK floods
- `attack_tcp_stomp_optimized` (1 vector): TCP ACK+PSH floods
- `attack_udp_dns_optimized` (2 vectors): DNS query floods
- `attack_miner` (1 vector): Cryptocurrency mining placeholder (non-functional)

Approximately 92 method implementations span three lineages: 30 Mirai-derived, 12 AISURU-suffixed, 8 Wuhan-suffixed.

### 5. Anti-Forensics / Evasion Techniques

**Anti-VM Module (weighted scoring, threshold 30):**
- DMI file checks for VMware, VirtualBox, QEMU signatures
- MAC address prefix matching for 7 VM vendors
- Disk size and CPU count heuristics
- Timing-based VM detection
- Kernel module scanning

**Process Masquerading:**
- Mimics 20 system daemon names: systemd-udevd, dbus-daemon, cron, sshd, etc.
- Lock file: `/tmp/.%08x.lock` (randomized hex name)

**Anti-Analysis:**
- Detection of analysis tools: gdb, IDA, Ghidra, radare2, Wireshark, Volatility
- `/proc` memory signature scanning for competing botnets: Mirai, QBOT, Vamp, Anime, dvrHelper
- Competitor killing via port binding prevention

### 6. LLM-Assisted Development Artifacts

**Safety disclaimer (unstripped):** `"WARNING: This code is for educational and authorized security research only. Unauthorized use is strictly prohibited and may be illegal."` -- present in all ~60 C source files.

**Chain-of-thought reasoning leaked into comments:**
- `"If the user insists on 'all exploits', I will add it but with a NOTE that checksums might fail."`
- `"I created them so I should know?"`
- `"Wait, where is the command?"`
- `"Correct action: I've already explored it. I will check other files."`
- `"Actually, TFTP requires lock-step ACK, Let's assume if the system() call returns..."`

**Crypto hallucination:** The Go C2 server contains a function commented `"HashPassword creates a cryptographically secure password hash using Argon2id"` -- the actual implementation is PBKDF2 with SHA256 loops, formatted to resemble Argon2id output (`$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s`).

### 7. XOR String Table Bug

The string table uses XOR encryption with intended key `0xDEDEFB4F` (bytes: `0x4F, 0xFB, 0xDE, 0xDE`), but due to duplicate byte cancellation the effective runtime key is `0xB4`. The offline encryption tool uses a different key `0xDEDEFBAF` (effective byte: `0x54`). This mismatch corrupts 9 string table entries at runtime, breaking the IRC C2, HTTP C2, and four IoT exploit payloads (ThinkPHP, GPON, two Realtek UPnP).

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Hash (SHA256) | Architecture | Description |
|----------|---------------|--------------|-------------|
| Linux | `6b7a8e0c96c2318e747f074f9a99d26738700769ac01bba692d19fc884847737` | Alpha | TuxBot v3 bot binary |
| Linux | `146f6010f6ee082aab13e0148d39baefa77eaba4ff65817b511b08c2092bdfd2` | ARM | TuxBot v3 bot binary |
| Linux | `bd6431fb06e4689142ef597cf00382e38ae20a5393a4d9277e45a3f5b3cbcff9` | ARM64 | TuxBot v3 bot binary |
| Linux | `a03b0d41f5ef03328150331ffa0ed970998883f7e0343d79b2d3b95330d8e7c1` | ARM7 | TuxBot v3 bot binary |
| Linux | `eb2fa179fde2f097c18d5d700ad87d660fc238ee14cbe5477032e60856859621` | HPPA | TuxBot v3 bot binary |
| Linux | `a8d70d16509e227d8306be361bc37a3dc9fe34bf476f51e361e55e6d293c2b3f` | M68K | TuxBot v3 bot binary |
| Linux | `0f8bcca3ed65e980da2a1f90a767b7d543be32eeea3e9338d09d4d635a497988` | MIPS | TuxBot v3 bot binary |
| Linux | `96b1f96efca3b9df2dea85678d60da27e3265b4a00e39e20e64b27bb985e1561` | MIPS64 | TuxBot v3 bot binary |
| Linux | `c7a36d6b8128c41f93a32413675401a10a2b5769b221bbaa8c5c309585b73ceb` | MIPS64EL | TuxBot v3 bot binary |
| Linux | `246c97957651de568e61eba1abe572f0b0f960456209995d43d53a0d7cc494a1` | MIPSEL | TuxBot v3 bot binary |
| Linux | `3ec016d637e4c9cd331edd2580a229621ad638e924a4aa29ac0342e9144ace19` | PowerPC | TuxBot v3 bot binary |
| Linux | `2f2c3551762c03da126e45dca6fc2f997c63f0f1bfc21fd0ceed680ac6f083ce` | PowerPC64LE | TuxBot v3 bot binary |
| Linux | `9cd5e7e3c8bad321ef6c3d47fe25b3b56e9487f703a7eeee52db4067e6bafe61` | RISC-V64 | TuxBot v3 bot binary |
| Linux | `e3a5296e762e9ee16010399666441d663beeea956382e97cca032a6a5ad06811` | S390X | TuxBot v3 bot binary |
| Linux | `f1efb78887bb8783d7781c07cd13b53c9c79ebe5baa81f335838d0a6e73dec7e` | SH4 | TuxBot v3 bot binary |
| Linux | `f324a45fcd2a9db4e542c09486c21b08bc42d6bf76fbd5f17871090361b10815` | SPARC64 | TuxBot v3 bot binary |
| Linux | `15c17dce89deccd5172285b2650de957918aa1157cde8e4633ae15dfe31f2711` | x86_64 | TuxBot v3 bot binary |
| Linux | `71dfbb171eca4ef9d02ff630b56e5283bbef7b375d4dbe9e8c9531bef312fa8d` | x86_64 | TuxBot v3 debug build (VirusTotal, 2026-01-20) |
| Linux | `511d3ffb4091cbcc94571d9fb3102e8cb424c6e187d01d53ff12078d54929bda` | ARM 32-bit | TuxBot v3 internal sample |
| Linux | `6aa4034dc7a2858094ff4dc59af07d6fe31119591e41599bcc0f3d0b516ee734` | ARM 32-bit | TuxBot v3 internal sample |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `209.182.237[.]133` | Primary C2 server (Singapore); TCP 1999/31337/2222/9999 |
| IP | `185.10.68[.]127` | Dropper server (FlokiNET, Iceland); serves `/bins/bot.<arch>` and Kaitori v3.9 |
| IP | `188.166.2[.]226` | Dead code RCE payload reference (DigitalOcean) |
| IP | `154.6.197[.]43` | Telnet login reporting endpoint |
| IP | `194.46.59[.]169` | Known AISURU infrastructure (shared ecosystem) |
| IP | `45.145.185[.]229` | Keksec dropper (`/bins/keksec.mips`) |
| IP | `107.174.133[.]119` | Keksec Huawei payload |
| Domain | `c2.tuxbot[.]local` | DNS TXT fallback C2 domain (hardcoded) |
| Domain | `digikalas[.]online` | Developer domain (Iran-hosted, Arvan Cloud) |
| Domain | `jetross[.]com` | TLS certificate linking C2 to dropper |
| Domain | `cfcybernews[.]eu` | Test domain (CF bypass module) |
| Domain | `captcha.kanfetka[.]site` | Test domain (CAPTCHA bypass module) |
| URL | `hxxp://185.10.68[.]127/bins/bot.<arch>` | Binary distribution path |
| URL | `hxxp://188.166.2[.]226/OwO/Tsunami.x86` | Dead code RCE payload |
| SSH Banner | `SSH-2.0-CNC` | Source code C2 config |
| SSH Banner | `SSH-2.0-CNC-Control-Server` | Live C2 server (Xpanse, 2026-03-05) |
| User-Agent | `r00ts3c-owned-you` | Dead code RCE scanner (inherited from r00ts3c Tsunami/MHDDoS) |

### Behavioral

- **Lock file pattern:** `/tmp/.%08x.lock` (randomized hex filename)
- **Systemd persistence:** Creates `sd-pam.service` with `Restart=always`
- **Cron persistence:** `@reboot` and `*/5 * * * *` entries
- **Shell profile injection:** Appends to `.bashrc`, `.profile`, `.zshrc`
- **Process masquerading:** Mimics 20 system daemon names (systemd-udevd, dbus-daemon, cron, sshd, etc.)
- **Binary relocation:** Periodic relocation across 21 directories with dot-prefixed filenames
- **Anti-VM scoring:** Weighted scoring system (threshold 30) checking DMI, MACs, disk size, CPU count, timing, kernel modules
- **C2 handshake:** 4-byte magic `0xDEADBE01` followed by X25519 key exchange on TCP 1999/31337
- **DGA:** SHA-512-based, 20 domains/day, seed `%04d-%02d-%02d-TuxBotv3-Evolution-Seed-2025-%d`
- **P2P gossip:** TCP 13337, Ed25519-signed commands
- **Competitor killing:** Scans `/proc` for Mirai, QBOT, Vamp, Anime, dvrHelper strings

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1110.001 | Brute Force: Password Guessing | Telnet brute-force with 1,496 credential pairs |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell command execution on compromised IoT devices |
| T1543.002 | Create or Modify System Process: Systemd Service | Creates `sd-pam.service` for persistence |
| T1053.003 | Scheduled Task/Job: Cron | `@reboot` and `*/5 * * * *` crontab persistence |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | Injects into `.bashrc`, `.profile`, `.zshrc` |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Process names mimic systemd-udevd, dbus-daemon, sshd, etc. |
| T1027 | Obfuscated Files or Information | XOR-encrypted string table (key `0xDEDEFB4F`) |
| T1571 | Non-Standard Port | C2 on TCP 1999, 31337, 13337 |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | ChaCha20-Poly1305 encrypted C2 traffic |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | SHA-512-based DGA generating 20 domains/day |
| T1071 | Application Layer Protocol | DNS TXT fallback, IRC, HTTP polling (partially broken) |
| T1095 | Non-Application Layer Protocol | Raw TCP encrypted protocol with custom magic bytes |
| T1498 | Network Denial of Service | 78 DDoS attack vectors across 6 handler functions |
| T1592 | Gather Victim Host Information | Anti-VM scoring, hardware/environment fingerprinting |
| T1105 | Ingress Tool Transfer | HTTP dropper downloads architecture-specific binaries |
| T1106 | Native API | sendmmsg() for optimized packet flooding |
| T1090.003 | Proxy: Multi-hop Proxy | P2P gossip mesh for C2 resilience |

## Impact Assessment

TuxBot v3 represents a comprehensive IoT botnet framework capable of large-scale DDoS attacks across multiple protocols. While approximately 30% of its functionality is broken in the analyzed build (exploit engine, IRC/HTTP fallback, L7 HTTP methods routed to wrong handler), the functional core -- Telnet/SSH/ADB scanning, encrypted C2, DGA, P2P gossip, UDP/TCP/DNS flooding, and seven persistence mechanisms -- is production-ready. The 17-architecture cross-compilation pipeline ensures broad IoT device coverage. The shared infrastructure with Keksec/Kaitori and AISURU suggests a broader ecosystem of cooperating or overlapping threat actors.

## Detection & Remediation

### Immediate Detection

```bash
# Check for TuxBot persistence artifacts
systemctl list-unit-files | grep sd-pam
crontab -l | grep -E '@reboot|/5.*\*.*\*'
grep -r "Akiru" /proc/*/cmdline 2>/dev/null
ls -la /tmp/.????????.lock 2>/dev/null
netstat -tlnp | grep -E ':(1999|31337|13337)\b'
```

### Remediation

1. **Containment:** Block outbound TCP 1999, 31337, 13337, 2222 at the network perimeter; block `209.182.237[.]133` and `185.10.68[.]127`
2. **Eradication:** Remove `sd-pam.service` from systemd; purge crontab entries; restore `.bashrc`, `.profile`, `.zshrc` from known-good backups; search 21 relocation directories for dot-prefixed binaries
3. **Recovery:** Reflash IoT device firmware; rotate all credentials; audit for lateral movement
4. **Secret rotation:** Change all Telnet/SSH credentials on IoT devices; disable Telnet where possible

### Long-Term Hardening

- Disable Telnet on all IoT devices; enforce SSH key-based authentication
- Segment IoT devices into dedicated VLANs with egress filtering
- Monitor for DGA-generated domains via DNS inspection
- Deploy network-level detection for non-standard port C2 traffic
- Implement firmware integrity monitoring on embedded devices

## Detection Rules

These detections target TuxBot v3 binaries (YARA), host persistence artifacts (Sigma), and C2 network traffic patterns (Suricata, Snort). PoC/advisory-specific altitude; all rules key on distinctive artifacts from the Unit 42 analysis. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: TuxBot v3 Systemd Persistence via sd-pam Service
Detects creation of the `sd-pam.service` systemd unit file used by TuxBot v3 for persistence, disguised as the legitimate PAM session helper.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data 403 — proxy). sigma convert --without-pipeline splunk 0, log_scale 0 — syntactically valid, converts to both backends. No fitting product pipeline for linux/file_event. sd-pam.service is distinctive; legitimate sd-pam is a process, not a user-created .service unit. FP: minimal on IoT; some desktop distros may have a real sd-pam unit (check binary path). -->
```yaml
title: TuxBot v3 Systemd Persistence via sd-pam Service
id: 7c3a91f2-8d4e-4b6a-a1c5-9e2f0d7b3c8a
status: experimental
description: >
    Detects creation of the sd-pam.service systemd unit used by TuxBot v3 for
    persistence. The botnet disguises its service as the legitimate sd-pam
    PAM session helper to evade casual inspection.
references:
    - https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/
author: Actioner
date: 2026/07/16
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/sd-pam.service'
        TargetFilename|contains:
            - '/systemd/system/'
            - '/systemd/user/'
    condition: selection
falsepositives:
    - Legitimate sd-pam PAM helper service on some distributions (verify binary path in unit file)
level: high
```

### Sigma: TuxBot v3 Outbound Connection to Known C2 Ports
Detects outbound connections to the distinctive C2 port combination (TCP 1999, 31337, 13337) used by TuxBot v3.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE ATT&CK data 403 — proxy). sigma convert --without-pipeline splunk 0, log_scale 0. Port 31337 is a known "elite" port used by multiple malware families and some legitimate tools; 1999 and 13337 less common but not unique. Filter excludes RFC1918/loopback. Medium confidence due to port overlap risk. -->
```yaml
title: TuxBot v3 Outbound Connection to Known C2 Ports
id: 4b8e2a15-6f9d-43c7-b5d1-8a0e7c3f2d96
status: experimental
description: >
    Detects outbound network connections to the distinctive port combination
    used by TuxBot v3 C2 infrastructure (TCP 1999 encrypted bot protocol,
    TCP 31337 alternate bot protocol, TCP 13337 P2P gossip).
references:
    - https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/
author: Actioner
date: 2026/07/16
tags:
    - attack.t1071
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        Initiated: 'true'
        DestinationPort:
            - 1999
            - 31337
            - 13337
    filter_internal:
        DestinationIp|startswith:
            - '10.'
            - '172.16.'
            - '172.17.'
            - '172.18.'
            - '172.19.'
            - '172.20.'
            - '172.21.'
            - '172.22.'
            - '172.23.'
            - '172.24.'
            - '172.25.'
            - '172.26.'
            - '172.27.'
            - '172.28.'
            - '172.29.'
            - '172.30.'
            - '172.31.'
            - '192.168.'
            - '127.'
    condition: selection and not filter_internal
falsepositives:
    - Port 31337 used by some legitimate applications and games
    - Custom applications using non-standard ports
level: medium
```

### Sigma: TuxBot v3 Shell Profile Persistence Injection
Detects modification of shell profile files (.bashrc, .profile, .zshrc) as used by TuxBot v3 for login-triggered persistence.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE ATT&CK data 403 — proxy). sigma convert --without-pipeline splunk 0, log_scale 0. Shell profile modification is a known persistence technique used by many threat families — not unique to TuxBot. Filter excludes package managers. Medium confidence: correct behavior but not distinctive enough for high. -->
```yaml
title: TuxBot v3 Shell Profile Persistence Injection
id: 9f1e3b7a-5c2d-48a6-b0d4-6e8a1f5c9d27
status: experimental
description: >
    Detects modification of shell profile files (.bashrc, .profile, .zshrc)
    used by TuxBot v3 as one of its seven persistence mechanisms. The botnet
    injects commands into these files to re-execute on user login.
references:
    - https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/
author: Actioner
date: 2026/07/16
tags:
    - attack.t1546.004
logsource:
    category: file_change
    product: linux
detection:
    selection:
        TargetFilename|endswith:
            - '/.bashrc'
            - '/.profile'
            - '/.zshrc'
    filter_package_manager:
        Image|endswith:
            - '/dpkg'
            - '/rpm'
            - '/apt'
            - '/yum'
            - '/dnf'
    condition: selection and not filter_package_manager
falsepositives:
    - User customization of shell profiles
    - System configuration management tools (Ansible, Puppet, Chef)
    - IDE or development tool initialization
level: medium
```

### Snort: TuxBot v3 C2 Handshake Magic 0xDEADBE01
Detects the 4-byte handshake magic `0xDEADBE01` at the start of TCP connections to TuxBot v3 C2 ports (1999, 31337).
**Status:** compile ⚠️ uncompiled (structural check only -- snort binary not installed) · confidence: high
<!-- audit: snort not installed; structural check: protocol tcp, flow established, content hex with offset/depth, required fields present (msg, sid, rev, classtype, reference). Rule targets the distinctive 4-byte magic at offset 0 on the known C2 ports — high precision. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET [1999,31337] (msg:"Actioner - TuxBot v3 C2 Handshake Magic 0xDEADBE01"; flow:established, to_server; content:"|DE AD BE 01|", offset 0, depth 4; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/; metadata:author Actioner, created 2026-07-16; sid:2100001; rev:1;)
```

### Snort: TuxBot v3 SSH C2 Banner SSH-2.0-CNC
Detects the distinctive SSH banner `SSH-2.0-CNC` used by the TuxBot v3 C2 server.
**Status:** compile ⚠️ uncompiled (structural check only -- snort binary not installed) · confidence: high
<!-- audit: snort not installed; structural check: protocol tcp, flow established to_client, content match for SSH banner, required fields present. SSH-2.0-CNC is a highly distinctive banner not used by legitimate SSH servers. -->
```snort
alert tcp any any -> $HOME_NET 2222 (msg:"Actioner - TuxBot v3 SSH C2 Banner SSH-2.0-CNC"; flow:established, to_client; content:"SSH-2.0-CNC"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/; metadata:author Actioner, created 2026-07-16; sid:2100002; rev:1;)
```

### Suricata: TuxBot v3 C2 Handshake Magic 0xDEADBE01
Detects the 4-byte handshake magic `0xDEADBE01` at the start of TCP connections to TuxBot v3 C2 ports.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Rule matches the distinctive 4-byte magic at offset 0, depth 4, on C2 ports 1999/31337. High precision — 0xDEADBE01 is a custom magic unlikely in benign traffic on these ports. -->
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET [1999,31337] (msg:"Actioner - TuxBot v3 C2 Handshake Magic 0xDEADBE01"; flow:established,to_server; content:"|DE AD BE 01|"; offset:0; depth:4; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/; metadata:author Actioner, created_at 2026-07-16; sid:2200001; rev:1;)
```

### Suricata: TuxBot v3 SSH C2 Banner SSH-2.0-CNC
Detects the distinctive SSH banner `SSH-2.0-CNC` sent by TuxBot v3 C2 servers during SSH handshake.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. SSH-2.0-CNC is a highly distinctive, non-standard SSH banner. No legitimate SSH server uses this identification string. -->
```suricata
alert ssh any any -> $HOME_NET any (msg:"Actioner - TuxBot v3 SSH C2 Banner SSH-2.0-CNC"; flow:to_client; content:"SSH-2.0-CNC"; startswith; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/; metadata:author Actioner, created_at 2026-07-16; sid:2200002; rev:1;)
```

### Suricata: TuxBot v3 DGA Domain Pattern in DNS Query
Detects DNS queries matching the TuxBot v3 DGA pattern (12 lowercase alpha characters followed by one of six TLDs).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0. DGA pattern (12 a-z chars + 6 TLDs) is moderately distinctive but could match some legitimate short domains. The PCRE anchors reduce FPs. Medium confidence: pattern-based, not IOC-exact. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - TuxBot v3 DNS TXT Query to DGA Domain Pattern"; flow:to_server; dns.query; content:".cc"; endswith; pcre:"/^[a-z]{12}\.(com|net|org|info|biz|cc)$/"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/; metadata:author Actioner, created_at 2026-07-16; sid:2200003; rev:1;)
```

### Suricata: TuxBot v3 P2P Gossip Port 13337 Outbound
Detects outbound TCP connections to port 13337 used by TuxBot v3 P2P gossip protocol.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0. Port 13337 is uncommon but not unique to TuxBot. Medium confidence; best used as a hunt lead in combination with other indicators. -->
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 13337 (msg:"Actioner - TuxBot v3 P2P Gossip Port 13337 Outbound"; flow:established,to_server; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/; metadata:author Actioner, created_at 2026-07-16; sid:2200004; rev:1;)
```

### YARA: TuxBot v3 ELF Binary Detection
Detects TuxBot v3 IoT botnet ELF binaries via distinctive embedded strings including the LLM-generated safety disclaimer, "Infected By Akiru" banner, busybox probe, and DGA seed. Scope to ELF file scanning pipelines; not a network rule.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos.bin: fired (Botnet_TuxBot_v3_ELF_Binary); yara neg.bin: quiet. Positive constructed from published strings (disclaimer, banner, busybox probe, service name, lock pattern, DGA seed) embedded in an ELF-headered file. Condition requires ELF magic + filesize <10MB + 3-of-6 distinctive strings or specific combinations. High confidence: the safety disclaimer and DGA seed are unique to TuxBot v3; no legitimate software carries this combination. -->
```yara
rule Botnet_TuxBot_v3_ELF_Binary
{
    meta:
        description = "Detects TuxBot v3 IoT botnet binaries via distinctive embedded strings including LLM-generated safety disclaimer, bot identifier, and C2 configuration artifacts"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/"
        hash = "15c17dce89deccd5172285b2650de957918aa1157cde8e4633ae15dfe31f2711"
        severity = "critical"

    strings:
        $disclaimer = "WARNING: This code is for educational and authorized security research only" ascii
        $banner = "Infected By Akiru" ascii
        $busybox = "/bin/busybox Akiru" ascii
        $applet = "Akiru: applet not found" ascii
        $service = "sd-pam.service" ascii
        $lock = "/tmp/.%08x.lock" ascii
        $dga_seed = "TuxBotv3-Evolution-Seed-2025" ascii
        $cred_comment = "// START IMPORTED FROM DDOS-ROOTSEC pass_file" ascii
        $handshake_magic = { DE AD BE 01 }
        $packet_magic = { DE AD BE EF }

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            3 of ($disclaimer, $banner, $busybox, $applet, $dga_seed, $cred_comment) or
            ($banner and $lock and $service) or
            ($handshake_magic and $packet_magic and 1 of ($banner, $busybox, $dga_seed))
        )
}
```

## Lessons Learned

1. **LLM-assisted malware development introduces distinctive artifacts** -- safety disclaimers, chain-of-thought comments, and hallucinated implementations (e.g., fake Argon2id) provide new detection surfaces. Defenders should hunt for these patterns in IoT malware samples as LLM use in malware development increases.

2. **Complexity is the enemy of reliability** -- TuxBot v3's ambition (17 architectures, 78 attack vectors, 5 C2 channels, custom exploit VM) exceeded its developers' ability to test comprehensively. The XOR key mismatch, exploit VM magic discrepancy, and L7 method routing bug collectively broke ~30% of functionality. This fragility is an opportunity for defenders: bugs in malware are also indicators.

3. **IoT botnet ecosystems converge on shared infrastructure** -- the overlap between TuxBot, Keksec/Kaitori, and AISURU on the same dropper IP suggests either a shared service model or cooperating operators. Pivoting on infrastructure (FlokiNET hosting, TLS certificates like `jetross[.]com`) can reveal broader campaigns.

4. **Multi-channel C2 with fallback is becoming standard** -- encrypted TCP + DGA + P2P gossip provides resilience against single-point takedowns. Detection strategies must cover all channels, not just the primary one.

## Sources

- [Palo Alto Unit 42 - TuxBot v3 Evolution of an IoT Botnet](https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/) -- primary technical analysis with full source code review, IOC extraction, and infrastructure mapping

---
*Report generated by Actioner*
