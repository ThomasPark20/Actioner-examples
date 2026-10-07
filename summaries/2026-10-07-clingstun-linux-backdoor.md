# Technical Analysis Report: ClingSTUN Linux Backdoor (2026-10-07)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-07
Version: 1.0-DRAFT

## Executive Summary

ClingSTUN is a Linux back-connect proxy backdoor that exploits 35+ known vulnerabilities in IoT devices -- routers, DVRs, cameras, and network appliances -- to turn them into remotely controlled proxy nodes. First observed on September 5, 2026, and publicly reported by Fortinet FortiGuard Labs on October 5, 2026, the malware is notable for its abuse of legitimate public STUN (Session Traversal Utilities for NAT) servers to mask command-and-control traffic as normal VoIP/WebRTC NAT traversal. ClingSTUN embeds operator commands within STUN transaction ID fields and spoofs responses from trusted infrastructure such as Google's STUN servers (stun.l.google.com), making network-level detection particularly challenging.

The malware supports ARM, MIPS R3000, PowerPC, Intel 80386, and AMD x86-64 architectures. It includes eight hardcoded self-propagation exploits enabling worm-like spreading, disables hardware watchdog timers to prevent auto-reboots, hides itself by bind-mounting fake /proc entries over its own process metadata, and persists across reboots by modifying SysV/BusyBox init scripts. Its proxy and tunneling capabilities enable attackers to route traffic through compromised devices, and it has also been observed launching denial-of-service attacks.

## Background: IoT Device Ecosystem and STUN Protocol

The STUN protocol (RFC 5389) is a widely used standard that allows devices behind NAT to discover their public IP address and port mappings. It is fundamental to VoIP, WebRTC, and video conferencing services. Public STUN servers operated by Google, Mozilla, and others handle massive volumes of legitimate traffic daily.

ClingSTUN exploits this ubiquity: its C2 traffic consists of standard-format STUN binding requests and responses, making it nearly indistinguishable from normal multimedia NAT traversal traffic on the wire. Devices targeted by ClingSTUN span the IoT ecosystem, including routers (D-Link, TP-Link, Linksys, Hytec Inter, LB-LINK, EnGenius), DVRs (MVPower, TBK, KGUARD), cameras (AVTECH), and enterprise appliances (Ivanti Connect Secure). Many of these devices run unpatched firmware with known critical vulnerabilities dating back to 2014.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2014-2026 | CVEs exploited by ClingSTUN are published (CVE-2014-8361 through CVE-2026-87827) |
| 2026-09-05 | First observed ClingSTUN activity; spike in CVE-2021-35394 exploitation attempts |
| 2026-09-05 to 2026-10-05 | Three downloader generations (v1, v2, v3) observed with evolving capabilities |
| 2026-10-05 | Fortinet FortiGuard Labs publishes primary technical analysis |
| 2026-10-05 | The Hacker News, Infosecurity Magazine report on ClingSTUN/Cling Botnet |
| 2026-10-06 | SecurityAffairs coverage published |

## Root Cause: Exploitation of Unpatched IoT Vulnerabilities

ClingSTUN gains initial access by exploiting known command injection, code injection, and buffer overflow vulnerabilities in Internet-facing IoT devices. The primary exploitation vector is CVE-2021-35394 (CVSS 9.8), a critical remote code execution vulnerability in the Realtek Jungle SDK's "MP Daemon" (compiled as `UDPServer`), which affects devices running Realtek SDK v2.x through v3.4.14B.

The full list of initial access CVEs observed in delivery infrastructure includes: CVE-2019-7256, CVE-2019-17621, CVE-2021-35394, CVE-2021-36380, CVE-2022-26289, CVE-2022-35555, CVE-2022-36553, CVE-2023-1389, CVE-2023-46805, CVE-2024-7029, CVE-2024-10915, CVE-2024-21887, CVE-2024-23624, CVE-2024-23625, CVE-2024-32281, CVE-2024-32292, CVE-2024-32314, CVE-2024-35340, CVE-2024-46048, CVE-2025-34035, CVE-2025-67038, and CVE-2026-36356.

## Technical Analysis of the Malicious Payload

### 1. Initial Delivery and Downloader Stages

ClingSTUN's delivery has evolved through three downloader generations:

- **v1-v2**: The malware is delivered to `/tmp`, and a shell script (`wget.sh`) downloads and executes architecture-appropriate binaries for ARM, MIPS, PowerPC, x86, and x86-64.
- **v3**: Enhanced with aggressive process elimination -- scans `/proc/mounts` entries, unmounts non-proc filesystems, kills associated processes, and terminates any process with an executable in `/tmp`.

Download servers have rotated over time:
- `124.163.212[.]119` (initial period, CVE-2022-36553 exploitation)
- `222.223.152[.]97` (second period)
- `118.145.196[.]225` (current)

### 2. Installation and Persistence

Upon execution, ClingSTUN:

1. **Copies itself** to two hidden paths: `/root/.cling` and `/usr/local/bin/.cling`
2. **Binds TCP port 33957** as a single-instance mutex to prevent duplicate execution
3. **Modifies boot scripts** for persistence by appending to:
   - `/etc/inittab`
   - `/etc/init.d/rcS`
   - `/etc/rc.d/rc.boot`
4. **Replaces the `wget` binary** while preserving the original, achieving execution when legitimate processes invoke compromised commands
5. **Disables the hardware watchdog timer** by opening `/dev/watchdog` and `/dev/misc/watchdog` and issuing `ioctl` commands to prevent automatic device reboots

### 3. C2 Infrastructure: STUN Protocol Abuse

ClingSTUN's C2 mechanism follows a four-step process:

1. **STUN Binding Requests**: Sends standard 20-byte STUN binding requests every 5 seconds to public STUN servers. The transaction ID field is set to all zeros in initial requests.
2. **Port Mapping Discovery**: Records externally observed IP addresses and ports from STUN responses.
3. **Registration**: Sends a custom registration message to each STUN server containing mapped ports and an infection tag (e.g., `realtek.selfrep`).
4. **Command Polling**: Polls for UDP packets where operator commands are encoded in the STUN transaction ID field.

**STUN Server List** (24 in v2, reduced to 13 in v3 with stricter connection requirements):

5.39.72[.]109, 20.14.234[.]56, 64.131.63[.]217, 66.51.128[.]1, 74.125.250[.]129, 77.72.169[.]210, 77.72.169[.]211, 77.72.169[.]212, 77.72.169[.]213, 81.187.30[.]115, 82.113.193[.]63, 83.211.9[.]232, 85.17.88[.]164, 85.93.219[.]114, 139.162.62[.]29, 145.249.115[.]184, 154.73.34[.]8, 185.125.180[.]70, 207.38.82[.]134, 212.53.40[.]43, 212.227.67[.]33, 212.227.67[.]34, 216.93.246[.]18, 217.0.0[.]249

Of these, `145.249.115[.]184` is a modified/operator-controlled STUN server. Commands delivered via `74.125.250[.]129` (stun.l.google.com) appear as legitimate Google STUN traffic.

### 4. Malware Capabilities

- **Back-connect proxy**: Turns infected devices into remotely controlled proxy nodes
- **TCP tunnel spawning/termination**: Creates and manages TCP tunnels on command
- **Proxy setup/removal**: Dynamic proxy configuration
- **Denial-of-service attacks**: Observed targets include `112.151.157[.]222:8080` (South Korean ISP), `192.170.240[.]137:53` (University of Chicago), `23.81.40[.]193:25565` and `147.185.221[.]129:25565` (Minecraft servers)
- **Remote command execution**: Arbitrary command execution on infected devices
- **Self-propagation**: Worm-like spreading using eight hardcoded exploits
- **Competitor elimination**: Scans for and kills competing malware processes

**Self-propagation CVEs** (8 hardcoded):
- CVE-2014-8361 (Realtek SDK miniigd SOAP)
- CVE-2016-20016 (MVPower CCTV DVR)
- CVE-2016-10372 (Eir D1000 router)
- CVE-2023-26801 (LB-LINK routers)
- CVE-2023-41011 (China Mobile HG6543C4/FiberHome)
- CVE-2024-3721 (TBK DVR)
- CVE-2025-34037 (Linksys ttcp_ip)
- CVE-2026-87827 (KGUARD DVR)

### 5. Anti-Forensics / Evasion Techniques

- **Process metadata spoofing**: Copies selected files from `/proc/1/` to `/tmp` and bind-mounts `/tmp` over its own `/proc/<pid>` directory, making the malware appear as PID 1 (init/systemd) to tools like `ps` and `top`
- **Command-line argument clearing**: Overwrites its own `/proc/<pid>/cmdline` to hide execution arguments
- **Legitimate protocol abuse**: STUN traffic blends with normal VoIP/WebRTC communications
- **Hidden files**: Uses dot-prefixed filenames (`.cling`) for installation
- **Process scanning and killing**: Enumerates `/proc` directory, compares `/proc/<pid>/cmdline` with executable basename, kills competing processes

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `124.163.212[.]119`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | /root/.cling | dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a | ClingSTUN backdoor binary (primary install) |
| Linux | /usr/local/bin/.cling | a297eddfa7abea8d411afc0f150f8f6f30e470a77204de87e3b0815fa9bb8a84 | ClingSTUN backdoor binary (secondary install) |
| Linux | /etc/inittab | - | Modified for persistence |
| Linux | /etc/init.d/rcS | - | Modified for persistence |
| Linux | /etc/rc.d/rc.boot | - | Modified for persistence |

**All known sample hashes (SHA256):**

| SHA256 | Description |
|--------|-------------|
| dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a | ClingSTUN sample |
| a297eddfa7abea8d411afc0f150f8f6f30e470a77204de87e3b0815fa9bb8a84 | ClingSTUN sample |
| 4fbd61cb9181ebbc4fe9a6e59d3c346dc00001da48d66bd890556fc6fad22b07 | ClingSTUN sample |
| 121f2050e3c891b29565fd73451fff7ae60199c86eb8d79ec1eb1d9844578487 | ClingSTUN sample |
| 48f9b72ce72ab7087794650d6eef10135345088384fbde1482f1c74a02b80302 | ClingSTUN sample |
| e6e113783356446aef66e5296db45b244f318292af7cebc2a9bd76f095a95c4c | ClingSTUN sample |
| c1d8e2829ea63b9dc1cf2c3421a5093406adad4d6622e238376e78e908e0e6e8 | ClingSTUN sample |
| 48962b3893f2c8261e32e6b95ea7d463d145a529a8b2a6c987dd979454405c73 | ClingSTUN sample |
| 76692a23abe718b93e63edefd743971ec627c0cdf3778f856bd5ec88003deaa2 | ClingSTUN sample |
| ec199c78c11040fd3127887222fd75a85e5797bf96aa691a117fdd83dd663d81 | ClingSTUN sample |
| c0d8ffebfba969b1c1ca76bd9623bb623e9f95155c8ceca77d8fcc521435a497 | ClingSTUN sample |
| f49f45303cbfccee14ff193ac9608f860e6d616f08c0ecbef1ec44f7c863d7ec | ClingSTUN sample |
| 9391c6ad17aced1142607c0c623b18d86a7697cc483d204ffac94093e26b8068 | ClingSTUN sample |
| e4d12208789f36efc5a1ff765088fed95d6bb5972d1a804a4536fd42366797d4 | ClingSTUN sample |
| 284e5ec8748f99fd1b8c331b699a5fe5fd4448bbaae0347a940f427f931c4d14 | ClingSTUN sample |
| 6581bf37184bb2db899b9893064d39dd314ea691adf3281cc0aa7e0a31e5138a | ClingSTUN sample |
| 10d83c1748895361e07320f68d44d427b43cadd2cbffe0ab5e607ab03aec83da | ClingSTUN sample |
| 2ed54e0f988a62039abed88f6394eb1e3d5ed931f0183556055417fb08844ecf | ClingSTUN sample |
| b90640b392827b4f2d280f6cf67860862953331917d42df23e1653a92f2f98ad | ClingSTUN sample |
| dfba6008a2c828a9cb62342aec53006ae05a60cb8d4c41c3fa216fd727e8c6a3 | ClingSTUN sample |
| 5c4e263546fb21f8fe8732789a5b6583eaa8ae11ebeef099462a7c9bf50e022d | ClingSTUN sample |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 124.163.212[.]119 | C2 download server (initial period) |
| IP | 222.223.152[.]97 | C2 download server (second period) |
| IP | 118.145.196[.]225 | C2 download server (current) |
| IP | 145.249.115[.]184 | Modified/operator-controlled STUN server |
| IP | 74.125.250[.]129 | Legitimate Google STUN server abused for command delivery (stun.l.google.com) |
| Port | 33957/TCP | Single-instance mutex binding port |
| Port | 3478/UDP | STUN protocol communication port |

### Behavioral

- Processes binding TCP port 33957 (single-instance check)
- High-frequency (every 5 seconds) 20-byte UDP datagrams to port 3478 (STUN)
- STUN binding requests with all-zero transaction IDs
- Bind-mounting /tmp over /proc/<pid> directories
- Modification of /etc/inittab, /etc/init.d/rcS, /etc/rc.d/rc.boot
- Access to /dev/watchdog and /dev/misc/watchdog device files
- Infection tag strings: "realtek.selfrep"

### Fortinet AV Signatures

- BASH/Mirai.AEH!tr.dldr
- BASH/Dloader.P!tr
- Linux/Agent.BHT!tr

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of 35+ CVEs in IoT devices (Realtek, D-Link, TP-Link, Ivanti, etc.) for initial access |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell script downloaders (wget.sh) execute architecture-specific payloads |
| T1037.004 | Boot or Logon Initialization Scripts: RC Scripts | Appends to /etc/inittab, /etc/init.d/rcS, /etc/rc.d/rc.boot for persistence |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Bind-mounts /tmp over /proc/<pid> to impersonate PID 1 (init/systemd) |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | Installs as dot-prefixed hidden files (.cling) |
| T1014 | Rootkit | Process metadata spoofing via /proc bind-mount deception |
| T1071 | Application Layer Protocol | Abuses legitimate STUN protocol (UDP/3478) for C2 communication |
| T1090 | Proxy | Converts infected devices into back-connect proxy nodes |
| T1105 | Ingress Tool Transfer | Downloads architecture-specific payloads from rotating C2 servers |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Disables hardware watchdog timer via ioctl to /dev/watchdog; replaces wget binary |
| T1057 | Process Discovery | Enumerates /proc directory to identify and kill competing processes |
| T1499 | Endpoint Denial of Service | Observed launching DoS attacks against multiple targets |

## Impact Assessment

ClingSTUN presents a significant threat to IoT infrastructure. The breadth of targeted CVEs (35+ vulnerabilities spanning 2014-2026) means that a large population of devices running outdated firmware is at risk. The malware's multi-architecture support (ARM, MIPS, PowerPC, x86, x86-64) covers the vast majority of embedded Linux platforms. Its STUN-based C2 mechanism is particularly insidious because the traffic is structurally identical to legitimate NAT traversal traffic used by millions of devices daily, making network-level detection without deep behavioral analysis very difficult. The proxy and tunneling capabilities mean compromised devices can be used to route malicious traffic, obscure attacker origins, or serve as launchpads for further attacks.

## Detection & Remediation

### Immediate Detection

```bash
# Check for ClingSTUN binary files
ls -la /root/.cling /usr/local/bin/.cling 2>/dev/null

# Check for single-instance port binding
ss -tlnp | grep 33957

# Check for modifications to boot scripts (look for .cling references)
grep -l '.cling' /etc/inittab /etc/init.d/rcS /etc/rc.d/rc.boot 2>/dev/null

# Check for suspicious /proc bind mounts
mount | grep '/proc/' | grep '/tmp'

# Check for frequent STUN traffic (port 3478 UDP)
ss -unp | grep 3478

# Check for known C2 connections
ss -tnp | grep -E '124\.163\.212\.119|222\.223\.152\.97|118\.145\.196\.225|145\.249\.115\.184'
```

### Remediation

1. **Isolate** affected devices from the network immediately
2. **Kill** the ClingSTUN process: identify PID via `ss -tlnp | grep 33957`, then `kill -9 <pid>`
3. **Remove** malware binaries: `rm -f /root/.cling /usr/local/bin/.cling`
4. **Restore** boot scripts: remove `.cling` entries from `/etc/inittab`, `/etc/init.d/rcS`, `/etc/rc.d/rc.boot`
5. **Restore** original `wget` binary if it was replaced
6. **Unmount** fake /proc entries: `umount /proc/<pid>` for any suspicious bind mounts
7. **Patch** all known vulnerabilities, prioritizing CVE-2021-35394 (Realtek Jungle SDK)
8. **Reboot** device to verify clean startup
9. **Monitor** network traffic for STUN beaconing patterns for 72+ hours

### Long-Term Hardening

- Maintain a comprehensive IoT device inventory with firmware version tracking
- Implement automated firmware update pipelines where vendor-supported
- Deploy network segmentation to isolate IoT devices from critical infrastructure
- Block or monitor outbound UDP/3478 (STUN) traffic from IoT segments that should not use VoIP/WebRTC
- Implement egress filtering to restrict IoT device outbound connections to known-good destinations
- Deploy IDS/IPS rules for STUN protocol anomalies (zeroed transaction IDs, high-frequency beaconing)
- Decommission end-of-life devices that no longer receive security updates

## Detection Rules

The rules below cover ClingSTUN's file-system artifacts, persistence modifications, process evasion, C2 network connections, and STUN protocol abuse patterns. The primary caveat is that STUN is legitimate traffic in VoIP/WebRTC environments, so the behavioral STUN rules (beaconing frequency, zeroed transaction IDs) require environment-specific tuning to avoid false positives in organizations with heavy WebRTC usage.

### Sigma Rules

#### 1. ClingSTUN Backdoor File Creation

Detects creation of the ClingSTUN backdoor binary in its known installation paths.

compile: `sigma convert` to Splunk/LogScale -- both passed | confidence: **high**

```yaml
title: ClingSTUN Backdoor File Creation in Known Paths
id: 7a3e1f4b-9c2d-4e8a-b6f5-1d0e3c7a9b2f
status: experimental
description: >
    Detects creation of the ClingSTUN backdoor binary in its known installation
    paths /root/.cling and /usr/local/bin/.cling, as reported by Fortinet
    FortiGuard Labs analysis of the ClingSTUN Linux proxy backdoor.
references:
    - https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure
    - https://thehackernews.com/2026/10/realtek-jungle-sdk-exploit-attempts.html
author: Actioner
date: 2026-10-07
tags:
    - attack.t1036.005
    - attack.t1564.001
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename:
            - '/root/.cling'
            - '/usr/local/bin/.cling'
    condition: selection
falsepositives:
    - Unlikely; these paths are specific to ClingSTUN malware
level: critical
```

<!-- audit: compile-status=passed (sigma convert --without-pipeline -t splunk, -t log_scale). sigma check blocked by proxy (MITRE ATT&CK data fetch 403); structural validation via convert confirms valid YAML, detection logic, and logsource. IOC paths are real (not defanged). No FP evasion concerns at this specificity. -->

#### 2. ClingSTUN Boot Script Persistence Modification

Detects modification of SysV/BusyBox init scripts containing `.cling` references, consistent with ClingSTUN persistence. Requires file integrity monitoring that captures changed content (e.g., auditd with `-w` rules or Sysmon for Linux file_change events with content logging).

compile: `sigma convert` to Splunk/LogScale -- both passed | confidence: **medium**

```yaml
title: ClingSTUN Boot Script Persistence Modification with Cling Reference
id: 8b4f2e5c-0d3a-4f9b-c7e6-2a1f4d8b0c3e
status: experimental
description: >
    Detects modification of SysV/BusyBox init scripts that contain references
    to the .cling binary, consistent with ClingSTUN persistence. The malware
    appends entries referencing /root/.cling or /usr/local/bin/.cling to
    /etc/inittab, /etc/init.d/rcS, and /etc/rc.d/rc.boot to survive reboots.
references:
    - https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure
author: Actioner
date: 2026-10-07
tags:
    - attack.t1037.004
logsource:
    category: file_change
    product: linux
detection:
    selection_file:
        TargetFilename:
            - '/etc/inittab'
            - '/etc/init.d/rcS'
            - '/etc/rc.d/rc.boot'
    selection_content:
        Contents|contains: '.cling'
    condition: selection_file and selection_content
falsepositives:
    - Legitimate system configuration changes referencing similarly named binaries
    - If content-based matching is unavailable in your log source, fall back to file-modification-only detection with higher FP tolerance
level: high
```

<!-- audit: compile-status=passed. Added content-based filter for '.cling' to avoid firing on every init script modification (critic finding: altitude violation). Medium confidence because content-based file_change detection depends on FIM tool capabilities; not all FIM solutions expose file contents in logs. If content matching is unavailable, this rule will not fire. Not defanged. -->

#### 3. ClingSTUN Process Hiding via Proc Bind Mount

Detects the evasion technique where ClingSTUN bind-mounts /tmp over its own /proc entry.

compile: `sigma convert` to Splunk/LogScale -- both passed | confidence: **medium**

```yaml
title: ClingSTUN Process Information Hiding via Proc Bind Mount
id: 9c5e3f6d-1a4b-5e0c-d8f7-3b2e5a9c1d4f
status: experimental
description: >
    Detects ClingSTUN evasion technique where the malware copies process
    information from /proc/1/ to /tmp and bind-mounts /tmp over its own
    /proc/<pid> directory to masquerade as PID 1 (init/systemd).
references:
    - https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure
author: Actioner
date: 2026-10-07
tags:
    - attack.t1014
    - attack.t1036.005
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'mount'
            - '/tmp'
            - '/proc/'
    condition: selection
falsepositives:
    - Container runtime operations that bind-mount /proc
    - Debugging or forensics workflows mounting proc entries
level: high
```

<!-- audit: compile-status=passed. Behavioral detection via command-line pattern. Medium confidence because container runtimes may trigger similar patterns; tuning filter for container orchestrators recommended. Not defanged. -->

#### 4. ClingSTUN Watchdog Timer Disable

Detects processes accessing watchdog device files, used by ClingSTUN to prevent auto-reboots. Note: watchdog disabling is a general IoT malware indicator (also seen in Mirai variants), not exclusive to ClingSTUN; correlate with other ClingSTUN-specific rules for attribution.

compile: `sigma convert` to Splunk/LogScale -- both passed | confidence: **medium**

```yaml
title: ClingSTUN Watchdog Timer Disabling via Device Access
id: 0d6a4e7f-2b5c-6f1d-e9a8-4c3f6b0d2e5a
status: experimental
description: >
    Detects processes accessing /dev/watchdog or /dev/misc/watchdog device
    files, which ClingSTUN opens and sends ioctl commands to disable the
    hardware watchdog timer and prevent automatic device reboots.
references:
    - https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure
author: Actioner
date: 2026-10-07
tags:
    - attack.t1562.001
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'SYSCALL'
        syscall: 'openat'
    selection_path:
        type: 'PATH'
        name:
            - '/dev/watchdog'
            - '/dev/misc/watchdog'
    condition: selection and selection_path
falsepositives:
    - Legitimate watchdog management daemons (watchdog, systemd-watchdog)
    - Embedded system firmware update processes
level: medium
```

<!-- audit: compile-status=passed. Requires auditd configured with -w /dev/watchdog -p rwa. Medium confidence due to legitimate watchdog daemons; correlate with process name to reduce FPs. Not defanged. -->

#### 5. ClingSTUN C2 Infrastructure Connection

Detects outbound connections to known ClingSTUN C2 download servers and modified STUN server.

compile: `sigma convert` to Splunk/LogScale -- both passed | confidence: **high**

```yaml
title: ClingSTUN Network Connection to Known C2 Infrastructure
id: 1e7b5f8a-3c6d-7e2f-f0b9-5d4a7c1e3f6b
status: experimental
description: >
    Detects outbound network connections to known ClingSTUN C2 download
    servers and the modified STUN server used for command delivery, as
    identified by Fortinet FortiGuard Labs.
references:
    - https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure
author: Actioner
date: 2026-10-07
tags:
    - attack.t1071
    - attack.t1105
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestinationIp:
            - '124.163.212.119'
            - '222.223.152.97'
            - '118.145.196.225'
            - '145.249.115.184'
    condition: selection
falsepositives:
    - Unlikely; these are confirmed ClingSTUN infrastructure IPs
level: critical
```

<!-- audit: compile-status=passed. IOC-based detection; high confidence but time-limited as infrastructure rotates. IPs are real (not defanged) per logsource-encoding.md requirement. -->

#### 6. ClingSTUN Single-Instance Port Binding

Detects binding to TCP port 33957, used as a mutex by ClingSTUN.

compile: `sigma convert` to Splunk/LogScale -- both passed | confidence: **high**

```yaml
title: ClingSTUN Single Instance Check on Port 33957
id: 2f8c6a9b-4d7e-8f3a-a1c0-6e5b8d2f4a7c
status: experimental
description: >
    Detects a process binding to TCP port 33957, which ClingSTUN uses as a
    single-instance mutex to prevent multiple copies from running on the
    same infected device.
references:
    - https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure
    - https://thehackernews.com/2026/10/realtek-jungle-sdk-exploit-attempts.html
author: Actioner
date: 2026-10-07
tags:
    - attack.t1071
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestinationPort: 33957
    condition: selection
falsepositives:
    - Applications legitimately using port 33957
level: high
```

<!-- audit: compile-status=passed. Port-based detection; high confidence as 33957 is not a well-known port. Not defanged (numeric port). -->

### Snort 3 Rules

#### 7. ClingSTUN STUN Binding Request with Zeroed Transaction ID

Detects the ClingSTUN-specific STUN binding request pattern: exactly 20 bytes with all-zero transaction ID.

```
alert udp $HOME_NET any -> $EXTERNAL_NET 3478 (msg:"Actioner - ClingSTUN STUN Binding Request with Zeroed Transaction ID"; flow:to_server; content:"|00 01 00 00|", depth 4; content:"|21 12 A4 42|", distance 0, within 4; content:"|00 00 00 00 00 00 00 00 00 00 00 00|", distance 0, within 12; dsize:20; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure; metadata:author Actioner, created 2026-10-07; sid:2100010; rev:1;)
```

compile: uncompiled (structural check only) | confidence: **high**

<!-- audit: structural check: semicolons terminate all options, header protocol udp matches non-http payload inspection, dsize constraint matches 20-byte STUN binding request, STUN magic cookie 0x2112A442 correctly encoded, content chaining with distance/within is valid. No Suricata-only keywords used. -->

#### 8. ClingSTUN Known C2 Download Server Connection

Detects TCP connections to confirmed ClingSTUN C2 download servers.

```
alert tcp $HOME_NET any -> [124.163.212.119,222.223.152.97,118.145.196.225] any (msg:"Actioner - ClingSTUN Connection to Known C2 Download Server"; flow:established, to_server; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure; metadata:author Actioner, created 2026-10-07; sid:2100011; rev:1;)
```

compile: uncompiled (structural check only) | confidence: **high**

<!-- audit: IP-based IOC rule. Structurally valid: square-bracket IP list, flow established to_server, all required fields present. Time-limited as C2 infrastructure rotates. -->

#### 9. ClingSTUN High-Frequency STUN Beaconing

Detects high-frequency minimal STUN binding requests consistent with ClingSTUN's 5-second polling interval.

```
alert udp $HOME_NET any -> $EXTERNAL_NET 3478 (msg:"Actioner - High-Frequency STUN Binding Requests Potential ClingSTUN Beaconing"; flow:to_server; content:"|00 01|", depth 2; content:"|21 12 A4 42|", offset 4, depth 4; dsize:20; detection_filter:track by_src, count 10, seconds 60; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure; metadata:author Actioner, created 2026-10-07; sid:2100012; rev:1;)
```

compile: uncompiled (structural check only) | confidence: **medium**

<!-- audit: Behavioral detection via detection_filter threshold. 10 hits in 60 seconds matches ClingSTUN's 5-second beacon interval (~12 expected). May fire in heavy WebRTC environments; tune count/seconds thresholds per deployment. Structurally valid. -->

### Suricata Rules

#### 10. ClingSTUN Zeroed Transaction ID STUN Request

Detects ClingSTUN's signature STUN binding request with all-zero transaction ID field.

```
alert udp $HOME_NET any -> $EXTERNAL_NET 3478 (msg:"Actioner - ClingSTUN STUN Binding Request with Zeroed Transaction ID"; flow:to_server; content:"|00 01 00 00|"; depth:4; content:"|21 12 A4 42|"; distance:0; within:4; content:"|00 00 00 00 00 00 00 00 00 00 00 00|"; distance:0; within:12; dsize:20; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure; metadata:author Actioner, created_at 2026-10-07; sid:2100020; rev:1;)
```

compile: uncompiled (structural check only) | confidence: **high**

<!-- audit: Suricata syntax: colon after depth/distance/within (not comma), metadata uses created_at. Structurally valid. High confidence as zeroed 12-byte transaction ID in a 20-byte-only STUN request is highly anomalous. -->

#### 11. ClingSTUN Command Delivery via Spoofed Google STUN

Detects potential ClingSTUN command delivery appearing as Google STUN server responses from 74.125.250.129.

```
alert udp 74.125.250.129 3478 -> $HOME_NET any (msg:"Actioner - Potential ClingSTUN Command via Spoofed Google STUN Response"; flow:to_client; content:"|01 01|"; depth:2; content:"|21 12 A4 42|"; offset:4; depth:4; dsize:>20; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure; metadata:author Actioner, created_at 2026-10-07; sid:2100021; rev:1;)
```

compile: uncompiled (structural check only) | confidence: **medium**

<!-- audit: Detects STUN success responses (0x0101) from Google's STUN IP that are larger than standard. Medium confidence because legitimate STUN responses also come from this IP; correlate with zeroed-transaction-ID request rule for higher fidelity. Structurally valid. -->

#### 12. ClingSTUN Known C2 Download Server (Suricata)

Detects any IP traffic to confirmed ClingSTUN C2 download servers.

```
alert ip $HOME_NET any -> [124.163.212.119,222.223.152.97,118.145.196.225] any (msg:"Actioner - ClingSTUN Connection to Known C2 Download Server"; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure; metadata:author Actioner, created_at 2026-10-07; sid:2100022; rev:1;)
```

compile: uncompiled (structural check only) | confidence: **high**

<!-- audit: IOC-based IP rule. Structurally valid. IP list in square brackets, all required fields present. Time-limited. -->

#### 13. ClingSTUN Modified STUN Server Communication

Detects STUN traffic to the operator-controlled modified STUN server at 145.249.115.184.

```
alert udp $HOME_NET any -> 145.249.115.184 3478 (msg:"Actioner - ClingSTUN Communication with Modified STUN Server"; flow:to_server; content:"|00 01|"; depth:2; content:"|21 12 A4 42|"; offset:4; depth:4; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure; metadata:author Actioner, created_at 2026-10-07; sid:2100023; rev:1;)
```

compile: uncompiled (structural check only) | confidence: **high**

<!-- audit: IOC-based rule targeting operator-controlled infrastructure. STUN magic cookie verification reduces FPs. Structurally valid. -->

#### 14. ClingSTUN High-Frequency STUN Beaconing (Suricata)

Detects high-frequency 20-byte STUN binding requests consistent with ClingSTUN's 5-second polling.

```
alert udp $HOME_NET any -> $EXTERNAL_NET 3478 (msg:"Actioner - High-Frequency STUN Binding Requests Potential ClingSTUN Beaconing"; flow:to_server; content:"|00 01|"; depth:2; content:"|21 12 A4 42|"; offset:4; depth:4; dsize:20; threshold:type both, track by_src, count 10, seconds 60; classtype:trojan-activity; reference:url,www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure; metadata:author Actioner, created_at 2026-10-07; sid:2100024; rev:1;)
```

compile: uncompiled (structural check only) | confidence: **medium**

<!-- audit: Behavioral threshold rule using Suricata's threshold syntax. May fire in WebRTC-heavy environments. Structurally valid. -->

### YARA Rules

#### 15. ClingSTUN Backdoor String-Based Detection

Detects ClingSTUN ELF binaries via characteristic file paths, infection tags, and protocol markers.

compile: `yarac` -- passed (exit code 0) | confidence: **high**

```yara
import "hash"

rule Malware_ClingSTUN_Backdoor_Strings : backdoor iot
{
    meta:
        description = "Detects ClingSTUN Linux proxy backdoor via characteristic strings found in malware samples across ARM, MIPS, PowerPC, and x86 architectures"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure"
        hash = "dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $path1 = "/root/.cling" ascii
        $path2 = "/usr/local/bin/.cling" ascii
        $persist1 = "/etc/inittab" ascii
        $persist2 = "/etc/init.d/rcS" ascii
        $persist3 = "/etc/rc.d/rc.boot" ascii
        $wdog1 = "/dev/watchdog" ascii
        $wdog2 = "/dev/misc/watchdog" ascii
        $stun_magic = { 21 12 A4 42 }
        $tag1 = "realtek.selfrep" ascii
        $port = "33957" ascii
        $proc1 = "/proc/1/" ascii
        $proc2 = "/proc/mounts" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            (2 of ($path*)) or
            ($tag1 and $stun_magic) or
            (1 of ($path*) and 1 of ($persist*) and 1 of ($wdog*)) or
            ($tag1 and 2 of ($persist*)) or
            ($port and 1 of ($path*) and $stun_magic) or
            (1 of ($proc*) and 1 of ($path*) and 1 of ($wdog*))
        )
}
```

<!-- audit: yarac compilation passed (exit 0). ELF magic check (0x7F454C46 little-endian = 0x464C457F) gates on Linux binaries. Condition requires multiple correlated string families to avoid FPs. Infection tag "realtek.selfrep" is highly specific. All strings are real (not defanged). -->

#### 16. ClingSTUN Known Sample Hash Detection

Detects known ClingSTUN samples by SHA256 hash match using the YARA hash module.

compile: `yarac` -- passed (exit code 0) | confidence: **high**

```yara
rule Malware_ClingSTUN_Backdoor_Hashes : backdoor iot
{
    meta:
        description = "Detects known ClingSTUN malware samples by SHA256 hash via YARA import"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $elf = { 7F 45 4C 46 }

    condition:
        $elf at 0 and filesize < 5MB and
        (
            hash.sha256(0, filesize) == "dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a" or
            hash.sha256(0, filesize) == "a297eddfa7abea8d411afc0f150f8f6f30e470a77204de87e3b0815fa9bb8a84" or
            hash.sha256(0, filesize) == "4fbd61cb9181ebbc4fe9a6e59d3c346dc00001da48d66bd890556fc6fad22b07" or
            hash.sha256(0, filesize) == "121f2050e3c891b29565fd73451fff7ae60199c86eb8d79ec1eb1d9844578487" or
            hash.sha256(0, filesize) == "48f9b72ce72ab7087794650d6eef10135345088384fbde1482f1c74a02b80302" or
            hash.sha256(0, filesize) == "e6e113783356446aef66e5296db45b244f318292af7cebc2a9bd76f095a95c4c" or
            hash.sha256(0, filesize) == "c1d8e2829ea63b9dc1cf2c3421a5093406adad4d6622e238376e78e908e0e6e8" or
            hash.sha256(0, filesize) == "48962b3893f2c8261e32e6b95ea7d463d145a529a8b2a6c987dd979454405c73" or
            hash.sha256(0, filesize) == "76692a23abe718b93e63edefd743971ec627c0cdf3778f856bd5ec88003deaa2" or
            hash.sha256(0, filesize) == "ec199c78c11040fd3127887222fd75a85e5797bf96aa691a117fdd83dd663d81" or
            hash.sha256(0, filesize) == "c0d8ffebfba969b1c1ca76bd9623bb623e9f95155c8ceca77d8fcc521435a497" or
            hash.sha256(0, filesize) == "f49f45303cbfccee14ff193ac9608f860e6d616f08c0ecbef1ec44f7c863d7ec" or
            hash.sha256(0, filesize) == "9391c6ad17aced1142607c0c623b18d86a7697cc483d204ffac94093e26b8068" or
            hash.sha256(0, filesize) == "e4d12208789f36efc5a1ff765088fed95d6bb5972d1a804a4536fd42366797d4" or
            hash.sha256(0, filesize) == "284e5ec8748f99fd1b8c331b699a5fe5fd4448bbaae0347a940f427f931c4d14" or
            hash.sha256(0, filesize) == "6581bf37184bb2db899b9893064d39dd314ea691adf3281cc0aa7e0a31e5138a" or
            hash.sha256(0, filesize) == "10d83c1748895361e07320f68d44d427b43cadd2cbffe0ab5e607ab03aec83da" or
            hash.sha256(0, filesize) == "2ed54e0f988a62039abed88f6394eb1e3d5ed931f0183556055417fb08844ecf" or
            hash.sha256(0, filesize) == "b90640b392827b4f2d280f6cf67860862953331917d42df23e1653a92f2f98ad" or
            hash.sha256(0, filesize) == "dfba6008a2c828a9cb62342aec53006ae05a60cb8d4c41c3fa216fd727e8c6a3" or
            hash.sha256(0, filesize) == "5c4e263546fb21f8fe8732789a5b6583eaa8ae11ebeef099462a7c9bf50e022d"
        )
}
```

<!-- audit: yarac compilation passed (exit 0). Hash-based detection is definitive but has zero coverage of new variants. 21 known sample hashes from Fortinet report. ELF gate and filesize constraint optimize scanning performance. hash module import is at file scope. -->

## Lessons Learned

1. **Legitimate protocol abuse is the new frontier**: ClingSTUN demonstrates that threat actors are increasingly embedding C2 communications within legitimate, widely-used protocols (STUN/WebRTC) rather than custom protocols. Defenders need deep protocol inspection capabilities and behavioral baselines for "normal" STUN traffic patterns in their environment.

2. **IoT vulnerability debt is compounding**: The exploit chain spans CVEs from 2014 through 2026, with many devices still unpatched against vulnerabilities disclosed years ago. The supply chain impact of SDK-level vulnerabilities like CVE-2021-35394 (Realtek Jungle SDK) means one flaw affects hundreds of downstream device models across dozens of manufacturers.

3. **Egress monitoring for IoT is not optional**: Most organizations lack visibility into outbound traffic from IoT devices. ClingSTUN's proxy and tunneling capabilities mean a compromised IoT device is not just a risk to itself but becomes infrastructure for the attacker. Network segmentation and egress filtering for IoT segments should be a baseline security requirement.

## Sources

- [Fortinet FortiGuard Labs -- ClingSTUN Analysis](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure) -- primary technical analysis by Vincent Li; source of all IOCs, CVE lists, and TTP details
- [The Hacker News -- Realtek Jungle SDK Exploit Attempts Deliver Cling Botnet](https://thehackernews.com/2026/10/realtek-jungle-sdk-exploit-attempts.html) -- detailed technical reporting with C2 infrastructure, STUN server list, and exploitation CVEs
- [SecurityAffairs -- ClingSTUN Linux Backdoor Abuses Public STUN Infrastructure](https://securityaffairs.com/200450/uncategorized/clingstun-linux-backdoor-abuses-public-stun-infrastructure.html) -- supplementary reporting on targeted vendors and capabilities
- [NVD -- CVE-2021-35394](https://nvd.nist.gov/vuln/detail/CVE-2021-35394) -- Realtek Jungle SDK RCE vulnerability details; listed in CISA Known Exploited Vulnerabilities catalog

---
*Report generated by Actioner*
