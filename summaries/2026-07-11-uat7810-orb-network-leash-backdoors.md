# Technical Analysis Report: UAT-7810 ORB Network with LONGLEASH/DOGLEASH/JARLEASH Backdoors (2026-07-11)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-11
Version: 1.0 (DRAFT)

## Executive Summary

UAT-7810 is a China-nexus APT group building Operational Relay Box (ORB) networks by compromising unpatched Ruckus and ASUS edge routers. Reported by [Cisco Talos](https://blog.talosintelligence.com/uat-7810/) on July 7, 2026, the group deploys a multi-tier implant ecosystem: LONGLEASH (a feature-rich reverse proxy/C2 relay with HTTP/DNS/SOCKS/ICMP tunneling), DOGLEASH (a passive TCP backdoor with command dispatch), and JARLEASH (a Java-based administration tool with web file management and FTP/SFTP capabilities). The compromised routers serve as relay infrastructure for secondary threat actors including UAT-5918, which targets critical infrastructure in Taiwan. The group exploits CVE-2020-22653, CVE-2020-22658, CVE-2023-25717 (Ruckus), and CVE-2025-2492 (ASUS AiCloud) for initial access. C2 infrastructure operates on non-standard ports (8088, 2222, 99) and uses a distinctive TLS certificate with "exploit" in all subject DN fields.

## Background: Operational Relay Box Networks and UAT-7810

Operational Relay Box (ORB) networks are purpose-built infrastructure layers where compromised edge devices (routers, IoT appliances) are repurposed as traffic relay nodes, obscuring the true origin of threat actor operations. By routing traffic through legitimate residential/enterprise IP space, ORB operators make attribution and network-level blocking significantly more difficult for defenders. UAT-7810 acts as an infrastructure provider, maintaining the ORB network for use by secondary Chinese APT groups. This division of labor -- where one group manages infrastructure while others conduct operations through it -- reflects the increasing specialization within China-nexus cyber operations.

The LEASH malware family represents an evolution: SHORTLEASH was the predecessor, with LONGLEASH being the current operational variant. The "ff-agent" codebase and "nz1.0" project designation indicate structured development practices. The malware targets MIPS architectures (multiple variants including MIPS32, MIPS32r2) as well as ARM (ARMv7) and x64, reflecting the diverse processor architectures found in targeted router hardware.

## Attack Chain

| Phase | Event |
|-------|-------|
| Reconnaissance | UAT-7810 identifies internet-facing Ruckus wireless routers and ASUS routers with AiCloud enabled running vulnerable firmware |
| Initial Access | Exploitation of CVE-2020-22653, CVE-2020-22658, CVE-2023-25717 (Ruckus) or CVE-2025-2492 (ASUS AiCloud) |
| Delivery | Shell scripts download architecture-appropriate malware binaries from attacker-controlled servers |
| Execution | Shell scripts execute LONGLEASH, DOGLEASH, or JARLEASH payloads on the compromised device |
| Persistence | iptables rule injection for firewall bypass; startup scripts for auto-execution; JARLEASH kills existing instances before respawning |
| C2 Establishment | LONGLEASH beacons to C2 servers on ports 8088/2222/99 using distinctive User-Agent; DOGLEASH binds to hardcoded port for passive listening |
| Relay Operations | Compromised devices function as ORB relay nodes, proxying traffic for secondary threat actors (e.g., UAT-5918) |
| Defense Evasion | LONGLEASH self-removes implant and traces upon detecting suspicious connections |

## Root Cause: Unpatched Edge Network Devices

The fundamental enabler for UAT-7810 operations is the widespread deployment of unpatched edge routers. The exploited vulnerabilities span a five-year window:

- **CVE-2020-22653 / CVE-2020-22658** (Ruckus): Remote code execution vulnerabilities disclosed in 2020, still present on unpatched devices
- **CVE-2023-25717** (Ruckus): Web management interface RCE (CVSS 9.8) exploitable without authentication
- **CVE-2025-2492** (ASUS AiCloud): Authentication bypass in ASUS router cloud service feature

These devices typically lack enterprise patch management, host-based detection, and logging infrastructure, making them ideal candidates for covert relay infrastructure.

## Technical Analysis of Malware Arsenal

### 1. LONGLEASH (Evolved SHORTLEASH)

LONGLEASH is the primary implant, compiled for MIPS processors using the Boost.Asio library for asynchronous I/O, with dependencies on Nanopb (protocol buffers), MbedTLS (cryptography), and musl libc.

**Internal designations:** "ff-agent" codebase, project "nz1.0"

**Architecture:**
- **Base module:** Logging and utility functions
- **Executor module:** Proxying and channel management (HTTP, DNS, SOCKS, TCP, ICMP, UDP)
- **Core module:** Authorization, node ID management, C2 coordination

**Capabilities:**
- Reverse shell to C2 servers
- Multi-protocol proxy server (HTTP, DNS, SOCKS, TCP, ICMP, UDP)
- Packet redirection (TCP, UDP, HTTP)
- SMTP server and client functionality
- Acts as intermediate C2 server for downstream nodes
- TLS certificate management via MbedTLS

**User-Agent string:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36`

**Self-defense:** Removes implant and all traces upon detecting suspicious or unauthorized connections, complicating forensic recovery.

### 2. DOGLEASH (Passive Backdoor)

DOGLEASH operates as a passive listener deployed via shell scripts that download the binary, inject iptables rules, and bind the implant to a target port.

**Deployment sequence:**
1. Shell script downloads architecture-specific binary
2. iptables rules added to permit inbound traffic on hardcoded port
3. Binary executes and binds to listening port

**Command protocol:** TCP connections are decoded using a hardcoded password. Command dispatch uses the following codes:

| Code | Function |
|------|----------|
| 0x2268, 0x2267 | Execute `/bin/sh -c <command>` |
| 0x2266 | Read file contents |
| 0x2271 | Rename/backup file |
| 0x2273, 0x2274 | Close socket |
| 0x3450 | Retrieve OS information (release, version, machine HW ID, node name) |

Additional command codes support execution of memory-resident code, enabling fileless operations.

### 3. JARLEASH (Java Administration Tool)

JARLEASH is a JAR-based backdoor providing a web-based administration interface for compromised devices.

**Capabilities:**
- Web-based file management interface
- FTP/SFTP server deployment
- Netcat server deployment for ad-hoc network access
- External configuration files with embedded defaults containing Simplified Chinese comments

**Startup behavior:** A startup script kills all existing JARLEASH instances before spawning a new container, ensuring single-instance execution and recovering from unstable states.

### 4. LEASHTEST (Development/Testing Binary)

Internal name "iot-test" -- a testing binary that validates MIPS platform functionality including thread creation/joining, TCP port binding, subprocess creation, async timers, and exception handling. Its presence on a device indicates active development/testing by UAT-7810 operators.

## Command and Control Infrastructure

**C2 Servers:**
- 194[.]233[.]92[.]26 (ports 8088, 2222)
- 217[.]15[.]160[.]247 (ports 8088, 2222, 99)
- 217[.]15[.]164[.]147 (ports 8088, 2222, 99)
- 95[.]182[.]100[.]231 (port 2222, Hong Kong)

**C2 URLs observed:**
- hxxp://217[.]15[.]160[.]247:8088/
- hxxp://217[.]15[.]160[.]247:2222/
- hxxp://217[.]15[.]160[.]247:99/
- hxxp://194[.]233[.]92[.]26:8088/
- hxxp://194[.]233[.]92[.]26:2222/
- hxxp://217[.]15[.]164[.]147:99/
- hxxp://217[.]15[.]164[.]147:8088/
- hxxp://217[.]15[.]164[.]147:2222/
- hxxp://95[.]182[.]100[.]231:2222/

**TLS Certificate:**
- SHA256 fingerprint: `c2ab9adaba93ff094b8f3fc37d906014d870582039d276b7bd03e6fd583d8a15`
- Subject DN: `C=exploit, ST=exploit, L=exploit, O=exploit, OU=exploit, CN=exploit`

The use of "exploit" in all certificate fields is a distinctive operational security failure that provides a reliable network fingerprint for detection.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: IP addresses use `[.]` for dots, URLs use `hxxp://` for scheme.

### File Hashes (SHA256)

| Hash | Description |
|------|-------------|
| 1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823 | LEASHTEST development binary |
| 755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f | LONGLEASH implant |
| e799d72929d7ccc7f6b6109742b8cc482838303207efc989543b6e1ca6d16e9c | JARLEASH startup script |
| 3b89d183eb014e29d9d0d4e45fc2b784a7fcfcf31dd48fd3bde30f8d956383d1 | JARLEASH configuration file |
| 324d95024fc8da5c92b5a1f4825aed5a2a91c9ca8fb6aa52abb332a4c9cf4257 | JARLEASH sample |
| bafba443170e54ef7fd431ce7f1b5e202719f3fd022e4ef70788904f574d2cdf | JARLEASH sample |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 194[.]233[.]92[.]26 | C2 server (ports 8088, 2222) |
| IP | 217[.]15[.]160[.]247 | C2 server (ports 8088, 2222, 99) |
| IP | 217[.]15[.]164[.]147 | C2 server (ports 8088, 2222, 99) |
| IP | 95[.]182[.]100[.]231 | C2 server (port 2222, Hong Kong) |
| TLS Fingerprint | c2ab9adaba93ff094b8f3fc37d906014d870582039d276b7bd03e6fd583d8a15 | C2 TLS certificate |
| TLS Subject DN | C=exploit, ST=exploit, L=exploit, O=exploit, OU=exploit, CN=exploit | C2 TLS certificate |

### Behavioral Indicators

- MIPS/ARM ELF binaries with internal strings "ff-agent" and "nz1.0"
- HTTP traffic with Chrome/122.0.6261.95 User-Agent from non-Windows devices (routers)
- TCP listeners on non-standard ports using hardcoded password authentication
- iptables rule injection following binary download and execution
- Shell scripts that kill existing Java processes before spawning new JAR-based services
- Outbound connections on ports 8088, 2222, or 99 from edge network devices

### Exploited Vulnerabilities

| CVE | Product | CVSS | Description |
|-----|---------|------|-------------|
| CVE-2020-22653 | Ruckus IoT Controller | 9.8 | Remote code execution |
| CVE-2020-22658 | Ruckus IoT Controller | 9.8 | Remote code execution |
| CVE-2023-25717 | Ruckus Wireless Admin | 9.8 | Unauthenticated RCE via web interface |
| CVE-2025-2492 | ASUS AiCloud | 9.2 | Authentication bypass |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of Ruckus/ASUS router vulnerabilities for initial access |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell scripts download and execute payloads; DOGLEASH executes /bin/sh -c |
| T1090.003 | Proxy: Multi-hop Proxy | ORB network relays traffic through chains of compromised routers |
| T1071.001 | Application Layer Protocol: Web Protocols | LONGLEASH HTTP C2 with spoofed User-Agent |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | TLS-encrypted C2 communications via MbedTLS |
| T1572 | Protocol Tunneling | DNS, ICMP, UDP tunneling capabilities in LONGLEASH |
| T1095 | Non-Application Layer Protocol | DOGLEASH custom TCP protocol with command codes |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | iptables rule injection to permit C2 traffic |
| T1070.004 | Indicator Removal: File Deletion | LONGLEASH self-removes upon detecting suspicious connections |
| T1082 | System Information Discovery | DOGLEASH 0x3450 command retrieves OS info |
| T1105 | Ingress Tool Transfer | Shell scripts download architecture-specific binaries from C2 |

## Impact Assessment

UAT-7810 represents a specialized infrastructure-building operation within the Chinese APT ecosystem. Key implications:

1. **Scale of compromise:** The targeting of commodity edge routers (Ruckus, ASUS) with years-old unpatched vulnerabilities suggests a potentially large number of compromised devices forming the ORB mesh
2. **Attribution obfuscation:** Traffic from secondary actors (UAT-5918) routing through residential/enterprise IP space makes network-level detection and attribution extremely difficult
3. **Critical infrastructure targeting:** The ORB network specifically supports operations against Taiwanese critical infrastructure, indicating strategic intent
4. **Multi-architecture capability:** Compiled variants for MIPS32, MIPS32r2, ARMv7, and x64 demonstrate investment in broad device compatibility
5. **Operational maturity:** The evolution from SHORTLEASH to LONGLEASH, structured codebase ("ff-agent", "nz1.0"), and testing infrastructure (LEASHTEST) indicate a well-resourced, disciplined development team

## Detection & Remediation

### Immediate Detection

1. Search network flow logs for connections to 194[.]233[.]92[.]26, 217[.]15[.]160[.]247, 217[.]15[.]164[.]147, or 95[.]182[.]100[.]231 on ports 8088, 2222, or 99
2. Search TLS inspection logs for certificates with subject DN containing "CN=exploit" or fingerprint c2ab9adaba93ff094b8f3fc37d906014d870582039d276b7bd03e6fd583d8a15
3. Monitor edge router management interfaces for unexpected iptables rule additions
4. Scan firmware on Ruckus and ASUS routers for ELF binaries containing "ff-agent" or "nz1.0"
5. Alert on HTTP traffic with Chrome/122.0.6261.95 User-Agent originating from non-desktop devices
6. Deploy existing Snort SIDs: 66433, 66432, 66430, 66431, 301493

### Remediation

1. **Patch immediately:** Apply firmware updates for CVE-2020-22653, CVE-2020-22658, CVE-2023-25717 (Ruckus) and CVE-2025-2492 (ASUS)
2. **Factory reset compromised devices:** Due to LONGLEASH self-deletion capabilities, firmware reflash is recommended over manual cleanup
3. **Block C2 infrastructure:** Add all four C2 IPs and associated ports to perimeter blocklists
4. **Block TLS fingerprint:** Configure TLS inspection to alert/block the exploit-subject certificate
5. **Audit iptables:** Review firewall rules on all Ruckus/ASUS devices for unauthorized port openings
6. **Disable unused services:** Disable AiCloud on ASUS routers if not required; disable web management on Ruckus devices from WAN side

### Long-Term Hardening

- Implement automated firmware patch management for edge network devices
- Deploy network-based anomaly detection for unusual outbound connections from router management VLANs
- Segment management interfaces behind VPN or jump hosts
- Enable logging on edge devices where supported and forward to SIEM
- Consider replacing end-of-life devices that no longer receive security updates
- Monitor for new ORB network IOCs as UAT-7810 infrastructure rotates

## Detection Rules

<!-- revision: v1.0 DRAFT — 14 rules (3 Sigma, 4 YARA, 5 Snort, 6 Suricata) targeting UAT-7810 LEASH family across network and file telemetry. Sigma check fails on ATT&CK data fetch (403 via proxy, not a rule issue); sigma convert validates all rules. YARA compiles clean. Snort/Suricata uncompiled (no compiler available). -->

These 18 rules (3 Sigma, 4 YARA, 5 Snort, 6 Suricata) target the UAT-7810 LEASH malware family and ORB network infrastructure across network and file telemetry. IOC-based network rules are high confidence but will rotate with infrastructure; TLS certificate and binary detection rules provide more durable detection. Compiles does not equal fires -- verify in your pipeline.

### Sigma: UAT-7810 LONGLEASH/DOGLEASH C2 Communication to Known Infrastructure

Detects network connections to UAT-7810 C2 IPs on the distinctive non-standard ports (8088, 2222, 99) used for LONGLEASH and DOGLEASH command-and-control.

**Status:** compile ✅ compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network: MITRE ATT&CK data fetch 403 via proxy -- not a rule issue). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Combination of specific C2 IPs and unusual port triplet is highly distinctive. FP risk: near-zero unless legitimate services run on these IPs. Infrastructure will rotate -- pair with TLS/behavioral rules. -->

```yaml
title: UAT-7810 LONGLEASH/DOGLEASH C2 Communication to Known Infrastructure
id: a1e2f3d4-5b6c-4a7d-8e9f-0a1b2c3d4e5f
status: experimental
description: >
    Detects network connections to UAT-7810 C2 infrastructure on distinctive
    non-standard ports (8088, 2222, 99) used by LONGLEASH and DOGLEASH backdoors
    for command-and-control communication within the ORB relay network.
references:
    - https://blog.talosintelligence.com/uat-7810/
author: Actioner
date: 2026/07/11
tags:
    - attack.t1090.003
    - attack.t1071.001
logsource:
    category: firewall
detection:
    selection_dst_ip:
        dst_ip:
            - '194.233.92.26'
            - '217.15.160.247'
            - '217.15.164.147'
            - '95.182.100.231'
    selection_port:
        dst_port:
            - 8088
            - 2222
            - 99
    condition: selection_dst_ip and selection_port
falsepositives:
    - None expected; combination of specific IPs and unusual ports is highly distinctive
level: critical
```

### Sigma: UAT-7810 TLS Certificate with Exploit Subject Fields

Detects TLS connections using the distinctive certificate where all subject DN fields are set to "exploit", a unique fingerprint for UAT-7810 C2 infrastructure.

**Status:** compile ✅ compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. All-exploit subject DN is an extreme outlier -- no legitimate CA would issue such a certificate. More durable than IP-based detection as cert may persist across infrastructure rotation. FP: security researchers generating test certs with "exploit" in fields -- extremely rare in production traffic. -->

```yaml
title: UAT-7810 TLS Certificate with Exploit Subject Fields
id: b2f3a4e5-6c7d-4b8e-9f0a-1b2c3d4e5f6a
status: experimental
description: >
    Detects TLS connections using the distinctive certificate observed in UAT-7810
    infrastructure where all subject DN fields (C, ST, L, O, OU, CN) are set to
    the value "exploit", a unique fingerprint for this threat actor's C2 infrastructure.
references:
    - https://blog.talosintelligence.com/uat-7810/
author: Actioner
date: 2026/07/11
tags:
    - attack.t1071.001
    - attack.t1573.002
logsource:
    category: network_connection
    product: zeek
detection:
    selection_tls_subject:
        tls.server.subject|contains|all:
            - 'CN=exploit'
            - 'O=exploit'
            - 'C=exploit'
    condition: selection_tls_subject
falsepositives:
    - Security testing using certificates with "exploit" in subject fields
level: critical
```

### Sigma: UAT-7810 LONGLEASH User-Agent to Known C2 Infrastructure

Detects HTTP traffic with the specific Chrome 122.0.6261.95 User-Agent string used by LONGLEASH directed at known UAT-7810 C2 IP addresses.

**Status:** compile ✅ compiles (convert) | Confidence: critical

<!-- audit: sigma check failed (network). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Double-anchored: specific UA AND specific destination IPs. FP: essentially zero -- requires both exact UA match and C2 IP destination. Note: UA alone would be high-FP as Chrome 122 is legitimate; the IP constraint eliminates this. -->

```yaml
title: UAT-7810 LONGLEASH User-Agent to Known C2 Infrastructure
id: c3a4b5e6-7d8e-4c9f-0a1b-2c3d4e5f6a7b
status: experimental
description: >
    Detects HTTP traffic containing the specific Chrome 122.0.6261.95 User-Agent
    string used by LONGLEASH malware for C2 communication, originating from
    non-Windows or edge device systems where this browser version is unexpected.
references:
    - https://blog.talosintelligence.com/uat-7810/
author: Actioner
date: 2026/07/11
tags:
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_ua:
        c-useragent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36'
    selection_dst:
        dst_ip:
            - '194.233.92.26'
            - '217.15.160.247'
            - '217.15.164.147'
            - '95.182.100.231'
    condition: selection_ua and selection_dst
falsepositives:
    - Legitimate Chrome 122.0.6261.95 users connecting to the same IPs (extremely unlikely)
level: critical
```

### YARA: UAT-7810 LONGLEASH Backdoor Binary

Detects LONGLEASH ELF binaries via internal project names ("ff-agent", "nz1.0") combined with the hardcoded User-Agent string or Boost/MbedTLS library signatures.

**Status:** compile ✅ yarac | Confidence: high

<!-- audit: yarac compiled clean, exit 0. Detection logic: ELF magic + (both project names) OR (UA + project name) OR (UA + 2 library strings). Sufficiently anchored to avoid FP on generic Boost-based ELF binaries. The dual project name condition is highly distinctive. -->

```yara
rule UAT7810_LONGLEASH_backdoor
{
    meta:
        description = "Detects LONGLEASH backdoor (aka ff-agent/nz1.0) used by UAT-7810 for ORB network C2 relay."
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f"
    strings:
        $project_name1 = "ff-agent" ascii
        $project_name2 = "nz1.0" ascii
        $user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36" ascii
        $lib_boost = "boost" ascii
        $lib_nanopb = "nanopb" ascii
        $lib_mbedtls = "mbedtls" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 10MB and
        (($project_name1 and $project_name2) or
         ($user_agent and any of ($project_name*)) or
         ($user_agent and 2 of ($lib_*)))
}
```

### YARA: UAT-7810 DOGLEASH Passive Backdoor

Detects DOGLEASH passive backdoor ELF binaries by matching the distinctive command dispatch code values (0x2268, 0x2267, 0x2266, 0x2271, 0x3450) combined with shell execution strings.

**Status:** compile ✅ yarac | Confidence: high

<!-- audit: yarac compiled clean, exit 0. Detection logic: ELF + /bin/sh + -c + 4 of 7 command codes. The command code values are 16-bit and could theoretically appear in benign binaries, but requiring 4+ codes PLUS shell strings in an ELF under 5MB narrows to DOGLEASH-like implants. -->

```yara
rule UAT7810_DOGLEASH_passive_backdoor
{
    meta:
        description = "Detects DOGLEASH passive backdoor used by UAT-7810."
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f"
    strings:
        $cmd_exec1 = { 68 22 }
        $cmd_exec2 = { 67 22 }
        $cmd_read  = { 66 22 }
        $cmd_rename = { 71 22 }
        $cmd_close1 = { 73 22 }
        $cmd_close2 = { 74 22 }
        $cmd_osinfo = { 50 34 }
        $shell_exec = "/bin/sh" ascii
        $shell_flag = "-c" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 5MB and
        $shell_exec and $shell_flag and 4 of ($cmd_*)
}
```

### YARA: UAT-7810 JARLEASH Java Backdoor

Detects JARLEASH JAR-based backdoor by matching JAR structure combined with capability indicators (FTP/SFTP server, file management, netcat).

**Status:** compile ✅ yarac | Confidence: medium

<!-- audit: yarac compiled clean, exit 0. Detection logic: ZIP/JAR magic + MANIFEST + .class + 2 capability strings. Medium confidence because individual capability strings (FtpServer, SftpServer) may appear in legitimate Java applications. The combination of multiple server capabilities in a single JAR raises confidence. -->

```yara
rule UAT7810_JARLEASH_java_backdoor
{
    meta:
        description = "Detects JARLEASH Java-based backdoor used by UAT-7810."
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "324d95024fc8da5c92b5a1f4825aed5a2a91c9ca8fb6aa52abb332a4c9cf4257"
    strings:
        $jar_magic = { 50 4B 03 04 }
        $class_ext = ".class" ascii
        $manifest = "META-INF/MANIFEST.MF" ascii
        $cap_ftp = "FtpServer" ascii
        $cap_sftp = "SftpServer" ascii
        $cap_netcat = "netcat" ascii nocase
        $cap_filemanager = "FileManager" ascii
        $chinese1 = { E4 B8 AD }
        $chinese2 = { E6 96 87 }
    condition:
        $jar_magic at 0 and $manifest and $class_ext and
        ((2 of ($cap_*)) or (1 of ($cap_*) and 1 of ($chinese*)))
}
```

### YARA: UAT-7810 LEASHTEST Development Binary

Detects the LEASHTEST ("iot-test") development binary used by UAT-7810 to validate MIPS platform capabilities before deploying operational implants.

**Status:** compile ✅ yarac | Confidence: high

<!-- audit: yarac compiled clean, exit 0. Detection logic: ELF + "iot-test" + project name + 3 test operation strings. The "iot-test" internal name combined with ff-agent/nz1.0 project references is highly distinctive. -->

```yara
rule UAT7810_LEASHTEST_dev_binary
{
    meta:
        description = "Detects LEASHTEST development/testing binary (iot-test) used by UAT-7810."
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823"
    strings:
        $internal_name = "iot-test" ascii
        $project1 = "ff-agent" ascii
        $project2 = "nz1.0" ascii
        $test_thread = "thread" ascii
        $test_tcp = "tcp" ascii
        $test_bind = "bind" ascii
        $test_async = "async" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 5MB and
        $internal_name and (1 of ($project*)) and 3 of ($test_*)
}
```

### Snort: UAT-7810 C2 Communication on Port 8088

Detects TCP connections to UAT-7810 C2 infrastructure on port 8088.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high

<!-- audit: no snort compiler available. Rule uses standard Snort 2.x syntax with dst_ip content match. Structural validation: msg, flow, classtype, reference, metadata, sid, rev all present. -->

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 8088 (msg:"Actioner - UAT-7810 LONGLEASH/DOGLEASH C2 Communication to Known Infrastructure on Port 8088"; flow:established,to_server; content:"GET"; http_method; dst_ip:194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created 2026-07-11, threat_actor UAT-7810; sid:2100201; rev:1;)
```

### Snort: UAT-7810 C2 Communication on Port 2222

Detects TCP connections to UAT-7810 C2 infrastructure on port 2222.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high

<!-- audit: no snort compiler available. Standard Snort 2.x rule targeting port 2222 C2 traffic. -->

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 2222 (msg:"Actioner - UAT-7810 LONGLEASH/DOGLEASH C2 Communication to Known Infrastructure on Port 2222"; flow:established,to_server; dst_ip:194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created 2026-07-11, threat_actor UAT-7810; sid:2100202; rev:1;)
```

### Snort: UAT-7810 C2 Communication on Port 99

Detects TCP connections to UAT-7810 C2 infrastructure on port 99.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high

<!-- audit: no snort compiler available. Standard Snort 2.x rule targeting port 99 C2 traffic. -->

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 99 (msg:"Actioner - UAT-7810 LONGLEASH/DOGLEASH C2 Communication to Known Infrastructure on Port 99"; flow:established,to_server; dst_ip:194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created 2026-07-11, threat_actor UAT-7810; sid:2100203; rev:1;)
```

### Snort: UAT-7810 LONGLEASH User-Agent Beacon to C2

Detects the Chrome 122.0.6261.95 User-Agent string in HTTP headers directed to known UAT-7810 C2 IPs.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high

<!-- audit: no snort compiler available. Content match on distinctive Chrome version substring; fast_pattern on most distinctive portion. -->

```
alert tcp $HOME_NET any -> $EXTERNAL_NET [99,2222,8088] (msg:"Actioner - UAT-7810 LONGLEASH C2 Beacon - Chrome 122.0.6261.95 User-Agent to Known C2"; flow:established,to_server; content:"Chrome/122.0.6261.95"; fast_pattern; http_header; dst_ip:194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created 2026-07-11, threat_actor UAT-7810; sid:2100204; rev:1;)
```

### Snort: UAT-7810 TLS Certificate with Exploit Subject DN

Detects TLS ServerHello containing the distinctive certificate with "exploit" in subject DN fields.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high

<!-- audit: no snort compiler available. Matches ASN.1 OID for CN (55 04 03) followed by "exploit" string within 20 bytes, then C OID (55 04 06) followed by "exploit". May require TLS inspection or raw packet analysis. -->

```
alert tcp any any -> any any (msg:"Actioner - UAT-7810 TLS Certificate with Exploit Subject DN Fields"; flow:established; content:"|55 04 03|"; content:"exploit"; within:20; content:"|55 04 06|"; content:"exploit"; within:20; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created 2026-07-11, threat_actor UAT-7810; sid:2100205; rev:1;)
```

### Suricata: UAT-7810 C2 Communication on Port 8088

Detects TCP connections to UAT-7810 C2 IP addresses on port 8088.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high

<!-- audit: no suricata compiler available. Uses Suricata IP group syntax for destination addresses. -->

```
alert tcp $HOME_NET any -> [194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231] 8088 (msg:"Actioner - UAT-7810 LONGLEASH/DOGLEASH C2 to Known Infrastructure Port 8088"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-11, threat_actor UAT-7810; sid:2200201; rev:1;)
```

### Suricata: UAT-7810 C2 Communication on Port 2222

Detects TCP connections to UAT-7810 C2 IP addresses on port 2222.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high

<!-- audit: no suricata compiler available. Uses Suricata IP group syntax for destination addresses. -->

```
alert tcp $HOME_NET any -> [194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231] 2222 (msg:"Actioner - UAT-7810 LONGLEASH/DOGLEASH C2 to Known Infrastructure Port 2222"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-11, threat_actor UAT-7810; sid:2200202; rev:1;)
```

### Suricata: UAT-7810 C2 Communication on Port 99

Detects TCP connections to UAT-7810 C2 IP addresses on port 99.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high

<!-- audit: no suricata compiler available. Uses Suricata IP group syntax for destination addresses. -->

```
alert tcp $HOME_NET any -> [194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231] 99 (msg:"Actioner - UAT-7810 LONGLEASH/DOGLEASH C2 to Known Infrastructure Port 99"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-11, threat_actor UAT-7810; sid:2200203; rev:1;)
```

### Suricata: UAT-7810 LONGLEASH HTTP User-Agent Beacon

Detects the Chrome 122.0.6261.95 User-Agent in HTTP traffic to UAT-7810 C2 infrastructure using Suricata's native HTTP inspection.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high

<!-- audit: no suricata compiler available. Uses Suricata http.user_agent sticky buffer for efficient UA matching. -->

```
alert http $HOME_NET any -> [194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231] any (msg:"Actioner - UAT-7810 LONGLEASH C2 Beacon - Chrome 122.0.6261.95 User-Agent"; flow:established,to_server; http.user_agent; content:"Chrome/122.0.6261.95"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-11, threat_actor UAT-7810; sid:2200204; rev:1;)
```

### Suricata: UAT-7810 TLS Certificate Subject DN Match

Detects TLS connections using certificates with "CN=exploit", "O=exploit", "C=exploit" in the subject using Suricata's native TLS inspection keywords.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high

<!-- audit: no suricata compiler available. Uses Suricata tls.cert_subject keyword for native TLS subject inspection without decryption. -->

```
alert tls any any -> any any (msg:"Actioner - UAT-7810 TLS Certificate with All-Exploit Subject DN"; flow:established; tls.cert_subject; content:"CN=exploit"; content:"O=exploit"; content:"C=exploit"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-11, threat_actor UAT-7810; sid:2200205; rev:1;)
```

### Suricata: UAT-7810 TLS Certificate SHA256 Fingerprint

Detects TLS connections matching the exact SHA256 certificate fingerprint observed in UAT-7810 C2 infrastructure.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: critical

<!-- audit: no suricata compiler available. Uses tls.cert_fingerprint for exact hash match -- highest confidence, zero FP. Note: requires Suricata TLS logging/inspection enabled. -->

```
alert tls any any -> any any (msg:"Actioner - UAT-7810 TLS Certificate SHA256 Fingerprint Match"; flow:established; tls.cert_fingerprint; content:"c2ab9adaba93ff094b8f3fc37d906014d870582039d276b7bd03e6fd583d8a15"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-11, threat_actor UAT-7810; sid:2200206; rev:1;)
```

## References

- [Cisco Talos: UAT-7810](https://blog.talosintelligence.com/uat-7810/) -- Primary source (2026-07-07)
- [NIST NVD: CVE-2023-25717](https://nvd.nist.gov/vuln/detail/CVE-2023-25717) -- Ruckus Wireless Admin RCE
- [NIST NVD: CVE-2025-2492](https://nvd.nist.gov/vuln/detail/CVE-2025-2492) -- ASUS AiCloud auth bypass
- [MITRE ATT&CK: Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/) -- ORB relay technique
- [MITRE ATT&CK: Application Layer Protocol (T1071.001)](https://attack.mitre.org/techniques/T1071/001/) -- HTTP C2 protocol
