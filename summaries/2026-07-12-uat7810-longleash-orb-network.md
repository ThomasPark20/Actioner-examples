# Technical Analysis Report: UAT-7810 LONGLEASH / DOGLEASH / JARLEASH ORB Network Campaign (2026-07-12)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-12
Version: 1.0

## Executive Summary

UAT-7810 is a China-nexus threat actor operating as a specialized infrastructure provider for the broader Chinese APT ecosystem. Cisco Talos disclosed on July 7, 2026, that the group has developed and deployed three custom malware families -- LONGLEASH, DOGLEASH, and JARLEASH -- along with one testing utility (LEASHTEST), to compromise internet-facing networking devices (Ruckus wireless routers, ASUS AiCloud routers) and build Operational Relay Box (ORB) networks. These ORBs serve as anonymization relays for secondary threat actors, including UAT-5918, enabling them to proxy attack traffic through legitimate regional infrastructure and evade attribution.

LONGLEASH represents a significant capability upgrade from its predecessor SHORTLEASH, adding multi-protocol proxy support (HTTP, DNS, SOCKS, TCP, ICMP, UDP), reverse shell access, SMTP server/client capabilities, TLS/PKI management, and self-removal on tamper detection. DOGLEASH provides a lightweight passive backdoor with arbitrary shellcode execution. JARLEASH is a Java-based administrative backdoor with file management, FTP/SFTP, and netcat capabilities. The group exploits known n-day vulnerabilities in Ruckus routers (CVE-2020-22653, CVE-2020-22658, CVE-2023-25717) and ASUS AiCloud routers (CVE-2025-2492). Four C2 IPs and a distinctive TLS certificate with all fields set to "exploit" provide high-fidelity network indicators.

## Background: Operational Relay Box (ORB) Networks

Operational Relay Box (ORB) networks are purpose-built infrastructure composed of compromised networking devices -- primarily routers and IoT devices -- that serve as proxy relays for advanced persistent threat operations. By routing malicious traffic through geographically distributed legitimate devices, ORB networks allow downstream APT groups to disguise the true origin of their he attacks, complicate forensic attribution, and blend into normal network traffic patterns. UAT-7810 functions as the infrastructure provisioning arm, while groups like UAT-5918 consume this infrastructure for their own campaigns against high-value targets. The targeting of edge networking devices (routers, wireless access points) is strategic: these devices often run minimal operating systems with limited logging, infrequent patching, and no endpoint detection capability, making them ideal long-term relay points.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2020 | Ruckus vulnerabilities CVE-2020-22653 and CVE-2020-22658 publicly disclosed |
| 2023-02 | CVE-2023-25717 (Ruckus) disclosed; exploitation begins |
| 2025 | UAT-7810 begins compromising Ruckus routers using n-day exploits; ORB network construction ramps up |
| 2025-04 | CVE-2025-2492 (ASUS AiCloud) disclosed |
| Early 2026 | UAT-7810 expands targeting to ASUS AiCloud routers via CVE-2025-2492 |
| 2026-07-07 | Cisco Talos publicly discloses UAT-7810 campaign, LONGLEASH, DOGLEASH, JARLEASH, and LEASHTEST |

## Root Cause: N-Day Vulnerability Exploitation in Networking Devices

UAT-7810 gains initial access exclusively through exploitation of known, unpatched vulnerabilities in internet-facing networking devices:

- **CVE-2020-22653 / CVE-2020-22658** (Ruckus): Remote code execution vulnerabilities in Ruckus wireless router web management interfaces. Despite being disclosed in 2020, many devices remain unpatched due to end-of-life status or operational neglect.
- **CVE-2023-25717** (Ruckus): Additional Ruckus router vulnerability enabling unauthenticated remote code execution through the web management interface (`/forms/doLogin` endpoint).
- **CVE-2025-2492** (ASUS AiCloud): Vulnerability in ASUS router AiCloud functionality enabling unauthorized access and code execution.

The attack chain follows a consistent pattern: exploit the vulnerability, download a shell script from attacker infrastructure, modify iptables rules to allow inbound TCP traffic on the backdoor port, then execute the DOGLEASH or LONGLEASH listener.

## Technical Analysis of the Malicious Payload

### 1. DOGLEASH -- Passive Linux Backdoor

DOGLEASH is a C-based Linux backdoor compiled for multiple architectures (MIPS variants, ARM, x64). It operates as a passive listener, binding to a hardcoded TCP port and authenticating incoming connections using a hardcoded password for decryption. Over 70 distinct variants have been identified across at least four C2 servers.

**Deployment method:** A shell script downloads the DOGLEASH binary, adds iptables rules to permit TCP traffic on the listener port, and executes the backdoor.

**Command dispatch codes:**

| Code | Function |
|------|----------|
| 0x2268, 0x2267 | Execute command via `/bin/sh -c` |
| 0x2266 | Read file contents |
| 0x2271 | Rename file (used for backup creation) |
| 0x2273, 0x2274 | Close socket listener |
| 0x3450 | Collect OS information (release, version, machine hardware ID, node name) |
| (default) | Execute arbitrary code in memory |

### 2. LONGLEASH -- Advanced Multi-Protocol Backdoor (ff-agent / nz1.0)

LONGLEASH is an updated variant of the previously documented SHORTLEASH backdoor framework. Its internal project name is "nz1.0" and the binary is identified as "ff-agent." It is compiled against four key libraries: Boost.Asio (asynchronous network I/O), Nanopb (protobuf message processing), MbedTLS (TLS/x509 certificate management), and musl libc.

**Architecture:** Three major components:
- **Base layer:** Logging, utilities, Base58/Base64 encoding-decoding
- **Executor:** Proxying, channel setup, connection management, authorization, message routing, tunnel management, self-removal logic
- **Core:** Authorization, node identification, HTTP encoding, protobuf message processing, SHA checksumming, task management, security functions

**Capabilities:**
- Reverse shell to C2
- Multi-protocol proxying: HTTP, DNS, SOCKS, TCP, ICMP, UDP
- Packet redirection (TCP, UDP, HTTP)
- SMTP server and client functionality
- TLS and PKI management (x509 certificates)
- Client authorization and message routing
- Network tunnel setup and management
- Intermediate C2 server (forwards commands from origin C2 to peer nodes)
- Self-removal and trace cleanup on tamper detection

**User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36`

### 3. JARLEASH -- Java-Based Administrative Backdoor

JARLEASH is a JAR-packaged Java backdoor deployed on at least one of the C2 servers for administrative purposes. Its configuration file contains comments in Simplified Chinese, reinforcing the China-nexus attribution.

**Capabilities:**
- Web-based file management interface
- FTP server
- SFTP server
- Netcat server deployment (binds to specified IP and port)

**Deployment:** A startup script kills any existing JARLEASH instances before spawning a new Java container, ensuring single-instance execution.

### 4. LEASHTEST -- MIPS Platform Validation Utility

LEASHTEST (internal name "iot-test") is a non-malicious MIPS ELF binary used by UAT-7810 to validate platform capabilities before deploying operational implants. It tests thread creation/joining, TCP port binding (acceptor), child process creation, asynchronous timer creation, "Hello World" output, and exception handling. Its presence on a device is a strong indicator of compromise by UAT-7810.

### 5. C2 Infrastructure

**C2 IP addresses:**
- 194.233.92[.]26
- 217.15.160[.]247
- 217.15.164[.]147
- 95.182.100[.]231 (Hong Kong-based)

**C2 URLs and port assignments:**

| URL | Port Function |
|-----|---------------|
| hxxp://217.15.160[.]247:8088/ | HTTP C2 |
| hxxp://217.15.160[.]247:2222/ | HTTP C2 |
| hxxp://217.15.160[.]247:99/ | TLS server |
| hxxp://194.233.92[.]26:8088/ | HTTP C2 |
| hxxp://194.233.92[.]26:2222/ | HTTP C2 |
| hxxp://217.15.164[.]147:99/ | TLS server |
| hxxp://217.15.164[.]147:8088/ | HTTP C2 |
| hxxp://217.15.164[.]147:2222/ | HTTP C2 |
| hxxp://95.182.100[.]231:2222/ | HTTP C2 |

**TLS certificate fingerprint:** `c2ab9adaba93ff094b8f3fc37d906014d870582039d276b7bd03e6fd583d8a15`

**TLS certificate subject (all fields set to "exploit"):**
```
C=exploit, ST=exploit, L=exploit, O=exploit, OU=exploit, CN=exploit
```

This certificate was observed on 194.233.92[.]26 and 217.15.164[.]147.

### 6. Anti-Forensics / Evasion Techniques

- **Self-removal:** LONGLEASH contains functionality to remove the implant and all traces from the device if suspicious connections or tampering are detected.
- **User-Agent spoofing:** LONGLEASH uses a Windows Chrome User-Agent string on Linux networking devices to blend with normal web traffic.
- **Process deduplication:** JARLEASH startup script kills existing instances before re-launching, preventing duplicate process detection.
- **Device selection:** Targeting of edge networking devices with minimal logging, no EDR, and infrequent patching minimizes detection surface.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxp://` replacing `http://`
> - IP addresses: `[.]` replacing dots (e.g., `194.233.92[.]26`)

### File System

| Malware | Hash (SHA256) | Description |
|---------|---------------|-------------|
| LEASHTEST | `1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823` | MIPS testing binary (iot-test) |
| LONGLEASH | `755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f` | Multi-protocol backdoor (ff-agent/nz1.0) |
| JARLEASH | `324d95024fc8da5c92b5a1f4825aed5a2a91c9ca8fb6aa52abb332a4c9cf4257` | JAR binary |
| JARLEASH | `bafba443170e54ef7fd431ce7f1b5e202719f3fd022e4ef70788904f574d2cdf` | JAR binary |
| JARLEASH | `e799d72929d7ccc7f6b6109742b8cc482838303207efc989543b6e1ca6d16e9c` | Startup script |
| JARLEASH | `3b89d183eb014e29d9d0d4e45fc2b784a7fcfcf31dd48fd3bde30f8d956383d1` | Configuration file |
| DOGLEASH | `604b53f87d6c070bf387e80c70a6df8d272fa3fc143148d41f13e59d52ab1f13` | Linux backdoor variant |
| DOGLEASH | `c92541f273eeb576d39235d0a5c6f18f2574b132a1022598edfa38065783ab98` | Linux backdoor variant |
| DOGLEASH | `29c7fccc6ef8cbfe4da9a169c7c74bacaea1fb515a1fddef91ab1b1522f76e4c` | Linux backdoor variant |
| DOGLEASH | 70+ additional variants (see Cisco Talos report for full list) | Multiple arch variants |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 194.233.92[.]26 | C2 server (ports 8088, 2222) |
| IP | 217.15.160[.]247 | C2 server (ports 99, 8088, 2222) |
| IP | 217.15.164[.]147 | C2 server (ports 99, 8088, 2222) |
| IP | 95.182.100[.]231 | C2 server (port 2222), Hong Kong |
| TLS Fingerprint | `c2ab9adaba93ff094b8f3fc37d906014d870582039d276b7bd03e6fd583d8a15` | C2 TLS cert fingerprint |
| TLS Subject | `C=exploit, ST=exploit, L=exploit, O=exploit, OU=exploit, CN=exploit` | C2 TLS cert subject |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36` | LONGLEASH C2 beacon |

### Behavioral

- Iptables rule additions allowing inbound TCP on non-standard ports on router/embedded devices
- MIPS/ARM/x64 ELF binaries binding to hardcoded TCP ports as listeners
- Outbound HTTP connections on ports 99, 2222, 8088 from networking devices
- Chrome Windows User-Agent strings originating from Linux embedded/IoT devices
- TLS certificates with all subject fields set to "exploit"
- Protobuf-encoded messages with Base58/Base64 encoding in HTTP traffic

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of CVE-2020-22653, CVE-2020-22658, CVE-2023-25717 (Ruckus), CVE-2025-2492 (ASUS AiCloud) |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | DOGLEASH executes commands via `/bin/sh -c`; deployment via shell scripts |
| T1071.001 | Application Layer Protocol: Web Protocols | LONGLEASH C2 over HTTP on ports 8088, 2222 |
| T1090 | Proxy | LONGLEASH provides HTTP, DNS, SOCKS, TCP, ICMP, UDP proxy functionality for ORB relay |
| T1090.002 | Proxy: External Proxy | ORB network relays traffic for secondary actors (UAT-5918) |
| T1571 | Non-Standard Port | C2 on ports 99, 2222, 8088 |
| T1105 | Ingress Tool Transfer | Shell scripts download DOGLEASH/LONGLEASH binaries from C2 |
| T1082 | System Information Discovery | DOGLEASH 0x3450 command collects OS release, version, machine HW ID, nodename |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | LONGLEASH TLS/PKI management via MbedTLS |
| T1036 | Masquerading | Windows Chrome User-Agent on Linux IoT devices to masquerade as legitimate browser traffic |
| T1070 | Indicator Removal | LONGLEASH self-removal on tamper detection |

## Impact Assessment

**Breadth:** The targeting of widely-deployed Ruckus and ASUS router families through known vulnerabilities exposes a large attack surface. Any organization running unpatched Ruckus (CVE-2020-22653/22658, CVE-2023-25717) or ASUS AiCloud (CVE-2025-2492) devices faces potential compromise.

**Depth:** Compromised devices serve as invisible relay infrastructure for downstream APT operations, meaning the ultimate victim organizations may have no direct relationship with the compromised device. The ORB architecture creates a layered threat where initial compromise enables entirely separate attack campaigns.

**Stealth:** Edge networking devices provide minimal visibility -- no EDR, limited logging, infrequent inspection. LONGLEASH's self-removal capability and User-Agent spoofing further reduce detection probability. The 70+ DOGLEASH variants suggest rapid iteration and customization per target.

## Detection & Remediation

### Immediate Detection

```bash
# Check for connections to known C2 IPs from network devices
# On network monitoring/firewall:
# Look for traffic to 194.233.92.26, 217.15.160.247, 217.15.164.147, 95.182.100.231
# on ports 99, 2222, 8088

# On suspected Ruckus/ASUS devices (if shell access available):
netstat -tlnp | grep -E ':(99|2222|8088)\b'
iptables -L -n | grep -E '(ACCEPT|DROP).*dpt:(99|2222|8088)'

# Check for suspicious ELF binaries
find / -type f -executable -newer /etc/passwd 2>/dev/null | xargs file | grep ELF

# Check for Java processes (JARLEASH)
ps aux | grep -i java
```

### Remediation

1. **Immediate:** Block C2 IPs (194.233.92[.]26, 217.15.160[.]247, 217.15.164[.]147, 95.182.100[.]231) at the perimeter firewall on all ports.
2. **Containment:** Isolate any Ruckus or ASUS router showing signs of compromise; capture forensic image before wiping.
3. **Eradication:** Factory reset and re-image affected networking devices with latest firmware.
4. **Patching:** Apply patches for CVE-2020-22653, CVE-2020-22658, CVE-2023-25717 (Ruckus) and CVE-2025-2492 (ASUS) immediately.
5. **Monitoring:** Deploy the detection rules below; monitor for TLS certificates with "exploit" in all subject fields.

### Long-Term Hardening

- Implement automated firmware update processes for networking infrastructure.
- Restrict management interface access to dedicated management VLANs; never expose router admin panels to the internet.
- Deploy network detection for non-standard port usage on edge devices.
- Consider replacing end-of-life networking equipment that no longer receives security updates.
- Implement TLS certificate inspection at network boundaries to detect anomalous certificate subjects.

## Detection Rules

The rules below cover network-level C2 communication (IP/port matching), TLS certificate fingerprinting, LONGLEASH User-Agent detection, exploit URI patterns for initial access, and file-level YARA signatures for all four LEASH-family tools. Two rules targeting ASUS AiCloud CVE-2025-2492 (one Sigma, one Suricata) were removed during review because POST requests to `/aicloud` are normal AiCloud functionality with no payload-level pattern to distinguish exploitation from legitimate use. The primary detection gap is on-device behavioral detection, which is limited by the minimal logging capabilities of embedded networking devices. Existing Cisco Talos Snort SIDs 66430-66433 and 301493 provide additional coverage.

### Sigma

#### 1. Network Connection to UAT-7810 C2 Infrastructure

Detects outbound connections from monitored endpoints to the four known UAT-7810 C2 IPs on their characteristic ports (99, 2222, 8088).
- Compile: sigma convert pass -- Confidence: high

<!-- audit: IOC-anchored on 4 C2 IPs + 3 ports. Will need updating if infrastructure rotates. No FP concern at this specificity level. Real IPs used (not defanged) per logsource-encoding spec. -->

```yaml
title: Network Connection to UAT-7810 C2 Infrastructure
id: 6e171ec6-fb61-405d-b576-d489237dc83d
status: experimental
description: >
    Detects outbound network connections to known UAT-7810 C2 IP addresses
    on characteristic ports (99, 2222, 8088) used for LONGLEASH and DOGLEASH
    command and control communications.
references:
    - https://blog.talosintelligence.com/uat-7810/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1071.001
    - attack.t1571
logsource:
    category: network_connection
detection:
    selection_ip:
        DestinationIp:
            - '194.233.92.26'
            - '217.15.160.247'
            - '217.15.164.147'
            - '95.182.100.231'
    selection_port:
        DestinationPort:
            - 99
            - 2222
            - 8088
    condition: selection_ip and selection_port
falsepositives:
    - Legitimate services hosted on these IPs (unlikely given port combination)
level: critical
```

#### 2. LONGLEASH User-Agent String to Non-Standard Port

Detects the hardcoded Chrome/122.0.6261.95 User-Agent in proxy logs when paired with the non-standard C2 ports, which is anomalous since this UA originates from Linux embedded devices.
- Compile: sigma convert pass -- Confidence: high

<!-- audit: UA string is Chrome 122 specific build (6261.95). Paired with non-standard ports to reduce FP. Chrome 122 is outdated by July 2026, reducing legitimate overlap further. Proxy log field names (c-useragent, dst_port) are common but pipeline-dependent. -->

```yaml
title: LONGLEASH User-Agent String to Non-Standard Port
id: 622f5c4b-4903-4c01-bca7-4f8e1a2fd1a9
status: experimental
description: >
    Detects HTTP requests using the specific Chrome/122.0.6261.95 User-Agent
    string hardcoded in LONGLEASH when destined for non-standard HTTP ports
    (99, 2222, 8088) characteristic of UAT-7810 C2 infrastructure.
references:
    - https://blog.talosintelligence.com/uat-7810/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1071.001
    - attack.t1036
logsource:
    category: proxy
detection:
    selection_ua:
        c-useragent|contains: 'Chrome/122.0.6261.95'
    selection_port:
        dst_port:
            - 99
            - 2222
            - 8088
    condition: selection_ua and selection_port
falsepositives:
    - Legitimate Chrome 122 traffic to non-standard ports (rare)
level: high
```

#### 3. Ruckus Router Known CVE URI Path Access (Supplementary)

Supplementary awareness rule that detects web requests to Ruckus management URI paths associated with CVE-2020-22653, CVE-2020-22658, and CVE-2023-25717. These paths are also used during normal administrator access, so this rule serves as a low-confidence enrichment signal rather than a standalone alert.
- Compile: sigma convert pass -- Confidence: low

<!-- audit: URI paths are common Ruckus admin endpoints. FPs WILL fire from legitimate admin access; this is a supplementary awareness rule, not a UAT-7810-specific detection. Downgraded to low confidence and medium level per review. webserver category requires web server logs from Ruckus devices or a reverse proxy in front of them. -->

```yaml
title: Ruckus Router Known CVE URI Path Access (Supplementary)
id: d3f11c2f-61df-4811-8c00-6691060ba4c4
status: experimental
description: >
    Supplementary awareness rule detecting web requests to Ruckus router
    management URI paths associated with CVE-2020-22653, CVE-2020-22658,
    and CVE-2023-25717. These paths are not specific to UAT-7810 exploitation
    and WILL fire on legitimate administrator access. Use as an enrichment
    signal in combination with other UAT-7810 indicators, not as a standalone alert.
references:
    - https://blog.talosintelligence.com/uat-7810/
    - https://nvd.nist.gov/vuln/detail/CVE-2023-25717
author: Actioner
date: 2026-07-12
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '/admin/_cmdstat.jsp'
            - '/forms/doLogin'
            - '/admin/wlan_config.jsp'
    condition: selection
falsepositives:
    - Legitimate Ruckus admin panel access WILL trigger this rule -- filter by source IP against known admin ranges or use only as a correlation signal
level: medium
```

#### 4. Firewall Traffic to UAT-7810 C2 Infrastructure

Detects firewall log entries for any traffic to the four known UAT-7810 C2 IPs, regardless of port.
- Compile: sigma convert pass -- Confidence: high

<!-- audit: Broadest IOC-based rule - matches any traffic to C2 IPs regardless of port. Higher FP potential than rule 1 since no port filter, but provides catch-all coverage. IPs will age out as infrastructure rotates. -->

```yaml
title: Firewall Traffic to UAT-7810 C2 Infrastructure
id: 2d531cf3-bb15-48bf-90f6-26d5b476fa14
status: experimental
description: >
    Detects firewall log entries showing traffic to known UAT-7810 C2 IP
    addresses. These IPs host LONGLEASH and DOGLEASH C2 servers on ports
    99, 2222, and 8088.
references:
    - https://blog.talosintelligence.com/uat-7810/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1071.001
    - attack.t1571
logsource:
    category: firewall
detection:
    selection:
        dst_ip:
            - '194.233.92.26'
            - '217.15.160.247'
            - '217.15.164.147'
            - '95.182.100.231'
    condition: selection
falsepositives:
    - Legitimate services hosted at these IPs (verify with threat intelligence)
level: high
```

### YARA

#### 5. APT_UAT7810_DOGLEASH_Backdoor

Detects DOGLEASH ELF backdoor binaries via the combination of shell execution pattern and characteristic command dispatch codes (0x2268, 0x2267, 0x2266, 0x2271, 0x3450).
- Compile: yarac pass -- Confidence: high

<!-- audit: ELF magic check + /bin/sh -c string + 3-of-7 hex command codes + 2-of-4 OS info strings. Command codes are 2-byte sequences that could appear by chance in arbitrary data; requiring 3+ plus the shell string and OS info strings significantly reduces FPs. Tested against known hash 604b53f87d6c070bf387e80c70a6df8d272fa3fc143148d41f13e59d52ab1f13. -->

```yara
rule APT_UAT7810_DOGLEASH_Backdoor
{
    meta:
        description = "Detects DOGLEASH backdoor used by UAT-7810 via command codes and shell execution pattern"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "604b53f87d6c070bf387e80c70a6df8d272fa3fc143148d41f13e59d52ab1f13"
        severity = "critical"

    strings:
        $cmd_exec = "/bin/sh -c" ascii
        $hex_cmd1 = { 22 68 }
        $hex_cmd2 = { 22 67 }
        $hex_cmd3 = { 22 66 }
        $hex_cmd4 = { 22 71 }
        $hex_cmd5 = { 22 73 }
        $hex_cmd6 = { 22 74 }
        $hex_cmd7 = { 34 50 }
        $os_info1 = "release" ascii
        $os_info2 = "version" ascii
        $os_info3 = "machine" ascii
        $os_info4 = "nodename" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        $cmd_exec and
        (3 of ($hex_cmd*) and 2 of ($os_info*))
}
```

#### 6. APT_UAT7810_LONGLEASH_Backdoor

Detects LONGLEASH ELF binaries via project identifiers (nz1.0, ff-agent), linked libraries (Boost, Nanopb, MbedTLS), and the hardcoded Chrome/122 User-Agent.
- Compile: yarac pass -- Confidence: high

<!-- audit: Three detection paths: (1) project name + 2 libs, (2) specific UA + lib, (3) project name + encoding + protocols. Project strings "nz1.0" and "ff-agent" are strong anchors. Library name strings (boost, nanopb, mbedtls) may appear in other Boost-using ELF binaries but the combination with project names or the specific Chrome UA build is highly specific. -->

```yara
rule APT_UAT7810_LONGLEASH_Backdoor
{
    meta:
        description = "Detects LONGLEASH backdoor (ff-agent/nz1.0) used by UAT-7810 for ORB network operations"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f"
        severity = "critical"

    strings:
        $proj1 = "nz1.0" ascii
        $proj2 = "ff-agent" ascii
        $ua = "Chrome/122.0.6261.95" ascii
        $lib1 = "boost" ascii nocase
        $lib2 = "nanopb" ascii
        $lib3 = "mbedtls" ascii nocase
        $func1 = "Base58" ascii
        $func2 = "Base64" ascii
        $proto1 = "SOCKS" ascii
        $proto2 = "SMTP" ascii
        $proto3 = "ICMP" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            (1 of ($proj*) and 2 of ($lib*)) or
            ($ua and 1 of ($lib*)) or
            (1 of ($proj*) and 1 of ($func*) and 2 of ($proto*))
        )
}
```

#### 7. APT_UAT7810_JARLEASH_Backdoor

Detects JARLEASH JAR-packaged Java backdoor via the combination of ZIP/JAR magic bytes, Java class markers, and server capability strings (FTP, SFTP, Netcat).
- Compile: yarac pass -- Confidence: medium

<!-- audit: ZIP magic (PK\x03\x04) at offset 0 + META-INF + .class confirms Java JAR. FTP/SFTP/Netcat string combinations narrow to administrative backdoors. May FP on legitimate Java applications bundling FTP + SFTP libraries; the combination of all three server types in a JAR is uncommon in benign software. -->

```yara
rule APT_UAT7810_JARLEASH_Backdoor
{
    meta:
        description = "Detects JARLEASH Java-based backdoor used by UAT-7810 for file management and remote access"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "324d95024fc8da5c92b5a1f4825aed5a2a91c9ca8fb6aa52abb332a4c9cf4257"
        severity = "high"

    strings:
        $pk = { 50 4B 03 04 }
        $java1 = "META-INF" ascii
        $java2 = ".class" ascii
        $ftp = "FtpServer" ascii
        $sftp = "SftpServer" ascii
        $sftp2 = "SFTP" ascii
        $netcat = "netcat" ascii nocase
        $nc = "Netcat" ascii

    condition:
        $pk at 0 and
        filesize < 50MB and
        all of ($java*) and
        (
            ($ftp and 1 of ($sftp*)) or
            ($ftp and 1 of ($nc, $netcat)) or
            (1 of ($sftp*) and 1 of ($nc, $netcat))
        )
}
```

#### 8. APT_UAT7810_LEASHTEST_MIPS_Testing

Detects the LEASHTEST MIPS testing binary via the "iot-test" internal name combined with Boost library usage and platform test function strings.
- Compile: yarac pass -- Confidence: medium

<!-- audit: "iot-test" string is the anchor. Combined with Boost and 3-of-5 platform test strings (Hello World, thread, acceptor, async, child). Downgraded to medium confidence: generic strings (thread, acceptor, async, child) are present in many Boost.Asio applications; the "iot-test" project name provides the primary discrimination. -->

```yara
rule APT_UAT7810_LEASHTEST_MIPS_Testing
{
    meta:
        description = "Detects LEASHTEST MIPS testing binary (iot-test) indicating UAT-7810 compromise"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823"
        severity = "medium"

    strings:
        $name = "iot-test" ascii
        $hw = "Hello World" ascii
        $thread = "thread" ascii
        $acceptor = "acceptor" ascii
        $timer = "async" ascii
        $child = "child" ascii
        $boost = "boost" ascii nocase

    condition:
        uint32(0) == 0x464C457F and
        filesize < 2MB and
        $name and
        $boost and
        3 of ($hw, $thread, $acceptor, $timer, $child)
}
```

#### 9. APT_UAT7810_TLS_Certificate_Exploit

Detects TLS certificate files with all distinguished name fields set to "exploit," a distinctive marker of UAT-7810 C2 infrastructure.
- Compile: yarac pass -- Confidence: high

<!-- audit: Certificate files with 4+ fields containing "=exploit" is an extremely specific pattern. No known legitimate CA or self-signed certificate convention uses "exploit" across C/ST/L/O/OU/CN. Filesize cap at 10KB targets certificate files specifically. -->

```yara
rule APT_UAT7810_TLS_Certificate_Exploit
{
    meta:
        description = "Detects TLS certificates with all fields set to 'exploit' as used by UAT-7810 C2 infrastructure"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        severity = "high"

    strings:
        $cn = "CN=exploit" ascii
        $o = "O=exploit" ascii
        $ou = "OU=exploit" ascii
        $c = "C=exploit" ascii
        $st = "ST=exploit" ascii
        $l = "L=exploit" ascii

    condition:
        filesize < 10KB and
        4 of them
}
```

### Snort 3

#### 10. UAT-7810 Outbound C2 Traffic

Detects outbound TCP connections to the four known UAT-7810 C2 IPs on their operational ports.
- Structural validation: pass (uncompiled) -- Confidence: high

<!-- audit: IP-anchored rule, bidirectional not needed since to_server captures the outbound connection establishment. Port list [99,2222,8088] matches all known C2 port assignments. Will need IP updates as infrastructure changes. -->

```
alert tcp $HOME_NET any -> [194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231] [99,2222,8088] (msg:"Actioner - UAT-7810 Outbound C2 Traffic to Known Infrastructure"; flow:established, to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created 2026-07-12; sid:2100201; rev:1;)
```

#### 11. UAT-7810 Inbound C2 Traffic

Detects inbound connections from known UAT-7810 C2 infrastructure to the protected network (DOGLEASH passive listener model where C2 initiates TCP to the compromised device).
- Structural validation: pass (uncompiled) -- Confidence: high

<!-- audit: Reverse direction coverage of rule 10. Catches C2 server-initiated connections (relevant for DOGLEASH passive listener model where C2 connects to the implant). flow:to_server is correct: C2 IPs are the source initiating the connection, $HOME_NET is the "server" (listener). -->

```
alert tcp [194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231] any -> $HOME_NET any (msg:"Actioner - UAT-7810 Inbound Traffic from Known C2 Infrastructure"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created 2026-07-12; sid:2100202; rev:1;)
```

#### 12. LONGLEASH C2 Beacon User-Agent to Non-Standard Port

Detects the specific Chrome/122.0.6261.95 User-Agent string in HTTP headers on non-standard C2 ports (99, 2222, 8088), hardcoded in LONGLEASH C2 communications.
- Structural validation: pass (uncompiled) -- Confidence: medium

<!-- audit: Uses http_header sticky buffer (Snort 3 correct, not dot-notation). Chrome/122.0.6261.95 is a specific build string. Port restriction [99,2222,8088] added to match Suricata rule 15 and align with title. By July 2026, Chrome 122 is significantly outdated, reducing legitimate traffic overlap. Downgraded to medium confidence as UA alone is not a definitive indicator. -->

```
alert http $HOME_NET any -> $EXTERNAL_NET [99,2222,8088] (msg:"Actioner - LONGLEASH C2 Beacon Chrome/122 UA to Non-Standard Port"; flow:established,to_server; http_header; content:"Chrome/122.0.6261.95"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created 2026-07-12; sid:2100203; rev:1;)
```

### Suricata

#### 13. UAT-7810 C2 Traffic to Known Infrastructure

Detects TCP connections to UAT-7810 C2 IPs on operational ports.
- Compile: suricata -T pass -- Confidence: high

<!-- audit: Mirror of Snort rule 10 for Suricata. Same IP/port logic. Uses tcp protocol (no app-layer buffers needed for IP-only matching). -->

```
alert tcp $HOME_NET any -> [194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231] [99,2222,8088] (msg:"Actioner - UAT-7810 C2 Traffic to Known Infrastructure IP and Port"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-12; sid:2200101; rev:1;)
```

#### 14. UAT-7810 TLS Certificate with Exploit Subject Fields

Detects TLS connections presenting certificates with the distinctive "C=exploit" and "CN=exploit" subject fields used by UAT-7810 infrastructure.
- Compile: suricata -T pass -- Confidence: high

<!-- audit: Uses tls.cert_subject sticky buffer (Suricata-only, correctly not used in Snort rules). Two content matches on C=exploit and CN=exploit within the subject field. Extremely low FP -- no legitimate certificates use "exploit" as the country code and common name. -->

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-7810 TLS Certificate with Exploit Subject Fields"; flow:established; tls.cert_subject; content:"C=exploit"; content:"CN=exploit"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-12; sid:2200102; rev:1;)
```

#### 15. LONGLEASH C2 Beacon with Chrome/122 User-Agent to Non-Standard Port

Detects LONGLEASH HTTP C2 beacons using the hardcoded Chrome/122 User-Agent string on non-standard ports.
- Compile: suricata -T pass -- Confidence: high

<!-- audit: Uses http.user_agent sticky buffer (Suricata dot-notation). Port restriction to [99,2222,8088] in rule header reduces FPs from legitimate Chrome 122 traffic. fast_pattern on the UA string for efficient matching. -->

```
alert http $HOME_NET any -> $EXTERNAL_NET [99,2222,8088] (msg:"Actioner - LONGLEASH C2 Beacon with Chrome/122 User-Agent to Non-Standard Port"; flow:established,to_server; http.user_agent; content:"Chrome/122.0.6261.95"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-12; sid:2200103; rev:1;)
```

#### 16. Ruckus Router CVE-2023-25717 doLogin Access (Supplementary)

Detects HTTP requests targeting the Ruckus `/forms/doLogin` endpoint associated with CVE-2023-25717. This endpoint is also used during normal administrator logins, so this rule serves as a low-confidence enrichment signal.
- Compile: suricata -T pass -- Confidence: low

<!-- audit: Uses http.uri sticky buffer. /forms/doLogin is the specific CVE-2023-25717 exploitation path but is also used for legitimate Ruckus admin logins. Downgraded to low confidence per review. Deploy with source IP filtering where possible. -->

```
alert http any any -> $HOME_NET any (msg:"Actioner - Ruckus Router CVE-2023-25717 doLogin Access (Supplementary)"; flow:established,to_server; http.uri; content:"/forms/doLogin"; fast_pattern; classtype:web-application-attack; reference:url,blog.talosintelligence.com/uat-7810/; reference:cve,2023-25717; metadata:author Actioner, created_at 2026-07-12; sid:2200104; rev:1;)
```

#### 17. Inbound Connection from UAT-7810 C2 Infrastructure

Detects inbound connections from known UAT-7810 C2 infrastructure, covering DOGLEASH's passive listener model where the C2 server initiates connections to compromised devices.
- Compile: suricata -T pass -- Confidence: high

<!-- audit: Reverse direction rule covering C2-to-implant connections. Relevant for DOGLEASH passive backdoor model. flow:to_server is correct: C2 IPs are the source initiating the connection, $HOME_NET is the "server" (listener). No port restriction on source since C2 may connect from ephemeral ports. -->

```
alert tcp [194.233.92.26,217.15.160.247,217.15.164.147,95.182.100.231] any -> $HOME_NET any (msg:"Actioner - Inbound Connection from UAT-7810 C2 Infrastructure"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-12; sid:2200106; rev:1;)
```

### Existing Vendor Rules

Cisco Talos has released the following Snort SIDs for this threat:
- **SID 66430, 66431, 66432, 66433** -- DOGLEASH/LONGLEASH detection rules
- **SID 301493** -- Additional coverage

ClamAV signatures:
- `Unix.Backdoor.Agent-10059997-1` through `Unix.Backdoor.Agent-10059999-0`
- `Java.Backdoor.Agent-10060000-0`
- `Unix.Backdoor.Agent_mips32-10060001-0` through `Unix.Backdoor.Agent_mips32el-10060006-0`

## Lessons Learned

This campaign demonstrates the strategic value of edge networking devices as persistent, low-visibility infrastructure for state-sponsored threat actors. UAT-7810's specialization as an infrastructure provider -- building ORB networks for consumption by other APT groups -- reflects an increasingly modular and service-oriented model within the Chinese APT ecosystem. The exploitation of vulnerabilities dating back to 2020 underscores that patch latency on networking infrastructure remains a critical and systemic weakness. Organizations must treat routers and wireless access points as first-class security assets requiring the same patch management discipline applied to servers and endpoints. The development of LEASHTEST as a dedicated platform validation tool suggests a mature development lifecycle with quality assurance processes, indicating this is an operationally sophisticated and well-resourced program.

## Sources

- [Cisco Talos -- UAT-7810 continues building ORB networks using new malware](https://blog.talosintelligence.com/uat-7810/) -- primary technical analysis and IOC source
- [The Hacker News -- China-Linked UAT-7810 Expands ORB Network With New LONGLEASH Malware](https://thehackernews.com/2026/07/china-linked-uat-7810-expands-orb.html) -- secondary coverage
- [BleepingComputer -- Chinese hackers develop LONGLEASH malware to expand ORB network](https://www.bleepingcomputer.com/news/security/chinese-hackers-develop-longleash-malware-to-expand-orb-network/) -- secondary coverage
- [SecurityWeek -- China-Linked APT Expands Arsenal With New Leash Backdoors](https://www.securityweek.com/china-linked-apt-expands-arsenal-with-new-leash-backdoors/) -- secondary coverage
- [Infosecurity Magazine -- China-Linked APT Expands Proxy Network With New Malware](https://www.infosecurity-magazine.com/news/uat-7810-china-apt-orb-proxy/) -- secondary coverage

---
*Report generated by Actioner*
