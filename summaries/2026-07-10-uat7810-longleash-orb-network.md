# Technical Analysis Report: UAT-7810 — China-Nexus APT Operating ORB Networks (2026-07-10)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-10
Version: 1.1 (FINAL)
<!-- revision: T1547 -> T1562.004 (iptables = firewall modification, not autostart) -->
<!-- revision: T1055 -> T1620 (DOGLEASH shellcode exec in own process, not injection) -->
<!-- revision: T1027 -> T1132 (Base58/Base64 encoding is network-layer data encoding, not file obfuscation) -->
<!-- revision: Hash scan remediation qualified with SSH/serial prerequisite; firmware re-flash noted as alternative -->
<!-- revision: Added SecurityScorecard LapDogs blog URL and NiCTeR Jan 2026 blog URL to Sources -->

## Executive Summary

UAT-7810 is a China-nexus advanced persistent threat group tracked by Cisco Talos that functions as an infrastructure-focused operator, building and maintaining Operational Relay Box (ORB) networks on compromised edge devices. Rather than conducting direct espionage, UAT-7810 provides relay infrastructure to secondary APT actors — including UAT-5918, which targets critical infrastructure in Taiwan — enabling them to route traffic through compromised devices and obscure their origins. The group develops and deploys custom malware including LONGLEASH (an upgraded multi-architecture backdoor with proxy and relay capabilities), DOGLEASH (a passive Linux backdoor), and JARLEASH (a Java-based administrative tool with Chinese-language configuration).

UAT-7810 gains initial access by exploiting known but unpatched (n-day) vulnerabilities in Ruckus wireless routers (CVE-2020-22653, CVE-2020-22658, CVE-2023-25717) since 2025, and expanded to ASUS AiCloud routers (CVE-2025-2492) in early 2026. Four C2 server IPs have been identified across Amsterdam/EU and Hong Kong hosting providers, operating on non-standard ports (99, 2222, 8088). The group uses TLS certificates with all subject fields set to "exploit" — a highly distinctive fingerprint. Cisco Talos assesses with high confidence that UAT-7810 is China-nexus, based in part on Simplified Chinese comments found in JARLEASH configuration files.

## Background: Operational Relay Box (ORB) Networks and Edge Device Targeting

Operational Relay Box (ORB) networks are multi-tier proxy infrastructures maintained by threat actors to obscure the true origin of cyberattacks. By routing malicious traffic through chains of compromised devices — particularly consumer and small-business edge devices like wireless routers — ORB operators create layers of indirection that frustrate attribution and network forensics. UAT-7810's ORB infrastructure, associated with the "LapDogs" network first exposed by SecurityScorecard in June 2025, serves as shared infrastructure for multiple China-nexus APT groups.

Edge devices such as Ruckus wireless access points and ASUS home routers are attractive targets because they are frequently deployed with default configurations, rarely receive timely security patches, lack endpoint detection and response (EDR) tooling, and run lightweight Linux-based operating systems amenable to cross-compiled malware. UAT-7810 exploits this patch gap by weaponizing vulnerabilities that are years old (the Ruckus CVEs date to 2020-2023), targeting the long tail of unpatched devices in the field.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2020 | CVE-2020-22653 and CVE-2020-22658 disclosed for Ruckus wireless routers |
| 2023 | CVE-2023-25717 disclosed for Ruckus wireless routers |
| 2025 | UAT-7810 begins exploiting Ruckus wireless router vulnerabilities to build ORB infrastructure |
| June 2025 | SecurityScorecard publicly discloses the "LapDogs" ORB network |
| 2025 | CVE-2025-2492 disclosed for ASUS AiCloud routers |
| Early 2026 | UAT-7810 begins exploitation campaign targeting ASUS AiCloud routers via CVE-2025-2492 |
| January 2026 | NiCTeR blog post documents AiCloud vulnerability exploitation activity |
| July 2026 | Cisco Talos publishes full technical analysis of UAT-7810 operations |

## Root Cause: Exploitation of N-Day Vulnerabilities in Edge Devices

UAT-7810 gains initial access exclusively through exploitation of known, publicly disclosed vulnerabilities in network edge devices — a classic n-day strategy that relies on the operational reality that many organizations and individual users fail to apply security patches to routers and wireless access points in a timely manner.

Four CVEs are confirmed as exploitation vectors:

- **CVE-2020-22653** (Ruckus wireless router) — remote code execution vulnerability disclosed in 2020, still actively exploited in 2025-2026
- **CVE-2020-22658** (Ruckus wireless router) — additional Ruckus vulnerability from the same disclosure window
- **CVE-2023-25717** (Ruckus wireless router) — more recent Ruckus vulnerability providing another entry point
- **CVE-2025-2492** (ASUS AiCloud router) — vulnerability in ASUS AiCloud functionality, exploited beginning early 2026

Post-exploitation, UAT-7810 deploys malware via shell scripts that download architecture-appropriate DOGLEASH binaries, configure iptables rules to permit traffic on specified ports, and execute the backdoor. JARLEASH is deployed alongside for persistent administrative access on devices with Java runtimes.

## Technical Analysis of the Malicious Payload

### 1. LONGLEASH — Upgraded Multi-Architecture Backdoor

LONGLEASH is an evolved variant of the earlier SHORTLEASH backdoor, internally named "ff-agent" with project version "nz1.0". It is compiled for multiple architectures (MIPS, ARM, x64) to accommodate diverse edge device hardware.

**Key libraries and dependencies:**
- **Boost.Asio** — asynchronous I/O framework for network operations
- **Nanopb** — lightweight Protocol Buffer (protobuf) processing for C2 communication
- **MbedTLS** — TLS encryption for secure C2 channels
- **musl libc** — lightweight C standard library for cross-platform IoT deployment

**Capabilities:**
- Reverse shell to C2 infrastructure
- Multi-protocol proxy servers: HTTP, DNS, SOCKS, TCP, ICMP, UDP
- Packet redirection across TCP, UDP, and HTTP
- SMTP server and client functionality
- TLS-encrypted C2 communications
- Intermediate C2 relay capability (core ORB function — forwarding commands to other compromised nodes)
- Self-removal upon detection of suspicious activity or analysis attempts

**Hardcoded User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36`

### 2. DOGLEASH — Passive Linux Backdoor

DOGLEASH is a passive backdoor deployed via shell scripts on compromised Linux-based edge devices. Unlike LONGLEASH's active C2 beaconing, DOGLEASH binds to a hardcoded local port and listens for incoming TCP connections — the operator connects to the device rather than the device calling home.

**Command codes and functions:**

| Code | Function |
|------|----------|
| 0x2268 | Execute command via `/bin/sh -c` |
| 0x2267 | Execute command via `/bin/sh -c` (alternate) |
| 0x2266 | Read file from disk |
| 0x2271 | Rename file (create backup) |
| 0x3273 | Close socket listener |
| 0x3274 | Close socket listener (alternate) |
| 0x3450 | Get OS information (release, version, machine hardware ID, node name) |
| Default | Execute arbitrary code in memory (shellcode) |

Commands are decoded using hardcoded password strings. DOGLEASH targets MIPS, ARM, and x64 architectures, with 65 unique samples identified across these platforms.

### 3. JARLEASH — Java-Based Administrative Tool

JARLEASH is a Java Archive (JAR) package deployed on compromised infrastructure and devices with available Java runtimes. Its configuration file contains comments in Simplified Chinese, providing one of the key attribution indicators linking UAT-7810 to China.

**Capabilities:**
- Web-based file management interface for browsing and manipulating files on compromised devices
- FTP/SFTP server hosting for bulk file transfer
- Netcat-style server on specified IP/port for arbitrary TCP connections
- Process spawning and instance management

### 4. LEASHTEST — Pre-Deployment Validation Tool

LEASHTEST is a non-malicious ELF binary internally named "iot-test" targeting MIPS platforms. It verifies that a target device can support the malware toolkit by testing thread creation, TCP port binding, child process spawning, asynchronous timer creation, and exception handling. Its presence on a device indicates UAT-7810 reconnaissance or pre-deployment validation.

### 5. C2 Infrastructure

UAT-7810 operates C2 servers hosted on VPS instances in Europe and Asia:

| IP Address | Location | Ports | Role |
|-----------|----------|-------|------|
| 194.233.92[.]26 | Amsterdam/EU | 2222, 8088 | C2 server, malware hosting |
| 217.15.160[.]247 | Amsterdam/EU | 99, 2222, 8088 | C2 server, malware hosting |
| 217.15.164[.]147 | Amsterdam/EU | 99, 2222, 8088 | C2 server, ASUS exploitation infrastructure |
| 95.182.100[.]231 | Hong Kong | 2222 | C2 server |

All C2 servers host multiple malware variants compiled for different architectures, enabling automated deployment of the correct binary for each compromised device type.

**TLS Configuration:** C2 communications use TLS with certificates bearing a distinctive subject DN where all fields are set to "exploit": `C=exploit, ST=exploit, L=exploit, O=exploit, OU=exploit, CN=exploit`. The certificate SHA256 fingerprint is `c2ab9adaba93ff094b8f3fc37d906014d870582039d276b7bd03e6fd583d8a15`.

**Communication encoding:** C2 traffic uses Base58, Base64, and custom password-based encryption schemes, with protobuf-serialized payloads.

### 6. Anti-Forensics / Evasion Techniques

- **Self-removal:** LONGLEASH includes functionality to delete itself from disk upon detecting suspicious activity or analysis environments
- **Custom encoding:** Multiple encoding schemes (Base58, Base64, password-based decryption) obfuscate C2 traffic
- **Passive listening (DOGLEASH):** By binding to a local port instead of beaconing out, DOGLEASH avoids detection by outbound-traffic-focused monitoring
- **iptables manipulation:** Firewall rules are modified post-compromise to permit backdoor traffic, blending with legitimate device administration

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Malware | Hash (SHA256) | Description |
|----------|---------|---------------|-------------|
| Linux (MIPS) | LEASHTEST | 1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823 | Pre-deployment test tool ("iot-test") |
| Linux (multi-arch) | LONGLEASH | 755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f | Upgraded backdoor ("ff-agent" v nz1.0) |
| Linux (multi-arch) | JARLEASH startup | e799d72929d7ccc7f6b6109742b8cc482838303207efc989543b6e1ca6d16e9c | Startup script |
| Linux (multi-arch) | JARLEASH config | 3b89d183eb014e29d9d0d4e45fc2b784a7fcfcf31dd48fd3bde30f8d956383d1 | Configuration file (Chinese comments) |
| Linux (multi-arch) | JARLEASH | 324d95024fc8da5c92b5a1f4825aed5a2a91c9ca8fb6aa52abb332a4c9cf4257 | Java backdoor JAR |
| Linux (multi-arch) | JARLEASH | bafba443170e54ef7fd431ce7f1b5e202719f3fd022e4ef70788904f574d2cdf | Java backdoor JAR (variant) |
| Linux (multi-arch) | DOGLEASH | 604b53f87d6c070bf387e80c70a6df8d272fa3fc143148d41f13e59d52ab1f13 | Passive backdoor (1 of 65 samples) |
| Linux (multi-arch) | DOGLEASH | c92541f273eeb576d39235d0a5c6f18f2574b132a1022598edfa38065783ab98 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 29c7fccc6ef8cbfe4da9a169c7c74bacaea1fb515a1fddef91ab1b1522f76e4c | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 425bf771c8c9f740b1ae9803dcb4fd45af4d6a6f171fcc72fc7d511095ca82ce | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | ac8eae94d27122f4751bc96d9ea52d30000b7ca37569a2291b2710824ca3396f | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | dc4f25b2247cfdd6fc96848db30a178baa4419a4a854e86e315b465836102d14 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 3878dd5c8eba1e5b53ab2e07e7b5482e95a3fd3e98268bcd7861318bc9902376 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 9b9e0e5a1eb469b8d20dc23351e08ff5d5731e1cedce0ddee9bbd00a76217f13 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 57bdab2ba4b05ec0338c06632599393d5b14227f31a43fe950ea8fdd47428715 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | b8d247fd1fb85d24a17afeec3815906dfbcdc5359647910b4a153900ec999a0f | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | d5cf7315186a78ab6a7475c338bdf101bc6461930aaa7a012a02cf93f347c207 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | dd0fc1a88180fde8367bec7086f99294f36b8332f12994293139ed532d2ebbac | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 5c3f190571645c4641dcff2c07a4c3ab9acad06aa9607350a385729d8d6139f1 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 323c3a91be60ebc3e06e942bad04899a15911cea23269e43d07829164b2ce5d4 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 880425fee707e9f42e0b8d60119ed639b1ad506ea29877d126bdebce379cd229 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | e5d2de8ae98579bfb940290f60e59a502b3065345aaf765456387989c0488b20 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 2e0e43776e2e1a37d882a1b2ebb7d337ee88950177e43831dae645a367824feb | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | b5969636eec376ad6c3ece2202b1722219955638e09b6f96d4cfc0598d3b1890 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 1660536f448b8b9f086ce9ea3ce4e9deefc59a76711ea53ee6d8f08fc8c1bb99 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 65feba2c971c214e71303ad2e0fbf62b45ebcaa784cbf3d0dab62786cb4c0469 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 53ac2b231c23d41234e55b1f7ed89f86234f785adbbe820959655d7b019d7df9 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 33c10b77e1da9f0679023d55fb3057879d15609db9c1d46ee5c3ff1240a3d052 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 5faea1650cac0f3ffd2dc1fb220182095a46e34158967d37c2a942e85e2ca97b | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 62d4ec87ed21f0d15cb769b0b2a5577cab41fc2cdb1e7e796c5bdff09264dd9a | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 534a4a5bff2609a2d6e088cb87465c08c2d69c6aaa7d2ffcbcd491274b8505f1 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 5eab4c61baa67ae2838a36c2e6ff0476a8f2117b96a7027b830c8cb46ce78efc | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 0af4c52a1d13e4132a1843ce7727abcf0ddd4d1ca6a4b17cdf599ec3f355c241 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | d4861088161fc72b9922abf933b4ea664a807105ec1eab4a173253aa60bfe6d7 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 3d296af7f29c0425655bd1cc0be48fe4aba52ee6760a89e805ca2589f4ef4d77 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | f235d2e044c2f7814e6bbcd835b9fd9f10f227dacfb9396185ec2013e7df4db4 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 4130f49fa81a699a667cafdbd6d1f6e781edd686c947eb8ae27134f6dc2c43d7 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 0a8555a71868749be8c905ed53296ce335af50a9262772b5e154ad3f9c35c2e4 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 20fcba222f74dd68aaeb1f0ad30cdf702a828ee164a182b30d05d600c35b72d9 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 912adea5339c73cb4a777a3e9f98bf3cb08da6622c9dd3b4cc9b083cb03d10a2 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 03926e3da998f32ad898b640bd15cf145768f9e849e6f18d81350234254c424e | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 16971f9706d70ac4925651c7c8719b9d77aff63e4c0a618129efc32c2c46b989 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 6917c0f9eafefe42e33e791b75a7e503ff8b081bc10a98449e4076787dfc6c16 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | c7c9bfa9ffcd8fb6a2afe656f510c406ddc58ebff48ce1d0fd3fad951b46a36e | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | b9fe48bda9a6c8787981a24f8bbc723a6f6aa80cab5fa53481937382f3c6ce85 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | f3fbf4481f30fd840f35568746f54be49eb92b2c9ac95597a7760abb171cb54b | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 6366d59b573d50fd23ff650923c4a8c1c918518a02d0a56f12c23533c45f439d | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 3fcaa3038e365b6ab0b121e2cd319c56b74e37381943a0da0e8dce407087cdb8 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | bf70c6f3a8e913f526ec57eeec50e1306f7b34b037915b7a1cf2968cc46acc58 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 0352f3e338261d98895df4c7b7a76b296485b2290c72bce56603351d167d0601 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 52b871429833e1dee348263844efb531f6a3fcd321f88dc8a876caaee912cedd | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 5db2ce9acd50f96d566e8d139f6490abf2bbf7a9293b876eeb4598fd2c37c515 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 3169a6dbcce684e2c5a2f166996b58ffa673df6e58b8edf2bdf3e66271c8c69e | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | d871d76171504597bbda387689e12e7a5e354c360ff135f4df231cec68c761af | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | d1f963b88672f3676a7da1580262ba0d4f367cc57a94b551754c20f77a670c43 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 76d9e2a2ff313f5b91cc67aab1127122baee1c3efbae1087e58a25bc5f1eb065 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 8c104da0e66ef6384663309aaf8fb49f549f2785d835eec620b265f8aa11d9f0 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | c494c878e28284539419612616d964ab9224cbe27e57f42293d91d02d684e3db | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 08701ed7975bf4f5688c2724d27ab497764200ad6f4dc53d3cc03b170378ced0 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 0a8cae96e25e85c612b0736fe886f9b124ad70ec425bc2ec1a8a4135b25436ba | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 8459ff264a2c81c68a34c4ee6bc109d141ad28b96037d34ff112322a4c853739 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 68445a37a9943a267a8b2100fba2678353d6ec88844505ccbba659e586c7a105 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 29686c933cec1e274467e2dae264625ae6f754824bb7f550bc9c3131f625562c | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | d973ad5a80c3d7468a9c392db4166857ed32b5d61cd6755766ba8922156dada3 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | f5a57dfae488d9dfe260b32460a1d947fb5af58ceaf2fb0139bc08b4bb79a966 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 2ebc1b6cf543e2cb3f22d9a5b54b6676bb71dde98df7532f8791297734e44fdd | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 6dbd507ca7cecea861f9cf704b3c5c37f5bd5392886a8c2562088892b7703fa5 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 89f0a67bc595ab8bce02c2f95f9292ad06e1868207e809c76bd16f0cab800c06 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | d81201d0fc19977e51104438a5b9cba861f4da20cea3ae9183edf16ab11d98f8 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 9d52cb4febf3342c34dcc8198dcaf453458be3699ab47dc08616aa7f18daa7fa | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 9a927c37a31b80975c5c5467f112b61478c9493c046281046443525358a5acb0 | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 6cda1e81667f869940401f05a55c8dea94dbdf3ceffb93b5f320a6462cfea44d | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 745538dea8ed9aec4466e67a9d0aecf9e7026ff16a792d1d6f306e8b67d3f34c | Passive backdoor |
| Linux (multi-arch) | DOGLEASH | 13acadb3541e75af50e02d5be56c2238b93d8f154ce5514be1558e6ee59a1432 | Passive backdoor |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 194.233.92[.]26 | C2 server (Amsterdam/EU), ports 2222, 8088 |
| IP | 217.15.160[.]247 | C2 server (Amsterdam/EU), ports 99, 2222, 8088 |
| IP | 217.15.164[.]147 | C2 server (Amsterdam/EU), ports 99, 2222, 8088; ASUS exploitation |
| IP | 95.182.100[.]231 | C2 server (Hong Kong), port 2222 |
| URL | hxxp://217.15.160[.]247:8088/ | Malware download endpoint |
| URL | hxxp://217.15.160[.]247:2222/ | Malware download endpoint |
| URL | hxxp://217.15.160[.]247:99/ | Malware download endpoint |
| URL | hxxp://194.233.92[.]26:8088/ | Malware download endpoint |
| URL | hxxp://194.233.92[.]26:2222/ | Malware download endpoint |
| URL | hxxp://217.15.164[.]147:99/ | Malware download endpoint |
| URL | hxxp://217.15.164[.]147:8088/ | Malware download endpoint |
| URL | hxxp://217.15.164[.]147:2222/ | Malware download endpoint |
| URL | hxxp://95.182.100[.]231:2222/ | Malware download endpoint |
| TLS Fingerprint | c2ab9adaba93ff094b8f3fc37d906014d870582039d276b7bd03e6fd583d8a15 | TLS certificate SHA256 fingerprint |
| TLS Subject | CN=exploit, O=exploit, OU=exploit, C=exploit, ST=exploit, L=exploit | Distinctive TLS certificate subject DN |

### Behavioral

- **LONGLEASH User-Agent:** HTTP C2 communications use a hardcoded Chrome 122 User-Agent string: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36`. This Chrome version (from early 2024) is increasingly rare in legitimate traffic.
- **Non-standard port usage:** C2 traffic operates on ports 99, 2222, and 8088 — none of which are standard HTTP/HTTPS ports.
- **iptables modification:** Post-compromise, shell scripts configure iptables rules to permit traffic on the backdoor's listening port.
- **DOGLEASH passive listening:** Unlike typical beaconing malware, DOGLEASH binds to a local port and waits for inbound connections, evading outbound traffic monitoring.
- **Protobuf-serialized C2:** LONGLEASH uses Protocol Buffers (via Nanopb) for structured C2 communication, with Base58/Base64/custom password-based encoding.

### Existing Vendor Signatures

**Cisco Snort SIDs:** 66433, 66432, 66430, 66431, 301493

**ClamAV Signatures:** Unix.Backdoor.Agent-10059997-1, Unix.Backdoor.Agent-10059998-0, Unix.Backdoor.Agent-10059999-0, Java.Backdoor.Agent-10060000-0, Unix.Backdoor.Agent_mips32-10060001-0, Unix.Backdoor.Agent_mips32r2-10060002-0, Unix.Backdoor.Agent_armv7-10060003-0, Unix.Backdoor.Agent_mips1-10060004-0, Unix.Backdoor.Agent_mips32r2el-10060005-0, Unix.Backdoor.Agent_mips32el-10060006-0

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of n-day vulnerabilities in Ruckus wireless routers (CVE-2020-22653, CVE-2020-22658, CVE-2023-25717) and ASUS AiCloud routers (CVE-2025-2492) |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | DOGLEASH executes commands via `/bin/sh -c`; shell scripts used for malware deployment |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | iptables rules modified post-compromise to permit traffic on backdoor listening ports |
| T1571 | Non-Standard Port | C2 communications on ports 99, 2222, and 8088 |
| T1090 | Proxy | LONGLEASH operates HTTP, DNS, SOCKS, TCP, ICMP, and UDP proxy servers; ORB network relays traffic for secondary APT actors |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 with hardcoded User-Agent and protobuf payloads |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | TLS-encrypted C2 using MbedTLS with distinctive "exploit" certificates |
| T1132 | Data Encoding | Base58, Base64, and custom password-based encoding applied to C2 network traffic and command payloads |
| T1620 | Reflective Code Loading | DOGLEASH default command handler receives and executes shellcode in its own process memory |
| T1082 | System Information Discovery | DOGLEASH command 0x3450 retrieves OS release, version, hardware ID, and node name |
| T1005 | Data from Local System | DOGLEASH command 0x2266 reads files from the compromised device |
| T1070.004 | Indicator Removal: File Deletion | LONGLEASH self-deletion capability upon suspicious activity detection |

## Impact Assessment

**Breadth:** UAT-7810's ORB network infrastructure poses a broad threat because it enables multiple secondary APT groups to conduct operations through the relay chain. The targeting of widely deployed consumer and small-business edge devices (Ruckus wireless access points, ASUS home routers) means the potential victim pool spans any organization or individual running unpatched firmware on these devices. 65 unique DOGLEASH samples across three architectures suggest significant scale.

**Depth:** Compromise grants the operator full remote access to the device, including command execution, file access, and the ability to use the device as a proxy node. For organizations with compromised edge devices, this means an attacker-controlled relay point operating within or adjacent to their network perimeter.

**Stealth:** The operational model — infrastructure maintenance by UAT-7810, offensive operations by secondary actors — creates a separation that complicates attribution. DOGLEASH's passive listening model (no outbound beaconing) and the use of TLS encryption further impede detection.

**Related actors:** UAT-5918, a separate China-nexus APT that targets critical infrastructure in Taiwan, shares overlapping tooling with UAT-7810 and is a known consumer of this ORB infrastructure.

## Detection & Remediation

### Immediate Detection

**Check for connections to known C2 IPs (firewall/proxy logs):**
```
# Search for connections to UAT-7810 C2 infrastructure
grep -E '194\.233\.92\.26|217\.15\.160\.247|217\.15\.164\.147|95\.182\.100\.231' /var/log/firewall.log
```

**Check for DOGLEASH listening ports on Linux edge devices:**
```
# Look for unexpected listening TCP ports (run on the device)
netstat -tlnp | grep -v -E ':(22|80|443|53)\s'
ss -tlnp | grep -v -E ':(22|80|443|53)\s'
```

**Check for LONGLEASH User-Agent in proxy logs:**
```
# Search for outdated Chrome 122 User-Agent in proxy logs
grep 'Chrome/122.0.6261.95' /var/log/proxy/access.log
```

**Check for TLS certificates with "exploit" subject (if TLS inspection is enabled):**
```
# Search for the distinctive certificate subject
grep -i 'CN=exploit' /var/log/tls-inspection.log
```

### Remediation

1. **Isolate compromised devices:** Immediately disconnect any Ruckus or ASUS device showing IOC matches from the network.
2. **Factory reset and firmware update:** Compromised edge devices should be factory reset and updated to the latest firmware that patches the exploited CVEs.
3. **Block C2 infrastructure:** Add 194.233.92[.]26, 217.15.160[.]247, 217.15.164[.]147, and 95.182.100[.]231 to network block lists.
4. **Audit iptables rules:** On any suspect Linux-based network device, review iptables rules for unauthorized port openings (especially ports 99, 2222, 8088).
5. **Hash scan:** Run the 65+ DOGLEASH SHA256 hashes, plus LONGLEASH, JARLEASH, and LEASHTEST hashes against file system inventories of edge devices where SSH or serial console access is available. For devices without shell access, firmware re-flash to a clean, patched image is the pragmatic remediation alternative.
6. **Monitor for lateral movement:** If a compromised device was inside the network perimeter, assume potential lateral movement and investigate adjacent systems.

### Long-Term Hardening

- **Patch management for edge devices:** Implement a formal patch management program that covers network edge devices (routers, wireless APs, IoT), not just servers and workstations.
- **Network segmentation:** Isolate edge devices from internal networks to limit the impact of compromise.
- **Outbound traffic monitoring:** Monitor edge device traffic for connections to non-standard ports and unusual TLS certificates.
- **Device inventory:** Maintain an up-to-date inventory of all edge devices, their firmware versions, and known vulnerability status.
- **TLS inspection at perimeter:** Deploy TLS inspection to identify certificates with anomalous subject DNs (e.g., all fields set to "exploit").

## Detection Rules

These detections target UAT-7810 C2 infrastructure, LONGLEASH backdoor artifacts, and the distinctive "exploit" TLS certificate. PoC/advisory-specific altitude (default); compiles does not equal fires -- verify in your SIEM/IDS pipeline before production deployment.

### Sigma: UAT-7810 C2 Infrastructure Connection

Detects outbound network connections to known UAT-7810 C2 IP addresses on their operational non-standard ports (99, 2222, 8088).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data unreachable via proxy, RuntimeError: HTTP Error 403); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Rule is syntactically valid and portable to both backends. No pipeline mapping applicable for generic firewall logsource. IPs are real (not defanged) per logsource-encoding guidelines. FP risk minimal — specific IPs + specific non-standard ports. -->
```yaml
title: Connection to UAT-7810 C2 Infrastructure
id: 8f3a1c7e-4d2b-4e9a-b6f0-1a3c5e7d9b2f
status: experimental
description: >
    Detects network connections to known UAT-7810 (China-nexus APT) C2 infrastructure
    on non-standard ports used for LONGLEASH and DOGLEASH backdoor communications.
references:
    - https://blog.talosintelligence.com/uat-7810/
author: Actioner
date: 2026/07/10
tags:
    - attack.t1571
    - attack.t1090
logsource:
    category: firewall
detection:
    selection_ip:
        dst_ip:
            - '194.233.92.26'
            - '217.15.160.247'
            - '217.15.164.147'
            - '95.182.100.231'
    selection_port:
        dst_port:
            - 99
            - 2222
            - 8088
    condition: selection_ip and selection_port
falsepositives:
    - Legitimate services hosted on these IP addresses (unlikely given port combination)
level: high
```

### Suricata: UAT-7810 TLS Certificate with Exploit Subject DN

Detects TLS connections where the server certificate subject contains "CN=exploit" and "O=exploit", matching the distinctive self-signed certificates used by UAT-7810 C2 infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). tls.cert_subject buffer used twice to anchor on both CN and O fields — even if Suricata normalizes DN order differently, both substrings will match. Could not use tls.cert_fingerprint because the blog provides SHA256 while Suricata expects SHA1 in colon-separated format. FP risk negligible — no legitimate certificate uses "exploit" across all subject fields. -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-7810 TLS Certificate with Exploit Subject DN"; flow:established,to_server; tls.cert_subject; content:"CN=exploit"; tls.cert_subject; content:"O=exploit"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-10; sid:2200001; rev:1;)
```

### Suricata: UAT-7810 LONGLEASH HTTP C2 User-Agent

Detects HTTP traffic with the Chrome/122.0.6261.95 User-Agent string hardcoded in LONGLEASH backdoor C2 communications. Scope to edge device subnets or pair with C2 IP alerts to reduce false positives from legitimate outdated Chrome browsers.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). http.user_agent sticky buffer with fast_pattern on Chrome version substring. Chrome 122 was current in Feb 2024; by mid-2026 legitimate usage is rare but not impossible — confidence medium, not high. Pairing with dst_ip would raise confidence but reduce portability as IPs rotate. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-7810 LONGLEASH HTTP C2 User-Agent"; flow:established,to_server; http.user_agent; content:"Chrome/122.0.6261.95"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created_at 2026-07-10; sid:2200002; rev:1;)
```

### Snort: UAT-7810 LONGLEASH HTTP C2 User-Agent

Detects HTTP traffic containing the Chrome/122.0.6261.95 User-Agent hardcoded in LONGLEASH.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: Snort is NOT installed in this environment. Structural check: http service in header, http_header sticky buffer (correct for Snort 3), content with fast_pattern modifier, flow:established, all required fields (msg, sid, rev) present, semicolons terminate all options. Valid Snort 3 syntax per reference spec. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-7810 LONGLEASH HTTP C2 User-Agent"; flow:established, to_server; http_header; content:"Chrome/122.0.6261.95", fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-7810/; metadata:author Actioner, created 2026-07-10; sid:2100001; rev:1;)
```

### YARA: UAT-7810 LONGLEASH Backdoor

Detects LONGLEASH backdoor (ELF binary) via its internal project name "ff-agent" combined with corroborating library references (Nanopb, MbedTLS) or the hardcoded Chrome/122 User-Agent string.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara scanner fired on positive sample (ELF header + "ff-agent" + "nanopb"), quiet on negative (ELF without LONGLEASH strings). Positive constructed from blog-published strings, not invented. "ff-agent" as internal project name is highly distinctive; combined with ELF format constraint and corroborating library/UA string, FP risk is minimal. fullword modifier on ff-agent prevents substring matches. -->
```yara
rule APT_UAT7810_LONGLEASH_Backdoor
{
    meta:
        description = "Detects LONGLEASH backdoor (internally named ff-agent v nz1.0) used by China-nexus APT UAT-7810 for ORB network operations"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f"
        severity = "high"

    strings:
        $internal_name = "ff-agent" ascii fullword
        $version = "nz1.0" ascii
        $ua = "Chrome/122.0.6261.95" ascii
        $lib_nanopb = "nanopb" ascii fullword
        $lib_mbedtls = "mbedtls" ascii nocase

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        $internal_name and
        1 of ($version, $ua, $lib_nanopb, $lib_mbedtls)
}
```

### YARA: UAT-7810 LEASHTEST Pre-Deployment Tool

Detects LEASHTEST (ELF binary internally named "iot-test"), a non-malicious utility used by UAT-7810 to validate target device capabilities before deploying operational malware. Its presence indicates UAT-7810 reconnaissance activity.
**Status:** compile ✅ compiles · confidence: medium · sample: fired ✓
<!-- audit: yarac exit 0. yara scanner fired on positive sample (ELF header + "iot-test" + "thread" + "async"), quiet on negative. "iot-test" is moderately distinctive — fullword modifier required; corroborating strings (thread, async, timer, bind) are individually common but the combination with iot-test in an ELF binary raises specificity. Confidence medium due to potential for benign IoT test utilities. -->
```yara
rule APT_UAT7810_LEASHTEST_Tool
{
    meta:
        description = "Detects LEASHTEST (iot-test) MIPS functionality testing tool used by UAT-7810 to verify compromised device capabilities"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823"
        severity = "medium"

    strings:
        $internal_name = "iot-test" ascii fullword
        $s1 = "thread" ascii
        $s2 = "async" ascii
        $s3 = "timer" ascii
        $s4 = "bind" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        $internal_name and
        2 of ($s*)
}
```

### YARA: DOGLEASH / JARLEASH — N/A (hash-based detection recommended)

DOGLEASH and JARLEASH lack sufficient distinctive string artifacts in the public reporting for reliable YARA signature generation without direct sample access. DOGLEASH's command codes (0x2268, 0x2267, etc.) are 16-bit values whose 2-byte representations are too common in arbitrary binaries to serve as YARA anchors. JARLEASH's Simplified Chinese comments are referenced but not quoted in the blog post. For these malware families, use the 65+ DOGLEASH SHA256 hashes and 2 JARLEASH SHA256 hashes provided in the IOC table above for hash-based IOC matching (e.g., SIEM hash lookup, VirusTotal retrohunt, or ClamAV signatures already published by Cisco).

## Lessons Learned

1. **Edge devices remain a persistent blind spot.** UAT-7810's success hinges on the reality that routers and wireless access points are rarely included in enterprise patch management programs, vulnerability scanning schedules, or EDR deployments. Organizations that treat edge devices as "set and forget" infrastructure leave them as perpetually soft targets.

2. **ORB networks decouple infrastructure from operations.** The UAT-7810 model — one group builds the relay network, other groups use it for operations — means that compromising an edge device may not produce observable malicious activity for weeks or months until a secondary actor routes an operation through it. This delayed activation window demands proactive IOC hunting, not just reactive alerting.

3. **N-day exploitation outpaces patching.** All four exploited CVEs were publicly known before UAT-7810 weaponized them. The Ruckus CVEs date to 2020-2023 and are still viable against deployed devices in 2026. This underscores that vulnerability disclosure without effective patch deployment is insufficient — particularly for device categories that lack auto-update mechanisms.

4. **Passive backdoors evade outbound monitoring.** DOGLEASH's design (bind to port, wait for inbound connections) is specifically optimized to evade detection approaches that focus on suspicious outbound connections or beaconing behavior. Detection strategies must also monitor for unexpected inbound connections to edge devices and unauthorized listening ports.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Cisco Talos Intelligence Blog: UAT-7810](https://blog.talosintelligence.com/uat-7810/) — primary technical analysis of UAT-7810 operations, malware families, IOCs, and ORB infrastructure
- [Infosecurity Magazine: UAT-7810 China APT ORB Proxy](https://www.infosecurity-magazine.com/news/uat-7810-china-apt-orb-proxy/) — secondary reporting with attribution context and operational summary
- [SecurityScorecard STRIKE: Unmasking the LapDogs ORB Network](https://securityscorecard.com/blog/unmasking-a-new-china-linked-covert-orb-network-inside-the-lapdogs-campaign/) — original June 2025 disclosure of LapDogs ORB infrastructure and ShortLeash backdoor
- [NiCTeR Blog: ASUS AiCloud Vulnerability Exploitation](https://blog.nicter.jp/2026/01/aicloud_vulnerability/) — January 2026 analysis of CVE-2025-2492 exploitation activity observed via darknet monitoring

---
*Report generated by Actioner*
