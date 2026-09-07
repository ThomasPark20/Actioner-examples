# Technical Analysis Report: Kimwolf v7 Botnet (2026-08-11)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-11
Version: 1.0

## Executive Summary

Kimwolf v7 is an evolved Android IoT botnet variant that represents a significant escalation in botnet resilience engineering. First discovered on February 3, 2026, through threat hunting by Palo Alto Unit 42, this version was developed in direct response to coordinated takedown operations in December 2025 that disrupted earlier Kimwolf variants. The botnet introduces a three-tier command-and-control resolution system combining Ethereum Name Service (ENS) queries through five public RPC endpoints, an operator-controlled RPC facade at rpcuniverse[.]com, and a Tor v3 hidden service as a fallback -- all routed through a local SOCKS5 proxy at 127.0.0.1:23075. The DDoS capability includes 15 attack methods across OSI layers 3-7, with the new HTTP/2 flood (case 17) using nghttp2 and BoringSSL to construct complete Chrome browser fingerprints that make attack traffic difficult to distinguish from legitimate requests. Infrastructure spans 22 C2 hosts in the 212.193.31[.]0/24 range (AS202799, Saint Petersburg, Russia) sharing identical SSH host keys, and an operator VPS at 23.94.221[.]104 (RackNerd, Dallas). The botnet targets Android TV boxes and IoT devices, spreading via unauthenticated Android Debug Bridge (ADB) instances on port 5555.

## Background: Kimwolf Botnet Ecosystem

Kimwolf is an Android/Linux IoT botnet lineage that evolved from the AISURU Linux variant, first observed active in August 2024. The broader Kimwolf ecosystem has been the subject of public disclosures by XLab, Synthient, Infoblox, Cloudflare, and KrebsOnSecurity. Version 7 marks a deliberate architectural pivot: the operators stripped network scanning, exploitation, and brute-force modules from the bot itself, separating the propagation pipeline from the DDoS payload. External loaders now handle initial access, while the v7 binary focuses exclusively on C2 communication and DDoS attack execution. The malware is compiled with Android NDK (Clang), uses Bionic libc, and statically links BoringSSL (for TLS) and nghttp2 (for HTTP/2 protocol support).

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2024-08 | Kimwolf botnet first active as AISURU Linux variant |
| 2023-12-09 | rpcuniverse[.]com apex domain registered via Namecheap |
| 2023-12-12 | eth[.]rpcuniverse[.]com subdomain registered |
| 2023-12-13 | TLS certificate (Let's Encrypt) first observed on 23.94.221[.]104 |
| 2025-09-02 | Earliest x86 sample (libn[redacted]kernel.so v1) with Dirty COW (CVE-2016-5195) reference |
| 2025-10 | APK variants begin distribution; package name com[.]android[.]logcatd |
| 2025-10 | Transition from Linux IoT to Android TV boxes |
| 2025-11 (early) | Kernel filename changed to libdevice.so (OpSec adjustment) |
| 2025-12 | Coordinated takedown operations (XLab, Synthient, Infoblox, Cloudflare) |
| 2025-12 | Kimwolf v7 developed in response; ENS, Tor, local proxy introduced |
| 2025-12 (early) | Kernel filename reverts to n[redacted]kernel.so |
| 2025-12-18 | First SSH host key on 212.193.31[.]102 (C2 seed host) |
| 2026-01-31 | Last C2 host added to 212.193.31[.]x range |
| 2026-02-03 | Kimwolf v7 discovered through threat hunting |
| 2026-08-11 | Unit 42 publishes technical analysis |

## Root Cause: ADB Exploitation via Residential Proxies

Kimwolf v7 spreads by misusing residential proxy services to reach unauthenticated Android Debug Bridge (ADB) instances on local networks, targeting port 5555. This allows the botnet to bypass network perimeter defenses by tunneling through legitimate residential IP addresses, making the scanning traffic appear to originate from local network peers. ADB, when left exposed without authentication (common on Android TV boxes and IoT devices), provides full shell access to the device. The v7 variant itself does not contain the scanning/exploitation code -- external loaders handle initial access and deploy the DDoS kernel payload.

## Technical Analysis of the Malicious Payload

### 1. Initial Loader and APK Delivery

The botnet deploys via two delivery methods. The first is a standalone ELF binary (ARM 32-bit, statically linked) that executes directly on compromised Linux/Android devices. The second is an Android APK wrapper that masquerades as a system service. APK variants use package names `com.android.logcatd` (Oct 2025) and `com.n2.systemservice0644` (later variants), with the APK signing certificate bearing SHA-1 thumbprint `2a1d96f1b066877812587ac94f45f82dfff5f5f9` and subject `C=CN, CN=a`. The APK probes for root access before executing the embedded ELF kernel payload with elevated privileges. Key APK components include `TorService` (Tor routing persistence) and `BootReceiver` (boot-time persistence).

### 2. Process Masquerading and Single-Instance Lock

Upon execution, the ELF kernel masks its process name as `netd_service` to blend with legitimate Android system processes. Older variants used `inetd` (Unix network services) and `TVHelper` (Android TV spoofing). A Unix domain socket `@n[redacted]boxv7` ensures single-instance execution -- if the socket is already bound, the new instance exits. The version identifier string `n_[redacted]_boxv7` is embedded in the binary.

### 3. C2 Infrastructure -- Three-Tier Resolution

The v7 architecture introduces a layered C2 resolution system designed to survive takedown operations:

**Tier 1 -- Ethereum Name Service (ENS):** The bot queries five hard-coded public Ethereum RPC endpoints in a shuffled (pseudo-random) order, providing five-way redundancy that prevents blocking through any single endpoint:
- hxxps://0xrpc[.]io/eth
- hxxps://eth[.]llamarpc[.]com
- hxxps://ethereum-rpc[.]publicnode[.]com
- hxxps://eth-protect[.]rpc[.]blxrbdn[.]com
- hxxps://eth[.]merkle[.]io

These legitimate public endpoints are used to resolve C2 addresses via blockchain-based ENS domain names. Because ENS records live on the Ethereum blockchain, they cannot be taken down through traditional domain registrar or DNS actions.

**Tier 2 -- Operator-Controlled RPC Facade:** Two samples hard-code `eth[.]rpcuniverse[.]com` as an additional RPC endpoint; others contact the IP directly at 23.94.221[.]104. This single-tenant VPS on AS36352 (RackNerd, Dallas) was registered December 12, 2023, with timing and exclusivity suggesting operator control. An Avalanche (AVAX) variant at `avax[.]rpcuniverse[.]com` is also present.

**Tier 3 -- Tor Fallback:** A hard-coded v3 onion address `edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd[.]onion` serves as the ultimate fallback. The bot implements SOCKS5 tunneling with a standard greeting (0x05 0x01 0x00), CONNECT with domain type 0x03, and a 62-byte .onion address.

**Local Proxy Architecture:** All C2 traffic -- whether clearnet or Tor -- routes through a local proxy at `127.0.0.1:23075`. This design decouples the proxy component from the main bot binary, allowing independent updates to the routing layer.

The primary C2 infrastructure resides on 22 hosts in the 212.193.31[.]0/24 range (AS202799, geolocated to Saint Petersburg, Russia), all sharing identical SSH host keys between December 18, 2025 and February 3, 2026. C2 communication occurs on ports 13 and 443.

### 4. DDoS Attack Arsenal (15 Methods)

Kimwolf v7 implements 15 DDoS attack methods spanning OSI layers 3-7:

| Case | Method | Notes |
|------|--------|-------|
| 0 | TCP socket flood | |
| 1 | UDP flood v1 | |
| 2 | Game server UDP | Port 27015 |
| 3 | DNS query flood | |
| 4 | UDP flood v2 | |
| 5 | TCP SYN flood | |
| 6 | TCP ACK flood | |
| 7 | TCP SYN-ACK flood | |
| 9 | Async UDP flood | |
| 10 | TCP RST flood | |
| 12 | High-performance UDP flood | ARM NEON SIMD-accelerated |
| 14 | ICMP flood | |
| 15 | epoll-based TCP connection flood | |
| 16 | TLS/HTTPS flood | BoringSSL |
| 17 | HTTP/2 flood with Chrome fingerprints | **New in v7** -- nghttp2 |

Cases 8, 11, and 13 are reserved or removed.

### 5. HTTP/2 DDoS Fingerprinting (Case 17 -- New in v7)

The function `attack_case17_http2_flood` implements a novel HTTP/2 flood attack that constructs complete browser fingerprints mimicking legitimate Chrome requests. The companion function `build_http2_attack_headers` manages header construction, while the statically linked nghttp2 library provides HTTP/2 protocol support. This makes flood traffic difficult to distinguish from legitimate browser requests, directly targeting application-layer DDoS mitigation systems.

### 6. High-Performance UDP Optimization (Case 12)

The UDP flood leverages ARM NEON SIMD instructions for high-performance IP/UDP checksum computation, tailored for the ARM processors in Android TV boxes. The PRNG function `prng_seed_from_urandom` implements Xorshift256 seeded from `/dev/urandom` (32 bytes, four 64-bit state words), with a SplitMix64 fallback if `/dev/urandom` is unavailable. Vectorized loops process four 16-bit halfwords simultaneously using VLD1.16, VADDW.U16, and VADD.I32 instructions.

### 7. Anti-Forensics / Evasion Techniques

- Binary stripped but retains some symbol information
- Statically linked libraries (BoringSSL, nghttp2) avoid dynamic dependency detection
- Bionic libc runtime (Android-native)
- Local proxy architecture isolates C2 routing from DDoS execution
- Process name masquerading (netd_service, inetd, TVHelper)
- Filename obfuscation cycling: libn[redacted]kernel.so to libdevice.so and back (Nov-Dec 2025)
- Version 7 removed scanning/exploitation/brute-force modules to reduce detection surface

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path / Name | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Android/Linux (ARM) | libn[redacted]kernel.so | 406647de09a0ffa279756b4ccb344b1b76a333320c5b50fd367901fa006cf0ff | ELF botnet kernel (1,720,108 bytes) |
| Android/Linux (ARM) | libn[redacted]kernel.so | 345222bca004595977f971d76900b0c65fd9bf9d91c50cd0c5bf5a93f1ad9e49 | ELF botnet kernel (1,712,624 bytes) |
| Android/Linux (ARM) | libn[redacted]kernel.so | 2ec2e85b0358e0c681cb5067489a9086ec97dbbf7e3c952dd9cd496b319d5af5 | ELF kernel; hard-codes eth[.]rpcuniverse[.]com (1,720,108 bytes) |
| Android/Linux (ARM) | libn[redacted]kernel.so | 9470c68f9b6fe5f90d61891b95623afd7b4298815b0f95e25610e1c09008dc24 | Dropped ELF kernel from APK (ARM) |
| Android/Linux (ARM) | libdevice.so | 8242443dfcec66e3fe04cbfa2fbd211ad34065ee07aa93813d792a437caab212 | Renamed kernel variant (ARM) |
| Android/Linux (x86) | libn[redacted]kernel.so v1 | 421111a57b0a4224c052fa4108d90429d579974b5b5111ed2e58516ba09422ca | Earliest x86 variant (Sept 2, 2025) |
| Android | APK wrapper | 951c94809aa6c7ab587125f9d4df30fa6a49ee0cbba76a4b7ceedaaa0e5dcd36 | APK distribution package |
| Android | APK wrapper | f07821e313c16cbbd82def45094a22c8d474164051bdbc7648d6869e012014b4 | APK distribution package |

**MD5 hashes:** d759364844d78a728505fb0485c3adbc, 036bcb62be72c4663b9564955f93b05f, 33faca1e0090f6b12eff703daf4606e4

**VHash (structural):** 76554ad09897ac723a850eaf8c525efa

**APK Signing Certificate:** SHA-1 thumbprint 2a1d96f1b066877812587ac94f45f82dfff5f5f9 (Subject: C=CN, CN=a)

**APK Package Names:** com[.]android[.]logcatd, com[.]n2[.]systemservice0644

### Network

| Type | Value | Context |
|------|-------|---------|
| IP (C2) | 212.193.31[.]119:13 | C2 server (AS202799, Saint Petersburg, Russia) |
| IP (C2) | 212.193.31[.]122:13 | C2 server |
| IP (C2) | 212.193.31[.]92:443 | C2 server |
| IP (C2) | 212.193.31[.]158:443 | C2 server |
| IP (C2) | 212.193.31[.]102 | C2 seed host (Dec 18, 2025) |
| IP (Operator) | 23.94.221[.]104 | Hosts rpcuniverse[.]com (RackNerd, Dallas) |
| Domain (Operator) | rpcuniverse[.]com | Operator-controlled Ethereum RPC facade |
| Domain (Operator) | eth[.]rpcuniverse[.]com | ENS resolution endpoint |
| Domain (Operator) | avax[.]rpcuniverse[.]com | Avalanche chain variant |
| Onion (C2 fallback) | edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd[.]onion | Tor v3 hidden service fallback |
| URL (ENS RPC) | hxxps://0xrpc[.]io/eth | Abused public Ethereum RPC endpoint |
| URL (ENS RPC) | hxxps://eth[.]llamarpc[.]com | Abused public Ethereum RPC endpoint |
| URL (ENS RPC) | hxxps://ethereum-rpc[.]publicnode[.]com | Abused public Ethereum RPC endpoint |
| URL (ENS RPC) | hxxps://eth-protect[.]rpc[.]blxrbdn[.]com | Abused public Ethereum RPC endpoint |
| URL (ENS RPC) | hxxps://eth[.]merkle[.]io | Abused public Ethereum RPC endpoint |
| TLS Cert SHA256 | f3e8a55a2a3ea7c7b6676e90f4f49a2c55b13065b68ee50c51cc35fe2b5c3237 | Let's Encrypt cert for rpcuniverse[.]com |

### Behavioral

- Process masquerades as `netd_service`, `inetd`, or `TVHelper`
- Unix domain socket `@n[redacted]boxv7` for single-instance lock
- Local SOCKS5 proxy on `127.0.0.1:23075` routing all C2 traffic
- SOCKS5 greeting bytes: `0x05 0x01 0x00`; CONNECT with domain type `0x03` + 62-byte .onion
- Outbound HTTPS to public Ethereum RPC endpoints from IoT/Android devices (anomalous blockchain traffic)
- ADB exploitation on port 5555 via residential proxy tunneling
- APK components: `TorService`, `BootReceiver`, class `systemservice0644.N[redacted]Kernel`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1036.005 | Masquerading: Match Legitimate Name or Location | Process masquerades as netd_service, inetd, TVHelper |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/2 DDoS with Chrome fingerprints; HTTPS to Ethereum RPC endpoints |
| T1090.003 | Proxy: Multi-hop Proxy | Three-tier C2 with local SOCKS5 proxy, Tor fallback |
| T1573 | Encrypted Channel | TLS via BoringSSL for C2; SOCKS5+TLS for Tor tunnel |
| T1571 | Non-Standard Port | C2 on port 13; local proxy on port 23075 |
| T1008 | Fallback Channels | ENS primary, operator RPC secondary, Tor tertiary |
| T1498 | Network Denial of Service | 15 DDoS methods across OSI layers 3-7 |
| T1498.001 | Network DoS: Direct Network Flood | UDP, ICMP, TCP SYN/ACK/RST floods |
| T1568 | Dynamic Resolution | Ethereum Name Service for C2 domain resolution via blockchain |
| T1547 | Boot or Logon Autostart Execution | APK BootReceiver for boot-time persistence |
| T1046 | Network Service Discovery | ADB enumeration via residential proxies (external loaders) |
| T1059 | Command and Scripting Interpreter | ADB shell access for payload deployment |

## Impact Assessment

Kimwolf v7 represents a meaningful advancement in botnet resilience architecture. The three-tier C2 resolution via blockchain (ENS), operator infrastructure, and Tor makes traditional takedown approaches significantly more difficult. The HTTP/2 DDoS with Chrome fingerprinting raises the bar for application-layer DDoS mitigation, as attack traffic now closely mimics legitimate browser behavior at the protocol and header level. The ARM NEON SIMD-optimized UDP flood demonstrates platform-specific performance engineering for the Android TV/IoT target base. The modular separation of propagation (external loaders) from DDoS execution (v7 kernel) complicates attribution and disruption, as removing the scanner does not stop the DDoS capability and vice versa. The C2 infrastructure spanning 22 hosts in a single Russian ASN with shared SSH keys suggests centralized, well-resourced operation.

## Detection & Remediation

### Immediate Detection

- Search DNS logs for queries to `rpcuniverse[.]com` or any subdomain
- Monitor for outbound connections to `212.193.31[.]0/24` on ports 13 and 443
- Check for processes named `netd_service` on non-system Android devices
- Look for local connections to `127.0.0.1:23075` (SOCKS5 proxy)
- Scan for the known SHA256 hashes in endpoint protection / AV logs
- Monitor for anomalous HTTPS traffic to public Ethereum RPC endpoints (0xrpc[.]io, llamarpc[.]com, publicnode[.]com, blxrbdn[.]com, merkle[.]io) from IoT/Android devices
- Check for Tor circuit establishment from Android TV boxes or IoT devices

### Remediation

1. **Containment:** Isolate affected Android TV boxes and IoT devices from the network immediately.
2. **Eradication:** Factory-reset compromised devices. For rooted devices, remove the ELF kernel payloads and APK packages (com.android.logcatd, com.n2.systemservice0644).
3. **Block C2:** Add the 212.193.31[.]0/24 range, 23.94.221[.]104, and rpcuniverse[.]com to firewall/proxy blocklists.
4. **Disable ADB:** On all Android TV boxes and IoT devices, disable ADB or restrict to USB-only mode. If network ADB is required, bind only to trusted interfaces and enforce authentication.
5. **Credential rotation:** Not directly applicable (ADB exploitation, not credential-based).

### Long-Term Hardening

- Segment Android TV boxes and consumer IoT devices from enterprise/production networks.
- Block outbound Tor circuit establishment from consumer/IoT device segments.
- Monitor and alert on Ethereum RPC endpoint traffic from non-workstation devices (IoT/embedded devices should not be querying blockchain RPCs).
- Rate-limit HTTP/2 requests with duplicate or static browser fingerprints from single sources.
- Deploy network-based IOC feeds that include .onion addresses for Tor hidden service C2.
- Consider blocking outbound connections on port 13 from consumer device segments (Daytime Protocol, rarely legitimately used).

## Detection Rules

These detections target Kimwolf v7's distinctive C2 infrastructure, process masquerading, network indicators, and file-level artifacts. PoC/advisory-specific altitude with strict leniency; Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify against your telemetry before promoting to production.

### Sigma: Kimwolf v7 DNS Query to Operator RPC Domain

Detects DNS queries to the operator-controlled rpcuniverse.com domain used for Ethereum-based C2 resolution.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Domain is operator-registered, single-tenant, not shared infrastructure. FP: legitimate Ethereum RPC users of rpcuniverse.com (unlikely in enterprise). -->
```yaml
title: Kimwolf v7 DNS Query to Operator-Controlled Ethereum RPC Domain
id: 7c3a1e9d-4b2f-48a5-9c6e-1d8f3a5b7e2c
status: experimental
description: >
    Detects DNS queries to the operator-controlled Ethereum RPC facade domain
    rpcuniverse.com used by Kimwolf v7 botnet for C2 resolution via ENS.
references:
    - https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1071.001
    - attack.t1568
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'rpcuniverse.com'
    condition: selection
falsepositives:
    - Legitimate use of rpcuniverse.com Ethereum RPC services (unlikely in enterprise environments)
level: high
```

<!-- revision: dropped by critic — Functionally broken. Rule uses Image|endswith: '/netd_service' but Kimwolf masquerades via prctl(PR_SET_NAME); actual binary is libn[redacted]kernel.so or libdevice.so, so Image will never contain netd_service. Not salvageable. -->

### Sigma: Kimwolf v7 Outbound Connection to Known C2 Subnet

Detects outbound firewall connections to the Kimwolf v7 C2 subnet 212.193.31.0/24 on the known C2 ports (13 and 443).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. All 22 C2 hosts share identical SSH keys in this /24; port 13 (Daytime) is a strong discriminator. Port 443 alone would FP but combined with the subnet it is precise. -->
```yaml
title: Kimwolf v7 Outbound Connection to Known C2 Infrastructure
id: 5e9d3a7c-1f4b-42e8-a6c9-8d2b0e5f7a3c
status: experimental
description: >
    Detects outbound network connections to known Kimwolf v7 C2 IP addresses
    in the 212.193.31.x range (AS202799, Saint Petersburg, Russia).
references:
    - https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1071.001
    - attack.t1571
logsource:
    category: firewall
detection:
    selection:
        dst_ip|startswith: '212.193.31.'
        dst_port:
            - 13
            - 443
    condition: selection
falsepositives:
    - Legitimate traffic to this IP range (verify with AS202799 ownership)
level: high
```

### Sigma: Kimwolf v7 Local SOCKS5 Proxy Port 23075

Detects local network connections to 127.0.0.1 on port 23075, the hard-coded local proxy port for Kimwolf v7 C2 routing.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Port 23075 is not a standard service port; any local connection to it is anomalous. FP only if a custom app happens to use this exact port. -->
```yaml
title: Kimwolf v7 Local SOCKS5 Proxy to Tor Fallback
id: 9b1c4e8d-3a5f-46d7-82e9-6f0d7b2a1c5e
status: experimental
description: >
    Detects local network connections to 127.0.0.1 on port 23075, the hard-coded
    local proxy port used by Kimwolf v7 to route C2 traffic through Tor or clearnet.
references:
    - https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1090.003
    - attack.t1573
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '127.0.0.1'
        DestinationPort: 23075
    condition: selection
falsepositives:
    - Custom applications configured to use local SOCKS proxy on this specific port
level: high
```

### Snort: Kimwolf v7 C2 on Port 13 with SOCKS5 Greeting

Detects outbound TCP connections to port 13 containing the SOCKS5 greeting bytes used by Kimwolf v7 for Tor-routed C2.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 validated via /etc/snort/snort.conf include local.rules, exit 0. Port 13 (Daytime) combined with SOCKS5 greeting is a strong indicator. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET 13 (msg:"Actioner - Kimwolf v7 C2 Connection to Port 13"; flow:established,to_server; content:"|05 01 00|"; depth:3; reference:url,unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/; classtype:trojan-activity; sid:2100101; rev:1;)
```

### Snort: Kimwolf v7 DNS Query for rpcuniverse.com

Detects DNS queries for the operator-controlled rpcuniverse.com domain using DNS wire-format matching.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 validated via /etc/snort/snort.conf include local.rules, exit 0. DNS label-length encoding: 0x0b = 11 bytes "rpcuniverse", 0x03 = 3 bytes "com". -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query for Kimwolf v7 Operator RPC Domain rpcuniverse.com"; content:"|0b|rpcuniverse|03|com|00|"; nocase; fast_pattern; reference:url,unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/; classtype:trojan-activity; sid:2100102; rev:1;)
```

### Suricata: Kimwolf v7 DNS Query to rpcuniverse.com

Detects DNS queries resolving any subdomain of rpcuniverse.com, the operator-controlled Ethereum RPC facade.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T exit 0. Uses dns.query sticky buffer with domain string match. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - Kimwolf v7 DNS Query to Operator RPC Domain rpcuniverse.com"; flow:to_server; dns.query; content:"rpcuniverse.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/; metadata:author Actioner, created_at 2026-08-11; sid:2200101; rev:1;)
```

### Suricata: Kimwolf v7 TLS SNI to rpcuniverse.com

Detects TLS connections with SNI matching rpcuniverse.com, indicating C2 communication via the operator's RPC endpoint.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T exit 0. Uses tls.sni with endswith modifier for subdomain coverage. -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Kimwolf v7 TLS Connection to Operator RPC Domain rpcuniverse.com"; flow:established,to_server; tls.sni; content:"rpcuniverse.com"; endswith; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/; metadata:author Actioner, created_at 2026-08-11; sid:2200102; rev:1;)
```

### Suricata: Kimwolf v7 SOCKS5 Tor Tunnel Initiation

Detects SOCKS5 CONNECT request tunneling to the hard-coded Kimwolf v7 Tor v3 onion address used as the fallback C2 channel.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T exit 0. Matches SOCKS5 greeting + CONNECT with domain type 0x03 + actual Kimwolf onion address. Specific to this threat actor's onion, not generic Tor usage. -->
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Kimwolf v7 SOCKS5 Tunnel to Tor Fallback C2"; flow:established,to_server; content:"|05 01 00|"; depth:3; content:"|05 01 00 03 3e|"; distance:0; content:"edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion"; distance:0; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/; metadata:author Actioner, created_at 2026-08-11; sid:2200103; rev:2;)
```

### Suricata: Kimwolf v7 Connection to Known C2 Subnet

Detects outbound TCP connections to the known Kimwolf v7 C2 subnet 212.193.31.0/24 on C2 ports 13 and 443.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T exit 0. Entire /24 is C2 infrastructure per Unit 42 analysis; 22 hosts share SSH keys. Port-constrained to 13 and 443 per intelligence. Time-bound IOC; remove when infrastructure rotates. -->
```suricata
alert tcp $HOME_NET any -> 212.193.31.0/24 [13,443] (msg:"Actioner - Kimwolf v7 Outbound Connection to Known C2 Subnet"; flow:established,to_server; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/; metadata:author Actioner, created_at 2026-08-11; sid:2200104; rev:2;)
```

### YARA: Kimwolf v7 ELF Botnet Binary

Detects Kimwolf v7 ELF binaries via version string, process name masquerading strings, operator RPC domains, and the hard-coded Tor onion address.
**Status:** compile ✅ compiles · confidence: high · sample: synthetic ✓
<!-- audit: yarac exit 0. YARA positive test fired on constructed ELF with published strings (boxv7 + @n + netd_service + inetd + rpcuniverse.com + 0xrpc.io + onion); negative (benign ELF) quiet. Condition requires ELF magic + filesize <5MB + multiple discriminating string combinations. -->
```yara
rule Malware_Kimwolf_V7_ELF_Botnet
{
    meta:
        description = "Detects Kimwolf v7 botnet ELF binaries via distinctive strings and structural markers"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/"
        hash = "406647de09a0ffa279756b4ccb344b1b76a333320c5b50fd367901fa006cf0ff"
        hash = "345222bca004595977f971d76900b0c65fd9bf9d91c50cd0c5bf5a93f1ad9e49"
        hash = "2ec2e85b0358e0c681cb5067489a9086ec97dbbf7e3c952dd9cd496b319d5af5"
        severity = "critical"

    strings:
        $ver = "boxv7" ascii
        $sock = "@n" ascii
        $proc1 = "netd_service" ascii fullword
        $proc2 = "TVHelper" ascii fullword
        $proc3 = "inetd" ascii fullword
        $rpc1 = "rpcuniverse.com" ascii
        $rpc2 = "0xrpc.io" ascii
        $rpc3 = "llamarpc.com" ascii
        $rpc4 = "publicnode.com" ascii
        $onion = "edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion" ascii
        $func1 = "attack_case17_http2_flood" ascii
        $func2 = "build_http2_attack_headers" ascii
        $func3 = "prng_seed_from_urandom" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            ($ver and $sock and 2 of ($proc*)) or
            ($onion) or
            (2 of ($rpc*) and 1 of ($proc*)) or
            (1 of ($func*) and $ver)
        )
}
```

## Lessons Learned

Kimwolf v7 demonstrates that botnet operators are actively investing in takedown-resistant architecture. The use of Ethereum Name Service for C2 resolution represents a meaningful evolution -- blockchain-based naming cannot be seized through traditional registrar or law enforcement channels, requiring new approaches to disruption. The separation of propagation from DDoS execution (external loaders vs. v7 kernel) shows increasing operational maturity. The HTTP/2 DDoS with Chrome fingerprinting highlights the arms race between DDoS operators and mitigation vendors, as volumetric defenses increasingly lose effectiveness against application-layer attacks that mimic legitimate traffic. Defenders should prioritize network segmentation of IoT/Android TV devices, disable unnecessary ADB access, and monitor for anomalous blockchain RPC traffic from non-workstation endpoints.

## Sources

- [Unit 42 - Kimwolf v7 Botnet Malware Analysis](https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/) -- primary technical analysis with IOCs, TTPs, and infrastructure mapping
- [XLab - Kimwolf Botnet Exposed](https://blog.xlab.qianxin.com/kimwolf-botnet-exposed/) -- prior disclosure of Kimwolf botnet variants
- [KrebsOnSecurity - Kimwolf Botnet Coverage](https://krebsonsecurity.com/2026/01/kimwolf-botnet/) -- investigative reporting on Kimwolf infrastructure and corporate/government network presence (Jan 2026)

---
*Report generated by Actioner*
