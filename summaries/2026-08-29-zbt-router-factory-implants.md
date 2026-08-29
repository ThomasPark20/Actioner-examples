# Technical Analysis Report: ZBT Router Factory Implants — DARKLANTERN & SPEAKINGSTONE (2026-08-29)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-29
Version: 1.1 (critic-revised)

## Executive Summary

VulnCheck disclosed on August 27, 2026 two previously undocumented factory-installed implants — codenamed **SPEAKINGSTONE** (CVE-2026-74232, CVSS 9.8) and **DARKLANTERN** (CVE-2026-74233, CVSS 9.8) — shipping in firmware across dozens of Chinese-manufactured ZBT router models. Both implants run as root with zero authentication, enabling unauthenticated remote command execution, WAN credential exfiltration, DNS hijacking, and reverse SSH tunneling. This follows VulnCheck's earlier August 5 disclosure of a third implant, ENDLESSDOORS (CVE-2026-66747), in the same product line. Together, these represent a systemic supply-chain compromise affecting routers sold worldwide on Amazon, AliExpress, Newegg, and other platforms under brands including Zbtlink, WiFlyer, MOFI, Lippert, Wave, and others. VulnCheck's sinkhole of the backup C2 identified 392 unique devices actively beaconing, 390 of them in China. Over 200 instances of DARKLANTERN were found Internet-exposed across 22 countries.

## Background: ZBT Routers

Shenzhen Zhibotong Electronics Co. (ZBT) is a Chinese manufacturer of OpenWrt-based routers sold globally as white-label products. They are rebranded and sold by dozens of companies (WiFlyer, WORDFI, HomeMyfi, Cioswi, CroSkylink, KuWFi, MOFI, Lippert, Wave, OneX, Digineo, ALLNET) on Amazon, AliExpress, Newegg, Shopee, and Alibaba. The firmware is developed in part by MoreQuick, an OEM firmware vendor. ZBT's MAC address OUI block is 78:A3:51. The routers serve consumer, small-business, and mobile/vehicle connectivity markets, making them high-value targets for supply-chain compromise due to their wide distribution and minimal security oversight.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2017-10-06 | Hardcoded timestamps in DARKLANTERN salt strings (`Salt_171006_808290505`) suggest implant development |
| 2017-10-07 | DARKLANTERN MAC-bypass string timestamp (`Allmac_171007_808290505`) |
| 2018-09-04 | Earliest affected firmware version (18.0904) shipped with DARKLANTERN |
| 2020-06-22 | Latest affected firmware version (20.0622) still shipping with implants |
| 2026-08-05 | VulnCheck publishes ENDLESSDOORS (CVE-2026-66747) disclosure |
| 2026-08-18 to 2026-08-21 | VulnCheck Internet scanning detects 203 DARKLANTERN instances across 22 countries |
| 2026-08-21 | VulnCheck sinkhole captures 392 unique SPEAKINGSTONE beacons |
| 2026-08-27 | VulnCheck publishes DARKLANTERN & SPEAKINGSTONE advisory |
| 2026-08-28 | The Hacker News covers the disclosure |

## Root Cause: Supply-Chain Firmware Implant

These are factory-installed implants baked into the firmware image at manufacturing time — not post-deployment compromises. The implants are launched at boot by the `inetdetect` watchdog binary. The firmware is developed by MoreQuick (identified by the hardcoded string "mqonu.com" in the DARKLANTERN authentication salt). There is no exploit vector — the backdoors are the product as shipped. Every device running affected firmware is compromised from first boot.

## Technical Analysis of the Malicious Payload

### 1. SPEAKINGSTONE (yunmgrd) — CVE-2026-74232

**Binary:** `/usr/bin/yunmgrd`
**SHA-256:** `b77811db4d218c65670a6c9a5b33c30ff81c6d779e15d658643138771178a818`
**Protocol:** UDP-based "zbtProtocol" (outbound beaconing)
**Beacon Port:** UDP/10000 outbound

SPEAKINGSTONE is a C2 agent that beacons to a hardcoded command-and-control server. On startup it sends a device fingerprint registration message (type 0x1001) containing the device model, firmware version, MAC address, uptime, SSID, LAN IP, and GPS coordinates.

**Supported command types:**
- **0x1001** — Device fingerprint beacon (registration)
- **0x2507** — Execute arbitrary commands as root
- **0x2502** — Exfiltrate WAN PPPoE username/password
- **0x230b** — Write DNS hijack list (via `/usr/sbin/dns.sh`)
- **0x2306** — Return current DNS hijack list
- **0x2405** — Open/close reverse SSH tunnel
- **0x2406** — Return current reverse SSH port
- **0x2602** — Update backup C2 server addresses

**Obfuscation:** Single-byte XOR with key 0x1f (observed on tested device); application is optional/inconsistent across firmware versions. No encryption. No authentication.

**Configuration file:** `/tmp/yunclient.conf`

### 2. DARKLANTERN (infosrvd) — CVE-2026-74233

**Binary:** `/usr/bin/infosrvd`
**SHA-256:** `7e2e036fec2fe7ab4bbd43978d9296563894c92a112f5ac2f39957f12108e245`
**Protocol:** UDP-based "revProto" (inbound listener)
**Listening Port:** UDP/9992 (firewall-opened via iptables rule)
**Response Port:** UDP/8897

DARKLANTERN is an inbound remote-control service. It listens on UDP port 9992, which is explicitly opened in the device's iptables configuration. It responds to a 19-byte info probe packet, returning the device model, firmware version, MAC address, SSID, public IP, and status in semicolon-delimited plaintext over UDP/8897.

**Authentication bypass:** The service uses a checksum scheme with the hardcoded salt "mqonu.com" (last 4 hex characters of an MD5 hash). The MAC address filter is defeated by sending an all-zeros MAC address — a hardcoded wildcard bypass.

**Command execution:** Command packets (type 0x17) prepend the payload to `/etc/exec/cmd`. Arbitrary command injection is achieved by inserting a semicolon to break out of the fixed prefix.

**Info probe packet (19 bytes):**
```
0c 16 1f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
```

**Wildcard MAC command prefix:**
```
0c 17 1f 12 34 56 00 00 00 00 00 00
```

### 3. C2 Infrastructure

| Component | Value | Details |
|-----------|-------|---------|
| Primary C2 domain | ac-link[.]com | Resolves to 47.107.224[.]89 |
| Backup C2 domain | www[.]findmyipaddr[.]com | Obfuscated in binary as concatenated substrings |
| C2 IP address | 47[.]107[.]224[.]89 | Alibaba Cloud, Shenzhen region |
| SPEAKINGSTONE beacon port | UDP/10000 outbound | To C2 |
| DARKLANTERN listen port | UDP/9992 inbound | From any source |
| DARKLANTERN response port | UDP/8897 | Response to probes |
| DARKLANTERN response port | UDP/8898 | Alternate response |

The backup C2 domain is obfuscated in the binary via string concatenation: `"ww" + "w.f" + "indmy" + "ipadd" + "r.co" + "m"`.

### 4. Supporting Binary — inetdetect

**Binary:** Connectivity watchdog
**SHA-256:** `ae6c356f1f09260b859f84d994ef8423540a6c0bdf98510d86b85834283e4926`
**Function:** Launches both SPEAKINGSTONE (`yunmgrd`) and DARKLANTERN (`infosrvd`) at boot.

### 5. Anti-Forensics / Evasion Techniques

- Implants masquerade as system services (`yunmgrd`, `infosrvd`) with names that blend into a Linux router environment
- SPEAKINGSTONE backup C2 domain is string-concatenation obfuscated to evade static string analysis
- Optional single-byte XOR obfuscation on SPEAKINGSTONE protocol payloads
- DARKLANTERN uses an all-zeros MAC wildcard bypass, making the MAC-based "authentication" entirely ineffective
- Commands are logged to `/tmp/cmd.log` (tmpfs, lost on reboot) rather than persistent storage

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `ac-link[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `47[.]107[.]224[.]89`)

### Package / Software Level

| Package / Component | Malicious Version(s) | Description |
|---------------------|----------------------|-------------|
| ZBT firmware (DARKLANTERN) | 18.0904, 18.1218, 19.0226, 19.0412, 19.0522, 19.0617, 19.0625, 19.0626, 19.0717, 19.0809, 19.0829, 19.1009, 19.1023, 19.1101, 19.1112, 20.0516, 20.0622 | Ships with infosrvd implant |
| ZBT firmware (SPEAKINGSTONE) | 19.1101, 3.0.0.4.528, 1.0.0.2.007, 1.0.0.3.001, 1.0.0.2.000, 3.0.0.4.380 | Ships with yunmgrd implant |

**Affected router models (DARKLANTERN):** WE1326, WE357, WE5926, WE826-Q, WE826-T2, WG108, WG3526, WE2426-C, WE5926-EC_QP, WF3526-P

**Affected router models (SPEAKINGSTONE):** L3_V2_8, WE826-T2, ZBT-7628, and multiple MoreQuick-branded models

### File System

| Platform | Path | Hash (SHA-256) | Description |
|----------|------|----------------|-------------|
| Linux (MIPS/ARM) | /usr/bin/yunmgrd | b77811db4d218c65670a6c9a5b33c30ff81c6d779e15d658643138771178a818 | SPEAKINGSTONE C2 agent |
| Linux (MIPS/ARM) | /usr/bin/infosrvd | 7e2e036fec2fe7ab4bbd43978d9296563894c92a112f5ac2f39957f12108e245 | DARKLANTERN remote-control service |
| Linux (MIPS/ARM) | (watchdog) | ae6c356f1f09260b859f84d994ef8423540a6c0bdf98510d86b85834283e4926 | inetdetect launcher for both implants |
| Linux (MIPS/ARM) | /etc/exec/cmd | — | Command execution wrapper |
| Linux (MIPS/ARM) | /tmp/yunclient.conf | — | SPEAKINGSTONE configuration |
| Linux (MIPS/ARM) | /tmp/info.txt | — | Device fingerprint data |
| Linux (MIPS/ARM) | /tmp/cmd.log | — | Command execution log |
| Linux (MIPS/ARM) | /usr/sbin/dns.sh | — | DNS hijacking activation script |
| Linux (MIPS/ARM) | /tmp/mac.txt | — | Device MAC address storage |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | ac-link[.]com | Primary SPEAKINGSTONE C2 |
| Domain | www[.]findmyipaddr[.]com | Backup SPEAKINGSTONE C2 |
| IP | 47[.]107[.]224[.]89 | SPEAKINGSTONE C2 server (Alibaba Cloud, Shenzhen) |
| Port | UDP/10000 outbound | SPEAKINGSTONE beacon port |
| Port | UDP/9992 inbound | DARKLANTERN listener |
| Port | UDP/8897 outbound | DARKLANTERN response |
| Port | UDP/8898 outbound | DARKLANTERN alternate response |

### Behavioral

- **SPEAKINGSTONE beacon pattern:** UDP outbound to port 10000 at regular intervals, containing device model, firmware version, MAC, uptime, SSID, LAN IP, GPS coordinates. Message type 0x1001 for registration.
- **DARKLANTERN iptables rule:** `iptables -A udp_packets -p udp --dport 9992 -j ACCEPT` explicitly opens the listener port.
- **Process names:** `yunmgrd` and `infosrvd` running as root on ZBT router devices.
- **SPEAKINGSTONE XOR encoding:** Optional single-byte XOR with key 0x1f on protocol payloads.
- **DARKLANTERN info probe response:** Semicolon-delimited plaintext containing model, firmware, MAC, SSID, public IP, and status sent from UDP/8897.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Implants factory-installed in router firmware by OEM manufacturer |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Both implants execute arbitrary commands as root via `/etc/exec/cmd` |
| T1071 | Application Layer Protocol | SPEAKINGSTONE uses custom UDP protocol ("zbtProtocol") for C2 |
| T1132.001 | Data Encoding: Standard Encoding | Single-byte XOR (0x1f) obfuscation on SPEAKINGSTONE protocol payloads |
| T1205 | Traffic Signaling | DARKLANTERN responds to a specific 19-byte UDP probe packet as an activation signal |
| T1005 | Data from Local System | SPEAKINGSTONE exfiltrates WAN PPPoE credentials (0x2502) |
| T1557 | Adversary-in-the-Middle | DNS hijacking capability (0x230b) via `/usr/sbin/dns.sh` |
| T1572 | Protocol Tunneling | Reverse SSH tunneling capability (0x2405) |
| T1082 | System Information Discovery | Device fingerprinting beacon includes model, firmware, MAC, IP, GPS, uptime |
| T1190 | Exploit Public-Facing Application | DARKLANTERN listens on firewall-opened UDP/9992 for unauthenticated commands |
| T1543.002 | Create or Modify System Process: Systemd Service | Implants started at boot by inetdetect watchdog service |

## Impact Assessment

- **Breadth:** Dozens of router models across 20+ brands sold on Amazon, AliExpress, Newegg, and Shopee globally. VulnCheck detected 203 DARKLANTERN instances Internet-exposed across 22 countries and 392 SPEAKINGSTONE devices actively beaconing. The true installed base is likely much larger.
- **Depth:** Full root command execution, credential theft, DNS hijacking, and reverse tunneling — total device compromise from factory.
- **Stealth:** Implants blend into the Linux router environment with innocuous service names. No encryption, no authentication barriers. The DARKLANTERN wildcard MAC bypass renders the only access control entirely moot.
- **Geographic concentration:** 390 of 392 sinkholed SPEAKINGSTONE devices were in China, 83% on China Mobile, 304 broadcasting "CMCC" SSID prefix. 363 were the L3_V2_8 model with firmware 3.0.0.4.528.

## Detection & Remediation

### Immediate Detection

**Network-level (any organization):**
```bash
# Check firewall/netflow logs for outbound UDP port 10000 traffic (SPEAKINGSTONE beacon)
# Check for DNS queries to ac-link[.]com or findmyipaddr[.]com
# Check for inbound UDP port 9992 traffic (DARKLANTERN)

# Scan for DARKLANTERN listener with a probe packet (Python):
# Send 0c161f00000000000000000000000000000001 to target:9992/UDP
# Listen on port 8897 for response starting with 0c161f
```

**On-device (if SSH access available):**
```bash
# Check for implant processes
ps | grep -E 'yunmgrd|infosrvd|inetdetect'

# Check for implant binaries
ls -la /usr/bin/yunmgrd /usr/bin/infosrvd 2>/dev/null

# Check for DARKLANTERN firewall rule
iptables -L udp_packets 2>/dev/null | grep 9992

# Check for configuration artifacts
ls -la /tmp/yunclient.conf /tmp/info.txt /etc/exec/cmd 2>/dev/null
```

### Remediation

1. **Isolate immediately:** Disconnect affected routers from the network. These devices cannot be trusted.
2. **Do not attempt to patch:** These are factory implants embedded in the firmware. No vendor patch exists. The manufacturer (ZBT) and firmware developer (MoreQuick) are the source of the compromise.
3. **Replace hardware:** Affected devices should be replaced with routers from vendors with auditable firmware supply chains.
4. **Rotate credentials:** Change all credentials that transited the compromised router, including WAN PPPoE credentials (which SPEAKINGSTONE can exfiltrate), Wi-Fi passwords, and any credentials used over unencrypted connections.
5. **Audit DNS:** If DNS hijacking was active, review DNS resolution logs for affected clients and assess potential credential theft or phishing exposure.
6. **Network forensics:** Review historical netflow for outbound UDP/10000 and inbound UDP/9992 traffic to scope exposure duration.

### Long-Term Hardening

- Avoid white-label Chinese-manufactured routers without auditable firmware provenance
- Implement network monitoring for unusual outbound UDP beaconing patterns
- Segment IoT/router management interfaces from production networks
- Perform firmware binary analysis before deploying network equipment at scale
- Monitor for iptables rule anomalies that open unexpected inbound ports

## Detection Rules

These detections target the known C2 infrastructure, network protocols, and file-level artifacts of the SPEAKINGSTONE and DARKLANTERN implants. PoC/advisory-specific (default altitude); compiles does not equal fires — verify in your environment's log pipeline. `sigma check` was blocked by the proxy fetching MITRE ATT&CK data; all Sigma rules convert cleanly to both Splunk and CrowdStrike LogScale.

### Sigma: SPEAKINGSTONE C2 Domain DNS Query

Detects DNS queries to the hardcoded C2 domains (ac-link.com, findmyipaddr.com) used by the SPEAKINGSTONE factory implant.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK fetch 403); splunk convert exit 0; log_scale convert exit 0. Fields use real (non-defanged) domain values. dns_query logsource; QueryName|endswith for subdomain coverage. -->
```yaml
title: ZBT SPEAKINGSTONE C2 Beacon to Known Domain
id: 8a3e1c4f-7b29-4d6e-a1f3-5c8d2e9b0a47
status: experimental
description: >
    Detects DNS queries to the hardcoded C2 domains used by the SPEAKINGSTONE
    (yunmgrd) factory implant found in ZBT routers. The implant beacons via UDP
    port 10000 to ac-link.com or the backup domain findmyipaddr.com.
references:
    - https://vulncheck.com/blog/zbt-darklantern-speakingstone
    - https://thehackernews.com/2026/08/china-made-zbt-routers-ship-with-two.html
author: Actioner
date: 2026/08/29
tags:
    - attack.t1071
    - attack.t1132
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'ac-link.com'
            - 'findmyipaddr.com'
    condition: selection
falsepositives:
    - Legitimate use of ac-link.com for non-malicious purposes (unlikely)
level: high
```

### Sigma: SPEAKINGSTONE C2 IP and Port

Detects network connections to the known SPEAKINGSTONE C2 IP 47.107.224.89 on UDP port 10000.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Firewall logsource with dst_ip + dst_port. IP is real (non-defanged). -->
```yaml
title: ZBT SPEAKINGSTONE C2 Communication to Known IP
id: 2f7d0e93-a4b1-4c58-9e6d-3b8f1a2c5d74
status: experimental
description: >
    Detects network connections to the known SPEAKINGSTONE C2 IP address
    47.107.224.89 (Alibaba Cloud, Shenzhen) on UDP port 10000, used by the
    yunmgrd factory implant in ZBT routers.
references:
    - https://vulncheck.com/blog/zbt-darklantern-speakingstone
    - https://thehackernews.com/2026/08/china-made-zbt-routers-ship-with-two.html
author: Actioner
date: 2026/08/29
tags:
    - attack.t1071
logsource:
    category: firewall
detection:
    selection:
        dst_ip: '47.107.224.89'
        dst_port: 10000
    condition: selection
falsepositives:
    - Other Alibaba Cloud services hosted on this IP (low likelihood given port specificity)
level: high
```

### Sigma: DARKLANTERN Inbound UDP Port 9992

Detects inbound UDP to port 9992, the DARKLANTERN listener port opened by the factory implant's iptables rule.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Medium confidence: UDP/9992 is uncommon but not unique to DARKLANTERN — scope to known ZBT router subnets for higher precision. -->
```yaml
title: ZBT DARKLANTERN Inbound UDP Probe on Port 9992
id: 4c6e8a12-d3f5-4b97-8e1c-9a7d2f0b3e56
status: experimental
description: >
    Detects inbound UDP connections to port 9992, which is the listening port
    opened by the DARKLANTERN (infosrvd) factory implant on ZBT routers. The
    implant responds to unauthenticated probes on this port and allows remote
    command execution.
references:
    - https://vulncheck.com/blog/zbt-darklantern-speakingstone
    - https://thehackernews.com/2026/08/china-made-zbt-routers-ship-with-two.html
author: Actioner
date: 2026/08/29
tags:
    - attack.t1190
logsource:
    category: firewall
detection:
    selection:
        dst_port: 9992
        protocol: 'udp'
    condition: selection
falsepositives:
    - Legitimate services on UDP port 9992 (uncommon)
level: medium
```

### Snort: DARKLANTERN Info Probe and Command Packets

Detects the 19-byte DARKLANTERN info probe packet and the wildcard-MAC command execution packet on UDP/9992.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -R exit 0 (pidfile suffix warning is cosmetic, not a rule error). Hex content matches the published VulnCheck probe packet exactly. -->
```snort
alert udp $EXTERNAL_NET any -> $HOME_NET 9992 (msg:"Actioner - ZBT DARKLANTERN Info Probe Packet"; dsize:19; content:"|0c 16 1f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01|"; depth:19; classtype:trojan-activity; reference:url,vulncheck.com/blog/zbt-darklantern-speakingstone; sid:2100010; rev:1;)
alert udp $EXTERNAL_NET any -> $HOME_NET 9992 (msg:"Actioner - ZBT DARKLANTERN Wildcard MAC Command Execution"; content:"|0c 17 1f|"; depth:3; content:"|00 00 00 00 00 00|"; distance:3; within:6; classtype:trojan-activity; reference:url,vulncheck.com/blog/zbt-darklantern-speakingstone; sid:2100011; rev:1;)
```

### Suricata: DARKLANTERN Probes, SPEAKINGSTONE DNS and Beacon

Detects DARKLANTERN probe/command packets on UDP/9992, SPEAKINGSTONE C2 DNS queries, and outbound beacon traffic.
**Status:** compile ✅ compiles · confidence: high (sids 2200010-2200013), medium (sid 2200014)
<!-- audit: suricata -T -S exit 0. DNS rules use dns.query sticky buffer (dot-notation). Hex content matches published VulnCheck packet structures. sid:2200014 downgraded to medium — the 0x1001 message type byte pattern is short and may match non-SPEAKINGSTONE UDP traffic on port 10000; depth:2 added to anchor the first content match. -->
```suricata
alert udp $EXTERNAL_NET any -> $HOME_NET 9992 (msg:"Actioner - ZBT DARKLANTERN Info Probe Packet"; dsize:19; content:"|0c 16 1f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01|"; depth:19; classtype:trojan-activity; reference:url,vulncheck.com/blog/zbt-darklantern-speakingstone; metadata:author Actioner, created_at 2026-08-29; sid:2200010; rev:1;)
alert udp $EXTERNAL_NET any -> $HOME_NET 9992 (msg:"Actioner - ZBT DARKLANTERN Wildcard MAC Command Execution"; content:"|0c 17 1f|"; depth:3; content:"|00 00 00 00 00 00|"; distance:3; within:6; classtype:trojan-activity; reference:url,vulncheck.com/blog/zbt-darklantern-speakingstone; metadata:author Actioner, created_at 2026-08-29; sid:2200011; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - ZBT SPEAKINGSTONE DNS Query to C2 Domain ac-link.com"; dns.query; content:"ac-link.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,vulncheck.com/blog/zbt-darklantern-speakingstone; metadata:author Actioner, created_at 2026-08-29; sid:2200012; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - ZBT SPEAKINGSTONE DNS Query to Backup C2 findmyipaddr.com"; dns.query; content:"findmyipaddr.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,vulncheck.com/blog/zbt-darklantern-speakingstone; metadata:author Actioner, created_at 2026-08-29; sid:2200013; rev:1;)
alert udp $HOME_NET any -> $EXTERNAL_NET 10000 (msg:"Actioner - ZBT SPEAKINGSTONE Outbound UDP Beacon to C2"; content:"|10 01|"; depth:2; content:"|00 00 00 00|"; offset:9; classtype:trojan-activity; reference:url,vulncheck.com/blog/zbt-darklantern-speakingstone; metadata:author Actioner, created_at 2026-08-29; sid:2200014; rev:1;)
```

### YARA: SPEAKINGSTONE yunmgrd Binary

Detects the SPEAKINGSTONE implant binary via published characteristic strings (zbtProtocol.c, yunclient.conf, cmcc_server, dnshack, setBackServer).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Strings sourced from VulnCheck's published binary analysis. No real sample available for validation. -->
```yara
rule ZBT_SPEAKINGSTONE_yunmgrd
{
    meta:
        description = "Detects the SPEAKINGSTONE (yunmgrd) factory implant binary found in ZBT router firmware"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://vulncheck.com/blog/zbt-darklantern-speakingstone"
        hash = "b77811db4d218c65670a6c9a5b33c30ff81c6d779e15d658643138771178a818"
        severity = "critical"

    strings:
        $s1 = "zbtProtocol.c" ascii
        $s2 = "zbt protocol running" ascii
        $s3 = "/tmp/yunclient.conf" ascii
        $s4 = "cmcc_server" ascii
        $s5 = "dnshack" ascii
        $s6 = "/etc/exec/cmd" ascii
        $s7 = "setBackServer" ascii
        $s8 = "regMsg" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 1MB and
        4 of ($s*)
}
```

### YARA: DARKLANTERN infosrvd Binary

Detects the DARKLANTERN implant binary via published characteristic strings (Salt_171006_808290505, Allmac_171007_808290505, startlocalserve, revProto).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Strings sourced from VulnCheck's published binary analysis. No real sample available for validation. -->
```yara
rule ZBT_DARKLANTERN_infosrvd
{
    meta:
        description = "Detects the DARKLANTERN (infosrvd) factory implant binary found in ZBT router firmware"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://vulncheck.com/blog/zbt-darklantern-speakingstone"
        hash = "7e2e036fec2fe7ab4bbd43978d9296563894c92a112f5ac2f39957f12108e245"
        severity = "critical"

    strings:
        $s1 = "/etc/exec/cmd " ascii
        $s2 = "/etc/exec/sysinfo" ascii
        $s3 = "/tmp/cmd.log" ascii
        $s4 = "/tmp/info.txt" ascii
        $s5 = "Salt_171006_808290505" ascii
        $s6 = "Allmac_171007_808290505" ascii
        $s7 = "startlocalserve" ascii
        $s8 = "invalid request pkt" ascii
        $s9 = "revProto" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 1MB and
        4 of ($s*)
}
```

### YARA: inetdetect Launcher Binary

Detects the inetdetect watchdog binary that launches both DARKLANTERN and SPEAKINGSTONE implants.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. No sample test (requires all three strings co-occurring in an ELF <500KB — narrow condition). Strings from VulnCheck's published analysis. -->
```yara
rule ZBT_inetdetect_launcher
{
    meta:
        description = "Detects the inetdetect watchdog binary that launches both DARKLANTERN and SPEAKINGSTONE implants on ZBT routers"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://vulncheck.com/blog/zbt-darklantern-speakingstone"
        hash = "ae6c356f1f09260b859f84d994ef8423540a6c0bdf98510d86b85834283e4926"
        severity = "high"

    strings:
        $s1 = "yunmgrd" ascii
        $s2 = "infosrvd" ascii
        $s3 = "inetdetect" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 500KB and
        all of them
}
```

## Lessons Learned

1. **Supply-chain hardware compromise is real and at scale.** These are not targeted implants — they ship in mass-market routers sold on major e-commerce platforms. The economics of white-label manufacturing enable invisible compromise at the firmware level.

2. **Zero-authentication remote root is the norm, not the exception, in budget IoT.** Both implants offer full root command execution with no encryption, no authentication, and no access controls. DARKLANTERN's "authentication" — a hardcoded salt with an all-zeros wildcard MAC bypass — is security theater.

3. **OEM firmware opacity is the enabler.** The firmware developer (MoreQuick) is distinct from the hardware manufacturer (ZBT), which is distinct from the retail brands. No party in the chain audits the firmware. The `mqonu.com` salt string links MoreQuick directly to the backdoor code.

4. **Internet exposure multiplies risk.** 203 DARKLANTERN listeners were found Internet-exposed. Any device with UDP/9992 open to the Internet can be remotely commanded by anyone who sends the published 19-byte probe.

5. **Sinkhole data reveals the true footprint.** VulnCheck's sinkhole of the backup C2 captured 392 unique devices in three days — predominantly Chinese ISP customers on China Mobile. This suggests the implants may serve domestic surveillance or network management purposes in addition to (or instead of) foreign intelligence collection.

## Sources

- [VulnCheck — Chinese Implants in the Supply Chain](https://vulncheck.com/blog/zbt-darklantern-speakingstone) — primary technical analysis of DARKLANTERN and SPEAKINGSTONE implants
- [VulnCheck — ENDLESSDOORS Is Phoning Home](https://vulncheck.com/blog/zbt-endlessdoors) — prior disclosure of the ENDLESSDOORS implant (CVE-2026-66747) in ZBT routers
- [The Hacker News — China-Made ZBT Routers Ship with Two Factory-Installed Backdoors](https://thehackernews.com/2026/08/china-made-zbt-routers-ship-with-two.html) — coverage of the DARKLANTERN/SPEAKINGSTONE disclosure

---
*Report generated by Actioner*
