# Technical Analysis Report: DragonForce Ransomware Campaign Using Microsoft Teams TURN Relay for C2 (2026-06-18)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-18
Version: 1.1-REVISED

## Executive Summary

In December 2025, operators affiliated with the DragonForce ransomware-as-a-service (RaaS) cartel compromised a major U.S. services firm and deployed a novel Go-based backdoor tracked by Symantec as **Backdoor.Turn**. The backdoor represents the first known malware family to abuse Microsoft Teams' TURN (Traversal Using Relays around NAT) relay infrastructure for command-and-control communications. By obtaining anonymous visitor tokens from Microsoft's Skype-backed identity services and routing traffic through legitimate Microsoft TURN relay servers before establishing a QUIC session to the actual C2 server, the attackers ensured that network defenders only observed outbound connections to legitimate Microsoft infrastructure. The intrusion went undetected for approximately one to two months. The attack chain included DLL sideloading via VirtualBox executables, multi-vector BYOVD (Bring Your Own Vulnerable Driver) exploitation for security tool termination, Active Directory reconnaissance, lateral movement with stolen credentials, data exfiltration, and ultimately DragonForce ransomware deployment.

## Background: Microsoft Teams TURN Relay Infrastructure

Microsoft Teams relies on TURN (Traversal Using Relays around NAT) and STUN (Session Traversal Utilities for NAT) servers to facilitate real-time media connections between clients, particularly when direct peer-to-peer connectivity is blocked by firewalls or NAT configurations. These relay servers are operated by Microsoft and are trusted by most enterprise network security controls because they are essential for legitimate Teams audio/video functionality. The DragonForce operators weaponized this trust relationship by using the relay infrastructure as a proxy for C2 traffic, a technique inspired by the "Ghost Calls" research presented at Black Hat 2025. DragonForce (tracked by Symantec as developed by the group Hackledorb) has been active since at least June 2023 and has transitioned from a standard RaaS model to a formalized cartel structure, suggesting elevated organizational maturity and resources.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| June 2023 | DragonForce ransomware first observed active |
| December 2025 | Initial compromise of the victim's SQL/MSSQL server |
| December 2025 | Delivery of malicious ZIP archive containing VirtualBox executable and sideloaded DLL |
| December 2025 -- February 2026 | ~1-2 months of undetected presence; Backdoor.Turn deployed, AD enumeration, lateral movement |
| Pre-detection 2026 | BYOVD drivers deployed to disable security products; ransomware detonated |
| March 2026 | Huntress researchers independently document the Huawei HWAuidoOs2Ec.sys driver vulnerability |
| June 16, 2026 | Symantec publicly discloses the Backdoor.Turn technique and full attack chain |

## Root Cause: SQL/MSSQL Server Exploitation or Access Broker Credentials

Symantec reported that attackers gained initial access by exploiting a vulnerability in either an SQL or MSSQL server, though the specific CVE is unknown. An alternative possibility noted by researchers is that the attackers purchased access via an initial access broker. The exact vector remains unconfirmed.

## Technical Analysis of the Malicious Payload

### 1. Initial Delivery and DLL Sideloading

The attackers delivered a malicious ZIP archive to the compromised environment. The archive contained a legitimate VirtualBox executable paired with a trojanized DLL named **vboxrt.dll**. When the VirtualBox binary was executed, it sideloaded the malicious vboxrt.dll, which served as the downloader/stager component. The vboxrt.dll downloads additional code from a list of attacker-controlled servers (see Network IOCs below).

**Known ZIP archive hashes (SHA256):**
- `9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759`
- `cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a`

**Known sideloaded DLL hashes (SHA256):**
- `f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b`
- `d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e`

### 2. Backdoor.Turn -- Go-Based RAT with Teams TURN Relay C2

Backdoor.Turn is a custom Go-based remote access trojan (RAT) that implements a novel C2 communication channel. The backdoor is injected into the legitimate Sysinternals **DbgView64.exe** process.

**C2 protocol flow:**
1. The backdoor requests an anonymous Teams visitor token from Microsoft's Skype-backed identity services
2. Using this token, it initiates a connection through a legitimate Microsoft TURN relay server
3. The relay connection is then used to establish a direct QUIC session to the attacker's actual C2 server
4. To network monitoring tools, only outbound connections to Microsoft-owned IP ranges are visible

**Backdoor capabilities:**
- Command execution and arbitrary process creation
- Network scanning with TLS certificate and web page title capture
- LDAP/Active Directory search for domain mapping
- Credential-based lateral movement
- Browser credential theft (password extraction)

**Known Backdoor.Turn hashes (SHA256):**
- `821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6`
- `048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c`

**Shellcode containing Backdoor.Turn (SHA256):**
- `ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0`

### 3. C2 Infrastructure

The vboxrt.dll downloader contacts a list of compromised/attacker-controlled servers to retrieve additional payloads. The Backdoor.Turn component communicates via the Teams TURN relay to a dedicated C2 server.

**C2 domains used by the downloader:**
- projetosmecanicos[.]com[.]br
- socialbizsolutions[.]com
- professionalhomebasedbusiness[.]com
- safefire[.]jo
- glanz-gmbh[.]de
- turnkeyaiagents[.]com
- comunidadesparentais[.]com[.]br
- mysimerp[.]net

**C2 IP addresses:**
- 62[.]164[.]177[.]25 (Backdoor.Turn C2)

**Staging infrastructure:**
- hxxp://192[.]36[.]27[.]51/TechSupV18Fix3.zip (malicious ZIP download)

### 4. Defense Evasion -- Multi-Vector BYOVD

The operators deployed multiple vulnerable signed drivers to gain kernel-level access and terminate security products:

| Driver | Vulnerability | Purpose |
|--------|--------------|---------|
| Huawei HWAuidoOs2Ec.sys | Novel (documented March 2026 by Huntress) | "Havoc Process Terminator" -- novel technique to kill AV/EDR processes |
| Topaz Antifraud wsftprm.sys | CVE-2023-52271 | Kernel-level security tool termination |
| Tower of Fantasy GameDriverx64.sys | CVE-2025-61155 | Kernel-level security tool termination |
| K7 Security K7RKScan.sys | CVE-2025-1055 | Kernel-level security tool termination |
| ABYSSWORKER | Custom malicious driver | Masquerades as Palo Alto Networks driver |

**BYOVD driver hashes (SHA256):**
- `b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383` (GameDriverx64 vulnerable driver)
- `b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877` (K7 vulnerable driver)
- `252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab` (Topaz Antifraud vulnerable driver)
- `087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2` (Tower of Fantasy vulnerable driver)
- `8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2` (ABYSSWORKER driver)
- `65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951` (ABYSSWORKER driver)

### 5. Anti-Forensics / Evasion Techniques

- **TURN relay masking:** All C2 traffic appeared as connections to legitimate Microsoft Teams servers, evading standard network monitoring and threat intelligence blocklists
- **Process injection:** Backdoor injected into legitimate DbgView64.exe process
- **DLL sideloading:** Malicious DLL loaded by trusted VirtualBox binary
- **BYOVD:** Multiple vulnerable drivers used to terminate EDR/AV at kernel level
- **Firewall rule modifications:** Rules modified to permit C2 communication
- **LimitBlankPassword registry modification:** System configuration weakened for credential access
- **User/group creation:** Rogue accounts added for persistent access

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### File System

| Platform | File / Component | Hash (SHA256) | Description |
|----------|-----------------|---------------|-------------|
| Windows | Backdoor.Turn | `821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6` | Go-based RAT with Teams TURN relay C2 |
| Windows | Backdoor.Turn | `048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c` | Go-based RAT variant |
| Windows | Shellcode (Backdoor.Turn) | `ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0` | Shellcode containing Backdoor.Turn |
| Windows | Downloader (vboxrt.dll) | `82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b` | Sideloaded DLL downloader |
| Windows | Sideloaded DLL | `f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b` | VirtualBox sideloading DLL |
| Windows | Sideloaded DLL | `d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e` | VirtualBox sideloading DLL variant |
| Windows | Malicious ZIP | `9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759` | Delivery archive |
| Windows | Malicious ZIP | `cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a` | Delivery archive variant |
| Windows | GameDriverx64.sys | `b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383` | Vulnerable BYOVD driver (CVE-2025-61155) |
| Windows | K7RKScan.sys | `b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877` | Vulnerable BYOVD driver (CVE-2025-1055) |
| Windows | wsftprm.sys | `252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab` | Vulnerable BYOVD driver (CVE-2023-52271) |
| Windows | Tower of Fantasy driver | `087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2` | Vulnerable BYOVD driver |
| Windows | ABYSSWORKER | `8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2` | Custom malicious driver (Palo Alto impersonation) |
| Windows | ABYSSWORKER | `65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951` | Custom malicious driver variant |
| Windows | AV killer | `6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4` | Security product termination tool |
| Windows | AV killer | `6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e` | Security product termination tool variant |
| Windows | Havoc Process Terminator | `8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531` | Kernel-level process terminator |
| Windows | DragonForce ransomware | `e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22` | Ransomware encryptor payload |
| Windows | ADExplore | `142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219` | AD reconnaissance tool |
| Windows | ADExplore | `8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3` | AD reconnaissance tool variant |
| Windows | Netscan | `d0da2832ae1e13a98f7ce7e33a66c1b0d9797b81f69ece134e4462ea55ac923e` | Network reconnaissance tool |
| Windows | Netscan | `aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5` | Network reconnaissance tool variant |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | projetosmecanicos[.]com[.]br | Downloader C2 server |
| Domain | socialbizsolutions[.]com | Downloader C2 server |
| Domain | professionalhomebasedbusiness[.]com | Downloader C2 server |
| Domain | safefire[.]jo | Downloader C2 server |
| Domain | glanz-gmbh[.]de | Downloader C2 server |
| Domain | turnkeyaiagents[.]com | Downloader C2 server |
| Domain | comunidadesparentais[.]com[.]br | Downloader C2 server |
| Domain | mysimerp[.]net | Downloader C2 server |
| IP | 62[.]164[.]177[.]25 | Backdoor.Turn C2 server |
| IP | 192[.]36[.]27[.]51 | Staging server for malicious ZIP download |
| URL | hxxp://192[.]36[.]27[.]51/TechSupV18Fix3.zip | Malicious ZIP archive delivery URL |

### Behavioral

- **DLL sideloading:** VirtualBox executable loads malicious vboxrt.dll from non-standard path
- **Process injection:** Backdoor.Turn injected into DbgView64.exe; network connections from DbgView64.exe are highly anomalous
- **TURN relay abuse:** C2 traffic routed through Microsoft Teams TURN relay servers using anonymous visitor tokens and QUIC protocol
- **Driver loading:** Loading of HWAuidoOs2Ec.sys, wsftprm.sys, GameDriverx64.sys, K7RKScan.sys, or ABYSSWORKER outside their expected software contexts
- **Registry modification:** LimitBlankPassword value changed to weaken credential requirements
- **Account creation:** Rogue user accounts and group membership changes for persistence
- **Firewall modification:** Windows Firewall rules altered to permit C2 traffic

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Initial access via SQL/MSSQL server vulnerability exploitation |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Malicious vboxrt.dll sideloaded by legitimate VirtualBox executable |
| T1055 | Process Injection | Backdoor.Turn injected into DbgView64.exe process |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communications over QUIC protocol tunneled through Teams TURN relay |
| T1090.002 | Proxy: External Proxy | Teams TURN relay used as external proxy to mask C2 destination |
| T1105 | Ingress Tool Transfer | vboxrt.dll downloads additional payloads from attacker-controlled servers |
| T1068 | Exploitation for Privilege Escalation | BYOVD exploitation of multiple signed kernel drivers |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Kernel-level termination of EDR/AV via vulnerable drivers and Havoc Process Terminator |
| T1078 | Valid Accounts | Rogue user accounts created for persistent access |
| T1087.002 | Account Discovery: Domain Account | LDAP/AD enumeration using ADExplore for domain mapping |
| T1046 | Network Service Scanning | Network scanning with Netscan and TLS certificate/web page title capture |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Browser-stored credential extraction |
| T1021 | Remote Services | Lateral movement using stolen credentials |
| T1486 | Data Encrypted for Impact | DragonForce ransomware deployment for file encryption |
| T1112 | Modify Registry | LimitBlankPassword registry modification to weaken access controls |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | Firewall rules modified to permit C2 communications |

## Impact Assessment

This campaign demonstrates a significant advancement in C2 evasion techniques. The abuse of Microsoft Teams TURN relay infrastructure represents a novel threat that is difficult to detect with conventional network security monitoring because:

1. **Traffic appears legitimate:** Outbound connections go to Microsoft-owned IP ranges that are commonly allowlisted in enterprise environments
2. **Protocol blending:** The use of QUIC over TURN relay mimics legitimate Teams media traffic patterns
3. **Extended dwell time:** The attackers maintained access for 1-2 months before detection, indicating the technique effectively evades standard SOC monitoring
4. **Broad applicability:** Any organization using Microsoft Teams may be vulnerable to this C2 technique since TURN relay traffic is expected and trusted

The victim was described as a major U.S. services firm. The DragonForce cartel's evolution from a standard RaaS to a formalized cartel structure suggests this technique may be offered to multiple affiliates, potentially including the prolific Scattered Spider group.

## Detection & Remediation

### Immediate Detection

Check for the presence of known IOC hashes on endpoints:

```powershell
# Search for known Backdoor.Turn and related file hashes
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Get-FileHash -Algorithm SHA256 | Where-Object {
    $_.Hash -in @(
        "821DA79D727351DD67CE5DF7950E9A3DE6647A3CF474BB3A093F67507FED92A6",
        "048E18416177DE2EAD251ABDF4D89837F6807C6ABA4D5B1DEBE49ADFDECBF05C",
        "CE66B8221446C9B6D83F0CE6382F430E519601641E5DAAAF1CA7A8A8806CB0B0",
        "F174C19902523DCF005FA044B6598403A5E5C0A5982398D1BC0DCC5EC1CD351B",
        "E45B18C93D187AAC5C4486F57483BC87580E15DEF82A312BFB377FF16EB96B22"
    )
}
```

```powershell
# Check for vboxrt.dll outside legitimate VirtualBox paths
Get-ChildItem -Path C:\ -Recurse -Filter "vboxrt.dll" -ErrorAction SilentlyContinue |
    Where-Object { $_.DirectoryName -notlike "*Oracle\VirtualBox*" }
```

```powershell
# Check for anomalous driver loads
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=6} |
    Where-Object { $_.Message -match 'HWAuidoOs2Ec|wsftprm|GameDriverx64|K7RKScan|ABYSSWORKER' }
```

```powershell
# Check for network connections from DbgView64.exe
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} |
    Where-Object { $_.Message -match 'DbgView64.exe' }
```

### Remediation

1. **Containment:** Immediately isolate any endpoints showing IOC matches; block all C2 domains and IPs at the firewall/proxy
2. **Eradication:** Remove malicious DLLs, drivers, and injected processes; remove rogue user accounts created for persistence; restore modified firewall rules and registry settings
3. **Credential rotation:** Force password resets for all accounts on compromised systems and any accounts used for lateral movement; rotate service account credentials
4. **Driver blocklist:** Add the BYOVD driver hashes to Windows Defender Application Control (WDAC) driver blocklists
5. **Recovery:** Restore encrypted systems from clean backups; verify backup integrity before restoration

### Long-Term Hardening

1. **TURN relay monitoring:** Implement deep packet inspection or metadata analysis for TURN/STUN traffic to detect anomalous session patterns; consider restricting anonymous Teams visitor token issuance where feasible
2. **QUIC protocol visibility:** Ensure network security tools can inspect QUIC traffic; consider blocking or proxying QUIC on egress until inspection capability is mature
3. **Driver load monitoring:** Deploy WDAC policies to restrict kernel driver loading to known-good signed drivers; monitor Sysmon Event ID 6 for unexpected driver loads
4. **DLL sideloading prevention:** Implement application allowlisting; monitor for DLL loads from unexpected paths (Sysmon Event ID 7)
5. **SQL/MSSQL hardening:** Patch public-facing database servers; restrict network access; enable SQL audit logging

## Detection Rules

Detection rules cover the core attack artifacts: DLL sideloading of vboxrt.dll, process injection into DbgView64.exe, BYOVD driver loading (Huawei and others), known C2 domain resolution, C2 IP connectivity, and file-level indicators of Backdoor.Turn and DragonForce ransomware. Note that the TURN relay C2 technique itself is difficult to detect at the network level because traffic flows to legitimate Microsoft IPs; detection therefore focuses on host-level artifacts and known infrastructure indicators that will need rotation tracking.

### Sigma: Backdoor.Turn VBoxRT DLL Sideloading

Detects sideloading of vboxrt.dll from non-standard VirtualBox paths, the primary delivery mechanism for Backdoor.Turn.

compile: pass | confidence: high

<!-- audit: sigma check pass (T1574.002 tag flagged as pySigma false positive -- DLL Side-Loading is valid ATT&CK sub-technique); splunk convert pass; log_scale convert pass. Keys on specific DLL name + path exclusion. FP risk: portable VirtualBox installations. -->

```yaml
title: Backdoor.Turn VBoxRT DLL Sideloading via VirtualBox or DbgView
id: 75113c78-6ec7-4ec1-aee4-cae13b1f2136
status: experimental
description: >
    Detects DLL sideloading of vboxrt.dll alongside legitimate VirtualBox or
    DbgView executables, a technique used by DragonForce operators to deploy
    the Backdoor.Turn Go-based RAT via malicious ZIP archives.
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
    - https://securityaffairs.com/193801/security/dragonforce-hid-inside-microsoft-teams-and-nobody-noticed-for-two-months.html
author: Actioner
date: 2026-06-18
tags:
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection_dll:
        ImageLoaded|endswith: '\vboxrt.dll'
    filter_legitimate:
        ImageLoaded|startswith:
            - 'C:\Program Files\Oracle\VirtualBox\'
            - 'C:\Program Files (x86)\Oracle\VirtualBox\'
    condition: selection_dll and not filter_legitimate
falsepositives:
    - Portable VirtualBox installations running from non-standard paths
level: high
```

### Sigma: Suspicious Network Connection from DbgView64 Process

Detects outbound network connections from DbgView64.exe, the injection target for Backdoor.Turn.

compile: pass | confidence: high

<!-- audit: sigma check pass (0 issues); splunk convert pass; log_scale convert pass. DbgView64 is a local debugging tool with no legitimate networking. FP risk: negligible -- only if DbgView checks for updates. -->

```yaml
title: Suspicious Network Connection from DbgView64 Process
id: 285f1a4d-cd92-4491-9a5c-97229db6d1ee
status: experimental
description: >
    Detects outbound network connections from DbgView64.exe, the process into
    which Backdoor.Turn is injected during DragonForce ransomware operations.
    DbgView64 is a Sysinternals debugging tool that should not make network
    connections under normal usage.
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
    - https://www.securityweek.com/microsoft-teams-relay-servers-abused-in-dragonforce-ransomware-attack/
author: Actioner
date: 2026-06-18
tags:
    - attack.t1055
    - attack.t1071.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\DbgView64.exe'
        Initiated: 'true'
    condition: selection
falsepositives:
    - DbgView64 checking for updates if configured to do so
level: high
```

### Sigma: BYOVD Loading of Huawei HWAuidoOs2Ec Driver

Detects loading of the vulnerable Huawei driver exploited via the novel Havoc Process Terminator technique.

compile: pass | confidence: high

<!-- audit: sigma check pass (0 issues after tag fix); splunk convert pass; log_scale convert pass. Specific driver name. FP risk: legitimate Huawei audio hardware only. -->

```yaml
title: BYOVD Loading of Huawei HWAuidoOs2Ec Driver
id: d283b8cc-d789-4782-b72e-6861ac3b7e55
status: experimental
description: >
    Detects the loading of the vulnerable Huawei audio driver HWAuidoOs2Ec.sys,
    exploited by DragonForce operators using a novel Havoc Process Terminator
    technique to terminate security processes at the kernel level.
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
    - https://securityaffairs.com/193801/security/dragonforce-hid-inside-microsoft-teams-and-nobody-noticed-for-two-months.html
author: Actioner
date: 2026-06-18
tags:
    - attack.t1068
logsource:
    category: driver_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\HWAuidoOs2Ec.sys'
    condition: selection
falsepositives:
    - Legitimate Huawei audio driver installations on Huawei hardware
level: high
```

### Sigma: BYOVD Loading of Drivers Exploited by DragonForce

Detects loading of Topaz Antifraud, Tower of Fantasy, and K7 Security drivers exploited in this campaign.

compile: pass | confidence: medium

<!-- audit: sigma check pass (0 issues after tag fix); splunk convert pass; log_scale convert pass. Medium confidence because these drivers have legitimate uses in their respective software ecosystems. -->

```yaml
title: BYOVD Loading of Drivers Exploited by DragonForce
id: 9dd85597-949b-4cf2-8b0a-7a80ea8a077b
status: experimental
description: >
    Detects loading of vulnerable drivers exploited in DragonForce ransomware
    operations for BYOVD attacks, including Topaz Antifraud wsftprm.sys
    (CVE-2023-52271), Tower of Fantasy GameDriverx64.sys (CVE-2025-61155),
    and K7 Security K7RKScan.sys (CVE-2025-1055). These drivers are used
    to gain kernel-level access and terminate security products.
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
author: Actioner
date: 2026-06-18
tags:
    - attack.t1068
logsource:
    category: driver_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith:
            - '\wsftprm.sys'
            - '\GameDriverx64.sys'
            - '\K7RKScan.sys'
    condition: selection
falsepositives:
    - Legitimate Topaz Antifraud installations
    - Tower of Fantasy game installations
    - K7 Security antivirus products
level: medium
```

### Sigma: DNS Query to DragonForce Backdoor.Turn C2 Domains

Detects DNS resolution of known C2 domains used by the Backdoor.Turn downloader.

compile: pass | confidence: high

<!-- revision: applied critic fixes -- changed level from critical to high because these are compromised legitimate domains with pre-existing benign traffic -->
<!-- audit: sigma check pass (0 issues); splunk convert pass; log_scale convert pass. IOC-based rule keyed on 8 specific C2 domains. Values are not defanged per logsource-encoding guidance. Will need updates as domains rotate. -->

```yaml
title: DNS Query to DragonForce Backdoor.Turn C2 Domains
id: 5b4e83e3-4561-414c-a356-abfa8de09e69
status: experimental
description: >
    Detects DNS queries to known command-and-control domains used by
    DragonForce operators for the Backdoor.Turn downloader component
    (vboxrt.dll) to retrieve payloads. These are compromised legitimate
    domains, so some benign traffic is expected.
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
author: Actioner
date: 2026-06-18
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'projetosmecanicos.com.br'
            - 'socialbizsolutions.com'
            - 'professionalhomebasedbusiness.com'
            - 'safefire.jo'
            - 'glanz-gmbh.de'
            - 'turnkeyaiagents.com'
            - 'comunidadesparentais.com.br'
            - 'mysimerp.net'
    condition: selection
falsepositives:
    - Legitimate access to these domains prior to their compromise
level: high
```

### YARA: Backdoor.Turn and DragonForce File Detection

Three YARA rules covering Backdoor.Turn RAT binaries (behavioral + C2 domain strings), the vboxrt.dll downloader, and the DragonForce ransomware encryptor.

compile: pass | confidence: high (Backdoor.Turn C2 domain match), medium (Backdoor.Turn behavioral), high (Downloader), low (Ransomware)

<!-- revision: applied critic fixes -- added PE gate (uint16(0)==0x5A4D) to C2-only branch in Malware_DragonForce_Backdoor_Turn to prevent matching threat intel docs/browser caches; fixed hash2 meta keys to duplicate hash keys in Turn and Downloader rules; tightened Malware_DragonForce_Ransomware to require $ransom1+$ransom2 together, removed standalone $ransom3 match, lowered confidence to low -->
<!-- audit: yarac compile pass (exit 0). Malware_DragonForce_Backdoor_Turn matches on either PE with embedded C2 domains (high confidence) or Go binary + TURN/QUIC + capability strings combination (medium, broader). Malware_DragonForce_Backdoor_Turn_Downloader requires PE + C2 domain + sideload indicator. Malware_DragonForce_Ransomware requires PE + DragonForce name + .dragonforce extension + crypto API -- low confidence due to limited unique strings. -->

```yara
rule Malware_DragonForce_Backdoor_Turn
{
    meta:
        description = "Detects Backdoor.Turn Go-based RAT used by DragonForce ransomware operators, which abuses Microsoft Teams TURN relay infrastructure for C2"
        author = "Actioner"
        date = "2026-06-18"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        hash = "821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6"
        hash = "048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $go1 = "runtime.main" ascii
        $go2 = "main.main" ascii

        $turn1 = "TURN" ascii fullword
        $turn2 = "STUN" ascii fullword
        $turn3 = "visitor" ascii
        $turn4 = "relay" ascii
        $turn5 = "teams" ascii nocase

        $quic1 = "quic-go" ascii
        $quic2 = "quic.Config" ascii
        $quic3 = "QUIC" ascii fullword

        $c2_1 = "projetosmecanicos.com.br" ascii
        $c2_2 = "socialbizsolutions.com" ascii
        $c2_3 = "professionalhomebasedbusiness.com" ascii
        $c2_4 = "safefire.jo" ascii
        $c2_5 = "glanz-gmbh.de" ascii
        $c2_6 = "turnkeyaiagents.com" ascii
        $c2_7 = "comunidadesparentais.com.br" ascii
        $c2_8 = "mysimerp.net" ascii

        $cap1 = "CreateProcess" ascii
        $cap2 = "ldap" ascii nocase
        $cap3 = "NetScan" ascii
        $cap4 = "credential" ascii nocase

    condition:
        filesize < 30MB and
        (
            (uint16(0) == 0x5A4D and 3 of ($c2_*)) or
            (
                all of ($go*) and
                2 of ($turn*) and
                1 of ($quic*) and
                1 of ($cap*)
            )
        )
}

rule Malware_DragonForce_Backdoor_Turn_Downloader
{
    meta:
        description = "Detects the vboxrt.dll downloader DLL used in DragonForce Backdoor.Turn sideloading attacks"
        author = "Actioner"
        date = "2026-06-18"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        hash = "f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b"
        hash = "d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e"
        tlp = "WHITE"
        severity = "high"

    strings:
        $s1 = "vboxrt.dll" ascii wide nocase
        $s2 = "VirtualBox" ascii wide
        $s3 = "DbgView" ascii wide

        $dl1 = "URLDownloadToFile" ascii
        $dl2 = "InternetOpenUrl" ascii
        $dl3 = "HttpSendRequest" ascii
        $dl4 = "WinHttpOpen" ascii

        $c2_1 = "projetosmecanicos.com.br" ascii
        $c2_2 = "socialbizsolutions.com" ascii
        $c2_3 = "professionalhomebasedbusiness.com" ascii
        $c2_4 = "turnkeyaiagents.com" ascii
        $c2_5 = "mysimerp.net" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($c2_*) and 1 of ($s*)) or
            (1 of ($s*) and 2 of ($dl*) and 1 of ($c2_*))
        )
}

rule Malware_DragonForce_Ransomware
{
    meta:
        description = "Detects DragonForce ransomware binary based on known hash"
        author = "Actioner"
        date = "2026-06-18"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        hash = "e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $ransom1 = "DragonForce" ascii wide nocase
        $ransom2 = ".dragonforce" ascii wide
        $encrypt1 = "CryptEncrypt" ascii
        $encrypt2 = "BCryptEncrypt" ascii
        $encrypt3 = "CryptGenRandom" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $ransom1 and $ransom2 and
        1 of ($encrypt*)
}
```

### Suricata: DragonForce C2 Domain and IP Detection

Ten Suricata rules covering DNS queries to all eight known C2 domains, TCP connectivity to the Backdoor.Turn C2 IP, and HTTP access to the staging server.

compile: pass | confidence: high

<!-- revision: applied critic fixes -- changed HTTP staging rule from generic .zip match to specific /TechSupV18Fix3.zip URI, bumped rev to 2 -->
<!-- audit: suricata -T pass (exit 0, "Configuration provided was successfully loaded"). IOC-based rules. DNS rules use dns.query sticky buffer with nocase. IP rules use direct destination match. Domains and IPs will need rotation tracking. -->

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain projetosmecanicos.com.br"; flow:to_server; dns.query; content:"projetosmecanicos.com.br"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-18; sid:2100101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain socialbizsolutions.com"; flow:to_server; dns.query; content:"socialbizsolutions.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-18; sid:2100102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain professionalhomebasedbusiness.com"; flow:to_server; dns.query; content:"professionalhomebasedbusiness.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-18; sid:2100103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain safefire.jo"; flow:to_server; dns.query; content:"safefire.jo"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-18; sid:2100104; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain glanz-gmbh.de"; flow:to_server; dns.query; content:"glanz-gmbh.de"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-18; sid:2100105; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain turnkeyaiagents.com"; flow:to_server; dns.query; content:"turnkeyaiagents.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-18; sid:2100106; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain comunidadesparentais.com.br"; flow:to_server; dns.query; content:"comunidadesparentais.com.br"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-18; sid:2100107; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain mysimerp.net"; flow:to_server; dns.query; content:"mysimerp.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-18; sid:2100108; rev:1;)

alert tcp $HOME_NET any -> 62.164.177.25 any (msg:"Actioner - TCP Connection to DragonForce Backdoor.Turn C2 IP 62.164.177.25"; flow:established,to_server; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-18; sid:2100109; rev:1;)

alert http $HOME_NET any -> 192.36.27.51 any (msg:"Actioner - HTTP Request to DragonForce Staging IP for TechSupV18Fix3.zip"; flow:established,to_server; http.uri; content:"/TechSupV18Fix3.zip"; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-18; sid:2100110; rev:2;)
```

## Lessons Learned

1. **Trusted infrastructure is not immune to abuse:** The abuse of Microsoft Teams TURN relay servers demonstrates that traffic to trusted cloud providers cannot be blindly allowlisted. Organizations need visibility into the nature of connections to cloud services, not just the destination IP/domain.

2. **QUIC protocol creates blind spots:** The use of QUIC (UDP-based, encrypted by default) for the final C2 hop makes traditional TLS inspection ineffective. Organizations should evaluate their QUIC inspection capabilities and consider restricting the protocol at egress where business requirements allow.

3. **Multi-vector BYOVD is the new normal:** The use of five different vulnerable drivers (including a novel Huawei exploitation) shows that attackers maintain arsenals of BYOVD options. Static driver blocklists must be continuously updated, and organizations should move toward WDAC-based driver allowlisting.

4. **DLL sideloading remains highly effective:** The pairing of trusted executables (VirtualBox, DbgView64) with malicious DLLs continues to bypass application control and EDR heuristics. Monitoring DLL loads from unexpected paths (Sysmon Event ID 7) remains a critical detection strategy.

5. **Anonymous authentication tokens broaden the attack surface:** Microsoft's issuance of anonymous visitor tokens for Teams services provided the initial foothold for the TURN relay abuse. Cloud service providers should review where anonymous or low-privilege tokens grant access to infrastructure that can be repurposed.

## Sources

- [Symantec/Broadcom - Hidden in Teams: DragonForce Attackers Weaponize Microsoft Teams Relays to Stay Hidden](https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor) -- primary technical analysis with full IOC listing, attack chain, and Backdoor.Turn details
- [Security Affairs - DragonForce Hid Inside Microsoft Teams and Nobody Noticed for Two Months](https://securityaffairs.com/193801/security/dragonforce-hid-inside-microsoft-teams-and-nobody-noticed-for-two-months.html) -- news coverage with attack timeline and BYOVD details
- [SecurityWeek - Microsoft Teams Relay Servers Abused in DragonForce Ransomware Attack](https://www.securityweek.com/microsoft-teams-relay-servers-abused-in-dragonforce-ransomware-attack/) -- news coverage with attribution details and capability summary
- [The Register - Crooks Found a New Way to Collaborate Using Teams](https://www.theregister.com/cyber-crime/2026/06/16/crooks-found-a-new-way-to-collaborate-using-teams-by-hiding-command-and-control-traffic/5256296) -- news coverage linking Scattered Spider and cartel model
- [BleepingComputer - Ransomware Gang Abuses Microsoft Teams Relays to Hide Malicious Traffic](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/) -- additional news coverage with C2 protocol details
- [Help Net Security - Cybercriminals Mask Malicious Communications Through Microsoft Teams Relays](https://www.helpnetsecurity.com/2026/06/16/dragonforce-microsoft-teams-malware-backdoor-turn/) -- news coverage with BYOVD driver inventory

---
*Report generated by Actioner*
