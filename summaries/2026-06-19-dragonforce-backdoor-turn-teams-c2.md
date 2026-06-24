# Technical Analysis Report: DragonForce Ransomware Deploys Backdoor.Turn via Microsoft Teams TURN Relay C2 (2026-06-19)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-19
Version: 2 (FINAL)

## Executive Summary

DragonForce ransomware operators (tracked as Hackledorb) deployed a novel Go-based remote access trojan called **Backdoor.Turn** that conceals command-and-control communications within Microsoft Teams relay (TURN) infrastructure. This represents the **first known case** of malware abusing Microsoft Teams TURN relay servers for C2 masking. The backdoor obtains an anonymous Teams visitor token from Microsoft's Skype-backed identity services, uses legitimate Microsoft TURN relay infrastructure to set up connections, and then establishes a direct QUIC session to the attacker's actual C2 server. To network defenders, the only visible traffic is outbound connections to legitimate Microsoft Teams servers.

The campaign targeted a major U.S. services firm, with initial compromise occurring in **December 2025** via exploitation of a SQL/MSSQL vulnerability. The attackers maintained access for **one to two months** undetected before deploying DragonForce ransomware. Post-ransomware, Backdoor.Turn was installed as a persistence mechanism for potential follow-up intrusions. The attack chain included DLL sideloading via legitimate VirtualBox executables, BYOVD (Bring Your Own Vulnerable Driver) defense evasion using four different vulnerable drivers (including a novel exploitation of Huawei's HWAuidoOs2Ec.sys), and a custom malicious driver (ABYSSWORKER) masquerading as a Palo Alto product. Symantec researcher Thibaut Passilly presented these findings at the Area41 Cybersecurity Conference in Zurich on June 18, 2026.

## Background: Microsoft Teams TURN Relay Infrastructure

Microsoft Teams uses TURN (Traversal Using Relays around NAT) relay servers as part of its real-time communication infrastructure. TURN relays help establish media connections between Teams clients when direct peer-to-peer connections are not possible due to NAT or firewall restrictions. These relays are operated by Microsoft on legitimate infrastructure and are widely whitelisted by enterprise firewalls. The Backdoor.Turn authors recognized that by obtaining an anonymous visitor token and routing initial connection setup through these TURN relays, their C2 traffic would blend in with legitimate Teams traffic, making detection extremely difficult. This technique was inspired by the "Ghost Calls" research concept but represents its first weaponization in the wild.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| December 2025 | Initial compromise via SQL/MSSQL vulnerability exploitation |
| December 2025 | PowerShell used to download ZIP archive from staging IP (192.36.27[.]51) disguised as tech support hotfix |
| December 2025 | DLL sideloading via legitimate VirtualBox executable; reconnaissance and persistence established |
| December 2025 – February 2026 | BYOVD attacks to disable security software; lateral movement via stolen credentials |
| ~February 2026 | DragonForce ransomware deployment; data exfiltration and encryption |
| Post-ransomware | Backdoor.Turn deployed and injected into DbgView64.exe for persistent access |
| March 2026 | Huntress independently documents HWAuidoOs2Ec.sys vulnerability (DragonForce had exploited it months earlier) |
| June 16, 2026 | Symantec/Broadcom publishes technical analysis |
| June 18, 2026 | Findings presented at Area41 Cybersecurity Conference, Zurich |

## Root Cause: SQL/MSSQL Server Vulnerability Exploitation

Initial access was achieved through exploitation of a vulnerability in a SQL or MSSQL server. The exact CVE is unknown; the Symantec report notes the possibility that access may have been acquired from an initial access broker (IAB). Once inside, the attackers used PowerShell to download a ZIP archive (`TechSupV18Fix3.zip`) from `hxxp://192.36.27[.]51/TechSupV18Fix3.zip`, disguised as a tech support hotfix.

## Technical Analysis of the Malicious Payload

### 1. Initial Loader: DLL Sideloading via VirtualBox

The downloaded ZIP archive contained a legitimate VirtualBox executable paired with a malicious DLL designed for sideloading. The attackers abused the VirtualBox executable to load a malicious DLL (identified by SHA256 `f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b` for one variant and `d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e` for another). The rogue DLL performed reconnaissance, established persistence, and initiated the defense evasion chain.

### 2. Defense Evasion: BYOVD and ABYSSWORKER

The attackers deployed multiple vulnerable drivers to disable security software:

| Driver | CVE | Description |
|--------|-----|-------------|
| HWAuidoOs2Ec.sys (Huawei audio driver) | None assigned at time of attack | Novel exploitation via custom "Havoc Process Terminator" tool |
| wsftprm.sys (Topaz Antifraud) | CVE-2023-52271 | Known vulnerable driver |
| GameDriverx64.sys (Tower of Fantasy) | CVE-2025-61155 | Known vulnerable driver |
| K7RKScan.sys (K7 Security) | CVE-2025-1055 | Known vulnerable driver |

Additionally, the attackers deployed **ABYSSWORKER**, a custom malicious kernel driver masquerading as a legitimate Palo Alto Networks product, and a custom **AV killer** tool to terminate security processes.

### 3. C2 Infrastructure: Backdoor.Turn via Teams TURN Relay

Backdoor.Turn is a Go-based RAT with a novel C2 communication mechanism:

1. **Token Acquisition**: The backdoor requests an anonymous visitor token from Microsoft Teams/Skype backend identity services
2. **TURN Relay Setup**: Uses the legitimate Microsoft TURN relay infrastructure to set up the initial connection
3. **QUIC Session**: Establishes a direct QUIC session to the attacker's actual C2 server at `62.164.177[.]25`
4. **Traffic Masking**: All C2 traffic visible to defenders appears as legitimate outbound connections to Microsoft Teams servers

The backdoor was injected into the legitimate `DbgView64.exe` process (Sysinternals Debugging Tools for Windows) to further blend with legitimate system administration activity.

**Known C2 domains:**
- projetosmecanicos[.]com[.]br
- socialbizsolutions[.]com
- professionalhomebasedbusiness[.]com
- safefire[.]jo
- glanz-gmbh[.]de
- turnkeyaiagents[.]com
- comunidadesparentais[.]com[.]br
- mysimerp[.]net

### 4. Backdoor Capabilities

Backdoor.Turn provides full RAT functionality:
- **Command execution and process creation**
- **Network scanning** with TLS certificate capture and web page title extraction
- **LDAP/Active Directory search** for comprehensive domain mapping
- **Credential-based lateral movement**
- **Browser credential theft**

### 5. Anti-Forensics / Evasion Techniques

- C2 traffic hidden within legitimate Microsoft Teams TURN relay connections
- Process injection into legitimate DbgView64.exe
- DLL sideloading via signed VirtualBox executables
- BYOVD to disable endpoint security products
- Modified firewall rules to facilitate remote access
- Modified LimitBlankPassword configuration
- Custom malicious driver (ABYSSWORKER) masquerading as Palo Alto product

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| Platform | Description | Hash (SHA256) |
|----------|-------------|---------------|
| Windows | Downloader | 82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b |
| Windows | Backdoor.Turn (variant 1) | 821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6 |
| Windows | Backdoor.Turn (variant 2) | 048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c |
| Windows | Shellcode/Backdoor.Turn | ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0 |
| Windows | VirtualBox sideloaded DLL (variant 1) | f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b |
| Windows | VirtualBox sideloaded DLL (variant 2) | d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e |
| Windows | GameDriverx64 (BYOVD) | b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383 |
| Windows | Tower of Fantasy driver (BYOVD) | 087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2 |
| Windows | K7 driver (BYOVD) | b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877 |
| Windows | Topaz Antifraud driver (BYOVD) | 252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab |
| Windows | ABYSSWORKER driver (variant 1) | 8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2 |
| Windows | ABYSSWORKER driver (variant 2) | 65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951 |
| Windows | AV killer (variant 1) | 6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4 |
| Windows | AV killer (variant 2) | 6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e |
| Windows | Havoc Process Terminator | 8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531 |
| Windows | ADExplore (variant 1) | 142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219 |
| Windows | ADExplore (variant 2) | 8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3 |
| Windows | Netscan (variant 1) | d0da2832ae1e13a98f7ce7e33a66c1b0d9797b81f69ece134e4462ea55ac923e |
| Windows | Netscan (variant 2) | aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5 |
| Windows | Malicious ZIP (variant 1) | 9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759 |
| Windows | Malicious ZIP (variant 2) | cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a |
| Windows | DragonForce ransomware | e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22 |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 192.36.27[.]51 | Staging server — ZIP payload download |
| IP | 62.164.177[.]25 | Backdoor.Turn C2 server |
| Domain | projetosmecanicos[.]com[.]br | C2 domain |
| Domain | socialbizsolutions[.]com | C2 domain |
| Domain | professionalhomebasedbusiness[.]com | C2 domain |
| Domain | safefire[.]jo | C2 domain |
| Domain | glanz-gmbh[.]de | C2 domain |
| Domain | turnkeyaiagents[.]com | C2 domain |
| Domain | comunidadesparentais[.]com[.]br | C2 domain |
| Domain | mysimerp[.]net | C2 domain |
| URL | hxxp://192.36.27[.]51/TechSupV18Fix3.zip | Malicious ZIP download URL |

### Behavioral

- DbgView64.exe initiating outbound network connections (process injection indicator)
- VirtualBox executables spawning cmd.exe, powershell.exe, or reconnaissance tools (DLL sideloading indicator)
- Loading of known vulnerable drivers (HWAuidoOs2Ec.sys, wsftprm.sys, GameDriverx64.sys, K7RKScan.sys)
- PowerShell downloading ZIP archives from external IPs
- Outbound connections to Microsoft Teams TURN relay infrastructure from non-Teams processes

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Initial access via SQL/MSSQL server vulnerability |
| T1059.001 | PowerShell | PowerShell used to download malicious ZIP archive from staging IP |
| T1574.002 | DLL Side-Loading | Legitimate VirtualBox executable used to load malicious DLL |
| T1055 | Process Injection | Backdoor.Turn injected into legitimate DbgView64.exe process |
| T1068 | Exploitation for Privilege Escalation | Multiple vulnerable drivers exploited for privilege escalation |
| T1562.001 | Disable or Modify Tools | BYOVD technique used to disable endpoint security software; custom AV killer deployed |
| T1036.005 | Match Legitimate Name or Location | ABYSSWORKER driver masquerading as legitimate Palo Alto product |
| T1105 | Ingress Tool Transfer | ZIP payload downloaded from staging IP 192.36.27[.]51 |
| T1071.001 | Web Protocols | C2 communications disguised within Microsoft Teams TURN relay protocol traffic |
| T1572 | Protocol Tunneling | QUIC session tunneled through Microsoft Teams TURN relay infrastructure |
| T1087.002 | Domain Account | Active Directory enumeration and LDAP search for domain mapping |
| T1018 | Remote System Discovery | Network scanning with TLS certificate capture and web page title extraction |
| T1555 | Credentials from Password Stores | Browser credential theft |
| T1486 | Data Encrypted for Impact | DragonForce ransomware deployment |

## Impact Assessment

**Breadth**: Targeted attack against a single major U.S. services firm (specific organization undisclosed). DragonForce operates as a RaaS cartel, and the Backdoor.Turn technique could be adopted by affiliates or other groups.

**Depth**: Full network compromise — initial access, privilege escalation, defense evasion, lateral movement, data exfiltration, and ransomware deployment. Post-ransomware persistent backdoor indicates intent for re-entry or access resale.

**Stealth**: Exceptionally high. The Teams TURN relay C2 masking technique is novel and designed specifically to evade network monitoring by hiding within legitimate Microsoft traffic. The 1-2 month dwell time before detection confirms its effectiveness.

**Broader significance**: This is the first documented weaponization of Microsoft Teams TURN relay infrastructure for C2. The technique could be replicated against any organization that whitelists Microsoft Teams traffic (effectively all enterprises). Detection requires visibility beyond traditional network monitoring.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for known Backdoor.Turn hashes on endpoint
Get-FileHash -Algorithm SHA256 -Path (Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -File) | Where-Object {
    $_.Hash -in @(
        "821DA79D727351DD67CE5DF7950E9A3DE6647A3CF474BB3A093F67507FED92A6",
        "048E18416177DE2EAD251ABDF4D89837F6807C6ABA4D5B1DEBE49ADFDECBF05C",
        "CE66B8221446C9B6D83F0CE6382F430E519601641E5DAAAF1CA7A8A8806CB0B0"
    )
}

# Check for DbgView64.exe with network connections (Sysmon Event ID 3)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=3} | Where-Object {
    $_.Properties[4].Value -like '*DbgView64.exe'
}

# Check for vulnerable driver loading (Sysmon Event ID 6 or 7)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=7} | Where-Object {
    $_.Properties[5].Value -match 'HWAuidoOs2Ec\.sys|wsftprm\.sys|GameDriverx64\.sys|K7RKScan\.sys'
}

# Check DNS logs for C2 domains
Get-DnsClientCache | Where-Object {
    $_.Entry -match 'socialbizsolutions\.com|turnkeyaiagents\.com|safefire\.jo|glanz-gmbh\.de|mysimerp\.net|professionalhomebasedbusiness\.com'
}

# Check for connections to known C2/staging IPs
Get-NetTCPConnection | Where-Object {
    $_.RemoteAddress -in @('62.164.177.25', '192.36.27.51')
}
```

### Remediation

1. **Containment**: Immediately isolate affected systems from the network. Block C2 IPs (62.164.177[.]25, 192.36.27[.]51) and all eight C2 domains at the firewall/proxy level.
2. **Eradication**: Scan all endpoints for the 21 SHA256 hashes listed in the IOC section. Remove Backdoor.Turn, ABYSSWORKER, and all associated vulnerable drivers. Rebuild compromised systems from clean images.
3. **Recovery**: Restore encrypted data from offline backups. Rotate all domain credentials, particularly service accounts exposed during AD enumeration. Revoke all active sessions and force re-authentication.
4. **Secret rotation**: Reset all passwords for accounts that were active on compromised systems. Rotate Kerberos krbtgt key twice. Invalidate all existing tokens and certificates.

### Long-Term Hardening

- **Driver signing enforcement**: Enable Hypervisor-Protected Code Integrity (HVCI) to prevent loading of vulnerable drivers via BYOVD attacks.
- **Application control**: Deploy Windows Defender Application Control (WDAC) policies to block execution of unauthorized VirtualBox executables and restrict DLL sideloading.
- **Network segmentation**: Restrict SQL/MSSQL server exposure to only required networks. Implement micro-segmentation for critical database servers.
- **Teams traffic inspection**: Deploy decryption and deep packet inspection for Teams/TURN traffic at the network edge. Monitor for non-Teams processes establishing connections to Teams TURN relay infrastructure.
- **Sysmon deployment**: Ensure Sysmon is configured to log process creation (Event 1), network connections (Event 3), and driver loads (Event 6/7) for detection of the full attack chain.

## Detection Rules

The rules below cover three detection layers: endpoint (Sigma for process/driver/network events), network (Suricata and Snort for C2 domain/IP traffic), and file (YARA for binary identification). The primary detection gap is the Teams TURN relay abuse itself -- since the C2 setup traverses legitimate Microsoft infrastructure, network-level detection must focus on the known C2 endpoints rather than the relay technique. Process-level detection of DbgView64.exe with network activity is the most reliable behavioral indicator.

### Sigma: VirtualBox DLL Sideloading for Backdoor Deployment

Detects VirtualBox processes spawning reconnaissance or attack tools, indicating DLL sideloading abuse as seen in the DragonForce deployment chain.

**compile: pass | confidence: high**

```yaml
title: Suspicious VirtualBox DLL Sideloading for Backdoor Deployment
id: 7a3e1f4b-9c2d-4e8a-b5f6-1d0e3c7a9b2f
status: experimental
description: >
    Detects DLL sideloading via legitimate VirtualBox executable loading a
    malicious DLL, as observed in DragonForce campaigns deploying Backdoor.Turn.
    The attackers abused VirtualBox executables to sideload malicious DLLs
    that performed reconnaissance, established persistence, and disabled
    security software.
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
author: Actioner
date: 2026-06-19
tags:
    - attack.t1574
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\VBoxSVC.exe'
            - '\VirtualBox.exe'
            - '\VirtualBoxVM.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\whoami.exe'
            - '\net.exe'
            - '\nltest.exe'
            - '\DbgView64.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate VirtualBox automation scripts
    - VirtualBox Guest Additions installation
level: high
```

<!-- audit: sigma check pass, sigma convert --without-pipeline -t splunk pass, sigma convert --without-pipeline -t log_scale pass. Tags use parent T1574 (T1574.002 trips InvalidATTACKTagIssue in pySigma). Field names match Sysmon process_creation schema. No defanged values in detection. -->

### Sigma: DragonForce BYOVD Vulnerable Driver Loading

Detects loading of specific vulnerable drivers exploited by DragonForce for defense evasion via the BYOVD technique.

**compile: pass | confidence: medium**

```yaml
title: DragonForce BYOVD Vulnerable Driver Loading
id: 8b4f2e5c-0d3a-4f9b-c6e7-2a1f4d8b0c3e
status: experimental
description: >
    Detects loading of vulnerable drivers abused by DragonForce ransomware
    operators for defense evasion via BYOVD technique. Includes Huawei
    HWAuidoOs2Ec.sys, Topaz wsftprm.sys, Tower of Fantasy GameDriverx64.sys,
    and K7 Security K7RKScan.sys drivers exploited in this campaign.
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
author: Actioner
date: 2026-06-19
tags:
    - attack.t1068
    - attack.t1562.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith:
            - '\HWAuidoOs2Ec.sys'
            - '\wsftprm.sys'
            - '\GameDriverx64.sys'
            - '\K7RKScan.sys'
    condition: selection
falsepositives:
    - Legitimate Huawei audio driver installations
    - Legitimate Topaz Antifraud software
    - Tower of Fantasy game installations
    - K7 Security antivirus installations
level: medium
```

<!-- audit: sigma check pass (0 errors, 0 condition errors; medium-severity InvalidATTACKTagIssue on attack.t1562.001 is a pySigma validator quirk, not an error — subtechnique is valid ATT&CK). sigma convert --without-pipeline -t splunk pass, -t log_scale pass. Confidence downgraded to medium: 3 of 4 drivers (K7, Topaz, Tower of Fantasy) are legitimate software components with broad install bases, creating a significant FP surface. T1562.001 tag added per review — BYOVD is used to disable security tools. -->

### Sigma: DNS Query to DragonForce Backdoor.Turn C2 Domain

Detects DNS queries to the eight known C2 domains used by Backdoor.Turn.

**compile: pass | confidence: high**

```yaml
title: DNS Query to DragonForce Backdoor.Turn C2 Domain
id: 9c5e3f6d-1a4b-5e0c-d7f8-3b2e5a9c1d4f
status: experimental
description: >
    Detects DNS queries to known command-and-control domains used by the
    DragonForce Backdoor.Turn malware campaign. These domains served as
    C2 endpoints for the Go-based RAT that abused Microsoft Teams TURN
    relay infrastructure.
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
author: Actioner
date: 2026-06-19
tags:
    - attack.t1071.001
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
    - Legitimate access to these compromised domains before takedown
level: critical
```

<!-- audit: sigma check pass (0 errors, 0 issues). sigma convert --without-pipeline -t splunk and -t log_scale both pass. Domains not defanged per logsource-encoding.md (rules use real values). endswith used for subdomain coverage. -->

### Sigma: Suspicious DbgView64 Process with Network Connections

Detects DbgView64.exe making outbound network connections, which is highly anomalous for this debugging tool and indicates process injection by Backdoor.Turn.

**compile: pass | confidence: medium**

```yaml
title: Suspicious DbgView64 Process with Network Connections
id: 0d6f4e7a-2b5c-6f1d-e8a9-4c3f6b0d2e5a
status: experimental
description: >
    Detects DbgView64.exe making network connections, which is anomalous
    for this debugging tool. DragonForce operators injected Backdoor.Turn
    into the legitimate DbgView64.exe process to establish C2 communications
    via Microsoft Teams TURN relay infrastructure.
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
author: Actioner
date: 2026-06-19
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
    - DbgView64 checking for software updates (rare)
level: medium
```

<!-- audit: sigma check pass (0 errors, 0 issues). sigma convert --without-pipeline -t splunk pass, -t log_scale pass. Confidence downgraded to medium: behavioral/TTP detection at this altitude (process name + network activity) caps at medium. DbgView64 can legitimately check for updates, though this is rare. -->

### Sigma: PowerShell Download from DragonForce Staging IP

Detects PowerShell downloading content from the known DragonForce staging IP address used to deliver the malicious ZIP payload.

**compile: pass | confidence: high**

```yaml
title: PowerShell Download of Suspicious ZIP from Known DragonForce Staging IP
id: 1e7a5f8b-3c6d-7a2e-f9b0-5d4e7c1a3f6b
status: experimental
description: >
    Detects PowerShell downloading a ZIP archive from the known staging IP
    used by DragonForce operators. The attackers used PowerShell to download
    a ZIP archive disguised as a tech support hotfix containing a VirtualBox
    executable and malicious DLL for sideloading.
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
author: Actioner
date: 2026-06-19
tags:
    - attack.t1105
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith: '\powershell.exe'
    selection_cmdline:
        CommandLine|contains|all:
            - '192.36.27.51'
            - '.zip'
    condition: selection_process and selection_cmdline
falsepositives:
    - Unlikely — specific IP indicator
level: critical
```

<!-- audit: sigma check pass (0 errors, 0 issues). sigma convert --without-pipeline -t splunk pass. IP not defanged per logsource-encoding.md. Narrow rule keyed on specific staging IP + ZIP extension in command line. -->

### Suricata: DNS Queries to DragonForce C2 Domains

Eight rules detecting DNS queries to all known Backdoor.Turn C2 domains.

**compile: pass | confidence: high**

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain socialbizsolutions.com"; flow:to_server; dns.query; content:"socialbizsolutions.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-19; sid:2100101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain turnkeyaiagents.com"; flow:to_server; dns.query; content:"turnkeyaiagents.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-19; sid:2100102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain glanz-gmbh.de"; flow:to_server; dns.query; content:"glanz-gmbh.de"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-19; sid:2100103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain safefire.jo"; flow:to_server; dns.query; content:"safefire.jo"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-19; sid:2100104; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain mysimerp.net"; flow:to_server; dns.query; content:"mysimerp.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-19; sid:2100105; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain professionalhomebasedbusiness.com"; flow:to_server; dns.query; content:"professionalhomebasedbusiness.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-19; sid:2100106; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain projetosmecanicos.com.br"; flow:to_server; dns.query; content:"projetosmecanicos.com.br"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-19; sid:2100109; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DragonForce Backdoor.Turn C2 Domain comunidadesparentais.com.br"; flow:to_server; dns.query; content:"comunidadesparentais.com.br"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-19; sid:2100110; rev:1;)
```

<!-- audit: suricata -T -S pass (exit 0, Suricata 7.0.3). Uses dns.query dot-notation sticky buffer correctly. All required fields present (msg, sid, rev). Each domain gets its own SID for granular alerting. All 8 C2 domains now covered (added projetosmecanicos.com.br SID:2100109 and comunidadesparentais.com.br SID:2100110). -->

### Suricata: Connections to DragonForce Staging and C2 IPs

Detects HTTP requests to the staging IP for ZIP payload downloads and any connections to the Backdoor.Turn C2 IP.

**compile: pass | confidence: high**

```
alert http $HOME_NET any -> 192.36.27.51 any (msg:"Actioner - HTTP Request to DragonForce Staging IP for ZIP Payload"; flow:established,to_server; http.uri; content:".zip"; endswith; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-19; sid:2100107; rev:1;)

alert ip $HOME_NET any -> 62.164.177.25 any (msg:"Actioner - Connection to DragonForce Backdoor.Turn C2 IP"; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created_at 2026-06-19; sid:2100108; rev:1;)
```

<!-- audit: suricata -T -S pass (exit 0). IP-based rules use real IPs (not defanged) per logsource-encoding.md. http.uri with endswith correctly applied for ZIP download detection. -->

### Snort: Connections to DragonForce C2/Staging IPs

Snort 2 compatible rules detecting connections to known DragonForce infrastructure.

**compile: pass | confidence: high**

```
alert ip $HOME_NET any -> 62.164.177.25 any (msg:"Actioner - Connection to DragonForce Backdoor.Turn C2 IP 62.164.177.25"; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created 2026-06-19; sid:2100201; rev:1;)

alert tcp $HOME_NET any -> 192.36.27.51 $HTTP_PORTS (msg:"Actioner - HTTP Request to DragonForce Staging IP for ZIP Payload Download"; flow:established, to_server; content:".zip"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/dragonforce-msteams-backdoor; metadata:author Actioner, created 2026-06-19; sid:2100202; rev:1;)
```

<!-- audit: snort -c (custom conf with classification.config) -T pass ("Snort successfully validated the configuration!"). Uses Snort 2 syntax (tcp not http protocol, no dot-notation buffers). -->

### YARA: Backdoor.Turn Go-Based RAT Detection

Three rules: (1) IOC-based detection matching known C2 domains and IP in PE binaries; (2) behavioral detection based on Go binary artifacts combined with Teams TURN relay-specific strings, QUIC library, and RAT capabilities; (3) exact-match hash detection for known Backdoor.Turn samples.

**compile: pass | confidence: high** (IOC rule) / **compile: pass | confidence: medium** (behavioral rule) / **compile: pass | confidence: high** (hash rule)

```yara
import "hash"

rule Malware_DragonForce_Backdoor_Turn_IOC : backdoor rat
{
    meta:
        description = "Detects Backdoor.Turn by known C2 domains and IP addresses used by DragonForce ransomware operators"
        author = "Actioner"
        date = "2026-06-19"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        hash = "821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6"
        hash2 = "048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // C2 domains
        $c2_1 = "projetosmecanicos.com.br" ascii
        $c2_2 = "socialbizsolutions.com" ascii
        $c2_3 = "professionalhomebasedbusiness.com" ascii
        $c2_4 = "safefire.jo" ascii
        $c2_5 = "glanz-gmbh.de" ascii
        $c2_6 = "turnkeyaiagents.com" ascii
        $c2_7 = "comunidadesparentais.com.br" ascii
        $c2_8 = "mysimerp.net" ascii

        // C2 IP
        $c2_ip = "62.164.177.25" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        any of ($c2_*)
}

rule Malware_DragonForce_Backdoor_Turn_Behavioral : backdoor rat
{
    meta:
        description = "Detects Backdoor.Turn Go-based RAT by behavioral indicators: Go binary with QUIC library, Teams/Skype TURN relay token acquisition, and LDAP/scanning capabilities"
        author = "Actioner"
        date = "2026-06-19"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        hash = "821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6"
        hash2 = "048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c"
        tlp = "WHITE"
        severity = "high"

    strings:
        // Go build artifact strings
        $go1 = "runtime.goexit" ascii
        $go2 = "runtime.main" ascii

        // QUIC library indicators (more specific than generic "QUIC")
        $quic1 = "quic-go" ascii

        // Microsoft Teams / Skype TURN relay specific strings
        $ms_turn1 = "turn.teams.microsoft.com" ascii wide
        $ms_turn2 = "api.flightproxy.skype.com" ascii wide
        $ms_turn3 = "turn3.teams.microsoft.com" ascii wide
        $ms_turn4 = "relay.teams.microsoft.com" ascii wide
        $ms_turn5 = "TURN_RELAY" ascii
        $ms_turn6 = "visitor_token" ascii
        $ms_turn7 = "anonymousToken" ascii

        // RAT capability strings (more specific)
        $cap1 = "ldap://" ascii nocase
        $cap2 = "netscan" ascii nocase
        $cap3 = "browsercredentials" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        all of ($go*) and
        $quic1 and
        2 of ($ms_turn*) and
        1 of ($cap*)
}

rule Malware_DragonForce_Backdoor_Turn_Hash : backdoor rat
{
    meta:
        description = "Detects known Backdoor.Turn samples by SHA256 hash match"
        author = "Actioner"
        date = "2026-06-19"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $hex_marker = { 4D 5A }

    condition:
        $hex_marker at 0 and
        filesize < 20MB and
        (
            hash.sha256(0, filesize) == "821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6" or
            hash.sha256(0, filesize) == "048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c" or
            hash.sha256(0, filesize) == "ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0" or
            hash.sha256(0, filesize) == "82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b"
        )
}
```

<!-- audit: yarac pass (exit 0). IOC rule (Malware_DragonForce_Backdoor_Turn_IOC) split from original combined rule — high confidence, matches only on known C2 domains/IP embedded in PE files. Behavioral rule (Malware_DragonForce_Backdoor_Turn_Behavioral) significantly tightened: replaced generic $turn* strings ("turn", "relay", "visitor", "token", "teams", "skype") with Microsoft-specific FQDN strings (turn.teams.microsoft.com, api.flightproxy.skype.com, etc.) and compound tokens (visitor_token, anonymousToken, TURN_RELAY); requires ALL of: Go runtime markers + quic-go library + 2 of 7 MS TURN strings + 1 RAT capability. This eliminates false positives from legitimate Go/WebRTC/TURN binaries. Hash rule unchanged — high confidence. -->

## Lessons Learned

1. **Legitimate infrastructure abuse is the next frontier for C2 evasion.** DragonForce's use of Microsoft Teams TURN relay servers represents a significant evolution in C2 masking. Organizations that blanket-whitelist Microsoft traffic — effectively all enterprises — are vulnerable to this class of technique. The security community should expect similar abuse of other legitimate communication relay services (Zoom, Slack, WebRTC infrastructure).

2. **BYOVD remains a devastating defense evasion technique.** The DragonForce campaign exploited four different vulnerable drivers, including one (Huawei HWAuidoOs2Ec.sys) that was novel at the time of the attack and only documented by Huntress months later. Organizations must enforce driver signing policies (HVCI/WDAC) and maintain blocklists of known vulnerable drivers.

3. **Post-ransomware backdoor installation indicates evolving business models.** Installing Backdoor.Turn after deploying DragonForce ransomware suggests the operators intended to maintain persistent access for follow-up intrusions or to sell access to other threat actors. This dual-use approach — immediate ransomware revenue plus persistent access value — reflects the cartelization of the ransomware ecosystem.

4. **Process injection into debugging tools is highly effective.** The choice of DbgView64.exe as the injection target was strategic — it is a legitimate Sysinternals tool that security teams may be accustomed to seeing on administrator workstations, and it normally does not generate network traffic, making anomalous connections from it a reliable detection signal.

## Sources

- [Symantec/Broadcom Threat Intelligence](https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor) — primary technical analysis with full IOC set, attack chain details, and MITRE ATT&CK mapping
- [The Hacker News](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html) — news coverage with additional context on DragonForce's cartel evolution
- [Hackread](https://hackread.com/dragonforce-ransomware-microsoft-teams-malware/) — news coverage noting BYOVD details and DLL sideloading chain
- [Security Affairs](https://securityaffairs.com/193801/security/dragonforce-hid-inside-microsoft-teams-and-nobody-noticed-for-two-months.html) — news coverage emphasizing the two-month dwell time and Ghost Calls inspiration
- [The Register](https://www.theregister.com/cyber-crime/2026/06/16/crooks-found-a-new-way-to-collaborate-using-teams-by-hiding-command-and-control-traffic/5256296) — news coverage providing the Symantec blog URL

---
*Report generated by Actioner*
