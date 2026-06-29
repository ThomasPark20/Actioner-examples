# Technical Analysis Report: CL-STA-1062 / TinyRCT Backdoor Campaign (2026-06-29)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-29
Version: 1.1 (FINAL)
<!-- revision: v1.0→v1.1 — Fixed ATT&CK mappings (T1056→T1113, T1027→T1573, T1140→T1573.001); flagged AES-128/AES-192 key-length discrepancy; corrected self-destruct prose (choice.exe only deletes file, not scheduled task); downgraded Rule 7 C2 IP from critical→high for Vultr reuse risk; reconciled Rule 4 header/body level mismatch; added IP IOC staleness note; added Snort rule redundancy note. -->

## Executive Summary

CL-STA-1062 is a Chinese-speaking advanced persistent threat cluster active since at least March 2022, targeting Southeast Asian government entities and critical energy infrastructure. The group uses a hybrid toolkit combining open-source tools (SoftEther VPN, Mimikatz, VNT, yuze, JuicyPotato, fscan) with a newly discovered custom backdoor called **TinyRCT** -- a previously undocumented C# remote access trojan. TinyRCT is delivered via AppDomainManager injection using a trojanized Chrome installer archive, establishes persistence through scheduled tasks masquerading as Google updater processes, and communicates with C2 infrastructure over HTTP using AES CBC encryption (24-byte key; see AES-128/AES-192 note below) with a hardcoded key and null IV. Cisco Talos tracks the same activity cluster as UAT-7237. The campaign has compromised at least 10 organizations across Southeast Asia and Taiwan between September and December 2025.

## Background: Targeted Organizations

CL-STA-1062 targets state-owned enterprises in the energy sector, government entities, and web hosting infrastructure across Southeast Asia and Taiwan. The threat actor deploys ASPX web shells on internet-facing servers for initial reconnaissance, then establishes persistent network tunneling using SoftEther VPN, VNT, and yuze -- all disguised as VMware tools or XDR agent executables. Data exfiltration includes MSSQL database contents and web server source code archived in password-protected RAR files.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| March 2022 | CL-STA-1062 operations first observed targeting East Asia |
| Mid-2025 | Campaigns shift to Taiwanese web hosting infrastructure |
| September 2025 | Infiltration of Southeast Asian government entity |
| October-December 2025 | At least 10 organizations breached |
| June 2026 | Unit 42 publishes TinyRCT analysis |

## Root Cause: AppDomainManager Injection and Web Shell Access

The TinyRCT infection chain begins with a malicious archive (`chrome_setup.zip`) containing three files: a legitimate `chrome_setup.exe`, a malicious `chrome_setup.exe.config`, and `MyAppDomainManager.dll`. When the user executes the Chrome installer, the .NET runtime loads the adjacent config file, triggering AppDomainManager injection (T1574.014) that covertly executes the malicious DLL. The loader validates execution from `%USERPROFILE%\Downloads` and contacts the staging server to retrieve the TinyRCT payload (`PerfWatson2.exe`).

For network-level initial access, the threat actor deploys ASPX web shells on compromised web servers, using them for system enumeration and to establish outbound connections to attacker infrastructure.

## Technical Analysis of the Malicious Payload

### 1. Delivery: AppDomainManager Injection Chain

The delivery archive `chrome_setup.zip` (SHA256: `00e09754526d0fe836ba27e3144ae161b0ecd3774abec5560504a16a67f0087c`) contains:

- **chrome_setup.exe** -- legitimate .NET binary (wrapper)
- **chrome_setup.exe.config** -- malicious configuration that specifies `MyAppDomainManager` as the AppDomainManager type
- **MyAppDomainManager.dll** (SHA256: `cbfe8de6ffadbb1d396f61e63eb18e8b11c29527c1528641e3223d4c516cf7c3`) -- downloader DLL

The loader validates it is running from `%USERPROFILE%\Downloads` and terminates if the check fails. Upon validation, it contacts `hxxp[:]//139.180.134[.]221/PerfWatson2.exe` to retrieve the TinyRCT payload.

### 2. TinyRCT Backdoor (PerfWatson2.exe)

**SHA256:** `4e1f8888d020decd09799ec946f1bf677cac6612b24582ddbf4d8ede425d8384`

TinyRCT is a custom C# RAT that masquerades as Microsoft Visual Studio's telemetry process (`PerfWatson2.exe`). Key characteristics:

- **Environment validation:** Requires execution from `%LOCALAPPDATA%`; terminates immediately if run from any other path
- **C2 communication:** HTTP-based; POST for host fingerprinting (username, machine name, OS version, local IP, execution path, PID, GUID); GET for command polling
- **Encryption:** AES CBC with hardcoded key `ThisIsASecretKey87654321` and null IV (all zeros). **Note:** Unit 42 reports AES-128 CBC; however, the 24-byte key corresponds to AES-192. Defenders should attempt decryption with both AES-128 (first 16 bytes) and AES-192 (full 24 bytes).
- **Beaconing interval:** 10-second sleep between GET polls (adjustable via C2 command)
- **Capabilities:** Arbitrary command execution, file enumeration, file exfiltration (40 KB chunks with gzip compression + AES encryption), screenshot capture (JPEG format), self-deletion
- **Language indicator:** Simplified Chinese strings identified in C2 response parsing function

### 3. Persistence

TinyRCT creates a scheduled task for persistence:
```
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0 {ACE7A46F-50FD-481C-AB32-3D838871DB40}" /tr PerfWatson2.exe /sc onlogon /rl highest
```

The task runs at SYSTEM-level privileges (`/rl highest`) and triggers on user logon.

### 4. Self-Destruct

TinyRCT's cleanup routine uses:
```
choice.exe /C Y /N /D Y /T 3 & del PerfWatson2.exe
```
This removes the `PerfWatson2.exe` binary after a 3-second delay. **Note:** The observed command only deletes the executable file; no corresponding `schtasks /delete` command was identified in Unit 42's analysis to remove the `GoogleUpdater` scheduled task. The orphaned scheduled task entry may persist as a forensic artifact.

### 5. Post-Compromise Tooling

| Tool | Purpose | Masquerade Name |
|------|---------|----------------|
| SoftEther VPN | Network tunneling | vmtools.exe |
| VNT | VPN tunneling | VMware executable names |
| yuze (P001water/yuze) | SOCKS5 proxy | XDR agent names |
| Mimikatz | Credential harvesting | -- |
| JuicyPotato | Privilege escalation | -- |
| fscan | Network scanning | -- |
| traceroute | Network reconnaissance | -- |

### 6. C2 Infrastructure

All known C2 IP addresses are hosted on Vultr cloud infrastructure. **IOC staleness warning:** Vultr IPs are ephemeral cloud allocations and may be reassigned to legitimate customers. These IOCs should be treated as time-limited; validate against current Vultr IP ownership before blocking in production. Recommended review interval: 90 days from publication date.

| IP Address | Role |
|------------|------|
| 45[.]32[.]113[.]172 | Primary TinyRCT C2 |
| 139[.]180[.]134[.]221 | Payload staging server |
| 202[.]182[.]102[.]5 | Additional C2 |
| 45[.]76[.]210[.]43 | Additional C2 |

**Staging URLs:**
- `hxxp[:]//139.180.134[.]221/sdksdk608/1.zip`
- `hxxp[:]//139.180.134[.]221/sdksdk608/anydesk%5f0117.zip`
- `hxxp[:]//139.180.134[.]221/sdksdk608/hamcore.se2`
- `hxxp[:]//139.180.134[.]221/sdksdk608/httpdf`
- `hxxp[:]//139.180.134[.]221/sdksdk608/vpn%5fbridge.config`
- `hxxp[:]//139.180.134[.]221/sdksdk608/win-vpn.rar`
- `hxxp[:]//139.180.134[.]221/PerfWatson2.exe`

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: `[.]` replacing dots in domains/IPs, `hxxp` replacing `http`.

### File Hashes (SHA256)

| Filename | SHA256 | Description |
|----------|--------|-------------|
| chrome_setup.zip | `00e09754526d0fe836ba27e3144ae161b0ecd3774abec5560504a16a67f0087c` | Delivery archive |
| TinyRCT downloader (MyAppDomainManager.dll) | `cbfe8de6ffadbb1d396f61e63eb18e8b11c29527c1528641e3223d4c516cf7c3` | AppDomainManager injection DLL |
| TinyRCT payload (PerfWatson2.exe) | `4e1f8888d020decd09799ec946f1bf677cac6612b24582ddbf4d8ede425d8384` | Custom C# RAT |
| fscan | `f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071a0b1` | Network scanner |
| SoftEther VPN | `dce5df29bddff5a4ddaea5c4fec14da91f7b69063a6e1c45ed61e5da4fc6c87b` | VPN tunneling tool |
| VNT | `9b481b69cd91b09fa7bae7428f646dd89473a4c03393e43da81fe756cde1c472` | VPN tunneling tool |

### Network

| Type | Value | Context |
|------|-------|---------|
| IPv4 | 45[.]32[.]113[.]172 | Primary TinyRCT C2 |
| IPv4 | 139[.]180[.]134[.]221 | Payload staging server |
| IPv4 | 202[.]182[.]102[.]5 | C2 infrastructure |
| IPv4 | 45[.]76[.]210[.]43 | C2 infrastructure |
| URL | hxxp[:]//139.180.134[.]221/PerfWatson2.exe | TinyRCT payload download |
| URL | hxxp[:]//139.180.134[.]221/sdksdk608/ | Staging directory |

### File System Artifacts

| Path / Filename | Description |
|-----------------|-------------|
| %USERPROFILE%\Downloads\chrome_setup.exe | Legitimate wrapper (delivery) |
| %USERPROFILE%\Downloads\chrome_setup.exe.config | Malicious AppDomainManager config |
| %USERPROFILE%\Downloads\MyAppDomainManager.dll | Downloader DLL |
| %LOCALAPPDATA%\PerfWatson2.exe | TinyRCT backdoor deployment location |
| hamcore.se2 | SoftEther VPN configuration file |
| vpn_bridge.config | SoftEther VPN bridge configuration |

### Behavioral

| Indicator | Description |
|-----------|-------------|
| Scheduled task: `GoogleUpdaterTaskSystem140.0.7272.0 {ACE7A46F-50FD-481C-AB32-3D838871DB40}` | TinyRCT persistence |
| AES key: `ThisIsASecretKey87654321` | Hardcoded encryption key (null IV) |
| URI path: `/sdksdk608/` | Staging server directory pattern |
| Process: PerfWatson2.exe from %LOCALAPPDATA% | TinyRCT execution |
| Self-destruct: `choice.exe /C Y /N /D Y /T 3 & del PerfWatson2.exe` | Cleanup command |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | ASPX web shells deployed on compromised web servers |
| T1574.014 | Hijack Execution Flow: AppDomainManager Injection | Malicious .config and MyAppDomainManager.dll hijack .NET runtime loading |
| T1053.005 | Scheduled Task/Job: Scheduled Task | GoogleUpdaterTaskSystem scheduled task with highest privileges |
| T1036.005 | Masquerading: Match Legitimate Name or Location | PerfWatson2.exe, vmtools.exe, XDRAgent.exe masquerading |
| T1572 | Protocol Tunneling | SoftEther VPN, VNT, yuze for network tunneling |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 (GET/POST) |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES CBC encryption/decryption of C2 traffic with hardcoded key over HTTP |
| T1041 | Exfiltration Over C2 Channel | File exfiltration via HTTP POST in 40 KB chunks |
| T1005 | Data from Local System | File enumeration and exfiltration |
| T1113 | Screen Capture | Screenshot capture (JPEG) |
| T1070.004 | Indicator Removal: File Deletion | Self-destruct cleanup of PerfWatson2.exe |
| T1003 | OS Credential Dumping | Mimikatz credential harvesting |
| T1068 | Exploitation for Privilege Escalation | JuicyPotato privilege escalation |

## Impact Assessment

The CL-STA-1062 campaign presents a high-severity threat to government and critical infrastructure organizations in Southeast Asia. The combination of a custom backdoor (TinyRCT) with extensive open-source tooling demonstrates both capability and operational pragmatism. The hardcoded AES key and null IV in TinyRCT represent a cryptographic weakness that enables defenders to decrypt intercepted C2 traffic. The campaign's multi-year persistence (since 2022), targeting of state-owned energy enterprises, and exfiltration of database contents and source code indicate strategic intelligence collection objectives consistent with state-sponsored espionage.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for TinyRCT payload in AppData
Get-ChildItem -Path "$env:LOCALAPPDATA" -Filter "PerfWatson2.exe" -ErrorAction SilentlyContinue

# Check for malicious scheduled task
schtasks /query /fo LIST /v | Select-String -Pattern "GoogleUpdaterTaskSystem"

# Check for MyAppDomainManager.dll in Downloads
Get-ChildItem -Path "$env:USERPROFILE\Downloads" -Filter "MyAppDomainManager.dll" -ErrorAction SilentlyContinue

# Check for SoftEther artifacts in non-standard locations
Get-ChildItem -Path "C:\" -Recurse -Include "hamcore.se2","vpn_bridge.config" -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -notmatch "SoftEther" }

# Check for connections to known C2 IPs
netstat -ano | Select-String -Pattern "45.32.113.172|139.180.134.221|202.182.102.5|45.76.210.43"
```

### Remediation

1. **Contain:** Isolate affected hosts; block all four C2 IPs (45[.]32[.]113[.]172, 139[.]180[.]134[.]221, 202[.]182[.]102[.]5, 45[.]76[.]210[.]43) at firewall/proxy
2. **Eradicate:** Remove `GoogleUpdaterTaskSystem` scheduled tasks; delete PerfWatson2.exe from %LOCALAPPDATA%; remove MyAppDomainManager.dll and associated config from Downloads
3. **Credential Reset:** Assume credential compromise via Mimikatz; reset all domain admin, service account, and affected user passwords
4. **Hunt:** Search for SoftEther VPN, VNT, and yuze binaries masquerading as VMware tools or XDR agents; scan for ASPX web shells on internet-facing servers
5. **Network:** Monitor for HTTP traffic containing the staging URI pattern `/sdksdk608/` and beaconing to known C2 infrastructure

### Long-Term Hardening

- Deploy application allowlisting to block execution from %LOCALAPPDATA% and %USERPROFILE%\Downloads
- Monitor for AppDomainManager injection by alerting on .config files adjacent to .NET executables in user-writable directories
- Enable Sysmon with configuration covering process creation (EID 1), image loads (EID 7), network connections (EID 3), and scheduled task creation
- Implement network segmentation between internet-facing servers and internal infrastructure
- Block SoftEther VPN traffic at the network perimeter

## Detection Rules

These detections target TinyRCT backdoor execution, AppDomainManager injection delivery, persistence mechanisms, tool masquerading, and C2 communication from the CL-STA-1062 campaign. PoC/advisory-specific altitude; all Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles clean does not mean fires clean -- verify rules in your pipeline with representative telemetry.

> **Advisory -- Intentional Omissions:** The SoftEther VPN file event rule does not include generic filenames like `vpnclient.exe` or `vpnserver.exe` as these would generate excessive false positives in environments with legitimate SoftEther deployments. These remain documented as IOCs for manual hunt reference.

### Sigma: TinyRCT Backdoor Execution as PerfWatson2.exe
Detects PerfWatson2.exe executing from outside legitimate Visual Studio directories, the primary indicator of TinyRCT backdoor deployment.
**Status:** compile pass (splunk exit 0, log_scale exit 0; sigma check STIX timeout -- environment issue) -- confidence: high
<!-- audit: sigma check failed due to MITRE STIX download timeout (network issue, not rule issue). splunk convert exit 0; log_scale convert exit 0. Fields: Image (process_creation/windows) -- standard Sysmon/4688 field. Non-defanged paths in detection values per logsource-encoding spec. -->
```yaml
title: TinyRCT Backdoor Execution as PerfWatson2.exe
id: a1b2c3d4-1111-4aaa-bbbb-000000000001
status: experimental
description: >
    Detects execution of PerfWatson2.exe from the local AppData directory,
    the known deployment path of the TinyRCT backdoor used by CL-STA-1062.
    The legitimate PerfWatson2.exe (Visual Studio telemetry) runs from
    VS installation directories, not from AppData.
references:
    - https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/
    - https://thehackernews.com/2026/06/chinese-speaking-apt-deploys-new.html
author: Actioner
date: 2026/06/29
tags:
    - attack.t1036.005
    - attack.t1574.014
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\PerfWatson2.exe'
    filter_legitimate:
        Image|startswith:
            - 'C:\Program Files\Microsoft Visual Studio\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate Visual Studio telemetry process running from unusual paths
level: high
```

### Sigma: TinyRCT AppDomainManager Injection via MyAppDomainManager.dll
Detects loading of MyAppDomainManager.dll -- the injection payload used by CL-STA-1062 to deliver TinyRCT.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: critical
<!-- audit: ImageLoaded (image_load/windows) -- standard Sysmon EID 7 field. "MyAppDomainManager" is a distinctive, campaign-specific name. -->
```yaml
title: TinyRCT AppDomainManager Injection via MyAppDomainManager.dll
id: a1b2c3d4-2222-4aaa-bbbb-000000000002
status: experimental
description: >
    Detects the TinyRCT delivery chain where chrome_setup.exe is executed
    from the Downloads directory alongside a malicious .config file and
    MyAppDomainManager.dll. This AppDomainManager injection technique
    (T1574.014) hijacks .NET runtime loading to execute arbitrary code.
references:
    - https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/
author: Actioner
date: 2026/06/29
tags:
    - attack.t1574.014
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\MyAppDomainManager.dll'
    condition: selection
falsepositives:
    - Legitimate .NET applications using a DLL named MyAppDomainManager.dll (unlikely)
level: critical
```

### Sigma: TinyRCT Scheduled Task Persistence via GoogleUpdater Masquerade
Detects creation of the specific scheduled task pattern used by TinyRCT for persistence.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: critical
<!-- audit: Image, CommandLine (process_creation/windows) -- standard fields. Task name and GUID are campaign-specific. -->
```yaml
title: TinyRCT Scheduled Task Persistence via GoogleUpdater Masquerade
id: a1b2c3d4-3333-4aaa-bbbb-000000000003
status: experimental
description: >
    Detects creation of a scheduled task matching the TinyRCT backdoor
    persistence pattern that masquerades as a Google updater task. The
    task name includes a specific GUID pattern and is set to run at
    logon with highest privileges.
references:
    - https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/
author: Actioner
date: 2026/06/29
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
    selection_task:
        CommandLine|contains|all:
            - '/create'
            - 'GoogleUpdaterTaskSystem'
            - 'PerfWatson2.exe'
    condition: selection_schtasks and selection_task
falsepositives:
    - Unknown
level: critical
```

### Sigma: TinyRCT Self-Destruct Command via Choice.exe
Detects the specific self-destruct command sequence used by TinyRCT for cleanup.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: high
<!-- audit: CommandLine (process_creation/windows) -- standard field. Pattern is highly specific to TinyRCT cleanup routine. -->
```yaml
title: TinyRCT Self-Destruct Command via Choice.exe
id: a1b2c3d4-4444-4aaa-bbbb-000000000004
status: experimental
description: >
    Detects the TinyRCT self-destruct command sequence that uses
    choice.exe with a 3-second delay followed by deletion of
    PerfWatson2.exe. This is the cleanup routine triggered by
    the CL-STA-1062 threat actor.
references:
    - https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/
author: Actioner
date: 2026/06/29
tags:
    - attack.t1070.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'choice.exe'
            - '/C Y'
            - '/T 3'
            - 'del '
            - 'PerfWatson2.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```

### Sigma: SoftEther VPN Masquerading as VMware or XDR Agent Executable
Detects SoftEther VPN components disguised as VMware tools or XDR agent binaries -- a key CL-STA-1062 tradecraft.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: high
<!-- audit: Image (process_creation/windows) -- standard field. Filters exclude legitimate VMware and security vendor paths. -->
```yaml
title: SoftEther VPN Tool Masquerading as VMware Executable
id: a1b2c3d4-5555-4aaa-bbbb-000000000005
status: experimental
description: >
    Detects SoftEther VPN components disguised as VMware executables
    (vmtools.exe, vmwared.exe) or XDR agent binaries, a technique
    used by CL-STA-1062 for network tunneling. Legitimate VMware
    tools are installed in VMware directories, not user-accessible paths.
references:
    - https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/
author: Actioner
date: 2026/06/29
tags:
    - attack.t1036.005
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection_names:
        Image|endswith:
            - '\vmtools.exe'
            - '\vmwared.exe'
            - '\XDRAgent.exe'
    filter_vmware:
        Image|startswith:
            - 'C:\Program Files\VMware\'
            - 'C:\Program Files (x86)\VMware\'
    filter_xdr:
        Image|startswith:
            - 'C:\Program Files\Palo Alto Networks\'
            - 'C:\Program Files\CrowdStrike\'
            - 'C:\Program Files\SentinelOne\'
    condition: selection_names and not (filter_vmware or filter_xdr)
falsepositives:
    - Portable VMware tools or XDR agents installed in non-standard directories
level: high
```

### Sigma: SoftEther VPN Configuration File in Non-Standard Location
Detects creation of SoftEther VPN configuration files outside legitimate installation directories.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: high
<!-- audit: TargetFilename (file_event/windows) -- standard Sysmon EID 11 field. hamcore.se2 and vpn_bridge.config are distinctive SoftEther artifacts. -->
```yaml
title: CL-STA-1062 Tool Combination - SoftEther Hamcore File Download
id: a1b2c3d4-6666-4aaa-bbbb-000000000006
status: experimental
description: >
    Detects creation of the SoftEther VPN configuration file hamcore.se2
    outside of standard SoftEther installation directories. CL-STA-1062
    deploys SoftEther components alongside other tools to establish
    persistent tunneling into compromised networks.
references:
    - https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/
author: Actioner
date: 2026/06/29
tags:
    - attack.t1572
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\hamcore.se2'
            - '\vpn_bridge.config'
    filter_softether:
        TargetFilename|contains:
            - '\SoftEther VPN\'
            - '\Program Files\'
            - '\Program Files (x86)\'
    condition: selection and not filter_softether
falsepositives:
    - Legitimate SoftEther VPN installations in non-standard paths
level: high
```

### Sigma: TinyRCT C2 Network Connection to Known Infrastructure
Detects outbound connections to known CL-STA-1062 C2 IP addresses.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: high (IOC-based; Vultr IPs subject to reallocation)
<!-- audit: DestinationIp (network_connection/windows) -- standard Sysmon EID 3 field. IPs are non-defanged per logsource-encoding spec. Vultr IPs may be reallocated. Downgraded from critical to high per Vultr IP reuse risk. -->
```yaml
title: TinyRCT C2 Network Connection to Known Infrastructure
id: a1b2c3d4-7777-4aaa-bbbb-000000000007
status: experimental
description: >
    Detects outbound network connections to known CL-STA-1062 C2
    infrastructure IP addresses used for TinyRCT command and control
    and payload staging.
references:
    - https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/
author: Actioner
date: 2026/06/29
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp:
            - '45.32.113.172'
            - '139.180.134.221'
            - '202.182.102.5'
            - '45.76.210.43'
    condition: selection
falsepositives:
    - Vultr cloud hosting IPs may be reused by legitimate services
level: high
```

### YARA: TinyRCT Backdoor and Downloader Detection
Detects TinyRCT backdoor binary, downloader DLL, and delivery archive via hardcoded AES key, campaign-specific strings, and file structure.
**Status:** compile pass (yarac exit 0) -- confidence: high (Backdoor) / medium (Downloader) / high (Archive)
<!-- audit: yarac exit 0. Three rules: APT_CLSTA1062_TinyRCT_Backdoor (AES key is unique, high confidence), APT_CLSTA1062_TinyRCT_Downloader (combinatorial strings), APT_CLSTA1062_ChromeSetup_Archive (ZIP with all three filenames). PE header check + filesize constraints. -->
```yara
import "pe"

rule APT_CLSTA1062_TinyRCT_Backdoor
{
    meta:
        description = "Detects TinyRCT backdoor used by CL-STA-1062 via hardcoded AES key, characteristic strings, and behavioral indicators"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/"
        hash = "4e1f8888d020decd09799ec946f1bf677cac6612b24582ddbf4d8ede425d8384"
        severity = "critical"

    strings:
        $aes_key = "ThisIsASecretKey87654321" ascii wide
        $name1 = "TinyRCT" ascii wide
        $name2 = "PerfWatson2" ascii wide
        $file1 = "PerfWatson2.exe" ascii wide
        $task1 = "GoogleUpdaterTaskSystem" ascii wide
        $task2 = "ACE7A46F-50FD-481C-AB32-3D838871DB40" ascii wide
        $loader = "MyAppDomainManager" ascii wide
        $cfg = "chrome_setup.exe.config" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $aes_key or
            ($name1 and 1 of ($file1, $task1, $task2)) or
            (2 of ($task1, $task2, $loader, $cfg)) or
            ($name2 and $task1)
        )
}

rule APT_CLSTA1062_TinyRCT_Downloader
{
    meta:
        description = "Detects TinyRCT downloader component (MyAppDomainManager.dll) used in AppDomainManager injection attacks by CL-STA-1062"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/"
        hash = "cbfe8de6ffadbb1d396f61e63eb18e8b11c29527c1528641e3223d4c516cf7c3"
        severity = "high"

    strings:
        $s1 = "MyAppDomainManager" ascii wide
        $s2 = "chrome_setup" ascii wide
        $s3 = "AppDomainManager" ascii wide
        $url1 = "139.180.134.221" ascii
        $url2 = "sdksdk608" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            ($s1 and ($s2 or $s3)) or
            ($s1 and 1 of ($url*)) or
            ($url2 and 1 of ($s*))
        )
}

rule APT_CLSTA1062_ChromeSetup_Archive
{
    meta:
        description = "Detects the malicious chrome_setup.zip archive used to deliver TinyRCT via AppDomainManager injection"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/"
        hash = "00e09754526d0fe836ba27e3144ae161b0ecd3774abec5560504a16a67f0087c"
        severity = "high"

    strings:
        $zip_hdr = { 50 4B 03 04 }
        $f1 = "chrome_setup.exe" ascii
        $f2 = "chrome_setup.exe.config" ascii
        $f3 = "MyAppDomainManager.dll" ascii

    condition:
        $zip_hdr at 0 and
        filesize < 50MB and
        all of ($f*)
}
```

### Snort: TinyRCT C2 Traffic and Payload Staging
Detects HTTP traffic to known CL-STA-1062 C2 infrastructure and the staging URI pattern `/sdksdk608/`.
**Status:** compile pass (snort -T exit 0, 5 rules validated) -- confidence: high (IP-based) / high (URI pattern)
<!-- audit: snort -c (minimal conf with vars) -T exit 0. 5 rules loaded. IP matching via content keyword in TCP payload. URI pattern sdksdk608 is campaign-specific. NOTE: SIDs 2100201/2100202 (content-based IP matching in HTTP payload) overlap with SIDs 2100204/2100205 (destination-IP matching). Content-based rules catch IPs in HTTP Host headers; destination-IP rules catch all TCP connections. Both are retained for defense-in-depth but operators should be aware of potential double-alerting. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - TinyRCT C2 Beacon to Known IP 45.32.113.172"; flow:established,to_server; content:"45.32.113.172"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/; metadata:author Actioner, created 2026-06-29; sid:2100201; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - TinyRCT Payload Staging Server 139.180.134.221"; flow:established,to_server; content:"139.180.134.221"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/; metadata:author Actioner, created 2026-06-29; sid:2100202; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - TinyRCT Payload Download URI Pattern sdksdk608"; flow:established,to_server; content:"/sdksdk608/"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/; metadata:author Actioner, created 2026-06-29; sid:2100203; rev:1;)
alert tcp $HOME_NET any -> 45.32.113.172 any (msg:"Actioner - TinyRCT Direct C2 Connection to 45.32.113.172"; flow:established,to_server; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/; metadata:author Actioner, created 2026-06-29; sid:2100204; rev:1;)
alert tcp $HOME_NET any -> 139.180.134.221 any (msg:"Actioner - TinyRCT Direct Connection to Staging Server 139.180.134.221"; flow:established,to_server; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/; metadata:author Actioner, created 2026-06-29; sid:2100205; rev:1;)
```

### Suricata: TinyRCT C2 HTTP Traffic and Known Infrastructure
Detects HTTP traffic to CL-STA-1062 infrastructure via Suricata HTTP and TCP sticky buffers.
**Status:** compile pass (suricata -T exit 0) -- confidence: high
<!-- audit: suricata -T -S exit 0. Uses http.host and http.uri dot-notation sticky buffers (correct Suricata syntax). IP group syntax for direct connection rule. Domain/IP values are real (not defanged). -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TinyRCT C2 HTTP Beacon to Known IP 45.32.113.172"; flow:established,to_server; http.host; content:"45.32.113.172"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/; metadata:author Actioner, created_at 2026-06-29; sid:2200201; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TinyRCT Payload Staging Server HTTP Connection"; flow:established,to_server; http.host; content:"139.180.134.221"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/; metadata:author Actioner, created_at 2026-06-29; sid:2200202; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TinyRCT Payload Download URI Pattern sdksdk608"; flow:established,to_server; http.uri; content:"/sdksdk608/"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/; metadata:author Actioner, created_at 2026-06-29; sid:2200203; rev:1;)
alert tcp $HOME_NET any -> [45.32.113.172,139.180.134.221,202.182.102.5,45.76.210.43] any (msg:"Actioner - TinyRCT CL-STA-1062 Direct Connection to Known C2 IP"; flow:established,to_server; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/; metadata:author Actioner, created_at 2026-06-29; sid:2200204; rev:1;)
```

## Lessons Learned

1. **AppDomainManager injection is a growing initial access vector.** CL-STA-1062's use of a malicious .config file alongside a legitimate .NET executable demonstrates how .NET runtime configuration can be weaponized. Organizations should monitor for .config files adjacent to executables in user-writable directories, particularly Downloads.

2. **Tool masquerading extends to security products.** Disguising SoftEther VPN as VMware tools (`vmtools.exe`) or XDR agents (`XDRAgent.exe`) is a deliberate evasion strategy designed to blend into environments where these legitimate tools are expected. Behavioral detection (process lineage, network connections) is more reliable than name-based detection alone.

3. **Hardcoded cryptographic material is a defensive gift.** TinyRCT's use of the static AES key `ThisIsASecretKey87654321` with a null IV enables defenders to decrypt intercepted C2 traffic, extract commands, and understand the full scope of compromise. This is unusual for a sophisticated threat actor and may indicate rapid development or limited operational security discipline.

4. **Hybrid toolkits complicate attribution but expand detection surface.** The combination of custom malware (TinyRCT) with widely-available open-source tools (Mimikatz, fscan, JuicyPotato) means that while attribution is challenging, each tool provides an independent detection opportunity.

## Sources

- [Unit 42 - CL-STA-1062 TinyRCT Backdoor Analysis](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/) -- primary technical analysis with full IOCs, TTPs, and malware reverse engineering
- [The Hacker News - Chinese-Speaking APT Deploys New TinyRCT Backdoor](https://thehackernews.com/2026/06/chinese-speaking-apt-deploys-new.html) -- secondary reporting with additional campaign timeline context

---
*Report generated by Actioner*
