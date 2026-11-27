# SoftwareOK Supply Chain Trojanization: Q-Dir and DesktopOK

**Date:** 2026-11-27  
**Status:** FINAL  
**TLP:** CLEAR  
**Author:** Actioner

---

## Executive Summary

Attackers compromised the official SoftwareOK website and replaced legitimate installers for Q-Dir (a multi-pane file explorer) and DesktopOK (a desktop icon layout utility) with trojanized versions that deliver a Python-based remote access trojan (RAT). The trojanized installers run the genuine software to avoid suspicion while silently fetching and deploying a RAT payload from an attacker-controlled staging server. The RAT persists via a scheduled task masquerading as Microsoft Edge and communicates with a command-and-control (C2) server on a non-standard port. AhnLab's ASEC discovered and published the findings on November 26, 2026. No threat actor attribution has been made, though Chinese-language comments were found in the malware source code.

## Background

Q-Dir and DesktopOK are free Windows utilities developed by Nenad Hrg under the SoftwareOK brand. Q-Dir is a quad-pane file manager with a reported 500K+ downloads, and DesktopOK saves and restores desktop icon positions. Both are distributed exclusively through the official SoftwareOK website (softwareok[.]com). Their niche popularity among power users and system administrators makes them valuable targets for supply chain attacks, as the audience is likely to have elevated privileges.

## Attack Timeline

| Date | Event |
|------|-------|
| Unknown | Attacker gains access to SoftwareOK website distribution infrastructure |
| Unknown | Trojanized installers for Q-Dir (12.83.0.0, 12.84.0.0, 12.85.0.0) and DesktopOK (12.82.0.0, 12.85.0.0) are uploaded |
| Unknown | Software update mechanism also delivers trojanized files to existing installations |
| 2026-11-26 | ASEC publishes advisory and technical analysis |
| 2026-11-27 | Wider media coverage (The Hacker News, GBHackers, others) |

**Note:** ASEC did not establish the exact distribution window. Additional versions beyond those confirmed may have been affected during the compromise period.

## Root Cause

The root cause of the initial compromise -- how the official SoftwareOK distribution files were replaced -- has not been determined. ASEC confirmed that tampered files appeared both through direct downloads from the official website and through the in-app update process, indicating the attacker had write access to the distribution infrastructure rather than performing a simple download redirect. The legitimate embedded executables retain the developer's valid code signature, suggesting the attacker modified only the installer wrapper/downloader rather than the core application binaries.

## Technical Analysis

### Execution Chain

1. **User execution.** A user downloads or updates Q-Dir or DesktopOK from the official SoftwareOK website. The trojanized installer executes.
2. **Legitimate program launch.** The installer drops the genuine Q-Dir or DesktopOK executable to `C:\Users\Public\` and launches it, maintaining the appearance of normal software behavior.
3. **Payload staging.** The installer downloads two files from `mail[.]c1a2[.]top`:
   - `https://mail[.]c1a2[.]top/dl/7zr.exe` -- a legitimate 7-Zip command-line extractor
   - `https://mail[.]c1a2[.]top/dl/dsv2_py39_agent.7z` -- a 7z archive containing a Python 3.9 runtime and the RAT agent
4. **Payload extraction.** `7zr.exe` extracts the archive to `C:\ProgramData\Microsoft\DeviceSync\b2\` (primary) or `C:\ProgramData\DeviceSync\b2\` (fallback).
5. **Persistence.** A scheduled task named `\UPnp\MicrosoftEdge_dcntel` is created, masquerading as a Microsoft Edge telemetry component. The task executes `pythonw.exe` to run `py_client_dsv2.py`.
6. **C2 communication.** The RAT connects to `8[.]210[.]69[.]51` on TCP port `9876`.

### RAT Capabilities

The Python RAT provides the following capabilities to the operator:

- **Shell command execution** -- arbitrary Windows command-line access
- **Python code execution** -- dynamic code execution on the host
- **File upload/download** -- exfiltration and tool deployment
- **Screenshot capture** -- visual reconnaissance
- **System information collection** -- OS version, hostname, user context
- **Process enumeration** -- with comparison against an embedded list of 1,206 security product process names
- **Security product detection** -- specifically checks for AhnLab V3, ESTSecurity ALYac, Hauri ViRobot, CrowdStrike Falcon, SentinelOne, Cylance, Trend Micro, Avast, McAfee, ESET, Symantec, Kaspersky, Bitdefender, Sophos, Fortinet, Elastic Security, Cybereason, Malwarebytes, and FireEye, among others. Results are reported to the C2.

### Persistence Mechanism

The scheduled task `\UPnp\MicrosoftEdge_dcntel` is designed to blend in with legitimate Microsoft Edge tasks. The `UPnp` parent folder and `MicrosoftEdge_dcntel` naming convention mimic Windows system components. The task launches `pythonw.exe` (the windowless Python interpreter) which executes the RAT script without displaying a console window.

## Indicators of Compromise

> **Note:** All indicators below are defanged for safe handling in prose. Detection rules in the Detection Rules section use real (non-defanged) values.

### File Hashes (SHA-256) -- Trojanized Installers

**Q-Dir 12.85.0.0:**
- `434b67dd403c74752b336fbb4fc94ee3a6fb615168e3fd31baea71d1a356ecd8`
- `8ac6901a941788ab9675a9ec9bebdbc00074cb76f19a7d84c2e1b0ddbcee4f48`

**Q-Dir 12.84.0.0:**
- `cf9e2433540d0b8ae8c9f4c9d5f11770343d413c1cfb201c5edae7155f88585a`
- `d1a2cf8882c254156848f4a12b6c6837a3cf0e460f876c6f8b00d32a1560640a`
- `7afa1e77c115eaa7798237039fde67c8a69686e7d9a4034a8df54aff2d1a126d`
- `1b7b7947527a05f0fae268b16894440549c2dd512d421a06960e27b5fb1d5fa0`

**Q-Dir 12.83.0.0:**
- `c41bd9eefd7a63fa329b24144a3483abac012ebc11bd5606b6c8295251d46422`
- `551e5744b24019f016f9ee8dd3a2c00429da587b20321abaef55c18c0a655a5d`
- `7524fcf3ffc44fc2e9a53af761c2a308edac31d02df3dfb1a4b57504243aec48`
- `b45ba4a1d9a25116b94e95ef48d63fffda7d77bd358d17d74c7575ce39986b84`

**DesktopOK 12.85.0.0:**
- `c12651f2988bb5e05afd1f4b1e6bce618111a4703f1aadc006bfacc6ac7e1d90`
- `f96cab94d9f0e0000dfef8b9fce16bcefd23679443cc8ba8f7811a55ea5799ec`

**DesktopOK 12.82.0.0:**
- `8c172c421129bda890b504e89d1bb72af477be9896b22a576920c050442b4a04`
- `5b43284e48edee4acbab49bc5a68eb21d3a369a058d859689b6a5dd2042a5e2a`
- `bdbbe28cde3dee061536e524bc2a14316015db0c958cad83023790d32a4f8d99`
- `393d2f9f05affa88aaa19f29f041d28fe5c3e1fc2fd84c76d1e2f1aa6da74a83`
- `ff4ec1cca4746e33d1205ed434e1e2ac9cee71fec477b032f56d3bde577626d2`

**MD5 (file not specified by ASEC):**
- `ae44745919f4ef516581ebfaa97a0b4a`

### Legitimate Installer Hashes (SHA-256) -- for verification

| Product | Version | SHA-256 |
|---------|---------|---------|
| Q-Dir | 12.85.0.0 | `f6ed37559bca28eff3379e4a87c36383e0b0913c058bf124a8b20d5ea975706d` |
| Q-Dir | 12.84.0.0 | `0a7a00ec5844cb80ecc6d210d7c0a8c3f44f3a5b138146101b0c534f15d8fabf` |
| Q-Dir | 12.83.0.0 | `fc2993e6ad8cd9f82d56d7107018e0a77c90f66d4ba208b15f9fed5cd4609910` |
| DesktopOK | 12.85.0.0 | `679729814dc2cc09be8f51cdeee767e67af924acff4790584ac77019a104a143` |
| DesktopOK | 12.82.0.0 | `68360f3a515f024a990b17ba96066b27333fe360a0e3e32b88ded9e4c23e5dd7` |

### Network Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `mail[.]c1a2[.]top` | Payload staging server |
| URL | `hxxps://mail[.]c1a2[.]top/dl/7zr[.]exe` | 7-Zip extractor download |
| URL | `hxxps://mail[.]c1a2[.]top/dl/dsv2_py39_agent[.]7z` | RAT payload archive |
| IP:Port | `8[.]210[.]69[.]51:9876` | C2 server |

### Host Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| Scheduled Task | `\UPnp\MicrosoftEdge_dcntel` | Persistence mechanism |
| Directory | `C:\ProgramData\Microsoft\DeviceSync\b2\` | Primary RAT install path |
| Directory | `C:\ProgramData\DeviceSync\b2\` | Fallback RAT install path |
| File | `[Install Path]\py39\pythonw.exe` | Bundled Python interpreter |
| File | `[Install Path]\py39\agent\py_client_dsv2.py` | RAT client script |
| File | `C:\Users\Public\Q-Dir.exe` or variants | Dropped legitimate binary |
| File | `7zr.exe` (downloaded) | Used for payload extraction |
| File | `dsv2_py39_agent.7z` (downloaded) | RAT payload archive |

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Context |
|-------------|----------------|---------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized installers on official website |
| T1204.002 | User Execution: Malicious File | User runs trojanized installer |
| T1105 | Ingress Tool Transfer | Download of 7zr.exe and RAT archive from staging server |
| T1059.006 | Command and Scripting Interpreter: Python | RAT implemented as Python script using bundled runtime |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence via MicrosoftEdge_dcntel task |
| T1036.004 | Masquerading: Masquerade Task or Service | Scheduled task impersonates Microsoft Edge |
| T1113 | Screen Capture | RAT screenshot capability |
| T1082 | System Information Discovery | RAT collects OS and system information |
| T1057 | Process Discovery | RAT enumerates running processes |
| T1518.001 | Software Discovery: Security Software Discovery | RAT checks processes against 1,206 security product names |
| T1571 | Non-Standard Port | C2 on TCP port 9876 |

## Impact Assessment

**Severity: HIGH**

- **Scope:** Any user who downloaded or updated Q-Dir (versions 12.83-12.85) or DesktopOK (versions 12.82, 12.85) from the official SoftwareOK website during the compromise window is potentially affected. The update mechanism means even users with previously legitimate installations may have been compromised.
- **Access:** The RAT provides full remote access including command execution, file transfer, and screenshot capture. This represents a complete host compromise.
- **Stealth:** The legitimate software functions normally, reducing the chance of user detection. The scheduled task masquerades as a Microsoft Edge component.
- **Remediation complexity:** Uninstalling the legitimate software does NOT remove the RAT. The scheduled task, Python environment, and RAT files must be separately identified and removed.

## Detection & Remediation

### Immediate Actions

1. **Hash verification.** Compare the SHA-256 hash of any installed Q-Dir or DesktopOK installer against the legitimate hashes listed above. Any match to a malicious hash confirms compromise.
2. **Scheduled task hunt.** Search for the scheduled task `\UPnp\MicrosoftEdge_dcntel` on all endpoints. Its presence confirms active RAT persistence.
3. **File system search.** Check for the directories `C:\ProgramData\Microsoft\DeviceSync\b2\` and `C:\ProgramData\DeviceSync\b2\`, and for `py_client_dsv2.py` anywhere on the system.
4. **Network monitoring.** Block and alert on connections to `8[.]210[.]69[.]51:9876` and DNS lookups for `c1a2[.]top`.
5. **Reinstallation is not sufficient.** If compromised, the RAT must be independently removed. Remove the scheduled task, delete the RAT directories, and verify no additional malware was deployed.
6. **Full scan.** Run updated antivirus scans. AhnLab detects these as Downloader/Win.Agent and Backdoor/Python.Agent.

## Detection Rules

<!-- revision: critic-softwareok READY pass — (1) defanged IOCs in remediation prose, (2) added TLS-inspection caveats on HTTP network rules, (3) fixed contains|all→contains single-value modifier in schtasks Sigma rule, (4) marked GBHackers source as content-unavailable -->

### Sigma: Python RAT Execution from DeviceSync Directory

Detects execution of `pythonw.exe` from the attacker-specific ProgramData paths used to host the Python RAT.
**Status:** compile-status: ✅ | confidence: high

```yaml
title: SoftwareOK Supply Chain - Python RAT Execution from DeviceSync Directory
id: 7a3c8f1e-4d2b-4e9a-b6c3-1f8e2d5a9b7c
status: experimental
description: Detects execution of pythonw.exe from the ProgramData DeviceSync directories used by the trojanized Q-Dir and DesktopOK installers to deploy a Python RAT.
references:
    - https://asec.ahnlab.com/en/96827/
    - https://thehackernews.com/2026/11/hackers-trojanize-official-q-dir-and.html
author: Actioner
date: 2026/11/27
tags:
    - attack.t1195.002
    - attack.t1059.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_path:
        Image|contains:
            - '\ProgramData\Microsoft\DeviceSync\b2\py39\pythonw.exe'
            - '\ProgramData\DeviceSync\b2\py39\pythonw.exe'
    condition: selection_path
falsepositives:
    - Unlikely, as these are specific attacker-chosen paths
level: high
```

<!-- audit: sigma check (excluding attacktag validator due to network-blocked MITRE data fetch): 0 errors, 0 issues. sigma convert to splunk: success. sigma convert to log_scale: success. -->

### Sigma: Scheduled Task Masquerading as Microsoft Edge

Detects creation of the `MicrosoftEdge_dcntel` scheduled task used for RAT persistence.
**Status:** compile-status: ✅ | confidence: high

```yaml
title: SoftwareOK Supply Chain - Scheduled Task Masquerading as Microsoft Edge
id: 2b9d4e6f-8a1c-4f3d-b5e7-3c6a9d2f1e8b
status: experimental
description: Detects creation of a scheduled task named MicrosoftEdge_dcntel under UPnp, used for persistence by the trojanized SoftwareOK installers.
references:
    - https://asec.ahnlab.com/en/96827/
    - https://thehackernews.com/2026/11/hackers-trojanize-official-q-dir-and.html
author: Actioner
date: 2026/11/27
tags:
    - attack.t1053.005
    - attack.t1036.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - 'MicrosoftEdge_dcntel'
    condition: selection_schtasks
falsepositives:
    - Unlikely, as this is a specific attacker-chosen task name
level: high
```

<!-- audit: sigma check (excluding attacktag validator): 0 errors, 0 issues. sigma convert to splunk: success. sigma convert to log_scale: success. -->

### Sigma: RAT Payload Archive Extraction via 7zr

Detects `7zr.exe` extracting the characteristic `dsv2_py39_agent` archive.
**Status:** compile-status: ✅ | confidence: high

```yaml
title: SoftwareOK Supply Chain - RAT Payload Archive Download via 7zr
id: 4c8e1a3d-6f2b-4d7e-a9b5-8e3c1f7d2a6e
status: experimental
description: Detects execution of 7zr.exe extracting the dsv2_py39_agent archive, characteristic of the SoftwareOK supply chain trojanization.
references:
    - https://asec.ahnlab.com/en/96827/
    - https://thehackernews.com/2026/11/hackers-trojanize-official-q-dir-and.html
author: Actioner
date: 2026/11/27
tags:
    - attack.t1195.002
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_7zr:
        Image|endswith: '\7zr.exe'
        CommandLine|contains: 'dsv2_py39_agent'
    condition: selection_7zr
falsepositives:
    - Unlikely, as this is a specific attacker payload name
level: high
```

<!-- audit: sigma check (excluding attacktag validator): 0 errors, 0 issues. sigma convert to splunk: success. sigma convert to log_scale: success. -->

### Sigma: RAT Script File Creation

Detects creation of the `py_client_dsv2.py` file on disk.
**Status:** compile-status: ✅ | confidence: high

```yaml
title: SoftwareOK Supply Chain - RAT Script File Creation
id: 5d9f2b4e-7c3a-4e8f-b1d6-9a4c2e6f3b7d
status: experimental
description: Detects creation of the py_client_dsv2.py RAT script file associated with the trojanized SoftwareOK installers.
references:
    - https://asec.ahnlab.com/en/96827/
    - https://thehackernews.com/2026/11/hackers-trojanize-official-q-dir-and.html
author: Actioner
date: 2026/11/27
tags:
    - attack.t1195.002
    - attack.t1105
logsource:
    category: file_event
    product: windows
detection:
    selection_rat_file:
        TargetFilename|endswith: '\py_client_dsv2.py'
    condition: selection_rat_file
falsepositives:
    - Custom Python development projects using an identical filename
level: high
```

<!-- audit: sigma check (excluding attacktag validator): 0 errors, 0 issues. sigma convert to splunk: success. sigma convert to log_scale: success. -->

### Sigma: Legitimate Binary Dropped to Public Folder

Detects Q-Dir or DesktopOK executables written to `C:\Users\Public\`, the staging technique used by the trojanized installer.
**Status:** compile-status: ✅ | confidence: medium

```yaml
title: SoftwareOK Supply Chain - Legitimate Binary Dropped to Public Folder
id: 6e1a3c5f-8d4b-4f9a-c2e7-1b5d3a7f8c6e
status: experimental
description: Detects Q-Dir or DesktopOK executables being written to C:\Users\Public, a technique used by the trojanized installers to run the legitimate software while deploying the RAT.
references:
    - https://asec.ahnlab.com/en/96827/
    - https://thehackernews.com/2026/11/hackers-trojanize-official-q-dir-and.html
author: Actioner
date: 2026/11/27
tags:
    - attack.t1195.002
    - attack.t1036
logsource:
    category: file_event
    product: windows
detection:
    selection_public:
        TargetFilename|startswith: 'C:\Users\Public\'
        TargetFilename|endswith:
            - '\Q-Dir.exe'
            - '\Q-Dir_x64.exe'
            - '\DesktopOK.exe'
            - '\DesktopOK_x64.exe'
    condition: selection_public
falsepositives:
    - Manual user action copying these files to the Public folder
level: medium
```

> **Caveat:** This rule relies on specific executable names being dropped to `C:\Users\Public\`; a user manually copying these files would trigger a false positive.

<!-- audit: sigma check (excluding attacktag validator): 0 errors, 0 issues. sigma convert to splunk: success. sigma convert to log_scale: success. -->

### Sigma: DNS Query to Staging Domain

Detects DNS resolution of the `c1a2.top` domain used for payload delivery.
**Status:** compile-status: ✅ | confidence: high

```yaml
title: SoftwareOK Supply Chain - DNS Query to Staging Domain
id: 8f2b4d6e-9a5c-4c1b-d3e8-2c7a1f5b9d4e
status: experimental
description: Detects DNS resolution of mail.c1a2.top, the staging domain used to download the Python RAT payload in the SoftwareOK supply chain attack.
references:
    - https://asec.ahnlab.com/en/96827/
    - https://thehackernews.com/2026/11/hackers-trojanize-official-q-dir-and.html
author: Actioner
date: 2026/11/27
tags:
    - attack.t1195.002
    - attack.t1105
logsource:
    category: dns_query
    product: windows
detection:
    selection_dns:
        QueryName|endswith: '.c1a2.top'
    condition: selection_dns
falsepositives:
    - Unlikely, as this is an attacker-controlled domain
level: high
```

<!-- audit: sigma check (excluding attacktag validator): 0 errors, 0 issues. sigma convert to splunk: success. sigma convert to log_scale: success. -->

### Snort: SoftwareOK Supply Chain Network Detection

Four rules covering DNS resolution of the staging domain, C2 communication, and payload downloads.
**Status:** compile-status: ✅ | confidence: high

```
# SoftwareOK Supply Chain Trojanization - Snort 2.9 Rules
# Reference: https://asec.ahnlab.com/en/96827/

# Detect DNS query for staging domain mail.c1a2.top
alert udp $HOME_NET any -> any 53 (msg:"Actioner - SoftwareOK Supply Chain DNS Query for mail.c1a2.top"; content:"|04|mail|04|c1a2|03|top|00|"; nocase; classtype:trojan-activity; sid:2100001; rev:1;)

# Detect C2 communication to 8.210.69.51 on port 9876
alert tcp $HOME_NET any -> 8.210.69.51 9876 (msg:"Actioner - SoftwareOK Supply Chain C2 Communication to 8.210.69.51:9876"; flow:to_server,established; classtype:trojan-activity; sid:2100002; rev:1;)

# Detect HTTP GET for RAT payload archive
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - SoftwareOK Supply Chain RAT Payload Download dsv2_py39_agent.7z"; flow:to_server,established; content:"/dl/dsv2_py39_agent.7z"; http_uri; classtype:trojan-activity; sid:2100003; rev:1;)

# Detect HTTP GET for 7zr.exe used in attack chain
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - SoftwareOK Supply Chain 7zr.exe Download from Staging"; flow:to_server,established; content:"/dl/7zr.exe"; http_uri; content:"c1a2.top"; http_header; classtype:trojan-activity; sid:2100004; rev:1;)
```

> **Note:** HTTP-layer rules (sid:2100003, sid:2100004) require TLS inspection to match; without decryption, use the DNS rule (sid:2100001) or deploy Suricata's TLS SNI rule (sid:2200003) which detects the connection without decryption.

<!-- audit: snort -c minimal.conf -T: "Snort successfully validated the configuration!" exit 0. -->

### Suricata: SoftwareOK Supply Chain Network Detection

Five rules covering DNS, C2, TLS SNI, and HTTP payload download patterns.
**Status:** compile-status: ✅ | confidence: high

```
# SoftwareOK Supply Chain Trojanization - Suricata Rules
# Reference: https://asec.ahnlab.com/en/96827/

# Detect DNS query for staging domain
alert dns $HOME_NET any -> any any (msg:"Actioner - SoftwareOK Supply Chain DNS Query for c1a2.top"; dns.query; content:"c1a2.top"; nocase; classtype:trojan-activity; sid:2200001; rev:1;)

# Detect C2 communication to 8.210.69.51 on port 9876
alert tcp $HOME_NET any -> 8.210.69.51 9876 (msg:"Actioner - SoftwareOK Supply Chain C2 Communication to 8.210.69.51:9876"; flow:to_server,established; classtype:trojan-activity; sid:2200002; rev:1;)

# Detect TLS SNI for staging domain
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SoftwareOK Supply Chain TLS SNI to mail.c1a2.top"; tls.sni; content:"mail.c1a2.top"; nocase; classtype:trojan-activity; sid:2200003; rev:1;)

# Detect HTTP request for RAT payload archive
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SoftwareOK Supply Chain RAT Payload Download dsv2_py39_agent.7z"; http.uri; content:"/dl/dsv2_py39_agent.7z"; classtype:trojan-activity; sid:2200004; rev:1;)

# Detect HTTP request for 7zr.exe from staging domain
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SoftwareOK Supply Chain 7zr.exe Download from Staging"; http.uri; content:"/dl/7zr.exe"; http.host; content:"c1a2.top"; classtype:trojan-activity; sid:2200005; rev:1;)
```

> **Note:** HTTP-layer rules (sid:2200004, sid:2200005) require TLS inspection to match; the TLS SNI rule (sid:2200003) detects the connection without decryption.

<!-- audit: suricata -T -S softwareok-supply-chain-suri.rules: "Configuration provided was successfully loaded. Exiting." exit 0. -->

### YARA: Trojanized Installer Hash Match

Matches any of the 17 known trojanized installer SHA-256 hashes published by ASEC.
**Status:** compile-status: ✅ | confidence: high

```yara
import "hash"

rule SoftwareOK_Supply_Chain_Trojanized_Installer
{
    meta:
        description = "Detects trojanized Q-Dir and DesktopOK installers from the SoftwareOK supply chain attack based on SHA-256 hashes"
        author = "Actioner"
        date = "2026-11-27"
        reference = "https://asec.ahnlab.com/en/96827/"
        hash1 = "434b67dd403c74752b336fbb4fc94ee3a6fb615168e3fd31baea71d1a356ecd8"
        hash2 = "8ac6901a941788ab9675a9ec9bebdbc00074cb76f19a7d84c2e1b0ddbcee4f48"
        hash3 = "cf9e2433540d0b8ae8c9f4c9d5f11770343d413c1cfb201c5edae7155f88585a"
        hash4 = "d1a2cf8882c254156848f4a12b6c6837a3cf0e460f876c6f8b00d32a1560640a"
        hash5 = "7afa1e77c115eaa7798237039fde67c8a69686e7d9a4034a8df54aff2d1a126d"
        hash6 = "1b7b7947527a05f0fae268b16894440549c2dd512d421a06960e27b5fb1d5fa0"
        hash7 = "c41bd9eefd7a63fa329b24144a3483abac012ebc11bd5606b6c8295251d46422"
        hash8 = "551e5744b24019f016f9ee8dd3a2c00429da587b20321abaef55c18c0a655a5d"
        hash9 = "7524fcf3ffc44fc2e9a53af761c2a308edac31d02df3dfb1a4b57504243aec48"
        hash10 = "b45ba4a1d9a25116b94e95ef48d63fffda7d77bd358d17d74c7575ce39986b84"
        hash11 = "c12651f2988bb5e05afd1f4b1e6bce618111a4703f1aadc006bfacc6ac7e1d90"
        hash12 = "f96cab94d9f0e0000dfef8b9fce16bcefd23679443cc8ba8f7811a55ea5799ec"
        hash13 = "8c172c421129bda890b504e89d1bb72af477be9896b22a576920c050442b4a04"
        hash14 = "5b43284e48edee4acbab49bc5a68eb21d3a369a058d859689b6a5dd2042a5e2a"
        hash15 = "bdbbe28cde3dee061536e524bc2a14316015db0c958cad83023790d32a4f8d99"
        hash16 = "393d2f9f05affa88aaa19f29f041d28fe5c3e1fc2fd84c76d1e2f1aa6da74a83"
        hash17 = "ff4ec1cca4746e33d1205ed434e1e2ac9cee71fec477b032f56d3bde577626d2"

    condition:
        hash.sha256(0, filesize) == "434b67dd403c74752b336fbb4fc94ee3a6fb615168e3fd31baea71d1a356ecd8" or
        hash.sha256(0, filesize) == "8ac6901a941788ab9675a9ec9bebdbc00074cb76f19a7d84c2e1b0ddbcee4f48" or
        hash.sha256(0, filesize) == "cf9e2433540d0b8ae8c9f4c9d5f11770343d413c1cfb201c5edae7155f88585a" or
        hash.sha256(0, filesize) == "d1a2cf8882c254156848f4a12b6c6837a3cf0e460f876c6f8b00d32a1560640a" or
        hash.sha256(0, filesize) == "7afa1e77c115eaa7798237039fde67c8a69686e7d9a4034a8df54aff2d1a126d" or
        hash.sha256(0, filesize) == "1b7b7947527a05f0fae268b16894440549c2dd512d421a06960e27b5fb1d5fa0" or
        hash.sha256(0, filesize) == "c41bd9eefd7a63fa329b24144a3483abac012ebc11bd5606b6c8295251d46422" or
        hash.sha256(0, filesize) == "551e5744b24019f016f9ee8dd3a2c00429da587b20321abaef55c18c0a655a5d" or
        hash.sha256(0, filesize) == "7524fcf3ffc44fc2e9a53af761c2a308edac31d02df3dfb1a4b57504243aec48" or
        hash.sha256(0, filesize) == "b45ba4a1d9a25116b94e95ef48d63fffda7d77bd358d17d74c7575ce39986b84" or
        hash.sha256(0, filesize) == "c12651f2988bb5e05afd1f4b1e6bce618111a4703f1aadc006bfacc6ac7e1d90" or
        hash.sha256(0, filesize) == "f96cab94d9f0e0000dfef8b9fce16bcefd23679443cc8ba8f7811a55ea5799ec" or
        hash.sha256(0, filesize) == "8c172c421129bda890b504e89d1bb72af477be9896b22a576920c050442b4a04" or
        hash.sha256(0, filesize) == "5b43284e48edee4acbab49bc5a68eb21d3a369a058d859689b6a5dd2042a5e2a" or
        hash.sha256(0, filesize) == "bdbbe28cde3dee061536e524bc2a14316015db0c958cad83023790d32a4f8d99" or
        hash.sha256(0, filesize) == "393d2f9f05affa88aaa19f29f041d28fe5c3e1fc2fd84c76d1e2f1aa6da74a83" or
        hash.sha256(0, filesize) == "ff4ec1cca4746e33d1205ed434e1e2ac9cee71fec477b032f56d3bde577626d2"
}
```

<!-- audit: yarac softwareok-supply-chain.yar /dev/null: exit 0. -->

### YARA: Python RAT String Detection

Detects the Python RAT payload or related artifacts based on distinctive strings including C2 infrastructure, file names, and directory references.
**Status:** compile-status: ✅ | confidence: medium

```yara
rule SoftwareOK_Supply_Chain_Python_RAT_Strings
{
    meta:
        description = "Detects the Python RAT payload deployed by trojanized SoftwareOK installers based on distinctive strings"
        author = "Actioner"
        date = "2026-11-27"
        reference = "https://asec.ahnlab.com/en/96827/"

    strings:
        $s1 = "py_client_dsv2" ascii wide
        $s2 = "dsv2_py39_agent" ascii wide
        $s3 = "DeviceSync" ascii wide
        $s4 = "MicrosoftEdge_dcntel" ascii wide
        $url1 = "mail.c1a2.top" ascii wide
        $url2 = "/dl/dsv2_py39_agent.7z" ascii wide
        $url3 = "/dl/7zr.exe" ascii wide
        $c2 = "8.210.69.51" ascii wide
        $port = "9876" ascii wide

    condition:
        (3 of ($s*)) or
        ($url1 and ($url2 or $url3)) or
        ($c2 and $port and 1 of ($s*))
}
```

> **Caveat:** The `$port` string "9876" is generic and only contributes in combination with the C2 IP and a payload-specific string.

<!-- audit: yarac softwareok-supply-chain.yar /dev/null: exit 0. -->

### YARA: Python RAT Script Detection

Detects the `py_client_dsv2.py` RAT script based on its header string combined with the C2 address and capability-related function names.
**Status:** compile-status: ✅ | confidence: medium

```yara
rule SoftwareOK_Supply_Chain_RAT_Script
{
    meta:
        description = "Detects the py_client_dsv2.py RAT script used in the SoftwareOK supply chain attack"
        author = "Actioner"
        date = "2026-11-27"
        reference = "https://asec.ahnlab.com/en/96827/"

    strings:
        $header = "py_client_dsv2" ascii
        $c2_ip = "8.210.69.51" ascii
        $c2_port = "9876" ascii
        $fn1 = "screenshot" ascii nocase
        $fn2 = "shell" ascii nocase
        $fn3 = "upload" ascii nocase
        $fn4 = "download" ascii nocase
        $fn5 = "sysinfo" ascii nocase

    condition:
        $header and $c2_ip and $c2_port and 2 of ($fn*)
}
```

> **Caveat:** This rule depends on the RAT script containing the exact C2 IP and port as ASCII strings; obfuscated variants would evade it.

<!-- audit: yarac softwareok-supply-chain.yar /dev/null: exit 0. -->

## Sources

1. **ASEC (AhnLab Security Intelligence Center).** [Software Supply Chain Attack via the Official SoftwareOK Website: Tampering with Q-Dir and DesktopOK Installation Files](https://asec.ahnlab.com/en/96827/). Published 2026-11-26. Primary source.
2. **The Hacker News.** [Hackers Trojanize Official Q-Dir and DesktopOK Downloads to Deliver Remote Access Malware](https://thehackernews.com/2026/11/hackers-trojanize-official-q-dir-and.html). Ravie Lakshmanan, 2026-11-27.
3. **Cryptika.** [Hackers Turn Trusted Windows Software Downloads Into Tools for Secretly Controlling PCs](https://www.cryptika.com/hackers-turn-trusted-windows-software-downloads-into-tools-for-secretly-controlling-pcs/). 2026-11-27.
4. **ThreadLinqs.** [Software Supply Chain Attack via Official SoftwareOK Website: Trojanized Q-Dir and DesktopOK Installers Deliver Python RAT](https://intel.threadlinqs.com/threat/TL-2026-6949). TL-2026-6949.
5. **GBHackers.** [Q-Dir and Desktop OK Installers](https://gbhackers.com/q-dir-and-desktop-ok-installers/). 2026-11-27. *(Referenced but content unavailable at fetch time.)*
