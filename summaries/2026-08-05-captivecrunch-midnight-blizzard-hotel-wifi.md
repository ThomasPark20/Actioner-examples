# Technical Analysis Report: CaptiveCrunch -- Midnight Blizzard Hotel Wi-Fi Campaign (2026-08-05)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-05
Version: 1.1 (FINAL)

## Executive Summary

Russian state actor Midnight Blizzard (Storm-2945/APT29) has been operating a worldwide campaign dubbed "CaptiveCrunch" that compromises hospitality Wi-Fi captive portals to deliver custom malware targeting corporate travelers. Active since at least February 2026 with DNS/HTTP manipulation via captive portals beginning in May 2026, the campaign deploys two primary payloads: CornFlake RAT (a Go-based remote access trojan) and ChocoShell (a PowerShell infostealer). The operation targets Microsoft 365 credentials, browser-stored passwords and cookies, WAM tokens, and Wi-Fi credentials through a combination of adversary-in-the-middle (AitM) infrastructure and Device Code Flow phishing. The campaign's C2 panel, FruitStone, masquerades as a legitimate cloud infrastructure portal. Six C2/AitM IP addresses and four phishing domains have been identified. The breadth of browser targets (11 browsers), multiple persistence mechanisms (services, registry, scheduled tasks, watchdog), and sophisticated evasion techniques (AMSI bypass, UAC bypass with three fallback methods, fake progress windows, symbol garbling) indicate a mature and well-resourced operation consistent with SVR-attributed threat activity.

## Background: Hotel Wi-Fi Captive Portal Attack Surface

Hotel Wi-Fi networks represent a high-value attack surface for state-sponsored actors targeting corporate travelers. Captive portals -- the web pages users must interact with before gaining internet access -- are inherently trusted by users who expect a login or terms-of-service page. This trust relationship creates an ideal vector for malware delivery and credential phishing. Corporate travelers frequently connect to hotel Wi-Fi with devices containing active Microsoft 365 sessions, VPN credentials, and browser-stored passwords for enterprise applications. Midnight Blizzard (also tracked as APT29, Cozy Bear, and attributed to Russia's SVR foreign intelligence service) has a documented history of targeting cloud authentication flows, including the 2024 Device Code Flow abuse campaigns against government and defense organizations. The CaptiveCrunch campaign extends this tradecraft to physical-access attack vectors by compromising the captive portal infrastructure of hotels worldwide.

## Attack Timeline (All Times UTC)

| Phase | Event |
|-------|-------|
| February 2026 | Campaign infrastructure established; initial CornFlake RAT development and testing |
| May 2026 | DNS/HTTP manipulation via compromised captive portals begins active operations |
| 2026-07-01 | ChocoShell C2 server at 213.145.86[.]112 becomes active |
| 2026-07-31 | Microsoft Security Blog publishes initial disclosure of the CaptiveCrunch campaign |
| 2026-08-03 | Additional reporting from The Register, BleepingComputer, and other outlets |

## Root Cause: Compromised Captive Portal Infrastructure

Initial access is achieved through drive-by compromise (T1189) of hotel Wi-Fi captive portals. When corporate travelers connect to a compromised hotel Wi-Fi network, the AitM infrastructure intercepts and manipulates the captive portal experience. The attacker-controlled DNS resolvers (38.146.28[.]132 and 107.189.26[.]194) redirect DNS queries, while AitM proxies at 31.57.243[.]154, 38.146.28[.]75, and 104.194.159[.]150 manipulate HTTP traffic to inject malicious content into the captive portal flow. A parallel Device Code Flow phishing operation uses four domains impersonating Microsoft 365 login pages (ms365-device[.]com, ms365-live[.]com, m365-owa[.]com, owa-ms365[.]com) to steal OAuth tokens.

## Technical Analysis of the Malicious Payload

### 1. CornFlake RAT (Go-based Remote Access Trojan)

CornFlake is a full-featured RAT written in Go, delivered through the compromised captive portal. Key characteristics:

**Installation and Persistence:**
- Installs to `%APPDATA%\svchost32\svchost32.exe` -- masquerading as a legitimate system process name
- Registers a Windows service named "svchost32" with display name "Cloud Sync Service"
- Creates Registry Run keys and named scheduled tasks for persistence redundancy
- Employs a persistence watchdog that continuously monitors and restores persistence mechanisms if removed
- Configuration stored in `sync.dat` alongside the binary

**Capabilities:**
- Keylogging, clipboard monitoring, and screenshot capture
- Audio and video capture from connected devices
- Browser credential extraction across 11 browsers: Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Firefox, Waterfox, LibreWolf, Floorp, and Zen
- File exfiltration and USB device monitoring
- Remote shell access

**Evasion:**
- Displays configurable fake progress windows mimicking legitimate software updates (winupdate, defender, directx, vcredist, sysopt, netfix, browser, pdfview) to provide a plausible cover story during installation
- Symbol garbling to hinder static analysis
- XOR string encoding throughout the binary
- GZip compression for payloads

**Cryptography:**
- ECDH P-256 key exchange for C2 session establishment
- SHA-256 session key derivation

**SHA256:** `918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593`

### 2. ChocoShell (PowerShell Infostealer)

ChocoShell is a fileless PowerShell infostealer designed for rapid credential harvesting. It executes entirely in memory and targets:

**Browser Credential Theft:**
- Chrome App-Bound Encryption bypass for modern Chrome versions
- Firefox NSS/SDR decryption for Firefox-family browsers
- Targets cookies, saved passwords, and session data across all 11 supported browsers

**Token Theft:**
- M365/Azure AD access and refresh tokens
- WAM (Web Account Manager) tokens from `_.tbres_` files
- Wi-Fi credentials via `netsh wlan show profile key=clear`

**UAC Bypass (three techniques with sequential fallback):**
1. SilentCleanup task hijack via `HKCU\Environment\windir`
2. COM handler hijack for wsreset.exe via `HKCU\Software\Classes`
3. Folder handler hijack for sdclt.exe via `HKCU\Software\Classes\Folder\shell\open\command`

**Defense Evasion:**
- AMSI disable via .NET reflection (amsiInitFailed field manipulation)
- Timing-based sandbox evasion
- PowerShell `-NoP` (NoProfile) execution
- Windows Defender signature locking
- Registry cleanup with 2-second lifecycle for UAC bypass artifacts

**SHA256:** `be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c`

### 3. C2 Infrastructure

**ChocoShell C2 Communication:**
ChocoShell communicates via HTTP with endpoints designed to blend with legitimate web analytics and CDN traffic:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/t/pixel.gif?m=<status>` | GET | Beacon check-in disguised as a tracking pixel |
| `/cdn/chunks/polyfill-7e2b.min.js` | GET | Payload delivery disguised as a JS polyfill chunk |
| `/t/event` | POST | Data exfiltration, GZip-compressed Base64-encoded JSON |

**C2 and AitM Infrastructure:**

| IP Address | Role |
|------------|------|
| 213.145.86[.]112 | ChocoShell C2 (active since 2026-07-01) |
| 107.189.26[.]194 | ChocoShell C2 / DNS Resolver |
| 31.57.243[.]154 | AitM infrastructure |
| 38.146.28[.]75 | AitM infrastructure |
| 38.146.28[.]132 | DNS Resolver |
| 104.194.159[.]150 | AitM infrastructure |

**FruitStone C2 Panel:**
The backend C2 panel masquerades as "Acuity Systems, Inc. -- Cloud Infrastructure Portal v3.2.1". It uses JWT-based authentication and Server-Sent Events (SSE) for real-time agent status updates.

**Phishing Domains (Device Code Flow abuse):**
- ms365-device[.]com
- ms365-live[.]com
- m365-owa[.]com
- owa-ms365[.]com

### 4. Anti-Forensics / Evasion Techniques

- **CornFlake:** Fake progress windows configurable to 8 themes; XOR string encoding; symbol garbling in Go binary; GZip compression of payloads
- **ChocoShell:** Entirely fileless (in-memory PowerShell); AMSI bypass via .NET reflection; 2-second registry artifact lifecycle for UAC bypass keys; timing-based sandbox detection; Defender signature locking
- **C2 Communication:** HTTP endpoints masquerade as web analytics (tracking pixels) and CDN resources (polyfill JS); GZip+Base64 encoding for exfiltrated data

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `ms365-device[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `213.145.86[.]112`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `%APPDATA%\svchost32\svchost32.exe` | `918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593` | CornFlake RAT binary |
| Windows | `%APPDATA%\svchost32\sync.dat` | N/A | CornFlake RAT configuration file |
| Windows | In-memory (PowerShell) | `be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c` | ChocoShell infostealer |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 213.145.86[.]112 | ChocoShell C2 (active since 2026-07-01) |
| IP | 107.189.26[.]194 | ChocoShell C2 / DNS Resolver |
| IP | 31.57.243[.]154 | AitM infrastructure |
| IP | 38.146.28[.]75 | AitM infrastructure |
| IP | 38.146.28[.]132 | DNS Resolver |
| IP | 104.194.159[.]150 | AitM infrastructure |
| Domain | ms365-device[.]com | Device Code Flow phishing |
| Domain | ms365-live[.]com | Device Code Flow phishing |
| Domain | m365-owa[.]com | Device Code Flow phishing |
| Domain | owa-ms365[.]com | Device Code Flow phishing |
| URL Pattern | `/t/pixel.gif?m=<status>` | ChocoShell beacon (tracking pixel disguise) |
| URL Pattern | `/cdn/chunks/polyfill-7e2b.min.js` | ChocoShell payload delivery (polyfill disguise) |
| URL Pattern | `/t/event` | ChocoShell data exfiltration |

### Behavioral

- Windows service "svchost32" with display name "Cloud Sync Service" installed
- Process execution from `%APPDATA%\svchost32\svchost32.exe`
- Registry modifications to `HKCU\Environment\windir`, `HKCU\Software\Classes` (wsreset COM handler), and `HKCU\Software\Classes\Folder\shell\open\command` (sdclt hijack) -- each with approximately 2-second lifetime
- PowerShell script blocks containing AMSI bypass patterns (AmsiUtils + amsiInitFailed via .NET reflection)
- Execution of `netsh wlan show profile key=clear` for Wi-Fi credential harvesting
- Scheduled task creation referencing svchost32.exe
- Persistence watchdog behavior: re-creation of deleted persistence mechanisms

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1189 | Drive-by Compromise | Compromised hotel Wi-Fi captive portals deliver CornFlake RAT |
| T1059.001 | PowerShell | ChocoShell executes as in-memory PowerShell with -NoP flag |
| T1547.001 | Registry Run Keys / Startup Folder | CornFlake RAT sets Registry Run keys for persistence |
| T1053.005 | Scheduled Task | CornFlake RAT creates named scheduled tasks |
| T1543.003 | Windows Service | CornFlake RAT registers "svchost32" service |
| T1548.002 | Bypass User Account Control | ChocoShell uses three UAC bypass techniques with fallback |
| T1562.001 | Disable or Modify Tools | ChocoShell disables AMSI via .NET reflection |
| T1555.003 | Credentials from Web Browsers | Both malware components target browser-stored credentials |
| T1528 | Steal Application Access Token | M365/Azure AD tokens, WAM tokens from _.tbres_ files |
| T1071.001 | Web Protocols | C2 communication via HTTP endpoints disguised as analytics/CDN |
| T1041 | Exfiltration Over C2 Channel | Stolen data exfiltrated via /t/event endpoint |
| T1036.005 | Match Legitimate Name or Location | svchost32.exe masquerades as legitimate svchost.exe |

## Impact Assessment

The CaptiveCrunch campaign represents a significant threat to corporate travelers worldwide. The attack surface -- hotel Wi-Fi networks -- is difficult to defend against at the endpoint level because captive portal interaction is an expected and necessary behavior. The breadth of credential theft (11 browser families, M365/Azure AD tokens, WAM tokens, Wi-Fi credentials) means a single successful compromise can yield access to corporate cloud environments, VPN credentials, and potentially facilitate lateral movement into enterprise networks. The campaign's attribution to Midnight Blizzard/APT29 (SVR) indicates intelligence-collection objectives, with corporate travelers in government, defense, technology, and diplomatic sectors at highest risk. The persistence watchdog and multiple redundant persistence mechanisms make complete eradication challenging without full reimaging.

## Detection & Remediation

### Immediate Detection

Check for CornFlake RAT installation:
```
dir "%APPDATA%\svchost32\svchost32.exe" 2>nul && echo INFECTED || echo CLEAN
sc query svchost32 2>nul | findstr "STATE"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul | findstr /i "svchost32"
schtasks /query /fo list /v 2>nul | findstr /i "svchost32"
```

Check for ChocoShell UAC bypass registry artifacts (may have been cleaned, but check):
```
reg query "HKCU\Environment" /v windir 2>nul
reg query "HKCU\Software\Classes\Folder\shell\open\command" 2>nul
```

Search DNS logs for phishing domains:
```
# Splunk
index=dns QueryName IN ("ms365-device.com","ms365-live.com","m365-owa.com","owa-ms365.com")

# KQL (Microsoft Sentinel)
DnsEvents | where Name in ("ms365-device.com","ms365-live.com","m365-owa.com","owa-ms365.com")
```

Search network logs for C2 IPs:
```
# Splunk
index=firewall dest_ip IN ("213.145.86.112","31.57.243.154","38.146.28.75","38.146.28.132","104.194.159.150","107.189.26.194")
```

### Remediation

1. **Contain:** Immediately isolate any host showing indicators. Disconnect from hotel/public Wi-Fi networks.
2. **Eradicate:** Full disk reimage is recommended due to the persistence watchdog. Manual removal must address: svchost32 service, Run keys, scheduled tasks, and the `%APPDATA%\svchost32\` directory simultaneously to prevent watchdog restoration.
3. **Credential Reset:** Rotate all Microsoft 365 credentials, revoke all Azure AD refresh tokens, and invalidate WAM tokens for affected users. Reset Wi-Fi passwords that may have been harvested.
4. **Token Revocation:** Use Azure AD `Revoke-AzureADUserAllRefreshToken` and review sign-in logs for Device Code Flow authentications from unexpected locations.
5. **Browser Credential Reset:** All passwords saved in browsers on affected devices should be considered compromised.

### Long-Term Hardening

- Deploy always-on VPN or SASE solutions that establish secure tunnels before captive portal interaction
- Implement Conditional Access policies in Azure AD blocking Device Code Flow authentication where not explicitly needed
- Enable AMSI and PowerShell script block logging (Event ID 4104) with centralized collection
- Deploy endpoint detection rules for the behavioral indicators identified in this report
- Establish travel security policies prohibiting direct hotel Wi-Fi connections without VPN protection
- Consider hardware security keys (FIDO2) for high-value accounts to mitigate token theft

## Detection Rules

The following 19 detection rules cover the CaptiveCrunch campaign across endpoint (Sigma), file (YARA), and network (Snort 3, Suricata) layers. Rules are IOC-specific and keyed on concrete artifacts from the intelligence; network rules for C2 IPs will require updates as infrastructure rotates. Snort and Suricata rules are structurally validated only (compilers not available in this environment). Snort IP rules (#15-17) and Suricata IP rules (#19) are parallel implementations for multi-engine coverage, not independent detections. AMSI bypass detection dropped -- generic TTP; ChocoShell-specific AMSI coverage provided by YARA rule #11.

### Sigma Rules

#### 1. CornFlake RAT Process Execution

Detects execution of svchost32.exe from the CornFlake RAT installation directory.

**Compile:** Splunk ✅ | LogScale ✅ | `sigma check` skipped (MITRE data fetch blocked)
**Confidence:** High

```yaml
title: CaptiveCrunch CornFlake RAT Process Execution - svchost32.exe
id: 7a3b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: >
    Detects execution of svchost32.exe from %APPDATA%\svchost32, the known
    installation path of the CornFlake RAT deployed by Midnight Blizzard
    (Storm-2945/APT29) in the CaptiveCrunch hotel Wi-Fi campaign.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\svchost32\svchost32.exe'
    condition: selection
falsepositives:
    - Unlikely; svchost32.exe in an AppData subdirectory is not a legitimate Windows binary
level: high
```

<!-- AUDIT: Splunk output: Image="*\\svchost32\\svchost32.exe". LogScale output: Image=/\\svchost32\\svchost32\.exe$/i. Uses endswith on Image path; no defanged values. Field name Image is standard Sysmon EID 1. sigma check skipped due to MITRE ATT&CK data fetch HTTP 403 from proxy; syntax validated by successful backend conversion to two targets. -->

#### 2. CornFlake RAT Service Installation

Detects the svchost32 Windows service installation event (System Event ID 7045).

**Compile:** Splunk ✅ | LogScale ✅ | `sigma check` skipped
**Confidence:** High

```yaml
title: CaptiveCrunch CornFlake RAT Service Installation
id: 8b4c2d5e-6f7a-4b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: >
    Detects installation of the Windows service named "svchost32" with display
    name "Cloud Sync Service", used by CornFlake RAT for persistence in the
    CaptiveCrunch campaign (Midnight Blizzard/APT29).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains: 'svchost32'
    selection_display:
        EventID: 7045
        ServiceFileName|contains: 'svchost32'
    condition: selection or selection_display
falsepositives:
    - Unlikely; legitimate software would not name a service svchost32
level: high
```

<!-- AUDIT: Splunk output: (EventID=7045 ServiceName="*svchost32*") OR (EventID=7045 ServiceFileName="*svchost32*"). Two selection blocks: one matches ServiceName, the other ServiceFileName, ORed together. EventID 7045 is System log service installation. No defanged values. -->

#### 3. UAC Bypass via Registry Hijack (CaptiveCrunch Hunt)

Detects registry writes to three UAC bypass paths observed in the CaptiveCrunch campaign. These registry paths are used by dozens of tools and are not ChocoShell-specific; treat as a hunt-level detection.

**Compile:** Splunk ✅ | LogScale ✅ | `sigma check` skipped
**Confidence:** Medium (hunt-level; UAC bypass registry paths are not tool-specific)

```yaml
title: UAC Bypass via Registry Hijack (CaptiveCrunch Hunt)
id: 9c5d3e6f-7a8b-4c0d-1e2f-3a4b5c6d7e8f
status: experimental
description: >
    Detects registry modifications associated with three UAC bypass techniques
    observed in the CaptiveCrunch campaign (SilentCleanup task hijack via
    Environment\windir, COM handler hijack for wsreset.exe, sdclt.exe folder
    hijack). These registry paths are used by multiple tools and are not
    exclusive to ChocoShell; treat as a hunt-level detection.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1548.002
logsource:
    category: registry_set
    product: windows
detection:
    selection_silentcleanup:
        TargetObject|contains: 'HKCU\Environment\windir'
    selection_com_hijack:
        TargetObject|contains|all:
            - 'HKCU\Software\Classes'
            - 'wsreset'
    selection_sdclt:
        TargetObject|contains: 'HKCU\Software\Classes\Folder\shell\open\command'
    condition: selection_silentcleanup or selection_com_hijack or selection_sdclt
falsepositives:
    - Developer tools that modify HKCU Environment variables
    - Software installers that register COM handlers under HKCU
    - Security testing and red team tools using the same UAC bypass techniques
level: medium
```

<!-- revision: downgraded from high to medium; relabeled as hunt-level; removed ChocoShell from title since logic is not tool-specific; expanded false positives -->
<!-- AUDIT: Splunk output: TargetObject="*HKCU\\Environment\\windir*" OR (TargetObject="*HKCU\\Software\\Classes*" TargetObject="*wsreset*") OR TargetObject="*HKCU\\Software\\Classes\\Folder\\shell\\open\\command*". LogScale output: TargetObject=/HKCU\\Environment\\windir/i or (TargetObject=/HKCU\\Software\\Classes/i TargetObject=/wsreset/i) or TargetObject=/HKCU\\Software\\Classes\\Folder\\shell\\open\\command/i. Three OR'd selection blocks each targeting a distinct UAC bypass registry path. These are well-documented UAC bypass techniques used by many tools. -->

#### 4. CornFlake RAT File Drop

Detects file creation of CornFlake RAT binary or config in the expected installation directory.

**Compile:** Splunk ✅ | LogScale ✅ | `sigma check` skipped
**Confidence:** High

```yaml
title: CaptiveCrunch CornFlake RAT File Drop
id: 0d6e4f7a-8b9c-4d1e-2f3a-4b5c6d7e8f9a
status: experimental
description: >
    Detects creation of svchost32.exe or sync.dat configuration file in the
    AppData\Roaming\svchost32 directory, indicating CornFlake RAT deployment
    from the CaptiveCrunch campaign (Midnight Blizzard/APT29).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\AppData\Roaming\svchost32\'
        TargetFilename|endswith:
            - '\svchost32.exe'
            - '\sync.dat'
    condition: selection
falsepositives:
    - Unlikely; no legitimate software uses this exact path and filename combination
level: high
```

<!-- AUDIT: AND of contains (path) and endswith (filename) ensures both path context and filename match. TargetFilename is standard Sysmon EID 11 field. No defanged values. -->

#### 5. Phishing Domain DNS Query

Detects DNS queries to the four known CaptiveCrunch phishing domains.

**Compile:** Splunk ✅ | LogScale ✅ | `sigma check` skipped
**Confidence:** High

```yaml
title: CaptiveCrunch Phishing Domain DNS Query
id: 1e7f5a8b-9c0d-4e2f-3a4b-5c6d7e8f9a0b
status: experimental
description: >
    Detects DNS queries to phishing domains used by Midnight Blizzard in the
    CaptiveCrunch campaign for Device Code Flow abuse targeting Microsoft 365
    credentials.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1528
logsource:
    category: dns_query
detection:
    selection:
        QueryName:
            - 'ms365-device.com'
            - 'ms365-live.com'
            - 'm365-owa.com'
            - 'owa-ms365.com'
    condition: selection
falsepositives:
    - None expected; these are known malicious domains
level: critical
```

<!-- AUDIT: Exact-match on QueryName (Sysmon EID 22). Values are NOT defanged (real domain values required for detection). Four domains from intelligence. IOC-specific; will not fire after domain takedown. -->

#### 6. C2 Infrastructure Network Connection

Detects outbound connections to all six known CaptiveCrunch C2/AitM IP addresses.

**Compile:** Splunk ✅ | LogScale ✅ | `sigma check` skipped
**Confidence:** High

```yaml
title: CaptiveCrunch C2 Infrastructure Network Connection
id: 2f8a6b9c-0d1e-4f3a-4b5c-6d7e8f9a0b1c
status: experimental
description: >
    Detects outbound network connections to known CaptiveCrunch C2 and AitM
    infrastructure IP addresses used by Midnight Blizzard (Storm-2945/APT29).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '213.145.86.112'
            - '31.57.243.154'
            - '38.146.28.75'
            - '38.146.28.132'
            - '104.194.159.150'
            - '107.189.26.194'
    condition: selection
falsepositives:
    - Unlikely; these are dedicated attacker infrastructure IPs
level: critical
```

<!-- AUDIT: DestinationIp is standard Sysmon EID 3 field. Six IPs listed without defanging. IOC-specific; requires update when infrastructure rotates. -->

#### 7. (Dropped) ChocoShell AMSI Bypass via .NET Reflection

**DROPPED:** AMSI bypass detection removed -- generic TTP (detects any AmsiUtils/amsiInitFailed bypass, not ChocoShell-specific). ChocoShell-specific AMSI coverage is provided by YARA rule #11, which combines AMSI bypass strings with ChocoShell-specific indicators (UAC bypass paths, C2 endpoints, browser targets).

#### 8. Wi-Fi Credential Harvesting via Netsh (CaptiveCrunch Hunt)

Detects `netsh wlan show profile key=clear` spawned from PowerShell with -NoP flag, consistent with ChocoShell execution context. Hunt-level; `netsh wlan` wifi enumeration is a well-known technique not exclusive to this campaign.

**Compile:** Splunk ✅ | LogScale ✅ | `sigma check` skipped
**Confidence:** Low (well-known technique; parent-process filter narrows but does not eliminate FPs)

```yaml
title: Wi-Fi Credential Harvesting via Netsh (CaptiveCrunch Hunt)
id: 4b0c8d1e-2f3a-4b5c-6d7e-8f9a0b1c2d3e
status: experimental
description: >
    Detects execution of netsh wlan show profile with key=clear parameter,
    used by ChocoShell and other tools to harvest stored Wi-Fi credentials.
    Narrowed with a parent-process filter requiring PowerShell with -NoP flag,
    consistent with ChocoShell execution context. Hunt-level; netsh wifi
    enumeration is a well-known technique not exclusive to this campaign.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1552.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'netsh'
            - 'wlan'
            - 'show'
            - 'profile'
            - 'key=clear'
    filter_parent:
        ParentCommandLine|contains:
            - '-NoP'
            - '-nop'
            - 'NoProfile'
    condition: selection and filter_parent
falsepositives:
    - IT administrators running Wi-Fi diagnostics from PowerShell with NoProfile flag
    - Automated network diagnostic scripts using PowerShell -NoP
level: low
```

<!-- revision: ATT&CK tag changed from t1555.003 (Credentials from Web Browsers, wrong) to t1552.001 (Credentials In Files); downgraded from medium to low; added parent-process filter for PowerShell -NoP; relabeled as hunt-level -->
<!-- AUDIT: Splunk output: CommandLine="*netsh*" CommandLine="*wlan*" CommandLine="*show*" CommandLine="*profile*" CommandLine="*key=clear*" ParentCommandLine IN ("*-NoP*", "*-nop*", "*NoProfile*"). LogScale output: CommandLine=/netsh/i CommandLine=/wlan/i CommandLine=/show/i CommandLine=/profile/i CommandLine=/key=clear/i ParentCommandLine=/-NoP/i or ParentCommandLine=/-nop/i or ParentCommandLine=/NoProfile/i. Parent-process filter reduces FPs by requiring PowerShell -NoP context. -->

---

### YARA Rules

#### 9. CornFlake RAT Detection (Primary)

Detects CornFlake RAT Go binary via service name, configuration file, and fake progress window theme strings.

**Compile:** yarac ✅
**Confidence:** High

```yara
rule APT29_CornFlake_RAT : CaptiveCrunch MidnightBlizzard
{
    meta:
        description = "Detects CornFlake RAT (Go-based) deployed by Midnight Blizzard in the CaptiveCrunch hotel Wi-Fi campaign. Keys on distinctive strings including service name, config file, evasion window themes, and C2 patterns."
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // Service and persistence artifacts
        $svc1 = "svchost32" ascii wide
        $svc2 = "Cloud Sync Service" ascii wide
        $cfg  = "sync.dat" ascii wide

        // Fake progress window themes
        $theme1 = "winupdate" ascii
        $theme2 = "defender" ascii
        $theme3 = "directx" ascii
        $theme4 = "vcredist" ascii
        $theme5 = "sysopt" ascii
        $theme6 = "netfix" ascii

        // Go binary indicators
        $go1 = "runtime.goexit" ascii
        $go2 = "main.main" ascii

        // Crypto indicators (ECDH P-256)
        $crypto1 = "P-256" ascii
        $crypto2 = "ecdh" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 25MB and
        (
            ($svc1 and $svc2) or
            ($svc1 and $cfg and 2 of ($theme*)) or
            ($svc1 and 1 of ($go*) and 1 of ($crypto*))
        )
}
```

<!-- AUDIT: MZ header check limits to PE files. Three OR'd condition branches each require $svc1 ("svchost32") as anchor. The theme strings (sysopt, netfix) are relatively uncommon and help reduce FPs when combined with service name. Go binary strings (runtime.goexit, main.main) are present in all non-stripped Go PE binaries. 25MB filesize cap accommodates Go binary bloat. -->

#### 10. CornFlake RAT Go Strings Variant

Broader detection variant targeting Go compilation artifacts combined with capability strings.

**Compile:** yarac ✅
**Confidence:** Medium

```yara
rule APT29_CornFlake_RAT_GoStrings : CaptiveCrunch MidnightBlizzard
{
    meta:
        description = "Detects CornFlake RAT via Go compilation artifacts combined with distinctive operational strings. Broader variant targeting the Go binary structure."
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593"
        tlp = "WHITE"
        severity = "high"

    strings:
        $go_build = "Go build" ascii
        $go_runtime = "runtime.goexit" ascii

        // Capability strings
        $cap1 = "keylog" ascii nocase
        $cap2 = "clipboard" ascii nocase
        $cap3 = "screenshot" ascii nocase
        $cap4 = "remote_shell" ascii nocase
        $cap5 = "file_exfil" ascii nocase
        $cap6 = "usb_monitor" ascii nocase

        $svc = "svchost32" ascii wide
        $cfg = "sync.dat" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 25MB and
        1 of ($go*) and
        $svc and
        $cfg and
        2 of ($cap*)
}
```

<!-- AUDIT: Requires all of: MZ header, Go runtime string, svchost32, sync.dat, plus 2 of 6 capability strings. Capability strings are speculative (derived from described capabilities, not confirmed exact strings in the binary) hence medium confidence. If strings are XOR-encoded in the actual sample, this rule may not fire without prior decoding. -->

#### 11. ChocoShell PowerShell Infostealer

Detects ChocoShell PowerShell infostealer via AMSI bypass, UAC bypass, and C2 endpoint patterns.

**Compile:** yarac ✅
**Confidence:** High

```yara
rule APT29_ChocoShell_Infostealer : CaptiveCrunch MidnightBlizzard
{
    meta:
        description = "Detects ChocoShell PowerShell infostealer used by Midnight Blizzard in the CaptiveCrunch campaign. Targets browser credentials, M365 tokens, and Wi-Fi creds with multiple UAC bypass techniques."
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // AMSI bypass via .NET reflection
        $amsi1 = "amsiInitFailed" ascii wide nocase
        $amsi2 = "AmsiUtils" ascii wide nocase

        // UAC bypass registry paths
        $uac1 = "Environment\\windir" ascii wide nocase
        $uac2 = "wsreset" ascii wide nocase
        $uac3 = "Folder\\shell\\open\\command" ascii wide nocase
        $uac4 = "sdclt" ascii wide nocase
        $uac5 = "SilentCleanup" ascii wide nocase

        // C2 beacon endpoints
        $c2_1 = "pixel.gif" ascii wide
        $c2_2 = "polyfill-7e2b.min.js" ascii wide
        $c2_3 = "/t/event" ascii wide

        // Browser credential theft targets
        $browser1 = "App-Bound Encryption" ascii wide nocase
        $browser2 = "NSS" ascii wide
        $browser3 = "tbres_" ascii wide

        // Wi-Fi credential harvesting
        $wifi = "netsh wlan show profile" ascii wide nocase

        // PowerShell indicators
        $ps1 = "-NoP" ascii wide nocase
        $ps2 = "Invoke-Expression" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            (2 of ($amsi*) and 1 of ($uac*)) or
            (1 of ($amsi*) and 2 of ($uac*) and 1 of ($c2_*)) or
            (2 of ($c2_*) and 1 of ($browser*) and 1 of ($uac*)) or
            ($wifi and 1 of ($amsi*) and 1 of ($c2_*)) or
            (1 of ($ps*) and 1 of ($amsi*) and 2 of ($uac*) and 1 of ($browser*))
        )
}
```

<!-- AUDIT: No MZ header check because ChocoShell is a PowerShell script (not PE). 5MB filesize cap. Five OR'd condition branches each require cross-category string matches (AMSI+UAC, UAC+C2, C2+browser, etc.) to reduce false positives. The "polyfill-7e2b.min.js" string is highly specific to this campaign's C2 infrastructure. All string references use real values (not defanged). -->

---

### Snort 3 Rules

#### 12. ChocoShell C2 Beacon via Tracking Pixel

Detects HTTP GET requests to the ChocoShell beacon endpoint disguised as a tracking pixel.

**Compile:** ⚠️ Structural check only (Snort 3 not installed)
**Confidence:** High

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch ChocoShell C2 Beacon via Tracking Pixel"; flow:established, to_server; http_method; content:"GET"; http_uri; content:"/t/pixel.gif?m=", fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created 2026-08-05; sid:2100101; rev:1;)
```

<!-- AUDIT: Uses http service protocol for http_uri sticky buffer. flow:established,to_server gates on client requests only. fast_pattern on the URI content. Semicolons terminate all options. No Suricata dot-notation (correct for Snort 3). -->

#### 13. ChocoShell C2 Payload Delivery via Polyfill URI

Detects HTTP requests to the specific polyfill-7e2b.min.js C2 payload URI.

**Compile:** ⚠️ Structural check only
**Confidence:** High

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch ChocoShell C2 Payload Delivery via Polyfill"; flow:established, to_server; http_uri; content:"/cdn/chunks/polyfill-7e2b.min.js", fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created 2026-08-05; sid:2100102; rev:1;)
```

<!-- AUDIT: URI path is highly specific (includes the hash fragment "7e2b"). Unlikely to match legitimate polyfill CDNs which use different naming conventions. -->

#### 14. ChocoShell C2 Exfil via Event Endpoint

Detects HTTP POST to the /t/event exfiltration endpoint, restricted to known C2 IPs to reduce false positives from legitimate analytics endpoints.

**Compile:** ⚠️ Structural check only
**Confidence:** Medium (URI alone is too generic; IP restriction required)

```
alert http $HOME_NET any -> [213.145.86.112,107.189.26.194] any (msg:"Actioner - CaptiveCrunch ChocoShell C2 Exfil via Event Endpoint"; flow:established, to_server; http_method; content:"POST"; http_uri; content:"/t/event", fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created 2026-08-05; sid:2100103; rev:2;)
```

<!-- revision: added destination IP restriction to C2 IPs (213.145.86.112, 107.189.26.194) to reduce FPs from legitimate /t/event analytics endpoints; bumped rev to 2 -->
<!-- AUDIT: "/t/event" is too short/generic on its own. Destination restricted to the two known ChocoShell C2 IPs. Will need updates as infrastructure rotates. -->

#### 15-17. C2 IP Address Alerts

Detects network connections to CaptiveCrunch C2 and AitM infrastructure IPs.

**Compile:** ⚠️ Structural check only
**Confidence:** High

```
alert ip $HOME_NET any -> 213.145.86.112 any (msg:"Actioner - CaptiveCrunch C2 IP 213.145.86.112 (ChocoShell C2)"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created 2026-08-05; sid:2100104; rev:1;)

alert ip $HOME_NET any -> 107.189.26.194 any (msg:"Actioner - CaptiveCrunch C2 IP 107.189.26.194 (ChocoShell C2/DNS)"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created 2026-08-05; sid:2100105; rev:1;)

alert ip $HOME_NET any -> [31.57.243.154,38.146.28.75,38.146.28.132,104.194.159.150] any (msg:"Actioner - CaptiveCrunch AitM Infrastructure IP"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created 2026-08-05; sid:2100106; rev:1;)
```

<!-- AUDIT: ip protocol for raw IP matching regardless of port/service. IP addresses are not defanged. IOC-specific; require updates as infrastructure rotates. -->

---

### Suricata Rules

#### 18. Phishing Domain TLS SNI Detection

Detects TLS ClientHello with SNI matching CaptiveCrunch phishing domains (4 rules, one per domain).

**Compile:** ⚠️ Structural check only (Suricata not installed)
**Confidence:** High

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch Phishing Domain ms365-device.com (TLS SNI)"; flow:established,to_server; tls.sni; content:"ms365-device.com"; nocase; endswith; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-05; sid:2100201; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch Phishing Domain ms365-live.com (TLS SNI)"; flow:established,to_server; tls.sni; content:"ms365-live.com"; nocase; endswith; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-05; sid:2100202; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch Phishing Domain m365-owa.com (TLS SNI)"; flow:established,to_server; tls.sni; content:"m365-owa.com"; nocase; endswith; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-05; sid:2100203; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch Phishing Domain owa-ms365.com (TLS SNI)"; flow:established,to_server; tls.sni; content:"owa-ms365.com"; nocase; endswith; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-05; sid:2100204; rev:1;)
```

<!-- AUDIT: Uses tls protocol with tls.sni sticky buffer (Suricata dot-notation, not Snort underscore). endswith modifier ensures exact domain match without subdomain false positives. nocase for case-insensitive SNI matching. Domain values are NOT defanged. Each domain gets its own SID for granular alerting. -->

#### 19. ChocoShell C2 HTTP URI Patterns

Detects HTTP requests to ChocoShell C2 beacon, payload, and exfil endpoints. The /t/event sub-rule is IP-restricted to known C2 servers to reduce false positives.

**Compile:** ⚠️ Structural check only
**Confidence:** High (beacon/polyfill), Medium (event endpoint -- IP-restricted)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch ChocoShell C2 Beacon via Tracking Pixel"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/t/pixel.gif?m="; startswith; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-05; sid:2100205; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch ChocoShell C2 Payload via Polyfill URI"; flow:established,to_server; http.uri; content:"/cdn/chunks/polyfill-7e2b.min.js"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-05; sid:2100206; rev:1;)

alert http $HOME_NET any -> [213.145.86.112,107.189.26.194] any (msg:"Actioner - CaptiveCrunch ChocoShell C2 Exfil via Event Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/t/event"; startswith; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-05; sid:2100207; rev:2;)
```

<!-- revision: /t/event sub-rule (SID 2100207) destination restricted to C2 IPs (213.145.86.112, 107.189.26.194) to reduce FPs; bumped rev to 2 -->
<!-- AUDIT: Uses Suricata dot-notation (http.method, http.uri). startswith modifier on URI content for pixel.gif and /t/event paths. The polyfill URI includes the specific hash "7e2b" making it highly distinctive. /t/event sub-rule now IP-restricted to avoid matching legitimate analytics. -->

#### 20. C2 IP Address Alerts

Detects network connections to CaptiveCrunch C2 and AitM IPs.

**Compile:** ⚠️ Structural check only
**Confidence:** High

```
alert ip $HOME_NET any -> 213.145.86.112 any (msg:"Actioner - CaptiveCrunch C2 IP 213.145.86.112 (ChocoShell C2)"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-05; sid:2100208; rev:1;)

alert ip $HOME_NET any -> 107.189.26.194 any (msg:"Actioner - CaptiveCrunch C2 IP 107.189.26.194 (ChocoShell C2/DNS)"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-05; sid:2100209; rev:1;)

alert ip $HOME_NET any -> [31.57.243.154,38.146.28.75,38.146.28.132,104.194.159.150] any (msg:"Actioner - CaptiveCrunch AitM Infrastructure IPs"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-05; sid:2100210; rev:1;)
```

<!-- AUDIT: ip protocol for raw IP matching. Suricata metadata uses created_at (underscore) per convention. IPs not defanged. IOC-specific. -->

## Lessons Learned

The CaptiveCrunch campaign demonstrates that physical-proximity attack vectors remain viable and attractive even for sophisticated state actors with extensive remote access capabilities. The use of hotel Wi-Fi captive portals as a malware delivery mechanism exploits a fundamental trust assumption: users expect to interact with a web page before gaining internet access, making them unusually receptive to prompts, downloads, and redirects during this interaction. The campaign's multi-layered credential theft approach -- combining browser credential extraction, M365 token theft, WAM token harvesting, and Wi-Fi credential harvesting -- shows that a single endpoint compromise in a travel context can cascade into enterprise-wide risk. Defenders should treat travel-device security as a distinct threat model requiring always-on VPN, restricted Device Code Flow authentication, and aggressive post-travel credential rotation policies.

## Sources

- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/) -- primary technical analysis and IOC disclosure
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/hotel-wi-fi-attacks-use-custom-malware-to-breach-microsoft-365-accounts/) -- reporting on malware capabilities and M365 targeting
- [The Hacker News](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html) -- reporting on captive portal hijacking mechanism
- [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/captivecrunch-midnight-blizzard/) -- campaign scope and attribution details
- [SC World](https://www.scworld.com/news/russia-linked-midnight-blizzard-targets-hotel-wi-fi-networks-in-us-europe) -- geographic scope of targeting (US and Europe)
- [The Register](https://www.theregister.com/security/2026/08/03/russias-svr-borks-public-wi-fis-for-digital-surveillance/5282399) -- SVR attribution and surveillance objectives

---
*Report generated by Actioner*
