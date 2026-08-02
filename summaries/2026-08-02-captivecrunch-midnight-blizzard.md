# Technical Analysis Report: CaptiveCrunch Campaign — Storm-2945 / Midnight Blizzard (2026-08-02)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-02
Version: DRAFT

## Executive Summary

Since early May 2026, Storm-2945 -- an operational sub-cluster of Midnight Blizzard (APT29/NOBELIUM), the Russian SVR-linked threat group -- has been conducting a campaign dubbed **CaptiveCrunch** that compromises hotel and hospitality WiFi captive portal gateways to deliver malware and steal credentials from travelers worldwide. The campaign manipulates DNS and HTTP traffic on captive portal networks at hotels, conference centers, and shared venues to redirect guests toward ClickFix-style fake update prompts that deliver the **CornFlake** Go-based RAT and the **ChocoShell** in-memory PowerShell stealer. Since July 16, the campaign escalated to include device code OAuth phishing, granting attackers MFA-satisfied access to Microsoft 365 accounts. The C2 infrastructure is managed via **FruitStone**, a web-based operator panel disguised as "CloudSync Console." The campaign primarily targets corporate travelers and government/diplomatic personnel, consistent with Midnight Blizzard's known victimology.

## Background: Hospitality Captive Portal Networks

Captive portals are the sign-in gateways used by hotels, conference centers, airports, and shared venues to authenticate guests before granting WiFi access. Because the captive portal gateway often serves as the DNS resolver for connected devices, administrative control of that gateway gives an attacker the ability to forge DNS responses and redirect HTTP traffic for all connected guests. This campaign exploits that architectural trust to manipulate what travelers see when they connect to venue WiFi, weaponizing a ubiquitous travel experience. Notable commonalities in equipment and management systems across multiple affected networks suggest the compromise may extend beyond isolated venue intrusions to shared infrastructure within the captive portal ecosystem.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-02-27 | IP 107.189.26[.]194 first observed (ChocoShell C2 / DNS resolver) |
| 2026-04-28 | IP 104.194.159[.]150 first observed (AitM infrastructure) |
| 2026-05 (early) | DNS and HTTP traffic manipulation from captive portal networks begins |
| 2026-05-14 | Domain ms365-live[.]com first observed |
| 2026-07-01 | IPs 38.146.28[.]75 and 213.145.86[.]112 first observed |
| 2026-07-03 | CornFlake RAT sample first observed (SHA-256: 918fa52a...) |
| 2026-07-10 | ChocoShell stealer sample first observed (SHA-256: be998574...) |
| 2026-07-15 | IP 38.146.28[.]132 first observed (DNS resolver) |
| 2026-07-16 | Device code phishing integrated into captive portal redirects; IP 31.57.243[.]154 first observed |
| 2026-07-20 | Domain m365-owa[.]com first observed |
| 2026-07-23 | ReliaQuest public disclosure of DNS poisoning / credential theft activity; domain ms365-device[.]com first observed |
| 2026-07-31 | Microsoft Security Blog publishes full CaptiveCrunch analysis |

## Root Cause: Captive Portal Gateway Compromise

Storm-2945 gained administrative control of captive portal gateways at hospitality venues worldwide. The exact initial access method is under investigation, but Microsoft assesses a combination of exposed management interfaces and weak or reused administrator credentials (low-to-medium confidence). Once in control, the gateway served as both the DNS resolver and HTTP redirect point for all connected devices, enabling DNS answer forgery and traffic manipulation without requiring endpoint compromise.

## Technical Analysis of the Malicious Payload

### 1. Initial Access and Delivery via ClickFix

Connected devices receive manipulated DNS responses and HTTP redirects through the compromised captive portal. Guests are presented with **ClickFix-style** social engineering prompts disguised as legitimate system operations:

- "Windows Driver Repair Utility" with manual script verification instructions
- "Google verification check failed" with paste-and-run instructions
- Fake browser updates, DirectX installers, PDF viewer updates, and disk optimization tools

The dropper type is configurable at build time via FruitStone with options including: `winupdate`, `defender`, `directx`, `vcredist`, `sysopt`, `netfix`, `browser`, `pdfview`. Android APK delivery was also observed on the same landing pages.

### 2. CornFlake RAT (Windows, Golang)

CornFlake is a full-featured Go-based remote access trojan with the following characteristics:

**Installation and Persistence:**
- Copies to `%APPDATA%\svchost32\svchost32.exe`
- Registers Windows service named `svchost32` with display name "Cloud Sync Service" and description "Synchronizes files with the cloud storage provider"
- Creates Registry Run key and scheduled task for redundant persistence
- Deploys a watchdog routine that continuously restores removed persistence mechanisms
- Runtime configuration stored in `sync.dat` (supports hot reconfiguration)

**Capabilities:**
- Keylogging (Raw Input API, captures password fields)
- Clipboard monitoring (SHA-256 deduplication, records active window title)
- Screenshot capture (idle-triggered and on-demand)
- Audio surveillance (WASAPI-based microphone, WAV encoding)
- Video surveillance (Media Foundation webcam, JPEG encoding)
- Browser credential theft (ChromeKatz-derived; Chrome App-Bound Encryption bypass; Firefox NSS/SDR decryption)
- File exfiltration (extension-based targeting, real-time filesystem monitoring, 1,000 files or 500 MB per cycle throttle)
- USB monitoring (detects and scans removable media insertion)
- Security posture survey (18 categories: AV/EDR products, Defender exclusions, UAC level, RDP history, Office MRU, credential hints)
- Remote shell (cmd.exe or PowerShell with -NoP flag)

**C2 Communication:**
- ECDH P-256 ephemeral key exchange with SHA-256 session key derivation
- Custom JSON protocol over encrypted channel
- Ephemeral key per session (prevents traffic decryption without session-specific private keys)
- Localhost HTTP API endpoints: `/upload`, `/reload`, `/status`

### 3. ChocoShell (In-Memory PowerShell Stealer)

ChocoShell is delivered and executed entirely in-memory via `[ScriptBlock]::Create()` after Base64 decoding. The script was authored with full developer comments -- consistent coding standards suggest potential AI-assisted code generation.

**C2 Communication:**
- Hardcoded C2 server: 213.145.86[.]112
- Beacon: `/t/pixel.gif?m=<status>` (masquerades as tracking pixel)
- Payload fetch: `/cdn/chunks/polyfill-7e2b.min.js` (disguised as JavaScript polyfill)
- Exfiltration: POST to `/t/event`
- Data format: GZip-compressed, Base64-wrapped JSON

**Defense Evasion:**
- AMSI bypass via .NET reflection (prevents ScriptBlock scanning)
- Evasion of Microsoft behavioral detection on suspicious PowerShell web request cmdlets
- Timing-based sandbox / VM detection (silent exit if detected)

**Privilege Escalation (Three silent UAC bypass techniques with ordered fallback):**

1. **SilentCleanup task hijack:** Writes malicious command to `HKCU\Environment\windir`, triggers the built-in SilentCleanup scheduled task, cleans up the registry value after 2 seconds
2. **wsreset.exe COM hijack:** Creates COM handler key in `HKCU\Software\Classes`, launches auto-elevating Windows Store reset tool
3. **sdclt.exe folder hijack:** Hijacks `HKCU\Software\Classes\Folder\shell\open\command`, launches Windows Backup utility with `/KickOffElev` flag
4. **Fallback:** Visible UAC prompt via `Start-Process -Verb RunAs`

**Credential and Token Theft:**
- Chromium browser credential theft (Chrome, Edge, Brave, Opera, Opera GX, Vivaldi): master key extraction from Local State, App-Bound Encryption bypass (Chrome v127+) via SYSTEM-level DPAPI access through token borrowing from winlogon.exe/wininit.exe/services.exe, Chrome DevTools Protocol remote debugging (`--remote-debugging-port`) with `Network.getAllCookies` command
- Firefox family browser theft (Firefox, Waterfox, LibreWolf, Floorp, Zen): copies unencrypted `cookies.sqlite` databases
- Microsoft 365 / Azure AD access tokens, refresh tokens
- Web Account Manager (WAM) tokens from `.tbres` files in Token Broker cache
- Wi-Fi credential harvesting via `netsh wlan show profile` with `key=clear`

**Anti-Forensics:**
- Locks Defender signature updates via downloaded module
- Creates Volume Shadow Copy (VSS) for database access
- Deletes VSS shadow copies via WMI post-exfiltration
- Nulls all data variables, forces garbage collection
- Removes temporary elevation scripts
- Verifies removal of UAC bypass registry keys

**WinGet DSC Variant:** Execution within WinGet Desired State Configuration host process (ConfigurationRemotingServer)

### 4. C2 Infrastructure — FruitStone Panel

FruitStone is a web-based C2 panel branded as "CloudSync Console" with footer text "Acuity Systems, Inc. -- Cloud Infrastructure Portal v3.2.1." Key features:

- JWT-based authentication with session revocation, rate limiting with IP blocking, multi-operator support
- Real-time agent status via Server-Sent Events (SSE) with geographic distribution visualization
- Campaign builder wizard: identity, capabilities toggle, file path targeting, evasion settings (Garble symbol randomization, XOR string encoding, GZip upload compression)
- Infrastructure management: proxy relays with TLS certificate tracking, beacon profiles with sleep intervals and TLS SNI spoofing (e.g., `teams.microsoft.com`), DNS fallback domains, staging servers with push-to-deploy

### 5. Device Code OAuth Phishing (July 16+)

Since July 16, CaptiveCrunch landing pages added device code phishing: guests are redirected to Microsoft's legitimate device code authentication flow, where the attacker initiates the request and presents the user with a code to enter at Microsoft's real sign-in page. When the victim enters the code, they authenticate the attacker's session instead of their own, granting the attacker MFA-satisfied access to the victim's Microsoft 365 account.

### 6. Anti-Forensics / Evasion Techniques

- AMSI bypass via .NET reflection
- Timing-based sandbox/VM detection
- Garble symbol randomization for Go binaries
- XOR string encoding
- TLS SNI spoofing (e.g., `teams.microsoft.com`)
- VSS shadow copy manipulation and cleanup
- Registry key cleanup post-exploitation
- Ephemeral ECDH keys preventing retrospective traffic decryption

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | %APPDATA%\svchost32\svchost32.exe | 918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593 | CornFlake RAT binary |
| Windows | %APPDATA%\svchost32\sync.dat | -- | CornFlake runtime configuration file |
| Windows | (in-memory) | be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c | ChocoShell PowerShell stealer |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | ms365-device[.]com | AitM phishing domain (first seen 2026-07-23) |
| Domain | ms365-live[.]com | AitM phishing domain (first seen 2026-05-14) |
| Domain | m365-owa[.]com | AitM phishing domain (first seen 2026-07-20) |
| Domain | owa-ms365[.]com | AitM phishing domain (first seen 2026-07-16) |
| IP | 31.57.243[.]154 | AitM infrastructure (first seen 2026-07-16) |
| IP | 38.146.28[.]75 | AitM infrastructure (first seen 2026-07-01) |
| IP | 38.146.28[.]132 | DNS resolver (first seen 2026-07-15) |
| IP | 104.194.159[.]150 | AitM infrastructure (first seen 2026-04-28) |
| IP | 107.189.26[.]194 | ChocoShell C2 / DNS resolver (first seen 2026-02-27) |
| IP | 213.145.86[.]112 | ChocoShell C2 (first seen 2026-07-01) |
| URL Pattern | /t/pixel.gif?m=\<status\> | ChocoShell C2 beacon (tracking pixel disguise) |
| URL Pattern | /cdn/chunks/polyfill-7e2b.min.js | ChocoShell payload delivery (polyfill disguise) |
| URL Pattern | /t/event | ChocoShell data exfiltration endpoint |

### Behavioral

- Windows service `svchost32` registered with display name "Cloud Sync Service" and description "Synchronizes files with the cloud storage provider"
- Registry modification: `HKCU\Environment\windir` (SilentCleanup UAC bypass)
- Registry modification: `HKCU\Software\Classes\Folder\shell\open\command` (sdclt.exe UAC bypass)
- COM hijacking via `HKCU\Software\Classes` (wsreset.exe UAC bypass)
- Process execution: `netsh wlan show profile <name> key=clear` (WiFi credential harvesting)
- Chrome launched with `--remote-debugging-port` and `--restore-last-session` flags
- File creation at `%APPDATA%\svchost32\svchost32.exe` shortly after WiFi connectivity test (NCSI endpoints)
- GZip-compressed, Base64-wrapped JSON exfiltration via POST

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.002 | Phishing: Spearphishing Link | Device code phishing via captive portal redirects to legitimate Microsoft sign-in |
| T1059.001 | Command and Scripting Interpreter: PowerShell | ChocoShell in-memory PowerShell execution via ScriptBlock::Create() |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | CornFlake remote shell via cmd.exe |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | CornFlake persistence via Run key registration |
| T1543.003 | Create or Modify System Process: Windows Service | CornFlake "svchost32" service creation |
| T1053.005 | Scheduled Task/Job: Scheduled Task | CornFlake scheduled task persistence |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | ChocoShell SilentCleanup/wsreset.exe/sdclt.exe UAC bypasses |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defender signature update locking; AMSI bypass |
| T1140 | Deobfuscate/Decode Files or Information | Base64-decoded ChocoShell execution |
| T1027 | Obfuscated Files or Information | XOR string encoding; Garble symbol randomization for Go binaries |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Timing-based sandbox/VM detection |
| T1112 | Modify Registry | UAC bypass registry manipulation (windir, COM handlers, folder shell command) |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | ChromeKatz-derived browser credential theft with ABE bypass |
| T1056.001 | Input Capture: Keylogging | CornFlake Raw Input API keylogger |
| T1115 | Clipboard Data | CornFlake clipboard monitoring with SHA-256 dedup |
| T1113 | Screen Capture | CornFlake idle-triggered and on-demand screenshot capture |
| T1123 | Audio Capture | CornFlake WASAPI-based microphone recording |
| T1125 | Video Capture | CornFlake Media Foundation webcam capture |
| T1552.001 | Unsecured Credentials: Credentials in Files | WiFi credential harvesting via netsh; WAM token theft from .tbres files |
| T1071.001 | Application Layer Protocol: Web Protocols | ChocoShell HTTPS C2 with URI path obfuscation |
| T1005 | Data from Local System | CornFlake file exfiltration with extension-based targeting |
| T1041 | Exfiltration Over C2 Channel | GZip-compressed JSON POST to /t/event |
| T1621 | Multi-Factor Authentication Request Generation | Device code phishing granting MFA-satisfied access |

## Impact Assessment

The campaign targets corporate travelers, government officials, and diplomatic personnel at hospitality venues worldwide. Impact dimensions:

- **Breadth:** Worldwide targeting across multiple countries via compromised captive portal infrastructure; potential for thousands of affected travelers
- **Depth:** Full endpoint compromise (keylogging, audio/video surveillance, credential theft, file exfiltration); MFA-satisfied M365 account takeover via device code phishing; access to corporate networks via stolen tokens and credentials
- **Stealth:** In-memory execution, AMSI bypass, anti-forensic cleanup, ephemeral encryption keys preventing retrospective analysis
- **Attribution confidence:** Microsoft attributes to Storm-2945 as a sub-cluster of Midnight Blizzard (SVR). ReliaQuest noted TTP overlap with APT28 (GRU/Forest Blizzard) but acknowledged assessment rests on TTP overlap rather than direct technical linkage.

## Detection & Remediation

### Immediate Detection

**Check for CornFlake persistence:**
```
dir "%APPDATA%\svchost32\svchost32.exe"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\svchost32"
schtasks /query /fo list /v | findstr /i "svchost32"
```

**Check for UAC bypass residue:**
```
reg query "HKCU\Environment" /v windir
reg query "HKCU\Software\Classes\Folder\shell\open\command"
```

**Check for ChocoShell C2 connections (network logs):**
Search proxy/firewall logs for: `/t/pixel.gif?m=`, `/cdn/chunks/polyfill-7e2b.min.js`, `/t/event`

**Check connections to known infrastructure:**
Search network logs for connections to: 213.145.86[.]112, 107.189.26[.]194, 31.57.243[.]154, 38.146.28[.]75, 38.146.28[.]132, 104.194.159[.]150

**Check DNS for phishing domains:**
Search DNS logs for: ms365-device[.]com, ms365-live[.]com, m365-owa[.]com, owa-ms365[.]com

### Remediation

1. **Containment:** Isolate affected endpoints from the network immediately; revoke all Microsoft 365 / Azure AD sessions and refresh tokens for affected users
2. **Eradication:** Remove CornFlake binary, service, scheduled tasks, and Run key; verify removal of all UAC bypass registry keys; scan for `sync.dat` configuration file
3. **Credential rotation:** Reset passwords for all accounts authenticated from affected devices; rotate WiFi credentials harvested via netsh; revoke and reissue OAuth tokens
4. **Identity review:** Audit Azure AD sign-in logs for device code authentication events from unusual locations; review conditional access policy gaps
5. **Network investigation:** Audit captive portal gateway configurations; check for unauthorized DNS resolver changes; verify management interface access controls

### Long-Term Hardening

- Disable Wi-Fi auto-connect to open networks on enterprise-managed devices via MDM
- Implement phishing-resistant MFA (passkeys, FIDO2) for all accounts
- Block device code authentication flow via Conditional Access policies where possible
- Deploy enterprise travel routers establishing encrypted tunnels to trusted infrastructure
- Train employees to recognize ClickFix-style paste-and-run prompts
- Restrict corporate credential use on guest/hotel network registration pages
- Implement Continuous Access Evaluation for real-time access revocation

## Detection Rules

These detections target CornFlake RAT persistence, ChocoShell C2 communication, UAC bypass techniques, and network indicators from the CaptiveCrunch campaign. PoC/advisory-specific altitude (strict). Note: `sigma check` was blocked by proxy (unable to fetch MITRE ATT&CK data); all Sigma rules validated via `sigma convert` to both Splunk and CrowdStrike LogScale (exit 0).

### Sigma: CornFlake RAT Windows Service Registration

Detects registration of the CornFlake RAT `svchost32` service with its distinctive display name and description.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0. Keys on campaign-specific service name/display/description strings. Minimal FP risk — service name and description are unique to this campaign. -->
```yaml
title: CornFlake RAT Windows Service Registration
id: 7c4e1a3b-9f2d-4e8a-b5c6-d1e7f0a2b3c4
status: experimental
description: >
    Detects registration of the CornFlake RAT Windows service with the distinctive
    service name "svchost32" and display name "Cloud Sync Service" used by Storm-2945
    in the CaptiveCrunch campaign.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026/08/02
tags:
    - attack.t1543.003
logsource:
    category: registry_set
    product: windows
detection:
    selection_path:
        TargetObject|contains: '\SYSTEM\CurrentControlSet\Services\svchost32'
    selection_values:
        Details|contains:
            - 'Cloud Sync Service'
            - 'Synchronizes files with the cloud storage provider'
    condition: selection_path or selection_values
falsepositives:
    - Unknown; service name and description are campaign-specific
level: high
```

### Sigma: CornFlake RAT File Drop and Persistence

Detects CornFlake RAT file creation at its distinctive `svchost32\svchost32.exe` path under AppData\Roaming.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Keys on unique nested directory + binary name. No known benign software uses this path pattern. -->
```yaml
title: CornFlake RAT File Drop and Persistence
id: a2b3c4d5-e6f7-4890-abcd-ef1234567890
status: experimental
description: >
    Detects CornFlake RAT persistence indicators including the distinctive file path
    svchost32\svchost32.exe under AppData\Roaming used by Storm-2945 in the
    CaptiveCrunch campaign.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026/08/02
tags:
    - attack.t1547.001
    - attack.t1053.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\svchost32\svchost32.exe'
    condition: selection
falsepositives:
    - Unknown; path is campaign-specific
level: high
```

### Sigma: ChocoShell UAC Bypass via SilentCleanup Environment Variable Hijack

Detects the SilentCleanup UAC bypass where `HKCU\Environment\windir` is modified to hijack the elevated task execution path.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. This UAC bypass technique is well-documented but setting the windir env var under HKCU is extremely rare in benign contexts. -->
```yaml
title: ChocoShell UAC Bypass via SilentCleanup Environment Variable Hijack
id: b3c4d5e6-f7a8-4901-bcde-f12345678901
status: experimental
description: >
    Detects the SilentCleanup UAC bypass technique used by ChocoShell where the windir
    environment variable is set under HKCU\Environment to hijack the elevated
    SilentCleanup scheduled task execution path.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026/08/02
tags:
    - attack.t1548.002
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Environment\windir'
        TargetObject|contains: 'HKCU'
    condition: selection
falsepositives:
    - Legitimate software modifying user-level windir environment variable (rare)
level: high
```

### Sigma: ChocoShell C2 Beacon URI Pattern

Detects HTTP requests matching the ChocoShell C2 beacon (`/t/pixel.gif?m=`), payload fetch (`polyfill-7e2b`), and exfiltration (`/t/event`) URI patterns.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. URI patterns are distinctive and campaign-specific. Filter by destination IP/domain for environments with high-volume tracking pixels. -->
```yaml
title: ChocoShell C2 Beacon URI Pattern
id: c4d5e6f7-a8b9-4012-cdef-123456789012
status: experimental
description: >
    Detects HTTP requests matching the ChocoShell C2 beacon and payload URI patterns
    used in the CaptiveCrunch campaign including the tracking pixel beacon and
    polyfill-disguised payload delivery paths.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026/08/02
tags:
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_beacon:
        cs-uri-stem|contains: '/t/pixel.gif'
        cs-uri-query|contains: 'm='
    selection_payload:
        cs-uri-stem: '/cdn/chunks/polyfill-7e2b.min.js'
    selection_exfil:
        cs-method: 'POST'
        cs-uri-stem: '/t/event'
    condition: selection_beacon or selection_payload or selection_exfil
falsepositives:
    - Legitimate tracking pixels with similar URI structure (filter by destination)
level: high
```

### Sigma: Wi-Fi Credential Harvesting via netsh

Detects `netsh wlan show profile` with `key=clear` used by ChocoShell to harvest stored Wi-Fi credentials.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. netsh wlan profile dump with key=clear is a known technique used by multiple threat actors; medium confidence due to legitimate admin usage. -->
```yaml
title: Wi-Fi Credential Harvesting via netsh
id: d5e6f7a8-b9c0-4123-defa-234567890123
status: experimental
description: >
    Detects use of netsh to enumerate Wi-Fi profiles with cleartext keys, a technique
    used by ChocoShell in the CaptiveCrunch campaign to harvest stored Wi-Fi credentials.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026/08/02
tags:
    - attack.t1552.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\netsh.exe'
        CommandLine|contains|all:
            - 'wlan'
            - 'show'
            - 'profile'
            - 'key=clear'
    condition: selection
falsepositives:
    - Network administrators troubleshooting Wi-Fi connectivity
level: medium
```

### Snort: ChocoShell C2 Beacon and Payload Fetch

Detects outbound HTTP requests to the ChocoShell tracking-pixel beacon URI and polyfill-disguised payload delivery path (Snort 2.9 syntax).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c (minimal config with classification.config) -T exit 0. Snort 2.9 syntax with http_uri modifier. URI patterns are campaign-specific. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ChocoShell C2 Beacon Pixel URI"; flow:established,to_server; content:"/t/pixel.gif"; http_uri; fast_pattern; content:"m="; http_uri; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; sid:2100001; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ChocoShell C2 Payload Fetch polyfill-7e2b"; flow:established,to_server; content:"/cdn/chunks/polyfill-7e2b.min.js"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; sid:2100002; rev:1;)
```

### Suricata: CaptiveCrunch AitM Domain DNS Queries

Detects DNS queries to the four known CaptiveCrunch adversary-in-the-middle phishing domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Dot-notation DNS sticky buffers. Domain IOCs are campaign-specific with no benign overlap. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CaptiveCrunch AitM Domain"; flow:to_server; dns.query; content:"ms365-device.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-02; sid:2200001; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CaptiveCrunch AitM Domain ms365-live"; flow:to_server; dns.query; content:"ms365-live.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-02; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CaptiveCrunch AitM Domain m365-owa"; flow:to_server; dns.query; content:"m365-owa.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-02; sid:2200003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CaptiveCrunch AitM Domain owa-ms365"; flow:to_server; dns.query; content:"owa-ms365.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-02; sid:2200004; rev:1;)
```

### Suricata: ChocoShell C2 HTTP Beacon and Payload Fetch

Detects outbound HTTP matching the ChocoShell tracking-pixel beacon and polyfill-disguised payload delivery URI patterns.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Dot-notation HTTP sticky buffers. URI patterns are distinctive and campaign-specific. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChocoShell C2 Beacon Pixel URI"; flow:established,to_server; http.uri; content:"/t/pixel.gif"; fast_pattern; content:"m="; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-02; sid:2200005; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChocoShell C2 Payload Fetch polyfill-7e2b"; flow:established,to_server; http.uri; content:"/cdn/chunks/polyfill-7e2b.min.js"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-02; sid:2200006; rev:1;)
```

### YARA: CornFlake RAT and ChocoShell Stealer

Detects CornFlake RAT via its distinctive service name, display name, and dropper strings; detects ChocoShell via its C2 URI patterns and credential theft indicators. CornFlake rule sample-tested: fires on positive, silent on negative.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara positive test: matched Malware_CornFlake_RAT_CaptiveCrunch on pos_cornflake.txt containing published strings (svchost32 + Cloud Sync Service). Negative test: no match on benign file. ChocoShell rule not independently sample-tested (no in-memory script sample). Condition requires 2+ campaign-specific strings to fire, limiting FP. -->
```yara
rule Malware_CornFlake_RAT_CaptiveCrunch
{
    meta:
        description = "Detects CornFlake RAT (Go-based) used by Storm-2945 in the CaptiveCrunch campaign via distinctive strings"
        author = "Actioner"
        date = "2026-08-02"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593"
        severity = "critical"

    strings:
        $svc_name = "svchost32" ascii wide
        $svc_display = "Cloud Sync Service" ascii wide
        $svc_desc = "Synchronizes files with the cloud storage provider" ascii wide
        $cfg_file = "sync.dat" ascii wide
        $api_upload = "/upload" ascii
        $api_reload = "/reload" ascii
        $api_status = "/status" ascii
        $dropper1 = "winupdate" ascii
        $dropper2 = "directx" ascii
        $dropper3 = "vcredist" ascii
        $dropper4 = "sysopt" ascii
        $dropper5 = "netfix" ascii
        $path = "svchost32\\svchost32.exe" ascii wide

    condition:
        filesize < 20MB and
        (
            ($svc_name and $svc_display) or
            ($svc_name and $svc_desc) or
            ($path and 2 of ($dropper*)) or
            ($cfg_file and $svc_name and 2 of ($api*))
        )
}

rule Malware_ChocoShell_Stealer_CaptiveCrunch
{
    meta:
        description = "Detects ChocoShell PowerShell stealer used by Storm-2945 in the CaptiveCrunch campaign via distinctive C2 URI patterns and credential theft strings"
        author = "Actioner"
        date = "2026-08-02"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c"
        severity = "critical"

    strings:
        $c2_beacon = "/t/pixel.gif?m=" ascii wide
        $c2_payload = "/cdn/chunks/polyfill-7e2b.min.js" ascii wide
        $c2_exfil = "/t/event" ascii wide
        $uac1 = "SilentCleanup" ascii wide
        $uac2 = "wsreset.exe" ascii wide
        $uac3 = "sdclt.exe" ascii wide
        $uac4 = "KickOffElev" ascii wide
        $token1 = ".tbres" ascii wide
        $token2 = "Token Broker" ascii wide
        $wifi = "key=clear" ascii wide

    condition:
        filesize < 5MB and
        (
            (2 of ($c2*)) or
            ($c2_beacon and 2 of ($uac*)) or
            ($c2_exfil and $token1 and $token2) or
            ($c2_beacon and $wifi and $token1)
        )
}
```

## Lessons Learned

1. **Captive portal trust is a systemic vulnerability.** The WiFi captive portal architecture -- where the gateway serves as both authentication broker and DNS resolver -- creates a single point of compromise that affects all connected devices. Organizations should treat all traffic on untrusted networks as potentially manipulated, regardless of whether the portal "looks legitimate."

2. **Device code phishing is a growing MFA bypass.** The integration of device code OAuth phishing into captive portal redirects represents a new escalation in credential theft, granting attackers MFA-satisfied session access without needing to intercept MFA codes. Conditional Access policies should block device code flow where possible.

3. **AI-assisted malware development lowers the barrier.** Microsoft noted ChocoShell's full developer comments and consistent coding standards suggest AI-assisted code generation. This aligns with a broader trend of state-sponsored actors leveraging AI to accelerate tooling development.

4. **Multi-layered persistence and evasion require multi-layered detection.** CornFlake's watchdog persistence restoration, ChocoShell's three-tiered UAC bypass with fallback, and ephemeral ECDH encryption demonstrate defense-in-depth on the attacker's side. Defenders need corresponding depth: endpoint (Sigma), network (Snort/Suricata), and file (YARA) detections operating together.

## Sources

- [Microsoft Security Blog: CaptiveCrunch](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/) -- primary technical analysis with full IOCs, malware analysis, and hunting queries
- [The Hacker News: Hijacked Hotel Wi-Fi Pushes Fake Updates to Deliver Surveillance Malware](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html) -- corroborating coverage with additional context on WAM token theft and attribution nuances
- [SecurityAffairs: Russian Hackers Hijack Hotel Wi-Fi to Steal Microsoft 365 Tokens](https://securityaffairs.com/196441/apt/russian-hackers-hijack-hotel-wi-fi-to-steal-microsoft-365-tokens.html) -- additional coverage noting ECDH encryption details and worldwide scope assessment

---
*Report generated by Actioner*
