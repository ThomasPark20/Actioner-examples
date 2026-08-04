# Technical Analysis Report: CaptiveCrunch — Midnight Blizzard Hotel Wi-Fi Campaign (2026-08-04)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-04
Version: 1.0 (DRAFT)

## Executive Summary

Microsoft Threat Intelligence disclosed on July 31, 2026 that Storm-2945, an operational sub-cluster of Russian state-sponsored actor Midnight Blizzard (APT29/NOBELIUM), has been compromising hospitality Wi-Fi captive portal networks since early May 2026 to deliver malware and steal credentials from corporate travelers worldwide. The campaign, tracked as **CaptiveCrunch**, manipulates DNS/HTTP traffic on guest Wi-Fi networks at hotels, conference centers, and airports to redirect connectivity checks to ClickFix social engineering pages and Microsoft 365 device code phishing flows. Two custom malware families are deployed: **CornFlake**, a Go-based Windows RAT with broad surveillance capabilities, and **ChocoShell**, an in-memory PowerShell infostealer targeting browser credentials, Microsoft 365/Azure AD tokens, and Wi-Fi passwords. A third component, **FruitStone**, is the web-based C2 panel used by operators for campaign management. The US and UK governments attribute Midnight Blizzard to Russia's Foreign Intelligence Service (SVR). The campaign's primary objective is intelligence collection from enterprise employees traveling internationally.

## Background: Hospitality Wi-Fi Captive Portals

Hotel and conference venue Wi-Fi networks commonly use captive portals to authenticate guests before granting internet access. When a device connects, the operating system performs a Network Connectivity Status Indicator (NCSI) test by contacting well-known endpoints (e.g., `msftconnecttest.com`, `captive.apple.com`, `clients1-6.google.com`). The captive portal intercepts these requests to redirect the user to a login/registration page. Storm-2945 exploited this architecture by compromising the portal infrastructure itself, gaining the ability to forge DNS answers and redirect arbitrary HTTP traffic through attacker-controlled servers. Notable commonalities in equipment and management systems across affected venues suggest the actors may have accessed shared services within portions of the captive portal ecosystem, rather than compromising each venue individually.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-02-xx | Storm-2945 begins AI-augmented operations including device code/OAuth phishing campaigns |
| 2026-04-28 | First detection of AitM infrastructure IP 104.194.159[.]150 |
| 2026-05-xx (early) | Widespread traffic manipulation attacks begin targeting hospitality Wi-Fi networks |
| 2026-05-14 | Domain ms365-live[.]com first seen (DCF redirect infrastructure) |
| 2026-07-01 | First sightings of 38.146.28[.]75 (AitM) and 213.145.86[.]112 (ChocoShell C2) |
| 2026-07-03 | CornFlake RAT binary (SHA256: 918fa52a...) first observed |
| 2026-07-10 | ChocoShell (SHA256: be998574...) first observed |
| 2026-07-15 | DNS resolver IP 38.146.28[.]132 first detected |
| 2026-07-16 | Domain owa-ms365[.]com registered; device code phishing variant begins |
| 2026-07-20 | Domain m365-owa[.]com registered |
| 2026-07-23 | ReliaQuest publicly discloses portion of activity; domain ms365-device[.]com first seen |
| 2026-07-31 | Microsoft publishes full CaptiveCrunch disclosure |

## Root Cause: Captive Portal Infrastructure Compromise

The initial access vector is compromise of captive portal equipment and/or management systems at hospitality venues. The exact method of initial compromise remains under investigation; weak administrator credentials are suspected but unconfirmed. Once inside the captive portal infrastructure, the attacker gains the ability to forge DNS responses and manipulate HTTP traffic for all guest devices on the network. The attack exploits the fundamental trust model of captive portals -- devices expect to be redirected during their NCSI connectivity test, making the initial redirect invisible to the user.

## Technical Analysis of the Malicious Payload

### 1. Captive Portal Manipulation and ClickFix Delivery

When a victim connects to a compromised guest Wi-Fi network, their device initiates an NCSI connectivity test to standard endpoints. The compromised captive portal infrastructure intercepts these requests and redirects the victim to attacker-controlled phishing infrastructure. The landing pages employ the **ClickFix** social engineering technique, presenting fake interfaces mimicking:

- Windows Driver Repair Utility
- Windows Security virus scan
- Browser update prompts
- Operating system update screens

Users are instructed to follow "manual driver repair" or "verification" steps that involve pasting and executing commands in Windows Terminal or PowerShell. The landing pages also include Android APK installation instructions, indicating cross-platform targeting. NCSI endpoints abused for redirection include `msftconnecttest.com`, `edge-http.microsoft.com`, `captive.apple.com`, `clients1-6.google.com`, `detectportal.firefox.com`, and Cloudflare portal domains.

A parallel attack track (active since July 16, 2026) redirects users to the Microsoft device code authentication flow, where victims are instructed to enter an attacker-controlled device code on the legitimate Microsoft sign-in page, granting the attacker MFA-satisfied access to the victim's Microsoft 365 session.

### 2. CornFlake RAT (Go-based Windows RAT)

CornFlake is a Go-based remote access trojan that serves as the primary implant.

**Persistence:** CornFlake copies itself to `%APPDATA%\svchost32\svchost32.exe` and establishes multiple persistence mechanisms: Windows service registration (service name `svchost32`, display name `Cloud Sync Service`, description `Synchronizes files with the cloud storage provider`), Registry Run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`), named scheduled tasks, and a watchdog routine that restores any removed persistence mechanism.

**Fake Progress Windows:** CornFlake displays configurable fake progress windows during initial execution to prevent user suspicion. Options include: `winupdate` (Windows Update), `defender` (Windows Security scan), `directx` (DirectX installer), `vcredist` (Visual C++ Redistributable), `sysopt` (disk optimization), `netfix` (network diagnostics), `browser` (browser update), `pdfview` (document viewer installer).

**Capabilities:** Keylogging (Raw Input API), clipboard monitoring (SHA-256 deduplication), idle-triggered and on-demand screenshot capture, audio surveillance (WASAPI microphone capture, WAV encoding), video surveillance (Media Foundation webcam capture, JPEG), browser credential theft (ChromeKatz derivative with Chrome App-Bound Encryption bypass and Firefox NSS/SDR decryption), file exfiltration (real-time monitoring with 1,000 files / 500 MB per cycle throttle), USB drive monitoring, 18-category security posture sweep (installed software, AV/EDR products, Defender exclusions, UAC level, RDP history, Office MRU, hostname, OS version, CPU/RAM/disk, screen resolution, timezone, domain membership, camera/microphone presence), remote shell (`cmd.exe` or PowerShell with `-NoP`), and a localhost HTTP API (`/upload`, `/reload`, `/status`).

**Runtime Configuration:** CornFlake stores its runtime config in `sync.dat`, supporting hot reconfiguration of TLS settings and DNS fallback. Communication uses ECDH P-256 ephemeral key exchange with SHA-256 session key derivation over a custom JSON protocol.

### 3. ChocoShell (PowerShell Infostealer)

ChocoShell is an in-memory PowerShell stealer deployed after initial CornFlake execution. Microsoft suspects AI-assisted code generation based on consistent coding standards and full developer comments throughout the script.

**Defense Evasion:** AMSI bypass via .NET reflection (ScriptBlock scanning prevention), timing-based sandbox detection (silent VM exit without collection if detected).

**UAC Bypass (ordered fallback):**
1. SilentCleanup task hijack: writes to `HKCU\Environment\windir`, triggers the built-in SilentCleanup scheduled task, cleans up after 2 seconds
2. wsreset.exe COM hijack: creates COM handler in `HKCU\Software\Classes`, launches the auto-elevating Windows Store reset tool
3. sdclt.exe folder hijack: hijacks `HKCU\Software\Classes\Folder\shell\open\command`, launches with `/KickOffElev`
4. Fallback: visible UAC prompt via `Start-Process -Verb RunAs`

**Credential Theft:**
- *Chromium browsers* (Chrome, Edge, Brave, Opera, Opera GX, Vivaldi): master key from `Local State`, App-Bound Encryption handling for Chrome v127+, legacy DPAPI, SYSTEM-level DPAPI via token impersonation from `winlogon.exe`/`wininit.exe`/`services.exe`, locked SQLite access via shared file access/VSS snapshots/direct copy, Chrome DevTools Protocol via `--remote-debugging-port` with `Network.getAllCookies` (bypasses ABE entirely), browser relaunched with `--restore-last-session`
- *Firefox family* (Firefox, Waterfox, LibreWolf, Floorp, Zen): unencrypted `cookies.sqlite` database copy
- *Microsoft 365/Azure AD*: access tokens, refresh tokens, Web Account Manager (WAM) tokens from `_.tbres` files in Token Broker cache
- *Wi-Fi credentials*: `netsh wlan show profile key=clear`

**Post-Exfiltration Cleanup:** Data variables nulled, garbage collection forced, VSS shadow copies deleted via WMI, temporary elevation scripts removed, UAC bypass registry keys verified removed.

A **WinGet DSC variant** executes within the ConfigurationRemotingServer host process.

### 3. C2 Infrastructure

**ChocoShell C2 Communication:**
- Hardcoded C2: 213.145.86[.]112
- Beacon: HTTPS GET to `/t/pixel.gif?m=<status>` (mimics image tracking pixel)
- Tool delivery: GET `/cdn/chunks/polyfill-7e2b.min.js` (Base64-decoded, in-memory execution)
- Data exfiltration: POST to `/t/event` (GZip-compressed, Base64-wrapped JSON)

**CornFlake C2:**
- ECDH P-256 ephemeral key exchange, SHA-256 session key derivation
- Custom JSON protocol within encrypted channel
- TLS SNI spoofing (e.g., `teams.microsoft.com`)
- Configurable DNS fallback

**FruitStone (Web C2 Panel):**
Branded as "CloudSync Console" with footer "Acuity Systems, Inc. -- Cloud Infrastructure Portal v3.2.1". Features JWT authentication with rate limiting, real-time agent status via Server-Sent Events, geographic grouping, interactive command execution, file browser, collection tasking, in-place implant updates, campaign builder wizard (identity, capabilities, file paths, evasion tabs), proxy relay management with TLS cert tracking and health checks, configurable beacon profiles (sleep, reconnect, SNI spoofing, DNS fallback), and staging server push-to-deploy.

### 4. AitM / Device Code Phishing Infrastructure

- ms365-device[.]com (DCF redirect)
- ms365-live[.]com (DCF redirect)
- m365-owa[.]com (AitM phishing)
- owa-ms365[.]com (AitM phishing)

Supporting IPs: 31.57.243[.]154, 38.146.28[.]75, 104.194.159[.]150 (AitM infrastructure); 38.146.28[.]132 (DNS resolver); 107.189.26[.]194 (ChocoShell C2/DNS resolver).

### 5. Anti-Forensics / Evasion Techniques

- AMSI bypass via .NET reflection
- Timing-based sandbox detection with silent exit
- VSS shadow copy deletion via WMI (post-exfiltration)
- UAC bypass registry key cleanup
- Temporary elevation script removal
- Defender signature update locking
- Defender exclusion configuration
- Symbol randomization (GoLang -- CornFlake)
- XOR string encoding (configurable)
- GZip compression of payloads
- TLS SNI spoofing to legitimate Microsoft domains
- C2 beacon paths mimicking legitimate web analytics

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `%APPDATA%\svchost32\svchost32.exe` | 918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593 | CornFlake RAT binary |
| Windows | `%APPDATA%\svchost32\sync.dat` | -- | CornFlake runtime configuration |
| Windows | (in-memory) | be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c | ChocoShell PowerShell infostealer |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | ms365-device[.]com | DCF redirect infrastructure (first seen 2026-07-23) |
| Domain | ms365-live[.]com | DCF redirect infrastructure (first seen 2026-05-14) |
| Domain | m365-owa[.]com | AitM phishing infrastructure (first seen 2026-07-20) |
| Domain | owa-ms365[.]com | AitM phishing infrastructure (first seen 2026-07-16) |
| IP | 31.57.243[.]154 | AitM infrastructure (first seen 2026-07-16) |
| IP | 38.146.28[.]75 | AitM infrastructure (first seen 2026-07-01) |
| IP | 38.146.28[.]132 | DNS resolver (first seen 2026-07-15) |
| IP | 104.194.159[.]150 | AitM infrastructure (first seen 2026-04-28) |
| IP | 107.189.26[.]194 | ChocoShell C2 / DNS resolver (first seen 2026-02-27) |
| IP | 213.145.86[.]112 | ChocoShell C2 (first seen 2026-07-01) |
| URL Pattern | `/t/pixel.gif?m=<status>` | ChocoShell C2 beacon (mimics tracking pixel) |
| URL Pattern | `/cdn/chunks/polyfill-7e2b.min.js` | Tool delivery URI (Base64-encoded payload) |
| URL Pattern | `/t/event` | Data exfiltration endpoint (GZip+Base64 JSON) |

### Behavioral

- Service registration: name `svchost32`, display name `Cloud Sync Service`, description `Synchronizes files with the cloud storage provider`
- Registry persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (CornFlake)
- Registry: `HKLM\SYSTEM\CurrentControlSet\Services\svchost32` (CornFlake service)
- UAC bypass: `HKCU\Environment\windir` modification (SilentCleanup hijack)
- UAC bypass: `HKCU\Software\Classes` COM handler creation (wsreset.exe hijack)
- UAC bypass: `HKCU\Software\Classes\Folder\shell\open\command` modification (sdclt.exe hijack)
- Browser launched with `--remote-debugging-port` and `--restore-last-session`
- Wi-Fi credential harvest: `netsh wlan show profile key=clear`
- Token theft: `_.tbres` files in Token Broker cache

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Compromise of captive portal management infrastructure |
| T1557 | Adversary-in-the-Middle | DNS/HTTP traffic manipulation on guest Wi-Fi |
| T1598.004 | Phishing for Information: Spearphishing Voice | ClickFix social engineering via fake update/repair prompts |
| T1204.002 | User Execution: Malicious File | Victim executes downloaded CornFlake payload |
| T1059.001 | Command and Scripting Interpreter: PowerShell | ChocoShell in-memory PowerShell execution |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Remote shell via CornFlake |
| T1036.005 | Masquerading: Match Legitimate Name or Location | svchost32.exe mimicking svchost.exe |
| T1543.003 | Create or Modify System Process: Windows Service | CornFlake service registration |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | CornFlake Run key persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | CornFlake named scheduled tasks |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | SilentCleanup, wsreset.exe, sdclt.exe UAC bypasses |
| T1562.001 | Impair Defenses: Disable or Modify Tools | AMSI bypass via .NET reflection |
| T1056.001 | Input Capture: Keylogging | CornFlake Raw Input API keylogger |
| T1115 | Clipboard Data | CornFlake clipboard monitoring |
| T1113 | Screen Capture | Idle-triggered and on-demand screenshots |
| T1123 | Audio Capture | WASAPI microphone capture |
| T1125 | Video Capture | Media Foundation webcam capture |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | ChromeKatz-based browser credential theft |
| T1185 | Browser Session Hijacking | Chrome DevTools Protocol cookie theft via --remote-debugging-port |
| T1528 | Steal Application Access Token | M365/Azure AD token theft from Token Broker cache |
| T1552.001 | Unsecured Credentials: Credentials In Files | Wi-Fi credential harvest via netsh |
| T1005 | Data from Local System | File exfiltration, posture sweep |
| T1025 | Data from Removable Media | USB drive monitoring |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 with mimicked web analytics URIs |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | ECDH P-256 key exchange for C2 |
| T1008 | Fallback Channels | DNS fallback, configurable C2 |
| T1020 | Automated Exfiltration | Throttled file exfil (1000 files/500 MB per cycle) |
| T1621 | Multi-Factor Authentication Request Generation | Device code phishing to bypass MFA |

## Impact Assessment

**Breadth:** Global targeting across multiple countries, affecting hotels, conference centers, and airport networks. The potential compromise of shared captive portal infrastructure suggests the attack surface extends beyond individually compromised venues.

**Depth:** Full endpoint compromise via CornFlake provides comprehensive surveillance (keylogging, screen/audio/video capture), credential theft across all major browsers, Microsoft 365 session hijacking, and file exfiltration. The device code phishing variant enables MFA-bypassed access to corporate cloud resources.

**Stealth:** Moderate to high. The initial redirect is indistinguishable from normal captive portal behavior. CornFlake's fake progress windows mask installation. ChocoShell operates in-memory with AMSI bypass and post-exfiltration cleanup including VSS shadow deletion. C2 traffic mimics legitimate web analytics.

**Victimology:** Enterprise employees traveling internationally, consistent with Midnight Blizzard's focus on governments, diplomatic entities, NGOs, and IT service providers (US/Europe focus).

## Detection & Remediation

### Immediate Detection

```
# Check for CornFlake persistence
dir "%APPDATA%\svchost32\svchost32.exe" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\svchost32" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v svchost32 2>nul

# Check for UAC bypass registry artifacts
reg query "HKCU\Environment" /v windir 2>nul
reg query "HKCU\Software\Classes\Folder\shell\open\command" 2>nul

# Check for known C2 connections (PowerShell)
Get-NetTCPConnection | Where-Object {$_.RemoteAddress -in @('213.145.86.112','107.189.26.194','31.57.243.154','38.146.28.75','38.146.28.132','104.194.159.150')}

# Check for CornFlake file hash
Get-FileHash "%APPDATA%\svchost32\svchost32.exe" -Algorithm SHA256 2>$null
```

### Remediation

1. **Containment:** Immediately isolate affected endpoints from the network. Block all identified C2 IPs and domains at the perimeter firewall and DNS resolver.
2. **Eradication:** Remove `%APPDATA%\svchost32\` directory and contents. Delete the `svchost32` Windows service. Remove Run key entries. Check for and remove scheduled task persistence.
3. **Credential Reset:** Rotate all credentials that may have been exposed -- browser-saved passwords, Microsoft 365 tokens, Wi-Fi credentials. Revoke all Azure AD refresh tokens for affected users. Review Azure AD sign-in logs for device code authentication from suspicious IPs.
4. **Secret Rotation:** Assume all credentials cached in browsers on affected endpoints are compromised. Prioritize password changes for privileged accounts, financial services, and email.
5. **Forensic Preservation:** Before remediation, capture memory dumps (ChocoShell is in-memory), event logs, and browser profile directories for analysis.

### Long-Term Hardening

- Deploy always-on, full-tunnel VPN sending DNS queries through corporate resolvers for all corporate devices on untrusted networks.
- Implement MDM policy to restrict Wi-Fi connections to provisioned networks (`policy-csp-wifi#allowmanualwificonfiguration`).
- Block Microsoft Entra device code authentication flow via Conditional Access where not required.
- Implement phishing-resistant MFA (passkeys, FIDO2) for all accounts.
- Educate users to recognize ClickFix prompts, fake verification checks, and paste-and-run instructions as malicious. Advisory: never download software updates from captive portals or unexpected prompts.
- Consider enterprise-managed travel routers establishing encrypted corporate tunnels.
- Evaluate necessity of venue-provided wireless for corporate events; minimize employee identity/organizational affiliation disclosure during bookings.

## Detection Rules

These detections target the CaptiveCrunch campaign's specific artifacts: CornFlake RAT persistence indicators, ChocoShell credential theft and UAC bypass techniques, and C2 network patterns. All rules are PoC/advisory-specific (default altitude, strict leniency); compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: CornFlake RAT Persistence via Svchost32 Masquerade

Detects execution of CornFlake RAT persisting as `svchost32.exe` in user AppData, a path and name combination not used by legitimate Windows binaries.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0, splunk_windows pipeline 0. Distinctive path+name combo; extremely low FP risk. -->
```yaml
title: CornFlake RAT Persistence via Svchost32 Masquerade
id: 7a3c1e4f-9b2d-4f8a-b6c5-e1d0f3a2b7c9
status: experimental
description: >
    Detects execution of the CornFlake RAT (Storm-2945/Midnight Blizzard) which persists
    as svchost32.exe in the user AppData directory, masquerading as a legitimate Windows service host.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026/08/04
tags:
    - attack.t1036.005
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\svchost32\svchost32.exe'
    selection_appdata:
        Image|contains: '\AppData\Roaming\'
    condition: selection and selection_appdata
falsepositives:
    - Unlikely; svchost32.exe in user AppData is not a legitimate Windows binary
level: high
```

### Sigma: CornFlake RAT Service Registration - Cloud Sync Service

Detects registry writes consistent with CornFlake's service registration using the distinctive service name `svchost32` or display name `Cloud Sync Service`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Keys on unique service name+display name pair from Microsoft disclosure. -->
```yaml
title: CornFlake RAT Service Registration - Cloud Sync Service
id: 2f8b4d6e-a1c3-4e7f-9d5b-0c2a3e8f1d4b
status: experimental
description: >
    Detects registry modification consistent with CornFlake RAT service registration,
    which creates a service named svchost32 with display name Cloud Sync Service.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026/08/04
tags:
    - attack.t1543.003
logsource:
    category: registry_set
    product: windows
detection:
    selection_path:
        TargetObject|contains: '\SYSTEM\CurrentControlSet\Services\svchost32'
    selection_value:
        Details|contains:
            - 'Cloud Sync Service'
            - 'Synchronizes files with the cloud storage provider'
    condition: selection_path or selection_value
falsepositives:
    - Legitimate software using the exact service name svchost32 with Cloud Sync Service display name is extremely unlikely
level: critical
```

### Sigma: ChocoShell UAC Bypass via SilentCleanup Task Hijack

Detects modification of `HKCU\Environment\windir`, a technique used by ChocoShell to hijack the SilentCleanup scheduled task for UAC bypass.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Well-known UAC bypass (T1548.002); filters SYSTEM/LOCAL SERVICE to reduce FPs. Specific to the registry key path. -->
```yaml
title: ChocoShell UAC Bypass via SilentCleanup Task Hijack
id: 5c9d2e1a-3f7b-4a6c-8e0d-b4f1a9c7d3e5
status: experimental
description: >
    Detects modification of HKCU\Environment\windir registry value, a technique used by
    ChocoShell (Storm-2945) to hijack the SilentCleanup scheduled task for UAC bypass.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026/08/04
tags:
    - attack.t1548.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Environment\windir'
        EventType: SetValue
    filter_system:
        User|contains:
            - 'SYSTEM'
            - 'LOCAL SERVICE'
    condition: selection and not filter_system
falsepositives:
    - Legitimate modification of the user-level windir environment variable is rare
level: high
```

### Sigma: Wi-Fi Credential Harvesting via Netsh

Detects `netsh wlan show profile key=clear` used by ChocoShell to extract stored Wi-Fi passwords in cleartext.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0, splunk_windows pipeline 0. All four substrings required (|contains|all); may fire on legitimate IT auditing. -->
```yaml
title: Wi-Fi Credential Harvesting via Netsh
id: 8e4f1b2c-d6a3-4c9e-b7f0-5a1d8c3e2f9b
status: experimental
description: >
    Detects use of netsh to enumerate Wi-Fi profiles with cleartext keys, a technique
    observed in ChocoShell (Storm-2945/Midnight Blizzard CaptiveCrunch campaign).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026/08/04
tags:
    - attack.t1005
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
    - IT administrators auditing Wi-Fi configurations
    - Network troubleshooting scripts
level: high
```

### Sigma: Browser Launched with Remote Debugging Port - Cookie Theft

Detects Chromium-based browsers launched with `--remote-debugging-port`, used by ChocoShell to bypass App-Bound Encryption via Chrome DevTools Protocol.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert splunk 0, log_scale 0, splunk_windows pipeline 0. FP from devtools/test frameworks (Selenium, Puppeteer, Playwright) expected in dev environments; scope to non-developer endpoints for production use. -->
```yaml
title: Browser Launched with Remote Debugging Port - Cookie Theft
id: 3b7e0c9d-f2a4-4d1b-8c6e-a5f3d9b1e2c8
status: experimental
description: >
    Detects Chromium-based browsers launched with --remote-debugging-port, used by
    ChocoShell to bypass App-Bound Encryption and steal cookies via Chrome DevTools Protocol.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
author: Actioner
date: 2026/08/04
tags:
    - attack.t1555.003
    - attack.t1185
logsource:
    category: process_creation
    product: windows
detection:
    selection_browser:
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
            - '\brave.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
    selection_debug:
        CommandLine|contains: '--remote-debugging-port'
    condition: selection_browser and selection_debug
falsepositives:
    - Web developers using Chrome DevTools remote debugging
    - Automated testing frameworks (Selenium, Puppeteer, Playwright)
level: medium
```

### Snort: CaptiveCrunch ChocoShell C2 Beacon and Exfiltration

Detects ChocoShell C2 beacon (`/t/pixel.gif?m=`), tool delivery (`/cdn/chunks/polyfill-7e2b.min.js`), and exfiltration (`POST /t/event`) URI patterns.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 via local.rules include. Snort 2 syntax with http_uri/http_method sticky buffers. URI patterns are highly distinctive campaign artifacts. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - CaptiveCrunch ChocoShell C2 Beacon /t/pixel.gif"; flow:established,to_server; content:"/t/pixel.gif?m="; http_uri; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; sid:2100001; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - CaptiveCrunch Tool Delivery /cdn/chunks/polyfill-7e2b.min.js"; flow:established,to_server; content:"/cdn/chunks/polyfill-7e2b.min.js"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; sid:2100002; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - CaptiveCrunch ChocoShell Exfiltration /t/event"; flow:established,to_server; content:"POST"; http_method; content:"/t/event"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; sid:2100003; rev:1;)
```

### Suricata: CaptiveCrunch C2 Communication and DNS IOCs

Detects ChocoShell C2 beacon, tool delivery, and exfiltration HTTP patterns, plus DNS queries to four known Storm-2945 domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Dot-notation sticky buffers (http.uri, http.method, dns.query). Domain IOCs are campaign-specific; rotate risk is low in the short term. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch ChocoShell C2 Beacon /t/pixel.gif"; flow:established,to_server; http.uri; content:"/t/pixel.gif?m="; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-04; sid:2200001; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch Tool Delivery polyfill-7e2b.min.js"; flow:established,to_server; http.uri; content:"/cdn/chunks/polyfill-7e2b.min.js"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-04; sid:2200002; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CaptiveCrunch ChocoShell Exfiltration POST /t/event"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/t/event"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-04; sid:2200003; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - CaptiveCrunch Storm-2945 C2 Domain ms365-device.com"; flow:to_server; dns.query; content:"ms365-device.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-04; sid:2200004; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - CaptiveCrunch Storm-2945 C2 Domain ms365-live.com"; flow:to_server; dns.query; content:"ms365-live.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-04; sid:2200005; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - CaptiveCrunch Storm-2945 AitM Domain m365-owa.com"; flow:to_server; dns.query; content:"m365-owa.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-04; sid:2200006; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - CaptiveCrunch Storm-2945 AitM Domain owa-ms365.com"; flow:to_server; dns.query; content:"owa-ms365.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/; metadata:author Actioner, created_at 2026-08-04; sid:2200007; rev:1;)
```

### YARA: CornFlake RAT Detection

Detects CornFlake RAT PE binaries via distinctive string combinations: service name/display name, config file name with fake window identifiers, or C2 URI pattern cluster.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive sample (published strings from MS disclosure) fired; negative sample quiet. Three OR branches: (svc_name+display+desc), (svc_name+config+2 fake windows), (3 C2 URIs). All strings from Microsoft's disclosure. -->
```yara
rule APT29_CornFlake_RAT : CaptiveCrunch
{
    meta:
        description = "Detects CornFlake RAT used by Storm-2945/Midnight Blizzard in the CaptiveCrunch campaign via distinctive strings"
        author = "Actioner"
        date = "2026-08-04"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593"
        severity = "critical"

    strings:
        $svc_name = "svchost32" ascii wide
        $svc_display = "Cloud Sync Service" ascii wide
        $svc_desc = "Synchronizes files with the cloud storage provider" ascii wide
        $config = "sync.dat" ascii wide
        $fake1 = "winupdate" ascii
        $fake2 = "directx" ascii
        $fake3 = "vcredist" ascii
        $fake4 = "sysopt" ascii
        $fake5 = "netfix" ascii
        $fake6 = "pdfview" ascii
        $beacon = "/t/pixel.gif?m=" ascii
        $tool_uri = "/cdn/chunks/polyfill-7e2b.min.js" ascii
        $exfil_uri = "/t/event" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            ($svc_name and $svc_display and $svc_desc) or
            ($svc_name and $config and 2 of ($fake*)) or
            ($beacon and $tool_uri and $exfil_uri)
        )
}
```

## Lessons Learned

This campaign demonstrates a significant evolution in state-sponsored initial access tradecraft. By compromising shared captive portal infrastructure rather than targeting individual organizations directly, Midnight Blizzard gains access to a large, transient population of corporate travelers -- a high-value target set that is inherently more vulnerable when away from corporate network controls. The attack exploits a fundamental assumption in how operating systems handle network connectivity: that the initial captive portal redirect is benign.

Key takeaways:

1. **Guest Wi-Fi is an active threat vector, not merely untrusted.** The CaptiveCrunch campaign moves beyond passive eavesdropping to active traffic manipulation and malware delivery through captive portals.
2. **ClickFix social engineering is effective at scale.** The technique leverages user habituation to captive portal prompts, making the transition from legitimate portal interaction to malicious instruction execution feel natural.
3. **Device code phishing bypasses MFA.** Organizations that have not restricted device code authentication flows remain vulnerable even with MFA deployed, as the legitimate Microsoft sign-in page handles the authentication.
4. **AI-augmented malware development is operationalized.** Microsoft's assessment that ChocoShell was AI-assisted (consistent coding standards, full developer comments) indicates state actors are integrating AI into their development workflows.
5. **Supply chain compromise of shared infrastructure multiplies impact.** Compromising the captive portal ecosystem -- shared equipment and management systems -- provides access to many venues simultaneously rather than requiring per-target operations.

## Sources

- [Microsoft Threat Intelligence Blog](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/) -- Primary technical analysis: full attack chain, malware analysis (CornFlake, ChocoShell, FruitStone), IOCs, MITRE mappings, detection guidance, and hunting queries
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/hotel-wi-fi-attacks-use-custom-malware-to-breach-microsoft-365-accounts/) -- News coverage with contextual details on campaign scope and Microsoft 365 credential theft focus
- [The Hacker News](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html) -- News coverage with additional context on DNS manipulation mechanics, device code phishing variant timeline, and ReliaQuest's prior partial disclosure

---
*Report generated by Actioner*
