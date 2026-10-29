# Technical Analysis Report: NIK C2 AI-Enabled Framework (2026-10-29)

Prepared by: Actioner (DRAFT)
Classification: TLP:CLEAR
Date: 2026-10-29
Version: 0.1-draft

## Executive Summary

NIK C2 is a newly discovered Go-based Windows remote access framework with integrated OpenAI API capabilities, documented by Cisco Talos on October 29, 2026. The framework provides operators with a comprehensive post-exploitation toolkit including credential theft, screen-lock ransomware (without file encryption), browser data exfiltration, cryptocurrency wallet targeting, SOCKS5 proxying, reverse shells, HVNC, and AI-generated content via the OpenAI API. All C2 communications traverse WebSocket over TLS (port 443) encrypted with AES-256-GCM, making passive network detection challenging. The framework is actively developed and hosted at 87.120.196[.]120 behind the domain total-sitevv[.]lol, with a distinctive TLS certificate bearing CN=nik-panel.

The discovery is significant because NIK C2 represents an emerging trend of commodity RAT frameworks integrating large-language-model APIs directly into their agent binaries, enabling operators to generate phishing content, adapt social engineering, and automate reconnaissance analysis on-host. Defenders should prioritize detection of the specific IOCs, behavioral patterns (fodhelper UAC bypass, csrss.exe masquerading in TEMP), and network signatures documented below.

## Background: NIK C2 Framework

NIK C2 is a panel-and-agent architecture: the operator runs a web panel (nik-panel) that manages deployed agents on victim Windows machines. The agent is compiled in Go, shipped as a PE binary, and renames itself to csrss.exe in the user's TEMP directory to blend with the legitimate Windows critical process. The panel builds agents on-the-fly under `/opt/nik_panel/data/build_<hash>/main.go`, embedding per-build configuration including C2 endpoints, AES keys, and the OpenAI API key.

The framework targets Windows exclusively. Its capabilities span the full kill chain from persistence through exfiltration, with a particular emphasis on credential and cryptocurrency theft. The ransomware module is screen-lock only (no file encryption), backing up the MBR and displaying a lock screen via mshta.exe, suggesting the operator's primary goal is extortion or disruption rather than data destruction.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-10-29 | Cisco Talos publishes full technical analysis of NIK C2 |
| Unknown | Initial discovery of NIK C2 infrastructure and samples |
| Unknown | Agent builds observed in the wild with embedded OpenAI API integration |

> Note: Cisco Talos did not publish a specific timeline of victim activity. The dates above reflect disclosure only.

## Root Cause: Initial Access Vector

The initial access vector for NIK C2 deployments has not been publicly documented by Cisco Talos. As a RAT framework, NIK C2 is a post-exploitation tool that requires a separate delivery mechanism. Likely delivery vectors include phishing attachments, drive-by downloads, or trojanized software. The framework's AI integration (OpenAI API) may itself be used to generate convincing phishing lures or social engineering pretexts for delivery.

## Technical Analysis of the Malicious Payload

### 1. Agent Deployment and Masquerading

The NIK C2 agent is a Go-compiled PE binary built on the panel server under `/opt/nik_panel/data/build_<hash>/main.go`. Upon execution, the agent:

- Renames itself to `csrss.exe` in `%TEMP%` to masquerade as the legitimate Windows Critical Service Process (T1036)
- Copies itself to `%appdata%\Roaming\Microsoft\Network` for persistence
- Establishes persistence via the `HKCU\...\Run` registry value named `SystemLock`
- Logs `[NIK] Starting` on initialization
- May also appear as `svchost.exe` or `simvol.exe`

### 2. Privilege Escalation and Defense Evasion

**UAC Bypass (fodhelper.exe):** The agent writes to `HKCU\Software\Classes\ms-settings\Shell\Open\command` and triggers `fodhelper.exe` to execute the payload with elevated privileges without a UAC prompt (T1548.002).

**AMSI Patch:** The agent patches the Anti-Malware Scan Interface in memory to disable PowerShell script-block scanning (T1562.001).

**Process Hollowing:** The agent uses process hollowing to inject code into legitimate processes (T1055.012).

**Anti-Analysis:**
- `IsDebuggerPresent` and `CheckRemoteDebuggerPresent` API calls to detect debuggers (T1622)
- Console window hiding (T1564.003)
- Optional BSOD-on-kill flag that triggers a Blue Screen of Death if the agent process is terminated

### 3. C2 Infrastructure

| Component | Value |
|-----------|-------|
| IP | 87.120.196[.]120 |
| Domain | total-sitevv[.]lol |
| Port | 443 (TLS) |
| Protocol | WebSocket over TLS |
| TLS Cert CN | nik-panel |
| Cert Serial | 7d16381a9de823943b5a0987dbd0f26edf22052b |
| JARM | 28d28d28d00000000042d42d0000001f361a1bf80ed39a1e352adeb016a07b |
| Encryption | AES-256-GCM |
| AES Seed | d791dd0ff3228ed29a8d7333d4567be829159c5632ea347780992006f91c5295 |
| AES Key | 4887AFC0A574E9419A9695EF083460F58E4EF9A1C40793523CE112251273BDF9 |

**C2 Endpoints:**
- `/api/c2/update` -- agent check-in and command polling
- `/api/c2/result` -- command result upload
- `/api/c2/screen` -- screenshot upload
- `/api/c2/file_chunk` -- file exfiltration (chunked)
- `/api/c2/rproxy_up` -- reverse proxy upstream
- `/api/c2/ws` -- WebSocket connection endpoint

### 4. Capabilities

**Credential and Data Theft:**
- Browser credential theft from Chromium/Firefox-based browsers (T1555.003), staged to `%TEMP%\browserdata.zip`
- Discord token theft (T1528)
- Cryptocurrency wallet seed-phrase hunting via regex: `(?i)(seed|phrase|mnemonic|recovery|backup|wallet).*(\.txt|\.md|\.csv|\.dat)` and `(?i)(private|privkey|secret).*(\.txt|\.md|\.key|\.pem)` (T1005)
- Wi-Fi password harvesting: `netsh wlan show profiles` followed by `netsh wlan show profile name="..." key=clear` (T1082)
- Keylogging (T1056.001)

**Reconnaissance:**
- `chcp 65001 >nul 2>&1 & systeminfo`
- `chcp 65001 >nul 2>&1 & wmic os get lastbootuptime /value`
- `bcdedit /enum` (hidden console)
- Security software enumeration (T1518.001)
- Process listing (T1057)

**Remote Access:**
- SOCKS5 proxy
- Reverse TCP tunnel
- RDP enablement
- Hidden VNC (HVNC)
- Screen, camera, and microphone capture (T1113)

**Ransomware (Screen Lock):**
- Backs up MBR to `%TEMP%\mbr_backup.bin` (T1006)
- PowerShell raw disk read of `\\.\PhysicalDrive0`
- Deploys lock screen via `%TEMP%\lock_screen.html` and `%TEMP%\lock_start.bat`
- Displays lock screen using `mshta.exe` (T1218.005)
- Writes `%TEMP%\bootkit.bin` (purpose unclear; no file encryption observed)

**AI Integration:**
- Outbound connections to `api.openai.com` from the agent process
- Operator can generate AI content (phishing text, social engineering scripts) through the panel, executed via the victim's outbound OpenAI API calls

### 5. Anti-Forensics / Evasion Techniques

- **Process masquerading:** Binary renamed to `csrss.exe` (a protected Windows process name), also seen as `svchost.exe` and `simvol.exe`
- **Debugger detection:** `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`
- **AMSI bypass:** In-memory patching to blind endpoint security
- **Console hiding:** Hides command-line windows during execution (T1564.003)
- **BSOD-on-kill:** Optional flag triggers system crash if the agent is terminated, complicating live response
- **Encrypted C2:** AES-256-GCM over WebSocket/TLS makes traffic inspection require TLS interception

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `total-sitevv[.]lol`)
> - IP addresses: `[.]` replacing dots (e.g., `87.120.196[.]120`)
> - URLs: `hxxps://` prefix

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | %TEMP%\csrss.exe | See ClamAV sig below | NIK C2 agent (renamed) |
| Windows | %appdata%\Roaming\Microsoft\Network\ | -- | Persistence copy of agent |
| Windows | %TEMP%\mbr_backup.bin | -- | MBR backup (ransomware module) |
| Windows | %TEMP%\lock_screen.html | -- | Lock screen HTML payload |
| Windows | %TEMP%\lock_start.bat | -- | Lock screen launcher |
| Windows | %TEMP%\bootkit.bin | -- | Bootkit component |
| Windows | %TEMP%\browserdata.zip | -- | Stolen browser data archive |

**ClamAV Signature:** `Win.Trojan.GoDiscorder-10060526-0`

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 87.120.196[.]120 | C2 server |
| Domain | total-sitevv[.]lol | C2 domain |
| TLS CN | nik-panel | C2 TLS certificate common name |
| Cert Serial | 7d16381a9de823943b5a0987dbd0f26edf22052b | C2 certificate serial |
| JARM | 28d28d28d00000000042d42d0000001f361a1bf80ed39a1e352adeb016a07b | C2 server TLS fingerprint |
| URL Pattern | /api/c2/update, /api/c2/result, /api/c2/screen, /api/c2/file_chunk, /api/c2/rproxy_up, /api/c2/ws | C2 endpoints |
| Domain | api.openai.com | AI API calls from victim host |

### Behavioral

- Process named `csrss.exe` running from `%TEMP%` (not `%SystemRoot%\System32\`)
- Registry value `SystemLock` under `HKCU\...\Run`
- Registry modification of `HKCU\Software\Classes\ms-settings\Shell\Open\command` (fodhelper UAC bypass)
- `mshta.exe` executing HTML from `%TEMP%`
- `netsh wlan show profile ... key=clear` command sequences
- `chcp 65001 >nul 2>&1 &` prefixed reconnaissance commands
- Outbound DNS to `api.openai.com` from non-AI-tool processes

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1071.001 | Application Layer Protocol: Web Protocols | WebSocket over TLS for all C2 traffic; OpenAI API calls |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-GCM encryption of C2 payloads |
| T1008 | Fallback Channels | Multiple C2 endpoints under /api/c2/ |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell raw disk read, AMSI patch |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | cmd.exe for recon (systeminfo, netsh) |
| T1047 | Windows Management Instrumentation | wmic os get lastbootuptime |
| T1218.005 | System Binary Proxy Execution: Mshta | Lock screen display via mshta.exe |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | SystemLock Run key persistence |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | fodhelper.exe UAC bypass |
| T1036 | Masquerading | Binary renamed to csrss.exe |
| T1055.012 | Process Injection: Process Hollowing | Code injection into legitimate processes |
| T1562.001 | Impair Defenses: Disable or Modify Tools | AMSI in-memory patching |
| T1564.003 | Hide Artifacts: Hidden Window | Console window hiding |
| T1622 | Debugger Evasion | IsDebuggerPresent, CheckRemoteDebuggerPresent |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Browser credential theft |
| T1539 | Steal Web Session Cookie | Browser cookie exfiltration |
| T1528 | Steal Application Access Token | Discord token theft |
| T1056.001 | Input Capture: Keylogging | Keylogger module |
| T1082 | System Information Discovery | systeminfo, wmic, Wi-Fi enumeration |
| T1057 | Process Discovery | Process listing |
| T1518.001 | Software Discovery: Security Software Discovery | Security product enumeration |
| T1005 | Data from Local System | Seed phrase file hunting, credential harvesting |
| T1113 | Screen Capture | Screenshot, camera, microphone capture |
| T1041 | Exfiltration Over C2 Channel | Data exfiltrated via /api/c2/file_chunk |
| T1006 | Direct Volume Access | MBR backup via raw disk read |

## Impact Assessment

**Breadth:** NIK C2 is a commodity framework available to any operator with panel access. The single known C2 domain/IP suggests a limited operator base currently, but the panel-based architecture allows rapid scaling.

**Depth:** The framework provides full system compromise: persistence, privilege escalation, credential theft, lateral movement (SOCKS5/RDP/HVNC), data exfiltration, and disruptive capability (screen-lock ransomware, BSOD-on-kill).

**Stealth:** The combination of process masquerading (csrss.exe), AMSI bypass, AES-256-GCM encrypted WebSocket traffic on port 443, and debugger evasion makes this moderately difficult to detect without endpoint telemetry (Sysmon or EDR).

**AI Factor:** The integration of OpenAI API calls is a distinguishing feature. While the AI integration does not directly enhance the malware's technical capabilities, it provides operators with on-demand content generation for social engineering, potentially increasing the effectiveness of follow-on attacks.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for csrss.exe running from TEMP
Get-Process | Where-Object { $_.Path -like "*\Temp\csrss.exe" }

# Check for SystemLock persistence
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object SystemLock

# Check for fodhelper UAC bypass registry key
Test-Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command"

# Check for staging files
@("$env:TEMP\mbr_backup.bin", "$env:TEMP\lock_screen.html", "$env:TEMP\lock_start.bat", "$env:TEMP\bootkit.bin", "$env:TEMP\browserdata.zip") | ForEach-Object { if (Test-Path $_) { "FOUND: $_" } }

# Check for NIK agent persistence directory
Test-Path "$env:APPDATA\Microsoft\Network\csrss.exe"
```

### Remediation

1. **Containment:** Isolate affected hosts from the network immediately; block 87.120.196[.]120 and total-sitevv[.]lol at the perimeter firewall/proxy
2. **Kill Agent:** Terminate csrss.exe process running from TEMP (caution: verify path -- do NOT terminate the legitimate `C:\Windows\System32\csrss.exe`)
3. **Remove Persistence:**
   - Delete `HKCU\...\Run\SystemLock` registry value
   - Delete `HKCU\Software\Classes\ms-settings\Shell\Open\command` if present
   - Remove agent binary from `%appdata%\Roaming\Microsoft\Network\`
4. **Credential Rotation:** Rotate all browser-saved passwords, Discord tokens, cryptocurrency wallet keys, and Wi-Fi passwords on affected hosts
5. **MBR Verification:** If `mbr_backup.bin` exists, verify MBR integrity with `bcdedit /enum` and consider restoring from backup
6. **Scan for Variants:** Use the YARA rule below and ClamAV signature `Win.Trojan.GoDiscorder-10060526-0` to scan enterprise-wide

### Long-Term Hardening

- Deploy Sysmon with configuration monitoring process creation, registry events, network connections, and DNS queries
- Block or alert on `mshta.exe` execution from user-writable directories via application control policies
- Monitor for processes resolving `api.openai.com` from hosts without sanctioned AI tooling
- Enforce UAC at "Always Notify" level and monitor for fodhelper.exe abuse patterns
- Consider blocking or alerting on outbound WebSocket connections to newly registered or low-reputation domains

## Detection Rules

The rules below target NIK C2-specific artifacts at the **specific** altitude (PoC/advisory-level indicators) with **strict** leniency (tight matching to minimize false positives). Seven Sigma rules cover endpoint behaviors, one YARA rule covers binary artifacts, four Suricata rules cover network indicators, and three Snort rules provide equivalent network coverage where Suricata is unavailable. The main caveat: the Sigma `sigma check` ATT&CK tag validator could not run due to a network restriction in the build environment; tags were manually verified against the MITRE ATT&CK framework.

### Sigma Rules

#### 1. NIK C2 - Suspicious csrss.exe in TEMP Directory

Detects a process named csrss.exe executing from a user TEMP directory, a hallmark of the NIK C2 agent's masquerading behavior.

**Status:** ✅ compiles (sigma check + convert splunk/log_scale) | **Confidence:** high

<!-- Audit: sigma check passed (0 errors, 0 issues, attacktag validator excluded due to network 403 on MITRE ATT&CK data fetch). sigma convert --without-pipeline -t splunk produced valid SPL. sigma convert --without-pipeline -t log_scale produced valid LogScale query. Field names (Image) match Sysmon process_creation schema. Values use real paths, not defanged. Tags attack.t1036 and attack.t1059.001 are valid technique IDs. -->

```yaml
title: NIK C2 - Suspicious csrss.exe in TEMP Directory
id: 5a5d757a-4188-482a-9de9-641d8954fa2d
status: experimental
description: >
    Detects a process named csrss.exe executing from a user TEMP directory,
    a technique used by the NIK C2 framework which renames its agent binary
    to csrss.exe and stages it in %TEMP%.
references:
    - https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1036
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith: '\csrss.exe'
    selection_temp:
        Image|contains:
            - '\AppData\Local\Temp\'
            - '\Windows\Temp\'
    filter_legit:
        Image|startswith: 'C:\Windows\System32\'
    condition: selection_image and selection_temp and not filter_legit
falsepositives:
    - Unlikely in production; csrss.exe should only run from System32
level: high
```

#### 2. NIK C2 - Fodhelper UAC Bypass via Registry Modification

Detects registry modification of the ms-settings shell open command key, the specific registry path abused by NIK C2 for fodhelper.exe UAC bypass.

**Status:** ✅ compiles (sigma check + convert splunk/log_scale) | **Confidence:** high

<!-- Audit: sigma check passed (0 errors, 0 issues). sigma convert --without-pipeline -t splunk and log_scale both successful. Logsource registry_set/windows maps to Sysmon EID 13. TargetObject field matches Sysmon schema. Tag attack.t1548.002 is correct sub-technique. -->

```yaml
title: NIK C2 - Fodhelper UAC Bypass via Registry Modification
id: e519f100-7e58-4737-9477-98e18b4547e6
status: experimental
description: >
    Detects registry modification of the ms-settings shell open command key
    used by the NIK C2 framework to perform UAC bypass via fodhelper.exe.
references:
    - https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1548.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Classes\ms-settings\Shell\Open\command'
    condition: selection
falsepositives:
    - Legitimate modification of ms-settings handler, which is rare
level: high
```

#### 3. NIK C2 - SystemLock Registry Run Key Persistence

Detects creation of a Run registry value named "SystemLock", the specific persistence mechanism used by the NIK C2 framework.

**Status:** ✅ compiles (sigma check + convert splunk/log_scale) | **Confidence:** high

<!-- Audit: sigma check passed (0 errors, 0 issues). sigma convert successful for both backends. Tag attack.t1547.001 is correct. TargetObject endswith filter is specific to "SystemLock" value name, minimizing FPs. -->

```yaml
title: NIK C2 - SystemLock Registry Run Key Persistence
id: b3e6dbb5-d74c-4262-8165-abc15bb42c13
status: experimental
description: >
    Detects creation of a Run registry value named SystemLock, used by the
    NIK C2 framework for persistence via the HKCU Run key.
references:
    - https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\CurrentVersion\Run\SystemLock'
    condition: selection
falsepositives:
    - Custom enterprise software using "SystemLock" as a run key name
level: high
```

#### 4. NIK C2 - mshta.exe Executing HTML from TEMP Directory

Detects mshta.exe executing an HTML/HTA file from a TEMP directory, matching the NIK C2 ransomware lock-screen delivery via lock_screen.html.

**Status:** ✅ compiles (sigma check + convert splunk/log_scale) | **Confidence:** high

<!-- Audit: sigma check passed (0 errors, 0 issues). sigma convert successful. Tag attack.t1218.005 correct for mshta proxy execution. CommandLine field matches Sysmon process_creation. Requires both TEMP path and .html/.hta extension to reduce FPs. -->

```yaml
title: NIK C2 - mshta.exe Executing HTML from TEMP Directory
id: 0a72b67d-582d-461a-ae7c-6c67f86c4eb3
status: experimental
description: >
    Detects mshta.exe executing an HTML file from TEMP, matching the NIK C2
    ransomware lock-screen delivery via lock_screen.html and lock_start.bat.
references:
    - https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith: '\mshta.exe'
    selection_arg:
        CommandLine|contains:
            - '\AppData\Local\Temp\'
    selection_html:
        CommandLine|endswith:
            - '.html'
            - '.hta'
    condition: selection_binary and selection_arg and selection_html
falsepositives:
    - Legitimate HTA applications deployed via TEMP (uncommon)
level: high
```

#### 5. NIK C2 - browserdata.zip Staging in TEMP

Detects creation of `browserdata.zip` in the TEMP directory, a staging artifact of the NIK C2 browser credential theft module.

**Status:** ✅ compiles (sigma check + convert splunk/log_scale) | **Confidence:** high

<!-- Audit: sigma check passed (0 errors, 0 issues). sigma convert successful. Logsource file_event/windows maps to Sysmon EID 11. TargetFilename field correct. Tags attack.t1555.003 and attack.t1005 match credential theft and local data collection. -->

```yaml
title: NIK C2 - browserdata.zip Staging in TEMP
id: 21523d66-212a-4224-9d8e-9fc98c090fb6
status: experimental
description: >
    Detects creation of browserdata.zip in the TEMP directory, an artifact
    of the NIK C2 credential-theft module that collects browser data for
    exfiltration.
references:
    - https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1555.003
    - attack.t1005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\browserdata.zip'
        TargetFilename|contains: '\Temp\'
    condition: selection
falsepositives:
    - Browser backup utilities that use this exact filename
level: high
```

#### 6. NIK C2 - Outbound Connection to OpenAI API from Non-AI Application

Detects DNS queries to api.openai.com from processes not typically associated with AI tooling, which may indicate NIK C2's AI module running on a compromised host.

**Status:** ✅ compiles (sigma check + convert splunk/log_scale) | **Confidence:** medium

<!-- Audit: sigma check passed (0 errors, 0 issues). sigma convert successful. Logsource dns_query/windows maps to Sysmon EID 22. Filter list covers common legitimate AI callers. Medium confidence because legitimate applications not in the filter list may trigger this. Tag attack.t1071.001 correct for web protocol communication. -->

```yaml
title: NIK C2 - Outbound Connection to OpenAI API from Non-AI Application
id: c2aac28f-d9fa-43f1-8aa1-0dc02d1f70e3
status: experimental
description: >
    Detects network connections to api.openai.com from processes not
    typically associated with AI tooling, which may indicate NIK C2
    AI-assisted command generation running on a compromised host.
references:
    - https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1071.001
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName: 'api.openai.com'
    filter_legit:
        Image|endswith:
            - '\python.exe'
            - '\python3.exe'
            - '\node.exe'
            - '\Code.exe'
            - '\cursor.exe'
            - '\copilot-agent.exe'
    condition: selection and not filter_legit
falsepositives:
    - Custom enterprise applications calling OpenAI API directly
    - Development tools or IDE plugins using OpenAI
level: medium
```

Environments with widespread AI tool usage will need to expand the filter list.

#### 7. NIK C2 - Wi-Fi Password Harvesting via netsh

Detects the `netsh wlan show profile ... key=clear` command sequence used by NIK C2 to extract saved Wi-Fi passwords.

**Status:** ✅ compiles (sigma check + convert splunk/log_scale) | **Confidence:** high

<!-- Audit: sigma check passed (0 errors, 0 issues). sigma convert successful. CommandLine contains|all ensures all four tokens are present in one command line. Tag attack.t1082 for system info discovery, attack.t1005 for local data. Logsource process_creation/windows correct. -->

```yaml
title: NIK C2 - Wi-Fi Password Harvesting via netsh
id: 24f31260-ff01-40aa-8d57-aba51a38ee58
status: experimental
description: >
    Detects the netsh wlan command sequence used by the NIK C2 framework
    to enumerate Wi-Fi profiles and extract saved passwords in cleartext.
references:
    - https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1082
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'netsh'
            - 'wlan'
            - 'show'
            - 'key=clear'
    condition: selection
falsepositives:
    - IT administrators auditing Wi-Fi configurations
level: high
```

### Suricata Rules

#### 8. NIK C2 - DNS Query to C2 Domain

Detects DNS queries for the NIK C2 domain total-sitevv[.]lol.

**Status:** ✅ compiles (suricata -T exit 0) | **Confidence:** high

<!-- Audit: Validated with suricata -T -S suricata_nik_c2_domain.rules -l /tmp/actioner. Suricata 7.0.3 RELEASE. Protocol dns with dns.query sticky buffer. Domain value is real (not defanged). SID 2100101 in custom range. -->

```
alert dns $HOME_NET any -> any any (msg:"Actioner - NIK C2 DNS Query to total-sitevv.lol"; flow:to_server; dns.query; content:"total-sitevv.lol"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/; metadata:author Actioner, created_at 2026-10-29; sid:2100101; rev:1;)
```

#### 9. NIK C2 - WebSocket C2 Endpoint Access

Detects HTTP requests to the /api/c2/ws WebSocket endpoint used by NIK C2 for command-and-control.

**Status:** ✅ compiles (suricata -T exit 0) | **Confidence:** high

<!-- Audit: Validated with suricata -T. Protocol http with http.uri dot-notation buffer. Content matches specific URI path. SID 2100102. -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - NIK C2 WebSocket Endpoint /api/c2/ws"; flow:established,to_server; http.uri; content:"/api/c2/ws"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/; metadata:author Actioner, created_at 2026-10-29; sid:2100102; rev:1;)
```

#### 10. NIK C2 - TLS Certificate Subject CN=nik-panel

Detects TLS connections where the server certificate subject contains CN=nik-panel, the distinctive certificate used by the NIK C2 panel.

**Status:** ✅ compiles (suricata -T exit 0) | **Confidence:** high

<!-- Audit: Validated with suricata -T. Protocol tls with tls.cert_subject sticky buffer. Content "CN=nik-panel" matches the certificate subject field as emitted by Suricata's TLS parser. SID 2100103. -->

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - NIK C2 TLS Certificate CN nik-panel"; flow:established,to_server; tls.cert_subject; content:"CN=nik-panel"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/; metadata:author Actioner, created_at 2026-10-29; sid:2100103; rev:1;)
```

#### 11. NIK C2 - TLS SNI to C2 Domain

Detects TLS connections with SNI set to total-sitevv[.]lol.

**Status:** ✅ compiles (suricata -T exit 0) | **Confidence:** high

<!-- Audit: Validated with suricata -T. Protocol tls with tls.sni sticky buffer. Domain not defanged. SID 2100104. -->

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - NIK C2 TLS SNI to total-sitevv.lol"; flow:established,to_server; tls.sni; content:"total-sitevv.lol"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/; metadata:author Actioner, created_at 2026-10-29; sid:2100104; rev:1;)
```

### Snort 3 Rules

#### 12. NIK C2 - DNS Query to C2 Domain (Snort)

Detects DNS queries for total-sitevv[.]lol using DNS wire-format label matching.

**Status:** ⚠️ uncompiled (Snort not installed; structural check only) | **Confidence:** high

<!-- Audit: Snort 3 not available in build environment. Structural review: protocol udp, port 53, flow to_server, content uses DNS wire format (|0e| = 14-byte label "total-sitevv", |03| = 3-byte label "lol", |00| = root). SID 2100201. All options semicolon-terminated. No Suricata-only buffers used. -->

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - NIK C2 DNS Query to total-sitevv.lol"; flow:to_server; content:"|0e|total-sitevv|03|lol|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/; metadata:author Actioner, created 2026-10-29; sid:2100201; rev:1;)
```

#### 13. NIK C2 - WebSocket C2 Endpoint Access (Snort)

Detects HTTP requests to the /api/c2/ URI path prefix used by NIK C2 for all command-and-control endpoints.

**Status:** ⚠️ uncompiled (Snort not installed; structural check only) | **Confidence:** high

<!-- Audit: Structural review: protocol http (Snort service keyword), flow established/to_server, http_uri sticky buffer (underscore notation for Snort 3), content "/api/c2/". SID 2100202. No Suricata-only keywords. -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - NIK C2 WebSocket C2 Endpoint Access"; flow:established, to_server; http_uri; content:"/api/c2/", fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/; metadata:author Actioner, created 2026-10-29; sid:2100202; rev:1;)
```

#### 14. NIK C2 - TLS ClientHello to C2 Domain (Snort)

Detects TLS ClientHello messages containing the SNI total-sitevv[.]lol by matching the domain string in the handshake payload.

**Status:** ⚠️ uncompiled (Snort not installed; structural check only) | **Confidence:** high

<!-- Audit: Structural review: protocol ssl (Snort service keyword), ssl_state:client_hello to gate on handshake, content match for domain split across two content statements with distance 0. SID 2100203. No Suricata-only keywords (tls.sni NOT used). -->

```
alert ssl $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - NIK C2 TLS ClientHello to total-sitevv.lol"; flow:established, to_server; ssl_state:client_hello; content:"total-sitevv", fast_pattern; content:".lol", distance 0; classtype:trojan-activity; reference:url,blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/; metadata:author Actioner, created 2026-10-29; sid:2100203; rev:1;)
```

### YARA Rule

#### 15. NIK C2 Agent Binary Detection

Detects NIK C2 agent PE binaries via distinctive strings including the build path, log marker, AES cryptographic material, C2 endpoints, and staging file references.

**Status:** ✅ compiles (yarac exit 0) | **Confidence:** high

<!-- Audit: Compiled with yarac yara_nik_c2_agent.yar /dev/null, exit code 0. Rule requires MZ header (PE), filesize under 30MB, and at least one high-confidence string combination. $build_path alone is sufficient (unique to NIK panel build system). $log_marker "[NIK] Starting" alone is sufficient. AES material requires co-occurrence with endpoint strings. All string values are real (not defanged). -->

```yara
rule Malware_NIK_C2_Agent : trojan rat
{
    meta:
        description = "Detects NIK C2 agent binary via distinctive strings including build path, log marker, AES key, and C2 endpoint patterns"
        author = "Actioner"
        date = "2026-10-29"
        reference = "https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/"
        severity = "critical"

    strings:
        $build_path = "/opt/nik_panel/data/build_" ascii
        $log_marker = "[NIK] Starting" ascii wide
        $aes_seed = "d791dd0ff3228ed29a8d7333d4567be829159c5632ea347780992006f91c5295" ascii nocase
        $aes_key = "4887AFC0A574E9419A9695EF083460F58E4EF9A1C40793523CE112251273BDF9" ascii nocase
        $endpoint1 = "/api/c2/update" ascii
        $endpoint2 = "/api/c2/result" ascii
        $endpoint3 = "/api/c2/screen" ascii
        $endpoint4 = "/api/c2/ws" ascii
        $endpoint5 = "/api/c2/file_chunk" ascii
        $endpoint6 = "/api/c2/rproxy_up" ascii
        $c2_domain = "total-sitevv.lol" ascii wide
        $panel_str = "nik-panel" ascii wide
        $mbr_file = "mbr_backup.bin" ascii wide
        $lock_file = "lock_screen.html" ascii wide
        $seed_regex = "seed|phrase|mnemonic|recovery" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 30MB and
        (
            $build_path or
            $log_marker or
            ($aes_seed and 1 of ($endpoint*)) or
            ($aes_key and 1 of ($endpoint*)) or
            (3 of ($endpoint*) and ($c2_domain or $panel_str)) or
            ($mbr_file and $lock_file and 1 of ($endpoint*)) or
            ($seed_regex and $c2_domain)
        )
}
```

## Lessons Learned

1. **AI integration in commodity RATs is here.** NIK C2's OpenAI API integration demonstrates that LLM-powered features are migrating from advanced threat actors to commodity frameworks. Defenders should begin monitoring for unexpected AI API traffic from endpoints.

2. **Go-based malware continues to proliferate.** The Go compilation toolchain produces large, statically linked binaries that complicate traditional signature-based detection but leave distinctive build artifacts (like the `/opt/nik_panel/data/build_` path) that serve as reliable detection anchors.

3. **Screen-lock ransomware is a lower-barrier alternative.** Unlike file-encrypting ransomware, NIK C2's lock-screen approach requires no cryptographic complexity, is trivially reversible by forensically savvy responders, but may still coerce payment from unsophisticated victims.

4. **WebSocket over TLS on 443 evades basic network monitoring.** The use of standard HTTPS port with WebSocket upgrade makes the C2 traffic indistinguishable from legitimate web traffic without TLS inspection or endpoint-level visibility. Organizations relying solely on perimeter network monitoring will miss this traffic.

5. **Classic UAC bypass techniques remain effective.** The fodhelper.exe UAC bypass is well-documented but still effective against default Windows configurations. Enforcing "Always Notify" UAC settings and monitoring the `ms-settings` registry key remain critical defensive measures.

## Sources

- [Cisco Talos Blog - NIK C2: New AI-Enabled Framework](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/) — primary technical analysis with full IOCs and behavioral details
- [Cisco Talos GitHub IOCs (2026/10)](https://github.com/Cisco-Talos/IOCs/tree/main/2026/10) — machine-readable IOC repository

---
*Report generated by Actioner*
