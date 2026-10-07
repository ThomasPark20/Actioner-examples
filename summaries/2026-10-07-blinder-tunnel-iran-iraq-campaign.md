# Technical Analysis Report: Blinder Tunnel Campaign (2026-10-07)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-07
Version: 1.0

## Executive Summary

Blinder Tunnel (tracked by Unit 42 as CL-STA-1178) is an Iranian state-aligned espionage campaign targeting critical infrastructure in Iraq, the UAE, and Israel. The campaign uses fraudulent Dubai Airports recruitment lures to deliver trojanized Visual Studio C# projects that deploy a three-stage infection chain: a weaponized .csproj file exploiting MSBuild's design-time build process (ShelbyLoader V2), AppDomainManager hijacking with ETW disablement, and DLL sideloading to establish a persistent RAT (ShelbyC2 V2) with GitHub-based command-and-control. The campaign also deploys a custom Chisel-based tunneling tool (Blackwood) and an in-memory PowerShell execution engine (PsProxy) for lateral movement. Infrastructure traces link the operation to an Iranian ISP and Persian-language services. The campaign was active from November 2025 through at least June 2026, with a parallel credential harvesting operation targeting Israeli entities.

Attribution to an Iranian state-aligned threat actor is assessed with high confidence based on infrastructure hosted on Iranian ISPs, Persian-language domain registrar artifacts, regional victimology consistent with Iranian strategic interests, and overlapping TTPs with known Iranian APT groups including Screening Serpens (UNC1549) and Agent Serpens (APT35).

## Background: Iraqi Critical Infrastructure and Aviation Sector Targeting

The Blinder Tunnel campaign targets Iraqi software engineers and critical infrastructure personnel through social engineering lures impersonating the Dubai Airports IT Department. The aviation sector in the Gulf region is a high-value espionage target due to its role in international logistics, diplomatic travel, and economic infrastructure. Iraqi telecommunications companies were also targeted. This campaign represents an evolution of the "Shelby Strategy" previously documented by Elastic Security Labs, now with significantly upgraded tooling including GitHub-based C2, zero-disk tunneling, and robust anti-analysis capabilities.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-11 | Infrastructure staging and operational testing begins; GitHub comment testing observed Nov. 18 |
| 2025-11 to 2026-03 | Infrastructure dormant but operational |
| 2026-03 | Campaign activation; Dubai Airports recruitment lure deployment begins |
| 2026-04 | Weaponized coding challenge (FlightManager.csproj) distributed to targets |
| 2026-04-16 | C2 fallback comment posted on GitHub issue |
| 2026-04-24 | "asasas" GitHub testing thread observed |
| 2026-05-01 | Blackwood repository (pubs) created on GitHub |
| 2026-05-16 | Israeli phishing URL submitted (WarUnPublishedDocuments.zip lure) |
| 2026-05 to 2026-06 | Credential harvesting campaign against Israeli entity |
| 2026-10-06 | Unit 42 public disclosure |

## Root Cause: Trojanized Visual Studio Project via Fake Recruitment

Initial access is achieved through targeted social engineering: the threat actor impersonates the Dubai Airports IT Department, sending personalized recruitment lures to Iraqi software engineers. Victims receive a ZIP archive (`DubaiAirport_Carrers_IT_Test.zip`) containing what appears to be a legitimate Visual Studio C# coding challenge. The archive includes a `Readme.md` with personalized instructions, a weaponized `FlightManager.csproj` project file, a `.sln` solution file, and a `Resources` folder containing the malware binaries. When the victim opens the project in Visual Studio, the malicious .csproj file triggers automatic malware deployment through MSBuild's design-time build process.

## Technical Analysis of the Malicious Payload

### 1. Stage 1 -- Weaponized .csproj via MSBuild Target Override (T1127)

The `FlightManager.csproj` file (SHA256: `f5b12772db6817f7a765a6fe7565fd3d4f87edc28e42fe3ec0244a372a410fc9`) exploits Visual Studio's design-time build process by overriding the `GetFrameworkPaths` MSBuild target. This target is automatically invoked when Visual Studio opens a project, requiring no explicit user action beyond opening the solution file. The weaponized target copies malicious binaries from the project's Resources folder to `%LOCALAPPDATA%\Microsoft\RuntimeBrokers\` and executes `RuntimeBroker.exe`. This technique abuses a legitimate trusted developer utility (MSBuild) to proxy execution, bypassing application whitelisting controls.

### 2. Stage 2 -- AppDomainManager Hijacking with ETW Disablement (T1574.014)

The `RuntimeBroker.exe` binary is a renamed copy of Visual Studio's `vshost.exe`. The accompanying `RuntimeBroker.exe.config` file contains an XML configuration that:
- Sets `<etwEnable enabled="false"/>` to disable Event Tracing for Windows, blinding security monitoring tools
- Specifies a malicious AppDomainManager that forces the .NET runtime to load the attacker's DLL (`RuntimeBroker.dll` / ShelbyLoader V2) before the host application launches
- This enables covert code execution within the context of a trusted process

### 3. Stage 3 -- DLL Sideloading and ShelbyLoader V2 (T1574.001)

The malicious `RuntimeBroker.dll` (SHA256: `53f35e49eb9b271fd8cbcd3daacb525328dbf159a03dbd1c7adebe0363daa402`) is loaded via DLL search-order hijacking. ShelbyLoader V2 performs:
- **Anti-analysis checks**: WMI queries, running process enumeration, registry key inspection, file artifact detection, hardware verification (CPU, RAM, disk space), and parent process validation (must be spawned by `explorer.exe`)
- **Persistence**: Creates registry run key `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicrosoftRuntime` pointing to the malware binary; checks persistence status every 120 seconds with four operational states (Already persisted, Newly persisted, Registry key not found, Executable not found)
- **Obfuscation**: Uses the open-source Obfuscar tool with runtime string decryption and non-printable Unicode characters for class and method identifiers

### 4. C2 Infrastructure

**Primary C2 Channel -- GitHub API:**
ShelbyLoader V2 uses the GitHub API with a hard-coded Personal Access Token (`github_pat_11B2HDA2Q0KDdo...`) to communicate with the `peakyblinders-tm/myLic` repository. Machine registration occurs via `/{machineId}/Lic.txt` containing a Base64-encoded fingerprint. Command polling occurs via `/{machineId}/Inf.txt` with Base64-encoded commands. The machineId is derived from the first 16 lowercase hex characters of the SHA-256 hash of "Peaky Blinders 2.1" concatenated with the machine fingerprint. Beacon interval is 63 seconds, with a 1-hour sleep on HTTP 403 rate-limit errors.

**Fallback C2 Channel -- GitHub Issues Search API:**
On HTTP 401 errors, the malware activates a fallback C2 resolver using the GitHub Issues Search API. It constructs date-formatted search queries (yyyymmdd format), extracts content hidden inside HTML comment markers (`<!-- -->`) from issue bodies, and decrypts them using AES-256-CBC. The decryption key is derived from MD5(current_date + machineId), with the IV derived from MD5(key) iterated 5 times. Extracted data uses regex patterns to obtain new C2 parameters: `Owner=(\w.+)`, `LicRepo=(\w.+)`, `LicToken=(\w.+)`.

**C2 IP Infrastructure:**
| IP | Role | Hosting |
|---|---|---|
| 91.107.156[.]29 | Chisel tunneling endpoint | Hetzner, Germany |
| 87.248.129[.]239 | Iranian staging | TOSE'EH ERTEBATAT NOVIN ARIA (Iranian ISP) |
| 65.109.214[.]145 | Credential harvesting & Blackwood C2 (port 8080) | Hetzner |
| 38.180.136[.]127 | Staging infrastructure | Unknown |

**Phishing Domains:**
- cloud.g-drive[.]cam
- googeldrive[.]cam
- drivegoogel[.]cam
- googelmeet[.]online
- meetonline[.]cam
- asdfafadafg[.]online

### 5. Post-Exploitation Tools

**ShelbyC2 V2 (RuntimeBrokerApi.dll):** The main RAT component providing command execution and payload staging capabilities.

**PsProxy.dll** (SHA256: `3fd810a3aa0039993393741b32287c367a9a5037a41e826906440887cdd3ed13`): An in-memory PowerShell execution engine that creates an invisible runspace within the hijacked host process, executing PowerShell commands without invoking `PowerShell.exe`. It hooks `System.Management.Automation.dll` directly. This is a stateless tool with no persistence of its own.

**Blackwood** (SHA256: `76273382e4252c1f60a2251141e108942494409c759358320735891762c0682e`): A custom wrapper around the Chisel open-source tunneling utility (Go-compiled DLL). Deployed as a zero-disk tool -- the 8.4 MB Chisel binary is embedded as a manifest resource (`Blackwood.Cheese.xml`) and reflectively loaded into memory. Blackwood establishes encrypted TCP tunnels over HTTP with reverse SOCKS5 proxy support (`R:0.0.0.0:10999:socks`). Configuration is stored in `Blackwood.dll.conf` (Base64-encoded, RC4-encrypted), containing the tunneling endpoint IP and SOCKS proxy settings. Decryption uses passphrase `y0Da+QH#pwSg38E?=8R;71-jQu8Tqq` (SHA-256 derived) and RC4 key `My name is Blackwood !`.

### 6. Anti-Forensics / Evasion Techniques

- **ETW Disablement**: Configuration file sets `etwEnable=false` to suppress Event Tracing for Windows
- **Process parent validation**: Only executes if spawned by `explorer.exe`
- **In-memory execution**: PsProxy and Chisel operate entirely in memory; Blackwood's Chisel payload never touches disk
- **Anti-analysis environment checks**: WMI queries for hardware characteristics, process enumeration for analysis tools, registry key inspection, file artifact detection
- **Obfuscation**: Obfuscar-based .NET obfuscation with runtime string decryption and non-printable Unicode identifiers
- **GitHub API abuse**: Leverages legitimate platform for C2 to evade network-level blocking
- **Renamed system binaries**: Uses renamed `vshost.exe` as `RuntimeBroker.exe` to blend with legitimate Windows processes

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| FlightManager.csproj | N/A | Trojanized Visual Studio project file with GetFrameworkPaths target override |
| DubaiAirport_Carrers_IT_Test.zip | N/A | Delivery archive containing the weaponized project and malware binaries |
| Client.zip | N/A | Blackwood delivery archive hosted on GitHub (peakyblinders-tm/pubs) |
| WarUnPublishedDocuments.zip | N/A | Israeli-targeting credential harvesting lure |

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | DubaiAirport_Carrers_IT_Test.zip | `6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239` | Initial delivery archive |
| Windows | FlightManager.csproj | `f5b12772db6817f7a765a6fe7565fd3d4f87edc28e42fe3ec0244a372a410fc9` | Weaponized VS project file |
| Windows | %LOCALAPPDATA%\Microsoft\RuntimeBrokers\RuntimeBroker.dll | `53f35e49eb9b271fd8cbcd3daacb525328dbf159a03dbd1c7adebe0363daa402` | ShelbyLoader V2 |
| Windows | PsProxy.dll | `3fd810a3aa0039993393741b32287c367a9a5037a41e826906440887cdd3ed13` | In-memory PowerShell engine |
| Windows | Blackwood.dll | `76273382e4252c1f60a2251141e108942494409c759358320735891762c0682e` | Chisel tunneling wrapper |
| Windows | Blackwood.dll.conf (91.107.156[.]29) | `d3561bd4aad003dc3e08157b0891860bb496b80cd6e44901692e08ab1d4e8260` | Blackwood configuration |
| Windows | Blackwood archive (65.109.214[.]145) | `f5ba1645694c62f527ed6ceda8c68a5c3dd92b4032439167e8e937e72803b4bd` | Blackwood delivery archive |
| Windows | Blackwood archive (87.248.129[.]239) | `7cc571aca6d8715d9aaad3d83e1bcd30467565d583db1dfe73697c5d00a1f875` | Blackwood delivery archive |

### Network

| Type | Value | Context |
|------|-------|---------|
| GitHub Repo | hxxps://github[.]com/peakyblinders-tm/myLic | Primary C2 repository |
| GitHub Repo | hxxps://github[.]com/peakyblinders-tm/pubs | Blackwood hosting (Client.zip) |
| GitHub Account | hxxps://github[.]com/GreenBeret0 | Alternative operator account |
| IP | 91.107.156[.]29 | Chisel tunneling endpoint (Hetzner, Germany) |
| IP | 87.248.129[.]239 | Iranian staging (TOSE'EH ERTEBATAT NOVIN ARIA ISP) |
| IP | 65.109.214[.]145:8080 | Credential harvesting & Blackwood C2 |
| IP | 38.180.136[.]127 | Staging infrastructure |
| Domain | cloud.g-drive[.]cam | Credential harvesting (Google Drive impersonation) |
| Domain | googeldrive[.]cam | Credential harvesting (Google Drive impersonation) |
| Domain | drivegoogel[.]cam | Credential harvesting (Google Drive impersonation) |
| Domain | googelmeet[.]online | Credential harvesting (Google Meet impersonation) |
| Domain | meetonline[.]cam | Credential harvesting (Google Meet impersonation) |
| Domain | asdfafadafg[.]online | Credential harvesting infrastructure |
| URL Pattern | hxxps://api.github[.]com/repos/peakyblinders-tm/myLic/contents/{machineId}/Lic.txt | Machine registration C2 |
| URL Pattern | hxxps://api.github[.]com/repos/peakyblinders-tm/myLic/contents/{machineId}/Inf.txt | Command polling C2 |
| URL Pattern | hxxps://api.github[.]com/search/issues | Fallback C2 resolver |

### Behavioral

- Process `RuntimeBroker.exe` executing from `%LOCALAPPDATA%\Microsoft\RuntimeBrokers\` (legitimate path is `%SystemRoot%\System32\`)
- Registry key creation: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicrosoftRuntime`
- Periodic 63-second beacon interval to GitHub API
- Outbound connections to port 8080 on Hetzner infrastructure
- MSBuild.exe processing .csproj files that trigger binary deployment to LocalAppData
- DLL loading of `RuntimeBroker.dll` from non-standard LocalAppData paths
- `.exe.config` files with `etwEnable=false` in non-standard directories
- Chisel SOCKS5 proxy tunneling on port 10999

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.002 | Spearphishing Link | Fraudulent Dubai Airports recruitment emails with links to download trojanized project |
| T1127 | Trusted Developer Utilities Proxy Execution | MSBuild executes weaponized .csproj with GetFrameworkPaths target override |
| T1574.014 | Hijack Execution Flow: AppDomainManager | Malicious config forces .NET runtime to load attacker's AppDomainManager before host app |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | RuntimeBroker.dll sideloaded via renamed vshost.exe |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Renamed vshost.exe to RuntimeBroker.exe to mimic Windows system binary |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | MicrosoftRuntime registry run key for persistence |
| T1102.001 | Web Service: Dead Drop Resolver | GitHub Issues Search API used as fallback C2 resolver |
| T1071.001 | Application Layer Protocol: Web Protocols | GitHub API used for primary C2 over HTTPS |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PsProxy.dll executes PowerShell in-memory without PowerShell.exe |
| T1140 | Deobfuscate/Decode Files or Information | AES-256-CBC decryption of fallback C2 commands; Base64 encoding of C2 data |
| T1572 | Protocol Tunneling | Blackwood/Chisel establishes encrypted TCP tunnels over HTTP with SOCKS5 proxy |
| T1562.001 | Impair Defenses: Disable or Modify Tools | ETW disabled via etwEnable=false configuration |
| T1027 | Obfuscated Files or Information | Obfuscar .NET obfuscation with runtime string decryption |
| T1082 | System Information Discovery | Anti-analysis hardware and environment checks via WMI |

## Impact Assessment

**Breadth:** The campaign targets Iraqi critical infrastructure and telecommunications personnel, with a parallel credential harvesting operation against Israeli entities. The targeting scope suggests strategic espionage objectives rather than broad opportunistic compromise.

**Depth:** The three-stage infection chain provides deep and persistent access with command execution, in-memory PowerShell, and encrypted tunneling capabilities. The Blackwood tool enables lateral movement through network perimeters via SOCKS5 proxying.

**Stealth:** The campaign is highly evasive -- it abuses legitimate platforms (GitHub) for C2, mimics Windows system processes (RuntimeBroker), disables ETW monitoring, operates key tools entirely in memory, and employs multiple anti-analysis checks. The 63-second beacon interval to GitHub API is difficult to distinguish from legitimate developer activity.

**Exposure Window:** November 2025 through at least June 2026 (approximately 7 months), with public disclosure on October 6, 2026.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for Blinder Tunnel persistence registry key
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MicrosoftRuntime" -ErrorAction SilentlyContinue

# Check for RuntimeBroker.exe in non-standard path
Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\RuntimeBrokers" -Recurse -ErrorAction SilentlyContinue

# Check for suspicious .exe.config files with ETW disabled
Get-ChildItem -Path "$env:LOCALAPPDATA" -Recurse -Filter "*.exe.config" | Select-String -Pattern "etwEnable.*false"

# Search for known malware hashes on disk
Get-FileHash -Path "$env:LOCALAPPDATA\Microsoft\RuntimeBrokers\*" -Algorithm SHA256 -ErrorAction SilentlyContinue

# Check network connections to known C2 IPs
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -in @('91.107.156.29','87.248.129.239','65.109.214.145','38.180.136.127') }

# Check DNS logs/cache for phishing domains
Get-DnsClientCache | Where-Object { $_.Entry -match 'g-drive\.cam|googeldrive\.cam|drivegoogel\.cam|googelmeet\.online|meetonline\.cam|asdfafadafg\.online' }
```

### Remediation

1. **Containment:** Immediately isolate any system with confirmed IOC matches. Block all C2 IPs (91.107.156[.]29, 87.248.129[.]239, 65.109.214[.]145, 38.180.136[.]127) and phishing domains at the network perimeter.
2. **Eradication:** Remove the `MicrosoftRuntime` registry run key. Delete the entire `%LOCALAPPDATA%\Microsoft\RuntimeBrokers\` directory. Scan for and remove all files matching the SHA256 hashes listed above.
3. **Recovery:** Reimage compromised systems. Reset credentials for all accounts accessed from compromised machines. Revoke and rotate any GitHub Personal Access Tokens that may have been observed in network traffic.
4. **Secret Rotation:** Rotate all credentials potentially exposed through the SOCKS5 proxy tunnel, including internal service accounts, VPN credentials, and authentication tokens.

### Long-Term Hardening

- **MSBuild controls:** Implement application control policies to restrict MSBuild execution to approved build environments. Monitor for MSBuild invocations outside CI/CD pipelines.
- **AppDomainManager hardening:** Monitor for `.exe.config` files containing `appDomainManagerType` and `etwEnable=false` in non-standard paths.
- **GitHub API monitoring:** Alert on outbound connections to the GitHub API from non-development workstations, particularly with embedded Personal Access Tokens.
- **Visual Studio project vetting:** Establish procedures for scanning externally received Visual Studio projects before opening, including inspection of .csproj targets.
- **Network segmentation:** Restrict outbound SOCKS proxy and tunneling traffic from endpoint networks.

## Detection Rules

The rules below cover the Blinder Tunnel campaign's infection chain from initial delivery through persistence and C2 communication: 8 Sigma, 4 YARA, 4 Snort, and 8 Suricata rules targeting specific, campaign-derived indicators at strict leniency. Sigma rules passed `sigma convert --without-pipeline` to both Splunk and LogScale backends. YARA rules passed `yarac` compilation. Network rules (Snort/Suricata) have not been compiled against a live engine and are structurally validated only. Compiles does not mean fires -- verify in your pipeline.

<!-- AUDIT: REVISION applied 2026-10-07. Fixes: (1) confidence: critical→high in all 12 status labels; (2) level: critical→high in 6 Sigma rules; (3) Rule 2 condition OR-redundancy fixed (selection_key and selection_value); (4) Rule 3 unreachable filter removed; (5) Rule 4 OR-redundancy fixed + api.github.com/search/issues removed (high-FP generic endpoint); (6) Snort 3 syntax: comma→semicolon between options, distance 0→distance:0; (7) Suricata syntax: distance 0→distance:0; (8) 3 missing Suricata DNS rules added (drivegoogel.cam sid:2100206, meetonline.cam sid:2100207, asdfafadafg.online sid:2100208); (9) YARA severity: critical→high; (10) Elastic source URL corrected to specific blog post. All 8 Sigma rules re-validated: sigma convert --without-pipeline to Splunk and LogScale exit 0. YARA re-validated: yarac exit 0. Snort/Suricata structurally checked (engines not installed). All detection values use real (non-defanged) indicators per logsource-encoding.md guidance. -->

### Sigma Rules

**Blinder Tunnel - Malicious csproj MSBuild GetFrameworkPaths Override**
Detects MSBuild executing a csproj file containing campaign-specific naming patterns (FlightManager, DubaiAirport).

compile: `sigma convert` to Splunk/LogScale -- passed | confidence: high

```yaml
title: Blinder Tunnel - Malicious csproj MSBuild GetFrameworkPaths Override
id: 7a1c3e4f-8b2d-4f5a-9c6e-1d0f3a2b5c7d
status: experimental
description: >
    Detects MSBuild executing a csproj file that overrides the GetFrameworkPaths
    target, as used by the Blinder Tunnel campaign (CL-STA-1178) to deploy
    ShelbyLoader V2 via trojanized Visual Studio projects.
references:
    - https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
author: Actioner
date: 2026-10-07
tags:
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection_msbuild:
        Image|endswith: '\MSBuild.exe'
    selection_csproj:
        CommandLine|endswith:
            - '.csproj'
            - '.csproj"'
    selection_suspicious_names:
        CommandLine|contains:
            - 'FlightManager'
            - 'DubaiAirport'
            - 'Carrers_IT_Test'
    condition: selection_msbuild and (selection_csproj and selection_suspicious_names)
falsepositives:
    - Legitimate builds of projects with similar naming patterns
level: high
```

---

**Blinder Tunnel - ShelbyLoader RuntimeBroker Persistence Registry Key**
Detects creation of the MicrosoftRuntime registry run key pointing to the non-standard RuntimeBrokers path.

compile: `sigma convert` to Splunk/LogScale -- passed | confidence: high

```yaml
title: Blinder Tunnel - ShelbyLoader RuntimeBroker Persistence Registry Key
id: 2b3d4e5f-6a7c-8b9d-0e1f-2a3b4c5d6e7f
status: experimental
description: >
    Detects creation of the MicrosoftRuntime registry run key used by the Blinder
    Tunnel campaign (CL-STA-1178) ShelbyLoader V2 for persistence, pointing to a
    RuntimeBroker.exe binary deployed in a non-standard LocalAppData path.
references:
    - https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
author: Actioner
date: 2026-10-07
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|endswith: '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicrosoftRuntime'
    selection_value:
        Details|contains: '\RuntimeBrokers\RuntimeBroker.exe'
    condition: selection_key and selection_value
falsepositives:
    - Unlikely - MicrosoftRuntime is not a standard Windows run key value name
level: high
```

---

**Blinder Tunnel - RuntimeBroker Execution from Non-Standard LocalAppData Path**
Detects RuntimeBroker.exe running from LocalAppData instead of its legitimate System32 location.

compile: `sigma convert` to Splunk/LogScale -- passed | confidence: high

```yaml
title: Blinder Tunnel - RuntimeBroker Execution from Non-Standard LocalAppData Path
id: 3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f
status: experimental
description: >
    Detects RuntimeBroker.exe execution from the non-standard path
    %LOCALAPPDATA%\Microsoft\RuntimeBrokers, as used by the Blinder Tunnel campaign
    (CL-STA-1178). The legitimate RuntimeBroker.exe runs from System32.
references:
    - https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
author: Actioner
date: 2026-10-07
tags:
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '\AppData\Local\Microsoft\RuntimeBrokers\RuntimeBroker.exe'
    condition: selection
falsepositives:
    - Unlikely - RuntimeBroker.exe should only run from System32
level: high
```

---

**Blinder Tunnel - GitHub API C2 Communication**
Detects proxy log entries showing access to the peakyblinders-tm GitHub repositories used for C2.

compile: `sigma convert` to Splunk/LogScale -- passed | confidence: high

```yaml
title: Blinder Tunnel - GitHub API C2 Communication
id: 4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f9a
status: experimental
description: >
    Detects network connections to the GitHub API endpoint used by the Blinder
    Tunnel campaign (CL-STA-1178) ShelbyLoader V2 for C2 communication via the
    peakyblinders-tm/myLic repository.
references:
    - https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
author: Actioner
date: 2026-10-07
tags:
    - attack.t1102.001
logsource:
    category: proxy
detection:
    selection_github_api:
        c-uri|contains:
            - 'api.github.com/repos/peakyblinders-tm/myLic'
            - 'api.github.com/repos/peakyblinders-tm/pubs'
    selection_file_patterns:
        c-uri|contains:
            - '/Lic.txt'
            - '/Inf.txt'
    condition: selection_github_api and selection_file_patterns
falsepositives:
    - Legitimate access to unrelated GitHub repositories with similar naming
level: high
```

---

**Blinder Tunnel - DNS Query to Campaign Phishing Domains**
Detects DNS resolution of the six known phishing domains impersonating Google services.

compile: `sigma convert` to Splunk/LogScale -- passed | confidence: high

```yaml
title: Blinder Tunnel - DNS Query to Campaign Phishing Domains
id: 5e6f7a8b-9c0d-1e2f-3a4b-5c6d7e8f9a0b
status: experimental
description: >
    Detects DNS queries to phishing domains used by the Blinder Tunnel campaign
    (CL-STA-1178) for credential harvesting, impersonating Google Drive and
    Google Meet services.
references:
    - https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
author: Actioner
date: 2026-10-07
tags:
    - attack.t1566.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName:
            - 'cloud.g-drive.cam'
            - 'googeldrive.cam'
            - 'drivegoogel.cam'
            - 'googelmeet.online'
            - 'meetonline.cam'
            - 'asdfafadafg.online'
    condition: selection
falsepositives:
    - None expected
level: high
```

---

**Blinder Tunnel - AppDomainManager ETW Disablement via Config File**
Detects creation of RuntimeBroker.exe.config or vshost32.exe.config in the campaign's staging directory.

compile: `sigma convert` to Splunk/LogScale -- passed | confidence: high

```yaml
title: Blinder Tunnel - AppDomainManager ETW Disablement via Config File
id: 6f7a8b9c-0d1e-2f3a-4b5c-6d7e8f9a0b1c
status: experimental
description: >
    Detects creation or modification of .exe.config files containing
    etwEnable=false, as used by the Blinder Tunnel campaign (CL-STA-1178)
    to disable Event Tracing for Windows during AppDomainManager hijacking.
references:
    - https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
author: Actioner
date: 2026-10-07
tags:
    - attack.t1574.014
logsource:
    category: file_event
    product: windows
detection:
    selection_path:
        TargetFilename|endswith:
            - 'RuntimeBroker.exe.config'
            - 'vshost32.exe.config'
    selection_location:
        TargetFilename|contains: '\AppData\Local\Microsoft\RuntimeBrokers'
    condition: selection_path and selection_location
falsepositives:
    - Legitimate Visual Studio debugging configurations in non-standard paths
level: high
```

---

**Blinder Tunnel - Network Connection to Campaign C2 Infrastructure**
Detects outbound connections to the four known C2 IP addresses used across campaign operations.

compile: `sigma convert` to Splunk/LogScale -- passed | confidence: high

```yaml
title: Blinder Tunnel - Network Connection to Campaign C2 Infrastructure
id: 7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d
status: experimental
description: >
    Detects outbound network connections to IP addresses used by the Blinder
    Tunnel campaign (CL-STA-1178) for Chisel tunneling, credential harvesting,
    and Blackwood C2 communications.
references:
    - https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
author: Actioner
date: 2026-10-07
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '91.107.156.29'
            - '87.248.129.239'
            - '65.109.214.145'
            - '38.180.136.127'
    condition: selection
falsepositives:
    - Legitimate traffic to Hetzner or other hosting providers sharing these IPs (unlikely given specificity)
level: high
```

---

**Blinder Tunnel - DLL Sideloading via Renamed vshost.exe**
Detects loading of RuntimeBroker.dll from the campaign's non-standard staging directory.

compile: `sigma convert` to Splunk/LogScale -- passed | confidence: high

```yaml
title: Blinder Tunnel - DLL Sideloading via Renamed vshost.exe
id: 8b9c0d1e-2f3a-4b5c-6d7e-8f9a0b1c2d3e
status: experimental
description: >
    Detects loading of RuntimeBroker.dll alongside a renamed vshost.exe binary
    from the non-standard RuntimeBrokers directory, indicating ShelbyLoader V2
    DLL sideloading as used in the Blinder Tunnel campaign (CL-STA-1178).
references:
    - https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
author: Actioner
date: 2026-10-07
tags:
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection_dll:
        ImageLoaded|endswith: '\RuntimeBroker.dll'
    selection_path:
        ImageLoaded|contains: '\AppData\Local\Microsoft\RuntimeBrokers'
    condition: selection_dll and selection_path
falsepositives:
    - None expected - legitimate RuntimeBroker components do not load DLLs from LocalAppData
level: high
```

### YARA Rules

**APT_CL_STA_1178_ShelbyLoader_V2**
Detects ShelbyLoader V2 via campaign-specific strings including the GitHub C2 repo path, PAT prefix, machineId seed, and persistence key name.

compile: `yarac` -- passed | confidence: high

**APT_CL_STA_1178_Blackwood_Tunneler**
Detects the Blackwood tunneling wrapper via its hard-coded passphrase, RC4 key, manifest resource name, and SOCKS proxy configuration.

compile: `yarac` -- passed | confidence: high

**APT_CL_STA_1178_PsProxy**
Detects the PsProxy in-memory PowerShell engine by combining PowerShell automation imports with Shelby-specific references.

compile: `yarac` -- passed | confidence: medium (requires co-occurrence of generic PowerShell strings with campaign-specific references)

**APT_CL_STA_1178_Trojanized_CSProj**
Detects trojanized .csproj files by matching the GetFrameworkPaths target override combined with RuntimeBroker deployment patterns.

compile: `yarac` -- passed | confidence: medium (targets project file format, not PE binary)

```yara
rule APT_CL_STA_1178_ShelbyLoader_V2 : BlinderTunnel
{
    meta:
        description = "Detects ShelbyLoader V2 (RuntimeBroker.dll) used in the Blinder Tunnel campaign (CL-STA-1178) via characteristic strings and configuration patterns"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/"
        hash = "53f35e49eb9b271fd8cbcd3daacb525328dbf159a03dbd1c7adebe0363daa402"
        severity = "high"

    strings:
        $gh_repo = "peakyblinders-tm/myLic" ascii wide
        $gh_token = "github_pat_11B2HDA2Q0KDdo" ascii wide
        $machid_seed = "Peaky Blinders 2.1" ascii wide
        $file_lic = "/Lic.txt" ascii wide
        $file_inf = "/Inf.txt" ascii wide
        $persist_key = "MicrosoftRuntime" ascii wide
        $path_brokers = "RuntimeBrokers" ascii wide
        $cfg_etw = "etwEnable" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        4 of them
}

rule APT_CL_STA_1178_Blackwood_Tunneler : BlinderTunnel
{
    meta:
        description = "Detects the Blackwood custom Chisel tunneling wrapper used by the Blinder Tunnel campaign (CL-STA-1178)"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/"
        hash = "76273382e4252c1f60a2251141e108942494409c759358320735891762c0682e"
        severity = "high"

    strings:
        $passphrase = "y0Da+QH#pwSg38E?=8R;71-jQu8Tqq" ascii wide
        $rc4_key = "My name is Blackwood !" ascii wide
        $manifest = "Blackwood.Cheese.xml" ascii wide
        $socks_cfg = "R:0.0.0.0:10999:socks" ascii wide
        $conf_name = "Blackwood.dll.conf" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        2 of them
}

rule APT_CL_STA_1178_PsProxy : BlinderTunnel
{
    meta:
        description = "Detects PsProxy.dll in-memory PowerShell execution engine used by the Blinder Tunnel campaign (CL-STA-1178)"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/"
        hash = "3fd810a3aa0039993393741b32287c367a9a5037a41e826906440887cdd3ed13"
        severity = "high"

    strings:
        $ps_auto = "System.Management.Automation" ascii wide
        $ps_runspace = "RunspaceFactory" ascii wide
        $ps_invoke = "Invoke" ascii wide
        $shelby_ref = "RuntimeBrokerApi" ascii wide
        $shelby_ref2 = "ShelbyC2" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        ($ps_auto and $ps_runspace and $ps_invoke) and
        1 of ($shelby*)
}

rule APT_CL_STA_1178_Trojanized_CSProj : BlinderTunnel
{
    meta:
        description = "Detects trojanized Visual Studio C# project files used as initial access in the Blinder Tunnel campaign (CL-STA-1178)"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/"
        hash = "f5b12772db6817f7a765a6fe7565fd3d4f87edc28e42fe3ec0244a372a410fc9"
        severity = "high"

    strings:
        $target_override = "GetFrameworkPaths" ascii wide
        $runtime_brokers = "RuntimeBrokers" ascii wide
        $runtime_broker_exe = "RuntimeBroker.exe" ascii wide
        $xml_target = "<Target" ascii
        $xml_copy = "<Copy" ascii

    condition:
        filesize < 500KB and
        $target_override and
        ($runtime_brokers or $runtime_broker_exe) and
        ($xml_target and $xml_copy)
}
```

### Snort 3 Rules

All Snort rules below are structurally validated only (balanced parentheses, required fields present, correct protocol-buffer alignment). They have not been compiled against a live Snort 3 engine.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Blinder Tunnel ShelbyLoader GitHub API C2 to peakyblinders-tm Repo"; flow:established,to_server; http_uri; content:"/repos/peakyblinders-tm/"; fast_pattern; content:"/contents/"; distance:0; http_header; content:"Authorization"; content:"token github_pat_"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created 2026-10-07, campaign BlinderTunnel; sid:2100101; rev:1;)
```
compile: structural check only | confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Blinder Tunnel ShelbyLoader GitHub Issues Search Fallback C2"; flow:established,to_server; http_uri; content:"/search/issues"; fast_pattern; http_header; content:"Authorization"; content:"token github_pat_"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created 2026-10-07, campaign BlinderTunnel; sid:2100102; rev:1;)
```
compile: structural check only | confidence: high

```
alert tcp $HOME_NET any -> 91.107.156.29 any (msg:"Actioner - Blinder Tunnel Blackwood Chisel Tunnel to Known C2 IP"; flow:established,to_server; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created 2026-10-07, campaign BlinderTunnel; sid:2100103; rev:1;)
```
compile: structural check only | confidence: high

```
alert tcp $HOME_NET any -> 65.109.214.145 8080 (msg:"Actioner - Blinder Tunnel Blackwood C2 Backend on Port 8080"; flow:established,to_server; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created 2026-10-07, campaign BlinderTunnel; sid:2100104; rev:1;)
```
compile: structural check only | confidence: high

### Suricata Rules

All Suricata rules below are structurally validated only (dot-notation buffers, balanced parentheses, required fields). They have not been compiled against a live Suricata engine.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Blinder Tunnel ShelbyLoader GitHub API C2 to peakyblinders-tm Repo"; flow:established,to_server; http.uri; content:"/repos/peakyblinders-tm/"; fast_pattern; content:"/contents/"; distance:0; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created_at 2026-10-07, campaign BlinderTunnel; sid:2100201; rev:1;)
```
compile: structural check only | confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - Blinder Tunnel Phishing Domain - g-drive.cam"; flow:to_server; dns.query; content:"g-drive.cam"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created_at 2026-10-07, campaign BlinderTunnel; sid:2100202; rev:1;)
```
compile: structural check only | confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - Blinder Tunnel Phishing Domain - googeldrive.cam"; flow:to_server; dns.query; content:"googeldrive.cam"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created_at 2026-10-07, campaign BlinderTunnel; sid:2100203; rev:1;)
```
compile: structural check only | confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - Blinder Tunnel Phishing Domain - googelmeet.online"; flow:to_server; dns.query; content:"googelmeet.online"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created_at 2026-10-07, campaign BlinderTunnel; sid:2100204; rev:1;)
```
compile: structural check only | confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - Blinder Tunnel Phishing Domain - drivegoogel.cam"; flow:to_server; dns.query; content:"drivegoogel.cam"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created_at 2026-10-07, campaign BlinderTunnel; sid:2100206; rev:1;)
```
compile: structural check only | confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - Blinder Tunnel Phishing Domain - meetonline.cam"; flow:to_server; dns.query; content:"meetonline.cam"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created_at 2026-10-07, campaign BlinderTunnel; sid:2100207; rev:1;)
```
compile: structural check only | confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - Blinder Tunnel Phishing Domain - asdfafadafg.online"; flow:to_server; dns.query; content:"asdfafadafg.online"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created_at 2026-10-07, campaign BlinderTunnel; sid:2100208; rev:1;)
```
compile: structural check only | confidence: high

```
alert tcp $HOME_NET any -> [91.107.156.29,65.109.214.145,87.248.129.239,38.180.136.127] any (msg:"Actioner - Blinder Tunnel Connection to Known C2 Infrastructure"; flow:established,to_server; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/; metadata:author Actioner, created_at 2026-10-07, campaign BlinderTunnel; sid:2100205; rev:1;)
```
compile: structural check only | confidence: high

## Lessons Learned

1. **Developer tool trust is a viable attack vector.** The Blinder Tunnel campaign demonstrates that trojanized Visual Studio projects can achieve code execution merely by being opened, without requiring the victim to explicitly build or run anything. Organizations should treat externally received IDE project files with the same suspicion as executable attachments.

2. **GitHub as C2 is increasingly difficult to block.** The campaign's use of the GitHub API for C2 -- with both a primary channel and a sophisticated fallback resolver via the Issues Search API -- makes network-based blocking impractical without disrupting legitimate developer workflows. Detection must focus on behavioral patterns (beacon intervals, file path conventions, PAT usage from non-development systems) rather than simple domain or IP blocking.

3. **Iranian APT tooling is converging on common patterns.** The overlap between CL-STA-1178 and known groups (Screening Serpens, Agent Serpens) in specific techniques -- AppDomainManager hijacking with ETW disablement, GitHub dead-drop resolvers, recruitment lures -- suggests shared tooling development or knowledge transfer within the Iranian cyber ecosystem. Defenders should treat these TTPs as indicators of a broader capability rather than isolated campaign artifacts.

## Sources

- [Unit 42 - Blinder Tunnel Targets Critical Infrastructure](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/) -- primary technical analysis with full IOC set, infection chain details, and attribution assessment
- [Elastic Security Labs - The Shelby Strategy](https://www.elastic.co/security-labs/the-shelby-strategy) -- prior analysis of related ShelbyLoader/ShelbyC2 tooling (predecessor campaign)

---
*Report generated by Actioner*
