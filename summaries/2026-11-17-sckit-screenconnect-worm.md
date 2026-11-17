# Technical Analysis Report: SCKit — ScreenConnect Worm Campaign (2026-11-17)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-17
Version: 1.1 (REVISED)

## Executive Summary

Threat actors are exploiting an authentication flaw in the RMM+ third-party extension for ConnectWise ScreenConnect to deploy unauthorized remote-access clients and the SCKit multi-component toolkit across managed service provider (MSP) environments. The campaign, confirmed active by Microsoft and ConnectWise as of November 2026, leverages cloud-hosted ScreenConnect panels to push commands to groups of managed endpoints, installing rogue ScreenConnect clients, stealing browser session cookies, and deploying the RelayTrap worm component that targets technician workstations connecting to infected devices. At least 288 endpoints across 48 organizations were compromised in a single wave, with a third reached within 10 minutes. CVE-2026-84869 (CVSS 9.9) enables the worm's endpoint-to-technician transfer technique; it was patched in ScreenConnect client version 26.6.5 (September 8, 2026). ConnectWise has disabled five related extensions across approximately 400 partner environments, but disabling extensions does not remove persistence or unauthorized access already established.

## Background: ConnectWise ScreenConnect

ConnectWise ScreenConnect is a widely deployed remote-support and remote-access platform used heavily by MSPs to manage client environments. Its extensibility through third-party add-ons (such as RMM+, Labtech Plus) provides additional management capabilities but also introduces supply-chain risk. The RMM+ extension versions 1.0.31 and 1.0.32 contained an authentication flaw where an empty access key was accepted when none was configured, bypassing ScreenConnect's user accounts, roles, and MFA controls. This flaw gave attackers a command execution channel across all endpoints managed through affected panels.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-08 | ConnectWise releases ScreenConnect client version 26.6.5, patching CVE-2026-84869 |
| 2026-09 (early) | Huntress begins tracking worm-like ScreenConnect installations |
| ~2026-10 (approx.) | Microsoft attributes a separate ConnectWise supply-chain attack to Storm-0940 (China-state-aligned), involving the ARTEX AI framework |
| 2026-11 (week of 10th) | Huntress and Blackpoint Cyber publish initial SCKit reports |
| 2026-11-11 | ConnectWise publicly reports the active campaign |
| 2026-11-13 | Huntress detects another spike: 205 hosts across 41 organizations affected |
| 2026-11-13 | Microsoft publishes detailed technical analysis of SCKit |
| 2026-11-16 | ConnectWise completes investigation, disables five extensions across ~400 partner environments, recommends technician client 26.6.5+ |

## Root Cause: RMM+ Extension Authentication Bypass

The initial access vector is an authentication flaw in the RMM+ ScreenConnect extension (versions 1.0.31 and 1.0.32). The extension authenticated with a shared access key, but the validation logic accepted an empty value when no key was configured — the default state. This allowed attackers to bypass ScreenConnect's normal user accounts, roles, and MFA, gaining the ability to push arbitrary commands to groups of managed endpoints through cloud-hosted ScreenConnect panels. No CVE has been assigned to this specific extension flaw; ConnectWise states it found no vulnerability in ScreenConnect itself for this incident vector.

## Technical Analysis of the Malicious Payload

### 1. Initial Deployment — Rogue ScreenConnect Client Installation

The attack begins when attacker-controlled commands are pushed via the compromised ScreenConnect panel. A ScreenConnect remote command starts `cmd.exe` on the endpoint, which runs `curl.exe` to fetch `/Bin/ScreenConnect.ClientSetup.msi` from attacker infrastructure with access-session parameters including a distinctive `c=Exploited<N>` marker (e.g., `c=Exploited9`). The MSI is saved to `C:\Windows\Temp\sc.msi` and installed silently via `msiexec /i /qn /norestart`. The rogue client is configured to connect to attacker-controlled ScreenConnect relays and panels (at `sc[.]payproofkit[.]com`, `cdn007-digitaldownloads[.]com`, and associated IPs) and runs as a Windows service named "Windows Update Agent" under LocalSystem from `C:\ProgramData\Windows Update Agent\`. The rogue client stops the legitimate ScreenConnect client and reuses its code libraries to appear normal.

### 2. SCKit Toolkit Deployment — Decoder, Bundle, and Staging

A PowerShell command decodes a URL-safe Base64 string into a batch file in Windows Temp. The batch sets `BATPATH`, downloads the decoder from `ns[.]mo7sen[.]dev/EadF.php?p=4`, and runs it with `-Mode full`. The decoder creates a VBScript wrapper and launches it via `wscript.exe` to run the batch hidden. The server-side endpoint `EadF.php` serves different components based on the `p` parameter:

- `p=4`: Decoder script
- `p=3&m=<machine-guid>`: Encrypted toolkit bundle
- `p=5`: sqlite3 utility
- `p=1&m=<machine-guid>`: Encrypted PowerShell script
- `p=6&m=<machine-guid>`: Cleanup component

**Encryption scheme:** The machine's GUID (from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`) is sent as the `m` parameter. The key is derived via SHA-256 of the machine ID, XORed with 32 bytes decoded from the `X-Lab-Half` response header, with machine ID bytes appended, then processed through PBKDF2-HMAC-SHA256 (4,096 iterations, salt from `X-Lab-Salt` header). Decryption uses AES-256-CBC with PKCS7 padding; the IV is the first 16 bytes of the decoded body. Post-processing involves GZip decompression followed by ZIP extraction.

The bundle is extracted to `%TEMP%\SCKitBundle`, then staged to `%TEMP%\SCKit\trapkit\payload`. A temporary PowerShell loader file matching the pattern `k<32-hex-chars>.ps1` is created and deleted after execution.

### 3. C2 Infrastructure

Command and control operates through multiple channels:

- **HTTP retrieval** from `ns[.]mo7sen[.]dev` for toolkit components (decoder, encrypted bundles, scripts, sqlite3)
- **Unauthorized ScreenConnect panels** at `sc[.]payproofkit[.]com` and `cdn007-digitaldownloads[.]com` (IPs: `185[.]99[.]255[.]28`, `155[.]94[.]150[.]39`)
- **ScreenConnect relays** at `newnewnew[.]gotdns[.]org` and `soxnewwork[.]homedns[.]org`
- **Rogue ScreenConnect server** at `185[.]241[.]211[.]197` (hosted by 1337 Services GmbH, a bulletproof hosting provider)
- **Remote commands** via the ScreenConnect console or the RMM+ extension API

### 4. Platform-Specific Behavior

#### Windows

**Persistence mechanisms:**
- Registry Run key: `HKLM\...\CurrentVersion\Run` with value `RelayTrapLiteAlert` (launches the Lite-Alert script at logon)
- Scheduled task running the TrapWatch watcher with payload filename and exclusion lists
- Files under `C:\ProgramData\RelayTrap` with a `trapbins` directory containing per-client builds
- Rogue ScreenConnect client services set to automatic start

**RelayTrap worm component:** The watcher runs with `-PollSeconds 10`, compiling `RelayTrap.exe` using the .NET C# compiler from `RelayTrap.cs`. When a technician connects to the infected endpoint to troubleshoot, RelayTrap delivers the batch launcher to the technician's workstation via CVE-2026-84869's file-transfer-and-execute flaw.

**Browser cookie theft:** Targets the `.ASPXAUTH` ScreenConnect session cookie from Chrome, Edge, Opera, and Opera GX. Copies cookie databases (using volume shadow copy fallback for locked files), decrypts via Chromium master key through DPAPI (AES-GCM for v10/v11 cookie values). Also performs memory scanning against processes whose command lines include `network.mojom.NetworkService`, using `OpenProcess`, `VirtualQueryEx`, and `ReadProcessMemory`, with fallback to other browser processes. Uses the legitimate `sqlite3.exe` for database queries.

**Lateral movement:** Uses stolen ScreenConnect session cookies plus anti-forgery and access tokens to enumerate accessible sessions and upload payloads via `ToolboxRelayUploader.exe`. Queues execution through the Shared Toolbox, then removes the uploaded item.

### 5. Anti-Forensics / Evasion Techniques

- **Defender exclusions:** Registry writes adding Microsoft Defender Antivirus path exclusions for staged MSI copies and `CWInstall_...\Installer.ps1` paths
- **Temporary file deletion:** PowerShell loader (`k<32-hex>.ps1`) deleted after execution
- **Service masquerading:** Rogue ScreenConnect client installed as "Windows Update Agent" service under `C:\ProgramData\Windows Update Agent\` with `UpdateConnect.ClientService.exe`
- **Machine-specific encryption:** Bundle and scripts encrypted per-machine using the hardware MachineGuid, preventing static analysis of captured traffic
- **VBScript wrapper:** Decoder launches execution through `wscript.exe` to suppress visible windows

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| RMM+ (ScreenConnect extension) | 1.0.31, 1.0.32 | Authentication flaw — empty access key accepted when none configured |
| Labtech Plus, RMM Plus, RMM+, RMM Plus Password Link, RMM+ Password Link | Various | Extensions disabled by ConnectWise across ~400 partner environments |

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | sc.msi | 61a672a13f03a9e81f573535ee92b1ed6cb7e848a33a06048865312d4e185ae2 | Rogue ScreenConnect installer |
| Windows | Staged toolkit ZIP | 8e6912deed82e80bb6bd66f73509d024b1f78b993515366d8317e69a97cff4f4 | SCKit bundle archive |
| Windows | ToolboxRelayUploader.exe | 8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af | Console payload distribution tool |
| Windows | Panel-Lateral-free.ps1 | 94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11 | Lateral movement script (free variant) |
| Windows | Panel-Lateral.ps1 | 7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec | Lateral movement script |
| Windows | LabConfig.ps1 | b93f10f30ee453d1e1c046fec9d141c41d7680be5cd46c3aeb3febe0f4953b4d | Configuration helper |
| Windows | RelayTrap.cs | 3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4 | Worm component C# source |
| Windows | TrapWatch.ps1 | d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a | Watcher/compiler script |
| Windows | trapkit\install.ps1 | 4a1dd3cd2ea14368afadf7e9dfdd63b104e3981ef8c85bbb6510919b810af04b | Trap installer |
| Windows | Lite-Alert.ps1 | cf50d73fa8117a758093b1344de41cd6a6ccddc645cdda1fa91a9264efe93956 | Persistence alert script |
| Windows | Stage0Loader.ps1 | 81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781 | Initial loader |
| Windows | Run-Lateral-Full.bat | 43b7a5e56f9e6c7b74e1ce2b7b5af63f383084625fcc2d3a5985fa1059e2db95 | Batch launcher |
| Windows | runnew.cmd | 50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61 | Command launcher |
| Windows | Stop-LabTrap.bat | 5dd3a6ba806ac472663e243cfc1c034c534d5d9a42ec362c3dbf0f8d950148d0 | Cleanup launcher |
| Windows | TRAP-PROOF.bat | 454c43d296b1276bde9a4f6ff1da2221cb35ccdb2fc7991bdd572e45bce12a8a | Proof artifact |
| Windows | C:\ProgramData\Windows Update Agent\ | — | Rogue ScreenConnect client installation path |
| Windows | C:\ProgramData\RelayTrap\ | — | RelayTrap persistence directory |
| Windows | %TEMP%\SCKitBundle\ | — | Bundle extraction directory |
| Windows | %TEMP%\SCKit\trapkit\payload\ | — | Staged payload directory |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | ns[.]mo7sen[.]dev | Decoder, bundle, script, and utility retrieval (C2) |
| Domain | sc[.]payproofkit[.]com | Unauthorized ScreenConnect panel and installer source |
| Domain | cdn007-digitaldownloads[.]com | Campaign infrastructure and configured installer source |
| Domain | newnewnew[.]gotdns[.]org | ScreenConnect relay |
| Domain | soxnewwork[.]homedns[.]org | ScreenConnect relay |
| IP | 185[.]99[.]255[.]28 | Unauthorized ScreenConnect server and installer source |
| IP | 155[.]94[.]150[.]39 | Associated with unauthorized panel |
| IP | 185[.]241[.]211[.]197 | Rogue ScreenConnect server (1337 Services GmbH bulletproof hosting) |
| URL Pattern | hxxp[s]://ns[.]mo7sen[.]dev/EadF[.]php?p=4 | Decoder retrieval |
| URL Pattern | /Bin/ScreenConnect[.]ClientSetup[.]msi?...c=Exploited | Rogue installer download with campaign marker |
| Client ID | 2588ef5c15954b10 | ScreenConnect client identifier (attacker) |
| Client ID | ed630cc2c873b091 | ScreenConnect client identifier (attacker) |

### Behavioral

- **Process chain:** ScreenConnect remote command -> `cmd.exe` -> `curl.exe` (fetch MSI) -> `msiexec.exe` (silent install) -> PowerShell (decode + stage) -> `wscript.exe` (VBScript wrapper) -> toolkit execution
- **Registry persistence:** `HKLM\...\CurrentVersion\Run\RelayTrapLiteAlert` value pointing to Lite-Alert.ps1
- **Scheduled tasks:** Tasks referencing "RelayTrap" or "TrapWatch" in their action fields
- **Defender exclusion writes:** Registry modifications under `\Microsoft\Windows Defender\Exclusions\Paths` for `CWInstall` directories and `sc.msi` paths
- **Cookie theft targeting:** Processes with `network.mojom.NetworkService` in command line scanned via `OpenProcess`/`VirtualQueryEx`/`ReadProcessMemory`
- **Temporary loader pattern:** PowerShell files matching `k[a-f0-9]{32}.ps1` in Temp directory, created and deleted during execution
- **HTTP response headers:** `X-Lab-Half` and `X-Lab-Salt` custom headers used for per-machine key derivation

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of RMM+ extension authentication flaw (empty access key bypass) |
| T1199 | Trusted Relationship | Abuse of MSP-to-client trust via ScreenConnect management platform |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Stage0Loader.ps1, Panel-Lateral.ps1, TrapWatch.ps1, Lite-Alert.ps1 and other PS1 scripts |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | cmd.exe used for curl download and msiexec execution; .bat/.cmd launchers |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | VBScript wrapper created by decoder for hidden execution |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | RelayTrapLiteAlert Run key for persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Scheduled tasks for TrapWatch watcher execution |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Registry writes adding Defender path exclusions for toolkit paths |
| T1539 | Steal Web Session Cookie | Theft of .ASPXAUTH ScreenConnect session cookie from browsers |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | DPAPI-based decryption of Chromium cookie databases |
| T1057 | Process Discovery | Memory scanning of browser processes for session tokens |
| T1570 | Lateral Tool Transfer | ToolboxRelayUploader distributing payloads via Shared Toolbox |
| T1105 | Ingress Tool Transfer | curl.exe fetching MSI installer and toolkit components from C2 |
| T1036.004 | Masquerading: Masquerade Task or Service | Rogue client installed as "Windows Update Agent" service |
| T1219 | Remote Access Software | Unauthorized ScreenConnect client installation for persistent access |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 for component retrieval from EadF.php endpoint |

## Impact Assessment

The campaign affects MSP environments running ConnectWise ScreenConnect with the RMM+ extension (versions 1.0.31 and 1.0.32). Huntress confirmed 205 hosts across 41 organizations in a single spike on November 13; a separate wave affected 288 computers across 48 organizations, with approximately one-third compromised within 10 minutes and all within 90 minutes. The worm component (RelayTrap) poses a supply-chain escalation risk: a compromised client endpoint can infect a technician's workstation, potentially cascading the compromise across all client networks that technician manages. ConnectWise disabled the five identified extensions across approximately 400 partner environments. The severity is amplified by the speed of deployment, the breadth of MSP-managed networks at risk, and the per-machine encryption that hinders bulk forensic analysis.

## Detection & Remediation

### Immediate Detection

Search for the following in your environment:
- **Network connections** to `ns[.]mo7sen[.]dev`, `sc[.]payproofkit[.]com`, `cdn007-digitaldownloads[.]com`, `newnewnew[.]gotdns[.]org`, `soxnewwork[.]homedns[.]org`, or IPs `185[.]99[.]255[.]28`, `155[.]94[.]150[.]39`, `185[.]241[.]211[.]197` (un-defang before use in search queries)
<!-- revision: defanged all IOCs in Immediate Detection section with [.] notation -->
- **Process command lines** containing `EadF.php`, `c=Exploited`, `Panel-Lateral`, `RelayTrap`, `TrapWatch`, `SCKitBundle`, `ToolboxRelayUploader`, or `Stage0Loader`
- **Registry values** named `RelayTrapLiteAlert` or containing `RelayTrap` under Run keys
- **Scheduled tasks** with actions referencing `RelayTrap` or `TrapWatch`
- **Defender exclusion writes** under `\Microsoft\Windows Defender\Exclusions\Paths` for `CWInstall` or `sc.msi`
- **File creation** matching pattern `k[a-f0-9]{32}.ps1` in user Temp directories
- **Services** named "Windows Update Agent" running from `C:\ProgramData\Windows Update Agent\`
- **File hashes** listed in the IOC tables above

### Remediation

1. **Disable extensions immediately:** Disable Labtech Plus, RMM Plus, RMM+, RMM Plus Password Link, and RMM+ Password Link per ConnectWise advisory. Do not re-enable until further guidance.
2. **Update technician clients** to version 26.6.5 or later (cloud console updates do not update clients).
3. **Investigate via out-of-band channel:** Use Defender for Endpoint live response or another tool not dependent on ScreenConnect. Isolate affected endpoints.
4. **Preserve logs:** Collect console, Toolbox, endpoint, and extension logs before remediation.
5. **Revoke sessions:** Revoke ScreenConnect web sessions and associated identity-provider sessions from a clean device. Rotate all exposed credentials.
6. **Remove persistence:** Delete the `RelayTrapLiteAlert` Run value, associated scheduled tasks, unauthorized Defender exclusions, trap files under `C:\ProgramData\RelayTrap`, and rogue ScreenConnect services. Use approved tooling, not the recovered cleanup script.
7. **Rebuild if uncertain:** If endpoint integrity cannot be established, rebuild the device.
8. **Enable protections:** Ensure Defender Antivirus, cloud-delivered protection, and tamper protection are enabled. Consider application control policies.

### Long-Term Hardening

- Audit and minimize third-party ScreenConnect extensions; apply the principle of least privilege to extension access keys
- Require non-default, strong access keys for all ScreenConnect extensions
- Monitor for unauthorized ScreenConnect client installations across the fleet
- Implement network-level monitoring for connections to known dynamic DNS providers (gotdns[.]org, homedns[.]org) and bulletproof hosting ranges
<!-- revision: defanged gotdns.org and homedns.org with [.] notation in Long-Term Hardening section -->
- Segment technician workstations from client endpoint management where feasible

## Detection Rules

These detections target the SCKit campaign's distinctive artifacts: C2 infrastructure, toolkit component names, persistence mechanisms, and file patterns. PoC/advisory-specific altitude (default), strict leniency. Compiles does not equal fires -- verify each rule in your pipeline before production deployment. The `sigma check` command could not complete ATT&CK tag validation due to a network restriction (MITRE data fetch blocked), but all Sigma rules converted cleanly to both Splunk and CrowdStrike LogScale via `sigma convert --without-pipeline`.

### Sigma: SCKit Campaign Infrastructure Network Connection
Detects network connections to known SCKit C2 domains and IP addresses used for payload delivery, unauthorized panels, and ScreenConnect relays.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403, network issue, not a rule defect); splunk convert exit 0; log_scale convert exit 0. Domain matching now uses campaign-specific subdomains (newnewnew.gotdns.org, soxnewwork.homedns.org) rather than broad dynamic DNS provider domains. -->
<!-- revision: replaced broad endswith 'gotdns.org' and 'homedns.org' with campaign-specific subdomains 'newnewnew.gotdns.org' and 'soxnewwork.homedns.org' to avoid matching all subdomains of popular dynamic DNS providers -->
```yaml
title: SCKit Campaign Infrastructure Network Connection
id: 7a3e1d9f-4b2c-4e8a-9d6f-1c0b3a5e7f2d
status: experimental
description: >
    Detects network connections to known SCKit campaign infrastructure domains
    and IP addresses used for C2, unauthorized ScreenConnect panels, and payload delivery.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://thehackernews.com/2026/11/connectwise-warns-screenconnect-attacks.html
author: Actioner
date: 2026/11/17
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: network_connection
    product: windows
detection:
    selection_domains:
        DestinationHostname|endswith:
            - 'mo7sen.dev'
            - 'payproofkit.com'
            - 'cdn007-digitaldownloads.com'
            - 'newnewnew.gotdns.org'
            - 'soxnewwork.homedns.org'
    selection_ips:
        DestinationIp:
            - '185.99.255.28'
            - '155.94.150.39'
            - '185.241.211.197'
    condition: selection_domains or selection_ips
falsepositives:
    - Legitimate use of newnewnew.gotdns.org or soxnewwork.homedns.org subdomains unrelated to this campaign
level: high
```

### Sigma: SCKit RelayTrap Persistence via Registry Run Key
Detects creation of the `RelayTrapLiteAlert` registry Run value or registry data referencing RelayTrap, used by SCKit for logon persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. RelayTrapLiteAlert is unique to this campaign; near-zero FP expected. -->
```yaml
title: SCKit RelayTrap Persistence via Registry Run Key
id: 2f8c5a1d-9e3b-4d7a-8c6e-0a4f1b2d3e5c
status: experimental
description: >
    Detects creation of the RelayTrapLiteAlert registry Run value used by the
    SCKit toolkit for persistence, or registry data referencing RelayTrap components.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
author: Actioner
date: 2026/11/17
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_valuename:
        TargetObject|endswith: '\RelayTrapLiteAlert'
    selection_valuedata:
        Details|contains: 'RelayTrap'
    condition: selection_valuename or selection_valuedata
falsepositives:
    - Unlikely; RelayTrapLiteAlert is a distinctive campaign artifact
level: critical
```

### Sigma: SCKit Toolkit Command-Line Indicators
Detects process execution with command-line strings distinctive to the SCKit campaign, including the `EadF.php` retrieval path, the `Exploited` client marker, and toolkit script names.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. All matched strings are campaign-specific; benign collision extremely unlikely. -->
```yaml
title: SCKit Toolkit Command-Line Indicators
id: 4d1e9a3c-6b7f-4c2d-8e5a-3f0b1c9d7e6a
status: experimental
description: >
    Detects process execution with command-line strings distinctive to the SCKit
    campaign, including the EadF.php retrieval path, the Exploited client marker,
    and toolkit script names.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
author: Actioner
date: 2026/11/17
tags:
    - attack.t1059.001
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'EadF.php'
            - 'c=Exploited'
            - 'Panel-Lateral'
            - 'RelayTrap'
            - 'TrapWatch'
            - 'SCKitBundle'
            - 'ToolboxRelayUploader'
            - 'Stage0Loader'
            - 'Lite-Alert.ps1'
    condition: selection
falsepositives:
    - Custom internal tools reusing these distinctive names is extremely unlikely
level: high
```

### Sigma: SCKit Generated PowerShell Loader File Creation
Detects creation of temporary PowerShell loader files matching the SCKit naming pattern `k` followed by 32 hex characters and `.ps1`, typically dropped in the user Temp directory.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0 (emits regex filter); log_scale convert exit 0. The k+32hex+.ps1 pattern is distinctive but not guaranteed unique; other tools could theoretically generate similar filenames. -->
```yaml
title: SCKit Generated PowerShell Loader File Creation
id: 8b2d4e6f-1a3c-4f5e-9d7b-0c8a2e4f6d1b
status: experimental
description: >
    Detects creation of temporary PowerShell loader files matching the SCKit naming
    pattern k followed by 32 hex characters and a .ps1 extension, typically dropped
    in the user Temp directory.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
author: Actioner
date: 2026/11/17
tags:
    - attack.t1059.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|re: '\\k[a-f0-9]{32}\.ps1$'
    condition: selection
falsepositives:
    - Applications generating temporary PowerShell scripts with a similar naming convention
level: medium
```

### Sigma: SCKit Defender Exclusion for ScreenConnect Installer Path
Detects registry writes adding Defender path exclusions for paths consistent with SCKit staging locations (`CWInstall` directories and `sc.msi`). Scope to environments where ScreenConnect installations are centrally managed to reduce FP.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. FP possible if IT admins legitimately exclude CWInstall paths during authorized deployments. CWInstall appears in legitimate ConnectWise deployment paths. -->
<!-- revision: downgraded confidence from high to medium — CWInstall appears in legitimate ConnectWise deployment paths and IT admins routinely add Defender exclusions for ConnectWise installation directories -->
```yaml
title: SCKit Defender Exclusion for ScreenConnect Installer Path
id: 5c9e3a1b-7d4f-4e2c-8b6a-2d0f1e3c5a7b
status: experimental
description: >
    Detects registry writes adding Microsoft Defender path exclusions for paths
    consistent with SCKit staging locations, specifically CWInstall directories
    and Windows Temp MSI files used by the campaign.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
author: Actioner
date: 2026/11/17
tags:
    - attack.t1562.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_path:
        TargetObject|contains: '\Microsoft\Windows Defender\Exclusions\Paths'
    selection_value:
        Details|contains:
            - 'CWInstall'
            - '\sc.msi'
    condition: selection_path and selection_value
falsepositives:
    - Legitimate IT administrators excluding ConnectWise installation paths from Defender scanning
level: high
```

### Snort: SCKit HTTP Request to EadF.php Payload Endpoint
Detects outbound HTTP requests to the `/EadF.php` endpoint used by the SCKit decoder and component retrieval infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -i lo -T exit 0. Snort 2.9.20 syntax. EadF.php is a campaign-specific URI path. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - SCKit HTTP Request to EadF.php Payload Endpoint"; flow:established,to_server; content:"/EadF.php"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; sid:2100010; rev:1;)
```

### Snort: SCKit ScreenConnect Installer with Exploited Marker
Detects HTTP requests for `ScreenConnect.ClientSetup.msi` containing the `c=Exploited` campaign marker in the URI.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -i lo -T exit 0. Both content matches in http_uri. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - SCKit ScreenConnect Installer with Exploited Marker"; flow:established,to_server; content:"ScreenConnect.ClientSetup.msi"; http_uri; fast_pattern; content:"c=Exploited"; http_uri; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; sid:2100011; rev:1;)
```

### Suricata: SCKit HTTP Request to EadF.php Payload Endpoint
Detects outbound HTTP requests to the `/EadF.php` endpoint used by the SCKit toolkit for decoder and component delivery.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Suricata 7.0.3 dot-notation buffers. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SCKit HTTP Request to EadF.php Payload Endpoint"; flow:established,to_server; http.uri; content:"/EadF.php"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-17; sid:2200010; rev:1;)
```

### Suricata: SCKit DNS Query to mo7sen.dev C2 Domain
Detects DNS queries to `mo7sen.dev`, the primary C2 domain used for SCKit decoder and payload retrieval.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. dns.query buffer; nocase for case-insensitive DNS matching. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - SCKit DNS Query to mo7sen.dev C2 Domain"; flow:to_server; dns.query; content:"mo7sen.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-17; sid:2200011; rev:1;)
```

### Suricata: SCKit DNS Query to payproofkit.com C2 Domain
Detects DNS queries to `payproofkit.com`, an unauthorized ScreenConnect panel domain used in the SCKit campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - SCKit DNS Query to payproofkit.com C2 Domain"; flow:to_server; dns.query; content:"payproofkit.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-17; sid:2200012; rev:1;)
```

### Suricata: SCKit DNS Query to cdn007-digitaldownloads.com
Detects DNS queries to `cdn007-digitaldownloads.com`, a campaign infrastructure domain used for installer delivery.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - SCKit DNS Query to cdn007-digitaldownloads.com"; flow:to_server; dns.query; content:"cdn007-digitaldownloads.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-17; sid:2200013; rev:1;)
```

### YARA: SCKit Toolkit Strings
Detects SCKit toolkit components via distinctive strings found in PowerShell scripts, batch files, and C# source, requiring 3 or more campaign-specific strings in a single file.
**Status:** compile ✅ compiles · confidence: high · sample: constructed (from published strings)
<!-- audit: yarac exit 0. yara pos.txt matched SCKit_Toolkit_Strings; yara neg.txt silent. Positive sample constructed from published source strings (SCKitBundle, RelayTrap, EadF.php, X-Lab-Half, X-Lab-Salt, lab-context.json, -PollSeconds). 3-of-15 threshold balances coverage and FP avoidance. -->
<!-- revision: relabeled sample status from 'fired ✓' to 'constructed (from published strings)' — the positive was a synthetic sample, not a real malware sample -->
```yara
rule SCKit_Toolkit_Strings
{
    meta:
        description = "Detects SCKit toolkit components via distinctive strings found in PowerShell scripts, batch files, and C# source"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        severity = "high"

    strings:
        $s1 = "SCKitBundle" ascii wide
        $s2 = "RelayTrap" ascii wide
        $s3 = "TrapWatch" ascii wide
        $s4 = "ToolboxRelayUploader" ascii wide
        $s5 = "Panel-Lateral" ascii wide
        $s6 = "Stage0Loader" ascii wide
        $s7 = "Lite-Alert" ascii wide
        $s8 = "RelayTrapLiteAlert" ascii wide
        $s9 = "TRAP-PROOF" ascii wide
        $s10 = "EadF.php" ascii wide
        $s11 = "X-Lab-Half" ascii wide
        $s12 = "X-Lab-Salt" ascii wide
        $s13 = "lab-context.json" ascii wide
        $s14 = "-PollSeconds" ascii wide
        $s15 = "c=Exploited" ascii wide

    condition:
        filesize < 5MB and 3 of them
}
```

### YARA: SCKit RelayTrap CS Source
Detects the RelayTrap.cs C# source file by the combination of campaign-specific strings and browser memory-scanning API references characteristic of the worm component.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. 4-of-6 threshold combines campaign strings (RelayTrap, .ASPXAUTH, network.mojom.NetworkService) with the specific API chain (OpenProcess, VirtualQueryEx, ReadProcessMemory). Hash: 3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4. -->
```yara
rule SCKit_RelayTrap_CS_Source
{
    meta:
        description = "Detects RelayTrap.cs source file used in the SCKit campaign worm component"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash = "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4"
        severity = "high"

    strings:
        $s1 = "RelayTrap" ascii
        $s2 = ".ASPXAUTH" ascii
        $s3 = "network.mojom.NetworkService" ascii
        $s4 = "VirtualQueryEx" ascii
        $s5 = "ReadProcessMemory" ascii
        $s6 = "OpenProcess" ascii

    condition:
        filesize < 2MB and 4 of them
}
```

## Lessons Learned

This campaign demonstrates the acute supply-chain risk inherent in third-party extensions for remote management platforms. The RMM+ authentication flaw — an empty default access key accepted as valid — is a textbook insecure-default vulnerability that bypassed ScreenConnect's own authentication, MFA, and RBAC. The worm component (RelayTrap) introduces an escalation vector unique to MSP environments: a compromised client endpoint can infect the technician connecting to investigate, potentially cascading across the technician's entire client portfolio.

Key takeaways:
- **Extension trust is platform trust.** Third-party extensions operate within the platform's trust boundary and can undermine its security controls. Organizations should audit extensions, enforce non-default credentials, and monitor for unauthorized extension activity.
- **Patching the console is not enough.** CVE-2026-84869 was patched in September 2026, but the fix requires updating individual technician clients — cloud console updates do not propagate to clients, leaving a remediation gap.
- **Disabling does not equal remediation.** ConnectWise disabled the offending extensions, but existing persistence, unauthorized clients, and stolen credentials survive extension disabling. Full investigation and cleanup are required for any environment that ran the affected extensions.

## Sources

- [Microsoft Security Blog — SCKit Abuses ScreenConnect](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/) — primary technical analysis with full IOC list, attack chain detail, and hunting queries
- [The Hacker News — ConnectWise Warns ScreenConnect Attacks](https://thehackernews.com/2026/11/connectwise-warns-screenconnect-attacks.html) — additional IOCs (185.241.211.197, Windows Update Agent service details), Huntress telemetry (205 hosts / 41 orgs), ConnectWise response timeline
- [CyberScoop — ConnectWise ScreenConnect SCKit Attack](https://cyberscoop.com/connectwise-screenconnect-sckit-attack/) — RMM+ authentication flaw details, 288 endpoints / 48 orgs telemetry, Storm-0940 attribution context, operational timeline

---
*Report generated by Actioner*
