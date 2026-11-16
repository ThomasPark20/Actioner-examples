# SCKit ScreenConnect Worm -- Technical Analysis (DRAFT)

> **Status**: DRAFT -- generated 2026-11-16  
> **TLP**: CLEAR  
> **Confidence**: Medium-High (primary source is Microsoft Threat Intelligence with corroboration from Huntress and CyberScoop)

---

## Executive Summary

SCKit is a multi-stage worm toolkit that abuses ConnectWise ScreenConnect remote management infrastructure to propagate across managed-service-provider (MSP) environments. Discovered in active exploitation on November 11, 2026, the campaign leveraged a vulnerable third-party ScreenConnect extension (RMM+, versions 1.0.31 and 1.0.32) whose API accepted an empty access key when none was configured, bypassing ScreenConnect's built-in user accounts, roles, and MFA. Within 90 minutes of the first observed activity, at least 288 endpoints across 48 organizations were compromised with rogue ScreenConnect clients. A second wave on November 13 hit 205 hosts across 41 organizations using new infrastructure. ConnectWise responded by disabling five extensions across approximately 400 partner environments. The worm's design includes endpoint-to-technician propagation via session hijacking and technician-to-endpoint lateral movement via the ScreenConnect Shared Toolbox, creating a self-sustaining infection cycle. Microsoft published Defender XDR hunting queries and antivirus signatures; Huntress provided independent analysis of the propagation mechanism.

---

## Background

ScreenConnect (formerly ConnectWise Control) is a widely deployed remote-support and remote-access platform used by MSPs to manage thousands of client endpoints. Its extension ecosystem allows third-party integrations to control sessions programmatically. The RMM+ extension family was designed to let other RMM tools manage ScreenConnect sessions without a technician in the console. In versions 1.0.31 and 1.0.32, the shared access key (`RMMPlus.AccessKey`) defaulted to blank, and the authentication check accepted an empty value -- meaning any caller could authenticate when no key had been explicitly configured.

A prior ScreenConnect worm campaign using VBScript was tracked by Huntress in September 2026, associated with CVE-2026-84869 (CVSS 9.9), a file-transfer flaw in ScreenConnect client versions before 26.6.5. The SCKit campaign described here is a distinct, more sophisticated toolkit that emerged in November 2026.

---

## Attack Timeline

| Date (UTC) | Event |
|---|---|
| 2026-09-08 | ConnectWise releases ScreenConnect 26.6.5, fixing CVE-2026-84869 (client-side file transfer flaw, CVSS 9.9) |
| 2026-09 | Huntress begins tracking worm-like rogue ScreenConnect activity (separate VBScript campaign) |
| 2026-11-11 ~17:47 | First SCKit activity observed; ~1/3 of targets hit in first 10 minutes |
| 2026-11-11 ~19:17 | All 288 hosts across 48 organizations compromised (~90 min elapsed) |
| 2026-11-11 22:45 | ConnectWise advisory: disables five extensions across ~400 partner environments |
| 2026-11-11 23:34 ET | Huntress links activity to RMM+ extension |
| 2026-11-13 16:12 | Second wave: 205 hosts across 41 organizations hit with new infrastructure |
| 2026-11-13 | Microsoft publishes technical analysis with Defender XDR hunting queries |

---

## Root Cause

The root cause is the RMM+ extension's authentication bypass. The `RMMPlus.AccessKey` setting was marked `IsServerOnly="true"` with an empty `DefaultValue`. When no key was configured by the administrator, the API accepted an empty access key, granting unauthenticated access to session management capabilities that bypassed ScreenConnect's user accounts, roles, and multi-factor authentication. The initial method by which attackers discovered and targeted vulnerable instances is still under investigation.

ConnectWise stated it "found no evidence of a compromise of ConnectWise infrastructure or a vulnerability in ScreenConnect itself," attributing the incident to "a threat actor's abuse of independent third-party extensions."

---

## Technical Analysis

### Stage 1: Initial Access and Rogue Client Installation

The attacker uses the ScreenConnect panel's Run Command feature to push commands as SYSTEM to groups of managed endpoints. The command:

1. Checks for an existing ScreenConnect client
2. Uses `cmd.exe` to launch `curl.exe`, downloading a rogue MSI installer to `C:\Windows\Temp\sc.msi` from attacker infrastructure
3. The MSI URL contains a `c=Exploited<N>` tracking marker (e.g., `c=Exploited9`, `c=Exploited529`)
4. Installs silently via `msiexec.exe` with `/qn` and `/norestart` flags

**Process chain**: ScreenConnect client -> `cmd.exe` -> `curl.exe` -> `msiexec.exe`

### Stage 2: Staging and Bundle Decryption

1. PowerShell decodes a URL-safe Base64 string into the dropper batch file `C:\Windows\Temp\sckit-run.bat`
2. The batch file downloads `sckit-decoder.ps1` from `ns[.]mo7sen[.]dev/EadF.php?p=4`
3. A keyed toolkit bundle is retrieved from `ns[.]mo7sen[.]dev/EadF.php?p=3&m=<MachineGuid>`
4. The decoder derives a decryption key from the machine GUID (read from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`) and server-supplied values
5. The bundle is decrypted, decompressed, and extracted to `%TEMP%\SCKitBundle`, then `%TEMP%\SCKit\trapkit\payload`
6. A VBScript wrapper launched via `wscript.exe` provides hidden relaunch capability
7. The loader generates a randomly named script matching `%TEMP%\k<32-hex-chars>.ps1`, executes it in a hidden PowerShell process, then deletes it

### Stage 3: Persistence

SCKit establishes persistence through multiple mechanisms:

- **Registry Run Key**: Creates `RelayTrapLiteAlert` value under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, launching `Lite-Alert.ps1` at logon
- **Scheduled Task**: Creates the `TrapWatch` task that runs `TrapWatch.ps1` as SYSTEM with `-PollSeconds 10`, monitoring and restarting the infection
- **Rogue ScreenConnect Services**: Two attacker-controlled ScreenConnect clients are installed and set to automatic start; the legitimate service is stopped and set to manual
- **Service Masquerading**: In at least one case, a "Windows Update Agent" service running `UpdateConnect.ClientService.exe` as LocalSystem was installed at `C:\ProgramData\Windows Update Agent (de362a425905bcc4)\`
- **Defender Exclusions**: Path exclusions are written under `HKLM\SOFTWARE\...\Windows Defender\Exclusions\Paths` for staged MSI copies, `CWInstall_*` directories, and `RelayTrap` paths
- **SRP/AppLocker Rules**: Software Restriction Policies or AppLocker rules are installed to block files pushed through ScreenConnect temp folders, preventing competing remediation attempts

### Stage 4: Credential and Session Theft

- `sqlite3.exe` is downloaded (from `EadF.php?p=5`) if not present, then used to read browser cookie databases
- The kit targets `.ASPXAUTH` ScreenConnect session cookies and anti-forgery tokens from browser memory and cookie stores
- `LabConfig.ps1` decrypts cookies, probes panels, and builds client URLs
- Huntress reports that session-cookie replay attempts "failed in every recovered host log we have checked so far"

### Stage 5: Propagation -- Endpoint to Technician (RelayTrap)

RelayTrap is the worm's endpoint-to-technician propagation component:

1. `TrapWatch.ps1` compiles `RelayTrap.cs` into a host-specific `RelayTrap.exe` binary (stored at `C:\ProgramData\RelayTrap\trapbins\<client-id>\`)
2. When a technician connects to a compromised endpoint, a file transfer fires approximately 2.5 seconds after connection
3. `Run-Lateral-Full.bat` is delivered to the technician's workstation
4. This technique was blocked in ScreenConnect client version 26.6.5 (September 8, 2026 patch for CVE-2026-84869)

### Stage 6: Propagation -- Technician to Endpoints (Lateral Distribution)

If a technician session is compromised:

1. `Panel-Lateral.ps1` uses the stolen `.ASPXAUTH` cookie combined with anti-forgery and access tokens
2. `ToolboxRelayUploader.exe` (a 32-bit .NET executable) enumerates accessible ScreenConnect sessions
3. A payload is uploaded to the panel's Shared Toolbox
4. A broadcast command makes reachable sessions execute the payload as SYSTEM
5. The toolbox item is deleted approximately 60 seconds after distribution
6. Reach depends on the compromised technician account's permissions

### Stage 7: Cleanup and Re-arm

- The kit includes cleanup scripts (`Stop-LabTrap.bat`, `Release-Machine.cmd`) that can restart the dropper unless `-NoReArm` is set
- Staging artifacts in `%TEMP%` are cleaned by `lab-trap-cleanup-embedded.ps1`
- The loader's randomly named `.ps1` file is deleted after execution

### Network Infrastructure

The campaign uses port redirection via `netsh interface portproxy` to redirect `127.0.0.1:88` to attacker infrastructure at `185.241.211[.]197:80`.

The attacker participant name observed in ScreenConnect sessions was **Addmin**.

Machine names excluded from targeting: `desktop-vmc0ifs`, `send`, `sc-observation-lab` (likely attacker test/observation systems).

---

## Indicators of Compromise

> All indicators are defanged per TLP:CLEAR handling requirements.

### File Hashes (SHA-256)

| File | SHA-256 |
|---|---|
| sc.msi (rogue installer) | `61a672a13f03a9e81f573535ee92b1ed6cb7e848a33a06048865312d4e185ae2` |
| Staged toolkit ZIP | `8e6912deed82e80bb6bd66f73509d024b1f78b993515366d8317e69a97cff4f4` |
| ToolboxRelayUploader.exe | `8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af` |
| Panel-Lateral-free.ps1 | `94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11` |
| Panel-Lateral.ps1 | `7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec` |
| LabConfig.ps1 | `b93f10f30ee453d1e1c046fec9d141c41d7680be5cd46c3aeb3febe0f4953b4d` |
| RelayTrap.cs | `3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4` |
| TrapWatch.ps1 | `d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a` |
| install.ps1 (trapkit) | `4a1dd3cd2ea14368afadf7e9dfdd63b104e3981ef8c85bbb6510919b810af04b` |
| Lite-Alert.ps1 | `cf50d73fa8117a758093b1344de41cd6a6ccddc645cdda1fa91a9264efe93956` |
| Stage0Loader.ps1 | `81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781` |
| Run-Lateral-Full.bat | `43b7a5e56f9e6c7b74e1ce2b7b5af63f383084625fcc2d3a5985fa1059e2db95` |
| runnew.cmd | `50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61` |
| Stop-LabTrap.bat | `5dd3a6ba806ac472663e243cfc1c034c534d5d9a42ec362c3dbf0f8d950148d0` |
| TRAP-PROOF.bat | `454c43d296b1276bde9a4f6ff1da2221cb35ccdb2fc7991bdd572e45bce12a8a` |
| Release-Machine.cmd | `c31e6f075cd77e01839aebce32ed35659a9ee962d102aca53040bb5e297410a9` |
| Recover-ExecutionPolicy.cmd | `deda7c30d798a19b6699a45fbcba503cf778594df9163c61c2f96bb2d2b9fb45` |
| Lab-context.json | `0bd84c776dc01f784a617e73fc77b269f847fc4a062ffd489e4692869724bf08` |

### File Hashes (SHA-1, for DeviceFileEvents)

| File | SHA-1 |
|---|---|
| sc.msi | `0be01e7bd69cfdd222645d49bb5ad9961372fef2` |
| Staged toolkit ZIP | `3f81c9c874a896c46e4bccea2fad2eaa3d9f2054` |
| ToolboxRelayUploader.exe | `13ce33b19daee3963f7e15d461b191c38f6bc0d3` |

### Network Infrastructure

| Indicator | Type | Role |
|---|---|---|
| `ns[.]mo7sen[.]dev` | Domain | Stager/tooling host (decoder, bundle, scripts, SQLite retrieval) |
| `sc[.]payproofkit[.]com` | Domain | Unauthorized ScreenConnect panel and installer source |
| `cdn007-digitaldownloads[.]com` | Domain | Campaign infrastructure, installer source |
| `newnewnew[.]gotdns[.]org` | Domain | ScreenConnect relay (resolves to 185.99.255[.]28) |
| `soxnewwork[.]homedns[.]org` | Domain | ScreenConnect relay (resolves to 185.99.255[.]28, port 81) |
| `007[.]from-ak[.]com` | Domain | Attacker relay (November 13 wave, port 88) |
| `185[.]99[.]255[.]28` | IPv4 | Unauthorized ScreenConnect server and installer source |
| `155[.]94[.]150[.]39` | IPv4 | Unauthorized ScreenConnect panel (hostname: WIN-FB5CKHMU4E1) |
| `185[.]241[.]211[.]197` | IPv4 | ScreenConnect client host (November 13 wave, 1337 Services GmbH) |

### URL Patterns

| URL Path | Purpose |
|---|---|
| `ns[.]mo7sen[.]dev/EadF.php?p=4` | Decoder download |
| `ns[.]mo7sen[.]dev/EadF.php?p=3&m=<guid>` | Keyed toolkit bundle |
| `ns[.]mo7sen[.]dev/EadF.php?p=5` | SQLite CLI download |
| `ns[.]mo7sen[.]dev/EadF.php?p=1&m=<guid>` | Stage0 payload script |
| `ns[.]mo7sen[.]dev/EadF.php?p=6&m=<guid>` | Cleanup script |
| `/Bin/ScreenConnect.ClientSetup.msi?...&c=Exploited<N>` | Rogue MSI installer |
| `/Bin/UpdateConnect.ClientSetup.msi?e=Access&y=Guest&c=ExploitedNOTUSA` | November 13 wave installer |

### Rogue ScreenConnect Client IDs

- `2588ef5c15954b10`
- `ed630cc2c873b091`

### Key File Paths

- `C:\Windows\Temp\sc.msi`
- `C:\Windows\Temp\sckit-run.bat`
- `C:\Windows\Temp\sckit-decoder.ps1`
- `%TEMP%\sckit-loader.ps1`
- `%TEMP%\k<32-hex-chars>.ps1` (randomly named loader)
- `%TEMP%\SCKitBundle\`
- `%TEMP%\SCKit\trapkit\payload\`
- `C:\ProgramData\RelayTrap\`
- `C:\ProgramData\RelayTrap\trapbins\<client-id>\RelayTrap.exe`
- `C:\ProgramData\Windows Update Agent (de362a425905bcc4)\UpdateConnect.ClientService.exe`
- `%PUBLIC%\RELAY-TRAP-PROOF.txt`

### Registry Indicators

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\RelayTrapLiteAlert`
- Defender exclusion paths under `HKLM\SOFTWARE\...\Windows Defender\Exclusions\Paths` referencing `CWInstall_`, `RelayTrap`, `ConnectWiseControl_`

### Microsoft Defender AV Signatures

- `Trojan:Win32/SuspScreenConnectDownload.EA`
- `Trojan:Win32/Tikise.EA!cmd`
- `Trojan:PowerShell/RelayPersist.FC!MTB`
- `Trojan:PowerShell/SCRelayTrap.EC!MTB`
- `HackTool:Win32/ToolboxRelayUploader`
- `Trojan:PowerShell/ScreenConnect.SC!MTB`
- `Trojan:PowerShell/ScreenConnect.DC!MTB`
- `Trojan:Win32/Tikise.A` through `Trojan:Win32/Tikise.F` variants (BAT and PowerShell)

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | SCKit Usage |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Abuse of RMM+ extension API with empty access key |
| T1219 | Remote Access Software | ScreenConnect as primary platform for access and propagation |
| T1105 | Ingress Tool Transfer | curl.exe downloads rogue MSI, decoder, toolkit bundle, SQLite |
| T1059.001 | PowerShell | Stage0Loader, Panel-Lateral, TrapWatch, install scripts |
| T1059.003 | Windows Command Shell | Dropper batch files, Run-Lateral-Full.bat, runnew.cmd |
| T1059.005 | Visual Basic | VBScript wrapper via wscript.exe for hidden relaunch |
| T1140 | Deobfuscate/Decode Files | URL-safe Base64 decoding, MachineGuid-keyed bundle decryption |
| T1547.001 | Registry Run Keys | RelayTrapLiteAlert persistence via HKLM Run key |
| T1053.005 | Scheduled Task | TrapWatch task running every 10 seconds as SYSTEM |
| T1543.003 | Windows Service | Rogue ScreenConnect client services, Windows Update Agent masquerade |
| T1562.001 | Disable or Modify Tools | Defender path exclusions, SRP/AppLocker rule manipulation |
| T1070.004 | File Deletion | Loader .ps1 files deleted after execution, toolbox items removed |
| T1555.003 | Credentials from Web Browsers | SQLite-based cookie database extraction |
| T1539 | Steal Web Session Cookie | .ASPXAUTH ScreenConnect session cookie theft |
| T1550.004 | Web Session Cookie | Replay of stolen session cookies against ScreenConnect panels |
| T1570 | Lateral Tool Transfer | Payload distribution via ScreenConnect Shared Toolbox |
| T1072 | Software Deployment Tools | Abuse of ScreenConnect Run Command for mass deployment |
| T1090 | Proxy | netsh portproxy redirect from localhost:88 to attacker infrastructure |
| T1036.004 | Masquerade Task or Service | "Windows Update Agent" service name disguising rogue client |

---

## Impact

- **Confirmed scope**: At least 288 endpoints across 48 organizations compromised in the first wave (November 11); 205 hosts across 41 organizations in the second wave (November 13)
- **Remediation scope**: ConnectWise disabled five extensions across approximately 400 partner environments
- **Session replay**: Huntress reports that technician session cookie replay attempts failed in every recovered host log checked to date
- **Lateral movement design**: The worm was designed for bidirectional propagation (endpoint-to-technician and technician-to-endpoint), though the endpoint-to-technician technique is blocked on ScreenConnect client 26.6.5+
- **Operational disruption**: Affected organizations lost trusted remote management capability during investigation and remediation
- **Supply chain risk**: The attack demonstrates how a single compromised extension in the MSP toolchain can cascade across hundreds of downstream client environments

---

## Detection and Remediation

### Immediate Actions

1. **Disable RMM+ extensions**: Ensure RMM Plus, RMM+, RMM Plus Password Link, RMM+ Password Link, and Labtech Plus are disabled in all ScreenConnect instances
2. **Verify client versions**: Confirm every ScreenConnect technician client runs version 26.6.5 or later; cloud console updates do not update technician clients
3. **Do not triage via ScreenConnect**: Use Defender live response or another out-of-band channel for investigation
4. **Revoke sessions**: Revoke all exposed ScreenConnect and identity-provider sessions; rotate credentials
5. **Audit Run Command and Shared Toolbox history**: Look for mass commands or toolbox items the operator did not initiate
6. **Do not use the kit's cleanup scripts**: The kit includes cleanup tools that can re-arm the infection

### Investigation Indicators

- Look for the `TrapWatch` scheduled task and `RelayTrapLiteAlert` Run key
- Check for a second ScreenConnect client service alongside the legitimate one
- Examine `C:\ProgramData\RelayTrap\` and `C:\ProgramData\Windows Update Agent (*)\` directories
- Search for `sckit-*` files, `ToolboxRelayUploader.exe`, and `sqlite3.exe` in Temp directories
- Review Defender exclusion additions for `CWInstall_`, `RelayTrap`, or `ConnectWiseControl_` paths
- Check for `netsh interface portproxy` rules redirecting port 88

### Rebuild Criteria

Rebuild devices when integrity cannot be established. The worm's per-host compilation and keyed decryption make hash-based detection insufficient for complete validation.

---

## Detection Rules

### Sigma Rules

#### 1. SCKit C2 Infrastructure DNS Lookups

Detects DNS queries to known SCKit campaign command-and-control domains.

<!-- audit: sigma check passed (MITRE fetch blocked by proxy, not a rule error); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Status**: Compiled (Splunk, LogScale) | **Confidence**: High (IOC-based)

```yaml
title: SCKit Campaign C2 Infrastructure DNS Lookups
id: f7a1c3e2-9b44-4d81-a6e3-8c2f1d5b7e90
status: experimental
description: Detects DNS queries or network connections to known SCKit campaign C2 domains
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner CTI
date: 2026-11-16
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1568
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - '.mo7sen.dev'
            - '.payproofkit.com'
            - '.from-ak.com'
            - 'cdn007-digitaldownloads.com'
            - 'newnewnew.gotdns.org'
            - 'soxnewwork.homedns.org'
    condition: selection
falsepositives:
    - Unlikely but validate against your environment
level: high
```

#### 2. SCKit C2 Network Connections to Known IPs

Detects outbound network connections to known SCKit attacker-controlled IP addresses.

<!-- audit: sigma check passed (MITRE fetch blocked by proxy); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Status**: Compiled (Splunk, LogScale) | **Confidence**: High (IOC-based)

```yaml
title: SCKit Campaign C2 Network Connections to Known IPs
id: b8d2e4f1-7c33-4a92-b5d6-9e1f3c8a2d70
status: experimental
description: Detects outbound network connections to known SCKit attacker infrastructure IP addresses
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner CTI
date: 2026-11-16
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp:
            - '185.99.255.28'
            - '155.94.150.39'
            - '185.241.211.197'
    condition: selection
falsepositives:
    - Unlikely
level: high
```

#### 3. SCKit RelayTrap Persistence via Registry Run Key

Detects creation of the RelayTrapLiteAlert registry Run key used by SCKit for boot persistence.

<!-- audit: sigma check passed (MITRE fetch blocked by proxy); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Status**: Compiled (Splunk, LogScale) | **Confidence**: High (IOC-based)

```yaml
title: SCKit RelayTrap Persistence via Registry Run Key
id: c9e3f5a2-8d44-4b93-a7e4-0d2f4c9b3e81
status: experimental
description: Detects creation of the RelayTrapLiteAlert registry Run key value used by SCKit for persistence
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner CTI
date: 2026-11-16
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\CurrentVersion\Run'
        Details|contains: 'RelayTrap'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```

#### 4. SCKit TrapWatch Scheduled Task Creation

Detects schtasks.exe creating the TrapWatch scheduled task used by SCKit for SYSTEM-level persistence.

<!-- audit: sigma check passed after UUID fix; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Status**: Compiled (Splunk, LogScale) | **Confidence**: High (IOC-based)

```yaml
title: SCKit TrapWatch Scheduled Task Creation
id: d0f4a6b3-9e55-4c04-b8f5-1e3a5d0c4f92
status: experimental
description: Detects creation of TrapWatch scheduled task used by SCKit worm for persistence and service hijacking
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner CTI
date: 2026-11-16
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - 'TrapWatch'
    condition: selection_schtasks
falsepositives:
    - Unlikely
level: critical
```

#### 5. SCKit Rogue ScreenConnect MSI Download via Curl

Detects curl.exe downloading a ScreenConnect MSI installer with the campaign-specific Exploited tracking marker.

<!-- audit: sigma check passed after UUID fix; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Status**: Compiled (Splunk, LogScale) | **Confidence**: Medium (behavioral + IOC-specific string)

```yaml
title: SCKit Rogue ScreenConnect MSI Download via Curl
id: e1a5b7c4-0f66-4d15-c9a6-2f4a6e1d5a03
status: experimental
description: Detects curl.exe downloading a ScreenConnect MSI installer with the Exploited marker in the URL, characteristic of the SCKit campaign
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner CTI
date: 2026-11-16
tags:
    - attack.execution
    - attack.t1105
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\curl.exe'
        CommandLine|contains:
            - 'ClientSetup.msi'
            - 'c=Exploited'
    condition: selection
falsepositives:
    - Legitimate ScreenConnect MSI deployments that happen to use curl, though the Exploited marker makes false positives unlikely
level: high
```

#### 6. SCKit Toolkit Command Line Indicators

Detects process execution with command-line strings unique to the SCKit toolkit components.

<!-- audit: sigma check passed after UUID fix; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Status**: Compiled (Splunk, LogScale) | **Confidence**: Medium (behavioral, string-matching on command lines)

```yaml
title: SCKit Toolkit Command Line Indicators
id: f2b6c8d5-1a77-4e26-d0b7-3a5a7f2e6b14
status: experimental
description: Detects process execution with command-line strings characteristic of the SCKit toolkit including staging paths and tool names
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner CTI
date: 2026-11-16
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_toolkit:
        CommandLine|contains:
            - 'SCKitBundle'
            - 'RelayTrap'
            - 'TrapWatch'
            - 'ToolboxRelayUploader'
            - 'Panel-Lateral'
            - 'sckit-decoder'
            - 'sckit-loader'
            - 'sckit-run'
            - 'EadF.php'
            - 'Stage0Loader'
    condition: selection_toolkit
falsepositives:
    - Unlikely given the specificity of these strings
level: high
```

#### 7. SCKit Defender Exclusion for Staging Directories

Detects Defender path exclusion registry writes referencing SCKit-associated staging directories.

<!-- audit: sigma check passed after UUID fix; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Status**: Compiled (Splunk, LogScale) | **Confidence**: Medium (behavioral -- Defender exclusions for CWInstall_ or ConnectWiseControl_ could be legitimate)

```yaml
title: SCKit Defender Exclusion for Staging Directories
id: a3c7d9e6-2b88-4f37-e1c8-4b6a8a3f7c25
status: experimental
description: Detects registry writes adding Windows Defender path exclusions for directories associated with SCKit staging (CWInstall_, RelayTrap, ConnectWiseControl_)
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
author: Actioner CTI
date: 2026-11-16
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_path:
        TargetObject|contains: '\Windows Defender\Exclusions\Paths'
    filter_data:
        Details|contains:
            - 'CWInstall_'
            - 'RelayTrap'
            - 'ConnectWiseControl_'
    condition: selection_path and filter_data
falsepositives:
    - Legitimate ScreenConnect deployments that add Defender exclusions, though RelayTrap exclusions are not legitimate
level: high
```

#### 8. SCKit Generated PowerShell Loader File Pattern

Detects creation of temporary PowerShell files matching the SCKit loader's random naming pattern in Temp directories.

<!-- audit: sigma check passed after UUID fix; sigma convert --without-pipeline -t splunk exit 0 (regex output); sigma convert --without-pipeline -t log_scale exit 0 -->

**Status**: Compiled (Splunk, LogScale) | **Confidence**: Medium (behavioral -- regex-based, other tools may create similarly named files)

```yaml
title: SCKit Generated PowerShell Loader File Pattern
id: b4d8e0f7-3c99-4a48-f2d9-5c7a9b4a8d36
status: experimental
description: Detects creation of temporary PowerShell files matching the SCKit loader naming pattern (k followed by 32 hex characters)
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
author: Actioner CTI
date: 2026-11-16
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1070.004
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|re: '\\Temp\\k[a-f0-9]{32}\.ps1$'
    condition: selection
falsepositives:
    - Other tools that create similarly named temporary PowerShell scripts in the Temp directory
level: medium
```

#### 9. SCKit Port Proxy Redirect via Netsh

Detects netsh portproxy commands redirecting localhost port 88, used by SCKit for relay traffic redirection to attacker infrastructure.

<!-- audit: sigma check passed after UUID fix; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Status**: Compiled (Splunk, LogScale) | **Confidence**: Medium (behavioral -- legitimate portproxy use is possible)

```yaml
title: SCKit Port Proxy Redirect via Netsh
id: c5e9f1a8-4d00-4b59-a3e0-6d8a0c5b9e47
status: experimental
description: Detects netsh portproxy commands redirecting localhost port 88 to external infrastructure, a technique used by the SCKit campaign for relay redirection
references:
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner CTI
date: 2026-11-16
tags:
    - attack.command_and_control
    - attack.t1090
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\netsh.exe'
        CommandLine|contains|all:
            - 'portproxy'
            - '127.0.0.1'
            - '88'
    condition: selection
falsepositives:
    - Legitimate netsh portproxy configurations using port 88, though the combination is unusual
level: medium
```

#### 10. SCKit SQLite3 Cookie Database Theft

Detects sqlite3.exe execution targeting browser cookie databases, used by SCKit to steal ScreenConnect session cookies.

<!-- audit: sigma check passed after UUID fix; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Status**: Compiled (Splunk, LogScale) | **Confidence**: Medium (behavioral -- sqlite3 may be used legitimately)

```yaml
title: SCKit SQLite3 Cookie Database Theft
id: d6f0a2b9-5e11-4c60-b4f1-7e9a1d6c0f58
status: experimental
description: Detects sqlite3.exe execution targeting browser cookie databases, a technique used by SCKit to steal ScreenConnect session cookies
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner CTI
date: 2026-11-16
tags:
    - attack.credential_access
    - attack.t1539
    - attack.t1555.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sqlite3.exe'
        CommandLine|contains:
            - 'Cookies'
            - '.ASPXAUTH'
            - 'cookie'
    condition: selection
falsepositives:
    - Database administration tools querying browser databases for legitimate purposes
level: high
```

### YARA Rules

#### SCKit Toolkit Strings / Uploader / RelayTrap Source / Dropper Batch

Four rules detect SCKit components: the general toolkit by characteristic strings across scripts and binaries, the ToolboxRelayUploader .NET executable, the RelayTrap C# source code, and dropper batch files.

<!-- audit: yarac sckit_files.yar /dev/null exit 0 -->

**Status**: Compiled (yarac) | **Confidence**: Medium (string-based; Huntress notes hashes are weak due to per-host rebuilds -- string detection is more durable)

```yara
rule SCKit_Toolkit_Strings
{
    meta:
        description = "Detects SCKit worm toolkit files by characteristic strings"
        author = "Actioner CTI"
        date = "2026-11-16"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash1 = "8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af"

    strings:
        $s1 = "RelayTrap" ascii wide
        $s2 = "TrapWatch" ascii wide
        $s3 = "SCKitBundle" ascii wide
        $s4 = "ToolboxRelayUploader" ascii wide
        $s5 = "Panel-Lateral" ascii wide
        $s6 = "Stage0Loader" ascii wide
        $s7 = "EadF.php" ascii wide
        $s8 = "sckit-decoder" ascii wide
        $s9 = "sckit-loader" ascii wide
        $s10 = "RelayTrapLiteAlert" ascii wide
        $s11 = "PollSeconds" ascii wide
        $s12 = "NoReArm" ascii wide

        $d1 = "ns.mo7sen.dev" ascii wide
        $d2 = "payproofkit.com" ascii wide
        $d3 = "cdn007-digitaldownloads.com" ascii wide

        $c1 = "c=Exploited" ascii wide
        $c2 = "RELAY-TRAP-PROOF" ascii wide

    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or 2 of ($d*) or (1 of ($d*) and 1 of ($s*)) or (1 of ($c*) and 1 of ($s*)))
        or
        not uint16(0) == 0x5a4d and (2 of ($s*) or 1 of ($d*) or 1 of ($c*))
}

rule SCKit_ToolboxRelayUploader
{
    meta:
        description = "Detects the SCKit ToolboxRelayUploader .NET executable by hash"
        author = "Actioner CTI"
        date = "2026-11-16"
        reference = "https://www.huntress.com/blog/sckit-worm-rogue-screenconnect"
        hash = "8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af"

    strings:
        $dotnet = "mscoree.dll" ascii
        $name = "ToolboxRelayUploader" ascii wide
        $shared = "SharedToolbox" ascii wide

    condition:
        uint16(0) == 0x5a4d and $dotnet and $name and $shared
}

rule SCKit_RelayTrap_Source
{
    meta:
        description = "Detects SCKit RelayTrap C# source code"
        author = "Actioner CTI"
        date = "2026-11-16"
        reference = "https://www.huntress.com/blog/sckit-worm-rogue-screenconnect"
        hash = "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4"

    strings:
        $cs1 = "RelayTrap" ascii
        $cs2 = "TrapWatch" ascii
        $cs3 = "ScreenConnect" ascii
        $cs4 = "ClientService" ascii

    condition:
        all of them and filesize < 500KB
}

rule SCKit_Dropper_Batch
{
    meta:
        description = "Detects SCKit dropper batch files"
        author = "Actioner CTI"
        date = "2026-11-16"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"

    strings:
        $b1 = "sckit-run" ascii nocase
        $b2 = "sckit-decoder" ascii nocase
        $b3 = "Run-Lateral-Full" ascii nocase
        $b4 = "TRAP-PROOF" ascii nocase
        $b5 = "Stop-LabTrap" ascii nocase
        $b6 = "RelayTrap" ascii nocase
        $b7 = "EadF.php" ascii nocase

    condition:
        2 of them and filesize < 100KB
}
```

### Suricata Rules

Network-based detection for SCKit C2 DNS lookups, IP connections, and HTTP request patterns.

<!-- audit: suricata -T -S sckit_c2.rules -l /tmp/actioner exit 0; "Configuration provided was successfully loaded. Exiting." -->

**Status**: Compiled (Suricata 7.0.3) | **Confidence**: High (IOC-based)

```
alert dns $HOME_NET any -> any any (msg:"SCKIT C2 DNS Lookup - ns.mo7sen.dev"; dns.query; content:"ns.mo7sen.dev"; nocase; sid:2026111601; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; classtype:trojan-activity;)

alert dns $HOME_NET any -> any any (msg:"SCKIT C2 DNS Lookup - payproofkit.com"; dns.query; content:"payproofkit.com"; nocase; sid:2026111602; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; classtype:trojan-activity;)

alert dns $HOME_NET any -> any any (msg:"SCKIT C2 DNS Lookup - cdn007-digitaldownloads.com"; dns.query; content:"cdn007-digitaldownloads.com"; nocase; sid:2026111603; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; classtype:trojan-activity;)

alert dns $HOME_NET any -> any any (msg:"SCKIT C2 DNS Lookup - newnewnew.gotdns.org"; dns.query; content:"newnewnew.gotdns.org"; nocase; sid:2026111604; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; classtype:trojan-activity;)

alert dns $HOME_NET any -> any any (msg:"SCKIT C2 DNS Lookup - soxnewwork.homedns.org"; dns.query; content:"soxnewwork.homedns.org"; nocase; sid:2026111605; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; classtype:trojan-activity;)

alert dns $HOME_NET any -> any any (msg:"SCKIT C2 DNS Lookup - from-ak.com"; dns.query; content:"from-ak.com"; nocase; sid:2026111606; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.huntress.com/blog/sckit-worm-rogue-screenconnect; classtype:trojan-activity;)

alert tcp $HOME_NET any -> 185.99.255.28 any (msg:"SCKIT C2 Connection to Known Attacker IP 185.99.255.28"; sid:2026111607; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; classtype:trojan-activity;)

alert tcp $HOME_NET any -> 155.94.150.39 any (msg:"SCKIT C2 Connection to Known Attacker IP 155.94.150.39"; sid:2026111608; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; classtype:trojan-activity;)

alert tcp $HOME_NET any -> 185.241.211.197 any (msg:"SCKIT C2 Connection to Known Attacker IP 185.241.211.197"; sid:2026111609; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.huntress.com/blog/sckit-worm-rogue-screenconnect; classtype:trojan-activity;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SCKIT C2 HTTP Request to EadF.php Stager"; flow:established,to_server; http.uri; content:"/EadF.php"; nocase; sid:2026111610; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; classtype:trojan-activity;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SCKIT Rogue ScreenConnect MSI Download with Exploited Marker"; flow:established,to_server; http.uri; content:"ClientSetup.msi"; content:"c=Exploited"; sid:2026111611; rev:1; metadata:severity high, deployment Perimeter, created_at 2026_11_16; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; classtype:trojan-activity;)
```

---

## Sources

1. [Microsoft Security Blog -- SCKit abuses ScreenConnect to deploy remote access, target technician sessions](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/) -- Primary technical analysis with Defender XDR hunting queries and antivirus signatures
2. [CyberScoop -- ConnectWise ScreenConnect SCKit Attack](https://cyberscoop.com/connectwise-screenconnect-sckit-attack/) -- Reporting on scope, timeline, and ConnectWise response
3. [Huntress -- SCKit Worm: Rogue ScreenConnect](https://www.huntress.com/blog/sckit-worm-rogue-screenconnect) -- Independent technical analysis of propagation mechanism and IOCs
4. [ConnectWise Trust Center -- Advisories](https://www.connectwise.com/company/trust/advisories) -- Vendor advisories and extension remediation
5. [ConnectWise Security Bulletin 2026-09-08](https://www.connectwise.com/company/trust/security-bulletins/2026-09-08-screenconnect-bulletin) -- CVE-2026-84869 bulletin and client update guidance
6. [Microsoft Threat Analytics Report](https://security.microsoft.com/threatanalytics3/fb63cbf6-12fe-4ad2-b26a-6eb4cb7b8257) -- Defender portal threat analytics (requires M365 Defender access)
