# Technical Analysis Report: SCKit Worm Campaign Targeting ScreenConnect MSP Environments (2026-11-14)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-11-14
Version: 1.0 (FINAL)

## Executive Summary

On 2026-11-11, attackers launched a coordinated campaign abusing **ConnectWise ScreenConnect** remote management infrastructure to deploy **SCKit**, a 16-component worm-like toolkit designed to spread through MSP environments. Initial access appears linked to an authentication flaw in the **RMM+ third-party ScreenConnect extension** (versions 1.0.31 and 1.0.32), where a blank default access key (`RMMPlus.AccessKey`) allowed unauthenticated command execution bypassing ScreenConnect user accounts, roles, and MFA. Attackers used ScreenConnect's Run Command feature to push commands to managed endpoints across multiple cloud-hosted panels, deploying rogue ScreenConnect Access clients and the SCKit toolkit.

SCKit's core innovation is **RelayTrap**, a C# component compiled on each victim host that replaces the legitimate ScreenConnect Guest process and exploits **CVE-2026-84869** (CVSS 9.9) -- a critical client-side flaw allowing Guest-to-Host file transfer and execution without Host confirmation -- to attempt payload delivery to connecting MSP technicians. On the technician's workstation, the toolkit steals **`.ASPXAUTH` session cookies** from browser databases and process memory, then replays those cookies against ScreenConnect management consoles to distribute commands to all endpoints the technician can access, creating cascading, worm-like propagation through MSP management infrastructure.

**Wave 1** (2026-11-11) affected at least **288 endpoints across 48 organizations** within 90 minutes, with one-third compromised in the first 10 minutes. **Wave 2** (2026-11-13) affected **205 hosts across 41 organizations** using new infrastructure. ConnectWise disabled five third-party extensions across approximately 400 partner environments. The toolkit's technician-pivot component (console takeover via stolen cookies) has **not been observed to succeed** in any recovered host logs, and **CVE-2026-84869 is blocked by ScreenConnect clients updated to version 26.6.5+** (patched 2026-09-08), though Blackpoint's testing confirmed unpatched clients remain vulnerable.

Severity: **Critical** (CVSS 9.9 CVE, active worm-like propagation through MSP supply chain, multi-stage toolkit with credential theft and lateral movement capabilities).

## Background: ConnectWise ScreenConnect and MSP Risk

ConnectWise ScreenConnect (formerly ConnectWise Control) is a widely-deployed remote monitoring and management (RMM) tool used by Managed Service Providers (MSPs) to manage thousands of customer endpoints. It provides remote access, support sessions, Run Command (execute commands as SYSTEM on managed hosts), file transfer, and Shared Toolbox (distribute files to multiple sessions) capabilities. The platform supports third-party extensions that integrate with external tools.

MSP environments represent a high-value supply-chain target: compromising a single MSP technician's session can cascade to hundreds or thousands of downstream customer endpoints. ScreenConnect's architecture -- where a single console can manage endpoints across many separate organizations -- amplifies this risk. The SCKit campaign specifically targets this trust architecture, weaponizing the technician-to-client trust relationship in reverse.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-20 (approx) | Earliest suspected CVE-2026-84869 exploitation activity (VBScript+XMRig campaign) |
| 2026-09-08 | ConnectWise releases ScreenConnect 26.6.5 patching CVE-2026-84869 |
| 2026-09-11 | CISA adds CVE-2026-84869 to KEV catalog (remediation deadline: Sep 14) |
| 2026-11-11 ~17:47 | **Wave 1**: SCKit Run Commands observed across multiple cloud-hosted ScreenConnect panels |
| 2026-11-11 (within 10 min) | ~96 endpoints compromised (one-third of Wave 1 total) |
| 2026-11-11 (within 90 min) | 288 endpoints across 48 organizations compromised |
| 2026-11-11 22:45 | ConnectWise disables five third-party extensions across ~400 partner environments |
| 2026-11-11 23:34 ET | Huntress links activity to RMM+ extension |
| 2026-11-12 | Huntress, BleepingComputer, CyberScoop publish initial reports |
| 2026-11-13 16:12 | **Wave 2**: 205 hosts across 41 organizations, new infrastructure (185[.]241[.]211[.]197, 007[.]from-ak[.]com) |
| 2026-11-13 | Microsoft publishes detailed technical blog; Blackpoint publishes APG analysis |
| 2026-11-14 | This report published |

## Vulnerability: CVE-2026-84869

| Field | Value |
|-------|-------|
| **CVE** | CVE-2026-84869 |
| **CVSS** | 9.9 (Critical) |
| **CWE** | CWE-862 (Missing Authorization), CWE-269 (Improper Privilege Management) |
| **Affected** | ConnectWise ScreenConnect client builds prior to 26.6.5.9742 |
| **Fixed** | ScreenConnect 26.6.5 (2026-09-08) |
| **CISA KEV** | Added 2026-09-11; remediation deadline 2026-09-14 |
| **Component** | ScreenConnect Host (technician) client, not the management server |

**Mechanism**: An attacker controlling an active Guest session (compromised endpoint) can push a file to the connecting technician's Host client and have it executed without Host confirmation. The flaw is in the file-transfer trust boundary between Guest and Host -- normally, only the Host (technician) initiates file transfers to endpoints, but CVE-2026-84869 allows the reverse direction with execution. In SCKit's implementation, RelayTrap sends a `TransferFilesMessage` with `FileAction.Run` and `canBeElevated` set, targeting the technician's machine when they connect to the compromised endpoint.

**Patch status**: Blackpoint's APG confirmed that fully patched ScreenConnect clients (26.6.5+) block the payload. The RelayTrap code does not check Host version before sending, so attempts against patched Hosts are expected but will fail.

## Initial Access: RMM+ Extension Authentication Bypass

The RMM+ third-party ScreenConnect extension (versions 1.0.31 and 1.0.32) uses a shared access key (`RMMPlus.AccessKey`) for authentication instead of ScreenConnect's built-in user accounts, roles, and MFA. If an administrator never configured this key, it defaulted to blank, and the extension accepted an empty key. This allowed an attacker to:

1. Send API calls with an empty access key
2. Bypass ScreenConnect login and MFA entirely
3. Execute Run Commands on managed endpoints as SYSTEM

Huntress observed commands reaching endpoints across multiple ScreenConnect instances within minutes, with no matching user login activity in ScreenConnect audit logs. All activity traced to the RMM+ extension.

**Extensions disabled by ConnectWise**: Labtech Plus, RMM Plus, RMM+, RMM Plus Password Link, RMM+ Password Link.

**Note**: Blackpoint found no direct technical link between the disabled extensions and SCKit's toolkit components. The initial access vector remains under active investigation.

## Technical Analysis: SCKit Toolkit

### Component Overview

SCKit consists of **16 scripts and components** organized into a staged delivery chain:

| Component | Purpose | SHA-256 |
|-----------|---------|---------|
| sc.msi | Rogue ScreenConnect Access client installer | `61a672a13f03a9e81f573535ee92b1ed6cb7e848a33a06048865312d4e185ae2` |
| sckit-run.bat | Initial batch dropper | -- |
| sckit-decoder.ps1 (p=4) | PowerShell decoder/bootstrap | `338e37f58043635ebab64ee5fdc919935e55cb146ca97834b358f934e55e88ec` |
| Encrypted bundle (p=3) | Toolkit archive (ZIP) | `8e6912deed82e80bb6bd66f73509d024b1f78b993515366d8317e69a97cff4f4` |
| Stage0Loader.ps1 (p=1) | Encrypted PowerShell loader | `81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781` |
| SilentForceInstall-WithUninstall.ps1 | Rogue Access client installer | `a1937467fd862916f89342cdd61f55c4bc405fb35b6e1379e27cfbfdba77dcdc` |
| RelayTrap.cs | C# source for Guest replacement | `3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4` |
| TrapWatch.ps1 | Service watcher / trap activation | `d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a` |
| install.ps1 | Trap installation and lockout | `4a1dd3cd2ea14368afadf7e9dfdd63b104e3981ef8c85bbb6510919b810af04b` |
| Lite-Alert.ps1 | Persistence alert script | `cf50d73fa8117a758093b1344de41cd6a6ccddc645cdda1fa91a9264efe93956` |
| Panel-Lateral-free.ps1 | Browser/session cookie collection | `94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11` |
| Panel-Lateral.ps1 | Full session collection variant | `7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec` |
| LabConfig.ps1 | Helper for session collection | `b93f10f30ee453d1e1c046fec9d141c41d7680be5cd46c3aeb3febe0f4953b4d` |
| ToolboxRelayUploader.exe | Shared Toolbox payload uploader | `8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af` |
| Run-Lateral-Full.bat | Lateral movement batch launcher | `43b7a5e56f9e6c7b74e1ce2b7b5af63f383084625fcc2d3a5985fa1059e2db95` |
| runnew.cmd | Alternate command launcher | `50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61` |
| Stop-LabTrap.bat | Cleanup script | `5dd3a6ba806ac472663e243cfc1c034c534d5d9a42ec362c3dbf0f8d950148d0` |
| TRAP-PROOF.bat | Proof-of-concept artifact | `454c43d296b1276bde9a4f6ff1da2221cb35ccdb2fc7991bdd572e45bce12a8a` |
| Release-Machine.cmd | SRP/AppLocker cleanup | `c31e6f075cd77e01839aebce32ed35659a9ee962d102aca53040bb5e297410a9` |
| Recover-ExecutionPolicy.cmd | Execution policy restoration | `deda7c30d798a19b6699a45fbcba503cf778594df9163c61c2f96bb2d2b9fb45` |
| Lab-context.json | Configuration | `0bd84c776dc01f784a617e73fc77b269f847fc4a062ffd489e4692869724bf08` |
| ScreenConnect.ClientSetup.msi (cdn007 variant) | Alternate rogue installer | `d85315bd7602b6f5c13dc0eada2c9cba0892c7cd3b1eb7dacb1bffdd536ceb21` |

### Infection Chain

#### Phase 1: Initial Deployment (Run Command Abuse)

1. Attacker sends Run Commands via ScreenConnect cloud panels (likely via RMM+ with blank key), executing as **NT AUTHORITY\SYSTEM**.
2. Commands check for existing ScreenConnect installation, then use `curl.exe` to download `sc.msi` from the attacker's server (URL pattern: `/Bin/ScreenConnect.ClientSetup.msi?...&c=Exploited<N>`; participant name: `Addmin`).
3. MSI saved to `C:\Windows\Temp\sc.msi`, installed silently with `msiexec /i ... /qn /norestart`.
4. A Base64-encoded batch script is decoded and written to `C:\Windows\Temp\sckit-run.bat`.

#### Phase 2: Staged Retrieval and Decryption

5. The batch dropper fetches the decoder from `hxxps://ns[.]mo7sen[.]dev/EadF.php?p=4` and executes it with `-Mode full`.
6. The decoder reads the machine's `MachineGuid` from `HKLM\SOFTWARE\Microsoft\Cryptography` and requests the encrypted bundle (`p=3&m=<machine-guid>`).
7. The server returns custom HTTP headers `X-Lab-Half` and `X-Lab-Salt` as key material.
8. **Key derivation**: SHA-256 of MachineGuid, XOR with decoded `X-Lab-Half`, append MachineGuid bytes, then **PBKDF2-HMAC-SHA256** (salt from `X-Lab-Salt`, 4,096 iterations) producing a 32-byte key.
9. **Decryption**: AES-256-CBC with PKCS7 padding (IV = first 16 bytes of body), then GZip decompression, yielding a ZIP extracted to `%TEMP%\SCKitBundle`.
10. The hidden-relaunch branch uses a VBScript wrapper via `wscript.exe` for stealth.

**Stage0Loader** (`p=1`) follows the same pattern but uses a hard-coded salt instead of the `X-Lab-Salt` header. The decrypted script is written to `%TEMP%\k<32-hex>.ps1` (GUID-named), executed in a hidden PowerShell process, then deleted.

**Server request selectors** (all via `ns[.]mo7sen[.]dev/EadF.php`):

| Parameter | Component |
|-----------|-----------|
| `p=1&m=<guid>` | Encrypted PowerShell loader |
| `p=3&m=<guid>` | Encrypted toolkit bundle |
| `p=4` | Decoder script |
| `p=5` | SQLite utility (for cookie DB access) |
| `p=6&m=<guid>` | Cleanup component (Stop-LabTrap.ps1) |

#### Phase 3: Persistence and Rogue Access

11. `SilentForceInstall-WithUninstall.ps1` installs **two rogue ScreenConnect Access clients** connecting to attacker-controlled servers (`sc[.]payproofkit[.]com` and `cdn007-digitaldownloads[.]com`).
12. Defender exclusions added via registry for staged MSI paths and `CWInstall_...\Installer.ps1`.
13. SRP/AppLocker rules block files pushed through ScreenConnect temp folders from running (`install.ps1`).
14. **Scheduled task** `TrapWatch` created, running as SYSTEM, polling every 10 seconds.
15. **Registry Run key** `RelayTrapLiteAlert` set in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.
16. Toolkit staged to `C:\ProgramData\RelayTrap\` with per-client `trapbins` subdirectories.

**Wave 2 persistence**: A rogue service named **"Windows Update Agent"** ran `UpdateConnect.ClientService.exe` from `C:\ProgramData\Windows Update Agent (de362a425905bcc4)\` under LocalSystem. Port proxy via `netsh interface portproxy` mapped `127.0.0.1:88` to `185[.]241[.]211[.]197:80`. The hosts file was also modified.

#### Phase 4: RelayTrap (Technician Targeting via CVE-2026-84869)

17. `TrapWatch.ps1` enumerates ScreenConnect client services and reads their executable paths and connection parameters.
18. For each client, TrapWatch copies the client's libraries and **compiles `RelayTrap.exe` on-host** using the .NET C# compiler against local ScreenConnect assemblies. It rebuilds when the source or libraries change.
19. TrapWatch stops the legitimate Guest service, changes its startup type to manual, and positions RelayTrap to take its place, reusing the original connection parameters.
20. When a technician connects with a **vulnerable Host client** (< 26.6.5), RelayTrap sends a `TransferFilesMessage` with `FileAction.Run` and `canBeElevated` set, attempting to deliver the batch launcher to the technician's workstation.
21. A 2.5-second delay follows the Host being marked as a target. The trap does **not check Host version** before sending.

**Skip lists**: The toolkit excludes specified client IDs (`2588ef5c15954b10`, `ed630cc2c873b091`), relay hosts, and machine names (`desktop-vmc0ifs`, `send`, `sc-observation-lab`).

#### Phase 5: Session Theft and Console Distribution (Conditional)

If execution is achieved on a technician's workstation:

22. `Panel-Lateral.ps1` searches Chrome, Edge, Opera, and Opera GX browser profiles for `.ASPXAUTH` cookies. Uses Volume Shadow Copy fallback for locked databases.
23. Cookie values decrypted using Chromium master key with DPAPI, plus AES-GCM for v10/v11 cookie values.
24. Embedded C# scanner targets `network.mojom.NetworkService` browser processes using `OpenProcess`, `VirtualQueryEx`, and `ReadProcessMemory` to extract cookies from memory (falls back to other browser processes).
25. Stolen auth cookies combined with anti-forgery and access tokens, used against `PageService.ashx` endpoints (`GetAccessToken`, `GetLiveData`, `AddSessionEvents`) to enumerate accessible sessions.
26. `ToolboxRelayUploader.exe` uploads payload via **Shared Toolbox**, queues execution across reachable sessions, then removes the uploaded item ~60 seconds later.
27. Commands run through existing agents as **NT AUTHORITY\SYSTEM** on target endpoints, requiring no separate execution method.

**Important**: Huntress states the console-takeover attempt **failed in every recovered host log** it examined. Blackpoint also found a delimiter bug in the cookie parsing code that causes `.ASPXAUTH` rows to be discarded before decryption, making browser-memory recovery the more plausible (but still unconfirmed) route.

#### Phase 6: Cleanup and Re-arm

28. `Stop-LabTrap.ps1` (via `p=6`) writes a stop marker, removes tasks/services/processes/Run entries/files, and restores ScreenConnect services.
29. The decoder's cleanup mode then re-runs the dropper unless `-NoReArm` is set, providing automatic persistence rearming.

### Code Characteristics

Huntress noted the recovered RelayTrap source contains **extensive comments** describing functionality, compatibility workarounds, and earlier coding errors, and "appears to have been generated with a large language model." The code includes operator-safety functions (e.g., `Test-LabOnlyOwnClients`, always returns false in this build) and configuration flags (`LabTrapMonitorOnly`, `PanelSessionWaitSec`, `HostSessionWaitSec`).

## Indicators of Compromise (IOCs)

> **Defanging Convention:** Domains and IPs use `[.]` notation; URLs use `hxxps://` or `hxxp://`; hashes, file paths, and filenames are not defanged. File hashes are weak indicators per Huntress, as scripts are rebuilt with different embedded values and RelayTrap.exe is compiled per-host.

### Network Infrastructure

| Indicator | Type | Role |
|-----------|------|------|
| ns[.]mo7sen[.]dev | Domain | Primary staging: decoder, bundle, scripts, SQLite, cleanup |
| sc[.]payproofkit[.]com | Domain | Attacker ScreenConnect panel and installer source |
| cdn007-digitaldownloads[.]com | Domain | Campaign infrastructure, installer source |
| newnewnew[.]gotdns[.]org | Domain | Attacker ScreenConnect relay (resolves to 185[.]99[.]255[.]28) |
| soxnewwork[.]homedns[.]org | Domain | Attacker relay on port 81 (client ed630cc2c873b091) |
| 007[.]from-ak[.]com | Domain | Wave 2 attacker relay (port 88) |
| 185[.]99[.]255[.]28 | IPv4 | Rogue ScreenConnect server and installer source |
| 155[.]94[.]150[.]39 | IPv4 | sc[.]payproofkit[.]com panel (hostname: WIN-FB5CKHMU4E1) |
| 185[.]241[.]211[.]197 | IPv4 | Wave 2 infrastructure (1337 Services GmbH) |

### URL Patterns

| URL Pattern | Purpose |
|-------------|---------|
| `hxxps://ns[.]mo7sen[.]dev/EadF.php?p=4` | Decoder retrieval |
| `hxxps://ns[.]mo7sen[.]dev/EadF.php?p=3&m=<guid>` | Encrypted bundle |
| `hxxps://ns[.]mo7sen[.]dev/EadF.php?p=1&m=<guid>` | Stage0 loader |
| `hxxps://ns[.]mo7sen[.]dev/EadF.php?p=5` | SQLite utility |
| `hxxps://ns[.]mo7sen[.]dev/EadF.php?p=6&m=<guid>` | Cleanup script |
| `/Bin/ScreenConnect.ClientSetup.msi?...&c=Exploited<N>` | Wave 1 installer pattern |
| `/Bin/UpdateConnect.ClientSetup.msi?...&c=ExploitedNOTUSA` | Wave 2 installer pattern |

### File Hashes (SHA-256)

| File | SHA-256 |
|------|---------|
| sc.msi (rogue installer) | `61a672a13f03a9e81f573535ee92b1ed6cb7e848a33a06048865312d4e185ae2` |
| Toolkit bundle (ZIP) | `8e6912deed82e80bb6bd66f73509d024b1f78b993515366d8317e69a97cff4f4` |
| ToolboxRelayUploader.exe | `8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af` |
| Panel-Lateral-free.ps1 | `94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11` |
| Panel-Lateral.ps1 | `7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec` |
| LabConfig.ps1 | `b93f10f30ee453d1e1c046fec9d141c41d7680be5cd46c3aeb3febe0f4953b4d` |
| RelayTrap.cs | `3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4` |
| TrapWatch.ps1 | `d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a` |
| install.ps1 | `4a1dd3cd2ea14368afadf7e9dfdd63b104e3981ef8c85bbb6510919b810af04b` |
| Lite-Alert.ps1 | `cf50d73fa8117a758093b1344de41cd6a6ccddc645cdda1fa91a9264efe93956` |
| Stage0Loader.ps1 | `81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781` |
| SilentForceInstall-WithUninstall.ps1 | `a1937467fd862916f89342cdd61f55c4bc405fb35b6e1379e27cfbfdba77dcdc` |
| sckit-decoder.ps1 | `338e37f58043635ebab64ee5fdc919935e55cb146ca97834b358f934e55e88ec` |
| ScreenConnect.ClientSetup.msi (cdn007) | `d85315bd7602b6f5c13dc0eada2c9cba0892c7cd3b1eb7dacb1bffdd536ceb21` |
| Run-Lateral-Full.bat | `43b7a5e56f9e6c7b74e1ce2b7b5af63f383084625fcc2d3a5985fa1059e2db95` |
| runnew.cmd | `50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61` |
| Stop-LabTrap.bat | `5dd3a6ba806ac472663e243cfc1c034c534d5d9a42ec362c3dbf0f8d950148d0` |
| TRAP-PROOF.bat | `454c43d296b1276bde9a4f6ff1da2221cb35ccdb2fc7991bdd572e45bce12a8a` |
| Release-Machine.cmd | `c31e6f075cd77e01839aebce32ed35659a9ee962d102aca53040bb5e297410a9` |
| Recover-ExecutionPolicy.cmd | `deda7c30d798a19b6699a45fbcba503cf778594df9163c61c2f96bb2d2b9fb45` |
| Lab-context.json | `0bd84c776dc01f784a617e73fc77b269f847fc4a062ffd489e4692869724bf08` |

### File Hashes (SHA-1)

| File | SHA-1 |
|------|-------|
| sc.msi | `0be01e7bd69cfdd222645d49bb5ad9961372fef2` |
| Toolkit bundle (ZIP) | `3f81c9c874a896c46e4bccea2fad2eaa3d9f2054` |
| ToolboxRelayUploader.exe | `13ce33b19daee3963f7e15d461b191c38f6bc0d3` |

### File Paths and Names

| Path | Description |
|------|-------------|
| `C:\Windows\Temp\sc.msi` | Rogue MSI installer |
| `C:\Windows\Temp\sckit-run.bat` | Initial batch dropper |
| `C:\Windows\Temp\sckit-decoder.ps1` | Decoder script |
| `C:\Windows\Temp\sckit-loader.ps1` | Loader script (Wave 2) |
| `%TEMP%\SCKitBundle\` | Extracted toolkit |
| `%TEMP%\SCKit\trapkit\payload\` | Staged payload components |
| `%TEMP%\k<32-hex>.ps1` | GUID-named PowerShell loader (regex: `k[0-9a-f]{32}\.ps1`) |
| `C:\ProgramData\RelayTrap\` | Main toolkit directory |
| `C:\ProgramData\RelayTrap\trapbins\<client-id>\RelayTrap.exe` | Compiled trap binary |
| `C:\ProgramData\Windows Update Agent (de362a425905bcc4)\` | Wave 2 rogue service |
| `CWInstall_<8-hex>-c1\Installer.ps1` | Defender exclusion installer |
| `%PUBLIC%\RELAY-TRAP-PROOF.txt` | Proof artifact |

### Registry and Scheduled Tasks

| Indicator | Type | Description |
|-----------|------|-------------|
| `HKLM\...\CurrentVersion\Run\RelayTrapLiteAlert` | Run Key | Persistence via alert script at logon |
| `Windows Defender\Exclusions\Paths` entries for RelayTrap, CWInstall_, ConnectWiseControl_ | Defender Exclusion | Defense evasion |
| Scheduled task `TrapWatch` (SYSTEM, 10-second poll) | Scheduled Task | Trap activation and monitoring |
| Service `Windows Update Agent` (rogue) | Service | Wave 2 persistence |
| `HKLM\SOFTWARE\Microsoft\Cryptography` MachineGuid read | Registry Read | Key derivation input |

### Custom HTTP Headers

| Header | Context |
|--------|---------|
| `X-Lab-Half` | Key material returned by staging server for bundle decryption |
| `X-Lab-Salt` | Salt for PBKDF2 key derivation in decoder stage |

### Rogue Client Identifiers

| Indicator | Type |
|-----------|------|
| `2588ef5c15954b10` | Attacker ScreenConnect client ID |
| `ed630cc2c873b091` | Attacker ScreenConnect client ID |
| `Addmin` | Attacker participant name in installer URLs |
| `Exploited<N>` / `ExploitedNOTUSA` | Campaign counter in installer `c=` parameter |

### Microsoft Defender Detections

- Trojan:Win32/SuspScreenConnectDownload.EA
- Trojan:Win32/Tikise.EA!cmd
- Trojan:PowerShell/RelayPersist.FC!MTB
- Trojan:PowerShell/SCRelayTrap.EC!MTB
- HackTool:Win32/ToolboxRelayUploader
- Trojan:BAT/Tikise.A through D
- Trojan:PowerShell/Tikise.A through F

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | RMM+ extension blank access key abuse for initial access |
| T1219 | Remote Access Software | Rogue ScreenConnect Access clients for persistent access |
| T1072 | Software Deployment Tools | ScreenConnect Run Command and Shared Toolbox for distribution |
| T1651 | Cloud Administration Command | Run Command on cloud-hosted ScreenConnect panels |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Decoder, loader, installer, TrapWatch, Panel-Lateral scripts |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | sckit-run.bat, runnew.cmd, Run-Lateral-Full.bat |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | VBScript wrapper for hidden relaunch |
| T1105 | Ingress Tool Transfer | curl.exe downloads MSI, decoder, scripts, sqlite3 |
| T1027 | Obfuscated Files or Information | Encrypted bundle and scripts (AES-256-CBC + GZip) |
| T1140 | Deobfuscate/Decode Files or Information | Base64 decode, PBKDF2 key derivation, AES decryption |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | RelayTrapLiteAlert Run key |
| T1053.005 | Scheduled Task/Job: Scheduled Task | TrapWatch task (SYSTEM, 10-second poll) |
| T1543.003 | Create or Modify System Process: Windows Service | "Windows Update Agent" rogue service (Wave 2) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defender path exclusions, SRP/AppLocker modifications |
| T1036.005 | Masquerading: Match Legitimate Name or Location | "Windows Update Agent" service name |
| T1203 | Exploitation for Client Execution | CVE-2026-84869 Guest-to-Host file execution |
| T1539 | Steal Web Session Cookie | .ASPXAUTH cookie theft from browser databases |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chromium/Firefox cookie decryption via DPAPI |
| T1550.004 | Use Alternate Authentication Material: Web Session Cookie | Replayed cookies against ScreenConnect panels |
| T1570 | Lateral Tool Transfer | Payload distribution via Shared Toolbox |
| T1090.001 | Proxy: Internal Proxy | netsh portproxy relay (Wave 2) |
| T1565.001 | Stored Data Manipulation | Hosts file modification (Wave 2) |
| T1489 | Service Stop | Stopping legitimate ScreenConnect Guest service |
| T1070.004 | Indicator Removal: File Deletion | Toolbox item removed ~60s after broadcast; temp file cleanup |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 and relay communications |

## Impact Assessment

The SCKit campaign represents a significant escalation in MSP-targeted attacks. Its worm-like architecture -- combining an RMM extension authentication bypass, rogue client deployment, a client-side RCE exploit, browser session theft, and legitimate platform features for distribution -- creates a multi-stage supply chain attack that could cascade from a single compromised MSP panel to thousands of downstream customer endpoints.

Key risk factors:

1. **MSP amplification**: Each compromised technician session potentially exposes every organization that technician manages.
2. **Trust inversion**: The campaign reverses the normal Host-to-Guest trust direction, exploiting the implicit trust MSPs place in their managed endpoints.
3. **Stealth**: The compiled RelayTrap binary reuses legitimate ScreenConnect libraries and connection parameters, making the compromised endpoint appear normal during remote support sessions.
4. **Automated propagation**: The 90-minute compromise window for 288 endpoints demonstrates highly automated tooling.
5. **Incomplete mitigation**: Removing the rogue client does not remove persistence. Isolation does not prevent reinfection after restoration. The cleanup/re-arm mechanism can automatically reinstall persistence.

**Mitigating factors**: CVE-2026-84869 is patched in 26.6.5+. The technician-pivot component has not been confirmed to succeed in the wild. Cookie-parsing bugs in the code reduce the effectiveness of browser DB theft.

## Detection and Remediation

### Immediate Detection Checks

Check for RelayTrap persistence:
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v RelayTrapLiteAlert
schtasks /query /tn "TrapWatch"
dir "C:\ProgramData\RelayTrap" /s
```

Check for rogue ScreenConnect clients:
```cmd
sc query | findstr /i "ScreenConnect"
sc query "Windows Update Agent"
```

Check for staging artifacts:
```cmd
dir C:\Windows\Temp\sc.msi C:\Windows\Temp\sckit-*.* 2>nul
dir %TEMP%\SCKit* /s 2>nul
```

Check Defender exclusions and port proxy:
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" 2>nul | findstr /i "RelayTrap CWInstall"
netsh interface portproxy show v4tov4
```

### Remediation Steps

1. **Do NOT triage over ScreenConnect.** Use WinRM, PowerShell remoting, or another out-of-band tool. If a technician already connected to a suspect host, treat that workstation as potentially exposed.
2. **Patch and disable**: Upgrade ScreenConnect clients to 26.6.5+ immediately. Disable RMM+ and the other listed extensions. If RMM+ must remain, set a strong `RMMPlus.AccessKey`.
3. **Audit panels**: Review Run Command and Shared Toolbox history for mass or unrecognized actions. Check for `c=Exploited` patterns in command logs.
4. **Isolate, then remediate**: Isolation does not remove persistence and reinfection has been observed after isolation was lifted. Remove the TrapWatch scheduled task, "Windows Update Agent" service, `C:\ProgramData\RelayTrap\` directory, `%TEMP%\SCKit*` files, the `RelayTrapLiteAlert` Run key, and all rogue ScreenConnect services.
5. **Clear defense evasion**: Remove SRP/AppLocker rules and Defender exclusions added by the kit. Clear netsh portproxy rules. Restore the hosts file.
6. **Revoke sessions**: From a **clean device**, terminate all active ScreenConnect web sessions, rotate ScreenConnect credentials, and revoke browser and identity-provider sessions.
7. **Hunt**: Block the listed domains and IPs. Search for the SHA-256 hashes. Connect ScreenConnect as a SIEM data source and run the detection rules below.
8. **Do not return hosts to service** until the rogue client, persistence, and defense-evasion artifacts are fully removed and reinfection is ruled out.

### Microsoft Defender XDR Advanced Hunting

Microsoft's blog provides KQL queries for:
- `DeviceNetworkEvents` for the listed domains and IPs
- `DeviceProcessEvents` for `/EadF.php`, `SCKit`, `RelayTrap`, `Panel-Lateral`, `ToolboxRelayUploader`, `.ASPXAUTH`, `c=Exploited`
- `DeviceFileEvents` for the SHA-1 hashes
- `DeviceRegistryEvents` for `RelayTrapLiteAlert`, Defender `Exclusions\Paths` writes
- `DeviceEvents` with `ScheduledTask` action types referencing RelayTrap or TrapWatch
- `DeviceFileEvents` (30-day lookback) for regex `k[0-9a-f]{32}.ps1`

## Detection Rules

37 detection rules: ten Sigma rules cover the endpoint behavioral chain (C2 DNS queries, C2 IP connections, rogue MSI installation, command-line artifacts, registry persistence, Defender exclusions, scheduled task creation, file system artifacts, session cookie theft, and port proxy relay). Four YARA rules target the RelayTrap source/binary, Panel-Lateral session theft scripts, the decoder/loader scripts, and the ToolboxRelayUploader binary. Eleven Snort rules and twelve Suricata rules cover DNS queries to all C2 domains, TCP connections to C2 IPs, HTTP URI patterns for the staging endpoint, HTTP response headers for the custom key exchange, and TLS SNI for C2 domains.

<!-- Validation audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); sigma convert --without-pipeline -t splunk passed for all 10 rules; sigma convert --without-pipeline -t log_scale passed for all 10 rules; yarac compiled all 4 YARA rules on first attempt; Snort/Suricata: structural review only (not installed). DNS label-length bytes in Snort rules were hand-counted and peer-reviewed but not machine-validated. All encoding follows logsource-encoding.md: values are real (not defanged), field names match Sysmon/Windows schema. -->

### Sigma Rules

#### 1. DNS Query to SCKit Campaign Infrastructure

Detects DNS queries to the six domains associated with the SCKit campaign: staging, panels, installer sources, and relay infrastructure.
**Compile: Splunk pass, LogScale pass | Confidence: high**

```yaml
title: DNS Query to SCKit Campaign Infrastructure
id: c7b3a1f2-9e4d-4a81-b5c6-3d8f2e7a9b01
status: experimental
description: >
    Detects DNS queries to domains associated with the November 2026 SCKit
    malware campaign targeting ScreenConnect MSP environments, including the
    staging server ns.mo7sen.dev, attacker panels, and relay infrastructure.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
    - https://blackpointcyber.com/blog/screenconnect-attack-sckit/
author: Actioner
date: 2026/11/14
tags:
    - attack.t1071.004
    - attack.t1105
    - cve.2026.84869
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'ns.mo7sen.dev'
            - 'payproofkit.com'
            - 'cdn007-digitaldownloads.com'
            - 'newnewnew.gotdns.org'
            - 'soxnewwork.homedns.org'
            - '007.from-ak.com'
    condition: selection
falsepositives:
    - Unknown
level: critical
```

#### 2. Network Connection to SCKit Campaign C2 IP Addresses

Detects outbound connections to the three known campaign IP addresses.
**Compile: Splunk pass, LogScale pass | Confidence: high**

```yaml
title: Network Connection to SCKit Campaign C2 IP Addresses
id: c7b3a1f2-9e4d-4a81-b5c6-3d8f2e7a9b02
status: experimental
description: >
    Detects outbound network connections to IP addresses associated with the
    November 2026 SCKit malware campaign infrastructure, including the rogue
    ScreenConnect server and relay endpoints.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner
date: 2026/11/14
tags:
    - attack.t1071.001
    - attack.t1219
    - cve.2026.84869
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '185.99.255.28'
            - '155.94.150.39'
            - '185.241.211.197'
    condition: selection
falsepositives:
    - Shared hosting environments may cause false positives
level: high
```

#### 3. SCKit Rogue ScreenConnect MSI Installation via Command Line

Detects the curl download pattern with `c=Exploited` marker or silent msiexec installation of sc.msi from Windows Temp.
**Compile: Splunk pass, LogScale pass | Confidence: high**

```yaml
title: SCKit Rogue ScreenConnect MSI Installation via Command Line
id: c7b3a1f2-9e4d-4a81-b5c6-3d8f2e7a9b03
status: experimental
description: >
    Detects the SCKit malware installation pattern where cmd.exe or
    powershell.exe uses curl to download a ScreenConnect MSI installer
    to Windows Temp and installs it silently with msiexec. The campaign
    uses the marker parameter c=Exploited in the installer URL.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner
date: 2026/11/14
tags:
    - attack.t1219
    - attack.t1059.003
    - attack.t1105
    - cve.2026.84869
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl_msi:
        Image|endswith: '\curl.exe'
        CommandLine|contains:
            - 'ClientSetup.msi'
            - 'sc.msi'
    selection_curl_exploited:
        Image|endswith: '\curl.exe'
        CommandLine|contains: 'c=Exploited'
    selection_msi_silent:
        Image|endswith: '\msiexec.exe'
        CommandLine|contains|all:
            - '\Windows\Temp\sc.msi'
            - '/qn'
    condition: (selection_curl_msi and selection_curl_exploited) or selection_msi_silent
falsepositives:
    - Legitimate silent MSI installations of ScreenConnect to Windows Temp directory
level: high
```

#### 4. SCKit Malware Command Line Artifacts

Detects command-line references to SCKit-specific component names, staging endpoints, and toolkit filenames.
**Compile: Splunk pass, LogScale pass | Confidence: critical**

```yaml
title: SCKit Malware Command Line Artifacts
id: c7b3a1f2-9e4d-4a81-b5c6-3d8f2e7a9b04
status: experimental
description: >
    Detects command line patterns specific to the SCKit malware toolkit,
    including references to SCKit component names, the EadF.php staging
    endpoint, RelayTrap components, Panel-Lateral scripts, and
    ToolboxRelayUploader used in the November 2026 campaign.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
    - https://blackpointcyber.com/blog/screenconnect-attack-sckit/
author: Actioner
date: 2026/11/14
tags:
    - attack.t1059.001
    - attack.t1059.003
    - cve.2026.84869
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'EadF.php'
            - 'SCKitBundle'
            - 'SCKit'
            - 'RelayTrap'
            - 'Panel-Lateral'
            - 'ToolboxRelayUploader'
            - 'TrapWatch'
            - 'sckit-decoder'
            - 'sckit-run'
            - 'sckit-loader'
            - 'Run-Lateral-Full'
            - 'Stop-LabTrap'
            - 'Lite-Alert'
            - 'c=Exploited'
    filter_legit:
        Image|endswith: '\code.exe'
    condition: selection and not filter_legit
falsepositives:
    - Security researchers analyzing SCKit samples
    - Software with coincidental naming (low probability for most strings)
level: critical
```

#### 5. SCKit RelayTrap Registry Persistence

Detects creation of the RelayTrapLiteAlert Run key or Run key values containing RelayTrap paths.
**Compile: Splunk pass, LogScale pass | Confidence: critical**

```yaml
title: SCKit RelayTrap Registry Persistence
id: c7b3a1f2-9e4d-4a81-b5c6-3d8f2e7a9b05
status: experimental
description: >
    Detects creation of the RelayTrapLiteAlert registry Run key used by
    the SCKit malware for persistence, or registry modifications referencing
    the RelayTrap path. This is a high-fidelity indicator of SCKit infection.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner
date: 2026/11/14
tags:
    - attack.t1547.001
    - cve.2026.84869
logsource:
    category: registry_set
    product: windows
detection:
    selection_runkey:
        TargetObject|endswith: '\CurrentVersion\Run\RelayTrapLiteAlert'
    selection_relaytrap_value:
        TargetObject|contains: '\CurrentVersion\Run\'
        Details|contains: 'RelayTrap'
    condition: selection_runkey or selection_relaytrap_value
falsepositives:
    - Unknown
level: critical
```

#### 6. SCKit Defender Exclusion Path Modifications

Detects Defender exclusion registry writes matching SCKit-associated paths. `ConnectWiseControl_` excluded (fires on every legitimate ScreenConnect installation).
**Compile: Splunk pass, LogScale pass | Confidence: medium**

```yaml
title: SCKit Defender Exclusion Path Modifications
id: c7b3a1f2-9e4d-4a81-b5c6-3d8f2e7a9b06
status: experimental
description: >
    Detects Windows Defender exclusion path registry modifications matching
    patterns used by the SCKit malware campaign, including exclusions for
    RelayTrap directories, ConnectWise installer paths, and Windows Temp
    folders used for staging.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://blackpointcyber.com/blog/screenconnect-attack-sckit/
author: Actioner
date: 2026/11/14
tags:
    - attack.t1562.001
    - cve.2026.84869
logsource:
    category: registry_set
    product: windows
detection:
    selection_defender_path:
        TargetObject|contains: '\Windows Defender\Exclusions\Paths'
    selection_sckit_values:
        TargetObject|contains:
            - 'RelayTrap'
            - 'CWInstall_'
    condition: selection_defender_path and selection_sckit_values
falsepositives:
    - Legitimate ConnectWise installations that add Defender exclusions for CWInstall_ paths during setup
level: medium
```

#### 7. SCKit TrapWatch Scheduled Task Creation

Detects schtasks.exe creating tasks referencing TrapWatch or RelayTrap.
**Compile: Splunk pass, LogScale pass | Confidence: critical**

```yaml
title: SCKit TrapWatch Scheduled Task Creation
id: c7b3a1f2-9e4d-4a81-b5c6-3d8f2e7a9b07
status: experimental
description: >
    Detects creation of scheduled tasks referencing TrapWatch or RelayTrap,
    which are used by the SCKit malware for persistence and monitoring of
    ScreenConnect client services.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner
date: 2026/11/14
tags:
    - attack.t1053.005
    - cve.2026.84869
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - 'TrapWatch'
            - 'RelayTrap'
    condition: selection_schtasks
falsepositives:
    - Unknown
level: critical
```

#### 8. SCKit Malware File System Artifacts

Detects file creation in RelayTrap directories, SCKit staging paths, and the characteristic hex-named PowerShell loader files.
**Compile: Splunk pass, LogScale pass | Confidence: critical**

```yaml
title: SCKit Malware File System Artifacts
id: c7b3a1f2-9e4d-4a81-b5c6-3d8f2e7a9b08
status: experimental
description: >
    Detects file creation events matching SCKit malware staging paths,
    including the RelayTrap directory in ProgramData, SCKitBundle in Temp,
    and the characteristic hex-named PowerShell loader files.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner
date: 2026/11/14
tags:
    - attack.t1105
    - attack.t1027
    - cve.2026.84869
logsource:
    category: file_event
    product: windows
detection:
    selection_relaytrap_dir:
        TargetFilename|contains: '\ProgramData\RelayTrap\'
    selection_sckit_temp:
        TargetFilename|contains:
            - '\SCKitBundle'
            - '\SCKit\trapkit\'
            - '\sckit-decoder.ps1'
            - '\sckit-run.bat'
            - '\sckit-loader.ps1'
    selection_hex_loader:
        TargetFilename|re: '\\Temp\\k[0-9a-f]{32}\.ps1$'
    condition: selection_relaytrap_dir or selection_sckit_temp or selection_hex_loader
falsepositives:
    - Unknown
level: critical
```

#### 9. SCKit Browser Cookie Database Access for Session Theft

Detects PowerShell processes referencing .ASPXAUTH cookies or Panel-Lateral scripts.
**Compile: Splunk pass, LogScale pass | Confidence: high**

```yaml
title: SCKit Browser Cookie Database Access for Session Theft
id: c7b3a1f2-9e4d-4a81-b5c6-3d8f2e7a9b09
status: experimental
description: >
    Detects PowerShell processes accessing browser cookie databases or
    referencing .ASPXAUTH cookies, consistent with the SCKit malware's
    technician session theft component that targets ScreenConnect
    authentication tokens.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    - https://blackpointcyber.com/blog/screenconnect-attack-sckit/
author: Actioner
date: 2026/11/14
tags:
    - attack.t1539
    - attack.t1555.003
    - cve.2026.84869
logsource:
    category: process_creation
    product: windows
detection:
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_cookie_theft:
        CommandLine|contains:
            - '.ASPXAUTH'
            - 'Panel-Lateral'
            - 'LabConfig.ps1'
    condition: selection_powershell and selection_cookie_theft
falsepositives:
    - Security tools auditing browser sessions
level: high
```

#### 10. SCKit Netsh Port Proxy for C2 Relay

Detects netsh portproxy commands creating the localhost:88 relay used in Wave 2.
**Compile: Splunk pass, LogScale pass | Confidence: medium**

```yaml
title: SCKit Netsh Port Proxy for C2 Relay
id: c7b3a1f2-9e4d-4a81-b5c6-3d8f2e7a9b10
status: experimental
description: >
    Detects netsh interface portproxy commands creating a redirect from
    localhost port 88 to external infrastructure, a technique used by
    SCKit Wave 2 to relay traffic through compromised endpoints.
references:
    - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
author: Actioner
date: 2026/11/14
tags:
    - attack.t1090.001
    - cve.2026.84869
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\netsh.exe'
        CommandLine|contains|all:
            - 'portproxy'
            - '127.0.0.1'
    selection_port:
        CommandLine|contains:
            - 'listenport=88 '
            - 'listenport=88"'
            - 'connectport=88 '
            - 'connectport=88"'
            - '185.241.211.197'
    condition: selection and selection_port
falsepositives:
    - Legitimate port forwarding configurations using port 88
level: medium
```

### YARA Rules

#### 11. SCKit RelayTrap C# Source or Binary

Detects the RelayTrap C# source or compiled binary by its ScreenConnect API references and file-transfer exploitation patterns.
**Compile: yarac pass | Confidence: high**

```yara
rule SCKit_RelayTrap_CSharp_Source
{
    meta:
        description = "Detects the SCKit RelayTrap C# source file or compiled binary that replaces the legitimate ScreenConnect Guest client to intercept technician sessions via CVE-2026-84869"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash = "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $relay_trap = "RelayTrap" ascii wide
        $transfer_files = "TransferFilesMessage" ascii wide
        $file_action_run = "FileAction.Run" ascii wide
        $can_be_elevated = "canBeElevated" ascii wide
        $screenconnect_ns = "ScreenConnect" ascii wide
        $endpoint_status = "EndPointStatusMessage" ascii wide
        $guest_process = "ScreenConnect.WindowsClient" ascii wide
        $trap_watch = "TrapWatch" ascii wide

    condition:
        filesize < 2MB and
        $relay_trap and
        $screenconnect_ns and
        (
            ($transfer_files and $file_action_run) or
            ($can_be_elevated and $endpoint_status) or
            ($guest_process and $trap_watch and 5 of them)
        )
}
```

#### 12. SCKit Panel-Lateral Session Theft Script

Detects the Panel-Lateral PowerShell scripts by their .ASPXAUTH theft patterns, browser memory scanning API calls, and ScreenConnect PageService interaction.
**Compile: yarac pass | Confidence: high**

```yara
rule SCKit_Panel_Lateral_Script
{
    meta:
        description = "Detects the SCKit Panel-Lateral PowerShell scripts used for ScreenConnect session cookie theft and console distribution"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash1 = "94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11"
        hash2 = "7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $aspxauth = ".ASPXAUTH" ascii wide nocase
        $panel_lateral = "Panel-Lateral" ascii wide
        $toolbox_relay = "ToolboxRelayUploader" ascii wide
        $page_service = "PageService.ashx" ascii wide
        $get_access_token = "GetAccessToken" ascii wide
        $get_live_data = "GetLiveData" ascii wide
        $add_session_events = "AddSessionEvents" ascii wide
        $open_process = "OpenProcess" ascii wide
        $read_process_memory = "ReadProcessMemory" ascii wide
        $virtual_query = "VirtualQueryEx" ascii wide
        $network_mojom = "network.mojom.NetworkService" ascii wide
        $shared_toolbox = "SharedToolbox" ascii wide

    condition:
        filesize < 5MB and
        (
            ($aspxauth and $panel_lateral) or
            ($aspxauth and 2 of ($page_service, $get_access_token, $get_live_data, $add_session_events)) or
            ($open_process and $read_process_memory and $virtual_query and $network_mojom) or
            ($shared_toolbox and $toolbox_relay and $aspxauth) or
            5 of them
        )
}
```

#### 13. SCKit Decoder and Stage0 Loader

Detects the decoder and loader scripts by their MachineGuid-based key derivation, custom HTTP headers (X-Lab-Half/X-Lab-Salt), and staging patterns.
**Compile: yarac pass | Confidence: high**

```yara
rule SCKit_Decoder_Loader
{
    meta:
        description = "Detects the SCKit decoder and Stage0 loader PowerShell scripts that use MachineGuid-based key derivation with PBKDF2-HMAC-SHA256 and AES-256-CBC to unpack the toolkit"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash1 = "338e37f58043635ebab64ee5fdc919935e55cb146ca97834b358f934e55e88ec"
        hash2 = "81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $machine_guid = "MachineGuid" ascii wide
        $x_lab_half = "X-Lab-Half" ascii wide
        $x_lab_salt = "X-Lab-Salt" ascii wide
        $pbkdf2 = "PBKDF2" ascii wide nocase
        $aes = "AES" ascii wide
        $sckit_bundle = "SCKitBundle" ascii wide
        $eadf_php = "EadF.php" ascii wide
        $mo7sen = "mo7sen" ascii wide
        $gzip = "GZip" ascii wide nocase
        $mode_full = "-Mode full" ascii wide

    condition:
        filesize < 2MB and
        (
            ($x_lab_half and $x_lab_salt) or
            ($machine_guid and $pbkdf2 and $aes and ($sckit_bundle or $eadf_php)) or
            ($eadf_php and $mo7sen) or
            ($sckit_bundle and ($gzip or $mode_full)) or
            4 of them
        )
}
```

#### 14. SCKit ToolboxRelayUploader Binary

Detects the ToolboxRelayUploader PE binary used for Shared Toolbox distribution.
**Compile: yarac pass | Confidence: high**

```yara
rule SCKit_ToolboxRelayUploader
{
    meta:
        description = "Detects the SCKit ToolboxRelayUploader executable used to distribute payloads through ScreenConnect Shared Toolbox"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash = "8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $toolbox_relay = "ToolboxRelayUploader" ascii wide
        $screenconnect = "ScreenConnect" ascii wide
        $shared_toolbox = "SharedToolbox" ascii wide
        $upload = "Upload" ascii wide
        $relay = "Relay" ascii wide
        $session_events = "SessionEvents" ascii wide

    condition:
        filesize < 10MB and
        uint16(0) == 0x5A4D and
        $toolbox_relay and
        $screenconnect and
        2 of ($shared_toolbox, $upload, $relay, $session_events)
}
```

### Snort Rules

#### 15-25. SCKit Campaign Network Detection (Snort)

Eleven rules covering TCP connections to the three C2 IPs, DNS queries for all six C2 domains (including Wave 2 relay 007.from-ak.com), HTTP URI pattern for the EadF.php staging endpoint, and HTTP response header detection for the custom X-Lab-Half key exchange.
**Compile: structural review (Snort not installed) | Confidence: high (IOC-based)**

```
alert tcp $HOME_NET any -> 185.99.255.28 any (msg:"Actioner - SCKit C2 Connection to 185.99.255.28 (Rogue ScreenConnect Server)"; flow:established, to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created 2026-11-14; sid:2100101; rev:1;)

alert tcp $HOME_NET any -> 155.94.150.39 any (msg:"Actioner - SCKit C2 Connection to 155.94.150.39 (sc.payproofkit.com Panel)"; flow:established, to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created 2026-11-14; sid:2100102; rev:1;)

alert tcp $HOME_NET any -> 185.241.211.197 any (msg:"Actioner - SCKit C2 Connection to 185.241.211.197 (Wave 2 Infrastructure)"; flow:established, to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/sckit-worm-rogue-screenconnect; metadata:author Actioner, created 2026-11-14; sid:2100103; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to SCKit Staging Domain ns.mo7sen.dev"; flow:to_server; content:"|02|ns|06|mo7sen|03|dev|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created 2026-11-14; sid:2100104; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to SCKit Domain payproofkit.com"; flow:to_server; content:"|0b|payproofkit|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created 2026-11-14; sid:2100105; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to SCKit Domain cdn007-digitaldownloads.com"; flow:to_server; content:"|17|cdn007-digitaldownloads|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created 2026-11-14; sid:2100106; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to SCKit Relay Domain newnewnew.gotdns.org"; flow:to_server; content:"|09|newnewnew|06|gotdns|03|org|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created 2026-11-14; sid:2100107; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to SCKit Relay Domain soxnewwork.homedns.org"; flow:to_server; content:"|0a|soxnewwork|07|homedns|03|org|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created 2026-11-14; sid:2100108; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to SCKit Wave 2 Relay Domain 007.from-ak.com"; flow:to_server; content:"|03|007|07|from-ak|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.huntress.com/blog/sckit-worm-rogue-screenconnect; metadata:author Actioner, created 2026-11-14; sid:2100111; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - SCKit HTTP Request to EadF.php Staging Endpoint"; flow:established, to_server; content:"/EadF.php"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created 2026-11-14; sid:2100109; rev:1;)

alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"Actioner - SCKit X-Lab-Half Header in HTTP Response (Key Exchange)"; flow:established, to_client; content:"X-Lab-Half"; http_header; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created 2026-11-14; sid:2100110; rev:1;)
```

### Suricata Rules

#### 26-37. SCKit Campaign Network Detection (Suricata)

Twelve rules covering DNS queries (dns.query sticky buffer) for six C2 domains, TCP connections to three C2 IPs, HTTP URI for the staging endpoint, and TLS SNI for two primary C2 domains.
**Compile: structural review (Suricata not installed) | Confidence: high (IOC-based)**

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to SCKit Staging Domain ns.mo7sen.dev"; flow:to_server; dns.query; content:"ns.mo7sen.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-14; sid:2200101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to SCKit Panel Domain payproofkit.com"; flow:to_server; dns.query; content:"payproofkit.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-14; sid:2200102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to SCKit Domain cdn007-digitaldownloads.com"; flow:to_server; dns.query; content:"cdn007-digitaldownloads.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-14; sid:2200103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to SCKit Relay Domain newnewnew.gotdns.org"; flow:to_server; dns.query; content:"newnewnew.gotdns.org"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-14; sid:2200104; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to SCKit Relay Domain soxnewwork.homedns.org"; flow:to_server; dns.query; content:"soxnewwork.homedns.org"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-14; sid:2200105; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to SCKit Wave 2 Relay Domain 007.from-ak.com"; flow:to_server; dns.query; content:"007.from-ak.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.huntress.com/blog/sckit-worm-rogue-screenconnect; metadata:author Actioner, created_at 2026-11-14; sid:2200106; rev:1;)

alert tcp $HOME_NET any -> 185.99.255.28 any (msg:"Actioner - SCKit C2 Connection to 185.99.255.28 (Rogue ScreenConnect Server)"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-14; sid:2200107; rev:1;)

alert tcp $HOME_NET any -> 155.94.150.39 any (msg:"Actioner - SCKit C2 Connection to 155.94.150.39 (sc.payproofkit.com Panel)"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-14; sid:2200108; rev:1;)

alert tcp $HOME_NET any -> 185.241.211.197 any (msg:"Actioner - SCKit C2 Connection to 185.241.211.197 (Wave 2 Infrastructure)"; flow:established,to_server; classtype:trojan-activity; reference:url,www.huntress.com/blog/sckit-worm-rogue-screenconnect; metadata:author Actioner, created_at 2026-11-14; sid:2200109; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SCKit HTTP Request to EadF.php Staging Endpoint"; flow:established,to_server; http.uri; content:"/EadF.php"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-14; sid:2200110; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS Connection to SCKit Staging Domain ns.mo7sen.dev"; flow:established,to_server; tls.sni; content:"ns.mo7sen.dev"; nocase; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-14; sid:2200111; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS Connection to SCKit Panel Domain payproofkit.com"; flow:established,to_server; tls.sni; content:"payproofkit.com"; nocase; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/; metadata:author Actioner, created_at 2026-11-14; sid:2200112; rev:1;)
```

## Lessons Learned

1. **Third-party extension risk in RMM platforms**: The RMM+ extension's blank default access key demonstrates that third-party integrations can silently bypass the authentication, MFA, and RBAC controls of the platform they extend. RMM vendors should enforce extension security reviews, require non-default credentials, and audit extension API activity separately from user activity.

2. **Trust inversion in remote support architectures**: SCKit inverts the normal technician-to-endpoint trust direction. MSPs must treat connected endpoints as potentially hostile, enforce mutual authentication in remote sessions, and implement client-version gating before allowing technician connections.

3. **Worm-like propagation through legitimate tooling**: By abusing Run Command and Shared Toolbox -- built-in ScreenConnect features -- SCKit spreads without needing separate exploitation or custom lateral-movement tools. The commands execute as SYSTEM through existing agents. Detection must focus on behavioral anomalies (mass commands, unfamiliar scripts, rogue client IDs) rather than just malicious binaries.

4. **LLM-assisted malware development**: Huntress noted the RelayTrap source appears LLM-generated, with extensive comments and debugging notes. This trend lowers the barrier for developing complex exploitation tools but also creates distinctive artifacts (verbose comments, operator-safety functions, configuration flags) that may aid analysis and detection.

## Sources

- [Microsoft Security Blog: SCKit abuses ScreenConnect to deploy remote access and target technician sessions](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/) -- primary technical analysis with comprehensive IOCs, infection chain, and Defender detection names
- [Huntress Blog: SCKit Worm Installs Rogue ScreenConnect Clients and Session Cookie Relays](https://www.huntress.com/blog/sckit-worm-rogue-screenconnect) -- initial discovery, Wave 1/2 timeline, RMM+ analysis, IOCs, and remediation guidance
- [Blackpoint Cyber APG: ScreenConnect Attack - SCKit Turns Remote Support Into an Attack Platform](https://blackpointcyber.com/blog/screenconnect-attack-sckit/) -- toolkit recovery, CVE-2026-84869 exploit analysis, key derivation details, cookie-parsing bug disclosure
- [BleepingComputer: New worm-like SCKit malware targets MSPs in ScreenConnect attacks](https://www.bleepingcomputer.com/news/security/new-worm-like-sckit-malware-targets-msps-in-screenconnect-attacks/) -- summary with ConnectWise response and Huntress quotes
- [The Hacker News: SCKit Malware Targets ScreenConnect](https://thehackernews.com/2026/11/sckit-malware-targets-screenconnect.html) -- summary with CISA KEV and prior exploitation context
- [CyberScoop: ConnectWise ScreenConnect SCKit attack](https://cyberscoop.com/connectwise-screenconnect-sckit-attack/) -- ConnectWise statement and extension disable details
- [ConnectWise Trust Center / Security Bulletins](https://www.connectwise.com/company/trust/security-bulletins) -- vendor advisory and patch information

---
*Report generated by Actioner v1.0 (FINAL)*
