# SCKit Malware -- ScreenConnect MSP Supply Chain Attack (CVE-2026-84869)

**Report Status:** DRAFT
**Date:** 2026-11-13
**Author:** Actioner
**TLP:** CLEAR

---

## Executive Summary

A worm-like malware toolkit dubbed "SCKit" is actively targeting managed service providers (MSPs) through ConnectWise ScreenConnect, a widely deployed remote monitoring and management (RMM) platform. The attack chain exploits an authentication weakness in RMM+ (versions 1.0.31 and 1.0.32), a third-party ScreenConnect extension, combined with CVE-2026-84869 (CVSS 9.9), a critical client-side file-transfer vulnerability in ScreenConnect itself.

First observed on November 11, 2026, the attack compromised at least **288 endpoints across 48 organizations** within a 90-minute window, with one-third of targets hit in the first 10 minutes. The toolkit consists of 16 scripts and components designed to install rogue ScreenConnect clients, replace the legitimate ScreenConnect Guest process with a relay trap, steal technician session cookies, and propagate laterally across MSP customer networks via ScreenConnect's built-in Run Command and Shared Toolbox features.

Reported by Huntress and Blackpoint Cyber's Adversary Pursuit Group. ConnectWise has disabled five potentially related third-party extensions across approximately 400 partner environments. The worm-like technician-to-endpoint propagation has **not been observed to succeed** in recovered host logs, and Blackpoint confirmed the exploit fails against fully patched ScreenConnect clients (26.6.5.9742+).

---

## Background: ScreenConnect and the MSP Ecosystem

ConnectWise ScreenConnect (formerly ConnectWise Control) is a remote support and access platform used by thousands of MSPs to manage client endpoints. The platform supports third-party extensions that enhance functionality, including RMM+ which provides remote command execution capabilities.

The MSP trust model creates a high-value target: a single compromised MSP technician session can reach hundreds of managed client endpoints. ScreenConnect's Run Command feature executes commands as NT AUTHORITY\SYSTEM on managed endpoints, and the Shared Toolbox enables file distribution across all connected sessions. Both features are legitimate administrative capabilities that become powerful lateral movement vectors when abused.

**RMM+ Extension (Third-Party):** RMM+ versions 1.0.31 and 1.0.32 authenticate API requests using a shared access key (`RMMPlus.AccessKey`). This key defaults to blank, and the authentication check accepts an empty value. This effectively bypasses ScreenConnect's native user accounts, role-based access, and multi-factor authentication when no key has been configured. The extension is independently developed and is not maintained by ConnectWise.

---

## Technical Analysis

### CVE-2026-84869 (CVSS 9.9)

**Vulnerability:** Improper privilege management and missing authorization in ConnectWise ScreenConnect. The flaw allows a malicious ScreenConnect Guest (the client-side agent on a managed endpoint) to transfer a file back to the connecting technician (the Host) and execute it without authorization or host confirmation.

- **Affected versions:** ScreenConnect builds prior to 26.6.5.9742
- **Fixed in:** ScreenConnect 26.6.5.9742 (version 26.6.5)
- **CISA KEV:** Added September 11, 2026 (federal patch deadline September 14, 2026)
- **Prior exploitation:** In September 2026, the CVE was used separately to distribute a four-stage VBScript payload deploying an XMRig cryptominer.
- **Exploitation mechanism:** Uses `TransferFilesMessage` with `FileAction.Run` and the `canBeElevated` flag. The RelayTrap component waits approximately 2.5 seconds after a technician connects before initiating the file transfer.

### RMM+ Authentication Bypass

- **Affected versions:** RMM+ 1.0.31 and 1.0.32
- **Mechanism:** The `RMMPlus.AccessKey` (an `IsServerOnly` setting) defaults to blank. The authentication check passes when both the configured key and the supplied key are empty strings.
- **Impact:** Allows unauthenticated command execution against all endpoints managed by the ScreenConnect instance, completely bypassing MFA and RBAC.
- **Evidence:** Huntress observed commands executed across multiple ScreenConnect instances with no matching user login activity; all command activity traced back to RMM+.

### SCKit Propagation Chain

**Phase 1 -- Initial Compromise (RMM+ Abuse)**
1. Attacker accesses cloud-hosted ScreenConnect panels via the RMM+ authentication bypass.
2. ScreenConnect's Run Command feature pushes commands as SYSTEM to groups of managed endpoints.
3. Commands install the attacker-controlled ScreenConnect client (`C:\Windows\Temp\sc.msi`) silently.
4. The Base64-encoded dropper (`sckit-run.bat`) is written to disk and executed.

**Phase 2 -- Kit Deployment (Per-Host Encrypted Delivery)**
5. The dropper downloads the decoder (`sckit-decoder.ps1`) from `hxxps://ns.mo7sen[.]dev/EadF.php?p=4`.
6. The decoder fetches a per-host encrypted SCKit bundle using the machine's UUID as a key identifier (via `EadF.php?p=1`).
7. Key derivation uses PBKDF2-HMAC-SHA256 with custom HTTP headers (`X-Lab-Half`, `X-Lab-Salt`).
8. Decrypted payload uses AES-256-CBC (no MAC) and GZip compression.
9. The temporary script (`k[0-9a-f]{32}.ps1`) extracts the toolkit to `C:\ProgramData\RelayTrap\`.

**Phase 3 -- Persistence and Trap Installation**
10. `install.ps1` establishes persistence:
    - **Scheduled task:** `TrapWatch` (runs as SYSTEM every 10 seconds)
    - **Registry Run key:** `RelayTrapLiteAlert` under `HKLM\...\CurrentVersion\Run`
    - **Defender exclusions:** Added for `powershell.exe`, `msiexec.exe`, and installation paths
    - **SRP/AppLocker rules:** Block files from ScreenConnect temp folders
11. A second rogue ScreenConnect Access client is installed for redundant persistent access.
12. TrapWatch compiles `RelayTrap.exe` on-host from `RelayTrap.cs`, reusing the legitimate client's libraries.
13. TrapWatch stops the legitimate ScreenConnect client service, sets it to manual start, and replaces the connection slot.

**Phase 4 -- Technician Targeting (Worm Component, Not Observed to Succeed)**
14. When a technician connects via ScreenConnect to the trapped endpoint, RelayTrap initiates a file transfer back to the technician's workstation using CVE-2026-84869.
15. `Run-Lateral-Full.bat` is transferred approximately 2.5 seconds after connection.
16. On the technician workstation, `Panel-Lateral.ps1` steals `.ASPXAUTH` session cookies from browsers (using DPAPI and AES-GCM decryption with `sqlite3.exe` for cookie database access).
17. Stolen cookies are replayed against ScreenConnect panel endpoints (`PageService.ashx`) to invoke `GetAccessToken`, `GetLiveData`, `AddSessionEvents`, and `QueuedCommand`.
18. `ToolboxRelayUploader.exe` uploads `SilentForceInstall-WithUninstall.ps1` to the Shared Toolbox, broadcasting it to all reachable sessions, then deletes it approximately 60 seconds later.

**Critical note:** Huntress and Blackpoint have **not observed** the technician-side worm propagation succeeding. Blackpoint confirmed the exploit fails against patched ScreenConnect clients. No evidence of patch bypass exists as of this report.

### SCKit Toolkit Components (16 Files)

| # | File | Description | SHA-256 |
|---|------|-------------|---------|
| 1 | Panel-Lateral-free.ps1 | Worm installer (config-free variant) | `94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11` |
| 2 | Panel-Lateral.ps1 | Steals technician SC login cookies, pushes to reachable sessions | `7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec` |
| 3 | LabConfig.ps1 | Helper library: cookie decryption, panel probing, installer URL generation | `b93f10f30ee453d1e1c046fec9d141c41d7680be5cd46c3aeb3febe0f4953b4d` |
| 4 | RelayTrap.cs | Trap source; reuses real client libraries and connection details | `3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4` |
| 5 | TrapWatch.ps1 | Runs as SYSTEM every 10s; stops legitimate clients, takes connection slot | `d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a` |
| 6 | install.ps1 | Sets up trap, TrapWatch task, Run key, SRP/AppLocker, Defender exclusions | `4a1dd3cd2ea14368afadf7e9dfdd63b104e3981ef8c85bbb6510919b810af04b` |
| 7 | ToolboxRelayUploader.exe | 32-bit .NET PE; uploads to Shared Toolbox using stolen token | `8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af` |
| 8 | Lite-Alert.ps1 | Logs file-run events and new SC services at logon | `cf50d73fa8117a758093b1344de41cd6a6ccddc645cdda1fa91a9264efe93956` |
| 9 | Stage0Loader.ps1 | Fetches EadF.php?p=1, decrypts with fixed salt, runs and deletes | `81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781` |
| 10 | Release-Machine.cmd | Removes trap using built-in tools | `c31e6f075cd77e01839aebce32ed35659a9ee962d102aca53040bb5e297410a9` |
| 11 | Recover-ExecutionPolicy.cmd | Removes SRP/AppLocker rules and stops AppLocker service | `deda7c30d798a19b6699a45fbcba503cf778594df9163c61c2f96bb2d2b9fb45` |
| 12 | lab-context.json | Config: attacker panel, RSA key, rogue client IDs | `0bd84c776dc01f784a617e73fc77b269f847fc4a062ffd489e4692869724bf08` |
| 13 | TRAP-PROOF.bat | Writes RELAY-TRAP-PROOF.txt and opens Notepad (demo payload) | `454c43d296b1276bde9a4f6ff1da2221cb35ccdb2fc7991bdd572e45bce12a8a` |
| 14 | Stop-LabTrap.bat | Runs decoder in cleanup mode | `5dd3a6ba806ac472663e243cfc1c034c534d5d9a42ec362c3dbf0f8d950148d0` |
| 15 | Run-Lateral-Full.bat | Dropper; downloads decoder, runs in full mode | `43b7a5e56f9e6c7b74e1ce2b7b5af63f383084625fcc2d3a5985fa1059e2db95` |
| 16 | runnew.cmd | Downloads loader via curl.exe; pushed to all targets | `50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61` |

**Additional Artifacts (not part of the 16-file kit):**

| File | SHA-256 |
|------|---------|
| SilentForceInstall-WithUninstall.ps1 | `a1937467fd862916f89342cdd61f55c4bc405fb35b6e1379e27cfbfdba77dcdc` |
| p=4 decoder payload | `338e37f58043635ebab64ee5fdc919935e55cb146ca97834b358f934e55e88ec` |
| p=3 decoded bundle | `8e6912deed82e80bb6bd66f73509d024b1f78b993515366d8317e69a97cff4f4` |
| ScreenConnect.ClientSetup.msi (rogue) | `d85315bd7602b6f5c13dc0eada2c9cba0892c7cd3b1eb7dacb1bffdd536ceb21` |

**Note:** Huntress warns that file hashes are weak indicators for SCKit because scripts are rebuilt with per-host embedded values and the RelayTrap binary is compiled individually on each endpoint.

---

## Indicators of Compromise

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `185.99.255[.]28` | IP Address | Attacker ScreenConnect server |
| `155.94.150[.]39` | IP Address | Attacker panel (`sc.payproofkit[.]com`) |
| `ns.mo7sen[.]dev` | Domain | Staging/bootstrap server (EadF.php) |
| `sc.payproofkit[.]com` | Domain | Attacker-controlled ScreenConnect panel |
| `cdn007-digitaldownloads[.]com` | Domain | C2 domain (identified by Blackpoint) |
| `soxnewwork.homedns[.]org` | Domain | Attacker relay (port 81) |
| `newnewnew.gotdns[.]org` | Domain | Attacker relay |
| `hxxps://ns.mo7sen[.]dev/EadF.php?p=1` | URL | Stage0 payload delivery |
| `hxxps://ns.mo7sen[.]dev/EadF.php?p=4` | URL | Decoder/dropper delivery |
| `hxxps://ns.mo7sen[.]dev/EadF.php?p=5` | URL | SQLite tool delivery |
| `hxxps://ns.mo7sen[.]dev/EadF.php?p=6` | URL | Cleaner (Stop-LabTrap.ps1) |

### Host Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `C:\ProgramData\RelayTrap\` | Directory | SCKit installation directory |
| `C:\ProgramData\RelayTrap\trapbins\` | Directory | Per-client compiled trap binaries |
| `C:\ProgramData\RelayTrap\payload\` | Directory | Dropper copies for propagation |
| `C:\Windows\Temp\sc.msi` | File | Rogue ScreenConnect installer |
| `C:\Windows\Temp\sckit-run.bat` | File | Base64-encoded dropper |
| `C:\Windows\Temp\sckit-decoder.ps1` | File | Decoder script |
| `C:\Windows\Temp\sckit-loader.ps1` | File | Loader script |
| `%TEMP%\k[0-9a-f]{32}.ps1` | File (regex) | Machine-specific decrypted script |
| `%TEMP%\sqlite3.exe` | File | Cookie database reader tool |
| `%TEMP%\runnew.cmd` | File | Download/execute script |
| `%PUBLIC%\RELAY-TRAP-PROOF.txt` | File | Trap proof-of-concept artifact |
| `TrapWatch` | Scheduled Task | Persistence (runs as SYSTEM, 10s interval) |
| `RelayTrapLiteAlert` | Registry Run Key | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| `2588ef5c15954b10` | Rogue Client ID | First rogue ScreenConnect Access client |
| `ed630cc2c873b091` | Rogue Client ID | Second rogue ScreenConnect Access client |
| `Addmin` | Actor Name | Participant name in rogue ScreenConnect sessions |
| `Exploited<N>` | Installer Pattern | Machine naming pattern in rogue client installers |

### Custom HTTP Headers (Staging Protocol)

| Header | Context |
|--------|---------|
| `X-Lab-Half` | Key material for p=1 payload decryption |
| `X-Lab-Salt` | Salt for p=4 payload decryption |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | SCKit Usage |
|-------------|----------------|-------------|
| T1190 | Exploit Public-Facing Application | RMM+ authentication bypass (blank access key) |
| T1072 | Software Deployment Tools | ScreenConnect Run Command abuse for mass execution |
| T1219 | Remote Access Software | Rogue ScreenConnect Access client installation |
| T1059.001 | Command and Scripting Interpreter: PowerShell | SCKit decoder, loader, Panel-Lateral, TrapWatch scripts |
| T1105 | Ingress Tool Transfer | Staged payload download from ns.mo7sen[.]dev |
| T1027 | Obfuscated Files or Information | Base64 dropper, per-host AES-256-CBC encrypted kit |
| T1140 | Deobfuscate/Decode Files or Information | PBKDF2 key derivation, AES decryption, GZip decompression |
| T1053.005 | Scheduled Task/Job: Scheduled Task | TrapWatch task (SYSTEM, every 10 seconds) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | RelayTrapLiteAlert persistence |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defender exclusions for powershell.exe, msiexec.exe |
| T1489 | Service Stop | Stops legitimate ScreenConnect client services |
| T1543.003 | Create or Modify System Process: Windows Service | Replacement ScreenConnect Guest service |
| T1539 | Steal Web Session Cookie | Targets .ASPXAUTH ScreenConnect session cookies |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | DPAPI/AES-GCM browser cookie extraction |
| T1550.004 | Use Alternate Authentication Material: Web Session Cookie | Replays stolen .ASPXAUTH cookies against SC panels |
| T1570 | Lateral Tool Transfer | Shared Toolbox broadcast to all connected sessions |

---

## Detection and Remediation

### Immediate Actions

1. **Disable RMM+ and related extensions.** Remove or disable RMM+ versions 1.0.31/1.0.32 and any of the five extensions ConnectWise identified: Labtech Plus, RMM Plus, RMM+, RMM Plus Password Link, RMM+ Password Link.
2. **Patch ScreenConnect** to version 26.6.5.9742 or later (addresses CVE-2026-84869).
3. **Set a non-blank `RMMPlus.AccessKey`** if the extension must remain in use temporarily.
4. **Do NOT triage suspected hosts via ScreenConnect.** Use EDR live response, WinRM, or another out-of-band tool to avoid triggering RelayTrap.
5. **Isolate compromised endpoints.** Note that isolation alone does not remove persistence; reinfection was observed within minutes of isolation removal.

### Hunting Guidance

- Search for the `C:\ProgramData\RelayTrap\` directory and all contents.
- Query for `TrapWatch` scheduled task and `RelayTrapLiteAlert` registry Run key.
- Review ScreenConnect Run Command and Shared Toolbox logs for unauthorized mass executions.
- Hunt for rogue ScreenConnect Access clients connecting to `185.99.255[.]28`, `soxnewwork.homedns[.]org`, or `newnewnew.gotdns[.]org`.
- Search for Defender exclusions added for `powershell.exe` and `msiexec.exe`.
- Look for PowerShell connections to `ns.mo7sen[.]dev` or downloads of `EadF.php`.
- Match temp file pattern `k[0-9a-f]{32}\.ps1` in %TEMP%.
- Check ScreenConnect Event ID 201 (file-run events) for unexpected Host-side file execution.
- Audit RMM+ command history for activity without matching operator logins.

### Credential and Session Remediation

- Revoke and rotate all ScreenConnect credentials.
- Terminate active web sessions from a clean device.
- Revoke browser and identity-provider sessions for technicians who connected to suspected endpoints.
- Review whether technician workstations show signs of execution or cookie access.

---

## Detection Rules

### Sigma Rules (8 rules)

All rules validated via `sigma convert` to Splunk and LogScale backends. `sigma check` could not complete ATT&CK tag validation due to external endpoint unavailability (proxy restriction); rules parse and convert correctly.

| File | Title | Compile | Confidence |
|------|-------|---------|------------|
| `/tmp/actioner/sckit-1.yml` | SCKit RelayTrap Directory and File Creation | PASS (convert) | HIGH |
| `/tmp/actioner/sckit-2.yml` | SCKit Dropper and Decoder Files in Windows Temp | PASS (convert) | HIGH |
| `/tmp/actioner/sckit-3.yml` | SCKit TrapWatch Scheduled Task Creation | PASS (convert) | HIGH |
| `/tmp/actioner/sckit-4.yml` | SCKit RelayTrapLiteAlert Registry Run Key Persistence | PASS (convert) | HIGH |
| `/tmp/actioner/sckit-5.yml` | SCKit C2 Communication to Staging Infrastructure | PASS (convert) | HIGH |
| `/tmp/actioner/sckit-6.yml` | SCKit PowerShell Download from Staging Server | PASS (convert) | HIGH |
| `/tmp/actioner/sckit-7.yml` | SCKit Defender Exclusion for PowerShell and MSIExec | PASS (convert) | MEDIUM |
| `/tmp/actioner/sckit-8.yml` | SCKit Rogue ScreenConnect Client Silent Installation | PASS (convert) | HIGH |

### YARA Rules (2 files, 9 rules)

| File | Rules | Compile | Confidence |
|------|-------|---------|------------|
| `/tmp/actioner/sckit-1.yar` | SCKit_RelayTrap_Source, SCKit_TrapWatch_Script, SCKit_PanelLateral_Script, SCKit_LabContext_Config, SCKit_ToolboxRelayUploader, SCKit_Stage0Loader, SCKit_Dropper_Batch | PASS (yarac) | HIGH |
| `/tmp/actioner/sckit-2.yar` | SCKit_Installer_MSI, SCKit_SilentForceInstall | PASS (yarac) | HIGH |

### Suricata/Snort Rules (1 file, 9 rules)

| File | Rules | Compile | Confidence |
|------|-------|---------|------------|
| `/tmp/actioner/sckit-1.rules` | 9 rules covering EadF.php endpoint, X-Lab headers, C2 domains, attacker IP, installer pattern | UNCOMPILED (no engine available) | HIGH |

---

## Sources

- **Huntress:** [SCKit Worm - Rogue ScreenConnect](https://www.huntress.com/blog/sckit-worm-rogue-screenconnect) -- Primary technical analysis
- **Blackpoint Cyber:** [ScreenConnect Attack - SCKit](https://blackpointcyber.com/blog/screenconnect-attack-sckit/) -- Adversary Pursuit Group loader analysis
- **BleepingComputer:** [New Worm-Like SCKit Malware Targets MSPs in ScreenConnect Attacks](https://www.bleepingcomputer.com/news/security/new-worm-like-sckit-malware-targets-msps-in-screenconnect-attacks/)
- **The Hacker News:** [SCKit Malware Targets ScreenConnect](https://thehackernews.com/2026/11/sckit-malware-targets-screenconnect.html)
- **CyberScoop:** [ConnectWise ScreenConnect SCKit Attack](https://cyberscoop.com/connectwise-screenconnect-sckit-attack/)
- **The Register:** [Hackers Exploiting ScreenConnect Plugin Flaw](https://www.theregister.com/security/2026/11/12/hackers-exploiting-screenconnect-plugin-flaw-to-spread-malware-across-hundreds-of-pcs/5309361)
- **ConnectWise Trust Center:** [Security Advisories](https://www.connectwise.com/company/trust/advisories) (returned 403 at time of fetch)
- **NVD:** [CVE-2026-84869](https://nvd.nist.gov/vuln/detail/cve-2026-84869)
- **Huntress (earlier activity):** [Rogue ScreenConnect Installations](https://www.huntress.com/blog/rogue-screenconnect-installations)
- **Microsoft attribution (related):** Storm-0940 attributed to earlier ConnectWise supply-chain attack (per CyberScoop)
