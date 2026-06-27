# SharkLoader / StrikeShark Campaign — Cobalt Strike Deployment Against Government and Diplomatic Targets

## Executive Summary

Kaspersky GReAT has uncovered an active campaign tracked as **StrikeShark**, employing a previously undocumented malware loader called **SharkLoader** to deploy Cobalt Strike Beacons against diplomatic, government, and software development organizations across nine countries. The campaign exploits multiple known vulnerabilities in internet-facing applications (Exchange, SharePoint, Openfire, GeoServer, Fortinet) and uses sophisticated DLL side-loading, API hooking via MinHook, ETW evasion through direct syscalls, and in-memory-only payload execution to evade detection. Post-exploitation activity includes Active Directory credential harvesting, LSASS dumping, and deployment of Chinese-language reconnaissance tools (FScan, Searchall, Pillager).

## Background

- **Campaign name:** StrikeShark
- **Malware family:** SharkLoader (new, custom loader)
- **Final payload:** Cobalt Strike Beacon (shellcode)
- **Discovery:** Kaspersky GReAT, published June 24-26, 2026
- **Initial discovery context:** Attack on an Indonesian diplomatic organization
- **Affected regions:** Indonesia, Taiwan, Hong Kong, Lebanon, Syria, Colombia, North Macedonia, Nepal, Serbia
- **Targeted sectors:** Diplomatic entities, government agencies, software development companies
- **Attribution:** Suspected Chinese-speaking threat actor (low confidence); no link to known APT groups established
- **Status:** Active campaign; ongoing investigation

## Technical Analysis

### Stage 1 -- Initial Access

The threat actor exploits publicly available vulnerabilities in internet-facing applications:

| CVE | Product | Type |
|-----|---------|------|
| CVE-2021-26855 | Microsoft Exchange (ProxyLogon) | RCE |
| CVE-2023-32315 | Openfire | Path Traversal/RCE |
| CVE-2024-36401 | GeoServer | RCE |
| CVE-2016-4437 | Apache Shiro | Deserialization |
| CVE-2021-36260 | Hikvision | RCE |
| CVE-2021-27076 | Microsoft SharePoint | RCE |
| CVE-2022-27925 | Zimbra Collaboration Suite | RCE |
| CVE-2022-41082 | Microsoft Exchange Server | RCE |
| CVE-2023-46747 | F5 BIG-IP | RCE |
| CVE-2024-21762 | Fortinet FortiOS | RCE |
| CVE-2022-40684 | Fortinet FortiOS | Auth Bypass |
| CVE-2023-20198 | Cisco IOS XE Web UI | Auth Bypass |
| CVE-2025-55182 | React Server Components | RCE |

Alternatively, attackers deliver malicious droppers disguised as legitimate software:
- Cisco AnyConnect VPN installer (`AnyConnect-win-4.10.04071-predeploy-k9exe`)
- Google Update utility (`GoogleUpdateStepup.exe`, `AutoUpdate.exe`)
- Decoy PDFs (liquid rocket engine design, biological treatment documents)
- Chinese-language social engineering lure: a filename referencing screenshots of OS and input method versions

### Stage 2 -- SharkLoader Deployment (DLL Side-Loading)

After gaining initial access, attackers deploy web shells and then execute a DLL side-loading chain:

1. **Legitimate EXE** (`SystemSettings.exe`) is copied to a non-standard directory (e.g., `%APPDATA%\xwreg\`, `%APPDATA%\xgdf\`, `%APPDATA%\reports\`, `C:\ProgramData\`, `C:\ADriveLogs_Logs\`)
2. **Malicious DLL** (`SystemSettings.dll`) is placed alongside it -- the legitimate EXE loads the malicious DLL via DLL search-order hijacking
3. Alternative side-loading targets include `msedge.dll`, `PrintDialog.dll`, `miracastview.dll`

The loader uses a **"Perfect DLL Hijacking"** technique that manipulates internal Windows Loader structures (`LdrpLoaderLock`, `LdrpWorkInProgress`) and forces release via `LeaveCriticalSection` before calling `CreateThread`, bypassing the Windows Loader Lock.

### Stage 3 -- Encrypted Module Decryption

SharkLoader decrypts two embedded modules:

- **DscCoreR.mui** -- Contains Cobalt Strike Beacon shellcode, encrypted with **Blowfish (ECB mode)**. The 16-byte decryption key is extracted from the first 16 bytes of the encrypted file. Alternative filenames: `GameInputInboxs32.mui`, `diagerr.xml`, `NtfsLog.etl`, `VistaCompat.nls`
- **SyncRes.dat** -- API hook installer using Microsoft Detours/MinHook library, encrypted with **AES-128 (CBC mode)**. First 16 bytes contain the AES key; subsequent 16 bytes contain the IV. Alternative filename: `SyncRest.dat`, `Ignored.Dat`

### Stage 4 -- API Hooking and Evasion (SyncRes.dat)

The SyncRes.dat module installs extensive API hooks via MinHook for:

**PPID Spoofing:** `CreateProcessA`/`CreateProcessW` are hooked to spoof the parent process as `svchost.exe`

**Direct Syscall Substitution:**
- `OpenProcessToken` -> `NtOpenProcessToken`
- `AdjustTokenPrivileges` -> `NtAdjustPrivilegesToken`
- `WriteProcessMemory` -> `NtWriteVirtualMemory`
- `VirtualAllocEx` -> `NtAllocateVirtualMemory`
- `VirtualProtectEx`/`VirtualProtect` -> `NtProtectVirtualMemory`
- `ResumeThread` -> `NtResumeThread`
- `GetThreadContext` -> `NtGetContextThread`

**ETW Evasion:** `EtwEventWrite`, `EventWriteEx`, `EventWrite` are hooked to return success without logging

**Module Loading:** `LoadLibraryA/Ex`, `GetModuleHandleA/W`, `GetProcAddress` replaced with custom implementations using **Murmur32 hashing** for function name resolution

**Memory Protection Evasion:** During Cobalt Strike Beacon sleep intervals, the malware temporarily modifies tracked memory regions from RWX (`PAGE_EXECUTE_READWRITE`) to RW (`PAGE_READWRITE`), then restores to RWX after sleep completes. A **Vectored Exception Handler (VEH)** monitors for access violations (0xC0000005) and restores RWX permissions.

### Stage 5 -- Cobalt Strike Beacon Execution

After API hooks are installed, the Cobalt Strike Beacon shellcode is written to a thread buffer and the malware calls `ResumeThread` to execute the suspended thread containing the beacon.

### Stage 6 -- Post-Exploitation

**System Enumeration:**
```
systeminfo | ipconfig /all | tasklist /svc | query user | nslookup
quser | netstat -ano | arp -a | net share
```

**Active Directory Enumeration:**
```
powershell "Get-ADGroupMember -Identity '' -Recursive | Select-Object Name, ObjectClass"
net group "Domain Controllers" /domain
net group "Enterprise Admins" /domain
```

**Credential Dumping:**
```
ntdsutil "ac i ntds" "ifm" "create full $temp" q q
Procdump64.exe -accepteula -ma lsass.exe $temp\lsass.dmp
```

**Post-Exploitation Tools:** FScan (network scanner), Searchall (sensitive data search), Pillager (information gathering), SharpGPOAbuse (Group Policy modification), Procdump64.exe (credential dumping), ntdsutil (NTDS extraction)

### Persistence Mechanisms

**Registry Run Key:**
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Value: MFUpdate
Data: %APPDATA%\Identities\SystemSettings.exe
```

**Scheduled Tasks:**
- `OneDrive Standalone Update Task-S-1-5-21-4165425321-4153752593-2322023643-1000`
- `MicrosoftUpdateTaskUserS-1-5-32-2456537112-101246289-228944324-1000`
- `\Microsoft\Windows\Edge\Edgeupdate`

Task creation command:
```
Schtasks /create /s /u "" /p "" /ru "SYSTEM" /tn "\\Microsoft\\Windows\\Edge\\Edgeupdate" /sc DAILY /tr "C:\\ADriveLogs_Logs\\SystemSettings.exe /F"
```

### C2 Infrastructure

C2 communication occurs over HTTPS to domains mimicking Microsoft services. One associated IP address was observed conducting internet-wide scanning activity.

## Indicators of Compromise (IOCs)

> All indicators are defanged for safe handling. Detection rules below use live (non-defanged) values.

### File Hashes (MD5)

| Hash | Description |
|------|-------------|
| `C559CC68986933200FD5D9E4388E2F58` | Dropper/Installer |
| `B3352B42432DEDC4A519F011DC8B5D5A` | Dropper |
| `24FCEBDEECBA65004FDB0923763D74FD` | Dropper |
| `1F65544978B8EA0E745E573B8EE9684B` | Dropper |
| `AA3086BE652C8B20B0B29B2730D57119` | SharkLoader DLL (SystemSettings.dll) |
| `9C872A0D5D5A38950E8B9AC9B488BE3F` | SharkLoader DLL variant |
| `D98F568496512E4F98670C61C97CB07A` | Legitimate SystemSettings.exe (abused) |
| `A514D1BB62D7916475946FE7C07AC0AA` | Encrypted module (DscCoreR.mui) |
| `9CBD560F820C95D7C38342CD558CB5C6` | Encrypted module (SyncRes.dat) |

### C2 Domains

| Domain | Notes |
|--------|-------|
| `connect-microsoft[.]com` | Primary C2 |
| `ms-record[.]com` | C2 domain |
| `ms-record[.]top` | C2 domain |
| `ms-tray[.]top` | C2 domain |

### File Artifacts

| Filename | Role |
|----------|------|
| `SystemSettings.exe` | Legitimate Windows binary abused for side-loading |
| `SystemSettings.dll` | SharkLoader main DLL |
| `DscCoreR.mui` | Encrypted Cobalt Strike Beacon shellcode |
| `SyncRes.dat` / `SyncRest.dat` | Encrypted API hook installer |
| `GameInputInboxs32.mui` | Alternative encrypted module name |
| `VistaCompat.nls` | Alternative encrypted module name |
| `Ignored.Dat` | Alternative encrypted module name |
| `diagerr.xml` | Alternative encrypted module name |
| `NtfsLog.etl` | Alternative encrypted module name |
| `GoogleUpdateStepup.exe` | Dropper disguised as Google Update |
| `AnyConnect-win-4.10.04071-predeploy-k9exe` | Dropper disguised as Cisco AnyConnect |
| `AutoUpdate.exe` | Dropper |

### Installation Paths

- `%APPDATA%\xwreg\`
- `%APPDATA%\xgdf\`
- `%APPDATA%\reports\`
- `%APPDATA%\Identities\`
- `C:\ProgramData\`
- `C:\Windows\ImmersiveControlPanel\`
- `C:\ADriveLogs_Logs\`

### Registry Keys

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MFUpdate` = `%APPDATA%\Identities\SystemSettings.exe`

### Scheduled Task Names

- `OneDrive Standalone Update Task-S-1-5-21-4165425321-4153752593-2322023643-1000`
- `MicrosoftUpdateTaskUserS-1-5-32-2456537112-101246289-228944324-1000`
- `\Microsoft\Windows\Edge\Edgeupdate`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of Exchange (ProxyLogon), Openfire, GeoServer, SharePoint, Fortinet, Cisco IOS XE, F5 BIG-IP, Zimbra |
| T1204.002 | User Execution: Malicious File | Dropper disguised as Cisco AnyConnect and Google Update installers |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | SystemSettings.exe loads malicious SystemSettings.dll from non-standard path |
| T1547.001 | Boot or Logon Autostart: Registry Run Keys | MFUpdate registry Run key persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Multiple scheduled tasks masquerading as OneDrive, Microsoft Update, Edge Update |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Malicious DLLs named after legitimate Windows components |
| T1562.001 | Impair Defenses: Disable or Modify Tools | ETW evasion via API hooking of EtwEventWrite |
| T1134.004 | Access Token Manipulation: Parent PID Spoofing | CreateProcess hooks spoof parent to svchost.exe |
| T1003.001 | OS Credential Dumping: LSASS Memory | Procdump64.exe used to dump LSASS |
| T1003.003 | OS Credential Dumping: NTDS | ntdsutil used to extract AD database |
| T1087.002 | Account Discovery: Domain Account | Get-ADGroupMember, net group enumeration |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 communication to Microsoft-mimicking domains |
| T1055 | Process Injection | Cobalt Strike Beacon shellcode injected into thread buffer |
| T1027.013 | Obfuscated Files: Encrypted/Encoded File | Blowfish and AES-128 encryption of payload modules |
| T1106 | Native API | Direct NT syscalls to bypass user-mode hooks |
| T1505.003 | Server Software Component: Web Shell | Web shells deployed on compromised Exchange/Openfire servers |
| T1082 | System Information Discovery | systeminfo, ipconfig /all, netstat -ano enumeration |

## Detection Rules

### Sigma Rule 1 -- SharkLoader DLL Side-Loading via SystemSettings.exe from Non-Standard Path

compile-status: **Compiles** | confidence: **high**

```yaml
title: SharkLoader DLL Side-Loading via SystemSettings.exe from Non-Standard Path
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects execution of SystemSettings.exe from non-standard directories, indicative of SharkLoader DLL side-loading as observed in the StrikeShark campaign.
references:
    - https://securelist.com/strikeshark-campaign/120326/
    - https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.defense_evasion
    - attack.t1574.002
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\SystemSettings.exe'
    filter_legitimate:
        Image|startswith:
            - 'C:\Windows\ImmersiveControlPanel\'
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate software that bundles SystemSettings.exe in non-standard locations
level: high
```

### Sigma Rule 2 -- SharkLoader Registry Run Key Persistence (MFUpdate)

compile-status: **Compiles** | confidence: **high**

```yaml
title: SharkLoader Registry Run Key Persistence - MFUpdate
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: Detects creation of the MFUpdate registry Run key value pointing to SystemSettings.exe under Identities folder, a persistence mechanism used by SharkLoader in the StrikeShark campaign.
references:
    - https://securelist.com/strikeshark-campaign/120326/
    - https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MFUpdate'
        Details|contains: '\Identities\SystemSettings.exe'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```

### Sigma Rule 3 -- SharkLoader Scheduled Task Creation (Edge Update Masquerade)

compile-status: **Compiles** | confidence: **high**

```yaml
title: SharkLoader Scheduled Task Creation - Edge Update Masquerade
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: Detects creation of scheduled tasks masquerading as Microsoft Edge updates used by SharkLoader for persistence, executing SystemSettings.exe from suspicious paths.
references:
    - https://securelist.com/strikeshark-campaign/120326/
    - https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html
author: Actioner CTI
date: 2026-06-27
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
            - 'Edgeupdate'
            - 'SystemSettings.exe'
    condition: selection_schtasks
falsepositives:
    - Unlikely
level: critical
```

### Sigma Rule 4 -- StrikeShark Post-Exploitation NTDS Credential Extraction

compile-status: **Compiles** | confidence: **medium**

```yaml
title: StrikeShark Post-Exploitation - NTDS Credential Extraction
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: experimental
description: Detects ntdsutil credential extraction commands observed in StrikeShark post-compromise activity targeting Active Directory databases.
references:
    - https://securelist.com/strikeshark-campaign/120326/
    - https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.credential_access
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ntdsutil.exe'
        CommandLine|contains|all:
            - 'ac i ntds'
            - 'ifm'
            - 'create full'
    condition: selection
falsepositives:
    - Legitimate Active Directory backup operations
level: high
```

### Sigma Rule 5 -- SharkLoader Dropper Execution (Known Filenames)

compile-status: **Compiles** | confidence: **high**

```yaml
title: SharkLoader Dropper Execution - Known Filenames
id: e5f6a7b8-c9d0-1234-efab-345678901234
status: experimental
description: Detects execution of known SharkLoader dropper filenames disguised as legitimate software installers, including fake Cisco AnyConnect and Google Update binaries.
references:
    - https://securelist.com/strikeshark-campaign/120326/
    - https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.execution
    - attack.t1204.002
    - attack.defense_evasion
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\GoogleUpdateStepup.exe'
            - '\AnyConnect-win-4.10.04071-predeploy-k9exe'
    condition: selection
falsepositives:
    - Legitimate Google Update or Cisco AnyConnect installers with matching names
level: medium
```

### YARA Rule 1 -- SharkLoader Dropper Strings

compile-status: **Compiles** | confidence: **high**

```yara
import "math"

rule SharkLoader_Dropper_Strings
{
    meta:
        description = "Detects SharkLoader dropper components based on distinctive string patterns and file artifacts observed in the StrikeShark campaign"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://securelist.com/strikeshark-campaign/120326/"
        hash1 = "C559CC68986933200FD5D9E4388E2F58"
        hash2 = "B3352B42432DEDC4A519F011DC8B5D5A"

    strings:
        $loader_dll = "SystemSettings.dll" ascii wide
        $enc_module1 = "DscCoreR.mui" ascii wide
        $enc_module2 = "SyncRes.dat" ascii wide
        $enc_module2b = "SyncRest.dat" ascii wide
        $alt_mui1 = "GameInputInboxs32.mui" ascii wide
        $alt_mui2 = "VistaCompat.nls" ascii wide
        $alt_dat1 = "Ignored.Dat" ascii wide
        $alt_xml1 = "diagerr.xml" ascii wide
        $alt_etl1 = "NtfsLog.etl" ascii wide

        $path1 = "\\xwreg\\" ascii wide
        $path2 = "\\xgdf\\" ascii wide

        $dropper1 = "GoogleUpdateStepup.exe" ascii wide
        $dropper2 = "AnyConnect-win-4.10.04071-predeploy-k9exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($loader_dll and ($enc_module1 or $enc_module2)) or
            (2 of ($path1, $path2, $alt_mui1, $alt_mui2, $alt_dat1, $alt_xml1, $alt_etl1)) or
            (any of ($dropper*) and any of ($enc_module*))
        )
}
```

### YARA Rule 2 -- SharkLoader API Hook Module

compile-status: **Compiles** | confidence: **medium**

```yara
rule SharkLoader_APIHook_Module
{
    meta:
        description = "Detects SharkLoader SyncRes.dat API hook installer module that uses MinHook and direct syscalls for evasion"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://securelist.com/strikeshark-campaign/120326/"
        hash = "9CBD560F820C95D7C38342CD558CB5C6"

    strings:
        $api1 = "NtOpenProcessToken" ascii
        $api2 = "NtAdjustPrivilegesToken" ascii
        $api3 = "NtWriteVirtualMemory" ascii
        $api4 = "NtAllocateVirtualMemory" ascii
        $api5 = "NtProtectVirtualMemory" ascii
        $api6 = "NtResumeThread" ascii
        $api7 = "NtGetContextThread" ascii
        $api8 = "NtCreateThreadEx" ascii
        $api9 = "NtQueueApcThread" ascii
        $api10 = "EtwEventWrite" ascii

        $hook1 = "CreateProcessA" ascii
        $hook2 = "CreateProcessW" ascii
        $hook3 = "VirtualAllocEx" ascii
        $hook4 = "VirtualProtectEx" ascii
        $hook5 = "WriteProcessMemory" ascii
        $hook6 = "ResumeThread" ascii

        $minhook = "MinHook" ascii wide
        $ldr1 = "LdrpLoaderLock" ascii
        $ldr2 = "LdrpWorkInProgress" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (5 of ($api*) and 3 of ($hook*)) or
            ($minhook and 3 of ($api*)) or
            (any of ($ldr*) and 3 of ($api*))
        )
}
```

### Snort Rules -- SharkLoader C2 DNS Lookups

compile-status: **Compiles** | confidence: **high**

```snort
alert udp any any -> any 53 (msg:"MALWARE SharkLoader C2 DNS Lookup - connect-microsoft.com"; content:"|11|connect-microsoft|03|com|00|"; nocase; sid:2026062701; rev:1; classtype:trojan-activity; metadata:author Actioner_CTI, created_at 2026_06_27;)

alert udp any any -> any 53 (msg:"MALWARE SharkLoader C2 DNS Lookup - ms-record.com"; content:"|09|ms-record|03|com|00|"; nocase; sid:2026062702; rev:1; classtype:trojan-activity; metadata:author Actioner_CTI, created_at 2026_06_27;)

alert udp any any -> any 53 (msg:"MALWARE SharkLoader C2 DNS Lookup - ms-record.top"; content:"|09|ms-record|03|top|00|"; nocase; sid:2026062703; rev:1; classtype:trojan-activity; metadata:author Actioner_CTI, created_at 2026_06_27;)

alert udp any any -> any 53 (msg:"MALWARE SharkLoader C2 DNS Lookup - ms-tray.top"; content:"|07|ms-tray|03|top|00|"; nocase; sid:2026062704; rev:1; classtype:trojan-activity; metadata:author Actioner_CTI, created_at 2026_06_27;)
```

### Suricata Rules -- SharkLoader C2 Detection (DNS and HTTP)

compile-status: **Compiles** | confidence: **high**

```suricata
alert dns any any -> any any (msg:"MALWARE SharkLoader C2 DNS Query - connect-microsoft.com"; dns.query; content:"connect-microsoft.com"; nocase; sid:2026062710; rev:1; classtype:trojan-activity;)

alert dns any any -> any any (msg:"MALWARE SharkLoader C2 DNS Query - ms-record.com"; dns.query; content:"ms-record.com"; nocase; sid:2026062711; rev:1; classtype:trojan-activity;)

alert dns any any -> any any (msg:"MALWARE SharkLoader C2 DNS Query - ms-record.top"; dns.query; content:"ms-record.top"; nocase; sid:2026062712; rev:1; classtype:trojan-activity;)

alert dns any any -> any any (msg:"MALWARE SharkLoader C2 DNS Query - ms-tray.top"; dns.query; content:"ms-tray.top"; nocase; sid:2026062713; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"MALWARE SharkLoader C2 HTTP Request - connect-microsoft.com"; http.host; content:"connect-microsoft.com"; sid:2026062714; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"MALWARE SharkLoader C2 HTTP Request - ms-record.com"; http.host; content:"ms-record.com"; sid:2026062715; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"MALWARE SharkLoader C2 HTTP Request - ms-record.top"; http.host; content:"ms-record.top"; sid:2026062716; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"MALWARE SharkLoader C2 HTTP Request - ms-tray.top"; http.host; content:"ms-tray.top"; sid:2026062717; rev:1; classtype:trojan-activity;)
```

## Remediation

### Immediate Actions

1. **Block C2 domains** at DNS resolvers and firewall: `connect-microsoft.com`, `ms-record.com`, `ms-record.top`, `ms-tray.top`
2. **Search for IOC hashes** across all endpoints using EDR or AV console
3. **Hunt for SystemSettings.exe** executing from non-standard paths (outside `C:\Windows\ImmersiveControlPanel\`)
4. **Audit registry Run keys** for `MFUpdate` entries and scheduled tasks mimicking OneDrive/Edge update names
5. **Scan for file artifacts**: `DscCoreR.mui`, `SyncRes.dat`, `GameInputInboxs32.mui`, `VistaCompat.nls` in `%APPDATA%` and `C:\ProgramData\`

### Vulnerability Patching

6. **Patch all exploited CVEs immediately** -- prioritize internet-facing Exchange, SharePoint, Openfire, GeoServer, Fortinet, and Cisco IOS XE instances
7. **Audit web shells** on Exchange and Openfire servers

### If Compromise Is Confirmed

8. **Reset all domain credentials** -- the actor targets NTDS databases and LSASS
9. **Isolate affected hosts** and perform forensic imaging
10. **Review Active Directory** for unauthorized Group Policy changes (SharpGPOAbuse usage)
11. **Audit lateral movement** using netstat, firewall logs, and authentication logs
12. **Enable enhanced ETW logging** -- the malware specifically disables ETW event writing
13. **Deploy memory-scanning EDR** capable of detecting Cobalt Strike Beacons with sleep-time memory permission toggling (RWX to RW)

### Long-Term Hardening

14. **Implement application whitelisting** to prevent DLL side-loading from non-standard paths
15. **Monitor for scheduled task creation** via Windows Event ID 4698
16. **Enable Sysmon** with DLL loading and process creation rules
17. **Restrict ntdsutil and Procdump** execution to authorized admin accounts only

## Sources

- [StrikeShark: a new campaign involving a custom SharkLoader and Cobalt Strike Beacon -- Securelist (Kaspersky GReAT)](https://securelist.com/strikeshark-campaign/120326/)
- [New SharkLoader Malware Deploys Cobalt Strike in StrikeShark Cyberattacks -- The Hacker News](https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html)
- [Mystery hackers use novel SharkLoader dropper against governments, software devs -- Help Net Security](https://www.helpnetsecurity.com/2026/06/26/sharkloader-dropper-governments-software-developers/)
- [Hackers Use Cisco AnyConnect and Google Update Lures to Drop SharkLoader Malware -- Cybersecurity News](https://cybersecuritynews.com/hackers-use-cisco-anyconnect-and-google-update-lures/)
- [Kaspersky warns of a new StrikeShark campaign -- Kaspersky Press Release](https://www.kaspersky.com/about/press-releases/kaspersky-warns-of-a-new-strikeshark-campaign-targeting-organizations-in-asia-latin-america-and-europe-with-advanced-malware)
- [StrikeShark Campaign Uses New SharkLoader Malware to Deploy Cobalt Strike Beacon -- GBHackers](https://gbhackers.com/sharkloader-malware-to-deploy-cobalt-strike/)

---
*Generated by Actioner -- 2026-06-27*
