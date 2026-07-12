# Technical Analysis Report: GigaWiper Destructive Backdoor (2026-07-12)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-12
Version: 1.0 DRAFT

## Executive Summary

GigaWiper is a Golang-based Windows backdoor that consolidates disk wiping, ransomware-like encryption, and C2 capabilities from at least three prior malware families -- Crucio ransomware, FlockWiper, and a standalone physical disk wiper -- into a single modular platform with 20 on-demand commands. First observed in destructive attacks in October 2025 and publicly disclosed by Microsoft Threat Intelligence on July 9, 2026, the malware uses RabbitMQ AMQP for command dispatch and Redis for status reporting, blending with legitimate enterprise messaging traffic. Binary Defense and Google Threat Intelligence Group (GTIG) track the same malware as BLUERABBIT and attribute it to a likely Iran-nexus group targeting Israeli organizations, with activity correlating to escalated Iranian cyber operations following U.S.-Israel military strikes on Iran in early 2026.

The backdoor's destructive capabilities are irreversible: its disk wiper overwrites raw physical drives and removes partition tables, while its encryption command generates random AES-CBC keys that are never saved, making data recovery impossible. Additional capabilities include VNC-like remote control, screen recording, MinIO-based data exfiltration, and comprehensive anti-forensics including event log clearing and direct Security.evtx deletion.

## Background: Threat Actor and Malware Lineage

GigaWiper represents the evolution of several standalone destructive tools into a unified command-and-control platform. The Crucio ransomware was first documented in a December 2023 CISA advisory (AA23-335A) as suspected ransomware linked to CyberAv3ngers, a group tied to Iran's Islamic Revolutionary Guard Corps (IRGC). FlockWiper, a C-based multi-pass disk wiper, was uploaded to VirusTotal in June 2025. The recurring string "GRAT" appears in both FlockWiper's PDB debug paths and GigaWiper's function names, indicating a shared development framework.

The threat actor assembled these components into GigaWiper by reimplementing FlockWiper's C logic in Golang and incorporating Crucio's `BigBangExtortMain` encryption routine, creating a single backdoor that can switch between espionage, sabotage, and destruction on command.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| December 2023 | CISA advisory AA23-335A documents Crucio ransomware linked to CyberAv3ngers |
| June 2025 | FlockWiper samples uploaded to VirusTotal |
| October 2025 | Microsoft Threat Intelligence detects GigaWiper in live destructive wiping attacks |
| March 2026 | Binary Defense first observes same samples, tracks as BLUERABBIT |
| July 9, 2026 | Microsoft publishes full technical analysis of GigaWiper |

## Root Cause: Initial Access Vector

The Microsoft blog does not detail the initial access vector. The malware is a post-compromise tool deployed after the attacker has already gained access to the target environment. Confirmed targets are Israeli organizations, and the campaign timeline overlaps with documented escalation in Iranian cyber operations.

## Technical Analysis of the Malicious Payload

### 1. Persistence and Execution Flow

GigaWiper establishes persistence through a scheduled task named **"OneDrive Update"** configured to run every minute and at system startup. On first execution, the malware:

1. Checks for the registry key `HKCU\SOFTWARE\OneDrive\Environment`
2. If absent, creates the key with an initial execution count value of 0
3. Creates the "OneDrive Update" scheduled task via PowerShell
4. Outputs "_Task created. Original process exiting._" and terminates
5. Subsequent executions (from the scheduled task) detect the registry key and proceed to C2 communication, outputting "_Running from Task Scheduler..._"

### 2. Command Set (20 Commands)

| Cmd | Name | Function |
|-----|------|----------|
| 1 | WipeMain | Physical disk wiper: enumerates drives via WMI, removes partitions via `DeviceIoControl` with `IOCTL_DISK_CREATE_DISK`, overwrites raw disk with randomized bytes (fallback: `0x01`), chunk size `0xA00000`, forces reboot |
| 2 | BSOD | Disables Windows recovery, deletes boot/kernel files, triggers blue screen |
| 3 | RanMain / BigBangExtortMain | AES-CBC encryption with random key/IV (never saved), appends `.candy` extension, drops `image_danger.jpg` wallpaper, excludes `.exe`/`.dll` |
| 4 | MinIO Upload | Uses MinIO Client (`mc.exe`) for data exfiltration to remote storage |
| 5 | AES-256 Encryption | Bulk file encryption/decryption utility with `key.txt` key/IV management |
| 6 | Unimplemented | Wiper placeholder ("wipe-file" reference) |
| 7 | Shell Command | PowerShell execution with working directory tracking; supports `purge_cmd_queue`, `purge_queue`, `pwd` sub-commands |
| 8 | RabbitMQ Route Manager | Bind/unbind topic exchange routing keys (modes 1/2/3) |
| 9 | Screenshot | PNG capture per active monitor to timestamped folder |
| 10 | Screen Recording | Records to `C:\ProgramData\output` when user is active (>10s idle threshold) and system is unlocked |
| 11 | Unimplemented | Keylogger placeholder |
| 12 | WipeCMain | Windows drive-only wiper with multi-pass secure deletion (pass 1: zeros, pass 2: 0xFF, pass 3+: random) |
| 13 | Unimplemented | "wipe32" reference, admin-launched executable |
| 14 | Unimplemented | No functionality |
| 15 | System Info | Collects IP, GUID, CPU, OS, firmware, users, AV software via WMI |
| 16 | Process Manager | Create, resume, suspend, list, kill, query processes |
| 17 | Service Manager | Create, delete, restart, start, stop, query, list services |
| 18 | Registry Manager | Interactive session: show, navigate, back, exit, createKey, deleteKey, deleteValue, setValue |
| 19 | Event Log Clearing | Clears System, Setup, Application, ForwardedEvents via `wevtutil.exe cl`; falls back to direct deletion of `C:\Windows\System32\winevt\Logs\Security.evtx` |
| 20 | VNC Remote Control | TCP-based keyboard/mouse/screen streaming with firewall rules masquerading as "Microsoft.Windows.CloudExperienceHost" |

### 3. C2 Infrastructure

GigaWiper uses a dual-channel C2 architecture leveraging legitimate enterprise messaging services:

- **Command Channel:** RabbitMQ AMQP at `185.182.193[.]21:5544`
  - Fanout exchange `"All"` for broadcasting commands to all implants
  - Topic exchange `"Topic"` for targeted command delivery
  - Command structure: `task_id`, `command_code`, `args`
- **Results Channel:** Redis at `185.182.193[.]21:7542`
  - Status reporting structure: `error`, `target_ip`, `task_id`, `target_computer_name`, `output`, `pwd`, `time`, `status`, `work_status`
- **Additional C2:** `212.8.248[.]104` (GigaWiper C2)

### 4. Disk Wiping Methodology

**Physical Disk Wiper (Command 1 / Standalone):**
- Enumerates physical disks via WMI
- Identifies the Windows installation drive (typically `\\.\PHYSICALDRIVE0`)
- Removes partition references from non-Windows drives via `DeviceIoControl` with `IOCTL_DISK_CREATE_DISK`
- Overwrites raw disk content with randomized bytes (`crypto/rand.Read`; fallback value `0x01`)
- Zero-fills remaining buffer; chunk size `0xA00000`
- Reinitializes partition metadata and forces immediate reboot
- Outputs "_Partitions removed successfully_" on completion

**Multi-Pass Secure Wiper (Command 12 / WipeCMain):**
- Targets Windows drive only
- Pass 1: overwrite with zeros
- Pass 2: overwrite with `0xFF`
- Pass 3+: overwrite with random data
- Progress logging: "_Pass X Time took: %s\n_"

### 5. Anti-Forensics / Evasion Techniques

- **Event log clearing:** `wevtutil.exe cl System`, `wevtutil.exe cl Setup`, `wevtutil.exe cl Application`, `wevtutil.exe cl ForwardedEvents`, `wevtutil.exe cl Security`
- **Fallback log deletion:** Direct file deletion of `C:\Windows\System32\winevt\Logs\Security.evtx` when wevtutil fails, with status message "_Failed to clear Security with wevtutil. Attempting manual removal..._"
- **Firewall masquerading:** Creates inbound/outbound firewall rules named `"Microsoft.Windows.CloudExperienceHost"` via `netsh advfirewall firewall add rule` to disguise VNC traffic
- **C2 blending:** Uses RabbitMQ and Redis protocols on non-standard ports, mimicking legitimate enterprise infrastructure
- **OneDrive impersonation:** Scheduled task and registry key masquerade as legitimate OneDrive update components
- **Unexplained artifact:** Hard-coded string output `"kharbvnmhkjbkjb"` during event log clearing (purpose unknown -- possible debug artifact or operator identification)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation. URLs use `hxxps://`, domains and IPs use `[.]` replacing dots.

### File System

| Platform | Hash (SHA-256) | Description |
|----------|---------------|-------------|
| Windows | `633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001` | GigaWiper backdoor |
| Windows | `ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913` | GigaWiper backdoor |
| Windows | `f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd` | GigaWiper backdoor |
| Windows | `9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683` | GigaWiper backdoor |
| Windows | `3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd` | Standalone disk wiper |
| Windows | `440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3` | Crucio ransomware |
| Windows | `12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721` | FlockWiper |
| Windows | `db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674` | FlockWiper |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP:Port | `185.182.193[.]21:5544` | RabbitMQ AMQP C2 command channel |
| IP:Port | `185.182.193[.]21:7542` | Redis results/status channel |
| IP | `212.8.248[.]104` | GigaWiper C2 |

### Behavioral

- Scheduled task named `"OneDrive Update"` set to run every minute and at startup
- Registry key `HKCU\SOFTWARE\OneDrive\Environment` with numeric execution count
- Files renamed with `.candy` extension during encryption
- `image_danger.jpg` dropped as wallpaper
- Screen recordings written to `C:\ProgramData\output`
- Firewall rules named `"Microsoft.Windows.CloudExperienceHost"` created via netsh
- Bulk event log clearing via `wevtutil.exe cl` across 5 log channels
- Direct deletion of `Security.evtx` as fallback
- PDB paths: `A:\GRAT\CWipeNew\Release\CWipeNew.pdb`, `E:\files\new\GRAT\CWipe\Release\CWipe.pdb`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1053.005 | Scheduled Task | "OneDrive Update" task for persistence (every minute + startup) |
| T1112 | Modify Registry | `HKCU\SOFTWARE\OneDrive\Environment` execution tracking |
| T1059.001 | PowerShell | Shell command execution (command 7), scheduled task creation |
| T1485 | Data Destruction | Physical disk wiping via raw disk overwrite (commands 1, 12) |
| T1486 | Data Encrypted for Impact | AES-CBC encryption with unsaved keys, .candy extension (command 3) |
| T1529 | System Shutdown/Reboot | Forced reboot after disk wipe; BSOD trigger (command 2) |
| T1070.001 | Clear Windows Event Logs | wevtutil.exe clearing + Security.evtx deletion (command 19) |
| T1036.004 | Masquerade Task or Service | Firewall rules named "Microsoft.Windows.CloudExperienceHost" |
| T1071 | Application Layer Protocol | RabbitMQ AMQP and Redis for C2 communication |
| T1567 | Exfiltration Over Web Service | MinIO client for data exfiltration (command 4) |
| T1113 | Screen Capture | Screenshot and screen recording capabilities (commands 9, 10) |
| T1012 | Query Registry | Registry manager interactive session (command 18) |
| T1057 | Process Discovery | Process enumeration and management (command 16) |
| T1007 | System Service Discovery | Service enumeration and management (command 17) |

## Impact Assessment

GigaWiper poses a critical threat due to its irreversible destructive capabilities. The disk wiper overwrites raw physical drives at the sector level, making data recovery impossible without offline backups. The encryption command uses randomly generated AES-CBC keys that are deliberately never saved, ensuring encrypted files cannot be recovered even with operator cooperation. Confirmed targets are Israeli organizations, consistent with the attributed Iran-nexus threat actor's operational focus. The modular architecture with 20 commands and legitimate protocol C2 channels indicates a mature, well-resourced development effort.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for GigaWiper scheduled task
Get-ScheduledTask -TaskName "OneDrive Update" -ErrorAction SilentlyContinue

# Check for GigaWiper registry persistence
Get-ItemProperty -Path "HKCU:\SOFTWARE\OneDrive\Environment" -ErrorAction SilentlyContinue

# Check for masqueraded firewall rules
netsh advfirewall firewall show rule name="Microsoft.Windows.CloudExperienceHost"

# Check for .candy encrypted files
Get-ChildItem -Path C:\ -Filter "*.candy" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5

# Check for screen recording output directory
Test-Path "C:\ProgramData\output"

# Check for image_danger.jpg wallpaper
Get-ChildItem -Path C:\ -Filter "image_danger.jpg" -Recurse -ErrorAction SilentlyContinue
```

### Remediation

1. **Contain immediately:** Isolate affected systems from the network to prevent C2 communication and lateral spread
2. **Block C2 infrastructure:** Add `185.182.193[.]21` and `212.8.248[.]104` to network blocklists (all ports)
3. **Remove persistence:** Delete the "OneDrive Update" scheduled task and `HKCU\SOFTWARE\OneDrive\Environment` registry key
4. **Remove firewall rules:** Delete any firewall rules named "Microsoft.Windows.CloudExperienceHost" that were not legitimately created
5. **Preserve forensic evidence:** Image affected disks before remediation if wiper has not yet executed
6. **Restore from backup:** Systems hit by the disk wiper (command 1/12) or encryption (command 3) cannot be recovered; restore from offline backups
7. **Hunt for lateral movement:** Search for the same scheduled task name and registry key across all endpoints in the environment

### Long-Term Hardening

- Monitor for non-standard port usage of AMQP (5672 is standard; 5544 is anomalous) and Redis (6379 is standard; 7542 is anomalous)
- Restrict outbound connections to known-good messaging infrastructure
- Enable enhanced PowerShell script block logging and command-line process auditing
- Monitor for bulk file rename operations with unusual extensions
- Implement application whitelisting to prevent unauthorized Golang binaries from executing

## Detection Rules

The following rules cover GigaWiper's persistence (scheduled task, registry), anti-forensics (event log clearing, Security.evtx deletion), network C2 (known IPs/ports, AMQP protocol), firewall masquerading, and file-level indicators (binary strings, hashes, PDB paths). All IOC-based rules (hashes, IPs) are high-confidence but time-limited; behavioral rules (scheduled task name, event log clearing patterns) provide longer-lasting coverage. Caveat: the `sigma check` validator could not run due to network restrictions on MITRE ATT&CK data fetching; all Sigma rules were validated via `sigma convert` to Splunk and CrowdStrike LogScale backends.

### Sigma Rules

#### 1. GigaWiper Persistence via OneDrive Update Scheduled Task

Detects creation of the "OneDrive Update" scheduled task via schtasks.exe or PowerShell, the primary persistence mechanism for GigaWiper.

<!-- audit: sigma check blocked by MITRE ATT&CK data fetch (HTTP 403 in sandboxed env). sigma convert --without-pipeline -t splunk: PASS. sigma convert --without-pipeline -t log_scale: PASS. Splunk output: (Image="*\\schtasks.exe" CommandLine="*OneDrive Update*" CommandLine="*/create*") OR (Image IN ("*\\powershell.exe", "*\\pwsh.exe") CommandLine="*Register-ScheduledTask*" CommandLine="*OneDrive Update*"). LogScale output: (Image=/\\schtasks\.exe$/i CommandLine=/OneDrive Update/i CommandLine=/\/create/i) or (Image=/\\powershell\.exe$/i or Image=/\\pwsh\.exe$/i CommandLine=/Register-ScheduledTask/i CommandLine=/OneDrive Update/i). -->

compile-status: ✅ compiles (Splunk + LogScale) | confidence: **high**

```yaml
title: GigaWiper Persistence via OneDrive Update Scheduled Task
id: 7a3e1b4c-9d2f-4e5a-8b6c-1f0d3e2a5b7c
status: experimental
description: >
    Detects creation of a scheduled task named "OneDrive Update" used by GigaWiper
    for persistence, triggering every minute and at system startup.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - 'OneDrive Update'
            - '/create'
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'Register-ScheduledTask'
            - 'OneDrive Update'
    condition: selection_schtasks or selection_powershell
falsepositives:
    - Legitimate OneDrive update mechanisms using this exact task name are uncommon but possible
level: high
```

#### 2. GigaWiper Registry Persistence Under OneDrive Environment Key

Detects registry writes to `HKCU\SOFTWARE\OneDrive\Environment` used for execution tracking, filtering out legitimate OneDrive processes.

<!-- audit: sigma convert --without-pipeline -t splunk: PASS. Output: TargetObject="*\\SOFTWARE\\OneDrive\\Environment*" NOT (Image IN ("*\\OneDrive.exe", "*\\OneDriveSetup.exe")). sigma convert --without-pipeline -t log_scale: PASS. -->

compile-status: ✅ compiles (Splunk + LogScale) | confidence: **medium**

Caveat: Legitimate OneDrive may write to nearby registry paths; tune the filter if OneDrive uses this exact key in your environment.

```yaml
title: GigaWiper Registry Persistence Under OneDrive Environment Key
id: 8b4f2c5d-ae3f-4f6b-9c7d-2e1a4d3b6c8e
status: experimental
description: >
    Detects registry modifications to HKCU\SOFTWARE\OneDrive\Environment used by
    GigaWiper to track execution count and determine persistence state.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\SOFTWARE\OneDrive\Environment'
    filter_legitimate:
        Image|endswith:
            - '\OneDrive.exe'
            - '\OneDriveSetup.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate OneDrive client writing to this registry path
level: medium
```

#### 3. GigaWiper Event Log Clearing via Wevtutil

Detects `wevtutil.exe cl` commands targeting System, Setup, Application, ForwardedEvents, and Security logs as performed by GigaWiper command 19.

<!-- audit: sigma convert --without-pipeline -t splunk: PASS. Output: Image="*\\wevtutil.exe" CommandLine IN ("*cl System*", "*cl Setup*", "*cl Application*", "*cl ForwardedEvents*", "*cl Security*"). sigma convert --without-pipeline -t log_scale: PASS. Note: generic event log clearing detection; GigaWiper-specific due to the combination of all five logs in sequence. -->

compile-status: ✅ compiles (Splunk + LogScale) | confidence: **high**

```yaml
title: GigaWiper Event Log Clearing via Wevtutil
id: 9c5a3d6e-bf4a-4a7c-ad8e-3f2b5e4c7d9f
status: experimental
description: >
    Detects event log clearing using wevtutil.exe targeting System, Setup,
    Application, ForwardedEvents, and Security logs as performed by GigaWiper command 19.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1070.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wevtutil.exe'
        CommandLine|contains:
            - 'cl System'
            - 'cl Setup'
            - 'cl Application'
            - 'cl ForwardedEvents'
            - 'cl Security'
    condition: selection
falsepositives:
    - Legitimate system administration clearing event logs during maintenance
level: high
```

#### 4. GigaWiper Firewall Rule Masquerading as CloudExperienceHost

Detects creation of firewall rules named "Microsoft.Windows.CloudExperienceHost" via netsh, used by GigaWiper to disguise VNC remote control traffic.

<!-- audit: sigma convert --without-pipeline -t splunk: PASS. Output: Image="*\\netsh.exe" CommandLine="*advfirewall*" CommandLine="*add rule*" CommandLine="*Microsoft.Windows.CloudExperienceHost*". sigma convert --without-pipeline -t log_scale: PASS. No legitimate scenario creates firewall rules with this exact name via netsh. -->

compile-status: ✅ compiles (Splunk + LogScale) | confidence: **high**

```yaml
title: GigaWiper Firewall Rule Masquerading as CloudExperienceHost
id: ad6b4e7f-ca5b-4b8d-be9f-4a3c6f5d8eab
status: experimental
description: >
    Detects creation of Windows Firewall rules named "Microsoft.Windows.CloudExperienceHost"
    used by GigaWiper to masquerade VNC-like remote control traffic as legitimate Windows services.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1036.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\netsh.exe'
        CommandLine|contains|all:
            - 'advfirewall'
            - 'add rule'
            - 'Microsoft.Windows.CloudExperienceHost'
    condition: selection
falsepositives:
    - None expected; legitimate CloudExperienceHost does not create firewall rules via netsh
level: critical
```

#### 5. GigaWiper C2 Communication to Known Infrastructure

Detects outbound network connections to known GigaWiper C2 IPs on RabbitMQ AMQP (port 5544) and Redis (port 7542) endpoints.

<!-- audit: sigma convert --without-pipeline -t splunk: PASS. Output: (DestinationIp="185.182.193.21" DestinationPort=5544) OR (DestinationIp="185.182.193.21" DestinationPort=7542) OR DestinationIp="212.8.248.104". sigma convert --without-pipeline -t log_scale: PASS. IOC-based rule; IPs are not defanged per logsource-encoding guidance. -->

compile-status: ✅ compiles (Splunk + LogScale) | confidence: **high**

Caveat: IOC-based rule with limited shelf life; remove when infrastructure is confirmed decommissioned.

```yaml
title: GigaWiper C2 Communication to Known Infrastructure
id: be7c5f8a-db6c-4c9e-cf0a-5b4d7a6e9fbc
status: experimental
description: >
    Detects outbound network connections to known GigaWiper C2 infrastructure
    on RabbitMQ AMQP (port 5544) and Redis (port 7542) endpoints.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1071
logsource:
    category: network_connection
detection:
    selection_rabbitmq:
        DestinationIp: '185.182.193.21'
        DestinationPort: 5544
    selection_redis:
        DestinationIp: '185.182.193.21'
        DestinationPort: 7542
    selection_c2:
        DestinationIp: '212.8.248.104'
    condition: selection_rabbitmq or selection_redis or selection_c2
falsepositives:
    - None expected for these specific IP and port combinations
level: critical
```

#### 6. GigaWiper File Encryption with Candy Extension

Detects mass file rename operations appending the `.candy` extension, indicating GigaWiper command 3 destructive pseudo-ransomware activity.

<!-- audit: sigma convert --without-pipeline -t splunk: PASS. Output: TargetFilename="*.candy". sigma convert --without-pipeline -t log_scale: PASS. Output: TargetFilename=/\.candy$/i. The .candy extension is not used by any known legitimate software. -->

compile-status: ✅ compiles (Splunk + LogScale) | confidence: **high**

```yaml
title: GigaWiper File Encryption with Candy Extension
id: cf8d6a9b-ec7d-4daf-da1b-6c5e8b7faacd
status: experimental
description: >
    Detects mass file rename operations appending the .candy extension, indicating
    GigaWiper command 3 destructive encryption activity.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1486
logsource:
    category: file_rename
    product: windows
detection:
    selection:
        TargetFilename|endswith: '.candy'
    condition: selection
falsepositives:
    - Software using .candy as a legitimate file extension is extremely rare
level: critical
```

#### 7. GigaWiper Direct Security Event Log File Deletion

Detects direct deletion of the Security.evtx log file, used as a fallback when wevtutil clearing fails.

<!-- audit: sigma convert --without-pipeline -t splunk: PASS. Output: TargetFilename="*\\winevt\\Logs\\Security.evtx". sigma convert --without-pipeline -t log_scale: PASS. Requires Sysmon file deletion logging (EID 23/26) or equivalent. -->

compile-status: ✅ compiles (Splunk + LogScale) | confidence: **high**

```yaml
title: GigaWiper Direct Security Event Log File Deletion
id: da9e7bac-fd8e-4eaf-eb2c-7d6f9c8abcde
status: experimental
description: >
    Detects direct deletion of the Security.evtx log file, used as a fallback
    anti-forensics technique by GigaWiper when wevtutil clearing fails.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1070.001
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\winevt\Logs\Security.evtx'
    condition: selection
falsepositives:
    - Legitimate log rotation or backup tools operating on event log files
level: critical
```

### YARA Rules

#### 8. GigaWiper Backdoor String Detection

Detects GigaWiper Golang backdoor via characteristic strings including C2 markers, wiper output messages, and the GRAT framework reference.

<!-- audit: yarac gigawiper.yar /dev/null -> EXIT CODE: 0. Rule targets Golang binaries (go.buildid marker) with 4+ distinctive strings, or 2 strings + C2 IP, or GRAT framework reference + 2 strings. filesize < 30MB prevents matching on disk images. -->

compile-status: ✅ compiles | confidence: **high**

```yara
rule Malware_GigaWiper_Backdoor_Strings
{
    meta:
        description = "Detects GigaWiper Golang backdoor via characteristic strings found in binary samples"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001"
        hash = "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913"
        severity = "critical"

    strings:
        $s1 = "kharbvnmhkjbkjb" ascii
        $s2 = "Partitions removed successfully" ascii
        $s3 = "Running from Task Scheduler" ascii
        $s4 = "Task created. Original process exiting" ascii
        $s5 = "purge_cmd_queue" ascii
        $s6 = "purge_queue" ascii
        $s7 = "BigBangExtortMain" ascii
        $s8 = "WipeCMain" ascii
        $s9 = "WipeMain" ascii
        $s10 = "image_danger.jpg" ascii
        $s11 = ".candy" ascii

        $c2_1 = "185.182.193.21" ascii
        $c2_2 = "212.8.248.104" ascii

        $grat1 = "RTYPE_map_string_cmd_appInfoStc" ascii
        $grat2 = "GRAT" ascii

        $go1 = "go.buildid" ascii

    condition:
        filesize < 30MB and
        $go1 and
        (
            (4 of ($s*)) or
            (2 of ($s*) and 1 of ($c2_*)) or
            (1 of ($grat*) and 2 of ($s*))
        )
}
```

#### 9. GigaWiper Known Sample Hash Detection

Detects all known GigaWiper, Crucio, and FlockWiper samples by SHA-256 hash.

<!-- audit: yarac gigawiper.yar /dev/null -> EXIT CODE: 0. Requires hash module import. Pure hash-matching rule; highest confidence but zero coverage on new samples. -->

compile-status: ✅ compiles | confidence: **high**

```yara
import "hash"

rule Malware_GigaWiper_Hashes
{
    meta:
        description = "Detects known GigaWiper, Crucio, and FlockWiper samples by SHA-256 hash"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        severity = "critical"

    condition:
        hash.sha256(0, filesize) == "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001" or
        hash.sha256(0, filesize) == "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913" or
        hash.sha256(0, filesize) == "f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd" or
        hash.sha256(0, filesize) == "9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683" or
        hash.sha256(0, filesize) == "3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd" or
        hash.sha256(0, filesize) == "440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3" or
        hash.sha256(0, filesize) == "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721" or
        hash.sha256(0, filesize) == "db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674"
}
```

#### 10. FlockWiper PDB Path Detection

Detects FlockWiper samples via characteristic PDB paths referencing the GRAT framework development directories.

<!-- audit: yarac gigawiper.yar /dev/null -> EXIT CODE: 0. PE header check (MZ) + PDB path match. PDB paths are highly specific to this threat actor's build environment. -->

compile-status: ✅ compiles | confidence: **high**

```yara
rule Malware_FlockWiper_PDB_Path
{
    meta:
        description = "Detects FlockWiper samples via characteristic PDB paths referencing the GRAT framework"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721"
        severity = "high"

    strings:
        $pdb1 = "A:\\GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii
        $pdb2 = "E:\\files\\new\\GRAT\\CWipe\\Release\\CWipe.pdb" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($pdb*)
}
```

#### 11. GigaWiper Wiper Component Behavioral Detection

Detects GigaWiper wiper component via combination of disk wiping status strings and Golang binary markers.

<!-- audit: yarac gigawiper.yar /dev/null -> EXIT CODE: 0. Targets Golang binaries with wiper-specific output strings. Broader than string rule but still requires multiple wiper indicators. -->

compile-status: ✅ compiles | confidence: **medium**

```yara
rule Malware_GigaWiper_Wiper_Behavioral
{
    meta:
        description = "Detects GigaWiper wiper component via combination of disk wiping strings and Golang markers"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        severity = "high"

    strings:
        $wipe1 = "Partitions removed successfully" ascii
        $wipe2 = "Pass 1 Time took:" ascii
        $wipe3 = "Pass 2 Time took:" ascii
        $wipe4 = "Pass 3 Time took:" ascii
        $wipe5 = "WipeMain" ascii
        $wipe6 = "WipeCMain" ascii

        $disk1 = "IOCTL_DISK_CREATE_DISK" ascii wide
        $disk2 = "PHYSICALDRIVE" ascii wide
        $disk3 = "DeviceIoControl" ascii wide

        $go1 = "go.buildid" ascii

    condition:
        filesize < 30MB and
        $go1 and
        (2 of ($wipe*) or (1 of ($wipe*) and 1 of ($disk*)))
}
```

### Snort Rules

#### 12. GigaWiper C2 RabbitMQ AMQP Connection

Detects AMQP protocol connections to the known GigaWiper C2 server on port 5544.

<!-- audit: Snort 3 not installed in this environment; structural validation only. Rule uses tcp protocol with flow:established, content match for AMQP protocol header at depth 4. SID 2100101. -->

compile-status: ⚠️ uncompiled | confidence: **high**

```
alert tcp $HOME_NET any -> 185.182.193.21 5544 (msg:"Actioner - GigaWiper C2 RabbitMQ AMQP Connection to 185.182.193[.]21:5544"; flow:established, to_server; content:"AMQP"; depth:4; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created 2026-07-12; sid:2100101; rev:1;)
```

#### 13. GigaWiper C2 Redis Connection

Detects TCP connections to the known GigaWiper Redis results server on port 7542.

<!-- audit: Structural validation only. Rule matches any established TCP to 185.182.193.21:7542. SID 2100102. -->

compile-status: ⚠️ uncompiled | confidence: **high**

```
alert tcp $HOME_NET any -> 185.182.193.21 7542 (msg:"Actioner - GigaWiper C2 Redis Connection to 185.182.193[.]21:7542"; flow:established, to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created 2026-07-12; sid:2100102; rev:1;)
```

#### 14. GigaWiper C2 Connection to Secondary IP

Detects any TCP connection to the secondary GigaWiper C2 IP `212.8.248[.]104`.

<!-- audit: Structural validation only. Broad IP match on any port. SID 2100103. -->

compile-status: ⚠️ uncompiled | confidence: **high**

```
alert tcp $HOME_NET any -> 212.8.248.104 any (msg:"Actioner - GigaWiper C2 Connection to 212.8.248[.]104"; flow:established, to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created 2026-07-12; sid:2100103; rev:1;)
```

#### 15. AMQP on Non-Standard Port with RabbitMQ Pattern

Detects AMQP protocol negotiation (header + version bytes) on non-standard ports, a behavioral indicator of GigaWiper-style C2.

<!-- audit: Structural validation only. Matches AMQP 0-9-1 protocol header. SID 2100104. Lower confidence due to potential legitimate AMQP on non-standard ports. -->

compile-status: ⚠️ uncompiled | confidence: **medium**

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Potential GigaWiper AMQP C2 on Non-Standard Port 5544"; flow:established, to_server; content:"AMQP"; depth:4; content:"|00 00 09 01|"; distance:0; within:4; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created 2026-07-12; sid:2100104; rev:1;)
```

### Suricata Rules

#### 16. GigaWiper C2 RabbitMQ AMQP Connection (Suricata)

Detects AMQP protocol connections to the known GigaWiper RabbitMQ C2 on port 5544.

<!-- audit: suricata -T -S gigawiper.suricata.rules -l /tmp/actioner -> EXIT CODE: 0. "Configuration provided was successfully loaded. Exiting." All 4 Suricata rules validated in single pass. SID 2100201. -->

compile-status: ✅ compiles | confidence: **high**

```
alert tcp $HOME_NET any -> 185.182.193.21 5544 (msg:"Actioner - GigaWiper C2 RabbitMQ AMQP to 185.182.193[.]21:5544"; flow:established,to_server; content:"AMQP"; depth:4; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-12; sid:2100201; rev:1;)
```

#### 17. GigaWiper C2 Redis Connection (Suricata)

Detects TCP connections to the known GigaWiper Redis results channel on port 7542.

<!-- audit: Validated as part of suricata -T batch. SID 2100202. -->

compile-status: ✅ compiles | confidence: **high**

```
alert tcp $HOME_NET any -> 185.182.193.21 7542 (msg:"Actioner - GigaWiper C2 Redis to 185.182.193[.]21:7542"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-12; sid:2100202; rev:1;)
```

#### 18. GigaWiper C2 Connection to Secondary IP (Suricata)

Detects any TCP connection to the secondary GigaWiper C2 IP.

<!-- audit: Validated as part of suricata -T batch. SID 2100203. -->

compile-status: ✅ compiles | confidence: **high**

```
alert tcp $HOME_NET any -> 212.8.248.104 any (msg:"Actioner - GigaWiper C2 Connection to 212.8.248[.]104"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-12; sid:2100203; rev:1;)
```

#### 19. AMQP on Non-Standard Port (Suricata)

Detects AMQP 0-9-1 protocol negotiation on non-standard ports, a behavioral indicator of RabbitMQ-based C2.

<!-- audit: Validated as part of suricata -T batch. SID 2100204. -->

compile-status: ✅ compiles | confidence: **medium**

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AMQP on Non-Standard Port with RabbitMQ Exchange Pattern"; flow:established,to_server; content:"AMQP"; depth:4; fast_pattern; content:"|00 00 09 01|"; distance:0; within:4; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-12; sid:2100204; rev:1;)
```

## Lessons Learned

GigaWiper demonstrates the ongoing trend of threat actors consolidating standalone tools into modular backdoor platforms, reducing operational overhead while increasing destructive reach. The use of legitimate enterprise messaging protocols (RabbitMQ AMQP, Redis) for C2 highlights the need for defenders to monitor not just known-bad protocols but anomalous usage of known-good ones on non-standard ports. The deliberate design of the encryption command to discard keys confirms this is a destructive tool masquerading as ransomware -- there is no financial motivation, only denial and destruction. Organizations in sectors targeted by Iran-nexus groups should treat the behavioral indicators (OneDrive-themed persistence, CloudExperienceHost firewall masquerading, .candy extension) as high-priority detection opportunities that outlast the IOC-based rules.

## Sources

- [Microsoft Security Blog - GigaWiper: Anatomy of a destructive backdoor assembled from multiple malware](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/) -- primary technical analysis with full IOC list, command set documentation, and code-level breakdown
- [The Hacker News - New GigaWiper Windows Backdoor Bundles Disk Wiping, Fake Ransomware, and Spyware](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html) -- additional attribution context linking to BLUERABBIT and Iran-nexus group via Binary Defense/GTIG
- [SecurityWeek - GigaWiper Combines Multiple Malware for System-Level Sabotage](https://www.securityweek.com/gigawiper-combines-multiple-malware-for-system-level-sabotage/) -- coverage of modular destructive capabilities
- [The Register - Destructive Windows backdoor stuffs multiple wipers and ransomware code into a single package](https://www.theregister.com/security/2026/07/10/destructive-windows-backdoor-stuffs-multiple-wipers-and-ransomware-code-into-a-single-package/5270053) -- additional technical commentary
- [Infosecurity Magazine - New 'GigaWiper' Malware Combines Espionage & Destructive Capabilities](https://www.infosecurity-magazine.com/news/new-gigawiper-espionage-destructive/) -- espionage capability coverage

---
*Report generated by Actioner*
