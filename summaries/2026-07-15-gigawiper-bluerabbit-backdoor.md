# Technical Analysis Report: GigaWiper (BLUERABBIT) Destructive Backdoor (2026-07-15)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-15
Version: 0.1 (DRAFT)

## Executive Summary

GigaWiper is a Golang-based destructive Windows backdoor that consolidates components from at least three previously separate malware families -- Crucio ransomware, FlockWiper, and a standalone disk wiper -- into a single multi-capability platform. First identified by Microsoft in October 2025 (with Binary Defense first observing it in March 2026), GigaWiper supports 20 command codes spanning physical disk wiping, pseudo-ransomware encryption (files renamed to `.candy` with unsaved keys), multi-pass secure wiping, screenshots, screen recording, VNC-like remote access, keylogging stubs, event log clearing, process/service/registry management, and PowerShell execution. The malware uses RabbitMQ (AMQP) for receiving C2 commands, Redis for returning results, and MinIO for exfiltration -- abusing legitimate enterprise messaging infrastructure. Google Threat Intelligence Group (GTIG) and Binary Defense track it as BLUERABBIT. Code fingerprints (PDB paths referencing "GRAT", shared function naming patterns) connect GigaWiper to CyberAv3ngers/IRGC-affiliated actors via a December 2023 CISA advisory on Crucio ransomware, with targets including Israeli organizations and critical infrastructure (water, energy) in the US, UK, and Ireland.

## Background: GigaWiper / BLUERABBIT

GigaWiper represents a trend of threat actors investing in operational efficiency by merging standalone destructive tools into unified platforms. The malware is compiled as unstripped Go portable executables for Windows, existing in two variants: standalone wiper binaries and larger binaries with full backdoor functionality. The "GRAT" framework tag appears in both FlockWiper PDB paths and GigaWiper function names (e.g., `rabbit_tools_tool_wipe_main`, `rabbit_tools_tool_ran_main`, `rabbit_bin.RunOnceRegistryMain`), suggesting a shared development framework with potentially undiscovered additional components. The evolution from Crucio (December 2023) through FlockWiper (June 2025, C-based) to GigaWiper (October 2025, Golang reimplementation) shows sustained development by the same actor.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| December 2023 | CISA advisory published on Crucio ransomware linking to CyberAv3ngers/IRGC |
| June 2025 | FlockWiper (C-based standalone wiper) observed in the wild |
| October 2025 | GigaWiper first identified by Microsoft -- consolidates Crucio, FlockWiper, and disk wiper |
| March 2026 | Binary Defense first observes GigaWiper samples |
| 2026-07-09 | Microsoft publishes detailed technical analysis of GigaWiper |

## Root Cause: Initial Access Vector

The initial access vector is not specified in the available source material. Microsoft's analysis focuses on post-compromise backdoor capabilities and destructive payloads. The malware is deployed after initial compromise of Windows environments.

## Technical Analysis of the Malicious Payload

### 1. Persistence and Initialization

On first execution, GigaWiper checks for the registry key `HKCU\SOFTWARE\OneDrive\Environment`. If absent, it creates a scheduled task named **"OneDrive Update"** via PowerShell that runs every minute and at system startup, then exits. On subsequent executions (registry key present), it proceeds with normal C2 communication. The scheduled task masquerades as a legitimate OneDrive component.

### 2. Command and Control Infrastructure

GigaWiper uses a dual-channel C2 architecture abusing legitimate enterprise messaging software:

- **RabbitMQ (AMQP)** on port 5544 for receiving commands -- uses a fanout exchange named "All" for broadcast commands and a topic exchange named "Topic" for targeted commands via routing keys
- **Redis** on port 7542 for returning command status and output
- **MinIO** for file exfiltration

C2 credentials are hard-coded in AES-encrypted configuration within the binary. Commands are structured as `cmd.Task` objects (task_id, command_code, args) with responses as `cmd.Result` objects (error, target_ip, task_id, target_computer_name, output, pwd, time, status, work_status).

### 3. Destructive Capabilities (20 Command Codes)

**Command 1 -- WipeMain (Physical Disk Wiper):** Operates at the physical disk level using `DeviceIoControl` with `IOCTL_DISK_CREATE_DISK` to remove partition metadata, then overwrites raw disk content in 0xA00000-byte (10 MB) chunks. Uses a random first byte followed by zero-filled remainder -- possibly to evade detections looking for full-disk zeroing.

**Command 2 -- BSOD Trigger:** Disables Windows recovery, takes ownership of boot/kernel files (bootmgr, ntoskrnl.exe) via `takeown` and `icacls`, then deletes them to force a Blue Screen of Death.

**Command 3 -- BigBangExtortMain/RanMain (Pseudo-Ransomware):** Derived from Crucio ransomware. Encrypts files using AES-256-CBC with randomly generated keys that are **never saved**, making decryption impossible. Files are renamed with the `.candy` extension. No ransom note is deployed -- this is purely destructive.

**Command 12 -- WipeCMain (Windows Drive Wiper):** Targets the Windows installation drive only. Performs multi-pass secure wiping (pass 1: zeros, pass 2: 0xFF, pass 3: random bytes) with timing output per pass.

### 4. Espionage and Remote Access Capabilities

**Command 7 -- PowerShell Execution:** Executes PowerShell commands with output parsing via the pattern `;"|?????|$pwd"` and maintains working directory context between commands using `os.Chdir`. Supports special operations: `purge_cmd_queue`, `purge_queue`, `pwd`.

**Command 9 -- Screenshots:** Captures per-monitor screenshots saved as `.\<timestamp>\<monitor_index>.png`.

**Command 10 -- Screen Recording:** Saves recordings to `C:\ProgramData\output`.

**Command 15 -- System Profiling (GRATClientInfo):** Collects system information including antivirus detection via PowerShell: `Get-CimInstance Win32_PnPEntity | Where-Object {$_.Name -match 'Antivirus|Endpoint'} | ConvertTo-Json`.

**Command 16 -- Process Management:** Supports createProcess, resumeProcess, suspendProcess, killProcess, list, processInfo.

**Command 17 -- Service Management:** Supports create, delete, restart, query, start, list, stop.

**Command 18 -- Registry Manager (RunOnceRegistryMain):** Interactive registry browser with operations: show, navigate, back, exit, createKey, deleteKey, deleteValue, setValue.

**Command 20 -- VNC-like Remote Desktop:** Establishes remote desktop control over TCP on an attacker-specified port with keyboard, mouse, and screen streaming. Creates Windows Firewall rules masquerading as "Microsoft.Windows.CloudExperienceHost" for inbound/outbound access.

### 5. Anti-Forensics / Evasion Techniques

**Command 19 -- Event Log Clearing:** Clears System, Setup, Application, ForwardedEvents, and Security logs via `wevtutil.exe cl`. Falls back to manual deletion of `C:\Windows\System32\winevt\Logs\Security.evtx` if the Security log clear fails. Prints the string "kharbvnmhkjbkjb" during execution (purpose unknown).

**Additional evasion:** Unsaved encryption keys render file recovery impossible; partition metadata removal precedes disk wiping; firewall rule names impersonate legitimate Windows components; the random-first-byte wiping pattern may evade zeroing-based detections.

**Stub/Unpopulated Commands:** Commands 6 (wipe-file), 11 (keylog), and 13 (wipe32) are logged but not yet implemented, suggesting active development.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `185.182.193[.]21`)

### File System

| Platform | Path / Name | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | GigaWiper backdoor sample 1 | `633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001` | Full backdoor binary |
| Windows | GigaWiper backdoor sample 2 | `ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913` | Full backdoor binary |
| Windows | GigaWiper backdoor sample 3 | `f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd` | Full backdoor binary |
| Windows | GigaWiper backdoor sample 4 | `9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683` | Full backdoor binary |
| Windows | Standalone wiper | `3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd` | Standalone wiper binary |
| Windows | Crucio ransomware | `440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3` | Related Crucio sample |
| Windows | FlockWiper sample 1 | `12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721` | FlockWiper (C-based) |
| Windows | FlockWiper sample 2 | `db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674` | FlockWiper (C-based) |
| Windows | `C:\ProgramData\output` | -- | Screen recording storage directory |
| Windows | `.\<timestamp>\<monitor_index>.png` | -- | Screenshot output files |
| Windows | `.\image_danger.jpg` | -- | Wallpaper image dropped by malware |
| Windows | `key.txt` | -- | Encryption key file (Command 5) |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP:Port | `185.182.193[.]21:5544` | RabbitMQ (AMQP) C2 server |
| IP:Port | `185.182.193[.]21:7542` | Redis results server |
| IP | `212.8.248[.]104` | Alternative C2 IP |

### Behavioral

- **Scheduled Task Persistence:** Creation of "OneDrive Update" scheduled task running every minute and at startup
- **Registry Tracking:** `HKCU\SOFTWARE\OneDrive\Environment` stores execution count for first-run vs. subsequent-run logic
- **RabbitMQ/Redis from Desktops:** AMQP (port 5544) and Redis (port 7542) traffic originating from ordinary Windows desktops rather than servers
- **Boot File Ownership Changes:** Processes using `takeown` and `icacls` to take ownership of `bootmgr` and `ntoskrnl.exe` outside maintenance windows
- **Event Log Clearing:** Batch clearing of System, Setup, Application, ForwardedEvents, and Security logs via `wevtutil.exe cl`
- **Firewall Rule Masquerading:** Rules named "Microsoft.Windows.CloudExperienceHost" for attacker-controlled port access
- **File Encryption with .candy Extension:** Files encrypted and renamed with `.candy` extension (no ransom note)
- **PowerShell AV Detection:** `Get-CimInstance Win32_PnPEntity | Where-Object {$_.Name -match 'Antivirus|Endpoint'}`
- **Physical Disk Access:** Use of `DeviceIoControl` with `IOCTL_DISK_CREATE_DISK` for partition removal
- **PDB Path Artifacts:** `A:\GRAT\CWipeNew\Release\CWipeNew.pdb` and `E:\files\new\GRAT\CWipe\Release\CWipe.pdb` in FlockWiper samples

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1053.005 | Scheduled Task | "OneDrive Update" task created for persistence, runs every minute + at startup |
| T1112 | Modify Registry | HKCU\SOFTWARE\OneDrive\Environment for execution tracking; registry manager (Command 18) |
| T1059.001 | PowerShell | Command 7 PowerShell execution with output parsing; AV enumeration; scheduled task creation |
| T1561.001 | Disk Content Wipe | Command 1 (WipeMain) overwrites raw disk via DeviceIoControl; Command 12 (WipeCMain) multi-pass |
| T1561.002 | Disk Structure Wipe | IOCTL_DISK_CREATE_DISK removes partition metadata before content wiping |
| T1486 | Data Encrypted for Impact | Command 3 AES-256-CBC encryption with unsaved keys; .candy extension |
| T1529 | System Shutdown/Reboot | Command 2 BSOD via boot file deletion (bootmgr, ntoskrnl.exe) |
| T1070.001 | Clear Windows Event Logs | Command 19 clears all major event logs via wevtutil.exe |
| T1113 | Screen Capture | Command 9 per-monitor screenshots; Command 10 screen recording |
| T1219 | Remote Access Software | Command 20 VNC-like remote desktop with screen streaming, keyboard/mouse |
| T1562.004 | Disable or Modify System Firewall | Firewall rules created masquerading as "Microsoft.Windows.CloudExperienceHost" |
| T1057 | Process Discovery | Command 16 process listing and information gathering |
| T1007 | System Service Discovery | Command 17 service listing and management |
| T1082 | System Information Discovery | Command 15 system profiling via WMI/CIM |
| T1518.001 | Security Software Discovery | PowerShell WMI query for antivirus/endpoint products |
| T1571 | Non-Standard Port | RabbitMQ on port 5544, Redis on port 7542 (non-default ports) |
| T1071 | Application Layer Protocol | RabbitMQ (AMQP) for C2 commands, Redis protocol for results |
| T1222.001 | Windows File and Directory Permissions Modification | takeown/icacls on boot files before deletion |

## Impact Assessment

GigaWiper poses severe risk due to its combination of multiple destructive capabilities in a single platform. The physical disk wiper (Command 1) and partition metadata removal render standard file recovery impossible. The pseudo-ransomware module uses unsaved encryption keys, making decryption unachievable even with full cooperation. The multi-pass wiper (Command 12) ensures forensic recovery of the Windows installation drive is infeasible. Attribution to CyberAv3ngers/IRGC-affiliated actors and targeting of critical infrastructure (water, energy) in Israel, the US, UK, and Ireland elevates the geopolitical significance. The presence of stub commands (6, 11, 13) indicates active development with additional capabilities likely forthcoming.

## Detection & Remediation

### Immediate Detection

- Search for scheduled tasks named "OneDrive Update" with 1-minute repeat intervals: `schtasks /query /tn "OneDrive Update" /v`
- Check for registry key: `reg query "HKCU\SOFTWARE\OneDrive\Environment"`
- Monitor for AMQP traffic on port 5544 or Redis traffic on port 7542 from desktop endpoints
- Search for `.candy` file extensions on file shares
- Check for firewall rules named "Microsoft.Windows.CloudExperienceHost"
- Look for `C:\ProgramData\output` directory containing screen recordings

### Remediation

1. **Contain:** Isolate affected hosts immediately; block C2 IPs (185.182.193[.]21, 212.8.248[.]104) at perimeter
2. **Eradicate:** Remove "OneDrive Update" scheduled task; delete HKCU\SOFTWARE\OneDrive\Environment registry key; remove malicious firewall rules; scan with updated AV signatures (Microsoft Defender detections: Giga, Wiper, FlockWiper, CutBrooch)
3. **Recover:** Restore from known-good backups (disk-wiped or encrypted systems cannot be recovered in place)
4. **Harden:** Enable tamper protection on endpoint security products; restrict RabbitMQ/Redis/AMQP traffic to authorized servers only

### Long-Term Hardening

- Monitor for anomalous AMQP/Redis traffic from non-server endpoints
- Implement application allowlisting to prevent unauthorized Go binaries
- Enable PowerShell script block logging and command-line auditing (Event ID 4688)
- Restrict `takeown` and `icacls` usage via AppLocker or WDAC policies
- Maintain offline backups for critical systems given the destructive nature of this threat

## Detection Rules

These detections target GigaWiper-specific artifacts at PoC/advisory-specific altitude: the distinctive scheduled task name, C2 infrastructure ports, event log clearing pattern, boot file ownership changes, and known file hashes. Sigma rules convert to Splunk and CrowdStrike LogScale; YARA targets file-level indicators. Snort/Suricata rules are structural-only (compilers not installed). Compiles does not equal fires -- verify in your pipeline.

### Sigma: GigaWiper OneDrive Update Scheduled Task Persistence

Detects creation of the "OneDrive Update" scheduled task used by GigaWiper for persistence with 1-minute repeat interval.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE ATT&CK data URL 403 in this env); splunk convert 0; log_scale convert 0 — portability proven. Keys on exact task name "OneDrive Update" in schtasks or PowerShell context, which is distinctive to this malware (legitimate OneDrive does not use this task name pattern). FP: custom admin scripts reusing the exact name, which is unlikely. -->
```yaml
title: GigaWiper OneDrive Update Scheduled Task Persistence
id: c7a3e1b4-8f2d-4e6a-9c01-3b5d7f9a2e84
status: experimental
description: >
    Detects creation of the OneDrive Update scheduled task used by GigaWiper
    for persistence. The task runs every minute and at system startup.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/15
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
            - '/Create'
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'OneDrive Update'
            - 'New-ScheduledTask'
    condition: selection_schtasks or selection_powershell
falsepositives:
    - Custom administrative scripts that create tasks named OneDrive Update
level: high
```

### Sigma: GigaWiper Boot File Ownership Takeover

Detects use of takeown/icacls against Windows boot files (bootmgr, ntoskrnl.exe), a precursor to GigaWiper BSOD attack (Command 2).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE ATT&CK data URL 403 in this env); splunk convert 0; log_scale convert 0 — portability proven. Keys on takeown or icacls targeting specific boot file names. These files should never have ownership changed outside OS servicing. FP: legitimate OS servicing or patching tools; scope to non-SYSTEM users or non-TrustedInstaller for production. -->
```yaml
title: GigaWiper Boot File Ownership Takeover
id: d8b4f2c5-9e3a-4f7b-a102-4c6e8a0b3f95
status: experimental
description: >
    Detects takeown or icacls commands targeting Windows boot files such as
    bootmgr or ntoskrnl.exe, consistent with GigaWiper Command 2 BSOD attack.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/15
tags:
    - attack.t1222.001
    - attack.t1529
logsource:
    category: process_creation
    product: windows
detection:
    selection_takeown:
        Image|endswith: '\takeown.exe'
        CommandLine|contains:
            - 'bootmgr'
            - 'ntoskrnl'
    selection_icacls:
        Image|endswith: '\icacls.exe'
        CommandLine|contains:
            - 'bootmgr'
            - 'ntoskrnl'
    condition: selection_takeown or selection_icacls
falsepositives:
    - OS servicing or patching operations by TrustedInstaller
level: critical
```

### Sigma: GigaWiper Bulk Event Log Clearing via wevtutil

Detects bulk clearing of Windows event logs via wevtutil.exe across multiple log channels, consistent with GigaWiper Command 19 anti-forensics.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE ATT&CK data URL 403 in this env); splunk convert 0; log_scale convert 0 — portability proven. Requires wevtutil.exe clearing event logs. A single "cl" is common for maintenance; this matches the specific "cl" action. For higher fidelity, correlate multiple clears within a short window (not expressible in a single Sigma rule). FP: legitimate log rotation scripts; scope to non-admin service accounts for production. -->
```yaml
title: GigaWiper Bulk Event Log Clearing via wevtutil
id: e9c5a3d6-0f4b-4a8c-b213-5d7f9a1c4a06
status: experimental
description: >
    Detects wevtutil.exe clearing event logs, consistent with GigaWiper
    Command 19 anti-forensics that clears System, Setup, Application,
    ForwardedEvents, and Security logs.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/15
tags:
    - attack.t1070.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wevtutil.exe'
        CommandLine|contains: ' cl '
    condition: selection
falsepositives:
    - Legitimate log maintenance or rotation scripts
    - SIEM log collection agents clearing logs after forwarding
level: high
```

### Sigma: GigaWiper Registry Tracking Key Access

Detects access to the HKCU\SOFTWARE\OneDrive\Environment registry key used by GigaWiper to track execution state and distinguish first-run from subsequent runs.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE ATT&CK data URL 403 in this env); splunk convert 0; log_scale convert 0 — portability proven. Keys on the specific registry path which is not used by legitimate OneDrive. Requires registry event logging (Sysmon EID 12/13). FP: unlikely; this exact path is not used by Microsoft OneDrive. -->
```yaml
title: GigaWiper Registry Tracking Key Access
id: f0d6b4e7-1a5c-4b9d-c324-6e8a0e2d5b17
status: experimental
description: >
    Detects creation or modification of the HKCU\SOFTWARE\OneDrive\Environment
    registry key used by GigaWiper to track execution count.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/15
tags:
    - attack.t1112
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|endswith: '\SOFTWARE\OneDrive\Environment'
    filter_onedrive:
        Image|endswith: '\OneDrive.exe'
    condition: selection and not filter_onedrive
falsepositives:
    - Legitimate OneDrive updates modifying similar registry paths
level: high
```

### Sigma: GigaWiper Firewall Rule Masquerading as CloudExperienceHost

Detects creation of Windows Firewall rules named "Microsoft.Windows.CloudExperienceHost" used by GigaWiper Command 20 for VNC-like remote access.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE ATT&CK data URL 403 in this env); splunk convert 0; log_scale convert 0 — portability proven. Keys on New-NetFirewallRule with specific display name. CloudExperienceHost is a UWP app that does not typically create firewall rules. FP: very unlikely; legitimate CloudExperienceHost firewall rules would be created by the OS, not via PowerShell. -->
```yaml
title: GigaWiper Firewall Rule Masquerading as CloudExperienceHost
id: a1e7c5f8-2b6d-4c0e-d435-7f9b1a3e6c28
status: experimental
description: >
    Detects PowerShell creation of firewall rules named
    Microsoft.Windows.CloudExperienceHost, used by GigaWiper for VNC access.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/15
tags:
    - attack.t1562.004
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'New-NetFirewallRule'
            - 'CloudExperienceHost'
    condition: selection
falsepositives:
    - Legitimate system administration creating firewall rules for CloudExperienceHost
level: high
```

### Sigma: GigaWiper AV Enumeration via WMI

Detects the specific WMI/CIM query pattern used by GigaWiper Command 15 to enumerate installed antivirus and endpoint security products.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check skipped (MITRE ATT&CK data URL 403 in this env); splunk convert 0; log_scale convert 0 — portability proven. Keys on the specific Get-CimInstance Win32_PnPEntity pattern with Antivirus|Endpoint filter. This exact combination is distinctive but some legitimate asset inventory tools may use similar queries. FP: IT inventory/compliance scripts querying PnP entities for security product inventory. -->
```yaml
title: GigaWiper AV Enumeration via WMI PnP Entity Query
id: b2f8d6a9-3c7e-4d1f-e546-8a0c2a4f7d39
status: experimental
description: >
    Detects the specific PowerShell WMI query pattern used by GigaWiper to
    enumerate antivirus and endpoint security products via Win32_PnPEntity.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/15
tags:
    - attack.t1518.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'Win32_PnPEntity'
            - 'Antivirus'
            - 'Endpoint'
    condition: selection
falsepositives:
    - IT asset inventory or compliance scanning scripts
level: medium
```

### Snort: GigaWiper RabbitMQ C2 on Non-Standard Port

Detects outbound AMQP traffic to port 5544, the non-standard port used by GigaWiper for RabbitMQ C2 communication.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural check passed. Keys on AMQP protocol header ("AMQP") to port 5544, which is non-standard for both AMQP (5672) and general traffic. FP: legitimate RabbitMQ deployments on port 5544, which is uncommon. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET 5544 (
    msg:"Actioner - GigaWiper RabbitMQ C2 AMQP on Non-Standard Port 5544";
    flow:established,to_server;
    content:"AMQP"; depth:4; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/;
    metadata:author Actioner, created 2026-07-15;
    sid:2100101;
    rev:1;
)
```

### Snort: GigaWiper Redis C2 on Non-Standard Port

Detects outbound Redis traffic to port 7542, the non-standard port used by GigaWiper for returning C2 results.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural check passed. Keys on Redis RESP protocol commands to port 7542 (non-standard; default Redis is 6379). FP: legitimate Redis on port 7542, which is uncommon. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET 7542 (
    msg:"Actioner - GigaWiper Redis C2 Results on Non-Standard Port 7542";
    flow:established,to_server;
    content:"*"; depth:1;
    content:"|0D 0A|"; distance:0; within:3;
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/;
    metadata:author Actioner, created 2026-07-15;
    sid:2100102;
    rev:1;
)
```

### Suricata: GigaWiper RabbitMQ C2 to Known IP

Detects AMQP connections to the known GigaWiper C2 IP on port 5544.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural check passed. Combines known C2 IP with AMQP protocol header detection. IOC-anchored; will age out when infrastructure rotates. -->
```suricata
alert tcp $HOME_NET any -> 185.182.193.21 5544 (
    msg:"Actioner - GigaWiper AMQP C2 to Known Infrastructure 185.182.193.21:5544";
    flow:established,to_server;
    content:"AMQP"; depth:4; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/;
    metadata:author Actioner, created_at 2026-07-15;
    sid:2200101;
    rev:1;
)
```

### Suricata: GigaWiper Redis C2 to Known IP

Detects Redis connections to the known GigaWiper C2 IP on port 7542.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural check passed. IOC-anchored to known C2 IP + non-standard Redis port. Will age out when infrastructure rotates. -->
```suricata
alert tcp $HOME_NET any -> 185.182.193.21 7542 (
    msg:"Actioner - GigaWiper Redis C2 Results to Known Infrastructure 185.182.193.21:7542";
    flow:established,to_server;
    content:"*"; depth:1;
    content:"|0D 0A|"; distance:0; within:3;
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/;
    metadata:author Actioner, created_at 2026-07-15;
    sid:2200102;
    rev:1;
)
```

### Suricata: GigaWiper Alternate C2 IP Connection

Detects any TCP connection to the known alternate GigaWiper C2 IP.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural check passed. Pure IOC match on alternate C2 IP. Will age out when infrastructure rotates. -->
```suricata
alert tcp $HOME_NET any -> 212.8.248.104 any (
    msg:"Actioner - GigaWiper Alternate C2 Connection to 212.8.248.104";
    flow:established,to_server;
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/;
    metadata:author Actioner, created_at 2026-07-15;
    sid:2200103;
    rev:1;
)
```

### YARA: GigaWiper Golang Backdoor Strings

Detects GigaWiper binaries via distinctive Go function names, internal strings, and framework references unique to the GRAT/BLUERABBIT tooling.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on positive (pos.txt containing published strings), quiet on negative. Keys on distinctive function names and internal strings from the GRAT framework that are unique to GigaWiper family binaries. No benign Go software uses these function/package names. -->
```yara
rule Malware_GigaWiper_BLUERABBIT_Strings
{
    meta:
        description = "Detects GigaWiper (BLUERABBIT) backdoor via distinctive Go function names and GRAT framework strings"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        severity = "critical"

    strings:
        $func1 = "rabbit_tools_tool_wipe_main" ascii
        $func2 = "rabbit_tools_tool_ran_main" ascii
        $func3 = "rabbit_tools_tool_wipec_main" ascii
        $func4 = "rabbit_bin.RunOnceRegistryMain" ascii
        $grat1 = "GRAT" ascii fullword
        $str1 = "Partitions removed successfully" ascii
        $str2 = "kharbvnmhkjbkjb" ascii
        $str3 = "Running from Task Scheduler" ascii
        $str4 = "Task created. Original process exiting." ascii
        $str5 = "purge_cmd_queue" ascii
        $str6 = "Exec cmd wipe-file" ascii
        $str7 = "Exec cmd keylog" ascii
        $str8 = "Exec cmd wipe32" ascii
        $pdb1 = "GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii
        $pdb2 = "GRAT\\CWipe\\Release\\CWipe.pdb" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            2 of ($func*) or
            (1 of ($func*) and 2 of ($str*)) or
            any of ($pdb*) or
            ($grat1 and 3 of ($str*))
        )
}
```

### YARA: GigaWiper Candy Ransomware Extension Dropper

Detects GigaWiper binaries containing the Crucio-derived ransomware module that encrypts files with the .candy extension using unsaved AES keys.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. No sample-test (distinctive strings are shorter, higher FP risk on synthetic positive). Keys on combination of .candy extension with encryption-related strings from the BigBangExtort/RanMain module. Medium confidence because .candy string alone is not unique; condition requires multiple corroborating strings. -->
```yara
rule Malware_GigaWiper_Crucio_Candy_Ransomware
{
    meta:
        description = "Detects GigaWiper Crucio-derived ransomware module with .candy file encryption"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        severity = "high"

    strings:
        $candy = ".candy" ascii
        $bigbang = "BigBangExtort" ascii
        $ranmain = "ran_main" ascii
        $keyreq = "Key/IV required" ascii
        $keyfile = "keyfile" ascii
        $wipe = "wipe_main" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $candy and
        (
            $bigbang or
            ($ranmain and 1 of ($keyreq, $keyfile)) or
            ($wipe and 2 of ($keyreq, $keyfile, $ranmain))
        )
}
```

## Lessons Learned

GigaWiper exemplifies the trend of threat actors consolidating standalone malware tools into unified, multi-capability platforms for operational efficiency. The use of legitimate enterprise messaging infrastructure (RabbitMQ, Redis, MinIO) for C2 and exfiltration complicates network-level detection, as these protocols may be allowed through corporate firewalls. The combination of irreversible destructive capabilities (unsaved encryption keys, physical disk wiping, partition removal) with espionage features (screen recording, VNC, system profiling) in a single implant gives operators flexibility to pivot from intelligence collection to destruction on command. Organizations in sectors targeted by IRGC-affiliated actors (critical infrastructure, water, energy) should prioritize monitoring for AMQP/Redis traffic from non-server endpoints and anomalous scheduled task creation patterns.

## Sources

- [Microsoft Security Blog - GigaWiper Analysis](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/) -- primary technical analysis with full IOCs, command code breakdown, and code evolution timeline
- [The Hacker News - GigaWiper Windows Backdoor](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html) -- additional context on Iran nexus, CyberAv3ngers attribution, and MinIO exfiltration channel
- [Hackread - Microsoft GigaWiper Backdoor](https://hackread.com/microsoft-gigawiper-backdoor-destroy-windows-pcs/) -- corroborating coverage of command codes and destructive capabilities
- [Infosecurity Magazine - GigaWiper Espionage and Destructive](https://www.infosecurity-magazine.com/news/new-gigawiper-espionage-destructive/) -- standalone wiper variant identification and operational efficiency analysis
- [The Register - Destructive Windows Backdoor](https://www.theregister.com/security/2026/07/10/destructive-windows-backdoor-stuffs-multiple-wipers-and-ransomware-code-into-a-single-package/5270053) -- AES-256-CBC encryption detail and unstripped PE notation

---
*Report generated by Actioner*
