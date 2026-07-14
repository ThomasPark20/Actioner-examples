# Technical Analysis Report: GigaWiper Windows Backdoor (2026-07-14)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-14
Version: 1.1-FINAL

<!-- revision: v1.0-DRAFT -> v1.1-FINAL (2026-07-14)
  Changes applied from critic review (NEEDS-REVISION):
  - DROPPED: Sigma rule "Event Log Clearing via wevtutil" (altitude violation; generic TTP duplicates community rules)
  - FIX: Sigma .candy rule downgraded level critical -> high; added falsepositives note for gaming software; added caveat about file_rename requiring Sysmon/EDR
  - FIX: YARA hash rule -- added performance overhead caveat in meta; cleaned up audit comment
  - FIX: Suricata Redis rule -- added caveat about content:"*" being a weak discriminator
  - FIX: All three Snort rules downgraded confidence high -> medium (uncompiled)
  - FIX: MITRE ATT&CK T1547.014 (Active Setup) corrected to T1547.001 (Registry Run Keys) for RunOnceRegistryMain
  - FIX: Noted IP-only Sigma rule overlap with IP+port rule in description
  - FIX: Remediation note that DisableLocalAdminMerge is Defender-specific
  - ADDED: New Sigma rule for command tracking marker ;"|?????|$pwd (process_creation)
  - Rule counts final: 7 Sigma, 2 YARA, 3 Suricata, 3 Snort = 15 total
-->

## Executive Summary

GigaWiper is a Golang-based destructive backdoor for Windows that consolidates disk-wiping, ransomware-like encryption, and command-and-control capabilities from three previously separate malware families -- Crucio ransomware, FlockWiper, and standalone disk wipers -- into a single modular operational platform. First observed by Microsoft Threat Intelligence in October 2025, GigaWiper communicates with its operators via RabbitMQ (AMQP) and Redis over non-standard ports, supports over 20 distinct command codes, and is capable of irreversible data destruction through physical disk overwriting, partition metadata removal, and AES-CBC file encryption with deliberately unrecoverable keys. The malware masquerades as OneDrive components for persistence and uses legitimate enterprise protocols to blend C2 traffic with normal business operations. Multiple sources attribute the malware to an Iran-nexus threat actor linked to CyberAv3ngers (IRGC-affiliated), tracked by some vendors as BLUERABBIT, with historical ties to critical infrastructure targeting in the US, Israel, UK, and Ireland.

## Background: GigaWiper Operational Platform

GigaWiper represents a consolidation trend in destructive malware development. Rather than deploying multiple standalone tools for different destructive objectives, the threat actor combined proven code from at least three prior malware families into a unified backdoor platform. The Crucio ransomware component (documented in a CISA advisory in December 2023) provides the file encryption capability; FlockWiper (a C-language disk wiper first uploaded to VirusTotal in June 2025) was reimplemented in Go for the multi-pass wiping function; and a standalone physical disk wiper provides raw disk-level destruction. The unstripped nature of the Go binary exposes internal function names and package paths that directly reveal its composite lineage.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| December 2023 | CISA advisory published on Crucio ransomware operations by IRGC-affiliated actors |
| June 2025 | FlockWiper first uploaded to VirusTotal |
| October 2025 | Microsoft Threat Intelligence begins observing GigaWiper destructive wiping activity |
| March 2026 | Binary Defense first observes BLUERABBIT samples |
| July 9, 2026 | Microsoft publishes detailed GigaWiper analysis blog |

## Root Cause: Initial Access Vector

The Microsoft report does not specify a precise initial access vector for GigaWiper deployments. Given the IRGC/CyberAv3ngers attribution context, prior campaigns by the same group have involved exploitation of internet-facing devices (particularly PLCs and OT/ICS systems), credential theft, and targeted intrusions against critical infrastructure. GigaWiper's design as a post-compromise destructive tool suggests it is deployed after initial access has already been established through other means.

## Technical Analysis of the Malicious Payload

### 1. Architecture and Code Structure

GigaWiper is compiled as an unstripped Golang portable executable (PE), which exposes internal package names and function references. Two distinct sample types have been identified in victim environments. Key Go package paths reveal the malware's composite architecture:

- `rabbit_tools_tool_wipe_main` -- Physical disk wiper module
- `rabbit_tools_tool_ran_main_cmd_extort` -- Ransomware/encryption module (Crucio-derived)
- `rabbit_tools_tool_wipec_main` -- Multi-pass Windows drive wiper (FlockWiper reimplementation)
- `rabbit_bin.RunOnceRegistryMain` -- Registry-based execution tracking
- `GRATClientInfo` -- Client identification structure

PDB paths embedded in related samples reference the "GRAT" project identifier:
- `A:\GRAT\CWipeNew\Release\CWipeNew.pdb`
- `E:\files\new\GRAT\CWipe\Release\CWipe.pdb`

### 2. Command Infrastructure

GigaWiper supports over 20 command codes organized into categories: "always run," "manage command," "special command," and "shell command." Key destructive commands include:

**Command 1 (WipeMain):** Physical disk-level destruction. Enumerates disks via WMI query `SELECT * FROM Win32_DiskDrive`, then overwrites raw disk content with random bytes (using Go's `crypto/rand`), removes partition metadata, and forces system restart. Chunk size: 0xA00000 (10.5 MB).

**Command 2 (System Sabotage):** Triggers BSOD by deleting boot files, disables Windows recovery via `bcdedit` commands, and manipulates file ownership/permissions.

**Command 3 (Ransomware - BigBangExtortMain):** Encrypts files using AES-256 CBC mode with randomly generated key/IV pairs that are deliberately not saved, making decryption impossible. Encrypted files receive the `.candy` extension. Excludes `.exe` and `.dll` files. Deploys a wallpaper overlay (`image_danger.jpg`) and drops `key.txt`.

**Command 12 (WipeCMain):** Multi-pass secure wiping targeting only the Windows installation drive. Reimplements FlockWiper logic in Go with a three-pass pattern: zeros, 0xFF bytes, then random bytes.

**Command 15 (Reconnaissance):** Collects system information including IP address, machine GUID, CPU, OS version, and network configuration. Enumerates installed antivirus software via PowerShell WMI query to `Win32_Product`.

**Command 19 (Log Tampering):** Clears Windows event logs (System, Setup, Application, ForwardedEvents, Security) using `wevtutil.exe` with the `clear-log` parameter, and deletes `C:\Windows\System32\winevt\Logs\Security.evtx` directly.

**Command 20 (Remote Access):** Establishes a TCP-based VNC-like remote control channel with keyboard/mouse input and screen streaming. Creates firewall rules named "Microsoft.Windows.CloudExperienceHost" to allow inbound/outbound traffic.

Additional capabilities include: PowerShell command execution, screenshot capture (PNG files at `.\<timestamp>\<monitor_index>.png`), screen recording (outputs to `C:\ProgramData\output`, activates when user is not idle for >10 seconds and system is unlocked), process management (create, suspend, resume, terminate, list), service CRUD operations, interactive registry navigation, keylogging, and file upload via MinIO Client (`mc.exe`).

### 3. C2 Infrastructure

GigaWiper uses a dual-protocol C2 architecture leveraging legitimate enterprise messaging systems:

**RabbitMQ (AMQP):** Primary command delivery channel on port 5544 (non-standard). Configuration is AES-encrypted and hard-coded. Uses two exchange types:
- Fanout exchange named "All" for broadcast commands to all implants
- Topic exchange named "Topic" for targeted commands to specific implants

**Redis:** Status updates and command output exfiltration on port 7542 (non-standard).

Command/response structures use Go types:
- Task: `task_id`, `command_code`, `args`
- Result: `error`, `target_ip`, `task_id`, `target_computer_name`, `output`, `pwd`, `time`, `status`, `work_status`

Shell command tracking appends the string `;"|?????|$pwd` to executed commands.

### 4. Persistence Mechanisms

GigaWiper establishes persistence through:

- **Scheduled Task:** Creates a task named "OneDrive Update" via PowerShell, configured for minute-level scheduling plus a startup trigger
- **Registry Tracking:** Writes execution counter to `HKCU\SOFTWARE\OneDrive\Environment`
- Operational strings include "Task created. Original process exiting." and "Running from Task Scheduler..." indicating the persistence handoff flow

### 5. Anti-Forensics / Evasion Techniques

- Masquerades persistence as legitimate OneDrive components ("OneDrive Update" task, OneDrive registry path)
- Firewall rules mimic legitimate Windows naming ("Microsoft.Windows.CloudExperienceHost")
- Uses legitimate enterprise protocols (RabbitMQ, Redis) that blend with normal business traffic
- Clears all major Windows event logs via multiple methods
- Non-standard ports for C2 avoid default service detection
- MinIO Client used for data exfiltration to attacker-controlled cloud storage

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `185.182.193[.]21`)

### File System

| Platform | Hash (SHA-256) | Description |
|----------|---------------|-------------|
| Windows | `633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001` | GigaWiper backdoor sample |
| Windows | `ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913` | GigaWiper backdoor sample |
| Windows | `f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd` | GigaWiper backdoor sample |
| Windows | `9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683` | GigaWiper backdoor sample |
| Windows | `3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd` | GigaWiper standalone wiper |
| Windows | `440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3` | Crucio ransomware |
| Windows | `12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721` | FlockWiper |
| Windows | `db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674` | FlockWiper |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 185.182.193[.]21 | Primary C2 -- RabbitMQ on port 5544, Redis on port 7542 |
| IP | 212.8.248[.]104 | Secondary GigaWiper C2 |
| Port | 5544 | Non-standard RabbitMQ AMQP C2 |
| Port | 7542 | Non-standard Redis C2 |

### Behavioral

- **Scheduled Task:** "OneDrive Update" created via PowerShell with minute-level recurrence and startup trigger
- **Registry Key:** `HKCU\SOFTWARE\OneDrive\Environment` used for execution tracking
- **Firewall Rule:** "Microsoft.Windows.CloudExperienceHost" created for remote access TCP traffic
- **File Extension:** `.candy` appended to encrypted files
- **Dropped Files:** `image_danger.jpg` (wallpaper), `key.txt` (encryption key placeholder)
- **Event Log Clearing:** `wevtutil.exe clear-log` targeting System, Setup, Application, ForwardedEvents, Security
- **Screen Recording Output:** `C:\ProgramData\output`
- **WMI Query:** `SELECT * FROM Win32_DiskDrive` for disk enumeration
- **RabbitMQ Exchanges:** "All" (fanout), "Topic" (topic exchange)
- **Embedded Strings:** "kharbvnmhkjbkjb", "Partitions removed successfully", "Exec cmd wipe-file", "Exec cmd keylog", "Exec cmd wipe32"

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1053.005 | Scheduled Task | "OneDrive Update" scheduled task for persistence with minute-level recurrence |
| T1112 | Modify Registry | Execution tracking via HKCU\SOFTWARE\OneDrive\Environment |
| T1547.001 | Registry Run Keys / Startup Folder | RunOnce registry-based persistence via RunOnceRegistryMain |
| T1561.001 | Disk Content Wipe | Physical disk overwriting with random bytes, partition metadata removal |
| T1561.002 | Disk Structure Wipe | Partition table destruction and metadata removal |
| T1486 | Data Encrypted for Impact | AES-256 CBC file encryption with .candy extension, keys deliberately not saved |
| T1529 | System Shutdown/Reboot | Forced restart after disk wiping operations |
| T1059.001 | PowerShell | PowerShell used for persistence setup, AV enumeration, and command execution |
| T1070.001 | Clear Windows Event Logs | wevtutil.exe clear-log for System, Setup, Application, ForwardedEvents, Security |
| T1071 | Application Layer Protocol | AMQP (RabbitMQ) and Redis protocols for C2 communication |
| T1571 | Non-Standard Port | RabbitMQ on port 5544, Redis on port 7542 |
| T1113 | Screen Capture | Screenshot capture of all monitors, continuous screen recording |
| T1021 | Remote Services | VNC-like TCP remote control with keyboard/mouse/screen streaming |
| T1562.004 | Disable or Modify System Firewall | Firewall rules created mimicking "Microsoft.Windows.CloudExperienceHost" |
| T1082 | System Information Discovery | System info collection including IP, GUID, CPU, OS, network config |
| T1518.001 | Security Software Discovery | Antivirus enumeration via PowerShell WMI query |
| T1057 | Process Discovery | Process listing and management capabilities |
| T1007 | System Service Discovery | Service enumeration and CRUD operations |
| T1012 | Query Registry | Interactive registry navigation and modification |

## Impact Assessment

GigaWiper's destructive capabilities are designed to be irreversible. The physical disk wiper (Command 1) overwrites raw disk content and removes partition metadata, rendering standard data recovery impossible. The ransomware module (Command 3) generates random AES keys that are never saved, meaning encrypted files cannot be recovered even if the malware operator cooperates. The multi-pass wiper (Command 12) applies a three-pass overwrite pattern (zeros, 0xFF, random bytes) to the Windows drive. The combination of these capabilities in a single platform gives the operator flexibility to choose the appropriate level of destruction for each target. Attribution to an IRGC-affiliated threat actor with a history of targeting critical infrastructure (US, Israeli, UK, Irish water/energy sectors) elevates the severity of this threat significantly.

## Detection & Remediation

### Immediate Detection

Check for GigaWiper persistence artifacts:

```powershell
# Check for the OneDrive Update scheduled task
schtasks /query /tn "OneDrive Update" 2>$null

# Check for the registry tracking key
reg query "HKCU\SOFTWARE\OneDrive\Environment" 2>$null

# Check for suspicious firewall rules
netsh advfirewall firewall show rule name="Microsoft.Windows.CloudExperienceHost" 2>$null

# Check for .candy encrypted files
Get-ChildItem -Path C:\ -Recurse -Filter "*.candy" -ErrorAction SilentlyContinue | Select-Object -First 10

# Check for screen recording output directory
Test-Path "C:\ProgramData\output"

# Search for GigaWiper hashes (requires file hash scanning capability)
# SHA-256: 633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001
# SHA-256: ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913
# SHA-256: f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd
# SHA-256: 9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683
```

Check network connections:
```powershell
# Check for connections to known C2 IPs
netstat -an | findstr "185.182.193.21"
netstat -an | findstr "212.8.248.104"

# Check for traffic on non-standard RabbitMQ/Redis ports
netstat -an | findstr ":5544"
netstat -an | findstr ":7542"
```

### Remediation

1. **Immediate Containment:** Block C2 IPs `185.182.193[.]21` and `212.8.248[.]104` at the network perimeter (firewall, proxy, DNS sinkhole). Block outbound traffic on ports 5544 and 7542.
2. **Remove Persistence:** Delete the "OneDrive Update" scheduled task. Remove the `HKCU\SOFTWARE\OneDrive\Environment` registry key. Remove the "Microsoft.Windows.CloudExperienceHost" firewall rule.
3. **Isolate Affected Systems:** Immediately isolate any system showing indicators of compromise to prevent lateral movement and destructive command execution.
4. **Forensic Imaging:** Before remediation, create forensic images of affected systems for evidence preservation.
5. **Credential Rotation:** Rotate all credentials accessible from compromised systems, including domain accounts, service accounts, and any cached credentials.

### Long-Term Hardening

- Enable Microsoft Defender tamper protection tenant-wide
- Enable `DisableLocalAdminMerge` to prevent antivirus exclusion bypass (Microsoft Defender-specific GPO setting; does not apply to third-party AV products)
- Configure always-on protection in Group Policy
- Enable cloud-delivered protection and automatic sample submission
- Run EDR in block mode with automated investigation/remediation
- Deploy attack surface reduction rules (executable prevalence/age/trust checks)
- Monitor for anomalous AMQP and Redis traffic from desktop endpoints
- Implement network segmentation to limit lateral movement from compromised systems

## Detection Rules

Seven Sigma rules, two YARA rules, three Suricata rules, and three Snort rules (15 total) cover GigaWiper's C2 infrastructure, persistence mechanisms, destructive payloads, and binary indicators. All rules target advisory-specific artifacts at strict leniency; the main caveat is that C2 IP-based rules require updates as infrastructure rotates. The IP-only Sigma rule intentionally overlaps with the IP+port rule to catch C2 migration to alternate ports. One generic Sigma rule (wevtutil event-log clearing) was dropped during review as an altitude violation -- it duplicated existing community coverage for T1070.001.

### Sigma: GigaWiper C2 Network Connection to Known Infrastructure

Compile: sigma-to-splunk pass, sigma-to-logscale pass | Confidence: high

```yaml
title: GigaWiper C2 Network Connection to Known Infrastructure
id: 8a3c1e7f-4b2d-4f6a-9e8c-1d5f0a3b7c2e
status: experimental
description: >
    Detects outbound network connections to known GigaWiper command-and-control
    IP addresses on non-standard ports used for RabbitMQ (5544) and Redis (7542)
    C2 channels.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-14
tags:
    - attack.t1071
    - attack.t1571
logsource:
    category: network_connection
detection:
    selection_ip:
        DestinationIp:
            - '185.182.193.21'
            - '212.8.248.104'
    selection_port:
        DestinationPort:
            - 5544
            - 7542
    condition: selection_ip and selection_port
falsepositives:
    - Legitimate RabbitMQ or Redis traffic to these specific IPs is extremely unlikely
level: critical
```

<!-- Validation audit: sigma check failed due to proxy blocking MITRE ATT&CK data download (HTTP 403 from raw.githubusercontent.com). sigma convert --without-pipeline -t splunk produced valid SPL: DestinationIp IN ("185.182.193.21", "212.8.248.104") DestinationPort IN (5544, 7542). sigma convert --without-pipeline -t log_scale also produced valid output. Rule syntax is correct; sigma check failure is environmental, not structural. IOC values are real (not defanged) per logsource-encoding.md. -->

### Sigma: GigaWiper Network Connection to Known C2 IP Addresses

Compile: sigma-to-splunk pass, sigma-to-logscale pass | Confidence: high

```yaml
title: GigaWiper Network Connection to Known C2 IP Addresses
id: 2f9b4d6a-8c1e-4a3f-b7d5-0e2c9f1a6b8d
status: experimental
description: >
    Detects any outbound network connection to GigaWiper C2 IP addresses
    regardless of port, providing broader coverage for infrastructure reuse.
    Note: this rule intentionally overlaps with the port-specific C2 rule
    (8a3c1e7f) to catch C2 migration to alternate ports on the same hosts.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-14
tags:
    - attack.t1071
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '185.182.193.21'
            - '212.8.248.104'
    condition: selection
falsepositives:
    - Legitimate traffic to these IP addresses
level: high
```

<!-- Validation audit: sigma convert --without-pipeline -t splunk: DestinationIp IN ("185.182.193.21", "212.8.248.104"). sigma convert --without-pipeline -t log_scale: valid output. Broader companion to the port-specific rule above, catches infrastructure reuse on alternate ports. -->

### Sigma: GigaWiper Scheduled Task Persistence via OneDrive Update

Compile: sigma-to-splunk pass, sigma-to-logscale pass | Confidence: high

```yaml
title: GigaWiper Scheduled Task Persistence via OneDrive Update
id: 5e8d2a1c-9f4b-4c7e-a3d6-0b1f8e5c2a9d
status: experimental
description: >
    Detects creation of the "OneDrive Update" scheduled task used by GigaWiper
    for persistence, configured to execute at minute-level intervals and on
    system startup.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-14
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_tool:
        Image|endswith:
            - '\schtasks.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_taskname:
        CommandLine|contains: 'OneDrive Update'
    condition: selection_tool and selection_taskname
falsepositives:
    - Legitimate Microsoft OneDrive update mechanisms may use similarly named tasks
level: high
```

<!-- Validation audit: sigma convert --without-pipeline -t splunk: Image IN ("*\\schtasks.exe", "*\\powershell.exe", "*\\pwsh.exe") CommandLine="*OneDrive Update*". Valid output. Task name is distinctive to GigaWiper per Microsoft report. Possible FP from legitimate OneDrive updater noted in falsepositives field. -->

### Sigma: GigaWiper Registry Persistence at OneDrive Environment Key

Compile: sigma-to-splunk pass, sigma-to-logscale pass | Confidence: medium

```yaml
title: GigaWiper Registry Persistence at OneDrive Environment Key
id: 7c4f1b3e-6a8d-4e2f-9d5c-3a0b8e7f1d6c
status: experimental
description: >
    Detects modification of the HKCU\SOFTWARE\OneDrive\Environment registry key
    used by GigaWiper for execution tracking and persistence state management.
    The RunOnceRegistryMain function writes to this key using RunOnce-style
    registry persistence.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-14
tags:
    - attack.t1547.001
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\SOFTWARE\OneDrive\Environment'
    condition: selection
falsepositives:
    - Legitimate OneDrive application writing to its own registry namespace
level: medium
```

<!-- Validation audit: sigma convert --without-pipeline -t splunk: TargetObject="*\\SOFTWARE\\OneDrive\\Environment*". Valid output. ATT&CK tag corrected from T1547.014 (Active Setup) to T1547.001 (Registry Run Keys) to match RunOnceRegistryMain behavior. Medium confidence due to potential legitimate OneDrive registry usage; best used in conjunction with other GigaWiper indicators. -->

### ~~Sigma: GigaWiper Event Log Clearing via wevtutil~~ (DROPPED)

Dropped during review: altitude violation. This rule detects a generic TTP (T1070.001 wevtutil clear-log) that is not GigaWiper-specific and duplicates well-maintained community Sigma rules for the same behavior. Use existing community coverage for event log clearing detection.

### Sigma: GigaWiper Firewall Rule Creation Mimicking Windows CloudExperienceHost

Compile: sigma-to-splunk pass, sigma-to-logscale pass | Confidence: high

```yaml
title: GigaWiper Firewall Rule Creation Mimicking Windows CloudExperienceHost
id: 1a5b8c3d-2e7f-4d9a-b6c1-8f0e3a4d5b2c
status: experimental
description: >
    Detects creation of firewall rules with the name
    "Microsoft.Windows.CloudExperienceHost", used by GigaWiper to disguise
    inbound/outbound TCP rules for its VNC-like remote access capability.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-14
tags:
    - attack.t1562.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_tool:
        Image|endswith:
            - '\netsh.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_firewall:
        CommandLine|contains|all:
            - 'Microsoft.Windows.CloudExperienceHost'
            - 'firewall'
    condition: selection_tool and selection_firewall
falsepositives:
    - Legitimate Windows CloudExperienceHost firewall configurations are typically managed by the OS, not via manual netsh or PowerShell commands
level: high
```

<!-- Validation audit: sigma convert --without-pipeline -t splunk: Image IN ("*\\netsh.exe", ...) CommandLine="*Microsoft.Windows.CloudExperienceHost*" CommandLine="*firewall*". Valid output. The firewall rule name is a distinctive GigaWiper indicator per Microsoft analysis. -->

### Sigma: GigaWiper Ransomware File Encryption with .candy Extension

Compile: sigma-to-splunk pass, sigma-to-logscale pass | Confidence: high

```yaml
title: GigaWiper Ransomware File Encryption with .candy Extension
id: 9b2e4f1a-7d8c-4a3e-b5f6-0c1d2e3a4b5c
status: experimental
description: >
    Detects file creation or rename events resulting in .candy file extension,
    the signature extension used by GigaWiper's ransomware-like encryption
    module derived from Crucio code. Note: the file_rename log source category
    requires Sysmon (Event ID 26) or an EDR that logs file rename operations;
    environments without these will not generate matching events.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-14
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
    - Applications or games that legitimately use .candy file extensions (e.g., CandyCrush or similar gaming software data files)
level: high
```

<!-- Validation audit: sigma convert --without-pipeline -t splunk: TargetFilename="*.candy". Valid output. Level downgraded from critical to high per review (single-extension match may FP with gaming software). Added Sysmon/EDR prerequisite caveat and expanded falsepositives. -->

### Sigma: GigaWiper Command Tracking Marker in Shell Execution

Compile: sigma-to-splunk pass, sigma-to-logscale pass | Confidence: high

```yaml
title: GigaWiper Command Tracking Marker in Shell Execution
id: 4d7e2f9a-3c1b-4e8d-a6f5-9b0c1d2e3f4a
status: experimental
description: >
    Detects the distinctive command tracking marker string ;"|?????|$pwd
    appended by GigaWiper to executed shell commands. This marker is used
    internally by the malware to correlate command output with task tracking
    and is a strong GigaWiper-specific artifact with near-zero false positive
    rate in legitimate environments.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026-07-14
tags:
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: ';"|?????|$pwd'
    condition: selection
falsepositives:
    - None expected; the marker string is a GigaWiper-specific internal artifact
level: critical
```

<!-- Validation audit: sigma convert --without-pipeline -t splunk: CommandLine="*;\"|*****|$pwd*". sigma convert --without-pipeline -t log_scale: CommandLine=/;"\|.....\|\$pwd/i. Both pass. Added in v1.1 per critic review -- the command tracking marker is a strong GigaWiper-specific behavioral indicator. -->

### YARA: GigaWiper Backdoor String Detection

Compile: yarac pass | Confidence: high

```yara
rule Malware_GigaWiper_Backdoor_Strings
{
    meta:
        description = "Detects GigaWiper Golang backdoor via characteristic function names, package references, PDB paths, and operational strings"
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001"
        severity = "critical"

    strings:
        $fn1 = "rabbit_tools_tool_wipe_main" ascii
        $fn2 = "rabbit_tools_tool_ran_main_cmd_extort" ascii
        $fn3 = "rabbit_tools_tool_wipec_main" ascii
        $fn4 = "rabbit_bin.RunOnceRegistryMain" ascii
        $fn5 = "BigBangExtortMain" ascii
        $fn6 = "GRATClientInfo" ascii

        $pdb1 = "GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii
        $pdb2 = "GRAT\\CWipe\\Release\\CWipe.pdb" ascii

        $str1 = "Partitions removed successfully" ascii
        $str2 = "Task created. Original process exiting." ascii
        $str3 = "Running from Task Scheduler" ascii
        $str4 = "Exec cmd wipe-file" ascii
        $str5 = "Exec cmd keylog" ascii
        $str6 = "Exec cmd wipe32" ascii
        $str7 = "kharbvnmhkjbkjb" ascii
        $str8 = ".candy" ascii

        $cfg1 = "OneDrive Update" ascii wide
        $cfg2 = "Microsoft.Windows.CloudExperienceHost" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            2 of ($fn*) or
            1 of ($pdb*) or
            (3 of ($str*) and 1 of ($cfg*)) or
            ($fn5 and $str8)
        )
}
```

<!-- Validation audit: yarac gigawiper_binary.yar /dev/null exited 0 (pass). Strings derived from Microsoft's analysis of unstripped Go binary function names (rabbit_tools_*, GRATClientInfo, BigBangExtortMain) and embedded PDB paths (GRAT\CWipe*). Condition requires PE header + multiple corroborating strings to minimize FPs. The .candy string alone would FP; it is gated behind $fn5 (BigBangExtortMain). -->

### YARA: GigaWiper Known Sample Hashes

Compile: yarac pass | Confidence: high

```yara
import "hash"

rule Malware_GigaWiper_Hashes
{
    meta:
        description = "Detects known GigaWiper, Crucio, and FlockWiper samples by SHA-256 hash"
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        severity = "critical"
        note = "The hash module computes a full-file SHA-256 for every scanned file, which adds CPU and I/O overhead. Consider deploying this rule only in targeted scans or alongside a pre-filter that limits the scan set."

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

<!-- Validation audit: yarac pass. All 8 hashes sourced directly from Microsoft blog. Requires YARA hash module support in scanning environment. Performance caveat added in meta. -->

### Suricata: GigaWiper AMQP C2 to 185.182.193[.]21:5544

Compile: suricata -T pass | Confidence: high

```
alert tcp $HOME_NET any -> 185.182.193.21 5544 (msg:"Actioner - GigaWiper AMQP C2 to 185.182.193.21:5544"; flow:established,to_server; content:"AMQP"; depth:4; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-14; sid:2100201; rev:1;)
```

<!-- Validation audit: suricata -T -S gigawiper_c2_suricata.rules -l /tmp/actioner-rules exited with "Configuration provided was successfully loaded. Exiting." (pass). Rule matches AMQP protocol header bytes on the specific C2 IP:port combination. -->

### Suricata: GigaWiper Redis C2 to 185.182.193[.]21:7542

Compile: suricata -T pass | Confidence: high

```
alert tcp $HOME_NET any -> 185.182.193.21 7542 (msg:"Actioner - GigaWiper Redis C2 to 185.182.193.21:7542"; flow:established,to_server; content:"*"; depth:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-14; sid:2100202; rev:1;)
```

<!-- Validation audit: suricata -T pass. Redis RESP protocol starts commands with "*" (array indicator). Combined with specific IP:port, this is highly targeted. Caveat: content:"*" with depth:1 is a weak protocol discriminator on its own -- the rule relies on the IP:port pair for specificity. -->

### Suricata: GigaWiper C2 to 212.8.248[.]104

Compile: suricata -T pass | Confidence: high

```
alert tcp $HOME_NET any -> 212.8.248.104 any (msg:"Actioner - GigaWiper C2 to 212.8.248.104"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-14; sid:2100203; rev:1;)
```

<!-- Validation audit: suricata -T pass. Broader catch-all for secondary C2 IP since specific port/protocol not documented for this IP. -->

### Snort: GigaWiper AMQP C2 Communication

Compile: uncompiled (structural check only) | Confidence: medium

```
alert tcp $HOME_NET any -> 185.182.193.21 5544 (msg:"Actioner - GigaWiper AMQP C2 Communication to 185.182.193.21:5544"; flow:established,to_server; content:"AMQP"; depth:4; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created 2026-07-14; sid:2100101; rev:1;)
```

<!-- Validation audit: Snort 3 is not installed in this environment. Structural check: rule uses tcp protocol (correct for non-HTTP), flow:established,to_server present, content match with depth constraint, all required fields (msg, sid, rev) present, semicolons terminate all options. No Suricata-only keywords used. -->

### Snort: GigaWiper Redis C2 Communication

Compile: uncompiled (structural check only) | Confidence: medium

```
alert tcp $HOME_NET any -> 185.182.193.21 7542 (msg:"Actioner - GigaWiper Redis C2 Communication to 185.182.193.21:7542"; flow:established,to_server; content:"*"; depth:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created 2026-07-14; sid:2100102; rev:1;)
```

<!-- Validation audit: Snort 3 not installed. Structural check: valid tcp rule with flow, content match, all required fields present. -->

### Snort: GigaWiper C2 to 212.8.248[.]104

Compile: uncompiled (structural check only) | Confidence: medium

```
alert tcp $HOME_NET any -> 212.8.248.104 any (msg:"Actioner - GigaWiper C2 Communication to 212.8.248.104"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created 2026-07-14; sid:2100103; rev:1;)
```

<!-- Validation audit: Snort 3 not installed. Structural check: valid tcp rule with flow, all required fields present. No content match (IP-only rule). -->

## Lessons Learned

GigaWiper demonstrates a maturation trend in destructive malware development: consolidation. By merging previously standalone tools into a single modular platform, the threat actor reduces operational complexity (fewer tools to deploy, fewer detection signatures to evade) while maintaining flexibility through a rich command set. The use of legitimate enterprise protocols (RabbitMQ, Redis, MinIO) for C2 and data exfiltration represents a deliberate effort to blend malicious traffic with normal business operations, making network-level detection more challenging. The irreversible nature of the encryption module (keys generated and immediately discarded) confirms the malware's intent is purely destructive, despite its ransomware-like presentation. Defenders should prioritize monitoring for anomalous AMQP and Redis traffic from desktop endpoints, validate that scheduled tasks match expected baselines, and ensure event log forwarding to a SIEM provides a secondary copy before GigaWiper's log-clearing module can execute.

## Sources

- [Microsoft Threat Intelligence: GigaWiper Analysis](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/) -- Primary source: full technical analysis with IOCs, TTPs, code structure, and detection guidance
- [The Hacker News: New GigaWiper Windows Backdoor](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html) -- Secondary coverage with attribution details linking GigaWiper to Iran-nexus/CyberAv3ngers threat actor
- [Hackread: Microsoft GigaWiper Backdoor](https://hackread.com/microsoft-gigawiper-backdoor-destroy-windows-pcs/) -- Secondary coverage summarizing destructive capabilities
- [The Register: Destructive Windows Backdoor](https://www.theregister.com/security/2026/07/10/destructive-windows-backdoor-stuffs-multiple-wipers-and-ransomware-code-into-a-single-package/5270053) -- Secondary coverage noting unstripped PE characteristics and command categories

---
*Report generated by Actioner*
