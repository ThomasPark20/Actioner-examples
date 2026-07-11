# Technical Analysis Report: GigaWiper Destructive Backdoor (2026-07-11)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-11
Version: 1.0 (DRAFT)

## Executive Summary

GigaWiper is a Go-based destructive backdoor that combines code from at least two prior malware families -- Crucio ransomware and FlockWiper -- into a unified multi-capability implant. [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/) published analysis on July 9, 2026. [Google Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence) tracks the same activity as BLUERABBIT. The backdoor uses RabbitMQ (AMQP) for command reception and Redis for result exfiltration, communicating over non-standard ports. It provides operators with disk-level wiping, fake ransomware encryption (files renamed .candy with unrecoverable keys), multi-pass secure wiping, VNC-like remote access, screenshot/recording, and full system management capabilities. Attribution indicators (PDB paths containing "GRAT", CISA's December 2023 Crucio advisory) link this toolset to IRGC-affiliated actors. The combination of destructive and espionage capabilities in a single binary, coupled with the RabbitMQ fanout architecture enabling simultaneous commands to all victims, makes this a high-severity threat to targeted organizations.

## Technical Analysis

### Execution Flow and Persistence

On first execution, GigaWiper checks for the registry key `HKCU\SOFTWARE\OneDrive\Environment`. If absent, it creates a scheduled task named "OneDrive Update" configured with two triggers: system startup and minute-interval recurrence. The task executes the malware via hidden PowerShell invocation. The registry key value serves as an execution counter -- subsequent runs increment the counter and print the debug string "Running from Task Scheduler..." before proceeding to C2 communication.

### C2 Architecture

GigaWiper employs a dual-protocol C2 design:

- **RabbitMQ (AMQP)** on 185[.]182[.]193[.]21:5544 -- receives tasking via two exchange types:
  - Fanout exchange "All" -- broadcasts commands simultaneously to all connected implants
  - Topic exchange "Topic" -- delivers targeted commands via dynamic routing keys (managed through Command 8)
- **Redis** on 185[.]182[.]193[.]21:7542 -- transmits results back to operators, structured as JSON containing `error`, `target_ip`, `task_id`, `target_computer_name`, `output`, `pwd`, `time`, `status`, and `work_status` fields
- **Secondary C2** at 212[.]8[.]248[.]104 -- purpose not fully detailed in source

Task messages contain `task_id`, `command_code`, and `args` fields. Hard-coded configuration is decrypted using AES with embedded keys.

### Command Capabilities

| Cmd | Name | Function |
|-----|------|----------|
| 1 | WipeMain | Physical disk-level wiping via WMI drive enumeration, DeviceIoControl IOCTL_DISK_CREATE_DISK partition removal, 0xA00000-byte chunk overwrite, forced reboot |
| 2 | BSOD | Boot file deletion + Windows recovery disable |
| 3 | RanMain/BigBangExtortMain | Fake ransomware: AES-CBC with random keys never persisted to disk; .candy extension; image_danger.jpg wallpaper |
| 4 | MinIO Upload | Configurable MinIO Client file exfiltration |
| 5 | Bulk Encrypt | AES-256-CBC file encryption/decryption utility |
| 7 | PowerShell | Execute commands with output parsing; queue purge variants |
| 8 | Route Mgmt | RabbitMQ bind/unbind/update routing keys |
| 9 | Screenshot | Per-monitor PNG capture to .\<timestamp>\<index>.png |
| 10 | Recording | Screen recording when unlocked/not idle (10s threshold) to C:\ProgramData\output |
| 12 | WipeCMain | FlockWiper reimplementation: multi-pass secure wiping (0x00, 0xFF, random) of Windows drive |
| 15 | Sysinfo | IP, GUID, CPU, OS, network config, antivirus enumeration via Get-WmiObject |
| 16 | Process Mgmt | Create, resume, suspend, kill, list, info |
| 17 | Service Mgmt | Create, delete, restart, query, start, stop, list |
| 18 | Registry | Interactive registry manipulation (show, navigate, createKey, deleteKey, setValue, deleteValue) |
| 19 | Log Clear | wevutil.exe clears System, Setup, Application, ForwardedEvents, Security; fallback to direct .evtx file deletion |
| 20 | VNC | Remote access over TCP with firewall rule "Microsoft.Windows.CloudExperienceHost" |

### Malware Family Relationships

**Crucio Ransomware:** Command 3 heavily reimplements Crucio's `BigBangExtortMain` function. CISA documented Crucio in December 2023 as an IRGC-affiliated tool, establishing actor continuity.

**FlockWiper:** Command 12 recodes FlockWiper (C-based, first observed June 2025) into Go with enhanced multi-pass wiping. PDB paths `A:\GRAT\CWipeNew\Release\CWipeNew.pdb` and `E:\files\new\GRAT\CWipe\Release\CWipe.pdb` confirm shared development framework. The "GRAT" identifier appears in both FlockWiper PDB paths and GigaWiper Go function names (`GRATClientInfo`).

### Event Log Clearing (Command 19)

The malware uses `wevutil.exe` (note: deliberate or incidental typo of wevtutil.exe) with the `clear` subcommand targeting five log channels. If the utility fails, direct file deletion at `C:\Windows\System32\winevt\Logs\Security.evtx` is attempted. The debug string "kharbvnmhkjbkjb" is printed during execution.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: IP addresses use `[.]` for dots.

### File Hashes

| Hash (SHA-256) | Component |
|----------------|-----------|
| 633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001 | GigaWiper backdoor |
| ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913 | GigaWiper backdoor |
| f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd | GigaWiper backdoor |
| 9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683 | GigaWiper backdoor |
| 3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd | Standalone wiper |
| 440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3 | Crucio ransomware |
| 12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721 | FlockWiper |
| db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674 | FlockWiper |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 185[.]182[.]193[.]21:5544 | RabbitMQ C2 (AMQP) |
| IP | 185[.]182[.]193[.]21:7542 | Redis result exfiltration |
| IP | 212[.]8[.]248[.]104 | Secondary C2 |

### Host Artifacts

| Platform | Indicator | Description |
|----------|-----------|-------------|
| Windows | HKCU\SOFTWARE\OneDrive\Environment | Execution counter registry key |
| Windows | Scheduled task "OneDrive Update" | Persistence (every minute + startup) |
| Windows | .candy file extension | Fake ransomware encrypted files |
| Windows | ./image_danger.jpg | Ransom wallpaper drop |
| Windows | C:\ProgramData\output | Screen recording output directory |
| Windows | Firewall rule "Microsoft.Windows.CloudExperienceHost" | VNC access masquerade |

### Behavioral

- RabbitMQ AMQP traffic on non-standard port 5544
- Redis protocol traffic on non-standard port 7542
- wevutil.exe (typo variant) or wevtutil.exe clearing multiple log channels in sequence
- Scheduled task "OneDrive Update" executing every minute
- Registry writes to HKCU\SOFTWARE\OneDrive\Environment from non-OneDrive processes
- Direct .evtx file deletion from C:\Windows\System32\winevt\Logs\

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1053.005 | Scheduled Task/Job: Scheduled Task | "OneDrive Update" scheduled task for persistence |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Registry execution counter at HKCU\SOFTWARE\OneDrive\Environment |
| T1071.001 | Application Layer Protocol: Web Protocols | RabbitMQ AMQP and Redis for C2 communication |
| T1561.001 | Disk Wipe: Disk Content Wipe | WipeMain: overwrite drives in chunks with random/zero bytes |
| T1561.002 | Disk Wipe: Disk Structure Wipe | DeviceIoControl IOCTL_DISK_CREATE_DISK to remove partition tables |
| T1486 | Data Encrypted for Impact | Fake ransomware with unrecoverable AES-CBC encryption (.candy) |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | wevutil.exe clearing System, Setup, Application, ForwardedEvents, Security |
| T1529 | System Shutdown/Reboot | Forced reboot after disk wiping |
| T1113 | Screen Capture | Per-monitor PNG screenshot capture |
| T1125 | Video Capture | Screen recording to C:\ProgramData\output |
| T1112 | Modify Registry | Interactive registry manipulation (Command 18) |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | Firewall rule creation masquerading as Windows component |
| T1082 | System Information Discovery | GRATClientInfo system enumeration |

## Detection & Remediation

### Immediate Detection

1. Search for scheduled tasks named "OneDrive Update" -- legitimate OneDrive uses different task names
2. Search registry for HKCU\SOFTWARE\OneDrive\Environment modifications by non-OneDrive.exe processes
3. Search network logs for connections to 185[.]182[.]193[.]21 (ports 5544, 7542) and 212[.]8[.]248[.]104
4. Search for wevutil.exe or wevtutil.exe executing with "clear" subcommand across multiple log channels
5. Search for firewall rules named "Microsoft.Windows.CloudExperienceHost"
6. Search for .candy file extension appearing on endpoints

### Remediation

1. **Containment:** Immediately isolate affected systems; block all three C2 IPs at perimeter firewalls
2. **Scheduled task removal:** Delete "OneDrive Update" scheduled task and associated binary
3. **Registry cleanup:** Remove HKCU\SOFTWARE\OneDrive\Environment key
4. **Firewall audit:** Remove "Microsoft.Windows.CloudExperienceHost" firewall rules not associated with legitimate Windows services
5. **Disk forensics:** Systems with evidence of Command 1/2/12 execution may have irrecoverable disk damage; image before any recovery attempt
6. **Network monitoring:** Deploy provided Snort/Suricata rules for ongoing detection of C2 communication

### Long-Term Hardening

- Monitor for RabbitMQ AMQP protocol traffic on non-standard ports (legitimate AMQP uses 5672)
- Implement application control to prevent execution of Go binaries from unexpected paths
- Deploy Windows Event Log forwarding to prevent local log clearing from being effective
- Restrict scheduled task creation to authorized administrators via Group Policy
- Monitor DeviceIoControl calls with disk-wiping IOCTLs from non-system processes

## Detection Rules

These 11 rules (4 Sigma, 4 YARA, 3 Snort, 3 Suricata) target GigaWiper across host, file, and network telemetry. IOC-based network rules are high confidence but rotate with infrastructure; behavioral Sigma rules provide longer-term detection value.

### Sigma: GigaWiper Scheduled Task Persistence via OneDrive Update

Detects creation of the distinctive "OneDrive Update" scheduled task used by GigaWiper for minute-interval persistence.

**Status:** compile ✅ compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network: MITRE ATT&CK data fetch 403 via proxy -- not a rule issue). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. "OneDrive Update" is not a legitimate Microsoft task name; near-zero FP. -->

```yaml
title: GigaWiper Scheduled Task Persistence via OneDrive Update
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: >
    Detects creation of a scheduled task named "OneDrive Update" used by GigaWiper
    for persistence. The task runs every minute and at system startup to re-execute
    the backdoor binary via hidden PowerShell invocation.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/11
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - 'OneDrive Update'
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'Register-ScheduledTask'
            - 'OneDrive Update'
    condition: selection_schtasks or selection_powershell
falsepositives:
    - Legitimate Microsoft OneDrive update mechanisms use different task names (e.g., "OneDrive Reporting Task")
level: high
```

### Sigma: GigaWiper Registry Execution Counter Modification

Detects modification of the HKCU\SOFTWARE\OneDrive\Environment registry key by non-OneDrive processes, indicating GigaWiper execution tracking.

**Status:** compile ✅ compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Legitimate OneDrive writes to different subkeys (e.g., \OneDrive\Accounts); the Environment subkey with non-OneDrive.exe writer is highly distinctive. -->

```yaml
title: GigaWiper Registry Execution Counter Modification
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: >
    Detects modification of the HKCU\SOFTWARE\OneDrive\Environment registry key
    used by GigaWiper as an execution counter to determine first-run status and
    track subsequent executions.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/11
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\SOFTWARE\OneDrive\Environment'
    filter_onedrive:
        Image|endswith: '\OneDrive.exe'
    condition: selection and not filter_onedrive
falsepositives:
    - Legitimate OneDrive application writing to its own registry subkeys (filtered by Image)
level: high
```

### Sigma: GigaWiper Event Log Clearing via wevutil.exe

Detects use of wevutil.exe (the malware's hardcoded binary name) or wevtutil.exe to clear Windows event logs as part of GigaWiper's defense evasion (Command 19).

**Status:** compile ✅ compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. The wevutil.exe typo variant is unique to this malware family. Combined with wevtutil.exe clear targeting multiple named logs, provides strong signal. FP: admin log rotation scripts -- rare in practice. -->

```yaml
title: GigaWiper Event Log Clearing via wevutil.exe
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: >
    Detects the use of wevutil.exe (note deliberate typo matching the malware's
    hardcoded binary name) or wevtutil.exe to clear multiple Windows event logs,
    a defense evasion technique used by GigaWiper Command 19.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/11
tags:
    - attack.t1070.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\wevtutil.exe'
            - '\wevutil.exe'
        CommandLine|contains: 'clear'
    selection_logs:
        CommandLine|contains:
            - 'System'
            - 'Setup'
            - 'Application'
            - 'ForwardedEvents'
            - 'Security'
    condition: selection and selection_logs
falsepositives:
    - Legitimate administrator clearing event logs during maintenance (should be rare and auditable)
level: high
```

### Sigma: GigaWiper Network Connection to Known C2 Infrastructure

Detects outbound connections to GigaWiper C2 IPs on their specific operational ports.

**Status:** compile ✅ compiles (convert) | Confidence: high (IOC-specific, limited shelf life)

<!-- audit: sigma check failed (network). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. IOC-based rule with infrastructure-rotation risk. Port+IP combinations are highly distinctive -- 5544 for AMQP and 7542 for Redis are non-standard. -->

```yaml
title: GigaWiper Network Connection to Known C2 Infrastructure
id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a
status: experimental
description: >
    Detects outbound network connections to GigaWiper C2 infrastructure including
    the RabbitMQ command server (185.182.193.21:5544), Redis results server
    (185.182.193.21:7542), and secondary C2 (212.8.248.104).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/11
tags:
    - attack.t1071.001
logsource:
    category: network_connection
    product: windows
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
    - Legitimate traffic to these IPs (unlikely given specific port combinations)
level: critical
```

### YARA: GigaWiper Backdoor Strings

Detects GigaWiper Go-based backdoor via characteristic GRAT framework function names, RabbitMQ exchange configuration, and operational debug strings.

**Status:** compile ✅ yarac exit 0 | Confidence: high

<!-- audit: yarac rules/yara/2026-07-11-gigawiper-destructive-backdoor.yar /dev/null exit 0. Rule targets Go binary string table entries unique to this malware family. Function names like rabbit_tools_tool_wipe_main and GRATClientInfo are not found in legitimate software. -->

```yara
rule Malware_GigaWiper_Backdoor_Strings
{
    meta:
        description = "Detects GigaWiper Go-based destructive backdoor via characteristic function names, command strings, and GRAT framework references"
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001"
        hash = "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913"
        severity = "critical"

    strings:
        $func1 = "rabbit_tools_tool_wipe_main" ascii
        $func2 = "rabbit_tools_tool_ran_main_cmd_extort" ascii
        $func3 = "rabbit_tools_tool_wipec_main" ascii
        $func4 = "RunOnceRegistryMain" ascii
        $func5 = "GRATClientInfo" ascii
        $func6 = "BigBangExtortMain" ascii

        $c2_1 = "185.182.193.21" ascii
        $c2_2 = "212.8.248.104" ascii
        $amqp = "amqp://" ascii

        $exch1 = "\"All\"" ascii
        $exch2 = "\"Topic\"" ascii

        $op1 = "Running from Task Scheduler" ascii
        $op2 = "kharbvnmhkjbkjb" ascii
        $op3 = "OneDrive Update" ascii wide
        $op4 = ".candy" ascii
        $op5 = "image_danger.jpg" ascii

        $reg = "SOFTWARE\\OneDrive\\Environment" ascii wide

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        filesize < 30MB and
        (
            3 of ($func*) or
            (2 of ($c2*) and 1 of ($func*)) or
            ($op2 and 1 of ($func*)) or
            (2 of ($op*) and $reg) or
            ($amqp and $exch1 and $exch2 and 1 of ($func*))
        )
}
```

### YARA: GigaWiper Standalone Wiper

Detects GigaWiper standalone wiper component via disk-wiping function references and multi-pass overwrite patterns.

**Status:** compile ✅ yarac exit 0 | Confidence: high

<!-- audit: yarac exit 0. Function names FindWindowsDrive, unallocateDrive, writeRandToDrive are unique to this wiper family and present in Go binary symbol tables. -->

```yara
rule Malware_GigaWiper_Standalone_Wiper
{
    meta:
        description = "Detects GigaWiper standalone wiper component via disk wiping function references and multi-pass overwrite patterns"
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd"
        severity = "critical"

    strings:
        $wipe1 = "FindWindowsDrive" ascii
        $wipe2 = "unallocateDrive" ascii
        $wipe3 = "writeRandToDrive" ascii
        $wipe4 = "WipeMain" ascii
        $wipe5 = "WipeCMain" ascii

        $pass = "Pass 1 Time took:" ascii
        $grat = "GRAT" ascii

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        filesize < 30MB and
        (
            3 of ($wipe*) or
            (2 of ($wipe*) and $pass) or
            ($wipe1 and $wipe2 and $wipe3 and $grat)
        )
}
```

### YARA: FlockWiper PDB Path

Detects FlockWiper samples via PDB paths containing the GRAT project framework identifier.

**Status:** compile ✅ yarac exit 0 | Confidence: high

<!-- audit: yarac exit 0. PDB paths are unique to this malware family's development environment. Any of the three patterns is sufficient for high-confidence detection. -->

```yara
rule Malware_FlockWiper_PDB_Path
{
    meta:
        description = "Detects FlockWiper C-based wiper samples via PDB paths containing the GRAT project framework identifier"
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721"
        hash = "db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674"
        severity = "critical"

    strings:
        $pdb1 = "A:\\GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii
        $pdb2 = "E:\\files\\new\\GRAT\\CWipe\\Release\\CWipe.pdb" ascii
        $pdb3 = "\\GRAT\\CWipe" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        any of ($pdb*)
}
```

### YARA: Crucio Ransomware Strings

Detects Crucio ransomware samples sharing code with GigaWiper Command 3 (BigBangExtortMain).

**Status:** compile ✅ yarac exit 0 | Confidence: medium

<!-- audit: yarac exit 0. The combination of BigBangExtortMain + .candy extension is unique to Crucio/GigaWiper family. Individual strings like .candy or key.txt are too generic alone; condition requires family-specific combinations. -->

```yara
rule Malware_Crucio_Ransomware_Strings
{
    meta:
        description = "Detects Crucio ransomware samples sharing code with GigaWiper Command 3 (fake ransomware / BigBangExtortMain)"
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3"
        severity = "high"

    strings:
        $s1 = "BigBangExtortMain" ascii
        $s2 = ".candy" ascii
        $s3 = "image_danger.jpg" ascii
        $s4 = "key.txt" ascii

        $arg1 = "-k" ascii
        $arg2 = "-i" ascii
        $arg3 = "--keyfile" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            ($s1 and $s2) or
            ($s2 and $s3 and 2 of ($arg*)) or
            ($s1 and $s3 and $s4)
        )
}
```

### Snort: GigaWiper C2 Communication (3 rules)

Three Snort rules covering GigaWiper C2 infrastructure: RabbitMQ AMQP on port 5544 (with AMQP protocol header match), Redis on port 7542, and secondary C2 at 212[.]8[.]248[.]104.

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high (IOC-specific)

<!-- audit: snort not available in environment. Rules follow standard Snort 3 syntax. SID 2100201 includes AMQP protocol magic "AMQP" at depth:4 for the RabbitMQ channel. SID 2100202 includes Redis RESP protocol "*" prefix. SID 2100203 is IP-only for secondary C2 (protocol unspecified in source). -->

```
alert tcp $HOME_NET any -> 185.182.193.21 5544 (msg:"Actioner - GigaWiper RabbitMQ C2 Communication to 185.182.193.21:5544"; flow:established,to_server; content:"AMQP"; depth:4; sid:2100201; rev:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-11;)

alert tcp $HOME_NET any -> 185.182.193.21 7542 (msg:"Actioner - GigaWiper Redis C2 Communication to 185.182.193.21:7542"; flow:established,to_server; content:"*"; depth:1; sid:2100202; rev:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-11;)

alert tcp $HOME_NET any -> 212.8.248.104 any (msg:"Actioner - GigaWiper Secondary C2 Communication to 212.8.248.104"; flow:established,to_server; sid:2100203; rev:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-11;)
```

### Suricata: GigaWiper C2 Communication (3 rules)

Three Suricata rules mirroring the Snort coverage with Suricata-specific syntax (fast_pattern placement).

**Status:** ⚠️ uncompiled (structural check only) | Confidence: high (IOC-specific)

<!-- audit: suricata not available in environment. Rules use Suricata 6+ syntax with proper keyword ordering. fast_pattern applied to AMQP header in SID 2100201. -->

```
alert tcp $HOME_NET any -> 185.182.193.21 5544 (msg:"Actioner - GigaWiper RabbitMQ AMQP C2 Channel"; flow:established,to_server; content:"AMQP"; depth:4; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-11; sid:2100201; rev:1;)

alert tcp $HOME_NET any -> 185.182.193.21 7542 (msg:"Actioner - GigaWiper Redis Result Exfiltration Channel"; flow:established,to_server; content:"*"; depth:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-11; sid:2100202; rev:1;)

alert tcp $HOME_NET any -> 212.8.248.104 any (msg:"Actioner - GigaWiper Secondary C2 Server"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-11; sid:2100203; rev:1;)
```

## References

- [Microsoft Threat Intelligence - GigaWiper: Anatomy of a Destructive Backdoor Assembled from Multiple Malware](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
- [CISA - Crucio Ransomware Advisory (December 2023)](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Google Threat Intelligence - BLUERABBIT Tracking](https://cloud.google.com/blog/topics/threat-intelligence)
