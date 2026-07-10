# Technical Analysis Report: GigaWiper Destructive Backdoor (2026-07-10)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-10
Version: 1.0-DRAFT

## Executive Summary

GigaWiper is a Go-based Windows backdoor that consolidates disk wiping, fake ransomware encryption, and spyware capabilities into a single modular platform with 20 distinct command handlers. Disclosed by Microsoft Threat Intelligence on July 9, 2026, the malware assembles code from three previously separate malware families -- Crucio ransomware (first analyzed by CISA in December 2023), FlockWiper (a C/C++ multi-pass wiper first observed June 2025), and a standalone disk wiper -- into one unified implant. GigaWiper uses RabbitMQ (AMQP) for command delivery and Redis for result exfiltration, communicating with C2 infrastructure at `185.182.193[.]21` on non-standard ports (5544 for AMQP, 7542 for Redis). The malware was first observed in compromised environments in October 2025.

The backdoor's capabilities span destructive operations (physical disk wiping, boot file deletion leading to BSOD, and undecryptable file encryption with `.candy` extension), espionage (screen recording, screenshots, keylogger slots, VNC-like remote access), and system manipulation (process/service/registry management, event log clearing, PowerShell execution). Persistence is achieved via a scheduled task named "OneDrive Update" set to run every minute.

## Background: GigaWiper Malware Platform

GigaWiper represents a convergence trend in destructive malware development: the consolidation of multiple proven destructive tools into a single, modular backdoor. The Go programming language was chosen for the main backdoor, while incorporating code patterns from the C/C++-based FlockWiper and the Crucio ransomware family. The "GRAT" identifier found in both FlockWiper PDB paths and GigaWiper function names links the tools to a common development framework or threat actor. The use of RabbitMQ and Redis for C2 -- instead of more common HTTP-based channels -- provides the operator with message queue reliability, targeted command delivery (via RabbitMQ topic exchange routing keys), and broadcast capability (via fanout exchange "All").

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| December 2023 | CISA publishes advisory on Crucio ransomware; code later reused in GigaWiper command 3 |
| June 2025 | FlockWiper (C/C++ wiper) first uploaded to VirusTotal |
| October 2025 | GigaWiper first observed in compromised environments |
| July 9, 2026 | Microsoft Threat Intelligence publishes detailed analysis of GigaWiper |

## Root Cause: Initial Access Vector

The Microsoft analysis does not detail the initial access vector used to deploy GigaWiper. The report focuses on post-compromise capabilities, indicating GigaWiper is deployed after an environment has already been compromised. The malware establishes persistence and awaits operator commands via RabbitMQ.

## Technical Analysis of the Malicious Payload

### 1. Modular Command Architecture

GigaWiper implements 20 command handlers dispatched via a `cmd.Task` structure received over RabbitMQ. Each command is mapped in `RTYPE_map_string_cmd_appInfoStc`. Key commands:

| Cmd | Function | Capability |
|-----|----------|------------|
| 1 | `WipeMain` | Physical disk wiping via `DeviceIoControl` with `IOCTL_DISK_CREATE_DISK` to remove partition metadata |
| 2 | (inline) | BSOD induction via boot file deletion (bootmgr, ntoskrnl.exe) and registry disablement |
| 3 | `RanMain` / `BigBangExtortMain` | Undecryptable file encryption with `.candy` extension; wallpaper replacement with `image_danger.jpg` |
| 4 | MinIO client | File exfiltration via MinIO upload |
| 5 | Crypto utility | AES-256-CBC file encryption/decryption with `crypto/rand.Read` for key/IV generation |
| 7 | Shell | PowerShell command execution |
| 8 | Route manager | Dynamic RabbitMQ binding management |
| 9 | Screenshot | One PNG per active monitor with timestamp naming |
| 10 | Screen recorder | Video capture triggered when system is unlocked and user not idle for 10+ seconds |
| 12 | `WipeCMain` | Secure multi-pass C: drive wipe (zeros, 0xFF, random bytes) |
| 13 | (reserved) | Admin-elevated wiper binary |
| 15 | `GRATClientInfo` | System enumeration and reconnaissance |
| 16-18 | Managers | Process, service, and registry management |
| 19 | Log clearer | Event log deletion; outputs the string "kharbvnmhkjbkjb" |
| 20 | VNC server | Remote desktop with keyboard/mouse control over TCP |

Commands 6, 11, and 14 are reserved/unfilled slots, suggesting ongoing development.

### 2. Persistence Mechanism

GigaWiper creates a scheduled task named "OneDrive Update" configured to run every minute and at system startup. A registry key at `HKCU\SOFTWARE\OneDrive\Environment` tracks execution state. When running from the task scheduler, the malware logs "Running from Task Scheduler..." internally.

### 3. C2 Infrastructure

**RabbitMQ (AMQP) -- Command Delivery:**
- Server: `185.182.193[.]21:5544`
- Fanout exchange "All" broadcasts commands to every infected host
- Topic exchange "Topic" delivers commands to specific machines via routing keys
- Task structure: `cmd.Task` with `task_id`, `command_code`, `args`

**Redis -- Result Exfiltration:**
- Server: `185.182.193[.]21:7542`
- Result structure: `cmd.Result` with `error`, `target_ip`, `task_id`, `target_computer_name`, `output`, `pwd`, `time`, `status`, `work_status`

**Additional C2:**
- `212.8.248[.]104` -- secondary GigaWiper C2 endpoint

### 4. Destructive Capabilities

**Disk Wiping (Command 1):** Enumerates physical drives via WMI query `SELECT * FROM Win32_DiskDrive`, uses `DeviceIoControl` with `IOCTL_DISK_CREATE_DISK` to remove partition metadata, then calls `main.writeRandToDrive` to overwrite disk contents. Logs "Partitions removed successfully" on completion.

**Multi-Pass Wipe (Command 12):** Reimplements FlockWiper logic in Go. Three-pass overwrite of C: drive (zeros, 0xFF, random) with timing output: "Pass 1 Time took: %s\n", "Pass 2 Time took: %s\n", "Pass 3 Time took: %s\n".

**Fake Ransomware (Command 3):** Encrypts files using AES-CBC with random keys generated via `crypto/rand.Read`, appends `.candy` extension, replaces wallpaper with `image_danger.jpg`. Based on Crucio ransomware code (`BigBangExtortMain`). Encryption is intentionally undecryptable -- the key is not preserved for the victim.

**BSOD Induction (Command 2):** Deletes boot configuration data and Windows boot files (bootmgr, ntoskrnl.exe), modifies registry to disable recovery.

### 5. Anti-Forensics / Evasion Techniques

- **Event log clearing (Command 19):** Uses `wevtutil.exe` to clear Security, System, and Application logs; falls back to manual deletion of `C:\Windows\System32\winevt\Logs\Security.evtx` if wevtutil fails. Outputs the unique string "kharbvnmhkjbkjb" on completion.
- **Firewall rule masquerading (Command 20):** Creates Windows Firewall rules with DisplayName containing "Microsoft.Windows.CloudExperienceHost" to disguise VNC-like remote access traffic.
- **Scheduled task masquerading:** Uses "OneDrive Update" as the task name, mimicking legitimate OneDrive update processes.
- **PowerShell AV discovery:** Queries `root\SecurityCenter2` WMI namespace for `AntivirusProduct` class to enumerate installed security products and output as JSON.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### File System

| Platform | Path / Name | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | GigaWiper backdoor | `633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001` | GigaWiper backdoor variant |
| Windows | GigaWiper backdoor | `ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913` | GigaWiper backdoor variant |
| Windows | GigaWiper backdoor | `f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd` | GigaWiper backdoor variant |
| Windows | GigaWiper backdoor | `9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683` | GigaWiper backdoor variant |
| Windows | Standalone wiper | `3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd` | Standalone wiper component |
| Windows | Crucio ransomware | `440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3` | Crucio ransomware (code basis for command 3) |
| Windows | FlockWiper | `12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721` | FlockWiper (code basis for command 12) |
| Windows | FlockWiper | `db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674` | FlockWiper variant |
| Windows | `C:\ProgramData\output` | -- | Screen recording storage directory |
| Windows | `C:\Windows\System32\winevt\Logs\Security.evtx` | -- | Targeted for manual deletion |
| Windows | `image_danger.jpg` | -- | Ransomware wallpaper image |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP:Port | `185.182.193[.]21:5544` | RabbitMQ (AMQP) C2 server |
| IP:Port | `185.182.193[.]21:7542` | Redis C2 server |
| IP | `212.8.248[.]104` | Secondary GigaWiper C2 |

### Behavioral

- Scheduled task "OneDrive Update" created to execute every minute and at startup
- Registry key `HKCU\SOFTWARE\OneDrive\Environment` created/modified by non-OneDrive processes
- PowerShell `Add-NetFirewallRule` with DisplayName containing "Microsoft.Windows.CloudExperienceHost"
- PowerShell WMI query to `SecurityCenter2\AntivirusProduct` with `ConvertTo-Json` output
- WMI query `SELECT * FROM Win32_DiskDrive` for physical disk enumeration
- Event log clearing via `wevtutil.exe` (Security, System, Application)
- Files encrypted with `.candy` extension
- AMQP traffic on port 5544 to external infrastructure
- Redis traffic on port 7542 to external infrastructure

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1053.005 | Scheduled Task | "OneDrive Update" task created for persistence (every minute + startup) |
| T1112 | Modify Registry | `HKCU\SOFTWARE\OneDrive\Environment` used for execution tracking |
| T1486 | Data Encrypted for Impact | AES-CBC encryption with `.candy` extension; keys not preserved (undecryptable) |
| T1561.002 | Disk Wipe: Disk Structure Wipe | Physical disk partition metadata removal via `IOCTL_DISK_CREATE_DISK` |
| T1529 | System Shutdown/Reboot | BSOD induction via boot file deletion |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | Firewall rules masquerading as CloudExperienceHost |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | Event log clearing via wevtutil and manual EVTX deletion |
| T1518.001 | Software Discovery: Security Software Discovery | WMI query for AntivirusProduct in SecurityCenter2 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell command execution (command 7) |
| T1113 | Screen Capture | Screenshots (command 9) and screen recording (command 10) |
| T1021 | Remote Services | VNC-like remote desktop server (command 20) |
| T1057 | Process Discovery | Process management (command 16) |
| T1012 | Query Registry | Registry management and querying (command 18) |
| T1007 | System Service Discovery | Service management (command 16/17) |
| T1082 | System Information Discovery | `GRATClientInfo` system enumeration (command 15) |

## Impact Assessment

GigaWiper is designed for maximum destructive impact. Its multi-modal destruction approach -- combining disk wiping, undecryptable encryption, and boot file deletion -- ensures data loss even if one destruction method is interrupted. The modular command architecture with reserved slots (commands 6, 11, 14) indicates active development. The use of RabbitMQ with fanout exchange enables simultaneous wipe commands across all compromised hosts, making coordinated mass destruction operationally simple for the attacker. The integration of espionage capabilities (screen recording, screenshots, VNC) alongside destructive functions suggests a workflow of intelligence gathering followed by destructive action.

## Detection & Remediation

### Immediate Detection

Check for the specific scheduled task:
```
schtasks /query /tn "OneDrive Update" /fo LIST /v
```

Check for the registry key:
```
reg query "HKCU\SOFTWARE\OneDrive\Environment"
```

Check for network connections to known C2:
```
netstat -an | findstr "185.182.193.21 212.8.248.104"
```

Search for `.candy` encrypted files:
```
dir /s /b C:\*.candy
```

Check for suspicious firewall rules:
```powershell
Get-NetFirewallRule | Where-Object { $_.DisplayName -like '*CloudExperienceHost*' } | Format-List
```

### Remediation

1. **Isolate** affected hosts from the network immediately to prevent broadcast wipe commands via RabbitMQ fanout exchange
2. **Block** C2 IPs `185.182.193.21` and `212.8.248.104` at the network perimeter on all ports
3. **Remove** the "OneDrive Update" scheduled task and the `HKCU\SOFTWARE\OneDrive\Environment` registry key
4. **Delete** any firewall rules with DisplayName matching "CloudExperienceHost" that were not legitimately created
5. **Scan** for known file hashes using endpoint detection tools
6. **Restore** from known-good backups if disk wiping or encryption has occurred -- encrypted files with `.candy` extension are not recoverable

### Long-Term Hardening

- Monitor for AMQP (RabbitMQ) and Redis traffic on non-standard ports to external IPs
- Implement application whitelisting to prevent unauthorized Go binaries from executing
- Enable PowerShell Script Block Logging and monitor for WMI SecurityCenter2 queries
- Restrict schtasks.exe execution to authorized administrative processes
- Monitor for bulk file rename operations (`.candy` extension) as an early indicator of encryption activity

## Detection Rules

These detections target GigaWiper-specific artifacts at advisory-specific altitude: scheduled task names, registry paths, Go function name strings, and C2 IP/port pairs. Compiles does not equal fires -- verify in your pipeline with representative log data.

### Sigma: GigaWiper Scheduled Task Persistence

Detects creation of the "OneDrive Update" scheduled task via schtasks.exe, the persistence mechanism used by GigaWiper.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403 via proxy); sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0; splunk_windows pipeline exit 0. Field names standard for process_creation/windows. Values not defanged. -->
```yaml
title: GigaWiper Scheduled Task Persistence - OneDrive Update
id: d8a1e7c3-4f52-4b9a-8c6d-1e3f5a7b9d0e
status: experimental
description: >
    Detects creation of the "OneDrive Update" scheduled task used by GigaWiper
    for persistence, configured to run every minute and at system startup.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/10
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith: '\schtasks.exe'
    selection_taskname:
        CommandLine|contains: 'OneDrive Update'
    condition: selection_binary and selection_taskname
falsepositives:
    - Legitimate OneDrive update mechanisms using identically named scheduled tasks
level: high
```

### Sigma: GigaWiper Registry Key Modification

Detects writes to the `HKCU\SOFTWARE\OneDrive\Environment` registry path by non-OneDrive processes, used by GigaWiper for execution tracking.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0; splunk_windows pipeline exit 0. Filter excludes legitimate OneDrive binaries. Medium confidence: legitimate OneDrive may write to adjacent keys; filter may not cover all OneDrive update paths. -->
```yaml
title: GigaWiper Registry Key Modification - OneDrive Environment
id: f3b2c8d1-6e54-4a7f-9b3c-2d1e0f4a5b6c
status: experimental
description: >
    Detects modifications to HKCU\SOFTWARE\OneDrive\Environment registry key
    used by GigaWiper for execution tracking.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/10
tags:
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\SOFTWARE\OneDrive\Environment'
    filter_onedrive:
        Image|endswith:
            - '\OneDrive.exe'
            - '\OneDriveSetup.exe'
    condition: selection and not filter_onedrive
falsepositives:
    - Legitimate OneDrive client writing to its own registry keys
level: medium
```

### Sigma: GigaWiper Firewall Rule Masquerading as CloudExperienceHost

Detects PowerShell `Add-NetFirewallRule` creating a firewall rule with DisplayName containing "CloudExperienceHost", used by GigaWiper command 20 to allow VNC-like inbound TCP.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. ps_script/windows logsource requires PowerShell Script Block Logging (EID 4104). Combination of Add-NetFirewallRule + CloudExperienceHost in script block is highly distinctive. -->
```yaml
title: GigaWiper Firewall Rule Masquerading as CloudExperienceHost
id: a7c4d9e2-3b51-4f8a-b6c5-8d2e1f3a0b7c
status: experimental
description: >
    Detects PowerShell Add-NetFirewallRule with DisplayName containing
    Microsoft.Windows.CloudExperienceHost, a masquerading technique used
    by GigaWiper command 20 (VNC-like remote access) to allow inbound TCP.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/10
tags:
    - attack.t1562.004
logsource:
    category: ps_script
    product: windows
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Add-NetFirewallRule'
            - 'CloudExperienceHost'
    condition: selection
falsepositives:
    - Legitimate Windows Cloud Experience Host firewall configuration
level: high
```

### Sigma: GigaWiper Antivirus Enumeration via WMI

Detects the specific PowerShell WMI pattern querying `SecurityCenter2\AntivirusProduct` with JSON output, as used by GigaWiper for security software discovery.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. Medium confidence: legitimate security monitoring scripts may use the same WMI query pattern with ConvertTo-Json. The three-term AND narrows FPs vs a single-term match. -->
```yaml
title: GigaWiper Antivirus Enumeration via WMI
id: e5f1a3b7-2c84-4d96-a9e8-6b0d3f7c2e1a
status: experimental
description: >
    Detects the specific PowerShell WMI query to SecurityCenter2 AntivirusProduct
    class with JSON output conversion, as used by GigaWiper for defense discovery.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/10
tags:
    - attack.t1518.001
logsource:
    category: ps_script
    product: windows
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'SecurityCenter2'
            - 'AntivirusProduct'
            - 'ConvertTo-Json'
    condition: selection
falsepositives:
    - Security monitoring scripts that enumerate installed antivirus products
    - IT asset management tools
level: medium
```

### Suricata: GigaWiper AMQP/Redis C2 Communication

Detects TCP connections to GigaWiper's known C2 infrastructure: AMQP on `185.182.193[.]21:5544`, Redis on `185.182.193[.]21:7542`, and any connection to `212.8.248[.]104`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Three rules: sid 2200001 (AMQP with AMQP header content match), sid 2200002 (Redis with RESP protocol content match), sid 2200003 (secondary C2 IP any port). IP-based rules are high confidence but time-limited; infrastructure will rotate. Values are real (not defanged). -->
```suricata
alert tcp $HOME_NET any -> 185.182.193.21 5544 (msg:"Actioner - GigaWiper AMQP C2 Communication to Known Infrastructure"; flow:established,to_server; content:"AMQP"; depth:4; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-10; sid:2200001; rev:1;)
alert tcp $HOME_NET any -> 185.182.193.21 7542 (msg:"Actioner - GigaWiper Redis C2 Communication to Known Infrastructure"; flow:established,to_server; content:"*"; depth:1; content:"|0d 0a|"; distance:0; within:10; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-10; sid:2200002; rev:1;)
alert tcp $HOME_NET any -> 212.8.248.104 any (msg:"Actioner - GigaWiper C2 Communication to Known IP 212.8.248.104"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-10; sid:2200003; rev:1;)
```

### Snort: N/A

Snort is not installed in this environment. The Suricata rules above cover the same network indicators. Label: uncompiled (structural check only).

### YARA: GigaWiper Go Backdoor and FlockWiper PDB

Detects GigaWiper via distinctive Go function names (`rabbit_tools_tool_wipe_main.WipeMain`, `BigBangExtortMain`, `GRATClientInfo`) and unique strings (`kharbvnmhkjbkjb`, `Partitions removed successfully`); separately detects FlockWiper via PDB paths containing the "GRAT" identifier.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: positive (constructed MZ + published function names) matched Malware_GigaWiper_Go_Backdoor; negative (benign MZ) did not match. Positive strings sourced from Microsoft's published function names and debug output. Condition requires MZ header + filesize <50MB + (3 of fn* OR 2 fn + 2 str OR 4 str). FlockWiper rule keys on exact PDB paths from published analysis. -->
```yara
rule Malware_GigaWiper_Go_Backdoor
{
    meta:
        description = "Detects GigaWiper Go-based destructive backdoor via distinctive function names and strings"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001"
        hash = "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913"
        hash = "f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd"
        hash = "9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683"
        severity = "critical"

    strings:
        $fn1 = "rabbit_tools_tool_wipe_main.WipeMain" ascii
        $fn2 = "rabbit_tools_tool_ran_main_cmd_extort.RanMain" ascii
        $fn3 = "rabbit_tools_tool_ran_main_bin.BigBangExtortMain" ascii
        $fn4 = "rabbit_tools_tool_wipec_main.WipeCMain" ascii
        $fn5 = "rabbit_bin.RunOnceRegistryMain" ascii
        $fn6 = "GRATClientInfo" ascii
        $fn7 = "RTYPE_map_string_cmd_appInfoStc" ascii

        $str1 = "Partitions removed successfully" ascii
        $str2 = "kharbvnmhkjbkjb" ascii
        $str3 = "Key/IV required. Use -k/-i or" ascii
        $str4 = "Pass 1 Time took: %s" ascii
        $str5 = "Running from Task Scheduler" ascii
        $str6 = "Task created. Original process exiting." ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (3 of ($fn*) or (2 of ($fn*) and 2 of ($str*)) or 4 of ($str*))
}

rule Malware_FlockWiper_PDB
{
    meta:
        description = "Detects FlockWiper wiper component via PDB debug paths containing GRAT identifier"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721"
        hash = "db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674"
        severity = "critical"

    strings:
        $pdb1 = "A:\\GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii
        $pdb2 = "E:\\files\\new\\GRAT\\CWipe\\Release\\CWipe.pdb" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        any of ($pdb*)
}
```

## Lessons Learned

GigaWiper demonstrates the threat of **malware consolidation**: threat actors are assembling proven destructive tools into unified, modular platforms rather than developing new capabilities from scratch. The combination of destruction (wiping + encryption + BSOD) with espionage (screen recording + VNC) in a single implant enables a "observe then destroy" workflow that maximizes both intelligence value and destructive impact.

The use of RabbitMQ's fanout exchange for C2 is particularly concerning for defenders: a single broadcast command can trigger simultaneous disk wipes across all compromised hosts, compressing the response window to near-zero. Organizations should prioritize network-level detection of AMQP and Redis traffic to external, non-corporate infrastructure, and maintain offline backups that cannot be reached by an attacker who has compromised the internal network.

The "GRAT" framework identifier linking FlockWiper (June 2025) to GigaWiper (October 2025) suggests a threat actor with a sustained development pipeline. Defenders should expect future iterations and watch for the "GRAT" string in Go binary function names as a durable attribution marker.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Microsoft Threat Intelligence Blog](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/) -- primary technical analysis with full IOC list, command table, and code-level details
- [The Hacker News](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html) -- news coverage summarizing key capabilities and scheduled task persistence
- [Hackread](https://hackread.com/microsoft-gigawiper-backdoor-destroy-windows-pcs/) -- news coverage with additional context on destructive capabilities
- [Security Affairs](https://securityaffairs.com/195068/malware/gigawiper-merges-three-malware-families-into-one-destructive-backdoor.html) -- coverage with RabbitMQ exchange configuration details
- [SecurityWeek](https://www.securityweek.com/gigawiper-combines-multiple-malware-for-system-level-sabotage/) -- coverage summarizing modular command architecture

---
*Report generated by Actioner*
