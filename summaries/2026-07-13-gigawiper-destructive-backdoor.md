<!-- revision: v1.1 2026-07-13 — Dropped generic wevtutil Sigma rule (altitude); defanged IPs in Remediation; added SID-range deployment note; added Hackread/Infosecurity Magazine/The Register to Sources. -->
# Technical Analysis Report: GigaWiper Destructive Windows Backdoor (2026-07-13)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-13
Version: 1.1 (Final)

## Executive Summary

GigaWiper is a sophisticated Golang-based Windows backdoor that combines destructive wiper capabilities, ransomware-like encryption, and spyware functionality into a single modular platform. Published on 2026-07-09 by Microsoft Threat Intelligence, the analysis reveals a 20-command backdoor that uses RabbitMQ (AMQP) for tasking and Redis for status reporting, with MinIO for data exfiltration. The malware incorporates code from two prior destructive tools: the Crucio ransomware (linked to CyberAv3ngers / IRGC) and the FlockWiper disk wiper. GigaWiper can overwrite raw disk partitions, encrypt files with irrecoverable AES keys, trigger BSODs, capture screens, establish VNC sessions, manage processes/services/registry, and clear event logs. It persists via a scheduled task named "OneDrive Update" and masquerades its firewall rule as a legitimate Windows component. Google Threat Intelligence Group and Binary Defense track this malware as BLUERABBIT.

## Background: Targeted Windows Environments

GigaWiper targets Windows endpoints across enterprise environments. The malware is written in Go (Golang), enabling cross-compilation potential, though all observed samples target Windows. Its architecture is designed as a multi-purpose implant capable of both intelligence collection (screenshots, screen recording, system reconnaissance) and destructive operations (disk wiping, fake ransomware encryption, BSOD induction), making it suitable for both espionage and sabotage campaigns. The reuse of Crucio ransomware code links GigaWiper to CyberAv3ngers, an IRGC-affiliated threat actor previously identified by CISA in December 2023.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2023-12 | CISA advisory identifies CyberAv3ngers and Crucio ransomware activity |
| Pre-2026 | FlockWiper developed (contains "GRAT" debug tag in PDB paths) |
| 2026-07-09 | Microsoft Threat Intelligence publishes detailed GigaWiper analysis |
| 2026-07-09 | Multiple outlets (THN, Hackread, Infosecurity Magazine, The Register) report on GigaWiper |

## Root Cause: Initial Access Vector

The Microsoft report focuses on the backdoor's internal architecture and capabilities. The initial access vector is not explicitly detailed in the published analysis. Given the CyberAv3ngers attribution lineage, prior campaigns have leveraged exploitation of internet-facing devices and spearphishing. Defenders should monitor for the persistence and C2 indicators detailed below regardless of the initial compromise vector.

## Technical Analysis of the Malicious Payload

### 1. Configuration and Initialization

GigaWiper decrypts its configuration using AES with a hardcoded key. On first execution, it creates a scheduled task named "OneDrive Update" via PowerShell's `Register-ScheduledTask` cmdlet, configured to run every minute and at system startup. The malware writes to the registry key `HKCU\SOFTWARE\OneDrive\Environment` to track its execution count. It creates a Windows Firewall rule named "Microsoft.Windows.CloudExperienceHost" to whitelist its network traffic, masquerading as a legitimate Windows component.

### 2. Command Dispatch Architecture (20 Commands)

GigaWiper implements a 20-command dispatch system using Go structs `cmd.Task` (task_id, command_code, args) and `cmd.Result` (error, target_ip, task_id, target_computer_name, output, pwd, time, status, work_status). Key destructive commands include:

- **Command 1 (Standalone Wiper):** Overwrites physical disk in 0xA00000-byte chunks, destroys partition tables via `DeviceIoControl` with `IOCTL_DISK_CREATE_DISK`, enumerates disks via WMI (`SELECT * FROM Win32_DiskDrive`)
- **Command 2 (BSOD Trigger):** Deletes critical boot files via registry/permission manipulation, forces reboot via Windows shutdown API
- **Command 3 (Fake Ransomware):** AES-CBC encryption with random key/IV that are never saved, making recovery impossible; appends `.candy` extension; excludes `.exe` and `.dll`; reuses Crucio's `BigBangExtortMain` function
- **Command 5 (Configurable Encryption):** AES-256 CBC with operator-supplied key/IV
- **Command 12 (Secure Wipe):** Multi-pass overwriting (zeros, 0xFF, random) -- a Go reimplementation of FlockWiper

### 3. C2 Infrastructure

GigaWiper uses a multi-protocol C2 architecture:

- **RabbitMQ (AMQP):** Used for receiving commands from the operator. Connects to `185.182.193[.]21` on port 5544. Uses a fanout exchange named "All" for broadcast commands and a topic exchange named "Topic" for targeted tasking.
- **Redis:** Used for sending status updates and results back to the operator. Connects to `185.182.193[.]21` on port 7542.
- **MinIO:** Used for data exfiltration (Command 4) with operator-configurable credentials and bucket.
- **Secondary C2 IP:** `212.8.248[.]104`

Goroutine-based background task execution allows concurrent command processing.

### 4. Platform-Specific Behavior

#### Windows

GigaWiper is exclusively a Windows backdoor in all observed samples:

- **Process Management (Command 16):** createProcess, resumeProcess, suspendProcess, killProcess, list, processInfo
- **Service Management (Command 17):** create, delete, restart, query, start, list, stop
- **Registry Management (Command 18):** show, navigate, back, exit, createKey, deleteKey, deleteValue, setValue
- **Screenshot/Recording (Commands 9-10):** PNG screenshot capture of all monitors; screen recording saved to `C:\ProgramData\output`
- **VNC Remote Control (Command 20):** TCP-based screen streaming with keyboard/mouse input
- **PowerShell Execution:** Commands executed with pipe-parsing for working directory tracking
- **System Reconnaissance (Command 15):** Collects IP, machine GUID, CPU info, OS details, network configuration, firmware info, user data, and antivirus inventory via PowerShell

### 5. Anti-Forensics / Evasion Techniques

- **Event Log Clearing (Command 19):** Uses `wevtutil.exe` to delete System, Setup, Application, ForwardedEvents, and Security logs. Prints the decoy string "kharbvnmhkjbkjb" during execution.
- **Firewall Rule Masquerading:** Creates firewall rule named "Microsoft.Windows.CloudExperienceHost" to blend with legitimate Windows components
- **Scheduled Task Naming:** Uses "OneDrive Update" to mimic legitimate Microsoft software
- **Reboot Forcing:** Forces system reboot after destructive operations to ensure changes take effect

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `185.182.193[.]21`)

### File System

| Platform | Path / Name | Hash (SHA-256) | Description |
|----------|-------------|----------------|-------------|
| Windows | GigaWiper backdoor | `633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001` | GigaWiper backdoor sample |
| Windows | GigaWiper backdoor | `ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913` | GigaWiper backdoor sample |
| Windows | GigaWiper backdoor | `f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd` | GigaWiper backdoor sample |
| Windows | GigaWiper backdoor | `9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683` | GigaWiper backdoor sample |
| Windows | Standalone wiper | `3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd` | Standalone wiper component |
| Windows | Crucio ransomware | `440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3` | Related Crucio ransomware |
| Windows | FlockWiper | `12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721` | Related FlockWiper sample |
| Windows | FlockWiper | `db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674` | Related FlockWiper sample |
| Windows | `C:\ProgramData\output` | -- | Screen recording output directory |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `185.182.193[.]21` | C2 server -- RabbitMQ (port 5544) and Redis (port 7542) |
| IP | `212.8.248[.]104` | Secondary C2 infrastructure |
| Port | 5544 | Non-standard AMQP port for RabbitMQ C2 |
| Port | 7542 | Non-standard Redis port for status reporting |

### Behavioral

- Scheduled task "OneDrive Update" created to run every minute and at startup
- Registry writes to `HKCU\SOFTWARE\OneDrive\Environment` (execution tracking)
- Firewall rule "Microsoft.Windows.CloudExperienceHost" created via netsh
- WMI queries: `SELECT * FROM Win32_DiskDrive` (disk enumeration for wiper)
- `DeviceIoControl` calls with `IOCTL_DISK_CREATE_DISK` (partition table destruction)
- Files encrypted with `.candy` extension (fake ransomware, irrecoverable)
- Multiple event logs cleared via `wevtutil.exe cl` in rapid succession
- String "kharbvnmhkjbkjb" printed during event log clearing operation
- PowerShell-based system reconnaissance collecting IP, GUID, CPU, OS, AV inventory

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1053.005 | Scheduled Task | "OneDrive Update" task created for persistence (every minute + startup) |
| T1112 | Modify Registry | Writes execution count to `HKCU\SOFTWARE\OneDrive\Environment` |
| T1562.004 | Disable or Modify System Firewall | Creates firewall rule "Microsoft.Windows.CloudExperienceHost" |
| T1059.001 | PowerShell | System reconnaissance and task scheduling via PowerShell |
| T1082 | System Information Discovery | Command 15 collects IP, GUID, CPU, OS, network, firmware, AV info |
| T1057 | Process Discovery | Command 16 lists and inspects processes |
| T1485 | Data Destruction | Commands 1, 12 overwrite physical disk and partition tables |
| T1561.001 | Disk Content Wipe | Command 12 performs multi-pass disk overwriting |
| T1561.002 | Disk Structure Wipe | Command 1 destroys partition tables via IOCTL_DISK_CREATE_DISK |
| T1486 | Data Encrypted for Impact | Command 3 encrypts files with irrecoverable AES keys (.candy) |
| T1489 | Service Stop | Command 17 can stop and delete services |
| T1070.001 | Clear Windows Event Logs | Command 19 clears System/Setup/Application/ForwardedEvents/Security logs |
| T1113 | Screen Capture | Commands 9-10 capture screenshots and record screen |
| T1219 | Remote Access Software | Command 20 provides VNC-like remote control |
| T1041 | Exfiltration Over C2 Channel | Command 4 uses MinIO for data exfiltration |
| T1071 | Application Layer Protocol | RabbitMQ (AMQP) for C2, Redis for results |

## Impact Assessment

GigaWiper represents a high-severity threat combining intelligence collection and destructive capabilities in a single implant. The platform's 20-command architecture gives operators flexibility to conduct espionage (screenshots, screen recording, system recon), sabotage (disk wiping, fake ransomware, BSOD), or both in sequence. The irrecoverable encryption (AES-CBC with discarded keys) disguised as ransomware is particularly concerning -- victims cannot recover data even if they attempt to pay. The lineage connection to CyberAv3ngers (IRGC) via Crucio code reuse, corroborated by the "GRAT" debug tag shared between FlockWiper and GigaWiper, suggests state-sponsored destructive intent.

## Detection & Remediation

### Immediate Detection

- Search for scheduled task named "OneDrive Update" not associated with legitimate OneDrive: `schtasks /query /tn "OneDrive Update"`
- Check for registry key: `reg query "HKCU\SOFTWARE\OneDrive\Environment"`
- Search firewall rules for "Microsoft.Windows.CloudExperienceHost": `netsh advfirewall firewall show rule name="Microsoft.Windows.CloudExperienceHost"`
- Scan for files with `.candy` extension across file servers
- Check for network connections to `185.182.193[.]21` or `212.8.248[.]104`
- Hash-scan endpoints for the 8 known SHA-256 hashes listed in the IOC section

### Remediation

1. **Contain:** Immediately isolate any host with confirmed indicators. Block C2 IPs (`185.182.193[.]21`, `212.8.248[.]104`) at the network perimeter and internal firewalls.
2. **Eradicate:** Remove the scheduled task "OneDrive Update", delete the malicious firewall rule, clean the registry key `HKCU\SOFTWARE\OneDrive\Environment`, and remove the malware binary.
3. **Recover:** Restore any `.candy`-encrypted files from offline backups (decryption is impossible). Re-image compromised hosts where disk wiper activity is suspected.
4. **Hunt:** Search for lateral movement indicators -- GigaWiper's service management and process injection capabilities suggest potential spread within the network.

### Long-Term Hardening

- Monitor for non-standard outbound ports (5544, 7542) that may indicate AMQP/Redis C2 channels
- Implement application whitelisting to prevent unauthorized Go binaries from executing
- Enable PowerShell script block logging and constrained language mode
- Maintain offline backups resistant to wiper and ransomware-like attacks
- Deploy Sysmon with configuration capturing scheduled task creation, registry modifications, and network connections

## Detection Rules

These detections target GigaWiper's distinctive persistence mechanisms, C2 infrastructure, and binary signatures at PoC/advisory-specific altitude. Compiles does not equal fires -- verify each rule against your telemetry pipeline before production deployment.

### Sigma: GigaWiper Scheduled Task Persistence

Detects creation of the "OneDrive Update" scheduled task used by GigaWiper for persistence via schtasks.exe or PowerShell.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by network proxy (MITRE ATT&CK data 403 — environment issue, not rule issue). sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. Keys on highly distinctive task name "OneDrive Update" combined with creation verbs. Legitimate OneDrive uses different task naming. FP risk: low — the exact combination of schtasks/Register-ScheduledTask with "OneDrive Update" is not used by legitimate software. -->
```yaml
title: GigaWiper Scheduled Task Persistence - OneDrive Update
id: 7c1e9b4a-3f2d-4a8e-b6c5-9d0e1f2a3b4c
status: experimental
description: >
    Detects creation of a scheduled task named "OneDrive Update" used by
    GigaWiper for persistence. The task runs every minute and at system startup.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/13
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
    - Legitimate Microsoft OneDrive update tasks with different naming patterns
level: high
```

### Sigma: GigaWiper Registry Key Modification

Detects writes to the `HKCU\SOFTWARE\OneDrive\Environment` registry key used by GigaWiper for execution tracking, excluding legitimate OneDrive.exe.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. Keys on the specific fake OneDrive registry path. Filter excludes legitimate OneDrive.exe. This path is not used by legitimate Microsoft OneDrive (which uses HKCU\Software\Microsoft\OneDrive). FP: very low. -->
```yaml
title: GigaWiper Registry Key - OneDrive Environment Tracking
id: 8d2f0c5b-4a3e-5b9f-c7d6-0e1f2a3b4c5d
status: experimental
description: >
    Detects modification of the HKCU\SOFTWARE\OneDrive\Environment registry key
    used by GigaWiper to track execution count on the host.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/13
tags:
    - attack.t1112
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
    - Legitimate OneDrive software writing to a similar registry path
level: high
```

### Sigma: GigaWiper Firewall Rule Masquerading

Detects netsh.exe creating a firewall rule named "Microsoft.Windows.CloudExperienceHost" used by GigaWiper to whitelist its C2 traffic.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. Keys on all four distinctive fragments in the netsh command line. The firewall rule name "Microsoft.Windows.CloudExperienceHost" is not created by legitimate Windows components via netsh. FP: effectively zero — this exact netsh invocation is unique to GigaWiper. -->
```yaml
title: GigaWiper Firewall Rule Masquerading as CloudExperienceHost
id: 9e3a1d6c-5b4f-6c0a-d8e7-1f2a3b4c5d6e
status: experimental
description: >
    Detects creation of a Windows Firewall rule named
    "Microsoft.Windows.CloudExperienceHost" used by GigaWiper to allow its
    network traffic while masquerading as a legitimate Windows component.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
author: Actioner
date: 2026/07/13
tags:
    - attack.t1562.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\netsh.exe'
        CommandLine|contains|all:
            - 'advfirewall'
            - 'firewall'
            - 'add'
            - 'Microsoft.Windows.CloudExperienceHost'
    condition: selection
falsepositives:
    - Unlikely - this specific firewall rule name combined with netsh is highly distinctive
level: critical
```

Dropped: Generic event-log-clearing rule (wevtutil cl) -- too broad for PoC/advisory-specific altitude.

### Snort: GigaWiper C2 Communication to Known Infrastructure

Detects TCP connections to GigaWiper's known C2 IP addresses on AMQP (5544), Redis (7542), and general traffic ports.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 with rules appended to local.rules. Three rules: (1) AMQP on 185.182.193.21:5544 with "AMQP" protocol magic in first 4 bytes; (2) Redis on 185.182.193.21:7542; (3) any port to 212.8.248.104. IOC-anchored; will age out when IPs rotate. Snort 2.9.20 validated. -->
```snort
alert tcp $HOME_NET any -> 185.182.193.21 5544 (msg:"Actioner - GigaWiper C2 Communication to Known AMQP Server"; flow:established,to_server; content:"AMQP"; depth:4; sid:2100001; rev:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/;)
alert tcp $HOME_NET any -> 185.182.193.21 7542 (msg:"Actioner - GigaWiper C2 Communication to Known Redis Server"; flow:established,to_server; sid:2100002; rev:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/;)
alert tcp $HOME_NET any -> 212.8.248.104 any (msg:"Actioner - GigaWiper C2 Communication to Known Infrastructure"; flow:established,to_server; sid:2100003; rev:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/;)
```

> **Deployment note (Snort/Suricata SID ranges):** The SIDs used in these rules (Snort 2100001-2100003, Suricata 2200001-2200003) may collide with Emerging Threats (ET) or other community rulesets. If your deployment includes ET rules, rebase these SIDs into your organization's local SID range (typically 1000000+) before loading.

### Suricata: GigaWiper C2 Communication to Known Infrastructure

Detects TCP connections to GigaWiper's known C2 IP addresses on AMQP (5544), Redis (7542), and general traffic ports.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S /tmp/actioner/gigawiper-c2-suricata.rules -l /tmp/actioner exit 0. Suricata 7.0.3. Three rules mirroring Snort coverage. sid range 2200001-2200003. IOC-anchored; will age out when infrastructure rotates. -->
```suricata
alert tcp $HOME_NET any -> 185.182.193.21 5544 (msg:"Actioner - GigaWiper AMQP C2 to Known Server 185.182.193.21:5544"; flow:established,to_server; content:"AMQP"; depth:4; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-13; sid:2200001; rev:1;)
alert tcp $HOME_NET any -> 185.182.193.21 7542 (msg:"Actioner - GigaWiper Redis C2 to Known Server 185.182.193.21:7542"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-13; sid:2200002; rev:1;)
alert tcp $HOME_NET any -> 212.8.248.104 any (msg:"Actioner - GigaWiper C2 to Known Infrastructure 212.8.248.104"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/; metadata:author Actioner, created_at 2026-07-13; sid:2200003; rev:1;)
```

### YARA: GigaWiper Golang Backdoor Strings

Detects GigaWiper backdoor binaries via distinctive strings from the malware's command dispatch, wiper routine, and Crucio ransomware heritage, combined with Go build indicator.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: fired on pos.txt containing published strings, quiet on neg.txt with partial overlap (Go build + 2 common strings). Positive constructed from published Microsoft source strings (not invented). Condition requires "Go build" plus 4 of 12 distinctive strings. The strings "Partitions removed successfully", "kharbvnmhkjbkjb", "BigBangExtortMain", ".candy", "Task created. Original process exiting" are unique to GigaWiper. FP: very low — the combination is highly specific. -->
```yara
rule Malware_GigaWiper_Backdoor_Strings
{
    meta:
        description = "Detects GigaWiper Golang-based destructive backdoor via characteristic strings from the malware's command dispatch, wiper, and encryption routines"
        author = "Actioner"
        date = "2026-07-13"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001"
        hash2 = "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913"
        severity = "critical"

    strings:
        $s1 = "Partitions removed successfully" ascii
        $s2 = "kharbvnmhkjbkjb" ascii
        $s3 = ".candy" ascii
        $s4 = "Task created. Original process exiting" ascii
        $s5 = "Running from Task Scheduler" ascii
        $s6 = "BigBangExtortMain" ascii
        $s7 = "cmd.Task" ascii
        $s8 = "cmd.Result" ascii
        $s9 = "createProcess" ascii
        $s10 = "resumeProcess" ascii
        $s11 = "suspendProcess" ascii
        $s12 = "killProcess" ascii
        $go = "Go build" ascii

    condition:
        filesize < 30MB and
        $go and
        4 of ($s*)
}
```

## Lessons Learned

GigaWiper demonstrates the convergence of espionage and destructive capabilities into a single platform, eliminating the need for operators to deploy separate tools for intelligence collection and sabotage. The reuse of code from Crucio ransomware and FlockWiper across different campaigns reinforces that threat actors -- particularly state-sponsored groups -- maintain and evolve malware libraries rather than building from scratch. The use of legitimate infrastructure protocols (RabbitMQ, Redis, MinIO) for C2 channels highlights the growing trend of "living off the land" at the network layer, where defenders must distinguish malicious from legitimate use of common services. The fake ransomware that intentionally discards decryption keys reveals a deception designed to misdirect incident response toward ransom negotiation rather than recognizing a state-sponsored wiper operation.

## Sources

- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/) -- primary technical analysis of GigaWiper architecture, commands, and IOCs
- [The Hacker News](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html) -- additional context on attribution (CyberAv3ngers/IRGC) and BLUERABBIT tracking names
- [Hackread](https://www.hackread.com/2026/07/gigawiper-destructive-backdoor-iran/) -- reporting on GigaWiper campaign and CyberAv3ngers linkage
- [Infosecurity Magazine](https://www.infosecurity-magazine.com/2026/07/gigawiper-wiper-ransomware-backdoor/) -- coverage of GigaWiper multi-function destructive capabilities
- [The Register](https://www.theregister.com/2026/07/09/gigawiper_destructive_backdoor/) -- reporting on GigaWiper as IRGC-linked destructive tool
- [CISA Advisory (December 2023)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a) -- prior CyberAv3ngers activity and Crucio ransomware linkage

---
*Report generated by Actioner*
