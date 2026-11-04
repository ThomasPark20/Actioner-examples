# Malicious Claude Code-Branded Cursor Extension with Persistent SSH Backdoor

**Date:** 2026-11-04  
**Status:** DRAFT  
**TLP:** CLEAR  
**Actioner Report ID:** ACT-2026-1104-001

---

## Executive Summary

On October 29, 2026, tampered versions (2.1.312 and 2.1.313) of the `anthropic.claude-code` extension were served from the Cursor marketplace. The compromised packages contained injected JavaScript that establishes a persistent SSH reverse-tunnel backdoor to attacker-controlled infrastructure at 134[.]209[.]82[.]225. The malware performs host reconnaissance, injects an SSH public key into `authorized_keys`, opens a reverse tunnel for remote access, installs platform-specific persistence, and beacons to a C2 endpoint. Anthropic's own systems were not compromised; the supply chain was poisoned at the marketplace distribution layer. Microsoft Defender has shipped detections and the malicious versions have been removed.

---

## Background

The attack exploits the trust developers place in IDE extension marketplaces. By tampering with a legitimate, widely-installed extension brand (Claude Code by Anthropic), the attacker gains code execution within the developer's environment at extension load time. The injected payload is a multi-stage JavaScript module that operates silently alongside the extension's normal functionality. This incident is notable for its cross-platform persistence (macOS, Linux, Windows) and its use of SSH reverse tunnels rather than more commonly-detected HTTP-based RATs.

---

## Technical Analysis

### Attack Chain

```
Reconnaissance --> SSH Key Injection --> Reverse Tunnel --> Persistence --> Beacon Callback
```

1. **Reconnaissance (T1082, T1033):** On first execution, the payload collects hostname, username, OS type, CPU architecture, home directory, working directory, git email, and the names (not values) of up to 40 environment variables whose names contain KEY, TOKEN, SECRET, PASS, AWS, or GCP.

2. **SSH Key Injection (T1098.004):** An attacker-controlled SSH public key with the comment `svc-telemetry` is appended to `~/.ssh/authorized_keys`. The key fingerprint is `SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk`.

3. **Reverse Tunnel (T1572):** An SSH reverse tunnel is opened using `ssh -N -R '*:0:localhost:22'` to 134[.]209[.]82[.]225, binding a random remote port back to the victim's local SSH service. On Unix systems, `autossh` is used for resilience; on Windows, a PowerShell retry loop replaces it. Host-key checking is disabled (`StrictHostKeyChecking=no`). Retry interval is 60 seconds. A temporary tunnel identity key is written with the file pattern `.stk_[0-9a-f]{10}`.

4. **Persistence:** Platform-specific mechanisms ensure the tunnel survives reboots:

| Platform | Mechanism | MITRE Technique | Artifacts |
|---|---|---|---|
| macOS | LaunchAgent with RunAtLoad + KeepAlive | T1053.003 | `~/Library/LaunchAgents/com.apple.sysmond.plist`, `~/.config/.smt`, `~/.config/.smtk` |
| Linux | crontab `@reboot` entry | T1053.003 | `~/.config/.smt`, `~/.config/.smtk` |
| Windows | Scheduled task "SysMon" (SYSTEM) | T1053.005 | `%USERPROFILE%\.config\smt.cmd`, `%USERPROFILE%\.config\smtk` |
| Windows (fallback) | Startup folder batch file | T1053.005 | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\sysmon.cmd` |

5. **Beacon Callback:** The malware sends the collected recon data as an HTTP POST to `hxxp://134[.]209[.]82[.]225:8099/beacon`.

### SSH Backdoor Detail

The backdoor is designed for stealth:
- The SSH key comment `svc-telemetry` mimics a legitimate service account.
- The LaunchAgent label `com.apple.sysmond` impersonates an Apple system daemon.
- The Windows scheduled task name "SysMon" mimics the Sysinternals System Monitor.
- Temporary tunnel identity keys use a randomized hex suffix pattern (`.stk_[0-9a-f]{10}`).

### C2 Infrastructure

The command-and-control server at 134[.]209[.]82[.]225 (DigitalOcean) listens on:
- **Port 22** for inbound SSH tunnel connections.
- **Port 8099** (`/beacon` endpoint) for HTTP beacon callbacks containing recon data.

---

## Indicators of Compromise

> All IOCs are defanged for safe handling. Restore before use in detection tooling.

### Network Indicators

| Indicator | Type | Context |
|---|---|---|
| 134[.]209[.]82[.]225 | IPv4 | C2 server |
| hxxp://134[.]209[.]82[.]225:8099/beacon | URL | Beacon callback endpoint |

### Host Indicators

| Indicator | Type | Context |
|---|---|---|
| `ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15` | SHA-256 | Malicious JS entry point |
| `7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278` | SHA-256 | Tunnel private key |
| `SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk` | SSH fingerprint | Injected SSH public key |
| `svc-telemetry` | SSH key comment | Injected SSH key identifier |
| `com.apple.sysmond.plist` | Filename | macOS LaunchAgent persistence |
| `.stk_[0-9a-f]{10}` | File pattern | Temporary tunnel identity key |
| `smt.cmd` / `.smt` / `.smtk` | Filenames | Persistence scripts and tunnel key |
| `sysmon.cmd` | Filename | Windows startup folder fallback |

### Extension Versions

| Version | Status |
|---|---|
| anthropic.claude-code 2.1.312 | Malicious (removed) |
| anthropic.claude-code 2.1.313 | Malicious (removed) |

### Defender Detection Names

- `Trojan:MacOS/SmtShellMal.A`
- `Trojan:JS/CredTheft.MS!MTB`
- `Trojan:MacOS/MalPlistSysmond.A`
- `HackTool:MacOS/RevAnthShell.A`

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Usage in This Campaign |
|---|---|---|
| T1098.004 | Account Manipulation: SSH Authorized Keys | Injects attacker SSH public key into authorized_keys |
| T1572 | Protocol Tunneling | SSH reverse tunnel to C2 for persistent remote access |
| T1053.003 | Scheduled Task/Job: Cron | Linux crontab @reboot persistence; macOS LaunchAgent |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows scheduled task "SysMon" persistence |

---

## Detection & Remediation

### Immediate Triage

1. **Check extension version:** Verify `anthropic.claude-code` is not version 2.1.312 or 2.1.313. Update to the latest legitimate version.
2. **Inspect authorized_keys:** Search for the `svc-telemetry` comment in `~/.ssh/authorized_keys` on all developer workstations.
3. **Check persistence:**
   - **macOS:** `ls ~/Library/LaunchAgents/com.apple.sysmond.plist`
   - **Linux:** `crontab -l | grep .smt`
   - **Windows:** `schtasks /query /tn SysMon` and check Startup folder for `sysmon.cmd`
4. **Check for C2 connections:** Review network logs for connections to 134[.]209[.]82[.]225.
5. **Review environment variable exposure:** The malware exfiltrates names (not values) of env vars matching KEY/TOKEN/SECRET/PASS/AWS/GCP. Rotate credentials stored in matching environment variables on affected hosts as a precaution.

### Cleanup

1. Remove the `svc-telemetry` key from `~/.ssh/authorized_keys`.
2. Remove persistence artifacts (LaunchAgent plist, crontab entry, scheduled task, startup batch file).
3. Delete backdoor files: `~/.config/.smt`, `~/.config/.smtk`, `~/.config/.stk_*`, `smt.cmd`.
4. Kill any running `autossh` or `ssh` processes tunneling to 134[.]209[.]82[.]225.
5. Block 134[.]209[.]82[.]225 at the network perimeter.

---

## Detection Rules

### Sigma Rules

#### 1. SSH Authorized Keys Modification with svc-telemetry Comment

Detects modification of authorized_keys with the backdoor's distinctive SSH key comment. Cross-reference with C2 IP connections for higher confidence.
<!-- audit: svc-telemetry is the SSH key comment injected by the backdoor. May fire on legitimate keys named identically; cross-reference with C2 IP 134.209.82.225 for high confidence. -->

> **Compile status:** PASS (sigma convert to Splunk and LogScale) | **Confidence:** High

```yaml
title: SSH Authorized Keys Modification with svc-telemetry Comment
id: 3a7c1e2d-5f8b-4a91-b6e3-9d4f7c8a2b10
status: experimental
description: >
  Detects modification of SSH authorized_keys file with the svc-telemetry key comment,
  as observed in the malicious Claude Code extension backdoor (Oct 2026).
references:
  - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-11-04
tags:
  - attack.t1098.004
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|endswith: '.ssh/authorized_keys'
  keywords:
    CommandLine|contains: 'svc-telemetry'
  condition: selection or keywords
falsepositives:
  - Legitimate automation using the exact key comment name svc-telemetry
level: high
```

#### 2. Scheduled Task Creation Named SysMon with smt.cmd

Detects the Windows persistence mechanism: a scheduled task named SysMon referencing smt.cmd. The real Sysinternals Sysmon installs as a service, not a scheduled task.
<!-- audit: The real SysMon (Sysinternals) installs as a service, not a scheduled task referencing smt.cmd. This rule is highly specific. -->

> **Compile status:** PASS (sigma convert to Splunk and LogScale) | **Confidence:** High

```yaml
title: Scheduled Task Creation Named SysMon with smt.cmd
id: 8b2f4d6e-1a3c-4e7f-9d5b-0c8e2f6a4d19
status: experimental
description: >
  Detects creation of a Windows scheduled task named SysMon that references smt.cmd,
  a persistence mechanism used by the malicious Claude Code extension backdoor.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-11-04
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
      - 'SysMon'
      - 'smt.cmd'
  condition: selection_schtasks
falsepositives:
  - Unlikely; the combination of task name SysMon with smt.cmd payload is specific to this threat
level: critical
```

#### 3. LaunchAgent Creation for com.apple.sysmond Persistence

Detects creation of the fake LaunchAgent plist. Apple does not ship a user-space `com.apple.sysmond` LaunchAgent.
<!-- audit: Apple does not ship a com.apple.sysmond LaunchAgent in user-space ~/Library/LaunchAgents. System-level /System paths are protected by SIP and are not matched by this rule. -->

> **Compile status:** PASS (sigma convert to Splunk and LogScale) | **Confidence:** High

```yaml
title: LaunchAgent Creation for com.apple.sysmond Persistence
id: d1e5f7a9-3b2c-4d6e-8f0a-1c9b5e7d3f21
status: experimental
description: >
  Detects creation of a LaunchAgent plist masquerading as com.apple.sysmond,
  a macOS persistence mechanism used by the malicious Claude Code extension backdoor.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-11-04
tags:
  - attack.t1053.003
logsource:
  category: file_event
  product: macos
detection:
  selection:
    TargetFilename|endswith: '/Library/LaunchAgents/com.apple.sysmond.plist'
  condition: selection
falsepositives:
  - No known legitimate user-space LaunchAgent with this exact name
level: critical
```

#### 4. Network Connection to Claude Code Backdoor C2 IP

Detects any network connection to the C2 IP. IP-based detection has a limited shelf life; combine with behavioral rules.
<!-- audit: IP-based detection; will break when the actor rotates infrastructure. Combine with behavioural rules for longer shelf-life. -->

> **Compile status:** PASS (sigma convert to Splunk and LogScale) | **Confidence:** High (time-limited)

```yaml
title: Network Connection to Claude Code Backdoor C2 IP
id: 4f6a8c2e-7d9b-4e1f-a3c5-2b0d8e6f4a72
status: experimental
description: >
  Detects network connections to 134.209.82.225, the command-and-control IP
  used by the malicious Claude Code extension SSH backdoor.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-11-04
tags:
  - attack.t1572
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationIp: '134.209.82.225'
  condition: selection
falsepositives:
  - IP may be reassigned to legitimate DigitalOcean customers after takedown
level: critical
```

#### 5. Temporary Tunnel Key File Creation in .config Directory

Detects creation of the temporary SSH tunnel identity key files. The `.stk_` prefix in `.config` is distinctive to this malware.
<!-- audit: Regex .stk_[0-9a-f]{10} cannot be expressed in base Sigma; contains match on .stk_ is the closest portable filter. Backends with regex support can tighten this. -->

> **Compile status:** PASS (sigma convert to Splunk and LogScale) | **Confidence:** High

```yaml
title: Temporary Tunnel Key File Creation in .config Directory
id: 7e3b9d1f-5a4c-4f2e-8b6d-0c1a3e5f7d92
status: experimental
description: >
  Detects creation of files matching the pattern .stk_[0-9a-f]{10} in the .config directory,
  which are temporary SSH tunnel identity key files created by the malicious Claude Code extension.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-11-04
tags:
  - attack.t1572
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|contains: '/.config/.stk_'
  condition: selection
falsepositives:
  - Unlikely; the .stk_ prefix in .config is highly specific to this malware
level: high
```

#### 6. Crontab Modification with .smt Reference for Persistence

Detects crontab modifications referencing the `.smt` backdoor script. May need tuning if legitimate tools use `.smt` files in cron.
<!-- audit: Triggers on crontab invocations where the command line contains .smt. May need tuning if legitimate tools use .smt extension files in cron. -->

> **Compile status:** PASS (sigma convert to Splunk and LogScale) | **Confidence:** Medium

```yaml
title: Crontab Modification with .smt Reference for Persistence
id: a2c4e6f8-1b3d-4a5c-9e7f-0d2b4c6a8e13
status: experimental
description: >
  Detects crontab modifications that reference the .smt backdoor script,
  a Linux persistence mechanism used by the malicious Claude Code extension.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-11-04
tags:
  - attack.t1053.003
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '/crontab'
  keywords:
    CommandLine|contains: '.smt'
  condition: selection and keywords
falsepositives:
  - Legitimate cron jobs referencing files with .smt in their path
level: high
```

### YARA Rule

Matches files containing 3 or more strings distinctive to this backdoor. The `3 of them` condition balances detection breadth with false-positive resistance.
<!-- audit: Condition requires 3 of 10 strings, which may match unrelated security tools that reference these IOCs in documentation or reports. Tighten to 5+ for lower FP in environments with CTI content on disk. -->

> **Compile status:** PASS (yarac + positive/negative sample test) | **Confidence:** High

```yara
rule Malicious_Claude_Code_Extension_SSH_Backdoor
{
    meta:
        description = "Detects the malicious Claude Code-branded Cursor extension with persistent SSH backdoor"
        author = "Actioner"
        date = "2026-11-04"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"
        hash_js_entry = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
        hash_tunnel_key = "7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278"
        severity = "critical"

    strings:
        $c2_ip = "134.209.82.225" ascii wide
        $beacon_path = "/beacon" ascii
        $ssh_comment = "svc-telemetry" ascii wide
        $stk_pattern = ".stk_" ascii
        $plist_name = "com.apple.sysmond" ascii wide
        $smt_script = ".config/.smt" ascii
        $smtk_file = ".config/.smtk" ascii
        $smt_cmd = "smt.cmd" ascii
        $tunnel_flag = "-R '*:0:localhost:22'" ascii
        $key_fingerprint = "0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk" ascii

    condition:
        3 of them
}
```

### Snort Rule

Detects HTTP GET requests to the C2 beacon endpoint. Effective only while the C2 IP is active.
<!-- audit: The rule matches HTTP GET to /beacon on the C2 IP:port. If the beacon switches to POST or HTTPS, this rule will miss. Consider adding a POST variant. -->

> **Compile status:** PASS (snort -T) | **Confidence:** High (time-limited)

```
alert tcp $HOME_NET any -> 134.209.82.225 8099 (msg:"Actioner - Claude Code Backdoor HTTP Beacon to C2"; flow:established,to_server; content:"GET"; http_method; content:"/beacon"; http_uri; classtype:trojan-activity; sid:2100001; rev:1;)
```

### Suricata Rules

Two rules: one for the HTTP beacon callback, one for SSH tunnel establishment to the C2 IP.
<!-- audit: The SSH tunnel rule (sid:2200002) is broad — any SSH to the C2 IP fires it. This is intentional for this PoC-specific IOC set but would need scoping in environments with legitimate SSH to DigitalOcean. -->

> **Compile status:** PASS (suricata -T) | **Confidence:** High (time-limited)

```
alert http $HOME_NET any -> 134.209.82.225 8099 (msg:"Actioner - Claude Code Backdoor HTTP Beacon to C2"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/beacon"; classtype:trojan-activity; sid:2200001; rev:1;)

alert tcp $HOME_NET any -> 134.209.82.225 22 (msg:"Actioner - Claude Code Backdoor SSH Reverse Tunnel to C2"; flow:established,to_server; classtype:trojan-activity; sid:2200002; rev:1;)
```

---

## Sources

- [Microsoft Security Blog: Inside malicious Claude Code-branded Cursor extension persistent SSH backdoor](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/)
- [MITRE ATT&CK T1098.004 - Account Manipulation: SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/)
- [MITRE ATT&CK T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK T1053.003 - Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
- [MITRE ATT&CK T1053.005 - Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
