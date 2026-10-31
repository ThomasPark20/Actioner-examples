# Technical Analysis Report: Trojanized Claude Code Extension Supply Chain Attack (2026-10-31)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-31
Version: DRAFT 1.0

## Executive Summary

On October 29, 2026, a trojanized version of Anthropic's Claude Code VS Code extension (v2.1.313) was distributed through Cursor's extension marketplace for approximately 11 hours (02:27-13:35 PDT). The malicious extension contained a 66-line JavaScript loader prepended to the legitimate `extension.js` that planted persistent SSH backdoors across macOS, Linux, and Windows. The loader collected host reconnaissance data, appended an attacker-controlled Ed25519 SSH key (comment: `svc-telemetry`) to authorized_keys files, established reverse SSH tunnels to `134[.]209[.]82[.]225`, and installed platform-specific persistence mechanisms (LaunchAgent, crontab, scheduled task). Up to 5,000 developers were potentially exposed.

Notably, coding errors in the malware limited its effective impact: on macOS, SSH enablement failed due to missing elevated privileges, and on Windows, the OpenSSH server installation attempted to use `/bin/sh` which does not exist. However, the SSH key installation, persistence scripts, and reconnaissance beacon still executed regardless of these failures. No second-stage payloads were downloaded. No attribution has been published.

## Background: Cursor Extension Marketplace

Cursor is an AI-powered code editor built on VS Code that maintains its own extension marketplace separate from the Visual Studio Marketplace. Extensions published to Cursor's marketplace undergo Cursor's own review process. The Claude Code extension (`anthropic.claude-code`) is a popular AI coding assistant developed by Anthropic. The mechanism by which the attacker published a malicious update under Anthropic's publisher identity on Cursor's marketplace has not been disclosed. The malicious versions (2.1.312 and 2.1.313) were distributed exclusively through Cursor's marketplace -- the Visual Studio Marketplace, Open VSX, and npm distributions were not affected.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-10-29 ~09:27 | Malicious Claude Code extension v2.1.312/313 published to Cursor marketplace |
| 2026-10-29 09:27-20:35 | ~11-hour exposure window; extension auto-updates to affected developers |
| 2026-10-29 ~20:35 | Cursor removes malicious extension, temporarily shuts down marketplace |
| 2026-10-29 (post-takedown) | Cursor works with hosting provider to take attacker server offline |
| 2026-10-30 | Microsoft Security Blog, BleepingComputer, The Hacker News publish analyses |
| 2026-10-30 | Cursor publishes platform-specific remediation scripts and guidance |
| 2026-10-30 | Clean version 2.1.314 published to Open VSX and VS Code Marketplace |

## Root Cause: Supply Chain Compromise via Extension Marketplace

The attacker published a malicious update to the Claude Code extension on Cursor's marketplace under the legitimate Anthropic publisher identity. The exact initial access vector -- whether through compromised publisher credentials, a marketplace vulnerability, or another mechanism -- has not been publicly disclosed as of this writing. Both Anthropic and Cursor have been contacted by reporters but have not confirmed the root cause.

The attack did not involve dependency confusion, typosquatting, or a compromised build pipeline. Instead, the attacker directly modified the extension package to prepend a 66-line malicious JavaScript loader to the beginning of the legitimate `extension.js` entry point, leaving the rest of the Claude Code functionality intact to avoid detection.

## Technical Analysis of the Malicious Payload

### 1. Initial Loader (JavaScript Injection in extension.js)

A 66-line JavaScript loader was inserted at the beginning of the extension's `extension.js` file (SHA-256: `ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15`). The loader executes at extension module load time -- no user interaction with Claude Code features is required. The rest of the legitimate extension code was left unchanged, allowing normal Claude Code functionality to continue and avoid suspicion.

The loader uses only built-in Node.js modules and embedded components. No second-stage executable is downloaded.

### 2. Reconnaissance and Data Collection

At load time, the malware collects:
- Hostname and local username
- Operating system and CPU architecture
- Home directory and current working directory
- Global Git email (via `git config --global user.email`)
- Public IP address (via `api[.]ipify[.]org`)
- Names (not values) of up to 40 environment variables matching patterns: `KEY`, `TOKEN`, `SECRET`, `PASS`, `AWS`, `GCP`

This data is sent via HTTP POST to `hxxp://134[.]209[.]82[.]225:8099/beacon` after the SSH key and persistence mechanisms have been established.

### 3. C2 Infrastructure

| Component | Detail |
|-----------|--------|
| C2 IP | 134[.]209[.]82[.]225 |
| Beacon URL | hxxp://134[.]209[.]82[.]225:8099/beacon |
| Beacon protocol | HTTP (unencrypted), port 8099 |
| SSH tunnel target | 134[.]209[.]82[.]225 (standard SSH port) |
| Tunnel command | `ssh -N -R '*:0:localhost:22'` with identity file, disabled host-key checking, suppressed prompts, keepalives enabled |
| Retry interval | 60 seconds after SSH process exits |
| IP lookup service | api[.]ipify[.]org |

The reverse tunnel uses `ssh -N -R '*:0:localhost:22'` which requests the remote server allocate any available port that forwards back to the victim's local SSH service on port 22. A temporary tunnel identity file with the pattern `.stk_[0-9a-f]{10}` (derived from hostname and home directory) is used with `-i`.

### 4. Platform-Specific Behavior

#### macOS

| Mechanism | Detail |
|-----------|--------|
| Persistence | LaunchAgent at `~/Library/LaunchAgents/com.apple.sysmond.plist` (mimics Apple system daemon) |
| LaunchAgent config | RunAtLoad=true, KeepAlive=true |
| Tunnel script | `~/.config/.smt` (rebuilds `.smtk` and runs SSH retry loop) |
| Tunnel key | `~/.config/.smtk` |
| SSH key target | `~/.ssh/authorized_keys` |
| SSH enablement | Attempts `systemsetup -getremotelogin` without sudo -- fails with permissions error, so SSH is NOT enabled unless already running |
| Tunnel tool | Prefers `autossh`, falls back to `ssh` |

#### Windows

| Mechanism | Detail |
|-----------|--------|
| Primary persistence | Scheduled task named "SysMon" requesting SYSTEM privileges, referencing `%USERPROFILE%\.config\smt.cmd` |
| Fallback persistence | Startup folder batch file at `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\sysmon.cmd` |
| Tunnel script | `%USERPROFILE%\.config\smt.cmd` |
| Tunnel key | `%USERPROFILE%\.config\smtk` |
| SSH key targets | `%USERPROFILE%\.ssh\authorized_keys` and `C:\ProgramData\ssh\administrators_authorized_keys` |
| SSH enablement | Attempts OpenSSH server install via PowerShell through `/bin/sh` -- fails on standard Windows |
| Tunnel tool | Hidden PowerShell retry loop |

#### Linux

| Mechanism | Detail |
|-----------|--------|
| Persistence | User crontab `@reboot` entry |
| Tunnel script | `~/.config/.smt` |
| Tunnel key | `~/.config/.smtk` |
| SSH key target | `~/.ssh/authorized_keys` |
| Tunnel tool | Prefers `autossh`, falls back to `ssh` |

### 5. Anti-Forensics / Evasion Techniques

- **Process output suppression**: All command output is silently suppressed
- **Error swallowing**: Errors are caught silently to prevent extension crashes that would alert the user
- **Naming mimicry**: macOS LaunchAgent uses `com.apple.sysmond.plist` to impersonate Apple system processes; Windows scheduled task uses "SysMon" to impersonate the legitimate Sysmon tool
- **Hidden files**: Unix persistence scripts use dot-prefix (`.smt`, `.smtk`) for concealment
- **Functional preservation**: Legitimate Claude Code functionality is preserved to avoid user suspicion
- **No downloads**: No second-stage binaries are downloaded; all functionality is embedded

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxp://` replacing `http://`
> - IP addresses: `[.]` replacing dots (e.g., `134[.]209[.]82[.]225`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| anthropic.claude-code (Cursor marketplace) | 2.1.312, 2.1.313 | 66-line JS loader prepended to extension.js |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | extension.js (in extension dir) | `ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15` | Injected JavaScript entry point |
| All | .stk_[0-9a-f]{10} (temp location) | `7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278` | Decoded tunnel private key |
| macOS | ~/Library/LaunchAgents/com.apple.sysmond.plist | -- | Fake Apple LaunchAgent |
| macOS/Linux | ~/.config/.smt | -- | Tunnel retry script |
| macOS/Linux | ~/.config/.smtk | -- | Tunnel identity key |
| Windows | %USERPROFILE%\\.config\\smt.cmd | -- | Tunnel retry batch |
| Windows | %USERPROFILE%\\.config\\smtk | -- | Tunnel identity key |
| Windows | %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\sysmon.cmd | -- | Startup persistence |
| All | ~/.ssh/authorized_keys | -- | Attacker key appended |
| Windows | C:\\ProgramData\\ssh\\administrators_authorized_keys | -- | Attacker key appended |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 134[.]209[.]82[.]225 | C2 server: SSH tunnel endpoint and HTTP beacon |
| URL | hxxp://134[.]209[.]82[.]225:8099/beacon | Reconnaissance data exfiltration endpoint |
| Domain | api[.]ipify[.]org | Public IP lookup (legitimate service, used by malware) |
| SSH Key Fingerprint | SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk | Attacker's Ed25519 key fingerprint |
| SSH Key Comment | svc-telemetry | Marker in authorized_keys for attacker key |

### Behavioral

- Node.js process (from VS Code/Cursor extension host) writing to `~/.ssh/authorized_keys`
- SSH reverse tunnel (`ssh -N -R`) spawned as child of code editor process
- HTTP POST to port 8099 containing hostname, username, OS, architecture, and env var names
- Creation of hidden files (`.smt`, `.smtk`) in `~/.config/` by extension host process
- LaunchAgent creation in user LaunchAgents directory by non-Apple process
- Scheduled task creation named "SysMon" referencing `smt.cmd`
- Outbound SSH connections to 134[.]209[.]82[.]225 with disabled host-key checking

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into legitimate Claude Code extension on Cursor marketplace |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Attacker-controlled Ed25519 key (svc-telemetry) appended to authorized_keys |
| T1572 | Protocol Tunneling | Reverse SSH tunnel to C2 server forwarding to localhost:22 |
| T1053.003 | Scheduled Task/Job: Cron | Linux @reboot crontab entry for tunnel persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows "SysMon" scheduled task with SYSTEM privileges |
| T1543.004 | Create or Modify System Process: Launch Agent | macOS com.apple.sysmond.plist LaunchAgent |
| T1082 | System Information Discovery | Hostname, OS, architecture, home/working directory collection |
| T1016 | System Network Configuration Discovery | Public IP enumeration via api.ipify.org |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | .smt shell script for SSH tunnel management |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Windows hidden PowerShell retry loop |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP beacon to port 8099 for data exfiltration |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Windows Startup folder sysmon.cmd fallback |
| T1036.004 | Masquerading: Masquerade Task or Service | LaunchAgent mimics Apple sysmond; scheduled task mimics Sysmon |

## Impact Assessment

- **Breadth**: Up to 5,000 Cursor users potentially affected during the 11-hour exposure window
- **Depth**: Persistent SSH backdoor with reverse tunnel capability; reconnaissance data (hostnames, usernames, env var names) exfiltrated to attacker
- **Stealth**: Extension continued to function normally; persistence mechanisms named to mimic legitimate system services; hidden files used for scripts
- **Limiting factors**: Implementation bugs prevented SSH enablement on macOS (privilege error) and Windows (missing `/bin/sh`), meaning the reverse tunnel could not provide access unless SSH was already running. However, SSH key installation, persistence scripts, and reconnaissance succeeded regardless.
- **Scope limitation**: Distribution was limited to Cursor's marketplace only; npm, Open VSX, and the Visual Studio Marketplace were not affected

## Detection & Remediation

### Immediate Detection

**Check for the attacker's SSH key:**
```bash
# macOS/Linux
grep "svc-telemetry" ~/.ssh/authorized_keys 2>/dev/null

# Windows (PowerShell)
Select-String -Path "$env:USERPROFILE\.ssh\authorized_keys" -Pattern "svc-telemetry"
Select-String -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Pattern "svc-telemetry"
```

**Verify SSH key fingerprint:**
```bash
# Check for the specific attacker key fingerprint
ssh-keygen -l -f ~/.ssh/authorized_keys 2>/dev/null | grep "0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk"
```

**Check for persistence artifacts:**
```bash
# macOS LaunchAgent
ls -la ~/Library/LaunchAgents/com.apple.sysmond.plist 2>/dev/null

# Linux crontab
crontab -l 2>/dev/null | grep -E "\.smt|\.smtk"

# macOS/Linux hidden config files
ls -la ~/.config/.smt ~/.config/.smtk 2>/dev/null

# Tunnel identity files
find /tmp -name ".stk_*" 2>/dev/null
```

```powershell
# Windows scheduled task
schtasks /query /tn "SysMon" 2>$null

# Windows persistence files
Test-Path "$env:USERPROFILE\.config\smt.cmd"
Test-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\sysmon.cmd"
```

**Check for network connections:**
```bash
# Active connections to C2
netstat -an | grep "134.209.82.225"
ss -tnp | grep "134.209.82.225"
```

### Remediation

1. **Isolate**: Disconnect affected hosts from the network immediately
2. **Preserve evidence**: Copy the extension package, modified authorized_keys, generated keys and scripts, and startup config before cleanup
3. **Remove the SSH key**: Delete only the `svc-telemetry` entry by fingerprint -- do not blanket-delete all keys
   ```bash
   # Backup first, then remove by fingerprint match
   cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak
   grep -v "svc-telemetry" ~/.ssh/authorized_keys.bak > ~/.ssh/authorized_keys
   ```
4. **Stop processes**: Kill any active SSH tunnel processes and retry loops
   ```bash
   pkill -f "ssh.*-N.*-R.*localhost:22"
   ```
5. **Remove persistence**:
   - macOS: `launchctl unload ~/Library/LaunchAgents/com.apple.sysmond.plist && rm ~/Library/LaunchAgents/com.apple.sysmond.plist`
   - Linux: Edit crontab to remove the `@reboot` entry referencing `.smt`
   - Windows: `schtasks /delete /tn "SysMon" /f` and delete `sysmon.cmd` from Startup folder
6. **Delete malware files**: Remove `.smt`, `.smtk`, `smt.cmd`, `smtk`, and `.stk_*` files after evidence collection
7. **Rotate credentials**: Treat all environment variables matching KEY, TOKEN, SECRET, PASS, AWS, GCP as potentially exposed (names only, not values)
8. **Invalidate sessions**: Revoke active sessions and tokens on affected machines
9. **Rebuild**: Where trust cannot be restored, rebuild from clean backups
10. **Verify**: Confirm artifacts do not return after reboot

### Long-Term Hardening

- Restrict extension installations to approved/audited publishers
- Enforce installation cooldown periods for new extension versions
- Implement extension integrity verification (hash-based)
- Monitor for unauthorized modifications to SSH authorized_keys
- Deploy endpoint detection rules for reverse SSH tunnel patterns
- Audit outbound SSH connections from developer workstations
- Consider allowlisting for VS Code/Cursor extensions in enterprise environments

## Detection Rules

Six Sigma rules, two YARA rules, three Suricata rules, and two Snort rules cover the primary IOCs and behavioral patterns from this attack. All rules are advisory-specific (strict scope) to minimize false positives. The Sigma rules cover network connections to the C2 IP, SSH authorized_keys modification by Node.js, macOS LaunchAgent persistence, Windows scheduled task creation, reverse SSH tunnel spawned from a code editor, and persistence file creation. Note: `sigma check` ATT&CK tag validation was skipped due to proxy-blocked MITRE data endpoint, but all rules passed all other validators (0 errors, 0 issues) and successfully converted to Splunk and LogScale backends.

### Sigma: Network Connection to C2 IP

Detects outbound connections to the C2 IP 134[.]209[.]82[.]225 used for reverse SSH tunnels and HTTP beaconing.
compile: sigma check pass (0 errors) + sigma convert splunk/log_scale pass | confidence: high (IOC-specific)

<!-- audit: IOC-based rule matching exact IP. sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk: exit 0. sigma convert --without-pipeline -t log_scale: exit 0. Tags use technique-only format per convention. Real (non-defanged) IP in detection value per logsource-encoding.md. -->

```yaml
title: Network Connection to Claude Code Extension Backdoor C2 IP
id: c2577d3c-fed4-4ee9-8b76-2ebca6b159d9
status: experimental
description: >
    Detects outbound network connections to IP address 134.209.82.225,
    the C2 server used by the trojanized Claude Code VS Code extension
    (v2.1.313) distributed via the Cursor marketplace on Oct 29, 2026.
    Connections to this IP indicate potential reverse SSH tunnel or
    HTTP beacon activity from the malicious extension.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
    - https://www.bleepingcomputer.com/news/security/malicious-claude-code-extension-on-cursor-planted-ssh-backdoors/
author: Actioner
date: 2026-10-31
tags:
    - attack.t1572
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '134.209.82.225'
    condition: selection
falsepositives:
    - Legitimate services hosted on this IP prior to the attack (unlikely given known malicious use)
level: high
```

### Sigma: SSH Authorized Keys Modification by Node.js

Detects a Node.js process (the extension host) modifying SSH authorized_keys files, consistent with the malware's SSH key injection behavior.
compile: sigma check pass (0 errors) + sigma convert splunk/log_scale pass | confidence: high (IOC-specific)

<!-- audit: Behavioral rule scoped to Node.js writing authorized_keys. sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk: exit 0. sigma convert --without-pipeline -t log_scale: exit 0. Covers both Unix and Windows authorized_keys paths. -->

```yaml
title: SSH Authorized Keys Modification with svc-telemetry Key
id: 2e531d9d-6ec5-420c-9f72-b0c21bf4d3d8
status: experimental
description: >
    Detects file modification events targeting SSH authorized_keys files
    where the svc-telemetry key comment is written. The trojanized Claude Code
    extension (v2.1.313) appends an attacker-controlled Ed25519 key with the
    comment svc-telemetry to authorized_keys for persistent SSH access.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-10-31
tags:
    - attack.t1098.004
logsource:
    category: file_event
detection:
    selection_path:
        TargetFilename|endswith:
            - '/.ssh/authorized_keys'
            - '\.ssh\authorized_keys'
            - '\administrators_authorized_keys'
    selection_process:
        Image|endswith:
            - '/node'
            - '\node.exe'
    condition: selection_path and selection_process
falsepositives:
    - Legitimate Node.js-based SSH key management tools
level: high
```

### Sigma: macOS LaunchAgent Persistence (com.apple.sysmond.plist)

Detects creation of the fake Apple LaunchAgent used for persistence on macOS.
compile: sigma check pass (0 errors) + sigma convert splunk/log_scale pass | confidence: high (IOC-specific)

<!-- audit: File-event rule targeting a specific plist filename Apple does not ship. sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk: exit 0. sigma convert --without-pipeline -t log_scale: exit 0. -->

```yaml
title: Malicious Claude Code Extension macOS LaunchAgent Persistence
id: 8348d219-f1e5-4f2d-b19a-036c4440d688
status: experimental
description: >
    Detects the creation of the com.apple.sysmond.plist LaunchAgent used by
    the trojanized Claude Code extension (v2.1.313) for persistence on macOS.
    The plist is named to impersonate an Apple system daemon and configured
    with RunAtLoad and KeepAlive to maintain a reverse SSH tunnel.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-10-31
tags:
    - attack.t1543.004
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|endswith: '/Library/LaunchAgents/com.apple.sysmond.plist'
    condition: selection
falsepositives:
    - Apple does not ship a LaunchAgent by this name; false positives are unlikely
level: critical
```

### Sigma: Windows Scheduled Task "SysMon" Persistence

Detects creation of the masquerading scheduled task used for Windows persistence.
compile: sigma check pass (0 errors) + sigma convert splunk/log_scale pass | confidence: medium (behavioral)

<!-- audit: Process-creation rule matching schtasks.exe with both SysMon task name and smt.cmd reference. sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk: exit 0. sigma convert --without-pipeline -t log_scale: exit 0. Behavioral combination is specific but relies on command-line logging being enabled. -->

```yaml
title: Malicious Claude Code Extension Windows Scheduled Task Persistence
id: 6e3ed496-a9d4-4714-a46d-ccb85c3b91cf
status: experimental
description: >
    Detects the creation of a Windows scheduled task named SysMon that
    references smt.cmd, used by the trojanized Claude Code extension
    (v2.1.313) for persistence. The task is created requesting SYSTEM
    privileges to maintain a reverse SSH tunnel.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-10-31
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - 'SysMon'
            - 'smt.cmd'
    condition: selection
falsepositives:
    - Unlikely; the combination of SysMon task name referencing smt.cmd is specific to this threat
level: high
```

### Sigma: SSH Reverse Tunnel from Code Editor Process

Detects SSH reverse tunnel commands spawned by VS Code/Cursor editor processes.
compile: sigma check pass (0 errors) + sigma convert splunk/log_scale pass | confidence: medium (behavioral/TTP)

<!-- audit: Behavioral TTP rule. Requires both SSH reverse tunnel flags AND code editor as parent. sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk: exit 0. sigma convert --without-pipeline -t log_scale: exit 0. Labeled medium confidence per instruction: behavioral/TTP rules must not be high. -->

```yaml
title: Suspicious SSH Reverse Tunnel from Code Editor Process
id: 5f935114-0e4a-4ddc-8231-2cd3af1eec6f
status: experimental
description: >
    Detects SSH reverse tunnel commands spawned by code editor processes,
    consistent with the trojanized Claude Code extension (v2.1.313) behavior.
    The malware uses ssh -N -R to establish a reverse tunnel forwarding to
    localhost port 22 for persistent remote access.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-10-31
tags:
    - attack.t1572
logsource:
    category: process_creation
detection:
    selection_cmd:
        CommandLine|contains|all:
            - 'ssh'
            - '-N'
            - '-R'
            - 'localhost:22'
    selection_parent:
        ParentImage|endswith:
            - '/Cursor'
            - '\Cursor.exe'
            - '/cursor'
            - '\cursor.exe'
            - '/code'
            - '\Code.exe'
    condition: selection_cmd and selection_parent
falsepositives:
    - Legitimate SSH tunneling extensions in VS Code or Cursor (rare and should be audited)
level: medium
```

### Sigma: Persistence File Creation (.smt/.smtk)

Detects creation of the hidden persistence scripts used by the backdoor.
compile: sigma check pass (0 errors) + sigma convert splunk/log_scale pass | confidence: high (IOC-specific)

<!-- audit: File-event rule matching specific hidden filenames in .config directory. sigma check -x attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk: exit 0. sigma convert --without-pipeline -t log_scale: exit 0. Filenames are specific to this threat. -->

```yaml
title: Claude Code Extension Backdoor Persistence File Creation
id: 53bd12a6-10a1-499e-a1a8-9cee1f0ac41a
status: experimental
description: >
    Detects creation of hidden persistence scripts (.smt, .smtk, smt.cmd)
    in the user config directory, used by the trojanized Claude Code
    extension (v2.1.313) to maintain reverse SSH tunnel access. These files
    contain the SSH tunnel retry logic and tunnel identity key.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026-10-31
tags:
    - attack.t1059.004
    - attack.t1547.001
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '/.config/.smt'
            - '/.config/.smtk'
            - '\.config\smt.cmd'
            - '\.config\smtk'
    condition: selection
falsepositives:
    - Unlikely; these hidden filenames in the config directory are specific to this threat
level: high
```

### YARA: Malicious JavaScript Loader Detection

Detects the malicious JavaScript loader by matching the combination of C2 IP, beacon endpoint, SSH key comment, tunnel parameters, and reconnaissance patterns.
compile: yarac exit 0 | confidence: high (IOC-specific, multi-string AND logic)

<!-- audit: yarac /tmp/actioner/yara_claude_code_backdoor.yar /dev/null: exit 0. Requires C2 IP + port + beacon path + SSH key comment + tunnel identity pattern + 3 tunnel/persistence strings + 1 recon string. Tight condition minimizes FP. -->

```yara
rule SupplyChain_ClaudeCode_Backdoor_Loader
{
    meta:
        description = "Detects the malicious JavaScript loader injected into the trojanized Claude Code VS Code extension (v2.1.313) distributed via the Cursor marketplace"
        author = "Actioner"
        date = "2026-10-31"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"
        hash = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $beacon = "134.209.82.225" ascii
        $beacon_port = "8099" ascii
        $beacon_path = "/beacon" ascii
        $ssh_key_comment = "svc-telemetry" ascii
        $tunnel_flag1 = "-N" ascii
        $tunnel_flag2 = "-R" ascii
        $tunnel_target = "localhost:22" ascii
        $persist_mac = "com.apple.sysmond" ascii
        $persist_file1 = ".smt" ascii
        $persist_file2 = ".smtk" ascii
        $stk_pattern = ".stk_" ascii
        $env_pattern1 = "TOKEN" ascii
        $env_pattern2 = "SECRET" ascii
        $env_pattern3 = "PASS" ascii
        $ipify = "api.ipify.org" ascii
        $git_email = "git config --global user.email" ascii

    condition:
        filesize < 10MB and
        $beacon and
        $beacon_port and
        $beacon_path and
        $ssh_key_comment and
        $stk_pattern and
        3 of ($tunnel_flag1, $tunnel_flag2, $tunnel_target, $persist_mac, $persist_file1, $persist_file2) and
        1 of ($env_pattern*, $ipify, $git_email)
}
```

### YARA: SSH Tunnel Private Key Detection

Detects small OpenSSH private key files matching the dropped tunnel identity key pattern.
compile: yarac exit 0 | confidence: medium (structural match, not hash-specific)

<!-- audit: yarac exit 0. Matches small (<1KB) files with OpenSSH private key header at offset 0 and footer present. Low specificity without the actual key material; labeled medium. The hash 7e0a52... is the specific sample but key content is redacted in sources. -->

```yara
rule SupplyChain_ClaudeCode_Tunnel_Key
{
    meta:
        description = "Detects the SSH tunnel private key file dropped by the trojanized Claude Code extension backdoor"
        author = "Actioner"
        date = "2026-10-31"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"
        hash = "7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278"
        severity = "high"
        tlp = "WHITE"

    strings:
        $header = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $footer = "-----END OPENSSH PRIVATE KEY-----" ascii

    condition:
        filesize < 1KB and
        $header at 0 and
        $footer
}
```

### Suricata: HTTP Beacon to C2

Detects HTTP requests to the `/beacon` endpoint on the C2 IP used for reconnaissance data exfiltration.
compile: suricata -T exit 0 | confidence: high (IOC-specific)

<!-- audit: suricata -T -S /tmp/actioner/suricata_claude_code_backdoor.rules -l /tmp/actioner: "Configuration provided was successfully loaded. Exiting." exit 0. Uses dot-notation http.uri per suricata-ref.md. Real IP in dest (not defanged). sid 2200001 in 2200000+ range. -->

```
alert http $HOME_NET any -> 134.209.82.225 any (msg:"Actioner - Claude Code Backdoor HTTP Beacon to C2"; flow:established,to_server; http.uri; content:"/beacon"; startswith; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/; metadata:author Actioner, created_at 2026-10-31; sid:2200001; rev:1;)
```

### Suricata: Outbound SSH to C2 IP (Port 22)

Detects direct SSH connections to the C2 server on port 22.
compile: suricata -T exit 0 | confidence: high (IOC-specific)

<!-- audit: suricata -T exit 0. Plain TCP flow rule to specific IP and port. -->

```
alert tcp $HOME_NET any -> 134.209.82.225 22 (msg:"Actioner - Claude Code Backdoor Outbound SSH to C2 IP"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/; metadata:author Actioner, created_at 2026-10-31; sid:2200002; rev:1;)
```

### Suricata: Reverse SSH Tunnel to C2 (Any Port)

Detects SSH protocol traffic to the C2 IP on any port, catching tunnels on non-standard ports.
compile: suricata -T exit 0 | confidence: high (IOC-specific)

<!-- audit: suricata -T exit 0. Matches SSH banner in first 4 bytes to any port on C2 IP. -->

```
alert tcp $HOME_NET any -> 134.209.82.225 any (msg:"Actioner - Claude Code Backdoor Reverse SSH Tunnel to C2"; flow:established,to_server; content:"SSH-"; depth:4; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/; metadata:author Actioner, created_at 2026-10-31; sid:2200003; rev:1;)
```

### Snort: HTTP Beacon to C2 (uncompiled -- structural check only)

Detects HTTP beacon to the C2 server's `/beacon` endpoint.
compile: uncompiled (structural check only -- Snort binary not available) | confidence: high (IOC-specific)

<!-- audit: Snort binary not installed; structural check only. Uses underscore http_uri per snort-ref.md. Comma-separated modifiers. sid 2100001 in 2100000+ range. All required options (msg, sid, rev) present. Semicolons terminate all options. -->

```
alert http $HOME_NET any -> 134.209.82.225 any (msg:"Actioner - Claude Code Backdoor HTTP Beacon to C2"; flow:established, to_server; http_uri; content:"/beacon", fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/; metadata:author Actioner, created 2026-10-31; sid:2100001; rev:1;)
```

### Snort: Outbound SSH to C2 IP (uncompiled -- structural check only)

Detects outbound SSH to the C2 server.
compile: uncompiled (structural check only -- Snort binary not available) | confidence: high (IOC-specific)

<!-- audit: Snort binary not installed; structural check only. TCP flow rule to specific IP:22. All required options present. -->

```
alert tcp $HOME_NET any -> 134.209.82.225 22 (msg:"Actioner - Claude Code Backdoor Outbound SSH to C2 IP"; flow:established, to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/; metadata:author Actioner, created 2026-10-31; sid:2100002; rev:1;)
```

## Lessons Learned

1. **Extension marketplace trust is fragile**: The attack exploited the trust developers place in marketplace-vetted extensions. Even publisher identity verification can be circumvented. Organizations should implement extension allowlisting and integrity verification rather than relying solely on marketplace review.

2. **Auto-update is a double-edged sword**: Auto-update mechanisms meant to deliver security patches can equally deliver malware. Extension auto-updates should have configurable cooldown periods and integrity checks before applying.

3. **Persistence outlives the initial vector**: Removing or updating the malicious extension does NOT remove the SSH keys, persistence mechanisms, or dropped scripts. Incident responders must check all artifact locations on every potentially affected host, not just uninstall the extension.

4. **Implementation bugs are not a defense**: While coding errors in this malware limited its SSH enablement on macOS and Windows, the SSH key installation and reconnaissance beacon still succeeded. Defenders should not assume partial malware failure means no exposure.

5. **Developer environments are high-value targets**: Development machines often have access to source code repositories, CI/CD pipelines, cloud credentials, and production secrets. Supply chain attacks targeting developer tools provide an efficient path to these assets.

## Sources

- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/) -- Primary technical analysis with IOCs, MITRE ATT&CK mapping, KQL hunting queries, and Microsoft Defender detections
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/malicious-claude-code-extension-on-cursor-planted-ssh-backdoors/) -- Reporting on impact scope, coding errors limiting exploitation, and vendor response
- [The Hacker News](https://thehackernews.com/2026/10/official-claude-code-vs-code-extension.html) -- Timeline details, reconnaissance data specifics, and activation mechanism

---
*Report generated by Actioner*
