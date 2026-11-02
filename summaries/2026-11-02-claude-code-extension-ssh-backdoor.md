# Technical Analysis Report: Malicious Claude Code Extension SSH Backdoor (2026-11-02)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-11-02
Version: 1.0

## Executive Summary

A malicious Visual Studio Code extension masquerading as an official "Claude Code" (Anthropic-branded) Cursor IDE extension was discovered planting persistent SSH backdoors and reverse tunnels on developer machines. The extension was published on the VS Code Marketplace and distributed through social-engineering campaigns targeting developers who use AI coding assistants. Once installed, the extension silently injected an attacker-controlled SSH public key (comment: `svc-telemetry`) into the victim's `~/.ssh/authorized_keys`, established reverse SSH tunnels (`ssh -N -R`) to a DigitalOcean C2 server at `134.209.82.225:8099`, and exfiltrated environment variables containing secrets (`KEY`, `TOKEN`, `SECRET`, `PASS`). The attack is cross-platform, with distinct persistence mechanisms for macOS (LaunchAgent `com.apple.sysmond`), Windows (scheduled task `SysMon` running `smt.cmd`), and Linux (crontab entries).

Microsoft Threat Intelligence attributed this campaign to a financially motivated threat actor and published technical details on 2026-10-30. The exposure window spans from approximately mid-October 2026 until the extension was removed from the marketplace. Any developer who installed the extension should assume full compromise of their SSH keys, environment secrets, and potentially lateral access to any system reachable via those credentials.

## Background: Claude Code / Cursor IDE Extensions

Claude Code is Anthropic's official CLI tool and IDE extension for AI-assisted software development. Cursor is a popular AI-native code editor built on VS Code. The attacker exploited developer trust in the "Claude" brand by publishing a convincing lookalike extension on the VS Code Marketplace. Developers searching for Claude Code integration with Cursor would discover the malicious extension, which used Anthropic's branding, logo, and documentation references to appear legitimate. The supply-chain vector is particularly dangerous because IDE extensions run with the full privileges of the developer's user account and have access to the terminal, filesystem, and environment variables.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-10-15 | Malicious extension first published to VS Code Marketplace |
| 2026-10-25 | First victim reports of suspicious SSH connections observed |
| 2026-10-28 | Extension reported and pulled from marketplace |
| 2026-10-30 | Microsoft Threat Intelligence publishes technical blog |
| 2026-11-02 | This report generated |

## Root Cause: Supply-Chain Extension Impersonation

The attacker published a trojanized VS Code extension using Anthropic's Claude Code branding. The extension passed marketplace review because the malicious payload was obfuscated within the extension's activation logic and triggered only after a delay. The initial loader decoded its payload using environment-derived keys and dropped platform-specific persistence components. The lack of mandatory code signing or publisher verification for VS Code Marketplace extensions enabled the impersonation.

## Technical Analysis of the Malicious Payload

### 1. Extension Loader and Activation

Upon installation and activation in the IDE, the extension's `activate()` function executes a multi-stage loader. The loader first performs anti-analysis checks (looking for debugger attachment and known sandbox hostnames), then decodes an embedded payload. Key artifacts include files prefixed with `.stk_` (e.g., `.stk_<random>`) dropped in the user's home directory, which serve as staging markers and contain encoded configuration data.

**Hash (loader):** `ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15`

### 2. SSH Key Injection and Credential Harvesting

The decoded payload performs two primary actions:

1. **SSH key injection:** Appends an attacker-controlled RSA public key to `~/.ssh/authorized_keys` with the distinctive comment `svc-telemetry`. This grants the attacker persistent SSH access to the victim machine.

2. **Environment variable exfiltration:** Enumerates all environment variables and extracts those matching patterns `KEY`, `TOKEN`, `SECRET`, and `PASS`. These are base64-encoded and exfiltrated to the C2 server via HTTP POST to `/beacon`.

### 3. C2 Infrastructure

| Property | Value |
|----------|-------|
| C2 IP | `134[.]209[.]82[.]225` |
| C2 Port | `8099` |
| Protocol | HTTP (beacon), SSH (reverse tunnel) |
| Beacon URI | `/beacon` |
| Tunnel Type | `ssh -N -R` (reverse port forward) |

The C2 server is hosted on DigitalOcean infrastructure. The beacon endpoint receives environment variable dumps and heartbeat check-ins. The reverse SSH tunnel provides the attacker with interactive shell access to the victim's machine, tunneled through the victim's outbound SSH connection.

### 4. Platform-Specific Behavior

#### macOS

- **Persistence:** LaunchAgent plist at `~/Library/LaunchAgents/com.apple.sysmond.plist` (masquerades as Apple system monitor daemon)
- **Payload files:** `.smt` and `.smtk` dropped in the user's home directory
- **Execution:** LaunchAgent triggers the reverse SSH tunnel on login

#### Windows

- **Persistence:** Scheduled task named `SysMon` (masquerades as Sysmon/Sysinternals) that executes `smt.cmd`
- **Payload files:** `smt.cmd` batch script containing SSH tunnel and beacon logic
- **Execution:** Runs at user logon via `schtasks /create`

#### Linux

- **Persistence:** Crontab entry running the beacon and tunnel scripts at regular intervals
- **Payload files:** `.stk_<random>` prefixed files in home directory
- **SSH injection:** Direct append to `~/.ssh/authorized_keys`

### 5. Anti-Forensics / Evasion Techniques

- Delayed activation (payload does not execute immediately upon extension install)
- Use of legitimate tool names for persistence (`SysMon`, `com.apple.sysmond`)
- Dot-prefixed hidden files (`.stk_`, `.smt`, `.smtk`)
- Environment-derived decryption keys for payload decoding
- Reverse tunneling avoids inbound firewall restrictions

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: `[.]` replacing dots in IPs/domains, `hxxps://` for URLs.

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Claude Code (VS Code extension) | Unknown | Trojanized IDE extension impersonating Anthropic's Claude Code |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | Extension loader | `ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15` | Malicious extension main payload |
| All | `~/.ssh/authorized_keys` | N/A | Injected key with comment `svc-telemetry` |
| All | `~/.stk_*` | N/A | Staging/marker files |
| macOS | `~/Library/LaunchAgents/com.apple.sysmond.plist` | N/A | Persistence LaunchAgent |
| macOS | `~/.smt`, `~/.smtk` | N/A | Payload scripts |
| Windows | `smt.cmd` | N/A | Persistence batch script |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `134[.]209[.]82[.]225:8099` | C2 server (DigitalOcean) — beacon + tunnel |
| URL Pattern | `hxxp://134[.]209[.]82[.]225:8099/beacon` | HTTP beacon endpoint |

### Behavioral

- SSH `authorized_keys` modification with `svc-telemetry` comment string
- Outbound SSH reverse tunnel (`ssh -N -R`) to external IP
- Scheduled task named `SysMon` executing `smt.cmd` (Windows)
- LaunchAgent `com.apple.sysmond` not signed by Apple (macOS)
- Process enumerating environment variables matching `KEY`, `TOKEN`, `SECRET`, `PASS`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized VS Code extension on marketplace |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Injected attacker SSH key with svc-telemetry comment |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows SysMon scheduled task for persistence |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS com.apple.sysmond LaunchAgent |
| T1572 | Protocol Tunneling | Reverse SSH tunnel to C2 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell commands for key injection and tunnel setup |
| T1552.001 | Unsecured Credentials: Credentials in Files | Environment variable harvesting (KEY, TOKEN, SECRET, PASS) |
| T1041 | Exfiltration Over C2 Channel | Secrets sent to C2 via HTTP /beacon |

## Impact Assessment

- **Breadth:** Unknown download count; any Cursor/VS Code user who searched for Claude Code extensions during the exposure window is at risk
- **Depth:** Full user-level compromise — SSH access, secrets exfiltration, persistent backdoor
- **Stealth:** High — uses legitimate service names, hidden files, and delayed activation
- **Lateral movement risk:** Exfiltrated SSH keys and API tokens enable access to cloud infrastructure, CI/CD pipelines, and production systems

## Detection & Remediation

### Immediate Detection

```bash
# Check for svc-telemetry SSH key
grep -r "svc-telemetry" ~/.ssh/authorized_keys

# Check for .stk_ staging files
ls -la ~/.*stk_* 2>/dev/null

# Check for macOS persistence
ls -la ~/Library/LaunchAgents/com.apple.sysmond.plist 2>/dev/null

# Check for Windows scheduled task (PowerShell)
# schtasks /query /tn "SysMon" 2>$null

# Check for active reverse tunnels
ps aux | grep "ssh -N -R" | grep -v grep

# Check for beacon connections
ss -tnp | grep "134.209.82.225"
```

### Remediation

1. **Containment:** Immediately uninstall the malicious extension from all IDE instances
2. **SSH key removal:** Remove the `svc-telemetry` key from `~/.ssh/authorized_keys` on all systems
3. **Kill active tunnels:** Terminate any SSH processes connecting to `134.209.82.225`
4. **Remove persistence:**
   - macOS: `launchctl unload ~/Library/LaunchAgents/com.apple.sysmond.plist && rm ~/Library/LaunchAgents/com.apple.sysmond.plist`
   - Windows: `schtasks /delete /tn "SysMon" /f`
   - Linux: Review and clean crontab entries
5. **Remove staging files:** Delete `~/.stk_*`, `~/.smt`, `~/.smtk` files
6. **Rotate all secrets:** Rotate every API key, token, password, and credential that was present in environment variables on the affected machine
7. **Audit SSH access:** Review `authorized_keys` on all systems the compromised machine could reach
8. **Review CI/CD:** Check for unauthorized access to build pipelines using exfiltrated tokens

### Long-Term Hardening

- Pin and verify VS Code extension publisher identities before installation
- Use extension allowlists in enterprise IDE deployments
- Monitor `authorized_keys` modifications with file integrity monitoring (FIM)
- Restrict outbound SSH to known hosts via firewall rules
- Store secrets in vaults (not environment variables) where possible
- Deploy network detection for unexpected reverse tunnel establishment

## Detection Rules

The following rules target the distinct artifacts and behaviors of this supply-chain backdoor. All rules are IOC-anchored to the specific indicators from the Microsoft blog; they are not broad behavioral detections. The one caveat: the C2 IP (`134.209.82.225`) is a DigitalOcean VPS that could be reassigned — if the actor migrates infrastructure, the network-layer rules will need updating while the host-based rules remain valid.

### Sigma: SSH Key Injection with svc-telemetry Comment

Compile: ✅ `sigma convert` (Splunk + LogScale) | Confidence: **high**

```yaml
title: SSH Key Injection with svc-telemetry Comment
id: 8a3e1f7c-4b2d-4e9a-b6c8-1d5f3a9e7b02
status: experimental
description: Detects command-line activity that writes an SSH public key with the distinctive svc-telemetry comment to authorized_keys, consistent with the malicious Claude Code extension SSH backdoor.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026/11/02
tags:
    - attack.t1098.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'authorized_keys'
            - 'svc-telemetry'
    condition: selection
falsepositives:
    - Legitimate SSH key management that coincidentally uses the svc-telemetry comment (extremely unlikely)
level: critical
```

<!-- AUDIT: Compile-status: ✅ sigma convert --without-pipeline -t splunk → CommandLine="*authorized_keys*" CommandLine="*svc-telemetry*"; -t log_scale → regex equivalent. sigma check failed due to proxy blocking MITRE ATT&CK data download (HTTP 403), not a rule defect. Targets process_creation on linux; requires audit/sysmon logging of command lines. The conjunction of both strings makes false positives negligible. Does not cover cases where the key is injected via a compiled binary that doesn't expose these strings in argv. -->

### Sigma: Suspicious SysMon Scheduled Task (Windows Persistence)

Compile: ✅ `sigma convert` (Splunk + LogScale) | Confidence: **high**

```yaml
title: Suspicious SysMon Scheduled Task Creation Pointing to smt.cmd
id: 2c7b4d1e-9f3a-4e6b-8d5c-0a2e7f1b3c94
status: experimental
description: Detects creation of a Windows scheduled task named SysMon that executes smt.cmd, consistent with the malicious Claude Code extension SSH backdoor persistence mechanism.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026/11/02
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
    - Legitimate scheduled tasks that coincidentally use both the name SysMon and reference smt.cmd (extremely unlikely)
level: critical
```

<!-- AUDIT: Compile-status: ✅ sigma convert --without-pipeline -t splunk → Image="*\schtasks.exe" CommandLine="*/create*" CommandLine="*SysMon*" CommandLine="*smt.cmd*"; -t log_scale → regex equivalent. Three-way conjunction on specific strings makes FP rate negligible. Requires Sysmon or Windows Security EventID 4688 with command-line auditing enabled. -->

### Sigma: Network Connection to C2 Server

Compile: ✅ `sigma convert` (Splunk + LogScale) | Confidence: **high**

```yaml
title: Network Connection to Claude Code Extension C2 Server
id: 5e9d2a8f-1c7b-4f3e-a0d6-3b8c5e2f7a19
status: experimental
description: Detects outbound network connections to IP 134.209.82.225, the command-and-control server associated with the malicious Claude Code extension SSH backdoor.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/
author: Actioner
date: 2026/11/02
tags:
    - attack.t1572
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '134.209.82.225'
    condition: selection
falsepositives:
    - Legitimate traffic to this DigitalOcean IP (verify context before alerting)
level: high
```

<!-- AUDIT: Compile-status: ✅ sigma convert --without-pipeline -t splunk → DestinationIp="134.209.82.225"; -t log_scale → regex equivalent. IOC-specific; will need update if C2 migrates. Platform-agnostic network_connection logsource. FP possible if IP is reassigned to legitimate service after takedown. -->

### YARA: Supply Chain Claude Code SSH Backdoor

Compile: ✅ `yarac` | Confidence: **high**

```yara
rule SupplyChain_ClaudeCode_SSH_Backdoor
{
    meta:
        description = "Detects the malicious Claude Code extension loader that plants SSH backdoor keys and reverse tunnels"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"
        hash = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
        severity = "critical"

    strings:
        $ssh_comment = "svc-telemetry" ascii wide
        $stk_pattern = ".stk_" ascii wide
        $beacon_path = "/beacon" ascii wide
        $beacon_port = "8099" ascii wide
        $smt_file = ".smt" ascii wide
        $smtk_file = ".smtk" ascii wide
        $plist_name = "com.apple.sysmond" ascii wide
        $ssh_args = "-N -R" ascii wide
        $env_key = "KEY" ascii
        $env_token = "TOKEN" ascii
        $env_secret = "SECRET" ascii
        $env_pass = "PASS" ascii

    condition:
        ($ssh_comment and $stk_pattern) or
        ($ssh_comment and $beacon_path and $beacon_port) or
        ($plist_name and ($smt_file or $smtk_file)) or
        ($stk_pattern and $ssh_args and 2 of ($env_key, $env_token, $env_secret, $env_pass))
}
```

<!-- AUDIT: Compile-status: ✅ yarac compiled cleanly. Four disjunctive condition clauses each require 2+ specific strings to match, keeping FP rate low. String set derived from Microsoft blog IOCs. $beacon_port now referenced in condition (fixed from initial draft). The $env_* strings are generic on their own but require conjunction with $stk_pattern and $ssh_args. -->

### Suricata: HTTP Beacon to C2

Compile: ✅ `suricata -T` | Confidence: **high**

```
alert http $HOME_NET any -> 134.209.82.225 any (msg:"Actioner - Claude Code Extension HTTP Beacon to C2"; flow:established,to_server; http.uri; content:"/beacon"; endswith; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/; metadata:author Actioner, created_at 2026-11-02; sid:2200101; rev:1;)
```

<!-- AUDIT: Compile-status: ✅ suricata -T validated. IOC-anchored to C2 IP in destination. http.uri content match on /beacon with endswith restricts to exact URI path. Will need IP update if C2 migrates. -->

### Snort 3: HTTP Beacon to C2

Compile: ⚠️ uncompiled (structural check only — snort not installed) | Confidence: **high**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Claude Code Extension C2 Beacon to 134.209.82.225:8099"; flow:established,to_server; content:"/beacon"; http_uri; content:"134.209.82.225"; sid:2100101; rev:1; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/;)
```

<!-- AUDIT: Compile-status: ⚠️ snort binary not available in environment; rule follows Snort 3 syntax conventions. Uses $EXTERNAL_NET destination (broader than Suricata variant) with IP matched as content in the packet. Dual content match on /beacon URI and C2 IP. -->

## Lessons Learned

This attack demonstrates the continued growth of supply-chain threats targeting developer tooling ecosystems. VS Code Marketplace extensions run with full user privileges and have no meaningful sandboxing, making them high-value targets. The use of a trusted brand name (Claude Code / Anthropic) as social engineering bait reflects attackers' awareness that developers are rapidly adopting AI coding assistants and may not verify publisher authenticity. Organizations should treat IDE extension installation with the same rigor as software supply-chain management: maintain allowlists, verify publishers, and monitor for post-install behavioral anomalies.

## Sources

- [Microsoft Security Blog: Inside malicious Claude Code-branded Cursor extension](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/) — primary technical analysis with IOCs, attack flow, and platform-specific persistence details

---
*Report generated by Actioner*
