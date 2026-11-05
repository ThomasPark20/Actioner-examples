# Malicious Claude Code-Branded Cursor Extension with Persistent SSH Backdoor

**Date:** 2026-11-05
**Status:** DRAFT
**TLP:** CLEAR
**Author:** Actioner

---

## Executive Summary

On October 29, 2026, a tampered Claude Code-branded extension (versions 2.1.312 and 2.1.313) was distributed through the Cursor extension marketplace for approximately 11 hours (02:27 -- 13:35 PDT). The extension contained a 66-line JavaScript loader injected before the legitimate extension code that collected host reconnaissance data, planted an attacker-controlled SSH public key, and established a persistent reverse SSH tunnel to external infrastructure at `134[.]209[.]82[.]225`. The attack targeted Windows and macOS developers, with Linux persistence mechanisms also present. Up to 5,000 developers may have been exposed. Anthropic confirmed its systems were not compromised. The attacker's server has been taken offline.

## Source Verification

| # | Source | Status |
|---|--------|--------|
| 1 | [Microsoft Security Blog -- Inside Malicious Claude Code-Branded Cursor Extension](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/) | VERIFIED |
| 2 | [HackRead -- Cursor Claude Code Extensions SSH Backdoor](https://hackread.com/cursor-claude-code-extensions-ssh-backdoor-code/) | VERIFIED |
| 3 | [The Register -- Anthropic: That Claude Code Extension Compromise](https://www.theregister.com/cyber-crime/2026/10/30/anthropic-that-claude-code-extension-compromise-couldnt-be-us/5306682) | VERIFIED |
| 4 | [Cursor Security Notice](https://cursor.com/blog/claude-code-extension-security-notice) | VERIFIED |
| 5 | [Phorion Analysis](https://phorion.io/blog/offical-claude-code-vsx-compromise/) | VERIFIED |

## Indicators of Compromise

### File Hashes

| Artifact | SHA-256 | MD5 |
|----------|---------|-----|
| VSIX 2.1.312 (darwin-arm64) | `fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364` | `e0d64d53e802a0217ba6f0e656ed2f20` |
| VSIX 2.1.312 (win32-x64) | `3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081` | `bd3b71ddf3d0cc3af76249afd2c0eda1` |
| VSIX 2.1.313 (darwin-arm64) | `80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c` | `34e491161e056c9b899a79b602ac73b9` |
| VSIX 2.1.313 (win32-x64) | `6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731` | `7838a3be2ca0ff08c1bdb160ef516d39` |
| Backdoored extension.js | `ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15` | `f49bcd657ef1e626e85ce858958c1769` |
| Tunnel private key file | `7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278` | -- |

### Network Indicators (Defanged)

| Indicator | Type | Context |
|-----------|------|---------|
| `134[.]209[.]82[.]225` | IPv4 | SSH tunnel destination and beacon C2 server |
| `hxxp://134[.]209[.]82[.]225:8099/beacon` | URL | HTTP POST beacon for host recon exfiltration |
| `tunnel@134[.]209[.]82[.]225` | SSH User | Reverse tunnel authentication user |
| `ifconfig[.]me` | Domain | Public IP lookup (legitimate service, used for recon) |
| `api[.]ipify[.]org` | Domain | Public IP lookup (legitimate service, used for recon) |

### SSH Key Artifacts

| Key | Type | Fingerprint | Comment |
|-----|------|-------------|---------|
| Unauthorized login key (planted in authorized_keys) | Ed25519 | `SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk` | `svc-telemetry` |
| Reverse tunnel identity key | Ed25519 | `SHA256:KOAU57+ZG6u3MG4WwzPzPX2O5YEe9qdOC1Bl+6MVyDQ` | `svc-telemetry-tun` |

**Planted public key:**
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P svc-telemetry
```

### Host Artifacts -- File Paths

**All Platforms:**
- `~/.ssh/authorized_keys` -- planted `svc-telemetry` public key
- `<TMPDIR>/.stk_<10 hex chars>` -- initial tunnel private key (hex = first 10 chars of MD5(hostname + HOME))

**macOS:**
- `~/Library/LaunchAgents/com.apple.sysmond.plist` -- persistence LaunchAgent (RunAtLoad, KeepAlive)
- `~/.config/.smt` -- persistence shell script (tunnel retry loop)
- `~/.config/.smtk` -- recreated tunnel private key

**Linux:**
- `~/.config/.smt` -- persistence shell script
- `~/.config/.smtk` -- tunnel private key
- User crontab `@reboot` entry referencing `~/.config/.smt`

**Windows:**
- `%USERPROFILE%\.config\smt.cmd` -- persistence batch script
- `%USERPROFILE%\.config\smtk` -- tunnel private key
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\sysmon.cmd` -- Startup folder fallback
- `C:\ProgramData\ssh\administrators_authorized_keys` -- additional key target

### Process and Command-Line Indicators

- `ssh -N -R '*:0:localhost:22'` -- reverse tunnel with server-allocated port
- `autossh -M 0` -- auto-reconnecting SSH wrapper
- SSH options: `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, `ServerAliveInterval=30`, `ServerAliveCountMax=3`, `ExitOnForwardFailure=yes`, `IdentitiesOnly=yes`, `BatchMode=yes`
- `schtasks /create /tn SysMon` -- Windows scheduled task creation
- `systemsetup -setremotelogin on` -- macOS Remote Login enablement
- `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0` -- Windows OpenSSH Server install

### Exfiltrated Data

Host reconnaissance data sent via HTTP POST to the beacon endpoint:
- Hostname, username, OS, architecture, home directory, working directory
- Git global email (`git config --global user.email`)
- Public IP address
- Up to 40 environment variable **names** matching `/KEY|TOKEN|SECRET|PASS|AWS|GCP/i` (values not exfiltrated per analysis)

### Microsoft Defender Detection Names

- `Trojan:MacOS/SmtShellMal.A`
- `Trojan:JS/CredTheft.MS!MTB`
- `Trojan:MacOS/MalPlistSysmond.A`
- `HackTool:MacOS/RevAnthShell.A`

## MITRE ATT&CK Mapping

| Technique ID | Name | Context |
|-------------|------|---------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Tampered extension distributed via Cursor marketplace |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Planted attacker ed25519 key in authorized_keys |
| T1572 | Protocol Tunneling | Reverse SSH tunnel to attacker server |
| T1053.003 | Scheduled Task/Job: Cron | Linux `@reboot` crontab persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows "SysMon" scheduled task (SYSTEM) |
| T1547.011 | Boot or Logon Autostart Execution: Plist Modification | macOS `com.apple.sysmond` LaunchAgent |
| T1547.001 | Boot or Logon Autostart Execution: Startup Folder | Windows `sysmon.cmd` in Startup folder |
| T1082 | System Information Discovery | Hostname, OS, architecture collection |
| T1016 | System Network Configuration Discovery | Public IP lookup via ifconfig.me/ipify |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell-based persistence and tunnel scripts |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Windows OpenSSH install and tunnel loop |
| T1041 | Exfiltration Over C2 Channel | Beacon POST with host reconnaissance data |

## Viability Gate

**PASS** -- Multiple concrete, distinctive artifacts are available: six unique file hashes, a specific attacker IP address, unique SSH key fingerprints, distinctive file paths, and specific command-line patterns. These are sufficient for high-fidelity detection rules.

## Detection Rules

### Sigma Rules (9 rules)

All rules validated via `sigma convert -t splunk --without-pipeline` (exit 0) and structural YAML validation (all required fields present).

| Rule File | Title | Technique | Confidence | Compile Status |
|-----------|-------|-----------|------------|----------------|
| `sigma_malicious_claude_extension_hash.yml` | File Hash Detection | T1195.002 | HIGH | PASS |
| `sigma_svc_telemetry_ssh_key.yml` | svc-telemetry SSH Key in Authorized Keys | T1098.004 | HIGH | PASS |
| `sigma_sysmon_scheduled_task.yml` | SysMon Scheduled Task Creation | T1053.005 | HIGH | PASS |
| `sigma_macos_launchagent_sysmond.yml` | com.apple.sysmond LaunchAgent | T1547.011 | HIGH | PASS |
| `sigma_reverse_ssh_tunnel.yml` | Reverse SSH Tunnel to Attacker IP | T1572 | HIGH | PASS |
| `sigma_smt_persistence_files.yml` | Persistence Script File Creation (.smt/.smtk) | T1547.001 | HIGH | PASS |
| `sigma_startup_sysmon_cmd.yml` | sysmon.cmd in Windows Startup Folder | T1547.001 | HIGH | PASS |
| `sigma_beacon_http_post.yml` | HTTP Beacon to Attacker Server | T1041 | HIGH | PASS |
| `sigma_ssh_reverse_tunnel_pattern.yml` | SSH Reverse Tunnel with StrictHostKeyChecking Disabled | T1572 | MEDIUM | PASS |

> **Note on confidence:** Hash-based and IP-based rules are HIGH confidence (specific to this threat). The behavioral SSH tunnel pattern rule (`sigma_ssh_reverse_tunnel_pattern.yml`) is MEDIUM confidence due to potential overlap with legitimate SSH usage in development environments.

### YARA Rules (4 rules)

Compiled with `yarac` (exit 0) and validated against test data.

| Rule Name | Description | Confidence | Compile Status |
|-----------|-------------|------------|----------------|
| `Malicious_Claude_Code_Extension_JS_Payload` | Backdoored extension.js with SSH backdoor markers | HIGH | PASS |
| `Malicious_Claude_Code_Extension_VSIX` | Malicious VSIX package with embedded backdoor | HIGH | PASS |
| `Malicious_Claude_Code_Persistence_Script` | Tunnel retry shell/batch persistence scripts | MEDIUM | PASS |
| `Malicious_Claude_Code_SSH_Private_Key` | Dropped tunnel private key with svc-telemetry-tun comment | HIGH | PASS |

### Suricata Rules (3 rules)

Validated with `suricata -T` (exit 0).

| SID | Description | Confidence | Compile Status |
|-----|-------------|------------|----------------|
| 2026110501 | HTTP Beacon POST to attacker C2 (134[.]209[.]82[.]225:8099/beacon) | HIGH | PASS |
| 2026110502 | SSH connection to attacker infrastructure (134[.]209[.]82[.]225:22) | HIGH | PASS |
| 2026110503 | Beacon exfiltration containing svc-telemetry marker | MEDIUM | PASS |

## Rule File Locations

All rules are located in `/tmp/actioner/`:

- `/tmp/actioner/sigma_malicious_claude_extension_hash.yml`
- `/tmp/actioner/sigma_svc_telemetry_ssh_key.yml`
- `/tmp/actioner/sigma_sysmon_scheduled_task.yml`
- `/tmp/actioner/sigma_macos_launchagent_sysmond.yml`
- `/tmp/actioner/sigma_reverse_ssh_tunnel.yml`
- `/tmp/actioner/sigma_smt_persistence_files.yml`
- `/tmp/actioner/sigma_startup_sysmon_cmd.yml`
- `/tmp/actioner/sigma_beacon_http_post.yml`
- `/tmp/actioner/sigma_ssh_reverse_tunnel_pattern.yml`
- `/tmp/actioner/yara_malicious_claude_extension.yar`
- `/tmp/actioner/suricata_malicious_claude_extension.rules`

## Remediation Guidance

1. **Isolate** any host with evidence of the extension (versions 2.1.312 or 2.1.313) or persistence artifacts.
2. **Remove** the `svc-telemetry` key from `~/.ssh/authorized_keys` (and `C:\ProgramData\ssh\administrators_authorized_keys` on Windows).
3. **Remove** persistence mechanisms:
   - macOS: `~/Library/LaunchAgents/com.apple.sysmond.plist`, unload via `launchctl`
   - Linux: `@reboot` crontab entry referencing `.smt`
   - Windows: Scheduled task "SysMon", `sysmon.cmd` from Startup folder
4. **Delete** dropped files: `~/.config/.smt`, `~/.config/.smtk`, `smt.cmd`, `.stk_*` temp files.
5. **Kill** active `ssh`/`autossh` processes connecting to `134[.]209[.]82[.]225`.
6. **Rotate** all credentials, tokens, and sessions accessible from affected hosts, working from a trusted system.
7. **Run** Cursor's remediation scripts: `remediate-macos.sh` (as affected user) or `remediate-windows.ps1` (elevated PowerShell).
8. **Consider rebuilding** affected hosts, as standalone persistence scripts operate independently of the extension.

## Caveats

- The attacker's server (`134[.]209[.]82[.]225`) has been taken offline by the hosting provider; IP-based detections are retrospective for this campaign but may detect infrastructure reuse.
- The SSH tunnel required admin/root privileges on macOS and Windows, which most victims lacked, so the tunnel usually failed. However, the SSH key planting and host reconnaissance still executed.
- Environment variable **names** were exfiltrated but **not values**; however, credential rotation is still advised given the SSH key compromise vector.
- Uninstalling the extension does NOT remove persistence artifacts. Manual cleanup or remediation scripts are required.
- The behavioral SSH tunnel pattern rule has elevated false-positive risk in CI/CD and development environments.

---

*Draft generated 2026-11-05 by Actioner. All network IOCs are defanged. All sources verified via direct fetch.*
