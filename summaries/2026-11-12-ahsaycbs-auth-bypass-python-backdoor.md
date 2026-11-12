# Technical Analysis Report: AhsayCBS Authentication Bypass + RCE Chain (CVE-2026-105133 / CVE-2026-105134) with Python Backdoor

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-11-12
Version: 1.0 (DRAFT)

## Executive Summary

Attackers are actively exploiting a chain of two vulnerabilities in Ahsay AhsayCBS backup server software to achieve unauthenticated remote code execution as NT AUTHORITY\SYSTEM. CVE-2026-105133 is an authentication bypass in the `checkSysPwd` function (CVSS 3.1: 7.3 High), and CVE-2026-105134 is an OS command injection in the Replication Receiver endpoint `/rps/api/json/UpdateReceivers.do` (CVSS 3.1: 10.0 Critical). Chained together, these flaws grant full, unauthenticated RCE on the backup server.

First observed by [Huntress](https://www.huntress.com/blog/ahsaycbs-flaws-exploit) on 2026-10-07 at 23:20 UTC, the campaign has hit at least five organizations. Observed post-exploitation includes JSP web shells (including a PNG steganography loader and a signed-API shell), XMRig cryptominers disguised as Microsoft Edge and `kvm-agent.exe`, tunneling tools (GOST and Chisel), remote access software (AnyDesk, Atera, Splashtop), and a host-keyed Python backdoor (`main.py`) that evades sandbox analysis by requiring a MachineGuid-derived marker file. The implant's C2 is `creepexplosiondarknight[.]com` over HTTPS, with DNS-over-HTTPS resolution. Both CVEs were added to the [CISA KEV catalog](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42944e2) on 2026-10-14. Ahsay's initial patches were incomplete; the fixed builds are v10.3.4.45 (v10) and v9.15.2.70 (v7/v8/v9).

## Background: AhsayCBS Backup Server

AhsayCBS (Cloud Backup Suite) is an enterprise backup management console used heavily by MSPs (Managed Service Providers) to centrally manage backup agents across customer environments. It runs as a Java-based web application (Tomcat servlet container) with a web console typically exposed on ports 443/8443. Its Replication Receiver component allows backup data replication between sites. AhsayCBS servers often hold credentials for storage targets, backup encryption keys, and may have network access to production systems, making them a high-value target.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-10-04 | NVD publishes CVE-2026-105133 and CVE-2026-105134 |
| 2026-10-07 23:20 | Huntress first observes exploitation in the wild |
| 2026-10-08 | Five organizations confirmed targeted; smash-and-grab activity with web shells and XMRig miners |
| 2026-10-08 to 2026-10-11 | Broader intrusion at one organization across three AhsayCBS servers with persistence, miners, tunneling, and Python implant |
| 2026-10-09 | Ahsay begins receiving partner reports of unauthorized access |
| 2026-10-10 | Ahsay acknowledges initial patch (v10.3.4.0 / v9.15.2.59) was incomplete |
| 2026-10-12 | Ahsay releases hotfixes v10.3.4.45 and v9.15.2.70 |
| 2026-10-14 | CISA adds both CVEs to the Known Exploited Vulnerabilities (KEV) catalog; federal remediation deadline set for 2026-10-17 under BOD 26-04 |

## Root Cause: Chained Authentication Bypass + Command Injection

**CVE-2026-105133** (CWE-287: Improper Authentication) resides in the `checkSysPwd` function in `com/ahsay/obs/api/ApiStructsAction.java`. By manipulating the `random` argument, an attacker bypasses authentication entirely. No privileges or user interaction are required.

**CVE-2026-105134** (CWE-77/CWE-78: OS Command Injection) is in the Replication Receiver component, accessible at `/rps/api/json/UpdateReceivers.do`. A crafted `random` argument triggers OS command injection. Commands execute as `NT AUTHORITY\SYSTEM` on Windows. Together, CVE-2026-105133 provides unauthenticated access, and CVE-2026-105134 delivers arbitrary command execution.

**Affected versions:** AhsayCBS v7 through v10 below v9.15.2.70 (v7/v8/v9) or v10.3.4.45 (v10). Earlier patches v10.3.4.0 and v9.15.2.59 are insufficient.

## Technical Analysis of the Malicious Payload

### 1. Initial Access and Web Shell Deployment

After exploiting the vulnerability chain, attackers deployed multiple JSP web shell families into `%CBS%\webapps\cbs` and `%CBS%\webapps\rps`:

- **Keyed command shell**: Requires a hardcoded key in parameter `p`; runs commands via `cmd.exe /c`; returns Base64-encoded output. Wrong key returns HTTP 404.
- **Keyed shell with file write**: Extends the above; parameter `w` (path) + `d` (Base64 data) writes files. Each instance has a unique 12-hex-character key ending in "P".
- **`status_*.jsp` / `st_*.jsp`**: Parameter-driven shells (`cmd`, `del`, `rm`) with 32-character hex auth secrets or simple passwords (`nobody`, `mysecret123`). `rm=1` triggers self-deletion. The `st_*` variant has no authentication and leaks environment paths via `get=env`.
- **nsmind.jsp**: A signed-API shell requiring `X-Auth-Token`, `X-Timestamp` (5-minute window), `X-Nonce` (anti-replay), and `X-Signature` (HMAC-SHA256). Supports `exec`, `cd`, `upload`, `download` actions. Upload/download use chunked transfers with 4GB per-file limit.
- **AhsayCBS.jsp** (PNG steganography loader): Receives a PNG via POST, extracts payloads from LSBs of RGB pixel values, decrypts with AES-ECB (key: `3c6e0b8a9c15224a`), loads as a Java class via custom ClassLoader, and stores it in the application context under attribute `QuCh`. Works on any servlet container with JDK 6+.

Web shells were also staged at Linux-style paths that manifest on Windows as `C:\opt\AhsayCBS`, `C:\usr\local\AhsayCBS`, `C:\home\ahsay\AhsayCBS`, alongside staging directories `C:\ahsay_tf`, `C:\ahsay_th`, `C:\ahsay_t0`, `C:\ahsay_poc_*`, and random 6-character folders (`xtj7iu`, `kje74x`, `103y9r`) with `pb_` marker files in `conf`.

### 2. Cryptomining

**Miner 1 (Edge masquerade):**
- `edge.exe` (XMRig) in `%TEMP%`, masquerading as Microsoft Edge
- Persistence via Windows service `MicrosoftEdgeUpdateSvc` using `msedge.exe` (modified NSSM) running as SYSTEM
- Mining pool: `xmr.kryptex[.]network:8029` and `51.195.127[.]124:8029`
- Pool user: `krxYMRN97D/creativejs`
- A companion script `Taskgmr.ps1` monitors for Task Manager and pauses mining when it detects it

**Miner 2 (kvm-agent):**
- `kvm-agent.exe` (XMRig) in `C:\Windows\SysWOW64\kvm-agent\`
- Persistence via scheduled task `kvm` running as SYSTEM every minute, using `tasklist` to check and restart
- Mining pool: `pool.supportxmr[.]com:443`, `pool-fr.supportxmr[.]com:443`, `104.243.43[.]115:443`
- Wallet: `83YFdNe2X8KhKnAERfr2hmN8L3tCKatsheuViWhF6qp2ZA4R8rRkBCgMknEycYqasNbX7C5BSrTp97zHUsUHJoZrR6f5SeX`
- Pool password: `zero`
- Backdated start date on the scheduled task

### 3. Python Implant (main.py) and C2

The Python backdoor is deployed as `main.py` via an embedded Python distribution under the `SYSTEM` profile, launched from a Run registry key through `explorer.exe`.

**Sandbox evasion (environmental keying):** The implant computes the SHA-256 hash of the host's `MachineGuid` (from `HKLM\SOFTWARE\Microsoft\Cryptography`) and checks for a file with that hash name in its directory. If the marker file is absent (as it would be on any sandbox or analyst machine), the implant exits silently.

**Payload chain:**
1. `main.py` is obfuscated: Base64 -> LZMA -> marshaled code object -> `exec()`
2. The compiled source name is `heap_shellcode_runner_bound_weaponized.py`
3. If the marker file exists, it allocates executable heap memory (`HeapCreate`, `HeapAlloc`, `RtlMoveMemory`) and runs a 673KB embedded blob via `CreateThread`
4. The blob contains a bootstrap and reflective loader that maps an x64 DLL into memory
5. The DLL is C++ with a JSON library, imports `bcrypt`, `KERNEL32`, `OLEAUT32`, `SHLWAPI`, and resolves networking APIs at runtime
6. No export table, PDB path, or version resource

**C2:** `hxxps://creepexplosiondarknight[.]com/d` over HTTPS. The DLL contains DNS-over-HTTPS fragments referencing Quad9 (`dns.quad9.net`) and Google DNS (`dns.google`). It reads `MachineGuid` and Windows version info for check-in. Post-check-in behavior is unknown.

### 4. Additional Tooling and Lateral Movement

- **Tunneling:** GOST and Chisel, staged in `.st<id>` folders as `wust<id>a.exe` and `wust<id>b.exe`
- **Remote access:** AnyDesk, Atera, Splashtop
- **Local account creation:** `wdguest`
- **Credential access:** Mimikatz on disk; on a related Veeam server, commands consistent with NetExec's Veeam credential-theft module were observed alongside a PowerShell script (likely launched remotely via WMI) that queried the VeeamBackup PostgreSQL database and decrypted stored credentials with DPAPI
- **Staging URLs (Alibaba OSS):**
  - `hxxp://imagefiles-backup.oss-ap-southeast-7.aliyuncs[.]com/javas/Office/win/Taskgmr.ps1`
  - `hxxp://imagefiles-backup.oss-ap-southeast-7.aliyuncs[.]com/javas/Office/win/edge.exe`
  - `hxxp://imagefiles-backup.oss-ap-southeast-7.aliyuncs[.]com/javas/Office/win/msedge.exe`
  - `hxxp://imagefiles-backup.oss-ap-southeast-7.aliyuncs[.]com/javas/Office/win/config.json`
  - `hxxp://imagefiles-backup.oss-ap-southeast-7.aliyuncs[.]com/javas/Office/win/WinRing0x64.sys`
- **Bitdefender-reported staging URLs:**
  - `hxxps://captcha-eyw[.]pages[.]dev`
  - `hxxps://captcha-eyw[.]pages[.]dev/challenges.ps1`
  - `hxxps://captcha-eyw[.]pages[.]dev/install.ps1`

### 5. Anti-Forensics / Evasion Techniques

- Microsoft Defender exclusions for `C:\ProgramData`, `C:\Windows`, temp folders, dropper processes, and `cbssvcX64.exe`
- MachineGuid-keyed marker file for sandbox evasion (T1480.001)
- Reflective DLL loading in memory (T1620)
- AES-encrypted payloads hidden in PNG LSBs (T1027.003)
- Base64/LZMA/marshal obfuscation chain
- Task Manager monitoring with automatic miner pausing
- Self-deleting web shells (`rm=1`)
- Backdated scheduled task timestamps
- DNS-over-HTTPS for C2 resolution

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| Platform | Path / Filename | Hash (SHA-256) | Description |
|----------|----------------|----------------|-------------|
| Windows | main.py | `8aac187bae71f75fa2dde03dcb4a9279c982182ee8254ae96e7a6626fe4c7617` | Python backdoor implant |
| Windows | (decoded marshal payload) | `91b3cc9d6421b651ec85a16062af3ba26700dad2eea4a8a7e42fdd2e422f8803` | Decoded marshal code object |
| Windows | (embedded blob) | `6953618238eb40f45b584e52aca22cebbe8ba03e9a80c15c6b593f51f7e49527` | 673KB shellcode blob |
| Windows | (x64 DLL) | `bb2472cf5dc7e5c94216d355bf84fba2c8d088d03d61a1ac0d78639049cf5e1f` | Reflectively loaded C2 DLL |
| Windows | (reflective loader tail) | `e79c91e8157fef862be8cbe80bdf57b87a541416717265f81f669d751fca4a3d` | Loader stub |
| Windows | AhsayCBS.jsp | `6c7a4061bcf08df5fe4a49d37442dc650d751be1a91a8bc802edff213e4d5e61` | PNG steganography loader |
| Windows | nsmind.jsp | `6c695baad1d81ed49194d07a79381292c0466208ff1a9862c0c55f971d6a409f` | Signed-API web shell |
| Windows | a2b59a4bb296604b.jsp | `e6e576a634166a16bdbfc09b14e7cf8eab90015d2dfa67dd73f3968ee869229b` | Keyed command shell |
| Windows | (status_*.jsp with `nobody`) | `7a13e59d816d68a071a8648e62a7c3c7f929a61c618a2133ab6f511da24f979d` | Web shell variant |
| Windows | (st_*.jsp, unauthenticated) | `875d0986ddaa51bfb5e03b06df1213cc3bb7966588d6153bdda57f2e3671e986` | Unauthenticated web shell |
| Windows | (cmd/del/rm shell) | `818bb464271a539c96bcbbfea1db7d5a722512041ed8ed10d3f6c7f366190044` | Web shell variant |
| Windows | edge.exe | `4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d` | XMRig miner (Edge disguise) |
| Windows | msedge.exe | `05f69ae6b2b89c1c4dcf836bff032232f11bf0109f2b498e2345045d06139034` | Modified NSSM service wrapper |
| Windows | Taskgmr.ps1 | `481728a7c9c4c02be07051d9c1958d902ea6397ebb8952ab83944818e3d25d21` | Task Manager monitor script |
| Windows | kvm-agent.exe | `8245c7e7d944923f1608592f6c3473dcc6e3a3e43df3dd1c6257e7880948787b` | XMRig miner (kvm disguise) |
| Windows | config.json (kvm) | `a87002c32723f1849b3ad17b1fe6da732c9810b54b08501be21f5b1fcd882a59` | Miner config |
| Windows | kvm task XML | `f76dae028e0c43248c128b3bf609e8d660ce0bf44b53ab9e097887e6f5206eb5` | Scheduled task definition |
| Windows | gost | `6f6b66cbdc4a5aa5685d0017abd3f65843a28bcc2bb4e5b78d6d12a844a51aa8` | GOST tunneling tool |
| Windows | chisel | `ca5f8e5247f1a044b8be45ef03187726b9af3ac30fd93fb5bb54144e34ed3738` | Chisel tunneling tool |

### Suspicious Paths

- `C:\ahsay_tf`, `C:\ahsay_th`, `C:\ahsay_t0`, `C:\ahsay_poc_*` (staging directories)
- `C:\opt\AhsayCBS`, `C:\usr\local\AhsayCBS`, `C:\home\ahsay\AhsayCBS` (Linux-path mimicry)
- `C:\Windows\SysWOW64\kvm-agent\` (miner installation)
- `%CBS%\webapps\cbs\`, `%CBS%\webapps\rps\` (web shell drop location)
- Random 6-char folders with `pb_` marker files in `conf`

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `creepexplosiondarknight[.]com` | Python implant C2 |
| URL | `hxxps://creepexplosiondarknight[.]com/d` | C2 check-in endpoint |
| Domain | `imagefiles-backup.oss-ap-southeast-7.aliyuncs[.]com` | Payload staging (Alibaba OSS) |
| Domain | `xmr.kryptex[.]network` | Mining pool (Miner 1) |
| Domain | `pool.supportxmr[.]com` | Mining pool (Miner 2) |
| Domain | `pool-fr.supportxmr[.]com` | Mining pool (Miner 2) |
| Domain | `captcha-eyw[.]pages[.]dev` | PowerShell staging (Bitdefender) |
| IP | `51.195.127[.]124:8029` | Mining pool (Miner 1) |
| IP | `104.243.43[.]115:443` | Mining pool (Miner 2) |
| IP | `177.4.12[.]11` | Attacker infrastructure |
| IP | `38.60.252[.]110` | Attacker infrastructure |
| IP | `107.191.47[.]199` | Attacker infrastructure |
| IP | `185.220.236[.]49` | Attacker infrastructure |
| IP | `104.234.26[.]10` | Attacker infrastructure |
| IP | `123.202.208[.]37` | Attacker infrastructure |
| IP | `13.143.164[.]15` | Attacker infrastructure (Bitdefender) |
| IP | `45.142.141[.]160` | Attacker infrastructure (Bitdefender) |
| IP | `74.208.22[.]238` | Attacker infrastructure (Bitdefender) |
| IP | `167.148.88[.]236` | Attacker infrastructure (Bitdefender) |

### Behavioral

- `cbssvcX64.exe` / `cbssvcX86.exe` spawning `cmd.exe`, `curl.exe`, `certutil.exe`, `python.exe`, or `powershell.exe`
- `python.exe` / `pythonw.exe` running from a SYSTEM profile path
- Requests to `UpdateReceivers.do` in AhsayCBS access logs
- New JSP files in AhsayCBS `webapps` directories
- Windows service `MicrosoftEdgeUpdateSvc` with non-Microsoft binary
- Scheduled task `kvm` running as SYSTEM with 1-minute interval
- Defender exclusions for system paths and `cbssvcX64.exe`
- Non-browser processes making DNS-over-HTTPS requests to `dns.quad9.net` or `dns.google`
- Local account `wdguest`
- Run registry key pointing to embedded Python distribution under SYSTEM profile

### Web Shell Secrets (for hunting)

- AES key: `3c6e0b8a9c15224a` (AhsayCBS.jsp)
- App context attribute: `QuCh` (AhsayCBS.jsp)
- API key: `NS_f1ChEBy4SCYGyIDkYcsWOivwtWyXt5il` (nsmind.jsp)
- HMAC secret: `NS_aAXMPsB8zsMdkVbjTp6zicnj9w8Hkaew` (nsmind.jsp)
- Keyed shell passwords ending in "P": `323ced5cf1f4P`, `12cd58cda26eP`, `232e4490b603P`, `be4f92982444P` (and others)
- Simple passwords: `nobody`, `mysecret123`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Chained CVE-2026-105133/105134 against AhsayCBS web console |
| T1059.001 | PowerShell | `Taskgmr.ps1` service monitor; credential theft scripts |
| T1059.003 | Windows Command Shell | Web shells execute via `cmd.exe /c` |
| T1059.006 | Python | `main.py` implant via embedded Python distribution |
| T1505.003 | Web Shell | Multiple JSP web shell families in webapps directories |
| T1053.005 | Scheduled Task | `kvm` task (SYSTEM, 1-minute interval) for miner persistence |
| T1547.001 | Registry Run Keys | Run key for Python implant startup via explorer.exe |
| T1543.003 | Windows Service | `MicrosoftEdgeUpdateSvc` for XMRig persistence |
| T1562.001 | Disable or Modify Tools | Defender exclusions for system paths and AhsayCBS process |
| T1027 | Obfuscated Files or Information | Base64/LZMA/marshal chain; AES encryption; signed API |
| T1027.003 | Steganography | AES payloads hidden in PNG pixel LSBs |
| T1620 | Reflective Code Loading | Reflective DLL loading in memory; in-memory Java class loading |
| T1480.001 | Environmental Keying | MachineGuid SHA-256 marker file check |
| T1036.004 | Masquerade Task or Service | `MicrosoftEdgeUpdateSvc` imitating Edge update |
| T1036.005 | Match Legitimate Name or Location | `edge.exe`, `msedge.exe` naming |
| T1555 | Credentials from Password Stores | Veeam PostgreSQL credential extraction via DPAPI |
| T1071.001 | Web Protocols | HTTPS C2 to creepexplosiondarknight[.]com |
| T1572 | Protocol Tunneling | GOST and Chisel |
| T1219 | Remote Access Software | AnyDesk, Atera, Splashtop |
| T1105 | Ingress Tool Transfer | curl/certutil downloads from Alibaba OSS |
| T1496.001 | Compute Hijacking | XMRig miners with MSR access |

## Impact Assessment

AhsayCBS is widely deployed among MSPs, meaning a single compromised backup server can expose credentials and data for many downstream customer environments. The attack chain requires no authentication and executes as SYSTEM, making exploitation trivial once the management interface is reachable. CISA's addition to the KEV catalog with a 3-day federal remediation deadline underscores the severity. The campaign's use of multiple persistence mechanisms (web shells, services, scheduled tasks, Run keys) means patching alone is insufficient for already-compromised hosts.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for suspicious JSP files in AhsayCBS webapps
Get-ChildItem -Recurse -Filter *.jsp "$env:CBS_HOME\webapps" | Where-Object { $_.Name -match '^[a-f0-9]{16}\.jsp$|^st_|^status_|^nsmind|^AhsayCBS\.jsp' }

# Check for kvm-agent miner
Get-ScheduledTask | Where-Object { $_.TaskName -eq 'kvm' }
Get-Service | Where-Object { $_.Name -eq 'MicrosoftEdgeUpdateSvc' }

# Check for suspicious staging directories
Test-Path C:\ahsay_tf, C:\ahsay_th, C:\ahsay_t0, C:\opt\AhsayCBS, C:\usr\local\AhsayCBS

# Check for Python under SYSTEM profile
Get-ChildItem -Recurse "C:\Windows\System32\config\systemprofile" -Filter python*.exe -ErrorAction SilentlyContinue

# Check Defender exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

### Remediation

1. **Isolate** the affected AhsayCBS server immediately
2. **Do NOT just patch** -- if compromise is suspected, perform a full re-image from a trusted backup (Ahsay Auto Save, choosing a version at least one day before the earliest suspicious artifact)
3. **Apply hotfix** v10.3.4.45 (v10) or v9.15.2.70 (v7/v8/v9) on the fresh installation
4. **Rotate all credentials** stored on or reachable from the server: AhsayCBS admin accounts, backup storage credentials, service accounts, cached domain credentials, and any credentials in downstream backup software (especially Veeam)
5. **Remove persistence:** Delete the `kvm` scheduled task, `MicrosoftEdgeUpdateSvc` service, Run keys pointing to embedded Python, and all suspicious JSP files
6. **Remove Defender exclusions** that were not intentionally configured
7. **Block IOCs** at the network perimeter (C2 domain, staging domains, and attacker IPs listed above)

### Long-Term Hardening

- Restrict AhsayCBS management console access to trusted IPs or VPN-only
- Monitor for child processes of `cbssvcX64.exe` / `cbssvcX86.exe` (the AhsayCBS service process should not spawn command shells)
- Implement web application directory integrity monitoring for the `webapps` directory
- Deploy network segmentation between backup infrastructure and production environments
- Enable PowerShell Script Block Logging and command-line process auditing

## Detection Rules

These detections target the AhsayCBS exploitation chain and its post-exploitation artifacts at the specific/advisory altitude. SIDs are placeholders; replace with your local SID allocation before deployment. Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; Suricata rules compile; YARA rules compile. Compiles != fires -- verify in your pipeline with representative telemetry.

### Sigma: AhsayCBS Service Suspicious Child Process

Detects the AhsayCBS service process (`cbssvcX64.exe` or `cbssvcX86.exe`) spawning command interpreters or download utilities, consistent with CVE-2026-105133/105134 exploitation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); splunk convert 0; log_scale convert 0. Keys on ParentImage endswith cbssvcX64/X86.exe + child process list. Distinctive: AhsayCBS service should never spawn these. FP: legitimate AhsayCBS scripted maintenance (rare, filter by environment). -->
```yaml
title: AhsayCBS Service Spawns Suspicious Child Process
id: 7c3a91e2-4b8f-4d1a-9e5c-6f2d8a0b3c7e
status: experimental
description: >
    Detects the AhsayCBS backup service process spawning command interpreters
    or download utilities, consistent with exploitation of CVE-2026-105133
    and CVE-2026-105134 for unauthenticated RCE.
references:
    - https://www.huntress.com/blog/ahsaycbs-flaws-exploit
    - https://www.huntress.com/blog/ahsaycbs-webshells
    - https://thehackernews.com/2026/11/attackers-exploit-ahsaycbs-flaws-to.html
author: Actioner
date: 2026-11-12
tags:
    - attack.t1190
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\cbssvcX64.exe'
            - '\cbssvcX86.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\curl.exe'
            - '\certutil.exe'
            - '\python.exe'
            - '\pythonw.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate AhsayCBS scripted maintenance operations
level: high
```

### Sigma: Python Execution from SYSTEM Profile Path

Detects `python.exe` or `pythonw.exe` running from a SYSTEM profile directory, consistent with the embedded Python distribution used by the AhsayCBS Python backdoor.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); splunk convert 0; log_scale convert 0. Keys on Image containing systemprofile + python. Distinctive: Python should not run from SYSTEM profile. FP: rare legitimate automation under SYSTEM with embedded Python. -->
```yaml
title: Python Execution from SYSTEM Profile Directory
id: 2e9d4a1b-8c3f-4e7a-b5d6-1f0c9a2e3d8b
status: experimental
description: >
    Detects Python interpreters executing from the SYSTEM profile directory,
    consistent with the AhsayCBS Python backdoor (main.py) that deploys an
    embedded Python distribution under the SYSTEM profile.
references:
    - https://www.huntress.com/blog/ahsaycbs-webshells
    - https://thehackernews.com/2026/11/attackers-exploit-ahsaycbs-flaws-to.html
author: Actioner
date: 2026-11-12
tags:
    - attack.t1059.006
    - attack.t1480.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '\systemprofile\'
        Image|endswith:
            - '\python.exe'
            - '\pythonw.exe'
    condition: selection
falsepositives:
    - Legitimate system-level Python automation deployed under SYSTEM profile
level: high
```

### Sigma: Scheduled Task kvm Miner Persistence

Detects creation of the `kvm` scheduled task used for XMRig miner persistence, running as SYSTEM with a one-minute interval.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); splunk convert 0; log_scale convert 0. Keys on schtasks /create with task name kvm + kvm-agent. Highly specific to this campaign. FP: legitimate KVM-related tooling (unlikely to match both task name and kvm-agent path). -->
```yaml
title: Scheduled Task Created for kvm-agent Miner Persistence
id: 4f8b2c6d-1a3e-4e9f-b7d5-2c0a8e3f6b1d
status: experimental
description: >
    Detects creation of the kvm scheduled task used to persist the XMRig
    cryptominer (kvm-agent.exe) observed in the AhsayCBS intrusion campaign.
references:
    - https://www.huntress.com/blog/ahsaycbs-webshells
author: Actioner
date: 2026-11-12
tags:
    - attack.t1053.005
    - attack.t1496.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - 'kvm-agent'
    condition: selection
falsepositives:
    - Legitimate KVM virtualization agent scheduled tasks
level: high
```

### Sigma: Fake Edge Update Service Creation

Detects creation of the `MicrosoftEdgeUpdateSvc` Windows service used by the XMRig miner for persistence via a modified NSSM wrapper.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); splunk convert 0; log_scale convert 0. Keys on service install event with ServiceName MicrosoftEdgeUpdateSvc. Real Edge update service is "edgeupdate" or "MicrosoftEdgeUpdate", not "MicrosoftEdgeUpdateSvc". FP: none expected. -->
```yaml
title: Fake Microsoft Edge Update Service Installation
id: 9a1e3b5c-7d2f-4c8a-b6e4-3f0d1a2c5e9b
status: experimental
description: >
    Detects installation of the MicrosoftEdgeUpdateSvc service, used in the
    AhsayCBS campaign to persist an XMRig miner via a modified NSSM wrapper
    masquerading as a Microsoft Edge update service.
references:
    - https://www.huntress.com/blog/ahsaycbs-flaws-exploit
author: Actioner
date: 2026-11-12
tags:
    - attack.t1543.003
    - attack.t1036.004
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName: 'MicrosoftEdgeUpdateSvc'
    condition: selection
falsepositives:
    - None expected - legitimate Edge update service uses different naming
level: critical
```

### Sigma: JSP Web Shell Creation in AhsayCBS Directories

Detects creation of JSP files in AhsayCBS webapps directories, consistent with web shell deployment after exploitation.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); splunk convert 0; log_scale convert 0. Keys on file creation with .jsp extension in webapps path. Medium confidence: legitimate AhsayCBS updates could create JSP files (filter by change window). -->
```yaml
title: JSP File Created in AhsayCBS Web Application Directory
id: b3d7e1f2-5a4c-4b9e-8c6d-7f2a0e1b3d5c
status: experimental
description: >
    Detects creation of JSP files within AhsayCBS web application directories,
    which may indicate web shell deployment following exploitation of
    CVE-2026-105133 and CVE-2026-105134.
references:
    - https://www.huntress.com/blog/ahsaycbs-webshells
    - https://www.huntress.com/blog/ahsaycbs-flaws-exploit
author: Actioner
date: 2026-11-12
tags:
    - attack.t1505.003
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\webapps\cbs\'
            - '\webapps\rps\'
        TargetFilename|endswith: '.jsp'
    condition: selection
falsepositives:
    - Legitimate AhsayCBS software updates or plugin installations
level: high
```

### Snort: AhsayCBS UpdateReceivers.do Exploitation Attempt

Detects HTTP requests to the `/rps/api/json/UpdateReceivers.do` endpoint used in CVE-2026-105134 exploitation.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: Snort not installed. Structural check: correct http service, http_uri sticky buffer, proper flow, semicolons, sid in range. Keys on the specific vulnerable endpoint path. FP: legitimate AhsayCBS replication receiver configuration (rare from external IPs). -->
```snort
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Actioner - AhsayCBS CVE-2026-105134 UpdateReceivers.do Exploitation Attempt";
    flow:established,to_server;
    http_uri;
    content:"/rps/api/json/UpdateReceivers.do", fast_pattern;
    classtype:web-application-attack;
    reference:url,www.huntress.com/blog/ahsaycbs-flaws-exploit;
    reference:cve,2026-105134;
    metadata:author Actioner, created 2026-11-12;
    sid:2100001;
    rev:1;
)
```

### Suricata: AhsayCBS UpdateReceivers.do Exploitation Attempt

Detects HTTP requests to the `/rps/api/json/UpdateReceivers.do` endpoint used in CVE-2026-105134 exploitation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T 0. Keys on the specific vulnerable endpoint with dot-notation http.uri. FP: legitimate replication receiver configuration from trusted admin IPs (scope to $EXTERNAL_NET -> $HOME_NET). -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Actioner - AhsayCBS CVE-2026-105134 UpdateReceivers.do Exploitation Attempt";
    flow:established,to_server;
    http.uri;
    content:"/rps/api/json/UpdateReceivers.do"; fast_pattern;
    classtype:web-application-attack;
    reference:url,www.huntress.com/blog/ahsaycbs-flaws-exploit;
    reference:cve,2026-105134;
    metadata:author Actioner, created_at 2026-11-12;
    sid:2200001;
    rev:1;
)
```

### Suricata: DNS Query for AhsayCBS Python Implant C2 Domain

Detects DNS resolution of `creepexplosiondarknight.com`, the C2 domain used by the Python backdoor.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T 0. Keys on exact C2 domain in dns.query. Real value (not defanged) in rule. FP: none expected (distinctive domain). -->
```suricata
alert dns $HOME_NET any -> any any (
    msg:"Actioner - AhsayCBS Python Implant C2 DNS Query (creepexplosiondarknight.com)";
    flow:to_server;
    dns.query;
    content:"creepexplosiondarknight.com"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.huntress.com/blog/ahsaycbs-webshells;
    metadata:author Actioner, created_at 2026-11-12;
    sid:2200002;
    rev:1;
)
```

### Suricata: AhsayCBS Campaign Payload Staging Domain

Detects DNS resolution of the Alibaba OSS bucket used for payload staging in the campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T 0. Keys on specific Alibaba OSS bucket domain. FP: none expected (distinctive bucket name). -->
```suricata
alert dns $HOME_NET any -> any any (
    msg:"Actioner - AhsayCBS Campaign Payload Staging Domain (Alibaba OSS)";
    flow:to_server;
    dns.query;
    content:"imagefiles-backup.oss-ap-southeast-7.aliyuncs.com"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.huntress.com/blog/ahsaycbs-flaws-exploit;
    metadata:author Actioner, created_at 2026-11-12;
    sid:2200003;
    rev:1;
)
```

### YARA: AhsayCBS Python Backdoor (main.py)

Detects the AhsayCBS Python backdoor based on distinctive strings from the obfuscation chain and sandbox evasion logic.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac 0. sample: constructed positive with published strings fired, benign negative silent. Keys on the compiled source name "heap_shellcode_runner_bound_weaponized" which is highly distinctive, combined with MachineGuid and heap manipulation strings. FP: none expected (unique source name). -->
```yara
rule Malware_AhsayCBS_Python_Backdoor_MainPy
{
    meta:
        description = "Detects the AhsayCBS Python backdoor (main.py) via distinctive obfuscation and sandbox-evasion strings"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://www.huntress.com/blog/ahsaycbs-webshells"
        hash = "8aac187bae71f75fa2dde03dcb4a9279c982182ee8254ae96e7a6626fe4c7617"
        severity = "critical"

    strings:
        $source_name = "heap_shellcode_runner_bound_weaponized" ascii
        $machine_guid = "MachineGuid" ascii wide
        $heap_create = "HeapCreate" ascii
        $heap_alloc = "HeapAlloc" ascii
        $rtl_move = "RtlMoveMemory" ascii
        $create_thread = "CreateThread" ascii
        $marshal = "marshal" ascii
        $lzma = "lzma" ascii

    condition:
        filesize < 5MB and
        $source_name and
        $machine_guid and
        2 of ($heap_create, $heap_alloc, $rtl_move, $create_thread) and
        1 of ($marshal, $lzma)
}
```

### YARA: AhsayCBS Reflective DLL (C2 Implant)

Detects the reflectively loaded x64 DLL used as the C2 implant, based on the C2 URL and DNS-over-HTTPS fragments.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac 0 (attempt 2: fixed unreferenced $bcrypt string). Keys on the C2 URL string and DoH resolver fragments from published DLL string analysis. FP: none expected (unique C2 domain). -->
```yara
rule Malware_AhsayCBS_Reflective_DLL_C2
{
    meta:
        description = "Detects the AhsayCBS reflectively loaded x64 DLL C2 implant via C2 URL and DoH resolver strings"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://www.huntress.com/blog/ahsaycbs-webshells"
        hash = "bb2472cf5dc7e5c94216d355bf84fba2c8d088d03d61a1ac0d78639049cf5e1f"
        severity = "critical"

    strings:
        $c2_url = "creepexplosiondarknight.com/d" ascii wide
        $doh_quad9 = "dns.quad9.net" ascii wide
        $doh_google = "dns.google" ascii wide
        $machine_guid = "MachineGuid" ascii wide
        $bcrypt = "bcrypt" ascii

    condition:
        filesize < 2MB and
        $c2_url and
        1 of ($doh_quad9, $doh_google) and
        $machine_guid and
        $bcrypt
}
```

### YARA: AhsayCBS JSP PNG Steganography Loader

Detects the AhsayCBS.jsp PNG steganography loader based on its hardcoded AES key and application context attribute.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac 0. Keys on the hardcoded AES key and QuCh attribute. Published values from Huntress analysis. FP: none expected (unique key+attribute combination). -->
```yara
rule Webshell_AhsayCBS_PNG_Stego_Loader
{
    meta:
        description = "Detects the AhsayCBS.jsp PNG steganography web shell via hardcoded AES key and context attribute"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://www.huntress.com/blog/ahsaycbs-webshells"
        hash = "6c7a4061bcf08df5fe4a49d37442dc650d751be1a91a8bc802edff213e4d5e61"
        severity = "critical"

    strings:
        $aes_key = "3c6e0b8a9c15224a" ascii
        $attr = "QuCh" ascii
        $lsb = "getRGB" ascii
        $classloader = "ClassLoader" ascii
        $aes = "AES" ascii

    condition:
        filesize < 100KB and
        $aes_key and
        $attr and
        2 of ($lsb, $classloader, $aes)
}
```

### YARA: AhsayCBS nsmind.jsp Signed API Web Shell

Detects the nsmind.jsp signed-API web shell via its hardcoded authentication tokens.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac 0. Keys on the published API key and HMAC secret from Huntress. FP: none expected (unique key values). -->
```yara
rule Webshell_AhsayCBS_Nsmind_Signed_API
{
    meta:
        description = "Detects the nsmind.jsp signed-API web shell via hardcoded API key and HMAC secret"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://www.huntress.com/blog/ahsaycbs-webshells"
        hash = "6c695baad1d81ed49194d07a79381292c0466208ff1a9862c0c55f971d6a409f"
        severity = "critical"

    strings:
        $api_key = "NS_f1ChEBy4SCYGyIDkYcsWOivwtWyXt5il" ascii
        $hmac_secret = "NS_aAXMPsB8zsMdkVbjTp6zicnj9w8Hkaew" ascii
        $x_auth = "X-Auth-Token" ascii
        $x_sig = "X-Signature" ascii
        $hmac_sha = "HmacSHA256" ascii

    condition:
        filesize < 100KB and
        1 of ($api_key, $hmac_secret) and
        2 of ($x_auth, $x_sig, $hmac_sha)
}
```

## Lessons Learned

1. **Backup infrastructure is a prime target.** AhsayCBS servers hold credentials for storage, encryption keys, and often have broad network access. Attackers know that backup servers are high-value, low-visibility targets in many environments.

2. **First patches can be incomplete.** Ahsay's initial hotfixes (v10.3.4.0, v9.15.2.59) did not fully address the vulnerabilities. Organizations that patched early may still have been vulnerable. Always verify that the installed version matches the vendor's confirmed-fixed build.

3. **Patching is not remediation after compromise.** The attackers deployed multiple independent persistence mechanisms (web shells, services, scheduled tasks, Run keys, accounts). Patching closes the front door but leaves all backdoors intact. If compromise is suspected, full re-imaging and credential rotation are required.

4. **Environmental keying defeats automated analysis.** The Python backdoor's use of MachineGuid-derived marker files means it will appear inert in any sandbox or analyst system, potentially leading analysts to dismiss it. Detection must focus on the deployment pattern (Python under SYSTEM profile) rather than detonation.

## Sources

- [Huntress - Threat Actors Exploit Critical AhsayCBS Flaws](https://www.huntress.com/blog/ahsaycbs-flaws-exploit) -- primary technical analysis of CVE exploitation, miner deployment, IOCs
- [Huntress - Inside an AhsayCBS Intrusion](https://www.huntress.com/blog/ahsaycbs-webshells) -- detailed follow-up with web shell analysis, Python implant reverse engineering, full IOC list
- [The Hacker News - Attackers Exploit AhsayCBS Flaws](https://thehackernews.com/2026/11/attackers-exploit-ahsaycbs-flaws-to.html) -- news coverage synthesizing Huntress and Ahsay findings
- [Bitdefender - Technical Advisory: AhsayCBS Exploitation Chain](https://www.bitdefender.com/blog/businessinsights/technical-advisory-ahsaycbs-exploitation-chain-cve-2026-105133-cve-2026-105134) -- MDR incident details, additional C2 IPs, CVSS analysis
- [CISA KEV Catalog Update](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42944e2) -- both CVEs added to KEV on 2026-10-14
- [BrainDetox - AhsayCBS CVE-2026-105133 Fix Status](https://braindetox.kr/en/posts/ahsaycbs_cve_2026_105133_105134_update.html) -- fixed version tracking and KEV status

<!-- revision: v1.1 — added SID placeholder caveat to Detection Rules preamble; fixed Snort flow spacing; extracted standalone rule files -->

---
*Report generated by Actioner*
