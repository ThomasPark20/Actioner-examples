# Technical Analysis Report: SPECTRE Backdoor -- UAT-10147 (2026-08-22)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-22
Version: FINAL
<!-- revision: 2026-08-22 post-critic review. DROPPED Snort and Suricata C2 registration beacon rules (/api/v1/register is a ubiquitous REST endpoint, extreme FP at strict leniency). DOWNGRADED Sigma Defender-exclusion rule from high to medium (behavioral TTP, not SPECTRE-specific). FIXED ATT&CK T1027.001 (Binary Padding) to T1027 (Obfuscated Files) and added T1027.007 (Dynamic API Resolution) for DJB2-variant PEB hash walking. ADDED coverage-gap caveat to Scheduled Task Persistence rule (PowerShell/COM/GPO blind spot). ADDED educational-rootkit FP note to YARA Linux rootkit rule. FIXED hash descriptions: noted undifferentiated sourcing, updated labels. -->

## Executive Summary

UAT-10147 is a Chinese-speaking, financially motivated intrusion group discovered by Cisco Talos in early 2026 after an operational security failure left their staging server's directory publicly accessible. The exposed infrastructure revealed a custom cross-platform backdoor called SPECTRE, an extensive toolkit spanning privilege escalation exploits, web shells, rootkits, and commodity RATs, and a target list containing approximately 170,000 URLs across government, education, media, technology, and gaming sectors in Brazil, Bolivia, China, Canada, and Vietnam.

SPECTRE supports 45 commands on Windows (including BYOVD-based EDR neutralization, process injection, credential theft, and in-memory .NET execution) and 29 commands on Linux (including a companion kernel rootkit that hooks syscalls for process/connection hiding). The actor also integrates agentic AI tools -- PentestGPT and DeepAudit -- into post-compromise operations for automated vulnerability scanning, exploit generation, and semi-autonomous payload deployment via ViewState deserialization attacks. The campaign exploits known vulnerabilities in Zimbra, AjaxPro, Nacos, and Telerik UI to gain initial access to internet-facing web servers.

## Background: Targeted Infrastructure

UAT-10147 targets internet-exposed Windows IIS and Linux web servers running vulnerable applications. The actor operates at scale: recovered infrastructure contained 17 target files of approximately 10,000 URLs each (totaling roughly 170,000), organized by geographic region and sector. Victims span government agencies, educational institutions, media organizations, technology companies, and gaming businesses. The campaign represents a convergence of traditional cybercrime (SEO fraud via BadIIS, credential theft) with advanced implant capabilities (kernel rootkits, BYOVD EDR bypass) and AI-assisted operations.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Late 2025 | SPECTRE development begins (PDB timestamps reference 2025-11-21 build dates) |
| Early 2026 | Talos discovers compromised system communicating with staging server at 139.180.197[.]150 |
| Early 2026 | OPSEC failure exposes open directory on C2 server, revealing full toolkit and target lists |
| 2026-08-19 | Talos publishes Part 1: SPECTRE cross-platform implant with rootkit and BYOVD analysis |
| 2026-08-21 | Talos publishes Part 2: UAT-10147 agentic AI integration into post-compromise operations |

## Root Cause: Exploitation of Public-Facing Applications

UAT-10147 gains initial access by exploiting known vulnerabilities in internet-facing web applications:

- **CVE-2022-27925** -- Zimbra Collaboration Suite unauthenticated RCE
- **CVE-2021-23758** -- AjaxPro .NET deserialization RCE
- **CVE-2021-29441 / CVE-2021-29442** -- Nacos framework arbitrary code execution via ScriptEngineFactory
- **CVE-2019-18935** -- Telerik UI ASP.NET AJAX JSON deserialization; the actor uses a customized weaponized PoC with file upload capability

Post-exploitation on Windows IIS follows a scripted sequence: privilege escalation via EfsPotato or other Potato-family exploits abusing SeImpersonatePrivilege, Defender exclusion additions for IIS directories, backdoor deployment, rogue admin account creation, and scheduled task persistence. On Linux, initial web shell access is followed by local privilege escalation exploits before installing additional implants.

## Technical Analysis of the Malicious Payload

### 1. SPECTRE Windows Implant (45 Commands)

The Windows variant of SPECTRE is a C-language implant with extensive anti-analysis, string encryption, and EDR bypass capabilities. Notable features:

**Anti-Analysis Engine:** A weighted scoring system evaluates multiple environmental factors (process name blocklists, RAM capacity, CPU core count, disk space, sleep acceleration, sandbox hostname/username patterns) against a threshold of 50 points. Exceeding the threshold triggers self-termination.

**String Encryption:** All strings are encrypted at compile time using a per-string xorshift32 PRNG scheme with unique 32-bit seeds. Decryption occurs via thread-local storage at runtime, preventing plaintext exposure in `.text` or `.rdata` sections.

**API Resolution:** Windows API calls are resolved at runtime via PEB hash walking using a DJB2 variant algorithm, eliminating IAT exposure.

**Command Categories:**
- **File Operations (unencrypted):** `shell`, `pwd`, `cd`, `ls`, `cat`, `mkdir`, `rm`, `cp`, `mv`, `download`, `upload`
- **Reconnaissance (unencrypted):** `ps`, `env`, `sysinfo`, `whoami`, `netinfo`, `reg`
- **Process Management (unencrypted):** `kill`, `screenshot`, `timestomp`, `exit`, `selfdel`, `getprivs`, `rev2self`
- **Encrypted Commands (21):** `regset`, `inject` (DLL injection into svchost.exe), `s-nject` (shellcode injection), `getsystem` (named pipe impersonation), `steal_token`, `make_token`, `keylog_start`/`stop`/`dump`, `hashdump`, `chromedump`, `vaultdump`, `execute_assembly`, `earlybird` (APC injection), `hollow` (process hollowing into RuntimeBroker.exe), `byovd_load`/`unload`/`verify`, `edr_kill`, `callbacks`, `proc_hide`, `auto_protect`

### 2. SPECTRE Linux Implant (29 Commands) and Specter Rootkit

The Linux variant supports 29 commands including standard file operations, reconnaissance, and rootkit management (`rootkit_load`, `rootkit_hide`, `rootkit_root`, `rootkit_hide_mod`, `rootkit_status`, `rootkit_persist`, `rootkit_unload`).

**Specter Rootkit (acpi_pad.ko):** A kernel module disguised as a legitimate ACPI module. It uses ftrace instrumentation (`FTRACE_OPS_FL_IPMODIFY`) to hook kernel functions:
- `hooked_tcp6_seq_show` / `hooked_tcp4_seq_show` -- hide network connections from `/proc/net/tcp`
- `hooked_tkill` / `hooked_tgkill` / `hooked_kill` -- intercept signals for IPC using magic PID 0x7A69 (31337) and real-time signals 35, 36, 37, 62
- `hooked_getdents64` -- hide files and processes from directory listings

**Rootkit IPC via signals:** Signal 37 to magic PID 0x7A69 triggers UID 0 overwrite (instant root). Other signals control process hiding and module concealment.

**Persistence:** Systemd unit `hardware-monitor.service` ordered `Before=sysinit.target` for pre-security-initialization execution.

### 3. C2 Infrastructure

- **Protocol:** HTTP POST
- **Registration:** `POST /api/v1/register`
- **Data exfiltration:** `POST /api/v1/output`
- **Payload format:** JSON (Linux variant)
- **Configuration storage (Windows):** NTFS Alternate Data Stream at `C:\Windows\System32\drivers\etc\hosts:cache` -- allows dynamic C2 updates without binary recompilation
- **Fallback:** Hardcoded C2 domains in binaries
- **Staging server:** 139.180.197[.]150:54321
- **Download server:** adminapi[.]tippusoni[.]in
- **Exfiltration sink:** webhook[.]site (legitimate SaaS abused for OOB callbacks)
- **Config polling:** Attacker-controlled Nacos configuration server

### 4. BYOVD EDR Neutralization

SPECTRE deploys vulnerable kernel drivers to achieve arbitrary kernel read/write:

- **RTCore64.sys** (MSI) -- CVE-2019-16098
- **DBUtil_2_3.sys** (Dell) -- CVE-2021-21551

Using these primitives, the implant unlinks kernel callbacks by walking doubly-linked lists of:
- `PspCreateProcessNotifyRoutine`
- `PspCreateThreadNotifyRoutine`
- `PspLoadImageNotifyRoutine`

**Neutralized EDR products:** CrowdStrike Falcon, SentinelOne, Microsoft Defender.

### 5. Anti-Forensics / Evasion Techniques

- **Timestomping** (`timestomp` command) on dropped files
- **Self-deletion** (`selfdel` command) for cleanup
- **Self-hollowing** into RuntimeBroker.exe directly from `main()` to evade behavioral EDR scans
- **NTFS ADS** for C2 configuration storage (invisible to standard directory listings)
- **Web shell stealth:** Returns `404 Not Found` on failed authentication; uses `X-ID` header with token `x9` for access control
- **Rootkit-level hiding:** Network connections, processes, files, and the kernel module itself are hidden from userspace tools

### 6. AI-Assisted Operations

UAT-10147 integrates agentic AI into post-compromise workflows:

- **PentestGPT** -- Automated web server scanning and PoC exploit execution
- **DeepAudit** -- Source code vulnerability scanning
- **AI-generated playbooks:** Comprehensive ASP.NET ViewState deserialization RCE guides including MachineKey extraction, ysoserial payload generation (TypeConfuseDelegate gadget chain), Python automation scripts for validation and deployment
- **Automated scripts:** `check_paths.py` (OOB recon via webhook[.]site), `deploy_implant.py` (ViewState-based SPECTRE delivery), `deploy_shell.py` (two-stage ASHX web shell deployment), `exfil.py` (three-stage PowerShell reconnaissance)
- **Operational case records:** Structured logs with hostname, IP, exploited page path, .NET runtime version, and MachineKey values

Evidence of AI-generated code in the Specter rootkit source includes product-specification-format comments ("Write a rootkit with features..."), uniform decorator formatting, pedagogical explanations of basic kernel concepts, and exhaustive multi-approach presentation patterns.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| Platform | Path / Artifact | Description |
|----------|----------------|-------------|
| Windows | `C:\Windows\System32\drivers\etc\hosts:cache` | NTFS ADS C2 configuration storage |
| Windows | `C:\ProgramData\dll.zip` | SPECTRE implant archive |
| Windows | `C:\ProgramData\user.bat` | Post-exploitation automation script |
| Windows | `sss.ashx`, `up.ashx` | ASHX web shells |
| Windows | `prcc1.rar` | Renamed EfsPotato privilege escalation tool |
| Windows | `[10 digits].[7 digits].dll` | Random DLL naming convention |
| Windows | `svchosts.exe` (note typo) | QuasarRAT binary |
| Linux | `acpi_pad.ko` | Specter rootkit kernel module (disguised) |
| Linux | `hardware-monitor.service` | Systemd persistence unit |

**PDB Development Paths (attribution artifacts):**
- `C:\Users\Administrator\Desktop\2025-11-21 (...)\dll\Release\demo.pdb`
- `C:\Users\Administrator\Desktop\2025-11-21 (...)\dll\x64\Release\demo.pdb`
- `C:\Users\iis\Desktop\AI\EfsPotatoCpp\x64\Release\EfsPotato.pdb`
- `C:\Users\Intel\Desktop\AI\EfsPotatoCPP\x64\Debug\EfsPotato.pdb`
- `C:\Users\Administrator\Desktop\...\svchost\x64\Release\service.pdb`

**Named Pipe:** `\\.\pipe\spectre_<tid>` (privilege escalation via impersonation)

**Registry:** `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` (exclusion additions for IIS dirs)

**Scheduled Task:** `Google Chrome Start` (highest privileges, logon trigger)

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 139.180.197[.]150 | Staging/download server |
| IP | 27.124.2[.]46 | C2 infrastructure |
| IP | 27.124.2[.]48 | C2 infrastructure |
| IP | 27.124.2[.]52 | C2 infrastructure |
| Domain | jyzyps[.]com | SEO/C2 domain |
| Domain | mma888[.]cc | Redirect domain |
| Domain | healthsave[.]net | Staging domain |
| Domain | vip8888vn[.]xyz | Vietnamese-targeted SEO domain |
| Domain | niupilao[.]vip | C2 domain |
| Domain | adminapi[.]tippusoni[.]in | Download/C2 server |
| URL | hxxps://js[.]jyzyps[.]com/js/vnnb[.]js | Malicious JavaScript payload |
| URL | hxxps://js[.]jyzyps[.]com/js/nb[.]js | Malicious JavaScript payload |
| URL | hxxp://vn[.]mma888[.]cc/ | Redirect target |
| URL | hxxp://thceshi[.]healthsave[.]net | Staging URL |
| Endpoint | `/api/v1/register` | SPECTRE C2 registration |
| Endpoint | `/api/v1/output` | SPECTRE C2 data exfiltration |

### File Hashes (SHA256)

The full IOC set (44 SHA256 hashes) is available at the [Cisco Talos IOC Repository](https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt). Representative samples:

> **Note:** The source IOC list does not attribute individual hashes to specific toolkit components. Descriptions below are generic because the Talos publication provides hashes as an undifferentiated campaign set. Where your IR triage identifies a specific binary (SPECTRE implant, web shell, rootkit module, EfsPotato, QuasarRAT), update the description accordingly.

| SHA256 | Description |
|--------|-------------|
| `008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2` | UAT-10147 campaign artifact (undifferentiated) |
| `11ccfdfb0dfe782ba0eeabaa8e65619a792f9258476a072b774ef19a5240b944` | UAT-10147 campaign artifact (undifferentiated) |
| `43124b72616ef38b0c8a07b167e971b0e4479626fb5ef2303b2ed993e21f6c4c` | UAT-10147 campaign artifact (undifferentiated) |
| `684e7ed556dcc9e2fe24fcfd73e6b9c29d7126584f87c5331c2607d39e29329f` | UAT-10147 campaign artifact (undifferentiated) |
| `830c6ca21a7da0eed436f8371c8a86baa62ab857a5478a222dd3189645d4d084` | UAT-10147 campaign artifact (undifferentiated) |
| `91d00ca46d1013c031aa8ff2e54b7b3496bac78f6147842766bffd4d32a2e042` | UAT-10147 campaign artifact (undifferentiated) |
| `b74beab9dac9ee7853b5e846eec6f778db01867b49f64d6be259ea9e19006121` | UAT-10147 campaign artifact (undifferentiated) |
| `cf0a6353f1fccf63fca02ed41eafd3da8d55f77b8b4c45666a37fa3cdc33da55` | UAT-10147 campaign artifact (undifferentiated) |
| `dd4c16c65513c3eb66691f87d5bb5595d38554395ec89be2b9e325e013ef53d5` | UAT-10147 campaign artifact (undifferentiated) |
| `dee976f262498184d746cc8305cc9e6905ad762c661df8d7daec120f14060b41` | UAT-10147 campaign artifact (undifferentiated) |

### Behavioral

- HTTP POST beaconing to `/api/v1/register` and `/api/v1/output` endpoints
- C2 configuration stored in NTFS Alternate Data Stream at `hosts:cache`
- Named pipe creation matching `\\.\pipe\spectre_*` pattern for privilege escalation
- Process hollowing into `RuntimeBroker.exe` and DLL injection into `svchost.exe`
- Signal-based IPC on Linux using magic PID 31337 (0x7A69) with real-time signals 35, 36, 37, 62
- `cmdkey.exe /list` spawned for LSASS-free credential enumeration
- Kernel callback unlinking via BYOVD arbitrary write for EDR neutralization

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of CVE-2022-27925 (Zimbra), CVE-2021-23758 (AjaxPro), CVE-2019-18935 (Telerik UI), CVE-2021-29441/29442 (Nacos) |
| T1105 | Ingress Tool Transfer | certutil downloading from adminapi[.]tippusoni[.]in; staging archives to C:\ProgramData |
| T1059.001 | PowerShell | Encoded PowerShell commands for reconnaissance, Defender exclusion bypass, file writes |
| T1055.012 | Process Hollowing | Self-hollowing into RuntimeBroker.exe; standard hollowing into svchost.exe |
| T1055.004 | Asynchronous Procedure Call | EarlyBird APC injection for pre-allocated memory shellcode delivery |
| T1134.001 | Token Impersonation/Theft | Named pipe impersonation (getsystem), steal_token, make_token commands |
| T1053.005 | Scheduled Task | "Google Chrome Start" task with highest privileges on logon |
| T1543.003 | Windows Service | Service installation via SCM for SPECTRE persistence |
| T1543.002 | Systemd Service | hardware-monitor.service ordered Before=sysinit.target |
| T1564.004 | NTFS File Attributes | C2 config stored in ADS at hosts:cache |
| T1562.001 | Disable or Modify Tools | Defender exclusion paths for IIS directories; BYOVD EDR callback unlinking |
| T1014 | Rootkit | Specter kernel module (acpi_pad.ko) hooking syscalls via ftrace |
| T1003.002 | SAM | hashdump extracting SAM/SYSTEM/SECURITY registry hives |
| T1555.003 | Credentials from Web Browsers | chromedump targeting Chrome/Edge Login Data + Local State |
| T1056.001 | Keylogging | keylog_start/stop/dump commands |
| T1078.003 | Local Accounts | Rogue admin account creation added to Administrators and RDP groups |
| T1021.001 | Remote Desktop Protocol | RDP access enabled via rogue local accounts |
| T1027 | Obfuscated Files or Information | Compile-time xorshift32 PRNG string encryption preventing plaintext exposure in binary sections |
| T1027.007 | Dynamic API Resolution | PEB hash walking via DJB2-variant algorithm to resolve Windows API calls at runtime, eliminating IAT exposure |
| T1140 | Deobfuscate/Decode Files | Base64-encoded PowerShell commands; web shell dynamic compilation |
| T1518.001 | Security Software Discovery | EDR process enumeration before BYOVD deployment |
| T1071.001 | Web Protocols | HTTP POST to /api/v1/register and /api/v1/output |
| T1041 | Exfiltration Over C2 Channel | Data exfiltration via SPECTRE C2 and webhook[.]site |

## Impact Assessment

**Breadth:** 170,000 URLs across 5 countries targeted; actual compromise count unknown but evidence of active exploitation across multiple victim organizations.

**Depth:** Full system compromise capability -- kernel-level rootkit on Linux, EDR neutralization on Windows, credential theft, persistence, and lateral movement.

**Stealth:** High -- rootkit-level hiding of processes, network connections, and files; NTFS ADS configuration storage; self-hollowing; string encryption; anti-analysis scoring engine; deceptive 404 responses from web shells.

**AI Multiplier:** Semi-autonomous offensive orchestration significantly increases the actor's throughput for exploitation at scale, with adaptive troubleshooting and iterative refinement of exploit payloads.

## Detection & Remediation

### Immediate Detection

**Windows:**
```powershell
# Check for SPECTRE ADS C2 configuration
Get-Item -Path "C:\Windows\System32\drivers\etc\hosts" -Stream * | Where-Object { $_.Stream -eq "cache" }

# Check for Defender exclusions on IIS directories
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | Where-Object { $_ -match "inetsrv" }

# Check for suspicious scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -match "Google Chrome Start" }

# Check for SPECTRE named pipes
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -match "^spectre_" }

# Check for rogue local admin accounts
Get-LocalGroupMember -Group "Administrators" | Format-Table
```

**Linux:**
```bash
# Check for disguised rootkit module
lsmod | grep acpi_pad
modinfo acpi_pad 2>/dev/null | grep -v "Intel Corporation"

# Check for persistence service
systemctl cat hardware-monitor.service 2>/dev/null

# Check for hooked functions (requires root)
cat /sys/kernel/debug/tracing/enabled_functions 2>/dev/null | grep hooked_
```

### Remediation

1. **Contain:** Isolate affected systems from the network immediately. Block C2 IPs (139.180.197[.]150, 27.124.2[.]46/48/52) and domains at the perimeter.
2. **Eradicate (Windows):** Remove NTFS ADS (`Remove-Item -Path "hosts" -Stream cache`), delete Defender exclusions, remove malicious scheduled tasks, uninstall BYOVD drivers, remove web shells from IIS webroots, delete rogue accounts.
3. **Eradicate (Linux):** Unload rootkit module (`rmmod acpi_pad` if possible), remove `hardware-monitor.service`, check for Meterpreter/NoodleRAT persistence, verify `/etc/passwd` integrity (CVE-2015-3246 may corrupt it).
4. **Recover:** Rebuild compromised servers from known-good images. Rotate all credentials that were accessible from compromised systems, especially those extracted via hashdump/chromedump.
5. **Rotate secrets:** Change all ASP.NET MachineKeys, database credentials, service account passwords, and API keys accessible from compromised IIS servers.

### Long-Term Hardening

- Patch internet-facing applications promptly -- UAT-10147 exclusively exploits known vulnerabilities with available patches (some dating to 2019-2022)
- Restrict IIS application pool identities and remove unnecessary SeImpersonatePrivilege grants
- Deploy kernel-mode driver blocklists (Microsoft's WDAC driver blocklist) to prevent RTCore64.sys and DBUtil_2_3.sys loading
- Monitor for NTFS Alternate Data Stream creation on system files
- Implement allowlisting for kernel module loading on Linux systems
- Monitor for webhook[.]site and similar legitimate SaaS services being used for data exfiltration

## Detection Rules

These detections target specific artifacts from the UAT-10147/SPECTRE campaign at advisory-specific altitude with strict matching. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify each rule against your telemetry pipeline before production deployment. Rule inventory: 5 Sigma, 2 YARA, 1 Suricata (DNS), 0 Snort. The C2 registration beacon rules (Snort and Suricata) were dropped during review -- `/api/v1/register` is a ubiquitous REST endpoint that would produce extreme false-positive volume at strict leniency.

### Sigma: SPECTRE NTFS ADS C2 Configuration Storage

Detects file write to the `hosts:cache` NTFS Alternate Data Stream used by SPECTRE for dynamic C2 configuration storage.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch blocked by proxy, not a rule error); splunk convert exit 0; log_scale convert exit 0. TargetFilename endswith match on hosts:cache is highly specific — no known legitimate use of this ADS path. -->

```yaml
title: SPECTRE Backdoor NTFS ADS C2 Configuration Storage
id: 7c3a92e1-4f8b-4d6e-a1c3-9b5e7d2f0a84
status: experimental
description: >
    Detects file write to an NTFS Alternate Data Stream at the Windows hosts file
    path (hosts:cache) used by the SPECTRE backdoor to store C2 configuration,
    enabling dynamic updates without recompilation.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/22
tags:
    - attack.t1564.004
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\drivers\etc\hosts:cache'
    condition: selection
falsepositives:
    - Unknown
level: high
```

### Sigma: Certutil Download from UAT-10147 C2 Infrastructure

Detects certutil downloading files from the adminapi[.]tippusoni[.]in staging domain used by UAT-10147.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (proxy); splunk convert exit 0; log_scale convert exit 0. IOC-keyed rule on a campaign-specific domain. Will not fire once infrastructure rotates — pair with behavioral rules or update IOCs as new infrastructure is identified. -->

```yaml
title: Certutil Download from UAT-10147 C2 Infrastructure
id: b8d4e6f2-1a3c-4e7b-9d5f-2c8a0b6e4d17
status: experimental
description: >
    Detects certutil.exe downloading files from the adminapi.tippusoni.in domain,
    a known UAT-10147 staging and C2 server used to deliver SPECTRE implants and
    tooling archives.
references:
    - https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations
author: Actioner
date: 2026/08/22
tags:
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains|all:
            - 'urlcache'
            - 'tippusoni.in'
    condition: selection
falsepositives:
    - Unknown
level: critical
```

### Sigma: Windows Defender Exclusion for IIS Directory

Supporting behavioral rule. Detects addition of IIS inetsrv directories to Defender exclusion paths, a defense evasion step observed before SPECTRE and BadIIS deployment but not SPECTRE-specific -- legitimate IIS administrators may add Defender exclusions for performance tuning. Scope to servers where IIS exclusion changes are not routine.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked (proxy); splunk convert exit 0; log_scale convert exit 0; splunk_windows pipeline convert exit 0. Medium confidence because legitimate IIS administrators may add Defender exclusions for performance tuning — but the combination with inetsrv path is more specific. FP risk in environments with scripted IIS deployments. -->

```yaml
title: Windows Defender Exclusion Path for IIS Directory
id: e5a1c3d7-9b2f-4e6a-8d0c-3f7b5a1e9c42
status: experimental
description: >
    Detects addition of IIS inetsrv directories to Windows Defender exclusion paths
    via PowerShell Add-MpPreference or registry modification, a defense evasion
    technique used by UAT-10147 before deploying SPECTRE and BadIIS implants.
references:
    - https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations
author: Actioner
date: 2026/08/22
tags:
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'Add-MpPreference'
            - '-ExclusionPath'
            - 'inetsrv'
    selection_reg:
        Image|endswith: '\reg.exe'
        CommandLine|contains|all:
            - 'Defender\Exclusions\Paths'
            - 'inetsrv'
    condition: selection_powershell or selection_reg
falsepositives:
    - Legitimate IIS administrators managing Defender exclusions for performance tuning
    - Scripted IIS deployment automation
level: medium
```

### Sigma: SPECTRE Backdoor Named Pipe Creation

Detects named pipe creation with the `spectre_` prefix, used by the SPECTRE getsystem command for privilege escalation via ImpersonateNamedPipeClient.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (proxy); splunk convert exit 0; log_scale convert exit 0. Pipe name prefix is highly distinctive — no legitimate software uses spectre_ as a pipe name prefix. Requires Sysmon EID 17/18 or equivalent pipe creation logging. -->

```yaml
title: SPECTRE Backdoor Named Pipe Creation
id: a2f9d4b6-3e1c-4a8d-b7c5-6d0e9f2a1b38
status: experimental
description: >
    Detects creation of named pipes with the spectre_ prefix, used by the SPECTRE
    backdoor getsystem command for privilege escalation via ImpersonateNamedPipeClient.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/22
tags:
    - attack.t1134.001
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|startswith: '\spectre_'
    condition: selection
falsepositives:
    - Unlikely in production environments
level: critical
```

### Sigma: UAT-10147 Scheduled Task Persistence via Google Chrome Start

Detects creation of a scheduled task named "Google Chrome Start" used by UAT-10147 for persistence with highest privileges. Does not cover task creation via PowerShell, COM, or Group Policy -- supplement with Windows Security EID 4698 monitoring on TaskName.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (proxy); splunk convert exit 0; log_scale convert exit 0. Task name is specific to the campaign. Theoretical FP from legitimate Chrome enterprise deployment using this exact name, but unlikely as Chrome does not use this task name by default. Coverage gap: only catches schtasks.exe process creation — not PowerShell New-ScheduledTask, COM ITaskService, or GPO-based task creation. Supplement with EID 4698 monitoring. -->

```yaml
title: UAT-10147 Scheduled Task Persistence via Google Chrome Start
id: c6b8e0d3-5a2f-4c9e-b1d7-8e3a4f6c2d59
status: experimental
description: >
    Detects creation of a scheduled task named Google Chrome Start, used by
    UAT-10147 to establish persistence with highest privileges on user logon,
    masquerading as a legitimate Chrome process.
references:
    - https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations
author: Actioner
date: 2026/08/22
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: 'Google Chrome Start'
    condition: selection
falsepositives:
    - Legitimate Chrome enterprise deployment using this exact task name
level: high
```

### Suricata: DNS Query to UAT-10147 C2 Domain

Detects DNS queries resolving the jyzyps[.]com domain, a confirmed UAT-10147 C2 and SEO fraud domain hosting malicious JavaScript payloads.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: Suricata not installed. Structural check: valid Suricata syntax with dns protocol, dns.query sticky buffer, endswith modifier for subdomain coverage, nocase, all required fields present. High confidence — domain is a campaign-specific IOC with no legitimate use. Will not fire once domain is burned; update with new IOCs as they are identified. -->

```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UAT-10147 C2 Domain jyzyps.com"; flow:to_server; dns.query; content:"jyzyps.com"; nocase; endswith; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-22; sid:2200002; rev:1;)
```

### YARA: UAT-10147 SPECTRE Windows Campaign Artifacts

Detects UAT-10147 Windows artifacts via attacker-compiled EfsPotato PDB paths and SPECTRE-specific operational strings (named pipe pattern, C2 endpoints, ADS config path).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. PDB paths Desktop\AI\EfsPotatoCpp and Desktop\AI\EfsPotatoCPP are unique to the attacker's build environment — no legitimate software produces these. svchost service PDB requires co-occurrence with C2/pipe/ADS indicators to reduce FP from other custom svchost projects. PE MZ header + 10MB filesize guard. YARA backslash escaping verified: \\x64 produces literal \x64 (not hex 0x64). Sample test not performed — binary header check (MZ) prevents plaintext test file matching. -->

```yara
rule UAT10147_SPECTRE_Windows_Campaign_Artifacts
{
    meta:
        description = "Detects UAT-10147 campaign artifacts including SPECTRE backdoor C2 indicators and attacker-compiled tooling PDB paths"
        author = "Actioner"
        date = "2026-08-22"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "critical"

    strings:
        // Attacker-compiled EfsPotato privilege escalation PDB paths
        $pdb1 = "Desktop\\AI\\EfsPotatoCpp\\x64\\Release\\EfsPotato.pdb" ascii
        $pdb2 = "Desktop\\AI\\EfsPotatoCPP\\x64\\Debug\\EfsPotato.pdb" ascii

        // SPECTRE service installer PDB path
        $pdb3 = "svchost\\x64\\Release\\service.pdb" ascii

        // SPECTRE C2 endpoint strings
        $c2a = "/api/v1/register" ascii
        $c2b = "/api/v1/output" ascii

        // SPECTRE named pipe for privilege escalation
        $pipe = "\\\\.\\pipe\\spectre_" ascii

        // SPECTRE NTFS ADS C2 configuration path
        $ads = "drivers\\etc\\hosts:cache" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($pdb1, $pdb2) or
            ($pdb3 and 1 of ($c2*, $pipe, $ads)) or
            ($pipe and ($c2a or $c2b)) or
            ($ads and ($c2a or $c2b))
        )
}
```

### YARA: Specter Linux Kernel Rootkit

Detects the Specter Linux rootkit kernel module via its distinctive `hooked_*` syscall function names used for process hiding, network connection concealment, and signal-based IPC interception. May match educational rootkit projects that reuse identical hooked function naming.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0 (both rules compiled in single file). ELF header check (0x464C457F) + 5MB filesize guard. hooked_tcp6_seq_show / hooked_tcp4_seq_show / hooked_tkill / hooked_tgkill / hooked_kill / hooked_getdents64 are distinctive function names unique to this rootkit — the hooked_ prefix combined with specific syscall names has no benign counterpart. Requires 3-of-6 match. Caveat: educational/tutorial rootkit projects may reuse identical hooked function naming conventions and trigger this rule on compiled .ko files. Sample test not performed — ELF header requirement prevents plaintext test. -->

```yara
rule UAT10147_Specter_Linux_Rootkit
{
    meta:
        description = "Detects the Specter Linux kernel rootkit module deployed by UAT-10147 via distinctive hooked syscall function names used for process hiding and network connection concealment"
        author = "Actioner"
        date = "2026-08-22"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "critical"

    strings:
        $hook1 = "hooked_tcp6_seq_show" ascii
        $hook2 = "hooked_tcp4_seq_show" ascii
        $hook3 = "hooked_tkill" ascii
        $hook4 = "hooked_tgkill" ascii
        $hook5 = "hooked_kill" ascii
        $hook6 = "hooked_getdents64" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        3 of ($hook*)
}
```

## Lessons Learned

1. **Known vulnerabilities at scale remain the primary initial access vector.** UAT-10147 exclusively exploits patched vulnerabilities (some from 2019), demonstrating that unpatched internet-facing applications remain the highest-leverage attack surface. Organizations that patch promptly would have been immune to every observed initial access technique.

2. **AI is lowering the barrier for sophisticated post-compromise operations.** The integration of PentestGPT and DeepAudit, combined with AI-generated exploitation playbooks, enables a financially motivated group to operate at a sophistication level previously associated with state-sponsored actors. The AI-generated Specter rootkit source code demonstrates that complex kernel-level implants can be produced with AI assistance.

3. **BYOVD is an escalating threat to endpoint security.** SPECTRE's ability to neutralize CrowdStrike, SentinelOne, and Defender via kernel callback unlinking underscores the need for driver-level blocklisting (WDAC/HVCI) as a mandatory hardening step, not an optional enhancement.

4. **Cross-platform capability is becoming standard.** SPECTRE's Windows and Linux variants share a unified C2 protocol, reflecting the reality that modern infrastructure spans both platforms. Detection strategies must cover both operating systems with equal rigor.

5. **OPSEC failures remain a critical intelligence source.** The exposed open directory on 139.180.197[.]150 provided unprecedented visibility into the actor's toolkit, AI workflows, target lists, and operational procedures, enabling comprehensive detection development that would otherwise require reverse engineering of recovered samples.

## Sources

- [Cisco Talos - UAT-10147 deploys SPECTRE](https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/) -- Primary technical analysis of the SPECTRE cross-platform implant, Specter rootkit, and BYOVD capabilities
- [Cisco Talos - UAT-10147 Agentic AI Integration](https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations) -- Primary analysis of AI-assisted post-compromise operations, exploitation workflows, and infrastructure details
- [CyberInsider - Chinese Hackers Use AI to Automate Attacks on 170,000 Servers](https://cyberinsider.com/chinese-hackers-use-ai-to-automate-attacks-on-170000-servers/) -- Third-party reporting on campaign scope, victimology, and AI integration
- [Cisco Talos IOC Repository](https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt) -- Full IOC set including 44 SHA256 hashes, domains, and IP addresses

---
*Report generated by Actioner*
