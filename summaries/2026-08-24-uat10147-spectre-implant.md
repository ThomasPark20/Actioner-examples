# Technical Analysis Report: UAT-10147 / SPECTRE Cross-Platform Implant (2026-08-24)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-24
Version: 1.1

## Executive Summary

UAT-10147 is a Chinese-speaking threat actor deploying SPECTRE, a sophisticated cross-platform backdoor targeting internet-facing IIS and Linux servers. First observed in April 2026, the campaign combines SEO fraud monetization (via BadIIS web shells) with deep post-exploitation capabilities including a 45-command Windows implant, a 29-command Linux implant, kernel-level rootkit persistence (Specter), and BYOVD-based EDR neutralization using RTCore64.sys (CVE-2019-16098) and DBUtil_2_3.sys (CVE-2021-21551). The actor exploits known vulnerabilities (Zimbra CVE-2022-27925, Telerik CVE-2019-18935, AjaxPro CVE-2021-23758, Nacos CVE-2021-29441/CVE-2021-29442) for initial access and employs AI-assisted tooling (PentestGPT, DeepAudit) for reconnaissance and exploit scaling. Victims span education, media, technology, and gaming sectors across Brazil, Bolivia, China, Canada, Vietnam, the U.S., India, the U.K., Germany, and the Netherlands, with Vietnamese internet users as a primary target for SEO manipulation.

## Background: SPECTRE Implant and UAT-10147

SPECTRE is a custom C-language backdoor developed by UAT-10147 for both Windows and Linux platforms. The Windows variant employs extensive obfuscation including xorshift32 PRNG-based per-string encryption, DJB2-variant API hash resolution via PEB walking, and anti-sandbox scoring (50-point self-termination threshold). The Linux variant is statically linked as an ELF x86-64 binary. Supporting the implant is the Specter kernel rootkit for Linux (leveraging ftrace hooking) and a BYOVD module for Windows that unlinks EDR kernel callbacks from doubly-linked lists. The actor's PDB paths contain Chinese-language strings and the QuasarRAT campaign ID contains the derogatory Chinese phrase directed at Vietnamese targets, confirming Chinese-language attribution. Evidence of AI-assisted development includes the `Desktop\AI\` folder path in PDB strings, pedagogical source code comments, and deployment of PentestGPT and DeepAudit on C2 infrastructure.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2022-2025 | Exploitation of known CVEs (Zimbra, Telerik, AjaxPro, Nacos) for initial server access |
| April 2026 | First observed deployment of SPECTRE implant |
| August 2026 | Cisco Talos publishes comprehensive analysis of UAT-10147 operations |

## Root Cause: Exploitation of Internet-Facing Servers

UAT-10147 gains initial access through exploitation of publicly disclosed vulnerabilities in internet-facing web servers:

- **CVE-2022-27925** - Zimbra Collaboration Suite directory traversal
- **CVE-2021-23758** - AjaxPro.NET deserialization
- **CVE-2019-18935** - Telerik UI for ASP.NET AJAX deserialization
- **CVE-2021-29441 / CVE-2021-29442** - Alibaba Nacos authentication bypass

The actor deploys PentestGPT (an open-source autonomous pentesting framework) and DeepAudit (an AI vulnerability scanner) on their C2 server to scan web servers and execute proof-of-concept exploits at scale, processing 170,000 URLs split into 17 files of approximately 10,000 URLs each.

## Technical Analysis of the Malicious Payload

### 1. Initial Access and Web Shell Deployment

After exploiting server vulnerabilities, UAT-10147 deploys a two-layer web shell architecture on IIS servers:

- **BadIIS/ASHX web shells**: C#/.NET web shells authenticated via the `X-ID` HTTP header with token value `x9` (fallback: `v` parameter). The `SeoEngineHandler` class hijacks the IIS request pipeline using reflection to serve fabricated content to search crawlers while delivering malicious JavaScript to targeted users (specifically Vietnamese users via Coc Coc browser targeting).
- **Web shell commands**: 0=sysinfo, 1=execute command, 2=read file, 3=write file, 4=download file, 5=directory listing.
- **Payload delivery**: Batch scripts using `certutil` for remote payload download, Microsoft Defender exclusion configuration, and payload deletion for anti-forensics.
- **ViewState exploitation**: ASP.NET ViewState deserialization using `badsecrets` library for exposed MachineKey discovery and `ysoserial.net` for malicious payload generation.

### 2. SPECTRE Implant (Windows)

The Windows SPECTRE implant is written in C with heavy custom obfuscation:

**Obfuscation:**
- xorshift32 PRNG for per-string encryption with unique 32-bit seeds per string
- Compile-time encryption with thread-local-storage decryption
- API resolution via PEB hash walking with DJB2 variant

**Anti-Sandbox (50-point threshold):**
- Process name blocklists
- RAM capacity detection
- CPU core count checks
- Disk space evaluation
- Sleep acceleration detection
- Sandbox hostname/username recognition

**Execution:**
- Self-hollowing targeting `RuntimeBroker.exe` on startup
- Process hollowing targeting `svchost.exe`
- APC EarlyBird injection
- Named pipe communication: `\\.\pipe\spectre_<tid>`

**45 commands** (24 plaintext + 21 encrypted):
- Plaintext: `shell`, `pwd`, `cd`, `ls`, `cat`, `mkdir`, `rm`, `cp`, `mv`, `download`, `upload`, `ps`, `kill`, `env`, `sleep`, `sysinfo`, `screenshot`, `whoami`, `netinfo`, `timestomp`, `rev2self`, `getprivs`, `selfdel`, `exit`
- Encrypted: `regset`, `inject`, `s-nject`, `getsystem`, `steal_token`, `make_token`, `earlybird`, `hollow`, `keylog_start`, `keylog_stop`, `keylog_dump`, `hashdump`, `chromedump`, `execute_assembly`, `vaultdump`, `byovd_load`, `byovd_unload`, `edr_kill`, `callbacks`, `proc_hide`, `byovd_verify`, `auto_protect`

**Persistence:**
- NTFS Alternate Data Stream for C2 configuration: `C:\Windows\System32\drivers\etc\hosts:cache`
- Scheduled task: "Google Chrome Start"

**BYOVD EDR Neutralization:**
1. Downloads vulnerable driver from C2
2. Decodes and writes to `%TEMP%`
3. Installs via SCM as transient kernel service
4. Opens IOCTL handle
5. Uses `NtQuerySystemInformation` to locate `ntoskrnl.exe`
6. References hardcoded per-build offset table for 13 Windows versions
7. Calculates kernel virtual addresses for `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine`
8. Performs targeted kernel writes to unlink EDR callbacks from doubly-linked lists
9. Targets: CrowdStrike Falcon, SentinelOne, Microsoft Defender, and other EDR vendors

**Credential Theft:**
- SAM/SYSTEM/SECURITY registry hive dumping (`HKLM\SAM\SAM`, `HKLM\SYSTEM`, `HKLM\SECURITY`)
- Chrome/Edge credential theft via DPAPI decryption
- Windows Credential Manager enumeration via `cmdkey.exe /list`
- Token theft from target PID via named pipe impersonation (`ImpersonateNamedPipeClient`)

### 3. C2 Infrastructure

**Protocol:** HTTP POST with JSON payloads to hardcoded C2 domains

**Endpoints:**
- `/api/v1/register` - Initial beacon/registration
- `/api/v1/output` - Command output exfiltration

**Configuration storage:** NTFS Alternate Data Stream at `C:\Windows\System32\drivers\etc\hosts:cache`

**Exfiltration:** Webhook-based data exfiltration over HTTPS blended with SaaS traffic; legitimate cloud configuration management service abuse for data routing.

### 4. Platform-Specific Behavior

#### Windows

- C-language implant with xorshift32 string encryption
- 45 commands including BYOVD, credential theft, process injection
- Self-hollowing into `RuntimeBroker.exe`
- Process hollowing into `svchost.exe`
- Named pipe IPC: `\\.\pipe\spectre_<tid>`
- NTFS ADS for C2 config persistence
- Privilege escalation via EfsPotato, RustPotato, GodPotato

#### Linux

- Statically-linked ELF x86-64 binary
- 29 commands including rootkit management
- Specter kernel rootkit via loadable kernel module (LKM)
- Rootkit masquerades as `acpi_pad.ko` (legitimate ACPI module)
- ftrace hooking with `FTRACE_OPS_FL_IPMODIFY` flag
- Hooked syscalls: `tcp6_seq_show`, `tcp4_seq_show`, `tkill`, `tgkill`, `kill`, `getdents64`
- Magic PID value `0x7A69` (decimal 31337) for signal-based IPC
- Systemd persistence: `hardware-monitor.service` with `Before=sysinit.target`
- Signal-based rootkit commands: Signal 37 (credential structure overwriting), Signal 62 (process hiding via PID list removal), Signal 36 (module hiding from `lsmod`)
- Privilege escalation via CVE-2022-0995, CVE-2021-3156, CVE-2015-5287, CVE-2015-3246, CVE-2010-3904, CVE-2022-0847 (Dirty Pipe)

### 5. Anti-Forensics / Evasion Techniques

- Weighted anti-sandbox scoring engine (self-terminates at 50 points)
- `timestomp` command for file timestamp manipulation
- Payload deletion after execution
- Kernel callback unlinking via BYOVD (disables EDR visibility into process/thread/image events)
- Process hiding via kernel PID list removal (rootkit Signal 62)
- Kernel module hiding from `lsmod` (rootkit Signal 36)
- Network connection hiding via `tcp4_seq_show` / `tcp6_seq_show` hooking
- File/directory hiding via `getdents64` hooking
- In-memory web shell compilation with static field caching

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### File System

| Platform | Path / Artifact | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `\\.\pipe\spectre_<tid>` | N/A | SPECTRE named pipe pattern |
| Windows | `C:\Windows\System32\drivers\etc\hosts:cache` | N/A | C2 config NTFS ADS |
| Windows | PDB: `C:\Users\Administrator\Desktop\2025-11-21 (x神订制全站劫持按浏览器语言跳转)\dll\Release\demo.pdb` | N/A | Build artifact |
| Windows | PDB: `C:\Users\Administrator\Desktop\x神的自安装服务\svchost\x64\Release\service.pdb` | N/A | Build artifact |
| Windows | PDB: `C:\Users\iis\Desktop\AI\EfsPotatoCpp\x64\Release\EfsPotato.pdb` | N/A | AI-compiled tool |
| Windows | PDB: `C:\Users\Intel\Desktop\AI\EfsPotatoCPP\x64\Debug\EfsPotato.pdb` | N/A | AI-compiled tool |
| Linux | `acpi_pad.ko` | N/A | Rootkit masquerading as ACPI module |
| Linux | `hardware-monitor.service` | N/A | Systemd persistence unit |
| Cross | SPECTRE implant | `008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2` | Malware sample |
| Cross | SPECTRE implant | `11ccfdfb0dfe782ba0eeabaa8e65619a792f9258476a072b774ef19a5240b944` | Malware sample |
| Cross | SPECTRE implant | `1c2edfb1b280fdc570591c88da5b1adbd249be6b8cc306a42525a515adaf73e8` | Malware sample |
| Cross | SPECTRE implant | `21274d668e28b01172fa326f42e396b825708ddc2336ae388d6729627c525775` | Malware sample |
| Cross | SPECTRE implant | `43124b72616ef38b0c8a07b167e971b0e4479626fb5ef2303b2ed993e21f6c4c` | Malware sample |
| Cross | SPECTRE implant | `50d88f3d8f91f18195f1e9948cf6b47d69d7e19226957b1e7e3b2e4bd7c4fef4` | Malware sample |
| Cross | Malware sample | `59a386b75b84f137c4e17c37e3430fc93c0184102b3fbdfe649cef2e0335d85b` | Campaign artifact |
| Cross | Malware sample | `684e7ed556dcc9e2fe24fcfd73e6b9c29d7126584f87c5331c2607d39e29329f` | Campaign artifact |
| Cross | Malware sample | `76df454fe87620dd59efb483a56a8b573c7d16207635cf2616a67e25dab57779` | Campaign artifact |
| Cross | Malware sample | `77cce6576f93961651133b543948ea3853cc2f06b8c3fd523f6858d6d18ad775` | Campaign artifact |
| Cross | Malware sample | `830c6ca21a7da0eed436f8371c8a86baa62ab857a5478a222dd3189645d4d084` | Campaign artifact |
| Cross | Malware sample | `91d00ca46d1013c031aa8ff2e54b7b3496bac78f6147842766bffd4d32a2e042` | Campaign artifact |
| Cross | Malware sample | `7565a5bc56fcd94c7f52cf7428747cd4f52d0d3b485900d3d9b06b470ccba23b` | Campaign artifact |
| Cross | Malware sample | `b74beab9dac9ee7853b5e846eec6f778db01867b49f64d6be259ea9e19006121` | Campaign artifact |
| Cross | Malware sample | `bfbd1aa2c0ace1575e86dc5cedc0754e4ae4aae97e70ac9f0523a2e8e8b22ed9` | Campaign artifact |
| Cross | Malware sample | `c88dab534081650d5a385f9bc5c61eced41b4e9fe63ace6173aa536c4aaffa67` | Campaign artifact |
| Cross | Malware sample | `cf0a6353f1fccf63fca02ed41eafd3da8d55f77b8b4c45666a37fa3cdc33da55` | Campaign artifact |
| Cross | Malware sample | `41f1514ad52c870bc4b51291cb939067e8ace23ec308419253ee0a2497bf2e21` | Campaign artifact |
| Cross | Malware sample | `dd4c16c65513c3eb66691f87d5bb5595d38554395ec89be2b9e325e013ef53d5` | Campaign artifact |
| Cross | Malware sample | `dee976f262498184d746cc8305cc9e6905ad762c661df8d7daec120f14060b41` | Campaign artifact |
| Cross | Malware sample | `2e9f10f5cc9fb5c9f935ee78a21de70168e398b7a47db54373a5dcb19c485398` | Campaign artifact |
| Cross | Malware sample | `e315f955a9b44a9c875d2e47f2a91e9e77043bd553ad616ada38eaf669d44b2e` | Campaign artifact |
| Cross | Malware sample | `58725b8e592435026928c39622f41b7ad4f4dc62e353eb459c3b4858eafd9e82` | Campaign artifact |
| Cross | Malware sample | `544a7d9d4de3904ad35e6cc87f34cb556fda722c3d3cae1a6334645f1a950cc7` | Campaign artifact |
| Cross | Malware sample | `9a8e9d587b570d4074f1c8317b163aa8d0c566efd88f294d9d85bc7776352a28` | Campaign artifact |
| Cross | Malware sample | `722bd55e1496cb614f4f365a4203da6166c637f2c6b9ec0da3844637bc6e9e9d` | Campaign artifact |
| Cross | Malware sample | `0345406e85aa7759c0af0372c23de0c5f3e9b6d53e970405e5c168f55c51a7e0` | Campaign artifact |
| Cross | Malware sample | `23a7adda56e2e5519e01f57f16f99e4be611aac4fa908f2ee2d99e3d96e14865` | Campaign artifact |
| Cross | Malware sample | `9619259c1ea9b1c6b8279fdb761018b14a41acc94f67f1469bf68bf393b4ba74` | Campaign artifact |
| Cross | Malware sample | `f07d869ddd17d4359e26da43574d0d07987b500a390196b72b3c1747a4cbb3bf` | Campaign artifact |
| Cross | Malware sample | `d0da3be9de8e7068a65247b8195d73e88f454820e13c1de62675e1f845d6fabf` | Campaign artifact |
| Cross | Malware sample | `0f56c703e9b7ddeb90646927bac05a5c6d95308c8e13b88e5d4f4b572423e036` | Campaign artifact |
| Cross | Malware sample | `35c960bda30ceeb22216fad7776b43ecf44aaccf2ff7f600f91a1afb49a8a43c` | Campaign artifact |
| Cross | Malware sample | `7172ebfb4e96e3b0bff59e87f670c5512144d445b276746c8c78593272720ebf` | Campaign artifact |
| Cross | Malware sample | `b02664c71d1a40760ff6eb253d1a9022d93262698d528d95e8983bf848b8827b` | Campaign artifact |
| Cross | Malware sample | `dbe956ae1135e81ae06220393ee80caacc62006295a1fb26e87f048a7a78b81b` | Campaign artifact |
| Cross | Malware sample | `4bbba075f56ee15760b1397100a82f2c7425b866cf1a35684fda5b712783f97b` | Campaign artifact |
| Cross | Malware sample | `1c70b2a55b6f3a3382f40fe15293b609d047103b0c6c7da0049f7c0e365ea880` | Campaign artifact |
| Cross | Malware sample | `fc54b68f0a375600c8ab23d894b56837db287b32209c0a455fb439a780593c80` | Campaign artifact |
| Cross | Malware sample | `b0c1c3b806a60807854173f2199ba49baf5c2729051b14e4725cb90cfc755519` | Campaign artifact |
| Cross | Malware sample | `089b19f7760a53272f580432460dc959cbb8ffb87bde43152795ff5d893debdd` | Campaign artifact |
| Cross | Malware sample | `1fc83b41d201bfbc4db94e332e0c770be9d74591d9817c1b938ccdf17c7a48a9` | Campaign artifact |
| Cross | Malware sample | `fea09e46f6adf23aa17c56faa14d19168b5417ed90d7b2b36f2c8dd5f6014ea7` | Campaign artifact |
| Cross | Malware sample | `061b765659bf24b62d242d4f8ca9a9884037e186714517509a8f48b54e1123a0` | Campaign artifact |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `27[.]124[.]2[.]46` | C2/infrastructure |
| IP | `27[.]124[.]2[.]48` | C2/infrastructure |
| IP | `27[.]124[.]2[.]52` | C2/infrastructure |
| IP | `139[.]180[.]197[.]150` | Management/C2 server with exposed directory |
| Domain | `jyzyps[.]com` | Malicious JavaScript hosting |
| Domain | `mma888[.]cc` | SEO fraud redirect target |
| Domain | `healthsave[.]net` | Staging/test domain |
| Domain | `niupilao[.]vip` | C2 domain |
| Domain | `b[.]niupilao[.]vip` | C2 subdomain |
| Domain | `vip[.]niupilao[.]vip` | C2 subdomain |
| Domain | `vip8888vn[.]xyz` | C2 domain (Vietnamese targeting) |
| Domain | `udvyiwvfs[.]cyou` | C2 domain |
| Domain | `adminapi[.]tippusoni[.]in` | Payload distribution server |
| URL | `hxxps://js[.]jyzyps[.]com/js/vnnb[.]js` | Malicious JavaScript |
| URL | `hxxps://js[.]jyzyps[.]com/js/nb[.]js` | Malicious JavaScript |
| URL | `hxxp://vn[.]mma888[.]cc/` | SEO fraud redirect |

### Behavioral

- SPECTRE C2 beaconing via HTTP POST to `/api/v1/register` and `/api/v1/output` endpoints with JSON payloads
- C2 configuration stored in NTFS ADS at `drivers\etc\hosts:cache`
- Named pipe creation matching pattern `\\.\pipe\spectre_<thread_id>`
- RTCore64.sys or DBUtil_2_3.sys driver loading (BYOVD indicator)
- `hardware-monitor.service` systemd unit creation (Linux rootkit persistence)
- Kernel module masquerading as `acpi_pad.ko`
- Scheduled task "Google Chrome Start" creation
- Web shell authentication via `X-ID: x9` HTTP header
- certutil-based download in batch scripts
- Microsoft Defender exclusion path modification

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of Zimbra, Telerik, AjaxPro, Nacos vulnerabilities |
| T1059.001 | PowerShell | PowerShell reconnaissance (system info, privilege tokens, IIS configs) |
| T1059.003 | Windows Command Shell | Batch script deployment for payload delivery |
| T1105 | Ingress Tool Transfer | certutil-based remote payload download |
| T1505.003 | Web Shell | BadIIS/ASHX web shells on IIS servers |
| T1053.005 | Scheduled Task | "Google Chrome Start" scheduled task for persistence |
| T1543.002 | Systemd Service | hardware-monitor.service for Linux rootkit persistence |
| T1564.004 | NTFS File Attributes | C2 config stored in hosts:cache ADS |
| T1014 | Rootkit | Specter LKM rootkit with ftrace hooking |
| T1068 | Exploitation for Privilege Escalation | EfsPotato, RustPotato, GodPotato, Dirty Pipe |
| T1055.012 | Process Hollowing | Self-hollowing into RuntimeBroker.exe, hollowing into svchost.exe |
| T1055.004 | Asynchronous Procedure Call | EarlyBird APC injection |
<!-- revision: T1559.001 (COM) corrected to T1559 (Inter-Process Communication); named pipes are not COM -->
| T1559 | Inter-Process Communication | Named pipe IPC (`\\.\pipe\spectre_<tid>`) |
| T1003.002 | Security Account Manager | SAM/SYSTEM/SECURITY hive dumping |
| T1555.003 | Credentials from Web Browsers | Chrome/Edge credential theft via DPAPI |
| T1562.001 | Disable or Modify Tools | BYOVD-based EDR callback unlinking |
| T1070.006 | Timestomp | timestomp command for file timestamp manipulation |
| T1071.001 | Web Protocols | HTTP POST C2 with JSON payloads |
| T1547.006 | Kernel Modules and Extensions | LKM rootkit deployed as acpi_pad.ko |
| T1564.001 | Hidden Files and Directories | Process/file hiding via rootkit syscall hooks |
| T1036.004 | Masquerade Task or Service | Rootkit masquerading as legitimate acpi_pad module |

## Impact Assessment

UAT-10147 demonstrates a high level of operational maturity, combining financially motivated SEO fraud with espionage-grade post-exploitation capabilities. The BYOVD capability to blind CrowdStrike, SentinelOne, and Microsoft Defender is particularly impactful, as it renders enterprise EDR solutions ineffective at detecting subsequent malicious activity. The Linux kernel rootkit provides persistent, stealthy access that survives user-level security controls and reboots. The actor's use of AI-assisted tooling (PentestGPT, DeepAudit) to scale exploitation across 170,000+ URLs represents a significant force multiplier. Victim organizations span multiple sectors and geographies, with Vietnamese entities disproportionately targeted for SEO fraud monetization.

## Detection & Remediation

### Immediate Detection

**Windows:**
```
# Check for SPECTRE named pipe
dir \\.\pipe\spectre_* 2>nul

# Check for NTFS ADS on hosts file
dir /r C:\Windows\System32\drivers\etc\hosts

# Check for suspicious scheduled tasks
schtasks /query /fo LIST /v | findstr /i "Google Chrome Start"

# Check for BYOVD drivers
sc query | findstr /i "RTCore64\|DBUtil_2_3"

# Check for RuntimeBroker with unusual parent
wmic process where "name='RuntimeBroker.exe'" get ParentProcessId,ProcessId,CommandLine
```

**Linux:**
```bash
# Check for rootkit module
lsmod | grep acpi_pad
# NOTE: if rootkit is active, module may be hidden from lsmod

# Check for persistence service
systemctl status hardware-monitor.service
cat /etc/systemd/system/hardware-monitor.service

# Check loaded kernel modules against known good baseline
diff <(lsmod | awk '{print $1}' | sort) <(cat /path/to/known_good_modules | sort)

# Check for ftrace hooks
cat /sys/kernel/debug/tracing/enabled_functions 2>/dev/null
```

### Remediation

1. **Contain**: Isolate affected IIS and Linux servers from the network immediately
2. **Eradicate (Windows)**: Remove BYOVD drivers, delete scheduled task "Google Chrome Start", clear hosts:cache ADS, terminate SPECTRE processes, remove web shells from IIS
3. **Eradicate (Linux)**: Attempt `rmmod acpi_pad` to unload the rootkit module, but note that the rootkit hides itself from `lsmod` (Signal 36) and may block `rmmod`; if removal fails, a kernel rebuild or full reimage is required. Remove hardware-monitor.service and rebuild kernel if module integrity cannot be verified
4. **Credentials**: Rotate all credentials on affected systems; assume SAM/SYSTEM/SECURITY and browser credentials are compromised
5. **Patch**: Apply patches for CVE-2022-27925, CVE-2019-18935, CVE-2021-23758, CVE-2021-29441/29442 on all exposed servers
6. **Monitor**: Deploy IOC-based detection for all listed hashes, domains, and IPs

### Long-Term Hardening

- Implement driver block policies (WDAC/HVCI) to prevent BYOVD attacks loading known vulnerable drivers
- Deploy Secure Boot and module signing enforcement on Linux servers
- Implement web application firewalls with virtual patching for internet-facing servers
- Enable and monitor for NTFS ADS creation/access on sensitive system files
- Restrict certutil execution via application control policies
- Monitor for kernel module loading events on Linux systems

## Detection Rules

These detections target SPECTRE implant artifacts, BYOVD driver loading, C2 communication patterns, and web shell authentication at PoC/advisory-specific altitude. Compiles-clean does not guarantee the rule fires in your telemetry pipeline -- verify in your environment before production deployment.

### Sigma: SPECTRE Implant Named Pipe Creation
Detects creation of named pipes matching the SPECTRE implant pattern `\\.\pipe\spectre_<tid>`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0. Pipe name is highly distinctive to SPECTRE implant. No known benign software uses this pattern. -->
<!-- revision: tag corrected from attack.t1559.001 (COM) to attack.t1559 (IPC) -->
```yaml
title: SPECTRE Implant Named Pipe Creation
id: 7c3a1b9e-4d2f-4e8a-b5c6-1a2b3c4d5e6f
status: experimental
description: Detects creation of named pipes matching the SPECTRE implant pattern (\\.\pipe\spectre_<tid>) used by UAT-10147 for inter-process communication.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/24
tags:
    - attack.t1559
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|startswith: '\spectre_'
    condition: selection
falsepositives:
    - Unlikely - highly specific pipe name pattern
level: critical
```

### Sigma: SPECTRE BYOVD Vulnerable Driver Loading
Detects loading of RTCore64.sys or DBUtil_2_3.sys, vulnerable drivers exploited by SPECTRE for kernel-level EDR callback unlinking.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Both drivers are on the Microsoft recommended driver block list. Legitimate MSI Afterburner and legacy Dell firmware tools are potential FPs but uncommon in server environments. -->
```yaml
title: SPECTRE BYOVD Vulnerable Driver Loading
id: 8d4b2c0f-5e3a-4f9b-a6d7-2b3c4d5e6f7a
status: experimental
description: Detects loading of vulnerable drivers (RTCore64.sys or DBUtil_2_3.sys) exploited by the SPECTRE implant for kernel-level EDR callback unlinking via BYOVD technique.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/24
tags:
    - attack.t1068
    - attack.t1014
logsource:
    category: driver_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith:
            - '\RTCore64.sys'
            - '\DBUtil_2_3.sys'
    condition: selection
falsepositives:
    - Legitimate MSI Afterburner installations loading RTCore64.sys
    - Legacy Dell firmware update utilities loading DBUtil_2_3.sys
level: high
```

### Sigma: SPECTRE C2 Configuration via NTFS Alternate Data Stream
Detects file access to the NTFS ADS used by SPECTRE to store C2 configuration on the Windows hosts file.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. The hosts:cache ADS is a highly distinctive artifact. Requires Sysmon EID 11/15 or equivalent file monitoring. -->
```yaml
title: SPECTRE C2 Configuration via NTFS Alternate Data Stream
id: 9e5c3d1a-6f4b-4a0c-b7e8-3c4d5e6f7a8b
status: experimental
description: Detects access to the NTFS Alternate Data Stream used by SPECTRE to store C2 configuration at C:\Windows\System32\drivers\etc\hosts:cache.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/24
tags:
    - attack.t1564.004
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: 'drivers\etc\hosts:cache'
    condition: selection
falsepositives:
    - Unlikely - specific ADS name on the hosts file is highly distinctive
level: critical
```

### Sigma: Specter Rootkit Systemd Persistence
Detects creation of the hardware-monitor.service systemd unit used by the Specter Linux rootkit for boot persistence. The service name is plausible for legitimate hardware monitoring software, so triage against installed packages before escalating.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. -->
<!-- revision: confidence downgraded high->medium; "hardware-monitor" is a plausible name for legitimate hw-monitoring daemons (e.g., custom lm-sensors wrappers). FP scenario documented. -->
```yaml
title: SPECTRE Rootkit Systemd Persistence via hardware-monitor Service
id: af6d4e2b-7a5c-4b1d-c8f9-4d5e6f7a8b9c
status: experimental
description: Detects creation of the hardware-monitor.service systemd unit file used by the Specter Linux rootkit for persistence across reboots.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/24
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/hardware-monitor.service'
    condition: selection
falsepositives:
    - Legitimate hardware monitoring tools or custom lm-sensors wrappers using the same service name
level: high
```

### Sigma: UAT-10147 Persistence via Google Chrome Start Scheduled Task
Detects schtasks.exe creating the "Google Chrome Start" scheduled task used by UAT-10147 for persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Task name is specific to this campaign. Legitimate Chrome installations do not create tasks with this exact name. -->
```yaml
title: UAT-10147 Persistence via Google Chrome Start Scheduled Task
id: b07e5f3c-8b6d-4c2e-d9a0-5e6f7a8b9c0d
status: experimental
description: Detects creation of the scheduled task named Google Chrome Start used by UAT-10147 for persistence on compromised Windows hosts.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
    - https://thehackernews.com/2026/08/uat-10147-uses-ai-to-scale-server.html
author: Actioner
date: 2026/08/24
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_tool:
        Image|endswith: '\schtasks.exe'
    selection_taskname:
        CommandLine|contains: 'Google Chrome Start'
    condition: selection_tool and selection_taskname
falsepositives:
    - Unlikely - legitimate Chrome does not create tasks with this exact name
level: high
```

<!-- revision: DROPPED Sigma rule "SPECTRE Self-Hollowing into RuntimeBroker" -- altitude mismatch; RuntimeBroker.exe legitimately spawns from non-svchost parents on workstations, producing hundreds of hits/day. Not suitable for production alerting. -->

### Sigma: UAT-10147 Web Shell Authentication Header
Detects HTTP requests containing the X-ID header used to authenticate UAT-10147 web shells on compromised IIS servers. Caveat: IIS does not log arbitrary request headers by default; the X-ID header must be added as a custom log field in IIS Advanced Logging or captured by a reverse proxy/WAF forwarding logs to the SIEM.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. -->
<!-- revision: field changed from cs-cookie to cs-uri-query fallback approach. X-ID is an HTTP header, not a cookie -- it would NOT appear in IIS cs(Cookie) logs. Detection now targets the cs-uri-query "v" fallback parameter and notes that header-based detection requires explicit IIS custom logging configuration for X-ID. -->
```yaml
title: UAT-10147 Web Shell Authentication Header in IIS Logs
id: d29a7b5e-0d8f-4e4a-f1c2-7a8b9c0d1e2f
status: experimental
description: |
    Detects HTTP requests matching the UAT-10147 web shell authentication pattern. The primary auth mechanism is the X-ID HTTP header (value x9), but IIS does not log arbitrary request headers by default -- deploy IIS Advanced Logging with X-ID as a custom field to capture it. This rule targets the fallback query-string parameter (v=x9) which IS logged in standard IIS W3C logs.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/24
tags:
    - attack.t1505.003
logsource:
    category: webserver
detection:
    selection_query_fallback:
        cs-uri-query|contains: 'v=x9'
    condition: selection_query_fallback
falsepositives:
    - Web applications using a query parameter v with value x9 in normal operation
level: high
```

### Snort: UAT-10147 Web Shell Authentication
Detects web shell authentication via the X-ID header with value x9 used by UAT-10147 BadIIS web shells.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 validated with classification.config, exit 0. -->
<!-- revision: DROPPED sid:2100001 (SPECTRE C2 Registration /api/v1/register) and sid:2100002 (SPECTRE C2 Output Exfil /api/v1/output) -- generic REST URI patterns with no destination pinning; thousands of FP/day expected. -->
```snort
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - UAT-10147 Web Shell Auth Header X-ID x9"; flow:established,to_server; content:"X-ID"; http_header; fast_pattern; content:"x9"; http_header; classtype:web-application-attack; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; sid:2100003; rev:1;)
```

### Suricata: UAT-10147 Web Shell Auth and Known C2 Domains
Detects web shell authentication and DNS queries to known UAT-10147 C2/infrastructure domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T exit 0. Domain-based DNS rules are high confidence (known IOCs). -->
<!-- revision: DROPPED sid:2200001 (SPECTRE C2 Registration /api/v1/register) and sid:2200002 (SPECTRE C2 Output Exfil /api/v1/output) -- generic REST URI patterns with no destination pinning; thousands of FP/day expected. Added sid:2200010 for healthsave.net (staging domain listed in IOC table). -->
```suricata
alert http any any -> $HOME_NET any (msg:"Actioner - UAT-10147 Web Shell Auth Header X-ID x9"; flow:established,to_server; http.header; content:"X-ID|3a 20|x9"; fast_pattern; classtype:web-application-attack; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-24; sid:2200003; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UAT-10147 C2 Domain jyzyps.com"; dns.query; content:"jyzyps.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-24; sid:2200004; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UAT-10147 C2 Domain niupilao.vip"; dns.query; content:"niupilao.vip"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-24; sid:2200005; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UAT-10147 C2 Domain vip8888vn.xyz"; dns.query; content:"vip8888vn.xyz"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-24; sid:2200006; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UAT-10147 C2 Domain udvyiwvfs.cyou"; dns.query; content:"udvyiwvfs.cyou"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-24; sid:2200007; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UAT-10147 C2 Domain mma888.cc"; dns.query; content:"mma888.cc"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-24; sid:2200008; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UAT-10147 Payload Domain tippusoni.in"; dns.query; content:"tippusoni.in"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-24; sid:2200009; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UAT-10147 Staging Domain healthsave.net"; dns.query; content:"healthsave.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-24; sid:2200010; rev:1;)
```

### YARA: SPECTRE Windows Implant, Linux Rootkit, and BadIIS Web Shell
Detects SPECTRE Windows implant (PDB paths, pipe name, C2 endpoints), Specter Linux rootkit (acpi_pad masquerade, ftrace hooks, rootkit commands), and BadIIS web shell (SeoEngineHandler class, X-ID auth).
**Status:** compile ✅ compiles · confidence: high (Windows implant, Linux rootkit) / medium (BadIIS web shell)
<!-- audit: yarac exit 0. Three rules. -->
<!-- revision: (1) Fixed pipe string from "\\\\.\\.\\pipe\\spectre_" to "\\\\.\\pipe\\spectre_" (extra \\. segment was a bug). (2) $cmd* strings (byovd_load, edr_kill, hashdump, etc.) are encrypted at compile time with xorshift32 PRNG -- they will NOT match on-disk binaries, only memory dumps; documented in condition comment. (3) BadIIS web shell downgraded high->medium; standalone $cls (SeoEngineHandler) branch could match SEO-themed .NET libraries. -->
```yara
rule UAT10147_SPECTRE_Windows_Implant
{
    meta:
        description = "Detects the SPECTRE Windows implant deployed by UAT-10147 based on distinctive PDB paths, named pipe pattern, and command strings"
        author = "Actioner"
        date = "2026-08-24"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        hash = "008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2"
        severity = "critical"

    strings:
        $pdb1 = "x神订制全站劫持按浏览器语言跳转" ascii wide
        $pdb2 = "x神的自安装服务" ascii wide
        $pdb3 = "\\Desktop\\AI\\EfsPotatoCpp\\" ascii
        $pdb4 = "\\Desktop\\AI\\EfsPotatoCPP\\" ascii

        $pipe = "\\\\.\\pipe\\spectre_" ascii wide

        // NOTE: $cmd* strings are encrypted at compile time with xorshift32 PRNG.
        // These will match only in memory dumps or decrypted samples, NOT on-disk binaries.
        $cmd1 = "byovd_load" ascii
        $cmd2 = "byovd_unload" ascii
        $cmd3 = "edr_kill" ascii
        $cmd4 = "hashdump" ascii
        $cmd5 = "chromedump" ascii
        $cmd6 = "steal_token" ascii
        $cmd7 = "earlybird" ascii
        $cmd8 = "execute_assembly" ascii

        $c2_1 = "/api/v1/register" ascii
        $c2_2 = "/api/v1/output" ascii

        $ads = "drivers\\etc\\hosts:cache" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($pdb*) or
            $pipe or
            (3 of ($cmd*)) or
            ($c2_1 and $c2_2 and $ads)
        )
}

rule UAT10147_Specter_Linux_Rootkit
{
    meta:
        description = "Detects the Specter Linux kernel rootkit deployed by UAT-10147 based on distinctive module masquerading and ftrace hooking artifacts"
        author = "Actioner"
        date = "2026-08-24"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "critical"

    strings:
        $mod = "acpi_pad" ascii fullword

        $hook1 = "tcp6_seq_show" ascii fullword
        $hook2 = "tcp4_seq_show" ascii fullword
        $hook3 = "getdents64" ascii fullword

        $cmd1 = "rootkit_load" ascii
        $cmd2 = "rootkit_hide" ascii
        $cmd3 = "rootkit_root" ascii
        $cmd4 = "rootkit_hide_mod" ascii
        $cmd5 = "rootkit_status" ascii
        $cmd6 = "rootkit_persist" ascii
        $cmd7 = "rootkit_unload" ascii

        $svc = "hardware-monitor.service" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 20MB and
        (
            (3 of ($cmd*)) or
            ($mod and 2 of ($hook*)) or
            ($svc and any of ($hook*))
        )
}

rule UAT10147_BadIIS_WebShell
{
    meta:
        description = "Detects UAT-10147 BadIIS/ASHX web shells with distinctive SeoEngineHandler class and X-ID authentication"
        author = "Actioner"
        date = "2026-08-24"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "medium"
        // revision: downgraded from high to medium; standalone $cls (SeoEngineHandler)
        // could match SEO-themed .NET libraries. Require $cls + at least one auth indicator.

    strings:
        $cls = "SeoEngineHandler" ascii wide fullword
        $auth1 = "X-ID" ascii wide
        $auth2 = "x9" ascii wide
        $vn = "\xe8\xb6\x8a\xe5\x8d\x97\xe8\x80\x81\xe9\x80\xbc" // 越南老逼

    condition:
        filesize < 5MB and
        (
            ($cls and any of ($auth*)) or
            ($auth1 and $auth2 and $vn)
        )
}
```

## Lessons Learned

This campaign underscores several key takeaways for defenders:

1. **BYOVD is now commodity**: UAT-10147's ability to blind enterprise EDR solutions by loading known vulnerable drivers and unlinking kernel callbacks demonstrates that BYOVD has moved beyond APT-exclusive tradecraft. Organizations must enforce driver block policies (WDAC/HVCI) and monitor for known vulnerable driver loads.

2. **AI-assisted offensive tooling scales**: The actor's deployment of PentestGPT and AI vulnerability scanners, combined with AI-generated post-exploitation utilities, demonstrates how AI lowers the barrier to scaling exploitation campaigns across tens of thousands of targets.

3. **Cross-platform implants demand cross-platform detection**: SPECTRE's Windows and Linux variants share operational objectives but use platform-specific persistence and evasion mechanisms, requiring detection engineering across both endpoint telemetry pipelines.

4. **Kernel-level persistence defeats user-space controls**: The Specter rootkit's use of ftrace hooking to intercept syscalls and hide processes, files, and network connections from user-space tooling means that compromised Linux servers may require kernel integrity verification or full rebuild rather than conventional remediation.

5. **SEO fraud as monetization bridge**: UAT-10147 combines espionage-grade post-exploitation with financially motivated SEO fraud, suggesting the actor treats server compromises as multi-use assets -- generating revenue through SEO manipulation while maintaining persistent access for intelligence collection.

## Sources

- [Cisco Talos - UAT-10147 deploys SPECTRE](https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/) -- Primary technical analysis with detailed SPECTRE implant, Specter rootkit, and BYOVD capability analysis
- [The Hacker News - UAT-10147 Uses AI to Scale Server Exploitation](https://thehackernews.com/2026/08/uat-10147-uses-ai-to-scale-server.html) -- Secondary coverage with additional context on AI-assisted tooling, victim targeting, and exploitation CVEs
- [Cisco Talos IOCs - GitHub](https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt) -- Published IOCs including SHA256 hashes, domains, IPs, and URLs

---
*Report generated by Actioner*
