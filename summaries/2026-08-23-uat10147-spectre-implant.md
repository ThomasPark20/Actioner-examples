# Technical Analysis Report: UAT-10147 SPECTRE Cross-Platform Implant (2026-08-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-23
Version: DRAFT 1.0

## Executive Summary

UAT-10147, a Chinese-speaking intrusion actor linked to the BadIIS malware-as-a-service ecosystem, has deployed SPECTRE -- a sophisticated cross-platform backdoor targeting Windows and Linux servers. The implant supports 45 commands on Windows (24 plaintext, 21 encrypted) and 29 on Linux, integrating credential theft, process injection, in-memory .NET execution, keylogging, and C2 communication via HTTP POST to `/api/v1/register` and `/api/v1/output` endpoints. Its most significant capabilities are a Linux kernel rootkit ("Specter") that uses ftrace hooking to hide processes, network connections, and kernel modules via signal-based IPC, and a Windows BYOVD module exploiting CVE-2019-16098 (RTCore64.sys) and CVE-2021-21551 (DBUtil_2_3.sys) to unlink EDR kernel callbacks. Talos identifies AI-assisted code generation artifacts in the rootkit source -- the first documented instance of AI-generated kernel-mode offensive tooling at this scale. The campaign targets internet-facing IIS and Linux servers across Brazil, Bolivia, China, Canada, and Vietnam, with a target list of approximately 170,000 URLs.

## Background: UAT-10147 and BadIIS Ecosystem

UAT-10147 is a Chinese-speaking cybercrime actor operating within the BadIIS malware-as-a-service (MaaS) ecosystem, monetizing compromised servers through SEO fraud targeting Vietnamese audiences. The actor has previously been documented by Cisco Talos leveraging AI-assisted exploitation workflows -- using tools like PentestGPT and DeepAudit to automate vulnerability scanning and exploit execution against internet-facing web servers. The SPECTRE implant represents a significant capability upgrade, introducing kernel-level stealth and EDR bypass that was historically reserved for top-tier APT groups. PDB paths in recovered samples reference the username "x神" (xshen) and development directories like `C:\Users\iis\Desktop\AI\`, indicating an organized development environment with AI integration.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025 (ongoing) | UAT-10147 targets ~170,000 internet-facing IIS and Linux servers |
| 2025-11-21 | PDB timestamp in recovered SPECTRE sample (DLL variant) |
| 2026-08 (pre-disclosure) | Cisco Talos publishes SPECTRE technical analysis |
| 2026-08-20 | Public coverage and IOC repository published |

## Root Cause: Exploitation of Public-Facing Applications

UAT-10147 gains initial access by exploiting known vulnerabilities in internet-facing servers:

- **CVE-2022-27925** -- Zimbra RCE
- **CVE-2021-23758** -- AjaxPro deserialization
- **CVE-2021-29441/29442** -- Nacos framework RCE
- **CVE-2019-18935** -- Telerik UI deserialization

Post-exploitation privilege escalation on Linux leverages CVE-2022-0995, CVE-2021-3156 (Baron Samedit), CVE-2022-0847 (Dirty Pipe), CVE-2015-3246, CVE-2015-5287, and CVE-2010-3904. On Windows, the actor deploys Potato-family tools (GodPotato, JuicyPotato, EfsPotato, RustPotato) for SYSTEM-level escalation.

## Technical Analysis of the Malicious Payload

### 1. Initial Access and Web Shell Deployment

UAT-10147 deploys persistent ASHX web shells with dynamic in-memory compilation via CodeDomProvider. Web shell access requires authentication through an `X-ID` HTTP header token, with the parameter `x9` (fallback: `v`) used for command input. The web shells integrate SEO fraud capabilities targeting Vietnamese search engines (Coc Coc crawler). AI-generated deployment scripts (`deploy_implant.py`, `deploy_shell.py`, `exfil.py`) automate post-exploitation workflows.

### 2. SPECTRE Implant Architecture

**Windows variant (45 commands):** Dual-layered obfuscation using PEB hash walking (DJB2 variant) for API resolution and per-string xorshift32 PRNG encryption with unique 32-bit seeds. Runtime decryption writes plaintext to thread-local storage. Commands include: shell execution (cmd.exe), DLL injection, shellcode injection, process hollowing (standard, APC EarlyBird, self-hollowing), registry operations, keylogging, hashdump (SAM/SYSTEM/SECURITY via RegSaveKeyA), chromedump (Chrome/Edge login databases), vaultdump (cmdkey.exe credential capture), execute_assembly (.NET CLR hosting), token theft/impersonation, and file download/upload.

**Linux variant (29 commands):** Statically-linked ELF x86-64 binary with no encrypted commands. Includes shell execution (/bin/sh), timestomping, anti-sandbox scoring, and direct rootkit control. Integrated kernel module loading and signal-based IPC for rootkit operations.

**Anti-analysis scoring system:** Both variants implement an 8-factor sandbox detection scoring system evaluating process name blocklists, RAM capacity, CPU core count, disk space, sleep acceleration, and sandbox hostname/username matching. Self-termination triggers at a cumulative score of 50 points.

### 3. C2 Infrastructure

SPECTRE communicates via HTTP POST to two endpoints:
- `/api/v1/register` -- initial check-in and registration
- `/api/v1/output` -- command output exfiltration

The Linux variant uses JSON payload formatting. C2 domain configuration is stored in NTFS Alternate Data Streams (`C:\Windows\System32\drivers\etc\hosts:cache`) on Windows, allowing dynamic updates that circumvent firewall-level domain blocks. Hardcoded fallback domains are encrypted in the binary using xorshift32.

### 4. Platform-Specific Behavior

#### Windows

- **Persistence:** Service installation via SCM; web shell persistence
- **Privilege Escalation:** Named pipe impersonation (`\\.\pipe\spectre_<tid>`) for SYSTEM token acquisition; Potato-family tools
- **Credential Theft:** SAM/SYSTEM/SECURITY hive dumping via RegSaveKeyA; Chrome/Edge login database exfiltration to `%TEMP%`; cmdkey.exe stdout capture; offline cracking via secretsdump.py and SharpChrome
- **Injection:** Process hollowing (standard, APC EarlyBird, self-hollowing); DLL injection; shellcode injection
- **BYOVD:** Downloads vulnerable drivers from C2 (RTCore64.sys / DBUtil_2_3.sys); uses arbitrary kernel R/W via IOCTL to locate and unlink PspCreateProcessNotifyRoutine, PspCreateThreadNotifyRoutine, PspLoadImageNotifyRoutine; hardcoded offsets for 13 Windows versions

#### Linux

- **Persistence:** Systemd unit `hardware-monitor.service` (Description: "Hardware Performance Monitor") with `Before=sysinit.target` for early boot loading
- **Rootkit (Specter):** Kernel module disguised as `acpi_pad.ko`; uses ftrace instrumentation framework with `FTRACE_OPS_FL_IPMODIFY` flag; hooks 6 syscall handlers: `hooked_tcp6_seq_show`, `hooked_tcp4_seq_show`, `hooked_tkill`, `hooked_tgkill`, `hooked_kill`, `hooked_getdents64`
- **Signal-based IPC (magic PID 0x7A69 / 31337):** Signal 62 = process hiding (task_struct removal); Signal 36 = module hiding (kernel module list unlinking); Signal 37 = UID 0 escalation (credential structure overwrite); Signal 35 = module load acknowledgement handshake
- **AI artifacts:** Machine-like uniform decorative separators, pedagogical code comments, three labeled methods ("Method 1/2/3" completeness pattern)

### 5. Anti-Forensics / Evasion Techniques

- **String obfuscation:** Per-string xorshift32 PRNG encryption with unique 32-bit seeds; compile-time encryption; runtime decryption to thread-local storage
- **API resolution:** PEB hash walking using DJB2 variant algorithm prevents static analysis of API imports
- **EDR bypass (BYOVD):** Kernel callback unlinking blinds CrowdStrike Falcon, SentinelOne, Microsoft Defender, and other callback-dependent EDR products
- **Rootkit stealth:** Process hiding from /proc, network connection hiding from /proc/net/tcp{4,6}, kernel module hiding from lsmod/proc/modules
- **NTFS ADS abuse:** C2 configuration stored in hosts:cache ADS avoids standard file listing
- **Timestomping:** Linux variant modifies file timestamps to blend with legitimate system files

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Gh0stCringe | Go-based loader | Wrapper/loader for SPECTRE deployment |
| QuasarRAT | Campaign variant | RAT with derogatory Chinese campaign ID targeting Vietnam |
| Noodle RAT | Type 0x03A2 ELF | Linux backdoor variant (documented by Trend Micro) |
| GodPotato | Open-source | Privilege escalation tool |
| EfsPotato | AI-compiled | Privilege escalation tool (built from AI directory) |
| RustPotato | Open-source | Privilege escalation tool |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `C:\Windows\System32\drivers\etc\hosts:cache` | N/A | NTFS ADS C2 config storage |
| Windows | `%TEMP%` (staging) | Multiple (see below) | Malware staging and chromedump output |
| Linux | `acpi_pad.ko` | See IOC hashes | Rootkit kernel module disguised as ACPI module |
| Linux | `hardware-monitor.service` | N/A | Systemd persistence unit |

**Selected SHA256 hashes (47 total -- see GitHub IOC repository for complete list):**

| SHA256 | Context |
|--------|---------|
| `008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2` | SPECTRE/related component |
| `11ccfdfb0dfe782ba0eeabaa8e65619a792f9258476a072b774ef19a5240b944` | SPECTRE/related component |
| `1c2edfb1b280fdc570591c88da5b1adbd249be6b8cc306a42525a515adaf73e8` | SPECTRE/related component |
| `21274d668e28b01172fa326f42e396b825708ddc2336ae388d6729627c525775` | SPECTRE/related component |
| `43124b72616ef38b0c8a07b167e971b0e4479626fb5ef2303b2ed993e21f6c4c` | SPECTRE/related component |
| `50d88f3d8f91f18195f1e9948cf6b47d69d7e19226957b1e7e3b2e4bd7c4fef4` | SPECTRE/related component |
| `59a386b75b84f137c4e17c37e3430fc93c0184102b3fbdfe649cef2e0335d85b` | SPECTRE/related component |
| `684e7ed556dcc9e2fe24fcfd73e6b9c29d7126584f87c5331c2607d39e29329f` | SPECTRE/related component |
| `76df454fe87620dd59efb483a56a8b573c7d16207635cf2616a67e25dab57779` | SPECTRE/related component |
| `77cce6576f93961651133b543948ea3853cc2f06b8c3fd523f6858d6d18ad775` | SPECTRE/related component |
| `830c6ca21a7da0eed436f8371c8a86baa62ab857a5478a222dd3189645d4d084` | SPECTRE/related component |
| `91d00ca46d1013c031aa8ff2e54b7b3496bac78f6147842766bffd4d32a2e042` | SPECTRE/related component |
| `7565a5bc56fcd94c7f52cf7428747cd4f52d0d3b485900d3d9b06b470ccba23b` | SPECTRE/related component |
| `b74beab9dac9ee7853b5e846eec6f778db01867b49f64d6be259ea9e19006121` | SPECTRE/related component |
| `bfbd1aa2c0ace1575e86dc5cedc0754e4ae4aae97e70ac9f0523a2e8e8b22ed9` | SPECTRE/related component |
| `c88dab534081650d5a385f9bc5c61eced41b4e9fe63ace6173aa536c4aaffa67` | SPECTRE/related component |
| `cf0a6353f1fccf63fca02ed41eafd3da8d55f77b8b4c45666a37fa3cdc33da55` | SPECTRE/related component |
| `41f1514ad52c870bc4b51291cb939067e8ace23ec308419253ee0a2497bf2e21` | SPECTRE/related component |
| `dd4c16c65513c3eb66691f87d5bb5595d38554395ec89be2b9e325e013ef53d5` | SPECTRE/related component |
| `dee976f262498184d746cc8305cc9e6905ad762c661df8d7daec120f14060b41` | SPECTRE/related component |
| `2e9f10f5cc9fb5c9f935ee78a21de70168e398b7a47db54373a5dcb19c485398` | SPECTRE/related component |
| `e315f955a9b44a9c875d2e47f2a91e9e77043bd553ad616ada38eaf669d44b2e` | SPECTRE/related component |
| `58725b8e592435026928c39622f41b7ad4f4dc62e353eb459c3b4858eafd9e82` | SPECTRE/related component |
| `544a7d9d4de3904ad35e6cc87f34cb556fda722c3d3cae1a6334645f1a950cc7` | SPECTRE/related component |
| `9a8e9d587b570d4074f1c8317b163aa8d0c566efd88f294d9d85bc7776352a28` | SPECTRE/related component |
| `722bd55e1496cb614f4f365a4203da6166c637f2c6b9ec0da3844637bc6e9e9d` | SPECTRE/related component |
| `0345406e85aa7759c0af0372c23de0c5f3e9b6d53e970405e5c168f55c51a7e0` | SPECTRE/related component |
| `23a7adda56e2e5519e01f57f16f99e4be611aac4fa908f2ee2d99e3d96e14865` | SPECTRE/related component |
| `9619259c1ea9b1c6b8279fdb761018b14a41acc94f67f1469bf68bf393b4ba74` | SPECTRE/related component |
| `f07d869ddd17d4359e26da43574d0d07987b500a390196b72b3c1747a4cbb3bf` | SPECTRE/related component |
| `d0da3be9de8e7068a65247b8195d73e88f454820e13c1de62675e1f845d6fabf` | SPECTRE/related component |
| `0f56c703e9b7ddeb90646927bac05a5c6d95308c8e13b88e5d4f4b572423e036` | SPECTRE/related component |
| `35c960bda30ceeb22216fad7776b43ecf44aaccf2ff7f600f91a1afb49a8a43c` | SPECTRE/related component |
| `7172ebfb4e96e3b0bff59e87f670c5512144d445b276746c8c78593272720ebf` | SPECTRE/related component |
| `b02664c71d1a40760ff6eb253d1a9022d93262698d528d95e8983bf848b8827b` | SPECTRE/related component |
| `dbe956ae1135e81ae06220393ee80caacc62006295a1fb26e87f048a7a78b81b` | SPECTRE/related component |
| `4bbba075f56ee15760b1397100a82f2c7425b866cf1a35684fda5b712783f97b` | SPECTRE/related component |
| `1c70b2a55b6f3a3382f40fe15293b609d047103b0c6c7da0049f7c0e365ea880` | SPECTRE/related component |
| `fc54b68f0a375600c8ab23d894b56837db287b32209c0a455fb439a780593c80` | SPECTRE/related component |
| `b0c1c3b806a60807854173f2199ba49baf5c2729051b14e4725cb90cfc755519` | SPECTRE/related component |
| `089b19f7760a53272f580432460dc959cbb8ffb87bde43152795ff5d893debdd` | SPECTRE/related component |
| `1fc83b41d201bfbc4db94e332e0c770be9d74591d9817c1b938ccdf17c7a48a9` | SPECTRE/related component |
| `fea09e46f6adf23aa17c56faa14d19168b5417ed90d7b2b36f2c8dd5f6014ea7` | SPECTRE/related component |
| `061b765659bf24b62d242d4f8ca9a9884037e186714517509a8f48b54e1123a0` | SPECTRE/related component |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `27.124.2[.]46` | C2/staging infrastructure |
| IP | `27.124.2[.]48` | C2/staging infrastructure |
| IP | `27.124.2[.]52` | C2/staging infrastructure |
| IP | `139.180.197[.]150` | Primary download/staging server (port 54321 also observed) |
| Domain | `jyzyps[.]com` | Malicious JavaScript hosting |
| Domain | `mma888[.]cc` | Redirect/C2 domain |
| Domain | `healthsave[.]net` | C2/testing domain |
| Domain | `niupilao[.]vip` | C2 domain (subdomains: b., vip.) |
| Domain | `vip8888vn[.]xyz` | C2 domain (Vietnamese targeting) |
| Domain | `udvyiwvfs[.]cyou` | C2 domain |
| Domain | `adminapi.tippusoni[.]in` | BadIIS distribution point |
| URL | `hxxps://js.jyzyps[.]com/js/vnnb.js` | Malicious JavaScript payload |
| URL | `hxxps://js.jyzyps[.]com/js/nb.js` | Malicious JavaScript payload |
| URL | `hxxp://vn.mma888[.]cc/` | Redirect target |

### Behavioral

- **Named pipe creation:** `\\.\pipe\spectre_<tid>` pattern for Windows privilege escalation
- **NTFS ADS:** C2 config stored in `C:\Windows\System32\drivers\etc\hosts:cache`
- **C2 endpoints:** HTTP POST to `/api/v1/register` (check-in) and `/api/v1/output` (exfil)
- **Web shell authentication:** `X-ID` header token required; `x9` parameter for commands
- **Sandbox evasion:** 8-factor scoring with 50-point self-termination threshold
- **Rootkit IPC:** Signals sent to magic PID 31337 (0x7A69) -- signal 62 (hide process), 36 (hide module), 37 (UID 0 escalation), 35 (handshake)
- **Kernel module disguise:** `acpi_pad.ko` mimicking legitimate ACPI pad driver
- **Systemd persistence:** `hardware-monitor.service` with `Before=sysinit.target`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of IIS, Zimbra, Nacos, Telerik vulnerabilities |
| T1059.003 | Windows Command Shell | cmd.exe command execution via SPECTRE shell command |
| T1059.004 | Unix Shell | /bin/sh command execution via SPECTRE Linux variant |
| T1505.003 | Web Shell | ASHX web shells with in-memory CodeDomProvider compilation |
| T1543.002 | Systemd Service | hardware-monitor.service persistence with Before=sysinit.target |
| T1547.006 | Kernel Modules and Extensions | acpi_pad.ko rootkit disguised as legitimate ACPI module |
| T1134.001 | Token Impersonation/Theft | Named pipe impersonation (\\.\pipe\spectre_) for SYSTEM tokens |
| T1068 | Exploitation for Privilege Escalation | BYOVD via RTCore64.sys (CVE-2019-16098) and DBUtil_2_3.sys (CVE-2021-21551) |
| T1562.001 | Disable or Modify Tools | EDR kernel callback unlinking (PspCreate*NotifyRoutine) |
| T1003.002 | Security Account Manager | SAM/SYSTEM/SECURITY hive dumping via RegSaveKeyA |
| T1555.003 | Credentials from Web Browsers | Chrome/Edge login database and Local State exfiltration |
| T1564.004 | NTFS File Attributes | C2 config stored in hosts:cache NTFS Alternate Data Stream |
| T1027 | Obfuscated Files or Information | Xorshift32 PRNG string encryption; PEB hash walking for API resolution |
| T1055.012 | Process Hollowing | Standard, APC EarlyBird, and self-hollowing injection techniques |
| T1071.001 | Web Protocols | HTTP POST C2 to /api/v1/register and /api/v1/output |
| T1014 | Rootkit | Ftrace-based syscall hooking hiding processes, modules, and network connections |
| T1070.006 | Timestomp | Linux variant modifies file timestamps |
| T1082 | System Information Discovery | sysinfo and netinfo commands in SPECTRE command set |
| T1057 | Process Discovery | ps command in SPECTRE command set |

## Impact Assessment

**Breadth:** Target list of approximately 170,000 URLs across 5 countries (Brazil, Bolivia, China, Canada, Vietnam), focused on internet-facing IIS and Linux servers. The BadIIS MaaS model enables broad distribution.

**Depth:** Full system compromise -- kernel-level rootkit (Linux), EDR blindness (Windows BYOVD), credential theft, and persistent C2. The rootkit achieves UID 0 escalation and can hide arbitrary processes, modules, and network connections from userspace tools.

**Stealth:** Very high. The BYOVD module disables visibility for CrowdStrike Falcon, SentinelOne, and Microsoft Defender by unlinking kernel callbacks. The Linux rootkit hides from standard process and module enumeration. NTFS ADS abuse avoids standard file listings.

**AI dimension:** First documented use of AI-assisted code generation in kernel-mode offensive tooling, lowering the barrier for rootkit development.

## Detection & Remediation

### Immediate Detection

**Windows:**
```
# Check for SPECTRE named pipes
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -like "spectre_*" }

# Check for NTFS ADS on hosts file
Get-Item -Path "C:\Windows\System32\drivers\etc\hosts" -Stream * | Where-Object { $_.Stream -eq "cache" }

# Check for BYOVD drivers loaded
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[EventData[Data[@Name='ImageLoaded'] and (contains(Data,'RTCore64.sys') or contains(Data,'DBUtil_2_3.sys'))]]"
```

**Linux:**
```bash
# Check for rootkit kernel module
lsmod | grep acpi_pad
# Note: if rootkit is active, it hides itself from lsmod -- check dmesg for ftrace registration
dmesg | grep -i "ftrace\|acpi_pad\|FTRACE_OPS_FL_IPMODIFY"

# Check for suspicious systemd service
systemctl status hardware-monitor.service
cat /etc/systemd/system/hardware-monitor.service
```

### Remediation

1. **Containment:** Isolate affected systems from the network immediately. The rootkit's process/network hiding makes live forensics unreliable -- boot from trusted media.
2. **BYOVD driver removal:** Block RTCore64.sys and DBUtil_2_3.sys via Windows Defender Application Control (WDAC) or driver block policies. Microsoft maintains a vulnerable driver blocklist -- ensure it is enabled.
3. **Credential rotation:** Assume all credentials on compromised hosts are exfiltrated. Rotate SAM hashes, domain credentials, browser-stored passwords, and vault credentials.
4. **Kernel module cleanup (Linux):** Boot from trusted media; remove `acpi_pad.ko` from module directories; remove `hardware-monitor.service`; rebuild initramfs if tampered.
5. **Web shell removal:** Search for ASHX handlers with `X-ID` header validation or `x9` parameter processing. Check CodeDomProvider in-memory compilation artifacts.
6. **IOC sweep:** Block all network IOCs (IPs, domains) at firewall/proxy. Search for all 47 SHA256 hashes across endpoints.

### Long-Term Hardening

- **Vulnerable driver blocklist:** Enable and maintain the Microsoft recommended driver block list via WDAC.
- **Kernel module signing:** Enforce kernel module signature verification on Linux (Secure Boot + module.sig_enforce=1). Note: this is advisory -- efficacy depends on boot configuration and whether modules are built-in.
- **EDR callback monitoring:** Deploy integrity monitoring for kernel callback registration tables.
- **Web server hardening:** Patch all known CVEs in internet-facing services; restrict ASHX handler deployment; implement WAF rules for suspicious headers (X-ID, x9).
- **ADS monitoring:** Enable Sysmon with FileCreateStreamHash (Event ID 15) to detect NTFS ADS creation on sensitive files.

## Detection Rules

These detections target SPECTRE implant artifacts at the specific/advisory altitude: BYOVD driver loading, named pipe creation, credential dumping, rootkit persistence, NTFS ADS abuse, C2 endpoint communication, and known C2 domains. All rules key on distinctive, campaign-specific indicators. Compiles != fires -- verify in your pipeline with representative telemetry.

### Sigma: SPECTRE BYOVD Vulnerable Driver Loading

Detects loading of RTCore64.sys or DBUtil_2_3.sys vulnerable drivers used by SPECTRE for BYOVD-based EDR callback unlinking.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE ATT&CK network fetch (proxy 403); sigma convert splunk 0, log_scale 0 — proves syntax+portability. CVE-2019-16098 (RTCore64) and CVE-2021-21551 (DBUtil) are well-documented BYOVD vectors; driver filenames are specific. FP: legitimate MSI Afterburner or Dell BIOS utility (rare in enterprise, easily filtered). -->
```yaml
title: SPECTRE BYOVD Vulnerable Driver Loading
id: 7e3a91c4-d2f8-4b5e-9c1a-3f6d8e2b7a05
status: experimental
description: >
    Detects loading of known vulnerable drivers (RTCore64.sys, DBUtil_2_3.sys) used by
    SPECTRE implant for BYOVD-based EDR callback unlinking. UAT-10147 downloads these
    drivers from C2 to achieve arbitrary kernel read/write.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
    - https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt
author: Actioner
date: 2026/08/23
tags:
    - attack.t1068
    - attack.t1562.001
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
    - Legitimate MSI Afterburner or Dell BIOS utility installations (rare in enterprise)
level: high
```

### Sigma: SPECTRE Implant Named Pipe Creation

Detects creation of the `\spectre_<tid>` named pipe used by SPECTRE for privilege escalation via token impersonation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Pipe name prefix "spectre_" is unique to this implant family; no known legitimate software uses this pattern. -->
```yaml
title: SPECTRE Implant Named Pipe Creation
id: 1b4c8d5f-a7e3-4f92-8d6b-2e9c1a3f5d70
status: experimental
description: >
    Detects creation of named pipes matching the SPECTRE implant pattern
    (\\.\pipe\spectre_<tid>), used for privilege escalation via token
    impersonation on Windows.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/23
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
    - Unlikely - pipe name is unique to SPECTRE implant
level: critical
```

### Sigma: SPECTRE SAM/SYSTEM/SECURITY Hive Dumping

Detects reg.exe save operations targeting SAM, SYSTEM, or SECURITY hives consistent with SPECTRE's hashdump credential theft module.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Detection keys on reg.exe + "save" + hive path combination. This is a known credential dumping technique (T1003.002); the combination of all three hives in one session is highly suspicious. FP: legitimate backup/forensic operations by sysadmins (filter by user context). -->
```yaml
title: SPECTRE SAM/SYSTEM/SECURITY Hive Dumping
id: 3c9e2f1a-b5d7-4e83-a6c0-8d4f7b2e1a93
status: experimental
description: >
    Detects SPECTRE's credential theft module dumping SAM, SYSTEM, and SECURITY
    registry hives via reg.exe save operations, consistent with the hashdump
    command observed in UAT-10147 intrusions.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/23
tags:
    - attack.t1003.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_tool:
        Image|endswith: '\reg.exe'
        CommandLine|contains: 'save'
    selection_hives:
        CommandLine|contains:
            - 'HKLM\SAM'
            - 'HKLM\SYSTEM'
            - 'HKLM\SECURITY'
    condition: selection_tool and selection_hives
falsepositives:
    - Legitimate backup or forensic operations by system administrators
level: high
```

### Sigma: SPECTRE Linux Rootkit Systemd Persistence

Detects creation of the hardware-monitor.service systemd unit used by SPECTRE's rootkit for early-boot persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Service name "hardware-monitor" with Description "Hardware Performance Monitor" is specific to SPECTRE rootkit persistence. FP: custom monitoring daemon with this exact service name (unlikely). -->
```yaml
title: SPECTRE Linux Rootkit Systemd Persistence
id: 5d2b4e7c-8f1a-4c69-b3d5-6a9e0f2c8b14
status: experimental
description: >
    Detects creation of the hardware-monitor.service systemd unit used by
    SPECTRE's Linux rootkit for persistence. The service is configured with
    Before=sysinit.target to load early in the boot process.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/23
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains: 'hardware-monitor.service'
    condition: selection
falsepositives:
    - Custom hardware monitoring services with this exact name (unlikely)
level: high
```

### Sigma: SPECTRE C2 Configuration via NTFS Alternate Data Stream

Detects file operations on the `hosts:cache` NTFS ADS used by SPECTRE to store updatable C2 configuration.
**Status:** compile ✅ compiles · confidence: critical
<!-- audit: sigma convert splunk 0, log_scale 0. ADS on the hosts file is not standard behavior; "cache" stream name on \drivers\etc\hosts is unique to SPECTRE. Requires Sysmon EID 15 (FileCreateStreamHash) or equivalent ADS-aware telemetry. -->
```yaml
title: SPECTRE C2 Configuration via NTFS Alternate Data Stream
id: 9a8f6d3b-c1e5-4a72-b7d9-2f0e8c4a6b31
status: experimental
description: >
    Detects file operations on the NTFS Alternate Data Stream
    hosts:cache used by SPECTRE to store and update C2 configuration,
    circumventing firewall-level domain blocks.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026/08/23
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
    - Unlikely - ADS on the hosts file is not standard behavior
level: critical
```

### Snort: SPECTRE C2 Beacon POST Endpoints

Detects HTTP POST requests to SPECTRE's C2 registration and output exfiltration endpoints.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c snort-test.conf -T exit 0 (Snort 2.9.20). URI patterns /api/v1/register and /api/v1/output are generic REST patterns that may appear in legitimate APIs; confidence medium due to FP potential. Pair with source/destination IP context for higher confidence. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - SPECTRE C2 Beacon POST to /api/v1/register"; flow:established,to_server; content:"POST"; http_method; content:"/api/v1/register"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; sid:2100101; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - SPECTRE C2 Beacon POST to /api/v1/output"; flow:established,to_server; content:"POST"; http_method; content:"/api/v1/output"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; sid:2100102; rev:1;)
```

### Suricata: SPECTRE C2 Beacon POST Endpoints

Detects HTTP POST requests to SPECTRE's C2 registration and output exfiltration endpoints using Suricata dot-notation buffers.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S exit 0 (Suricata 7.0.3). Same FP caveat as Snort -- /api/v1/register and /api/v1/output are generic REST paths. Best paired with destination IP/domain context. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SPECTRE C2 Registration Beacon POST /api/v1/register"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/v1/register"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-23; sid:2200101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SPECTRE C2 Output Exfiltration POST /api/v1/output"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/v1/output"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata:author Actioner, created_at 2026-08-23; sid:2200102; rev:1;)
```

### Suricata: SPECTRE Known C2 Domain DNS Queries

Detects DNS queries to known UAT-10147 C2 domains from the published IOC list.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0 (Suricata 7.0.3). Domains are from published Talos IOC repository. Rotate as infrastructure changes; current as of 2026-08-23. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - SPECTRE C2 DNS Query to Known UAT-10147 Domain niupilao.vip"; flow:to_server; dns.query; content:"niupilao.vip"; nocase; fast_pattern; classtype:trojan-activity; reference:url,github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt; metadata:author Actioner, created_at 2026-08-23; sid:2200103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - SPECTRE C2 DNS Query to Known UAT-10147 Domain udvyiwvfs.cyou"; flow:to_server; dns.query; content:"udvyiwvfs.cyou"; nocase; fast_pattern; classtype:trojan-activity; reference:url,github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt; metadata:author Actioner, created_at 2026-08-23; sid:2200104; rev:1;)
```

### YARA: SPECTRE Windows Implant

Detects SPECTRE Windows PE implant via characteristic PDB paths containing Chinese development strings, named pipe pattern, and C2 endpoint strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos-windows.txt matched (PDB Chinese string + pipe + api endpoint trigger); neg-windows.txt clean. PDB strings are from published Talos analysis and are unique to this actor. Condition requires MZ header + size cap + distinctive string combinations. -->
```yara
rule Malware_SPECTRE_Windows_Implant
{
    meta:
        description = "Detects SPECTRE Windows implant via characteristic PDB paths, named pipe pattern, and API resolution strings associated with UAT-10147"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pdb1 = "x神订制全站劫持按浏览器语言跳转" ascii wide
        $pdb2 = "x神的自安装服务" ascii wide
        $pdb3 = "svchost\\x64\\Release\\service.pdb" ascii
        $pipe = "\\\\.\\pipe\\spectre_" ascii wide
        $api_register = "/api/v1/register" ascii
        $api_output = "/api/v1/output" ascii
        $ads = "drivers\\etc\\hosts:cache" ascii wide
        $web_header = "X-ID" ascii
        $web_param = "x9" ascii
        $efspotato = "EfsPotato" ascii wide
        $cmd_hashdump = "hashdump" ascii
        $cmd_chromedump = "chromedump" ascii
        $cmd_vaultdump = "vaultdump" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($pdb*) or
            ($pipe and 1 of ($api*)) or
            (3 of ($cmd*, $ads, $web_header, $web_param, $api_register, $api_output, $efspotato))
        )
}
```

### YARA: SPECTRE Linux Rootkit Kernel Module

Detects the SPECTRE "Specter" Linux rootkit kernel module via ftrace hooking function names, signal-based IPC references, and acpi_pad disguise strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos-linux.txt matched (3 hook function names trigger); neg-linux.txt clean. Hook function names (hooked_tcp6_seq_show, etc.) are from published Talos analysis of rootkit source. Condition requires ELF header or acpi_pad string + combination of hook/ftrace/persistence strings. -->
```yara
rule Rootkit_SPECTRE_Linux_Kernel_Module
{
    meta:
        description = "Detects SPECTRE Linux rootkit kernel module (Specter/acpi_pad.ko) via ftrace hooking strings, signal-based IPC magic values, and hooked syscall handler names"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $hook1 = "hooked_tcp6_seq_show" ascii
        $hook2 = "hooked_tcp4_seq_show" ascii
        $hook3 = "hooked_tkill" ascii
        $hook4 = "hooked_tgkill" ascii
        $hook5 = "hooked_kill" ascii
        $hook6 = "hooked_getdents64" ascii
        $ftrace = "FTRACE_OPS_FL_IPMODIFY" ascii
        $mod_name = "acpi_pad" ascii
        $svc = "hardware-monitor" ascii
        $desc = "Hardware Performance Monitor" ascii
        $magic_hex = { 69 7A 00 00 }

    condition:
        (uint32(0) == 0x464C457F or $mod_name) and
        (
            (3 of ($hook*)) or
            ($ftrace and 1 of ($hook*)) or
            ($mod_name and $svc and $desc) or
            (2 of ($hook*) and $magic_hex)
        )
}
```

## Lessons Learned

1. **AI lowers the rootkit barrier.** The SPECTRE rootkit contains clear AI-generated code artifacts -- pedagogical comments, machine-uniform formatting, labeled "Method 1/2/3" patterns. This is the first documented case of AI-assisted kernel-mode offensive tooling at scale. Kernel rootkits are no longer exclusive to top-tier APT groups.

2. **BYOVD remains a systemic blind spot.** SPECTRE's use of RTCore64.sys and DBUtil_2_3.sys to unlink EDR kernel callbacks blinds CrowdStrike, SentinelOne, and Defender simultaneously. The vulnerable driver blocklist exists but is not universally enforced. Organizations should enable WDAC-based driver blocking as a priority.

3. **Cross-platform parity is operational.** SPECTRE maintains functional parity across Windows (45 commands) and Linux (29 commands + rootkit), indicating the actor treats both platforms as equally viable targets. Linux-first persistence (systemd + kernel module) is sophisticated and resistant to standard detection.

4. **NTFS ADS is undermonitored.** Storing C2 configuration in `hosts:cache` ADS is a simple but effective evasion technique. Most organizations lack ADS monitoring (Sysmon EID 15 or equivalent). This is a low-cost, high-impact detection gap to close.

## Sources

- [Cisco Talos - UAT-10147 Deploys SPECTRE](https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/) -- primary technical analysis of SPECTRE implant, rootkit, and BYOVD capabilities
- [Cisco Talos - UAT-10147 AI-Assisted Exploitation](https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/) -- prior report on AI-assisted exploitation workflows, infrastructure details, and initial access techniques
- [Cisco Talos IOC Repository (GitHub)](https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt) -- complete IOC list including 47 SHA256 hashes, 4 IPs, 13 domains
- [it-learn.io - AI-Assisted Rootkits Arrive](https://blog.it-learn.io/posts/2026-08-20-ai-assisted-rootkits-arrive-uat-10147-spectre-campaign/) -- independent coverage with detection guidance and Splunk queries
- [Vulners - UAT-10147 SPECTRE Entry](https://vulners.com/talosblog/TALOSBLOG:23821417B443FA3AC0D458609330F0CA) -- vulnerability database cross-reference

---
*Report generated by Actioner*
