<!-- revision: v2.0 2026-08-20 — FINAL. Applied critic verdict: Sigma 1 narrowed with X-ID:x9 header filter; Sigma 6 (generic reg.exe hive dump) dropped as community-duplicate; YARA 2 ftrace_flag made optional (macro resolves to constant at compile time); YARA 3 condition tightened to require $ashx2 (X-seo); Snort 1-2 and Suricata 1-2 X-ID value check added; Snort IOC domains expanded to cover all 7 IOC domains; Suricata DNS added healthsave.net; MITRE T1036 corrected to T1036.005; remediation corrected Sysmon/WDAC driver blocking guidance. 7 Sigma, 3 YARA, 8 Snort, 8 Suricata rules. -->
# Technical Analysis Report: SPECTRE Cross-Platform Implant Deployed by UAT-10147 (2026-08-20)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-20
Version: 2.0 (FINAL)

## Executive Summary

SPECTRE is a sophisticated cross-platform post-exploitation implant deployed by UAT-10147, a Chinese-speaking intrusion actor. First documented by Cisco Talos on August 20, 2026, the implant targets both Windows and Linux servers with a unified command-and-control architecture derived from the open-source Havoc framework. The campaign is notable for three distinguishing capabilities: (1) a Linux kernel rootkit ("Specter") that abuses the ftrace instrumentation framework for stealth, (2) a Windows BYOVD (Bring Your Own Vulnerable Driver) module that unlinks EDR kernel callbacks using CVE-2019-16098 (RTCore64.sys) and CVE-2021-21551 (DBUtil_2_3.sys), and (3) AI-assisted malware development workflows evidenced by PDB strings and code structure patterns.

UAT-10147 targets internet-facing IIS and Linux servers at scale, with a geographic focus on Vietnamese infrastructure. The actor operates a dual-purpose ecosystem combining espionage-grade implant deployment with SEO fraud monetization through the BadIIS malware-as-a-service platform. The SPECTRE implant provides 45 commands on Windows (24 plaintext, 21 encrypted) and 29 on Linux, encompassing credential theft, keylogging, process injection, token manipulation, and rootkit-mediated privilege escalation.

## Background

UAT-10147 is a Chinese-speaking threat actor tracked by Cisco Talos operating a multi-platform post-exploitation ecosystem. The actor has been linked to prior campaigns involving AI-assisted exploitation workflows and the BadIIS malware-as-a-service infrastructure. Development artifacts -- including PDB paths containing Chinese characters (e.g., "x\xe7\xa5\x9e" / x-shen) and build paths with dedicated "AI" folders -- indicate a developer-operator model where custom tooling is augmented by AI-assisted code generation.

The SPECTRE implant is architecturally derived from the open-source Havoc C2 framework but has been extensively customized with proprietary rootkit, BYOVD, and anti-sandbox capabilities. The actor's targeting focuses on Vietnamese infrastructure, evidenced by "vn[.]xyz" suffix domains, targeting of the Coc Coc browser (Vietnamese-specific), and derogatory Vietnamese strings embedded in campaign identifiers.

## Attack Timeline

| Phase | Event |
|-------|-------|
| Reconnaissance | Target identification of internet-facing IIS and Linux servers |
| Initial Access | Exploitation of internet-facing server vulnerabilities |
| Execution | SPECTRE implant deployment (platform-appropriate variant) |
| Anti-Analysis | Weighted 50-point anti-sandbox scoring; silent exit on failure |
| Persistence | Windows: service installation via SCM; Linux: systemd unit (hardware-monitor.service) |
| Privilege Escalation | Windows: named pipe impersonation + Potato family tools; Linux: rootkit UID 0 overwrite |
| Defense Evasion | Windows: BYOVD EDR callback unlinking; Linux: ftrace-based syscall hooking |
| Rootkit Deployment | Linux: acpi_pad.ko kernel module loaded, process/module hiding activated |
| Credential Theft | hashdump (SAM/SYSTEM/SECURITY), chromedump, vaultdump, token theft |
| C2 Establishment | HTTP POST beaconing to /api/v1/register and /api/v1/output endpoints |
| Monetization | BadIIS/ASHX SEO fraud engine deployment on compromised web servers |
| Exfiltration | Stolen credentials and system data exfiltrated over C2 channel |

## Root Cause / Initial Access

Initial access is achieved through exploitation of internet-facing IIS web servers and Linux servers. The exact vulnerabilities exploited for initial access are not specified in the primary source, but the actor's known operational pattern involves targeting unpatched or misconfigured internet-facing services. Once access is obtained, the SPECTRE implant is deployed along with auxiliary tooling including Potato-family privilege escalation tools (GodPotato, JuicyPotato, EfsPotato, RustPotato) and BadIIS web shell components.

## Technical Analysis

### 1. SPECTRE Implant Architecture

SPECTRE is a cross-platform C2 implant derived from the Havoc framework, compiled as a native Windows PE or statically-linked ELF x86-64 binary for Linux. The implant uses HTTP POST-based C2 communication with JSON payloads over two endpoints: `/api/v1/register` (initial beacon registration) and `/api/v1/output` (command output exfiltration). An `X-ID` HTTP header with value `x9` is used for beacon authentication.

**Windows variant (45 commands):** 24 plaintext commands and 21 encrypted commands. Notable capabilities include:
- `shell` -- command execution via Windows Command Shell
- `execute_assembly` -- in-memory .NET CLR hosting for assembly execution
- `inject` -- three modalities of process injection (process hollowing into svchost.exe by default, APC EarlyBird injection)
- `hashdump` -- SAM/SYSTEM/SECURITY registry hive extraction to %TEMP%
- `chromedump` -- Chrome and Edge credential theft via offline DPAPI decryption (SharpChrome)
- `vaultdump` -- Windows Credential Manager enumeration via cmdkey.exe
- `steal_token` / `make_token` -- token impersonation and credential-based token spawning
- `keylog_start` / `keylog_stop` / `keylog_dump` -- process-targeted keystroke logging
- `regset` -- registry modification for persistence
- `sleep` -- configurable beacon interval

**Linux variant (29 commands):** No encrypted/obfuscated command names. Includes standard reconnaissance (`sysinfo`, `ps`, `netinfo`, `whoami`, `id`, `env`, `pwd`, `cd`, `ls`, `cat`), file operations (`upload`, `download`), and rootkit interaction commands (`rootkit_*` suite).

### 2. Self-Hollowing and Process Injection

On startup, the Windows SPECTRE implant performs self-hollowing into RuntimeBroker.exe, replacing its own process image with a legitimate Windows binary to evade casual process listing inspection. Three process injection modalities are available:
- **Process Hollowing:** Default target is svchost.exe; creates a suspended process, unmaps the original image, and writes the implant code
- **APC EarlyBird Injection:** Pre-allocation technique that queues an APC before the target thread's first instruction executes
- **Standard Injection:** Conventional VirtualAllocEx/WriteProcessMemory/CreateRemoteThread pattern

### 3. Anti-Sandbox and Anti-Analysis

**Windows (weighted scoring, 50-point threshold):** A composite anti-sandbox scoring routine evaluates multiple environmental factors. If the cumulative score reaches 50 points, the implant exits silently. Factors include:
- Process name blocklist checking (analysis tools)
- RAM capacity validation
- CPU core count validation
- Disk space assessment
- Sleep acceleration detection (timing-based sandbox detection)
- Sandbox hostname/username enumeration

**Linux (eight-factor engine):** An equivalent anti-analysis engine with eight evaluation criteria adapted for Linux environments.

**String Obfuscation:** All API references are resolved via PEB hash walking using a DJB2 hash variant. Strings are encrypted at compile time using a per-string xorshift32 PRNG scheme with unique 32-bit seeds. Decryption occurs in thread-local storage, ensuring no plaintext strings exist in .text or .rdata sections.

### 4. BYOVD EDR Bypass (Windows)

SPECTRE includes a BYOVD (Bring Your Own Vulnerable Driver) module that exploits two known vulnerable signed drivers to gain arbitrary kernel read/write primitives:

- **RTCore64.sys** (MSI Afterburner) -- CVE-2019-16098, CVSS 7.8: Allows any authenticated user to read and write arbitrary memory, I/O ports, and MSRs
- **DBUtil_2_3.sys** (Dell) -- CVE-2021-21551, CVSS 7.8: Insufficient IOCTL access control enabling privilege escalation

The exploitation sequence:
1. Download vulnerable driver from C2 server
2. Decode and write to %TEMP%
3. Install as transient kernel service via Service Control Manager
4. Open IOCTL device handle for arbitrary read/write
5. Calculate ntoskrnl.exe kernel virtual address using per-build offset tables (supporting 13 Windows versions)
6. Unlink EDR kernel callbacks: `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine`

This effectively "blinds" EDR products (including CrowdStrike Falcon, SentinelOne, Microsoft Defender) to process creation, thread creation, and image load events.

### 5. Linux Rootkit -- "Specter" (acpi_pad.ko)

The Specter rootkit disguises itself as the legitimate ACPI processor power management kernel module `acpi_pad.ko`. It uses the ftrace instrumentation framework with the `FTRACE_OPS_FL_IPMODIFY` flag to hook kernel functions, a technique that generates minimal noise against kernel integrity checking mechanisms because ftrace is a legitimate kernel debugging interface.

**Hooked syscall handlers:**
- `hooked_tcp4_seq_show` / `hooked_tcp6_seq_show` -- hide network connections from /proc/net/tcp
- `hooked_getdents64` -- hide files and directories from directory listings
- `hooked_kill` / `hooked_tkill` / `hooked_tgkill` -- intercept signals for IPC with the implant

**Signal-based IPC (magic PID 0x7A69 / 31337 decimal):**
Kill syscalls targeting PID 0x7A69 are intercepted as IPC commands:
- **Signal 62:** Process hiding -- removes task_struct from kernel PID list, making the process invisible in /proc/\<pid\> and to ps
- **Signal 36:** Module hiding -- unlinks THIS_MODULE from the module list, hiding from lsmod
- **Signal 37:** UID 0 escalation -- directly overwrites the calling process's credential structure to grant root privileges
- **Signal 35:** Module load acknowledgement handshake

**Persistence:** Installed as systemd unit "Hardware Performance Monitor" (`hardware-monitor.service`) with `Before=sysinit.target` directive for pre-boot execution priority.

### 6. BadIIS Web Shell and SEO Monetization

UAT-10147 deploys a dual-layer ASHX web shell architecture on compromised IIS servers:
- **Loader layer:** Obfuscated string reversal with Base64 decoding, in-memory dynamic compilation via CodeDomProvider
- **Handler layer:** Static assembly caching with double-checked locking, numeric parameter dispatch
- **Evasion:** Returns fake "404 Not Found" responses on authentication failure; uses `X-seo` configuration string for the SEO engine

The SEO fraud engine redirects search engine traffic through compromised servers, providing an additional monetization stream beyond espionage operations.

### 7. Credential Access

- **hashdump:** Exports SAM (`HKLM\SAM\SAM`), SYSTEM (`HKLM\SYSTEM`), and SECURITY (`HKLM\SECURITY`) registry hives to %TEMP% for offline credential extraction
- **chromedump:** Copies Chrome and Edge Login Data and Local State files for offline DPAPI decryption using SharpChrome
- **vaultdump:** Enumerates Windows Credential Manager via cmdkey.exe without touching LSASS
- **steal_token:** Steals access tokens from target PIDs
- **make_token:** Creates tokens from supplied credentials

### 8. C2 Protocol

- **Transport:** HTTP POST over standard HTTP ports
- **Endpoints:** `/api/v1/register` (beacon registration), `/api/v1/output` (data exfiltration)
- **Payload format:** JSON
- **Authentication:** `X-ID` header with value `x9`
- **C2 domain storage:** Hardcoded (encrypted) in the binary; updatable via NTFS Alternate Data Stream at `C:\Windows\System32\drivers\etc\hosts:cache` (allows domain changes without recompilation)
- **Beacon interval:** Configurable via `sleep` command; jitter support on Linux variant

## Indicators of Compromise

### Network Indicators

**Domains:**
- jyzyps[.]com
- mma888[.]cc
- healthsave[.]net
- vip8888vn[.]xyz
- b[.]niupilao[.]vip
- vip[.]niupilao[.]vip
- udvyiwvfs[.]cyou

**IP Addresses:**
- 27[.]124[.]2[.]46
- 27[.]124[.]2[.]48
- 27[.]124[.]2[.]52
- 139[.]180[.]197[.]150

**URLs:**
- hxxps://js[.]jyzyps[.]com/js/vnnb.js
- hxxps://js[.]jyzyps[.]com/js/nb.js
- hxxp://vn[.]mma888[.]cc/
- hxxp://thceshi[.]healthsave[.]net
- hxxp://www[.]xxxx[.]vip
- hxxp://spider[.]xxxx[.]com

**C2 Endpoints:**
- `/api/v1/register` (POST -- beacon registration)
- `/api/v1/output` (POST -- data exfiltration)

### Host Indicators

**File Paths:**
- `C:\Windows\System32\drivers\etc\hosts:cache` (NTFS ADS C2 config)
- `acpi_pad.ko` (Linux rootkit kernel module)
- `hardware-monitor.service` (Linux systemd persistence unit)
- `RTCore64.sys` (BYOVD driver -- CVE-2019-16098)
- `DBUtil_2_3.sys` (BYOVD driver -- CVE-2021-21551)

**PDB Strings (Development Artifacts):**
- `C:\Users\Administrator\Desktop\2025-11-21 (x神订制全站劫持按浏览器语言跳转)\dll\Release\demo.pdb`
- `C:\Users\Administrator\Desktop\x神的自安装服务\svchost\x64\Release\service.pdb`
- `C:\Users\iis\Desktop\AI\EfsPotatoCpp\x64\Release\EfsPotato.pdb`
- `C:\Users\Intel\Desktop\AI\EfsPotatoCPP\x64\Debug\EfsPotato.pdb`

**Process Indicators:**
- Self-hollowing target: `RuntimeBroker.exe` (from non-standard parent)
- Default injection target: `svchost.exe`
- Magic PID for rootkit IPC: `0x7A69` (31337)

### File Hashes (SHA256)

**SPECTRE Implant and Associated Tooling:**

| SHA256 | Context |
|--------|---------|
| 008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2 | SPECTRE/UAT-10147 tooling |
| 11ccfdfb0dfe782ba0eeabaa8e65619a792f9258476a072b774ef19a5240b944 | SPECTRE/UAT-10147 tooling |
| 1c2edfb1b280fdc570591c88da5b1adbd249be6b8cc306a42525a515adaf73e8 | SPECTRE/UAT-10147 tooling |
| 21274d668e28b01172fa326f42e396b825708ddc2336ae388d6729627c525775 | SPECTRE/UAT-10147 tooling |
| 43124b72616ef38b0c8a07b167e971b0e4479626fb5ef2303b2ed993e21f6c4c | SPECTRE/UAT-10147 tooling |
| 50d88f3d8f91f18195f1e9948cf6b47d69d7e19226957b1e7e3b2e4bd7c4fef4 | SPECTRE/UAT-10147 tooling |
| 59a386b75b84f137c4e17c37e3430fc93c0184102b3fbdfe649cef2e0335d85b | SPECTRE/UAT-10147 tooling |
| 684e7ed556dcc9e2fe24fcfd73e6b9c29d7126584f87c5331c2607d39e29329f | SPECTRE/UAT-10147 tooling |
| 76df454fe87620dd59efb483a56a8b573c7d16207635cf2616a67e25dab57779 | SPECTRE/UAT-10147 tooling |
| 77cce6576f93961651133b543948ea3853cc2f06b8c3fd523f6858d6d18ad775 | SPECTRE/UAT-10147 tooling |
| 830c6ca21a7da0eed436f8371c8a86baa62ab857a5478a222dd3189645d4d084 | SPECTRE/UAT-10147 tooling |
| 91d00ca46d1013c031aa8ff2e54b7b3496bac78f6147842766bffd4d32a2e042 | SPECTRE/UAT-10147 tooling |
| 7565a5bc56fcd94c7f52cf7428747cd4f52d0d3b485900d3d9b06b470ccba23b | SPECTRE/UAT-10147 tooling |
| b74beab9dac9ee7853b5e846eec6f778db01867b49f64d6be259ea9e19006121 | SPECTRE/UAT-10147 tooling |
| bfbd1aa2c0ace1575e86dc5cedc0754e4ae4aae97e70ac9f0523a2e8e8b22ed9 | SPECTRE/UAT-10147 tooling |
| c88dab534081650d5a385f9bc5c61eced41b4e9fe63ace6173aa536c4aaffa67 | SPECTRE/UAT-10147 tooling |
| cf0a6353f1fccf63fca02ed41eafd3da8d55f77b8b4c45666a37fa3cdc33da55 | SPECTRE/UAT-10147 tooling |
| 41f1514ad52c870bc4b51291cb939067e8ace23ec308419253ee0a2497bf2e21 | SPECTRE/UAT-10147 tooling |
| dd4c16c65513c3eb66691f87d5bb5595d38554395ec89be2b9e325e013ef53d5 | SPECTRE/UAT-10147 tooling |
| dee976f262498184d746cc8305cc9e6905ad762c661df8d7daec120f14060b41 | SPECTRE/UAT-10147 tooling |
| 2e9f10f5cc9fb5c9f935ee78a21de70168e398b7a47db54373a5dcb19c485398 | SPECTRE/UAT-10147 tooling |
| e315f955a9b44a9c875d2e47f2a91e9e77043bd553ad616ada38eaf669d44b2e | SPECTRE/UAT-10147 tooling |
| 58725b8e592435026928c39622f41b7ad4f4dc62e353eb459c3b4858eafd9e82 | SPECTRE/UAT-10147 tooling |
| 544a7d9d4de3904ad35e6cc87f34cb556fda722c3d3cae1a6334645f1a950cc7 | SPECTRE/UAT-10147 tooling |
| 9a8e9d587b570d4074f1c8317b163aa8d0c566efd88f294d9d85bc7776352a28 | SPECTRE/UAT-10147 tooling |
| 722bd55e1496cb614f4f365a4203da6166c637f2c6b9ec0da3844637bc6e9e9d | SPECTRE/UAT-10147 tooling |
| 0345406e85aa7759c0af0372c23de0c5f3e9b6d53e970405e5c168f55c51a7e0 | SPECTRE/UAT-10147 tooling |
| 23a7adda56e2e5519e01f57f16f99e4be611aac4fa908f2ee2d99e3d96e14865 | SPECTRE/UAT-10147 tooling |
| 9619259c1ea9b1c6b8279fdb761018b14a41acc94f67f1469bf68bf393b4ba74 | SPECTRE/UAT-10147 tooling |
| f07d869ddd17d4359e26da43574d0d07987b500a390196b72b3c1747a4cbb3bf | SPECTRE/UAT-10147 tooling |
| d0da3be9de8e7068a65247b8195d73e88f454820e13c1de62675e1f845d6fabf | SPECTRE/UAT-10147 tooling |
| 0f56c703e9b7ddeb90646927bac05a5c6d95308c8e13b88e5d4f4b572423e036 | SPECTRE/UAT-10147 tooling |
| 35c960bda30ceeb22216fad7776b43ecf44aaccf2ff7f600f91a1afb49a8a43c | SPECTRE/UAT-10147 tooling |
| 7172ebfb4e96e3b0bff59e87f670c5512144d445b276746c8c78593272720ebf | SPECTRE/UAT-10147 tooling |
| b02664c71d1a40760ff6eb253d1a9022d93262698d528d95e8983bf848b8827b | SPECTRE/UAT-10147 tooling |
| dbe956ae1135e81ae06220393ee80caacc62006295a1fb26e87f048a7a78b81b | SPECTRE/UAT-10147 tooling |
| 4bbba075f56ee15760b1397100a82f2c7425b866cf1a35684fda5b712783f97b | SPECTRE/UAT-10147 tooling |
| 1c70b2a55b6f3a3382f40fe15293b609d047103b0c6c7da0049f7c0e365ea880 | SPECTRE/UAT-10147 tooling |
| fc54b68f0a375600c8ab23d894b56837db287b32209c0a455fb439a780593c80 | SPECTRE/UAT-10147 tooling |
| b0c1c3b806a60807854173f2199ba49baf5c2729051b14e4725cb90cfc755519 | SPECTRE/UAT-10147 tooling |
| 089b19f7760a53272f580432460dc959cbb8ffb87bde43152795ff5d893debdd | SPECTRE/UAT-10147 tooling |
| 1fc83b41d201bfbc4db94e332e0c770be9d74591d9817c1b938ccdf17c7a48a9 | SPECTRE/UAT-10147 tooling |
| fea09e46f6adf23aa17c56faa14d19168b5417ed90d7b2b36f2c8dd5f6014ea7 | SPECTRE/UAT-10147 tooling |
| 061b765659bf24b62d242d4f8ca9a9884037e186714517509a8f48b54e1123a0 | SPECTRE/UAT-10147 tooling |

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | SPECTRE Usage |
|-------------|----------------|---------------|
| T1190 | Exploit Public-Facing Application | Initial access via IIS/Linux server exploitation |
| T1059.003 | Windows Command Shell | `shell` command execution |
| T1059.004 | Unix Shell | Linux `/bin/sh` execution |
| T1106 | Native API | PEB hash walking for API resolution |
| T1055.012 | Process Hollowing | Self-hollowing into RuntimeBroker.exe; injection into svchost.exe |
| T1543.003 | Windows Service | BadIIS service installation |
| T1543.002 | Systemd Service | hardware-monitor.service persistence |
| T1134.001 | Token Impersonation/Theft | steal_token command |
| T1134.003 | Make and Impersonate Token | make_token / named pipe impersonation |
| T1068 | Exploitation for Privilege Escalation | GodPotato, JuicyPotato, EfsPotato, RustPotato |
| T1014 | Rootkit | Specter kernel module (acpi_pad.ko) |
| T1562.001 | Disable or Modify Tools | BYOVD EDR callback unlinking |
| T1564.004 | NTFS File Attributes | C2 config in hosts:cache ADS |
| T1027 | Obfuscated Files or Information | xorshift32 PRNG string encryption |
| T1497.001 | System Checks (Virtualization/Sandbox Evasion) | 50-point weighted anti-sandbox scoring |
| T1003.002 | Security Account Manager | hashdump -- SAM/SYSTEM/SECURITY hive export |
| T1555.003 | Credentials from Web Browsers | chromedump -- Chrome/Edge DPAPI offline decryption |
| T1056.001 | Keylogging | keylog_start/stop/dump commands |
| T1082 | System Information Discovery | sysinfo command |
| T1057 | Process Discovery | ps command |
| T1071.001 | Web Protocols | HTTP POST C2 communication |
| T1041 | Exfiltration Over C2 Channel | download command, credential exfiltration |
| T1036.005 | Match Legitimate Name or Location | acpi_pad.ko mimicking legitimate ACPI kernel module |

## Impact Assessment

**Severity: Critical**

SPECTRE represents a high-capability post-exploitation framework with the following impact dimensions:

- **EDR Neutralization:** The BYOVD module can blind endpoint detection products by unlinking kernel callbacks across 13 Windows versions, enabling undetected follow-on operations
- **Persistent Root Access:** The Linux rootkit provides kernel-level persistence with process hiding, module hiding, and direct UID 0 escalation -- invisible to standard user-space monitoring tools
- **Credential Compromise:** Multiple credential harvesting vectors (registry hive dumps, browser credential theft, Windows Vault enumeration, token manipulation) enable lateral movement and persistent access
- **Cross-Platform Coverage:** Unified C2 architecture targets both Windows and Linux infrastructure, allowing the actor to maintain presence across heterogeneous environments
- **Anti-Forensic Design:** Per-string compile-time encryption, PEB hash walking, and memory-only execution patterns complicate incident response and malware analysis
- **Monetization Layer:** The BadIIS SEO fraud component provides the actor with an immediate revenue stream from compromised servers, incentivizing wider targeting

**Affected Industries:** Organizations running internet-facing IIS web servers or Linux servers, with particular focus on Vietnamese infrastructure.

## Detection & Remediation

### Immediate Detection Actions

1. **Network IOC sweep:** Search proxy/DNS logs for the domains listed in the IOC section (jyzyps[.]com, niupilao[.]vip, udvyiwvfs[.]cyou, vip8888vn[.]xyz, mma888[.]cc, healthsave[.]net) and IP addresses (27[.]124[.]2[.]46, 27[.]124[.]2[.]48, 27[.]124[.]2[.]52, 139[.]180[.]197[.]150)
2. **C2 endpoint detection:** Search HTTP logs for POST requests to `/api/v1/register` or `/api/v1/output` with `X-ID` header
3. **NTFS ADS inspection:** Check for the NTFS Alternate Data Stream at `C:\Windows\System32\drivers\etc\hosts:cache` using `dir /r` or PowerShell `Get-Item -Stream *`
4. **Driver audit:** Search for `RTCore64.sys` or `DBUtil_2_3.sys` loaded outside legitimate MSI Afterburner or Dell utility contexts
5. **Linux rootkit check:** Inspect for `hardware-monitor.service` systemd units and `acpi_pad.ko` loaded from non-standard paths; check for processes using signal IPC to PID 31337
6. **Hash-based scanning:** Deploy the 44 SHA256 hashes to EDR/AV for retrospective scanning

### Remediation

- Isolate and reimage any host with confirmed SPECTRE indicators; the rootkit's kernel-level presence means runtime forensics are unreliable
- Rotate all credentials accessible from compromised hosts (local accounts, domain accounts, browser-stored passwords, Windows Vault entries)
- Block all listed IOC domains and IPs at network perimeter
- Patch or remove RTCore64.sys (CVE-2019-16098) and DBUtil_2_3.sys (CVE-2021-21551) from all endpoints
- Deploy WDAC (Windows Defender Application Control) driver blocklist policies to prevent loading of known vulnerable drivers; use Sysmon Event ID 6 for driver load logging and detection, but note that Sysmon cannot block driver loads, only log them
- Audit IIS servers for unauthorized ASHX handlers and SEO-related modifications

## Detection Rules

### Sigma Rules

**Rule 1: SPECTRE C2 HTTP POST Endpoints**
Detects HTTP POST requests to the /api/v1/register and /api/v1/output C2 endpoints with the X-ID: x9 authentication header used by the SPECTRE implant.
- **Status:** compile: ✅ compiles (sigma convert splunk + log_scale) | confidence: high
<!-- revision: v2 — added X-ID:x9 header filter to reduce false positives from generic REST paths -->
<!-- audit: sigma convert --without-pipeline -t splunk spectre_c2_endpoints.yml -> exit 0; sigma convert --without-pipeline -t log_scale spectre_c2_endpoints.yml -> exit 0 -->

```yaml
title: SPECTRE Implant C2 HTTP POST to Registration and Output Endpoints
id: 7a3e1f4b-9c2d-4e5a-b8f7-1d6c3a2e5f09
status: experimental
description: Detects HTTP POST requests to SPECTRE implant C2 API endpoints with X-ID authentication header used for beacon registration and data exfiltration.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
    - https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt
author: Actioner
date: 2026-08-20
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: proxy
detection:
    selection:
        c-uri|endswith:
            - '/api/v1/register'
            - '/api/v1/output'
        cs-method: 'POST'
    selection_header:
        cs-header|contains: 'X-ID: x9'
    condition: selection and selection_header
falsepositives:
    - Legitimate applications using the same API paths with an X-ID: x9 header value (unlikely)
level: high
```

**Rule 2: SPECTRE NTFS ADS C2 Configuration Storage**
Detects file access to the NTFS Alternate Data Stream on the hosts file used for C2 domain configuration.
- **Status:** compile: ✅ compiles (sigma convert splunk + log_scale) | confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk spectre_ntfs_ads_c2_config.yml -> exit 0; sigma convert --without-pipeline -t log_scale spectre_ntfs_ads_c2_config.yml -> exit 0 -->

```yaml
title: SPECTRE C2 Configuration Storage via NTFS Alternate Data Stream on Hosts File
id: 2b8d4e6f-1a3c-5d7e-9f0b-4c2a8e6d1f3b
status: experimental
description: Detects access to an NTFS Alternate Data Stream on the hosts file used by SPECTRE implant to store C2 configuration without modifying the visible file content.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026-08-20
tags:
    - attack.t1564.004
    - attack.t1071.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: 'C:\Windows\System32\drivers\etc\hosts:cache'
    condition: selection
falsepositives:
    - Unlikely in production environments
level: high
```

**Rule 3: SPECTRE BYOVD Vulnerable Driver Load**
Detects loading of RTCore64.sys or DBUtil_2_3.sys drivers exploited by SPECTRE for EDR callback unlinking.
- **Status:** compile: ✅ compiles (sigma convert splunk + log_scale) | confidence: medium
- Caveat: Legitimate MSI Afterburner and Dell utility installations load these drivers; requires environmental baselining.
<!-- audit: sigma convert --without-pipeline -t splunk spectre_byovd_driver_load.yml -> exit 0; sigma convert --without-pipeline -t log_scale spectre_byovd_driver_load.yml -> exit 0 -->

```yaml
title: SPECTRE BYOVD Vulnerable Driver Load - RTCore64 or DBUtil
id: 5c9a7e2d-3f1b-4d6e-a8c0-7e5b2d4f9a1c
status: experimental
description: Detects loading of known vulnerable drivers RTCore64.sys (CVE-2019-16098) or DBUtil_2_3.sys (CVE-2021-21551) used by SPECTRE implant to gain arbitrary kernel read/write for EDR callback unlinking.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026-08-20
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
    - Legitimate MSI Afterburner installations loading RTCore64.sys
    - Dell system utilities loading DBUtil_2_3.sys
level: high
```

**Rule 4: SPECTRE Linux Rootkit Systemd Persistence**
Detects creation of the hardware-monitor.service systemd unit used by the Specter rootkit.
- **Status:** compile: ✅ compiles (sigma convert splunk + log_scale) | confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk spectre_linux_rootkit_systemd.yml -> exit 0; sigma convert --without-pipeline -t log_scale spectre_linux_rootkit_systemd.yml -> exit 0 -->

```yaml
title: SPECTRE Linux Rootkit Persistence via Fake Hardware Monitor Systemd Service
id: 8d4f2a1e-6b3c-4e7d-9a5f-2c8e1b7d3f6a
status: experimental
description: Detects creation of the hardware-monitor.service systemd unit used by the SPECTRE Linux rootkit for persistence, configured to start before sysinit.target.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026-08-20
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
    - Legitimate hardware monitoring services with exactly this filename
level: high
```

**Rule 5: SPECTRE Linux Rootkit Kernel Module Load from Non-Standard Path**
Detects loading of acpi_pad.ko from non-standard locations outside the kernel module tree.
- **Status:** compile: ✅ compiles (sigma convert splunk + log_scale) | confidence: medium
- Caveat: Requires syslog visibility into insmod/modprobe commands; legitimate ACPI module loading from /lib/modules/ is filtered.
<!-- audit: sigma convert --without-pipeline -t splunk spectre_linux_rootkit_module.yml -> exit 0; sigma convert --without-pipeline -t log_scale spectre_linux_rootkit_module.yml -> exit 0 -->

```yaml
title: SPECTRE Rootkit Kernel Module Masquerading as ACPI Driver
id: 3e7c9a5d-2b4f-1d8e-6a0c-9f3b7e2d5a1c
status: experimental
description: Detects loading of the acpi_pad.ko kernel module from non-standard locations, used by the SPECTRE rootkit to disguise itself as a legitimate ACPI processor power management module.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026-08-20
tags:
    - attack.t1547.006
    - attack.t1014
logsource:
    product: linux
    service: syslog
detection:
    selection_module:
        - Message|contains|all:
            - 'insmod'
            - 'acpi_pad.ko'
        - Message|contains|all:
            - 'modprobe'
            - 'acpi_pad'
    filter_standard:
        Message|contains:
            - '/lib/modules/'
            - '/usr/lib/modules/'
    condition: selection_module and not filter_standard
falsepositives:
    - Manual loading of ACPI pad module for testing
level: medium
```

<!-- revision: v2 — Sigma Rule 6 (Credential Dumping via Registry Hive Export) dropped. Generic reg.exe + SAM/SYSTEM/SECURITY pattern is already covered by multiple community Sigma rules (e.g., sigma/rules/windows/process_creation/proc_creation_win_reg_dump_sam.yml) and is not SPECTRE-specific at strict altitude. -->

**Rule 6: SPECTRE Self-Hollowing into RuntimeBroker.exe**
<!-- revision: v2 — renumbered from Rule 7 after dropping Rule 6 (registry hive dump) -->
Detects RuntimeBroker.exe spawned from non-standard parent processes, consistent with SPECTRE's self-hollowing.
- **Status:** compile: ✅ compiles (sigma convert splunk + log_scale) | confidence: medium
- Caveat: Behavioral rule; may trigger on legitimate third-party software that launches RuntimeBroker.exe.
<!-- audit: sigma convert --without-pipeline -t splunk spectre_self_hollowing_runtimebroker.yml -> exit 0; sigma convert --without-pipeline -t log_scale spectre_self_hollowing_runtimebroker.yml -> exit 0 -->

```yaml
title: SPECTRE Self-Hollowing into RuntimeBroker.exe
id: 6f1b3d8a-4e2c-7a5d-9b0e-3c8f1a6d2e7b
status: experimental
description: Detects suspicious RuntimeBroker.exe process creation patterns consistent with SPECTRE implant self-hollowing behavior, where the implant replaces its own memory image with RuntimeBroker.exe.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026-08-20
tags:
    - attack.t1055.012
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\RuntimeBroker.exe'
    filter_legitimate:
        ParentImage|endswith:
            - '\svchost.exe'
            - '\services.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Third-party application management software spawning RuntimeBroker.exe
level: medium
```

**Rule 7: SPECTRE UAT-10147 Known C2 Infrastructure DNS Queries**
<!-- revision: v2 — renumbered from Rule 8 after dropping Rule 6 (registry hive dump) -->
Detects DNS lookups to known UAT-10147 command and control domains.
- **Status:** compile: ✅ compiles (sigma convert splunk + log_scale) | confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk spectre_ioc_domains.yml -> exit 0; sigma convert --without-pipeline -t log_scale spectre_ioc_domains.yml -> exit 0 -->

```yaml
title: SPECTRE UAT-10147 Known C2 Infrastructure DNS Queries
id: 9e5a1c7b-3d2f-4a8e-6b0d-8f4c2e1a7d3b
status: experimental
description: Detects DNS queries to known command and control domains associated with the SPECTRE implant deployed by UAT-10147.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
    - https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt
author: Actioner
date: 2026-08-20
tags:
    - attack.t1071.001
logsource:
    category: dns
detection:
    selection_subdomain:
        query|endswith:
            - '.jyzyps.com'
            - '.niupilao.vip'
            - '.udvyiwvfs.cyou'
            - '.vip8888vn.xyz'
            - '.mma888.cc'
            - '.healthsave.net'
    selection_apex:
        query:
            - 'jyzyps.com'
            - 'niupilao.vip'
            - 'b.niupilao.vip'
            - 'vip.niupilao.vip'
            - 'udvyiwvfs.cyou'
            - 'vip8888vn.xyz'
            - 'mma888.cc'
            - 'healthsave.net'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: critical
```

### YARA Rules

**Rule 1: SPECTRE_Implant_Windows_PDB_Strings**
Detects SPECTRE implant Windows PE binaries via PDB path strings and C2 endpoint patterns.
- **Status:** compile: ✅ compiles (yarac exit 0) | confidence: high

**Rule 2: SPECTRE_Linux_Rootkit_Specter**
Detects the Specter Linux kernel rootkit module via hooked function names and ftrace indicators.
- **Status:** compile: ✅ compiles (yarac exit 0) | confidence: high
<!-- revision: v2 — $ftrace_flag made optional; FTRACE_OPS_FL_IPMODIFY is a C preprocessor macro that resolves to a numeric constant at compile time and will not appear as a literal string in a compiled .ko binary -->

**Rule 3: SPECTRE_BadIIS_WebShell**
Detects BadIIS ASHX web shell components via CodeDomProvider and cryptographic loader patterns.
- **Status:** compile: ✅ compiles (yarac exit 0) | confidence: high
<!-- revision: v2 — condition tightened: $ashx2 (X-seo) now mandatory to anchor the match to the campaign; prevents 3-of-6 generic .NET strings from firing alone -->

<!-- audit: yarac spectre_implant.yar /dev/null -> exit 0 (all 3 rules) -->

```yara
rule SPECTRE_Implant_Windows_PDB_Strings
{
    meta:
        description = "Detects SPECTRE implant and associated tooling via PDB debug path strings and development artifacts from UAT-10147"
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        hash = "008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2"

    strings:
        $pdb1 = "x\xe7\xa5\x9e\xe8\xae\xa2\xe5\x88\xb6\xe5\x85\xa8\xe7\xab\x99\xe5\x8a\xab\xe6\x8c\x81" ascii
        $pdb2 = "x\xe7\xa5\x9e\xe7\x9a\x84\xe8\x87\xaa\xe5\xae\x89\xe8\xa3\x85\xe6\x9c\x8d\xe5\x8a\xa1" ascii
        $pdb3 = "EfsPotatoCpp" ascii
        $c2_path1 = "/api/v1/register" ascii
        $c2_path2 = "/api/v1/output" ascii
        $magic_pid = { 69 7A 00 00 }
        $rootkit_mod = "acpi_pad" ascii
        $xid_header = "X-ID" ascii

    condition:
        uint16(0) == 0x5A4D and (
            any of ($pdb*) or
            (all of ($c2_path*) and $xid_header)
        )
        or
        uint32(0) == 0x464C457F and (
            $rootkit_mod and $magic_pid
        )
}

rule SPECTRE_Linux_Rootkit_Specter
{
    meta:
        description = "Detects the Specter Linux kernel rootkit module (acpi_pad.ko) used by SPECTRE implant for process/module hiding and privilege escalation"
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        hash = "1fc83b41d201bfbc4db94e332e0c770be9d74591d9817c1b938ccdf17c7a48a9"

    strings:
        $mod_name = "acpi_pad" ascii
        $ftrace_flag = "FTRACE_OPS_FL_IPMODIFY" ascii
        $hook1 = "hooked_tcp4_seq_show" ascii
        $hook2 = "hooked_tcp6_seq_show" ascii
        $hook3 = "hooked_getdents64" ascii
        $hook4 = "hooked_kill" ascii
        $hook5 = "hooked_tkill" ascii
        $svc_name = "hardware-monitor" ascii

    condition:
        uint32(0) == 0x464C457F and
        $mod_name and
        (
            ($ftrace_flag and 1 of ($hook*)) or
            (2 of ($hook*) and $svc_name)
        )
}

rule SPECTRE_BadIIS_WebShell
{
    meta:
        description = "Detects BadIIS web shell components associated with UAT-10147 SPECTRE campaign, including the dual-layer ASHX loader"
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        hash = "43124b72616ef38b0c8a07b167e971b0e4479626fb5ef2303b2ed993e21f6c4c"

    strings:
        $ashx1 = "CodeDomProvider" ascii wide
        $ashx2 = "X-seo" ascii wide
        $ashx3 = "CompileAssemblyFromSource" ascii wide
        $rev1 = "FromBase64String" ascii wide
        $rev2 = "IHttpHandler" ascii wide
        $fake404 = "404 Not Found" ascii wide

    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0xBBEF or uint16(0) == 0x253C) and
        $ashx2 and 2 of them
}
```

### Snort Rules

- **Status:** ⚠️ uncompiled (structural check only -- Snort is not installed in this environment)

<!-- revision: v2 — Snort 1-2: added content:"x9"; http_header; to check X-ID value, not just header presence. Added rules for 5 missing IOC domains. -->
```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"SPECTRE Implant C2 Beacon Registration Endpoint"; flow:established,to_server; content:"POST"; http_method; content:"/api/v1/register"; http_uri; content:"X-ID"; http_header; content:"x9"; http_header; sid:2100001; rev:2; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"SPECTRE Implant C2 Data Exfiltration Endpoint"; flow:established,to_server; content:"POST"; http_method; content:"/api/v1/output"; http_uri; content:"X-ID"; http_header; content:"x9"; http_header; sid:2100002; rev:2; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SPECTRE C2 Infrastructure - Known Malicious Domain jyzyps.com"; flow:established,to_server; content:"jyzyps.com"; nocase; sid:2100003; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SPECTRE C2 Infrastructure - Known Malicious Domain niupilao.vip"; flow:established,to_server; content:"niupilao.vip"; nocase; sid:2100004; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SPECTRE C2 Infrastructure - Known Malicious Domain udvyiwvfs.cyou"; flow:established,to_server; content:"udvyiwvfs.cyou"; nocase; sid:2100005; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SPECTRE C2 Infrastructure - Known Malicious Domain vip8888vn.xyz"; flow:established,to_server; content:"vip8888vn.xyz"; nocase; sid:2100006; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SPECTRE C2 Infrastructure - Known Malicious Domain mma888.cc"; flow:established,to_server; content:"mma888.cc"; nocase; sid:2100007; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SPECTRE C2 Infrastructure - Known Malicious Domain healthsave.net"; flow:established,to_server; content:"healthsave.net"; nocase; sid:2100008; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)
```

### Suricata Rules

- **Status:** ⚠️ uncompiled (structural check only -- Suricata is not installed in this environment)

<!-- revision: v2 — Suricata 1-2: added http.header_names + content:"x9" to check X-ID value. Added healthsave.net DNS rule (sid:2200008). -->
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SPECTRE Implant C2 Beacon Registration"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/v1/register"; http.header_names; content:"X-ID"; http.header; content:"x9"; sid:2200001; rev:2; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata: created_at 2026_08_20, updated_at 2026_08_20;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SPECTRE Implant C2 Data Exfiltration"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/v1/output"; http.header_names; content:"X-ID"; http.header; content:"x9"; sid:2200002; rev:2; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata: created_at 2026_08_20, updated_at 2026_08_20;)

alert dns $HOME_NET any -> any any (msg:"Actioner - SPECTRE C2 DNS Lookup - jyzyps.com"; dns.query; content:"jyzyps.com"; nocase; sid:2200003; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata: created_at 2026_08_20, updated_at 2026_08_20;)

alert dns $HOME_NET any -> any any (msg:"Actioner - SPECTRE C2 DNS Lookup - niupilao.vip"; dns.query; content:"niupilao.vip"; nocase; sid:2200004; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata: created_at 2026_08_20, updated_at 2026_08_20;)

alert dns $HOME_NET any -> any any (msg:"Actioner - SPECTRE C2 DNS Lookup - udvyiwvfs.cyou"; dns.query; content:"udvyiwvfs.cyou"; nocase; sid:2200005; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata: created_at 2026_08_20, updated_at 2026_08_20;)

alert dns $HOME_NET any -> any any (msg:"Actioner - SPECTRE C2 DNS Lookup - vip8888vn.xyz"; dns.query; content:"vip8888vn.xyz"; nocase; sid:2200006; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata: created_at 2026_08_20, updated_at 2026_08_20;)

alert dns $HOME_NET any -> any any (msg:"Actioner - SPECTRE C2 DNS Lookup - mma888.cc"; dns.query; content:"mma888.cc"; nocase; sid:2200007; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata: created_at 2026_08_20, updated_at 2026_08_20;)

alert dns $HOME_NET any -> any any (msg:"Actioner - SPECTRE C2 DNS Lookup - healthsave.net"; dns.query; content:"healthsave.net"; nocase; sid:2200008; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/; metadata: created_at 2026_08_20, updated_at 2026_08_20;)
```

### ClamAV Signatures (Vendor-Provided)

The following ClamAV signatures were released by Cisco Talos for this campaign and can be deployed via standard ClamAV updates:

- Win.Malware.Generic-10060235-0, -10060218-0, -9883082-0, -10060252-0, -10060220-0
- Win.Malware.BadPotato-10060230-0
- Win.Malware.BadIIS-10059985-0
- Win.Malware.Ulise-10056576-0
- Win.Exploit.Marte-10033857-0
- Win.Tool.GodPotato-10019688-1
- Win.Tool.juicypotato-10041758-0
- Win.Loader.BadiisSet-10060291-1
- Asp.Rootkit.Badiis-10060290-1
- Unix.Rootkit.Malware-10060258-0
- Unix.Rootkit.Spectre-10060260-0
- Unix.Trojan.Backdoor-6678692-0
- Unix.Backdoor.Msfvenom-10012672-0

Vendor Snort rule SIDs: 1:66688, 1:66689, 1:66690, 1:301548

## Sources

1. [Cisco Talos - UAT-10147 Deploys SPECTRE: A Cross-Platform Implant with Linux Rootkit and BYOVD Capabilities](https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/)
2. [Cisco Talos IOC Repository - UAT-10147 deploys SPECTRE](https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt)
3. [NVD - CVE-2019-16098 (RTCore64.sys)](https://nvd.nist.gov/vuln/detail/CVE-2019-16098)
4. [NVD - CVE-2021-21551 (DBUtil_2_3.sys)](https://nvd.nist.gov/vuln/detail/CVE-2021-21551)
5. [GodPotato Privilege Escalation Tool](https://github.com/BeichenDream/GodPotato)
6. [JuicyPotato Privilege Escalation Tool](https://github.com/ohpe/juicy-potato)
7. [EfsPotato Privilege Escalation Tool](https://github.com/zcgonvh/EfsPotato)
8. [RustPotato Privilege Escalation Tool](https://github.com/safedv/RustPotato)
