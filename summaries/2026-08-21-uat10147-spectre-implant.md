# UAT-10147 Deploys SPECTRE: Cross-Platform Implant with Linux Rootkit and BYOVD Capabilities

**Date**: 2026-08-21
**Author**: Actioner
**Status**: FINAL
**TLP**: CLEAR
**Source**: Cisco Talos Intelligence

---

## Executive Summary

On August 20, 2026, Cisco Talos published detailed analysis of **UAT-10147**, a highly capable Chinese-speaking intrusion actor operating a multi-platform post-exploitation ecosystem. The group deploys **SPECTRE**, a custom C-language backdoor targeting both Windows and Linux systems, notable for integrating a Linux kernel rootkit ("Specter") and Bring Your Own Vulnerable Driver (BYOVD) capabilities for kernel-level EDR bypass on Windows. The campaign targets internet-facing IIS and Linux web servers across government, education, media, technology, and gaming sectors, with confirmed victims in Brazil, Bolivia, Canada, China, and Vietnam. Talos recovered AI-generated code comments in the rootkit source, marking the first documented instance of AI-assisted development in kernel-mode offensive tooling at this scale. The group monetizes access through SEO fraud targeting Vietnamese users while maintaining long-term persistent access via advanced implants.

---

## Background

UAT-10147 is tracked by Cisco Talos as a financially motivated cybercrime group with Chinese-speaking operators. The group has been observed deploying a broad arsenal including QuasarRAT, Gh0stCringe, Noodle RAT, Meterpreter, EfsPotato, BadIIS, and custom web shells, alongside the flagship SPECTRE implant. Their operational workflow incorporates AI-driven tooling (PentestGPT, DeepAudit) to automate reconnaissance, exploit development, validation, payload deployment, and operational documentation -- representing an evolution toward semi-autonomous offensive orchestration.

An earlier Talos report documented UAT-10147 integrating agentic AI into post-compromise operations, including Python scripts for exploit validation (`check_paths.py`), implant deployment (`deploy_implant.py`), web shell installation (`deploy_shell.py`), and multi-stage reconnaissance exfiltration (`exfil.py`). The attacker's machine username "dajiba" was recovered from local file paths, and an exposed open directory at `139.180.197[.]150` contained approximately 170,000 target URLs split across 17 files.

---

## Attack Timeline

| Phase | Activity |
|-------|----------|
| **Initial Access** | Exploitation of internet-facing servers via known CVEs: CVE-2022-27925 (Zimbra RCE), CVE-2021-23758 (AjaxPro deserialization), CVE-2021-29441/29442 (Nacos RCE), CVE-2019-18935 (Telerik UI deserialization) |
| **Execution** | Web shell deployment (`sss.ashx`, `up.ashx`), batch script execution (`back.bat`, `bai.bat`, `user.bat`) |
| **Persistence** | Scheduled task "Google Chrome Start" (Windows), `hardware-monitor.service` systemd unit (Linux), BadIIS module for SEO fraud |
| **Privilege Escalation** | EfsPotato, Dirty Pipe (CVE-2022-0847), Baron Samedit (CVE-2021-3156), CVE-2022-0995, CVE-2015-5287, CVE-2015-3246, CVE-2010-3904 |
| **Defense Evasion** | Defender exclusion paths for IIS directories, BYOVD via RTCore64.sys/DBUtil_2_3.sys, Specter rootkit process/module hiding, NTFS ADS for C2 config, anti-analysis scoring |
| **Credential Access** | Registry hive dumping (SAM/SYSTEM/SECURITY to %TEMP%), Chrome/Edge credential theft, cmdkey.exe enumeration |
| **C2** | SPECTRE HTTP POST beacon to `/api/v1/register` and `/api/v1/output` with `X-ID: x9` header authentication |
| **Exfiltration** | webhook.site SaaS-based exfiltration, AI-generated exfiltration scripts |

---

## Root Cause

The intrusions exploit **unpatched internet-facing web servers** running vulnerable software (Zimbra, AjaxPro, Nacos, Telerik UI). The root cause is a combination of:

1. **Unpatched known vulnerabilities** in internet-facing services (some CVEs dating to 2019)
2. **Exposed ASP.NET MachineKeys** enabling ViewState deserialization attacks
3. **Insufficient monitoring** of kernel driver loading and module installation
4. **Lack of HVCI enforcement** allowing unsigned/vulnerable driver exploitation

---

## Technical Analysis

### Stage 1: Initial Access and Web Shell Deployment

UAT-10147 exploits known vulnerabilities in internet-facing servers to gain initial access. The group deploys ASHX web shells (`sss.ashx` for command execution, `up.ashx` for file upload) and uses AI-generated Python scripts for automated deployment with fallback mechanisms. Tools like `badsecrets` are used to enumerate exposed ASP.NET MachineKeys for ViewState deserialization attacks via `ysoserial`.

### Stage 2: Privilege Escalation and Defense Evasion (Windows)

On Windows targets, the attacker:

1. **Adds Defender exclusion paths** for IIS directories:
   - `C:\Windows\SysWOW64\inetsrv`
   - `C:\Windows\System32\inetsrv`

2. **Deploys QuasarRAT** disguised as `svchosts.exe` (note: legitimate is `svchost.exe` without trailing 's')

3. **Creates persistence** via scheduled task named "Google Chrome Start" configured to execute at highest privileges during user logon

4. **Creates administrator accounts** via `user.bat` scripts

### Stage 3: SPECTRE Windows Implant

The Windows variant of SPECTRE supports **45 commands** covering:

- **Screenshots** and **keylogging**
- **Credential theft** (registry hive dumping, browser credential extraction)
- **Token impersonation** and **privilege escalation**
- **Process injection** via process hollowing (default target: `svchost.exe`) and APC EarlyBird injection
- **Self-hollowing** into `RuntimeBroker.exe` on startup
- **In-memory .NET execution**
- **Named pipe IPC**: `\\.\pipe\spectre_<tid>`

#### BYOVD EDR Bypass

SPECTRE deploys vulnerable drivers to `%TEMP%` and creates transient kernel services via the Service Control Manager:

| Driver | Vendor | CVE | Purpose |
|--------|--------|-----|---------|
| `RTCore64.sys` | MSI (Micro-Star International) | CVE-2019-16098 | Arbitrary kernel memory read/write |
| `DBUtil_2_3.sys` | Dell | CVE-2021-21551 | Arbitrary kernel memory read/write |

These drivers are exploited to **tamper with kernel callbacks** used by EDR products, effectively unlinking security product notifications and blinding endpoint detection.

#### C2 Configuration Storage

SPECTRE stores its C2 configuration in an **NTFS Alternate Data Stream** at:
```
C:\Windows\System32\drivers\etc\hosts:cache
```

This leverages the legitimate hosts file as a carrier, hiding configuration data from standard file system browsing.

#### String Obfuscation

- **Per-string xorshift32 PRNG** with 32-bit seeds for string encryption
- **DJB2 variant hash** for dynamic API resolution

#### Anti-Analysis

The implant employs a cumulative scoring system (threshold: **50 points**) evaluating:
- Process names (debuggers, analysis tools)
- RAM size, CPU core count, disk space
- Sleep acceleration detection
- Sandbox-associated hostnames and usernames

Exceeding the threshold triggers self-termination.

#### Credential Dumping

Registry hives are saved to `%TEMP%`:
- `HKLM\SAM\SAM`
- `HKLM\SYSTEM`
- `HKLM\SECURITY`

Additional credential sources:
- Chrome/Edge `Login Data` and `Local State` files
- Windows Credential Manager via `cmdkey.exe /list`

### Stage 4: SPECTRE Linux Implant

The Linux variant supports **29 commands** and shares C2 protocol characteristics with the Windows version:
- HTTP POST to `/api/v1/register` (beacon registration)
- HTTP POST to `/api/v1/output` (command output exfiltration)
- JSON payloads with `X-ID: x9` header authentication (fallback: `v` URL parameter)
- Hardcoded fallback C2 domains in binary

### Stage 5: Specter Linux Kernel Rootkit

The companion rootkit module is disguised as a legitimate ACPI power management module:

- **Filename**: `acpi_pad.ko`
- **Persistence**: Fraudulent systemd service `hardware-monitor.service` with `Before=sysinit.target`

#### Hooking via ftrace (FTRACE_OPS_FL_IPMODIFY)

| Hooked Function | Purpose |
|-----------------|---------|
| `hooked_tcp6_seq_show` | Hide network connections from `/proc/net/tcp6` |
| `hooked_tcp4_seq_show` | Hide network connections from `/proc/net/tcp` |
| `hooked_tkill` | Intercept signals for IPC |
| `hooked_tgkill` | Intercept signals for IPC |
| `hooked_kill` | Intercept signals for IPC |
| `hooked_getdents64` | Hide files/processes from directory listings |

#### Signal-Based IPC

The rootkit uses **magic PID 0x7A69 (31337 decimal)** with custom signal operations:

| Signal | Operation |
|--------|-----------|
| 62 | Process hiding (hide/unhide from `ps`, `/proc`) |
| 36 | Module hiding (hide from `lsmod`, `/proc/modules`) |
| 37 | Root privilege escalation (set UID to 0) |
| 35 | Load acknowledgment |

#### AI-Assisted Development

Talos recovered **AI-generated code comments** in the rootkit source code, representing the first documented instance of AI-assisted development in kernel-mode offensive tooling. The actor used tools including PentestGPT for web server scanning and DeepAudit for source code vulnerability analysis.

### Associated Malware: Noodle RAT (Linux)

UAT-10147 also deploys Noodle RAT on Linux targets:
- Copies itself to `/tmp/CCCCCCCC`
- RC4 decryption with hardcoded key: `r0st@#$`
- Connects to attacker-controlled C2 infrastructure

### SEO Fraud Module (BadIIS)

- **Handler class**: `SeoEngineHandler`
- **Configuration header**: `X-seo`
- **Targets**: Vietnamese users (Coc Coc browser/search engine)
- **C2 domains**: Use `.vn[.]xyz` suffix (e.g., `vip8888vn[.]xyz`)

---

## Indicators of Compromise

### Network Infrastructure

| Type | Indicator | Context |
|------|-----------|---------|
| IP | `139.180.197[.]150` | Primary C2/staging server with open directory |
| IP | `27.124.2[.]46` | C2 infrastructure |
| IP | `27.124.2[.]48` | C2 infrastructure |
| IP | `27.124.2[.]52` | C2 infrastructure |
| IP | `18.140.163[.]186` | Secondary C2 |
| Domain | `adminapi.tippusoni[.]in` | Staging/download server |
| Domain | `kl21177[.]com` | Staging/download server |
| Domain | `vip8888vn[.]xyz` | SEO fraud C2 |
| Domain | `b.niupilao[.]vip` | C2 domain |
| Domain | `vip.niupilao[.]vip` | C2 domain |
| Domain | `udvyiwvfs[.]cyou` | C2 domain |
| Domain | `js.jyzyps[.]com` | SEO fraud JS delivery |
| URL | `http://vn.mma888[.]cc/` | SEO fraud redirect |
| URL | `http://thceshi.healthsave[.]net` | C2 endpoint |

### File Hashes (SHA256)

#### SPECTRE & Campaign Samples (from Talos IOC Repository)

```
008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2
11ccfdfb0dfe782ba0eeabaa8e65619a792f9258476a072b774ef19a5240b944
1c2edfb1b280fdc570591c88da5b1adbd249be6b8cc306a42525a515adaf73e8
21274d668e28b01172fa326f42e396b825708ddc2336ae388d6729627c525775
43124b72616ef38b0c8a07b167e971b0e4479626fb5ef2303b2ed993e21f6c4c
50d88f3d8f91f18195f1e9948cf6b47d69d7e19226957b1e7e3b2e4bd7c4fef4
59a386b75b84f137c4e17c37e3430fc93c0184102b3fbdfe649cef2e0335d85b
684e7ed556dcc9e2fe24fcfd73e6b9c29d7126584f87c5331c2607d39e29329f
76df454fe87620dd59efb483a56a8b573c7d16207635cf2616a67e25dab57779
77cce6576f93961651133b543948ea3853cc2f06b8c3fd523f6858d6d18ad775
830c6ca21a7da0eed436f8371c8a86baa62ab857a5478a222dd3189645d4d084
91d00ca46d1013c031aa8ff2e54b7b3496bac78f6147842766bffd4d32a2e042
7565a5bc56fcd94c7f52cf7428747cd4f52d0d3b485900d3d9b06b470ccba23b
b74beab9dac9ee7853b5e846eec6f778db01867b49f64d6be259ea9e19006121
bfbd1aa2c0ace1575e86dc5cedc0754e4ae4aae97e70ac9f0523a2e8e8b22ed9
c88dab534081650d5a385f9bc5c61eced41b4e9fe63ace6173aa536c4aaffa67
cf0a6353f1fccf63fca02ed41eafd3da8d55f77b8b4c45666a37fa3cdc33da55
41f1514ad52c870bc4b51291cb939067e8ace23ec308419253ee0a2497bf2e21
dd4c16c65513c3eb66691f87d5bb5595d38554395ec89be2b9e325e013ef53d5
dee976f262498184d746cc8305cc9e6905ad762c661df8d7daec120f14060b41
2e9f10f5cc9fb5c9f935ee78a21de70168e398b7a47db54373a5dcb19c485398
e315f955a9b44a9c875d2e47f2a91e9e77043bd553ad616ada38eaf669d44b2e
58725b8e592435026928c39622f41b7ad4f4dc62e353eb459c3b4858eafd9e82
544a7d9d4de3904ad35e6cc87f34cb556fda722c3d3cae1a6334645f1a950cc7
9a8e9d587b570d4074f1c8317b163aa8d0c566efd88f294d9d85bc7776352a28
722bd55e1496cb614f4f365a4203da6166c637f2c6b9ec0da3844637bc6e9e9d
0345406e85aa7759c0af0372c23de0c5f3e9b6d53e970405e5c168f55c51a7e0
23a7adda56e2e5519e01f57f16f99e4be611aac4fa908f2ee2d99e3d96e14865
9619259c1ea9b1c6b8279fdb761018b14a41acc94f67f1469bf68bf393b4ba74
f07d869ddd17d4359e26da43574d0d07987b500a390196b72b3c1747a4cbb3bf
d0da3be9de8e7068a65247b8195d73e88f454820e13c1de62675e1f845d6fabf
0f56c703e9b7ddeb90646927bac05a5c6d95308c8e13b88e5d4f4b572423e036
35c960bda30ceeb22216fad7776b43ecf44aaccf2ff7f600f91a1afb49a8a43c
7172ebfb4e96e3b0bff59e87f670c5512144d445b276746c8c78593272720ebf
b02664c71d1a40760ff6eb253d1a9022d93262698d528d95e8983bf848b8827b
dbe956ae1135e81ae06220393ee80caacc62006295a1fb26e87f048a7a78b81b
4bbba075f56ee15760b1397100a82f2c7425b866cf1a35684fda5b712783f97b
1c70b2a55b6f3a3382f40fe15293b609d047103b0c6c7da0049f7c0e365ea880
fc54b68f0a375600c8ab23d894b56837db287b32209c0a455fb439a780593c80
b0c1c3b806a60807854173f2199ba49baf5c2729051b14e4725cb90cfc755519
089b19f7760a53272f580432460dc959cbb8ffb87bde43152795ff5d893debdd
1fc83b41d201bfbc4db94e332e0c770be9d74591d9817c1b938ccdf17c7a48a9
fea09e46f6adf23aa17c56faa14d19168b5417ed90d7b2b36f2c8dd5f6014ea7
061b765659bf24b62d242d4f8ca9a9884037e186714517509a8f48b54e1123a0
```

#### Agentic AI Campaign Samples (Related IOC Set)

```
175e83adc721cd7d634ebd2c63fb8d2404c009067bc7719ef02c5d1f9d81e9a1
1f0496ad392b5b9edf9e59a56af4d8e17638ddbb12e086f104d9a0f316ad59a1
37cabc04da36e710dd4aee8609ab7553c039a54dd085460854e9ddb49b0e7032
50232092004b9ad335e1e72e3a6dcfde93c4470007ddfcc637e6e5f899f68be0
73b272612cec9e03a7e2f7516ece600fb1b45b719fa9d93b382ed25ec314e5c0
9fa27b231502d6d33441ab54227da50cbd325847ce2272f9c0e79b4ea873e432
cfce59111338701b2990be9aadc80166ac0618cb57483d6a065f1e2526a34494
fbe9c6052d7261bd252322e155d86bd370340f1fbb2b0a1e9c7b444f6275614a
00892f276299a13721642e8a9bcbcb949a658547c6c8271866a1997b79f1e5c5
23a83c6bbdd7d6c09a5187338065d15f2a90a252772813cba83b9818aa56cef7
8280502c2c6902e61fc4c02a9a81b4720688449a5bca3d89dbd1e2edd507c69a
d190b349d791267a9583ba9f4a1ab0e4199d1a3abfd4dae514ed5def0754ba94
```

### Staging URLs

```
https://js.jyzyps[.]com/js/vnnb.js
https://js.jyzyps[.]com/js/nb.js
http://vn.mma888[.]cc/
http://thceshi.healthsave[.]net
http://www.xxxx[.]vip
http://spider.xxxx[.]com
adminapi.tippusoni[.]in/4/pr.exe
adminapi.tippusoni[.]in/4/prcc2.txt
adminapi.tippusoni[.]in/4/svchosts.exe
adminapi.tippusoni[.]in/5/pr.exe
adminapi.tippusoni[.]in/5/svchosts.exe
kl21177[.]com/1/prcc1.rar
kl21177[.]com/1/dll.zip
139.180.197[.]150:54321/4/pr.exe
139.180.197[.]150:54321/4/svchosts.exe
```

### File System Artifacts

| Artifact | Platform | Context |
|----------|----------|---------|
| `C:\Windows\System32\drivers\etc\hosts:cache` | Windows | NTFS ADS storing C2 configuration |
| `%TEMP%\RTCore64.sys` | Windows | BYOVD driver (deployed to temp) |
| `%TEMP%\DBUtil_2_3.sys` | Windows | BYOVD driver (deployed to temp) |
| `\\.\pipe\spectre_<tid>` | Windows | Named pipe for IPC |
| `svchosts.exe` | Windows | QuasarRAT masquerading |
| `sss.ashx` | Windows/IIS | Primary web shell |
| `up.ashx` | Windows/IIS | Upload web shell |
| `acpi_pad.ko` | Linux | Specter rootkit disguised as ACPI module |
| `hardware-monitor.service` | Linux | Rootkit persistence systemd unit |
| `/tmp/CCCCCCCC` | Linux | Noodle RAT staging path |

### Scheduled Tasks / Services

| Name | Platform | Details |
|------|----------|---------|
| `Google Chrome Start` | Windows | Scheduled task, highest privileges, logon trigger |
| `hardware-monitor.service` | Linux | Systemd unit, `Before=sysinit.target` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Details |
|--------|-----------|----|---------|
| Initial Access | Exploit Public-Facing Application | T1190 | Zimbra, AjaxPro, Nacos, Telerik UI CVEs |
<!-- revision: removed T1559 (COM/DDE) mapping for named pipe IPC — T1559 covers COM and DDE, not named pipes -->
| Execution | Command and Scripting Interpreter | T1059 | Batch scripts, PowerShell, web shells |
| Persistence | Scheduled Task/Job | T1053.005 | "Google Chrome Start" scheduled task |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | Transient kernel driver service |
| Persistence | Create or Modify System Process: Systemd Service | T1543.002 | `hardware-monitor.service` |
| Persistence | Server Software Component: Web Shell | T1505.003 | `sss.ashx`, `up.ashx` ASHX handlers |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | BYOVD, Dirty Pipe, Baron Samedit, EfsPotato |
| Privilege Escalation | Access Token Manipulation | T1134 | Token impersonation |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Defender exclusion paths, EDR callback unlinking |
| Defense Evasion | Process Injection: Process Hollowing | T1055.012 | svchost.exe/RuntimeBroker.exe hollowing |
| Defense Evasion | Rootkit | T1014 | Specter kernel rootkit (ftrace hooks) |
| Defense Evasion | Hide Artifacts: NTFS File Attributes | T1564.004 | ADS on hosts file for C2 config |
| Defense Evasion | Masquerading | T1036 | `acpi_pad.ko`, `svchosts.exe`, "Google Chrome Start" |
| Defense Evasion | Obfuscated Files or Information | T1027 | Xorshift32 PRNG string encryption |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | Anti-analysis scoring (50-point threshold) |
| Credential Access | OS Credential Dumping: Security Account Manager | T1003.002 | SAM/SYSTEM/SECURITY hive dumping |
| Credential Access | Credentials from Password Stores: Credentials from Web Browsers | T1555.003 | Chrome/Edge Login Data extraction |
| Credential Access | Credentials from Password Stores: Windows Credential Manager | T1555.004 | `cmdkey.exe /list` |
| Discovery | System Information Discovery | T1082 | Anti-analysis environment checks |
| Lateral Movement | (Not specifically documented) | -- | -- |
| Collection | Screen Capture | T1113 | Screenshot capability |
| Collection | Input Capture: Keylogging | T1056.001 | Keylogger |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP POST C2 with JSON payloads |
| Command and Control | Data Encoding | T1132 | Base64 encoding in payloads |
| Exfiltration | Exfiltration Over Web Service | T1567 | webhook.site SaaS exfiltration |
| Resource Development | Obtain Capabilities: Tool | T1588.002 | AI-assisted tool development (PentestGPT, DeepAudit) |

---

## Impact

- **Scope**: Approximately 170,000 target URLs identified in the actor's exposed infrastructure; confirmed compromises across 5 countries (Brazil, Bolivia, Canada, China, Vietnam)
- **Sectors**: Government, education, media, technology, gaming
- **Severity**: Critical -- kernel-level persistence and EDR bypass significantly reduce defender visibility
- **Novelty**: First documented AI-assisted kernel rootkit development represents an inflection point in offensive capability democratization
- **Financial**: SEO fraud monetization targeting Vietnamese search engine traffic provides ongoing revenue
- **Data Risk**: Credential dumping (SAM hives, browser credentials) enables lateral movement and further compromise

---

## Detection and Remediation

### Immediate Actions

1. **Scan for IOCs**: Check all file hashes against endpoint telemetry; query DNS logs for listed domains; check network logs for listed IPs
2. **Hunt for BYOVD indicators**: Search for `RTCore64.sys` or `DBUtil_2_3.sys` loaded from non-standard paths (especially `%TEMP%`)
3. **Audit kernel modules**: On Linux hosts, verify `acpi_pad.ko` is a legitimate ACPI module (check digital signature, source package)
4. **Review systemd services**: Check for `hardware-monitor.service` units, especially with `Before=sysinit.target`
5. **Check NTFS ADS**: Scan for alternate data streams on `C:\Windows\System32\drivers\etc\hosts`
6. **Review Defender exclusions**: Audit for exclusions on `inetsrv` or `inetpub` directories
7. **Audit scheduled tasks**: Search for tasks named "Google Chrome Start"

### Strategic Mitigations

1. **Patch internet-facing servers**: Prioritize CVE-2022-27925, CVE-2021-23758, CVE-2021-29441/29442, CVE-2019-18935
2. **Enable HVCI**: Deploy Hypervisor-Protected Code Integrity to prevent unsigned/vulnerable driver loading
3. **Enforce BYOVD blocklists**: Apply Microsoft's recommended driver blocklist and custom rules for RTCore64.sys/DBUtil_2_3.sys
4. **Rotate ASP.NET MachineKeys**: Regenerate keys on all IIS servers to prevent ViewState deserialization attacks
5. **Monitor east-west traffic**: Alert on outbound connections from IIS worker processes to Linux infrastructure
6. **Kernel module signing**: Enforce `CONFIG_MODULE_SIG_FORCE` on Linux systems to prevent unsigned module loading
7. **Deploy auditd rules**: Monitor `/sbin/insmod` and `/sbin/modprobe` execution

---

## Detection Rules

### Sigma Rules

#### 1. SPECTRE BYOVD Vulnerable Driver Installation

```yaml
title: SPECTRE BYOVD Vulnerable Driver Installation via Service Control Manager
id: 8a3e1f4b-7c29-4d85-b1e6-9f2a3c5d8e07
status: experimental
description: >
    Detects the installation of known vulnerable drivers (RTCore64.sys, DBUtil_2_3.sys)
    used by UAT-10147's SPECTRE implant to perform BYOVD attacks for kernel-level EDR bypass.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026-08-21
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1068
    - attack.t1543.003
logsource:
    product: windows
    category: driver_load
detection:
    selection_drivers:
        ImageLoaded|endswith:
            - '\RTCore64.sys'
            - '\DBUtil_2_3.sys'
    filter_legitimate_paths:
        ImageLoaded|startswith:
            - 'C:\Program Files\MSI\'
            - 'C:\Program Files (x86)\MSI\'
            - 'C:\Program Files\Dell\'
    condition: selection_drivers and not filter_legitimate_paths
falsepositives:
    - Legitimate MSI Afterburner or Dell BIOS utility installations loading these drivers from expected paths
level: high
```

**Splunk SPL**:
```
ImageLoaded IN ("*\\RTCore64.sys", "*\\DBUtil_2_3.sys") NOT (ImageLoaded IN ("C:\\Program Files\\MSI\\*", "C:\\Program Files (x86)\\MSI\\*", "C:\\Program Files\\Dell\\*"))
```

<!-- revision: Sigma #2 — downgraded level to medium; removed "SPECTRE" from title; reframed description as behavioral TTP -->
#### 2. Transient Kernel Driver Service from Temp Directory

```yaml
title: Transient Kernel Driver Service Creation from Temp Directory
id: 2b4c6e8a-1d3f-5a97-c0e2-4f6b8d9a1c3e
status: experimental
description: >
    Detects creation of kernel-mode driver services with ImagePath pointing to temporary
    or user-writable directories. Loading kernel drivers from non-standard paths such as
    %TEMP% or C:\Users\Public is a common BYOVD pattern used to side-load vulnerable
    drivers for kernel callback tampering.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026-08-21
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1543.003
    - attack.t1068
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_kernel:
        ServiceType|contains: 'kernel'
    selection_temp_paths:
        ImagePath|contains:
            - '\AppData\Local\Temp\'
            - '\Windows\Temp\'
            - '\Users\Public\'
    condition: selection and selection_kernel and selection_temp_paths
falsepositives:
    - Some legitimate security products may temporarily load drivers from user-writable directories during installation
level: medium
```

**Splunk SPL**:
```
Provider_Name="Service Control Manager" EventID=7045 ServiceType="*kernel*" ImagePath IN ("*\\AppData\\Local\\Temp\\*", "*\\Windows\\Temp\\*", "*\\Users\\Public\\*")
```

<!-- revision: Sigma #3 (Process Hollowing into RuntimeBroker/Svchost) DROPPED — generic T1055.012 TTP with zero SPECTRE-specific artifacts; wrong altitude for this report. -->

<!-- revision: Sigma #4 — renamed title (removed "to Temp Directory" since no temp-path filter); noted generic T1003.002; fixed CommandLine|contains|all with single element to plain CommandLine|contains -->
#### 3. Registry Hive Credential Dumping via reg.exe

```yaml
title: Registry Hive Credential Dumping via reg.exe
id: 9c1e3a5b-7d2f-4f98-e6a0-8b4d2c6e0a1f
status: experimental
description: >
    Detects reg.exe saving SAM, SYSTEM, or SECURITY hives, a generic T1003.002
    technique used by numerous threat actors including UAT-10147's SPECTRE implant
    for offline credential extraction.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026-08-21
tags:
    - attack.credential_access
    - attack.t1003.002
logsource:
    product: windows
    category: process_creation
detection:
    selection_tool:
        Image|endswith: '\reg.exe'
    selection_save:
        CommandLine|contains: 'save'
    selection_hive:
        CommandLine|contains:
            - 'hklm\sam'
            - 'hklm\system'
            - 'hklm\security'
    condition: selection_tool and selection_save and selection_hive
falsepositives:
    - Legitimate backup or disaster recovery software
    - System administrators performing authorized registry backups
level: high
```

**Splunk SPL**:
```
Image="*\\reg.exe" CommandLine="*save*" CommandLine IN ("*hklm\\sam*", "*hklm\\system*", "*hklm\\security*")
```

#### 4. SPECTRE C2 Configuration via NTFS ADS on Hosts File

```yaml
title: SPECTRE C2 Configuration via NTFS Alternate Data Stream on Hosts File
id: 4e6a8c0b-2d1f-3b57-a9e4-7c5f1d3a6b8e
status: experimental
description: >
    Detects access to or creation of an NTFS Alternate Data Stream (ADS) named cache on
    the Windows hosts file, used by SPECTRE to store its C2 configuration in the path
    C:\Windows\System32\drivers\etc\hosts:cache.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026-08-21
tags:
    - attack.defense_evasion
    - attack.t1564.004
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: '\drivers\etc\hosts:cache'
    condition: selection
falsepositives:
    - Extremely unlikely in legitimate use
level: critical
```

**Splunk SPL**:
```
TargetFilename="*\\drivers\\etc\\hosts:cache*"
```

#### 5. SPECTRE Defender Exclusion Path Addition for IIS Directories

```yaml
title: SPECTRE Defender Exclusion Path Addition for IIS Directories
id: 7f2b4d6e-8a1c-3e59-b0d4-5c9a7e3f1b2d
status: experimental
description: >
    Detects addition of Microsoft Defender exclusion paths for IIS directories
    (inetsrv), a technique used by UAT-10147 to prevent detection of web shells
    and SPECTRE implant components deployed to IIS server paths.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
    - https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/
author: Actioner
date: 2026-08-21
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_exclusion:
        CommandLine|contains|all:
            - 'Add-MpPreference'
            - '-ExclusionPath'
        CommandLine|contains:
            - 'inetsrv'
            - 'inetpub'
    condition: selection_powershell and selection_exclusion
falsepositives:
    - Administrators configuring Defender exclusions for IIS during initial server setup
level: high
```

**Splunk SPL**:
```
Image IN ("*\\powershell.exe", "*\\pwsh.exe") CommandLine="*Add-MpPreference*" CommandLine="*-ExclusionPath*" CommandLine IN ("*inetsrv*", "*inetpub*")
```

#### 6. SPECTRE Named Pipe Creation

```yaml
title: SPECTRE Named Pipe Creation
id: 1a3c5e7f-9b2d-4f16-c8e0-3d5a7b9c1e4f
status: experimental
description: >
    Detects creation of named pipes matching the SPECTRE implant pattern
    (\\.\pipe\spectre_<tid>), used for inter-process communication during
    process hollowing and command execution.
references:
    - https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
author: Actioner
date: 2026-08-21
tags:
    - attack.execution
logsource:
    product: windows
    category: pipe_created
detection:
    selection:
        PipeName|startswith: '\spectre_'
    condition: selection
falsepositives:
    - Extremely unlikely in legitimate use
level: critical
```

**Splunk SPL**:
```
PipeName="\\spectre_*"
```

#### 7. SPECTRE Persistence via Masquerading Scheduled Task

```yaml
title: SPECTRE Persistence via Google Chrome Masquerading Scheduled Task
id: 3b5d7f9a-1c2e-4a86-d0f4-6e8b0a2c4d7f
status: experimental
description: >
    Detects creation of scheduled tasks named Google Chrome Start used by UAT-10147
    for persistence, configured to execute malware at highest privileges during
    user logon events.
references:
    - https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/
author: Actioner
date: 2026-08-21
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: 'Google Chrome Start'
    condition: selection
falsepositives:
    - Extremely unlikely - Google Chrome does not use scheduled tasks with this naming convention
level: high
```

**Splunk SPL**:
```
Image="*\\schtasks.exe" CommandLine="*Google Chrome Start*"
```

### YARA Rules

```yara
rule SPECTRE_Windows_Implant {
    meta:
        author = "Actioner"
        description = "Detects SPECTRE Windows implant based on debug log strings, named pipe pattern, C2 endpoints, and API hashing"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        hash = "008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2"
        severity = "critical"

    strings:
        $pipe = "\\\\.\\pipe\\spectre_" ascii wide
        $c2_register = "/api/v1/register" ascii
        $c2_output = "/api/v1/output" ascii
        $header_xid = "X-ID" ascii
        $ads_path = "\\drivers\\etc\\hosts:cache" ascii wide
        $debug1 = "spectre" ascii
        $driver1 = "RTCore64.sys" ascii wide
        $driver2 = "DBUtil_2_3.sys" ascii wide
        $hollowing_target1 = "svchost.exe" ascii wide
        $hollowing_target2 = "RuntimeBroker.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($pipe) or
            ($c2_register and $c2_output and ($header_xid or $pipe)) or
            ($ads_path and $header_xid) or
            (any of ($driver*) and any of ($hollowing_target*) and $debug1)
        )
}
// revision: YARA #1 — tightened $c2_register+$c2_output branch to require $header_xid or $pipe anchor; removed nocase from $debug1

rule SPECTRE_Linux_Implant {
    meta:
        author = "Actioner"
        description = "Detects SPECTRE Linux implant based on C2 endpoints, configuration patterns, and debug strings"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "critical"

    strings:
        $c2_register = "/api/v1/register" ascii
        $c2_output = "/api/v1/output" ascii
        $header_xid = "X-ID" ascii
        $debug = "spectre" ascii nocase
        $service = "hardware-monitor.service" ascii
        $rootkit_name = "acpi_pad.ko" ascii
        $magic_pid = { 69 7A 00 00 }

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            ($c2_register and $c2_output and ($header_xid or $debug)) or
            ($debug and $service) or
            ($debug and $rootkit_name) or
            ($header_xid and $c2_register and $debug) or
            ($magic_pid and $c2_register and ($header_xid or $debug))
        )
}
// revision: YARA #2 — tightened $c2_register+$c2_output branch to require $header_xid or $debug; anchored $magic_pid branch similarly

rule Specter_Linux_Rootkit {
    meta:
        author = "Actioner"
        description = "Detects the Specter Linux kernel rootkit module deployed by SPECTRE, based on hooked function names and IPC signals"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "critical"

    strings:
        $hook1 = "hooked_tcp6_seq_show" ascii
        $hook2 = "hooked_tcp4_seq_show" ascii
        $hook3 = "hooked_tkill" ascii
        $hook4 = "hooked_tgkill" ascii
        $hook5 = "hooked_kill" ascii
        $hook6 = "hooked_getdents64" ascii
        $ftrace = "FTRACE_OPS_FL_IPMODIFY" ascii
        $module_name = "acpi_pad" ascii
        $service = "hardware-monitor" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            (3 of ($hook*)) or
            ($ftrace and $module_name) or
            ($module_name and 2 of ($hook*)) or
            ($service and $module_name and 1 of ($hook*))
        )
}

rule SPECTRE_BYOVD_Driver_RTCore64 {
    meta:
        author = "Actioner"
        description = "Detects vulnerable RTCore64.sys driver (CVE-2019-16098) used by SPECTRE for BYOVD kernel callback tampering"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "high"

    strings:
        $driver_name = "RTCore64" ascii wide
        $msi1 = "Micro-Star" ascii wide
        $msi2 = "MICRO-STAR INTERNATIONAL" ascii wide
        $device = "\\Device\\RTCore64" ascii wide
        $symlink = "\\DosDevices\\RTCore64" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        ($device or $symlink or $driver_name) and
        (1 of ($msi*))
}

rule SPECTRE_BYOVD_Driver_DBUtil {
    meta:
        author = "Actioner"
        description = "Detects vulnerable DBUtil_2_3.sys driver (CVE-2021-21551) used by SPECTRE for BYOVD kernel callback tampering"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "high"

    strings:
        $driver_name = "DBUtil_2_3" ascii wide
        $dell1 = "Dell" ascii wide
        $dell2 = "DELL" ascii wide
        $device = "\\Device\\DBUtil" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        ($device or $driver_name) and
        (1 of ($dell*))
}

rule SPECTRE_SEO_WebShell {
    meta:
        author = "Actioner"
        description = "Detects the SeoEngineHandler ASHX web shell used by UAT-10147 for SEO fraud operations"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "high"

    strings:
        $class = "SeoEngineHandler" ascii wide
        $config = "X-seo" ascii wide
        $handler = ".ashx" ascii nocase
        $webshell1 = "sss.ashx" ascii
        $webshell2 = "up.ashx" ascii

    condition:
        filesize < 1MB and
        (
            ($class and $config) or
            ($class and $handler) or
            (all of ($webshell*))
        )
}

rule SPECTRE_NoodleRAT_Linux {
    meta:
        author = "Actioner"
        description = "Detects NoodleRAT Linux variant indicators associated with UAT-10147 campaigns, including RC4 key and staging path"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "high"

    strings:
        $rc4_key = "r0st@#$" ascii
        $staging_path = "/tmp/CCCCCCCC" ascii
        $noodle1 = "noodle" ascii nocase

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            ($rc4_key and $staging_path) or
            ($rc4_key and $noodle1) or
            ($staging_path and $noodle1)
        )
}
```

### Suricata Rules

```
# Suricata rules for SPECTRE C2 communication detection
# Author: Actioner
# Reference: https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/

# revision: All SIDs reassigned from ET reserved range (2000000-2999999) to custom 9000001+ range
# revision: SID 2200003 (X-ID+/api/v1/ combo) DROPPED — redundant with SIDs 9000001+9000002

# SPECTRE C2 beacon registration
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SPECTRE C2 Registration Beacon POST to /api/v1/register"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/v1/register"; http.header; content:"X-ID"; content:"x9"; sid:9000001; rev:1; metadata:created_at 2026_08_21; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

# SPECTRE C2 command output exfiltration
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SPECTRE C2 Output Exfiltration POST to /api/v1/output"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/v1/output"; http.header; content:"X-ID"; content:"x9"; sid:9000002; rev:1; metadata:created_at 2026_08_21; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

# UAT-10147 staging server download
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-10147 Staging Domain adminapi.tippusoni.in"; flow:established,to_server; http.host; content:"adminapi.tippusoni.in"; sid:9000003; rev:1; metadata:created_at 2026_08_21; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/;)

# UAT-10147 C2 domain kl21177.com
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-10147 C2 Domain kl21177.com DNS Lookup"; dns.query; content:"kl21177.com"; sid:9000004; rev:1; metadata:created_at 2026_08_21; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/;)

# UAT-10147 SEO fraud domain
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-10147 SEO Fraud Domain vip8888vn.xyz DNS Lookup"; dns.query; content:"vip8888vn.xyz"; sid:9000005; rev:1; metadata:created_at 2026_08_21; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

# UAT-10147 C2 IP
alert ip $HOME_NET any -> 139.180.197.150 any (msg:"Actioner - UAT-10147 C2 Server 139.180.197.150"; sid:9000006; rev:1; metadata:created_at 2026_08_21; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

# UAT-10147 SEO fraud JS delivery
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-10147 SEO Fraud JS Delivery Domain jyzyps.com"; flow:established,to_server; http.host; content:"jyzyps.com"; sid:9000007; rev:1; metadata:created_at 2026_08_21; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

# UAT-10147 C2 domain niupilao.vip
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-10147 C2 Domain niupilao.vip DNS Lookup"; dns.query; content:"niupilao.vip"; sid:9000008; rev:1; metadata:created_at 2026_08_21; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)

# UAT-10147 C2 domain udvyiwvfs.cyou
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-10147 C2 Domain udvyiwvfs.cyou DNS Lookup"; dns.query; content:"udvyiwvfs.cyou"; sid:9000009; rev:1; metadata:created_at 2026_08_21; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/;)
```

### Existing Vendor Coverage

#### ClamAV Signatures (from Talos)
- `Unix.Rootkit.Spectre-10060260-0`
- `Win.Malware.BadIIS-10059985-0`
- `Win.Tool.GodPotato-10019688-1`
- `Py.Loader.Tool-10060293-1`
- `Py.Loader.Tool-10060293-2`
- `Win.Malware.Generic-10060228-0`
- `Win.Loader.Downloader-10060287-1`

#### Snort SIDs (from Talos)
- Snort 2: 66688, 66689, 66690, 66696, 66697
- Snort 3: 66690, 301548

---

<!-- revision: sources reformatted as markdown links -->
## Sources

1. [Cisco Talos, "UAT-10147 deploys SPECTRE: A cross-platform implant with Linux rootkit and BYOVD capabilities," August 20, 2026.](https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/)

2. [Cisco Talos, "UAT-10147: Chinese-speaking adversary integrates agentic AI into post-compromise operations," 2026.](https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/)

3. [Cisco Talos IOC Repository - SPECTRE deployment indicators.](https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.txt)

4. [Cisco Talos IOC Repository - Agentic AI campaign indicators.](https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20integrates%20agentic%20AI.txt)

5. [CyberInsider, "Chinese hackers use AI to automate attacks on 170,000 servers," 2026.](https://cyberinsider.com/chinese-hackers-use-ai-to-automate-attacks-on-170000-servers/)

6. [it-learn.io, "AI-Assisted Rootkits Arrive -- UAT-10147 SPECTRE Campaign," August 20, 2026.](https://blog.it-learn.io/posts/2026-08-20-ai-assisted-rootkits-arrive-uat-10147-spectre-campaign/)
