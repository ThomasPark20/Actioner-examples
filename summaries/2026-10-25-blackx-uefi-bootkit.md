# Technical Analysis Report: BlackX UEFI Bootkit (2026-10-25)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-25
Version: DRAFT

## Executive Summary

BlackX is a UEFI bootkit discovered in early 2026 by Kaspersky researchers, targeting diplomatic organizations in Central Asia (Tajikistan, Uzbekistan, Turkmenistan). The bootkit exploits CVE-2022-21894 ("Baton Drop") to bypass Secure Boot on fully patched Windows systems where manual certificate revocation steps were not applied. Once installed, it loads a kernel driver signed with a revoked certificate that disables security product callbacks (targeting Kaspersky and Avast), tampers with ETW providers, and deploys follow-on payloads including a cloud-based RAT and the OxiDLLRunner DLL sideloading framework.

Kaspersky attributes BlackX with medium confidence to APT41 (also tracked as Brass Typhoon, Wicked Panda, Barium), noting code overlap with the FishMonger subgroup's tools, including the shared "xdd" identifier and DLL sideloading techniques. The bootkit appears derived from the BlackLotus UEFI bootkit whose source was partially leaked in July 2023.

## Background: UEFI Secure Boot and the Baton Drop Vulnerability

UEFI Secure Boot is designed to ensure that only cryptographically signed, trusted code executes during the boot process. CVE-2022-21894, known as "Baton Drop" (CVSS 4.4), is a security feature bypass that allows attackers to enroll custom Machine Owner Keys (MOKs) and load arbitrary EFI files, effectively circumventing Secure Boot. While Microsoft patched the vulnerability, full remediation requires manually revoking the "Windows Production PCA 2011" certificate by adding it to the Secure Boot Forbidden Signature Database (DBX). This certificate expired on October 19, 2026, but expiration alone does not prevent vulnerable binaries from loading unless the certificate is explicitly blocklisted. All observed BlackX victims ran fully patched Windows systems but had not applied these manual revocation steps.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2022-10 | BlackLotus UEFI bootkit first advertised on cybercrime forums |
| 2023-03 | ESET confirms BlackLotus exploits CVE-2022-21894 |
| 2023-07 | BlackLotus source code partially leaked online |
| Early 2026 | BlackX discovered targeting Central Asian diplomatic entities |
| 2026-10 | Kaspersky publishes full technical analysis of BlackX |

## Root Cause: Post-Compromise UEFI Installation

BlackX requires prior administrator access for installation. The attackers drop an installer (`inst.exe`) and an encrypted payload file (`PVMDIJGKAX2`) to `C:\ProgramData\Intel\`. The installer is invoked with the encrypted file name and an RC4 decryption key as command-line arguments:

```
C:\ProgramData\Intel\inst.exe PVMDIJGKAX2 Q46F6MDLI3RX2KV1
```

The installer decrypts the payload using the RC4 key `Q46F6MDLI3RX2KV1` and drops files to both the system and EFI System Partition, bootstrapping the UEFI infection.

## Technical Analysis of the Malicious Payload

### 1. UEFI Bootkit Installation (Baton Drop Exploitation)

The bootkit exploits CVE-2022-21894 to enroll custom Machine Owner Keys (MOKs) into the UEFI firmware. This allows loading arbitrary EFI binaries during the boot process, before the operating system starts. The UEFI payload persists across reboots and OS reinstalls (unless the EFI System Partition is cleaned), making it extremely difficult to remove with traditional endpoint security tools.

A scheduled task named `Secure-Boot-Update` is created as part of the persistence mechanism.

### 2. Kernel Driver Injection

The UEFI payload injects a malicious kernel driver into the Windows kernel. The driver is signed with a certificate issued to "Wenjiang District Mingyu Network Technology Service Studio" (certificate serial: `0bcdf5e0da32d68900b8b7638459d072`), which has since been revoked by its issuer. The driver performs the following actions:

- **Security callback disabling:** Removes process, thread, and registry callbacks registered by security products
- **ETW tampering:** Disables or modifies Event Tracing for Windows providers to blind security monitoring
- **Targeted anti-security routines:** Contains specific code paths that execute only when Kaspersky or Avast products are detected (Kaspersky reports these routines were ineffective against their products)
- **File protection:** Intercepts file open requests for the bootkit's files and returns a handle to `calc.exe` instead, effectively hiding its presence on disk

### 3. C2 Infrastructure

BlackX employs two C2 channels:

**Cloud-based RAT:** A remote access trojan uses legitimate cloud storage services for command-and-control:
- Google Drive
- OneDrive
- Yandex.Disk

The RAT executes .NET payloads via `TEST.Class1.RunCMD()`, transfers files, and sends initial system information. It uses a file-suffix protocol for tasking:

| Suffix | Direction | Purpose |
|--------|-----------|---------|
| `0X01` | Input | .NET payload for execution |
| `0X02` | Output | RunCMD output |
| `0X03` | Input | File upload task |
| `0X04` | Output | Uploaded file |
| `0X05` | Input | File download task |
| `0X06` | Output | Download status |
| `SSSR` | Output | Initial system information |

**OxiDLLRunner / Rust payload:** The legitimate `jcef_helper.exe` (MD5: `af8a983b9ada07eae1259bf2953abd40`) is renamed to `googleupdate.exe` and used for DLL sideloading. The sideloaded OxiDLLRunner (OLLVM-obfuscated) decrypts `v8_context_snapshot.bin` to launch shellcode and a Rust payload. The Rust payload contacts `www[.]archivetj[.]com` to retrieve DLL plugins, which are executed via their `create_plugin` exported function in separate threads.

### 4. Platform-Specific Behavior

#### Windows

BlackX targets Windows systems exclusively, as it relies on UEFI Secure Boot bypass via Baton Drop and injects a Windows kernel driver. The full kill chain operates within the Windows ecosystem from UEFI boot through kernel driver to user-mode payloads.

### 5. Anti-Forensics / Evasion Techniques

- **Pre-OS persistence:** Loads before the operating system, evading all traditional AV scanning
- **File hiding via handle redirection:** Returns `calc.exe` handles when bootkit files are accessed
- **ETW tampering:** Blinds security monitoring at the kernel level
- **Security product targeting:** Specifically disables callbacks from Kaspersky and Avast
- **OLLVM obfuscation:** OxiDLLRunner uses OLLVM to resist static analysis
- **Encrypted payloads:** RC4 encryption for the installer package; encrypted `v8_context_snapshot.bin` for the Rust payload
- **Legitimate binary sideloading:** Uses a signed, legitimate binary (`jcef_helper.exe` / `googleupdate.exe`) to load malicious code
- **Cloud C2:** Uses legitimate cloud services (Google Drive, OneDrive, Yandex.Disk) to blend C2 traffic with normal activity

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (MD5) | Description |
|----------|------|------------|-------------|
| Windows | C:\ProgramData\Intel\inst.exe | -- | BlackX installer executable |
| Windows | C:\ProgramData\Intel\PVMDIJGKAX2 | -- | RC4-encrypted payload package |
| Windows | (sideload dir)\googleupdate.exe | af8a983b9ada07eae1259bf2953abd40 | Renamed jcef_helper.exe used for DLL sideloading |
| Windows | (sideload dir)\v8_context_snapshot.bin | -- | Encrypted Rust payload / shellcode |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | www[.]archivetj[.]com | C2 for Rust payload plugin retrieval |
| Cloud Service | Google Drive | RAT C2 channel |
| Cloud Service | OneDrive | RAT C2 channel |
| Cloud Service | Yandex.Disk | RAT C2 channel |

### Certificate

| Field | Value |
|-------|-------|
| Subject CN | Wenjiang District Mingyu Network Technology Service Studio |
| Serial Number | 0bcdf5e0da32d68900b8b7638459d072 |
| Status | Revoked |

### Behavioral

- Installer command line: `inst.exe PVMDIJGKAX2 Q46F6MDLI3RX2KV1` (RC4 key as argument)
- Scheduled task `Secure-Boot-Update` created for persistence
- Kernel driver disabling process/thread/registry callbacks for security products
- ETW provider tampering at kernel level
- File open redirects to `calc.exe` for bootkit files
- DLL sideloading: `googleupdate.exe` loading an OLLVM-obfuscated DLL in a non-Google directory
- Plugin DLLs loaded via `create_plugin` exported function
- String marker `xdd` shared with FishMonger kernel implant (PDB path: `C:\Users\xdd\Desktop`)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1542.003 | Pre-OS Boot: Bootkit | UEFI bootkit exploiting Baton Drop to persist below the OS |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Renamed jcef_helper.exe as googleupdate.exe loads OxiDLLRunner |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Kernel driver disables security product callbacks (Kaspersky, Avast) |
| T1562.006 | Impair Defenses: Indicator Blocking | ETW provider tampering to blind security monitoring |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Secure-Boot-Update scheduled task for persistence |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | File open requests redirected to calc.exe |
| T1102 | Web Service | RAT uses Google Drive, OneDrive, Yandex.Disk for C2 |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | RC4 encryption for installer payload |
| T1014 | Rootkit | Kernel-level driver with security callback removal and file hiding |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Files placed in ProgramData\Intel\; binary renamed to googleupdate.exe |

## Impact Assessment

BlackX represents a high-severity threat due to its pre-OS persistence mechanism, which survives reboots and is invisible to traditional endpoint security tools. The targeting of Central Asian diplomatic organizations (Tajikistan, Uzbekistan, Turkmenistan) aligns with Chinese state-sponsored espionage objectives. The attack surface is significant: any Windows system with Secure Boot enabled but without the manual DBX revocation steps applied to CVE-2022-21894 is potentially vulnerable. The use of cloud services for C2 makes network-level detection challenging.

## Detection & Remediation

### Immediate Detection

Check for BlackX artifacts on potentially compromised systems:

```powershell
# Check for installer artifacts
Get-ChildItem -Path "C:\ProgramData\Intel\" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "inst\.exe|PVMDIJGKAX2" }

# Check for the persistence scheduled task
Get-ScheduledTask | Where-Object { $_.TaskName -eq "Secure-Boot-Update" }

# Check for googleupdate.exe outside normal Google directories
Get-Process -Name "googleupdate" -ErrorAction SilentlyContinue | Where-Object { $_.Path -notlike "*\Google\*" }

# Check EFI partition for recently modified .efi files (requires admin)
mountvol S: /S
Get-ChildItem -Path "S:\EFI\" -Recurse -Filter "*.efi" | Sort-Object LastWriteTime -Descending | Select-Object -First 20
mountvol S: /D
```

### Remediation

1. **Apply Secure Boot DBX revocations:** Follow Microsoft's guidance to add the "Windows Production PCA 2011" certificate to the Secure Boot Forbidden Signature Database (DBX). This is the primary mitigation -- patching alone is insufficient.
2. **Clean the EFI System Partition:** Mount the ESP and inspect/remove unauthorized .efi files. A clean OS reinstall does not suffice without cleaning the ESP.
3. **Remove persistence artifacts:** Delete the `Secure-Boot-Update` scheduled task, remove files from `C:\ProgramData\Intel\`, and remove the sideloading directory.
4. **Rotate credentials:** Assume all credentials on compromised systems are compromised. Rotate cloud service tokens, domain credentials, and any accessed secrets.
5. **Check for lateral movement:** Investigate whether the attacker pivoted to other systems, particularly those with diplomatic or sensitive data.

### Long-Term Hardening

- **Enforce Secure Boot DBX updates** via group policy or endpoint management across the fleet. Note: this is a manual process that must be verified per-system.
- **Monitor EFI System Partition integrity** using firmware attestation or Measured Boot with TPM.
- **Deploy kernel-level monitoring** that can detect callback removal and ETW tampering (e.g., Windows Defender Credential Guard, Virtualization-Based Security).
- **Restrict administrative access** to systems handling sensitive data -- BlackX requires prior admin access for installation.

## Detection Rules

These detections cover the BlackX UEFI bootkit kill chain at PoC/advisory-specific altitude: installer artifacts and command-line patterns, persistence via scheduled tasks, DLL sideloading, EFI partition writes, and C2 domain resolution. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles != fires -- verify in your pipeline with real telemetry.

### Sigma: BlackX Installer Command Line

Detects the BlackX bootkit installer via its distinctive command-line arguments (encrypted payload name and RC4 key) or its known install path.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (attacktag excluded — MITRE data endpoint blocked by proxy; tags are syntactically valid technique IDs). splunk 0; log_scale 0. splunk_windows pipeline 0. Values are real, not defanged. Highly distinctive strings from Kaspersky report: PVMDIJGKAX2 (payload filename) and Q46F6MDLI3RX2KV1 (RC4 key) are unique to this campaign. FP risk negligible. -->
```yaml
title: BlackX UEFI Bootkit Installer Command Line
id: 7c3a1f8e-4d2b-4e9a-b6f1-8a3c5d7e9f01
status: experimental
description: >
    Detects the BlackX UEFI bootkit installer execution with its characteristic
    command-line pattern including the encrypted payload file and RC4 decryption key.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/
author: Actioner
date: 2026/10/25
tags:
    - attack.t1542.003
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_path:
        Image|endswith: '\inst.exe'
        Image|contains: '\ProgramData\Intel\'
    selection_cmdline:
        CommandLine|contains|all:
            - 'PVMDIJGKAX2'
            - 'Q46F6MDLI3RX2KV1'
    condition: selection_path or selection_cmdline
falsepositives:
    - Unlikely - highly specific command-line artifacts
level: critical
```

### Sigma: BlackX Persistence via Scheduled Task

Detects creation of the `Secure-Boot-Update` scheduled task used by BlackX for persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Task name "Secure-Boot-Update" is from the Kaspersky report. Microsoft's own Secure Boot update mechanisms do not use a scheduled task with this exact name. Low FP risk but confirm no internal tooling uses this exact task name. -->
```yaml
title: BlackX UEFI Bootkit Persistence via Scheduled Task
id: 9e4b2c6d-1a3f-4b8e-c7d5-2f6a8e0b4c19
status: experimental
description: >
    Detects creation of the Secure-Boot-Update scheduled task, used by the
    BlackX UEFI bootkit for persistence on compromised systems.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/
author: Actioner
date: 2026/10/25
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'Secure-Boot-Update'
    selection_tools:
        Image|endswith:
            - '\schtasks.exe'
            - '\at.exe'
    condition: selection and selection_tools
falsepositives:
    - Legitimate Microsoft Secure Boot update mechanisms using this exact task name
level: high
```

### Sigma: BlackX OxiDLLRunner Sideloading via googleupdate.exe

Detects execution of `googleupdate.exe` from non-standard (non-Google) directories, indicating potential DLL sideloading as used by BlackX's OxiDLLRunner.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Sideloading vector from Kaspersky report: legitimate jcef_helper.exe renamed to googleupdate.exe in attacker-controlled directory. Filter excludes standard Google Update paths. Some FP possible from legitimate Google Update in custom install locations — tune filter as needed. -->
```yaml
title: BlackX OxiDLLRunner Sideloading via googleupdate.exe
id: 3f8a5e7c-6b1d-4c2e-a9f3-5d7b0e4a8c26
status: experimental
description: >
    Detects DLL sideloading via a renamed jcef_helper.exe masquerading as
    googleupdate.exe, used by the BlackX campaign to load OxiDLLRunner.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html
author: Actioner
date: 2026/10/25
tags:
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\googleupdate.exe'
    filter_legitimate:
        Image|contains:
            - '\Google\Update\'
            - '\Google\Chrome\'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate Google Update binaries in non-standard locations
level: high
```

### Sigma: Suspicious EFI File Write to System Partition

Detects file writes of .efi files to the EFI System Partition outside of standard Windows servicing processes.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Broader detection for UEFI bootkit installation. Filters for TiWorker.exe, TrustedInstaller.exe, poqexec.exe (Windows Update / servicing stack). Additional FPs possible from BIOS/firmware update tools, BitLocker provisioning, or third-party boot managers — tune filter for environment. Medium confidence due to filter-dependent FP rate. -->
```yaml
title: Suspicious EFI File Write to System Partition
id: b2d4f6a8-3c1e-4d7b-a5e9-1f8c0b6d2e47
status: experimental
description: >
    Detects file creation events writing EFI binaries to the EFI System Partition,
    which may indicate UEFI bootkit installation such as BlackX.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/
author: Actioner
date: 2026/10/25
tags:
    - attack.t1542.003
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\EFI\'
        TargetFilename|endswith: '.efi'
    filter_windows_update:
        Image|endswith:
            - '\TiWorker.exe'
            - '\TrustedInstaller.exe'
            - '\poqexec.exe'
    condition: selection and not filter_windows_update
falsepositives:
    - Legitimate UEFI firmware updates
    - Boot manager updates via Windows Update
level: high
```

### Sigma: BlackX Installer File Drop in ProgramData\Intel

Detects creation of BlackX-specific files (`inst.exe`, `PVMDIJGKAX2`) in the `C:\ProgramData\Intel\` staging directory.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. File names and paths directly from Kaspersky report. Intel legitimately uses ProgramData\Intel\ for driver/software data but would not drop inst.exe or PVMDIJGKAX2 there. FP risk very low. -->
```yaml
title: BlackX Installer File Drop in ProgramData Intel Directory
id: d1e3f5a7-2b4c-4e6d-8a0c-9f1b3d5e7a29
status: experimental
description: >
    Detects file creation in C:\ProgramData\Intel\ matching BlackX bootkit
    installer artifacts including inst.exe and the encrypted payload file.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html
author: Actioner
date: 2026/10/25
tags:
    - attack.t1542.003
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\ProgramData\Intel\'
        TargetFilename|endswith:
            - '\inst.exe'
            - '\PVMDIJGKAX2'
    condition: selection
falsepositives:
    - Unlikely - combination of path and specific file names is highly distinctive
level: critical
```

### Snort: DNS Query to BlackX C2 Domain

Detects DNS queries for the BlackX C2 domain `archivetj.com` used by the Rust payload for plugin retrieval.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf (via include) -T exit 0. DNS label-length encoding: |09|archivetj (9 bytes) |03|com (3 bytes) |00| (root). Domain from Kaspersky report. Single-domain IOC — rotates if actor changes infrastructure. -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to BlackX C2 Domain archivetj.com"; flow:to_server; content:"|09|archivetj|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/uefi-bootkit-blackx/121539/; metadata:author Actioner, created 2026-10-25; sid:2100101; rev:1;)
alert tcp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to BlackX C2 Domain archivetj.com (TCP)"; flow:established,to_server; content:"|09|archivetj|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/uefi-bootkit-blackx/121539/; metadata:author Actioner, created 2026-10-25; sid:2100102; rev:1;)
```

### Suricata: DNS Query to BlackX C2 Domain

Detects DNS queries for the BlackX C2 domain `archivetj.com` via Suricata's `dns.query` buffer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Using dns.query sticky buffer (dot notation). Second rule uses http.host (normalized to lowercase; nocase removed per Suricata warning). Domain from Kaspersky report. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to BlackX C2 Domain archivetj.com"; flow:to_server; dns.query; content:"archivetj.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/uefi-bootkit-blackx/121539/; metadata:author Actioner, created_at 2026-10-25; sid:2200101; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to BlackX C2 Domain archivetj.com"; flow:established,to_server; http.host; content:"archivetj.com"; classtype:trojan-activity; reference:url,securelist.com/uefi-bootkit-blackx/121539/; metadata:author Actioner, created_at 2026-10-25; sid:2200102; rev:1;)
```

### YARA: BlackX Installer Artifacts

Detects BlackX installer binaries via the distinctive encrypted payload filename (`PVMDIJGKAX2`), RC4 key, install path, and scheduled task name.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on constructed positive (MZ header + published strings from Kaspersky report), quiet on negative. Strings are campaign-unique artifacts published by Kaspersky. Condition requires PE header + 2 of 4 strings — high specificity. -->
```yara
rule APT41_BlackX_Installer_Artifacts
{
    meta:
        description = "Detects BlackX UEFI bootkit installer artifacts via distinctive strings including the encrypted payload filename and RC4 key"
        author = "Actioner"
        date = "2026-10-25"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $installer_payload = "PVMDIJGKAX2" ascii wide
        $rc4_key = "Q46F6MDLI3RX2KV1" ascii wide
        $install_path = "\\ProgramData\\Intel\\inst.exe" ascii wide
        $task_name = "Secure-Boot-Update" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        2 of them
}
```

### YARA: BlackX OxiDLLRunner / Rust Payload Strings

Detects BlackX OxiDLLRunner or Rust payload components via the C2 domain, exported plugin function name, and the "xdd" attribution marker.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. Strings from Kaspersky report. "xdd" is a 3-byte fullword match — alone it is too short, but condition requires it paired with the C2 domain or in a 3-of-5 combination. Medium confidence because individual strings (especially "create_plugin" and "googleupdate.exe") could appear in benign software; the combination raises specificity. -->
```yara
rule APT41_BlackX_OxiDLLRunner_Strings
{
    meta:
        description = "Detects BlackX OxiDLLRunner or Rust payload components via C2 domain, exported function, and attribution strings"
        author = "Actioner"
        date = "2026-10-25"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $c2_domain = "archivetj.com" ascii wide
        $export_fn = "create_plugin" ascii wide
        $xdd_marker = "xdd" ascii fullword
        $v8_payload = "v8_context_snapshot.bin" ascii wide
        $sideload_name = "googleupdate.exe" ascii wide nocase

    condition:
        filesize < 50MB and
        (
            ($c2_domain and 1 of ($export_fn, $xdd_marker)) or
            (3 of them)
        )
}
```

### YARA: BlackX Kernel Driver Certificate

Detects files signed with the revoked certificate (Wenjiang District Mingyu Network Technology Service Studio) used by the BlackX bootkit kernel driver.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Certificate CN and serial from Kaspersky report. UTF-8 hex of Chinese name included for completeness. Certificate is revoked; legitimate use of this signer is not expected. -->
```yara
rule APT41_BlackX_KernelDriver_Certificate
{
    meta:
        description = "Detects files signed with the revoked certificate used by the BlackX bootkit kernel driver (Wenjiang District Mingyu Network Technology Service Studio)"
        author = "Actioner"
        date = "2026-10-25"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $cert_cn = "Wenjiang District Mingyu Network Technology Service Studio" ascii wide
        $cert_cn_zh = {E6 B8 A9 E6 B1 9F E5 8C BA E6 98 8E E5 AE 87 E7 BD 91 E7 BB 9C E6 8A 80 E6 9C AF E6 9C 8D E5 8A A1 E5 B7 A5 E4 BD 9C E5 AE A4}
        $cert_serial = "0bcdf5e0da32d68900b8b7638459d072" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}
```

## Lessons Learned

1. **Secure Boot patching is incomplete without manual revocation.** CVE-2022-21894 was patched in 2022, but the revocation of the "Windows Production PCA 2011" certificate requires manual DBX updates that most organizations have not applied. This gap between "patched" and "mitigated" is the core enabler for BlackX.

2. **UEFI-level threats require firmware-aware detection.** Traditional endpoint security operates at or above the OS level and cannot reliably detect bootkits that load before the operating system. Organizations need Measured Boot, TPM attestation, and EFI System Partition monitoring.

3. **Source code leaks enable derivative threats.** BlackX appears derived from BlackLotus, whose source was partially leaked in 2023. This demonstrates how leaked offensive tooling lowers the barrier for state-sponsored actors to develop sophisticated firmware-level implants.

4. **Cloud C2 blends with legitimate traffic.** The use of Google Drive, OneDrive, and Yandex.Disk for C2 makes network-level detection extremely difficult without deep inspection of cloud API usage patterns.

## Sources

- [Kaspersky Securelist - BlackX UEFI Bootkit Analysis](https://securelist.com/uefi-bootkit-blackx/121539/) -- primary technical analysis by Georgy Kucherin, Vladimir Nestor, and Vasily Berdnikov
- [BleepingComputer - BlackX UEFI Bootkit Exploits Baton Drop](https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/) -- news coverage with additional context on certificate revocation
- [The Hacker News - BlackX UEFI Bootkit Bypasses Secure Boot](https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html) -- news coverage with installer command-line details and FishMonger/APT41 attribution context

---
*Report generated by Actioner*
