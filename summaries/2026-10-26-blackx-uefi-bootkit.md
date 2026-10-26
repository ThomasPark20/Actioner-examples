# Technical Analysis Report: BlackX UEFI Bootkit (2026-10-26)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-26
Version: DRAFT 1.0

## Executive Summary

BlackX is a UEFI bootkit discovered by Kaspersky researchers in early 2026, deployed against diplomatic entities in Tajikistan, Uzbekistan, and Turkmenistan. It exploits the "Baton Drop" Secure Boot bypass (CVE-2022-21894) to load a malicious kernel driver before the operating system starts, then deploys user-mode components including a cloud-based RAT and the OxiDLLRunner DLL sideloading chain. The bootkit specifically targets Kaspersky and Avast security products with callback-disabling and ETW-tampering routines, though Kaspersky reports these were ineffective. Attribution is assessed at medium confidence to APT41 (also tracked as Brass Typhoon, Wicked Panda, Barium), with overlap to the FishMonger subgroup (Aquatic Panda, Earth Lusca) via shared string artifacts and kernel implant characteristics. BlackX is assessed to be an updated version of the BlackLotus bootkit (first seen late 2022), though the BlackLotus source code was never fully public.

## Background: UEFI Secure Boot and the Baton Drop Vulnerability

UEFI Secure Boot is a firmware security mechanism that validates cryptographic signatures of boot components before execution, preventing unauthorized code from loading during the pre-OS boot phase. CVE-2022-21894 ("Baton Drop"), patched by Microsoft in January 2022, is a Secure Boot Security Feature Bypass that allows attackers to enroll custom Machine Owner Keys (MOKs) and load arbitrary EFI files. The fix requires manual revocation of the "Windows Production PCA 2011" certificate from the Secure Boot Forbidden Signature Database (DBX). This revocation is not automatic upon patch installation; administrators must trigger it via a registry flag under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot` and a scheduled task named `Secure-Boot-Update`. CVE-2023-24932 is a related downgrade attack that can bypass the CVE-2022-21894 mitigations by forcing boot with an older, signed Windows Boot Manager. The "Windows Production PCA 2011" certificate expired on October 19, 2026, but expiry alone does not block vulnerable binaries unless the certificate is explicitly blocklisted.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Oct 2022 | BlackLotus UEFI bootkit first advertised on cybercrime forums |
| Jan 2022 | Microsoft patches CVE-2022-21894 (Baton Drop) |
| Mar 2023 | ESET confirms BlackLotus actively exploits Baton Drop in the wild |
| Jul 2023 | Incomplete BlackLotus source code leaked |
| Early 2026 | BlackX campaign targeting Central Asian diplomatic entities discovered |
| Jun 2026 | ESET publishes FishMonger/SprySOCKS report linking kernel implant PDB path to "xdd" identifier |
| Oct 19, 2026 | "Windows Production PCA 2011" certificate expires |
| Oct 23, 2026 | Kaspersky publishes BlackX technical report |

## Root Cause: Secure Boot Bypass via Baton Drop (CVE-2022-21894)

Initial access is unspecified in available reporting. However, the installer (`inst.exe`) requires administrator-level privileges on the target. Once executed, the installer exploits CVE-2022-21894 to bypass Secure Boot and enroll custom MOKs, enabling loading of arbitrary EFI binaries. The exploitation implementation is described by Kaspersky as "remarkably similar" to BlackLotus's approach. The installer is launched via the command line:

```
C:\ProgramData\Intel\inst.exe PVMDIJGKAX2 Q46F6MDLI3RX2KV1
```

where `PVMDIJGKAX2` is an RC4-encrypted extensionless container holding the files and strings needed for installation, and `Q46F6MDLI3RX2KV1` is the RC4 decryption key. The installer binary (`inst.exe`) itself contains no embedded malicious strings or blobs, making static detection of it in isolation difficult.

## Technical Analysis of the Malicious Payload

### 1. Installer and UEFI Payload Deployment

The installer (`C:\ProgramData\Intel\inst.exe`) decrypts the `PVMDIJGKAX2` container using the RC4 key `Q46F6MDLI3RX2KV1` and drops files to both the system partition and the UEFI (EFI System) partition. Specific EFI file names and partition paths were not disclosed by Kaspersky. The UEFI payload exploits CVE-2022-21894 to install custom MOKs, which allow arbitrary EFI files to load during boot, and injects a malicious kernel driver into the Windows kernel.

### 2. Kernel Driver

The kernel driver is signed with a certificate issued to "Wenjiang District Mingyu Network Technology Service Studio" (certificate serial: `0bcdf5e0da32d68900b8b7638459d072`), which has since been revoked by its issuer. The driver performs the following actions:

- **Disables security callbacks**: removes process, thread, and registry callbacks registered by security products.
- **Tampers with ETW providers**: disrupts Event Tracing for Windows to prevent security tools from receiving telemetry.
- **Conditional targeting**: some tampering routines execute only if Kaspersky or Avast products are detected on the system. Kaspersky states these routines were ineffective against their products.
- **File access interception**: intercepts kernel-level file open requests for the bootkit's protected files and returns a handle to `calc.exe` (Windows Calculator) instead, preventing analysts from reading the actual bootkit files.

### 3. C2 Infrastructure

BlackX uses a multi-layered C2 architecture:

**Cloud storage RAT**: Uses Google Drive, OneDrive, or Yandex.Disk for command and control. The RAT polls files in cloud storage and acts on them based on file suffix:

| Suffix | Direction | Function |
|--------|-----------|----------|
| `0X01` | Input | .NET file to parse and execute via `TEST.Class1.RunCMD` |
| `0X02` | Output | Result of RunCMD execution |
| `0X03` | Input | File upload task |
| `0X04` | Output | Uploaded file content |
| `0X05` | Input | File download task to infected machine |
| `0X06` | Output | Download status |
| `SSSR` | Output | Initial system information |

**OxiDLLRunner/Rust payload C2**: The Rust payload communicates with `www[.]archivetj[.]com` to receive DLL plugins that export `create_plugin`, each executed in a separate thread.

### 4. Platform-Specific Behavior

#### Windows

BlackX targets Windows systems with UEFI Secure Boot, specifically those where the manual Baton Drop revocation steps have not been applied. The full attack chain operates exclusively on Windows:

- **Boot phase**: UEFI payload loads before the OS, injecting the kernel driver.
- **Kernel phase**: Driver manipulates OS security mechanisms.
- **User-mode phase**: DLL sideloading via `googleupdate.exe` (renamed `jcef_helper.exe`, MD5: `af8a983b9ada07eae1259bf2953abd40`) loads the OxiDLLRunner DLL, which decrypts `v8_context_snapshot.bin` containing shellcode and a Rust PE payload.
- **Persistence**: Achieved at the firmware level through MOK enrollment; the bootkit persists across OS reinstallation.

### 5. Anti-Forensics / Evasion Techniques

- **RC4-encrypted installer payload**: The `PVMDIJGKAX2` container is encrypted; `inst.exe` contains no plaintext malicious strings.
- **OLLVM obfuscation**: The OxiDLLRunner DLL is obfuscated with OLLVM.
- **DLL sideloading**: Uses a legitimate, signed binary (`googleupdate.exe`/`jcef_helper.exe`) to load the malicious DLL.
- **File access redirection**: Kernel driver returns `calc.exe` handle for bootkit files, frustrating forensic analysis.
- **Kernel callback removal**: Disables security product hooks at the kernel level.
- **ETW tampering**: Prevents security tools from receiving event telemetry.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (MD5) | Description |
|----------|------|------------|-------------|
| Windows | `C:\ProgramData\Intel\inst.exe` | N/A | BlackX installer executable (no embedded malicious strings) |
| Windows | `PVMDIJGKAX2` (same dir as inst.exe) | N/A | RC4-encrypted container with installation payload |
| Windows | `googleupdate.exe` (renamed `jcef_helper.exe`) | `af8a983b9ada07eae1259bf2953abd40` | Legitimate binary abused for DLL sideloading |
| Windows | `v8_context_snapshot.bin` (same dir as googleupdate.exe) | N/A | Encrypted payload decrypted by OxiDLLRunner |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `www[.]archivetj[.]com` | Rust payload C2 -- delivers DLL plugins |
| Cloud Service | Google Drive | Cloud RAT C2 channel |
| Cloud Service | OneDrive | Cloud RAT C2 channel |
| Cloud Service | Yandex.Disk | Cloud RAT C2 channel |

### Certificates

| Attribute | Value |
|-----------|-------|
| Subject | Wenjiang District Mingyu Network Technology Service Studio |
| Serial Number | `0bcdf5e0da32d68900b8b7638459d072` |
| Status | Revoked |
| Usage | Signing malicious kernel driver |

### Behavioral

- Installer execution pattern: `inst.exe <encrypted_file> <RC4_key>` from `C:\ProgramData\Intel\`
- DLL sideloading: `googleupdate.exe` (OriginalFileName: `jcef_helper.exe`) loading an OLLVM-obfuscated DLL
- Kernel driver disabling process/thread/registry callbacks and ETW providers
- File access redirection: opening bootkit files returns `calc.exe` handle
- Cloud storage polling with file suffixes `0X01`-`0X06` and `SSSR`
- Rust payload calling `create_plugin` export on downloaded DLLs

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1542.003 | Pre-OS Boot: Bootkit | UEFI bootkit exploiting CVE-2022-21894 to persist before OS load |
| T1553.006 | Subvert Trust Controls: Code Signing Policy Modification | Secure Boot bypass via Baton Drop; enrolling custom MOKs |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Legitimate `googleupdate.exe` sideloads OxiDLLRunner DLL |
| T1014 | Rootkit | Kernel driver with callback removal and file access redirection |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Disabling security product callbacks and ETW providers |
| T1027 | Obfuscated Files or Information | OLLVM obfuscation of OxiDLLRunner; RC4-encrypted container |
| T1140 | Deobfuscate/Decode Files or Information | RC4 decryption of PVMDIJGKAX2; decryption of v8_context_snapshot.bin |
| T1102 | Web Service | Cloud storage (Google Drive, OneDrive, Yandex.Disk) used for C2 |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | .NET payloads executed via TEST.Class1.RunCMD |

## Impact Assessment

BlackX targets a narrow set of diplomatic entities in Central Asia (Tajikistan, Uzbekistan, Turkmenistan), consistent with an espionage campaign. The UEFI-level persistence is exceptionally difficult to detect and survives OS reinstallation. The bootkit's kernel driver actively undermines endpoint security products, and the file access redirection technique hinders incident response. The mitigation gap is significant: fully patched Windows systems remain vulnerable if the manual Secure Boot revocation steps were not applied, and the "Windows Production PCA 2011" certificate expiration on October 19, 2026, does not automatically close the gap.

## Detection & Remediation

### Immediate Detection

- Search for the presence of `C:\ProgramData\Intel\inst.exe` and `PVMDIJGKAX2` on endpoints.
- Check for `googleupdate.exe` with OriginalFileName `jcef_helper.exe` in non-standard locations (outside legitimate Google or Chromium install directories).
- Query DNS logs for `archivetj[.]com`.
- Review Secure Boot DBX status: check whether the "Windows Production PCA 2011" certificate is in the DBX. If not, the system may be vulnerable.
- Look for the scheduled task `Secure-Boot-Update` (legitimate Microsoft mitigation; its absence on a patched system may indicate incomplete remediation).
- Monitor for process creation events matching `inst.exe` with command-line arguments containing `PVMDIJGKAX2` or `Q46F6MDLI3RX2KV1`.

### Remediation

1. **Containment**: Isolate affected systems from the network immediately.
2. **Secure Boot revocation**: Apply the manual DBX update to revoke the "Windows Production PCA 2011" certificate. Follow [Microsoft's guidance on revoking vulnerable boot managers](https://techcommunity.microsoft.com/blog/windows-itpro-blog/revoking-vulnerable-windows-boot-managers/4121735).
3. **Firmware-level remediation**: A UEFI bootkit cannot be removed by OS reinstallation alone. Re-flash the system firmware and clear the MOK database to remove the enrolled malicious keys.
4. **Driver certificate blocking**: Block the revoked certificate (serial `0bcdf5e0da32d68900b8b7638459d072`) via Windows Defender Application Control (WDAC) or equivalent driver signing policies.
5. **Credential rotation**: Assume all credentials on affected systems are compromised. Rotate domain admin credentials, service account credentials, and any secrets accessible from affected hosts.
6. **Cloud storage audit**: Review Google Drive, OneDrive, and Yandex.Disk activity for accounts accessible from affected systems for signs of RAT C2 traffic.

### Long-Term Hardening

- **Advisory**: Apply the Secure Boot DBX revocation on all Windows systems. Note that this revocation is configuration-dependent -- on systems with non-standard boot configurations or dual-boot setups, applying the revocation without testing may cause boot failures. Test in your environment before broad deployment.
- Enable Secure Boot DBX monitoring and alerting for unauthorized MOK enrollments.
- Implement WDAC policies to restrict kernel driver loading to trusted certificates.
- Deploy UEFI firmware integrity monitoring where supported by hardware.
- Block the domain `archivetj[.]com` at the network perimeter.

## Detection Rules

These detections target the BlackX UEFI bootkit's distinctive installer artifacts, DLL sideloading chain, file-level indicators, and C2 domain. All rules are PoC/advisory-specific (default altitude, strict leniency), keying on concrete artifacts from the Kaspersky report. Note: compile status reflects validation against the installed toolchain; it does not guarantee the rule will fire in your environment without telemetry verification.

### Sigma: BlackX Installer Execution

Detects execution of the BlackX installer with its distinctive encrypted container filename or RC4 key on the command line.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Keys on published artifacts PVMDIJGKAX2 and Q46F6MDLI3RX2KV1 from Kaspersky report. FP risk: negligible — random alphanumeric strings. Evasion: attacker changes key/container name → rule no longer fires (expected for specific-altitude). -->
```yaml
title: BlackX UEFI Bootkit Installer Execution
id: 7c3a1e8f-4b2d-4f6e-9a1c-5d8e3f7b2a4c
status: experimental
description: >
    Detects execution of the BlackX UEFI bootkit installer with its distinctive
    encrypted container filename and RC4 decryption key on the command line.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/
author: Actioner
date: 2026/10/26
tags:
    - attack.t1542.003
    - attack.t1140
logsource:
    category: process_creation
    product: windows
detection:
    selection_path:
        Image|endswith: '\inst.exe'
        Image|contains: '\ProgramData\Intel\'
    selection_cmdline:
        CommandLine|contains:
            - 'PVMDIJGKAX2'
            - 'Q46F6MDLI3RX2KV1'
    condition: selection_path or selection_cmdline
falsepositives:
    - Unlikely - highly specific to BlackX campaign artifacts
level: critical
```

### Sigma: BlackX OxiDLLRunner Sideloading via Renamed jcef_helper

Detects execution of `googleupdate.exe` (renamed `jcef_helper.exe`) with the known MD5 hash used by BlackX for DLL sideloading.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Keys on published MD5 AF8A983B9ADA07EAE1259BF2953ABD40 and OriginalFileName metadata from Kaspersky report. FP: legitimate jcef_helper.exe in Chromium-based apps may match the renamed-binary selection — the hash selection is precise. Hashes field availability depends on Sysmon config. -->
```yaml
title: BlackX OxiDLLRunner Sideloading via Renamed jcef_helper
id: 2f8d6a4e-1c3b-4e7f-8d5a-9b2c6e1f3a7d
status: experimental
description: >
    Detects the execution of googleupdate.exe (renamed jcef_helper.exe) used by
    BlackX to sideload the OxiDLLRunner DLL. Matches the known MD5 hash or the
    original filename with a suspicious parent path.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html
author: Actioner
date: 2026/10/26
tags:
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains: 'AF8A983B9ADA07EAE1259BF2953ABD40'
    selection_renamed:
        OriginalFileName: 'jcef_helper.exe'
        Image|endswith: '\googleupdate.exe'
    condition: selection_hash or selection_renamed
falsepositives:
    - Legitimate JCEF helper binary in Chromium-based applications
level: high
```

### Sigma: BlackX Encrypted Container or Payload File Creation

Detects creation of the BlackX-specific RC4-encrypted container `PVMDIJGKAX2` or the encrypted payload `v8_context_snapshot.bin` under `ProgramData`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. PVMDIJGKAX2 is a unique extensionless filename; v8_context_snapshot.bin is a legitimate Chromium file but scoped to ProgramData (non-standard for legitimate Chromium installs). FP: v8_context_snapshot.bin selection may match Electron apps writing to ProgramData — the PVMDIJGKAX2 selection has near-zero FP risk. -->
```yaml
title: BlackX Encrypted Container or Payload File Creation
id: 9e4b7d2c-3a1f-4c8e-b6d5-1f7a2e8c4b3d
status: experimental
description: >
    Detects creation of BlackX-specific files: the RC4-encrypted container
    PVMDIJGKAX2 or the encrypted payload v8_context_snapshot.bin in paths
    associated with the campaign.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
author: Actioner
date: 2026/10/26
tags:
    - attack.t1027
    - attack.t1074.001
logsource:
    category: file_event
    product: windows
detection:
    selection_container:
        TargetFilename|endswith: '\PVMDIJGKAX2'
    selection_payload:
        TargetFilename|endswith: '\v8_context_snapshot.bin'
        TargetFilename|contains: '\ProgramData\'
    condition: selection_container or selection_payload
falsepositives:
    - Legitimate Chromium-based applications creating v8_context_snapshot.bin in program directories
level: high
```

### Snort: BlackX DNS Query to C2 Domain archivetj.com

Detects DNS queries for the BlackX C2 domain `archivetj[.]com` used by the Rust payload to receive DLL plugins.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 -T exit 0 with minimal config + classification. DNS label-length encoding: archivetj = 9 bytes (|09|), com = 3 bytes (|03|), root (|00|). Real (not defanged) values in rule. -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - BlackX DNS Query to C2 Domain archivetj.com"; content:"|09|archivetj|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/uefi-bootkit-blackx/121539; sid:2100001; rev:1;)
```

### Suricata: BlackX DNS Query to C2 Domain archivetj.com

Detects DNS queries for the BlackX C2 domain `archivetj[.]com` via Suricata's native DNS query buffer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T exit 0. Uses dns.query sticky buffer with dot-notation. Real (not defanged) domain value. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - BlackX DNS Query to C2 Domain archivetj.com"; flow:to_server; dns.query; content:"archivetj.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/uefi-bootkit-blackx/121539; metadata:author Actioner, created_at 2026-10-26; sid:2200001; rev:1;)
```

### YARA: BlackX Installer and Payload Strings

Detects BlackX components via distinctive campaign strings including the encrypted container name, RC4 key, RAT command method, plugin export, and C2 domain.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: pos.txt with published strings PVMDIJGKAX2 + Q46F6MDLI3RX2KV1 + TEST.Class1.RunCMD → Bootkit_BlackX_Installer_Strings matched. neg.txt (benign text) → no match. Condition: 2 of 9 strings, covering installer, RAT, and sideloading artifacts. No PE header gate on rule 1 to catch non-PE artifacts (encrypted containers, scripts). -->
```yara
rule Bootkit_BlackX_Installer_Strings
{
    meta:
        description = "Detects BlackX UEFI bootkit components via installer-specific strings, RC4 key, encrypted container name, and RAT command identifiers"
        author = "Actioner"
        date = "2026-10-26"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $installer_container = "PVMDIJGKAX2" ascii wide
        $rc4_key = "Q46F6MDLI3RX2KV1" ascii wide
        $rat_method = "TEST.Class1.RunCMD" ascii wide
        $plugin_export = "create_plugin" ascii fullword
        $c2_domain = "archivetj.com" ascii wide
        $encrypted_payload = "v8_context_snapshot.bin" ascii wide
        $rat_suffix_sssr = "SSSR" ascii fullword
        $rat_suffix_01 = "0X01" ascii fullword
        $rat_suffix_02 = "0X02" ascii fullword

    condition:
        2 of them
}

rule Bootkit_BlackX_OxiDLLRunner_Sideload
{
    meta:
        description = "Detects the legitimate jcef_helper.exe binary (renamed googleupdate.exe) abused by BlackX for DLL sideloading based on PE metadata"
        author = "Actioner"
        date = "2026-10-26"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        hash = "af8a983b9ada07eae1259bf2953abd40"
        severity = "high"
        tlp = "WHITE"

    strings:
        $original_name = "jcef_helper.exe" ascii wide
        $c2_domain = "archivetj.com" ascii wide
        $plugin_fn = "create_plugin" ascii fullword
        $container = "PVMDIJGKAX2" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $original_name and
        1 of ($c2_domain, $plugin_fn, $container)
}
```

## Lessons Learned

- **Manual revocation is a deployment gap**: The Baton Drop mitigation requires manual steps that many organizations have not completed, even four years after the patch. Bootkits like BlackX demonstrate the risk of leaving this gap open.
- **UEFI persistence defeats standard remediation**: OS reinstallation does not remove a UEFI bootkit. Organizations need firmware integrity monitoring and the ability to re-flash firmware and clear MOK databases as part of their incident response playbook.
- **Cloud storage C2 is hard to detect at the network level**: Using Google Drive, OneDrive, and Yandex.Disk for C2 blends with legitimate traffic. Detection must focus on endpoint behavioral indicators (file suffixes, .NET payload execution patterns) rather than network-level domain blocking.
- **DLL sideloading via legitimate signed binaries remains effective**: The use of a renamed, legitimate Chromium component (`jcef_helper.exe` as `googleupdate.exe`) highlights the continued value of monitoring `OriginalFileName` mismatches.
- **APT tooling evolution**: BlackX demonstrates that espionage actors are building on leaked or reverse-engineered bootkit frameworks (BlackLotus) to develop more targeted, evasion-focused variants.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Kaspersky Securelist - BlackX UEFI Bootkit](https://securelist.com/uefi-bootkit-blackx/121539/) — primary technical analysis by Georgy Kucherin, Vladimir Nestor, Vasily Berdnikov
- [BleepingComputer - BlackX UEFI Bootkit Exploits Baton Drop Flaw](https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/) — secondary coverage with timeline and remediation context
- [The Hacker News - BlackX UEFI Bootkit Bypasses Secure Boot](https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html) — secondary coverage with attribution and FishMonger overlap details
- [Microsoft - Revoking Vulnerable Windows Boot Managers](https://techcommunity.microsoft.com/blog/windows-itpro-blog/revoking-vulnerable-windows-boot-managers/4121735) — remediation guidance for Secure Boot DBX revocation

---
*Report generated by Actioner*
