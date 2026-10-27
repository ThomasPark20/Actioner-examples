<!-- revision: fixed Sigma driver rule (logsource image_load->driver_load, SignatureStatus->OR Valid/Revoked), defanged archivetj.com in Immediate Detection, corrected T1027.002->T1027 (OLLVM is compile-time obfuscation not packing), added attack.t1071.004 tag to DNS Sigma rule, added TPM 2.0 caveat to hardening item 5 -->
# Technical Analysis Report: BlackX UEFI Bootkit (2026-10-27)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-27
Version: DRAFT 1.0

## Executive Summary

BlackX is a UEFI bootkit discovered by Kaspersky in early 2026, used in an espionage campaign targeting diplomatic agencies in Tajikistan, Uzbekistan, and Turkmenistan. Attributed with medium confidence to APT41 (Brass Typhoon/Wicked Panda), the bootkit exploits CVE-2022-21894 ("Baton Drop") and CVE-2023-24932 to bypass Secure Boot on fully patched Windows systems that have not manually applied Microsoft's DBX revocation. The attack chain enrolls custom Machine Owner Keys (MOKs) to load arbitrary EFI binaries, injects a malicious kernel driver signed with a now-revoked certificate, and deploys user-mode payloads including a cloud-storage-based RAT and the "OxiDLLRunner" Rust-based implant. The campaign demonstrates that the Baton Drop vulnerability remains a live threat to organizations that have not completed the manual Secure Boot revocation process.

## Background: Secure Boot and Baton Drop (CVE-2022-21894)

Secure Boot is a UEFI firmware feature designed to ensure only trusted, signed software loads during the boot process. CVE-2022-21894, known as "Baton Drop," is a vulnerability in the Windows Boot Manager that allows an attacker with administrator privileges or physical access to bypass Secure Boot by exploiting a flaw in the Boot Configuration Data (BCD) handling. Microsoft patched the vulnerability but deliberately did not automatically revoke the "Windows Production PCA 2011" certificate used to sign vulnerable boot components, because doing so risked rendering systems unbootable. Instead, administrators must manually set a registry flag under `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot` and run a scheduled task named `Secure-Boot-Update` to add the certificate to the DBX (Secure Boot Forbidden List). The certificate expired on October 19, 2026, but Kaspersky confirms this expiration does not prevent vulnerable binaries from loading unless the DBX update has been applied.

BlackLotus, the first in-the-wild UEFI bootkit to bypass Secure Boot, was advertised on hacking forums in October 2022 for $5,000 and confirmed by ESET in March 2023. BlackX's Secure Boot bypass is "remarkably similar" to BlackLotus, and Kaspersky concludes the BlackX authors either reverse-engineered BlackLotus or obtained its full source code.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2022-10 | BlackLotus UEFI bootkit advertised on hacking forums |
| 2023-01 | Microsoft patches CVE-2022-21894 (Baton Drop) |
| 2023-03 | ESET confirms BlackLotus is genuine |
| 2023-07 | Incomplete BlackLotus source code leaked online |
| 2023-2024 | FishMonger/APT41 campaigns with SprySOCKS backdoor targeting Honduras, Taiwan, Thailand, Pakistan (per ESET) |
| Early 2026 | BlackX UEFI bootkit campaign targeting Central Asian diplomatic agencies discovered |
| 2026-06 | ESET publishes FishMonger report linking activity to APT41 umbrella |
| 2026-10-19 | "Windows Production PCA 2011" certificate expires (does not block vulnerable binaries) |
| 2026-10-22 | Kaspersky publishes Securelist report on BlackX |

## Root Cause: Incomplete Secure Boot Revocation

The targeted systems were fully patched Windows installations. The attack succeeded because administrators had not completed the manual Secure Boot revocation process (Microsoft KB5025885). Initial access vector is undisclosed; attackers had already obtained administrator privileges before deploying BlackX.

## Technical Analysis of the Malicious Payload

### 1. Installation and Secure Boot Bypass

The installer is delivered as `inst.exe` in the path `C:\ProgramData\Intel\` alongside an RC4-encrypted file named `PVMDIJGKAX2`. The installation command follows the pattern:

```
C:\ProgramData\Intel\inst.exe PVMDIJGKAX2 Q46F6MDLI3RX2KV1
```

The second argument (`Q46F6MDLI3RX2KV1`) serves as the RC4 decryption key. The installer decrypts the archive, extracts the bootkit components, enrolls a custom Machine Owner Key (MOK) in the UEFI firmware, and modifies the EFI System Partition to load arbitrary EFI binaries. This process exploits CVE-2022-21894 in a manner "remarkably similar" to BlackLotus, using a downgrade path (CVE-2023-24932) that forces the system to boot with an older, vulnerable Windows Boot Manager signed under the still-trusted "Windows Production PCA 2011" certificate.

### 2. Malicious Kernel Driver

The UEFI payload injects a malicious kernel driver into the Windows kernel. The driver is signed with a certificate issued to "Wenjiang District Mingyu Network Technology Service Studio" (certificate serial: `0bcdf5e0da32d68900b8b7638459d072`), which has since been revoked by the issuer.

The driver performs the following actions:
- **Disables security callbacks**: Removes process, thread, and registry callbacks associated with security products
- **Tampers with ETW**: Modifies Event Tracing for Windows (ETW) providers to prevent security tools from accessing their output
- **Conditional anti-security routines**: Some tampering procedures execute only if Kaspersky or Avast products are detected on the infected machine (Kaspersky reports these routines are ineffective against its products)
- **File protection**: Intercepts user requests to open the bootkit's files and returns a handle to `calc.exe` instead

### 3. C2 Infrastructure

BlackX deploys two distinct user-mode payloads with different C2 mechanisms:

**RAT (Cloud Storage C2)**:
- Uses Google Drive, OneDrive, and Yandex.Disk as C2 channels
- Iterates over files in cloud storage with suffixes 0X01 through 0X06
- Initial system information file tagged with `SSSR`
- Executes .NET payloads via the method `TEST.Class1.RunCMD`
- Supports file upload and download tasks

**OxiDLLRunner (Domain-based C2)**:
- OLLVM-obfuscated DLL sideloaded by `googleupdate.exe` (a renamed legitimate `jcef_helper.exe`, MD5: `AF8A983B9ADA07EAE1259BF2953ABD40`)
- Decrypts `v8_context_snapshot.bin` to launch shellcode and a Rust payload
- The Rust payload contacts `www[.]archivetj[.]com` to download DLL plugins
- Downloaded DLLs must export a `create_plugin` function, which is invoked in separate threads

### 4. Anti-Forensics / Evasion Techniques

- **UEFI persistence**: Loads before the operating system, surviving OS reinstallation unless the EFI System Partition is cleaned
- **Secure Boot bypass**: Exploits Baton Drop to appear as a legitimately signed boot component
- **DLL sideloading**: Uses a legitimate Chromium Embedded Framework binary (`jcef_helper.exe`) renamed to `googleupdate.exe`
- **OLLVM obfuscation**: The OxiDLLRunner DLL is obfuscated with OLLVM, a common technique among Chinese-speaking threat actors
- **RC4 encryption**: Installation payload encrypted with RC4
- **Cloud C2**: RAT traffic blends with legitimate enterprise cloud storage usage
- **ETW tampering**: Prevents endpoint security from accessing telemetry
- **File handle substitution**: Opens `calc.exe` instead of bootkit files when they are accessed
- **Revoked but valid signing**: Uses a third-party code-signing certificate that was valid at the time of signing

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `archivetj[.]com`)

### File System

| Platform | Path / Filename | Hash | Description |
|----------|----------------|------|-------------|
| Windows | `C:\ProgramData\Intel\inst.exe` | — | BlackX installer executable |
| Windows | `C:\ProgramData\Intel\PVMDIJGKAX2` | — | RC4-encrypted bootkit payload |
| Windows | `googleupdate.exe` | MD5: `AF8A983B9ADA07EAE1259BF2953ABD40` | Renamed `jcef_helper.exe` used for DLL sideloading |
| Windows | `v8_context_snapshot.bin` | — | Encrypted payload decrypted by OxiDLLRunner |

Note: SHA256 hashes were not available in the public reporting at the time of this analysis. The Kaspersky Securelist report may contain additional hashes in its full IOC appendix.

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `archivetj[.]com` | OxiDLLRunner C2 domain for DLL plugin delivery |
| Domain | `www[.]archivetj[.]com` | Full C2 URL |
| Cloud Service | Google Drive | RAT C2 channel |
| Cloud Service | OneDrive | RAT C2 channel |
| Cloud Service | Yandex.Disk | RAT C2 channel |

### Certificates

| Serial Number | Subject | Status | Context |
|---------------|---------|--------|---------|
| `0bcdf5e0da32d68900b8b7638459d072` | Wenjiang District Mingyu Network Technology Service Studio | Revoked | BlackX kernel driver signing certificate |

### Behavioral

- Process creation from `C:\ProgramData\Intel\inst.exe` with arguments containing `PVMDIJGKAX2` and RC4 key `Q46F6MDLI3RX2KV1`
- `jcef_helper.exe` renamed to `googleupdate.exe` executing from non-standard paths
- Kernel driver loading with Wenjiang District certificate signature
- ETW provider tampering following driver load
- File-open interception returning handles to `calc.exe`
- Cloud storage API calls with file suffixes 0X01-0X06 and SSSR tags
- DLL plugins downloaded with `create_plugin` exports
- PDB path or string containing `\xdd\Desktop\`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1542.003 | Pre-OS Boot: Bootkit | BlackX installs as a UEFI bootkit, loading before the OS by exploiting Baton Drop to enroll custom MOKs and inject a kernel driver |
| T1553.006 | Subvert Trust Controls: Code Signing Policy Modification | Enrolls a custom Machine Owner Key (MOK) to bypass Secure Boot and load unsigned/arbitrary EFI binaries |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Renames legitimate `jcef_helper.exe` to `googleupdate.exe` for OxiDLLRunner sideloading |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Kernel driver disables process/thread/registry callbacks and tampers with ETW providers; conditional routines target Kaspersky and Avast |
| T1071.001 | Application Layer Protocol: Web Protocols | OxiDLLRunner Rust payload communicates with archivetj[.]com over HTTP/S to fetch DLL plugins |
| T1102 | Web Service | RAT uses Google Drive, OneDrive, and Yandex.Disk as C2 channels |
| T1140 | Deobfuscate/Decode Files or Information | RC4 decryption of the PVMDIJGKAX2 archive and decryption of v8_context_snapshot.bin |
| T1027 | Obfuscated Files or Information | OxiDLLRunner is obfuscated at compile time with OLLVM (Obfuscating LLVM), a compile-time obfuscation framework |

## Impact Assessment

BlackX targets a narrow set of diplomatic organizations in Central Asia, suggesting a targeted espionage campaign rather than wide-scale deployment. However, the underlying vulnerability (Baton Drop) affects any Windows system where the manual Secure Boot revocation has not been applied, which Microsoft and the NSA have warned is common across enterprise environments. The UEFI-level persistence makes this particularly difficult to detect and remediate, as the bootkit survives OS reinstallation and standard disk-based forensic acquisition may miss EFI System Partition modifications.

## Detection & Remediation

### Immediate Detection

1. Check for the presence of `C:\ProgramData\Intel\inst.exe` or `PVMDIJGKAX2` on endpoints
2. Search for `googleupdate.exe` with original filename `jcef_helper.exe` in process creation logs
3. Check DNS logs for queries to `archivetj[.]com`
4. Verify Secure Boot revocation status by checking for Event ID 1037 in the System event log (indicates revocation was applied)
5. Audit loaded kernel drivers for the certificate serial `0bcdf5e0da32d68900b8b7638459d072`

### Remediation

1. **Apply DBX revocation**: Follow Microsoft KB5025885 to complete the Secure Boot revocation process (set registry flag, run Secure-Boot-Update task, verify Event ID 1037)
2. **Clean EFI System Partition**: If compromise is confirmed, rebuild the EFI System Partition from known-good media
3. **Reinstall from clean media**: UEFI bootkits survive OS reinstallation; a clean firmware flash or EFI partition rebuild is required
4. **Block C2**: Add `archivetj[.]com` to DNS blocklists and proxy deny lists
5. **Revoke compromised credentials**: Assume all credentials on infected systems are compromised
6. **Audit cloud storage**: Review Google Drive, OneDrive, and Yandex.Disk API access for unusual file patterns (suffixes 0X01-0X06, SSSR tags)

### Long-Term Hardening

1. Deploy the Secure Boot DBX update across all Windows endpoints via enterprise management tools
2. Monitor for Event ID 1037 to confirm revocation is applied fleet-wide
3. Implement kernel driver allowlisting policies (WDAC/HVCI)
4. Enable Sysmon with driver-load logging (Event ID 6) and image-load logging (Event ID 7)
5. Monitor EFI System Partition integrity with Measured Boot and TPM attestation (note: requires TPM 2.0 hardware and firmware-level configuration; verify endpoint fleet support before deploying, as many older systems lack TPM 2.0 or have it disabled in firmware)

## Detection Rules

Three YARA rules target the bootkit installer, OxiDLLRunner, and RAT components via campaign-specific strings. Five Sigma rules detect installer execution, DLL sideloading, C2 DNS queries, driver loading, and file drops. One Snort and one Suricata rule detect DNS queries to the known C2 domain. SHA256 hashes were not available in public reporting, so YARA rules rely on string combinations rather than hash matching; they should be updated when hashes are published.

### YARA: BlackX Bootkit Installer and Components

Detects BlackX installer and associated components via campaign-specific strings including the encrypted payload name, RC4 key, .NET method, and plugin export.
compile: validated | confidence: high (campaign-specific strings)

<!-- audit: yarac exit 0; condition requires MZ header + filesize < 10MB + combination of unique campaign strings (PVMDIJGKAX2 + RC4 key, or .NET method + SSSR tag, or create_plugin + payload file, or 3-of-8); no SHA256 hashes available in public reporting so hash pinning is absent; strings are unique to this campaign per Kaspersky Securelist report -->

```yara
rule APT41_BlackX_Bootkit_Installer
{
    meta:
        description = "Detects BlackX UEFI bootkit installer and associated components based on unique strings from the campaign targeting Central Asian diplomats"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $inst_arg = "PVMDIJGKAX2" ascii wide
        $rc4_key = "Q46F6MDLI3RX2KV1" ascii wide
        $path1 = "\\ProgramData\\Intel\\inst.exe" ascii wide
        $payload_file = "v8_context_snapshot.bin" ascii wide
        $plugin_export = "create_plugin" ascii fullword
        $dotnet_method = "TEST.Class1.RunCMD" ascii
        $tag_sssr = "SSSR" ascii fullword
        $pdb_xdd = "\\xdd\\Desktop\\" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($inst_arg and $rc4_key) or
            ($dotnet_method and $tag_sssr) or
            ($plugin_export and $payload_file) or
            (3 of them)
        )
}
```

### YARA: BlackX OxiDLLRunner

Detects the OxiDLLRunner component via the C2 domain string combined with other campaign indicators.
compile: validated | confidence: high (domain-anchored)

<!-- audit: yarac exit 0; anchored on archivetj.com C2 domain string which is unique and campaign-specific; secondary condition requires at least one additional indicator; OLLVM obfuscation may affect string visibility in packed samples -->

```yara
rule APT41_BlackX_OxiDLLRunner
{
    meta:
        description = "Detects the OxiDLLRunner component of the BlackX UEFI bootkit campaign, an OLLVM-obfuscated DLL that decrypts and launches a Rust payload"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $export = "create_plugin" ascii fullword
        $payload = "v8_context_snapshot.bin" ascii wide
        $c2 = "archivetj.com" ascii wide
        $xdd = "xdd" ascii fullword
        $rust_marker = ".rustc" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        $c2 and
        (1 of ($export, $payload, $xdd, $rust_marker))
}
```

### YARA: BlackX RAT Cloud C2

Detects the BlackX RAT component via the .NET method name and cloud storage file-suffix patterns.
compile: validated | confidence: medium (relies on .NET method string which may not survive obfuscation in future variants)

<!-- audit: yarac exit 0; TEST.Class1.RunCMD is a distinctive .NET method name but could be changed in future variants; SSSR tag and 0X01-0X06 suffixes add specificity; no hash pinning available -->

```yara
rule APT41_BlackX_RAT_CloudC2
{
    meta:
        description = "Detects the BlackX RAT component that uses cloud storage services (Google Drive, OneDrive, Yandex.Disk) for C2 communication"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $dotnet_method = "TEST.Class1.RunCMD" ascii
        $tag = "SSSR" ascii fullword
        $suffix1 = "0X01" ascii
        $suffix2 = "0X02" ascii
        $suffix3 = "0X03" ascii
        $suffix4 = "0X04" ascii
        $suffix5 = "0X05" ascii
        $suffix6 = "0X06" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $dotnet_method and
        ($tag or 3 of ($suffix*))
}
```

### Sigma: BlackX Installer Execution

Detects execution of `inst.exe` from the `ProgramData\Intel` directory or with the campaign-specific RC4 key argument.
compile: validated | confidence: high (campaign-specific path and arguments)

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check failed due to MITRE ATT&CK data fetch (HTTP 403 on proxy, not a rule syntax issue); logsource process_creation/windows uses standard Sysmon EID 1 fields; values are real (not defanged) per logsource-encoding guidance -->

```yaml
title: BlackX UEFI Bootkit Installer Execution
id: a3c7e1b4-9f2d-4a6e-8b5c-1d7f0e3a2c9b
status: experimental
description: >
    Detects execution of the BlackX UEFI bootkit installer (inst.exe) from the
    ProgramData\Intel directory with the characteristic encrypted payload argument
    and RC4 key, as observed in the APT41 campaign targeting Central Asian diplomats.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/
author: Actioner
date: 2026-10-27
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
    selection_args:
        CommandLine|contains|all:
            - 'PVMDIJGKAX2'
            - 'Q46F6MDLI3RX2KV1'
    condition: selection_path or selection_args
falsepositives:
    - Unlikely; the file name and arguments are specific to this campaign
level: critical
```

### Sigma: BlackX DLL Sideloading via Renamed jcef_helper.exe

Detects the OriginalFileName/Image mismatch characteristic of the BlackX DLL sideloading technique.
compile: validated | confidence: medium (OriginalFileName matching depends on Sysmon configuration and PE metadata preservation)

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; uses OriginalFileName (PE metadata, rename-resistant per Sysmon guidance) combined with Image endswith check; legitimate jcef_helper.exe renamed to googleupdate.exe is specific but theoretically possible in Chromium-derived software -->

```yaml
title: BlackX DLL Sideloading via Renamed jcef_helper.exe
id: b4d8f2c5-0a3e-5b7f-9c6d-2e801f4b3d0c
status: experimental
description: >
    Detects potential DLL sideloading activity associated with the BlackX bootkit
    campaign. The legitimate jcef_helper.exe is renamed to googleupdate.exe and
    used to sideload the OxiDLLRunner malicious DLL.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html
author: Actioner
date: 2026-10-27
tags:
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'jcef_helper.exe'
        Image|endswith: '\googleupdate.exe'
    condition: selection
falsepositives:
    - Legitimate software that renames jcef_helper.exe is unlikely but possible in Chromium-derived applications
level: high
```

### Sigma: BlackX C2 DNS Query

Detects DNS resolution of the archivetj[.]com C2 domain used by the OxiDLLRunner payload.
compile: validated | confidence: high (IOC-anchored to known C2 domain)

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; QueryName endswith archivetj.com catches both bare domain and www subdomain; value is real (not defanged) per logsource-encoding guidance; single-domain rule will need updating if additional C2 domains are disclosed -->

```yaml
title: BlackX C2 DNS Query to archivetj.com
id: c5e903d6-1b4f-4c8a-ad7e-3f902a5c4e1d
status: experimental
description: >
    Detects DNS queries to archivetj.com, the C2 domain used by the OxiDLLRunner
    Rust payload component of the BlackX UEFI bootkit campaign attributed to APT41.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/
author: Actioner
date: 2026-10-27
tags:
    - attack.t1071.001
    - attack.t1071.004
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'archivetj.com'
    condition: selection
falsepositives:
    - Legitimate access to archivetj.com is unlikely but cannot be fully excluded
level: high
```

### Sigma: BlackX Driver with Wenjiang Certificate

Detects loading of a driver signed with the revoked Wenjiang District certificate associated with the BlackX kernel driver.
compile: validated | confidence: medium (depends on Sysmon driver_load logging capturing signature details; Signature field may not contain this value in all configurations)

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; uses driver_load category which maps to Sysmon EID 6; Signature field contains certificate subject; SignatureStatus OR covers both Valid (pre-CRL propagation) and Revoked (post-CRL propagation); behavioral rule dependent on Sysmon configuration -->

```yaml
title: BlackX Malicious Driver Loading with Revoked Wenjiang Certificate
id: d6f004e7-2c5a-4d9b-9e8f-4a0a3b6d5f2e
status: experimental
description: >
    Detects loading of a driver signed with the revoked certificate issued to
    Wenjiang District Mingyu Network Technology Service Studio, associated with
    the BlackX bootkit kernel driver used for security product tampering.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
    - https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html
author: Actioner
date: 2026-10-27
tags:
    - attack.t1553.006
    - attack.t1562.001
logsource:
    category: driver_load
    product: windows
detection:
    selection:
        Signed: 'true'
        Signature|contains: 'Wenjiang'
    selection_status_valid:
        SignatureStatus: 'Valid'
    selection_status_revoked:
        SignatureStatus: 'Revoked'
    condition: selection and (selection_status_valid or selection_status_revoked)
falsepositives:
    - Other software legitimately signed by this entity, though the certificate is revoked
level: high
```

### Sigma: BlackX File Drop in ProgramData\Intel

Detects creation of BlackX-associated files in the `C:\ProgramData\Intel` staging directory.
compile: validated | confidence: medium (path-based detection; legitimate Intel software may install to this directory)

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; uses file_event category (Sysmon EID 11); requires both the directory path and one of three specific filenames to reduce FPs from legitimate Intel software; PVMDIJGKAX2 is a highly specific extensionless filename -->

```yaml
title: BlackX Bootkit File Drop in ProgramData Intel Directory
id: e7a105f8-3d6b-4e0c-af9a-5b1a4c7e6a3f
status: experimental
description: >
    Detects creation of files associated with the BlackX bootkit installer in the
    C:\ProgramData\Intel directory, including the installer, encrypted payload,
    and sideloading components.
references:
    - https://securelist.com/uefi-bootkit-blackx/121539/
author: Actioner
date: 2026-10-27
tags:
    - attack.t1542.003
    - attack.t1027
logsource:
    category: file_event
    product: windows
detection:
    selection_path:
        TargetFilename|contains: '\ProgramData\Intel\'
    selection_files:
        TargetFilename|endswith:
            - '\inst.exe'
            - '\PVMDIJGKAX2'
            - '\v8_context_snapshot.bin'
    condition: selection_path and selection_files
falsepositives:
    - Legitimate Intel software installations in ProgramData\Intel may create executables
level: medium
```

### Snort: BlackX C2 DNS Query

Detects DNS queries for archivetj[.]com in UDP DNS traffic using DNS wire-format label encoding.
compile: validated | confidence: high (IOC-anchored to known C2 domain)

<!-- audit: snort -c test.conf -T exit 0; Snort 2.9.20; DNS wire-format encoding: |09| = 9-byte label "archivetj", |03| = 3-byte label "com", |00| = root; nocase handles case variation; fast_pattern set on the domain content match -->

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - BlackX UEFI Bootkit C2 DNS Query to archivetj.com"; flow:to_server; content:"|09|archivetj|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,securelist.com/uefi-bootkit-blackx/121539/; metadata:author Actioner, created 2026-10-27; sid:2100101; rev:1;)
```

### Suricata: BlackX C2 DNS Query

Detects DNS queries for archivetj[.]com using Suricata's native `dns.query` sticky buffer.
compile: validated | confidence: high (IOC-anchored to known C2 domain)

<!-- audit: suricata -T -S blackx_c2_suricata.rules -l /tmp/actioner exit 0; Suricata 7.0.3; uses dns protocol with dns.query sticky buffer for normalized domain matching; nocase and fast_pattern applied -->

```
alert dns $HOME_NET any -> any any (msg:"Actioner - BlackX UEFI Bootkit C2 DNS Query to archivetj.com"; flow:to_server; dns.query; content:"archivetj.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/uefi-bootkit-blackx/121539/; metadata:author Actioner, created_at 2026-10-27; sid:2100201; rev:1;)
```

## Lessons Learned

1. **Manual revocation gaps persist**: The Baton Drop patch requires a manual step that many organizations have not completed, even years after the fix was available. BlackX demonstrates that nation-state actors will exploit these gaps.
2. **BlackLotus lineage continues**: BlackX confirms that the BlackLotus techniques are being adopted or evolved by state-sponsored actors, elevating UEFI bootkits from a crimeware concern to an espionage tool.
3. **Cloud storage C2 is increasingly common**: Using Google Drive, OneDrive, and Yandex.Disk for C2 makes network-based detection extremely difficult, as these are legitimate enterprise services.
4. **Certificate expiration is not revocation**: The October 2026 expiration of the Windows Production PCA 2011 certificate does not prevent exploitation. Only adding the certificate to the DBX blocklist mitigates Baton Drop.
5. **UEFI integrity monitoring is essential**: Traditional endpoint detection does not inspect the EFI System Partition or UEFI variables. Organizations need Measured Boot, TPM attestation, and WDAC/HVCI policies to detect and prevent this class of attack.

## Sources

- [Kaspersky Securelist - New BlackX UEFI bootkit exploiting Baton Drop](https://securelist.com/uefi-bootkit-blackx/121539/) -- primary technical analysis by Kaspersky researchers Georgy Kucherin, Vladimir Nestor, Vasily Berdnikov
- [BleepingComputer - BlackX UEFI bootkit exploits Baton Drop flaw to bypass Secure Boot](https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/) -- secondary reporting with additional context on the Baton Drop vulnerability
- [The Hacker News - BlackX UEFI Bootkit Bypasses Secure Boot](https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html) -- secondary reporting with FishMonger/ESET link details and attribution analysis
- [NetManageIT - BlackX UEFI Bootkit Targets Central Asian Diplomats](https://blog.netmanageit.com/blackx-uefi-bootkit-central-asia-diplomatic-targets/) -- secondary reporting with IOC consolidation
- [Microsoft KB5025885 - Managing Windows Boot Manager revocations](https://support.microsoft.com/en-us/topic/kb5025885) -- Microsoft remediation guidance for Baton Drop
- [NSA/CISA BlackLotus Mitigation Guide (U/OO/167397-23)](https://media.defense.gov/2023/Jun/22/2003245723/-1/-1/0/CSI_BlackLotus_Mitigation_Guide.PDF) -- government guidance applicable to BlackX remediation

---
*Report generated by Actioner*
