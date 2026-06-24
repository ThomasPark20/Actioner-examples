# Technical Analysis Report: GentleKiller EDR Killer Framework (2026-06-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-23
Version: 1.1 FINAL

<!-- revision: v1.0 DRAFT -> v1.1 FINAL. Changes applied per critic review:
  - Sigma "Security Product Service Terminated": DROPPED (generic TTP, not GentleKiller-specific, no aggregation logic, wrong ATT&CK tag)
  - Sigma "BYOVD Vulnerable Driver Load": Removed phantom IOC \PoisonX.sys (no source evidence). Gated generic filenames \eb.sys, \dmx.sys behind hash co-occurrence.
  - Sigma "EDR Killer Executable": Removed \Symantec.exe from filename selection (legitimate Symantec binary; hash detection remains).
  - Sigma "OxideHarvest Credential Stealer": Removed selection_args (generic CLI flags). Removed attack.t1059.003 tag. Hash+filename detection only.
  - Sigma "Third-Party EDR Killers": Changed attack.t1036.001 -> attack.t1562.001 (defense impairment is the primary TTP).
  - YARA "GentleKiller EDR Killer Variants": Removed $drv09 = "PoisonX.sys". Tightened standalone proc* threshold from 8 to 10.
  - YARA "OxideHarvest Credential Stealer": Added OxideHarvest-specific $oxide* strings to condition. Downgraded severity to low to avoid FP on legitimate Rust password managers (Bitwarden, 1Password).
  - Removed invalid ATT&CK TID T1685 from MITRE mapping (does not exist).
  - Removed PoisonX.sys from PowerShell sweep and driver regex.
  - Clarified GameDriverX64.sys vs vgk.sys in variant table (same variant, different driver filenames from different games).
-->

## Executive Summary

The **Gentlemen** ransomware-as-a-service (RaaS) operation distributes **GentleKiller**, a modular EDR-killer framework comprising at least eight variants, each exploiting a different legitimately signed but vulnerable kernel driver via Bring Your Own Vulnerable Driver (BYOVD) attacks. The framework targets more than 400 processes across 48 distinct security products, terminating them at kernel level before deploying ransomware payloads. Alongside GentleKiller, the operation distributes three additional third-party EDR killers (HexKiller, ThrottleBlood, HavocKiller) and a Rust-based credential stealer called OxideHarvest.

ESET research documents 27 distinct samples (SHA-1 hashes), 14 vulnerable driver files, and the complete targeted process list. Victims are primarily selected based on exposed FortiGate configurations in Southeast Asia, South America, and Western Europe. Initial access also leverages exploitation of BeyondTrust remote access products. The GentleKiller framework uses commercial packers (Enigma, Themida), fabricated version information, and copied digital signatures from legitimate vendors to evade detection.

## Background: Gentlemen RaaS

The Gentlemen is a ransomware-as-a-service operation providing affiliates with a comprehensive toolset for pre-ransomware intrusion activities. The operation's primary differentiator is GentleKiller, a purpose-built EDR-killer framework designed to systematically disable endpoint protection before ransomware deployment. The affiliate model enables broad distribution while maintaining operational security through separation of tool development from deployment.

The framework is notable for its breadth of coverage (48 security vendors, 400+ processes) and its modular architecture, where each variant is tailored to a specific vulnerable driver. This allows affiliates to select the variant best suited to evade the specific endpoint protection deployed by the target organization.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026 (ongoing) | Gentlemen RaaS active, distributing GentleKiller to affiliates |
| 2026-06-19 | ESET publishes detailed technical analysis of GentleKiller framework |
| 2026-06-20 | Xcitium ThreatLabs publishes PoisonX 0-day driver reverse engineering |
| 2026-06-23 | The Hacker News and Infosecurity Magazine publish coverage |

## Root Cause: Initial Access Vectors

Victim selection is primarily driven by exposed **FortiGate (mis)configurations** identified through leaked data. Additional initial access vectors include exploitation of **BeyondTrust/Bomgar** remote access products (referenced via Huntress reporting and CERT/CC VU#457458). The Gentlemen operation targets organizations in Southeast Asia, South America, and Western Europe.

## Technical Analysis of the Malicious Payload

### 1. GentleKiller Framework Architecture

GentleKiller uses a modular design with eight documented variants, each paired with a specific vulnerable driver. Variant naming follows a convention with suffixes indicating the protection level applied:

- **Suffix "1"**: Enigma packer protection + fake digital signatures + fabricated version information
- **Suffix "2"**: Themida packer protection + fake digital signatures + fabricated version information
- **"Light"**: No binary packing + fake signatures + fabricated version information
- **"Clear"**: No protection, no fake signatures, no version information (bare variant)

<!-- revision: Clarified Valorant variant row. GameDriverX64.sys is the Tower of Fantasy AntiCheat driver; vgk.sys is the Valorant AntiCheat driver. Both are used by the same "Valorant" variant. The SHA-1 7556AE58... in the IOC table corresponds to vgk.sys (Tower of Fantasy origin despite Valorant naming). -->

| Variant Name | Executable Pattern | Vulnerable Driver | Driver Origin |
|---|---|---|---|
| Kaspersky | Kasps.exe | eb.sys | Custom rootkit |
| FACEIT | FaceIT{1,2,Light,Clear}.exe | nseckrnl.sys | NSecsoft driver |
| Valorant | Valorant{1,2,Light,Clear}.exe | GameDriverX64.sys (Tower of Fantasy) / vgk.sys (Valorant) | Game AntiCheat drivers |
| Javelin | EAAntiCheat{suffix}.exe, EASolo{suffix}.exe | stpm_old.sys, stpm_new.sys | Safetica Process Monitor |
| WatchDog | BitD1.exe | dmx.sys | Zemana WatchDog Antimalware |
| Network Blocker | MB2.exe | 360netmon_wfp.sys | Qihoo 360 NetMon WFP driver |
| Cleaner | Deletor.exe | IMFForceDelete.sys | IObit ForceDelete filter driver |
| G11 | Symantec.exe | G11.sys (PoisonX) | PoisonX rootkit (Microsoft-signed) |

### 2. BYOVD Exploitation Mechanism

Each GentleKiller variant installs its paired vulnerable driver as a Windows service (T1543.003), then sends IOCTL commands to the driver to terminate target processes at kernel level. This bypasses Protected Process Light (PPL) restrictions that prevent user-mode process termination.

The **PoisonX** driver (G11.sys) is particularly notable:
- Microsoft Hardware Compatibility signed (legitimate signature)
- Uses symbolic link `\\.\{F8284233-48F4-4680-ADDD-F8284233}`
- Kill command IOCTL: `0x22E010`
- Accepts null-terminated ASCII decimal PID string, converts via `atoi()`, then calls `ZwOpenProcess` followed by `ZwTerminateProcess`
- No signature checks, ACLs, or privilege validation on the IOCTL interface
- At time of discovery: 0/71 detections on VirusTotal
- Over 15 versions identified

### 3. Third-Party EDR Killer Tools

The Gentlemen operation also distributes three third-party EDR killers with added evasion layers:

| Tool | Executable | Driver | Driver Origin | Prior Use |
|---|---|---|---|---|
| HexKiller | Avast.exe | googleApiUtil64.sys | Baidu Antivirus BdApi | Warlock gang |
| ThrottleBlood | Sent.exe | ThrottleBlood.sys | TechPowerUp (GPU-Z) | MedusaLocker, DragonForce |
| HavocKiller | Sophos.exe | havoc.sys | Huawei Audio | Previously documented |

### 4. OxideHarvest Credential Stealer

**OxideHarvest** (filenames: buildx641.exe, buildx64.exe) is a Rust-based credential stealer distributed alongside GentleKiller. It targets browser credential stores:

- **Chromium-based**: Chrome, Edge, Brave, Opera
- **Gecko-based**: Firefox

Command-line parameters: `-i` (hosts), `-u` (username), `-p` (password), `-t` (threads), `-o` (output file).

### 5. Anti-Forensics / Evasion Techniques

- **Commercial packers**: Enigma and Themida used to protect binaries
- **Masquerading**: Filenames impersonate legitimate security vendors (Kaspersky, FACEIT, Valorant, Symantec, Avast, Sophos)
- **Fake version info**: Fabricated PE version information mimicking legitimate products
- **Invalid digital signatures**: Copied legitimate certificates (invalid but visually convincing)
- **Vendor icons**: Embedded icons from legitimate security products
- **Detection naming**: ESET detects as Win64/KillAV.EA, Win32/KillAV.NVL, Win64/KillAV.AT, Win64/KillAV.DE

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

#### GentleKiller Variant Executables

| Filename | SHA-1 | ESET Detection | Description |
|---|---|---|---|
| Kasps.exe | `8AE6BD18B129061F63642531F1B684CF0383C75D` | Win64/KillAV.EA | Kaspersky variant |
| FaceIT1.exe | `D605994FC72A2BB59B5CFB1624A1B9170ECA73A2` | Win64/KillAV.EA | FACEIT variant (Enigma) |
| Valorant2.exe | `5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3` | Win64/KillAV.EA | Valorant variant (Themida) |
| EASolo2Light.exe | `331879F5EEC8892BBD896F90BDBB1BAD0BF63BD6` | Win64/KillAV.EA | Javelin variant (newer driver) |
| EASOLO1clear.exe | `F11AEBCCB9A86A7E2E653F90BAEC697F233C255F` | Win64/KillAV.EA | Javelin variant (older driver) |
| EAAntiCheatLight.exe | `EF9CD06683159397F099CAA244E94E6EAAD96EBA` | Win64/KillAV.EA | Javelin variant (both drivers) |
| BitD1.exe | `A11EE9CDC59E5CAA59AEFD27B30D104F3AD68E62` | Win64/KillAV.EA | WatchDog variant (Themida) |
| MB2.exe | `2F86898528C6CAB3540C486A9BFAA0C029B73950` | Win64/KillAV.EA | Network Blocker variant (Themida) |
| Deletor.exe | `A19117175DBC9BA4D23B5DCE8415E299A2E32192` | Win64/KillAV.EA | Cleaner variant |
| Symantec.exe | `D29670E684E40DDC89B47010C37CBC96737035B6` | Win64/KillAV.EA | G11/PoisonX variant |

#### Third-Party EDR Killer Executables

| Filename | SHA-1 | ESET Detection | Description |
|---|---|---|---|
| Avast.exe | `CF4D74DF17A91B4A36A2911B22AFEC5D8FA93A01` | Win32/KillAV.NVL | HexKiller |
| Sent.exe | `7131B377E96016DC1911020C9F95B1B4D042D7B4` | Win64/KillAV.AT | ThrottleBlood |
| Sophos.exe | `F0537CBB773AE12100B36731E7C39F5A9D852B14` | Win64/KillAV.DE | HavocKiller |

#### Vulnerable Drivers

| Filename | SHA-1 | ESET Detection | Legitimate Origin |
|---|---|---|---|
| eb.sys | `BA914FE77B177B45799403B16DD14765C510A074` | Win64/Agent.ITG | Custom rootkit |
| nseckrnl.sys | `B0B912A3FD1C05D72080848EC4C92880004021A1` | Win64/VulnDriver.NSecsoft.A | NSecsoft |
| vgk.sys | `7556AE58C215B8245A43F764F0676C7A8F0FDD1A` | Win64/VulnDriver.PerfectWorld.A | Tower of Fantasy AntiCheat |
| stpm_old.sys | `711EF221526997039E804A18DB9647C91680BBE2` | Win64/VulnDriver.Safetica.A | Safetica Process Monitor |
| stpm_new.sys | `68FEC379F2AE76C3D2CE913F7BE650CEA1D06990` | Win64/VulnDriver.Safetica.H | Safetica Process Monitor |
| dmx.sys | `96F0DBF52AED0AFD43E44500116B04B674F7358E` | Win64/VulnDriver.WatchDogDev.C | Zemana WatchDog |
| 360netmon_wfp.sys | `9AD51AD97C01E97AB59214116740785E0F6320A8` | Win64/VulnDriver.Qihoo360.A | Qihoo 360 |
| IMFForceDelete.sys | `12500F6C87CE62712A0ED6652C57468D15C14223` | Win64/VulnDriver.IObit.D.gen | IObit |
| G11.sys | `56BEE9DF5833A637F5C54D5911DF98B0812FE643` | Win64/Agent.IYQ | PoisonX rootkit |
| googleApiUtil64.sys | `EC296F9501AD71E430810CB5CDC38D954D4BA536` | Win64/VulnDriver.Baidu.B | Baidu Antivirus |
| ThrottleBlood.sys | `82ED942A52CDCF120A8919730E00BA37619661A3` | Win64/VulnDriver.GPUZ.B | TechPowerUp |
| havoc.sys | `1FA071303FB846308571E64727501FB98B1C2BE6` | Win64/VulnDriver.Huawei.D | Huawei Audio |

#### OxideHarvest Credential Stealer

| Filename | SHA-1 | ESET Detection |
|---|---|---|
| buildx641.exe | `A5CF917EC4A7DFBDFA43621398604805D860C718` | Win64/Spy.Agent.AGC |
| buildx64.exe | `D4B19141102015D436321E6F26976E98183CFD27` | Win64/Spy.Agent.AGC |

### Network

No C2 domains, IP addresses, or network-level indicators were disclosed in the available sources.

### Behavioral

- Installation of kernel drivers as Windows services immediately before security product process termination
- Rapid sequential termination of multiple security product processes
- PoisonX IOCTL `0x22E010` sent to device `\\.\{F8284233-48F4-4680-ADDD-F8284233}`
- Executable filenames mimicking security vendor products (Kaspersky, Symantec, Avast, Sophos, SentinelOne)
- Command-line pattern for OxideHarvest: `-i <hosts> -u <user> -p <pass> -t <threads> -o <outfile>`

## MITRE ATT&CK Mapping

<!-- revision: Removed T1685 (does not exist in ATT&CK). BYOVD is covered by T1068 (Exploitation for Privilege Escalation) and T1543.003 (Windows Service for driver install). -->

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1106 | Native API | Direct Windows API calls for driver loading and process termination (ZwOpenProcess, ZwTerminateProcess) |
| T1543.003 | Create or Modify System Process: Windows Service | Vulnerable drivers installed as kernel services prior to exploitation |
| T1036 | Masquerading | Executables named after legitimate security products |
| T1036.001 | Invalid Code Signature | Copied but invalid digital signatures from legitimate vendors |
| T1027 | Obfuscated Files or Information | Commercial packers (Enigma, Themida) used to protect binaries |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Core objective: terminate 400+ security product processes |
| T1068 | Exploitation for Privilege Escalation | BYOVD exploitation of signed kernel drivers for kernel-level access |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | OxideHarvest targeting Chromium and Gecko credential stores |

## Impact Assessment

GentleKiller's coverage of 48 security vendors and 400+ processes makes it one of the most comprehensive EDR-killer frameworks documented. The use of Microsoft-signed drivers (PoisonX) with zero VirusTotal detections at discovery represents a significant detection gap. The framework's modular architecture and multiple protection tiers (Enigma, Themida, Light, Clear) enable affiliates to select evasion levels appropriate to the target's detection capabilities.

Organizations running any of the 48 targeted security products are at risk. The combination of FortiGate misconfiguration exploitation for initial access, EDR disablement via GentleKiller, credential theft via OxideHarvest, and subsequent ransomware deployment represents a complete attack chain.

## Detection & Remediation

### Immediate Detection

<!-- revision: Removed PoisonX.sys from file search and driver regex (phantom IOC with no source evidence). -->

```powershell
# Check for known GentleKiller driver files on disk
Get-ChildItem -Path C:\ -Recurse -Include eb.sys,nseckrnl.sys,GameDriverX64.sys,stpm_old.sys,stpm_new.sys,dmx.sys,360netmon_wfp.sys,IMFForceDelete.sys,G11.sys,googleApiUtil64.sys,ThrottleBlood.sys,havoc.sys -ErrorAction SilentlyContinue

# Check for known GentleKiller executable names
Get-ChildItem -Path C:\ -Recurse -Include Kasps.exe,FaceIT1.exe,Valorant2.exe,BitD1.exe,MB2.exe,Deletor.exe,Symantec.exe,Avast.exe,Sent.exe,Sophos.exe,buildx641.exe,buildx64.exe -ErrorAction SilentlyContinue

# Check for PoisonX device symbolic link
Get-WmiObject Win32_PnPEntity | Where-Object { $_.Name -like "*F8284233*" }

# Check loaded drivers for known vulnerable driver names
Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -match "(eb|nseckrnl|GameDriverX64|stpm_old|stpm_new|dmx|360netmon_wfp|IMFForceDelete|G11|googleApiUtil64|ThrottleBlood|havoc)\.sys" }
```

### Remediation

1. **Contain**: Isolate affected endpoints from the network immediately
2. **Identify**: Scan for IOC hashes across the environment using EDR (if still operational) or offline scanning tools
3. **Remove**: Unload malicious drivers and delete GentleKiller executables
4. **Restore**: Restart terminated security services; verify EDR sensor health
5. **Credential rotation**: Assume browser-stored credentials are compromised if OxideHarvest artifacts are found; rotate all affected passwords
6. **FortiGate audit**: Review FortiGate configurations for exposed management interfaces; apply CERT/CC VU#457458 mitigations

### Long-Term Hardening

- Enable **Windows Defender Application Control (WDAC)** or **Hypervisor-Protected Code Integrity (HVCI)** to block unsigned/vulnerable kernel drivers
- Deploy the **Microsoft Vulnerable Driver Blocklist** and keep it current
- Monitor for unexpected driver loads via Sysmon Event ID 6 (driver loaded)
- Monitor for Windows service creation (Event ID 7045) involving unknown drivers
- Audit and restrict access to FortiGate management interfaces
- Implement Protected Process Light (PPL) for security services where supported

## Detection Rules

The rules below cover GentleKiller's primary detection surfaces: vulnerable driver loading, EDR-killer executable identification, OxideHarvest credential stealer execution, and third-party tool identification. No Snort or Suricata rules are provided because the sources disclose no network-level indicators (no C2 domains, IPs, or URLs).

<!-- revision: Dropped "Sigma: Security Product Service Terminated Unexpectedly" -- generic TTP not specific to GentleKiller, wrong ATT&CK tag (was t1543.003, should be t1562.001), and lacked aggregation/correlation logic needed to reduce false positives from benign service crashes. -->

### Sigma: GentleKiller BYOVD Vulnerable Driver Load

Detects loading of the 12 vulnerable drivers abused by GentleKiller variants, matching on SHA-1 hashes and driver filenames in Sysmon driver_load events. Generic filenames (`eb.sys`, `dmx.sys`) are gated behind hash co-occurrence to reduce false positives.

**Status:** compile ✅ compiles -- confidence: high

<!-- audit: sigma check 0 errors, 0 condition errors, 0 issues. sigma convert --without-pipeline -t splunk and -t log_scale both succeed. Hashes|contains used because Sysmon Hashes field is multi-algo formatted (e.g. "SHA1=BA914..."). Generic driver filenames eb.sys and dmx.sys gated behind hash co-occurrence to prevent FP from legitimate Zemana or custom rootkit usage. Removed phantom IOC PoisonX.sys (no source evidence for this filename). -->

```yaml
title: GentleKiller BYOVD Vulnerable Driver Load
id: c2fc9dfc-b498-4edf-8eea-dc6cc210e4bf
status: experimental
description: >
    Detects loading of vulnerable drivers abused by the GentleKiller EDR killer
    framework distributed by the Gentlemen RaaS operation. These drivers are
    legitimately signed but contain exploitable IOCTL handlers used to terminate
    security processes at kernel level.
references:
    - https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
    - https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html
author: Actioner
date: 2026/06/23
modified: 2026/06/23
tags:
    - attack.t1543.003
    - attack.t1068
logsource:
    category: driver_load
    product: windows
detection:
    selection_hash:
        Hashes|contains:
            - 'BA914FE77B177B45799403B16DD14765C510A074'
            - 'B0B912A3FD1C05D72080848EC4C92880004021A1'
            - '7556AE58C215B8245A43F764F0676C7A8F0FDD1A'
            - '711EF221526997039E804A18DB9647C91680BBE2'
            - '68FEC379F2AE76C3D2CE913F7BE650CEA1D06990'
            - '96F0DBF52AED0AFD43E44500116B04B674F7358E'
            - '9AD51AD97C01E97AB59214116740785E0F6320A8'
            - '12500F6C87CE62712A0ED6652C57468D15C14223'
            - '56BEE9DF5833A637F5C54D5911DF98B0812FE643'
            - 'EC296F9501AD71E430810CB5CDC38D954D4BA536'
            - '82ED942A52CDCF120A8919730E00BA37619661A3'
            - '1FA071303FB846308571E64727501FB98B1C2BE6'
    selection_specific_name:
        ImageLoaded|endswith:
            - '\nseckrnl.sys'
            - '\GameDriverX64.sys'
            - '\stpm_old.sys'
            - '\stpm_new.sys'
            - '\360netmon_wfp.sys'
            - '\IMFForceDelete.sys'
            - '\G11.sys'
            - '\googleApiUtil64.sys'
            - '\ThrottleBlood.sys'
            - '\havoc.sys'
    selection_generic_name:
        ImageLoaded|endswith:
            - '\eb.sys'
            - '\dmx.sys'
    selection_generic_hash:
        Hashes|contains:
            - 'BA914FE77B177B45799403B16DD14765C510A074'
            - '96F0DBF52AED0AFD43E44500116B04B674F7358E'
    condition: selection_hash or selection_specific_name or (selection_generic_name and selection_generic_hash)
falsepositives:
    - Legitimate installations of the original software (FACEIT Anti-Cheat, Valorant, Safetica, Zemana, IObit, Baidu Antivirus, Huawei audio driver)
level: high
```

### Sigma: GentleKiller EDR Killer Executable

Detects execution of GentleKiller variant executables by SHA-1 hash or the distinctive filename patterns used by the framework. Hash-based detection is authoritative (level: critical); filename-based detection covers known naming variants.

**Status:** compile ✅ compiles -- confidence: high

<!-- audit: sigma check 0 errors, 0 condition errors, 0 issues. sigma convert --without-pipeline -t splunk and -t log_scale both succeed. Hash-based selections are authoritative; filename selections cover known naming variants including suffix permutations. Removed \Symantec.exe from filename selection (legitimate Symantec binary produces FPs; hash D29670E6... still detects the malicious variant). Added attack.t1562.001 tag (defense impairment). sigma-cli flags t1562.001 as InvalidATTACKTagIssue due to incomplete bundled ATT&CK data; this is a validator limitation, not a rule error. -->

```yaml
title: GentleKiller EDR Killer Executable
id: 5df15923-dbbe-4c4b-8a09-40cc306b5385
status: experimental
description: >
    Detects execution of GentleKiller EDR killer variants and associated tools
    (HexKiller, ThrottleBlood, HavocKiller) used by the Gentlemen RaaS operation.
    These executables masquerade as legitimate security products using names like
    Kaspersky, FACEIT, and Valorant.
references:
    - https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
    - https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html
author: Actioner
date: 2026/06/23
modified: 2026/06/23
tags:
    - attack.t1036.001
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains:
            - '8AE6BD18B129061F63642531F1B684CF0383C75D'
            - 'D605994FC72A2BB59B5CFB1624A1B9170ECA73A2'
            - '5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3'
            - '331879F5EEC8892BBD896F90BDBB1BAD0BF63BD6'
            - 'F11AEBCCB9A86A7E2E653F90BAEC697F233C255F'
            - 'EF9CD06683159397F099CAA244E94E6EAAD96EBA'
            - 'A11EE9CDC59E5CAA59AEFD27B30D104F3AD68E62'
            - '2F86898528C6CAB3540C486A9BFAA0C029B73950'
            - 'A19117175DBC9BA4D23B5DCE8415E299A2E32192'
            - 'D29670E684E40DDC89B47010C37CBC96737035B6'
            - 'CF4D74DF17A91B4A36A2911B22AFEC5D8FA93A01'
            - '7131B377E96016DC1911020C9F95B1B4D042D7B4'
            - 'F0537CBB773AE12100B36731E7C39F5A9D852B14'
    selection_name:
        Image|endswith:
            - '\Kasps.exe'
            - '\FaceIT1.exe'
            - '\FaceIT2.exe'
            - '\FaceITLight.exe'
            - '\FaceITClear.exe'
            - '\Valorant1.exe'
            - '\Valorant2.exe'
            - '\ValorantLight.exe'
            - '\ValorantClear.exe'
            - '\EASolo1clear.exe'
            - '\EASolo2Light.exe'
            - '\EAAntiCheatLight.exe'
            - '\BitD1.exe'
            - '\MB2.exe'
            - '\Deletor.exe'
    condition: selection_hash or selection_name
falsepositives:
    - Unlikely - these filenames in the observed naming pattern are highly specific to GentleKiller
level: critical
```

### Sigma: OxideHarvest Credential Stealer Execution

Detects OxideHarvest (buildx641/buildx64) by SHA-1 hash or filename. Detection relies on hash and filename only; generic CLI argument matching was removed to eliminate false positives from unrelated tools.

**Status:** compile ✅ compiles -- confidence: high

<!-- audit: sigma check 0 errors, 0 condition errors, 0 issues. sigma convert --without-pipeline -t splunk and -t log_scale both succeed. Removed selection_args (generic CLI flags -i -u -p -t -o match many legitimate tools). Removed attack.t1059.003 tag (OxideHarvest is a credential stealer, not a command shell executor). Hash and filename detection only. -->

```yaml
title: OxideHarvest Credential Stealer Execution
id: 57770a18-c2fc-4855-a72d-9bcea6ca3322
status: experimental
description: >
    Detects execution of OxideHarvest (buildx641/buildx64), a Rust-based
    credential stealer distributed alongside the GentleKiller EDR killer by the
    Gentlemen RaaS operation. It targets browser credential stores for Chrome,
    Edge, Firefox, Brave, and Opera.
references:
    - https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
    - https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html
author: Actioner
date: 2026/06/23
modified: 2026/06/23
tags:
    - attack.t1555.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains:
            - 'A5CF917EC4A7DFBDFA43621398604805D860C718'
            - 'D4B19141102015D436321E6F26976E98183CFD27'
    selection_name:
        Image|endswith:
            - '\buildx641.exe'
            - '\buildx64.exe'
    condition: selection_hash or selection_name
falsepositives:
    - Unlikely - hash and filename detection is highly specific
level: critical
```

### Sigma: Third-Party EDR Killer Tools (HexKiller, ThrottleBlood, HavocKiller)

Detects execution of HexKiller, ThrottleBlood, and HavocKiller tools distributed by the Gentlemen RaaS alongside GentleKiller, identified by SHA-1 hash.

**Status:** compile ✅ compiles -- confidence: high

<!-- audit: sigma check 0 errors, 0 condition errors, 0 issues. sigma convert --without-pipeline -t splunk and -t log_scale both succeed. Pure hash-based detection; zero expected false positives. Executable filenames (Avast.exe, Sent.exe, Sophos.exe) are too generic for filename-only detection. Changed tag from attack.t1036.001 to attack.t1562.001 (defense impairment is the primary TTP for EDR killers). sigma-cli flags t1562.001 as InvalidATTACKTagIssue due to incomplete bundled ATT&CK data; this is a validator limitation. -->

```yaml
title: GentleKiller Third-Party EDR Killer Tools (HexKiller, ThrottleBlood, HavocKiller)
id: 59eb1655-983d-4465-ba56-2a39b5c6a400
status: experimental
description: >
    Detects execution of third-party EDR killer tools distributed alongside
    GentleKiller by the Gentlemen RaaS. These include HexKiller (abuses Baidu
    BdApi driver), ThrottleBlood (abuses TechPowerUp driver), and HavocKiller
    (abuses Huawei audio driver). The executables masquerade as legitimate
    security products (Avast.exe, Sent.exe, Sophos.exe).
references:
    - https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
    - https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html
author: Actioner
date: 2026/06/23
modified: 2026/06/23
tags:
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_hexkiller:
        Hashes|contains: 'CF4D74DF17A91B4A36A2911B22AFEC5D8FA93A01'
    selection_throttleblood:
        Hashes|contains: '7131B377E96016DC1911020C9F95B1B4D042D7B4'
    selection_havockiller:
        Hashes|contains: 'F0537CBB773AE12100B36731E7C39F5A9D852B14'
    condition: 1 of selection_*
falsepositives:
    - None expected - hash-based detection is highly specific
level: critical
```

### YARA: GentleKiller EDR Killer Variants

Detects GentleKiller EDR killer PE executables by the combination of multiple embedded security product process names and vulnerable driver filenames, or PoisonX device path indicators.

**Status:** compile ✅ compiles -- confidence: medium

<!-- audit: yarac exit code 0. Rule keys on 5+ of 13 security process names AND 1+ driver filename, or 10+ process names standalone, or device path + 2 process names. Removed $drv09 = "PoisonX.sys" (phantom IOC). Tightened standalone proc* threshold from 8 to 10 to reduce FP from security management tools that may embed multiple process names. -->

```yara
import "pe"

rule Malware_GentleKiller_EDR_Killer
{
    meta:
        description = "Detects GentleKiller EDR killer variants used by the Gentlemen RaaS operation. These PE executables load vulnerable drivers to terminate security processes at kernel level."
        author = "Actioner"
        date = "2026-06-23"
        modified = "2026-06-23"
        reference = "https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $proc01 = "CSFalconService.exe" ascii wide
        $proc02 = "MsMpEng.exe" ascii wide
        $proc03 = "SentinelAgent.exe" ascii wide
        $proc04 = "SentinelServiceHost.exe" ascii wide
        $proc05 = "SophosHealth.exe" ascii wide
        $proc06 = "avp.exe" ascii wide
        $proc07 = "ekrn.exe" ascii wide
        $proc08 = "cbdefense.exe" ascii wide
        $proc09 = "CylanceSvc.exe" ascii wide
        $proc10 = "cortexService.exe" ascii wide
        $proc11 = "McsAgent.exe" ascii wide
        $proc12 = "ccSvcHst.exe" ascii wide
        $proc13 = "NisSrv.exe" ascii wide
        $drv01 = "eb.sys" ascii wide
        $drv02 = "nseckrnl.sys" ascii wide
        $drv03 = "GameDriverX64.sys" ascii wide
        $drv04 = "stpm_old.sys" ascii wide
        $drv05 = "stpm_new.sys" ascii wide
        $drv06 = "dmx.sys" ascii wide
        $drv07 = "360netmon_wfp.sys" ascii wide
        $drv08 = "IMFForceDelete.sys" ascii wide
        $drv09 = "G11.sys" ascii wide
        $dev01 = "\\\\Device\\\\{F8284233-48F4-4680-ADDD-F8284233}" ascii wide
        $dev02 = "\\\\.\\{F8284233-48F4-4680-ADDD-F8284233}" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            (5 of ($proc*) and 1 of ($drv*)) or
            (10 of ($proc*)) or
            (1 of ($dev*) and 2 of ($proc*))
        )
}
```

### YARA: PoisonX BYOVD Driver

Detects the PoisonX vulnerable driver (G11.sys) by its unique device symbolic link GUID and kernel process termination API imports.

**Status:** compile ✅ compiles -- confidence: high

<!-- audit: yarac exit code 0. Keys on unique PoisonX device GUID {F8284233-48F4-4680-ADDD-F8284233} combined with ZwOpenProcess and ZwTerminateProcess API names. GUID is unique to PoisonX; no known legitimate use. No changes from v1.0. -->

```yara
rule Malware_PoisonX_BYOVD_Driver
{
    meta:
        description = "Detects PoisonX vulnerable driver (G11.sys) used by the GentleKiller G11 variant to terminate EDR processes including CrowdStrike Falcon via kernel-mode ZwTerminateProcess."
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://threatlabsnews.xcitium.com/blog/reverse-engineering-a-0-day-poisonx-byovd-driver-bypasses-crowdstrike-edr/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $dev = "{F8284233-48F4-4680-ADDD-F8284233}" ascii wide
        $api1 = "ZwOpenProcess" ascii
        $api2 = "ZwTerminateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $dev and
        ($api1 and $api2)
}
```

### YARA: OxideHarvest Credential Stealer

Detects the OxideHarvest Rust-based credential stealer. Detection requires OxideHarvest-specific filename strings combined with browser credential indicators, or a high threshold of browser credential artifacts. Severity downgraded to low to avoid false positives on legitimate Rust-based password managers (Bitwarden, 1Password).

**Status:** compile ✅ compiles -- confidence: low

<!-- audit: yarac exit code 0. Added $oxide1/$oxide2 (OxideHarvest-specific filename strings) as anchors. Condition now requires either oxide string + rust + browser evidence, or high-threshold browser evidence (4+ credential files + 3+ browser paths). Downgraded severity to low per critic guidance to avoid FP on legitimate Rust password managers. -->

```yara
rule Malware_OxideHarvest_Credential_Stealer
{
    meta:
        description = "Detects OxideHarvest (buildx641/buildx64), a Rust-based credential stealer targeting Chromium and Gecko browser stores, distributed by the Gentlemen RaaS operation."
        author = "Actioner"
        date = "2026-06-23"
        modified = "2026-06-23"
        reference = "https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/"
        tlp = "WHITE"
        severity = "low"

    strings:
        $rust1 = ".cargo" ascii
        $rust2 = "rustc" ascii
        $oxide1 = "buildx641" ascii wide
        $oxide2 = "buildx64" ascii wide
        $browser1 = "Login Data" ascii wide
        $browser2 = "Web Data" ascii wide
        $browser3 = "Cookies" ascii wide
        $browser4 = "logins.json" ascii wide
        $browser5 = "key4.db" ascii wide
        $browser6 = "cert9.db" ascii wide
        $chrome1 = "Google\\Chrome\\User Data" ascii wide
        $chrome2 = "Microsoft\\Edge\\User Data" ascii wide
        $chrome3 = "BraveSoftware\\Brave-Browser\\User Data" ascii wide
        $chrome4 = "Opera Software" ascii wide
        $firefox1 = "Mozilla\\Firefox\\Profiles" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            (1 of ($oxide*) and 1 of ($rust*) and 2 of ($browser*) and 1 of ($chrome*, $firefox1)) or
            (1 of ($rust*) and 4 of ($browser*) and 3 of ($chrome*, $firefox1))
        )
}
```

### Network Rules

No Snort or Suricata rules generated. The available sources disclose no C2 domains, IP addresses, URLs, or network-level behavioral patterns. Network detection is not feasible from the current intelligence.

## Lessons Learned

1. **BYOVD as a commodity service**: GentleKiller demonstrates the industrialization of BYOVD attacks within RaaS ecosystems. The modular framework approach -- eight variants, each targeting a different driver -- shows sophisticated supply-chain thinking by ransomware developers.

2. **Microsoft-signed driver blind spot**: The PoisonX driver being Microsoft Hardware Compatibility signed with 0/71 VirusTotal detections at discovery underscores that driver signature alone is insufficient for trust. Organizations must deploy the Vulnerable Driver Blocklist and HVCI/WDAC.

3. **EDR fragility to kernel-level attacks**: With 400+ processes across 48 vendors targeted, the framework reveals that EDR products broadly remain vulnerable to kernel-level termination. Defenders should monitor for driver load events (Sysmon EID 6) and unexpected service terminations (Windows EID 7034) as a second line of defense.

4. **Credential theft as a standard post-exploitation step**: The bundling of OxideHarvest alongside EDR killers shows that credential harvesting is now a standard step in the pre-ransomware toolkit, not an optional post-exploitation activity.

## Sources

- [ESET WeLiveSecurity - Killing Me Gently: Inside Gentlemen's EDR Killer Framework](https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/) -- primary technical analysis with full IOC table, targeted process list, variant architecture, and MITRE ATT&CK mapping
- [The Hacker News - The Gentlemen RaaS Uses GentleKiller](https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html) -- news coverage summarizing ESET findings with additional context on affiliate model
- [Infosecurity Magazine - GentleKiller Gentlemen Ransomware](https://www.infosecurity-magazine.com/news/gentlekiller-gentlemen-ransomware/) -- secondary coverage with victim geography and initial access details
- [Xcitium ThreatLabs - Reverse Engineering a 0-day: PoisonX BYOVD Driver](https://threatlabsnews.xcitium.com/blog/reverse-engineering-a-0-day-poisonx-byovd-driver-bypasses-crowdstrike-edr/) -- detailed reverse engineering of PoisonX driver IOCTL interface and kernel process termination mechanism
- [Huntress - Uptick in BeyondTrust/Bomgar Exploitation](https://www.huntress.com/blog/uptick-bomgar-exploitation) -- referenced initial access vector via BeyondTrust exploitation
- [CERT/CC VU#457458](https://kb.cert.org/vuls/id/457458) -- vulnerability note referenced for FortiGate initial access vector

---
*Report generated by Actioner*
