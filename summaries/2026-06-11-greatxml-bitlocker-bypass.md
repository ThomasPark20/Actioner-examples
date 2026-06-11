# Technical Analysis Report: GreatXML BitLocker Bypass (2026-06-11)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-11
Version: 1.0 (DRAFT)

## Executive Summary

On June 10-11, 2026, security researcher Nightmare Eclipse (also tracked as Chaotic Eclipse / Dead Eclipse, GitHub: MSNightmare) publicly released "GreatXML," a proof-of-concept exploit that bypasses BitLocker full-disk encryption by abusing residual artifacts left by Microsoft Defender's Offline Scan feature. The exploit plants a crafted `unattend.xml` file and a `Recovery` directory structure onto the recovery partition; upon rebooting into Windows Recovery Environment (WinRE) via Shift+Restart, a command shell with unrestricted access to the BitLocker-protected volume spawns. Notably, the public PoC is deliberately incomplete -- the researcher omitted the final component needed to achieve a full SYSTEM shell, framing it as a capture-the-flag challenge.

GreatXML is the eighth public exploit in an escalating campaign by Nightmare Eclipse targeting Microsoft Defender and Windows security components, following BlueHammer (CVE-2026-33825), RedSun (CVE-2026-41091), UnDefend (CVE-2026-45498), RoguePlanet, YellowKey, GreenPlasma, and MiniPlasma. No CVE has been assigned for GreatXML. No patch is available as of June 11, 2026. The prerequisite is that Microsoft Defender Offline Scan must have been initiated at least once on the target system, after which the system becomes permanently vulnerable until Microsoft addresses the underlying issue.

## Background: Microsoft Defender Offline Scan and Windows Recovery Environment

Microsoft Defender Offline Scan is a feature designed to detect and remove persistent malware that resists removal during normal Windows operation. When initiated, Windows reboots into a minimal recovery environment (WinRE) where Defender performs a scan without the operating system's full boot, allowing it to access and remediate files that are normally locked by running processes.

The Windows Recovery Environment (WinRE) is stored on a dedicated recovery partition and uses Windows PE as its base. WinRE supports `unattend.xml` answer files for automated configuration -- a mechanism designed for OEM and enterprise deployment scenarios. BitLocker Full Volume Encryption protects the operating system volume at rest, but WinRE operates in a trust boundary where the BitLocker-protected volume must be accessible for scan and repair operations. This architectural requirement means that any mechanism capable of executing code within WinRE effectively has access to the decrypted BitLocker volume.

The GreatXML exploit leverages the intersection of these three components: Defender Offline Scan creates the conditions, `unattend.xml` provides the code execution vector, and WinRE provides the trusted context where BitLocker volumes are unlocked.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-02 | BlueHammer (CVE-2026-33825) PoC released targeting Defender TOCTOU |
| 2026-05-20 | Microsoft patches CVE-2026-41091 (RedSun) and CVE-2026-45498 (UnDefend) |
| 2026-06-09 | RoguePlanet PoC released (Defender race condition LPE) |
| 2026-06-10 | GreatXML PoC released on GitHub (MSNightmare/GreatXML); YellowKey (BitLocker bypass via FsTx files) also released |
| 2026-06-10-11 | Security Online, SecurityWeek, BleepingComputer, Cybernews publish coverage |
| 2026-06-11 | No CVE assigned; no Microsoft patch available |

## Root Cause: Defender Offline Scan Residual Configuration in WinRE

The root cause is the trust relationship between Microsoft Defender Offline Scan and the Windows Recovery Environment. When Defender initiates an offline scan, it configures WinRE to execute Defender scanning logic upon next boot into recovery mode. This configuration persists on the recovery partition. The GreatXML exploit abuses this by replacing or augmenting the recovery partition contents with attacker-controlled files:

1. A crafted `unattend.xml` placed at the root of the recovery partition
2. A `Recovery\WindowsRE` directory structure containing additional configuration

When the system subsequently boots into WinRE (triggered via Shift+Restart), the Windows PE environment processes the `unattend.xml` answer file, which can specify arbitrary commands to execute during the recovery session. Because WinRE operates with full access to the BitLocker-decrypted volume and runs with SYSTEM privileges, the attacker gains unrestricted access to the protected data and a SYSTEM-level execution context.

**Prerequisites:**
- Microsoft Defender Offline Scan must have been initiated at least once on the target system
- The attacker must have write access to the recovery partition (typically requires local administrator privileges or physical access)
- The system must reboot into WinRE (Shift+Restart or forced recovery boot)

## Technical Analysis of the Malicious Payload

### 1. Reconnaissance: Defender Offline Scan State

The attacker first determines whether a Defender Offline Scan has ever been initiated on the target system. This is the prerequisite that opens the attack surface. The researcher notes: "If you ever attempted to use Windows Defender Offline Scan, you're automatically vulnerable to a bitlocker bypass." It remains unclear whether the vulnerability can be triggered without a prior offline scan.

### 2. Recovery Partition Staging

The attacker copies two artifacts to the root of the recovery partition:

- **`unattend.xml`**: A crafted Windows answer file that specifies commands to execute during the WinRE boot process. This file follows the standard `urn:schemas-microsoft-com:unattend` schema and uses pass settings (e.g., `windowsPE`, `offlineServicing`) to define execution points within the recovery environment.

- **`Recovery\WindowsRE\` directory**: Contains additional configuration files that complement the answer file, potentially including WinRE customization XML and scripts.

The recovery partition is typically mounted as a hidden volume (e.g., `\\?\Volume{GUID}\` or assigned a drive letter via `diskpart`). Administrative access is normally required to write to it.

### 3. WinRE Boot Trigger

The attacker triggers a reboot into WinRE using Shift+Click on the Restart button (accessible from the Start menu or lock screen), or via:
- `shutdown /r /o /t 0` (restart to advanced options)
- `reagentc /boottore` followed by restart
- Forced recovery boot via interrupted boot sequence

### 4. SYSTEM Shell Spawn (Incomplete in Public PoC)

Upon booting into WinRE, the Windows PE environment processes the planted `unattend.xml`. The answer file's `RunSynchronousCommand` or similar execution directives spawn a command shell with SYSTEM privileges. Because WinRE has already unlocked the BitLocker volume for recovery operations, this shell has unrestricted read/write access to the encrypted volume's contents.

The public PoC on GitHub is deliberately incomplete -- the researcher withheld the final component that achieves the full SYSTEM shell, framing it as a challenge for other researchers to complete.

### 5. Anti-Forensics / Evasion Techniques

- The attack occurs entirely within WinRE, which has minimal logging compared to a full Windows boot
- Recovery partition modifications may not be monitored by endpoint security tools
- The exploit leverages legitimate Windows mechanisms (answer files, WinRE) rather than malware payloads
- Physical access attacks leave no network-based indicators

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Microsoft Defender Offline Scan | All versions (current June 2026) | Systems where offline scan has been initiated are vulnerable |
| Windows Recovery Environment | All versions with WinRE enabled | Recovery partition susceptible to answer file injection |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `<RecoveryPartition>\unattend.xml` | N/A (attacker-crafted) | Malicious answer file planted on recovery partition |
| Windows | `<RecoveryPartition>\Recovery\WindowsRE\` | N/A | Malicious recovery directory structure |

### Network

No network IOCs -- this is a local/physical access exploit with no C2 component.

### Behavioral

- Creation of `unattend.xml` at the root of a non-system drive or recovery partition
- Modification of files within `Recovery\WindowsRE\` directory outside of normal Windows servicing
- Initiation of Defender Offline Scan followed by abnormal recovery partition access
- Reboot into WinRE (reagentc, Shift+Restart, `shutdown /r /o`) from a non-administrative context
- Unexpected command prompt or shell spawning during WinRE boot sequence

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1542.003 | Pre-OS Boot: Bootkit | Planting crafted files on recovery partition to execute code during WinRE pre-OS boot, bypassing BitLocker |
| T1068 | Exploitation for Privilege Escalation | Abusing Defender offline scan residual configuration to achieve SYSTEM shell access |
| T1006 | Direct Volume Access | Writing directly to recovery partition (hidden volume) to stage exploit files |
| T1553.006 | Subvert Trust Controls: Code Signing Policy Modification | Abusing WinRE's trust in unattend.xml answer files to execute unsigned commands |

## Impact Assessment

**Breadth:** All Windows systems where Microsoft Defender Offline Scan has been initiated at least once are vulnerable. Given that Defender Offline Scan is a commonly recommended troubleshooting step and may be triggered by enterprise management tools, the affected population could be substantial across consumer and enterprise Windows installations.

**Depth:** The exploit grants SYSTEM-level access to BitLocker-decrypted volumes, representing maximum confidentiality impact. An attacker with physical access or local administrator rights can read the entire protected volume contents, extract credentials, install persistent backdoors, or exfiltrate sensitive data.

**Stealth:** The attack occurs during WinRE boot, which has minimal audit logging. Standard endpoint detection tools are not active during recovery mode. Recovery partition modifications may not be monitored.

**Active Exploitation:** No known exploitation in the wild as of June 11, 2026. The public PoC is deliberately incomplete, which raises the bar for script-kiddie exploitation but provides sufficient detail for skilled attackers to complete the chain.

**Physical Access Requirement:** The most common attack scenario requires physical access to the target machine (to write to the recovery partition and trigger WinRE reboot). However, an attacker with existing local administrator access could stage the exploit remotely for later physical execution or combine it with a forced reboot.

## Detection & Remediation

### Immediate Detection

**Check for anomalous files on the recovery partition:**
```powershell
# Mount and inspect the recovery partition
$recoveryPartition = Get-Partition | Where-Object { $_.Type -eq 'Recovery' }
if ($recoveryPartition) {
    $tempLetter = 'R'
    $recoveryPartition | Set-Partition -NewDriveLetter $tempLetter
    # Check for suspicious unattend.xml at root
    if (Test-Path "${tempLetter}:\unattend.xml") {
        Write-Warning "ALERT: unattend.xml found on recovery partition - potential GreatXML exploit staging"
        Get-Content "${tempLetter}:\unattend.xml" | Select-Object -First 50
    }
    # Check for anomalous Recovery directory
    if (Test-Path "${tempLetter}:\Recovery\WindowsRE") {
        Write-Warning "ALERT: Recovery\WindowsRE directory found on recovery partition root"
        Get-ChildItem "${tempLetter}:\Recovery\WindowsRE" -Recurse
    }
    # Remove the drive letter when done
    $recoveryPartition | Remove-PartitionAccessPath -AccessPath "${tempLetter}:\"
}
```

**Check Defender Offline Scan history:**
```powershell
# Check if Defender Offline Scan has been used (makes system vulnerable)
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
    Where-Object { $_.Id -eq 1131 -or $_.Id -eq 1132 } |
    Select-Object -First 5 TimeCreated, Message
```

### Remediation

1. **Immediate:** Inspect recovery partitions on high-value systems for unexpected `unattend.xml` files or modified `Recovery\WindowsRE` directories
2. **Immediate:** Remove any unauthorized `unattend.xml` or `Recovery` directory structures from recovery partitions
3. **Short-term:** Enable file integrity monitoring on recovery partition contents where feasible
4. **Short-term:** Restrict recovery partition write access via disk-level ACLs
5. **Pending patch:** Apply Microsoft security update when released addressing the WinRE answer file trust issue
6. **If compromised:** Assume full volume contents have been accessed; rotate all credentials stored on the system, review for persistence mechanisms

### Long-Term Hardening

- Enable BitLocker with TPM+PIN rather than TPM-only configuration, as PIN requirement adds an authentication barrier to WinRE access
- Implement physical security controls on endpoints to prevent unauthorized boot media or recovery mode access
- Monitor recovery partition integrity via scheduled integrity checks
- Consider disabling WinRE on high-security systems where recovery via installation media is acceptable (`reagentc /disable`)
- Deploy Sysmon with file event monitoring (Event ID 11) to detect writes to recovery partition paths
- Implement UEFI Secure Boot with custom policies to restrict WinRE modifications

## Detection Rules

These detections target the GreatXML exploit chain and related Nightmare Eclipse tooling at the PoC/advisory-specific altitude with strict leniency. The exploit is a local/physical access attack with no network component, so only Sigma (endpoint) and YARA (file content) rules are generated. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. One key caveat: because the exploit executes within WinRE (outside the normal Windows OS), Sysmon and other endpoint telemetry sources may not be active during the actual exploitation phase -- these rules primarily detect the staging/preparation phase on the live OS.

### Sigma: Suspicious Unattend.xml or Recovery Directory Creation on Non-System Partition
Detects creation of unattend.xml at a drive root or Recovery\WindowsRE directory structures outside normal Windows installation paths, targeting the file-staging phase of the GreatXML exploit.
<!-- audit: sigma check 0 errors, 0 issues; splunk convert 0; log_scale convert 0. Targets file_event on Windows. Filter excludes known legitimate paths (Windows\Panther, Windows\Setup, $WINDOWS.~BT). Regex anchored to drive-root unattend.xml. Values use real paths (not defanged). FP surface: OSD/MDT deployments, admin WinRE customization. Evasion: staging via direct disk write (bypasses file event logging). -->
**Status:** compile ✅ compiles · confidence: medium
```yaml
title: Suspicious Unattend.xml or Recovery Directory Creation on Non-System Partition
id: 3f8e7a2d-1c9b-4d6e-a5f3-8b0c2e1d9a4f
status: experimental
description: >
    Detects creation of unattend.xml files or Recovery\WindowsRE directory structures
    outside of normal Windows installation paths, consistent with the GreatXML
    BitLocker bypass exploit. The exploit plants a crafted unattend.xml and a Recovery
    directory on the recovery partition; when the system reboots into WinRE, a SYSTEM
    shell spawns with unrestricted access to the BitLocker-protected volume. This rule
    targets file creation events where unattend.xml appears at a drive root or alongside
    a Recovery\WindowsRE directory structure outside the Windows directory.
references:
    - https://securityonline.info/greatxml-bitlocker-bypass-poc/
    - https://www.securityweek.com/greatxml-zero-day-exploit-bypasses-bitlocker/
    - https://github.com/MSNightmare/GreatXML
author: Actioner
date: 2026/06/11
tags:
    - attack.t1542.003
    - attack.t1068
logsource:
    category: file_event
    product: windows
detection:
    selection_unattend_root:
        TargetFilename|re: '^[A-Z]:\\unattend\.xml$'
    selection_recovery_winre:
        TargetFilename|contains: '\Recovery\WindowsRE\'
    filter_windows_dir:
        TargetFilename|contains:
            - '\Windows\Panther\'
            - '\Windows\Setup\'
            - '\$WINDOWS.~BT\'
    condition: (selection_unattend_root or selection_recovery_winre) and not filter_windows_dir
falsepositives:
    - Legitimate Windows deployment tools using unattend.xml for automated setup
    - System administrators configuring Windows Recovery Environment
    - MDT or SCCM task sequences writing unattend.xml for OS deployment
level: high
```

### Sigma: Nightmare Eclipse GreatXML Exploit Tool Execution
Detects execution of the GreatXML exploit binary or related Nightmare Eclipse BitLocker bypass tools by process image name or original filename.
<!-- audit: sigma check 0 errors, 0 issues; splunk convert 0; log_scale convert 0. Simple filename match — trivially evaded by rename, but catches unmodified PoC usage. OriginalFileName provides PE metadata resilience. Pair with YARA rule for content-based detection. -->
**Status:** compile ✅ compiles · confidence: high
```yaml
title: Nightmare Eclipse GreatXML Exploit Tool Execution
id: a7d1e4b9-3c2f-4e8a-9b6d-5f0a1c8e7d3b
status: experimental
description: >
    Detects execution of the GreatXML exploit tool or related Nightmare Eclipse
    BitLocker bypass tooling by process name or original filename. GreatXML abuses
    Microsoft Defender offline scan artifacts to bypass BitLocker encryption and
    spawn a SYSTEM shell when rebooting into Windows Recovery Environment.
references:
    - https://securityonline.info/greatxml-bitlocker-bypass-poc/
    - https://www.securityweek.com/greatxml-zero-day-exploit-bypasses-bitlocker/
    - https://github.com/MSNightmare/GreatXML
author: Actioner
date: 2026/06/11
tags:
    - attack.t1068
    - attack.t1542.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith:
            - '\GreatXML.exe'
            - '\YellowKey.exe'
    selection_originalfilename:
        OriginalFileName|contains:
            - 'GreatXML'
    condition: 1 of selection_*
falsepositives:
    - Unlikely - these are known exploit tool names from the Nightmare Eclipse campaign
level: critical
```

### Sigma: Windows Defender Offline Scan Initiation via Command Line
Detects initiation of Defender Offline Scan via MpCmdRun.exe or PowerShell, which creates the prerequisite condition that makes a system vulnerable to GreatXML.
<!-- audit: sigma check 0 errors, 0 issues; splunk convert 0; log_scale convert 0. Informational/medium rule — offline scan initiation is legitimate but expands the GreatXML attack surface. High FP in environments that regularly run offline scans. Not a direct detection of exploitation. -->
**Status:** compile ✅ compiles · confidence: low
```yaml
title: Windows Defender Offline Scan Initiation via Command Line
id: b5c2d8e1-4f7a-3e9b-a6d0-2c1f8e0d5a3b
status: experimental
description: >
    Detects initiation of Microsoft Defender Offline Scan via MpCmdRun.exe or
    PowerShell, which is a prerequisite condition for the GreatXML BitLocker
    bypass exploit. Once an offline scan has been initiated at least once, the
    system becomes vulnerable to GreatXML. Monitoring offline scan initiation
    provides visibility into the expanding attack surface.
references:
    - https://securityonline.info/greatxml-bitlocker-bypass-poc/
    - https://www.securityweek.com/greatxml-zero-day-exploit-bypasses-bitlocker/
    - https://github.com/MSNightmare/GreatXML
author: Actioner
date: 2026/06/11
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection_mpcmdrun:
        Image|endswith: '\MpCmdRun.exe'
        CommandLine|contains|all:
            - '-Scan'
            - '-ScanType'
            - '3'
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - 'Start-MpWDOScan'
    condition: 1 of selection_*
falsepositives:
    - Legitimate administrator-initiated Defender offline scans
    - Scheduled Defender maintenance tasks
    - Enterprise security tools triggering offline scans for remediation
level: medium
```

### YARA: GreatXML Exploit Tool Binary Detection
Detects PE files or scripts containing strings characteristic of the GreatXML exploit tool, including the tool name, author attribution, and the combination of unattend.xml/WinRE/Defender references.
<!-- audit: yarac exit 0. Condition requires filesize<5MB plus (GreatXML name + XML/recovery references) OR (author strings + XML + Defender) OR (name + Defender + BitLocker). FP: extremely unlikely outside of security research tools referencing GreatXML by name. -->
**Status:** compile ✅ compiles · confidence: high
```yara
rule Exploit_GreatXML_BitLocker_Bypass
{
    meta:
        description = "Detects the GreatXML exploit tool that abuses Microsoft Defender offline scan artifacts to bypass BitLocker encryption via crafted unattend.xml and Recovery directory planted on the recovery partition"
        author = "Actioner"
        date = "2026-06-11"
        reference = "https://github.com/MSNightmare/GreatXML"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $name1 = "GreatXML" ascii wide
        $name2 = "greatxml" ascii wide nocase

        $xml1 = "unattend.xml" ascii wide nocase
        $xml2 = "unattend" ascii wide
        $xml3 = "<settings pass=" ascii wide

        $recov1 = "Recovery\\WindowsRE" ascii wide
        $recov2 = "\\Recovery\\" ascii wide
        $recov3 = "WinRE" ascii wide

        $defender1 = "Windows Defender" ascii wide nocase
        $defender2 = "OfflineScan" ascii wide
        $defender3 = "WdBoot" ascii wide
        $defender4 = "MpCmdRun" ascii wide

        $author1 = "Nightmare" ascii wide
        $author2 = "MSNightmare" ascii wide
        $author3 = "Chaotic Eclipse" ascii wide
        $author4 = "Dead Eclipse" ascii wide

        $bitlocker1 = "BitLocker" ascii wide nocase
        $bitlocker2 = "FVE" ascii wide

    condition:
        filesize < 5MB and
        (
            ($name1 or $name2) and (1 of ($xml*) or 1 of ($recov*))
        ) or
        (
            filesize < 5MB and
            2 of ($author*) and (1 of ($xml*) or 1 of ($recov*)) and 1 of ($defender*)
        ) or
        (
            filesize < 5MB and
            1 of ($name*) and 1 of ($defender*) and 1 of ($bitlocker*)
        )
}
```

### YARA: GreatXML Crafted Unattend.xml Payload
Detects XML answer files containing the combination of unattend namespace, WinRE settings pass, and command execution directives consistent with a weaponized unattend.xml payload.
<!-- audit: yarac exit 0. Targets the actual planted XML payload rather than the exploit tool binary. Condition: XML file < 500KB with unattend namespace + settings/WinRE pass + command execution element. FP: legitimate answer files that include both recovery passes and RunSynchronous commands — review context. -->
**Status:** compile ✅ compiles · confidence: medium
```yara
rule Exploit_GreatXML_Unattend_XML_Payload
{
    meta:
        description = "Detects crafted unattend.xml files consistent with GreatXML exploit payload that targets WinRE to bypass BitLocker and spawn SYSTEM shell"
        author = "Actioner"
        date = "2026-06-11"
        reference = "https://github.com/MSNightmare/GreatXML"
        severity = "high"
        tlp = "WHITE"

    strings:
        $xml_header = "<?xml" ascii wide nocase
        $unattend_ns = "urn:schemas-microsoft-com:unattend" ascii wide nocase
        $settings = "<settings pass=" ascii wide nocase

        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "powershell" ascii wide nocase
        $cmd3 = "command" ascii wide nocase

        $winre1 = "windowsPE" ascii wide nocase
        $winre2 = "offlineServicing" ascii wide nocase
        $winre3 = "oobeSystem" ascii wide nocase

        $shell1 = "RunSynchronous" ascii wide nocase
        $shell2 = "FirstLogonCommands" ascii wide nocase
        $shell3 = "RunSynchronousCommand" ascii wide nocase
        $shell4 = "LogonCommands" ascii wide nocase

    condition:
        filesize < 500KB and
        $xml_header and
        $unattend_ns and
        1 of ($settings, $winre*) and
        1 of ($cmd*) and
        1 of ($shell*)
}
```

### Snort / Suricata: N/A
No network detection rules are generated. GreatXML is a local/physical access exploit with no network communication component. The exploit chain occurs entirely on the local system (file staging on recovery partition followed by WinRE reboot).

## Lessons Learned

1. **Recovery environments are a blind spot for endpoint security.** WinRE operates outside the normal Windows boot, where endpoint detection agents, Sysmon, and audit logging are not active. Any exploit that stages artifacts on the live OS for execution during recovery boot creates a detection gap -- defenders can only catch the preparation phase, not the exploitation phase.

2. **Defender features that expand the recovery partition attack surface are themselves a risk.** Defender Offline Scan is a legitimate security feature, but it creates a persistent configuration on the recovery partition that the GreatXML exploit leverages. The irony of a security feature creating a security vulnerability underscores the need for defense-in-depth approaches to boot-time security.

3. **Incomplete PoCs still provide actionable intelligence.** Although Nightmare Eclipse deliberately withheld the final exploit component, the published mechanism (answer file injection on recovery partition + WinRE reboot) provides sufficient detail for skilled attackers to complete the chain. Detection engineering should not wait for a complete weaponized exploit to deploy rules.

4. **BitLocker TPM-only configurations are increasingly targeted.** Both GreatXML and YellowKey (released on the same day) bypass BitLocker when configured with TPM-only protection. Organizations should evaluate upgrading to TPM+PIN configurations on high-value endpoints.

## Sources

- [Security Online - GreatXML BitLocker Bypass PoC](https://securityonline.info/greatxml-bitlocker-bypass-poc/) -- primary news coverage reporting exploit mechanism and researcher attribution
- [SecurityWeek - GreatXML Zero-Day Exploit Bypasses BitLocker](https://www.securityweek.com/greatxml-zero-day-exploit-bypasses-bitlocker/) -- secondary news coverage with additional technical context on the exploit chain
- [GitHub - MSNightmare/GreatXML](https://github.com/MSNightmare/GreatXML) -- public PoC repository containing unattend.xml and Recovery directory structure (deliberately incomplete)
- [Nightmare Eclipse Blog - GreatXML Announcement](https://deadeclipse666.blogspot.com/2026/06/greatxml-bitlocker-that-seems-to-only.html) -- researcher's original blog post announcing the exploit
- [BleepingComputer - Windows BitLocker Zero-Day Gives Access to Protected Drives](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/) -- coverage of related YellowKey exploit and Nightmare Eclipse campaign context
- [Cybernews - BitLocker Bypass and Privilege Escalation Exploit Released](https://cybernews.com/security/researcher-releases-bitlocker-bypass-and-privilege-escalation-exploit/) -- campaign context and researcher motivation analysis
- [Actioner - RoguePlanet Zero-Day Report (2026-06-10)](2026-06-10-defender-rogueplanet-zero-day.md) -- prior Actioner analysis of related Nightmare Eclipse exploit

---
*Report generated by Actioner*
