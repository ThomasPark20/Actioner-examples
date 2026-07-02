# Windows BlueHammer — Microsoft Defender Local Privilege Escalation (CVE-2026-33825)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-30
Version: 1 (DRAFT)

## Executive Summary

CVE-2026-33825 ("BlueHammer") is a high-severity (CVSS 7.8) local privilege escalation vulnerability in Microsoft Defender's threat remediation engine, rooted in a time-of-check to time-of-use (TOCTOU) race condition. An authenticated local attacker can exploit the race to redirect Defender's privileged file operations via NTFS junction points, ultimately gaining SYSTEM-level access. The vulnerability was publicly disclosed with a working proof-of-concept on April 7, 2026 by the researcher "Chaotic Eclipse" (also referenced as "Nightmare Eclipse"), patched on April 14, 2026 (April Patch Tuesday), and added to the CISA Known Exploited Vulnerabilities catalog on April 22, 2026. CISA confirmed on June 30, 2026 that ransomware gangs are actively exploiting the flaw.

## Technical Analysis

### Affected Products

| Product | Affected Versions | Fixed Version |
|---|---|---|
| Microsoft Defender Antimalware Platform | Prior to 4.18.26030.3011 | 4.18.26030.3011+ |
| Windows 10 (all editions) | All supported | Apply April 2026 Patch Tuesday |
| Windows 11 (all editions) | All supported | Apply April 2026 Patch Tuesday |
| Windows Server 2016/2019/2022/2025 | All supported | Apply April 2026 Patch Tuesday |

### Attack Chain

The BlueHammer exploit follows a multi-stage privilege escalation chain:

**Stage 1 — Trigger Defender Remediation:**
The attacker drops an EICAR test file (`foo.exe`) into a temporary directory. Microsoft Defender's real-time protection engine (MsMpEng.exe) detects the file and initiates its remediation workflow, which involves privileged file operations.

**Stage 2 — Oplock Pause:**
The exploit opens `RstrtMgr.dll` with a batch opportunistic lock (oplock) as a tripwire. When Defender interacts with the target file and reaches the critical remediation point, the exploit uses the oplock callback to pause Defender's file operation thread at the exact moment between the path check and the write operation.

**Stage 3 — Cloud Files API Stall:**
The exploit registers a directory as a Cloud Files sync root using `CfRegisterSyncRoot()` and `CfConnectSyncRoot()`, drops a randomly-named `.lock` placeholder, and triggers `CfCallbackFetchPlaceHolders` callbacks to further stall the WinDefend service process, widening the race window.

**Stage 4 — NTFS Junction Redirect:**
During the pause, the exploit replaces the target temporary directory with an NTFS junction point that redirects Defender's target path from the attacker-controlled temporary directory to `C:\Windows\System32`. When the oplock is released, Defender's privileged write operation now targets the system directory.

**Stage 5 — Credential Extraction via VSS:**
The exploit enumerates Volume Shadow Copy devices (`\\Device\HarddiskVolumeShadowCopy*`) and reads sensitive registry hives:
- `\\Device\HarddiskVolumeShadowCopy*\Windows\System32\Config\SAM`
- `\\Device\HarddiskVolumeShadowCopy*\Windows\System32\Config\SYSTEM`
- `\\Device\HarddiskVolumeShadowCopy*\Windows\System32\Config\SECURITY`

It then recovers the boot key from SYSTEM hive keys (`Control\Lsa\JD`, `Control\Lsa\Skew1`, `Control\Lsa\GBG`, `Control\Lsa\Data`), decrypts the LSA secret key, and extracts the Password Encryption Key from SAM.

**Stage 6 — Administrator Password Reset and SYSTEM Token:**
Using `samlib.dll` function `SamiChangePasswordUser()`, the exploit resets the local Administrator password to a hardcoded value (`$PWNed666!!!WDFAIL`). It then calls `LogonUserEx()` to obtain a security token, duplicates it with SYSTEM integrity, and creates a malicious Windows Service via `CreateService()` with a GUID-style name.

**Stage 7 — Cleanup:**
The exploit restores the original Administrator NTLM password hash using `SamiChangePasswordUser()` again, erasing evidence of the password change.

### Key Vulnerable Component

The TOCTOU race exists in Defender's remediation engine (MsMpEng.exe / MpSigStub.exe), which performs privileged file operations during malware cleanup without adequately validating the file path at the time of the write operation. The Cloud Files Mini Filter Driver (`cldflt.sys`) is also leveraged to amplify the race window.

### Related Vulnerabilities

The same researcher disclosed two additional Microsoft Defender flaws:
- **RedSun** — A second privilege escalation flaw leveraging the Windows Cloud Files API with NTFS junctions and the Storage Tiers Management service (`TieringEngineService.exe`).
- **UnDefend** — A flaw exploitable as a standard user to block Defender definition updates.

## Indicators of Compromise

### Host-Based Indicators

| Type | Value | Context |
|---|---|---|
| Password String | `$PWNed666!!!WDFAIL` | Hardcoded PoC password for Administrator reset |
| File | `foo.exe` in `%TEMP%` | EICAR trigger file dropped by exploit |
| File | `.lock` placeholder in sync root | Cloud Files placeholder for stalling Defender |
| DLL | `samlib.dll` loaded by non-LSASS process | SAM API access for password manipulation |
| DLL | `cldapi.dll` loaded by untrusted process | Cloud Files sync root registration |
| DLL | `RstrtMgr.dll` in user temp directory | Oplock tripwire file |
| Registry Hive Access | `\\Device\HarddiskVolumeShadowCopy*\...\Config\SAM` | Credential extraction via VSS |
| Registry Hive Access | `\\Device\HarddiskVolumeShadowCopy*\...\Config\SYSTEM` | Boot key extraction via VSS |
| Registry Hive Access | `\\Device\HarddiskVolumeShadowCopy*\...\Config\SECURITY` | LSA secret extraction via VSS |
| Registry Keys | `Control\Lsa\JD`, `Skew1`, `GBG`, `Data` | Boot key recovery subkeys |
| Service Creation | GUID-named service (Event ID 7045) | Malicious service for SYSTEM execution |
| Security Events | Event ID 4723/4724 for Administrator | Rapid password change/restore cycle |
| Defender Signature | `Exploit:Win32/DfndrPEBluHmr.BB` | Microsoft signature for original PoC binary |

### Network Indicators

| Type | Value | Context |
|---|---|---|
| URL | `hxxps://go[.]microsoft[.]com/fwlink/?LinkID=121721&arch=x64` | Legitimate Defender update URL fetched by exploit to obtain `update.cab` |

Note: The exploit primarily uses local system resources and does not require external C2 infrastructure. The Defender update URL fetch is a legitimate Microsoft endpoint used in the staging phase.

### Source Repository

| Type | Value |
|---|---|
| GitHub PoC | `hxxps://github[.]com/Nightmare-Eclipse/BlueHammer` |

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Exploit Stage |
|---|---|---|
| T1068 | Exploitation for Privilege Escalation | Core vulnerability exploitation via TOCTOU race |
| T1003.002 | OS Credential Dumping: Security Account Manager | SAM/SYSTEM/SECURITY hive extraction from VSS |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Abuse of Defender remediation to redirect file ops |
| T1562 | Impair Defenses | Cloud Files API abuse to stall WinDefend |
| T1543.003 | Create or Modify System Process: Windows Service | GUID-named service creation for SYSTEM execution |
| T1574 | Hijack Execution Flow | NTFS junction point redirect of Defender write |
| T1006 | Direct Volume Access | VSS shadow copy enumeration for hive access |

## Detection Rules

### Temporal Correlation Guidance

For highest-fidelity BlueHammer detection, correlate multiple rule firings within a short time window (e.g., 5 minutes on the same host): samlib.dll non-LSASS load + Administrator password change (Event 4723/4724) + VSS shadow copy hive access. Any two of these three occurring together within a short window strongly indicates active exploitation rather than benign activity.

### Sigma Rules

**1. samlib.dll Non-LSASS Load**
Detects samlib.dll loaded by a process other than lsass.exe or known Windows utilities, indicating potential SAM API abuse for password manipulation. Caveat: filter exclusions for net.exe, runas.exe, mstsc.exe, and dsac.exe reduce noise but should be validated per environment.
- Status: Compiled (Splunk + LogScale)
- Confidence: **medium** — samlib.dll loads outside LSASS are uncommon but occur in several built-in Windows utilities
- File: `rules/sigma/windows-bluehammer-samlib-nonlsass-load.yml`

```yaml
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\samlib.dll'
    filter_lsass:
        Image|endswith: '\lsass.exe'
    filter_known_legitimate:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
            - '\runas.exe'
            - '\mstsc.exe'
            - '\dsac.exe'
    condition: selection and not (filter_lsass or filter_known_legitimate)
level: medium
```

**2. Administrator Password Reset via SAM API**
Detects password change events (4723/4724) targeting the local Administrator account from non-machine accounts. Caveat: LAPS and manual rotation will trigger this rule; correlate with samlib load and VSS access for higher fidelity.
- Status: Compiled (Splunk + LogScale)
- Confidence: **medium** — Administrator password changes can occur legitimately (LAPS, manual rotation)
- File: `rules/sigma/windows-bluehammer-rapid-password-change-restore.yml`

```yaml
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4723
            - 4724
        TargetUserName: 'Administrator'
    filter_known_sources:
        SubjectUserName|endswith: '$'
    condition: selection and not filter_known_sources
level: medium
```

**3. Cloud Files Sync Root Registration by Untrusted Process**
Detects cldapi.dll loaded by processes outside known cloud storage providers and system directories. Caveat: requires tuning per environment to whitelist additional cloud providers.
- Status: Compiled (Splunk + LogScale)
- Confidence: **medium** — Requires tuning for environment-specific cloud providers
- File: `rules/sigma/windows-bluehammer-cloud-files-syncroot-abuse.yml`

```yaml
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\cldapi.dll'
    filter_known_providers:
        Image|endswith:
            - '\OneDrive.exe'
            - '\OneDriveSetup.exe'
            - '\iCloudDrive.exe'
            - '\Dropbox.exe'
            - '\GoogleDriveFS.exe'
            - '\FileCoAuth.exe'
    filter_system:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not (filter_known_providers or filter_system)
level: medium
```

**4. VSS Shadow Copy Hive Enumeration**
Detects file access to registry hives (SAM, SYSTEM, SECURITY) via Volume Shadow Copy device paths, a key credential extraction indicator. Caveat: requires Sysmon with FileAccess logging (Event ID 2) or equivalent EDR telemetry; without this configuration the rule will not fire.
- Status: Compiled (Splunk + LogScale)
- Confidence: **medium** — strong signal when telemetry is available, but file_access logging is not enabled by default
- File: `rules/sigma/windows-bluehammer-vss-shadow-copy-enumeration.yml`

```yaml
logsource:
    category: file_access
    product: windows
detection:
    selection:
        TargetFilename|contains: 'HarddiskVolumeShadowCopy'
        TargetFilename|endswith:
            - '\Windows\System32\Config\SAM'
            - '\Windows\System32\Config\SYSTEM'
            - '\Windows\System32\Config\SECURITY'
    condition: selection
level: medium
```

**5. RstrtMgr.dll Exclusive Handle in Temp Directory**
Detects RstrtMgr.dll file events in user AppData temp directories, matching the oplock tripwire technique. Caveat: scoped to `\Users\*\AppData\Local\Temp\` to reduce false positives from other `\Users\` subpaths.
- Status: Compiled (Splunk + LogScale)
- Confidence: **high** — RstrtMgr.dll copied to user temp paths is highly unusual
- File: `rules/sigma/windows-bluehammer-rstrtmgr-oplock-tripwire.yml`

```yaml
logsource:
    category: file_event
    product: windows
detection:
    selection_rstrtmgr:
        TargetFilename|endswith: '\RstrtMgr.dll'
    selection_temp_path:
        TargetFilename|contains:
            - '\Users\*\AppData\Local\Temp\'
    condition: selection_rstrtmgr and selection_temp_path
level: high
```

**6. GUID-Named Temporary Service Creation**
Detects service installation (Event ID 7045) where the service name matches a GUID pattern, as used in BlueHammer's SYSTEM execution step. Caveat: Windows Update and MSI-based installers can create GUID-named services legitimately.
- Status: Compiled (Splunk + LogScale)
- Confidence: **medium** — Some legitimate software uses GUID-named services
- File: `rules/sigma/windows-bluehammer-guid-temp-service-creation.yml`

```yaml
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|re: '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    condition: selection
level: medium
```

### YARA Rule

**BlueHammer Exploit Binary Detection**
Detects BlueHammer exploit binaries via distinctive strings including the hardcoded Administrator password, SAM API + Cloud Files API combinations, and VSS hive + LSA key extraction patterns. Caveat: variants that change the hardcoded password will only match the multi-string condition branches.
- Status: Compiled (yarac exit 0)
- Confidence: **high** — Keyed on exploit-specific strings (`$PWNed666!!!WDFAIL`, `SamiChangePasswordUser` + Cloud Files APIs)
- File: `rules/yara/windows_bluehammer.yar`

```yara
rule BlueHammer_CVE_2026_33825_Exploit_Artifact
{
    strings:
        $pwd_reset      = "$PWNed666!!!WDFAIL" ascii wide
        $sami_func      = "SamiChangePasswordUser" ascii wide
        $cf_register    = "CfRegisterSyncRoot" ascii wide
        $cf_connect     = "CfConnectSyncRoot" ascii wide
        $vss_sam        = "HarddiskVolumeShadowCopy" ascii wide
        $hive_sam       = "\\Config\\SAM" ascii wide
        $hive_system    = "\\Config\\SYSTEM" ascii wide
        ...
    condition:
        $pwd_reset
        or ($sami_func and any of ($cf_register, $cf_connect, $cf_callback))
        or ($vss_sam and 2 of ($hive_*) and 2 of ($lsa_*))
        or ($defender_url and any of ($cf_register, $cf_connect) and $rstrtmgr)
}
```

## Remediation

1. **Patch immediately**: Update the Microsoft Defender Antimalware Platform to version **4.18.26030.3011 or higher**. This is auto-updated via Windows Update but verify with `Get-MpComputerStatus` in PowerShell.
2. **Apply April 2026 Patch Tuesday updates**: Ensure all Windows 10, 11, and Server systems have the April 14, 2026 cumulative update installed.
3. **Verify patch status**: Run `Get-MpComputerStatus` and confirm `AMProductVersion` is 4.18.26030.3011+.
4. **Monitor for exploitation indicators**: Deploy the Sigma rules above to detect exploitation attempts, especially the samlib.dll non-LSASS load and VSS hive access rules.
5. **Audit Administrator account activity**: Review Security Event IDs 4723/4724 for any unexpected password changes on the built-in Administrator account.
6. **Review service installations**: Check Event ID 7045 for any GUID-named services that may indicate post-exploitation activity.
7. **CISA BOD 22-01 compliance**: Federal agencies were required to patch by May 7, 2026. Verify compliance.

## Sources

- [BleepingComputer: CISA Windows BlueHammer flaw now exploited by ransomware gangs](https://www.bleepingcomputer.com/news/security/cisa-windows-bluehammer-flaw-now-exploited-by-ransomware-gangs/)
- [BleepingComputer: CISA orders feds to patch BlueHammer flaw exploited as zero-day](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-microsoft-defender-flaw-exploited-in-zero-day-attacks/)
- [Picus Security: BlueHammer & RedSun: Windows Defender CVE-2026-33825 Zero-day Vulnerability Explained](https://www.picussecurity.com/resource/blog/bluehammer-redsun-windows-defender-cve-2026-33825-zero-day-vulnerability-explained)
- [Cyderes: BlueHammer: Inside the Windows Zero-Day](https://www.cyderes.com/howler-cell/windows-zero-day-bluehammer)
- [DenizHalil: CVE-2026-33825 (BlueHammer) Vulnerability Analysis](https://denizhalil.com/2026/06/12/cve-2026-33825-bluehammer-vulnerability-analysis/)
- [OP Innovate: BlueHammer Microsoft Defender Privilege Escalation](https://op-c.net/blog/bluehammer-microsoft-defender-privilege-escalation-cve-2026-33825/)
- [Penligent: BlueHammer, RedSun, and the Windows Defender Race to SYSTEM](https://www.penligent.ai/hackinglabs/bluehammer-redsun-and-the-windows-defender-race-to-system/)
- [The Hacker News: Three Microsoft Defender Zero-Days Actively Exploited](https://thehackernews.com/2026/04/three-microsoft-defender-zero-days.html)
- [SecurityWeek: Recent Microsoft Defender Vulnerability Exploited as Zero-Day](https://www.securityweek.com/recent-microsoft-defender-vulnerability-exploited-as-zero-day/)
- [Microsoft MSRC: CVE-2026-33825 Advisory](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2026-33825)
- [NVD: CVE-2026-33825](https://nvd.nist.gov/vuln/detail/CVE-2026-33825)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
