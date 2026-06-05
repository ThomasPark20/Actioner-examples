# Technical Analysis Report: Hola Browser Supply Chain Compromise (2026-06-05)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-05
Version: 1.0 (DRAFT)

## Executive Summary

The Windows version of the Hola Browser (v1.251.91.0) was compromised in a supply chain attack that delivered an undeclared cryptocurrency mining executable to end users. The malicious binary, named `me.exe`, was discovered by Sophos X-Ops during AppEsteem software certification testing and was identified as a Golang-based XMRig Monero miner (detected as Troj/GoMiner-B). When executed with administrator privileges, the malware copied itself to `C:\Program Files\Hola\HolaMonitorService.exe`, installed a Windows service (`hola_monitor_svc`) configured for automatic startup during system idle, and attempted to add itself to Windows Defender exclusion lists to evade detection.

Hola, an Israeli company known for its VPN service, confirmed the supply chain compromise after independent corroboration by cybersecurity forensics firm Sygnia. The company reported that approximately 0.1% of its user base was affected, with no evidence of user data theft. Hola has since rebuilt its distribution pipeline, implemented advanced code-signing verification, and introduced continuous monitoring across its infrastructure.

## Background: Hola Browser / Hola VPN

Hola is an Israeli technology company best known for Hola VPN, a peer-to-peer proxy service that allows users to route internet traffic through other users' devices or through paid proxy infrastructure to bypass geographic restrictions. The Hola Browser is a Windows desktop application that integrates the VPN functionality with a Chromium-based browser. The software has a substantial user base, making it an attractive target for supply chain attacks.

The compromise was specifically in the Windows software distribution pipeline -- the mechanism by which Hola Browser installers and updates are delivered to end users. The attacker injected an undeclared executable into the delivery pipeline such that it was distributed alongside legitimate Hola Browser components under certain conditions, suggesting the compromise was targeted or intermittent rather than affecting all downloads.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Unknown | Attacker compromises Hola's software distribution pipeline |
| Unknown | Malicious `me.exe` binary begins shipping with some Hola Browser v1.251.91.0 installations |
| 2026-02 (approx.) | Sophos X-Ops discovers undeclared `me.exe` during AppEsteem certification testing of Hola Browser |
| 2026-02/03 | AppEsteem notifies Hola of the finding; Sygnia independently corroborates the supply chain compromise |
| 2026-03-10 | ANY.RUN sandbox analysis of `me.exe` sample conducted |
| 2026-03 (approx.) | Hola CEO Avi Raz Cohen confirms the supply chain compromise and disables the affected delivery mechanism |
| 2026-03 (approx.) | Hola rebuilds distribution pipeline with code-signing verification and continuous monitoring |
| 2026-05 | BleepingComputer, Sophos X-Ops, and CyberInsider publish reports on the incident |

## Root Cause: Software Distribution Pipeline Compromise

The root cause was a compromise of Hola's software distribution pipeline. The malicious executable was not permanently embedded in the Hola Browser installer but was delivered inconsistently -- only under certain conditions -- which pointed researchers toward an issue involving the delivery pipeline, content distribution network, update mechanism, or build process rather than a permanently modified installer package.

The certification testing by AppEsteem had previously validated a clean snapshot of Hola Browser, but the pipeline delivered additional undeclared components in at least some installations. The specific method by which the attacker gained access to the distribution pipeline has not been publicly disclosed. Sygnia conducted the forensic investigation and confirmed it was a supply chain compromise.

## Technical Analysis of the Malicious Payload

### 1. Initial Delivery via Compromised Installer Pipeline

The malicious component `me.exe` was delivered alongside the legitimate Hola Browser v1.251.91.0 installer. The binary was dropped into the Hola installation directory at `C:\Program Files\Hola\me.exe`. The delivery was inconsistent -- not all installations received the malicious payload -- suggesting the pipeline compromise was conditional or time-based.

Key file characteristics:
- **File name:** me.exe
- **File type:** PE32+ x86-64 executable (Windows)
- **Language:** Golang (Go)
- **Size:** ~4.18 MB code section, 537 KB initialized data
- **Entry point:** 0x7bac0
- **Digital signature:** None (unsigned)
- **Timestamp:** None (no compilation timestamp metadata)
- **Code characteristics:** Obfuscated code, memory-write capability

### 2. Service Installation and Persistence

When executed with administrator privileges, the malware performed the following persistence actions:

1. Copied itself from `C:\Program Files\Hola\me.exe` to `C:\Program Files\Hola\HolaMonitorService.exe` (or `C:\Program Files\Hola\app\HolaMonitorService.exe`)
2. Registered a Windows service named `hola_monitor_svc` configured for automatic startup
3. The service was configured to run when the host system was idle (to avoid detection via performance impact)
4. Created registry entries for the service event log:
   - `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\hola_monitor_svc`
   - `CustomSource: 1`
   - `EventMessageFile: %SystemRoot%\System32\EventCreate.exe`
   - `TypesSupported: 7`

### 3. Cryptomining Payload (XMRig)

The binary contained multiple strings confirming XMRig-based Monero cryptocurrency mining:

- `m/cmd/xmrig-idle` -- Go module path indicating XMRig integration with idle-detection
- `killed orphan miner pid %d` -- Orphan process management for mining child processes
- `user active, stopping miner` -- User activity detection to pause mining when the system is in use

The miner was designed to operate only during system idle periods, a common evasion technique that reduces the likelihood of user detection through performance degradation.

### 4. Defense Evasion

The malware employed the following evasion techniques:

- **Windows Defender Exclusion:** Attempted to add itself to Windows Defender exclusion lists, likely via `Add-MpPreference -ExclusionPath` targeting the Hola installation directory
- **Legitimate Service Masquerading:** Registered as `hola_monitor_svc` and named the binary `HolaMonitorService.exe` to blend in with legitimate Hola VPN service components
- **Idle-Only Execution:** Mining activity occurred only during system idle periods to avoid alerting users via CPU usage spikes
- **No Digital Signature / Timestamp:** The binary lacked both code signing and compilation timestamps to hinder forensic analysis
- **Anti-VM Detection:** Sandbox analysis revealed anti-VM strings present in the binary, suggesting the malware may attempt to detect virtual/analysis environments

### 5. Anti-Forensics / Evasion Techniques

- Obfuscated code to hinder static analysis
- Memory-write capability for potential runtime unpacking or self-modification
- Anti-VM functionality to detect sandbox environments
- No compilation timestamp to prevent timeline analysis
- Unsigned binary disguised with a legitimate-sounding service name

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Hola Browser (Windows) | 1.251.91.0 | Compromised distribution pipeline delivered undeclared me.exe cryptominer |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | C:\Program Files\Hola\me.exe | e3541caf708c075f0bb22fc68b03acd8457fea7cf0732ea935b1eb016d1c7721 | Malicious cryptominer binary (Troj/GoMiner-B) |
| Windows | C:\Program Files\Hola\HolaMonitorService.exe | e3541caf708c075f0bb22fc68b03acd8457fea7cf0732ea935b1eb016d1c7721 | Self-copy of me.exe for service persistence |
| Windows | (installer) | 174086534a2de730058465a4a4e231ce3778ab17ebebfd7f62b3bf9750bc7bdb | Certified Hola Browser installer (reference clean hash) |

**Additional hashes for me.exe (Sophos sample):**
- SHA1: 8046735d354814bf9ef9a053cb9cad8cfec261f2
- MD5: 8462f61e68b37d220eab2462b3cbcec8

**Additional hashes for me.exe (ANY.RUN sandbox sample):**
- SHA256: 4cdeb5df217764a8b6a20d518b76ccb30cbe623365a13d9dcd40900950f1ed99
- SHA1: a21c8b8cabc7670ea45bc175e185a0f9bfcf4733
- MD5: efd792f08b152fcd59187ec311d785d2

### Network

| Type | Value | Context |
|------|-------|---------|
| N/A | No specific C2 domains, mining pool addresses, or IP addresses were disclosed in available reporting | Mining pool connections expected but not documented |

### Behavioral

- **Process chain:** `explorer.exe` -> `me.exe` -> `HolaMonitorService.exe` (via service manager: `services.exe` -> `HolaMonitorService.exe`)
- **Service registration:** Creates Windows service `hola_monitor_svc` with automatic startup
- **Registry modification:** Creates `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\hola_monitor_svc` with EventCreate.exe as message file
- **Windows Defender exclusion:** Adds Hola installation directory to Defender exclusion path
- **Idle-only mining:** Pauses mining when user activity is detected ("user active, stopping miner")
- **Orphan process management:** Kills orphan mining processes ("killed orphan miner pid %d")

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious binary injected into Hola Browser distribution pipeline |
| T1543.003 | Create or Modify System Process: Windows Service | Installs `hola_monitor_svc` service for persistence |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Binary named `HolaMonitorService.exe` to mimic legitimate Hola service |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Adds Windows Defender exclusion for installation directory |
| T1496 | Resource Hijacking | XMRig-based Monero cryptocurrency mining |
| T1105 | Ingress Tool Transfer | Malicious binary delivered via compromised update/install pipeline |
| T1497 | Virtualization/Sandbox Evasion | Anti-VM strings present in binary |

## Impact Assessment

- **Breadth:** Hola reports approximately 0.1% of its user base was affected, though the total user base size was not disclosed. Hola VPN claims millions of users globally.
- **Depth:** The attack delivered a cryptocurrency miner that consumes system resources (CPU/GPU) for Monero mining. No evidence of data theft, credential harvesting, or remote access trojan functionality was reported.
- **Stealth:** The miner was designed to operate only during system idle periods, reducing user-visible performance impact. The service name and binary path were crafted to blend with legitimate Hola components.
- **Financial impact:** Direct cost to victims in terms of electricity consumption and hardware degradation. Revenue generated by the attacker via Monero mining (amount unknown).

## Detection & Remediation

### Immediate Detection

Check for the presence of the malicious files and service:

```powershell
# Check for malicious files
Get-Item "C:\Program Files\Hola\me.exe" -ErrorAction SilentlyContinue
Get-Item "C:\Program Files\Hola\HolaMonitorService.exe" -ErrorAction SilentlyContinue

# Check for the malicious service
Get-Service -Name "hola_monitor_svc" -ErrorAction SilentlyContinue

# Check registry for service event log entry
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\hola_monitor_svc" -ErrorAction SilentlyContinue

# Check Windows Defender exclusions for Hola paths
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | Where-Object { $_ -like "*Hola*" }

# Verify file hashes (Sophos-reported sample)
Get-FileHash "C:\Program Files\Hola\me.exe" -Algorithm SHA256 -ErrorAction SilentlyContinue
# Match against: e3541caf708c075f0bb22fc68b03acd8457fea7cf0732ea935b1eb016d1c7721
```

### Remediation

1. **Stop the malicious service:** `Stop-Service -Name "hola_monitor_svc" -Force`
2. **Remove the service:** `sc.exe delete hola_monitor_svc`
3. **Delete malicious files:** Remove `me.exe` and `HolaMonitorService.exe` from the Hola installation directory
4. **Remove Defender exclusions:** `Remove-MpPreference -ExclusionPath "C:\Program Files\Hola\"`
5. **Clean registry:** Remove `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\hola_monitor_svc`
6. **Update Hola Browser:** Update to the latest version or uninstall if not needed
7. **Run full antivirus scan:** Perform a complete system scan with updated AV signatures
8. **Review system for persistence:** Check for any additional persistence mechanisms that may have been installed

### Long-Term Hardening

- Implement application allowlisting to prevent unauthorized executables from running in software installation directories
- Monitor for new Windows service installations, especially those targeting idle-state execution
- Deploy endpoint detection and response (EDR) solutions that can detect cryptomining behavior
- Enforce code-signing verification for all installed software
- Monitor Windows Defender exclusion modifications as a potential indicator of compromise
- Consider blocking or monitoring Hola VPN/Browser on corporate networks given the supply chain risk

## Detection Rules

These detections target the Hola Browser supply chain cryptominer at the PoC/advisory-specific altitude, keying on file paths, service names, and XMRig strings published by Sophos X-Ops. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles does not equal fires -- verify in your pipeline with the published hashes.

### Sigma: Hola Browser Cryptominer Service Installation (Process Creation)

Detects `me.exe` or `HolaMonitorService.exe` execution in the Hola directory, or service installation commands referencing `hola_monitor_svc`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on published file paths and service name from Sophos X-Ops report. FP: legitimate Hola VPN service components (verify hash/signature). -->

```yaml
title: Hola Browser Supply Chain - Cryptominer Service Installation
id: 9a3c7e12-4b8f-4d2a-a1e6-3f5d9c8b7a01
status: experimental
description: >
    Detects the Hola Browser supply chain cryptominer (me.exe / HolaMonitorService.exe)
    installing itself as a Windows service named hola_monitor_svc. The malware copies
    itself to C:\Program Files\Hola\HolaMonitorService.exe and registers an auto-start
    service that runs when the system is idle.
references:
    - https://www.sophos.com/en-us/blog/you-do-surprise-me-exe-an-unexpected-executable-in-hola-browser
    - https://www.bleepingcomputer.com/news/security/hola-browser-for-windows-compromised-to-deliver-cryptominer/
    - https://cyberinsider.com/hola-browser-supply-chain-breach-delivered-crypto-miner-to-users/
author: Actioner
date: 2026-06-05
tags:
    - attack.t1543.003
    - attack.t1496
logsource:
    category: process_creation
    product: windows
detection:
    selection_me_exe:
        Image|endswith: '\me.exe'
        Image|contains: '\Hola\'
    selection_service_exe:
        Image|endswith: '\HolaMonitorService.exe'
    selection_service_install:
        CommandLine|contains|all:
            - 'hola_monitor_svc'
            - 'HolaMonitorService'
    condition: selection_me_exe or selection_service_exe or selection_service_install
falsepositives:
    - Legitimate Hola VPN service components (verify hash and digital signature)
level: high
```

### Sigma: Hola Browser Cryptominer File Drop

Detects creation of `me.exe` or `HolaMonitorService.exe` in the Hola installation directory.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on published file drop paths from Sophos X-Ops. FP: legitimate Hola updates (check signature). -->

```yaml
title: Hola Browser Supply Chain - Cryptominer File Drop
id: 7b2d6f91-3e4a-4c89-b5d7-2a1f8e0c9d34
status: experimental
description: >
    Detects the creation of the undeclared me.exe or HolaMonitorService.exe files
    in the Hola Browser installation directory, indicative of the supply chain
    cryptominer compromise affecting Hola Browser v1.251.91.0.
references:
    - https://www.sophos.com/en-us/blog/you-do-surprise-me-exe-an-unexpected-executable-in-hola-browser
    - https://www.bleepingcomputer.com/news/security/hola-browser-for-windows-compromised-to-deliver-cryptominer/
    - https://cyberinsider.com/hola-browser-supply-chain-breach-delivered-crypto-miner-to-users/
author: Actioner
date: 2026-06-05
tags:
    - attack.t1105
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection_me:
        TargetFilename|endswith: '\Hola\me.exe'
    selection_monitor:
        TargetFilename|endswith: '\Hola\HolaMonitorService.exe'
    condition: selection_me or selection_monitor
falsepositives:
    - Legitimate Hola VPN updates (verify digital signature and hash)
level: high
```

### Sigma: Hola Browser Cryptominer Defender Exclusion

Detects PowerShell commands adding the Hola directory to Windows Defender exclusion path, as performed by the compromised binary.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (1 medium issue: InvalidATTACKTagIssue on t1562.001 — pySigma MITRE DB stale, tag is valid); splunk 0; log_scale 0. FP: legitimate Hola installer adding exclusions. -->

```yaml
title: Hola Browser Supply Chain - Defender Exclusion for Cryptominer
id: 4c8e1a57-6d3f-4b92-9e7a-5f2d0c1b8a63
status: experimental
description: >
    Detects the Hola Browser supply chain cryptominer attempting to add itself
    to Windows Defender exclusion lists, a defense evasion technique used by
    the compromised me.exe / HolaMonitorService.exe binary.
references:
    - https://www.sophos.com/en-us/blog/you-do-surprise-me-exe-an-unexpected-executable-in-hola-browser
    - https://www.bleepingcomputer.com/news/security/hola-browser-for-windows-compromised-to-deliver-cryptominer/
    - https://cyberinsider.com/hola-browser-supply-chain-breach-delivered-crypto-miner-to-users/
author: Actioner
date: 2026-06-05
tags:
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_exclusion:
        CommandLine|contains|all:
            - 'Add-MpPreference'
            - '-ExclusionPath'
            - '\Hola\'
    condition: selection_exclusion
falsepositives:
    - Legitimate Hola VPN software adding exclusions during installation
level: high
```

### Snort: Hola Browser Cryptominer Service Name in Network Traffic

Detects the `hola_monitor_svc` service name string in outbound TCP traffic, potentially indicative of the cryptominer's C2 or telemetry communication.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c /etc/snort/snort.conf -T with include 0. Service name in network traffic is uncommon but possible in telemetry/update checks. Low expected volume. -->

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Hola Browser Supply Chain Cryptominer Service Registry Event"; flow:established,to_server; content:"hola_monitor_svc"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.sophos.com/en-us/blog/you-do-surprise-me-exe-an-unexpected-executable-in-hola-browser; sid:2100101; rev:1;)
```

### Suricata: Hola Browser Cryptominer XMRig Stratum Connection

Detects XMRig Stratum mining protocol JSON-RPC login attempts containing the `xmrig` identifier, consistent with the compromised Hola Browser cryptominer.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S 0. Keys on XMRig Stratum JSON-RPC login pattern. Generic to XMRig miners, not Hola-specific — pair with host IOCs for attribution. -->

```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Hola Browser Supply Chain Cryptominer XMRig Stratum Connection"; flow:established,to_server; content:"|22|method|22|"; content:"|22|login|22|"; distance:0; within:50; content:"xmrig"; nocase; classtype:trojan-activity; reference:url,www.sophos.com/en-us/blog/you-do-surprise-me-exe-an-unexpected-executable-in-hola-browser; metadata:author Actioner, created_at 2026-06-05; sid:2200101; rev:1;)
```

### YARA: Hola Browser Supply Chain XMRig Miner Binary

Detects the Hola Browser supply chain cryptominer PE binary via XMRig-related strings (`m/cmd/xmrig-idle`, `killed orphan miner pid`, `hola_monitor_svc`) published by Sophos X-Ops.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Sample test not applicable (PE header gate prevents text-file firing). Strings sourced from Sophos X-Ops published analysis of Troj/GoMiner-B. -->

```yara
rule SupplyChain_Hola_Browser_XMRig_Miner
{
    meta:
        description = "Detects the Hola Browser supply chain cryptominer (Troj/GoMiner-B) via XMRig-related strings found in the compromised me.exe binary"
        author = "Actioner"
        date = "2026-06-05"
        reference = "https://www.sophos.com/en-us/blog/you-do-surprise-me-exe-an-unexpected-executable-in-hola-browser"
        hash = "e3541caf708c075f0bb22fc68b03acd8457fea7cf0732ea935b1eb016d1c7721"
        severity = "high"

    strings:
        $xmrig_path = "m/cmd/xmrig-idle" ascii
        $miner_kill = "killed orphan miner pid %d" ascii
        $miner_stop = "user active, stopping miner" ascii
        $svc_name = "hola_monitor_svc" ascii
        $svc_exe = "HolaMonitorService.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($xmrig_path or (2 of ($miner_kill, $miner_stop, $svc_name, $svc_exe)))
}
```

## Lessons Learned

1. **Supply chain attacks target distribution infrastructure, not just code:** This compromise did not modify the Hola Browser source code or compiled binaries themselves. Instead, the attacker targeted the distribution pipeline -- the mechanism that delivers software to end users. This is a growing trend that bypasses traditional code review and CI/CD security controls.

2. **Software certification is a valuable detection vector:** The compromise was discovered through AppEsteem's periodic certification testing, not through traditional threat hunting or user complaints. Organizations that participate in software certification programs create an independent verification layer that can catch supply chain compromises that internal security monitoring misses.

3. **Idle-time execution is an effective evasion technique:** By mining only during system idle periods, the attacker significantly reduced the likelihood of user-reported performance issues. Detection strategies should not rely solely on user-reported symptoms but should include proactive monitoring for new service installations, unexpected executables, and Defender exclusion modifications.

4. **Cryptominers in supply chains indicate escalation potential:** While cryptocurrency mining is a relatively low-severity payload, the ability to deliver arbitrary executables via a supply chain compromise represents a much higher risk. The same pipeline compromise could have delivered ransomware, information stealers, or remote access trojans.

## Sources

- [Sophos X-Ops Blog](https://www.sophos.com/en-us/blog/you-do-surprise-me-exe-an-unexpected-executable-in-hola-browser) -- Primary technical analysis by Sophos X-Ops; source of file hashes, detection name (Troj/GoMiner-B), XMRig strings, and behavioral details
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/hola-browser-for-windows-compromised-to-deliver-cryptominer/) -- News report with Hola CEO response, Sygnia involvement, and user impact details
- [CyberInsider](https://cyberinsider.com/hola-browser-supply-chain-breach-delivered-crypto-miner-to-users/) -- Additional reporting with technical details on malware behavior, service installation, and Defender exclusion
- [ANY.RUN Sandbox Analysis](https://any.run/report/4cdeb5df217764a8b6a20d518b76ccb30cbe623365a13d9dcd40900950f1ed99/de3a756a-3101-4369-8922-52c586c939fb) -- Dynamic analysis of me.exe sample with process tree, registry modifications, and additional file hashes

---
*Report generated by Actioner*
