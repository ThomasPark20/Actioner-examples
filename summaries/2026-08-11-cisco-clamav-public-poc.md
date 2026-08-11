# Technical Analysis Report: Cisco ClamAV High-Severity Parser Vulnerabilities (2026-08-11)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-11
Version: 1.1 (FINAL)

## Executive Summary

Cisco disclosed seven high-severity vulnerabilities (CVE-2026-20337 through CVE-2026-20348) in ClamAV, affecting file parsers for ZIP, PESpin, GPT, PDF, Mach-O, and XAR formats. All vulnerabilities carry a CVSS 3.1 base score of 7.5 and allow remote, unauthenticated attackers to cause denial-of-service conditions by submitting crafted files for scanning. Public proof-of-concept exploit code exists for CVE-2026-20337 (ZIP heap overflow) and CVE-2026-20338 (ZIP double-free). Cisco Secure Endpoint Connector for Windows is rated High severity because ClamAV runs in a privileged security context; Linux and macOS connectors are rated Medium. Patches are available in ClamAV 1.5.4 and 1.4.6. No exploitation in the wild has been observed.

## Background: ClamAV and Cisco Secure Endpoint

ClamAV is an open-source antivirus engine maintained by Cisco Talos, widely deployed in email gateways, file scanning pipelines, and endpoint protection. It is integrated into Cisco Secure Endpoint Connector (formerly AMP for Endpoints) across Windows, macOS, and Linux platforms, as well as Cisco Secure Endpoint Private Cloud. ClamAV parses a broad range of archive and executable formats including ZIP, PE (with unpacker support for PESpin and others), GPT partition images, PDF, Mach-O, and XAR archives. A crash in the ClamAV scanning process directly impacts the security posture of any system relying on it for real-time or on-demand file inspection.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-07 | ClamAV 1.5.4 and 1.4.6 security patch versions published |
| 2026-08-07 | Cisco PSIRT advisory cisco-sa-clamav-WuuvVd26 published |
| 2026-08-11 | SecurityWeek reports on the vulnerabilities and public PoC availability |

## Root Cause: Parser Memory Safety Defects

All seven vulnerabilities stem from memory safety defects in ClamAV's file format parsers. The root causes span improper boundary checking (CWE-120, CWE-121, CWE-125), integer overflow (CWE-190), and double-free (CWE-415). An attacker exploits these by submitting a specially crafted file (ZIP archive, PESpin-packed PE, GPT image, PDF, Mach-O binary, or XAR archive) to any system running a vulnerable ClamAV instance. The file is processed during routine scanning, triggering the memory corruption and crashing the ClamAV process.

## Technical Analysis of the Vulnerabilities

### 1. CVE-2026-20337 -- ZIP Catalogue Capacity Heap Overflow (PoC Available)

A flaw in ZIP catalogue capacity tracking causes a write beyond a heap allocation while indexing local file headers. When ClamAV processes a crafted ZIP archive with manipulated catalogue entries, the parser fails to validate boundary conditions, resulting in an out-of-bounds heap write. This crashes the scanning process. Affects ClamAV 1.5.0--1.5.3. CWE-120/CWE-121/CWE-125. Discovered by Kevin Stubbings (GitHub Security Lab). Bug ID: CSCwu34288.

### 2. CVE-2026-20338 -- ZIP Catalogue Merging Double-Free (PoC Available)

Improper ownership handling during ZIP catalogue record merging can trigger an invalid free (double-free) while scanning a malformed archive. The parser incorrectly manages memory lifecycle when merging catalogue records, leading to memory corruption and process termination. Affects ClamAV 1.5.0--1.5.3. CWE-120/CWE-121/CWE-125 (advisory); the mechanism is a double-free (CWE-415). Discovered independently by Daggolu Rakesh and Yazdan Soltani. Bug ID: CSCwv57797.

### 3. CVE-2026-20339 -- PESpin Unpacker Integer Overflow

An integer overflow in the PESpin unpacker allocates an undersized buffer and then writes beyond it when rebuilding a PE file. The PESpin packer format uses compressed/encrypted PE sections; the ClamAV unpacker miscalculates the required buffer size when decompressing. This is one of the oldest-affected bugs, present from ClamAV 0.90 through 1.5.3. CWE-190/CWE-415. Discovered by Feng Xue and Yazdan Soltani. Bug ID: CSCwu78432.

### 4. CVE-2026-20345 -- GPT Partition Name Endian Conversion Overflow

An indexing error during GPT partition name endian conversion causes reads or writes beyond a stack-allocated partition entry. GPT partition names are stored as UTF-16LE; the conversion routine fails to properly bound the index when processing oversized or malformed partition names. Affects ClamAV 0.98.2--1.5.3. CWE-120/CWE-121/CWE-125. Discovered by Atuin/Tianchu Chen (Tencent Xuanwu Lab). Bug ID: CSCwu59475.

### 5. CVE-2026-20346 -- PDF Parser Integer Underflow

An integer underflow in the PDF parser causes a crash when reading a malformed hexadecimal string. PDF hex strings use paired hex digits; a malformed string with an odd number of digits or other structural anomalies triggers the underflow, leading to an invalid memory read. Affects ClamAV 1.4.5 and earlier, 1.5.0--1.5.3. CWE-120/CWE-121/CWE-125. Discovered by Tristan (@TristanInSec). Bug ID: CSCwu65985.

### 6. CVE-2026-20347 -- Mach-O Parser Integer Overflow

Undefined behavior and integer overflow in the Mach-O parser can crash ClamAV when processing crafted Mach-O binaries. The parser performs arithmetic on header fields without adequate overflow protection. Affects ClamAV 1.4.5 and earlier, 1.5.0--1.5.3. CWE-120/CWE-121/CWE-125. Discovered by Tristan (@TristanInSec). Bug ID: CSCwu65985.

### 7. CVE-2026-20348 -- XAR Parser Excessive Allocation

Incorrect size handling in the XAR parser can request an excessive allocation or exceed scan limits when decompressing a malformed table of contents. This leads to process termination via resource exhaustion or bounds violation. Affects ClamAV 0.98.1--1.5.3. CWE-120/CWE-121/CWE-125. Discovered by leduckhuong. Bug ID: CSCwu99410.

### Additional: CVE-2025-8088 -- UnRAR Path Traversal (Windows)

ClamAV 1.5.4 also incorporates an upstream UnRAR fix that rejects path separators in NTFS alternate data stream names, preventing file extraction outside the temporary scan directory on Windows. Affects ClamAV 0.101.0--1.5.3. Discovered by Yazdan Soltani.

### 8. Platform-Specific Severity

On Windows, ClamAV runs the scanning process in a privileged security context (Cisco Secure Endpoint Connector), making crashes more impactful (CVSS High, 7.5). On Linux and macOS, the scanning process runs with lower privileges (CVSS Medium, 5.3 for the connector products).

### 9. Anti-Forensics / Evasion Techniques

Not applicable. These are DoS vulnerabilities triggered by crafted input files. No persistence, lateral movement, or evasion techniques are involved.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through.

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| ClamAV | 0.90 -- 1.5.3 | CVE-2026-20339 (PESpin); broadest affected range |
| ClamAV | 0.98.1 -- 1.5.3 | CVE-2026-20348 (XAR) |
| ClamAV | 0.98.2 -- 1.5.3 | CVE-2026-20345 (GPT) |
| ClamAV | 1.5.0 -- 1.5.3 | CVE-2026-20337, CVE-2026-20338 (ZIP); CVE-2026-20346, CVE-2026-20347 (PDF, Mach-O) |
| Cisco Secure Endpoint Connector (Windows) | Prior to TBD Aug 2026 release | High severity (CVSS 7.5) |
| Cisco Secure Endpoint Connector (Linux) | Prior to TBD Aug 2026 release | Medium severity (CVSS 5.3) |
| Cisco Secure Endpoint Connector (macOS) | Prior to TBD Aug 2026 release | Medium severity (CVSS 5.3) |

### File System

No specific malicious file hashes are published. The exploit vector is a crafted file submitted for scanning; the file structure itself is the weapon.

### Network

No network-level IOCs. These vulnerabilities are exploited via file submission to the scanning engine, not via network protocol exploitation.

### Behavioral

- ClamAV process (clamd, clamscan, clamdscan) crashes with SIGSEGV or SIGABRT signals
- Repeated ClamAV service restarts in short succession
- ClamAV scan failures or incomplete scans on specific files
- Windows Application Error events (EventID 1000) for ClamAV executables

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1499.004 | Endpoint Denial of Service: Application or System Exploitation | Crafted files crash the ClamAV scanning process, causing denial of service |

## Impact Assessment

**Breadth:** ClamAV is one of the most widely deployed open-source antivirus engines, used directly and embedded in Cisco Secure Endpoint products across enterprise environments. The PESpin vulnerability (CVE-2026-20339) has the broadest affected range, going back to ClamAV 0.90.

**Depth:** All vulnerabilities cause denial of service (process crash). While rated High on Windows due to the privileged execution context, there is no evidence of code execution. The impact is disruption of file scanning capabilities, which could be chained with other attacks -- an attacker could crash the scanner and then deliver malware through the unprotected channel.

**Stealth:** Low stealth. Exploitation causes visible crashes and service restarts. The availability of public PoC code for two ZIP parser vulnerabilities (CVE-2026-20337, CVE-2026-20338) increases the likelihood of opportunistic exploitation.

## Detection & Remediation

### Immediate Detection

**Linux systems:**
```bash
# Check ClamAV version
clamscan --version
# Look for recent ClamAV crashes in logs
journalctl -u clamav-daemon --since "7 days ago" | grep -iE "segfault|signal|abort|core dump"
# Check dmesg for ClamAV crashes
dmesg | grep -i clam
```

**Windows systems:**
```powershell
# Check for ClamAV application errors in Event Log
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1000} | Where-Object { $_.Message -match 'clam' }
# Check ClamAV version
& "C:\Program Files\ClamAV\clamscan.exe" --version
```

### Remediation

1. **Update ClamAV** to version 1.5.4 (or 1.4.6 for the 1.4.x branch). These versions include patches for all seven CVEs.
2. **Update Cisco Secure Endpoint Connector** via the Cisco Secure Endpoint portal. Automatic updates may apply depending on policy configuration.
3. **Verify the update** by checking the ClamAV version reported by `clamscan --version`.
4. **Review scan logs** for any evidence of prior exploitation (crashes during file scanning).

### Long-Term Hardening

- Enable automatic ClamAV updates to receive security patches promptly
- Monitor ClamAV process health via system monitoring (process crash alerts)
- Consider sandboxing ClamAV scanning processes to limit the impact of future parser vulnerabilities (advisory: efficacy depends on deployment architecture)
- Implement file type restrictions at ingress points to reduce the attack surface for parser exploitation

## Detection Rules

These rules detect ClamAV process crashes (indicating possible exploitation of CVE-2026-20337 through CVE-2026-20348) and crafted files targeting specific vulnerable parsers. PoC/advisory-specific altitude; Snort/Suricata detect PESpin-packed PE files in transit that could trigger CVE-2026-20339. Compiles does not equal fires -- verify in your pipeline.

### Sigma: ClamAV Process Crash on Linux

Detects ClamAV process crashes via syslog on Linux, indicating possible exploitation of parser vulnerabilities.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (403 proxy to MITRE ATT&CK data, not a rule error); splunk convert exit 0; log_scale convert exit 0. Confidence medium: crash detection is reliable but not specific to these CVEs — any ClamAV crash matches. FP: resource exhaustion, unrelated bugs, OOM kills. -->
```yaml
title: ClamAV Process Crash or Abnormal Termination
id: 9a3e7c12-bf4d-4e8a-a1c6-d5f2e0b89734
status: experimental
description: >
    Detects ClamAV scanning processes (clamd, clamscan) terminating abnormally,
    which may indicate exploitation of CVE-2026-20337, CVE-2026-20338, or related
    ClamAV parser vulnerabilities via crafted files.
references:
    - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26
    - https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html
author: Actioner
date: 2026/08/11
tags:
    - attack.t1499.004
logsource:
    product: linux
    service: syslog
detection:
    selection_process:
        SyslogIdentifier|contains:
            - 'clamd'
            - 'clamscan'
            - 'clamdscan'
    selection_crash:
        Message|contains:
            - 'segfault'
            - 'SIGSEGV'
            - 'SIGABRT'
            - 'core dumped'
            - 'signal 11'
            - 'signal 6'
            - 'double free'
            - 'corrupted size'
            - 'heap-buffer-overflow'
    condition: selection_process and selection_crash
falsepositives:
    - Legitimate ClamAV crashes due to resource exhaustion or unrelated bugs
level: high
```

### Sigma: ClamAV Process Crash on Windows

Detects ClamAV application error events on Windows, where ClamAV runs in a privileged context (High severity).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (403 proxy to MITRE ATT&CK data, not a rule error); splunk convert exit 0; log_scale convert exit 0. Confidence medium: Windows Application Error EventID 1000 is reliable for crash detection but not CVE-specific. FP: version upgrades, config issues, resource exhaustion. -->
```yaml
title: ClamAV Process Crash on Windows - Potential Parser Exploit
id: b7d4e1f8-3a52-4c9b-8e06-f1a2d3c4b5e7
status: experimental
description: >
    Detects ClamAV scanning processes crashing on Windows via Application Error
    events, which may indicate exploitation of CVE-2026-20337 through CVE-2026-20348
    ClamAV parser vulnerabilities. Windows is rated High severity as ClamAV runs
    in a privileged security context on this platform.
references:
    - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26
    - https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html
author: Actioner
date: 2026/08/11
tags:
    - attack.t1499.004
logsource:
    product: windows
    service: application
detection:
    selection_event:
        EventID: 1000
    selection_process:
        Data|contains:
            - 'clamd.exe'
            - 'clamscan.exe'
            - 'clamdscan.exe'
            - 'ClamScanSvc.exe'
    condition: selection_event and selection_process
falsepositives:
    - Legitimate ClamAV crashes due to resource exhaustion
    - ClamAV version upgrades or configuration issues
level: high
```

### Snort: PESpin Packed PE in Transit (CVE-2026-20339)

Detects PESpin-packed PE files traversing the network that could trigger CVE-2026-20339 integer overflow in ClamAV's PESpin unpacker. Hunt-grade: flags the file format processed by the vulnerable parser, not exploit intent. Pair with ClamAV crash detection for confirmed exploitation.
**Status:** compile ✅ compiles · confidence: medium · hunt-grade
<!-- audit: snort -c (with custom test config) -T exit 0. Rule keys on MZ header + PE signature + "PESpin" string in file content. Confidence medium: PESpin-packed files are uncommon in legitimate traffic but the rule does not prove exploit intent — it flags the file format the vulnerable parser processes. Hunt-oriented; pair with ClamAV crash detection for confirmed exploitation. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PESpin Packed PE in Transit (CVE-2026-20339)"; flow:established,to_server; content:"MZ"; depth:2; content:"PE|00 00|"; distance:0; content:"PESpin"; nocase; fast_pattern; sid:2100101; rev:1; classtype:attempted-dos; reference:url,sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26; metadata:author Actioner, created 2026-08-11;)
```

### Suricata: PESpin Packed PE in Transit (CVE-2026-20339)

Detects PESpin-packed PE files in reassembled file content that could trigger CVE-2026-20339 integer overflow. Hunt-grade: flags the file format processed by the vulnerable parser, not exploit intent. Pair with ClamAV crash detection for confirmed exploitation.
**Status:** compile ✅ compiles · confidence: medium · hunt-grade
<!-- audit: suricata -T -S exit 0. Uses file.data sticky buffer for reassembled file inspection. Confidence medium: same as Snort variant — flags PESpin format, not exploit intent specifically. Pair with crash detection. -->
```suricata
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PESpin Packed PE in Transit (CVE-2026-20339)"; flow:established,to_server; file.data; content:"MZ"; depth:2; content:"PE|00 00|"; distance:0; content:"PESpin"; nocase; fast_pattern; classtype:attempted-dos; reference:url,sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26; metadata:author Actioner, created_at 2026-08-11; sid:2200101; rev:1;)
```

### YARA: Malformed ZIP Targeting ClamAV Catalogue Overflow (CVE-2026-20337)

Detects ZIP archives with anomalous central directory entry ratios that may target CVE-2026-20337 heap overflow in ClamAV's ZIP catalogue capacity tracking. Hunt-grade: ratio heuristic may match edge-case legitimate archives; tune threshold for environment.
**Status:** compile ✅ compiles · confidence: low · hunt-grade
<!-- audit: yarac exit 0. Rule keys on ZIP structure: CDFH/LFH ratio anomaly (>3:1 with >100 CDFH). The absolute-count branch (#cdfh > 10000) was removed because legitimate large archives (e.g. Java WARs, node_modules bundles) routinely exceed that count. Without the actual PoC, the ratio threshold is a conservative estimate based on the advisory's description of catalogue capacity tracking overflow. FP: legitimate archives with unusual structure. Tune threshold for environment. -->
```yara
rule Exploit_CVE_2026_20337_ZIP_Catalogue_Overflow
{
    meta:
        description = "Detects malformed ZIP archives with central directory anomalies that may trigger CVE-2026-20337 heap overflow in ClamAV ZIP catalogue capacity tracking"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26"
        severity = "low"

    strings:
        // ZIP local file header signature
        $lfh = { 50 4B 03 04 }
        // ZIP central directory file header signature
        $cdfh = { 50 4B 01 02 }
        // ZIP end of central directory record
        $eocd = { 50 4B 05 06 }

    condition:
        // Must be a ZIP file
        $lfh at 0 and
        $eocd and
        filesize < 50MB and
        // Anomaly: central directory headers significantly outnumber local file headers
        // (indicates potential catalogue capacity manipulation for overflow)
        #cdfh > #lfh * 3 and #cdfh > 100
}
```

### YARA: PESpin Packed PE with Anomalous Sections (CVE-2026-20339)

Detects PESpin-packed PE files with section sizes that could trigger CVE-2026-20339 integer overflow in the ClamAV PESpin unpacker.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0 (with import "pe"). Rule keys on PESpin markers + PE section virtual_size > 0x7FFFFFFF or raw_data_size > filesize — conditions that would trigger integer overflow in buffer size calculation. FP: corrupted PE files, non-malicious PESpin-packed software (rare). PESpin is an uncommon packer in modern legitimate software. -->
```yara
import "pe"

rule Exploit_CVE_2026_20339_PESpin_Anomaly
{
    meta:
        description = "Detects PESpin-packed PE files with anomalous section sizes that may trigger CVE-2026-20339 integer overflow in ClamAV PESpin unpacker"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26"
        severity = "high"

    strings:
        // PESpin signature markers in PE overlay/section
        $pespin1 = "PESpin" ascii nocase
        $pespin2 = { 50 45 53 70 69 6E }
        // Common PESpin stub entry patterns
        $stub1 = { EB 01 ?? 60 E8 00 00 00 00 }
        $stub2 = { 9C 60 E8 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (1 of ($pespin*) or 1 of ($stub*)) and
        // Anomalous section virtual size (very large, potential integer overflow trigger)
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].virtual_size > 0x7FFFFFFF or
            pe.sections[i].raw_data_size > filesize
        )
}
```

## Lessons Learned

1. **Parser complexity is attack surface.** ClamAV's broad format support (ZIP, PE packers, GPT, PDF, Mach-O, XAR) means seven independent parser bugs in a single patch cycle. Organizations using ClamAV should monitor for crashes as a leading indicator of exploitation attempts.

2. **Privileged scanning context amplifies impact.** The differential severity rating (High on Windows vs. Medium on Linux/macOS) highlights that the security context of the scanning process matters. Sandboxing or privilege-reducing the scanning process is a structural defense.

3. **Long-tail vulnerability exposure.** CVE-2026-20339 (PESpin) affects ClamAV from version 0.90, and CVE-2026-20348 (XAR) from 0.98.1. Legacy deployments that have not updated will carry this exposure indefinitely.

4. **Public PoC accelerates risk.** With PoC code available for two ZIP parser vulnerabilities, the window between disclosure and exploitation attempts is compressed. Prioritize patching ClamAV and Cisco Secure Endpoint Connector.

## Sources

- [Cisco Security Advisory cisco-sa-clamav-WuuvVd26](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26) -- primary Cisco PSIRT advisory with all seven CVEs, CVSS scores, affected products, and fixed releases
- [ClamAV Blog: ClamAV 1.5.4 and 1.4.6 Security Patch](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html) -- official ClamAV release notes with per-CVE fix descriptions, affected version ranges, and researcher credits
- [SecurityWeek: Cisco Warns of High-Severity ClamAV Vulnerabilities With Public PoC](https://www.securityweek.com/cisco-warns-of-high-severity-clamav-vulnerabilities-with-public-poc/) -- reporting on PoC availability and severity assessment
- [GitHub Advisory GHSA-rhg3-hwfw-hp7p](https://github.com/advisories/GHSA-rhg3-hwfw-hp7p) -- GitHub Security Advisory for CVE-2026-20337 with EPSS score
- [ClamAV 1.5.4 GitHub Release](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4) -- official release with changelog
- [Linuxiac: ClamAV 1.5.4 Security Analysis](https://linuxiac.com/clamav-1-5-4-open-source-antivirus-fixes-eight-security-vulnerabilities/) -- additional technical context on vulnerability mechanics

---
*Report generated by Actioner*
