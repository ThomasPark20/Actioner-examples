# Technical Analysis Report: Certighost AD CS Domain Controller Impersonation Exploit (2026-07-26)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-26
Version: 1.0

## Executive Summary

CVE-2026-54121 ("Certighost") is an improper authorization vulnerability (CVSS 8.8) in Active Directory Certificate Services that allows any low-privileged domain user to impersonate a Domain Controller by obtaining a valid DC certificate. The flaw exists in the enrollment chase fallback mechanism of the AD CS Certificate Policy Enterprise module (`certpdef.dll`), where the CA follows a requester-supplied `cdc` (Client DC) attribute over SMB and LDAP without verifying that the target host is an actual Domain Controller. By standing up rogue LDAP and SMB services and supplying forged DC identity data (`objectSid`, `dNSHostName`), an attacker obtains a certificate signed for the target DC, authenticates via PKINIT, and performs DCSync to extract the `krbtgt` secret and all domain credentials. A full proof-of-concept is publicly available. Microsoft patched the vulnerability on July 14, 2026; public disclosure with PoC followed on July 24, 2026. No in-the-wild exploitation has been confirmed as of the disclosure date, but the low barrier to entry (any domain account + network access to CA) makes rapid weaponization likely. All Windows Server versions from 2012 through 2025 with AD CS Enterprise CA role are affected.

## Background: Active Directory Certificate Services Enrollment Chase

Active Directory Certificate Services (AD CS) is the Microsoft PKI implementation that issues and manages digital certificates within an Active Directory environment. The Enterprise CA supports a "client DC chase" fallback mechanism, controlled by the `EDITF_ENABLECHASECLIENTDC` flag, that allows certificate requesters to specify an alternative Domain Controller for identity resolution via the `cdc` enrollment request attribute. When enabled (often a default or commonly configured state), the CA contacts the host specified in the `cdc` attribute over SMB (port 445) and LDAP (port 389) to resolve the requesting principal's directory object. The `rmd` (Remote Machine Domain) attribute identifies which principal to look up. Prior to the July 2026 patch, the CA performed no validation that the host specified in `cdc` was actually a legitimate Domain Controller, creating a path for identity spoofing.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-14 | Researchers H0j3n and Aniq Fakhrul report vulnerability to Microsoft MSRC |
| 2026-05-22 | Microsoft confirms the vulnerability |
| 2026-07-14 | Microsoft releases July 2026 security update patching CVE-2026-54121 |
| 2026-07-24 | Public disclosure with full proof-of-concept exploit released |
| 2026-07-26 | Analysis date; no confirmed in-the-wild exploitation reported |

## Root Cause: Missing Domain Controller Validation in Enrollment Chase

The vulnerability exists in the `CRequestInstance::_LoadPrincipalObject` code path within `certpdef.dll`. When processing a certificate enrollment request, the CA calls `polGetRequestAttribute(policy, L"cdc", &bstrString)` to read the attacker-controlled `cdc` attribute. This value is passed to `_GetDSObject` with `chase = 1` enabled, causing the CA to contact the specified host for LDAP/SMB identity resolution. The CA accepted the response without any verification that the contacted host was a real Domain Controller -- no `SERVER_TRUST_ACCOUNT` flag check, no SID validation, and no DNS hostname verification against Active Directory computer objects.

The vulnerable code path:

```
CRequestInstance::_LoadPrincipalObject reads cdc attribute
  -> polGetRequestAttribute(policy, L"cdc", &bstrString)
  -> _GetDSObject(..., chase = 1, cdc)
  -> CA accepts response without DC verification
```

## Technical Analysis of the Malicious Payload

### 1. Machine Account Creation (Prerequisite)

The attacker leverages the default `ms-DS-MachineAccountQuota` value of 10, which permits any authenticated domain user to create up to 10 computer accounts. The PoC tool creates a machine account with a `GHOST` prefix (e.g., `GHOSTABCDEFGH$`) by default, though this is configurable via the `--computer-name` argument. This account is used to authenticate the rogue services to the CA.

### 2. Rogue LDAP/SMB Service Deployment

The attacker runs `certighost.py` with root/administrator privileges to bind rogue LDAP (port 389) and SMB/LSA (port 445) listeners on the attacker-controlled machine. These services intercept the CA's authentication chase connection and serve forged directory data.

PoC command line:
```
sudo python3 certighost.py -d <domain> -u <user> -p '<password>' --dc-ip <dc-ip>
```

### 3. Certificate Enrollment with Forged Identity

The tool submits a certificate enrollment request to the Enterprise CA using the default `Machine` certificate template, injecting the `cdc` attribute (pointing to the attacker's rogue services) and the `rmd` attribute (identifying the target DC). The CA contacts the attacker's rogue LDAP/SMB services, which respond with the target DC's `objectSid` and `dNSHostName`. The CA, trusting this response, signs a certificate containing the target DC's identity.

### 4. PKINIT Authentication and DCSync

With the forged DC certificate (exported as a `.pfx` file), the attacker performs PKINIT Kerberos authentication to obtain a TGT as the target Domain Controller. Using this DC-level authentication, the attacker executes DCSync (MS-DRSR directory replication) to extract the `krbtgt` hash and all domain account credentials, exported as a `.ccache` Kerberos credential cache file.

### 5. Patched Code Path (July 2026 Update)

The patch adds `CRequestInstance::_ValidateChaseTargetIsDC` behind the `Feature_3185813818` servicing gate in `certpdef.dll`:

- Rejects empty strings, values exceeding 260 characters, IPv4/IPv6 literals
- Blocks LDAP metacharacters: `( ) * [ \ ]`
- Performs a DC verification LDAP query: `(&(objectCategory=computer)(dNSHostName=<target>)(userAccountControl:1.2.840.113556.1.4.803:=8192))` where `8192` = `SERVER_TRUST_ACCOUNT` flag
- Requires exactly one matching computer object
- Adds SID comparison after object resolution to block substitution attacks

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)

### Package / Software Level

| Package / Component | Version | Description |
|---------------------|---------|-------------|
| certighost.py | PoC (July 2026) | Exploit tool for CVE-2026-54121 AD CS DC impersonation |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows Server | `%SystemRoot%\System32\certpdef.dll` | N/A (varies by build) | Vulnerable AD CS Certificate Policy Enterprise module |
| Attacker | `certighost.py` | N/A (source from GitHub) | PoC exploit script |
| Attacker output | `<target_dc>.pfx` | N/A (generated per attack) | Stolen DC certificate with private key |
| Attacker output | `<target_dc>.ccache` | N/A (generated per attack) | Kerberos credential cache from PKINIT auth |

### Network

| Type | Value | Context |
|------|-------|---------|
| Port | TCP/389 (LDAP) | Rogue LDAP listener on attacker machine; CA connects to this |
| Port | TCP/445 (SMB) | Rogue SMB/LSA listener on attacker machine; CA connects to this |
| Protocol | MS-WCCE | Certificate enrollment protocol exploited via cdc/rmd attributes |
| Protocol | MS-DRSR | Directory replication protocol used for DCSync post-exploitation |

### Behavioral

- **Certificate enrollment with `cdc` request attribute**: The Enterprise CA processes a certificate request containing the `cdc` enrollment attribute, directing it to contact a non-DC host for identity resolution. This attribute is rarely used in legitimate operations and is the primary exploit indicator.
- **Machine account creation with GHOST prefix**: The PoC default naming pattern creates computer accounts starting with `GHOST` followed by random characters (configurable).
- **CA outbound SMB/LDAP to non-DC hosts**: The CA server initiates SMB (445) and LDAP (389) connections to a host that is not a registered Domain Controller -- abnormal behavior for certificate enrollment processing.
- **PKINIT authentication for DC accounts from non-DC sources**: A Kerberos TGT request using certificate-based authentication (PreAuthType 16) for a Domain Controller machine account originating from a non-DC IP address.
- **DCSync replication from non-DC IP**: Directory replication (DS-Replication-Get-Changes-All) operations initiated from a host that is not a registered Domain Controller.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1649 | Steal or Forge Authentication Certificates | Obtaining a valid DC certificate by exploiting AD CS enrollment chase to accept forged identity from rogue LDAP/SMB services |
| T1003.006 | OS Credential Dumping: DCSync | Using the stolen DC certificate for PKINIT authentication followed by MS-DRSR directory replication to extract krbtgt and all domain credentials |
| T1136.002 | Create Account: Domain Account | Creating a machine account via ms-DS-MachineAccountQuota to host rogue LDAP/SMB services and authenticate to the CA |
| T1583.004 | Acquire Infrastructure: Server | Deploying rogue LDAP and SMB services on an attacker-controlled host to serve forged DC identity data to the CA during enrollment chase (note: T1557 Adversary-in-the-Middle was considered but the attacker directs the CA to a new endpoint rather than intercepting existing traffic) |

## Impact Assessment

**Severity: Critical.** A single low-privileged domain account with network access to the Enterprise CA is sufficient to fully compromise the entire Active Directory domain. The attack extracts the `krbtgt` hash, enabling Golden Ticket creation and persistent domain-wide access. All Windows Server versions from 2012 through 2025 with the AD CS Enterprise CA role are affected, as are Windows 10 versions 1607 and 1809. The default `ms-DS-MachineAccountQuota` of 10 and the common availability of the `Machine` certificate template mean most enterprise AD deployments meet the prerequisites. The full PoC is public and requires no advanced tooling beyond Python and standard Impacket dependencies.

## Detection & Remediation

### Immediate Detection

**Check if the chase flag is enabled (run on CA server):**
```powershell
certutil -getreg policy\EditFlags
```
If the output includes `EDITF_ENABLECHASECLIENTDC`, the CA is potentially vulnerable (prior to the July 2026 patch).

**Search for suspicious certificate enrollment events:**
```powershell
# Search for Event 4887 with cdc attribute in certificate enrollment
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4887} |
    Where-Object { $_.Message -match 'cdc:' } |
    Select-Object TimeCreated, Message
```

**Search for GHOST-prefixed computer accounts:**
```powershell
Get-ADComputer -Filter 'Name -like "GHOST*"' -Properties Created, WhenCreated |
    Select-Object Name, WhenCreated, DistinguishedName
```

### Remediation

1. **Apply the July 2026 security update immediately** -- this is the definitive fix (patches `certpdef.dll` with `_ValidateChaseTargetIsDC` validation).

2. **Interim mitigation (if patching is delayed):**
   ```powershell
   certutil -setreg policy\EditFlags -EDITF_ENABLECHASECLIENTDC
   Restart-Service CertSvc -Force
   ```
   *Advisory: efficacy depends on whether the flag was previously enabled and whether any legitimate multi-site CA enrollment relies on client DC chase. Test in non-production first.*

3. **Reduce ms-DS-MachineAccountQuota** to 0 to prevent unprivileged users from creating machine accounts (breaks some legitimate workflows -- evaluate impact).

4. **Audit and rotate credentials** if exploitation is suspected: reset `krbtgt` password twice, revoke and reissue all potentially compromised certificates.

### Long-Term Hardening

- Restrict certificate template enrollment permissions to only necessary accounts and groups.
- Implement certificate manager approval for sensitive templates (especially `Machine`).
- Monitor AD CS certificate enrollment events (4886, 4887, 4888) with SIEM alerting.
- Set `ms-DS-MachineAccountQuota` to 0 and manage machine account creation through controlled processes.
- Deploy network segmentation to restrict which hosts can reach the CA's LDAP/SMB ports.
- Consider implementing a Certificate Authority Web Enrollment (CAWE) proxy to mediate enrollment requests.

## Detection Rules

These detections target the Certighost (CVE-2026-54121) exploit chain at three stages: the distinctive `cdc` enrollment attribute abuse, PoC-default machine account creation, and certificate-based PKINIT authentication for DC accounts. The YARA rule detects the PoC tool itself. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: AD CS Certificate Request with CDC Chase Attribute

Detects certificate enrollment events (Event 4887) where the Attributes field contains the `cdc` request attribute, the core mechanism exploited by Certighost.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 errors 0 issues (attacktag excluded - MITRE data unreachable via proxy); splunk convert exit 0; log_scale convert exit 0. Field "Attributes" matches the EventData XML name for the certificate request attributes in Event 4887. The cdc enrollment attribute is extremely rare in legitimate operations, making this a high-fidelity indicator. -->
```yaml
title: AD CS Certificate Request with CDC Chase Attribute - Certighost CVE-2026-54121
id: 8f3c1a7e-5d92-4b6f-a1e3-9c0d2f8b4e71
status: experimental
description: >
    Detects certificate enrollment events where the Attributes field contains the
    cdc (Client DC) request attribute. The Certighost exploit (CVE-2026-54121) abuses
    this attribute to redirect the CA's authentication chase to a rogue LDAP/SMB server,
    enabling domain controller impersonation and subsequent DCSync credential theft.
references:
    - https://thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html
    - https://github.com/aniqfakhrul/CVE-2026-54121
    - https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26
author: Actioner
date: 2026/07/26
tags:
    - attack.t1649
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4887
        Attributes|contains: 'cdc:'
    condition: selection
falsepositives:
    - Legitimate use of the cdc enrollment attribute in multi-site CA deployments (extremely rare)
level: high
```

### Sigma: Computer Account Creation with Certighost Default Naming

Detects creation of computer accounts matching the Certighost PoC default naming convention (GHOST prefix), indicating potential CVE-2026-54121 exploitation.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 errors 0 issues; splunk convert exit 0; log_scale convert exit 0. Confidence medium (not high) because the GHOST prefix is the PoC default but is configurable via --computer-name. Orgs with legitimate "GHOST"-prefixed computer names should tune the filter. -->
```yaml
title: Computer Account Creation with Certighost Default Naming Pattern
id: 2a9e6b1d-4c83-4f5a-b7d2-1e0f3c8a5d96
status: experimental
description: >
    Detects creation of computer accounts matching the Certighost PoC default naming
    convention (GHOST prefix followed by random characters). The Certighost exploit
    (CVE-2026-54121) creates a machine account to host rogue LDAP/SMB services for
    redirecting CA authentication.
references:
    - https://thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html
    - https://github.com/aniqfakhrul/CVE-2026-54121
author: Actioner
date: 2026/07/26
tags:
    - attack.t1136.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4741
        SamAccountName|startswith: 'GHOST'
    condition: selection
falsepositives:
    - Legitimate computer accounts with names beginning with GHOST
level: medium
```

### Sigma: PKINIT Certificate Authentication for Machine Account (TTP Companion)

TTP companion rule: detects Kerberos TGT requests using PKINIT certificate-based authentication (PreAuthType 16) for any machine account, which is the post-exploitation authentication step in the Certighost attack chain. Requires per-environment baseline -- filter known DC IPs and legitimate PKINIT sources before deployment.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check 0 errors 0 issues (NumberAsStringIssue fixed by using integer for PreAuthType); splunk convert exit 0; log_scale convert exit 0. Confidence lowered from medium to low per critic review: condition matches ALL machine accounts (TargetUserName|endswith: '$'), not only DC accounts, making title misleading at the original level. Relabeled as TTP companion. Requires environment-specific tuning to filter legitimate DC PKINIT events and smart card / WHfB auth. Does not filter by source IP (environment-specific). -->
```yaml
title: PKINIT Certificate Authentication for Machine Account - TTP Companion
id: 5d7b3e9a-1f24-4c68-9a3b-6e8d0c2f7a15
status: experimental
description: >
    TTP companion rule: detects Kerberos TGT requests using PKINIT certificate-based
    authentication (PreAuthType 16) for any machine account (trailing $). After exploiting
    CVE-2026-54121, the attacker uses the stolen DC certificate to authenticate
    via PKINIT before performing DCSync. Requires per-environment baseline to filter
    legitimate DC and smart-card PKINIT events.
references:
    - https://thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html
    - https://github.com/aniqfakhrul/CVE-2026-54121
author: Actioner
date: 2026/07/26
tags:
    - attack.t1649
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4768
        PreAuthType: 16
        TargetUserName|endswith: '$'
    condition: selection
falsepositives:
    - Legitimate PKINIT authentication by domain controllers during normal operations
    - Smart card authentication for computer accounts
level: low
```

### YARA: Certighost PoC Exploit Tool

Detects the Certighost PoC exploit tool (`certighost.py`) via distinctive strings including the tool name, CVE identifier, and attack-specific command-line arguments.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac exit 0. Sample test: fired on constructed positive (certighost.py-like script with tool name + cdc/rmd attrs + CLI args), silent on negative (generic certutil script). Positive is constructed from published PoC README strings, not a copy of the actual tool. Strings keyed on: tool name "certighost", CVE ID, enrollment attributes "cdc"/"rmd", CLI args "--dc-ip"/"--computer-name"/"--listener", and chase flag constant. -->
```yara
rule Exploit_Certighost_CVE_2026_54121
{
    meta:
        description = "Detects the Certighost PoC exploit tool (certighost.py) for CVE-2026-54121 AD CS DC impersonation"
        author = "Actioner"
        date = "2026-07-26"
        reference = "https://github.com/aniqfakhrul/CVE-2026-54121"
        severity = "critical"

    strings:
        $tool_name = "certighost" ascii nocase
        $cve = "CVE-2026-54121" ascii
        $attr_cdc = "cdc" ascii fullword
        $attr_rmd = "rmd" ascii fullword
        $arg_dcip = "--dc-ip" ascii
        $arg_compname = "--computer-name" ascii
        $arg_listener = "--listener" ascii
        $ghost_prefix = "GHOST" ascii
        $chase_flag = "EDITF_ENABLECHASECLIENTDC" ascii
        $pkinit = "PKINIT" ascii nocase

    condition:
        filesize < 1MB and
        (
            ($tool_name and $attr_cdc and $attr_rmd) or
            ($cve and 2 of ($arg_dcip, $arg_compname, $arg_listener)) or
            ($tool_name and $ghost_prefix and 1 of ($arg_dcip, $arg_compname, $arg_listener)) or
            ($chase_flag and $tool_name) or
            ($pkinit and $tool_name and $attr_cdc)
        )
}
```

### Snort: N/A

No distinctive network-level signatures suitable for Snort detection. The exploit uses standard AD protocols (LDAP port 389, SMB port 445, Kerberos port 88) with no unique payload signatures distinguishable from legitimate traffic at the network layer. The CA-to-rogue-host connection could theoretically be detected by anomaly-based monitoring (CA connecting to non-DC hosts on 445/389), but this requires environment-specific baseline knowledge not expressible in a portable Snort rule.

### Suricata: N/A

Same rationale as Snort. The exploit traffic uses standard MS-WCCE, LDAP, SMB, and Kerberos protocols without distinctive content patterns. TLS/JA3 fingerprinting is not applicable as the exploit operates over plaintext LDAP and SMB.

## Lessons Learned

CVE-2026-54121 joins a growing class of AD CS abuse techniques (following Certified Pre-Owned/ESC1-ESC11) that exploit the inherent trust relationships in Microsoft's PKI infrastructure. The core lesson is that any enrollment mechanism accepting client-supplied routing or identity hints without validation creates a privilege escalation path. The vulnerability's low barrier to entry (any domain user, default configurations, standard tooling) combined with domain-wide impact (krbtgt extraction) makes it a critical patch-now issue. Organizations should treat AD CS infrastructure with the same security rigor as Domain Controllers themselves, restricting network access, monitoring enrollment events, and minimizing the attack surface by removing unnecessary certificate templates and reducing `ms-DS-MachineAccountQuota`.

<!-- revision: 2026-07-26 critic pass — (1) Sigma Rule 2 level high→medium to match confidence:medium; (2) Sigma Rule 3 relabeled TTP companion, confidence medium→low, level medium→low, added per-environment baseline caveat, fixed misleading title; (3) YARA sample label "fired ✓"→"constructed" (positive was constructed, not the real tool); (4) ATT&CK T1557→T1583.004 (attacker deploys rogue services, does not intercept traffic); (5) report version DRAFT→1.0 -->

## Sources

- [The Hacker News - Certighost Exploit](https://thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html) -- primary reporting on CVE-2026-54121 disclosure, attack chain, and impact
- [CVE-2026-54121 PoC Repository (Aniq Fakhrul)](https://github.com/aniqfakhrul/CVE-2026-54121) -- public proof-of-concept exploit tool with usage documentation
- [H0j3n's Technical Gist](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26) -- detailed technical analysis of the vulnerable and patched code paths in certpdef.dll
- [Microsoft Security Response Center - CVE-2026-54121](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54121) -- official Microsoft advisory and patch information

---
*Report generated by Actioner*
