# Technical Analysis Report: Certighost (CVE-2026-54121) ADCS Domain Takeover (2026-07-28)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-28
Version: 1.0

## Executive Summary

CVE-2026-54121, dubbed "Certighost," is a high-severity (CVSS 8.8) improper authorization vulnerability in Windows Active Directory Certificate Services (AD CS) that allows any authenticated domain user to impersonate a Domain Controller and achieve full domain compromise. The flaw exploits an enrollment fallback mechanism called a "chase," in which the Certificate Authority (CA) contacts a requester-supplied host for identity data without verifying it is a legitimate Domain Controller. Researchers H0j3n and Aniq Fakhrul reported the vulnerability to Microsoft on May 14, 2026; Microsoft patched it on July 14, 2026, and the researchers publicly released a working proof-of-concept (`certighost.py`) on July 24, 2026.

The attack requires only a standard domain account with no administrative privileges. The attacker creates a machine account, sets up rogue LSA and LDAP services, submits a poisoned certificate request with custom `cdc` and `rmd` attributes, and receives a certificate authenticating them as the targeted Domain Controller. This certificate is then used via PKINIT to obtain a Kerberos TGT, enabling DCSync to extract the `krbtgt` secret and achieve Golden Ticket-level domain persistence. Affected systems span Windows Server 2012 through Server 2025 and Windows 10 versions 1607/1809. No in-the-wild exploitation has been confirmed as of July 28, 2026, but the public PoC significantly lowers the exploitation barrier.

## Background: Active Directory Certificate Services (AD CS)

AD CS provides public key infrastructure (PKI) for Windows domains, issuing certificates used for authentication, encryption, and digital signatures. The service supports cross-domain enrollment scenarios where a CA may need to look up identity information from another domain controller. This "chase" fallback is triggered when the CA cannot resolve the requesting entity's identity from its local directory. The chase process accepts two request attributes: `cdc` (Client Domain Controller), specifying which host to contact, and `rmd` (Remote Machine Descriptor), naming the principal to look up. Prior to the patch, the CA followed the requester-supplied `cdc` address over SMB and LDAP without validating that the destination was an actual Domain Controller.

The default `ms-DS-MachineAccountQuota` setting (10) allows any domain user to create machine accounts, providing the authentication principal needed to launch the attack. The default "Machine" certificate template is accessible to domain computers, completing the attack prerequisites that exist in most enterprise AD deployments.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-14 | H0j3n and Aniq Fakhrul report vulnerability to Microsoft |
| 2026-05-22 | Microsoft confirms the vulnerability |
| 2026-07-14 | Microsoft releases patch in July 2026 Patch Tuesday (CVE-2026-54121) |
| 2026-07-24 | Researchers publicly disclose technical details and release certighost.py PoC |
| 2026-07-28 | No confirmed in-the-wild exploitation; not yet listed in CISA KEV catalog |

## Root Cause: Improper Authorization in AD CS Chase Fallback

The vulnerability (CWE-285: Improper Authorization) exists in the `CRequestInstance::_LoadPrincipalObject` and `CRequestInstance::_GetDSObject` functions within `certpdef.dll`. When processing a certificate enrollment request, the CA calls `polGetRequestAttribute()` to read the `cdc` and `rmd` attributes. If present, the CA initiates a chase by connecting to the `cdc`-specified host via SMB (port 445) and LDAP (port 389) to retrieve the identity object named in `rmd`. The CA accepted the chase target based solely on it responding as a domain principal, without confirming it was a registered Domain Controller in Active Directory.

## Technical Analysis of the Malicious Payload

### 1. Machine Account Creation

The PoC tool creates a computer account (default naming pattern: `GHOSTXXXXXXXXX$`) using SAMR over the existing domain credentials. This leverages the default `ms-DS-MachineAccountQuota` that permits standard users to create up to 10 machine accounts. Alternatively, the `--computer-name` flag allows reuse of an existing controlled machine account.

### 2. Rogue Service Deployment

The tool starts privileged listeners on the attacker host:
- **Port 445 (SMB/LSA)**: A rogue LSA service that intercepts the CA's authentication challenge and relays it to the legitimate Domain Controller via Netlogon to validate the machine account
- **Port 389 (LDAP)**: A rogue LDAP service that returns the target DC's `objectSid` and `dNSHostName` when the CA queries for the identity object

### 3. Poisoned Certificate Request

The tool submits a certificate enrollment request to the Enterprise CA using the Machine certificate template, embedding two custom request attributes:
- `cdc`: Points to the attacker-controlled host IP/hostname
- `rmd`: Contains the target Domain Controller's DNS name

When the CA processes this request and triggers the chase fallback, it contacts the attacker's rogue services, retrieves the spoofed DC identity data, and issues a legitimate certificate containing the target DC's identity.

### 4. PKINIT Authentication and DCSync

With the fraudulent certificate in hand, the tool:
1. Performs PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) to obtain a Kerberos TGT as the target DC
2. Extracts the DC account's NT hash
3. Saves credentials to a `.ccache` file and the certificate to a `.pfx` file
4. The attacker can then use the DC credentials to perform DCSync, extracting the `krbtgt` hash and all domain account secrets

### 5. Tool Details

**Repository**: `hxxps://github[.]com/aniqfakhrul/CVE-2026-54121`
**Research writeup**: `hxxps://gist[.]github[.]com/H0j3n/a5ef2609b5f2944ac2390a191a534c26`

**Usage**:
```
sudo python3 certighost.py -d <domain> -u <username> -p <password> --dc-ip <dc-ip>
```

**Dependencies**: impacket, cryptography, pyasn1, asn1crypto, pycryptodome, dnspython

**Key classes/functions in the tool**: `NLOracle`, `LSASrv`, `RogueLDAP`, `CertServerRequest`, `DirtyDH`, `pkinit_and_hash`, `request_cert`, `build_pkinit_asreq`, `sign_authpack`, `create_computer_samr`, `run_lsa`

**Output files**: `.pfx` (certificate), `.ccache` (Kerberos credential cache)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots

### File System

| Platform | Path / Name | Description |
|----------|-------------|-------------|
| Linux/Windows | `certighost.py` | Main PoC exploit script |
| Any | `*.pfx` | Certificate file generated by the tool containing DC identity |
| Any | `*.ccache` | Kerberos credential cache file generated by the tool |

### Behavioral

- **Computer account creation**: Machine accounts with names matching `GHOST*` pattern created by standard domain users (Event ID 4741)
- **Outbound SMB/LDAP from CA**: Enterprise CA servers making outbound connections on TCP 445 and TCP/UDP 389 to non-Domain-Controller hosts
- **Certificate enrollment anomalies**: Certificate requests via the Machine template containing `cdc` and `rmd` custom attributes (Event ID 4886)
- **Certificate issuance with DC identity**: Certificates issued embedding Domain Controller identity to non-DC machine accounts (Event ID 4887)
- **PKINIT from unexpected source**: Kerberos TGT requests using certificate authentication (pre-auth type 16) for DC machine accounts from non-DC IP addresses (Event ID 4768)
- **DCSync from unusual source**: Directory replication requests from accounts/hosts not in the Domain Controllers OU (Event ID 4662)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1649 | Steal or Forge Authentication Certificates | Attacker obtains fraudulent certificate with DC identity via ADCS chase abuse; PKINIT used with this certificate to obtain DC TGT |
| T1136.002 | Create Account: Domain Account | Machine account created (GHOST* naming) to satisfy CA authentication requirements |
| T1003.006 | OS Credential Dumping: DCSync | DCSync performed using forged DC credentials to extract krbtgt and domain secrets |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Access to krbtgt enables domain-wide Golden Ticket persistence (downstream impact) |

## Impact Assessment

The vulnerability affects virtually every organization running an Enterprise CA on Windows Server 2012 through 2025. The attack requires only standard domain user credentials (no admin rights), has low complexity, and needs no user interaction. A successful exploit grants complete domain compromise, including access to all user credentials, the ability to forge Kerberos tickets, and persistent domain-level access. The public availability of a fully automated PoC tool significantly increases the risk of exploitation by less sophisticated threat actors.

## Detection & Remediation

### Immediate Detection

1. **Audit CA certificate issuance**: Review Event ID 4887 on CA servers for recently issued certificates using the Machine template to unexpected requesters
2. **Check for rogue machine accounts**: Query AD for recently created computer accounts, especially those matching the `GHOST*` pattern:
   ```powershell
   Get-ADComputer -Filter 'Name -like "GHOST*"' -Properties Created,ManagedBy | Select Name,Created,ManagedBy
   ```
3. **Review PKINIT activity**: Search Event ID 4768 for certificate-based TGT requests (PreAuthType 16) for DC accounts from non-DC IP addresses
4. **Check for DCSync indicators**: Review Event ID 4662 for replication GUID access from non-DC accounts

### Remediation

1. **Apply the July 2026 security update** on all CA hosts immediately. Verify the build meets the safe thresholds documented in CVE-2026-54121
2. **Temporary workaround** (if patching is delayed): Disable the chase fallback feature:
   ```
   certutil -setreg policy\EditFlags -EDITF_ENABLECHASECLIENTDC
   Restart-Service CertSvc -Force
   ```
   *Caution: tested only in lab environments; may disrupt legitimate cross-domain certificate enrollment.*
3. **Rotate the krbtgt password** twice (to invalidate all existing tickets) if exploitation is suspected
4. **Review and remediate machine accounts** created during the exposure window
5. **Revoke suspicious certificates** issued through the Machine template during the exposure window

### Long-Term Hardening

1. **Reduce `ms-DS-MachineAccountQuota`** to 0 to prevent standard users from creating machine accounts
2. **Restrict certificate template permissions**: Remove `Authenticated Users` or `Domain Computers` enrollment rights from the Machine template; grant enrollment only to specific security groups
3. **Enable comprehensive certificate auditing**: Configure Certificate Services to log all enrollment, issuance, and denial events (Events 4886, 4887, 4888, 4889)
4. **Monitor CA outbound network connections**: CA servers should not initiate outbound SMB or LDAP to hosts outside the known DC list
5. **Implement certificate enrollment policies**: Require CA manager approval for sensitive certificate templates

## Detection Rules

These rules target the Certighost (CVE-2026-54121) attack chain at multiple stages, from tool-specific artifacts to behavioral indicators of the ADCS chase abuse. The PoC-specific rules (GHOST naming pattern, certighost command line) detect unmodified tool usage at medium confidence but are trivially evaded by renaming or using custom flags; the behavioral PKINIT rule provides complementary TTP-level coverage that requires tuning to each environment's DC inventory. Two initially drafted rules were dropped during review (see notes below).

### Dropped: Certificate Issued via Machine Template

Dropped: bare EventID 4887 with no template filter; fires on every certificate issuance event. Pure noise on any active CA. Removed during review.

### Sigma: Computer Account Created With GHOST Naming Pattern

Detects the default naming convention of the Certighost PoC tool. Note: the PoC's `--computer-name` flag allows any arbitrary name, so this pattern matches only default/unmodified usage.

Compile: PASS (sigma convert exit 0, both Splunk and LogScale) | Confidence: medium

<!-- Audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check blocked by proxy (environment limitation). GHOST prefix is from the PoC tool's default behavior. Trivially evaded via --computer-name flag to specify a custom name; downgraded from high to medium. SamAccountName field is standard in Event 4741 schema. -->

```yaml
title: Computer Account Created With GHOST Naming Pattern
id: 248af25c-f222-4b2f-af55-38e41899473c
status: experimental
description: >
    Detects creation of computer accounts whose SAM account name starts with
    GHOST, matching the default naming convention used by the Certighost PoC
    tool (CVE-2026-54121) which creates accounts named GHOSTXXXXXXXXX$.
references:
    - https://github.com/aniqfakhrul/CVE-2026-54121
    - https://hackread.com/microsoft-certighost-flaw-domain-controller-impersonation/
    - https://nvd.nist.gov/vuln/detail/CVE-2026-54121
author: Actioner
date: 2026-07-28
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

### Sigma: Certighost PoC Tool Execution

Detects command-line execution of the certighost.py exploit tool. Trivially evaded by renaming the script file.

Compile: PASS (sigma convert exit 0, both Splunk and LogScale) | Confidence: medium

<!-- Audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check blocked by proxy (environment limitation). Detects unmodified tool use only; trivially evaded by renaming the script. Downgraded from high to medium. CommandLine field requires process command-line audit policy enabled (Windows Security 4688 or Sysmon EID 1). -->

```yaml
title: Certighost PoC Tool Execution via Command Line
id: 32c19fc9-c788-4be7-a3d8-a044ad3937d2
status: experimental
description: >
    Detects execution of the Certighost proof-of-concept exploit tool
    (certighost.py) for CVE-2026-54121 via command-line arguments. The tool
    exploits ADCS chase fallback to impersonate domain controllers.
references:
    - https://github.com/aniqfakhrul/CVE-2026-54121
    - https://nvd.nist.gov/vuln/detail/CVE-2026-54121
author: Actioner
date: 2026-07-28
tags:
    - attack.t1649
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'certighost'
    condition: selection
falsepositives:
    - Authorized penetration testing using the Certighost tool
level: medium
```

### Sigma: PKINIT Certificate-Based TGT Request for Machine Account (Complementary TTP-Level Rule)

Complementary TTP-level rule detecting certificate-based Kerberos authentication for machine accounts. This covers the post-exploitation authentication step in the Certighost attack chain but is not specific to Certighost; it fires on any PKINIT machine account authentication.

Compile: PASS (sigma convert exit 0, both Splunk and LogScale) | Confidence: medium

<!-- Audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check blocked by proxy (environment limitation). PreAuthType 16 = PKINIT (certificate-based). The filter excludes localhost; environments should add known DC IPs to the filter to reduce noise. This is a behavioral/TTP rule and will fire on legitimate smart card or certificate-based machine authentication. -->

```yaml
title: PKINIT Certificate-Based TGT Request for Machine Account
id: 468ed524-c91c-4862-b368-7f3c4bca2339
status: experimental
description: >
    Detects Kerberos TGT requests (Event ID 4768) using certificate-based
    authentication (PKINIT, pre-auth type 16) for machine accounts. In the
    Certighost attack chain (CVE-2026-54121), the attacker uses a fraudulently
    obtained DC certificate to authenticate via PKINIT and obtain a TGT for
    the target domain controller account.
references:
    - https://hackread.com/microsoft-certighost-flaw-domain-controller-impersonation/
    - https://nvd.nist.gov/vuln/detail/CVE-2026-54121
    - https://github.com/aniqfakhrul/CVE-2026-54121
author: Actioner
date: 2026-07-28
tags:
    - attack.t1649
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4768
        PreAuthType: '16'
        TargetUserName|endswith: '$'
    filter_localhost:
        IpAddress:
            - '::1'
            - '127.0.0.1'
    condition: selection and not filter_localhost
falsepositives:
    - Legitimate PKINIT authentication by domain controllers
    - Smart card or certificate-based authentication for machine accounts
level: medium
```

### Dropped: Directory Replication Request (DCSync)

Dropped: logically cannot detect Certighost because the rule filters out machine accounts (SubjectUserName ending with $), but Certighost authenticates as the DC machine account. The rule would suppress the exact traffic it was meant to catch. Removed during review.

### YARA: Certighost PoC Exploit Tool

Detects the certighost.py exploit file via class names, function names, and OIDs unique to the tool.

Compile: PASS (yarac exit 0) | Confidence: high

<!-- Audit: yarac /tmp/actioner/certighost-tool.yar /dev/null exit 0. Strings derived from PoC repository analysis: NLOracle, LSASrv, RogueLDAP, CertServerRequest, DirtyDH are class names; pkinit_and_hash, request_cert, build_pkinit_asreq, sign_authpack, create_computer_samr, run_lsa are function names; OIDs are PKINIT and certificate-related. Condition requires 3+ class matches OR functional+OID combo OR tool name + supporting evidence. Trivially evaded by renaming/obfuscating the script. -->

```yara
rule Exploit_CVE_2026_54121_Certighost_Tool
{
    meta:
        description = "Detects the Certighost PoC exploit tool (certighost.py) for CVE-2026-54121 targeting AD CS chase enrollment"
        author = "Actioner"
        date = "2026-07-28"
        reference = "https://github.com/aniqfakhrul/CVE-2026-54121"
        severity = "critical"

    strings:
        $class1 = "NLOracle" ascii
        $class2 = "LSASrv" ascii
        $class3 = "RogueLDAP" ascii
        $class4 = "CertServerRequest" ascii
        $class5 = "DirtyDH" ascii

        $func1 = "pkinit_and_hash" ascii
        $func2 = "request_cert" ascii
        $func3 = "build_pkinit_asreq" ascii
        $func4 = "sign_authpack" ascii
        $func5 = "create_computer_samr" ascii
        $func6 = "run_lsa" ascii

        $oid1 = "1.3.6.1.5.2.3.1" ascii
        $oid2 = "91ae6020-9e3c-11cf-8d7c-00aa00c091be" ascii

        $str1 = "certighost" ascii nocase
        $str2 = "EDITF_ENABLECHASECLIENTDC" ascii
        $str3 = "ms-DS-MachineAccountQuota" ascii

    condition:
        filesize < 500KB and
        (
            3 of ($class*) or
            (2 of ($func*) and 1 of ($oid*)) or
            ($str1 and 2 of ($class*, $func*, $oid*)) or
            all of ($str*)
        )
}
```

## Lessons Learned

1. **Default AD configurations are dangerous**: The combination of default `ms-DS-MachineAccountQuota` (10), default Machine template ACLs, and the chase fallback feature created a pre-existing attack surface in most enterprise environments. Organizations should audit and restrict these defaults.

2. **ADCS remains a high-value attack surface**: Following ESC1-ESC14 and PetitPotam, Certighost demonstrates that AD CS continues to harbor exploitable authorization flaws. Security teams should treat CA servers as Tier 0 assets with the same protections as domain controllers.

3. **Patching speed is critical**: With only 10 days between patch release and public PoC availability, the window for safe patching was extremely narrow. Organizations need processes to prioritize and deploy critical AD infrastructure patches within days, not weeks.

4. **Multi-stage detection is essential**: No single event reliably detects Certighost exploitation. Effective detection requires correlating certificate enrollment events (4886/4887), machine account creation (4741), PKINIT authentication (4768), and DCSync activity (4662) to identify the complete attack chain.

## Sources

- [Hackread - Microsoft Certighost Flaw Domain Controller Impersonation](https://hackread.com/microsoft-certighost-flaw-domain-controller-impersonation/) -- primary technical coverage with attack chain details, detection events, and remediation steps
- [NVD - CVE-2026-54121](https://nvd.nist.gov/vuln/detail/CVE-2026-54121) -- official CVE entry with CVSS 8.8 score, CWE-285, and affected product version thresholds
- [Certighost PoC Repository (aniqfakhrul)](https://github.com/aniqfakhrul/CVE-2026-54121) -- original PoC exploit code with usage instructions and dependencies
- [H0j3n Technical Writeup (GitHub Gist)](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26) -- original researcher's detailed technical analysis of the vulnerability mechanism
- [BleepingComputer - New Certighost PoC Exploit](https://www.bleepingcomputer.com/news/security/new-certighost-poc-exploit-lets-attackers-hijack-windows-domains/) -- news coverage with timeline and impact assessment (403 at fetch time; details corroborated by other sources)
- [Help Net Security - PoC Exploit Released for CVE-2026-54121](https://www.helpnetsecurity.com/2026/07/27/certighost-cve-2026-54121-poc-exploit-released/) -- additional technical coverage with detection event IDs and Microsoft Defender alert names
- [The Hacker News - Certighost Exploit](https://thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html) -- coverage including patch validation function details and detection methodology
- [Field Effect - Public Exploit Enables Domain Controller Impersonation](https://fieldeffect.com/blog/public-exploit-enables-domain-controller-impersonation) -- CVSS analysis and remediation guidance
- [Microsoft Security Response Center - CVE-2026-54121](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54121) -- official Microsoft advisory (dynamic content not fully fetchable)

---
*Report generated by Actioner*

<!-- revision: 2026-07-28 REVISE pass. CUT Certificate Issued via Machine Template (bare EventID 4887 noise). CUT DCSync rule (filters out machine accounts, logically misses Certighost). Downgraded GHOST naming and PoC execution rules from high to medium confidence. Relabeled PKINIT as complementary TTP-level rule. Replaced T1550.003 (Pass the Ticket) with T1649 (Steal or Forge Authentication Certificates) for cert-based auth step. Defanged PoC repository URLs. Fixed intro paragraph consistency. Promoted version from DRAFT to 1.0. -->
