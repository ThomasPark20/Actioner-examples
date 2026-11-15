# Technical Analysis Report: Check Point PHP2Shell Exploitation & TSGA Backdoor (2026-11-15)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-11-15
Version: 1.0

## Executive Summary

A multi-stage exploitation campaign is actively targeting Check Point Security Gateways with exposed Mobile Access portals. Attackers exploit the PHP2Shell vulnerability chain (CVE-2026-109618, CVE-2026-109619) for initial access, then escalate to root via CVE-2026-123039 -- a missing-authorization flaw in the Gaia OS DynamicCLI daemon that listens on a world-writable Unix socket. Post-compromise, the attackers deploy the TSGA backdoor (a PhiliKit variant) and TSProxy for persistent encrypted access, followed by internal reconnaissance with the gogo scanner and lateral movement to VMware ESXi hosts via SSH using the `vpxuser` account. In a subset of Israeli victims, the destroy_v6 ELF wiper was deployed, deleting data and dropping a politically themed note named DREAM_ANNEXATION.txt. CISA added CVE-2026-123039 to the KEV catalog on November 13, 2026, with a federal remediation deadline of November 16, 2026.

## Background: Check Point Security Gateways

Check Point Security Gateways are widely deployed network security appliances running the Gaia operating system. The Mobile Access portal provides remote connectivity (VPN, SSL portal) and is commonly Internet-facing. Affected versions include R81, R81.10, R81.20, R82, R82.10, and R82.20. The DynamicCLI daemon, which runs as root, exposes a Unix socket at `/tmp/dynamic_socket` that is world-writable and performs no caller authentication, allowing any local user to execute arbitrary commands as root.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Late October 2026 | Activity from 130.94.19[.]204 begins approximately one week after a security fix became available |
| 2026-10-30 | Wave 1: Targeted attacks against Israeli organizations; some victims suffer destructive wiper deployment |
| 2026-11-02 | Wave 2: Broader, opportunistic exploitation targeting organizations across multiple countries and sectors |
| 2026-11-13 | CISA adds CVE-2026-123039 to the Known Exploited Vulnerabilities catalog |
| 2026-11-16 | Federal remediation deadline per BOD 22-01 / BOD 26-04 |

## Root Cause: PHP2Shell + DynamicCLI Privilege Escalation

Initial access is achieved through the PHP2Shell vulnerability chain (CVE-2026-109618, CVE-2026-109619) targeting the Check Point Mobile Access portal. The attackers exploit PHP session handling to upload webshells, staging them as `.tpl` template files. The PHP session files in `/opt/CPcvpn-R81.20/tmp/` contain the distinctive marker string `upload_progress_pwn`. Once a webshell is established, the attacker escalates from the portal service account to root by sending commands to the world-writable Unix socket `/tmp/dynamic_socket` (CVE-2026-123039, CVSS 7.8, CWE-732/CWE-862).

## Technical Analysis of the Malicious Payload

### 1. Initial Access -- PHP2Shell Webshells

The attackers exploit the Mobile Access portal to upload PHP webshells. Webshells are staged through `/tmp/.up.tpl`, then copied to the portal template directory as `challenge_render.tpl` or files matching the `zz*.tpl` naming pattern. Initial webshells are simple command-execution scripts; upgraded variants require a hardcoded key for authentication and support command execution, PHP code evaluation, and file upload. Repeated Apache/PHP process crashes on targeted gateways are an early behavioral indicator of exploitation attempts.

### 2. TSGA Backdoor and TSProxy

After privilege escalation, the attackers deploy the TSGA backdoor, which self-relocates and runs as `slot_CPconfigdaemon`. TSGA is a Linux gateway implant with Check Point-specific capabilities:

- Encrypted remote access via a passive backdoor
- Configuration theft from the appliance
- Persistence through backup and snapshot injection
- Process injection for stealth
- Binary firewall-log tampering to destroy forensic evidence

TSProxy (`/lib/libcpfwcommon.so`) is injected into selected appliance processes. It hooks networking functions to intercept specially marked attacker connections while passing legitimate traffic through transparently. TSProxy shares credentials, communication secrets, a TLS certificate, and a private key with the PhiliKit component `libdssafe.so`. Communication occurs on TCP port 11072. TSGA creates a Unix socket at `/tmp/.p_sock`.

### 3. C2 Infrastructure

| Type | Value | Context |
|------|-------|---------|
| IP | 130.94.19[.]204 | Primary attack/scanning infrastructure |
| Port | TCP 11072 | PhiliKit/TSProxy communication |
| Hosting | LightNode VPS | VPS infrastructure used for operations |
| Socket | /tmp/.p_sock | TSGA local IPC socket |
| Socket | /tmp/dynamic_socket | DynamicCLI target for privilege escalation |

No domains, full URLs, or C2 beacon patterns were disclosed in public reporting.

### 4. Platform-Specific Behavior

#### Check Point Gaia OS (Linux)
- Initial access: PHP2Shell exploitation of Mobile Access portal
- Privilege escalation: DynamicCLI socket abuse (CVE-2026-123039)
- Persistence: TSGA (`slot_CPconfigdaemon`), TSProxy (`libcpfwcommon.so`), backup/snapshot injection
- Discovery: gogo network scanner for internal asset mapping

#### VMware ESXi
- Lateral movement: SSH using `vpxuser` service account
- Impact: destroy_v6 wiper execution -- recursively traverses directories, overwrites files with zeros, then deletes them; drops DREAM_ANNEXATION.txt note in each processed directory

### 5. Anti-Forensics / Evasion Techniques

- Binary firewall-log tampering by TSGA to erase evidence of attacker activity
- TSProxy hooks networking functions within legitimate appliance processes, blending C2 traffic with normal operations
- Webshell upgrades adding hardcoded-key authentication to prevent third-party access
- Wiper activity potentially used as a smoke screen to destroy forensic evidence
- Scanning activity concentrated in the 00:00--09:00 UTC window

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `130.94.19[.]204`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Gaia OS | slot_CPconfigdaemon | Not disclosed | TSGA backdoor binary (self-relocated) |
| Gaia OS | /tmp/CPconfigdaemon | Not disclosed | TSGA initial launch point |
| Gaia OS | /lib/libcpfwcommon.so | Not disclosed | TSProxy injected library |
| Gaia OS | /tmp/.up.tpl | Not disclosed | Staged webshell upload |
| Gaia OS | challenge_render.tpl | Not disclosed | Webshell in portal template folder |
| Gaia OS | zz*.tpl (portal template dir) | Not disclosed | Webshell naming pattern |
| Gaia OS | /opt/CPcvpn-R81.20/tmp/ (PHP sessions) | Not disclosed | PHP session files with upload_progress_pwn |
| Gaia OS | /tmp/.p_sock | N/A | TSGA Unix socket |
| Gaia OS | /tmp/dynamic_socket | N/A | DynamicCLI daemon socket (CVE-2026-123039) |
| Linux/ESXi | destroy_v6 | Not disclosed | Linux ELF wiper binary |
| Linux/ESXi | DREAM_ANNEXATION.txt | Not disclosed | Wiper note, politically themed (Hebrew) |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 130.94.19[.]204 | Primary scanning and exploitation infrastructure |
| Port | TCP 11072 | PhiliKit/TSProxy communication port |
| Hosting | LightNode VPS | Attack infrastructure hosting provider |

### Behavioral

- Repeated Apache/PHP process crashes on Check Point gateways (exploitation attempts)
- PHP session files containing the string `upload_progress_pwn`
- Creation of `.tpl` files in the Mobile Access portal template directory
- Process named `slot_CPconfigdaemon` running on the appliance
- Outbound connections on TCP port 11072
- SSH sessions from gateway to ESXi using `vpxuser` account
- Activity concentrated between 00:00 and 09:00 UTC (08:00-17:00 China Standard Time)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | PHP2Shell exploitation of Mobile Access portal (CVE-2026-109618, CVE-2026-109619) |
| T1068 | Exploitation for Privilege Escalation | DynamicCLI socket abuse for root access (CVE-2026-123039) |
| T1505.003 | Server Software Component: Web Shell | PHP webshells (zz*.tpl, challenge_render.tpl) in portal template directories |
| T1543 | Create or Modify System Process | TSGA deployed as persistent daemon (slot_CPconfigdaemon) |
| T1055 | Process Injection | TSProxy injected into appliance processes to intercept attacker traffic |
| T1070 | Indicator Removal | Binary firewall-log tampering by TSGA |
| T1046 | Network Service Discovery | gogo scanner deployed for internal network mapping |
| T1021.004 | Remote Services: SSH | Lateral movement to ESXi via vpxuser SSH access |
| T1078 | Valid Accounts | Abuse of vpxuser service account on ESXi |
| T1485 | Data Destruction | destroy_v6 wiper overwrites and deletes files on ESXi |
| T1573 | Encrypted Channel | TSGA and TSProxy encrypted remote access communications |
| T1071.001 | Application Layer Protocol: Web Protocols | Initial exploitation and webshell communication over HTTP/HTTPS |

## Impact Assessment

Check Point reported active exploitation against "a couple of dozen customers." Wave 1 (October 30) specifically targeted Israeli organizations, with some suffering destructive data wiping on VMware ESXi infrastructure. Wave 2 (November 2) expanded opportunistically to organizations across multiple countries and sectors. The combination of root-level gateway compromise, persistent backdoor implantation with backup/snapshot survival, and potential destructive wiper deployment represents a severe impact. The attacker's ability to tamper with firewall logs complicates forensic investigation.

## Detection & Remediation

### Immediate Detection

```bash
# Check for TSGA backdoor artifacts
ls -la /tmp/CPconfigdaemon /tmp/.p_sock 2>/dev/null
ps aux | grep slot_CPconfigdaemon

# Check for exploit staging files
find /opt/CPcvpn-*/tmp/ -name "*.tpl" 2>/dev/null
find / -name "challenge_render.tpl" -o -name ".up.tpl" 2>/dev/null
ls -la /lib/libcpfwcommon.so

# Check for DynamicCLI socket permissions
ls -la /tmp/dynamic_socket

# Check for wiper artifacts
find / -name "DREAM_ANNEXATION.txt" -o -name "destroy_v6" 2>/dev/null

# Check PHP session files for exploit markers
grep -r "upload_progress_pwn" /opt/CPcvpn-*/tmp/ 2>/dev/null

# Check for webshell pattern
find /opt/CPcvpn-*/portal/ -name "zz*.tpl" 2>/dev/null

# Check for suspicious network connections
netstat -tlnp | grep 11072
```

### Remediation

1. **Immediate**: Apply the patch referenced in Check Point advisory SK1000362 for CVE-2026-123039 across all affected versions (R81 through R82.20).
2. **Containment**: Isolate compromised gateways from the network. Block traffic to/from 130.94.19[.]204.
3. **Eradication**: Remove all webshell files (zz*.tpl, challenge_render.tpl, .up.tpl). Remove TSGA artifacts (slot_CPconfigdaemon, /tmp/CPconfigdaemon, /tmp/.p_sock). Verify integrity of /lib/libcpfwcommon.so against known-good copies.
4. **Credential rotation**: Rotate all credentials stored on or accessible from the gateway, including vpxuser on connected ESXi hosts.
5. **Forensic triage**: Per BOD 26-04, forensic triage is required. Review backup and snapshot integrity, as TSGA persists through these mechanisms.

### Long-Term Hardening

- Restrict access to the Mobile Access portal to trusted IP ranges where feasible.
- Monitor for unexpected `.tpl` file creation in portal template directories.
- Implement network segmentation between security gateways and ESXi management interfaces.
- Ensure the DynamicCLI socket is patched to enforce authentication; monitor the /tmp/dynamic_socket permissions.
- Deploy file integrity monitoring on gateway appliances.

## Detection Rules

Six Sigma rules, three Suricata rules, three Snort rules, and three YARA rules cover the key artifacts of this campaign: TSGA backdoor deployment, wiper artifacts, webshell staging, DynamicCLI socket abuse, campaign infrastructure, and network indicators. The primary caveat is that no file hashes were publicly disclosed, so file-based detections rely on path and name patterns rather than cryptographic indicators.

### Sigma Rules

#### 1. TSGA Backdoor Deployment on Check Point Gateway

Detects creation of TSGA backdoor file artifacts including slot_CPconfigdaemon, the PhiliKit socket, and TSProxy library.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check blocked by proxy 403 on MITRE ATT&CK data fetch (environment issue, not rule issue); fields use standard linux file_event schema; values are real (not defanged) per logsource-encoding ref -->

**Compile: pass (sigma convert splunk+logscale) | Confidence: high**

```yaml
title: TSGA Backdoor Deployment on Check Point Gateway
id: 1fec1047-c49c-4519-a70f-fc13e8c8d3df
status: experimental
description: >
    Detects creation of TSGA backdoor artifacts on Check Point Gaia OS appliances,
    including the slot_CPconfigdaemon binary and the PhiliKit Unix socket .p_sock.
    These are associated with the PHP2Shell campaign (CVE-2026-109618, CVE-2026-109619)
    and privilege escalation via CVE-2026-123039.
references:
    - https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html
    - https://securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html
author: Actioner
date: 2026-11-15
tags:
    - attack.t1505.003
    - attack.t1543
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains:
            - 'slot_CPconfigdaemon'
            - '/tmp/CPconfigdaemon'
            - '/tmp/.p_sock'
            - 'libcpfwcommon.so'
    condition: selection
falsepositives:
    - Legitimate Check Point processes creating libcpfwcommon.so during patching
level: high
```

#### 2. destroy_v6 Wiper or DREAM_ANNEXATION Note Detection

Detects the wiper binary or its signature ransom-free note file on Linux/ESXi systems.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; string matches are specific to this campaign's unique filenames -->

**Compile: pass (sigma convert splunk+logscale) | Confidence: high**

```yaml
title: destroy_v6 Wiper or DREAM_ANNEXATION Note Detection
id: 23618ce7-c68d-4a6b-9e25-3aefe0c9e6e3
status: experimental
description: >
    Detects creation of the destroy_v6 Linux ELF wiper binary or the
    DREAM_ANNEXATION.txt note file dropped during destructive operations
    linked to the PHP2Shell Check Point gateway exploitation campaign.
references:
    - https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html
    - https://securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html
author: Actioner
date: 2026-11-15
tags:
    - attack.t1485
    - attack.t1059.004
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains:
            - 'destroy_v6'
            - 'DREAM_ANNEXATION.txt'
    condition: selection
falsepositives:
    - Unlikely in production environments
level: high
```

#### 3. PHP2Shell Webshell Template File on Check Point Gateway

Detects webshell staging files and template patterns used during PHP2Shell exploitation.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; CPcvpn path combined with .tpl extension narrows false positives to Check Point portal context -->

**Compile: pass (sigma convert splunk+logscale) | Confidence: high**

```yaml
title: PHP2Shell Webshell Template File on Check Point Gateway
id: c7f1d866-f878-45e0-acb9-19173e38514f
status: experimental
description: >
    Detects creation of suspicious .tpl files in Check Point Mobile Access portal
    directories matching the zz*.tpl naming pattern or known staging paths used
    during PHP2Shell exploitation (CVE-2026-109618, CVE-2026-109619).
references:
    - https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html
    - https://securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html
author: Actioner
date: 2026-11-15
tags:
    - attack.t1505.003
    - attack.t1190
logsource:
    category: file_event
    product: linux
detection:
    selection_staging:
        TargetFilename|contains:
            - '/tmp/.up.tpl'
            - 'challenge_render.tpl'
    selection_webshell_pattern:
        TargetFilename|endswith: '.tpl'
        TargetFilename|contains: '/CPcvpn'
    condition: selection_staging or selection_webshell_pattern
falsepositives:
    - Legitimate Check Point portal template updates
level: high
```

#### 4. Check Point DynamicCLI Socket Privilege Escalation

Detects interaction with the DynamicCLI Unix socket used for CVE-2026-123039 exploitation. Requires network-level socket monitoring on Linux.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; DestinationHostname for Unix socket monitoring is non-standard in most SIEM pipelines; may require custom field mapping -->

**Compile: pass (sigma convert splunk+logscale) | Confidence: medium**

```yaml
title: Check Point DynamicCLI Socket Privilege Escalation
id: 4a8276c6-32c4-4a82-a53b-ef70640b7565
status: experimental
description: >
    Detects processes interacting with the world-writable /tmp/dynamic_socket
    Unix socket used by the Gaia OS DynamicCLI daemon. Exploitation of
    CVE-2026-123039 sends commands through this socket for root execution.
references:
    - https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html
    - https://securityaffairs.com/203040/hacking/u-s-cisa-adds-check-point-and-unrealircd-flaws-to-its-known-exploited-vulnerabilities-catalog.html
author: Actioner
date: 2026-11-15
tags:
    - attack.t1068
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestinationHostname: '/tmp/dynamic_socket'
    condition: selection
falsepositives:
    - Legitimate Check Point Gaia OS administration processes communicating with DynamicCLI
level: medium
```

#### 5. Network Connection to PHP2Shell Campaign Infrastructure

Detects connections to the confirmed attack IP 130.94.19[.]204.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; single IP IOC rule; value is real (not defanged) per logsource-encoding ref -->

**Compile: pass (sigma convert splunk+logscale) | Confidence: high**

```yaml
title: Network Connection to PHP2Shell Campaign Infrastructure
id: 499d4851-2706-4ba0-a081-c33b2424fea8
status: experimental
description: >
    Detects network connections to IP address 130.94.19.204, the primary
    attack infrastructure used in the PHP2Shell exploitation campaign
    targeting Check Point Security Gateways with Mobile Access portals.
references:
    - https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html
    - https://securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html
author: Actioner
date: 2026-11-15
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '130.94.19.204'
    condition: selection
falsepositives:
    - Unlikely; this IP is confirmed attack infrastructure
level: high
```

#### 6. Gogo Network Scanner Execution on Linux Gateway

Detects execution of the gogo scanner used for internal discovery. Caveat: "gogo" is a generic name; verify in the context of Check Point appliances.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; generic tool name may produce false positives in non-gateway environments -->

**Compile: pass (sigma convert splunk+logscale) | Confidence: medium**

```yaml
title: Gogo Network Scanner Execution on Linux Gateway
id: de4b0d27-5d29-4568-bddd-083b06cd5b10
status: experimental
description: >
    Detects execution of the gogo network scanner, an internal discovery tool
    deployed during the PHP2Shell Check Point gateway exploitation campaign
    for lateral movement preparation.
references:
    - https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html
    - https://securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html
author: Actioner
date: 2026-11-15
tags:
    - attack.t1046
logsource:
    category: process_creation
    product: linux
detection:
    selection_name:
        Image|endswith: '/gogo'
    selection_cmdline:
        CommandLine|contains: 'gogo'
    condition: selection_name or selection_cmdline
falsepositives:
    - Legitimate use of similarly named tools; verify context on Check Point appliances
level: medium
```

### Suricata Rules

#### 7. PHP2Shell Campaign C2 Connection to 130.94.19[.]204

Alerts on any IP traffic to the confirmed attacker IP.

<!-- audit: suricata -T -S exit 0; simple IP match rule; no app-layer dependency -->

**Compile: pass (suricata -T) | Confidence: high**

```
alert ip $HOME_NET any -> 130.94.19.204 any (msg:"Actioner - PHP2Shell Campaign C2 Connection to 130.94.19.204"; flow:to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html; metadata:author Actioner, created_at 2026-11-15; sid:2200001; rev:1;)
```

#### 8. PhiliKit Communication on TCP Port 11072

Alerts on established TCP sessions to port 11072, used by the PhiliKit/TSProxy implant.

<!-- audit: suricata -T -S exit 0; port-based detection; may produce false positives in environments with legitimate services on 11072 -->

**Compile: pass (suricata -T) | Confidence: medium**

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 11072 (msg:"Actioner - PhiliKit Communication on TCP Port 11072"; flow:established,to_server; classtype:trojan-activity; reference:url,securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html; metadata:author Actioner, created_at 2026-11-15; sid:2200002; rev:1;)
```

#### 9. PHP2Shell Upload Progress Marker in HTTP Request

Detects the `upload_progress_pwn` string in HTTP request bodies, a distinctive marker of PHP2Shell exploitation payloads.

<!-- audit: suricata -T -S exit 0; uses http.request_body sticky buffer; string is highly specific to this exploit chain -->

**Compile: pass (suricata -T) | Confidence: high**

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PHP2Shell Upload Progress Marker in HTTP Request"; flow:established,to_server; http.request_body; content:"upload_progress_pwn"; fast_pattern; classtype:web-application-attack; reference:url,securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html; metadata:author Actioner, created_at 2026-11-15; sid:2200003; rev:1;)
```

### Snort Rules

#### 10. PHP2Shell Campaign C2 Connection

<!-- audit: snort not installed; structural check only; rule follows snort-ref.md format with ip protocol, no sticky buffers required -->

**Compile: uncompiled (structural check only) | Confidence: high**

```
alert ip $HOME_NET any -> 130.94.19.204 any (msg:"Actioner - PHP2Shell Campaign C2 Connection to 130.94.19.204"; classtype:trojan-activity; reference:url,thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html; metadata:author Actioner, created 2026-11-15; sid:2100001; rev:1;)
```

#### 11. PhiliKit Communication on TCP Port 11072

<!-- audit: snort not installed; structural check only; uses tcp protocol with flow established, no sticky buffers needed -->

**Compile: uncompiled (structural check only) | Confidence: medium**

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 11072 (msg:"Actioner - PhiliKit Communication on TCP Port 11072"; flow:established, to_server; classtype:trojan-activity; reference:url,securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html; metadata:author Actioner, created 2026-11-15; sid:2100002; rev:1;)
```

#### 12. PHP2Shell Upload Progress Marker in HTTP Request

<!-- audit: snort not installed; structural check only; uses http service with http_client_body sticky buffer per snort-ref.md -->

**Compile: uncompiled (structural check only) | Confidence: high**

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PHP2Shell Upload Progress Marker in HTTP Request"; flow:established, to_server; http_client_body; content:"upload_progress_pwn", fast_pattern; classtype:web-application-attack; reference:url,securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html; metadata:author Actioner, created 2026-11-15; sid:2100003; rev:1;)
```

### YARA Rules

#### 13. TSGA Backdoor Binary Detection

Detects the TSGA backdoor by matching ELF magic bytes combined with distinctive internal strings.

<!-- audit: yarac exit 0; requires 2 of 5 strings plus ELF header; strings are specific to this implant family -->

**Compile: pass (yarac) | Confidence: high**

```yara
rule TSGA_Backdoor_CheckPoint
{
    meta:
        description = "Detects TSGA backdoor deployed on Check Point gateways during PHP2Shell exploitation campaign"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html"
        severity = "high"

    strings:
        $s1 = "slot_CPconfigdaemon" ascii
        $s2 = "/tmp/.p_sock" ascii
        $s3 = "CPconfigdaemon" ascii
        $s4 = "libcpfwcommon.so" ascii
        $s5 = "libdssafe.so" ascii

    condition:
        uint32(0) == 0x464C457F and
        2 of ($s*)
}
```

#### 14. destroy_v6 Wiper Binary Detection

Detects the destroy_v6 ELF wiper by its unique string artifacts.

<!-- audit: yarac exit 0; any-of condition on two campaign-unique strings plus ELF check -->

**Compile: pass (yarac) | Confidence: high**

```yara
rule Destroy_V6_Wiper
{
    meta:
        description = "Detects the destroy_v6 Linux ELF wiper used in the PHP2Shell Check Point campaign for ESXi wiping"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html"
        severity = "critical"

    strings:
        $s1 = "DREAM_ANNEXATION" ascii
        $s2 = "destroy_v6" ascii

    condition:
        uint32(0) == 0x464C457F and
        any of ($s*)
}
```

#### 15. PHP2Shell Webshell Detection

Detects PHP webshells containing the distinctive upload_progress_pwn marker combined with execution functions.

<!-- audit: yarac exit 0; requires campaign-specific marker AND a PHP exec function; reduces false positives versus marker alone -->

**Compile: pass (yarac) | Confidence: high**

```yara
rule PHP2Shell_Webshell_CheckPoint
{
    meta:
        description = "Detects PHP webshells deployed via PHP2Shell exploitation on Check Point Mobile Access portals"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html"
        severity = "high"

    strings:
        $upload_marker = "upload_progress_pwn" ascii
        $tpl_staging = "/tmp/.up.tpl" ascii
        $challenge = "challenge_render.tpl" ascii
        $php_exec1 = "system(" ascii
        $php_exec2 = "passthru(" ascii
        $php_exec3 = "shell_exec(" ascii
        $php_upload = "move_uploaded_file(" ascii

    condition:
        ($upload_marker or $tpl_staging or $challenge) and
        any of ($php_exec*, $php_upload)
}
```

## Lessons Learned

This campaign underscores several critical defensive gaps. First, the DynamicCLI daemon's world-writable socket with no authentication (CVE-2026-123039) is a design-level flaw in a security product -- local privilege escalation on network security appliances is particularly damaging because the appliance is the trust boundary. Second, the attacker's ability to persist through backup and snapshot mechanisms means that standard restore-from-backup remediation may reintroduce the implant. Third, the wiper activity targeting ESXi via lateral movement from the gateway demonstrates why network segmentation between security infrastructure and virtualization management is essential. Finally, the PhiliKit/TSGA implant's integration with Check Point-specific internals (firewall log tampering, configuration theft, process injection into appliance services) represents a sophisticated, appliance-aware threat that generic endpoint detection will miss -- defenders need appliance-specific integrity monitoring.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [The Hacker News - PHP2Shell Exploitation](https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html) -- Primary technical analysis with comprehensive IOCs, timeline, and malware details
- [Security Affairs - Unpatched Check Point Gateways Wiped](https://securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html) -- Additional technical details on file paths, Unix sockets, and webshell patterns
- [Security Affairs - CISA KEV Addition](https://securityaffairs.com/203040/hacking/u-s-cisa-adds-check-point-and-unrealircd-flaws-to-its-known-exploited-vulnerabilities-catalog.html) -- CISA KEV catalog addition details, CVE descriptions, CWE mappings
- [GBHackers - CISA Check Point Zero-Day](https://gbhackers.com/cisa-check-point-zero-day-vulnerability/) -- CISA advisory context (returned empty content)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -- Official KEV entry for CVE-2026-123039 with BOD 26-04 forensic triage requirement
- [Check Point Advisory SK1000362](https://support.checkpoint.com/results/sk/sk1000362) -- Vendor security advisory for CVE-2026-123039

---
*Report generated by Actioner*
