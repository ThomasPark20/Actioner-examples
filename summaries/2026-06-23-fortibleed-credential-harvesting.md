# Technical Analysis Report: FortiBleed Credential Harvesting Campaign (2026-06-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-23
Version: 1.0

## Executive Summary

The FortiBleed campaign is a large-scale, Russian-attributed credential-harvesting operation that has targeted over 430,000 FortiGate firewall devices across 194 countries since at least February 2026. Using a custom Golang-based tool called "FortigateSniffer" that abuses the legitimate FortiOS `diagnose sniffer packet` command, the threat actors passively capture authentication traffic across 24 protocols -- including Kerberos, RADIUS, NTLM, LDAP, RDP, and MSSQL -- without deploying traditional malware. SOCRadar's analysis confirms 86,644 devices with working compromised credentials, 110+ million credentials harvested across 659 harvest cycles, and 19,000 devices under active sniffing at the time of reporting. The operation uses a five-phase attack chain encompassing reconnaissance, brute-force initial access, passive credential collection, distributed GPU-accelerated hash cracking, and lateral movement. CISA issued warnings on June 18, 2026. Fortinet published its official analysis on June 19, 2026. The campaign remains actively ongoing.

**NOTE:** This report covers the FortiBleed credential-harvesting campaign targeting FortiGate devices. It is distinct from the FortiSandbox exploitation campaign (CVE-2026-39808, CVE-2026-39813, CVE-2026-25089) documented separately in [2026-06-17-fortisandbox-active-exploitation.md](2026-06-17-fortisandbox-active-exploitation.md), although both fall under the broader pattern of Fortinet infrastructure targeting.

## Background: FortiGate Firewalls

FortiGate is Fortinet's flagship next-generation firewall platform, deployed globally as a perimeter security appliance providing firewall, VPN, IPS, and web filtering services. FortiGate devices manage SSL-VPN remote access and administrative interfaces that are frequently exposed to the internet. A critical weakness exploited in this campaign is the legacy SHA-256 password hashing used in FortiOS versions prior to 7.2.11, 7.4.8, and 7.6.1. When upgrading from earlier versions, existing administrator passwords remain stored as SHA-256 hashes until the corresponding administrator successfully logs in and triggers re-hashing with the stronger PBKDF2 algorithm -- creating a window of vulnerability even on patched systems.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-02 (est.) | FortiBleed campaign begins; initial reconnaissance and credential sourcing |
| 2026-03 | AI-automated target identification and password spraying campaign observed against inadequately secured edge devices (precursor campaign) |
| 2026-06-12 | Security researcher Volodymyr Diachenko discovers the FortiBleed operation |
| 2026-06-18 | CISA issues warning to Fortinet customers regarding FortiBleed credential compromise |
| 2026-06-19 | Fortinet publishes official PSIRT blog analysis by Carl Windsor; SOCRadar publishes "Dismantling FortiBleed" whitepaper |
| 2026-06-19 | 86,644 devices confirmed with working compromised credentials; 19,000 under active sniffing |
| 2026-06-23 | Campaign remains actively ongoing with continuous addition of newly compromised devices |

## Root Cause: Credential Reuse, Weak Hygiene, and Passive Network Sniffing

The FortiBleed campaign does not exploit a single zero-day vulnerability. Instead, it leverages a combination of:

1. **Credential reuse** from previous Fortinet incidents (FG-IR-26-060 / CVE-2026-24858, FG-IR-25-647 / CVE-2025-59718, CVE-2025-59719)
2. **Brute-force attacks** using 16 curated wordlists targeting FortiGate admin naming conventions against devices with weak passwords and no MFA
3. **Passive network sniffing** via the legitimate `diagnose sniffer packet` FortiOS diagnostic command, weaponized through the custom FortigateSniffer tool
4. **Legacy SHA-256 hashing** weakness in pre-7.2.11/7.4.8/7.6.1 FortiOS versions enabling offline credential cracking

## Technical Analysis of the Malicious Payload

### 1. Phase 1: Credential Sourcing and Reconnaissance

The campaign begins with internet-wide scanning using **Masscan** for port sweeps, followed by a custom **Shodan_Recon** tool for target identification. A purpose-built **FortiProbe-fast** binary filters responses to identify FortiGate devices specifically. Targets are ranked by organization revenue for prioritization. According to SOCRadar, 59.3 million hosts were scanned during the reconnaissance phase, identifying 437,000+ FortiGate devices with 80,553 selected as primary targets.

### 2. Phase 2: Initial Access via Credential Spraying

Once targets are identified, threat actors employ SSH brute-force attacks using 16 curated wordlists tailored to FortiGate administrator naming conventions. Parallel credential stuffing campaigns target SSL-VPN portals at `/remote/logincheck` and admin portals at `/logincheck`. Credentials from three prior Fortinet authentication bypass vulnerabilities (CVE-2026-24858, CVE-2025-59718, CVE-2025-59719) are also sprayed against the target set.

Compromised credential profile breakdown (per SOCRadar):
- Generic admin accounts: 35%
- Built-in Fortinet system accounts: 28.3%
- Organization-specific accounts: 36.7%

### 3. Phase 3: Core Exploitation -- FortigateSniffer

The centerpiece of the campaign is **FortigateSniffer**, a Golang-based tool that abuses the legitimate FortiOS `diagnose sniffer packet` command to passively capture authentication traffic transiting compromised FortiGate devices. The tool captures credentials across **24 protocols** including:

- Kerberos
- RADIUS
- NTLM
- LDAP
- MSSQL
- RDP
- And 18 additional authentication protocols

Key operational security feature: the sniffer operates exclusively between **07:00-18:00 Moscow Time**, coinciding with business hours when authentication traffic volume is highest and the activity blends with normal operations.

### 4. Phase 4: Credential Cracking

Harvested password hashes are processed through a distributed GPU cracking infrastructure:
- **Hashtopolis** orchestration platform with **Hashcat** engine
- Additional GPU capacity rented through **vast.ai**
- **Telegram bot** provides real-time telemetry to a hardcoded campaign administrator
- The SHA-256 hashing used by legacy FortiOS installations is significantly weaker than PBKDF2, enabling faster cracking

### 5. Phase 5: Lateral Movement and Exfiltration

Cracked credentials enable Active Directory traversal and further network penetration. SOCRadar confirmed that DFS backup data exfiltration from a NATO-aligned defense contractor was triggered within minutes of Kerberos hash cracking -- demonstrating the speed of the automated pipeline from credential harvest to active exploitation.

### 6. C2 Infrastructure

The campaign operates from **Eastern European micro-hosters** using four dedicated subnet blocks for segregated functions:
- C2 aggregation
- Credential validation
- Sniffer deployment
- Proxy rotation

More than **260 operation servers** support the campaign. The offensive testing lab consists of seven **Kali Linux VMs** running under QEMU/KVM with strict IPTables rules and shared tmux access. Campaign operations are coordinated through **CyberStrike** automation.

### 7. Anti-Forensics / Evasion Techniques

- **No traditional malware deployed** -- the FortigateSniffer abuses a legitimate diagnostic command, making detection via traditional AV/EDR ineffective
- **Business-hours-only operation** (07:00-18:00 Moscow Time) to blend with normal traffic
- **Passive sniffing** rather than active man-in-the-middle, reducing network anomaly signatures
- Segregated infrastructure across multiple micro-hosters to resist takedown

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` replacing protocol prefixes
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Suspicious Account Indicators

| Account Name | Context |
|--------------|---------|
| forticloud | Unauthorized admin account identified by Fortinet on compromised devices |
| fortiuser | Unauthorized admin account identified by Fortinet on compromised devices |
| fortinet-support | Unauthorized admin account identified by Fortinet on compromised devices |
| fortinet-tech-support | Unauthorized admin account identified by Fortinet on compromised devices |

### Software / Tool Level

| Tool | Type | Description |
|------|------|-------------|
| FortigateSniffer | Golang binary | Custom tool abusing `diagnose sniffer packet` to capture auth traffic across 24 protocols |
| FortiProbe-fast | Binary | Reconnaissance tool to fingerprint and filter FortiGate devices from scan results |
| Shodan_Recon | Script/tool | Custom Shodan integration for internet-wide FortiGate device discovery |
| Masscan | Scanner | Port sweeping tool used for initial target enumeration (59.3M hosts scanned) |
| Hashtopolis + Hashcat | Cracking infra | Distributed GPU cluster for offline credential cracking |
| CyberStrike | Automation | Campaign orchestration and automation framework |

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| Endpoint | `/remote/logincheck` | FortiGate SSL-VPN login endpoint targeted for credential spraying |
| Endpoint | `/logincheck` | FortiGate admin portal login endpoint targeted for credential spraying |
| FortiOS Command | `diagnose sniffer packet` | Legitimate diagnostic command abused by FortigateSniffer for passive traffic capture |

**Note:** Specific C2 IP addresses, domains, and file hashes (SHA256) for FortigateSniffer are contained in the full [SOCRadar "Dismantling FortiBleed" whitepaper](https://socradar.io/blog/dismantling-fortibleed/) which requires download. Public reporting does not include granular network IOCs at this time.

### Behavioral Indicators

- FortiGate devices executing `diagnose sniffer packet` commands outside scheduled maintenance windows
- Sniffer activity concentrated between 07:00-18:00 Moscow Time (04:00-15:00 UTC)
- Multiple failed login attempts from single source IPs against SSL-VPN or admin portals
- Login activity using the suspicious account names listed above
- Unexpected configuration backup or export operations
- Outbound data transfers from FortiGate devices to unfamiliar Eastern European IP ranges

### Vulnerability Context

| CVE | Description | Relevance |
|-----|-------------|-----------|
| CVE-2026-24858 | FortiCloud SSO login authentication bypass (patched January 2026) | Credentials from exploitation reused in FortiBleed spraying |
| CVE-2025-59718 | Critical authentication bypass (patched December 2025) | Credentials from exploitation reused in FortiBleed spraying |
| CVE-2025-59719 | Critical authentication bypass (patched December 2025) | Credentials from exploitation reused in FortiBleed spraying |
| FG-IR-26-060 | Fortinet incident reference | Credential source for FortiBleed campaign |
| FG-IR-25-647 | Fortinet incident reference | Credential source for FortiBleed campaign |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1595 | Active Scanning | Masscan port sweeps across 59.3M hosts; Shodan_Recon and FortiProbe-fast for FortiGate device fingerprinting |
| T1589.001 | Gather Victim Identity Information: Credentials | Reuse of credentials harvested from prior CVE-2026-24858, CVE-2025-59718, CVE-2025-59719 exploits |
| T1078 | Valid Accounts | Login using compromised legitimate credentials (35% generic admin, 28.3% built-in Fortinet, 36.7% organization-specific) |
| T1078.001 | Valid Accounts: Default Accounts | Exploitation of unrenamed default admin accounts and creation of unauthorized accounts (forticloud, fortiuser, etc.) |
| T1110.001 | Brute Force: Password Guessing | SSH brute-force using 16 curated wordlists targeting FortiGate admin naming conventions |
| T1110.003 | Brute Force: Password Spraying | Credential spraying against SSL-VPN portals and admin interfaces |
| T1040 | Network Sniffing | FortigateSniffer passively captures authentication traffic across 24 protocols via `diagnose sniffer packet` |
| T1557 | Adversary-in-the-Middle | Passive credential interception from network traffic transiting compromised FortiGate devices |
| T1110.002 | Brute Force: Password Cracking | Distributed Hashtopolis/Hashcat GPU cluster with vast.ai capacity for offline hash cracking |
| T1021 | Remote Services | Access via SSL VPN and SSH using compromised credentials |
| T1005 | Data from Local System | Exfiltration of FortiGate device configurations containing credentials |
| T1530 | Data from Cloud Storage Object | Exfiltration of DFS backup data from compromised networks |
| T1071 | Application Layer Protocol | C2 communications through Eastern European micro-hoster infrastructure |

## Impact Assessment

- **Scale:** 430,000+ devices targeted; 86,644 confirmed compromised; 110M+ credentials harvested across 659 pipelines
- **Geographic breadth:** 194 countries affected; top targets: India, United States, Mexico, Colombia, Thailand, Taiwan
- **Sectoral impact:** Telecommunications (5,600+ credential entries), Government (591 entries across 111 domains), Education, IT Services
- **Victim profile:** 66% organizations with fewer than 200 employees; 90% with annual revenue under $100 million
- **Severity:** NATO-aligned defense contractor confirmed compromised with DFS backup exfiltration
- **Stealth:** No traditional malware -- passive sniffing via legitimate diagnostic command evades AV/EDR
- **Credential exposure:** Full device configurations including usernames, plaintext/hashed passwords, device IPs and ports

The data exposed includes not just VPN credentials but full device configurations, enabling attackers to understand network topology, firewall rules, and security posture of victim organizations.

## Detection & Remediation

### Immediate Detection

```bash
# On FortiGate CLI -- check for active sniffer processes
diagnose sys top | grep -i sniffer

# Check for unauthorized admin accounts
config system admin
show | grep -E "forticloud|fortiuser|fortinet-support|fortinet-tech-support"
end

# Check for recent configuration exports
execute log filter category event
execute log display | grep -i "backup\|config download"

# Verify password hashing method (should show PBKDF2, not SHA-256)
# Requires FortiOS 7.2.11+, 7.4.8+, or 7.6.1+
get system status | grep -i version

# Review VPN login logs for brute-force patterns
execute log filter category event
execute log filter field action login
execute log display
```

### Remediation

1. **Terminate all active sessions** -- immediately end all SSL VPN and administrative sessions on FortiGate devices
2. **Reset ALL credentials** -- rotate every VPN and administrative password; treat all existing credentials as compromised
3. **Remove unauthorized accounts** -- delete any accounts matching forticloud, fortiuser, fortinet-support, fortinet-tech-support, or any other unrecognized admin accounts
4. **Enable MFA** -- deploy phishing-resistant multi-factor authentication on all external gateways and admin interfaces
5. **Upgrade FortiOS** -- update to 7.4, 7.6, or 8.0 to enable PBKDF2 password hashing; minimum versions: 7.2.11, 7.4.8, 7.6.1
6. **Force PBKDF2 migration** -- use `set login-lockout-upon-weaker-encryption` to remove legacy SHA-256 password configurations
7. **Audit configurations** -- review firewall rules, VPN settings, and admin accounts for unauthorized changes
8. **Monitor Active Directory** -- treat compromised FortiGate credentials as potential AD compromise; review domain controller logs for lateral movement
9. **Check exposure** -- use [SOCRadar's FortiBleed exposure checker](https://socradar.io/free-tools/fortibleed) to determine if your devices appear in the compromised dataset
10. **Restrict management access** -- limit external management access via local-in policies; remove internet-facing admin interfaces

### Long-Term Hardening

- Enforce strong, unique passwords for all FortiGate admin and VPN accounts; prohibit default and vendor-styled account names
- Implement network segmentation to limit the blast radius of FortiGate compromise
- Enable comprehensive logging on FortiGate devices and forward to SIEM for real-time monitoring
- Subscribe to Fortinet PSIRT advisories and SOCRadar threat feeds for timely patching
- Conduct regular credential audits to identify accounts with legacy SHA-256 hashing
- Implement network traffic analysis for anomalous sniffer-like behavior on FortiGate devices

## Detection Rules

The following rules detect indicators of the FortiBleed campaign at multiple stages: suspicious diagnostic command abuse, unauthorized account usage, brute-force attempts, configuration exfiltration, and network-level credential spraying. Sigma rules target FortiGate event logs; Suricata rules detect network-visible brute-force and suspicious account activity; Snort rules cover credential spraying at the TCP layer; YARA rules identify the FortigateSniffer tooling and related campaign artifacts. No specific C2 IP addresses or file hashes are available in public reporting, so network IOC-based rules are not included -- deploy SOCRadar's full IOC feed when the whitepaper indicators become available.

### Sigma: FortiGate Diagnostic Sniffer Packet Command Abuse

Detects execution of the `diagnose sniffer packet` command on FortiGate devices, which is the core mechanism abused by the FortigateSniffer tool to passively harvest credentials.

Compile status: compiles (sigma check 0 errors, 0 issues; splunk/logscale convert pass) | Confidence: **high**

```yaml
title: FortiGate Diagnostic Sniffer Packet Command Abuse
id: 26b68970-e997-4d60-ae92-933a023a26d2
status: experimental
description: >
    Detects execution of the FortiOS 'diagnose sniffer packet' command which
    is abused by the FortiBleed campaign's FortigateSniffer tool to passively
    capture authentication traffic across 24 protocols including Kerberos,
    RADIUS, NTLM, LDAP, and MSSQL. This command is a legitimate diagnostic
    tool but its use should be monitored, especially when invoked outside
    maintenance windows or by unexpected accounts.
references:
    - https://securityaffairs.com/194004/hacking/fortibleed-the-most-detailed-breakdown-yet-of-an-active-russian-credential-harvesting-operation.html
    - https://thehackernews.com/2026/06/cisa-warns-fortinet-customers-as.html
    - https://socradar.io/blog/dismantling-fortibleed/
author: Actioner
date: 2026-06-23
tags:
    - attack.t1040
    - attack.t1557
logsource:
    product: fortinet
    service: event
detection:
    selection:
        action|contains: 'diagnose sniffer packet'
    condition: selection
falsepositives:
    - Legitimate network diagnostics by authorized FortiGate administrators during scheduled maintenance
    - Automated monitoring scripts that use sniffer diagnostics
level: high
```

<!-- audit: sigma check 0 errors 0 condition-errors 0 issues; splunk convert produces action="*diagnose sniffer packet*"; logscale convert produces action=/diagnose sniffer packet/i; logsource product:fortinet service:event requires Fortinet event log forwarding to SIEM. Field 'action' maps to FortiGate log action field. No defanged values in rule. -->

### Sigma: FortiGate Suspicious Default or Backdoor Admin Account Login

Detects login attempts using unauthorized account names (forticloud, fortiuser, fortinet-support, fortinet-tech-support) identified by Fortinet as indicators of FortiBleed compromise.

Compile status: compiles (sigma check 0 errors, 0 issues; splunk/logscale convert pass) | Confidence: **high**

```yaml
title: FortiGate Suspicious Default or Backdoor Admin Account Login
id: 5184123c-bff0-4244-a967-047bc6f7ac9a
status: experimental
description: >
    Detects login attempts using suspicious administrator account names
    associated with the FortiBleed campaign. Fortinet has identified
    unauthorized accounts such as forticloud, fortiuser, fortinet-support,
    and fortinet-tech-support being used by threat actors for persistent
    access to compromised FortiGate devices.
references:
    - https://www.fortinet.com/blog/psirt-blogs/analysis-of-reported-credential-compromise-of-fortigate-devices
    - https://thehackernews.com/2026/06/cisa-warns-fortinet-customers-as.html
    - https://securityaffairs.com/194004/hacking/fortibleed-the-most-detailed-breakdown-yet-of-an-active-russian-credential-harvesting-operation.html
author: Actioner
date: 2026-06-23
tags:
    - attack.t1078
    - attack.t1078.001
logsource:
    product: fortinet
    service: event
detection:
    selection:
        user:
            - 'forticloud'
            - 'fortiuser'
            - 'fortinet-support'
            - 'fortinet-tech-support'
    condition: selection
falsepositives:
    - Organizations that have legitimately created accounts with these exact names for internal support purposes
level: critical
```

<!-- audit: sigma check 0 errors 0 condition-errors 0 issues; splunk convert produces user IN ("forticloud", "fortiuser", "fortinet-support", "fortinet-tech-support"); logscale convert pass. Account names sourced from Fortinet's official PSIRT blog. -->

### Sigma: FortiGate SSL VPN or Admin Portal Failed Login Attempt

Detects failed login events on FortiGate devices consistent with the credential spraying phase of the FortiBleed campaign; aggregate by source IP in SIEM to identify brute-force patterns.

Compile status: compiles (sigma check 0 errors, 0 issues; splunk convert pass) | Confidence: **medium**

> **Deployment note:** This rule fires on individual failed logins. To detect brute-force patterns, create a SIEM correlation rule that triggers when this alert fires more than 10 times from the same source IP within 60 seconds.

```yaml
title: FortiGate SSL VPN or Admin Portal Failed Login Attempt
id: 0b1eac1d-d9d5-41bc-8a6c-6196a83de550
status: experimental
description: >
    Detects failed login attempts to FortiGate SSL VPN or admin portals,
    consistent with the FortiBleed campaign's credential spraying phase
    using curated wordlists targeting FortiGate admin naming conventions.
    Aggregate multiple hits from the same source IP to identify brute
    force activity.
references:
    - https://securityaffairs.com/194004/hacking/fortibleed-the-most-detailed-breakdown-yet-of-an-active-russian-credential-harvesting-operation.html
    - https://thehackernews.com/2026/06/cisa-warns-fortinet-customers-as.html
    - https://www.fortinet.com/blog/psirt-blogs/analysis-of-reported-credential-compromise-of-fortigate-devices
author: Actioner
date: 2026-06-23
tags:
    - attack.t1110.003
    - attack.t1110.001
logsource:
    product: fortinet
    service: event
detection:
    selection:
        action: 'login'
        status: 'failure'
    condition: selection
falsepositives:
    - Users who have genuinely forgotten their password and make multiple attempts
    - Automated monitoring systems that perform login health checks
level: medium
```

<!-- audit: sigma check 0 errors 0 condition-errors 0 issues; splunk convert produces action="login" status="failure"; original pipe-aggregation syntax removed due to pySigma deprecation. Threshold-based detection should be implemented at SIEM correlation layer. -->

### Sigma: FortiGate Unauthorized Configuration Export or Backup

Detects configuration backup or export operations that may indicate credential exfiltration, as FortiBleed harvested full device configurations containing plaintext and hashed passwords.

Compile status: compiles (sigma check 0 errors, 0 issues; splunk/logscale convert pass) | Confidence: **medium**

```yaml
title: FortiGate Unauthorized Configuration Export or Backup
id: f1e09ed6-7579-4302-ba9b-2b170f73003a
status: experimental
description: >
    Detects FortiGate configuration backup or export operations which may
    indicate an attacker exfiltrating device configurations containing
    credentials. The FortiBleed campaign harvested full device configurations
    including usernames and hashed passwords from compromised FortiGate
    devices.
references:
    - https://socradar.io/free-tools/fortibleed
    - https://thehackernews.com/2026/06/cisa-warns-fortinet-customers-as.html
    - https://www.fortinet.com/blog/psirt-blogs/analysis-of-reported-credential-compromise-of-fortigate-devices
author: Actioner
date: 2026-06-23
tags:
    - attack.t1005
    - attack.t1530
logsource:
    product: fortinet
    service: event
detection:
    selection:
        action|contains:
            - 'backup'
            - 'execute backup'
            - 'sys_conf'
    condition: selection
falsepositives:
    - Scheduled automated configuration backups
    - Legitimate administrator-initiated backups during maintenance windows
level: medium
```

<!-- audit: sigma check 0 errors 0 condition-errors 0 issues; splunk convert produces action IN ("*backup*", "*execute backup*", "*sys_conf*"); logscale convert pass. action field values based on FortiGate event log schema for configuration operations. -->

### Suricata: FortiGate SSL VPN Credential Spraying

Detects high-frequency POST requests to the FortiGate SSL-VPN login endpoint `/remote/logincheck`, consistent with FortiBleed's automated credential spraying infrastructure.

Compile status: compiles (suricata -T pass, 0 warnings) | Confidence: **high**

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - FortiBleed FortiGate SSL VPN Credential Spraying"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/remote/logincheck"; fast_pattern; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-admin; reference:url,socradar.io/blog/dismantling-fortibleed/; reference:url,thehackernews.com/2026/06/cisa-warns-fortinet-customers-as.html; metadata:author Actioner, created_at 2026_06_23, confidence high, deployment Perimeter; sid:2200001; rev:1;)
```

<!-- audit: suricata -T -S pass exit 0; dot-notation http.method and http.uri buffers correct for Suricata 7.x; threshold type both fires once per 60s after 10 hits from same src; /remote/logincheck is the standard FortiGate SSL-VPN login endpoint. -->

### Suricata: FortiGate Admin Portal Brute Force

Detects high-frequency POST requests to the FortiGate admin login endpoint `/logincheck`, targeting the administrative interface credential spraying vector.

Compile status: compiles (suricata -T pass, 0 warnings) | Confidence: **high**

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - FortiBleed FortiGate Admin Portal Brute Force"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/logincheck"; fast_pattern; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-admin; reference:url,socradar.io/blog/dismantling-fortibleed/; reference:url,fortinet.com/blog/psirt-blogs/analysis-of-reported-credential-compromise-of-fortigate-devices; metadata:author Actioner, created_at 2026_06_23, confidence high, deployment Perimeter; sid:2200002; rev:1;)
```

<!-- audit: suricata -T -S pass exit 0; /logincheck is standard FortiGate admin login endpoint distinct from /remote/logincheck (SSL-VPN). Both endpoints are targeted in FortiBleed Phase 2. -->

### Suricata: FortiGate SSH Brute Force Attempt

Detects high-frequency SSH connection attempts to FortiGate management ports, consistent with FortiBleed's SSH brute-force phase using curated wordlists.

Compile status: compiles (suricata -T pass, 0 warnings) | Confidence: **medium**

> **Caveat:** This rule triggers on any SSH brute-force against port 22, not FortiGate-specific. Scope deployment to network segments containing FortiGate management interfaces.

```
alert ssh $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Actioner - FortiBleed FortiGate SSH Brute Force Attempt"; flow:to_server; threshold:type both, track by_src, count 15, seconds 60; classtype:attempted-admin; reference:url,securityaffairs.com/194004/hacking/fortibleed-the-most-detailed-breakdown-yet-of-an-active-russian-credential-harvesting-operation.html; metadata:author Actioner, created_at 2026_06_23, confidence medium, deployment Perimeter; sid:2200003; rev:1;)
```

<!-- audit: suricata -T -S pass exit 0; ssh protocol enables SSH app-layer; threshold 15/60s to reduce FP from legitimate admin SSH. Generic SSH brute-force, not FortiGate-specific at network layer. -->

### Suricata: Suspicious FortiGate Admin Account Login (forticloud)

Detects HTTP POST login attempts using the "forticloud" username, an unauthorized account name identified by Fortinet in compromised FortiBleed devices.

Compile status: compiles (suricata -T pass, 0 warnings) | Confidence: **high**

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - FortiBleed Suspicious FortiGate Admin Account Login Attempt"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/logincheck"; http.request_body; content:"username=forticloud"; fast_pattern; classtype:attempted-admin; reference:url,fortinet.com/blog/psirt-blogs/analysis-of-reported-credential-compromise-of-fortigate-devices; metadata:author Actioner, created_at 2026_06_23, confidence high, deployment Perimeter; sid:2200004; rev:1;)
```

<!-- audit: suricata -T -S pass exit 0; http.request_body inspects POST body; "username=forticloud" matches URL-encoded form field. Additional rules for fortinet-support (sid 2200005) also validated. -->

### Suricata: Suspicious fortinet-support Account Login

Detects HTTP POST login attempts using the "fortinet-support" username, another unauthorized account name associated with FortiBleed compromise.

Compile status: compiles (suricata -T pass, 0 warnings) | Confidence: **high**

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - FortiBleed Suspicious fortinet-support Account Login"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/logincheck"; http.request_body; content:"username=fortinet-support"; fast_pattern; classtype:attempted-admin; reference:url,fortinet.com/blog/psirt-blogs/analysis-of-reported-credential-compromise-of-fortigate-devices; metadata:author Actioner, created_at 2026_06_23, confidence high, deployment Perimeter; sid:2200005; rev:1;)
```

<!-- audit: suricata -T -S pass exit 0; mirrors sid 2200004 logic for different account name. -->

### Snort: FortiGate SSL VPN Credential Spraying

Detects high-frequency POST requests to the FortiGate SSL-VPN login endpoint at the TCP layer for Snort 2.x deployments.

Compile status: compiles (snort -T pass via local.rules inclusion) | Confidence: **high**

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"Actioner - FortiBleed FortiGate SSL VPN Credential Spraying Attempt"; flow:established,to_server; content:"POST"; depth:4; content:"/remote/logincheck"; content:"username="; nocase; detection_filter:track by_src, count 10, seconds 60; classtype:attempted-admin; reference:url,socradar.io/blog/dismantling-fortibleed/; reference:url,thehackernews.com/2026/06/cisa-warns-fortinet-customers-as.html; sid:2100001; rev:1;)
```

<!-- audit: snort 2.9.20 validation pass via local.rules inclusion; tcp protocol with depth:4 for POST match; detection_filter for rate-based alerting; /remote/logincheck is FortiGate SSL-VPN endpoint. -->

### Snort: FortiGate Admin Login Brute Force

Detects high-frequency POST requests to the FortiGate admin portal login endpoint for Snort 2.x deployments.

Compile status: compiles (snort -T pass via local.rules inclusion) | Confidence: **high**

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"Actioner - FortiBleed FortiGate Admin Login Brute Force via HTTPS"; flow:established,to_server; content:"POST"; depth:4; content:"/logincheck"; content:"username="; nocase; detection_filter:track by_src, count 10, seconds 60; classtype:attempted-admin; reference:url,socradar.io/blog/dismantling-fortibleed/; reference:url,fortinet.com/blog/psirt-blogs/analysis-of-reported-credential-compromise-of-fortigate-devices; sid:2100002; rev:1;)
```

<!-- audit: snort 2.9.20 validation pass via local.rules inclusion; mirrors sid 2100001 for admin portal endpoint /logincheck vs /remote/logincheck. -->

### Snort: FortiGate Configuration Exfiltration

Detects potential exfiltration of FortiGate device configurations containing encrypted credential blocks, matching the FortiBleed campaign's configuration harvesting pattern.

Compile status: compiles (snort -T pass via local.rules inclusion) | Confidence: **low**

> **Caveat:** This rule has a high false positive potential as "ENC" and "set password" may appear in legitimate FortiGate management traffic. Deploy only on segments where FortiGate management traffic should not contain large outbound data transfers.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - FortiBleed Potential Credential Exfiltration Large Outbound Data from FortiGate"; flow:established,to_server; dsize:>5000; content:"ENC"; depth:10; content:"set password"; classtype:policy-violation; reference:url,socradar.io/blog/dismantling-fortibleed/; sid:2100003; rev:1;)
```

<!-- audit: snort 2.9.20 validation pass; dsize:>5000 limits to large payloads; "ENC" in first 10 bytes + "set password" matches FortiGate config format with encrypted passwords. Low confidence due to generic pattern. -->

### YARA: FortiBleed FortigateSniffer Tool

Detects the FortigateSniffer Golang binary and related tooling via tool name strings, the abused diagnostic command, and protocol capture indicators.

Compile status: compiles (yarac pass) | Confidence: **medium**

> **Caveat:** Without published file hashes, this rule relies on string-based detection. The tool name "FortigateSniffer" and command string "diagnose sniffer packet" are the strongest indicators; protocol name strings alone are insufficient.

```yara
rule FortiBleed_FortigateSniffer_Tool
{
    meta:
        description = "Detects the FortigateSniffer Golang-based tool used in the FortiBleed campaign to passively capture authentication traffic from compromised FortiGate devices across 24 protocols"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://securityaffairs.com/194004/hacking/fortibleed-the-most-detailed-breakdown-yet-of-an-active-russian-credential-harvesting-operation.html"
        severity = "critical"

    strings:
        $tool1 = "FortigateSniffer" ascii wide nocase
        $tool2 = "fortisniffer" ascii wide nocase
        $cmd1 = "diagnose sniffer packet" ascii wide
        $cmd2 = "diag sniffer packet" ascii wide
        $proto1 = "RADIUS" ascii
        $proto2 = "Kerberos" ascii
        $proto3 = "NTLM" ascii
        $proto4 = "LDAP" ascii
        $proto5 = "MSSQL" ascii
        $proto6 = "RDP" ascii
        $go1 = "go.buildid" ascii
        $go2 = "runtime.main" ascii
        $forti1 = "FortiOS" ascii wide
        $forti2 = "FortiGate" ascii wide
        $forti3 = "fortigate" ascii wide

    condition:
        (any of ($tool*)) or
        (any of ($cmd*) and 3 of ($proto*)) or
        (any of ($go*) and any of ($cmd*) and any of ($forti*))
}
```

<!-- audit: yarac compile pass exit 0; three OR branches: (1) direct tool name match, (2) diagnostic command + 3 protocol names, (3) Go binary + diagnostic command + Fortinet reference. Branch 1 is highest confidence; branches 2-3 may match unrelated Go tools that reference FortiGate diagnostics. No hash available for hash meta field. -->

### YARA: FortiBleed Campaign Wordlist

Detects FortiBleed campaign credential databases and wordlists containing the specific unauthorized account names identified by Fortinet alongside FortiGate context strings.

Compile status: compiles (yarac pass) | Confidence: **medium**

```yara
rule FortiBleed_Campaign_Wordlist
{
    meta:
        description = "Detects FortiBleed campaign wordlists and credential databases used for brute-forcing FortiGate admin accounts with curated naming conventions"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://socradar.io/blog/dismantling-fortibleed/"
        severity = "high"

    strings:
        $h1 = "forticloud" ascii nocase
        $h2 = "fortiuser" ascii nocase
        $h3 = "fortinet-support" ascii nocase
        $h4 = "fortinet-tech-support" ascii nocase
        $p1 = "admin" ascii
        $p2 = "password" ascii nocase
        $ctx1 = "FortiGate" ascii wide nocase
        $ctx2 = "FortiOS" ascii wide nocase
        $ctx3 = "SSL-VPN" ascii wide nocase

    condition:
        filesize < 100MB and
        3 of ($h*) and
        any of ($p*) and
        any of ($ctx*)
}
```

<!-- audit: yarac compile pass exit 0; requires 3 of 4 suspicious account names + password-related string + FortiGate context to reduce FP. filesize < 100MB limits scanning scope. -->

### YARA: FortiBleed Reconnaissance Tool

Detects FortiBleed campaign reconnaissance tools (FortiProbe-fast, Shodan_Recon) used for internet-wide FortiGate device enumeration.

Compile status: compiles (yarac pass) | Confidence: **medium**

```yara
rule FortiBleed_Recon_Tool
{
    meta:
        description = "Detects FortiBleed campaign reconnaissance tools such as FortiProbe-fast and Shodan_Recon used for internet-wide scanning to identify FortiGate devices"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://securityaffairs.com/194004/hacking/fortibleed-the-most-detailed-breakdown-yet-of-an-active-russian-credential-harvesting-operation.html"
        severity = "high"

    strings:
        $tool1 = "FortiProbe" ascii wide nocase
        $tool2 = "Shodan_Recon" ascii wide
        $tool3 = "FortiProbe-fast" ascii wide
        $scan1 = "masscan" ascii nocase
        $forti1 = "FortiGate" ascii wide
        $forti2 = "FortiOS" ascii wide
        $go1 = "go.buildid" ascii
        $go2 = "runtime.main" ascii

    condition:
        (any of ($tool*)) or
        (any of ($go*) and $scan1 and any of ($forti*))
}
```

<!-- audit: yarac compile pass exit 0; tool name strings FortiProbe-fast and Shodan_Recon from SOCRadar/SecurityAffairs reporting. No file hashes available. -->

## Lessons Learned

1. **Perimeter appliances are high-value targets:** FortiGate firewalls sit at the network boundary and process all authentication traffic. Compromising a single device gives access to credentials for every service whose traffic transits that device, making them disproportionately valuable targets compared to individual endpoints.

2. **Legitimate tools as weapons:** The FortigateSniffer tool abuses a built-in diagnostic command (`diagnose sniffer packet`) rather than deploying custom malware. This "living off the land" approach on network appliances is an emerging pattern that evades traditional malware detection entirely.

3. **Password hashing upgrades do not retroactively protect:** FortiOS's upgrade-persistence issue -- where existing SHA-256 hashes persist until the corresponding admin logs in on the new version -- creates a silent vulnerability window. Organizations must force credential rotation post-upgrade, not merely deploy the patch.

4. **Credential hygiene at scale remains poor:** The campaign's success (86,644 confirmed compromises out of 430,000 targets) demonstrates that a significant fraction of internet-facing FortiGate devices use default, weak, or previously-compromised credentials without MFA -- a systemic industry failure.

5. **Small organizations bear disproportionate risk:** With 66% of victims having fewer than 200 employees and 90% under $100M revenue, the FortiBleed campaign confirms that smaller organizations with less mature security programs are systematically exploited as initial access points, potentially enabling supply-chain compromise of their larger partners.

## Sources

- [The Hacker News - CISA Warns Fortinet Customers as FortiBleed Campaign Compromises 86,000+ Devices](https://thehackernews.com/2026/06/cisa-warns-fortinet-customers-as.html) -- detailed attack timeline, credential breakdown, CVE references, remediation guidance, and CISA advisory context
- [Security Affairs - FortiBleed: The Most Detailed Breakdown Yet of an Active Russian Credential-Harvesting Operation](https://securityaffairs.com/194004/hacking/fortibleed-the-most-detailed-breakdown-yet-of-an-active-russian-credential-harvesting-operation.html) -- five-phase attack chain, FortigateSniffer tool details, infrastructure analysis, victim demographics, and attribution
- [SecurityWeek - Fortinet Responds to FortiBleed Campaign](https://www.securityweek.com/fortinet-responds-to-fortibleed-campaign/) -- Fortinet's official response, CVE cross-references, remediation recommendations
- [SOCRadar - Dismantling FortiBleed Whitepaper](https://socradar.io/blog/dismantling-fortibleed/) -- primary technical analysis source; full IOCs and tooling details in downloadable whitepaper
- [SOCRadar - FortiBleed Exposure Checker](https://socradar.io/free-tools/fortibleed) -- free tool to check if devices appear in FortiBleed dataset; campaign metrics (437K+ devices, 750K+ credentials, 105M+ records)
- [Fortinet PSIRT Blog - Analysis of Reported Credential Compromise of FortiGate Devices](https://www.fortinet.com/blog/psirt-blogs/analysis-of-reported-credential-compromise-of-fortigate-devices) -- official Fortinet analysis by Carl Windsor (June 19, 2026); unauthorized account names, PBKDF2 guidance, FG-IR references

---
*Report generated by Actioner*
