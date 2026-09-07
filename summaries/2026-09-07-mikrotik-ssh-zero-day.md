# Technical Analysis Report: MikroTik RouterOS SSH Zero-Day "MikroTrick" Chain (2026-09-07)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-07
Version: DRAFT

## Executive Summary

Six vulnerabilities in MikroTik RouterOS, disclosed by CERT Polska on September 5, 2026, include two critical SSH flaws (CVE-2026-67276 and CVE-2026-86060, both CVSS 9.2) that chain into unauthenticated full administrative takeover of any RouterOS device with SSH exposed to the internet. Dubbed "MikroTrick," this chain has been actively exploited as a zero-day since at least September 2, 2026 -- one day before MikroTik silently released patches. Attackers forge SSH authentication by exploiting an incomplete RSA public key comparison (exponent omitted), then escalate privileges via an argument-handling flaw triggered by the crafted username "-2." Post-exploitation activity includes creation of a backdoor account named "ops," SSH key injection, firewall rule manipulation, SOCKS proxy enablement, and packet-sniffing configuration. Two attacker IPs (82.192.72[.]4 and 103.102.31[.]18) and three staging scripts with known SHA-256 hashes have been identified. MikroTik issued patches in versions 6.49.21, 7.23.4, 7.24.2, and 7.25beta3; however, many routers run for years without updates, leaving a large attack surface.

## Background: MikroTik RouterOS

MikroTik RouterOS is the operating system powering MikroTik's widely deployed line of network routers and switches. It is used globally by ISPs, enterprises, and home users, with an estimated millions of devices deployed. RouterOS exposes multiple management services (SSH, WebFig, Winbox, API) that, when internet-facing, become attack surfaces. SSH (port 22) is commonly left exposed for remote administration. The platform's popularity, combined with historically infrequent patching by operators, makes it a high-value target for threat actors seeking network-level persistence, traffic interception, and botnet recruitment.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-02 | Active exploitation of CVE-2026-67276 + CVE-2026-86060 begins (zero-day); earliest confirmed compromise via SSH user "-2" |
| 2026-09-03 | MikroTik silently releases patched versions 7.25beta3, 7.24.2, 7.23.4, 6.49.21 with no vulnerability details |
| 2026-09-04 | Security researcher Nick Pratley publishes binary diffs and working PoC exploit code, demonstrating RSA signature forgery with exponent=1; version 7.23.5 released |
| 2026-09-05 | CERT Polska publishes coordinated disclosure of six RouterOS CVEs; Costin Raiu publishes technical breakdown on Medium; NVD records published at 20:17 UTC |
| 2026-09-05 | MikroTik issues unprecedented push notification via official mobile app warning users to update |
| 2026-09-06 | Widespread news coverage (The Hacker News, SecurityAffairs) |

## Root Cause: SSH Authentication Bypass + Privilege Escalation Chain

The MikroTrick attack chain exploits two distinct vulnerabilities in sequence:

**CVE-2026-67276 (CWE-347, CVSS 9.2) -- SSH Authentication Bypass:** RouterOS does not compare the complete RSA public key when matching an SSH authentication request to an authorized user key. It checks the key type and modulus but omits the exponent. Because signature verification uses the client-supplied key, an attacker who knows an authorized RSA modulus can supply a key with exponent=1, forge a valid signature, and open an SSH command channel as the target user without possessing the private key.

**CVE-2026-86060 (CWE-88, CVSS 9.2) -- SSH Session Privilege Escalation:** RouterOS contains an argument-handling flaw in the SSH login path involving usernames that begin with a prohibited character (specifically "-"). This allows the trusted RouterOS policy mask to be changed, enabling privilege escalation from the authenticated session to full administrative control. The username "-2" is the specific crafted value observed in the wild.

**Prerequisites:** The attacker needs (1) network access to an SSH service on the target device, and (2) knowledge of a valid authorized RSA modulus. Default RouterOS configurations may expose SSH to the internet. The modulus may be obtainable through other means, including CVE-2026-67281 (unauthenticated file read via WebFig).

## Technical Analysis of the Malicious Payload

### 1. Initial Access -- SSH Authentication Forgery (CVE-2026-67276)

The attacker connects to the target RouterOS SSH service and supplies a crafted RSA public key with the correct modulus (matching an authorized key) but with exponent set to 1. Because RouterOS only checks the key type and modulus during key matching, it accepts this key as authorized. Signature verification then uses the attacker's supplied key (with e=1), allowing trivial signature forgery. This grants an authenticated SSH session as the matched user.

### 2. Privilege Escalation -- Username "-2" (CVE-2026-86060)

After gaining an authenticated session, the attacker exploits the argument-handling flaw by using the username "-2" (beginning with the prohibited "-" character). This triggers a policy mask manipulation in the SSH login path, escalating the session to full administrative privileges regardless of the original user's permission level. The "-2" username appears in RouterOS logs as `ssh:-2@<attacker_IP>` and is the primary forensic indicator.

### 3. Post-Exploitation Actions

Once full admin access is achieved, attackers perform the following observed actions:

- **Backdoor account creation:** A privileged user account named "ops" is created for persistent access
- **SSH key injection:** Unauthorized SSH public keys are imported via `/user ssh-keys import` for key-based persistence
- **Firewall rule modification:** Attacker-injected rules to permit traffic and blend malicious flows
- **SOCKS proxy enablement:** Router converted to a traffic relay via `/ip socks` configuration
- **Scheduler persistence:** Scheduled scripts that re-fetch payloads from attacker infrastructure using `fetch` commands
- **Packet sniffing:** Traffic interception configured on the compromised router
- **DNS modification:** DNS settings altered for potential traffic redirection
- **Log clearing:** Device logs may be wiped to remove forensic evidence

### 4. Attacker Infrastructure and Tooling

The attacker infrastructure serves three Python/shell scripts and a BusyBox binary:

- **ftpsrv.py** -- Staging/serving script
- **launch.sh** -- Exploitation launch script
- **serve.py** -- Payload serving script
- **BusyBox binary** -- MIPS architecture, 2010 build, matches BusyBox 1.16.1 official precompiled binary

All three scripts had zero VirusTotal detections at time of analysis. The tools are served from 82.192.72[.]4 (Leaseweb infrastructure).

### 5. Additional Vulnerabilities in the Same Disclosure

CERT Polska disclosed four additional RouterOS vulnerabilities alongside the MikroTrick chain:

| CVE | CVSS | Type | Description |
|-----|------|------|-------------|
| CVE-2026-67277 | 8.8 | CWE-306 | Pre-auth btest connection accepted; uninitialized buffer disclosure + integer underflow can restart kernel |
| CVE-2026-67278 | 6.3 | CWE-347 | Malformed RSA/PKCS#1 v1.5 X.509 signature acceptance enables TLS/IKEv2 impersonation |
| CVE-2026-67279 | 6.9 | CWE-841 | SSH enters connection protocol after client rekey without authentication |
| CVE-2026-67281 | 8.7 | CWE-824 | WebFig `/jsproxy` unauthenticated directory traversal reads root filesystem |

CVE-2026-67278 affects outbound TLS and IKEv2 connections regardless of inbound SSH exposure, representing a distinct compromise vector. CVE-2026-67281 may provide the RSA modulus needed for CVE-2026-67276 exploitation.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `82.192.72[.]4`)

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|----------------|---------------|-------------|
| RouterOS (MIPS) | ftpsrv.py | 6e95f70fdbabb57881b3f5b2c8465d4b17ba901100704efb1278bb3386e6729d | Staging/serving script (0 VT detections) |
| RouterOS (MIPS) | launch.sh | 972b474b896f9fac3cd6b5b8476b410b8f39fbedee8a3b0c745d6e3b328d7dcd | Exploitation launch script (0 VT detections) |
| RouterOS (MIPS) | serve.py | 6dca83338d60467b65b7789d4d59754e40a7aaa36f40ea2da57538367ac9b89e | Payload serving script (0 VT detections) |
| RouterOS (MIPS) | BusyBox | N/A | BusyBox 1.16.1 precompiled binary (MIPS, 2010 build) |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 82.192.72[.]4 | Leaseweb; primary attacker IP, payload distribution |
| IP | 103.102.31[.]18 | Secondary attacker IP, exploitation attempts |

### Behavioral

- **SSH login with username "-2"**: Log entries formatted as `ssh:-2@<IP>` followed by configuration actions; the defining indicator of MikroTrick exploitation
- **"ops" account creation**: Privileged backdoor user account created post-exploitation
- **SSH key injection**: Unauthorized keys added via `/user ssh-keys import`
- **Scheduler entries**: Scripts containing `fetch`, `http://`, or `https://` references that re-fetch payloads
- **SOCKS proxy activation**: `/ip socks` enabled for traffic relay
- **Firewall rule changes**: Attacker-injected NAT/filter rules
- **Packet sniffer configuration**: Traffic interception settings added
- **Log absence**: Cleared logs are themselves an indicator; absence of "-2" does not confirm safety

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of internet-exposed SSH service via CVE-2026-67276 |
| T1078 | Valid Accounts | Forged SSH authentication using manipulated RSA key (exponent=1) |
| T1068 | Exploitation for Privilege Escalation | CVE-2026-86060 username argument-handling flaw escalates to full admin |
| T1136.001 | Create Account: Local Account | Backdoor account "ops" created post-exploitation |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Unauthorized SSH public keys injected for persistence |
| T1053 | Scheduled Task/Job | Scheduler entries with fetch commands for payload persistence |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | Firewall rules modified to permit attacker traffic |
| T1090 | Proxy | SOCKS proxy enabled to relay traffic through compromised router |
| T1040 | Network Sniffing | Packet sniffer configured on compromised router |
| T1070 | Indicator Removal | Device logs cleared to remove forensic evidence |

## Impact Assessment

**Breadth:** MikroTik claims millions of deployed devices worldwide. Any RouterOS device with SSH exposed to the internet and running an unpatched version (6.x < 6.49.21, 7.x < 7.23.4, 7.24.x < 7.24.2) is vulnerable. Many MikroTik routers operate for years without updates.

**Depth:** Full administrative compromise of the network device. Attackers gain the ability to intercept, redirect, and manipulate all traffic flowing through the router, create persistent backdoor access, and use the router as a pivot point or proxy for further attacks.

**Stealth:** The attack leaves minimal traces. The "-2" username in logs is the primary forensic artifact, but attackers may clear logs. Exploitation was occurring as a zero-day for at least 24 hours before patches were available, and working PoC code was published the day after patches dropped.

## Detection & Remediation

### Immediate Detection

Run these commands directly on RouterOS devices to check for compromise:

```
# Check for rogue users (look for dash-prefixed names like "-2", and "ops")
/user print detail

# Check for unauthorized SSH keys
/user ssh-keys print detail

# Check for suspicious scheduled tasks and scripts
/system scheduler print detail
/system script print detail

# Audit firewall and proxy settings
/ip firewall filter print
/ip firewall nat print
/ip proxy print
/ip socks print

# Review device logs for "-2" entries
/log print

# Check device-mode flagged status (post-update indicator)
/system/device-mode/print
```

### Remediation

1. **Preserve evidence** before any changes: `/export show-sensitive` and state dumps
2. **Remove malicious accounts**: `/user remove [find name="-2"]` and `/user remove [find name="ops"]` (use ID-based removal if name-based commands fail due to dash parsing)
3. **Delete unauthorized SSH keys, scheduler entries, and suspicious scripts**
4. **Update RouterOS** to patched versions: 6.49.21, 7.23.4/7.23.5, or 7.24.2+
5. **Rotate all credentials**: account passwords, SSH keypairs, RADIUS/TACACS+ secrets, VPN credentials, API tokens
6. **Restrict management access** (advisory -- efficacy depends on deployment configuration):
   ```
   /ip service set ssh address=<management_subnet>/32
   /ip service disable telnet,ftp,www,api,api-ssl
   ```
7. **Enable remote syslog** for SIEM visibility:
   ```
   /system logging action add target=remote remote=<siem_ip>
   ```
8. **Hunt downstream systems** for unauthorized sessions through the compromised router
9. **Factory reset and rebuild from trusted backup** if dwell time is confirmed or cannot be ruled out

### Long-Term Hardening

- Never expose RouterOS management services (SSH, WebFig, Winbox, API) to the internet without IP allowlisting
- Implement automated firmware update monitoring for MikroTik devices
- Forward RouterOS syslog to SIEM for continuous monitoring
- Deploy network-level detection (Snort/Suricata) at perimeter to flag known attacker infrastructure
- Audit all MikroTik devices for default credentials and unnecessary services

## Detection Rules

These detections target the MikroTrick exploitation chain at two layers: host/syslog (Sigma rules keying on the distinctive "-2" username and "ops" backdoor account) and network (Snort/Suricata rules matching inbound SSH from confirmed attacker IPs). All rules are PoC/advisory-specific (default altitude); compiles does not equal fires -- verify in your environment's log pipeline.

### Sigma: MikroTik MikroTrick SSH Username "-2" in Syslog

Detects the SSH username "-2" forensic indicator in forwarded syslog, the hallmark of CVE-2026-86060 exploitation in the MikroTrick chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (with -x attacktag; MITRE data fetch blocked by proxy, not a rule issue). splunk convert 0; log_scale convert 0. Keywords fieldless match: portable across SIEM ingestion schemas. The "-2" username is highly distinctive — not a legitimate RouterOS or Unix username. -->
```yaml
title: MikroTik MikroTrick Exploitation - SSH Username "-2" in Syslog
id: c7e3a1d4-8f2b-4e6a-9c1d-5b3f7a0e2d84
status: experimental
description: >
    Detects the SSH username "-2" indicator in forwarded syslog, the forensic
    hallmark of CVE-2026-86060 exploitation in the MikroTrick attack chain
    against MikroTik RouterOS. The prohibited-character username triggers the
    argument-handling flaw that escalates privileges to full admin.
references:
    - https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve/
    - https://securityaffairs.com/198538/security/your-mikrotik-router-may-already-be-compromised-look-for-ssh-user-2.html
    - https://thehackernews.com/2026/09/attackers-hijack-mikrotik-routers.html
author: Actioner
date: 2026/09/07
tags:
    - attack.t1078
    - attack.t1068
logsource:
    product: linux
    service: syslog
detection:
    keywords:
        - 'ssh:-2@'
        - 'user -2 logged'
        - 'for -2 from'
        - 'Invalid user -2'
    condition: keywords
falsepositives:
    - Legitimate usernames containing "-2" substring in unrelated SSH deployments (very unlikely)
level: critical
```

### Sigma: MikroTik Post-Exploitation Backdoor Account "ops"

Detects creation or modification of the "ops" backdoor account in forwarded RouterOS syslog, a confirmed post-exploitation indicator from the MikroTrick campaign. Scope to MikroTik syslog sources to reduce false positives.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (with -x attacktag). splunk convert 0; log_scale convert 0. Keywords AND logic: both an account-action keyword AND "ops" must appear in the same log entry. Medium confidence because "ops" is a plausible legitimate account name in some environments; pair with the "-2" rule as anchor. -->
```yaml
title: MikroTik MikroTrick Post-Exploitation - Backdoor Account "ops" Creation
id: a2f4b8c6-1d3e-4a7f-8b5c-9e0d2f6a3c18
status: experimental
description: >
    Detects the creation of a user account named "ops" in forwarded MikroTik
    RouterOS syslog, a confirmed post-exploitation indicator from the MikroTrick
    campaign exploiting CVE-2026-67276 and CVE-2026-86060. Attackers create this
    privileged backdoor account after gaining unauthenticated admin access.
references:
    - https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve/
    - https://securityaffairs.com/198538/security/your-mikrotik-router-may-already-be-compromised-look-for-ssh-user-2.html
    - https://thehackernews.com/2026/09/attackers-hijack-mikrotik-routers.html
author: Actioner
date: 2026/09/07
tags:
    - attack.t1136.001
logsource:
    product: linux
    service: syslog
detection:
    selection_account:
        - 'user added'
        - 'user changed'
    selection_name:
        - 'ops'
    condition: selection_account and selection_name
falsepositives:
    - Legitimate creation of an account named "ops" on MikroTik devices (uncommon but possible in some environments)
level: high
```

### Snort: Inbound SSH from Known MikroTrick Attacker IP

Detects inbound SSH connections from the two confirmed MikroTrick attacker IPs (82.192.72[.]4 and 103.102.31[.]18) to any host on port 22.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 -c /etc/snort/snort.conf -R <file> -T exit 0. IP-based detection is precise but ephemeral — attacker infrastructure rotates. Content "SSH-" at depth 4 matches the SSH protocol version exchange banner, confirming SSH traffic. -->
```snort
alert tcp [82.192.72.4,103.102.31.18] any -> $HOME_NET 22 (msg:"Actioner - Inbound SSH from Known MikroTrick Attacker IP"; flow:to_server,established; content:"SSH-"; depth:4; sid:2100101; rev:1; classtype:trojan-activity; reference:url,cert.pl/en/posts/2026/09/mikrotik-routeros-cve/; reference:cve,2026-67276; reference:cve,2026-86060;)
```

### Suricata: Inbound SSH from Known MikroTrick Attacker IP

Detects inbound SSH connections from the two confirmed MikroTrick attacker IPs to any host on port 22 using Suricata's SSH protocol detection.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T -S <file> -l /tmp exit 0. Uses ssh protocol for app-layer detection. Same IP-ephemerality caveat as Snort rule. -->
```suricata
alert ssh [82.192.72.4,103.102.31.18] any -> $HOME_NET 22 (msg:"Actioner - Inbound SSH from Known MikroTrick Attacker IP"; flow:to_server,established; sid:2200101; rev:1; classtype:trojan-activity; reference:url,cert.pl/en/posts/2026/09/mikrotik-routeros-cve/; reference:cve,2026-67276; reference:cve,2026-86060; metadata:author Actioner, created_at 2026-09-07;)
```

### YARA: N/A

No endpoint file-level indicators suitable for YARA detection. The attack payloads (ftpsrv.py, launch.sh, serve.py, BusyBox) target MIPS RouterOS and would not be found on standard endpoints where YARA scanning is deployed. File hashes are provided in the IOC table for hash-based lookups.

## Lessons Learned

1. **Silent patching creates a dangerous window.** MikroTik's decision to release patches without vulnerability details on September 3 was intended to buy patching time, but working exploit code was reverse-engineered from the binary diffs within 24 hours. The embargo proved ineffective since patches are publicly distributed.

2. **Network infrastructure devices are high-value, low-visibility targets.** Routers often run for years without updates and lack the endpoint detection coverage that servers and workstations receive. Compromised routers provide attackers with traffic interception, pivoting, and proxy capabilities that are difficult to detect.

3. **The "-2" username is a narrow detection window.** While highly distinctive as a forensic artifact, attackers can clear logs or modify their tooling to use different prohibited-character usernames. The underlying vulnerability (argument-handling flaw with prohibited leading characters) is not specific to "-2" -- any username beginning with "-" could trigger the policy mask manipulation.

4. **RSA key comparison flaws highlight cryptographic implementation pitfalls.** CVE-2026-67276's root cause -- comparing modulus but omitting exponent -- is a subtle but devastating oversight. Full key comparison (type + modulus + exponent) is a fundamental requirement for secure key matching.

## Sources

- [CERT Polska - Vulnerabilities in Mikrotik RouterOS software](https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve/) -- primary coordinated disclosure of six CVEs with technical details
- [The Hacker News - Attackers Hijack MikroTik Routers](https://thehackernews.com/2026/09/attackers-hijack-mikrotik-routers.html) -- news coverage with CERT Polska and MikroTik advisory references
- [SecurityAffairs - Your MikroTik Router May Already Be Compromised](https://securityaffairs.com/198538/security/your-mikrotik-router-may-already-be-compromised-look-for-ssh-user-2.html) -- coverage with Costin Raiu analysis, attacker IPs, file hashes
- [Severity Daily - MikroTik withheld the RouterOS advisory](https://severitydaily.com/mikrotik-routeros-mikrotrick-silent-patch-cve-2026-67276-86060/) -- timeline analysis of silent patching and PoC publication
- [Security Arsenal - MikroTik RouterOS SSH Exploitation Detection Guide](https://securityarsenal.com/blog/mikrotik-routeros-ssh-exploitation-mikrotrick-chain-detecting-rogue-user-2-and-emergency-remediation-guide) -- RouterOS CLI detection commands and remediation sequence
- [CVEFeed - CVE-2026-86060](https://cvefeed.io/vuln/detail/CVE-2026-86060) -- CVE details, CVSS 9.2, CWE-88

---
*Report generated by Actioner*
