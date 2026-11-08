# Technical Analysis Report: cPGuard Update Channel Supply Chain Attack (2026-11-08)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-08
Version: 1.0 (DRAFT)

## Executive Summary

On November 2, 2026, an attacker compromised OPSSHIELD's update distribution infrastructure and published malicious scripts through the cPGuard auto-update channel, affecting approximately 2,950 customer Linux servers. The attacker gained initial access by registering a fraudulent trial account and exploiting weaknesses in the billing portal's callback mechanism to obtain command execution on the licensing server. Within a 70-minute window (02:08–03:20 UTC), the malicious update installed a hidden setuid-root shell (`/var/tmp/.cpg91511_sh`), established persistence via a cron job (`/etc/cron.d/i93677`), and exfiltrated root credentials including `/etc/shadow`, SSH private keys, MySQL passwords, cloud storage keys, and shell history. Billing records for approximately 7,900 customer accounts were also stolen.

This is a software supply-chain attack with concrete, distinctive indicators suitable for detection rules.

## Background: cPGuard / OPSSHIELD

cPGuard is a server security product by OPSSHIELD that provides malware scanning, firewall management, and intrusion detection for Linux web hosting servers. It is widely deployed on shared hosting and VPS environments running cPanel, DirectAdmin, and similar control panels. The auto-update mechanism runs as root to apply security patches, making it a high-value target for supply-chain compromise.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-11-01 | Attacker registers fraudulent trial account on OPSSHIELD billing portal |
| 2026-11-01 22:58 | Attacker gains command execution on licensing server via crafted callback requests |
| 2026-11-02 02:04–02:09 | Attacker uses stolen update-publishing key to upload malicious scripts |
| 2026-11-02 02:08–03:20 | ~2,950 servers pull and execute the malicious update (70-minute window) |
| 2026-11-02 ~14:00 | OPSSHIELD detects the compromise (within 12 hours) |
| 2026-11-03 | Public disclosure; initial remediation update v5.88.25 released |
| 2026-11-04 | Corrected remediation: v5.88.26 (removes backdoor), follow-up update removes cron task |

## Root Cause: Billing Portal Callback Exploitation → Update Key Theft

The attacker registered a free cPGuard trial under a false identity and exploited the billing portal's callback pages (`manage.opsshield[.]com`) to gain command execution on the licensing server. This provided access to the update-publishing key, which was then used to sign and push malicious scripts through the trusted auto-update channel. No software vulnerability in cPGuard itself was exploited — the supply chain was compromised at the distribution infrastructure level.

## Technical Analysis of the Malicious Payload

### 1. Malicious Update Scripts (Initial Delivery)

Four malicious shell scripts were pushed through the update channel, all running as root:

| Script | SHA-256 |
|--------|---------|
| `cpguard-v58812-i91511.sh` | `2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38` |
| `cpguard-v58812-i91511b.sh` | `ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a` |
| `cpguard-v58812-i91511c.sh` | `d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26` |
| `cpguard-v58812-i91511d.sh` | `6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77` |

Affected cPGuard versions: **5.88.12 through 5.88.19**. Remediation version: **5.88.26+**.

### 2. Backdoor Installation and Persistence

The scripts performed the following actions:

- **Setuid-root shell**: Copied `/bin/bash` to `/var/tmp/.cpg91511_sh` and set the setuid bit (`chmod u+s`), providing any local user instant root access
- **Cron persistence**: Created `/etc/cron.d/i93677` pointing to scripts in `/var/tmp/.i93677/` for persistent execution
- **Staging directory**: Created `/var/tmp/.cpg91511/` to stage collected data

### 3. Credential Harvesting

The scripts collected and staged the following sensitive data:

| Target | Path | Data Type |
|--------|------|-----------|
| Password hashes | `/etc/shadow` | Local account credential hashes |
| SSH keys | `/root/.ssh/` | Root SSH private keys, authorized_keys |
| MySQL credentials | `/root/.my.cnf` | MySQL root password |
| Cloud storage keys | `/root/.s3cfg` | S3/DigitalOcean access keys |
| Shell history | `~root/.bash_history` | Commands containing credentials/tokens |

All collected data was archived to `/var/tmp/.cpg91511/loot.tgz`.

### 4. Infrastructure Compromise

Beyond customer servers, the attacker:
- Copied 32 files from the licensing server (one per customer server)
- Cloned/snapshotted three OPSSHIELD cloud servers
- Exfiltrated billing records for ~7,900 accounts (names, addresses, emails, bcrypt-hashed passwords)

### 5. Anti-Forensics / Evasion Techniques

- Used hidden directories (dot-prefixed: `.cpg91511`, `.i93677`) to reduce visibility
- Leveraged the trusted update channel to bypass integrity checks
- Operated within a 70-minute window to minimize detection exposure

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `94.183.188[.]91`)
> - Domains: `[.]` replacing dots

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `/var/tmp/.cpg91511_sh` | — | Setuid-root shell (copy of /bin/bash) |
| Linux | `/var/tmp/.cpg91511/` | — | Staging directory for harvested data |
| Linux | `/var/tmp/.cpg91511/loot.tgz` | — | Archive of harvested credentials |
| Linux | `/var/tmp/.i93677/` | — | Cron job payload directory |
| Linux | `/etc/cron.d/i93677` | — | Persistence cron job |
| Linux | `cpguard-v58812-i91511.sh` | `2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38` | Primary malicious update script |
| Linux | `cpguard-v58812-i91511b.sh` | `ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a` | Secondary malicious script |
| Linux | `cpguard-v58812-i91511c.sh` | `d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26` | Tertiary malicious script |
| Linux | `cpguard-v58812-i91511d.sh` | `6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77` | Quaternary malicious script |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `94.183.188[.]91` | Primary attacker operating address (per OPSSHIELD) |
| Domain | `manage.opsshield[.]com` | Billing portal (attack vector) |

### Behavioral

- Creation of hidden setuid-root shell binaries in `/var/tmp/`
- Cron job creation under `/etc/cron.d/` with numeric-only name
- Bulk credential harvesting: simultaneous access to `/etc/shadow`, `/root/.ssh/`, `/root/.my.cnf`, `/root/.s3cfg`
- Archival of harvested data to `.tgz` in hidden staging directory

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into cPGuard auto-update channel |
| T1078 | Valid Accounts | Fraudulent trial account used to access billing portal |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Malicious bash scripts executed as root via update mechanism |
| T1053.003 | Scheduled Task/Job: Cron | Persistence via `/etc/cron.d/i93677` |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | Setuid-root shell at `/var/tmp/.cpg91511_sh` |
| T1552.004 | Unsecured Credentials: Private Keys | Root SSH private keys harvested |
| T1552.003 | Unsecured Credentials: Bash History | Root shell history collected |
| T1005 | Data from Local System | `/etc/shadow`, MySQL credentials, S3 keys collected |
| T1530 | Data from Cloud Storage Object | Cloud storage credentials (`/root/.s3cfg`) targeted |
| T1560.001 | Archive Collected Data: Archive via Utility | Data archived to `loot.tgz` |

## Impact Assessment

- **Breadth**: ~2,950 servers executed the malicious update; ~7,900 billing accounts exposed
- **Depth**: Full root credential compromise on affected servers — password hashes, SSH keys, database credentials, cloud storage keys
- **Stealth**: Exploited trusted update channel; operated within 70-minute window; used hidden dot-prefixed directories
- **Lateral movement risk**: Stolen SSH keys may grant access to additional infrastructure trusted by the compromised servers

## Detection & Remediation

### Immediate Detection

```bash
# Check if affected cPGuard versions were installed
grep 'Successfully updated' /opt/cpguard/logs/install_log

# Check for backdoor artifacts
ls -la /var/tmp/.cpg91511_sh /var/tmp/.cpg91511/ /var/tmp/.i93677/ /etc/cron.d/i93677 2>/dev/null

# Check current version
cpgcli --version
```

### Remediation

1. **Update cPGuard** to version 5.88.26+ (`cpgcli update --start`) — removes the backdoor and cron job
2. **Verify artifact removal**: confirm `/var/tmp/.cpg91511_sh`, `/var/tmp/.cpg91511/`, `/var/tmp/.i93677/`, and `/etc/cron.d/i93677` are gone; delete manually if present
3. **Reset ALL root credentials** from a trusted recovery environment: change root password, all local account passwords, and any reused passwords on other systems
4. **Rotate MySQL root password** and all database credentials in `/root/.my.cnf`
5. **Replace SSH keys**: regenerate `/root/.ssh/` keys, remove old public keys from trusted_hosts on all reachable systems, audit `authorized_keys` for unknown entries
6. **Rotate cloud credentials**: S3 keys (`/root/.s3cfg`), DigitalOcean tokens, and any secrets visible in shell history
7. **Reset OPSSHIELD billing portal** password at `manage.opsshield.com` and enable 2FA
8. **Treat compromised servers as breached**: if OPSSHIELD confirms manual attacker logins on a specific server, rebuild from a pre-November 1 backup

### Long-Term Hardening

- Verify update channels via cryptographic signing with pinned certificates, not just key-based authentication
- Implement update integrity verification independent of the vendor's infrastructure
- Restrict cPGuard update service to dedicated, minimal-privilege accounts where possible
- Monitor for unauthorized cron job creation in `/etc/cron.d/`

## Detection Rules

These detections target the specific file-system artifacts, credential-harvesting behavior, network indicators, and malicious script content from the cPGuard supply chain attack. PoC/advisory-specific altitude; compiles ≠ fires — verify in your pipeline before production deployment.

### Sigma: cPGuard Supply Chain Backdoor File Artifacts
Detects creation of the hidden setuid-root shell, staging directories, and persistence cron job specific to this attack.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (ATT&CK data 403 from proxy); splunk convert exit 0; log_scale convert exit 0. File paths are campaign-unique hidden artifacts unlikely in benign activity. -->
```yaml
title: cPGuard Supply Chain - Backdoor File Artifacts
id: 7a3e1b4c-9d2f-4e8a-b5c1-6f0e3d2a1b8c
status: experimental
description: Detects creation of files associated with the cPGuard supply chain attack including the hidden setuid-root shell and staging directories
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://www.csoonline.com/article/4244961/attackers-turned-opsshields-trusted-update-channel-into-a-supply-chain-attack-2.html
author: Actioner
date: 2026/11/08
tags:
    - attack.t1195.002
    - attack.t1059.004
logsource:
    category: file_event
    product: linux
detection:
    selection_backdoor:
        TargetFilename|contains:
            - '/var/tmp/.cpg91511_sh'
            - '/var/tmp/.cpg91511/'
            - '/var/tmp/.i93677/'
    selection_cron:
        TargetFilename: '/etc/cron.d/i93677'
    condition: selection_backdoor or selection_cron
falsepositives:
    - Legitimate cPGuard operations during the affected version window (5.88.12-5.88.19) prior to remediation
level: critical
```

### Sigma: cPGuard Supply Chain Credential Harvesting
Detects shell commands consistent with the bulk credential harvesting pattern — simultaneous access to shadow, SSH keys, MySQL credentials, and cloud storage keys.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check skipped (ATT&CK data 403 from proxy); splunk convert exit 0; log_scale convert exit 0. Condition requires shadow + at least one other credential target, or cpg91511/loot.tgz references. Medium confidence: individual file accesses are benign; the combination is suspicious but not exclusive to this campaign. -->
```yaml
title: cPGuard Supply Chain - Credential Harvesting via Script
id: 8b4f2c5d-ae30-5f9b-c6d2-701f4e3b2c9d
status: experimental
description: Detects shell commands consistent with the cPGuard supply chain attack credential harvesting - reading /etc/shadow, SSH keys, MySQL credentials, and shell history as root
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://www.csoonline.com/article/4244961/attackers-turned-opsshields-trusted-update-channel-into-a-supply-chain-attack-2.html
author: Actioner
date: 2026/11/08
tags:
    - attack.t1552.004
    - attack.t1552.003
    - attack.t1005
logsource:
    category: process_creation
    product: linux
detection:
    selection_shadow:
        CommandLine|contains: '/etc/shadow'
    selection_sshkeys:
        CommandLine|contains: '/root/.ssh'
    selection_mysql:
        CommandLine|contains: '/root/.my.cnf'
    selection_s3:
        CommandLine|contains: '/root/.s3cfg'
    selection_archive:
        CommandLine|contains:
            - 'loot.tgz'
            - '.cpg91511'
    filter_legitimate:
        Image|endswith:
            - '/passwd'
            - '/useradd'
            - '/usermod'
            - '/chpasswd'
    condition: (selection_shadow and (selection_sshkeys or selection_mysql or selection_s3)) or selection_archive and not filter_legitimate
falsepositives:
    - System administration scripts that read shadow and SSH key files simultaneously
    - Backup scripts archiving credential stores
level: high
```

### Snort: cPGuard Supply Chain Attacker IP
Detects outbound traffic to the primary attacker operating address identified by OPSSHIELD.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0. IP directly attributed by vendor as attacker's operating address. High confidence but time-limited — attacker may rotate. -->
```snort
alert ip $HOME_NET any -> 94.183.188.91 any (msg:"Actioner - cPGuard Supply Chain Attack - Outbound to Attacker IP 94.183.188.91"; flow:to_server; sid:2100050; rev:1; classtype:trojan-activity; reference:url,thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html;)
```

### Suricata: cPGuard Supply Chain Attacker IP
Detects outbound traffic to the primary attacker operating address identified by OPSSHIELD.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Same IP as Snort rule. -->
```suricata
alert ip $HOME_NET any -> 94.183.188.91 any (msg:"Actioner - cPGuard Supply Chain Attacker IP 94.183.188.91"; sid:2200050; rev:1; classtype:trojan-activity; reference:url,thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html; metadata:author Actioner, created_at 2026-11-08;)
```

### YARA: cPGuard Supply Chain Malicious Update Script
Detects the malicious update scripts by their distinctive file paths, script names, and credential harvesting artifact combination.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive test: constructed script with published paths/names → matched. Negative test: benign update script → no match. Script names (cpguard-v58812-i91511*) are campaign-unique identifiers from the vendor advisory. -->
```yara
rule Supply_Chain_cPGuard_Backdoor_Script
{
    meta:
        description = "Detects malicious cPGuard update scripts from the November 2026 supply chain attack"
        author = "Actioner"
        date = "2026-11-08"
        reference = "https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html"
        hash = "2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38"
        severity = "critical"

    strings:
        $path1 = "/var/tmp/.cpg91511_sh" ascii
        $path2 = "/var/tmp/.cpg91511/" ascii
        $path3 = "/var/tmp/.i93677/" ascii
        $cron = "/etc/cron.d/i93677" ascii
        $loot = "loot.tgz" ascii
        $shadow = "/etc/shadow" ascii
        $sshkey = "/root/.ssh" ascii
        $mycnf = "/root/.my.cnf" ascii
        $s3cfg = "/root/.s3cfg" ascii
        $script_name1 = "cpguard-v58812-i91511" ascii
        $script_name2 = "cpguard-v58812-i91511b" ascii
        $script_name3 = "cpguard-v58812-i91511c" ascii
        $script_name4 = "cpguard-v58812-i91511d" ascii

    condition:
        any of ($script_name*) or
        ($path1 and $shadow) or
        ($path2 and ($loot or $sshkey or $mycnf)) or
        ($cron and $path3) or
        ($s3cfg and $shadow) or
        (3 of ($path1, $path2, $path3, $cron, $loot))
}
```

## Lessons Learned

This attack demonstrates the critical risk of software supply-chain compromise through distribution infrastructure rather than source code. The attacker did not modify cPGuard's code — they compromised the billing/licensing infrastructure to obtain update-publishing keys, turning a trusted auto-update channel into a malware delivery mechanism. The 70-minute attack window and root-level execution privileges highlight that even brief supply-chain compromises can have devastating, cascading effects when the compromised software runs with elevated privileges. Organizations should verify update integrity independently of the vendor's infrastructure and implement monitoring for unexpected credential access patterns.

## Sources

- [The Hacker News](https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html) — Primary technical report with IOCs, timeline, and malicious script hashes
- [CSO Online](https://www.csoonline.com/article/4244961/attackers-turned-opsshields-trusted-update-channel-into-a-supply-chain-attack-2.html) — Additional analysis of attack chain and remediation steps
- [SecurityWeek](https://securityweek.com/malicious-cpguard-updates-served-in-opsshield-supply-chain-attack) — Coverage with OPSSHIELD response details
- [NetworkWorld](https://www.networkworld.com/article/4244919/attackers-turned-opsshields-trusted-update-channel-into-a-supply-chain-attack.html) — Supply chain analysis context

---
*Report generated by Actioner*
