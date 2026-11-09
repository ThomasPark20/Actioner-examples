# Technical Analysis Report: cPGuard Update Channel Hijack (2026-11-09)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-09
Version: 1.0 (DRAFT)

## Executive Summary

On November 2, 2026, attackers compromised OPSSHIELD's update distribution infrastructure and pushed malicious scripts through cPGuard's legitimate auto-update channel, backdooring approximately 2,950 customer Linux servers within a 72-minute window (02:08--03:20 UTC). The malicious update ran as root and harvested `/etc/shadow`, SSH private keys, MySQL credentials, and shell history, staging the data as `loot.tgz` in a hidden directory before exfiltrating it. The attacker also installed a persistent setuid-root shell backdoor and a cron job for continued access. Separately, OPSSHIELD's billing database containing approximately 7,900 customer account records (including bcrypt password hashes) was copied. The attack began with a fraudulent customer account registration followed by exploitation of the billing portal to gain command execution on the licensing server and steal the update-signing key. OPSSHIELD detected the compromise within 12 hours and released a clean update (v5.88.26).

## Background: cPGuard / OPSSHIELD

cPGuard is a commercial Linux security product developed by OPSSHIELD, widely deployed on web hosting servers running cPanel, DirectAdmin, and Plesk control panels. It provides WAF, malware scanning, and intrusion prevention capabilities. The product uses an automatic update mechanism that pulls updates from OPSSHIELD's CDN infrastructure, executing them with root privileges. This trust relationship -- a security product with root-level auto-update -- made it a high-value supply chain target. Hosting providers such as Namecheap offer cPGuard as an add-on, making the blast radius significant across the shared hosting ecosystem.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-11-01, 15:38 | Probing of manage[.]opsshield[.]com begins |
| 2026-11-01, 16:34 | Attacker registers fraudulent customer account, orders free cPGuard trial |
| 2026-11-01, 21:17 | Trial installed on attacker-controlled server to study licensing protocol |
| 2026-11-01, 21:40--21:51 | cPGuard bans the attacker IP twice |
| 2026-11-01, 22:50 | Crafted requests sent to billing portal callback pages |
| 2026-11-01, 22:58 | Command execution achieved on billing/licensing server; data collection begins |
| 2026-11-02, 02:04--02:09 | Malicious update scripts uploaded to CDN using stolen access key |
| 2026-11-02, 02:08--03:20 | Customer servers that polled during this window install the malicious update (~2,950 servers) |
| 2026-11-02, 02:13 | Attacker copies three OPSSHIELD cloud servers |
| 2026-11-02 (within 12h) | OPSSHIELD detects the compromise |
| 2026-11-02 | Stolen key revoked; clean update v5.88.26 published |
| 2026-11-03 | Entry point traced; full disclosure published |

## Root Cause: Billing Portal Exploitation Leading to Update Channel Hijack

The attacker registered a customer account under a false identity and obtained a free cPGuard trial to study the licensing communication protocol. After reconnaissance, the attacker sent crafted requests to callback endpoints on the billing portal (`manage[.]opsshield[.]com`), achieving command execution on the billing/licensing server. The exact vulnerable request was not logged, but two possible entry points were patched. SSH, control panel, FTP, and API token access were ruled out as the initial vector. From the licensing server, the attacker stole the update-publishing access key and used it to upload malicious scripts to the update CDN, which were then distributed through the legitimate cPGuard auto-update channel.

## Technical Analysis of the Malicious Payload

### 1. Malicious Update Delivery

Four variants of the malicious script were pushed through the update channel:

| File | SHA-256 |
|------|---------|
| `cpguard-v58812-i91511.sh` | `2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38` |
| `cpguard-v58812-i91511b.sh` | `ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a` |
| `cpguard-v58812-i91511c.sh` | `d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26` |
| `cpguard-v58812-i91511d.sh` | `6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77` |

The scripts were distributed as cPGuard versions 5.88.12 through 5.88.19. Servers that polled the update channel between 02:08 and 03:20 UTC on November 2 received and executed the malicious script as root.

### 2. Credential and Secret Harvesting

The malicious script collected sensitive files from each compromised server:

- `/etc/shadow` and `/etc/passwd` -- local account password hashes
- `/root/.ssh/` -- SSH private keys, `authorized_keys`, `known_hosts`
- `/root/.my.cnf` -- MySQL root password (where present)
- Root shell history -- potentially containing plaintext passwords and API tokens
- `/root/.s3cfg` -- cloud storage keys (on a subset of servers)

Collected files were staged in the hidden directory `/var/tmp/.cpg91511/` and packaged as `/var/tmp/.cpg91511/loot.tgz` before exfiltration.

### 3. Persistence Mechanisms

The script installed two persistence mechanisms:

1. **Setuid-root shell backdoor** at `/var/tmp/.cpg91511_sh` -- a hidden binary with the setuid bit set, allowing any user who can execute it to obtain a root shell.
2. **Cron-based persistence** via `/etc/cron.d/i93677` with supporting files in `/var/tmp/.i93677/`.

### 4. Exfiltration

Initial reports indicated data was exfiltrated to OPSSHIELD's own licensing server under a compromised account, from which the attacker retrieved it. The later disclosure states data went to an attacker-controlled server. Exfiltration endpoints followed the URL pattern `*_rx.php`. The attacker's main operating IP was `94[.]183[.]188[.]91`, and they spoofed the user agent `cPGuard/5.88.11` to blend with legitimate update traffic.

### 5. OPSSHIELD Infrastructure Compromise

On OPSSHIELD's internal servers (not customer servers), investigators found:

**Web shells:**
- `/i90248_probe.txt`, `/i90573_probe.txt` -- probe files
- `/i90573_sh.php`, `/i90573_x.php` -- PHP web shells

**gsocket backdoor:**
- `/usr/bin/defunct`, `defunct.service`, `/lib/systemd/system/defunct.dat`
- Process masquerading as `[slub_flushwq]`

**Go implant (multiple copies):**
- `/usr/sbin/pythno3`, `/usr/sbin/netstat.cfg`, `/etc/profile.d/bash.cfg`
- `/usr/lib/system.mark`, `/usr/lib/libgdi.so.0.8.2`, `/boot/system.pub`
- Process masquerading as `[rcu_gp]`

**Process hiding:**
- `/etc/profile.d/gateway.sh` -- script that hides attacker processes from `ps`, `netstat`, `ls`, and `find`

### 6. Anti-Forensics / Evasion Techniques

- Hidden (dot-prefixed) file and directory names in `/var/tmp/`
- Process name masquerading as kernel threads (`[slub_flushwq]`, `[rcu_gp]`)
- Typosquatted binary names (`pythno3` mimicking `python3`)
- `gateway.sh` in `/etc/profile.d/` to hide malicious processes from common inspection tools
- Spoofed `cPGuard/5.88.11` user agent to blend with legitimate traffic
- Use of the vendor's own infrastructure for exfiltration to avoid anomalous external connections

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `94[.]183[.]188[.]91`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| cPGuard | 5.88.12 through 5.88.19 | Malicious updates pushed via hijacked update channel |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `cpguard-v58812-i91511.sh` | `2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38` | Malicious update script (base variant) |
| Linux | `cpguard-v58812-i91511b.sh` | `ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a` | Malicious update script (variant b) |
| Linux | `cpguard-v58812-i91511c.sh` | `d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26` | Malicious update script (variant c) |
| Linux | `cpguard-v58812-i91511d.sh` | `6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77` | Malicious update script (variant d) |
| Linux | `/var/tmp/.cpg91511_sh` | -- | Setuid-root shell backdoor |
| Linux | `/var/tmp/.cpg91511/` | -- | Staging directory for harvested data |
| Linux | `/var/tmp/.cpg91511/loot.tgz` | -- | Archive of harvested credentials |
| Linux | `/etc/cron.d/i93677` | -- | Persistence cron job |
| Linux | `/var/tmp/.i93677/` | -- | Cron job supporting files |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `94[.]183[.]188[.]91` | Main attacker operating address |
| URL Pattern | `*_rx.php` | Exfiltration endpoint URI pattern |
| User-Agent | `cPGuard/5.88.11` | Spoofed user agent observed from attacker IP |

### Behavioral

- Root-privileged process reading `/etc/shadow`, `/root/.ssh/*`, and `/root/.my.cnf` in rapid succession
- Creation of hidden dot-prefixed directories under `/var/tmp/` with setuid binaries
- tar/gzip operations creating archives in `/var/tmp/` hidden directories
- Cron job creation in `/etc/cron.d/` by non-standard processes
- Outbound data transfer following credential harvesting activity

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Hijacked cPGuard auto-update channel to distribute malicious scripts to ~2,950 servers |
| T1078 | Valid Accounts | Used stolen update-signing key and compromised licensing server account |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Malicious payload was a bash shell script executed as root |
| T1072 | Software Deployment Tools | Abused cPGuard's legitimate auto-update mechanism for payload delivery |
| T1003 | OS Credential Dumping | Harvested `/etc/shadow` and `/etc/passwd` for password hashes |
| T1552.004 | Unsecured Credentials: Private Keys | Collected SSH private keys from `/root/.ssh/` |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | Installed hidden setuid-root shell at `/var/tmp/.cpg91511_sh` |
| T1053.003 | Scheduled Task/Job: Cron | Created cron job at `/etc/cron.d/i93677` for persistence |
| T1560.001 | Archive Collected Data: Archive via Utility | Packaged harvested data as `loot.tgz` |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | Used dot-prefixed paths (`.cpg91511`, `.i93677`) to hide artifacts |
| T1041 | Exfiltration Over C2 Channel | Exfiltrated collected data to attacker-controlled endpoint |
| T1505.003 | Server Software Component: Web Shell | Deployed PHP web shells on OPSSHIELD infrastructure (`i90573_sh.php`, `i90573_x.php`) |
| T1036.004 | Masquerading: Masquerade Task or Service | Go implant masqueraded as kernel threads (`[rcu_gp]`, `[slub_flushwq]`) |
| T1071.001 | Application Layer Protocol: Web Protocols | Spoofed cPGuard user agent for blending with legitimate HTTP traffic |

## Impact Assessment

- **Breadth:** Approximately 2,950 customer Linux servers executed the malicious update; 7,900 billing accounts exposed.
- **Depth:** Root-level compromise on affected servers -- complete access to password hashes, SSH keys, database credentials, and shell history. The setuid backdoor and cron persistence provided ongoing access.
- **Stealth:** The attack leveraged a trusted update channel and ran as part of the expected update process, making detection difficult without specific IOC monitoring. The 72-minute window was narrow but sufficient to hit a large number of servers.
- **Data exposure:** bcrypt-hashed billing portal passwords, names, email addresses, and postal addresses for all ~7,900 OPSSHIELD customers. On compromised servers: root password hashes, SSH private keys, MySQL root passwords, shell history, and cloud storage keys.

## Detection & Remediation

### Immediate Detection

Check if a cPGuard server received an affected update:

```bash
grep 'Successfully updated' /opt/cpguard/logs/install_log | grep -E '5\.88\.1[2-9]'
```

Check for persistence artifacts:

```bash
ls -la /var/tmp/.cpg91511_sh /etc/cron.d/i93677 /var/tmp/.i93677/ /var/tmp/.cpg91511/ 2>/dev/null
```

Check for the loot archive:

```bash
find /var/tmp/ -name "loot.tgz" -o -name ".cpg91511" 2>/dev/null
```

### Remediation

1. **Update cPGuard** immediately: `cpgcli update --start` and verify version >= 5.88.26 with `cpgcli --version`.
2. **Remove persistence artifacts** if the update did not clean them: `/etc/cron.d/i93677`, `/var/tmp/.i93677/`, `/var/tmp/.cpg91511_sh`.
3. **Rotate all credentials** from a trusted recovery environment:
   - Reset root password and all local account passwords.
   - Generate new SSH key pairs under `/root/.ssh/`; remove old public keys from all remote `authorized_keys`.
   - Change MySQL root password and any credentials in `/root/.my.cnf`.
   - Rotate S3 keys (`/root/.s3cfg`), DigitalOcean tokens, and any secrets visible in shell history.
4. **Treat downstream systems as exposed:** any server reachable via SSH keys from a compromised host should be treated as compromised until its keys are replaced.
5. **Reset OPSSHIELD billing portal password** and enable 2FA at manage[.]opsshield[.]com.
6. **Full rebuild** if evidence of manual attacker login is found, or if integrity cannot be confirmed. Use a backup from before November 1.

### Long-Term Hardening

- Implement update signature verification with pinned keys for all auto-update mechanisms.
- Apply least-privilege to security products -- update agents should not need root access to download updates.
- Segment billing/licensing infrastructure from update-signing infrastructure.
- Deploy file integrity monitoring (FIM) for `/etc/cron.d/`, `/var/tmp/`, and auto-update binary directories.
- Implement egress filtering to detect anomalous outbound transfers following update operations.
- Require MFA for all vendor portal accounts and restrict API key permissions.

## Detection Rules

These rules cover the cPGuard supply chain attack's file artifacts, network indicators, and behavioral patterns. All IOC-specific rules target distinctive, attack-unique indicators, while behavioral rules carry lower confidence due to potential overlap with legitimate administrative activity. The `sigma check` command could not run (MITRE ATT&CK data fetch blocked by proxy), so Sigma rules were validated via `sigma convert` to both Splunk and LogScale backends.

### Sigma: cPGuard Malicious File Artifacts

Detects creation of the attack-specific file paths including the setuid backdoor, staging directory, loot archive, and cron persistence.

**Compile:** ✅ (`sigma convert` to Splunk exit 0, LogScale exit 0) | **Confidence:** high

```yaml
title: cPGuard Supply Chain Attack - Malicious File Artifacts
id: d40e6cbb-8730-4706-a7e3-8f6fc5af3593
status: experimental
description: >
    Detects creation of file artifacts associated with the cPGuard supply chain
    attack (November 2026), including the setuid-root backdoor shell, the data
    collection staging directory, the loot archive, and the persistence cron job.
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://opsshield.com/notice/security-incident-disclosure-servermanage.html
author: Actioner
date: 2026-11-09
tags:
    - attack.t1195.002
    - attack.t1548.001
    - attack.t1053.003
logsource:
    category: file_event
    product: linux
detection:
    selection_backdoor:
        TargetFilename|endswith: '/var/tmp/.cpg91511_sh'
    selection_staging:
        TargetFilename|contains: '/var/tmp/.cpg91511/'
    selection_loot:
        TargetFilename|endswith: '/var/tmp/.cpg91511/loot.tgz'
    selection_cron:
        TargetFilename|endswith: '/etc/cron.d/i93677'
    selection_cron_dir:
        TargetFilename|contains: '/var/tmp/.i93677/'
    condition: 1 of selection*
falsepositives:
    - Unlikely - these paths are unique to this attack
level: critical
```

<!-- Audit: Validated via sigma convert --without-pipeline -t splunk (exit 0) and -t log_scale (exit 0). sigma check failed due to MITRE ATT&CK data fetch blocked by proxy (HTTP 403), not a rule issue. Tags use procedure-level technique IDs only. All file paths are real (not defanged) per logsource-encoding guidance. -->

### Sigma: cPGuard Malicious Script Execution

Detects execution of the four known malicious update script variants by filename or command line.

**Compile:** ✅ (`sigma convert` to Splunk exit 0, LogScale exit 0) | **Confidence:** high

```yaml
title: cPGuard Supply Chain Attack - Malicious Script Execution
id: 0c72f2d4-9932-4429-8236-c44a664ce630
status: experimental
description: >
    Detects execution of the malicious cPGuard update scripts associated with the
    November 2026 supply chain attack. The scripts were named cpguard-v58812-i91511
    with variants b, c, and d.
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://opsshield.com/notice/security-incident-disclosure-servermanage.html
author: Actioner
date: 2026-11-09
tags:
    - attack.t1195.002
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_script_name:
        CommandLine|contains: 'cpguard-v58812-i91511'
    selection_image:
        Image|endswith:
            - '/cpguard-v58812-i91511.sh'
            - '/cpguard-v58812-i91511b.sh'
            - '/cpguard-v58812-i91511c.sh'
            - '/cpguard-v58812-i91511d.sh'
    condition: 1 of selection*
falsepositives:
    - Unlikely - these filenames are unique to this attack
level: critical
```

<!-- Audit: Validated via sigma convert --without-pipeline -t splunk (exit 0) and -t log_scale (exit 0). Script names match all four known SHA-256 hashed variants from OPSSHIELD disclosure. -->

### Sigma: cPGuard Credential Harvesting Pattern

Detects the auditd access pattern of reading /etc/shadow together with SSH keys or MySQL config, as observed in the attack's harvesting phase.

**Compile:** ✅ (`sigma convert` to Splunk exit 0, LogScale exit 0) | **Confidence:** medium

```yaml
title: cPGuard Supply Chain Attack - Credential Harvesting Pattern
id: 3fc3fed8-cb40-4dd5-b309-a7b705f3b0e9
status: experimental
description: >
    Detects the credential and secret harvesting pattern used by the cPGuard
    supply chain attack, where the malicious script reads /etc/shadow, SSH
    private keys, and MySQL credentials, then stages them to a hidden directory
    under /var/tmp.
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://opsshield.com/notice/security-incident-disclosure-servermanage.html
author: Actioner
date: 2026-11-09
tags:
    - attack.t1003
    - attack.t1552.004
    - attack.t1560.001
logsource:
    product: linux
    service: auditd
detection:
    selection_shadow:
        type: 'PATH'
        name: '/etc/shadow'
    selection_ssh:
        type: 'PATH'
        name|startswith: '/root/.ssh/'
    selection_mycnf:
        type: 'PATH'
        name: '/root/.my.cnf'
    selection_s3cfg:
        type: 'PATH'
        name: '/root/.s3cfg'
    condition: selection_shadow and (selection_ssh or selection_mycnf or selection_s3cfg)
falsepositives:
    - Backup scripts that read /etc/shadow and SSH keys simultaneously
    - Configuration management tools performing credential audits
level: medium
```

<!-- Audit: Validated via sigma convert. This is a behavioral/TTP rule correlating multiple file accesses -- requires auditd file access auditing enabled for these paths. Medium confidence due to potential overlap with backup and config management tools. -->

### Sigma: Connection to Attacker IP

Detects outbound network connections to the attacker's primary operating IP address.

**Compile:** ✅ (`sigma convert` to Splunk exit 0, LogScale exit 0) | **Confidence:** high

```yaml
title: cPGuard Supply Chain Attack - Connection to Attacker IP
id: e60da170-498c-4899-baf7-2d405331ca5d
status: experimental
description: >
    Detects network connections to IP 94.183.188.91, identified as the main
    attacker operating address in the cPGuard supply chain attack (November 2026).
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://opsshield.com/notice/security-incident-disclosure-servermanage.html
author: Actioner
date: 2026-11-09
tags:
    - attack.t1041
logsource:
    category: firewall
detection:
    selection:
        dst_ip: '94.183.188.91'
    condition: selection
falsepositives:
    - Legitimate traffic to this IP if it is reassigned in the future
level: high
```

<!-- Audit: Validated via sigma convert. IOC-specific rule matching single known attacker IP. IP is real (not defanged) in the rule per logsource-encoding guidance. High confidence as a known attacker IOC. -->

### Sigma: Setuid Backdoor Execution

Detects execution of the hidden setuid-root shell backdoor at `/var/tmp/.cpg91511_sh`.

**Compile:** ✅ (`sigma convert` to Splunk exit 0, LogScale exit 0) | **Confidence:** high

```yaml
title: cPGuard Supply Chain Attack - Hidden Setuid Backdoor in var tmp
id: 3ba1f08f-9f44-4744-a1d3-3cafb98878ab
status: experimental
description: >
    Detects execution of the hidden setuid-root shell backdoor placed at
    /var/tmp/.cpg91511_sh by the cPGuard supply chain attack.
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://opsshield.com/notice/security-incident-disclosure-servermanage.html
author: Actioner
date: 2026-11-09
tags:
    - attack.t1548.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/var/tmp/.cpg91511_sh'
    condition: selection
falsepositives:
    - Unlikely - this path is unique to this attack
level: critical
```

<!-- Audit: Validated via sigma convert. IOC-specific path unique to this incident. -->

### Sigma: Spoofed cPGuard User Agent

Detects HTTP requests using the spoofed `cPGuard/5.88.11` user agent observed from the attacker.

**Compile:** ✅ (`sigma convert` to Splunk exit 0, LogScale exit 0) | **Confidence:** medium

```yaml
title: cPGuard Supply Chain Attack - Spoofed User Agent
id: bb148aa4-488f-4af1-8287-039e60433b51
status: experimental
description: >
    Detects HTTP requests using the spoofed user agent string cPGuard/5.88.11
    observed in the cPGuard supply chain attack. The attacker used this to
    impersonate legitimate cPGuard update traffic.
references:
    - https://opsshield.com/notice/security-incident-disclosure-servermanage.html
author: Actioner
date: 2026-11-09
tags:
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-useragent|contains: 'cPGuard/5.88.11'
    condition: selection
falsepositives:
    - Legitimate cPGuard version 5.88.11 update traffic (this specific version existed before the attack)
level: medium
```

<!-- Audit: Validated via sigma convert. Medium confidence because cPGuard 5.88.11 was a real version and legitimate instances would produce the same UA string. Best used in correlation with other indicators. -->

### YARA: cPGuard Malicious Update Script

Detects the malicious cPGuard update scripts by content patterns including staging paths, persistence mechanisms, and credential harvesting targets.

**Compile:** ✅ (`yarac` exit 0) | **Confidence:** high

```yara
rule SupplyChain_cPGuard_Malicious_Update_Script
{
    meta:
        description = "Detects malicious cPGuard update scripts from the November 2026 supply chain attack based on distinctive file paths, collection patterns, and script naming"
        author = "Actioner"
        date = "2026-11-09"
        reference = "https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html"
        hash = "2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38"
        hash2 = "ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a"
        hash3 = "d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26"
        hash4 = "6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $staging_dir = "/var/tmp/.cpg91511" ascii
        $backdoor_path = "/var/tmp/.cpg91511_sh" ascii
        $loot_archive = "loot.tgz" ascii
        $cron_persist = "/etc/cron.d/i93677" ascii
        $cron_workdir = "/var/tmp/.i93677" ascii
        $shadow_read = "/etc/shadow" ascii
        $ssh_read = "/root/.ssh" ascii
        $mycnf_read = "/root/.my.cnf" ascii
        $script_name = "cpguard-v58812-i91511" ascii

    condition:
        filesize < 1MB and
        $script_name and
        (
            ($staging_dir and $loot_archive) or
            ($backdoor_path and $cron_persist) or
            (3 of ($shadow_read, $ssh_read, $mycnf_read, $staging_dir, $cron_workdir))
        )
}
```

<!-- Audit: Compiled with yarac exit 0. Requires $script_name as anchor plus either staging+loot combination, backdoor+cron combination, or 3-of-5 credential harvesting indicators. High confidence because $script_name is attack-unique. -->

### YARA: cPGuard Setuid Backdoor Binary

Detects the ELF binary dropped as the setuid-root backdoor.

**Compile:** ✅ (`yarac` exit 0) | **Confidence:** high

```yara
rule SupplyChain_cPGuard_Setuid_Backdoor
{
    meta:
        description = "Detects the setuid-root shell backdoor dropped by the cPGuard supply chain attack at /var/tmp/.cpg91511_sh"
        author = "Actioner"
        date = "2026-11-09"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $path_marker = ".cpg91511_sh" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        $path_marker
}
```

<!-- Audit: Compiled with yarac exit 0. Matches ELF binaries containing the unique path marker string. High confidence due to attack-specific string. -->

### YARA: cPGuard Go Implant (OPSSHIELD Infrastructure)

Detects the Go implant artifacts found on OPSSHIELD's internal servers -- relevant for organizations with similar tooling or infrastructure connections.

**Compile:** ✅ (`yarac` exit 0) | **Confidence:** medium

```yara
rule SupplyChain_cPGuard_GoImplant_Infra
{
    meta:
        description = "Detects Go implant artifacts found on OPSSHIELD infrastructure during the cPGuard supply chain attack. The implant masqueraded as system processes."
        author = "Actioner"
        date = "2026-11-09"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"
        severity = "high"
        tlp = "WHITE"

    strings:
        $fake_proc1 = "[slub_flushwq]" ascii
        $fake_proc2 = "[rcu_gp]" ascii
        $implant_name1 = "pythno3" ascii
        $implant_name2 = "netstat.cfg" ascii
        $implant_name3 = "system.mark" ascii
        $implant_name4 = "libgdi.so.0.8.2" ascii
        $hiding_script = "gateway.sh" ascii

    condition:
        filesize < 50MB and
        (
            2 of ($fake_proc*) or
            3 of ($implant_name*) or
            ($hiding_script and 1 of ($fake_proc*))
        )
}
```

<!-- Audit: Compiled with yarac exit 0. Medium confidence because individual strings (e.g., gateway.sh, rcu_gp) can appear in legitimate contexts; the rule requires combinations to reduce FPs. Primarily relevant for OPSSHIELD infrastructure or similar hosting providers. -->

### Suricata: Outbound Connection to Attacker IP

Detects any outbound IP traffic to the known attacker address.

**Compile:** ✅ (`suricata -T` exit 0) | **Confidence:** high

```
alert ip $HOME_NET any -> 94.183.188.91 any (msg:"Actioner - cPGuard Supply Chain Attack - Outbound Connection to Attacker IP 94.183.188.91"; classtype:trojan-activity; reference:url,thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html; metadata:author Actioner, created_at 2026-11-09; sid:2100101; rev:1;)
```

<!-- Audit: Validated with suricata -T -S exit 0. IP-based rule, high confidence. Will need removal when IP is reassigned. -->

### Suricata: Spoofed cPGuard User Agent

Detects HTTP traffic with the spoofed cPGuard/5.88.11 user agent string.

**Compile:** ✅ (`suricata -T` exit 0) | **Confidence:** medium

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - cPGuard Supply Chain Attack - Spoofed cPGuard User Agent in HTTP Request"; flow:established,to_server; http.user_agent; content:"cPGuard/5.88.11"; fast_pattern; classtype:trojan-activity; reference:url,opsshield.com/notice/security-incident-disclosure-servermanage.html; metadata:author Actioner, created_at 2026-11-09; sid:2100102; rev:1;)
```

<!-- Audit: Validated with suricata -T -S exit 0. Medium confidence -- legitimate cPGuard 5.88.11 instances generate identical UA. Best used in correlation. -->

### Suricata: Exfiltration URI Pattern _rx.php

Detects HTTP requests to `_rx.php` endpoints used for data exfiltration.

**Compile:** ✅ (`suricata -T` exit 0) | **Confidence:** medium

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - cPGuard Supply Chain Attack - Exfiltration URI Pattern _rx.php"; flow:established,to_server; http.uri; content:"_rx.php"; fast_pattern; classtype:trojan-activity; reference:url,opsshield.com/notice/security-incident-disclosure-servermanage.html; metadata:author Actioner, created_at 2026-11-09; sid:2100103; rev:1;)
```

<!-- Audit: Validated with suricata -T -S exit 0. Medium confidence -- _rx.php is a short pattern that may appear in legitimate web applications. Best used in correlation with other indicators. -->

### Snort: Outbound Connection to Attacker IP

Detects outbound IP traffic to the known attacker address.

**Compile:** ⚠️ uncompiled (snort binary not available) | **Confidence:** high

```
alert ip $HOME_NET any -> 94.183.188.91 any (msg:"Actioner - cPGuard Supply Chain Attack - Outbound to Attacker IP 94.183.188.91"; classtype:trojan-activity; reference:url,thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html; metadata:author Actioner, created 2026-11-09; sid:2100201; rev:1;)
```

<!-- Audit: Structural check only -- snort binary not available. IP-based rule, msg/sid/rev present, semicolons balanced. -->

### Snort: Spoofed cPGuard User Agent

Detects HTTP traffic with the spoofed cPGuard/5.88.11 user agent.

**Compile:** ⚠️ uncompiled (snort binary not available) | **Confidence:** medium

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - cPGuard Supply Chain Attack - Spoofed cPGuard/5.88.11 User Agent"; flow:established, to_server; http_header; content:"cPGuard/5.88.11", fast_pattern; classtype:trojan-activity; reference:url,opsshield.com/notice/security-incident-disclosure-servermanage.html; metadata:author Actioner, created 2026-11-09; sid:2100202; rev:1;)
```

<!-- Audit: Structural check only. Uses http_header (Snort 3 underscore notation, not Suricata dot notation). -->

### Snort: Exfiltration URI Pattern _rx.php

Detects HTTP requests to `_rx.php` exfiltration endpoints.

**Compile:** ⚠️ uncompiled (snort binary not available) | **Confidence:** medium

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - cPGuard Supply Chain Attack - Exfiltration URI Pattern _rx.php"; flow:established, to_server; http_uri; content:"_rx.php", fast_pattern; classtype:trojan-activity; reference:url,opsshield.com/notice/security-incident-disclosure-servermanage.html; metadata:author Actioner, created 2026-11-09; sid:2100203; rev:1;)
```

<!-- Audit: Structural check only. Uses http_uri (Snort 3 underscore notation). -->

## Lessons Learned

1. **Security products are high-value supply chain targets.** cPGuard's root-level auto-update mechanism gave the attacker immediate root access to thousands of servers through a single compromise of the vendor's infrastructure. Security tooling must undergo the same supply chain hardening it defends against.

2. **Billing and licensing infrastructure is part of the attack surface.** The attacker did not need to compromise the update infrastructure directly -- they pivoted through the billing portal, a less-hardened component, to steal the update-signing key. Separation of concerns (billing vs. code signing vs. update distribution) with independent credential stores is essential.

3. **Update channel integrity requires cryptographic verification.** The attacker was able to push unsigned or weakly-verified updates because the signing key was stored accessibly from the licensing server. Update signing keys should be stored in HSMs or air-gapped systems, and clients should verify signatures independently before executing any update.

4. **Short attack windows can still have massive impact.** Despite the malicious update being live for only ~72 minutes, approximately 2,950 servers were compromised. Auto-update polling intervals mean even brief compromises of update channels can achieve wide distribution.

5. **Defense-in-depth detection is critical.** Organizations should monitor not just for known malicious indicators but also for behavioral anomalies such as security products creating hidden directories, dropping setuid binaries, or archiving sensitive credential files.

## Sources

- [The Hacker News - cPGuard Update Channel Hijacked](https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html) -- primary reporting with IOCs, timeline, and remediation steps
- [OPSSHIELD - Update Channel Compromise Notice](https://opsshield.com/notice/cpguard-update-channel-compromise.html) -- vendor primary disclosure with affected versions and remediation
- [OPSSHIELD - Security Incident Disclosure (ServerManage)](https://opsshield.com/notice/security-incident-disclosure-servermanage.html) -- detailed vendor disclosure with comprehensive IOCs, infrastructure compromise details, and timeline
- [SecurityWeek - Malicious cPGuard Updates Served in OpsShield Supply Chain Attack](https://www.securityweek.com/malicious-cpguard-updates-served-in-opsshield-supply-chain-attack/) -- secondary reporting with remediation context
- [Aviatrix - cPGuard Autoupdate Hijack 2026](https://aviatrix.ai/threat-research-center/hackers-hijack-cpguard-autoupdate-backdoor-steal-data-2026/) -- third-party analysis with MITRE ATT&CK mapping
- [Shattered.io - cPGuard Supply Chain Attack: 2,950 Servers Hit](https://shattered.io/opsshield-cpguard-supply-chain-attack-2950-servers-root-2026/) -- secondary reporting
- [Bellator Cyber - cPGuard OpsShield Supply Chain Attack](https://bellatorcyber.com/blog/cpguard-opsshield-supply-chain-attack) -- secondary analysis with remediation guidance

---
*Report generated by Actioner*
