# Technical Analysis Report: cPGuard Update Channel Supply Chain Attack (November 2026)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-06
Version: 1.0 (FINAL)

## Executive Summary

On November 2, 2026, an unknown threat actor compromised the update distribution channel of cPGuard, a Linux server security product developed by JETWEB (branded OPSSHIELD), and pushed a malicious shell script to approximately 2,950 production Linux servers. The attacker registered a trial account on November 1, pivoted to the billing server within hours, and then injected a credential-harvesting payload into the cPGuard auto-update mechanism. The malicious update (versions 5.88.12 through 5.88.19) executed a shell script that exfiltrated `/etc/shadow`, SSH private keys, MySQL credentials (`/root/.my.cnf`), S3 configuration (`/root/.s3cfg`), and shell history from every affected host. Harvested data was staged in a hidden directory, archived, and sent to attacker-controlled infrastructure at 94.183.188[.]91. The attacker also deployed a setuid-root backdoor shell and a cron-based persistence mechanism. The vendor released a clean version (5.88.26) the same day, but all credentials on impacted hosts should be considered compromised.

## Background: cPGuard

cPGuard is a commercial security and malware-scanning product for Linux servers, commonly deployed on cPanel/WHM and Plesk hosting environments. It is distributed by OPSSHIELD (formerly JETWEB) and runs as a privileged daemon that receives automatic updates from the vendor's infrastructure. Because cPGuard operates with root privileges and updates are applied automatically, a compromise of the update channel is equivalent to root-level code execution on every subscribed server -- a textbook software supply chain risk.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-11-01 (daytime) | Attacker registers a trial cPGuard account |
| 2026-11-01 22:58 | Attacker gains unauthorized access to the billing/management server |
| 2026-11-02 02:04 | First malicious update payload (`cpguard-v58812-i91511.sh`) pushed to the update channel |
| 2026-11-02 02:04-02:09 | Multiple script variants (b, c, d) pushed in rapid succession |
| 2026-11-02 (morning) | OPSSHIELD detects anomaly, begins investigation |
| 2026-11-02 (day) | Clean version 5.88.26 released; advisory published at manage.opsshield[.]com |

## Root Cause: Update Channel Hijacking via Billing Server Compromise

The attacker compromised the OPSSHIELD billing/management server, which had access to the cPGuard update distribution mechanism. Starting from a trial account registration (a low-privilege entry point), the attacker escalated to administrative access on the billing server within approximately 25 hours. The exact escalation path has not been publicly disclosed. Once the attacker controlled the update channel, they pushed malicious shell scripts that were automatically downloaded and executed with root privileges by every cPGuard installation running versions 5.88.12 through 5.88.19.

## Technical Analysis of the Malicious Payload

### 1. Delivery: Supply Chain Update Injection

The malicious payload was delivered as a shell script through cPGuard's legitimate auto-update mechanism. Four script variants were pushed in quick succession during a five-minute window:

- `cpguard-v58812-i91511.sh` -- initial payload
- `cpguard-v58812-i91511b.sh` -- variant B
- `cpguard-v58812-i91511c.sh` -- variant C
- `cpguard-v58812-i91511d.sh` -- variant D

The naming convention mimics legitimate cPGuard update scripts (version prefix `v58812`), with the `i91511` identifier appearing to be an attacker-chosen campaign tag.

### 2. Credential Harvesting and Data Collection

Upon execution with root privileges, the script created a hidden staging directory at `/var/tmp/.cpg91511/` and systematically copied sensitive files:

- **`/etc/shadow`** and **`/etc/passwd`** -- system account credentials (password hashes)
- **`/root/.ssh/*`** -- SSH private keys, authorized_keys, known_hosts
- **`/root/.my.cnf`** -- MySQL root credentials (commonly stored in plaintext)
- **`/root/.s3cfg`** -- AWS S3 access keys and secrets
- **Root shell history** -- command history potentially containing credentials, API keys, and operational intelligence

The collected data was packaged into `/var/tmp/.cpg91511/loot.tgz` using tar/gzip.

### 3. C2 Infrastructure

| Type | Value | Role |
|------|-------|------|
| IP | 94.183.188[.]91 | Primary attacker operating address; exfiltration target |

The archived loot package was exfiltrated to 94.183.188[.]91. The IP is allocated to an Iranian ISP (AS44244 - Irancell), though this does not necessarily indicate attacker origin as the host may be a compromised intermediary or VPN exit node.

### 4. Platform-Specific Behavior

#### Linux (sole target)

This attack exclusively targets Linux servers running the cPGuard security product. All payloads are POSIX shell scripts executed as root. The attack leverages Linux-specific paths (`/etc/shadow`, `/root/.ssh/`), utilities (`tar`, `chmod`), and persistence mechanisms (`/etc/cron.d/`, setuid bits).

### 5. Persistence Mechanisms

The attacker deployed two persistence mechanisms:

**Setuid-root backdoor shell:**
A copy of a shell binary was placed at `/var/tmp/.cpg91511_sh` with the setuid bit set. This allows any local user (or attacker with any-user access) to obtain a root shell without authentication, surviving credential rotation.

**Cron-based scheduled task:**
A cron job was installed at `/etc/cron.d/i93677` with supporting files in `/var/tmp/.i93677/`. This provides periodic re-execution capability, likely for maintaining C2 callbacks or re-harvesting credentials if the initial exfiltration failed.

### 6. Anti-Forensics / Evasion Techniques

- **Hidden directories**: Use of dot-prefixed directories (`.cpg91511`, `.i93677`) to avoid casual directory listing
- **`/var/tmp/` staging**: Use of `/var/tmp/` rather than `/tmp/` to survive reboots and tmpwatch cleanup
- **Legitimate update channel**: Delivery via trusted software update mechanism bypasses most endpoint detection and integrity monitoring
- **Rapid iteration**: Four script variants pushed in 5 minutes suggests the attacker was refining the payload in real-time or targeting different configurations

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `94.183.188[.]91`)
> - URLs: `hxxps://` (e.g., `hxxps://manage.opsshield[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| cPGuard | 5.88.12 -- 5.88.19 | Compromised update channel delivering malicious shell scripts |
| cPGuard | 5.88.26 | Clean version (fixed) |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `cpguard-v58812-i91511.sh` | `2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38` | Initial malicious update script |
| Linux | `cpguard-v58812-i91511b.sh` | `ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a` | Variant B |
| Linux | `cpguard-v58812-i91511c.sh` | `d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26` | Variant C |
| Linux | `cpguard-v58812-i91511d.sh` | `6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77` | Variant D |
| Linux | `/var/tmp/.cpg91511/` | -- | Hidden staging directory for harvested data |
| Linux | `/var/tmp/.cpg91511/loot.tgz` | -- | Archived credential package |
| Linux | `/var/tmp/.cpg91511_sh` | -- | Setuid-root backdoor shell |
| Linux | `/etc/cron.d/i93677` | -- | Persistence cron job |
| Linux | `/var/tmp/.i93677/` | -- | Persistence support directory |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 94.183.188[.]91 | Primary attacker IP; data exfiltration and C2 |

### Behavioral

- Creation of hidden dot-prefixed directories under `/var/tmp/` by a security product update process
- Bulk access to `/etc/shadow`, `/root/.ssh/*`, `/root/.my.cnf`, and `/root/.s3cfg` in rapid sequence
- `tar`/`gzip` archiving of files from a hidden `/var/tmp/` directory
- `chmod +s` applied to a binary in `/var/tmp/`
- Cron job creation in `/etc/cron.d/` referencing hidden directories in `/var/tmp/`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker hijacked the cPGuard update channel to push malicious scripts to ~2,950 servers |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Payload delivered and executed as a POSIX shell script with root privileges |
| T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Script harvested /etc/shadow and /etc/passwd for offline password cracking |
| T1552.004 | Unsecured Credentials: Private Keys | SSH private keys, MySQL credentials, and S3 access keys stolen from root home directory |
| T1053.003 | Scheduled Task/Job: Cron | Persistence via /etc/cron.d/i93677 scheduled task |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | Hidden setuid-root shell binary at /var/tmp/.cpg91511_sh |
| T1560.001 | Archive Collected Data: Archive via Utility | Credential data archived as loot.tgz using tar/gzip before exfiltration |
| T1041 | Exfiltration Over C2 Channel | Archived data exfiltrated to 94.183.188[.]91 |
<!-- revision: defanged IP in ATT&CK table (was bare 94.183.188.91). -->

## Impact Assessment

**Breadth:** Approximately 2,950 Linux servers received the malicious update. These are predominantly web hosting servers running cPanel/WHM or Plesk, meaning each server likely hosts multiple customer websites and databases. The downstream impact could affect tens of thousands of hosted sites.

**Depth:** The attacker obtained root-level credentials, SSH keys, database passwords, and cloud storage keys from every affected host. This represents total compromise -- the attacker can return via any of these credential sets even after the malicious update is removed.

**Stealth:** Delivery via a trusted update channel means no anomalous download source appeared in logs. The five-minute attack window was extremely brief. The hidden directory naming and `/var/tmp/` staging were designed to avoid casual detection.

## Detection & Remediation

### Immediate Detection

Run the following commands on any server that had cPGuard versions 5.88.12 through 5.88.19 installed:

```bash
# Check for staging directory and loot archive
ls -la /var/tmp/.cpg91511/ 2>/dev/null
ls -la /var/tmp/.cpg91511_sh 2>/dev/null

# Check for persistence cron job
ls -la /etc/cron.d/i93677 2>/dev/null
ls -la /var/tmp/.i93677/ 2>/dev/null

# Check for setuid files in /var/tmp
find /var/tmp -perm -4000 -type f 2>/dev/null

# Search for the script file names
find / -name "cpguard-v58812-i91511*" -type f 2>/dev/null

# Check for connections to attacker IP
grep -r "94.183.188.91" /var/log/ 2>/dev/null
ss -tnp | grep "94.183.188.91"
```

### Remediation

1. **Immediate containment:** Block outbound traffic to 94.183.188[.]91 at the network/firewall level.
2. **Remove persistence artifacts:**
   - `rm -f /var/tmp/.cpg91511_sh`
   - `rm -rf /var/tmp/.cpg91511/`
   - `rm -f /etc/cron.d/i93677`
   - `rm -rf /var/tmp/.i93677/`
3. **Update cPGuard** to version 5.88.26 or later.
4. **Rotate ALL credentials** on affected hosts:
   - All system user passwords (especially root)
   - All SSH keys (regenerate key pairs; revoke old public keys from all authorized_keys files on remote systems)
   - MySQL/MariaDB root and application passwords
   - AWS S3 access keys and secrets referenced in `/root/.s3cfg`
   - Any API keys or tokens visible in root shell history
5. **Audit SSH authorized_keys** on all systems for unauthorized additions.
6. **Review cron jobs** system-wide for unrecognized entries.
7. **Check for additional backdoors** -- the setuid shell may have been used to deploy further payloads.

### Long-Term Hardening

- **Pin and verify software updates:** Implement cryptographic signature verification for all third-party security tools. Do not auto-apply updates from vendors without GPG/code signature checks.
- **Restrict outbound network access** from servers to only necessary destinations.
- **Credential hygiene:** Avoid storing plaintext credentials in dotfiles (`~/.my.cnf`, `~/.s3cfg`). Use credential managers, IAM roles, or vault solutions instead.
- **File integrity monitoring (FIM):** Deploy FIM on critical directories (`/etc/cron.d/`, `/var/tmp/`) to detect unexpected file creation.
- **Setuid monitoring:** Alert on any new setuid binaries, especially outside of standard system paths.

## Detection Rules

These rules target the specific artifacts of the cPGuard supply chain attack (November 2026): staging directories, persistence mechanisms, credential harvesting patterns, and the known attacker IP. They are tuned for high-confidence, low-false-positive detection of this specific campaign. The one caveat is that file event rules require auditd or an equivalent file monitoring agent configured on the target paths.

### Sigma: Staging Directory and Backdoor File Creation

Detects creation of the hidden staging directory `/var/tmp/.cpg91511/` or the setuid backdoor shell `/var/tmp/.cpg91511_sh`.

Compile: Splunk ✅, LogScale ✅ | Confidence: **high**

```yaml
title: cPGuard Supply Chain Attack - Staging Directory Creation
id: 1bdef533-9737-45f3-8a6c-661460ae5e1e
status: experimental
description: >
    Detects creation of hidden staging directory /var/tmp/.cpg91511/ used by the
    cPGuard supply chain attack to collect harvested credentials and SSH keys
    before archiving and exfiltration.
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://manage.opsshield.com
author: Actioner
date: 2026-11-06
tags:
    - attack.t1074.001
logsource:
    category: file_event
    product: linux
detection:
    selection_staging:
        TargetFilename|contains:
            - '/var/tmp/.cpg91511/'
            - '/var/tmp/.cpg91511_sh'
    condition: selection_staging
falsepositives:
    - Unlikely. The path is specific to this attack campaign.
level: critical
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk (output: TargetFilename IN ("*/var/tmp/.cpg91511/*", "*/var/tmp/.cpg91511_sh*")) and -t log_scale. No encoding or FP-evasion concerns; path strings are campaign-unique IOCs. -->
<!-- revision: removed attack.t1560.001 tag — rule detects file creation (staging), not archiving; T1074.001 alone is accurate. -->

### Sigma: Cron Persistence via i93677

Detects creation of the malicious cron job `/etc/cron.d/i93677` or the associated persistence directory `/var/tmp/.i93677/`.

Compile: Splunk ✅, LogScale ✅ | Confidence: **high**

```yaml
title: cPGuard Supply Chain Attack - Cron Persistence via i93677
id: 44aaa84c-84eb-4750-ab49-079d4a276102
status: experimental
description: >
    Detects creation of the malicious cron job /etc/cron.d/i93677 and the
    associated persistence directory /var/tmp/.i93677/ dropped by the cPGuard
    supply chain attack for maintaining access on compromised Linux servers.
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://manage.opsshield.com
author: Actioner
date: 2026-11-06
tags:
    - attack.t1053.003
logsource:
    category: file_event
    product: linux
detection:
    selection_cron:
        TargetFilename|endswith: '/cron.d/i93677'
    selection_persist_dir:
        TargetFilename|contains: '/var/tmp/.i93677/'
    condition: selection_cron or selection_persist_dir
falsepositives:
    - Unlikely. The cron job name and hidden directory are specific to this campaign.
level: critical
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale. IOC-specific path match; no encoding considerations. -->

### Sigma: Credential Harvesting Commands

Detects process execution referencing both the staging path and sensitive credential files being harvested.

Compile: Splunk ✅, LogScale ✅ | Confidence: **high**

```yaml
title: cPGuard Supply Chain Attack - Credential Harvesting Commands
id: 823b93bf-b467-4fee-bfc0-8f9ef1bd7407
status: experimental
description: >
    Detects process execution patterns consistent with the cPGuard supply chain
    attack credential harvesting stage, where /etc/shadow, SSH keys, MySQL
    credentials, and S3 configs are copied into a hidden staging directory.
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://manage.opsshield.com
author: Actioner
date: 2026-11-06
tags:
    - attack.t1003.008
    - attack.t1552.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_staging_path:
        CommandLine|contains: '/var/tmp/.cpg91511'
    selection_sensitive_files:
        CommandLine|contains:
            - '/etc/shadow'
            - '/root/.ssh/'
            - '/root/.my.cnf'
            - '/root/.s3cfg'
    condition: selection_staging_path and selection_sensitive_files
falsepositives:
    - Backup scripts that reference both /var/tmp/.cpg91511 and sensitive credential files simultaneously (extremely unlikely).
level: critical
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale. AND logic between staging path and sensitive file reference eliminates FPs; requires process_creation logging (auditd or osquery). -->

### Sigma: Setuid Root Backdoor Shell

Detects `chmod +s` targeting the campaign-specific backdoor shell path `/var/tmp/.cpg91511`.

Compile: Splunk ✅, LogScale ✅ | Confidence: **high**

```yaml
title: cPGuard Supply Chain Attack - Setuid Root Backdoor Shell
id: 15dcdf03-1779-4f3b-bfd0-104403d6e471
status: experimental
description: >
    Detects chmod commands setting the setuid bit on the hidden backdoor shell
    /var/tmp/.cpg91511_sh deployed by the cPGuard supply chain attack as a
    persistent root-level backdoor.
references:
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://manage.opsshield.com
author: Actioner
date: 2026-11-06
tags:
    - attack.t1548.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_chmod_setuid:
        Image|endswith: '/chmod'
        CommandLine|contains|all:
            - '+s'
            - '/var/tmp/.cpg91511'
    condition: selection_chmod_setuid
falsepositives:
    - Unlikely. The path is specific to this attack campaign.
level: critical
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale. Artifact-specific path match; confidence upgraded to high now that detection keys on campaign path, not any /var/tmp/ file. -->
<!-- revision: narrowed CommandLine|contains from '/var/tmp/' to '/var/tmp/.cpg91511' per critic verdict — resolves altitude mismatch. Description and confidence aligned. -->

### YARA: Malicious cPGuard Update Script Content

Matches on the combination of campaign-specific strings found in the malicious shell scripts: staging paths, loot archive name, persistence artifacts, and attacker IP.

Compile: yarac ✅ | Confidence: **high**

```yara
rule SupplyChain_cPGuard_Malicious_Update_Script
{
    meta:
        description = "Detects the malicious shell scripts pushed via the cPGuard update channel supply chain attack (Nov 2026). Matches on staging directory paths, loot archive name, credential harvesting targets, and persistence artifacts unique to this campaign."
        author = "Actioner"
        date = "2026-11-06"
        reference = "https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html"
        hash = "2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38"
        hash = "ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a"
        hash = "d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26"
        hash = "6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $staging_dir   = "/var/tmp/.cpg91511" ascii
        $loot_archive  = "loot.tgz" ascii
        $backdoor_path = "/var/tmp/.cpg91511_sh" ascii
        $cron_persist  = "/etc/cron.d/i93677" ascii
        $persist_dir   = "/var/tmp/.i93677" ascii

        $harvest1 = "/etc/shadow" ascii
        $harvest2 = "/root/.ssh/" ascii
        $harvest3 = "/root/.my.cnf" ascii
        $harvest4 = "/root/.s3cfg" ascii

        $script_name1 = "cpguard-v58812-i91511" ascii
        $attacker_ip  = "94.183.188.91" ascii

    condition:
        filesize < 1MB and
        (
            ($staging_dir and $loot_archive) or
            ($staging_dir and 2 of ($harvest*)) or
            ($backdoor_path and $cron_persist) or
            ($script_name1 and $attacker_ip) or
            (3 of ($staging_dir, $backdoor_path, $cron_persist, $persist_dir, $loot_archive))
        )
}
```

<!-- audit: validated via yarac (exit 0). Condition requires multiple campaign-specific strings co-occurring; individual strings like "/etc/shadow" alone will not trigger. The loot_archive string "loot.tgz" is generic but only matches when paired with the staging path. filesize < 1MB scopes to scripts. -->

### Suricata: Outbound Traffic to Attacker IP

Alerts on any outbound IP traffic to the known attacker address 94.183.188[.]91.

Compile: suricata -T ✅ | Confidence: **high**

```
alert ip $HOME_NET any -> 94.183.188.91 any (msg:"Actioner - cPGuard Supply Chain Attack - Outbound Traffic to Attacker IP 94.183.188.91"; flow:to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html; metadata:author Actioner, created_at 2026-11-06, mitre_attack T1041; sid:9000001; rev:1;)
```

<!-- audit: validated via suricata -T -S (exit 0, "Configuration provided was successfully loaded"). IP-based rule; confidence is high while the IP remains attacker-controlled but will decay as the IP is reassigned or rotated. Single-IP match with no content inspection keeps engine overhead minimal. -->
<!-- revision: moved SID from 2100100 (Emerging Threats reserved range) to 9000001 (local/custom range). -->

## Lessons Learned

1. **Auto-update trust is a liability.** cPGuard's automatic update mechanism gave the attacker a root-level code execution primitive on every subscribed server. Security products that run as root must implement cryptographic signature verification on every update payload, not just TLS transport security.

2. **Billing systems are attack surface.** The attacker's path to the update channel ran through the billing/management server -- a system typically maintained by a different team with different security standards. Any system with write access to software distribution infrastructure must be treated as tier-zero.

3. **Credential sprawl amplified the blast radius.** The attack was devastating because servers routinely stored plaintext credentials in dotfiles (`~/.my.cnf`, `~/.s3cfg`). A single compromised host yields not just system access but lateral movement into databases and cloud services. Credential vaulting and IAM-based authentication would have significantly limited post-compromise impact.

4. **Detection requires endpoint telemetry.** Without file integrity monitoring or process auditing (auditd), this attack leaves minimal forensic evidence. Organizations running third-party security products should monitor the behavior of those products, not just rely on them for monitoring.

## Sources

- [The Hacker News](https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html) -- primary public reporting on the cPGuard update channel compromise, timeline, and IOCs
- [OPSSHIELD Disclosure](https://manage.opsshield.com) -- vendor disclosure and advisory with affected version details and remediation guidance

---
*Report generated by Actioner*
