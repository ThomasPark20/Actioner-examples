# cPGuard (OpsShield) Supply Chain Attack — Technical Analysis

> **Status:** DRAFT  
> **Date:** 2026-11-04  
> **TLP:** CLEAR  
> **Severity:** Critical  

---

## Executive Summary

On November 2, 2026, an attacker compromised credentials for OpsShield's (formerly cPGuard) update distribution system and pushed malicious update scripts to Linux servers running cPGuard security software. Versions 5.88.12 through 5.88.19 contained a shell script that installed a persistent backdoor, harvested sensitive system files (credentials, SSH keys, database configs, shell history), staged them in a hidden directory, and exfiltrated the archive via the OpsShield licensing server. The attack was detected within 12 hours. OpsShield estimates 32 files were taken from the licensing server. No file hashes, C2 IP addresses, or exfiltration domains have been publicly disclosed, limiting network-layer detection to behavioral patterns.

---

## Background

cPGuard is a server security suite widely deployed on Linux web hosting servers (cPanel, Plesk, DirectAdmin environments). In 2026, the product rebranded to OpsShield. The software receives updates through a centralized update channel that pushes versioned shell scripts to enrolled servers for execution with root privileges — a design that makes the update channel a high-value supply chain target.

---

## Technical Analysis

### Update Mechanism Compromise

- **Initial Access:** At 02:06 UTC on November 2, 2026, the attacker authenticated to OpsShield's update distribution system using compromised credentials. The method of credential compromise has not been disclosed.
- **Malicious Distribution:** The attacker pushed tainted updates labeled versions **5.88.12 through 5.88.19**. Each version delivered the malicious payload script `cpguard-v58812-i91511.sh` to target servers through the legitimate update channel.
- **Trust Abuse:** Because cPGuard updates execute as root, the malicious script inherited full system privileges on every server that pulled the update.

### Malicious Script Behavior

The payload script `cpguard-v58812-i91511.sh` performed the following actions:

1. **Backdoor Installation:** Created a hidden backdoor shell at `/var/tmp/.cpg91511_sh`, providing persistent access to the compromised host.
2. **Staging Directory Creation:** Created the hidden directory `/var/tmp/.cpg91511/` to stage collected data prior to exfiltration.

### Data Collection

The script targeted high-value system files:

| Target File | Intelligence Value |
|---|---|
| `/etc/shadow` | Hashed user passwords — offline cracking yields plaintext credentials |
| `/etc/passwd` | User account enumeration, service accounts, home directories |
| Root's `my.cnf` | MariaDB/MySQL credentials in plaintext |
| Root's `.bash_history` | Command history — may reveal credentials, internal hostnames, architecture |
| Root's `authorized_keys` | SSH public keys — identifies trusted hosts and lateral movement paths |
| Root's `known_hosts` | SSH host fingerprints — maps internal infrastructure |

### Data Exfiltration

Collected files were archived into `/var/tmp/.cpg91511/loot.tgz` and uploaded to the OpsShield licensing server using the same compromised account. This is a notable tradecraft choice: exfiltrating through a trusted, already-whitelisted endpoint avoids triggering network-based detections for connections to unknown external hosts.

OpsShield estimated **32 files** were taken from the licensing server before containment.

---

## Indicators of Compromise

### File System Artifacts

| Type | Indicator | Context |
|---|---|---|
| Script | `cpguard-v58812-i91511.sh` | Malicious update payload |
| Backdoor | `/var/tmp/.cpg91511_sh` | Hidden backdoor shell |
| Directory | `/var/tmp/.cpg91511/` | Data staging directory |
| Archive | `/var/tmp/.cpg91511/loot.tgz` | Exfiltration archive |

### Affected Versions

| Indicator | Value |
|---|---|
| Malicious versions | 5.88.12 through 5.88.19 |
| Fixed version | 5.88.25+ |

### Detection Check (Host-Based)

Run on potentially affected servers:

```bash
grep 'Successfully updated' /opt/cpguard/logs/install_log
```

An entry referencing versions 5.88.12 through 5.88.19 confirms the malicious update was installed.

### Network Indicators

**N/A** — No C2 IP addresses, exfiltration domains, or network-layer IOCs have been published. Exfiltration was conducted through the legitimate OpsShield licensing infrastructure.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Application |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker hijacked the cPGuard update channel to distribute malicious scripts |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Malicious payload delivered as a bash shell script |
| T1005 | Data from Local System | Collection of /etc/shadow, /etc/passwd, my.cnf, bash_history, SSH keys |
| T1560.001 | Archive Collected Data: Archive via Utility | Sensitive files packed into loot.tgz before exfiltration |
| T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Direct theft of credential files for offline password cracking |
| T1074.001 | Data Staged: Local Data Staging | Hidden directory /var/tmp/.cpg91511/ used as collection staging area |

---

## Detection & Remediation

### Immediate Actions

1. **Check for compromise:** Run the detection check above on all servers with cPGuard/OpsShield installed.
2. **Search for artifacts:** Check for the existence of `/var/tmp/.cpg91511_sh`, `/var/tmp/.cpg91511/`, and `/var/tmp/.cpg91511/loot.tgz`.
3. **Update immediately:** Upgrade to cPGuard/OpsShield version **5.88.25 or later**.
4. **If compromised:**
   - Rotate all passwords (system users, MariaDB/MySQL root).
   - Regenerate SSH key pairs and clear `authorized_keys` / `known_hosts`.
   - Audit `.bash_history` for any credentials or sensitive commands that were exposed.
   - Review MariaDB/MySQL `my.cnf` for exposed credentials and rotate them.
   - Assume full root compromise and investigate for additional persistence mechanisms.
5. **Monitor:** Deploy the detection rules below to identify any residual artifacts or similar activity.

### Longer-Term Recommendations

- Evaluate whether cPGuard/OpsShield update scripts should be subject to integrity verification (e.g., code signing) before execution.
- Restrict outbound connections from production servers to only required endpoints.
- Implement file integrity monitoring (FIM) on sensitive files and /var/tmp.

---

## Detection Rules

### Sigma Rules

#### Rule 1: Staging Directory and Backdoor File Creation

Detects creation of files at the published attack artifact paths. High-fidelity due to distinctive hidden directory and file naming.
<!-- audit: keys on /var/tmp/.cpg91511* paths from advisory; no hash IOCs; unique naming convention virtually eliminates FP -->

- **File:** `/tmp/actioner/sigma_cpguard_file_creation.yml`
- **Compile:** PASS (sigma convert --without-pipeline -t splunk, -t log_scale)
- **Confidence:** High

```yaml
title: cPGuard Supply Chain Attack - Staging Directory and Backdoor File Creation
id: 7a3e1d4b-9c2f-4e8a-b5d6-1f0a3c7e9b2d
status: experimental
description: >
  Detects creation of files associated with the cPGuard/OpsShield supply chain attack
  (Nov 2, 2026), including the backdoor shell and staging directory artifacts.
references:
  - https://www.opsshield.com/cpguard-security-incident-nov-2026/
  - https://thehackernews.com/2026/11/cpguard-supply-chain-attack.html
author: CTI Analyst
date: 2026-11-04
tags:
  - attack.t1195.002
  - attack.t1059.004
logsource:
  category: file_event
  product: linux
detection:
  selection_staging:
    TargetFilename|startswith: '/var/tmp/.cpg91511'
  selection_backdoor:
    TargetFilename: '/var/tmp/.cpg91511_sh'
  selection_loot:
    TargetFilename: '/var/tmp/.cpg91511/loot.tgz'
  condition: selection_staging or selection_backdoor or selection_loot
falsepositives:
  - Unlikely - highly specific artifact paths unique to this attack
level: critical
```

#### Rule 2: Malicious Update Script Execution

Detects execution of the specific malicious script filename pushed through the compromised update channel.
<!-- audit: exact filename from advisory; no hash; unique script name prefix+suffix pattern -->

- **File:** `/tmp/actioner/sigma_cpguard_script_exec.yml`
- **Compile:** PASS (sigma convert --without-pipeline -t splunk, -t log_scale)
- **Confidence:** High

```yaml
title: cPGuard Supply Chain Attack - Malicious Update Script Execution
id: 2b8f6e1a-4d3c-5a7b-9e0f-8c2d1b6a4f3e
status: experimental
description: >
  Detects execution of the malicious cPGuard update script cpguard-v58812-i91511.sh
  distributed via the compromised OpsShield update channel on Nov 2, 2026.
references:
  - https://www.opsshield.com/cpguard-security-incident-nov-2026/
  - https://thehackernews.com/2026/11/cpguard-supply-chain-attack.html
author: CTI Analyst
date: 2026-11-04
tags:
  - attack.t1195.002
  - attack.t1059.004
logsource:
  category: process_creation
  product: linux
detection:
  selection_script_name:
    CommandLine|contains: 'cpguard-v58812-i91511.sh'
  selection_script_image:
    Image|endswith: '/cpguard-v58812-i91511.sh'
  condition: selection_script_name or selection_script_image
falsepositives:
  - Unlikely - highly specific malicious script name
level: critical
```

#### Rule 3: Sensitive File Access by cPGuard Process

Detects cPGuard-related processes accessing /etc/shadow or /etc/passwd, indicating credential harvesting. Caveat: legitimate cPGuard scanning may trigger this — tune per environment.
<!-- audit: behavioral rule; cpguard processes reading shadow is abnormal for security product; tuning may be needed -->

- **File:** `/tmp/actioner/sigma_cpguard_shadow_access.yml`
- **Compile:** PASS (sigma convert --without-pipeline -t splunk, -t log_scale)
- **Confidence:** Medium

```yaml
title: cPGuard Supply Chain Attack - Sensitive File Access by cPGuard Process
id: 3c9a7f2b-5e4d-6b8c-a1e0-9d3f2c7b5a4e
status: experimental
description: >
  Detects access to /etc/shadow or /etc/passwd by processes related to cPGuard,
  indicating potential credential harvesting as part of the supply chain attack.
references:
  - https://www.opsshield.com/cpguard-security-incident-nov-2026/
  - https://thehackernews.com/2026/11/cpguard-supply-chain-attack.html
author: CTI Analyst
date: 2026-11-04
tags:
  - attack.t1003.008
  - attack.t1005
logsource:
  category: file_access
  product: linux
detection:
  selection_process:
    Image|contains: 'cpguard'
  selection_files:
    TargetFilename:
      - '/etc/shadow'
      - '/etc/passwd'
  condition: selection_process and selection_files
falsepositives:
  - Legitimate cPGuard security scanning operations may access these files
level: high
```

#### Rule 4: Loot Archive Creation in Staging Directory

Detects tar/gzip activity targeting the known attack staging directory.
<!-- audit: combines archiver process with exact staging path; minimal FP surface -->

- **File:** `/tmp/actioner/sigma_cpguard_loot_archive.yml`
- **Compile:** PASS (sigma convert --without-pipeline -t splunk, -t log_scale)
- **Confidence:** High

```yaml
title: cPGuard Supply Chain Attack - Loot Archive Creation in Staging Directory
id: 4d0b8a3c-6f5e-7c9d-b2f1-0e4a3d8c6b5f
status: experimental
description: >
  Detects creation of the loot.tgz archive in the attack staging directory,
  indicating data collection and packaging for exfiltration.
references:
  - https://www.opsshield.com/cpguard-security-incident-nov-2026/
  - https://thehackernews.com/2026/11/cpguard-supply-chain-attack.html
author: CTI Analyst
date: 2026-11-04
tags:
  - attack.t1560.001
  - attack.t1005
logsource:
  category: process_creation
  product: linux
detection:
  selection_tar:
    Image|endswith:
      - '/tar'
      - '/gzip'
  selection_target:
    CommandLine|contains: '/var/tmp/.cpg91511'
  condition: selection_tar and selection_target
falsepositives:
  - Unlikely - specific to the known attack staging directory
level: critical
```

#### Rule 5: Suspicious Archive Creation in Hidden /var/tmp Directory

Broader behavioral rule detecting archive creation in hidden directories under /var/tmp. Caveat: may require tuning to exclude known benign tools.
<!-- audit: behavioral catch-all; hidden dirs in /var/tmp are uncommon for archiving; .snap/.java filtered; medium confidence due to FP potential -->

- **File:** `/tmp/actioner/sigma_cpguard_hidden_dir_archive.yml`
- **Compile:** PASS (sigma convert --without-pipeline -t splunk, -t log_scale)
- **Confidence:** Medium

```yaml
title: Suspicious Archive Creation in Hidden /var/tmp Directory
id: 5e1c9b4d-7a6f-8d0e-c3a2-1f5b4e9d7c6a
status: experimental
description: >
  Detects tar or gzip archive creation within hidden directories under /var/tmp,
  a behavioral pattern observed in the cPGuard supply chain attack for staging
  collected data before exfiltration.
references:
  - https://www.opsshield.com/cpguard-security-incident-nov-2026/
  - https://thehackernews.com/2026/11/cpguard-supply-chain-attack.html
author: CTI Analyst
date: 2026-11-04
tags:
  - attack.t1560.001
  - attack.t1074.001
logsource:
  category: process_creation
  product: linux
detection:
  selection_archiver:
    Image|endswith:
      - '/tar'
      - '/gzip'
  selection_hidden_tmp:
    CommandLine|contains: '/var/tmp/.'
  filter_known:
    CommandLine|contains:
      - '/var/tmp/.snap'
      - '/var/tmp/.java'
  condition: selection_archiver and selection_hidden_tmp and not filter_known
falsepositives:
  - Backup tools or package managers using hidden directories in /var/tmp
level: high
```

### YARA Rules

#### Rule 1: cPGuard Supply Chain Attack Artifacts (Composite)

Matches files containing the distinctive attack identifiers combined with credential file references. Requires the attack-specific strings plus evidence of credential targeting.
<!-- audit: composite rule requiring attack-specific + credential strings; low FP; no hashes available -->

- **File:** `/tmp/actioner/yara_cpguard_supply_chain.yar` (rule: `cpguard_supply_chain_attack_artifacts`)
- **Compile:** PASS (yarac)
- **Sample Match:** PASS (pos.txt matched both rules)
- **Confidence:** High

#### Rule 2: cPGuard Malicious Script Strings

Simpler rule matching any of the three most distinctive artifact strings. Useful for broad scanning.
<!-- audit: any-of-three rule; each string is unique to this attack; high confidence for initial triage -->

- **File:** `/tmp/actioner/yara_cpguard_supply_chain.yar` (rule: `cpguard_malicious_script_strings`)
- **Compile:** PASS (yarac)
- **Sample Match:** PASS (pos.txt matched)
- **Confidence:** High

```yara
rule cpguard_supply_chain_attack_artifacts
{
    meta:
        description = "Detects artifacts from the cPGuard/OpsShield supply chain attack (Nov 2, 2026)"
        author = "CTI Analyst"
        date = "2026-11-04"
        reference = "https://thehackernews.com/2026/11/cpguard-supply-chain-attack.html"
        severity = "critical"
        tlp = "white"

    strings:
        $script_name = "cpguard-v58812-i91511" ascii wide
        $staging_dir = ".cpg91511" ascii wide
        $backdoor = ".cpg91511_sh" ascii wide
        $loot_file = "loot.tgz" ascii wide
        $shadow = "/etc/shadow" ascii wide
        $passwd = "/etc/passwd" ascii wide
        $mysql_conf = "my.cnf" ascii wide
        $ssh_keys = "authorized_keys" ascii wide
        $known_hosts = "known_hosts" ascii wide
        $shell_history = ".bash_history" ascii wide
        $var_tmp_staging = "/var/tmp/.cpg91511" ascii wide

    condition:
        ($script_name or $staging_dir or $backdoor) and
        ($loot_file or $var_tmp_staging) and
        any of ($shadow, $passwd, $mysql_conf, $ssh_keys, $known_hosts, $shell_history)
}

rule cpguard_malicious_script_strings
{
    meta:
        description = "Detects the specific malicious script filename from the cPGuard supply chain attack"
        author = "CTI Analyst"
        date = "2026-11-04"
        reference = "https://thehackernews.com/2026/11/cpguard-supply-chain-attack.html"
        severity = "critical"
        tlp = "white"

    strings:
        $script = "cpguard-v58812-i91511.sh" ascii wide
        $staging = "/var/tmp/.cpg91511" ascii wide
        $backdoor = "/var/tmp/.cpg91511_sh" ascii wide

    condition:
        any of them
}
```

### Snort/Suricata Rules

**N/A** — No network-layer indicators (C2 IP addresses, exfiltration domains, or distinctive HTTP/DNS patterns) have been published for this incident. Exfiltration was conducted through the legitimate OpsShield licensing infrastructure, making signature-based network detection infeasible without additional IOCs. If network IOCs are disclosed in future advisories, Suricata rules should be developed targeting:

- HTTP POST requests to the licensing server containing archive data
- DNS lookups to identified C2 domains
- TLS connections to identified C2 IP addresses

---

## Sources

- [OpsShield Security Incident Advisory (Nov 2026)](https://www.opsshield.com/cpguard-security-incident-nov-2026/)
- [The Hacker News — cPGuard Supply Chain Attack](https://thehackernews.com/2026/11/cpguard-supply-chain-attack.html)
- [SecurityWeek — cPGuard Update Channel Hijacked](https://www.securityweek.com/2026/11/cpguard-opsshield-supply-chain-attack/)

---

*Report generated 2026-11-04. This is a DRAFT for review.*
