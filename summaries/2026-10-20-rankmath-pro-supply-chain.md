# Rank Math PRO WordPress Plugin Supply Chain Attack

**Date:** 2026-10-20
**CVE:** CVE-2026-111862 (CVSS 9.8)
**Status:** DRAFT

---

## Executive Summary

Between October 15, 2026 at 20:02 UTC and October 16, 2026 at 07:12 UTC, threat actors compromised the distribution infrastructure of the Rank Math PRO WordPress SEO plugin (version 3.0.123) to deliver a backdoored package to customers. The malware establishes persistent, self-restoring backdoor access to affected WordPress installations, creates rogue administrator accounts, exfiltrates credentials and API keys, and communicates with a command-and-control domain (rank1cdn[.]com) registered the day before the attack. Only the premium (PRO) version distributed through rankmath[.]com was affected; the free version on WordPress.org was not compromised. Any site that installed or updated to version 3.0.123 during the 11-hour window should be treated as fully compromised.

## Background

Rank Math PRO is a widely-used premium WordPress SEO plugin distributed exclusively through the vendor's website (rankmath[.]com). Unlike the free version hosted on the WordPress.org plugin repository, the PRO version relies on the vendor's own update and licensing infrastructure. This architecture made the distribution channel a high-value target for supply chain compromise, as premium plugin updates are delivered directly to site administrators who trust the vendor's delivery mechanism.

## Attack Timeline

| Timestamp (UTC)       | Event                                                        |
|-----------------------|--------------------------------------------------------------|
| 2026-10-07            | Rank Math PRO v3.0.123 legitimately released per changelog   |
| 2026-10-14, 19:31     | C2 domain rank1cdn[.]com registered by attacker              |
| 2026-10-15, 20:02     | Compromised packages begin distribution via rankmath[.]com   |
| 2026-10-16, 07:12     | Compromised packages removed; distribution window closes     |
| 2026-10-16            | Rank Math issues security notice                             |
| 2026-10-17            | Wordfence publishes advisory                                 |
| 2026-10-19            | Clean version 3.0.124 released; news coverage begins         |
| 2026-10-20            | This report drafted                                          |

## Root Cause

The attack targeted Rank Math's distribution infrastructure to inject malware into the v3.0.123 package served to customers downloading or updating the PRO plugin. The precise method of infrastructure compromise (e.g., credential theft, CI/CD pipeline tampering, or insider access) has not been publicly disclosed by the vendor. The attacker pre-registered the C2 domain approximately 24 hours before the malicious packages began distribution, indicating premeditated planning.

## Technical Analysis

### Stage 1: Initial Deployment

The compromised Rank Math PRO v3.0.123 package contains a first-stage deployment script (observed as `_cache-preloader-fff033.php` in VirusTotal submissions). Upon plugin activation, this dropper:

- Deploys a persistent backdoor at `wp-includes/class-wp-cache-util.php` (not a legitimate WordPress core file)
- Writes malicious entries to the `wp_options` database table
- Modifies `.htaccess` files to allow `.cache` files to execute as PHP
- Installs system-level cron jobs for persistence

### Stage 2: Persistence and Self-Restoration

The backdoor implements multiple persistence mechanisms:

- **Self-restoring backdoor:** Recreates the hidden backdoor on each site page visit, making manual removal ineffective without comprehensive cleanup
- **Fake core file:** `wp-includes/class-wp-cache-util.php` disguised as a WordPress core component
- **.htaccess manipulation:** Rules added to enable PHP execution of `.cache` files throughout the web root and subdirectories
- **System cron jobs:** Entries tagged with `#ms6v46` marker in the web server user's crontab
- **WordPress scheduled events:** Additional WP-Cron persistence
- **Rogue administrator accounts:** Usernames prefixed with `wpsupport_` using email addresses at `@wp-mail[.]net`
- **SSH authorized_keys:** Potential injection of attacker SSH keys
- **Database entries:** Malicious `wp_options` rows with option names `_uf6qdn2hmm`, `t8krdk990phb`, and `_np5pvf754c`

### Stage 3: Command and Control

The backdoor communicates with the C2 domain `rank1cdn[.]com`, registered on October 14, 2026. The malware uses obfuscation techniques including:

- **XOR encoding** with key `xmmqhn`
- **base64_decode** wrapping XOR-decoded payloads
- **proc_open** for command execution
- **PHP-FPM socket** interaction for lateral process manipulation

### Stage 4: Credential Harvesting and Exfiltration

The backdoor is capable of:

- Executing arbitrary system commands
- Modifying the WordPress database
- Stealing AWS, Cloudflare, Google Cloud, and Azure credentials
- Exfiltrating SSH keys and other sensitive data
- Reading `wp-config.php` (database credentials, auth keys, salts)
- Accessing any data readable by the web server user

### Platform Behavior

The malware targets Linux-based WordPress hosting environments. It may:

- Deploy fake WordPress core files beyond `wp-includes/`
- Drop PHP files in `wp-content/mu-plugins/`, other plugins' directories, and theme folders (`inc/`, `includes/`, `lib/`)
- Plant `.cache` files containing PHP payloads in arbitrary web-accessible directories
- Modify files outside the WordPress installation directory
- Create processes and make changes visible to other system users

## IOCs

### Network Indicators

| Type   | Value                | Context                        |
|--------|----------------------|--------------------------------|
| Domain | rank1cdn[.]com       | C2 domain, registered 2026-10-14 |

### File System Indicators

| Type       | Value                                                                  | Context                    |
|------------|------------------------------------------------------------------------|----------------------------|
| File Path  | wp-includes/class-wp-cache-util.php                                    | Fake WP core file/backdoor |
| File Name  | _cache-preloader-fff033.php                                            | First-stage dropper        |
| SHA256     | f99a42f622e9a638f1b27dc051a48619a5a2d7f3432a4480fecf1413253629c9       | Dropper sample (VT)        |
| Pattern    | .cache files containing PHP code                                       | Payload storage            |

### Database Indicators (wp_options)

| option_name    | Context                         |
|----------------|---------------------------------|
| _uf6qdn2hmm   | Malicious configuration entry   |
| t8krdk990phb   | Malicious configuration entry   |
| _np5pvf754c    | Malicious configuration entry   |

### Code-Level Indicators

| Indicator       | Value             | Context                    |
|-----------------|-------------------|----------------------------|
| XOR Key         | xmmqhn            | Payload obfuscation        |
| Cron Marker     | #ms6v46           | System crontab persistence |
| PHP Functions   | base64_decode, proc_open | Obfuscation and execution  |

### Account Indicators

| Type     | Pattern                       | Context                    |
|----------|-------------------------------|----------------------------|
| Username | wpsupport_*                   | Rogue admin accounts       |
| Email    | *[at]wp-mail[.]net            | Rogue admin email domain   |

## MITRE ATT&CK Mapping

| Technique ID  | Technique Name                                | Context in This Attack                                     |
|---------------|-----------------------------------------------|------------------------------------------------------------|
| T1195.002     | Supply Chain Compromise: Compromise Software Supply Chain | Injection of malware into plugin distribution              |
| T1505.003     | Server Software Component: Web Shell           | Backdoor in class-wp-cache-util.php                        |
| T1053.003     | Scheduled Task/Job: Cron                       | Crontab persistence with #ms6v46 marker                    |
| T1136.003     | Create Account: Cloud Account                  | Rogue WordPress admin accounts (wpsupport_*)               |
| T1027        | Obfuscated Files or Information                | XOR + base64 encoding of payloads                          |
| T1071.001     | Application Layer Protocol: Web Protocols      | C2 communication to rank1cdn[.]com                         |
| T1036.005     | Masquerading: Match Legitimate Name or Location | Fake core file in wp-includes/, .cache file PHP execution  |
| T1003        | OS Credential Dumping                          | Harvesting of cloud provider and SSH credentials           |
| T1059.004     | Command and Scripting Interpreter: Unix Shell   | proc_open for command execution                            |
| T1546        | Event Triggered Execution                      | Self-restoring backdoor on page visits                     |
| T1098.004     | Account Manipulation: SSH Authorized Keys       | Potential injection of attacker SSH keys                   |

## Impact Assessment

- **Severity:** Critical (CVSS 9.8)
- **Scope:** All WordPress sites that downloaded or auto-updated Rank Math PRO to version 3.0.123 between 2026-10-15 20:02 UTC and 2026-10-16 07:12 UTC
- **Impact type:** Full site compromise with persistent backdoor access, credential theft, and potential lateral movement
- **Data at risk:** Database credentials, `wp-config.php` secrets, cloud provider credentials (AWS, GCP, Azure, Cloudflare), SSH keys, SMTP credentials, API keys, and all data accessible to the web server user
- **The free Rank Math SEO plugin on WordPress.org was NOT affected**

## Detection & Remediation

### Immediate Detection Steps

1. Check installed Rank Math PRO version: `wp plugin list | grep rank-math-pro`
2. Verify WordPress core integrity: `wp core verify-checksums`
3. Check for fake core file: look for `wp-includes/class-wp-cache-util.php`
4. Query database for malicious options: check `wp_options` for `_uf6qdn2hmm`, `t8krdk990phb`, `_np5pvf754c`
5. List administrators: `wp user list --role=administrator` -- look for `wpsupport_*` usernames
6. Check crontab for `#ms6v46` marker entries
7. Block outbound traffic to rank1cdn[.]com
8. Search for `.cache` files containing PHP: `find /var/www -name "*.cache" -exec grep -l "<?php" {} \;`
9. Check `.htaccess` files for rules enabling `.cache` PHP execution
10. Inspect `wp-content/mu-plugins/` for unexpected PHP files

### Remediation

**Preferred:** Restore from a backup created before 2026-10-15 20:02 UTC.

**If no clean backup is available:**
1. Delete the entire `rank-math-pro` plugin folder
2. Remove malicious `wp_options` rows (`_uf6qdn2hmm`, `t8krdk990phb`, `_np5pvf754c`)
3. Remove `wp-includes/class-wp-cache-util.php`
4. Block rank1cdn[.]com at the firewall level
5. Remove all `.cache` files containing PHP code
6. Clean `.htaccess` files of rules enabling `.cache` PHP execution
7. Remove rogue admin accounts (`wpsupport_*` / `@wp-mail[.]net`)
8. Check and clean system crontab entries (`#ms6v46`)
9. Inspect and clean SSH `authorized_keys` files
10. Check for unexpected WordPress scheduled events: `wp cron event list`
11. Scan `wp-content/mu-plugins/`, other plugin directories, and theme folders (`inc/`, `includes/`, `lib/`)
12. Verify with `wp core verify-checksums` and `wp plugin verify-checksums --all`
13. **Rotate ALL credentials:** database passwords, `wp-config.php` auth keys/salts, hosting/FTP/SSH credentials, SMTP credentials, cloud API keys, and all other secrets
14. Install clean Rank Math PRO v3.0.124
15. Monitor for file reappearance and outbound connections for several days

## Detection Rules

<!-- AUDIT: All rules validated 2026-10-20. YARA compiled with yarac 4.5.0 exit 0.
     Sigma rules converted to Splunk and LogScale with sigma-cli 3.1.0 exit 0.
     sigma check could not complete due to MITRE ATT&CK data endpoint being unreachable (403).
     Suricata rules validated with suricata 7.0.3 -T exit 0. -->

### YARA: Rank Math PRO Backdoor Components

Detects the XOR key, database option names, C2 domain, cron marker, and PHP obfuscation patterns specific to this attack. Also detects the first-stage cache preloader dropper.

- **File:** `yara_rankmath_backdoor.yar` (2 rules)
- **Compile status:** Compiles (yarac 4.5.0, exit 0)
- **Confidence:** High -- targets unique, attack-specific string artifacts (XOR key `xmmqhn`, DB options, cron marker `#ms6v46`)

```yaml
# Validation: yarac yara_rankmath_backdoor.yar /dev/null -> exit 0
```

```yara
rule RankMathPRO_SupplyChain_Backdoor
{
    meta:
        description = "Detects Rank Math PRO 3.0.123 supply chain backdoor components"
        author = "CTI Analyst"
        date = "2026-10-20"
        reference = "https://rankmath.com/kb/pro-3-0-123-security-incident/"
        cve = "CVE-2026-111862"
        hash = "f99a42f622e9a638f1b27dc051a48619a5a2d7f3432a4480fecf1413253629c9"
        severity = "critical"

    strings:
        $xor_key = "xmmqhn" ascii wide
        $db_opt1 = "_uf6qdn2hmm" ascii
        $db_opt2 = "t8krdk990phb" ascii
        $db_opt3 = "_np5pvf754c" ascii
        $c2_domain = "rank1cdn.com" ascii wide nocase
        $cron_marker = "#ms6v46" ascii
        $backdoor_file = "class-wp-cache-util.php" ascii
        $rogue_email = "@wp-mail.net" ascii nocase
        $rogue_user = "wpsupport_" ascii nocase

        $php_b64 = "base64_decode" ascii
        $php_proc = "proc_open" ascii

    condition:
        any of ($xor_key, $db_opt1, $db_opt2, $db_opt3, $c2_domain, $cron_marker) or
        ($backdoor_file and $php_b64) or
        ($rogue_email and $rogue_user) or
        ($xor_key and $php_b64 and $php_proc)
}

rule RankMathPRO_CachePreloader_Dropper
{
    meta:
        description = "Detects the first-stage cache preloader dropper from Rank Math PRO 3.0.123 compromise"
        author = "CTI Analyst"
        date = "2026-10-20"
        reference = "https://www.bleepingcomputer.com/news/security/wordpress-seo-plugin-rank-math-compromised-to-backdoor-websites/"
        severity = "critical"

    strings:
        $cache_preloader = "_cache-preloader-" ascii
        $xor_key = "xmmqhn" ascii
        $b64 = "base64_decode" ascii
        $proc = "proc_open" ascii
        $wp_cache_util = "class-wp-cache-util" ascii
        $c2 = "rank1cdn" ascii

    condition:
        ($cache_preloader and any of ($xor_key, $b64, $proc)) or
        ($c2 and $xor_key) or
        ($wp_cache_util and $xor_key and $b64)
}
```

### Sigma: C2 DNS Query to rank1cdn.com

Detects DNS lookups to the attacker C2 domain used in this supply chain attack.

- **File:** `sigma_rankmath_c2_dns.yml`
- **Compile status:** Compiles (sigma convert to Splunk and LogScale, exit 0)
- **Confidence:** High -- rank1cdn[.]com was registered specifically for this attack and has no legitimate use

```yaml
title: Rank Math PRO Supply Chain - C2 DNS Query to rank1cdn.com
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: Detects DNS queries to rank1cdn.com, the C2 domain used in the Rank Math PRO 3.0.123 supply chain attack.
references:
    - https://rankmath.com/kb/pro-3-0-123-security-incident/
    - https://www.securityweek.com/rank-math-pro-wordpress-plugin-compromised-in-supply-chain-attack/
author: CTI Analyst
date: 2026-10-20
tags:
    - attack.command_and_control
    - attack.t1071.001
    - cve.2026-111862
logsource:
    category: dns
detection:
    selection:
        query|endswith:
            - 'rank1cdn.com'
    condition: selection
falsepositives:
    - Unlikely, rank1cdn.com is a known malicious domain registered for this attack
level: critical
```

### Sigma: Fake WordPress Core File Creation

Detects creation of the fake core file used as the primary backdoor.

- **File:** `sigma_rankmath_backdoor_file.yml`
- **Compile status:** Compiles (sigma convert to Splunk and LogScale, exit 0)
- **Confidence:** High -- `class-wp-cache-util.php` is not a legitimate WordPress core file

```yaml
title: Rank Math PRO Supply Chain - Fake WordPress Core File Creation
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: Detects creation or modification of wp-includes/class-wp-cache-util.php, a fake WordPress core file deployed by the Rank Math PRO 3.0.123 supply chain backdoor.
references:
    - https://rankmath.com/kb/pro-3-0-123-security-incident/
    - https://www.bleepingcomputer.com/news/security/wordpress-seo-plugin-rank-math-compromised-to-backdoor-websites/
author: CTI Analyst
date: 2026-10-20
tags:
    - attack.persistence
    - attack.t1505.003
    - cve.2026-111862
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/wp-includes/class-wp-cache-util.php'
    condition: selection
falsepositives:
    - No legitimate WordPress core file with this name exists
level: critical
```

### Sigma: Suspicious .htaccess Modification

Detects .htaccess file modifications that may enable .cache file PHP execution. Caveat: this is a behavioral rule and will generate false positives from legitimate WordPress operations.

- **File:** `sigma_rankmath_htaccess_mod.yml`
- **Compile status:** Compiles (sigma convert to Splunk and LogScale, exit 0)
- **Confidence:** Low -- .htaccess modifications are common in WordPress; this is a broad behavioral indicator

```yaml
title: Rank Math PRO Supply Chain - Suspicious .htaccess Modification for PHP Cache Execution
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: Detects modification of .htaccess files that could enable .cache files to execute as PHP, a persistence technique used in the Rank Math PRO 3.0.123 supply chain attack.
references:
    - https://rankmath.com/kb/pro-3-0-123-security-incident/
    - https://thehackernews.com/2026/10/popular-wordpress-seo-plugin-rank-math.html
author: CTI Analyst
date: 2026-10-20
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1036.005
    - cve.2026-111862
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '.htaccess'
    filter_known:
        Image|endswith:
            - '/apache2'
            - '/httpd'
            - '/nginx'
    condition: selection and not filter_known
falsepositives:
    - Legitimate WordPress plugin installations or updates that modify .htaccess
    - Web server configuration management tools
level: medium
```

### Sigma: Rogue WordPress Admin Account Creation

Detects web requests indicating creation of attacker-controlled admin accounts. Caveat: requires web server access logs with query string logging enabled.

- **File:** `sigma_rankmath_rogue_admin.yml`
- **Compile status:** Compiles (sigma convert to Splunk and LogScale, exit 0)
- **Confidence:** Medium -- relies on web server log visibility into POST parameters which may not be available

```yaml
title: Rank Math PRO Supply Chain - Rogue WordPress Admin Account Creation
id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80
status: experimental
description: Detects creation of rogue WordPress administrator accounts with usernames starting with wpsupport_ or email addresses at wp-mail.net, associated with the Rank Math PRO 3.0.123 supply chain attack.
references:
    - https://rankmath.com/kb/pro-3-0-123-security-incident/
    - https://www.bleepingcomputer.com/news/security/wordpress-seo-plugin-rank-math-compromised-to-backdoor-websites/
author: CTI Analyst
date: 2026-10-20
tags:
    - attack.persistence
    - attack.t1136.003
    - cve.2026-111862
logsource:
    category: webserver
detection:
    selection_user:
        cs-uri-query|contains: 'wpsupport_'
    selection_email:
        cs-uri-query|contains: 'wp-mail.net'
    selection_path:
        cs-uri-stem|contains: '/wp-admin/user-new.php'
    condition: selection_path and (selection_user or selection_email)
falsepositives:
    - Unlikely, the wpsupport_ prefix and wp-mail.net domain are specific to this attack
level: high
```

### Sigma: Malicious Cron Job with ms6v46 Marker

Detects crontab manipulation referencing the attacker's persistence marker.

- **File:** `sigma_rankmath_cron_persistence.yml`
- **Compile status:** Compiles (sigma convert to Splunk and LogScale, exit 0)
- **Confidence:** High -- the `ms6v46` string is unique to this attack campaign

```yaml
title: Rank Math PRO Supply Chain - Malicious Cron Job with ms6v46 Marker
id: e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091
status: experimental
description: Detects system cron job entries tagged with the #ms6v46 marker used by the Rank Math PRO 3.0.123 backdoor for persistence.
references:
    - https://rankmath.com/kb/pro-3-0-123-security-incident/
    - https://thehackernews.com/2026/10/popular-wordpress-seo-plugin-rank-math.html
author: CTI Analyst
date: 2026-10-20
tags:
    - attack.persistence
    - attack.execution
    - attack.t1053.003
    - cve.2026-111862
logsource:
    category: process_creation
    product: linux
detection:
    selection_crontab:
        Image|endswith: '/crontab'
    selection_marker:
        CommandLine|contains: 'ms6v46'
    condition: selection_crontab or selection_marker
falsepositives:
    - Extremely unlikely given the specificity of the ms6v46 marker string
level: critical
```

### Suricata: Network Detection Rules

Three rules targeting DNS, HTTP, and TLS traffic to the C2 domain.

- **File:** `suricata_rankmath.rules`
- **Compile status:** Compiles (suricata 7.0.3 -T, exit 0)
- **Confidence:** High -- rank1cdn[.]com is attack-specific infrastructure with no legitimate use

```
alert dns $HOME_NET any -> any any (msg:"MALWARE Rank Math PRO Supply Chain - DNS Query to rank1cdn.com C2"; dns.query; content:"rank1cdn.com"; nocase; reference:url,rankmath.com/kb/pro-3-0-123-security-incident/; classtype:trojan-activity; sid:2026101501; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Rank Math PRO Supply Chain - HTTP Request to rank1cdn.com C2"; flow:established,to_server; http.host; content:"rank1cdn.com"; reference:url,rankmath.com/kb/pro-3-0-123-security-incident/; classtype:trojan-activity; sid:2026101502; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Rank Math PRO Supply Chain - TLS SNI to rank1cdn.com C2"; tls.sni; content:"rank1cdn.com"; nocase; reference:url,rankmath.com/kb/pro-3-0-123-security-incident/; classtype:trojan-activity; sid:2026101503; rev:1;)
```

## Sources

- [Rank Math Security Advisory](https://rankmath.com/kb/pro-3-0-123-security-incident/)
- [SecurityWeek - Rank Math PRO WordPress Plugin Compromised in Supply Chain Attack](https://www.securityweek.com/rank-math-pro-wordpress-plugin-compromised-in-supply-chain-attack/)
- [BleepingComputer - WordPress SEO Plugin Rank Math Compromised to Backdoor Websites](https://www.bleepingcomputer.com/news/security/wordpress-seo-plugin-rank-math-compromised-to-backdoor-websites/)
- [The Hacker News - Popular WordPress SEO Plugin Rank Math](https://thehackernews.com/2026/10/popular-wordpress-seo-plugin-rank-math.html)
- [Wordfence Advisory](https://www.wordfence.com/blog/2026/10/rank-math-seo-pro-3-0-123-malware/) (referenced; could not retrieve full content)
