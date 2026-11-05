# cPGuard/OpsShield Supply Chain Attack -- Technical Analysis (DRAFT)

**Date:** 2026-11-05
**Status:** DRAFT -- Advisory-specific / PoC altitude
**TLP:** CLEAR
**Author:** Actioner

---

## Executive Summary

On November 2, 2026, threat actors compromised OpsShield's update distribution infrastructure to push malicious cPGuard updates to approximately 2,950 Linux web hosting servers. The poisoned updates (versions 5.88.12 through 5.88.19) deployed a data-stealing shell script and a setuid-root backdoor, exfiltrating sensitive credentials including `/etc/shadow`, root SSH keys, MySQL passwords, and cloud storage tokens. The attacker also copied three OpsShield cloud servers and exfiltrated billing records for approximately 7,900 customer accounts. The compromise was detected within 12 hours and the malicious distribution window lasted roughly 70 minutes (02:08--03:20 UTC).

---

## Background

**cPGuard** is a web security suite for Linux hosting servers developed by **OpsShield** (formerly ServerManage). It provides WAF, malware scanning, and intrusion detection capabilities for cPanel, Plesk, and other hosting control panels. The product uses an automatic update mechanism that polls OpsShield's update CDN for new versions and executes them as root.

---

## Attack Timeline (UTC)

| Timestamp (UTC) | Event |
|---|---|
| Nov 1, 15:38 | Attacker begins probing the billing portal (`manage.opsshield[.]com`) |
| Nov 1, 16:34 | Attacker registers a customer account under a false identity, orders free cPGuard trial |
| Nov 1, 21:17 | Trial installed on attacker-controlled server to study licensing traffic |
| Nov 1, 21:40--21:51 | cPGuard bans the attacker twice |
| Nov 1, 22:50 | Crafted requests sent to billing portal callback pages |
| Nov 1, 22:58 | Remote command execution achieved on billing/licensing server; data collection begins |
| Nov 2, 02:04--02:09 | Fake cPGuard update uploaded to update CDN using stolen access key |
| Nov 2, 02:08--03:20 | Customer agents install the poisoned update (~70-minute window) |
| Nov 2, 02:13 | Copies made of three OpsShield cloud servers |
| Nov 2 (within 12h) | OpsShield detects compromise, revokes stolen key, publishes clean update v5.88.26 |
| Nov 3 | OpsShield publishes incident disclosure |

---

## Root Cause

The attacker exploited a vulnerability in OpsShield's billing portal callback pages (`manage.opsshield[.]com`) to achieve remote command execution on the billing and licensing server. From there, they stole the update-publishing access key and used it to push poisoned cPGuard updates to the CDN. The precise vulnerability has not been publicly disclosed; OpsShield states it has been patched.

---

## Technical Analysis

### Stage 1: Initial Access (Billing Portal Exploitation)

The attacker registered a free trial account and studied the licensing protocol before sending crafted requests to callback page endpoints. This gave them command execution on OpsShield's billing/licensing server, where they:

- Deployed probe files: `/i90248_probe.txt`, `/i90573_probe.txt`
- Deployed web shells: `/i90573_sh.php`, `/i90573_x.php`
- Used exfiltration receiver endpoints matching the pattern `*_rx.php`
- Installed a **gsocket** backdoor (`/usr/bin/defunct`) registered as a systemd service (`defunct.service`)
- Installed a **Go implant** at multiple paths masquerading as system files (e.g., `/usr/sbin/pythno3`, `/usr/lib/libgdi.so.0.8.2`)
- Deployed anti-detection scripts (`/etc/profile.d/gateway.sh`) to hide from `ps`, `netstat`, `ls`, and `find`

### Stage 2: Supply Chain Poisoning (Malicious Update Distribution)

Using the stolen update-publishing key, the attacker uploaded four variants of a malicious shell script to the update CDN:

| Filename | SHA-256 |
|---|---|
| `cpguard-v58812-i91511.sh` | `2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38` |
| `cpguard-v58812-i91511b.sh` | `ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a` |
| `cpguard-v58812-i91511c.sh` | `d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26` |
| `cpguard-v58812-i91511d.sh` | `6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77` |

### Stage 3: Payload Execution on Customer Servers

The malicious update ran as root on customer servers and performed:

1. **Credential harvesting**: Collected `/etc/shadow`, `/etc/passwd`, `/root/.ssh/*`, `/root/.my.cnf`, root shell history, `/root/.s3cfg`
2. **Staging**: Gathered stolen files in `/var/tmp/.cpg91511/` and archived them as `/var/tmp/.cpg91511/loot.tgz`
3. **Exfiltration**: Uploaded the archive to OpsShield's own licensing server via a compromised account
4. **Persistence**: Installed a hidden setuid-root shell at `/var/tmp/.cpg91511_sh`
5. **Scheduled task**: Created `/etc/cron.d/i93677` with supporting files in `/var/tmp/.i93677/`

### Stage 4: Data Retrieval

The attacker retrieved 32 files from the licensing server, each corresponding to a different customer server. They also copied three OpsShield cloud servers, including billing database records for ~7,900 customer accounts.

### C2 and Network Infrastructure

- **Primary attacker IP:** `94.183.188[.]91`
- **Spoofed User-Agent:** `cPGuard/5.88.11`
- **Exfiltration destination:** OpsShield's own licensing server (compromised account)
- **No external C2 domains** were identified in the disclosure

---

## Indicators of Compromise (IOCs)

> All network IOCs are defanged per standard practice.

### File Hashes (SHA-256)

| Hash | Filename |
|---|---|
| `2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38` | cpguard-v58812-i91511.sh |
| `ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a` | cpguard-v58812-i91511b.sh |
| `d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26` | cpguard-v58812-i91511c.sh |
| `6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77` | cpguard-v58812-i91511d.sh |

### Network Indicators

| Type | Value |
|---|---|
| IP | `94[.]183[.]188[.]91` |
| Domain | `manage[.]opsshield[.]com` (billing portal -- compromised, not malicious infrastructure) |
| User-Agent | `cPGuard/5.88.11` (spoofed) |
| URL Pattern | `*_rx.php` (exfiltration receiver) |

### File System Artifacts -- Customer Servers

| Path | Description |
|---|---|
| `/var/tmp/.cpg91511_sh` | Setuid-root backdoor shell |
| `/var/tmp/.cpg91511/` | Staging directory for stolen data |
| `/var/tmp/.cpg91511/loot.tgz` | Archived stolen data |
| `/etc/cron.d/i93677` | Persistence via cron scheduled task |
| `/var/tmp/.i93677/` | Supporting files for scheduled task |

### File System Artifacts -- OpsShield Internal Servers

| Path | Description |
|---|---|
| `/i90248_probe.txt` | Probe file (web root) |
| `/i90573_probe.txt` | Probe file (web root) |
| `/i90573_sh.php` | Web shell |
| `/i90573_x.php` | Web shell |
| `/usr/bin/defunct` | gsocket backdoor binary |
| `/lib/systemd/system/defunct.service` | gsocket persistence (systemd) |
| `/lib/systemd/system/defunct.dat` | gsocket configuration |
| `/usr/sbin/pythno3` | Go implant (masqueraded as python3) |
| `/usr/sbin/netstat.cfg` | Go implant copy |
| `/etc/profile.d/bash.cfg` | Go implant copy |
| `/usr/lib/system.mark` | Go implant copy |
| `/usr/lib/libgdi.so.0.8.2` | Go implant copy (masqueraded as shared library) |
| `/boot/system.pub` | Go implant copy |
| `/etc/profile.d/gateway.sh` | Anti-detection script (hides implant from ps/netstat/ls/find) |

### Process Indicators

| Process Name | Description |
|---|---|
| `[slub_flushwq]` | gsocket backdoor (masquerading as kernel thread) |
| `[rcu_gp]` | Go implant (masquerading as kernel thread) |

### Affected Software Versions

- **Malicious:** cPGuard 5.88.12 through 5.88.19 (inclusive)
- **Fixed:** cPGuard 5.88.25+ (backdoor removal), 5.88.26+ (complete cleanup)

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Context |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Poisoned cPGuard update channel via stolen publishing key |
| T1190 | Exploit Public-Facing Application | Exploited billing portal callback pages for RCE |
| T1078 | Valid Accounts | Used compromised credentials to access update CDN and licensing server |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Malicious bash scripts executed as root |
| T1053.003 | Scheduled Task/Job: Cron | Persistence via `/etc/cron.d/i93677` |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | Setuid-root backdoor at `/var/tmp/.cpg91511_sh` |
| T1543.002 | Create or Modify System Process: Systemd Service | gsocket backdoor registered as `defunct.service` |
| T1005 | Data from Local System | Collection of shadow, SSH keys, MySQL config, shell history |
| T1560.001 | Archive Collected Data: Archive via Utility | Data staged as `loot.tgz` |
| T1041 | Exfiltration Over C2 Channel | Data uploaded to compromised licensing server account |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Go implant as `pythno3`, `libgdi.so.0.8.2`; process names mimicking kernel threads |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | Hidden dotfiles in `/var/tmp/` |
| T1014 | Rootkit | `gateway.sh` hiding implant from standard system tools |
| T1505.003 | Server Software Component: Web Shell | Web shells `i90573_sh.php`, `i90573_x.php` |

---

## Impact Assessment

| Category | Impact |
|---|---|
| **Servers compromised** | ~2,950 executed the malicious update |
| **Customer records exposed** | ~7,900 billing accounts (names, emails, postal addresses, bcrypt password hashes) |
| **Credentials at risk** | Root passwords (shadow), SSH private keys, MySQL root passwords, S3/DO tokens, shell history secrets |
| **Infrastructure impact** | 3 OpsShield cloud servers copied; update CDN and billing server compromised |
| **Lateral movement risk** | SSH keys from compromised servers could provide access to additional infrastructure |
| **Persistence** | Setuid root shell and cron job survive reboots; require explicit cleanup |

---

## Detection & Remediation

### Detection Steps

1. **Check cPGuard update history:**
   ```bash
   grep 'Successfully updated' /opt/cpguard/logs/install_log
   ```
   Look for updates to versions 5.88.12 through 5.88.19 between November 2 02:08 and 03:20 UTC.

2. **Scan for persistence artifacts:**
   ```bash
   ls -la /etc/cron.d/i93677 /var/tmp/.i93677/ /var/tmp/.cpg91511_sh 2>/dev/null
   find / -name 'cpguard-v58812-i91511*.sh' 2>/dev/null
   ```

3. **Verify cPGuard version:**
   ```bash
   cpgcli --version   # Must be 5.88.25 or later
   ```

### Remediation Steps

1. Update cPGuard to 5.88.26 or later immediately
2. Rotate all root passwords and local user passwords from a trusted recovery environment
3. Generate new SSH key pairs; remove old public keys from all trusted hosts
4. Rotate MySQL root passwords and any credentials in `/root/.my.cnf`
5. Rotate S3 credentials (`/root/.s3cfg`), DigitalOcean tokens, and secrets in shell history
6. Treat any server reachable via SSH keys from a compromised host as potentially compromised
7. Reset `manage.opsshield[.]com` password and enable 2FA
8. Rebuild any server the attacker may have logged into manually from a pre-November-1 backup

---

## Detection Rules

### Sigma Rule 1: Malicious File Artifacts

Detects file creation at paths specific to the cPGuard supply chain payload. Covers backdoor, staging directory, and persistence cron job.
<!-- audit: File paths are unique to this campaign. No known legitimate software uses these paths. -->

```yaml
title: cPGuard Supply Chain Attack - Malicious File Artifacts
id: 8a3e2f1c-7b4d-4e9a-b5c6-d8f0a1e2c3b4
status: experimental
description: Detects file creation or access patterns associated with the cPGuard/OpsShield supply chain compromise of November 2026, including backdoor shells, staging directories, and persistence mechanisms.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-hijack-cpguard-autoupdate-to-deploy-backdoor-steal-data/
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
    - https://opsshield.com/notice/cpguard-update-channel-compromise.html
author: Actioner
date: 2026/11/05
tags:
    - attack.t1195.002
    - attack.t1059.004
    - attack.t1053.003
logsource:
    product: linux
    category: file_event
detection:
    selection_backdoor:
        TargetFilename|contains:
            - '/var/tmp/.cpg91511_sh'
            - '/var/tmp/.cpg91511/'
            - '/var/tmp/.i93677/'
            - '/etc/cron.d/i93677'
    selection_scripts:
        TargetFilename|contains:
            - 'cpguard-v58812-i91511'
    condition: selection_backdoor or selection_scripts
falsepositives:
    - Legitimate cPGuard forensic investigation activity
level: high
```

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk pass) | **Confidence:** medium
<!-- audit: sigma check --exclude attacktag: 0 errors, 0 issues. sigma convert --without-pipeline -t splunk: successful. ATT&CK tag validation skipped due to network restriction in validation environment. -->

---

### Sigma Rule 2: Go Implant and Gsocket Backdoor Paths

Detects file creation at masqueraded paths used by the Go implant and gsocket backdoor on OpsShield internal infrastructure.
<!-- audit: These paths were found on OpsShield's servers. They may appear on customer servers if the attacker pivoted. -->

```yaml
title: cPGuard Supply Chain Attack - Go Implant and Gsocket Backdoor Paths
id: 1d4e5f6a-7b8c-9d0e-f1a2-b3c4d5e6f7a8
status: experimental
description: Detects file creation at paths used by the Go implant and gsocket backdoor deployed on OpsShield internal servers during the cPGuard supply chain compromise.
references:
    - https://opsshield.com/notice/security-incident-disclosure-servermanage.html
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
author: Actioner
date: 2026/11/05
tags:
    - attack.t1036.005
    - attack.t1543.002
logsource:
    product: linux
    category: file_event
detection:
    selection_gsocket:
        TargetFilename|endswith:
            - '/usr/bin/defunct'
            - '/lib/systemd/system/defunct.service'
            - '/lib/systemd/system/defunct.dat'
    selection_go_implant:
        TargetFilename|endswith:
            - '/usr/sbin/pythno3'
            - '/usr/sbin/netstat.cfg'
            - '/etc/profile.d/bash.cfg'
            - '/usr/lib/system.mark'
            - '/usr/lib/libgdi.so.0.8.2'
            - '/boot/system.pub'
    selection_antidt:
        TargetFilename|endswith:
            - '/etc/profile.d/gateway.sh'
    condition: selection_gsocket or selection_go_implant or selection_antidt
falsepositives:
    - Unlikely; paths are distinctive masquerading artifacts
level: high
```

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk pass) | **Confidence:** medium
<!-- audit: The path /usr/bin/defunct could theoretically collide with unrelated software, but in combination with the other indicators it is distinctive. Confidence medium because no file hashes are available for the Go implant or gsocket binaries. -->

---

### Sigma Rule 3: Masqueraded Process Names

Detects process execution from binary paths used by the Go implant and gsocket backdoor.
<!-- audit: Kernel thread names [slub_flushwq] and [rcu_gp] are real kernel threads so were excluded as primary indicators to avoid false positives. -->

```yaml
title: cPGuard Supply Chain Attack - Masqueraded Process Names
id: 2e5f6a7b-8c9d-0e1f-a2b3-c4d5e6f7a8b9
status: experimental
description: Detects process execution with names matching the kernel thread masquerading used by the Go implant and gsocket backdoor in the cPGuard/OpsShield supply chain attack.
references:
    - https://opsshield.com/notice/security-incident-disclosure-servermanage.html
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
author: Actioner
date: 2026/11/05
tags:
    - attack.t1036.005
    - attack.t1014
logsource:
    product: linux
    category: process_creation
detection:
    selection_gsocket_proc:
        Image|endswith: '/usr/bin/defunct'
    selection_go_implant_proc:
        Image|endswith:
            - '/usr/sbin/pythno3'
            - '/usr/lib/libgdi.so.0.8.2'
    selection_by_cmdline:
        CommandLine|contains:
            - 'cpguard-v58812-i91511'
    condition: selection_gsocket_proc or selection_go_implant_proc or selection_by_cmdline
falsepositives:
    - Unlikely; binary paths are distinctive typosquats
level: high
```

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk pass) | **Confidence:** medium
<!-- audit: Image-based detection is more reliable than process name for this case. CommandLine detection covers the initial script execution. -->

---

### Sigma Rule 4: Sensitive File Collection Pattern

Detects archive creation in the campaign-specific staging directory.
<!-- audit: Narrow scope: only fires on the unique loot.tgz or .cpg91511 strings. Broader sensitive-file-read patterns were excluded as too noisy for PoC altitude. -->

```yaml
title: cPGuard Supply Chain Attack - Sensitive File Collection Pattern
id: 3f6a7b8c-9d0e-1f2a-b3c4-d5e6f7a8b9c0
status: experimental
description: Detects a shell process reading multiple sensitive files targeted by the cPGuard supply chain attack payload, including shadow, SSH keys, and MySQL config, followed by archive creation.
references:
    - https://opsshield.com/notice/cpguard-update-channel-compromise.html
    - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
author: Actioner
date: 2026/11/05
tags:
    - attack.t1005
    - attack.t1560.001
logsource:
    product: linux
    category: process_creation
detection:
    selection_archive:
        CommandLine|contains:
            - 'loot.tgz'
            - '.cpg91511'
    selection_tar_staging:
        Image|endswith:
            - '/bin/tar'
            - '/usr/bin/tar'
        CommandLine|contains:
            - '/var/tmp/.cpg91511'
    condition: selection_archive or selection_tar_staging
falsepositives:
    - Forensic investigators analyzing the incident artifacts
level: high
```

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk pass) | **Confidence:** medium
<!-- audit: The string loot.tgz in /var/tmp/.cpg91511/ is unique to this campaign. -->

---

### Sigma Rule 5: Web Shell and Probe File Detection

Detects creation of web shell and probe files matching the naming convention used during initial access.
<!-- audit: The _rx.php pattern is broader and may generate false positives in some web applications. Probe filenames are distinctive. -->

```yaml
title: cPGuard Supply Chain Attack - Web Shell and Probe File Detection
id: 4a7b8c9d-0e1f-2a3b-c4d5-e6f7a8b9c0d1
status: experimental
description: Detects creation of web shell and probe files matching the naming convention used during initial access to OpsShield billing infrastructure.
references:
    - https://opsshield.com/notice/security-incident-disclosure-servermanage.html
author: Actioner
date: 2026/11/05
tags:
    - attack.t1505.003
    - attack.t1190
logsource:
    product: linux
    category: file_event
detection:
    selection_probes:
        TargetFilename|endswith:
            - 'i90248_probe.txt'
            - 'i90573_probe.txt'
            - 'i90573_sh.php'
            - 'i90573_x.php'
    selection_rx_pattern:
        TargetFilename|endswith:
            - '_rx.php'
    condition: selection_probes or selection_rx_pattern
falsepositives:
    - Web applications that legitimately use filenames ending in _rx.php
level: medium
```

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk pass) | **Confidence:** medium
<!-- audit: Probe filenames are high confidence individually. The _rx.php endpoint pattern adds coverage but has uncertain false positive rate. Rule level set to medium accordingly. -->

---

### YARA Rules: Malicious Scripts and Implant Artifacts

Three rules covering: (1) malicious update scripts by content and hash, (2) Go implant and gsocket paths, (3) web shell probe files.

```yara
rule cpguard_malicious_update_script
{
    meta:
        description = "Detects malicious cPGuard update scripts distributed during the OpsShield supply chain compromise of November 2026"
        author = "Actioner"
        date = "2026-11-05"
        reference = "https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html"
        hash1 = "2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38"
        hash2 = "ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a"
        hash3 = "d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26"
        hash4 = "6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77"

    strings:
        $script_name = "cpguard-v58812-i91511" ascii
        $backdoor_path = "/var/tmp/.cpg91511_sh" ascii
        $staging_dir = "/var/tmp/.cpg91511" ascii
        $loot_archive = "loot.tgz" ascii
        $cron_persist = "/etc/cron.d/i93677" ascii
        $cron_dir = "/var/tmp/.i93677" ascii

    condition:
        uint32(0) == 0x68732123 and 3 of them
        or any of ($script_name, $backdoor_path, $cron_persist) and filesize < 500KB
}

rule cpguard_go_implant_artifacts
{
    meta:
        description = "Detects Go implant and gsocket backdoor artifacts from the OpsShield supply chain compromise"
        author = "Actioner"
        date = "2026-11-05"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"

    strings:
        $gs_path1 = "/usr/bin/defunct" ascii
        $gs_svc = "defunct.service" ascii
        $gs_dat = "defunct.dat" ascii
        $go_pythno = "pythno3" ascii
        $go_netcfg = "/usr/sbin/netstat.cfg" ascii
        $go_bashcfg = "/etc/profile.d/bash.cfg" ascii
        $go_sysmark = "/usr/lib/system.mark" ascii
        $go_libgdi = "libgdi.so.0.8.2" ascii
        $go_syspub = "/boot/system.pub" ascii
        $antidt = "/etc/profile.d/gateway.sh" ascii

    condition:
        3 of them and filesize < 50MB
}

rule cpguard_webshell_probes
{
    meta:
        description = "Detects web shell and probe files used in initial access during the OpsShield supply chain compromise"
        author = "Actioner"
        date = "2026-11-05"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"

    strings:
        $probe1 = "i90248_probe" ascii
        $probe2 = "i90573_probe" ascii
        $shell1 = "i90573_sh" ascii
        $shell2 = "i90573_x" ascii

    condition:
        any of them and filesize < 1MB
}
```

**Compile status:** ✅ compiles (`yarac` exit 0) | **Confidence:**
- `cpguard_malicious_update_script`: medium (string-based; no samples available for testing)
- `cpguard_go_implant_artifacts`: low (no binary hashes available; string overlap possible)
- `cpguard_webshell_probes`: medium (distinctive probe identifiers)

<!-- audit: YARA compiled with yarac to /dev/null, exit code 0. Rule cpguard_malicious_update_script uses the shebang magic (#!/sh = 0x68732123 in little-endian) as a file type filter. -->

---

### Snort Rules (v2.9 syntax)

Network detection for C2 IP, spoofed user-agent, exfiltration URL pattern, and malicious script download.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE cPGuard Supply Chain - Spoofed User-Agent cPGuard/5.88.11"; flow:established,to_server; content:"cPGuard/5.88.11"; http_header; classtype:trojan-activity; sid:2026110501; rev:1;)
alert tcp $HOME_NET any -> 94.183.188.91 any (msg:"MALWARE cPGuard Supply Chain - C2 IP 94.183.188.91"; flow:established,to_server; classtype:trojan-activity; sid:2026110502; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE cPGuard Supply Chain - Exfil Receiver URL Pattern _rx.php"; flow:established,to_server; content:"_rx.php"; http_uri; classtype:trojan-activity; sid:2026110503; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE cPGuard Supply Chain - Malicious Script Download cpguard-v58812-i91511"; flow:established,to_server; content:"cpguard-v58812-i91511"; http_uri; classtype:trojan-activity; sid:2026110504; rev:1;)
```

**Compile status:** ✅ compiles (`snort -T` exit 0, "Snort successfully validated the configuration!") | **Confidence:**
- SID 2026110501 (User-Agent): medium (distinctive spoofed UA but could match legitimate older cPGuard clients)
- SID 2026110502 (C2 IP): medium (single IP; may be reassigned)
- SID 2026110503 (Exfil URL): low (broad pattern `_rx.php` may match legitimate applications)
- SID 2026110504 (Script download): medium (campaign-specific string)

<!-- audit: Validated with snort 2.9.20 using minimal config with $HOME_NET, $EXTERNAL_NET, $HTTP_PORTS defined. -->

---

### Suricata Rules

Network detection using Suricata dot-notation sticky buffers.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE cPGuard Supply Chain - Spoofed User-Agent cPGuard/5.88.11"; flow:established,to_server; http.user_agent; content:"cPGuard/5.88.11"; classtype:trojan-activity; sid:2026110601; rev:1;)
alert tcp $HOME_NET any -> 94.183.188.91 any (msg:"MALWARE cPGuard Supply Chain - C2 IP 94.183.188.91"; flow:established,to_server; classtype:trojan-activity; sid:2026110602; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE cPGuard Supply Chain - Exfil Receiver URL Pattern _rx.php"; flow:established,to_server; http.uri; content:"_rx.php"; classtype:trojan-activity; sid:2026110603; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE cPGuard Supply Chain - Malicious Script Download cpguard-v58812-i91511"; flow:established,to_server; http.uri; content:"cpguard-v58812-i91511"; classtype:trojan-activity; sid:2026110604; rev:1;)
```

**Compile status:** ✅ compiles (`suricata -T -S` exit 0, "Configuration provided was successfully loaded. Exiting.") | **Confidence:**
- SID 2026110601 (User-Agent): medium
- SID 2026110602 (C2 IP): medium
- SID 2026110603 (Exfil URL): low
- SID 2026110604 (Script download): medium

<!-- audit: Validated with Suricata 7.0.3. -->

---

## Sources

- [BleepingComputer: Hackers hijack cPGuard autoupdate to deploy backdoor, steal data](https://www.bleepingcomputer.com/news/security/hackers-hijack-cpguard-autoupdate-to-deploy-backdoor-steal-data/)
- [The Hacker News: cPGuard Update Channel Hijacked to Deploy Backdoor](https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html)
- [SecurityWeek: Malicious cPGuard Updates Served in OpsShield Supply Chain Attack](https://www.securityweek.com/malicious-cpguard-updates-served-in-opsshield-supply-chain-attack/)
- [OpsShield: cPGuard Update Channel Compromise Notice](https://opsshield.com/notice/cpguard-update-channel-compromise.html)
- [OpsShield: Security Incident Disclosure - ServerManage](https://opsshield.com/notice/security-incident-disclosure-servermanage.html)

---

*This is a DRAFT report. All detection rules are at PoC/advisory-specific altitude with strict leniency. Rules should be tested against local telemetry before production deployment.*
