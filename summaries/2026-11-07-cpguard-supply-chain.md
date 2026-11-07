# cPGuard Update Channel Supply Chain Attack

**Report Status:** DRAFT  
**Date:** 2026-11-07  
**TLP:** CLEAR  
**Author:** Actioner CTI  

---

## Executive Summary

On November 2, 2026, an unidentified threat actor hijacked the update distribution channel of cPGuard, a Linux web-server security suite developed by OPSSHIELD, to push malicious scripts to approximately 2,950 customer servers. The attacker gained initial access by exploiting the OPSSHIELD billing portal (manage.opsshield[.]com) through a newly registered trial account, achieving command execution on the billing and licensing server within hours. The stolen update-publishing key was used to distribute four variants of a malicious shell script disguised as a legitimate cPGuard update (versions 5.88.12 through 5.88.19). The script executed as root, installed a setuid-root backdoor shell, established cron-based persistence, harvested credentials (/etc/shadow, SSH private keys, MySQL passwords, shell history, S3 configurations), and exfiltrated the collected data. Additionally, approximately 7,900 billing portal customer records were stolen, and three OPSSHIELD cloud servers were copied. The attack window was approximately 70 minutes before detection and remediation began.

---

## Background

**cPGuard** is a commercial security suite for Linux web hosting servers, providing malware scanning, firewall management, and intrusion detection. It is developed by **OPSSHIELD** (previously ServerManage) and integrates with cPanel/WHM, DirectAdmin, and other hosting control panels. The product uses an auto-update agent (`cpgcli`) that runs as root and fetches updates from OPSSHIELD's CDN infrastructure.

The auto-update mechanism's root-level execution privileges made the update channel a high-value target: any code delivered through it would execute with full system privileges on every server that received the update.

---

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| **Nov 1, 15:38** | Attacker begins probing the billing portal (manage.opsshield[.]com) |
| **Nov 1, 16:34** | Attacker registers a customer account under a false identity; orders a free cPGuard trial |
| **Nov 1, 21:17** | Attacker installs the trial on their own server to study agent-to-licensing communication |
| **Nov 1, 21:40-21:51** | cPGuard flags and bans the attacker twice (bans not enforced on nftables firewalls) |
| **Nov 1, 22:50** | Attacker sends crafted requests to billing portal callback pages |
| **Nov 1, 22:58** | Attacker gains command execution on the billing and licensing server; begins data collection |
| **Nov 2, 02:04-02:09** | Attacker uploads the malicious script to update storage using a stolen update-publishing key |
| **Nov 2, 02:08-03:20** | cPGuard agents on ~2,950 servers install the fake update (runs as root); ~70-minute window |
| **Nov 2, 02:13** | Attacker copies three OPSSHIELD cloud servers |
| **Nov 2 (within 12h)** | OPSSHIELD detects the compromise; stolen update key revoked |
| **Nov 2** | Clean update v5.88.26 published (removes backdoor shell) |
| **Nov 3** | Entry point traced; initial advisory published |
| **Nov 3** | Follow-up update removes the i93677 scheduled task |
| **Nov 4** | Full incident disclosure published |

---

## Root Cause

The root cause was **insufficient access controls on the billing portal callback endpoints** at manage.opsshield[.]com. A newly registered trial customer account was able to send crafted requests to callback pages that granted command execution on the billing and licensing server. OPSSHIELD's logs do not capture the exact request that granted access, but two suspected entry points have been patched, and vendor components are undergoing line-by-line review.

Contributing factors:
- **nftables firewall bug**: cPGuard's temporary bans were not enforced on nftables-based firewalls, allowing the attacker to continue probing after being banned twice.
- **Update key storage**: The update-publishing key was accessible from the compromised billing/licensing server.
- **Root-level auto-update**: The update agent runs as root with no code-signing verification beyond the CDN access key.

---

## Technical Analysis

### Stage 1: Initial Access and Reconnaissance

The attacker registered a trial account on the billing portal and installed cPGuard on their own server to study the update protocol. After being banned twice (bans ineffective due to the nftables bug), the attacker sent crafted requests to billing portal callback pages, achieving command execution on the billing and licensing server at 22:58 UTC on November 1.

**Artifacts on the OPSSHIELD billing server:**
- `/i90248_probe.txt` - probe file
- `/i90573_probe.txt` - probe file
- `/i90573_sh.php` - web shell
- `/i90573_x.php` - web shell

The file naming follows a distinctive `i9xxxx` pattern consistent across all attack artifacts.

### Stage 2: Update Channel Hijack

Between 02:04-02:09 UTC on November 2, the attacker used the stolen update-publishing key to upload four variants of a malicious shell script to the update CDN:

| Script Variant | SHA-256 |
|---|---|
| `cpguard-v58812-i91511.sh` | `2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38` |
| `cpguard-v58812-i91511b.sh` | `ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a` |
| `cpguard-v58812-i91511c.sh` | `d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26` |
| `cpguard-v58812-i91511d.sh` | `6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77` |

These were distributed as versions 5.88.12 through 5.88.19 via the normal auto-update channel.

### Stage 3: Malicious Payload Execution

The malicious script executed as root on each victim server and performed the following actions:

**Credential Harvesting:**
- `/etc/shadow` and `/etc/passwd` (local password hashes and user accounts)
- `/root/.ssh/` (SSH private keys, authorized_keys, known_hosts)
- `/root/.my.cnf` (MySQL/MariaDB root password, where present)
- Root shell history (may contain plaintext passwords, API tokens)
- `/root/.s3cfg` (S3/cloud storage access keys, on select servers)

**Staging and Exfiltration:**
- Created hidden directory `/var/tmp/.cpg91511/`
- Packaged collected data as `/var/tmp/.cpg91511/loot.tgz`
- Exfiltrated via HTTP POST to `*_rx.php` endpoints

**Persistence:**
- Installed setuid-root backdoor shell at `/var/tmp/.cpg91511_sh`
- Created scheduled task at `/etc/cron.d/i93677` with supporting files in `/var/tmp/.i93677/`

### Stage 4: OPSSHIELD Infrastructure Compromise

Beyond the customer servers, the attacker installed additional persistent implants on OPSSHIELD's internal servers:

**gsocket Backdoor:**
- Binary: `/usr/bin/defunct`
- Systemd service: `defunct.service`
- Data file: `/lib/systemd/system/defunct.dat`
- Masquerades as kernel thread: `[slub_flushwq]`

**Go-based Implant (multiple copies):**
- `/usr/sbin/pythno3` (typosquatting python3)
- `/usr/sbin/netstat.cfg`
- `/etc/profile.d/bash.cfg`
- `/usr/lib/system.mark`
- `/usr/lib/libgdi.so.0.8.2`
- `/boot/system.pub`
- Masquerades as kernel thread: `[rcu_gp]`

**Process Hiding:**
- `/etc/profile.d/gateway.sh` - hides the implant from `ps`, `netstat`, `ls`, and `find`

### Stage 5: Data Exfiltration

- Approximately 32 files per host were collected and exfiltrated
- Exfiltration occurred via HTTP POST to `*_rx.php` endpoints
- The attacker used the IP `94.183.188[.]91` with a fake `cPGuard/5.88.11` User-Agent
- Billing portal database (~7,900 customer records) was also exfiltrated
- Three OPSSHIELD cloud servers were copied at 02:13 UTC

---

## Indicators of Compromise

> **Note:** All indicators are defanged where applicable. Replace `[.]` with `.` for operational use.

### Network Indicators

| Type | Indicator | Context |
|---|---|---|
| IP Address | `94.183.188[.]91` | Primary attacker operating address |
| User-Agent | `cPGuard/5.88.11` | Fake User-Agent used by attacker |
| URL Pattern | `*_rx.php` | Exfiltration endpoints |

### File Hashes (SHA-256)

| Hash | Filename |
|---|---|
| `2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38` | cpguard-v58812-i91511.sh |
| `ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a` | cpguard-v58812-i91511b.sh |
| `d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26` | cpguard-v58812-i91511c.sh |
| `6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77` | cpguard-v58812-i91511d.sh |

### File Paths - Customer Servers

| Path | Description |
|---|---|
| `/var/tmp/.cpg91511_sh` | Setuid-root backdoor shell |
| `/var/tmp/.cpg91511/` | Staging directory for harvested data |
| `/var/tmp/.cpg91511/loot.tgz` | Packaged exfiltration archive |
| `/etc/cron.d/i93677` | Persistence scheduled task |
| `/var/tmp/.i93677/` | Scheduled task supporting files |

### File Paths - OPSSHIELD Infrastructure (for reference)

| Path | Description |
|---|---|
| `/i90248_probe.txt` | Probe file (web root) |
| `/i90573_probe.txt` | Probe file (web root) |
| `/i90573_sh.php` | Web shell |
| `/i90573_x.php` | Web shell |
| `/usr/bin/defunct` | gsocket backdoor binary |
| `defunct.service` | gsocket systemd service |
| `/lib/systemd/system/defunct.dat` | gsocket data file |
| `/usr/sbin/pythno3` | Go implant (typosquat) |
| `/usr/sbin/netstat.cfg` | Go implant copy |
| `/etc/profile.d/bash.cfg` | Go implant copy |
| `/usr/lib/system.mark` | Go implant copy |
| `/usr/lib/libgdi.so.0.8.2` | Go implant copy |
| `/boot/system.pub` | Go implant copy |
| `/etc/profile.d/gateway.sh` | Process-hiding script |

### Detection via cPGuard Logs

Check for affected installation:
```bash
grep 'Successfully updated' /opt/cpguard/logs/install_log
```
Versions 5.88.12 through 5.88.19 indicate an affected install. Note: this confirms installation of the affected update but does not prove the malicious script executed.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Context |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Hijacked cPGuard update channel to distribute malicious scripts |
| T1078 | Valid Accounts | Used compromised credentials to access update CDN and licensing server |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Malicious bash scripts executed as root |
| T1072 | Software Deployment Tools | Abused the cPGuard auto-update mechanism for distribution |
| T1053.003 | Scheduled Task/Job: Cron | Installed persistence via /etc/cron.d/i93677 |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | Setuid-root backdoor shell at /var/tmp/.cpg91511_sh |
| T1003 | OS Credential Dumping | Harvested /etc/shadow password hashes |
| T1552.004 | Unsecured Credentials: Private Keys | Collected SSH private keys from /root/.ssh/ |
| T1552.001 | Unsecured Credentials: Credentials In Files | Collected MySQL credentials from /root/.my.cnf and S3 keys from /root/.s3cfg |
| T1005 | Data from Local System | Collected shell history, SSH configs, credential files |
| T1074.001 | Data Staged: Local Data Staging | Staged collected data in /var/tmp/.cpg91511/loot.tgz |
| T1041 | Exfiltration Over C2 Channel | Exfiltrated loot.tgz via HTTP POST to _rx.php endpoints |
| T1505.003 | Server Software Component: Web Shell | Web shells deployed on OPSSHIELD billing server |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | Hidden dotfiles/directories in /var/tmp/ |
| T1036.004 | Masquerading: Masquerade Task or Service | Implants masquerade as kernel threads [slub_flushwq] and [rcu_gp] |
| T1070 | Indicator Removal | gateway.sh script hides processes from ps, netstat, ls, find |

---

## Impact Assessment

### Scope
- **~2,950 Linux servers** executed the malicious update as root
- **~7,900 customer accounts** had billing data (name, company, address, email, bcrypt-hashed passwords) exfiltrated
- **3 OPSSHIELD cloud servers** were cloned by the attacker
- **All cPGuard license keys** are being reissued

### Severity: CRITICAL

The attack achieved root-level access on approximately 2,950 servers through a trusted update channel. Exfiltrated data includes password hashes, SSH private keys, database credentials, and shell history containing potential plaintext secrets. Each compromised server's SSH keys may grant lateral access to additional systems.

### Cascading Risk
- Servers reachable via SSH keys from affected hosts must be treated as exposed
- MySQL/MariaDB credentials may grant access to customer databases
- S3/cloud storage keys may provide access to backups and data stores
- Shell history may contain API tokens, passwords, and other secrets typed at the command line

---

## Detection & Remediation

### Immediate Detection Steps

1. **Check update logs:**
   ```bash
   grep 'Successfully updated to 5\.88\.1[2-9]' /opt/cpguard/logs/install_log
   ```

2. **Check for persistence artifacts:**
   ```bash
   ls -la /var/tmp/.cpg91511_sh /etc/cron.d/i93677 /var/tmp/.i93677/ /var/tmp/.cpg91511/ 2>/dev/null
   ```

3. **Check for infrastructure implants (if operating OPSSHIELD-like infrastructure):**
   ```bash
   ls -la /usr/bin/defunct /usr/sbin/pythno3 /usr/sbin/netstat.cfg /etc/profile.d/gateway.sh 2>/dev/null
   ```

### Remediation Steps

1. **Update cPGuard immediately:** `cpgcli update --start` -- verify version >= 5.88.26
2. **Verify artifact removal:** Confirm `/etc/cron.d/i93677`, `/var/tmp/.i93677/`, and `/var/tmp/.cpg91511_sh` are removed; delete manually if present
3. **Reset all root credentials:** From a trusted recovery environment, change root password and all local user passwords
4. **Rotate SSH keys:** Generate new root SSH keys; remove old public keys from all authorized_keys files; review for unrecognized entries
5. **Rotate database credentials:** Change MySQL root password and all passwords in `/root/.my.cnf`
6. **Rotate cloud/API credentials:** S3 keys, DigitalOcean tokens, and any secrets found in shell history
7. **Assess lateral exposure:** Treat all servers reachable via SSH keys from an affected host as potentially compromised
8. **Reset billing portal password:** All OPSSHIELD customers should reset their portal password and enable 2FA at manage.opsshield[.]com
9. **Rebuild if confirmed manual access:** If OPSSHIELD confirms manual attacker login on a server, rebuild from a clean backup taken before November 1

> **Important:** Because the attacker's hiding script conceals implants from standard tools (`ps`, `netstat`, `ls`, `find`), verify from a trusted boot environment or using known-good static binaries.

---

## Detection Rules

### Sigma Rules

**File:** `rules/sigma/2026-11-07-cpguard-supply-chain.yml`

| Rule Title | Compile Status | Confidence | Notes |
|---|---|---|---|
| cPGuard Supply Chain Attack - Malicious Update Script Artifacts | ✅ compiles | **High** | File-event detection for all known malicious file paths including customer-side and infrastructure artifacts. Very low false-positive risk due to highly specific paths. |
| cPGuard Supply Chain Attack - Malicious Script Execution | ✅ compiles | **High** | Process-creation detection for malicious script names and disguised implant processes. |
| cPGuard Supply Chain Attack - Credential Harvesting Behavior | ✅ compiles | **Medium** | Behavioral detection combining /etc/shadow, SSH key, or MySQL credential access with staging directory activity. May trigger on legitimate security auditing tools that read /etc/shadow while writing to /var/tmp. |

**Validation:** Successfully converted to Splunk and LogScale via `sigma convert --without-pipeline`. The `sigma check` command failed due to inability to fetch MITRE ATT&CK data in the validation environment (network restriction), not due to rule syntax errors.

<!-- audit: sigma check could not validate ATT&CK tags due to proxy/network restriction blocking the MITRE data download. Rules parse and convert correctly. Manual review of tag format confirms compliance with SigmaHQ schema. -->

### YARA Rules

**File:** `rules/yara/2026-11-07-cpguard-supply-chain.yar`

| Rule Name | Compile Status | Confidence | Notes |
|---|---|---|---|
| CPGuard_Malicious_Update_Script | ✅ compiles | **High** | Detects the malicious shell scripts by script names, file paths, and credential harvesting patterns. Requires shebang header. |
| CPGuard_Backdoor_Shell | ✅ compiles | **High** | Detects the setuid-root backdoor ELF binary by path strings. |
| CPGuard_GSocket_Backdoor | ✅ compiles | **High** | Detects the gsocket backdoor by service name, binary path, and fake process name. |
| CPGuard_Go_Implant | ✅ compiles | **High** | Detects the Go-based implant ELF binary by its distinctive file paths (typosquatted names). |
| CPGuard_Webshell_Artifacts | ✅ compiles | **Medium** | Detects web shells by the i9xxxx naming pattern. Slightly broader matching. |
| CPGuard_Hiding_Script | ✅ compiles | **Medium** | Detects the process-hiding shell script by combining gateway.sh path with tool names and fake process names. |

**Validation:** All rules compiled successfully via `yarac`.

### Snort Rules

**File:** `rules/snort/2026-11-07-cpguard-supply-chain.rules`

| SID | Rule Description | Compile Status | Confidence | Notes |
|---|---|---|---|---|
| 2026110701 | Outbound connection to attacker IP 94.183.188[.]91 | ✅ compiles | **High** | Direct IOC match. Will become stale when infrastructure changes. |
| 2026110702 | Inbound connection from attacker IP 94.183.188[.]91 | ✅ compiles | **High** | Direct IOC match. |
| 2026110703 | Fake cPGuard/5.88.11 User-Agent | ✅ compiles | **Medium** | Detects the specific fake UA string; limited shelf life. |
| 2026110704 | POST to _rx.php exfiltration endpoint | ✅ compiles | **Medium** | Detects the exfiltration URL pattern. May match legitimate PHP endpoints ending in _rx.php. |
| 2026110705 | Malicious update script name in HTTP traffic | ✅ compiles | **High** | Detects the distinctive cpguard-v58812-i91511 string in URI. |
| 2026110706 | Exfiltration of loot.tgz archive | ✅ compiles | **Medium** | POST request with loot.tgz in URI. Generic filename could cause FPs in other contexts. |

**Validation:** Successfully validated via `snort -T`.

### Suricata Rules

**File:** `rules/suricata/2026-11-07-cpguard-supply-chain.rules`

| SID | Rule Description | Compile Status | Confidence | Notes |
|---|---|---|---|---|
| 2026110801 | Outbound connection to attacker IP 94.183.188[.]91 | ✅ compiles | **High** | Direct IOC match. |
| 2026110802 | Inbound connection from attacker IP 94.183.188[.]91 | ✅ compiles | **High** | Direct IOC match. |
| 2026110803 | Fake cPGuard/5.88.11 User-Agent | ✅ compiles | **Medium** | Uses sticky buffer http.user_agent. |
| 2026110804 | POST to _rx.php exfiltration endpoint | ✅ compiles | **Medium** | Uses sticky buffers http.method and http.uri. |
| 2026110805 | Malicious update script name in HTTP traffic | ✅ compiles | **High** | Distinctive string match in http.uri. |
| 2026110806 | Exfiltration of loot.tgz archive | ✅ compiles | **Medium** | POST with loot.tgz in URI. |

**Validation:** Successfully validated via `suricata -T`.

---

## Sources

- [The Hacker News: cPGuard Update Channel Hijacked to Backdoor Linux Servers and Collect Password Hashes](https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html)
- [OPSSHIELD Advisory: cPGuard Update Channel Compromise](https://opsshield.com/notice/cpguard-update-channel-compromise.html)
- [OPSSHIELD Full Disclosure: Security Incident Disclosure - ServerManage](https://opsshield.com/notice/security-incident-disclosure-servermanage.html)
- [OPSSHIELD Full Disclosure (Archived Nov 4)](https://web.archive.org/web/20261104101526/https://opsshield.com/notice/security-incident-disclosure-servermanage.html)
- [Aviatrix Threat Research: cPGuard Autoupdate Hijack 2026](https://aviatrix.ai/threat-research-center/hackers-hijack-cpguard-autoupdate-backdoor-steal-data-2026/)
- [Shattered.io: cPGuard Supply Chain Attack - 2,950 Servers Hit](https://shattered.io/opsshield-cpguard-supply-chain-attack-2950-servers-root-2026/)
- [The Hacker Wire: cPGuard Update Channel Hijacked to Backdoor Linux Servers](https://www.thehackerwire.com/cpguard-update-channel-hijacked-to-backdoor-linux-servers-and-steal-credentials/)
- [Security Online: cPGuard Supply Chain Attack](https://securityonline.info/cpguard-supply-chain-attack/)
- [Cryptika: Hackers Hijacked Linux Hosting Server Security Tool cPGuard](https://www.cryptika.com/hackers-hijacked-linux-hosting-server-security-tool-cpguard-and-used-it-as-a-backdoor/)
- [SafetyBis: cPGuard Supply-Chain Breach - Rotate Secrets](https://www.safetybis.com/blog/cpguard-supply-chain-rotate-secrets/)
- [OPSSHIELD Support](https://support.opsshield.com/shared/support)
