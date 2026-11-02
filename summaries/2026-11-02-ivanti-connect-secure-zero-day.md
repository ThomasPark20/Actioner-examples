# Technical Analysis Report: Ivanti Connect Secure Zero-Day Exploitation (CVE-2025-0282) (2026-11-02)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-02
Version: 1.0

## Executive Summary

Two critical zero-day vulnerabilities in Ivanti Connect Secure VPN appliances — CVE-2025-0282 (unauthenticated remote code execution, CVSS 9.0) and CVE-2025-0283 (authenticated local privilege escalation) — have been actively exploited by UNC5221, a suspected China-nexus espionage actor, since at least mid-December 2024. The campaign deploys a sophisticated malware ecosystem including SPAWNANT (persistence installer), SPAWNMOLE (tunneler), SPAWNSNAIL (SSH backdoor), SPAWNSLOTH (log tamper), PHASEJAM (web shell dropper), and DRYHOOK (credential stealer) to maintain persistent access that survives firmware upgrades.

The attack is notable for its anti-forensic sophistication: the threat actor blocks syslog forwarding via iptables, tampers with Ivanti's Integrity Checker Tool manifest by re-signing it with a new RSA key pair, and deploys a fake upgrade mechanism that simulates a 13-step progress bar while preserving implants. Affected organizations should immediately apply Ivanti Connect Secure 22.7R2.5, perform factory resets on compromised appliances, and rotate all credentials that may have transited the VPN, including LDAP service accounts and VPN session tokens.

## Background: Ivanti Connect Secure

Ivanti Connect Secure (formerly Pulse Connect Secure) is an SSL VPN gateway widely deployed across enterprise and government networks for remote access. Its internet-facing nature and access to internal network resources make it a high-value target. UNC5221 has repeatedly targeted Ivanti products, having previously exploited CVE-2023-46805 and CVE-2024-21887 in late 2023, establishing the SPAWN malware family as their signature toolset for these appliances.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Mid-December 2024 | Earliest observed exploitation of CVE-2025-0282 in the wild |
| 2024-12-xx | Attackers perform version fingerprinting via hc_launcher JAR requests |
| 2024-12-xx | Initial exploitation, PHASEJAM deployment, web shell installation |
| 2024-12-xx | SPAWNANT/SPAWNMOLE/SPAWNSNAIL deployed for persistent backdoor access |
| 2024-12-xx | DRYHOOK deployed to harvest credentials from DSAuth.pm |
| 2024-12-xx | LDAP harvesting and lateral movement to Active Directory via SMB/RDP |
| 2025-01-08 | Mandiant/Google Threat Intelligence publishes detailed analysis |
| 2025-01-08 | Ivanti releases Connect Secure 22.7R2.5 patch |
| 2025-01-08 | CISA adds CVE-2025-0282 to Known Exploited Vulnerabilities catalog |

## Root Cause: Stack-Based Buffer Overflow (CVE-2025-0282)

CVE-2025-0282 is an unauthenticated stack-based buffer overflow in the Ivanti Connect Secure web component, affecting versions prior to 22.7R2.5. The vulnerability allows remote code execution without authentication, making it ideal for initial access. Exploitation is version-specific — attackers fingerprint the exact firmware version by requesting known version-specific Host Checker JAR files (`/dana-cached/hc/hc_launcher.<version>.jar`) before sending the exploit payload. CVE-2025-0283 is a related stack-based buffer overflow enabling authenticated local privilege escalation, though technical details are limited.

## Technical Analysis of the Malicious Payload

### 1. Initial Exploitation and Staging (PHASEJAM Dropper)

After exploiting CVE-2025-0282, the attacker executes a multi-stage bootstrap:

1. Disables SELinux: `setenforce 0`
2. Blocks syslog forwarding: iptables rules drop outbound UDP/TCP 514 and 6514
3. Remounts root filesystem read-write: `mount -o remount,rw /`
4. Writes base64-encoded staging script to `/tmp/.t`
5. Creates setuid ELF loader at `/tmp/svb` (chmod 6777), which calls `setuid(0)` and executes `/tmp/s` (PHASEJAM)
6. After execution, `/tmp/svb` is zeroed with `dd`, permissions reset, and deleted

PHASEJAM (`/tmp/s`) is a bash script that deploys web shells into Ivanti's CGI infrastructure:
- Injects `AccessAllow()` Perl subroutine into `/home/webserver/htdocs/dana-na/jam/getComponent.cgi` and `/home/webserver/htdocs/dana-na/auth/restAuth.cgi`
- Replaces `/home/bin/remotedebug` with a hook script (original backed up to `remotedebug.bak`)
- Web shell supports 5 commands via HTTP parameters: command execution (cmd 1/2), file upload (cmd 3/5), and file exfiltration (cmd 4)

### 2. Persistence Ecosystem (SPAWN Family)

**SPAWNANT** (`/root/lib/libupgrade.so`, ELF32): Hijacks `dspkginstall` via exported `snprintf` using LD_PRELOAD. On firmware upgrade, copies itself and companion libraries to the new partition, sets `LD_PRELOAD` in `DSUpgrade.pm`, and deploys `compcheckresult.cgi` web shell — surviving the upgrade.

**SPAWNMOLE** (`/root/home/lib/libsocks5.so`): Hooks `accept()` in the `web` process. Activates on a magic-byte sequence in incoming connections to tunnel attacker traffic. All other traffic passes unmodified, making detection via traffic analysis difficult.

**SPAWNSNAIL** (`/root/home/lib/libsshd.so`): Injected into `dsmdm` and `dslogserver` processes. Provides SSH backdoor capability with embedded private key material.

**SPAWNSLOTH** (`/tmp/.liblogblock.so`): Blocks log generation to prevent detection.

### 3. C2 Infrastructure

C2 communication occurs through the implanted web shells on the Ivanti appliance itself — the attacker sends HTTP requests to the compromised CGI endpoints with commands encoded in query parameters and the `HTTP_CODE` header. SPAWNMOLE provides an additional tunneling channel activated by magic bytes in the connection stream. No external C2 domains or IPs were published in the analyzed source.

### 4. Credential Theft (DRYHOOK)

DRYHOOK patches `DSAuth.pm` to intercept `setPrompt`, `runSignin`, and `runSigninEBSL` functions. On successful authentication, it writes RC4-encrypted (hardcoded key) and Base64-encoded `username=password` pairs to `/tmp/cmdmmap.kuwMW`. This captures all VPN user credentials in real time.

### 5. Anti-Forensics / Evasion Techniques

- **Log wiping**: `sed -i` removes lines containing `segfault`, `SystemError`, `setenforce`, `mount`, `bin/rm`, `bin/web` from debug logs, audit logs, and event logs
- **Syslog suppression**: iptables blocks outbound ports 514 and 6514
- **ICT evasion**: Recomputes SHA256 hashes for all modified files, generates a new RSA-2048 key pair, and re-signs the integrity manifest
- **Evidence destruction**: Removes core dumps (`/data/var/cores/*`), state dumps (`/data/var/statedumps/*`), and clears dmesg
- **Fake upgrade**: Patches `DSUpgrade.pm` to display a fake 13-step progress bar and overwrites `/home/VERSION` with the new version, while the actual upgrade never executes

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### File System

| Platform | Path | Hash (MD5) | Description |
|----------|------|------------|-------------|
| ICS | /tmp/.t | — | Base64 staging script (deleted after execution) |
| ICS | /tmp/svb | — | Setuid ELF loader (zeroed and deleted) |
| ICS | /tmp/s | d18e5425ecd9608ecb992606b974e15d | PHASEJAM dropper (bash) |
| ICS | /tmp/.liblogblock.so | — | SPAWNSLOTH log tamper |
| ICS | /tmp/cmdmmap.kuwMW | — | DRYHOOK credential log (RC4+Base64) |
| ICS | /tmp/lmdbcerr | — | LDAP query tool |
| ICS | /root/lib/libupgrade.so | 61bb586dc4e047ab081ef6ca65684e48 | SPAWNANT installer |
| ICS | /root/home/lib/libsshd.so | e7d24813535f74187db31d4114f607a1 | SPAWNSNAIL SSH backdoor |
| ICS | /root/home/lib/libsocks5.so | a638fd203ddb540d0484d8e00490df06 | SPAWNMOLE tunneler |
| ICS | /home/webserver/htdocs/dana-na/jam/getComponent.cgi | — | Web shell host |
| ICS | /home/webserver/htdocs/dana-na/auth/restAuth.cgi | — | Web shell host |
| ICS | /home/webserver/htdocs/dana-na/auth/compcheckresult.cgi | — | SPAWNANT web shell (upgrade partition) |
| ICS | /home/bin/remotedebug | — | Replaced with command hook |
| ICS | /home/perl/DSUpgrade.pm | — | Patched for fake upgrade |
| ICS | /home/perl/DSAuth.pm | — | Patched by DRYHOOK |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | /dana-cached/hc/hc_launcher.22.7.2.XXXX.jar | Version fingerprinting reconnaissance |
| URL Pattern | /dana-na/jam/getComponent.cgi | PHASEJAM web shell endpoint |
| URL Pattern | /dana-na/auth/restAuth.cgi | PHASEJAM web shell endpoint |

### Behavioral

- Process chain: exploitation → `setenforce 0` → iptables syslog block → `mount -o remount,rw /` → base64 decode → setuid binary → PHASEJAM dropper
- File modification: `.bak` copies created alongside web shell targets
- LDAP queries from VPN appliance to domain controllers using managed service accounts
- Archive of `/runtime/mtmp/lmdb` disguised as CSS file in `/home/webserver/htdocs/dana-na/css/`
- SMB and RDP lateral movement from VPN appliance to internal hosts

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | CVE-2025-0282 unauthenticated RCE against Ivanti Connect Secure |
| T1068 | Exploitation for Privilege Escalation | Setuid ELF binary `/tmp/svb` for root escalation |
| T1059.004 | Unix Shell | Bash staging scripts and PHASEJAM dropper |
| T1505.003 | Web Shell | getComponent.cgi, restAuth.cgi, compcheckresult.cgi |
| T1574.006 | Dynamic Linker Hijacking | SPAWNANT LD_PRELOAD persistence via libupgrade.so |
| T1556 | Modify Authentication Process | DRYHOOK patching DSAuth.pm credential capture |
| T1562.006 | Indicator Blocking | iptables blocking syslog on ports 514/6514 |
| T1070.002 | Clear Linux or Mac System Logs | sed-based removal of exploitation artifacts from logs |
| T1070.004 | File Deletion | Zeroing and removing staging artifacts |
| T1601 | Modify System Image | Fake upgrade mechanism, VERSION file falsification |
| T1046 | Network Service Discovery | nmap from compromised appliance |
| T1087.002 | Domain Account Discovery | LDAP harvesting of Active Directory |
| T1021.002 | SMB/Windows Admin Shares | Lateral movement to domain controllers |
| T1572 | Protocol Tunneling | SPAWNMOLE tunneler and PySoxy |
| T1552 | Unsecured Credentials | DRYHOOK credential theft and cache archive theft |

## Impact Assessment

Ivanti Connect Secure is deployed across thousands of organizations globally, including government agencies and Fortune 500 companies. The campaign demonstrates a high degree of sophistication with upgrade-surviving persistence, integrity tool evasion, and credential harvesting. The attacker's ability to harvest VPN credentials and LDAP data enables extensive follow-on access to internal networks even after the appliance is patched, making credential rotation critical. CISA issued an emergency directive requiring federal agencies to disconnect and patch affected devices.

## Detection & Remediation

### Immediate Detection

```bash
# Check for PHASEJAM web shell markers in CGI files
grep -l 'AccessAllow()' /home/webserver/htdocs/dana-na/jam/getComponent.cgi /home/webserver/htdocs/dana-na/auth/restAuth.cgi 2>/dev/null

# Check for SPAWNANT persistence libraries
ls -la /root/lib/libupgrade.so /root/home/lib/libsshd.so /root/home/lib/libsocks5.so /tmp/.liblogblock.so 2>/dev/null

# Check for DRYHOOK credential log
ls -la /tmp/cmdmmap.kuwMW 2>/dev/null

# Check for remotedebug replacement
file /home/bin/remotedebug  # Should be ELF, not script

# Check for syslog blocking iptables rules
iptables -L OUTPUT -n | grep -E '(514|6514)'

# Check for DSUpgrade.pm tampering
grep 'processUpgradeDisplay' /home/perl/DSUpgrade.pm

# Run Ivanti Integrity Checker Tool (ICT) — but note it can be evaded
```

### Remediation

1. **Isolate** affected appliances immediately; do not continue normal operations
2. **Capture forensic image** before any remediation — the threat actor aggressively wipes artifacts
3. **Factory reset** the Ivanti appliance (not just patch — SPAWNANT survives upgrades)
4. **Apply** Ivanti Connect Secure 22.7R2.5 on the factory-reset appliance
5. **Rotate ALL credentials** that transited the VPN: user passwords, LDAP service accounts, certificates, API keys, session tokens
6. **Review** LDAP query logs and Active Directory for unauthorized access from VPN appliance IPs
7. **Hunt** for lateral movement indicators: SMB/RDP connections from VPN appliance to internal hosts

### Long-Term Hardening

- Implement network segmentation limiting VPN appliance access to only required internal services
- Deploy out-of-band monitoring for VPN appliance — do not rely solely on appliance-generated syslog
- Monitor for version-fingerprinting HTTP requests to `/dana-cached/hc/hc_launcher.*.jar` from non-client sources
- Subscribe to Ivanti security advisories for timely patching
- Consider deploying YARA rules on appliance filesystem snapshots as a secondary integrity check

## Detection Rules

These rules detect post-exploitation artifacts from the UNC5221 campaign targeting Ivanti Connect Secure via CVE-2025-0282. The Sigma rules cover file creation for web shells and persistence libraries, iptables-based syslog blocking, log tampering via sed, and version fingerprinting reconnaissance. YARA rules target the five known malware families (PHASEJAM, SPAWNANT, DRYHOOK, SPAWNSNAIL, SPAWNMOLE). Network rules detect web shell access and version fingerprinting requests. Note: without IOC-level C2 infrastructure (no IPs/domains published), network detection focuses on the on-appliance web shell URI patterns.

### Sigma: Ivanti Connect Secure Web Shell File Creation

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check crashes on MITRE ATT&CK data fetch (proxy 403), not a rule syntax issue; 5 rules all convert cleanly to both SPL and LogScale -->

Detects file creation in Ivanti Connect Secure dana-na web directories consistent with PHASEJAM web shell deployment.

✅ compiles (Splunk + LogScale) · confidence: high

```yaml
title: Ivanti Connect Secure Post-Exploitation - Web Shell Creation in Dana Directories
id: 7a3e9c1b-4d2f-48e6-b5a1-9c0d3e7f2a8b
status: experimental
description: >
    Detects file creation events in Ivanti Connect Secure web-accessible directories
    (dana-na) consistent with PHASEJAM web shell deployment following exploitation
    of CVE-2025-0282. The attacker drops web shells into getComponent.cgi and
    restAuth.cgi after gaining unauthenticated RCE.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day
    - https://www.ivanti.com/blog/security-update-ivanti-connect-secure-policy-secure-and-neurons-for-zta-gateways
author: Actioner
date: 2026-11-02
tags:
    - attack.t1505.003
    - attack.t1190
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|contains:
            - '/home/webserver/htdocs/dana-na/jam/getComponent.cgi'
            - '/home/webserver/htdocs/dana-na/auth/restAuth.cgi'
            - '/home/webserver/htdocs/dana-na/auth/compcheckresult.cgi'
    condition: selection_path
falsepositives:
    - Legitimate Ivanti Connect Secure software updates modifying CGI files
level: critical
```

### Sigma: SPAWNANT Persistence Library Creation

Detects creation of malicious shared libraries used for LD_PRELOAD persistence.

✅ compiles (Splunk + LogScale) · confidence: high

```yaml
title: Ivanti Connect Secure Post-Exploitation - SPAWNANT Persistence via LD_PRELOAD
id: 2f8b4e6a-1c3d-49a7-8e5b-0d7f9a2c6b1e
status: experimental
description: >
    Detects creation of shared libraries used by the SPAWNANT installer for
    LD_PRELOAD-based persistence on Ivanti Connect Secure appliances.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day
author: Actioner
date: 2026-11-02
tags:
    - attack.t1574.006
logsource:
    category: file_event
    product: linux
detection:
    selection_libs:
        TargetFilename|endswith:
            - '/lib/libupgrade.so'
            - '/lib/libsocks5.so'
            - '/lib/libsshd.so'
            - '/tmp/.liblogblock.so'
    condition: selection_libs
falsepositives:
    - Legitimate Ivanti shared library updates during patching
level: high
```

### Sigma: Syslog Blocking via Iptables

Detects iptables rules blocking outbound syslog traffic to prevent log forwarding.

✅ compiles (Splunk + LogScale) · confidence: high

```yaml
title: Ivanti Connect Secure Post-Exploitation - Syslog Blocking via Iptables
id: 5e9d1a3c-7b4f-42e8-9c6d-8a0e2f5b3d7c
status: experimental
description: >
    Detects iptables commands that block outbound syslog traffic on ports 514 and
    6514, used by UNC5221 to prevent log forwarding from compromised appliances.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day
author: Actioner
date: 2026-11-02
tags:
    - attack.t1562.006
logsource:
    category: process_creation
    product: linux
detection:
    selection_iptables:
        Image|endswith: '/iptables'
        CommandLine|contains|all:
            - 'OUTPUT'
            - 'DROP'
    selection_ports:
        CommandLine|contains:
            - '--dport 514'
            - '--dport 6514'
    condition: selection_iptables and selection_ports
falsepositives:
    - Legitimate firewall hardening blocking outbound syslog
level: high
```

### Sigma: Log Tampering via Sed

Detects sed-based removal of exploitation artifacts from Ivanti debug and audit logs.

✅ compiles (Splunk + LogScale) · confidence: critical

```yaml
title: Ivanti Connect Secure Post-Exploitation - Log Tampering via Sed
id: 8c2f5b7d-3a1e-4d9f-6e0b-4c8a9d1f7e3b
status: experimental
description: >
    Detects sed commands used to remove evidence of exploitation from Ivanti
    debug and audit logs by UNC5221.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day
author: Actioner
date: 2026-11-02
tags:
    - attack.t1070.002
logsource:
    category: process_creation
    product: linux
detection:
    selection_sed:
        Image|endswith: '/sed'
        CommandLine|contains: '-i'
    selection_targets:
        CommandLine|contains:
            - 'debuglog'
            - 'audit.log'
            - 'log.events.vc0'
    selection_patterns:
        CommandLine|contains:
            - 'segfault'
            - 'setenforce'
            - 'AUT24604'
            - 'SYS31048'
    condition: selection_sed and selection_targets and selection_patterns
falsepositives:
    - Legitimate log rotation scripts (unlikely to match specific patterns)
level: critical
```

### Sigma: Version Fingerprinting via HC Launcher

Detects HTTP requests to version-specific Host Checker JAR files used for pre-exploitation reconnaissance.

✅ compiles (Splunk + LogScale) · confidence: medium

```yaml
title: Ivanti Connect Secure Pre-Exploitation - Version Fingerprinting via HC Launcher
id: 4d7e2a9b-6c1f-43b8-5e0d-1a3c8b5f9e2d
status: experimental
description: >
    Detects HTTP requests to Ivanti Connect Secure Host Checker launcher JAR files
    used for version fingerprinting prior to CVE-2025-0282 exploitation.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day
author: Actioner
date: 2026-11-02
tags:
    - attack.t1592.004
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/dana-cached/hc/hc_launcher.'
        cs-uri-stem|endswith: '.jar'
    condition: selection
falsepositives:
    - Legitimate Host Checker component downloads by VPN clients
    - Vulnerability scanners checking Ivanti versions
level: medium
```

### YARA: PHASEJAM Dropper

Detects the PHASEJAM bash dropper script by its distinctive web shell deployment strings.

✅ compiles (`yarac` exit 0) · confidence: high

```yara
rule APT_UNC5221_PHASEJAM_Dropper
{
    meta:
        description = "Detects PHASEJAM dropper script used by UNC5221 to deploy web shells on Ivanti Connect Secure"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
        severity = "critical"

    strings:
        $s1 = "AccessAllow()" ascii
        $s2 = "/jam/getComponent.cgi" ascii
        $s3 = "sub AccessAllow()" ascii
        $s4 = "cp -f /home/bin/remotedebug" ascii
        $s5 = "pkill cgi-server" ascii
        $s6 = "/home/webserver/htdocs/dana-na" ascii
        $s7 = "remotedebug.bak" ascii
        $s8 = "/auth/restAuth.cgi" ascii
        $s9 = "MIME::Base64" ascii
        $s10 = "HTTP_CODE" ascii

    condition:
        filesize < 20KB and
        8 of ($s*)
}
```

### YARA: SPAWNANT Installer

Detects the SPAWNANT ELF installer by its LD_PRELOAD hijacking strings.

✅ compiles (`yarac` exit 0) · confidence: high

```yara
rule APT_UNC5221_SPAWNANT_Installer
{
    meta:
        description = "Detects SPAWNANT installer (libupgrade.so) for LD_PRELOAD persistence on Ivanti Connect Secure"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
        hash = "61bb586dc4e047ab081ef6ca65684e48"
        severity = "critical"

    strings:
        $s1 = "dspkginstall" ascii
        $s2 = "vsnprintf" ascii
        $s3 = "bom_files" ascii
        $s4 = "do-install" ascii
        $s5 = "ld.so.preload" ascii
        $s6 = "LD_PRELOAD" ascii
        $s7 = "scanner.py" ascii

    condition:
        uint32(0) == 0x464C457F and
        5 of ($s*)
}
```

### YARA: DRYHOOK Credential Stealer

Detects DRYHOOK by its DSAuth.pm patching strings.

✅ compiles (`yarac` exit 0) · confidence: high

```yara
rule APT_UNC5221_DRYHOOK_Credential_Stealer
{
    meta:
        description = "Detects DRYHOOK credential stealer that patches DSAuth.pm on Ivanti Connect Secure"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
        hash = "d18e5425ecd9608ecb992606b974e15d"
        severity = "critical"

    strings:
        $s1 = "/home/perl/DSAuth.pm" ascii
        $s2 = "replace_content" ascii
        $s3 = "setPrompt =" ascii
        $s4 = "runSignin = *DSAuthc::RealmSignin_runSignin" ascii
        $s5 = "/bin/mount -o remount,rw /" ascii
        $s6 = "cmdmmap.kuwMW" ascii
        $s7 = "runSigninEBSL" ascii
        $s8 = "pkill cgi-server" ascii
        $s9 = "RC4" ascii

    condition:
        filesize < 20KB and
        8 of ($s*)
}
```

### YARA: SPAWNSNAIL SSH Backdoor

Detects SPAWNSNAIL ELF backdoor by SSH key material and injection target strings.

✅ compiles (`yarac` exit 0) · confidence: high

```yara
rule APT_UNC5221_SPAWNSNAIL_SSH_Backdoor
{
    meta:
        description = "Detects SPAWNSNAIL SSH backdoor (libsshd.so) on Ivanti Connect Secure"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
        hash = "e7d24813535f74187db31d4114f607a1"
        severity = "critical"

    strings:
        $s1 = "PRIVATE KEY-----" ascii
        $s2 = "id_ed25519" ascii
        $s3 = "id_rsa" ascii
        $s4 = "selinux" ascii nocase
        $s5 = "libssh" ascii
        $s6 = "dsmdm" ascii
        $s7 = "dslogserver" ascii

    condition:
        uint32(0) == 0x464C457F and
        $s1 and
        ($s2 or $s3) and
        2 of ($s4, $s5, $s6, $s7)
}
```

### YARA: SPAWNMOLE Tunneler

Detects SPAWNMOLE ELF tunneler by process injection and SOCKS strings.

✅ compiles (`yarac` exit 0) · confidence: medium

```yara
rule APT_UNC5221_SPAWNMOLE_Tunneler
{
    meta:
        description = "Detects SPAWNMOLE tunneler (libsocks5.so) on Ivanti Connect Secure"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
        hash = "a638fd203ddb540d0484d8e00490df06"
        severity = "critical"

    strings:
        $s1 = "/proc/self/exe" ascii
        $s2 = "/proc/%d/maps" ascii
        $s3 = "libsocks5" ascii
        $s4 = "accept" ascii

    condition:
        uint32(0) == 0x464C457F and
        all of ($s*)
}
```

### Snort: Version Fingerprinting and Web Shell Response

<!-- audit: snort not installed in environment; structural check only; rules follow Snort 3 syntax with http service, underscore-notation sticky buffers -->

⚠️ uncompiled (snort not installed) · confidence: high

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Ivanti Connect Secure Version Fingerprinting via HC Launcher JAR Request"; flow:established, to_server; http_uri; content:"/dana-cached/hc/hc_launcher.", fast_pattern; content:".jar"; distance 0; classtype:attempted-recon; reference:url,cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day; reference:cve,2025-0282; metadata:author Actioner, created 2026-11-02; sid:2100010; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Ivanti Connect Secure PHASEJAM Web Shell Response with AccessAllow Marker"; flow:established, to_client; http_stat_code; content:"200"; file_data; content:"AccessAllow"; fast_pattern; content:"MIME::Base64"; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day; reference:cve,2025-0282; metadata:author Actioner, created 2026-11-02; sid:2100011; rev:1;)
```

### Suricata: Web Shell Access and Version Fingerprinting

✅ compiles (`suricata -T` exit 0) · confidence: high

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Ivanti Connect Secure Version Fingerprinting via HC Launcher JAR Request"; flow:established,to_server; http.uri; content:"/dana-cached/hc/hc_launcher."; fast_pattern; content:".jar"; endswith; classtype:attempted-recon; reference:url,cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day; reference:cve,2025-0282; metadata:author Actioner, created_at 2026-11-02; sid:2100010; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Ivanti Connect Secure PHASEJAM Web Shell Access via getComponent.cgi"; flow:established,to_server; http.uri; content:"/dana-na/jam/getComponent.cgi"; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day; reference:cve,2025-0282; metadata:author Actioner, created_at 2026-11-02; sid:2100011; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Ivanti Connect Secure PHASEJAM Web Shell Access via restAuth.cgi"; flow:established,to_server; http.uri; content:"/dana-na/auth/restAuth.cgi"; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day; reference:cve,2025-0282; metadata:author Actioner, created_at 2026-11-02; sid:2100012; rev:1;)
```

## Lessons Learned

This campaign reinforces that edge devices — VPN gateways, firewalls, load balancers — remain the most dangerous blind spot in enterprise security. UNC5221's ability to survive firmware upgrades, evade the vendor's own integrity checker by re-signing the manifest, and suppress syslog forwarding means that traditional defense-in-depth assumptions (patch → verify → monitor) are insufficient for internet-facing appliances. Organizations must treat VPN appliance compromise as equivalent to domain controller compromise: the attacker harvests every credential that passes through, and lateral movement begins immediately.

## Sources

- [Google Cloud / Mandiant Threat Intelligence Blog](https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day) — primary technical analysis of UNC5221 campaign, malware families, and exploitation chain
- [Ivanti Security Advisory](https://www.ivanti.com/blog/security-update-ivanti-connect-secure-policy-secure-and-neurons-for-zta-gateways) — vendor advisory with affected versions and patch guidance
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — KEV entry for CVE-2025-0282

---
*Report generated by Actioner*
