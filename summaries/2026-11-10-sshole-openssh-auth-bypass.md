# SSHole (CVE-2026-123158) -- OpenSSH Authentication Bypass on musl-based Linux

**Status:** DRAFT | **Date:** 2026-11-10 | **TLP:** CLEAR | **CVSSv3:** 8.1 (High)

---

## Executive Summary

CVE-2026-123158, codenamed **SSHole**, is a critical authentication bypass in OpenSSH affecting systems linked against the musl C library (primarily Alpine Linux). The flaw allows an unauthenticated attacker to log in to accounts with no usable password -- such as `root`, key-only users, and LDAP-backed accounts -- by submitting a password between 257 and 1,024 bytes. The vulnerability was publicly disclosed on November 5, 2026, and exploitation was observed in the wild within approximately 38 hours. As of November 10, 2026, GreyNoise has confirmed 20 successful exploitation chains from 6 attacker IPs across multiple countries, with post-exploitation activity including deployment of a Python-based C2 agent (TAC Agent), SSH key injection for persistence, and privilege escalation via `doas`. OpenSSH 10.6p2 fixes the flaw. Organizations running musl-based Linux with OpenSSH should patch immediately and audit for compromise.

---

## Background

### Vulnerability Origin

The root cause is a chain of behaviors across two codebases spanning over a decade:

1. **August 2012 -- musl libc changes:** musl commit `b3c4cc12` changed `crypt()` to return `"*"` on failure instead of `NULL`. A subsequent commit (`88bf5a8a`, August 29, 2012) added SHA-512 hashing with a `KEY_MAX` of 256 bytes, causing `crypt()` to fail (returning `"*"`) for passwords exceeding that limit.

2. **July 2016 -- OpenSSH CVE-2016-6210 fix:** To prevent username enumeration, OpenSSH introduced "salt borrowing" -- when an account has no usable password hash (stored as `*`), sshd borrows the salt from another account's real `$5$`/`$6$` hash to perform a dummy `crypt()` call.

3. **The collision:** When an attacker submits a password of 257-1,024 bytes against an account with `*` in its password field, musl's `crypt()` fails and returns `"*"`. sshd compares this return value against the stored `"*"` -- they match, and authentication succeeds.

### Discoverer

Ozgun Kultekin of Wakefield discovered and responsibly disclosed the vulnerability. The technical write-up was published at [sshhole.com](https://sshhole.com/).

### Affected Configurations

All four conditions must be true:

- OpenSSH server linked against **musl libc** (not glibc)
- PAM is **disabled** (`openssh-server` without PAM, or `UsePAM no`)
- `PasswordAuthentication` is **yes** (OpenSSH default)
- At least one account has `*` as its password field **and** at least one other account has a `$5$` or `$6$` hash

**Affected platforms:** Alpine Linux (all branches 3.16 through 3.24 and edge), OpenWrt (only if OpenSSH is installed instead of Dropbear), Buildroot, Yocto, and any custom Linux distribution using musl.

**Not affected:** glibc-based Linux distributions, non-Linux systems, Dropbear SSH, systems with `PasswordAuthentication no`, systems using PAM (`UsePAM yes`), accounts locked with `!` instead of `*`, and systems with no `$5$`/`$6$` hashes.

---

## Technical Analysis

### Exploitation Mechanism

```
Attacker                        Target (Alpine + OpenSSH + musl)
   |                                      |
   |--- SSH connection (port 22) -------->|
   |--- SSH_MSG_USERAUTH_REQUEST -------->|
   |    username: "alpine"                |
   |    method: "password"                |
   |    password: [257-1024 bytes] ------>| sshd: no hash for "alpine" (field = "*")
   |                                      | sshd: borrows salt from another account's $6$ hash
   |                                      | musl crypt(): password > 256 bytes -> FAIL -> returns "*"
   |                                      | sshd: strcmp("*", "*") == 0 -> AUTH SUCCESS
   |<--- SSH_MSG_USERAUTH_SUCCESS --------|
   |                                      |
   |--- (post-exploitation) ------------>|
```

**Key characteristics:**
- **Single-packet exploit:** Succeeds on every attempt with one connection
- **No prior authentication needed:** Only requires network access to port 22 and knowledge of a valid username
- **Privilege escalation path:** On Alpine tiny-cloud images, the `alpine` user has passwordless `doas`, enabling immediate root escalation

### Exploitation Timeline

| Date (UTC) | Event |
|---|---|
| 2012-08-09 | musl commit changes `crypt()` failure return to `"*"` |
| 2012-08-29 | musl adds 256-byte password length limit for SHA-512 |
| 2016-07-15 | OpenSSH CVE-2016-6210 fix introduces salt borrowing |
| ~2022 | Alpine 3.16 changes root password field from `!` to `*` |
| 2026-11-04 21:18 | Fix committed (not yet public) |
| 2026-11-05 09:00 | Fix published; OpenSSH 10.6p2 released at 09:01 |
| 2026-11-05 12:19 | sshhole.com write-up published |
| 2026-11-05 13:16 | First public exploit on GitHub |
| 2026-11-05 15:46 | CVE-2026-123158 reserved |
| 2026-11-05 16:17 | NVD publishes CVE (CVSS 8.1) |
| 2026-11-06 00:05 | First exploitation attempt observed ([Previdian](https://previdian.com/CVE-2026-123158)) |
| 2026-11-07 00:46 | First confirmed successful exploitation ([GreyNoise](https://sshole.events.greynoise.io)) |
| 2026-11-09 | Added to CISA KEV |
| 2026-11-10 09:56 | Last recorded exploitation activity (as of report) |

### Observed Post-Exploitation Activity

Based on GreyNoise gridpoint telemetry, confirmed attacker activity includes:

1. **Initial Access & Reconnaissance:** Login as `alpine` via oversized password, followed by `id`, `uname -a`, `hostname`, `uptime`, `/etc/os-release`, `ip a`, `netstat -nat`, `ps`, `pgrep`
2. **Privilege Escalation:** `doas -n sh -c ...`, `doas -n true`, `doas cat /etc/shadow`
3. **Persistence:**
   - SSH key injection into `/home/alpine/.ssh/authorized_keys` and `/root/.ssh/authorized_keys` with markers `SSHHOLE-HIT` and `fleet-access`
   - Rogue sshd on port 2222 with `AllowTcpForwarding=yes`
   - TAC Agent (`tac_agent.py`) installed via OpenRC init script (`/etc/init.d/tac-agent`, `rc-update add`)
   - Password hash set for `alpine` account via `/etc/shadow` modification
4. **Defense Evasion:** `HISTFILE=/dev/null`, base64-encoded payloads, `.ash_history` modification
5. **C2 Communication:** TAC Agent v0.1.1 communicating with `tac.vpnla[.]org:8443` via HTTPS (Cloudflare Worker), polling every 150 seconds
6. **Infrastructure Staging:** Python 3.12 portable environment extracted from `/tmp/py3.tar.gz`, DNS resolver changed to `1.1.1.1`, APK repository manipulation

---

## Indicators of Compromise

> All indicators are defanged per TLP:CLEAR handling.

### Network Indicators

#### Attacker IP Addresses (Confirmed Exploitation)

| IP Address | ASN / Org | Country | Activity |
|---|---|---|---|
| `183[.]220[.]91[.]15` | AS9808, China Mobile | CN | 2 exploits, Nov 7 |
| `20[.]255[.]63[.]133` | AS8075, Microsoft | HK | 4 exploits, Nov 7 (GT10 seed) |
| `209[.]248[.]50[.]17` | AS32135, SAKURA LTD | SG | 1 exploit, Nov 7 |
| `79[.]116[.]138[.]30` | AS57269, DIGI Spain | ES | 2 exploits, Nov 7 - Nov 10 |
| `20[.]2[.]81[.]241` | AS8075, Microsoft | HK | 1 exploit, Nov 8 |
| `47[.]80[.]65[.]43` | AS45102, Alibaba | PH | 1 exploit, Nov 8 |
| `89[.]116[.]89[.]18` | (early recon) | JP | 8 attempts, Nov 6 |

#### Attacker IPs (Authentication Bypass Attempts -- GreyNoise Tagged Malicious)

| IP Address |
|---|
| `43[.]224[.]227[.]158` |
| `213[.]86[.]169[.]133` |
| `31[.]59[.]220[.]26` |

#### Additional GT10 Cluster IPs

| IP Address |
|---|
| `152[.]175[.]65[.]88` |
| `202[.]155[.]94[.]33` |

### C2 Infrastructure

| Indicator | Type | Context |
|---|---|---|
| `tac[.]vpnla[.]org` | Domain | TAC Agent C2 (Cloudflare Worker) |
| `tac[.]vpnla[.]org:8443` | URL | C2 endpoint (HTTPS) |
| `104[.]21[.]88[.]83` | IP | Cloudflare shared IP (pinned in /etc/hosts; do NOT block IP alone) |

### C2 Protocol Indicators

- **User-Agent:** `TAC-Agent/1.0`
- **HTTP Headers:** `X-TAC-Poll-Interval`, `X-TAC-Agent-Capabilities`, `X-TAC-Agent-Version`, `X-TAC-Executor-Info`
- **API Paths:** `/agent/register`, `/agent/poll`, `/agent/result-object`, `/agent/results`, `/agent/file-object`, `/agent/update-artifacts/<id>`
- **Poll Interval:** 150 seconds + up to 1 second jitter

### File Indicators (SHA-256)

| Hash | File | Size | Notes |
|---|---|---|---|
| `55e6384f6d1648be9b48fb899e46623e9c05eb0df2cbf95f6701680d4e7cbc2a` | `tac_agent.py` | 89,559 bytes | TAC Agent v0.1.1, built 2026-06-09 |
| `7cf69bd6573a90d7bd287810b5c3746841cee6a7f77cadd016f34a97fc7b2361` | `/etc/init.d/tac-agent` | 308 bytes | OpenRC persistence script |
| `9f8db02efe7c1396c570c3828eea5149e752249972f9db317f3e32900c806dad` | `/tmp/apk_repos` | -- | Modified APK repository list |
| `c036cbb7553a909f8b8877d4461924307f27ecb66cff928eeeafd569c3887e29` | `/tmp/wtest` | 5,242,880 bytes | Disk write test artifact |

#### Attacker-Planted authorized_keys Hashes (SHA-256)

| Hash | Context |
|---|---|
| `46c3dd127423e8daef9c44204c1d5075f15e74ce7d76c3382741257e29bbde14` | Root key (Victims #3 and #4) |
| `85b6b4f428815b6e9690ce5a30718f4222b8c6f5b60bfd3ac6cffd24a8e56eeb` | Variant |
| `982635df1087d504f10ad6517e2206688700b99744aa0fc24d4d4ef7464fdffd` | Variant |
| `9646cc1045a29b901c1e90dd0d98d9d9b1816876ed2c8d60fe700d1fc6d46ba2` | Variant |
| `462bc15fb7fa63cc4e33e56a2dca17f3dec0dcdd4143fc5fcb95bae2605eb932` | Variant |
| `99a83986fe6c6b8dad3b9129f759e55dbafa98c72d336a0d5a45148b52456de0` | Variant |

### SSH Public Keys (Attacker)

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC+fr+jwfsBA8u1VnsHZL4Tz5zujgovCL6JgYzUYkfvR SSHHOLE-HIT
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFQrQmHWfW5QjOEZ4+Y5cz4yuF/dTlneMsoRlpe/jsTJ fleet-access
```

### Host Indicators (File Paths)

| Path | Purpose |
|---|---|
| `/opt/py3/tac_agent.py` | TAC Agent main script |
| `/usr/local/bin/tac_agent.py` | TAC Agent alternate location |
| `/opt/py3/run_tac.sh` | TAC Agent launcher |
| `/etc/init.d/tac-agent` | OpenRC persistence |
| `/root/.config/tac/agent.json` | TAC Agent configuration |
| `~/.config/tac/agent.json.lock` | TAC Agent lock file |
| `/run/tac-agent.pid` | TAC Agent PID file |
| `/tmp/py3.tar.gz` | Portable Python 3.12 archive |
| `/tmp/apk_repos` | Modified APK repositories |
| `/tmp/resolv.conf.bak` | Backup of original resolv.conf |
| `/tmp/zzz1`, `/tmp/exec_test.txt` | Attacker test files |

### Network Fingerprints

| Type | Value |
|---|---|
| HASSH | `6372ee6957562199b2fb773b0be1bf34` |
| HASSH | `a2de0f306611e0957be704f5b0e35a82` |
| HASSH | `38da7a9dfb196c72a7354bb4cdce64d9` |
| SSH Client | Paramiko 5.1.0 |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed Activity |
|---|---|---|---|
| **Initial Access** | Valid Accounts: Default Accounts | T1078.001 | Login to `alpine`/`root` accounts via oversized password |
| **Initial Access** | Exploit Public-Facing Application | T1190 | Exploitation of CVE-2026-123158 against internet-facing sshd |
| **Persistence** | Account Manipulation: SSH Authorized Keys | T1098.004 | Injection of `SSHHOLE-HIT` and `fleet-access` keys |
| **Persistence** | Create or Modify System Process: Init Script | T1543.004 | TAC Agent OpenRC init script at `/etc/init.d/tac-agent` |
| **Persistence** | External Remote Services | T1133 | Rogue sshd on port 2222 |
| **Privilege Escalation** | Abuse Elevation Control Mechanism | T1548 | `doas -n` for root escalation |
| **Defense Evasion** | Indicator Removal: Clear Command History | T1070.003 | `HISTFILE=/dev/null` |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | Base64-encoded payloads |
| **Credential Access** | OS Credential Dumping: /etc/passwd and /etc/shadow | T1003.008 | `doas cat /etc/shadow` |
| **Discovery** | System Information Discovery | T1082 | `id`, `uname -a`, `hostname`, `uptime`, `/etc/os-release` |
| **Discovery** | System Owner/User Discovery | T1033 | `id`, `/etc/passwd` enumeration |
| **Discovery** | System Network Configuration Discovery | T1016 | `ip a`, `netstat -nat`, `nslookup`, `/etc/resolv.conf` |
| **Discovery** | System Network Connections Discovery | T1049 | `netstat -nat` |
| **Discovery** | Process Discovery | T1057 | `ps`, `pgrep` |
| **Command and Control** | Application Layer Protocol: Web Protocols | T1071.001 | TAC Agent HTTPS C2 to `tac[.]vpnla[.]org:8443` |
| **Execution** | Command and Scripting Interpreter: Python | T1059.006 | TAC Agent (`tac_agent.py`) Python implant |

---

## Detection & Remediation

### Immediate Remediation

1. **Patch:** Update to OpenSSH 10.6p2 or the distribution's fixed package, then **restart sshd** (the upgrade alone does not restart a running daemon):
   ```bash
   apk upgrade -U -a
   rc-service sshd restart
   ```

2. **Workaround (if patching is delayed):** Disable password authentication:
   ```bash
   mkdir -p /etc/ssh/sshd_config.d
   echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/00-no-passwords.conf
   sshd -t && rc-service sshd restart
   sshd -T | grep -i passwordauthentication
   ```

3. **Alpine fixed package versions:**

   | Branch | Fixed openssh |
   |---|---|
   | edge | 10.6_p2-r0 |
   | 3.24 | 10.3_p1-r2 |
   | 3.23 | 10.2_p1-r1 |
   | 3.22 | 10.0_p1-r11 |
   | 3.21 | 9.9_p2-r1 |
   | 3.20 | 9.7_p1-r6 |
   | 3.19 | 9.6_p1-r3 |
   | 3.18 | 9.3_p2-r4 |
   | 3.17 | 9.1_p1-r7 |
   | 3.16 | 9.0_p1-r6 |

### Compromise Assessment

Run on all exposed Alpine/musl systems:

```bash
# Check for successful password logins to no-password accounts
grep "Accepted password for" /var/log/messages | grep -E "\b(root|alpine)\b"

# List accounts with '*' password field (potential targets)
awk -F: '$2=="*"{print $1}' /etc/shadow

# List accounts with real hashes (trigger condition)
awk -F: '$2 ~ /^\$[56]\$/{print $1}' /etc/shadow

# Check for attacker SSH keys
grep -r "SSHHOLE-HIT\|fleet-access\|AAAAC3NzaC1lZDI1NTE5AAAAIC+fr+jwfsBA\|AAAAC3NzaC1lZDI1NTE5AAAAIFQrQmHW" /root/.ssh/ /home/*/.ssh/ 2>/dev/null

# Check for TAC Agent artifacts
ls -la /opt/py3/tac_agent.py /usr/local/bin/tac_agent.py /etc/init.d/tac-agent /root/.config/tac/ 2>/dev/null

# Check for rogue sshd
ps aux | grep "sshd.*2222"

# Review doas usage, recently created users, and modified files
```

If any indicators are found, treat the machine as compromised. Rebuild from a known-good image after forensic preservation.

---

## Detection Rules

### Rule 1: SSHole -- Accepted Password Login to No-Password Account (Sigma)

Detects successful SSH password authentication to accounts that should not accept passwords (root, alpine, key-only users), which is the primary log signature of CVE-2026-123158 exploitation.

**Status:** `sigma convert -t splunk` exit 0 | `sigma check` blocked by network (MITRE ATT&CK data unreachable) | **Confidence: HIGH**

```yaml
title: SSHole - Accepted Password Login to No-Password Account
id: 8a3f1b2c-4d5e-6f7a-8b9c-0d1e2f3a4b5c
status: experimental
description: |
    Detects successful SSH password authentication to accounts that should not accept passwords
    (e.g., root, alpine, key-only users). This is a primary indicator of CVE-2026-123158 (SSHole)
    exploitation on musl-based Linux systems such as Alpine Linux.
references:
    - https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
    - https://nvd.nist.gov/vuln/detail/cve-2026-123158
    - https://sshole.events.greynoise.io
author: Actioner CTI
date: 2026-11-10
tags:
    - attack.initial_access
    - attack.t1078.001
    - attack.t1021.004
    - cve.2026.123158
logsource:
    product: linux
    service: sshd
detection:
    selection:
        - syslog_message|contains: 'Accepted password for'
    filter_valid_users:
        syslog_message|contains:
            - 'Accepted password for root '
            - 'Accepted password for alpine '
    condition: selection and filter_valid_users
falsepositives:
    - Legitimate password-based login to root on systems where root has a valid password set
    - Environments where the alpine user is intentionally given a password
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma check exit 1 (MITRE ATT&CK data fetch blocked by proxy 403, not a rule defect); rule parses and converts cleanly -->

### Rule 2: SSHole Post-Exploitation -- TAC Agent Persistence (Sigma)

Detects process execution or command lines referencing the TAC agent implant (`tac_agent.py`), a Python-based C2 observed in confirmed post-exploitation of CVE-2026-123158.

**Status:** `sigma convert -t splunk` exit 0 | `sigma check` blocked by network | **Confidence: HIGH** (IOC-specific)

```yaml
title: SSHole Post-Exploitation - TAC Agent Persistence
id: 1c2d3e4f-5a6b-7c8d-9e0f-1a2b3c4d5e6f
status: experimental
description: |
    Detects file creation or process execution associated with the TAC agent
    (tac_agent.py), a Python-based C2 implant observed in post-exploitation
    activity following CVE-2026-123158 (SSHole) compromise. The agent communicates
    with tac.vpnla.org:8443 and persists via OpenRC init scripts.
references:
    - https://sshole.events.greynoise.io
    - https://nvd.nist.gov/vuln/detail/cve-2026-123158
author: Actioner CTI
date: 2026-11-10
tags:
    - attack.persistence
    - attack.t1059.006
    - attack.t1543.004
    - cve.2026.123158
logsource:
    category: process_creation
    product: linux
detection:
    selection_process:
        CommandLine|contains:
            - 'tac_agent.py'
            - 'tac-agent'
    selection_file_paths:
        CommandLine|contains:
            - '/opt/py3/tac_agent.py'
            - '/usr/local/bin/tac_agent.py'
            - '/etc/init.d/tac-agent'
            - '/opt/py3/run_tac.sh'
    condition: selection_process or selection_file_paths
falsepositives:
    - Legitimate use of software named tac_agent (unlikely)
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma check exit 1 (network); rule parses and converts cleanly -->

### Rule 3: SSHole Post-Exploitation -- SSHHOLE-HIT Authorized Key Injection (Sigma)

Detects commands injecting SSH public keys with the attacker markers `SSHHOLE-HIT` or `fleet-access`, or containing the specific ed25519 key prefix observed in confirmed intrusions.

**Status:** `sigma convert -t splunk` exit 0 | `sigma check` blocked by network | **Confidence: HIGH** (IOC-specific)

```yaml
title: SSHole Post-Exploitation - SSHHOLE-HIT Authorized Key Injection
id: 2d3e4f5a-6b7c-8d9e-0f1a-2b3c4d5e6f7a
status: experimental
description: |
    Detects commands that inject SSH public keys with the marker comment
    'SSHHOLE-HIT' or 'fleet-access' into authorized_keys files. This is a
    specific persistence technique observed in CVE-2026-123158 post-exploitation.
references:
    - https://sshole.events.greynoise.io
    - https://nvd.nist.gov/vuln/detail/cve-2026-123158
author: Actioner CTI
date: 2026-11-10
tags:
    - attack.persistence
    - attack.t1098.004
    - cve.2026.123158
logsource:
    category: process_creation
    product: linux
detection:
    selection_marker:
        CommandLine|contains:
            - 'SSHHOLE-HIT'
            - 'fleet-access'
    selection_key_injection:
        CommandLine|contains|all:
            - 'authorized_keys'
            - 'AAAAC3NzaC1lZDI1NTE5'
    condition: selection_marker or selection_key_injection
falsepositives:
    - Legitimate automation using these exact key comments (very unlikely)
level: critical
```

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma check exit 1 (network); rule parses and converts cleanly -->

### Rule 4: SSHole Post-Exploitation -- HISTFILE Suppression (Sigma)

Detects commands setting `HISTFILE=/dev/null`, a defense evasion technique observed in CVE-2026-123158 post-exploitation to suppress shell command history.

**Status:** `sigma convert -t splunk` exit 0 | `sigma check` blocked by network | **Confidence: MEDIUM** (behavioral/TTP -- not SSHole-exclusive)

```yaml
title: SSHole Post-Exploitation - HISTFILE Suppression via SSH
id: 3e4f5a6b-7c8d-9e0f-1a2b-3c4d5e6f7a8b
status: experimental
description: |
    Detects commands setting HISTFILE=/dev/null, a defense evasion technique
    observed in CVE-2026-123158 post-exploitation activity. Attackers use this
    to suppress shell command history recording.
references:
    - https://sshole.events.greynoise.io
    - https://nvd.nist.gov/vuln/detail/cve-2026-123158
author: Actioner CTI
date: 2026-11-10
tags:
    - attack.defense_evasion
    - attack.t1070.003
    - cve.2026.123158
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: 'HISTFILE=/dev/null'
    condition: selection
falsepositives:
    - Security testing and penetration testing activities
    - Some legitimate administrative scripts that suppress history
level: medium
```

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma check exit 1 (network); rule parses and converts cleanly -->

### Rule 5: SSHole Post-Exploitation -- TAC C2 Domain Resolution (Sigma)

Detects DNS queries for `tac.vpnla.org`, the C2 domain used by the TAC Agent implant deployed in confirmed CVE-2026-123158 intrusions.

**Status:** `sigma convert -t splunk` exit 0 | `sigma check` blocked by network | **Confidence: HIGH** (IOC-specific)

```yaml
title: SSHole Post-Exploitation - TAC C2 Domain Resolution
id: 4f5a6b7c-8d9e-0f1a-2b3c-4d5e6f7a8b9c
status: experimental
description: |
    Detects DNS resolution of tac.vpnla.org, the command-and-control domain
    used by the TAC agent implant observed in CVE-2026-123158 post-exploitation.
references:
    - https://sshole.events.greynoise.io
    - https://nvd.nist.gov/vuln/detail/cve-2026-123158
author: Actioner CTI
date: 2026-11-10
tags:
    - attack.command_and_control
    - attack.t1071.001
    - cve.2026.123158
logsource:
    category: dns_query
    product: linux
detection:
    selection:
        query|contains: 'tac.vpnla.org'
    condition: selection
falsepositives:
    - Legitimate use of tac.vpnla.org (unknown, treat as suspicious)
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma check exit 1 (network); rule parses and converts cleanly -->

### Rule 6: SSHole Post-Exploitation -- Rogue SSHD on Port 2222 (Sigma)

Detects execution of sshd or sshd-session with `-p 2222`, indicating a rogue SSH listener observed as a persistence and lateral movement technique in confirmed intrusions.

**Status:** `sigma convert -t splunk` exit 0 | `sigma check` blocked by network | **Confidence: MEDIUM** (behavioral -- port 2222 has legitimate uses)

```yaml
title: SSHole Post-Exploitation - Rogue SSHD on Port 2222
id: 5a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d
status: experimental
description: |
    Detects execution of sshd with the -p 2222 flag, indicating a rogue SSH
    listener on a non-standard port. This was observed as a persistence and
    lateral movement technique in CVE-2026-123158 post-exploitation.
references:
    - https://sshole.events.greynoise.io
    - https://nvd.nist.gov/vuln/detail/cve-2026-123158
author: Actioner CTI
date: 2026-11-10
tags:
    - attack.persistence
    - attack.t1133
    - cve.2026.123158
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/sshd'
            - '/sshd-session'
        CommandLine|contains: '-p 2222'
    condition: selection
falsepositives:
    - Legitimate SSH servers configured to listen on port 2222
level: medium
```

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma check exit 1 (network); rule parses and converts cleanly -->

### Rule 7: SSHole -- Oversized SSH Password Attempt (Suricata)

Attempts to detect oversized password payloads in SSH traffic. **Important caveat:** SSH traffic is encrypted after key exchange, so this rule is effective only with SSL/TLS inspection or an SSH decryption proxy.

**Status:** :warning: uncompiled (structural check only -- Suricata not installed) | **Confidence: LOW** (encrypted traffic limits applicability)

```
alert ssh any any -> any 22 (msg:"EXPLOIT SSHole CVE-2026-123158 - Oversized SSH Password Auth Attempt"; flow:to_server,established; ssh.software; content:"SSH-2.0-"; content:"password"; within:2048; byte_test:4,>,256,0,relative; reference:cve,2026-123158; classtype:attempted-admin; sid:2026123158; rev:1; metadata:created_at 2026_11_10, deployment Perimeter, signature_severity Critical, attack_target Server, affected_product OpenSSH, tag SSHole;)
```

<!-- audit: structural review only; Suricata not available for compilation; SSH encryption severely limits rule utility without decryption capability -->

### Rule 8: SSHole -- TAC Agent Python Implant (YARA)

Detects the TAC Agent Python implant based on its C2 protocol strings, custom HTTP headers, and domain indicators.

**Status:** `yarac` exit 0 (compiled successfully) | **Confidence: HIGH** (IOC-specific)

```yara
rule SSHole_TACAgent_PythonImplant
{
    meta:
        description = "Detects the TAC agent Python implant used in CVE-2026-123158 post-exploitation"
        author = "Actioner CTI"
        date = "2026-11-10"
        reference = "https://sshole.events.greynoise.io"
        hash = "55e6384f6d1648be9b48fb899e46623e9c05eb0df2cbf95f6701680d4e7cbc2a"
        severity = "critical"

    strings:
        $ua = "TAC-Agent/1.0" ascii
        $c2_path1 = "/agent/register" ascii
        $c2_path2 = "/agent/poll" ascii
        $c2_path3 = "/agent/result-object" ascii
        $c2_path4 = "/agent/results" ascii
        $c2_path5 = "/agent/file-object" ascii
        $c2_path6 = "/agent/update-artifacts/" ascii
        $header1 = "X-TAC-Poll-Interval" ascii
        $header2 = "X-TAC-Agent-Capabilities" ascii
        $header3 = "X-TAC-Agent-Version" ascii
        $header4 = "X-TAC-Executor-Info" ascii
        $domain = "tac.vpnla.org" ascii
        $version = "v0.1.1" ascii
        $executor = "__executor_worker__" ascii

    condition:
        filesize < 200KB and
        (
            ($ua and any of ($c2_path*)) or
            ($domain and any of ($header*)) or
            (3 of ($c2_path*) and any of ($header*)) or
            ($executor and $ua) or
            ($version and $domain and $ua)
        )
}
```

<!-- audit: yarac compiled successfully exit 0; no warnings -->

---

## Sources

| Source | URL | Retrieved |
|---|---|---|
| [The Hacker News -- Exploitation Report](https://thehackernews.com/2026/11/hackers-exploited-openssh-sshole-flaw.html) | thehackernews.com | 2026-11-10 |
| [The Hacker News -- Emergency Fix](https://thehackernews.com/2026/11/openssh-issues-emergency-fix-for-flaw.html) | thehackernews.com | 2026-11-10 |
| [SecurityWeek -- Exploitation Report](https://www.securityweek.com/hackers-exploiting-sshole-authentication-bypass-in-openssh/) | securityweek.com | 2026-11-10 |
| [The Register -- Technical Analysis](https://www.theregister.com/security/2026/11/05/get-root-on-a-musl-linux-system-by-slamming-it-with-an-overly-long-password/5307910) | theregister.com | 2026-11-10 |
| [Alpine Linux Security Advisory](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/) | alpinelinux.org | 2026-11-10 |
| [GreyNoise SSHole Event Page](https://sshole.events.greynoise.io) | sshole.events.greynoise.io | 2026-11-10 |
| [Previdian CVE-2026-123158 Telemetry](https://previdian.com/CVE-2026-123158) | previdian.com | 2026-11-10 |
| [SSHole Technical Write-up (Kultekin)](https://sshhole.com/) | sshhole.com | 2026-11-10 |
| [NVD -- CVE-2026-123158](https://nvd.nist.gov/vuln/detail/cve-2026-123158) | nvd.nist.gov | 2026-11-10 |
| [OpenSSH 10.6p2 Release Notes](https://www.openssh.org/releasenotes.html#10.6p2) | openssh.org | 2026-11-10 |

---

*Report generated 2026-11-10. Draft for review -- verify IOCs against your environment before deploying detection rules to production.*
