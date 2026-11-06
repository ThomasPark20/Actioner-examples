# Technical Analysis Report: CWP Linux Backdoor ("cwpdoor") (2026-11-06)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-11-06
Version: 1.0 (DRAFT)

## Executive Summary

QiAnXin XLab researchers discovered a backdoor embedded in the CWP (Control Web Panel, formerly CentOS Web Panel) web server binary `cwpsrv`. The modified binary responds to specially crafted HTTP requests containing custom `X-Ngx-Integrity` headers to execute arbitrary commands on the host without writing any access log entries. The backdoor was delivered via a shell script (`cwpsrv_update.sh`) disguised as a routine version update, downloaded from `136.0.141[.]71`. Two backdoored versions were identified (1.15.10 and 1.24.0), and the installer employed timestomping to reset file modification times after replacing the legitimate binary, defeating naive forensic timeline analysis. At the time of disclosure, all three artifacts had zero detections on VirusTotal.

CWP is a free Linux server management panel used by hosting providers and system administrators globally. Any CWP installation that executed the malicious update script is compromised at root level, with the attacker holding persistent, stealthy command execution through normal-looking HTTPS traffic to the web panel's own port. The backdoor's authentication mechanism (timestamp + cryptographic signature in headers) limits opportunistic abuse but guarantees that the original operator retains exclusive access.

## Background: Control Web Panel (CWP)

Control Web Panel (CWP) is a free, widely-deployed Linux web hosting control panel (comparable to cPanel or Plesk) that provides a web interface for managing Apache/Nginx, DNS, email, databases, and system services. It runs on CentOS, Rocky Linux, AlmaLinux, and Oracle Linux. The `cwpsrv` binary is CWP's own web server process, typically running as root and binding to the panel's administrative port. Because CWP manages the entire server stack, compromise of `cwpsrv` grants the attacker root-level control over every hosted site, database, and email account on the server. CWP has a history of critical vulnerabilities (e.g., CVE-2022-44877 RCE), making it a known target for server-focused threat actors.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-29 | `cwpsrv_update.sh` installer script captured (earliest known artifact date) |
| 2026-06-29 (est.) | Backdoored `cwpsrv` binaries (versions 1.15.10 and 1.24.0) staged on `136.0.141[.]71` |
| 2026-11 (early) | QiAnXin XLab publicly discloses the backdoor |
| 2026-11-06 | The Hacker News publishes coverage; community detection guidance issued |

## Root Cause: Supply-Chain Binary Replacement

The attack vector is a trojanized update script (`cwpsrv_update.sh`) that masquerades as a legitimate CWP version update. The script requires root privileges (standard for CWP administration) and, when executed, downloads a backdoored `cwpsrv` binary from `136.0.141[.]71`, replaces the legitimate binary at `/usr/local/cwpsrv/bin/cwpsrv`, and restarts the service. The initial delivery mechanism for the script (how administrators were tricked into running it) has not been publicly detailed; possibilities include compromised update channels, phishing targeting CWP administrators, or exploitation of a prior CWP vulnerability to gain initial shell access.

## Technical Analysis of the Malicious Payload

### 1. Installer Script (cwpsrv_update.sh)

The shell script (`MD5: e505d4ffa21cf494a5dc2d7c8f4f1236`) acts as a dropper. It downloads the appropriate backdoored `cwpsrv` binary based on the installed CWP version from `hxxps://136.0.141[.]71/static/cwpsrv_1.15.10` or `hxxps://136.0.141[.]71/static/cwpsrv_1.24.0`. Before replacing the binary, it creates a backup at `/usr/local/cwpsrv/bin/cwpsrv.prev-<date-time>` (which may later be deleted). After replacement, the script performs timestomping -- resetting the new binary's file modification and access timestamps to match the original -- to defeat forensic timeline analysis. The service is then restarted to load the backdoored binary.

### 2. Backdoored cwpsrv Binary

Two versions of the backdoored binary have been identified:
- **cwpsrv 1.15.10** — MD5: `965aea67fb40de1bab5169ada993349f`
- **cwpsrv 1.24.0** — MD5: `d3f4e95113d49ab3991b45e457bda75b`

The modified binary contains additional code that intercepts incoming HTTP requests and inspects them for headers prefixed with `X-Ngx-Integrity`. When a request carries the correct set of these headers -- including a valid timestamp and a cryptographic signature -- the binary extracts and executes the command payload embedded in the request. The execution occurs within the web server process itself, so no child process is spawned for simple commands, and the request is never written to the access log.

### 3. C2 Infrastructure

The backdoor operates over the existing CWP HTTPS channel. The attacker sends crafted HTTP requests to the CWP panel's web port; the `X-Ngx-Integrity`-prefixed headers serve as the command and authentication channel. Locally, the backdoored binary communicates through a Unix domain socket named `ngx_http_integrity_helper`, which relays commands between the HTTP handler and the execution component. The download/staging server is `136.0.141[.]71`.

| Component | Value | Role |
|-----------|-------|------|
| Download server | `136.0.141[.]71` | Hosts installer script and backdoored binaries |
| C2 channel | HTTPS to CWP panel port | Attacker sends commands via HTTP headers |
| Local relay | Unix socket `ngx_http_integrity_helper` | Internal command relay within backdoored process |

### 4. Platform-Specific Behavior

#### Linux

This backdoor is Linux-only, targeting servers running CWP. The `cwpsrv` binary is an ELF executable. The installer script assumes a standard CWP installation path (`/usr/local/cwpsrv/bin/`). The backdoor runs with the privileges of the `cwpsrv` process, which is typically root.

### 5. Anti-Forensics / Evasion Techniques

- **Timestomping (T1070.006):** The installer resets file timestamps on the replaced binary to match the original, hiding the modification from `ls -la` and basic forensic timelines.
- **Log suppression:** Backdoor-triggered requests are never written to the CWP access log, making HTTP-level detection impossible from server logs alone.
- **Signature-gated activation (T1027):** The backdoor only activates when the request carries a valid timestamp and cryptographic signature in the `X-Ngx-Integrity` headers, preventing accidental triggering or discovery by scanners sending random headers.
- **Zero AV detections:** At the time of disclosure, all three artifacts (installer + two binaries) had zero detections on VirusTotal.
- **Backup deletion:** The installer's backup file (`cwpsrv.prev-*`) may be deleted post-installation to remove evidence of the original binary.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` (e.g., `hxxps://136.0.141[.]71/static/cwpsrv_update.sh`)
> - IP addresses: `[.]` replacing dots (e.g., `136.0.141[.]71`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `cwpsrv` | 1.15.10 (MD5 `965aea67fb40de1bab5169ada993349f`) | Backdoored CWP web server binary |
| `cwpsrv` | 1.24.0 (MD5 `d3f4e95113d49ab3991b45e457bda75b`) | Backdoored CWP web server binary |
| `cwpsrv_update.sh` | N/A (MD5 `e505d4ffa21cf494a5dc2d7c8f4f1236`) | Installer/dropper script |

### File System

| Platform | Path | Hash (MD5) | Description |
|----------|------|------------|-------------|
| Linux | `/usr/local/cwpsrv/bin/cwpsrv` | `965aea67fb40de1bab5169ada993349f` or `d3f4e95113d49ab3991b45e457bda75b` | Replaced backdoored binary |
| Linux | `/usr/local/cwpsrv/bin/cwpsrv.prev-<date-time>` | (original hash) | Backup of legitimate binary (may be deleted) |
| Linux | `cwpsrv_update.sh` (temp location) | `e505d4ffa21cf494a5dc2d7c8f4f1236` | Installer script |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `136.0.141[.]71` | Download server hosting backdoored binaries and installer |
| URL | `hxxps://136.0.141[.]71/static/cwpsrv_update.sh` | Installer script download |
| URL | `hxxps://136.0.141[.]71/static/cwpsrv_1.15.10` | Backdoored binary (v1.15.10) |
| URL | `hxxps://136.0.141[.]71/static/cwpsrv_1.24.0` | Backdoored binary (v1.24.0) |

### Behavioral

- Presence of Unix domain socket named `ngx_http_integrity_helper` (detectable via `ss -axp | grep integrity`).
- String `X-Ngx-Integrity` present in the cwpsrv binary on disk (detectable via `strings /usr/local/cwpsrv/bin/cwpsrv | grep X-Ngx-Integrity`).
- HTTP requests to a CWP panel containing `X-Ngx-Integrity` headers that do not appear in access logs.
- Recent modification of `/usr/local/cwpsrv/bin/cwpsrv` with timestamps that do not match package manager records (timestomping artifact).
- Presence of backup files matching `/usr/local/cwpsrv/bin/cwpsrv.prev-*`.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1036 | Masquerading | Installer script `cwpsrv_update.sh` disguised as a legitimate CWP version update |
| T1070.006 | Indicator Removal: Timestomp | Installer resets file timestamps on the replaced binary to match the original |
| T1505.003 | Server Software Component: Web Shell | Modified `cwpsrv` binary acts as a web shell, executing commands received via HTTP headers |
| T1027 | Obfuscated Files or Information | Backdoor activation gated behind cryptographic signature verification in custom headers |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 commands delivered via HTTPS requests with custom headers to the CWP panel port |

## Impact Assessment

**Breadth:** CWP is used on an estimated tens of thousands of Linux servers worldwide, primarily by small-to-medium hosting providers. The exact number of compromised installations is unknown, but any server that executed the malicious update script is fully compromised. **Depth:** Critical -- the attacker gains root-level command execution on the server, with access to all hosted websites, databases, email, and credentials. **Stealth:** Very high -- zero AV detections, no access log entries for backdoor commands, timestomped binaries, and signature-gated activation make this exceptionally difficult to detect through standard monitoring.

## Detection & Remediation

### Immediate Detection

Run these commands on any CWP server to check for compromise:

```bash
# Check for the backdoor Unix socket
ss -axp | grep integrity

# Check for backdoor strings in the cwpsrv binary
strings /usr/local/cwpsrv/bin/cwpsrv | grep X-Ngx-Integrity

# Verify binary hash against known-bad MD5s
md5sum /usr/local/cwpsrv/bin/cwpsrv

# Check for backup files left by the installer
ls -la /usr/local/cwpsrv/bin/cwpsrv.prev-*

# Check for network connections to the download server
ss -tnp | grep 136.0.141.71
```

If the `X-Ngx-Integrity` string is present or the Unix socket exists, the server is compromised.

### Remediation

1. **Isolate** the affected server immediately -- do not simply restart CWP.
2. **Preserve evidence:** Copy the backdoored binary and any `cwpsrv.prev-*` backup files for forensic analysis before remediation.
3. **Reinstall CWP** from the official repository or restore `cwpsrv` from a known-good backup (verify hash).
4. **Rotate all credentials:** Root password, CWP admin credentials, database passwords, hosted site credentials, SSH keys, and any API tokens accessible from the server.
5. **Audit server activity:** Review command history, cron jobs, SSH authorized_keys, and any new user accounts for signs of lateral movement.
6. **Block IOCs:** Firewall `136.0.141[.]71` at the network perimeter.
7. **Scan other CWP servers** in the environment using the detection commands above.

### Long-Term Hardening

- Pin CWP updates to official repositories only; validate update script checksums before execution.
- Implement file integrity monitoring (FIM) on critical binaries (`/usr/local/cwpsrv/bin/cwpsrv`).
- Deploy network egress filtering to restrict server-to-internet traffic to known-good destinations.
- Monitor for anomalous HTTP headers in web traffic via WAF or IDS rules.
- Consider migrating from CWP to a panel with a stronger security track record if risk tolerance is low.

## Detection Rules

These rules target the CWP backdoor's durable artifacts at PoC/advisory-specific altitude with strict leniency: the installer script name and download server IP (Sigma process creation), the cwpsrv binary path (Sigma file events), the unique backdoor strings in the binary (YARA), and network traffic to the staging IP plus the characteristic HTTP header and URI patterns (Suricata). The one caveat that matters: the `X-Ngx-Integrity` header detection (Suricata SID 2200903) inspects the raw HTTP header buffer and will only fire if traffic to the CWP port is routed through the sensor -- most CWP panels use HTTPS, so TLS inspection or a sensor on the server itself is required.

### Sigma: CWP Backdoor Installer Script Execution
Detects execution of `cwpsrv_update.sh` or download activity targeting the backdoor staging server `136.0.141[.]71` and the `/static/cwpsrv` URI path.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: altitude=PoC/advisory-specific, strict leniency. `sigma check` exits 1 ONLY because the pySigma D3FEND tag-validator cannot reach the MITRE ATT&CK API (HTTP 403 in this sandboxed environment; RuntimeError: Failed to load MITRE ATT&CK data) -- NOT a rule defect; the rule parses correctly. Portability oracle passed: `sigma convert --without-pipeline -t splunk` exit 0 => CommandLine="*cwpsrv_update.sh*" OR (Image IN ("*/curl","*/wget") CommandLine IN ("*136.0.141.71*","*/static/cwpsrv*")); `-t log_scale` exit 0 => equivalent regex output. Two selection blocks joined by OR in condition; each converts unambiguously. Tags are technique-only per spec (no tactic tags). product:linux matches the target platform. -->
```yaml
title: CWP Backdoor Installer Script Execution
id: 7a4c1e3b-8d2f-4f5a-b6e9-3c1d7a5e2f80
status: experimental
description: >-
  Detects execution of the cwpsrv_update.sh installer script used to deploy the
  CWP (Control Web Panel) Linux backdoor ("cwpdoor"). The script replaces the
  legitimate cwpsrv binary with a backdoored version that responds to hidden
  HTTP headers for command execution.
references:
  - https://blog.xlab.qianxin.com/
  - https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html
author: Actioner
date: 2026/11/06
tags:
  - attack.t1036
  - attack.t1505.003
logsource:
  category: process_creation
  product: linux
detection:
  selection_script:
    CommandLine|contains: 'cwpsrv_update.sh'
  selection_curl:
    Image|endswith:
      - '/curl'
      - '/wget'
    CommandLine|contains:
      - '136.0.141.71'
      - '/static/cwpsrv'
  condition: selection_script or selection_curl
falsepositives:
  - Legitimate CWP updates from official sources (verify download origin)
level: high
```

### Sigma: CWP Binary Replacement File Event
Detects file modification events targeting the `cwpsrv` binary path, consistent with the backdoor installer replacing the legitimate binary.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: altitude=PoC/advisory-specific, strict leniency. `sigma check` exit 1 due to offline D3FEND API only (same environment issue as above). `sigma convert --without-pipeline -t splunk` exit 0 => TargetFilename="/usr/local/cwpsrv/bin/cwpsrv*" NOT (TargetFilename IN ("*.log","*.pid")); `-t log_scale` exit 0. Legitimate CWP updates also write to this path, hence medium confidence -- the rule is a tripwire that requires triage. Filter excludes log/pid files in the cwpsrv directory. file_event category + product:linux is standard for auditd/Sysmon-for-Linux. -->
```yaml
title: CWP Backdoor Binary Replacement via File Modification
id: 9b5d2e4c-1a3f-4e7b-c8d0-4a2e6b3f1d92
status: experimental
description: >-
  Detects file modification events targeting the cwpsrv binary path, consistent
  with the CWP backdoor installer replacing the legitimate binary. The installer
  backs up the original as cwpsrv.prev-<timestamp> before dropping the
  backdoored version.
references:
  - https://blog.xlab.qianxin.com/
  - https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html
author: Actioner
date: 2026/11/06
tags:
  - attack.t1505.003
  - attack.t1070.006
logsource:
  category: file_event
  product: linux
detection:
  selection_binary:
    TargetFilename|startswith: '/usr/local/cwpsrv/bin/cwpsrv'
  filter_logs:
    TargetFilename|endswith:
      - '.log'
      - '.pid'
  condition: selection_binary and not filter_logs
falsepositives:
  - Legitimate CWP software updates modifying the cwpsrv binary
level: medium
```

### Sigma: CWP Backdoor Unix Socket Inspection
Detects execution of socket inspection commands searching for the `integrity` keyword, consistent with the XLab-recommended detection check or the backdoor's own `ngx_http_integrity_helper` socket activity.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: altitude=advisory detection command. `sigma check` exit 1 due to offline D3FEND API only. `sigma convert --without-pipeline -t splunk` exit 0 => Image IN ("*/ss","*/netstat") CommandLine="*integrity*"; `-t log_scale` exit 0. Informational level because this rule fires when a defender runs the recommended check as well as when an attacker probes. Medium confidence: the keyword "integrity" in a socket listing is not unique to this backdoor (other software may use it), but in the context of a CWP server it is a strong indicator. -->
```yaml
title: CWP Backdoor Unix Socket Detection via ss Command
id: 3e6f1a7d-4b2c-4d8e-a9f1-5c3d8e2a7b40
status: experimental
description: >-
  Detects execution of socket inspection commands (ss, netstat) combined with
  the keyword "integrity", consistent with defenders or the backdoor itself
  interacting with the ngx_http_integrity_helper Unix socket used by the
  CWP backdoor for command relay.
references:
  - https://blog.xlab.qianxin.com/
  - https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html
author: Actioner
date: 2026/11/06
tags:
  - attack.t1505.003
  - attack.t1071.001
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - '/ss'
      - '/netstat'
    CommandLine|contains: 'integrity'
  condition: selection
falsepositives:
  - Administrators running the recommended XLab detection command
level: informational
```

### YARA: Backdoored cwpsrv Binary Detection
Detects the CWP backdoored `cwpsrv` binary by matching both the `X-Ngx-Integrity` custom header string and the `ngx_http_integrity_helper` Unix socket name within an ELF binary, neither of which exists in legitimate CWP builds.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: `yarac /tmp/actioner/cwpdoor.yar /tmp/actioner/cwpdoor_compiled.yarc` exit 0. Both matched strings are unique backdoor artifacts explicitly documented by XLab; their co-occurrence in an ELF binary is a definitive indicator. filesize<20MB scopes to server binaries. ELF magic check (7F 45 4C 46 at offset 0) constrains to Linux executables. No sample available for live-fire test but strings are source-published IOCs. -->
```yara
rule Backdoor_CWP_CWPDoor_Strings
{
    meta:
        description = "Detects the CWP (Control Web Panel) backdoored cwpsrv binary by characteristic strings: the X-Ngx-Integrity custom header prefix and the ngx_http_integrity_helper Unix socket name. Both are unique to the backdoor and not present in legitimate CWP builds."
        author = "Actioner"
        date = "2026-11-06"
        reference = "https://blog.xlab.qianxin.com/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $header = "X-Ngx-Integrity" ascii
        $socket = "ngx_http_integrity_helper" ascii
        $elf    = { 7F 45 4C 46 }

    condition:
        $elf at 0 and
        filesize < 20MB and
        $header and
        $socket
}
```

### YARA: CWP Backdoor Installer Script Detection
Detects the `cwpsrv_update.sh` installer script by matching the download server IP, backdoored binary URI paths, and the target installation path within a shell script.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: `yarac /tmp/actioner/cwpdoor_installer.yar /tmp/actioner/cwpdoor_installer_compiled.yarc` exit 0. Matches on the conjunction of the staging IP (136.0.141.71), at least one download path (/static/cwpsrv_*), the target binary path, and a shebang at offset 0. All are source-published IOCs. filesize<1MB scopes to scripts. -->
```yara
rule Backdoor_CWP_CWPDoor_Installer
{
    meta:
        description = "Detects the cwpsrv_update.sh installer script used to deploy the CWP backdoor. Matches on the combination of the download server IP, backdoored binary filenames, and shell script markers."
        author = "Actioner"
        date = "2026-11-06"
        reference = "https://blog.xlab.qianxin.com/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $ip       = "136.0.141.71" ascii
        $path1    = "/static/cwpsrv_1.15.10" ascii
        $path2    = "/static/cwpsrv_1.24.0" ascii
        $path3    = "/static/cwpsrv_update.sh" ascii
        $target   = "/usr/local/cwpsrv/bin/cwpsrv" ascii
        $shebang  = "#!/bin/" ascii

    condition:
        $shebang at 0 and
        filesize < 1MB and
        $ip and
        $target and
        1 of ($path*)
}
```

### Suricata: CWP Backdoor Network Detection (3 rules)
Three rules covering: (1) any traffic to the download server IP `136.0.141[.]71`, (2) HTTP requests to the `/static/cwpsrv` URI path used to download backdoored artifacts, and (3) HTTP requests containing the `X-Ngx-Integrity` header used for backdoor command delivery.
**Status:** compile ✅ compiles · confidence: high (SID 2200901), high (SID 2200902), medium (SID 2200903)
<!-- audit: `suricata -T -S /tmp/actioner/cwpdoor.rules -l /tmp/actioner` exit 0, "Configuration provided was successfully loaded. Exiting." All three rules: balanced parentheses, unique SIDs (2200901-2200903), dot-notation sticky buffers (http.uri, http.header), flow directives present, required fields (msg/sid/rev) present. SID 2200901: IP-based rule, high confidence (source-published staging IP). SID 2200902: URI pattern match on /static/cwpsrv, high confidence (unique to this campaign). SID 2200903: header inspection for X-Ngx-Integrity in raw HTTP header buffer, medium confidence because TLS inspection is required to see inside HTTPS traffic to the CWP port; without it the rule is blind. The header name is unique enough to be a strong indicator when visible. -->
```suricata
alert ip $HOME_NET any -> 136.0.141.71 any (msg:"Actioner - CWP Backdoor Download Server Contact (136.0.141.71)"; flow:to_server; reference:url,blog.xlab.qianxin.com; classtype:trojan-activity; sid:2200901; rev:1; metadata:author Actioner, created_at 2026-11-06;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CWP Backdoor Installer or Binary Download URI"; flow:established,to_server; http.uri; content:"/static/cwpsrv"; fast_pattern; reference:url,blog.xlab.qianxin.com; classtype:trojan-activity; sid:2200902; rev:1; metadata:author Actioner, created_at 2026-11-06;)
alert http any any -> $HOME_NET any (msg:"Actioner - CWP Backdoor X-Ngx-Integrity Header in HTTP Request"; flow:established,to_server; http.header; content:"X-Ngx-Integrity"; fast_pattern; reference:url,blog.xlab.qianxin.com; classtype:web-application-attack; sid:2200903; rev:1; metadata:author Actioner, created_at 2026-11-06;)
```

## Lessons Learned

This backdoor demonstrates the danger of trusting update mechanisms that operate outside of package manager verification. The attacker did not exploit a vulnerability in CWP itself -- they delivered a script that a root-privileged administrator would run, relying on the implicit trust in "update" scripts in the hosting panel ecosystem. The combination of timestomping, log suppression, and cryptographic gating made the backdoor nearly invisible to standard monitoring. Defenders managing self-hosted control panels should implement file integrity monitoring on critical binaries, restrict update sources to verified origins, and deploy network-level detection for anomalous HTTP headers even when traffic is encrypted (via TLS inspection or host-based sensors).

## Sources

- [QiAnXin XLab Blog](https://blog.xlab.qianxin.com/) — primary research: backdoor discovery, technical analysis, IOCs, and detection commands
- [The Hacker News — Hackers Hide Linux Backdoor in Control Web Panel](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html) — public disclosure coverage, corroborates IOCs and technical details

---
*Report generated by Actioner*
