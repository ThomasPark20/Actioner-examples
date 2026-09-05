<!-- revision: v1.1 2026-09-05 — (1) Sigma DNS: removed attack.t1568 (hardcoded domains, not DGA); (2) Sigma files: replaced attack.t1547.004 with T1074.001; (3) ATT&CK table: T1070.004→T1070.002, T1574.002→T1554, T1497.001→T1480; (4) YARA CurlRAT: removed unverifiable meta hash 83f7d565…; (5) Suricata: added 3 DNS rules for maltrail domains (primgs.lol, grip-cdns.space, cleanos.online) as sid:2200009-2200011. -->
# Technical Analysis Report: Ted HAProxy Backdoor (2026-09-05)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-05
Version: 1.1 FINAL

## Executive Summary

A Linux toolkit dubbed "ted" has been discovered compiled into trojanized HAProxy instances deployed at two South Korean organizations in the automotive and media sectors. Rapid7 Labs attributes the campaign with medium confidence to North Korean state-sponsored actors, noting infrastructure overlaps with APT37, delivery model parallels with Lazarus, and initial access patterns consistent with Kimsuky. The ted backdoor intercepts HTTP traffic passing through compromised HAProxy load balancers, selectively serving modified pages to targeted visitors while erasing C2 connections from HAProxy's internal statistics. A companion RAT called CurlRAT, distributed through trojanized system daemons (crond, sshd, agetty, atd, polkitd), provides persistent remote access with 12-hour default beaconing, reverse shell capabilities, and file transfer. An SSH keylogger captures plaintext passwords. None of the six primary C2 domains currently resolve, but binary integrity checks, network correlation, and the detection rules below provide actionable coverage.

## Background: HAProxy Load Balancers at South Korean Enterprises

HAProxy is a widely deployed open-source load balancer and reverse proxy. By replacing the legitimate HAProxy binary on a production server, the attackers positioned the ted implant inline with all web traffic traversing the organization's infrastructure -- an ideal vantage point for both watering-hole content injection and credential interception. The attack does not exploit any vulnerability in HAProxy itself; it requires prior code execution and root access on the host to replace the running binary. HAProxy 2.8.12 (released November 2024) is the specific version the implant was compiled against, and a recompiled binary reports the same version string as a clean build, making version-based detection ineffective.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2024-11-22 | HAProxy 2.8.12-0fdb194 released (version targeted by ted build ID 24112201) |
| Mid-2025 onward | Trojanized HAProxy binaries uploaded to VirusTotal (~18 MB each) |
| 2026-09-04 | Rapid7 Labs publishes technical report on ted backdoor and CurlRAT |
| 2026-09-04 | None of the six primary C2 domains resolve |
| 2026-09-05 | The Hacker News and SC World report on the campaign |

## Root Cause: Exposed Groupware Portal (Hypothesized)

Rapid7's hypothesis for initial access is compromise through an exposed Groupware portal -- a common Korean enterprise collaboration platform. This aligns with ENKI's prior research documenting Kimsuky compromising a South Korean groupware vendor through a mail server flaw and deploying a Gomir family variant. The stager component deploys only where HAProxy or cron is already running and verifies root privileges before dropping payloads, confirming the attackers required existing code execution on the host.

## Technical Analysis of the Malicious Payload

### 1. Ted HAProxy Backdoor (Implant)

The ted backdoor is compiled as a custom filter plugin (`ted_plugin`) directly into the HAProxy binary, hooking the HTTP parser at the HTX (HTTP transaction) layer. Key characteristics:

- **Build ID:** 24112201, targeting HAProxy version 2.8.12-0fdb194
- **Binary size:** ~18 MB
- **Plugin routines:** Debug symbols reveal function names prefixed with `ted_` (e.g., `ted_load_filter_config`, `ted_chn_analyze_for_htx_constprop_0`, `ted_http_headers_for_htx`, `ted_http_payload`, `ted_pipe_master_thread`, `ted_pipe_worker_thread`, `ted_flt_register_ops2`)
- **Code heritage:** Routines prefixed `ngx_` (e.g., `ngx_decode`, `ngx_decrypt_script`) suggest code reuse from an nginx backdoor, paralleling patterns observed in the Funnull campaign

**Traffic filtering:** A request for the specific image path `/favorite_list_2x_m500_ico.jpg` switches the filter into C2 mode. For content injection, only requests passing four checks receive a modified page: User-Agent matching, URL/referer pattern matching, IP whitelist (CIDR /24 blocks stored in `haproxy-1001.cache` and `haproxy-1002.cache`), and an Accept-Language operator key override.

**Response manipulation:** The implant rewrites Content-Type and Content-Length headers, forces the status code to 200 OK, deletes the Accept-Ranges header (preventing byte-range-based integrity detection), and substitutes/appends body chunks via HTX buffer manipulation.

**Statistics evasion:** The implant decrements HAProxy's live connection counters (beconn, feconn, actconn, cum_conn, cum_req, bytes_in, bytes_out, sps_max, conn_max, cps_max) using hardcoded struct offsets specific to HAProxy 2.8.12, dropping C2 connections from the load balancer's statistics entirely.

**C2 opcodes:**
- Opcode 0 (0x30): Beacon with build ID and HAProxy version
- Opcode 1 (0x31): File upload
- Opcode 2 (0x32): File download
- Opcode 3 (0x33): Command execution (stdout/stderr merged via ` 2>&1`)
- Opcode 9 (0x39): Configuration update

**Encryption:** A substitution cipher with a distinctive 128+ character alphabet (`E1x0X3f2R5w4g7u6D968kAeCdBPEpDhGJF4IiHHKzJvMtLl...`), plus a rolling cumulative XOR cipher keyed from decoded headers.

### 2. CurlRAT (Remote Access Trojan)

CurlRAT is deployed as trojanized replacements for legitimate Linux daemons: crond, sshd, agetty, atd, and polkitd. On CentOS variants, functions are prefixed `atd_` (e.g., `atd_reverse_try_root`, `atd_http_request`, `atd_check_haproxy`).

- **Beacon interval:** 43,200 seconds (12 hours) default; drops to 30-second intervals when a fast-poll flag is set by the operator
- **Retry logic:** Up to 6 attempts with 5-second intervals
- **Victim ID:** MD5 hash of concatenated string `cron_3.0pl1-137ubuntu3` + hostname + IPv4 + hardware UUID
- **C2 POST format:** `name=%s&value=%s&type=%d` (application/x-www-form-urlencoded)
- **C2 authentication:** `User-token` header (MD5-hashed victim ID, uppercase) and `api_token: ecd427ea8330a4ff73618483e00b9b41`
- **XOR encryption:** Single-byte key 0x58 for configuration; feedback XOR cipher with seed modulo 240+10 for C2 traffic
- **Virtualization gate:** Aborts unless `/usr/lib/libvirtlog.so.0` exists (confirming the host is virtualized)

**Command modes:**
- Mode 0: Command execution via popen
- Mode 1: Config write to disk
- Mode 2: Staged payload drop with decompression
- Mode 3: Reverse shell with setuid(0)/setreuid(0,0)
- Mode 4: Beacon transmission (10 KB system info)
- Mode 5: PTY shell (IP:port format)

### 3. C2 Infrastructure

All six primary C2 domains follow the pattern `img.<name>.<tld>`:

| Domain (defanged) | Status |
|---|---|
| img[.]monderhouse[.]space | Not resolving |
| img[.]smartnords[.]site | Not resolving |
| img[.]darklights[.]store | Not resolving |
| img[.]responsive[.]pstatic[.]autos | Not resolving |
| img[.]socialteams[.]store | Not resolving |
| img[.]worksongo[.]store | Not resolving |

Additional domains found in maltrail's APT37 trail database but not in Rapid7's primary list:
- primgs[.]lol / admin[.]primgs[.]lol
- grip-cdns[.]space / show[.]grip-cdns[.]space
- cleanos[.]online / app[.]cleanos[.]online

### 4. SSH Keylogger

A trojanized SSH daemon captures plaintext passwords, encrypts them, and writes them to the fixed path `/var/lib/sshd/c8c68e629bba773a10ac80012d10bf19`. Hardcoded master passwords are checked before logging.

### 5. Anti-Forensics / Evasion Techniques

- **Log stripping:** Strips the keywords `tmp`, `wget`, `cron`, and `crond` from root's bash_history and six system logs (auth.log, audit/audit.log, syslog, secure, messages, cmd.log)
- **Timestomping:** The backdoored crond binary is given the creation timestamp of `/usr/bin/ssh`
- **HAProxy statistics scrubbing:** Live connection counters decremented to hide C2 connections
- **Deployment gate:** Stager deploys only where HAProxy or cron is already running and verifies root
- **Response header manipulation:** Accept-Ranges header deleted; Content-Length adjusted to hide modified body size

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - URLs: `hxxps://` or `hxxp://`

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | ~/cache/haproxy-1000.cache | -- | Ted operational config |
| Linux | ~/cache/haproxy-1001.cache | -- | Ted IP ACL list |
| Linux | ~/cache/haproxy-1002.cache | -- | Ted IP ACL list |
| Linux | ~/cache/haproxy-1000.cache.bak | -- | Ted config backup |
| Linux | /var/lib/sshd/c8c68e629bba773a10ac80012d10bf19 | 4bb923eb040aa13ca8fd409c31ee4729c60ddff32e350efe1c5a4a9168a065f5 | SSH keylogger output |
| Linux | /var/lib/snapd/g580 | -- | CurlRAT victim ID storage |
| Linux | /var/lib/snapd/g105 | -- | CurlRAT encrypted config |
| Linux | /tmp/jasper-log | -- | Log erasure staging file |
| Linux | /tmp/t[ID]_w.pipe | -- | Ted named pipe (per connection) |
| Linux | /tmp/nimon.unix-docbase.8564479396043450766-db6fb4443bc | -- | CurlRAT config staging |
| Linux | (HAProxy binary) | 94630b96f628c96a6bff7904b40ffc9ad67c86f8a4ff6080c3b524831c93f402 | Ted backdoor sample 1 |
| Linux | (HAProxy binary) | 72e70936f0dbe459142a1d867617c35f8d0cce5d18c6a49e1090a2a5adc8e558 | Ted backdoor sample 2 |
| Linux | (HAProxy binary) | a8bfab4de81a1acb04aacdf757346946b0f5e30f0c9f402004016d0e425119c7 | Ted backdoor sample 3 |
| Linux | (cronie variant) | d53c760c23b4405eb04ad0f20ead375440344b3bdf1fb7854ed12e40d155eabe | CurlRAT as crond |
| Linux | (agetty variant) | 2f02b09d61d432134e994ad671258f523bbf289ae6091fd4eae192c60bd51b6f | CurlRAT as agetty |
| Linux | (atd variant) | 8f30b57928934ae67478d0e690c91d046e35a638da098d02922a4a88a0fdb66c | CurlRAT as atd |
| Linux | (polkitd variant) | a1d8af3a6acb731f07f72040eccb3450c1c83d40e29f736c2a63d35388660be4 | CurlRAT as polkitd |
| Linux | (stager) | 5db1b6d52faf60b4f32d6fd0c7c938e4d05d29a14c32ded4a9668357c08b6a91 | CurlRAT stager |
| Linux | (stager) | 09739441ed4599bac2f8159028f772f71e4b25c8badfff95574e56d7384f3dbe | CurlRAT stager |
| Linux | (stager) | fea1bc36632c71e5a839803469ef60ac47595d36b2c50934ac109ade6df06e61 | CurlRAT stager |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | img[.]monderhouse[.]space | C2 (primary, fallback on validation failure) |
| Domain | img[.]smartnords[.]site | C2 |
| Domain | img[.]darklights[.]store | C2 (backup config host) |
| Domain | img[.]responsive[.]pstatic[.]autos | C2 |
| Domain | img[.]socialteams[.]store | C2 |
| Domain | img[.]worksongo[.]store | C2 |
| Domain | primgs[.]lol | C2 (maltrail APT37 trail) |
| Domain | admin[.]primgs[.]lol | C2 (maltrail APT37 trail) |
| Domain | grip-cdns[.]space | C2 (maltrail APT37 trail) |
| Domain | show[.]grip-cdns[.]space | C2 (maltrail APT37 trail) |
| Domain | cleanos[.]online | C2 (maltrail APT37 trail) |
| Domain | app[.]cleanos[.]online | C2 (maltrail APT37 trail) |
| URL Pattern | /favorite_list_2x_m500_ico.jpg | Ted C2 trigger URI path |
| HTTP Header | api_token: ecd427ea8330a4ff73618483e00b9b41 | CurlRAT C2 authentication |

### Behavioral

- CurlRAT beacons every 12 hours (43,200s) by default; switches to 30-second intervals when operator sets fast-poll flag
- C2 POST body uses form encoding `name=%s&value=%s&type=%d`
- Ted C2 mode activated by requesting specific image URI; C2 traffic then hidden from HAProxy connection stats
- Trojanized crond timestamps itself to match `/usr/bin/ssh` creation time
- Selective keyword erasure from bash_history and system logs (`tmp`, `wget`, `cron`, `crond`)
- CurlRAT aborts unless the virtualization marker `/usr/lib/libvirtlog.so.0` exists on the host

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1036.005 | Masquerading: Match Legitimate Name or Location | CurlRAT replaces legitimate daemon binaries (crond, sshd, agetty, atd, polkitd) |
| T1071.001 | Application Layer Protocol: Web Protocols | Ted C2 via crafted HTTP requests through HAProxy; CurlRAT beacons via HTTP POST |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Command execution via popen (CurlRAT mode 0) and shell (Ted opcode 3) |
| T1056.001 | Input Capture: Keylogging | Trojanized SSH daemon captures plaintext passwords |
| T1070.003 | Indicator Removal: Clear Command History | Strips keywords from root's bash_history |
| T1070.002 | Indicator Removal: Clear Linux or Mac System Logs | Selectively strips keywords from six system log files |
| T1070.006 | Indicator Removal: Timestomp | Backdoored crond given timestamp of /usr/bin/ssh |
| T1480 | Execution Guardrails | CurlRAT requires /usr/lib/libvirtlog.so.0 to exist before executing (environment gate, not evasion) |
| T1041 | Exfiltration Over C2 Channel | Captured credentials and file exfiltration over HTTP C2 |
| T1554 | Compromise Client Software Binary | HAProxy binary replaced with backdoored version containing ted implant |
| T1557 | Adversary-in-the-Middle | Ted intercepts and modifies HTTP traffic through HAProxy |
| T1105 | Ingress Tool Transfer | File upload/download via Ted opcodes 1 and 2 |

## Impact Assessment

Two confirmed South Korean organizations are affected (automotive and media sectors). The implant's position inline with all web traffic through HAProxy provides the attackers with watering-hole capability (selective content modification to targeted visitors), credential harvesting (SSH password capture), and persistent C2 access hidden within legitimate infrastructure. The statistical counter scrubbing and log stripping make detection through normal operational monitoring exceptionally difficult. Rapid7 notes tactical overlap with Lazarus's Operation SyncHole (server-side visitor filtering and redirect on South Korean media sites) and concurrent AnySign4PC watering hole operations (July 2026).

## Detection & Remediation

### Immediate Detection

```bash
# Check for Ted config cache files
find / -name "haproxy-*.cache" -path "*/cache/*" 2>/dev/null

# Check for SSH keylogger output
ls -la /var/lib/sshd/c8c68e629bba773a10ac80012d10bf19 2>/dev/null

# Check for CurlRAT config storage
ls -la /var/lib/snapd/g580 /var/lib/snapd/g105 2>/dev/null

# Check for jasper-log staging file
ls -la /tmp/jasper-log 2>/dev/null

# Check for named pipes matching Ted's pattern
find /tmp -name "t*_w.pipe" 2>/dev/null

# Verify HAProxy binary integrity (compare SHA256 to known-good)
sha256sum $(which haproxy) 2>/dev/null

# Check for Ted function names in HAProxy binary
strings $(which haproxy) 2>/dev/null | grep -E "ted_(load_filter|http_payload|pipe_master|flt_register)"

# Check for CurlRAT indicators in system daemons
for bin in /usr/sbin/crond /usr/sbin/sshd /sbin/agetty /usr/sbin/atd /usr/lib/polkit-1/polkitd; do
    [ -f "$bin" ] && strings "$bin" 2>/dev/null | grep -l "atd_reverse_try_root\|atd_check_haproxy" && echo "ALERT: $bin may be trojanized"
done

# Check for virtualization marker used by CurlRAT
ls -la /usr/lib/libvirtlog.so.0 2>/dev/null
```

### Remediation

1. **Contain:** Isolate affected HAProxy servers from the network immediately. Preserve forensic images before remediation.
2. **Verify binaries:** Compare SHA256 hashes of HAProxy, crond, sshd, agetty, atd, and polkitd against known-good packages from the distribution repository. Reinstall from trusted sources.
3. **Rotate credentials:** All SSH passwords and keys on affected hosts and any hosts those systems could reach must be considered compromised and rotated.
4. **Audit logs:** Check for evidence of the log-stripping keywords (`tmp`, `wget`, `cron`, `crond`) having been removed. Recover logs from centralized logging infrastructure if available.
5. **Network blocking:** Block the C2 domains listed in the IOC section at DNS and proxy layers even though they do not currently resolve -- they may be reactivated.
6. **Sweep for lateral movement:** The attackers had root access and SSH password capture; assume lateral movement to other internal systems.

### Long-Term Hardening

- Implement binary integrity monitoring (e.g., AIDE, Tripwire, or dm-verity) on critical infrastructure binaries including HAProxy, SSH, and cron daemons
- Deploy centralized, append-only log collection to prevent selective log stripping
- Restrict internet-facing Groupware portal access and apply mail server patches promptly
- Monitor for HAProxy binary replacement through file integrity monitoring rather than version string checks (which the implant preserves)

## Detection Rules

These detections target the Ted HAProxy backdoor and CurlRAT toolkit at PoC/advisory-specific altitude with strict leniency. The Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; YARA rules compile and fire on constructed test samples. Compiles does not equal fires in your environment -- verify against your telemetry pipeline.

### Sigma: DNS Query to Ted Backdoor C2 Domains

Detects DNS queries to known C2 domains used by the Ted/CurlRAT campaign infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to network error fetching MITRE ATT&CK data (proxy 403), not a rule issue. sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. No pipeline-mapped conversion available for dns_query category. All domain values are real (not defanged) in the rule. Nine domain suffixes cover the six Rapid7-reported domains plus three from maltrail APT37 trails. Revision: removed attack.t1568 (Dynamic Resolution) -- these are hardcoded C2 domains, not DGA-generated. -->
```yaml
title: DNS Query to Ted Backdoor C2 Domains
id: 8f3a1c7e-4b2d-4e9f-a6c8-1d5e0f7b3a2c
status: experimental
description: >
    Detects DNS queries to known C2 domains used by the Ted HAProxy backdoor
    and CurlRAT toolkit attributed to North Korean state-sponsored actors
    targeting South Korean organizations.
references:
    - https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/
    - https://thehackernews.com/2026/09/new-ted-backdoor-hides-inside-victims.html
author: Actioner
date: 2026/09/05
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.monderhouse.space'
            - '.smartnords.site'
            - '.darklights.store'
            - '.pstatic.autos'
            - '.socialteams.store'
            - '.worksongo.store'
            - '.primgs.lol'
            - '.grip-cdns.space'
            - '.cleanos.online'
    condition: selection
falsepositives:
    - Unlikely - these are attacker-registered domains with no known legitimate use
level: high
```

### Sigma: Ted Backdoor Distinctive File Artifacts on Linux Host

Detects file creation at paths specific to the Ted backdoor config cache, SSH keylogger output, and CurlRAT victim ID storage.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to network error fetching MITRE ATT&CK data (proxy 403), not a rule issue. sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Paths are distinctive enough for high confidence: haproxy-1000.cache is not a legitimate HAProxy artifact, c8c68e629bba773a10ac80012d10bf19 is an attacker-chosen MD5-like path, g580/g105 under snapd are not legitimate snapd files. Revision: replaced attack.t1547.004 (Winlogon Helper DLL, Windows-only) with attack.t1074.001 (Local Data Staging). -->
```yaml
title: Ted Backdoor Distinctive File Artifacts on Linux Host
id: 2e7b4d9a-6c1f-4a8e-b3d5-9f0e2c7a1b4d
status: experimental
description: >
    Detects file creation at paths associated with the Ted HAProxy backdoor
    and CurlRAT toolkit, including configuration cache files, SSH keylogger
    output, and victim ID storage used by DPRK-attributed actors.
references:
    - https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/
    - https://thehackernews.com/2026/09/new-ted-backdoor-hides-inside-victims.html
author: Actioner
date: 2026/09/05
tags:
    - attack.t1036.005
    - attack.t1074.001
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains:
            - '/cache/haproxy-1000.cache'
            - '/cache/haproxy-1001.cache'
            - '/cache/haproxy-1002.cache'
            - '/var/lib/sshd/c8c68e629bba773a10ac80012d10bf19'
            - '/var/lib/snapd/g580'
            - '/var/lib/snapd/g105'
            - '/tmp/jasper-log'
    condition: selection
falsepositives:
    - Unlikely - these are distinctive attacker-chosen paths not used by legitimate software
level: critical
```

### Snort: Ted Backdoor C2 Trigger URI and CurlRAT Beacon

Detects HTTP requests for the Ted C2 trigger URI `/favorite_list_2x_m500_ico.jpg` and CurlRAT beacon POST with the hardcoded `api_token` header value.
**Status:** compile ⚠️ uncompiled (structural check only -- snort not installed)  · confidence: high
<!-- audit: snort binary not available in this environment. Structural check: protocol http with http_uri/http_header/http_client_body sticky buffers, flow established/to_server, semicolons terminate all options, SIDs in 2100000+ range, Snort 3 comma-form content modifiers used. Two rules: sid:2100001 for Ted trigger URI, sid:2100002 for CurlRAT api_token beacon. /actioner:setup installs the full toolchain. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Ted Backdoor C2 Trigger URI Request (favorite_list_2x_m500_ico.jpg)"; flow:established,to_server; http_uri; content:"/favorite_list_2x_m500_ico.jpg", fast_pattern; classtype:trojan-activity; reference:url,www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/; metadata:author Actioner, created 2026-09-05; sid:2100001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CurlRAT C2 Beacon POST with api_token Header"; flow:established,to_server; http_method; content:"POST"; http_header; content:"api_token", fast_pattern; content:"ecd427ea8330a4ff73618483e00b9b41"; http_client_body; content:"name="; content:"&value="; content:"&type="; classtype:trojan-activity; reference:url,www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/; metadata:author Actioner, created 2026-09-05; sid:2100002; rev:1;)
```

### Suricata: Ted Backdoor C2 Trigger URI, C2 Domain DNS, and CurlRAT Beacon

Detects the Ted C2 trigger URI, DNS queries to campaign C2 domains, and CurlRAT beacon POST with the hardcoded `api_token` header.
**Status:** compile ⚠️ uncompiled (structural check only -- suricata not installed) · confidence: high
<!-- audit: suricata binary not available in this environment. Structural check: dot-notation sticky buffers (http.uri, http.method, http.request_header, http.request_body, dns.query), flow directives present, semicolons terminate all options, SIDs in 2200000+ range, msg prefixed "Actioner - ", metadata includes author and created_at. Eleven rules: sid:2200001 Ted trigger URI, sid:2200002-2200007 six Rapid7-sourced C2 domain DNS, sid:2200009-2200011 three maltrail-sourced C2 domain DNS, sid:2200008 CurlRAT beacon. /actioner:setup installs the full toolchain. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Ted Backdoor C2 Trigger URI Request (favorite_list_2x_m500_ico.jpg)"; flow:established,to_server; http.uri; content:"/favorite_list_2x_m500_ico.jpg"; fast_pattern; endswith; classtype:trojan-activity; reference:url,www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/; metadata:author Actioner, created_at 2026-09-05; sid:2200001; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Ted Backdoor C2 Domain (monderhouse.space)"; flow:to_server; dns.query; content:"monderhouse.space"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/; metadata:author Actioner, created_at 2026-09-05; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Ted Backdoor C2 Domain (smartnords.site)"; flow:to_server; dns.query; content:"smartnords.site"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/; metadata:author Actioner, created_at 2026-09-05; sid:2200003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Ted Backdoor C2 Domain (darklights.store)"; flow:to_server; dns.query; content:"darklights.store"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/; metadata:author Actioner, created_at 2026-09-05; sid:2200004; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Ted Backdoor C2 Domain (pstatic.autos)"; flow:to_server; dns.query; content:"pstatic.autos"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/; metadata:author Actioner, created_at 2026-09-05; sid:2200005; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Ted Backdoor C2 Domain (socialteams.store)"; flow:to_server; dns.query; content:"socialteams.store"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/; metadata:author Actioner, created_at 2026-09-05; sid:2200006; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Ted Backdoor C2 Domain (worksongo.store)"; flow:to_server; dns.query; content:"worksongo.store"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/; metadata:author Actioner, created_at 2026-09-05; sid:2200007; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Ted Backdoor C2 Domain (primgs.lol)"; flow:to_server; dns.query; content:"primgs.lol"; nocase; fast_pattern; classtype:trojan-activity; reference:url,github.com/stamparm/maltrail; metadata:author Actioner, created_at 2026-09-05; sid:2200009; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Ted Backdoor C2 Domain (grip-cdns.space)"; flow:to_server; dns.query; content:"grip-cdns.space"; nocase; fast_pattern; classtype:trojan-activity; reference:url,github.com/stamparm/maltrail; metadata:author Actioner, created_at 2026-09-05; sid:2200010; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Ted Backdoor C2 Domain (cleanos.online)"; flow:to_server; dns.query; content:"cleanos.online"; nocase; fast_pattern; classtype:trojan-activity; reference:url,github.com/stamparm/maltrail; metadata:author Actioner, created_at 2026-09-05; sid:2200011; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CurlRAT C2 Beacon POST with api_token Header"; flow:established,to_server; http.method; content:"POST"; http.request_header; content:"api_token"; content:"ecd427ea8330a4ff73618483e00b9b41"; http.request_body; content:"name="; content:"&value="; content:"&type="; classtype:trojan-activity; reference:url,www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/; metadata:author Actioner, created_at 2026-09-05; sid:2200008; rev:1;)
```

### YARA: Ted HAProxy Backdoor Binary Detection

Detects trojanized HAProxy ELF binaries containing the Ted backdoor plugin via distinctive function names, config paths, build identifiers, C2 token, and the unique substitution cipher alphabet.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: positive file with ELF magic + ted_load_filter_config/ted_chn_analyze_for_htx/ted_http_headers_for_htx/ted_http_payload + haproxy-1000.cache/haproxy-1001.cache + 2.8.12-0fdb194 matched DPRK_Ted_HAProxy_Backdoor; negative file with clean HAProxy strings did not match. Strings sourced from Rapid7's published debug symbol and config path analysis. The $api_token branch alone is an MD5 hash (32 hex chars) which could in theory appear in other contexts but is combined with the ELF check and filesize constraint. -->
```yara
rule DPRK_Ted_HAProxy_Backdoor : backdoor apt
{
    meta:
        description = "Detects the Ted backdoor compiled into trojanized HAProxy binaries, targeting South Korean organizations. Keys on distinctive ted_plugin function names, C2 config paths, build identifiers, and the substitution cipher alphabet unique to this implant."
        author = "Actioner"
        date = "2026-09-05"
        reference = "https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/"
        hash = "94630b96f628c96a6bff7904b40ffc9ad67c86f8a4ff6080c3b524831c93f402"
        hash = "72e70936f0dbe459142a1d867617c35f8d0cce5d18c6a49e1090a2a5adc8e558"
        hash = "a8bfab4de81a1acb04aacdf757346946b0f5e30f0c9f402004016d0e425119c7"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Ted plugin function names (debug symbols)
        $fn1 = "ted_load_filter_config" ascii
        $fn2 = "ted_chn_analyze_for_htx" ascii
        $fn3 = "ted_http_headers_for_htx" ascii
        $fn4 = "ted_http_payload" ascii
        $fn5 = "ted_pipe_master_thread" ascii
        $fn6 = "ted_pipe_worker_thread" ascii
        $fn7 = "ted_flt_register_ops2" ascii
        $fn8 = "ted_task_for_response" ascii
        $fn9 = "ted_reload_filter_config" ascii
        $fn10 = "ted_load_ip_set" ascii
        $fn11 = "ted_save_capture_log2" ascii

        // C2 config file paths
        $path1 = "haproxy-1000.cache" ascii
        $path2 = "haproxy-1001.cache" ascii
        $path3 = "haproxy-1002.cache" ascii

        // Build ID and version string
        $build = "24112201" ascii
        $ver = "2.8.12-0fdb194" ascii

        // C2 authentication token
        $api_token = "ecd427ea8330a4ff73618483e00b9b41" ascii

        // C2 trigger URI
        $trigger_uri = "favorite_list_2x_m500_ico.jpg" ascii

        // Nginx-reuse indicator (code heritage)
        $ngx1 = "ngx_decode" ascii
        $ngx2 = "ngx_decrypt_script" ascii

        // Named pipe pattern
        $pipe = "_w.pipe" ascii

        // Substitution cipher alphabet fragment (unique to ted)
        $cipher = "E1x0X3f2R5w4g7u6D968kAeCdBPEpDhGJF4IiHHKzJvMtLl" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 25MB and
        (
            (3 of ($fn*)) or
            (2 of ($path*) and ($ver or $build)) or
            ($api_token) or
            ($trigger_uri and 1 of ($fn*)) or
            ($cipher) or
            (1 of ($ngx*) and $pipe and 1 of ($path*))
        )
}
```

### YARA: CurlRAT Trojanized Binary Detection

Detects CurlRAT variants masquerading as legitimate Linux daemons (crond, sshd, agetty, atd, polkitd) via distinctive `atd_` prefixed function names, victim ID seed, C2 POST format, and virtualization gate path.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: positive file with ELF magic + atd_reverse_try_root/atd_reverse_create_conn/atd_http_request/atd_download_to_file/atd_get_system_info + /var/lib/snapd/g580 matched DPRK_CurlRAT_Trojanized_Binary; negative clean HAProxy file did not match. The $id_seed "cron_3.0pl1-137ubuntu3" is a fabricated version string unique to this actor's victim ID generation. $post_fmt "name=%s&value=%s&type=%d" is somewhat generic but only fires in combination with the virtualization check path. Revision: removed unverifiable meta hash 83f7d565b0465546027052b597af46eae3a199e7a91fcc2ab936341147349130 (not present in Rapid7 IOC table or public sources). -->
```yara
rule DPRK_CurlRAT_Trojanized_Binary : backdoor apt
{
    meta:
        description = "Detects CurlRAT variants masquerading as legitimate Linux daemons (crond, sshd, agetty, atd, polkitd) used alongside the Ted HAProxy backdoor in DPRK-attributed operations."
        author = "Actioner"
        date = "2026-09-05"
        reference = "https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/"
        hash = "5db1b6d52faf60b4f32d6fd0c7c938e4d05d29a14c32ded4a9668357c08b6a91"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // CurlRAT function naming convention (atd_ prefix on CentOS variants)
        $atd1 = "atd_reverse_try_root" ascii
        $atd2 = "atd_reverse_create_conn" ascii
        $atd3 = "atd_http_request" ascii
        $atd4 = "atd_download_to_file" ascii
        $atd5 = "atd_get_system_info" ascii
        $atd6 = "atd_create_id" ascii
        $atd7 = "atd_encrypt_url" ascii
        $atd8 = "atd_decrypt_url" ascii
        $atd9 = "atd_check_haproxy" ascii
        $atd10 = "atd_run_shell" ascii

        // Victim ID generation seed string
        $id_seed = "cron_3.0pl1-137ubuntu3" ascii

        // C2 POST body format
        $post_fmt = "name=%s&value=%s&type=%d" ascii

        // CurlRAT config paths
        $cfg1 = "/var/lib/snapd/g580" ascii
        $cfg2 = "/var/lib/snapd/g105" ascii

        // Virtualization check marker
        $virt_check = "/usr/lib/libvirtlog.so.0" ascii

        // C2 HTTP header
        $header1 = "User-token" ascii
        $header2 = "api_token" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            (3 of ($atd*)) or
            ($id_seed) or
            ($post_fmt and $virt_check) or
            (2 of ($cfg*) and 1 of ($header*))
        )
}
```

## Lessons Learned

This campaign demonstrates the strategic value attackers derive from compromising infrastructure-layer software like load balancers. A backdoored HAProxy binary sits at the ideal vantage point for watering-hole attacks -- upstream of all web traffic, trusted by clients and servers alike, and largely invisible to endpoint security products that focus on user-space process activity. Key takeaways:

1. **Binary integrity monitoring is essential for infrastructure software.** Version strings are trivially preserved in recompiled binaries, making version-based detection worthless. File hash comparison against distribution packages remains the most reliable detection.
2. **HAProxy's internal statistics cannot be trusted for security monitoring** when the binary itself is compromised. The ted implant's counter-scrubbing technique renders connection-based anomaly detection blind to C2 activity.
3. **Attribution complexity is increasing.** Mandiant's 2023 assessment noted shared tooling across North Korean clusters (APT37, Lazarus, Kimsuky). The ted campaign reinforces this -- infrastructure overlaps with APT37, delivery parallels with Lazarus, and initial access consistent with Kimsuky make precise attribution difficult and suggest coordinated or shared operational resources.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Rapid7 Labs Technical Report](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/) -- primary technical analysis of Ted backdoor, CurlRAT, and SSH keylogger with IOCs and C2 protocol details
- [The Hacker News](https://thehackernews.com/2026/09/new-ted-backdoor-hides-inside-victims.html) -- reporting on Rapid7 findings with additional context on attribution and Operation SyncHole parallels
- [SC World](https://www.scworld.com/brief/new-linux-toolkit-found-in-trojanized-haproxy-targeting-south-korean-organizations) -- summary reporting on the campaign
- [ENKI Groupware Research](https://www.enki.co.kr/en/media-center/blog/analysis-of-kimsuky-s-attack-on-a-south-korean-groupware-vendor-using-a-new-gomir-family-variant) -- Kimsuky groupware compromise supporting the initial access hypothesis
- [Kaspersky Operation SyncHole Report](https://securelist.com/operation-synchole-watering-hole-attacks-by-lazarus/116326/) -- Lazarus watering hole operations against South Korean media with similar tactical approach
- [Mandiant 2023 North Korea Assessment](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-cyber-structure-alignment-2023) -- shared tooling across DPRK clusters complicating attribution
- [maltrail APT37 Trails](https://github.com/stamparm/maltrail) -- additional C2 domains associated with APT37 infrastructure
- [ThreatFox Ricochet Chollima Tag](https://threatfox.abuse.ch/browse/tag/RicochetChollima/) -- community IOC sharing for related DPRK activity

---
*Report generated by Actioner*
