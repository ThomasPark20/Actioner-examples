# Cacti 4HTTP2ROOT Zero-Day: Unauthenticated RCE via Guest Access

**Date:** 2026-11-27  
**Status:** DRAFT  
**Severity:** Critical (Provisional)  
**CVE:** None assigned (unverified reference CVE-2026-132165 on Sploitus; treat as unconfirmed)  
**Affected:** Cacti Core 1.2.31 (latest stable) with guest access enabled  
**Patch:** None available at time of publication  

---

## Executive Summary

On November 26, 2026, security researcher "ek0ms savi0r" publicly disclosed a zero-day exploit chain affecting Cacti Core 1.2.31, the latest stable release of the open-source network monitoring platform. Dubbed **4HTTP2ROOT** (also referenced as **4HTTP2SHELL**), the vulnerability enables unauthenticated remote code execution in as few as four HTTP requests when anonymous guest access is enabled. The chain exploits a stored second-order SQL injection through a guest-editable profile setting, which ultimately leads to arbitrary command execution via Cacti's poller subsystem. No official CVE has been assigned, no vendor patch exists, and the proof-of-concept code is publicly available. Previdian independently verified the exploit in a lab environment. watchTowr confirmed it was reacting and had alerted its platform clients.

## Background

Cacti is a widely deployed open-source network monitoring and graphing framework built on PHP and MySQL/MariaDB. It is commonly used to monitor network infrastructure via SNMP polling and stores credentials for routers, switches, and servers. Cacti includes an optional "guest" account that provides anonymous read-only access. While this account has been disabled by default since version 0.8.7, many deployments enable it for convenience, creating the attack surface this exploit chain requires.

## Attack Timeline

| Date | Event |
|------|-------|
| 2026-11-26 | Researcher "ek0ms savi0r" publishes PoC on GitHub |
| 2026-11-26 | Previdian reports independent lab verification |
| 2026-11-27 | watchTowr publishes FAQ and alerts platform clients |
| 2026-11-27 | Multiple security news outlets publish coverage |
| 2026-11-27 | No CVE assigned, no vendor patch available |

## Root Cause Analysis

The exploit chain relies on four distinct failures in Cacti's input validation and execution pipeline:

1. **Missing type validation on guest-editable setting:** The `auth_profile.php` endpoint accepts arbitrary non-numeric strings for the `preview_graphs_per_page` user setting, which should only hold an integer. The write itself uses a prepared statement (safe), but the value is never validated as numeric.

2. **Stored defaults bypass request-side validation:** When `graph_view.php` reads the stored default value from the `settings_user` database table, it bypasses the integer validation applied to request-time parameters. The stored value is trusted implicitly.

3. **SQL LIMIT clause injection with stacked statements:** The stored non-numeric value is concatenated directly into a SQL `LIMIT` clause in `get_allowed_graphs()` within `lib/auth.php`. The PHP PDO database driver accepts stacked statements, allowing the injected value to execute an additional `UPDATE` query that modifies `poller_item.arg1`.

4. **Unsafe command execution from database-stored value:** The `graph_realtime.php` endpoint triggers `poller_realtime.php` / `cmd_realtime.php`, which reads `poller_item.arg1` and passes it to `exec_poll()` in `lib/poller.php`. This function calls PHP's `popen()` without any allowlist or sanitization, executing the attacker-controlled value as a shell command.

## Technical Analysis

### Exploit Chain Stages

The complete exploit chain requires exactly four HTTP requests:

**Stage 1 — Session Acquisition (GET)**
```
GET /cacti/auth_profile.php?tab=general&header=false
```
An unauthenticated visitor obtains a PHP session cookie and `csrfMagicToken` from the guest-accessible profile page.

**Stage 2 — Stored SQL Fragment Injection (POST)**
```
POST /cacti/auth_profile.php
Parameters: tab=general, action=update_data, header=false
Body: name=preview_graphs_per_page, value=<injected SQL>
```
The guest user stores a crafted non-numeric string into the `preview_graphs_per_page` setting in the `settings_user` database table. The injected value contains a stacked SQL statement designed to `UPDATE` the `poller_item` table, specifically modifying `arg1` (and optionally `host_id`/`action`) for a chosen `local_data_id`.

**Stage 3 — Second-Order SQL Injection Trigger (GET)**
```
GET /cacti/graph_view.php?action=preview&page=1&clear=1
```
Loading the graph preview page causes Cacti to read the stored `preview_graphs_per_page` value and concatenate it into a `LIMIT` clause. The stacked `UPDATE` statement executes, writing the attacker's command string into `poller_item.arg1`.

**Stage 4 — Command Execution (GET)**
```
GET /cacti/graph_realtime.php?action=init&local_graph_id=1&ds_step=10&size=90
```
The realtime graph initialization triggers the poller subsystem (`poller_realtime.php` -> `cmd_realtime.php` -> `lib/poller.php`), which reads the modified `poller_item.arg1` and passes it to `popen()`, executing the attacker's command with the privileges of the Cacti web/poller process.

### Affected Code Paths

| File | Function/Area | Role |
|------|--------------|------|
| `auth_profile.php` | `update_data` action | Accepts non-numeric setting value |
| `graph_view.php` | Preview action | Reads stored default, triggers SQLi |
| `lib/auth.php` | `get_allowed_graphs()` | Constructs LIMIT clause with unsanitized value |
| `lib/html_graph.php` | ~line 87 | Default value for `preview_graphs_per_page` |
| `lib/html_utility.php` | ~line 661 | Unfiltered default path |
| `graph_realtime.php` | `init` action | Triggers poller execution |
| `poller_realtime.php` | Poller invocation | Reads modified poller_item |
| `cmd_realtime.php` | ~line 221 | Passes arg1 to exec_poll() |
| `lib/poller.php` | `exec_poll()`, ~line 37 | Calls `popen()` with attacker value |

### Database Tables Involved

- **`settings_user`**: Stores the malicious non-numeric `preview_graphs_per_page` value
- **`poller_item`**: The `arg1` column is modified via stacked SQL to contain the attacker's command

### Command Execution Context

Commands execute with the privileges of the Cacti web server/poller process. In the PoC demonstration, root access was achieved because Cacti was running as root — this is a deployment misconfiguration, not a separate privilege escalation. Typical production deployments run as `www-data` or `apache`.

### Persistence and Post-Exploitation

- The PoC writes output to `cache/4http2root-proof.txt` as a demonstration artifact
- A PHP webshell can be dropped in the Cacti web root or `cache/` directory for persistent access
- Cacti commonly stores SNMP community strings, device credentials, and database credentials, enabling lateral movement to monitored infrastructure

### Platform Behavior

- **Precondition:** Guest access must be enabled (`Configuration > Settings > Authentication > Guest User` set to a user)
- **Guest access default:** Disabled since Cacti 0.8.7, but commonly enabled in production
- **Realtime graphing:** Must be enabled (this is the default)
- **Database driver:** PDO with stacked-statement support (default configuration)

## Indicators of Compromise

### Network IOCs (Defanged)

| Type | Indicator | Context |
|------|-----------|---------|
| URL | `hxxps://github[.]com/ekomsSavior/Sad-Girls-0day-Club/tree/main/4http2shell` | PoC Repository |
| URL | `hxxps://ravenai[.]sh/blog/four-requests-to-shell-cacti` | Technical writeup |

### Host IOCs

| Type | Indicator | Context |
|------|-----------|---------|
| File | `cache/4http2root-proof.txt` | PoC proof-of-concept output file |
| File | Unexpected `.php` files in Cacti `cache/` directory | Potential webshell |
| DB | Non-numeric values in `settings_user` for `preview_graphs_per_page` | Exploit stage 2 artifact |
| DB | Unexpected commands in `poller_item.arg1` | Exploit stage 3 artifact |
| Log | PHP warnings about non-numeric values in `graph_view.php` | Exploit stage 3 signal |

### Web Log Indicators

| Pattern | Context |
|---------|---------|
| POST to `auth_profile.php` with `action=update_data` from unauthenticated/guest sessions | Stage 2 — setting injection |
| GET to `graph_view.php` with `action=preview` and `clear=1` | Stage 3 — SQLi trigger |
| GET to `graph_realtime.php` with `action=init` | Stage 4 — command execution |
| Requests for files under `/cache/` that do not match normal graph output | Post-exploitation artifact access |

## MITRE ATT&CK Mapping

| Technique ID | Name | Chain Stage |
|-------------|------|-------------|
| T1190 | Exploit Public-Facing Application | Initial Access (Stages 1-4) |
| T1078.001 | Valid Accounts: Default Accounts | Guest account abuse (Stage 1) |
| T1565.001 | Data Manipulation: Stored Data Manipulation | Database record modification (Stage 3) |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Command execution via popen() (Stage 4) |
| T1505.003 | Server Software Component: Web Shell | Potential webshell deployment (Post-exploitation) |
| T1552 | Unsecured Credentials | Access to stored device/SNMP credentials (Post-exploitation) |

## Impact Assessment

**Severity: Critical**

- **Unauthenticated RCE:** No credentials required; exploitable by any network-reachable attacker when guest access is enabled
- **Low complexity:** Only 4 HTTP requests needed; PoC is publicly available
- **No patch available:** Zero-day with no vendor fix at time of disclosure
- **Credential exposure:** Cacti stores network device credentials (SNMP communities, login credentials) that could enable lateral movement across monitored infrastructure
- **Monitoring disruption:** Attacker can suppress or manipulate monitoring alerts by modifying poller configurations
- **Wide deployment:** Cacti is used by enterprises, ISPs, and data centers globally

**Mitigating factors:**
- Guest access is disabled by default since Cacti 0.8.7
- Commands run as the Cacti process user (not necessarily root)
- Realtime graphing must be enabled (though it is by default)
- No confirmed in-the-wild exploitation as of 2026-11-27

## Detection & Remediation

### Immediate Mitigations

1. **Disable the guest account** — This is the single most effective mitigation. Navigate to `Configuration > Settings > Authentication` and set Guest User to "No User."
2. **Restrict network access** to the Cacti web interface via firewall rules or VPN; do not expose Cacti to the internet.
3. **Run Cacti as an unprivileged user** (e.g., `www-data` or dedicated `cacti` user), not root.
4. **Audit the database** for signs of tampering:
   - Check `settings_user` for non-numeric values in `preview_graphs_per_page`
   - Check `poller_item` for unexpected values in `arg1`
5. **Monitor the filesystem** for unexpected files in Cacti's `cache/` directory, especially PHP files.
6. **Rotate credentials** stored on the Cacti host (SNMP communities, device credentials, database passwords) if compromise is suspected.
7. **Disable stacked-statement support** in the database driver where possible (limits this class of injection).
8. **Apply the vendor patch** as soon as one is released for Cacti Core beyond 1.2.31.

### Detection Guidance

- Correlate the three web request stages (profile POST, graph preview GET, realtime init GET) from a single client IP within a short time window (10 minutes)
- Alert on guest sessions performing profile update operations
- Monitor for PHP/web server processes spawning shell child processes (especially from `cmd_realtime.php` or `poller_realtime.php`)
- Watch Cacti logs (`log/cacti.log`) for non-numeric value warnings from `graph_view.php`

## Detection Rules

### Sigma: Cacti Guest Profile Setting Manipulation

Detects POST requests to `auth_profile.php` with `action=update_data`, the initial setting injection step of the 4HTTP2ROOT exploit chain.

**Status:** ✅ Compiles | Confidence: **High**

```yaml
title: Cacti 4HTTP2ROOT Guest Profile Setting Manipulation
id: 7c3a1e9f-2d4b-4f8a-b6e1-9a0c5d3f7e2b
status: experimental
description: Detects HTTP POST requests to Cacti auth_profile.php with action=update_data targeting the preview_graphs_per_page setting, which is the initial step of the 4HTTP2ROOT unauthenticated RCE exploit chain.
references:
    - https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html
    - https://github.com/ekomsSavior/Sad-Girls-0day-Club/tree/main/4http2shell
    - https://watchtowr.com/intelligence/4http2root-cacti-zero-day-faq/
author: Actioner
date: 2026/11/27
tags:
    - attack.t1190
    - attack.t1565.001
logsource:
    category: webserver
    service: access
detection:
    selection_uri:
        cs-uri-query|contains|all:
            - 'auth_profile.php'
            - 'action=update_data'
    selection_method:
        cs-method: 'POST'
    condition: selection_uri and selection_method
falsepositives:
    - Legitimate Cacti administrators updating their profile display settings
level: high
```

<!-- audit: sigma check passed (0 errors, 0 issues; tag validators excluded due to proxy blocking MITRE ATT&CK data fetch — HTTP 403). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. -->

Legitimate admin profile updates will match; tune by excluding authenticated admin source IPs.

### Sigma: Cacti 4HTTP2ROOT Realtime Graph Command Execution Trigger

Detects GET requests to `graph_realtime.php` with `action=init` and PoC-default parameters (`ds_step`, `size`), indicating the command execution trigger stage.

**Status:** ✅ Compiles | Confidence: **Medium**

```yaml
title: Cacti 4HTTP2ROOT Realtime Graph Command Execution Trigger
id: 8b4d2f1a-3e5c-4a9b-c7f2-0b1d6e4a8f3c
status: experimental
description: Detects HTTP GET requests to Cacti graph_realtime.php with the action=init parameter combined with PoC-default parameters ds_step and size, indicating the command execution trigger stage of the 4HTTP2ROOT exploit chain.
references:
    - https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html
    - https://github.com/ekomsSavior/Sad-Girls-0day-Club/tree/main/4http2shell
    - https://watchtowr.com/intelligence/4http2root-cacti-zero-day-faq/
author: Actioner
date: 2026/11/27
tags:
    - attack.t1190
    - attack.t1059.004
logsource:
    category: webserver
    service: access
detection:
    selection:
        cs-uri-query|contains|all:
            - 'graph_realtime.php'
            - 'action=init'
            - 'ds_step='
            - 'size='
    condition: selection
falsepositives:
    - Legitimate use of Cacti realtime graphing by authenticated administrators
level: medium
```

<!-- audit: sigma check passed (0 errors, 0 issues; tag validators excluded due to proxy blocking MITRE ATT&CK data fetch — HTTP 403). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. -->

The `ds_step` and `size` parameters appear in the PoC default and in legitimate realtime graph usage; correlate with Stages 2-3 for higher fidelity.

### Sigma: Cacti Web/Poller Process Spawning Shell

Detects PHP or web server processes associated with Cacti's realtime poller spawning shell processes, indicating successful command execution.

**Status:** ✅ Compiles | Confidence: **Medium**

```yaml
title: Cacti Web Server Process Spawning Shell
id: 9c5e3a2b-4f6d-4b0c-d8a3-1c2e7f5b9a4d
status: experimental
description: Detects the Cacti web server or PHP process spawning a shell process, which may indicate successful exploitation of the 4HTTP2ROOT vulnerability chain where a modified poller_item.arg1 value is executed via popen().
references:
    - https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html
    - https://github.com/ekomsSavior/Sad-Girls-0day-Club/tree/main/4http2shell
author: Actioner
date: 2026/11/27
tags:
    - attack.t1059.004
    - attack.t1505.003
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/php-fpm'
            - '/php-cgi'
            - '/php'
            - '/apache2'
            - '/httpd'
            - '/nginx'
        ParentCommandLine|contains:
            - 'cmd_realtime.php'
            - 'poller_realtime.php'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Cacti poller operations that invoke shell commands
    - Custom Cacti scripts executed via the poller
level: medium
```

<!-- audit: sigma check passed (0 errors, 0 issues; tag validators excluded due to proxy blocking MITRE ATT&CK data fetch — HTTP 403). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. This is a TTP/behavioral rule and therefore labeled medium confidence. -->

This is a behavioral/TTP rule that may fire on legitimate poller shell invocations; requires endpoint telemetry (Sysmon for Linux or auditd).

### Snort: Cacti 4HTTP2ROOT Detection

Network-level detection for the profile update injection, SQL injection trigger, and command execution trigger stages.

**Status:** ✅ Compiles | Confidence: **High** (sids 2100001, 2100003), **Medium** (sid 2100002)

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Cacti 4HTTP2ROOT Guest Profile Setting Manipulation (POST auth_profile.php update_data)"; flow:to_server,established; content:"POST"; http_method; content:"/auth_profile.php"; http_uri; content:"action=update_data"; http_uri; content:"preview_graphs_per_page"; http_client_body; classtype:web-application-attack; sid:2100001; rev:1; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:created_at 2026_11_27;)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Cacti 4HTTP2ROOT Realtime Graph Command Execution Trigger (graph_realtime.php action=init)"; flow:to_server,established; content:"/graph_realtime.php"; http_uri; content:"action=init"; http_uri; classtype:web-application-attack; sid:2100002; rev:1; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:created_at 2026_11_27;)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Cacti 4HTTP2ROOT SQL Injection Trigger via graph_view.php Preview"; flow:to_server,established; content:"/graph_view.php"; http_uri; content:"action=preview"; http_uri; content:"clear=1"; http_uri; classtype:web-application-attack; sid:2100003; rev:1; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:created_at 2026_11_27;)
```

<!-- audit: snort -T -c (minimal config with rules appended) exit 0 — "Snort successfully validated the configuration!" Rules parsed with no errors. -->

SID 2100002 will match legitimate realtime graph usage; deploy with threshold or suppress for known admin IPs.

### Suricata: Cacti 4HTTP2ROOT Detection

Network-level detection using Suricata sticky buffers for the exploit chain stages.

**Status:** ✅ Compiles | Confidence: **High** (sids 2200001, 2200003), **Medium** (sid 2200002)

```
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Cacti 4HTTP2ROOT Guest Profile Setting Manipulation (POST auth_profile.php update_data)"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/auth_profile.php"; content:"action=update_data"; http.request_body; content:"preview_graphs_per_page"; classtype:web-application-attack; sid:2200001; rev:1; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:created_at 2026_11_27;)

alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Cacti 4HTTP2ROOT Realtime Graph Command Execution Trigger (graph_realtime.php action=init)"; flow:to_server,established; http.uri; content:"/graph_realtime.php"; content:"action=init"; classtype:web-application-attack; sid:2200002; rev:1; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:created_at 2026_11_27;)

alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Cacti 4HTTP2ROOT SQL Injection Trigger via graph_view.php Preview"; flow:to_server,established; http.uri; content:"/graph_view.php"; content:"action=preview"; content:"clear=1"; classtype:web-application-attack; sid:2200003; rev:1; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:created_at 2026_11_27;)
```

<!-- audit: suricata -T -S /tmp/actioner/cacti-4http2root-suri.rules -l /tmp/actioner exit 0 — "Configuration provided was successfully loaded. Exiting." All 3 rules loaded without errors. -->

### YARA: Cacti 4HTTP2ROOT File Artifacts

File-level detection for the PoC proof file and potential webshell artifacts associated with the 4HTTP2ROOT exploit chain.

**Status:** ✅ Compiles | Confidence: **High** (Cacti_4HTTP2ROOT_Proof_File), **Low** (Cacti_4HTTP2ROOT_Webshell_Indicator)

```yara
rule Cacti_4HTTP2ROOT_Proof_File
{
    meta:
        description = "Detects the proof-of-concept output file created by the Cacti 4HTTP2ROOT exploit chain (cache/4http2root-proof.txt)"
        author = "Actioner"
        date = "2026-11-27"
        reference = "https://github.com/ekomsSavior/Sad-Girls-0day-Club/tree/main/4http2shell"
        hash = "n/a"

    strings:
        $proof_filename = "4http2root-proof" ascii wide
        $poc_marker1 = "4http2root" ascii wide nocase
        $poc_marker2 = "4http2shell" ascii wide nocase
        $poc_repo = "Sad-Girls-0day-Club" ascii wide

    condition:
        filesize < 1MB and ($proof_filename or $poc_repo or ($poc_marker1 and $poc_marker2))
}

rule Cacti_4HTTP2ROOT_Webshell_Indicator
{
    meta:
        description = "Detects potential web shells dropped via the Cacti 4HTTP2ROOT exploit chain in the Cacti cache directory"
        author = "Actioner"
        date = "2026-11-27"
        reference = "https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html"

    strings:
        $php_tag = "<?php" ascii
        $shell_func1 = "popen(" ascii
        $shell_func2 = "system(" ascii
        $shell_func3 = "exec(" ascii
        $shell_func4 = "passthru(" ascii
        $shell_func5 = "shell_exec(" ascii
        $shell_func6 = "proc_open(" ascii
        $cacti_marker1 = "cacti" ascii nocase
        $cacti_marker2 = "poller" ascii nocase

    condition:
        filesize < 100KB and $php_tag and any of ($shell_func*) and any of ($cacti_marker*)
}
```

<!-- audit: yarac /tmp/actioner/cacti-4http2root.yar /dev/null exit 0 — compiled without errors. The webshell rule is behavioral (generic PHP shell detection scoped to Cacti context) and therefore labeled low confidence. -->

The webshell indicator rule is broad and will match legitimate Cacti PHP files containing shell functions; scope scanning to the `cache/` directory.

## Sources

- [The Hacker News — Unpatched Cacti Zero-Day Enables RCE in Just Four HTTP Requests via Guest Access](https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html)
- [ek0ms savi0r PoC Repository (GitHub)](https://github.com/ekomsSavior/Sad-Girls-0day-Club/tree/main/4http2shell)
- [watchTowr — 4HTTP2ROOT Cacti Zero-Day FAQ](https://watchtowr.com/intelligence/4http2root-cacti-zero-day-faq/)
- [RavenAI — Four Requests to Shell Cacti](https://ravenai.sh/blog/four-requests-to-shell-cacti)
- [ThreatLinqs — TL-2026-6953](https://intel.threadlinqs.com/threat/TL-2026-6953)
- [Mallory.ai — Cacti Zero-Day Enables Unauthenticated RCE](https://mallory.ai/stories/01a21b9c-40fa-74f2-934a-a092d4b8fd13)
- [Sploitus — cacti-cve-4http2root PoC](https://sploitus.com/exploit?id=94438D01-939A-575F-818F-185FC6320F00)
- [watchTowr on X (Twitter)](https://x.com/watchtowrcyber/status/2126054622443737594)
- [Cacti Releases (GitHub)](https://github.com/Cacti/cacti/releases)
- [Cacti User Management Documentation](https://docs.cacti.net/User-Management.md)
