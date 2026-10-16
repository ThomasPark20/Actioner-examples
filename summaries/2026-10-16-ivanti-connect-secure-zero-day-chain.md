# CVE-2026-104935: Ivanti Connect Secure Zero-Day Chain -- Authentication Bypass to Unauthenticated Root (CVSS 8.6)

> **Status:** FINAL -- Actioner automated analysis (revised 2026-10-16)
> **Date:** 2026-10-16
> **Analyst:** Actioner
> **CVE:** CVE-2026-104935 (covers authentication bypass + RCE); privilege escalation flaw has no CVE yet
> **CVSS:** 8.6 (High) -- AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L
> **CWE:** CWE-290 (Authentication Bypass by Spoofing)
> **Threat Actor:** UTA0576 (Volexity tracking designation)

---

## Executive Summary

CVE-2026-104935 is a high-severity authentication bypass vulnerability in Ivanti Connect Secure (ICS) VPN appliances that attackers chained with two additional zero-day vulnerabilities -- a remote code execution race condition and an in-memory privilege escalation flaw -- to achieve unauthenticated root-level command execution. Volexity discovered active exploitation by a previously unknown threat actor tracked as UTA0576, beginning October 3, 2026, against a fully patched ICS appliance running version 22.8R2.4. The attack is notable for its entirely in-memory operation: no web shell, backdoor, or persistent implant was deployed. The attacker re-exploited the full chain for each command, evaded Ivanti's Integrity Checker Tool, and selectively tampered with logs. Post-exploitation activity focused on credential theft from Active Directory, including LAPS passwords and BitLocker recovery keys, Kerberoasting, password spraying, and network traffic sniffing. CISA added CVE-2026-104935 to its Known Exploited Vulnerabilities (KEV) catalog on October 13, 2026, with a federal patching deadline of October 16, 2026. Ivanti has patched the authentication bypass and RCE components; the privilege escalation flaw remains unpatched, with a fix expected "in the coming weeks."

## Sources

| Source | Link |
|--------|------|
| Volexity Blog (Primary) | [A Series of Unauthenticated Events: Chained Exploitation of Ivanti Connect Secure Zero-Days](https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/) |
| Volexity GitHub IOCs | [volexity/threat-intel -- 2026-10-13 Ivanti](https://github.com/volexity/threat-intel/tree/main/2026/2026-10-13%20Ivanti) |
| CISA Alert | [CISA Urges Patching Newly Exploited Vulnerability in Ivanti Connect Secure](https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-urges-patching-newly-exploited-vulnerability-ivanti-connect-secure) |
| CISA KEV | [CISA Adds Two Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-adds-two-known-exploited-vulnerabilities-catalog) |
| The Hacker News | [Attacker Chains Three Ivanti Connect Secure Zero-Days](https://thehackernews.com/2026/10/attacker-chains-three-ivanti-connect.html) |
| CyberScoop | [Ivanti Connect Secure zero-day actively exploited](https://cyberscoop.com/ivanti-connect-secure-zero-day-actively-exploited/) |
| The Register | [Ivanti patches Connect Secure zero-day after researchers confirm in-the-wild attacks](https://www.theregister.com/security/2026/10/14/ivanti-patches-connect-secure-zero-day-after-researchers-confirm-in-the-wild-attacks/5303095) |
| Rapid7 | [Ivanti Connect Secure zero-day exploited in the wild (CVE-2026-104935)](https://www.rapid7.com/blog/post/etr-ivanti-connect-secure-zero-day-exploited-in-the-wild-cve-2026-104935/) |
| SOCRadar | [CVE-2026-104935 Ivanti Connect Secure](https://socradar.io/blog/cve-2026-104935-ivanti-connect-secure/) |
| eSentire | [Ivanti Connect Secure Zero-Day Vulnerability (CVE-2026-104935)](https://www.esentire.com/security-advisories/ivanti-connect-secure-zero-day-vulnerability-cve-2026-104935) |

## Affected Products and Versions

| Affected Version Branch | Fixed Version |
|-------------------------|---------------|
| 25.1.1.1 and prior | 25.1.1.2 |
| 25.1.2.2 and prior | 25.1.3.0 / 25.1.3.1 |
| 22.8R2.4 and prior | 22.8R2.5 |

- **Not affected:** 22.7.x and below
- **End of life:** 22.8 branch reaches end of life January 31, 2027
- **Patch coverage:** CVE-2026-104935 (auth bypass + RCE) is patched. The privilege escalation to root is **not yet patched** -- fix expected in coming weeks.
- **Note:** Ivanti identified a portion of this vulnerability through its product security program in June 2026 and shipped a partial fix in the July 2026 release of 25.1.3.0. Attackers exploited it before backporting to other supported branches was complete.

## Technical Analysis

### Exploit Chain Overview

The attack chains three zero-day vulnerabilities in sequence to escalate from unauthenticated external access to root-level command execution:

**Step 1 -- Authentication Bypass (welcome.cgi + X-DSCGI-PATH header)**

The attacker sends an HTTP request to the publicly accessible login path `/dana-na/auth/url_default/welcome.cgi` with a crafted `X-DSCGI-PATH` header pointing to a protected CGI script (e.g., `wu.cgi`). The front-end routing checks the URL path for access control but uses the header value for routing, allowing the request to reach an authenticated-only endpoint without credentials.

**Step 2 -- Remote Code Execution (file write race condition via wu.cgi)**

The attacker uploads a Perl script with a `.zip` extension to the `wu.cgi` upload handler. The handler writes the file to `/home/runtime/tmp/<MD5(filename)>` before validating it as a ZIP archive and deleting it. Concurrent requests using `X-DSCGI-PATH: /home/runtime/tmp/<MD5(filename)>` execute the file during the race window. This runs code as the `cgi-server` user.

**Step 3 -- Privilege Escalation (in-memory libdsplibs.so patching via DSCache/dsinvoked)**

The Perl payload launches a Bash script, which runs a Base64-encoded, zlib-compressed Python payload via `exec()` (entirely in memory). The Python payload:
1. Patches the in-memory copy of `/home/lib/libdsplibs.so` in the cgi-server process
2. Alters a DSCache maintenance task (`ScriptUtil/updateOpswatSDK`) to launch the Perl interpreter
3. Requests that the root-level `dsinvoked` service execute the modified task with a malicious Perl argument
4. Confirms root by testing readability of `/etc/shadow`
5. Restores DSCache, the library, and process memory via `/proc/self/mem` -- the on-disk library is never modified

### Key Operational Characteristics

- **No persistence:** No web shell, backdoor, or malware was deployed. The attacker re-ran the full exploit chain for each command.
- **In-memory only:** Library modifications exist only in process memory. On-disk binaries remain clean.
- **Integrity Checker evasion:** Ivanti's Integrity Checker Tool cannot detect this chain because the exploit operates in memory and restores all modified configuration data.
- **Command channel:** Each command's output returns directly in the HTTP response. No separate C2 channel was established.
- **LLM-assisted development (medium confidence):** Volexity assessed with medium confidence that UTA0576 used large language models, based on the sophistication of the exploit chain and the presence of "highly specific scripts using hardcoded credentials."

### Post-Exploitation Activity

| Activity | Detail |
|----------|--------|
| Credential extraction | LDAP domain credentials from appliance configuration |
| AD reconnaissance | LDAP searches for LAPS passwords (`ms-Mcs-AdmPwd`), BitLocker recovery keys (`ms-FVE-RecoveryPassword`), `unixUserPassword` attributes |
| Kerberoasting | `/tmp/mk.py` -- custom Python Kerberos implementation |
| Credential testing | `/tmp/rr.py` -- validates harvested credentials |
| Password spraying | `sp_run.py` producing `sp_out.txt` and `spray_hits.json` |
| Network sniffing | Renamed tcpdump (`dsstatmond`) in `/data/.icscap/` capturing LDAP, HTTP, FTP, telnet traffic |
| Credential parsing | `/data/.icscap/h.py` -- extracts plaintext LDAP, HTTP Basic, NTLM challenge-response material from captures |
| Username enumeration | Extracted from `log.events.vc0` authentication logs to `/tmp/pu.txt` |
| Configuration theft | `/home/etc/pulse/`, `/home/etc/`, `/home/*.cfg`, `/home/runtime`, `/etc/resolv.conf` |
| Log tampering | Selective truncation/rewriting of `/home/runtime/dlogs/debuglog` and `/var/log/audit/audit.log` |
| Anti-forensics | Self-deletion of payloads, temp files, CGI source; output redirection to `/dev/null`; restoration of DSCache and memory patches |

### MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Initial Access | T1190 -- Exploit Public-Facing Application | Authentication bypass via X-DSCGI-PATH header on welcome.cgi |
| Execution | T1059.004 -- Unix Shell | Bash stager in exploit chain |
| Execution | T1059.006 -- Python | In-memory Python payload for privilege escalation and post-exploitation tools |
| Privilege Escalation | T1068 -- Exploitation for Privilege Escalation | In-memory libdsplibs.so patching to gain root via dsinvoked |
| Defense Evasion | T1070.002 -- Indicator Removal: Clear Linux or Mac System Logs | Selective deletion/rewriting of debuglog and audit.log |
| Defense Evasion | T1036.005 -- Masquerading: Match Legitimate Name or Location | tcpdump renamed to dsstatmond |
| Credential Access | T1040 -- Network Sniffing | Traffic capture on plaintext protocol ports (LDAP 389, HTTP, FTP, telnet) |
| Credential Access | T1558.003 -- Steal or Forge Kerberos Tickets: Kerberoasting | Custom Python Kerberos implementation |
| Credential Access | T1110.003 -- Brute Force: Password Spraying | sp_run.py against AD accounts |
| Credential Access | T1552 -- Unsecured Credentials | LDAP extraction of LAPS passwords and BitLocker recovery keys |
| Discovery | T1087.002 -- Account Discovery: Domain Account | Username enumeration from authentication logs and AD queries |

### Timeline

| Date | Event |
|------|-------|
| June 2026 | Ivanti internally identifies a portion of the vulnerability |
| July 2026 | Partial fix shipped in 25.1.3.0 release |
| September 30, 2026 | OpenVPN server observed running on `108.165.147[.]64` |
| October 1, 2026 | Earliest confirmed exploitation (per CyberScoop/Volexity's Sean Koessel) |
| October 3, 2026 | Exploitation of observed victim appliance begins (per Volexity blog) |
| October 5, 2026 | Volexity investigation begins |
| October 13, 2026 | Volexity publishes report; Ivanti publishes advisory and patches; CISA adds to KEV |
| October 16, 2026 | CISA federal patching deadline |
| Coming weeks | Privilege escalation fix expected |

## Indicators of Compromise

### Viability Gate Assessment

**PASS (PoC/Advisory-Specific).** Volexity's primary report provides concrete artifacts: specific HTTP exploitation paths and headers, file system paths for post-exploitation tools, an attacker IP address, file hashes from the YARA rules, and detailed behavioral indicators. Volexity also published YARA rules and an IOC CSV on GitHub. The exploit chain mechanism is described at sufficient detail for detection rule creation.

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| IP Address | `108[.]165[.]147[.]64` | UTA0576 exploitation source IP (Evoxt VPS); ran OpenVPN server Sept 30 -- Oct 7, 2026 |

### HTTP Indicators

| Type | Value | Context |
|------|-------|---------|
| URI Path | `/dana-na/auth/url_default/welcome.cgi` | Exploit entry point; high-volume requests indicate chain replay |
| HTTP Header | `X-DSCGI-PATH: /home/webserver/htdocs/dana/fb/smb/wu.cgi` | Routes unauthenticated request to upload handler |
| HTTP Header | `X-DSCGI-PATH: /home/runtime/tmp/<MD5(filename)>` | Executes uploaded Perl payload during race window |

### File System Indicators

| Type | Path | Context |
|------|------|---------|
| Upload staging | `/home/runtime/tmp/<MD5(filename)>` | Perl payload written by wu.cgi before deletion |
| Root payload | `/home/runtime/tmp/ics-root-run-inband-*.pl` | Self-deleting root execution payload |
| Root results | `/home/runtime/tmp/ics-root-result-inband-*` | Command results, deleted during cleanup |
| LDAP tool | `/tmp/ml.py` | LDAPv3 query tool |
| AD recon tool | `/tmp/rq5.py` | LAPS, BitLocker, password attribute extraction |
| Kerberos tool | `/tmp/mk.py` | Python Kerberoasting implementation |
| Credential tester | `/tmp/rr.py` | Credential validation script |
| Username list | `/tmp/pu.txt` | Usernames extracted from authentication logs |
| Spray output | `/tmp/sp_out.txt` | Password spray results |
| Spray hits | `spray_hits.json` | Successful spray credentials |
| Spray helper | `sp_run.py` | Password spray execution script |
| Renamed tcpdump | `/data/.icscap/dsstatmond` | Masquerading traffic capture binary |
| Capture files | `/data/.icscap/cap0` through `/data/.icscap/cap*` | Eight rotating pcap files |
| Credential parser | `/data/.icscap/h.py` | Extracts plaintext creds from captures |
| Modified library | `/home/lib/libdsplibs.so` | Patched in memory only; on-disk copy unchanged |
| Tampered logs | `/home/runtime/dlogs/debuglog` | Selectively truncated/rewritten |
| Tampered logs | `/var/log/audit/audit.log` | Selectively truncated/rewritten |

### File Hashes

| Type | Hash | Context |
|------|------|---------|
| SHA-256 | `25b95f47359c327e3a5ae5ac5cd147f8d9afd98092faf136822ee287e25e3dc8` | UTA0576 Python privilege escalation exploit (from Volexity YARA rule) |

### Process Indicators

| Indicator | Context |
|-----------|---------|
| `dsstatmond` process running from `/data/.icscap/` | Renamed tcpdump for traffic capture (observed as PID 5012) |
| Python interpreter at `/home/venv3/bin/python3.6` | Used to run `/data/.icscap/h.py` credential parser |

---

## Detection Rules

### Sigma Rules

#### 1. Ivanti Connect Secure Authentication Bypass via X-DSCGI-PATH Header Mismatch (CVE-2026-104935)

Detects HTTP requests to the Ivanti Connect Secure welcome.cgi endpoint with header values referencing the wu.cgi upload handler or temporary file paths, the primary exploitation vector. Requires web server access logs with header field logging (the `X-DSCGI-PATH` header may be logged in a referer or custom header field depending on the web log configuration).
<!-- audit: sigma convert -t splunk: PASS | sigma convert -t log_scale: PASS. sigma check: could not complete ATT&CK tag validation due to network restrictions. -->
**Status:** compile pass · confidence: high

```yaml
title: Ivanti Connect Secure Authentication Bypass via X-DSCGI-PATH Header Mismatch (CVE-2026-104935)
id: 7f3a2c91-e8d4-4b5a-9c1f-6d2e8a4f7b3d
status: experimental
description: >
    Detects HTTP requests to the Ivanti Connect Secure welcome.cgi endpoint
    with an X-DSCGI-PATH header referencing the wu.cgi upload handler, which
    is the primary exploitation vector for CVE-2026-104935. The header routes
    the unauthenticated request to a protected CGI script, bypassing
    authentication.
references:
    - https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
    - https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-urges-patching-newly-exploited-vulnerability-ivanti-connect-secure
author: Actioner
date: 2026/10/16
tags:
    - attack.t1190
    - cve.2026-104935
logsource:
    category: webserver
detection:
    selection_uri:
        cs-uri-stem|contains: '/dana-na/auth/url_default/welcome.cgi'
    selection_header:
        cs-referer|contains:
            - 'wu.cgi'
            - '/home/runtime/tmp/'
            - '/home/webserver/htdocs/dana/fb/smb/wu.cgi'
    condition: selection_uri and selection_header
falsepositives:
    - Authorized penetration testing against Ivanti Connect Secure appliances
level: critical
```

---

#### 2. Ivanti Connect Secure welcome.cgi Request from Known UTA0576 IP (CVE-2026-104935)

Detects requests to the Ivanti Connect Secure welcome.cgi endpoint from the known UTA0576 exploitation source IP address. This is a high-fidelity, IOC-specific detection.
<!-- audit: sigma convert -t splunk: PASS | sigma convert -t log_scale: PASS. sigma check: could not complete ATT&CK tag validation due to network restrictions. -->
**Status:** compile pass · confidence: high

```yaml
title: Ivanti Connect Secure welcome.cgi Request from Known UTA0576 IP (CVE-2026-104935)
id: 4e8b1d73-c9f2-4a06-b5d3-2f7e0c3a9d51
status: experimental
description: >
    Detects requests to the Ivanti Connect Secure welcome.cgi endpoint
    from the known UTA0576 exploitation source IP address 108.165.147.64
    (Evoxt VPS). This is a high-fidelity IOC-only detection that will
    expire when the attacker rotates infrastructure.
references:
    - https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
    - https://thehackernews.com/2026/10/attacker-chains-three-ivanti-connect.html
author: Actioner
date: 2026/10/16
tags:
    - attack.t1190
    - cve.2026-104935
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/dana-na/auth/url_default/welcome.cgi'
        src_ip: '108.165.147.64'
    condition: selection
falsepositives:
    - Legitimate traffic from the listed IP after infrastructure turnover
level: critical
```

---

#### 3. Ivanti Connect Secure Hidden .icscap Directory or dsstatmond Process (CVE-2026-104935)

Detects creation of or access to the hidden `.icscap` directory or the `dsstatmond` process (renamed tcpdump) used by UTA0576 for traffic capture. Requires process-level telemetry (auditd or EDR) on the ICS appliance.
<!-- audit: sigma convert -t splunk: PASS | sigma convert -t log_scale: PASS. sigma check: could not complete ATT&CK tag validation due to network restrictions. -->
**Status:** compile pass · confidence: high

```yaml
title: Ivanti Connect Secure Hidden .icscap Directory or dsstatmond Process (CVE-2026-104935)
id: 9d2c4f85-b7e1-4a39-8c6d-5e3f1b2a0d74
status: experimental
description: >
    Detects creation of or access to the hidden .icscap directory or the
    dsstatmond process used by UTA0576 for traffic capture on compromised
    Ivanti Connect Secure appliances. The attacker renamed tcpdump to
    dsstatmond in /data/.icscap/ to capture plaintext credentials.
references:
    - https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
author: Actioner
date: 2026/10/16
tags:
    - attack.t1040
    - attack.t1036.005
    - cve.2026-104935
logsource:
    category: process_creation
    product: linux
detection:
    selection_process:
        Image|endswith: '/dsstatmond'
    selection_path:
        CommandLine|contains:
            - '.icscap'
            - '/data/.icscap/'
    condition: selection_process or selection_path
falsepositives:
    - Legitimate Ivanti diagnostic processes using similar naming (unlikely)
level: critical
```

---

#### 4. Ivanti Connect Secure Post-Exploitation Credential Theft Tools (CVE-2026-104935)

Detects execution of the specific Python scripts deployed by UTA0576 for LDAP reconnaissance, Kerberoasting, credential testing, and password spraying on compromised ICS appliances. Requires process-level telemetry on the appliance.
<!-- audit: sigma convert -t splunk: PASS | sigma convert -t log_scale: PASS. sigma check: could not complete ATT&CK tag validation due to network restrictions. -->
**Status:** compile pass · confidence: high

```yaml
title: Ivanti Connect Secure Post-Exploitation Credential Theft Tools (CVE-2026-104935)
id: 1a6e3b98-d4c7-4f52-a8d1-7c9f0e5b2a63
status: experimental
description: >
    Detects execution of Python scripts associated with UTA0576
    post-exploitation on Ivanti Connect Secure. The attacker deployed
    credential theft, Kerberoasting, LDAP reconnaissance, and password
    spraying tools in /tmp/ on the compromised appliance.
references:
    - https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
author: Actioner
date: 2026/10/16
tags:
    - attack.t1059.006
    - attack.t1558.003
    - attack.t1110.003
    - cve.2026-104935
logsource:
    category: process_creation
    product: linux
detection:
    selection_interpreter:
        Image|endswith:
            - '/python'
            - '/python3'
            - '/python3.6'
    selection_scripts:
        CommandLine|contains:
            - '/tmp/ml.py'
            - '/tmp/rq5.py'
            - '/tmp/mk.py'
            - '/tmp/rr.py'
            - 'sp_run.py'
            - '/data/.icscap/h.py'
    condition: selection_interpreter and selection_scripts
falsepositives:
    - Custom administrative Python scripts on the appliance using matching filenames
level: critical
```

---

#### 5. Ivanti Connect Secure Log Tampering Post-Exploitation (CVE-2026-104935)

Detects attempts to tamper with or delete Ivanti Connect Secure debug and audit logs. UTA0576 selectively truncated and rewrote entries in debuglog and audit.log. Requires process-level telemetry on the appliance.
<!-- audit: sigma convert -t splunk: PASS | sigma convert -t log_scale: PASS. sigma check: could not complete ATT&CK tag validation due to network restrictions. -->
**Status:** compile pass · confidence: medium

```yaml
title: Ivanti Connect Secure Log Tampering Post-Exploitation (CVE-2026-104935)
id: 3b5d7e29-a1c8-4f63-b9d4-8e2f0c6a1b75
status: experimental
description: >
    Detects attempts to tamper with or delete Ivanti Connect Secure debug
    and audit logs. UTA0576 selectively truncated and rewrote debuglog and
    audit.log entries to cover exploitation tracks.
references:
    - https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
author: Actioner
date: 2026/10/16
tags:
    - attack.t1070.002
    - cve.2026-104935
logsource:
    category: process_creation
    product: linux
detection:
    selection_logs:
        CommandLine|contains:
            - '/home/runtime/dlogs/debuglog'
            - '/var/log/audit/audit.log'
    selection_action:
        CommandLine|contains:
            - 'rm '
            - 'truncate '
            - 'shred '
            - '> /dev/null'
            - 'echo "" >'
            - 'sed -i'
    condition: selection_logs and selection_action
falsepositives:
    - Legitimate log rotation by Ivanti system maintenance processes
level: high
```

---

### Snort Rules

Detects requests to the Ivanti Connect Secure welcome.cgi endpoint with `X-DSCGI-PATH` header values referencing the wu.cgi upload handler, the primary CVE-2026-104935 exploitation vector. The rule operates on HTTP traffic; for HTTPS-protected appliance endpoints, TLS inspection is required upstream.
<!-- audit: rule syntax validated against Snort 2.x format. -->

**Status:** compile pass · confidence: high

```
alert tcp any any -> any $HTTP_PORTS (msg:"EXPLOIT Ivanti Connect Secure CVE-2026-104935 Auth Bypass - X-DSCGI-PATH to wu.cgi"; flow:to_server,established; content:"/dana-na/auth/url_default/welcome.cgi"; http_uri; content:"X-DSCGI-PATH"; http_header; content:"wu.cgi"; http_header; reference:cve,2026-104935; reference:url,www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/; classtype:web-application-attack; sid:2026104901; rev:1; priority:1;)
```

```
alert tcp any any -> any $HTTP_PORTS (msg:"EXPLOIT Ivanti Connect Secure CVE-2026-104935 Auth Bypass - X-DSCGI-PATH to runtime tmp"; flow:to_server,established; content:"/dana-na/auth/url_default/welcome.cgi"; http_uri; content:"X-DSCGI-PATH"; http_header; content:"/home/runtime/tmp/"; http_header; reference:cve,2026-104935; reference:url,www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/; classtype:web-application-attack; sid:2026104902; rev:1; priority:1;)
```

> **Prerequisite:** If the Ivanti ICS appliance serves over HTTPS (standard configuration), TLS inspection/decryption must be positioned upstream to expose HTTP content to Snort. Scope `any any -> any $HTTP_PORTS` to `any any -> $ICS_VPN_NET $HTTP_PORTS` in production.

---

### Suricata Rules

Equivalent detection using Suricata's HTTP-aware keywords. Requires TLS inspection for HTTPS traffic.
<!-- audit: rule syntax validated against Suricata 7.x format. -->

**Status:** compile pass · confidence: high

```
alert http any any -> any any (msg:"EXPLOIT Ivanti Connect Secure CVE-2026-104935 Auth Bypass - X-DSCGI-PATH to wu.cgi"; flow:to_server,established; http.uri; content:"/dana-na/auth/url_default/welcome.cgi"; http.header; content:"X-DSCGI-PATH"; content:"wu.cgi"; reference:cve,2026-104935; reference:url,www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/; classtype:web-application-attack; sid:2026105001; rev:1;)
```

```
alert http any any -> any any (msg:"EXPLOIT Ivanti Connect Secure CVE-2026-104935 Auth Bypass - X-DSCGI-PATH to runtime tmp"; flow:to_server,established; http.uri; content:"/dana-na/auth/url_default/welcome.cgi"; http.header; content:"X-DSCGI-PATH"; content:"/home/runtime/tmp/"; reference:cve,2026-104935; reference:url,www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/; classtype:web-application-attack; sid:2026105002; rev:1;)
```

> **Prerequisite:** TLS inspection required for HTTPS-served ICS endpoints. Scope destination to ICS VPN appliance addresses in production.

---

### YARA Rules

#### Rules 1-2: Volexity Official YARA Rules (from [volexity/threat-intel](https://github.com/volexity/threat-intel/tree/main/2026/2026-10-13%20Ivanti))

These rules are authored by Volexity and published under their threat-intel repository license. They detect the exploit chain's HTTP header pattern and the in-memory Python privilege escalation payload. **Deployment note:** `exploit_log_ivanti_rce` matches a single HTTP header string and may fire on cached threat intelligence reports, blog mirrors, or SIEM log archives that contain the indicator verbatim. Scope file-scan deployments to appliance images and forensic artifacts, not analyst workstations or document stores.
<!-- audit: yarac /tmp/actioner/ivanti-cve-2026-104935.yar /dev/null: PASS (exit 0). -->

**Status:** compile pass · confidence: high (Volexity-authored, based on observed samples)

```yara
rule exploit_log_ivanti_rce: CVE_2026_104935
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-10-12"
    description = "Identifies files or memory regions containing request headers matching RCE vulnerability for Ivanti."
    os = "linux"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20261012"
    last_modified = "2026-10-12T19:35:53Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13503
    version = 1

  strings:
    $s1 = "X-DSCGI-PATH: /home/webserver/htdocs/dana/fb/smb/wu.cgi" ascii

  condition:
    $s1
}

rule exploit_py_ivanti_oct26: CVE_2026_104935 UTA0576
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-10-10"
    description = "Detection for EoP vuln implementation in Python used by UTA0576."
    hash1 = "25b95f47359c327e3a5ae5ac5cd147f8d9afd98092faf136822ee287e25e3dc8"
    os = "linux"
    os_arch = "all"
    scan_context = "memory"
    severity = "critical"
    report1 = "TIB-20261012"
    last_modified = "2026-10-12T19:36:10Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13500
    version = 3

  strings:
    $magic1 = "target dsinvoked broker is busy; stop retries and clear its current child" ascii
    $magic2 = "PATCH_LOCATOR arch=%s offset=%s sha256=%s encoding=%s open=%s call=%s evidence=%s"

    $pycombo1 = "import os,socket,time,_frozen_importlib_external as ie"
    $pycombo2 = "def say(*x): print(*x,flush=True)"

  condition:
    any of ($magic*) or
    all of ($pycombo*)
}
```

#### Rule 3: UTA0576 Post-Exploitation Credential Tools (Actioner)

Detects the post-exploitation Python tooling deployed by UTA0576 on compromised ICS appliances, targeting LAPS passwords, BitLocker recovery keys, Kerberoasting, and credential spray infrastructure.
<!-- audit: yarac /tmp/actioner/ivanti-cve-2026-104935.yar /dev/null: PASS (exit 0). -->

**Status:** compile pass · confidence: medium

```yara
rule apt_py_uta0576_credential_tools: CVE_2026_104935 UTA0576
{
  meta:
    author = "Actioner"
    date = "2026-10-16"
    description = "Detects UTA0576 post-exploitation Python scripts for LDAP reconnaissance, Kerberoasting, and credential harvesting on Ivanti Connect Secure."
    reference = "https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/"
    severity = "critical"

  strings:
    $icscap_dir = "/data/.icscap/" ascii
    $dsstatmond = "dsstatmond" ascii

    $ldap_tool1 = "ms-Mcs-AdmPwd" ascii wide
    $ldap_tool2 = "ms-FVE-RecoveryPassword" ascii wide
    $ldap_tool3 = "unixUserPassword" ascii wide

    $kerb1 = "Kerberoast" ascii nocase
    $spray1 = "spray_hits" ascii
    $spray2 = "sp_out.txt" ascii

  condition:
    (2 of ($ldap_tool*) and ($icscap_dir or $dsstatmond)) or
    ($icscap_dir and $dsstatmond) or
    ($kerb1 and ($spray1 or $spray2))
}
```

---

## Recommended Immediate Actions

1. **Patch immediately** to 25.1.1.2, 25.1.3.0/25.1.3.1, or 22.8R2.5 depending on branch. The CISA federal deadline is October 16, 2026.
2. **Hunt for compromise indicators** even after patching -- Ivanti's Integrity Checker Tool will **not** detect this chain. Conduct memory and network forensics per Volexity's guidance.
3. **Check for the `.icscap` directory** under `/data/` and the `dsstatmond` process. Check `/tmp/` for unexpected Python scripts (`ml.py`, `rq5.py`, `mk.py`, `rr.py`, `h.py`, `sp_run.py`).
4. **Review web logs** for high-volume `welcome.cgi` requests and any request where the `X-DSCGI-PATH` header does not match the URL path.
5. **Rotate all credentials** stored on or accessible through the appliance, including LDAP service credentials, domain administrator passwords, LAPS passwords, and BitLocker recovery keys.
6. **If compromise is confirmed**, follow CISA's recovery guidance: back up configuration, factory reset, upgrade, restore configuration, then reset all passwords, revoke/reissue certificates, and reset stored API keys.
7. **Monitor for lateral movement** targeting Active Directory -- the attacker's observed objective was credential harvesting to enable broader network access.
8. **Deploy detection rules** from this report into SIEM, network monitoring, and endpoint telemetry infrastructure.

## Limitations and Caveats

- The `sigma check` validator could not complete MITRE ATT&CK tag validation due to network restrictions in the validation environment (HTTP 403 on MITRE ATT&CK data source). All five Sigma rules were validated via successful Splunk SPL and LogScale conversion.
- The `X-DSCGI-PATH` header is a non-standard HTTP header that most web log configurations do not log by default. The Sigma rules that detect it via `cs-referer` require custom log field mapping to capture this header value. Organizations should configure their ICS web access logs or reverse proxy to log this header explicitly.
- Snort/Suricata rules require TLS inspection upstream of the ICS appliance to see HTTP content in HTTPS sessions, which is the standard ICS configuration.
- The privilege escalation vulnerability has no CVE and no patch. Even after upgrading, the third chain link remains exploitable if an attacker finds another path to code execution as the cgi-server user.
- IOCs are limited: only one IP address is published, no web shells or persistent implants exist, and the exploit is entirely in-memory. Detection depends on behavioral indicators and log forensics rather than traditional IOC matching.
- Volexity's assessment of LLM-assisted exploit development is at medium confidence and should not be used for attribution.

---

*FINAL report generated 2026-10-16. Revision: (1) Sigma #2 title/description aligned to IOC-only logic; (2) Sigma #4 corrected /tmp/h.py to /data/.icscap/h.py per IOC table; (3) YARA #3 ldap_tool branch anchored to ICS-appliance co-conditions to reduce false positives; (4) T1552.004 replaced with T1552 for LAPS/BitLocker credential extraction; (5) Suricata SIDs offset to 2026105001-2 to avoid Snort SID overlap; (6) YARA #1 deployment guidance added for cached-report false positives. Primary detection relies on HTTP header mismatch indicators, behavioral process monitoring, and file system artifact hunting. Promote through your organization's detection engineering workflow before production deployment.*
