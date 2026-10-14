# Technical Analysis Report: Ivanti Connect Secure Zero-Day Chain — CVE-2026-104935 / UTA0576 (2026-10-14)

Prepared by: Actioner
Classification: DRAFT
Date: 2026-10-14
Version: 0.1

## Executive Summary

On October 13, 2026, Volexity disclosed active exploitation of a zero-day exploit chain targeting fully patched Ivanti Connect Secure (ICS) VPN appliances. The threat actor UTA0576 chained three vulnerabilities — an authentication bypass, a file-write/RCE flaw (tracked together as CVE-2026-104935, CVSS 8.6), and an unpatched privilege escalation — to achieve unauthenticated root-level code execution. CISA added CVE-2026-104935 to the Known Exploited Vulnerabilities catalog on October 13, 2026, with federal agencies required to remediate within 72 hours.

The attack was first observed on October 3, 2026, against a single customer running the then-latest ICS version 22.8R2.4. UTA0576 deployed no web shells or backdoors, instead re-exploiting the full chain for each command and exfiltrating credentials (LDAP service accounts, LAPS passwords, BitLocker recovery keys) via the exploit channel itself. Multiple anti-forensics measures were employed, including in-memory-only modifications and log tampering, rendering the Ivanti Integrity Checker Tool insufficient for detecting compromise. Patches for CVE-2026-104935 were released October 13; the privilege escalation fix remains pending.

## Background: Ivanti Connect Secure VPN

Ivanti Connect Secure (formerly Pulse Connect Secure) is one of the most widely deployed enterprise SSL VPN appliances, providing remote access to corporate networks. It runs a custom Linux-based OS with a web-based management and authentication interface served by CGI handlers. ICS appliances sit on the network perimeter and handle authentication for remote users, making them high-value targets — compromise provides direct access to internal networks and stored credentials. Ivanti ICS has been the target of multiple zero-day campaigns since 2024, including exploitation by UNC5221 (CVE-2023-46805/CVE-2024-21887) and CVE-2025-22457.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-30 | UTA0576 infrastructure at 108.165.147[.]64 begins running OpenVPN server |
| 2026-10-03 | First observed exploitation of the zero-day chain against a fully patched ICS 22.8R2.4 appliance |
| 2026-10-03 – 2026-10-07 | Active post-exploitation: credential theft, AD enumeration, LAPS/BitLocker harvesting, packet capture, password spraying |
| 2026-10-07 | UTA0576 infrastructure at 108.165.147[.]64 ceases OpenVPN operation |
| 2026-10-13 | Volexity publishes full technical analysis; Ivanti releases patches for CVE-2026-104935 |
| 2026-10-13 | CISA adds CVE-2026-104935 to the KEV catalog |
| 2026-10-14 | Privilege escalation component remains unpatched; fix expected "in the coming weeks" |

## Root Cause: Authentication Bypass via CGI Routing Mismatch (CVE-2026-104935)

The root cause is a discrepancy between URL-based authorization checks and request routing in the ICS web server. The public endpoint `/dana-na/auth/url_default/welcome.cgi` is accessible without authentication, but the web server uses the `X-DSCGI-PATH` HTTP header to determine which CGI handler actually processes the request. An attacker can set this header to point to a protected handler (such as `wu.cgi`, the file upload handler), causing the server to check authorization against the URL path (which passes) while routing execution to the protected handler (which should not be accessible). This mismatch enables unauthenticated access to any CGI handler on the appliance.

## Technical Analysis of the Malicious Payload

### 1. Authentication Bypass and File Upload (CVE-2026-104935)

The first stage sends an HTTP POST to `/dana-na/auth/url_default/welcome.cgi` with the `X-DSCGI-PATH` header set to `/home/webserver/htdocs/dana/fb/smb/wu.cgi`. The URL path passes the authorization check (welcome.cgi is public), but the request is routed to wu.cgi, the file upload handler. The attacker uploads a Perl script disguised with a `.zip` extension. The upload handler writes the file to disk at a path derived from the MD5 hash of the client-supplied filename before validating it as a ZIP archive.

### 2. Race Condition Code Execution

Before the upload handler can validate and delete the uploaded file, the attacker sends parallel requests using `X-DSCGI-PATH` pointing to the temporary upload path (e.g., `/home/runtime/tmp/<MD5-of-filename>`). This race condition allows the uploaded Perl script to execute as the `cgi-server` user. The Perl script launches a Bash script, which in turn executes a Python stage delivered as Base64-encoded, zlib-compressed code via `exec()` — running entirely in memory.

### 3. Privilege Escalation via DSCache/dsinvoked Trust Abuse

The Python stage exploits a trust relationship between the `cgi-server` process and the privileged `dsinvoked` service. The `dsinvoked` service reads the DSCache configuration to determine which program runs for each maintenance task. The exploit patches the in-memory copy of `libdsplibs.so` in the cgi-server process (via `/proc/self/mem`) to modify a DSCache task entry, replacing the legitimate handler (`/home/bin/updateOpswatSDK.pl`) with a path to the attacker's Perl payload. When the task is triggered via `dsinvoked`, the payload executes as root. Success is verified by checking readability of `/etc/shadow`. After execution, the DSCache entry and in-memory library modifications are restored.

### 4. Post-Exploitation Activity

UTA0576 conducted extensive credential theft and reconnaissance, all channeled through the exploit mechanism itself (no web shell, no backdoor):

- **Credential extraction**: Harvested stored LDAP service account credentials and authentication configuration directly from the appliance.
- **Active Directory enumeration**: Deployed a custom Python LDAPv3 tool (`/tmp/ml.py`) and query script (`/tmp/rq5.py`) to harvest LAPS passwords, BitLocker recovery keys, `userPassword`/`unixUserPassword` attributes, and logon script paths.
- **Kerberoasting**: Used a Python Kerberos implementation (`/tmp/mk.py`) with Kerberoast functionality; validated credentials with `/tmp/rr.py`.
- **Packet capture**: Deployed a renamed `tcpdump` binary (`/data/.icscap/dsstatmond`) to capture network traffic in rotating captures (`/data/.icscap/cap*`). A parser (`/data/.icscap/h.py`, executed with `/home/venv3/bin/python3.6`) extracted plaintext LDAP credentials, HTTP Basic authentication, and NTLM challenge-response material from the captures.
- **Log reconnaissance**: Parsed `log.events.vc0` for usernames, output to `/tmp/pu.txt`.
- **Password spraying**: Ran spraying via `sp_run.py`, producing `/tmp/sp_out.txt` and `/tmp/spray_hits.json`.
- **Exfiltration**: All results were JSON and zlib/Base64 encoded, sent back via the exploit channel's HTTP response.

### 5. Anti-Forensics / Evasion Techniques

UTA0576 employed multiple anti-forensics measures specifically designed to evade the Ivanti Integrity Checker Tool (ICT):

- **In-memory-only modifications**: All library patches to `libdsplibs.so` were performed via `/proc/self/mem`, leaving no on-disk changes for ICT to detect.
- **Configuration restoration**: DSCache entries were restored to their original values after each execution.
- **Log tampering**: Selective filtering and rewriting of entries in `/home/runtime/dlogs/debuglog` and `/var/log/audit/audit.log`.
- **File deletion**: Self-deletion of root payloads (`/home/runtime/tmp/ics-root-run-inband-*.pl`), result files (`/home/runtime/tmp/ics-root-result-inband-*`), and post-exploitation tools (`/tmp/rq5.py`, `/tmp/rr.py`).
- **Capture rotation**: Eight rotating capture files overwrote earlier traffic evidence.
- **No persistent implants**: No web shells, backdoors, or scheduled tasks were deployed — the full exploit chain was re-run for every command.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `108.165.147[.]64`)
> - URLs: `hxxps://` or `hxxp://`

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| ICS (Linux) | /tmp/ml.py | N/A | Custom Python LDAPv3 tool for AD enumeration |
| ICS (Linux) | /tmp/rq5.py | N/A | LDAP query script for LAPS/BitLocker harvesting |
| ICS (Linux) | /tmp/mk.py | N/A | Python Kerberos implementation with Kerberoast capability |
| ICS (Linux) | /tmp/rr.py | N/A | Credential validation test script |
| ICS (Linux) | /tmp/sp_run.py | N/A | Password spraying script |
| ICS (Linux) | /tmp/sp_out.txt | N/A | Password spraying output |
| ICS (Linux) | /tmp/spray_hits.json | N/A | Successful spray results in JSON |
| ICS (Linux) | /tmp/pu.txt | N/A | Extracted usernames from log parsing |
| ICS (Linux) | /data/.icscap/h.py | N/A | Packet capture parser for credential extraction |
| ICS (Linux) | /data/.icscap/dsstatmond | N/A | Renamed tcpdump binary for covert packet capture |
| ICS (Linux) | /data/.icscap/cap* | N/A | Rotating packet capture files |
| ICS (Linux) | /home/runtime/tmp/ics-root-run-inband-*.pl | N/A | Root-level Perl payload (self-deleting) |
| ICS (Linux) | /home/runtime/tmp/ics-root-result-inband-* | N/A | Exploit execution result files (self-deleting) |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 108.165.147[.]64 | UTA0576 infrastructure — Evoxt VPS running OpenVPN (Sep 30 – Oct 7, 2026) |
| URL Pattern | /dana-na/auth/url_default/welcome.cgi | Exploit entry point (anomalous POST volume) |
| HTTP Header | X-DSCGI-PATH: /home/webserver/htdocs/dana/fb/smb/wu.cgi | Exploit routing header targeting file upload handler |
| HTTP Header | X-DSCGI-PATH: /home/runtime/tmp/\<MD5\> | Exploit routing header targeting uploaded payload |

### Behavioral

- **POST requests to welcome.cgi**: This endpoint is normally accessed via GET for authentication. POST requests, especially with the `X-DSCGI-PATH` header, indicate exploitation.
- **X-DSCGI-PATH header mismatch**: Any request where the URL path and `X-DSCGI-PATH` header target different CGI handlers is anomalous.
- **Unexpected files in /tmp/**: Presence of `.py` scripts, `.json` files, or `.txt` output files not associated with normal ICS operations.
- **Hidden directory /data/.icscap/**: This directory and any files within it (particularly renamed binaries and capture files) are not part of standard ICS operation.
- **Packet capture processes**: Renamed tcpdump (`dsstatmond`) running from `/data/.icscap/` on the VPN appliance.
- **Modified log entries**: Gaps or inconsistencies in `/home/runtime/dlogs/debuglog` and `/var/log/audit/audit.log`.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of welcome.cgi authentication bypass to reach protected CGI handlers |
| T1068 | Exploitation for Privilege Escalation | DSCache/dsinvoked trust abuse to escalate from cgi-server to root |
| T1059 | Command and Scripting Interpreter | Perl, Bash, and Python scripts used throughout the exploit chain |
| T1040 | Network Sniffing | Renamed tcpdump (dsstatmond) capturing network traffic for credential extraction |
| T1552 | Unsecured Credentials | Extraction of stored LDAP service account credentials from the appliance |
| T1558.003 | Kerberoasting | Custom Python Kerberos tool used for Kerberoast attacks against AD |
| T1110.003 | Password Spraying | Automated password spraying via sp_run.py against enumerated accounts |
| T1087 | Account Discovery | LDAP enumeration of AD accounts, LAPS passwords, and BitLocker keys |
| T1070.001 | Clear Linux or Mac System Logs | Selective filtering and rewriting of debuglog and audit.log entries |
| T1070.004 | File Deletion | Self-deletion of payloads, scripts, and result files after execution |
| T1620 | Reflective Code Loading | In-memory patching of libdsplibs.so via /proc/self/mem; Python exec() of zlib-compressed code |

## Impact Assessment

- **Breadth**: Ivanti Connect Secure is deployed across thousands of enterprises and government agencies globally. Affected versions include builds prior to 25.1.3.0 and 22.8R2.4 and earlier. The number of compromised appliances is unknown — Volexity disclosed exploitation of a single customer, but broader scanning is likely given the window between first exploitation (October 3) and patch release (October 13).
- **Depth**: The chain provides unauthenticated root access to the appliance, enabling full credential theft (LDAP, LAPS, BitLocker, Kerberos), packet capture of all VPN traffic, and a pivot point into the internal network. Stolen credentials may enable domain-wide compromise.
- **Stealth**: The attack specifically evades the Ivanti Integrity Checker Tool through in-memory-only modifications and configuration restoration. No persistent implants are left, making post-incident detection extremely difficult without network and memory forensics.
- **Residual risk**: The privilege escalation vulnerability remains unpatched. While patching CVE-2026-104935 blocks the current exploit chain, the escalation flaw may be independently exploitable in combination with other vectors.

## Detection & Remediation

### Immediate Detection

1. **Search web/proxy logs** for POST requests to `/dana-na/auth/url_default/welcome.cgi` — this endpoint should only receive GET requests during normal authentication flows.
2. **Search for the X-DSCGI-PATH header** in web server logs, IDS/IPS logs, or packet captures. This header with a value targeting `wu.cgi` or a `/home/runtime/tmp/` path is a definitive indicator.
3. **Check for the attacker directory**: `ls -la /data/.icscap/` on ICS appliances. Any content is anomalous.
4. **Check for post-exploitation artifacts**: `ls -la /tmp/ml.py /tmp/rq5.py /tmp/mk.py /tmp/rr.py /tmp/sp_run.py /tmp/pu.txt /tmp/sp_out.txt /tmp/spray_hits.json 2>/dev/null`
5. **Check for connections to** 108.165.147[.]64 in firewall/VPN logs (active September 30 – October 7, 2026).
6. **Do NOT rely solely on the Ivanti Integrity Checker Tool** — it does not detect this attack chain.

### Remediation

1. **Patch immediately**: Apply ICS builds 22.8R2.5, 25.1.1.2, 25.1.3.0, or 25.1.3.1 depending on your version track.
2. **Assume compromise if unpatched**: If the appliance was running an affected version between October 3 and patch application, conduct full forensic analysis.
3. **Rotate credentials**: Reset all LDAP service account passwords stored on the appliance. Rotate LAPS passwords and BitLocker recovery keys. Invalidate active VPN sessions.
4. **Review Active Directory**: Check for unauthorized access, Kerberoast activity, and password spray attempts originating from the VPN appliance's IP.
5. **Network forensics**: Capture and review traffic from VPN appliances for evidence of data exfiltration.
6. **Memory forensics**: If compromise is suspected, capture memory from the appliance before rebooting, as in-memory modifications are lost on reboot.

### Long-Term Hardening

- Implement network segmentation to limit VPN appliance access to backend services (especially LDAP/AD).
- Deploy network-level detection for anomalous HTTP headers on VPN appliance traffic.
- Monitor for the pending privilege escalation patch and apply immediately upon release.
- Consider deploying third-party integrity monitoring that inspects process memory, not just filesystem state.
- Restrict and monitor outbound connections from VPN appliances.

## Detection Rules

These detections target the CVE-2026-104935 exploit chain against Ivanti Connect Secure, keying on the authentication bypass POST to welcome.cgi, the X-DSCGI-PATH exploit header, and known UTA0576 infrastructure. PoC/advisory-specific (default altitude). Compiles does not equal fires — verify each rule against your log pipeline's field mappings.

### Sigma: Ivanti ICS CVE-2026-104935 - Anomalous POST to welcome.cgi
Detects HTTP POST requests to the Ivanti Connect Secure welcome.cgi authentication endpoint, which is characteristic of CVE-2026-104935 exploitation using the X-DSCGI-PATH header routing bypass.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to proxy blocking MITRE ATT&CK data fetch (RuntimeError: HTTP 403), not a rule defect. sigma convert --without-pipeline splunk exit 0; log_scale exit 0. No pipeline-mapped conversion (no webserver pipeline available). Fields cs-uri-stem / cs-method are standard W3C extended log format fields. Values are real (not defanged). -->
```yaml
title: Ivanti Connect Secure CVE-2026-104935 - Anomalous POST to welcome.cgi
id: 7f3a8b2e-1c4d-4e9f-b6a5-d8e2f0c3a1b7
status: experimental
description: >
    Detects HTTP POST requests to the Ivanti Connect Secure welcome.cgi endpoint,
    which is normally accessed via GET for authentication. POST requests to this
    endpoint are characteristic of CVE-2026-104935 exploitation, where an attacker
    uses the X-DSCGI-PATH header to route requests to protected CGI handlers like
    wu.cgi for file upload and code execution.
references:
    - https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
    - https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-adds-two-known-exploited-vulnerabilities-catalog
author: Actioner
date: 2026-10-14
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/dana-na/auth/url_default/welcome.cgi'
        cs-method: 'POST'
    condition: selection
falsepositives:
    - Custom integrations that POST to the Ivanti authentication endpoint
level: high
```

### Sigma: Connection to UTA0576 Infrastructure IP
Detects network connections to or from IP 108.165.147[.]64, used by UTA0576 as VPN infrastructure during exploitation of CVE-2026-104935. This IP may be rotated; lower confidence after October 2026.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed due to proxy blocking MITRE ATT&CK data fetch (RuntimeError: HTTP 403), not a rule defect. sigma convert --without-pipeline splunk exit 0; log_scale exit 0. No pipeline-mapped conversion (no firewall pipeline available). IP is real (not defanged) in the rule. Confidence medium because infrastructure IPs rotate; this indicator has a limited shelf life. -->
```yaml
title: Connection to UTA0576 Infrastructure IP 108.165.147.64
id: 4e1c9d3a-5f2b-4a8e-97c6-b0d3e5f7a2c8
status: experimental
description: >
    Detects network connections to or from the IP address 108.165.147.64, which
    was used by UTA0576 as VPN infrastructure during exploitation of Ivanti
    Connect Secure zero-days (CVE-2026-104935). The IP hosted an OpenVPN server
    on an Evoxt VPS from September 30 to October 7, 2026.
references:
    - https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
    - https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-adds-two-known-exploited-vulnerabilities-catalog
author: Actioner
date: 2026-10-14
tags:
    - attack.t1190
logsource:
    category: firewall
detection:
    selection_dst:
        dst_ip: '108.165.147.64'
    selection_src:
        src_ip: '108.165.147.64'
    condition: selection_dst or selection_src
falsepositives:
    - Legitimate traffic to Evoxt VPS hosting services at this IP after infrastructure rotation
level: high
```

### Snort: Ivanti ICS CVE-2026-104935 X-DSCGI-PATH Exploit Attempt
Detects HTTP POST requests to welcome.cgi with the X-DSCGI-PATH header targeting wu.cgi, the definitive network signature of the CVE-2026-104935 exploit chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -R (file) -T exit 0 ("Snort successfully validated the configuration!"). Snort 2.9.20. Rule uses http_uri and http_header sticky buffers. content:"POST" with depth:4 gates on the method. All three content matches must be present in the same session for the alert to fire. Values are real (not defanged). -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Ivanti ICS CVE-2026-104935 X-DSCGI-PATH Header Exploit Attempt"; flow:established,to_server; content:"POST"; depth:4; content:"/dana-na/auth/url_default/welcome.cgi"; http_uri; content:"X-DSCGI-PATH"; http_header; content:"wu.cgi"; http_header; sid:2100010; rev:1; classtype:web-application-attack; reference:url,www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/; reference:cve,2026-104935;)
```

### Suricata: Ivanti ICS CVE-2026-104935 X-DSCGI-PATH Exploit Attempt
Detects HTTP POST requests to welcome.cgi with the X-DSCGI-PATH header targeting wu.cgi, the definitive network signature of the CVE-2026-104935 exploit chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S (file) -l /tmp/actioner exit 0 ("Configuration provided was successfully loaded. Exiting."). Suricata 7.0.3. Rule uses dot-notation sticky buffers (http.method, http.uri, http.header). fast_pattern on the URI. Values are real (not defanged). -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Ivanti ICS CVE-2026-104935 X-DSCGI-PATH Header Exploit Attempt"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/dana-na/auth/url_default/welcome.cgi"; fast_pattern; http.header; content:"X-DSCGI-PATH"; content:"wu.cgi"; classtype:web-application-attack; reference:url,www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/; reference:cve,2026-104935; metadata:author Actioner, created_at 2026-10-14; sid:2200010; rev:1;)
```

### Suricata: Outbound Connection to UTA0576 Infrastructure
Detects outbound connections to 108.165.147[.]64, UTA0576's known C2/VPN infrastructure during the CVE-2026-104935 campaign. Infrastructure may rotate; treat as time-bounded indicator.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S (file) -l /tmp/actioner exit 0 ("Configuration provided was successfully loaded. Exiting."). Suricata 7.0.3. Simple IP-based rule. Confidence medium because attacker IPs rotate. IP is real (not defanged) in the rule. -->
```suricata
alert ip $HOME_NET any -> 108.165.147.64 any (msg:"Actioner - Outbound Connection to UTA0576 Infrastructure 108.165.147.64"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/; reference:cve,2026-104935; metadata:author Actioner, created_at 2026-10-14; sid:2200011; rev:1;)
```

### YARA: N/A
No file-level indicators (hashes, byte patterns, or distinctive strings from malware samples) were published by Volexity in the blog post. The post-exploitation tools were described but not released. If Volexity's GitHub threat-intel repository publishes sample hashes or YARA rules, this section should be updated.

## Lessons Learned

1. **Ivanti's own integrity tools are insufficient**: UTA0576 specifically designed the exploit chain to evade the Integrity Checker Tool by using in-memory-only modifications and restoring configurations. Organizations must supplement vendor tools with network-level monitoring and memory forensics.
2. **Stateless exploitation is an emerging trend**: By re-running the full exploit chain for every command instead of deploying persistent implants, UTA0576 eliminated most filesystem-based detection opportunities. Detection must shift toward network traffic analysis and behavioral monitoring.
3. **VPN appliances remain prime targets**: This is the fourth major zero-day campaign targeting Ivanti Connect Secure since 2024. Organizations should treat edge devices as high-risk, implement network segmentation to limit their backend access, and maintain rapid patching capabilities.
4. **LLM-assisted exploit development**: Volexity assessed with medium confidence that UTA0576 used LLM tools in developing the exploit chain and operational tooling, reflecting the emerging reality of AI-augmented offensive operations.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Volexity Blog — A Series of Unauthenticated Events: Chained Exploitation of Ivanti Connect Secure Zero-Days](https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/) — Primary technical analysis with exploit chain details, IOCs, and detection guidance
- [CISA Alert — CISA Adds Two Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-adds-two-known-exploited-vulnerabilities-catalog) — CISA KEV listing confirming active exploitation of CVE-2026-104935
- [The Hacker News — Attacker Chains Three Ivanti Connect Secure Zero-Days for Root Access, Only Two Patched So Far](https://thehackernews.com/2026/10/attacker-chains-three-ivanti-connect.html) — Technical reporting with version/patch details and ATT&CK context
- [Volexity on X (Twitter)](https://x.com/Volexity/status/2110034602672709712) — Initial disclosure announcement with summary of findings

---
*Report generated by Actioner*
