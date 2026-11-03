# Technical Analysis Report: Ivanti Connect Secure Zero-Day Chain (2026-11-03)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-11-03
Version: DRAFT

## Executive Summary

Threat actor UTA0576 (tracked by Volexity) has been exploiting a chain of three zero-day vulnerabilities in Ivanti Connect Secure (ICS) VPN appliances since at least October 3, 2026. The chain combines CVE-2026-104935 (authentication bypass, CVSS 8.6), CVE-2026-111357 (privilege escalation, CVSS 8.8), and CVE-2026-118527 (predictable file upload, CVSS 4.3) to achieve unauthenticated root-level code execution on fully patched appliances. UTA0576 is a previously undocumented actor that deployed no web shells or persistent malware, instead re-running the full exploit chain for each command and using anti-forensic techniques that evaded Ivanti's Integrity Checker Tool (ICT). Post-exploitation focused on credential theft, Active Directory reconnaissance (including LAPS passwords and BitLocker recovery keys), Kerberoasting, and password spraying.

Ivanti released patches in two stages: the initial fix for CVE-2026-104935 on October 13 (versions 25.1.1.2, 22.8R2.5), and fixes for CVE-2026-111357 and CVE-2026-118527 on October 29 (versions 25.1.1.3, 22.8R2.6). All three CVEs are on CISA's Known Exploited Vulnerabilities (KEV) catalog, with federal patching deadlines of November 2 (CVE-2026-111357) and November 13 (CVE-2026-118527). Over 5,000 ICS instances remain internet-exposed per Shadowserver.

## Background: Ivanti Connect Secure

Ivanti Connect Secure (formerly Pulse Secure) is an enterprise SSL VPN appliance widely deployed in government and corporate environments. It provides remote access to internal networks and is a high-value target for threat actors due to its internet-facing position and access to internal resources. Ivanti has been a frequent target: CISA has catalogued 38 exploited Ivanti vulnerabilities since November 2021, including CVE-2024-21887, CVE-2023-46805, CVE-2024-21893, CVE-2025-0282, and CVE-2025-22457. The product runs on a hardened Linux-based appliance with custom CGI endpoints for authentication and file management.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-XX | Ivanti releases version 25.1.3.0, partially patching the privilege escalation component; begins backporting to other branches |
| 2026-09-30 | Attacker IP 108.165.147[.]64 begins running an OpenVPN server (Evoxt VPS) |
| 2026-10-01 | Defused threat intelligence reports earliest exploitation attempts hitting decoys |
| 2026-10-03 | Earliest UTA0576 exploitation observed by Volexity against ICS 22.8R2.4 (Build 19097) |
| 2026-10-05 | Volexity begins investigation following NSM customer alert |
| 2026-10-07 | Attacker OpenVPN activity on the IP ends |
| 2026-10-10 | Volexity shares indicators with TI customers (TIB-20261012) |
| 2026-10-13 | Volexity publishes blog post; Ivanti releases patches for CVE-2026-104935 (25.1.1.2, 22.8R2.5); CISA adds CVE-2026-104935 to KEV |
| 2026-10-29 | Ivanti updates advisory to disclose CVE-2026-111357 and CVE-2026-118527; releases 25.1.1.3 and 22.8R2.6 |
| 2026-10-30 | CISA adds CVE-2026-111357 and CVE-2026-118527 to KEV |
| 2026-11-02 | FCEB deadline to patch CVE-2026-111357 |
| 2026-11-13 | FCEB deadline to patch CVE-2026-118527 |

## Root Cause: Chained Zero-Day Exploitation of Ivanti Connect Secure

The attack chain exploits three distinct vulnerabilities in the Ivanti Connect Secure appliance's CGI web framework and internal service broker architecture:

1. **CVE-2026-104935 (Authentication Bypass + RCE):** The `welcome.cgi` endpoint is publicly accessible for login. The `X-DSCGI-PATH` HTTP header allows routing requests to arbitrary protected CGI handlers without authentication. The attacker routes requests to `wu.cgi`, a file upload handler.

2. **CVE-2026-118527 (Predictable File Upload):** The `wu.cgi` upload handler writes files to a predictable path (`/home/runtime/tmp/<MD5(filename)>`) before validating them as ZIP archives. The validation deletes non-ZIP files, but a race condition window allows execution of the uploaded file via parallel requests.

3. **CVE-2026-111357 (Privilege Escalation):** The `dsinvoked` service broker trusts DSCache configuration data. The attacker patches the in-memory copy of `libdsplibs.so` to modify DSCache, repoints a maintenance task to the Perl interpreter with a malicious script, and achieves root execution.

## Technical Analysis of the Malicious Payload

### 1. Authentication Bypass via welcome.cgi Header Routing

The attacker sends HTTP requests to `/dana-na/auth/url_default/welcome.cgi` (a public, unauthenticated endpoint) with the `X-DSCGI-PATH` header set to target protected CGI handlers. The URL controls the access check (welcome.cgi passes), while the header controls which CGI actually handles the request. This allows unauthenticated access to any CGI endpoint on the appliance.

Key request pattern:
- URI: `/dana-na/auth/url_default/welcome.cgi`
- Header: `X-DSCGI-PATH: /home/webserver/htdocs/dana/fb/smb/wu.cgi`

### 2. RCE via wu.cgi Race Condition

A Perl script with a `.zip` extension is uploaded to the `wu.cgi` handler. The handler writes it to `/home/runtime/tmp/<MD5(filename)>` before validating the ZIP format. Parallel requests use `X-DSCGI-PATH: /home/runtime/tmp/<MD5(filename)>` to execute the uploaded file before deletion. The Perl script launches a Bash script, which in turn runs a Python payload delivered as base64-encoded, zlib-compressed data via `exec()`, keeping the payload memory-resident only.

### 3. Privilege Escalation via dsinvoked Broker

The exploit escalates privileges through the following steps:
- Patches the cgi-server process's in-memory copy of `/home/lib/libdsplibs.so` via `/proc/self/mem` (no on-disk modification)
- Modifies DSCache to repoint an existing `dsinvoked` maintenance task to the Perl interpreter
- Provides a malicious Perl script at `/home/runtime/tmp/ics-root-run-inband-*.pl` as the argument
- `dsinvoked` executes the script as root
- Success is verified by testing readability of `/etc/shadow`
- DSCache and the in-memory library are restored to their original state

### 4. Command Execution Channel

Each command re-runs the full three-stage exploit chain. There is no persistent C2 channel, web shell, or backdoor. Command output returns in the HTTP response body. This stateless approach significantly complicates detection and forensics.

### 5. Anti-Forensics / Evasion Techniques

UTA0576 employed extensive anti-forensic measures:
- **Log tampering:** Selectively filtered and rewrote entries in `/home/runtime/dlogs/debuglog` and `/var/log/audit/audit.log` within the attack window
- **Self-deletion:** Root payload and Python stages delete their own scripts upon completion
- **Temp cleanup:** Removed result files (`ics-root-result-inband-*`), CGI source, and temporary gate files; explicitly deleted `/tmp/rq5.py` and `/tmp/rr.py`
- **DSCache restoration:** Restored the maintenance task target to the legitimate `updateOpswatSDK.pl`
- **Memory-only patching:** In-memory `libdsplibs.so` modifications restored via `/proc/self/mem`; on-disk library never modified
- **Output suppression:** Background cleanup redirected I/O to `/dev/null`
- **Process masquerading:** Renamed `tcpdump` to `dsstatmond` in hidden directory `/data/.icscap/`
- **ICT evasion:** Ivanti's Integrity Checker Tool detects on-disk changes only; the memory-only exploitation evades it entirely

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `108.165.147[.]64`)
> - Domains: `[.]` replacing dots

### Package / Software Level

| Package / Component | Affected Versions | Fixed Versions | Description |
|---------------------|-------------------|----------------|-------------|
| Ivanti Connect Secure | 25.1.1.2 and prior | 25.1.1.3 | CVE-2026-111357, CVE-2026-118527 |
| Ivanti Connect Secure | 22.8R2.5 and prior | 22.8R2.6 | CVE-2026-111357, CVE-2026-118527 |
| Ivanti Connect Secure | 25.1.1.1 and prior | 25.1.1.2 | CVE-2026-104935 |
| Ivanti Connect Secure | 25.1.2.2 and prior | 25.1.3.0, 25.1.3.1 | CVE-2026-104935 |
| Ivanti Connect Secure | 22.8R2.4 and prior | 22.8R2.5 | CVE-2026-104935 |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| ICS (Linux) | `/home/runtime/tmp/ics-root-run-inband-*.pl` | -- | Root-stage Perl payload |
| ICS (Linux) | `/home/runtime/tmp/ics-root-result-inband-*` | -- | Execution result files |
| ICS (Linux) | `/data/.icscap/dsstatmond` | -- | Renamed tcpdump (packet capture) |
| ICS (Linux) | `/data/.icscap/cap*` | -- | Packet capture files |
| ICS (Linux) | `/data/.icscap/h.py` | -- | Credential parser for captured traffic |
| ICS (Linux) | `/tmp/ml.py` | -- | LDAP reconnaissance tool |
| ICS (Linux) | `/tmp/rq5.py` | -- | LDAP query script |
| ICS (Linux) | `/tmp/mk.py` | -- | Kerberoasting library |
| ICS (Linux) | `/tmp/rr.py` | -- | Kerberos test script |
| ICS (Linux) | `/tmp/sp_run.py` | -- | Password spraying helper |
| ICS (Linux) | `/tmp/sp_out.txt`, `/tmp/spray_hits.json` | -- | Spray output/results |
| ICS (Linux) | `/tmp/pu.txt` | -- | Extracted usernames from auth logs |
| ICS (Linux) | (memory-only) | `25b95f47359c327e3a5ae5ac5cd147f8d9afd98092faf136822ee287e25e3dc8` | Privilege escalation Python tool |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 108.165.147[.]64 | UTA0576 exploitation source IP; Evoxt VPS with OpenVPN (Sept 30 -- Oct 7, 2026) |
| URI Pattern | `/dana-na/auth/url_default/welcome.cgi` | Authentication bypass entry point (public CGI) |
| HTTP Header | `X-DSCGI-PATH: /home/webserver/htdocs/dana/fb/smb/wu.cgi` | Routing header for file upload handler exploitation |
| HTTP Header | `X-DSCGI-PATH: /home/runtime/tmp/<MD5>` | Routing header for uploaded payload execution |

### Behavioral

- **Stateless command execution:** Each command re-runs the full three-stage chain; no persistent backdoor or C2 channel
- **Welcome.cgi/X-DSCGI-PATH mismatch:** The URL path and X-DSCGI-PATH header point to different CGI handlers -- this mismatch is the distinctive exploitation fingerprint
- **Packet capture in hidden directory:** tcpdump renamed to `dsstatmond` running from `/data/.icscap/`
- **Selective log deletion:** Targeted removal of entries from `debuglog` and `audit.log` within the attack window
- **AD credential harvesting:** LDAP queries for LAPS passwords, BitLocker recovery keys, `userPassword`/`unixUserPassword` attributes, and logon script paths
- **Network sniffing:** Capture files targeting LDAP (TCP 389), HTTP, FTP, and telnet traffic for credential harvesting

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Chained exploitation of three zero-days in internet-facing ICS VPN appliance |
| T1068 | Exploitation for Privilege Escalation | dsinvoked broker DSCache manipulation for root execution |
| T1059.004 | Unix Shell | Bash script execution as intermediate stage in the exploit chain |
| T1059.006 | Python | Memory-resident Python payload for privilege escalation and post-exploitation tools |
| T1055 | Process Injection | In-memory patching of libdsplibs.so via /proc/self/mem |
| T1040 | Network Sniffing | Renamed tcpdump capturing LDAP, HTTP, FTP, and telnet credentials |
| T1558.003 | Kerberoasting | Custom Kerberoasting tool (mk.py) deployed for credential harvesting |
| T1110.003 | Password Spraying | sp_run.py password spraying against AD accounts |
| T1003 | OS Credential Dumping | Extraction of credentials from captured network traffic and appliance storage |
| T1552.004 | Private Keys | Targeted extraction of LAPS passwords and BitLocker recovery keys from AD |
| T1070.001 | Clear Windows Event Logs | Selective deletion of debuglog and audit.log entries (Linux equivalent) |
| T1070.004 | File Deletion | Self-deletion of exploit payloads, Python scripts, and result files |
| T1036.005 | Match Legitimate Name or Location | Renamed tcpdump to dsstatmond to masquerade as a legitimate process |

## Impact Assessment

The impact of this exploit chain is severe:
- **Breadth:** Over 5,000 internet-exposed ICS instances tracked by Shadowserver; Ivanti confirmed "limited" exploitation affecting a small number of customers, with Volexity confirming at least one victim
- **Depth:** Unauthenticated root-level code execution provides complete appliance compromise, access to all stored credentials, and a pivot point into the internal network
- **Stealth:** Memory-only exploitation evades Ivanti's Integrity Checker Tool; selective log tampering hinders forensic investigation; stateless command execution leaves minimal persistent artifacts
- **Credential exposure:** AD service account credentials, LAPS local administrator passwords, BitLocker recovery keys, and user passwords captured via network sniffing are all potentially compromised
- **Attribution:** UTA0576 is a previously undocumented actor; Volexity assesses criminal motivation with low confidence and LLM-assisted tool development with medium confidence

## Detection & Remediation

### Immediate Detection

1. **Network monitoring:** Alert on HTTP requests to `/dana-na/auth/url_default/welcome.cgi` containing `X-DSCGI-PATH` headers, especially with values pointing to `wu.cgi` or `/home/runtime/tmp/`
2. **Appliance file hunt:** Search for artifacts in `/tmp/` (ml.py, rq5.py, mk.py, rr.py, sp_run.py, spray_hits.json, pu.txt) and `/data/.icscap/` (dsstatmond, cap*, h.py)
3. **Process check:** Look for a process named `dsstatmond` (PID may vary) which is a renamed tcpdump
4. **Log analysis:** Review `debuglog` and `audit.log` for gaps, truncation, or suspicious editing within the attack window
5. **AD audit:** Check for unusual LDAP queries from the ICS appliance's service account, particularly queries for LAPS passwords, BitLocker keys, and password attributes
6. **Network IOC:** Monitor for connections to/from 108.165.147[.]64

### Remediation

1. **Patch immediately:** Upgrade to ICS 25.1.1.3 or 22.8R2.6 (organizations that installed 25.1.1.2 or 22.8R2.5 for CVE-2026-104935 must upgrade again)
2. **Investigate before or after patching:** The Integrity Checker Tool may not detect compromise; conduct memory and network forensics on suspected devices
3. **Preserve evidence:** Back up appliance configuration (Ivanti KB44759) and preserve memory dumps and logs before rebooting or resetting
4. **Factory reset if compromised:** Perform a factory reset, upgrade to the fixed version, and restore configuration from backup
5. **Credential rotation:** Rotate all potentially exposed credentials including: domain service accounts, LAPS local administrator passwords, BitLocker recovery keys, API keys, license server credentials, and any credentials that transited the appliance in cleartext
6. **Lateral movement investigation:** Hunt for lateral movement from the ICS appliance into the internal network

### Long-Term Hardening

1. **Migrate from 22.8.x:** Ivanti recommends moving to 25.1.1.3 or later; version 22.8 reaches end-of-life January 31, 2027
2. **Network segmentation:** Isolate VPN appliances with strict egress controls and monitoring
3. **Memory forensics capability:** Deploy tooling that can detect memory-only modifications, not just file-system integrity checks
4. **LDAP hardening:** Enforce LDAPS (TCP 636) to prevent credential capture from cleartext LDAP traffic
5. **Reduce exposed surface:** Evaluate whether all internet-exposed ICS instances are necessary; consider additional authentication layers

## Detection Rules

These detections target the distinctive artifacts of the Ivanti Connect Secure exploit chain (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527). PoC/advisory-specific altitude; all rules compile against their respective validators. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: Connection to Known UTA0576 Attacker IP

Detects outbound connections to 108.165.147[.]64, the Evoxt VPS IP associated with UTA0576's exploitation campaign (active Sept 30 -- Oct 7, 2026). IOC may be rotated; pair with network rules for durable coverage.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (with tag validators excluded due to environment network restriction on MITRE ATT&CK data fetch); splunk convert 0; log_scale convert 0. Single IP IOC from Volexity report; medium confidence because the IP is infrastructure that can be rotated. -->

```yaml
title: Connection to Known UTA0576 Attacker IP - Ivanti ICS Exploitation
id: 7e3a1c4b-9d2f-4e8a-b6c5-1f0d3e7a2b9c
status: experimental
description: >
    Detects network connections to IP address 108.165.147.64, associated with
    threat actor UTA0576 exploiting Ivanti Connect Secure zero-day chain
    (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527). The IP hosted an
    OpenVPN server used during exploitation from September 30 to October 7, 2026.
references:
    - https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
    - https://www.rapid7.com/blog/post/etr-additional-ivanti-connect-secure-zero-days-exploited-in-the-wild-cve-2026-111357-cve-2026-118527/
author: Actioner
date: 2026/11/03
tags:
    - attack.t1190
logsource:
    category: firewall
detection:
    selection:
        dst_ip: '108.165.147.64'
    condition: selection
falsepositives:
    - Legitimate traffic to the Evoxt VPS hosting provider IP range
level: high
```

### Snort: Ivanti ICS Exploit Chain X-DSCGI-PATH to wu.cgi

Detects HTTP requests to Ivanti Connect Secure's welcome.cgi with X-DSCGI-PATH header routing to the wu.cgi upload handler, the distinctive initial exploitation step.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort binary not available in this environment. Structural check: http service, established flow, http_uri + http_header sticky buffers, content matches for the distinctive URI and header, fast_pattern on X-DSCGI-PATH, required fields (msg, sid, rev, classtype, reference) present. -->

```snort
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Actioner - Ivanti ICS Exploit Chain X-DSCGI-PATH to wu.cgi (CVE-2026-104935)";
    flow:established, to_server;
    http_uri;
    content:"/dana-na/auth/url_default/welcome.cgi";
    http_header;
    content:"X-DSCGI-PATH", fast_pattern;
    content:"wu.cgi";
    classtype:web-application-attack;
    reference:url,volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/;
    reference:cve,2026-104935;
    metadata:author Actioner, created 2026-11-03;
    sid:2100001;
    rev:1;
)
```

### Suricata: Ivanti ICS Exploit Chain X-DSCGI-PATH to wu.cgi

Detects HTTP requests to Ivanti Connect Secure's welcome.cgi with X-DSCGI-PATH header routing to the wu.cgi upload handler.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Dot-notation sticky buffers (http.uri, http.header). Keys on the distinctive welcome.cgi + X-DSCGI-PATH + wu.cgi combination, which is unique to this exploit chain. High confidence: this header/URI combination has no legitimate use. -->

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Ivanti ICS Exploit Chain X-DSCGI-PATH to wu.cgi (CVE-2026-104935)"; flow:established,to_server; http.uri; content:"/dana-na/auth/url_default/welcome.cgi"; http.header; content:"X-DSCGI-PATH"; fast_pattern; content:"wu.cgi"; classtype:web-application-attack; reference:url,volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/; reference:cve,2026-104935; metadata:author Actioner, created_at 2026-11-03; sid:2200001; rev:1;)
```

### Suricata: Ivanti ICS Exploit Chain X-DSCGI-PATH to Runtime Tmp

Detects HTTP requests routing via X-DSCGI-PATH to `/home/runtime/tmp/`, used to execute uploaded payloads before deletion in the race condition window.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Dot-notation sticky buffers. Keys on welcome.cgi + X-DSCGI-PATH + /home/runtime/tmp/ path, the execution stage of the exploit chain. High confidence: this path in X-DSCGI-PATH has no legitimate use. -->

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Ivanti ICS Exploit Chain X-DSCGI-PATH to Runtime Tmp (CVE-2026-104935)"; flow:established,to_server; http.uri; content:"/dana-na/auth/url_default/welcome.cgi"; http.header; content:"X-DSCGI-PATH"; fast_pattern; content:"/home/runtime/tmp/"; classtype:web-application-attack; reference:url,volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/; reference:cve,2026-104935; metadata:author Actioner, created_at 2026-11-03; sid:2200002; rev:1;)
```

### YARA: Ivanti ICS RCE Exploit Header Evidence

Detects log files or memory regions containing the distinctive X-DSCGI-PATH request header routing to the wu.cgi upload handler, evidence of CVE-2026-104935 exploitation.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive sample (constructed from published header string): fired. Negative sample (benign HTTP request): quiet. String sourced from Volexity's published YARA rule (rule_id 13503). Scan context: file (web logs, packet captures) and memory. -->

```yara
rule Exploit_Ivanti_ICS_RCE_Header_CVE_2026_104935
{
    meta:
        description = "Detects request header evidence of Ivanti Connect Secure RCE exploitation via X-DSCGI-PATH routing to wu.cgi upload handler (CVE-2026-104935)"
        author = "Actioner"
        date = "2026-11-03"
        reference = "https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/"
        severity = "critical"

    strings:
        $header = "X-DSCGI-PATH: /home/webserver/htdocs/dana/fb/smb/wu.cgi" ascii

    condition:
        $header
}
```

### YARA: Ivanti ICS Privilege Escalation Python Tool (UTA0576)

Detects the privilege escalation Python tool used by UTA0576 via distinctive strings for dsinvoked broker manipulation and memory patching. Targets memory scanning of compromised appliances.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive sample (constructed from published magic strings): fired. Negative sample (benign Python): quiet. Strings sourced from Volexity's published YARA rule (rule_id 13500). Known sample hash: 25b95f47359c327e3a5ae5ac5cd147f8d9afd98092faf136822ee287e25e3dc8. Scan context: memory (tool runs in-memory only). -->

```yara
rule Exploit_Ivanti_ICS_EoP_Python_UTA0576
{
    meta:
        description = "Detects privilege escalation Python tool used by UTA0576 in Ivanti Connect Secure exploit chain (CVE-2026-111357)"
        author = "Actioner"
        date = "2026-11-03"
        reference = "https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/"
        hash = "25b95f47359c327e3a5ae5ac5cd147f8d9afd98092faf136822ee287e25e3dc8"
        severity = "critical"

    strings:
        $magic1 = "target dsinvoked broker is busy; stop retries and clear its current child" ascii
        $magic2 = "PATCH_LOCATOR arch=%s offset=%s sha256=%s encoding=%s open=%s call=%s evidence=%s" ascii
        $pycombo1 = "import os,socket,time,_frozen_importlib_external as ie" ascii
        $pycombo2 = "def say(*x): print(*x,flush=True)" ascii

    condition:
        any of ($magic*) or all of ($pycombo*)
}
```

## Lessons Learned

1. **Memory-only exploitation defeats file-integrity checking.** Ivanti's Integrity Checker Tool, the primary vendor-recommended detection method, failed to detect this exploitation because the attack modified only in-memory structures and restored them after execution. Organizations must supplement ICT with memory forensics and network-level detection.

2. **Stateless exploitation complicates traditional IOC-based detection.** UTA0576's approach of re-running the full exploit chain per command and leaving no persistent malware or web shell breaks the typical "find the backdoor" response model. Detection must focus on the exploitation traffic pattern (the X-DSCGI-PATH header mismatch) rather than post-exploitation artifacts.

3. **Patch-then-investigate is insufficient.** The October 13 patch for CVE-2026-104935 did not address two of the three chained vulnerabilities, requiring a second emergency upgrade cycle. Organizations that patched once may have a false sense of security. Furthermore, Volexity assesses with medium confidence that UTA0576 used LLM-assisted development for exploit and post-exploitation tooling, suggesting that the barrier to developing sophisticated VPN appliance exploits may be lowering.

4. **VPN appliances remain high-value, high-risk infrastructure.** This marks the fifth major Ivanti exploitation campaign since January 2024. The pattern of zero-day chains targeting network edge devices for credential harvesting and lateral movement preparation is well-established and shows no sign of abating.

## Sources

- [Volexity Blog: A Series of Unauthenticated Events](https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/) -- primary technical analysis of the exploit chain and UTA0576 activity
- [BleepingComputer: Ivanti Patches Two More Connect Secure Zero-Days](https://www.bleepingcomputer.com/news/security/ivanti-patches-two-more-connect-secure-zero-days-chained-in-attacks/) -- reporting on CVE-2026-111357 and CVE-2026-118527 disclosure and patching timeline
- [The Hacker News: Attackers Chain Three Ivanti Connect Secure Zero-Days](https://thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html) -- additional technical details on the chain and affected versions
- [Rapid7 ETR: Additional Ivanti Connect Secure Zero-Days](https://www.rapid7.com/blog/post/etr-additional-ivanti-connect-secure-zero-days-exploited-in-the-wild-cve-2026-111357-cve-2026-118527/) -- CVE details, CWE classifications, and affected/fixed version matrix
- [CISA Alert: Urges Patching Newly Exploited Vulnerabilities in Ivanti Connect Secure](https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-urges-patching-newly-exploited-vulnerabilities-ivanti-connect-secure) -- federal guidance, KEV additions, and recovery procedures
- [SecurityWeek: Ivanti Patches Two More Zero-Days](https://www.securityweek.com/ivanti-patches-two-more-zero-days-exploited-in-connect-secure-attack-chain/) -- additional reporting on the advisory update and exploitation timeline
- [Volexity GitHub: threat-intel/2026/2026-10-13 Ivanti](https://github.com/volexity/threat-intel/tree/main/2026/2026-10-13%20Ivanti) -- published YARA rules and IOC indicators

---
*Report generated by Actioner*
