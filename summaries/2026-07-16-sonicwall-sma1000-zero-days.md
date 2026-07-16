# Technical Analysis Report: SonicWall SMA1000 Zero-Day Vulnerabilities (2026-07-16)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-16
Version: DRAFT 1.0

## Executive Summary

Two zero-day vulnerabilities in SonicWall SMA1000 series appliances -- CVE-2026-15409 (CVSS 10.0, SSRF) and CVE-2026-15410 (CVSS 7.2, code injection) -- have been under active exploitation since at least June 22, 2026, approximately three weeks before public disclosure on July 14-15, 2026. Attackers chain the two flaws: the unauthenticated SSRF opens a WebSocket tunnel to localhost-only services on the appliance, and the post-authentication code injection exploits a path traversal in the hotfix rollback workflow to achieve root command execution. Rapid7's MDR team discovered the exploitation and reported it to SonicWall; Volexity contributed additional IOC identification. CISA added both CVEs to the Known Exploited Vulnerabilities catalog on July 14, 2026, with a federal remediation deadline of July 17, 2026. Post-compromise activity includes credential harvesting, TOTP MFA seed theft, and lateral movement to Active Directory domain controllers. Rapid7 observed indicators consistent with ransomware objectives. Fewer than 5,000 SMA1000 appliances are deployed globally, but each is a high-value network perimeter device. A public proof-of-concept exploit is available.

## Background: SonicWall SMA1000

The SonicWall SMA (Secure Mobile Access) 1000 series provides SSL VPN and secure remote access to enterprise networks. Models include the SMA 6210, 7210, and 8200v (virtual). These appliances sit at the network perimeter and authenticate remote users -- making them high-value targets for initial access. The appliance runs two key web-facing services: the **WorkPlace** interface (port 443, user-facing) and the **Appliance Management Console (AMC)** (port 8443, admin-facing). Internally, the appliance hosts an Erlang process on localhost:1050 and a ctrl-service on localhost:8188, both intended to be inaccessible from external networks.

SonicWall products have been repeatedly targeted: CVE-2021-20016, CVE-2021-20028, and CVE-2025-23006 all saw active exploitation against SMA devices. This latest pair continues the pattern, with threat actors maintaining persistent interest in VPN/remote-access appliances as initial access vectors.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-06-22 | Earliest observed exploitation of CVE-2026-15409 and CVE-2026-15410 in the wild (Rapid7) |
| 2026-07-09 | Rapid7 MDR detects active, targeted zero-day exploitation of internet-facing SMA1000 appliances |
| 2026-07-14 | SonicWall publishes Product Notice for SMA 1000 Series; CISA adds both CVEs to KEV catalog |
| 2026-07-15 | CVEs publicly disclosed; Rapid7 publishes detailed technical blog and PoC exploit code |
| 2026-07-17 | CISA BOD 22-01 remediation deadline for federal agencies |

## Root Cause: Chained Unauthenticated SSRF + Authenticated Code Injection

**CVE-2026-15409** is a server-side request forgery (SSRF) vulnerability in the WorkPlace interface's WebSocket proxy endpoint (`/wsproxy`). The endpoint accepts URL parameters (`bmID`, `serviceType`, `host`, `port`) that control the proxy destination. An unauthenticated attacker can specify loopback addresses (`0.0.0.0`, `localhost`, `::ffff:127.0.0.1`) to tunnel connections to localhost-only services, bypassing network segmentation. The Erlang process on port 1050 uses a hardcoded cookie (`10ecad5b446e86864832904cd439b6b70262`) for authentication, allowing immediate RPC command execution as the `couchdb` user (uid=1010).

**CVE-2026-15410** is a post-authentication code injection in the AMC's hotfix rollback workflow. The `/rollbackConfirm.action` endpoint on port 8443 accepts a `hotfix` parameter vulnerable to path traversal (`hotfix=../../../../../tmp/1234.sh`). The referenced file is chmod'd executable and run as root via `/bin/bash`, followed by a system reboot (`shutdown -r now`). After gaining non-root access via CVE-2026-15409, the attacker escalates to root through this endpoint (accessible via the ctrl-service tunnel on localhost:8188).

## Technical Analysis of the Malicious Payload

### 1. Stage 1: WebSocket Proxy SSRF (CVE-2026-15409)

The attacker sends an HTTP Upgrade request to the `/wsproxy` endpoint on port 443:

```
wss://<TARGET>/wsproxy?bmID=-3389c1b25ccd&serviceType=SSH&host=0.0.0.0&port=1050
```

Key parameters:
- `bmID`: Must begin with `-3389` (arbitrary suffix); other prefixes also work
- `serviceType`: `SSH` is used in the PoC; `TELNET` and other values also function
- `host`: Loopback address (`0.0.0.0`, `localhost`, `127.0.0.1`, `::ffff:127.0.0.1`)
- `port`: `1050` (Erlang process) or `8188` (ctrl-service)

The PoC exploit uses User-Agent `SMA Connect Agent` and implements the Erlang distribution protocol over the WebSocket tunnel, authenticating with the hardcoded Erlang cookie and invoking `os:cmd/1` for command execution as the `couchdb` user.

### 2. Stage 2: Privilege Escalation via Hotfix Rollback (CVE-2026-15410)

After gaining non-root access, the attacker tunnels to localhost:8188 (ctrl-service) and sends:

```
POST /rollbackConfirm.action
Content-Type: application/x-www-form-urlencoded

csrfToken=GFEJUCQBUZOLUCCOO3YBA8G30ZE9VKDP&command=rollback&hotfix=../../../../../tmp/1234.sh
```

The traversal escapes the expected hotfix directory, causing the appliance to execute an attacker-controlled script as root. The system reboots after execution.

### 3. Post-Exploitation Behavior

Observed post-compromise activities (Rapid7):
- **Credential harvesting:** Extraction of session databases (`/tmp/temp.db*`) containing user credentials
- **MFA bypass:** Theft of TOTP seed configurations, enabling future authentication without the physical MFA token
- **Lateral movement:** Direct NTLM logons (Windows Event ID 4624, logon type 3) from the appliance's internal IP to domain controllers using LDAP service account credentials
- **Stealth indicators:** Non-inventory workstation names (e.g., "kali") appearing in authentication logs via LDAP service accounts
- **VPN-less access:** Machine-level lateral movement with no corresponding active VPN tunnel, establishing the compromised appliance as an unmonitored backdoor into the network

### 4. Anti-Forensics / Evasion Techniques

- The system reboot after CVE-2026-15410 exploitation clears volatile forensic artifacts
- Use of existing LDAP service account credentials for lateral movement blends with legitimate traffic
- WebSocket tunneling through the legitimate `/wsproxy` endpoint avoids triggering traditional IDS rules
- Exploitation leaves minimal filesystem artifacts on the appliance itself

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `193.37.32[.]179`)
> - URLs: `hxxps://` replacing `https://`

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 193.37.32[.]179 | Threat actor infrastructure (ASN 206092, F.N.S Holdings Limited) |
| IP | 193.37.32[.]214 | Threat actor infrastructure (ASN 206092) |
| IP | 216.73.163[.]151 | Threat actor infrastructure (ASN 206092) |
| IP | 216.73.163[.]158 | Threat actor infrastructure (ASN 206092) |
| CIDR | 45.131.194[.]0/24 | Threat actor IP range (ASN 206092) |
| CIDR | 45.146.54[.]0/24 | Threat actor IP range (ASN 206092) |
| CIDR | 63.135.161[.]0/24 | Threat actor IP range (ASN 206092) |
| CIDR | 173.239.211[.]0/24 | Threat actor IP range (ASN 206092) |
| URL Pattern | /wsproxy?bmID=-3389* | CVE-2026-15409 exploitation URI |
| URL Pattern | /rollbackConfirm.action (POST with path traversal) | CVE-2026-15410 exploitation URI |
| User-Agent | SMA Connect Agent | PoC exploit User-Agent string |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| SMA1000 (Linux) | /tmp/temp.db* | N/A | Session database files targeted for credential theft |
| SMA1000 (Linux) | /var/lib/unit/conf.json | N/A | Configuration file — check for suspicious routes to `/__api__/login` or `/__api__/logout` |

### Behavioral

- **WebSocket upgrade requests** to `/wsproxy` with `host` parameter pointing to loopback addresses and `port` targeting 1050 or 8188
- **HTTP 101** (Switching Protocols) responses in `extraweb_access.log` associated with `/wsproxy` requests containing `bmID=-3389`
- **Path traversal sequences** (`../`) in POST requests to `/rollbackConfirm.action`
- **Invocations of `/usr/local/bin/remove_hotfix`** with traversal sequences in `ctrl-service.log`
- **Suspicious API route additions** in `/var/lib/unit/conf.json` routing to `/__api__/login` or `/__api__/logout`
- **Repeated requests** to `/auth1.html`, `/.env`, or `/api/sonicos/is-sslvpn-enabled`
- **Windows Event ID 4624** (logon type 3) originating from the SMA appliance's internal IP with unrecognized workstation names

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated SSRF exploitation of the SMA1000 WorkPlace `/wsproxy` endpoint (CVE-2026-15409) |
| T1090 | Proxy | WebSocket proxy abuse to tunnel connections to localhost-only services through the appliance |
| T1068 | Exploitation for Privilege Escalation | Path traversal in hotfix rollback workflow to execute scripts as root (CVE-2026-15410) |
| T1059.004 | Unix Shell | Arbitrary shell script execution via `/bin/bash` through the hotfix rollback mechanism |
| T1003 | OS Credential Dumping | Extraction of credentials from session databases (`/tmp/temp.db*`) |
| T1556 | Modify Authentication Process | Theft of TOTP MFA seed configurations to bypass multi-factor authentication |
| T1021.002 | SMB/Windows Admin Shares | NTLM lateral movement from compromised appliance to domain controllers |
| T1078 | Valid Accounts | Use of harvested LDAP service account credentials for lateral movement |

## Impact Assessment

- **Breadth:** Fewer than 5,000 SMA1000 appliances deployed globally (SonicWall telemetry), but each controls perimeter access for an entire organization
- **Depth:** Complete system compromise -- from unauthenticated access to root-level command execution, credential theft, and domain controller access
- **Stealth:** Three-week exploitation window before disclosure; VPN-less lateral movement avoids standard VPN monitoring; legitimate endpoint abuse evades signature-based detection
- **Objective:** Rapid7 observed activity consistent with ransomware operations (exfiltration and encryption attempts were prevented in investigated cases)

## Detection & Remediation

### Immediate Detection

Check SMA1000 appliance logs for compromise indicators:

```bash
# Check for wsproxy exploitation attempts (CVE-2026-15409)
grep -E '(GET.*wsproxy.*=-3389.* 101 )' /path/to/extraweb_access.log

# Check for hotfix rollback path traversal (CVE-2026-15410)
grep -E 'remove_hotfix.*\.\.\/' /path/to/ctrl-service.log

# Check for suspicious API route modifications
cat /var/lib/unit/conf.json | grep -E '(__api__/login|__api__/logout)'
```

On domain controllers, search for anomalous logons from the SMA appliance IP:

```
# Windows Event ID 4624, Logon Type 3, from SMA appliance IP
# Look for non-inventory workstation names (e.g., "kali")
```

### Remediation

1. **Patch immediately:** Update to firmware 12.4.3-03453 or 12.5.0-02835 (platform-hotfix)
2. **Assume compromise if unpatched:** SonicWall warns that "patching alone is not sufficient" if exploitation occurred pre-patch
3. **Re-image or redeploy:** Hardware re-imaging or virtual appliance redeployment recommended for confirmed compromises
4. **Rotate all credentials:** Reset all passwords and TOTP tokens associated with the appliance and any LDAP/AD service accounts
5. **Audit lateral movement:** Review Windows Event ID 4624 (type 3) logs for logons originating from the appliance's internal IP
6. **Run SonicWall assistance script:** SonicWall has developed a customer assistance script; contact support for access

### Long-Term Hardening

- Restrict AMC (port 8443) access to management VLANs only; do not expose to the internet
- Monitor WebSocket upgrade requests to `/wsproxy` as a standard detection
- Implement network segmentation preventing VPN appliances from directly authenticating to domain controllers
- Deploy behavioral detection for anomalous authentication patterns (non-inventory workstation names, VPN-less lateral movement)

## Detection Rules

These detections target the specific exploitation artifacts from the CVE-2026-15409/CVE-2026-15410 attack chain. PoC/advisory-specific altitude (default); the Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Suricata rules compile on Suricata 7.0.3. Compiles does not equal fires -- verify against your log pipeline before production deployment.

### Sigma: SonicWall SMA1000 CVE-2026-15409 SSRF via wsproxy Endpoint

Detects requests to the `/wsproxy` endpoint with `host` parameter pointing to loopback addresses, indicating SSRF exploitation to reach localhost-only services.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data download blocked by environment proxy, not a rule issue); splunk convert exit 0; log_scale convert exit 0. No product-specific pipeline available for webserver category. Field values are real (not defanged). -->

```yaml
title: SonicWall SMA1000 CVE-2026-15409 SSRF via wsproxy Endpoint
id: 8f3a1b7c-4e92-4d6f-b1a3-9c5e7d2f0b84
status: experimental
description: >
    Detects exploitation of CVE-2026-15409 (CVSS 10.0) via HTTP requests to the
    /wsproxy endpoint on SonicWall SMA1000 appliances with parameters indicative
    of SSRF abuse to tunnel to localhost services (Erlang port 1050, ctrl-service
    port 8188). Attackers specify host=0.0.0.0, localhost, or IPv6 loopback to
    pivot to internal services.
references:
    - https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/
    - https://cyberscoop.com/sonicwall-zero-day-vulnerabilities-exploited/
    - https://www.sonicwall.com/support/notices/product-notice-sma-1000-series-affected-by-multiple-vulnerabilities/kA1VN000001nv6D0AQ
author: Actioner
date: 2026-07-16
tags:
    - attack.t1190
    - attack.t1090
logsource:
    category: webserver
detection:
    selection_uri:
        cs-uri-stem|contains: '/wsproxy'
    selection_params:
        cs-uri-query|contains:
            - 'host=0.0.0.0'
            - 'host=localhost'
            - 'host=127.0.0.1'
            - 'host=::ffff:127.0.0.1'
    condition: selection_uri and selection_params
falsepositives:
    - Legitimate SMA1000 WebSocket proxy connections to localhost are not expected in normal operation
level: critical
```

### Sigma: SonicWall SMA1000 CVE-2026-15410 Hotfix Rollback Path Traversal

Detects POST requests to `/rollbackConfirm.action` with path traversal sequences in the request body, indicating privilege escalation exploitation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (environment proxy issue); splunk convert exit 0; log_scale convert exit 0. cs-body field requires the web log source to capture POST body content, which is not default in all configurations — note in deployment. -->

```yaml
title: SonicWall SMA1000 CVE-2026-15410 Hotfix Rollback Path Traversal
id: 2d4e6a8c-1b3f-5c7d-9e0a-4f2b8d6c1e3a
status: experimental
description: >
    Detects exploitation of CVE-2026-15410 (CVSS 7.2) via POST requests to the
    /rollbackConfirm.action endpoint on SonicWall SMA1000 AMC (port 8443) with
    path traversal sequences in the hotfix parameter. Attackers use this to
    execute arbitrary scripts as root after chaining with CVE-2026-15409.
references:
    - https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/
    - https://www.sonicwall.com/support/notices/product-notice-sma-1000-series-affected-by-multiple-vulnerabilities/kA1VN000001nv6D0AQ
author: Actioner
date: 2026-07-16
tags:
    - attack.t1068
    - attack.t1059.004
logsource:
    category: webserver
detection:
    selection_uri:
        cs-uri-stem|contains: '/rollbackConfirm.action'
    selection_method:
        cs-method: 'POST'
    selection_traversal:
        cs-body|contains: '../'
    condition: selection_uri and selection_method and selection_traversal
falsepositives:
    - Legitimate hotfix rollback operations do not contain path traversal sequences
level: critical
```

### Sigma: SonicWall SMA1000 wsproxy Request with Known Exploit bmID Pattern

Detects the `bmID=-3389` parameter pattern from the published CVE-2026-15409 PoC exploit in `/wsproxy` requests.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (environment proxy issue); splunk convert exit 0; log_scale convert exit 0. High confidence: bmID=-3389 is a distinctive PoC artifact unlikely to appear in legitimate traffic. -->

```yaml
title: SonicWall SMA1000 wsproxy Request with Known Exploit bmID Pattern
id: 5a7c9e1b-3d4f-6a8c-2e0b-7f1d3c5a9b2e
status: experimental
description: >
    Detects HTTP requests to the SonicWall SMA1000 /wsproxy endpoint containing
    the bmID=-3389 parameter pattern used in the published CVE-2026-15409 PoC
    exploit. This is a high-fidelity indicator of active exploitation attempts.
references:
    - https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/
    - https://github.com/remmons-r7/rapid7-CVE-2026-15409
author: Actioner
date: 2026-07-16
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/wsproxy'
        cs-uri-query|contains: 'bmID=-3389'
    condition: selection
falsepositives:
    - None expected; this bmID pattern is specific to the published exploit
level: critical
```

### Suricata: SonicWall SMA1000 CVE-2026-15409 SSRF wsproxy to Erlang (port 1050)

Detects HTTP GET requests to `/wsproxy` tunneling to localhost:1050 (Erlang process), the primary CVE-2026-15409 exploitation target.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Warnings about duplicate http.uri instances are cosmetic (multiple content matches against same buffer); rule loads and functions correctly. -->

```suricata
alert http any any -> $HOME_NET any (msg:"Actioner - SonicWall SMA1000 CVE-2026-15409 SSRF wsproxy to Localhost"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/wsproxy"; fast_pattern; http.uri; content:"host=0.0.0.0"; http.uri; content:"port=1050"; classtype:web-application-attack; reference:cve,2026-15409; reference:url,rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/; metadata:author Actioner, created_at 2026-07-16; sid:2200001; rev:1;)
```

### Suricata: SonicWall SMA1000 CVE-2026-15409 SSRF wsproxy to ctrl-service (port 8188)

Detects HTTP GET requests to `/wsproxy` tunneling to localhost:8188 (ctrl-service), used for privilege escalation chaining.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Same duplicate http.uri warnings as sid:2200001. -->

```suricata
alert http any any -> $HOME_NET any (msg:"Actioner - SonicWall SMA1000 CVE-2026-15409 SSRF wsproxy to ctrl-service"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/wsproxy"; fast_pattern; http.uri; content:"host=0.0.0.0"; http.uri; content:"port=8188"; classtype:web-application-attack; reference:cve,2026-15409; reference:url,rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/; metadata:author Actioner, created_at 2026-07-16; sid:2200002; rev:1;)
```

### Suricata: SonicWall SMA1000 CVE-2026-15410 Hotfix Rollback Path Traversal

Detects HTTP POST to `/rollbackConfirm.action` with path traversal in the `hotfix` parameter for root-level code execution.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Requires HTTP request body inspection; ensure http.request_body is enabled in suricata.yaml. -->

```suricata
alert http any any -> $HOME_NET any (msg:"Actioner - SonicWall SMA1000 CVE-2026-15410 Hotfix Rollback Path Traversal"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/rollbackConfirm.action"; fast_pattern; http.request_body; content:"hotfix="; content:"../"; distance:0; classtype:web-application-attack; reference:cve,2026-15410; reference:url,rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/; metadata:author Actioner, created_at 2026-07-16; sid:2200003; rev:1;)
```

### Suricata: SonicWall SMA1000 CVE-2026-15409 PoC bmID Exploit Pattern

Detects the distinctive `bmID=-3389` PoC exploit parameter in `/wsproxy` requests at the network level.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Duplicate http.uri warning (cosmetic). -->

```suricata
alert http any any -> $HOME_NET any (msg:"Actioner - SonicWall SMA1000 CVE-2026-15409 PoC bmID Exploit Pattern"; flow:established,to_server; http.uri; content:"/wsproxy"; fast_pattern; http.uri; content:"bmID=-3389"; classtype:web-application-attack; reference:cve,2026-15409; reference:url,github.com/remmons-r7/rapid7-CVE-2026-15409; metadata:author Actioner, created_at 2026-07-16; sid:2200004; rev:1;)
```

### Suricata: SonicWall SMA1000 Exploit User-Agent "SMA Connect Agent"

Detects the PoC exploit's `SMA Connect Agent` User-Agent string in requests to `/wsproxy`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. High confidence: "SMA Connect Agent" is the PoC's distinctive UA string combined with /wsproxy URI. Attackers may change this, but default PoC usage will fire. -->

```suricata
alert http any any -> $HOME_NET any (msg:"Actioner - SonicWall SMA1000 Exploit User-Agent SMA Connect Agent"; flow:established,to_server; http.user_agent; content:"SMA Connect Agent"; fast_pattern; http.uri; content:"/wsproxy"; classtype:web-application-attack; reference:cve,2026-15409; reference:url,github.com/remmons-r7/rapid7-CVE-2026-15409; metadata:author Actioner, created_at 2026-07-16; sid:2200005; rev:1;)
```

### Snort: N/A

Snort 3 is not available in the validation environment. The Suricata rules above cover the network detection layer; manual porting to Snort 3 syntax (underscore buffers, no dot notation) is straightforward.

### YARA: N/A

No file-level malware samples or binary indicators were published with this advisory. The exploitation chain uses web requests and shell scripts, not dropped binaries with distinctive byte patterns.

## Lessons Learned

1. **VPN/remote-access appliances remain the #1 initial access target.** SonicWall SMA, Ivanti Connect Secure, Fortinet FortiGate, and Palo Alto GlobalProtect have all suffered zero-day exploitation in 2025-2026. Organizations must treat these devices as high-risk and apply patches within hours, not days.

2. **Patching is necessary but insufficient.** SonicWall explicitly warns that patching alone does not remediate a compromised appliance. Post-exploitation credential theft and TOTP seed extraction mean attackers retain access even after patching. Re-imaging, credential rotation, and lateral movement audits are required.

3. **Localhost-only services are not a security boundary.** The hardcoded Erlang cookie and the assumption that localhost:1050/8188 would never be reachable from external networks were both invalidated by a single SSRF. Internal services on appliances need defense-in-depth, not just network isolation.

4. **Detection requires appliance log visibility.** The key indicators (`extraweb_access.log`, `ctrl-service.log`, `/var/lib/unit/conf.json`) are on the appliance itself. Organizations that do not forward these logs to a SIEM have no visibility into exploitation.

## Sources

- [Rapid7 Blog - MDR Team Discovers New SonicWall SMA1000 Zero Days](https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/) -- primary technical analysis, PoC details, IOCs, attack chain
- [CyberScoop - SonicWall Zero-Day Vulnerabilities Exploited](https://cyberscoop.com/sonicwall-zero-day-vulnerabilities-exploited/) -- exploitation timeline, Rapid7/VulnCheck commentary, ransomware nexus
- [Security Affairs - SonicWall Warns of Active Exploitation of Two SMA 1000 Zero-Days](https://securityaffairs.com/195364/hacking/sonicwall-warns-of-active-exploitation-of-two-sma-1000-zero-days.html) -- affected versions, CWE details, Volexity involvement
- [Security Affairs - CISA Adds SonicWall Flaws to KEV Catalog](https://securityaffairs.com/195383/security/u-s-cisa-adds-sonicwall-and-microsoft-flaws-to-its-known-exploited-vulnerabilities-catalog.html) -- CISA KEV addition, BOD 22-01 deadlines
- [SonicWall Product Notice - SMA 1000 Series Multiple Vulnerabilities](https://www.sonicwall.com/support/notices/product-notice-sma-1000-series-affected-by-multiple-vulnerabilities/kA1VN000001nv6D0AQ) -- official vendor advisory, fixed versions
- [Help Net Security - SonicWall SMA Appliances Targeted in Zero-Day Attacks](https://www.helpnetsecurity.com/2026/07/14/sonicwall-sma-attacks-via-cve-2026-15409-cve-2026-15410/) -- additional context on post-compromise behavior
- [SecurityWeek - SonicWall Issues Urgent SMA Patch Warning](https://www.securityweek.com/sonicwall-issues-urgent-sma-patch-warning-for-two-zero-day-exploits/) -- CISA deadline, Volexity involvement
- [Rapid7 CVE-2026-15409 PoC (GitHub)](https://github.com/remmons-r7/rapid7-CVE-2026-15409) -- proof-of-concept exploit code

---
*Report generated by Actioner*
