<!-- REVISION LOG (2026-09-03):
  - Fix 1: Sigma Rule 2 — changed ATT&CK tag from attack.t1059 to attack.t1505.003 (webshell, not command execution); removed CVE tag cve.2026.83549 (post-exploitation artifact, not direct CVE indicator).
  - Fix 2: YARA Rule 16 (KNUCKLEBALL) — removed bogus uint32(0)==0x6F707974 magic check; added explicit parentheses for operator precedence; confidence dropped to medium.
  - Fix 3: YARA Rule 18 (ROOTRUN) — removed entirely; replaced with behavioral rule using setuid syscall patterns, path strings, and ELF characteristics.
  - Fix 4: YARA Rule 19 (Suo5) — confidence dropped to low; added caveat about generic strings.
  - Fix 5: MITRE ATT&CK table — corrected T1547.004 (Winlogon Helper DLL) to T1037.004 (RC Scripts).
  - Fix 6: Sigma Rule 2 — removed cve.2026.83549 tag (ORANGETAIL is post-exploitation, not a direct CVE-2026-83549 indicator).
-->
# SonicWall SMA 1000 Chained Zero-Day Vulnerabilities (CVE-2026-83548, CVE-2026-83549)

**Date:** 2026-09-03
**Status:** FINAL
**Author:** Actioner
**TLP:** CLEAR

---

## Executive Summary

On September 1, 2026, SonicWall disclosed two actively exploited zero-day vulnerabilities in SMA 1000 series appliances (models 6210, 7210, 8200v). CVE-2026-83548 is a critical (CVSS 10.0) pre-authentication server-side request forgery (SSRF) in the Appliance Work Place interface. CVE-2026-83549 is a high-severity (CVSS 7.8) post-authentication OS command injection in the Appliance Management Console (AMC). Threat actors are chaining both vulnerabilities to achieve unauthenticated remote code execution on vulnerable appliances. No workarounds exist; organizations must apply hotfix 12.4.3-03526 or 12.5.0-02952 immediately. This is the third round of exploitation targeting SMA 1000 appliances in 2026, following CVE-2026-15409/CVE-2026-15410, which were exploited by UTA0533 beginning June 22, 2026 to deploy the KNUCKLEBALL malware ecosystem.

---

## Background

### Product Context

SonicWall Secure Mobile Access (SMA) 1000 is an enterprise VPN gateway used for remote access. The affected models — SMA 6210, 7210, and 8200v — are deployed across government, critical infrastructure, and enterprise environments. SMA 100 series appliances and SonicWall firewalls' SSL-VPN feature are **not** affected.

### Vulnerability Timeline

| Date | Event |
|------|-------|
| 2026-06-22 | First observed exploitation of CVE-2026-15409/15410 by UTA0533 |
| 2026-07-14 | SonicWall releases hotfixes 12.4.3-03453 and 12.5.0-02835 for CVE-2026-15409/15410 |
| 2026-07-17 | Volexity publishes technical analysis of UTA0533 / KNUCKLEBALL campaign |
| 2026-08-XX | INC ransomware group begins exploiting SMA 1000 flaws |
| 2026-09-01 | SonicWall discloses CVE-2026-83548/83549 — new zero-days in the same components, actively exploited |
| 2026-09-02 | CISA and security vendors publish advisories |

### Prior Exploitation History

The same SMA 1000 components were targeted via CVE-2026-15409 (SSRF in WorkPlace) and CVE-2026-15410 (command injection in AMC), patched in July 2026. Threat group UTA0533 chained those earlier flaws to deploy the KNUCKLEBALL dropper, Suo5 reverse proxy, ORANGETAIL webshell, and ROOTRUN privilege escalation tool. The September 2026 CVEs (83548/83549) target the same functional areas, suggesting the July patches were bypassed or incomplete. Organizations that patched to 12.4.3-03453 or 12.5.0-02835 remain vulnerable to the new CVEs.

---

## Technical Analysis

### CVE-2026-83548 — Pre-Authentication SSRF (CVSS 10.0)

- **Component:** Appliance Work Place interface
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Authentication:** None required
- **Description:** A pre-authentication SSRF flaw enables a remote unauthenticated attacker to access sensitive functionality and perform unauthorized operations. The appliance can be made to function as an unintended forward proxy.

Based on the analogous CVE-2026-15409, the exploitation pattern targets the `/wsproxy` endpoint. Attackers send crafted WebSocket upgrade requests with:
- `bmID` parameter beginning with `-3389`
- `User-Agent: SMA Connect Agent`
- `host` parameter set to loopback addresses (`0.0.0.0`, `127.0.0.1`, `::ffff:127.0.0.1`, `localhost`)
- `port` parameter targeting internal services: `1050` (CouchDB/Erlang), `1051` (EPMD), or `8188` (control service)

A successful request returns HTTP 101 (Switching Protocols), establishing a WebSocket tunnel to localhost-only services. CouchDB ships with hardcoded credentials `admin:admin` and is accessible at port 1050 through this tunnel.

### CVE-2026-83549 — Post-Authentication Command Injection (CVSS 7.8)

- **Component:** Appliance Management Console (AMC)
- **CWE:** CWE-78 (OS Command Injection)
- **Authentication:** Administrator (bypassed via SSRF chain)
- **Description:** Improper neutralization of special elements enables a remote attacker authenticated as an administrator to execute arbitrary OS commands, resulting in remote code execution.

Based on the analogous CVE-2026-15410, the exploitation path involves:
1. Using the SSRF tunnel to query CouchDB and obtain the appliance's `product_uuid` from `/sys/class/dmi/id/product_uuid`
2. Deriving the control service authentication password (UUID with dashes removed, Base64-encoded)
3. Exploiting path traversal in the `sysCtrl.execRemoveHotfix` RPC method via `POST /rollbackConfirm.action`
4. Payload: `hotfix=../../../../../tmp/<script>.sh` — the service constructs `/var/lib/aventail/avp/rollback/../../../../../tmp/<script>.sh`, resolving outside the intended directory
5. The script executes as **root** without path validation

### Attack Chain Summary

```
Attacker → GET /wsproxy (SSRF, CVE-2026-83548)
    → WebSocket tunnel to localhost:1050 (CouchDB)
        → Obtain product_uuid, stage payload script
    → WebSocket tunnel to localhost:8188 (control service)
        → POST /rollbackConfirm.action with path traversal (CVE-2026-83549)
            → Root-level code execution
                → Deploy malware (KNUCKLEBALL → Suo5 + ORANGETAIL)
                → Establish persistence
                → Credential harvesting & lateral movement
```

### Affected Versions

| Branch | Vulnerable | Patched |
|--------|-----------|---------|
| 12.4.x | 12.4.3-03453 and earlier | **12.4.3-03526** |
| 12.5.x | 12.5.0-02835 and earlier | **12.5.0-02952** |

Firmware versions previously listed as patched for CVE-2026-15409/15410 (12.4.3-03453, 12.5.0-02835) are **vulnerable** to CVE-2026-83548/83549.

---

## Indicators of Compromise

> **Viability Gate Note:** SonicWall's advisory for CVE-2026-83548/83549 does not include IOCs. The indicators below are drawn from the documented UTA0533/KNUCKLEBALL campaign (CVE-2026-15409/15410), which targets the same components and attack surfaces. These IOCs remain relevant for detecting both current and prior exploitation. Confidence is assessed per indicator.

### Network Indicators

| Indicator | Type | Context | Confidence |
|-----------|------|---------|------------|
| 42[.]200[.]172[.]14 | IPv4 | Attack source (UTA0533) | Medium |
| 81[.]19[.]140[.]217 | IPv4 | Attack source (UTA0533) | Medium |
| 89[.]117[.]20[.]1 | IPv4 | Attack source (UTA0533) | Medium |
| 108[.]205[.]8[.]173 | IPv4 | Attack source (UTA0533) | Medium |
| 147[.]45[.]51[.]19 | IPv4 | Attack source (UTA0533) | Medium |
| 150[.]241[.]210[.]53 | IPv4 | Attack source (UTA0533) | Medium |
| 202[.]8[.]105[.]201 | IPv4 | Attack source (UTA0533) | Medium |
| 217[.]77[.]15[.]99 | IPv4 | Attack source (UTA0533) | Medium |
| 193[.]37[.]32[.]179 | IPv4 | F.N.S Holdings Ltd (ASN 206092) | Medium |
| 193[.]37[.]32[.]214 | IPv4 | F.N.S Holdings Ltd (ASN 206092) | Medium |
| 45[.]131[.]194[.]0/24 | CIDR | F.N.S Holdings Ltd infrastructure | Low |
| 45[.]146[.]54[.]0/24 | CIDR | F.N.S Holdings Ltd infrastructure | Low |
| helprans[.]com | Domain | Attacker-registered domain | High |

> **Note:** Over 200 different source IPs were observed, many through commercial VPN services (ExpressVPN, MullvadVPN). IP-based indicators are supplementary and should not be used as sole detection criteria.

### File Indicators

| File | Path | SHA256 | MD5 |
|------|------|--------|-----|
| KNUCKLEBALL dropper | /usr/lib/python3.11/site-packages/deploy_new.py | `8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3` | `b6df166291f80ee89032d769c99714f3` |
| Suo5 proxy agent | /tmp/agent_wp8.jar | `1e1e68bbb899450a57274a8b12082ed4e2040a2aae77014f20431689d2b4edee` | `54d21399b8b52b48a0fef68450593e45` |
| ORANGETAIL webshell | /tmp/agent_wp9.jar | `ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081` | `5f3a55201c511c9ff9be4c16c41028a2` |
| ROOTRUN setuid binary | /usr/bin/xzfind | `81a9af3846bad3a1107164ff7cf0a08e020b31a3b32fd17866e17d4c1565f7f2` | `5cb00bbfe818ee3e85fb99ab1db1af7c` |

### Host Indicators

| Indicator | Context |
|-----------|---------|
| `/tmp/1234.sh` | Staged privilege escalation script |
| `/tmp/hypdate.b64` | Encoded CVE-2026-15410 payload |
| `/var/tmp/lib.sh` | tcpdump LDAP sniffer script |
| `/etc/init.d/workplace` modified to invoke `deploy_new.py` | KNUCKLEBALL persistence |
| `/var/lib/unit/conf.json` with routes to `127.0.0.1:8085` | NGINX Unit config hijacking |
| `/__api__/login` and `/__api__/logout` endpoints responding HTTP 200 | Webshell reverse proxy routes (non-standard; indicate compromise) |
| Unexpected setuid binaries outside baseline (`find / -perm -4000`) | ROOTRUN or variants |

### User-Agent Indicators

| User-Agent | Context |
|------------|---------|
| `SMA Connect Agent` | Used in /wsproxy SSRF exploitation |
| `Mozilla/6.0 (Windows NT 11.0; Win64; x64) AppleWebKit/1537.136 (KHTML, like Gecko) Chrome/149.0.0.1 Safari/1537.136` | ORANGETAIL webshell gating string (fabricated version numbers) |

### Log File Locations for Forensic Review

| Log Path | What to Look For |
|----------|-----------------|
| `/var/log/aventail/extraweb_access.log` | `GET /wsproxy` with `bmID=-3389`, HTTP 101 responses |
| `/var/log/aventail/extraweb_access.log` | POST to `/__api__/login` or `/__api__/logout` |
| `/var/log/aventail/ctrl-service.log` | `hotfix removal` entries containing `../` |
| `/var/log/aventail/access_servers.log` | `WEBSOCK` entries with connections to port 1050 or 8188 |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Application |
|-------------|----------------|-------------|
| T1190 | Exploit Public-Facing Application | SSRF via /wsproxy (CVE-2026-83548) to establish tunnels to internal services |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Root command execution via sysCtrl.execRemoveHotfix path traversal (CVE-2026-83549) |
| T1059.006 | Command and Scripting Interpreter: Python | KNUCKLEBALL dropper (`deploy_new.py`) |
| T1505.003 | Server Software Component: Web Shell | ORANGETAIL webshell; Suo5 reverse proxy |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | ROOTRUN (`xzfind`) setuid binary |
| T1037.004 | Boot or Logon Initialization Scripts: RC Scripts | Persistence via `/etc/init.d/workplace` modification |
| T1090 | Proxy | Suo5 agent for traffic tunneling through compromised appliance |
| T1040 | Network Sniffing | tcpdump capturing unencrypted LDAP traffic on TCP/389 |
| T1552.001 | Unsecured Credentials: Credentials In Files | Reading CouchDB credential stores and product_uuid |
| T1105 | Ingress Tool Transfer | Deployment of JAR files and Python scripts to compromised appliance |

---

## Detection Rules

### Viability Gate Assessment

| Criterion | Status |
|-----------|--------|
| Vendor advisory with technical details | Partial — describes components but no exploitation specifics |
| Public PoC or exploit code | Not available for CVE-2026-83548/83549 |
| IOCs from prior campaign (same components) | Available — extensive from CVE-2026-15409/15410 |
| Observable network patterns | Available — /wsproxy endpoint, User-Agent strings, WebSocket upgrades |
| Observable host artifacts | Available — file paths, hashes, persistence mechanisms |

**Assessment:** Sufficient concrete artifacts exist for production-ready detections based on the documented exploitation patterns from the analogous CVE-2026-15409/15410 campaign. The same components (WorkPlace SSRF + AMC command injection) are involved, making these patterns directly applicable. Rules are labeled at PoC/advisory-specific altitude.

---

### Sigma Rules

#### 1. SonicWall SMA 1000 SSRF Exploitation via wsproxy Endpoint

Detects HTTP requests to the /wsproxy endpoint with bmID=-3389 parameter, the documented exploitation pattern for SMA 1000 pre-authentication SSRF.

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** high

<!-- audit: sigma convert --without-pipeline -t splunk: OK; sigma convert --without-pipeline -t log_scale: OK. sigma check unavailable (MITRE data fetch blocked). YAML parse: OK. -->

```yaml
title: SonicWall SMA 1000 SSRF Exploitation via wsproxy Endpoint
id: 7a3e1c4f-8d2b-4e6a-9f1c-3b5a7d9e2f4c
status: experimental
description: Detects HTTP requests targeting the SonicWall SMA 1000 /wsproxy endpoint with the bmID parameter beginning with -3389, indicating exploitation of pre-authentication SSRF vulnerabilities (CVE-2026-83548, CVE-2026-15409).
references:
    - https://psirt.global.sonicwall.com/vuln-list
    - https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
    - https://www.resecurity.com/blog/article/from-wsproxy-to-root-inc-ransomware-and-sonicwall-sma-exploit-chain
author: Actioner
date: 2026/09/03
tags:
    - attack.t1190
    - cve.2026.83548
    - cve.2026.15409
logsource:
    category: webserver
    product: sonicwall
detection:
    selection:
        cs-uri-query|contains: 'bmID=-3389'
        cs-uri-stem|contains: '/wsproxy'
    condition: selection
falsepositives:
    - Legitimate SMA Connect Agent activity may generate similar requests but should be validated against known client IPs
level: high
```

#### 2. ORANGETAIL Webshell Access via Anomalous User-Agent

Detects HTTP requests carrying the fabricated User-Agent string (Chrome/149.0.0.1) used as a gating mechanism by the ORANGETAIL webshell.

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** high

<!-- audit: sigma convert --without-pipeline -t splunk: OK; sigma convert --without-pipeline -t log_scale: OK. -->

```yaml
title: ORANGETAIL Webshell Access via Anomalous User-Agent
id: 2b8f3d5e-1a4c-4b7d-8e9f-6c2a1d7e3f5b
status: experimental
description: Detects HTTP requests with the implausible User-Agent string used by ORANGETAIL webshell on compromised SonicWall SMA 1000 appliances. The User-Agent contains fabricated version numbers (Windows NT 11.0, Chrome 149.0.0.1) used as a gating mechanism.
references:
    - https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
    - https://www.resecurity.com/blog/article/from-wsproxy-to-root-inc-ransomware-and-sonicwall-sma-exploit-chain
author: Actioner
date: 2026/09/03
tags:
    - attack.t1505.003
    - cve.2026.15410
logsource:
    category: webserver
detection:
    selection:
        c-useragent|contains: 'Chrome/149.0.0.1'
    condition: selection
falsepositives:
    - None expected. This User-Agent string contains fabricated version numbers and is not generated by any legitimate browser.
level: critical
```

#### 3. SonicWall SMA 1000 Webshell Access via Injected API Endpoints

Detects POST requests to /__api__/login or /__api__/logout, non-standard endpoints injected by KNUCKLEBALL malware through NGINX Unit config hijacking.

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** high

<!-- audit: sigma convert --without-pipeline -t splunk: OK; sigma convert --without-pipeline -t log_scale: OK. -->

```yaml
title: SonicWall SMA 1000 Webshell Access via Injected API Endpoints
id: 4d6e8f1a-2c3b-4a5d-9e7f-1b8c2d3e4f6a
status: experimental
description: Detects HTTP POST requests to /__api__/login or /__api__/logout endpoints on SonicWall SMA 1000 appliances. These are non-standard endpoints injected by KNUCKLEBALL malware through NGINX Unit configuration hijacking and serve as reverse proxy routes to ORANGETAIL and Suo5 webshells.
references:
    - https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
    - https://www.resecurity.com/blog/article/from-wsproxy-to-root-inc-ransomware-and-sonicwall-sma-exploit-chain
author: Actioner
date: 2026/09/03
tags:
    - attack.t1505.003
    - cve.2026.83549
logsource:
    category: webserver
    product: sonicwall
detection:
    selection:
        cs-uri-stem|contains:
            - '/__api__/login'
            - '/__api__/logout'
        cs-method: 'POST'
    condition: selection
falsepositives:
    - These endpoints are not part of legitimate SonicWall SMA firmware. Their presence indicates compromise.
level: critical
```

#### 4. SonicWall SMA 1000 Command Injection via Hotfix Rollback Path Traversal

Detects path traversal patterns in ctrl-service logs indicating exploitation of the sysCtrl.execRemoveHotfix RPC method for root-level command execution.

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** high

<!-- audit: sigma convert --without-pipeline -t splunk: OK; sigma convert --without-pipeline -t log_scale: OK. Fixed YAML parse error in |all: construct on attempt 2. -->

```yaml
title: SonicWall SMA 1000 Command Injection via Hotfix Rollback Path Traversal
id: 9f1e2d3c-4b5a-6c7d-8e9f-0a1b2c3d4e5f
status: experimental
description: Detects path traversal patterns in SonicWall SMA 1000 ctrl-service logs indicating exploitation of the sysCtrl.execRemoveHotfix RPC method for arbitrary command execution as root (CVE-2026-83549, CVE-2026-15410).
references:
    - https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
    - https://www.resecurity.com/blog/article/from-wsproxy-to-root-inc-ransomware-and-sonicwall-sma-exploit-chain
author: Actioner
date: 2026/09/03
tags:
    - attack.t1059.004
    - cve.2026.83549
    - cve.2026.15410
logsource:
    product: sonicwall
    service: ctrl-service
detection:
    selection_hotfix:
        message|contains: 'hotfix removal'
    selection_traversal:
        message|contains: '../'
    condition: selection_hotfix and selection_traversal
falsepositives:
    - None expected. Legitimate hotfix rollback operations do not contain path traversal sequences.
level: critical
```

#### 5. KNUCKLEBALL Malware File Artifacts on SonicWall SMA 1000

Detects file creation events for artifacts associated with KNUCKLEBALL dropper and its payloads (Suo5, ORANGETAIL, ROOTRUN).

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** high

<!-- audit: sigma convert --without-pipeline -t splunk: OK; sigma convert --without-pipeline -t log_scale: OK. -->

```yaml
title: KNUCKLEBALL Malware File Artifacts on SonicWall SMA 1000
id: 5e7f9a1b-3c4d-2e6f-8a0b-1c2d3e4f5a6b
status: experimental
description: Detects creation or presence of file artifacts associated with KNUCKLEBALL malware dropper and associated payloads (Suo5, ORANGETAIL, ROOTRUN) on SonicWall SMA 1000 appliances.
references:
    - https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
    - https://www.resecurity.com/blog/article/from-wsproxy-to-root-inc-ransomware-and-sonicwall-sma-exploit-chain
author: Actioner
date: 2026/09/03
tags:
    - attack.t1105
    - attack.t1059.006
logsource:
    category: file_event
    product: linux
detection:
    selection_knuckleball:
        TargetFilename|endswith: '/site-packages/deploy_new.py'
    selection_agents:
        TargetFilename|endswith:
            - '/agent_wp8.jar'
            - '/agent_wp9.jar'
    selection_rootrun:
        TargetFilename|endswith: '/xzfind'
        TargetFilename|contains: '/usr/bin/'
    condition: selection_knuckleball or selection_agents or selection_rootrun
falsepositives:
    - None expected. These filenames are specific to the KNUCKLEBALL malware ecosystem.
level: critical
```

---

### Suricata Rules

#### 6. SonicWall SMA 1000 SSRF via wsproxy with SMA Connect Agent

Detects exploitation of the /wsproxy SSRF with the bmID=-3389 parameter and SMA Connect Agent User-Agent, the documented exploitation pattern for CVE-2026-83548.

**Status:** ✅ compiles (suricata -T) | **Confidence:** high

<!-- audit: suricata -T -S suricata_sonicwall_wsproxy.rules: "Configuration provided was successfully loaded. Exiting." All 6 rules loaded. -->

```
alert http any any -> any any (msg:"Actioner - SonicWall SMA 1000 SSRF Exploitation via wsproxy (CVE-2026-83548)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/wsproxy"; content:"bmID=-3389"; http.user_agent; content:"SMA Connect Agent"; classtype:web-application-attack; sid:2200001; rev:1; metadata: author Actioner, created_at 2026-09-03, cve CVE-2026-83548, mitre_attack T1190;)
```

#### 7. SonicWall SMA 1000 wsproxy Tunnel to CouchDB Port 1050

Detects /wsproxy requests targeting CouchDB on port 1050, used to extract credentials and the product_uuid needed for the command injection stage.

**Status:** ✅ compiles (suricata -T) | **Confidence:** high

<!-- audit: suricata -T validated. -->

```
alert http any any -> any any (msg:"Actioner - SonicWall SMA 1000 wsproxy Tunnel to CouchDB Port 1050 (CVE-2026-83548)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/wsproxy"; content:"port=1050"; http.user_agent; content:"SMA Connect Agent"; classtype:web-application-attack; sid:2200002; rev:1; metadata: author Actioner, created_at 2026-09-03, cve CVE-2026-83548, mitre_attack T1190;)
```

#### 8. SonicWall SMA 1000 wsproxy Tunnel to Control Service Port 8188

Detects /wsproxy requests targeting the control service on port 8188, the second stage of exploitation for command injection via sysCtrl.execRemoveHotfix.

**Status:** ✅ compiles (suricata -T) | **Confidence:** high

<!-- audit: suricata -T validated. -->

```
alert http any any -> any any (msg:"Actioner - SonicWall SMA 1000 wsproxy Tunnel to Control Service Port 8188 (CVE-2026-83548)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/wsproxy"; content:"port=8188"; http.user_agent; content:"SMA Connect Agent"; classtype:web-application-attack; sid:2200003; rev:1; metadata: author Actioner, created_at 2026-09-03, cve CVE-2026-83548, mitre_attack T1190;)
```

#### 9. ORANGETAIL Webshell Anomalous User-Agent Detection

Detects the fabricated Chrome/149.0.0.1 User-Agent string used as the gating mechanism for ORANGETAIL webshell access.

**Status:** ✅ compiles (suricata -T) | **Confidence:** high

<!-- audit: suricata -T validated. -->

```
alert http any any -> any any (msg:"Actioner - ORANGETAIL Webshell Anomalous User-Agent (Chrome/149.0.0.1)"; flow:established,to_server; http.user_agent; content:"Chrome/149.0.0.1"; classtype:trojan-activity; sid:2200004; rev:1; metadata: author Actioner, created_at 2026-09-03, mitre_attack T1505.003;)
```

#### 10. SonicWall SMA 1000 Webshell API Endpoint Access

Detects POST requests to the /__api__/log prefix, which matches the injected /__api__/login and /__api__/logout webshell routes.

**Status:** ✅ compiles (suricata -T) | **Confidence:** medium

<!-- audit: suricata -T validated. Partial URI match on "/__api__/log" catches both /login and /logout. Medium confidence because legitimate APIs could theoretically use this path prefix on non-SMA systems. -->

```
alert http any any -> any any (msg:"Actioner - SonicWall SMA 1000 Webshell API Endpoint Access"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/__api__/log"; classtype:trojan-activity; sid:2200005; rev:1; metadata: author Actioner, created_at 2026-09-03, mitre_attack T1505.003;)
```

#### 11. SonicWall SMA 1000 Hotfix Rollback Path Traversal

Detects POST requests to /rollbackConfirm.action containing path traversal sequences in the request body, indicating exploitation of CVE-2026-83549.

**Status:** ✅ compiles (suricata -T) | **Confidence:** high

<!-- audit: suricata -T validated. -->

```
alert http any any -> any any (msg:"Actioner - SonicWall SMA 1000 Hotfix Rollback Path Traversal (CVE-2026-83549)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/rollbackConfirm.action"; http.request_body; content:"../../../"; classtype:web-application-attack; sid:2200006; rev:1; metadata: author Actioner, created_at 2026-09-03, cve CVE-2026-83549, mitre_attack T1059.004;)
```

---

### Snort Rules

#### 12. SonicWall SMA 1000 SSRF via wsproxy with bmID=-3389

Detects the wsproxy SSRF exploitation pattern with bmID=-3389 and SMA Connect Agent User-Agent.

**Status:** ⚠️ uncompiled (structural check only) | **Confidence:** high

```
alert tcp any any -> any any (msg:"Actioner - SonicWall SMA 1000 SSRF via wsproxy with bmID=-3389 (CVE-2026-83548)"; flow:established,to_server; content:"GET"; http_method; content:"/wsproxy"; http_uri; content:"bmID=-3389"; http_uri; content:"SMA Connect Agent"; http_header; classtype:web-application-attack; sid:2100001; rev:1; metadata: author Actioner, created_at 2026-09-03;)
```

#### 13. ORANGETAIL Webshell Anomalous User-Agent

Detects the fabricated Chrome/149.0.0.1 User-Agent used for ORANGETAIL webshell gating.

**Status:** ⚠️ uncompiled (structural check only) | **Confidence:** high

```
alert tcp any any -> any any (msg:"Actioner - ORANGETAIL Webshell Anomalous User-Agent (Chrome/149.0.0.1)"; flow:established,to_server; content:"Chrome/149.0.0.1"; http_header; classtype:trojan-activity; sid:2100002; rev:1; metadata: author Actioner, created_at 2026-09-03;)
```

#### 14. SonicWall SMA 1000 Webshell API Endpoint Access

Detects POST requests to the injected /__api__/log endpoints.

**Status:** ⚠️ uncompiled (structural check only) | **Confidence:** medium

```
alert tcp any any -> any any (msg:"Actioner - SonicWall SMA 1000 Webshell API Endpoint Access"; flow:established,to_server; content:"POST"; http_method; content:"/__api__/log"; http_uri; classtype:trojan-activity; sid:2100003; rev:1; metadata: author Actioner, created_at 2026-09-03;)
```

#### 15. SonicWall SMA 1000 Hotfix Rollback Path Traversal

Detects path traversal in requests to /rollbackConfirm.action.

**Status:** ⚠️ uncompiled (structural check only) | **Confidence:** high

```
alert tcp any any -> any any (msg:"Actioner - SonicWall SMA 1000 Hotfix Rollback Path Traversal (CVE-2026-83549)"; flow:established,to_server; content:"POST"; http_method; content:"/rollbackConfirm.action"; http_uri; content:"../../../"; http_client_body; classtype:web-application-attack; sid:2100004; rev:1; metadata: author Actioner, created_at 2026-09-03;)
```

---

### YARA Rules

#### 16. KNUCKLEBALL Dropper Detection

Detects the KNUCKLEBALL Python dropper (deploy_new.py) based on string patterns related to Java agent deployment and payload file names.

**Status:** ✅ compiles (yarac) | **Confidence:** medium

<!-- audit: yarac: exit 0. Revision: removed bogus uint32(0)==0x6F707974 magic ("typo" in LE, not a valid Python signature); added explicit parentheses to fix operator precedence so both branches require the magic-byte guard; confidence dropped to medium. -->

```yara
rule KNUCKLEBALL_Dropper {
    meta:
        description = "Detects KNUCKLEBALL malware dropper (deploy_new.py) used in SonicWall SMA 1000 exploitation by UTA0533"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3"
        mitre_attack = "T1059.006"
    strings:
        $s1 = "deploy_new" ascii
        $s2 = "agent_wp8" ascii
        $s3 = "agent_wp9" ascii
        $s4 = "CommandStartup" ascii
        $s5 = "Java Attach" ascii wide
        $jar1 = "agent_wp8.jar" ascii
        $jar2 = "agent_wp9.jar" ascii
    condition:
        (uint16(0) == 0x2123 and 3 of ($s*)) or
        (uint16(0) == 0x2123 and all of ($jar*) and 1 of ($s*))
}
```

#### 17. ORANGETAIL Webshell Detection

Detects the ORANGETAIL Java webshell based on its gating User-Agent string and AES encryption characteristics.

**Status:** ✅ compiles (yarac) | **Confidence:** high

<!-- audit: yarac: exit 0. -->

```yara
rule ORANGETAIL_Webshell {
    meta:
        description = "Detects ORANGETAIL Java webshell used in SonicWall SMA 1000 post-exploitation"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
        mitre_attack = "T1505.003"
    strings:
        $s1 = "errorDialog_jsp" ascii
        $s2 = "AES" ascii wide
        $s3 = "ECB" ascii wide
        $ua = "Chrome/149.0.0.1" ascii
        $jar_magic = { 50 4B 03 04 }
    condition:
        $jar_magic at 0 and
        ($ua or ($s1 and $s2 and $s3))
}
```

#### 18. ROOTRUN Setuid Binary Detection

Detects the ROOTRUN setuid privilege-escalation binary (xzfind) based on behavioral strings: the binary sets effective UID 0 via setuid/setgid, references the specific disguised path `/usr/bin/xzfind`, and executes shell commands. Targets small ELF binaries consistent with the known sample.

**Status:** ✅ compiles (yarac) | **Confidence:** medium

<!-- audit: Revision: original rule used the file's own SHA256 as an in-binary hex string, which is logically impossible (a file cannot contain its own hash). Replaced with behavioral strings from ROOTRUN: setuid/setgid syscall patterns, path strings, shell invocation. yarac: exit 0. -->

```yara
rule ROOTRUN_Setuid_Binary {
    meta:
        description = "Detects ROOTRUN setuid binary (xzfind) used for privilege escalation on compromised SonicWall SMA 1000 appliances"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://www.resecurity.com/blog/article/from-wsproxy-to-root-inc-ransomware-and-sonicwall-sma-exploit-chain"
        hash = "81a9af3846bad3a1107164ff7cf0a08e020b31a3b32fd17866e17d4c1565f7f2"
        mitre_attack = "T1548.001"
    strings:
        $path1 = "/usr/bin/xzfind" ascii
        $setuid = "setuid" ascii
        $setgid = "setgid" ascii
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $exec1 = "execve" ascii
        $exec2 = "system" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 50KB and
        $path1 and
        1 of ($setuid, $setgid) and
        1 of ($shell*, $exec*)
}
```

#### 19. Suo5 Proxy Agent Detection

Detects the Suo5 (Sou5) reverse proxy agent used for post-exploitation traffic tunneling.

> **Caveat:** The strings in this rule (`error_jsp`, `workplace`, `CONNECT`, `tunnel`) are common in Java web applications with error handling and proxy functionality. No strings uniquely identifying Suo5 (e.g., unique class names or protocol markers) are available from public reporting. This rule should be used as a hunting lead, not as a sole indicator. Matches require manual validation.

**Status:** ✅ compiles (yarac) | **Confidence:** low

<!-- audit: yarac: exit 0. Revision: confidence dropped from medium to low; all strings are generic Java/web terms. Added caveat. -->

```yara
rule Suo5_Proxy_Agent {
    meta:
        description = "Detects Suo5 (Sou5) reverse proxy agent used in SonicWall SMA 1000 post-exploitation"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "1e1e68bbb899450a57274a8b12082ed4e2040a2aae77014f20431689d2b4edee"
        mitre_attack = "T1090"
        confidence = "low"
    strings:
        $s1 = "error_jsp" ascii
        $s2 = "workplace" ascii
        $jar_magic = { 50 4B 03 04 }
        $proxy1 = "CONNECT" ascii wide
        $proxy2 = "tunnel" ascii wide
    condition:
        $jar_magic at 0 and
        $s1 and $s2 and
        1 of ($proxy*)
}
```

---

## Remediation Guidance

### Immediate Actions

1. **Patch immediately** to firmware version **12.4.3-03526** or **12.5.0-02952** or higher
2. **Review logs** at the paths listed in the IOC section for indicators of exploitation
3. **Check file system** for artifacts listed in the host indicators table
4. **Audit setuid binaries** with `find / -perm -4000 -type f` and compare against known baseline

### If Compromise is Confirmed

1. **Re-image the appliance** from clean media — do not patch in place
2. **Reset all credentials** — user passwords, administrator passwords, TOTP/MFA seeds
3. **Rotate directory service credentials** that may have transited the compromised appliance (LDAP traffic may have been captured)
4. **Do not restore configuration** from backups unless backup pre-dates the affected firmware versions
5. **Investigate lateral movement** — review Active Directory Event ID 4624 (logon type 3) from the appliance's internal IP address
6. **Engage incident response** to scope internal network compromise before closure

### Monitoring Recommendations

- Deploy the Suricata rules from this report on network sensors monitoring traffic to/from SMA 1000 appliances
- Ingest SMA appliance logs (`extraweb_access.log`, `ctrl-service.log`, `access_servers.log`) into SIEM and deploy the Sigma rules
- Monitor for the ORANGETAIL gating User-Agent across all web proxy and WAF logs
- Scan SMA appliance file systems with the YARA rules during forensic triage

---

## Sources

- [SonicWall PSIRT Advisory](https://psirt.global.sonicwall.com/vuln-list)
- [The Hacker News - Attackers Exploit Two SonicWall SMA 1000 Zero-Days](https://thehackernews.com/2026/09/attackers-exploit-two-sonicwall-sma.html)
- [SecurityWeek - SonicWall Warns of Two SMA1000 Zero-Days Exploited in Attacks](https://www.securityweek.com/sonicwall-warns-of-two-sma1000-zero-days-exploited-in-attacks/)
- [Rapid7 - Critical SonicWall SMA1000 Vulnerabilities Exploited in the Wild](https://www.rapid7.com/blog/post/etr-critical-sonicwall-sma1000-vulnerabilities-cve-2026-83548-cve-2026-83549-exploited-in-the-wild/)
- [Sophos - SonicWall SMA1000 Vulnerabilities in Active Exploitation](https://www.sophos.com/en-us/blog/sonicwall-83548-83549)
- [Help Net Security - SonicWall SMA 1000 Appliances Under Attack via Zero-Day Flaws](https://www.helpnetsecurity.com/2026/09/02/sonicwall-sma-1000-cve-2026-83548-cve-2026-83549-zero-day-attacks/)
- [Security Affairs - SonicWall Patches Two New Actively Exploited Zero-Days in SMA 1000 VPNs](https://securityaffairs.com/198303/security/sonicwall-patches-two-new-actively-exploited-zero-days-in-sma-1000-vpns.html)
- [Volexity - Proxying to Compromise: SonicWall Secure Mobile Access 0-day Exploitation](https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/)
- [Resecurity - From WSProxy to Root: INC Ransomware and SonicWall SMA Exploit Chain](https://www.resecurity.com/blog/article/from-wsproxy-to-root-inc-ransomware-and-sonicwall-sma-exploit-chain)
- [Cybersecurity Dive - Researchers Trace SonicWall SMA1000 Exploitation to Late June](https://www.cybersecuritydive.com/news/researchers-sonicwall-sma1000-exploitation-june/825654/)
- [Triskele Labs - Critical SonicWall SMA 1000 Zero-Day Vulnerabilities](https://www.triskelelabs.com/resources/critical-sonicwall-sma-1000-zero-day-vulnerabilities-patch-and-investigate-for-compromise-cve-2026-15409-cve-2026-15410)

---

*FINAL report generated by Actioner on 2026-09-03. Revised per critic review on 2026-09-03.*
