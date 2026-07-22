# Technical Analysis Report: SonicWall SMA 1000 Zero-Day Exploitation by UTA0533 (2026-07-22)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-22
Version: 1.0 (DRAFT)

## Executive Summary

Volexity discovered and disclosed active zero-day exploitation of SonicWall SMA 1000 series VPN appliances by a previously undocumented threat actor tracked as UTA0533. Two vulnerabilities were chained: CVE-2026-15409, a critical (CVSS 10.0) pre-authentication server-side request forgery (SSRF) in the `/wsproxy` endpoint of the Workplace interface, and CVE-2026-15410, a high-severity (CVSS 7.2) post-authentication code injection flaw in the Appliance Management Console's `remove_hotfix` workflow. Exploitation began no later than June 22, 2026 -- weeks before SonicWall's public disclosure on July 14 and patch release during the week of July 20. UTA0533 deployed four custom tools on compromised appliances: ROOTRUN (setuid privilege escalation binary), KNUCKLEBALL (Python-based JAR injector), Suo5 (open-source HTTP forwarding proxy), and ORANGETAIL (custom Behinder-like Java web shell). Persistence was achieved through startup script modification, NGINX Unit configuration tampering, and in-memory Java agent injection. A secondary appliance was used for credential interception via tcpdump capture of unencrypted LDAP traffic. CISA added both CVEs to the Known Exploited Vulnerabilities (KEV) catalog on July 14, 2026. Affected models include SMA 6210, 7210, and 8200v running firmware prior to 12.4.3-03453 or 12.5.0-02835.

## Background: SonicWall SMA 1000 Architecture

SonicWall Secure Mobile Access (SMA) 1000 series appliances provide SSL VPN gateway functionality for enterprise remote access. The appliance architecture exposes a Workplace web interface on port 443 for end-user VPN connectivity and an Appliance Management Console (AMC) for administrative management. Internally, the appliance runs several localhost-only services including CouchDB on port 1050 (Erlang distribution), an Erlang Port Mapper Daemon (EPMD) on port 1051, and an XML-RPC control service (ctrl-service) on port 8188. The Workplace interface is served through NGINX Unit, which proxies requests to a Java-based application server on port 8085. The architecture's reliance on localhost-bound services that assume network-level isolation proved critical to the exploit chain's success.

## Attack Timeline (All Times UTC)

| Date | Event |
|------|-------|
| 2026-06-22 | Earliest observed compromise; ROOTRUN binary (xzfind) written to disk on Appliance 1 |
| 2026-06-28 | KNUCKLEBALL deployment; CouchDB and ctrl-service exploitation; ORANGETAIL and Suo5 JAR injection |
| 2026-06-29 | CVE-2026-15410 privilege escalation exploit payload (hypdate.b64) created |
| 2026-06-30 | Additional staging artifacts observed in /tmp |
| 2026-07-02 | Appliance 2 rebooted (flushing memory-resident artifacts); tcpdump LDAP credential capture initiated via lib.sh |
| 2026-07-14 | SonicWall public disclosure; CISA adds both CVEs to KEV catalog (remediation deadline: July 17) |
| 2026-07-17 | Volexity publishes detailed technical analysis |
| Week of 2026-07-20 | SonicWall releases patches: 12.4.3-03453 and 12.5.0-02835 |

## Root Cause: Pre-Authentication SSRF to Root via Chained Exploits

The attack chain exploits a fundamental architectural assumption: localhost-bound services (CouchDB, ctrl-service) do not require strong authentication because they are network-isolated. CVE-2026-15409 breaks this isolation by allowing an unauthenticated attacker to tunnel WebSocket connections to any localhost port. CouchDB uses default credentials (`admin:admin`), enabling the attacker to read the appliance's `product_uuid` from `/sys/class/dmi/id/product_uuid` (world-readable). This UUID, with dashes removed and Base64-encoded, yields the ctrl-service authentication password. The attacker then authenticates to the ctrl-service and exploits CVE-2026-15410 (path traversal in `sysCtrl.execRemoveHotfix`) to execute arbitrary scripts as root.

## Technical Analysis of the Exploitation Chain

### Stage 1: CVE-2026-15409 -- Pre-Authentication SSRF via /wsproxy

The `/wsproxy` endpoint on the SonicWall Workplace interface (port 443) is designed to proxy WebSocket connections for the SMA Connect Agent. An unauthenticated attacker can abuse this endpoint by sending a crafted request with a User-Agent header containing `SMA Connect Agent` and a `bmID` parameter starting with `-3389`. No valid session cookie is required.

**Exploit request format:**
```
GET /wsproxy?bmID=-3389<suffix>&serviceType=SSH&host=0.0.0.0&port=<target_port> HTTP/1.1
User-Agent: SMA Connect Agent
```

**Successful exploitation returns:**
```
HTTP/1.1 101 Switching Protocols
Sec-WebSocket-Protocol: binary
```

The SSRF allows tunneling to three critical localhost services:
- `127.0.0.1:1050` -- CouchDB Erlang distribution (named "couchdb")
- `127.0.0.1:1051` -- Erlang Port Mapper Daemon (EPMD)
- `127.0.0.1:8188` -- SMA control service (XML-RPC, realm "XMLRPC")

### Stage 2: CouchDB Exploitation and UUID Extraction

CouchDB is accessible with default credentials `admin:admin`. The attacker used the CouchDB tunnel to:
1. Read the appliance hardware UUID from `/sys/class/dmi/id/product_uuid`
2. Write a shell script (`/tmp/1234.sh`) as the `couchdb` user
3. The script derives the ctrl-service password by stripping dashes from the UUID and Base64-encoding the result

A critical finding by Volexity: a common default UUID value exists across multiple physical SonicWall appliances from the vendor, meaning a single derived password works on many devices. Virtual appliances (8200v) are not vulnerable to this UUID-based bypass.

### Stage 3: CVE-2026-15410 -- Command Injection via Path Traversal

The ctrl-service on port 8188 exposes the `sysCtrl.execRemoveHotfix` XML-RPC method. This method invokes `/usr/local/bin/remove_hotfix` with a hotfix identifier parameter. The remove_hotfix script runs:
```
chmod +x ${__rollback}
exec ${__rollback} --unattended
```

The attacker exploits path traversal by supplying `../../../../../tmp/1234.sh` as the hotfix identifier, causing the script at `/tmp/1234.sh` to execute as root.

**Log evidence (ctrl-service.log):**
```
running hotfix removal for:../../../../../tmp/1234.sh
Command '['/usr/local/bin/remove_hotfix', '../../../../../tmp/1234.sh']' exited with status '1'
```

### Stage 4: Malware Deployment

#### ROOTRUN (xzfind)
- **Type:** ELF setuid binary (13,464 bytes)
- **Path:** `/usr/bin/xzfind`
- **Function:** Enables any unprivileged user to execute commands as root via `setuid()` syscall
- **Usage:** `xzfind <command>`

#### KNUCKLEBALL (deploy_new.py)
- **Type:** Python script (81,476 bytes)
- **Path:** `/usr/lib/python3.11/site-packages/deploy_new.py`
- **Function:** Extracts two Base64-encoded JAR files and injects them into the legitimate SonicWall Workplace Java process (`workplace.startup.CommandStartup`) using the Java Attach API
- **Injection mechanism:** Creates `/tmp/.attach_pid<PID>` and `/tmp/.java_pid<PID>` sockets; sends `load instrument false <path>` command
- **Post-injection:** Modifies `/var/lib/unit/conf.json` to add two proxy routes redirecting `/__api__/login` and `/__api__/logout` to `http://127.0.0.1:8085`

#### Suo5 (agent_wp8.jar)
- **Type:** Java archive (34,520 bytes)
- **Path:** `/tmp/agent_wp8.jar` (staging), injected into JVM
- **Target class:** `com/aventail/jsp/workplace/error_jsp`
- **Access URI:** `/workplace/error.jsp` (proxied via `/__api__/login`)
- **Function:** Open-source HTTP forwarding proxy enabling traffic tunneling through the compromised appliance

#### ORANGETAIL (agent_wp9.jar)
- **Type:** Java archive (21,800 bytes)
- **Path:** `/tmp/agent_wp9.jar` (staging), injected into JVM
- **Target class:** `com/aventail/jsp/workplace/dialogs/errorDialog_jsp`
- **Access URI:** `/workplace/dialogs/errorDialog.jsp` (proxied via `/__api__/logout`)
- **Function:** Custom Behinder-like Java web shell accepting AES-128-ECB encrypted Java payloads
- **Encryption:** AES-128-ECB with hardcoded key `615...e4a4`
- **Command parameter:** POST parameter `find`
- **Response format:** JSON with Base64+AES-encrypted content
- **String obfuscation:** Character-by-character construction via `String.valueOf()`

#### Shared Malware User-Agent Gate
Both Suo5 and ORANGETAIL validate incoming requests against a distinctive hardcoded User-Agent string:
```
Mozilla/6.0 (Windows NT 11.0; Win64; x64) AppleWebKit/1537.136 (KHTML, like Gecko) Chrome/149.0.0.1 Safari/1537.136
```
This malformed User-Agent (non-existent browser versions, Windows NT 11.0) serves as an authentication gate preventing accidental triggering.

### Stage 5: Persistence Mechanisms

1. **Startup script injection:** Added `python3 /usr/lib/python3.11/site-packages/deploy_new.py` to `/etc/init.d/workplace` to re-inject JARs on reboot
2. **NGINX Unit configuration modification:** Routes added to `/var/lib/unit/conf.json`:
```json
{
  "match": {"uri": "/__api__/login"},
  "action": {"rewrite": "/workplace/error.jsp", "proxy": "http://127.0.0.1:8085"}
},
{
  "match": {"uri": "/__api__/logout"},
  "action": {"rewrite": "/workplace/dialogs/errorDialog.jsp", "proxy": "http://127.0.0.1:8085"}
}
```
3. **Setuid binary persistence:** `/usr/bin/xzfind` provides continued root access from unprivileged context
4. **In-memory Java agent persistence:** JAR agents resident in JVM process memory survive until process restart

### Stage 6: Credential Interception

On a second compromised appliance, the threat actor deployed `/var/tmp/lib.sh`, a shell script launching tcpdump to capture unencrypted LDAP traffic:
```bash
tcpdump -i any '<LDAP TCP 389>' -w /var/tmp/<filename> -C 100 -W 10 &
```
This captures cleartext usernames and passwords from directory service authentication traffic transiting the VPN appliance. The position of the appliance as a VPN gateway makes it an ideal vantage point for credential harvesting.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in report prose use defanged notation: IP addresses use `[.]` for dots. Detection rules use real values.

### File Hashes

| Hash (SHA256) | Filename | Description |
|---------------|----------|-------------|
| 81a9af3846bad3a1107164ff7cf0a08e020b31a3b32fd17866e17d4c1565f7f2 | xzfind | ROOTRUN setuid privilege escalation binary |
| 8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3 | deploy_new.py | KNUCKLEBALL Python JAR injector |
| 1e1e68bbb899450a57274a8b12082ed4e2040a2aae77014f20431689d2b4edee | agent_wp8.jar | Suo5 HTTP forwarding proxy |
| ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081 | agent_wp9.jar | ORANGETAIL Java web shell |

| Hash (MD5) | Hash (SHA1) | Filename |
|------------|-------------|----------|
| 5cb00bbfe818ee3e85fb99ab1db1af7c | 04d4a9fbb32e967200eb98be014ca914a03bfa6b | xzfind |
| b6df166291f80ee89032d769c99714f3 | b4ee1f50fbb49f0ff5fde3d026343bc23ee08d51 | deploy_new.py |
| 54d21399b8b52b48a0fef68450593e45 | c2b0ae0a1f42a139abe4dd612676066ec1426394 | agent_wp8.jar |
| 5f3a55201c511c9ff9be4c16c41028a2 | 5e5b716f2385c818ec61198be1a2a07a4560eac5 | agent_wp9.jar |

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| IP | 108[.]205[.]8[.]173 | Non-VPN source IP used by UTA0533 |
| IP | 147[.]45[.]51[.]19 | Non-VPN source IP used by UTA0533 |
| IP | 150[.]241[.]210[.]53 | Non-VPN source IP used by UTA0533 |
| IP | 202[.]8[.]105[.]201 | Non-VPN source IP used by UTA0533 |
| IP | 217[.]77[.]15[.]99 | Non-VPN source IP used by UTA0533 |
| IP | 42[.]200[.]172[.]14 | Non-VPN source IP used by UTA0533 |
| IP | 81[.]19[.]140[.]217 | Non-VPN source IP used by UTA0533 |
| IP | 89[.]117[.]20[.]1 | Non-VPN source IP used by UTA0533 |
| IP | 193[.]37[.]32[.]179 | ASN 206092 (F.N.S Holdings) infrastructure |
| IP | 193[.]37[.]32[.]214 | ASN 206092 (F.N.S Holdings) infrastructure |
| IP | 216[.]73[.]163[.]151 | ASN 206092 (F.N.S Holdings) infrastructure |
| IP | 216[.]73[.]163[.]158 | ASN 206092 (F.N.S Holdings) infrastructure |

### File System Indicators

| Path | Description |
|------|-------------|
| `/usr/bin/xzfind` | ROOTRUN setuid binary |
| `/usr/lib/python3.11/site-packages/deploy_new.py` | KNUCKLEBALL Python injector |
| `/etc/init.d/workplace` | Modified startup script (persistence) |
| `/var/lib/unit/conf.json` | Modified NGINX Unit configuration |
| `/tmp/1234.sh` | Privilege escalation script (couchdb user) |
| `/tmp/hypdate.b64` | Base64-encoded CVE-2026-15410 exploit payload |
| `/tmp/agent_wp8.jar` | Suo5 JAR (staging location) |
| `/tmp/agent_wp9.jar` | ORANGETAIL JAR (staging location) |
| `/tmp/agent_wp8.log` | Redirected to /dev/null |
| `/tmp/agent_wp9.log` | Redirected to /dev/null |
| `/tmp/.attach_pid<PID>` | Java Attach API socket |
| `/tmp/.java_pid<PID>` | Java Attach API socket |
| `/var/tmp/lib.sh` | tcpdump launcher for LDAP credential capture |

### Behavioral Indicators

| Log Source | Pattern | Significance |
|------------|---------|--------------|
| extraweb_access.log | `GET /wsproxy?bmID=-3389` with HTTP 101 response | CVE-2026-15409 SSRF exploitation |
| extraweb_access.log | `POST /__api__/login` or `POST /__api__/logout` with HTTP 200 | Web shell access via proxied routes |
| ctrl-service.log | `remove_hotfix` with `../` path traversal | CVE-2026-15410 command injection |
| Any | User-Agent: `Mozilla/6.0 (Windows NT 11.0; Win64; x64)` | Malware C2 gating string |

### Attacker Workstation Hostnames

Leaked via authentication artifacts:
- `DESKTOP-5P0TSCP`
- `DESKTOP-IC3C80F`
- `DESKTOP-KRLUI3J`
- `KALI`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | CVE-2026-15409 SSRF and CVE-2026-15410 command injection against SMA Workplace interface |
| T1090 | Proxy | Suo5 HTTP forwarding proxy tunneling traffic through compromised appliance |
| T1219 | Remote Access Software | ORANGETAIL custom Java web shell for persistent remote command execution |
| T1068 | Exploitation for Privilege Escalation | CVE-2026-15410 path traversal in remove_hotfix for root execution |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | ROOTRUN (xzfind) setuid binary for unprivileged root access |
| T1059.006 | Command and Scripting Interpreter: Python | KNUCKLEBALL deploy_new.py Python-based JAR injector |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | /tmp/1234.sh exploitation script; /var/tmp/lib.sh tcpdump launcher |
| T1547.004 | Boot or Logon Autostart Execution: Unix Shell Configuration Modification | /etc/init.d/workplace startup script modified for persistence |
| T1040 | Network Sniffing | tcpdump capturing unencrypted LDAP credentials on port 389 |
| T1046 | Network Service Scanning | EPMD enumeration via SSRF to discover CouchDB node |
| T1133 | External Remote Services | Exploitation of internet-facing VPN appliance |
| T1505.003 | Server Software Component: Web Shell | ORANGETAIL Java web shell injected into Workplace application |
| T1036.005 | Masquerading: Match Legitimate Name or Location | xzfind named to resemble xz utilities; deploy_new.py placed in site-packages |

## Affected Products and Remediation

### Affected Firmware Versions

| Affected Version | Fixed Version |
|------------------|---------------|
| 12.4.3-03245 | 12.4.3-03453+ |
| 12.4.3-03387 | 12.4.3-03453+ |
| 12.4.3-03434 | 12.4.3-03453+ |
| 12.5.0-02283 | 12.5.0-02835+ |
| 12.5.0-02624 | 12.5.0-02835+ |
| 12.5.0-02800 | 12.5.0-02835+ |

### Affected Models
- SMA 6210
- SMA 7210
- SMA 8200v

### Remediation Steps

1. **Patch immediately:** Update to firmware 12.4.3-03453+ or 12.5.0-02835+; no workarounds exist
2. **Forensic audit:** Inspect appliances for IOC artifacts beginning June 22, 2026
3. **File integrity:** Check for unexpected files in `/tmp/`, `/var/tmp/`, `/usr/bin/xzfind`, and Python site-packages
4. **Setuid audit:** Run `find / -perm -4000` to identify unexpected setuid binaries
5. **Configuration review:** Verify `/var/lib/unit/conf.json` and `/etc/init.d/workplace` for unauthorized modifications
6. **Credential rotation:** Assume all credentials processed by compromised appliances are exposed; rotate domain passwords, LDAP service accounts, and VPN user credentials
7. **Network audit:** Review downstream authentication infrastructure for unauthorized access from appliance IPs

## Impact Assessment

This campaign demonstrates a sophisticated, appliance-aware threat actor with pre-positioned capability to exploit SonicWall-specific internals. Key risk factors:

1. **Pre-authentication entry point** -- CVE-2026-15409 requires no credentials and no user interaction
2. **Default credentials in localhost services** -- CouchDB `admin:admin` and deterministic ctrl-service password derived from hardware UUID undermine defense-in-depth
3. **Shared hardware UUID** -- Multiple physical appliances share a common default UUID, enabling single-password attacks across customer base
4. **VPN gateway position** -- Compromised appliance captures all VPN user credentials and network traffic
5. **Firmware-update-resistant persistence** -- Startup script and NGINX configuration modifications survive standard reboots

Rapid7 identified overlapping TTPs suggesting UTA0533 may be a single coordinated group. INC Ransomware has been noted as an emerging weaponizer of this vulnerability chain.

## Sources

- [Volexity: Proxying to Compromise: SonicWall Secure Mobile Access 0-Day Exploitation](https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/) -- Primary research source; incident response investigation discovering UTA0533 activity
- [The Hacker News: SonicWall SMA Zero-Days Exploited](https://thehackernews.com/2026/07/sonicwall-sma-zero-days-exploited.html) -- News coverage with additional context on INC Ransomware and Rapid7 correlation
- [Security Affairs: Volexity Uncovers Zero-Day Campaign Targeting SonicWall VPN Appliances](https://securityaffairs.com/195626/hacking/volexity-uncovers-zero-day-campaign-targeting-sonicwall-vpn-appliances.html) -- Detailed coverage of exploitation chain and IOCs
- [BleepingComputer: SonicWall SMA1000 Flaws Exploited as Zero-Days to Push Custom Malware](https://www.bleepingcomputer.com/news/security/sonicwall-sma1000-flaws-exploited-as-zero-days-to-push-custom-malware/) -- Patch version details, affected models, and exploitation methodology
- [Rapid7: MDR Team Discovers New SonicWall SMA1000 Zero Days Being Actively Exploited](https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/) -- Independent corroboration with additional network IOCs and ASN attribution
- [Tenable: CVE-2026-15409 and CVE-2026-15410 SonicWall SMA 1000 Zero-Day Vulnerabilities](https://www.tenable.com/blog/cve-2026-15409-cve-2026-15410-sonicwall-sma-1000-zero-day-vulnerabilities-exploited-in-the) -- Firmware version matrix and CISA KEV details
- [Help Net Security: SonicWall SMA Zero-Days Exploited](https://www.helpnetsecurity.com/2026/07/21/sonicwall-sma-zero-days-exploited-cve-2026-15409-cve-2026-15410/) -- Additional timeline and patching context

## Detection Rules

These 17 rules (5 Sigma, 3 Snort, 3 Suricata, 6 YARA) target the UTA0533/SonicWall SMA exploitation chain across host, network, and file telemetry. IOC-based rules are high confidence but subject to infrastructure rotation. TTP-based rules provide durable detection at medium-high confidence. Compile status does not equal production-ready -- validate in your pipeline.

### Sigma: CVE-2026-15409 SSRF Exploitation via /wsproxy

Detects HTTP requests to the `/wsproxy` endpoint with the distinctive `bmID=-3389` parameter pattern indicative of CVE-2026-15409 SSRF exploitation.

**Status:** compile :white_check_mark: compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network: MITRE ATT&CK data fetch 403 via proxy -- not a rule issue). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Targets the exact exploitation pattern documented by Volexity. The bmID=-3389 prefix combined with /wsproxy is highly specific to this vulnerability. FP risk: legitimate SMA Connect Agent traffic may hit /wsproxy but would use valid bmID values, not the -3389 prefix. -->

```yaml
title: SonicWall SMA CVE-2026-15409 SSRF Exploitation via wsproxy Endpoint
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: >
    Detects exploitation of CVE-2026-15409 via crafted requests to the /wsproxy
    endpoint with bmID parameter starting with -3389, enabling unauthenticated
    WebSocket tunneling to localhost services on SonicWall SMA 1000 appliances.
references:
    - https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
author: Actioner
date: 2026/07/22
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2026-15409
logsource:
    category: webserver
    product: sonicwall
detection:
    selection_uri:
        cs-uri-query|contains: '/wsproxy'
    selection_bmid:
        cs-uri-query|contains: 'bmID=-3389'
    selection_status:
        sc-status: 101
    condition: selection_uri and selection_bmid and selection_status
falsepositives:
    - Legitimate SMA Connect Agent sessions using the /wsproxy endpoint with different bmID values
level: critical
```

### Sigma: CVE-2026-15410 Path Traversal in remove_hotfix

Detects path traversal attempts targeting the SonicWall ctrl-service remove_hotfix workflow, as recorded in ctrl-service.log.

**Status:** compile :white_check_mark: compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network: MITRE ATT&CK data fetch 403 via proxy -- not a rule issue). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Exact pattern from Volexity's ctrl-service.log evidence. Path traversal in remove_hotfix is never legitimate. FP risk: near-zero -- remove_hotfix should only receive sanitized hotfix identifiers. -->

```yaml
title: SonicWall SMA CVE-2026-15410 Path Traversal in remove_hotfix
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: >
    Detects path traversal sequences in SonicWall ctrl-service logs indicating
    exploitation of CVE-2026-15410 via the sysCtrl.execRemoveHotfix method.
references:
    - https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
author: Actioner
date: 2026/07/22
tags:
    - attack.privilege_escalation
    - attack.t1068
    - cve.2026-15410
logsource:
    category: application
    product: sonicwall
detection:
    selection_remove:
        EventData|contains: 'remove_hotfix'
    selection_traversal:
        EventData|contains: '../'
    condition: selection_remove and selection_traversal
falsepositives:
    - None expected - path traversal in remove_hotfix is never legitimate
level: critical
```

### Sigma: UTA0533 Malware File Creation on SonicWall Appliance

Detects creation of known UTA0533 malware artifacts on the filesystem, including ROOTRUN, KNUCKLEBALL, and staging files.

**Status:** compile :white_check_mark: compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network: MITRE ATT&CK data fetch 403 via proxy -- not a rule issue). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Targets known file paths documented by Volexity. These paths are highly specific to the campaign. FP risk: xzfind could theoretically be a legitimate xz-related utility name on other Linux systems, but not on SonicWall appliances. -->

```yaml
title: UTA0533 Malware Artifacts on SonicWall SMA Appliance
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: >
    Detects creation or presence of files associated with UTA0533 tooling
    on SonicWall SMA appliances, including ROOTRUN, KNUCKLEBALL, and
    exploit staging artifacts.
references:
    - https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
author: Actioner
date: 2026/07/22
tags:
    - attack.persistence
    - attack.t1547.004
    - attack.t1548.001
logsource:
    category: file_event
    product: linux
detection:
    selection_rootrun:
        TargetFilename|endswith: '/xzfind'
        TargetFilename|contains: '/usr/bin/'
    selection_knuckleball:
        TargetFilename|endswith: '/deploy_new.py'
        TargetFilename|contains: '/site-packages/'
    selection_staging:
        TargetFilename:
            - '/tmp/hypdate.b64'
            - '/tmp/1234.sh'
            - '/tmp/agent_wp8.jar'
            - '/tmp/agent_wp9.jar'
    selection_persistence:
        TargetFilename: '/var/tmp/lib.sh'
    condition: 1 of selection_*
falsepositives:
    - Unlikely on SonicWall appliances; xzfind is not a legitimate SonicWall binary
level: critical
```

### Sigma: Suspicious Malformed User-Agent String for ORANGETAIL/Suo5 Web Shell

Detects HTTP requests using the distinctive malformed User-Agent string hardcoded in ORANGETAIL and Suo5 as an authentication gate.

**Status:** compile :white_check_mark: compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network: MITRE ATT&CK data fetch 403 via proxy -- not a rule issue). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. The User-Agent contains non-existent values (Mozilla/6.0, Windows NT 11.0, Chrome/149.0.0.1, AppleWebKit/1537.136) making it extremely distinctive. FP risk: near-zero -- no legitimate browser generates this string. -->

```yaml
title: ORANGETAIL and Suo5 Malformed User-Agent Gate String
id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80
status: experimental
description: >
    Detects HTTP requests using the malformed User-Agent string hardcoded
    in both ORANGETAIL and Suo5 web shell components as an authentication
    mechanism. Contains fictitious version numbers (Mozilla/6.0, Windows
    NT 11.0, Chrome/149.0.0.1).
references:
    - https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
author: Actioner
date: 2026/07/22
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: webserver
detection:
    selection:
        cs-user-agent|contains: 'Mozilla/6.0 (Windows NT 11.0'
    selection_chrome:
        cs-user-agent|contains: 'Chrome/149.0.0.1'
    condition: selection and selection_chrome
falsepositives:
    - None expected - this User-Agent string contains deliberately invalid version numbers
level: critical
```

### Sigma: UTA0533 Network IOC - Known Attacker IP Addresses

Detects network connections from known UTA0533 non-VPN source IP addresses.

**Status:** compile :white_check_mark: compiles (convert) | Confidence: medium

<!-- audit: sigma check failed (network: MITRE ATT&CK data fetch 403 via proxy -- not a rule issue). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. IOC-based detection subject to infrastructure rotation. Medium confidence due to potential IP reassignment over time. Covers the 8 non-VPN IPs and 4 ASN 206092 IPs documented by Volexity and Rapid7. -->

```yaml
title: UTA0533 Known Attacker Source IP Addresses
id: e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091
status: experimental
description: >
    Detects network connections from IP addresses attributed to UTA0533
    by Volexity and Rapid7 investigations. These are non-VPN IPs directly
    associated with the threat actor's infrastructure.
references:
    - https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
    - https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/
author: Actioner
date: 2026/07/22
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: firewall
detection:
    selection:
        src_ip:
            - '108.205.8.173'
            - '147.45.51.19'
            - '150.241.210.53'
            - '202.8.105.201'
            - '217.77.15.99'
            - '42.200.172.14'
            - '81.19.140.217'
            - '89.117.20.1'
            - '193.37.32.179'
            - '193.37.32.214'
            - '216.73.163.151'
            - '216.73.163.158'
    condition: selection
falsepositives:
    - IP address reuse after infrastructure decommission; verify current threat intel before blocking
level: high
```

### Snort: CVE-2026-15409 SSRF Exploitation via /wsproxy

Detects HTTP GET requests to `/wsproxy` containing `bmID=-3389` indicative of CVE-2026-15409 exploitation. Caveat: does not validate WebSocket upgrade response.

**Status:** compile :warning: uncompiled (structural check only) | Confidence: high

<!-- audit: Structural review only -- Snort not available for compilation. Rule targets the exact URI pattern and parameter documented by Volexity. Content matches are case-insensitive for the URI and exact for the bmID parameter. -->

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"EXPLOIT SonicWall SMA CVE-2026-15409 SSRF via wsproxy bmID=-3389"; flow:established,to_server; content:"GET"; http_method; content:"/wsproxy"; http_uri; content:"bmID=-3389"; http_uri; content:"SMA Connect Agent"; http_header; reference:cve,2026-15409; classtype:web-application-attack; sid:2026001; rev:1;)
```

### Snort: ORANGETAIL/Suo5 Malformed User-Agent String

Detects the distinctive malformed User-Agent used as an authentication gate by both ORANGETAIL and Suo5 web shell components.

**Status:** compile :warning: uncompiled (structural check only) | Confidence: high

<!-- audit: Structural review only. The malformed UA contains unique markers (Mozilla/6.0, Windows NT 11.0, Chrome/149.0.0.1) that do not match any real browser. -->

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"MALWARE ORANGETAIL/Suo5 Malformed User-Agent Gate String"; flow:established,to_server; content:"Mozilla/6.0 (Windows NT 11.0"; http_header; content:"Chrome/149.0.0.1"; http_header; reference:url,www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/; classtype:trojan-activity; sid:2026002; rev:1;)
```

### Snort: UTA0533 POST to Proxied Web Shell Endpoints

Detects POST requests to `/__api__/login` or `/__api__/logout` which are hijacked by ORANGETAIL/Suo5 NGINX Unit configuration modifications.

**Status:** compile :warning: uncompiled (structural check only) | Confidence: medium

<!-- audit: Structural review only. Medium confidence because /__api__/login and /__api__/logout are also legitimate SonicWall endpoints. The POST method and the combination with other indicators increases confidence. Best deployed on SonicWall-facing network segments. -->

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"EXPLOIT UTA0533 POST to Hijacked SonicWall API Endpoint"; flow:established,to_server; content:"POST"; http_method; content:"/__api__/log"; http_uri; content:"Mozilla/6.0"; http_header; reference:url,www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/; classtype:web-application-attack; sid:2026003; rev:1;)
```

### Suricata: CVE-2026-15409 SSRF Exploitation via /wsproxy

Detects CVE-2026-15409 exploitation via `/wsproxy` with the distinctive `bmID=-3389` parameter. Caveat: may trigger on legitimate SMA Connect Agent traffic if bmID coincidentally starts with -3389.

**Status:** compile :warning: uncompiled (structural check only) | Confidence: high

<!-- audit: Structural review only -- Suricata not available for compilation. Uses http.uri and http.user_agent sticky buffers for Suricata 6+ syntax. -->

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"EXPLOIT SonicWall SMA CVE-2026-15409 SSRF wsproxy bmID=-3389"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/wsproxy"; content:"bmID=-3389"; http.user_agent; content:"SMA Connect Agent"; reference:cve,2026-15409; classtype:web-application-attack; sid:2026101; rev:1;)
```

### Suricata: ORANGETAIL/Suo5 Malformed User-Agent String

Detects the deliberately malformed User-Agent string used as a gate by both Suo5 and ORANGETAIL web shell components.

**Status:** compile :warning: uncompiled (structural check only) | Confidence: high

<!-- audit: Structural review only. Uses Suricata 6+ http.user_agent sticky buffer. The combination of Mozilla/6.0 and Chrome/149.0.0.1 is unique to this malware family. -->

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MALWARE ORANGETAIL/Suo5 Malformed User-Agent Gate String"; flow:established,to_server; http.user_agent; content:"Mozilla/6.0 (Windows NT 11.0"; content:"Chrome/149.0.0.1"; reference:url,www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/; classtype:trojan-activity; sid:2026102; rev:1;)
```

### Suricata: UTA0533 Known Attacker IP Addresses

Detects inbound connections from UTA0533 non-VPN source IPs to HTTP services. Caveat: IOC-based; subject to infrastructure rotation.

**Status:** compile :warning: uncompiled (structural check only) | Confidence: medium

<!-- audit: Structural review only. IP-based detection is inherently ephemeral. Uses Suricata IP grouping syntax. -->

```
alert ip [108.205.8.173,147.45.51.19,150.241.210.53,202.8.105.201,217.77.15.99,42.200.172.14,81.19.140.217,89.117.20.1,193.37.32.179,193.37.32.214,216.73.163.151,216.73.163.158] any -> $HOME_NET any (msg:"THREAT UTA0533 Known Source IP Address"; reference:url,www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/; classtype:trojan-activity; sid:2026103; rev:1;)
```

### YARA: ROOTRUN Setuid Privilege Escalation Binary

Detects the ROOTRUN (xzfind) ELF setuid binary used by UTA0533 for privilege escalation on compromised SonicWall appliances.

**Status:** compile :white_check_mark: compiles (yarac exit 0) | Confidence: high

<!-- audit: yarac rootrun.yar /dev/null exit 0. Uses ELF header and size constraints for the known 13,464-byte binary. Includes string patterns from setuid binary functionality. -->

```yara
rule UTA0533_ROOTRUN_Setuid_Binary
{
    meta:
        description = "Detects ROOTRUN (xzfind) setuid privilege escalation binary deployed by UTA0533"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "81a9af3846bad3a1107164ff7cf0a08e020b31a3b32fd17866e17d4c1565f7f2"
        tlp = "white"

    strings:
        $elf_header = { 7F 45 4C 46 }
        $setuid_call = "setuid" ascii
        $bash = "/bin/bash" ascii
        $xzfind = "xzfind" ascii

    condition:
        $elf_header at 0 and
        filesize < 20KB and
        filesize > 10KB and
        2 of ($setuid_call, $bash, $xzfind)
}
```

### YARA: KNUCKLEBALL Python JAR Injector

Detects the KNUCKLEBALL (deploy_new.py) Python script used to inject Suo5 and ORANGETAIL JARs into the SonicWall Workplace Java process.

**Status:** compile :white_check_mark: compiles (yarac exit 0) | Confidence: high

<!-- audit: yarac knuckleball.yar /dev/null exit 0. Targets distinctive strings from the Java Attach API injection mechanism and the specific JAR filenames. The combination of attach_pid, java_pid, agent_wp patterns, and unit/conf.json modification is unique to this tool. -->

```yara
rule UTA0533_KNUCKLEBALL_JAR_Injector
{
    meta:
        description = "Detects KNUCKLEBALL (deploy_new.py) Python-based JAR injector used by UTA0533"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3"
        tlp = "white"

    strings:
        $attach_pid = ".attach_pid" ascii
        $java_pid = ".java_pid" ascii
        $agent_wp8 = "agent_wp8" ascii
        $agent_wp9 = "agent_wp9" ascii
        $unit_conf = "unit/conf.json" ascii
        $load_instrument = "load instrument false" ascii
        $workplace_startup = "CommandStartup" ascii
        $deploy_new = "deploy_new" ascii

    condition:
        filesize < 200KB and
        3 of them
}
```

### YARA: Suo5 HTTP Forwarding Proxy JAR

Detects the Suo5 (agent_wp8.jar) HTTP forwarding proxy component deployed by UTA0533.

**Status:** compile :white_check_mark: compiles (yarac exit 0) | Confidence: high

<!-- audit: yarac suo5.yar /dev/null exit 0. Targets the specific Java class path and JAR structure combined with the error_jsp class name that is the injection target. -->

```yara
rule UTA0533_Suo5_Proxy_JAR
{
    meta:
        description = "Detects Suo5 (agent_wp8.jar) HTTP forwarding proxy used by UTA0533"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "1e1e68bbb899450a57274a8b12082ed4e2040a2aae77014f20431689d2b4edee"
        tlp = "white"

    strings:
        $pk_header = { 50 4B 03 04 }
        $class_target = "com/aventail/jsp/workplace/error_jsp" ascii
        $agent_wp8 = "agent_wp8" ascii
        $mozilla6 = "Mozilla/6.0" ascii

    condition:
        $pk_header at 0 and
        filesize < 100KB and
        2 of ($class_target, $agent_wp8, $mozilla6)
}
```

### YARA: ORANGETAIL Java Web Shell

Detects the ORANGETAIL (agent_wp9.jar) custom Behinder-like Java web shell deployed by UTA0533.

**Status:** compile :white_check_mark: compiles (yarac exit 0) | Confidence: high

<!-- audit: yarac orangetail.yar /dev/null exit 0. Targets distinctive strings from the web shell including the injection target class, the POST parameter name, and the AES encryption markers. -->

```yara
rule UTA0533_ORANGETAIL_Webshell
{
    meta:
        description = "Detects ORANGETAIL (agent_wp9.jar) custom Java web shell used by UTA0533"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
        tlp = "white"

    strings:
        $pk_header = { 50 4B 03 04 }
        $class_target = "com/aventail/jsp/workplace/dialogs/errorDialog_jsp" ascii
        $agent_wp9 = "agent_wp9" ascii
        $find_param = "find" ascii
        $mozilla6 = "Mozilla/6.0" ascii
        $string_valueof = "String.valueOf" ascii
        $aes = "AES" ascii

    condition:
        $pk_header at 0 and
        filesize < 100KB and
        ($class_target or $agent_wp9) and
        2 of ($find_param, $mozilla6, $string_valueof, $aes)
}
```

### YARA: UTA0533 Malformed User-Agent String in Any File

Detects the presence of the distinctive malformed User-Agent string used as a C2 gate by UTA0533 tooling across any file type.

**Status:** compile :white_check_mark: compiles (yarac exit 0) | Confidence: high

<!-- audit: yarac ua_gate.yar /dev/null exit 0. The combination of Mozilla/6.0, Windows NT 11.0, and Chrome/149.0.0.1 is unique to this malware family. Useful for scanning configuration files, logs, and memory dumps. -->

```yara
rule UTA0533_Malformed_UserAgent_Gate
{
    meta:
        description = "Detects the malformed User-Agent string hardcoded in ORANGETAIL and Suo5 as an authentication gate"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        tlp = "white"

    strings:
        $ua_full = "Mozilla/6.0 (Windows NT 11.0; Win64; x64) AppleWebKit/1537.136 (KHTML, like Gecko) Chrome/149.0.0.1 Safari/1537.136" ascii wide
        $ua_mozilla6 = "Mozilla/6.0 (Windows NT 11.0" ascii wide
        $ua_chrome149 = "Chrome/149.0.0.1" ascii wide

    condition:
        $ua_full or ($ua_mozilla6 and $ua_chrome149)
}
```

### YARA: CVE-2026-15410 Exploit Payload Staging File

Detects Base64-encoded exploit payloads targeting the SonicWall remove_hotfix path traversal vulnerability, staged as .b64 files.

**Status:** compile :white_check_mark: compiles (yarac exit 0) | Confidence: medium

<!-- audit: yarac exploit_staging.yar /dev/null exit 0. Medium confidence because the rule relies on path traversal strings that could appear in other exploit tools. The combination with remove_hotfix and SonicWall-specific paths increases specificity. -->

```yara
rule UTA0533_CVE_2026_15410_Exploit_Staging
{
    meta:
        description = "Detects staging artifacts for CVE-2026-15410 exploitation of SonicWall remove_hotfix path traversal"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        tlp = "white"

    strings:
        $traversal = "../../../../../tmp/" ascii
        $remove_hotfix = "remove_hotfix" ascii
        $exec_remove = "execRemoveHotfix" ascii
        $ctrl_service = "sysCtrl" ascii
        $product_uuid = "product_uuid" ascii
        $b64_marker = "hypdate" ascii

    condition:
        filesize < 500KB and
        3 of them
}
```
