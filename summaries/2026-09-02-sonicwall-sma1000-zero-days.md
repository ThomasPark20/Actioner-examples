# Technical Analysis Report: SonicWall SMA1000 New Zero-Day Vulnerabilities (CVE-2026-83548 & CVE-2026-83549) (2026-09-02)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-02
Version: 1.0 (DRAFT)

## Executive Summary

On September 1, 2026, SonicWall published advisory SNWLID-2026-0016 disclosing two new zero-day vulnerabilities in its SMA1000 series secure remote access appliances that are being actively exploited in the wild. CVE-2026-83548 is a critical (CVSS 10.0) pre-authentication server-side request forgery (SSRF) vulnerability in the Appliance Work Place interface stemming from an "unintended alternate access path" that can serve as a forward proxy. CVE-2026-83549 is a high-severity (CVSS 7.8) post-authentication OS command injection vulnerability in the Appliance Management Console (AMC). SonicWall confirmed the two vulnerabilities are being chained to achieve unauthenticated remote code execution. These are distinct from the prior CVE-2026-15409/CVE-2026-15410 pair disclosed in July 2026, and critically, the affected versions include the firmware releases that patched those earlier flaws (up to 12.4.3-03453 and 12.5.0-02835). Affected models are SMA 6210, 7210, and 8200v. Fixed versions are 12.4.3-03526 and 12.5.0-02952. SonicWall has not publicly released IOCs or detailed attack information, and the CVEs have not yet been added to CISA's Known Exploited Vulnerabilities (KEV) catalog as of this writing.

## Background: SonicWall SMA 1000 Architecture

SonicWall Secure Mobile Access (SMA) 1000 series appliances provide SSL VPN gateway functionality for enterprise remote access. The appliance exposes two primary web interfaces: the Appliance Work Place interface on port 443 for end-user VPN connectivity, and the Appliance Management Console (AMC) for administrative management. Internally, the appliance runs several localhost-only services including CouchDB, an Erlang Port Mapper Daemon, and an XML-RPC control service. The architecture relies on NGINX Unit to proxy requests to a Java-based application server. This product line has been repeatedly targeted in 2026 -- the July 2026 exploitation campaign (CVE-2026-15409/15410) by threat actor UTA0533 demonstrated the viability of chaining SSRF and command injection flaws in these same components to achieve root-level compromise. The INC ransomware gang was subsequently linked to post-exploitation activity. The September 2026 CVEs represent new vulnerabilities in the same architectural components, exploitable even on appliances patched for the July flaws.

## Attack Timeline (All Times UTC)

| Date | Event |
|------|-------|
| 2026-06-22 | Earliest known exploitation of prior SMA1000 zero-days (CVE-2026-15409/15410) by UTA0533 |
| 2026-07-14 | SonicWall discloses CVE-2026-15409/15410; CISA adds to KEV; patches 12.4.3-03453 and 12.5.0-02835 released |
| 2026-08-31 | CVE-2026-83548 and CVE-2026-83549 reserved |
| 2026-09-01 | SonicWall publishes advisory SNWLID-2026-0016 confirming active exploitation of both new CVEs |
| 2026-09-01 | Hotfix versions 12.4.3-03526 and 12.5.0-02952 released |
| 2026-09-02 | Multiple security outlets report on the chained exploitation; CVEs not yet in CISA KEV |

## Root Cause: Pre-Authentication SSRF Chained with Post-Authentication Command Injection

The attack chain mirrors the architectural pattern of the July 2026 exploitation: an unauthenticated SSRF vulnerability in the externally-facing Appliance Work Place interface is used to bypass authentication boundaries, followed by exploitation of a command injection flaw in the administrative AMC component to achieve code execution.

**CVE-2026-83548 (SSRF -- CVSS 10.0):** A pre-authentication SSRF exists in the Appliance Work Place interface due to an "unintended alternate access path" that can function as a forward proxy. Unlike the July CVE-2026-15409 which exploited the `/wsproxy` WebSocket endpoint, this new vulnerability exploits a different access path. The flaw allows a remote, unauthenticated attacker to access sensitive internal functionality and perform unauthorized operations, including reaching the AMC or other internal services.

**CVE-2026-83549 (OS Command Injection -- CVSS 7.8):** A post-authentication OS command injection vulnerability exists in the AMC component. An authenticated administrator can execute arbitrary OS commands on the appliance. Unlike CVE-2026-15410 which exploited path traversal in the `remove_hotfix` workflow, this is a direct command injection flaw (CWE-78). When chained with CVE-2026-83548, the authentication requirement is effectively bypassed, enabling unauthenticated RCE.

## Technical Analysis of the Exploitation Chain

### 1. Stage 1: SSRF via Unintended Alternate Access Path (CVE-2026-83548)

The SSRF vulnerability (CWE-918, CWE-441) exists in the Appliance Work Place interface and stems from an unintended alternate access path that can serve as a forward proxy. The exact endpoint has not been publicly disclosed by SonicWall or independent researchers as of this writing. Based on the CWE-441 (Unintended Proxy or Intermediary) classification, the flaw allows the appliance to be weaponized as a request proxy, enabling:

- Access to localhost-bound services (CouchDB, ctrl-service, EPMD)
- Credential theft from cloud metadata services
- Internal network reconnaissance
- Bypassing authentication controls to reach the AMC

### 2. Stage 2: OS Command Injection via AMC (CVE-2026-83549)

The command injection vulnerability (CWE-78) in the AMC enables an attacker who has gained administrative access (potentially via the SSRF) to inject OS commands. The CVSS vector (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) indicates local attack vector with low privileges required, but when chained with the SSRF, the effective attack is remote and unauthenticated. Successful exploitation yields arbitrary command execution on the underlying Linux-based operating system, likely as root given SMA1000 architecture.

### 3. Post-Exploitation (Inferred from Prior Campaigns)

While SonicWall has not disclosed post-exploitation details for CVE-2026-83548/83549, the July 2026 campaign by UTA0533 demonstrated the following post-exploitation pattern on the same appliance platform:

- **Privilege escalation**: ROOTRUN setuid binary (`xzfind`) for root command execution
- **Malware deployment**: KNUCKLEBALL Python dropper (`deploy_new.py`) deploying Java-based payloads
- **Persistence**: NGINX Unit configuration tampering (`/var/lib/unit/conf.json`), startup script modification, in-memory Java agent injection
- **Web shell access**: ORANGETAIL (`agent_wp9.jar`) -- a custom Behinder-like Java web shell with encrypted payload execution
- **Tunneling**: Suo5 (`agent_wp8.jar`) -- reverse proxy for covert access to internal resources
- **Credential harvesting**: tcpdump capture of unencrypted LDAP traffic
- **Lateral movement**: NTLM authentication from appliance IP to domain controllers with non-inventory workstation names

### 4. Anti-Forensics / Evasion Techniques (Inferred)

Prior campaigns demonstrated memory-resident artifact deployment that is flushed on reboot, and modification of the appliance's NGINX Unit configuration to blend web shell access into legitimate traffic patterns.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation.

> **IMPORTANT NOTE:** SonicWall has NOT publicly released IOCs specific to CVE-2026-83548/CVE-2026-83549 exploitation. The IOCs below are drawn from the prior July 2026 exploitation campaign (CVE-2026-15409/15410) against the same appliance platform by threat actor UTA0533. These are included for cross-reference and historical hunting only -- they may or may not be relevant to the current exploitation activity.

### File System (from prior UTA0533 campaign)

| Platform | Path / Filename | Description |
|----------|----------------|-------------|
| Linux (SMA1000) | deploy_new.py | KNUCKLEBALL dropper |
| Linux (SMA1000) | agent_wp8.jar | Suo5 reverse proxy |
| Linux (SMA1000) | agent_wp9.jar | ORANGETAIL web shell |
| Linux (SMA1000) | xzfind | ROOTRUN privilege escalation binary |
| Linux (SMA1000) | /var/lib/unit/conf.json | NGINX Unit config (tampered for persistence) |
| Linux (SMA1000) | /tmp/temp.db* | Session theft artifacts |
| Linux (SMA1000) | /tmp/1234.sh | Exploit payload script |
| Linux (SMA1000) | hypdate.b64 | CVE-2026-15410 exploit payload |
| Linux (SMA1000) | lib.sh | LDAP credential capture script |

### Network (from prior UTA0533 campaign -- ASN 206092, F.N.S Holdings Limited)

| Type | Value | Context |
|------|-------|---------|
| IP Range | 45[.]131[.]194[.]0/24 | UTA0533 infrastructure |
| IP Range | 45[.]146[.]54[.]0/24 | UTA0533 infrastructure |
| IP Range | 63[.]135[.]161[.]0/24 | UTA0533 infrastructure |
| IP Range | 173[.]239[.]211[.]0/24 | UTA0533 infrastructure |
| IP | 193[.]37[.]32[.]179 | UTA0533 infrastructure |
| IP | 193[.]37[.]32[.]214 | UTA0533 infrastructure |
| IP | 216[.]73[.]163[.]151 | UTA0533 infrastructure |
| IP | 216[.]73[.]163[.]158 | UTA0533 infrastructure |

### Behavioral

**Appliance-level indicators (check on SMA1000 appliance):**

- **extraweb_access.log**: Requests to `/__api__/login` or `/__api__/logout` returning HTTP 200
- **extraweb_access.log**: Requests to `/wsproxy` with `host=0.0.0.0` or `host=127.0.0.1` returning HTTP 101
- **ctrl-service.log**: `remove_hotfix` invocations containing path traversal sequences (`../../../../../tmp/`)
- **File system**: Non-standard routes in `/var/lib/unit/conf.json` for `/__api__/login` or `/__api__/logout`
- **File system**: Unexpected JAR files in web application directories
- **Network**: NTLM logons (Windows Event ID 4624, type 3) originating from the SMA appliance IP with non-inventory workstation names (DESKTOP-KRLUI3J, DESKTOP-IC3C80F, DESKTOP-5P0TSCP, KALI, localhost)

**Note:** SonicWall recommends contacting their Technical Support to review appliances for indicators of compromise related to the new CVEs.

## MITRE ATT&CK Mapping

| TID | Technique | Observed / Inferred Behavior |
|-----|-----------|------------------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of SSRF (CVE-2026-83548) in the internet-facing Appliance Work Place interface |
| T1090 | Proxy | SSRF vulnerability weaponizes the appliance as a forward proxy to reach internal services |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | OS command injection (CVE-2026-83549) enables arbitrary shell command execution on the appliance |
| T1505.003 | Server Software Component: Web Shell | ORANGETAIL Java web shell deployed on compromised appliances (prior campaign) |
| T1078 | Valid Accounts | Stolen credentials used for lateral movement from compromised appliance (prior campaign) |
| T1021 | Remote Services | NTLM lateral movement from appliance IP to domain controllers (prior campaign) |
| T1543 | Create or Modify System Process | NGINX Unit configuration tampering for persistence (prior campaign) |
| T1557 | Adversary-in-the-Middle | tcpdump LDAP credential interception on secondary appliance (prior campaign) |

## Impact Assessment

**Scope:** All organizations running SonicWall SMA1000 series appliances (models 6210, 7210, 8200v) on firmware versions prior to 12.4.3-03526 or 12.5.0-02952 are vulnerable. This includes organizations that applied the July 2026 patches for CVE-2026-15409/15410, as the new CVEs affect those patched versions.

**Severity:** The chained exploitation achieves unauthenticated remote code execution with likely root privileges on the appliance. A compromised SMA appliance provides direct access to internal enterprise networks, VPN session data, cached credentials, and can serve as a persistent pivot point.

**Exposure:** SMA1000 appliances are internet-facing by design. Prior exploitation campaigns targeted organizations across the US, Australia, UAE, Colombia, and Switzerland spanning private and government sectors. The INC ransomware gang was linked to post-exploitation activity.

## Detection & Remediation

### Immediate Detection

1. **Check firmware version**: Verify SMA1000 appliances are running 12.4.3-03526+ or 12.5.0-02952+
2. **Review appliance logs**: Check `extraweb_access.log` for anomalous requests to internal API endpoints or proxy-like behavior
3. **Check NGINX Unit config**: Inspect `/var/lib/unit/conf.json` for unexpected routes
4. **Monitor lateral movement**: Search Windows Security logs for Event ID 4624 (LogonType 3) originating from SMA appliance IPs with suspicious workstation names
5. **Contact SonicWall**: SonicWall Technical Support can assist with IOC analysis on affected appliances

### Remediation

1. **Patch immediately**: Upgrade to firmware 12.4.3-03526 or 12.5.0-02952 (or later)
2. **If compromise is suspected**: Re-image physical appliances or redeploy virtual appliances
3. **Reset all credentials**: Change all user and administrator passwords
4. **Reset TOTP tokens**: Invalidate all TOTP tokens to prevent use of potentially stolen authentication factors
5. **Restrict AMC access**: Ensure the Appliance Management Console is not exposed to the internet
6. **Monitor post-patch**: Continue monitoring for lateral movement and anomalous authentication patterns after patching

### Long-Term Hardening

- Implement network segmentation to isolate SMA appliances from sensitive internal systems
- Deploy a web application firewall (WAF) in front of the Appliance Work Place interface
- Enable comprehensive logging on SMA appliances and forward to SIEM
- Establish a rapid patching cadence for edge/VPN appliances given the frequency of zero-day targeting
- Monitor CISA KEV catalog for additions of these CVEs and comply with remediation deadlines

## Detection Rules

These rules cover network-level SSRF exploitation patterns targeting SonicWall SMA1000 Appliance Work Place and AMC interfaces, post-compromise lateral movement indicators, appliance configuration tampering, and file-level malware artifacts from prior exploitation campaigns. The primary caveat is that SonicWall has not disclosed the specific exploitation path for CVE-2026-83548 (the new SSRF), so network detection rules are based on observable architectural patterns and prior exploitation TTPs rather than confirmed payloads.

### Sigma: SonicWall SMA1000 Appliance Work Place SSRF Exploitation Indicators

Detects HTTP access log patterns indicative of SSRF exploitation via the SMA1000 Appliance Work Place interface, covering both the prior `/wsproxy` abuse and internal API access patterns.

<!-- audit: Webserver logsource maps generically; field names (cs-uri-stem, sc-status) follow W3C extended log format. No defanged values in rule. Sigma converts to Splunk and LogScale without pipeline. Prior exploitation patterns (/__api__/, /wsproxy, host=localhost) are documented by Rapid7. New SSRF path unknown -- rule covers known architectural indicators only. FP risk from legitimate SMA Connect Agent sessions or monitoring tools. -->

- Compile: sigma convert Splunk ✅ / LogScale ✅
- Confidence: **medium** -- covers known exploitation patterns but the new CVE-2026-83548 access path is undisclosed

```yaml
title: SonicWall SMA1000 Appliance Work Place SSRF Exploitation Indicators
id: 8e3a2f71-c594-4b82-a1d7-9f6e5c8b0d43
status: experimental
description: >
    Detects HTTP access patterns in SMA1000 appliance web server logs indicative
    of SSRF exploitation via the Appliance Work Place interface. Covers the
    unintended alternate access path pattern (CVE-2026-83548) and prior wsproxy
    abuse (CVE-2026-15409) where an unauthenticated attacker forces the appliance
    to proxy requests to internal localhost services. Monitor for requests returning
    HTTP 101 (WebSocket upgrade) or HTTP 200 to internal API endpoints that should
    not be externally accessible.
references:
    - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0016
    - https://www.securityweek.com/sonicwall-warns-of-two-sma1000-zero-days-exploited-in-attacks/
    - https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1190
    - attack.t1090
logsource:
    category: webserver
detection:
    selection_ssrf_api:
        cs-uri-stem|contains:
            - '/__api__/login'
            - '/__api__/logout'
        sc-status: 200
    selection_wsproxy:
        cs-uri-stem|contains: '/wsproxy'
        sc-status: 101
    selection_proxy_ssrf:
        cs-uri-stem|contains:
            - 'host=0.0.0.0'
            - 'host=127.0.0.1'
            - 'host=localhost'
            - '::ffff:127.0.0.1'
    condition: 1 of selection_*
falsepositives:
    - Legitimate SMA Connect Agent sessions using /wsproxy with valid bmID values
    - Internal monitoring tools accessing the appliance API
level: high
```

### Sigma: Lateral Movement from SonicWall SMA1000 Appliance via NTLM

Detects NTLM network logon events from compromised SMA1000 appliances with suspicious workstation names observed in prior UTA0533 exploitation campaigns.

<!-- audit: Windows Security logsource with EventID 4624/LogonType 3. Workstation names from Rapid7 IOC report for prior CVE-2026-15409/15410 campaign. Same threat actors may reuse infrastructure against new CVEs. No defanged values in rule (workstation names are literal). FP from legitimate hosts named KALI (pen-test boxes). Tune SourceNetworkAddress to SMA appliance IP range for higher fidelity. -->

- Compile: sigma convert Splunk ✅ / LogScale ✅
- Confidence: **medium** -- workstation names are from prior campaign; same actors may reuse them

```yaml
title: Lateral Movement from SonicWall SMA1000 Appliance via NTLM
id: a4b92c6d-1e87-4f53-96d0-3c8a5e7f2b19
status: experimental
description: >
    Detects NTLM network logon events (type 3) originating from SonicWall SMA1000
    appliance IP addresses with suspicious workstation names. After chaining
    CVE-2026-83548 (SSRF) and CVE-2026-83549 (command injection) for
    unauthenticated RCE, attackers pivot from compromised SMA appliances into
    internal networks. Prior exploitation by UTA0533 exhibited NTLM logons from
    the appliance IP with non-inventory workstation names. Tune SourceNetworkAddress
    to your SMA appliance IP range.
references:
    - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0016
    - https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1021
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        WorkstationName:
            - 'DESKTOP-KRLUI3J'
            - 'DESKTOP-IC3C80F'
            - 'DESKTOP-5P0TSCP'
            - 'KALI'
            - 'localhost'
    condition: selection
falsepositives:
    - Legitimate workstations that happen to have matching names
    - Penetration testing from authorized workstations named KALI
level: high
```

### Sigma: SonicWall SMA1000 NGINX Unit Configuration Tampering

Detects modification of the NGINX Unit configuration file on SMA1000 appliances, a persistence technique used after exploitation to expose web shells.

<!-- audit: Linux file_event logsource. TargetFilename path is the documented NGINX Unit config location on SMA1000 appliances per Rapid7 analysis. Modification of this file outside firmware updates is highly anomalous. Requires Sysmon for Linux or auditd file monitoring on the appliance (may not be feasible on all deployments). No defanged values. -->

- Compile: sigma convert Splunk ✅ / LogScale ✅
- Confidence: **high** -- modification of this specific file outside patch operations is a strong indicator of compromise

```yaml
title: SonicWall SMA1000 NGINX Unit Configuration Tampering
id: d7f18e43-5a29-4c61-b802-6e9d3f1a7c50
status: experimental
description: >
    Detects modification of the NGINX Unit configuration file on SonicWall SMA1000
    appliances, a technique used by attackers after exploiting CVE-2026-83548 and
    CVE-2026-83549 to expose web shells or establish persistence. Prior exploitation
    by UTA0533 modified /var/lib/unit/conf.json to add routes for /__api__/login and
    /__api__/logout endpoints. This rule monitors for file changes to the Unit
    configuration and for command-line activity involving the conf.json path on
    Linux-based SMA appliances.
references:
    - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0016
    - https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1505.003
    - attack.t1543
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains:
            - '/var/lib/unit/conf.json'
    condition: selection
falsepositives:
    - Legitimate SMA appliance firmware updates or hotfix installations
    - Authorized administrator configuration changes
level: critical
```

### Suricata: SonicWall SMA1000 SSRF and Exploitation Network Detection

Three Suricata rules detecting network-level exploitation patterns: internal API access attempts via SSRF, wsproxy endpoint abuse with localhost targeting, and the SMA Connect Agent user-agent spoofing pattern.

<!-- audit: All rules use http protocol with dot-notation sticky buffers. SID range 2100301-2100303. Flow established,to_server on all rules. Second rule fixed to avoid duplicate http.uri buffer (content chained within single sticky buffer context). Third rule combines URI and UA matching for higher fidelity. All three validated with suricata -T. Reference URLs use bare domain (no protocol) per Suricata convention. -->

- Compile: suricata -T ✅
- Confidence: **medium** -- patterns cover known exploitation vectors; the specific new SSRF path is undisclosed

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - SonicWall SMA1000 SSRF Exploitation - Internal API Access Attempt"; flow:established,to_server; http.uri; content:"/__api__/"; fast_pattern; http.method; content:"GET"; classtype:web-application-attack; reference:url,psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0016; reference:cve,2026-83548; metadata:author Actioner, created_at 2026-09-02, confidence medium; sid:2100301; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - SonicWall SMA1000 Wsproxy SSRF to Localhost Service"; flow:established,to_server; http.uri; content:"/wsproxy"; fast_pattern; content:"host="; content:"port="; classtype:web-application-attack; reference:url,psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0016; reference:cve,2026-83548; metadata:author Actioner, created_at 2026-09-02, confidence medium; sid:2100302; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - SonicWall SMA1000 SMA Connect Agent SSRF User-Agent"; flow:established,to_server; http.uri; content:"/wsproxy"; http.user_agent; content:"SMA Connect Agent"; fast_pattern; classtype:web-application-attack; reference:url,rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/; reference:cve,2026-83548; metadata:author Actioner, created_at 2026-09-02, confidence medium; sid:2100303; rev:1;)
```

### Snort: SonicWall SMA1000 SSRF Internal API Access

Snort 3 equivalent of the Suricata internal API access rule. Snort is not available in this environment for compilation.

- Compile: ⚠️ uncompiled (snort not available)
- Confidence: **medium**

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - SonicWall SMA1000 SSRF - Internal API Access Attempt"; flow:established, to_server; http_uri; content:"/__api__/", fast_pattern; http_method; content:"GET"; classtype:web-application-attack; reference:url,psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0016; reference:cve,2026-83548; metadata:author Actioner, created 2026-09-02; sid:2100304; rev:1;)
```

### YARA: SonicWall SMA1000 Post-Exploitation Malware Artifacts

Detects post-exploitation artifacts from SonicWall SMA1000 compromises including ORANGETAIL web shell, KNUCKLEBALL dropper, Suo5 proxy, ROOTRUN escalation tool, and exploitation payload strings.

<!-- audit: Two rules. First rule targets file-system malware artifacts (deploy_new.py, agent_wp8/9.jar, xzfind, conf.json tampering indicators, remove_hotfix exploitation strings). Second rule targets PCAP/network capture artifacts containing SSRF exploitation request patterns. All strings are ASCII with appropriate modifiers. Conditions use logical combinations to avoid single-string false positives. Compiled with yarac exit 0. Malware names from Volexity/BleepingComputer reporting on prior UTA0533 campaign. -->

- Compile: yarac ✅
- Confidence: **medium** -- malware artifacts are from the prior July 2026 campaign but may be reused against newly compromised appliances

```yara
rule SonicWall_SMA1000_Post_Exploit_Artifacts
{
    meta:
        description = "Detects post-exploitation artifacts from SonicWall SMA1000 compromises including ORANGETAIL web shell, KNUCKLEBALL dropper, Suo5 proxy, and ROOTRUN escalation tool. These malware families were deployed by UTA0533 via CVE-2026-15409/15410 and may be reused in exploitation of CVE-2026-83548/83549."
        author = "Actioner"
        date = "2026-09-02"
        reference = "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0016"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $knuckleball1 = "deploy_new.py" ascii fullword
        $knuckleball2 = "agent_wp8.jar" ascii fullword
        $knuckleball3 = "agent_wp9.jar" ascii fullword

        $orangetail1 = "agent_wp9" ascii
        $orangetail2 = "Behinder" ascii nocase

        $suo5_1 = "agent_wp8" ascii
        $suo5_2 = "suo5" ascii nocase fullword

        $rootrun1 = "xzfind" ascii fullword

        $path1 = "/var/lib/unit/conf.json" ascii
        $path2 = "/var/lib/aventail" ascii
        $path3 = "__api__/login" ascii
        $path4 = "__api__/logout" ascii

        $cmd1 = "remove_hotfix" ascii
        $cmd2 = "sysCtrl.execRemoveHotfix" ascii
        $cmd3 = "rollbackConfirm" ascii

    condition:
        filesize < 10MB and
        (
            2 of ($knuckleball*) or
            all of ($orangetail*) or
            all of ($suo5_*) or
            $rootrun1 or
            (2 of ($path*) and 1 of ($cmd*)) or
            ($cmd2)
        )
}

rule SonicWall_SMA1000_SSRF_Exploit_Request
{
    meta:
        description = "Detects network capture artifacts containing SonicWall SMA1000 SSRF exploitation request patterns targeting wsproxy or internal API endpoints"
        author = "Actioner"
        date = "2026-09-02"
        reference = "https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $wsproxy = "/wsproxy?bmID=-3389" ascii
        $ua = "SMA Connect Agent" ascii
        $api_login = "/__api__/login" ascii
        $api_logout = "/__api__/logout" ascii
        $host_local1 = "host=0.0.0.0" ascii
        $host_local2 = "host=127.0.0.1" ascii
        $host_local3 = "host=localhost" ascii

    condition:
        filesize < 50MB and
        (
            ($wsproxy and $ua) or
            ($wsproxy and 1 of ($host_local*)) or
            ($api_login and $api_logout)
        )
}
```

## Lessons Learned

1. **Patch-on-patch vulnerability risk**: The new CVEs affect firmware versions that were the fix for the July 2026 zero-days, demonstrating that patch releases themselves can introduce or leave open new attack surfaces in the same components. Organizations should not assume that a patched appliance is fully secure and should maintain continuous monitoring.

2. **Repeated targeting of edge/VPN appliances**: SonicWall SMA1000 has now been subject to two separate zero-day exploitation campaigns in under three months, both targeting the same architectural components (Appliance Work Place SSRF + AMC command injection). This pattern mirrors broader industry trends of persistent threat actor focus on SSL VPN and secure access gateway appliances.

3. **IOC gap in vendor advisories**: SonicWall's advisory for the new CVEs contains no IOCs or detailed attack information, leaving defenders without concrete indicators for detection. This underscores the need for independent security research and behavioral detection capabilities that do not rely solely on vendor-provided IOCs.

4. **Architectural defense-in-depth**: The fundamental weakness -- localhost services trusting network isolation rather than implementing their own authentication -- persists across multiple vulnerability generations. Organizations should implement defense-in-depth controls around edge appliances including network segmentation, WAF deployment, and enhanced monitoring of lateral movement patterns from VPN infrastructure.

## Sources

- [SonicWall PSIRT Advisory SNWLID-2026-0016](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0016) -- Official vendor advisory confirming active exploitation and providing fixed versions
- [SecurityWeek: SonicWall Warns of Two SMA1000 Zero-Days Exploited in Attacks](https://www.securityweek.com/sonicwall-warns-of-two-sma1000-zero-days-exploited-in-attacks/) -- News coverage with CVE details, CVSS scores, and affected versions
- [Infosecurity Magazine: Hackers Chain SonicWall Zero-Day](https://www.infosecurity-magazine.com/news/hackers-chain-sonicwall-zeroday/) -- Coverage confirming chained exploitation and remediation steps
- [BleepingComputer: SonicWall Warns of Actively Exploited SMA1000 Zero-Day Flaws](https://www.bleepingcomputer.com/news/security/sonicwall-warns-of-actively-exploited-sma1000-zero-day-flaws/) -- Additional reporting with version details
- [BleepingComputer: SonicWall SMA1000 Flaws Exploited to Push Custom Malware](https://www.bleepingcomputer.com/news/security/sonicwall-sma1000-flaws-exploited-as-zero-days-to-push-custom-malware/) -- UTA0533 malware details (KNUCKLEBALL, ORANGETAIL, Suo5, ROOTRUN)
- [Rapid7: MDR Team Discovers SonicWall SMA1000 Zero Days (CVE-2026-15409/15410)](https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410/) -- Detailed technical analysis of prior exploitation chain with IOCs and log indicators
- [SecurityWeek: Recent SonicWall Vulnerabilities Exploited in Ransomware Attacks](https://www.securityweek.com/recent-sonicwall-vulnerabilities-exploited-in-ransomware-attacks/) -- INC ransomware gang and UTA0533 attribution for prior campaign
- [THREATINT CVE-2026-83549](https://cve.threatint.com/CVE/CVE-2026-83549) -- CVE record with CWE-78 classification and CVSS vector
- [OffSeq Threat Radar: CVE-2026-83548](https://radar.offseq.com/threat/cve-2026-83548-cwe-918-server-side-request-forgery-ssrf-in-sonicwall-sma1000-7c769411ea7323c3) -- CVE record with CWE-918 and CWE-441 classifications

---
*Report generated by Actioner*
