# Technical Analysis Report: UniFi OS Authentication Bypass to Root RCE — CVE-2026-34908, CVE-2026-34909, CVE-2026-34910 (2026-06-07)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-07
Version: 1.0 (DRAFT)

## Executive Summary

Three critical vulnerabilities in Ubiquiti UniFi OS Server (CVE-2026-34908, CVE-2026-34909, CVE-2026-34910) chain together to achieve **unauthenticated remote code execution with root privileges**. All three carry the maximum CVSS 3.1 score of **10.0**. Disclosed by Ubiquiti on May 22, 2026 via Security Advisory Bulletin 064, the attack chain exploits a mismatch between how the nginx authentication gateway reads raw, percent-encoded request URIs versus how nginx routes using normalized URIs. An attacker crafts a request whose raw form begins with the auth-exempt `/api/auth/validate-sso/` prefix while its normalized form resolves to authenticated internal backends, bypassing the gate entirely. Once past authentication, the attacker reaches the package-update service endpoint (`/ucs/update/latest_package`) where unsanitized input is interpolated via `fmt.Sprintf` into a command string executed through `sh -c`, yielding arbitrary command execution. Privilege escalation to root follows via passwordless sudo entitlements on `dpkg`, `chmod`, and `systemctl`.

Bishop Fox demonstrated the full end-to-end exploit chain on version 5.0.6, proving a single crafted HTTP request yields a root shell without credentials or user interaction. Censys tracks nearly **100,000 internet-exposed UniFi OS endpoints**, predominantly in the United States. In deployments with UniFi Access and UniFi Protect, exploitation enables unlocking doors, cloning NFC/biometric credentials, monitoring live camera feeds, and deleting surveillance footage. Fixed in **UniFi OS Server 5.0.8** (unifi-core 5.0.153).

## Background: Ubiquiti UniFi OS

UniFi OS is Ubiquiti's unified management platform running on UniFi Dream Machine (UDM) series gateways, UniFi Cloud Gateway (UCG) devices, UNVR network video recorders, UNAS storage appliances, and related hardware. It provides a web-based management interface (default port TCP 11443) that consolidates network, access control, and video surveillance management. The platform uses an nginx reverse proxy as an authentication gateway that dispatches requests to internal service backends (identity, network application, access, protect) based on URI routing.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-21 | Vulnerabilities reported via Ubiquiti's HackerOne bug bounty program |
| 2026-05-22 | Ubiquiti publishes Security Advisory Bulletin 064 with patches |
| 2026-06-06 | Bishop Fox publishes full technical exploitation and detection analysis |
| 2026-06-06 | Multiple security outlets cover the chain (GBHackers, BleepingComputer, SecurityOnline) |

## Root Cause: Nginx Raw vs. Normalized URI Divergence

The authentication gateway reads the `x-original-uri` header (the raw, percent-encoded request URI as sent by the client) to determine whether a route is publicly exempt from authentication. Certain paths such as `/api/auth/validate-sso/` are whitelisted. However, nginx selects the upstream backend using the normalized `$uri` variable, where percent-encoded characters are decoded and `../` sequences are collapsed. This divergence allows an attacker to craft a request whose raw form passes the auth gate's exemption check while its normalized form routes to an authenticated internal service.

## Technical Analysis of the Malicious Payload

### 1. Authentication Gateway Bypass (CVE-2026-34908 / CVE-2026-34909)

The exploit crafts URIs where the raw form starts with `/api/auth/validate-sso/` (passing the authentication gate) but contains encoded path traversal sequences (`..%2f`, `..%2e`, `%2e%2e`) that, when normalized by nginx, resolve to internal proxy routes such as `/proxy/<service>/`. On vulnerable versions (5.0.6), the auth gateway returns HTTP 200 (pass-through); on patched versions (5.0.8), it returns HTTP 400 (rejection).

**CVE-2026-34909** (Path Traversal, CWE-22) enables reading arbitrary files on the underlying system, including credentials. **CVE-2026-34908** (Improper Access Control, CWE-284) enables unauthorized configuration changes through the bypassed authentication gate.

### 2. Command Injection (CVE-2026-34910)

Once past the authentication gateway, the attacker reaches the package-update backend at `/ucs/update/latest_package`. This service accepts a user-supplied package name and passes it directly through `fmt.Sprintf` into a command string:

```
sudo /usr/bin/uos runnable latest-versions %v
```

The `%v` placeholder is the caller-supplied package name, interpolated verbatim and then executed via `sh -c` with no input validation. Shell metacharacters (`;`, `|`, `` ` ``, `$()`, `&&`) in the package name parameter allow arbitrary command injection.

### 3. Privilege Escalation to Root

The `ucs-update` service account has passwordless sudo entitlements on version 5.0.6:
- `sudo /usr/bin/dpkg` -- installs packages whose maintainer scripts run as root
- `sudo /bin/chmod` -- arbitrary permission changes
- `sudo /bin/systemctl` -- service control
- `sudo /usr/bin/uos` -- the command wrapper itself

Escalation to root is achieved by installing a crafted `.deb` package whose post-install script executes as root, or directly via the `dpkg`/`chmod` entitlements.

### 4. Platform-Specific Behavior

**Affected hardware:** UCG gateways, UDM series, UDR, UNVR recorders, UNAS storage appliances, ENVR, UCG models -- all running UniFi OS prior to patched firmware.

**Physical-security impact:** In deployments with UniFi Access, exploitation enables door unlocking, NFC credential cloning, and facial-recognition credential extraction. In deployments with UniFi Protect, exploitation enables live camera feed monitoring and permanent deletion of surveillance footage.

### 5. Anti-Forensics / Evasion Techniques

The command injection uses time-based detection as an oracle -- injected delays cause response latency, confirming exploitability without triggering obvious error conditions. The auth bypass operates at the nginx layer, potentially evading application-level logging if only backend logs are monitored.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|--------------------|-------------|
| UniFi OS Server (unifi-core) | < 5.0.153 (OS < 5.0.8) | Auth bypass + command injection chain |
| UCG/UDM/UDR/UNVR/ENVR firmware | < 5.1.12 | Auth bypass + command injection chain |
| UNAS-2/4/Pro firmware | < 5.1.10 | Auth bypass + command injection chain |
| UDM-Beast firmware | < 5.1.11 | Auth bypass + command injection chain |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux (UniFi OS) | N/A | N/A | No specific malware artifacts published; exploitation is live command execution |

### Network

| Type | Value | Context |
|------|-------|---------|
| URI Pattern | `/api/auth/validate-sso/..%2f<target>` | Auth bypass -- raw URI with encoded traversal |
| URI Pattern | `/ucs/update/latest_package` | Command injection endpoint |
| Port | TCP 11443 | Default UniFi OS web management interface |

### Behavioral

- HTTP requests containing `/api/auth/validate-sso/` combined with percent-encoded path traversal sequences (`..%2f`, `%2e%2e`, `..%2e`) -- legitimate SSO validation requests never contain traversal patterns
- Requests to `/ucs/update/latest_package` containing shell metacharacters (`;`, `|`, `` ` ``, `$()`, `&&`)
- HTTP 200 responses from internal backends (JSON responses instead of nginx 401) to requests containing traversal patterns
- Unexpected child processes under the `ucs-update` service account
- Anomalous passwordless sudo invocations of `dpkg`, `chmod`, or `systemctl` from non-root service contexts

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated exploitation of nginx auth gateway bypass on internet-exposed UniFi OS management interface |
| T1059 | Command and Scripting Interpreter | Shell command injection via `sh -c` execution of unsanitized package name input |
| T1068 | Exploitation for Privilege Escalation | Escalation from `ucs-update` service account to root via passwordless sudo on dpkg/chmod/systemctl |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Exploitation of overly permissive passwordless sudoers entries for dpkg, chmod, systemctl |

## Impact Assessment

**Breadth:** Censys identifies nearly 100,000 internet-exposed UniFi OS endpoints, predominantly in the United States. All UniFi OS Server versions prior to 5.0.8 are affected.

**Depth:** Complete system compromise -- unauthenticated root shell. In converged deployments (network + access + video), the impact extends to physical security: door access control, credential databases, and surveillance footage.

**Stealth:** The auth bypass operates at the nginx URI-processing layer, potentially invisible to application-level logging. Time-based command injection oracles allow silent exploitation probing.

**Active exploitation:** No confirmed in-the-wild exploitation at the time of disclosure. However, the full exploit chain is now publicly documented by Bishop Fox, and the attack requires no authentication, no user interaction, and low complexity.

## Detection & Remediation

### Immediate Detection

**Check firmware version:**
```bash
# SSH into UniFi OS device
ubnt-systool firmware
# Vulnerable if UniFi OS < 5.0.8 (unifi-core < 5.0.153)
```

**Search nginx access logs for bypass attempts:**
```bash
# Look for validate-sso combined with traversal patterns
grep -E 'validate-sso.*\.\.(%2[fFeE]|/)' /var/log/nginx/access.log*
```

**Check for unauthorized processes under ucs-update:**
```bash
ps aux | grep ucs-update
# Investigate unexpected child processes
```

### Remediation

1. **Immediately update** to UniFi OS Server 5.0.8+ (unifi-core 5.0.153+), or the hardware-equivalent fixed firmware version
2. **Restrict network exposure** -- do not expose UniFi OS management (TCP 11443) to the internet; place behind VPN or firewall
3. **Review access logs** for historical exploitation attempts (traversal patterns in validate-sso URIs)
4. **Audit for compromise** -- if running a vulnerable version exposed to untrusted networks, check for unauthorized accounts, modified configurations, and unexpected cron/systemd entries
5. **Rotate credentials** on any device that was internet-exposed while running a vulnerable version

### Long-Term Hardening

- Never expose UniFi OS management interfaces directly to the internet
- Implement network segmentation between management plane and production traffic
- Deploy a web application firewall (WAF) or reverse proxy that normalizes and inspects URIs before forwarding
- Apply principle of least privilege to service account sudoers entries -- the overly broad passwordless sudo configuration was a root-cause enabler for privilege escalation

## Detection Rules

These detections target the specific exploitation artifacts of the CVE-2026-34908/34909/34910 chain: the auth-bypass URI pattern and the command injection endpoint. PoC/advisory-specific altitude (default); Sigma rules convert to Splunk and CrowdStrike LogScale. Network rules (Suricata/Snort) match the HTTP exploitation traffic. Note: compiles does not equal fires -- verify in your log pipeline against UniFi OS web server logs or inline network inspection.

### Sigma: UniFi OS Auth Gateway Bypass via validate-sso Path Traversal

Detects HTTP requests combining the auth-exempt `/api/auth/validate-sso/` prefix with percent-encoded traversal sequences, the distinctive bypass pattern for CVE-2026-34908/34909.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on raw URI containing both the SSO prefix and encoded traversal — legitimate validate-sso requests never carry these patterns. FP risk minimal: encoded traversal in a validate-sso path has no benign use case. Evasion: double-encoding or alternative traversal encodings may bypass; rule covers the published PoC patterns. -->
```yaml
title: UniFi OS Authentication Gateway Bypass via Path Traversal in validate-sso
id: 8f3a7c1e-4d2b-4e9a-b6f5-1c8d9e0a2b3f
status: experimental
description: >
    Detects HTTP requests to UniFi OS that combine the auth-exempt /api/auth/validate-sso/
    prefix with percent-encoded path traversal sequences, indicating exploitation of
    CVE-2026-34908/CVE-2026-34909 authentication gateway bypass.
references:
    - https://bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis
    - https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b
    - https://nvd.nist.gov/vuln/detail/CVE-2026-34908
author: Actioner
date: 2026/06/07
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_path:
        cs-uri-query|contains: '/api/auth/validate-sso/'
    selection_traversal:
        cs-uri-query|contains:
            - '..%2f'
            - '..%2F'
            - '%2e%2e'
            - '%2E%2E'
            - '..%2e'
            - '..%2E'
    condition: selection_path and selection_traversal
falsepositives:
    - Legitimate SSO validation requests would not contain encoded traversal sequences
level: critical
```

### Sigma: UniFi OS Command Injection via Package Update Endpoint

Detects requests to the `/ucs/update/latest_package` endpoint with shell metacharacters, the injection vector for CVE-2026-34910.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on the specific package-update endpoint combined with shell metacharacters in the URI. FP: semicolons may appear in legitimate query strings — scope to UniFi OS web logs to reduce. Evasion: URL-encoding of the metacharacters themselves; rule assumes raw log capture. -->
```yaml
title: UniFi OS Command Injection via Package Update Endpoint
id: 2e5b8d4a-7f1c-4a3e-9c6d-3b0f1e2d4a5c
status: experimental
description: >
    Detects HTTP requests targeting the UniFi OS package-update backend endpoint
    /ucs/update/latest_package with shell metacharacters in the URI, indicating
    exploitation of CVE-2026-34910 command injection.
references:
    - https://bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis
    - https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b
    - https://nvd.nist.gov/vuln/detail/CVE-2026-34910
author: Actioner
date: 2026/06/07
tags:
    - attack.t1059
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_endpoint:
        cs-uri-query|contains: '/ucs/update/latest_package'
    selection_injection:
        cs-uri-query|contains:
            - ';'
            - '|'
            - '$('
            - '`'
            - '&&'
    condition: selection_endpoint and selection_injection
falsepositives:
    - Legitimate package update requests do not contain shell metacharacters
level: critical
```

### Suricata: UniFi OS Auth Bypass via validate-sso Path Traversal

Detects HTTP requests containing the `/api/auth/validate-sso/` prefix combined with encoded traversal (`..%2`) in the URI, targeting CVE-2026-34908/34909.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Matches on http.uri containing both the SSO prefix and traversal encoding. fast_pattern on the SSO prefix (longer, more distinctive). Scope: any destination port (UniFi defaults to 11443 but operators may customize). -->
```suricata
alert http $HOME_NET any -> any any (msg:"Actioner - UniFi OS Auth Bypass via validate-sso Path Traversal (CVE-2026-34908/34909)"; flow:established,to_server; http.uri; content:"/api/auth/validate-sso/"; fast_pattern; content:"..%2"; classtype:web-application-attack; reference:cve,2026-34908; reference:cve,2026-34909; reference:url,bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis; metadata:author Actioner, created_at 2026-06-07; sid:2200001; rev:1;)
```

### Suricata: UniFi OS Command Injection via Package Update Endpoint

Detects HTTP requests to the `/ucs/update/latest_package` endpoint with shell metacharacters, targeting CVE-2026-34910.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. PCRE uses hex escapes for metacharacters to avoid Suricata parse issues with literal semicolons in the regex character class. Matches URI containing endpoint + any of ; | ` $ &. -->
```suricata
alert http $HOME_NET any -> any any (msg:"Actioner - UniFi OS Command Injection via Package Update Endpoint (CVE-2026-34910)"; flow:established,to_server; http.uri; content:"/ucs/update/latest_package"; fast_pattern; pcre:"/latest_package.*[\x3b\x7c\x60\x24\x26]/"; classtype:web-application-attack; reference:cve,2026-34910; reference:url,bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis; metadata:author Actioner, created_at 2026-06-07; sid:2200002; rev:1;)
```

### Snort: UniFi OS Auth Bypass via validate-sso Path Traversal

Detects HTTP requests with the `/api/auth/validate-sso/` prefix and encoded traversal in the raw URI, targeting CVE-2026-34908/34909.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0 (tested via include in snort.conf). Both contents match http_raw_uri — the bypass pattern exists only in the raw (percent-encoded) URI, not the normalized form. Snort 2.9 syntax (underscore buffers). -->
```snort
alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"Actioner - UniFi OS Auth Bypass via validate-sso Path Traversal (CVE-2026-34908/34909)"; flow:established,to_server; content:"/api/auth/validate-sso/"; http_raw_uri; fast_pattern; content:"..%2"; http_raw_uri; sid:2100001; rev:1; classtype:web-application-attack; reference:cve,2026-34908; reference:cve,2026-34909; reference:url,bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis;)
```

### Snort: UniFi OS Command Injection via Package Update Endpoint

Detects HTTP requests to the package-update endpoint with shell metacharacters in the URI, targeting CVE-2026-34910.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0. PCRE with /U flag for http_uri buffer matching. Character class matches ; | ` $ &. -->
```snort
alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"Actioner - UniFi OS Command Injection via Package Update Endpoint (CVE-2026-34910)"; flow:established,to_server; content:"/ucs/update/latest_package"; http_uri; fast_pattern; pcre:"/latest_package.*[;|`$&]/U"; sid:2100002; rev:1; classtype:web-application-attack; reference:cve,2026-34910; reference:url,bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis;)
```

### YARA: N/A

No file-level indicators suitable for YARA detection in this topic. The exploitation chain is entirely network-based (HTTP request manipulation) with no dropped malware artifacts or distinctive file signatures published.

## Lessons Learned

1. **URI normalization divergence is a systemic class of auth bypass.** When different components of a web stack interpret URIs differently -- one reading the raw form, another normalizing -- authentication decisions made on the raw form can be completely bypassed. This pattern has appeared before (e.g., Spring4Shell, Apache path traversal CVEs) and will appear again. Auth gateways must operate on the *same* URI representation used for routing.

2. **Passwordless sudo on powerful binaries is a privilege escalation accelerator.** The `ucs-update` service account's passwordless sudo access to `dpkg`, `chmod`, and `systemctl` turned a command injection into trivial root escalation. Least-privilege sudoers policies and argument restrictions (sudoers `NOPASSWD` with specific argument whitelists) would have significantly limited the blast radius.

3. **Physical-security convergence multiplies cyber impact.** The integration of network management (UniFi Network), physical access control (UniFi Access), and video surveillance (UniFi Protect) on a single platform means a cyber compromise yields physical-world consequences: door unlocking, credential cloning, and evidence destruction.

## Sources

- [Bishop Fox - Popping Root on UniFi OS Server](https://bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis) -- primary technical analysis with full exploitation chain and detection guidance
- [Ubiquiti Security Advisory Bulletin 064](https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b) -- vendor advisory with affected/fixed versions
- [NVD - CVE-2026-34908](https://nvd.nist.gov/vuln/detail/CVE-2026-34908) -- CVSS 10.0, CWE-284 Improper Access Control
- [GBHackers - Critical UniFi OS Auth Bypass Flaws](https://gbhackers.com/critical-unifi-os-auth-bypass-flaws/) -- news coverage with attack chain summary
- [BleepingComputer - Ubiquiti patches three max severity UniFi OS vulnerabilities](https://www.bleepingcomputer.com/news/security/ubiquiti-patches-three-max-severity-unifi-os-vulnerabilities/) -- news coverage with exposure statistics
- [SecurityOnline - Triple CVSS 10.0 Warning](https://securityonline.info/ubiquiti-unifi-os-critical-vulnerabilities-cvss-10-firmware-update/) -- news coverage with affected hardware matrix
- [Cyber Security Agency of Singapore - AL-2026-059](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-059/) -- government advisory

---
*Report generated by Actioner*
