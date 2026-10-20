# Technical Analysis Report: Plex2Shell Exploit Chain -- Unauthenticated RCE in Plex Media Server

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-20
Version: 1.0 (FINAL)

## Executive Summary

Plex2Shell is a chain of four vulnerabilities in Plex Media Server (CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656) that, when exploited in sequence, achieve unauthenticated remote code execution. The chain was discovered by researcher Zach Main and reported to Plex on July 27, 2026. Plex shipped fixes on August 3, 2026 in version 1.43.3.10861, but the researcher published a detailed writeup and proof-of-concept on October 16, 2026. Within 24 hours, honeypot operators observed in-the-wild exploitation deploying XMRig-based cryptocurrency miners and a reverse proxy backdoor called "myawesomeproxy." The assessed CVSS 3.1 impact of the full chain is 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). All Plex Media Server instances below version 1.43.3.10861 -- including NAS, VM, and Docker deployments -- are vulnerable.

## Background

Plex Media Server is a widely deployed media management and streaming platform used by millions of home users, small businesses, and organizations. It typically listens on TCP port 32400 and is frequently exposed directly to the internet via Plex's remote access feature. The server includes a transcoding subsystem that leverages x264/x265 codec libraries loaded dynamically from a Codecs directory. The companion protocol endpoint (`/player/`) supports interactions with Plex clients and accepts connections with minimal authentication validation. This combination of internet exposure, media transcoding, and plugin architecture creates the attack surface exploited by Plex2Shell.

## Attack Timeline

| Date (UTC) | Event |
|---|---|
| 2026-07-27 | Zach Main reports four vulnerabilities to Plex |
| 2026-08-03 | Plex releases version 1.43.3.10861 with fixes |
| 2026-08-04 | Plex confirms bugs, awards bug bounty |
| 2026-09-23 | CVE IDs assigned (CVE-2026-96652, -96654, -96655, -96656) |
| 2026-10-16 | Zach Main publishes detailed writeup and PoC at zmain[.]info/blog/plex2shell; PoC code released on GitHub (code-zm/plex2shell) |
| 2026-10-17 | First in-the-wild exploitation observed on a honeypot (boredhackerblog[.]info); attackers deploy XMRig miner and myawesomeproxy |
| 2026-10-20 | Multiple news outlets report weaponization; Reddit reports of compromised Plex servers with "mylovelyminer" payload |

## Root Cause

The Plex2Shell chain exploits four distinct vulnerability classes:

1. **CVE-2026-96652 (CVSS 5.3) -- Unauthenticated SSRF:** The `/player/timeline` companion-protocol endpoint checks only that an authentication header is present, not that it is valid. The `protocol` parameter is inserted into a constructed callback URL without validation, allowing an attacker to make the server POST to an arbitrary destination from a loopback origin.

2. **CVE-2026-96654 (CVSS 6.9) -- Improper Neutralization / Token Theft:** The `searchOne` endpoint allows an attacker to invoke plugin management functions with attacker-supplied parameters. A dead auth guard (return value discarded) fails to block unrecognized identifiers, and the identifier is inserted into an internal URL without encoding. An outbound-request helper attaches the owner's admin token based on a loose string-prefix hostname match, leaking it to an attacker-controlled server.

3. **CVE-2026-96655 (CVSS 5.3) -- Authenticated SSRF + Arbitrary File Write:** Using the stolen admin token, the attacker triggers a transcode via `/video/:/transcode/universal` pointing to an attacker-hosted video. The `TranscoderH264Options` preference is abused to pass the x264 `dump-yuv` option, which writes raw frame data to an attacker-chosen file path in the Codecs directory. The "video" is a specially crafted MP4 containing an ELF shared object padded with YUV420p frame data.

4. **CVE-2026-96656 (CVSS 8.6) -- Unsigned Codec Loading / Code Execution:** The Plex transcoder loads any `.so` file found in the Codecs directory via `dlopen` without checking the library name (no "lib" prefix requirement), executable permissions, digital signatures, or required symbols. When `dlopen` loads the planted `.so`, its ELF constructors (`DT_INIT_ARRAY`) execute before symbol resolution. The malicious shared object contains a `__attribute__((constructor))` function that calls `fork()` then `execve("/bin/sh", ["/bin/sh", "-c", CMD], NULL)`, achieving arbitrary command execution as the `plex` user (typically uid 1000).

## Technical Analysis

### Stage 1: Unauthenticated SSRF (CVE-2026-96652)

The attacker sends an HTTP request to `/player/timeline` on port 32400 with a crafted `protocol=` parameter. Because the endpoint only validates the presence (not validity) of an auth header, and requests from loopback are trusted by internal APIs, this SSRF reaches internal plugin management endpoints that would otherwise require authentication.

### Stage 2: Admin Token Theft (CVE-2026-96654)

The SSRF is pivoted to hit the `searchOne` endpoint with an injected `identifier` parameter. Due to a broken access-control guard and loose hostname-prefix matching in the outbound request helper, the server attaches the owner's admin authentication token to a request sent to the attacker's server.

### Stage 3: Weaponized Transcode (CVE-2026-96655)

With the admin token, the attacker initiates a transcode of an attacker-hosted "video" file. The `TranscoderH264Options` server preference is set to include `dump-yuv=<path>` or `stats=<path>`, causing the x264 encoder to write data to a file path of the attacker's choosing within the Codecs directory. The attacker-hosted MP4 is crafted so the written YUV data contains a valid ELF shared object.

### Stage 4: Code Execution via dlopen (CVE-2026-96656)

A second transcode request causes the codec directory to be re-enumerated. The planted `.so` file is loaded by `dlopen`, which executes its constructor function immediately. The constructor forks and calls `execve` with `/bin/sh -c <attacker_command>`. The process runs as the `plex` user.

### Post-Exploitation

Observed payloads include:
- **x12345**: An XMRig-based cryptocurrency miner retrieved via `wget` or `curl` from 217[.]60[.]194[.]116, also referred to as "mylovelyminer" in process listings. Mining pool: `ota.proxystream[.]st`.
- **myawesomeproxy**: A Linux reverse proxy backdoor that connects to `global.relay.proxystream[.]st`. When run, it displays a notice about potential use of the host's internet traffic. VirusTotal classifies it as a stealthy backdoor and reverse proxy.

### C2 Infrastructure

The `proxystream[.]st` domain family serves as both the mining pool and proxy relay. Bitsight flagged `global.relay.proxystream[.]st` in August 2026 in connection with the AISURU/Kimwolf DDoS and proxyware botnet.

### Platform Behavior

The exploit chain works across all Plex Media Server platforms (bare-metal Linux, Docker, NAS devices, VMs). The payload targets differ: the PoC includes both `payload_linux.c` and `payload_windows.c`. On Linux, code runs as `uid=1000(plex)`. Docker deployments may run as root depending on container configuration.

## IOCs

> **Defanging Convention:** URLs use `hxxps://` and `hxxp://`; domains/IPs use `[.]`; emails use `[at]`.

### Network Indicators

| Type | Indicator | Context |
|---|---|---|
| IP | 91[.]92[.]40[.]202 | Attacker source IP |
| IP | 176[.]65[.]139[.]228 | Attacker source IP |
| IP | 45[.]194[.]92[.]222 | Attacker source IP |
| IP | 217[.]60[.]194[.]116 | Payload hosting server |
| Domain | ota[.]proxystream[.]st | XMRig mining pool |
| Domain | global[.]relay[.]proxystream[.]st | Proxy relay C2 (linked to AISURU/Kimwolf botnet) |

### File Indicators

| Filename | SHA-256 | Description |
|---|---|---|
| x12345 | `b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49` | XMRig-based cryptocurrency miner |
| myawesomeproxy | `e546b10aee5edc754da4f9b0baace00392257121911f630145078eafad1e6bd9` | Linux reverse proxy backdoor |

### Process Names

| Name | Description |
|---|---|
| mylovelyminer | XMRig miner process name |
| myawesomeproxy | Reverse proxy backdoor process name |
| x12345 | Miner binary name |

### File System Indicators

| Path / Pattern | Description |
|---|---|
| `*/Plex Media Server/Codecs/*` (unexpected `.so` files) | Planted malicious shared objects |
| Files named `zz<digits>.so` in Codecs directory | Naming pattern used by the exploit |
| `Preferences.xml` with `dump-yuv` or `stats=` in `TranscoderH264Options` | Evidence of exploit stage 3 |

### Vulnerable Software

| Package | Vulnerable Versions | Fixed Version |
|---|---|---|
| Plex Media Server | < 1.43.3.10861 | 1.43.3.10861 |

## MITRE ATT&CK Mapping

| Technique | ID | Exploit Stage / Activity |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Initial access via Plex port 32400 (CVE-2026-96652) |
| Server-Side Request Forgery | T1190 | SSRF in stages 1 and 3 |
| Steal Application Access Token | T1528 | Admin token theft via searchOne injection (CVE-2026-96654) |
| Hijack Execution Flow: Dynamic Linker Hijacking | T1574.006 | Unsigned `.so` loaded from Codecs directory (CVE-2026-96656) |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Shell execution via ELF constructor fork/execve |
| Ingress Tool Transfer | T1105 | wget/curl retrieval of miner and proxy payloads |
| Resource Hijacking | T1496 | XMRig cryptocurrency mining |
| Proxy: External Proxy | T1090.002 | myawesomeproxy reverse proxy backdoor |
| Application Layer Protocol | T1071.001 | HTTP-based payload download and C2 |

## Impact Assessment

**Severity: CRITICAL**

- **Scope:** All Plex Media Server instances below version 1.43.3.10861 exposed to the network. Shodan and Censys data indicate tens of thousands of internet-facing Plex servers on port 32400.
- **Access Required:** None -- the chain is fully unauthenticated.
- **Exploitation Complexity:** Low -- public PoC code is available on GitHub and was weaponized within 24 hours.
- **Impact:** Full remote code execution as the Plex service user. Observed exploitation deploys cryptocurrency miners (resource hijacking, increased electricity costs) and reverse proxy backdoors (which could be leveraged to proxy attacks through residential/corporate IPs).
- **Lateral Movement Risk:** Plex servers on residential networks could serve as pivot points into corporate VPNs and email systems. The `plex` user may have access to media files and network shares.
- **Data at Risk:** Plex admin tokens, media library contents, network access credentials if stored on the same host.

## Detection & Remediation

### Immediate Actions

1. **Update Plex Media Server** to version 1.43.3.10861 or later immediately.
2. **Audit Codecs directories** for unexpected `.so` files, particularly those named `zz<digits>.so` or with large near-zero-entropy tails.
3. **Check Preferences.xml** for `dump-yuv` or `stats=` values in `TranscoderH264Options`.
4. **Review running processes** for `mylovelyminer`, `myawesomeproxy`, `x12345`, or any shell processes parented by Plex Media Server / Plex Transcoder.
5. **Block known IOC IPs** at the firewall: 91[.]92[.]40[.]202, 176[.]65[.]139[.]228, 45[.]194[.]92[.]222, 217[.]60[.]194[.]116.
6. **Block DNS resolution** for `proxystream[.]st` and subdomains.

### Long-Term Hardening

1. **Do not expose port 32400 directly** to the internet. Use Plex's built-in relay or a VPN.
2. **Rotate the Plex owner token** on any server that was exposed while unpatched.
3. **Enable automatic updates** for Plex Media Server.
4. **Deploy the hunting script** from the PoC repository (`detection/hunt/plex2shell-hunt.sh`) on Linux and Docker hosts.
5. **Monitor for unexpected child processes** of Plex Media Server, particularly shells and interpreters.

## Detection Rules

> **Validation note:** `sigma check` could not run because the proxy blocked the MITRE ATT&CK data download (HTTP 403). All Sigma rules were validated via `sigma convert` to Splunk and LogScale (exit 0). YARA rules validated via `yarac` (exit 0). Suricata rules validated via `suricata -T` (exit 0). SIDs 2026101-2026104 fall within the Emerging Threats reserved range (2000000-2999999); reassign to a local range before production deployment.

### Sigma Rules

**SIGMA-1: Plex2Shell SSRF via Player Timeline Endpoint (CVE-2026-96652)**
Detects HTTP requests to `/player/timeline` with a full URL injected into the `protocol` parameter (e.g., `protocol=http://attacker-ip/...`), indicating stage 1 SSRF exploitation. Legitimate Plex clients use bare values like `protocol=http`. Requires Plex web access logs.
<!-- Validation: sigma convert -t splunk exit 0; sigma convert -t log_scale exit 0; sigma check blocked by proxy (MITRE data fetch 403) -->

```yaml
title: Plex2Shell SSRF via Player Timeline Endpoint (CVE-2026-96652)
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: >
    Detects HTTP requests to the Plex Media Server /player/timeline endpoint
    with a full URL injected into the protocol parameter (e.g., protocol=http://...),
    indicating exploitation of the unauthenticated SSRF in CVE-2026-96652
    (Plex2Shell chain stage 1). Legitimate Plex clients use bare protocol
    values such as protocol=http or protocol=https without a URL.
references:
    - https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html
    - https://www.securityweek.com/plex2shell-exploit-chain-weaponized-against-plex-servers-hours-after-disclosure/
    - https://zmain.info/blog/plex2shell
author: Actioner
date: 2026/10/20
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2026.96652
logsource:
    category: webserver
    product: plex
detection:
    selection:
        cs-uri-stem|contains: '/player/timeline'
    exploit_injection:
        cs-uri-query|contains:
            - 'protocol=http://'
            - 'protocol=https://'
            - 'protocol=http%3A//'
            - 'protocol=https%3A//'
            - 'protocol=http%3a//'
            - 'protocol=https%3a//'
    condition: selection and exploit_injection
falsepositives:
    - Custom Plex client implementations injecting full URLs into the protocol parameter (unlikely)
level: high
```
> compile-status: ✅ compiles (Splunk + LogScale) | confidence: medium -- Caveat: custom Plex-product logsource requires mapping; detects URL injection specifically, not bare `protocol=http` values.

---

**SIGMA-2: Plex2Shell searchOne Identifier Injection (CVE-2026-96654)**
Detects path-traversal patterns in `searchOne` requests, consistent with stage 2 admin token theft. Requires Plex web access logs.
<!-- Validation: sigma convert -t splunk exit 0; sigma convert -t log_scale exit 0 -->

```yaml
title: Plex2Shell searchOne Identifier Injection (CVE-2026-96654)
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: >
    Detects requests to the Plex Media Server searchOne endpoint with
    path-traversal or injection patterns in the identifier parameter,
    consistent with CVE-2026-96654 (Plex2Shell chain stage 2) used to
    steal the owner admin token.
references:
    - https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html
    - https://zmain.info/blog/plex2shell
author: Actioner
date: 2026/10/20
tags:
    - attack.credential_access
    - attack.t1528
    - cve.2026.96654
logsource:
    category: webserver
    product: plex
detection:
    selection:
        cs-uri-stem|contains: 'searchOne'
    traversal:
        cs-uri-query|contains:
            - '../'
            - '%2e%2e'
            - 'identifier=/'
    condition: selection and traversal
falsepositives:
    - Unlikely in normal Plex operation
level: high
```
> compile-status: ✅ compiles (Splunk + LogScale) | confidence: medium -- Caveat: requires Plex-product logsource mapping; URL-encoding variants may not cover all evasion techniques.

---

**SIGMA-3: Plex TranscoderH264Options Tampering (CVE-2026-96655/96656)**
Detects modifications to the Plex Preferences.xml file, which may indicate stage 3-4 exploitation injecting `dump-yuv` or `stats=` options. Requires file integrity monitoring.
<!-- Validation: sigma convert -t splunk exit 0; sigma convert -t log_scale exit 0 -->

```yaml
title: Plex TranscoderH264Options Tampering for File Write (CVE-2026-96655/96656)
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: >
    Detects modification of the Plex Media Server TranscoderH264Options
    preference to include dump-yuv or stats= x264 options, which is the
    mechanism used in CVE-2026-96655/96656 (Plex2Shell stages 3-4) to
    write a malicious shared object into the Codecs directory.
references:
    - https://securityaffairs.com/201324/hacking/plex2shell-exploit-used-to-turn-vulnerable-plex-servers-into-crypto-miners.html
    - https://zmain.info/blog/plex2shell
author: Actioner
date: 2026/10/20
tags:
    - attack.persistence
    - attack.t1574
    - cve.2026.96655
    - cve.2026.96656
logsource:
    category: file_change
    product: linux
detection:
    selection_file:
        TargetFilename|endswith: 'Preferences.xml'
        TargetFilename|contains: 'Plex Media Server'
    condition: selection_file
falsepositives:
    - Normal Plex preference changes (requires secondary analysis of TranscoderH264Options content)
level: medium
```
> compile-status: ✅ compiles (Splunk + LogScale) | confidence: low -- Caveat: fires on any Preferences.xml change, not specifically dump-yuv; secondary triage required to confirm malicious content.

---

**SIGMA-4: Plex Media Server or Transcoder Spawning Shell Process**
Detects shell interpreters spawned as child processes of Plex binaries, consistent with successful code execution via the planted `.so` constructor.
<!-- Validation: sigma convert -t splunk exit 0; sigma convert -t log_scale exit 0 -->

```yaml
title: Plex Media Server or Transcoder Spawning Shell Process
id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80
status: experimental
description: >
    Detects the Plex Media Server or Plex Transcoder process spawning
    a shell interpreter, which is consistent with successful exploitation
    of the Plex2Shell chain (CVE-2026-96656) where a malicious shared
    object loaded via dlopen executes fork/execve to spawn a shell.
references:
    - https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html
    - https://zmain.info/blog/plex2shell
author: Actioner
date: 2026/10/20
tags:
    - attack.execution
    - attack.t1059.004
    - cve.2026.96656
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/Plex Media Server'
            - '/Plex Transcoder'
            - '/Plex Script Host'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/zsh'
            - '/ash'
            - '/ksh'
            - '/busybox'
    condition: selection_parent and selection_child
falsepositives:
    - Plex post-processing scripts or legitimate Plex plugins that invoke shell commands
level: medium
```
> compile-status: ✅ compiles (Splunk + LogScale) | confidence: medium -- Caveat: behavioral TTP rule; legitimate Plex post-processing scripts may spawn shells, requiring baseline tuning.

---

**SIGMA-5: Plex2Shell Known Attacker Infrastructure Communication**
Detects network connections to IPs and domains observed in October 2026 Plex2Shell exploitation campaigns.
<!-- Validation: sigma convert -t splunk exit 0; sigma convert -t log_scale exit 0 -->

```yaml
title: Plex2Shell Known Attacker Infrastructure Communication
id: e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091
status: experimental
description: >
    Detects network connections to known Plex2Shell attacker infrastructure
    IPs and domains observed in October 2026 exploitation campaigns deploying
    XMRig miners and myawesomeproxy backdoors.
references:
    - https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html
    - https://www.securityweek.com/plex2shell-exploit-chain-weaponized-against-plex-servers-hours-after-disclosure/
author: Actioner
date: 2026/10/20
tags:
    - attack.command_and_control
    - attack.t1071
    - attack.t1496
logsource:
    category: network_connection
    product: linux
detection:
    selection_ip:
        DestinationIp:
            - '91.92.40.202'
            - '176.65.139.228'
            - '45.194.92.222'
            - '217.60.194.116'
    selection_domain:
        DestinationHostname|endswith:
            - 'proxystream.st'
    condition: selection_ip or selection_domain
falsepositives:
    - Unlikely; these are known malicious indicators
level: high
```
> compile-status: ✅ compiles (Splunk + LogScale) | confidence: high -- IOC-based; IPs may be reassigned over time; review periodically.

---

**SIGMA-6: Plex2Shell Post-Exploitation Miner or Proxy Process Names**
Detects process creation matching known payload names from the Plex2Shell campaigns.
<!-- Validation: sigma convert -t splunk exit 0; sigma convert -t log_scale exit 0 -->

```yaml
title: Plex2Shell Post-Exploitation Miner or Proxy Process Names
id: f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f809102
status: experimental
description: >
    Detects process creation with names matching known Plex2Shell
    post-exploitation payloads: the XMRig miner (mylovelyminer, x12345)
    and the reverse proxy backdoor (myawesomeproxy).
references:
    - https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html
author: Actioner
date: 2026/10/20
tags:
    - attack.execution
    - attack.t1496
    - attack.t1090
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/mylovelyminer'
            - '/myawesomeproxy'
            - '/x12345'
    condition: selection
falsepositives:
    - Unlikely; these are specific malware payload names
level: high
```
> compile-status: ✅ compiles (Splunk + LogScale) | confidence: high -- Matches specific, distinctive malware binary names; trivially evaded by renaming.

---

### Suricata Rules

<!-- Validation: suricata -T -S suricata-plex2shell.rules -l /tmp/actioner => exit 0 on attempt 2 (removed malformed IP-only rule) -->

**SURICATA-1: Plex2Shell SSRF via /player/timeline (CVE-2026-96652)**
Alerts on HTTP requests containing both `/player/timeline` and `protocol=` in the URI, matching stage 1 exploitation.

```
alert http any any -> any any (msg:"Plex2Shell SSRF - Suspicious protocol parameter in /player/timeline (CVE-2026-96652)"; flow:to_server,established; http.uri; content:"/player/timeline"; content:"protocol="; sid:2026101; rev:1; classtype:web-application-attack; metadata:cve CVE-2026-96652, created_at 2026_10_20, confidence medium;)
```
> compile-status: ✅ compiles | confidence: medium -- Legitimate Plex clients also hit /player/timeline; the rule fires on any protocol= parameter, so tuning for benign values is needed.

**SURICATA-2: Plex2Shell searchOne Identifier Injection (CVE-2026-96654)**
Alerts on HTTP requests to `searchOne` containing `identifier=` and path-traversal sequences.

```
alert http any any -> any any (msg:"Plex2Shell searchOne identifier injection (CVE-2026-96654)"; flow:to_server,established; http.uri; content:"searchOne"; content:"identifier="; content:".."; sid:2026102; rev:1; classtype:web-application-attack; metadata:cve CVE-2026-96654, created_at 2026_10_20, confidence medium;)
```
> compile-status: ✅ compiles | confidence: medium -- Path traversal in searchOne is abnormal, but `..` content match may have false positives in unrelated query strings.

**SURICATA-3: Plex2Shell C2 -- DNS lookup for proxystream[.]st**
Alerts on DNS queries for the `proxystream[.]st` domain used as the mining pool and proxy relay.

```
alert dns any any -> any any (msg:"Plex2Shell C2 - DNS lookup for proxystream.st mining pool"; dns.query; content:"proxystream.st"; nocase; sid:2026103; rev:1; classtype:trojan-activity; metadata:created_at 2026_10_20, confidence high;)
```
> compile-status: ✅ compiles | confidence: high -- Specific malicious domain; no legitimate use known.

**SURICATA-4: Plex2Shell Payload Download from Known IP**
Alerts on HTTP traffic to the payload hosting server at 217[.]60[.]194[.]116.

```
alert http any any -> $EXTERNAL_NET any (msg:"Plex2Shell Payload Download from Known Attacker IP 217.60.194.116"; flow:to_server,established; http.host; content:"217.60.194.116"; sid:2026104; rev:1; classtype:trojan-activity; metadata:created_at 2026_10_20, confidence high;)
```
> compile-status: ✅ compiles | confidence: high -- Specific IOC; IP may be reassigned over time.

---

### YARA Rules

<!-- Validation: yarac yara-plex2shell-payloads.yar /dev/null => exit 0 on attempt 2 (added hash module import, removed unreferenced string) -->

**YARA-1: Plex2Shell ELF Constructor Payload**
Detects small ELF shared objects containing `/bin/sh` and `-c` strings, consistent with the Plex2Shell PoC payload structure.

```yara
rule Plex2Shell_ELF_Constructor_Payload
{
    meta:
        description = "Detects ELF shared objects with constructor-based fork/execve pattern matching the Plex2Shell PoC payload (CVE-2026-96656)"
        author = "Actioner"
        date = "2026-10-20"
        reference = "https://github.com/code-zm/plex2shell"
        confidence = "medium"

    strings:
        $elf = { 7F 45 4C 46 }
        $binsh = "/bin/sh" ascii
        $dash_c = "-c" ascii

    condition:
        $elf at 0 and $binsh and $dash_c and filesize < 100KB
}
```
> compile-status: ✅ compiles | confidence: low -- Generic pattern that will match many legitimate small ELF binaries containing /bin/sh; use as a hunting rule only.

**YARA-2: Plex2Shell Known Miner Hash (x12345)**
Matches the specific SHA-256 hash of the observed XMRig miner payload.

```yara
import "hash"

rule Plex2Shell_Known_Miner_Hash
{
    meta:
        description = "Detects the known x12345 XMRig miner payload deployed via Plex2Shell exploitation"
        author = "Actioner"
        date = "2026-10-20"
        reference = "https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html"
        confidence = "high"

    condition:
        hash.sha256(0, filesize) == "b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49"
}
```
> compile-status: ✅ compiles | confidence: high -- Exact hash match; no false positives possible.

**YARA-3: Plex2Shell Known Proxy Hash (myawesomeproxy)**
Matches the specific SHA-256 hash of the observed myawesomeproxy backdoor.

```yara
rule Plex2Shell_Known_Proxy_Hash
{
    meta:
        description = "Detects the known myawesomeproxy backdoor deployed via Plex2Shell exploitation"
        author = "Actioner"
        date = "2026-10-20"
        reference = "https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html"
        confidence = "high"

    condition:
        hash.sha256(0, filesize) == "e546b10aee5edc754da4f9b0baace00392257121911f630145078eafad1e6bd9"
}
```
> compile-status: ✅ compiles | confidence: high -- Exact hash match; no false positives possible.

**YARA-4: Plex2Shell Proxy Strings**
Detects ELF binaries containing strings associated with the myawesomeproxy backdoor.

```yara
rule Plex2Shell_Proxy_Strings
{
    meta:
        description = "Detects the myawesomeproxy reverse proxy tool by string patterns"
        author = "Actioner"
        date = "2026-10-20"
        reference = "https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html"
        confidence = "medium"

    strings:
        $s1 = "myawesomeproxy" ascii wide
        $s2 = "agreeing to potential use" ascii wide
        $s3 = "internet traffic" ascii wide
        $domain = "proxystream.st" ascii wide

    condition:
        uint32(0) == 0x464C457F and ($s1 or ($s2 and $s3) or $domain)
}
```
> compile-status: ✅ compiles | confidence: medium -- Survives recompilation as long as strings are not stripped; the consent notice string is distinctive.

**YARA-5: Plex2Shell Miner Strings**
Detects ELF binaries containing strings associated with the mylovelyminer XMRig payload.

```yara
rule Plex2Shell_Miner_Strings
{
    meta:
        description = "Detects the mylovelyminer XMRig payload by string patterns"
        author = "Actioner"
        date = "2026-10-20"
        reference = "https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html"
        confidence = "medium"

    strings:
        $miner_name = "mylovelyminer" ascii wide
        $pool = "ota.proxystream.st" ascii wide
        $xmrig = "xmrig" ascii wide nocase

    condition:
        uint32(0) == 0x464C457F and ($miner_name or ($pool and $xmrig))
}
```
> compile-status: ✅ compiles | confidence: medium -- Survives recompilation if miner name and pool address are unchanged; trivially evaded by reconfiguration.

---

## Sources

All references used in this report:

- [SecurityWeek: Plex2Shell Exploit Chain Weaponized Against Plex Servers Hours After Disclosure](https://www.securityweek.com/plex2shell-exploit-chain-weaponized-against-plex-servers-hours-after-disclosure/)
- [Security Affairs: Plex2Shell exploit used to turn vulnerable Plex servers into crypto miners](https://securityaffairs.com/201324/hacking/plex2shell-exploit-used-to-turn-vulnerable-plex-servers-into-crypto-miners.html)
- [The Hacker News: Hackers Exploit Plex2Shell Flaws to Deploy Crypto Miners](https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html)
- [Zach Main: Plex2Shell Technical Writeup](https://zmain.info/blog/plex2shell)
- [BoredHackerBlog: Plex2Shell In the Wild (Honeypot Report)](https://boredhackerblog.info/2026/10/plex2shell-in-wild.html)
- [GitHub: code-zm/plex2shell (PoC + Detection Content)](https://github.com/code-zm/plex2shell)
- [VirusTotal: x12345 Miner Sample](https://www.virustotal.com/gui/file/b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49)
- [VirusTotal: myawesomeproxy Backdoor Sample](https://www.virustotal.com/gui/file/e546b10aee5edc754da4f9b0baace00392257121911f630145078eafad1e6bd9/detection)
