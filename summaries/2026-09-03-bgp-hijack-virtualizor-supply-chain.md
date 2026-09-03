# DRAFT -- BGP Hijack Delivers Malicious Virtualizor Updates via Softaculous Traffic Interception

> **Status**: DRAFT -- Actioner automated analysis
> **Date**: 2026-09-03
> **TLP**: CLEAR
> **Sector relevance**: Hosting providers, VPS/hypervisor operators, ISPs, Softaculous customers

---

## Executive Summary

Between August 28, 2026 ~20:57 UTC and August 30, 2026 ~06:10 UTC (~33 hours), threat actors executed a BGP hijack against Hetzner IP space (162.55.80.0/24) used by Softaculous, redirecting update traffic for the Virtualizor VPS management platform to attacker-controlled infrastructure. The attacker obtained valid Let's Encrypt TLS certificates for 28 Softaculous-family domains during the diversion window and served malicious Virtualizor update packages that achieved root-level compromise of affected hypervisor nodes. The attack exploited the absence of cryptographic package verification in Virtualizor's update client.

A small number of Virtualizor installations received the malicious update during the two active diversion windows. AlbaHost publicly confirmed 5 of its 34 hypervisor nodes were compromised.

---

## Technical Analysis

### BGP Hijack Mechanism

The attacker network **AS62390 (NexonHost)** announced the more-specific prefix **162.55.80.0/24** -- a subset of Hetzner's (AS24940) broader /16 announcement. The route propagated through transit provider **AS6204 (Zet.net)** with the spoofed AS path `20912 6204 62390 24940`.

The more-specific /24 announcement defeated the legitimate /16 via standard BGP longest-prefix-match routing. At peak diversion, approximately **72% of RIPE RIS collector peers** (266 of 368) routed traffic through the hijacked path.

**Two active diversion windows:**
- **Wave 1**: Aug 28 ~21:00 UTC -- Aug 29 ~08:50 UTC (~12 hours)
- **Lull**: Aug 29 ~08:50 -- ~20:00 UTC (Hetzner announced specific range; near-zero diversion)
- **Wave 2**: Aug 29 ~20:00 UTC -- Aug 30 ~06:10 UTC (~10 hours)

### TLS Certificate Abuse

During the hijack window, the attacker obtained a **valid Let's Encrypt certificate** covering 28 domains across the Softaculous product family:
- `api.virtualizor.com`, `files.virtualizor.com`, `virtualizor.com`
- `api.softaculous.com`, `files.softaculous.com`, `softaculous.com`
- `api.sitepad.com`, `files.sitepad.com`, `sitepad.com`
- `api.webuzo.com`, `files.webuzo.com`, `webuzo.com`
- `backuply.com`, `ampps.com`, `pagelayer.com`, `popularfx.com` (and www variants)

Automated domain-ownership validation (HTTP-01 or DNS-01 challenge) was routed through the hijacked path, enabling the attacker to pass Let's Encrypt's checks. The certificate has since been revoked.

### Malicious Update Payload

Virtualizor servers that performed an update check during a diverted interval received a malicious package. The update client lacked cryptographic signature verification, so the modified package was not rejected.

**Injected files (three legitimate Virtualizor files modified):**
- `/usr/local/virtualizor/globals.php`
- `/usr/local/virtualizor/_universal.php`
- `/usr/local/virtualizor/zzvirtservice`

**Attack chain executed by injected code:**

1. **SSH key injection** -- Added attacker-controlled ed25519 public key to root's `authorized_keys`
   - Public key: `AAAAC3NzaC1lZDI1NTE5AAAAIP13pPAm5jmInLQYD3XNb3HwrW4cAKDcphoT4kSKrnte`
   - Fingerprint: `SHA256:YQmy1hKF1h5cdJLxlZ5EScNoxe/UDWahjsWuQw2ERi8`
2. **Java 17 installation** -- Installed Java runtime if absent
3. **Payload download** -- Downloaded JAR payload from `cdn[.]nerat[.]cc/installer/widdow.jar`
4. **Payload execution** -- Ran Java payload as root
5. **Systemd persistence** -- Created `/etc/systemd/system/java-jre-update.service`
6. **Cron persistence** -- Root cron job executing modified code
7. **Account creation** -- Created unauthorized system account `proxyuser`
8. **C2 communication** -- Established connections to `cdn[.]nerat[.]cc` and `connect[.]ne-rat[.]xyz`

**Post-compromise activity observed:**
- SSH login to `proxyuser` account from `193.32.127[.]248`
- Command infrastructure at `31.77.220[.]138:2025`

---

## Indicators of Compromise

### Network IOCs

| Type | Value | Context |
|------|-------|---------|
| C2 Domain | `cdn[.]nerat[.]cc` | Payload download and C2 |
| C2 Domain | `connect[.]ne-rat[.]xyz` | C2 communications |
| Attacker IP | `193.32.127[.]248` | SSH access to proxyuser account |
| C2 IP | `31.77.220[.]138:2025` | Command infrastructure |
| Hijacked Prefix | `162.55.80[.]0/24` | BGP hijack target |
| Target IP | `162.55.80[.]8` | softaculous.com resolution |
| Attacker ASN | AS62390 (NexonHost) | Origin of malicious announcement |
| Transit ASN | AS6204 (Zet.net) | Transit provider for hijacked route |

### File IOCs

| Type | Value | Context |
|------|-------|---------|
| SHA-256 | `b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7` | Malicious payload (jre-runtime.dat) |
| SHA-256 | `73e74402b3a61c7bab289fc11347bd54c7fcdc2fa2e410f4c3de9d6cd7377d48` | Virtualizor security scanner |
| File path | `/etc/systemd/system/java-jre-update.service` | Persistence systemd service |
| File path | `/usr/lib/jvm/.cache/jre-runtime.dat` | Dropped payload |
| File path | `/usr/lib/jvm/.cache/.installed` | Installation marker |
| File path | `/tmp/widdow.jar` | Downloaded JAR payload |
| File path | `/tmp/.vz_svc_done` | Completion marker |
| File path | `/usr/local/virtualizor/globals.php` | Modified Virtualizor file |
| File path | `/usr/local/virtualizor/_universal.php` | Modified Virtualizor file |
| File path | `/usr/local/virtualizor/zzvirtservice` | Modified Virtualizor file |

### Host IOCs

| Type | Value | Context |
|------|-------|---------|
| SSH Key | `AAAAC3NzaC1lZDI1NTE5AAAAIP13pPAm5jmInLQYD3XNb3HwrW4cAKDcphoT4kSKrnte` | Attacker ed25519 public key |
| SSH Fingerprint | `SHA256:YQmy1hKF1h5cdJLxlZ5EScNoxe/UDWahjsWuQw2ERi8` | Attacker key fingerprint |
| Account | `proxyuser` | Unauthorized system account |
| Service | `java-jre-update` | Malicious systemd service name |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Context |
|--------|-----------|-----|---------|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Malicious update served via hijacked update infrastructure |
| Initial Access | Trusted Relationship | T1199 | Abuse of Softaculous update trust chain |
| Execution | Command and Scripting Interpreter | T1059 | Java payload execution as root |
| Persistence | Create or Modify System Process: Systemd Service | T1543.002 | java-jre-update.service |
| Persistence | Scheduled Task/Job: Cron | T1053.003 | Root cron job for persistence |
| Persistence | Account Manipulation: SSH Authorized Keys | T1098.004 | Attacker SSH key added to root |
| Persistence | Create Account: Local Account | T1136.001 | proxyuser account creation |
| Defense Evasion | Subvert Trust Controls: Code Signing | T1553.004 | Obtained valid Let's Encrypt TLS certificate |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS-based C2 to nerat.cc / ne-rat.xyz |
| Lateral Movement | Remote Services: SSH | T1021.004 | SSH login from 193.32.127.248 |

---

## Viability Gate Assessment

**Verdict: VIABLE** -- Multiple concrete, source-attributed artifacts available for detection:

- **File-based IOCs**: Specific file paths, hashes, systemd service name -- high-confidence host detection
- **Network IOCs**: Two C2 domains, two attacker IPs, payload download URL -- high-confidence network detection
- **Host artifacts**: SSH key string, proxyuser account name -- deterministic matching
- **Limitation**: Exact malicious code injected into PHP files not published; detection relies on C2 strings and artifact paths rather than bytecode signatures

---

## Detection Rules

### Sigma Rules

<!-- audit: all rules validated via sigma convert to splunk and log_scale backends; sigma check blocked by network (MITRE ATT&CK data fetch 403) — structural and semantic validation passed -->

---

**SIGMA-01: Malicious Systemd Service Creation**

Detects creation of the java-jre-update.service persistence unit installed by the compromised Virtualizor update.

- **Compile-status**: PASS (sigma convert splunk + log_scale)
- **Confidence**: HIGH

```yaml
title: Virtualizor BGP Hijack - Malicious Systemd Service Creation
id: d24108df-3d46-485a-85c8-720ff3ab60a9
status: experimental
description: Detects creation of the java-jre-update.service systemd unit file, a persistence mechanism deployed by the malicious Virtualizor update delivered via BGP hijack of Softaculous infrastructure (Aug 28-30, 2026).
author: Actioner
date: 2026/09/03
references:
    - https://www.virtualizor.com/blog/security-incident-bgp-hijacking/
    - https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html
tags:
    - attack.persistence
    - attack.t1543.002
    - attack.t1195.002
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/java-jre-update.service'
        TargetFilename|contains: '/systemd/'
    condition: selection
falsepositives:
    - Legitimate Java update service with identical naming (highly unlikely)
level: critical
```

<!-- audit: file=/tmp/actioner/sigma-virtualizor-systemd-persistence.yml; splunk_output='TargetFilename="*/java-jre-update.service" TargetFilename="*/systemd/*"'; log_scale_output='TargetFilename=/\/java-jre-update\.service$/i TargetFilename=/\/systemd\//i'; attempts=1 -->

---

**SIGMA-02: Malicious Payload File Creation**

Detects creation of payload and marker files dropped by the compromised Virtualizor update package.

- **Compile-status**: PASS (sigma convert splunk + log_scale)
- **Confidence**: HIGH

```yaml
title: Virtualizor BGP Hijack - Malicious Payload File Creation
id: 442e7e43-7eb5-4d11-a3cf-ae355af49239
status: experimental
description: Detects creation of payload and marker files associated with the malicious Virtualizor update delivered via BGP hijack, including jre-runtime.dat, widdow.jar, and installation markers.
author: Actioner
date: 2026/09/03
references:
    - https://www.virtualizor.com/blog/security-incident-bgp-hijacking/
    - https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html
tags:
    - attack.execution
    - attack.t1059
    - attack.t1195.002
logsource:
    category: file_event
    product: linux
detection:
    selection_payload:
        TargetFilename: '/usr/lib/jvm/.cache/jre-runtime.dat'
    selection_marker_installed:
        TargetFilename: '/usr/lib/jvm/.cache/.installed'
    selection_marker_jar:
        TargetFilename: '/tmp/widdow.jar'
    selection_marker_done:
        TargetFilename: '/tmp/.vz_svc_done'
    condition: 1 of selection_*
falsepositives:
    - None expected
level: critical
```

<!-- audit: file=/tmp/actioner/sigma-virtualizor-payload-drop.yml; splunk_output='TargetFilename IN ("/usr/lib/jvm/.cache/jre-runtime.dat", "/usr/lib/jvm/.cache/.installed", "/tmp/widdow.jar", "/tmp/.vz_svc_done")'; attempts=1 -->

---

**SIGMA-03: C2 Domain DNS Query**

Detects DNS queries to C2 domains used by the Virtualizor backdoor.

- **Compile-status**: PASS (sigma convert splunk + log_scale)
- **Confidence**: HIGH

```yaml
title: Virtualizor BGP Hijack - C2 Domain DNS Query
id: e904fdb3-d174-4f1b-b264-84582b72ac86
status: experimental
description: Detects DNS queries to C2 domains used by the malicious Virtualizor backdoor delivered via BGP hijack of Softaculous infrastructure.
author: Actioner
date: 2026/09/03
references:
    - https://www.virtualizor.com/blog/security-incident-bgp-hijacking/
    - https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: dns_query
    product: linux
detection:
    selection:
        QueryName|endswith:
            - 'nerat.cc'
            - 'ne-rat.xyz'
    condition: selection
falsepositives:
    - None expected
level: critical
```

<!-- audit: file=/tmp/actioner/sigma-virtualizor-c2-dns.yml; splunk_output='QueryName IN ("*nerat.cc", "*ne-rat.xyz")'; attempts=1 -->

---

**SIGMA-04: Unauthorized Proxyuser Account**

Detects creation of or SSH login to the proxyuser account planted by the backdoor.

- **Compile-status**: PASS (sigma convert splunk + log_scale)
- **Confidence**: HIGH

```yaml
title: Virtualizor BGP Hijack - Unauthorized Proxyuser Account
id: 94c6b215-d489-467f-aa34-40d96bf716ad
status: experimental
description: Detects creation of or login to the proxyuser account, an unauthorized system account created by the malicious Virtualizor update.
author: Actioner
date: 2026/09/03
references:
    - https://www.virtualizor.com/blog/security-incident-bgp-hijacking/
    - https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html
tags:
    - attack.persistence
    - attack.t1136.001
    - attack.t1195.002
logsource:
    product: linux
    service: sshd
detection:
    selection:
        User: 'proxyuser'
    condition: selection
falsepositives:
    - Legitimate proxyuser account on non-Virtualizor systems
level: high
```

<!-- audit: file=/tmp/actioner/sigma-virtualizor-proxyuser.yml; splunk_output='User="proxyuser"'; attempts=1 -->

---

**SIGMA-05: Attacker SSH Source IP**

Detects SSH connections from the known attacker IP address used to access compromised hosts.

- **Compile-status**: PASS (sigma convert splunk + log_scale)
- **Confidence**: HIGH (time-limited -- IP may be reassigned)

```yaml
title: Virtualizor BGP Hijack - Attacker SSH Source IP
id: 71b9939d-8432-4185-8088-e56ac06af15b
status: experimental
description: Detects SSH connections from the known attacker IP address 193.32.127.248 observed logging into compromised Virtualizor hosts via the proxyuser account.
author: Actioner
date: 2026/09/03
references:
    - https://www.virtualizor.com/blog/security-incident-bgp-hijacking/
    - https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html
tags:
    - attack.command_and_control
    - attack.t1021.004
    - attack.t1195.002
logsource:
    product: linux
    service: sshd
detection:
    selection:
        SrcIP: '193.32.127.248'
    condition: selection
falsepositives:
    - IP reassignment after incident
level: critical
```

<!-- audit: file=/tmp/actioner/sigma-virtualizor-ssh-attacker.yml; splunk_output='SrcIP="193.32.127.248"'; attempts=1 -->

---

### Suricata Rules

<!-- audit: all rules validated via suricata -T (v7.0.3); "Configuration provided was successfully loaded. Exiting." -->

---

**SURICATA-01 through SURICATA-07: C2 Domain, Payload, and Attacker IP Detection**

Seven rules covering DNS queries to C2 domains (cdn.nerat.cc, connect.ne-rat.xyz), HTTP download of widdow.jar payload, TLS SNI matching for C2 domains, and outbound connections to attacker IPs (31.77.220.138, 193.32.127.248).

- **Compile-status**: PASS (suricata -T v7.0.3)
- **Confidence**: HIGH

```
# Detect DNS queries to C2 domain cdn.nerat.cc
alert dns $HOME_NET any -> any any (msg:"Actioner - Virtualizor BGP Hijack C2 DNS Query (cdn.nerat.cc)"; dns.query; content:"cdn.nerat.cc"; nocase; endswith; sid:2200001; rev:1; metadata:created_at 2026_09_03, updated_at 2026_09_03, attack_target Server, deployment Perimeter, signature_severity Critical, tag Supply_Chain; classtype:trojan-activity; reference:url,www.virtualizor.com/blog/security-incident-bgp-hijacking/;)

# Detect DNS queries to C2 domain connect.ne-rat.xyz
alert dns $HOME_NET any -> any any (msg:"Actioner - Virtualizor BGP Hijack C2 DNS Query (connect.ne-rat.xyz)"; dns.query; content:"connect.ne-rat.xyz"; nocase; endswith; sid:2200002; rev:1; metadata:created_at 2026_09_03, updated_at 2026_09_03, attack_target Server, deployment Perimeter, signature_severity Critical, tag Supply_Chain; classtype:trojan-activity; reference:url,www.virtualizor.com/blog/security-incident-bgp-hijacking/;)

# Detect HTTP request for malicious widdow.jar payload
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Virtualizor BGP Hijack Payload Download (widdow.jar)"; http.uri; content:"/installer/widdow.jar"; sid:2200003; rev:1; metadata:created_at 2026_09_03, updated_at 2026_09_03, attack_target Server, deployment Perimeter, signature_severity Critical, tag Supply_Chain; classtype:trojan-activity; reference:url,thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html;)

# Detect TLS connection to C2 domain nerat.cc
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Virtualizor BGP Hijack C2 TLS SNI (nerat.cc)"; tls.sni; content:"nerat.cc"; endswith; sid:2200004; rev:1; metadata:created_at 2026_09_03, updated_at 2026_09_03, attack_target Server, deployment Perimeter, signature_severity Critical, tag Supply_Chain; classtype:trojan-activity; reference:url,www.virtualizor.com/blog/security-incident-bgp-hijacking/;)

# Detect TLS connection to C2 domain ne-rat.xyz
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Virtualizor BGP Hijack C2 TLS SNI (ne-rat.xyz)"; tls.sni; content:"ne-rat.xyz"; endswith; sid:2200005; rev:1; metadata:created_at 2026_09_03, updated_at 2026_09_03, attack_target Server, deployment Perimeter, signature_severity Critical, tag Supply_Chain; classtype:trojan-activity; reference:url,www.virtualizor.com/blog/security-incident-bgp-hijacking/;)

# Detect outbound connection to attacker command infrastructure
alert ip $HOME_NET any -> 31.77.220.138 any (msg:"Actioner - Virtualizor BGP Hijack Attacker C2 IP (31.77.220.138)"; sid:2200006; rev:1; metadata:created_at 2026_09_03, updated_at 2026_09_03, attack_target Server, deployment Perimeter, signature_severity Critical, tag Supply_Chain; classtype:trojan-activity; reference:url,thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html;)

# Detect outbound connection to known attacker SSH source
alert ip $HOME_NET any -> 193.32.127.248 any (msg:"Actioner - Virtualizor BGP Hijack Attacker SSH IP (193.32.127.248)"; sid:2200007; rev:1; metadata:created_at 2026_09_03, updated_at 2026_09_03, attack_target Server, deployment Perimeter, signature_severity Critical, tag Supply_Chain; classtype:trojan-activity; reference:url,thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html;)
```

<!-- audit: file=/tmp/actioner/suricata-virtualizor-c2.rules; suricata_output="Configuration provided was successfully loaded. Exiting."; attempts=1 -->

---

### Snort Rules

**SNORT-01 through SNORT-03: Payload Download and Attacker IP Detection**

Three rules covering HTTP download of widdow.jar payload and outbound connections to attacker IPs.

- **Compile-status**: WARNING -- uncompiled (structural check only)
- **Confidence**: HIGH (structural)

```
# Detect HTTP request for malicious widdow.jar payload
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Virtualizor BGP Hijack Payload Download (widdow.jar)"; flow:to_server,established; content:"GET"; http_method; content:"/installer/widdow.jar"; http_uri; sid:2100001; rev:1; classtype:trojan-activity; reference:url,thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html; metadata:created_at 2026_09_03, attack_target Server;)

# Detect outbound connection to attacker C2 infrastructure
alert ip $HOME_NET any -> 31.77.220.138 any (msg:"Actioner - Virtualizor BGP Hijack Attacker C2 IP (31.77.220.138)"; sid:2100002; rev:1; classtype:trojan-activity; reference:url,thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html; metadata:created_at 2026_09_03, attack_target Server;)

# Detect outbound connection to known attacker SSH source
alert ip $HOME_NET any -> 193.32.127.248 any (msg:"Actioner - Virtualizor BGP Hijack Attacker SSH IP (193.32.127.248)"; sid:2100003; rev:1; classtype:trojan-activity; reference:url,thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html; metadata:created_at 2026_09_03, attack_target Server;)
```

<!-- audit: file=/tmp/actioner/snort-virtualizor-c2.rules; snort not available in environment; structural check only; attempts=0 -->

---

### YARA Rules

<!-- audit: all rules compiled via yarac v4.5.0; exit code 0 -->

---

**YARA-01: Payload Hash Match (jre-runtime.dat)**

Matches the known malicious payload by SHA-256 hash with Java class file magic bytes.

- **Compile-status**: PASS (yarac v4.5.0)
- **Confidence**: HIGH

```yara
import "hash"

rule Virtualizor_BGP_Hijack_Payload_JRE_Runtime
{
    meta:
        description = "Detects the malicious jre-runtime.dat payload dropped by compromised Virtualizor update"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://www.virtualizor.com/blog/security-incident-bgp-hijacking/"
        hash = "b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7"
        severity = "critical"

    condition:
        (uint32(0) == 0xBEBAFECA or uint32(0) == 0xCAFEBABE) and
        filesize < 50MB and
        hash.sha256(0, filesize) == "b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7"
}
```

<!-- audit: file=/tmp/actioner/yara-virtualizor-backdoor.yar; yarac exit code 0; attempts=2 (first attempt: hash import order, unreferenced string) -->

---

**YARA-02: Modified PHP Files with C2 Strings**

Detects Virtualizor PHP or script files containing injected C2 domain strings and attack markers.

- **Compile-status**: PASS (yarac v4.5.0)
- **Confidence**: HIGH

```yara
rule Virtualizor_BGP_Hijack_Modified_PHP_Files
{
    meta:
        description = "Detects Virtualizor PHP files containing injected C2 domain strings from the BGP hijack supply chain attack"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html"
        severity = "critical"

    strings:
        $c2_1 = "cdn.nerat.cc" ascii wide
        $c2_2 = "connect.ne-rat.xyz" ascii wide
        $payload_url = "cdn.nerat.cc/installer/widdow.jar" ascii wide
        $marker_1 = "jre-runtime.dat" ascii wide
        $marker_2 = ".vz_svc_done" ascii wide
        $marker_3 = "widdow.jar" ascii wide
        $service = "java-jre-update.service" ascii wide

    condition:
        filesize < 5MB and
        (
            any of ($c2_*) or
            ($payload_url) or
            (2 of ($marker_*)) or
            ($service and any of ($marker_*))
        )
}
```

<!-- audit: file=/tmp/actioner/yara-virtualizor-backdoor.yar; yarac exit code 0; attempts=2 -->

---

**YARA-03: Widdow JAR Payload**

Detects the widdow.jar Java archive containing C2 domain strings.

- **Compile-status**: PASS (yarac v4.5.0)
- **Confidence**: MEDIUM (requires C2 string presence in JAR)

```yara
rule Virtualizor_BGP_Hijack_Widdow_JAR
{
    meta:
        description = "Detects the widdow.jar Java payload used in the Virtualizor BGP hijack supply chain attack"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html"
        severity = "critical"

    strings:
        $pk_header = { 50 4B 03 04 }
        $c2_1 = "cdn.nerat.cc" ascii
        $c2_2 = "connect.ne-rat.xyz" ascii
        $c2_3 = "ne-rat" ascii
        $java_class = ".class" ascii

    condition:
        $pk_header at 0 and
        filesize < 50MB and
        $java_class and
        any of ($c2_*)
}
```

<!-- audit: file=/tmp/actioner/yara-virtualizor-backdoor.yar; yarac exit code 0; attempts=2 -->

---

**YARA-04: Attacker SSH Key Injection**

Detects the specific attacker-controlled ed25519 SSH public key in authorized_keys or similar files.

- **Compile-status**: PASS (yarac v4.5.0)
- **Confidence**: HIGH

```yara
rule Virtualizor_BGP_Hijack_SSH_Key_Injection
{
    meta:
        description = "Detects the attacker-controlled SSH ed25519 public key injected into root authorized_keys by the malicious Virtualizor update"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html"
        severity = "critical"

    strings:
        $ssh_key = "AAAAC3NzaC1lZDI1NTE5AAAAIP13pPAm5jmInLQYD3XNb3HwrW4cAKDcphoT4kSKrnte" ascii

    condition:
        filesize < 1MB and
        $ssh_key
}
```

<!-- audit: file=/tmp/actioner/yara-virtualizor-backdoor.yar; yarac exit code 0; attempts=2 -->

---

## Remediation Guidance

Per Virtualizor advisory:

1. **Immediate check**: Look for `/etc/systemd/system/java-jre-update.service` -- if present, contact Virtualizor support; do not manually delete
2. **Run scanner**: Execute `https://files.virtualizor.com/security/virtualizor_security_scan.sh` (SHA-256: `73e74402b3a61c7bab289fc11347bd54c7fcdc2fa2e410f4c3de9d6cd7377d48`)
3. **Update**: Install Virtualizor 3.2.9.9 or later
4. **Audit SSH**: Remove unrecognized keys from root's `authorized_keys`; check for the fingerprint `SHA256:YQmy1hKF1h5cdJLxlZ5EScNoxe/UDWahjsWuQw2ERi8`
5. **Audit accounts**: Check for unauthorized `proxyuser` account
6. **Rotate credentials**: Reset all API keys, rotate SSH keys, restrict SSH to trusted IPs
7. **Network audit**: Check for outbound connections to `cdn[.]nerat[.]cc`, `connect[.]ne-rat[.]xyz`, `193.32.127[.]248`, `31.77.220[.]138`
8. **Client area**: Reset password if logged into Softaculous between Aug 28 20:57 UTC and Aug 30 06:10 UTC; review payment card statements

---

## Sources

- Virtualizor Advisory: https://www.virtualizor.com/blog/security-incident-bgp-hijacking/
- The Hacker News: https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html
- SecurityWeek: https://www.securityweek.com/malicious-virtualizor-update-served-via-bgp-hijacking/
- The Register: https://www.theregister.com/security/2026/09/01/33-hour-bgp-hijack-of-softaculous-traffic-prompts-security-scramble/5293608

---

*DRAFT -- Actioner automated analysis -- 2026-09-03*
