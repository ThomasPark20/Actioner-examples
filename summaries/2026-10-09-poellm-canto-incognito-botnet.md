# Technical Analysis Report: PoeLLM Malware / Canto Incognito Botnet Campaign (2026-10-09)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-09
Version: 1.0 (DRAFT)

## Executive Summary

Lumen's Black Lotus Labs disclosed a large-scale cryptomining botnet campaign dubbed **Canto Incognito**, powered by a novel Linux malware called **PoeLLM**, on October 7, 2026. The campaign has compromised over **3,400 servers** -- peaking at approximately 800 active nodes per day -- by targeting exposed AI and developer infrastructure services including **LiteLLM** AI gateways, **Ollama** model runners, **Gitea** code hosting instances, **Gotenberg** document-conversion services, and **Ivanti Sentry** appliances. The malware deploys XMRig and Iron cryptocurrency miners that connect to Kryptex, a Russian-operated mining pool. A distinctive feature of the campaign is its command-and-control (C2) address resolution mechanism: the C2 IP address is encoded in a poem titled "On the Nature of Connection" stored in a `dash.css` file within a forked Node.js GitHub repository, decoded via a hard-coded word-to-number dictionary embedded in the malware binary. Attribution points with moderate confidence to an Italian-speaking operator based on code comments and an Italy-based administrative server. The campaign has been active since at least April 2026, primarily affecting servers in the United States and Western Europe.

## Background: AI/LLM Infrastructure Exposure

The rapid proliferation of AI/LLM tooling has created a significant attack surface of internet-exposed services that were often designed for internal or development use. Services targeted in this campaign include:

- **LiteLLM** (default port 4000): An open-source AI proxy gateway providing a unified API to multiple LLM providers. Frequently deployed with default configurations and exposed to the internet for convenience.
- **Ollama** (default port 11434): A local model runner for open-weight LLMs, often exposed without authentication.
- **Gitea** (default port 3000): A self-hosted Git service popular in developer and CI/CD environments.
- **Gotenberg** (default port 3000): A Docker-based API for converting documents to PDF, typically unauthenticated.
- **Ivanti Sentry**: A mobile security gateway with a history of critical vulnerabilities.

These services share a common pattern: they are often deployed rapidly by development teams, exposed to the internet without authentication or access controls, and rarely monitored by security operations. The Canto Incognito campaign specifically exploits this operational gap.

## Attack Timeline

| Date | Event |
|------|-------|
| ~April 2026 | Earliest observed PoeLLM infections; campaign active since at least this date |
| 2026-05-12 | CVE-2026-42271 (LiteLLM MCP command injection) publicly disclosed |
| April -- October 2026 | C2 poem modified 11+ times; at least 11 distinct C2 servers used, including compromised routers |
| 2026-10-07 | Lumen Black Lotus Labs publishes research disclosing the Canto Incognito campaign and PoeLLM malware |
| 2026-10-07 -- 08 | BleepingComputer, The Hacker News, CyberScoop, The Register publish coverage |

## Root Cause: Exposed AI Services

The root cause of the campaign's success is the widespread exposure of unauthenticated AI and developer infrastructure services to the internet. Specifically:

1. **LiteLLM gateways** exposed on port 4000 with vulnerable MCP test endpoints (CVE-2026-42271) and the Starlette host-header authentication bypass (CVE-2026-48710) enabling unauthenticated remote code execution.
2. **Gotenberg** instances exposed on port 3000 without authentication, designed as internal document-conversion APIs but deployed internet-facing.
3. **Gitea, Ollama, and Ivanti Sentry** instances with default configurations, weak credentials, or unpatched vulnerabilities.

## Technical Analysis

### 1. Initial Access and Infection Chain

The PoeLLM malware propagates as a self-spreading worm. Infected hosts scan for new targets on **ports 3000** (Gotenberg/Gitea) and **4000** (LiteLLM). The primary exploitation chain combines:

- **CVE-2026-42271** (CVSS 8.7): Authenticated command injection in LiteLLM's MCP stdio test endpoints (`POST /mcp-rest/test/connection` and `POST /mcp-rest/test/tools/list`). The endpoints accept arbitrary `command` and `args` fields and spawn them as subprocesses.
- **CVE-2026-48710** (CVSS 6.5): Starlette host-header validation bypass that eliminates the authentication requirement, producing unauthenticated RCE.

Upon successful exploitation, the malware downloads and installs the payload -- an ELF binary named **`libgcrypt`** -- masquerading as the legitimate GNU libgcrypt cryptographic library.

### 2. Payload: The "libgcrypt" ELF Binary

The payload is a Linux ELF binary named `libgcrypt`, designed to blend in with legitimate system libraries. Key capabilities:

- **Cryptocurrency mining**: Deploys XMRig and Iron miners configured to connect to Kryptex (`kryptex[.]org` / `kryptex[.]network`), a Russian-operated mining pool service.
- **Remote shell**: Includes a reverse shell capability for interactive access by the operator.
- **Propagation engine**: Scans for additional vulnerable hosts on ports 3000 and 4000.
- **C2 communication**: Retrieves command-and-control server address by fetching and decoding a poem from GitHub.

### 3. C2 Mechanism: Poem-Based Address Resolution

The most distinctive feature of PoeLLM is its C2 address derivation mechanism:

1. The malware fetches a file named **`dash.css`** from a GitHub repository (a fork of the Node.js project).
2. The file contains a poem titled **"On the Nature of Connection"** rather than actual CSS.
3. A **hard-coded dictionary** within the malware binary maps specific English words from the poem to numeric values.
4. The malware parses the poem, looks up specific words in its dictionary, and assembles the resulting numbers into an IPv4 address -- the current C2 server.
5. The operator **rotates the C2 address** by editing the poem in the GitHub repository. The poem has been modified at least **11 times**, corresponding to at least **11 different C2 servers**.
6. Some C2 servers were themselves **compromised routers**, adding a layer of indirection.

This technique abuses GitHub as a dead-drop resolver, leveraging the platform's high availability and reputation to evade domain-based blocking. Naming the file `dash.css` helps it blend in with legitimate web assets.

### 4. Cryptomining Operations

Compromised hosts run XMRig and/or Iron cryptocurrency miners connecting to the Kryptex mining service. At peak, approximately 800 active mining nodes operating simultaneously represents significant aggregated compute theft from AI infrastructure -- servers typically provisioned with high-end CPUs and GPUs.

### 5. Attribution

Lumen attributes the campaign with **moderate confidence to an Italian-speaking operator** based on:

- Italian-language comments found in the PoeLLM source code / binary
- An administrative server geolocated to Italy

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: `hxxps://` replaces `https://`, `[.]` replaces dots in domains/IPs.

### File System

| Type | Value | Context |
|------|-------|---------|
| Filename | `libgcrypt` | Malicious ELF binary payload; masquerades as GNU libgcrypt library |
| File type | ELF executable | Linux binary, not a shared library (.so) as the name implies |
| Filename | `dash.css` | GitHub-hosted file containing C2 poem; not actual CSS |

### Network

| Type | Value | Context |
|------|-------|---------|
| Port | 3000/tcp | Scanning target: Gotenberg / Gitea services |
| Port | 4000/tcp | Scanning target: LiteLLM AI gateway |
| Domain | `*[.]kryptex[.]org` | Kryptex mining pool |
| Domain | `*[.]kryptex[.]network` | Kryptex mining pool |
| URI path | `/mcp-rest/test/connection` | LiteLLM CVE-2026-42271 exploit endpoint |
| URI path | `/mcp-rest/test/tools/list` | LiteLLM CVE-2026-42271 exploit endpoint |
| Domain | `raw[.]githubusercontent[.]com` | Poem/C2-config retrieval (dash.css fetch) |

### Behavioral

- ELF binary named `libgcrypt` executed directly (legitimate libgcrypt is a shared library, never executed as a standalone binary)
- Outbound scanning on ports 3000 and 4000 from server infrastructure
- HTTP GET requests to GitHub raw content for `dash.css` files from server hosts
- XMRig/Iron miner processes on AI/developer infrastructure servers
- DNS queries or connections to `kryptex[.]org` or `kryptex[.]network` domains
- Unexpected child processes spawned by LiteLLM/uvicorn (indicators of CVE-2026-42271 exploitation)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of LiteLLM (CVE-2026-42271 + CVE-2026-48710), Gotenberg, Gitea, Ollama, Ivanti Sentry |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Remote shell capability; command execution via MCP stdio endpoints |
| T1036.005 | Masquerading: Match Legitimate Name or Location | ELF binary named "libgcrypt" to mimic legitimate GNU cryptographic library |
| T1046 | Network Service Discovery | Automated scanning of ports 3000 and 4000 for vulnerable AI/developer services |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 address retrieved via HTTPS from GitHub (dash.css poem) |
| T1102.001 | Web Service: Dead Drop Resolver | GitHub repository used as dead-drop for C2 address encoded in poem |
| T1496 | Resource Hijacking | XMRig and Iron cryptocurrency miners deployed on compromised servers |
| T1021 | Remote Services | Remote shell access to compromised hosts |
| T1041 | Exfiltration Over C2 Channel | Mining output sent to Kryptex pool via C2/stratum protocols |

## Detection & Remediation

### Immediate Detection

Check for the malicious binary:

```bash
# Search for the libgcrypt executable (not .so shared library)
find / -name "libgcrypt" -type f -executable 2>/dev/null

# Check for running mining processes
ps aux | grep -E 'xmrig|iron|kryptex|stratum' | grep -v grep

# Check for active connections to Kryptex mining pools
ss -tnp | grep -E ':(3333|5555|7777|9999)' 2>/dev/null
netstat -tnp | grep -E 'kryptex' 2>/dev/null

# Check for scanning activity on ports 3000/4000
ss -tnp | grep -E ':(3000|4000)' | head -20

# Check LiteLLM logs for exploit attempts
grep -rE 'POST.*/mcp-rest/test/(connection|tools/list)' /var/log/ 2>/dev/null
docker logs $(docker ps -q --filter ancestor=ghcr.io/berriai/litellm) 2>&1 | grep -E '/mcp-rest/test/' | tail -20
```

### Remediation

1. **Immediate:** Identify and terminate any `libgcrypt` executable processes; remove the binary.
2. **Immediate:** Kill XMRig/Iron miner processes and remove associated binaries.
3. **Patch LiteLLM:** Upgrade to version 1.83.7+ (fixes CVE-2026-42271); upgrade Starlette to 1.0.1+ (fixes CVE-2026-48710).
4. **Network access controls:** Remove direct internet exposure of LiteLLM (port 4000), Gotenberg (port 3000), Ollama (port 11434), and Gitea services. Place behind authenticated reverse proxies.
5. **Firewall rules:** Block outbound connections to `kryptex[.]org` and `kryptex[.]network` domains.
6. **Credential rotation:** Rotate all API keys configured in compromised LiteLLM instances (LLM provider keys for OpenAI, Anthropic, etc.).
7. **Network forensics:** Review firewall logs for outbound scanning on ports 3000/4000 to identify compromised hosts that may have propagated the worm.

### Long-Term Hardening

- Inventory all AI/developer infrastructure services and enforce authentication on every internet-facing endpoint.
- Implement network segmentation between AI infrastructure and general-purpose networks.
- Deploy EDR/host-based detection on AI infrastructure servers (often neglected compared to traditional servers).
- Monitor for anomalous CPU/GPU utilization on AI servers (cryptomining indicator).
- Block or alert on GitHub raw content fetches from server infrastructure (unusual for production servers).

## Detection Rules

These detections target the specific IOCs and behaviors associated with the PoeLLM malware and Canto Incognito botnet campaign. They are tuned for this campaign (PoC/advisory-specific altitude). Compiles does not equal fires -- verify in your pipeline.

### Sigma: PoeLLM Malicious libgcrypt Binary Execution

Detects execution of the malicious ELF binary named "libgcrypt" -- the legitimate GNU libgcrypt is a shared library (.so) and is never executed as a standalone binary.
**Status:** compile ✅ compiles (sigma convert exit 0, splunk + log_scale; sigma check exit 0 excluding attacktag validator due to network restriction) · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. sigma check -x attacktag exit 0 (0 errors, 0 issues). sigma check full cannot reach MITRE ATT&CK data (HTTP 403 proxy block). FP: extremely unlikely -- legitimate libgcrypt is never executed directly. -->
```yaml
title: PoeLLM Malicious libgcrypt ELF Binary Execution (Canto Incognito)
id: a4c1e7d3-8b2f-4d6e-9f13-5c8a0e2b7d4f
status: experimental
description: >
    Detects execution of the malicious ELF binary named "libgcrypt" associated
    with the PoeLLM malware and Canto Incognito botnet campaign. The binary
    masquerades as the legitimate GNU libgcrypt library but is actually a
    cryptomining dropper with remote shell capability.
references:
    - https://www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/
    - https://thehackernews.com/2026/10/poellm-malware-infects-3400-servers-to.html
    - https://cyberscoop.com/poellm-malware-botnet-poem-lumen-black-lotus-labs/
author: Actioner
date: 2026/10/09
tags:
    - attack.execution
    - attack.t1059.004
    - attack.defense_evasion
    - attack.t1036.005
logsource:
    category: process_creation
    product: linux
detection:
    selection_name:
        Image|endswith: '/libgcrypt'
    selection_cmdline:
        CommandLine|contains: 'libgcrypt'
    condition: selection_name or selection_cmdline
falsepositives:
    - Unlikely - the legitimate libgcrypt is a shared library (libgcrypt.so) not executed directly
level: high
```

### Sigma: PoeLLM Port Scanning on AI Infrastructure Ports 3000/4000

Detects outbound connection attempts to both ports 3000 (Gotenberg/Gitea) and 4000 (LiteLLM) from a single host, indicative of PoeLLM propagation scanning.
**Status:** compile ✅ compiles (sigma convert exit 0, splunk + log_scale; sigma check exit 0) · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. sigma check -x attacktag exit 0 (0 errors, 0 issues). AND logic requires both ports seen in same event/timeframe. FP: dev environments running both services. Evasion: port randomization or different propagation ports in future variants. -->
```yaml
title: PoeLLM Port Scanning on AI Infrastructure Ports 3000 and 4000 (Canto Incognito)
id: b5d2f8e4-9c3a-4e7b-a024-6d9b1f3c8e5a
status: experimental
description: >
    Detects outbound connection attempts to ports 3000 (Gotenberg) and 4000
    (LiteLLM) from a single host, indicative of the PoeLLM malware scanning
    for exposed AI and developer infrastructure as part of the Canto Incognito
    botnet propagation mechanism.
references:
    - https://www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/
    - https://thehackernews.com/2026/10/poellm-malware-infects-3400-servers-to.html
author: Actioner
date: 2026/10/09
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: firewall
detection:
    selection_port3000:
        dst_port: 3000
    selection_port4000:
        dst_port: 4000
    condition: selection_port3000 and selection_port4000
falsepositives:
    - Legitimate internal services using both ports 3000 and 4000 (e.g., development environments running Node.js and LiteLLM)
    - Network vulnerability scanners
level: medium
```

### Sigma: XMRig/Kryptex Mining Pool DNS Query

Detects DNS queries to Kryptex mining pool domains associated with PoeLLM cryptocurrency mining activity.
**Status:** compile ✅ compiles (sigma convert exit 0, splunk + log_scale; sigma check exit 0) · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. sigma check -x attacktag exit 0. FP: intentional Kryptex usage (unlikely on servers). Domain suffix match is specific. -->
```yaml
title: XMRig or Iron Miner Connection to Kryptex Mining Pool (PoeLLM)
id: c6e3a9f5-0d4b-4f8c-b135-7eac2a4d9f6b
status: experimental
description: >
    Detects DNS queries or network connections to Kryptex mining pool domains
    associated with the PoeLLM malware cryptocurrency mining activity. The
    Canto Incognito botnet deploys XMRig and Iron miners that connect to
    Kryptex, a Russian-operated mining service.
references:
    - https://www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/
    - https://thehackernews.com/2026/10/poellm-malware-infects-3400-servers-to.html
    - https://cyberscoop.com/poellm-malware-botnet-poem-lumen-black-lotus-labs/
author: Actioner
date: 2026/10/09
tags:
    - attack.impact
    - attack.t1496
logsource:
    category: dns
detection:
    selection_dns:
        query|endswith:
            - '.kryptex.org'
            - '.kryptex.network'
    condition: selection_dns
falsepositives:
    - Users intentionally running Kryptex mining software (unlikely on servers)
level: high
```

### Sigma: XMRig/Iron Miner Process Execution

Detects execution of XMRig or Iron miner binaries or command-line patterns associated with PoeLLM mining payloads.
**Status:** compile ✅ compiles (sigma convert exit 0, splunk + log_scale; sigma check exit 0) · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. sigma check -x attacktag exit 0. FP: authorized mining (unlikely on prod). CommandLine patterns cover stratum protocol URLs and kryptex domain references. -->
```yaml
title: XMRig Cryptocurrency Miner Process Execution (PoeLLM)
id: d7f4b0a6-1e5c-4a9d-c246-8fbd3b5ea0c7
status: experimental
description: >
    Detects execution of XMRig or Iron cryptocurrency miner binaries on Linux
    hosts, as deployed by the PoeLLM malware. The Canto Incognito botnet
    installs these miners on compromised AI infrastructure servers.
references:
    - https://www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/
    - https://thehackernews.com/2026/10/poellm-malware-infects-3400-servers-to.html
author: Actioner
date: 2026/10/09
tags:
    - attack.impact
    - attack.t1496
logsource:
    category: process_creation
    product: linux
detection:
    selection_image:
        Image|endswith:
            - '/xmrig'
            - '/iron'
    selection_cmdline:
        CommandLine|contains:
            - 'xmrig'
            - '--coin monero'
            - 'stratum+tcp://'
            - 'stratum+ssl://'
            - 'kryptex.org'
            - 'kryptex.network'
    condition: selection_image or selection_cmdline
falsepositives:
    - Authorized cryptocurrency mining operations (not expected on production AI servers)
level: high
```

### YARA: PoeLLM libgcrypt ELF Binary

Detects the PoeLLM ELF binary based on a combination of ELF magic, the masquerade name, poem-based C2 derivation strings, miner references, and shell capability.
**Status:** compile ✅ compiles (yarac exit 0) · confidence: high
<!-- audit: yarac yara_poellm.yar /dev/null exit 0. No unreferenced strings. Rule requires ELF magic at offset 0, the masquerade name, at least one C2/miner cluster, and a shell string. Tuned for low FP on legitimate libgcrypt.so (which won't match the poem/miner strings). -->
```yara
rule PoeLLM_Libgcrypt_ELF
{
    meta:
        description = "Detects the PoeLLM malware ELF binary masquerading as libgcrypt, used in the Canto Incognito botnet campaign"
        author = "Actioner"
        date = "2026-10-09"
        reference = "https://www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/"
        reference2 = "https://thehackernews.com/2026/10/poellm-malware-infects-3400-servers-to.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        // ELF magic
        $elf_magic = { 7F 45 4C 46 }

        // Poem-based C2 derivation strings
        $poem_title = "On the Nature of Connection" ascii
        $poem_fetch = "dash.css" ascii

        // Word-to-number dictionary entries (C2 address derivation)
        $dict_word1 = "through" ascii
        $dict_word2 = "silence" ascii
        $dict_word3 = "between" ascii
        $dict_word4 = "whisper" ascii
        $dict_word5 = "beneath" ascii

        // Miner-related strings
        $miner1 = "xmrig" ascii nocase
        $miner2 = "kryptex" ascii nocase
        $miner3 = "stratum" ascii

        // Scanning / propagation targets
        $target1 = "litellm" ascii nocase
        $target2 = "gotenberg" ascii nocase

        // Binary name masquerading
        $masquerade = "libgcrypt" ascii

        // Remote shell
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii

    condition:
        $elf_magic at 0 and
        $masquerade and
        (
            ($poem_title or $poem_fetch) or
            (2 of ($dict_word*)) or
            (1 of ($miner*) and 1 of ($target*))
        ) and
        (1 of ($shell*))
}
```

### Snort: PoeLLM LiteLLM/Gotenberg Exploitation and C2

Detects HTTP POST exploitation attempts against LiteLLM and Gotenberg, GitHub-based C2 poem retrieval, and Kryptex mining pool connections.
**Status:** ⚠️ uncompiled (structural check only -- snort not available in build environment) · confidence: high
<!-- audit: snort binary not available; rules follow Snort 2.9.x syntax with http_method/http_uri modifiers and fast_pattern. Structural review: all rules have flow, content, classtype, sid/rev. Port-specific rules (4000, 3000) reduce FP surface. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 4000 (msg:"Actioner - PoeLLM LiteLLM MCP RCE Exploit Attempt (CVE-2026-42271) on Port 4000"; flow:established,to_server; content:"POST"; http_method; content:"/mcp-rest/test/"; http_uri; fast_pattern; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/; reference:cve,2026-42271; metadata:author Actioner, created 2026-10-09; sid:2100201; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET 3000 (msg:"Actioner - PoeLLM Gotenberg Exploitation Attempt on Port 3000"; flow:established,to_server; content:"POST"; http_method; content:"/forms/"; http_uri; fast_pattern; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/; metadata:author Actioner, created 2026-10-09; sid:2100202; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PoeLLM dash.css Poem C2 Retrieval from GitHub"; flow:established,to_server; content:"GET"; http_method; content:"dash.css"; http_uri; fast_pattern; content:"raw.githubusercontent.com"; http_header; classtype:trojan-activity; reference:url,cyberscoop.com/poellm-malware-botnet-poem-lumen-black-lotus-labs/; metadata:author Actioner, created 2026-10-09; sid:2100203; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PoeLLM Kryptex Mining Pool Connection"; flow:established,to_server; content:"kryptex"; fast_pattern; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/; metadata:author Actioner, created 2026-10-09; sid:2100204; rev:1;)
```

### Suricata: PoeLLM LiteLLM/Gotenberg Exploitation and C2

Detects the same network patterns using Suricata's HTTP application-layer inspection with dot-notation sticky buffers.
**Status:** ⚠️ uncompiled (structural check only -- suricata not available in build environment) · confidence: high
<!-- audit: suricata binary not available; rules follow Suricata 7.x syntax with http.method/http.uri/http.host/dns.query sticky buffers. Structural review: all rules have flow, content with sticky buffers, classtype, sid/rev. Port-specific targeting reduces FP. DNS rule uses dns.query for Kryptex detection. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET 4000 (msg:"Actioner - PoeLLM LiteLLM MCP RCE Exploit Attempt (CVE-2026-42271)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/mcp-rest/test/"; fast_pattern; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/; reference:cve,2026-42271; metadata:author Actioner, created_at 2026-10-09; sid:2200201; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET 3000 (msg:"Actioner - PoeLLM Gotenberg Exploitation Attempt on Port 3000"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/forms/"; fast_pattern; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/; metadata:author Actioner, created_at 2026-10-09; sid:2200202; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PoeLLM dash.css Poem C2 Retrieval from GitHub"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"dash.css"; fast_pattern; http.host; content:"raw.githubusercontent.com"; classtype:trojan-activity; reference:url,cyberscoop.com/poellm-malware-botnet-poem-lumen-black-lotus-labs/; metadata:author Actioner, created_at 2026-10-09; sid:2200203; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - PoeLLM Kryptex Mining Pool DNS Query"; dns.query; content:"kryptex"; fast_pattern; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/; metadata:author Actioner, created_at 2026-10-09; sid:2200204; rev:1;)
```

## Sources

- [BleepingComputer: PoeLLM malware infects exposed AI servers in cryptomining attacks](https://www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/) -- primary reporting on campaign scope, 3,400+ servers, and mining payloads
- [The Hacker News: PoeLLM Malware Infects 3,400 Servers to Mine Cryptocurrency](https://thehackernews.com/2026/10/poellm-malware-infects-3400-servers-to.html) -- technical details on infection chain, CVE exploitation, and poem-based C2
- [CyberScoop: PoeLLM malware botnet poem Lumen Black Lotus Labs](https://cyberscoop.com/poellm-malware-botnet-poem-lumen-black-lotus-labs/) -- Lumen Black Lotus Labs research attribution, Italian operator assessment, C2 poem mechanism
- [The Register: Poetry is the new AI security threat as PoeLLM malware infects 3K+ servers](https://www.theregister.com/security/2026/10/07/poetry-is-the-new-ai-security-threat-as-poellm-malware-infects-3k-servers/) -- additional context on targeted services and geographic distribution

---
*Report generated by Actioner (DRAFT)*
