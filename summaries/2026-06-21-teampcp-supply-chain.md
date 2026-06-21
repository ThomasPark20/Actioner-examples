# TeamPCP Open-Source Supply Chain Attack

<!-- revision: REVISE pass 2026-06-21. Sigma 4 dropped (behavioral, ~100% FP in dev/CI). Sigma 2 downgraded to medium (IP reassignment risk), 4 recon IPs excluded with rationale. Sigma 3 narrowed to full attacker paths. Sigma 5 tightened to AND logic for file markers. Sigma 6 hooks changed to endswith. Sigma 8 lowered to low (|re portability). YARA 1 added filesize<10MB, renamed reference2. YARA 3 changed to 2 of ($marker_*). YARA 4 added TeamPCP-specific strings, confidence now high-with-strings/low-without. Snort 1-6,8 anchored to Host header. Cloudflare tunnel URLs defanged. T1021.007 replaced with T1021. T1609 noted as Containers matrix, remapped to T1059. CVE-2026-45321 context added. Cloudflare tunnel IOCs noted as ephemeral. -->

**Date:** 2026-06-21
**Status:** REVISED
**TLP:** CLEAR

---

## Executive Summary

TeamPCP (also tracked as UNC6780 by Google GTIG) is a threat group that has systematically compromised over 1,000 open-source software packages across npm, PyPI, and GitHub Actions since late February 2026. The campaign has affected packages with approximately 500 million combined weekly downloads, stolen an estimated 500,000 credentials, and resulted in the exfiltration of over 300 GB of data from impacted organizations. Notable victims include GitHub (~3,800 internal repositories exfiltrated), Checkmarx, Bitwarden, LiteLLM, TanStack, Mistral AI, UiPath, SAP, Red Hat, and Microsoft DurableTask. The group's self-propagating worm, dubbed "Mini Shai-Hulud," represents a novel escalation in supply chain attack sophistication by publishing trojanized versions of every package accessible to a compromised developer account.

<!-- revision: CVE-2026-45321 was referenced in the original exec summary without further context. This CVE relates to the GitHub Actions OIDC token audience bypass that enabled TeamPCP's cross-org propagation (Wave 4). Full exploitation details are covered in the Phoenix Security and Unit 42 references. -->

---

## Sources

- [CyberScoop - TeamPCP breaks open source software trust model](https://cyberscoop.com/teampcp-breaks-open-source-software-trust-model/)
- [Unit 42 - Weaponizing the Protectors: TeamPCP Multi-Stage Supply Chain Attack](https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/)
- [ramimac - Incident Timeline: TeamPCP Supply Chain Campaign](https://ramimac.me/teampcp/)
- [Phoenix Security - TeamPCP Wave Four: GitHub Breach via Poisoned VS Code Extension](https://phoenix.security/teampcp-github-breach-durabletask-pypi-supply-chain-wave-four-2026/)
- [Orca Security - TanStack and 160+ npm/PyPI Packages Compromised](https://orca.security/resources/blog/tanstack-npm-supply-chain-worm/)
- [Tenable - Mini Shai-Hulud Supply Chain Attack FAQ](https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions)

---

## Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| **Name** | TeamPCP |
| **Aliases** | UNC6780 (GTIG), PCPcat |
| **Key Handles** | ResoluteXBF (core manager), diencracked, Shinigami, Persy_PCP, ShellForce, CipherForce, DeadCatx3 |
| **Attribution** | Primary operator based in South Africa (per Google) |
| **Motivation** | Notoriety and chaos; monetization via credential sales and ransomware partnerships (Vect ransomware) |
| **Telegram** | @Persy_PCP, @teampcp |

---

## Campaign Timeline

| Date | Event |
|------|-------|
| 2026-02-27 | Initial PwnRequest exploitation; `aqua-bot` PAT exfiltrated |
| 2026-03-19 | Wave 1: Trivy (Aqua Security) compromised via GitHub Actions; 76 of 77 version tags poisoned |
| 2026-03-22 | ICP blockchain C2 fallback events observed |
| 2026-03-23 | Checkmarx VS Code extensions poisoned on OpenVSX; LiteLLM PyPI v1.82.7/v1.82.8 infected |
| 2026-03-24 | Checkmarx KICS GitHub Action (all 35 tags) and ast-github-action v2.3.28 compromised |
| 2026-04-15 | Vect ransomware group begins publishing victims using TeamPCP-stolen credentials |
| 2026-05-11 | Mini Shai-Hulud worm: 400+ malicious versions across 172 packages in 5 hours |
| 2026-05-20 | GitHub confirms breach; ~3,800 internal repositories exfiltrated via poisoned VS Code extension |
| 2026-05 | AntV ecosystem compromise: 323 packages |
| 2026-05 | DurableTask PyPI worm (v1.4.1-1.4.3) |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | TeamPCP Usage |
|-------------|------|---------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Injected malware into npm/PyPI packages and GitHub Actions |
| T1059.006 | Command and Scripting Interpreter: Python | Python-based credential harvesters (kube.py, prop.py, pgmonitor.py) |
| T1027 | Obfuscated Files or Information | Double base64 encoding, AES-256-CBC encryption, WAV steganography |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 communication |
| T1102.001 | Web Service: Dead Drop Resolver | FIRESCALE dead-drop pattern via GitHub commit search API; ICP blockchain C2 |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvesting .aws/credentials, .kube/config, .npmrc, .ssh/*, .env files |
| T1543.002 | Create or Modify System Process: Systemd Service | pgsql-monitor.service, sysmon.service persistence |
| T1543.004 | Create or Modify System Process: Launch Agent | com.user.gh-token-monitor.plist on macOS |
| T1057 | Process Discovery | Reading /proc/PID/environ for runner secrets |
| T1560.001 | Archive Collected Data: Archive via Utility | openssl + tar for encrypted payload staging |
| T1567.001 | Exfiltration Over Web Service: Code Repository | Encrypted credential bundles pushed as results.json to public GitHub repos |
| T1041 | Exfiltration Over C2 Channel | Data exfiltrated to attacker-controlled domains |
| T1021 | Remote Services | AWS SSM SendCommand for lateral propagation |
| T1059 | Command and Scripting Interpreter | kubectl exec for lateral movement into pods (originally mapped T1609/Containers matrix; remapped to Enterprise matrix T1059) |
| T1485 | Data Destruction | Geofenced wiper (roulette.py) targeting he_IL/fa_IR locales |
| T1078 | Valid Accounts | Stolen PATs and OIDC tokens used for package publishing |

<!-- revision: T1021.007 does not exist as a sub-technique; replaced with T1021 (Remote Services). T1609 (Container Administration Command) is in the Containers matrix, not Enterprise; remapped to T1059 (Command and Scripting Interpreter) for Enterprise coverage. -->

---

## Indicators of Compromise

### C2 Domains (Defanged)

| Domain | Usage |
|--------|-------|
| scan[.]aquasecurtiy[.]org | Primary C2 (Trivy campaign) |
| checkmarx[.]zone | Checkmarx wave C2 |
| models[.]litellm[.]cloud | LiteLLM wave C2 |
| git-tanstack[.]com | TanStack typosquat C2 |
| check[.]git-service[.]com | DurableTask wave C2 & payload delivery |
| t[.]m-kosche[.]com | AntV/secondary payload delivery |
| nsa[.]cat | Operational VPS |
| tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io | ICP blockchain fallback C2 |

### Cloudflare Tunnel URLs (Defanged)

<!-- revision: These Cloudflare tunnel URLs are ephemeral and rotate frequently. They are included for historical correlation only and are not covered in network detection rules because they resolve to shared Cloudflare infrastructure where blocking would cause collateral damage. -->

- championships-peoples-point-cassette[.]trycloudflare[.]com
- create-sensitivity-grad-sequence[.]trycloudflare[.]com
- investigation-launches-hearings-copying[.]trycloudflare[.]com
- plug-tab-protective-relay[.]trycloudflare[.]com
- souls-entire-defined-routes[.]trycloudflare[.]com

### IP Addresses

| IP | Context |
|----|---------|
| 23[.]142[.]184[.]129 | C2 infrastructure |
| 45[.]148[.]10[.]212 | C2 infrastructure |
| 63[.]251[.]162[.]11 | C2 infrastructure |
| 83[.]142[.]209[.]11 | Checkmarx/Telnyx wave |
| 83[.]142[.]209[.]194 | TanStack/Mini Shai-Hulud wave |
| 83[.]142[.]209[.]203 | Checkmarx/Telnyx wave |
| 195[.]5[.]171[.]242 | C2 infrastructure |
| 209[.]34[.]235[.]18 | C2 infrastructure |
| 212[.]71[.]124[.]188 | C2 infrastructure |
| 209[.]159[.]147[.]239 | TruffleHog credential validation (NYC VPS) -- excluded from detection rules (shared hosting, high reassignment risk) |
| 170[.]62[.]100[.]245 | Cloud enumeration/S3 scanning (Kali Linux) -- excluded from detection rules (short-lived VPS) |
| 154[.]47[.]29[.]12 | Organization reconnaissance -- excluded from detection rules (shared hosting) |
| 103[.]75[.]11[.]59 | Credential re-validation (macOS ARM) -- excluded from detection rules (shared hosting) |

### Compromised Package Versions

**PyPI:**
- litellm 1.82.7, 1.82.8
- telnyx 4.87.1, 4.87.2
- durabletask 1.4.1, 1.4.2, 1.4.3
- guardrails-ai 0.10.1
- mistralai 2.4.6

**npm:**
- @tanstack/* (42 packages, 84 malicious versions)
- @uipath/* (66 entries)
- @squawk/* (87 entries)
- @mistralai/* (mistralai, mistralai-azure, mistralai-gcp)
- @emilgroup/*, @opengov/*, @v7/* namespaces
- AntV ecosystem (323 packages)

**GitHub Actions:**
- aquasecurity/trivy-action (76 of 77 version tags)
- aquasecurity/setup-trivy (all tags)
- checkmarx/kics-github-action (all 35 tags)
- checkmarx/ast-github-action v2.3.28

### File Hashes (SHA-256) -- Selected

| Hash | Artifact |
|------|----------|
| 3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf | durabletask-1.4.1.tar.gz |
| 85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f | durabletask-1.4.2.tar.gz |
| c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc | durabletask-1.4.3.tar.gz |
| 069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce | rope.pyz payload |
| 0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349 | Trivy wave payload |
| 7b5cc85e82249b0c452c66563edca498ce9d0c70badef04ab2c52acef4d629ca | Trivy wave payload |
| e4edd126e139493d2721d50c3a8c49d3a23ad7766d0b90bc45979ba675f35fea | Trivy wave payload |

### Malicious File Artifacts

| Path | Description |
|------|-------------|
| /tmp/managed.pyz | Second-stage payload |
| ~/.cache/.sys-update-check | AWS SSM propagation marker |
| ~/.cache/.sys-update-check-k8s | Kubernetes propagation marker |
| /usr/bin/pgmonitor.py | Persistence payload (root) |
| ~/.local/bin/pgmonitor.py | Persistence payload (non-root) |
| kamikaze.sh | Destructive script |
| kube.py, prop.py | Credential harvesters |
| tpcp.tar.gz | Exfiltration archive |
| session.key / payload.enc | Encryption artifacts |
| .claude/router_runtime.js | Mini Shai-Hulud AI tool hook |
| .vscode/setup.mjs | Mini Shai-Hulud VS Code hook |

### Exfiltration Repository Names (Russian Folklore Theme)

BABA-YAGA, KOSCHEI, FIREBIRD, PTITSA, RUSALKA, MOROZKO, LESHY, DOMOVOI, VODYANOY

---

## Detection Rules

### Sigma Rules

#### 1. TeamPCP C2 Domain DNS Lookups

Detects DNS queries resolving known TeamPCP command-and-control domains. IOC-based detection with no expected false positives.

<!-- Audit: sigma check passed (0 errors). sigma convert --without-pipeline -t splunk succeeded. -->

**File:** `rules/sigma/2026-06-21-teampcp-supply-chain.yml` (rule 1 of 7)

```yaml
title: TeamPCP Supply Chain Attack - C2 Domain DNS Lookups
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects DNS queries to known TeamPCP command-and-control domains used in supply chain attack campaigns from March-May 2026.
references:
    - https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/
    - https://ramimac.me/teampcp/
    - https://phoenix.security/teampcp-github-breach-durabletask-pypi-supply-chain-wave-four-2026/
author: Actioner CTI
date: 2026-06-21
tags:
    - attack.t1071.001
    - attack.t1102.001
logsource:
    category: dns
detection:
    selection:
        query|endswith:
            - 'scan.aquasecurtiy.org'
            - 'checkmarx.zone'
            - 'models.litellm.cloud'
            - 'git-tanstack.com'
            - 'check.git-service.com'
            - 't.m-kosche.com'
            - 'nsa.cat'
            - 'tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io'
    condition: selection
falsepositives:
    - Unlikely, these are attacker-controlled domains
level: high
```

**Splunk SPL:**
```
query IN ("*scan.aquasecurtiy.org", "*checkmarx.zone", "*models.litellm.cloud", "*git-tanstack.com", "*check.git-service.com", "*t.m-kosche.com", "*nsa.cat", "*tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io")
```

| Compile | Confidence |
|---------|------------|
| pass (sigma check + splunk) | high |

---

#### 2. TeamPCP C2 IP Address Connections

Detects outbound network connections to TeamPCP attacker infrastructure IPs. Four reconnaissance/validation IPs (209.159.147.239, 170.62.100.245, 154.47.29.12, 103.75.11.59) were excluded because they are shared hosting or short-lived VPS nodes with high reassignment likelihood. Confidence downgraded to medium because core C2 IPs may also be reassigned over time.

<!-- revision: Downgraded from high to medium per critic. Excluded 4 recon IPs with documented rationale. -->
<!-- Audit: sigma check passed (0 errors). sigma convert --without-pipeline -t splunk succeeded. -->

**File:** `rules/sigma/2026-06-21-teampcp-supply-chain.yml` (rule 2 of 7)

```yaml
title: TeamPCP Supply Chain Attack - C2 IP Address Connections
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
    Detects network connections to IP addresses associated with TeamPCP supply chain attack
    infrastructure. Confidence is medium because IPs may be reassigned over time. Four
    reconnaissance/validation IPs (209.159.147.239, 170.62.100.245, 154.47.29.12, 103.75.11.59)
    were excluded because they are shared hosting or short-lived VPS nodes with high reassignment
    likelihood and would generate excessive false positives.
references:
    - https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/
    - https://phoenix.security/teampcp-github-breach-durabletask-pypi-supply-chain-wave-four-2026/
author: Actioner CTI
date: 2026-06-21
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '23.142.184.129'
            - '45.148.10.212'
            - '63.251.162.11'
            - '83.142.209.11'
            - '83.142.209.194'
            - '83.142.209.203'
            - '195.5.171.242'
            - '209.34.235.18'
            - '212.71.124.188'
    condition: selection
falsepositives:
    - IP address reassignment after infrastructure takedown
level: medium
```

| Compile | Confidence |
|---------|------------|
| pass (sigma check + splunk) | medium |

---

#### 3. TeamPCP Persistence via Fake PostgreSQL Service

Detects creation of systemd services masquerading as PostgreSQL monitoring and TeamPCP-specific persistence payloads at known attacker paths. The `selection_payload` uses full paths (`/usr/bin/pgmonitor.py`, etc.) and `selection_payload_user` (home-relative paths) requires co-occurrence with `selection_service` to avoid matching any arbitrary file named `pglog`.

<!-- revision: Narrowed selection_payload to full attacker paths. User-relative paths now AND with selection_service to prevent standalone pglog false positives. -->
<!-- Audit: sigma check passed (0 errors). sigma convert --without-pipeline -t splunk succeeded. -->

**File:** `rules/sigma/2026-06-21-teampcp-supply-chain.yml` (rule 3 of 7)

```yaml
title: TeamPCP Supply Chain Attack - Persistence via Fake PostgreSQL Service
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: >
    Detects the creation of systemd services masquerading as PostgreSQL monitoring and
    TeamPCP-specific persistence payloads. The selection_payload condition uses full attacker
    paths to avoid matching any file arbitrarily named pglog.
references:
    - https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/
    - https://phoenix.security/teampcp-github-breach-durabletask-pypi-supply-chain-wave-four-2026/
author: Actioner CTI
date: 2026-06-21
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection_service:
        TargetFilename|endswith:
            - '/pgsql-monitor.service'
            - '/sysmon.service'
    selection_payload:
        TargetFilename:
            - '/usr/bin/pgmonitor.py'
            - '/usr/bin/pglog'
            - '/usr/bin/.pg_state'
    selection_payload_user:
        TargetFilename|endswith:
            - '/.local/bin/pgmonitor.py'
            - '/.local/bin/pglog'
            - '/.local/bin/.pg_state'
    condition: selection_service or selection_payload or (selection_payload_user and selection_service)
falsepositives:
    - Legitimate PostgreSQL monitoring scripts at these exact paths (unlikely)
level: medium
```

| Compile | Confidence |
|---------|------------|
| pass (sigma check + splunk) | medium |

---

#### ~~4. TeamPCP Credential File Access by Python~~ -- DROPPED

<!-- revision: DROPPED. Behavioral rule, not artifact-specific. ~100% FP rate in dev/CI environments where any Python/Node process touching credential files matches. The YAML title said "Python" but the report described "Python/Node", further indicating scope creep. -->

---

#### 5. TeamPCP OpenSSL Encryption for Exfiltration

Detects openssl used with the specific session.key + payload.enc + AES-256-CBC pattern used by TeamPCP for encrypted exfiltration staging. Both file-name markers (session.key and payload.enc) are now required together via AND logic to prevent `aes-256-cbc` alone from firing.

<!-- revision: Tightened OR to AND logic. Both session.key and payload.enc are now required together. aes-256-cbc alone no longer matches. -->
<!-- Audit: sigma check passed (0 errors). sigma convert --without-pipeline -t splunk succeeded. -->

**File:** `rules/sigma/2026-06-21-teampcp-supply-chain.yml` (rule 4 of 7)

```yaml
title: TeamPCP Supply Chain Attack - OpenSSL Encryption for Exfiltration
id: e5f6a7b8-c9d0-1234-efab-345678901234
status: experimental
description: >
    Detects the use of openssl to generate session keys and encrypt payloads for exfiltration,
    matching the specific AES-256-CBC + session.key + payload.enc pattern used by TeamPCP.
    Both file-name markers (session.key and payload.enc) are required together to avoid
    matching legitimate openssl usage.
references:
    - https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/
author: Actioner CTI
date: 2026-06-21
tags:
    - attack.t1027
    - attack.t1560.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_openssl:
        Image|endswith: '/openssl'
    selection_markers:
        CommandLine|contains|all:
            - 'session.key'
            - 'payload.enc'
    selection_aes_encrypt:
        CommandLine|contains|all:
            - 'aes-256-cbc'
            - 'session.key'
            - 'payload.enc'
    condition: selection_openssl and (selection_markers or selection_aes_encrypt)
falsepositives:
    - Legitimate use of openssl with both session.key and payload.enc filenames (unlikely)
level: medium
```

| Compile | Confidence |
|---------|------------|
| pass (sigma check + splunk) | medium |

---

#### 6. Mini Shai-Hulud GitHub Token Monitor Persistence

Detects the gh-token-monitor persistence mechanism (systemd service or macOS LaunchAgent) and malicious AI tool hooks planted by the Mini Shai-Hulud worm. Hook paths use `endswith` matching to avoid collisions with legitimate VS Code extension files that might contain `setup.mjs` in a deeper path.

<!-- revision: Changed selection_hooks from contains to endswith to prevent .vscode/setup.mjs from colliding with legitimate VS Code extension files. -->
<!-- Audit: sigma check passed (0 errors). sigma convert --without-pipeline -t splunk succeeded. -->

**File:** `rules/sigma/2026-06-21-teampcp-supply-chain.yml` (rule 5 of 7)

```yaml
title: TeamPCP Mini Shai-Hulud - GitHub Token Monitor Persistence
id: f6a7b8c9-d0e1-2345-fabc-456789012345
status: experimental
description: >
    Detects the gh-token-monitor persistence mechanism used by the Mini Shai-Hulud worm
    to poll for GitHub tokens every 60 seconds. Also detects malicious AI tool hooks
    (.claude/router_runtime.js and .vscode/setup.mjs) using endswith matching to avoid
    collisions with legitimate VS Code extension files.
references:
    - https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions
    - https://orca.security/resources/blog/tanstack-npm-supply-chain-worm/
author: Actioner CTI
date: 2026-06-21
tags:
    - attack.t1543.002
    - attack.t1543.004
logsource:
    category: file_event
detection:
    selection_systemd:
        TargetFilename|endswith: '/gh-token-monitor.service'
    selection_launchagent:
        TargetFilename|endswith: '/com.user.gh-token-monitor.plist'
    selection_hooks:
        TargetFilename|endswith:
            - '/.claude/router_runtime.js'
            - '/.vscode/setup.mjs'
    condition: selection_systemd or selection_launchagent or selection_hooks
falsepositives:
    - Unlikely, these are specific malware artifacts
level: high
```

| Compile | Confidence |
|---------|------------|
| pass (sigma check + splunk) | high |

---

#### 7. FIRESCALE Dead Drop via GitHub API

Detects proxy/web traffic containing the FIRESCALE dead-drop pattern in GitHub commit search API queries, used by TeamPCP for dynamic C2 resolution. The string "FIRESCALE" is a unique marker with no legitimate use.

<!-- Audit: sigma check passed (0 errors). sigma convert --without-pipeline -t splunk succeeded. -->

**File:** `rules/sigma/2026-06-21-teampcp-supply-chain.yml` (rule 6 of 7)

```yaml
title: TeamPCP Supply Chain Attack - FIRESCALE Dead Drop via GitHub API
id: a7b8c9d0-e1f2-3456-abcd-567890123456
status: experimental
description: Detects HTTP requests to the GitHub commit search API containing the FIRESCALE dead-drop pattern used by TeamPCP for C2 resolution.
references:
    - https://phoenix.security/teampcp-github-breach-durabletask-pypi-supply-chain-wave-four-2026/
author: Actioner CTI
date: 2026-06-21
tags:
    - attack.t1102.001
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains|all:
            - 'api.github.com/search/commits'
            - 'FIRESCALE'
    condition: selection
falsepositives:
    - Unlikely, FIRESCALE is a unique TeamPCP dead-drop marker
level: high
```

| Compile | Confidence |
|---------|------------|
| pass (sigma check + splunk) | high |

---

#### 8. Process Environment Variable Theft via /proc

Detects reading of /proc/PID/environ to steal runner secrets from CI/CD environments, a technique used by TeamPCP in compromised GitHub Actions workflows. Confidence lowered to low because the `|re` modifier has portability concerns across SIEM backends and the pattern is not TeamPCP-specific.

<!-- revision: Lowered confidence from medium to low. Noted |re portability concerns. Pattern is generic /proc environ access, not TeamPCP-specific. -->
<!-- Audit: sigma check passed (0 errors). sigma convert --without-pipeline -t splunk succeeded. -->

**File:** `rules/sigma/2026-06-21-teampcp-supply-chain.yml` (rule 7 of 7)

```yaml
title: TeamPCP Supply Chain Attack - Process Environment Variable Theft via /proc
id: b8c9d0e1-f2a3-4567-bcde-678901234567
status: experimental
description: >
    Detects reading of /proc/PID/environ to steal runner secrets from CI/CD environments,
    a technique used by TeamPCP in compromised GitHub Actions workflows. Confidence lowered
    to low because the |re modifier has portability concerns across SIEM backends and the
    pattern is not TeamPCP-specific.
references:
    - https://ramimac.me/teampcp/
    - https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/
author: Actioner CTI
date: 2026-06-21
tags:
    - attack.t1552.001
    - attack.t1057
logsource:
    category: file_access
    product: linux
detection:
    selection:
        TargetFilename|re: '/proc/\d+/environ'
    filter_main:
        Image|endswith:
            - '/systemd'
            - '/dockerd'
            - '/containerd'
    condition: selection and not filter_main
falsepositives:
    - Process monitoring tools
    - Container runtime introspection
    - The |re modifier may not be supported by all SIEM backends
level: low
```

| Compile | Confidence |
|---------|------------|
| pass (sigma check + splunk) | low |

---

### YARA Rules

#### 9. TeamPCP Mini Shai-Hulud Dropper

Detects TeamPCP dropper payloads based on known C2 domains, file artifacts, exfiltration repo names, and behavioral strings. Covers multiple campaign waves.

<!-- revision: Added filesize < 10MB constraint. Renamed non-standard reference2 meta key to reference_phoenix. -->
<!-- Audit: yarac compiled successfully (exit 0). -->

**File:** `rules/yara/2026-06-21-teampcp-supply-chain.yar` (rule: `TeamPCP_MiniShaiHulud_Dropper`)

| Compile | Confidence |
|---------|------------|
| pass (yarac) | high |

#### 10. TeamPCP DurableTask PyPI Dropper

Detects the specific DurableTask PyPI dropper that downloads rope.pyz from check[.]git-service[.]com to /tmp/managed.pyz with process detachment.

<!-- Audit: yarac compiled successfully (exit 0). -->

**File:** `rules/yara/2026-06-21-teampcp-supply-chain.yar` (rule: `TeamPCP_DurableTask_PyPI_Dropper`)

| Compile | Confidence |
|---------|------------|
| pass (yarac) | high |

#### 11. TeamPCP WAV Steganography

Detects WAV files containing TeamPCP steganographic payload markers. Requires WAV header at offset 0 plus at least two of three encryption markers (session.key, aes-256-cbc, payload.enc) for higher specificity.

<!-- revision: Changed condition from any of ($marker_*) to 2 of ($marker_*) for higher specificity. -->
<!-- Audit: yarac compiled successfully (exit 0). -->

**File:** `rules/yara/2026-06-21-teampcp-supply-chain.yar` (rule: `TeamPCP_WAV_Steganography`)

| Compile | Confidence |
|---------|------------|
| pass (yarac) | medium |

#### 12. TeamPCP Credential Harvester Script

Detects Python-based credential harvesting scripts that access multiple cloud credential paths combined with IMDS/Kubernetes API endpoints, exfiltration tooling, and at least one TeamPCP-specific string (C2 domain, unique filename). Without the TeamPCP-specific co-occurrence, matches are behavioral only and should be triaged manually.

<!-- revision: Added $teampcp_* string family (C2 domains, tpcp.tar.gz, pgmonitor) and required any of ($teampcp_*) in condition. Confidence raised to high when TeamPCP strings present; without them the rule no longer fires, eliminating behavioral-only matches. -->
<!-- Audit: yarac compiled successfully (exit 0). -->

**File:** `rules/yara/2026-06-21-teampcp-supply-chain.yar` (rule: `TeamPCP_Credential_Harvester_Script`)

| Compile | Confidence |
|---------|------------|
| pass (yarac) | high |

---

### Snort Rules

#### 13-20. TeamPCP C2 Domain and Payload Detection (8 rules)

Eight Snort 2.x rules detecting HTTP traffic to TeamPCP C2 domains (check[.]git-service[.]com, scan[.]aquasecurtiy[.]org, checkmarx[.]zone, models[.]litellm[.]cloud, git-tanstack[.]com, t[.]m-kosche[.]com), rope.pyz payload downloads, and FIRESCALE dead-drop traffic. SIDs 2026062101-2026062108.

<!-- revision: Rules 1-6 and 8 now anchor domain matching to the Host header using content:"Host|3a 20|"; http_header; distance:0 instead of bare http_header content matches. Rule 7 (URI-only) unchanged. All rules bumped to rev:2. -->
<!-- Audit: snort -T validated configuration successfully. -->

**File:** `rules/snort/2026-06-21-teampcp-supply-chain.rules`

| Compile | Confidence |
|---------|------------|
| pass (snort -T) | high |

---

### Suricata Rules

#### 21-32. TeamPCP C2 Domain, Payload, and DNS Detection (12 rules)

Twelve Suricata rules covering HTTP host-based detection for six C2 domains, rope.pyz payload downloads, FIRESCALE dead-drop pattern, and DNS query detection for four key TeamPCP domains. SIDs 2026062201-2026062212.

<!-- Audit: suricata -T exited with "Configuration provided was successfully loaded. Exiting." -->

**File:** `rules/suricata/2026-06-21-teampcp-supply-chain.rules`

| Compile | Confidence |
|---------|------------|
| pass (suricata -T) | high |

---

## Detection Rule Summary

| # | Type | Title | Compile Status | Confidence |
|---|------|-------|---------------|------------|
| 1 | Sigma | TeamPCP C2 Domain DNS Lookups | pass | high |
| 2 | Sigma | TeamPCP C2 IP Address Connections | pass | medium |
| 3 | Sigma | Persistence via Fake PostgreSQL Service | pass | medium |
| ~~4~~ | ~~Sigma~~ | ~~Credential File Access by Python~~ | ~~dropped~~ | ~~n/a~~ |
| 5 | Sigma | OpenSSL Encryption for Exfiltration | pass | medium |
| 6 | Sigma | Mini Shai-Hulud GitHub Token Monitor Persistence | pass | high |
| 7 | Sigma | FIRESCALE Dead Drop via GitHub API | pass | high |
| 8 | Sigma | Process Environment Variable Theft via /proc | pass | low |
| 9 | YARA | TeamPCP Mini Shai-Hulud Dropper | pass | high |
| 10 | YARA | TeamPCP DurableTask PyPI Dropper | pass | high |
| 11 | YARA | TeamPCP WAV Steganography | pass | medium |
| 12 | YARA | TeamPCP Credential Harvester Script | pass | high |
| 13-20 | Snort | TeamPCP C2 Domain & Payload Detection (8 rules) | pass | high |
| 21-32 | Suricata | TeamPCP C2 Domain, Payload & DNS Detection (12 rules) | pass | high |

---

## Recommendations

1. **Immediate lockfile audit**: Check all npm and PyPI lockfiles for the compromised package versions listed above; use `npm audit` and `pip-audit` with updated advisory databases.
2. **Credential rotation**: Any CI/CD environment that installed affected packages should rotate all credentials (cloud IAM, GitHub PATs, npm tokens, SSH keys, Kubernetes service account tokens).
3. **Network monitoring**: Deploy the Sigma/Snort/Suricata rules above to detect C2 communication to known TeamPCP infrastructure.
4. **File integrity monitoring**: Monitor for creation of gh-token-monitor.service, pgsql-monitor.service, router_runtime.js, and setup.mjs artifacts.
5. **GitHub Actions review**: Pin all third-party GitHub Actions to full commit SHAs rather than version tags; audit workflow run logs for unexpected modifications.
6. **OIDC token hardening**: Restrict GitHub Actions OIDC token audience claims and implement subject claim filtering to prevent token hijacking.

---

*Report revised 2026-06-21. All detection rules re-validated (sigma check, yarac, snort -T, suricata -T).*
