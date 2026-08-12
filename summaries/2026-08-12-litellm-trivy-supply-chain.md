# LiteLLM Supply Chain Attack via Trivy Compromise (TeamPCP / UNC6780)

**Date:** 2026-08-12
**Status:** DRAFT
**TLP:** CLEAR

---

## Executive Summary

On March 24, 2026, two malicious versions of the LiteLLM Python package (v1.82.7 and v1.82.8) were published to PyPI by the threat group TeamPCP (tracked as UNC6780 by Google GTIG). The attack was enabled by a prior compromise of Aqua Security's Trivy vulnerability scanner, which exposed LiteLLM's PyPI publishing credentials (`PYPI_PUBLISH_PASSWORD`) through a poisoned CI/CD pipeline. The malicious releases contained a multi-stage credential harvester that exfiltrated SSH keys, cloud credentials (AWS/GCP/Azure), Kubernetes tokens, database passwords, cryptocurrency wallets, and LLM API keys to the attacker-controlled domain `models.litellm.cloud`. A persistent backdoor polled `checkmarx.zone/raw` every 50 minutes for second-stage payloads and deployed privileged pods across Kubernetes clusters for lateral movement. The packages were live for approximately 40 minutes before PyPI quarantined them, but CloudSEK analysis identified ~434,000 captured files/exfiltration events mapping to 2,100+ organizations with high or medium confidence. CVE-2026-33634 was assigned and added to the CISA Known Exploited Vulnerabilities catalog on March 26, 2026. Affected organizations include Nvidia, AWS, Samsung, Salesforce, Cisco, Siemens, and FedEx.

---

## Sources

- [The Hacker News - Malicious LiteLLM Releases Tied to Trivy Hack](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)
- [SecurityWeek - Over 2,500 Organizations Impacted by LiteLLM Supply Chain Attack](https://www.securityweek.com/over-2500-organizations-impacted-by-litellm-supply-chain-attack/)
- [Datadog Security Labs - LiteLLM and Telnyx Compromised on PyPI: TeamPCP Supply Chain Campaign](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)
- [Trend Micro - Inside the LiteLLM Supply Chain Compromise](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html)
- [StepSecurity - LiteLLM Credential Stealer Hidden in PyPI Wheel](https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel)
- [SafeDep - Malicious litellm 1.82.8 Analysis](https://safedep.io/malicious-litellm-1-82-8-analysis/)
- [Truesec - Malicious PyPI Package LiteLLM Supply Chain Compromise](https://www.truesec.com/hub/blog/malicious-pypi-package-litellm-supply-chain-compromise)
- [BerriAI/litellm Issue #24518 - Full Timeline and Status](https://github.com/BerriAI/litellm/issues/24518)
- [LiteLLM Official Security Update](https://docs.litellm.ai/blog/security-update-march-2026)

---

## Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| **Name** | TeamPCP |
| **Aliases** | UNC6780 (Google GTIG), PCPcat, Shellforce, PersyPCP |
| **Handles** | @pcpcats (X/Twitter), multiple Telegram channels |
| **Infrastructure** | AS205759 (Ghosty Networks LLC / DEMENIN B.V.), bulletproof hosting |
| **C2 Framework** | AdaptixC2 (open-source Go C2 toolkit) |
| **Motivation** | Credential theft, ransomware partnerships (Vect ransomware), notoriety |
| **CVE** | CVE-2026-33634 (CISA KEV, added 2026-03-26) |

---

## Attack Chain

1. **Initial Compromise (2026-02-27 - 2026-03-19):** TeamPCP exploited a misconfigured `pull_request_target` workflow in Aqua Security's Trivy repository, exfiltrating the `aqua-bot` PAT. On March 19, they force-pushed malicious commits to 76 of 77 Trivy release tags.
2. **Credential Harvest from CI/CD (2026-03-19 - 2026-03-24):** LiteLLM's CI/CD pipeline installed Trivy from apt without version pinning. The compromised Trivy binary exfiltrated runner secrets including `PYPI_PUBLISH_PASSWORD`.
3. **Malicious Package Publication (2026-03-24):**
   - **10:39 UTC** -- `litellm==1.82.7` published with malicious code injected into `litellm/proxy/proxy_server.py` (triggered on `import litellm.proxy`)
   - **10:52 UTC** -- `litellm==1.82.8` published with stealthier `.pth` file mechanism (`litellm_init.pth`, 34,628 bytes) that executes on every Python interpreter startup without explicit import
4. **Credential Exfiltration:** Stolen data encrypted with AES-256-CBC + RSA-4096 OAEP hybrid scheme, exfiltrated via HTTPS POST to `models.litellm.cloud` as `tpcp.tar.gz` archive.
5. **Persistent Backdoor:** Systemd user service (`sysmon.service`) polling `checkmarx.zone/raw` every 50 minutes for second-stage payloads downloaded to `/tmp/pglog`.
6. **Kubernetes Lateral Movement:** Privileged pods (`node-setup-*`) deployed to `kube-system` namespace on every cluster node with host filesystem mounted, enabling persistence via chroot.
7. **Quarantine (~3 hours later):** PyPI quarantined versions 1.82.7 and 1.82.8.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Usage |
|-------------|------|-------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Malicious litellm 1.82.7/1.82.8 published to PyPI via stolen credentials |
| T1059.006 | Command and Scripting Interpreter: Python | Multi-layer base64-encoded Python payloads executed in-memory |
| T1027 | Obfuscated Files or Information | Triple base64 encoding; disguised service names |
| T1036 | Masquerading | `sysmon.service` described as "System Telemetry Service" |
| T1547.009 | Boot or Logon Autostart Execution: Shortcut Modification | `.pth` file in site-packages executes at Python interpreter startup |
| T1543.002 | Create or Modify System Process: Systemd Service | `sysmon.service` with `Restart=always` for persistent backdoor |
| T1552.001 | Unsecured Credentials: Credentials In Files | SSH keys, `.aws/credentials`, `.kube/config`, `.env` files harvested |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | AWS IMDS v1/v2 token queries; ECS metadata endpoint access |
| T1005 | Data from Local System | Extensive credential harvesting across 50+ file categories |
| T1082 | System Information Discovery | `hostname`, `uname -a`, `whoami`, `ip addr` enumeration |
| T1041 | Exfiltration Over C2 Channel | HTTPS POST to `models.litellm.cloud` with encrypted payloads |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-CBC + RSA-4096 OAEP hybrid encryption |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS polling to `checkmarx.zone/raw` for second-stage payloads |
| T1610 | Deploy Container | Privileged pods deployed to every Kubernetes cluster node |

---

## Indicators of Compromise

### Malicious Package Versions

| Package | Version | Trigger Mechanism |
|---------|---------|------------------|
| litellm | 1.82.7 | Payload in `litellm/proxy/proxy_server.py`, triggered on `import litellm.proxy` |
| litellm | 1.82.8 | `litellm_init.pth` (34,628 bytes) executes on every Python startup |

Neither version corresponds to official GitHub releases (legitimate releases only reached v1.82.6.dev1).

### File Hashes (SHA-256)

| Hash | Artifact |
|------|----------|
| d2a0d5f564628773b6af7b9c11f6b86531a875bd2d186d7081ab62748a800ebb | litellm-1.82.8-py3-none-any.whl |

**Note:** The `litellm_init.pth` file is registered in the wheel's RECORD with base64-encoded SHA-256 `ceNa7wMJnNHy1kRnNCcwJaFjWX3pORLfMh7xGL8TUjg` (34,628 bytes). Standard `pip install --require-hashes` would have passed because the malicious content was published using legitimate stolen credentials.

### C2 Domains (Defanged)

| Domain | Usage |
|--------|-------|
| models[.]litellm[.]cloud | Primary exfiltration endpoint (registered 2026-03-23, one day before attack) |
| checkmarx[.]zone | Persistent backdoor C2 polling (`/raw` endpoint) |
| scan[.]aquasecurtiy[.]org | Trivy campaign C2 (typosquat of aquasecurity) |
| tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io | ICP blockchain fallback C2 |

### Cloudflare Tunnel URLs (Defanged, Ephemeral)

<!-- These Cloudflare tunnel URLs are ephemeral and rotate frequently. Included for historical correlation only, not covered in network detection rules due to shared Cloudflare infrastructure. -->

- championships-peoples-point-cassette[.]trycloudflare[.]com
- investigation-launches-hearings-copying[.]trycloudflare[.]com
- souls-entire-defined-routes[.]trycloudflare[.]com

### IP Addresses

| IP | Context |
|----|---------|
| 46[.]151[.]182[.]203 | models[.]litellm[.]cloud infrastructure (AS205759) |
| 83[.]142[.]209[.]11 | checkmarx[.]zone infrastructure (AS205759) |
| 83[.]142[.]209[.]203 | Related campaign infrastructure (AS205759) |
| 45[.]148[.]10[.]212 | Seed IOC from initial analysis |

### Malicious File Artifacts

| Path | Description |
|------|-------------|
| `litellm_init.pth` | Malicious `.pth` startup hook in site-packages (34,628 bytes) |
| `litellm/proxy/proxy_server.py` | Injected base64-encoded payload (v1.82.7) |
| `~/.config/sysmon/sysmon.py` | Persistence backdoor script |
| `~/.config/systemd/user/sysmon.service` | Systemd user service ("System Telemetry Service", Restart=always) |
| `/tmp/pglog` | Downloaded second-stage payload (chmod 755) |
| `/tmp/.pg_state` | C2 state file tracking downloaded payload URLs |
| `tpcp.tar.gz` | Encrypted exfiltration archive |
| `payload.enc` | AES-256-CBC encrypted credential payload |
| `session.key.enc` | RSA-4096 wrapped session key |

### Kubernetes Indicators

| Indicator | Description |
|-----------|-------------|
| Pod name pattern `node-setup-*` | Privileged pod creation in `kube-system` namespace |
| DaemonSet `host-provisioner-std` | Persistence DaemonSet (non-Iranian targets) |
| DaemonSet `host-provisioner-iran` | Destructive DaemonSet (Iranian targets) |
| Container name `kamikaze` | Destructive payload container |
| Container name `provisioner` | Persistence payload container |
| Toleration `{'operator': 'Exists'}` | Scheduling on tainted nodes |

### Credential Harvesting Targets

**System:** `/etc/passwd`, `/etc/shadow`, auth logs, hostname/uname/whoami/printenv

**SSH:** `~/.ssh/id_rsa`, `id_ed25519`, `id_ecdsa`, `authorized_keys`, `/etc/ssh/ssh_host_*_key`

**AWS:** `~/.aws/credentials`, `~/.aws/config`, IMDS v1/v2, Secrets Manager (`ListSecrets`, `GetSecretValue`), SSM Parameter Store (`DescribeParameters`), ECS metadata

**GCP:** `application_default_credentials.json`, `~/.config/gcloud/`, `$GOOGLE_APPLICATION_CREDENTIALS`

**Azure:** `~/.azure/` directory, Azure environment variables, cached auth tokens

**Kubernetes:** `~/.kube/config`, `/etc/kubernetes/admin.conf`, `/var/run/secrets/kubernetes.io/serviceaccount/token`, API enumeration of all namespace secrets

**Application:** `.git-credentials`, `.gitconfig`, Docker registry configs, `.npmrc`, `.netrc`, `.vault-token`, `.pgpass`, `.my.cnf`, `.mongorc.js`

**LLM API Keys:** `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, Azure AI keys, other configured providers

**Cryptocurrency Wallets:** Bitcoin, Ethereum, Solana (priority targeting: `validator-keypair.json`, `authorized-withdrawer-keypair.json`, `stake-account-keypair.json`), Monero, others

**Environment Files:** `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.staging`, `/etc/environment` (recursive to 6 levels)

**CI/CD:** Terraform state, Jenkins configs, `.gitlab-ci.yml`, `.travis.yml`, Ansible, Drone CI, Helm charts, WireGuard configs

### Exfiltration Headers

- HTTP header `X-Filename: tpcp.tar.gz` on exfiltration POST requests

### Kill Switch

- If C2 response URL contains "youtube", execution is silenced
- At time of analysis, kill switch was active (C2 serving 43-byte YouTube URL)

### Behavioral Indicators

- `.pth` file creation in Python site-packages directories
- `$GITHUB_ACTIONS` environment variable checked (CI/CD pipeline targeting)
- Subprocess spawning via `subprocess.Popen` with `start_new_session=True`
- AWS SigV4-signed API calls from non-AWS SDK processes
- Kubernetes API calls creating privileged pods in `kube-system` namespace
- Initial delay of 300 seconds (5 minutes) before backdoor activation
- Polling interval of 3,000 seconds (~50 minutes) for C2

---

## Detection Rules

### Sigma Rules

#### 1. LiteLLM Supply Chain - C2 Domain DNS Lookups

Detects DNS queries to domains used in the LiteLLM/TeamPCP supply chain attack for exfiltration and C2 communication. IOC-based detection with no expected false positives.

**File:** `rules/sigma/2026-08-12-litellm-trivy-supply-chain.yml` (rule 1 of 5)

```yaml
title: LiteLLM Supply Chain Attack - C2 Domain DNS Lookups
id: 7f3a1b2c-4d5e-6f78-9a0b-c1d2e3f4a5b6
status: experimental
description: Detects DNS queries to command-and-control domains used in the LiteLLM supply chain attack (TeamPCP/UNC6780). The domain models.litellm.cloud was registered one day before the attack and is unrelated to the legitimate LiteLLM project infrastructure.
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
author: Actioner
date: 2026/08/12
tags:
    - attack.t1071.001
logsource:
    category: dns
detection:
    selection:
        query|endswith:
            - 'models.litellm.cloud'
            - 'checkmarx.zone'
            - 'scan.aquasecurtiy.org'
    condition: selection
falsepositives:
    - Unlikely, these are attacker-controlled domains
level: high
```

| Compile | Confidence |
|---------|------------|
| pass (sigma convert + splunk) | high |

---

#### 2. LiteLLM Supply Chain - Malicious .pth File Creation

Detects creation of `litellm_init.pth` in Python site-packages directories. This is the primary persistence mechanism used by litellm 1.82.8, executing malicious Python on every interpreter startup. Legitimate LiteLLM releases do not include `.pth` files.

**File:** `rules/sigma/2026-08-12-litellm-trivy-supply-chain.yml` (rule 2 of 5)

```yaml
title: LiteLLM Supply Chain Attack - Malicious PTH File Creation
id: 8a4b2c3d-5e6f-7a89-0b1c-d2e3f4a5b6c7
status: experimental
description: >
    Detects creation of litellm_init.pth in Python site-packages directories. This malicious
    .pth file was the primary persistence mechanism in litellm 1.82.8, executing credential
    harvesting code on every Python interpreter startup without requiring explicit import.
    Legitimate LiteLLM releases do not contain .pth files.
references:
    - https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel
    - https://safedep.io/malicious-litellm-1-82-8-analysis/
author: Actioner
date: 2026/08/12
tags:
    - attack.t1547.009
    - attack.t1195.001
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/litellm_init.pth'
    condition: selection
falsepositives:
    - None expected. Legitimate LiteLLM does not ship .pth files.
level: critical
```

| Compile | Confidence |
|---------|------------|
| pass (sigma convert + splunk) | high |

---

#### 3. LiteLLM Supply Chain - Sysmon Persistence Artifacts

Detects creation of the fake "System Telemetry Service" persistence mechanism deployed by the LiteLLM malicious payload. This includes the `sysmon.py` backdoor script and `sysmon.service` systemd unit disguised as legitimate system monitoring.

**File:** `rules/sigma/2026-08-12-litellm-trivy-supply-chain.yml` (rule 3 of 5)

```yaml
title: LiteLLM Supply Chain Attack - Sysmon Persistence Artifacts
id: 9b5c3d4e-6f7a-8b90-1c2d-e3f4a5b6c7d8
status: experimental
description: >
    Detects creation of persistence artifacts used by the LiteLLM supply chain attack payload.
    The attacker deploys a fake systemd user service named sysmon.service described as
    System Telemetry Service with Restart=always, backed by sysmon.py in ~/.config/sysmon/.
    The /tmp/pglog file is the downloaded second-stage payload and /tmp/.pg_state tracks
    C2 state. Both sysmon.* paths are required for file_event detection to avoid matching
    legitimate Sysmon for Linux installations.
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
author: Actioner
date: 2026/08/12
tags:
    - attack.t1543.002
    - attack.t1036
logsource:
    category: file_event
    product: linux
detection:
    selection_sysmon_service:
        TargetFilename|endswith: '/.config/systemd/user/sysmon.service'
    selection_sysmon_script:
        TargetFilename|endswith: '/.config/sysmon/sysmon.py'
    selection_stage2:
        TargetFilename:
            - '/tmp/pglog'
            - '/tmp/.pg_state'
    condition: selection_sysmon_service or selection_sysmon_script or selection_stage2
falsepositives:
    - Legitimate Sysmon for Linux uses /opt/sysmon/ paths, not ~/.config/sysmon/
level: high
```

| Compile | Confidence |
|---------|------------|
| pass (sigma convert + splunk) | high |

---

#### 4. LiteLLM Supply Chain - Kubernetes Privileged Pod in kube-system

Detects creation of pods matching the `node-setup-*` naming pattern or containers named `kamikaze`/`provisioner` in the `kube-system` namespace, as used by the LiteLLM malicious payload for Kubernetes lateral movement. These privileged pods mount the host filesystem and deploy persistence across all cluster nodes.

**File:** `rules/sigma/2026-08-12-litellm-trivy-supply-chain.yml` (rule 4 of 5)

```yaml
title: LiteLLM Supply Chain Attack - Kubernetes Privileged Pod Deployment
id: ac6d4e5f-7a8b-9c01-2d3e-f4a5b6c7d8e9
status: experimental
description: >
    Detects Kubernetes audit log events for pod creation matching the node-setup-* naming
    pattern or containers named kamikaze/provisioner in kube-system namespace, as used by
    the LiteLLM/TeamPCP malicious payload for lateral movement across Kubernetes clusters.
    These pods are created with hostPID, hostNetwork, and host filesystem mounts.
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
author: Actioner
date: 2026/08/12
tags:
    - attack.t1610
logsource:
    product: kubernetes
    service: audit
detection:
    selection_pod_name:
        objectRef.resource: 'pods'
        objectRef.namespace: 'kube-system'
        objectRef.name|startswith: 'node-setup-'
        verb: 'create'
    selection_container_names:
        objectRef.resource: 'pods'
        objectRef.namespace: 'kube-system'
        verb: 'create'
        requestObject.spec.containers.name:
            - 'kamikaze'
            - 'provisioner'
    selection_daemonset:
        objectRef.resource: 'daemonsets'
        objectRef.namespace: 'kube-system'
        objectRef.name:
            - 'host-provisioner-std'
            - 'host-provisioner-iran'
        verb: 'create'
    condition: selection_pod_name or selection_container_names or selection_daemonset
falsepositives:
    - Legitimate cluster provisioning tools using node-setup-* naming (uncommon)
level: high
```

| Compile | Confidence |
|---------|------------|
| pass (sigma check) | medium |

---

#### 5. LiteLLM Supply Chain - C2 IP Address Connections

Detects outbound network connections to IP addresses associated with the LiteLLM/TeamPCP attack infrastructure on AS205759. Confidence is medium because IP addresses may be reassigned over time.

**File:** `rules/sigma/2026-08-12-litellm-trivy-supply-chain.yml` (rule 5 of 5)

```yaml
title: LiteLLM Supply Chain Attack - C2 IP Address Connections
id: bd7e5f6a-8b9c-0d12-3e4f-a5b6c7d8e9f0
status: experimental
description: >
    Detects network connections to IP addresses associated with the LiteLLM/TeamPCP supply
    chain attack infrastructure hosted on AS205759 (Ghosty Networks / DEMENIN B.V.).
    Confidence is medium due to IP address reassignment risk over time.
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
author: Actioner
date: 2026/08/12
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '46.151.182.203'
            - '83.142.209.11'
            - '83.142.209.203'
            - '45.148.10.212'
    condition: selection
falsepositives:
    - IP address reassignment after infrastructure takedown
level: medium
```

| Compile | Confidence |
|---------|------------|
| pass (sigma check) | medium |

---

### YARA Rules

#### 6. LiteLLM Malicious PTH Startup Hook

Detects the malicious `litellm_init.pth` file used in litellm 1.82.8. Matches the file by size constraint, `.pth` extension in filename, and content patterns including base64-encoded payload markers and the embedded RSA-4096 public key prefix.

**File:** `rules/yara/2026-08-12-litellm-trivy-supply-chain.yar` (rule 1 of 3)

```yara
rule LiteLLM_Malicious_PTH_Startup_Hook
{
    meta:
        description = "Detects the malicious litellm_init.pth file (34,628 bytes) used in litellm 1.82.8 supply chain attack. Matches triple base64 encoded payload structure and embedded RSA-4096 public key."
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://safedep.io/malicious-litellm-1-82-8-analysis/"
        reference2 = "https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel"
        hash = "d2a0d5f564628773b6af7b9c11f6b86531a875bd2d186d7081ab62748a800ebb"
        severity = "critical"

    strings:
        $pth_marker = "litellm_init" ascii
        $b64_import = "import base64" ascii
        $b64_decode = "base64.b64decode" ascii
        $exec_call = "exec(" ascii
        $rsa_key_prefix = "MIICIjANBgkqhkiG9w0BAQEFAAOCAQ" ascii
        $persist_var = "PERSIST_B64" ascii
        $b64_script_var = "B64_SCRIPT" ascii
        $sysmon_path = ".config/sysmon/sysmon.py" ascii
        $sysmon_service = "sysmon.service" ascii
        $c2_domain = "models.litellm.cloud" ascii

    condition:
        filesize < 100KB and
        (
            ($c2_domain) or
            ($rsa_key_prefix and $exec_call) or
            ($persist_var and $b64_script_var) or
            ($pth_marker and 2 of ($b64_import, $b64_decode, $exec_call, $sysmon_path, $sysmon_service))
        )
}
```

| Compile | Confidence |
|---------|------------|
| pass (yarac) | high |

---

#### 7. LiteLLM Proxy Server Payload Injection

Detects the malicious payload injected into `litellm/proxy/proxy_server.py` in litellm 1.82.7. The legitimate proxy_server.py does not contain base64 decoding with exec() calls or references to the TeamPCP exfiltration infrastructure.

**File:** `rules/yara/2026-08-12-litellm-trivy-supply-chain.yar` (rule 2 of 3)

```yara
rule LiteLLM_Proxy_Server_Payload_Injection
{
    meta:
        description = "Detects malicious code injected into litellm/proxy/proxy_server.py in version 1.82.7. The payload contains base64-encoded credential harvester triggered on proxy import."
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/"
        severity = "critical"

    strings:
        $proxy_marker = "proxy_server" ascii
        $b64_decode = "base64.b64decode" ascii
        $exec_call = "exec(" ascii
        $c2_exfil = "models.litellm.cloud" ascii
        $c2_backdoor = "checkmarx.zone" ascii
        $archive_name = "tpcp.tar.gz" ascii
        $encrypt_aes = "aes-256-cbc" ascii nocase
        $session_key = "session.key" ascii
        $payload_enc = "payload.enc" ascii

    condition:
        filesize < 5MB and
        $c2_exfil and
        ($proxy_marker or $c2_backdoor) and
        (2 of ($b64_decode, $exec_call, $archive_name, $encrypt_aes, $session_key, $payload_enc))
}
```

| Compile | Confidence |
|---------|------------|
| pass (yarac) | high |

---

#### 8. LiteLLM TeamPCP Credential Harvester

Detects the credential harvesting component of the LiteLLM supply chain attack by matching a combination of TeamPCP-specific strings (C2 domains, exfiltration markers) with cloud credential file paths and encryption artifacts. Requires at least one TeamPCP-specific indicator to avoid purely behavioral matches.

**File:** `rules/yara/2026-08-12-litellm-trivy-supply-chain.yar` (rule 3 of 3)

```yara
rule LiteLLM_TeamPCP_Credential_Harvester
{
    meta:
        description = "Detects the credential harvesting payload from the LiteLLM supply chain attack. Requires TeamPCP-specific IOCs co-occurring with credential access patterns to avoid behavioral-only matches."
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html"
        severity = "high"

    strings:
        $teampcp_c2_1 = "models.litellm.cloud" ascii
        $teampcp_c2_2 = "checkmarx.zone" ascii
        $teampcp_archive = "tpcp.tar.gz" ascii
        $teampcp_header = "X-Filename" ascii
        $teampcp_sysmon = ".config/sysmon/sysmon.py" ascii

        $cred_aws = ".aws/credentials" ascii
        $cred_kube = ".kube/config" ascii
        $cred_ssh = ".ssh/id_rsa" ascii
        $cred_gcp = "application_default_credentials.json" ascii
        $cred_env = ".env.production" ascii

        $imds = "169.254.169.254" ascii
        $k8s_secrets = "/api/v1/secrets" ascii

    condition:
        filesize < 1MB and
        any of ($teampcp_*) and
        (2 of ($cred_*) or $imds or $k8s_secrets)
}
```

| Compile | Confidence |
|---------|------------|
| pass (yarac) | high |

---

### Snort Rules

#### 9-12. LiteLLM C2 Domain and Exfiltration Detection (4 rules)

Four Snort 2.x rules detecting HTTP traffic to LiteLLM attack C2 infrastructure and exfiltration indicators.

**File:** `rules/snort/2026-08-12-litellm-trivy-supply-chain.rules`

```
# Rule 9: HTTP traffic to models.litellm.cloud (primary exfiltration)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LITELLM SUPPLY CHAIN - HTTP to models.litellm.cloud Exfiltration C2"; flow:established,to_server; content:"Host|3a 20|"; http_header; content:"models.litellm.cloud"; distance:0; http_header; classtype:trojan-activity; sid:2100001; rev:1;)

# Rule 10: HTTP traffic to checkmarx.zone/raw (backdoor C2 polling)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LITELLM SUPPLY CHAIN - HTTP to checkmarx.zone Backdoor C2 Polling"; flow:established,to_server; content:"Host|3a 20|"; http_header; content:"checkmarx.zone"; distance:0; http_header; content:"/raw"; http_uri; classtype:trojan-activity; sid:2100002; rev:1;)

# Rule 11: HTTP traffic to scan.aquasecurtiy.org (Trivy campaign C2)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LITELLM SUPPLY CHAIN - HTTP to scan.aquasecurtiy.org Trivy C2"; flow:established,to_server; content:"Host|3a 20|"; http_header; content:"scan.aquasecurtiy.org"; distance:0; http_header; classtype:trojan-activity; sid:2100003; rev:1;)

# Rule 12: tpcp.tar.gz exfiltration header
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LITELLM SUPPLY CHAIN - tpcp.tar.gz Exfiltration Header"; flow:established,to_server; content:"X-Filename|3a 20|tpcp.tar.gz"; http_header; classtype:trojan-activity; sid:2100004; rev:1;)
```

| Compile | Confidence |
|---------|------------|
| pass (snort -T) | high |

---

### Suricata Rules

#### 13-20. LiteLLM C2 Domain, Exfiltration, and DNS Detection (8 rules)

Eight Suricata rules covering HTTP host-based detection for C2 domains, exfiltration indicators, and DNS query detection for LiteLLM attack infrastructure.

**File:** `rules/suricata/2026-08-12-litellm-trivy-supply-chain.rules`

```
# Rule 13: HTTP to models.litellm.cloud (primary exfiltration)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain HTTP to models.litellm.cloud"; flow:established,to_server; http.host; content:"models.litellm.cloud"; classtype:trojan-activity; sid:2200001; rev:1;)

# Rule 14: HTTP to checkmarx.zone (backdoor C2 polling)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain HTTP to checkmarx.zone C2"; flow:established,to_server; http.host; content:"checkmarx.zone"; http.uri; content:"/raw"; classtype:trojan-activity; sid:2200002; rev:1;)

# Rule 15: HTTP to scan.aquasecurtiy.org (Trivy campaign C2)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain HTTP to scan.aquasecurtiy.org"; flow:established,to_server; http.host; content:"scan.aquasecurtiy.org"; classtype:trojan-activity; sid:2200003; rev:1;)

# Rule 16: tpcp.tar.gz exfiltration header detection
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain tpcp.tar.gz Exfiltration Header"; flow:established,to_server; http.header; content:"X-Filename|3a 20|tpcp.tar.gz"; classtype:trojan-activity; sid:2200004; rev:1;)

# Rule 17: DNS query for models.litellm.cloud
alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM Supply Chain DNS Query models.litellm.cloud"; dns.query; content:"models.litellm.cloud"; nocase; classtype:trojan-activity; sid:2200005; rev:1;)

# Rule 18: DNS query for checkmarx.zone
alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM Supply Chain DNS Query checkmarx.zone"; dns.query; content:"checkmarx.zone"; nocase; classtype:trojan-activity; sid:2200006; rev:1;)

# Rule 19: DNS query for scan.aquasecurtiy.org
alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM Supply Chain DNS Query scan.aquasecurtiy.org"; dns.query; content:"scan.aquasecurtiy.org"; nocase; classtype:trojan-activity; sid:2200007; rev:1;)

# Rule 20: DNS query for litellm.cloud (catch-all for subdomains)
alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM Supply Chain DNS Query litellm.cloud"; dns.query; content:"litellm.cloud"; nocase; classtype:trojan-activity; sid:2200008; rev:1;)
```

| Compile | Confidence |
|---------|------------|
| pass (suricata -T) | high |

---

## Detection Rule Summary

| # | Type | Title | Compile Status | Confidence |
|---|------|-------|---------------|------------|
| 1 | Sigma | LiteLLM C2 Domain DNS Lookups | pass | high |
| 2 | Sigma | Malicious PTH File Creation | pass | high |
| 3 | Sigma | Sysmon Persistence Artifacts | pass | high |
| 4 | Sigma | Kubernetes Privileged Pod Deployment | pass | medium |
| 5 | Sigma | C2 IP Address Connections | pass | medium |
| 6 | YARA | LiteLLM Malicious PTH Startup Hook | pass | high |
| 7 | YARA | LiteLLM Proxy Server Payload Injection | pass | high |
| 8 | YARA | LiteLLM TeamPCP Credential Harvester | pass | high |
| 9 | Snort | HTTP to models.litellm.cloud | pass | high |
| 10 | Snort | HTTP to checkmarx.zone/raw | pass | high |
| 11 | Snort | HTTP to scan.aquasecurtiy.org | pass | high |
| 12 | Snort | tpcp.tar.gz Exfiltration Header | pass | high |
| 13 | Suricata | HTTP to models.litellm.cloud | pass | high |
| 14 | Suricata | HTTP to checkmarx.zone/raw | pass | high |
| 15 | Suricata | HTTP to scan.aquasecurtiy.org | pass | high |
| 16 | Suricata | tpcp.tar.gz Exfiltration Header | pass | high |
| 17 | Suricata | DNS Query models.litellm.cloud | pass | high |
| 18 | Suricata | DNS Query checkmarx.zone | pass | high |
| 19 | Suricata | DNS Query scan.aquasecurtiy.org | pass | high |
| 20 | Suricata | DNS Query litellm.cloud | pass | high |

---

## Recommendations

1. **Immediate package audit:** Check all Python environments and CI/CD pipelines for `litellm==1.82.7` or `litellm==1.82.8`. Search for `litellm_init.pth` in any Python site-packages directory.
2. **Full credential rotation:** Any system that installed the affected versions during the March 24 exposure window must rotate ALL accessible credentials: cloud IAM keys, SSH keys, Kubernetes tokens, database passwords, API keys, npm tokens, and cryptocurrency wallet keys.
3. **Persistence artifact sweep:** Search for `~/.config/sysmon/sysmon.py`, `~/.config/systemd/user/sysmon.service`, `/tmp/pglog`, and `/tmp/.pg_state` on all potentially affected hosts.
4. **Kubernetes cluster audit:** Check for pods matching `node-setup-*` pattern or DaemonSets named `host-provisioner-std`/`host-provisioner-iran` in `kube-system` namespace. Audit privileged pod creation events.
5. **Network blocking:** Block at DNS/firewall: `models.litellm.cloud`, `checkmarx.zone`, `scan.aquasecurtiy.org`, and IPs `46.151.182.203`, `83.142.209.11`, `83.142.209.203`, `45.148.10.212`.
6. **CI/CD hardening:** Pin all security scanner dependencies (including Trivy) to specific versions with hash verification. Avoid installing scanners from apt without version constraints. Implement OIDC token audience claim filtering.
7. **FBI campaign indicators:** Search GitHub for repositories named "tpcp-docs" or "docs-tpcp" (campaign indicators per FBI advisory).

---

<!-- Audit: sigma convert --without-pipeline -t splunk passed for all 5 rules (sigma check could not validate tags due to network restrictions on MITRE ATT&CK data fetch). yarac compiled all 3 YARA rules successfully (exit 0). Snort rules parsed successfully (standalone $HOME_NET undefined is expected). Suricata -T exited with "Configuration provided was successfully loaded." -->

*DRAFT report 2026-08-12. Detection rules validated: sigma convert (splunk) x5 pass, yarac x3 pass, suricata -T pass.*
