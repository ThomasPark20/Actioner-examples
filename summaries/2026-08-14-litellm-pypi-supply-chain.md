# Technical Analysis Report: TeamPCP LiteLLM PyPI Supply Chain Attack (2026-08-14)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-14
Version: 1.1

## Executive Summary

On March 24, 2026, the threat actor group tracked by Google as UNC6780 (self-identified as "TeamPCP") published two poisoned releases of the widely-used LiteLLM AI proxy library (versions 1.82.7 and 1.82.8) to the Python Package Index (PyPI). The malicious packages contained a multi-stage credential-stealing payload that harvested SSH keys, cloud credentials (AWS, GCP, Azure), Kubernetes tokens, database passwords, cryptocurrency wallet files, and LLM API keys from over 50 categories of secrets. Data was encrypted with AES-256-CBC/RSA-4096-OAEP hybrid encryption and exfiltrated to the attacker-controlled domain `models[.]litellm[.]cloud`. The packages were live for approximately 2 hours and 32 minutes before PyPI quarantined them, during which they accumulated over 119,000 downloads. CloudSEK's analysis of roughly 434,000 captured files maps potential exposure to over 2,500 organizations, including NVIDIA, Cisco, Deloitte, Volkswagen, FedEx, and Siemens. The attack is the second stage of a broader supply chain campaign that began with the compromise of Aqua Security's Trivy scanner via incomplete credential rotation, which yielded the PyPI publishing token used to upload the malicious LiteLLM releases. CVE-2026-33634 (CVSS4B 9.4) was assigned and added to CISA's Known Exploited Vulnerabilities catalog on March 26, 2026. The FBI issued FLASH-20260702-01 warning of active weaponization of stolen credentials.

## Background: LiteLLM

LiteLLM is an open-source Python library maintained by BerriAI that provides a unified interface for calling over 100 LLM APIs (OpenAI, Anthropic, Azure, AWS Bedrock, etc.) through a single proxy gateway. It is widely used in enterprise AI/ML infrastructure as a centralization layer for LLM API key management, cost tracking, and rate limiting. With approximately 15-20 million weekly downloads on PyPI and deployment across CI/CD pipelines, Kubernetes clusters, and cloud environments, compromise of this package provides immediate access to high-value credential stores. The library's typical deployment context -- handling API keys, running in privileged CI environments, and operating alongside cloud orchestration tools -- made it an exceptionally high-value target for credential theft.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-12 (approx.) | TeamPCP develops pcpcat.py v1, early credential harvesting tooling |
| 2026-03-19 | TeamPCP force-pushes malicious commits to 76 of 77 Trivy-action GitHub Actions tags; publishes malicious Trivy 0.69.4 binary |
| 2026-03-19 | Compromised Trivy-action executes in CI/CD pipelines, harvesting runner environment variables including PyPI publishing tokens |
| 2026-03-23 | Attacker registers `models[.]litellm[.]cloud` domain for exfiltration |
| 2026-03-24 10:39 | Malicious LiteLLM 1.82.7 and 1.82.8 published to PyPI using stolen publishing token |
| 2026-03-24 11:58 | First community report of anomalous behavior (fork bomb / CPU at 100%) |
| 2026-03-24 ~13:10 | PyPI quarantines malicious versions |
| 2026-03-24 16:00 | PyPI confirms full remediation; all installations up to this time considered suspect |
| 2026-03-26 | CVE-2026-33634 added to CISA Known Exploited Vulnerabilities catalog |
| 2026-04-02 | PyPI publishes incident report (PYSEC-2026-2) |
| 2026-07-02 | FBI issues FLASH-20260702-01 advisory warning of credential weaponization |
| 2026-08-12 | Malicious versions confirmed removed from PyPI release history |

## Root Cause: Trivy CI/CD Credential Theft Leading to PyPI Token Compromise

The attack chain originated from incomplete credential rotation after the Aqua Security Trivy scanner compromise. TeamPCP gained access to Trivy's GitHub repository and force-pushed malicious commits to 76 of 77 release tags for the `aquasecurity/trivy-action` GitHub Action. When LiteLLM's CI/CD pipeline ran with the compromised Trivy action, the malicious code harvested environment variables from the CI runner process, including the PyPI API token used to publish LiteLLM releases. The attackers specifically targeted `Runner.Worker` and `Runner.Listener` process memory, plus environment variables and CI configuration files (`.env`, `.json`, `.yml`). With the stolen PyPI token in hand, the attacker published two backdoored LiteLLM versions (1.82.7 and 1.82.8) to PyPI, completing the second stage of the supply chain attack.

## Technical Analysis of the Malicious Payload

### 1. Initial Delivery: Malicious PyPI Package

**Version 1.82.7** injected a base64-encoded malicious payload into `litellm/proxy/proxy_server.py`, which executed when the LiteLLM proxy server was imported or started.

**Version 1.82.8** introduced a more aggressive delivery mechanism: `litellm_init.pth` (34,628 bytes, SHA-256: `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238`). Python `.pth` files placed in `site-packages` are executed automatically at interpreter startup, meaning the malicious code ran on every Python process in the affected environment, regardless of whether LiteLLM was explicitly imported.

The payload used three layers of encoding:
- **Layer 0 (Launcher):** Single Python line spawning a subprocess to avoid blocking the interpreter
- **Layer 1 (Orchestrator):** RSA key management, encryption pipeline initialization, and subprocess orchestration
- **Layer 2 (Collector):** Comprehensive credential harvesting across 50+ secret categories

### 2. Credential Harvesting (Layer 2)

The collector module systematically targeted:

- **SSH keys:** `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, and all key files
- **Cloud credentials:** AWS (`~/.aws/credentials`, Secrets Manager, SSM Parameter Store via IMDSv2), GCP (`application_default_credentials.json`), Azure (`~/.azure/`)
- **Kubernetes:** Service account tokens, kubeconfig files, secrets enumeration across all namespaces
- **Database credentials:** MySQL, PostgreSQL, MongoDB, Redis, HashiCorp Vault
- **CI/CD secrets:** Terraform state files, GitLab CI configs, Jenkins credentials, Ansible vault
- **API keys:** Environment variables including `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and Azure AI keys
- **Cryptocurrency wallets:** Bitcoin, Ethereum, Solana validator keypairs, Cardano, Monero
- **Communication tokens:** Slack/Discord webhook tokens
- **System credentials:** `/etc/shadow` password hashes, Git credentials, npm publish tokens
- **Dotenv files:** `.env` files across 6 directory levels

For AWS environments, the payload included embedded SigV4 signing for authenticated API calls to Secrets Manager (`ListSecrets`, `GetSecretValue`) and SSM Parameter Store (`DescribeParameters`), plus EC2 Instance Metadata Service (IMDSv1 and IMDSv2 token) queries and ECS container metadata endpoint enumeration.

### 3. C2 Infrastructure

| Component | Value | Details |
|-----------|-------|---------|
| Primary exfil domain | `models[.]litellm[.]cloud` | Registered 2026-03-23, HTTPS POST exfiltration |
| C2 polling endpoint | `checkmarx[.]zone/raw` | GET requests every ~50 minutes (sysmon.py), ~5 minutes (pglog) |
| Trivy exfil domain | `scan[.]aquasecurtiy[.]org` | Typosquatted domain (note misspelling of "security") |
| Telnyx payload server | `83[.]142[.]209[.]203:8080` | WAV steganography payload delivery |
| Related infrastructure | `83[.]142[.]209[.]11` | `checkmarx[.]zone` host, AS205759 |
| Related infrastructure | `46[.]151[.]182[.]203` | `models[.]litellm[.]cloud` host, AS205759 |
| Cloudflare tunnels | `championships-peoples-point-cassette[.]trycloudflare[.]com` | Tunneled C2 |
| Cloudflare tunnels | `investigation-launches-hearings-copying[.]trycloudflare[.]com` | Tunneled C2 |
| ICP canister | `tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io` | Blockchain-backed fallback C2 |
| Fallback exfil | `tpcp-docs` / `docs-tpcp` GitHub repositories | Stolen data uploaded as release assets tagged `data-<timestamp>` |

**Encryption:** Harvested data was packaged as `tpcp.tar.gz`, encrypted with a random 32-byte AES-256-CBC session key (PBKDF2 derivation), and the session key was wrapped with a 4096-bit RSA public key (OAEP padding). The archive contained `payload.enc` + `session.key.enc`. The exfiltration POST included the header `X-Filename: tpcp.tar.gz`.

**Kill switch:** The C2 polling mechanism included a kill switch -- if the C2 response contained the string "youtube", the payload silently skipped execution, providing a pragmatic bypass for environments with network monitoring.

### 4. Platform-Specific Behavior

#### Linux (Primary Target)

**Persistence:** The payload installed a systemd user service masquerading as "System Telemetry Service":
- Backdoor script: `~/.config/sysmon/sysmon.py` (SHA-256: `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a`)
- Service unit: `~/.config/systemd/user/sysmon.service`
- Polling interval: ~50 minutes to `hxxps://checkmarx[.]zone/raw`
- State file: `/tmp/.pg_state`
- Second-stage binary: `/tmp/pglog`

#### Kubernetes Environments

The payload deployed privileged pods for lateral movement:
- Pod naming pattern: `node-setup-{node_name}`
- Container image: `alpine:latest`
- Privileges: `hostPID`, `hostNetwork` enabled; host filesystem mounted at `/host`
- Namespace: `kube-system`
- The pod used `chroot` to write backdoors to all cluster nodes
- Enumerated all secrets across all namespaces via Kubernetes API

**DaemonSet variants:**
- `host-provisioner-std` -- Standard persistence, mounted host filesystem
- `host-provisioner-iran` -- Iran-targeted variant that mounted host root and executed destructive wipe operations upon detecting Tehran timezone or Farsi language settings
- Container named `kamikaze` -- Destructive variant for Iranian targets

### 5. Anti-Forensics / Evasion Techniques

- **Multi-layer encoding:** Three layers of obfuscation (base64, subprocess spawning, encrypted communications)
- **Hybrid encryption:** AES-256-CBC + RSA-4096-OAEP prevents traffic inspection
- **Kill switch:** "youtube" string check in C2 response for network monitoring bypass
- **Process naming:** Persistence service named `sysmon.service` / "System Telemetry Service" to blend with legitimate monitoring
- **Staging file cleanup:** Temporary files in `/tmp/` with innocuous names (`pglog`, `.pg_state`)
- **Fork bomb side effect:** Resource exhaustion (CPU 100%, OOM) served as both a distraction and an early detection vector
- **Cloudflare tunnels and ICP canister:** Infrastructure diversity to resist takedown
- **Bulletproof hosting:** Infrastructure hosted on AS205759, resistant to abuse reports
- **"Back to the Future" timestamps:** October 26, 1985 timestamps in artifacts to complicate forensic timeline analysis

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing all dots (e.g., `83[.]142[.]209[.]203`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.82.7 | Base64-encoded payload injected into `proxy_server.py` |
| litellm (PyPI) | 1.82.8 | Malicious `litellm_init.pth` executing at Python startup |
| telnyx (PyPI) | 4.87.1, 4.87.2 | Related TeamPCP compromise, WAV steganography payload |
| aquasec/trivy (Docker) | 0.69.4, 0.69.5, 0.69.6 | Infected Trivy scanner binary |
| aquasecurity/trivy-action (GitHub) | 76 of 77 version tags | Force-pushed malicious commits |
| aquasecurity/setup-trivy (GitHub) | 0.2.0-0.2.6 | All 7 tags compromised |
| Checkmarx/kics-github-action | v1.1 | Compromised action |
| Checkmarx/ast-github-action | v2.3.28 | Compromised action |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `site-packages/litellm_init.pth` | `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238` | Malicious .pth startup hook (34,628 bytes) |
| Linux | `litellm/proxy/proxy_server.py` | `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b` | Modified proxy server (v1.82.7) |
| Linux | `~/.config/sysmon/sysmon.py` | `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a` | Persistent C2 polling backdoor |
| Linux | `~/.config/systemd/user/sysmon.service` | -- | Systemd persistence unit |
| Linux | `/tmp/tpcp.tar.gz` | -- | Exfiltration staging archive |
| Linux | `/tmp/payload.enc` | -- | AES-encrypted credential dump |
| Linux | `/tmp/session.key.enc` | -- | RSA-wrapped AES session key |
| Linux | `/tmp/session.key` | -- | Plaintext AES session key (pre-encryption) |
| Linux | `/tmp/.pg_state` | -- | C2 beacon state file |
| Linux | `/tmp/pglog` | -- | Downloaded second-stage executable |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `models[.]litellm[.]cloud` | Primary credential exfiltration endpoint (HTTPS POST) |
| Domain | `checkmarx[.]zone` | C2 polling server |
| URL Pattern | `hxxps://checkmarx[.]zone/raw` | C2 polling endpoint and second-stage payload delivery |
| Domain | `scan[.]aquasecurtiy[.]org` | Trivy credential exfiltration (typosquat) |
| Domain | `aquasecurtiy[.]org` | Typosquat of aquasecurity.org |
| IP | `83[.]142[.]209[.]203:8080` | Telnyx payload server (WAV steganography) |
| IP | `83[.]142[.]209[.]11` | checkmarx[.]zone host (AS205759) |
| IP | `46[.]151[.]182[.]203` | models[.]litellm[.]cloud host (AS205759) |
| Domain | `championships-peoples-point-cassette[.]trycloudflare[.]com` | Cloudflare tunnel C2 |
| Domain | `investigation-launches-hearings-copying[.]trycloudflare[.]com` | Cloudflare tunnel C2 |
| Domain | `souls-entire-defined-routes[.]trycloudflare[.]com` | Cloudflare tunnel C2 |
| Domain | `tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io` | ICP canister fallback C2 |
| HTTP Header | `X-Filename: tpcp.tar.gz` | Exfiltration header marker |

### Behavioral

- Python process creating `litellm_init.pth` in any site-packages directory
- Bulk reads of SSH keys + cloud credentials + crypto wallets from a single process
- `systemctl --user enable sysmon.service` execution
- DNS queries to `models[.]litellm[.]cloud` or `checkmarx[.]zone` from CI/CD runners
- Kubernetes API calls to enumerate secrets across all namespaces with `Python-urllib` User-Agent
- Privileged pod creation in `kube-system` namespace with `hostPID`/`hostNetwork` and names matching `node-setup-*`
- CloudTrail events for `GetSecretValue`, `ListSecrets`, `DescribeParameters` with `Python-urllib` User-Agent
- CPU at 100% / OOM errors in containers immediately after `pip install litellm`
- Creation of `~/.config/sysmon/` directory structure
- Outbound HTTPS POST containing encrypted archive to attacker infrastructure
- GitHub repositories prefixed with `tpcp-docs-` or named `docs-tpcp` containing release assets tagged `data-<timestamp>`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Poisoned LiteLLM PyPI packages 1.82.7/1.82.8 published via stolen publishing token |
| T1546 | Event Triggered Execution | `.pth` file executed at Python interpreter startup, running malicious code before any application logic |
| T1059.006 | Command and Scripting Interpreter: Python | Malicious payload executed via Python subprocess spawning and base64-decoded execution |
| T1543.002 | Create or Modify System Process: Systemd Service | sysmon.service installed as user systemd unit for persistent C2 polling |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvested SSH keys, cloud credentials, API keys, database configs, and wallet files from disk |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Queried EC2 IMDSv1/v2 and ECS metadata endpoints for cloud credentials |
| T1005 | Data from Local System | Collected 50+ categories of sensitive files including .env, shell history, and git credentials |
| T1560.001 | Archive Collected Data: Archive via Utility | Packaged stolen data as tpcp.tar.gz before encryption and exfiltration |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-CBC encryption of exfiltrated data with RSA-4096 key wrapping |
| T1041 | Exfiltration Over C2 Channel | Stolen credentials exfiltrated via HTTPS POST to models[.]litellm[.]cloud |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS-based C2 communications and exfiltration |
| T1610 | Deploy Container | Deployed privileged pods (node-setup-*) in Kubernetes for lateral movement |
| T1611 | Escape to Host | Container escape via hostPID/hostNetwork with host filesystem mount and chroot |
| T1078 | Valid Accounts | Stolen credentials reused for authenticated access to cloud APIs and secret stores |
| T1027 | Obfuscated Files or Information | Multi-layer base64 encoding and subprocess spawning to evade static analysis |
| T1020 | Automated Exfiltration | Credentials automatically collected, encrypted, and exfiltrated without operator interaction |
| T1098 | Account Manipulation | Potential for account manipulation using stolen CI/CD and cloud credentials |

## Impact Assessment

**Breadth:** Over 119,000 downloads of the malicious packages during the ~2.5-hour exposure window. With LiteLLM's typical install rate of ~1,700 per minute and an estimated 40-50% unpinned installs fetching the latest version, the actual number of affected installations is significant. CloudSEK's analysis of the attacker's captured data (434,000 files) maps exposure to 2,500+ organizations, with high-confidence matches for organizations whose domains appeared in captured CI runner environments.

**Depth:** Full credential compromise -- the payload harvested 50+ categories of secrets including cloud keys, SSH keys, Kubernetes tokens, database passwords, and cryptocurrency wallets. For Kubernetes environments, the attack enabled cluster-wide lateral movement and potential data destruction. The embedded AWS SigV4 signing capability allowed direct access to AWS Secrets Manager and SSM Parameter Store.

**Stealth:** Despite the multi-layer obfuscation, the initial detection came from a performance side effect (fork bomb / CPU exhaustion), not from security tooling. The persistence mechanism (sysmon.service) was designed to blend with legitimate monitoring services.

**Named victims include:** NVIDIA, Cisco, Deloitte, Volkswagen, FedEx, Siemens, and X Corp (per CloudSEK's dataset analysis).

## Detection & Remediation

### Immediate Detection

Check for compromised LiteLLM versions:
```shell
pip show litellm | grep Version
# Affected: 1.82.7 or 1.82.8
```

Check for persistence artifacts:
```shell
ls -la ~/.config/sysmon/sysmon.py
ls -la /root/.config/sysmon/sysmon.py
systemctl --user status sysmon.service
ls -la /tmp/.pg_state /tmp/pglog /tmp/tpcp.tar.gz 2>/dev/null
```

Check for malicious .pth files:
```shell
find $(python3 -c "import site; print(' '.join(site.getsitepackages()))") \
  -name "*.pth" -exec grep -l "base64\|subprocess\|exec" {} \;
```

Check Kubernetes for lateral movement pods:
```shell
kubectl get pods -A | grep "node-setup-"
kubectl get daemonsets -A | grep -E "host-provisioner|kamikaze"
```

Check for tpcp-docs exfiltration repositories:
```shell
# Search your GitHub organization for attacker repositories
gh repo list <org> --json name -q '.[].name' | grep -i "tpcp-docs\|docs-tpcp"
```

### Remediation

1. **Immediately pin LiteLLM to <=1.82.6** in all environments (requirements.txt, Pipfile, pyproject.toml)
2. **Treat all affected systems as full credential compromise events** -- rotate ALL secrets those systems could access
3. **Priority rotation:** Cloud credentials (AWS/GCP/Azure), GitHub/npm tokens, CI/CD secrets, SSH keys, Kubernetes service account tokens, PyPI publishing tokens, database passwords, LLM API keys
4. **Remove persistence:** Delete `~/.config/sysmon/` directory, disable and remove `sysmon.service`, remove `/tmp/pglog` and `/tmp/.pg_state`
5. **Kubernetes:** Delete any `node-setup-*` pods, `host-provisioner-*` DaemonSets, and `kamikaze` containers; audit all secrets for unauthorized access
6. **Review CloudTrail/cloud audit logs** for unauthorized `GetSecretValue`, `ListSecrets`, or `DescribeParameters` calls with `Python-urllib` User-Agent
7. **Scan downstream artifacts** from exposed build/release pipelines for further compromise
8. **Search GitHub organizations** for `tpcp-docs` repositories containing exfiltrated data

### Long-Term Hardening

1. **Enable PyPI Trusted Publishers** (OIDC-based publishing) instead of long-lived API tokens
2. **Implement dependency version pinning** with cryptographic hashes (pip `--require-hashes`, lockfiles)
3. **Adopt dependency cooldowns** (e.g., 3 days before auto-upgrading to newly published versions)
4. **Pin GitHub Actions to full commit SHA** rather than mutable version tags
5. **Migrate from long-lived tokens to temporary credentials** via OIDC integrations and secrets managers
6. **Deploy runtime monitoring** for .pth file creation in Python site-packages directories
7. **Implement network egress controls** for CI/CD runners, restricting outbound connections to known-good destinations
8. **Use pipeline security scanning tools:** zizmor (GitHub Actions static analysis), gato/Gato-X (pipeline vulnerability detection), allstar (OpenSSF GitHub security policy enforcement)

## Detection Rules

Six Sigma rules, two YARA rules, three Snort rules, and three Suricata rules cover the primary IOCs: malicious file creation (.pth and persistence artifacts), DNS queries to exfiltration domains, credential staging files, Kubernetes lateral movement patterns, compromised package installation, and network exfiltration traffic. All rules are tuned to advisory-specific indicators and may require adaptation to local log source configurations.

### Sigma: LiteLLM Malicious PTH File Creation

Detects creation of the `litellm_init.pth` file used for Python startup hook credential theft.
compile: pass (sigma convert splunk/logscale succeeded) | confidence: high

```yaml
title: LiteLLM Malicious PTH File Creation
id: 8a3c7e2d-4f1b-4e9a-b5d6-1c2e3f4a5b6c
status: experimental
description: Detects creation of the malicious litellm_init.pth file used by TeamPCP to execute credential-stealing code at Python interpreter startup (CVE-2026-33634).
references:
    - https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
author: Actioner
date: 2026-08-14
tags:
    - attack.t1546
    - attack.t1059.006
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: 'litellm_init.pth'
    condition: selection
falsepositives:
    - Legitimate litellm package installations prior to the attack (versions before 1.82.7 did not contain this file)
level: critical
```

<!-- audit: sigma convert --without-pipeline -t splunk and -t log_scale both succeeded. ATT&CK tag corrected from T1547.013 (XDG Autostart Entries) to T1546 (Event Triggered Execution) to accurately reflect Python .pth startup hook abuse. -->

### Sigma: TeamPCP Sysmon Persistence Service Installation

Detects creation of the sysmon.py backdoor or sysmon.service systemd unit for persistent C2 polling.
compile: pass (sigma convert splunk/logscale succeeded) | confidence: high

```yaml
title: TeamPCP Sysmon Persistence Service Installation
id: 9b4d8f3e-5a2c-4d0b-c6e7-2d3f4a5b6c7d
status: experimental
description: Detects creation of the sysmon.py backdoor or sysmon.service systemd unit used by TeamPCP for persistent C2 polling after LiteLLM compromise (CVE-2026-33634).
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
author: Actioner
date: 2026-08-14
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection_sysmon_py:
        TargetFilename|endswith: '/.config/sysmon/sysmon.py'
    selection_sysmon_svc:
        TargetFilename|endswith: '/.config/systemd/user/sysmon.service'
    condition: selection_sysmon_py or selection_sysmon_svc
falsepositives:
    - Legitimate system monitoring tools named sysmon (unlikely on Linux)
level: critical
```

<!-- audit: sigma check failed due to MITRE ATT&CK data fetch blocked by proxy (HTTP 403), not a rule syntax issue. sigma convert --without-pipeline -t splunk produced: TargetFilename IN ("*/.config/sysmon/sysmon.py", "*/.config/systemd/user/sysmon.service"). Both conversions confirm valid syntax. -->

### Sigma: TeamPCP Exfiltration Domain DNS Query

Detects DNS queries to TeamPCP exfiltration and C2 domains.
compile: pass (sigma convert splunk/logscale succeeded) | confidence: high

```yaml
title: TeamPCP Exfiltration Domain DNS Query
id: ac5e9f4a-6b3d-4e1c-d7f8-3e4a5b6c7d8e
status: experimental
description: Detects DNS queries to TeamPCP exfiltration and C2 domains used in the LiteLLM/Trivy supply chain campaign (CVE-2026-33634).
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html
author: Actioner
date: 2026-08-14
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: dns
detection:
    selection:
        query|endswith:
            - 'models.litellm.cloud'
            - 'checkmarx.zone'
            - 'aquasecurtiy.org'
            - 'scan.aquasecurtiy.org'
    condition: selection
falsepositives:
    - None expected
level: critical
```

<!-- audit: sigma check failed due to MITRE ATT&CK data fetch blocked by proxy (HTTP 403), not a rule syntax issue. sigma convert --without-pipeline -t splunk produced: query IN ("*models.litellm.cloud", "*checkmarx.zone", "*aquasecurtiy.org", "*scan.aquasecurtiy.org"). Both conversions confirm valid syntax. -->

### Sigma: TeamPCP Kubernetes Privileged Pod Deployment

Detects creation of privileged pods matching TeamPCP naming patterns for lateral movement.
compile: pass (sigma convert splunk/logscale succeeded) | confidence: high

```yaml
title: TeamPCP Kubernetes Privileged Pod Deployment
id: bd6fa0b5-7c4e-4f2d-e8a9-4f5b6c7d8e9f
status: experimental
description: Detects creation of privileged pods matching TeamPCP naming patterns used for lateral movement after LiteLLM supply chain compromise (CVE-2026-33634).
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
author: Actioner
date: 2026-08-14
tags:
    - attack.t1610
    - attack.t1611
logsource:
    category: application
    product: kubernetes
    service: audit
detection:
    selection_resource:
        objectRef.resource: 'pods'
    selection_names:
        objectRef.name|startswith: 'node-setup-'
    selection_containers:
        requestObject.spec.containers.name:
            - 'kamikaze'
            - 'provisioner'
            - 'host-provisioner-std'
            - 'host-provisioner-iran'
    condition: selection_resource and (selection_names or selection_containers)
falsepositives:
    - Custom Kubernetes deployments using node-setup naming convention
level: critical
```

<!-- audit: sigma check failed due to MITRE ATT&CK data fetch blocked by proxy (HTTP 403), not a rule syntax issue. sigma convert --without-pipeline -t splunk produced: objectRef.resource="pods" objectRef.name="node-setup-*" OR requestObject.spec.containers.name IN ("kamikaze", "provisioner", "host-provisioner-std", "host-provisioner-iran"). Both conversions confirm valid syntax. -->

### Sigma: Installation of Compromised LiteLLM Package Version

Detects pip install commands targeting the known-compromised LiteLLM versions.
compile: pass (sigma convert splunk/logscale succeeded) | confidence: medium | note: only detects installs explicitly specifying version 1.82.7 or 1.82.8

```yaml
title: Installation of Compromised LiteLLM Package Version
id: ce7ab1c6-8d5f-4a3e-f9ba-5a6c7d8e9f0a
status: experimental
description: Detects pip install commands targeting the known-compromised LiteLLM versions 1.82.7 or 1.82.8 associated with the TeamPCP supply chain attack (CVE-2026-33634).
references:
    - https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html
    - https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/
author: Actioner
date: 2026-08-14
tags:
    - attack.t1195.002
logsource:
    category: process_creation
    product: linux
detection:
    selection_pip_binary:
        Image|endswith:
            - '/pip'
            - '/pip3'
    selection_pip_module:
        Image|endswith:
            - '/python'
            - '/python3'
        CommandLine|contains:
            - '-m pip'
    selection_package:
        CommandLine|contains: 'litellm'
    selection_version:
        CommandLine|contains:
            - '1.82.7'
            - '1.82.8'
    condition: (selection_pip_binary or selection_pip_module) and selection_package and selection_version
falsepositives:
    - Forensic analysis or testing of the compromised versions in isolated environments
    - Unpinned pip install commands (without explicit version) will not be detected by this rule
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk and -t log_scale both succeeded. Rule now covers both direct pip/pip3 binaries and python -m pip invocations. Medium confidence because unpinned pip install commands (without explicit version string) will not be detected. Level downgraded from critical to high to reflect this detection gap. -->

### Sigma: TeamPCP Exfiltration Staging Files Created

Detects creation of temporary files used for staging encrypted credential exfiltration.
compile: pass (sigma convert splunk/logscale succeeded) | confidence: high

```yaml
title: TeamPCP Exfiltration Staging Files Created
id: df8bc2d7-9e6a-4b4f-a0cb-6b7d8e9f0a1b
status: experimental
description: Detects creation of temporary files used by TeamPCP for staging encrypted credential exfiltration after LiteLLM compromise (CVE-2026-33634).
references:
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
author: Actioner
date: 2026-08-14
tags:
    - attack.t1074.001
    - attack.t1560.001
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename:
            - '/tmp/tpcp.tar.gz'
            - '/tmp/payload.enc'
            - '/tmp/session.key.enc'
            - '/tmp/.pg_state'
    condition: selection
falsepositives:
    - Unlikely; file names tpcp.tar.gz, payload.enc, and session.key.enc are distinctive to this campaign
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk and -t log_scale both succeeded. Generic paths /tmp/session.key (OpenSSL) and /tmp/pglog (PostgreSQL) removed to reduce false positives; retained only the four campaign-distinctive paths. -->

### YARA: TeamPCP LiteLLM Malicious Payload and Sysmon Backdoor

Detects the malicious litellm_init.pth payload content and the sysmon.py persistent backdoor based on string combinations unique to the TeamPCP campaign.
compile: pass (yarac compiled without errors) | confidence: high

```yara
rule TeamPCP_LiteLLM_Malicious_PTH_Payload
{
    meta:
        description = "Detects the malicious litellm_init.pth file or related TeamPCP credential-stealing payload from the LiteLLM supply chain attack (CVE-2026-33634)"
        author = "Actioner"
        date = "2026-08-14"
        reference = "https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/"
        hash_pth = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
        hash_proxy = "a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b"
        hash_sysmon = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"

    strings:
        // Campaign-specific indicators (unique to TeamPCP)
        $specific_pth = "litellm_init.pth" ascii
        $specific_exfil = "models.litellm.cloud" ascii
        $specific_c2 = "checkmarx.zone" ascii
        $specific_tpcp = "tpcp.tar.gz" ascii
        $specific_team = "TeamPCP" ascii nocase
        $specific_rsa = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvahaZDo8mucujrT15ry+" ascii
        $specific_xfn = "X-Filename: tpcp.tar.gz" ascii
        $specific_sysmon = ".config/sysmon/sysmon.py" ascii

        // Generic indicators (may appear in legitimate AI/ML software)
        $generic_svc = "sysmon.service" ascii
        $generic_pgstate = "/tmp/.pg_state" ascii
        $generic_pglog = "/tmp/pglog" ascii
        $generic_openai = "OPENAI_API_KEY" ascii
        $generic_anthropic = "ANTHROPIC_API_KEY" ascii

    condition:
        1 of ($specific_*) and 3 of them
}

rule TeamPCP_LiteLLM_Sysmon_Backdoor
{
    meta:
        description = "Detects the sysmon.py persistent backdoor deployed by TeamPCP after LiteLLM compromise"
        author = "Actioner"
        date = "2026-08-14"
        reference = "https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html"
        hash = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"

    strings:
        $c2_poll = "checkmarx.zone/raw" ascii
        $kill_switch = "youtube" ascii
        $sysmon_dir = ".config/sysmon" ascii
        $systemd_unit = "System Telemetry Service" ascii
        $pg_state = ".pg_state" ascii

    condition:
        ($c2_poll and $kill_switch) or ($systemd_unit and $sysmon_dir) or ($c2_poll and $pg_state)
}
```

<!-- audit: yarac compiled both rules to /dev/null without errors or warnings. Rule TeamPCP_LiteLLM_Malicious_PTH_Payload uses tiered string matching: requires at least 1 campaign-specific string ($specific_*) plus 3 total matches, preventing false positives from generic strings like OPENAI_API_KEY or ANTHROPIC_API_KEY that appear in legitimate AI/ML projects. Rule TeamPCP_LiteLLM_Sysmon_Backdoor requires logical combinations of C2 domain + kill switch or persistence indicators. -->

**TLS Inspection Required:** All six network detection rules below (Snort and Suricata) inspect HTTP-layer content and will only match if TLS decryption/SSL inspection is deployed in the traffic path, since the attacker's C2 and exfiltration endpoints use HTTPS.

### Snort: TeamPCP Network Exfiltration Detection

Three rules detecting HTTPS POST exfiltration to `models[.]litellm[.]cloud`, C2 polling to `checkmarx[.]zone/raw`, and the `X-Filename: tpcp.tar.gz` exfiltration header.
compile: pass (Snort successfully validated the configuration) | confidence: high

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE TeamPCP LiteLLM Credential Exfiltration to models.litellm.cloud"; flow:established,to_server; content:"models.litellm.cloud"; http_header; content:"POST"; http_method; content:"tpcp.tar.gz"; http_header; reference:cve,2026-33634; classtype:trojan-activity; sid:2026081401; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE TeamPCP C2 Polling to checkmarx.zone"; flow:established,to_server; content:"checkmarx.zone"; http_header; content:"/raw"; http_uri; content:"GET"; http_method; reference:cve,2026-33634; classtype:trojan-activity; sid:2026081402; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE TeamPCP X-Filename tpcp.tar.gz Exfiltration Header"; flow:established,to_server; content:"X-Filename|3a 20|tpcp.tar.gz"; http_header; reference:cve,2026-33634; classtype:trojan-activity; sid:2026081403; rev:1;)
```

<!-- audit: Snort 2.9.20 validated all three rules with "Snort successfully validated the configuration!" via snort -c /etc/snort/snort.conf -R tpcp.rules -T. Rules use http_header, http_method, http_uri content modifiers for accurate HTTP inspection. Note these rules will not match TLS-encrypted traffic without SSL inspection/decryption in the path. -->

### Suricata: TeamPCP Network Exfiltration Detection

Three rules using Suricata's native HTTP keywords for detecting exfiltration to `models[.]litellm[.]cloud`, C2 polling, and the tpcp exfiltration header.
compile: pass (Configuration provided was successfully loaded. Exiting.) | confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE TeamPCP LiteLLM Credential Exfiltration to models.litellm.cloud"; flow:established,to_server; http.method; content:"POST"; http.host; content:"models.litellm.cloud"; http.header; content:"tpcp.tar.gz"; reference:cve,2026-33634; classtype:trojan-activity; sid:2026081411; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE TeamPCP C2 Polling to checkmarx.zone"; flow:established,to_server; http.method; content:"GET"; http.host; content:"checkmarx.zone"; http.uri; content:"/raw"; reference:cve,2026-33634; classtype:trojan-activity; sid:2026081412; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE TeamPCP X-Filename tpcp.tar.gz Exfiltration Header"; flow:established,to_server; http.header; content:"X-Filename|3a 20|tpcp.tar.gz"; reference:cve,2026-33634; classtype:trojan-activity; sid:2026081413; rev:1;)
```

<!-- audit: Suricata 7.0.3 validated all three rules with "Configuration provided was successfully loaded. Exiting." via suricata -T -S litellm_teampcp_exfil.suricata.rules -l /tmp/actioner/suricata_logs. Rules use Suricata sticky buffer syntax (http.method, http.host, http.uri, http.header) for protocol-aware matching. As with Snort, TLS inspection is required for encrypted traffic. -->

## Lessons Learned

1. **Mutable version tags in GitHub Actions are a critical risk.** The entire attack chain was enabled by the ability to force-push to existing Git tags. Organizations must pin GitHub Actions to full commit SHAs rather than mutable version tags, and CI/CD platforms should consider enforcing immutable tag references.

2. **PyPI publishing tokens in CI/CD environments need defense-in-depth.** The stolen Trivy token was a long-lived API key accessible to CI runner processes. PyPI's Trusted Publishers (OIDC-based) mechanism eliminates persistent tokens entirely and should be the default for all maintained packages. Dependency cooldowns (delaying auto-upgrades to newly published versions) would have reduced the blast radius.

3. **Python .pth files represent a powerful and under-monitored persistence vector.** The `.pth` startup hook mechanism allowed code execution on every Python process without explicit import, bypassing application-level security controls. Enterprises should monitor for `.pth` file creation in site-packages directories as a critical security event.

4. **Supply chain attacks increasingly target AI/ML infrastructure.** LiteLLM's role as a centralized LLM API key proxy meant that compromising a single dependency exposed keys for OpenAI, Anthropic, Azure, and other AI services across entire organizations. The concentration of high-value credentials in AI gateway libraries makes them prime targets.

5. **Credential rotation after upstream compromise must be exhaustive.** Aqua Security's incomplete credential rotation after the initial Trivy compromise directly enabled the second-stage LiteLLM attack. Organizations must treat upstream supply chain incidents as full-scope credential compromise events.

## Sources

- [The Hacker News - Malicious LiteLLM Releases Tied to Trivy Hack](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html) -- Primary reporting with timeline, attribution to UNC6780/TeamPCP, and impact assessment
- [Datadog Security Labs - LiteLLM Compromised on PyPI: TeamPCP Supply Chain Campaign](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/) -- Comprehensive technical analysis with IOCs, detection queries, MITRE mapping, and Kubernetes lateral movement details
- [Trend Micro - Inside the LiteLLM Supply Chain Compromise](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html) -- Deep technical analysis of payload architecture, file hashes, encryption methods, and the three-layer malware encoding
- [Snyk - How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM](https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/) -- File hashes (SHA-256), persistence artifact details, credential targeting categories, and detection commands
- [PyPI Blog - Incident Report: LiteLLM/Telnyx Supply Chain Attacks](https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/) -- Official PyPI incident report with exposure metrics, download counts, advisory IDs (PYSEC-2026-2), and remediation recommendations
- [Kaspersky - Trojanization of Trivy, Checkmarx, and LiteLLM](https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/) -- Broader campaign context including Checkmarx and npm scope compromise, destructive Iran-targeting capability, and additional domain IOCs
- [LiteLLM Official - Security Update: Suspected Supply Chain Incident](https://docs.litellm.ai/blog/security-update-march-2026) -- Vendor disclosure and remediation guidance
- [GitGuardian - Trivy's March Supply Chain Attack Shows Where Secret Exposure Hurts Most](https://blog.gitguardian.com/trivys-march-supply-chain-attack-shows-where-secret-exposure-hurts-most/) -- Analysis of root cause credential exposure patterns
- [Netenrich - LiteLLM PyPI Supply Chain Attack: What Happened & How to Fix It](https://netenrich.com/blog/litellm-pypi-supply-chain-attack) -- Practitioner-focused remediation guide
- [HeroDevs - The LiteLLM Supply Chain Attack](https://www.herodevs.com/blog-posts/the-litellm-supply-chain-attack-what-happened-why-it-matters-and-what-to-do-next) -- Impact analysis and organizational response guidance

<!-- revision: v1.1 2026-08-14 — Fixed ATT&CK mapping T1547.013→T1546 (Event Triggered Execution) in Sigma PTH rule and MITRE table. Sigma pip install rule: added python -m pip coverage, downgraded critical→high, noted unpinned-install detection gap. Sigma staging files rule: removed generic paths /tmp/session.key and /tmp/pglog to reduce false positives. YARA PTH payload rule: tiered strings into specific/generic, changed condition from 3-of-13 to 1-specific+3-total. Added visible TLS inspection caveat for Snort/Suricata rules. Aligned IP defanging example with actual report convention. All changed rules re-validated with sigma convert and yarac. -->

---
*Report generated by Actioner*
