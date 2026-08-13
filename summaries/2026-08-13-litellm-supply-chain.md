# Technical Analysis Report: LiteLLM Supply Chain Attack via Trivy Compromise (CVE-2026-33634)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-13
Version: 1.0

## Executive Summary

On March 24, 2026, two malicious versions of the `litellm` Python package (v1.82.7 and v1.82.8) were published to PyPI by the threat actor group TeamPCP (tracked by Google as UNC6780). The packages were available for approximately 40 minutes before PyPI quarantined them, but during that window they were downloaded by automated CI/CD pipelines across an estimated 2,500+ organizations, exposing approximately 434,000 CI/CD pipelines. The compromise originated through a prior supply chain attack on Aqua Security's Trivy vulnerability scanner: the poisoned Trivy binary scraped process memory on GitHub Actions runners to extract the LiteLLM maintainer's `PYPI_PUBLISH_PASSWORD` token in plaintext, which was then used to publish the backdoored packages directly to PyPI.

The malicious payload operated in three stages: (1) comprehensive credential harvesting sweeping SSH keys, cloud credentials (AWS/GCP/Azure), Kubernetes tokens, AI provider API keys, cryptocurrency wallets, and environment variables; (2) Kubernetes lateral movement deploying privileged pods to every cluster node; and (3) persistent systemd backdoor polling an attacker-controlled C2 for secondary payloads. Exfiltrated data was encrypted with AES-256-CBC + RSA-4096 key wrapping before transmission to attacker infrastructure. The incident was assigned CVE-2026-33634 (CVSS 9.4) and added to CISA's Known Exploited Vulnerabilities catalog on March 26, 2026. FBI advisory FLASH-20260702-01 subsequently warned that affiliated actors will likely weaponize exfiltrated credentials long after the initial compromise window.

## Background: LiteLLM

LiteLLM is a widely adopted open-source Python library and proxy server that provides a unified API interface to over 100 LLM providers (OpenAI, Anthropic, Azure, AWS Bedrock, etc.). It serves as an AI gateway in enterprise environments, meaning it inherently handles and proxies sensitive API keys and credentials. At the time of the attack, the package had approximately 95 million monthly PyPI downloads and was integrated into CI/CD pipelines, production infrastructure, and development environments across thousands of organizations including NVIDIA, Cisco, Salesforce, Siemens, FedEx, Volkswagen, and others.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Late Feb 2026 | Trivy GitHub Action compromised via `pull_request_target` exploit; attacker obtains CI secrets |
| 2026-03-19 17:43 | Trivy v0.69.4 tags force-pushed to malicious release (76 of 77 trivy-action tags + all 7 setup-trivy tags rewritten) |
| 2026-03-20 | TeamPCP deploys CanisterWorm self-propagating npm worm via compromised infrastructure |
| 2026-03-23 | Checkmarx KICS and AST GitHub Actions compromised |
| 2026-03-23 12:58 | C2 domains `checkmarx[.]zone` and `models.litellm[.]cloud` registered via Spaceship, Inc. |
| 2026-03-24 10:39 | `litellm` v1.82.7 published to PyPI (payload in `proxy_server.py`) |
| 2026-03-24 10:52 | `litellm` v1.82.8 published to PyPI (added `.pth` persistence mechanism) |
| 2026-03-24 11:48 | Community disclosure issue #24512 opened on LiteLLM GitHub |
| 2026-03-24 ~13:38 | PyPI quarantine initiated for both versions |
| 2026-03-24 15:09 | Maintainer credentials rotated |
| 2026-03-26 | CVE-2026-33634 added to CISA KEV catalog |
| 2026-07-02 | FBI FLASH-20260702-01 advisory issued |
| 2026-08-12 | Updated impact assessment published; ~2,500 organizations and 434,000 pipelines affected |

## Root Cause: Trivy CI/CD Dependency Compromise

The attack exploited an unpinned dependency in LiteLLM's CI/CD pipeline. LiteLLM's security scanning script ran `sudo apt-get install trivy` without version pinning, which automatically installed the compromised Trivy v0.69.4 binary published on March 19. The poisoned Trivy binary employed a process memory scraping technique: it read `/proc/<pid>/mem` for GitHub Actions runner processes (`Runner.Worker`, `Runner.Listener`) to extract the `PYPI_PUBLISH_PASSWORD` token in plaintext, bypassing GitHub's secret masking. With the PyPI publishing token in hand, the attacker uploaded the backdoored LiteLLM packages directly, bypassing the official CI/CD release workflow entirely. The identical RSA-4096 public key embedded across the Trivy, Checkmarx KICS, and LiteLLM payloads confirms this was one coordinated campaign by TeamPCP.

## Technical Analysis of the Malicious Payload

### 1. Delivery and Execution Mechanism

**Version 1.82.7** embedded a base64-encoded payload directly inside `litellm/proxy/proxy_server.py`. The malicious code executed upon import of the `litellm.proxy` module.

**Version 1.82.8** escalated the approach by adding a `litellm_init.pth` file (34,628 bytes) to the Python site-packages directory. The `.pth` mechanism is a Python feature that executes code on every interpreter startup -- not just when LiteLLM is imported. This meant the payload fired across all Python processes in the affected environment, dramatically increasing the blast radius. The `.pth` file contained a three-layer base64-encoded payload:

- **Layer 0 (Launcher):** Single-line Python executing Layer 1 via `subprocess.Popen`
- **Layer 1 (Orchestrator):** Contains hardcoded RSA-4096 public key, implements AES-256-CBC + PBKDF2 encryption, coordinates exfiltration
- **Layer 2 (Collector):** Comprehensive credential harvester targeting 50+ secret categories
- **Layer 3 (Persistence):** Systemd backdoor and Kubernetes lateral movement

A notable side effect: the `.pth` launcher spawned child processes on every interpreter startup, causing exponential fork loops that resulted in massive RAM consumption and system freezes -- a potential early detection signal.

### 2. Credential Harvesting (Stage 1)

The collector swept the following credential categories:

- **System data:** hostname, environment variables, running processes, routing tables, `/var/log/auth.log`
- **SSH:** all key files under `/home/*/` and `/root/` directories
- **Cloud credentials:** AWS (`~/.aws/credentials`, `~/.aws/config`), GCP/Azure service account files, IMDSv2 queries with full SigV4 signing implementation
- **AWS API operations:** EC2 IMDS v1/v2 queries, Secrets Manager (`ListSecrets`, `GetSecretValue`), SSM Parameter Store (`DescribeParameters`)
- **Kubernetes:** `~/.kube/config`, service account tokens from `/var/run/secrets/kubernetes.io/serviceaccount/`, cluster secrets across all namespaces
- **Container:** Docker `config.json`, registry tokens
- **AI provider keys:** OpenAI, Anthropic, Azure AI API keys from environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.)
- **CI/CD:** npm auth tokens, publishing tokens, `.env` files, Git configs, webhook tokens (Slack/Discord)
- **Database credentials:** MySQL, PostgreSQL, MongoDB, Redis, HashiCorp Vault tokens
- **Cryptocurrency wallets:** Bitcoin, Ethereum, Solana, Cardano, Monero wallets, Ledger configurations, seed phrases
- **TLS certificates and WireGuard keys**
- **Shell history** (for embedded credentials and API keys)

### 3. C2 Infrastructure

**Primary exfiltration endpoint:** `hxxps://models.litellm[.]cloud/` -- the attacker registered this domain to mimic the legitimate LiteLLM project (the real project uses `litellm.ai`). Stolen data was encrypted, bundled as `tpcp.tar.gz`, and uploaded via HTTP POST with curl.

**Secondary C2 polling:** `hxxps://checkmarx[.]zone/raw` -- used by the persistence backdoor to poll for secondary payloads every 5 minutes (or 3,000 seconds / ~50 minutes in some variants).

**Additional infrastructure:**
- `scan.aquasecurtiy[.]org` -- typosquatting Aqua Security domain used in the broader Trivy campaign
- `83.142.209[.]203:8080` -- Telnyx payload server (related campaign)
- `83.142.209[.]11` -- `checkmarx[.]zone` hosting
- `46.151.182[.]203` -- `models.litellm[.]cloud` hosting (AS205759, Ghosty Networks LLC / DEMENIN B.V.)
- Cloudflare tunnel domains: `championships-peoples-point-cassette.trycloudflare[.]com`, `investigation-launches-hearings-copying.trycloudflare[.]com`, `souls-entire-defined-routes.trycloudflare[.]com`
- ICP canister: `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0[.]io`
- GitHub data drops: repositories with `tpcp-docs-` prefix, stolen data uploaded as release assets tagged `data-<timestamp>`

**Kill switch:** The C2 polling loop terminated if it received a response containing a YouTube URL with the string "youtube".

**Encryption scheme:**
- 32-byte AES-256 session key generated via `openssl rand`
- Data encrypted with AES-256-CBC using PBKDF2 key derivation
- Session key wrapped with RSA-4096-OAEP using a hardcoded public key
- Temporary files: `session.key`, `payload.enc`, `session.key.enc`, `tpcp.tar.gz`

### 4. Kubernetes Lateral Movement (Stage 2)

The payload read Kubernetes service account tokens from the standard mount path and queried the cluster API to enumerate all secrets across every namespace. It then deployed privileged pods to every node in the cluster:

- **Namespace:** `kube-system`
- **Pod naming:** `node-setup-{node_name}` (truncated to 35 chars)
- **Container name:** `setup`
- **Container image:** `alpine:latest`
- **Privileges:** `hostPID: true`, `hostNetwork: true`, host filesystem mounted at `/host`
- **Payload:** Used chroot to write the `sysmon` backdoor onto each node's host filesystem

### 5. Persistence (Stage 3)

**Systemd user service:**
- Backdoor script: `~/.config/sysmon/sysmon.py` (or `/root/.config/sysmon/sysmon.py`)
- Systemd unit: `~/.config/systemd/user/sysmon.service` (Description: "System Telemetry Service")
- Activation: `systemctl --user daemon-reload && systemctl --user enable --now sysmon.service`
- Behavior: Initial 300-second delay, then polls `hxxps://checkmarx[.]zone/raw` at regular intervals
- Downloads secondary payload to `/tmp/pglog`, executes as background process
- State tracking: `/tmp/.pg_state`

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.82.7 | Base64 payload injected in `proxy_server.py` |
| litellm (PyPI) | 1.82.8 | Added `litellm_init.pth` for interpreter-startup execution |
| telnyx (PyPI) | 4.87.1, 4.87.2 | Related TeamPCP compromise; WAV-steganography payload |
| trivy (binary) | 0.69.4 | Upstream compromise; memory-scraping credential theft |
| trivy-action (GitHub) | 76 of 77 tags | Force-pushed malicious commits |
| setup-trivy (GitHub) | all 7 tags | Force-pushed malicious commits |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `site-packages/litellm_init.pth` | `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238` | Malicious .pth startup hook (v1.82.8) |
| Linux | `litellm/proxy/proxy_server.py` | `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b` | Compromised proxy module (v1.82.7) |
| Linux | `~/.config/sysmon/sysmon.py` | `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a` | Persistent backdoor script |
| Linux | `~/.config/systemd/user/sysmon.service` | -- | Systemd persistence unit ("System Telemetry Service") |
| Linux | `/tmp/pglog` | -- | Downloaded secondary payload |
| Linux | `/tmp/.pg_state` | -- | C2 polling state file |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `models.litellm[.]cloud` | Primary exfiltration endpoint (POST) |
| Domain | `checkmarx[.]zone` | C2 polling for secondary payloads |
| Domain | `scan.aquasecurtiy[.]org` | Trivy campaign exfiltration (typosquat) |
| IP | `46.151.182[.]203` | models.litellm[.]cloud hosting |
| IP | `83.142.209[.]11` | checkmarx[.]zone hosting |
| IP | `83.142.209[.]203:8080` | Telnyx payload server |
| Domain | `championships-peoples-point-cassette.trycloudflare[.]com` | Cloudflare tunnel |
| Domain | `investigation-launches-hearings-copying.trycloudflare[.]com` | Cloudflare tunnel |
| Domain | `souls-entire-defined-routes.trycloudflare[.]com` | Cloudflare tunnel |
| Domain | `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0[.]io` | ICP canister C2 |
| URL Pattern | `hxxps://models.litellm[.]cloud/` (POST) | Credential exfiltration via `tpcp.tar.gz` |
| URL Pattern | `hxxps://checkmarx[.]zone/raw` (GET) | Persistent backdoor polling |

### Behavioral

- Python `.pth` file creation in site-packages triggering code execution on every interpreter startup
- Exponential fork loops / massive RAM consumption from `.pth` launcher spawning child processes
- Creation of `~/.config/sysmon/sysmon.py` and `sysmon.service` systemd unit
- Kubernetes privileged pod deployment with `node-setup-*` naming in `kube-system` namespace
- `alpine:latest` containers with `hostPID`, `hostNetwork`, and host filesystem mount at `/host`
- Process memory scraping via `/proc/<pid>/mem` on CI/CD runners
- `tpcp-docs-*` GitHub repository creation with release assets tagged `data-<timestamp>`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Poisoned Trivy scanner led to compromised LiteLLM PyPI packages |
| T1546 | Event Triggered Execution | `.pth` file executes on every Python interpreter startup |
| T1059.006 | Command and Scripting Interpreter: Python | Multi-layer base64-encoded Python payload execution |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvesting SSH keys, `.env` files, cloud credential files, wallet files |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | IMDSv2 queries with SigV4 signing for AWS credential theft |
| T1543.002 | Create or Modify System Process: Systemd Service | Persistent `sysmon.service` polling C2 for secondary payloads |
| T1610 | Deploy Container | Privileged Kubernetes pods deployed to every cluster node |
| T1611 | Escape to Host | Container escape via hostPID/hostNetwork and host filesystem mount |
| T1027 | Obfuscated Files or Information | Three-layer base64 encoding of payload |
| T1041 | Exfiltration Over C2 Channel | AES-256+RSA-4096 encrypted credential bundle sent to attacker domain |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-CBC with PBKDF2 for data encryption |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP POST exfiltration and GET-based C2 polling |
| T1082 | System Information Discovery | Hostname, environment, processes, routing enumeration |

## Impact Assessment

The 40-minute exposure window was sufficient for widespread propagation through automated CI/CD pipelines. CloudSEK's analysis identified approximately 2,500 organizations and 434,000 CI/CD pipelines with potential exposure. Notable entities on the affected list include NVIDIA, AWS, Samsung, Salesforce, Cisco, ServiceNow, Accenture Federal Services, Siemens, Regeneron Pharmaceuticals, London Stock Exchange Group, FedEx, Volkswagen, Orange, HP, Deutsche Bahn, NGINX, Zscaler, Deloitte, and X Corp. Confirmed downstream compromises include Checkmarx (unauthorized GitHub repository access), Mercor (compromised by malicious LiteLLM versions), and the European Commission (CERT-EU assessed 91.7 GB compressed data exfiltrated from an AWS account).

These figures represent reconstructed exposure based on captured file analysis, not confirmed compromises in every case. However, the FBI advisory FLASH-20260702-01 warns that affiliated actors will likely weaponize exfiltrated credentials for months following the initial incident.

## Detection & Remediation

### Immediate Detection

Check for compromised LiteLLM versions:
```bash
pip show litellm | grep -E "^Version:"
# Flag versions 1.82.7 or 1.82.8
```

Search for the malicious `.pth` file:
```bash
find / -name "litellm_init.pth" 2>/dev/null
```

Check for persistence artifacts:
```bash
ls -la ~/.config/sysmon/sysmon.py
ls -la ~/.config/systemd/user/sysmon.service
ls -la /tmp/pglog /tmp/.pg_state
systemctl --user status sysmon.service
```

Search for suspicious Kubernetes pods:
```bash
kubectl get pods -n kube-system | grep "node-setup-"
```

Search network logs for C2 communication:
```bash
# Search proxy/DNS logs for attacker domains
grep -E "models\.litellm\.cloud|checkmarx\.zone|scan\.aquasecurtiy\.org" /var/log/proxy.log
```

### Remediation

1. **Immediate rollback:** Pin LiteLLM to v1.82.6 or upgrade to v1.83.0+ (released via new CI/CD v2 pipeline)
2. **Remove persistence artifacts:** Delete `litellm_init.pth`, `~/.config/sysmon/sysmon.py`, `sysmon.service`; preserve copies for forensic analysis
3. **Rotate ALL secrets:** API keys (OpenAI, Anthropic, Azure AI), cloud credentials (AWS/GCP/Azure), SSH keys, Kubernetes tokens, database passwords, CI/CD publishing tokens, npm auth tokens, Docker registry credentials
4. **Audit CI/CD pipelines:** Clear build caches, review GitHub Actions/GitLab CI workflow logs for v1.82.7/1.82.8 installations during the March 24 window
5. **Kubernetes remediation:** Remove `node-setup-*` pods from `kube-system`, audit cluster secrets, rotate all service account tokens
6. **Network egress filtering:** Block C2 domains at the network perimeter
7. **Verify Docker images:** The official LiteLLM Proxy Docker image (`ghcr.io/berriai/litellm`) was unaffected; LiteLLM Cloud users were also unaffected

### Long-Term Hardening

- **Pin dependencies with cryptographic hashes** in CI/CD pipelines (`pip install litellm==1.82.6 --hash=sha256:...`)
- **Implement cosign verification** for Docker images (LiteLLM signs images with cosign starting v1.83.0-nightly)
- **Transition to short-lived credentials** via a secrets manager rather than static tokens in CI/CD
- **Monitor for `.pth` file creation** in Python site-packages directories (anomaly detection)
- **Deploy egress network monitoring** for unexpected outbound connections from CI/CD runners and production infrastructure

## Detection Rules

These detections target the LiteLLM/TeamPCP supply chain attack artifacts at PoC/advisory-specific altitude. Sigma rules cover host-level persistence and lateral movement; Snort and Suricata rules cover C2/exfiltration network traffic; YARA rules detect the malicious `.pth` and `sysmon.py` files. All rules use real (non-defanged) indicator values; compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: LiteLLM Malicious PTH File Creation

Detects creation of `litellm_init.pth` in Python site-packages, the startup persistence mechanism used by TeamPCP in v1.82.8.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 through proxy — not a rule defect); splunk convert exit 0; log_scale convert exit 0. File event on specific filename suffix is highly distinctive with minimal FP surface. -->
```yaml
title: LiteLLM Supply Chain - Malicious PTH File Creation
id: 3f8a2c1d-9e4b-4d7a-b5f6-8c3e1a0d2f9b
status: experimental
description: >
    Detects creation of litellm_init.pth in Python site-packages directories,
    a persistence mechanism used by TeamPCP in the LiteLLM supply chain attack
    (CVE-2026-33634). The .pth file executes malicious code on every Python
    interpreter startup.
references:
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://docs.litellm.ai/blog/security-update-march-2026
author: Actioner
date: 2026/08/13
tags:
    - attack.t1546
    - attack.t1059.006
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/litellm_init.pth'
    condition: selection
falsepositives:
    - Legitimate LiteLLM installations of known-safe versions (verify version is not 1.82.7 or 1.82.8)
level: critical
```

### Sigma: LiteLLM Sysmon Backdoor Persistence

Detects creation of the TeamPCP `sysmon.py` backdoor or its `sysmon.service` systemd unit used for persistent C2 polling.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 — proxy issue, not rule defect); splunk convert exit 0; log_scale convert exit 0. Paths are highly specific to this campaign. Legitimate Sysmon for Linux uses /opt/sysmon paths, not ~/.config/sysmon/. -->
```yaml
title: LiteLLM Supply Chain - Sysmon Backdoor Persistence
id: 7b4e6d2a-1c8f-4a3e-9d5b-0f7c2e8a4b6d
status: experimental
description: >
    Detects creation of the TeamPCP sysmon backdoor script or systemd service
    used for persistence in the LiteLLM supply chain attack. The attacker
    deploys sysmon.py to ~/.config/sysmon/ and a systemd user service named
    sysmon.service that polls checkmarx.zone for secondary payloads.
references:
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
author: Actioner
date: 2026/08/13
tags:
    - attack.t1543.002
    - attack.t1059.006
logsource:
    category: file_event
    product: linux
detection:
    selection_sysmon_script:
        TargetFilename|endswith: '/.config/sysmon/sysmon.py'
    selection_systemd_unit:
        TargetFilename|endswith: '/.config/systemd/user/sysmon.service'
    condition: selection_sysmon_script or selection_systemd_unit
falsepositives:
    - Legitimate Microsoft Sysmon for Linux installations use different paths
level: high
```

### Sigma: LiteLLM Kubernetes Privileged Pod Deployment

Detects kubectl commands deploying `node-setup-*` pods to `kube-system`, consistent with TeamPCP's Kubernetes lateral movement technique.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 — proxy, not rule defect); splunk convert exit 0; log_scale convert exit 0. Medium confidence: kubectl+kube-system+node-setup combo is distinctive but legitimate provisioning tools may use similar naming patterns. Requires process_creation logging on K8s management hosts. -->
```yaml
title: LiteLLM Supply Chain - Kubernetes Privileged Pod Deployment
id: a9c3f5e1-2d7b-4e8a-b6c4-3f1d0e9a8b5c
status: experimental
description: >
    Detects creation of privileged pods matching the TeamPCP naming convention
    node-setup-* in the kube-system namespace, used for lateral movement across
    Kubernetes cluster nodes during the LiteLLM supply chain attack.
references:
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
    - https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
author: Actioner
date: 2026/08/13
tags:
    - attack.t1610
    - attack.t1611
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'kubectl'
            - 'kube-system'
            - 'node-setup-'
    condition: selection
falsepositives:
    - Legitimate cluster provisioning using node-setup naming convention
level: high
```

### Sigma: LiteLLM TeamPCP C2 Domain DNS Query

Detects DNS queries to the three attacker-controlled domains used for credential exfiltration and C2 polling in the TeamPCP campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 — proxy, not rule defect); splunk convert exit 0; log_scale convert exit 0. Attacker-registered domains with no legitimate use. Note: scan.aquasecurtiy.org contains intentional typo (attacker's typosquat of aquasecurity). -->
```yaml
title: LiteLLM Supply Chain - C2 Domain DNS Query
id: d2e8f4a6-3b9c-4d1e-a7f5-6c0b8e2d4a9f
status: experimental
description: >
    Detects DNS queries to the attacker-controlled C2 domains used in the
    LiteLLM/TeamPCP supply chain attack for credential exfiltration and
    secondary payload delivery.
references:
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
author: Actioner
date: 2026/08/13
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'models.litellm.cloud'
            - 'checkmarx.zone'
            - 'scan.aquasecurtiy.org'
    condition: selection
falsepositives:
    - None expected - these are attacker-controlled domains
level: critical
```

### Snort: LiteLLM TeamPCP HTTP Exfiltration and C2

Detects HTTP POST exfiltration to `models.litellm.cloud` and GET-based C2 polling to `checkmarx.zone/raw`.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort binary not available in environment. Rules structurally validated: http service protocol, http_header/http_uri/http_method sticky buffers (underscore notation), flow:established,to_server, unique SIDs in 2100000+ range, all options semicolon-terminated. No Suricata-only keywords used. Advisory: http_header matches anywhere in the header block; http_host would be more precise for domain matching if your Snort version supports it. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM TeamPCP Exfiltration to models.litellm.cloud"; flow:established,to_server; http_header; content:"models.litellm.cloud"; fast_pattern; http_method; content:"POST"; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created 2026-08-13; sid:2100001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM TeamPCP C2 Polling checkmarx.zone"; flow:established,to_server; http_header; content:"checkmarx.zone"; fast_pattern; http_uri; content:"/raw"; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created 2026-08-13; sid:2100002; rev:1;)
```

### Suricata: LiteLLM TeamPCP HTTP and DNS C2 Detection

Detects HTTP exfiltration, C2 polling, and DNS resolution of all three attacker-controlled domains used in the TeamPCP campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Dot-notation buffers (http.host, http.method, http.uri, dns.query). All SIDs unique in 2200000+ range. Domains are attacker-controlled with no legitimate use — high precision. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM TeamPCP Exfiltration to models.litellm.cloud"; flow:established,to_server; http.host; content:"models.litellm.cloud"; http.method; content:"POST"; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-13; sid:2200001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM TeamPCP C2 Polling checkmarx.zone"; flow:established,to_server; http.host; content:"checkmarx.zone"; http.uri; content:"/raw"; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-13; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM TeamPCP DNS Query to Exfil Domain"; dns.query; content:"models.litellm.cloud"; nocase; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-13; sid:2200003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM TeamPCP DNS Query to C2 Domain"; dns.query; content:"checkmarx.zone"; nocase; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-13; sid:2200004; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - TeamPCP DNS Query to Typosquat Aqua Security"; dns.query; content:"scan.aquasecurtiy.org"; nocase; classtype:trojan-activity; reference:url,www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-13; sid:2200005; rev:1;)
```

### YARA: LiteLLM TeamPCP PTH Backdoor and Sysmon Backdoor

Detects the malicious `litellm_init.pth` launcher and the `sysmon.py` persistent backdoor via distinctive string combinations (C2 domains, file paths, encryption markers).

**PTH Backdoor —** **Status:** compile ✅ compiles · confidence: medium · sample: constructed
<!-- audit: yarac exit 0. Positive test fired on constructed sample containing published indicators (tpcp variable name, subprocess.Popen, crypto markers from Snyk/Datadog analysis); negative test (clean litellm import) quiet. revision: replaced $tpcp_marker="litellm" (matched every legitimate litellm file) with $tpcp_var="tpcp" (attacker group variable name) and added $session_key_enc="session.key.enc" (encryption temp file); downgraded confidence high→medium per critic — second condition branch still relies on common strings (subprocess.Popen, base64, AES/RSA) whose distinctiveness depends on co-occurrence with "tpcp". -->

**Sysmon Backdoor —** **Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac exit 0. Positive test fired on constructed sample (checkmarx.zone + pglog + pg_state); negative test quiet. revision: relabeled sample: fired→constructed (test used synthetic sample, not upstream malware binary). Confidence stays high — checkmarx.zone + persistence file combo is highly distinctive. -->
```yara
rule Supply_Chain_LiteLLM_TeamPCP_PTH_Backdoor
{
    meta:
        description = "Detects the malicious litellm_init.pth file used by TeamPCP in the LiteLLM supply chain attack (CVE-2026-33634)"
        author = "Actioner"
        date = "2026-08-13"
        reference = "https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/"
        hash = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
        severity = "critical"

    strings:
        $pth_exec = "subprocess.Popen" ascii
        $b64_import = "base64" ascii
        $tpcp_var = "tpcp" ascii
        $session_key_enc = "session.key.enc" ascii
        $crypto1 = "AES" ascii
        $crypto2 = "RSA" ascii
        $crypto3 = "OAEP" ascii
        $c2_domain1 = "models.litellm.cloud" ascii
        $c2_domain2 = "checkmarx.zone" ascii
        $exfil_archive = "tpcp.tar.gz" ascii
        $sysmon_path = ".config/sysmon/sysmon.py" ascii
        $k8s_lateral = "node-setup-" ascii

    condition:
        filesize < 100KB and
        (
            (2 of ($c2_domain*, $exfil_archive, $sysmon_path, $k8s_lateral)) or
            ($pth_exec and $b64_import and $tpcp_var and 1 of ($crypto*)) or
            ($pth_exec and $b64_import and $session_key_enc)
        )
}

rule Supply_Chain_LiteLLM_TeamPCP_Sysmon_Backdoor
{
    meta:
        description = "Detects the sysmon.py backdoor script used by TeamPCP for persistent C2 polling"
        author = "Actioner"
        date = "2026-08-13"
        reference = "https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/"
        hash = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"
        severity = "critical"

    strings:
        $c2_poll = "checkmarx.zone" ascii
        $c2_path = "/raw" ascii
        $pglog = "/tmp/pglog" ascii
        $pg_state = "/tmp/.pg_state" ascii
        $sysmon_svc = "sysmon.service" ascii

    condition:
        filesize < 50KB and
        $c2_poll and
        2 of ($c2_path, $pglog, $pg_state, $sysmon_svc)
}
```

## Lessons Learned

1. **Unpinned dependencies in CI/CD are a critical attack surface.** LiteLLM's pipeline installed Trivy without version pinning, allowing the compromised binary to propagate silently. Hash-pinned dependencies and verified signatures are essential for security-critical tooling.

2. **Security scanners themselves are high-value supply chain targets.** The irony of this attack -- a vulnerability scanner becoming the attack vector -- underscores that security tooling sits in highly privileged positions within CI/CD pipelines and must be treated with the same rigor as production code dependencies.

3. **Python's `.pth` mechanism is a powerful persistence vector.** The ability to execute arbitrary code on every interpreter startup, regardless of what application code runs, dramatically amplifies the blast radius of a compromised package. Organizations should monitor for `.pth` file creation in site-packages.

4. **Brief exposure windows can have massive impact.** Forty minutes was sufficient for the malicious packages to propagate through hundreds of thousands of automated CI/CD pipelines. The gap between publication and human review is the attacker's window of opportunity.

5. **Credential rotation must assume worst case.** FBI advisory FLASH-20260702-01 warns that exfiltrated credentials may be weaponized months after the initial compromise, making comprehensive rotation a necessity rather than a precaution.

## Sources

- [Datadog Security Labs - LiteLLM and Telnyx Compromised on PyPI](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/) -- primary technical analysis with detailed C2 infrastructure, payload architecture, and cross-campaign correlation
- [Snyk - How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM](https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/) -- detailed technical breakdown with file hashes, three-stage payload analysis, encryption scheme, and Kubernetes lateral movement
- [Trend Micro - Inside the LiteLLM Supply Chain Compromise](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html) -- multi-layer payload analysis, AWS API exploitation, persistence mechanism details
- [LiteLLM Official Security Update](https://docs.litellm.ai/blog/security-update-march-2026) -- official timeline, affected versions, remediation guidance, verified safe versions
- [The Hacker News - Malicious LiteLLM Releases Tied to Trivy Hack](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html) -- updated impact assessment (August 2026), CVE-2026-33634, FBI FLASH reference
- [SecurityWeek - Over 2,500 Organizations Impacted](https://www.securityweek.com/over-2500-organizations-impacted-by-litellm-supply-chain-attack/) -- CloudSEK exposure analysis, affected organization list, clarification on reconstructed exposure methodology
- [Kaspersky - Critical Supply Chain Attack on Trivy, LiteLLM, Checkmarx](https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/) -- broader TeamPCP campaign context, additional IOCs including typosquat domain
- [Legit Security - When Your Scanner Becomes the Weapon](https://www.legitsecurity.com/blog/when-your-scanner-becomes-the-weapon-from-trivy-to-litellm) -- CI/CD compromise chain details, process memory scraping technique
- [Cycode - LiteLLM Supply Chain Attack Analysis](https://cycode.com/blog/lite-llm-supply-chain-attack/) -- behavioral detection indicators, fork-bomb side effect, Kubernetes pod patterns
- [Deepwatch - Software Supply Chain Alert](https://www.deepwatch.com/labs/ca-a-26-005-software-supply-chain-attacks-and-infrastructure-risk/) -- CERT advisory context and infrastructure risk analysis

---
*Report generated by Actioner*
