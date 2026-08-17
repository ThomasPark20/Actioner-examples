# Technical Analysis Report: Trivy/LiteLLM PyPI Supply Chain Attack -- TeamPCP Campaign (CVE-2026-33634)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-17
Version: 1.0 (DRAFT)

## Executive Summary

On March 24, 2026, two trojanized versions of the LiteLLM Python package (1.82.7 and 1.82.8) were published to PyPI, containing a multi-stage credential harvesting payload that targeted cloud API keys, SSH keys, Kubernetes tokens, database credentials, and cryptocurrency wallets. The malicious packages were live for approximately 40 minutes before quarantine, but the exposure window extended to ~16:00 UTC. The root cause was not a compromise of LiteLLM itself -- it traced back to the breach of Aqua Security's Trivy scanner beginning March 19, which exposed LiteLLM's PyPI publishing token (`PYPI_PUBLISH`) through their CI/CD pipeline. The attack is attributed to the TeamPCP campaign, tracked by Google as UNC6780. CloudSEK recovered ~434,000 captured files from the attackers' infrastructure, mapping exposure to 2,100--2,500+ organizations including NVIDIA, Cisco, Deloitte, Volkswagen, and FedEx. CERT-EU assessed with high confidence that approximately 91.7 GB of compressed data was exfiltrated from a European Commission AWS account. CVE-2026-33634 was added to the CISA KEV catalog on March 26, 2026.

**Note:** This report covers the trojanized PyPI package supply chain attack. For the separate LiteLLM RCE vulnerability (CVE-2026-42271), see `summaries/2026-06-09-litellm-cve-2026-42271-rce.md`.

## Background: LiteLLM and Trivy

**LiteLLM** is a widely-used open-source Python library by BerriAI that provides a unified API gateway for calling 100+ LLM providers (OpenAI, Anthropic, Azure, etc.). It is commonly deployed in CI/CD pipelines, production AI services, and developer environments where it naturally has access to API keys and cloud credentials.

**Trivy** is Aqua Security's open-source vulnerability scanner used in CI/CD pipelines for container image, filesystem, and code scanning. LiteLLM's CI/CD pipeline used Trivy for security scanning without version pinning, creating the dependency chain that the attackers exploited.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Late February 2026 | Initial Trivy CI compromise via misconfigured `pull_request_target` workflow; `aqua-bot` PAT exfiltrated |
| 2026-03-01 | First disclosure of Trivy compromise; incomplete credential rotation by Aqua Security |
| 2026-03-19 17:43 | Attackers force-push malicious commits to 76 of 77 `trivy-action` version tags and all 7 `setup-trivy` tags |
| 2026-03-19 18:05 | First credential collection from compromised Trivy builds |
| 2026-03-20 | Malicious npm packages deployed via CanisterWorm across @EmilGroup, @opengov scopes |
| 2026-03-22 | Malicious Trivy Docker Hub images active |
| 2026-03-23 | Checkmarx KICS GitHub Action compromised; `models[.]litellm[.]cloud` domain registered |
| 2026-03-24 10:39 | Malicious `litellm` 1.82.7 published to PyPI |
| 2026-03-24 10:52 | Malicious `litellm` 1.82.8 published to PyPI (13-minute iteration) |
| 2026-03-24 11:48 | Security researcher reports fork-bomb crash from .pth subprocess spawning |
| 2026-03-24 12:44-12:46 | Attacker deploys botnet (88 comments from 73 accounts in 102 seconds) to close GitHub issue #24512 |
| 2026-03-24 ~14:00 | Community detection via GitHub issue analysis |
| 2026-03-24 ~13:38-17:00 | PyPI quarantines then removes malicious versions |
| 2026-03-26 | CVE-2026-33634 added to CISA Known Exploited Vulnerabilities catalog |
| 2026-03-27 | Malicious `telnyx` 4.87.1 and 4.87.2 published to PyPI (related TeamPCP operation) |
| 2026-03-30 | Clean LiteLLM v1.83.0 released through new CI/CD v2 pipeline |

## Root Cause: Trivy CI/CD Compromise

The attack chain originated with a misconfigured `pull_request_target` GitHub Actions workflow in the Trivy repository. An automated bot account (`MegaGame10418` / `hackerbot-claw`) submitted a pull request that exploited this workflow to execute code in the context of the Trivy repository, exfiltrating the `aqua-bot` Personal Access Token from the CI runner's memory (`Runner.Worker` process). After an initial disclosure on March 1, Aqua Security performed credential rotation, but residual access paths remained -- the attackers retained enough access to force-push malicious commits to 76 of 77 release tags in `trivy-action` and all 7 tags in `setup-trivy` on March 19.

LiteLLM's CI/CD pipeline pulled Trivy without version pinning. When the compromised Trivy build ran in LiteLLM's CI environment, it harvested the `PYPI_PUBLISH` token from the GitHub Actions runner environment, enabling the attacker to publish directly to PyPI under the legitimate LiteLLM maintainer account (`krrishdholakia`), bypassing all normal review controls.

## Technical Analysis of the Malicious Payload

### 1. Delivery Mechanism -- .pth Startup Hook and proxy_server.py Injection

**Version 1.82.7** contained the malicious payload injected directly into `litellm/proxy/proxy_server.py` as a base64-encoded blob. The payload executed whenever anything imported `litellm.proxy`.

**Version 1.82.8** added `litellm_init.pth` (34,628 bytes, SHA-256: `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238`) to the Python `site-packages/` directory. Python's `.pth` file mechanism causes this file to execute on **every** interpreter startup -- no import required. This fires for `pip install`, `python -c`, IDE language servers, and any Python process in the environment. The file was correctly declared in the wheel's `RECORD` file, so it passed pip's hash verification.

### 2. Multi-Layer Payload Architecture

The payload used a three-layer base64-encoded structure to evade static detection:

- **Layer 0 (Launcher):** Single-line Python executing base64-decoded Layer 1 via `subprocess.Popen`
- **Layer 1 (Orchestrator):** Contains hardcoded RSA-4096 public key, embeds Layers 2-3, handles AES-256-CBC encryption (PBKDF2 key derivation) and exfiltration orchestration
- **Layer 2 (Collector):** Credential harvester targeting 50+ categories of secrets with a 10-second per-command timeout
- **Layer 3 (Persistence):** Systemd-based C2 polling daemon

### 3. Credential Harvesting -- Targeted File Paths and Variables

The collector (Layer 2) systematically harvested:

**SSH Keys:**
- `/home/*/.ssh/id_*`, `/root/.ssh/id_*`, `/etc/ssh/ssh_host_*`

**Cloud Credentials:**
- AWS: `~/.aws/credentials`, `~/.aws/config` + Secrets Manager (`ListSecrets`, `GetSecretValue`) + SSM Parameter Store (`DescribeParameters`) via embedded SigV4 signing; EC2 IMDS v1 and v2 queries
- GCP: `~/.config/gcloud/*`, `$GOOGLE_APPLICATION_CREDENTIALS`
- Azure: `~/.azure/*`, `$AZURE_*` environment variables

**Kubernetes:**
- `~/.kube/config`, `/var/run/secrets/kubernetes.io/serviceaccount/` token + cluster-wide secret enumeration via `/api/v1/secrets` and `/api/v1/namespaces/{ns}/secrets`

**Application Configs:**
- `.env`, `.env.local`, `.env.production`, `.env.staging` (recursive to 6 directory levels)
- `~/.git-credentials`, `.gitconfig`, `~/.docker/config.json`, `~/.npmrc`
- `.pgpass` (PostgreSQL), `.my.cnf` (MySQL), `.mongorc.js` (MongoDB), `.netrc`

**API Keys (environment variables):**
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_*`, `AZURE_*`, `KUBECONFIG`, `NPM_TOKEN`, `GITHUB_ACTIONS`

**Cryptocurrency Wallets:**
- Bitcoin, Ethereum, Solana (`validator-keypair.json`, `authorized-withdrawer-keypair.json`), Exodus, Electrum

**System Files:**
- `/etc/passwd`, `/etc/shadow`, `/var/log/auth.log`, `/var/log/secure` (last 200 entries)
- Shell history files, CI/CD configs (Jenkins, `.gitlab-ci.yml`, `.travis.yml`), Terraform state files, Ansible playbooks

### 4. C2 Infrastructure

**Primary Exfiltration:** `models[.]litellm[.]cloud` (registered March 23, 2026 via Spaceship, Inc.; hosted by DEMENIN B.V.) -- HTTPS POST with encrypted payload. HTTP header `X-Filename: tpcp.tar.gz` identifies the exfiltration stream.

**Secondary C2 Polling:** `checkmarx[.]zone` -- the persistence daemon polls `hxxps://checkmarx[.]zone/raw` every 50 minutes (3,000 seconds, with 5-minute initial sleep) for follow-on payloads. At analysis time, the endpoint returned YouTube URLs (kill switch), but can switch to live payloads at any time.

**Fallback Exfiltration:** If direct C2 fails, the payload creates a public GitHub repository named `tpcp-docs` under the victim's GitHub account and uploads encrypted data as release assets tagged `data-<timestamp>`.

**Related Campaign Infrastructure:**
- `aquasecurtiy[.]org` (Trivy typosquat, note misspelling of "security"), resolving to `45[.]148[.]10[.]212`
- `83[.]142[.]209[.]203:8080` (Telnyx second-stage server)
- `83[.]142[.]209[.]11` (AS205759 - Ghosty Networks LLC)
- `46[.]151[.]182[.]203` (AS205759 - DEMENIN B.V.)
- `tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io` (ICP canister C2 for CanisterWorm)
- Cloudflare tunnels: `championships-peoples-point-cassette[.]trycloudflare[.]com`, `investigation-launches-hearings-copying[.]trycloudflare[.]com`, `souls-entire-defined-routes[.]trycloudflare[.]com`

### 5. Encryption and Exfiltration Protocol

- 32-byte random AES-256-CBC session key generated via `openssl rand`
- PBKDF2 key derivation
- Session key wrapped with hardcoded RSA-4096-OAEP public key (prefix: `MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA...`)
- Data bundled as `tpcp.tar.gz` containing `payload.enc` + `session.key.enc`
- Exfiltrated via HTTPS POST with `curl`
- Same RSA key pair used across Trivy, KICS, and LiteLLM operations (campaign linkage)
- TLS configuration consistent with AdaptixC2 framework (Go-based C2)

### 6. Persistence Mechanism

**Local Backdoor:**
- Script: `~/.config/sysmon/sysmon.py` (SHA-256: `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a`)
- Systemd unit: `~/.config/systemd/user/sysmon.service` (description: "System Telemetry Service")
- Activation: `systemctl --user daemon-reload && systemctl --user enable --now sysmon.service` (Restart=always)
- Polls `hxxps://checkmarx[.]zone/raw`, downloads to `/tmp/pglog`, makes executable, runs as background process
- State tracking: `/tmp/.pg_state`
- Kill switch: response containing "youtube" string deactivates globally

### 7. Kubernetes Lateral Movement

When a Kubernetes service account token is found at the standard mount path:

**Non-Iranian systems:** Deploys `host-provisioner-std` DaemonSet -- creates privileged pods named `node-setup-{node_name}` (truncated to 35 chars) in `kube-system` namespace using `alpine:latest` image with `hostPID: true`, `hostNetwork: true`, and host filesystem mounted at `/host`. Installs `sysmon.py` backdoor on the underlying node via chroot.

**Iranian systems (geofenced):** Deploys `host-provisioner-iran` DaemonSet with `kamikaze` container that deletes the host filesystem and force-reboots nodes (destructive wiper).

### 8. Anti-Forensics / Evasion Techniques

- Three-layer base64 encoding for static detection evasion
- In-memory execution minimizes disk artifacts
- Locale/region geofencing to alter behavior by country
- Service masquerading as legitimate "System Telemetry Service"
- `.pth` mechanism is an obscure Python feature; newer Python versions skip hidden `.pth` files
- Kill switch allows global deactivation without per-host commands
- Bot army (88 comments from 73 accounts in 102 seconds) deployed to suppress disclosure on GitHub
- Published using legitimate credentials -- no hash mismatch, no typosquatted package name, no suspicious domains in the package metadata

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.82.7 | Payload in `proxy_server.py`; base64-encoded credential harvester |
| litellm (PyPI) | 1.82.8 | Added `litellm_init.pth` startup hook + payload in `proxy_server.py` |
| telnyx (PyPI) | 4.87.1 | Related TeamPCP operation; XOR-encrypted payload in WAV file |
| telnyx (PyPI) | 4.87.2 | Related TeamPCP operation |
| trivy (Docker) | 0.69.4 | Compromised Docker images on Docker Hub, GHCR, AWS ECR |
| trivy-action (GitHub) | 76 of 77 tags | Force-pushed malicious commits |
| setup-trivy (GitHub) | all 7 tags | Force-pushed malicious commits |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux/macOS | `site-packages/litellm_init.pth` | `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238` | Malicious .pth startup hook (34,628 bytes) |
| Linux/macOS | `litellm/proxy/proxy_server.py` | `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b` | Injected payload in proxy server |
| Linux | `~/.config/sysmon/sysmon.py` | `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a` | Persistence backdoor script |
| Linux | `~/.config/systemd/user/sysmon.service` | -- | Systemd unit ("System Telemetry Service") |
| Linux | `/tmp/pglog` | -- | Downloaded second-stage payload |
| Linux | `/tmp/.pg_state` | -- | Beacon state file |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `models[.]litellm[.]cloud` | Primary credential exfiltration endpoint |
| Domain | `checkmarx[.]zone` | C2 polling endpoint (payload delivery) |
| Domain | `aquasecurtiy[.]org` | Trivy typosquat domain (note misspelled "security") |
| IP | `83[.]142[.]209[.]203:8080` | Telnyx second-stage payload server |
| IP | `83[.]142[.]209[.]11` | Campaign infrastructure (AS205759) |
| IP | `46[.]151[.]182[.]203` | Campaign infrastructure (AS205759 - DEMENIN B.V.) |
| IP | `45[.]148[.]10[.]212` | Resolves from `scan[.]aquasecurtiy[.]org` |
| Domain | `tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io` | ICP canister C2 (CanisterWorm) |
| Domain | `championships-peoples-point-cassette[.]trycloudflare[.]com` | Cloudflare tunnel C2 |
| Domain | `investigation-launches-hearings-copying[.]trycloudflare[.]com` | Cloudflare tunnel C2 |
| Domain | `souls-entire-defined-routes[.]trycloudflare[.]com` | Cloudflare tunnel C2 |
| URL Pattern | `hxxps://models[.]litellm[.]cloud/` | HTTPS POST exfiltration with `X-Filename: tpcp.tar.gz` header |
| URL Pattern | `hxxps://checkmarx[.]zone/raw` | C2 polling endpoint (every 50 min) |
| URL Pattern | `hxxp://83[.]142[.]209[.]203:8080/ringtone.wav` | Telnyx WAV-embedded payload |

### Behavioral

- Python `.pth` file auto-executing on interpreter startup (no import required)
- Subprocess spawning from `.pth` execution causing uncontrolled fork bomb (detection trigger in v1.82.8)
- Systemd user service `sysmon.service` with `Restart=always` and "System Telemetry Service" description
- Kubernetes API calls to `/api/v1/secrets` for cluster-wide secret enumeration
- Privileged pod creation (`node-setup-*`) in `kube-system` namespace with `hostPID: true`, `hostNetwork: true`
- GitHub repository creation named `tpcp-docs` or `docs-tpcp` as exfiltration fallback
- AES-256-CBC encrypted data exfiltrated as `tpcp.tar.gz` via HTTPS POST
- EC2 IMDS v1/v2 queries for credential retrieval with embedded SigV4 signing
- Geofenced destructive behavior (wiper) targeting Iranian systems

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized LiteLLM PyPI packages published via stolen CI/CD credentials |
| T1059.006 | Command and Scripting Interpreter: Python | Multi-layer base64-encoded Python payload executed via .pth hook |
| T1547 | Boot or Logon Autostart Execution | `.pth` file mechanism executes on every Python interpreter startup |
| T1543.002 | Create or Modify System Process: Systemd Service | `sysmon.service` installed as persistent user systemd unit |
| T1036.004 | Masquerading: Masquerade Task or Service | Service named "System Telemetry Service" and script named `sysmon.py` |
| T1005 | Data from Local System | Systematic harvesting of SSH keys, cloud creds, .env files, shell history |
| T1552.001 | Unsecured Credentials: Credentials In Files | Targeting `.aws/credentials`, `.kube/config`, `.env`, `.pgpass`, etc. |
| T1552.004 | Unsecured Credentials: Private Keys | SSH private key collection from `~/.ssh/id_*` |
| T1078.004 | Valid Accounts: Cloud Accounts | AWS IMDS queries and Secrets Manager enumeration using harvested creds |
| T1041 | Exfiltration Over C2 Channel | AES-256/RSA-4096 encrypted exfiltration to `models[.]litellm[.]cloud` |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST for exfiltration, HTTPS GET for C2 polling |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-CBC with RSA-4096 wrapped session keys |
| T1610 | Deploy Container | Privileged `node-setup-*` pods deployed in `kube-system` for lateral movement |
| T1611 | Escape to Host | Host filesystem mounted in privileged pods; backdoor installed via chroot |
| T1530 | Data from Cloud Storage Object | AWS Secrets Manager and SSM Parameter Store enumeration |
| T1583.001 | Acquire Infrastructure: Domains | `models[.]litellm[.]cloud` registered day before attack; `checkmarx[.]zone` |

## Impact Assessment

**Breadth:** 2,100--2,500+ organizations with potential exposure. CloudSEK recovered ~434,000 captured files from attacker infrastructure. Approximately 95% of affected organizations were compromised via the Trivy vector (active for 5 days) before the LiteLLM packages appeared (40-minute window). High-profile entities identified in captured data include NVIDIA, Cisco, Deloitte, Volkswagen, FedEx, Siemens, and X Corp.

**Depth:** The payload harvested 50+ categories of secrets including cloud provider credentials (AWS, GCP, Azure), Kubernetes cluster secrets, SSH keys, database passwords, cryptocurrency wallets, and CI/CD tokens. One organization had approximately 3,477 stolen secrets. CERT-EU assessed with high confidence that ~91.7 GB of compressed data was exfiltrated from a European Commission AWS account.

**Stealth:** The attack used legitimate publishing credentials -- there was no hash mismatch, no typosquatted package name, and no suspicious metadata. Standard package integrity checks would not detect the compromise. The .pth mechanism is obscure and not commonly monitored.

**Severity:** CVE-2026-33634 received a CVSS4B score of 9.4. Added to CISA KEV catalog March 26, 2026.

## Detection & Remediation

### Immediate Detection

```bash
# Check for malicious .pth file
find / -name "litellm_init.pth" 2>/dev/null

# Check for persistence backdoor
ls -la ~/.config/sysmon/sysmon.py 2>/dev/null
systemctl --user status sysmon.service 2>/dev/null

# Check for beacon state files
ls -la /tmp/pglog /tmp/.pg_state 2>/dev/null

# Check installed LiteLLM version
pip show litellm 2>/dev/null | grep -i version

# Check for C2 connections in DNS logs
grep -E "models\.litellm\.cloud|checkmarx\.zone|aquasecurtiy\.org" /var/log/syslog /var/log/dns* 2>/dev/null

# Check for tpcp-docs GitHub repos (exfiltration fallback)
# Review GitHub account for unexpected "tpcp-docs" or "docs-tpcp" repositories

# Check Kubernetes for lateral movement
kubectl get pods -n kube-system | grep "node-setup-"
```

### Remediation

1. **Contain:** Isolate any system that ran LiteLLM 1.82.7 or 1.82.8, or any Trivy version pulled between March 19-24, 2026
2. **Eradicate:** Remove `litellm_init.pth` from all `site-packages/` directories; disable and remove `sysmon.service` and `~/.config/sysmon/sysmon.py`; delete `/tmp/pglog` and `/tmp/.pg_state`
3. **Rotate ALL credentials:** API keys (OpenAI, Anthropic, Azure, etc.), AWS access keys, GCP service accounts, Azure credentials, SSH keys, Kubernetes tokens, database passwords, GitHub tokens, npm tokens, Docker registry credentials, Slack/Discord webhooks -- treat every secret on the affected system as compromised
4. **Audit Kubernetes clusters:** Check for `node-setup-*` pods in `kube-system`; review all cluster secrets for unauthorized access; check nodes for `sysmon.py` persistence
5. **Pin to safe version:** Use LiteLLM >= 1.83.0 (released via new CI/CD v2 pipeline) or pin to <= 1.82.6
6. **Review GitHub:** Check for unauthorized `tpcp-docs` repositories; review release assets for `data-<timestamp>` tags

### Long-Term Hardening

- **Pin CI/CD dependencies** to specific versions/hashes -- never pull `latest` for security-critical tools
- **Use hash-pinned actions** in GitHub Actions (`uses: action@sha256:...`) instead of mutable tags
- **Implement package provenance verification** (SLSA, Sigstore) for all PyPI/npm dependencies
- **Monitor .pth files** in Python environments -- they are a known persistence vector
- **Restrict PyPI publishing tokens** to specific packages with short expiry and IP restrictions
- **Rotate CI/CD secrets immediately** after any upstream supply chain incident -- do not assume partial rotation is sufficient

## Detection Rules

These detections target the TeamPCP/LiteLLM supply chain attack (CVE-2026-33634) at PoC/advisory-specific altitude, keying on the campaign's distinctive artifacts: the malicious `.pth` file, persistence paths, C2 domains, and exfiltration patterns. All Sigma rules convert to Splunk and CrowdStrike LogScale; compiles != fires -- verify in your pipeline.

### Sigma: TeamPCP Malicious litellm_init.pth File Creation

Detects creation of `litellm_init.pth` in Python site-packages, the startup hook used by the trojanized LiteLLM 1.82.8 package.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK network fetch 403, not a rule error); splunk convert exit 0; log_scale convert exit 0. File path is unique to this attack; no legitimate use of this filename. -->
```yaml
title: TeamPCP Malicious litellm_init.pth File Creation
id: 8e3c1a4b-7f2d-4e89-b6a1-c5d9f0e28473
status: experimental
description: >
    Detects creation of litellm_init.pth in Python site-packages directories,
    consistent with the TeamPCP supply chain attack (CVE-2026-33634) that used
    a .pth startup hook to execute credential harvesting on every Python
    interpreter start.
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
    - https://docs.litellm.ai/blog/security-update-march-2026
author: Actioner
date: 2026/08/17
tags:
    - attack.t1195.002
    - attack.t1547
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/litellm_init.pth'
    condition: selection
falsepositives:
    - Legitimate LiteLLM installations using versions 1.82.7 or 1.82.8 (these versions are themselves malicious)
level: critical
```

### Sigma: TeamPCP Sysmon.py Persistence Backdoor Installation

Detects creation of `sysmon.py` or `sysmon.service` in user config directories, the persistence mechanism masquerading as "System Telemetry Service."
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk convert exit 0; log_scale convert exit 0. Paths ~/.config/sysmon/sysmon.py and ~/.config/systemd/user/sysmon.service are distinctive to this campaign. Minor FP risk from custom monitoring tools using the same naming convention in user-level config dirs. -->
```yaml
title: TeamPCP Sysmon.py Persistence Backdoor Installation
id: a2f9b7c4-3e81-4d65-9c0a-d8e6f1b54729
status: experimental
description: >
    Detects creation of sysmon.py or sysmon.service in user config directories,
    consistent with the TeamPCP campaign (CVE-2026-33634) persistence mechanism
    that masquerades as System Telemetry Service and polls checkmarx.zone for
    follow-on payloads.
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
author: Actioner
date: 2026/08/17
tags:
    - attack.t1543.002
    - attack.t1036.004
logsource:
    category: file_event
    product: linux
detection:
    selection_sysmon_script:
        TargetFilename|endswith: '/.config/sysmon/sysmon.py'
    selection_sysmon_service:
        TargetFilename|endswith: '/.config/systemd/user/sysmon.service'
    condition: selection_sysmon_script or selection_sysmon_service
falsepositives:
    - Custom monitoring tools named sysmon deployed to user config directories
level: high
```

### Sigma: TeamPCP C2 Domain DNS Query

Detects DNS queries to the campaign's C2 domains: `models.litellm.cloud` (exfiltration), `checkmarx.zone` (payload polling), and `aquasecurtiy.org` (Trivy typosquat).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk convert exit 0; log_scale convert exit 0. Domains are attacker-controlled with no legitimate use. aquasecurtiy.org is a deliberate misspelling of "aquasecurity". -->
```yaml
title: TeamPCP C2 Domain DNS Query
id: d4e8c2a1-5b93-4f76-8d0e-a7c3f9b16285
status: experimental
description: >
    Detects DNS queries to known TeamPCP campaign C2 domains used for credential
    exfiltration (models.litellm.cloud) and payload polling (checkmarx.zone),
    indicators from the LiteLLM/Trivy supply chain attack (CVE-2026-33634).
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
author: Actioner
date: 2026/08/17
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
            - 'aquasecurtiy.org'
    condition: selection
falsepositives:
    - None expected - these are attacker-controlled domains
level: critical
```

### Sigma: TeamPCP Kubernetes Privileged node-setup Pod Creation

Detects Kubernetes API calls creating privileged pods named `node-setup-*` in `kube-system`, the lateral movement pattern used to compromise cluster nodes.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: splunk convert exit 0; log_scale convert exit 0. Proxy log source; requires API audit logging. Medium confidence due to potential for legitimate node-setup naming in custom operators, though the combination with hostPID+privileged narrows it. -->
```yaml
title: TeamPCP Kubernetes Privileged node-setup Pod Creation
id: f1b3d7e9-4a26-4c80-95d2-e8c0a6f47b13
status: experimental
description: >
    Detects creation of privileged pods named node-setup-* in kube-system namespace,
    consistent with the TeamPCP campaign (CVE-2026-33634) Kubernetes lateral movement
    that mounts host filesystem and installs persistent backdoors on cluster nodes.
references:
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
    - https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
author: Actioner
date: 2026/08/17
tags:
    - attack.t1610
    - attack.t1611
logsource:
    category: proxy
detection:
    selection_uri:
        cs-uri-stem|contains|all:
            - '/api/v1/namespaces/kube-system/pods'
        cs-method: 'POST'
    selection_body:
        cs-body|contains|all:
            - 'node-setup-'
            - 'hostPID'
            - 'privileged'
    condition: selection_uri and selection_body
falsepositives:
    - Legitimate Kubernetes operators deploying privileged pods with node-setup prefix in kube-system
level: high
```

### Snort: TeamPCP C2 DNS Query to models.litellm.cloud

Detects DNS queries for the primary TeamPCP exfiltration domain using DNS wire-format label-length encoding.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -R tpcp.rules -T exit 0. DNS label encoding: |06|models (6 bytes) |07|litellm (7 bytes) |05|cloud (5 bytes) |00| (root). -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - TeamPCP C2 DNS Query to models.litellm.cloud"; flow:to_server; content:"|06|models|07|litellm|05|cloud|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/; reference:cve,2026-33634; metadata:author Actioner, created 2026-08-17; sid:2100001; rev:1;)
```

### Snort: TeamPCP C2 DNS Query to checkmarx.zone

Detects DNS queries for the TeamPCP C2 polling domain used by the persistence backdoor.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0. DNS label encoding: |09|checkmarx (9 bytes) |04|zone (4 bytes) |00| (root). -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - TeamPCP C2 DNS Query to checkmarx.zone"; flow:to_server; content:"|09|checkmarx|04|zone|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/; reference:cve,2026-33634; metadata:author Actioner, created 2026-08-17; sid:2100002; rev:1;)
```

### Snort: TeamPCP Exfiltration Header X-Filename tpcp.tar.gz

Detects HTTP requests with the distinctive `X-Filename: tpcp.tar.gz` header used for encrypted credential exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0. Header content match uses hex colon-space (|3a 20|) separator. fast_pattern on the distinctive tpcp.tar.gz value. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TeamPCP Exfiltration Header X-Filename tpcp.tar.gz"; flow:established, to_server; http_header; content:"X-Filename|3a 20|tpcp.tar.gz", fast_pattern; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/; reference:cve,2026-33634; metadata:author Actioner, created 2026-08-17; sid:2100003; rev:1;)
```

### Suricata: TeamPCP C2 DNS Query to models.litellm.cloud

Detects DNS queries for the primary TeamPCP exfiltration domain using Suricata's `dns.query` buffer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. dns.query buffer matches the query name directly without wire-format encoding. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - TeamPCP C2 DNS Query to models.litellm.cloud"; flow:to_server; dns.query; content:"models.litellm.cloud"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-17; sid:2200001; rev:1;)
```

### Suricata: TeamPCP C2 DNS Query to checkmarx.zone

Detects DNS queries for the TeamPCP C2 polling domain used by the persistence backdoor.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - TeamPCP C2 DNS Query to checkmarx.zone"; flow:to_server; dns.query; content:"checkmarx.zone"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-17; sid:2200002; rev:1;)
```

### Suricata: TeamPCP Trivy Typosquat Domain aquasecurtiy.org

Detects DNS queries for the Trivy typosquat domain (deliberately misspelled "aquasecurtiy" instead of "aquasecurity").
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Domain is a deliberate misspelling; no legitimate use. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - TeamPCP Trivy Typosquat Domain aquasecurtiy.org"; flow:to_server; dns.query; content:"aquasecurtiy.org"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-17; sid:2200003; rev:1;)
```

### Suricata: TeamPCP Exfiltration Header X-Filename tpcp.tar.gz

Detects HTTP requests with the `X-Filename: tpcp.tar.gz` header used for encrypted credential exfiltration to C2.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. http.header buffer with content match on distinctive header name and value. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TeamPCP Exfiltration Header X-Filename tpcp.tar.gz"; flow:established,to_server; http.header; content:"X-Filename"; content:"tpcp.tar.gz"; distance:0; within:20; fast_pattern; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-17; sid:2200004; rev:1;)
```

### YARA: TeamPCP LiteLLM .pth Payload

Detects the malicious `litellm_init.pth` file by matching distinctive string combinations from the TeamPCP payload including C2 domains, persistence paths, and the campaign's RSA public key prefix.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive sample (published strings: models.litellm.cloud, tpcp.tar.gz, .config/sysmon/sysmon.py, TeamPCP, import subprocess, base64) fired; negative sample (benign strings) quiet. SHA-256 hash 71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238 from Snyk analysis. RSA key prefix is the same across Trivy/KICS/LiteLLM operations (campaign linkage). -->
```yara
rule Supply_Chain_TeamPCP_LiteLLM_Pth_Payload
{
    meta:
        description = "Detects the malicious litellm_init.pth file from the TeamPCP supply chain attack (CVE-2026-33634) that harvests cloud credentials, SSH keys, and Kubernetes tokens"
        author = "Actioner"
        date = "2026-08-17"
        reference = "https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/"
        hash = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
        severity = "critical"

    strings:
        $pth_exec = "import subprocess" ascii
        $b64_layer = "base64" ascii
        $c2_domain = "models.litellm.cloud" ascii
        $c2_poll = "checkmarx.zone" ascii
        $exfil_name = "tpcp.tar.gz" ascii
        $sysmon_path = ".config/sysmon/sysmon.py" ascii
        $service_desc = "System Telemetry Service" ascii
        $rsa_prefix = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA" ascii
        $teampcp = "TeamPCP" ascii nocase
        $pglog = "/tmp/pglog" ascii
        $pg_state = "/tmp/.pg_state" ascii

    condition:
        filesize < 100KB and
        (
            3 of ($c2_domain, $c2_poll, $exfil_name, $sysmon_path, $service_desc, $teampcp) or
            ($rsa_prefix and 1 of ($c2_domain, $c2_poll, $exfil_name)) or
            ($pth_exec and $b64_layer and 2 of ($c2_domain, $c2_poll, $sysmon_path, $pglog, $pg_state))
        )
}
```

### YARA: TeamPCP Sysmon Persistence Backdoor

Detects the `sysmon.py` persistence backdoor that polls `checkmarx.zone` for follow-on payloads and uses a YouTube-string kill switch.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive sample (published strings: checkmarx.zone, /tmp/pglog, /tmp/.pg_state, System Telemetry Service, youtube, tpcp) fired; negative sample quiet. SHA-256 hash 6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a from Snyk analysis. -->
```yara
rule Supply_Chain_TeamPCP_Sysmon_Backdoor
{
    meta:
        description = "Detects the TeamPCP sysmon.py persistence backdoor that polls checkmarx.zone for follow-on payloads and masquerades as System Telemetry Service"
        author = "Actioner"
        date = "2026-08-17"
        reference = "https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/"
        hash = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"
        severity = "critical"

    strings:
        $c2_poll = "checkmarx.zone" ascii
        $dl_path = "/tmp/pglog" ascii
        $state_file = "/tmp/.pg_state" ascii
        $sysmon_svc = "System Telemetry Service" ascii
        $kill_switch = "youtube" ascii
        $tpcp = "tpcp" ascii

    condition:
        filesize < 50KB and
        (
            ($c2_poll and 1 of ($dl_path, $state_file, $sysmon_svc)) or
            ($c2_poll and $kill_switch and $tpcp)
        )
}
```

## Lessons Learned

1. **Supply chain trust is transitive:** LiteLLM was not directly compromised -- it was a downstream victim of the Trivy breach. Organizations must audit not just their own dependencies but the security posture of their CI/CD tooling and scanning infrastructure.

2. **Incomplete credential rotation is worse than none:** Aqua Security's partial rotation after the initial March 1 disclosure left residual access paths that the attacker exploited 18 days later. When a CI/CD compromise is detected, all credentials -- including service account tokens, PATs, and publishing tokens -- must be rotated atomically.

3. **Python .pth files are a blind spot:** The `.pth` mechanism is a legitimate but obscure Python feature that executes code on every interpreter startup without requiring an import. Most security monitoring does not track `.pth` file creation in `site-packages/`, making it an effective persistence vector. Newer Python versions mitigate this by skipping hidden `.pth` files.

4. **Legitimate credentials defeat integrity checks:** Because the malicious packages were published using stolen but valid credentials, standard package integrity verification (hash checks, signature verification) provided no protection. Package provenance frameworks (SLSA, Sigstore) that attest to the build process -- not just the publisher identity -- are needed.

5. **The 40-minute window is misleading:** While the malicious PyPI packages were live for approximately 40 minutes, the broader Trivy compromise was active for 5+ days (March 19-24), and the persistence backdoor (`sysmon.service`) continues to operate on any compromised system that has not been remediated. The exfiltrated credentials remain usable until rotated.

## Sources

- [Datadog Security Labs - TeamPCP Supply Chain Campaign](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/) -- Primary technical analysis with IOCs, payload architecture, and full campaign timeline
- [Trend Micro - Inside the LiteLLM Supply Chain Compromise](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html) -- Detailed payload analysis with file hashes, credential harvesting paths, C2 infrastructure, and Kubernetes lateral movement
- [Snyk - Poisoned Security Scanner Backdooring LiteLLM](https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/) -- Technical analysis of .pth mechanism, exfiltration encryption, persistence details, and file hashes
- [Cycode - LiteLLM Supply Chain Attack](https://cycode.com/blog/lite-llm-supply-chain-attack/) -- Three-stage payload analysis and Kubernetes attack patterns
- [LiteLLM Official Security Update](https://docs.litellm.ai/blog/security-update-march-2026) -- Vendor advisory with affected versions, remediation steps, and CI/CD v2 pipeline details
- [The Hacker News - Malicious LiteLLM Releases](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html) -- News coverage with CloudSEK data recovery details, UNC6780 attribution, and CERT-EU findings
- [SecurityWeek - Trivy Behind the 2500-Org Compromise](https://www.securityweek.com/trivy-not-litellm-behind-the-2500-org-compromise/) -- Root cause attribution to Trivy and impact scope
- [GitGuardian - Trivy's March Supply Chain Attack](https://blog.gitguardian.com/trivys-march-supply-chain-attack-shows-where-secret-exposure-hurts-most/) -- Trivy compromise timeline and credential rotation failure analysis

---
*Report generated by Actioner*
