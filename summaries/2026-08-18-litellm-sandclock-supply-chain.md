# Technical Analysis Report: SANDCLOCK LiteLLM Supply Chain Attack (2026-08-18)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-18
Version: 1.0

## Executive Summary

On March 24, 2026, the financially motivated threat actor TeamPCP (tracked by Google as UNC6780) published two malicious versions of the LiteLLM Python package (1.82.7 and 1.82.8) to PyPI after stealing the maintainer's publishing credentials through a prior upstream compromise of the Trivy GitHub Action. The backdoor, designated SANDCLOCK, exploited Python's `.pth` startup file mechanism to execute a multi-layered credential stealer on every interpreter invocation -- without requiring an explicit `import litellm` -- harvesting SSH keys, cloud provider credentials (AWS, GCP, Azure), Kubernetes tokens, CI/CD secrets, and AI provider API keys. Stolen data was encrypted with AES-256-CBC under a hardcoded RSA-4096 public key and exfiltrated to the attacker-controlled domain `models[.]litellm[.]cloud`. A persistent backdoor (`sysmon.py` registered as a systemd user service) polled `checkmarx[.]zone` for follow-on payloads. The malicious packages were live on PyPI for approximately 40 minutes before quarantine, but downstream CI/CD cache and dependency resolution propagated them across an estimated 2,500+ organizations and 434,000 CI/CD pipelines, resulting in approximately 415,427 credential capture files spanning 2,038 repositories. CVE-2026-33634 was added to CISA's Known Exploited Vulnerabilities catalog on March 26, 2026; the FBI issued FLASH-20260702-01 on July 2, 2026.

## Background: LiteLLM

LiteLLM is a widely adopted open-source Python library (maintained by BerriAI) that provides a unified API gateway for over 100 LLM providers (OpenAI, Anthropic, Azure, AWS Bedrock, etc.). It is commonly deployed in CI/CD pipelines, cloud-native infrastructure, and production AI proxy servers, making it a high-value supply chain target. LiteLLM's CI pipeline used the `aquasecurity/trivy-action` GitHub Action for security scanning, which became the upstream entry point for the attack.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-03-19 17:43 | TeamPCP force-pushes malicious commits to 76 of 77 `aquasecurity/trivy-action` release tags via un-revoked automation token |
| 2026-03-19 -- 2026-03-20 | Peak credential harvesting from Trivy Action compromise (240k+ capture files) |
| 2026-03-23 | Attacker registers `models[.]litellm[.]cloud` exfiltration domain; compromises Checkmarx KICS (all 35 tags) |
| 2026-03-24 10:39 | Malicious `litellm==1.82.7` published to PyPI (payload in `proxy_server.py`) |
| 2026-03-24 10:52 | Malicious `litellm==1.82.8` published to PyPI (adds `litellm_init.pth` mechanism) |
| 2026-03-24 ~16:00 | Both malicious versions quarantined and removed from PyPI (~40 min window) |
| 2026-03-26 | CVE-2026-33634 added to CISA KEV catalog |
| 2026-07-02 | FBI FLASH advisory FLASH-20260702-01 issued |
| 2026-08-12--17 | Public reporting by Resecurity, CloudSEK, Snyk, Trend Micro, and others |

## Root Cause: Upstream Trivy GitHub Action Compromise

The attack chain originated from an un-revoked automation token for the `aquasecurity/trivy-action` GitHub repository. TeamPCP used this token to force-push malicious commits to nearly all release tags of the Trivy security scanner GitHub Action. LiteLLM's CI pipeline used an unpinned reference to `trivy-action`, automatically consuming the compromised version. The poisoned Trivy Action harvested LiteLLM's PyPI API publishing token from the CI runner's environment, which TeamPCP then used to publish the backdoored LiteLLM packages directly.

## Technical Analysis of the Malicious Payload

### 1. Delivery Mechanism: .pth File Injection

The primary delivery used Python's `.pth` file execution mechanism. The file `litellm_init.pth` (34,628 bytes, SHA-256: `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238`) was placed in the Python `site-packages/` directory. Python interpreters scan `.pth` files at startup and execute any line beginning with `import`; this means the SANDCLOCK payload ran on **every Python interpreter invocation** in any environment where LiteLLM was installed, regardless of whether LiteLLM itself was imported. This also bypassed `pip install --ignore-scripts` protections.

Version 1.82.7 additionally injected malicious code directly into `proxy_server.py` (SHA-256: `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b`), which executed when `litellm.proxy` was imported -- the standard import path for LiteLLM's proxy server mode.

### 2. Multi-Layer Payload Architecture

The payload used a three-layer base64-encoded architecture designed to avoid static detection:

| Layer | Name | Function |
|-------|------|----------|
| 0 | Launcher | Single Python line decoding Layer 1 via `subprocess.Popen` |
| 1 | Orchestrator | Contains RSA-4096 public key; handles encryption and exfiltration coordination |
| 2 | Collector | Credential harvesting across 50+ categories |
| 3 | Persistence | C2 polling backdoor (`sysmon.py`) |

**Environment gating:** The payload checked for the `GITHUB_ACTIONS` environment variable. If set, it activated, explicitly targeting CI/CD pipeline environments. It also performed locale and registry geofencing to exclude specific regions.

**Anti-forensics:** Internal timestamps in the payload were set to October 26, 1985 (the "Back to the Future" date) as a deliberate anti-forensic marker. The multi-layer encoding ensured decoded payloads never touched disk as standalone files.

### 3. Credential Harvesting (Layer 2 Collector)

The collector targeted 50+ credential categories with system reconnaissance commands (`hostname`, `uname -a`, `whoami`, `ip addr`, `printenv`) executed with 10-second timeouts:

**Cloud Credentials:**
- AWS: `~/.aws/credentials`, `~/.aws/config`, environment variables, IMDS v1/v2 tokens
- GCP: `~/.config/gcloud/`, `$GOOGLE_APPLICATION_CREDENTIALS`
- Azure: `~/.azure/` directories, environment variables
- Embedded AWS SigV4 signing to call Secrets Manager (`ListSecrets`, `GetSecretValue`) and SSM Parameter Store

**Kubernetes:**
- Service account tokens from standard mount paths
- kubeconfig files and cluster admin configs
- `kubectl get secrets --all-namespaces` enumeration
- Direct API calls to `/api/v1/secrets` and `/api/v1/namespaces/{ns}/secrets`

**CI/CD & DevOps:**
- `.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.development` (up to 6 directory levels deep)
- Terraform state files, `.gitlab-ci.yml`, `.travis.yml`, Jenkins, Ansible configs
- GitHub Actions masked secrets (bypassed via `/proc/<pid>/mem` scraping)
- npm auth tokens, Vault tokens

**SSH & System:**
- All private key formats across `/home/` and `/root/`
- SSH host keys, `authorized_keys`, SSH config files
- `/etc/passwd`, `/etc/shadow`, auth logs

**Application & Other:**
- `.git-credentials`, `.gitconfig`, Docker `config.json`
- Database configs: `.my.cnf`, `.pgpass`, `.mongorc.js`, `.netrc`
- Slack/Discord webhook URLs
- Cryptocurrency wallet files (Bitcoin, Ethereum, Solana, Cardano, Monero, etc.)
- LLM API keys (OpenAI, Anthropic, Azure AI, and dozens of other providers)
- WireGuard VPN configs, Helm charts, TLS/SSL private keys, shell history

### 4. C2 Infrastructure

**Exfiltration endpoint:** `hxxps://models[.]litellm[.]cloud/` -- a typosquatted domain registered on March 23, 2026, one day before the attack, resolving to `46[.]151[.]182[.]203` (AS205759, Ghosty Networks LLC / DEMENIN B.V.).

**Persistence C2:** `hxxps://checkmarx[.]zone/raw` -- resolving to `83[.]142[.]209[.]11` (same AS). The persistence backdoor polled this endpoint every 3,000 seconds (~50 minutes).

**Alternative exfiltration:** `scan[.]aquasecurtiy[.]org` (deliberate typosquat of "aquasecurity") used during the Trivy compromise phase.

**Fallback exfiltration:** When network exfiltration failed, the malware created public GitHub repositories within the victim's own GitHub accounts (named `tpcp-docs`, `docs-tpcp`, or `tpcp-docs-*`) and uploaded stolen data as release assets tagged `data-<timestamp>`.

**Encryption protocol:**
- A 32-byte AES-256 session key generated via `openssl rand`
- Data encrypted with AES-256-CBC (PBKDF2 key derivation)
- Session key encrypted with a hardcoded 4096-bit RSA public key (OAEP padding)
- Bundled into `tpcp.tar.gz` containing `payload.enc` + `session.key.enc`

**Kill switch:** The C2 endpoint at `/raw` served a 43-byte YouTube URL. Any response containing the string "youtube" prevented payload execution, enabling global deactivation via a single server change.

### 5. Persistence Mechanism

The Layer 3 component installed a persistent backdoor:

- **Script:** `~/.config/sysmon/sysmon.py` (SHA-256: `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a`)
- **Service:** `~/.config/systemd/user/sysmon.service` with description "System Telemetry Service" and `Restart=always`
- **Activation:** `systemctl --user daemon-reload && systemctl --user enable --now sysmon.service`

Backdoor behavior:
- Initial sleep: 300 seconds (5 minutes)
- Polls `hxxps://checkmarx[.]zone/raw` every 3,000 seconds (~50 minutes)
- User-Agent spoofing in requests
- Checks response for "youtube" string (kill switch); if found, skips execution
- Downloads stage-2 payload to `/tmp/pglog`
- Sets executable permissions: `chmod 755`
- Executes as detached process: `start_new_session=True`
- Records URL in `/tmp/.pg_state` to prevent re-download

### 6. Kubernetes Lateral Movement

On systems with Kubernetes access, the payload attempted to deploy privileged pods to every node:
- Namespace: `kube-system`
- Pod naming: `node-setup-{node_name}`, container named `setup`
- Image: `alpine:latest`
- Privileged flags: `hostPID: true`, `hostNetwork: true`
- Host filesystem mounted at `/host`
- Wrote backdoor to host via chroot and enabled as systemd service on each node

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.82.7 | Malicious code injected into `proxy_server.py` |
| litellm (PyPI) | 1.82.8 | Adds `litellm_init.pth` .pth file execution mechanism + `proxy_server.py` injection |
| aquasecurity/trivy-action (GitHub) | 76 of 77 tags | Force-pushed malicious commits (upstream compromise) |
| checkmarx/kics-github-action (GitHub) | All 35 tags (v1--v2.1.20) | Hijacked release tags |
| checkmarx-util (npm) | 1.0.4 | Three-layer nesting with postinstall hook |
| aquasec/trivy (Docker Hub) | 0.69.5, 0.69.6 | Malicious container images |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `site-packages/litellm_init.pth` | `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238` | .pth launcher (34,628 bytes) |
| Linux | `litellm/proxy/proxy_server.py` | `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b` | Injected proxy server |
| Linux | `~/.config/sysmon/sysmon.py` | `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a` | Persistence backdoor |
| Linux | `~/.config/systemd/user/sysmon.service` | -- | Systemd persistence unit ("System Telemetry Service") |
| Linux | `/tmp/.pg_state` | -- | C2 state tracking file |
| Linux | `/tmp/pglog` | -- | Downloaded stage-2 payload |
| Linux | `/tmp/tpcp.tar.gz` | -- | Exfiltration bundle (payload.enc + session.key.enc) |
| Linux | `/tmp/session.key`, `/tmp/payload.enc`, `/tmp/session.key.enc` | -- | Temporary encryption artifacts |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `models[.]litellm[.]cloud` | Primary exfiltration endpoint (registered 2026-03-23) |
| Domain | `checkmarx[.]zone` | Persistence C2 (polled every ~50 min) |
| Domain | `scan[.]aquasecurtiy[.]org` | Trivy-phase exfiltration (typosquat) |
| IP | `46[.]151[.]182[.]203` | models[.]litellm[.]cloud / litellm[.]cloud |
| IP | `83[.]142[.]209[.]11` | checkmarx[.]zone |
| ASN | AS205759 | Ghosty Networks LLC / DEMENIN B.V. (bulletproof hosting) |

### Behavioral

- `.pth` file creation in Python `site-packages/` outside known package baselines
- Fork bomb / runaway processes causing CPU at 100% and OOM errors during credential collection
- Bulk credential file reads (SSH keys + cloud configs + wallet files) from a single process
- Process memory scraping via `/proc/<pid>/mem` to bypass GitHub Actions secret masking
- IMDS (Instance Metadata Service) queries for cloud instance credentials
- Kubernetes privileged pod deployment to every node in `kube-system` namespace
- Systemd user service installation under `~/.config/sysmon/`
- GitHub repository creation named `tpcp-docs` / `docs-tpcp` with release assets tagged `data-<timestamp>`
- Capture files named `<YYYYMMDD>_<HHMMSS>_<us>_127.0.0.1.txt` (JSON format with `"isSecret":true`)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into LiteLLM PyPI releases via compromised Trivy GitHub Action |
| T1059.006 | Command and Scripting Interpreter: Python | .pth file execution and multi-layer Python payload |
| T1543.002 | Create or Modify System Process: Systemd Service | Persistence via sysmon.service systemd user unit |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvesting .env, .aws/credentials, .git-credentials, kubeconfig, etc. |
| T1552.004 | Unsecured Credentials: Private Keys | Collection of SSH private keys, code-signing keys, TLS keys |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | IMDS v1/v2 credential harvesting |
| T1005 | Data from Local System | Sweeping 50+ credential categories from filesystem |
| T1057 | Process Discovery | Running processes enumeration for memory scraping targets |
| T1003.007 | OS Credential Dumping: Proc Filesystem | /proc/<pid>/mem scraping to extract GitHub Actions masked secrets |
| T1041 | Exfiltration Over C2 Channel | Encrypted exfiltration to models[.]litellm[.]cloud |
| T1567 | Exfiltration Over Web Service | Fallback exfil via public GitHub repos with release assets |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS-based C2 and exfiltration |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-CBC data encryption |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA-4096-OAEP session key wrapping |
| T1105 | Ingress Tool Transfer | Downloading follow-on payloads from checkmarx[.]zone/raw to /tmp/pglog |
| T1611 | Escape to Host | Kubernetes privileged pod deployment for container escape |
| T1078.004 | Valid Accounts: Cloud Accounts | Using harvested credentials for AWS SigV4 API calls |

## Impact Assessment

**Breadth:** Approximately 2,500+ organizations across technology, banking, healthcare, retail, and government sectors. Notable confirmed victims include Microsoft, Azure, IBM, NVIDIA, FedEx, PayPal (Zettle), Deloitte, Bosch, Cisco (327 secrets, 1,900 runs), X Corp/Twitter (3,459 secrets), Orange S.A. (180 secrets, 5,642 runs), Volkswagen (2,242 runs), Thales Group, and a US GovCloud AWS tenant (account ID: 073638633986).

**Depth:** 415,427 credential capture files across 2,038 repositories and 898 GitHub owners. Resecurity acquired a 152.5 GiB archive containing the full victim manifests and stolen credentials. The stealer's AWS SigV4 implementation enabled direct cloud API abuse beyond mere credential exfiltration.

**Stealth:** The 40-minute PyPI exposure window was brief, but downstream dependency caches and transitive dependencies (DSPy, MLflow, CrewAI, OpenHands, Arize Phoenix) significantly extended the effective exposure. The .pth execution mechanism was particularly stealthy as it required no imports and bypassed `--ignore-scripts`.

## Detection & Remediation

### Immediate Detection

Check for the malicious .pth file:
```bash
find $(python3 -c "import site; print(' '.join(site.getsitepackages()))") -name "litellm_init.pth" 2>/dev/null
```

Check for persistence artifacts:
```bash
ls -la ~/.config/sysmon/sysmon.py 2>/dev/null
ls -la ~/.config/systemd/user/sysmon.service 2>/dev/null
ls -la /tmp/.pg_state /tmp/pglog 2>/dev/null
```

Verify installed LiteLLM version:
```bash
pip show litellm | grep Version
# Affected: 1.82.7, 1.82.8. Safe: <=1.82.6 or >=1.83.0
```

Check for C2 communication:
```bash
# DNS/network logs for attacker domains
grep -E "models\.litellm\.cloud|checkmarx\.zone|scan\.aquasecurtiy\.org" /var/log/dns* /var/log/syslog 2>/dev/null
```

Check for fallback exfiltration repos:
```bash
# Search for repos created by CI service accounts with suspicious names
gh repo list --json name -q '.[].name' | grep -iE "tpcp-docs|docs-tpcp"
```

### Remediation

1. **Immediate:** Remove litellm 1.82.7/1.82.8 and upgrade to >=1.83.0; delete `litellm_init.pth` from all site-packages directories
2. **Persistence removal:** Stop and disable `sysmon.service`; delete `~/.config/sysmon/` and the systemd unit file; remove `/tmp/.pg_state` and `/tmp/pglog`
3. **Credential rotation (critical):** Rotate ALL credentials that were accessible in any environment where the compromised versions were installed -- GitHub tokens, SSH keys, AWS/GCP/Azure credentials, Kubernetes tokens, API keys, database passwords, registry tokens
4. **Kubernetes audit:** Check for unauthorized privileged pods named `node-setup-*` in `kube-system` namespace across all clusters
5. **GitHub audit:** Search for unauthorized repositories named `tpcp-docs` or `docs-tpcp` across organization accounts; check for unexpected release assets

### Long-Term Hardening

- Pin all CI/CD action references to full commit SHAs (not tags)
- Pin all Python dependency versions with hash verification (`pip install --require-hashes`)
- Implement supply chain security tooling (e.g., Sigstore verification, SLSA provenance)
- Monitor for `.pth` file creation in Python site-packages directories
- Restrict CI runner network egress to known-good endpoints
- Enable IMDS v2 (IMDSv2) with hop limit=1 to prevent credential theft from within containers

## Detection Rules

These detections target specific SANDCLOCK campaign artifacts at the PoC/advisory-specific altitude (default, strict). Sigma rules are syntactically valid and convert without errors via `--without-pipeline`; field mapping requires the appropriate product pipeline in production. Compiles != fires -- verify in your pipeline before production deployment.

### Sigma: SANDCLOCK Malicious .pth File in Site-Packages

Detects creation of the SANDCLOCK-specific `litellm_init.pth` payload file in Python site-packages.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed on MITRE ATT&CK data fetch (proxy 403, env-specific); sigma convert --without-pipeline splunk 0, log_scale 0. No fitting pipeline for linux/file_event. Keyed on exact filename -- highly distinctive, no legitimate use outside dev builds. -->
```yaml
title: SANDCLOCK Malicious .pth File Creation in Python Site-Packages
id: 8b4e2a91-7f3c-4d1e-a6b8-9c0d2e5f1a3b
status: experimental
description: >
    Detects creation of litellm_init.pth in Python site-packages directories,
    a malicious file dropped by compromised LiteLLM versions 1.82.7/1.82.8 that
    executes on every Python interpreter startup to harvest credentials.
references:
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
    - https://www.resecurity.com/blog/article/the-litellm-supply-chain-attack-teampcp-sandclock-cicd-credential-harvesting-campaign-via-a-backdoored-trivy-github-action
    - https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html
author: Actioner
date: 2026/08/18
tags:
    - attack.t1195.002
    - attack.t1059.006
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/litellm_init.pth'
    condition: selection
falsepositives:
    - Legitimate LiteLLM development builds using .pth files (unlikely in production)
level: high
```

### Sigma: SANDCLOCK Persistence via Fake Sysmon Systemd Service

Detects file creation at the SANDCLOCK persistence paths (`~/.config/sysmon/sysmon.py` or `sysmon.service` systemd unit).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed on MITRE ATT&CK data fetch (proxy 403, env-specific); sigma convert --without-pipeline splunk 0, log_scale 0. Paths are distinctive -- legitimate Sysmon for Linux uses different install paths (/opt/sysmon). -->
```yaml
title: SANDCLOCK Persistence via Fake Sysmon Systemd User Service
id: 3c7d1e5f-9a2b-4f6c-8d0e-1b3a5c7d9e2f
status: experimental
description: >
    Detects creation of the SANDCLOCK backdoor persistence mechanism which
    installs a fake sysmon.py script under ~/.config/sysmon/ and registers
    it as a systemd user service (sysmon.service) that polls checkmarx.zone
    for follow-on payloads every 50 minutes.
references:
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
    - https://www.resecurity.com/blog/article/the-litellm-supply-chain-attack-teampcp-sandclock-cicd-credential-harvesting-campaign-via-a-backdoored-trivy-github-action
author: Actioner
date: 2026/08/18
tags:
    - attack.t1543.002
    - attack.t1059.006
logsource:
    category: file_event
    product: linux
detection:
    selection_sysmon_script:
        TargetFilename|contains: '/.config/sysmon/sysmon.py'
    selection_sysmon_service:
        TargetFilename|contains: '/.config/systemd/user/sysmon.service'
    condition: selection_sysmon_script or selection_sysmon_service
falsepositives:
    - Legitimate Sysmon for Linux installations (would use different paths)
level: high
```

### Sigma: SANDCLOCK C2 DNS Query to Known Infrastructure

Detects DNS queries to the three known SANDCLOCK C2/exfiltration domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed on MITRE ATT&CK data fetch (proxy 403, env-specific); sigma convert --without-pipeline splunk 0, log_scale 0. All three domains are attacker-controlled; no legitimate use. Values are real (not defanged) per logsource-encoding spec. -->
```yaml
title: SANDCLOCK C2 DNS Query to Known Infrastructure
id: 5e9f1a3b-2c7d-4e8f-b0a6-3d1c5e7f9a2b
status: experimental
description: >
    Detects DNS queries to known SANDCLOCK campaign C2 and exfiltration
    domains including models.litellm.cloud (exfil), checkmarx.zone
    (persistence C2), and scan.aquasecurtiy.org (Trivy-related exfil).
references:
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
    - https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html
    - https://www.cloudsek.com/blog/ai-supply-chain-breach-2500-companies-434000-cicd-pipelines
author: Actioner
date: 2026/08/18
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
    - None expected - these are attacker-controlled typosquatted domains
level: critical
```

### Sigma: SANDCLOCK Backdoor Staging Files in /tmp

Detects creation of SANDCLOCK-specific staging files used by the persistence backdoor for C2 state tracking and payload storage.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed on MITRE ATT&CK data fetch (proxy 403, env-specific); sigma convert --without-pipeline splunk 0, log_scale 0. /tmp/.pg_state could overlap with PostgreSQL temp files in some environments -- hence medium, not high. -->
```yaml
title: SANDCLOCK Backdoor Staging Files in /tmp
id: 7a2b4c6d-8e0f-1a3b-5c7d-9e2f4a6b8c0d
status: experimental
description: >
    Detects creation of SANDCLOCK-specific staging files in /tmp used by
    the persistence backdoor for C2 state tracking (.pg_state) and
    downloaded payload storage (pglog).
references:
    - https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
    - https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
author: Actioner
date: 2026/08/18
tags:
    - attack.t1059.006
    - attack.t1105
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename:
            - '/tmp/.pg_state'
            - '/tmp/pglog'
    condition: selection
falsepositives:
    - PostgreSQL temporary state files could overlap with .pg_state naming
level: medium
```

### Suricata: SANDCLOCK C2 and Exfiltration Network Indicators

Detects DNS queries and TLS/HTTP connections to all three known SANDCLOCK campaign domains. Scope to egress from CI/CD and development infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). All 5 rules validated. Dot-notation buffers used (dns.query, http.host, tls.sni). Domains are real values per logsource-encoding spec. No FP risk -- all domains are attacker-controlled. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - SANDCLOCK DNS Query to Exfiltration Domain models.litellm.cloud"; flow:to_server; dns.query; content:"models.litellm.cloud"; nocase; fast_pattern; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-18; sid:2200001; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - SANDCLOCK DNS Query to Persistence C2 Domain checkmarx.zone"; flow:to_server; dns.query; content:"checkmarx.zone"; nocase; fast_pattern; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-18; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - SANDCLOCK DNS Query to Trivy Typosquat Domain scan.aquasecurtiy.org"; flow:to_server; dns.query; content:"scan.aquasecurtiy.org"; nocase; fast_pattern; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-18; sid:2200003; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SANDCLOCK HTTPS Exfil to models.litellm.cloud"; flow:established,to_server; http.host; content:"models.litellm.cloud"; fast_pattern; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-18; sid:2200004; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - SANDCLOCK TLS Connection to C2 Domain checkmarx.zone"; flow:established,to_server; tls.sni; content:"checkmarx.zone"; fast_pattern; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-18; sid:2200005; rev:1;)
```

### Snort: SANDCLOCK DNS Queries to C2 Domains

Detects DNS queries (label-length-encoded) to the three SANDCLOCK campaign domains over UDP port 53.
**Status:** compile ⚠️ uncompiled (snort not installed; structural check only) · confidence: high
<!-- audit: snort binary not available in environment. Rules structurally validated: label-length encoding correct (models=06, litellm=07, cloud=05; checkmarx=09, zone=04; scan=04, aquasecurtiy=0c, org=03), all terminated with |00|, sid range 2100000+, flow/classtype/reference present. -->
<!-- revision: SID 2100003 aquasecurtiy label-length fixed |0b|→|0c| (12 chars = 0x0c); YARA PTH branch 4 threshold raised 3-of-6→4-of-6; detection summary clarified --without-pipeline limitation; YARA status label corrected to "constructed positive"; ATT&CK T1003→T1003.007 (Proc Filesystem). -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - SANDCLOCK DNS Query to Exfil Domain models.litellm.cloud"; flow:to_server; content:"|06|models|07|litellm|05|cloud|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created 2026-08-18; sid:2100001; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - SANDCLOCK DNS Query to C2 Domain checkmarx.zone"; flow:to_server; content:"|09|checkmarx|04|zone|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created 2026-08-18; sid:2100002; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - SANDCLOCK DNS Query to Typosquat Domain scan.aquasecurtiy.org"; flow:to_server; content:"|04|scan|0c|aquasecurtiy|03|org|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,snyk.io/blog/poisoned-security-scanner-backdooring-litellm/; reference:cve,2026-33634; metadata:author Actioner, created 2026-08-18; sid:2100003; rev:1;)
```

### YARA: SANDCLOCK LiteLLM .pth Payload and Sysmon Backdoor

Detects the SANDCLOCK credential-stealer `.pth` payload and the `sysmon.py` persistence backdoor by matching campaign-specific strings (exfil domain, persistence paths, encryption artifacts, C2 indicators).
**Status:** compile ✅ compiles · confidence: high · sample: fired on constructed positive
<!-- audit: yarac exit 0. yara fired on constructed positive (exfil domain + persistence paths + encryption markers from published Snyk analysis); quiet on benign litellm import script. Two rules: Supply_Chain_SANDCLOCK_LiteLLM_PTH keyed on exfil domain/persistence paths/encryption artifacts; Supply_Chain_SANDCLOCK_Sysmon_Backdoor keyed on C2 poll endpoint + kill switch + staging files. Positive constructed from published source indicators, not invented. -->
```yara
rule Supply_Chain_SANDCLOCK_LiteLLM_PTH
{
    meta:
        description = "Detects the SANDCLOCK credential-stealer .pth file dropped by malicious LiteLLM 1.82.7/1.82.8 packages. Keys on double base64-encoded launcher, campaign markers, and exfiltration domain."
        author = "Actioner"
        date = "2026-08-18"
        reference = "https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/"
        hash = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth_exec = "import subprocess" ascii
        $b64_decode = "base64" ascii
        $campaign_marker1 = "tpcp" ascii nocase
        $exfil_domain = "models.litellm.cloud" ascii
        $c2_domain = "checkmarx.zone" ascii
        $alt_exfil = "scan.aquasecurtiy.org" ascii
        $persistence_path = ".config/sysmon/sysmon.py" ascii
        $service_name = "sysmon.service" ascii
        $pg_state = "/tmp/.pg_state" ascii
        $pglog = "/tmp/pglog" ascii
        $rsa_marker = "BEGIN PUBLIC KEY" ascii
        $aes_key_gen = "openssl rand" ascii
        $tar_bundle = "tpcp.tar.gz" ascii
        $proc_mem = "/proc/" ascii
        $mem_path = "/mem" ascii

    condition:
        filesize < 100KB and
        $pth_exec and $b64_decode and
        (
            ($exfil_domain or $c2_domain or $alt_exfil) or
            ($campaign_marker1 and $tar_bundle) or
            ($persistence_path and $service_name) or
            (4 of ($pg_state, $pglog, $rsa_marker, $aes_key_gen, $proc_mem, $mem_path))
        )
}

rule Supply_Chain_SANDCLOCK_Sysmon_Backdoor
{
    meta:
        description = "Detects the SANDCLOCK persistence backdoor (sysmon.py) that polls checkmarx.zone for follow-on payloads with a YouTube-based kill switch."
        author = "Actioner"
        date = "2026-08-18"
        reference = "https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/"
        hash = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"
        severity = "high"
        tlp = "WHITE"

    strings:
        $c2_poll = "checkmarx.zone" ascii
        $raw_endpoint = "/raw" ascii
        $kill_switch = "youtube" ascii
        $pglog = "/tmp/pglog" ascii
        $pg_state = "/tmp/.pg_state" ascii
        $chmod = "chmod" ascii
        $start_new_session = "start_new_session" ascii
        $persistence_sysmon = "sysmon.py" ascii

    condition:
        filesize < 50KB and
        $c2_poll and
        (
            ($raw_endpoint and $kill_switch) or
            ($pglog and $pg_state) or
            ($chmod and $start_new_session and $persistence_sysmon)
        )
}
```

## Lessons Learned

1. **Unpinned CI dependencies are a critical attack surface.** LiteLLM's CI consumed Trivy via an unpinned tag reference, enabling a single upstream compromise to cascade through the entire supply chain. Pinning GitHub Actions to full commit SHAs (not tags) would have prevented this propagation entirely.

2. **Python's .pth mechanism is a stealth persistence vector.** The `.pth` file execution mechanism -- which runs arbitrary Python on interpreter startup without explicit imports and bypasses `--ignore-scripts` -- is under-monitored in most security tooling. Organizations should baseline and monitor `.pth` files in all Python environments.

3. **Short exposure windows do not equal limited impact.** Despite the malicious packages being live on PyPI for only ~40 minutes, dependency caching, CI/CD auto-updates, and transitive dependencies (via DSPy, MLflow, CrewAI, etc.) dramatically extended the effective blast radius to 2,500+ organizations.

4. **CI/CD environments require credential scoping and network egress controls.** The SANDCLOCK stealer harvested credentials from CI runners with broad access. Implementing least-privilege token scoping, restricting network egress from CI runners, and enabling IMDSv2 with hop-limit=1 would significantly limit credential theft from compromised build environments.

## Sources

- [Resecurity Blog](https://www.resecurity.com/blog/article/the-litellm-supply-chain-attack-teampcp-sandclock-cicd-credential-harvesting-campaign-via-a-backdoored-trivy-github-action) -- primary threat intelligence with victim manifests and capture file analysis
- [The Hacker News](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html) -- attack timeline and CVE/CISA KEV details
- [Security Affairs](https://securityaffairs.com/197377/hacking/litellm-supply-chain-attack-technology-banking-and-healthcare-the-most-affected.html) -- sector impact and scope assessment
- [Snyk Blog](https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/) -- detailed technical analysis with file hashes, code structure, and persistence mechanisms
- [Trend Micro](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html) -- multi-layer payload architecture and credential category analysis
- [CloudSEK Blog](https://www.cloudsek.com/blog/ai-supply-chain-breach-2500-companies-434000-cicd-pipelines) -- exposure dataset and organization impact quantification
- [SOCRadar Blog](https://socradar.io/blog/litellm-supply-chain-attack/) -- C2 infrastructure details and MITRE ATT&CK mapping

---
*Report generated by Actioner*
