# Technical Analysis Report: LiteLLM 1.107.0 Supply Chain Compromise (2026-10-23)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-23
Version: DRAFT 1.0

## Executive Summary

On October 21, 2026, the LiteLLM AI gateway project's release pipeline was compromised, resulting in the publication of malicious version 1.107.0 to PyPI and official Docker registries (GHCR, Docker Hub). The malicious package installs a credential stealer (self-named "privcollect") and a remote access backdoor via Python startup hooks (`cook.pth`, `cook.py`, `sitecustomize.py`). The stealer targets cloud provider credentials (AWS, Azure, GCP), AI tool API keys, SSH/GPG/TLS private keys, browser saved passwords, environment variables, and LiteLLM's own stored proxy credentials. Stolen data is encrypted (AES-256-CBC + RSA-4096 OAEP) and exfiltrated to `litellm[.]dev/healthcheck`. The backdoor polls a GitHub dead-drop repository hourly for C2 instructions. The exposure window was approximately two hours (11:39-13:20 UTC) before PyPI quarantined the package. The last known clean version is 1.106.2. Attackers gained access through stolen GitHub CLI OAuth tokens from three LiteLLM engineers' accounts.

## Background: LiteLLM

LiteLLM is a widely-used open-source Python library and proxy server that provides a unified interface for interacting with over 100 LLM providers (OpenAI, Anthropic, Azure, Google, etc.). It is commonly deployed as an AI gateway in enterprise environments, meaning it often has access to multiple AI provider API keys, cloud credentials, and database connection strings. Its PyPI package sees high download volumes, and its Docker images are used in production Kubernetes deployments. This positioning makes it a high-value supply chain target: a compromise of LiteLLM can yield credentials for dozens of downstream services in a single attack.

This is the second supply chain compromise of LiteLLM in 2026. In March 2026, versions 1.82.7 and 1.82.8 were compromised by the TeamPCP group via a poisoned Aqua Trivy GitHub Action in LiteLLM's CI/CD pipeline. That earlier attack used a similar `.pth` startup hook delivery mechanism.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-10-21 09:48:21 | Commit `783c43bc` adds `data = "cook"` to Maturin config in `pyproject.toml` |
| 2026-10-21 10:46:29 | Commit `20535d8f` adds `COPY cook ./cook` to Dockerfiles |
| 2026-10-21 10:51:23 | Malicious container build starts via private `BerriAI/project-releaser` workflow (run `39587059944`) |
| 2026-10-21 11:06:31 | Malicious container build finishes |
| 2026-10-21 11:39:51 | Malicious `litellm==1.107.0` wheels published to PyPI (7 wheels) |
| 2026-10-21 11:46:30 | Socket.dev malware alert triggers |
| 2026-10-21 11:46:56 | Malicious Docker images pushed; floating tags `latest`, `main-latest`, `main-stable` updated |
| 2026-10-21 ~13:01 | GitHub dead-drop pointer returns HTTP 200 with empty body |
| 2026-10-21 ~13:14 | Registry checks confirm floating tags resolve to the malicious image index |
| 2026-10-21 ~13:20 | PyPI quarantines litellm 1.107.0 |
| 2026-10-21 ~13:51 | GHCR malicious images removed |
| 2026-10-21 ~14:20 | Docker Hub malicious images removed |
| 2026-10-22 | BerriAI confirms compromise via stolen GitHub CLI OAuth tokens from three engineers |

## Root Cause: Stolen GitHub CLI OAuth Tokens

According to LiteLLM's director of security Oliver Jensen, the malicious release was executed through three engineers' GitHub accounts using stolen GitHub CLI OAuth tokens. One compromised account triggered the private `BerriAI/project-releaser` release workflow, and another approved it. The workflow was dispatched against a lookalike fork `Berri-AI/litellm` (note the hyphen — the legitimate organization is `BerriAI`). Build provenance records list `vcs:source` as `https://github.com/Berri-AI/litellm` with dispatch input `"source_owner": "Berri-AI"`.

The exact method by which the OAuth tokens were initially stolen remains unknown. LiteLLM has revoked all involved tokens, removed all but one unaffected user from the GitHub organization, and removed trusted publishing links to the organization from public registries. Because the initial compromise vector is unresolved, further access cannot be ruled out.

## Technical Analysis of the Malicious Payload

### 1. Delivery: Trojanized Python Wheels and Docker Images

The attacker did not modify LiteLLM's application source code. Instead, three files were injected into the built wheels via the Maturin build system's `data` directive (`data = "cook"` in `pyproject.toml`). These files are placed in `litellm-1.107.0.data/purelib/` inside each wheel, which installs them to the root of the Python `site-packages` directory:

- **`cook.pth`** (12 bytes): Contains only `import cook`. Python automatically processes `.pth` files at interpreter startup.
- **`cook.py`** (22,252 bytes): The credential stealer ("privcollect"), containing Base64-encoded zlib-compressed source (~61 KB decoded).
- **`sitecustomize.py`** (25,509 bytes): The remote code loader/backdoor, also Base64/zlib-compressed.

All seven platform wheels (macOS x86_64/arm64, manylinux x86_64/aarch64, musllinux x86_64/aarch64, Windows amd64) contain the payload. The sdist (`tar.gz`) contains the tampered `pyproject.toml` but lacks the payload files.

Docker images were built from the same malicious source, with `COPY cook ./cook` added to Dockerfiles.

### 2. Stage 1: Credential Stealer ("privcollect")

When any Python process starts in the compromised environment, `cook.pth` triggers `import cook`, which spawns a daemon thread running the credential collector. It sets `PRIVCOLLECT_ACTIVE=1` to suppress duplicate collection in child processes.

The collector runs 16 independent modules targeting:

**Cloud and infrastructure:**
- AWS credentials (config, credentials, instance metadata via IMDSv2, ECS task credentials, STS `GetCallerIdentity` validation, Secrets Manager, SSM Parameter Store)
- Azure credentials and instance metadata
- Google Cloud service-account tokens and credential files
- Kubernetes secrets (all namespaces), Docker configs, Vault tokens, Terraform/Packer state

**Developer credentials:**
- Git credentials, `.gitconfig`, `.netrc`
- npm and PyPI tokens
- SSH keys, GPG private keys, TLS private keys
- `.env` files across the filesystem
- Shell histories and application histories

**AI tooling credentials:**
- `~/.codex/auth.json`
- `~/.claude/.credentials.json`
- `~/.gemini/oauth_creds.json`
- `~/.cursor/mcp.json`
- Copilot, Windsurf, Kiro, Zed, Continue, OpenCode, and Hugging Face configurations

**Browser data:**
- Chromium: login databases, cookies, Web Data, history
- Firefox: login and key databases

**Runtime and host:**
- All non-empty environment variables
- Other readable process environments on Linux (via `/proc/*/environ`)
- Host and network information

**LiteLLM-specific (when `DATABASE_URL` is set):**
- `SELECT "credential_name", "credential_values" FROM "LiteLLM_CredentialsTable" LIMIT 500;`
- `SELECT "model_name", "litellm_params" FROM "LiteLLM_ProxyModelTable" LIMIT 500;`

### 3. Encryption and Exfiltration

Collected data is:
1. Serialized as JSON
2. Encrypted with a random AES-256-CBC key (PBKDF2-derived)
3. The AES key is wrapped with an embedded RSA-4096 public key (OAEP padding)
4. Packed into a gzip-compressed TAR archive containing `hdr.json`, `data.bin`, and `key.bin`
5. Uploaded via HTTP POST to `hxxp://www[.]litellm[.]dev/healthcheck`

Upload headers:
- `X-Token: XWiA8gZNa7NcX2XRoAEb`
- `X-SHA256: <body checksum>`
- `Content-Type: application/octet-stream`
- `User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)`

Retries: up to 4 attempts, 120-second timeout per request. On HTTP 200 response, the collector creates the marker file `/tmp/.pc_once_72129118c59f5636c0bb` to suppress future collection on that host.

RSA-4096 public key fingerprint (SHA256 of DER SubjectPublicKeyInfo): `a898fd08ad220fed52488906eb45d196f332b972ad5d85214e7726545ecc4218`

### 4. Stage 2: Remote Code Loader (Backdoor/RAT)

`sitecustomize.py` starts independently of the credential stealer. Its execution chain:

1. Takes an exclusive lock on `/tmp/remote_code_loader.lock`
2. Forks a detached child process via `setsid`
3. The child redirects stdin/stdout/stderr to `/dev/null`, changes working directory to `/`
4. Polls the GitHub dead-drop: `hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt`
5. If the pointer returns a domain, fetches `http://<domain>/codepy`
6. The downloaded code is executed via `exec(compile(code, "<remote>", "exec"), {"__name__": "__main__"})`
7. The loop sleeps 3,600 seconds (1 hour) and repeats

The downloaded code has no signature or content-hash verification, making the channel susceptible to domain takeover for further exploitation.

Historical dead-drop values observed: `localhost:18909` and `test[.]test[.]com:18909`. As of 13:01 UTC on October 21, the pointer returned an empty body. The GitHub account `letters9813` hosted the pointer repository `pythonclient-test`.

### 5. Anti-Forensics / Evasion Techniques

- **Startup hook persistence**: `.pth` and `sitecustomize.py` execute before any user code, including investigation tools. Running `python` or `pip` to inspect the environment re-triggers the payload.
- **Detached daemon**: The loader fork redirects all standard streams to `/dev/null` and changes CWD to `/`, making it difficult to associate with any particular application.
- **Suppression markers**: `PRIVCOLLECT_ACTIVE` environment variable and `/tmp/.pc_once_*` file prevent re-execution, reducing signal in telemetry.
- **Obfuscation**: Payload source is Base64-encoded and zlib-compressed within the delivery files.
- **Lookalike domains**: `litellm[.]dev` (exfiltration) mimics the legitimate project. `Berri-AI` (GitHub org) differs from `BerriAI` by one hyphen.
- **Clean git tag**: The v1.107.0 git tag contains no malicious code; the payload was injected only at build time.
- **On Windows**: The daemon fork fails silently, but the credential collector still runs.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.107.0 | All 7 wheels contain cook.pth, cook.py, sitecustomize.py |
| litellm (sdist) | 1.107.0 | Tampered pyproject.toml (`data = "cook"`), no payload files |
| ghcr.io/berriai/litellm | v1.107.0, latest, main-latest, main-stable | Malicious Docker images |
| ghcr.io/berriai/litellm-database | v1.107.0 | Malicious Docker image |
| ghcr.io/berriai/litellm-non_root | v1.107.0 | Malicious Docker image |
| docker.io/litellm/litellm | v1.107.0 | Malicious Docker image |

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| All | cook.pth (site-packages root) | `7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb` | Startup hook: `import cook` (12 bytes) |
| All | cook.pth (variant) | `84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d` | Startup hook variant |
| All | cook.py (site-packages root) | `9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25` | Credential stealer "privcollect" (22,252 bytes) |
| All | cook.py (variant) | `03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea` | Credential stealer variant |
| All | sitecustomize.py (site-packages root) | `34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa` | Remote code loader (25,509 bytes) |
| All | sitecustomize.py (variant) | `b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465` | Remote code loader variant |
| macOS x86_64 | litellm-1.107.0-...-macosx_10_12_x86_64.whl | `7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d` | Malicious wheel |
| macOS arm64 | litellm-1.107.0-...-macosx_11_0_arm64.whl | `0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a` | Malicious wheel |
| Linux x86_64 | litellm-1.107.0-...-manylinux_2_28_x86_64.whl | `462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7` | Malicious wheel |
| Linux aarch64 | litellm-1.107.0-...-manylinux_2_28_aarch64.whl | `668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6` | Malicious wheel |
| Linux x86_64 | litellm-1.107.0-...-musllinux_1_2_x86_64.whl | `1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00` | Malicious wheel |
| Linux aarch64 | litellm-1.107.0-...-musllinux_1_2_aarch64.whl | `c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054` | Malicious wheel |
| Windows amd64 | litellm-1.107.0-...-win_amd64.whl | `12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484` | Malicious wheel |
| All | litellm-1.107.0.tar.gz | `2befe2a79fb4fbbd9a543b5b40b530c8cffa8771bab22b8fb22b2e4ae3b1f819` | Tampered sdist |
| Docker | Image index | `sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e` | Malicious container image index |
| Docker | Linux amd64 manifest | `sha256:bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5` | Malicious container manifest |
| Docker | Linux arm64 manifest | `sha256:56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf` | Malicious container manifest |
| Linux | /tmp/remote_code_loader.lock | N/A | Loader instance lock file |
| Linux | /tmp/.pc_once_72129118c59f5636c0bb | N/A | Upload completion marker |
| Linux | /tmp/.pc_sq_* and /tmp/.pc_e_* | N/A | Temporary staging directories |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | litellm[.]dev | Exfiltration endpoint (lookalike domain) |
| URL | `hxxp://www[.]litellm[.]dev/healthcheck` | POST exfiltration endpoint |
| URL | `hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt` | Dead-drop pointer for RAT C2 |
| URL Pattern | `http://<domain>/codepy` | RAT payload download path |
| HTTP Header | `X-Token: XWiA8gZNa7NcX2XRoAEb` | Exfiltration authentication token |
| HTTP Header | `X-SHA256: <hash>` | Body integrity check |
| User-Agent | `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)` | Exfiltration UA string |
| GitHub Repo | `letters9813/pythonclient-test` | Dead-drop repository |
| GitHub Org | `Berri-AI/litellm` (note hyphen) | Lookalike fork used for malicious build |

### Behavioral

- Python process reading `/proc/*/environ` for all readable processes
- Orphaned `python` process with working directory `/` (detached loader daemon)
- Environment variable `PRIVCOLLECT_ACTIVE=1` set in process environment
- Outbound HTTP POST to `/healthcheck` with `X-Token` header and `application/octet-stream` content type
- AWS STS `GetCallerIdentity` calls from the host around installation time
- Hourly outbound HTTP to `raw.githubusercontent.com` for dead-drop resolution
- Reads of `LiteLLM_CredentialsTable` and `LiteLLM_ProxyModelTable` via Prisma when `DATABASE_URL` is set
- Files `cook.pth`, `cook.py`, `sitecustomize.py` in Python site-packages root directory

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Malicious code injected into LiteLLM's build pipeline via compromised release workflow |
| T1528 | Steal Application Access Token | GitHub CLI OAuth tokens stolen from three engineers to trigger the release |
| T1546 | Event Triggered Execution | `.pth` file and `sitecustomize.py` execute malicious code at every Python interpreter startup |
| T1059.006 | Command and Scripting Interpreter: Python | Payload is Python code executed via interpreter startup hooks and `exec()` |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Payload source is Base64-encoded and zlib-compressed |
| T1140 | Deobfuscate/Decode Files or Information | Runtime decoding of Base64+zlib payload before execution |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvests credential files for cloud, AI, and developer tools |
| T1552.004 | Unsecured Credentials: Private Keys | Collects SSH, GPG, and TLS private keys |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Queries AWS IMDSv2, ECS task credentials, Azure/GCP instance metadata |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Extracts Chromium and Firefox login databases, cookies, autofill |
| T1102.001 | Web Service: Dead Drop Resolver | Polls GitHub repository for C2 domain instructions |
| T1105 | Ingress Tool Transfer | Downloads and executes remote Python code from C2 |
| T1041 | Exfiltration Over C2 Channel | Stolen data encrypted and uploaded to attacker-controlled domain |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-CBC encryption of exfiltrated data |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA-4096 OAEP wrapping of session key |

## Impact Assessment

**Breadth:** LiteLLM is a top-downloaded AI infrastructure package. Any organization that installed version 1.107.0 or pulled affected Docker tags during the ~2 hour exposure window is potentially impacted. Automated CI/CD pipelines with unpinned dependencies are at highest risk.

**Depth:** The payload harvests credentials across every major cloud provider, AI service, browser, and developer tool. In LiteLLM proxy deployments, the attacker gains direct access to stored upstream AI provider credentials and model configurations. The RAT backdoor provides persistent remote code execution capability.

**Stealth:** The payload runs via interpreter startup hooks, meaning it executes before any user code and is triggered even by investigation tools (python, pip). The clean git tag and lookalike domains add to the difficulty of detection.

**Mitigating factors:** The exposure window was short (~2 hours). Multiple AppSec firms detected the malicious release within 6 minutes. The RAT dead-drop returned an empty body during the exposure window, suggesting the second-stage C2 may not have been operationally active.

## Detection & Remediation

### Immediate Detection

Check for the presence of malicious files (do NOT use the compromised environment's Python interpreter):

```bash
# Check for malicious files in all Python environments (use system tools, not Python)
find / -name "cook.pth" -o -name "cook.py" -path "*/site-packages/*" 2>/dev/null
find / -name "sitecustomize.py" -path "*/site-packages/*" -newer /tmp 2>/dev/null

# Check for runtime artifacts
ls -la /tmp/remote_code_loader.lock /tmp/.pc_once_72129118c59f5636c0bb 2>/dev/null

# Check for the detached loader process
ps aux | grep -E 'python.*setsid|python.*/' | grep -v grep

# Check installed litellm version (use pip show via unzip, not pip directly)
unzip -p $(find / -name "litellm-*.dist-info" -path "*/METADATA" 2>/dev/null | head -1) | grep Version

# Check Docker image digests
docker images --digests | grep -i litellm

# Check for exfiltration in proxy/firewall logs
grep -i 'litellm\.dev' /var/log/proxy/*.log 2>/dev/null
grep -i 'letters9813' /var/log/proxy/*.log 2>/dev/null

# Verify wheel hashes against known-bad list
pip cache list litellm 2>/dev/null | xargs sha256sum 2>/dev/null
```

### Remediation

1. **Isolate** affected systems immediately. Do not run Python on them.
2. **Remove** malicious files manually (not via pip):
   - Delete `cook.pth`, `cook.py`, and `sitecustomize.py` from all `site-packages` directories
   - Kill any orphaned Python processes with CWD `/`
   - Remove `/tmp/remote_code_loader.lock` and `/tmp/.pc_once_*`
3. **Pin** to LiteLLM 1.106.2 by version and hash. Use digest-pinned Docker images.
4. **Rotate ALL credentials** that were accessible from compromised environments:
   - Cloud provider credentials (AWS, Azure, GCP)
   - AI provider API keys
   - SSH, GPG, and TLS keys
   - Git, npm, PyPI tokens
   - Database credentials
   - Browser saved passwords
   - LiteLLM proxy stored credentials
5. **Audit logs** for use of exposed credentials during and after the exposure window.
6. **Rebuild** affected environments from clean images/backups.
7. **Review** GitHub organization access, revoke all tokens, enable mandatory 2FA and branch protection.

### Long-Term Hardening

- Pin all dependencies to specific versions and hashes (pip `--require-hashes`)
- Pin Docker images to digest, not floating tags
- Implement software bill of materials (SBOM) monitoring
- Use SLSA provenance verification for build artifacts
- Monitor for new `.pth` files in site-packages directories
- Restrict outbound network access from production environments
- Implement runtime file integrity monitoring for Python installations
- Require hardware security keys for CI/CD pipeline authentication

## Detection Rules

These detections target the specific IOCs from the LiteLLM 1.107.0 supply chain compromise at PoC/advisory-specific altitude. Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; YARA rules compile and fire on constructed positive samples. `sigma check` was unavailable due to a network-blocked MITRE ATT&CK data fetch; portability was proven via `sigma convert`. Suricata rules are structural-check only (not installed).

### Sigma: LiteLLM Exfiltration to Lookalike Domain

Detects HTTP POST to the `litellm[.]dev/healthcheck` exfiltration endpoint used by the privcollect stealer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data 403); splunk convert exit 0; log_scale convert exit 0. Keys on the specific exfil domain+path pair. Low FP: litellm.dev is attacker-controlled, /healthcheck path alone is generic but domain scopes it. -->
```yaml
title: LiteLLM Supply Chain - Exfiltration to Lookalike Domain
id: 8a3c1e7f-4b2d-4f6a-9e8c-1d5a7b3f2e09
status: experimental
description: >
    Detects HTTP POST requests to the litellm.dev exfiltration endpoint used by
    the malicious LiteLLM 1.107.0 supply chain package. The credential stealer
    uploads encrypted data to /healthcheck on the lookalike domain.
references:
    - https://socket.dev/blog/litellm-compromise
    - https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/
author: Actioner
date: 2026/10/23
tags:
    - attack.t1041
    - attack.t1567
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '/healthcheck'
        r-dns|contains: 'litellm.dev'
    condition: selection
falsepositives:
    - Legitimate health check endpoints on unrelated services (filter by domain)
level: high
```

### Sigma: LiteLLM Dead Drop Resolver Access

Detects proxy traffic to the GitHub-hosted dead-drop URL used by the RAT backdoor to resolve C2 domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data 403); splunk convert exit 0; log_scale convert exit 0. Keys on three URI fragments specific to the attacker's dead-drop repo path. Near-zero FP risk. -->
```yaml
title: LiteLLM Supply Chain - GitHub Dead Drop Resolver Access
id: 2f9a4b71-6c8e-43d5-a1e7-9b3d5f2c8a04
status: experimental
description: >
    Detects DNS queries or proxy requests to the GitHub-hosted dead drop URL used by
    the LiteLLM 1.107.0 RAT backdoor to retrieve C2 domain instructions. The loader
    polls raw.githubusercontent.com for letters9813/pythonclient-test/main/domain.txt hourly.
references:
    - https://socket.dev/blog/litellm-compromise
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-docker/
author: Actioner
date: 2026/10/23
tags:
    - attack.t1102.001
    - attack.t1105
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains|all:
            - 'letters9813'
            - 'pythonclient-test'
            - 'domain.txt'
    condition: selection
falsepositives:
    - Unlikely - specific to the attacker-controlled repository path
level: critical
```

### Sigma: LiteLLM Malicious Python Startup Hook Files

Detects creation of the three malicious files (`cook.pth`, `cook.py`, `sitecustomize.py` in site-packages) dropped by the compromised package.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data 403); splunk convert exit 0; log_scale convert exit 0. cook.pth and cook.py are highly distinctive. sitecustomize.py scoped to site-packages to reduce FP (legitimate sitecustomize.py exists but is rare in production). -->
```yaml
title: LiteLLM Supply Chain - Malicious Python Startup Hook Files
id: 5e7b3a92-1d4f-48c6-b2e9-8f6c4a1d3b07
status: experimental
description: >
    Detects creation of the malicious files dropped by the LiteLLM 1.107.0 supply chain
    package. The payload installs cook.pth, cook.py, and a malicious sitecustomize.py
    in the Python site-packages directory to achieve persistence via interpreter startup hooks.
references:
    - https://socket.dev/blog/litellm-compromise
    - https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/
author: Actioner
date: 2026/10/23
tags:
    - attack.t1546
    - attack.t1195.001
logsource:
    category: file_event
detection:
    selection_pth:
        TargetFilename|endswith: '/cook.pth'
    selection_cook:
        TargetFilename|endswith: '/cook.py'
    selection_sitecustomize:
        TargetFilename|contains|all:
            - 'site-packages'
            - 'sitecustomize.py'
    condition: selection_pth or selection_cook or selection_sitecustomize
falsepositives:
    - Legitimate sitecustomize.py in site-packages (rare in production; cook.pth and cook.py are highly specific)
level: high
```

### Sigma: LiteLLM Loader Lock and Marker Files

Detects creation of the remote code loader lock file and credential upload marker, both specific to this payload.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data 403); splunk convert exit 0; log_scale convert exit 0. Keys on exact file paths unique to this malware. Zero expected FP. -->
```yaml
title: LiteLLM Supply Chain - Loader Lock and Marker File Creation
id: 9c2d8e14-3a5f-47b1-b6f9-4e7c1a8d5b23
status: experimental
description: >
    Detects creation of the remote code loader lock file and the credential upload
    marker file used by the malicious LiteLLM 1.107.0 payload. These files are
    created in /tmp during execution of the supply chain malware.
references:
    - https://socket.dev/blog/litellm-compromise
    - https://www.kodemsecurity.com/resources/litellm-supply-chain-attack-litellm-1-107-0-affected-versions-iocs-and-first-hour-response-runbook
author: Actioner
date: 2026/10/23
tags:
    - attack.t1059.006
    - attack.t1546
logsource:
    category: file_event
detection:
    selection_lock:
        TargetFilename: '/tmp/remote_code_loader.lock'
    selection_marker:
        TargetFilename: '/tmp/.pc_once_72129118c59f5636c0bb'
    condition: selection_lock or selection_marker
falsepositives:
    - Unlikely - file names are specific to this malware
level: critical
```

### Suricata: LiteLLM Exfiltration and Dead Drop Access

Detects outbound HTTP to the exfiltration endpoint and the dead-drop resolver. Scope to source trees running Python workloads.
**Status:** compile ⚠️ uncompiled (structural check only -- suricata not installed) · confidence: high
<!-- audit: structural review only. Both rules use dot-notation sticky buffers (http.host, http.uri, http.header, http.method). SID range 2200000+. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Exfiltration to litellm.dev"; flow:established,to_server; http.method; content:"POST"; http.host; content:"litellm.dev"; http.uri; content:"/healthcheck"; http.header; content:"X-Token|3a 20|XWiA8gZNa7NcX2XRoAEb"; classtype:trojan-activity; reference:url,socket.dev/blog/litellm-compromise; metadata: author Actioner, created_at 2026-10-23; sid:2200001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Dead Drop Resolver Access"; flow:established,to_server; http.host; content:"raw.githubusercontent.com"; http.uri; content:"/letters9813/pythonclient-test/"; content:"domain.txt"; classtype:trojan-activity; reference:url,socket.dev/blog/litellm-compromise; metadata: author Actioner, created_at 2026-10-23; sid:2200002; rev:1;)
```

### YARA: LiteLLM Malicious Payload Detection

Detects the cook.py credential stealer, sitecustomize.py backdoor, or cook.pth startup hook by specific strings unique to this campaign.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on pos_cook.txt (12-byte cook.pth content "import cook") and pos_payload.txt (file with 3+ privcollect strings). Quiet on neg_cook.txt and neg_payload.txt. Strings sourced from Socket.dev and Kodem IOC lists. -->
```yara
rule SupplyChain_LiteLLM_CookPayload
{
    meta:
        description = "Detects the malicious cook.py credential stealer or sitecustomize.py backdoor loader from the LiteLLM 1.107.0 supply chain compromise"
        author = "Actioner"
        date = "2026-10-23"
        reference = "https://socket.dev/blog/litellm-compromise"
        severity = "critical"

    strings:
        $pth_content = "import cook" ascii fullword
        $env_marker = "PRIVCOLLECT_ACTIVE" ascii
        $marker_path = ".pc_once_72129118c59f5636c0bb" ascii
        $lock_path = "remote_code_loader.lock" ascii
        $exfil_endpoint = "/healthcheck" ascii
        $exfil_header = "XWiA8gZNa7NcX2XRoAEb" ascii
        $deaddrop_repo = "letters9813/pythonclient-test" ascii
        $deaddrop_file = "domain.txt" ascii
        $ua_string = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)" ascii

    condition:
        filesize < 200KB and
        (
            ($pth_content and filesize < 100) or
            (3 of ($env_marker, $marker_path, $lock_path, $exfil_endpoint, $exfil_header)) or
            ($deaddrop_repo and $deaddrop_file) or
            ($env_marker and $exfil_header) or
            ($ua_string and $exfil_endpoint)
        )
}

rule SupplyChain_LiteLLM_WheelIOCs
{
    meta:
        description = "Detects LiteLLM 1.107.0 malicious wheel package by structural indicators in the archive content"
        author = "Actioner"
        date = "2026-10-23"
        reference = "https://socket.dev/blog/litellm-compromise"
        severity = "critical"

    strings:
        $wheel_name = "litellm-1.107.0" ascii
        $data_dir = "litellm-1.107.0.data/purelib/" ascii
        $cook_pth = "cook.pth" ascii
        $cook_py = "cook.py" ascii
        $maturin_cook = "data = \"cook\"" ascii

    condition:
        filesize < 50MB and
        $wheel_name and
        (
            ($data_dir and ($cook_pth or $cook_py)) or
            $maturin_cook
        )
}
```

## Lessons Learned

1. **AI infrastructure is a high-value supply chain target.** LiteLLM's role as a credential aggregator (storing API keys for dozens of AI providers) makes it an exceptionally attractive target. A single compromise can yield access to every downstream AI service.

2. **GitHub CLI OAuth tokens are a critical attack surface.** The attackers bypassed branch protection, code review, and trusted publishing by stealing GitHub CLI tokens from developer machines. Organizations should audit OAuth token scopes, enforce short-lived tokens, and require hardware security keys for release workflows.

3. **Python startup hooks are a powerful persistence mechanism.** `.pth` files and `sitecustomize.py` execute before any user code, including diagnostic tools. Defenders must inspect Python environments without invoking the interpreter — treating `.pth` file creation as a high-fidelity detection signal.

4. **Floating Docker tags are dangerous.** The `latest`, `main-latest`, and `main-stable` tags were silently replaced with malicious images. All production deployments should pin images by digest.

5. **Prior compromises should inform future defenses.** This is the second LiteLLM compromise in 2026. The March TeamPCP attack used the same `.pth` delivery mechanism. The recurrence suggests that the root causes from the first incident were not fully addressed.

6. **Short exposure windows still matter.** Despite the ~2 hour window, automated CI/CD pipelines that install latest versions on every build could have been compromised. Organizations should implement package provenance verification and quarantine delays for new releases of critical dependencies.

## Sources

- [Socket.dev - LiteLLM PyPI Package and Docker Images Compromised](https://socket.dev/blog/litellm-compromise) — Primary technical analysis with file hashes, IOCs, process chain, and credential collection details
- [BleepingComputer - LiteLLM release pipeline hacked to distribute info-stealer malware](https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/) — Comprehensive overview with timeline, encryption details, and credential target categories
- [Datadog Security Labs - LiteLLM supply chain compromise](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-docker/) — Timeline details and exposure window analysis
- [The Hacker News - LiteLLM Compromised in Supply Chain Attack](https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html) — GitHub token theft details and attack vector context
- [Kodem Security - LiteLLM Supply Chain Attack IOCs and Response Runbook](https://www.kodemsecurity.com/resources/litellm-supply-chain-attack-litellm-1-107-0-affected-versions-iocs-and-first-hour-response-runbook) — IOC tables, host artifacts, and behavioral indicators
- [Snyk - How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM](https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/) — Connection to March 2026 TeamPCP incident and Trivy compromise chain

---
*Report generated by Actioner*
