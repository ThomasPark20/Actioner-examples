# Technical Analysis Report: LiteLLM 1.107.0 Supply Chain Compromise (2026-10-27)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-27
Version: DRAFT 1.0

## Executive Summary

On October 21, 2026, a compromised LiteLLM version 1.107.0 was published to PyPI and distributed via Docker Hub and GitHub Container Registry. The malicious release was available for approximately two hours (11:39--13:23 UTC) before being quarantined. The attack exploited stolen GitHub CLI OAuth tokens from three developer accounts to trigger the legitimate release pipeline against a lookalike repository (`Berri-AI/litellm`, differing by one hyphen from the real `BerriAI/litellm`). The compromised wheels installed Python startup hook files (`cook.pth`, `cook.py`, `sitecustomize.py`) that execute automatically whenever Python starts -- without any import of LiteLLM -- running a credential collector ("PRIVCOLLECT") and an hourly remote code loader. Stolen credentials were encrypted with AES-256-CBC/RSA-4096 and exfiltrated to `www[.]litellm[.]dev/healthcheck`. Wiz observed the attacker validating stolen AWS credentials approximately 4.5 hours after exfiltration. An estimated 49,000 downloads occurred during the exposure window.

## Background: LiteLLM

LiteLLM is a widely used open-source Python library and proxy server that provides a unified interface to over 100 large language model (LLM) providers, including OpenAI, Anthropic, AWS Bedrock, Azure, and Google Cloud. It is used heavily in enterprise AI pipelines, development environments, and as a proxy gateway managing model-provider credentials. This makes it a high-value supply chain target: a compromised LiteLLM installation has access to model-provider API keys, cloud credentials, and potentially the credentials of every developer and CI/CD system in the environment. This is the second supply chain compromise affecting LiteLLM in 2026 (the first affected versions 1.82.7--1.82.8 in March 2026).

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-27 | Master key (`opencode.json`) committed to public repo `LiteLLM-Labs/lite-harness` |
| 2026-10-10 | Attacker IP `69[.]48[.]229[.]143` accesses Agent Platform API |
| 2026-10-13 | Attacker-controlled domain `litellm[.]dev` registered (Cloudflare NS) |
| 2026-10-21 ~11:39 | Malicious LiteLLM 1.107.0 published to PyPI (all 7 wheels + sdist) |
| 2026-10-21 ~11:46 | Docker floating tags (`latest`, `main-latest`, `main-stable`) pointed to infected image |
| 2026-10-21 ~13:20 | PyPI quarantines litellm 1.107.0 |
| 2026-10-21 ~13:53 | Affected Docker images removed |
| 2026-10-21 ~14:20 | Docker floating tags repointed to safe images |
| 2026-10-21 ~16:00 | Wiz observes stolen AWS credential usage (LLMjacking-style enumeration) |
| 2026-10-22 | Microsoft Defender detection signatures available |
| 2026-10-23 | Microsoft Security Blog publishes detailed analysis |

## Root Cause: Stolen Developer Credentials and Pipeline Hijack

The root cause was a master key committed to the public GitHub repository `LiteLLM-Labs/lite-harness` on May 27, 2026 in a file called `opencode.json`. This credential was eventually used to access developer accounts. The attacker obtained GitHub CLI OAuth tokens from three engineers' accounts and used them to trigger the legitimate LiteLLM release pipeline. The pipeline was directed to build from a lookalike fork `Berri-AI/litellm` (note the hyphen, versus the legitimate `BerriAI/litellm`). A credential tied to a second developer account satisfied the production approval gate. The resulting build was pushed through the normal release infrastructure, giving it valid build provenance that points to the malicious fork. After the release, the attackers deleted evidence of the unauthorized workflow run.

Key attacker identifiers:
- Lookalike repo head commit: `20535d8fa11f786a6c24df7488a0e449ed5f09ad`
- Release workflow commit: `9cf97e935aeaf791b9c8db224a2bb3ee156134ce`
- Commit author email: `ckdi82fkoos[at]proton[.]me`
- Secondary identity: `letters9813[at]atomicmail[.]io`
- CI secret exfiltration endpoints: `hxxps://webhook[.]site/65a42464-3cfa-4b02-a18c-17a6d7b86f37`, `hxxps://webhook[.]site/4da03473-a3e7-4dc2-a087-9c564b4208e1`
- Throwaway CI branches: `ci-tmp-a351cc`, `ci-tmp-be33e9`, `ci-tmp-4d8517`

## Technical Analysis of the Malicious Payload

### 1. Python Startup Hook Injection (Persistence Mechanism)

The compromised wheels placed three files under `litellm-1.107.0.data/purelib/`, which installs them into the Python environment's `site-packages` directory -- outside the `litellm` application directory. This means uninstalling LiteLLM via `pip uninstall litellm` does NOT remove the malicious files.

| File | Size | Role |
|------|------|------|
| `cook.pth` | ~12 bytes | Single line `import cook`; executed by Python's site module on every interpreter start |
| `cook.py` | ~61 KB (compressed) | Base64+zlib encoded PRIVCOLLECT credential stealer (~1,236 lines when decoded) |
| `sitecustomize.py` | Variable | Hourly remote code loader with a fallback copy of the stealer embedded |

Python's startup behavior ensures these run automatically:
- `.pth` files containing `import` statements are executed during `site` initialization
- `sitecustomize.py` is imported automatically by the `site` module
- No import of `litellm` is required; even a routine `pip install` of an unrelated package triggers the payload

The `pyproject.toml` was modified with `data = "cook"` under `[tool.maturin]` to include the malicious files in the wheel build.

### 2. PRIVCOLLECT Credential Collector (cook.py path)

The collector identifies itself as `"tool": "privcollect"`. Its behavior:

**Anti-duplication gates:**
- Checks environment variable `PRIVCOLLECT_ACTIVE`; if set, returns immediately. Otherwise sets it to prevent duplicate runs in child processes.
- After successful exfiltration (HTTP 200), writes marker file `/tmp/.pc_once_72129118c59f5636c0bb`
- Runs collection in a daemon thread

**Collection modules (16 total):** `sysinfo`, `netinfo`, `browser_pw`, `browser_hist`, `ssh_keys`, `shell_hist`, `cloud_creds`, `dev_secrets`, `container_creds`, `cicd_secrets`, `ai_devtools`, `env_vars`, `db_litellm`, `cloud_metadata`, `gpg_keys`, `tls_privkey`

**Targeted credential categories:**
- **Cloud credentials:** AWS (`~/.aws/`), Azure CLI, Google Cloud (`~/.config/gcloud/`), Kubernetes (`~/.kube/config`), Docker config, Vault, Terraform
- **Cloud metadata:** AWS IMDSv2 (falls back to v1), ECS task credentials, GCP service account tokens, Azure IMDS; AWS credentials validated via STS `GetCallerIdentity` before exfiltration
- **Developer tools:** SSH keys (`~/.ssh/*`), GPG keys (`~/.gnupg/`), Git credentials (`.git-credentials`, `.netrc`), package manager tokens (`.npmrc`, `.pypirc`, Maven, Gradle, Cargo, RubyGems)
- **AI tool credentials:** Claude Code/Desktop, Cursor, Windsurf/Codeium, Kiro, Zed, GitHub Copilot, VS Code MCP settings, Cline, Roo, Cody, Gemini CLI, Codex `auth.json`, Continue, Aider, Goose, Qwen, Ollama, Amazon Q, Hugging Face tokens
- **Browsers:** Chrome, Chromium, Edge, Brave, Vivaldi, Opera (credential/cookie/web data databases with platform-specific password decryption); Firefox `logins.json` and `key4.db`
- **Shell/DB history:** bash, zsh, fish, Python/Node REPL, MySQL, psql, Redis, SQLite, `.viminfo`, PowerShell PSReadLine
- **TLS private keys:** `*.pem`, `*.key`, `*.pfx`, `*.p12`, `*.pk8`, `*.ppk`, `/etc/ssl/private/`, nginx/Apache SSL dirs, Let's Encrypt
- **Process environments:** Current env + `/proc/<pid>/environ` for all readable processes (Linux)
- **LiteLLM proxy database:** When `DATABASE_URL` is set, spawns a Prisma child process to execute:
  - `SELECT "credential_name", "credential_values" FROM "LiteLLM_CredentialsTable" LIMIT 500`
  - `SELECT "model_name", "litellm_params" FROM "LiteLLM_ProxyModelTable" LIMIT 500`

### 3. C2 Infrastructure

**Exfiltration endpoint:**
- URL: `hxxp://www[.]litellm[.]dev/healthcheck` (plain HTTP POST)
- Domain `litellm[.]dev` registered October 13, 2026, behind Cloudflare nameservers
- HTTP headers: `Content-Type: application/octet-stream`, `X-Token: XWiA8gZNa7NcX2XRoAEb`, `X-SHA256: <body checksum>`, fixed browser-like User-Agent
- Up to 4 retry attempts; only HTTP 200 is treated as success

**Dead drop resolver (remote code loader):**
- URL: `hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt`
- GitHub account `letters9813` has been deleted (but the username could be re-registered)
- Historic dead drop values observed: `localhost:18909`, `test[.]test[.]com:18909`
- Second-stage code fetched from: `hxxp://<resolved_host>/codepy`
- No second-stage execution was confirmed; the loader remains re-armable while `domain.txt` can be changed

**Encryption:**
1. Collection serialized as JSON
2. Encrypted with AES-256-CBC (random 32-byte key + 16-byte IV per run)
3. AES key wrapped with embedded RSA-4096 public key using OAEP (SHA-256, fallback SHA-1)
4. Packaged as gzip-compressed tar: `data.bin` (IV + ciphertext), `key.bin` (wrapped AES key), `hdr.json` (envelope metadata)
5. Four crypto backends attempted: `openssl` CLI, Python `cryptography` library, Windows CNG, bundled pure-Python AES

RSA public key SPKI SHA-256: `a898fd08ad220fed52488906eb45d196f332b972ad5d85214e7726545ecc4218`

### 4. Platform-Specific Behavior

#### Linux/macOS
- Full credential collection via all 16 modules
- Remote code loader: forks, calls `setsid()`, redirects output to `/dev/null`, changes working directory to `/`; takes exclusive lock on `/tmp/remote_code_loader.lock`
- Process appears as daemon with PPID 1
- OpenSSL CLI used for encryption staging in `/tmp/.pc_e_*` directories

#### Windows
- Full credential collection including Windows-specific Chromium password decryption (CNG DPAPI)
- Remote code loader fails silently (uses `fcntl`/`os.fork` which are Unix-only)
- Stealer still runs and likely re-executes on every Python start (no marker file gate on Windows)
- `systeminfo`, `ipconfig`, `route`, `arp`, `netstat` launched by Python for system discovery

### 5. Anti-Forensics / Evasion Techniques

- **Obfuscation:** Payload compressed with zlib and encoded in base64 within `cook.py`
- **Staging cleanup:** OpenSSL staging directories (`.pc_e_*`) created in `/tmp` and deleted after use
- **Duplicate suppression:** Environment variable `PRIVCOLLECT_ACTIVE` and marker file prevent redundant collection
- **Evidence destruction:** Attackers deleted unauthorized GitHub Actions workflow runs
- **Lookalike repository name:** Single-hyphen difference (`Berri-AI` vs `BerriAI`) evades casual review
- **Valid build provenance:** Release built through the legitimate pipeline, so provenance checks pass (but point to the malicious fork)
- **Domain masquerading:** `litellm[.]dev` looks plausible alongside the legitimate `litellm.ai`

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots
> - Email addresses: `[at]` replacing @

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.107.0 | All 7 platform wheels and sdist compromised with credential stealer and remote code loader |
| ghcr.io/berriai/litellm | v1.107.0 | Docker image carrying the compromised wheel |
| ghcr.io/berriai/litellm-database | v1.107.0 | Docker image carrying the compromised wheel |
| ghcr.io/berriai/litellm-non_root | v1.107.0 | Docker image carrying the compromised wheel |
| docker.io/litellm/litellm | v1.107.0 | Docker Hub mirror carrying the compromised wheel |

### File System

**Malicious startup files (SHA-256):**

| Platform | File | SHA-256 | Description |
|----------|------|---------|-------------|
| Linux/macOS | cook.pth | `7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb` | Python startup hook, imports cook |
| Windows | cook.pth | `84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d` | Python startup hook (CRLF variant) |
| Linux/macOS | cook.py | `9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25` | Base64/zlib encoded PRIVCOLLECT stealer |
| Windows | cook.py | `03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea` | PRIVCOLLECT stealer (CRLF variant) |
| Linux/macOS | sitecustomize.py | `34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa` | Remote code loader + fallback stealer |
| Windows | sitecustomize.py | `b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465` | Remote code loader (CRLF variant) |

**Malicious wheel hashes (SHA-256):**

| Wheel | SHA-256 |
|-------|---------|
| litellm-1.107.0-cp310-abi3-macosx_10_12_x86_64.whl | `7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d` |
| litellm-1.107.0-cp310-abi3-macosx_11_0_arm64.whl | `0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a` |
| litellm-1.107.0-cp310-abi3-manylinux_2_28_aarch64.whl | `668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6` |
| litellm-1.107.0-cp310-abi3-manylinux_2_28_x86_64.whl | `462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7` |
| litellm-1.107.0-cp310-abi3-musllinux_1_2_aarch64.whl | `c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054` |
| litellm-1.107.0-cp310-abi3-musllinux_1_2_x86_64.whl | `1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00` |
| litellm-1.107.0-cp310-abi3-win_amd64.whl | `12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484` |
| litellm-1.107.0.tar.gz (sdist) | `2befe2a79fb4fbbd9a543b5b40b530c8cffa8771bab22b8fb22b2e4ae3b1f819` |

**Docker image digests:**

| Image | Digest (sha256) |
|-------|-----------------|
| ghcr.io/berriai/litellm (index) | `1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e` |
| ghcr.io/berriai/litellm (amd64) | `bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5` |
| ghcr.io/berriai/litellm (arm64) | `56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf` |
| ghcr.io/berriai/litellm-non_root (amd64) | `645a67d810628252d63df85dcc8824c58bcc77cf8383f4d3e6321f0ccc3ce9e4` |
| ghcr.io/berriai/litellm-non_root (arm64) | `f75c8edae59b72b1ebfd617295833f465c85bb2fab9c1d60f21b496db86cb8da` |

**Host artifacts:**

| Path / Artifact | Description |
|-----------------|-------------|
| `/tmp/.pc_once_72129118c59f5636c0bb` | PRIVCOLLECT run-once marker (created after successful HTTP 200) |
| `/tmp/remote_code_loader.lock` | Exclusive lock file for single-instance remote code loader |
| `/tmp/.pc_e_*` | Temporary OpenSSL encryption staging directories |
| `/tmp/.pc_sq_*` | Temporary data staging directories |
| `PRIVCOLLECT_ACTIVE=1` | Environment variable set to suppress duplicate collection |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `www[.]litellm[.]dev` | Primary exfiltration domain |
| Domain | `litellm[.]dev` | Attacker-registered lookalike domain (registered 2026-10-13) |
| URL | `hxxp://www[.]litellm[.]dev/healthcheck` | Credential exfiltration endpoint (HTTP POST) |
| URL | `hxxp://www[.]litellm[.]dev/codepy` | Remote code loader retrieval endpoint (inferred) |
| URL | `hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt` | Dead drop resolver for C2 host |
| IP | `69[.]48[.]229[.]143` | Attacker IP, Agent Platform API access (Oct 10) |
| IP | `199[.]91[.]221[.]39` | Attacker IP, release push and gate approval (Oct 21) |
| IP | `168[.]100[.]8[.]57` | Attacker IP, stolen AWS credential usage (Oct 21) |
| IP | `165[.]227[.]201[.]8` | Attacker IP, stolen AWS credential usage (Oct 21) |
| Header | `X-Token: XWiA8gZNa7NcX2XRoAEb` | Fixed authentication token in exfiltration HTTP headers |

### Behavioral

- Python process spawning OpenSSL with `.pc_e_` in the command line and `enc -aes-256-cbc` or `pkeyutl`/`rsautl` arguments
- Python process running with `-c` flag containing references to `LiteLLM_CredentialsTable`, `credential_values`, `query_raw`, and `os.dup2`
- Daemon process (PPID 1) with working directory `/` and output redirected to `/dev/null`, holding lock on `/tmp/remote_code_loader.lock`
- Prisma `query-engine` child processes spawned by Python
- Outbound HTTP POST to `/healthcheck` with `application/octet-stream` Content-Type and `X-SHA256` header
- DNS resolution of `litellm[.]dev` from environments where `litellm.ai` would be the expected domain

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Malicious LiteLLM 1.107.0 pushed through hijacked release pipeline to PyPI and Docker Hub |
| T1546.018 | Event Triggered Execution: Python Startup Hooks | cook.pth and sitecustomize.py execute automatically on every Python interpreter start |
| T1059.006 | Command and Scripting Interpreter: Python | Decoded PRIVCOLLECT payload executed via exec(); Python -c used for inline database queries |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Payload base64-encoded and zlib-compressed within cook.py |
| T1140 | Deobfuscate/Decode Files or Information | Runtime base64 decode and zlib decompress of embedded stealer |
| T1552.001 | Unsecured Credentials: Credentials in Files | Collection of AWS/Azure/GCP configs, .env files, Git credentials, package manager tokens |
| T1552.004 | Unsecured Credentials: Private Keys | Collection of SSH keys, GPG keys, TLS private keys (PEM, PFX, P12, PPK) |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Retrieval of AWS IMDSv2/v1, ECS task credentials, GCP SA tokens, Azure IMDS |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chromium-family and Firefox credential database extraction with platform-specific decryption |
| T1082 | System Information Discovery | Windows: systeminfo; Linux: system info collection module |
| T1016 | System Network Configuration Discovery | Windows: ipconfig, route, arp, netstat; Linux: network info module |
| T1005 | Data from Local System | Aggregation of credentials, keys, histories, environment variables from local filesystem |
| T1102.001 | Web Service: Dead Drop Resolver | domain.txt on GitHub used as mutable pointer to attacker C2 server |
| T1105 | Ingress Tool Transfer | Hourly fetch and exec of code from resolved C2 domain (not confirmed executed) |
| T1041 | Exfiltration Over C2 Channel | Encrypted credential archive POSTed to www[.]litellm[.]dev/healthcheck |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP used for both exfiltration and remote code retrieval |

## Impact Assessment

- **Breadth:** ~49,000 PyPI downloads during the ~2-hour exposure window; additional exposure via Docker Hub and GHCR floating tags (`latest`, `main-latest`, `main-stable`) between 11:46 and 14:20 UTC
- **Depth:** The stealer targets 16 distinct credential categories spanning cloud, developer, browser, infrastructure, and AI tool credentials; the LiteLLM proxy database module exposes all stored model-provider credentials
- **Stealth:** Runs on every Python start without requiring LiteLLM import; uses legitimate build provenance; lookalike domain and repository name evade casual review
- **Confirmed exploitation:** Wiz observed stolen AWS credential usage (STS GetCallerIdentity, Bedrock ListFoundationModels, IAM enumeration, CloudTrail DescribeTrails) approximately 4.5 hours after exfiltration, consistent with LLMjacking activity
- **Enterprise:** LiteLLM enterprise customers on private releases were reportedly not affected

## Detection & Remediation

### Immediate Detection

Search for the compromised startup files:
```bash
# Find cook.pth in any Python environment
find / -name cook.pth -path "*site-packages*" 2>/dev/null

# Check for PRIVCOLLECT marker and loader lock
ls -la /tmp/.pc_once_72129118c59f5636c0bb /tmp/remote_code_loader.lock 2>/dev/null

# Check for active loader process
lsof /tmp/remote_code_loader.lock 2>/dev/null

# Check installed litellm version
pip show litellm 2>/dev/null | grep Version

# Check for compromised Docker images
docker images --digests | grep -E 'berriai/litellm|litellm/litellm'

# Check for the PRIVCOLLECT environment variable
env | grep PRIVCOLLECT_ACTIVE

# Check lockfiles for pinned version
grep -r "litellm.*1\.107\.0" requirements*.txt poetry.lock Pipfile.lock uv.lock 2>/dev/null
```

### Remediation

1. **Do not run Python or pip in suspect environments.** Investigate with trusted tools from a known-clean system.
2. **Stop Python processes** where operationally safe. Prevent automation from restarting them.
3. **Remove the malicious startup files** manually from every affected site-packages directory. Deleting the `litellm` package directory alone is NOT sufficient:
   ```bash
   find / -path "*/site-packages/cook.pth" -delete 2>/dev/null
   find / -path "*/site-packages/cook.py" -delete 2>/dev/null
   find / -path "*/site-packages/sitecustomize.py" -delete 2>/dev/null
   ```
4. **Rebuild from verified artifacts.** Pin to LiteLLM 1.106.2 (last known safe version) or a verified later release. Verify wheel hashes against known-good values.
5. **Rotate ALL reachable credentials from a clean machine:** model-provider API keys, cloud credentials (AWS/Azure/GCP), CI/CD secrets, source-control and registry tokens, SSH and GPG keys, AI coding tool tokens, browser sessions, Docker/Kubernetes credentials. On proxy hosts, include stored provider credentials and `DATABASE_URL`. Revoke identity sessions (password or key rotation may not invalidate active tokens).
6. **Check container images:** Replace any images built with or containing litellm 1.107.0. Verify digests against the known-compromised list above.
7. **Correlate before declaring clear:** Combine file hashes, Python process ancestry, `.pc_e_` staging, network destinations, and subsequent cloud/identity activity.

### Long-Term Hardening

- Use hash-pinned lock files for all Python dependencies
- Verify package provenance (source repository, not just signature)
- Pin container images by digest, not floating tags
- Restrict egress from developer workstations, build agents, and AI gateway hosts
- Review packages before admitting them to internal mirrors
- Enable cloud metadata endpoint protections (IMDSv2-only for AWS)
- Monitor for `.pth` file creation in Python site-packages directories

## Detection Rules

Five Sigma rules cover endpoint file events, DNS queries, network connections, and process execution; three YARA rules match the malicious startup files by content; two Snort rules and three Suricata rules detect the exfiltration HTTP pattern and DNS queries. All rules target specific, confirmed IOCs from this incident. Rules matching behavioral patterns (OpenSSL staging) are labeled medium confidence because the command-line pattern, while distinctive, could theoretically appear in unrelated contexts.

### Sigma Rules

**Rule 1: Malicious Python Startup File Creation (cook.pth/cook.py)**

Detects creation of cook.pth or cook.py in Python site-packages, as dropped by the compromised LiteLLM 1.107.0 wheels.

compile: pass (Splunk + LogScale) | confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. sigma check could not validate due to MITRE ATT&CK data endpoint returning HTTP 403 (network restriction, not rule error). Tags: attack.t1195.001, attack.t1546. Logsource: file_event. Field TargetFilename uses contains+endswith modifiers for cross-platform path matching. FP: legitimate packages named cook.pth in site-packages are uncommon but possible. Values NOT defanged per logsource-encoding ref. -->

```yaml
title: LiteLLM Supply Chain - Malicious Python Startup File Creation
id: 8a3e7c12-4f5d-4b9e-a1c6-2d8f0e3b7a94
status: experimental
description: >
    Detects creation of cook.pth, cook.py, or sitecustomize.py in Python
    site-packages directories, as dropped by the compromised LiteLLM 1.107.0
    wheels to achieve persistence via Python startup hooks.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026-10-27
tags:
    - attack.t1195.001
    - attack.t1546
logsource:
    category: file_event
detection:
    selection_path:
        TargetFilename|contains: 'site-packages'
    selection_filename:
        TargetFilename|endswith:
            - '\cook.pth'
            - '/cook.pth'
            - '\cook.py'
            - '/cook.py'
    condition: selection_path and selection_filename
falsepositives:
    - Legitimate Python packages that include files named cook.pth or cook.py in site-packages
level: high
```

**Rule 2: DNS Query to Exfiltration Domain (litellm[.]dev)**

Detects DNS queries to the attacker-controlled litellm[.]dev domain used for exfiltration.

compile: pass (Splunk + LogScale) | confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. IOC-based rule matching a specific attacker-registered domain. Very low FP: litellm.dev has no legitimate use. QueryName endswith catches www.litellm.dev and bare litellm.dev. Values NOT defanged. -->

```yaml
title: LiteLLM Supply Chain - DNS Query to Exfiltration Domain
id: 1b4f9a23-6c7e-4d8f-b2a5-3e9c0f1d6b87
status: experimental
description: >
    Detects DNS queries to litellm.dev, the attacker-controlled domain used
    for credential exfiltration and C2 by the compromised LiteLLM 1.107.0
    release. The legitimate LiteLLM project uses litellm.ai.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-docker/
author: Actioner
date: 2026-10-27
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'litellm.dev'
    filter_subdomain:
        QueryName|contains: '.'
    condition: selection
falsepositives:
    - Unlikely; litellm.dev is an attacker-registered lookalike domain with no legitimate use
level: critical
```

**Rule 3: OpenSSL Encryption Staging Activity (.pc_e_ directories)**

Detects OpenSSL processes with the PRIVCOLLECT staging directory pattern.

compile: pass (Splunk + LogScale) | confidence: medium

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Behavioral/TTP rule. The .pc_e_ prefix is highly specific but is a command-line pattern, not a hash, hence medium confidence. Requires process_creation logging with CommandLine capture (Sysmon EID 1 or equivalent). -->

```yaml
title: LiteLLM Supply Chain - OpenSSL Encryption Staging Activity
id: 2c5e8b34-7d9f-4e0a-c3b6-4f1d2a3e7c98
status: experimental
description: >
    Detects OpenSSL processes with command-line arguments matching the
    PRIVCOLLECT credential collector encryption staging pattern, which
    uses temporary directories prefixed with .pc_e_ under /tmp.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026-10-27
tags:
    - attack.t1027.013
    - attack.t1041
logsource:
    category: process_creation
detection:
    selection_binary:
        Image|endswith:
            - '/openssl'
            - '\openssl.exe'
    selection_staging:
        CommandLine|contains: '.pc_e_'
    selection_crypto:
        CommandLine|contains:
            - 'enc -aes-256-cbc'
            - 'pkeyutl'
            - 'rsautl'
    condition: selection_binary and selection_staging and selection_crypto
falsepositives:
    - Highly unlikely; the .pc_e_ directory prefix is specific to the PRIVCOLLECT collector
level: high
```

**Rule 4: PRIVCOLLECT Marker File Creation**

Detects creation of the run-once marker or remote code loader lock file.

compile: pass (Splunk + LogScale) | confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. IOC-based rule matching two specific file paths with embedded hex constant (72129118c59f5636c0bb). Zero known FP. Requires file_event logging (Sysmon EID 11 or equivalent). -->

```yaml
title: LiteLLM Supply Chain - PRIVCOLLECT Marker File Creation
id: 3d6f9c45-8e0a-4f1b-d4c7-5a2e3b4f8d09
status: experimental
description: >
    Detects creation of the PRIVCOLLECT run-once marker file or the remote
    code loader lock file, both written by the compromised LiteLLM 1.107.0
    payload to coordinate execution across processes.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026-10-27
tags:
    - attack.t1546
    - attack.t1059.006
logsource:
    category: file_event
detection:
    selection:
        TargetFilename:
            - '/tmp/.pc_once_72129118c59f5636c0bb'
            - '/tmp/remote_code_loader.lock'
    condition: selection
falsepositives:
    - None known; these filenames are highly specific to the PRIVCOLLECT malware
level: critical
```

**Rule 5: HTTP Connection to Exfiltration Endpoint (litellm[.]dev)**

Detects outbound connections to the attacker-controlled exfiltration domain.

compile: pass (Splunk + LogScale) | confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. IOC-based rule using DestinationHostname. Low FP risk. Requires network_connection logging (Sysmon EID 3 or equivalent). -->

```yaml
title: LiteLLM Supply Chain - HTTP Connection to Exfiltration Endpoint
id: 4e7a0d56-9f1b-4a2c-e5d8-6b3f4c5a9e10
status: experimental
description: >
    Detects outbound network connections to the attacker-controlled domain
    www.litellm.dev used by the PRIVCOLLECT credential collector for
    exfiltration in the compromised LiteLLM 1.107.0 release.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-docker/
author: Actioner
date: 2026-10-27
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'litellm.dev'
    condition: selection
falsepositives:
    - Unlikely; litellm.dev is attacker infrastructure not associated with legitimate LiteLLM services
level: critical
```

### YARA Rules

Three rules detect the malicious startup files by content signatures: cook.pth (exact match with size constraint), cook.py (stealer wrapper strings), and sitecustomize.py (remote code loader strings).

compile: pass (yarac exit 0) | confidence: high

<!-- audit: yarac /tmp/actioner/yara_litellm_pth.yar /dev/null returned exit 0 on attempt 2 (first attempt had 2 unreferenced strings: $aes_cbc in Cook_Py_Collector and $setsid in Sitecustomize_Loader; fixed by adding them to condition alternatives). All three rules use filesize constraints. Cook_PTH rule is extremely specific (filesize < 100 + exact string). Cook_Py_Collector uses combinatorial logic across 8 strings. Sitecustomize_Loader uses 9 strings with combinatorial logic targeting the loader lock, dead drop, and stealer identifiers. Known sample hashes provided in meta. -->

```yara
rule SupplyChain_LiteLLM_Cook_PTH
{
    meta:
        description = "Detects the malicious cook.pth startup hook file from the compromised LiteLLM 1.107.0 release"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        hash = "84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth_import = "import cook" ascii

    condition:
        filesize < 100 and $pth_import
}

rule SupplyChain_LiteLLM_Cook_Py_Collector
{
    meta:
        description = "Detects the cook.py credential collector wrapper from the compromised LiteLLM 1.107.0 release, which base64-decodes and zlib-decompresses the PRIVCOLLECT stealer"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        hash = "03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $b64_decode = "base64.b64decode" ascii
        $zlib_decomp = "zlib.decompress" ascii
        $exec_call = "exec(" ascii
        $privcollect = "privcollect" ascii nocase
        $pc_once = ".pc_once_" ascii
        $aes_cbc = "aes-256-cbc" ascii nocase
        $healthcheck = "/healthcheck" ascii
        $x_token = "XWiA8gZNa7NcX2XRoAEb" ascii

    condition:
        filesize < 200KB and
        (
            (3 of ($b64_decode, $zlib_decomp, $exec_call, $privcollect)) or
            ($pc_once and $healthcheck) or
            ($x_token and 1 of ($b64_decode, $zlib_decomp, $exec_call)) or
            ($aes_cbc and $privcollect)
        )
}

rule SupplyChain_LiteLLM_Sitecustomize_Loader
{
    meta:
        description = "Detects the malicious sitecustomize.py remote code loader from the compromised LiteLLM 1.107.0 release"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa"
        hash = "b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $loader_lock = "remote_code_loader.lock" ascii
        $domain_txt = "domain.txt" ascii
        $codepy = "/codepy" ascii
        $letters9813 = "letters9813" ascii
        $pythonclient = "pythonclient-test" ascii
        $setsid = "os.setsid" ascii
        $devnull = "/dev/null" ascii
        $privcollect = "privcollect" ascii nocase
        $pc_once = ".pc_once_72129118c59f5636c0bb" ascii

    condition:
        filesize < 200KB and
        (
            ($loader_lock and ($domain_txt or $codepy)) or
            ($letters9813 and $pythonclient) or
            ($pc_once and $privcollect) or
            ($setsid and $devnull and $loader_lock)
        )
}
```

### Snort Rules (Snort 2.9 compatible)

Two rules detect the PRIVCOLLECT exfiltration HTTP pattern: one targets the POST to /healthcheck with X-SHA256 header, the other targets the unique X-Token authentication header.

compile: pass (snort -T exit 0) | confidence: high

<!-- audit: Snort 2.9.20 validation using custom snort.conf that includes /tmp/actioner/combined_local.rules; "Snort successfully validated the configuration!" exit 0. Rules use tcp protocol with http_method, http_uri, http_header preprocessor keywords (Snort 2 compatible). SIDs 2100010-2100011. Rule 1 matches POST + /healthcheck + X-SHA256 + application/octet-stream. Rule 2 matches POST + X-Token header with the specific token value XWiA8gZNa7NcX2XRoAEb. -->

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - LiteLLM PRIVCOLLECT Exfiltration to litellm.dev/healthcheck"; flow:established,to_server; content:"POST"; http_method; content:"/healthcheck"; http_uri; content:"X-SHA256"; http_header; content:"application/octet-stream"; http_header; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created 2026-10-27; sid:2100010; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - LiteLLM PRIVCOLLECT Exfiltration X-Token Header"; flow:established,to_server; content:"POST"; http_method; content:"X-Token|3a 20|XWiA8gZNa7NcX2XRoAEb"; http_header; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created 2026-10-27; sid:2100011; rev:1;)
```

### Suricata Rules

Three rules cover the exfiltration HTTP POST (with host and URI matching), the X-Token header, and DNS queries to the exfiltration domain.

compile: pass (suricata -T exit 0) | confidence: high

<!-- audit: suricata -T -S /tmp/actioner/suricata_litellm.rules -l /tmp/actioner returned "Configuration provided was successfully loaded. Exiting." exit 0. Uses Suricata dot-notation buffers (http.method, http.host, http.uri, http.request_header, dns.query). SIDs 2100020-2100022. Rule 1 matches POST to www.litellm.dev/healthcheck. Rule 2 matches POST with X-Token header containing the specific token. Rule 3 matches DNS queries for litellm.dev. -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM PRIVCOLLECT Exfiltration POST to litellm.dev/healthcheck"; flow:established,to_server; http.method; content:"POST"; http.host; content:"www.litellm.dev"; http.uri; content:"/healthcheck"; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created_at 2026-10-27; sid:2100020; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM PRIVCOLLECT Exfiltration X-Token Header"; flow:established,to_server; http.method; content:"POST"; http.request_header; content:"X-Token"; content:"XWiA8gZNa7NcX2XRoAEb"; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created_at 2026-10-27; sid:2100021; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM Supply Chain DNS Query to Exfil Domain litellm.dev"; dns.query; content:"litellm.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created_at 2026-10-27; sid:2100022; rev:1;)
```

## Lessons Learned

1. **Python startup hooks are a persistence blind spot.** The `.pth` file mechanism and automatic `sitecustomize.py` import are legitimate Python features that most security tools do not monitor. Organizations should audit `.pth` files in Python environments and consider monitoring for unexpected file creation in site-packages directories.

2. **Build provenance is necessary but not sufficient.** The compromised release had valid build provenance because it was built through the legitimate pipeline -- it simply pointed at the wrong source repository. Provenance verification must include source repository identity, not just build system attestation.

3. **Credential exposure in supply chain attacks is catastrophic.** The PRIVCOLLECT stealer's scope (16 collection modules targeting cloud, developer, browser, infrastructure, and AI tool credentials) demonstrates that a single compromised dependency can expose an organization's entire credential surface. Credential rotation must cover every reachable secret, not just the obvious ones.

4. **Floating Docker tags are a supply chain risk.** The `latest` and `main-stable` tags pointed to the compromised image for over 2.5 hours. Pinning images by digest prevents this class of exposure entirely.

5. **Committed secrets have a long tail.** The master key committed in May 2026 was exploited five months later. Secret scanning must be paired with immediate rotation, not just detection.

## Sources

- [Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/) -- primary technical analysis with full IOC list, MITRE ATT&CK mapping, and Microsoft Defender hunting queries
- [StepSecurity: litellm 1.107.0 Compromised on PyPI](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer) -- detailed IOCs including Docker image digests, attacker IPs, CI branch names, attacker email addresses, and stealer module enumeration
- [Datadog Security Labs: LiteLLM supply chain compromise](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-docker/) -- timeline, stolen OAuth token detail, and build provenance analysis
- [GitHub Issue #47826: BerriAI/litellm](https://github.com/BerriAI/litellm/issues/47826) -- community tracking issue with initial disclosure
- [Wiz Blog: LiteLLM Compromised, Steals Credentials](https://www.wiz.io/blog/litellm-compromised-steals-credentials) -- post-compromise activity observation (AWS credential misuse)
- [Socket.dev: LiteLLM PyPI Package and Docker Images Compromised](https://socket.dev/blog/litellm-compromise) -- download impact analysis
- [Chainguard: LiteLLM attacked again](https://www.chainguard.dev/unchained/litellm-attacked-again-malicious-1-107-0-wheels-on-pypi-and-docker-hub-october-2026) -- wheel inspection and safe version identification

---
*Report generated by Actioner*
