# Technical Analysis Report: LiteLLM v1.107.0 Supply Chain Attack (2026-10-22)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-22
Version: 1.0-DRAFT

## Executive Summary

On October 21, 2026, LiteLLM version 1.107.0 was published to PyPI and Docker Hub containing a credential stealer ("privcollect") and a remote access trojan (RAT). The attack leveraged stolen GitHub CLI OAuth tokens -- suspected to have been harvested from an internet-exposed LiteLLM deployment's logs -- to compromise three engineers' accounts, disable branch protections, and trigger the release pipeline from a lookalike repository (`Berri-AI/litellm` instead of `BerriAI/litellm`). The malicious version was live on PyPI for approximately 1 hour 41 minutes (11:39-13:20 UTC) and on Docker registries for approximately 2 hours 32 minutes (11:48-14:20 UTC). The stealer exfiltrates browser credentials, cloud tokens, SSH/GPG keys, AI tool API keys, environment variables, and LiteLLM proxy database secrets to the attacker-controlled domain `litellm[.]dev`. Post-exploitation activity from IPs 168[.]100[.]8[.]57 and 165[.]227[.]201[.]8 validated stolen AWS credentials and performed IAM enumeration consistent with LLMjacking. All users should pin to v1.106.2, treat all credentials on affected hosts as compromised, and rotate them from a clean environment.

## Background: LiteLLM

LiteLLM is a widely-used open-source Python library and proxy server (~23 million weekly downloads) that provides a unified interface for calling 100+ LLM APIs. It is commonly deployed as a proxy server in production environments with access to numerous AI provider API keys, cloud credentials, and database connections. This makes it a high-value target: compromising LiteLLM provides access not just to the host system but to the full set of AI service credentials it manages.

This is the second supply chain compromise of LiteLLM in 2026. In March 2026, the TeamPCP group used a similar `.pth` file persistence mechanism. After that incident, LiteLLM moved releases to a private repository, made Docker tags immutable, and began signing Docker images. The October attack occurred after release permissions were temporarily broadened for two additional engineers.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-10-13 00:45 | Attacker registers domain `litellm[.]dev` (behind Cloudflare) |
| 2026-10-13 06:43 | GitHub account `letters9813` created for dead-drop repository |
| 2026-10-19 | LiteLLM temporarily expands release permissions to two additional engineers |
| 2026-10-21 08:56-10:46 | 10 malicious commits pushed to lookalike repository `Berri-AI/litellm`; first nine are GitHub-signed |
| 2026-10-21 09:48 | Commit `783c43bc` adds `data = "cook"` to `pyproject.toml` (bundles malware into wheels) |
| 2026-10-21 10:46 | Commit `20535d8f` adds `COPY cook ./cook` to Dockerfiles |
| 2026-10-21 10:51-11:06 | Malicious build pipeline executes |
| 2026-10-21 ~11:39 | Malicious `litellm==1.107.0` uploaded to PyPI (7 wheels + source tarball) |
| 2026-10-21 ~11:48 | Malicious Docker images pushed to Docker Hub and GHCR |
| 2026-10-21 ~13:01 | Dead-drop `domain.txt` observed returning HTTP 200 with empty body |
| 2026-10-21 ~13:20 | PyPI quarantines the malicious package |
| 2026-10-21 ~13:30 | GitHub takes down the `letters9813` dead-drop repository |
| 2026-10-21 ~13:53 | Docker tags removed from Docker Hub and GHCR |
| 2026-10-21 16:20-17:01 | Attacker validates stolen AWS instance role credentials (~4.5 hours after exfiltration) |
| 2026-10-22 | LiteLLM publicly discloses the incident |

## Root Cause: Stolen GitHub CLI OAuth Tokens via LiteLLM Log Exposure

The attacker accessed an internet-exposed internal LiteLLM deployment through an "unexpected, innocuously named user account." LiteLLM reports that Claude Code can, in some situations, embed a user's GitHub CLI OAuth token in a response body. When response bodies are logged by LiteLLM, those tokens can persist in the logs. The attacker is suspected of harvesting three sets of developer GitHub CLI credentials from these logs.

Using the stolen tokens, the attacker:
1. Accessed a token belonging to a GitHub organization owner and disabled branch protections
2. Force-pushed malicious commits to a hyphenated lookalike repository `Berri-AI/litellm` (legitimate: `BerriAI/litellm`)
3. Used one account to trigger the `BerriAI/project-releaser` workflow and another to approve it
4. The release workflow built, signed, and published the poisoned artifacts

All compromised tokens have been revoked. LiteLLM removed all users except one unaffected user from the GitHub organization and severed trusted publishing links.

## Technical Analysis of the Malicious Payload

### 1. Persistence via Python Startup Hooks (cook.pth + sitecustomize.py)

The attack employs a novel dual-persistence mechanism -- the first documented use of both `.pth` files and `sitecustomize.py` together in the wild.

**cook.pth**: A 12-byte file containing only `import cook`, placed in the Python `site-packages` directory. Python `.pth` files in `site-packages` are processed automatically at interpreter startup. This triggers the credential stealer on every Python invocation.

**sitecustomize.py**: A 25,509-byte file also placed in `site-packages`. Python automatically imports `sitecustomize` at interpreter startup. This module implements the RAT/backdoor functionality.

Build-level injection was achieved via `pyproject.toml` modifications:
- `[tool.maturin]` section with `data = "cook"` (bundles the `cook/` directory into wheels)
- Dockerfiles modified with `COPY cook ./cook`

### 2. Stage 1: Credential Stealer ("privcollect")

`cook.py` (22,252 bytes) contains a single line of obfuscated Python that decodes (Base64 + zlib decompression) into a ~61,000-byte stealer script. The decoded module's internal name is `p14c7d1bb`.

**Configuration variables:**
- `PC_URL` -- exfiltration endpoint
- `PC_TOKEN` -- hardcoded auth token (`XWiA8gZNa7NcX2XRoAEb`)
- `PC_PUBKEY` -- RSA-4096 public key for encrypting exfiltrated data
- `PC_MODULES` -- list of 16 collection modules
- `PC_ONCE_PATH` -- path to run-once marker
- `PC_ASYNC` -- async execution flag

**16 collection modules:**
`sysinfo`, `netinfo`, `browser_pw`, `browser_hist`, `ssh_keys`, `shell_hist`, `cloud_creds`, `dev_secrets`, `container_creds`, `cicd_secrets`, `ai_devtools`, `env_vars`, `db_litellm`, `cloud_metadata`, `gpg_keys`, `tls_privkey`

**Data targeted:**
- **Browsers:** Chrome, Chromium, Edge, Brave, Vivaldi, Opera, Firefox, Safari -- login databases, cookies, browsing history
- **Cloud credentials:** AWS (`~/.aws/`), GCP (service account keys, ADC), Azure (CLI token cache), instance metadata endpoints (IMDSv1/v2, GCP, Azure)
- **SSH/GPG/TLS:** `~/.ssh/` private keys, `~/.gnupg/`, `/etc/ssl/private`, Let's Encrypt, nginx/Apache SSL dirs
- **AI development tools:** Claude Code, Claude Desktop, Cursor, Windsurf/Codeium, Kiro, Zed, GitHub Copilot, VS Code MCP settings, Cline, Roo, Cody, Gemini CLI, Amazon Q, Codex CLI, Continue, Aider, Goose, HuggingFace, and others
- **CI/CD secrets:** GitLab Runner configs, Jenkins master keys, Vault tokens, Terraform/Packer credentials, Kubernetes service account tokens, `/run/secrets`
- **Package managers:** `.npmrc`, `.pypirc`, pip config, Maven, Gradle, Composer, RubyGems, Cargo credentials
- **LiteLLM database:** `SELECT "credential_name", "credential_values" FROM "LiteLLM_CredentialsTable" LIMIT 500` and `SELECT "model_name", "litellm_params" FROM "LiteLLM_ProxyModelTable" LIMIT 500`
- **Environment variables:** All current-process vars plus every readable process's vars via `/proc/<pid>/environ` on Linux
- **Shell history:** bash, zsh, fish, Python/Node REPL, MySQL, psql, Redis, SQLite, `.viminfo`, PowerShell PSReadLine

**Anti-duplication:** Sets `PRIVCOLLECT_ACTIVE=1` environment variable and creates `/tmp/.pc_once_72129118c59f5636c0bb` as a run-once marker.

**Encryption and exfiltration:**
- Collected data packed into a gzip-compressed TAR archive containing `hdr.json`, `data.bin`, `key.bin`
- Data encrypted with AES-256-CBC using a random key
- AES key wrapped with embedded RSA-4096 public key (OAEP with SHA-256)
- RSA public key prefix: `MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvxRBQMVXDXVskKS47haU`
- RSA public key fingerprint (SHA-256 of DER SPKI): `a898fd08ad220fed52488906eb45d196f332b972ad5d85214e7726545ecc4218`
- Crypto backends tried in order: `openssl` CLI, Python `cryptography` package, Windows CNG, bundled pure-Python AES

### 3. C2 Infrastructure

**Exfiltration endpoint:**
- URL: `hxxp://www[.]litellm[.]dev/healthcheck`
- Method: HTTP POST
- Headers:
  - `X-Token: XWiA8gZNa7NcX2XRoAEb`
  - `X-SHA256: <body checksum>`
  - `Content-Type: application/octet-stream`
  - `User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)`
- Retry: Up to 4 attempts, 120-second timeout per request

**Dead-drop resolver:**
- URL: `hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain[.]txt`
- Purpose: Provides the current C2 domain for the second-stage payload
- Historic values: `localhost:18909`, `test[.]test[.]com:18909`
- Status at time of reporting: 404 (GitHub removed the repository)

**Second-stage payload:**
- URL: `hxxp://{domain}/codepy`
- Downloaded, compiled, and executed without signature or hash verification

### 4. Stage 2: Remote Access Trojan (sitecustomize.py)

The RAT runs only on Linux and macOS (uses `fcntl`/`fork`, crashes silently on Windows).

**Execution flow:**
1. Forks a background daemon (detaches from parent, redirects stdio to `/dev/null`, sets cwd to `/`)
2. Acquires lock at `/tmp/remote_code_loader.lock`
3. Enters infinite loop with 3600-second (1 hour) intervals
4. Each cycle: fetches `domain.txt` from GitHub dead-drop, then if domain available, fetches and executes `/codepy` payload

**Remote execution function:**
```python
async def exec_code(code):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        _executor,
        lambda: exec(
            compile(code, "<remote>", "exec"),
            {"__name__": "__main__"},
        ),
    )
```

### 5. Post-Exploitation Activity

Between 16:20 and 17:01 UTC (approximately 4.5 hours after exfiltration), the attacker validated stolen AWS instance role credentials from source IPs 168[.]100[.]8[.]57 and 165[.]227[.]201[.]8:

1. `sts:GetCallerIdentity` -- credential validation
2. `bedrock:ListFoundationModels` + `ListModels` -- LLMjacking reconnaissance
3. In limited environments: IAM enumeration (`ListRoles`, `ListUsers`, `ListAccessKeys`) and general discovery (`ListAccounts`, `DescribeTrails`)

### 6. Anti-Forensics / Evasion Techniques

- **Obfuscation:** `cook.py` uses Base64 + zlib compression as a single-line payload
- **Anti-duplication:** Run-once marker file and environment variable to prevent redundant exfiltration
- **Daemon detachment:** RAT forks to background, detaches from parent (PID 1), redirects stdio to `/dev/null`
- **Lock file:** Prevents multiple RAT instances via `/tmp/remote_code_loader.lock`
- **Legitimate filenames:** `sitecustomize.py` is a legitimate Python filename, and `cook.pth` is innocuous
- **IE7 User-Agent:** Uses a legacy Internet Explorer User-Agent string for the exfiltration request
- **Domain impersonation:** Uses `litellm[.]dev` as exfiltration domain, mimicking the legitimate LiteLLM project
- **Windows failure mode:** The stealer's run-once marker uses a Unix path that fails on Windows, causing the stealer to potentially re-run on every Python start

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.107.0 | All 7 wheels and source tarball contain credential stealer and/or tampered build config |
| litellm/litellm (Docker Hub) | v1.107.0, latest, main-latest, main-stable | Docker images with stealer and RAT |
| ghcr.io/berriai/litellm (GHCR) | v1.107.0 | GitHub Container Registry images |
| ghcr.io/berriai/litellm-database (GHCR) | v1.107.0 | Database variant images |
| ghcr.io/berriai/litellm-non_root (GHCR) | v1.107.0 | Non-root variant images |

### File System

| Platform | Path / File | SHA256 | Description |
|----------|-------------|--------|-------------|
| Linux/macOS | cook.pth (site-packages) | `7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb` | 12-byte persistence trigger |
| Windows | cook.pth (site-packages) | `84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d` | 12-byte persistence trigger |
| Linux/macOS | cook.py (site-packages) | `9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25` | 22,252-byte obfuscated stealer |
| Windows | cook.py (site-packages) | `03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea` | 22,252-byte obfuscated stealer |
| Linux/macOS | sitecustomize.py (site-packages) | `34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa` | 25,509-byte RAT module |
| Windows | sitecustomize.py (site-packages) | `b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465` | 25,509-byte RAT module |
| All | /tmp/.pc_once_72129118c59f5636c0bb | N/A | Stealer run-once marker |
| All | /tmp/remote_code_loader.lock | N/A | RAT daemon lock file |
| All | .pc_sq_*, .pc_e_* (temp dir) | N/A | Temporary staging directories |

**Malicious wheel hashes (SHA-256):**

| Wheel | SHA256 |
|-------|--------|
| litellm-1.107.0-cp310-abi3-macosx_10_12_x86_64.whl | `7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d` |
| litellm-1.107.0-cp310-abi3-macosx_11_0_arm64.whl | `0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a` |
| litellm-1.107.0-cp310-abi3-manylinux_2_28_aarch64.whl | `668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6` |
| litellm-1.107.0-cp310-abi3-manylinux_2_28_x86_64.whl | `462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7` |
| litellm-1.107.0-cp310-abi3-musllinux_1_2_aarch64.whl | `c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054` |
| litellm-1.107.0-cp310-abi3-musllinux_1_2_x86_64.whl | `1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00` |
| litellm-1.107.0-cp310-abi3-win_amd64.whl | `12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484` |
| litellm-1.107.0.tar.gz | `2befe2a79fb4fbbd9a543b5b40b530c8cffa8771bab22b8fb22b2e4ae3b1f819` |

**Malicious container image digests (SHA-256):**

| Image | Platform | Digest |
|-------|----------|--------|
| ghcr.io/berriai/litellm | amd64 | `bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5` |
| ghcr.io/berriai/litellm | arm64 | `56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf` |
| ghcr.io/berriai/litellm-database | amd64 | `24581ddc30767f16ecb69d2b0517556f2cd7dea56971adb42a3d1beb97d69523` |
| ghcr.io/berriai/litellm-database | arm64 | `827dd893c74cf621a860a66a3a447a5c732533f087589ce905573e285c0a239c` |
| ghcr.io/berriai/litellm-non_root | amd64 | `645a67d810628252d63df85dcc8824c58bcc77cf8383f4d3e6321f0ccc3ce9e4` |
| ghcr.io/berriai/litellm-non_root | arm64 | `f75c8edae59b72b1ebfd617295833f465c85bb2fab9c1d60f21b496db86cb8da` |
| docker.io/litellm/litellm | amd64 | `bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5` |
| docker.io/litellm/litellm | arm64 | `56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf` |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `litellm[.]dev` | Attacker-controlled exfiltration domain (registered 2026-10-13, Cloudflare) |
| Domain | `www[.]litellm[.]dev` | Exfiltration endpoint host |
| URL | `hxxp://www[.]litellm[.]dev/healthcheck` | HTTP POST exfiltration endpoint |
| URL | `hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain[.]txt` | Dead-drop C2 domain resolver |
| URL | `hxxp://{domain}/codepy` | Second-stage payload download path |
| IP | `168[.]100[.]8[.]57` | Post-exploitation AWS credential validation |
| IP | `165[.]227[.]201[.]8` | Post-exploitation AWS credential validation |
| HTTP Header | `X-Token: XWiA8gZNa7NcX2XRoAEb` | Hardcoded exfiltration auth token |
| User-Agent | `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)` | Stealer exfiltration UA |
| Git Email | `ckdi82fkoos@proton[.]me` | Attacker commit author email |
| GitHub Account | `letters9813` | Dead-drop account (created 2026-10-13, deleted) |
| GitHub Repo | `Berri-AI/litellm` | Hyphenated lookalike repository |

### Behavioral

- Python process creating `cook.pth` or `cook.py` in `site-packages`
- Detached Python daemon with parent PID 1, cwd `/`, holding lock on `/tmp/remote_code_loader.lock`
- HTTP POST to `/healthcheck` with `X-Token` header and `application/octet-stream` content type
- Hourly HTTP GET to GitHub raw content for `domain.txt` followed by GET to `/codepy`
- Environment variable `PRIVCOLLECT_ACTIVE=1` set in process environment
- AWS API calls `sts:GetCallerIdentity` followed by `bedrock:ListFoundationModels` from unexpected IPs
- Temporary directories matching `.pc_sq_*` or `.pc_e_*` patterns in system temp directory

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into LiteLLM v1.107.0 wheels and Docker images via compromised release pipeline |
| T1546 | Event Triggered Execution | Python `.pth` file and `sitecustomize.py` execute on every Python interpreter start |
| T1059.006 | Command and Scripting Interpreter: Python | Malicious Python code executed via `.pth` import, exec(compile(...)), and remote code download |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | cook.py uses Base64 + zlib compression; exfiltrated data encrypted with AES-256-CBC + RSA-4096 |
| T1140 | Deobfuscate/Decode Files or Information | Self-deobfuscation at runtime to unpack the stealer payload |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvests credentials from config files, .env files, CI/CD configs, shell history |
| T1552.004 | Unsecured Credentials: Private Keys | Steals SSH private keys, GPG keys, TLS private keys |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Queries AWS IMDS, GCP metadata, and Azure instance metadata endpoints |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Extracts saved passwords and cookies from Chrome, Firefox, Edge, Safari |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication via HTTP POST/GET to attacker-controlled endpoints |
| T1041 | Exfiltration Over C2 Channel | Stolen credentials exfiltrated via HTTP POST to litellm[.]dev |
| T1105 | Ingress Tool Transfer | Second-stage Python payload downloaded from /codepy endpoint |
| T1560.001 | Archive Collected Data: Archive via Utility | Collected data packed into gzip-compressed TAR archive |

## Impact Assessment

- **Breadth:** LiteLLM has ~23 million weekly PyPI downloads. The malicious version was available for ~1.7 hours on PyPI and ~2.5 hours on Docker registries. The prior March 2026 incident reportedly affected 2,500+ organizations and 434,000 CI/CD pipelines (per CloudSEK).
- **Depth:** The stealer's 16 modules target every credential class on the host: cloud provider tokens, AI API keys, browser data, SSH/GPG keys, CI/CD secrets, container secrets, and the LiteLLM proxy database itself. A single compromised host could expose an organization's entire AI infrastructure.
- **Stealth:** Python startup hooks execute silently, the daemon detaches and runs hourly, the exfiltration domain mimics the legitimate project, and the IE7 User-Agent string may evade basic UA-based filtering.
- **Post-exploitation confirmed:** AWS credential validation and LLMjacking reconnaissance observed 4.5 hours after exfiltration from two known attacker IPs.

## Detection & Remediation

### Immediate Detection

```bash
# Check for malicious files in Python site-packages
find / -name cook.pth -path "*site-packages*" 2>/dev/null
find / -name cook.py -path "*site-packages*" 2>/dev/null

# Check for stealer/RAT marker files
ls -la /tmp/.pc_once_72129118c59f5636c0bb /tmp/remote_code_loader.lock 2>/dev/null

# Check for running RAT daemon
lsof /tmp/remote_code_loader.lock 2>/dev/null

# Check for staging directories
ls -lad /tmp/.pc_sq_* /tmp/.pc_e_* 2>/dev/null

# Check installed litellm version
pip show litellm 2>/dev/null | grep -i version

# Check Docker images
docker images | grep -i litellm
docker inspect litellm/litellm:latest 2>/dev/null | grep -i digest

# Check for environment variable
env | grep PRIVCOLLECT_ACTIVE
```

### Remediation

1. **Contain:** Immediately isolate any host or container where litellm 1.107.0 was installed or the Docker image was pulled. Preserve evidence before rebuilding.
2. **Eradicate:** Remove the malicious package. Do NOT use the affected environment's Python or pip to inspect it -- rebuild from a reviewed artifact. Kill any detached Python daemon holding `/tmp/remote_code_loader.lock`.
3. **Rotate credentials (from a clean environment):** Treat ALL credentials accessible from affected hosts as compromised. This includes: cloud provider credentials (AWS, GCP, Azure), AI API keys, SSH keys, GPG keys, browser passwords, CI/CD tokens, container secrets, database credentials, and the LiteLLM proxy's stored credentials.
4. **Pin dependencies:** Pin to `litellm==1.106.2` by digest. Verify the integrity of all LiteLLM Docker images by digest, not tag.
5. **Block network indicators:** Block `litellm[.]dev`, the `letters9813` GitHub URLs, and monitor for `/codepy` requests.
6. **Audit cloud logs:** Review AWS CloudTrail, GCP audit logs, and Azure activity logs for unauthorized access from IPs `168[.]100[.]8[.]57` and `165[.]227[.]201[.]8`, or unexpected `sts:GetCallerIdentity` and `bedrock:ListFoundationModels` calls.
7. **Audit GitHub access:** Review GitHub audit logs for unauthorized access via the compromised engineers' accounts.

### Long-Term Hardening

- Enforce digest-pinned dependencies in all CI/CD pipelines and production deployments
- Require multi-party approval (with out-of-band verification) for release workflows
- Implement Python package integrity verification (e.g., Sigstore/PEP 740)
- Monitor for `.pth` files in `site-packages` directories as a detection control
- Restrict LiteLLM deployments from public internet access
- Redact or prevent logging of OAuth tokens and API keys in LLM proxy response bodies
- Use immutable Docker image tags and content trust/signing

## Detection Rules

Five Sigma rules, three Snort rules, five Suricata rules, and four YARA rules detect the stealer persistence files, exfiltration traffic, C2 dead-drop communication, and malicious package contents. All rules validated except where noted. The primary caveat is that `sitecustomize.py` is also a legitimate Python filename -- detection by filename alone requires correlation with other indicators.

### Sigma Rules

File creation of malicious cook.pth in Python site-packages.
Compile: sigma convert Splunk/LogScale -- validated. sigma check -- environment-blocked (MITRE ATT&CK data URL unreachable, not a rule defect).
Confidence: high

```yaml
title: LiteLLM Supply Chain - Malicious cook.pth File in Site-Packages
id: 8a1f3c7e-4b2d-4e9a-b6f1-d8c5e2a9f3b7
status: experimental
description: >
    Detects the creation of cook.pth in a Python site-packages directory,
    a persistence mechanism used by the LiteLLM v1.107.0 supply chain attack
    to load the privcollect credential stealer on every Python interpreter start.
references:
    - https://www.aikido.dev/blog/litellm-compromised-infostealer-rat
    - https://stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026-10-22
tags:
    - attack.t1195.002
    - attack.t1546
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains: 'site-packages'
        TargetFilename|endswith: 'cook.pth'
    condition: selection
falsepositives:
    - Legitimate Python packages using cook.pth (unlikely name)
level: critical
```

<!-- audit: Validated via sigma convert --without-pipeline -t splunk (exit 0) and -t log_scale (exit 0). sigma check blocked by environment proxy on MITRE ATT&CK data URL (HTTP 403), not a rule syntax issue. Tags use technique-level only per convention. TargetFilename uses real values, not defanged. -->

---

Detection of privcollect run-once marker and remote code loader lock file.
Compile: sigma convert Splunk/LogScale -- validated.
Confidence: high

```yaml
title: LiteLLM Supply Chain - Stealer Run-Once Marker File
id: 2d7e9b4a-6f1c-4a3e-8d5b-c9e2f1a7b3d6
status: experimental
description: >
    Detects creation of the privcollect stealer run-once marker file
    /tmp/.pc_once_72129118c59f5636c0bb or the remote code loader lock file
    /tmp/remote_code_loader.lock, both indicators of the LiteLLM v1.107.0 compromise.
references:
    - https://www.aikido.dev/blog/litellm-compromised-infostealer-rat
    - https://www.wiz.io/blog/litellm-compromised-steals-credentials
author: Actioner
date: 2026-10-22
tags:
    - attack.t1195.002
    - attack.t1059.006
logsource:
    category: file_event
detection:
    selection_marker:
        TargetFilename: '/tmp/.pc_once_72129118c59f5636c0bb'
    selection_lock:
        TargetFilename: '/tmp/remote_code_loader.lock'
    condition: selection_marker or selection_lock
falsepositives:
    - None known
level: critical
```

<!-- audit: Validated via sigma convert --without-pipeline -t splunk (exit 0) and -t log_scale (exit 0). Exact file path values from Aikido/StepSecurity analysis. No defanging needed for file paths. -->

---

DNS query to the attacker-controlled exfiltration domain.
Compile: sigma convert Splunk/LogScale -- validated.
Confidence: high

```yaml
title: LiteLLM Supply Chain - DNS Query to Exfiltration Domain litellm.dev
id: f4c8a1e6-3b7d-4d2f-9e5a-a6b3c8d1f2e9
status: experimental
description: >
    Detects DNS resolution of the attacker-controlled domain litellm.dev used
    as the exfiltration endpoint in the LiteLLM v1.107.0 supply chain attack.
    This domain is not affiliated with the legitimate LiteLLM project.
references:
    - https://www.wiz.io/blog/litellm-compromised-steals-credentials
    - https://stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026-10-22
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'litellm.dev'
    condition: selection
falsepositives:
    - None known - this domain is attacker-controlled
level: critical
```

<!-- audit: Validated via sigma convert. Uses real domain value (not defanged) per logsource-encoding spec. endswith handles both bare domain and subdomains. -->

---

HTTP proxy log detection for exfiltration traffic.
Compile: sigma convert Splunk/LogScale -- validated.
Confidence: high

```yaml
title: LiteLLM Supply Chain - HTTP POST to litellm.dev Healthcheck Exfil Endpoint
id: b3e5d8f2-1a9c-4c7e-a4b6-e7f2d9c1a8b5
status: experimental
description: >
    Detects HTTP connections to the exfiltration endpoint www.litellm.dev/healthcheck
    used by the privcollect credential stealer in the LiteLLM v1.107.0 compromise.
references:
    - https://www.aikido.dev/blog/litellm-compromised-infostealer-rat
    - https://stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026-10-22
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '/healthcheck'
        r-dns|endswith: 'litellm.dev'
    condition: selection
falsepositives:
    - None known - this domain is attacker-controlled
level: critical
```

<!-- audit: Validated via sigma convert. Proxy logsource fields c-uri and r-dns are standard W3C extended log format field names. Real domain values used. -->

---

Detection of the PRIVCOLLECT_ACTIVE environment variable in process creation.
Compile: sigma convert Splunk/LogScale -- validated.
Confidence: medium

```yaml
title: LiteLLM Supply Chain - PRIVCOLLECT_ACTIVE Environment Variable
id: a1d4f7c9-8e3b-4b6a-c2d5-f9e1a3b7d8c6
status: experimental
description: >
    Detects process creation where the PRIVCOLLECT_ACTIVE environment variable is set,
    indicating the LiteLLM v1.107.0 privcollect credential stealer is active or has
    been inherited by child processes.
references:
    - https://www.wiz.io/blog/litellm-compromised-steals-credentials
    - https://stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026-10-22
tags:
    - attack.t1059.006
    - attack.t1195.002
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'PRIVCOLLECT_ACTIVE'
    condition: selection
falsepositives:
    - Security researchers analyzing the malware
level: critical
```

<!-- audit: Validated via sigma convert. CommandLine may not always contain the env var string; detection depends on how the variable is propagated. Medium confidence as env var may not appear in logged command line. -->

### Snort Rules

Detects HTTP POST to the litellm.dev exfiltration endpoint with the hardcoded X-Token header.
Compile: snort -T validated (via local.rules include).
Confidence: high

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - LiteLLM Supply Chain Exfil POST to litellm.dev/healthcheck"; flow:established,to_server; content:"POST"; http_method; content:"/healthcheck"; http_uri; content:"X-Token|3a 20|XWiA8gZNa7NcX2XRoAEb"; http_header; fast_pattern; classtype:trojan-activity; reference:url,www.aikido.dev/blog/litellm-compromised-infostealer-rat; metadata:author Actioner, created 2026-10-22; sid:2100001; rev:1;)
```

<!-- audit: Snort 2.9 syntax validated. Uses http_method, http_uri, http_header sticky buffers. X-Token header matched with hex colon-space separator. fast_pattern on the most unique content string. -->

---

Detects HTTP GET/POST to the /codepy second-stage payload endpoint.
Compile: snort -T validated.
Confidence: high

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - LiteLLM Supply Chain C2 Fetch /codepy Endpoint"; flow:established,to_server; content:"/codepy"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,www.wiz.io/blog/litellm-compromised-steals-credentials; metadata:author Actioner, created 2026-10-22; sid:2100002; rev:1;)
```

<!-- audit: Snort 2.9 syntax validated. Short URI path "/codepy" may generate FPs in environments with legitimate /codepy endpoints (unlikely). -->

---

Detects HTTP fetch of the GitHub dead-drop domain.txt file.
Compile: snort -T validated.
Confidence: high

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - LiteLLM Supply Chain GitHub Dead Drop domain.txt Fetch"; flow:established,to_server; content:"/letters9813/pythonclient-test/main/domain.txt"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer; metadata:author Actioner, created 2026-10-22; sid:2100003; rev:1;)
```

<!-- audit: Snort 2.9 syntax validated. Full path match is highly specific, very low FP risk. GitHub raw content uses HTTPS so this requires TLS interception or visibility at the proxy layer. -->

### Suricata Rules

Detects HTTP POST to litellm.dev/healthcheck exfiltration endpoint.
Compile: suricata -T validated (exit 0).
Confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Exfil POST to litellm.dev healthcheck"; flow:established,to_server; http.method; content:"POST"; http.host; content:"litellm.dev"; endswith; http.uri; content:"/healthcheck"; startswith; fast_pattern; classtype:trojan-activity; reference:url,www.aikido.dev/blog/litellm-compromised-infostealer-rat; metadata:author Actioner, created_at 2026-10-22; sid:2200001; rev:1;)
```

<!-- audit: Suricata 7.0.3 validated. Dot-notation buffers. http.host endswith matches both bare domain and www. subdomain. Exfil uses plain HTTP so no TLS interception required. -->

---

Detects HTTP POST with the hardcoded X-Token exfiltration header.
Compile: suricata -T validated.
Confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Exfil X-Token Header"; flow:established,to_server; http.method; content:"POST"; http.header; content:"X-Token: XWiA8gZNa7NcX2XRoAEb"; fast_pattern; classtype:trojan-activity; reference:url,www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer; metadata:author Actioner, created_at 2026-10-22; sid:2200002; rev:1;)
```

<!-- audit: Suricata 7.0.3 validated. X-Token value is 20-char unique string -- extremely low FP risk. -->

---

Detects DNS query to the attacker-controlled litellm.dev domain.
Compile: suricata -T validated.
Confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM Supply Chain DNS Query to litellm.dev"; dns.query; content:"litellm.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.wiz.io/blog/litellm-compromised-steals-credentials; metadata:author Actioner, created_at 2026-10-22; sid:2200003; rev:1;)
```

<!-- audit: Suricata 7.0.3 validated. dns.query buffer. Matches any query containing litellm.dev. Real domain value used (not defanged). -->

---

Detects HTTP fetch to the /codepy second-stage payload path.
Compile: suricata -T validated.
Confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain C2 Fetch codepy Endpoint"; flow:established,to_server; http.uri; content:"/codepy"; startswith; fast_pattern; classtype:trojan-activity; reference:url,www.wiz.io/blog/litellm-compromised-steals-credentials; metadata:author Actioner, created_at 2026-10-22; sid:2200004; rev:1;)
```

<!-- audit: Suricata 7.0.3 validated. startswith on "/codepy" for precision. -->

---

Detects HTTP fetch of the GitHub dead-drop domain.txt resolver.
Compile: suricata -T validated.
Confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain GitHub Dead Drop domain.txt Fetch"; flow:established,to_server; http.uri; content:"/letters9813/pythonclient-test/main/domain.txt"; fast_pattern; classtype:trojan-activity; reference:url,www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer; metadata:author Actioner, created_at 2026-10-22; sid:2200005; rev:1;)
```

<!-- audit: Suricata 7.0.3 validated. Full URI path is highly specific. GitHub raw content uses HTTPS; requires TLS interception or proxy visibility. -->

### YARA Rules

Detects the malicious cook.pth persistence trigger file.
Compile: yarac -- validated (exit 0).
Confidence: high

```yara
rule SupplyChain_LiteLLM_CookPth : litellm supply_chain
{
    meta:
        description = "Detects the malicious cook.pth file used in the LiteLLM v1.107.0 supply chain attack for Python startup persistence"
        author = "Actioner"
        date = "2026-10-22"
        reference = "https://www.aikido.dev/blog/litellm-compromised-infostealer-rat"
        severity = "critical"
        hash = "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        hash = "84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d"

    strings:
        $pth_content = "import cook" fullword

    condition:
        filesize < 50 and $pth_content
}
```

<!-- audit: yarac validated (exit 0). Matches the exact 12-byte cook.pth file content. filesize < 50 prevents matching against larger files that happen to contain "import cook". -->

---

Detects the obfuscated privcollect credential stealer (cook.py, decoded form).
Compile: yarac -- validated (exit 0).
Confidence: high

```yara
rule SupplyChain_LiteLLM_CookPy_Stealer : litellm supply_chain stealer
{
    meta:
        description = "Detects the obfuscated cook.py privcollect credential stealer from the LiteLLM v1.107.0 supply chain attack"
        author = "Actioner"
        date = "2026-10-22"
        reference = "https://stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer"
        severity = "critical"
        hash = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        hash = "03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea"

    strings:
        $s1 = "privcollect" ascii
        $s2 = "PRIVCOLLECT_ACTIVE" ascii
        $s3 = "PC_URL" ascii
        $s4 = "PC_TOKEN" ascii
        $s5 = "PC_PUBKEY" ascii
        $s6 = "PC_MODULES" ascii
        $s7 = "PC_ONCE_PATH" ascii
        $s8 = ".pc_once_72129118c59f5636c0bb" ascii
        $s9 = "pc_post" ascii
        $s10 = "p14c7d1bb" ascii
        $rsa_prefix = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvxRBQMVXDXVskKS47haU" ascii
        $x_token = "XWiA8gZNa7NcX2XRoAEb" ascii
        $exfil_url = "litellm.dev/healthcheck" ascii
        $ua = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)" ascii

    condition:
        filesize < 100KB and (3 of ($s*) or $rsa_prefix or ($x_token and $exfil_url) or ($ua and $exfil_url))
}
```

<!-- audit: yarac validated (exit 0). Targets decompressed/decoded stealer payload. RSA key prefix and X-Token are unique to this campaign. 3 of ($s*) requires multiple config variable names for high specificity. -->

---

Detects the sitecustomize.py RAT module.
Compile: yarac -- validated (exit 0).
Confidence: high

```yara
rule SupplyChain_LiteLLM_Sitecustomize_RAT : litellm supply_chain rat
{
    meta:
        description = "Detects the malicious sitecustomize.py RAT module from the LiteLLM v1.107.0 supply chain attack that fetches and executes remote Python code"
        author = "Actioner"
        date = "2026-10-22"
        reference = "https://www.wiz.io/blog/litellm-compromised-steals-credentials"
        severity = "critical"
        hash = "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa"
        hash = "b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465"

    strings:
        $s1 = "remote_code_loader" ascii
        $s2 = "exec_code" ascii
        $s3 = "/codepy" ascii
        $s4 = "LOOP_INTERVAL" ascii
        $s5 = "GITHUB_RAW_URL" ascii
        $s6 = "resolve_domain" ascii
        $s7 = "fetch_text" ascii
        $s8 = "letters9813" ascii
        $s9 = "pythonclient-test" ascii
        $exec_pattern = "exec(compile(code" ascii

    condition:
        filesize < 100KB and (3 of ($s*) or ($exec_pattern and 1 of ($s*)))
}
```

<!-- audit: yarac validated (exit 0). Targets the decoded RAT module. String combination is highly specific to this campaign. exec(compile(code is the unique remote execution pattern. -->

---

Detects LiteLLM v1.107.0 malicious wheel files by embedded metadata.
Compile: yarac -- validated (exit 0).
Confidence: medium

```yara
rule SupplyChain_LiteLLM_Wheel_1107 : litellm supply_chain
{
    meta:
        description = "Detects LiteLLM v1.107.0 malicious wheel files by embedded payload indicators in the compressed archive"
        author = "Actioner"
        date = "2026-10-22"
        reference = "https://stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer"
        severity = "critical"

    strings:
        $wheel_meta = "litellm-1.107.0" ascii
        $pth_entry = "cook.pth" ascii
        $cook_entry = "cook.py" ascii
        $maturin = "tool.maturin" ascii
        $data_cook = "data = \"cook\"" ascii

    condition:
        filesize < 50MB and $wheel_meta and ($pth_entry or $cook_entry) and ($maturin or $data_cook)
}
```

<!-- audit: yarac validated (exit 0). Targets the wheel/archive files. Requires version string AND payload file names AND build config indicators. Medium confidence as ZIP entry names may be compressed in the wheel; works best on extracted wheels or source tarballs. -->

## Lessons Learned

1. **AI tool response logging is a credential exposure vector.** The suspected root cause -- GitHub CLI OAuth tokens embedded in LLM response bodies and captured in LiteLLM logs -- highlights a new class of credential leakage. Organizations using LLM proxies must sanitize response bodies before logging and restrict access to log stores.

2. **Supply chain attacks on AI infrastructure have cascading impact.** LiteLLM's role as a credential aggregator for multiple AI providers means a single compromise exposes an organization's entire AI credential surface. The stealer's 16 targeted modules and specific LiteLLM database queries demonstrate attacker awareness of this amplification.

3. **Release pipeline security must survive temporary exceptions.** LiteLLM had hardened its release process after the March incident, but temporarily broadening permissions for two engineers recreated the attack surface. Temporary access grants need the same security controls (MFA, out-of-band approval, audit) as permanent ones.

4. **Python `.pth` files remain a powerful persistence vector.** The combination of `.pth` and `sitecustomize.py` for dual-stage execution at interpreter startup -- the first documented use in the wild -- demonstrates that Python's startup hook mechanisms need monitoring as part of endpoint detection.

5. **Post-exploitation speed matters.** The attacker validated stolen AWS credentials within 4.5 hours of exfiltration and targeted Bedrock/LLM services (LLMjacking). Detection and response windows for supply chain attacks on AI infrastructure are measured in hours, not days.

## Sources

- [The Hacker News - LiteLLM Compromised in Supply Chain Attack](https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html) -- Initial reporting on the compromise, payload mechanics, and affected artifacts
- [The Hacker News - LiteLLM Suspects GitHub Token Leak](https://thehackernews.com/2026/10/litellm-suspects-github-token-leak-in.html) -- Root cause analysis, detailed timeline, post-exploitation activity
- [The Register - LiteLLM Supply Chain Attack](https://www.theregister.com/security/2026/10/21/litellm-supply-chain-attack-hoovers-up-passwords-and-secrets/5304548) -- Independent reporting on stealer capabilities and scale
- [Aikido Security - LiteLLM Compromised: Infostealer and RAT](https://www.aikido.dev/blog/litellm-compromised-infostealer-rat) -- Primary file path indicators, stealer module analysis, file hashes
- [Wiz - LiteLLM Compromised: Steals Credentials](https://www.wiz.io/blog/litellm-compromised-steals-credentials) -- Post-exploitation activity, AWS credential validation, IP indicators, container digests
- [StepSecurity - LiteLLM 1.107.0 Compromised](https://stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer) -- Wheel hashes, code string analysis, encryption details, build-level injection, RSA key details
- [Socket - LiteLLM Compromise](https://socket.dev/blog/litellm-compromise) -- Mitigation guidance, wheel hashes, container image digests
- [LiteLLM Security Incident Advisory](https://docs.litellm.ai/blog/security-incident-oct-21-2026) -- Official vendor incident disclosure
- [LiteLLM GitHub Issue #47826](https://github.com/BerriAI/litellm/issues/47826) -- Community discussion and tracking

---
*Report generated by Actioner*
