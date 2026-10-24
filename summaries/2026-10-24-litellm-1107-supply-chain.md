# Technical Analysis Report: LiteLLM 1.107.0 Supply Chain Compromise (2026-10-24)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-24
Version: 1.0 (DRAFT)

## Executive Summary

On October 21, 2026, attackers compromised the release pipeline for LiteLLM -- a widely used open-source AI gateway/proxy for LLM API calls -- and published a malicious version 1.107.0 to PyPI and container registries (GHCR, Docker Hub). The attack leveraged stolen developer credentials to redirect the build workflow to a lookalike GitHub repository (`Berri-AI/litellm`, hyphenated, vs. the legitimate `BerriAI/litellm`), which contained backdoored build configuration injecting three malicious files (`cook.pth`, `cook.py`, `sitecustomize.py`) into Python's `site-packages` directory. These files exploit Python's `.pth` startup hook mechanism to execute a credential stealer and a remote code loader on every Python interpreter invocation -- even without importing LiteLLM. The stealer harvests cloud credentials (AWS, Azure, GCP), browser data, SSH/GPG keys, environment variables, shell histories, AI tool configurations, and LiteLLM proxy database secrets, encrypting and exfiltrating them to the attacker-controlled domain `litellm[.]dev`. A companion remote code loader polls a GitHub-hosted dead drop resolver hourly for second-stage payload instructions. The malicious release was live on PyPI for approximately 1 hour 43 minutes (11:39-13:23 UTC) and on container registries slightly longer. Seven malicious platform-specific wheels were published. The package was quarantined on PyPI and affected container images removed the same day.

## Background: LiteLLM

LiteLLM is a popular open-source Python library and proxy server that provides a unified interface for calling 100+ LLM providers (OpenAI, Anthropic, Azure, AWS Bedrock, etc.) through a single API. It is widely deployed in production AI infrastructure as a gateway/proxy, often with access to multiple cloud provider API keys and credentials. This makes it a high-value target for supply chain attacks, as compromising a LiteLLM deployment can yield access to numerous downstream AI service credentials, cloud infrastructure secrets, and sensitive data flowing through the proxy. The project is maintained by BerriAI and distributed via PyPI and Docker Hub/GHCR container images.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-10-13 00:45 | Attacker registers lookalike domain `litellm[.]dev` (behind Cloudflare) |
| 2026-10-13 06:43 | GitHub account `letters9813` created (dead drop host) |
| 2026-10-18 04:17 | Dead drop repository `pythonclient-test` created on GitHub |
| 2026-10-19 02:51 | Dead drop `domain.txt` updated to `test[.]test[.]com:18909` |
| 2026-10-20 09:15 | Dead drop `domain.txt` emptied (disabling second-stage loader) |
| 2026-10-21 08:56-10:46 | Ten attacker commits pushed to lookalike `Berri-AI/litellm` repository |
| 2026-10-21 10:08:29 | Branch protection rejects unauthorized workflow change |
| 2026-10-21 10:08:34 | Org owner token overrides branch protection |
| 2026-10-21 10:46:39 | Staging build run starts from `Berri-AI/litellm` |
| 2026-10-21 11:11:18 | Second developer credential satisfies production approval gate |
| 2026-10-21 11:39:51-11:40:13 | Seven malicious wheels uploaded to PyPI |
| 2026-10-21 11:46:56 | Infected container images published; floating tags (`latest`, `main-latest`, `main-stable`) repointed |
| 2026-10-21 11:53:49-11:54:01 | Attacker deletes workflow run records |
| 2026-10-21 12:06 | Compromise reported in BerriAI/litellm issue #47826 |
| 2026-10-21 ~13:23 | Version 1.107.0 removed/quarantined from PyPI |
| 2026-10-21 13:51 | GHCR tags made unavailable |
| 2026-10-21 14:20 | Docker Hub tags removed or repointed |
| 2026-10-21 (afternoon) | `letters9813` account and dead drop repository deleted |
| 2026-10-22 | Microsoft Defender detections available |
| 2026-10-23 | Microsoft publishes detailed technical analysis |

## Root Cause: Compromised Release Pipeline via Stolen Developer Credentials

The attacker gained access to developer credentials associated with the BerriAI GitHub organization. According to LiteLLM maintainers (not independently confirmed by Microsoft), the attacker used stolen credentials tied to a developer account to alter the release workflow, redirecting the build process to a lookalike repository `Berri-AI/litellm` (note the hyphen -- the legitimate organization is `BerriAI`). When branch protection initially rejected the unauthorized workflow modification, an organization owner token was used to override the protection five seconds later. A credential tied to a second developer account then satisfied the production approval gate, allowing the malicious build to proceed. The exact method by which the attacker first obtained access to the upstream environment remains unknown. The attacker commit author identity was `Berri-AI <ckdi82fkoos@proton[.]me>`.

## Technical Analysis of the Malicious Payload

### 1. Build System Injection

The attacker modified the `pyproject.toml` build configuration, adding `data = "cook"` under `[tool.maturin]` and including a `cook/` directory in the source. This instructs the Maturin build tool to package the contents of the `cook/` directory into the wheel's `litellm-1.107.0.data/purelib/` path. When pip installs the wheel, files in `purelib/` are placed directly into the Python environment's `site-packages` directory -- critically, outside the `litellm` application directory itself. This means uninstalling or deleting the `litellm` package directory does not remove the malicious files.

Three files were injected:
- **`cook.pth`** -- Python startup hook trigger (12 bytes: `import cook`)
- **`cook.py`** -- Primary payload launcher (Base64+zlib-compressed stealer and loader)
- **`sitecustomize.py`** -- Secondary Unix-oriented payload launcher

Seven platform-specific wheels were built and published, covering macOS (x86_64, ARM64), Linux (glibc aarch64/x86_64, musl aarch64/x86_64), and Windows (amd64).

### 2. Persistence via Python Startup Hooks (.pth Files)

The core persistence mechanism exploits Python's `.pth` file processing. During site initialization, Python reads all `.pth` files in `site-packages`. Lines that begin with `import` are executed as Python code. The `cook.pth` file contains the single line `import cook`, which triggers execution of `cook.py` on every Python interpreter startup -- including pip, pytest, linters, IDE helpers, and any script -- without the user explicitly importing LiteLLM.

`cook.py` contains obfuscated code that decodes and executes a zlib-compressed, Base64-encoded payload:
```
exec(zlib.decompress(base64.b64decode(...)), {'__name__': 'p14c7d1bb'})
```

`sitecustomize.py` provides a redundant execution path, particularly effective on Unix systems. Both files have LF (Unix) and CRLF (Windows) line-ending variants, accounting for the two SHA-256 hashes per file.

### 3. Credential Stealer ("PRIVCOLLECT")

The decoded payload is a comprehensive credential stealer that self-identifies as `privcollect`. On first execution it sets the environment variable `PRIVCOLLECT_ACTIVE=1` to prevent recursive invocation. The stealer runs as a daemon thread and targets:

- **AI/Developer Tools:** AI assistant configs, IDE settings, GitHub Copilot tokens, VS Code credentials, MCP configuration files
- **Source Control & Packages:** Git credentials, package manager configs (npm, pip), `.env`/dotenv files, private key files
- **Cloud Infrastructure:** AWS credentials and config, Azure CLI token caches, Google Cloud application default credentials, Kubernetes service account files, Docker config with registry auth, mounted secrets volumes
- **Cloud Metadata:** AWS STS `GetCallerIdentity`, IMDSv2 metadata credential requests, GCP metadata API
- **Browsers:** Chromium-family and Firefox credential stores, cookie databases, browsing history
- **Keys & Certificates:** SSH keys, GPG keyrings, TLS certificates and keys
- **Infrastructure Tools:** CI/CD configs (Jenkins, GitLab CI, CircleCI), HashiCorp Vault tokens, Terraform state
- **Shell Histories:** bash, zsh, fish, Python, database client histories
- **Process Environments:** On Linux, reads `/proc/<pid>/environ` for all readable process environments
- **LiteLLM Proxy Database:** Queries `LiteLLM_CredentialsTable` (credential_values) and `LiteLLM_ProxyModelTable` (litellm_params) with a 500-row limit; kills Prisma `query-engine` processes to release database locks

Collection modules run sequentially with independent error handling. Shallow directory walks and file-size limits constrain searches to avoid excessive resource consumption.

### 4. Exfiltration Protocol

Collected data is encrypted and exfiltrated via HTTP POST:

1. A fresh 32-byte AES-256 key and 16-byte IV are generated per run
2. Collected data is encrypted with AES-256-CBC
3. The AES key is wrapped with a hardcoded 4,096-bit RSA public key using OAEP padding (SHA-256, falling back to SHA-1)
4. The encrypted data, wrapped key, and metadata are packaged into a gzip tar archive with members: `data.bin`, `key.bin`, `hdr.json`
5. The archive is POSTed to `hxxp://www[.]litellm[.]dev/healthcheck` with headers:
   - `Content-Type: application/octet-stream`
   - `User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)`
   - `X-Token: XWiA8gZNa7NcX2XRoAEb`
   - `X-SHA256: <SHA-256 of request body>`
6. Only HTTP 200 is treated as success
7. On successful exfiltration, the marker file `/tmp/.pc_once_72129118c59f5636c0bb` is created to prevent repeat runs

The RSA public key prefix is `MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvxRBQMVXDXVskKS47haU`.

### 5. Remote Code Loader

A companion component establishes an hourly polling loop to fetch and execute arbitrary second-stage code:

1. On Unix, the loader daemonizes via `os.fork()`, `setsid()`, redirects output to `/dev/null`, and changes cwd to `/`
2. Acquires an exclusive `fcntl` lock on `/tmp/remote_code_loader.lock` to ensure single-instance execution
3. Polls `hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt` to resolve the second-stage server address
4. Requests `http://<resolved-host>/codepy` and executes the response directly via `exec()` without any signature verification
5. Loop interval: 3,600 seconds (1 hour)

At the time of analysis, `domain.txt` was empty, so no second-stage payload was confirmed to have been delivered. Historical values observed in the dead drop included `localhost:18909` and `test[.]test[.]com:18909`, suggesting pre-deployment testing.

### 6. Anti-Forensics / Evasion Techniques

- **Lookalike repository:** `Berri-AI/litellm` (hyphenated) vs. legitimate `BerriAI/litellm`
- **Lookalike domain:** `litellm[.]dev` (registered 2026-10-13) mimicking the legitimate project
- **Workflow log deletion:** Build run records deleted within minutes of publication (11:53-11:54 UTC)
- **Dead drop architecture:** Second-stage server address resolved dynamically via GitHub-hosted file, allowing rapid C2 rotation
- **Payload obfuscation:** Source embedded as Base64+zlib-compressed blob with aliased imports
- **Encrypted exfiltration:** AES-256-CBC + RSA-4096 OAEP prevents content inspection
- **Browser-like User-Agent:** Mimics Internet Explorer 7.0 to blend with web traffic
- **Run-once marker:** Prevents repeated exfiltration that could trigger volume-based alerts
- **Line-ending variants:** Separate hashes for LF and CRLF variants of payload files

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.107.0 | Backdoored wheels with credential stealer and remote code loader |
| litellm sdist (PyPI) | 1.107.0 | Source distribution tarball with backdoor |
| ghcr.io/berriai/litellm | v1.107.0 | Compromised container image |
| ghcr.io/berriai/litellm-database | v1.107.0 | Compromised container image |
| ghcr.io/berriai/litellm-non_root | v1.107.0 | Compromised container image |
| docker.io/litellm/litellm | v1.107.0 | Compromised container image |

**Affected floating tags** (between 11:46 and 14:20 UTC on 2026-10-21): `latest`, `main-latest`, `main-stable`

**Last known clean version:** litellm 1.106.2

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux/macOS | `<site-packages>/cook.pth` | 7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb | Startup hook trigger (LF) |
| Windows | `<site-packages>/cook.pth` | 84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d | Startup hook trigger (CRLF) |
| Linux/macOS | `<site-packages>/cook.py` | 9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25 | Primary payload launcher (LF) |
| Windows | `<site-packages>/cook.py` | 03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea | Primary payload launcher (CRLF) |
| Linux/macOS | `<site-packages>/sitecustomize.py` | 34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa | Secondary payload launcher (LF) |
| Windows | `<site-packages>/sitecustomize.py` | b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465 | Secondary payload launcher (CRLF) |
| All | `/tmp/.pc_once_72129118c59f5636c0bb` | -- | Stealer run-once marker |
| All | `/tmp/remote_code_loader.lock` | -- | Loader single-instance lock |
| All | `<tmpdir>/.pc_e_*` | -- | Stealer staging directories |
| All | `<tmpdir>/.pc_sq_*` | -- | Stealer staging directories |
| Docker | `/app/.venv/lib/python3.13/site-packages/` | -- | Container payload path |

**Malicious wheel hashes (SHA256):**

| Wheel Platform | SHA256 |
|----------------|--------|
| macosx_10_12_x86_64 | 7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d |
| macosx_11_0_arm64 | 0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a |
| manylinux_2_28_aarch64 | 668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6 |
| manylinux_2_28_x86_64 | 462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7 |
| musllinux_1_2_aarch64 | c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054 |
| musllinux_1_2_x86_64 | 1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00 |
| win_amd64 | 12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484 |

**Source distribution hash (SHA256):**
- litellm-1.107.0.tar.gz: `2befe2a79fb4fbbd9a543b5b40b530c8cffa8771bab22b8fb22b2e4ae3b1f819`

**Container image index hash (SHA256):**
- ghcr.io/berriai/litellm:v1.107.0: `1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e`
- ghcr.io/berriai/litellm:v1.107.0 (amd64 manifest): `bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5`

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | litellm[.]dev | Attacker-registered exfiltration domain (registered 2026-10-13, behind Cloudflare) |
| Domain | www[.]litellm[.]dev | Exfiltration endpoint hostname |
| URL Pattern | hxxp://www[.]litellm[.]dev/healthcheck | Credential exfiltration POST endpoint |
| URL | hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt | Dead drop resolver for second-stage C2 |
| URL Pattern | hxxp://&lt;resolved-host&gt;/codepy | Second-stage payload download path |
| HTTP Header | X-Token: XWiA8gZNa7NcX2XRoAEb | Fixed authentication token in exfiltration requests |
| User-Agent | Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0) | Fixed User-Agent in exfiltration requests |
| Email | ckdi82fkoos[at]proton[.]me | Attacker commit author email |

### Behavioral

- `.pth` files in `site-packages` executing `import cook` on every Python startup
- Daemon thread spawned during Python site initialization performing credential harvesting
- Background process daemonizing via `fork()`/`setsid()` with `/dev/null` output redirection
- Hourly HTTP polling to GitHub raw content URL for C2 resolution
- Encrypted HTTP POST exfiltration with AES-256-CBC + RSA-4096 OAEP wrapping
- `/proc/<pid>/environ` reads for harvesting process environment variables
- Prisma `query-engine` process termination to access LiteLLM proxy database
- Creation of temporary staging directories with `.pc_e_` and `.pc_sq_` prefixes
- Run-once marker file creation after successful exfiltration

### Git/Repository Artifacts

| Artifact | Value | Context |
|----------|-------|---------|
| Lookalike repo | github[.]com/Berri-AI/litellm | Malicious source fork (hyphenated org name; now 404) |
| Malicious head commit | 20535d8fa11f786a6c24df7488a0e449ed5f09ad | Final attacker commit |
| Clean v1.107.0 tag | 66c8f5b1a9 | Legitimate tag (not compromised) |
| Malicious workflow commit | 9cf97e935aeaf791b9c8db224a2bb3ee156134ce | Private BerriAI repo |
| Build run ID | 39587059944 | BerriAI/project-releaser |
| GitHub account | letters9813 | Dead drop host (deleted) |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Attacker compromised LiteLLM release pipeline to distribute malicious package via PyPI and container registries |
| T1546.018 | Event Triggered Execution: Python Startup Hooks | Malicious `.pth` file in site-packages executes `import cook` on every Python interpreter startup |
| T1059.006 | Command and Scripting Interpreter: Python | Payload executed via Python's built-in site initialization mechanism |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Stealer source embedded as Base64+zlib-compressed blob with aliased imports |
| T1140 | Deobfuscate/Decode Files or Information | Runtime decompression and execution of encoded payload |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvests credentials from config files, dotenv files, shell histories |
| T1552.004 | Unsecured Credentials: Private Keys | Collects SSH keys, GPG keyrings, TLS private keys |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Queries AWS IMDSv2 and GCP metadata APIs for instance credentials |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Extracts credential data from Chromium and Firefox browser stores |
| T1082 | System Information Discovery | Runs `systeminfo`, `ipconfig`, `route`, `arp`, `netstat` on Windows |
| T1016 | System Network Configuration Discovery | Network configuration enumeration via system commands |
| T1005 | Data from Local System | Broad collection of credentials, configs, and secrets from local filesystem |
| T1074.001 | Data Staged: Local Data Staging | Stages collected data in `.pc_e_*` and `.pc_sq_*` temporary directories before exfiltration |
| T1041 | Exfiltration Over C2 Channel | Encrypted credential archive POSTed to attacker-controlled domain |
| T1102.001 | Web Service: Dead Drop Resolver | GitHub-hosted `domain.txt` file used to resolve second-stage C2 server address |
| T1105 | Ingress Tool Transfer | Remote code loader fetches and executes second-stage payload from resolved C2 server |

## Impact Assessment

**Breadth:** LiteLLM is one of the most popular AI gateway libraries with significant adoption across enterprises deploying LLM-based applications. Any organization that installed `litellm==1.107.0` via pip or pulled affected container images during the ~2-hour exposure window is potentially compromised. The exposure window was relatively short (11:39-14:20 UTC on October 21, 2026), but automated CI/CD pipelines and container deployments may have pulled the malicious version quickly.

**Depth:** The stealer is comprehensive -- it targets virtually every credential store on the host: cloud provider credentials, API keys, SSH/GPG keys, browser data, environment variables, database credentials, and LiteLLM proxy secrets (which may include credentials for dozens of AI providers). Because the `.pth` persistence runs on every Python invocation, any Python process on an affected system could trigger the stealer.

**Stealth:** The encrypted exfiltration (AES-256-CBC + RSA-4096) prevents content inspection. The single HTTP POST to a plausible-looking domain with a browser-like User-Agent is difficult to detect without specific IOC knowledge. The run-once marker prevents repeated exfiltration that might trigger alerts.

**Defender Detections:** Microsoft Defender detections: `Trojan:PyPI/Stealer.SA`, `Trojan:PyPI/LiteLlmSupplyChain.A`, `Trojan:PyPI/LiteLlmSupplyChain.B`, `Backdoor:PyPI/LiteLlmSupplyChain.C`. Vulnerability tracking ID: TVM-2026-0003.

## Detection & Remediation

### Immediate Detection

**Check for the malicious package:**
```bash
# Check if litellm 1.107.0 is installed
pip show litellm 2>/dev/null | grep -i "version: 1.107.0"
pip3 show litellm 2>/dev/null | grep -i "version: 1.107.0"

# Search for malicious files in ALL Python environments
find / -name "cook.pth" -path "*/site-packages/*" 2>/dev/null
find / -name "cook.py" -path "*/site-packages/*" 2>/dev/null
find / -name "sitecustomize.py" -path "*/site-packages/*" -newer /tmp 2>/dev/null

# Check for stealer artifacts
ls -la /tmp/.pc_once_72129118c59f5636c0bb 2>/dev/null
ls -la /tmp/remote_code_loader.lock 2>/dev/null
ls -la /tmp/.pc_e_* /tmp/.pc_sq_* 2>/dev/null

# Check pip/uv caches
find ~/.cache/pip ~/.cache/uv -name "litellm-1.107.0*" 2>/dev/null

# Verify file hashes (Linux/macOS payload variants)
sha256sum <site-packages>/cook.pth    # expect 7f191632... or 84dc8c82...
sha256sum <site-packages>/cook.py     # expect 9dd0a392... or 03ac2a8b...
```

**Check container images:**
```bash
# Check for affected container digests
docker images --digests | grep -E "litellm|1bbcb144"
```

**Check for network indicators:**
```bash
# Search DNS logs/proxy logs for exfiltration domain
grep -r "litellm.dev" /var/log/ 2>/dev/null
# Search for dead drop access
grep -r "letters9813" /var/log/ 2>/dev/null
```

### Remediation

1. **Do not run Python or pip in a suspect environment.** Investigate from a known-clean system.
2. **Isolate affected hosts** immediately. Stop Python processes where operationally safe.
3. **Remove malicious files** -- delete `cook.pth`, `cook.py`, `sitecustomize.py` from ALL `site-packages` directories, including virtual environments, pip/uv caches, and bytecode caches (`__pycache__/cook*.pyc`, `__pycache__/sitecustomize*.pyc`).
4. **Remove dist-info:** Delete `litellm-1.107.0.dist-info` directories.
5. **Rebuild from verified artifacts.** Pin to `litellm>=1.106.2,!=1.107.0` or a verified later release. Use hash-pinned lock files.
6. **Rotate ALL credentials** reachable from affected hosts from a CLEAN machine:
   - Cloud provider credentials (AWS, Azure, GCP)
   - API keys for all AI providers configured in LiteLLM
   - SSH keys, GPG keys
   - `DATABASE_URL` and other database credentials on proxy hosts
   - Browser-stored passwords (change at provider sites)
   - CI/CD tokens, Vault tokens
   - Revoke sessions, not just passwords/keys
7. **Rebuild affected container images** from verified base images and pinned package versions.
8. **Check internal mirrors and lock files** for cached copies of the malicious version.
9. **Correlate evidence:** Match file hashes, process ancestry, `.pc_e_` staging directories, network destinations (`litellm[.]dev`), and identity usage before declaring compromise.

### Long-Term Hardening

- **Pin dependencies with hashes** in lock files (`pip install --require-hashes`, `uv pip install --require-hashes`)
- **Pin container images by digest**, not tags
- **Use reviewed internal mirrors** rather than pulling directly from public registries
- **Restrict outbound network access** from production environments
- **Monitor for `.pth` file creation** in Python site-packages directories
- **Require multi-party approval** for release pipeline changes with hardware-backed credentials
- **Audit GitHub organization settings:** branch protection, deployment environment rules, token permissions
- **Enable Microsoft Defender for Endpoint** and Defender Antivirus where applicable

## Detection Rules

These detections target the specific artifacts and network indicators from the LiteLLM 1.107.0 supply chain compromise at PoC/advisory-specific altitude. Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles != fires -- verify each rule in your pipeline with representative telemetry.

### Sigma: Malicious cook.pth File Creation in Python Site-Packages
Detects creation of `cook.pth` in Python `site-packages` directories, the persistence mechanism used by the LiteLLM 1.107.0 backdoor.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch blocked by proxy, not a rule issue); splunk convert exit 0; log_scale convert exit 0. Keys on specific filename + path combination. FP risk: a legitimate Python package named 'cook' with a .pth file in site-packages is theoretically possible but extremely unlikely in practice. -->
```yaml
title: LiteLLM Supply Chain - Malicious cook.pth File Creation in Python Site-Packages
id: 8a3e7c1b-4d2f-4e9a-b5c6-1f0d8e2a7b3c
status: experimental
description: >
    Detects creation of the malicious cook.pth file in Python site-packages directories,
    a persistence mechanism used in the LiteLLM 1.107.0 supply chain compromise to execute
    credential-stealing code on every Python interpreter startup.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026/10/24
tags:
    - attack.t1546
    - attack.t1195.001
logsource:
    category: file_event
detection:
    selection_filename:
        TargetFilename|endswith: '/cook.pth'
    selection_path:
        TargetFilename|contains: 'site-packages'
    condition: selection_filename and selection_path
falsepositives:
    - Legitimate Python packages named 'cook' that use .pth files (unlikely in combination with site-packages path)
level: critical
```

### Sigma: DNS Query to Exfiltration Domain litellm.dev
Detects DNS queries to the attacker-registered domain `litellm[.]dev` used for credential exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy MITRE fetch; splunk convert exit 0; log_scale exit 0. litellm.dev is attacker-controlled, distinct from the legitimate litellm.ai. Zero expected FP. -->
```yaml
title: LiteLLM Supply Chain - Credential Exfiltration to litellm.dev
id: 2f4a8b6c-7e1d-4c3a-9d5f-0b2e8a1c6d4f
status: experimental
description: >
    Detects network connections to the malicious litellm.dev domain used as the exfiltration
    endpoint in the LiteLLM 1.107.0 supply chain compromise. The attacker-registered domain
    mimics the legitimate project and receives stolen credentials via HTTP POST.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026/10/24
tags:
    - attack.t1041
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'litellm.dev'
    condition: selection
falsepositives:
    - None expected; litellm.dev is an attacker-registered domain distinct from litellm.ai (the legitimate project domain)
level: critical
```

### Sigma: Stealer Marker File Creation
Detects creation of `/tmp/.pc_once_72129118c59f5636c0bb`, the run-once marker written by the stealer after successful exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk convert exit 0; log_scale exit 0. Highly specific 20-char hex suffix. Zero expected FP. -->
```yaml
title: LiteLLM Supply Chain - Stealer Marker File Creation
id: 5c9d1e7a-3b4f-4a2e-8f6c-0d1b9a5e7c3f
status: experimental
description: >
    Detects creation of the run-once marker file /tmp/.pc_once_72129118c59f5636c0bb
    written by the LiteLLM 1.107.0 credential stealer after successful exfiltration.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026/10/24
tags:
    - attack.t1059.006
    - attack.t1005
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains: '.pc_once_72129118c59f5636c0bb'
    condition: selection
falsepositives:
    - None expected; highly specific marker filename
level: critical
```

### Sigma: Stealer Staging Directory Creation
Detects creation of temporary staging directories with `.pc_e_` or `.pc_sq_` prefixes used for pre-exfiltration data staging.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk convert exit 0; log_scale exit 0. Distinctive prefix pattern. Low FP risk from other software using .pc_e_ or .pc_sq_ prefixes. -->
```yaml
title: LiteLLM Supply Chain - Stealer Staging Directory Creation
id: 7a2e4b8c-1d6f-4e5a-9c3b-2f0d7a8e1b5c
status: experimental
description: >
    Detects creation of temporary staging directories with the .pc_e_ or .pc_sq_ prefix
    used by the LiteLLM 1.107.0 credential stealer to stage collected data before exfiltration.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026/10/24
tags:
    - attack.t1074.001
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - '.pc_e_'
            - '.pc_sq_'
    condition: selection
falsepositives:
    - Unlikely; distinctive prefix pattern
level: high
```

### Sigma: Remote Code Loader Lock File
Detects creation of `/tmp/remote_code_loader.lock`, the lockfile ensuring single-instance execution of the hourly second-stage loader.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk convert exit 0; log_scale exit 0. Specific filename. Zero expected FP from legitimate software. -->
```yaml
title: LiteLLM Supply Chain - Remote Code Loader Lock File
id: 3e8a1c5d-9b2f-4d7e-a6c4-8f0b3d1e5a2c
status: experimental
description: >
    Detects creation of /tmp/remote_code_loader.lock, the lockfile used by the LiteLLM 1.107.0
    remote code loader to ensure single-instance execution while polling for second-stage payloads.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026/10/24
tags:
    - attack.t1105
    - attack.t1059.006
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '/remote_code_loader.lock'
    condition: selection
falsepositives:
    - None expected; specific to this supply chain attack's loader component
level: critical
```

### Sigma: Dead Drop Resolver Access via Proxy
Detects proxy log entries showing access to the GitHub-hosted dead drop file used for C2 resolution.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk convert exit 0; log_scale exit 0. Keys on attacker-controlled repo path components. Zero FP risk - repo deleted. -->
```yaml
title: LiteLLM Supply Chain - Dead Drop Resolver Access
id: 9c4d2e7a-5b1f-4a8e-b3c6-0d9f1a2e8b5c
status: experimental
description: >
    Detects DNS queries or proxy connections to the GitHub-hosted dead drop file used by the
    LiteLLM 1.107.0 remote code loader to resolve its second-stage C2 server address.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: Actioner
date: 2026/10/24
tags:
    - attack.t1102.001
logsource:
    category: proxy
detection:
    selection:
        cs-uri|contains|all:
            - 'letters9813'
            - 'pythonclient-test'
            - 'domain.txt'
    condition: selection
falsepositives:
    - None expected; attacker-controlled repository (now deleted)
level: critical
```

### Snort: LiteLLM Credential Exfiltration and Dead Drop Access
Detects the specific HTTP POST exfiltration to `/healthcheck` with the fixed X-Token header, the dead drop resolver access, and the characteristic User-Agent + X-SHA256 header combination.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c test.conf -T exit 0 via include method (Snort 2.9.20). Rules use tcp protocol with $HTTP_PORTS and http_* sticky buffers for Snort 2.x compat. Three rules covering distinct detection angles for the exfiltration. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - LiteLLM Supply Chain Credential Exfiltration to litellm.dev"; flow:established,to_server; content:"POST"; http_method; content:"/healthcheck"; http_uri; fast_pattern; content:"X-Token|3a 20|XWiA8gZNa7NcX2XRoAEb"; http_header; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; sid:2100010; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - LiteLLM Supply Chain Dead Drop Resolver Access"; flow:established,to_server; content:"/letters9813/pythonclient-test/main/domain.txt"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer; sid:2100011; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - LiteLLM Supply Chain Exfil User-Agent and X-SHA256 Header"; flow:established,to_server; content:"POST"; http_method; content:"Mozilla/4.0 (compatible|3b| MSIE 7.0|3b| Windows NT 10.0|3b| WOW64|3b| Trident/7.0)"; http_header; fast_pattern; content:"X-SHA256"; http_header; content:"X-Token"; http_header; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; sid:2100012; rev:1;)
```

### Suricata: LiteLLM Credential Exfiltration and C2 Communication
Detects HTTP POST exfiltration to `www[.]litellm[.]dev/healthcheck`, the fixed X-Token header, the dead drop resolver access, and DNS queries to the exfil domain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Uses dot-notation sticky buffers (http.method, http.host, http.uri, http.request_header, dns.query). Four rules covering HTTP exfil, auth header, dead drop, and DNS resolution. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Credential Exfiltration POST to litellm.dev"; flow:established,to_server; http.method; content:"POST"; http.host; content:"www.litellm.dev"; http.uri; content:"/healthcheck"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created_at 2026-10-24; sid:2200010; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Exfil X-Token Header"; flow:established,to_server; http.method; content:"POST"; http.request_header; content:"X-Token"; content:"XWiA8gZNa7NcX2XRoAEb"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created_at 2026-10-24; sid:2200011; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Dead Drop Resolver Access"; flow:established,to_server; http.uri; content:"/letters9813/pythonclient-test/main/domain.txt"; fast_pattern; classtype:trojan-activity; reference:url,www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer; metadata:author Actioner, created_at 2026-10-24; sid:2200012; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM Supply Chain DNS Query to Exfil Domain litellm.dev"; dns.query; content:"litellm.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created_at 2026-10-24; sid:2200013; rev:1;)
```

### YARA: LiteLLM 1.107.0 Malicious Payload Files
Detects the malicious `cook.pth`, `cook.py`, and `sitecustomize.py` payload files via distinctive strings including the stealer config keys, exfiltration domain/token, dead drop URL, obfuscation namespace, RSA key prefix, and database table names.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive test fired on both pos_pth.txt (cook.pth content) and pos_payload.txt (stealer config strings from published source). Negative test (benign litellm import) quiet. Covers pth trigger (filesize<100), stealer config (3-of PRIVCOLLECT vars), exfil indicators (domain+token), dead drop (repo+path), obfuscation signature, database targets, and RSA key prefix. -->
```yara
rule SupplyChain_LiteLLM_1107_Payload : supply_chain credential_stealer
{
    meta:
        description = "Detects malicious files from the LiteLLM 1.107.0 supply chain compromise - cook.pth, cook.py, and sitecustomize.py payload files"
        author = "Actioner"
        date = "2026-10-24"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        hash = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        hash = "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth_content = "import cook" ascii

        $privcollect_tag = "privcollect" ascii nocase
        $privcollect_active = "PRIVCOLLECT_ACTIVE" ascii
        $pc_url = "PC_URL" ascii
        $pc_token = "PC_TOKEN" ascii
        $pc_pubkey = "PC_PUBKEY" ascii
        $pc_modules = "PC_MODULES" ascii
        $pc_once = "PC_ONCE_PATH" ascii

        $exfil_domain = "www.litellm.dev" ascii
        $exfil_path = "/healthcheck" ascii
        $exfil_token = "XWiA8gZNa7NcX2XRoAEb" ascii

        $dead_drop = "letters9813/pythonclient-test" ascii
        $code_path = "/codepy" ascii
        $remote_loader = "remote_code_loader.lock" ascii

        $marker = ".pc_once_72129118c59f5636c0bb" ascii

        $obf_exec = "exec(zlib.decompress(base64.b64decode(" ascii
        $obf_namespace = "__name__': 'p14c7d1bb" ascii

        $db_table1 = "LiteLLM_CredentialsTable" ascii
        $db_table2 = "LiteLLM_ProxyModelTable" ascii

        $rsa_key_prefix = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvxRBQMVXDXVskKS47haU" ascii

    condition:
        filesize < 5MB and
        (
            ($pth_content and filesize < 100) or
            (3 of ($privcollect_tag, $privcollect_active, $pc_url, $pc_token, $pc_pubkey, $pc_modules, $pc_once)) or
            ($exfil_domain and ($exfil_token or $exfil_path)) or
            ($dead_drop and ($code_path or $remote_loader)) or
            ($marker) or
            ($obf_exec and $obf_namespace) or
            ($db_table1 and $db_table2) or
            ($rsa_key_prefix) or
            ($remote_loader and $code_path)
        )
}

rule SupplyChain_LiteLLM_1107_Wheel : supply_chain
{
    meta:
        description = "Detects malicious LiteLLM 1.107.0 wheel packages containing the backdoor payload files in the data/purelib directory"
        author = "Actioner"
        date = "2026-10-24"
        reference = "https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $wheel_path = "litellm-1.107.0.data/purelib/" ascii
        $cook_pth = "cook.pth" ascii
        $cook_py = "cook.py" ascii
        $sitecustomize = "sitecustomize.py" ascii
        $maturin_data = "data = \"cook\"" ascii

    condition:
        filesize < 50MB and
        $wheel_path and
        2 of ($cook_pth, $cook_py, $sitecustomize, $maturin_data)
}
```

## Lessons Learned

1. **Python startup hooks are a potent persistence vector.** The `.pth` file mechanism is a documented Python feature, but its abuse for malware persistence is not widely monitored. Any `.pth` file in `site-packages` that contains an `import` statement executes on every Python invocation, making it an ideal persistence mechanism for supply chain attacks targeting Python ecosystems. Organizations should monitor for unexpected `.pth` file creation in Python environments.

2. **Build pipeline security is the new perimeter.** This attack did not exploit a code vulnerability -- it compromised the release infrastructure. Stolen developer credentials allowed the attacker to redirect the build to a lookalike repository and bypass branch protections. This highlights the need for hardware-backed credentials (FIDO2/WebAuthn), mandatory multi-party approval for release pipelines, and continuous monitoring of CI/CD workflows.

3. **Lookalike resources remain effective.** The single-character difference between `BerriAI` and `Berri-AI` in the GitHub organization name, and between `litellm.ai` (legitimate) and `litellm.dev` (malicious), demonstrates that typosquatting and lookalike techniques continue to be effective, even against security-conscious organizations.

4. **Supply chain attacks on AI infrastructure are escalating.** This is the second supply chain compromise targeting LiteLLM in 2026 (following the August 2026 incident via a different vector). AI gateway and proxy libraries are high-value targets because they aggregate credentials for multiple AI providers, making a single compromise extremely impactful.

5. **Credential rotation scope must be comprehensive.** Because the stealer targets virtually every credential store on the host -- cloud providers, AI APIs, SSH keys, browser data, environment variables, database credentials, and proxy secrets -- remediation requires exhaustive credential rotation, not just replacing the compromised package.

## Sources

- [Microsoft Security Blog - Inside the LiteLLM 1.107.0 Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/) -- Primary technical analysis with detailed payload breakdown, MITRE mapping, and IOCs
- [StepSecurity - litellm 1.107.0 Compromised on PyPI](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer) -- Detailed timeline, wheel hashes, build pipeline forensics, dead drop analysis
- [Datadog Security Labs - LiteLLM Supply Chain Compromise](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-docker/) -- Container image analysis and additional IOCs
- [Socket.dev - LiteLLM PyPI Package and Docker Images Compromised](https://socket.dev/blog/litellm-compromise) -- Package-level analysis
- [The Hacker News - LiteLLM Compromised in Supply Chain Attack](https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html) -- News coverage
- [LiteLLM Official Incident Report](https://docs.litellm.ai/blog/security-incident-oct-21-2026) -- Vendor disclosure and remediation guidance
- [Kodem Security - LiteLLM Supply Chain Attack](https://www.kodemsecurity.com/resources/litellm-supply-chain-attack-litellm-1-107-0-affected-versions-iocs-and-first-hour-response-runbook) -- IOC-focused analysis and response runbook
- [Wiz - LiteLLM Compromised, Steals Credentials](https://www.wiz.io/blog/litellm-compromised-steals-credentials) -- Cloud security impact analysis
- [The Register - LiteLLM Supply Chain Attack](https://www.theregister.com/security/2026/10/21/litellm-supply-chain-attack-hoovers-up-passwords-and-secrets/5304548) -- News coverage

---
*Report generated by Actioner*
