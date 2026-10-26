# Technical Analysis Report: LiteLLM v1.107.0 Supply Chain Compromise (October 2026)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-26
Version: DRAFT

## Executive Summary

On October 21, 2026, attackers published a malicious version 1.107.0 of the popular LiteLLM AI proxy library to PyPI, Docker Hub, and GitHub Container Registry (GHCR). The compromise originated from a master key accidentally committed to a public GitHub repository on May 27, 2026, which was never revoked. The attacker used this key to extract a GitHub CLI OAuth token with organization-owner privileges, harvested additional developer credentials via malicious GitHub Actions workflows, then hijacked the release pipeline to push trojanized packages. The malicious package installs a credential stealer ("PRIVCOLLECT") and a remote access backdoor via Python startup hooks (cook.pth/cook.py and sitecustomize.py), which execute whenever the Python interpreter starts -- even without importing LiteLLM. The stealer harvests cloud credentials (AWS/Azure/GCP), AI API keys, browser data, SSH/GPG keys, environment variables, and LiteLLM proxy database contents, encrypting and exfiltrating them to litellm[.]dev/healthcheck. The backdoor checks a GitHub-hosted dead drop hourly for attacker-supplied Python code. The malicious packages were live for approximately 1 hour 43 minutes on PyPI before quarantine; Docker Hub tags were cleaned roughly 2.5 hours later. Estimated exposure: over 49,000 downloads. Wiz observed attackers using stolen AWS credentials to query Amazon Bedrock models approximately 4.5 hours after exfiltration.

**Note:** This is a DISTINCT event from the August 2026 LiteLLM compromise (TeamPCP/Trivy/Sandclock supply chain attack), involving different TTPs and infrastructure.

## Background: LiteLLM

LiteLLM is an open-source Python library and proxy server that provides a unified interface to over 100 large language model (LLM) providers including OpenAI, Anthropic, AWS Bedrock, Azure, and Google Cloud. It is widely used in enterprise AI deployments as a proxy layer for managing API keys, routing, rate limiting, and cost tracking across multiple LLM providers. The legitimate project is maintained under the GitHub organization "BerriAI" (capital I) at github.com/BerriAI/litellm. Its broad adoption means a supply chain compromise provides access to a high concentration of AI service credentials and cloud infrastructure secrets.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-27 | Master key for LiteLLM Agent Platform committed to public repo `LiteLLM-Labs/lite-harness` (commit `e10b14a`, file `opencode.json`). Force-pushed over but key never revoked. |
| 2026-10-10, ~22:11 | Attacker from 69.48.229[.]143 uses unrevoked master key to access Agent Platform; extracts GitHub CLI OAuth token with org-owner privileges |
| 2026-10-10, 22:11-22:12 | Malicious workflow `cache.yml` pushed to branches `ci-tmp-a351cc` and `ci-tmp-4d8517` in BerriAI/litellm and BerriAI/litellm-auto; steals developer GitHub tokens via webhook[.]site endpoints |
| 2026-10-12 | Second malicious commit; expanded secret collection (Anthropic, OpenAI, AWS Bedrock, Tavily API keys, PostgreSQL/Redis credentials) |
| 2026-10-13 | Exfiltration domain litellm[.]dev registered |
| 2026-10-21, 10:08-11:08 | Branch protection overridden; release pipeline repointed to lookalike repository Berri-AI/litellm (lowercase 'i') |
| 2026-10-21, 11:39:51 | Malicious PyPI wheels for litellm==1.107.0 published |
| 2026-10-21, 11:46:56 | Docker Hub and GHCR tags updated to compromised images |
| 2026-10-21, 11:53-11:54 | Attacker deletes production and staging workflow run records |
| 2026-10-21, 12:06 | Upwind researcher Lidor Machluf reports the attack |
| 2026-10-21, 13:23 | PyPI quarantines litellm v1.107.0 (~1h43m exposure) |
| 2026-10-21, 13:51 | GHCR images removed |
| 2026-10-21, 14:20 | Docker Hub tags cleaned/repointed to safe images |
| 2026-10-22 | Microsoft Defender detections available |
| 2026-10-23 | Microsoft Threat Intelligence publishes detailed analysis |

## Root Cause: Leaked Master Key and Stolen GitHub OAuth Tokens

The root cause was an unrevoked master key for a LiteLLM Agent Platform deployment. On May 27, 2026, a configuration file (`opencode.json`) was committed to the public repository `LiteLLM-Labs/lite-harness` at commit `e10b14a`, exposing the master key. While the commit was force-pushed over and keys were flagged for revocation, the master key itself was never actually revoked.

On October 10, an attacker operating from 69.48.229[.]143 used this key to access the Agent Platform and extract a GitHub CLI OAuth token. This token was insufficiently scoped and was tied to a GitHub organization owner's account, granting owner-level access to all BerriAI repositories. The attacker then used malicious GitHub Actions workflows (`cache.yml`) on throwaway branches (`ci-tmp-*`) to harvest additional developer tokens and secrets, sending them to webhook[.]site exfiltration endpoints. With three sets of compromised developer credentials, the attacker disabled branch protections, repointed the release deployer to a lookalike repository ("Berri-AI/litellm" with lowercase 'i'), and used one stolen token to trigger the release and another to approve it.

## Technical Analysis of the Malicious Payload

### 1. Delivery: Trojanized Python Packages

The attacker modified only the package distribution artifacts, not LiteLLM's application source code. Seven platform-specific wheel files were published to PyPI, each containing three malicious files placed under `litellm-1.107.0.data/purelib/` which get relocated into the Python site-packages directory during installation:

- **cook.pth** -- A Python path configuration file containing a single line: `import cook`. Python executes `.pth` files at interpreter startup.
- **cook.py** -- A wrapper that Base64-decodes and zlib-decompresses an embedded payload (the PRIVCOLLECT credential stealer), then executes it in a daemon thread.
- **sitecustomize.py** -- A Unix-oriented loader with an embedded collector and remote code retrieval capability.

These files reside in the site-packages root, meaning they execute on every Python interpreter startup regardless of whether LiteLLM is imported. Running `python` or `pip` in an affected environment triggers the malware.

### 2. Credential Stealer: PRIVCOLLECT

The stealer identifies itself as PRIVCOLLECT and sets the environment variable `PRIVCOLLECT_ACTIVE` as a duplicate-suppression flag. It targets:

- **Cloud credentials:** AWS (~/.aws/), Azure CLI, Google Cloud configs and caches, Kubernetes service-account files, Docker config, mounted secrets, AWS/GCP metadata endpoints (169.254.169.254, metadata.google.internal)
- **AI and developer tools:** AI assistant and IDE configs, GitHub Copilot, VS Code, MCP integrations, Anthropic/OpenAI API keys
- **Source control and packages:** Git credentials, GitHub/GitLab tokens, npm/PyPI/pip/Yarn/Maven/Gradle/Composer/RubyGems/Cargo configs, dotenv files
- **Browser data:** Chromium-family and Firefox credential stores, cookies, autofill/payment data, browsing history
- **Keys and infrastructure:** SSH, GPG, TLS private keys, CI/CD secrets, Vault tokens, infrastructure-tool configs
- **Process environments:** Own environment variables and, on Linux, other readable processes via /proc
- **Shell histories:** Bash, Zsh, and database client histories
- **LiteLLM proxy database:** Selected fields from `LiteLLM_CredentialsTable` and `LiteLLM_ProxyModelTable`, up to 500 rows per query

**Exfiltration:** Data is serialized as JSON, encrypted with AES-256-CBC (fresh 32-byte key, 16-byte IV), and the AES key is wrapped with an embedded 4096-bit RSA public key using OAEP (SHA-256, falling back to SHA-1). The resulting archive (gzip tar containing data.bin, key.bin, and hdr.json) is POSTed to `hxxp://www[.]litellm[.]dev/healthcheck` with `Content-Type: application/octet-stream` and an `X-SHA256` header. Only HTTP 200 is treated as success, after which a marker file `/tmp/.pc_once_72129118c59f5636c0bb` is written.

OpenSSL staging directories are created under `/tmp/.pc_e_*` during the encryption process.

### 3. C2 Infrastructure and Backdoor

The backdoor component (Unix-oriented, embedded in sitecustomize.py) operates as follows:

1. Takes an exclusive lock on `/tmp/remote_code_loader.lock`
2. Detaches as a background daemon process
3. Every hour, reads `domain.txt` from `hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt`
4. Validates and resolves the returned server domain
5. Requests `/codepy` from that server
6. Compiles and executes the response as Python code

No content-signature verification is performed on the downloaded code. At the time of Microsoft's analysis, `domain.txt` was empty, so second-stage code retrieval was not confirmed. The loader remains re-armable if the dead drop is populated.

### 4. Platform-Specific Behavior

#### Linux/macOS (Unix)
Both the credential stealer and the backdoor/remote loader are active. The stealer reads other process environments via /proc. sitecustomize.py provides the remote code loader. cook.pth + cook.py provide the PRIVCOLLECT stealer.

#### Windows
The stealer is active via cook.pth + cook.py (Windows-specific wheel variant). The remote code loader component in sitecustomize.py is Unix-oriented and was not confirmed to function on Windows.

### 5. Anti-Forensics / Evasion Techniques

- **Throwaway branches:** Malicious GitHub Actions workflows pushed to short-lived `ci-tmp-*` branches deleted within minutes, leaving almost nothing in normal repository history
- **Run record deletion:** Production and staging workflow run records deleted after release
- **Startup hook abuse:** Payload runs before any application code and outside the LiteLLM package directory
- **Encryption:** Exfiltrated data encrypted with AES-256-CBC + RSA-4096 OAEP wrapping
- **Obfuscation:** cook.py uses Base64 + zlib compression to hide the embedded stealer
- **Duplicate suppression:** PRIVCOLLECT_ACTIVE environment variable prevents re-execution
- **Lookalike repository:** "Berri-AI" (lowercase i) vs legitimate "BerriAI" (uppercase I)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.107.0 | Trojanized Python package with credential stealer and backdoor |
| litellm (Docker Hub) | v1.107.0, latest, main-latest, main-stable | Compromised container images |
| litellm (GHCR) | v1.107.0, latest, main-latest, main-stable | Compromised container images |

### File System

| Platform | Path / Artifact | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | cook.pth (variant 1) | 7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb | Python startup hook loader |
| All | cook.pth (variant 2) | 84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d | Python startup hook loader |
| Unix | cook.py | 9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25 | PRIVCOLLECT stealer wrapper |
| Windows | cook.py | 03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea | PRIVCOLLECT stealer wrapper (Windows variant) |
| Unix | sitecustomize.py | 34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa | Remote loader + collector |
| Windows | sitecustomize.py | b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465 | Remote loader + collector (Windows variant) |
| macOS x86_64 | Wheel | 7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d | Malicious distribution package |
| macOS arm64 | Wheel | 0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a | Malicious distribution package |
| Linux aarch64 | Wheel (manylinux) | 668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6 | Malicious distribution package |
| Linux x86_64 | Wheel (manylinux) | 462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7 | Malicious distribution package |
| Linux aarch64 | Wheel (musllinux) | c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054 | Malicious distribution package |
| Linux x86_64 | Wheel (musllinux) | 1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00 | Malicious distribution package |
| Windows | Wheel (win_amd64) | 12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484 | Malicious distribution package |
| All | /tmp/remote_code_loader.lock | -- | Backdoor exclusive lock file |
| All | /tmp/.pc_once_72129118c59f5636c0bb | -- | Exfiltration success marker |
| All | /tmp/.pc_e_* | -- | OpenSSL staging directories |

**Container image index digests:**
- Docker Hub / GHCR litellm: `sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e`
- GHCR litellm-database: `sha256:c00f9d92c427...` (truncated in source)
- GHCR litellm-non_root: `sha256:7b00e91cd2fe...` (truncated in source)

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | www[.]litellm[.]dev | Credential exfiltration endpoint (registered 2026-10-13) |
| URL | hxxp://www[.]litellm[.]dev/healthcheck | PRIVCOLLECT data upload endpoint |
| URL | hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt | Dead drop resolver for backdoor C2 |
| IP | 69.48.229[.]143 | Attacker source IP during initial compromise |
| URL | hxxps://webhook[.]site/65a42464-3cfa-4b02-a18c-17a6d7b86f37 | Credential exfiltration endpoint (workflow stage) |
| URL | hxxps://webhook[.]site/4da03473-a3e7-4dc2-a087-9c564b4208e1 | Credential exfiltration endpoint (workflow stage) |
| Repository | github[.]com/Berri-AI/litellm | Lookalike repository (note lowercase 'i' vs legitimate BerriAI) |
| Repository | github[.]com/letters9813/pythonclient-test | Dead drop hosting repository |

### Behavioral

- Python startup hooks (cook.pth / sitecustomize.py) executing in any Python process without explicit import of LiteLLM
- Environment variable `PRIVCOLLECT_ACTIVE` set as duplicate-suppression flag
- Daemon process holding exclusive lock on `/tmp/remote_code_loader.lock`
- Hourly HTTP GET requests to GitHub raw content URLs containing `/letters9813/pythonclient-test`
- HTTP POST to `/healthcheck` with `Content-Type: application/octet-stream` and `X-SHA256` header
- OpenSSL subprocess invocations from Python for AES/RSA encryption (staging under `/tmp/.pc_e_*`)
- GitHub Actions workflows named `cache.yml` on branches matching `ci-tmp-*` pattern

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Trojanized litellm v1.107.0 pushed to PyPI, Docker Hub, and GHCR |
| T1546.018 | Event Triggered Execution: Python Startup Hooks | cook.pth and sitecustomize.py execute at Python interpreter startup |
| T1059.006 | Command and Scripting Interpreter: Python | Backdoor downloads and executes arbitrary Python code |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | cook.py uses Base64 + zlib to hide PRIVCOLLECT payload |
| T1140 | Deobfuscate/Decode Files or Information | Runtime decompression and decoding of embedded stealer |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvests credentials from config files, dotenv, Git credentials |
| T1552.004 | Unsecured Credentials: Private Keys | Steals SSH, GPG, TLS private keys |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Queries AWS/GCP metadata endpoints for cloud credentials |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Extracts Chromium and Firefox credential stores |
| T1082 | System Information Discovery | Collects system and host information |
| T1016 | System Network Configuration Discovery | Collects network configuration details |
| T1005 | Data from Local System | Harvests environment variables, shell history, process data |
| T1102.001 | Web Service: Dead Drop Resolver | Reads C2 domain from GitHub-hosted domain.txt file |
| T1105 | Ingress Tool Transfer | Downloads and executes remote Python code via /codepy |
| T1041 | Exfiltration Over C2 Channel | Encrypted credential archive POSTed to litellm[.]dev/healthcheck |
| T1078 | Valid Accounts | Attacker used stolen developer GitHub OAuth tokens to trigger and approve releases |

## Impact Assessment

- **Breadth:** Over 49,000 estimated downloads during the ~1h43m PyPI exposure window; Docker Hub and GHCR images affected for ~2.5 hours. Any environment that installed litellm==1.107.0 or pulled affected container tags is compromised.
- **Depth:** Complete credential theft across cloud (AWS/Azure/GCP), AI services (OpenAI, Anthropic, Bedrock), developer tools (GitHub, SSH, GPG), browsers, and infrastructure secrets. Wiz confirmed active abuse of stolen AWS credentials for LLMjacking (unauthorized Bedrock model queries) within 4.5 hours.
- **Stealth:** Payload activates on any Python invocation, including diagnostic commands (pip, python). Startup files reside outside the LiteLLM package directory, surviving simple package uninstallation. Encrypted exfiltration to a plausible-looking domain (litellm.dev) resembling legitimate infrastructure.
- **Enterprise impact:** LiteLLM enterprise customers using the private repository were not affected. Open-source users running LiteLLM proxy are high-value targets as the stealer specifically extracts stored provider credentials and model configurations from the proxy database.

## Detection & Remediation

### Immediate Detection

Check for the presence of malicious startup files in Python site-packages:

```bash
# Find cook.pth / cook.py in any Python environment (DO NOT use python/pip - they trigger the malware)
find / -name "cook.pth" -o -name "cook.py" -path "*/site-packages/*" 2>/dev/null

# Check for the backdoor lock file
ls -la /tmp/remote_code_loader.lock

# Check for exfiltration marker
ls -la /tmp/.pc_once_72129118c59f5636c0bb

# Check for OpenSSL staging directories
ls -la /tmp/.pc_e_* 2>/dev/null

# Check installed litellm version WITHOUT invoking Python
strings $(find / -path "*/litellm/version.py" 2>/dev/null) | grep version

# Check for the PRIVCOLLECT environment variable
env | grep PRIVCOLLECT_ACTIVE

# Check DNS/network logs for exfiltration domain
grep -r "litellm.dev" /var/log/ 2>/dev/null

# Verify wheel hashes (compare against known-bad SHA256 list above)
sha256sum $(find / -name "litellm-1.107.0*.whl" 2>/dev/null)
```

**Microsoft Defender detections:**
- Antivirus: `Trojan:PyPI/Stealer.SA`, `Trojan:PyPI/LiteLlmSupplyChain.A`, `Trojan:PyPI/LiteLlmSupplyChain.B`, `Backdoor:PyPI/LiteLlmSupplyChain.C`
- Vulnerability management: `TVM-2026-0003`

### Remediation

1. **Do NOT run Python or pip** in a suspect environment -- this triggers the malware. Inspect from a known-clean system or use non-Python tools (find, strings, sha256sum).
2. **Isolate affected systems** immediately. Disconnect from the network to prevent further exfiltration.
3. **Remove all copies** of litellm 1.107.0 including pip caches, mirror caches, lock files, build outputs, and container images. Compare against the SHA256 hashes above.
4. **Verify removal of startup files**: confirm cook.pth, cook.py, and sitecustomize.py are removed from all site-packages directories. Removing the litellm package alone is NOT sufficient.
5. **Rotate ALL credentials** from a known-clean machine: AWS/Azure/GCP keys, AI API keys (OpenAI, Anthropic, etc.), GitHub tokens, SSH keys, GPG keys, database credentials, CI/CD secrets, browser-stored passwords. Revoke all active sessions.
6. **Rebuild from verified artifacts.** Pin to litellm==1.106.2 by hash digest. Use container image digests, not mutable tags.
7. **Review cloud usage logs** for unauthorized activity, particularly Amazon Bedrock queries (LLMjacking).
8. **Review GitHub organization settings** for unauthorized workflow changes, branch protection modifications, and unexpected releaser configurations.

### Long-Term Hardening

- **Pin dependencies by hash** in lock files and container builds (use `--require-hashes` with pip).
- **Use container image digests** rather than mutable tags.
- **Scope GitHub tokens** to minimum required permissions; never grant org-owner level access to service accounts.
- **Implement secret scanning** with automated revocation (the GitGuardian key was also stolen, potentially giving the attacker control over secret-scanning alerts).
- **Restrict outbound network access** from CI/CD environments and production deployments.
- **Audit master keys and service credentials** regularly; ensure revocation processes are actually completed.
- **Monitor Python site-packages** for unexpected .pth files, which are a known persistence vector.

## Detection Rules

These detections target the LiteLLM v1.107.0 supply chain compromise at PoC/advisory-specific altitude, covering: malicious file creation (Sigma), DNS/network exfiltration (Sigma, Snort, Suricata), dead drop resolver access (Sigma, Snort, Suricata), backdoor lock file (Sigma), and file-level stealer signatures (YARA). Note: compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: Malicious Python Startup Hook Files in Site-Packages

Detects creation of cook.pth or cook.py in Python site-packages directories, the persistence mechanism for the PRIVCOLLECT stealer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. sigma check fails due to MITRE ATT&CK data fetch blocked by proxy (not a rule issue). Keys on distinctive file names + site-packages path. FP: a legitimate "cook" package installed via pip would match; scope to environments that do not use such a package. -->
```yaml
title: LiteLLM Supply Chain - Malicious Python Startup Hook Files
id: 8a3c1e7f-4b2d-4f6a-9e1c-3d5b7a9f2c4e
status: experimental
description: >
    Detects creation of cook.pth, cook.py, or sitecustomize.py files associated
    with the LiteLLM v1.107.0 supply chain compromise credential stealer
    (PRIVCOLLECT). These files are placed in Python site-packages to execute
    at interpreter startup via Python startup hooks.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/
author: Actioner
date: 2026/10/26
tags:
    - attack.t1195.001
    - attack.t1546.018
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|endswith:
            - '/cook.pth'
            - '/cook.py'
    selection_sitepackages:
        TargetFilename|contains: 'site-packages'
    condition: selection_path and selection_sitepackages
falsepositives:
    - Legitimate Python packages named 'cook' installed in site-packages
level: high
```

### Sigma: DNS Query to Exfiltration Domain

Detects DNS queries to litellm[.]dev, the PRIVCOLLECT credential exfiltration domain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Domain registered 2026-10-13 by the attacker. Minimal FP risk as this is an attacker-registered domain, not legitimate LiteLLM infrastructure. If the domain is sinkholed or repurposed post-incident, FP may increase. -->
```yaml
title: LiteLLM Supply Chain - DNS Query to Exfiltration Domain
id: 2f9b4c8e-7d1a-4e3f-b5c6-1a8d9e2f4b7c
status: experimental
description: >
    Detects DNS queries to litellm.dev, the exfiltration domain used by the
    PRIVCOLLECT credential stealer distributed via malicious LiteLLM v1.107.0
    packages. Stolen credentials are POSTed to litellm.dev/healthcheck.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026/10/26
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'litellm.dev'
    condition: selection
falsepositives:
    - Legitimate access to litellm.dev if the domain is repurposed post-incident
level: critical
```

### Sigma: Dead Drop Resolver GitHub Access

Detects proxy/web log access to the GitHub-hosted dead drop used by the LiteLLM v1.107.0 backdoor to retrieve C2 server addresses.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Keys on the distinctive path /letters9813/pythonclient-test which is the attacker-controlled GitHub repo. Very low FP unless a legitimate developer accesses this specific user's repo. -->
```yaml
title: LiteLLM Supply Chain - Dead Drop Resolver GitHub Access
id: 4e7a1b3c-9f2d-4a6e-8c5b-2d1f7e3a9b4c
status: experimental
description: >
    Detects DNS queries or network connections to the GitHub-hosted dead drop
    resolver used by the LiteLLM v1.107.0 backdoor. The malware reads
    domain.txt from github.com/letters9813/pythonclient-test hourly.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html
author: Actioner
date: 2026/10/26
tags:
    - attack.t1102.001
    - attack.t1105
logsource:
    category: proxy
detection:
    selection:
        cs-uri|contains: '/letters9813/pythonclient-test'
    condition: selection
falsepositives:
    - Legitimate developer access to the letters9813 GitHub user repositories
level: high
```

### Sigma: Remote Code Loader Lock File Creation

Detects creation of the exclusive lock file used by the LiteLLM v1.107.0 backdoor before fetching and executing remote code.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Exact path match /tmp/remote_code_loader.lock is highly distinctive. Virtually no FP expected. -->
```yaml
title: LiteLLM Supply Chain - Remote Code Loader Lock File Creation
id: 6c3d9e2f-1a4b-4c8e-b7f5-9d2a1e3c5b8f
status: experimental
description: >
    Detects creation of the remote code loader lock file used by the LiteLLM
    v1.107.0 backdoor. The malware creates /tmp/remote_code_loader.lock as an
    exclusive lock before fetching and executing attacker-supplied code.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026/10/26
tags:
    - attack.t1105
    - attack.t1059.006
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename: '/tmp/remote_code_loader.lock'
    condition: selection
falsepositives:
    - Unlikely in production environments
level: critical
```

### Snort: Credential Exfiltration and Dead Drop Access

Detects HTTP POST to the PRIVCOLLECT exfiltration endpoint and access to the GitHub dead drop resolver.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c minimal.conf -T exit 0. Rule 2100101 keys on POST + /healthcheck URI + litellm.dev host + application/octet-stream content type. Rule 2100102 keys on the distinctive /letters9813/pythonclient-test URI path + raw.githubusercontent.com host. Both use distinctive multi-content anchors for low FP. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LITELLM SUPPLY CHAIN - Credential Exfiltration to litellm.dev healthcheck"; flow:established,to_server; content:"POST"; http_method; content:"/healthcheck"; http_uri; content:"litellm.dev"; http_header; content:"application/octet-stream"; http_header; sid:2100101; rev:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LITELLM SUPPLY CHAIN - Dead Drop Resolver Access to letters9813 Repo"; flow:established,to_server; content:"/letters9813/pythonclient-test"; http_uri; fast_pattern; content:"raw.githubusercontent.com"; http_header; sid:2100102; rev:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks;)
```

### Suricata: Credential Exfiltration, DNS, and Dead Drop

Detects the PRIVCOLLECT exfiltration POST, DNS queries to the exfiltration domain, and access to the dead drop resolver.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Three rules: sid 2200101 (HTTP POST exfil with host/uri/method/content-type match), sid 2200102 (DNS query for litellm.dev), sid 2200103 (HTTP dead drop access with URI + host match). All use dot-notation sticky buffers per Suricata 7.x. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Credential Exfiltration to litellm.dev"; flow:established,to_server; http.method; content:"POST"; http.host; content:"litellm.dev"; http.uri; content:"/healthcheck"; startswith; http.content_type; content:"application/octet-stream"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks; metadata:author Actioner, created_at 2026-10-26; sid:2200101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM Supply Chain DNS Query to Exfiltration Domain"; dns.query; content:"litellm.dev"; endswith; nocase; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks; metadata:author Actioner, created_at 2026-10-26; sid:2200102; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Dead Drop Resolver Access"; flow:established,to_server; http.uri; content:"/letters9813/pythonclient-test"; fast_pattern; http.host; content:"raw.githubusercontent.com"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks; metadata:author Actioner, created_at 2026-10-26; sid:2200103; rev:1;)
```

### YARA: cook.pth Startup Hook Loader

Detects the cook.pth file that triggers the PRIVCOLLECT credential stealer on Python startup.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Tested: yara pos-cook.txt matched SupplyChain_LiteLLM_CookPTH_Loader, neg-cook.txt silent. Positive built from the source's published "import cook" string (Microsoft blog). filesize < 1KB + fullword match keeps FP minimal. -->
```yara
rule SupplyChain_LiteLLM_CookPTH_Loader
{
    meta:
        description = "Detects the cook.pth loader file from the LiteLLM v1.107.0 supply chain compromise that triggers credential theft on Python startup"
        author = "Actioner"
        date = "2026-10-26"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        severity = "critical"

    strings:
        $pth_import = "import cook" ascii fullword

    condition:
        filesize < 1KB and $pth_import
}
```

### YARA: PRIVCOLLECT Credential Stealer Payload

Detects the PRIVCOLLECT credential stealer payload via characteristic strings found in cook.py and sitecustomize.py.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Requires 4 of 9 distinctive strings including PRIVCOLLECT_ACTIVE identifier, lock file path, exfil domain/path, dead drop repo, marker file, and LiteLLM database table names. All strings sourced from Microsoft blog. 4-of-9 threshold balances variant coverage with FP avoidance. -->
```yara
rule SupplyChain_LiteLLM_PRIVCOLLECT_Stealer
{
    meta:
        description = "Detects the PRIVCOLLECT credential stealer payload from the LiteLLM v1.107.0 supply chain compromise via characteristic strings"
        author = "Actioner"
        date = "2026-10-26"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        severity = "critical"

    strings:
        $s1 = "PRIVCOLLECT_ACTIVE" ascii
        $s2 = "remote_code_loader.lock" ascii
        $s3 = "/healthcheck" ascii
        $s4 = "litellm.dev" ascii
        $s5 = "letters9813" ascii
        $s6 = "pythonclient-test" ascii
        $s7 = ".pc_once_72129118c59f5636c0bb" ascii
        $s8 = "LiteLLM_CredentialsTable" ascii
        $s9 = "LiteLLM_ProxyModelTable" ascii

    condition:
        filesize < 5MB and 4 of them
}
```

## Lessons Learned

1. **Secret revocation must be verified, not assumed.** The root cause was a master key that was flagged for revocation but never actually revoked. Organizations must implement verified revocation workflows with confirmation checks, not just intent-based flagging.

2. **Service account tokens require strict scoping.** The GitHub CLI OAuth token extracted from the Agent Platform had organization-owner privileges -- far more than needed for its function (opening pull requests). Principle of least privilege for service accounts is critical.

3. **Python startup hooks (.pth files) are a potent persistence mechanism.** They execute before any application code and on every Python invocation, making them invisible to application-level monitoring. Defenders should monitor site-packages for unexpected .pth files.

4. **Supply chain attacks now target AI infrastructure specifically.** The stealer specifically harvests AI API keys, LLM proxy credentials, and provider configurations. As AI deployments grow, the concentration of valuable credentials in AI infrastructure tooling creates high-value targets.

5. **"pip uninstall" is not sufficient remediation.** The malicious startup files reside outside the package directory structure and survive standard uninstallation. Full system inspection and rebuild from clean images is required.

6. **GitHub Actions workflows on throwaway branches can harvest secrets undetected.** The attacker's use of ephemeral `ci-tmp-*` branches and immediate deletion left minimal audit trail in standard repository history.

## Sources

- [Microsoft Threat Intelligence - Inside the LiteLLM 1.107.0 Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/) — Primary technical analysis with IOCs, SHA256 hashes, MITRE ATT&CK mapping, and Defender detections
- [BleepingComputer - LiteLLM release pipeline hacked to distribute info-stealer malware](https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/) — Detailed timeline with Docker Hub/GHCR image digests, PyPI exposure window, and download estimates
- [The Hacker News - LiteLLM Compromised in Supply Chain Attack](https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html) — Researcher quotes from Socket, StepSecurity, and SafeDep; tampered pyproject.toml detail
- [The Hacker News - Leaked LiteLLM Master Key Let Attackers Hijack Release Pipeline](https://thehackernews.com/2026/10/leaked-litellm-master-key-let-attackers.html) — Root cause deep dive: master key leak, GitHub token theft via cache.yml workflows, webhook.site exfiltration, and operational TTPs
- [SecurityWeek - LiteLLM Compromised in Fresh Supply Chain Attack](https://www.securityweek.com/litellm-compromised-in-fresh-supply-chain-attack/) — Wiz findings on LLMjacking (Bedrock abuse within 4.5 hours), Claude Code token hypothesis, and 49K download estimate

---
*Report generated by Actioner*
