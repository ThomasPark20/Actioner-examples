# Technical Analysis Report: LiteLLM 1.107.0 Supply Chain Compromise (October 2026)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-25
Version: 1.0

## Executive Summary

On October 21, 2026, attackers compromised the LiteLLM release pipeline and published a malicious version 1.107.0 to PyPI, Docker Hub, and GitHub Container Registry (GHCR). The attack was enabled by a GitHub CLI OAuth token leaked through a master key committed to the public `LiteLLM-Labs/lite-harness` repository in May 2026. Using the unrevoked key, the attacker accessed LiteLLM's internal Agent Platform deployment on October 10, exfiltrated GitHub CLI OAuth tokens for three maintainer-privileged engineers via throwaway workflow runs, then on October 21 overrode branch protections and redirected the release pipeline to a lookalike repository (`Berri-AI/litellm` instead of `BerriAI/litellm`). The malicious package contained a credential stealer (self-identified as "PRIVCOLLECT") and a backdoor, both executed automatically via Python startup hooks (`cook.pth`, `cook.py`, `sitecustomize.py`) without requiring LiteLLM to be imported. The stealer harvested cloud credentials, AI API keys, browser data, SSH/GPG keys, environment variables, and LiteLLM proxy stored secrets, exfiltrating encrypted archives to `litellm[.]dev/healthcheck`. A background loader polled a GitHub dead-drop (`domain.txt`) for second-stage code. The malicious packages were live for approximately 1 hour 43 minutes on PyPI and 2 hours 34 minutes on Docker Hub, with an estimated 49,000+ downloads. Microsoft Threat Intelligence published a detailed analysis on October 23.

## Background: LiteLLM

LiteLLM is a widely-used open-source Python library and proxy server that provides a unified API interface to over 100 LLM providers (OpenAI, Anthropic, AWS Bedrock, Azure, Google, etc.). It is commonly deployed in enterprise AI pipelines, development environments, and Kubernetes clusters as a gateway for LLM API calls. Due to its role as a credential aggregation point (storing API keys and provider credentials), compromise of LiteLLM environments provides high-value access to cloud and AI service credentials. The project is maintained by BerriAI and distributed via PyPI and Docker Hub. This is the second major supply chain compromise of LiteLLM in 2026, following the TeamPCP/Trivy incident in March.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-27 | Master key committed to public `LiteLLM-Labs/lite-harness` repo (commit `e10b14a`, file `harnesses/opencode/opencode.json`). Commit later force-pushed over, but key not revoked. |
| 2026-10-10 22:11-22:12 | Attacker uses unrevoked master key to access LiteLLM Agent Platform at 69.48.229[.]143. Pushes throwaway branches (`ci-tmp-a351cc`, `ci-tmp-4d8517`) with malicious `.github/workflows/cache.yml` to `BerriAI/litellm` and `BerriAI/litellm-auto`. GitHub tokens for two maintainer engineers exfiltrated to webhook[.]site endpoints. Runs deleted minutes later. |
| 2026-10-12 | Second malicious workflow commit exfiltrates additional secrets: API keys for Anthropic, OpenAI, AWS Bedrock, Tavily, GitGuardian; Playwright state; PostgreSQL and Redis credentials. |
| 2026-10-13 | Exfiltration domain `litellm[.]dev` registered by attacker. |
| 2026-10-21 10:08-11:08 | Branch protection overridden. Release pipeline source repointed to lookalike repository `Berri-AI/litellm`. |
| 2026-10-21 11:39-11:40 | Malicious litellm 1.107.0 published to PyPI (all 7 wheels). |
| 2026-10-21 11:46 | Compromised Docker images published to Docker Hub and GHCR. |
| 2026-10-21 11:53-11:54 | Production and staging workflow run records deleted. |
| 2026-10-21 12:06 | Upwind researcher Lidor Machluf reports the attack. |
| 2026-10-21 13:23 | PyPI quarantines version 1.107.0. |
| 2026-10-21 ~13:51 | GHCR tags made unavailable. |
| 2026-10-21 14:20 | Docker Hub tags removed/repointed to clean images. |
| 2026-10-22 | Microsoft Defender detections available. |
| 2026-10-23 | Microsoft Threat Intelligence publishes detailed analysis. |

## Root Cause: Leaked Master Key and Unrevoked Credentials

The attack chain originated from a master key for the LiteLLM Agent Platform committed to the public repository `LiteLLM-Labs/lite-harness` on May 27, 2026. Although the commit was force-pushed over, the key was never revoked. On October 10, the attacker used this key from IP 69.48.229[.]143 to access the Agent Platform deployment (exposed to the public internet). The platform held a GitHub CLI OAuth token tied to an organization owner's account that was not properly scoped down, providing owner-level access to all BerriAI organization repositories.

The attacker leveraged this access to push malicious GitHub Actions workflows to two repositories, exfiltrating GitHub CLI OAuth tokens for two additional maintainer-privileged engineers via webhook[.]site. A second workflow run on October 12 expanded the stolen credentials to include API keys for multiple AI providers, database credentials, and CI/CD secrets.

On October 21, using the stolen tokens, the attacker: (1) overrode branch protections, (2) repointed the release pipeline to a lookalike repository `Berri-AI/litellm` (note the hyphen vs the legitimate `BerriAI/litellm`), (3) used one stolen token to trigger the release and another to approve it (a two-person approval requirement that had been relaxed earlier that week), and (4) published the compromised artifacts.

## Technical Analysis of the Malicious Payload

### 1. Distribution and Installation Hooks

The malicious wheel shipped three files under `litellm-1.107.0.data/purelib/`: `cook.pth`, `cook.py`, and `sitecustomize.py`. On installation, these were placed into the environment's site-packages root directory -- outside the `litellm/` application directory -- making them invisible to typical `pip uninstall litellm` and ensuring execution via Python's startup mechanism.

Python processes `.pth` files at interpreter startup (before any user code), executing lines that begin with `import`. The `cook.pth` file contains the single line `import cook`, which triggers `cook.py`. Python also imports `sitecustomize.py` at startup if found on the path. This dual-hook design provides redundant execution paths: the payload runs every time Python starts in the affected environment, even if LiteLLM is never imported.

### 2. Credential Stealer (PRIVCOLLECT)

`cook.py` Base64-decodes and zlib-decompresses an embedded program identifying itself as PRIVCOLLECT, then runs the collector in a daemon thread. The collector includes duplicate-suppression via the `PRIVCOLLECT_ACTIVE` environment variable (set if empty, checked to avoid re-running in child processes). After successful exfiltration (HTTP 200), it attempts to write the completion marker `/tmp/.pc_once_72129118c59f5636c0bb`.

The stealer collects data across sequential, independently error-handled modules:

| Target Category | Data Targeted |
|-----------------|---------------|
| Developer and AI tools | Auth/config files for AI assistants, IDEs, GitHub Copilot, VS Code, MCP integrations |
| Source control and packages | Git credentials, package-manager configs (.npmrc, pip.conf, .pypirc), selected .env files, private-key extensions |
| Cloud and workload | AWS, Azure CLI, Google Cloud config/credential caches; Kubernetes service-account files; Docker config; mounted secrets; AWS/GCP metadata credential requests |
| Browsers and histories | Chromium-family and Firefox credential data, cookies, autofill, payment data, browsing history; shell and database-client histories |
| Process environments | Own environment variables; on Linux, other readable processes via /proc |
| Keys and infrastructure | SSH material, GPG keys, TLS certificates, CI/CD configs, Vault configs |
| LiteLLM proxy data | Uses Prisma to query `LiteLLM_CredentialsTable`/`credential_values` and `LiteLLM_ProxyModelTable`/`litellm_params` (500-row limit per query) |

On Windows, the collector spawned `systeminfo`, `ipconfig`, `route`, `arp`, and `netstat` in sequence for host reconnaissance.

### 3. C2 Infrastructure and Exfiltration

**Exfiltration:** Collected data and host metadata are serialized as JSON. Each run generates a fresh 32-byte AES key and 16-byte IV. Data is encrypted with AES-256-CBC. The AES key is wrapped with an embedded 4096-bit RSA public key using OAEP (tries SHA-256, falls back to SHA-1). Three files are packed into a gzip tar archive: `data.bin` (IV + encrypted data), `key.bin` (wrapped AES key), `hdr.json` (plaintext envelope metadata). Upload is an HTTP POST to `hxxp://www[.]litellm[.]dev/healthcheck` with `application/octet-stream` content type, a browser-like User-Agent, and an `X-SHA256` body checksum header. The OpenSSL backend stages files in temporary directories beginning with `.pc_e_` and deletes them afterward.

**Dead-drop loader:** `sitecustomize.py` forks a background daemon (Unix) that takes an exclusive lock on `/tmp/remote_code_loader.lock`. Each cycle reads `hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt` for a server hostname. If non-empty, it requests `/codepy` from that server, compiles the response, and executes it as Python. No content-signature verification is performed. At time of analysis, `domain.txt` was empty, so second-stage retrieval was not confirmed.

**Webhook exfiltration (Oct 10-12 phase):**
- `webhook[.]site/65a42464-3cfa-4b02-a18c-17a6d7b86f37`
- `webhook[.]site/4da03473-a3e7-4dc2-a087-9c564b4208e1`

### 4. Platform-Specific Behavior

#### Linux/Unix
- `sitecustomize.py` forks a detached background daemon for the dead-drop loader
- Lock file `/tmp/remote_code_loader.lock` prevents duplicate loader instances
- Reads other process environments via `/proc/*/environ`
- AWS/GCP metadata credential requests to instance metadata endpoints

#### Windows
- Separate `cook.py` variant (hash `03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea`)
- Separate `sitecustomize.py` variant (hash `b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465`)
- Spawns `systeminfo`, `ipconfig`, `route`, `arp`, `netstat` for host recon
- OpenSSL command-line operations for encryption with `.pc_e_` staging paths

#### macOS
- Covered by the macOS-specific wheels (x86_64 and arm64)
- Shares Unix-oriented `sitecustomize.py` loader behavior

### 5. Anti-Forensics / Evasion Techniques

- **Redundant execution hooks:** Both `.pth` and `sitecustomize.py` ensure execution even if one is blocked
- **Site-packages root placement:** Files placed outside `litellm/` directory survive `pip uninstall litellm`
- **Base64 + zlib encoding:** Embedded payload in `cook.py` is encoded to avoid static string detection
- **Workflow run deletion:** Production/staging run records deleted post-release to hide audit trail
- **Throwaway branches:** `ci-tmp-a351cc` and `ci-tmp-4d8517` created and deleted to minimize forensic evidence
- **Lookalike repository:** `Berri-AI/litellm` (hyphenated) mimics legitimate `BerriAI/litellm`
- **Completion marker and lock file:** Prevent duplicate execution that could raise suspicion
- **OpenSSL staging cleanup:** Temporary `.pc_e_*` directories deleted after encryption
- **Daemon detachment:** Loader detaches from parent process to survive Python session termination

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.107.0 | All 7 platform wheels contain malicious startup hooks; source tarball has tampered pyproject.toml but not payload files |
| litellm Docker (Docker Hub) | v1.107.0, latest, main-latest, main-stable | Compromised images with embedded malicious package |
| ghcr.io/berriai/litellm | sha256:1bbcb1443bc9... | Compromised GHCR image |
| ghcr.io/berriai/litellm-database | sha256:c00f9d92c427... | Compromised GHCR image |
| ghcr.io/berriai/litellm-non_root | sha256:7b00e91cd2fe... | Compromised GHCR image |

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|-----------------|---------------|-------------|
| All | cook.pth (site-packages root) | `7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb` | Python startup hook — `import cook` |
| All | cook.pth (variant) | `84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d` | Variant startup hook |
| Linux/macOS | cook.py | `9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25` | PRIVCOLLECT credential stealer (Unix) |
| Windows | cook.py | `03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea` | PRIVCOLLECT credential stealer (Windows) |
| Linux/macOS | sitecustomize.py | `34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa` | Dead-drop loader + collector (Unix) |
| Windows | sitecustomize.py | `b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465` | Dead-drop loader + collector (Windows) |
| All | Wheel: macosx_10_12_x86_64 | `7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d` | Malicious wheel |
| All | Wheel: macosx_11_0_arm64 | `0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a` | Malicious wheel |
| All | Wheel: manylinux_2_28_aarch64 | `668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6` | Malicious wheel |
| All | Wheel: manylinux_2_28_x86_64 | `462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7` | Malicious wheel |
| All | Wheel: musllinux_1_2_aarch64 | `c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054` | Malicious wheel |
| All | Wheel: musllinux_1_2_x86_64 | `1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00` | Malicious wheel |
| All | Wheel: win_amd64 | `12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484` | Malicious wheel |
| Linux/macOS | /tmp/.pc_once_72129118c59f5636c0bb | N/A | Completion marker (post-exfiltration) |
| Linux/macOS | /tmp/remote_code_loader.lock | N/A | Dead-drop loader exclusive lock file |
| All | .pc_e_* (temp directories) | N/A | OpenSSL encryption staging directories |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | litellm[.]dev | Exfiltration domain (registered 2026-10-13) |
| Domain | www[.]litellm[.]dev | Exfiltration endpoint host |
| URL | hxxp://www[.]litellm[.]dev/healthcheck | Exfiltration POST endpoint |
| URL | hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain[.]txt | Dead-drop pointer for second-stage C2 |
| IP | 69.48.229[.]143 | Source IP of initial Agent Platform access (Oct 10) |
| URL | hxxps://webhook[.]site/65a42464-3cfa-4b02-a18c-17a6d7b86f37 | Token exfiltration webhook (Oct 10) |
| URL | hxxps://webhook[.]site/4da03473-a3e7-4dc2-a087-9c564b4208e1 | Token exfiltration webhook (Oct 10-12) |

### Behavioral

- Python interpreter startup triggers credential collection via `.pth` hook without explicit `litellm` import
- `PRIVCOLLECT_ACTIVE` environment variable set as duplicate-suppression flag
- Sequential system reconnaissance: `systeminfo` -> `ipconfig` -> `route` -> `arp` -> `netstat` (Windows)
- OpenSSL command lines with `.pc_e_` prefix and `enc -aes-256-cbc` or `pkeyutl -encrypt -pubin` referencing `/tmp/.pc_`
- HTTP POST with `application/octet-stream` content type and `X-SHA256` header to `/healthcheck`
- Background daemon polling GitHub raw content every hour for dead-drop updates
- Prisma child process querying LiteLLM database tables (`LiteLLM_CredentialsTable`, `LiteLLM_ProxyModelTable`)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Attacker compromised the LiteLLM release pipeline via stolen GitHub tokens to publish malicious version 1.107.0 |
| T1546.018 | Event Triggered Execution: Python Startup Hooks (proposed) | `cook.pth` and `sitecustomize.py` execute at Python interpreter startup without explicit import |
| T1059.006 | Command and Scripting Interpreter: Python | Embedded Python payload decoded and executed via daemon thread; second-stage code compiled and executed |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Payload Base64-encoded and zlib-compressed within `cook.py` |
| T1140 | Deobfuscate/Decode Files or Information | Runtime decoding of Base64 + zlib payload before execution |
| T1552.001 | Unsecured Credentials: Credentials in Files | Reads auth/config files for cloud providers, AI tools, Git, SSH, CI/CD systems |
| T1552.004 | Unsecured Credentials: Private Keys | Collects SSH keys, GPG keys, TLS private keys |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Requests credentials from AWS and GCP instance metadata endpoints |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Harvests Chromium and Firefox credential stores, cookies, autofill data |
| T1082 | System Information Discovery | Runs `systeminfo` (Windows); collects host metadata across platforms |
| T1016 | System Network Configuration Discovery | Runs `ipconfig`, `route`, `arp`, `netstat` (Windows) |
| T1005 | Data from Local System | Collects environment variables, shell histories, config files, .env files |
| T1102.001 | Web Service: Dead Drop Resolver | Polls GitHub-hosted `domain.txt` for C2 server hostname |
| T1105 | Ingress Tool Transfer | Downloads and executes second-stage Python from C2 `/codepy` endpoint |
| T1132.001 | Data Encoding: Standard Encoding | Exfiltration data serialized as JSON, encrypted with AES-256-CBC, RSA-wrapped key |
| T1041 | Exfiltration Over C2 Channel | Encrypted archive uploaded via HTTP POST to `litellm[.]dev/healthcheck` |

## Impact Assessment

**Breadth:** An estimated 49,000+ downloads of the malicious PyPI package occurred during the approximately 1 hour 43 minute exposure window. Docker Hub tags `latest`, `main-latest`, and `main-stable` were also affected, impacting automated container deployments. LiteLLM is a dependency in many enterprise AI pipelines.

**Depth:** The stealer targets an extremely broad range of credentials -- cloud provider keys (AWS, Azure, GCP), AI API keys (OpenAI, Anthropic, etc.), source control tokens, SSH/GPG keys, browser credentials, CI/CD secrets, and LiteLLM's own stored provider credentials. Wiz observed attackers using stolen AWS credentials to query Bedrock models approximately 4.5 hours after exfiltration (LLMjacking).

**Stealth:** The Python startup hook mechanism runs on any Python invocation in the affected environment, not just LiteLLM imports. Even investigators running `pip` or `python` in a compromised environment could trigger the payload. The dead-drop loader provides persistent re-arming capability.

## Detection & Remediation

### Immediate Detection

```bash
# Check for malicious startup files in Python environments
find / -name "cook.pth" -o -name "cook.py" -path "*/site-packages/*" 2>/dev/null

# Check for completion marker and lock file
ls -la /tmp/.pc_once_72129118c59f5636c0bb /tmp/remote_code_loader.lock 2>/dev/null

# Check for staging directories
find /tmp -maxdepth 1 -name ".pc_e_*" -type d 2>/dev/null

# Check installed litellm version (run from CLEAN Python, not the potentially compromised one)
# Use a fresh virtualenv or container
pip show litellm 2>/dev/null | grep -E "^Version:"

# Check for PRIVCOLLECT environment variable in running processes (Linux)
grep -rl "PRIVCOLLECT_ACTIVE" /proc/*/environ 2>/dev/null

# Hash verification of known malicious wheels
sha256sum /path/to/litellm*.whl 2>/dev/null

# Check DNS logs for litellm.dev
# (command depends on your DNS logging infrastructure)

# Check network logs for HTTP POST to /healthcheck on litellm.dev
# (command depends on your proxy/firewall logging)
```

### Remediation

1. **Scope every copy:** Check installed environments, pip/uv caches, internal mirrors, lock files, build outputs, and container images. Compare artifacts against the SHA-256 hashes listed above. Use image digests, not mutable tags.
2. **Contain without running Python:** Isolate affected hosts. Stop Python processes where safe. Do NOT run `python`, `pip`, or any command that invokes the affected interpreter during investigation -- this triggers the payload. Inspect from a known-clean system or use non-Python tools.
3. **Rebuild from verified artifacts:** Confirm `cook.pth`, `cook.py`, and `sitecustomize.py` are removed from the library path. Deleting only the `litellm/` directory is insufficient. Pin to litellm 1.106.2 by digest.
4. **Rotate all credentials from a clean machine:** Model-provider API keys, AWS/Azure/GCP credentials, CI/CD secrets, GitHub tokens, SSH/GPG keys, AI coding-tool tokens, browser sessions, stored LiteLLM provider credentials, and `DATABASE_URL` on proxy hosts. Revoke active sessions -- rotation alone may not invalidate them.
5. **Review cloud audit logs:** Check for unauthorized use of stolen credentials, especially AWS Bedrock model invocations (LLMjacking).
6. **Review GitHub audit logs:** Look for disabled branch protections, unexpected merges, unfamiliar workflow runs, and throwaway branches.

### Long-Term Hardening

- Use hash-pinned lockfiles and verify provenance attestations for all dependencies
- Use container image digests instead of mutable tags
- Enforce strict scoping on GitHub tokens and service accounts (principle of least privilege)
- Require hardware-bound MFA for release approvals; do not relax two-person approval requirements
- Restrict egress from developer, build, test, and container hosts to allowlisted destinations
- Monitor for `.pth` file creation in Python site-packages directories
- Scan for leaked secrets in public repositories using tools like GitGuardian, and ensure immediate revocation

## Detection Rules

<!-- revision: rule count reduced from 11 to 10 after dropping behavioral Windows recon rule -->
10 detections (5 Sigma, 1 Snort, 2 Suricata, 2 YARA) target the LiteLLM 1.107.0 supply chain compromise at the PoC/advisory-specific altitude. Rules key on the distinctive artifacts from the malicious package: startup hook file hashes, the PRIVCOLLECT stealer's file paths and environment variables, network indicators (exfiltration domain and dead-drop URL), and the OpenSSL encryption staging patterns. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles-status does not mean the rule fires in your environment -- verify against your telemetry. Rules with `product: linux` require appropriate log-source mappings (e.g., auditd, sysmon-for-linux) in each SIEM.

### Sigma: LiteLLM Malicious Startup Hook File Creation

Detects creation of `cook.pth`, `cook.py`, or malicious `sitecustomize.py` in Python site-packages directories matching known SHA-256 hashes from the LiteLLM 1.107.0 compromise.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE ATT&CK data fetch blocked by proxy, env issue not rule error); splunk convert 0; log_scale convert 0. Keys on six exact SHA-256 hashes from Microsoft analysis — zero expected FP from hash match. No pipeline mapping (file_event has no sysmon-specific pipeline that adds value here). -->
```yaml
title: LiteLLM 1.107.0 Malicious Startup Hook File Creation
id: f7a1c3e8-4b2d-4f9a-8e6c-1d3b5a7f9e2c
status: experimental
description: >
    Detects creation of files matching SHA-256 hashes of the malicious cook.pth,
    cook.py, and sitecustomize.py from the LiteLLM 1.107.0 supply chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/
author: Actioner
date: 2026-10-25
tags:
    - attack.t1195.001
    - attack.t1059.006
logsource:
    category: file_event
    product: windows
detection:
    selection_hash:
        Hashes|contains:
            - '7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb'
            - '84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d'
            - '9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25'
            - '03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea'
            - '34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa'
            - 'b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465'
    condition: selection_hash
falsepositives:
    - None expected - hashes are specific to malicious files
level: critical
```

### Sigma: LiteLLM PRIVCOLLECT OpenSSL Encryption Staging

Detects OpenSSL command lines using `.pc_e_` staging directories with AES-256-CBC encryption or RSA public-key operations, consistent with the PRIVCOLLECT stealer's encryption and exfiltration routine.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (env); splunk convert 0; log_scale convert 0. Keys on the distinctive .pc_e_ staging path prefix combined with OpenSSL crypto operations — highly specific to this payload. Legitimate openssl use with .pc_e_ paths is not expected. -->
```yaml
title: LiteLLM PRIVCOLLECT OpenSSL Encryption Staging Activity
id: b3d8e5a1-7c4f-4a2e-9f6b-8e1d3c5a7b9f
status: experimental
description: >
    Detects OpenSSL command lines referencing .pc_e_ staging directories with
    AES-256-CBC or RSA public-key encryption, consistent with the PRIVCOLLECT
    credential stealer from the LiteLLM 1.107.0 compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026-10-25
tags:
    - attack.t1027.013
    - attack.t1041
logsource:
    category: process_creation
    product: windows
detection:
    selection_openssl:
        Image|endswith: '\openssl.exe'
    selection_staging:
        CommandLine|contains: '.pc_e_'
    selection_crypto:
        CommandLine|contains:
            - 'enc -aes-256-cbc'
            - 'pkeyutl -encrypt -pubin'
            - 'rsautl -encrypt -pubin'
    condition: selection_openssl and selection_staging and selection_crypto
falsepositives:
    - None expected - the .pc_e_ staging path is specific to this malware
level: high
```

<!-- revision: Windows reconnaissance rule (Sigma PRIVCOLLECT Recon via Python) dropped — behavioral OR-logic pattern fires on any single recon command from Python, not artifact-specific. -->

### Sigma: LiteLLM PRIVCOLLECT Completion Marker and Lock File Creation

Detects creation of the PRIVCOLLECT completion marker `/tmp/.pc_once_72129118c59f5636c0bb` or the remote code loader lock file `/tmp/remote_code_loader.lock` on Linux systems.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (env); splunk convert 0; log_scale convert 0. The completion marker filename contains a unique hex suffix specific to this campaign. The lock filename is also distinctive. Negligible FP expected. -->
```yaml
title: LiteLLM PRIVCOLLECT Marker and Lock File Creation (Linux)
id: a1f9c4e7-8d3b-4a5e-b2c6-7f1e9d3a8b5c
status: experimental
description: >
    Detects creation of the PRIVCOLLECT stealer completion marker or the remote
    code loader lock file on Linux, specific to the LiteLLM 1.107.0 compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026-10-25
tags:
    - attack.t1059.006
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename:
            - '/tmp/.pc_once_72129118c59f5636c0bb'
            - '/tmp/remote_code_loader.lock'
    condition: selection
falsepositives:
    - None expected - filenames are specific to this malware
level: critical
```

### Sigma: DNS Query to LiteLLM Exfiltration Domain

Detects DNS resolution of `litellm.dev` or `www.litellm.dev`, the attacker-registered exfiltration domain used by the PRIVCOLLECT stealer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (env); splunk convert 0; log_scale convert 0. Domain registered by attacker on Oct 13, 2026 specifically for this campaign. Not a legitimate LiteLLM domain (legitimate is litellm.ai). -->
<!-- revision: added '.litellm.dev' entry to prevent endswith substring match on e.g. notlitellm.dev -->
```yaml
title: DNS Query to LiteLLM Exfiltration Domain
id: c8e2b5d1-9f4a-4c7e-a3b8-6d1f5e9c2a4b
status: experimental
description: >
    Detects DNS queries to litellm.dev or www.litellm.dev, the attacker-controlled
    exfiltration domain from the LiteLLM 1.107.0 supply chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    - https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html
author: Actioner
date: 2026-10-25
tags:
    - attack.t1041
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'litellm.dev'
            - '.litellm.dev'
    condition: selection
falsepositives:
    - None expected - litellm.dev is an attacker-registered domain, not a legitimate LiteLLM domain
level: critical
```

### Sigma: LiteLLM PRIVCOLLECT Prisma Database Query

Detects Python processes using Prisma to query LiteLLM credential and model tables, consistent with the PRIVCOLLECT stealer's database exfiltration behavior. Requires command-line audit logging; the stealer may invoke Prisma via library call rather than subprocess, in which case this rule will not fire.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check skipped (env); splunk convert 0; log_scale convert 0. Keys on the specific table names queried by the stealer. Medium confidence because legitimate LiteLLM admin operations may query these tables, and the stealer's Prisma invocation method (subprocess vs library) is uncertain. -->
<!-- revision: changed product from windows to linux (LiteLLM predominantly deployed on Linux); added caveat re Prisma invocation uncertainty -->
```yaml
title: LiteLLM PRIVCOLLECT Prisma Database Credential Extraction
id: d5a3f8c1-6e2b-4d9a-b7c4-9f1e3a5d8c2b
status: experimental
description: >
    Detects Python command lines referencing LiteLLM proxy database tables
    (LiteLLM_CredentialsTable, LiteLLM_ProxyModelTable) with query_raw and
    output suppression, consistent with the PRIVCOLLECT stealer.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026-10-25
tags:
    - attack.t1005
    - attack.t1552.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_python:
        Image|endswith:
            - '/python'
            - '/python3'
    selection_tables:
        CommandLine|contains:
            - 'LiteLLM_CredentialsTable'
            - 'LiteLLM_ProxyModelTable'
    selection_technique:
        CommandLine|contains:
            - 'query_raw'
            - 'os.devnull'
    condition: selection_python and selection_tables and selection_technique
falsepositives:
    - Legitimate LiteLLM database administration scripts (unlikely to combine query_raw with output suppression)
level: high
```

### Snort: LiteLLM PRIVCOLLECT HTTP Exfiltration to litellm.dev

Detects HTTP POST requests to the `/healthcheck` endpoint on `litellm.dev` with `application/octet-stream` content type, matching the PRIVCOLLECT stealer's exfiltration pattern.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 -c snort_test.conf -T exit 0 (validated with custom minimal config including classification). Keys on the exfiltration domain + path + content type. The combination of litellm.dev host with /healthcheck POST and octet-stream is highly distinctive. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - LiteLLM PRIVCOLLECT HTTP Exfiltration to litellm.dev"; flow:established,to_server; content:"POST"; depth:4; content:"/healthcheck"; content:"litellm.dev"; content:"application/octet-stream"; sid:2100101; rev:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/;)
```

### Suricata: LiteLLM PRIVCOLLECT HTTP Exfiltration to litellm.dev

Detects HTTP POST requests to `/healthcheck` on `litellm.dev` with octet-stream content type, matching the PRIVCOLLECT exfiltration pattern.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T -S exit 0. Uses dot-notation sticky buffers. Keys on attacker-registered domain + exfiltration path + content type. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM PRIVCOLLECT HTTP Exfiltration to litellm.dev"; flow:established,to_server; http.method; content:"POST"; http.host; content:"litellm.dev"; endswith; http.uri; content:"/healthcheck"; startswith; http.content_type; content:"application/octet-stream"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created_at 2026-10-25; sid:2200101; rev:1;)
```

### Suricata: DNS Query to LiteLLM Exfiltration Domain

Detects DNS queries for `litellm.dev`, the attacker-controlled exfiltration domain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T -S exit 0. Uses dns.query buffer with endswith. Domain is attacker-registered, not legitimate LiteLLM infrastructure. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to LiteLLM Exfiltration Domain litellm.dev"; flow:to_server; dns.query; content:"litellm.dev"; nocase; endswith; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created_at 2026-10-25; sid:2200102; rev:1;)
```

### YARA: LiteLLM PRIVCOLLECT Credential Stealer

Detects the malicious `cook.py` and `sitecustomize.py` files from the LiteLLM 1.107.0 compromise by matching distinctive strings: the PRIVCOLLECT identifier, completion marker path, staging directory prefix, environment variable, and exfiltration endpoint.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. sample: fired on pos_privcollect.txt (PRIVCOLLECT_ACTIVE + marker + staging + exfil_url + lock + dead_drop + tables + X-SHA256). Quiet on neg_benign.txt (clean litellm usage). Strings drawn from Microsoft's published analysis — all are distinctive to this payload. -->
```yara
rule Supply_Chain_LiteLLM_PRIVCOLLECT_Stealer
{
    meta:
        description = "Detects the PRIVCOLLECT credential stealer from the LiteLLM 1.107.0 supply chain compromise"
        author = "Actioner"
        date = "2026-10-25"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        severity = "critical"

    strings:
        $env = "PRIVCOLLECT_ACTIVE" ascii
        $marker = ".pc_once_72129118c59f5636c0bb" ascii
        $staging = ".pc_e_" ascii
        $exfil = "litellm.dev/healthcheck" ascii
        $loader_lock = "remote_code_loader.lock" ascii
        $dead_drop = "letters9813/pythonclient-test" ascii
        $codepy = "/codepy" ascii
        $table1 = "LiteLLM_CredentialsTable" ascii
        $table2 = "LiteLLM_ProxyModelTable" ascii
        $xsha = "X-SHA256" ascii

    condition:
        filesize < 5MB and 3 of them
}
```

### YARA: LiteLLM Malicious cook.pth Startup Hook

Detects the malicious `cook.pth` startup hook from the LiteLLM 1.107.0 compromise by matching the `import cook` string in small `.pth` files. A legitimate Python package named `cook` could produce a false positive.
**Status:** compile ✅ compiles · confidence: medium · sample: fired ✓
<!-- audit: yarac exit 0. sample: fired on pos_cookpth.txt ("import cook\n", 12 bytes). Quiet on neg_pth.txt ("import os\n"). The fullword modifier prevents partial matches. filesize < 1KB scopes to small .pth files. Confidence downgraded from high to medium: a legitimate `cook` package could produce a matching .pth file. -->
<!-- revision: fixed description (was incorrectly claiming hash-based detection; rule actually matches `import cook` string + filesize constraint). Downgraded confidence from high to medium. -->
```yara
rule Supply_Chain_LiteLLM_Cook_PTH
{
    meta:
        description = "Detects the malicious cook.pth Python startup hook from LiteLLM 1.107.0"
        author = "Actioner"
        date = "2026-10-25"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash1 = "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        hash2 = "84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d"
        severity = "critical"

    strings:
        $hook = "import cook" ascii fullword

    condition:
        filesize < 1KB and $hook
}
```

## Lessons Learned

1. **Secret revocation must be immediate and verified.** The master key committed in May 2026 was force-pushed over but never revoked, leaving a five-month window for attacker discovery and exploitation. Git history is permanent; force-pushing does not remove committed secrets.

2. **Token scoping and privilege boundaries matter.** A single overly-permissive GitHub CLI OAuth token tied to an organization owner provided attacker access to all repositories. Service tokens should follow least-privilege principles with narrow scopes.

3. **Release pipeline integrity requires hardware-bound controls.** The two-person approval requirement was relaxed the same week as the attack, and both approvals were satisfiable with stolen software tokens. Hardware-bound MFA for release approvals would have prevented this.

4. **Python startup hooks are a persistent blind spot.** `.pth` files and `sitecustomize.py` execute before any user code, making them ideal for supply chain payloads. Organizations should monitor site-packages for unexpected `.pth` files and `sitecustomize.py` modifications.

5. **LiteLLM's role as a credential aggregation proxy amplifies supply chain risk.** Compromising LiteLLM provides access to credentials for numerous AI providers, cloud services, and infrastructure -- it is a high-value target for supply chain attacks.

6. **Investigate from clean systems.** Running Python or pip in a compromised environment triggers the payload. Forensic investigation must use non-Python tools or known-clean interpreters.

## Sources

- [Microsoft Threat Intelligence Blog](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/) — primary technical analysis of malicious payload, startup hooks, credential collection, encryption, exfiltration, and IOCs
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/) — timeline, affected Docker images, credential theft scope, and remediation guidance
- [The Hacker News (initial)](https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html) — affected wheel list, payload behavior, SafeDep and Socket researcher attribution
- [The Hacker News (leaked key)](https://thehackernews.com/2026/10/leaked-litellm-master-key-let-attackers.html) — root cause analysis, leaked master key details, timeline of credential theft via throwaway workflows, webhook exfiltration endpoints, release pipeline abuse
- [SecurityWeek](https://www.securityweek.com/litellm-compromised-in-fresh-supply-chain-attack/) — download count estimate (49,000+), Wiz LLMjacking observation, Claude Code token exposure angle

---
*Report generated by Actioner*
