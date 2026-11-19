# Technical Analysis Report: Microsoft Agent Framework PyPI Supply Chain Attack (2026-11-19)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-19
Version: 1.0
<!-- revision: v1.0 — applied critic fixes: added cs-method POST filter to Sigma webhook rule; renumbered Suricata SID 2100101→1000101 (custom range); dropped sid:2100102 DNS-only rule (too broad); verified T1546.016 valid -->

## Executive Summary

On November 17, 2026, an attacker published two malicious versions (1.26.1 and 1.26.2) of Microsoft's official `agent-framework` Python package on PyPI. The compromised releases contained a credential-stealing payload that executed automatically at every Python interpreter startup via `.pth` hook files, without requiring the application to import the package. The stealer harvested Azure CLI credentials, cloud managed-identity tokens, CI/CD secrets (Azure DevOps and GitHub Actions OIDC tokens), package manager credentials (pip, npm, Docker, Git), Hugging Face tokens, and environment variables containing secret-like values. Stolen data was zlib-compressed, base64-encoded, and exfiltrated via a single HTTPS POST to a webhook[.]site endpoint. Both malicious versions were quarantined within approximately 40-55 minutes of the first upload. The package averages roughly 41,000 downloads per week across all versions; the number of installations of the malicious versions during the exposure window is not publicly confirmed. Any system that installed either version should be treated as fully compromised, and all credentials present on those systems should be rotated immediately.

## Background: Microsoft Agent Framework

Microsoft's `agent-framework` is a widely used Python package for building AI agent applications, published to PyPI as the official distribution. It depends on `agent-framework-core` for its runtime. The package had approximately 196,000 monthly downloads at the time of the compromise, making it a high-value supply chain target. The last legitimate release was version 1.26.0, published November 12, 2026. This is the second Microsoft-related PyPI package compromised in 2026; in May, the `durabletask` package was similarly attacked by the TeamPCP threat actors.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-11-12 18:24 | Legitimate `agent-framework` 1.26.0 published (wheel + sdist) |
| 2026-11-17 (time unknown) | PyPI account `vibiret` created and added as a maintainer of the project |
| 2026-11-17 20:35:20 | Malicious version 1.26.1 published (wheel only, no sdist, no provenance attestation) |
| 2026-11-17 21:06:16 | Version 1.26.1 quarantined by PyPI |
| 2026-11-17 21:08:39 | Malicious version 1.26.2 published (~2 min after first quarantine) |
| 2026-11-17 21:16:44 | Version 1.26.2 quarantined by PyPI |
| 2026-11-17 ~21:20-21:30 | Both versions removed; 1.26.0 restored as latest |
| 2026-11-18 | Public disclosure by security researchers |

## Root Cause: Compromised PyPI Publisher Account

The attacker gained unauthorized access to publish releases under Microsoft's official `agent-framework` PyPI project. StepSecurity identified a new PyPI account, `vibiret`, that was added as a maintainer of the project on November 17 before the malicious uploads. The exact mechanism of account compromise or maintainer-addition is not publicly confirmed. Wiz reported that attacker tooling identified itself as **Cairn**, an open-source AI penetration-testing framework, and sent a `CAIRN_ESRP_PROBE2` connectivity probe. The first publish attempt from an AWS IP was rejected by ESRP IP filtering; a second attempt from Microsoft-owned IP space succeeded. Both malicious releases were uploaded as wheels only (no sdist), lacked provenance attestations, and used the User-Agent `RestSharp/106.13.0.0` for the PyPI upload -- all anomalies compared to the legitimate 1.26.0 release.

## Technical Analysis of the Malicious Payload

### 1. Persistence via .pth Startup Hooks

Both versions exploited Python's `.pth` file mechanism. When a `.pth` file contains an `import` statement, Python's `site` module executes it at every interpreter startup, before any application code runs.

**Version 1.26.1:** Installed `agent_framework_meta.pth` in site-packages containing:
```python
import agent_framework_meta
```
This triggered `agent_framework_meta/__init__.py`, which had been modified to call `_telemetry._start()` inside a silent `try/except`:
```python
try:
    from . import _telemetry as _telemetry
    _telemetry._start()
except Exception:
    pass
```

**Version 1.26.2:** The attacker adapted after the first quarantine. The package's `__init__.py` was restored to the clean 1.26.0 version, and the payload was moved to a standalone hook:
- `af_runtime_diag.pth` containing `import af_runtime_diag`
- `af_runtime_diag.py` as a top-level module

This meant inspecting only the package's `__init__.py` would miss the second variant entirely.

### 2. Process Detachment and Anti-Recursion

The credential stealer used several techniques to avoid detection and prevent duplicate runs:

- **Environment guard:** Set `_AF_TEL=1` on first run; child processes inherit this, preventing re-execution within the same process tree.
- **Process detachment:** Called `os.fork()` followed by `os.setsid()` to fully detach the collector as a new session leader. On Windows (no `fork`), fell back to a daemon thread.
- **Silent failure:** All operations wrapped in exception handlers that silently discard errors -- no log output or stack traces.
- **Decoy naming:** Functions and descriptions used terms like `_telemetry` and "Lightweight runtime diagnostics hook."
- **URL obfuscation:** The exfiltration URL was stored base64-encoded in a variable named `_ENC`:
```python
_ENC = "aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi"
```

### 3. Credential and Token Harvesting

**Environment variables:** Collected any whose name contained secret-related keywords. Version 1.26.1 used 31 keywords (TOKEN, SECRET, PASSWORD, KEY, AZURE, AWS, GITHUB, GH_, OPENAI, HF_, FOUNDRY, TENANT, CLIENT, MANAGED, NPM, PIP, NUGET, SYSTEM, BUILD, AGENT, etc.). Version 1.26.2 added ACTIONS, OIDC, RUNNER, and ARM_.

**Process environment scraping:** Read `/proc/[0-9]*/environ` for up to 300 processes, applying the same keyword filter.

**Credential files:** Read up to 60 files (1.26.1) or 80 files (1.26.2), each under 256 KiB, with content truncated to 120,000 characters. Targeted paths include:
- `~/.azure/*.json`, `~/.azure/*/*.json` (Azure CLI)
- `.npmrc`, `pip.conf`, `.netrc`, `.git-credentials` (package managers/VCS)
- `.docker/config.json` (container registry)
- Hugging Face tokens under `.cache/huggingface/` and `.huggingface/`
- Azure DevOps agent `.credentials` files under multiple paths
- `.env` and `.json` files under `/app/` and `/workspace/`
- Version 1.26.2 added: `/home/runner/work/_temp/*` and `/home/runner/.azure/*` (GitHub Actions)

**Azure managed-identity tokens:** Queried `IDENTITY_ENDPOINT` (or IMDS at `169.254.169.254`) for access tokens across 12 Azure resources: ARM, Graph, Key Vault, Storage, Cognitive Services, Azure AI/ML, Search, Container Registry, Azure DevOps (`499b84ac-1321-427f-aa17-267ca6975798`), and AzureADTokenExchange. Also collected IMDS instance metadata.

**Azure DevOps OIDC (both versions):** If `SYSTEM_ACCESSTOKEN` and `SYSTEM_OIDCREQUESTURI` were set, requested an OIDC token for `api://AzureADTokenExchange`.

**GitHub Actions OIDC (1.26.2 only):** In workflows with `id-token: write`, used `ACTIONS_ID_TOKEN_REQUEST_URL` and the runtime token to request JWTs for audiences `api://AzureADTokenExchange` and `https://management.azure.com/`.

**Host context:** Hostname, username, working directory, and first 20 command-line arguments.

### 4. C2 / Exfiltration Infrastructure

The exfiltration used a single webhook[.]site endpoint. All collected data was serialized as JSON, zlib-compressed, base64-encoded, and sent in one HTTPS POST:

- **Endpoint:** `hxxps://webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb?t=telemetry`
- **Method:** POST with `Content-Type: application/octet-stream`
- **User-Agent (1.26.1):** `af-runtime-diagnostics/1`
- **User-Agent (1.26.2):** `runtime-diagnostics/1`
- **No retry logic, no fallback channel.** Failures silently ignored.
- **No second stage.** The payload downloaded no additional code and established no persistent C2 channel.

### 5. Anti-Forensics / Evasion Techniques

- **No persistence beyond .pth hooks:** No scheduled tasks, services, or cron jobs.
- **No file writes:** The payload wrote no files to disk beyond the installed package files.
- **Silent exception handling:** All errors suppressed.
- **Process detachment:** Forked and detached to avoid appearing as a child of the installing process.
- **Legitimate dependency retained:** Both malicious versions maintained their dependency on `agent-framework-core` 1.26.0, allowing the framework to function normally while the stealer ran.
- **Version 1.26.2 evasion:** Restored `__init__.py` to clean state, defeating naive checks of only the package initializer.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` replacing `https://`
> - Domains: `[.]` replacing dots (e.g., `webhook[.]site`)

### Package / Software Level

| Package / Component | Malicious Version | SHA256 (Wheel) |
|---------------------|-------------------|----------------|
| `agent-framework` | 1.26.1 | `d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110` |
| `agent-framework` | 1.26.2 | `3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9` |

### File System

| File | SHA256 | Version | Description |
|------|--------|---------|-------------|
| `agent_framework_meta.pth` | `21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e` | 1.26.1 | Startup hook |
| `agent_framework_meta/_telemetry.py` | `39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663` | 1.26.1 | Credential stealer |
| `af_runtime_diag.pth` | `325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93` | 1.26.2 | Startup hook |
| `af_runtime_diag.py` | `54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f` | 1.26.2 | Credential stealer |
| `agent_framework_meta/__init__.py` | `c275ccbe520ef3c0f02dc6a35389e427f9f1b4e0b12e140cd7bf7179ce143f02` | 1.26.1 | Modified package init |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL | `hxxps://webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb?t=telemetry` | Exfiltration endpoint |
| Domain | `webhook[.]site` | Exfiltration service |
| User-Agent | `af-runtime-diagnostics/1` | Exfil UA (v1.26.1) |
| User-Agent | `runtime-diagnostics/1` | Exfil UA (v1.26.2) |
| Upload UA | `RestSharp/106.13.0.0` | PyPI upload User-Agent (registry forensics) |

### Behavioral

- Presence of `agent_framework_meta.pth` or `af_runtime_diag.pth` in any Python `site-packages` directory
- Environment variable `_AF_TEL=1` set in running processes
- Python processes making HTTPS POST requests to `webhook[.]site` with `application/octet-stream` content type
- Python processes reading `/proc/*/environ` for large numbers of PIDs
- Requests to Azure IMDS (`169.254.169.254`) from build/runner/CI processes requesting tokens for multiple Azure resource audiences in rapid succession
- OIDC token requests to `ACTIONS_ID_TOKEN_REQUEST_URL` or `SYSTEM_OIDCREQUESTURI` from unexpected processes

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker published malicious versions of a legitimate PyPI package |
| T1546.016 | Event Triggered Execution: Installer Packages | .pth hook files execute code at every Python interpreter startup |
| T1552.001 | Unsecured Credentials: Credentials in Files | Harvested credentials from Azure CLI, pip, npm, Docker, Git, Hugging Face config files |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Queried Azure IMDS for managed-identity tokens |
| T1528 | Steal Application Access Token | Requested Azure DevOps OIDC and GitHub Actions OIDC tokens |
| T1041 | Exfiltration Over C2 Channel | Exfiltrated data via HTTPS POST to webhook[.]site |
| T1059.006 | Command and Scripting Interpreter: Python | Payload executed as Python code via .pth import mechanism |
| T1057 | Process Discovery | Enumerated `/proc/*/environ` for up to 300 processes |
| T1082 | System Information Discovery | Collected hostname, username, working directory, command-line arguments, IMDS instance metadata |

## Impact Assessment

**Breadth:** The `agent-framework` package averaged approximately 41,000 downloads per week (196,000/month) across all versions. The malicious versions were available for approximately 40-55 minutes. The actual number of compromised installations during this window is unknown but likely limited by the short exposure period. However, CI/CD systems with loose version pins (`>=1.26`) and automated dependency resolution could have pulled the malicious versions during builds.

**Depth:** The stealer was comprehensive: it targeted not just static credentials but also dynamically minted cloud identity tokens (Azure managed identity, Azure DevOps OIDC, GitHub Actions OIDC). An attacker who obtained these tokens could access Azure resources (Key Vault, Storage, Container Registry, Azure Resource Manager, Microsoft Graph), Azure DevOps pipelines, and GitHub Actions workflows. The credential file harvesting covered the full developer/CI toolchain.

**Stealth:** The payload executed silently at Python startup, required no explicit import, wrote no files, produced no log output, and detached from the parent process. Version 1.26.2's restoration of the clean `__init__.py` specifically defeated naive detection of the first variant.

**Advisories:** GHSA-764m-3ppc-5m73, OSV MAL-2026-20101, Mend MSC-2026-13866. No CVE assigned.

## Detection & Remediation

### Immediate Detection

Check for the presence of malicious files in any Python environment:

```bash
# Search for malicious .pth files
find / -name "agent_framework_meta.pth" -o -name "af_runtime_diag.pth" 2>/dev/null

# Search for malicious payload files
find / -name "_telemetry.py" -path "*/agent_framework_meta/*" 2>/dev/null
find / -name "af_runtime_diag.py" 2>/dev/null

# Check installed version (DO NOT run pip in a suspected environment -- the hook re-executes)
# Instead, inspect the METADATA file directly:
find / -path "*/agent_framework-1.26.*/METADATA" 2>/dev/null | xargs grep "^Version:"

# Check for the environment guard variable
env | grep _AF_TEL

# Search network logs for exfiltration
# (Adapt to your log system)
grep -r "webhook.site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb" /var/log/
grep -rE "(af-runtime-diagnostics|runtime-diagnostics)/1" /var/log/
```

### Remediation

1. **Do NOT run Python or pip in the affected environment.** The `.pth` hook will re-execute the stealer on any Python invocation.
2. **Isolate affected systems.** Block outbound connections to `webhook[.]site`.
3. **Remove from a clean environment.** Mount the filesystem from a clean system or use container inspection tools to remove:
   - `agent_framework_meta.pth` and `agent_framework_meta/` directory
   - `af_runtime_diag.pth` and `af_runtime_diag.py`
   - Any cached `.pyc` bytecode files for these modules
   - The `agent_framework-1.26.1.dist-info/` or `agent_framework-1.26.2.dist-info/` directories
4. **Pin to safe version:** `agent-framework==1.26.0`
5. **Rotate ALL credentials** that were present on affected machines, including:
   - Azure service principals, managed identity role assignments, and federated credentials
   - Azure DevOps PATs and service connections
   - GitHub tokens and OIDC trust configurations
   - Git credentials, npm tokens, pip credentials, Docker registry credentials
   - Hugging Face tokens
   - Any values in `.env` files or CI/CD secret variables
6. **Review audit logs** for Azure, GitHub, and Azure DevOps for unauthorized access using potentially stolen tokens.
7. **Rebuild affected CI/CD environments** rather than attempting to clean them.

### Long-Term Hardening

- **Pin exact versions** of all dependencies in requirements files and lock files. Avoid range specifiers like `>=`.
- **Use hash verification:** `pip install --require-hashes` with known-good hashes.
- **Enable PyPI Trusted Publishers** to restrict which CI systems can publish to your packages.
- **Monitor for `.pth` file creation** in site-packages directories as part of endpoint detection.
- **Block or alert on webhook[.]site** and similar data-exfiltration services at the network perimeter.
- **Implement OIDC audience restrictions** to limit which audiences federated identity tokens can be minted for.
- **Review managed identity role assignments** to enforce least-privilege.

## Detection Rules

These rules cover the three key detection surfaces: malicious package installation, file system artifacts from the .pth hooks, and network exfiltration to the known webhook[.]site endpoint. The YARA rules target the actual malicious Python files for retrospective scanning. The primary caveat is that the exfiltration endpoint (webhook[.]site) is a legitimate service, so the Sigma proxy rule and Suricata rule pair the domain with the specific User-Agent strings, HTTP method, and/or URI path to reduce false positives.

### Sigma: Pip Install of Malicious Agent Framework Versions

Detects explicit pip install commands specifying the compromised versions 1.26.1 or 1.26.2.
<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk exit 0, sigma convert --without-pipeline -t log_scale exit 0); sigma check failed due to MITRE ATT&CK data endpoint unreachable (HTTP 403 from proxy), not a rule defect; structural validation via successful Splunk and LogScale conversion confirms syntax correctness -->
**compile: pass (convert) | confidence: high**

```yaml
title: Pip Install of Malicious Microsoft Agent Framework Versions
id: 7a6925ef-ecb8-4d72-b79f-9d1a434936d3
status: experimental
description: >
    Detects pip install commands targeting the compromised agent-framework
    versions 1.26.1 or 1.26.2, which contain a credential-stealing payload
    that executes at Python startup via .pth hooks.
references:
    - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
    - https://www.stepsecurity.io/blog/microsoft-agent-framework-pypi-package-compromised
author: Actioner
date: 2026-11-19
tags:
    - attack.t1195.002
    - attack.t1059.006
logsource:
    category: process_creation
detection:
    selection_pip:
        CommandLine|contains:
            - 'pip install'
            - 'pip3 install'
    selection_package:
        CommandLine|contains:
            - 'agent-framework==1.26.1'
            - 'agent-framework==1.26.2'
            - 'agent_framework==1.26.1'
            - 'agent_framework==1.26.2'
    condition: selection_pip and selection_package
falsepositives:
    - Unlikely, as these specific versions have been quarantined and removed from PyPI
level: critical
```

### Sigma: Suspicious PTH File Creation in Python Site-Packages

Detects creation of the specific `.pth` hook files used by the malicious agent-framework versions.
<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk exit 0, sigma convert --without-pipeline -t log_scale exit 0); sigma check failed due to external endpoint unreachable, not rule defect; T1546.016 is the sub-technique for installer package persistence -->
**compile: pass (convert) | confidence: high**

```yaml
title: Suspicious PTH File Creation in Python Site-Packages
id: 83594a26-96ee-4528-a1d5-62237e6d500c
status: experimental
description: >
    Detects the creation of .pth files associated with the malicious
    agent-framework versions 1.26.1 and 1.26.2 in Python site-packages
    directories. These hooks execute code at every Python interpreter startup.
references:
    - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
    - https://socket.dev/blog/agent-framework-pypi-package-compromised-with-credential-stealer
author: Actioner
date: 2026-11-19
tags:
    - attack.t1546.016
    - attack.t1195.002
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'agent_framework_meta.pth'
            - 'af_runtime_diag.pth'
    condition: selection
falsepositives:
    - Legitimate package installations that happen to use these exact filenames are extremely unlikely
level: critical
```

### Sigma: Outbound Connection to Webhook.site with Diagnostics User-Agent

Detects HTTP traffic to webhook[.]site with the specific User-Agent strings used by the credential stealer.
<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk exit 0, sigma convert --without-pipeline -t log_scale exit 0); sigma check failed due to external endpoint unreachable, not rule defect; proxy logsource fields cs-method, cs-host, and cs-useragent are standard W3C proxy log fields; cs-method POST filter added per reviewer feedback -->
**compile: pass (convert) | confidence: medium**

```yaml
title: Outbound Connection to Webhook.site with Diagnostics User-Agent
id: 5ea7ad92-1a36-4f18-ad1d-c9c60e68558c
status: experimental
description: >
    Detects HTTP POST requests to webhook.site using User-Agent strings
    associated with the malicious agent-framework credential stealer.
    The malware exfiltrates stolen credentials to this endpoint.
references:
    - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
    - https://www.mend.io/blog/microsoft-agent-framework-pypi-credential-stealer/
author: Actioner
date: 2026-11-19
tags:
    - attack.t1041
    - attack.t1567
logsource:
    category: proxy
detection:
    selection_method:
        cs-method: 'POST'
    selection_domain:
        cs-host|contains: 'webhook.site'
    selection_ua:
        cs-useragent:
            - 'af-runtime-diagnostics/1'
            - 'runtime-diagnostics/1'
    condition: selection_method and selection_domain and selection_ua
falsepositives:
    - Custom developer tooling using identical User-Agent strings against webhook.site
level: high
```

### YARA: Agent Framework Credential Stealer Payload

Detects the malicious Python credential stealer files from both versions using the base64-encoded exfiltration URL, guard variable, and behavioral indicators.
<!-- audit: compile-status=pass (yarac exit 0); two rules in file: Supply_Chain_AgentFramework_Credential_Stealer targets the full payload scripts, Supply_Chain_AgentFramework_PTH_Hook targets the small .pth trigger files; filesize constraints tuned to known file sizes (payload <50KB, pth <100 bytes) -->
**compile: pass | confidence: high**

```yara
rule Supply_Chain_AgentFramework_Credential_Stealer
{
    meta:
        description = "Detects the credential-stealing payload from compromised Microsoft agent-framework PyPI package versions 1.26.1 and 1.26.2"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"
        hash1 = "39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663"
        hash2 = "54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $enc_url = "aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi" ascii
        $guard_var = "_AF_TEL" ascii
        $ua1 = "af-runtime-diagnostics/1" ascii
        $ua2 = "runtime-diagnostics/1" ascii
        $setsid = "os.setsid()" ascii
        $proc_environ = "/proc/" ascii
        $proc_glob = "*/environ" ascii
        $imds = "169.254.169.254" ascii
        $oidc_aud = "api://AzureADTokenExchange" ascii
        $cred1 = ".git-credentials" ascii
        $cred2 = ".docker/config.json" ascii
        $cred3 = ".azure/" ascii
        $telemetry_desc = "Lightweight runtime diagnostics hook" ascii

    condition:
        filesize < 50KB and
        $enc_url and $guard_var and
        (1 of ($ua*)) and
        (2 of ($setsid, $proc_environ, $proc_glob, $imds, $oidc_aud)) and
        (1 of ($cred*) or $telemetry_desc)
}

rule Supply_Chain_AgentFramework_PTH_Hook
{
    meta:
        description = "Detects the malicious .pth startup hooks from compromised Microsoft agent-framework PyPI package versions 1.26.1 and 1.26.2"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://www.stepsecurity.io/blog/microsoft-agent-framework-pypi-package-compromised"
        hash1 = "21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e"
        hash2 = "325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth1 = "import agent_framework_meta" ascii
        $pth2 = "import af_runtime_diag" ascii

    condition:
        filesize < 100 and
        (1 of them)
}
```

### Suricata: Agent Framework Credential Stealer Exfiltration

Detects the specific exfiltration POST to the known webhook[.]site UUID path with the diagnostics User-Agent substring.
<!-- audit: compile-status=pass (suricata -T exit 0); sid:1000101 targets the specific UUID path + UA; SID in custom range 1000000-1999999; DNS-only webhook.site rule dropped (too broad for a legitimate service) -->
**compile: pass | confidence: high**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Agent Framework Credential Stealer Exfil to Webhook.site"; flow:established,to_server; http.method; content:"POST"; http.host; content:"webhook.site"; fast_pattern; http.uri; content:"/d381fd80-ec62-42ad-8f5c-d1b15103c9bb"; http.user_agent; content:"diagnostics/1"; classtype:trojan-activity; reference:url,www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi; metadata:author Actioner, created_at 2026-11-19; sid:1000101; rev:1;)
```

## Lessons Learned

1. **Python `.pth` files are a stealth persistence vector.** They execute at every interpreter startup without requiring any explicit import, making them an ideal vector for supply chain attacks. Organizations should monitor `.pth` file creation in site-packages directories.

2. **Short exposure windows can still cause significant damage.** Even though the malicious versions were available for under an hour, automated CI/CD pipelines with loose version pins could have installed them during builds, potentially compromising cloud credentials and service connections across many environments.

3. **Attacker adaptation is rapid.** Version 1.26.2 was published within minutes of 1.26.1's quarantine, with an improved evasion technique (restoring the clean `__init__.py`). This demonstrates that supply chain attackers actively monitor for detection and iterate quickly.

4. **Credential rotation scope is broad.** Because the stealer targeted not just static credentials but also dynamically minted identity tokens (managed identity, OIDC), remediation requires reviewing and potentially revoking federated trust relationships, not just rotating passwords.

5. **Package provenance attestation matters.** The malicious versions lacked provenance attestations and were published as wheel-only. Enforcing provenance verification and monitoring for anomalous publishing patterns (wheel-only, new maintainer, unusual User-Agent) could have flagged the compromise earlier.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Wiz Research: Microsoft agent-framework Compromised](https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi) -- primary technical analysis with hashes, file paths, and attack tooling attribution
- [StepSecurity: Microsoft agent-framework PyPI Package Compromised](https://www.stepsecurity.io/blog/microsoft-agent-framework-pypi-package-compromised) -- detailed timeline with per-second timestamps, file hashes, publisher account details
- [Mend.io: Microsoft agent-framework on PyPI: Credential Stealer](https://www.mend.io/blog/microsoft-agent-framework-pypi-credential-stealer/) -- file-level IOCs, credential file count per version, advisory MSC-2026-13866
- [Socket: agent-framework PyPI Package Compromised with Credential Stealer](https://socket.dev/blog/agent-framework-pypi-package-compromised-with-credential-stealer) -- code snippets, execution chain analysis, full credential file path list
- [Aikido: Two Malicious agent-framework Releases Hit PyPI in 33 Minutes](https://www.aikido.dev/blog/two-malicious-agent-framework-releases-hit-pypi-in-33-minutes) -- wheel file forensics, timestamp analysis, publishing anomalies
- [BleepingComputer: Microsoft's Agent Framework PyPI Package Compromised to Steal Credentials](https://www.bleepingcomputer.com/news/security/microsofts-agent-framework-pypi-package-compromised-to-steal-credentials/) -- initial public reporting
- [The Hacker News: Attackers Compromise Microsoft's Agent Framework PyPI Package](https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html) -- public reporting
- [Ostorlab: Microsoft Agent Framework PyPI Backdoor Steals Cloud Credentials](https://blog.ostorlab.co/microsoft-agent-framework-pypi-backdoor.html) -- remediation guidance, advisory references (GHSA-764m-3ppc-5m73, OSV MAL-2026-20101)
- [Orca Security: Microsoft Agent Framework PyPI Supply-Chain Attack](https://orca.security/resources/research/microsoft-agent-framework-pypi-supply-chain-attack-versions-1-26-1-and-1-26-2-steal-cloud-credentials/) -- scope clarification (sibling packages unaffected)
- [Endor Labs: agent-framework Compromised](https://www.endorlabs.com/learn/agent-framework-compromised-software-supply-chain-attack) -- remediation and blocking guidance

---
*Report generated by Actioner*
