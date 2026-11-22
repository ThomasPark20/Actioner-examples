# Microsoft Agent Framework PyPI Supply Chain Attack

**Date:** 2026-11-22
**Status:** FINAL
**TLP:** WHITE
**Severity:** Critical

---

## Executive Summary

On November 17, 2026, an attacker published two malicious versions (1.26.1 and 1.26.2) of Microsoft's official `agent-framework` Python package on PyPI, 33 minutes apart. The compromised versions contained a credential stealer that exploited Python's `.pth` startup hook mechanism to execute on every Python interpreter launch -- even without importing the package. The stealer harvested environment variables, credential files, Azure managed-identity tokens, Azure DevOps OIDC tokens, and GitHub Actions OIDC tokens, then exfiltrated the data as compressed, base64-encoded JSON to a `webhook[.]site` endpoint. The malicious versions were quarantined approximately 45 minutes after the first publication. With roughly 190,000 monthly downloads, the blast radius could have been significant, though Wiz's analysis of the exfiltration endpoint (limited to 50 requests on the free tier) found only 3 unique successful victim exfiltrations among 17 non-sandbox requests.

---

## Background

Microsoft Agent Framework is an open-source Python framework for building and orchestrating AI agents, published as `agent-framework` on PyPI. The package is a meta-package that installs `agent-framework-core` and sibling packages (`agent-framework-openai`, `agent-framework-purview`, `agent-framework-redis`, `agent-framework-tools`, `agent-framework-postgres`).

This is the second Microsoft-related PyPI package compromise in 2026. In May 2026, the TeamPCP group published three malicious versions of `durabletask` to distribute the Mini Shai-Hulud worm.

---

## Attack Timeline

| Time (UTC)              | Event                                                              |
|-------------------------|--------------------------------------------------------------------|
| Nov 12, 2026 ~18:25     | Legitimate version 1.26.0 published to PyPI                       |
| Nov 17, 2026 ~20:35     | Malicious version 1.26.1 published                                |
| Nov 17, 2026 ~21:08     | Malicious version 1.26.2 published (expanded targeting)            |
| Nov 17, 2026 ~21:20     | Both malicious versions quarantined on PyPI                        |
| Nov 17, 2026            | Wiz reports findings to Microsoft                                  |
| Nov 18, 2026            | Public disclosure by Aikido, Socket, SafeDep, and others           |
| Nov 20, 2026            | Microsoft public statement; `microsoft/agent-framework` and `microsoft/onnxruntime` repos made private during investigation |

**Exposure window:** Approximately 45 minutes (20:35 to ~21:20 UTC on November 17, 2026).

---

## Root Cause

According to Wiz, the attacker compromised a **Microsoft ESRP (Engineering System Release Pipeline) client certificate and private key** used to sign and publish the package. A first publish attempt from AWS infrastructure was blocked by ESRP IP filtering. The attacker then succeeded from Microsoft-owned IP space.

The attacker's tooling sent progress reports to the same webhook endpoint used for exfiltration, exposing operational details. The tooling identifies itself as **Cairn**, described as an open-source AI penetration-testing framework. It staged the package at `/tmp/cairn_pkg` and sent a `CAIRN_ESRP_PROBE2` connectivity probe. The tooling environment included an AI coding agent configuration using the `Pi` harness with a `pi_glm53` model.

A suspicious PyPI maintainer account `vibiret` was created on November 17, 2026 and associated with the malicious publications.

---

## Technical Analysis

### Persistence Mechanism

Both malicious versions abuse Python's `.pth` file mechanism. When a `.pth` file contains an `import` statement, Python's `site` module executes it at every interpreter startup. This means the stealer runs:

- On every `python` or `python3` invocation
- During `pip install` commands
- In CI/CD pipeline steps
- In any application running in the affected virtual environment

**No explicit import of `agent-framework` is required.**

### Version 1.26.1

- Drops `agent_framework_meta.pth` in `site-packages` containing `import agent_framework_meta`
- Modified `agent_framework_meta/__init__.py` calls `_telemetry._start()`
- Stealer payload in `agent_framework_meta/_telemetry.py`
- Forks a detached process (`os.fork()` + `os.setsid()`) on Linux/macOS; daemon thread on Windows
- Sets `_AF_TEL=1` environment variable as recursion guard
- User-Agent: `af-runtime-diagnostics/1`
- Collects up to 60 credential files, scans up to 300 `/proc/*/environ`

### Version 1.26.2

- Restores `__init__.py` to the legitimate 1.26.0 version
- Drops `af_runtime_diag.pth` in `site-packages` containing `import af_runtime_diag`
- Standalone stealer in `af_runtime_diag.py`
- User-Agent: `runtime-diagnostics/1`
- Expands environment variable patterns: adds `ACTIONS`, `OIDC`, `RUNNER`, `ARM_`
- Adds GitHub Actions OIDC token collection
- Adds GitHub-hosted runner paths (`/home/runner/`)
- Increases credential file limit to 80

### Data Collection Targets

**Environment Variables** (matched by name substring):
`TOKEN`, `SECRET`, `PASSWORD`, `KEY`, `AZURE`, `AWS`, `GITHUB`, `OPENAI`, `HF_`, `FOUNDRY`, `NPM`, `PIP`, `NUGET`, `SYSTEM`, `BUILD`, `AGENT`, `MANAGED`, `TENANT`, `CLIENT` (v1.26.2 adds: `ACTIONS`, `OIDC`, `RUNNER`, `ARM_`)

**Credential Files:**
- Azure CLI: `~/.azure/*.json`, `~/.azure/*/*.json`
- Package managers: `.npmrc`, `pip.conf`, `.netrc`
- VCS: `.git-credentials`
- Container: `.docker/config.json`
- AI/ML: Hugging Face tokens, Azure AI Foundry configs
- Azure DevOps: `.credentials` files under `_work`, `vss-agent`, `/mnt/azure_nvme_temp`
- Application: `.env`, `*.json` under `/app` and `/workspace`
- Process environments: `/proc/*/environ` (up to 300 processes)

**Cloud Identity Tokens:**
- **Azure IMDS managed-identity tokens** for 12 resources: ARM, Graph, Key Vault, Storage, Cognitive Services, Azure AI/ML, Search, Container Registry, Azure DevOps, AzureADTokenExchange
- **Azure DevOps OIDC tokens** via `SYSTEM_OIDCREQUESTURI` for `api://AzureADTokenExchange`
- **GitHub Actions OIDC tokens** (v1.26.2) via `ACTIONS_ID_TOKEN_REQUEST_URL` for `api://AzureADTokenExchange` and `https://management.azure.com/`
- **Azure instance metadata** from IMDS at `169.254.169.254`

### Exfiltration

- Data compiled as JSON, zlib-compressed (level 9), base64-encoded
- Sent as HTTPS POST with `Content-Type: application/octet-stream`
- Destination: `hxxps://webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb?t=telemetry`
- 25-second timeout; failures silently ignored, no retry
- Encoded destination stored as base64 in variable `_ENC`: `aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi`

---

## Indicators of Compromise

### File Hashes (SHA256)

| File | SHA256 |
|------|--------|
| `agent_framework-1.26.1-py3-none-any.whl` | `d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110` |
| `agent_framework-1.26.2-py3-none-any.whl` | `3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9` |
| `agent_framework_meta/__init__.py` (1.26.1) | `c275ccbe520ef3c0f02dc6a35389e427f9f1b4e0b12e140cd7bf7179ce143f02` |
| `agent_framework_meta/_telemetry.py` | `39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663` |
| `agent_framework_meta.pth` | `21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e` |
| `af_runtime_diag.py` | `54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f` |
| `af_runtime_diag.pth` | `325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93` |

### File Hash (SHA1)

| File | SHA1 |
|------|------|
| `_telemetry.py` | `0a013e4724c4437cf9b177def1d988113e167539` |

### Network Indicators

| Indicator | Type | Description |
|-----------|------|-------------|
| `webhook[.]site` | Domain | Exfiltration destination |
| `hxxps://webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb?t=telemetry` | URL | Full exfiltration endpoint |
| `af-runtime-diagnostics/1` | User-Agent | v1.26.1 stealer |
| `runtime-diagnostics/1` | User-Agent | v1.26.2 stealer |

### Host Indicators

| Indicator | Type | Description |
|-----------|------|-------------|
| `agent_framework_meta.pth` | Filename | v1.26.1 startup hook in `site-packages` |
| `af_runtime_diag.pth` | Filename | v1.26.2 startup hook in `site-packages` |
| `agent_framework_meta/_telemetry.py` | Filename | v1.26.1 stealer payload |
| `af_runtime_diag.py` | Filename | v1.26.2 stealer payload |
| `_AF_TEL=1` | Environment variable | Recursion guard set by stealer |
| `/tmp/cairn_pkg` | Directory | Attacker staging directory |
| `CAIRN_ESRP_PROBE2` | String | Attacker connectivity probe |
| `aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi` | Base64 string | Encoded exfiltration URL in payload |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Malicious PyPI package versions |
| Event Triggered Execution | T1546 | Python `.pth` startup hooks for persistence (Python .pth startup hook; no exact sub-technique) |
| Command and Scripting Interpreter: Python | T1059.006 | Python-based stealer execution |
| Unsecured Credentials: Credentials In Files | T1552.001 | Harvesting credential files (Azure CLI, .npmrc, .git-credentials, etc.) |
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | Azure IMDS token theft |
| Steal Application Access Token | T1528 | Azure OIDC, managed identity, GitHub Actions OIDC token theft |
| Data from Local System | T1005 | Collection of .env files, JSON configs |
| Process Discovery | T1057 | `/proc/*/environ` enumeration |
| System Information Discovery | T1082 | Hostname, user, cwd, argv collection |
| Obfuscated Files or Information | T1027 | Base64-encoded destination URL, zlib compression |
| Masquerading | T1036.005 | Telemetry/diagnostics naming to appear legitimate |
| Exfiltration Over Web Service | T1567 | POST to webhook[.]site |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTPS POST exfiltration |

---

## Impact Assessment

**Scope:** Any Python environment that installed `agent-framework` 1.26.1 or 1.26.2 during the ~45-minute exposure window is compromised. This includes:
- Developer workstations
- CI/CD runners (GitHub Actions, Azure DevOps pipelines, Jenkins)
- Build agents
- Production servers with the package installed
- Docker containers built during the window

**Package popularity:** ~190,000 downloads per month.

**Actual impact (per Wiz):** The free-tier webhook[.]site endpoint accepted a maximum of 50 requests. Of those: 4 from the attacker, 29 from sandboxes/vendor scans, and only 17 (representing 3 unique victims) contained actual exfiltrated credential data.

**Credential exposure:** Stolen tokens include Azure managed-identity tokens, Azure DevOps OIDC tokens, and GitHub Actions OIDC tokens that may be valid for up to 24 hours. Rotating stored secrets alone is insufficient -- freshly issued tokens must also be considered compromised.

---

## Detection & Remediation

### Immediate Actions

1. **Identify exposure:** Search lockfiles, CI logs, virtualenvs, and container images for `agent-framework==1.26.1` or `agent-framework==1.26.2`. Pin to 1.26.0 with hash verification.
2. **Check for execution:** Search `site-packages` directories for `agent_framework_meta.pth`, `af_runtime_diag.pth`, `agent_framework_meta/_telemetry.py`, and `af_runtime_diag.py`.
3. **Check egress logs:** Search proxy and DNS logs for `webhook[.]site` and specifically the UUID `d381fd80-ec62-42ad-8f5c-d1b15103c9bb`. HTTP 200 means data was accepted.
4. **Rotate credentials** on all affected hosts/runners: Azure CLI sessions, Azure DevOps PATs and service connections, npm/PyPI/NuGet/Docker/Hugging Face tokens, Git credentials, and all secrets present in the environment.
5. **Audit Azure identities:** Review sign-in and activity logs for managed identities and federated credentials reachable from affected infrastructure. Consider managed-identity and OIDC-exchanged tokens compromised for up to 24 hours.
6. **Audit GitHub Actions (v1.26.2):** For workflows with `id-token: write` that installed 1.26.2, treat OIDC tokens as exposed. Review Entra ID federated credentials that trust those repos.
7. **Isolate** affected hosts and runners.

### Long-Term Recommendations

- Enforce hash-pinned dependencies in lockfiles
- Use tools like Socket, SafeDep, or Aikido to monitor for supply chain anomalies
- Restrict webhook[.]site and similar data-forwarding services at the egress proxy. **Note:** Blanket blocking of webhook[.]site may disrupt legitimate developer and QA workflows that rely on the service for webhook testing and debugging. Recommend allowlisting by team or documented purpose rather than blanket blocking.
- Monitor for `.pth` file creation in Python `site-packages` directories as a persistence vector

---

## Detection Rules

### Sigma Rules

#### 1. Malicious Python PTH File From Agent Framework Supply Chain Attack

- **File:** `sigma-agent-framework-pth-persistence.yml`
- **ID:** `a5cea1e7-f8e7-4057-9eac-1f7f99085bba`
- **Log source:** `file_event`
- **Compile status:** PASS (sigma convert to Splunk and LogScale successful)
- **Confidence:** High
- **ATT&CK:** T1195.002, T1546

#### 2. Agent Framework Credential Stealer Module File Creation

- **File:** `sigma-agent-framework-stealer-module.yml`
- **ID:** `a6ce9e41-a4de-4369-ac47-7e787b02025e`
- **Log source:** `file_event`
- **Compile status:** PASS (sigma convert to Splunk and LogScale successful)
- **Confidence:** High
- **ATT&CK:** T1195.002, T1059.006

#### 3. Agent Framework Credential Exfiltration to Webhook.site

- **File:** `sigma-agent-framework-webhook-exfil.yml`
- **ID:** `bdd5059b-21b7-42e0-b831-be1aa570634b`
- **Log source:** `proxy`
- **Compile status:** PASS (sigma convert to Splunk and LogScale successful)
- **Confidence:** High
- **ATT&CK:** T1567

<!-- revision: dropped Sigma #4 (DNS Query to Webhook.site From Python Process) by critic — webhook.site is a widely-used legitimate developer tool; Python + webhook.site is a common developer pattern; pure FP noise -->

#### 4. Suspicious af-runtime-diagnostics User-Agent String

- **File:** `sigma-agent-framework-useragent.yml`
- **ID:** `ca8c120c-9717-41f3-bb9c-70cab6a53336`
- **Log source:** `proxy`
- **Compile status:** PASS (sigma convert to Splunk and LogScale successful)
- **Confidence:** High
- **ATT&CK:** T1071.001, T1567

#### 5. Agent Framework Stealer Execution Guard Environment Variable

- **File:** `sigma-agent-framework-env-guard.yml`
- **ID:** `b1bcb13e-76fd-4fa3-829b-031e421bbe69`
- **Log source:** `process_creation`
- **Compile status:** PASS (sigma convert to Splunk and LogScale successful)
- **Confidence:** Medium
- **ATT&CK:** T1059.006, T1546
- **Caveat:** Requires EDR telemetry that captures process environment variables (e.g., CrowdStrike); will not fire from Sysmon or standard Windows event logs.

> **Note:** `sigma check` could not complete ATT&CK tag validation due to network restrictions in the validation environment (MITRE ATT&CK endpoint unreachable). All 5 rules parse successfully and convert to both Splunk SPL and LogScale query syntax without errors.

### YARA Rules

#### 1. Supply_Chain_Agent_Framework_PTH_Hook

- **File:** `yara-agent-framework-supply-chain.yar`
- **Description:** Detects malicious `.pth` startup hook files
- **Compile status:** PASS (yarac compiled successfully)
- **Confidence:** High

#### 2. Supply_Chain_Agent_Framework_Stealer_Telemetry

- **Description:** Detects the `_telemetry.py` stealer payload (v1.26.1)
- **Compile status:** PASS
- **Confidence:** High

#### 3. Supply_Chain_Agent_Framework_Stealer_Diag

- **Description:** Detects the `af_runtime_diag.py` stealer payload (v1.26.2)
- **Compile status:** PASS
- **Confidence:** High

#### 4. Supply_Chain_Agent_Framework_Wheel_Malicious

- **Description:** Detects the malicious wheel archives
- **Compile status:** PASS
- **Confidence:** High

### Suricata Rules

| SID | Description | Compile Status | Confidence |
|-----|-------------|---------------|------------|
| 2200001 | POST to Webhook.site exfiltration UUID | PASS | High |
| 2200002 | User-Agent af-runtime-diagnostics/1 | PASS | High |
| 2200003 | User-Agent runtime-diagnostics/1 | PASS | High |
<!-- revision: dropped Suricata SID 2200004 (DNS query to webhook.site) by critic — bare DNS detection for a legitimate service with no process context; every developer querying webhook.site fires this -->

> Suricata validated with `suricata -T`: "Configuration provided was successfully loaded. Exiting."

### Snort Rules

| SID | Description | Compile Status | Confidence |
|-----|-------------|---------------|------------|
| 2100001 | POST to Webhook.site exfiltration UUID | PASS | High |
| 2100002 | User-Agent af-runtime-diagnostics/1 | PASS | High |
| 2100003 | User-Agent runtime-diagnostics/1 | PASS | High |

> Snort 2.x validated: "Snort successfully validated the configuration!"

---

## Lessons Learned

1. **Python `.pth` files are a potent persistence vector.** They execute on every interpreter startup without any import, making them ideal for supply chain attacks. Organizations should monitor `site-packages` for unexpected `.pth` files.

2. **ESRP signing credential compromise bypasses standard package integrity checks.** The attacker overcame IP-based restrictions by running from Microsoft-owned infrastructure, suggesting deep access to Microsoft's internal systems or cloud resources.

3. **Webhook[.]site as exfiltration channel limits blast radius but enables rapid operations.** The free-tier 50-request limit accidentally constrained the attack, but the attacker traded reliability for speed and operational simplicity.

4. **OIDC and managed-identity tokens cannot be rotated like stored secrets.** Organizations must audit identity activity logs and revoke sessions; simply rotating passwords and API keys is insufficient.

5. **Rapid iteration (33 minutes between versions) shows automated tooling.** The Cairn AI pentesting framework suggests AI-assisted attack development is becoming operational.

---

## Sources

- [The Hacker News - Attackers Compromise Microsoft's Agent Framework PyPI Package](https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html)
- [Aikido - Two Malicious Agent Framework Releases Hit PyPI in 33 Minutes](https://www.aikido.dev/blog/two-malicious-agent-framework-releases-hit-pypi-in-33-minutes)
- [Wiz - Malicious Version of Microsoft's Agent Framework Published to PyPI](https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi)
- [Socket - Agent Framework PyPI Package Compromised with Credential Stealer](https://socket.dev/blog/agent-framework-pypi-package-compromised-with-credential-stealer)
- [SafeDep - Microsoft Agent Framework PyPI Compromise](https://safedep.io/blog/microsoft-agent-framework-pypi-compromise)
- [Chainguard - Microsoft Agent Framework Compromised on PyPI](https://www.chainguard.dev/unchained/microsoft-agent-framework-compromised-on-pypi-november-2026)
- [Endor Labs - Agent Framework Compromised Software Supply Chain Attack](https://www.endorlabs.com/learn/agent-framework-compromised-software-supply-chain-attack)
- [OX Security - Hijacked Releases of Microsoft's Official Agent Framework](https://www.ox.security/blog/breaking-hijacked-releases-of-microsofts-official-agent-framework-steals-azure-and-ci-credentials/)
- [StepSecurity - Microsoft Agent Framework PyPI Package Compromised](https://www.stepsecurity.io/blog/microsoft-agent-framework-pypi-package-compromised)
- [PyPI - agent-framework](https://pypi.org/project/agent-framework/)
