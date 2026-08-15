# Technical Analysis Report: LiteLLM/Trivy Supply-Chain Compromise (2026-08-15)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-15
Version: 1.1 FINAL

## Executive Summary

In March 2026, the TeamPCP threat group (tracked by Google as UNC6780) executed a multi-stage supply chain attack that compromised both Aqua Security's Trivy vulnerability scanner and BerriAI's LiteLLM AI proxy framework. The attack began on March 19 when attackers force-pushed malicious commits to 76 of 77 trivy-action tags and all seven setup-trivy tags, then published a trojanized Trivy v0.69.4 binary. Five days later, on March 24, the attackers leveraged credentials exposed through the Trivy CI/CD compromise to publish malicious LiteLLM versions 1.82.7 and 1.82.8 to PyPI, which were live for approximately 40 minutes before quarantine.

Analysis of approximately 434,000 captured files by CloudSEK and SOCRadar indicates potential exposure affecting 2,100-2,500 organizations. Critically, over 95% of these organizations were exposed via the Trivy compromise before the LiteLLM packages were even published, establishing Trivy -- not LiteLLM -- as the primary attack vector. The malware harvested environment variables (including API keys for OpenAI, Anthropic, and cloud providers), SSH keys, Kubernetes tokens, database credentials, and shell history. Stolen data was exfiltrated to attacker-controlled infrastructure and, as a fallback, uploaded as release assets to public GitHub repositories created on victim accounts. CVE-2026-33634 was assigned to this vulnerability and added to CISA's Known Exploited Vulnerabilities catalog on March 26, 2026.

## Background: LiteLLM and Trivy

**LiteLLM** is a widely-used open-source Python library (published on PyPI as `litellm`) maintained by BerriAI that provides a unified interface for calling 100+ LLM APIs (OpenAI, Anthropic, Azure, etc.). It is deployed as a proxy server in production AI/ML pipelines and typically has access to API keys and cloud credentials via environment variables.

**Trivy** is Aqua Security's open-source vulnerability scanner for containers, filesystems, and IaC. It is commonly integrated into CI/CD pipelines via GitHub Actions (`trivy-action`, `setup-trivy`) and runs with access to the full CI/CD environment, including secrets and deployment credentials. Its widespread adoption in DevSecOps pipelines made it a high-value supply chain target.

Both tools are positioned at critical trust boundaries: LiteLLM proxies AI API credentials, and Trivy runs in CI/CD with access to build and deployment secrets. Compromising either provides access to an organization's most sensitive credentials.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Late February 2026 | Aqua Security performs credential rotation after initial security incident; rotation is incomplete, leaving some credentials valid |
| 2026-03-19 ~17:43 | Attackers force-push malicious commits to 76 of 77 trivy-action tags and all 7 setup-trivy tags |
| 2026-03-19 18:05 | Malicious Trivy v0.69.4 build published (commit 1885610c replaces `actions/checkout` with imposter 70379aad) |
| 2026-03-19 18:22 | Trivy v0.69.4 binary distributed via GitHub Releases, GHCR, ECR Public, Docker Hub, deb/rpm, get.trivy.dev |
| 2026-03-19 ~21:42 | Trivy v0.69.4 binary remediated (~3 hours exposure) |
| 2026-03-19 ~21:44 | setup-trivy tag compromise remediated (~4 hours exposure) |
| 2026-03-20 ~05:40 | trivy-action tag hijack remediated (~12 hours exposure) |
| 2026-03-22 15:43 | Malicious Docker Hub images v0.69.5 and v0.69.6 pushed using separately compromised credentials |
| 2026-03-23 ~01:40 | Docker Hub v0.69.5/v0.69.6 images remediated (~10 hours exposure) |
| 2026-03-24 10:39 | Malicious LiteLLM v1.82.7 and v1.82.8 published to PyPI using API tokens exposed from the Trivy CI/CD compromise |
| 2026-03-24 ~11:19 | PyPI quarantines malicious LiteLLM versions (~40 minutes exposure) |
| 2026-03-25 | Community scanning scripts published for detection |
| 2026-03-26 | CVE-2026-33634 added to CISA Known Exploited Vulnerabilities catalog |
| 2026-03-27 | LiteLLM security townhall; SHA-256 checksums for verified versions released |
| 2026-03-30 | Clean LiteLLM v1.83.0 released via new CI/CD v2 pipeline |
| 2026-07-02 | FBI releases FLASH-20260702-01 advisory warning about credential weaponization |

## Root Cause: Incomplete Credential Rotation After Initial Trivy Breach

The root cause was incomplete credential rotation by Aqua Security following a security incident in late February 2026. Attackers retained valid credentials from the initial breach and used them to re-access Aqua Security's infrastructure, enabling the March 19 compromise of Trivy's GitHub Actions (trivy-action and setup-trivy) and binary release pipeline. The exposed CI/CD environment also contained PyPI publishing API tokens for LiteLLM (a downstream dependency in the CI/CD security scanning workflow), which the attackers used five days later to publish malicious LiteLLM releases directly to PyPI, bypassing LiteLLM's official CI/CD pipeline entirely.

## Technical Analysis of the Malicious Payload

### 1. Trivy GitHub Actions Tag Hijacking (trivy-action / setup-trivy)

The attackers force-pushed 76 of 77 trivy-action version tags and all 7 setup-trivy tags to malicious commits. The malicious trivy-action injected an infostealer into `entrypoint.sh` that executed before the legitimate Trivy scan:

- Dumped Runner.Worker process memory via `/proc/<pid>/mem` to harvest in-memory secrets
- Scanned 50+ filesystem paths for credential files
- Used AES-256-CBC encryption with RSA-4096 hybrid scheme for data protection
- Exfiltrated to attacker C2 infrastructure at `scan.aquasecurtiy[.]org` (note: typosquatted "security")
- **Fallback exfiltration**: created public repositories with `tpcp-docs` prefix on victim GitHub accounts and uploaded stolen data as release assets tagged `data-<timestamp>`

### 2. Trivy v0.69.4 Binary Compromise

The malicious commit (1885610c) replaced the legitimate `actions/checkout` action with an imposter (70379aad). The composite action downloaded malware from a typosquatted domain. The build also added `--skip=validate` to goreleaser to bypass validation checks. The compromised binary was distributed across all official channels: GitHub Releases, GHCR, ECR Public, Docker Hub, deb/rpm packages, and the get.trivy.dev download site.

### 3. LiteLLM PyPI Package Poisoning (v1.82.7, v1.82.8)

Two malicious components were injected:

- **`proxy_server.py`** (both versions): Modified to include credential harvesting logic that activated on import
- **`litellm_init.pth`** (v1.82.8 only): A Python path configuration file automatically executed at Python interpreter startup. This .pth mechanism runs code regardless of whether LiteLLM is explicitly imported, bypassing `--ignore-scripts` protections

The malware harvested:
- Environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, AWS_SECRET_ACCESS_KEY, etc.)
- SSH keys and Git/Docker repository credentials
- Kubernetes service account tokens
- Database and LDAP configurations
- Shell history files and cryptocurrency wallet keys
- Cloud metadata server tokens and AWS Secrets Manager values

### 4. C2 Infrastructure

| Component | Domain/IP | Role |
|-----------|-----------|------|
| LiteLLM exfiltration | `models.litellm[.]cloud` | Primary credential exfiltration via HTTPS POST |
| Secondary C2 | `checkmarx[.]zone/raw` | Command retrieval and further instructions |
| Trivy C2 | `scan.aquasecurtiy[.]org` | Trivy payload delivery and exfiltration (typosquatted) |
| Trivy C2 IP | `45[.]148[.]10[.]212` | IP address for Trivy C2 infrastructure |

Neither `models.litellm[.]cloud` nor `checkmarx[.]zone` is affiliated with the legitimate LiteLLM project or Checkmarx security company.

### 5. Persistence Mechanisms

- **Python .pth file** (`litellm_init.pth`): Executes at Python interpreter startup without explicit import
- **Systemd service**: Creates a service masquerading as "System Telemetry Service" on Linux hosts
- **Kubernetes pod deployment**: In Kubernetes environments, deploys new pods for persistent access
- **GitHub repository fallback**: Creates `tpcp-docs` / `docs-tpcp` repositories on victim accounts for persistent data exfiltration

### 6. Anti-Forensics / Evasion Techniques

- Typosquatted domains mimicking legitimate security companies (aquasecurtiy vs aquasecurity, checkmarx)
- Bypassed goreleaser validation with `--skip=validate`
- .pth file execution bypasses Python `--ignore-scripts` protections
- AES-256-CBC + RSA-4096 hybrid encryption on exfiltrated data
- Short exposure windows (40 minutes for LiteLLM, 3-12 hours for Trivy components) to minimize detection opportunity

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm (PyPI) | 1.82.7 | Modified proxy_server.py with credential stealer |
| litellm (PyPI) | 1.82.8 | Modified proxy_server.py + litellm_init.pth startup persistence |
| trivy (binary) | 0.69.4 | Compromised build with imposter checkout action |
| trivy (Docker Hub) | 0.69.5 | Malicious image pushed directly to Docker Hub |
| trivy (Docker Hub) | 0.69.6 | Malicious image pushed directly to Docker Hub |
| trivy-action (GitHub) | Tags 0.0.1 through 0.34.2 | 76 of 77 tags force-pushed to malicious commits |
| setup-trivy (GitHub) | Tags v0.2.0 through v0.2.5 | All 7 tags force-pushed to malicious commits |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Any | `*/litellm_init.pth` | N/A (inline code) | Malicious Python startup persistence file |
| Linux/macOS | Trivy v0.69.4 Linux-64bit.tar.gz | `385d498d18a3a7c67878ca7322716f9da25683eb1a4bf9e9592da0d5f2ab09f6` | Compromised Trivy binary |
| Linux | Trivy v0.69.4 Linux-32bit.tar.gz | `0ca60dd18178d1c79d59cc06be12c540c121a4aea467484244667131aa13c311` | Compromised Trivy binary |
| macOS | Trivy v0.69.4 macOS-64bit.tar.gz | `90d61cf37355b89fae9ff84867100e1721c1876007ef1771e465ce5a721141ad` | Compromised Trivy binary |
| macOS | Trivy v0.69.4 macOS-ARM64.tar.gz | `1dc871b02cd7a1fd80babb1b8762a2fd9cc2b735d4d3759d012626de3ccc7a5b` | Compromised Trivy binary |

### Container Image Digests

| Image | Digest | Description |
|-------|--------|-------------|
| trivy:0.69.4 | `sha256:27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3` | Compromised container image |
| trivy:0.69.4 (linux/amd64) | `sha256:12c702212dee1cbec9471e9261501a3335963321fe76e60e5a715b5acd3c40a2` | Compromised platform-specific image |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `models[.]litellm[.]cloud` | LiteLLM credential exfiltration endpoint |
| Domain | `checkmarx[.]zone` | Secondary C2 for LiteLLM malware (`/raw` path for commands) |
| Domain | `scan[.]aquasecurtiy[.]org` | Trivy C2 and payload delivery (typosquatted "security") |
| IP | `45[.]148[.]10[.]212` | Trivy C2 infrastructure |

### Behavioral

- Public GitHub repositories created with `tpcp-docs` or `docs-tpcp` prefix on organizational accounts
- Release assets tagged with `data-<timestamp>` pattern containing exfiltrated credentials
- Process memory reading via `/proc/<pid>/mem` on CI runner Worker processes
- Systemd service creation with "System Telemetry Service" description
- Kubernetes pod deployment from unauthorized images

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into LiteLLM PyPI packages and Trivy GitHub Actions/binaries |
| T1199 | Trusted Relationship | Exploited trust in CI/CD security scanning tools (Trivy) to access downstream credentials (LiteLLM PyPI tokens) |
| T1078 | Valid Accounts | Used compromised PyPI API tokens from incomplete credential rotation to publish malicious packages |
| T1059.006 | Command and Scripting Interpreter: Python | Malicious Python code in proxy_server.py and litellm_init.pth |
| T1546.016 | Event Triggered Execution: Installer Packages | litellm_init.pth auto-executed by Python interpreter at startup |
| T1543.002 | Create or Modify System Process: Systemd Service | Created "System Telemetry Service" systemd unit for persistence |
| T1036.004 | Masquerading: Masquerade Task or Service | Systemd service disguised as legitimate telemetry service |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvested API keys, SSH keys, cloud credentials, and tokens from environment variables and filesystem |
| T1005 | Data from Local System | Collected environment variables, shell history, credential files, and Kubernetes tokens |
| T1003.007 | OS Credential Dumping: Proc Filesystem | Dumped Runner.Worker process memory via /proc/<pid>/mem |
| T1041 | Exfiltration Over C2 Channel | Encrypted credential exfiltration to models.litellm.cloud and scan.aquasecurtiy.org |
| T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository | Fallback exfiltration via tpcp-docs GitHub repositories and release assets |
| T1071.004 | Application Layer Protocol: DNS | DNS resolution of attacker-controlled C2 domains |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST for credential exfiltration and C2 communication |

## Impact Assessment

**Breadth:** Approximately 2,100-2,500 organizations potentially exposed based on analysis of ~434,000 captured files. Over 95% of affected entities (2,188 identified by SOCRadar) had data collection end before March 24, confirming Trivy as the primary exposure vector.

**Depth:** Critical -- the malware targeted the most sensitive classes of secrets: cloud provider credentials (AWS, GCP, Azure), AI API keys (OpenAI, Anthropic), Kubernetes tokens, SSH keys, database passwords, GitLab tokens, Slack webhooks, and GitHub Actions tokens. Confirmed high-confidence compromise of the European Commission AWS account (~91.7 GB compressed data exfiltrated per CERT-EU assessment). Mercor confirmed as an affected organization via the malicious LiteLLM versions.

**Stealth:** Moderate -- the short exposure windows (40 minutes for LiteLLM, 3-12 hours for Trivy components) limited detection opportunity but also limited the blast radius. The .pth persistence mechanism and typosquatted domains added evasion capability.

**Attribution:** TeamPCP campaign, tracked by Google Threat Intelligence as UNC6780. FBI has issued specific guidance (FLASH-20260702-01) about credential weaponization from this campaign.

## Detection & Remediation

### Immediate Detection

```bash
# Check for malicious litellm_init.pth anywhere in Python site-packages
find / -name "litellm_init.pth" -type f 2>/dev/null

# Check for tpcp-docs repositories in your GitHub organization
# (requires gh CLI authenticated to your org)
gh api /orgs/YOUR_ORG/repos --paginate -q '.[].name' | grep -i 'tpcp-docs\|docs-tpcp'

# Check pip install history for malicious LiteLLM versions
pip show litellm 2>/dev/null | grep -E "^Version: 1\.82\.(7|8)$"

# Check for Trivy v0.69.4 binaries
trivy --version 2>/dev/null | grep "0.69.4"

# Check Docker image history for compromised Trivy images
docker images --format '{{.Repository}}:{{.Tag}}' | grep -E 'trivy:(0\.69\.[456])'

# Check GitHub Actions workflow logs for trivy-action usage during exposure window
# Audit runs between 2026-03-19 and 2026-03-24

# Search for systemd service masquerading as telemetry
systemctl list-unit-files | grep -i telemetry
find /etc/systemd /run/systemd /usr/lib/systemd -name "*telemetry*" -type f 2>/dev/null

# DNS log search for C2 domains
grep -rE 'models\.litellm\.cloud|checkmarx\.zone|scan\.aquasecurtiy\.org' /var/log/dns* /var/log/syslog 2>/dev/null
```

### Remediation

1. **Immediate containment**: If any malicious version was installed, isolate affected systems from the network
2. **Credential rotation (highest priority)**: Rotate ALL secrets that were accessible during the exposure window:
   - API keys (OpenAI, Anthropic, cloud providers)
   - SSH keys
   - AWS/GCP/Azure credentials
   - Kubernetes service account tokens
   - Database passwords
   - GitLab/GitHub tokens
   - Slack webhooks
3. **Package rollback**:
   - LiteLLM: Pin to v1.82.6 or earlier, or upgrade to v1.83.0+
   - Trivy binary: Use v0.69.2 or v0.69.3
   - trivy-action: Update to v0.35.0
   - setup-trivy: Update to v0.2.6
4. **Filesystem cleanup**: Remove any `litellm_init.pth` files and the "System Telemetry Service" systemd unit
5. **GitHub audit**: Search for and remove any `tpcp-docs` or `docs-tpcp` repositories; check for unauthorized release assets
6. **Container image audit**: Verify Trivy container images by digest against known-good values
7. **Cloud API log audit**: Audit cloud provider logs (AWS CloudTrail, GCP Audit Logs, Azure Activity Log) for unauthorized activity using credentials that were accessible during the exposure window

### Long-Term Hardening

- **Pin GitHub Actions by full SHA hash**, not mutable tags
- **Pin PyPI packages** by hash (`pip install litellm==1.82.6 --hash sha256:...`)
- Use **cosign** to verify binary and container image signatures with timestamps proving pre-attack dates
- Implement **dependency lockfiles** with hash verification in CI/CD pipelines
- Monitor for anomalous PyPI package publishes via PyPI's RSS/atom feeds
- Segment CI/CD secrets so that scanning tools do not have access to deployment credentials
- Enable DNS logging and monitor for queries to newly-registered or typosquatted domains

## Detection Rules

13 detection rules (3 Sigma, 3 Snort, 5 Suricata, 2 YARA) target the specific C2 domains, malicious file artifacts, and exfiltration patterns from the TeamPCP supply chain campaign (CVE-2026-33634). All rules key on distinctive, advisory-confirmed indicators at specific altitude. Compiles does not equal fires -- verify in your pipeline with appropriate log sources.

### Sigma: DNS Query to LiteLLM/Trivy C2 Domains

Detects DNS queries to the three attacker-controlled C2 and exfiltration domains confirmed in the campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data 403 from proxy, unrelated to rule validity). sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Domains are attacker-controlled and unrelated to any legitimate service. No pipeline-mapped conversion applicable (dns_query is generic). -->
```yaml
title: DNS Query to LiteLLM/Trivy Supply Chain C2 Domains
id: 7a3e1c9b-4f2d-4e8a-b5c6-d7e9f0a1b2c3
status: experimental
description: >
    Detects DNS queries to known C2 and exfiltration domains used in the TeamPCP
    supply chain compromise (CVE-2026-33634) targeting LiteLLM PyPI packages and
    Trivy vulnerability scanner. The domain models.litellm.cloud was used for
    credential exfiltration, checkmarx.zone for secondary C2, and
    scan.aquasecurtiy.org (typosquatted) for Trivy payload delivery.
references:
    - https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html
    - https://www.securityweek.com/trivy-not-litellm-behind-the-2500-org-compromise/
    - https://github.com/advisories/GHSA-69fq-xp46-6x23
    - https://docs.litellm.ai/blog/security-update-march-2026
author: Actioner
date: 2026/08/15
tags:
    - attack.t1071.004
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
    - None expected - these are attacker-controlled domains unrelated to legitimate LiteLLM or Checkmarx infrastructure
level: critical
```

### Sigma: LiteLLM Malicious PTH File Creation

Detects creation of `litellm_init.pth`, the unique persistence file from compromised LiteLLM v1.82.8.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data 403, proxy issue). splunk exit 0; log_scale exit 0. File name is unique to the malicious package; zero benign use expected. -->
```yaml
title: LiteLLM Malicious PTH File Creation
id: 8b4f2d0c-5a3e-4f9b-c6d7-e8f0a1b2c3d4
status: experimental
description: >
    Detects creation of litellm_init.pth, a malicious Python path configuration
    file injected by compromised LiteLLM v1.82.8 (CVE-2026-33634). Python
    automatically executes .pth files at interpreter startup, enabling the
    malware to run without LiteLLM being explicitly imported.
references:
    - https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html
    - https://docs.litellm.ai/blog/security-update-march-2026
    - https://github.com/pypa/advisory-database/tree/main/vulns/litellm/PYSEC-2026-2.yaml
author: Actioner
date: 2026/08/15
tags:
    - attack.t1546.016
    - attack.t1195.002
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'litellm_init.pth'
    condition: selection
falsepositives:
    - None expected - this file is unique to the malicious LiteLLM package
level: critical
```

<!-- revision: dropped "Suspicious Systemd Service Masquerading as System Telemetry" — behavioral pattern-matching on "telemetry" in systemd unit names violates specific altitude at strict leniency; matches opentelemetry-collector.service, nvidia-telemetry.service, etc. -->

### Sigma: GitHub Proxy Traffic Matching TeamPCP Exfiltration Pattern

Detects proxy traffic to GitHub containing `tpcp-docs` or `docs-tpcp` repository paths used as a fallback exfiltration channel.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk exit 0; log_scale exit 0. The tpcp-docs string is a campaign-specific artifact confirmed by FBI FLASH-20260702-01. Extremely unlikely in benign traffic. -->
<!-- revision: changed cs-uri to c-uri per Sigma proxy taxonomy for portable backend conversion -->
```yaml
title: GitHub Repository Creation Matching TeamPCP Exfiltration Pattern
id: 0d6b4f2e-7c5a-4b1d-e8f9-a0b1c2d3e4f5
status: experimental
description: >
    Detects creation of or interaction with GitHub repositories matching the
    tpcp-docs naming pattern used by the TeamPCP campaign (CVE-2026-33634) as
    a fallback data exfiltration channel. Stolen credentials were uploaded as
    release assets tagged data-<timestamp> to public repositories with
    tpcp-docs or docs-tpcp prefixed names on victim accounts.
references:
    - https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html
    - https://github.com/advisories/GHSA-69fq-xp46-6x23
author: Actioner
date: 2026/08/15
tags:
    - attack.t1567.001
    - attack.t1041
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - 'tpcp-docs'
            - 'docs-tpcp'
        cs-host: 'github.com'
    condition: selection
falsepositives:
    - Legitimate repositories with tpcp-docs in the name are extremely unlikely
level: critical
```

### Snort: DNS Queries to TeamPCP C2 Domains

Detects DNS queries for the three campaign C2 domains via DNS wire-format label-length encoding.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c (patched config) -T exit 0. Rules use label-length-encoded DNS wire format for accurate matching. Snort 2.9 validated. SIDs 2100101-2100103. -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to LiteLLM Exfil Domain models.litellm.cloud"; flow:to_server; content:"|06|models|07|litellm|05|cloud|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html; reference:cve,2026-33634; sid:2100101; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to TeamPCP C2 Domain scan.aquasecurtiy.org"; flow:to_server; content:"|04|scan|0c|aquasecurtiy|03|org|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,github.com/advisories/GHSA-69fq-xp46-6x23; reference:cve,2026-33634; sid:2100102; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to TeamPCP C2 Domain checkmarx.zone"; flow:to_server; content:"|09|checkmarx|04|zone|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,docs.litellm.ai/blog/security-update-march-2026; reference:cve,2026-33634; sid:2100103; rev:1;)
```

### Suricata: DNS and TLS Detection for TeamPCP C2 Infrastructure

Detects DNS queries and TLS SNI connections to campaign C2 domains, plus HTTP requests to the secondary C2 command endpoint.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Suricata 7.0.3. Removed redundant nocase from http.host (already normalized to lowercase per W: detect-http-host warning). SIDs 2200101-2200105. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to LiteLLM Exfil Domain models.litellm.cloud"; flow:to_server; dns.query; content:"models.litellm.cloud"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-15; sid:2200101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to TeamPCP Trivy C2 Domain scan.aquasecurtiy.org"; flow:to_server; dns.query; content:"scan.aquasecurtiy.org"; nocase; fast_pattern; classtype:trojan-activity; reference:url,github.com/advisories/GHSA-69fq-xp46-6x23; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-15; sid:2200102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to TeamPCP Secondary C2 checkmarx.zone"; flow:to_server; dns.query; content:"checkmarx.zone"; nocase; fast_pattern; classtype:trojan-activity; reference:url,docs.litellm.ai/blog/security-update-march-2026; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-15; sid:2200103; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to LiteLLM Exfil Domain models.litellm.cloud"; flow:established,to_server; tls.sni; content:"models.litellm.cloud"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-15; sid:2200104; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to TeamPCP Secondary C2 checkmarx.zone/raw"; flow:established,to_server; http.host; content:"checkmarx.zone"; fast_pattern; http.uri; content:"/raw"; startswith; classtype:trojan-activity; reference:url,docs.litellm.ai/blog/security-update-march-2026; reference:cve,2026-33634; metadata:author Actioner, created_at 2026-08-15; sid:2200105; rev:1;)
```

### YARA: TeamPCP LiteLLM PTH Loader and Trivy Infostealer

Detects the malicious litellm_init.pth persistence file and the Trivy infostealer payload by campaign-specific strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: SupplyChain_TeamPCP_LiteLLM_PTH_Loader fired on pos_pth.txt (contains litellm_init + models.litellm.cloud from advisory), quiet on neg_pth.txt (benign litellm usage). Strings sourced from GHSA-69fq-xp46-6x23 and PYSEC-2026-2. -->
<!-- revision: fixed operator precedence in SupplyChain_TeamPCP_LiteLLM_PTH_Loader condition — added explicit parens so filesize constraint applies to both branches -->
```yara
rule SupplyChain_TeamPCP_LiteLLM_PTH_Loader
{
    meta:
        description = "Detects the malicious litellm_init.pth file used for Python startup persistence in the TeamPCP supply chain attack (CVE-2026-33634)"
        author = "Actioner"
        date = "2026-08-15"
        reference = "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth_name = "litellm_init" ascii
        $c2_1 = "models.litellm.cloud" ascii wide
        $c2_2 = "checkmarx.zone" ascii wide
        $c2_3 = "scan.aquasecurtiy.org" ascii wide
        $env_1 = "OPENAI_API_KEY" ascii
        $env_2 = "ANTHROPIC_API_KEY" ascii
        $env_3 = "AWS_SECRET_ACCESS_KEY" ascii

    condition:
        filesize < 500KB and
        (($pth_name and 1 of ($c2_*)) or
        (2 of ($c2_*) and 1 of ($env_*)))
}

rule SupplyChain_TeamPCP_Trivy_Infostealer
{
    meta:
        description = "Detects the TeamPCP infostealer payload injected into compromised Trivy GitHub Actions (CVE-2026-33634)"
        author = "Actioner"
        date = "2026-08-15"
        reference = "https://github.com/advisories/GHSA-69fq-xp46-6x23"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $c2 = "scan.aquasecurtiy.org" ascii wide
        $repo_1 = "tpcp-docs" ascii
        $repo_2 = "docs-tpcp" ascii
        $proc_mem = "/proc/" ascii
        $data_tag = "data-" ascii
        $skip_validate = "--skip=validate" ascii

    condition:
        filesize < 5MB and
        ($c2 or (1 of ($repo_*) and $data_tag)) and
        ($proc_mem or $skip_validate)
}
```

## Lessons Learned

1. **Incomplete credential rotation is as dangerous as no rotation.** The entire attack chain originated from Aqua Security's incomplete credential rotation in late February 2026. Partial remediation created a false sense of security while leaving attackers with valid access.

2. **CI/CD security tools are high-value supply chain targets.** Trivy, as a vulnerability scanner, runs in nearly every CI/CD pipeline with access to the full environment. Compromising the security tool itself is particularly insidious because it operates in a position of elevated trust.

3. **Mutable Git tags are an anti-pattern for security.** The force-push to 76 trivy-action tags was possible because Git tags are mutable by default. Organizations must pin GitHub Actions to full SHA commit hashes, not version tags.

4. **Python .pth files bypass standard package safety controls.** The `litellm_init.pth` mechanism executes code at interpreter startup without any explicit import, bypassing `--ignore-scripts` and similar protections. Python environments should audit .pth files in site-packages directories.

5. **Supply chain attacks cascade across trust boundaries.** The Trivy compromise led to the LiteLLM compromise, which then exposed secrets for thousands of downstream organizations. A single point of failure in the security scanning infrastructure propagated across the entire software supply chain.

## Sources

- [The Hacker News - Malicious LiteLLM Releases Tied to Trivy](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html) — Primary reporting on the connection between Trivy and LiteLLM compromises, exposure statistics from CloudSEK
- [SecurityWeek - Trivy, Not LiteLLM, Behind the 2,500-Org Compromise](https://www.securityweek.com/trivy-not-litellm-behind-the-2500-org-compromise/) — Analysis confirming Trivy as root cause, SOCRadar exposure data showing 95% pre-LiteLLM exposure
- [GitHub Advisory GHSA-69fq-xp46-6x23](https://github.com/advisories/GHSA-69fq-xp46-6x23) — Aqua Security advisory with CVE-2026-33634 details, full IOC list, binary hashes, container digests, and remediation guidance
- [LiteLLM Security Update: March 2026](https://docs.litellm.ai/blog/security-update-march-2026) — BerriAI official advisory with malicious file details, C2 domains, verified clean version hashes, and CI/CD v2 pipeline migration
- [PyPA Advisory Database PYSEC-2026-2](https://github.com/pypa/advisory-database/tree/main/vulns/litellm/PYSEC-2026-2.yaml) — PyPI ecosystem advisory confirming malware capabilities, persistence mechanisms, and affected versions
- [NVD CVE-2026-33634](https://nvd.nist.gov/vuln/detail/CVE-2026-33634) — National Vulnerability Database entry (CVSS 9.4 Critical, EPSS 59.164%)

---
*Report generated by Actioner*
