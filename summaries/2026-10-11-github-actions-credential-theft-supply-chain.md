# Technical Analysis Report: GhostAction — Credential-Stealing GitHub Actions Supply Chain Campaign (2026-10-11)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-10-11
Version: 1.0

## Executive Summary

In October 2026, attackers behind the GhostAction campaign compromised two high-profile open-source maintainer accounts — Takashi Kitao (author of the pyxel game engine, ~18,400 stars) and Henry Wu (henrywoo, original author of Uber's athenadriver) — and used them to push malicious GitHub Actions workflows into 345 repositories across two automated bursts on October 8. The workflows, disguised as security audits, steal named Actions secrets and systematically scan both the working tree and full git history for 13 categories of credentials (AWS, AI service keys, GitHub/GitLab PATs, Google/Firebase, Slack, SendGrid, and more), then exfiltrate them via plain HTTP POST to a hardcoded C2 IP (193.32.204[.]199). This is the third major wave of GhostAction: the original September 2025 campaign hit 817 repositories and stole over 3,325 secrets; an August-September 2026 wave infected 772 repositories targeting 2,577 secrets. Socket reported that by October 7, more than 500 accounts had committed the workflow to tens of thousands of repositories. Confirmed exfiltration was observed in the `uber/athenadriver` run log, and PyPI/crates.io publishing credentials were targeted in `kitao/pyxel`. The attack bypasses code review by committing directly to default branches using stolen maintainer credentials, likely obtained from infostealer logs or credential dumps.

## Background: GitHub Actions and CI/CD Supply Chain Risk

GitHub Actions is GitHub's native CI/CD platform, where workflow files (YAML) under `.github/workflows/` define automated pipelines triggered by repository events (push, pull request, manual dispatch). Workflows can access repository secrets — encrypted environment variables configured by maintainers for deployments, API access, and publishing. A workflow committed by a trusted maintainer to the default branch inherits full trust: it runs automatically on push events without additional approval gates unless explicitly configured. This trust model makes Actions workflows a high-value injection target. When an attacker obtains a maintainer's credentials, they can commit workflows that execute on every repository the account can write to, accessing all configured secrets. The GhostAction campaign weaponizes this trust at scale, automating injection across hundreds of repositories in minutes.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-09 | Original GhostAction campaign: 817 repos, 327 users, 3,325+ secrets exfiltrated. C2: 45.139.104[.]115 |
| 2025-10 to 2026-03 | Intermittent waves using 170.39.218[.]2 and *.oast[.]fun endpoints (~325 repos) |
| 2026-08-30 | kuafuai/DevOpsGPT modified to embed XMRig miner in Docker image |
| 2026-08-31 | New GhostAction wave begins; 143 repos injected on day one. C2 shifts to 193.32.204[.]199 |
| 2026-09-02 to 09-30 | Wave escalates: 772 repos across 373 users/orgs, targeting 2,577 secrets. 499 runs execute in 32 repos, exfiltrating 26 secrets from 13 repos |
| 2026-09-04 to 09-05 | C2 IP 193.32.204[.]199 first observed in honeypot records |
| 2026-09-07 | `security-check.yml` variant appears, posting to per-injection API endpoint on port 3000 |
| 2026-10-07 | Socket observes 500+ accounts committing the workflow; `typecho-fans/plugins` injected (blocked by approval gate) |
| 2026-10-08 13:20-13:44 | Kitao account (pyxel) pushes workflow to 27 repos; attacker manually re-runs twice |
| 2026-10-08 21:10-21:26 | henrywoo account pushes workflow to 318 repos (39 source, 279 forks) in 16 minutes |
| 2026-10-08 21:25:54 | Last push: `uber/athenadriver` |
| 2026-10-08 21:26:04 | C2 acknowledges receipt of athenadriver exfiltration (4 seconds after run start) |
| 2026-10-09 | ~378 repos still carry live malicious workflow on default branch |

## Root Cause: Compromised Maintainer Credentials

Initial access was achieved by obtaining valid GitHub credentials for maintainer accounts, likely personal access tokens (PATs) leaked in infostealer logs or credential dumps. The attacker used these credentials to authenticate directly and push commits to default branches under the victim's identity, bypassing pull-request review requirements. The compromised accounts (kitao, henrywoo, xxyangyoulin) had write access to numerous repositories, including organizationally-owned ones like `uber/athenadriver`. No vulnerability in GitHub itself was exploited; the attack leveraged stolen credentials and the implicit trust given to maintainer commits.

## Technical Analysis of the Malicious Payload

### 1. Workflow Injection

The attacker commits a single YAML file to `.github/workflows/` on the default branch. Three filename variants have been observed:
- `security-audit.yml` (October 2026 wave, primary variant)
- `github_actions_security.yml` (August-September 2026 wave)
- `security-check.yml` (September 2026, per-injection endpoint variant)

Commit messages include "Add security audit workflow," "Update security audit workflow," "Add Github Actions Security workflow," and "Trigger security scan." The workflow triggers on `workflow_dispatch` (manual) and an unfiltered `push` (any branch, any tag), ensuring it executes on every subsequent push.

### 2. Credential Harvesting

The workflow contains a single shell step that performs three collection passes:

**Pass 1 — Named secrets extraction:** Before injection, the attacker parses the target repository's existing workflow files to identify configured secret names. These are templated into the malicious workflow as `${{ secrets.NAME }}` references, so GitHub resolves them at runtime. For pyxel, this captured PyPI, crates.io, and GitHub PAT publishing secrets.

**Pass 2 — Working tree scan:** Greps the checked-out source tree for 13 credential regex patterns covering AWS access keys (AKIA/ASIA prefixes), AI service keys (Anthropic `sk-ant-`, OpenAI `sk-proj-`, OpenRouter `sk-or-`), source control tokens (GitHub `ghp_`/`github_pat_`, GitLab `glpat-`), Google/Firebase/GCP API keys, Slack bot tokens, and SendGrid API keys.

**Pass 3 — Git history mining:** Runs `git log -p --all` (enabled by `fetch-depth: 0` checkout) and searches the full commit history for the same 13 patterns. This recovers secrets that were committed and later deleted — a common scenario where developers accidentally push credentials and remove them in a subsequent commit, without rotating the secret.

AWS key context is captured with surrounding lines to pair access key IDs with their corresponding secret access keys.

### 3. C2 Infrastructure

The exfiltration uses plain HTTP POST to a hardcoded IP address. No DNS resolution is involved, meaning DNS-based monitoring will not detect the connection.

| Wave | Endpoint | Protocol |
|------|----------|----------|
| October 2026 | `193.32.204[.]199:80` with `/?c=monami` (named secrets found) or `/?c=new` (history sweep only) | HTTP POST |
| September 2026 variant | `193.32.204[.]199:3000/api/workflow/receive?inj=<id>` | HTTP POST |
| October-December 2025, March 2026 | `170.39.218[.]2` | HTTP POST |
| September 2025 | `45.139.104[.]115` (via `bold-dhawan[.]45-139-104-115[.]plesk[.]page`) | HTTP POST |
| November 2025, March-April 2026 | `*.oast[.]fun` (Interactsh) | HTTP POST |

The POST body uses distinctive markers: `REPO=<owner/repo>`, `AKIA_CTX_START` / `AKIA_CTX_END` for AWS key context blocks. Each run returns a repository identifier whether or not credentials are found, giving the operator a map of reachable execution contexts.

### 4. Platform-Specific Behavior

The payload executes exclusively on GitHub-hosted `ubuntu-latest` runners. The workflow's `GITHUB_TOKEN` is scoped to `contents: read`, so privilege escalation depends on the exfiltrated secrets, not the Actions token itself. The shell script uses standard POSIX utilities (grep, curl, git) available on all runner images.

### 5. Related Activity: DevOpsGPT Cryptominer

On August 30, 2026, a commit to `kuafuai/DevOpsGPT` ("fix(subtask)") modified four files to embed an XMRig 6.21.0 cryptocurrency miner in the Docker image. The miner binary was installed as `/usr/local/bin/pyworker`, its config XOR-encrypted with key `devops2024`, and a health-check scheduler restarted it every 45 seconds. The mining pool was `pool.supportxmr[.]com:3333`. GitGuardian notes the commit used a forged author email and does not attribute the miner to the GhostAction operator with certainty.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxp://193.32.204[.]199/?c=monami`)
> - IP addresses: `[.]` replacing dots (e.g., `193.32.204[.]199`)
> - Domains: `[.]` replacing dots (e.g., `bold-dhawan[.]45-139-104-115[.]plesk[.]page`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `.github/workflows/security-audit.yml` | N/A (injected file) | October 2026 primary variant; history-mining credential stealer |
| `.github/workflows/github_actions_security.yml` | N/A (injected file) | August-September 2026 variant; named-secrets exfiltrator |
| `.github/workflows/security-check.yml` | N/A (injected file) | September 2026 per-injection-ID variant |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| ubuntu-latest runner | `.github/workflows/security-audit.yml` | Not published | Malicious workflow (October 2026 wave) |
| ubuntu-latest runner | `.github/workflows/github_actions_security.yml` | Not published | Malicious workflow (Aug-Sept 2026 wave) |
| Linux (DevOpsGPT) | `/usr/local/bin/pyworker` | Not published | XMRig 6.21.0 miner binary |
| Linux (DevOpsGPT) | `/var/run/devops.pid` | Not published | Miner PID file |
| Linux (DevOpsGPT) | `/var/log/devops.log` | Not published | Miner log file |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `193.32.204[.]199` (ports 80, 3000) | Primary C2 — credential exfiltration (Aug 2026-present) |
| IP | `170.39.218[.]2` | Legacy C2 (Oct-Dec 2025, Mar 2026) |
| IP | `45.139.104[.]115` | Legacy C2 (Sept 2025 original campaign) |
| Domain | `bold-dhawan[.]45-139-104-115[.]plesk[.]page` | Original campaign C2 hostname |
| Domain | `objective-hopper[.]45-139-104-115[.]plesk[.]page` | Original campaign C2 hostname |
| Domain | `carte-avantage[.]com` | Original campaign C2 |
| Domain pattern | `*[.]oast[.]fun` | Interactsh endpoints (Nov 2025, Mar-Apr 2026) |
| URL pattern | `hxxp://193.32.204[.]199/?c=monami` | Exfil with named secrets present |
| URL pattern | `hxxp://193.32.204[.]199/?c=new` | Exfil with history-only sweep |
| URL pattern | `hxxp://193.32.204[.]199:3000/api/workflow/receive?inj=<id>` | Per-injection endpoint variant |
| Mining pool | `pool.supportxmr[.]com:3333` | XMRig mining pool (DevOpsGPT) |

### Behavioral

- **Commit pattern:** Rapid, unsigned commits adding workflow files to default branches across many repositories in a single session (27 repos in 24 minutes, then 318 repos in 16 minutes).
- **Exfiltration body markers:** POST bodies contain `REPO=`, `AKIA_CTX_START`, and `AKIA_CTX_END` as distinctive delimiters.
- **History mining:** Workflow checks out with `fetch-depth: 0` and runs `git log -p --all` to scan deleted commits for credentials.
- **No DNS resolution:** C2 communication uses a hardcoded IP address over plain HTTP, producing no DNS query.
- **Commit messages:** "Add security audit workflow," "Update security audit workflow," "Add Github Actions Security workflow," "Trigger security scan."

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Attacker used stolen GitHub PATs to authenticate as maintainers |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Injected malicious workflows into trusted open-source repositories |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Workflow payload is a bash script using grep, git, and curl |
| T1552.001 | Unsecured Credentials: Credentials in Files | Scanned working tree and git history for credential patterns |
| T1005 | Data from Local System | Harvested credentials from working tree files and git history |
| T1041 | Exfiltration Over C2 Channel | Credentials sent via HTTP POST to hardcoded C2 IP |

## Impact Assessment

**Breadth:** Over 1,900 unique repositories infected across all waves; 373+ GitHub users/organizations affected. The October 2026 burst alone hit 345 repositories tied to two high-profile accounts, with downstream risk to all forks and mirrors. Socket reported 500+ accounts and tens of thousands of repositories by October 7.

**Depth:** Confirmed exfiltration of 26 secrets from 13 repositories in the August-September 2026 wave. The October wave targeted PyPI, crates.io, and GitHub publishing credentials for pyxel (18,400 stars), posing a risk of downstream package registry compromise. Credentials committed and deleted at any point in a repository's history are exposed.

**Stealth:** The workflow runs on every push without approval, completes in seconds (4 seconds observed for athenadriver), and uses plain HTTP to a bare IP, producing no DNS query. Only 16% of affected repositories were cleaned within a week of the August-September wave.

## Detection & Remediation

### Immediate Detection

Search your GitHub organization for the workflow files and exfiltration indicators:

```bash
# GitHub code search (scope to your org)
# Search for C2 IP in workflow files
gh api search/code -X GET -f q='"193.32.204.199" org:YOUR-ORG path:.github/workflows'

# Search for exfiltration markers
gh api search/code -X GET -f q='"AKIA_CTX_START" org:YOUR-ORG path:.github/workflows'

# Search for workflow file names
gh api search/code -X GET -f q='filename:security-audit.yml org:YOUR-ORG path:.github/workflows'
gh api search/code -X GET -f q='filename:github_actions_security.yml org:YOUR-ORG path:.github/workflows'

# Check audit log for suspicious workflow additions since Aug 31
gh api orgs/YOUR-ORG/audit-log -X GET -f phrase='action:git.push' -f after='2026-08-31'
```

Check proxy/firewall logs for outbound connections to the C2 IP:

```
dst_ip=193.32.204.199 OR dst_ip=170.39.218.2 OR dst_ip=45.139.104.115
```

### Remediation

1. **Delete the malicious workflow** from all branches in every affected repository (the workflow triggers on any push to any branch).
2. **Revoke the compromised GitHub credential** (PAT or session) that enabled injection. Rotate sessions, tokens, OAuth grants, and SSH keys; re-enroll phishing-resistant MFA.
3. **Rotate all reachable secrets:** Every secret configured in Actions for affected repos, plus every credential ever committed to any branch at any time (the history sweep captures deleted secrets).
4. **Audit workflow runs** since August 31, 2026. Treat any completed run of the malicious workflow as confirmed exfiltration.
5. **Hold releases** until clean. If PyPI, npm, crates.io, or container registry credentials were configured, assume they are exposed and audit package registries for unauthorized publishes.
6. **Check forks and mirrors** of infected repositories, especially private ones that may have inherited the workflow.
7. **For AWS:** Review CloudTrail for the exposure window and afterward for new IAM users, access keys, or activity from unusual regions.

### Long-Term Hardening

- **Require pull-request review for workflow changes** via branch protection rules on `.github/workflows/*`.
- **Require approval for workflow runs** — this was the one control that stopped exfiltration in the `typecho-fans/plugins` case.
- **Restrict runner egress** with an allowed-endpoints list (e.g., StepSecurity Harden-Runner). The payload uses a bare IP over plain HTTP, which produces no DNS query.
- **Pin actions by SHA** rather than tag references.
- **Enable GitHub secret scanning with push protection** to block accidental credential commits before they enter history.
- **Use short-lived OIDC credentials** instead of long-lived secrets for cloud access from Actions.

## Detection Rules

These detections target the GhostAction campaign's specific workflow file names, C2 IP addresses, and file-level credential-stealing patterns. PoC/advisory-specific (default altitude, strict leniency). Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; `sigma check` passes with ATT&CK tag validator excluded due to proxy network restriction (ATT&CK data endpoint 403). YARA rules compile and fire on a reconstructed positive sample.

### Sigma: GhostAction Malicious Workflow File Creation
Detects creation of workflow files matching GhostAction naming conventions (`security-audit.yml`, `github_actions_security.yml`, `security-check.yml`) under `.github/workflows/`.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 errors/0 issues (ATT&CK tag validator excluded — proxy 403 on MITRE data endpoint, not a rule defect). splunk convert exit 0: TargetFilename IN ("*.github/workflows/security-audit.yml", ...). log_scale convert exit 0. No pipeline fit for file_event generic logsource. Values are real (not defanged). -->
```yaml
title: GhostAction Malicious Workflow File Creation
id: 7a3e4c91-2b8f-4d6a-9e1c-5f0a3d7b8c2e
status: experimental
description: >
    Detects creation of GitHub Actions workflow files matching the GhostAction
    campaign naming pattern (security-audit.yml, github_actions_security.yml,
    security-check.yml), used in the October 2026 wave to steal CI/CD secrets
    and cloud credentials from over 340 repositories.
references:
    - https://www.stepsecurity.io/blog/ghostaction-returns
    - https://socket.dev/blog/ghostaction-cloud-credentials
    - https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/
    - https://thehackernews.com/2026/10/credential-stealing-github-actions.html
author: Actioner
date: 2026/10/11
tags:
    - attack.t1195.002
logsource:
    category: file_event
detection:
    selection_path:
        TargetFilename|endswith:
            - '.github/workflows/security-audit.yml'
            - '.github/workflows/github_actions_security.yml'
            - '.github/workflows/security-check.yml'
    condition: selection_path
falsepositives:
    - Legitimate security audit workflows with these exact file names
level: medium
```

### Sigma: GhostAction Network Exfiltration to C2 IP
Detects outbound connections to the active GhostAction C2 IP 193.32.204.199 on ports 80 or 3000.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 errors/0 issues. splunk convert exit 0: DestinationIp="193.32.204.199" DestinationPort IN (80, 3000). log_scale convert exit 0. Values real (not defanged). IP is a confirmed malicious endpoint per StepSecurity and Socket. -->
```yaml
title: GhostAction Network Exfiltration to C2 IP
id: 9c5a6e13-4d0b-4f8c-ba3e-7a2c5f9d0e4a
status: experimental
description: >
    Detects outbound network connections to the GhostAction C2 IP address
    193.32.204.199 on ports 80 or 3000, used for credential exfiltration
    from compromised GitHub Actions runners.
references:
    - https://www.stepsecurity.io/blog/ghostaction-returns
    - https://socket.dev/blog/ghostaction-cloud-credentials
author: Actioner
date: 2026/10/11
tags:
    - attack.t1041
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '193.32.204.199'
        DestinationPort:
            - 80
            - 3000
    condition: selection
falsepositives:
    - None expected; this is a known malicious endpoint
level: critical
```

### Sigma: GhostAction Legacy C2 Network Connection
Detects outbound connections to legacy GhostAction C2 IPs 170.39.218.2 and 45.139.104.115.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 errors/0 issues. splunk convert exit 0: DestinationIp IN ("170.39.218.2", "45.139.104.115"). log_scale convert exit 0. Values real (not defanged). Confidence medium: legacy IPs may have been reassigned. -->
```yaml
title: GhostAction Legacy C2 Network Connection
id: 2d1e3f04-5a6b-4c7d-8e9f-0a1b2c3d4e5f
status: experimental
description: >
    Detects outbound network connections to legacy GhostAction C2 endpoints
    including IP 170.39.218.2 and 45.139.104.115, used in the 2025 and
    early 2026 waves of the campaign.
references:
    - https://www.stepsecurity.io/blog/ghostaction-campaign-over-3-000-secrets-stolen-through-malicious-github-workflows
    - https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/
author: Actioner
date: 2026/10/11
tags:
    - attack.t1041
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '170.39.218.2'
            - '45.139.104.115'
    condition: selection
falsepositives:
    - IP address may have been reassigned to a benign host since the 2025 campaign
level: high
```

### Suricata: GhostAction HTTP Exfiltration to C2 IP
Detects HTTP POST traffic to 193.32.204.199 containing the GhostAction exfiltration body marker `AKIA_CTX_START`.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed in this environment. Rule follows Suricata 7 syntax with dot-notation sticky buffers. Structural review: alert http, flow established to_server, content match on destination IP and POST body marker. -->
```suricata
alert http $HOME_NET any -> 193.32.204.199 any (
    msg:"Actioner - GhostAction Credential Exfiltration to C2";
    flow:established,to_server;
    http.method; content:"POST";
    http.request_body; content:"AKIA_CTX_START"; fast_pattern;
    http.request_body; content:"REPO=";
    classtype:trojan-activity;
    reference:url,www.stepsecurity.io/blog/ghostaction-returns;
    reference:url,socket.dev/blog/ghostaction-cloud-credentials;
    metadata:author Actioner, created_at 2026-10-11;
    sid:10000001; rev:1;
)
```

### Suricata: GhostAction HTTP Exfiltration Query Parameter
Detects HTTP requests to 193.32.204.199 with the `?c=monami` query parameter used when named secrets are present.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed. Structural review: matches on destination IP and URI query parameter unique to GhostAction named-secrets exfiltration path. -->
```suricata
alert http $HOME_NET any -> 193.32.204.199 any (
    msg:"Actioner - GhostAction Exfil Query Parameter monami";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"?c=monami";
    classtype:trojan-activity;
    reference:url,www.stepsecurity.io/blog/ghostaction-returns;
    metadata:author Actioner, created_at 2026-10-11;
    sid:10000002; rev:1;
)
```

### Snort: N/A
Suricata rules cover the network detection layer for this campaign. Snort equivalents would duplicate the Suricata rules; the Suricata syntax (dot-notation sticky buffers) is preferred. A Snort deployment can adapt the Suricata rules by replacing `http.method`/`http.uri`/`http.request_body` with `http_method`/`http_uri`/`http_client_body`.

### YARA: GhostAction Malicious Workflow (October 2026)
Detects GhostAction workflow files by matching the C2 IP in combination with exfiltration body markers, query parameters, or workflow name strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on positive sample containing reconstructed workflow with C2 IP + AKIA_CTX markers + credential patterns (from published StepSecurity/Socket analysis). Quiet on negative (benign CI workflow). Positive is source-faithful, not invented. -->
```yara
rule GhostAction_Malicious_Workflow_Oct2026 : supply_chain
{
    meta:
        description = "Detects GhostAction malicious GitHub Actions workflow files used to steal CI/CD secrets and cloud credentials via exfiltration to 193.32.204.199"
        author = "Actioner"
        date = "2026-10-11"
        reference = "https://www.stepsecurity.io/blog/ghostaction-returns"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // C2 IP addresses - current and legacy
        $c2_current = "193.32.204.199" ascii
        $c2_legacy1 = "170.39.218.2" ascii
        $c2_legacy2 = "45.139.104.115" ascii

        // Exfiltration body markers unique to GhostAction
        $marker1 = "AKIA_CTX_START" ascii
        $marker2 = "AKIA_CTX_END" ascii
        $marker3 = "REPO=" ascii

        // URL query parameters used in exfiltration
        $param1 = "?c=monami" ascii
        $param2 = "?c=new" ascii
        $param3 = "?inj=" ascii

        // Workflow structure indicators
        $wf_name1 = "Security Audit" ascii
        $wf_name2 = "Github Actions Security" ascii
        $wf_name3 = "Security Check" ascii

        // Git history mining pattern
        $gitlog = "git log -p --all" ascii

        // Secret scanning patterns used by the payload
        $secret1 = "AKIA" ascii
        $secret2 = "ASIA" ascii
        $fetch_depth = "fetch-depth: 0" ascii

    condition:
        filesize < 50KB and
        (
            (any of ($c2_*) and any of ($marker*)) or
            (any of ($c2_*) and any of ($param*)) or
            (any of ($c2_*) and $gitlog and $fetch_depth) or
            (2 of ($marker*) and any of ($wf_name*)) or
            (any of ($c2_*) and any of ($wf_name*) and ($secret1 or $secret2) and $fetch_depth)
        )
}
```

### YARA: GhostAction Workflow History Mining Variant
Detects the October 2026 GhostAction variant that mines full git history for cloud and AI credentials using `git log -p --all` combined with multi-provider credential regex patterns and curl exfiltration.
**Status:** compile ✅ compiles · confidence: medium · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on positive (reconstructed workflow with git-log history mining + 3+ credential prefixes + AKIA_CTX markers + curl). Quiet on negative (standard CI build). Confidence medium not high because individual strings (curl, AKIA, fetch-depth) appear in benign contexts; the rule requires their co-occurrence with history mining and exfil markers. -->
```yara
rule GhostAction_Workflow_HistoryMining : supply_chain
{
    meta:
        description = "Detects GhostAction October 2026 variant workflow that mines full git history for cloud and AI credentials"
        author = "Actioner"
        date = "2026-10-11"
        reference = "https://socket.dev/blog/ghostaction-cloud-credentials"
        severity = "high"
        tlp = "WHITE"

    strings:
        // Workflow triggers for the malicious pattern
        $trigger1 = "workflow_dispatch" ascii

        // Full history checkout
        $checkout = "fetch-depth: 0" ascii

        // Git history search
        $gitlog = "git log -p --all" ascii

        // Credential patterns scanned by the payload
        $cred_aws = "AKIA" ascii
        $cred_anthropic = "sk-ant-" ascii
        $cred_openai = "sk-proj-" ascii
        $cred_openrouter = "sk-or-" ascii
        $cred_github_pat = "ghp_" ascii
        $cred_gitlab = "glpat-" ascii

        // Exfiltration markers
        $exfil1 = "AKIA_CTX_START" ascii
        $exfil2 = "AKIA_CTX_END" ascii
        $exfil3 = "curl" ascii

    condition:
        filesize < 50KB and
        $trigger1 and $checkout and $gitlog and
        (3 of ($cred_*)) and
        ($exfil3 and (any of ($exfil1, $exfil2)))
}
```

## Lessons Learned

1. **Maintainer account security is the CI/CD perimeter.** A compromised maintainer credential is a universal key to every repository the account can write to, and GitHub Actions gives that key immediate, automatic code execution. Phishing-resistant MFA and short-lived credentials are not optional for accounts with write access to popular repositories.

2. **Git history is a credential archive.** The GhostAction history-mining variant demonstrates that `git log -p --all` is a one-command credential dump for any secret ever committed. Secret scanning must cover full history, not just the current tree, and organizations must assume that any credential ever pushed — even if immediately reverted — is compromised.

3. **Workflow changes deserve the same review rigor as code changes.** The attack succeeds because workflow files committed to the default branch execute without review. Branch protection rules that require pull-request approval for `.github/workflows/*` are the single most effective preventive control, as demonstrated by the approval gate that stopped exfiltration in the `typecho-fans/plugins` case.

4. **Egress controls matter for CI/CD runners.** The payload exfiltrates over plain HTTP to a bare IP address, producing no DNS query. DNS-based monitoring alone is insufficient; runner egress must be controlled by an IP/endpoint allowlist.

5. **Cleanup rates are dangerously low.** Only 16% of affected repositories were cleaned within a week of the August-September wave, and 378 repositories still carried the live workflow when the October wave began. Automated scanning and remediation for workflow-layer supply chain attacks must become standard practice.

## Sources

- [The Hacker News — Credential-Stealing GitHub Actions Workflows](https://thehackernews.com/2026/10/credential-stealing-github-actions.html) — Initial news coverage of the October 2026 wave
- [StepSecurity — GhostAction Returns](https://www.stepsecurity.io/blog/ghostaction-returns) — Primary technical analysis of the October 2026 burst; timeline, IOCs, workflow variants, and detection guidance
- [StepSecurity — GhostAction Campaign: Over 3,000 Secrets Stolen](https://www.stepsecurity.io/blog/ghostaction-campaign-over-3-000-secrets-stolen-through-malicious-github-workflows) — Original September 2025 campaign disclosure
- [Socket — GhostAction: Cloud Credentials](https://socket.dev/blog/ghostaction-cloud-credentials) — Technical analysis of the October 2026 credential-harvesting variant; secret pattern categories, affected repository enumeration
- [GitGuardian — GhostAction GitHub Actions Supply Chain Attack Returns](https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/) — August-September 2026 wave analysis; scale metrics (772 repos, 2,577 secrets), DevOpsGPT miner, full timeline with legacy C2 endpoints

---
*Report generated by Actioner*
