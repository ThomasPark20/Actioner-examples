# Technical Analysis Report: GhostAction GitHub Actions Supply Chain Attack (2026-10-12)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-12
Version: 1.0-DRAFT

## Executive Summary

The GhostAction campaign is an ongoing software supply-chain attack in which threat actors use stolen GitHub maintainer credentials to inject malicious GitHub Actions workflows into public repositories. First observed in September 2025, the campaign escalated significantly in October 2026 when two high-profile maintainer accounts -- `kitao` (author of the pyxel game engine, 18,400 stars) and `henrywoo` (original author of Uber's athenadriver) -- were compromised and used to push credential-stealing workflows into 345+ repositories within minutes. Socket subsequently identified more than 500 GitHub accounts committing the workflow to tens of thousands of repositories since October 7, 2026. The malicious workflow files, disguised as "Security Audit" or "Github Actions Security," harvest CI/CD secrets, scan working trees and full git histories for credential patterns (AWS keys, AI provider API keys, GitHub/GitLab PATs, cloud and SaaS tokens), and exfiltrate them via plain HTTP POST to the hardcoded C2 IP `193.32.204[.]199`. GitGuardian's earlier analysis of the August-September 2026 wave documented 772 repositories affected across 373 users/organizations, with 2,577 secrets targeted and confirmed exfiltration of 26 secrets from 13 repositories.

## Background: GitHub Actions CI/CD

GitHub Actions is GitHub's built-in CI/CD platform that executes workflows defined in YAML files under `.github/workflows/`. Workflows run on GitHub-hosted or self-hosted runners with access to repository secrets configured by maintainers. A contributor with write access to a repository's default branch can add or modify workflow files without pull request review unless branch protection rules are explicitly configured. This architectural trust model makes workflow injection a high-impact attack vector: a single compromised maintainer account can silently deploy credential-harvesting code across every repository the account can write to, including organization-owned repositories.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-09 | GhostAction first observed; 817 repositories across 327 users affected; 3,325 secrets exfiltrated (per GitGuardian) |
| 2026-08-30 | `kuafuai/DevOpsGPT` repository tampered to embed XMRig miner in Docker image |
| 2026-08-31 | New wave begins; ~143 repositories receive malicious workflow |
| 2026-09-02 to 2026-09-05 | Peak injection period; ~400 repositories, 294 on Sep 5 alone |
| 2026-09-07 | `security-check.yml` variant appears in 7 repositories |
| 2026-09-15 | ~103 additional repositories injected |
| 2026-09-30 | GitGuardian reports 772 repos, 373 users/orgs, 2,577 secrets targeted; only 124 repos (16%) cleaned |
| 2026-10-07 | Socket begins tracking new burst; 500+ accounts identified |
| 2026-10-08 13:20-13:44 UTC | `kitao` account pushes workflow to 27 repositories including `kitao/pyxel` |
| 2026-10-08 21:10-21:26 UTC | `henrywoo` account pushes workflow to 318 repositories (39 source, 279 forks) in 16-minute window |
| 2026-10-09 | The Hacker News, Socket, and StepSecurity publish advisories; campaign ongoing |

## Root Cause: Stolen Maintainer Credentials

The attacker obtained GitHub credentials (likely leaked personal access tokens from infostealer logs or credential dumps) for legitimate open-source maintainers. These credentials enabled direct commits to default branches under the victims' own identities, bypassing pull request review. The commits were unsigned, a potential detection signal. StepSecurity notes the attacker performed reconnaissance of existing workflow files to identify which secrets each repository had configured, then templated those secret names into the injected payload before committing.

## Technical Analysis of the Malicious Payload

### 1. Workflow Injection

The attacker commits a single YAML workflow file to `.github/workflows/` on the default branch. Three filename variants have been observed:

- `security-audit.yml` (display name: "Security Audit")
- `github_actions_security.yml` (display name: "Github Actions Security")
- `security-check.yml` (display name: "Security Check")

Commit messages include `Add security audit workflow`, `Update security audit workflow`, `Add Github Actions Security workflow`, and `Trigger security scan`. The workflow triggers on both `workflow_dispatch` (enabling manual execution) and an unfiltered `push` event (any branch, any tag), ensuring it runs on the next push to any branch.

### 2. Credential Harvesting (Variant B -- History Mining)

The checkout step uses `actions/checkout@v4` with `fetch-depth: 0` to clone the entire repository history. A single "Audit" run step then executes four collection stages:

1. **Named secrets exfiltration:** Conditionally appends the repository's Actions secrets (identified during reconnaissance) into the output buffer. Repositories with named secrets use the URL marker `?c=monami`; those without use `?c=new`.
2. **Working tree scan:** Runs `grep -rEiho` with `--exclude-dir=.git` across the working tree, matching 13 credential patterns including AWS access keys, AI provider keys, GitHub/GitLab PATs, Google/Firebase keys, Slack tokens, and SendGrid keys.
3. **Git history scan:** Runs `git log -p --all` (capped at 200,000 lines) piped through grep with the same 13 patterns (limited to 300 matches), exposing credentials that were committed and later deleted.
4. **AWS key pairing:** Extracts +/-2 lines of context around `AKIA`/`ASIA` hits, delimited by `AKIA_CTX_START` and `AKIA_CTX_END` markers, to pair AWS access key IDs with their corresponding secret access keys.

### 3. C2 Infrastructure

All collected data is sent in a single HTTP POST via `curl -s -m 20 -X POST --data-binary` to the hardcoded endpoint over plain HTTP. The body includes the `REPO=$GITHUB_REPOSITORY` identifier so the operator can correlate exfiltrated credentials with their source repositories. Failures are silenced with `|| true`.

**Current C2:** `193.32.204[.]199` (ports 80 and 3000)
- Port 80: `hxxp://193.32.204[.]199/?c=monami` or `hxxp://193.32.204[.]199/?c=new`
- Port 3000: `hxxp://193.32.204[.]199:3000/api/workflow/receive?inj=<id>`

**Legacy C2 endpoints (September 2025 through April 2026):**
- `45.139.104[.]115` (via Plesk-hosted domains)
- `170.39.218[.]2`
- `*.oast[.]fun` (Interactsh)
- `bold-dhawan.45-139-104-115[.]plesk[.]page`
- `carte-avantage[.]com`
- `objective-hopper.45-139-104-115[.]plesk[.]page`

### 4. Execution Evidence

- `uber/athenadriver` (run 37846728441): exfiltration confirmed. The `OK` HTTP response from the C2 appeared in logs four seconds after the run started. The workflow's `GITHUB_TOKEN` had `contents: read` permissions, so the workflow could not push code directly, but any stolen registry or cloud tokens enable lateral movement.
- `kitao/pyxel`: five workflow runs observed, including two manual `workflow_dispatch` triggers from the compromised session, indicating hands-on operator activity.
- `typecho-fans/plugins`: exfiltration blocked because the repository required approval for workflow runs (`action_required` status).

### 5. Anti-Forensics / Evasion Techniques

- Workflows were committed under the victim maintainer's own identity, making the commits appear legitimate in git history.
- Workflow display names ("Security Audit", "Github Actions Security") mimic legitimate security tooling.
- The `|| true` suffix on the curl command suppresses error output.
- The cache-busting timestamp written to `GITHUB_ENV` as a "Prepare Cache Busting" step disguises the workflow's purpose.
- Every run returns the `REPO=` identifier even when no credentials are found, providing the operator with a map of reachable execution contexts for future targeting.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxp://` replaces `http://`
> - IP addresses: `[.]` replacing dots (e.g., `193.32.204[.]199`)
> - Domains: `[.]` replacing dots

### Workflow Files

| Filename | Display Name | Commit Message |
|----------|-------------|----------------|
| `security-audit.yml` | Security Audit | Add security audit workflow |
| `github_actions_security.yml` | Github Actions Security | Add Github Actions Security workflow |
| `security-check.yml` | Security Check | Add security check workflow |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `193.32.204[.]199` (port 80, 3000) | Active C2 -- credential exfiltration endpoint |
| IP | `45.139.104[.]115` | Legacy C2 (Sep 2025) |
| IP | `170.39.218[.]2` | Legacy C2 (Oct 2025 - Apr 2026) |
| Domain | `bold-dhawan.45-139-104-115[.]plesk[.]page` | Legacy C2 domain |
| Domain | `carte-avantage[.]com` | Legacy C2 domain |
| Domain | `objective-hopper.45-139-104-115[.]plesk[.]page` | Legacy C2 domain |
| Domain | `*[.]oast[.]fun` | Interactsh -- used for testing/validation |
| URL | `hxxp://193.32.204[.]199/?c=monami` | Exfil endpoint (repos with named secrets) |
| URL | `hxxp://193.32.204[.]199/?c=new` | Exfil endpoint (repos without named secrets) |
| URL | `hxxp://193.32.204[.]199:3000/api/workflow/receive?inj=<id>` | Per-injection tracking endpoint |

### Behavioral

- Request body contains `REPO=` prefix followed by the GitHub repository identifier
- Request body delimiters `AKIA_CTX_START` and `AKIA_CTX_END` around AWS key context
- URL parameter `?c=monami` indicates named-secret exfiltration variant
- Checkout with `fetch-depth: 0` combined with `git log -p --all` in a workflow step
- Rapid unsigned commits adding workflow files across multiple repositories from a single account

### Compromised Accounts (Injection Vectors, Not Attacker-Owned)

| Account | Role | Repositories Affected |
|---------|------|----------------------|
| `kitao` | Author of pyxel (18,400 stars) | 27 repositories |
| `henrywoo` | Original author of Uber's athenadriver | 318 repositories (39 source, 279 forks) |
| `xxyangyoulin` | Earlier campaign participant | Unknown count |

### GitHub Search Queries (Hunting)

- `"AKIA_CTX_START" path:.github/workflows`
- `"c=monami"`
- `"193.32.204.199" path:.github/workflows`
- `org:YOUR-ORG "193.32.204.199" path:.github/workflows`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious workflow injected into repositories via compromised maintainer accounts |
| T1078.004 | Valid Accounts: Cloud Accounts | Stolen GitHub PATs used to authenticate and push commits as legitimate maintainers |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Bash script within the workflow step executes grep and curl commands on Ubuntu runners |
| T1552.001 | Unsecured Credentials: Credentials In Files | Working tree scanned for hardcoded credentials using regex patterns |
| T1552.004 | Unsecured Credentials: Private Keys | SSH keys and private key material targeted in credential sweep |
| T1119 | Automated Collection | Automated grep of 13 credential patterns across working tree and full git history |
| T1048.003 | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | Data exfiltrated via plain HTTP POST to hardcoded IP address |

## Impact Assessment

- **Breadth:** 345+ repositories in the October 8 wave alone; 772 in the August-September wave; tens of thousands of repositories since October 7 across 500+ accounts (per Socket).
- **Depth:** High-impact repositories including `kitao/pyxel` (published to PyPI and crates.io), `henrywoo/pyllama` (2,777 stars), and organization-owned repositories like `uber/athenadriver`. Stolen publishing credentials could enable downstream package supply chain attacks.
- **Stealth:** Workflow names mimic legitimate security tooling; commits appear under trusted maintainer identities; the `|| true` suppresses errors.
- **Confirmed impact:** GitGuardian confirmed exfiltration of 26 secrets from 13 repositories in the August-September wave. The September 2025 wave exfiltrated 3,325 secrets. No malicious package releases have been observed as of October 9, 2026.
- **Cleanup rate:** Only 16% (124 of 772) of affected repositories showed effective cleanup as of October 5, 2026.

## Detection & Remediation

### Immediate Detection

Search for the malicious workflow files in your repositories:

```bash
# Search across all org repositories for the C2 IP
gh api search/code -q '.items[] | "\(.repository.full_name): \(.path)"' \
  --method GET -f q='org:YOUR-ORG "193.32.204.199" path:.github/workflows'

# Search for AKIA context markers
gh api search/code -q '.items[] | "\(.repository.full_name): \(.path)"' \
  --method GET -f q='org:YOUR-ORG "AKIA_CTX_START" path:.github/workflows'

# Check for the specific workflow filenames
find /path/to/repos -path '*/.github/workflows/security-audit.yml' -o \
  -path '*/.github/workflows/github_actions_security.yml' -o \
  -path '*/.github/workflows/security-check.yml'

# Hunt for C2 IP in network/egress logs
grep -r '193.32.204.199' /var/log/
```

### Remediation

1. **Contain:** Block egress to `193.32.204[.]199` (ports 80 and 3000), `45.139.104[.]115`, and `170.39.218[.]2` at the network perimeter and on self-hosted runners.
2. **Eradicate:** Delete the malicious workflow file from all branches (not just the default branch). Revert the injection commit.
3. **Rotate:** Revoke the compromised GitHub credential (PAT/session). Rotate ALL Actions secrets. Rotate every credential ever committed to any branch, since the `git log -p --all` sweep reaches deleted secrets.
4. **Verify:** Audit workflow runs since August 31, 2026 for the indicators above. Treat any completed run as confirmed exfiltration.
5. **Package audit:** Review PyPI, npm, crates.io, and container registry release history against your own build outputs. Do not cut new releases until the repository is clean.
6. **Forks:** Check forks of infected repositories for `.github/workflows/security-audit.yml` before enabling Actions.

### Long-Term Hardening

- Require pull request review for changes to `.github/workflows/` via branch protection rules and CODEOWNERS.
- Enable GitHub secret scanning with push protection.
- Require approval for workflow runs from outside collaborators.
- Use egress allowlists (e.g., StepSecurity Harden-Runner) on CI/CD runners to block unauthorized outbound connections.
- Enforce phishing-resistant MFA (security keys) on all maintainer accounts.
- Pin GitHub Actions to specific commit SHAs rather than mutable tags.

## Detection Rules

Three Sigma rules target process-level indicators on CI/CD runners, one YARA rule detects the malicious workflow files on disk, and network rules (Snort/Suricata) target HTTP exfiltration to the known C2 IP. The Sigma rules require process creation logging (e.g., Sysmon or auditd) on runners, which is not standard on GitHub-hosted runners; they are most applicable to self-hosted runner environments. The network rules require inline inspection of HTTP traffic from runner egress.

### Sigma: GhostAction Credential Exfiltration via Curl to Known C2 IP

Detects curl POST commands directed at the GhostAction C2 IP, the primary exfiltration mechanism observed across all campaign variants.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0. sigma convert --without-pipeline -t log_scale: exit 0. sigma check failed due to proxy blocking MITRE ATT&CK data fetch (HTTP 403), not a rule syntax issue. Tags attack.t1048.003 and attack.t1059.004 are valid technique-level tags. -->

compile: **sigma convert exit 0** | confidence: **high**

```yaml
title: GhostAction Credential Exfiltration via Curl to Known C2 IP
id: ea8d50d2-871c-4d3d-b3c9-8a09aeb34b79
status: experimental
description: >
    Detects curl commands posting data to the GhostAction C2 IP address
    193.32.204.199, as used by the malicious GitHub Actions workflow to
    exfiltrate stolen credentials from CI/CD runners.
references:
    - https://www.stepsecurity.io/blog/ghostaction-returns
    - https://socket.dev/blog/ghostaction-cloud-credentials
    - https://thehackernews.com/2026/10/credential-stealing-github-actions.html
author: Actioner
date: 2026-10-12
tags:
    - attack.t1048.003
    - attack.t1059.004
logsource:
    category: process_creation
detection:
    selection_curl:
        Image|endswith: '/curl'
        CommandLine|contains|all:
            - 'POST'
            - '193.32.204.199'
    condition: selection_curl
falsepositives:
    - Legitimate services communicating with this IP address (unlikely)
level: high
```

### Sigma: GhostAction Workflow Body Markers in Process Execution

Detects distinctive string markers (`AKIA_CTX_START`, `AKIA_CTX_END`, `c=monami`) unique to the GhostAction payload appearing in process command lines.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0. sigma convert --without-pipeline -t log_scale: exit 0. sigma check blocked by proxy (HTTP 403 to MITRE ATT&CK). Tags attack.t1048.003 and attack.t1119 are valid. -->

compile: **sigma convert exit 0** | confidence: **high**

```yaml
title: GhostAction Workflow Body Markers in Process Execution
id: f3b645fc-992a-4cf7-b5a1-0449a12f210c
status: experimental
description: >
    Detects process execution containing distinctive body markers used by
    the GhostAction credential-stealing workflow, including the AKIA context
    delimiters and monami campaign identifier.
references:
    - https://www.stepsecurity.io/blog/ghostaction-returns
    - https://socket.dev/blog/ghostaction-cloud-credentials
author: Actioner
date: 2026-10-12
tags:
    - attack.t1048.003
    - attack.t1119
logsource:
    category: process_creation
detection:
    selection_markers:
        CommandLine|contains:
            - 'AKIA_CTX_START'
            - 'AKIA_CTX_END'
            - 'c=monami'
    condition: selection_markers
falsepositives:
    - Security research or testing environments reproducing the attack
level: high
```

### Sigma: Suspicious Git History Credential Sweep in CI Environment

Detects behavioral patterns consistent with automated git history mining for credentials, as performed by the GhostAction Variant B payload.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0. sigma convert --without-pipeline -t log_scale: exit 0. sigma check blocked by proxy (HTTP 403 to MITRE ATT&CK). Tags attack.t1552.001 and attack.t1119 are valid. Level medium due to potential overlap with legitimate secret scanning tools. -->

compile: **sigma convert exit 0** | confidence: **medium**

```yaml
title: Suspicious Git History Credential Sweep in CI Environment
id: 3661cb2a-8d4a-4d18-bc51-ef73c8185c3f
status: experimental
description: >
    Detects a process piping full git history output through grep for
    credential patterns, a behavior characteristic of the GhostAction
    workflow that mines entire git histories for leaked secrets.
references:
    - https://www.stepsecurity.io/blog/ghostaction-returns
    - https://socket.dev/blog/ghostaction-cloud-credentials
author: Actioner
date: 2026-10-12
tags:
    - attack.t1552.001
    - attack.t1119
logsource:
    category: process_creation
detection:
    selection_git_log:
        CommandLine|contains|all:
            - 'git log'
            - '-p'
            - '--all'
    selection_grep_creds:
        CommandLine|contains:
            - 'AKIA'
            - 'sk-ant-'
            - 'ghp_'
            - 'glpat-'
            - 'sk-proj-'
    condition: selection_git_log or selection_grep_creds
falsepositives:
    - Legitimate secret scanning tools such as truffleHog or git-secrets
    - Developer searches for key patterns during audits
level: medium
```

### YARA: GhostAction Malicious Workflow File Detection

Detects GhostAction workflow files on disk by matching the C2 IP, exfiltration markers, and structural patterns unique to the campaign.

<!-- audit: yarac yara_ghostaction_workflow.yar /dev/null: exit 0. Rule targets YAML workflow files under 50KB. Two detection paths: (1) C2 IP + body markers, (2) fetch-depth:0 + git-log sweep + workflow name + curl. No PE header requirement since targets are YAML text files. -->

compile: **yarac exit 0** | confidence: **high**

```yara
rule SupplyChain_GhostAction_Malicious_Workflow
{
    meta:
        description = "Detects GhostAction malicious GitHub Actions workflow files that steal credentials from CI/CD runners and git history"
        author = "Actioner"
        date = "2026-10-12"
        reference = "https://www.stepsecurity.io/blog/ghostaction-returns"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $c2_ip = "193.32.204.199" ascii
        $marker1 = "AKIA_CTX_START" ascii
        $marker2 = "AKIA_CTX_END" ascii
        $param_monami = "c=monami" ascii
        $param_new = "c=new" ascii
        $fetch_depth = "fetch-depth: 0" ascii
        $git_sweep = "git log -p --all" ascii
        $wf_name1 = "Security Audit" ascii
        $wf_name2 = "Github Actions Security" ascii
        $step_name = "Prepare Cache Busting" ascii
        $job_name = "send-secrets" ascii
        $curl_post = "curl -s" ascii
        $data_binary = "--data-binary" ascii

    condition:
        filesize < 50KB and
        (
            (
                $c2_ip and
                2 of ($marker1, $marker2, $param_monami, $param_new)
            ) or
            (
                $fetch_depth and
                $git_sweep and
                1 of ($wf_name1, $wf_name2, $step_name, $job_name) and
                ($curl_post or $data_binary)
            )
        )
}
```

### Snort: GhostAction HTTP POST Exfiltration

Detects HTTP POST requests to the GhostAction C2 IP containing credential exfiltration body markers.

<!-- audit: snort not available in environment. Structural check: correct http service, flow established/to_server, http_method content "POST", http_client_body with content match, SIDs in 2100000+ range, semicolons terminate all options. -->

compile: **uncompiled (structural check only)** | confidence: **high**

```snort
alert http $HOME_NET any -> 193.32.204.199 any (msg:"Actioner - GhostAction HTTP POST Credential Exfiltration to C2 IP"; flow:established, to_server; http_method; content:"POST"; http_client_body; content:"REPO=", fast_pattern; classtype:trojan-activity; reference:url,www.stepsecurity.io/blog/ghostaction-returns; metadata:author Actioner, created 2026-10-12; sid:2100101; rev:1;)

alert http $HOME_NET any -> 193.32.204.199 any (msg:"Actioner - GhostAction AWS Key Context Exfiltration Marker"; flow:established, to_server; http_method; content:"POST"; http_client_body; content:"AKIA_CTX_START", fast_pattern; classtype:trojan-activity; reference:url,www.stepsecurity.io/blog/ghostaction-returns; metadata:author Actioner, created 2026-10-12; sid:2100102; rev:1;)
```

### Suricata: GhostAction HTTP POST Exfiltration

Detects HTTP POST requests to the GhostAction C2 IP containing credential exfiltration body markers and the monami campaign parameter.

<!-- audit: suricata not available in environment. Structural check: correct http protocol, flow established,to_server, dot-notation sticky buffers (http.method, http.request_body, http.uri), semicolons terminate all options, SIDs in 2200000+ range. -->

compile: **uncompiled (structural check only)** | confidence: **high**

```suricata
alert http $HOME_NET any -> 193.32.204.199 any (msg:"Actioner - GhostAction HTTP POST Credential Exfiltration to C2 IP"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"REPO="; fast_pattern; classtype:trojan-activity; reference:url,www.stepsecurity.io/blog/ghostaction-returns; metadata:author Actioner, created_at 2026-10-12; sid:2200101; rev:1;)

alert http $HOME_NET any -> 193.32.204.199 any (msg:"Actioner - GhostAction AWS Key Context Exfiltration Marker"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"AKIA_CTX_START"; fast_pattern; classtype:trojan-activity; reference:url,www.stepsecurity.io/blog/ghostaction-returns; metadata:author Actioner, created_at 2026-10-12; sid:2200102; rev:1;)

alert http $HOME_NET any -> 193.32.204.199 any (msg:"Actioner - GhostAction Monami Campaign Parameter in HTTP Request"; flow:established,to_server; http.uri; content:"c=monami"; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/ghostaction-cloud-credentials; metadata:author Actioner, created_at 2026-10-12; sid:2200103; rev:1;)
```

## Lessons Learned

1. **CI/CD credential trust model is fragile.** A single compromised maintainer PAT grants full workflow injection access to every repository that account can write to, including organization-owned repositories. Branch protection rules and CODEOWNERS for `.github/workflows/` are not universally enforced, leaving most open-source repositories exposed.

2. **Deleted secrets are not gone.** The GhostAction Variant B payload's use of `fetch-depth: 0` and `git log -p --all` to scan full git history demonstrates that credentials committed at any point in a repository's lifecycle remain extractable. Secret scanning at push time is insufficient; historical credential sweeps and forced rotation are necessary after any compromise.

3. **GitHub-hosted runners lack process-level visibility.** Standard GitHub-hosted runners do not provide process creation logging, making endpoint-level detection rules (Sigma) impractical without self-hosted infrastructure or third-party tooling like StepSecurity Harden-Runner. Network egress controls and workflow approval policies are the most effective detection layers for most organizations.

4. **Cleanup rate is dangerously low.** With only 16% of affected repositories showing cleanup as of October 5, the window for secondary exploitation (malicious package publication using stolen registry tokens) remains wide open.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [The Hacker News](https://thehackernews.com/2026/10/credential-stealing-github-actions.html) -- primary news report on the October 2026 wave, citing StepSecurity and Socket research
- [StepSecurity Blog: GhostAction Returns](https://www.stepsecurity.io/blog/ghostaction-returns) -- primary technical advisory with workflow structure, IOCs, hunting queries, and execution evidence
- [Socket Blog: GhostAction Cloud Credentials](https://socket.dev/blog/ghostaction-cloud-credentials) -- detailed technical analysis of workflow file structure, credential patterns, and compromised account activity
- [GitGuardian Blog: GhostAction Returns](https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/) -- August-September 2026 wave analysis with exfiltration endpoint history, secret categories, and cleanup statistics
- [CSO Online: GhostAction Campaign](https://www.csoonline.com/article/4052826/ghostaction-campaign-steals-3325-secrets-in-github-supply-chain-attack.html) -- background on September 2025 wave and historical secret theft figures
- [CybersecurityNews: GhostAction Supply Chain Campaign](https://cybersecuritynews.com/ghostaction-supply-chain-campaign/) -- additional details on targeted credential types and delivery mechanism

---
*Report generated by Actioner*
