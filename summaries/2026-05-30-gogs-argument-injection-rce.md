# Technical Analysis Report: Gogs Argument-Injection RCE via Pull-Request Branch Name (2026-05-30)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-05-30
Version: 1.0 (DRAFT)

## Executive Summary

Rapid7 Labs disclosed (2026-05-28) an unpatched, critical argument-injection vulnerability (CWE-88, CVSSv4 9.4) in **Gogs**, a popular self-hosted Git service. Any authenticated user can achieve remote code execution as the Gogs server process by opening a pull request whose **base branch name** begins with `--exec=<command>` and then triggering the **"Rebase before merging"** merge operation. The vulnerable `Merge()` function in `internal/database/pull.go` passes the branch name to `git rebase` without a `--` argument separator, so git parses `--exec=` as its own flag and runs the attacker's command via `sh -c` after each replayed commit.

Because Gogs ships with open registration (`DISABLE_REGISTRATION = false`) and unlimited repo creation (`MAX_CREATION_LIMIT = -1`) by default, an effectively **unauthenticated** attacker can self-register and exploit any default-configured instance — no admin rights, no victim interaction. Successful exploitation yields full server compromise: read of every (including private) repository, credential dumping (password hashes, API tokens, SSH keys, 2FA secrets), and network pivot. Gogs 0.14.2 and 0.15.0+dev (commit b53d3162) are confirmed affected; all prior versions supporting rebase-merge are likely vulnerable. The flaw was reported via GitHub Security Advisory **GHSA-qf6p-p7ww-cwr9** on 2026-03-17; as of disclosure **no patch exists**, and Rapid7 has shipped a public Metasploit module. ~2,400 instances are internet-exposed (Shadowserver). No CVE has been assigned.

## Background: Gogs Self-Hosted Git Service

Gogs is a lightweight, self-hosted Git service written in Go, widely deployed by small teams as a self-managed alternative to GitHub/GitLab. It exposes a web UI and API for repositories, pull requests, and merges. The "Rebase before merging" merge style invokes `git rebase` server-side to replay PR commits onto the base branch — the code path abused here. This is a distinct, never-patched `Merge()` path from prior Gogs argument-injection fixes (e.g. CVE-2024-39933 and related), which is why a default, current install remains exploitable.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-03-16 | Rapid7 Labs discovers the vulnerability |
| 2026-03-17 | Reported to Gogs maintainers via GHSA-qf6p-p7ww-cwr9 |
| 2026-03-28 | Maintainer acknowledgment; no further updates afterward |
| 2026-05-28 | Rapid7 public disclosure + Metasploit module released (still unpatched) |
| 2026-05-29 | Secondary press coverage (SecurityWeek, BleepingComputer, The Register) |

## Root Cause: Argument Injection into `git rebase` (CWE-88)

The `Merge()` function in `internal/database/pull.go` passes the pull request's base branch name to the `git rebase` invocation **without inserting a `--` end-of-options separator** before the positional branch argument. Git therefore interprets a branch name that begins with a leading `-`/`--` as an option rather than a ref. Since `git rebase` supports `--exec=<cmd>` (run `sh -c <cmd>` after replaying each commit), an attacker who names their branch `--exec=<cmd>` obtains arbitrary command execution as the Gogs server user. Git forbids spaces in branch names, so the attacker uses the shell `${IFS}` token (expands to whitespace under `sh -c`) to separate command tokens.

## Technical Analysis of the Malicious Payload

### 1. Malicious Branch Name (the injected argument)

The attacker creates a branch whose name is the injected git flag, using only Git-legal characters (`$ { } = -`):

```
--exec=touch${IFS}/tmp/rce_proof
```

For payloads needing characters Git forbids in branch names (`: ~ ^ ? * [ \ //`), base64 is used to smuggle them:

```
--exec=echo${IFS}<base64_payload>|base64${IFS}-d|sh
```

On Windows, where pipe characters are unavailable in the branch name, a file-based loader is used:

```
--exec=sh${IFS}.abcdef
```

### 2. Server-Side Execution

When the PR is merged with the "Rebase before merging" style, Gogs runs (literal, verbatim from Rapid7):

```
git rebase --quiet '--exec=touch${IFS}/tmp/rce_proof' 'head_repo/feature'
```

Git treats `--exec=...` as its exec hook and runs the command via `sh -c` after each replayed commit. `${IFS}` expands to a space at that point, defeating Git's space prohibition in the branch name.

### 3. Delivery Endpoint

- **PR creation:** attacker pushes the malicious branch and opens a pull request using it as the base.
- **Trigger:** `POST /{owner}/{repo}/pulls/{index}/merge` with body parameter `merge_style=rebase` (the web UI "Rebase before merging" button), handled by `internal/route/repo/pull.go` → `pr.Merge()`.

### 4. Post-Exploitation

Code runs as the Gogs server user, enabling repository theft (incl. private), credential/secret dumping, and pivot. The Metasploit module provisions an API token named `msf_<hex>` for its workflow.

### 5. Evasion / Cleanup Notes

The exploit is noisy: a failed rebase corrupts repo git state and leaves a failed PR plus an error in the Gogs log. The `msf_<hex>` token and dropped payload files (`.abcdef`, `.abcdef.bat` on Windows) persist unless cleaned up.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs `hxxps://`, domains `[.]`, IPs `[.]`, emails `[at]`.

### Package / Software Level

| Package / Component | Affected Version | Description |
|---------------------|------------------|-------------|
| Gogs | 0.14.2, 0.15.0+dev (commit b53d3162), and prior rebase-merge versions | Argument injection in `Merge()` (`internal/database/pull.go`) — GHSA-qf6p-p7ww-cwr9 |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `/tmp/rce_proof` | n/a | PoC proof file dropped by default `touch` payload |
| Windows | `.abcdef`, `.abcdef.bat` (in target repo working dir) | n/a | File-based loader artifacts dropped by Metasploit module |

### Network

| Type | Value | Context |
|------|-------|---------|
| URI Pattern | `POST /{owner}/{repo}/pulls/{index}/merge` (body `merge_style=rebase`) | Rebase-merge trigger endpoint |
| Request Artifact | `--exec=` in PR branch-name / request body | Injected git flag |
| Request Artifact | `${IFS}` token alongside `--exec=` | Whitespace smuggling in payload |

### Behavioral

- Git child process under the Gogs server carrying `--exec=` on its command line (`git rebase --quiet '--exec=...' '...'`).
- Branch names beginning with `--` in repo refs / PR history.
- Gogs error-log signature on a malformed/failed attempt:
  `[E] ...merge: git checkout '--exec=<...>': exit status 128 - error: unknown option \`exec=<...>\``
- API token named `msf_<hex>` persisting in user settings.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | RCE via the public Gogs pull-request rebase-merge web endpoint |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `git rebase --exec` runs the attacker command via `sh -c` |
| T1078 | Valid Accounts | Authenticated/self-registered user account used to reach the vulnerable flow |
| T1552 | Unsecured Credentials | Post-exploit dump of password hashes, API tokens, SSH keys, 2FA secrets |

## Impact Assessment

Breadth: ~2,400 internet-exposed Gogs instances (Shadowserver), most on default config that allows open registration. Depth: full RCE as the server process → complete instance and repository compromise plus credential theft. Stealth: low — exploitation leaves error logs, failed PRs, and corrupted git state — but no patch exists, so detection-and-respond is the only option for many.

## Detection & Remediation

### Immediate Detection

- Hunt process telemetry on Gogs hosts for `git` invocations whose command line contains `--exec=` (see Sigma below).
- Grep Gogs logs for `--exec=` and `` unknown option `exec= `` and for branch names starting with `--`.
- Audit user API tokens for any named `msf_<hex>`.

### Remediation

No vendor patch is available. Interim mitigations (efficacy is config-dependent — treat as advisory, not a fix):
- Disable open registration (`DISABLE_REGISTRATION = true`) and restrict repo creation to reduce the unauthenticated attack surface.
- Disable the "Rebase before merging" merge style / restrict who can merge, if operationally feasible.
- Place Gogs behind authenticated reverse-proxy / network ACLs; remove internet exposure.
- Monitor for the IOCs above; rotate all instance secrets (tokens, SSH keys, 2FA) if exploitation is suspected.

### Long-Term Hardening

- Track the upstream advisory (GHSA-qf6p-p7ww-cwr9) for a fix and apply immediately; consider migrating to an actively maintained fork/alternative given the slow vendor response.

## Detection Rules

These detections target the Gogs argument-injection RCE at PoC/advisory-specific altitude. The host Sigma rule (a `git` child process of the Gogs server carrying the injected `--exec=` flag) is the most durable anchor; the merge-failure log Sigma and the Snort/Suricata HTTP rules are lower-confidence support that catch the failure/probing path and the `--exec=`+`${IFS}` payload — both convert/compile cleanly. Compiles ≠ fires — validate against your own pipeline, tune the HTTP rules for TLS-terminating proxies, and note the literal `${IFS}` token is evadable (`$IFS$9`/tabs).

### Sigma: git rebase --exec child process under Gogs
Detects a `git` child process of the Gogs server carrying an injected `--exec=` flag during a rebase/checkout — the server-side RCE artifact.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. revision: added ParentImage endswith '/gogs' anchor (critic: bare rule fired on benign CI/CD `git rebase --exec='make test'`); now scoped to git as a direct child of the gogs server + CommandLine rebase|checkout + '--exec='. Demoted critical→medium / high→medium since efficacy depends on the parent being the gogs binary (telemetry-dependent). No pipeline fits generic process_creation, so name-mapping (2) skipped; --without-pipeline proves portability only. Tactic context (T1190/T1059.004) in ATT&CK table, not tags. -->
```yaml
title: Gogs Argument Injection via git rebase --exec Child Process
id: 7f3c1a2e-9d54-4b6a-8e21-3c5f0a7b91d2
status: experimental
description: >
    Detects a git child process spawned by the Gogs server carrying an injected
    --exec flag, the artifact of CWE-88 argument injection (GHSA-qf6p-p7ww-cwr9)
    where a malicious pull request base branch name beginning with --exec= is
    passed to git rebase, causing git to run an attacker command via sh -c.
references:
    - https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/
    - https://www.securityweek.com/gogs-zero-day-exposes-servers-to-remote-code-execution/
author: Actioner
date: 2026/05/30
tags:
    - attack.t1190
    - attack.t1059.004
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '/gogs'
    selection_git:
        Image|endswith:
            - '/git'
            - '\git.exe'
    selection_inject:
        CommandLine|contains:
            - 'rebase'
            - 'checkout'
    selection_exec:
        CommandLine|contains: '--exec='
    condition: selection_parent and selection_git and selection_inject and selection_exec
falsepositives:
    - Legitimate CI tooling invoking git rebase with a genuine --exec hook (rare as a direct child of the gogs server process)
level: medium
```

### Sigma: Gogs merge-failure log signature for --exec injection
Detects the Gogs error-log line emitted when an injected `--exec=` branch name is rejected by git during a rebase merge. Hunt-only on the failure/probing path; pair with the process rule above.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check 0; splunk 0; log_scale 0 (log_scale → /"unknown option `exec="/i, a meaningful distinctive match, not a bare-keyword search). revision: (a) dropped the bare '--exec=' keyword (critic: noisy against generic syslog); keep ONLY the distinctive "unknown option `exec=" signature; (b) retargeted logsource from linux/syslog to the Gogs application log (product: gogs / service: application); (c) reconciled level → low (matches prose). low: catches only the FAILED/probing path; a clean successful exec may not emit this line. -->
```yaml
title: Gogs Pull Request Merge Failure Indicating --exec Argument Injection
id: b2e8d4c6-1a73-49f5-9c0d-6e2f8a3b7d41
status: experimental
description: >
    Detects the Gogs server error log signature produced when a malicious pull
    request base branch name beginning with --exec= is passed to git during a
    rebase merge, where git rejects the injected flag with "unknown option exec=".
    Indicative of attempted exploitation of the Gogs argument-injection RCE
    (GHSA-qf6p-p7ww-cwr9).
references:
    - https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/
    - https://www.bleepingcomputer.com/news/security/new-gogs-zero-day-flaw-lets-hackers-get-remote-code-execution/
author: Actioner
date: 2026/05/30
tags:
    - attack.t1190
    - attack.t1059.004
logsource:
    product: gogs
    service: application
detection:
    selection_merge:
        - "unknown option `exec="
    condition: selection_merge
falsepositives:
    - Unlikely; the literal git "unknown option exec=" string in a Gogs merge context is highly specific
level: low
```

### Snort: Gogs --exec branch-name argument injection in HTTP request
Two rules: the `--exec=`+`${IFS}` payload in the POST body, and the more durable rebase-merge endpoint path. Literal `${IFS}` adjacency is bypassable via `$IFS$9`/tabs; pair with the host Sigma rules and tune for TLS termination.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: validate-snort.sh exit 0. revision: renumbered out of the low round range 2100001-2 → 2100901-2100902, the next free repo-consistent sub-block (existing repo SIDs end at 2100801; no collision). Snort2 syntax: content+http_client_body/http_uri/http_method, '|24|{IFS}' = literal $ + {IFS}. confidence low: HTTP-layer rules miss TLS-terminated traffic and the literal ${IFS} adjacency is evadable ($IFS$9, tabs); host Sigma is the durable anchor. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Gogs Argument Injection RCE via Malicious --exec Branch Name (GHSA-qf6p-p7ww-cwr9)"; flow:established,to_server; content:"POST"; http_method; content:"--exec="; http_client_body; fast_pattern; content:"|24|{IFS}"; http_client_body; distance:0; classtype:web-application-attack; reference:url,rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/; sid:2100901; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Gogs Pull Request Rebase Merge Endpoint with Injected Argument"; flow:established,to_server; content:"POST"; http_method; content:"/pulls/"; http_uri; content:"/merge"; http_uri; distance:0; content:"merge_style=rebase"; http_client_body; classtype:web-application-attack; reference:url,rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/; sid:2100902; rev:1;)
```

### Suricata: Gogs --exec branch-name argument injection in HTTP request
Two rules: the `--exec=`+`${IFS}` payload in the request body, and the rebase-merge endpoint path. Literal `${IFS}` adjacency is bypassable via `$IFS$9`/tabs; pair with the host Sigma rules and tune for TLS termination.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: suricata -T exit 0 (7.0.3). revision: per the toolkit-mandated Suricata 2200000+ range, renumbered off the round 2200001-2 to 2200901-2200902 — the next free non-colliding repo-consistent sub-block (existing repo SIDs end at 2200801-2). Critic flagged possible ET-block overlap; this follows the toolkit's mandated 2200000+ range and the repo's per-topic sub-block convention. Dot-notation buffers (http.request_body/http.uri/http.method). confidence low: same TLS-visibility and whitespace-token evasion ($IFS$9, tabs) caveats as Snort; host Sigma is the durable anchor. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Gogs Argument Injection RCE via Malicious --exec Branch Name (GHSA-qf6p-p7ww-cwr9)"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"--exec="; content:"${IFS}"; distance:0; classtype:web-application-attack; reference:url,rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/; metadata:author Actioner, created_at 2026-05-30; sid:2200901; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Gogs Pull Request Rebase Merge with Injected --exec Argument"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/pulls/"; content:"/merge"; distance:0; http.request_body; content:"merge_style=rebase"; classtype:web-application-attack; reference:url,rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/; metadata:author Actioner, created_at 2026-05-30; sid:2200902; rev:1;)
```

### YARA: N/A
No durable file-level malware sample; the dropped artifacts (`/tmp/rce_proof`, `.abcdef`) are attacker-arbitrary, not a fixed signature.

## Lessons Learned

A single missing `--` end-of-options separator before a user-controlled positional argument is a recurring, high-impact class of bug (CWE-88) in tools that shell out to git. Gogs had patched sibling instances but left the `Merge()` path exposed — a reminder to audit *every* code path that concatenates user input into a git command, not just the one in the last CVE. The slow maintainer response (acknowledged March, still unpatched at May disclosure) underscores the operational risk of depending on lightly maintained open-source infrastructure; defenders must lean on compensating controls (registration lockdown, network ACLs, the detections above) when a vendor fix is not forthcoming.

## Sources

- [SecurityWeek — Gogs Zero-Day Exposes Servers to Remote Code Execution](https://www.securityweek.com/gogs-zero-day-exposes-servers-to-remote-code-execution/) — originating news item
- [Rapid7 Labs — Authenticated RCE via Argument Injection in Gogs (NOT FIXED)](https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/) — primary technical analysis, payload artifacts, IOCs
- [The Hacker News — Critical Gogs RCE Vulnerability Lets Any Authenticated User Execute Arbitrary Code](https://thehackernews.com/2026/05/critical-gogs-rce-vulnerability-lets.html) — corroborating technical writeup
- [BleepingComputer — New Gogs zero-day flaw lets hackers get remote code execution](https://www.bleepingcomputer.com/news/security/new-gogs-zero-day-flaw-lets-hackers-get-remote-code-execution/) — corroboration, affected versions, exposure stats
- [The Register — No fix yet for critical RCE bug in open-source Git service Gogs](https://www.theregister.com/security/2026/05/29/no-fix-yet-for-critical-gogs-rce-bug-exploit-module-is-out/) — patch-status and exploit-availability corroboration
- [Rapid7 Metasploit PR #21515 — Add Gogs rebase RCE exploit module](https://github.com/rapid7/metasploit-framework/pull/21515) — exploit module (msf_ token IOC, merge workflow)

---
*Report generated by Actioner*
