# Technical Analysis Report: Mini Shai-Hulud — Compromised @antv npm Packages (CI/CD Credential Theft) (2026-05-30)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-05-30
Version: 1.0 (FINAL)

## Executive Summary

On 2026-05-19, a threat actor (tracked publicly as **TeamPCP**) compromised the npm maintainer account `atool` that publishes the popular `@antv` data-visualization namespace and, in a ~22-minute automated burst, published **600+ malicious package versions across ~320 unique packages** (≈279 of them `@antv`, plus downstream packages such as `echarts-for-react`, `timeago.js`, `size-sensor`, `canvas-nest.js`). Microsoft branded the wave **"Mini Shai-Hulud,"** a lighter, faster-spreading descendant of the November 2025 Shai-Hulud / Shai-Hulud 2.0 npm worm. The malicious versions carry a **`preinstall` hook** that runs an obfuscated ~500 KB stager during `npm install`, installs the **Bun** runtime, and executes a credential-stealer (`bun_environment.js` / `index.js`) purpose-built for **CI/CD secret theft**.

The payload harvests 20+ credential classes (GitHub, npm, AWS, GCP, Azure, HashiCorp Vault, Kubernetes, 1Password, Stripe, DB strings), scrapes the **GitHub Actions `Runner.Worker` process memory** for masked secrets, escalates via a passwordless **sudoers** injection, exfiltrates to `t.m-kosche[.]com:443` and over the **Session P2P network** (`filev2.getsession[.]org/file/`), and self-propagates using stolen npm tokens. It creates public GitHub repos advertising the compromise (`niagA oG eW ereH :duluH-iahS` = "Shai-Hulud: Here We Go Again") and plants a **dead-man's-switch** GitHub token whose revocation triggers home-directory destruction. This campaign is **distinct** from the `oob[.]moika[.]tech` dependency-confusion, the `vpmdhaj`/`X-Supply:1` typosquat, and the `colortoolsv2`/`mimelib2` EtherHiding campaigns covered earlier; the unique anchors here are the `@antv`/`atool` vector, `t.m-kosche[.]com`, the Session-network exfil, and the reversed repo marker.

Severity: **High** (active, self-propagating, CI/CD-credential-theft worm in a high-download namespace).

## Background: @antv npm Ecosystem

`@antv` is Ant Group's open-source data-visualization family (G2, G6, X6, L7, S2, F2, G2Plot, Graphin, data-set, etc.), collectively ~16M weekly downloads; `echarts-for-react` alone has 1M+ weekly downloads. Because these are direct/transitive dependencies of countless front-end builds and run inside CI/CD pipelines, a `preinstall`-stage payload executes with the pipeline's ambient cloud and registry credentials — the exact target of this campaign.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-11 | Earlier Mini Shai-Hulud wave (gh-token-monitor/kitty-monitor persistence variant) |
| 2026-05-19 | `atool` maintainer account compromised; ~600+ malicious versions across ~320 packages published in a ~22-minute automated burst |
| 2026-05-20 | Microsoft Security Blog publishes analysis ("Mini Shai Hulud"); npm begins removals |
| 2026-05-20+ | 2,200+ public exfil repos observed with the reversed campaign description |

## Root Cause: Maintainer Account Compromise → Supply-Chain Injection

The npm account `atool` (publisher of the `@antv` namespace) was compromised — most plausibly via a stolen npm token harvested by a prior Shai-Hulud wave — and used to publish trojanized versions of every package it maintained. The injection replaces/augments the package so that `package.json` contains a malicious `preinstall` script, ensuring code execution at install time before any application code runs.

## Technical Analysis of the Malicious Payload

### 1. Preinstall Loader (`setup_bun.js` → Bun bootstrap)

The trojanized `package.json` adds `"preinstall": "node setup_bun.js"`. `setup_bun.js` is a small loader that ensures the **Bun** JavaScript runtime is present (fetching from `bun.sh` if needed) and then runs the main obfuscated payload with Bun (`bun run index.js` / `bun_environment.js`; some variants invoke `bun run .claude/`). Running under Bun sidesteps Node-centric EDR hooks and supports the ~500 KB obfuscated bundle.

### 2. Obfuscated Stealer (`bun_environment.js` / `index.js`)

Two obfuscation layers: **Layer 1** is ~1,732 Base64 strings reordered with shuffle key `0xa31de`; **Layer 2** encrypts the C2 domain and target env-var names with a custom **PBKDF2 + SHA-256** scheme decrypted at runtime. The stealer enumerates and validates 20+ credential types:

- **GitHub** — `GITHUB_TOKEN`, PATs (`ghp_`/`gho_`), installation tokens (`ghs_`); validates via `/user`; enumerates repo/org secrets.
- **npm** — validates tokens via `/-/whoami`, exchanges OIDC tokens, enumerates packages (used for self-propagation).
- **AWS** — IMDS `169.254.169[.]254`, ECS metadata `169.254.170[.]2`, `~/.aws/`, SecretsManager across regions.
- **HashiCorp Vault** — 12+ token paths (`~/.vault-token`, `/var/run/secrets/vault/token`), connects `127.0.0[.]1:8200`.
- **Kubernetes** — service-account tokens, namespace secret enumeration.
- **1Password** — CLI interaction, master-password / 2FA-bypass attempts.
- Also GCP, Azure, SSH, Stripe, database connection strings.

### 3. CI Runner Memory Scraping

Locates the GitHub Actions `Runner.Worker` PID by scanning `/proc`, reads its memory, and extracts masked secrets with the distinctive pattern:
`tr -d '\0' | grep -aoE '"[^"]+":{"value":"[^"]*","isSecret":true}' | sort -u`

### 4. C2 Infrastructure & Exfiltration

Collected data is serialized, compressed, encrypted, and exfiltrated over two channels: (a) **HTTPS to `t.m-kosche[.]com:443`**; (b) **Session P2P network** via `filev2.getsession[.]org/file/`. A tertiary channel abuses the **GitHub Git Data API** (creating blobs/trees/commits in victim repos, avoiding `main`/`master`/`dependabot/`/`renovate/`/`gh-pages` branches) and creates **public repos** under stolen accounts with description `niagA oG eW ereH :duluH-iahS`.

### 5. Privilege Escalation, Persistence & Propagation

- **Sudoers injection** (passwordless): `echo 'runner ALL=(ALL) NOPASSWD:ALL' > /mnt/runner` (via bind mount); DNS/host tampering via `/etc/hosts`.
- **Dead-man's switch**: plants a GitHub token named `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` (commit-message marker variant: `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner`) and a monitor daemon (`gh-token-monitor` / `kitty-monitor`) that **wipes the home directory** if the token is revoked while the monitor is active.
- **Self-propagation**: uses stolen npm tokens to backdoor additional packages; enumerates `/user/repos` and `/user/orgs` to spread.
- **Legitimacy forgery**: forges **SLSA provenance attestations** via Sigstore (Fulcio/Rekor) to make malicious versions appear signed/verified.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs `hxxps://`; domains/IPs use `[.]`; emails `[at]`. Hashes/paths are not defanged.

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `@antv/*` (g2, g6, x6, l7, s2, f2, g2plot, graphin, data-set, …) | versions published 2026-05-19 (~279 pkgs) | `preinstall` hook + obfuscated Bun stealer |
| `echarts-for-react` | versions published 2026-05-19 | Downstream package compromised in same burst |
| `timeago.js`, `size-sensor`, `canvas-nest.js` (and others) | versions published 2026-05-19 | Non-`@antv` packages compromised via `atool` account |

> Treat **any** `@antv`/`atool`-published version dated 2026-05-19 as suspect; consult the per-package version lists in the Snyk/Socket/Mend sources for the authoritative enumeration.

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Cross-platform | `index.js` (malicious JS payload) | `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c` | Obfuscated stealer (Microsoft IOC) |
| Cross-platform | `cat.py` (backdoor) | `fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142` | Python backdoor script (Microsoft IOC) |
| Cross-platform | `setup_bun.js` | `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a` | Preinstall Bun loader (Shai-Hulud 2.0 lineage) |
| Cross-platform | `bun_environment.js` | `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0` | Main Bun stealer payload (lineage hash; variant-dependent) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `t.m-kosche[.]com:443` | Primary HTTPS C2 / exfil |
| URL | `hxxps://filev2.getsession[.]org/file/` | Session P2P exfil channel |
| IP | `169.254.169[.]254` | AWS IMDS (credential target, not attacker-owned) |
| IP | `169.254.170[.]2` | ECS metadata (credential target) |
| IP | `127.0.0[.]1:8200` | Local Vault (credential target) |

### Behavioral

- `package.json` `preinstall` set to `node setup_bun.js`; child `bun run index.js` / `bun run .claude/`.
- Process command line containing `grep -aoE '...":{"value":"...","isSecret":true}'` (runner memory scrape).
- Sudoers entry `runner ALL=(ALL) NOPASSWD:ALL`.
- Public GitHub repo description `niagA oG eW ereH :duluH-iahS`; GitHub token name `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`.
- Outbound to `t.m-kosche[.]com` and `filev2.getsession[.]org`.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Trojanized `@antv` npm versions via compromised `atool` account |
| T1059.007 | JavaScript | Obfuscated Bun/Node stager run from `preinstall` |
| T1552.001 | Credentials In Files | Reads `~/.aws/`, `~/.npmrc`, `~/.vault-token`, K8s SA tokens |
| T1003.007 | Proc Filesystem | Scrapes `Runner.Worker` memory via `/proc` for masked secrets |
| T1552.005 | Cloud Instance Metadata API | Queries AWS IMDS / ECS metadata |
| T1548.003 | Sudo and Sudo Caching | Injects passwordless sudoers rule |
| T1567 | Exfiltration Over Web Service | Exfil to `t.m-kosche[.]com`, Session network, GitHub Git Data API |
| T1657 | Financial Theft | Financially motivated (TeamPCP); broad credential monetization |
| T1554 | Compromise Host Software Binary | Self-propagation by backdooring further npm packages |
| T1485 | Data Destruction | Dead-man's-switch home-directory wipe on token revocation |

## Impact Assessment

Breadth: ~320 packages / ~16M weekly downloads; 2,200+ exfil repos observed. Depth: full CI/CD credential compromise (cloud, registry, source control) plus self-propagation and host-wipe risk. Stealth: runs at `preinstall` under Bun with multi-layer obfuscation and forged SLSA provenance.

## Detection & Remediation

### Immediate Detection

- Inventory installed `@antv`/`echarts-for-react`/`timeago.js`/`size-sensor` versions; flag any published 2026-05-19.
- Grep lockfiles and `node_modules` for `setup_bun.js`, `bun_environment.js`, and `preinstall` running `node setup_bun.js`.
- Search GitHub org for repos described `Shai-Hulud: Here We Go Again` and for the `IfYouRevoke...`/`IfYouInvalidate...` token names.
- Hunt host telemetry for the `"isSecret":true` grep pattern and the `runner ALL=(ALL) NOPASSWD:ALL` sudoers entry.

### Remediation

1. **Order matters (dead-man's switch):** isolate host → stop/remove the `gh-token-monitor`/`kitty-monitor` persistence → only then rotate tokens. Revoking the planted GitHub token first can trigger the home-directory wipe.
2. Pin/rollback to known-good `@antv` versions predating 2026-05-19; purge caches and `node_modules`; reinstall with `--ignore-scripts` where feasible.
3. Rotate **all** credentials exposed to affected pipelines (GitHub, npm, AWS/GCP/Azure, Vault, K8s, 1Password, Stripe, DB).
4. Audit npm/GitHub for unexpected package publishes and new public repos under your accounts.

> Remediation is advisory; efficacy of `--ignore-scripts` depends on your install tooling and whether the payload also lands via transitive deps.

### Long-Term Hardening

Enforce `npm ci --ignore-scripts` in CI; use scoped, short-lived registry tokens and OIDC without long-lived secrets; restrict CI runner egress to an allowlist (block `t.m-kosche[.]com`, Session endpoints); run installs in least-privilege, ephemeral runners without ambient cloud metadata access.

## Detection Rules

These detections target the Mini Shai-Hulud (@antv) chain at **PoC/advisory-specific** altitude: the npm `preinstall`→Bun loader, the CI runner memory-scrape + sudoers escalation, the reversed exfil-repo/dead-man-switch markers, and the `t.m-kosche[.]com` / Session-network egress. Confidence is now per-rule (and per-SID for the network families): only the high-precision anchors carry `high`; behavioral OR-rules and the legitimate-Session-network leg are `medium`. Compiles ≠ fires — validate field mappings (Sysmon/auditd vs your schema) in your own pipeline before production; the three Sigma rules' `sigma check` exit 1 is only the environment's D3FEND egress 403 (not a rule defect), and the load-bearing oracle is clean conversion to both Splunk and CrowdStrike.

### Sigma: Mini Shai-Hulud npm Preinstall Bun Loader Execution
Detects the trojanized `preinstall` hook bootstrapping Bun to run the obfuscated stager (`setup_bun.js` / `bun run index.js`).
**Status:** compile ✅ compiles · confidence: high
<!-- revision: KEEP per critic verdict — no change. -->
<!-- audit: sigma check exit=1 (D3FEND fetch HTTP 403 egress block — documented env limitation, not a rule defect); sigma convert --without-pipeline -t splunk exit=0; -t log_scale exit=0. specific-altitude: keys on npm lifecycle context AND distinctive loader filenames. Low FP (legit Bun preinstall is rare); generic process_creation logsource for cross-platform portability. -->
```yaml
title: Mini Shai-Hulud npm Preinstall Bun Loader Execution
id: 2f8a1c34-9d52-4e7b-b6a1-3c0e5f7a9b21
status: experimental
description: >
    Detects the Mini Shai-Hulud (@antv) supply-chain payload executing during npm
    install via a malicious preinstall hook that bootstraps the Bun runtime and runs
    the obfuscated stager (setup_bun.js -> bun run index.js / bun_environment.js).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/
    - https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/
author: Actioner
date: 2026/05/30
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: process_creation
detection:
    selection_npm_lifecycle:
        CommandLine|contains:
            - 'npm-lifecycle'
            - 'preinstall'
    selection_loader:
        CommandLine|contains:
            - 'setup_bun.js'
            - 'bun_environment.js'
            - 'bun run index.js'
            - 'bun run .claude/'
    condition: selection_npm_lifecycle and selection_loader
falsepositives:
    - Legitimate packages that genuinely ship a Bun-based preinstall step (rare)
level: high
```

### Sigma: Shai-Hulud CI Runner Memory Secret Scraping and Sudoers Injection
Detects the runner-memory secret scrape (the `grep -aoE`/`tr -d` command keying on the `":{"value":"` format) and/or the passwordless sudoers injection used for escalation on CI runners.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: memscrape selection no longer keys on the bare '"isSecret":true' substring (GHA's standard masked-secret serialization → fired on benign runner telemetry); now requires the full scrape COMMAND (grep + -aoE + tr -d + the ":{"value":" fragment) via contains|all. Sudoers half kept. Capped high→medium (behavioral OR-rule). -->
<!-- audit: sigma check exit=1 (D3FEND 403 env block); splunk exit=0; log_scale exit=0. Values are literal command-line substrings (not auditd hex args), so no hex encoding needed here. OR of two distinctive anchors; sudoers string is near-unique to this campaign. -->
```yaml
title: Shai-Hulud CI Runner Memory Secret Scraping and Sudoers Injection
id: 7b1e9d04-2a3f-4c88-9e15-6d4b0a2f8c77
status: experimental
description: >
    Detects the Mini Shai-Hulud CI/CD credential-theft chain: scraping the GitHub
    Actions Runner.Worker process memory for masked secrets via the distinctive
    grep/tr scrape command, and/or injecting a passwordless sudoers rule for the
    runner user.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/
    - https://flashpoint.io/blog/mini-shai-hulud-worm-new-era-ci-cd-exploitation/
author: Actioner
date: 2026/05/30
tags:
    - attack.t1552.001
    - attack.t1003.007
    - attack.t1548.003
detection:
    selection_memscrape:
        CommandLine|contains|all:
            - 'grep'
            - '-aoE'
            - 'tr -d'
            - '":{"value":"'
    selection_sudoers:
        CommandLine|contains: 'runner ALL=(ALL) NOPASSWD:ALL'
    condition: selection_memscrape or selection_sudoers
falsepositives:
    - Security tooling that legitimately greps runner memory for the masked-secret format (rare)
level: medium
logsource:
    category: process_creation
    product: linux
```

### Sigma: Shai-Hulud Exfiltration Repo Marker and Dead-Man-Switch Token
Detects host references to the reversed campaign repo description and the dead-man's-switch GitHub token names.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: dropped the plaintext-English 'Shai-Hulud: Here We Go Again' variant — it matches published campaign prose (this report, vendor blogs, TI feeds) and collides on defenders' own workstations. Kept the reversed marker + both dead-man-switch token names. Capped high→medium (no sample corroboration). -->
<!-- audit: sigma check exit=1 (D3FEND 403 env block); splunk exit=0; log_scale exit=0. Remaining strings are near-unique campaign markers (reversed marker + token names); primary FP is the analyst's own IR/TI tooling. Generic process_creation for cross-platform reach (these strings also appear in scripts/logs - consider extending to file_event under the malware path in tuning). -->
```yaml
title: Shai-Hulud Exfiltration Repo Marker and Dead-Man-Switch Token
id: c4d2f6a8-1b09-4e3c-8a7d-9f2e0b5c3a14
status: experimental
description: >
    Detects host-side artifacts of Mini Shai-Hulud GitHub-based exfiltration and
    persistence: the reversed campaign repo description used when creating public
    exfil repos, and the dead-man-switch GitHub token names that wipe the host if
    revoked.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/
    - https://cybersecurityreach.org/investigations/ifyourevokethistokenitwillwipethecomputeroftheowner-shai-hulud-2026
author: Actioner
date: 2026/05/30
tags:
    - attack.t1567
    - attack.t1657
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'niagA oG eW ereH :duluH-iahS'
            - 'IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner'
            - 'IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner'
    condition: selection
falsepositives:
    - Threat-intel/research tooling referencing these reversed/token markers
level: medium
```

### Snort: Mini Shai-Hulud C2 / Session Exfil Egress
Detects TLS ClientHello SNI to `t.m-kosche[.]com` (sid 2100501, **high**) and HTTP exfil to `filev2.getsession[.]org/file/` (sid 2100502, **medium**). Snort 2 syntax (this env is Snort 2.9.20).
**Status:** compile ✅ compiles · confidence: 2100501 high · 2100502 medium
The getsession leg (2100502) targets the **legitimate Session P2P network**, so it is medium-precision — pair it with the SNI/DNS anchor or scope to CI-runner source ranges before alerting.
<!-- revision: labeled SIDs individually (2100501 high / 2100502 medium); surfaced the Session-network FP caveat in reader prose (was audit-only); annotated the .rules file header per-SID. -->
<!-- audit: snort -T validated via wrapper config (var defs + classification.config/reference.config + include) since this env's `-R` flag is pidfile-only in Snort2; exit=0. SNI rule gates on TLS record byte 16 03 then literal domain (high); getsession rule is generic substring (Session is a legit P2P net - the /file/ + host pairing is the campaign anchor, medium-precision on its own). -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - Mini Shai-Hulud C2 SNI t.m-kosche.com [HIGH]"; flow:established,to_server; content:"|16 03|"; depth:2; content:"t.m-kosche.com"; nocase; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/; sid:2100501; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Mini Shai-Hulud Session Exfil filev2.getsession.org [MEDIUM - pair with SNI/DNS anchor]"; flow:established,to_server; content:"filev2.getsession.org"; nocase; content:"/file/"; nocase; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/; sid:2100502; rev:1;)
```

### Suricata: Mini Shai-Hulud C2 / Session Exfil Egress
TLS SNI (sid 2200501) and DNS query (sid 2200502) for `t.m-kosche[.]com` (**high**), plus HTTP host/uri exfil to `filev2.getsession[.]org/file/` (sid 2200503, **medium**).
**Status:** compile ✅ compiles · confidence: 2200501/2200502 high · 2200503 medium
The getsession HTTP rule (2200503) matches the **legitimate Session P2P network**, so it is medium-precision — pair it with the SNI/DNS anchor or scope to CI-runner source ranges before alerting.
<!-- revision: labeled SIDs individually (2200501/2200502 high, 2200503 medium); surfaced the Session-network FP caveat in reader prose (was audit-only); annotated the .rules file header per-SID. -->
<!-- audit: suricata -T -S exit=0 (removed redundant `nocase` on http.host - host buffer is normalized lowercase). bsize:14 = len("t.m-kosche.com") for tight SNI/DNS match. getsession HTTP rule is lower-precision alone (legit Session traffic exists); pair with the SNI/DNS anchor. -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Mini Shai-Hulud C2 TLS SNI t.m-kosche.com [HIGH]"; flow:established,to_server; tls.sni; content:"t.m-kosche.com"; nocase; bsize:14; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/; metadata:author Actioner, created_at 2026-05-30; sid:2200501; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - Mini Shai-Hulud C2 DNS Query t.m-kosche.com [HIGH]"; dns.query; content:"t.m-kosche.com"; nocase; bsize:14; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/; metadata:author Actioner, created_at 2026-05-30; sid:2200502; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Mini Shai-Hulud Session Exfil to filev2.getsession.org [MEDIUM - pair with SNI/DNS anchor]"; flow:established,to_server; http.host; content:"filev2.getsession.org"; http.uri; content:"/file/"; nocase; startswith; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/; metadata:author Actioner, created_at 2026-05-30; sid:2200503; rev:1;)
```

### YARA: Mini Shai-Hulud @antv Payload
Detects the stager/payload (`setup_bun.js`, `bun_environment.js`, `index.js`) via campaign markers — reversed repo description, dead-man-switch token names, the full grep/tr memory-scrape command, C2/Session pairing, and sudoers injection.
**Status:** compile ✅ compiles · confidence: medium · sample: constructed
<!-- revision: (a) relabeled high→medium — sample is `constructed` (built from published strings, no confirmed upstream sample). (b) DROPPED the ($secret_grep and $is_secret) branch — it keyed on the GHA secret-serialization format itself and fired on legit runner logs; replaced with all of ($scrape_grep,$scrape_trd,$scrape_pat) requiring the actual grep -aoE / tr -d scrape command. Kept reversed-marker, token-name, c2+session, and sudoers+egress branches. -->
<!-- audit: yarac exit=0; yara fired on constructed positive (carries published markers + scrape command), quiet on benign @antv snippet that includes the bare GHA isSecret format (the dropped branch would have falsely matched it). Positive built from PUBLISHED strings, not invented. -->
```yara
rule MiniShaiHulud_AntV_Payload
{
    meta:
        description = "Detects Mini Shai-Hulud (@antv) npm supply-chain stager/payload (setup_bun.js, bun_environment.js, index.js) via distinctive exfil markers, dead-man-switch token names, runner memory-scrape command, and C2/Session pairing"
        author = "Actioner"
        date = "2026-05-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/"
        hash = "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c"
        hash = "fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142"
    strings:
        $repo_desc   = "niagA oG eW ereH :duluH-iahS" ascii wide
        $token_nuke  = "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner" ascii wide nocase
        $token_nuke2 = "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner" ascii wide nocase
        $scrape_grep = "grep -aoE" ascii
        $scrape_trd  = "tr -d" ascii
        $scrape_pat  = "\":{\"value\":\"" ascii
        $c2          = "t.m-kosche.com" ascii wide nocase
        $session     = "filev2.getsession.org" ascii wide nocase
        $sudoers     = "runner ALL=(ALL) NOPASSWD:ALL" ascii
    condition:
        any of ($repo_desc, $token_nuke, $token_nuke2)
        or (all of ($scrape_grep, $scrape_trd, $scrape_pat))
        or ($c2 and $session)
        or ($sudoers and ($c2 or $session))
}
```

## Lessons Learned

`preinstall`-stage execution in CI/CD turns any compromised transitive dependency into instant credential theft against ambient cloud/registry secrets. The dead-man's-switch token inverts incident response: naive credential revocation can destroy the host, so persistence removal must precede rotation. Forged SLSA/Sigstore attestations show provenance signals can be gamed; supply-chain trust must rest on pinned, reproducible builds and least-privilege ephemeral runners, not on badges.

## Sources

- [Mini Shai Hulud: Compromised @antv npm packages enable CI/CD credential theft — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/) — primary source: hashes, C2, runner-scrape command, sudoers, repo marker
- [Mini Shai-Hulud Hits AntV: 300+ Malicious npm Packages — Snyk](https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/) — package enumeration, file names, Sigstore forgery
- [Mini Shai-Hulud Hits @antv Ecosystem, 639 Compromised npm Packages — Socket](https://socket.dev/blog/antv-packages-compromised) — version counts, `atool` account vector, Session-network exfil
- [The Shai-Hulud 2.0 npm worm: analysis — Datadog Security Labs](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/) — lineage: setup_bun.js/bun_environment.js hashes and preinstall mechanics
- [The Mini Shai-Hulud Worm and the New Era of CI/CD Exploitation — Flashpoint](https://flashpoint.io/blog/mini-shai-hulud-worm-new-era-ci-cd-exploitation/) — TeamPCP attribution, CI/CD credential-theft chain
- [IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner — Cybersecurity Reach Foundation](https://cybersecurityreach.org/investigations/ifyourevokethistokenitwillwipethecomputeroftheowner-shai-hulud-2026) — dead-man's-switch token and remediation ordering
- [Mini Shai-Hulud Pushes Malicious AntV npm Packages — The Hacker News](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html) — corroboration of scope and timeline

---
*Report generated by Actioner (FINAL — revised per critic verdict)*
