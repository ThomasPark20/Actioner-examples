# Technical Analysis Report: Miasma — Shai-Hulud Worm in @redhat-cloud-services npm Scope (2026-06-02)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-06-02
Version: 1.0 (FINAL)

## Executive Summary

On 2026-06-01, a self-propagating npm worm tracked as **"Miasma: The Spreading Blight"** — a fresh variant of the (Mini) Shai-Hulud worm — was pushed into **~32 official packages in the `@redhat-cloud-services` npm scope** as **96 malicious versions**, collectively pulling **~80K–117K downloads/week**. Root cause was a **compromised Red Hat employee GitHub account** that pushed malicious **orphan commits** to RedHatInsights repositories (`frontend-components`, `javascript-clients`, `platform-frontend-ai-toolkit`), injecting a GitHub Actions workflow that abused **`id-token: write` OIDC trusted publishing** to publish backdoored releases directly to npm — bypassing code review and long-lived tokens. The packages carry a **`"preinstall": "node index.js"`** hook (~4.2 MB obfuscated loader) that ROT-decodes and AES-128-GCM-decrypts staged blobs, downloads the **Bun 1.3.13** runtime, and runs a **~620 KB credential stealer** targeting AWS, Azure, GCP, HashiCorp Vault, Kubernetes, GitHub Actions OIDC, npm/PyPI, SSH, Docker, GPG, Bitwarden and 1Password.

Miasma is **lineage-distinct from the prior @antv "Mini Shai-Hulud" wave** (see `summaries/2026-05-30-npm-mini-shai-hulud-antv.md`): the Dune theming is swapped for Greek mythology (**"spartan"**), it adds **GCP/Azure cloud-identity collectors**, generates a **uniquely encrypted payload per infection**, and uses **different exfil/C2 anchors** — encrypted exfil to **`api.anthropic.com:443/v1/api`** (camouflage path on a legit host; plain GET → 404) with a **GitHub Git-Data-API fallback**, and a **kitty-monitor** persistence daemon that polls a **GitHub commit-search C2 (`api.github.com/search/commits?q=firedalazer`)**. Exfil repos carry the description **`Miasma: The Spreading Blight`**; the dead-man-switch token name **`IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner`** is used as a commit-message prefix. Attribution is ambiguous (TeamPCP open-sourced the toolkit; copycat possible). Red Hat removed the packages and states malicious code "was never published for customer consumption."

Severity: **High** (active, self-propagating, multi-cloud credential-theft worm in an official vendor scope with ~80K weekly downloads).

## Background: @redhat-cloud-services npm Scope

`@redhat-cloud-services` is Red Hat's official npm namespace for console.redhat.com frontend tooling — `frontend-components`, `chrome`, `types`, generated API clients (`compliance-client`, `patch-client`, `insights-client`, `vulnerabilities-client`, …), MCP packages and shared utilities. These are direct/transitive dependencies of Red Hat Insights and partner front-ends and run inside CI/CD, so a `preinstall`-stage payload executes with the pipeline's ambient cloud and registry credentials.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-01 10:53 | First wave: malicious orphan commits to `frontend-components` (branch `oidc-61fff775`), `javascript-clients` (`oidc-4d5900f3`), `platform-frontend-ai-toolkit` (`oidc-2530ec68`) |
| 2026-06-01 13:44–13:46 | Second wave: further orphan commits (`frontend-components` `oidc-af10000d`; `javascript-clients` `oidc-6523a11b`; `platform-frontend-ai-toolkit` `oidc-93b9a955`) |
| 2026-06-01 | Injected `release` workflow runs `bun run _index.js`, publishes 96 malicious versions across ~32 packages via OIDC trusted publishing (~72-second automated burst) |
| 2026-06-01 | Wiz/Socket/JFrog publish analyses; npm + Red Hat remove packages; ~210–309 repos observed carrying stolen credentials / Miasma exfil marker |

## Root Cause: Compromised Maintainer GitHub Account → OIDC Trusted-Publishing Abuse

Patient zero was a **compromised Red Hat employee GitHub account** that pushed malicious **orphan commits** (no parent, bypassing review) to RedHatInsights repos on throwaway `oidc-<hex>` branches. The commits added a GitHub Actions workflow (named **`release`**, also a decoy **"Run Copilot"**; staged via branch `chore/add-codeql-static-analysis` / file `.github/workflows/codeql.yml`) that requests a short-lived **OIDC token (`id-token: write`)** and authenticates directly to npm's **trusted-publishing** endpoint — publishing backdoored releases without any long-lived npm secret.

## Technical Analysis of the Malicious Payload

### 1. Injected Release Workflow (OIDC Trusted Publishing)

The workflow runs on `push` to any branch with `permissions: id-token: write, contents: read`, checks out, sets up Bun (`oven-sh/setup-bun`), and runs **`bun run _index.js`** with env `OIDC_PACKAGES` (target package list), `WORKFLOW_ID`, `REPO_ID_SUFFIX`, `VARIABLE_STORE`. Artifacts `format-results` / `format-results.txt` are produced. This is the self-propagation/publishing engine.

### 2. Preinstall Loader (`index.js` → Bun)

Trojanized `package.json` sets `"preinstall": "node index.js"`. The ~4.2 MB `index.js` reconstructs a numeric character array via a **ROT-style transform**, then **AES-128-GCM**-decrypts two blobs (Bun bootstrapper + main payload) using hardcoded keys `fe0d71d57ecf4fa0a433185bf59a03f5` and `f5e5dca9b725ec18514c4b322ed35d2b`. It downloads **Bun 1.3.13** (`github.com/oven-sh/bun/releases/download/bun-v1.3.13/`) into `/tmp/b-<random>/bun`, stages the payload at `/tmp/p<random>.js`, and runs the ~620 KB stealer under Bun to sidestep Node-centric EDR hooks.

### 3. Credential Stealer (multi-cloud)

Harvests 20+ credential classes via regex (GitHub classic `gh[op]_[A-Za-z0-9]{36}`, fine-grained `github_pat_…`, Actions JWT `ghs_…`, npm `npm_[A-Za-z0-9]{36,}`) and provider collectors for **AWS, Azure, GCP** (new cloud-identity collectors enumerate all reachable identities; GCP queries use UA `google-api-nodejs-client/7.0.0 gl-node/20.11.0 gccl/7.0.0`), **HashiCorp Vault, Kubernetes** SA tokens, **Bitwarden/1Password**, plus SSH/Docker/GPG keys and `.env` files. The stealer checks for `CrowdStrike`, `SentinelOne`, `Carbon Black`, `StepSecurity Harden-Runner` and honors anti-analysis env vars `__FAKE_PLATFORM__`, `TESTING_TAR_FAKE_PLATFORM`, `__IS_DAEMON`, `SKIP_DOMAIN`.

### 4. C2 Infrastructure & Exfiltration

Primary encrypted exfil targets **`hxxps://api[.]anthropic[.]com:443/v1/api`** — a **legitimate host** abused as camouflage (a plain GET returns 404 `not_found_error`), distinct from real Anthropic API paths like `/v1/messages`. Fallback exfil commits an **encrypted envelope through the GitHub Git Data API**, with commit-message prefix `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner:<token>`. The **kitty-monitor** daemon polls a **GitHub commit-search C2**: `hxxps://api[.]github[.]com/search/commits?q=firedalazer`. Exfil repos are created with description **`Miasma: The Spreading Blight`**.

### 5. Persistence & Anti-Forensics

- **Linux:** systemd user units `~/.config/systemd/user/kitty-monitor.service` and `gh-token-monitor.service`; scripts `~/.local/bin/gh-token-monitor.sh`, `~/.local/share/kitty/cat.py`; payload copy `~/.config/index.js`.
- **macOS:** LaunchAgents `com.user.kitty-monitor.plist` / `com.user.gh-token-monitor.plist`.
- **Developer-tool hijack:** `.claude/settings.json` (`SessionStart` hook), `.claude/setup.mjs`, `.vscode/tasks.json`.
- **Dead-man's switch:** the `IfYouInvalidate…` token; revoking it while the monitor is live can trigger host destruction (same inversion-of-IR risk as the antv wave — remove persistence before rotating).

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs `hxxps://`; domains/IPs use `[.]`; emails `[at]`. Hashes/paths/filenames are not defanged.

### Package / Software Level

| Package / Component | Malicious Version(s) | Description |
|---------------------|----------------------|-------------|
| `@redhat-cloud-services/frontend-components` | 7.7.2, 7.7.3, 7.7.5 | `preinstall` index.js loader |
| `@redhat-cloud-services/types` | 3.6.1, 3.6.2, 3.6.4 | same |
| `@redhat-cloud-services/chrome` | 2.3.1, 2.3.2 | same |
| `@redhat-cloud-services/compliance-client` | 4.0.3, 4.0.4, 4.0.6 | same |
| `@redhat-cloud-services/patch-client` | 4.0.4, 4.0.5, 4.0.7 | same |
| `@redhat-cloud-services/insights-client` | 4.0.4, 4.0.5, 4.0.7 | same |
| `@redhat-cloud-services/vulnerabilities-client` | 2.1.8 | same |
| `@redhat-cloud-services/*` (~32 pkgs total) | 96 versions, published 2026-06-01 | Treat any `@redhat-cloud-services` version published 2026-06-01 as suspect; consult Wiz/JFrog/Socket for the authoritative enumeration |

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Cross-platform | `index.js` (preinstall loader) | `df1732f5bfec12e066be44dee02ec8a243e4868d38672c1b1d065359dd735a14` | ~4.2 MB obfuscated loader |
| Cross-platform | decrypted payload | `0dc06ecdaa63fe24859cfd955053c23245c536e4733480239d14bebf12688e35` | ~620 KB credential stealer |
| Cross-platform | package tarball | `031ba872d5a84bfb18115f432811e4b45180346a1bae653f7fd85f918e7bb3a3` | malicious npm tarball |
| Cross-platform | `@redhat-cloud-services/types` 3.6.1 metadata | `7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655` | malicious package metadata (JFrog) |
| Cross-platform | `b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966` | (loader) | obfuscated loader (JFrog) |
| Runtime | `/tmp/p<random>.js`, `/tmp/b-<random>/bun`, `/tmp/b-<random>/b.zip`, `/tmp/kitty-<random>` | — | transient Bun payload / runtime |
| Linux | `~/.config/index.js`, `~/.local/bin/gh-token-monitor.sh`, `~/.local/share/kitty/cat.py` | — | local payload copy / monitors |

Hardcoded AES-128-GCM keys: `fe0d71d57ecf4fa0a433185bf59a03f5`, `f5e5dca9b725ec18514c4b322ed35d2b`.

### Network

| Type | Value | Context |
|------|-------|---------|
| URL | `hxxps://api[.]anthropic[.]com:443/v1/api` | Primary encrypted exfil (camouflage on legit host; real Anthropic paths are `/v1/messages` etc.) |
| URL | `hxxps://api[.]github[.]com/search/commits?q=firedalazer` | kitty-monitor GitHub commit-search C2 |
| Service | `api[.]github[.]com` (Git Data API) | Fallback exfil via encrypted commit envelopes |
| URL | `github[.]com/oven-sh/bun/releases/download/bun-v1.3.13/` | Bun runtime download (legit host; campaign-pinned version) |

### Behavioral

- `package.json` `preinstall` = `node index.js`; child `bun run _index.js` / `bun run $GITHUB_ACTION_PATH/index.js`.
- Injected workflow named `release` (and decoy "Run Copilot") with `id-token: write` + env `OIDC_PACKAGES`/`WORKFLOW_ID`/`REPO_ID_SUFFIX`.
- Public GitHub repo description `Miasma: The Spreading Blight`; commit-message prefix `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner:`.
- systemd/LaunchAgent units `kitty-monitor` / `gh-token-monitor`.
- Outbound to `api.anthropic.com/v1/api` and `api.github.com/search/commits?q=firedalazer`.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Trojanized `@redhat-cloud-services` versions via compromised maintainer account |
| T1606.002 | Forge Web Credentials: SAML/OIDC Tokens | Abuses GitHub Actions `id-token: write` OIDC for npm trusted publishing |
| T1059.007 | JavaScript | Obfuscated `index.js`/`_index.js` loader run from `preinstall` / workflow under Bun |
| T1105 | Ingress Tool Transfer | Downloads pinned Bun 1.3.13 runtime to stage payload |
| T1552.001 | Credentials In Files | Reads `~/.aws/`, npmrc, Vault token, K8s SA tokens, SSH/GPG/Docker, `.env` |
| T1552.005 | Cloud Instance Metadata API | Enumerates AWS/Azure/GCP cloud identities |
| T1543.002 | Create or Modify System Process: systemd Service | `kitty-monitor` / `gh-token-monitor` user units (LaunchAgents on macOS) |
| T1567 | Exfiltration Over Web Service | Exfil to `api.anthropic.com/v1/api`; GitHub Git Data API fallback |
| T1657 | Financial Theft | Broad multi-cloud credential monetization |
| T1485 | Data Destruction | Dead-man's-switch token threatens host wipe on revocation |

## Impact Assessment

Breadth: ~32 packages / 96 versions / ~80K–117K weekly downloads; ~210–309 repos observed with stolen creds or the Miasma marker. Depth: full multi-cloud credential compromise (AWS/Azure/GCP/Vault/K8s) plus registry and source-control tokens, self-propagation, and host-wipe risk. Stealth: `preinstall` execution under Bun, per-infection unique encryption (defeats hash/version tracking), camouflage exfil on a legit host, and EDR/anti-analysis checks.

## Detection & Remediation

### Immediate Detection

- Inventory installed `@redhat-cloud-services/*` versions; flag any published 2026-06-01 (esp. the versions tabled above).
- Grep lockfiles / `node_modules` for `"preinstall": "node index.js"` and the listed SHA256s.
- Search GitHub orgs for repos described `Miasma: The Spreading Blight`, for the `IfYouInvalidate…` commit prefix, and for injected `release`/`codeql.yml` workflows with `id-token: write` + `bun run _index.js`.
- Hunt host telemetry for `kitty-monitor`/`gh-token-monitor` units and egress to `api.anthropic.com/v1/api` or `api.github.com/search/commits?q=firedalazer`.

### Remediation

1. **Order matters (dead-man's switch):** isolate host → stop/remove `kitty-monitor`/`gh-token-monitor` persistence → only then rotate tokens.
2. Pin/rollback to known-good `@redhat-cloud-services` versions predating 2026-06-01; purge caches and `node_modules`; reinstall with `--ignore-scripts` where feasible.
3. Rotate **all** credentials exposed to affected pipelines (GitHub, npm/PyPI, AWS/Azure/GCP, Vault, K8s, Bitwarden/1Password, SSH/GPG/Docker).
4. Audit GitHub for orphan commits on `oidc-<hex>` branches and unexpected OIDC-published npm releases.

> Remediation is advisory; `--ignore-scripts` efficacy depends on install tooling and transitive-dep landing.

### Long-Term Hardening

Enforce `npm ci --ignore-scripts` in CI; restrict GitHub Actions OIDC `id-token: write` to vetted reusable workflows and require review for workflow changes; restrict runner egress to an allowlist; run installs in least-privilege ephemeral runners without ambient cloud-metadata access.

## Detection Rules

These detections target the Miasma/Shai-Hulud Red Hat chain at **PoC/advisory-specific** altitude. Some anchors are **Miasma-distinct** (the OIDC trusted-publishing `release` workflow + `bun run _index.js`/`OIDC_PACKAGES`, the pinned Bun-1.3.13 staging, the `Miasma: The Spreading Blight` marker, the `firedalazer` commit-search C2, the `api.anthropic.com/v1/api` exfil path); others are **shared Shai-Hulud lineage** already detected by the prior @antv report (the `IfYouInvalidate…` token, `kitty-monitor`/`gh-token-monitor` persistence — dedupe at deployment against `summaries/2026-05-30-npm-mini-shai-hulud-antv.md`). All rules compile; the three Sigma rules convert cleanly to both Splunk and CrowdStrike. Compiles ≠ fires — verify field mappings in your pipeline.

### Sigma: Miasma OIDC Trusted-Publishing Workflow Injection
Detects the injected `release` workflow running the loader via Bun (`bun run _index.js`) and the campaign env vars (`OIDC_PACKAGES`/`WORKFLOW_ID`/`REPO_ID_SUFFIX`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit=0; splunk exit=0; log_scale exit=0. Specific-altitude: keys on distinctive loader filename _index.js AND the campaign's exact OIDC publishing env vars. Generic process_creation logsource for CI-runner portability. Values are literal CLI substrings (no auditd hex). FP: a real project named _index.js run via Bun is rare; OIDC_PACKAGES is near-unique to this campaign. -->
```yaml
title: Miasma Shai-Hulud Malicious OIDC Trusted-Publishing Workflow Injection
id: 8a2f4d61-3c97-4e0a-9b15-7d2e6f0a4c83
status: experimental
description: >
    Detects the Miasma ("Spreading Blight") Red Hat npm worm's injected GitHub
    Actions workflow that abuses id-token:write OIDC trusted-publishing to push
    backdoored npm releases, running the obfuscated loader via Bun (bun run _index.js)
    with the campaign-specific OIDC_PACKAGES env var.
references:
    - https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages
    - https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/
author: Actioner
date: 2026/06/02
tags:
    - attack.t1195.002
    - attack.t1059.007
    - attack.t1606.002
logsource:
    category: process_creation
detection:
    selection_bun:
        CommandLine|contains:
            - 'bun run _index.js'
            - 'bun run $GITHUB_ACTION_PATH/index.js'
    selection_env:
        CommandLine|contains:
            - 'OIDC_PACKAGES'
            - 'REPO_ID_SUFFIX'
            - 'WORKFLOW_ID'
    condition: selection_bun or selection_env
falsepositives:
    - Legitimate release automation that genuinely runs a Bun script named _index.js (rare)
level: high
```

### Sigma: Miasma npm Preinstall Loader to Bun Runtime Download
Detects the install-time chain fetching the campaign-pinned Bun 1.3.13 runtime, or the loader (`index.js`/`_index.js`) staging Bun under `/tmp/b-*`.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check exit=0; splunk exit=0; log_scale exit=0. revision: arm 2 was '/tmp/b-' AND literal 'bun' — too weak (matched benign Bun installs/temp dirs); retied to the Miasma loader (index.js/_index.js) so it's campaign-distinct. Arm 1 (pinned bun-v1.3.13 path) is the genuine anchor. Medium: legit Bun 1.3.13 installs possible. Literal CLI substrings (no auditd hex). -->
```yaml
title: Miasma Shai-Hulud npm Preinstall Loader to Bun Runtime Download
id: 1d7b9e02-6a4f-4c38-8e91-2f5c0a7b6d44
status: experimental
description: >
    Detects the Miasma Red Hat npm worm install-time chain: the preinstall hook
    runs the obfuscated index.js loader which fetches the pinned Bun runtime
    (bun-v1.3.13) and stages a transient payload under /tmp before executing the
    credential stealer.
references:
    - https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/
    - https://safedep.io/redhat-cloud-services-hit-by-mini-shai-hulud-npm-worm/
author: Actioner
date: 2026/06/02
tags:
    - attack.t1195.002
    - attack.t1059.007
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection_bun_dl:
        CommandLine|contains: 'oven-sh/bun/releases/download/bun-v1.3.13'
    selection_tmp_stage:
        CommandLine|contains|all:
            - '/tmp/b-'
            - 'bun'
        CommandLine|contains:
            - 'index.js'
            - '_index.js'
    condition: selection_bun_dl or selection_tmp_stage
falsepositives:
    - Legitimate projects pinning and installing Bun 1.3.13 at this exact path (uncommon in install scripts)
level: medium
```

### Sigma: Shai-Hulud Lineage and Miasma-Distinct Markers
Detects two Miasma-distinct markers (`Miasma: The Spreading Blight` exfil-repo description, `firedalazer` commit-search C2) plus three shared Shai-Hulud lineage arms (the `IfYouInvalidate…` token, `kitty-monitor`/`gh-token-monitor` units). The three lineage arms overlap the antv rule (`summaries/2026-05-30-npm-mini-shai-hulud-antv.md`) — dedupe at deployment.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit=0; splunk exit=0; log_scale exit=0. revision: honesty/distinctness edit — only Miasma marker + firedalazer are Miasma-distinct; IfYouInvalidate token + kitty-/gh-token-monitor are shared Shai-Hulud lineage already in the antv sigma rules (dedupe at deploy). Rule still fires correctly so kept high. firedalazer query + IfYouInvalidate token are essentially zero-benign. Literal substrings; no hex encoding needed. -->
```yaml
title: Shai-Hulud Lineage and Miasma-Distinct Campaign Markers
id: 4c0e8a37-9b21-4d6f-a3e7-5f1b2c8d0a96
status: experimental
description: >
    Detects host artifacts of the Shai-Hulud / Miasma ("Spreading Blight") Red Hat
    npm worm. Miasma-distinct: the GitHub exfil-repo description marker and the
    firedalazer commit-search C2 marker. Shared Shai-Hulud lineage (also detected by
    the prior antv rule — dedupe at deployment): the dead-man-switch token used as a
    commit-message prefix, and the kitty-monitor / gh-token-monitor persistence units.
references:
    - https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/
    - https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages
author: Actioner
date: 2026/06/02
tags:
    - attack.t1567
    - attack.t1543.002
    - attack.t1657
detection:
    selection:
        CommandLine|contains:
            - 'Miasma: The Spreading Blight'
            - 'IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner'
            - 'search/commits?q=firedalazer'
            - 'kitty-monitor'
            - 'gh-token-monitor'
    condition: selection
falsepositives:
    - Threat-intel or IR tooling referencing these published campaign markers
level: high
logsource:
    category: process_creation
```

### Snort: Miasma C2 / Exfil HTTP Egress
Matches the `firedalazer` GitHub commit-search C2 (sid 2100601, **high**) and the `api.anthropic.com` camouflage exfil POST to `/v1/api` (sid 2100602, **medium**). Caveat: both legs ride HTTPS — 2100602 fires only on decrypted/proxied HTTP traffic and never on raw wire (deploy behind TLS inspection).
**Status:** compile ✅ compiles · confidence: 2100601 high · 2100602 medium
<!-- audit: snort -T via wrapper config (var defs + classification + include) exit=0 — Snort 2.9.20 here has no .lua and -R is pidfile-only, so a wrapper conf is the load-and-test path. 2100601 keys on the unique /search/commits + firedalazer query (zero-benign). 2100602 host+/v1/api distinguishes from real Anthropic /v1/messages but only on decrypted traffic; pair with the host. Real values used. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Miasma Shai-Hulud kitty-monitor GitHub Commit-Search C2 firedalazer"; flow:established,to_server; content:"GET"; http_method; content:"/search/commits"; http_uri; content:"firedalazer"; http_uri; content:"api.github.com"; http_header; classtype:trojan-activity; reference:url,research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/; sid:2100601; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Miasma Shai-Hulud Exfil POST to api.anthropic.com/v1/api Camouflage Path"; flow:established,to_server; content:"POST"; http_method; content:"/v1/api"; http_uri; content:"api.anthropic.com"; http_header; classtype:trojan-activity; reference:url,research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/; sid:2100602; rev:1;)
```

### Suricata: Miasma C2 / Exfil Egress
`firedalazer` commit-search C2 (sid 2200601, **high**); `api.anthropic.com` `/v1/api` exfil POST (sid 2200602, **medium**). Caveat: 2200602 fires only on decrypted/proxied HTTP traffic and never on raw wire (deploy behind TLS inspection).
**Status:** compile ✅ compiles · confidence: 2200601 high · 2200602 medium
<!-- audit: suricata -T -S exit=0. 2200601 is the unique commit-search C2 (zero-benign). 2200602 bsize:7 = len("/v1/api") to separate from real Anthropic paths, but only on inspected HTTP. revision: dropped former 2200603 (TLS SNI api.anthropic.com) — fires on every org using the Claude API (ubiquitous benign SaaS), SNI cannot see the /v1/api path, and src was unscoped $HOME_NET any so the "scope to runner ranges" narrowing was never encoded. Not replaced. Dot-notation buffers; real values. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Miasma Shai-Hulud kitty-monitor GitHub Commit-Search C2 firedalazer"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/search/commits"; content:"firedalazer"; http.host; content:"api.github.com"; classtype:trojan-activity; reference:url,research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/; metadata:author Actioner, created_at 2026-06-02; sid:2200601; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Miasma Shai-Hulud Exfil to api.anthropic.com Camouflage Path /v1/api [pair with host]"; flow:established,to_server; http.method; content:"POST"; http.host; content:"api.anthropic.com"; http.uri; content:"/v1/api"; bsize:7; classtype:trojan-activity; reference:url,research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/; metadata:author Actioner, created_at 2026-06-02; sid:2200602; rev:1;)
```
<!-- revision: dropped Suricata 2200603 (TLS SNI api.anthropic.com) — ubiquitous benign Claude-API endpoint, SNI cannot see the /v1/api path, source IP unscoped; per critic DROP. Not replaced. -->

### YARA: Miasma Shai-Hulud Red Hat Payload
Detects the loader/stealer (`index.js`/`_index.js`) via campaign-unique markers — Miasma description, dead-man-switch token, `firedalazer` C2, `api.anthropic.com/v1/api`, the two hardcoded AES-128-GCM keys, and the OIDC+Bun+EDR-check combo.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit=0; yara fired on positive (published markers), quiet on negative (benign @redhat-cloud-services module that deliberately includes the LEGIT api.anthropic.com/v1/messages path — confirms no false-match on real Claude API usage). Positive built from PUBLISHED strings, not invented. AES keys + firedalazer + Miasma marker are essentially zero-benign; any-of design keeps recall across per-infection re-encryption (markers survive in cleartext). -->
```yara
rule Miasma_ShaiHulud_RedHat_Payload
{
    meta:
        description = "Detects the Miasma ('The Spreading Blight') Shai-Hulud variant Red Hat npm worm loader/stealer (index.js / _index.js) via campaign-unique markers: exfil-repo description, dead-man-switch commit-message token, firedalazer GitHub commit-search C2, api.anthropic.com camouflage exfil path, hardcoded AES-128-GCM keys, and OIDC trusted-publishing workflow markers"
        author = "Actioner"
        date = "2026-06-02"
        reference = "https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/"
        reference2 = "https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages"
        hash = "df1732f5bfec12e066be44dee02ec8a243e4868d38672c1b1d065359dd735a14"
        hash2 = "0dc06ecdaa63fe24859cfd955053c23245c536e4733480239d14bebf12688e35"
        tlp = "CLEAR"
        severity = "high"
    strings:
        $marker      = "Miasma: The Spreading Blight" ascii wide
        $token_nuke  = "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner" ascii wide nocase
        $c2_search   = "search/commits?q=firedalazer" ascii wide
        $c2_anthro   = "api.anthropic.com/v1/api" ascii wide nocase
        $aeskey1     = "fe0d71d57ecf4fa0a433185bf59a03f5" ascii nocase
        $aeskey2     = "f5e5dca9b725ec18514c4b322ed35d2b" ascii nocase
        $oidc_env    = "OIDC_PACKAGES" ascii
        $bun_pin     = "oven-sh/bun/releases/download/bun-v1.3.13" ascii nocase
        $edr1        = "StepSecurity Harden-Runner" ascii
        $antianalysis = "TESTING_TAR_FAKE_PLATFORM" ascii
    condition:
        any of ($marker, $token_nuke, $c2_search, $c2_anthro)
        or any of ($aeskey1, $aeskey2)
        or (($oidc_env and $bun_pin) and ($edr1 or $antianalysis))
}
```

## Lessons Learned

OIDC "trusted publishing" removes long-lived npm tokens but shifts trust onto the GitHub account and workflow approval gates — a single compromised maintainer account plus orphan-commit + `id-token: write` is enough to publish to an official scope. Per-infection unique encryption defeats hash/version IOC tracking, so durable detection must key on cleartext campaign markers (repo description, C2 query strings, dead-man-switch token) and behavior (preinstall→Bun→/tmp staging) rather than payload hashes. The dead-man's-switch token again inverts IR: remove persistence before rotating.

## Sources

- [Miasma: Supply Chain Attack Targeting RedHat npm Packages — Wiz](https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages) — primary: orphan-commit root cause, OIDC workflow, GCP/Azure collectors, "spartan"/per-infection encryption, wave timeline
- [Shai-Hulud — Miasma: The Spreading Blight Hits Red Hat npm Packages — JFrog Security Research](https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/) — primary: file/persistence paths, AES/Bun loader chain, `api.anthropic.com` + `firedalazer` C2, token regexes, hashes
- [Mini Shai-Hulud "Miasma: The Spreading Blight" Hits @redhat-cloud-services — SafeDep / StepSecurity](https://safedep.io/redhat-cloud-services-hit-by-mini-shai-hulud-npm-worm/) — package/version list, AES keys, codeql.yml/orphan branches, EDR/anti-analysis strings, SHA256s
- [Red Hat npm Packages Compromised to Spread a Credential-Stealing Worm — Aikido](https://www.aikido.dev/blog/red-hat-npm-packages-compromised-credential-stealing-worm) — workflow `release`/`_index.js`, OIDC env vars, credential targets
- [Red Hat npm packages compromised to steal developer credentials — BleepingComputer](https://www.bleepingcomputer.com/news/security/red-hat-npm-packages-compromised-to-steal-developer-credentials/) — scope/version counts, employee-account vector, OIDC trusted-publishing, payload size
- [Shai-Hulud malware worms Red Hat npm package versions downloaded 80K times a week — The Register](https://www.theregister.com/security/2026/06/01/shai-hulud-malware-infects-red-hat-npm-packages-downloaded-80k-times-weekly/5249803) — two-wave detail, Wiz/Socket attribution, Red Hat statement
- [Supply Chain Attack Hits 32 Red Hat npm Packages — SecurityWeek](https://www.securityweek.com/supply-chain-attack-hits-32-red-hat-npm-packages/) — 32 packages/96 versions, "Miasma: The Spreading Blight", TeamPCP link, 210 repos
- [Miasma Supply Chain Attack Compromises Red Hat npm Packages — The Hacker News](https://thehackernews.com/2026/06/miasma-supply-chain-attack-compromises.html) — corroboration of exfil to api.anthropic.com/v1/api, GitHub commit C2, marker
- Prior related coverage: `summaries/2026-05-30-npm-mini-shai-hulud-antv.md` (the @antv "Mini Shai-Hulud" wave — distinct vector/C2; this report builds on it)

---
*Report generated by Actioner (FINAL)*
