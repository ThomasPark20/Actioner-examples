# Technical Analysis Report: Typosquatted npm Packages Stealing Cloud & CI/CD Secrets (vpmdhaj OpenSearch Supply-Chain) (2026-05-30)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-05-30
Version: 1.0 (DRAFT)

## Executive Summary

An active npm supply-chain campaign uses typosquatted packages impersonating OpenSearch and ElasticSearch JavaScript libraries to steal cloud and CI/CD secrets. All known packages were published on 2026-05-28 by the npm maintainer `vpmdhaj`, with version numbers artificially inflated (e.g. `1.0.9108`, `2.1.9201`) and `package.json` metadata spoofed to point at `github.com/opensearch-project/opensearch-js` to fake maturity and legitimacy. The malicious code runs via npm install lifecycle hooks (`preinstall`/`install`/`postinstall`) — so it executes on `npm install` alone, with no `require()` of the package needed — making continuous-integration runners and developer workstations the primary blast radius.

The payload is a multi-stage stealer that beacons to `hxxp://aab[.]sportsontheweb[.]net/x[.]php` (port 80) carrying a campaign-unique `X-Supply: 1` HTTP header, then drops a ~195KB Bun-compiled stage-2 credential harvester. It systematically targets AWS instance/task metadata (IMDSv2 at 169.254.169[.]254, ECS at 169.254.170[.]2), AWS STS (`GetCallerIdentity`/`AssumeRole`), Secrets Manager across 16+ regions, HashiCorp Vault tokens, npm auth tokens, and GitHub Actions environment context. Defenders should treat the `X-Supply: 1` header and the `/x.php` C2 URL as high-confidence proxy/network indicators and the three published stager SHA256 hashes as exact-match file indicators.

## Background: npm Ecosystem & OpenSearch/ElasticSearch Client Libraries

OpenSearch and ElasticSearch are widely deployed search/analytics engines whose official Node.js clients (`@opensearch-project/opensearch`, `@elastic/elasticsearch`) are common dependencies in cloud and data-platform tooling. Because these libraries are frequently installed on servers and CI/CD runners that hold cloud roles and secrets, packages impersonating them are a high-value vector: a single trojanized install hook executing inside a pipeline can reach instance metadata, assumed roles, and secret stores. npm's lifecycle hooks (`preinstall`/`install`/`postinstall`) execute arbitrary code at install time, which this campaign abuses to run before any human inspects the dependency.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-28 | Maintainer `vpmdhaj` publishes all known malicious packages to npm with inflated versions and spoofed repository metadata |
| 2026-05-28 | Packages distribute Gen-1 (`preinstall.js`/`index.js`) and Gen-2 (`setup.mjs`) install-hook stagers |
| 2026-05-28 | Stagers beacon to aab[.]sportsontheweb[.]net/x[.]php and drop Bun stage-2 credential harvester |
| 2026-05-28 | Microsoft Security publishes advisory documenting the campaign |

## Root Cause: Supply-Chain Compromise via Typosquatting + Install Hooks

The initial access vector is dependency confusion / typosquatting: developers or CI configs install a package whose name resembles a legitimate OpenSearch/ElasticSearch library (e.g. `opensearch-setup`, `elastic-opensearch-helper`, `search-cluster-setup`). The package's `package.json` declares install lifecycle hooks that execute the bundled stager automatically during `npm install`. No application-level `require()` of the package is required — install alone triggers execution — so the compromise lands inside build/CI environments where cloud credentials are routinely present.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection — Typosquatted Packages & Install Hooks

Two generations of staging are observed:

- **Gen-1:** `package.json` declares `install` + `preinstall` + `postinstall` hooks invoking `preinstall.js` / `index.js`.
- **Gen-2:** `package.json` declares a `preinstall` hook invoking `setup.mjs`.

Both spoof `homepage`/`repository`/`bugs` to `github.com/opensearch-project/opensearch-js` and inflate versions (1.0.7265+, 1.0.9108, 2.1.9201) to mimic a mature, trusted package.

### 2. Stager → Bun Stage-2 Credential Harvester

The stager beacons to the C2 (stage-1), retrieves stage-2 (gzipped, Bun-compiled), and writes it into `node_modules` as `payload.bin`. When spawning the detached stage-2 process it sets the environment marker `__DAEMONIZED=1`. Stage-2 is a ~195KB Bun executable script (`opensearch_init.js`, alt `ai_init.js`) that performs credential harvesting. Known artifact hashes:

- `preinstall.js` (Gen-1 stager): `638788afc4f1b5860a328312caf5895abd5f5632d28a4f2a85b09076e270d15d`
- `setup.mjs` (Gen-2 stager): `77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d`
- `payload.gz` (gzipped Bun stage-2): `bfa149694ec6411c23936311a999163ade54d6f38e2f4b0e3cfb8cb67bd7cfaa`

### 3. C2 Infrastructure

- **Domain:** aab[.]sportsontheweb[.]net
- **URL:** hxxp://aab[.]sportsontheweb[.]net/x[.]php (stage-1 beacon and stage-2 retrieval), port 80 (plain HTTP).
- **Campaign-unique HTTP header:** `X-Supply: 1` — a high-confidence proxy indicator, used as a fast-pattern anchor in the Snort/Suricata rules below.

### 4. Platform-Specific Behavior

The stagers and Bun stage-2 are designed for the npm install context (Linux CI runners and developer hosts are the dominant target). Stage-2 targets cloud/CI credential surfaces rather than OS-specific persistence:

- **AWS:** IMDSv2 (169.254.169[.]254), ECS task metadata (169.254.170[.]2), AWS environment credentials, STS `GetCallerIdentity`/`AssumeRole`, Secrets Manager `ListSecrets`/`GetSecretValue` across 16+ regions.
- **HashiCorp Vault:** reads `VAULT_TOKEN` / `VAULT_AUTH_TOKEN`.
- **npm:** `/-/whoami` and `/-/npm/v1/tokens` (npm auth token theft, enabling onward package poisoning).
- **GitHub Actions:** reads `GITHUB_REPOSITORY` / `RUNNER_OS` for CI context fingerprinting.

### 5. Anti-Forensics / Evasion Techniques

The stage-2 payload is spawned as a detached/daemonized process (marker `__DAEMONIZED=1`) to survive the install step, and is delivered gzipped and Bun-compiled rather than as readable JS, hindering casual inspection. Inflated version numbers and spoofed GitHub metadata are social-engineering evasions designed to pass cursory dependency review.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs use `hxxp://`; domains/IPs use `[.]`; emails use `[at]`. Hashes and file paths are not defanged.

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| @vpmdhaj/elastic-helper | 1.0.7269 | Typosquat, install-hook stager (Gen-1/2) |
| @vpmdhaj/devops-tools | 1.0.7267 | Typosquat, install-hook stager |
| @vpmdhaj/opensearch-setup | 1.0.7267 | Typosquat, install-hook stager |
| @vpmdhaj/search-setup | 1.0.7268 | Typosquat, install-hook stager |
| opensearch-security-scanner | 1.0.10 | Typosquat, install-hook stager |
| opensearch-setup | 1.0.9103 | Typosquat, install-hook stager |
| opensearch-setup-tool | 1.0.9108 | Typosquat, install-hook stager |
| opensearch-config-utility | 1.0.9106 | Typosquat, install-hook stager |
| search-engine-setup | 1.0.9108 | Typosquat, install-hook stager |
| search-cluster-setup | 1.0.9104 | Typosquat, install-hook stager |
| elastic-opensearch-helper | 1.0.9108 | Typosquat, install-hook stager |
| vpmdhaj-opensearch-setup | 1.0.9102 | Typosquat, install-hook stager |
| env-config-manager | 2.1.9201 | Typosquat, install-hook stager |
| app-config-utility | 1.0.9300 | Typosquat, install-hook stager |

All published 2026-05-28 by npm maintainer `vpmdhaj`; `package.json` homepage/repository/bugs spoofed to `github.com/opensearch-project/opensearch-js`.

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | (in package) preinstall.js | 638788afc4f1b5860a328312caf5895abd5f5632d28a4f2a85b09076e270d15d | Gen-1 install-hook stager |
| Linux | (in package) setup.mjs | 77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d | Gen-2 install-hook stager |
| Linux | node_modules/**/payload.gz | bfa149694ec6411c23936311a999163ade54d6f38e2f4b0e3cfb8cb67bd7cfaa | Gzipped Bun stage-2 payload |
| Linux | node_modules/**/payload.bin | - | Stage-2 dropped in node_modules |
| Linux | opensearch_init.js (~195KB) | - | Bun stage-2 credential harvester |
| Linux | ai_init.js | - | Alternate Gen-2 stage-2 |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | aab[.]sportsontheweb[.]net | C2 (stage-1 beacon + stage-2 retrieval) |
| URL Pattern | hxxp://aab[.]sportsontheweb[.]net/x[.]php | C2 endpoint, port 80 |
| HTTP Header | `X-Supply: 1` | Campaign-unique beacon header (high-confidence) |

### Behavioral

- Node.js/Bun process spawned from an npm install lifecycle hook (`preinstall`/`postinstall`) that immediately reads cloud/CI credentials.
- Environment marker `__DAEMONIZED=1` set when the stager spawns the detached stage-2 payload.
- Access to AWS IMDS 169.254.169[.]254 / ECS 169.254.170[.]2, STS `GetCallerIdentity`/`AssumeRole`, Secrets Manager `GetSecretValue`/`ListSecrets`, Vault `VAULT_TOKEN`/`VAULT_AUTH_TOKEN`, npm `/-/npm/v1/tokens` — within an install context.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Typosquatted npm packages impersonating OpenSearch/ElasticSearch libraries |
| T1547.013 | Boot or Logon Autostart Execution: XDG Autostart (install-hook-style auto-exec) | npm install lifecycle hooks auto-execute the stager |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP beacon to /x.php with X-Supply header |
| T1555 | Credentials from Password Stores | Harvests AWS Secrets Manager, Vault, npm tokens |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Queries AWS IMDSv2 / ECS task metadata |
| T1087 | Account Discovery | STS GetCallerIdentity to enumerate identity/role |
| T1580 | Cloud Infrastructure Discovery | Enumerates Secrets Manager across 16+ regions, AssumeRole |
| T1078 | Valid Accounts | Steals cloud/CI credentials for reuse |

<!-- audit: artifact list maps T1547.013 loosely — Microsoft cites T1547.013 for the install-hook auto-execution; the closer npm-specific behavior is lifecycle-hook abuse, no exact ATT&CK sub-technique exists, so T1547.013 retained per source. T1552.005/T1528 added for IMDS/token theft specificity. -->

## Impact Assessment

- **Breadth:** 14+ packages published in one day by a single maintainer; impacts any environment that installed them. CI/CD runners and developer hosts are the principal targets.
- **Depth:** Full cloud/CI credential theft — AWS role credentials via IMDS/STS, Secrets Manager contents across 16+ regions, Vault tokens, npm publish tokens (enabling onward supply-chain poisoning), and GitHub Actions context.
- **Stealth:** Executes at install time before code review; payload is gzipped/Bun-compiled and daemonized; spoofed metadata defeats cursory inspection.

## Detection & Remediation

### Immediate Detection

- Search package manifests / lockfiles for any package by maintainer `vpmdhaj` or the names listed above:
  `grep -RInE "vpmdhaj|opensearch-setup|elastic-opensearch-helper|search-cluster-setup|env-config-manager|app-config-utility" package*.json` across repos and CI configs.
- Hunt proxy/web logs for outbound requests to `aab[.]sportsontheweb[.]net`, the `/x.php` path, or the `X-Supply: 1` request header.
- Search hosts/CI runners for dropped files `payload.bin`, `opensearch_init.js`, `ai_init.js` under `node_modules`, and for the three stager SHA256 hashes.

### Remediation

1. **Contain:** Isolate any affected CI runner / host; block `aab[.]sportsontheweb[.]net` at egress.
2. **Eradicate:** Remove the offending packages, purge `node_modules` and npm cache, delete dropped `payload.*`/`*_init.js` artifacts.
3. **Rotate (assume compromise):** Rotate all credentials reachable from the affected environment — AWS access keys / assumed-role sessions, Secrets Manager values, Vault tokens, npm auth tokens (`/-/npm/v1/tokens`), and any GitHub Actions secrets. Revoke and reissue.
4. **Audit:** Review CloudTrail (STS AssumeRole/GetCallerIdentity, Secrets Manager GetSecretValue) and npm token usage for unauthorized activity post-2026-05-28.

### Long-Term Hardening

- Enforce IMDSv2 with hop limit 1 and, where feasible, deny IMDS access from build steps; scope CI roles to least privilege.
- Use lockfiles with integrity pinning, an internal npm registry/allowlist, and `--ignore-scripts` for installs in untrusted contexts.
- Short-lived, scoped CI credentials (OIDC over long-lived keys); secret scanning on egress.

## Detection Rules

These detections cover the campaign at three layers: the network C2 (the `X-Supply: 1` header and the `/x.php` URL on aab[.]sportsontheweb[.]net) via Snort and Suricata; the install-hook-to-cloud-credential chain and the dropped stage-2 files via Sigma; and the three published stager SHA256 hashes plus campaign-unique strings via YARA. All rules compiled cleanly (Sigma converts to Splunk and CrowdStrike log_scale — the real portability oracle here, as `sigma check`'s MITRE tag validator hard-fails offline in this sandbox; the YARA string rule fired on a published-string positive and stayed quiet on a benign negative) — but compiles/fires-in-test does not guarantee it fires in your pipeline, so validate field mappings against your own telemetry.

### Sigma: npm Install-Hook Spawning Cloud Credential Harvester
Detects a Node.js/Bun process spawned from an npm install hook that immediately touches AWS IMDS/STS/Secrets Manager, Vault tokens, or npm tokens — the campaign's install-time credential-theft chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check could NOT complete in this sandbox — its ATTACK/D3FEND tag validator unconditionally fetches MITRE D3FEND data and the network returns HTTP 403 (cannot be bypassed via -x/--validation-config; environment limitation, not a rule defect). Compile/portability therefore proven via the conversion oracle: sigma convert --without-pipeline -t splunk = exit 0 AND -t log_scale = exit 0 (both produced valid queries). Pairs install-hook context (ParentCommandLine) OR the credential/marker targets with a node/bun process to avoid alerting on all IMDS access. 169.254.169.254/170.2 and __DAEMONIZED are real (un-defanged) literal substrings, not IP-typed matches, so no IPAddress modifier. FP: rare cloud-aware install scripts; tune via package allowlist. No fitting -p pipeline for generic linux process_creation, so portability is syntactic-valid, not schema-mapped. -->
```yaml
title: npm Install-Hook Spawning Cloud Credential Harvester (Typosquat OpenSearch Supply-Chain)
id: 3f1c9a2e-7d4b-4e8a-9c61-2a5b8e0f1d34
status: experimental
description: Detects a Node.js process spawned from an npm install lifecycle hook that immediately reaches into cloud/CI credential stores (AWS IMDS/STS/Secrets Manager, HashiCorp Vault, npm tokens), consistent with the vpmdhaj typosquatted OpenSearch/ElasticSearch npm campaign.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/
author: Actioner
date: 2026/05/30
tags:
    - attack.t1195.002
    - attack.t1071.001
    - attack.t1552.005
    - attack.t1555
    - attack.t1580
    - attack.t1528
logsource:
    category: process_creation
    product: linux
detection:
    selection_proc:
        Image|endswith:
            - '/node'
            - '/bun'
    selection_hook:
        ParentCommandLine|contains:
            - 'preinstall'
            - 'postinstall'
            - 'npm install'
            - 'npm ci'
    selection_target:
        CommandLine|contains:
            - '169.254.169.254'
            - '169.254.170.2'
            - 'GetCallerIdentity'
            - 'AssumeRole'
            - 'GetSecretValue'
            - 'ListSecrets'
            - 'VAULT_TOKEN'
            - 'VAULT_AUTH_TOKEN'
            - '/-/npm/v1/tokens'
            - '__DAEMONIZED'
    condition: selection_proc and (selection_hook or selection_target)
falsepositives:
    - Legitimate cloud-aware npm packages that query instance metadata during installation (rare; tune by package allowlist)
level: high
```

### Sigma: Dropped Bun Stage-2 Credential Harvester in node_modules
Detects creation of the campaign's stage-2 artifacts (payload.bin/.gz, opensearch_init.js, ai_init.js) inside a node_modules tree.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked offline (same D3FEND-fetch 403 limitation as the rule above). Compile/portability proven via conversion: sigma convert --without-pipeline -t splunk = exit 0 AND -t log_scale = exit 0. Anchors on campaign-specific filenames AND node_modules path to keep FP near-zero. file_event/linux maps to Sysmon-for-Linux EID 11 or auditd file watch; no fitting -p pipeline, so syntactic-valid not schema-mapped. -->
```yaml
title: Dropped Bun Stage-2 Credential Harvester in node_modules (Typosquat OpenSearch Supply-Chain)
id: b7e2d4c8-1a93-4f6d-8b20-9c3e7f5a6e11
status: experimental
description: Detects creation of the campaign-specific stage-2 artifacts (payload.bin, opensearch_init.js, ai_init.js) inside a node_modules tree, dropped by the vpmdhaj typosquatted npm packages during npm install.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/
author: Actioner
date: 2026/05/30
tags:
    - attack.t1195.002
    - attack.t1105
    - attack.t1564
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|contains: 'node_modules'
    selection_name:
        TargetFilename|endswith:
            - '/payload.bin'
            - '/payload.gz'
            - '/opensearch_init.js'
            - '/ai_init.js'
    condition: selection_path and selection_name
falsepositives:
    - Unlikely; these filenames within node_modules are specific to this campaign
level: high
```

### Snort: npm Typosquat C2 (X-Supply header + x.php beacon)
Two rules: outbound HTTP carrying the campaign-unique `X-Supply: 1` header, and requests for `/x.php` to host aab[.]sportsontheweb[.]net.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: validated as single-line rules: snort -c <conf> -T exit 0 ("successfully validated the configuration"); Snort 2.9 requires each rule on one line (multi-line shown here for readability — collapse to one line per rule when deploying, or use trailing backslash continuations). |3a 20| = ": " literal in the raw header so "X-Supply: 1" matches exactly; fast_pattern on the header. Real un-defanged C2 values. Port-based ($HTTP_PORTS) since Snort 2.9 has no http proto keyword. sid 2100501-2100502. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"ACTIONER npm Typosquat C2 - X-Supply header beacon (vpmdhaj OpenSearch supply-chain)";
    flow:established,to_server;
    content:"X-Supply|3a 20|1"; http_header; fast_pattern; nocase;
    sid:2100501; rev:1;
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/;
)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"ACTIONER npm Typosquat C2 - x.php stager on aab.sportsontheweb.net (vpmdhaj OpenSearch supply-chain)";
    flow:established,to_server;
    content:"/x.php"; http_uri;
    content:"aab.sportsontheweb.net"; http_header; nocase;
    sid:2100502; rev:1;
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/;
)
```

### Suricata: npm Typosquat C2 (X-Supply header + x.php beacon)
Two rules mirroring the Snort logic using dot-notation sticky buffers (`http.request_header`, `http.host`, `http.uri`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: validated as single-line rules: suricata -T -S <rules> -l /tmp exit 0, "2 rules successfully loaded, 0 rules failed" (collapse each rule to one line when deploying). |3a 20| = ": " inside request_header buffer. http.host carries no nocase (buffer is already lowercased — adding nocase is a parse error in Suricata 7). Real un-defanged C2 values. sid 2200501-2200502; metadata author/created_at present. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Actioner - npm Typosquat C2 X-Supply Header Beacon (vpmdhaj OpenSearch supply-chain)";
    flow:established,to_server;
    http.request_header; content:"X-Supply|3a 20|1"; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/;
    metadata:author Actioner, created_at 2026-05-30;
    sid:2200501; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Actioner - npm Typosquat C2 x.php Stager on aab.sportsontheweb.net (vpmdhaj OpenSearch supply-chain)";
    flow:established,to_server;
    http.host; content:"aab.sportsontheweb.net";
    http.uri; content:"/x.php";
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/;
    metadata:author Actioner, created_at 2026-05-30;
    sid:2200502; rev:1;
)
```

### YARA: vpmdhaj OpenSearch Typosquat Stagers (hash + strings)
Two rules: exact-match on the three published stager SHA256 hashes, and a strings rule keyed on campaign-unique markers (C2 host, /x.php, X-Supply, __DAEMONIZED).
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Strings rule sample-tested: positive built from PUBLISHED strings (aab.sportsontheweb.net, /x.php, X-Supply, __DAEMONIZED) MATCHED; benign opensearch-client negative was QUIET. Hash rule is exact-match (one variant each) — provenance from advisory, not sample-run (no live binary), hence no "fired" claim for it. Strings rule condition requires C2 host alone, or X-Supply paired with /x.php or __DAEMONIZED, to keep FP low. -->
```yara
import "hash"

rule npm_typosquat_opensearch_vpmdhaj_stagers
{
    meta:
        description = "Matches the vpmdhaj typosquatted OpenSearch/ElasticSearch npm supply-chain stagers by known SHA256 (Gen-1 preinstall.js, Gen-2 setup.mjs, gzipped Bun stage-2 payload)"
        author = "Actioner"
        date = "2026-05-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/"
        hash = "638788afc4f1b5860a328312caf5895abd5f5632d28a4f2a85b09076e270d15d"
        hash = "77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d"
        hash = "bfa149694ec6411c23936311a999163ade54d6f38e2f4b0e3cfb8cb67bd7cfaa"
    condition:
        hash.sha256(0, filesize) == "638788afc4f1b5860a328312caf5895abd5f5632d28a4f2a85b09076e270d15d" or
        hash.sha256(0, filesize) == "77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d" or
        hash.sha256(0, filesize) == "bfa149694ec6411c23936311a999163ade54d6f38e2f4b0e3cfb8cb67bd7cfaa"
}

rule npm_typosquat_opensearch_vpmdhaj_strings
{
    meta:
        description = "Matches vpmdhaj typosquat OpenSearch npm stager/payload by campaign-unique strings (C2 host, x.php beacon, X-Supply header, daemonize marker)"
        author = "Actioner"
        date = "2026-05-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/"
    strings:
        $c2_host = "aab.sportsontheweb.net" ascii
        $c2_url  = "/x.php" ascii
        $hdr     = "X-Supply" ascii
        $daemon  = "__DAEMONIZED" ascii
    condition:
        $c2_host or ($hdr and ($c2_url or $daemon))
}
```

## Lessons Learned

Install-time code execution via npm lifecycle hooks remains a potent supply-chain vector: this campaign achieved cloud/CI credential theft without any victim ever importing the package. The combination of typosquatting, inflated versions, and spoofed GitHub metadata shows social-engineering of the dependency-review step is a deliberate, effective evasion. Defenders should treat CI runners as crown-jewel-adjacent (they hold live cloud roles and tokens), default to `--ignore-scripts` plus registry allowlists, and enforce IMDSv2 with restricted hop limits so a single poisoned dependency cannot pivot to instance credentials.

## Sources

- [Microsoft Security Blog — Typosquatted npm packages used to steal cloud and CI/CD secrets](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/) — primary advisory; source of all packages, hashes, C2, and credential-targeting detail
- [MITRE ATT&CK — T1195.002 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/) — technique reference for the supply-chain vector
- [MITRE ATT&CK — T1552.005 Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/) — technique reference for IMDS credential theft
- [npm Docs — scripts (lifecycle hooks)](https://docs.npmjs.com/cli/v10/using-npm/scripts) — reference for preinstall/install/postinstall execution behavior abused here

---
*Report generated by Actioner*
