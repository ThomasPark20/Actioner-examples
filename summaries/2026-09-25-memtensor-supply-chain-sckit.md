# Technical Analysis Report: MemTensor Supply Chain Attack - sckit Credential Stealer (2026-09-25)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-25
Version: 1.0 DRAFT

## Executive Summary

On September 23, 2026, threat actors compromised the legitimate MemTensor AI memory framework by hijacking GitHub Actions CI/CD pipelines to steal npm and PyPI publish tokens. Using these tokens, they published trojanized versions of two packages -- the npm package `@memtensor/memos-cloud-openclaw-plugin` (versions 0.1.21, 0.1.23, 0.1.25) and the PyPI package `MemoryOS` (version 2.0.34). Both deliver a cross-platform, statically-linked Go binary called "sckit" that functions as a credential stealer and supply-chain worm. The implant targets Windows, Linux, and macOS, harvesting developer credentials (npm/PyPI tokens, GitHub/GitLab PATs, AWS keys, SSH keys, Vault tokens, and more) and exfiltrating them to C2 infrastructure under `skyleen[.]fr`. The worm component includes templates to self-propagate by publishing poisoned versions to other packages and GitHub Actions workflows using stolen credentials. The Go module path `supplychain.local/campaign/cmd/implant` was embedded in the binaries. Three malicious npm releases were published within a 2-hour-14-minute window, alternating with clean versions to evade detection. The PyPI variant was quarantined and npm versions removed.

## Background: MemTensor and AI Supply Chain Risk

MemTensor is an open-source memory framework for large language models (LLMs) and AI agents. Its MemOS Cloud OpenClaw plugin is an npm package used to integrate memory-recall capabilities into AI agent pipelines. The PyPI package `MemoryOS` provides the Python equivalent. Both packages had established trust in the AI/ML developer community, making them high-value supply chain targets. The attack exploited the CI/CD trust boundary -- GitHub Actions pipelines that publish packages -- rather than compromising maintainer accounts directly.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-23 ~T1 | Threat actor pushes commits to MemTensor GitHub repos causing CI workflows to leak publish tokens |
| 2026-09-23 ~T1+30m | `@memtensor/memos-cloud-openclaw-plugin` v0.1.21 published to npm (malicious) |
| 2026-09-23 ~T1+60m | v0.1.22 published (clean -- community intervention) |
| 2026-09-23 ~T1+90m | v0.1.23 published (malicious, second attempt) |
| 2026-09-23 ~T1+100m | v0.1.24 published (clean) |
| 2026-09-23 ~T1+134m | v0.1.25 published (malicious, third attempt with TLS cert bundle) |
| 2026-09-23 | `MemoryOS` v2.0.34 published to PyPI (malicious) |
| 2026-09-23 | Aikido, SafeDep, Socket, and StepSecurity publish advisories |
| 2026-09-23 | npm malicious versions removed; PyPI version quarantined |

## Root Cause: GitHub Actions Pipeline Token Theft

The attacker pushed commits to the MemTensor GitHub repositories (`MemTensor/MemOS` and `MemTensor/MemOS-Cloud-OpenClaw-Plugin`) that modified CI/CD workflows. These commits caused the GitHub Actions release jobs to exfiltrate their npm or PyPI publish tokens to attacker infrastructure before the legitimate publish step executed. The malicious commits were authored under the names `MemTensor CI Review`, `release-maintenance`, and `Memtensor-AI`.

Key malicious commits:
- `b52958f` on MemTensor/MemOS (author: `MemTensor CI Review`)
- `41bf5c7` on MemTensor/MemOS tag v2.0.34 (author: `release-maintenance`)
- Five commits on MemTensor/MemOS-Cloud-OpenClaw-Plugin (author: `Memtensor-AI`)

## Technical Analysis of the Malicious Payload

### 1. npm Injection Mechanism

The compromised npm package embeds the sckit Go binary in a hidden `.sckit/` directory organized by platform:

```
.sckit/linux-amd64/sckit
.sckit/linux-arm64/sckit
.sckit/darwin-amd64/sckit
.sckit/darwin-arm64/sckit
.sckit/windows-amd64/sckit.exe
.sckit/windows-arm64/sckit.exe
```

The launcher `lib/sckit.js` imports at plugin registration and during memory-recall events. It invokes the platform-appropriate binary as a detached child process with:

```
sckit stage0 --config64 <base64_encoded_config>
```

The `SCKIT_EVENT_TEXT` environment variable forwards user prompts to the C2 server, enabling prompt exfiltration. Version 0.1.25 added `lib/tls-trust.js` and `.sckit/ca-roots.pem` as a TLS certificate fallback mechanism. The npm campaign ID is `cloud-openclaw-semi-nuclear`.

Package size inflation was a key indicator: clean baseline was ~272 KB; malicious versions were ~43.6-43.9 MB due to bundled Go executables.

### 2. PyPI Injection Mechanism

The compromised `MemoryOS` v2.0.34 uses a logging initialization hook:

- `src/memos/__init__.py` triggers the import chain
- `src/memos/log.py` contains `configure_logging()` which imports `memos._stage0`
- `src/memos/_stage0.py` contains `trigger()` that launches the Go binary with `start_new_session=True`
- `src/memos/_initial_ci_delivery.py` handles CI-specific token capture
- `src/memos/_pypi_bridge.sh` activates when `$0` equals `/app/twine-upload.sh` and `GITHUB_ACTIONS=true`

The PyPI campaign ID is `memos-semi-nuclear`.

### 3. The sckit Go Implant

The implant is a statically-linked Go binary compiled with `go1.27.1`. Its internal module path is `supplychain.local/campaign/cmd/implant` with packages `internal/agent`, `internal/wire`, and `internal/presentation`.

**Configuration schema:** `sckit.runtime.v1` (delivered as base64-encoded JSON via `--config64`)

**Credential harvesting targets:**

| Category | Specific Targets |
|----------|-----------------|
| Package Registries | `.npmrc`, `.pypirc`, `npm_*` tokens, `pypi-*` tokens |
| VCS Platforms | `.git-credentials`, `.netrc`, `github_pat_*`, `gh[opusr]_*`, `glpat-*` tokens |
| Cloud Providers | AWS access keys (`AKIA*`, `ASIA*`), associated env vars |
| SSH | `id_rsa`, `id_ecdsa`, `id_ed25519` |
| Secrets Management | `.vault-token`, `hvs.*` Vault tokens |
| Developer Tools | `credentials.db`, `access_tokens.json`, `stored_tokens`, `msal_token_cache` |
| Messaging/SaaS | Slack (`xox[abprs]-*`), Stripe (`sk_live_*`), SendGrid (`SG.*`), Hugging Face (`hf_*`) |
| Generic | JWTs (`eyJ*` pattern), database/broker connection strings, `.env` files |

**Expiration timestamps:**
- npm variant: `1792714982` (October 23, 2026 00:23:02 UTC)
- PyPI variant: `1792724380` (October 23, 2026 02:59:40 UTC)

### 4. Self-Propagation (Worm) Capabilities

The sckit binary contains templates to install itself into:
- npm packages (via stolen `NPM_TOKEN` / `NODE_AUTH_TOKEN`)
- Python packages (via stolen PyPI tokens)
- GitHub Actions workflows (`runtime-update.yml` containing `sckit stage0` commands)

The CI helper uses Ed25519 key validation for signed index verification and operates via the `/initial-ci-v2` endpoint on the C2.

### 5. C2 Infrastructure

| Component | Indicator | Purpose |
|-----------|-----------|---------|
| npm C2 | `8a8acaf167b3.skyleen[.]fr` | Primary C2 for npm implant |
| npm C2 | `0b48fafd6fbe.skyleen[.]fr` | Secondary npm C2 |
| npm C2 | `266297c6df27.skyleen[.]fr` | Tertiary npm C2 |
| PyPI C2 | `c747d139e7e9.skyleen[.]fr` | Primary C2 for PyPI implant |
| PyPI C2 | `73376a079d87.skyleen[.]fr` | Secondary PyPI C2 |
| PyPI C2 | `d4f77a3a8cb0.skyleen[.]fr` | Tertiary PyPI C2 |
| CI Capture | `10729e014d0e.skyleen[.]fr` | CI token exfiltration endpoint |
| Historical IP | `139.84.223[.]178` | Infrastructure IP |

**C2 URL paths:**
- `/config` -- control/tasking retrieval
- `/status` -- preflight check
- `/batch` -- credential exfiltration (results upload)
- `/initial-ci-v2` -- CI token capture
- `/observe/<selector>` -- observation reporting

### 6. Persistence

**State directories:**
- npm variant: `$HOME/.openclaw/.cache/runtime`
- PyPI variant: `$HOME/.memos/.cache/runtime`

**Process isolation:** Both variants use `detached=true` (Node.js) / `start_new_session=True` (Python) to separate the implant from the parent process.

## Indicators of Compromise (IOCs)

### Malicious Package Hashes (SHA-256)

| Package | Hash |
|---------|------|
| `memos-cloud-openclaw-plugin-0.1.21.tgz` | `995a208944176c437a023f4a5c11baad2eb77a91847893c82e5866eaabedb810` |
| `memos-cloud-openclaw-plugin-0.1.23.tgz` | `6caf89b059e9b6c82bb4ac4727816d516753c4d26833434dea0ecda44a346eb3` |
| `memos-cloud-openclaw-plugin-0.1.25.tgz` | `a6870826cd7c7ec8d32af227252efcdcdca03ac956d4702cdc2157ca82641673` |
| `memoryos-2.0.34-py3-none-any.whl` | `39ee644406829a4b630b31759c20478bc22d576d6a59b253ed86f72c360aa5ef` |
| `memoryos-2.0.34.tar.gz` | `92b46d18fc553c494eda714f204459edb74c205bf53b18a9092bcf02c7a6c5be` |

### sckit Implant Binary Hashes (SHA-256)

| Platform | npm Payload Hash | PyPI Payload Hash |
|----------|-----------------|-------------------|
| linux-amd64 | `381ac6dc1715d9298fe81b2a53a11f7b7d78e361ee3a6619ad54f8c4b062cc18` | `c1b0998347b489582bae7b7f4930f9831d9ef4b6bc150cfd488ee1a43272dd36` |
| linux-arm64 | `e077c387b223811064b7bbc5a55a0182fca9bf50894f949ff284d4be87d44b26` | `8f647f17a1934679c4095e21bee2b9bd83e28476603758bc91408a0c8443e3b4` |
| darwin-amd64 | `65faf8ccbcf5b34eb4f72c71bf82815fa9c1e2f947b9c898491540e866132c31` | `9de0d5b0ca184f71f630be5781d134998883a02d5d7bc65aeb9559d8f9efb364` |
| darwin-arm64 | `f8ccdd1da7dff1aef16377a2842bc7acf7c516e32122dd6e42dc4a4e57653fce` | `5405e330507602e803f7dd6f2a9d4555aec8558ab222b51413594a962da6888a` |
| windows-amd64 | `56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be` | `16de381deb978744535b10f68fe15165251374b86eef18ffc2c47f61ea673047` |
| windows-arm64 | `d6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26` | `f7c4014e284f3d56c452b8b222a287c54f73fc4a40a7e022e765ac8376362947` |

### Network IOCs

| Type | Indicator |
|------|-----------|
| Domain | `skyleen[.]fr` (parent, block all subdomains) |
| Subdomain | `8a8acaf167b3.skyleen[.]fr` |
| Subdomain | `0b48fafd6fbe.skyleen[.]fr` |
| Subdomain | `266297c6df27.skyleen[.]fr` |
| Subdomain | `c747d139e7e9.skyleen[.]fr` |
| Subdomain | `73376a079d87.skyleen[.]fr` |
| Subdomain | `d4f77a3a8cb0.skyleen[.]fr` |
| Subdomain | `10729e014d0e.skyleen[.]fr` |
| IP | `139.84.223[.]178` |

### Host IOCs

| Type | Indicator |
|------|-----------|
| File Path | `.sckit/<platform>-<arch>/sckit` or `sckit.exe` |
| File Path | `lib/sckit.js` (npm) |
| File Path | `lib/tls-trust.js` (npm v0.1.25) |
| File Path | `.sckit/ca-roots.pem` (npm v0.1.25) |
| File Path | `src/memos/_stage0.py` (PyPI) |
| File Path | `src/memos/_initial_ci_delivery.py` (PyPI) |
| File Path | `src/memos/_pypi_bridge.sh` (PyPI) |
| Directory | `$HOME/.openclaw/.cache/runtime` |
| Directory | `$HOME/.memos/.cache/runtime` |
| Process | `sckit stage0 --config64 <base64>` |
| Env Var | `SCKIT_EVENT_TEXT` |
| Env Var | `SCKIT_CI_RESULT_V2` |
| Env Var | `SCKIT_CI_OBSERVATION_V2` |
| Env Var | `SCKIT_INITIAL_CI_CHECKOUT_SHA` |
| Build Path | `supplychain.local/campaign/cmd/implant` |
| Go Version | `go1.27.1` |
| Config Schema | `sckit.runtime.v1` |
| Log String | `SCKit credential receipt acknowledged.` |

## MITRE ATT&CK Mapping

| Technique | Name | Usage |
|-----------|------|-------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Compromised legitimate npm/PyPI packages via CI/CD token theft |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell-based launcher scripts (_pypi_bridge.sh) |
| T1059.007 | Command and Scripting Interpreter: JavaScript | lib/sckit.js launcher in npm package |
| T1082 | System Information Discovery | Environment variable enumeration for CI/CD context |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvesting .npmrc, .pypirc, .vault-token, SSH keys |
| T1555 | Credentials from Password Stores | Scanning for credentials.db, access_tokens.json |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 communication via skyleen[.]fr |
| T1041 | Exfiltration Over C2 Channel | Credential upload via /batch endpoint |
| T1199 | Trusted Relationship | Abuse of GitHub Actions CI/CD trust |
| T1074.001 | Data Staged: Local Data Staging | Credentials staged in .cache/runtime directories |

## Detection Rules

### Sigma Rules

#### 1. Sckit Go Implant Process Execution

Detects the unique `sckit stage0 --config64` command-line pattern used when the implant launches.
<!-- audit: rule_type=sigma compile_status=pass(splunk,logscale) confidence=high altitude=specific leniency=strict sigma_check=skipped(ATT&CK_data_403) -->

- **File:** `rules/sigma/2026-09-25-memtensor-supply-chain-sckit-process.yml`
- **ID:** `7c3a8f1e-2d4b-4e6a-9f12-3b5c7d8e9a01`
- **Log Source:** `process_creation`
- **Tags:** `attack.t1195.002`, `attack.t1059.004`

#### 2. Sckit Implant State Directory Creation

Detects file creation events involving the `.openclaw/.cache/runtime`, `.memos/.cache/runtime`, or `.sckit/` persistence directories.
<!-- audit: rule_type=sigma compile_status=pass(splunk,logscale) confidence=high altitude=specific leniency=strict sigma_check=skipped(ATT&CK_data_403) -->

- **File:** `rules/sigma/2026-09-25-memtensor-supply-chain-sckit-file.yml`
- **ID:** `a2b4c6d8-e0f2-4a6b-8c0d-2e4f6a8b0c2d`
- **Log Source:** `file_event`
- **Tags:** `attack.t1074.001`

#### 3. Sckit C2 Communication to skyleen.fr

Detects DNS queries resolving to any subdomain of `skyleen.fr`, the sole C2 domain used by both npm and PyPI sckit variants.
<!-- audit: rule_type=sigma compile_status=pass(splunk,logscale) confidence=high altitude=specific leniency=strict sigma_check=skipped(ATT&CK_data_403) -->

- **File:** `rules/sigma/2026-09-25-memtensor-supply-chain-sckit-network.yml`
- **ID:** `d4e6f8a0-b2c4-4d6e-8f0a-2c4e6f8a0b2c`
- **Log Source:** `dns_query`
- **Tags:** `attack.t1071.001`, `attack.t1041`

#### 4. Sckit Environment Variable Indicators

Detects processes referencing sckit-specific environment variables (`SCKIT_EVENT_TEXT`, `SCKIT_CI_RESULT_V2`, `SCKIT_CI_OBSERVATION_V2`, `SCKIT_INITIAL_CI_CHECKOUT_SHA`).
<!-- audit: rule_type=sigma compile_status=pass(splunk,logscale) confidence=high altitude=specific leniency=strict sigma_check=skipped(ATT&CK_data_403) -->

- **File:** `rules/sigma/2026-09-25-memtensor-supply-chain-sckit-env.yml`
- **ID:** `f0a2b4c6-d8e0-4f2a-8b6c-0d2e4f6a8b0c`
- **Log Source:** `process_creation`
- **Tags:** `attack.t1059.004`, `attack.t1082`

### Snort Rules

#### 5. Sckit C2 DNS Query (sid:9000101)

Detects DNS queries containing the `skyleen.fr` domain in UDP packets to port 53.
<!-- audit: rule_type=snort compile_status=pass confidence=high altitude=specific leniency=strict snort_version=2.9.20 -->

#### 6. Sckit C2 IP Connection (sid:9000102)

Detects any IP traffic to the known sckit infrastructure address `139.84.223.178`.
<!-- audit: rule_type=snort compile_status=pass confidence=medium altitude=specific leniency=strict note=IP_may_be_reassigned -->

#### 7. Sckit Credential Exfiltration /batch (sid:9000103)

Detects HTTP POST to `/batch` on `skyleen.fr` hosts, matching the credential upload endpoint.
<!-- audit: rule_type=snort compile_status=pass confidence=high altitude=specific leniency=strict -->

#### 8. Sckit C2 Config Retrieval (sid:9000104)

Detects HTTP GET to `/config` on `skyleen.fr` hosts, matching the C2 tasking endpoint.
<!-- audit: rule_type=snort compile_status=pass confidence=high altitude=specific leniency=strict -->

#### 9. Sckit CI Token Capture (sid:9000105)

Detects HTTP requests to `/initial-ci-v2` on `skyleen.fr` hosts, used for CI pipeline token theft.
<!-- audit: rule_type=snort compile_status=pass confidence=high altitude=specific leniency=strict -->

- **File:** `rules/snort/2026-09-25-memtensor-supply-chain-sckit.rules`

### Suricata Rules

#### 10. Sckit C2 DNS Query (sid:9000201)

Detects DNS queries ending in `skyleen.fr` using Suricata's `dns.query` keyword.
<!-- audit: rule_type=suricata compile_status=pass confidence=high altitude=specific leniency=strict suricata_version=7.0.3 -->

#### 11. Sckit C2 TLS SNI (sid:9000202)

Detects TLS client hello SNI values ending in `skyleen.fr`.
<!-- audit: rule_type=suricata compile_status=pass confidence=high altitude=specific leniency=strict -->

#### 12. Sckit C2 IP Connection (sid:9000203)

Detects connections to the known infrastructure IP `139.84.223.178`.
<!-- audit: rule_type=suricata compile_status=pass confidence=medium altitude=specific leniency=strict note=IP_may_be_reassigned -->

#### 13. Sckit Credential Exfiltration /batch (sid:9000204)

Detects HTTP POST to `/batch` on `skyleen.fr` hosts via Suricata sticky buffers.
<!-- audit: rule_type=suricata compile_status=pass confidence=high altitude=specific leniency=strict -->

#### 14. Sckit C2 Config Retrieval (sid:9000205)

Detects HTTP GET to `/config` on `skyleen.fr` hosts.
<!-- audit: rule_type=suricata compile_status=pass confidence=high altitude=specific leniency=strict -->

#### 15. Sckit CI Token Capture (sid:9000206)

Detects HTTP requests to `/initial-ci-v2` on `skyleen.fr` hosts.
<!-- audit: rule_type=suricata compile_status=pass confidence=high altitude=specific leniency=strict -->

- **File:** `rules/suricata/2026-09-25-memtensor-supply-chain-sckit.rules`

### YARA Rules

#### 16. sckit_go_implant_strings

Detects the sckit Go implant via its unique module path `supplychain.local/campaign/cmd/implant` and runtime configuration schema strings.
<!-- audit: rule_type=yara compile_status=pass confidence=high altitude=specific leniency=strict -->

#### 17. sckit_go_implant_campaign_ids

Detects sckit binaries by campaign identifiers (`cloud-openclaw-semi-nuclear`, `memos-semi-nuclear`) paired with the `skyleen.fr` C2 domain.
<!-- audit: rule_type=yara compile_status=pass confidence=high altitude=specific leniency=strict -->

#### 18. sckit_npm_package_payload

Detects the malicious JavaScript launcher code in compromised npm packages by matching `launchStageZero`, `.sckit/`, `--config64`, and `SCKIT_EVENT_TEXT`.
<!-- audit: rule_type=yara compile_status=pass confidence=high altitude=specific leniency=strict -->

#### 19. sckit_pypi_stage0_loader

Detects the Python stage0 loader in compromised PyPI packages by matching `_stage0`, `trigger()`, `.sckit`, `_initial_ci_delivery`, and `_pypi_bridge`.
<!-- audit: rule_type=yara compile_status=pass confidence=high altitude=specific leniency=strict -->

#### 20. sckit_implant_hashes

Hash-based detection for all 12 known sckit binary variants across platforms and campaigns using the `hash` module.
<!-- audit: rule_type=yara compile_status=pass confidence=high altitude=specific leniency=strict note=requires_hash_module -->

- **File:** `rules/yara/2026-09-25-memtensor-supply-chain-sckit.yar`

## Detection Gaps and Recommendations

1. **CI/CD Pipeline Monitoring:** Organizations should audit GitHub Actions logs for unexpected commits modifying workflow files, especially those authored by unknown service accounts (`MemTensor CI Review`, `release-maintenance`).
2. **Package Size Anomaly:** The jump from ~272 KB to ~43 MB is a reliable pre-installation indicator. Package registries and SCA tools should flag extreme size increases.
3. **Missing Provenance Attestation:** The malicious npm releases lack the `gitHead` field and have no matching repository tags -- indicators of unauthorized publishing.
4. **Credential Rotation:** Any developer who installed affected versions should rotate ALL credentials in `$HOME`, including npm/PyPI tokens, GitHub/GitLab tokens, SSH keys, cloud CLI tokens, and `.env` secrets.
5. **BASH_ENV Monitoring:** The PyPI CI bridge writes to `BASH_ENV` and `GITHUB_ENV` -- monitoring these for unexpected modifications in CI runners is advised.

## Sources

- [The Hacker News - Compromised MemTensor Packages Deliver sckit Credential Stealer](https://thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html)
- [StepSecurity - Sckit Supply Chain Worm Hits MemTensor npm & PyPI Scopes](https://www.stepsecurity.io/blog/sckit-supply-chain-worm-hits-memtensor-npm-pypi-scopes)
- [SafeDep - MemTensor npm and PyPI Packages Hit by a Go Worm](https://safedep.io/memtensor-sckit-worm-npm-pypi/)
- [Semgrep - AI Supply Chain Attack Hits an OpenClaw Memory Plugin](https://semgrep.dev/blog/2026/the-ai-ecosystem-has-worms-now-inside-the-memtensor-compromise/)
- [Aikido - MemTensor npm and PyPI hit by "supplychain.local" malware](https://www.aikido.dev/blog/supplychain-local-memtensor-npm-pypi)
- [SC Media - MemTensor npm, PyPI packages compromised with cross-platform credential stealer](https://www.scworld.com/news/memtensor-npm-pypi-packages-compromised-with-cross-platform-credential-stealer)
- [Socket - @memtensor/memos-cloud-openclaw-plugin file explorer](https://socket.dev/npm/package/@memtensor/memos-cloud-openclaw-plugin/files/0.1.21/lib/sckit.js)
