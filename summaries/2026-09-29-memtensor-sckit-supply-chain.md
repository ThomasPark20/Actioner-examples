# Technical Analysis Report: MemTensor sckit npm/PyPI Supply Chain Attack (2026-09-29)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-29
Version: 1.0 (DRAFT)

## Executive Summary

On September 23, 2026, attackers compromised the GitHub Actions release pipelines of the MemTensor project and used stolen publish tokens to inject malicious code into two legitimate packages: `@memtensor/memos-cloud-openclaw-plugin` on npm (versions 0.1.21, 0.1.23, 0.1.25) and `MemoryOS` on PyPI (version 2.0.34). The compromised packages deliver **sckit**, a cross-platform Go-based credential stealer and self-propagating worm that targets developer credentials, cloud tokens, SSH keys, and CI/CD secrets. The implant communicates with C2 infrastructure under the `skyleen[.]fr` domain using hex-prefixed subdomains. This is the first documented supply-chain worm specifically targeting AI agent memory infrastructure.

## Background

### MemTensor Project Context

MemTensor provides memory infrastructure for AI agent systems. The `@memtensor/memos-cloud-openclaw-plugin` npm package is an OpenClaw memory plugin, while `MemoryOS` is the core Python memory library. Both are used in AI agent deployments, giving the attackers access to environments likely rich in cloud credentials, API keys, and CI/CD tokens.

### Discovery Timeline

| Date | Event |
|------|-------|
| 2026-09-23 | Malicious versions published to npm and PyPI |
| 2026-09-23 | Semgrep and SafeDep detect anomalous package contents |
| 2026-09-24 | npm advisories issued; PyPI quarantines MemoryOS 2.0.34 |
| 2026-09-25 | Public disclosure via The Hacker News and multiple outlets |

### Attack Vector

The attackers obtained publish tokens by pushing crafted commits to MemTensor's GitHub repositories that caused the existing CI/CD workflows to hand over npm and PyPI tokens. Malicious commits were authored under pseudonyms `MemTensor CI Review`, `release-maintenance`, and `Memtensor-AI`. The attacker alternated between clean and malicious builds (npm: clean 0.1.22/0.1.24, malicious 0.1.21/0.1.23/0.1.25) suggesting iterative testing.

## Technical Analysis

### 1. Infection Chain

**npm variant:** The malicious payload is embedded in `lib/sckit.js` and wires into code paths that execute during agent gateway startup and memory-recall events. It does **not** execute at install time, evading install-time scanners.

**PyPI variant:** The payload resides in `memos/_stage0.py` with execution points in `memos/log.py` and `memos/configs/mem_cube.py`. It activates upon module import.

Both variants download and execute the sckit Go binary for the target platform (`linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`, `windows-amd64`, `windows-arm64`) and store it under `.sckit/<os>-<arch>/sckit`.

### 2. sckit Implant Capabilities

The Go binary (built with `go1.27.1`, module path `supplychain.local/campaign/cmd/implant`) provides:

- **Credential harvesting:** Scans developer home directories for `.npmrc`, `.pypirc`, `.git-credentials`, `.netrc`, SSH keys (`id_rsa`, `id_ecdsa`, `id_ed25519`), `.vault-token`, `msal_token_cache`, `access_tokens.json`, `access_tokens.db`, `credentials.db`
- **Environment variable exfiltration:** Targets `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `PYPI_API_TOKEN`, `INPUT_PASSWORD`, `BASH_ENV`, `GITHUB_ENV`
- **Token regex scanning:** Embedded regex matches JWTs, AWS keys (AKIA/ASIA), GitHub PATs, GitLab PATs, npm tokens, PyPI tokens, Hugging Face tokens, Vault tokens, Slack tokens, Stripe live keys, and SendGrid keys
- **Self-propagation:** Uses stolen npm/PyPI tokens to self-publish malicious packages, and hijacks GitHub Actions workflows by writing to `$GITHUB_ENV` with `BASH_ENV=` injection
- **AI agent data capture:** Records prompt and recall data via `SCKIT_EVENT_TEXT` environment variable

### 3. Command & Control

**Primary domain:** `skyleen[.]fr`

**npm implant C2 subdomains:**
- `8a8acaf167b3.skyleen[.]fr`
- `0b48fafd6fbe.skyleen[.]fr`
- `266297c6df27.skyleen[.]fr`

**PyPI implant C2 subdomains:**
- `c747d139e7e9.skyleen[.]fr`
- `73376a079d87.skyleen[.]fr`
- `d4f77a3a8cb0.skyleen[.]fr`

**CI token capture endpoint:**
- `10729e014d0e.skyleen[.]fr/eb57efaa7365698fc1e4decc/initial-ci-v2`

**C2 URL paths:**
- `/<24_hex_chars>/config` — control/configuration
- `/status` — preflight check
- `/batch` — results exfiltration

**Command-line pattern:** `sckit stage0 --config64 <base64_config>`

### 4. Persistence & Staging

**State directories:**
- `$HOME/.openclaw/.cache/runtime/`
- `$HOME/.memos/.cache/runtime/`
- `$HOME/.sckit/<os>-<arch>/`

**Malicious CI scripts (worm propagation):**
- `runtime-update.yml`
- `.github/scripts/sckit-publish-bridge.sh`
- `sckit_poetry_build.py`
- `src/memos/_pypi_bridge.sh`
- `src/memos/_initial_ci_delivery.py`

**CI log markers:**
- `SCKit credential receipt acknowledged.`
- `SCKIT_CI_RESULT_V2`
- `SCKIT_CI_OBSERVATION_V2`
- `chore: allow native PyPI upload [skip ci]`

## Indicators of Compromise

### Compromised Package Versions

| Registry | Package | Malicious Versions | Safe Version |
|----------|---------|--------------------|--------------|
| npm | `@memtensor/memos-cloud-openclaw-plugin` | 0.1.21, 0.1.23, 0.1.25 | 0.1.24 |
| PyPI | `MemoryOS` | 2.0.34 | 2.0.33 |

### File Hashes (SHA-256)

**Malicious npm packages:**

| Version | SHA-256 |
|---------|---------|
| 0.1.21 | `995a208944176c437a023f4a5c11baad2eb77a91847893c82e5866eaabedb810` |
| 0.1.23 | `6caf89b059e9b6c82bb4ac4727816d516753c4d26833434dea0ecda44a346eb3` |
| 0.1.25 | `a6870826cd7c7ec8d32af227252efcdcdca03ac956d4702cdc2157ca82641673` |

**Malicious PyPI packages:**

| Format | SHA-256 |
|--------|---------|
| Wheel | `39ee644406829a4b630b31759c20478bc22d576d6a59b253ed86f72c360aa5ef` |
| tar.gz | `92b46d18fc553c494eda714f204459edb74c205bf53b18a9092bcf02c7a6c5be` |

**sckit Go implant binaries (npm variant):**

| Platform | SHA-256 |
|----------|---------|
| linux-amd64 | `381ac6dc1715d9298fe81b2a53a11f7b7d78e361ee3a6619ad54f8c4b062cc18` |
| linux-arm64 | `e077c387b223811064b7bbc5a55a0182fca9bf50894f949ff284d4be87d44b26` |
| darwin-amd64 | `65faf8ccbcf5b34eb4f72c71bf82815fa9c1e2f947b9c898491540e866132c31` |
| darwin-arm64 | `f8ccdd1da7dff1aef16377a2842bc7acf7c516e32122dd6e42dc4a4e57653fce` |
| windows-amd64 | `56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be` |
| windows-arm64 | `d6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26` |

**sckit Go implant binaries (PyPI variant):**

| Platform | SHA-256 |
|----------|---------|
| linux-amd64 | `c1b0998347b489582bae7b7f4930f9831d9ef4b6bc150cfd488ee1a43272dd36` |
| linux-arm64 | `8f647f17a1934679c4095e21bee2b9bd83e28476603758bc91408a0c8443e3b4` |
| darwin-amd64 | `9de0d5b0ca184f71f630be5781d134998883a02d5d7bc65aeb9559d8f9efb364` |
| darwin-arm64 | `5405e330507602e803f7dd6f2a9d4555aec8558ab222b51413594a962da6888a` |
| windows-amd64 | `16de381deb978744535b10f68fe15165251374b86eef18ffc2c47f61ea673047` |
| windows-arm64 | `f7c4014e284f3d56c452b8b222a287c54f73dc4a40a7e022e765ac8376362947` |

### Network Indicators (Defanged)

**C2 Domain:**
- `skyleen[.]fr` (all subdomains)

**npm C2 Subdomains:**
- `8a8acaf167b3[.]skyleen[.]fr`
- `0b48fafd6fbe[.]skyleen[.]fr`
- `266297c6df27[.]skyleen[.]fr`

**PyPI C2 Subdomains:**
- `c747d139e7e9[.]skyleen[.]fr`
- `73376a079d87[.]skyleen[.]fr`
- `d4f77a3a8cb0[.]skyleen[.]fr`

**CI Token Capture:**
- `10729e014d0e[.]skyleen[.]fr/eb57efaa7365698fc1e4decc/initial-ci-v2`

### Malicious Git Commits

**MemTensor/MemOS repository:**
- `b52958f` (author: `MemTensor CI Review`)
- `41bf5c7` (tag: `v2.0.34`, author: `release-maintenance`)

**MemTensor/MemOS-Cloud-OpenClaw-Plugin repository:**
- `e0c1ca3`, `91e3eeb`, `ef159b8`, `1fed130`, `9b97ec6` (author: `Memtensor-AI`)
- Carrier commits: `4649e31`, `6c05ade`, `89f989c`, `8c5ae11`, `8be32ad`

### Host-Based Indicators

**Processes:**
- `sckit` / `sckit.exe` with arguments `stage0 --config64 <base64>`

**File system artifacts:**
- `$HOME/.openclaw/.cache/runtime/*`
- `$HOME/.memos/.cache/runtime/*`
- `$HOME/.sckit/<os>-<arch>/sckit`
- `lib/sckit.js` (in npm package directory)
- `memos/_stage0.py` (in PyPI package directory)

**Environment variables (set by implant):**
- `SCKIT_EVENT_TEXT`

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Usage |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Hijacked legitimate npm/PyPI packages via stolen CI tokens |
| T1555 | Credentials from Password Stores | Harvests .npmrc, .pypirc, .vault-token, credential databases |
| T1005 | Data from Local System | Scans home directories for SSH keys, tokens, and credential files |
| T1041 | Exfiltration Over C2 Channel | Stolen credentials sent to skyleen[.]fr subdomains via /batch endpoint |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 with /config, /status, /batch URL paths |
| T1105 | Ingress Tool Transfer | Downloads platform-specific Go binary from staging infrastructure |
| T1036 | Masquerading | Publishes under legitimate package maintainer identities |
| T1027 | Obfuscated Files or Information | Base64-encoded configuration passed via --config64 flag |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Worm propagation scripts (sckit-publish-bridge.sh, _pypi_bridge.sh) |
| T1547 | Boot or Logon Autostart Execution | Hooks into agent startup and memory-recall event paths |

## Detection and Remediation

### Immediate Actions

1. **Audit `package.json` / `requirements.txt` / lockfiles** for `@memtensor/memos-cloud-openclaw-plugin` versions 0.1.21/0.1.23/0.1.25 and `MemoryOS` version 2.0.34.
2. **Search for `.sckit/` directories** under developer home directories on all systems.
3. **Search for staging directories** `$HOME/.openclaw/.cache/runtime/` and `$HOME/.memos/.cache/runtime/`.
4. **Block `skyleen[.]fr`** and all subdomains at DNS and HTTP proxy level.
5. **Search CI/CD logs** for `SCKIT_CI_RESULT_V2`, `SCKIT_CI_OBSERVATION_V2`, `SCKit credential receipt acknowledged`.
6. **Rotate all credentials** on affected systems: npm tokens, PyPI tokens, GitHub PATs, AWS keys, SSH keys, Vault tokens, Slack/Stripe/SendGrid keys.
7. **Audit GitHub Actions** workflows for unauthorized `runtime-update.yml` files or references to `sckit-publish-bridge.sh`.

### Longer-Term Measures

- Implement package pinning and integrity checking (npm `npm audit signatures`, pip `--require-hashes`).
- Use Socket.dev, Snyk, or equivalent for real-time supply chain monitoring.
- Restrict GitHub Actions workflow permissions; avoid passing publish tokens through environment variables.
- Monitor for processes named `sckit` on developer workstations and CI/CD runners.
- Enable DNS logging and alert on skyleen[.]fr domain lookups.

## Detection Rules

### Sigma Rules (4 rules)

#### 1. MemTensor sckit Go Implant Process Execution

Detects execution of the sckit Go binary by process name or command-line pattern (`stage0 --config64`). Cross-platform detection via process_creation; Windows logsource specified, adaptable for Linux/macOS EDR.

- **File:** `rules/sigma/2026-09-29-memtensor-sckit-supply-chain.yml` (rule 1)
- **Compile status:** Compiled (sigma convert to Splunk and Loki exit 0; sigma check could not reach MITRE ATT&CK API for tag validation but rule structure is valid)
- **Confidence:** High -- advisory-specific binary name and unique command-line pattern

#### 2. MemTensor Malicious Package File Artifacts

Detects file creation in sckit staging directories (.openclaw/.cache/runtime, .memos/.cache/runtime, .sckit/).

- **File:** `rules/sigma/2026-09-29-memtensor-sckit-supply-chain.yml` (rule 2)
- **Compile status:** Compiled (sigma convert exit 0)
- **Confidence:** High -- directory paths are specific to the malicious payload

#### 3. MemTensor sckit Credential File Access

Detects access to credential files targeted by sckit (.npmrc, .pypirc, SSH keys, etc.) by non-standard processes.

- **File:** `rules/sigma/2026-09-29-memtensor-sckit-supply-chain.yml` (rule 3)
- **Compile status:** Compiled (sigma convert exit 0)
- **Confidence:** Medium -- behavioral pattern, requires tuning of filter_expected for environment

#### 4. MemTensor sckit GitHub Actions CI Poisoning Indicators

Detects sckit-specific CI/CD script names and log markers in process creation events on Linux (CI runner detection).

- **File:** `rules/sigma/2026-09-29-memtensor-sckit-supply-chain.yml` (rule 4)
- **Compile status:** Compiled (sigma convert exit 0)
- **Confidence:** High -- script names and log strings are unique to the sckit worm

### YARA Rules (3 rules)

#### 5. MemTensor_sckit_Go_Implant

Detects the sckit Go binary across all platforms (ELF, PE, Mach-O) by Go module path (`supplychain.local/campaign/cmd/implant`), C2 domain, internal package paths, and credential harvesting patterns.

- **File:** `rules/yara/2026-09-29-memtensor-sckit-supply-chain.yar` (rule 1)
- **Compile status:** Compiled (yarac exit 0)
- **Confidence:** High -- Go module path is unique to this implant; C2 subdomain matching is campaign-specific

#### 6. MemTensor_sckit_NPM_Payload

Detects the malicious JavaScript loader (`lib/sckit.js`) and associated CI marker strings in npm package files.

- **File:** `rules/yara/2026-09-29-memtensor-sckit-supply-chain.yar` (rule 2)
- **Compile status:** Compiled (yarac exit 0)
- **Confidence:** High -- advisory-specific C2 domain, CI markers, and staging paths

#### 7. MemTensor_sckit_PyPI_Payload

Detects malicious Python components in the compromised MemoryOS PyPI package by stage0 module, execution points, and CI delivery scripts.

- **File:** `rules/yara/2026-09-29-memtensor-sckit-supply-chain.yar` (rule 3)
- **Compile status:** Compiled (yarac exit 0)
- **Confidence:** High -- combines C2 domain with package-specific file paths and CI scripts

### Suricata Rules (11 rules, SIDs 2026092901-2026092911)

#### 8. MemTensor sckit C2 Domain DNS Lookup (SID 2026092901)

Detects DNS queries for skyleen[.]fr domain.

- **Compile status:** Compiled (suricata -T exit 0)
- **Confidence:** High -- skyleen[.]fr is a known malicious C2 domain

#### 9-11. MemTensor sckit C2 HTTP Communication (SIDs 2026092902-2026092904)

Detects HTTP requests to skyleen[.]fr with /config, /status, and /batch URI paths.

- **Compile status:** Compiled (suricata -T exit 0)
- **Confidence:** High -- C2 domain + URI path combination is campaign-specific

#### 12. MemTensor sckit CI Token Capture (SID 2026092905)

Detects HTTP communication with the CI token capture endpoint at `10729e014d0e.skyleen[.]fr`.

- **Compile status:** Compiled (suricata -T exit 0)
- **Confidence:** High -- exact endpoint with unique path

#### 13-18. MemTensor sckit C2 Subdomain Communication (SIDs 2026092906-2026092911)

Detects HTTP traffic to the six known hex-prefixed C2 subdomains used by the npm and PyPI implant variants.

- **File:** `rules/suricata/2026-09-29-memtensor-sckit-supply-chain.rules`
- **Compile status:** Compiled (suricata -T exit 0)
- **Confidence:** High -- each subdomain is unique to the campaign

### Snort Rules (6 rules)

Adapted from the Suricata ruleset for Snort environments. Covers C2 config/status/batch endpoints and known C2 subdomains.

- **File:** `rules/snort/2026-09-29-memtensor-sckit-supply-chain.rules`
- **Compile status:** Not validated (Snort binary not available; syntax derived from Suricata rules)
- **Confidence:** High (pending Snort-specific validation)

## Viability Assessment

**PASS.** This is a supply-chain attack against named packages with:
- Specific compromised package names and version numbers
- 17 SHA-256 hashes across package archives and implant binaries for 6 platforms
- A unique Go module path (`supplychain.local/campaign/cmd/implant`) serving as a high-fidelity YARA anchor
- Named C2 domain (`skyleen[.]fr`) with 7 known subdomains providing network detection surface
- Distinctive command-line pattern (`sckit stage0 --config64`)
- Unique CI log markers and script names for worm propagation detection
- File system artifacts in campaign-specific directory paths

All indicators are concrete and advisory-specific, supporting high-confidence detection rules.

## Sources

- [The Hacker News -- Compromised MemTensor Packages Deliver sckit Credential Stealer via npm and PyPI](https://thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html)
- [Semgrep -- The AI Ecosystem Has Worms Now: Inside the MemTensor Compromise](https://semgrep.dev/blog/2026/the-ai-ecosystem-has-worms-now-inside-the-memtensor-compromise/)
- [SafeDep -- MemTensor npm and PyPI Packages Hit by a Go Worm](https://safedep.io/memtensor-sckit-worm-npm-pypi/)
- [SC Media -- MemTensor npm, PyPI packages compromised with cross-platform credential stealer](https://www.scworld.com/news/memtensor-npm-pypi-packages-compromised-with-cross-platform-credential-stealer)
- [Forkast -- The First Supply-Chain Worm Targeting AI Agent Memory Infrastructure](https://forkast.news/the-first-supply-chain-worm-targeting-ai-agent-memory-infrastructure-just-hit-npm-and-pypi/)
