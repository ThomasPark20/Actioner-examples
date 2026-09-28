# Technical Analysis Report: MemTensor sckit Supply Chain Attack -- Compromised npm/PyPI Packages (2026-09-28)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-09-28
Version: 1.1

<!-- revision: v1.1 2026-09-28 — applied critic CONDITIONAL PASS fixes (3 blocking, 6 material, 2 advisory). Blocking: removed tactic-only Sigma tags; removed T1552.007 and T1547 from ATT&CK mapping. Material: removed product:linux from both Sigma rules (cross-platform); added Windows patterns to process Sigma rule; expanded Suricata from 3+1 to 6+1 rules covering all C2 subdomains; added HTTPS caveat to Snort; merged T1555 into T1552.001; replaced T1059 with T1105 in Sigma Rule 1 tags; fixed YARA hash attribution with labeled per-platform/per-variant meta keys. Advisory: Windows process_creation addressed via cross-platform selection; all 12 binary hashes present in IOC table and YARA meta. -->

## Executive Summary

On September 23, 2026, multiple security firms (Aikido, Socket, SafeDep, StepSecurity) disclosed that legitimate MemTensor packages on both npm and PyPI were compromised to deliver "sckit," a cross-platform Go-based credential stealer and worm implant. The attack targeted the npm package `@memtensor/memos-cloud-openclaw-plugin` (versions 0.1.21, 0.1.23, 0.1.25) and the PyPI package `MemoryOS` (version 2.0.34). The attacker compromised MemTensor's GitHub Actions release pipelines by injecting commits that hijacked CI/CD publish tokens, enabling publication of trojanized packages to both registries. The sckit implant is a statically linked, stripped Go binary that harvests credentials from developer machines and CI environments (npm, PyPI, AWS, GitHub, GitLab, SSH keys, Vault tokens, and more), communicates with C2 infrastructure under the `skyleen[.]fr` domain using XChaCha20-Poly1305 encrypted CBOR over HTTPS, and contains self-propagation templates for npm, PyPI, and GitHub Actions workflows.

The exposure window spanned approximately 5 hours on September 23 (00:48--05:25 UTC) before quarantine actions began. The C2 configuration carries an expiration date of October 22, 2026, indicating a time-bounded campaign. All affected package versions have been quarantined or removed. Developers and CI systems that installed affected versions should rotate all secrets accessible from those environments immediately.

## Background: MemTensor and the AI Memory Integration Ecosystem

MemTensor provides AI memory management tools: `@memtensor/memos-cloud-openclaw-plugin` is an npm package that integrates memory-recall capabilities into AI agent gateways via the OpenClaw framework, while `MemoryOS` is its Python counterpart on PyPI (149 modules import its logger at load time). These packages are used by AI/ML developers and may run in CI/CD environments with elevated access to registry tokens and cloud credentials, making them high-value supply chain targets.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-03 06:46 | Last clean npm version 0.1.20 published |
| 2026-09-03 11:30 | Last clean PyPI version 2.0.33 published |
| 2026-09-23 00:48 | First malicious npm release (0.1.21) pushed via compromised GitHub Actions pipeline |
| 2026-09-23 00:48--02:03 | Five commits by `Memtensor-AI` on ephemeral `sc/release-*` branches (npm) |
| 2026-09-23 ~01:00--05:25 | Four malicious releases across npm (0.1.21, 0.1.23, 0.1.25) and PyPI (2.0.34) |
| 2026-09-23 (day) | Aikido, Socket, SafeDep, StepSecurity publish advisories; packages quarantined |
| 2026-10-22 | C2 configuration expiration date embedded in implant |

## Root Cause: GitHub Actions CI/CD Pipeline Compromise

The attacker compromised MemTensor's GitHub Actions release pipelines by pushing commits that modified the workflow's validation scripts. For npm, the attacker injected code that wrote a `BASH_ENV` entry pointing to an attacker-controlled script (`.github/scripts/sckit-publish-bridge.sh`), which forced Bash to execute it before the legitimate publish step. This bridge script captured the `NPM_TOKEN` via the sckit binary and terminated the job. For PyPI, a custom build backend (`sckit_poetry_build.py`) captured the `INPUT_PASSWORD` token before upload. Once tokens were exfiltrated, the attacker published trojanized package versions containing the sckit implant directly to both registries.

Key malicious commits in the MemOS repository:
- `b52958f`: Added six sckit binaries and Python bridge (token capture)
- `41bf5c7`: Removed registration call, enabled legitimate-appearing publishing

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection -- npm Package

Malicious versions of `@memtensor/memos-cloud-openclaw-plugin` (0.1.21, 0.1.23, 0.1.25) introduced `lib/sckit.js`, which selects the platform-specific sckit binary from `.sckit/<os>-<arch>/`. The binary is invoked via `spawn()` with arguments `stage0 --config64 <base64_config>`, executed as a detached background process with stdio redirected to `/dev/null`. Execution triggers at two points: (1) when the OpenClaw agent gateway starts, and (2) whenever the plugin handles a memory-recall event, with user prompts passed via the `SCKIT_EVENT_TEXT` environment variable. Version 0.1.25 additionally includes `.sckit/ca-roots.pem` for TLS trust.

### 2. Dependency Injection -- PyPI Package

The compromised `MemoryOS` 2.0.34 modifies `memos/log.py` to hook `configure_logging()`. Since 149 modules invoke `get_logger()` at import time, simply importing the package triggers the sckit payload once per process without any explicit API call. Additional malicious files include `memos/_stage0.py`, `memos/_sckit_config64`, `memos/_pypi_bridge.sh`, and `memos/_initial_ci_delivery.py`.

### 3. C2 Infrastructure

The sckit implant communicates with C2 servers using encrypted CBOR protocol with XChaCha20-Poly1305 over HTTPS. All known C2 subdomains resolve to a single IP: `139.84.223[.]178`.

**npm C2 servers:**
- `8a8acaf167b3[.]skyleen[.]fr`
- `0b48fafd6fbe[.]skyleen[.]fr`
- `266297c6df27[.]skyleen[.]fr`

**PyPI C2 servers:**
- `c747d139e7e9[.]skyleen[.]fr`
- `73376a079d87[.]skyleen[.]fr`
- `d4f77a3a8cb0[.]skyleen[.]fr`

**URI patterns:** `/<hex_hash>/config`, `/<hex_hash>/status`, `/<hex_hash>/batch`

**Configuration schema:** `sckit.runtime.v1`, campaign profile `semi-nuclear`, campaign ID `cloud-openclaw-semi-nuclear`.

### 4. Platform-Specific Behavior

The sckit binary is a statically linked, stripped Go executable compiled for six platform/architecture combinations. Binary directory structure: `.sckit/<os>-<arch>/sckit` (or `sckit.exe` on Windows).

#### Linux (amd64/arm64)
- Binary dropped at `.sckit/linux-amd64/sckit` or `.sckit/linux-arm64/sckit`
- State tracking at `$HOME/.openclaw/.cache/runtime/` (npm) or `$HOME/.memos/.cache/runtime/` (PyPI)
- Executes as detached background process with stdio to `/dev/null`

#### macOS (amd64/arm64)
- Binary dropped at `.sckit/darwin-amd64/sckit` or `.sckit/darwin-arm64/sckit`
- Same execution and state-tracking pattern as Linux

#### Windows (amd64/arm64)
- Binary dropped at `.sckit/windows-amd64/sckit.exe` or `.sckit/windows-arm64/sckit.exe`
- Same execution pattern adapted for Windows process creation

### 5. Credential Harvesting and Worm Propagation

**Credential files targeted:**
- `.npmrc`, `.pypirc`, `.git-credentials`, `.vault-token`, `id_ecdsa`, `credentials.db`, `access_tokens.json`, `stored_tokens`

**Environment variables harvested:**
- `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `PYPI_API_TOKEN`, `SCKIT_EVENT_TEXT`, `BASH_ENV`
- Any environment variable containing: tokens, passwords, API keys, private keys, session cookies, database connection strings

**Explicitly targeted services:** AWS access keys, GitHub/GitLab tokens, npm/PyPI API tokens, Hugging Face tokens, HashiCorp Vault tokens, Slack tokens, Stripe keys, SendGrid keys, JWTs

**Worm propagation:** The implant contains Go functions (`recursivePublish`, `prepareRemoteRepository`) and templates to install itself in npm packages (via `npm publish`/`npm version patch`), Python packages (via `twine upload`), and GitHub Actions workflows (via `runtime-update.yml` containing `./%s/linux-amd64/sckit stage0 --config64 %q`). This enables autonomous spread across repositories accessible with stolen credentials.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `skyleen[.]fr`)
> - IP addresses: `[.]` replacing dots (e.g., `139.84.223[.]178`)

### Package / Software Level

| Package / Component | Malicious Version | Hash (SHA256) | Description |
|---------------------|-------------------|---------------|-------------|
| `@memtensor/memos-cloud-openclaw-plugin` | 0.1.21 | `995a208944176c437a023f4a5c11baad2eb77a91847893c82e5866eaabedb810` | Malicious npm plugin with sckit Go implant |
| `@memtensor/memos-cloud-openclaw-plugin` | 0.1.23 | `6caf89b059e9b6c82bb4ac4727816d516753c4d26833434dea0ecda44a346eb3` | Malicious npm plugin with sckit Go implant |
| `@memtensor/memos-cloud-openclaw-plugin` | 0.1.25 | `a6870826cd7c7ec8d32af227252efcdcdca03ac956d4702cdc2157ca82641673` | Malicious npm plugin with sckit Go implant + ca-roots.pem |
| `MemoryOS` (PyPI) | 2.0.34 (wheel) | `39ee644406829a4b630b31759c20478bc22d576d6a59b253ed86f72c360aa5ef` | Malicious PyPI wheel with sckit implant |
| `MemoryOS` (PyPI) | 2.0.34 (sdist) | `92b46d18fc553c494eda714f204459edb74c205bf53b18a9092bcf02c7a6c5be` | Malicious PyPI source distribution |

### File System

| Platform | Path / Hash (SHA256) | Description |
|----------|----------------------|-------------|
| linux-amd64 | `381ac6dc1715d9298fe81b2a53a11f7b7d78e361ee3a6619ad54f8c4b062cc18` | sckit binary (npm variant) |
| linux-arm64 | `e077c387b223811064b7bbc5a55a0182fca9bf50894f949ff284d4be87d44b26` | sckit binary (npm variant) |
| darwin-amd64 | `65faf8ccbcf5b34eb4f72c71bf82815fa9c1e2f947b9c898491540e866132c31` | sckit binary (npm variant) |
| darwin-arm64 | `f8ccdd1da7dff1aef16377a2842bc7acf7c516e32122dd6e42dc4a4e57653fce` | sckit binary (npm variant) |
| windows-amd64 | `56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be` | sckit binary (npm variant) |
| windows-arm64 | `d6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26` | sckit binary (npm variant) |
| linux-amd64 | `c1b0998347b489582bae7b7f4930f9831d9ef4b6bc150cfd488ee1a43272dd36` | sckit binary (PyPI variant) |
| linux-arm64 | `8f647f17a1934679c4095e21bee2b9bd83e28476603758bc91408a0c8443e3b4` | sckit binary (PyPI variant) |
| darwin-amd64 | `9de0d5b0ca184f71f630be5781d134998883a02d5d7bc65aeb9559d8f9efb364` | sckit binary (PyPI variant) |
| darwin-arm64 | `5405e330507602e803f7dd6f2a9d4555aec8558ab222b51413594a962da6888a` | sckit binary (PyPI variant) |
| windows-amd64 | `16de381deb978744535b10f68fe15165251374b86eef18ffc2c47f61ea673047` | sckit binary (PyPI variant) |
| windows-arm64 | `f7c4014e284f3d56c452b8b222a287c54f73dc4a40a7e022e765ac8376362947` | sckit binary (PyPI variant) |

**Dropped file paths (npm):**
- `.sckit/<os>-<arch>/sckit` (or `sckit.exe`)
- `.sckit/ca-roots.pem` (v0.1.25)
- `lib/sckit.js`, `lib/tls-trust.js`
- `$HOME/.openclaw/.cache/runtime/` (state directory)

**Dropped file paths (PyPI):**
- `memos/.sckit/<os>-<arch>/sckit` (or `sckit.exe`)
- `memos/_stage0.py`, `memos/_sckit_config64`
- `memos/_pypi_bridge.sh`, `memos/_initial_ci_delivery.py`
- `sckit_poetry_build.py` (sdist)
- `$HOME/.memos/.cache/runtime/` (state directory)

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `8a8acaf167b3[.]skyleen[.]fr` | npm C2 server |
| Domain | `0b48fafd6fbe[.]skyleen[.]fr` | npm C2 server |
| Domain | `266297c6df27[.]skyleen[.]fr` | npm C2 server |
| Domain | `c747d139e7e9[.]skyleen[.]fr` | PyPI C2 server |
| Domain | `73376a079d87[.]skyleen[.]fr` | PyPI C2 server |
| Domain | `d4f77a3a8cb0[.]skyleen[.]fr` | PyPI C2 server |
| IP | `139.84.223[.]178` | Resolves all known C2 subdomains |
| URL Pattern | `hxxps://<subdomain>[.]skyleen[.]fr/<hex>/config` | C2 configuration retrieval |
| URL Pattern | `hxxps://<subdomain>[.]skyleen[.]fr/<hex>/status` | C2 status beacon |
| URL Pattern | `hxxps://<subdomain>[.]skyleen[.]fr/<hex>/batch` | C2 batch command/exfil |

### Behavioral

- Process named `sckit` executing with `stage0 --config64` arguments
- Process launched from `.sckit/` directory path
- DNS queries to `*.skyleen[.]fr` subdomains with 12-character hex prefixes
- Outbound HTTPS to `139.84.223[.]178`
- Reads of `.npmrc`, `.pypirc`, `.git-credentials`, `.vault-token`, SSH keys in `$HOME`
- Environment variable enumeration for tokens/keys/passwords
- Invocation of `npm publish`, `npm version patch`, or `twine upload` from unexpected contexts
- Creation of `runtime-update.yml` GitHub Actions workflow files in repositories

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Compromised MemTensor GitHub Actions pipelines to publish trojanized npm/PyPI packages |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | BASH_ENV hijack to execute sckit-publish-bridge.sh before legitimate CI steps |
| T1059.007 | Command and Scripting Interpreter: JavaScript | lib/sckit.js loader spawns sckit binary on gateway start and memory-recall events |
| T1059.006 | Command and Scripting Interpreter: Python | memos/log.py hook triggers sckit on any import of MemoryOS |
| T1552.001 | Unsecured Credentials: Credentials In Files | Reads SSH keys (id_ecdsa), .git-credentials, .npmrc, .pypirc, .vault-token, credentials.db, access_tokens.json, stored_tokens from $HOME and CI environments |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication via HTTPS to skyleen[.]fr subdomains |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | XChaCha20-Poly1305 encrypted CBOR payloads over HTTPS |
| T1105 | Ingress Tool Transfer | Go binary embedded in package, dropped to .sckit/ directory |
| T1078.004 | Valid Accounts: Cloud Accounts | Stolen CI tokens used to publish further malicious packages |

<!-- revision: v1.1 — removed T1555 (merged credential file harvesting into T1552.001 which better describes unsecured credential files); removed T1552.007 (Container API — no evidence of container orchestration API access; env var harvesting is covered by T1552.001); removed T1547 (Boot or Logon Autostart Execution — runtime-update.yml in GitHub Actions is CI/CD persistence via T1195.002/T1078.004, not OS-level autostart). -->

## Impact Assessment

**Breadth:** Moderate -- affects all users/CI systems that installed `@memtensor/memos-cloud-openclaw-plugin` 0.1.21/0.1.23/0.1.25 from npm or `MemoryOS` 2.0.34 from PyPI during the ~5-hour exposure window. Download counts not publicly reported but the AI/ML developer community using MemTensor tools is the primary audience.

**Depth:** Critical per-victim -- the sckit implant harvests all developer and CI credentials (npm, PyPI, AWS, GitHub, GitLab, SSH, Vault, and more), enabling further supply chain propagation. The worm capability (`recursivePublish`, `prepareRemoteRepository`) means a single compromised developer could propagate the infection across all their accessible repositories.

**Stealth:** High -- binary is statically linked and stripped Go (resistant to string-based AV), runs detached in background with stdio suppressed, uses encrypted C2 channel, and leverages legitimate package infrastructure for delivery. Time-bounded campaign (expires Oct 22, 2026) suggests operational discipline.

## Detection & Remediation

### Immediate Detection

Check for affected package versions in your environment:

```bash
# npm: check lockfiles and node_modules
grep -r "memos-cloud-openclaw-plugin" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
find . -path "*/node_modules/@memtensor/memos-cloud-openclaw-plugin/package.json" -exec grep '"version"' {} \;

# PyPI: check installed packages
pip show MemoryOS 2>/dev/null | grep -i version

# Check for sckit binary artifacts
find $HOME -name "sckit" -o -name "sckit.exe" -o -name "_stage0.py" -o -name "_sckit_config64" -o -name "_pypi_bridge.sh" 2>/dev/null
find . -path "*/.sckit/*" 2>/dev/null

# Check for state directories
ls -la $HOME/.openclaw/.cache/runtime/ 2>/dev/null
ls -la $HOME/.memos/.cache/runtime/ 2>/dev/null

# Network: check DNS logs for C2 domains
grep -i "skyleen.fr" /var/log/dns* /var/log/syslog 2>/dev/null

# Process: check for running sckit processes
ps aux | grep -i sckit
```

### Remediation

1. **Contain:** Isolate any machine (developer workstation or CI runner) that installed affected versions. Block `139.84.223[.]178` and `*.skyleen[.]fr` at network perimeter.
2. **Eradicate:** Remove compromised packages (`npm uninstall @memtensor/memos-cloud-openclaw-plugin` and downgrade to 0.1.20; `pip install MemoryOS==2.0.33`). Delete `.sckit/` directories, state directories, and all dropped files listed in IOCs.
3. **Rotate secrets:** Treat ALL credentials accessible from compromised hosts/CI as leaked. Rotate: npm tokens, PyPI API tokens, GitHub/GitLab PATs, AWS access keys, SSH keys, Vault tokens, Slack/Stripe/SendGrid keys, JWTs, and any environment variable containing secrets.
4. **Audit CI:** Review GitHub Actions workflow histories for unauthorized commits, especially on `sc/release-*` branches. Check for unauthorized `runtime-update.yml` workflows in repositories.
5. **Scan downstream:** If compromised CI tokens were used to publish packages you maintain, audit those packages for injected sckit payloads.

### Long-Term Hardening

- Pin package versions and verify checksums in lockfiles; enable npm `--ignore-scripts` where feasible
- Require MFA/OIDC for registry publish tokens; use short-lived, scoped tokens in CI
- Implement GitHub Actions workflow pinning (commit SHA, not tags) and require approval for workflow changes
- Deploy egress filtering from CI runners to restrict outbound connections
- Use tools like Socket, Aikido, or StepSecurity to monitor for supply chain anomalies in dependencies
- Restrict `BASH_ENV` usage in CI workflows; audit for unexpected modifications to shell environment variables

## Detection Rules

These rules target the sckit implant's specific process execution patterns, C2 domain infrastructure, and binary/loader artifacts across Sigma, Snort, Suricata, and YARA. The C2 uses HTTPS with encrypted CBOR payloads, so HTTP-layer Snort rules require TLS inspection to see Host headers and URIs; DNS and IP rules work without it.

### Sigma: sckit Go implant process execution
Detects execution of the sckit binary with its characteristic `stage0 --config64` arguments or from the `.sckit/` drop directory (cross-platform: Linux, macOS, Windows).
**Status:** compile ✅ · confidence: high
<!-- audit: `sigma check` fails ONLY due to offline D3FEND data fetch (HTTP 403 in sandboxed environment) — NOT a rule defect. Portability validated: `sigma convert --without-pipeline -t splunk` exit 0 => (Image IN ("*/sckit", "*\sckit.exe") CommandLine IN ("*stage0*", "*--config64*")) OR Image IN ("*.sckit/*", "*.sckit\*"); `sigma convert --without-pipeline -t log_scale` exit 0. Two selection blocks OR'd: selection_binary matches binary name + args (Linux/macOS + Windows paths), selection_path matches drop directory (forward and backslash). High confidence: both the binary name "sckit" and the "stage0 --config64" argument pattern are specific to this implant and not known in legitimate software. FP risk: unknown legitimate tool named "sckit" (none found). revision v1.1: removed tactic-only tags (attack.execution, attack.credential_access); replaced attack.t1059 with attack.t1105 (rule detects transferred tool, not command interpreter); removed attack.t1555 (merged into T1552.001); removed product:linux from logsource (cross-platform package); added Windows Image endswith '\sckit.exe' and path contains '.sckit\'. -->
```yaml
title: sckit Go implant execution via MemTensor supply chain compromise
id: 8c4e2f1a-3d7b-4a9e-b5c1-6f8d0e2a7b3c
status: experimental
description: >-
  Detects execution of the sckit Go-based credential stealer delivered via
  compromised MemTensor npm/PyPI packages. The binary is invoked with
  'stage0 --config64' arguments from npm plugin startup or Python import hooks.
references:
  - https://thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html
  - https://www.aikido.dev/blog/supplychain-local-memtensor-npm-pypi
  - https://socket.dev/blog/memtensor-compromise
author: Actioner
date: 2026/09/28
tags:
  - attack.t1105
  - attack.t1195.002
logsource:
  category: process_creation
detection:
  selection_binary:
    Image|endswith:
      - '/sckit'
      - '\sckit.exe'
    CommandLine|contains:
      - 'stage0'
      - '--config64'
  selection_path:
    Image|contains:
      - '.sckit/'
      - '.sckit\'
  condition: selection_binary or selection_path
falsepositives:
  - Unknown legitimate software named sckit (unlikely)
level: high
```

### Sigma: DNS query to sckit C2 subdomains on skyleen[.]fr
Detects DNS resolution of the six known sckit C2 subdomains, which use 12-character hex prefixes under skyleen[.]fr.
**Status:** compile ✅ · confidence: high
<!-- audit: `sigma check` fails only due to offline D3FEND data (same environment issue as above). Portability validated: `sigma convert --without-pipeline -t splunk` exit 0 => QueryName="*.skyleen.fr" QueryName IN ("*8a8acaf167b3*",...); `sigma convert --without-pipeline -t log_scale` exit 0. Single selection map with endswith + contains produces AND between the two field conditions. High confidence: the 12-char hex subdomain prefixes are campaign-specific identifiers (8a8acaf167b3, 0b48fafd6fbe, 266297c6df27, c747d139e7e9, 73376a079d87, d4f77a3a8cb0). FP risk: legitimate skyleen.fr subdomains matching these exact hex prefixes (near-zero probability). revision v1.1: removed tactic-only tag (attack.command_and_control); removed product:linux from logsource (DNS resolution is cross-platform). -->
```yaml
title: DNS query to sckit C2 subdomains on skyleen.fr
id: 9d5f3a2b-4e8c-5b0f-c6d2-7a9e1f3b8c4d
status: experimental
description: >-
  Detects DNS resolution of known sckit C2 subdomains under skyleen.fr
  used by the MemTensor supply chain compromise for command-and-control
  communication with the Go-based credential stealer implant.
references:
  - https://thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html
  - https://www.aikido.dev/blog/supplychain-local-memtensor-npm-pypi
  - https://socket.dev/blog/memtensor-compromise
author: Actioner
date: 2026/09/28
tags:
  - attack.t1071.001
  - attack.t1195.002
logsource:
  category: dns_query
detection:
  selection:
    QueryName|endswith:
      - '.skyleen.fr'
    QueryName|contains:
      - '8a8acaf167b3'
      - '0b48fafd6fbe'
      - '266297c6df27'
      - 'c747d139e7e9'
      - '73376a079d87'
      - 'd4f77a3a8cb0'
  condition: selection
falsepositives:
  - Legitimate use of skyleen.fr hosting with matching subdomain prefixes (very unlikely)
level: critical
```

### Snort: sckit C2 network indicators
Alerts on HTTP traffic containing `skyleen.fr` Host header with `/config` URI path (C2 beacon), and on any traffic to the C2 IP `139.84.223.178`. The C2 uses HTTPS; the HTTP-layer rule (sid:2100901) requires TLS inspection/termination to see cleartext headers and URIs -- without it, only the IP rule (sid:2100902) fires.
**Status:** compile ✅ · confidence: medium
<!-- audit: validated via Snort 2.9.20: copied to /etc/snort/rules/local.rules => `snort -c /etc/snort/snort.conf -T` => "Snort successfully validated the configuration! Snort exiting" exit 0. Two rules: sid:2100901 matches HTTP Host header containing "skyleen.fr" + URI "/config" (C2 beacon pattern); sid:2100902 matches any IP traffic to 139.84.223.178. Medium confidence: the IP is commodity VPS (Vultr) that may be reassigned; the HTTP rule requires both Host and URI match for specificity but also requires TLS inspection since the C2 uses HTTPS with encrypted CBOR payloads. revision v1.1: added HTTPS/TLS inspection caveat to prose and audit comment. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - sckit C2 beacon to skyleen.fr subdomain (MemTensor supply chain)"; flow:established,to_server; content:"skyleen.fr"; http_header; content:"/config"; http_uri; reference:url,thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html; classtype:trojan-activity; sid:2100901; rev:1;)
alert ip $HOME_NET any -> 139.84.223.178 any (msg:"Actioner - sckit C2 server IP contact (MemTensor supply chain)"; reference:url,thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html; classtype:trojan-activity; sid:2100902; rev:1;)
```

### Suricata: sckit C2 DNS queries and IP contact
Detects DNS queries for all six C2 subdomains under skyleen[.]fr (three npm, three PyPI), plus IP-level contact with the C2 server.
**Status:** compile ✅ · confidence: high
<!-- audit: validated with `suricata -T -S suricata-memtensor.rules -l /tmp/actioner` => "Configuration provided was successfully loaded. Exiting." exit 0, Suricata 7.0.3. Seven rules with unique SIDs (2200901-2200907). All six C2 subdomains now have individual DNS rules using dns.query sticky buffer with full subdomain content match + endswith + nocase. The seventh rule covers the IP for catch-all. High confidence on DNS rules (campaign-specific hex prefixes matching exact FQDN); medium on IP rule (VPS may be reassigned). revision v1.1: expanded from 3+1 to 6+1 rules covering all six C2 subdomains; changed content match from parent-domain+prefix pair to full subdomain FQDN for precision; bumped rev to 2; renumbered SIDs for the three new rules (2200904-2200906), IP rule now 2200907. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - sckit C2 DNS query 8a8acaf167b3.skyleen.fr (MemTensor supply chain)"; dns.query; content:"8a8acaf167b3.skyleen.fr"; endswith; nocase; reference:url,thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html; classtype:trojan-activity; sid:2200901; rev:2; metadata:author Actioner, created_at 2026-09-28;)
alert dns $HOME_NET any -> any any (msg:"Actioner - sckit C2 DNS query 0b48fafd6fbe.skyleen.fr (MemTensor supply chain)"; dns.query; content:"0b48fafd6fbe.skyleen.fr"; endswith; nocase; reference:url,thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html; classtype:trojan-activity; sid:2200902; rev:2; metadata:author Actioner, created_at 2026-09-28;)
alert dns $HOME_NET any -> any any (msg:"Actioner - sckit C2 DNS query 266297c6df27.skyleen.fr (MemTensor supply chain)"; dns.query; content:"266297c6df27.skyleen.fr"; endswith; nocase; reference:url,thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html; classtype:trojan-activity; sid:2200903; rev:2; metadata:author Actioner, created_at 2026-09-28;)
alert dns $HOME_NET any -> any any (msg:"Actioner - sckit C2 DNS query c747d139e7e9.skyleen.fr (MemTensor supply chain)"; dns.query; content:"c747d139e7e9.skyleen.fr"; endswith; nocase; reference:url,thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html; classtype:trojan-activity; sid:2200904; rev:2; metadata:author Actioner, created_at 2026-09-28;)
alert dns $HOME_NET any -> any any (msg:"Actioner - sckit C2 DNS query 73376a079d87.skyleen.fr (MemTensor supply chain)"; dns.query; content:"73376a079d87.skyleen.fr"; endswith; nocase; reference:url,thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html; classtype:trojan-activity; sid:2200905; rev:2; metadata:author Actioner, created_at 2026-09-28;)
alert dns $HOME_NET any -> any any (msg:"Actioner - sckit C2 DNS query d4f77a3a8cb0.skyleen.fr (MemTensor supply chain)"; dns.query; content:"d4f77a3a8cb0.skyleen.fr"; endswith; nocase; reference:url,thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html; classtype:trojan-activity; sid:2200906; rev:2; metadata:author Actioner, created_at 2026-09-28;)
alert ip $HOME_NET any -> 139.84.223.178 any (msg:"Actioner - sckit C2 server IP contact (MemTensor supply chain)"; reference:url,thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html; classtype:trojan-activity; sid:2200907; rev:2; metadata:author Actioner, created_at 2026-09-28;)
```

### YARA: sckit Go implant binary
Detects the sckit Go binary via its embedded module path (`supplychain.local/campaign/cmd/implant`), configuration schema, campaign ID, and credential-harvesting function names, scoped to executable file headers (ELF, PE, Mach-O).
**Status:** compile ✅ · confidence: high
<!-- audit: `yarac yara-memtensor.yar /dev/null` exit 0. Three rules total. Rule 1 (memtensor_sckit_implant): condition requires executable magic bytes AND (go_module OR config_schema+campaign_id OR 2-of-4 function names OR c2_domain+stage0+config64). Go module path "supplychain.local/campaign/cmd/implant" is highly specific. Function names embedded in Go pclntab even when stripped. All 12 binary SHA256 hashes documented in meta with labeled per-platform per-variant keys (npm_hash_<platform>, pypi_hash_<platform>). Rule 2 (memtensor_sckit_npm_loader): targets lib/sckit.js; hash meta now carries all 3 malicious npm package version hashes with version labels. Rule 3 (memtensor_sckit_python_loader): hash meta now carries both wheel and sdist hashes with explicit labels. No sample testing (samples unavailable in sandbox). revision v1.1: expanded implant rule hash meta from 3 unlabeled to 12 labeled per-platform/per-variant hashes; npm loader hash meta expanded from 1 to all 3 package version hashes with version labels; python loader hash meta expanded with explicit wheel/sdist labels. -->
```yara
rule memtensor_sckit_implant
{
    meta:
        description = "Detects the sckit Go-based credential stealer/implant delivered via compromised MemTensor npm/PyPI packages (supply chain attack, Sep 2026)"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html"
        npm_hash_linux_amd64 = "381ac6dc1715d9298fe81b2a53a11f7b7d78e361ee3a6619ad54f8c4b062cc18"
        npm_hash_linux_arm64 = "e077c387b223811064b7bbc5a55a0182fca9bf50894f949ff284d4be87d44b26"
        npm_hash_darwin_amd64 = "65faf8ccbcf5b34eb4f72c71bf82815fa9c1e2f947b9c898491540e866132c31"
        npm_hash_darwin_arm64 = "f8ccdd1da7dff1aef16377a2842bc7acf7c516e32122dd6e42dc4a4e57653fce"
        npm_hash_windows_amd64 = "56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be"
        npm_hash_windows_arm64 = "d6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26"
        pypi_hash_linux_amd64 = "c1b0998347b489582bae7b7f4930f9831d9ef4b6bc150cfd488ee1a43272dd36"
        pypi_hash_linux_arm64 = "8f647f17a1934679c4095e21bee2b9bd83e28476603758bc91408a0c8443e3b4"
        pypi_hash_darwin_amd64 = "9de0d5b0ca184f71f630be5781d134998883a02d5d7bc65aeb9559d8f9efb364"
        pypi_hash_darwin_arm64 = "5405e330507602e803f7dd6f2a9d4555aec8558ab222b51413594a962da6888a"
        pypi_hash_windows_amd64 = "16de381deb978744535b10f68fe15165251374b86eef18ffc2c47f61ea673047"
        pypi_hash_windows_arm64 = "f7c4014e284f3d56c452b8b222a287c54f73dc4a40a7e022e765ac8376362947"

    strings:
        $go_module = "supplychain.local/campaign/cmd/implant" ascii
        $func1 = "readCredentialFile" ascii
        $func2 = "extractJSONCredentials" ascii
        $func3 = "recursivePublish" ascii
        $func4 = "prepareRemoteRepository" ascii
        $config_schema = "sckit.runtime.v1" ascii
        $campaign_id = "cloud-openclaw-semi-nuclear" ascii
        $c2_domain = "skyleen.fr" ascii
        $stage0_arg = "stage0" ascii
        $config64_arg = "--config64" ascii

    condition:
        (
            uint32(0) == 0x464C457F or
            uint16(0) == 0x5A4D or
            uint32(0) == 0xFEEDFACE or
            uint32(0) == 0xFEEDFACF or
            uint32(0) == 0xCEFAEDFE or
            uint32(0) == 0xCFFAEDFE
        )
        and (
            $go_module or
            ($config_schema and $campaign_id) or
            (2 of ($func1, $func2, $func3, $func4)) or
            ($c2_domain and $stage0_arg and $config64_arg)
        )
}

rule memtensor_sckit_npm_loader
{
    meta:
        description = "Detects the sckit JavaScript loader (lib/sckit.js) from compromised @memtensor/memos-cloud-openclaw-plugin npm package"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://socket.dev/blog/memtensor-compromise"
        npm_pkg_hash_0_1_21 = "995a208944176c437a023f4a5c11baad2eb77a91847893c82e5866eaabedb810"
        npm_pkg_hash_0_1_23 = "6caf89b059e9b6c82bb4ac4727816d516753c4d26833434dea0ecda44a346eb3"
        npm_pkg_hash_0_1_25 = "a6870826cd7c7ec8d32af227252efcdcdca03ac956d4702cdc2157ca82641673"

    strings:
        $sckit_path = ".sckit/" ascii
        $stage0 = "stage0" ascii
        $config64 = "--config64" ascii
        $openclaw = "openclaw" ascii
        $spawn = "spawn" ascii
        $devnull = "/dev/null" ascii

    condition:
        filesize < 256KB and
        $sckit_path and $stage0 and $config64 and
        ($openclaw or ($spawn and $devnull))
}

rule memtensor_sckit_python_loader
{
    meta:
        description = "Detects the sckit Python loader from compromised MemoryOS PyPI package"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://socket.dev/blog/memtensor-compromise"
        pypi_wheel_hash = "39ee644406829a4b630b31759c20478bc22d576d6a59b253ed86f72c360aa5ef"
        pypi_sdist_hash = "92b46d18fc553c494eda714f204459edb74c205bf53b18a9092bcf02c7a6c5be"

    strings:
        $stage0_py = "_stage0.py" ascii
        $sckit_config = "_sckit_config64" ascii
        $pypi_bridge = "_pypi_bridge.sh" ascii
        $ci_delivery = "_initial_ci_delivery.py" ascii
        $sckit_poetry = "sckit_poetry_build" ascii

    condition:
        filesize < 10MB and 3 of them
}
```

## Lessons Learned

This attack demonstrates the cascading risk of CI/CD pipeline compromise: by hijacking a single GitHub Actions workflow via `BASH_ENV` injection, the attacker obtained registry publish tokens and weaponized legitimate packages trusted by downstream consumers. The worm-like propagation capability (embedded templates for npm, PyPI, and GitHub Actions) means a single compromised developer could seed infections across their entire project portfolio. Defenders should treat CI publish tokens as crown jewels, enforce short-lived OIDC-based authentication for registry publishing, pin GitHub Actions to commit SHAs rather than tags, and deploy supply chain monitoring tools that detect unexpected binary additions to package artifacts. The time-bounded C2 configuration (expiring Oct 22, 2026) suggests the operator planned a finite campaign window, but the stolen credentials may be exploited beyond that date.

## Sources

- [The Hacker News -- Compromised MemTensor Packages Deliver sckit](https://thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html) -- primary news report covering affected packages, C2 domain, and multi-ecosystem scope
- [Aikido -- "supplychain.local": Novel Go Worm in MemTensor npm/PyPI](https://www.aikido.dev/blog/supplychain-local-memtensor-npm-pypi) -- detailed technical analysis with SHA256 hashes, C2 subdomains, URI patterns, credential file targets, and propagation templates
- [Socket -- MemTensor npm and PyPI Packages Compromised](https://socket.dev/blog/memtensor-compromise) -- comprehensive IOC listing with per-platform binary hashes, file paths, package delivery mechanism analysis, and attack timeline
- [SafeDep -- MemTensor sckit Worm: npm and PyPI](https://safedep.io/memtensor-sckit-worm-npm-pypi) -- GitHub Actions compromise mechanism analysis, BASH_ENV hijack technique, malicious commit details, and worm propagation function names

---
*Report generated by Actioner*
