# Technical Analysis Report: Tensorlake npm Supply Chain Compromise -- Shai-Hulud Worm (2026-10-08)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-08
Version: 1.0

## Executive Summary

On October 8, 2026, version 0.5.144 of the `tensorlake` npm package -- the official TypeScript SDK for TensorLake -- was published with a malicious payload identified as a variant of the **Shai-Hulud** self-propagating npm worm. The compromise was detected by Socket.dev within 11 minutes of publication (flagged at 01:23:10 UTC). The malicious version introduces a `preinstall` lifecycle hook that executes an obfuscated dropper (`setup.mjs`), which downloads the Bun runtime and launches a ~856 KB credential-stealing and self-propagating payload (`Math_Symbol.js`). The malware targets npm tokens, GitHub tokens, AWS/GCP/Azure credentials, HashiCorp Vault secrets, Kubernetes configs, SSH keys, cryptocurrency wallet data, browser extensions, and AI tooling configurations. It resolves its C2 domain via an Ethereum smart contract (EtherHiding), currently pointing to `iseekaigogo[.]com`. A dead-man's switch threatens to wipe the infected host's home directory if the embedded GitHub token is revoked before the persistence mechanism is removed.

The root cause is assessed as a compromised maintainer account. The malicious release went through the project's normal GitHub Actions CI/CD pipeline and carried valid Sigstore build provenance -- underscoring that provenance proves where a build came from, not that the source was clean. The malicious version has been removed from npm. Version 0.5.143 is confirmed clean. Six companion `tensorlake-native-*@0.5.144` binary packages published from the same run contained no observed payload but should be treated as affected. PyPI and Cargo distributions were not impacted. The package had approximately 12,000 weekly downloads.

This is the third major Shai-Hulud campaign in 2026, following the @antv Mini Shai-Hulud wave (May), the @redhat-cloud-services Miasma variant (June), and the ChainDrop keyv/cacheable mass-propagation event (August, 400+ packages). OX Security reports the cryptographic public keys in the Tensorlake variant differ from prior campaigns, and the original TeamPCP group members were reportedly arrested in August -- suggesting either a copycat or an independent actor reusing the Shai-Hulud codebase.

## Background: TensorLake and the npm Ecosystem

TensorLake is a data processing and AI pipeline platform. Its npm package (`tensorlake`) provides the TypeScript SDK for interacting with TensorLake services. The package had approximately 12,000 weekly downloads and over 100,000 lifetime installs at the time of compromise. Like many npm packages, it uses lifecycle hooks (`preinstall`, `postinstall`) that execute arbitrary code during `npm install` -- a feature repeatedly exploited in supply chain attacks. The `preinstall` hook executes before the package's code is available to the consuming project, making it an ideal vector for pre-execution malware delivery in CI/CD pipelines.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-10-07 01:20 | First malicious commit (`e90c47bbb2`) pushed to `tensorlakeai/tensorlake` repository under a maintainer's identity |
| 2026-10-07 ~01:20--2026-10-08 01:12 | ~20-hour window during which the repository contained malicious code before npm publish |
| 2026-10-08 01:12:07 | Malicious `tensorlake@0.5.144` published to npm via GitHub Actions release run `37706134202` |
| 2026-10-08 01:12 | Six `tensorlake-native-*@0.5.144` binary packages published from the same pipeline run |
| 2026-10-08 01:23:10 | Socket.dev flags the malicious release (~11 minutes after publication) |
| 2026-10-08 (time unknown) | Malicious version removed from npm registry |
| 2026-10-08 | Multiple security vendors (Socket, Endor Labs, OX Security, Aikido, Elastic) publish analyses |

## Root Cause: Compromised Maintainer Account via GitHub Actions Pipeline

The attacker gained access to a maintainer's GitHub account and pushed verified commits to the `tensorlakeai/tensorlake` repository. The most notable commits include `e90c47bbb2` (initial malicious code injection on Oct 7) and `41b38f0` (malware introduction via direct file upload, per Aikido). The malicious release then flowed through the project's legitimate GitHub Actions CI/CD pipeline (release run `37706134202`), producing a valid Sigstore build provenance attestation. This is consistent with Shai-Hulud's established playbook: compromise a maintainer account, inject code into the trusted pipeline, and let the automation publish the backdoored release.

As Endor Labs noted: "Provenance confirms where a build came from, not that the source was clean."

## Technical Analysis of the Malicious Payload

### 1. Stage 1: Preinstall Hook and Dropper (setup.mjs)

The compromised `package.json` contains:
```json
"scripts": {
    "preinstall": "node lib/setup.mjs"
}
```

The `setup.mjs` file (SHA-256: `25a0735d0db7dc40e5d45ce42d9c106067e6a66e184d967cfecfab17c3bcb5ef`) is an obfuscated JavaScript loader. Its primary functions:

1. **CI environment detection**: Checks for environment variables (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `RUNNER_ENVIRONMENT`, and others for Jenkins, CircleCI, Travis, Buildkite, Azure DevOps, Bitbucket, Drone, Netlify, Vercel) to identify build environments
2. **Bun runtime bootstrap**: Downloads Bun v1.3.13 from `github[.]com/oven-sh/bun/releases/download/bun-v1.3.13/` if not already present
3. **Payload execution**: Launches the Stage 2 payload (`lib/Math_Symbol.js`) under the Bun runtime to sidestep Node.js-centric EDR monitoring

### 2. Stage 2: Credential Stealer and Worm Payload (Math_Symbol.js)

The main payload (SHA-256: `b50a00900399ba99fb6ce1fc151519cb99d44320ef2a631f2237e1aea0ad6fec`) is approximately 856 KB of heavily obfuscated JavaScript using control-flow flattening and Base91 string encoding. It contains Dune-themed strings (`sandworm`, `sardaukar`, `fedaykin`, `ornithopter`, `sietch`, `navigator`, `lasgun`, `mentat`, `ghola`, `tleilaxu`, `kanly`, `laza`).

**Worm marker**: Sets `globalThis.WORMTAG='tensrlake'` to tag infected packages and prevent reinfection.

**Credential harvesting targets over 300 unique patterns across:**

- **npm**: `.npmrc` files, npm token API, OIDC token exchange
- **GitHub**: Tokens checked for repository and workflow permissions; PATs (`ghp_`, `gho_`, `ghs_`)
- **AWS**: IMDS (`169.254.169[.]254`), ECS task credentials (`169.254.170[.]2`), Secrets Manager, SSM Parameter Store, `~/.aws/credentials`, `~/.aws/config`
- **GCP**: `~/.config/gcloud/legacy_credentials`
- **Azure**: `~/.azure`
- **HashiCorp Vault**: Local instance at `127.0.0[.]1:8200`, including Kubernetes and AWS auth paths; token paths at `~/.vault-token`, `/home/runner/.vault-token`, `/vault/token`, `/var/run/secrets/vault-token`, `/var/run/secrets/vault/token`, `/run/secrets/vault_token`, `/run/secrets/VAULT_TOKEN`, `~/.vault/token`, `/etc/vault/token`
- **Kubernetes**: Service-account tokens, `KUBECONFIG`, `~/.kube/config`, `~/.kube/cache/discovery`, `~/.kube/http-cache`, `~/.config/helm`
- **SSH**: `~/.ssh`, `/etc/ssh`, private keys
- **Docker**: `~/.docker`, `/var/lib/docker/containers`
- **VPN**: `/etc/openvpn`, `~/.cert/nm-openvpn`
- **TLS/Certificates**: `/etc/ssl/private`, `/etc/letsencrypt/live`, `/etc/ssl/cert.pem`, `~/.pki/nssdb`
- **Keyrings**: `~/.local/share/keyrings`, `~/.local/share/gopass/stores`, `~/.config/kwalletd`, `~/.gnupg/private-keys-v1.d`
- **Environment files**: `.env` files across project directories
- **AI tooling**: `.claude`, `.cursor`, `.kiro`, Windsurf, Zed, `~/.config/github-copilot` configurations and MCP files
- **Messaging/Remote**: Signal, Telegram Desktop `tdata`, Discord, Element, Remmina
- **Browsers**: Firefox, Chrome, Chromium, Brave, Edge, Opera, Vivaldi profiles and extensions

**Cryptocurrency wallet extension theft** (14 targeted Chrome extensions):

| Extension ID | Wallet |
|---|---|
| `nkbihfbeogaeaoehlefnkodbefgpgknn` | MetaMask |
| `bfnaelmomeimhlpmgjnjophhpkkoljpa` | Phantom |
| `hnfanknocfeofbddgcijnmhnfnkdnaad` | Coinbase Wallet |
| `acmacodkjbdgmoleebolmdjonilkdbch` | Rabby Wallet |
| `egjidjbpglichdcondbcbdnbeeppgdph` | Trust Wallet |
| `ibnejdfjmmkpcnlpebklmnkoeoihofec` | TronLink |
| `fnjhmkhhmkbjkkabndcnnogagogbneec` | Ronin Wallet |
| `bhhhlbepdkbapadjdnnojkbgioiodbic` | Solflare Wallet |
| `dmkamcknogkgcdfhhbddcghachkejeap` | Keplr |
| `aholpfdialjgjfhomihkjbmgjidlcdno` | Exodus Web3 Wallet |
| `mcohilncbfahbmgdjkbpemcciiolgcge` | OKX Wallet |
| `opfgelmcmbiajamepnmloijbpoleiama` | Rainbow |
| `ppbibelpcjmhbdihakflkdcoccbgbkpo` | UniSat Wallet |
| `lgmpcpglpngdoalbgeoldeajfclnhafa` | SafePal Extension Wallet |

**HackBrowserData binary**: The malware downloads a platform-matched `HackBrowserData` binary from the C2 to extract additional browser-stored credentials, cookies, and history.

**Exfiltration encryption**: Stolen data is gzip-compressed, encrypted with a randomly generated AES-256-GCM key, and the AES key is RSA-encrypted with the attacker's hardcoded public key. Two new RSA public keys are embedded (partial prefixes per OX Security):
- `MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsx7qQlP6BjB14dud92Hk`
- `MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmSsAhtZtB2S7XBxe5Ofr`

### 3. C2 Infrastructure

**Primary C2 domain**: `iseekaigogo[.]com`

**EtherHiding dead-drop resolution**: The malware queries an Ethereum smart contract at address `0xb614155Fd88114d40549b259457Bcf921Df091B9` to dynamically resolve its C2 domain. The contract was last updated on September 21, 2026, from wallet `0x779f83aE56309682beDb04816c19d358c4B21040` (holding approximately $12.44, created ~16 days before the attack). The contract currently points to the same hardcoded domain.

**Ethereum RPC endpoints used for contract resolution** (approximately 30, named ones include):
- `eth[.]llamarpc[.]com`
- `rpc[.]ankr[.]com`
- `ethereum[.]publicnode[.]com`
- `go[.]getblock[.]io`
- `eth-mainnet[.]nodereal[.]io`

**GitHub fallback C2**: The worm searches GitHub commit history for a signed marker string `thebeautifulmarchoftime` and validates against an embedded RSA public key.

**Exfiltration fallback**: Creates public GitHub repositories on the victim's account with Dune-themed names and description `Shai-Hulud: Here We Go Again`.

**Abused legitimate endpoints** (not attacker-controlled):
- `api[.]github[.]com` -- credential checks, repository creation, token monitoring
- `registry[.]npmjs[.]org` -- token checks, OIDC exchange, maintainer lookup, republishing
- `169.254.169[.]254` -- AWS/cloud instance metadata (IMDS)
- `169.254.170[.]2` -- ECS/container task credentials
- `127.0.0[.]1:8200` -- local HashiCorp Vault

### 4. Platform-Specific Behavior

#### Linux
- **Persistence**: systemd user unit `~/.config/systemd/user/gh-token-monitor.service`; script `~/.local/bin/gh-token-monitor.sh`; config directory `~/.config/gh-token-monitor/`
- **Dead-man's switch wipe**: `rm -rf ~/`

#### macOS
- **Persistence**: LaunchAgent at `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`
- **Dead-man's switch wipe**: `rm -rf ~/`

#### Windows
- **Persistence**: `ONLOGON` scheduled task named `gh-token-monitor` running `monitor.ps1`; files in `%LOCALAPPDATA%\gh-token-monitor`
- **Dead-man's switch wipe**: `Remove-Item $env:USERPROFILE -Recurse -Force`

### 5. Self-Propagation Mechanism

The worm activates only when a stolen npm token has package write permissions (and the ability to publish without 2FA). For each writable package associated with the victim's publishing identity:

1. Downloads the latest tarball from the npm registry
2. Extracts it to a temporary directory
3. Injects `Math_Symbol.js` (or variant names: `math_init.js`, `opensearch_init.js`, `ai_init.js`) and `setup.mjs`
4. Adds the `preinstall` hook and bumps the patch version in `package.json`
5. Builds Sigstore provenance and republishes to npm

The worm also plants GitHub Actions workflows and developer-tool hooks:
- `.claude/settings.json` with a `SessionStart` hook pointing to `.claude/setup.mjs`
- `.vscode/tasks.json` with a `folderOpen` task pointing to `.vscode/setup.mjs`
- Commits these hooks to up to 50 branches per accessible repository
- Uses worm commit signature: author `claude`, message `chore: update config` or `Add Copilot workflow` / `chore: update dependencies`

### 6. Dead-Man's Switch / Anti-Forensics

The `gh-token-monitor` persistence daemon polls `api[.]github[.]com/user` with the embedded stolen GitHub token. If the token is revoked (indicating the victim has detected the compromise), the daemon executes an attacker-supplied handler via `Invoke-Expression` (Windows) or the equivalent on other platforms, resulting in recursive deletion of the user's home directory.

Key intimidation strings:
- `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`
- `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients`

**Critical remediation implication**: The persistence mechanism MUST be removed before revoking any stolen tokens.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots
> - Email addresses: `[at]` replacing @

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `tensorlake` | 0.5.144 | Preinstall hook executing `node lib/setup.mjs`; credential stealer and self-propagating worm |
| `tensorlake-native-linux-x64` | 0.5.144 | Binary companion; no payload observed but from same compromised build |
| `tensorlake-native-linux-arm64` | 0.5.144 | Same |
| `tensorlake-native-darwin-x64` | 0.5.144 | Same |
| `tensorlake-native-darwin-arm64` | 0.5.144 | Same |
| `tensorlake-native-win32-x64` | 0.5.144 | Same |
| `tensorlake-native-win32-arm64` | 0.5.144 | Same |

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Cross-platform | `lib/setup.mjs` | `25a0735d0db7dc40e5d45ce42d9c106067e6a66e184d967cfecfab17c3bcb5ef` | Obfuscated dropper; bootstraps Bun and launches payload |
| Cross-platform | `lib/Math_Symbol.js` | `b50a00900399ba99fb6ce1fc151519cb99d44320ef2a631f2237e1aea0ad6fec` | ~856 KB obfuscated credential stealer and worm payload |
| Linux | `~/.config/systemd/user/gh-token-monitor.service` | -- | Systemd user unit for persistence |
| Linux | `~/.local/bin/gh-token-monitor.sh` | -- | Persistence script |
| Linux | `~/.config/gh-token-monitor/` | -- | Persistence configuration directory |
| macOS | `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` | -- | LaunchAgent for persistence |
| Windows | `%LOCALAPPDATA%\gh-token-monitor\monitor.ps1` | -- | PowerShell persistence script |
| Cross-platform | `.claude/settings.json` | -- | Developer-tool hijack (SessionStart hook) |
| Cross-platform | `.claude/setup.mjs` | -- | Developer-tool hijack payload |
| Cross-platform | `.vscode/tasks.json` | -- | Developer-tool hijack (folderOpen task) |
| Cross-platform | `.vscode/setup.mjs` | -- | Developer-tool hijack payload |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `iseekaigogo[.]com` | Primary C2 domain (resolved via EtherHiding; disposable) |
| ETH Address | `0xb614155Fd88114d40549b259457Bcf921Df091B9` | EtherHiding resolver contract (durable indicator) |
| ETH Wallet | `0x779f83aE56309682beDb04816c19d358c4B21040` | Contract updater wallet |
| Domain | `eth[.]llamarpc[.]com` | Ethereum RPC endpoint (legitimate, used for contract resolution) |
| Domain | `rpc[.]ankr[.]com` | Ethereum RPC endpoint (legitimate) |
| Domain | `ethereum[.]publicnode[.]com` | Ethereum RPC endpoint (legitimate) |
| Domain | `go[.]getblock[.]io` | Ethereum RPC endpoint (legitimate) |
| Domain | `eth-mainnet[.]nodereal[.]io` | Ethereum RPC endpoint (legitimate) |
| URL | `hxxps://api[.]github[.]com/user` | Dead-man's switch token validation endpoint (legitimate) |
| IP | `169.254.169[.]254` | Cloud IMDS endpoint (targeted for credential theft) |
| IP | `169.254.170[.]2` | ECS/container credential endpoint (targeted) |
| IP | `127.0.0[.]1:8200` | Local HashiCorp Vault (targeted) |

### Behavioral

- Process tree: `npm` -> `node` -> `node lib/setup.mjs` -> downloads Bun -> `bun lib/Math_Symbol.js`
- Bun runtime downloaded to `/tmp/b-<random>/bun` during npm install
- DNS queries from `node` or `bun` processes to Ethereum RPC endpoints
- HTTP POST to Ethereum RPC endpoints containing contract address `0xb614155Fd88114d40549b259457Bcf921Df091B9`
- GitHub API calls to enumerate maintainer packages and create repositories with description "Shai-Hulud: Here We Go Again"
- npm registry API calls to republish packages with bumped patch versions
- File creation of `gh-token-monitor` persistence artifacts
- GitHub commits with author `claude` and message `chore: update config`
- Worm tag: `globalThis.WORMTAG='tensrlake'`
- Strings: `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`, `thebeautifulmarchoftime`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into official tensorlake npm package via compromised maintainer account |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Payload executed via Node.js preinstall hook and Bun runtime |
| T1105 | Ingress Tool Transfer | Downloads Bun runtime and HackBrowserData binary from remote servers |
| T1555 | Credentials from Password Stores | Steals credentials from browser extensions, keyrings, and credential files |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvests `.npmrc`, `.aws/credentials`, SSH keys, `.env` files, vault tokens |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Probes AWS IMDS (169.254.169.254) and ECS task credential endpoints |
| T1539 | Steal Web Session Cookie | HackBrowserData extracts browser cookies and session data |
| T1102.001 | Web Service: Dead Drop Resolver | EtherHiding: resolves C2 domain via Ethereum smart contract query (dead-drop resolver pattern) |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communications over HTTPS; data exfiltration via GitHub API |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows ONLOGON scheduled task for gh-token-monitor persistence |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS LaunchAgent for gh-token-monitor persistence |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux systemd user unit for gh-token-monitor persistence |
| T1485 | Data Destruction | Dead-man's switch wipes home directory upon token revocation |
| T1078 | Valid Accounts | Uses stolen npm tokens and GitHub PATs to publish packages and create repositories |

## Impact Assessment

- **Breadth**: tensorlake had ~12,000 weekly downloads, but the malicious version was live for a relatively short window (~hours before detection). The self-propagation mechanism means any downstream developer whose npm token was stolen could have their packages compromised in turn.
- **Depth**: Full credential compromise of all secrets on affected hosts -- npm, GitHub, AWS, GCP, Azure, Kubernetes, Vault, SSH, browser data, crypto wallets, and AI tooling configs.
- **Stealth**: Valid build provenance, no network anomalies beyond Ethereum RPC queries (common in Web3 environments), and persistence mechanisms designed to survive package removal.
- **Chilling effect**: The dead-man's switch creates a dangerous IR inversion where responders risk data destruction if they revoke stolen tokens before removing persistence.

## Detection & Remediation

### Immediate Detection

Check if the compromised version was installed:

```bash
# Check npm lockfiles for tensorlake@0.5.144
grep -r '"tensorlake.*0\.5\.144"' package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Check npm cache
npm cache ls tensorlake 2>/dev/null | grep 0.5.144

# Check for persistence artifacts (Linux)
ls -la ~/.config/systemd/user/gh-token-monitor.service 2>/dev/null
ls -la ~/.local/bin/gh-token-monitor.sh 2>/dev/null
ls -la ~/.config/gh-token-monitor/ 2>/dev/null

# Check for persistence artifacts (macOS)
ls -la ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null

# Check for persistence artifacts (Windows PowerShell)
# Get-ScheduledTask -TaskName "gh-token-monitor" 2>$null
# Test-Path "$env:LOCALAPPDATA\gh-token-monitor\monitor.ps1"

# Check for developer-tool hijack files
find . -name "setup.mjs" -path "*/.claude/*" -o -name "setup.mjs" -path "*/.vscode/*" 2>/dev/null

# Check for worm-created Git commits
git log --all --author="claude" --grep="chore: update config" 2>/dev/null
```

### Remediation

**CRITICAL: Order of operations matters. Remove persistence BEFORE revoking tokens.**

1. **Isolate affected hosts** from the network immediately
2. **Remove persistence artifacts** on each affected host:
   - Linux: `systemctl --user disable --now gh-token-monitor.service && rm -f ~/.config/systemd/user/gh-token-monitor.service ~/.local/bin/gh-token-monitor.sh && rm -rf ~/.config/gh-token-monitor/`
   - macOS: `launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist && rm ~/Library/LaunchAgents/com.user.gh-token-monitor.plist`
   - Windows: `Unregister-ScheduledTask -TaskName "gh-token-monitor" -Confirm:$false; Remove-Item -Recurse "$env:LOCALAPPDATA\gh-token-monitor"`
3. **Only then revoke and rotate ALL exposed credentials**:
   - npm tokens
   - GitHub PATs and app tokens
   - AWS access keys and session tokens
   - GCP service account keys
   - Azure credentials
   - Kubernetes service account tokens
   - HashiCorp Vault tokens
   - SSH keys
   - Any secrets in `.env` files
4. **Audit GitHub and npm activity** for unauthorized repository creation, unexpected package publications, and new workflow files
5. **Check for developer-tool hijack files**: Remove `.claude/setup.mjs`, `.claude/settings.json` (if modified), `.vscode/setup.mjs`, `.vscode/tasks.json` (if modified)
6. **Remove the malicious package**: Delete lockfile entries referencing 0.5.144 and reinstall from clean sources. Pin to `tensorlake@0.5.143`
7. **Rebuild affected CI/CD environments** from trusted images
8. **Scan for worm propagation**: Check if any packages maintained by compromised accounts have unexpected new versions

### Long-Term Hardening

- Install npm packages with `--ignore-scripts` by default; explicitly allowlist packages that need lifecycle hooks
- Upgrade to npm 12+ which blocks `preinstall` hooks by default
- Enable 2FA on all npm accounts; avoid `bypass_2fa: true` automation tokens
- Add a soak period before adopting new package versions in production
- Use lockfile-only installs in CI/CD (`npm ci` instead of `npm install`)
- Monitor for unexpected npm publishes and GitHub repository creation via audit logs
- Implement network egress controls to detect unusual DNS queries from build systems (Ethereum RPC endpoints from Node.js processes)

## Detection Rules

The rules below cover the Tensorlake Shai-Hulud attack chain from initial dropper execution through persistence installation and C2 resolution. All rules target specific, confirmed artifacts from this incident. The primary caveat is that Ethereum RPC queries from Node.js are legitimate in Web3 environments, requiring environmental tuning of the EtherHiding detection rule.

### Sigma Rule 1: Tensorlake Shai-Hulud Preinstall Hook Execution

Detects Node.js executing the `lib/setup.mjs` dropper from an npm preinstall hook, the initial execution vector for this compromise.
<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk and -t log_scale both succeed). Targets Windows process_creation; Linux/macOS coverage requires Sysmon-for-Linux or auditd equivalent. The filter_known block reduces FPs from angular/babel which also use setup scripts. -->
<!-- revision: Tightened CommandLine from setup.mjs to lib/setup.mjs + lib\setup.mjs; dropped meaningless |contains|all (single item); downgraded confidence high->medium per FP surface from other npm packages with lib/setup.mjs. -->

**Compile: pass (convert) | Confidence: medium**

```yaml
title: Tensorlake Shai-Hulud Preinstall Hook Execution via Node
id: 7c3a1e8f-4b2d-4f6a-9e0c-1d5f8a3b7c2e
status: experimental
description: >
    Detects node.js executing the Shai-Hulud dropper setup.mjs from
    the tensorlake npm package preinstall hook during npm install.
references:
    - https://socket.dev/blog/tensorlake-compromise
    - https://www.endorlabs.com/learn/tensorlake-npm-package-compromised-by-shai-hulud-in-latest-software-supply-chain-attack
author: Actioner
date: 2026-10-08
tags:
    - attack.t1059.007
    - attack.t1195.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\npm.cmd'
            - '\npx.cmd'
            - '\node.exe'
    selection_child:
        Image|endswith: '\node.exe'
        CommandLine|contains:
            - 'lib/setup.mjs'
            - 'lib\setup.mjs'
    filter_known:
        CommandLine|contains:
            - 'node_modules\@angular'
            - 'node_modules\@babel'
    condition: selection_parent and selection_child and not filter_known
falsepositives:
    - Legitimate npm packages using lib/setup.mjs as a preinstall script
level: medium
```

### Sigma Rule 2: Bun Runtime Download by Node Process

Detects a Node.js process spawning curl/wget to download the Bun runtime from GitHub releases, characteristic of the Shai-Hulud dropper bootstrap sequence.
<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk succeeds). Cross-platform logsource (no product specified). Low FP rate: developers typically install Bun via shell, not programmatically from a Node.js child process. -->
<!-- revision: Downgraded confidence high->medium; CI/CD scripts that install Bun via Node exist. -->

**Compile: pass (convert) | Confidence: medium**

```yaml
title: Bun Runtime Download by Node Process - Shai-Hulud Indicator
id: 8d4b2f9a-5c3e-4a7b-be1d-2e6f9b4c8d3f
status: experimental
description: >
    Detects a Node.js or npm process spawning curl/wget to download
    the Bun runtime from GitHub releases, a behavior characteristic
    of the Shai-Hulud worm dropper (setup.mjs).
references:
    - https://socket.dev/blog/tensorlake-compromise
    - https://www.aikido.dev/blog/tensorlake-npm-package-compromised
author: Actioner
date: 2026-10-08
tags:
    - attack.t1105
    - attack.t1059.007
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '/node'
            - '/bun'
            - '\node.exe'
            - '\bun.exe'
    selection_download:
        Image|endswith:
            - '/curl'
            - '/wget'
            - '\curl.exe'
            - '\wget.exe'
        CommandLine|contains: 'oven-sh/bun/releases'
    condition: selection_parent and selection_download
falsepositives:
    - Developers intentionally installing Bun via curl from a Node script
    - CI/CD pipelines that programmatically install Bun via Node.js
level: medium
```

### Sigma Rule 3: Shai-Hulud gh-token-monitor Persistence

Detects creation of `gh-token-monitor` persistence artifacts (systemd units, LaunchAgents, scheduled tasks) used by the Shai-Hulud worm's dead-man's switch.
<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk and -t log_scale succeed). file_event category; requires Sysmon EventID 11 or equivalent. -->
<!-- revision: Tightened monitor.ps1 to gh-token-monitor\monitor.ps1 + gh-token-monitor/monitor.ps1 to reduce FP surface; added attack.t1543.002 (Systemd Service) tag since rule also detects systemd persistence artifact. -->

**Compile: pass (convert) | Confidence: high**

```yaml
title: Shai-Hulud gh-token-monitor Persistence Installation
id: 9e5c3a0b-6d4f-4b8c-cf2e-3f7a0c5d9e4a
status: experimental
description: >
    Detects creation of gh-token-monitor persistence artifacts used
    by the Shai-Hulud worm to maintain access and enforce its
    dead-man's switch mechanism across Linux, macOS, and Windows.
references:
    - https://socket.dev/blog/tensorlake-compromise
    - https://www.ox.security/blog/shai-hulud-here-we-go-again-tensorlake-npm-package-hit-with-malware/
author: Actioner
date: 2026-10-08
tags:
    - attack.t1053.005
    - attack.t1543.001
    - attack.t1543.002
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - 'gh-token-monitor.service'
            - 'com.user.gh-token-monitor.plist'
            - 'gh-token-monitor\monitor.ps1'
            - 'gh-token-monitor/monitor.ps1'
    condition: selection
falsepositives:
    - Legitimate GitHub CLI monitoring tools (very unlikely to use this exact naming)
level: critical
```

### Sigma Rule 4: Shai-Hulud EtherHiding C2 Resolution

Detects DNS queries from Node.js or Bun processes to Ethereum RPC endpoints used by Shai-Hulud for on-chain C2 domain resolution.
<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk succeeds). dns_query category requires Sysmon EventID 22. In Web3/blockchain development environments this rule WILL produce false positives and should be tuned by environment. Medium confidence due to legitimate use of these RPC endpoints in dapp development. -->
<!-- revision: Corrected MITRE tag from T1568.002 (DGA) to T1102.001 (Dead Drop Resolver) — EtherHiding reads domain from blockchain contract, not DGA. Added .ankr.com to selection_rpc (was listed as IOC but missing from rule). -->

**Compile: pass (convert) | Confidence: medium**

```yaml
title: Shai-Hulud EtherHiding C2 Resolution via Ethereum RPC
id: af6d4b1c-7e5a-4c9d-d03f-4a8b1d6e0f5b
status: experimental
description: >
    Detects DNS queries to Ethereum RPC endpoints used by the
    Shai-Hulud worm to resolve its C2 domain via an on-chain
    smart contract (EtherHiding technique).
references:
    - https://www.endorlabs.com/learn/tensorlake-npm-package-compromised-by-shai-hulud-in-latest-software-supply-chain-attack
    - https://www.aikido.dev/blog/tensorlake-npm-package-compromised
author: Actioner
date: 2026-10-08
tags:
    - attack.t1102.001
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection_rpc:
        QueryName|endswith:
            - '.llamarpc.com'
            - '.publicnode.com'
            - '.nodereal.io'
            - '.ankr.com'
            - 'go.getblock.io'
    selection_process:
        Image|endswith:
            - '/node'
            - '/bun'
            - '\node.exe'
            - '\bun.exe'
    condition: selection_rpc and selection_process
falsepositives:
    - Legitimate blockchain/Web3 applications querying Ethereum RPC endpoints from Node.js
level: medium
```

### YARA Rule: Shai-Hulud Tensorlake Payload and Dropper

Detects the Shai-Hulud worm payload (`Math_Symbol.js`) and dropper (`setup.mjs`) from the compromised `tensorlake@0.5.144` package via characteristic strings and markers.
<!-- audit: compile-status=pass (yarac exit 0). Two rules in one file: payload detection (critical) uses wormtag+tensrlake marker, kill-switch string, ETH address with Dune strings, or C2 domain with Math_Symbol reference; dropper detection (high) uses Bun download URL with payload/worm references. File size constraints limit scanning overhead. -->

**Compile: pass (yarac) | Confidence: high**

```yara
rule Supply_Chain_ShaiHulud_Tensorlake_Payload
{
    meta:
        description = "Detects the Shai-Hulud worm payload (Math_Symbol.js) from the compromised tensorlake@0.5.144 npm package"
        author = "Actioner"
        date = "2026-10-08"
        reference = "https://socket.dev/blog/tensorlake-compromise"
        hash = "b50a00900399ba99fb6ce1fc151519cb99d44320ef2a631f2237e1aea0ad6fec"
        severity = "critical"

    strings:
        $wormtag = "WORMTAG" ascii
        $tensrlake = "tensrlake" ascii
        $killswitch = "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner" ascii
        $marker = "thebeautifulmarchoftime" ascii
        $dune1 = "sandworm" ascii
        $dune2 = "sardaukar" ascii
        $dune3 = "fedaykin" ascii
        $dune4 = "ornithopter" ascii
        $dune5 = "sietch" ascii
        $eth_addr = "0xb614155Fd88114d40549b259457Bcf921Df091B9" ascii
        $c2_domain = "iseekaigogo" ascii
        $math_sym = "Math_Symbol" ascii

    condition:
        filesize < 2MB and
        (
            ($wormtag and $tensrlake) or
            $killswitch or
            ($eth_addr and 2 of ($dune*)) or
            ($c2_domain and $math_sym) or
            (4 of ($dune*) and $marker)
        )
}

rule Supply_Chain_ShaiHulud_Tensorlake_Dropper
{
    meta:
        description = "Detects the Shai-Hulud dropper (setup.mjs) from the compromised tensorlake@0.5.144 npm package"
        author = "Actioner"
        date = "2026-10-08"
        reference = "https://socket.dev/blog/tensorlake-compromise"
        hash = "25a0735d0db7dc40e5d45ce42d9c106067e6a66e184d967cfecfab17c3bcb5ef"
        severity = "high"

    strings:
        $setup_import = "Math_Symbol" ascii
        $bun_download = "oven-sh/bun/releases" ascii
        $wormtag = "WORMTAG" ascii
        $worm_profile = "WORM_PROFILE" ascii

    condition:
        filesize < 500KB and
        $bun_download and
        ($setup_import or $wormtag or $worm_profile)
}
```

### Suricata Rules: Shai-Hulud C2 and EtherHiding Detection

Two rules covering DNS resolution of the primary C2 domain and HTTP requests containing the attacker's smart contract address. SIDs 2100010-2100012 fall within the Emerging Threats reserved range; for production deployment, organizations should use their own SID allocation (e.g., 9000000+).
<!-- audit: compile-status=pass (suricata -T exit 0, "Configuration provided was successfully loaded"). Rule 2100010 targets the specific C2 domain (high confidence, disposable domain); 2100012 targets the contract address in HTTP POST bodies (high confidence, durable IOC but requires TLS inspection). -->
<!-- revision: Dropped Suricata 2100011 per critic — eth.llamarpc.com is a major public RPC endpoint; DNS-only detection without process context produces unacceptable FP rate at specific/strict altitude. -->

### Suricata Rule 2100010: C2 Domain DNS

Detects DNS queries for the Shai-Hulud primary C2 domain `iseekaigogo.com`.
<!-- audit: High confidence; disposable domain with no legitimate use. -->

**Compile: pass (suricata -T) | Confidence: high**

```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - Shai-Hulud C2 Domain Resolution (iseekaigogo.com)"; flow:to_server; dns.query; content:"iseekaigogo.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/tensorlake-compromise; metadata:author Actioner, created_at 2026-10-08, mitre_attack T1102.001; sid:2100010; rev:1;)
```

### Suricata Rule 2100012: Ethereum Contract HTTP Query

Detects HTTP POST requests containing the attacker's Ethereum smart contract address used for EtherHiding C2 resolution. Requires TLS inspection (MITM proxy / SSL termination) to be effective, since virtually all Ethereum RPC traffic is HTTPS.
<!-- audit: High confidence where TLS inspection is deployed; contract address is a durable, unique IOC. -->
<!-- revision: Added TLS inspection caveat; updated MITRE metadata from T1568.002 to T1102.001. -->

**Compile: pass (suricata -T) | Confidence: high**

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Shai-Hulud Ethereum Contract Query for C2 Resolution"; flow:established,to_server; http.request_body; content:"0xb614155Fd88114d40549b259457Bcf921Df091B9"; fast_pattern; classtype:trojan-activity; reference:url,www.endorlabs.com/learn/tensorlake-npm-package-compromised-by-shai-hulud-in-latest-software-supply-chain-attack; metadata:author Actioner, created_at 2026-10-08, mitre_attack T1102.001; sid:2100012; rev:1;)
```

## Lessons Learned

1. **Build provenance is necessary but not sufficient.** The malicious tensorlake release carried valid Sigstore provenance because the attacker modified the source before the trusted pipeline built it. Provenance proves the build happened where it claimed; it does not prove the source was clean. Organizations need source-level integrity checks, not just build-output attestation.

2. **Preinstall hooks remain the npm ecosystem's most dangerous feature.** This is the third major Shai-Hulud campaign exploiting `preinstall` hooks in 2026 alone. npm 12's decision to block preinstall hooks by default is the correct structural fix. Until adoption is widespread, `--ignore-scripts` and explicit allowlisting are the recommended defense.

3. **IR playbooks must account for adversarial anti-forensics.** The dead-man's switch that wipes the victim's home directory upon token revocation creates a dangerous inversion: the natural first step in incident response (revoke compromised credentials) becomes the trigger for data destruction. Detection engineering and IR procedures must be updated to prioritize persistence removal before credential rotation.

4. **The Shai-Hulud codebase has become a shared weapon.** With the original TeamPCP group reportedly arrested in August 2026 and new public keys appearing in the Tensorlake variant, the Shai-Hulud toolkit has effectively become a commodity. Defenders should expect continued incidents using this codebase with varying operators and infrastructure.

5. **EtherHiding provides durable C2 resilience.** On-chain C2 resolution via Ethereum smart contracts means domain takedowns alone cannot sever the attacker's control channel. Detection must focus on the RPC resolution pattern (Node.js processes querying Ethereum endpoints) and the contract address itself.

## Sources

- [Socket.dev - TensorLake npm SDK Compromised in ChainDrop Shai-Hulud Credential-Stealing Attack](https://socket.dev/blog/tensorlake-compromise) -- primary technical analysis with file hashes, persistence details, remediation guidance, and discovery timeline
- [Endor Labs - Tensorlake npm package compromised by Shai-Hulud](https://www.endorlabs.com/learn/tensorlake-npm-package-compromised-by-shai-hulud-in-latest-software-supply-chain-attack) -- root cause analysis, provenance discussion, C2 infrastructure, and EtherHiding details
- [OX Security - Shai-Hulud: Here We Go Again](https://www.ox.security/blog/shai-hulud-here-we-go-again-tensorlake-npm-package-hit-with-malware/) -- attribution analysis, cryptographic key comparison, dead-man's switch details, and Ethereum wallet tracking
- [Aikido - tensorlake NPM package compromised with Shai Hulud worm](https://www.aikido.dev/blog/tensorlake-npm-package-compromised) -- detailed credential target enumeration, crypto wallet extension IDs, HackBrowserData analysis, and environment variable lists
- [Elastic Security Labs - Shai-Hulud CHAINDROP npm Supply Chain](https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain) -- CHAINDROP variant analysis, prior campaign details, developer-tool hijack mechanisms, and self-propagation flow
- [The Hacker News - Tensorlake npm Package Compromised](https://thehackernews.com/2026/10/tensorlake-npm-package-compromised-to.html) -- initial public reporting and summary
- [CyberPress - Malicious Tensorlake npm Package Steals AWS Keys, SSH Credentials and Crypto Wallet Data](https://cyberpress.org/tensorlake-package-steals-credentials/) -- additional coverage

---
*Report generated by Actioner*
