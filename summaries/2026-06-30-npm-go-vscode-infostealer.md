# Hijacked npm and Go Packages Use VS Code Tasks to Deploy Python Infostealer (2026-06-30)

Prepared by: Actioner
Sources: [The Hacker News](https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html), [JFrog Security Research](https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/)
Date: 2026-06-30

## Summary

Two hijacked npm packages and 16 Go packages were weaponized to deploy a cross-platform Python-based information stealer via a novel VS Code task auto-execution technique. The attack avoids npm lifecycle scripts (compatible with npm v12 security hardening) and instead hides execution inside a VS Code task configured to run on folder open. The payload chain uses blockchain dead drops (TronGrid, Aptos, BSC) to retrieve encrypted JavaScript, launches a socket.io backdoor, and ultimately deploys the "InvisibleFerret" Python infostealer. Attributed to North Korea's "Fake Font" campaign, a variant of the "Contagious Interview" operation targeting software developers.

## Attack Chain

1. **Initial Access**: Developer installs hijacked npm package (`html-to-gutenberg@4.2.11` or `fetch-page-assets@1.2.9`) or one of 16 compromised Go packages
2. **Execution Trigger**: `.vscode/tasks.json` contains task "eslint-check" with `runOn: folderOpen` -- auto-executes when workspace opens in VS Code or Cursor
3. **Payload Disguise**: Task runs `node ./public/fonts/fa-solid-400.woff2` -- JavaScript code disguised as a font file with 752 leading spaces to appear empty
4. **Dead Drop Resolution**: JS contacts TronGrid/Aptos/BSC blockchain APIs to retrieve encrypted C2 URLs from transaction data (XOR-decoded after `?.?` marker)
5. **Backdoor**: Socket.io backdoor connects to C2, provides shell execution, clipboard harvesting, file operations, process management
6. **Python Deployment**: Downloads and installs Python (`python.zip`/`python.7z`/`7zr.exe`/`get-pip.py`)
7. **Data Theft**: Python infostealer harvests credentials, wallets, developer tools, cloud storage metadata
8. **Exfiltration**: Data packaged as compressed ZIP (`<hostname>$<username>`) and uploaded to C2 + Telegram bot

## Compromised Packages

### npm Packages
| Package | Version | Upload Date | JFrog Detection |
|---------|---------|-------------|-----------------|
| html-to-gutenberg | 4.2.11 | 2026-05-25 | XRAY-1008590 |
| fetch-page-assets | 1.2.9 | 2026-05-25 | XRAY-1008535 |

### Go Packages (16 -- discovered by Nextron Systems)
| Package |
|---------|
| github[.]com/lambda-platform/lambda |
| github[.]com/reauheau/goaubio |
| github[.]com/glacialspring/go-winsparkle |
| github[.]com/bm-197/chill |
| github[.]com/naol7/dist-task-scheduler |
| github[.]com/anatoli-derese/a2sv-excercise |
| github[.]com/amantsehay/a2sv-go-course |
| github[.]com/dexbotsdev/uniswap-v2-v3-arbitrage |
| github[.]com/lambda-platform/ebarimt-rest-api |
| github[.]com/lambda-platform/dan |
| github[.]com/zainirfan13/graphql-client |
| github[.]com/hngi/team-fierce-backend-golang |
| github[.]com/glacialspring/static |
| github[.]com/rickt/slack-weather-bot |
| github[.]com/Barsu5489/commerce |
| github[.]com/Setsu548/Logistic |

## IOCs (Defanged)

### C2 Infrastructure

> **Note:** C2 IP addresses are subject to rotation. These indicators have a limited shelf life and should be reviewed periodically for continued relevance.

| Indicator | Type | Context |
|-----------|------|---------|
| 166[.]88[.]134[.]62 | IPv4 | C2 server (port 443) |
| 198[.]105[.]127[.]210 | IPv4 | C2 server (port 443) |
| 23[.]27[.]202[.]27 | IPv4 | C2 server (ports 443, 27017) |

### C2 Endpoints
- `/$/boot` -- initial beacon
- `/$/{id}` -- session management
- `/verify-human/{channel}` -- verification
- `/snv` -- staging
- `/u/e`, `/u/f` -- upload endpoints
- `/d/python.zip`, `/d/python.7z`, `/d/7zr.exe` -- payload downloads

### Blockchain Dead Drop Addresses (TronGrid)
| Address | Purpose |
|---------|---------|
| TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP | Dead drop resolver |
| TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG | Dead drop resolver |
| TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v | Dead drop resolver |

### Blockchain Dead Drop Addresses (Aptos)
| Address | Purpose |
|---------|---------|
| 0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e | Dead drop resolver |
| 0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3 | Dead drop resolver |
| 0x533b2dbcaeff19cd1f799234a27b578d713d8fcaa341b7501e4526106483e0b1 | Dead drop resolver |

### Abused Legitimate Services
| Domain | Service |
|--------|---------|
| api[.]trongrid[.]io | TronGrid blockchain API |
| fullnode[.]mainnet[.]aptoslabs[.]com | Aptos blockchain API |
| bsc-dataseed[.]binance[.]org | Binance Smart Chain RPC |
| bsc-rpc[.]publicnode[.]com | BSC public RPC |
| api[.]telegram[.]org | Telegram Bot API (exfil) |

### Telegram Exfiltration
- Bot target ID: `7699029999`
- Pattern: `https://api[.]telegram[.]org/bot{token}/sendDocument`

### File System Artifacts
| Path | Platform | Purpose |
|------|----------|---------|
| .vscode/tasks.json | All | Malicious task definition |
| public/fonts/fa-solid-400.woff2 | All | JS payload disguised as font |
| %LOCALAPPDATA%\Programs\Python\Python3127\python.exe | Windows | Dropped Python runtime |
| %USERPROFILE%\.npm | Windows | Data staging directory |
| ~/.node_modules | Linux/macOS | Dependency staging |
| /tmp/.npm | Linux/macOS | Data staging directory |
| /tmp/get-pip.py | Linux/macOS | pip installer |

### Victim Identifier Pattern
- ZIP archive naming: `<hostname>$<username>`
- `_V` header with codes like `A8-**` used for C2 selection

## Data Targeted by Infostealer

- **Browsers**: Chromium-based and Mozilla Firefox (passwords, cookies, history)
- **Password Managers & Authenticators**: Various desktop applications
- **Cryptocurrency Wallets**: Multiple wallet applications
- **Developer Tools**: Git credentials, GitHub CLI (`hosts.yml`), GitHub Desktop logs, VS Code global storage, npm CLI
- **OS Credential Stores**: Windows Credential Manager, Linux Secret Service, KDE Wallet, macOS Keychain
- **Cloud Storage**: Dropbox, Google Drive, Microsoft OneDrive, Apple iCloud, Box, Mega, pCloud (metadata)

## MITRE ATT&CK Mapping

| Technique | ID | Context |
|-----------|----|---------|
| Supply Chain Compromise: Compromise Software Dependencies | T1195.001 | Hijacked npm/Go packages |
| Command and Scripting Interpreter: JavaScript | T1059.007 | JS disguised as font file |
| Command and Scripting Interpreter: Python | T1059.006 | Python infostealer deployment |
| Scheduled Task/Job | T1053 | VS Code task auto-execution on folder open |
| Obfuscated Files or Information | T1027 | 752 leading spaces, font file disguise |
| Web Service: Dead Drop Resolver | T1102.001 | Blockchain APIs for C2 resolution |
| Application Layer Protocol: Web Protocols | T1071.001 | Socket.io over HTTP/HTTPS |
| Credentials from Password Stores | T1555 | Browser, OS, and app credential theft |
| Credentials from Web Browsers | T1555.003 | Chromium and Firefox data theft |
| Unsecured Credentials | T1552 | Git creds, GitHub CLI, dev tool configs |
| Data Staged: Local Data Staging | T1074.001 | ZIP archives in .npm / /tmp/.npm |
| Exfiltration Over C2 Channel | T1041 | Data upload to C2 server |
| Exfiltration Over Web Service | T1567 | Telegram bot upload |
| Ingress Tool Transfer | T1105 | Python runtime download |
| Clipboard Data | T1115 | Clipboard harvesting via backdoor |

## Attribution

- **Campaign**: "Fake Font" -- variant of "Contagious Interview"
- **Actor**: Suspected North Korea (DPRK)
- **Backdoor**: InvisibleFerret
- **Tracking**: OpenSourceMalware team
- **Active Since**: Contagious Interview campaign ongoing since 2023

## Detection Index

| # | Detection | Type | File | Confidence |
|---|-----------|------|------|------------|
| 1 | VS Code task spawning node to execute font-disguised JS | Sigma | `sigma/npm-go-vscode-infostealer-vscode-task-exec.yml` | high |
| 2 | Python execution from unusual staging paths | Sigma | `sigma/npm-go-vscode-infostealer-python-staging.yml` | medium |
| 3 | DNS queries to blockchain dead drop APIs from dev tools | Sigma | `sigma/npm-go-vscode-infostealer-c2-dns.yml` | medium |
| 4 | Network connections to known C2 IPs | Sigma | `sigma/npm-go-vscode-infostealer-data-exfil.yml` | medium |
| 5 | Telegram Bot API exfiltration via proxy | Sigma | `sigma/npm-go-vscode-infostealer-telegram-exfil.yml` | medium |
| 6 | Malicious VS Code tasks.json with FakeFont pattern | YARA | `yara/npm_go_vscode_infostealer.yar` | high |
| 7 | Blockchain dead drop resolver JS code | YARA | `yara/npm_go_vscode_infostealer.yar` | high |
| 8 | InvisibleFerret Python infostealer artifacts | YARA | `yara/npm_go_vscode_infostealer.yar` | medium |

## Validation

- Sigma: `sigma check` -- skipped (D3FEND ontology network fetch error in environment; rules parse correctly)
- Sigma: `sigma convert --without-pipeline -t splunk` -- exit 0 (5 rules)
- Sigma: `sigma convert --without-pipeline -t log_scale` -- exit 0 (5 rules)
- YARA: `yarac` -- exit 0 (3 rules)

## References

- [The Hacker News -- Hijacked npm and Go Packages Use VS Code Tasks to Deploy Python Infostealer](https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html)
- [JFrog Security Research -- Hijacked npm Packages Use Novel VSCode Autorun and Blockchain Dead Drops](https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/)
- [Nextron Systems -- Go package cluster discovery](https://www.nextron-systems.com/)

---
*Generated by Actioner -- 2026-06-30*
