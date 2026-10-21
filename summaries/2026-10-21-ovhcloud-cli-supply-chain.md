# Technical Analysis Report: OVHcloud CLI Supply-Chain Attack (2026-10-21)

**Prepared by:** Actioner
**Date:** 2026-10-21
**Status:** FINAL
**TLP:** CLEAR

---

## Executive Summary

On October 19, 2026, attackers leveraged a hijacked GitHub contributor account (`HassenBF`, ID 4911006) to replace release binaries of the OVHcloud CLI tool (versions v0.11.0 through v0.15.0) with trojanized builds containing credential-stealing malware. The malicious binaries were available for approximately 94 minutes before OVHcloud removed them. The attack is attributed by researchers at OpenSourceMalware to the GlassWorm threat actor, based on shared infrastructure including a Solana blockchain dead-drop wallet. OVHcloud has not confirmed the GlassWorm attribution.

The compromised builds targeted macOS (Intel and ARM), Linux (x86_64 and arm64), and Windows (x86_64) platforms. Source builds, Docker images, and the Go module proxy were not affected. The malware's purpose was to steal secrets from developer workstations, including OVHcloud API credentials stored in `~/.ovh.conf` and environment variables.

---

## Timeline (UTC, October 2026)

| Date/Time | Event |
|---|---|
| 2026-03-05/06 | Attacker force-pushes amended commits with GlassWorm loaders to four `HassenBF` personal repositories |
| 2026-10-13 08:35:05 | Malicious build source commit `5ead8ef` merged to `main` (PR #296 by `FrostByte0x`) |
| 2026-10-15 | Attacker deletes branches `dev/test-changest` and `test/trigger-probe` from `ovh/ovhcloud-docs` |
| 2026-10-16 | Last legitimate release workflow run before the incident |
| 2026-10-19 12:47 | Swapped (malicious) archives go live on GitHub Releases for v0.11.0 through v0.15.0 |
| 2026-10-19 13:50 | A customer's CI job, which pins the Linux arm64 SHA-256, fails and files a public issue |
| 2026-10-19 14:21 | OVHcloud deletes the swapped files; exposure window closes (~94 minutes) |
| 2026-10-19 16:00 | v0.16.0 tag pushed |
| 2026-10-19 17:16 | v0.16.0 published as an immutable release with a signed tag under the `ovh-cds` account |

---

## Attack Details

### Access Vector

The attacker hijacked the GitHub account of a legitimate OVHcloud contributor (`HassenBF`). Evidence suggests the account was compromised since at least March 5, 2026, when four of its personal repositories were force-pushed with amended commits containing GlassWorm loaders. The compromised account had sufficient permissions to modify existing GitHub release assets via the GitHub Releases API.

### Release Tampering

GitHub's release immutability feature was not enabled for the `ovh/ovhcloud-cli` repository, allowing anyone with write access to delete and re-upload release assets under the same filenames without triggering CI/CD pipelines. The attacker replaced the following files on releases v0.11.0 through v0.15.0:

- `ovhcloud-cli_Darwin_arm64.tar.gz`
- `ovhcloud-cli_Darwin_x86_64.tar.gz`
- `ovhcloud-cli_Linux_arm64.tar.gz`
- `ovhcloud-cli_Linux_x86_64.tar.gz`
- `ovhcloud-cli_Windows_x86_64.zip`
- `checksums.txt` (replaced to match the malicious archives)

**Not replaced:** Linux i386, Windows i386, Windows arm64, and WebAssembly builds.

**Not affected:** Homebrew (cask pinned original hashes), `go install` / source builds (v0.15.0 tag still points to commit `760fd72`), and the Docker image.

### Malicious Build Characteristics

The trojanized binary was built locally (not through CI/CD) and exhibits these distinguishing metadata:

- **Module version:** `v0.15.1-0.20261013083505-5ead8ef9b43d+dirty`
- **VCS revision:** `5ead8ef9b43d354dfb5caadff803b11afc8c5c58` (not the legitimate `760fd72`)
- **VCS modified:** `true`
- **Build flags:** `-ldflags="-s -w"` (strips symbols and debug info); legitimate GoReleaser builds use `-trimpath` and set `version.Version`
- **Missing:** The `-X github.com/ovh/ovhcloud-cli/internal/version.Version={{.Tag}}` ldflag present in legitimate builds

### GlassWorm Connection

The loader found in the compromised contributor's repositories (`preinstall.js`, SHA-256: `43df42fd79f6f81e530892b54634598770d6e496796a863c596e616bcb3fec70`) uses techniques consistent with GlassWorm campaigns:

1. **Unicode obfuscation:** Payload encoded using invisible variation-selector characters (U+FE00 to U+FE0F and U+E0100 to U+E01EF)
2. **AES-256-CBC decryption:** Hardcoded key `zetqHyfDfod88zloncfnOaS9gGs90ONX`, IV `a041fdaa0521fb5c3e26b217aaf24115`
3. **Solana dead-drop:** Queries the memo field of Solana wallet transactions for C2 payload URLs
4. **Russian locale skip:** Exits if the host shows Russian language plus a Russian timezone or UTC offset +2 to +12
5. **macOS throttle:** Writes `~/init.json` and re-runs at most every two days

The Solana wallet `BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC` is a known GlassWorm indicator appearing in multiple public tracking repositories. Researchers note that linking the same actor to both the March personal-repo tampering and the October CLI compromise is inference; the October binary itself was not preserved for independent analysis.

---

## Indicators of Compromise (IOCs)

### File Hashes (SHA-256)

| Hash | Description |
|---|---|
| `3833daffcaaaab27e4e0e0833240ffcb1df8df648f4ec0bc4a75c176e28933cb` | Malicious v0.15.0 `ovhcloud-cli_Linux_arm64.tar.gz` |
| `5c2beb56e6d83a4b426565a1557791ef759316abcc4effb38dd627c90aeb80e0` | Legitimate v0.15.0 `ovhcloud-cli_Linux_arm64.tar.gz` |
| `43df42fd79f6f81e530892b54634598770d6e496796a863c596e616bcb3fec70` | GlassWorm `preinstall.js` loader |
| `0f79989912572a24ba13baabb32b3fd084496271c51448d47b66fe1aedbf293c` | Decrypted GlassWorm stage-two payload |
| `2ba01d4141fce7342a7f0cc330e6c08da83cfe5d4bfd1a79b69f20d2b1f4f7e5` | GlassWorm Wave 3 `f_ex86.node` native addon |
| `fdba5be3da2467e642bd8710f971e6b266b30ac15f5f413982fd719d7e0bffd9` | GlassWorm Wave 3 multi-component native addon |
| `4e339dcdc3e3a8bf5271f7f76a9c4f064d3e34cbb51f8770ff4cce910fbcbce5` | GlassWorm Wave 3 native addon |
| `1ed7ca5301e96e3cef201311b76ba33f842fdb34e91041177865b6e07acb7b4d` | GlassWorm Wave 3 native addon |
| `43253a888417dfab034f781527e08fb58e929096cb4ef69456c3e13550cb4e9e` | GlassWorm native addon |
| `de81eacd045a88598f16680ce01bf99837b1d8170c7fc38a18747ef10e930776` | GlassWorm native addon |
| `9c7f93b925c86b911f4488c10709407b2c1f0695ec120cb998a9fd34d22c503a` | GlassWorm encrypted npm archive |

### Network Indicators

| Indicator | Description |
|---|---|
| `45[.]32[.]150[.]251` | GlassWorm C2 / Stage 2 payload delivery server |
| `45[.]32[.]151[.]157` | GlassWorm C2 payload server |
| `70[.]34[.]242[.]255` | GlassWorm C2 payload server |
| `208[.]85[.]20[.]124` | GlassWorm exfiltration server (POST /wall, port 80) |
| `217[.]69[.]3[.]152` | GlassWorm exfiltration server (/wall, /log endpoints) |
| `217[.]69[.]0[.]159` | GlassWorm DHT bootstrap node (port 10000) |
| `217[.]69[.]11[.]57` | GlassWorm DHT node (port 5000/10000) |
| `217[.]69[.]11[.]99` | GlassWorm DHT node (port 5000/10000) |
| `45[.]32[.]150[.]97` | GlassWorm auxiliary infrastructure |
| `45[.]150[.]34[.]158` | GlassWorm Ledger phishing recovery-phrase server |
| `45[.]32[.]150[.]251/get_arhive_npm/` | Stage 2 archive download path |
| `45[.]32[.]150[.]251/led-win32` | Ledger-targeting executable download |
| `208[.]85[.]20[.]124:80/wall` | Exfiltration endpoint (POST) |

### Blockchain Indicators

| Indicator | Description |
|---|---|
| `BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC` | Primary GlassWorm Solana C2 wallet (Stage 2 memo lookup) |
| `6YGcuyFRJKZtcaYCCFba9fScNUvPkGXodXE1mJiSzqDJ` | GlassWorm Stage 0 Solana memo lookup wallet |
| `DSRUBTziADDHSik7WQvSMjvwCHFsbsThrbbjWMoJPUiW` | GlassWorm Chrome extension C2 wallet |
| `G2YxRa6wt1qePMwfJzdXZG62ej4qaTC7YURzuh2Lwd3t` | GlassWorm funding/seed wallet |

### Build Metadata Indicators

| Indicator | Description |
|---|---|
| Module version `v0.15.1-0.20261013083505-5ead8ef9b43d+dirty` | Pseudo-version of malicious build |
| Commit `5ead8ef9b43d354dfb5caadff803b11afc8c5c58` | Malicious build source commit |
| Commit `760fd72` | Legitimate v0.15.0 tag commit |

### Host Artifacts

| Path/Artifact | Platform | Description |
|---|---|---|
| `~/init.json` | macOS | Throttle marker (re-run interval of two days) |
| `%APPDATA%\ozTjbCl\index.js` | Windows | Stage 1 staging script |
| `%TEMP%\TvVdSR.exe` | Windows | Ledger-targeting dropped executable |
| `%TEMP%\WlpSxEJPU\` | Windows | Staging directory |
| `%TEMP%\AGeZdIX\` | Windows | Stage 2 collection directory |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateLedger` | Windows | Persistence Run key |
| `~/.ovh.conf` | Linux/macOS | OVHcloud API credentials file (target) |
| `preinstall.js` | All | GlassWorm loader in package root |
| `src/index.js` (36,936 bytes) | All | Inline loader variant in compromised repos |

### Compromised GitHub Account

| Detail | Value |
|---|---|
| Username | `HassenBF` |
| GitHub ID | `4911006` |
| Compromise evidence | Force-pushed repositories on 2026-03-05/06 |
| Force-pushed repositories | `HassenBF/treasure-hunt-game`, `HassenBF/crwn-clothing`, `HassenBF/next-dashboard`, `HassenBF/padel-bot` |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Attacker replaced legitimate release binaries with trojanized builds |
| Valid Accounts | T1078 | Hijacked GitHub contributor account used for release tampering |
| Command and Scripting Interpreter: JavaScript | T1059.007 | preinstall.js loader executes JavaScript payloads |
| Obfuscated Files or Information: Encrypted/Encoded File | T1027.013 | Unicode variation-selector character obfuscation and AES-256-CBC encryption |
| Web Service: Bidirectional Communication | T1102.002 | Solana blockchain memo used as dead-drop for C2 URL retrieval |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTPS communication to C2/exfiltration servers |
| Exfiltration Over C2 Channel | T1041 | Stolen credentials exfiltrated to attacker-controlled servers |
| Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | UpdateLedger Run key for persistence |
| Data Staged: Local Data Staging | T1074.001 | Credentials staged in temporary directories before exfiltration |
| Credentials from Password Stores | T1555 | Targeting of browser credentials, crypto wallets, API keys |

---

## Detection Rules

This report ships 23 detection rules across four formats: 5 Sigma, 4 YARA, 7 Snort, and 7 Suricata.

### Sigma Rules

#### 1. OVHcloud CLI Malicious Build Metadata Detection
- **File:** `sigma_ovhcloud_cli_malicious_build_metadata.yml`
- **Confidence:** HIGH

Detects execution of the backdoored OVHcloud CLI binary by matching the malicious build commit hash `5ead8ef` or dirty module version string in process creation events.

#### 2. GlassWorm Solana RPC Dead Drop Connection
- **File:** `sigma_glassworm_solana_rpc_connection.yml`
- **Confidence:** MEDIUM

Detects outbound proxy connections to Solana RPC endpoints, which GlassWorm uses for memo-based C2 resolution. **Caveat:** This rule operates at the proxy URL level and cannot match the specific GlassWorm wallet address (`BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC`) in the HTTP request body; it is therefore a heuristic that will flag any non-excluded Solana RPC traffic. For body-level wallet address matching, deploy the companion Snort (sid:2100006) or Suricata (sid:2200003) rules instead.

#### 3. GlassWorm C2 and Exfiltration Server Communication
- **File:** `sigma_glassworm_c2_network_indicators.yml`
- **Confidence:** HIGH

Matches firewall log entries for outbound connections to 10 known GlassWorm C2 and exfiltration IP addresses. **Caveat:** Several of these IPs are hosted on Vultr shared infrastructure and may be reassigned to legitimate services over time. This indicator set should be revalidated within 90 days of publication.

#### 4. GlassWorm Credential Staging and Persistence Artifacts
- **File:** `sigma_glassworm_credential_staging.yml`
- **Confidence:** HIGH

Detects file creation in GlassWorm-specific staging directories (`ozTjbCl`, `WlpSxEJPU`, `AGeZdIX`) and the `TvVdSR.exe` drop path.

#### 5. GlassWorm Registry Run Key Persistence
- **File:** `sigma_glassworm_persistence_registry.yml`
- **Confidence:** HIGH

Detects creation of the `UpdateLedger` registry Run key entry combined with the `TvVdSR.exe` executable path, or the `TvVdSR.exe` path alone. The `UpdateLedger` value name on its own is not sufficient to fire this rule, as it may overlap with legitimate Ledger Live auto-updater entries.

### YARA Rules

#### 6. OVHcloud_CLI_Malicious_Build
- **File:** `yara_ovhcloud_glassworm.yar` (rule 1 of 4)
- **Confidence:** HIGH

Matches Go binaries containing the malicious commit hash `5ead8ef9b43d354dfb5caadff803b11afc8c5c58` combined with OVHcloud module path, or the dirty pseudo-version string.

#### 7. GlassWorm_Preinstall_Loader
- **File:** `yara_ovhcloud_glassworm.yar` (rule 2 of 4)
- **Confidence:** HIGH

Matches the GlassWorm preinstall.js loader by its hardcoded AES key/IV, Solana wallet addresses, or the combination of crypto operations with Unicode obfuscation patterns.

#### 8. GlassWorm_Stage2_Payload
- **File:** `yara_ovhcloud_glassworm.yar` (rule 3 of 4)
- **Confidence:** MEDIUM

Matches the decrypted stage-two payload through its Solana RPC endpoints, wallet address, and `ivbase64`/`secretkey` HTTP header references. **Caveat:** This rule detects GlassWorm broadly across campaigns, not specifically the October 2026 OVHcloud CLI variant.

#### 9. GlassWorm_Native_Addon
- **File:** `yara_ovhcloud_glassworm.yar` (rule 4 of 4)
- **Confidence:** MEDIUM

Matches GlassWorm native addon binaries (`.node` files) by embedded C2/exfiltration IP addresses and staging directory names. **Caveat:** This rule detects GlassWorm broadly across campaigns, not specifically the October 2026 OVHcloud CLI variant.

### Snort Rules

#### 10. GlassWorm C2 - Stage 2 Payload Delivery Server (sid:2100001)
- **File:** `snort_glassworm_c2.rules`
- **Confidence:** HIGH

IP-based rule matching outbound connections to the Stage 2 payload delivery server at `45.32.150.251`.

#### 11. GlassWorm Exfiltration - POST to /wall Endpoint (sid:2100002)
- **File:** `snort_glassworm_c2.rules`
- **Confidence:** HIGH

Matches HTTP POST requests to the `/wall` exfiltration endpoint, constrained to destination IP `208.85.20.124` on port 80.

#### 12. GlassWorm Exfiltration Server Communication (sid:2100003)
- **File:** `snort_glassworm_c2.rules`
- **Confidence:** HIGH

IP-based rule matching outbound connections to the secondary exfiltration server at `217.69.3.152`.

#### 13. GlassWorm DHT Bootstrap Node Communication (sid:2100004)
- **File:** `snort_glassworm_c2.rules`
- **Confidence:** HIGH

IP-based rule matching outbound connections to the DHT bootstrap node at `217.69.0.159` on port 10000.

#### 14. GlassWorm Ledger Phishing Recovery Phrase Server (sid:2100005)
- **File:** `snort_glassworm_c2.rules`
- **Confidence:** HIGH

IP-based rule matching outbound connections to the Ledger phishing server at `45.150.34.158`.

#### 15. GlassWorm Solana Memo Dead Drop Query (sid:2100006)
- **File:** `snort_glassworm_c2.rules`
- **Confidence:** HIGH

Content-matching rule detecting Solana RPC `getSignaturesForAddress` calls that include the specific GlassWorm wallet address `BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC` in the HTTP request body, constrained to the `api.mainnet-beta.solana.com` host header.

#### 16. GlassWorm Stage 2 Archive Download Path (sid:2100007)
- **File:** `snort_glassworm_c2.rules`
- **Confidence:** MEDIUM

Content-matching rule detecting HTTP requests to the `/get_arhive_npm/` URI path used for Stage 2 archive downloads. Medium confidence because the path could theoretically appear on other servers, though it is an uncommon misspelling.

### Suricata Rules

#### 17. GlassWorm Exfiltration POST to /wall Endpoint (sid:2200001)
- **File:** `suricata_glassworm_c2.rules`
- **Confidence:** HIGH

Matches HTTP POST requests to the `/wall` exfiltration endpoint, constrained to `208.85.20.124` via the `http.host` sticky buffer.

#### 18. GlassWorm Stage 2 Archive Download (sid:2200002)
- **File:** `suricata_glassworm_c2.rules`
- **Confidence:** MEDIUM

Content-matching rule detecting HTTP requests to the `/get_arhive_npm/` URI path. Medium confidence because the path alone is the only discriminator.

#### 19. GlassWorm Solana Memo Dead Drop Query (sid:2200003)
- **File:** `suricata_glassworm_c2.rules`
- **Confidence:** HIGH

Matches Solana RPC `getSignaturesForAddress` calls containing the GlassWorm wallet address `BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC` in the HTTP request body via the `http.request_body` sticky buffer.

#### 20. GlassWorm C2 Payload Delivery Server Connection (sid:2200004)
- **File:** `suricata_glassworm_c2.rules`
- **Confidence:** HIGH

IP-based rule matching outbound connections to GlassWorm C2 payload servers at `45.32.150.251`, `45.32.151.157`, and `70.34.242.255`.

#### 21. GlassWorm Exfiltration Server Communication (sid:2200005)
- **File:** `suricata_glassworm_c2.rules`
- **Confidence:** HIGH

IP-based rule matching outbound connections to exfiltration servers at `208.85.20.124` and `217.69.3.152`.

#### 22. GlassWorm DHT Bootstrap Node Connection (sid:2200006)
- **File:** `suricata_glassworm_c2.rules`
- **Confidence:** HIGH

IP-based rule matching outbound connections to DHT nodes at `217.69.0.159`, `217.69.11.57`, and `217.69.11.99` on port 10000.

#### 23. GlassWorm Ledger Phishing Recovery Phrase Server (sid:2200007)
- **File:** `suricata_glassworm_c2.rules`
- **Confidence:** HIGH

IP-based rule matching outbound connections to the Ledger phishing recovery-phrase server at `45.150.34.158`.

---

## Affected Versions and Remediation

### Affected Versions

| Version | Release Date | Status |
|---|---|---|
| v0.10.0 | Pre-April 2026 | **CLEAN** |
| v0.11.0 | April 14, 2026 | **COMPROMISED** (binaries replaced Oct 19) |
| v0.12.0 | - | **COMPROMISED** (binaries replaced Oct 19) |
| v0.13.0 | - | **COMPROMISED** (binaries replaced Oct 19) |
| v0.14.0 | - | **COMPROMISED** (binaries replaced Oct 19) |
| v0.15.0 | September 16, 2026 | **COMPROMISED** (binaries replaced Oct 19) |
| v0.16.0 | October 19, 2026 | **CLEAN** (immutable release, signed tag) |

### Recommended Actions

1. **Immediate:** Upgrade to v0.16.0 or remove the OVHcloud CLI if running v0.11.0 through v0.15.0
2. **Credential rotation:** Rotate ALL secrets stored on any machine that ran an affected binary, including OVHcloud API credentials (`~/.ovh.conf`), environment variables, SSH keys, and cloud provider tokens
3. **Forensic investigation:** Check download timestamps, CI/CD logs, cached archives, and workstation installation records for the exposure window (12:47-14:21 UTC, October 19)
4. **Container audit:** Review container builds that fetched GitHub release archives during the exposure window
5. **Hash verification:** Compare installed binary hash against known-good v0.16.0 checksums from a separate source (not the release page `checksums.txt`, which was also replaced)
6. **Build metadata check:** Run `go version -m <binary>` (does not execute the binary) and flag output containing `vcs.modified=true`, `+dirty`, or commit `5ead8ef`
7. **Enable release immutability:** For repository maintainers, enable GitHub's release immutability feature (GA since October 2025)

---

## Intelligence Gaps

1. **No preserved malicious binary:** OVHcloud deleted the trojanized archives before researchers could obtain samples for full analysis. The second-stage behavior, exfiltration destination, and complete list of targeted credential files remain unknown for the October variant.
2. **Hashes for v0.11.0 through v0.14.0:** Only the v0.15.0 Linux arm64 malicious hash has been published. Hashes for other affected versions and platforms are unavailable.
3. **Account compromise method:** How the `HassenBF` GitHub account credentials were initially obtained is unknown.
4. **Download count:** OVHcloud has not disclosed how many copies of the malicious binaries were downloaded during the 94-minute window.
5. **Attribution certainty:** The GlassWorm attribution is researcher inference based on shared Solana wallet infrastructure. No analysis of the October binary payload has confirmed GlassWorm code reuse.

---

## References

- [OpenSourceMalware - Glassworm Hacks OVH Cloud's CLI Tool](https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool)
- [BleepingComputer - OVHcloud CLI Releases Backdoored on GitHub to Steal Developer Secrets](https://www.bleepingcomputer.com/news/security/ovhcloud-cli-releases-backdoored-on-github-to-steal-developer-secrets/)
- [The Hacker News - Hackers Hijack Five OVHcloud CLI Releases](https://thehackernews.com/2026/10/hackers-hijack-five-ovhcloud-cli.html)
- [SecurityWeek - Hijacked Developer Account Used to Plant Stealer in OVHcloud CLI](https://www.securityweek.com/hijacked-developer-account-used-to-plant-stealer-in-ovhcloud-cli/)
- [Help Net Security - Info-Stealing Malware Slipped into OVHcloud CLI Releases on GitHub](https://www.helpnetsecurity.com/2026/10/21/ovhcloud-cli-github-malware/)
- [GridinSoft - OVHcloud CLI Compromise: Old Releases, Replaced Files](https://blog.gridinsoft.com/ovhcloud-cli-release-files-replaced/)
- [Checkmarx Zero - GlassWorm Targets Developer IDEs Again](https://checkmarx.com/zero-post/glassworm-targets-developer-ides-again-hiding-staged-malware-behind-runtime-rebuilt-loaders/)
- [The Hacker News - GlassWorm Malware Uses Solana Dead Drops](https://thehackernews.com/2026/03/glassworm-malware-uses-solana-dead.html)
- [The Hacker News - GlassWorm Attack Uses Stolen GitHub Tokens](https://thehackernews.com/2026/03/glassworm-attack-uses-stolen-github.html)
- [SOC Prime - GlassWorm Supply-Chain Malware and Chrome RAT Threat](https://socprime.com/active-threats/glassworm-hides-a-rat-inside-a-malicious-chrome-extension/)

---

*Report generated: 2026-10-21 | Actioner Final v1.1*
