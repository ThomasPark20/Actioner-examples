# SoftwareOK Supply Chain Attack: Trojanized Q-Dir and DesktopOK Installers

**Date:** 2026-11-28
**Status:** DRAFT
**TLP:** CLEAR
**Source:** AhnLab ASEC, The Hacker News

---

## Executive Summary

AhnLab's ASEC division disclosed a software supply chain compromise affecting SoftwareOK, the official developer and distributor of the Q-Dir multi-pane file manager and DesktopOK desktop icon layout utility. Attackers replaced legitimate installers on the official SoftwareOK website with trojanized versions that deliver a Python-based remote access trojan (RAT). The compromise affected both direct downloads and the auto-update mechanism of already-installed software, significantly expanding the potential victim pool. The RAT establishes persistence via a scheduled task masquerading as Microsoft Edge and communicates with a C2 server at 8.210.69[.]51:9876. Chinese-language comments in the malware code suggest a Chinese-speaking development environment, though no attribution to a known threat actor has been made.

## Affected Software

| Software   | Affected Versions                  |
|-----------|-----------------------------------|
| Q-Dir     | 12.83.0.0, 12.84.0.0, 12.85.0.0 |
| DesktopOK | 12.82.0.0, 12.85.0.0             |

Both direct downloads from the official website and updates to existing installations were compromised.

## Attack Chain

1. **Initial Access (T1195.002):** Legitimate installers on the SoftwareOK website were replaced with trojanized versions. The replacement mechanism is unknown.

2. **Execution (T1204.002):** Victim downloads and runs the trojanized installer. The installer drops and launches the genuine Q-Dir or DesktopOK executable to `C:\Users\Public\` to maintain the appearance of a normal installation.

3. **Ingress Tool Transfer (T1105):** The installer downloads two payloads from `mail.c1a2[.]top/dl/`:
   - `7zr.exe` - Legitimate 7-Zip command-line extractor (used as a LOLBin)
   - `dsv2_py39_agent.7z` - Archive containing a bundled Python 3.9 runtime and the RAT agent

4. **Installation:** The 7zr.exe tool extracts the RAT package to one of:
   - Primary: `C:\ProgramData\Microsoft\DeviceSync\b2\`
   - Fallback: `C:\ProgramData\DeviceSync\b2\`

5. **Persistence (T1053.005, T1036.005):** A scheduled task named `\UPnp\MicrosoftEdge_dcntel` is created, masquerading as a Microsoft Edge component. It executes:
   ```
   "[Install Path]\py39\pythonw.exe" "[Install Path]\py39\agent\py_client_dsv2.py"
   ```

6. **Command and Control (T1571):** The RAT connects to `8.210.69[.]51` on TCP port 9876.

7. **Capabilities:**
   - Shell command execution (T1059.003)
   - Python code execution (T1059.006)
   - File upload and download (T1041)
   - Screenshot capture (T1113)
   - OS and system information collection (T1082)
   - Process enumeration against 1,206 security product names (T1057, T1518.001)
   - Reporting of detected security products to C2

## Indicators of Compromise

### Network IOCs

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `mail.c1a2[.]top` | Payload staging and download server |
| URL | `hxxps://mail.c1a2[.]top/dl/7zr.exe` | 7-Zip extractor download |
| URL | `hxxps://mail.c1a2[.]top/dl/dsv2_py39_agent.7z` | RAT package download |
| IP | `8.210.69[.]51` | C2 server |
| Port | TCP/9876 | C2 communication port |

### File Hashes (SHA-256) - Malicious Trojanized Installers

**Q-Dir 12.85.0.0:**
- `434b67dd403c74752b336fbb4fc94ee3a6fb615168e3fd31baea71d1a356ecd8`
- `8ac6901a941788ab9675a9ec9bebdbc00074cb76f19a7d84c2e1b0ddbcee4f48`

**Q-Dir 12.84.0.0:**
- `1b7b7947527a05f0fae268b16894440549c2dd512d421a06960e27b5fb1d5fa0`
- `7afa1e77c115eaa7798237039fde67c8a69686e7d9a4034a8df54aff2d1a126d`
- `cf9e2433540d0b8ae8c9f4c9d5f11770343d413c1cfb201c5edae7155f88585a`
- `d1a2cf8882c254156848f4a12b6c6837a3cf0e460f876c6f8b00d32a1560640a`

**Q-Dir 12.83.0.0:**
- `551e5744b24019f016f9ee8dd3a2c00429da587b20321abaef55c18c0a655a5d`
- `7524fcf3ffc44fc2e9a53af761c2a308edac31d02df3dfb1a4b57504243aec48`
- `c41bd9eefd7a63fa329b24144a3483abac012ebc11bd5606b6c8295251d46422`
- `b45ba4a1d9a25116b94e95ef48d63fffda7d77bd358d17d74c7575ce39986b84`

**DesktopOK 12.85.0.0:**
- `c12651f2988bb5e05afd1f4b1e6bce618111a4703f1aadc006bfacc6ac7e1d90`
- `f96cab94d9f0e0000dfef8b9fce16bcefd23679443cc8ba8f7811a55ea5799ec`

**DesktopOK 12.82.0.0:**
- `393d2f9f05affa88aaa19f29f041d28fe5c3e1fc2fd84c76d1e2f1aa6da74a83`
- `5b43284e48edee4acbab49bc5a68eb21d3a369a058d859689b6a5dd2042a5e2a`
- `8c172c421129bda890b504e89d1bb72af477be9896b22a576920c050442b4a04`
- `bdbbe28cde3dee061536e524bc2a14316015db0c958cad83023790d32a4f8d99`
- `ff4ec1cca4746e33d1205ed434e1e2ac9cee71fec477b032f56d3bde577626d2`

**MD5 (from ASEC IOC list, file unspecified):**
- `ae44745919f4ef516581ebfaa97a0b4a`

### Host Artifacts

| Type | Indicator | Context |
|------|-----------|---------|
| Scheduled Task | `\UPnp\MicrosoftEdge_dcntel` | Persistence mechanism |
| File Path | `C:\ProgramData\Microsoft\DeviceSync\b2\` | Primary RAT install directory |
| File Path | `C:\ProgramData\DeviceSync\b2\` | Fallback RAT install directory |
| File Path | `[Install]\py39\pythonw.exe` | Bundled Python interpreter |
| File Path | `[Install]\py39\agent\py_client_dsv2.py` | RAT client script |
| File Name | `7zr.exe` | Legitimate 7-Zip used for extraction |
| File Name | `dsv2_py39_agent.7z` | RAT package archive |
| File Name | `py_client_dsv2.py` | RAT main script |
| Drop Path | `C:\Users\Public\` | Legitimate app dropped here as decoy |

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Context |
|-------------|----------------|---------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized installers on official website |
| T1204.002 | User Execution: Malicious File | Victim runs trojanized installer |
| T1105 | Ingress Tool Transfer | Download of 7zr.exe and RAT archive |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Shell command execution via RAT |
| T1059.006 | Command and Scripting Interpreter: Python | Python-based RAT execution |
| T1053.005 | Scheduled Task/Job: Scheduled Task | MicrosoftEdge_dcntel persistence task |
| T1036.004 | Masquerading: Masquerade Task or Service | Task masquerades as Microsoft Edge |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Edge-impersonating scheduled task |
| T1082 | System Information Discovery | OS/system info collection |
| T1057 | Process Discovery | Enumeration of running processes |
| T1518.001 | Software Discovery: Security Software Discovery | 1,206 security product process check |
| T1113 | Screen Capture | Screenshot capability |
| T1571 | Non-Standard Port | C2 on TCP/9876 |
| T1041 | Exfiltration Over C2 Channel | File upload over C2 |

## Detection Rules

### Sigma Rules

| File | Description | Compile | Confidence |
|------|-------------|---------|------------|
| `2026-11-28-softwareok-supply-chain-schtask.yml` | Scheduled task creation matching MicrosoftEdge_dcntel or UPnp path | PASS (sigma check + splunk/spl2 convert) | HIGH |
| `2026-11-28-softwareok-supply-chain-rat-exec.yml` | Python RAT execution from DeviceSync directories | PASS (sigma check + splunk/spl2 convert) | HIGH |
| `2026-11-28-softwareok-supply-chain-installer-child.yml` | Q-Dir/DesktopOK spawning suspicious child processes | PASS (sigma check + splunk/spl2 convert) | MEDIUM |
| `2026-11-28-softwareok-supply-chain-c2-dns.yml` | DNS queries to c1a2.top C2 domain | PASS (sigma check + splunk/spl2 convert) | HIGH |

### YARA Rules

| File | Description | Compile | Confidence |
|------|-------------|---------|------------|
| `2026-11-28-softwareok-supply-chain.yar` (rule: SoftwareOK_SupplyChain_TrojanizedInstaller) | PE file detection for trojanized installers with RAT-specific strings | PASS (yarac) | HIGH |
| `2026-11-28-softwareok-supply-chain.yar` (rule: SoftwareOK_SupplyChain_PythonRAT_Agent) | Python RAT script detection with C2 and capability strings | PASS (yarac) | HIGH |
| `2026-11-28-softwareok-supply-chain.yar` (rule: SoftwareOK_SupplyChain_RAT_Archive) | 7z archive containing the py39 RAT agent package | PASS (yarac) | MEDIUM |

### Snort Rules

| File | SID | Description | Compile | Confidence |
|------|-----|-------------|---------|------------|
| `2026-11-28-softwareok-supply-chain.rules` | 2026112801 | DNS query for c1a2.top C2 domain | PASS (snort -T) | HIGH |
| `2026-11-28-softwareok-supply-chain.rules` | 2026112802 | Outbound C2 connection to 8.210.69.51:9876 | PASS (snort -T) | HIGH |
| `2026-11-28-softwareok-supply-chain.rules` | 2026112803 | RAT archive download (dsv2_py39_agent.7z) | PASS (snort -T) | HIGH |
| `2026-11-28-softwareok-supply-chain.rules` | 2026112804 | 7zr.exe download from C2 domain | PASS (snort -T) | MEDIUM |

### Suricata Rules

| File | SID | Description | Compile | Confidence |
|------|-----|-------------|---------|------------|
| `2026-11-28-softwareok-supply-chain.rules` | 2026112810 | DNS query for c1a2.top | PASS (suricata -T) | HIGH |
| `2026-11-28-softwareok-supply-chain.rules` | 2026112811 | DNS query for mail.c1a2.top | PASS (suricata -T) | HIGH |
| `2026-11-28-softwareok-supply-chain.rules` | 2026112812 | Outbound C2 to 8.210.69.51:9876 | PASS (suricata -T) | HIGH |
| `2026-11-28-softwareok-supply-chain.rules` | 2026112813 | HTTP download of dsv2_py39_agent.7z | PASS (suricata -T) | HIGH |
| `2026-11-28-softwareok-supply-chain.rules` | 2026112814 | HTTP download of 7zr.exe from c1a2.top | PASS (suricata -T) | MEDIUM |
| `2026-11-28-softwareok-supply-chain.rules` | 2026112815 | TLS SNI match for c1a2.top | PASS (suricata -T) | HIGH |

## Targeted Security Products

The RAT checks running processes against a list of 1,206 security product names and reports findings to C2. Named products include:

**Korean vendors:** AhnLab V3, ESTsecurity ALYac, INCA Internet nProtect, Hauri ViRobot, SGA Solutions VirusChaser
**International vendors:** CrowdStrike Falcon, SentinelOne, Cylance, Trend Micro, Avast, McAfee, ESET, Symantec, Kaspersky, Bitdefender, Sophos, Fortinet, Elastic Security, Cybereason, Malwarebytes, FireEye

## Hunting Guidance

1. **Scheduled Task Audit:** Search for the scheduled task `\UPnp\MicrosoftEdge_dcntel` on all endpoints. The `UPnp` task folder is not used by legitimate Microsoft software.

2. **File System Checks:**
   - Look for `C:\ProgramData\Microsoft\DeviceSync\b2\` or `C:\ProgramData\DeviceSync\b2\` directories containing a `py39\` subdirectory
   - Search for `py_client_dsv2.py` on disk
   - Check `C:\Users\Public\` for recently dropped Q-Dir or DesktopOK executables

3. **Network Indicators:**
   - Block and alert on DNS queries to `c1a2.top` and subdomains
   - Block and alert on connections to `8.210.69.51` (especially TCP/9876)

4. **Process Monitoring:**
   - Alert on `pythonw.exe` running from `ProgramData` directories
   - Alert on Q-Dir or DesktopOK installer processes spawning command shells, Python, 7-Zip, or task schedulers

5. **Hash Verification:** Compare hashes of installed Q-Dir and DesktopOK executables against known-good values from before the compromise window. Note that reinstalling the program does NOT remove the RAT.

## Analyst Notes

- The mechanism by which the official website was compromised and installers replaced has not been disclosed.
- Chinese-language comments in the malware source code provide a low-confidence indicator of a Chinese-speaking development environment. No attribution to a known threat group has been made.
- The auto-update compromise vector is particularly concerning as it reaches users who already trust the software.
- The RAT's security product enumeration (1,206 names) suggests the operators intended to tailor follow-on activity based on the victim's defensive posture.
- The use of a bundled Python runtime means victims do not need Python installed for the RAT to function.

## References

- [AhnLab ASEC Report](https://asec.ahnlab.com/en/96827/)
- [The Hacker News Coverage](https://thehackernews.com/2026/11/hackers-trojanize-official-q-dir-and.html)
- [Threadlinqs Intel Report TL-2026-6949](https://intel.threadlinqs.com/threat/TL-2026-6949)
- [Brandefense Advisory](https://brandefense.io/security-news/q-dir-desktopok-supply-chain-attack/)

---
*Report generated: 2026-11-28 | Actioner Detection Engineering | DRAFT*
