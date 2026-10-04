# CloudSyncD macOS Backdoor — Fake Zoom Installer

**Date:** 2026-10-04
**Status:** DRAFT
**TLP:** CLEAR
**Last Updated:** 2026-10-04

---

## Executive Summary

CloudSyncD is a two-stage macOS backdoor delivered through a trojanized Zoom installer, discovered by Jamf Threat Labs in mid-September 2026. The dropper (`app_installer`) phishes the user's local account password via a fake Zoom authentication dialog, validates it against the local directory using `dscl`, and conceals it in a JSON configuration file using zero-width Unicode characters. It then extracts and executes a universal Mach-O second-stage payload (`cloudsyncd`, ~756 KB) that establishes C2 communication disguised as jQuery JavaScript requests. The backdoor is capable of receiving and executing arbitrary Mach-O binaries or gzipped tar archives from its C2 infrastructure.

## Source Assessment

| # | Source | Type | Accessed |
|---|--------|------|----------|
| 1 | [Jamf Threat Labs - CloudSyncD Research](https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/) | Primary Research | 2026-10-04 |
| 2 | [Hackread - CloudSyncD macOS Backdoor](https://hackread.com/cloudsyncd-macos-backdoor-fake-zoom-installer-passwords/) | Secondary Reporting | 2026-10-04 |
| 3 | [SecurityWeek - macOS Users Targeted by Fake Zoom Installer](https://www.securityweek.com/macos-users-targeted-by-fake-zoom-installer-carrying-cloudsyncd-backdoor/) | Secondary Reporting | 2026-10-04 |
| 4 | [Security Affairs - Fake Zoom Installer Hides macOS Backdoor](https://securityaffairs.com/200293/malware/fake-zoom-installer-hides-macos-backdoor-cloudsyncd.html) | Secondary Reporting | 2026-10-04 |
| 5 | [Infosecurity Magazine - CloudSyncD macOS Backdoor](https://www.infosecurity-magazine.com/news/cloudsyncd-macos-backdoor-fake/) | Secondary Reporting | 2026-10-04 |

## Technical Analysis

### Kill Chain

1. **Delivery:** Victim is lured to download a trojanized Zoom DMG disk image. The mounted volume is named "Zoom."
2. **Gatekeeper Bypass:** The app is ad-hoc signed. A custom background image in the DMG guides the user step-by-step through manually overriding Gatekeeper via System Settings.
3. **Credential Phishing:** The dropper (`app_installer`) presents a fake Zoom authentication dialog capturing the user's macOS local account password.
4. **Credential Validation:** The password is validated against the local directory service using `dscl`.
5. **Credential Storage:** The password is stored in `~/.config/zoom/data.json` using a novel zero-width Unicode obfuscation technique: 48 invisible characters (U+200B ZERO WIDTH SPACE and U+200C ZERO WIDTH NON-JOINER) encode the offset and length of a base64-encoded password padded with 32-64 random filler characters.
6. **Fileless Execution Attempt:** The dropper attempts to execute the second-stage payload through `/dev/fd/` (anonymous file descriptor) to avoid writing to disk. This is typically blocked by System Integrity Protection (returns rc=13).
7. **Fallback Execution:** On SIP-blocked systems, the dropper uses `mkstemp` to write the payload temporarily to disk, then executes it via `sudo` using the harvested password. A temporary shell script `.app_swap_<pid>.sh` facilitates this.
8. **Second Stage (CloudSyncD):** A ~756 KB universal Mach-O binary (ARM slice: `main-arm64.out`, Intel slice: `cshelper`) establishes C2 communication.
9. **C2 Communication:** Beacons disguised as jQuery JavaScript fetch requests sent every 8-16 seconds. Initial survey includes hardware UUID, CPU details, memory, OS version, machine name, username, MAC address, hardware model, and raw `ioreg` output. Tasks delivered as JSON with base64-encoded, encrypted payloads (ChaCha20-Poly1305 encryption). The C2 can deliver gzipped tar archives or complete Mach-O executables.

### Persistence

Jamf Threat Labs noted that while LaunchAgent persistence capability appears to be built into the implant, it was **not observed** during analysis. No persistence mechanism was triggered because no C2 task was delivered during the analysis window.

## Indicators of Compromise

> **Note:** No file hashes (SHA256/MD5) or specific C2 domain names were published in the primary research or any secondary reporting at time of analysis. IOCs below are file paths, process names, and behavioral indicators.

### File System Artifacts

| Indicator | Type | Context |
|-----------|------|---------|
| `Zoom.app/Contents/MacOS/app_installer` | File Path | First-stage dropper binary |
| `~/.config/zoom/data.json` | File Path | Credential storage file with zero-width Unicode encoding |
| `~/.local/share/cloudsync/.config/logs/` | Directory | CloudSyncD working directory |
| `sync.err` | File Name | CloudSyncD log file (within working directory) |
| `.app_swap_<pid>.sh` | File Name | Temporary privilege escalation script (system temp directory) |

### Process / Binary Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `app_installer` | Process Name | First-stage dropper |
| `cloudsyncd` | Process Name | Second-stage backdoor |
| `main-arm64.out` | Binary Name | ARM64 slice of second-stage payload |
| `cshelper` | Binary Name | Intel x86_64 slice of second-stage payload |

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| jQuery-mimicking URI paths | Behavioral | C2 beacons masquerade as jQuery `.js` fetch requests |
| Two C2 domains registered 2011, same registrar, behind Cloudflare | Infrastructure | Specific domains not published |
| 8-16 second beacon interval | Behavioral | C2 check-in frequency |
| ChaCha20-Poly1305 encrypted payloads | Behavioral | Task encryption with identical keys/IVs across builds |

### Behavioral Indicators

| Indicator | Description |
|-----------|-------------|
| Zero-width Unicode in JSON files | U+200B and U+200C characters (48 total) encoding credential offset/length in `data.json` version field after "1.0.0" |
| `dscl` invocation from non-system parent | Credential validation against local directory service |
| `/dev/fd/` execution from unsigned binary | Fileless execution attempt |
| `sudo` with programmatically supplied password | Privilege escalation using phished credentials |
| ~756 KB Universal Mach-O | Ad-hoc signed, supports ARM64 + x86_64 |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Context |
|--------|-----------|-----|---------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Fake Zoom download site |
| Execution | User Execution: Malicious File | T1204.002 | User mounts DMG and runs installer |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | `.app_swap_<pid>.sh` temp script |
| Defense Evasion | Subvert Trust Controls: Code Signing | T1553.002 | Ad-hoc signed binary; user guided to bypass Gatekeeper |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | `cloudsyncd` mimics system daemon; Zoom branding |
| Defense Evasion | Obfuscated Files or Information: Encrypted/Encoded File | T1027.013 | ChaCha20-Poly1305 encrypted logs and C2 traffic |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | Zero-width Unicode credential encoding |
| Credential Access | Input Capture: GUI Input Capture | T1056.002 | Fake Zoom password dialog |
| Privilege Escalation | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | T1548.003 | `sudo` execution with harvested password |
| Discovery | System Information Discovery | T1082 | Hardware UUID, CPU, memory, OS, model enumeration |
| Discovery | System Owner/User Discovery | T1033 | Username collection in C2 survey |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | jQuery-mimicking HTTP beacons |
| Command and Control | Ingress Tool Transfer | T1105 | C2 delivers Mach-O binaries or tar archives |
| Persistence | Boot or Logon Autostart Execution: Launch Agent | T1547.011 | Capability present but not observed |

## Detection Rules

### Sigma Rules

#### 1. CloudSyncD Fake Zoom Installer Spawning Suspicious Child Processes

Detects the CloudSyncD dropper masquerading as a Zoom installer spawning credential validation or second-stage processes.

<!-- audit: sigma check pass (0 errors, 0 issues, -x attacktag due to network restriction), sigma convert splunk exit 0, sigma convert log_scale exit 0 -->

```yaml
title: CloudSyncD Fake Zoom Installer Spawning Suspicious Child Processes
id: 9a2c7e41-3b8f-4d5e-a1c6-8e7f2d9b0a34
status: experimental
description: Detects the CloudSyncD dropper masquerading as a Zoom installer spawning suspicious child processes including credential validation via dscl or privilege escalation via sudo.
references:
    - https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/
    - https://hackread.com/cloudsyncd-macos-backdoor-fake-zoom-installer-passwords/
author: Actioner CTI
date: 2026-10-04
tags:
    - attack.execution
    - attack.t1204.002
    - attack.credential_access
    - attack.t1056.002
logsource:
    category: process_creation
    product: macos
detection:
    selection_parent:
        ParentImage|endswith: '/app_installer'
        ParentCommandLine|contains: 'Zoom'
    selection_child:
        Image|endswith:
            - '/dscl'
            - '/sudo'
            - '/cloudsyncd'
            - '/cshelper'
            - '/main-arm64.out'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Zoom installers that may invoke system utilities (unlikely to match this specific parent-child pattern)
level: high
```

#### 2. CloudSyncD Backdoor File Artifacts

Detects creation of files associated with the CloudSyncD macOS backdoor including the working directory structure and credential storage file.

<!-- audit: sigma check pass (0 errors, 0 issues, -x attacktag), sigma convert splunk exit 0, sigma convert log_scale exit 0 -->

```yaml
title: CloudSyncD Backdoor Binary File Creation
id: 5d3f8a12-7c4b-49e1-b6d2-3e8a1f5c7d90
status: experimental
description: Detects creation of files associated with the CloudSyncD macOS backdoor including the working directory structure and credential storage file.
references:
    - https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/
    - https://securityaffairs.com/200293/malware/fake-zoom-installer-hides-macos-backdoor-cloudsyncd.html
author: Actioner CTI
date: 2026-10-04
tags:
    - attack.persistence
    - attack.t1036.005
    - attack.defense_evasion
logsource:
    category: file_event
    product: macos
detection:
    selection_workdir:
        TargetFilename|contains: '/.local/share/cloudsync/.config/logs/'
    selection_credential_file:
        TargetFilename|endswith: '/.config/zoom/data.json'
    selection_temp_script:
        TargetFilename|contains: '.app_swap_'
        TargetFilename|endswith: '.sh'
    condition: selection_workdir or selection_credential_file or selection_temp_script
falsepositives:
    - Legitimate Zoom configuration files (unlikely to use .config/zoom/data.json path)
level: medium
```

#### 3. Suspicious dscl Credential Validation

Detects the use of `dscl` to validate credentials by a non-standard parent process, as used by CloudSyncD.

<!-- audit: sigma check pass (0 errors, 0 issues, -x attacktag), sigma convert splunk exit 0, sigma convert log_scale exit 0 -->

```yaml
title: Suspicious dscl Credential Validation by Non-Standard Process
id: 7b1e4c89-2d6f-4a3e-95c8-1f2d7e8b6a43
status: experimental
description: Detects the use of dscl to validate user credentials by a non-standard parent process, as used by CloudSyncD to verify phished passwords against local accounts.
references:
    - https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/
    - https://hackread.com/cloudsyncd-macos-backdoor-fake-zoom-installer-passwords/
author: Actioner CTI
date: 2026-10-04
tags:
    - attack.credential_access
    - attack.t1056.002
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/dscl'
        CommandLine|contains:
            - 'authorizationhost'
            - '-authonly'
            - 'passwd'
    filter_main:
        ParentImage|endswith:
            - '/SecurityAgent'
            - '/authorizationhost'
            - '/System Preferences'
            - '/systemsetup'
    condition: selection and not filter_main
falsepositives:
    - System administration scripts validating credentials
    - MDM enrollment or management tools
level: medium
```

#### 4. Suspicious Fileless Execution via /dev/fd

Detects attempts to execute binaries through anonymous file descriptors, a technique used by CloudSyncD before falling back to disk-based execution.

<!-- audit: sigma check pass (0 errors, 0 issues, -x attacktag), sigma convert splunk exit 0, sigma convert log_scale exit 0 -->

```yaml
title: Suspicious Fileless Execution via /dev/fd on macOS
id: 2e5a9f37-8c1d-4b6e-a7d3-9f4c2e1b8d56
status: experimental
description: Detects attempts to execute binaries through anonymous file descriptors via /dev/fd, a technique used by CloudSyncD to achieve fileless execution before falling back to disk-based methods.
references:
    - https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/
    - https://securityaffairs.com/200293/malware/fake-zoom-installer-hides-macos-backdoor-cloudsyncd.html
author: Actioner CTI
date: 2026-10-04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        CommandLine|contains: '/dev/fd/'
    filter_legitimate:
        ParentImage|endswith:
            - '/bash'
            - '/zsh'
            - '/sh'
    condition: selection and not filter_legitimate
falsepositives:
    - Development tools or shell scripts using file descriptor redirection
level: medium
```

### YARA Rules

#### 5. CloudSyncD Backdoor Binary

Detects the CloudSyncD second-stage backdoor based on Mach-O magic bytes and embedded strings associated with C2 survey and communication.

<!-- audit: yarac exit 0, compiles cleanly against /dev/null -->

```yara
rule CloudSyncD_Backdoor_Binary
{
    meta:
        description = "Detects the CloudSyncD second-stage macOS backdoor binary based on embedded strings and characteristics"
        author = "Actioner CTI"
        date = "2026-10-04"
        reference = "https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/"
        reference2 = "https://hackread.com/cloudsyncd-macos-backdoor-fake-zoom-installer-passwords/"

    strings:
        $macho_magic1 = { CA FE BA BE }
        $macho_magic2 = { CF FA ED FE }
        $macho_magic3 = { FE ED FA CF }

        $s1 = "cloudsyncd" ascii
        $s2 = "sync.err" ascii
        $s3 = "cloudsync/.config/logs" ascii
        $s4 = "hw_model" ascii
        $s5 = "cpu_cores" ascii
        $s6 = "machine_name" ascii
        $s7 = "hwid" ascii

        $c2_1 = "jQuery" ascii
        $c2_2 = "task" ascii

        $crypto = "ChaCha20" ascii

    condition:
        ($macho_magic1 at 0 or $macho_magic2 at 0 or $macho_magic3 at 0) and
        3 of ($s*) and
        1 of ($c2*) and
        $crypto
}
```

#### 6. CloudSyncD Dropper Binary

Detects the first-stage dropper based on Mach-O format, embedded file paths, credential storage references, and zero-width Unicode byte sequences.

<!-- audit: yarac exit 0, compiles cleanly against /dev/null -->

```yara
rule CloudSyncD_Dropper
{
    meta:
        description = "Detects the CloudSyncD first-stage dropper disguised as a Zoom installer"
        author = "Actioner CTI"
        date = "2026-10-04"
        reference = "https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/"
        reference2 = "https://securityaffairs.com/200293/malware/fake-zoom-installer-hides-macos-backdoor-cloudsyncd.html"

    strings:
        $macho_magic1 = { CA FE BA BE }
        $macho_magic2 = { CF FA ED FE }
        $macho_magic3 = { FE ED FA CF }

        $s1 = "app_installer" ascii
        $s2 = "data.json" ascii
        $s3 = ".config/zoom" ascii
        $s4 = "/dev/fd/" ascii
        $s5 = "mkstemp" ascii
        $s6 = "dscl" ascii

        $unicode1 = { E2 80 8B }
        $unicode2 = { E2 80 8C }

        $swap = ".app_swap_" ascii

    condition:
        ($macho_magic1 at 0 or $macho_magic2 at 0 or $macho_magic3 at 0) and
        3 of ($s*) and
        all of ($unicode*) and
        $swap
}
```

#### 7. CloudSyncD Zero-Width Unicode Credential File

Detects the `data.json` credential exfiltration file based on JSON structure containing dense zero-width Unicode characters.

<!-- audit: yarac exit 0, compiles cleanly against /dev/null -->

```yara
rule CloudSyncD_ZeroWidth_Unicode_Credential_File
{
    meta:
        description = "Detects the CloudSyncD data.json credential file containing zero-width Unicode character encoding"
        author = "Actioner CTI"
        date = "2026-10-04"
        reference = "https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/"

    strings:
        $json_ver = "\"version\"" ascii
        $json_ver2 = "1.0.0" ascii

        $zwsp = { E2 80 8B }
        $zwnj = { E2 80 8C }

    condition:
        filesize < 10KB and
        $json_ver and $json_ver2 and
        #zwsp > 10 and
        #zwnj > 10
}
```

### Suricata Rules

#### 8. CloudSyncD C2 Beacon - Initial Survey

Detects the initial C2 beacon containing hardware enumeration data sent via jQuery-mimicking URI.

<!-- audit: suricata -T exit 0, configuration successfully loaded -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE CloudSyncD C2 Beacon - jQuery URI Masquerade with Hardware UUID"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"jquery"; nocase; content:".js"; http.request_body; content:"hwid"; content:"cpu_cores"; content:"hw_model"; classtype:trojan-activity; sid:2026100401; rev:1;)
```

#### 9. CloudSyncD C2 Check-in

Detects subsequent C2 check-in beacons carrying hardware UUID via jQuery-mimicking URI.

<!-- audit: suricata -T exit 0, configuration successfully loaded -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE CloudSyncD C2 Check-in - jQuery URI with Hardware Identifier"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"jquery"; nocase; content:".js"; http.request_body; content:"hwid"; pcre:"/^[a-fA-F0-9\-]{36}/R"; classtype:trojan-activity; sid:2026100402; rev:1;)
```

### Snort Rules

#### 10-11. CloudSyncD C2 Beacon and Check-in (Snort 2.x)

Snort 2.x compatible versions of the Suricata rules above.

<!-- audit: snort -T -c /etc/snort/snort.conf exit 0, "Snort successfully validated the configuration!" -->

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE CloudSyncD C2 Beacon - jQuery URI Masquerade with Hardware UUID"; flow:established,to_server; content:"POST"; http_method; content:"jquery"; http_uri; nocase; content:".js"; http_uri; content:"hwid"; http_client_body; content:"cpu_cores"; http_client_body; content:"hw_model"; http_client_body; classtype:trojan-activity; sid:2026100401; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE CloudSyncD C2 Check-in - jQuery URI with Hardware Identifier"; flow:established,to_server; content:"POST"; http_method; content:"jquery"; http_uri; nocase; content:".js"; http_uri; content:"hwid"; http_client_body; pcre:"/hwid.{0,10}[a-fA-F0-9\-]{36}/R"; classtype:trojan-activity; sid:2026100402; rev:1;)
```

## Detection Gaps & Recommendations

1. **Missing Hash IOCs:** No file hashes were published by Jamf Threat Labs or any secondary source at time of writing. Monitor for updated IOC releases from Jamf to create hash-based detections.
2. **Missing C2 Domains:** The two C2 domains (registered 2011, behind Cloudflare) were not disclosed. Network-level blocking requires Jamf IOC publication or independent discovery.
3. **Persistence Not Observed:** LaunchAgent persistence was not triggered during analysis. Monitor for future variants that complete the persistence installation.
4. **Encrypted C2:** The ChaCha20-Poly1305 encrypted C2 traffic will evade content-based network inspection. TLS inspection or endpoint-level monitoring is required.
5. **Recommended Endpoint Telemetry:** Deploy macOS process creation logging (e.g., via Endpoint Security Framework, osquery, or Jamf Protect) to detect the dropper-to-backdoor execution chain. Monitor `~/.config/zoom/` and `~/.local/share/cloudsync/` for unexpected file creation.

## Rule Validation Summary

| # | Type | Title | Compile Status | Confidence |
|---|------|-------|----------------|------------|
| 1 | Sigma | CloudSyncD Fake Zoom Process Creation | PASS | Medium |
| 2 | Sigma | CloudSyncD File Artifacts | PASS | Medium |
| 3 | Sigma | Suspicious dscl Credential Validation | PASS | Medium |
| 4 | Sigma | Fileless Execution via /dev/fd | PASS | Low |
| 5 | YARA | CloudSyncD Backdoor Binary | PASS | Medium |
| 6 | YARA | CloudSyncD Dropper | PASS | Medium |
| 7 | YARA | Zero-Width Unicode Credential File | PASS | Medium |
| 8 | Suricata | CloudSyncD C2 Beacon (Initial Survey) | PASS | Low |
| 9 | Suricata | CloudSyncD C2 Check-in | PASS | Low |
| 10 | Snort | CloudSyncD C2 Beacon (Initial Survey) | PASS | Low |
| 11 | Snort | CloudSyncD C2 Check-in | PASS | Low |

---

*Report generated 2026-10-04 by Actioner CTI. All rules are behavioral/TTP-based due to absence of published hash and domain IOCs. No rule is rated high confidence because all detections rely on behavioral patterns rather than exact artifact matches.*
