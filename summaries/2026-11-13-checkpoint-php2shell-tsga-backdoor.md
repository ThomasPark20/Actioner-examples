# Check Point Gateway PHP2Shell Exploitation + TSGA Backdoor (CVE-2026-123039)

**Date:** 2026-11-13
**Status:** FINAL
**Author:** Actioner
**Classification:** TLP:CLEAR

---

## Executive Summary

An unknown threat actor has been exploiting unpatched Check Point Security Gateways through the PHP2Shell vulnerability chain (CVE-2026-109618 / CVE-2026-109619) combined with a Gaia OS local privilege escalation flaw (CVE-2026-123039) to deploy a sophisticated backdoor called TSGA. Activity began on October 30, 2026, initially targeting Israeli organizations in a destructive campaign, followed by a broader opportunistic wave starting November 2, 2026. The attackers gain initial access through vulnerable Mobile Access portals, escalate to root via the DynamicCLI IPC interface, deploy PHP web shells and the TSGA/TSProxy backdoor suite, then pivot internally using credential theft and the gogo network scanner. In at least one case, the attackers moved to a VMware ESXi host and deployed the destroy_v6 wiper with politically themed ransom-style notes. The toolset overlaps with the PhiliKit malware framework previously attributed by ESET to the China-nexus group Armory Castle (UNC5221), though Check Point notes the destructive component and Israel focus are atypical for that threat actor, raising false-flag or access-broker possibilities.

---

## Background: Check Point Security Gateways

Check Point Security Gateways are enterprise network security appliances running Gaia OS, a hardened Linux-based operating system. They provide firewall, VPN, intrusion prevention, and mobile access capabilities. The Mobile Access portal is a web-based interface that enables remote SSL VPN access. Affected products include:

- Check Point Security Gateways (R81 through R82.20)
- Check Point Force Firewalls
- Check Point Management and Log Servers
- Multi-Domain Security Management and Multi-Domain Log Server
- Maestro Orchestrator
- Scalable Platforms

---

## Technical Analysis

### Phase 1: PHP2Shell Initial Access (CVE-2026-109618 / CVE-2026-109619)

PHP2Shell refers to two critical vulnerabilities in PHP 5+ (CVE-2026-109618 and CVE-2026-109619) that enable remote code execution. These flaws were patched on October 21, 2026, but exploitation began days before patches were released and accelerated against unpatched systems afterward.

**Exploitation indicators:**
- PHP session files containing the `upload_progress_pwn` marker in `/opt/CPcvpn-R81.20/tmp/`
- Hundreds of Apache/PHP worker segmentation faults on the target gateway (observed Oct 30)
- HTTP requests from attacker IPs to the Mobile Access portal

### Phase 2: Gaia OS Privilege Escalation (CVE-2026-123039)

**CVE-2026-123039** (CVSS 7.8) is a local privilege escalation vulnerability in the DynamicCLI IPC interface on Gaia OS. The root-level daemon `dynamic_server` listens on `/tmp/dynamic_socket`, a **world-writable Unix socket with no authentication**. Any local user can send privileged commands that execute as root. Once the attacker has code execution through PHP2Shell (running as the portal service account), a single command to this socket escalates to root.

### Phase 3: Web Shell Deployment

After gaining root, the attackers deploy PHP web shells:

- **Naming pattern:** `zz<random>.tpl` files in the Mobile Access portal's login-page template directory
- **Deployment command:** `printf <base64> | base64 -d > <templates>/zz<random>.tpl`
- **Hardcoded authentication key:** `zz2026`
- **Capabilities:** OS command execution, PHP code evaluation, file upload
- **Encoding:** Accepts plain-text and base64-encoded commands with XOR obfuscation
- **Upload staging:** Files written to `/tmp/.up.tpl`, then copied as `challenge_render.tpl` into the portal directory

### Phase 4: TSGA Backdoor Deployment

TSGA is a standalone passive Linux gateway implant with roots in Tiny SHell (tsh). It is a variant of the PhiliKit malware framework.

**Deployment:**
- Initial binary dropped to `/tmp/CPconfigdaemon`
- Launched via: `nohup /tmp/CPconfigdaemon >/tmp/.bd.log 2>&1 &`
- Self-relocates and relaunches as `slot_CPconfigdaemon` when running as root
- Persists across reboots via backup/snapshot persistence mechanisms

**Capabilities:**
- Encrypted remote access and interactive shell with pseudo-terminal support
- Arbitrary shell, Python, and Perl execution
- File transfer to operator-chosen paths
- Configuration collection (selected or full appliance config)
- Backup and snapshot persistence
- Process injection into appliance processes
- Binary firewall log tampering
- Listens on **TCP port 11072** on all IPv4 interfaces

**TSProxy component:**
- Shared library written to `/lib/libcpfwcommon.so`
- Injected into selected appliance processes to intercept networking calls
- Provides encrypted SOCKS-style proxy functionality
- Handles specially marked attacker connections while passing normal traffic
- Shares credentials, transport secrets, activation-selector digests, and TLS materials with PhiliKit's `libdssafe.so`
- Communicates via Unix socket `/tmp/.p_sock`

### Phase 5: Internal Reconnaissance and Lateral Movement

- **gogo scanner** deployed on the gateway for internal asset and service discovery
- **SSH lateral movement** to VMware ESXi hosts using the `vpxuser` service account

### Phase 6: Destructive Activity (Wave 1 Only)

- **destroy_v6** wiper: Linux ELF binary that recursively overwrites files with zeros then deletes them
  - `-f` flag: Fast mode (skips zero-overwrite)
  - `-w` flag: Pipe-separated exclusion list
- **DREAM_ANNEXATION.txt** ransom-style note dropped in each processed directory
  - Contains politically themed content referencing the Israeli-Palestinian conflict
  - Brands the note with "Dream Security"
  - Rejects ransom negotiation

---

## Indicators of Compromise

### File System Indicators

| Indicator | Type | Context |
|---|---|---|
| `/tmp/CPconfigdaemon` | File path | TSGA backdoor initial drop location |
| `slot_CPconfigdaemon` | Process name | TSGA backdoor persistent process name |
| `/lib/libcpfwcommon.so` | File path | TSProxy malicious shared library |
| `/tmp/.p_sock` | Unix socket | TSGA/PhiliKit IPC socket |
| `/tmp/.bd.log` | File path | TSGA background output log |
| `/tmp/.up.tpl` | File path | Web shell upload staging path |
| `challenge_render.tpl` | File name | Uploaded file staged in portal directory |
| `zz*.tpl` | File pattern | Web shell files in template directory |
| `DREAM_ANNEXATION.txt` | File name | Wiper ransom-style note |
| `/tmp/dynamic_socket` | Unix socket | DynamicCLI IPC (exploitation target) |
| `/tmp/beacon.sh` | File path | Post-exploitation beacon script |
| `/tmp/collect.sh` | File path | Post-exploitation collection script |
| `/tmp/.c1104` | File path | Post-exploitation marker file |
| `/tmp/.wtest` | File path | Post-exploitation test file |
| `/var/www/.wtest` | File path | Post-exploitation test file |

### SHA-256 Hashes

| Hash | Component |
|---|---|
| `edb3e92eb7bda7413a09edcc4b1ba3cbed4bcdf42808a8abce63b6e4c3fda2b3` | TPL web shell |
| `4171b521fa6441382aa2fa014a08e18ff9a6e0ab6096c9144072bf46b37a2ec8` | slot_CPconfigdaemon (TSGA) |
| `d7549671c7189979f0624ec52dad9ea6a707d23146e3585ab8f8c4720eca0c63` | CPconfigdaemon (TSGA) |
| `3b51080a909023f7d484e2443740b572307ce0054eb9e32d98f0a06bfcd2db90` | gogo scanner |
| `c7d9477309fac6c638a1128442056a242de086996add8cb49cd6496c36003237` | destroy_v6 wiper |
| `0522937c0c0337be54fe25493539e5f5f8ceb9742c980aaff1cfc9515f3a96f7` | DREAM_ANNEXATION.txt |
| `ee16e1695711b9d60c62925fcfb2fe1a29c18ae26565bc05410a14e16d2a39d7` | philistine (PhiliKit variant) |
| `fb1a6235eb6bce8c9ec8cd8bb85f17c9c2bde8ecb45b7a243a30ceadf26654da` | libdssafe.so (PhiliKit component) |

### Network Indicators

| Indicator | Type | Context |
|---|---|---|
| `130.94.19[.]204` | IP | Primary attacker IP (both waves) |
| `130.94.19[.]168` | IP | Secondary attacker IP |
| `85.11.167[.]243` | IP | Earliest PHP2Shell scanning activity |
| `2.59.133[.]151` | IP | First confirmed PHP2Shell exploitation |
| `185.65.134[.]250` | IP | Reverse shell and persistence activity |
| `206.245.153[.]56` | IP | C2/staging server |
| TCP 11072 | Port | TSGA encrypted remote access listener |
| TCP 42104 | Port | Reverse shell port (on 206.245.153.56) |
| TCP 8088 | Port | Tool download port (on 206.245.153.56) |
| `http://206.245.153[.]56:8088/tools/collect.sh` | URL | Post-exploitation tool download |
| `php2shell-scan/109618` | User-Agent | Scanning user-agent string |
| LightNode VPS | Infrastructure | Hosting provider for attacker infrastructure |

### Behavioral Indicators

- Apache process (`apache2`) spawning shell processes (`sh`, `bash`)
- PHP session files with `upload_progress_pwn` marker
- Hundreds of Apache/PHP worker segfaults in a short time window
- Non-`dynamic_server` processes accessing `/tmp/dynamic_socket`
- Commands bypassing the default Clish wrapper (suggesting root execution through the socket)
- Use of `system()` sink (rare in legitimate Mobile Access traffic)
- Activity concentrated in 00:00-09:00 UTC window

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Campaign Usage |
|---|---|---|
| T1190 | Exploit Public-Facing Application | PHP2Shell exploitation of Mobile Access portals |
| T1068 | Exploitation for Privilege Escalation | CVE-2026-123039 DynamicCLI socket exploitation |
| T1505.003 | Server Software Component: Web Shell | PHP web shells (zz*.tpl) in portal templates |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell commands via web shell, beacon.sh, collect.sh |
| T1036.004 | Masquerading: Masquerade Task or Service | TSGA masquerading as CPconfigdaemon |
| T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking | TSProxy planted as libcpfwcommon.so |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | TSGA hidden files (.p_sock, .bd.log, .up.tpl) |
| T1055 | Process Injection | TSGA injecting TSProxy into appliance processes |
| T1005 | Data from Local System | Configuration and credential extraction from appliance |
| T1046 | Network Service Discovery | gogo scanner for internal reconnaissance |
| T1021.004 | Remote Services: SSH | SSH lateral movement via vpxuser to ESXi |
| T1485 | Data Destruction | destroy_v6 wiper |
| T1561.001 | Disk Wipe: Disk Content Wipe | Zero-overwrite before deletion |
| T1070.004 | Indicator Removal: File Deletion | Wiper destroying evidence |
| T1082 | System Information Discovery | Recon via /proc/* and system enumeration |
| T1562 | Impair Defenses | Binary firewall log tampering |

---

## Detection & Remediation

### Immediate Actions

1. **Patch immediately:** Apply Check Point hotfixes for CVE-2026-123039 (sk1000362) and ensure PHP2Shell patches (Oct 21) are applied
2. **Temporary mitigation:** Stop the `dynamic_server` process and prevent restart until hotfixes are applied
3. **Hunt for compromise:**
   - Search for `zz*.tpl` files in Mobile Access portal template directories
   - Check for `/tmp/CPconfigdaemon`, `slot_CPconfigdaemon` processes
   - Look for `/lib/libcpfwcommon.so` modifications
   - Check for `/tmp/.p_sock`, `/tmp/.bd.log`, `/tmp/.up.tpl`
   - Review Apache logs for `upload_progress_pwn` markers
   - Check for connections to/from the listed attacker IPs
   - Monitor for TCP 11072 listeners
4. **Block attacker infrastructure:** Add listed IPs to blocklists
5. **Review ESXi hosts:** Check for lateral movement via vpxuser, wiper artifacts

### Long-Term Recommendations

- Restrict Mobile Access portal exposure to required networks only
- Implement network segmentation between security gateways and internal infrastructure
- Monitor DynamicCLI socket access with auditd rules
- Deploy file integrity monitoring on Check Point appliance critical paths
- Restrict vpxuser SSH access from gateway segments

---

## Detection Rules

### Sigma Rules

All rules validated via `sigma convert` to Splunk SPL and CrowdStrike LogScale. `sigma check` could not complete due to MITRE ATT&CK data fetch failure (proxy environment limitation; not a structural rule issue).

#### Sigma Rule 1: TSGA Backdoor Process Execution
- **File:** `/tmp/actioner/checkpoint-1.yml`
- **Compile status:** PASS (converts to Splunk + LogScale)
- **Confidence:** HIGH
- **Targets:** Process creation events matching TSGA backdoor execution patterns (slot_CPconfigdaemon, nohup launch with .bd.log redirect)

**Splunk SPL:**
```
Image="*/CPconfigdaemon" OR (CommandLine="*nohup*" CommandLine="*CPconfigdaemon*" CommandLine="*.bd.log*")
```

<!-- revision: downgraded to medium; socket path may not appear in compiled exploit cmdline -->
#### Sigma Rule 2: DynamicCLI Privilege Escalation (CVE-2026-123039)
- **File:** `/tmp/actioner/checkpoint-2.yml`
- **Compile status:** PASS (converts to Splunk + LogScale)
- **Confidence:** MEDIUM
- **Targets:** Non-legitimate processes accessing /tmp/dynamic_socket
- **Caveat:** A compiled exploit may connect to the socket programmatically without the path appearing in the process command line. Supplement with auditd monitoring on `/tmp/dynamic_socket` for connect() syscalls.

**Splunk SPL:**
```
CommandLine="*/tmp/dynamic_socket*" NOT Image="*/dynamic_server"
```

<!-- revision: downgraded to medium; tightened "zz" substring to "/zz" path prefix to reduce false positives -->
#### Sigma Rule 3: PHP2Shell Web Shell Deployment
- **File:** `/tmp/actioner/checkpoint-3.yml`
- **Compile status:** PASS (converts to Splunk + LogScale)
- **Confidence:** MEDIUM
- **Targets:** base64-decoded .tpl file creation and /zz*.tpl web shell pattern
- **Caveat:** The 2-char substring "zz" is too broadly matching; rule tightened to require "/zz" path component. May still need environment-specific tuning.

**Splunk SPL:**
```
(CommandLine="*base64*" CommandLine="*-d*" CommandLine="*.tpl*") OR (CommandLine="*/zz*" CommandLine="*.tpl*")
```

<!-- revision: CRITICAL→high; ATT&CK tag corrected t1571→t1564.001 (Hide Artifacts: Hidden Files and Directories) -->
#### Sigma Rule 4: TSGA Hidden File Artifacts
- **File:** `/tmp/actioner/checkpoint-4.yml`
- **Compile status:** PASS (converts to Splunk + LogScale)
- **Confidence:** HIGH
- **Targets:** Creation of .p_sock, .bd.log, and .up.tpl files

**Splunk SPL:**
```
TargetFilename IN ("*/.p_sock", "*/.bd.log", "*/.up.tpl")
```

<!-- revision: CRITICAL→high -->
#### Sigma Rule 5: TSProxy Shared Library Injection
- **File:** `/tmp/actioner/checkpoint-5.yml`
- **Compile status:** PASS (converts to Splunk + LogScale)
- **Confidence:** HIGH
- **Targets:** Modification of /lib/libcpfwcommon.so

**Splunk SPL:**
```
TargetFilename="/lib/libcpfwcommon.so"
```

<!-- revision: CRITICAL→high -->
#### Sigma Rule 6: Destroy_v6 Wiper Execution
- **File:** `/tmp/actioner/checkpoint-6.yml`
- **Compile status:** PASS (converts to Splunk + LogScale)
- **Confidence:** HIGH
- **Targets:** Execution of destroy_v6/destory_v6 wiper binary

**Splunk SPL:**
```
Image IN ("*/destroy_v6", "*/destory_v6") OR CommandLine IN ("*destroy_v6*", "*destory_v6*")
```

#### Sigma Rule 7: PHP2Shell Post-Exploitation Beacon Activity
- **File:** `/tmp/actioner/checkpoint-7.yml`
- **Compile status:** PASS (converts to Splunk + LogScale)
- **Confidence:** MEDIUM
- **Targets:** Post-exploitation beacon and collection scripts from GreyNoise observations

**Splunk SPL:**
```
CommandLine IN ("*/tmp/beacon.sh*", "*/tmp/collect.sh*") OR CommandLine IN ("*/tmp/.c1104*", "*/tmp/.wtest*", "*/tmp/.loot-*")
```

### YARA Rules

All rules compiled successfully with `yarac`.

#### YARA Rule 1: TSGA_Backdoor_CPconfigdaemon
- **File:** `/tmp/actioner/checkpoint-1.yar`
- **Compile status:** PASS
- **Confidence:** HIGH
- **Targets:** ELF binaries containing TSGA backdoor strings (process names, socket paths, log files)

#### YARA Rule 2: PHP2Shell_WebShell_TPL
- **File:** `/tmp/actioner/checkpoint-2.yar`
- **Compile status:** PASS
- **Confidence:** HIGH
- **Targets:** PHP web shells with the zz2026 hardcoded key, PHP execution functions, and upload staging paths

#### YARA Rule 3: Destroy_v6_Wiper
- **File:** `/tmp/actioner/checkpoint-3.yar`
- **Compile status:** PASS
- **Confidence:** HIGH
- **Targets:** ELF binaries containing destroy_v6 wiper and DREAM_ANNEXATION note indicators

#### YARA Rule 4: TSProxy_libcpfwcommon
- **File:** `/tmp/actioner/checkpoint-4.yar`
- **Compile status:** PASS
- **Confidence:** HIGH
- **Targets:** ELF shared libraries matching the TSProxy component with related PhiliKit indicators

#### YARA Rule 5: PhiliKit_Philistine_Variant
- **File:** `/tmp/actioner/checkpoint-5.yar`
- **Compile status:** PASS
- **Confidence:** MEDIUM
- **Targets:** ELF binaries matching 3+ PhiliKit family strings (broader family detection)

### Snort/Suricata Rules

> These rules are structural only and could not be compiled in this environment.

<!-- revision: Suricata Rule 1 (TSGA C2 on TCP 11072) DROPPED — port-only alerting with cosmetic null-byte check has near-zero discriminative value -->

#### Suricata Rule 2: PHP2Shell Scanner User-Agent

```
alert http any any -> any any (msg:"ET SCAN PHP2Shell Scanner User-Agent Detected"; flow:to_server,established; http.user_agent; content:"php2shell-scan/109618"; nocase; classtype:web-application-attack; sid:2026110002; rev:1;)
```
- **Confidence:** HIGH | Uncompiled (structural check only)

<!-- revision: downgraded to medium; "/tools/collect.sh" is a generic URI path -->
#### Suricata Rule 3: PHP2Shell Post-Exploitation Tool Download

```
alert http any any -> $EXTERNAL_NET any (msg:"ETPRO MALWARE PHP2Shell Post-Exploitation Tool Download (collect.sh)"; flow:to_server,established; http.uri; content:"/tools/collect.sh"; endswith; classtype:trojan-activity; sid:2026110003; rev:1;)
```
- **Confidence:** MEDIUM | Uncompiled (structural check only)

---

## Sources

- [The Hacker News: Hackers Exploit PHP2Shell Flaws in Check Point Gateways](https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html) - November 13, 2026
- [SecurityWeek: PHP2Shell Exploited in Destructive Check Point Gateway Attacks](https://www.securityweek.com/php2shell-exploited-in-destructive-check-point-gateway-attacks/) - November 13, 2026
- [BleepingComputer: Check Point Patches Zero-Day That Lets Hackers Get Root Access](https://www.bleepingcomputer.com/news/security/check-point-patches-zero-day-that-lets-hackers-get-root-access/) - November 13, 2026
- [Check Point Research: PHP2Shell Exploitation on Check Point Gateway](https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/) - Primary technical source
- [Check Point Advisory sk1000362](https://support.checkpoint.com/results/sk/sk1000362) - CVE-2026-123039 advisory
- [GreyNoise PHP2Shell Activity Tracker](https://php.events.greynoise.io/) - Scanning/exploitation telemetry
- [ESET APT Activity Report Q4 2025-Q1 2026](https://web-assets.esetstatic.com/wls/en/papers/threat-reports/eset-apt-activity-report-q4-2025-q1-2026.pdf) - PhiliKit attribution context
