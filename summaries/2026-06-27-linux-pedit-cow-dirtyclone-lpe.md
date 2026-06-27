# Linux Kernel LPE: pedit COW (CVE-2026-46331) & DirtyClone (CVE-2026-43503)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-27
Version: 1.1 (REVISED)

## Executive Summary

CVE-2026-46331 ("pedit COW") and CVE-2026-43503 ("DirtyClone") are two Linux kernel local privilege escalation vulnerabilities that exploit page-cache memory corruption to silently modify cached setuid-root binaries in memory, granting unprivileged local users root access. Both were publicly disclosed with working proof-of-concept exploits in late June 2026 and belong to a broader family of "DirtyFrag" kernel flaws that have surfaced over six weeks (Copy Fail, DirtyFrag, Fragnesia, pedit COW, DirtyClone).

**pedit COW** (CVSS 8.5 High) resides in the traffic-control packet editor (`net/sched/act_pedit`), where `tcf_pedit_act()` computes the copy-on-write range once before iterating over edit keys. Runtime-resolved offsets bypass this precomputed range, enabling out-of-bounds writes to page-cache memory. A weaponized PoC (`packet_edit_meme`) was published on GitHub on June 17, 2026 -- one day after CVE assignment -- and achieves reliable root on RHEL 8/9/10, Debian 11-13, and Ubuntu 18.04-24.04.

**DirtyClone** (CVSS 8.8 High) exploits the loss of the `SKBFL_SHARED_FRAG` safety flag during socket buffer cloning in `__pskb_copy_fclone()` and `skb_shift()`. An attacker routes file-backed memory pages through a loopback IPsec tunnel, where in-place ESP decryption overwrites the cached binary's authentication logic. JFrog Security Research published a working exploit walkthrough on June 25, 2026.

Both exploits are **silent** -- they leave no kernel logs or audit traces and bypass on-disk file-integrity monitoring since modifications exist only in kernel memory. The common prerequisite is unprivileged user namespaces (enabled by default on Debian, Fedora, RHEL, and most distributions) which grants `CAP_NET_ADMIN` within a namespace. Immediate kernel patching is strongly recommended.

## Background

### Affected Kernels

| CVE | Vulnerable Range | Fixed In | Root Cause Commit |
|-----|-----------------|----------|-------------------|
| CVE-2026-46331 | v5.18 through v7.1-rc6 | v7.1-rc7 | `899ee91156e5` |
| CVE-2026-43503 | v5.10.x through v7.1-rc4 | v7.1-rc5 (commit `48f6a5356a33`) | Multiple frag-transfer helpers |

### Severity Ratings

| CVE | CVSS v4.0 | Red Hat Rating | Attack Vector | Privileges Required |
|-----|-----------|----------------|---------------|-------------------|
| CVE-2026-46331 | 8.5 (High) | Important | Local | Low (unprivileged userns) |
| CVE-2026-43503 | 8.8 (High) | Important | Local | Low (unprivileged userns) |

### Affected Distributions

| Distribution | CVE-2026-46331 | CVE-2026-43503 | Notes |
|-------------|----------------|----------------|-------|
| RHEL 10 (kernel 6.12.0-228.el10) | Vulnerable | Vulnerable | RHSB-2026-008 published |
| RHEL 8, 9 | Vulnerable | Vulnerable | |
| Debian 13 Trixie (6.12.90+deb13.1) | Vulnerable (fix via security channel) | Vulnerable | |
| Debian 11, 12 | Vulnerable | Vulnerable | |
| Ubuntu 18.04 - 24.04 | Vulnerable | Partially mitigated (AppArmor) | USN-8373-1 |
| Ubuntu 26.04 | Patched | Patched | Enhanced AppArmor restrictions |
| Fedora | Vulnerable | Vulnerable (default userns) | |
| SUSE | Advisory published | Advisory published | |

### DirtyFrag Family Timeline

| Vulnerability | CVE(s) | Disclosure Date |
|--------------|--------|-----------------|
| Copy Fail | CVE-2026-31431 | Late April 2026 |
| DirtyFrag | CVE-2026-43284, CVE-2026-43500 | May 7, 2026 |
| Fragnesia | CVE-2026-46300 | May 13, 2026 |
| DirtyClone | CVE-2026-43503 | May 23, 2026 (CVE); June 25, 2026 (PoC) |
| pedit COW | CVE-2026-46331 | June 16, 2026 (CVE); June 17, 2026 (PoC) |

## Technical Analysis

### CVE-2026-46331 — pedit COW

#### Root Cause

The vulnerability resides in `tcf_pedit_act()` in `net/sched/act_pedit.c`. The function calls `skb_ensure_writable()` once before the edit-key loop using `tcfp_off_max_hint`, but this hint does not account for runtime header offsets added by typed keys at execution time. This creates a partial copy-on-write condition where writes land in unprivatized shared page-cache pages.

#### Exploitation Chain (packet_edit_meme)

The public PoC exploit (`packet_edit_meme` by sgkdev) follows this four-step chain:

1. **Namespace Setup**: The exploit creates an unprivileged user namespace to obtain namespace-local `CAP_NET_ADMIN`:
   - Spawns a child process via `clone()` with `CLONE_NEWUSER | CLONE_NEWNET`
   - On Ubuntu, uses `aa-exec` with permissive AppArmor profiles (`trinity`, `chrome`, `flatpak`) to bypass namespace restrictions (the `--ubuntu` flag)

2. **Traffic Control Binding**: Configures a `tc` pedit action with typed keys whose runtime offset exceeds the precomputed writable range:
   - Loads `act_pedit` kernel module (auto-loaded on demand)
   - Falls back from `cls_basic`/`em_meta` to `matchall` classifier on RHEL where former modules are unavailable

3. **Page-Cache Targeting**: Feeds zero-copy file references via `sendfile()` to direct corruption at the cached `/bin/su` ELF image in memory

4. **Payload Injection**: Overwrites the ELF entry point with shellcode that executes:
   ```
   setgid(0) → setuid(0) → execve("/bin/sh")
   ```

#### Key Kernel Functions

| Function | Role |
|----------|------|
| `tcf_pedit_act()` | Vulnerable function; partial COW computation |
| `skb_ensure_writable()` | Called once before loop (should be per-key) |
| `offset_valid()` | Missing INT_MIN guard |

#### Exploit Source Files

- `packet_edit_meme.c` (main exploit)
- `pedit_primitive.c` / `pedit_primitive.h` (write primitive)
- `test_cve.c` (vulnerability test)

#### Upstream Fix

The patch moves `skb_ensure_writable()` inside the per-key loop and adds overflow checking on offset arithmetic. Fix commits: `899ee91156e5`, `2bec122b9fb9`, `3dee9d0c198f`, `b198ed4e5258`.

### CVE-2026-43503 — DirtyClone

#### Root Cause

During socket buffer cloning, the functions `__pskb_copy_fclone()` and `skb_shift()` fail to preserve the `SKBFL_SHARED_FRAG` flag. This flag marks the packet's memory as shared with a file on disk. Without it, the kernel skips copy-on-write protections, treating shared page-cache memory as exclusively owned packet data.

#### Exploitation Chain (JFrog Security Research)

1. **Binary Memory-Mapping**: Load target setuid binary into page cache:
   ```c
   int fd = open("/usr/bin/su", O_RDONLY);
   char *p = mmap(NULL, mmap_size, PROT_READ, MAP_SHARED, fd, 0);
   ```

2. **Page Injection via vmsplice/splice**: Attach file-backed pages into a UDP socket buffer without copying:
   ```c
   struct iovec iov = { .iov_base = p + patch_offset, .iov_len = 16 };
   vmsplice(pipefd[1], &iov, 1, 0);
   splice(pipefd[0], NULL, sockfd, NULL, 16, 0);
   ```

3. **User Namespace Creation**: Obtain `CAP_NET_ADMIN` capability:
   ```
   unshare -Urn
   ```

4. **Loopback Network Configuration**:
   ```
   ip link set lo up
   ip addr add 10.99.0.2/24 dev lo
   ```

5. **IPsec Tunnel Setup**: Configure ESP tunnel on loopback:
   ```
   ip xfrm state add src 127.0.0.1 dst 127.0.0.1 proto esp spi 0x12345678 \
       reqid 1 mode transport enc 'cbc(aes)' ... auth 'hmac(sha1)' ...
   ip xfrm policy add src 127.0.0.1 dst 127.0.0.1 dir out \
       tmpl src 127.0.0.1 dst 127.0.0.1 proto esp reqid 1 mode transport
   ```

6. **Netfilter TEE Rule** (triggers packet cloning via `nf_dup_ipv4()` -> `__pskb_copy_fclone()`):
   ```
   iptables -t mangle -A OUTPUT -p udp --dport 4500 -j TEE --gateway 10.99.0.2
   ```

7. **Trigger and Execute**: Send crafted UDP packet. The cloned skb reaches `esp_input()` where AES-CBC decryption operates directly on page-cache memory, overwriting the binary's authentication logic with attacker-controlled bytes. Execute the modified `/usr/bin/su` from the poisoned cache to obtain root.

#### Key Kernel Functions

| Function | Role |
|----------|------|
| `__pskb_copy_fclone()` | Drops `SKBFL_SHARED_FRAG` during clone |
| `skb_shift()` | Also drops the safety flag |
| `nf_dup_ipv4()` | Triggered by TEE netfilter rule |
| `esp_input()` | In-place ESP decryption (write primitive) |

#### Kernel Modules Required

- `esp4` / `esp6` (IPsec ESP processing)
- `rxrpc` (alternative vulnerable path)

#### Upstream Fix

Commit `48f6a5356a33` (merged May 21, 2026) preserves `SKBFL_SHARED_FRAG` across all skb copy/clone, coalesce, GRO receive, and segment paths. Original researcher Hyunwoo Kim submitted a broader multi-site patch on May 16 covering additional frag-transfer helpers.

### Shared Exploitation Characteristics

Both vulnerabilities share critical properties:

- **No audit trail**: Modifications occur only in kernel memory; no kernel logs or auditd events are generated by the corruption itself
- **File integrity bypass**: Disk copies remain unmodified; tools like AIDE, OSSEC, and Tripwire detect nothing
- **Reboot clears evidence**: Rebooting evicts the poisoned page cache and restores original binaries
- **Same prerequisite**: Unprivileged user namespaces providing `CAP_NET_ADMIN`
- **Same target**: Setuid-root binaries (`/bin/su`, `/usr/bin/su`)
- **Same payload**: `setgid(0)` + `setuid(0)` + `execve("/bin/sh")` shellcode injected into cached ELF entry point

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs and IPs below use defanged notation where applicable.

### Exploit Artifacts

| Indicator | Type | Context |
|-----------|------|---------|
| `packet_edit_meme` | File name | pedit COW PoC exploit binary |
| `packet_edit_meme.c` | File name | pedit COW PoC source |
| `pedit_primitive.c` | File name | pedit COW primitive library |
| `pedit_primitive.h` | File name | pedit COW primitive header |
| `test_cve.c` | File name | pedit COW vulnerability test |
| `dirtyclone.py` | File name | DirtyClone Python PoC |
| `hxxps://github[.]com/sgkdev/packet_edit_meme` | URL | pedit COW PoC repository |
| `hxxps://github[.]com/aexdyhaxor/CVE-2026-43503-DirtyClone` | URL | DirtyClone PoC repository |

### Process Indicators

| Indicator | Context |
|-----------|---------|
| Process `packet_edit_meme` executing | pedit COW exploitation in progress |
| `unshare -Urn` by non-root user | Namespace creation for either exploit |
| `aa-exec -p trinity` / `aa-exec -p chrome` / `aa-exec -p flatpak` | AppArmor bypass for pedit COW on Ubuntu |
| `tc ... action pedit ...` by non-root user | pedit COW traffic control configuration |
| `ip xfrm state add ... 127.0.0.1 ... esp ...` | DirtyClone IPsec loopback tunnel setup |
| `ip xfrm policy add ... 127.0.0.1 ... esp ...` | DirtyClone IPsec policy configuration |
| `iptables -t mangle ... -j TEE --gateway` | DirtyClone netfilter cloning trigger |
| Unexpected `su` spawning `/bin/sh` as root without `-c` flag | Post-exploitation shell from poisoned binary |

### Kernel Module Indicators

| Module | Context |
|--------|---------|
| `act_pedit` | Required for CVE-2026-46331; rarely needed in production |
| `esp4` / `esp6` | Required for CVE-2026-43503 IPsec decryption path |
| `rxrpc` | Alternative path for CVE-2026-43503 |

### Detection Challenge

Both exploits are designed to be **forensically silent**. The page-cache corruption occurs in kernel memory space and generates no kernel log entries, no auditd syscall events for the actual corruption operation, and no file modification events. Detection must focus on the **preparation phase** (namespace creation, module loading, network configuration) rather than the corruption itself.

## MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|-----------|-------|-----------|
| Exploitation for Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) | Core technique: kernel vulnerability exploitation for root access |
| Abuse Elevation Control Mechanism: Setuid and Setgid | [T1548.001](https://attack.mitre.org/techniques/T1548/001/) | Exploits target setuid-root binaries (`/bin/su`, `/usr/bin/su`) |
| Escape to Host | [T1611](https://attack.mitre.org/techniques/T1611/) | Namespace creation used to obtain `CAP_NET_ADMIN` |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | In-memory modification of cached binary code pages without touching disk |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Exploit may probe kernel version and module availability |
<!-- revision: 2026-06-27-R1 -- removed T1070.006 (Timestomp): exploits do not modify timestamps. Removed T1014 (Rootkit): in-memory page-cache corruption is not a rootkit. Added T1055 (Process Injection) as closer match for in-memory binary modification. -->

## Detection Rules

<!-- revision: 2026-06-27-R1 -- 4 of 7 Sigma rules revised (rules 1, 3, 5, 7). All 7 re-validated via sigma convert (Splunk + LogScale --without-pipeline). All 4 YARA rules unchanged, re-validated via yarac. -->
### Sigma Rules (7 rules) -- all validated via Splunk and LogScale conversion

#### 1. act_pedit Kernel Module Load Detection

<!-- revision: 2026-06-27-R1 -- changed logsource from syslog/EventType:module_load to auditd/type:KERN_MODULE+name:act_pedit. Fixed condition from "selection or keywords" (overly broad) to single "selection" with structured fields. Downgraded level from high to medium to match medium confidence. -->

**Compile status**: PASS (Splunk + LogScale)
**Confidence**: Medium

```yaml
title: Linux act_pedit Kernel Module Load - Potential CVE-2026-46331 Exploitation
id: 7a3b2c1d-4e5f-6a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: Detects loading of the act_pedit kernel module which is required for CVE-2026-46331
    (pedit COW) exploitation. The module is rarely loaded in production environments and
    its loading by non-root users via unprivileged user namespaces is a strong indicator
    of exploitation preparation.
references:
    - https://github.com/sgkdev/packet_edit_meme
    - https://thehackernews.com/2026/06/new-linux-pedit-cow-exploit-enables.html
    - https://ubuntu.com/security/CVE-2026-46331
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.privilege-escalation
    - attack.t1068
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: KERN_MODULE
        name: 'act_pedit'
    condition: selection
falsepositives:
    - Legitimate traffic control configuration using pedit actions
    - Network administrators configuring tc rules
level: medium
```

#### 2. packet_edit_meme Exploit Process Execution

**Compile status**: PASS (Splunk + LogScale)
**Confidence**: High

```yaml
title: Linux pedit COW Exploit Process Chain - CVE-2026-46331
id: 8b4c3d2e-5f6a-7b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: Detects the process execution pattern associated with the packet_edit_meme exploit
    for CVE-2026-46331. The exploit binary spawns a user namespace child process with
    CAP_NET_ADMIN, configures tc pedit rules to corrupt page cache of /bin/su, then
    executes the poisoned setuid binary to gain root.
references:
    - https://github.com/sgkdev/packet_edit_meme
    - https://thehackernews.com/2026/06/new-linux-pedit-cow-exploit-enables.html
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.privilege-escalation
    - attack.t1068
    - attack.t1548.001
logsource:
    product: linux
    category: process_creation
detection:
    selection_exploit_binary:
        Image|endswith:
            - '/packet_edit_meme'
        CommandLine|contains:
            - 'packet_edit_meme'
    selection_ubuntu_bypass:
        Image|endswith:
            - '/aa-exec'
        CommandLine|contains:
            - 'trinity'
            - 'chrome'
            - 'flatpak'
    condition: selection_exploit_binary or selection_ubuntu_bypass
falsepositives:
    - Legitimate use of aa-exec with these profiles is uncommon but possible
level: critical
```

#### 3. Unprivileged User Namespace Creation for CAP_NET_ADMIN

<!-- revision: 2026-06-27-R1 -- downgraded confidence to Low (from Medium) and level to medium (from high). Added filter_container_runtimes exclusion for Flatpak/Podman/Buildah/bwrap/bubblewrap. Added tuning guidance to description. Too generic for "specific" altitude due to legitimate container runtime usage. -->

**Compile status**: PASS (Splunk + LogScale)
**Confidence**: Low

```yaml
title: Unprivileged User Namespace Creation for Network Admin Capabilities
id: 9c5d4e3f-6a7b-8c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: Detects the use of unshare to create user namespaces with network namespace capabilities,
    which is the common prerequisite for both CVE-2026-46331 (pedit COW) and CVE-2026-43503
    (DirtyClone) exploitation. Both exploits require CAP_NET_ADMIN obtained via unprivileged
    user namespaces. Note that this pattern is also used legitimately by Flatpak, Podman,
    and other container runtimes, so tuning is expected to be necessary. Consider baselining
    expected users and processes that invoke unshare in your environment.
references:
    - https://github.com/sgkdev/packet_edit_meme
    - https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.privilege-escalation
    - attack.t1068
    - attack.defense-evasion
    - attack.t1611
logsource:
    product: linux
    category: process_creation
detection:
    selection_unshare:
        Image|endswith: '/unshare'
        CommandLine|contains|all:
            - '-U'
            - '-r'
            - '-n'
    filter_container_runtimes:
        ParentImage|endswith:
            - '/flatpak'
            - '/podman'
            - '/buildah'
            - '/bwrap'
            - '/bubblewrap'
    condition: selection_unshare and not filter_container_runtimes
falsepositives:
    - Flatpak application launches
    - Podman and Buildah container operations
    - Bubblewrap sandboxing (used by GNOME and other desktop components)
    - Container runtime operations
    - Legitimate namespace isolation for testing
level: medium
```

#### 4. DirtyClone IPsec Loopback Tunnel Configuration

**Compile status**: PASS (Splunk + LogScale)
**Confidence**: High

```yaml
title: DirtyClone IPsec Loopback Tunnel Configuration - CVE-2026-43503
id: 0d6e5f4a-7b8c-9d0e-1f2a-3b4c5d6e7f8a
status: experimental
description: Detects configuration of IPsec/XFRM state and policy on the loopback interface, which
    is a key step in the DirtyClone (CVE-2026-43503) exploitation chain. The exploit creates
    a loopback IPsec tunnel to trigger in-place ESP decryption that overwrites page-cache memory.
references:
    - https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/
    - https://thehackernews.com/2026/06/new-dirtyclone-linux-kernel-flaw-lets.html
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.privilege-escalation
    - attack.t1068
logsource:
    product: linux
    category: process_creation
detection:
    selection_xfrm_state:
        Image|endswith: '/ip'
        CommandLine|contains|all:
            - 'xfrm'
            - 'state'
            - 'add'
            - '127.0.0.1'
            - 'esp'
    selection_xfrm_policy:
        Image|endswith: '/ip'
        CommandLine|contains|all:
            - 'xfrm'
            - 'policy'
            - 'add'
            - '127.0.0.1'
            - 'esp'
    selection_tee_rule:
        Image|endswith:
            - '/iptables'
            - '/iptables-nft'
        CommandLine|contains|all:
            - 'TEE'
            - 'mangle'
            - 'OUTPUT'
    condition: selection_xfrm_state or selection_xfrm_policy or selection_tee_rule
falsepositives:
    - IPsec testing on loopback in development environments
level: high
```

#### 5. Suspicious vmsplice/splice Syscalls from Exploit Binaries

<!-- revision: 2026-06-27-R1 -- BLOCKER FIX: removed invalid dual logsource (service: auditd + category: process_creation are mutually exclusive in Sigma). Kept service: auditd only, as this rule detects SYSCALL audit records, not process creation events. -->

**Compile status**: PASS (Splunk + LogScale)
**Confidence**: High

```yaml
title: Suspicious vmsplice/splice Syscalls on Setuid Binary - Page Cache Injection
id: 1e7f6a5b-8c9d-0e1f-2a3b-4c5d6e7f8a9b
status: experimental
description: Detects auditd syscall events for vmsplice and splice operations from known
    exploit binaries. This pattern is characteristic of both CVE-2026-46331 (pedit COW)
    and CVE-2026-43503 (DirtyClone) which use vmsplice/splice to inject page-cache-backed
    memory into socket buffers for corruption.
references:
    - https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/
    - https://github.com/sgkdev/packet_edit_meme
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.privilege-escalation
    - attack.t1068
logsource:
    product: linux
    service: auditd
detection:
    selection_vmsplice:
        type: SYSCALL
        syscall: 'vmsplice'
        exe|endswith:
            - '/packet_edit_meme'
            - '/dirtyclone'
    selection_splice:
        type: SYSCALL
        syscall: 'splice'
        exe|endswith:
            - '/packet_edit_meme'
            - '/dirtyclone'
    condition: selection_vmsplice or selection_splice
falsepositives:
    - Legitimate use of vmsplice/splice for high-performance I/O
level: critical
```

#### 6. Suspicious tc pedit Action Configuration

**Compile status**: PASS (Splunk + LogScale)
**Confidence**: Medium

```yaml
title: Suspicious Traffic Control pedit Action Configuration - CVE-2026-46331
id: 2f8a7b6c-9d0e-1f2a-3b4c-5d6e7f8a9b0c
status: experimental
description: Detects execution of tc (traffic control) commands that configure pedit actions,
    which is a required step in CVE-2026-46331 exploitation. The exploit configures
    typed pedit keys with runtime offsets that exceed the precomputed writable range.
references:
    - https://github.com/sgkdev/packet_edit_meme
    - https://tuxcare.com/blog/pedit-cow-cve/
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.privilege-escalation
    - attack.t1068
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/tc'
        CommandLine|contains|all:
            - 'pedit'
            - 'action'
    condition: selection
falsepositives:
    - Legitimate network traffic control configuration
    - Network quality of service (QoS) tuning
level: medium
```

#### 7. Setuid Binary Spawning Shell as Root (Post-Exploitation)

<!-- revision: 2026-06-27-R1 -- downgraded confidence to Low (from Medium) and level to low (from medium) due to high FP rate from interactive su sessions. Removed redundant ParentImage '/su' (subsumed by '/bin/su' and '/usr/bin/su'). Added 'su -' and 'su - root' to filter_legitimate to cover common admin patterns. Expanded description with FP warning and correlation guidance. -->

**Compile status**: PASS (Splunk + LogScale)
**Confidence**: Low

```yaml
title: Setuid Binary Execution After User Namespace Operations - Page Cache LPE
id: 3a9b8c7d-0e1f-2a3b-4c5d-6e7f8a9b0c1d
status: experimental
description: Detects execution of setuid binaries (su) spawning a root shell without standard
    login flags, which is the final step in page-cache poisoning LPE exploits. After corrupting
    the cached binary via pedit COW or DirtyClone, the attacker executes it to trigger the
    injected shellcode (setgid(0)+setuid(0)+execve("/bin/sh")). Note that interactive su
    sessions legitimately spawn shells as root; this rule has a high false-positive rate
    and should be correlated with other indicators from this report for actionable alerting.
references:
    - https://github.com/sgkdev/packet_edit_meme
    - https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.privilege-escalation
    - attack.t1068
    - attack.t1548.001
logsource:
    product: linux
    category: process_creation
detection:
    selection_su_spawn_shell:
        ParentImage|endswith:
            - '/bin/su'
            - '/usr/bin/su'
        Image|endswith:
            - '/sh'
            - '/bash'
        User: 'root'
    filter_legitimate:
        ParentCommandLine|contains:
            - '-c'
            - '--command'
            - '--login'
            - 'su -'
            - 'su - root'
    condition: selection_su_spawn_shell and not filter_legitimate
falsepositives:
    - Interactive su sessions spawning shells (common admin workflow)
    - Automated scripts using su to switch users
    - System services that invoke su for privilege changes
level: low
```

### YARA Rules (4 rules) -- compiled successfully with yarac

**Compile status**: PASS (yarac)

```yara
rule packet_edit_meme_exploit_CVE_2026_46331
{
    meta:
        description = "Detects the packet_edit_meme PoC exploit binary for CVE-2026-46331 (pedit COW page-cache corruption LPE)"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://github.com/sgkdev/packet_edit_meme"
        severity = "critical"
        cve = "CVE-2026-46331"

    strings:
        $s1 = "packet_edit_meme" ascii
        $s2 = "pedit_primitive" ascii
        $s3 = "tcf_pedit_act" ascii
        $s4 = "act_pedit" ascii
        $s5 = "skb_ensure_writable" ascii

        $exploit_str1 = "/bin/su" ascii
        $exploit_str2 = "/bin/sh" ascii
        $exploit_str3 = "setgid" ascii
        $exploit_str4 = "setuid" ascii
        $exploit_str5 = "execve" ascii

        $cmd1 = "cls_basic" ascii
        $cmd2 = "em_meta" ascii
        $cmd3 = "matchall" ascii

        $ubuntu_bypass = "aa-exec" ascii
        $profile1 = "trinity" ascii
        $profile2 = "flatpak" ascii

        $cow_str1 = "page-cache" ascii nocase
        $cow_str2 = "page_cache" ascii nocase
        $cow_str3 = "cow" ascii nocase

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (
            ($s1 and any of ($exploit_str*)) or
            ($s2 and $s4) or
            (3 of ($s*) and 2 of ($exploit_str*)) or
            ($s1 and $ubuntu_bypass) or
            (2 of ($cmd*) and any of ($exploit_str*)) or
            (any of ($cow_str*) and any of ($s*) and any of ($exploit_str*)) or
            ($ubuntu_bypass and any of ($profile*) and $s1)
        )
}

rule dirtyclone_exploit_CVE_2026_43503
{
    meta:
        description = "Detects DirtyClone exploit binaries or scripts for CVE-2026-43503 (page-cache corruption via IPsec packet cloning)"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/"
        severity = "critical"
        cve = "CVE-2026-43503"

    strings:
        $name1 = "DirtyClone" ascii nocase
        $name2 = "dirtyclone" ascii nocase
        $name3 = "dirty_clone" ascii nocase
        $name4 = "CVE-2026-43503" ascii

        $func1 = "__pskb_copy_fclone" ascii
        $func2 = "skb_shift" ascii
        $func3 = "nf_dup_ipv4" ascii
        $func4 = "esp_input" ascii
        $func5 = "SKBFL_SHARED_FRAG" ascii

        $exploit_cmd1 = "unshare -Urn" ascii
        $exploit_cmd2 = "xfrm state add" ascii
        $exploit_cmd3 = "xfrm policy add" ascii
        $exploit_cmd4 = "vmsplice" ascii
        $exploit_cmd5 = "splice" ascii
        $exploit_cmd6 = "-j TEE --gateway" ascii

        $target1 = "/usr/bin/su" ascii
        $target2 = "/bin/su" ascii

    condition:
        filesize < 5MB and
        (
            (any of ($name*) and 2 of ($exploit_cmd*)) or
            (2 of ($func*) and any of ($target*)) or
            ($exploit_cmd1 and $exploit_cmd2 and $exploit_cmd3 and $exploit_cmd6) or
            (any of ($name*) and any of ($func*) and any of ($target*))
        )
}

rule pagecache_poisoning_shellcode_generic
{
    meta:
        description = "Detects generic page-cache poisoning shellcode pattern: setgid(0)+setuid(0)+execve(/bin/sh) commonly injected into cached setuid binaries"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://thehackernews.com/2026/06/new-linux-pedit-cow-exploit-enables.html"
        severity = "high"

    strings:
        // x86_64 shellcode: setgid(0) - syscall 106
        $sc_setgid = { 48 31 FF 48 C7 C0 6A 00 00 00 0F 05 }

        // x86_64 shellcode: setuid(0) - syscall 105
        $sc_setuid = { 48 31 FF 48 C7 C0 69 00 00 00 0F 05 }

        // x86_64 shellcode: execve("/bin/sh") common pattern
        $sc_execve_binsh = { 2F 62 69 6E 2F 73 68 00 }

        // Common exploit strings
        $str_pagecache = "page.cache" ascii nocase
        $str_sendfile = "sendfile" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (
            ($sc_setgid and $sc_setuid and $sc_execve_binsh) or
            (all of ($sc_*) and any of ($str_*))
        )
}

rule dirtyclone_python_poc
{
    meta:
        description = "Detects the Python-based DirtyClone PoC exploit script (CVE-2026-43503)"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://github.com/aexdyhaxor/CVE-2026-43503-DirtyClone"
        severity = "critical"
        cve = "CVE-2026-43503"

    strings:
        $name1 = "dirtyclone" ascii nocase
        $name2 = "CVE-2026-43503" ascii
        $name3 = "DirtyClone" ascii

        $py_import1 = "import ctypes" ascii
        $py_import2 = "import os" ascii
        $py_import3 = "import subprocess" ascii

        $py_cmd1 = "unshare" ascii
        $py_cmd2 = "xfrm" ascii
        $py_cmd3 = "iptables" ascii
        $py_cmd4 = "/usr/bin/su" ascii
        $py_cmd5 = "/bin/su" ascii

    condition:
        filesize < 1MB and
        any of ($name*) and
        any of ($py_import*) and
        2 of ($py_cmd*)
}
```

### Snort/Suricata Rules

**Not applicable.** Both CVE-2026-46331 and CVE-2026-43503 are local privilege escalation vulnerabilities exploited through kernel interfaces (tc subsystem, netfilter, XFRM/IPsec). All network traffic involved in the DirtyClone exploit occurs on the loopback interface within a user namespace and never traverses monitored network segments. Network IDS rules would not provide detection value.

### Detection Rule Summary

<!-- revision: 2026-06-27-R1 -- updated confidence for rules 1 (Medium, unchanged), 3 (Low, downgraded), 7 (Low, downgraded) -->
| # | Type | Title | Compile Status | Confidence |
|---|------|-------|---------------|------------|
| 1 | Sigma | act_pedit Kernel Module Load | PASS (Splunk + LogScale) | Medium |
| 2 | Sigma | pedit COW Exploit Process Chain | PASS (Splunk + LogScale) | High |
| 3 | Sigma | Unprivileged User Namespace Creation | PASS (Splunk + LogScale) | Low |
| 4 | Sigma | DirtyClone IPsec Loopback Tunnel | PASS (Splunk + LogScale) | High |
| 5 | Sigma | vmsplice/splice from Exploit Binaries | PASS (Splunk + LogScale) | High |
| 6 | Sigma | Suspicious tc pedit Configuration | PASS (Splunk + LogScale) | Medium |
| 7 | Sigma | Setuid Binary Spawning Root Shell | PASS (Splunk + LogScale) | Low |
| 8 | YARA | packet_edit_meme ELF Detection | PASS (yarac) | High |
| 9 | YARA | DirtyClone Exploit Binary/Script | PASS (yarac) | High |
| 10 | YARA | Page-Cache Poisoning Shellcode (Generic) | PASS (yarac) | Medium |
| 11 | YARA | DirtyClone Python PoC | PASS (yarac) | High |

## Remediation

### Immediate Actions

1. **Patch kernels** to v7.1-rc7 or later (fixes both CVEs), or apply distribution-specific backported patches
2. **Check distribution advisories**:
   - Red Hat: RHSB-2026-008, Bugzilla #2480902
   - Ubuntu: USN-8373-1
   - Debian: Security tracker entries for both CVEs
   - SUSE: Published security advisories

### Workarounds (if patching is not immediately possible)

**Disable unprivileged user namespaces** (blocks both exploits):
```bash
# RHEL / CentOS
sysctl -w user.max_user_namespaces=0

# Debian / Ubuntu
sysctl -w kernel.unprivileged_userns_clone=0
```

**Block act_pedit module loading** (CVE-2026-46331 only):
```bash
echo 'install act_pedit /bin/true' | sudo tee /etc/modprobe.d/disable-act_pedit.conf
```

**Blacklist IPsec modules** (CVE-2026-43503 only; breaks IPsec and AFS):
```bash
echo -e 'blacklist esp4\nblacklist esp6\nblacklist rxrpc' | \
    sudo tee /etc/modprobe.d/disable-dirtyclone-modules.conf
```

**Flush page cache** (emergency evidence removal / tamper recovery):
```bash
echo 3 > /proc/sys/vm/drop_caches
```

### Verification Commands

```bash
# Check if act_pedit module is loaded
lsmod | grep -w act_pedit

# Check unprivileged user namespace status (RHEL)
sysctl user.max_user_namespaces

# Check unprivileged user namespace status (Debian/Ubuntu)
sysctl kernel.unprivileged_userns_clone

# Check for active pedit tc rules
tc actions list action pedit

# Verify kernel version is patched
uname -r
```

### Long-Term Recommendations

- Monitor for additional DirtyFrag family variants; five have emerged in six weeks and more are likely given the systematic nature of the `SKBFL_SHARED_FRAG` flag handling errors across the kernel networking stack
- Evaluate restricting unprivileged user namespaces permanently on systems that do not require them
- Consider Ubuntu 24.04+ AppArmor namespace restrictions as a defense-in-depth measure, though note the `aa-exec` bypass documented in the pedit COW exploit

## Sources

- [New Linux pedit COW Exploit Enables Root Access by Poisoning Cached Binaries - The Hacker News](https://thehackernews.com/2026/06/new-linux-pedit-cow-exploit-enables.html)
- [New DirtyClone Linux Kernel Flaw Lets Local Users Gain Root via Cloned Packets - The Hacker News](https://thehackernews.com/2026/06/new-dirtyclone-linux-kernel-flaw-lets.html)
- [DirtyClone Fourth Linux Kernel Flaw in Six Weeks Escalates to Root - Security Affairs](https://securityaffairs.com/194338/uncategorized/dirtyclone-fourth-linux-kernel-flaw-in-six-weeks-escalates-to-root.html)
- [Dissecting and Exploiting Linux LPE Variant: DirtyClone (CVE-2026-43503) - JFrog Security Research](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [pedit-cow (CVE-2026-46331): Linux tc Flaw Grants Root - TuxCare](https://tuxcare.com/blog/pedit-cow-cve/)
- [New Linux pedit COW Exploit Allows Attackers to Gain System Root Access - Cybersecurity News](https://cybersecuritynews.com/linux-pedit-cow-exploit/)
- [New DirtyClone Linux Vulnerability Allows Attackers to Gain Root Access Via Cloned Packets - Cybersecurity News](https://cybersecuritynews.com/dirtyclone-linux-vulnerability/)
- [CVE-2026-46331 - Ubuntu Security](https://ubuntu.com/security/CVE-2026-46331)
- [packet_edit_meme PoC Repository - GitHub (sgkdev)](https://github.com/sgkdev/packet_edit_meme)
- [CVE-2026-43503-DirtyClone PoC Repository - GitHub (aexdyhaxor)](https://github.com/aexdyhaxor/CVE-2026-43503-DirtyClone)

---
*Generated by Actioner -- 2026-06-27*
*Revised: 2026-06-27-R1 -- critic review applied (4 Sigma rules fixed, 2 MITRE mappings corrected)*
