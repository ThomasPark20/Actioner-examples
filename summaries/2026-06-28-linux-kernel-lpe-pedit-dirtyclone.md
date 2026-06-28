# Technical Analysis Report: Linux Kernel LPE Wave — pedit COW (CVE-2026-46331) & DirtyClone (CVE-2026-43503) (2026-06-28)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-28
Version: 1.0 (DRAFT)

## Executive Summary

Two new Linux kernel local privilege escalation vulnerabilities with published proof-of-concept exploits enable unprivileged local users to gain root access by corrupting shared page-cache memory. Both exploit the same fundamental design gap: kernel fast paths writing into pages they do not exclusively own.

**CVE-2026-46331 ("pedit COW")** is an out-of-bounds write in the traffic-control packet-editing action (`act_pedit`). The vulnerable function `tcf_pedit_act()` validates the writable copy-on-write range before runtime offsets resolve, allowing writes to land on shared page-cache pages. The published PoC poisons the cached ELF image of `/bin/su`, injecting shellcode to produce a root shell while on-disk integrity checks remain clean. The exploit requires `CAP_NET_ADMIN` obtained via unprivileged user namespaces (default on RHEL, Debian, Fedora). Affected kernels span versions 5.18 through 7.1-rc7. The PoC appeared within one day of CVE assignment on June 16, 2026.

**CVE-2026-43503 ("DirtyClone")** (CVSS 8.8) corrupts file-backed memory through cloned network packets processed by IPsec. The function `__pskb_copy_fclone()` drops the `SKBFL_SHARED_FRAG` safety flag during packet cloning, allowing IPsec in-place decryption to overwrite page-cache-backed buffer data. The exploit uses `vmsplice`/`splice` to wire `/usr/bin/su` pages into a network packet, then triggers cloning via the netfilter `TEE` target and ESP decryption with attacker-controlled AES-CBC parameters to overwrite the binary's authentication logic. The attack leaves no audit trail, no kernel logs, and no on-disk modifications. DirtyClone is the fourth vulnerability in the "DirtyFrag" family disclosed in six weeks. The fix was merged May 21, 2026 (mainline commit `48f6a5356a33`), shipping in Linux v7.1-rc5.

Both vulnerabilities are actively being discussed in the security community. No confirmed in-the-wild exploitation has been reported, but weaponized PoCs are publicly available for both.

## Background: Linux Page Cache and Copy-on-Write

The Linux kernel page cache serves as a shared memory store for file-backed data. When a process reads a file, the kernel maps pages from this cache into the process's address space. The Copy-on-Write (COW) discipline requires that any modification to a shared page first creates a private copy, ensuring the original cached data remains unmodified.

Both CVE-2026-46331 and CVE-2026-43503 belong to a class of vulnerabilities where kernel code paths violate this COW discipline, writing directly to shared page-cache pages. This class includes the earlier Dirty Pipe (CVE-2022-0847), Copy Fail (CVE-2026-31431), DirtyFrag (CVE-2026-43284/CVE-2026-43500), and Fragnesia (CVE-2026-46300). The shared trait is that a kernel fast path writes into a page it does not exclusively own, enabling attackers to corrupt in-memory copies of files (particularly setuid binaries) without modifying the on-disk originals.

A key prerequisite for both exploits is `CAP_NET_ADMIN`, which on modern distributions (RHEL, Debian, Ubuntu, Fedora) is available to unprivileged users through user namespaces enabled by default.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Late May 2026 | pedit COW fix discussed on netdev mailing list as a data-corruption fix (no CVE, no security framing) |
| 2026-05-16 | Broader multi-site DirtyFrag patch submitted covering fragment-transfer helpers |
| 2026-05-19 | JFrog independently rediscovers DirtyClone's affected function, builds working exploit |
| 2026-05-21 | DirtyClone combined fix merged into mainline (commit 48f6a5356a33) |
| 2026-05-23 | CVE-2026-43503 assigned for DirtyClone |
| 2026-05-24 | Linux v7.1-rc5 ships as first fixed version for DirtyClone |
| 2026-06-04 | pedit COW kernel commit merged |
| 2026-06-16 | CVE-2026-46331 assigned by kernel.org CNA; pedit COW upstream patch merged |
| 2026-06-17 | Weaponized pedit COW PoC (packet_edit_meme) published on GitHub |
| Late June 2026 | JFrog publishes full DirtyClone technical writeup and exploit walkthrough |

## Root Cause: CVE-2026-46331 (pedit COW)

The vulnerability resides in `tcf_pedit_act()` within the `act_pedit` module of the traffic-control (tc) subsystem. The function calls `skb_ensure_writable()` to compute a safe COW range, but this validation occurs before typed packet-editing keys resolve their final offsets at runtime. When the resolved offsets exceed the pre-validated range, the write lands outside the privately copied region and hits a shared page-cache page directly.

The exploit acquires `CAP_NET_ADMIN` via a user namespace (`unshare -Urn`), configures tc pedit rules that trigger the OOB write, and targets the in-memory cached copy of `/bin/su`. The corrupted binary is then executed to obtain a root shell. File-integrity tools report no changes because the on-disk file is never modified.

## Root Cause: CVE-2026-43503 (DirtyClone)

The vulnerability exists in `__pskb_copy_fclone()` and related fragment-transfer helpers (`skb_shift()`, `skb_segment()`, `skb_gro_receive()`, `skb_gro_receive_list()`, `tcp_clone_payload()`). These functions drop the `SKBFL_SHARED_FRAG` safety flag when cloning socket buffers that reference shared page-cache memory. This flag normally signals that cryptographic transformations (IPsec ESP decryption) must not modify the buffer data in place.

The exploit chain:
1. Opens `/usr/bin/su` read-only and `mmap()`s it with `MAP_SHARED` to bring pages into the page cache
2. Uses `vmsplice()` to inject page-cache pages into a pipe, then `splice()` to transfer them into a UDP socket
3. Enters a user namespace (`unshare -Urn`) and configures a loopback IPsec tunnel with attacker-controlled AES-CBC parameters (`ip xfrm state add ... proto esp ... enc 'cbc(aes)' ... auth 'hmac(sha1)' ...`)
4. Configures a netfilter TEE rule (`iptables -t mangle -A OUTPUT -p udp --dport 4500 -j TEE --gateway 10.99.0.2`) to duplicate packets
5. The TEE target calls `nf_dup_ipv4()` which invokes `__pskb_copy_fclone()` — dropping the shared-frag flag
6. The unflagged clone proceeds through `esp_input()` for IPsec decryption, which overwrites page-cache data in place
7. Since the attacker controls the AES-CBC key, IV, and packet layout, they can compute the exact ciphertext/IV needed to produce chosen plaintext bytes at target offsets in `/usr/bin/su`
8. The next invocation of `su` loads the corrupted in-memory copy and grants root

## Technical Analysis of the Malicious Payload

### 1. pedit COW — Page Cache Poisoning via Traffic Control

The pedit COW exploit (`packet_edit_meme`) operates as a single compiled C binary with the following components:
- `packet_edit_meme.c` — main exploit logic
- `pedit_primitive.c` / `pedit_primitive.h` — core COW primitive
- `test_cve.c` — testing harness

The exploit supports multiple distribution targets:
- **RHEL 10.0** (kernel 6.12.0-228.el10) — falls back to `matchall` classifier since RHEL lacks `cls_basic`/`em_meta` modules
- **Debian 13 trixie** (kernel 6.12.90+deb13.1)
- **Ubuntu 24.04.4** (kernel 6.17.0-22) — uses `--ubuntu` flag for AppArmor bypass

**Ubuntu AppArmor Bypass:** On Ubuntu, the exploit re-executes via `aa-exec` using permissive AppArmor profiles (`trinity`, `chrome`, `flatpak`) that carry `userns,` rules, bypassing `kernel.apparmor_restrict_unprivileged_userns` restrictions. This bypass works on Ubuntu 24.04.4 but fails on 26.04.

### 2. DirtyClone — Page Cache Corruption via IPsec Packet Cloning

The DirtyClone exploit (developed by JFrog Security Research) operates through a seven-stage attack chain:

**Stage 1 (Binary Mapping):**
```c
int fd = open("/usr/bin/su", O_RDONLY);
char *p = mmap(NULL, mmap_size, PROT_READ, MAP_SHARED, fd, 0);
```

**Stage 2 (Packet Wiring via vmsplice/splice):**
```c
struct iovec iov = { .iov_base = p + patch_offset, .iov_len = 16 };
vmsplice(pipefd[1], &iov, 1, 0);
splice(pipefd[0], NULL, sockfd, NULL, 16, 0);
```

**Stage 3 (IPsec Namespace Setup):**
```
unshare -Urn
ip link set lo up
ip addr add 10.99.0.2/24 dev lo
ip xfrm state add src 127.0.0.1 dst 127.0.0.1 proto esp spi 0x12345678 \
    reqid 1 mode transport enc 'cbc(aes)' ... auth 'hmac(sha1)' ...
ip xfrm policy add src 127.0.0.1 dst 127.0.0.1 dir out \
    tmpl src 127.0.0.1 dst 127.0.0.1 proto esp reqid 1 mode transport
```

**Stage 4 (TEE Duplication Trigger):**
```
iptables -t mangle -A OUTPUT -p udp --dport 4500 -j TEE --gateway 10.99.0.2
```

**Stages 5-7 (Cryptographic Corruption):** The attacker controls AES-CBC key, per-packet IV, and packet layout: `P[i] = AES_decrypt(C[i]) XOR C[i-1]`. This allows computation of exact ciphertext/IV values needed to produce chosen plaintext at the target binary's authentication-check offsets.

### 3. Anti-Forensics / Evasion Techniques

Both exploits share critical evasion characteristics:
- **No on-disk modification:** Page-cache corruption only affects the in-memory copy; the file on disk is never written
- **File-integrity bypass:** Tools like AIDE, Tripwire, and `debsums` report clean checksums since the on-disk file is unchanged
- **No audit trail (DirtyClone):** The exploit explicitly leaves no kernel logs or audit traces
- **Namespace isolation:** Exploit operations (tc rules, IPsec tunnels) occur in ephemeral user/network namespaces that are destroyed after exploitation
- **Cache eviction defense:** `echo 3 > /proc/sys/vm/drop_caches` clears poisoned pages but does not remediate already-opened root shells

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation where applicable.

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| packet_edit_meme | N/A (PoC exploit) | pedit COW exploit binary targeting CVE-2026-46331 |
| act_pedit (kernel module) | 5.18 — 7.1-rc7 | Vulnerable kernel module in traffic-control subsystem |
| esp4, esp6 (kernel modules) | Pre-7.1-rc5 | IPsec modules used by DirtyClone exploit chain |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | /bin/su | N/A (in-memory target) | Target setuid binary corrupted in page cache by pedit COW |
| Linux | /usr/bin/su | N/A (in-memory target) | Target setuid binary corrupted in page cache by DirtyClone |
| Linux | /etc/modprobe.d/disable-act_pedit.conf | N/A (mitigation) | Mitigation file to block act_pedit module loading |

### Network

No external network indicators. Both exploits operate entirely locally via loopback interfaces within user namespaces.

### Behavioral

**pedit COW (CVE-2026-46331):**
- `unshare` invocation with user + network namespace flags (`-Urn` or equivalent permutations)
- `tc` commands configuring `pedit` actions with `munge` parameters
- `aa-exec` invocations using permissive profiles (`trinity`, `chrome`, `flatpak`) on Ubuntu systems
- Execution of the `packet_edit_meme` binary
- Loading of the `act_pedit` kernel module from within a user namespace

**DirtyClone (CVE-2026-43503):**
- `unshare -Urn` creating user + network namespaces for `CAP_NET_ADMIN` acquisition
- `ip xfrm state add` and `ip xfrm policy add` configuring loopback IPsec with ESP
- `iptables -t mangle ... -j TEE` configuring packet duplication via TEE target
- `vmsplice()` and `splice()` syscalls targeting file-backed memory of setuid binaries
- Loading of `esp4`/`esp6` kernel modules from within a user namespace

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | Both CVEs exploit kernel vulnerabilities to escalate from unprivileged user to root |
| T1548 | Abuse Elevation Control Mechanism | pedit COW bypasses Ubuntu AppArmor user namespace restrictions via aa-exec with permissive profiles |
| T1014 | Rootkit (Defense Evasion) | Page-cache-only corruption leaves no on-disk traces; bypasses file-integrity monitoring |
| T1059.004 | Unix Shell | Exploit payloads spawn root shells after corrupting setuid binaries |

## Impact Assessment

**Breadth:** All major Linux distributions with unprivileged user namespaces enabled by default are affected. This includes RHEL 8-10, Debian 11-13, Ubuntu 18.04-26.04, Fedora, SUSE, and Amazon Linux. Multi-tenant servers, CI runners, container hosts, and Kubernetes clusters with untrusted user namespace creation are particularly at risk.

**Depth:** Full root-level privilege escalation from any unprivileged local user. DirtyClone additionally leaves no audit trail, making post-exploitation forensics extremely difficult.

**Stealth:** Both exploits operate entirely through the page cache without modifying on-disk files. DirtyClone is specifically described as "silent" with no kernel logs or audit traces. Standard file-integrity monitoring tools are ineffective.

**Exposure Window (pedit COW):** The upstream patch was discussed publicly as a data-corruption fix with no CVE and no security framing. The CVE was assigned weeks after exploitable details were public, and a weaponized PoC appeared within one day.

**Exposure Window (DirtyClone):** DirtyClone is the fourth variant in the DirtyFrag family. Partial patching of earlier variants (Copy Fail, DirtyFrag, Fragnesia) left exploitable gaps in the remaining code paths.

## Detection & Remediation

### Immediate Detection

**Check if vulnerable modules are loaded:**
```bash
lsmod | grep act_pedit
lsmod | grep -E 'esp4|esp6'
```

**Check if tc pedit rules exist:**
```bash
tc actions list action pedit
```

**Check user namespace configuration:**
```bash
sysctl kernel.unprivileged_userns_clone 2>/dev/null
sysctl user.max_user_namespaces
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
```

**Check kernel version:**
```bash
uname -r
# pedit COW: vulnerable 5.18 through 7.1-rc7
# DirtyClone: fixed in 7.1-rc5 (commit 48f6a5356a33)
```

### Remediation

1. **Update kernel** to a version containing the fixes for both CVEs. Check distribution security advisories.

2. **Block act_pedit module** (if tc pedit rules are not in use):
```bash
echo 'install act_pedit /bin/true' | sudo tee /etc/modprobe.d/disable-act_pedit.conf
```

3. **Restrict unprivileged user namespaces:**
```bash
# Debian/Ubuntu:
sudo sysctl -w kernel.unprivileged_userns_clone=0
# RHEL/Fedora:
sudo sysctl -w user.max_user_namespaces=0
```

4. **Blacklist DirtyClone attack modules** (temporary — breaks IPsec and AFS):
```bash
echo 'install esp4 /bin/true' | sudo tee /etc/modprobe.d/disable-esp.conf
echo 'install esp6 /bin/true' | sudo tee -a /etc/modprobe.d/disable-esp.conf
echo 'install rxrpc /bin/true' | sudo tee -a /etc/modprobe.d/disable-esp.conf
```

5. **Clear poisoned page cache** (temporary — does not remediate open shells):
```bash
echo 3 > /proc/sys/vm/drop_caches
```

### Long-Term Hardening

- Restrict unprivileged user namespace creation as a default security posture. Ubuntu 24.04+ enforces this via AppArmor, though bypass vectors exist (pedit COW PoC demonstrates this via `aa-exec` with permissive profiles).
- Audit and remove permissive AppArmor profiles (`trinity`, `chrome`, `flatpak`) that allow `userns,` rules unless explicitly needed.
- Monitor kernel module loading events for `act_pedit`, `esp4`, `esp6` from within user namespaces.
- Consider deploying runtime security tools (Falco, Tracee) that monitor syscall patterns rather than relying solely on file-integrity monitoring, which is blind to page-cache-only attacks.

## Detection Rules

These detections target the specific PoC artifacts and exploit command patterns of CVE-2026-46331 (pedit COW) and CVE-2026-43503 (DirtyClone). All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; `sigma check` failed only due to a transient MITRE ATT&CK STIX data download error, not a rule syntax issue. Compiles do not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: TC Pedit Action Configuration via User Namespace

Detects `tc` pedit munge commands characteristic of CVE-2026-46331 exploitation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (transient MITRE STIX download IncompleteRead — not a rule syntax issue); splunk convert exit 0; log_scale convert exit 0. Keys on distinctive 'tc ... pedit ... munge' command-line pattern from the published PoC. FP risk: legitimate tc pedit configurations exist but are rare outside network-engineering contexts. -->
```yaml
title: Pedit COW Exploit - TC Pedit Action Configuration via User Namespace
id: 8a3c1e7f-4b2d-4f9a-b6e1-c2d5f8a0e3b7
status: experimental
description: >
    Detects tc (traffic control) pedit action configuration commands indicative of
    CVE-2026-46331 exploitation. The exploit uses tc pedit actions from within a
    user namespace to corrupt page-cache memory of setuid binaries like /bin/su.
references:
    - https://thehackernews.com/2026/06/new-linux-pedit-cow-exploit-enables.html
    - https://github.com/sgkdev/packet_edit_meme
    - https://www.scworld.com/news/2-linux-kernel-flaw-pocs-published-enabling-local-privilege-escalation
author: Actioner
date: 2026/06/28
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: linux
detection:
    selection_tc:
        Image|endswith: '/tc'
        CommandLine|contains|all:
            - 'pedit'
            - 'munge'
    condition: selection_tc
falsepositives:
    - Legitimate network traffic shaping with tc pedit rules
level: high
```

### Sigma: Unshare with User and Network Namespace for Privilege Escalation

Detects `unshare` creating combined user + network namespaces, the prerequisite for both exploits to obtain `CAP_NET_ADMIN`.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (transient MITRE STIX download — not syntax); splunk convert exit 0; log_scale convert exit 0. Covers all permutations of -U -n -r flags. Medium confidence: unshare with these flags is also used by container runtimes and dev environments, so environment-specific tuning may be needed. -->
```yaml
title: Pedit COW / DirtyClone - Unshare with User and Network Namespace
id: 2f6b9d4e-8c1a-4e3f-a7d5-b9c0e2f1a4d6
status: experimental
description: >
    Detects unshare invocations creating user and network namespaces, a prerequisite
    for both CVE-2026-46331 (pedit COW) and CVE-2026-43503 (DirtyClone) exploits
    which require CAP_NET_ADMIN obtained via unprivileged user namespaces.
references:
    - https://thehackernews.com/2026/06/new-linux-pedit-cow-exploit-enables.html
    - https://thehackernews.com/2026/06/new-dirtyclone-linux-kernel-flaw-lets.html
    - https://github.com/sgkdev/packet_edit_meme
author: Actioner
date: 2026/06/28
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/unshare'
        CommandLine|contains:
            - '-Urn'
            - '-Unr'
            - '-rUn'
            - '-rnU'
            - '-nUr'
            - '-nrU'
    condition: selection
falsepositives:
    - Container runtimes creating namespaces
    - Development and testing environments
level: medium
```

### Sigma: IPsec XFRM State and Policy Configuration

Detects `ip xfrm` state/policy configuration commands used in the DirtyClone exploit's loopback IPsec tunnel setup.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (transient MITRE STIX download — not syntax); splunk convert exit 0; log_scale convert exit 0. Condition uses OR to catch either state or policy creation. Medium confidence: legitimate IPsec VPN configurations produce the same commands, so this should be correlated with unshare namespace events. -->
```yaml
title: DirtyClone Exploit - IPsec XFRM State and Policy Configuration
id: 5d8e2a1b-3c7f-4a9e-b0d6-e4f3c1a2b5d8
status: experimental
description: >
    Detects ip xfrm state and policy configuration commands characteristic of
    CVE-2026-43503 (DirtyClone) exploitation. The exploit configures loopback
    IPsec tunnels with ESP encryption to trigger in-place decryption of
    page-cache-backed network packet data.
references:
    - https://thehackernews.com/2026/06/new-dirtyclone-linux-kernel-flaw-lets.html
    - https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/
    - https://www.scworld.com/news/2-linux-kernel-flaw-pocs-published-enabling-local-privilege-escalation
author: Actioner
date: 2026/06/28
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: linux
detection:
    selection_xfrm_state:
        Image|endswith: '/ip'
        CommandLine|contains|all:
            - 'xfrm'
            - 'state'
            - 'add'
            - 'esp'
    selection_xfrm_policy:
        Image|endswith: '/ip'
        CommandLine|contains|all:
            - 'xfrm'
            - 'policy'
            - 'add'
    condition: selection_xfrm_state or selection_xfrm_policy
falsepositives:
    - Legitimate IPsec VPN configuration
level: medium
```

### Sigma: Iptables TEE Target on Mangle Table

Detects iptables rules using the TEE target on the mangle table, a specific step in the DirtyClone exploit chain that triggers the vulnerable `__pskb_copy_fclone()` packet cloning.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (transient MITRE STIX download — not syntax); splunk convert exit 0; log_scale convert exit 0. The combination of mangle table + TEE target is distinctive and rare in normal operations. -->
```yaml
title: DirtyClone Exploit - Iptables TEE Target on Mangle Table
id: 7c4f3b2a-9d6e-4a1f-b8c5-d3e2a0f1b7c9
status: experimental
description: >
    Detects iptables rules using the TEE target on the mangle table, a specific
    step in CVE-2026-43503 (DirtyClone) exploitation. The exploit uses TEE to
    duplicate UDP packets destined for port 4500, triggering packet cloning via
    __pskb_copy_fclone() which drops the SKBFL_SHARED_FRAG safety flag.
references:
    - https://thehackernews.com/2026/06/new-dirtyclone-linux-kernel-flaw-lets.html
    - https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/
author: Actioner
date: 2026/06/28
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/iptables'
            - '/ip6tables'
        CommandLine|contains|all:
            - 'mangle'
            - 'TEE'
    condition: selection
falsepositives:
    - Network mirroring configurations using TEE target
level: high
```

### Sigma: AppArmor Bypass via aa-exec with Permissive Profiles

Detects `aa-exec` invocations using permissive AppArmor profiles (`trinity`, `chrome`, `flatpak`) to bypass user namespace restrictions, as used in the pedit COW exploit's Ubuntu mode.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (transient MITRE STIX download — not syntax); splunk convert exit 0; log_scale convert exit 0. Distinctive artifact from the published PoC's --ubuntu bypass. FP risk low: aa-exec with these specific profiles is abnormal outside exploit/testing contexts. -->
```yaml
title: Pedit COW Exploit - AppArmor Bypass via aa-exec
id: 3e1d9c8b-5a2f-4b7e-c6d0-f4a3b2e1c0d5
status: experimental
description: >
    Detects the use of aa-exec with permissive profiles (trinity, chrome, flatpak)
    to bypass AppArmor restrictions on unprivileged user namespaces, as used in the
    CVE-2026-46331 (pedit COW) exploit's Ubuntu bypass mode.
references:
    - https://thehackernews.com/2026/06/new-linux-pedit-cow-exploit-enables.html
    - https://github.com/sgkdev/packet_edit_meme
author: Actioner
date: 2026/06/28
tags:
    - attack.t1068
    - attack.t1548
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/aa-exec'
        CommandLine|contains:
            - 'trinity'
            - 'chrome'
            - 'flatpak'
    condition: selection
falsepositives:
    - Legitimate AppArmor profile testing
level: high
```

### YARA: Pedit COW PoC Binary (packet_edit_meme)

Detects compiled pedit COW exploit binaries by matching the PoC's distinctive string artifacts (`packet_edit_meme`, `pedit_primitive`, `act_pedit`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Keys on published PoC strings from github.com/sgkdev/packet_edit_meme. Condition requires ELF header + anchor string + 2 supporting strings. -->
```yara
rule Exploit_CVE_2026_46331_PeditCOW_POC
{
    meta:
        description = "Detects the pedit COW exploit PoC (packet_edit_meme) for CVE-2026-46331 targeting Linux kernel tc pedit page-cache corruption"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://github.com/sgkdev/packet_edit_meme"
        severity = "critical"

    strings:
        $s1 = "packet_edit_meme" ascii fullword
        $s2 = "pedit_primitive" ascii fullword
        $s3 = "/bin/su" ascii
        $s4 = "act_pedit" ascii
        $s5 = "--ubuntu" ascii
        $s6 = "aa-exec" ascii
        $s7 = "CAP_NET_ADMIN" ascii
        $s8 = "page cache" ascii nocase
        $s9 = "tcf_pedit_act" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        ($s1 or $s2) and
        2 of ($s3, $s4, $s5, $s6, $s7, $s8, $s9)
}
```

### YARA: DirtyClone PoC Binary

Detects compiled DirtyClone exploit binaries by matching distinctive string artifacts from the JFrog PoC (`DirtyClone`, `SKBFL_SHARED_FRAG`, `__pskb_copy_fclone`).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. Keys on JFrog-published PoC strings. Medium confidence: condition uses 3-of-10 which may match unrelated kernel analysis tools containing the same function names. Narrow via ELF + filesize constraint. -->
```yara
rule Exploit_CVE_2026_43503_DirtyClone_POC
{
    meta:
        description = "Detects the DirtyClone exploit PoC for CVE-2026-43503 targeting Linux kernel skb clone page-cache corruption via IPsec"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/"
        severity = "critical"

    strings:
        $s1 = "DirtyClone" ascii nocase
        $s2 = "dirtyclone" ascii
        $s3 = "SKBFL_SHARED_FRAG" ascii
        $s4 = "__pskb_copy_fclone" ascii
        $s5 = "vmsplice" ascii
        $s6 = "ip xfrm" ascii
        $s7 = "/usr/bin/su" ascii
        $s8 = "page cache" ascii nocase
        $s9 = "esp_input" ascii
        $s10 = "cbc(aes)" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        3 of them
}
```

### Snort: N/A

No external network indicators suitable for Snort detection. Both exploits operate entirely on the local system via loopback interfaces within user namespaces.

### Suricata: N/A

No external network indicators suitable for Suricata detection. Both exploits operate entirely on the local system via loopback interfaces within user namespaces.

## Lessons Learned

1. **Page-cache COW violations are a systemic class, not isolated bugs.** Four variants in six weeks (Copy Fail, DirtyFrag, Fragnesia, DirtyClone) plus pedit COW from a separate subsystem demonstrate that the "shared page not exclusively owned" pattern is widely scattered across the kernel's networking stack. Partial patches leave exploitable gaps in adjacent code paths.

2. **Unprivileged user namespaces remain the key enabler.** Both exploits require `CAP_NET_ADMIN`, obtainable by any local user via `unshare -Urn` on default configurations of most distributions. Restricting unprivileged user namespace creation (`kernel.unprivileged_userns_clone=0` or `user.max_user_namespaces=0`) is the single most effective mitigation — but breaks legitimate container and sandbox workflows. Ubuntu's AppArmor-based restriction was bypassed by the pedit COW PoC via `aa-exec` with permissive profiles.

3. **File-integrity monitoring is blind to page-cache attacks.** These exploits corrupt only the in-memory representation of files without touching the on-disk originals. Organizations relying solely on AIDE, Tripwire, or similar tools for integrity assurance have a critical detection gap. Runtime security tools monitoring syscall behavior (Falco, Tracee, auditd with syscall rules) offer better coverage for this attack class.

4. **Security-critical patches need security framing.** The pedit COW fix was initially discussed as a "data-corruption fix" with no CVE and no security advisory. The CVE was assigned weeks after exploitable details were public, and a weaponized PoC appeared the next day. Delayed security classification extends the exposure window.

## Sources

- [The Hacker News — New Linux pedit COW Exploit Enables Root Access by Poisoning Cached Binaries](https://thehackernews.com/2026/06/new-linux-pedit-cow-exploit-enables.html) — Primary source on CVE-2026-46331 technical details and timeline
- [The Hacker News — New DirtyClone Linux Kernel Flaw Lets Local Users Gain Root Access](https://thehackernews.com/2026/06/new-dirtyclone-linux-kernel-flaw-lets.html) — Primary source on CVE-2026-43503 technical details
- [Security Affairs — DirtyClone Fourth Linux Kernel Flaw in Six Weeks](https://securityaffairs.com/194338/uncategorized/dirtyclone-fourth-linux-kernel-flaw-in-six-weeks-escalates-to-root.html) — DirtyFrag family context and DirtyClone timeline
- [SC World — 2 Linux Kernel Flaw PoCs Published](https://www.scworld.com/news/2-linux-kernel-flaw-pocs-published-enabling-local-privilege-escalation) — Combined coverage of both CVEs with exploit mechanism details
- [JFrog Security Research — Dissecting and Exploiting Linux LPE Variant: DirtyClone](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/) — Full technical writeup of the DirtyClone exploit by the discoverers
- [GitHub — sgkdev/packet_edit_meme](https://github.com/sgkdev/packet_edit_meme) — Published pedit COW proof-of-concept exploit repository
- [The CyberSec Guru — Two New Linux LPEs Hit Page Cache From Opposite Ends](https://thecybersecguru.com/news/linux-lpe-pedit-cow-dirtyclone-cve-2026-46331-cve-2026-43503/) — Technical details of both exploits with command examples

---
*Report generated by Actioner*
