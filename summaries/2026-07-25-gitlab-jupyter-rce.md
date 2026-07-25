# Technical Analysis Report: GitLab RCE via Oj JSON Parser Memory Corruption (2026-07-25)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-25
Version: 1.0 (DRAFT)

## Executive Summary

On July 24, 2026, security research firm depthfirst published a working proof-of-concept exploit achieving Remote Code Execution (RCE) against GitLab CE/EE by chaining two memory corruption vulnerabilities (CVE-2026-54592, CVE-2026-54500) in the Oj Ruby JSON parsing gem. The exploit targets GitLab's Jupyter notebook diff rendering pipeline: an authenticated user pushes crafted `.ipynb` files to a repository and requests their commit diffs, triggering the vulnerable `ipynbdiff` gem to parse attacker-controlled JSON through Oj's C extension. The first bug (a nesting stack buffer overflow) corrupts the parser's callback function pointer; the second bug (a signed integer truncation causing heap pointer disclosure) defeats ASLR. Together, they redirect code execution to `system()`, running arbitrary commands as the `git` user with access to all repository data, Rails secrets, and CI/CD credentials. GitLab patched the underlying Oj dependency in the June 10, 2026 patch releases (18.10.8, 18.11.5, 19.0.2), but classified the fix as a bug fix rather than a security release -- no CVE was assigned to the GitLab-level chain, and no CVSS score was published for the full exploit. Affected versions span GitLab CE/EE 15.2.0 through 19.0.1. No in-the-wild exploitation has been reported as of publication date.

## Background: GitLab Jupyter Notebook Diff Rendering

GitLab supports rendering diffs for Jupyter notebook files (`.ipynb`) through the `ipynbdiff` Ruby gem. When a user views a commit diff or merge request diff involving a notebook file, the `ipynbdiff` gem parses the notebook's JSON structure using `Oj::Parser.usual.parse()`. This parsing occurs within the Puma web server worker process, running as the `git` system user. The Oj (Optimized JSON) gem is a high-performance JSON parser for Ruby implemented as a C extension, making it susceptible to memory safety issues that pure Ruby code would not exhibit.

The call chain from diff request to vulnerable parser:

```
HTTP request to /diffs_stream or /commit/:sha/diffs
  -> Gitlab::Diff::Rendered::Notebook::DiffFile#notebook_diff
    -> IpynbDiff.diff()
      -> Transformer#validate_notebook()
        -> Oj::Parser.usual.parse(notebook_json)
```

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-21 | depthfirst reports two memory corruption bugs to Oj gem maintainer |
| 2026-05-27 | Oj maintainer merges fixes |
| 2026-06-04 | Oj 3.17.3 released with fixes for CVE-2026-54592 and CVE-2026-54500 |
| 2026-06-05 | depthfirst reports full GitLab exploit chain to GitLab security team |
| 2026-06-08 | GitLab confirms the vulnerability |
| 2026-06-10 | GitLab releases patch versions 18.10.8, 18.11.5, 19.0.2 with Oj 3.17.3; fix listed under bug fixes, not security fixes |
| 2026-07-24 | depthfirst publishes full PoC exploit and technical writeup |

## Root Cause: Two Memory Corruption Bugs in the Oj JSON Parser (C Extension)

The exploit chains two distinct memory safety vulnerabilities in the Oj gem's C extension code:

**CVE-2026-54592 -- Stack Buffer Overflow via Unchecked Nesting Depth** (CVSS 7.5 High): The parser maintained a fixed 1,024-byte array (`where_path[MAX_STACK]`) tracking JSON collection depth. `Oj::Doc#each_child` in `ext/oj/fast.c` incremented `doc->where` past the fixed-size array without bounds checking and never decremented it, enabling out-of-bounds writes that corrupt adjacent parser state.

**CVE-2026-54500 -- Information Disclosure via Uninitialized Stack Memory Read** (CVSS 5.3 Medium): In `ext/oj/intern.c`, the `form_attr()` function handling long object keys (254+ bytes) allocated a heap buffer `b`, populated it, freed it, but then passed the *uninitialized stack buffer* `buf` (not `b`) to `rb_intern3()`. This leaked process stack memory contents through the interned Symbol value, enabling heap pointer disclosure for ASLR bypass.

## Technical Analysis of the Malicious Payload

### 1. Stage 1 -- Nesting Stack Overflow for Callback Corruption

The attacker opens 2,132 nested JSON arrays (consecutive `[` characters) in a crafted Jupyter notebook. Each nesting level writes a type selector (`0x01` for arrays) at `parser_base + 0x14 + depth`, advancing past the 1,024-byte stack array into the parser's internal `buf.head` pointer.

At depth 2,132, the low byte of `buf.head` changes from `0x80` to `0x01`, shifting the logical buffer start backward by `0x7f` bytes to an interior address (`P+0x801`). A 4,001-digit number then forces `realloc()` on this forged pointer. Jemalloc copies the interior region and caches the address in a thread-local 3,584-byte bin.

### 2. Stage 2 -- Heap Spray via Ruby Array Overlap

Closing an inner array with 446 elements triggers `rb_ary_new_from_values()`, allocating exactly 3,568 bytes from the cached jemalloc bin -- reclaiming the forged buffer region. Two adjacent Ruby `VALUE` elements (positions 176 and 177) are then used to assemble a controlled instruction pointer that overwrites the parser's `p->start` callback. Immediate Float value `-1e45` and an encoded Fixnum supply the target address bytes.

A trailing invalid character (`X`) after the deep nesting raises a parse exception. The `parser_reset()` handler clears parse state but leaves `p->start` corrupted -- the corrupted callback survives to the next parse invocation.

### 3. Stage 3 -- ASLR Bypass via Heap Pointer Leak

A separate notebook object with two 65,565-byte keys triggers the signed integer truncation bug:

1. Each oversized key allocates heap storage; the pointer is stored in the external union view at offset 8
2. Truncation of key length from 65,565 to 29 (via signed `int16_t` assignment) causes the parser to read through the inline union view instead, exposing bytes 2-30 which include the heap pointer at positions 6-13
3. The leaked pointer bytes appear in the rendered diff HTML output as part of a cell ID field
4. The attacker extracts the eight-byte pointer, reverses HTML entity escaping, and uses it to calculate library base addresses

A control-flow oracle probes candidate addresses: setting `p->start` to `libc_base + 0x8470e` (an `eb fe` infinite loop gadget) hangs the request if the guess is correct. Candidate testing takes 5-10 minutes on a fresh two-worker installation.

### 4. Stage 4 -- RCE via Gadget Chain and system()

Two notebook files named to sort lexically (`a01`, `a02`) ensure sequential processing by the same Puma worker on the `diffs_stream` endpoint:

- **a01 (corruption notebook):** Old side is benign; new side contains the array nesting overflow plus the exception trigger
- **a02 (trigger notebook):** Old side contains a binary blob encoding the gadget chain; new side is benign

Processing flow:
1. `a01.new` parses, corrupts `p->start`, raises exception
2. GitLab catches the exception and continues streaming the diff
3. `a02.old` parses next in the same worker, invoking the corrupted `p->start` callback

The gadget chain:
- `p->start` points to `libruby + 0x269b4a`: moves R12 (raw `a02.old` blob pointer) to RDI and calls offset `0x28`
- Blob offset `0x28` stores `libruby + 0x22d565` (second gadget)
- Blob offset `0x58` stores `libc + 0x58750` (address of `system()`)
- Blob offset `0x00`: the shell command string (max 39 bytes, e.g., `touch /tmp/pwned\x00`)

Commands execute as the `git` system user running the Puma worker process.

### 5. Execution Context and Impact

The `git` user on a GitLab installation has access to:
- All repository source code on the instance
- Rails application secrets (used for session signing, encryption)
- CI/CD runner tokens and service credentials
- Database connection credentials
- SSH keys for repository access

### 6. Constraints and Portability

- The PoC targets GitLab 18.11.3 on x86-64 with hardcoded offsets from that specific build image
- Jemalloc thread-local caching behavior is build-specific
- Porting to a new target version requires 1-2 hours of offset adjustment
- The leaked library base address is valid only until Puma master restarts
- Requires authenticated repository push access (any project member role with push permissions)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation where applicable.

### Package / Software Level

| Package / Component | Vulnerable Versions | Fixed Version | Description |
|---------------------|---------------------|---------------|-------------|
| Oj (Ruby gem) | 3.13.0 - 3.17.1 | 3.17.3 | Memory corruption in JSON parser C extension |
| GitLab CE/EE | 15.2.0 - 18.10.7 | 18.10.8 | Notebook diff triggers vulnerable Oj parsing |
| GitLab CE/EE | 18.11.0 - 18.11.4 | 18.11.5 | Notebook diff triggers vulnerable Oj parsing |
| GitLab CE/EE | 19.0.0 - 19.0.1 | 19.0.2 | Notebook diff triggers vulnerable Oj parsing |

### File System

| Platform | Path / Pattern | Description |
|----------|---------------|-------------|
| Linux (GitLab) | `*.ipynb` in Git repositories | Crafted Jupyter notebooks with deep nesting (2000+ levels) and oversized keys (65000+ bytes) |
| Linux (GitLab) | `/tmp/pwned` or similar | PoC default payload output file |
| Linux (GitLab) | Core dumps from Puma/Ruby processes | Crash artifacts from ASLR probing phase |

### Behavioral

- **Rapid Puma worker crashes (SIGSEGV/SIGABRT):** The ASLR bypass phase probes candidate addresses by crashing or hanging workers, producing 5-10 minutes of repeated segfaults
- **Sequential diff requests for two notebook files:** The exploit requires processing `a01` (corruption) then `a02` (trigger) in the same worker, producing a pattern of rapid diff endpoint hits
- **Notebook files with anomalous JSON structure:** Deep nesting (2,000+ levels of `[`), keys exceeding 65,000 bytes, 446+ element arrays, and embedded binary blobs
- **Process spawning from git user via Puma:** Post-exploitation command execution produces child processes under the `git` user with `puma`/`ruby` as parent
- **GitLab application logs:** Parse exceptions in notebook diff rendering followed by successful diff completion (the exploit recovers from the first parse error)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Authenticated exploitation of GitLab's notebook diff rendering endpoint via crafted .ipynb file commits |
| T1059 | Command and Scripting Interpreter | Arbitrary command execution as the git user via system() redirection |
| T1499.004 | Application or System Exploitation (Endpoint DoS) | Puma worker crashes during ASLR bypass probing phase |
| T1003 | OS Credential Dumping | Post-exploitation access to Rails secrets, CI/CD tokens, database credentials |
| T1083 | File and Directory Discovery | Access to all repository source code on the instance |

## Impact Assessment

- **Breadth:** All GitLab CE/EE self-managed instances running versions 15.2.0 through 19.0.1 with Jupyter notebook diff rendering enabled (default configuration)
- **Depth:** Full RCE as the git user -- access to all repository data, Rails secrets, CI/CD credentials, and the ability to execute arbitrary commands
- **Stealth:** Moderate -- the ASLR probing phase produces observable Puma worker crashes over 5-10 minutes, but post-exploitation command execution leaves minimal forensic artifacts
- **Authentication requirement:** Attacker needs authenticated push access to any project on the target GitLab instance
- **No in-the-wild exploitation** reported as of July 25, 2026

## Detection & Remediation

### Immediate Detection

1. **Check GitLab version and Oj gem version:**
```bash
# Check GitLab version
cat /opt/gitlab/version-manifest.txt | head -1
gitlab-ctl status

# Check Oj gem version (must be >= 3.17.3)
/opt/gitlab/embedded/bin/gem list oj
```

2. **Search for anomalous Puma crashes:**
```bash
# Check for recent segfaults in syslog
grep -E 'puma.*segfault|ruby.*SIGSEGV|puma.*signal 11' /var/log/syslog /var/log/messages 2>/dev/null

# Check for core dumps
find /var/core /var/crash /tmp -name 'core.*' -newer /var/log/syslog -type f 2>/dev/null
```

3. **Search for suspicious notebook files in repositories:**
```bash
# Search for recently pushed .ipynb files with anomalous sizes
find /var/opt/gitlab/git-data/repositories -name '*.ipynb' -size +1M -mtime -30 2>/dev/null
```

4. **Check for unexpected processes under git user:**
```bash
ps aux | grep -E '^git' | grep -v -E 'gitlab|puma|sidekiq|gitaly'
```

### Remediation

1. **Upgrade immediately** to GitLab 18.10.8, 18.11.5, 19.0.2, or any later version
2. If upgrade is not immediately possible, **disable Jupyter notebook diff rendering** by setting the feature flag:
   ```bash
   gitlab-rails runner "Feature.disable(:ipynb_semantic_diff)"
   ```
3. **Rotate all secrets** if exploitation is suspected: Rails secret key base, CI/CD runner tokens, database passwords, SSH host keys
4. **Audit git user process history** for unauthorized command execution
5. **Review repository push logs** for recently committed `.ipynb` files with unusual sizes or from unexpected users

### Long-Term Hardening

- Enable process monitoring and alerting for the `git` user account
- Implement JSON parsing depth limits at the application or WAF layer
- Consider running Puma workers in a sandboxed environment (containers, seccomp profiles) to limit post-exploitation impact
- Monitor for Oj gem security advisories and apply updates promptly
- Restrict repository push access following the principle of least privilege

## Detection Rules

Three Sigma rules, two YARA rules, and three Suricata rules target the exploit's observable artifacts: process spawning from the git user via Puma workers, anomalous notebook diff endpoint access, Puma worker crash patterns, malicious notebook JSON structures (deep nesting, oversized keys, heap spray payloads), and network-level indicators of exploit delivery. Rules are calibrated to the specific exploit chain mechanics documented in the PoC; false positives are possible from legitimate Jupyter notebook workflows and should be tuned per environment.

### Sigma Rule 1: Suspicious Command Execution by Git User After Notebook Diff Processing

Compile: Splunk ✅ | LogScale ✅ | Confidence: high

<!-- audit: sigma check failed due to network restriction (cannot fetch MITRE ATT&CK data), not a rule syntax issue. sigma convert --without-pipeline -t splunk and -t log_scale both succeeded, confirming syntactic validity. Fields target Linux process_creation events with git user, Puma/Ruby parent, and suspicious child processes. Filter excludes known legitimate git hook and gitlab-shell operations. -->

```yaml
title: Suspicious Command Execution by Git User After GitLab Notebook Diff Processing
id: ebfbb5ba-ef5b-445d-a143-4303eb2447d8
status: experimental
description: >
    Detects suspicious command execution by the git user on a GitLab server, which may
    indicate exploitation of the Oj JSON parser memory corruption chain (CVE-2026-54592 /
    CVE-2026-54500) via malicious Jupyter notebook diffs. The exploit corrupts a parser
    callback pointer in the Puma worker process, redirecting execution to system() when
    a subsequent notebook diff is rendered. Commands run as the git user with access to
    repository data, Rails secrets, and CI/CD credentials.
references:
    - https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html
    - https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities
    - https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-0-2-released/
author: Actioner
date: 2026/07/25
tags:
    - attack.t1190
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_user:
        User: 'git'
    selection_parent:
        ParentImage|endswith:
            - '/puma'
            - '/ruby'
            - '/bundle'
    selection_commands:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/curl'
            - '/wget'
            - '/python'
            - '/python3'
            - '/perl'
            - '/nc'
            - '/ncat'
    filter_legitimate:
        CommandLine|contains:
            - 'git-hook'
            - 'gitlab-shell'
            - 'authorized_keys'
    condition: selection_user and selection_parent and selection_commands and not filter_legitimate
falsepositives:
    - GitLab custom hooks executed via git-hook mechanisms
    - GitLab maintenance scripts running under the git user via Puma workers
level: high
```

### Sigma Rule 2: GitLab Notebook Diff Endpoint Probing

Compile: Splunk ✅ | LogScale ✅ | Confidence: medium

<!-- audit: sigma convert --without-pipeline to both Splunk and LogScale succeeded. Logsource category webserver matches generic web server access logs. Rule requires both a diff-related URI stem and .ipynb extension co-occurring. Medium confidence because legitimate notebook diff activity will also match; intended as a correlation signal rather than standalone alert. -->

```yaml
title: GitLab Notebook Diff Endpoint Probing with Large Payloads
id: 484ebcb8-ac2d-484f-b125-5ee588e3f50b
status: experimental
description: >
    Detects HTTP requests to GitLab commit diff or merge request diff endpoints involving
    Jupyter notebook files (.ipynb), which is the attack surface for the Oj parser memory
    corruption RCE chain. The exploit requires pushing crafted notebooks and then requesting
    their diffs via the diffs_stream endpoint. Multiple rapid diff requests against notebook
    files in the same project may indicate heap spray and ASLR bypass attempts.
references:
    - https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html
    - https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities
author: Actioner
date: 2026/07/25
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_endpoint:
        cs-uri-stem|contains:
            - '/diffs_stream'
            - '/diffs'
            - '/commit/'
            - '/merge_requests/'
    selection_notebook:
        cs-uri-stem|contains: '.ipynb'
    condition: selection_endpoint and selection_notebook
falsepositives:
    - Legitimate code review activity involving Jupyter notebooks
    - CI/CD pipelines that programmatically access diff endpoints for notebook files
level: medium
```

### Sigma Rule 3: GitLab Puma Worker Crash During Notebook Diff Rendering

Compile: Splunk ✅ | LogScale ✅ | Confidence: medium

<!-- audit: sigma convert --without-pipeline to both Splunk and LogScale succeeded. Targets Linux syslog entries for Puma/Ruby process crashes (SIGSEGV, SIGABRT). The ASLR probing phase produces 5-10 minutes of repeated crashes, which is anomalous for production GitLab. Medium confidence due to potential overlap with legitimate OOM or gem compatibility crashes. -->

```yaml
title: GitLab Puma Worker Crash or Hang During Notebook Diff Rendering
id: d6aeaa44-cd9e-43fb-991e-15b522cb6876
status: experimental
description: >
    Detects Puma worker process crashes (SIGSEGV, SIGABRT) or abnormal termination on
    GitLab servers, which may indicate active exploitation of the Oj parser memory corruption
    vulnerabilities. The exploit chain causes controlled crashes during the ASLR bypass
    probing phase (5-10 minutes of repeated requests causing worker hangs) before achieving
    code execution. Repeated Puma worker restarts correlate with heap layout probing.
references:
    - https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html
    - https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities
author: Actioner
date: 2026/07/25
tags:
    - attack.t1190
    - attack.t1499.004
logsource:
    product: linux
    service: syslog
detection:
    selection_process:
        process.name|contains:
            - 'puma'
            - 'ruby'
    selection_signal:
        message|contains:
            - 'SIGSEGV'
            - 'SIGABRT'
            - 'segfault'
            - 'signal 11'
            - 'signal 6'
            - 'core dumped'
    condition: selection_process and selection_signal
falsepositives:
    - Puma worker crashes due to memory pressure or out-of-memory conditions
    - Ruby gem compatibility issues causing segmentation faults
    - Legitimate application bugs in custom GitLab extensions
level: medium
```

### YARA Rule 1: Malicious Jupyter Notebook for Oj RCE Exploit

Compile: ✅ `yarac` exit 0 | Confidence: high

<!-- audit: yarac compiled cleanly with no warnings after fixing regex repeat intervals and replacing slow patterns with literal string matches. Rule requires 2+ Jupyter notebook format markers AND either deep nesting (500+ brackets), long padding keys (100-char runs of A/a indicating 65000+ byte keys), or large number + command string. Tuned to avoid false positives on legitimate notebooks which would not contain 500+ consecutive brackets or 100-char homogeneous key padding. -->

```yara
rule Exploit_GitLab_Malicious_Jupyter_Notebook_Oj_RCE
{
    meta:
        description = "Detects malicious Jupyter notebook (.ipynb) files crafted to exploit CVE-2026-54592 and CVE-2026-54500 in the Oj JSON parser via GitLab notebook diff rendering. The exploit uses deeply nested JSON arrays (2000+ levels) to overflow the parser nesting stack, and oversized object keys (65000+ bytes) to trigger signed integer truncation for heap pointer disclosure."
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities"
        severity = "high"

    strings:
        $nb_cells = "\"cells\"" ascii
        $nb_meta = "\"metadata\"" ascii
        $nb_nbformat = "\"nbformat\"" ascii

        $deep_nest_array = /\[{500,}/ ascii
        $deep_nest_object = /\{{500,}/ ascii

        $long_key_a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
        $long_key_b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ascii

        $large_number = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" ascii

        $cmd_touch = "touch /tmp/" ascii
        $cmd_curl = "curl " ascii
        $cmd_wget = "wget " ascii
        $cmd_bash = "/bin/bash" ascii
        $cmd_sh = "/bin/sh" ascii
        $cmd_nc = "nc -e" ascii
        $cmd_python = "python -c" ascii
        $cmd_id = { 69 64 00 }

    condition:
        filesize < 50MB and
        2 of ($nb_*) and
        (
            ($deep_nest_array or $deep_nest_object) or
            ($long_key_a or $long_key_b) or
            ($large_number and 1 of ($cmd_*))
        )
}
```

### YARA Rule 2: Jupyter Notebook Heap Spray Payload

Compile: ✅ `yarac` exit 0 | Confidence: medium

<!-- audit: yarac compiled cleanly with no warnings. Rule targets the heap spray phase of the exploit: Float immediates (-1e45) used to encode gadget addresses in Ruby VALUE slots, combined with large null-element arrays (446+ elements for 3568-byte allocation) or deep bracket nesting. Medium confidence because Float values could appear in legitimate scientific notebooks, though the combination with deep nesting or mass null arrays is highly anomalous. -->

```yara
rule Exploit_GitLab_Notebook_Heap_Spray_Payload
{
    meta:
        description = "Detects Jupyter notebook payloads containing binary data patterns consistent with the GitLab Oj RCE heap spray and gadget chain. The exploit embeds crafted Float immediates and Fixnum values that encode ROP gadget addresses for redirecting execution to system()."
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities"
        severity = "high"

    strings:
        $nb_cells = "\"cells\"" ascii
        $nb_type = "\"cell_type\"" ascii

        $float_neg = "-1e45" ascii
        $float_neg2 = "-1e44" ascii
        $float_neg3 = "-1e46" ascii

        $array_fill = "null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null" ascii

        $deep_brackets = "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[" ascii

    condition:
        filesize < 50MB and
        1 of ($nb_*) and
        (
            1 of ($float_neg*) and
            ($array_fill or $deep_brackets)
        )
}
```

### Suricata Rule 1: Notebook Diff Request with Deep Nesting Payload

Compile: ⚠️ uncompiled (structural check only) | Confidence: medium

<!-- audit: Suricata not installed; structural validation performed: dot-notation sticky buffers (http.uri, http.request_body) correctly used, semicolons terminate all options, protocol is http, flow established/to_server present, msg/sid/rev required fields present. The content match for 20 consecutive brackets is a conservative threshold; real exploit uses 2000+. Will match only if the deeply nested JSON is visible in the HTTP request body (direct Git push via HTTP, not SSH). -->

```
alert http $HOME_NET any -> any any (msg:"Actioner - GitLab Notebook Diff Request with Deeply Nested JSON Payload (Oj RCE CVE-2026-54592)"; flow:established,to_server; http.uri; content:"/diffs"; content:".ipynb"; http.request_body; content:"[[[[[[[[[[[[[[[[[[[["; fast_pattern; classtype:web-application-attack; reference:url,depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities; reference:cve,2026-54592; metadata:author Actioner, created_at 2026-07-25; sid:2100010; rev:1;)
```

### Suricata Rule 2: Notebook Commit with Oversized JSON Key

Compile: ⚠️ uncompiled (structural check only) | Confidence: medium

<!-- audit: Structural validation passed: dot-notation buffers, semicolons, required fields all present. Matches HTTP POST/PUT containing notebook format marker and long padding string characteristic of the 65000+ byte key overflow. Limited to HTTP-protocol Git operations; SSH pushes bypass this rule. -->

```
alert http $HOME_NET any -> any any (msg:"Actioner - GitLab Notebook Commit with Oversized JSON Key (Oj Info Leak CVE-2026-54500)"; flow:established,to_server; http.uri; content:".ipynb"; http.request_body; content:"\"cells\""; content:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; fast_pattern; classtype:web-application-attack; reference:url,depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities; reference:cve,2026-54500; metadata:author Actioner, created_at 2026-07-25; sid:2100011; rev:1;)
```

### Suricata Rule 3: Diff Response with Heap Pointer Leak Artifact

Compile: ⚠️ uncompiled (structural check only) | Confidence: low

<!-- audit: Structural validation passed. Targets server-to-client diff responses containing cell_type markers alongside Unicode escape sequences that may indicate leaked heap pointer bytes rendered as HTML entities. Low confidence due to high false positive potential from legitimate notebook diffs containing Unicode content. Threshold of 3 matches in 300 seconds reduces noise. -->

```
alert http any any -> $HOME_NET any (msg:"Actioner - GitLab Puma Worker Diff Response Containing Heap Pointer Leak Artifact"; flow:established,to_client; http.stat_code; content:"200"; http.response_body; content:"cell_type"; content:"\\u00"; fast_pattern; threshold:type both, track by_dst, count 3, seconds 300; classtype:web-application-attack; reference:url,depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities; metadata:author Actioner, created_at 2026-07-25; sid:2100012; rev:1;)
```

## Lessons Learned

1. **Dependency depth creates hidden attack surface:** GitLab's Jupyter notebook diff rendering traverses multiple gems (ipynbdiff -> Oj) before reaching vulnerable C code. The Oj gem is a transitive dependency whose memory safety issues had direct RCE implications for GitLab, yet the fix was classified as a bug fix rather than a security release.

2. **Memory-unsafe language extensions in safe-language ecosystems remain a critical risk:** Ruby's memory safety guarantees do not extend to C extensions. The Oj gem's C implementation introduced classic memory corruption primitives (stack buffer overflow, use-after-free, information disclosure) that would be impossible in pure Ruby.

3. **Silent security fixes delay defender response:** GitLab's June 10 patch listed the Oj 3.17.3 bump under "bug fixes" with no CVE, no CVSS score, and no security advisory. Organizations that prioritize only labeled security fixes may have delayed patching by 6+ weeks, leaving a window between patch availability and the July 24 PoC publication.

4. **Authenticated-only does not mean low risk:** While the exploit requires authenticated push access, any user with Developer role (or higher) on any project -- including public projects accepting contributions -- has sufficient access to execute the full chain.

## Sources

- [The Hacker News - Researcher Publishes GitLab RCE PoC](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html) -- Primary news coverage of the PoC publication, including affected version ranges and timeline
- [depthfirst - Going depthfirst: Achieving GitLab RCE via Two Ruby Memory Corruption Vulnerabilities](https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities) -- Original researcher disclosure with full technical exploit chain details
- [GitLab Patch Release 19.0.2, 18.11.5, 18.10.8](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-0-2-released/) -- GitLab patch release containing the Oj 3.17.3 dependency update
- [SentinelOne - CVE-2026-54592](https://www.sentinelone.com/vulnerability-database/cve-2026-54592/) -- CVE details for the Oj nesting stack buffer overflow (CVSS 7.5)
- [SentinelOne - CVE-2026-54902](https://www.sentinelone.com/vulnerability-database/cve-2026-54902/) -- CVE details for the Oj use-after-free vulnerability (CVSS 6.3)
- [GitLab Advisory Database - CVE-2026-54500](https://advisories.gitlab.com/gem/oj/CVE-2026-54500/) -- CVE details for the Oj information disclosure via uninitialized memory (CVSS 5.3)

---
*Report generated by Actioner*
