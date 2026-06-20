# Technical Analysis Report: AutoJack — Zero-Click RCE in Microsoft AutoGen Studio (2026-06-20)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-20
Version: 1.1 (REVISED)
<!-- revision: v1.1 — dropped browser-agent-spawn Sigma rule (generic TTP); downgraded WebSocket proxy Sigma to low confidence; added localhost-visibility caveats to WebSocket proxy Sigma/Suricata/Snort rules; added per-category Detection Rules preamble; added Windows-only coverage caveat; clarified YARA severity vs confidence -->

## Executive Summary

AutoJack is a three-bug exploit chain discovered by Microsoft Research in AutoGen Studio that allows a single malicious web page to achieve zero-click remote code execution on any host running an AI browsing agent backed by AutoGen Studio. The attack exploits a confused-deputy flaw: because the browsing agent runs on the same machine as AutoGen Studio, its headless browser inherits localhost trust. A malicious page opened by the agent can silently open a WebSocket to the unauthenticated MCP endpoint, pass base64-encoded `StdioServerParams` containing an arbitrary command, and have AutoGen Studio spawn that command under the developer's account — no user interaction required.

The vulnerability was never released in a PyPI package (stable 0.4.2.2 is not affected). Only development builds from the main branch between the MCP plugin landing and fix commit `b047730` are vulnerable. Pre-release PyPI versions 0.4.3.dev1 and 0.4.3.dev2 were also affected. No in-the-wild exploitation has been reported. Despite the narrow exposure window, the attack pattern — AI agent as confused deputy to exploit localhost-trusted services — represents a novel and broadly applicable threat class.

## Background: Microsoft AutoGen Studio

AutoGen Studio is Microsoft's open-source visual development environment for building multi-agent AI applications using the AutoGen framework. It provides a web-based IDE (typically bound to `localhost:8081`) where developers design, test, and run AI agent workflows. A key feature is integration with the Model Context Protocol (MCP), which allows agents to connect to external tool servers via WebSocket. The MCP WebSocket endpoint at `/api/mcp/ws/` accepts connection parameters including the command to spawn an MCP server process — the core surface exploited by AutoJack.

When combined with a browsing agent (e.g., using Playwright's `MultimodalWebSurfer`), the agent's headless browser navigates to arbitrary URLs as part of its task. This creates a scenario where untrusted web content executes in the same localhost context as privileged AutoGen Studio endpoints.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Pre-2026-06-18 | Microsoft Research discovers three chained vulnerabilities in AutoGen Studio main branch |
| Pre-2026-06-18 | Fix committed to main branch at commit `b047730` (version 0.7.2 in pyproject.toml) |
| 2026-06-18 | Microsoft publishes detailed security blog post disclosing the AutoJack vulnerability chain |
| 2026-06-19 | Coverage published by The Hacker News and Cybersecurity News |

## Root Cause: Confused-Deputy Exploit via Localhost Trust + Auth Bypass + Command Injection

The attack chains three distinct weaknesses (CWEs):

1. **CWE-1385 — Origin allowlist trusts localhost**: The WebSocket origin check passes for any connection from `localhost` or `127.0.0.1`. Since the browsing agent's headless browser runs on the same machine, JavaScript on any page rendered by the agent inherits localhost identity.

2. **CWE-306 — Authentication middleware opt-out for MCP paths**: The FastAPI authentication middleware explicitly excludes `/api/mcp` and `/api/ws` paths, assuming the handler would verify tokens itself. It never did.

3. **CWE-78 — StdioServerParams from URL executed verbatim**: The `server_params` query parameter is base64-decoded, deserialized into a `StdioServerParams` object, and the `command` field is passed directly to process creation with no validation or allowlist.

## Technical Analysis of the Malicious Payload

### 1. Agent Navigation to Malicious Page (Initial Access)

The attacker crafts a web page containing a JavaScript payload and causes the AI browsing agent to visit it. This can happen through:
- The agent being directly prompted to visit a URL
- Prompt injection via a previously trusted page
- The agent discovering the malicious page through search results

No user interaction is required — the agent autonomously navigates and renders the page in its headless browser.

### 2. WebSocket Exploit Payload (Exploitation)

When the agent's browser renders the malicious page, JavaScript executes and opens a WebSocket connection to the local AutoGen Studio instance:

```
ws://localhost:8081/api/mcp/ws/?server_params=<base64-encoded-JSON>
```

The base64 payload decodes to a `StdioServerParams` JSON object:

```json
{
  "type": "StdioServerParams",
  "command": "calc.exe",
  "args": [],
  "env": { "pwned": "true" }
}
```

The `command` field can be any executable on the system, with arbitrary arguments and environment variables.

### 3. Vulnerable Endpoint Code

The MCP WebSocket route in `autogenstudio/web/routes/mcp.py`:

```python
@router.websocket("/ws/{session_id}")
async def mcp_websocket(websocket: WebSocket, session_id: str):
    encoded = websocket.query_params.get("server_params")
    decoded = base64.b64decode(encoded)
    params = StdioServerParams(**json.loads(decoded))
    await create_mcp_session(bridge, params, session_id)
```

The authentication middleware in `app.py` explicitly skips MCP paths:

```python
if request.url.path.startswith("/api/ws") or \
   request.url.path.startswith("/api/mcp"):
    return await call_next(request)
```

### 4. Command Execution (Impact)

AutoGen Studio spawns the attacker-specified process under the developer's user account with full privileges. The attacker can execute any command, including reverse shells, credential harvesters, ransomware, or lateral movement tools.

### 5. No Traditional C2 Infrastructure

This is not a malware campaign with C2 servers. The exploit leverages the victim's own localhost service as the execution engine. The only network artifact is the WebSocket connection from the browser agent to `localhost:8081`.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Package / Software Level

| Package / Component | Affected Version | Description |
|---------------------|-----------------|-------------|
| autogenstudio (GitHub main) | Between MCP plugin landing and commit `b047730` | Vulnerable MCP WebSocket endpoint |
| autogenstudio (PyPI pre-release) | 0.4.3.dev1, 0.4.3.dev2 | Pre-release dev builds with vulnerable code |
| autogenstudio (PyPI stable) | 0.4.2.2 | NOT affected — MCP route never included |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Cross-platform | `autogenstudio/web/routes/mcp.py` | Vulnerable MCP WebSocket route handler |
| Cross-platform | `app.py` | FastAPI application with auth bypass in middleware |

### Network

| Type | Value | Context |
|------|-------|---------|
| Port | 8081 (default, configurable) | AutoGen Studio default listen port |
| WebSocket Path | `/api/mcp/ws/` | Vulnerable MCP WebSocket endpoint |
| Query Parameter | `server_params=<base64>` | Base64-encoded StdioServerParams payload |
| Protocol | `ws://localhost:8081/api/mcp/ws/?server_params=` | Full exploit WebSocket URI pattern |

### Behavioral

- Python process with `autogenstudio` in command line spawning shell interpreters (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `bash.exe`, `wsl.exe`) or LOLBins (`certutil.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `curl.exe`, `wget.exe`, `bitsadmin.exe`)
- Python/Node processes with `playwright`, `MultimodalWebSurfer`, or `autogen` in command line spawning unexpected child processes
- WebSocket connections to `/api/mcp/ws/` containing `server_params=` in the query string
- Base64-encoded JSON payloads containing `StdioServerParams` and a `command` field in WebSocket traffic on ports 8080/8081

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Malicious web page exploits the AutoGen Studio MCP WebSocket endpoint accessible from the browsing agent's localhost context |
| T1059 | Command and Scripting Interpreter | Arbitrary command execution via `StdioServerParams.command` field — attacker can invoke any shell interpreter or executable |
| T1203 | Exploitation for Client Execution | The browsing agent acts as a confused deputy — it renders a malicious page that exploits a local service the agent has implicit trust with |
| T1059.001 | PowerShell | PowerShell can be specified as the command in the exploit payload |
| T1059.003 | Windows Command Shell | cmd.exe can be specified as the command in the exploit payload |
| T1059.004 | Unix Shell | bash can be specified as the command on Linux/macOS hosts |

## Impact Assessment

**Scope**: Limited to developers running AutoGen Studio from the main branch (post-MCP-landing, pre-fix) with a browsing agent configured. The stable PyPI release (0.4.2.2) is not affected. Pre-release PyPI versions 0.4.3.dev1 and 0.4.3.dev2 are affected.

**Severity**: Critical for affected configurations — zero-click RCE under the developer's full user context. No authentication, no user interaction, no exploit kit required. A single page visit by the browsing agent is sufficient.

**Novel threat class**: AutoJack demonstrates that AI browsing agents create a new attack surface where untrusted web content can exploit localhost-trusted services through the agent as a confused deputy. This pattern applies broadly to any AI agent framework that combines web browsing with local service access.

## Detection & Remediation

### Immediate Detection

Check if you are running a vulnerable version:

```bash
# Check if MCP route file exists in your installation
find $(python3 -c "import autogenstudio; print(autogenstudio.__path__[0])" 2>/dev/null) -name "mcp.py" -path "*/routes/*" 2>/dev/null

# Check installed version
pip show autogenstudio 2>/dev/null | grep Version

# Check if the endpoint is live
curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/api/mcp/ws/ 2>/dev/null
```

**Microsoft Defender Advanced Hunting (KQL)**:

```kql
DeviceProcessEvents
| where InitiatingProcessCommandLine matches regex @"(?i)autogenstudio|autogen[\s_\-]?studio"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","wsl.exe",
  "certutil.exe","mshta.exe","rundll32.exe","regsvr32.exe","curl.exe","wget.exe","bitsadmin.exe")
```

```kql
DeviceNetworkEvents
| where RemotePort in (8081, 8080)
| where RemoteUrl has "/api/mcp/ws/" and RemoteUrl has "server_params="
```

### Remediation

1. **Update immediately**: Pull the latest main branch (at or after commit `b047730`) or wait for the next stable PyPI release
2. **If running a pre-release**: Uninstall versions 0.4.3.dev1 / 0.4.3.dev2 and install stable 0.4.2.2 or the fixed main branch
3. **Audit process logs**: Check for any unexpected child processes spawned by the AutoGen Studio Python process
4. **Rotate credentials**: If exploitation is suspected, rotate all credentials accessible to the developer account

### Long-Term Hardening

- **Bind to loopback only**: Ensure AutoGen Studio listens on `127.0.0.1`, not `0.0.0.0`
- **Use host firewall rules**: Block non-loopback traffic to port 8081
- **Deploy behind an authenticated reverse proxy**: Enforce authentication on all paths including `/api/mcp`
- **Run under a low-privilege account**: Use a sandboxed profile or container for AI agent workloads
- **Allowlist MCP server executables**: Do not accept arbitrary commands — maintain a whitelist of permitted MCP server binaries
- **Separate agent browsing identity**: Run the browsing agent in a different security context from the AutoGen Studio service

## Detection Rules

Two Sigma rules, one YARA rule, one Suricata rule, and one Snort rule cover the AutoJack exploit chain. **Endpoint (Sigma):** Both process-creation rules target Windows only; Linux/macOS process telemetry is not covered. **Network (Suricata/Snort) and proxy (Sigma):** The WebSocket proxy, Suricata, and Snort rules detect localhost-to-localhost traffic that requires a host-level HTTP proxy or IDS sensor inspecting loopback; perimeter deployments will not see AutoJack exploitation. **File (YARA):** Scans for exploit page artifacts on disk or in memory; no network sensor dependency.

Dropped: generic AI-agent-spawns-shell detection; not AutoJack-specific at `specific` altitude.

### Sigma: AutoGen Studio Process Spawning Suspicious Child

Detects the AutoGen Studio Python process spawning shell interpreters or LOLBins — the direct observable of successful AutoJack exploitation.
<!-- audit: sigma check 0 errors, 0 issues; sigma convert --without-pipeline -t splunk OK; sigma convert --without-pipeline -t log_scale OK; behavioral rule from Microsoft's KQL query 1; fields: ParentCommandLine contains autogenstudio variants, Image endswith shell/LOLBin list -->

**Compile**: sigma check ✅ | splunk ✅ | log_scale ✅
**Confidence**: medium (behavioral — legitimate MCP servers may spawn interpreters)

```yaml
title: AutoGen Studio Python Process Spawning Suspicious Child (AutoJack)
id: 8c241a1c-28f2-4a7e-8646-6efb14ff5219
status: experimental
description: >
    Detects AutoGen Studio's Python process spawning shell interpreters or LOLBins,
    consistent with the AutoJack zero-click RCE exploit chain where a malicious web
    page hijacks the MCP WebSocket endpoint to execute arbitrary commands under
    the developer's account.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/
    - https://thehackernews.com/2026/06/autojack-attack-lets-one-web-page.html
author: Actioner
date: 2026/06/20
tags:
    - attack.t1059
    - attack.t1203
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentCommandLine|contains:
            - 'autogenstudio'
            - 'autogen_studio'
            - 'autogen-studio'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\bash.exe'
            - '\wsl.exe'
            - '\certutil.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\regsvr32.exe'
            - '\curl.exe'
            - '\wget.exe'
            - '\bitsadmin.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate MCP server tools spawned by AutoGen Studio that invoke shell interpreters
    - Developer workflow automation that chains AutoGen Studio with shell commands
level: medium
```

### Sigma: WebSocket to AutoGen Studio MCP Endpoint with server_params

Detects web proxy log entries showing requests to the MCP WebSocket endpoint with the `server_params` query parameter — the network-level signature of AutoJack exploitation. Requires a host-level HTTP proxy or IDS sensor inspecting loopback traffic; perimeter deployments will not see AutoJack exploitation.
<!-- audit: sigma check 0 errors, 0 issues; sigma convert --without-pipeline -t splunk OK; sigma convert --without-pipeline -t log_scale OK; proxy logsource with cs-uri-stem and cs-uri-query fields -->

**Compile**: sigma check ✅ | splunk ✅ | log_scale ✅
**Confidence**: low (pre-fix, 100% of legitimate MCP connections use the same URI pattern and are false positives)

```yaml
title: WebSocket Connection to AutoGen Studio MCP Endpoint with server_params (AutoJack)
id: 8d47c889-a12c-4e0b-a110-ac05bbf01bc4
status: experimental
description: >
    Detects network connections to the AutoGen Studio MCP WebSocket endpoint
    containing a server_params query parameter, the attack surface exploited
    by the AutoJack vulnerability to pass attacker-controlled StdioServerParams
    for arbitrary command execution. Requires a host-level HTTP proxy or IDS
    sensor inspecting loopback traffic; perimeter deployments will not see
    AutoJack exploitation.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/
    - https://thehackernews.com/2026/06/autojack-attack-lets-one-web-page.html
author: Actioner
date: 2026/06/20
tags:
    - attack.t1190
    - attack.t1059
logsource:
    category: proxy
detection:
    selection:
        cs-uri-stem|contains: '/api/mcp/ws/'
        cs-uri-query|contains: 'server_params='
    condition: selection
falsepositives:
    - Legitimate AutoGen Studio MCP server registration via the pre-fix URL parameter interface — pre-fix, 100% of legitimate MCP connections match this pattern
level: low
```

### YARA: AutoJack MCP WebSocket Exploit Page

Detects HTML/JavaScript files crafted to exploit the AutoJack vulnerability by targeting the AutoGen Studio MCP WebSocket endpoint with encoded StdioServerParams.
<!-- audit: yarac exit 0; matches on ws://localhost:8081/api/mcp/ws/ or 127.0.0.1 variants with server_params= and either StdioServerParams string or base64/WebSocket JS API usage; filesize < 1MB constraint -->

**Compile**: yarac ✅
**Confidence**: medium (behavioral — the combination of WebSocket URL + parameter + type string is distinctive but could appear in benign security research). Note: the YARA meta `severity` field is set to `high` reflecting impact if the rule matches a true positive (RCE); detection confidence remains medium due to possible benign security-research artifacts.

```yara
rule Exploit_AutoJack_MCP_WebSocket_Payload
{
    meta:
        description = "Detects HTML/JavaScript payloads crafted to exploit the AutoJack vulnerability by opening a WebSocket to the AutoGen Studio MCP endpoint with base64-encoded StdioServerParams for arbitrary command execution"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/"
        severity = "high"

    strings:
        $ws1 = "ws://localhost:8081/api/mcp/ws/" ascii wide nocase
        $ws2 = "ws://127.0.0.1:8081/api/mcp/ws/" ascii wide nocase
        $ws3 = "ws://localhost:8080/api/mcp/ws/" ascii wide nocase
        $ws4 = "ws://127.0.0.1:8080/api/mcp/ws/" ascii wide nocase
        $param = "server_params=" ascii wide nocase
        $type1 = "StdioServerParams" ascii wide
        $type2 = "U3RkaW9TZXJ2ZXJQYXJhbXM" ascii wide
        $func1 = "WebSocket" ascii wide
        $func2 = "new WebSocket" ascii wide
        $func3 = "btoa" ascii wide
        $func4 = "base64" ascii wide nocase

    condition:
        filesize < 1MB and
        (1 of ($ws*)) and
        ($param) and
        (1 of ($type*) or 1 of ($func*))
}
```

### Suricata: HTTP WebSocket Upgrade to AutoGen Studio MCP Endpoint

Detects HTTP WebSocket upgrade requests targeting the AutoGen Studio MCP endpoint with the `server_params` query parameter in network traffic. Requires a host-level HTTP proxy or IDS sensor inspecting loopback traffic; perimeter deployments will not see AutoJack exploitation.
<!-- audit: suricata -T exit 0; http protocol with http.uri and http.header sticky buffers; matches Upgrade: websocket header + /api/mcp/ws/ URI + server_params= in URI; sid:2100301 -->

**Compile**: suricata -T ✅
**Confidence**: medium (behavioral — matches the specific URI pattern and WebSocket upgrade combination; localhost-only visibility caveat applies)

```
# Caveat: Requires a host-level HTTP proxy or IDS sensor inspecting loopback traffic; perimeter deployments will not see AutoJack exploitation.
alert http any any -> any any (msg:"Actioner - HTTP WebSocket Upgrade to AutoGen Studio MCP Endpoint with server_params (AutoJack)"; flow:established,to_server; http.uri; content:"/api/mcp/ws/"; fast_pattern; content:"server_params="; http.header; content:"Upgrade"; content:"websocket"; nocase; classtype:web-application-attack; reference:url,www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/; metadata:author Actioner, created_at 2026-06-20; sid:2100301; rev:2;)
```

### Snort: HTTP WebSocket Upgrade to AutoGen Studio MCP Endpoint

Detects the same HTTP WebSocket upgrade pattern as the Suricata rule above, using Snort 3 underscore-notation sticky buffers. Requires a host-level HTTP proxy or IDS sensor inspecting loopback traffic; perimeter deployments will not see AutoJack exploitation.
<!-- audit: snort -c /etc/snort/snort.conf -R ... -T exit 0 (pidfile suffix warning is non-fatal); http service with http_uri and http_header buffers; sid:2100301 -->

**Compile**: snort -T ✅ (non-fatal pidfile warning)
**Confidence**: medium (behavioral — same pattern as Suricata rule; localhost-only visibility caveat applies)

```
# Caveat: Requires a host-level HTTP proxy or IDS sensor inspecting loopback traffic; perimeter deployments will not see AutoJack exploitation.
alert http any any -> any any (msg:"Actioner - HTTP WebSocket Upgrade to AutoGen Studio MCP Endpoint with server_params (AutoJack)"; flow:established, to_server; http_uri; content:"/api/mcp/ws/", fast_pattern; content:"server_params="; http_header; content:"Upgrade"; content:"websocket", nocase; classtype:web-application-attack; reference:url,www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/; metadata:author Actioner, created 2026-06-20; sid:2100301; rev:2;)
```

## Lessons Learned

AutoJack demonstrates a novel and underappreciated attack surface created by AI browsing agents. The core insight is that **localhost trust boundaries dissolve when an AI agent can browse untrusted content while residing on the same machine as privileged local services**. This is not unique to AutoGen Studio — any AI agent framework that combines autonomous web browsing with access to localhost-bound services (development tools, databases, APIs) is potentially vulnerable to the same confused-deputy pattern.

Key takeaways:

1. **AI agents are not users**: Traditional localhost trust assumptions break when a non-human agent with full browser capabilities can be directed to visit attacker-controlled content
2. **Auth bypass by architecture**: The middleware exclusion for MCP paths was a reasonable development shortcut that became a critical vulnerability when combined with the agent browsing model
3. **Zero-click is the new norm for agent exploits**: Unlike traditional browser exploits that require user interaction, AI agent exploits are zero-click by design — the agent autonomously navigates to the malicious page
4. **Defense in depth for AI frameworks**: Agent frameworks must treat all URL parameters as untrusted, enforce authentication on all endpoints regardless of assumed access patterns, and sandbox agent browsing from privileged local services

## Sources

- [Microsoft Security Blog — AutoJack: Single-Page RCE on Host Running AI Agent](https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/) — primary technical disclosure with vulnerable code snippets, KQL hunting queries, and remediation guidance
- [The Hacker News — AutoJack Attack Lets One Web Page Hijack AI Agent](https://thehackernews.com/2026/06/autojack-attack-lets-one-web-page.html) — additional coverage confirming affected pre-release PyPI versions and disclosure timeline

---
*Report generated by Actioner*
