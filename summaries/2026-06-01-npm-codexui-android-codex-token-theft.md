# Technical Analysis Report: Malicious npm Package `codexui-android` — OpenAI Codex Token Theft (2026-06-03)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-03
Version: 1.1 (FINAL)

## Executive Summary

`codexui-android` is a functional npm package advertised on npm and GitHub as a remote web UI for OpenAI Codex. From version `0.1.82` onward, the package was trojanized: an obfuscated bundle chunk (`chunk-PUR7OUAG.js`) imported at the top of the CLI entry point (`dist-cli/index.js`) executes at module load — before any application logic — and reads the local Codex credential file `~/.codex/auth.json` (or `$CODEX_HOME/auth.json`). It XOR-encrypts the contents with the static key `anyclaw2026`, base64-encodes them, and POSTs them to an attacker-controlled server `sentry.anyclaw[.]store/startlog` that masquerades as Sentry telemetry. The stolen material is the full OAuth set: `access_token`, `refresh_token`, `id_token`, and account ID. Because OpenAI refresh tokens do not inherently expire, an attacker holding one can silently impersonate the victim indefinitely.

The package reached ~27,000–29,000 weekly npm downloads. The same author (npm account `friuns` / "Igor Levochkin"; Google Play developer "BrutalStrike") shipped an Android app, "OpenClaw Codex Claude AI Agent" (`gptos.intelligence.assistant`), that bootstrapped the malicious npm build on every launch via `pnpm add codexui-android@latest --prefer-offline`, contributing 60,000+ combined mobile installs. The campaign was disclosed by Aikido Security (researcher Charlie Eriksen) on ~2026-05-27; the npm account was reportedly claimed-compromised by the author the next day. This is a software supply-chain credential-theft attack (T1195.002).

## Background: OpenAI Codex CLI and `~/.codex/auth.json`

OpenAI Codex's CLI stores OAuth session material in `~/.codex/auth.json` (overridable with `$CODEX_HOME`). That file holds the access token, refresh token, id token, and account ID — everything needed to act as the user against OpenAI's API. A package that runs in the developer's environment has read access to this file, making it a high-value target for any malicious dependency. `codexui-android` positioned itself as legitimate tooling (a remote UI for Codex) with active development and a real feature set, which lent it credibility and download volume while the credential-theft logic ran silently on each invocation.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-04 | Malicious code introduced at `codexui-android@0.1.82`; exfiltration runs on each invocation for ~1 month |
| 2026-05-27 | Aikido Security publishes analysis of the token-stealing chunk |
| 2026-05-28 | Package author claims the npm account was compromised (post-disclosure) |
| 2026-06-02 | The Hacker News and other outlets report; ~27k–29k weekly npm downloads, 60k+ mobile installs cited |

## Root Cause: Trojanized npm Package (Supply Chain)

The CLI entry `dist-cli/index.js` begins with `#!/usr/bin/env node` followed by `import "./chunk-PUR7OUAG.js";`. That import executes the malicious chunk at module load — "no function call, no condition, no user interaction" — so the theft fires whenever the CLI is invoked (and, on Android, whenever the OpenClaw app relaunches and re-pulls the package). The malicious logic running before application code gave it full access to stored authentication files from startup. Whether this was an account compromise (author's claim) or intentional publishing by the author is disputed; the behavioral artifacts are the same either way.

## Technical Analysis of the Malicious Payload

### 1. Load-Time Trigger
`dist-cli/index.js` top-of-file `import "./chunk-PUR7OUAG.js";` runs at module load. No user interaction is required; every CLI invocation triggers it.

### 2. Credential Harvest
The chunk reads `~/.codex/auth.json` (or `$CODEX_HOME/auth.json`) and returns the entire file as JSON, capturing `access_token`, `refresh_token`, `id_token`, and account ID in one sweep.

### 3. C2 Infrastructure
Harvested data is XOR-encrypted with the static key `anyclaw2026`, base64-encoded, and sent via HTTP POST to `hxxps://sentry[.]anyclaw[.]store/startlog` with `User-Agent: codexui/{version}`. The host name impersonates Sentry (legitimate error-tracking SaaS) to blend with telemetry. A source-map comment reads: `Send tokens to our startlog endpoint (always, independent of Sentry)` — exfiltration occurs unconditionally, independent of any genuine Sentry usage.

### 4. Platform-Specific Behavior

#### Node / developer workstations
Installed via npm/pnpm; the CLI entry triggers theft of `~/.codex/auth.json` on each run.

#### Android
"OpenClaw Codex Claude AI Agent" (`gptos.intelligence.assistant`) ran `pnpm add codexui-android@latest --prefer-offline` on each launch, pulling and executing the malicious build server-side/in its embedded node runtime.

### 5. Anti-Forensics / Evasion Techniques
Logic is hidden in an obfuscated, separately-named bundle chunk (`chunk-PUR7OUAG.js`) rather than in readable entry code; the C2 host name (`sentry.anyclaw[.]store`) and the masquerade as Sentry telemetry are designed to evade casual network review.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs `hxxps://`; domains/IPs `[.]`; emails `[at]`.

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `codexui-android` (npm) | `0.1.82` and onward | Reads `~/.codex/auth.json` and exfiltrates OAuth tokens at module load |
| `gptos.intelligence.assistant` (Google Play) | "OpenClaw Codex Claude AI Agent" | Bootstraps the malicious npm build on each launch |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Node | `dist-cli/index.js` | (not published) | CLI entry; `import "./chunk-PUR7OUAG.js"` |
| Node | `chunk-PUR7OUAG.js` | (not published) | Obfuscated chunk; reads auth.json, XOR+base64, POSTs to C2 |
| Node/Codex | `~/.codex/auth.json` (`$CODEX_HOME/auth.json`) | n/a | Targeted credential file (victim artifact, not malicious) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `sentry[.]anyclaw[.]store` | C2 / exfiltration host (Sentry masquerade) |
| URL Pattern | `hxxps://sentry[.]anyclaw[.]store/startlog` | POST exfiltration endpoint |
| HTTP Header | `User-Agent: codexui/{version}` | Distinctive UA on exfil POST |

### Behavioral

- Load-time execution: a `node`/`pnpm`/`npm` process reads `~/.codex/auth.json` immediately on CLI start.
- Outbound HTTP POST to `sentry.anyclaw[.]store/startlog` with `User-Agent: codexui/…` and an XOR(`anyclaw2026`)+base64 body.
- Static XOR key `anyclaw2026`; exfil comment string `Send tokens to our startlog endpoint`.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Trojanized npm package `codexui-android@0.1.82+` |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious logic in node bundle chunk executes at module load |
| T1552.001 | Unsecured Credentials: Credentials in Files | Reads `~/.codex/auth.json` OAuth tokens |
| T1567 | Exfiltration Over Web Service | HTTP POST of tokens to attacker server |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP(S) C2/exfil to `sentry.anyclaw[.]store` |
| T1071.004 | Application Layer Protocol: DNS | Resolution of the `anyclaw[.]store` C2 host |
| T1027 | Obfuscated Files or Information | Hidden in obfuscated chunk; XOR+base64 body; Sentry masquerade |

## Impact Assessment

Breadth: ~27k–29k weekly npm downloads and 60k+ mobile installs over a ~1-month exposure window. Depth: full OAuth token set stolen, including the non-expiring refresh token — durable, silent impersonation of the victim's OpenAI Codex account. Stealth: theft runs at module load with no user interaction; traffic masquerades as Sentry telemetry.

## Detection & Remediation

### Immediate Detection

```bash
# Is the malicious package present?
npm ls codexui-android 2>/dev/null; find / -type d -name codexui-android 2>/dev/null
# Look for the malicious chunk on disk
find / -name 'chunk-PUR7OUAG.js' 2>/dev/null
grep -rl "sentry.anyclaw.store" / 2>/dev/null
# Any history of resolving / contacting the C2 (check proxy, DNS, EDR logs)
grep -i "anyclaw.store" /var/log/* 2>/dev/null
```

### Remediation

1. Containment: uninstall `codexui-android` and the OpenClaw Android app; block `*.anyclaw[.]store` at DNS/proxy/firewall.
2. Eradication: remove `chunk-PUR7OUAG.js` / the package from all caches (`~/.npm`, `~/.pnpm-store`), lockfiles, and CI images.
3. Recovery — secret rotation (critical): revoke/rotate OpenAI Codex sessions and re-authenticate so the stolen `refresh_token` is invalidated. Refresh tokens do not expire on their own, so rotation is mandatory, not optional.
4. Audit OpenAI account activity for unauthorized API usage during/after the exposure window.

### Long-Term Hardening

- Pin and review dependencies; use `--ignore-scripts` where feasible and vet packages that read credential paths.
- Restrict filesystem access of build/runtime tooling to credential files (`~/.codex`, `~/.aws`, etc.).
- Egress-filter developer/build hosts; alert on outbound POSTs from `node`/`pnpm` to non-allowlisted hosts.

## Detection Rules

These detections cover the campaign's concrete artifacts: the load-time read of `~/.codex/auth.json` by a node/pnpm/npm process (Sigma process_creation), the HTTP POST exfil to `sentry.anyclaw[.]store/startlog` with the `codexui/` User-Agent (Sigma proxy, Snort, Suricata), the C2 DNS resolution (Sigma dns_query), and the malicious chunk's published strings (YARA, sample-tested). Compiles ≠ fires — validate field mappings against your own pipeline before production.

### Sigma: codexui-android Install Hook Reading Codex Auth Token File
Detects a node/pnpm/npm process referencing `~/.codex/auth.json` or `codexui-android`, the load-time credential read. Tune to your environment if legitimate Codex tooling reads the same file.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: level high → medium to match prose/audit (legit Codex CLI reads the same auth.json). -->
<!-- audit: sigma check 0; splunk 0; log_scale 0. category process_creation, product linux — Linux CommandLine field; on macOS/Windows map to the equivalent process-creation source. Medium not high: legitimate Codex CLI also reads auth.json, so this keys on the package name OR the path appearing on a node/pnpm/npm cmdline; pair with the proxy/DNS/YARA detections for confirmation. T1195.002 supply chain + T1552.001 creds-in-files. -->
```yaml
title: codexui-android Install Hook Reading Codex Auth Token File
id: 6f3a1c8e-2b94-4d77-9a1e-5c0d8e2f7b41
status: experimental
description: >
    Detects a node/pnpm/npm process tree reading the OpenAI Codex credential file
    (~/.codex/auth.json or $CODEX_HOME/auth.json), consistent with the malicious
    codexui-android npm package whose chunk-PUR7OUAG.js exfiltrates Codex tokens at
    module load time.
references:
    - https://www.aikido.dev/blog/codex-remote-ui-steals-ai-tokens
    - https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html
author: Actioner
date: 2026/06/03
tags:
    - attack.t1195.002
    - attack.t1552.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_interp:
        Image|endswith:
            - '/node'
            - '/pnpm'
            - '/npm'
    selection_target:
        CommandLine|contains:
            - '.codex/auth.json'
            - 'codexui-android'
    condition: selection_interp and selection_target
falsepositives:
    - Legitimate Codex CLI tooling that reads its own auth.json
level: medium
```

### Sigma: codexui-android Token Exfiltration to sentry.anyclaw.store
Detects web traffic to the C2 host, the `/startlog` URI, or the `codexui/` User-Agent in proxy logs.
**Status:** compile ✅ compiles · confidence: high
<!-- revision: level critical → high (no critical confidence tier; prose says high). -->
<!-- audit: sigma check 0; splunk 0; log_scale 0. category proxy; fields c-uri, cs-User-Agent are common Sigma proxy fields (map to your proxy schema, e.g. Zscaler/BlueCoat/PAN URL-filtering). OR condition across three attacker-specific cues so any one fires; host+UA are the distinctive legs, the bare /startlog URI is the broad cue (could collide with unrelated paths). T1567 exfil-over-web + T1552.001. -->
```yaml
title: codexui-android Token Exfiltration to sentry.anyclaw.store
id: b1d6e2f4-7a83-4c12-9e55-3f0a1c8d2e90
status: experimental
description: >
    Detects HTTP POST exfiltration of stolen OpenAI Codex tokens by the malicious
    codexui-android npm package to its C2 endpoint sentry.anyclaw.store/startlog,
    identifiable by the host, the /startlog URI, and the codexui/ User-Agent.
references:
    - https://www.aikido.dev/blog/codex-remote-ui-steals-ai-tokens
    - https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html
author: Actioner
date: 2026/06/03
tags:
    - attack.t1567
    - attack.t1552.001
logsource:
    category: proxy
detection:
    selection_host:
        c-uri|contains: 'sentry.anyclaw.store'
    selection_uri:
        c-uri|contains: '/startlog'
    selection_ua:
        cs-User-Agent|startswith: 'codexui/'
    condition: selection_host or selection_uri or selection_ua
falsepositives:
    - None expected; the host and User-Agent are attacker-specific
level: high
```

### Sigma: codexui-android C2 Domain DNS Resolution
Detects DNS resolution of the attacker-registered `anyclaw[.]store` (observed host `sentry.anyclaw[.]store`).
**Status:** compile ✅ compiles · confidence: high
<!-- revision: level critical → high (no critical confidence tier; prose says high). -->
<!-- audit: sigma check 0; splunk 0; log_scale 0. category dns_query; QueryName|endswith catches the observed sentry.* subdomain and any sibling on the same registered domain. attacker-owned domain → high. T1071.004 DNS. -->
```yaml
title: codexui-android C2 Domain DNS Resolution
id: 3c9f4a17-8e62-4b05-a7d3-1d2e9f0b6c84
status: experimental
description: >
    Detects DNS resolution of the codexui-android C2/exfiltration domain anyclaw[.]store
    (observed host sentry.anyclaw[.]store), the attacker-controlled server that
    masquerades as Sentry telemetry and receives the exfiltrated Codex tokens.
references:
    - https://www.aikido.dev/blog/codex-remote-ui-steals-ai-tokens
    - https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html
author: Actioner
date: 2026/06/03
tags:
    - attack.t1071.004
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'anyclaw.store'
    condition: selection
falsepositives:
    - None expected; domain is attacker-registered infrastructure
level: high
```

### Snort: codexui-android Token Exfil POST to sentry.anyclaw.store/startlog
Detects the outbound HTTP POST to `/startlog` with the `sentry.anyclaw.store` Host and `codexui/` User-Agent. HTTP only — encrypted HTTPS exfil needs the proxy/DNS detections instead.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 (-c snort-run.conf -T) validated OK. 2.x dialect: non-dotted modifiers (http_method/http_uri/http_header) as standalone options after each content; tcp+$HTTP_PORTS (not http service). UA literal uses |3A| for the colon. sid 2100777. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - codexui-android Codex Token Exfil POST to sentry.anyclaw.store/startlog"; flow:established,to_server; content:"POST"; http_method; content:"/startlog"; http_uri; fast_pattern; content:"sentry.anyclaw.store"; http_header; content:"User-Agent|3A| codexui/"; http_header; classtype:trojan-activity; reference:url,aikido.dev/blog/codex-remote-ui-steals-ai-tokens; sid:2100777; rev:1;)
```

### Suricata: codexui-android Token Exfil POST to sentry.anyclaw.store/startlog
Detects the same exfil POST using dotted sticky buffers (`http.host`, `http.uri`, `http.user_agent`). HTTP only; HTTPS exfil → use proxy/DNS detections.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 (-T -S) loaded OK. dotted buffers; bsize:20 anchors the exact host length; startswith on uri+UA. sid 2200777. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - codexui-android Codex Token Exfil POST to sentry.anyclaw.store/startlog"; flow:established,to_server; http.method; content:"POST"; http.host; content:"sentry.anyclaw.store"; bsize:20; http.uri; content:"/startlog"; startswith; fast_pattern; http.user_agent; content:"codexui/"; startswith; classtype:trojan-activity; reference:url,aikido.dev/blog/codex-remote-ui-steals-ai-tokens; metadata:author Actioner, created_at 2026-06-03; sid:2200777; rev:1;)
```

### YARA: codexui-android Codex Token Stealer
Matches the malicious chunk and bootstrap artifacts via the source's published strings (C2 host, XOR key, exfil comment, `/startlog`, `chunk-PUR7OUAG`, `.codex/auth.json`).
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac 0. sample test: pos.txt (built from Aikido's published strings: import "./chunk-PUR7OUAG.js", "Send tokens to our startlog endpoint", anyclaw2026, sentry.anyclaw.store, /startlog, .codex/auth.json, codexui/) MATCHED; neg.txt (benign Codex UI posting to the real *.ingest.sentry.io) quiet. Condition layered so a single high-uniqueness string (c2host/comment) or a key+path combo fires, avoiding single-weak-string FPs. -->
```yara
rule Malware_codexui_android_Codex_Token_Stealer
{
    meta:
        description = "Detects the malicious codexui-android npm package install chunk that exfiltrates OpenAI Codex auth.json tokens"
        author = "Actioner"
        date = "2026-06-03"
        reference = "https://www.aikido.dev/blog/codex-remote-ui-steals-ai-tokens"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $chunk    = "chunk-PUR7OUAG" ascii
        $xorkey   = "anyclaw2026" ascii
        $c2host   = "sentry.anyclaw.store" ascii
        $path     = "/startlog" ascii
        $comment  = "Send tokens to our startlog endpoint" ascii nocase
        $auth     = ".codex/auth.json" ascii
        $ua       = "codexui/" ascii
        $codexenv = "CODEX_HOME" ascii

    condition:
        $c2host or
        $comment or
        ($xorkey and ($path or $auth)) or
        ($chunk and ($auth or $codexenv)) or
        (2 of ($path, $auth, $ua, $codexenv))
}
```

## Lessons Learned

A package with real functionality and high download volume is a credible delivery vehicle; "looks legitimate and is actively developed" is not a trust signal. Module-load-time code in a dependency runs with full access to local credential files before any sandboxing or user consent — credential files for AI/dev tooling (`~/.codex`, cloud creds) are now first-class targets. Non-expiring refresh tokens turn a one-time theft into durable account access, so rotation must be treated as mandatory after any exposure. Masquerading exfil as Sentry telemetry shows defenders cannot trust traffic by brand-name alone; egress allowlisting and per-host scrutiny matter.

## Sources

- [The Hacker News — OpenAI Codex Authentication Tokens Stolen in codexui-android npm Supply Chain Attack](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html) — disclosure summary, IOCs (host, auth.json, token set), author/account, install counts
- [Aikido Security — Legitimate-Looking Codex Remote UI Secretly Steals Your AI Tokens](https://www.aikido.dev/blog/codex-remote-ui-steals-ai-tokens) — primary technical analysis: chunk name, load-time import, XOR key, /startlog endpoint, User-Agent, Android bootstrap command
- [Cybersecurity News — Legitimate-Looking Codex Remote UI Steals OpenAI Codex Authentication Tokens](https://cybersecuritynews.com/legitimate-looking-codex-remote-ui/) — corroborates package/version, dist-cli/index.js entry, exfil host/path/UA, XOR key, Android package ID
- [Hackread — 27,000-Download Codex UI Tool Secretly Stole OpenAI Refresh Tokens](https://hackread.com/codex-ui-tool-secretly-stole-openai-refresh-tokens/) — corroborates package, credential path, exfil domain, chunk import, source-map comment, Google Play developer

---
*Report generated by Actioner*
