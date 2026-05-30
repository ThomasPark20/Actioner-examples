# npm Dependency-Confusion Supply-Chain Attack — "moika.tech" Campaign

<!--
VALIDATION LOG (DRAFT). Toolchain confirmed installed and exercised:
  sigma (targets: splunk, log_scale), yarac, snort 2.9.20, suricata 7.0.3.
Observed results:
  - YARA (/tmp/dc.yar): yarac -> exit 0 (compiles). Sample-test: yara on /tmp/dc_pos.txt
    (real published strings) FIRED rule npm_depconf_moika_stager; /tmp/dc_neg.txt (benign)
    stayed quiet -> sample: fired ✓.
  - Snort (/tmp/dc.snort.rules via /tmp/dc.snort.conf): snort -c ... -T -> exit 0; engine
    listed active rules 9200001/9200002/9200003 (compiles).
  - Suricata (/tmp/dc.suri.rules): suricata -T -S ... -l /tmp -> exit 0; "all 4 rules
    processed" (compiles).
  - Sigma (/tmp/dc_dns.yml, /tmp/dc_proc.yml): sigma convert --without-pipeline -t splunk
    -> exit 0 AND -t log_scale -> exit 0 (both portability targets pass; valid SPL +
    LogScale queries emitted). `sigma check` exited 1, but ONLY because this offline
    sandbox cannot fetch MITRE D3FEND tag data (HTTP 403 from the validator's urlopen) --
    a network/environment failure, not a rule defect; rule parsing+conversion succeeded.
    Sigma rules are labeled "compiles" on the strength of the dual-backend conversion
    oracle, with this caveat recorded.
All artifacts are verbatim from the authoritative extracted-artifacts block; none invented.
WebSearch corroborated the campaign independently: SafeDep and Sonatype both name the
oob.moika.tech C2 and the same dependency-confusion cluster, and The Hacker News covered it;
these are cited in ## Sources alongside the Microsoft primary.
-->

- **Date:** 2026-05-30
- **Mode:** DRAFT
- **Altitude:** specific (PoC/advisory-specific)
- **Leniency:** strict
- **Author:** Actioner

## Summary

Microsoft Security reported a live npm supply-chain campaign in which three coordinated
maintainer accounts published roughly 45 malicious packages whose names mimic
corporate/internal org scopes, exploiting **dependency confusion**: packages are pinned to
absurdly high versions (e.g. `v100.100.100`, `99.5.7`) so package managers prefer the
public malicious package over the intended private one. Each package ships a `postinstall`
hook (`node scripts/postinstall.js`) containing ~7-13 KB of obfuscator.io-style JavaScript
that runs automatically on `npm install`, profiles the developer/CI environment (hostname,
env vars, OS platform, Node version, project layout), and beacons to the C2 at
`oob[.]moika[.]tech`, requesting an OS-specific second-stage loader (`/payload/win`,
`/payload/mac`, `/payload/linux`) while authenticating with a hardcoded, campaign-unique
`X-Secret` header. The campaign includes kill-switch / CI-bypass environment variables and
tmpdir-dropped init files, indicating deliberate evasion and staged execution.

The strongest, lowest-false-positive detection anchors are the shared hardcoded HTTP header
value `X-Secret: l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1` and the C2 domain `oob[.]moika[.]tech`,
both campaign-unique. Process-creation telemetry of an npm `postinstall` spawning `node`
provides a behavioral backstop, and YARA strings catch the dropped/obfuscated stager on disk.

## Threat Details

- **Initial access / delivery:** Dependency confusion (T1195.003). Malicious public npm
  packages reuse internal-looking scope names and publish at inflated versions so resolvers
  prefer them over the private originals.
- **Malicious maintainer accounts (npm):** `mr.4nd3r50n`, `ce-rwb`, `t-in-one`.
- **Maintainer emails:** mr.4nd3r50n[at]yandex[.]ru, ogvanta[at]yandex[.]ru,
  t-in-one[at]yandex[.]ru.
- **Impersonated scopes (~45 packages):** `@cloudplatform-single-spa` (v100.100.100),
  `@wb-track`, `@data-science`, `@ce-rwb` (v3.5.22), `@payments-widget`,
  `@travel-autotests`, `@t-in-one` (v5.7.1 and 99.5.7-99.5.8), `@capibar.chat`,
  `@sber-ecom-core`.
- **Execution:** `"postinstall": "node scripts/postinstall.js"` runs on install
  (T1059.007). Payload is ~7-13 KB obfuscator.io-style obfuscated JS (T1027).
- **Command and control:** `hxxps://oob[.]moika[.]tech` with OS-specific endpoints
  `/payload/win`, `/payload/mac`, `/payload/linux` (T1071.001 / T1090). The stager sends
  HTTP auth header `X-Secret: l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1` — a single hardcoded value
  shared across all three actors (campaign-unique, HIGH-confidence network indicator).
- **Recon collected (T1083 / T1087 / T1005):** hostname, environment variables,
  `os.platform()`, `process.versions.node`, project root; walks `package.json`,
  `yarn.lock`, and `.git`.
- **Evasion / kill-switch env vars:** `CI`, `CLOUDPLATFORM_SINGLE_SPA_NO_TELEMETRY`,
  `T_IN_ONE_NO_TELEMETRY`. Recon env markers: `*_RECON_ONLY=1`, `*_PKG`, `*_VER`,
  `*_SECRET`.
- **Dropped files (tmpdir):** `._cloudplatform-single-spa_init.js`, `._wb-track_init.js`,
  `._t-in-one_init.js`; cache dirs `~/.cache/.<scope>_init/`.
- **Lure / infrastructure domains:** `npm[.]t-in-one[.]io`, `docs[.]t-in-one[.]io`,
  `jira[.]t-in-one[.]io`.
- **Hashes:** No SHA256 hashes were published.

## Indicators of Compromise (defanged)

| Type | Indicator | Confidence |
|------|-----------|------------|
| Domain (C2) | `oob[.]moika[.]tech` | high |
| URL | `hxxps://oob[.]moika[.]tech/payload/win` | high |
| URL | `hxxps://oob[.]moika[.]tech/payload/mac` | high |
| URL | `hxxps://oob[.]moika[.]tech/payload/linux` | high |
| HTTP header | `X-Secret: l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1` | high |
| Domain (lure) | `npm[.]t-in-one[.]io`, `docs[.]t-in-one[.]io`, `jira[.]t-in-one[.]io` | medium |
| npm account | `mr.4nd3r50n`, `ce-rwb`, `t-in-one` | high |
| Email | mr.4nd3r50n[at]yandex[.]ru, ogvanta[at]yandex[.]ru, t-in-one[at]yandex[.]ru | medium |
| File (dropped) | `._cloudplatform-single-spa_init.js`, `._wb-track_init.js`, `._t-in-one_init.js` | medium |
| Path | `~/.cache/.<scope>_init/` | medium |
| Package scope | `@cloudplatform-single-spa`, `@t-in-one`, `@ce-rwb`, `@wb-track`, `@sber-ecom-core`, etc. | medium |

## MITRE ATT&CK

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.003 | Compromise Software Dependencies and Development Tools | Dependency confusion via high-versioned public packages mimicking internal scopes |
| T1027 | Obfuscated Files or Information | ~7-13 KB obfuscator.io-style stager |
| T1059.007 | Command and Scripting Interpreter: JavaScript | `node scripts/postinstall.js` install hook |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 to oob[.]moika[.]tech |
| T1090 | Proxy / C2 connection | OS-specific payload endpoints |
| T1083 | File and Directory Discovery | Walks package.json / yarn.lock / .git |
| T1087 | Account Discovery | Environment / account profiling |
| T1005 | Data from Local System | Env vars, hostname, project metadata |

## Detection Rules

These rules target the campaign's lowest-FP anchors: the campaign-unique `X-Secret` header
value and the dedicated C2 domain `oob[.]moika[.]tech` (Snort + Suricata, HTTP/TLS/DNS), the
npm postinstall-to-node execution chain (Sigma process_creation), DNS resolution of the C2
and lure domains (Sigma dns_query), and the unique on-disk strings (YARA). Compiles != fires
— verify in your own pipeline.

> Validation: YARA, Snort, and Suricata all compiled (exit 0); YARA also fired on a positive
> sample and stayed quiet on a benign one. Both Sigma rules convert cleanly to Splunk and
> CrowdStrike LogScale; `sigma check` exited non-zero only because its MITRE D3FEND tag
> lookup is network-blocked here (HTTP 403) — an environment issue, not a rule defect.

| Type | Rule | Compile · Confidence |
|------|------|----------------------|
| Snort | C2 X-Secret / Host / DNS | ✅ compiles · high |
| Suricata | C2 X-Secret / Host / SNI / DNS | ✅ compiles · high |
| Sigma | DNS query to C2 / lure | ✅ compiles · high |
| Sigma | postinstall → node | ✅ compiles · medium |
| YARA | unique stager strings | ✅ compiles · high · sample: fired ✓ |

### 1. Snort — C2 X-Secret header, Host, and DNS (network)

Detects the campaign-unique `X-Secret` auth value, the C2 Host header, and the C2 DNS query. ✅ compiles · confidence: **high**

<!-- audit: Three rules in /tmp/dc.snort.rules, validated against /tmp/dc.snort.conf via snort -c /tmp/dc.snort.conf -T -> exit 0; engine listed active 9200001/9200002/9200003. 9200001: X-Secret value l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1 is hardcoded/shared across all three actors -> effectively zero-FP; fast_pattern on the header. 9200002: cleartext Host: oob.moika.tech. 9200003: DNS query for oob.moika.tech encoded as length-prefixed labels (Snort 2.9 has no dns rule protocol, so udp/53 + content). HTTPS variants need TLS inspection or the Suricata TLS-SNI/DNS rules below. -->

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"NPM-DEPCONF moika.tech stager C2 X-Secret header"; flow:established,to_server; content:"X-Secret|3a 20|l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1"; http_header; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/; sid:9200001; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"NPM-DEPCONF moika.tech C2 Host header"; flow:established,to_server; content:"Host|3a 20|oob.moika.tech"; http_header; nocase; classtype:trojan-activity; sid:9200002; rev:1;)
alert udp $HOME_NET any -> $DNS_SERVERS $DNS_PORTS (msg:"NPM-DEPCONF moika.tech C2 DNS query"; content:"|03|oob|05|moika|04|tech|00|"; nocase; classtype:trojan-activity; sid:9200003; rev:1;)
```

### 2. Suricata — C2 X-Secret header, Host, TLS SNI, and DNS (network)

Detects the unique `X-Secret` value and the C2 host on HTTP, the TLS SNI for the HTTPS payload fetch, and the C2 DNS query. ✅ compiles · confidence: **high**

<!-- audit: Four rules in /tmp/dc.suri.rules, validated via suricata -T -S /tmp/dc.suri.rules -l /tmp -> exit 0, "all 4 rules processed". 2200001: campaign-unique X-Secret value (sticky http.header). 2200002: http.host=oob.moika.tech. 2200003: tls.sni for the https /payload/* fetch. 2200004: dns.query catches name resolution even under TLS encryption. Dedicated C2 infra -> very low FP. -->

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - NPM-DEPCONF moika.tech stager C2 X-Secret header"; flow:established,to_server; http.header; content:"X-Secret|3a 20|l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1"; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/; metadata:author Actioner, created_at 2026-05-30; sid:2200001; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - NPM-DEPCONF moika.tech C2 HTTP Host"; flow:established,to_server; http.host; content:"oob.moika.tech"; bsize:14; classtype:trojan-activity; metadata:author Actioner, created_at 2026-05-30; sid:2200002; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - NPM-DEPCONF moika.tech C2 TLS SNI"; flow:established,to_server; tls.sni; content:"oob.moika.tech"; bsize:14; classtype:trojan-activity; metadata:author Actioner, created_at 2026-05-30; sid:2200003; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - NPM-DEPCONF moika.tech C2 DNS query"; dns.query; content:"oob.moika.tech"; bsize:14; classtype:trojan-activity; metadata:author Actioner, created_at 2026-05-30; sid:2200004; rev:1;)
```

### 3. Sigma — DNS query to C2 (DNS telemetry)

Flags DNS lookups to the C2 and lure domains. ✅ compiles · confidence: **high**

<!-- audit: rule at /tmp/dc_dns.yml; sigma convert --without-pipeline -t splunk -> exit 0 AND -t log_scale -> exit 0 (valid SPL: QueryName="oob.moika.tech" OR QueryName IN (...); valid LogScale regex). sigma check exited 1 ONLY due to offline MITRE D3FEND fetch (HTTP 403) -- environment, not rule. category dns_query; matches oob.moika.tech (C2, high) and the *.t-in-one.io lure FQDNs (medium). Technique-only tags per spec. -->

```yaml
title: NPM Dependency-Confusion moika.tech C2/Lure DNS Query
id: 3f2b9c10-4d51-4a7e-9b21-aa01b0901001
status: experimental
description: Detects DNS resolution of the moika.tech C2 or t-in-one.io lure domains used by the npm dependency-confusion campaign.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/
author: Actioner
date: 2026/05/30
tags:
    - attack.t1071.001
    - attack.t1195.003
logsource:
    category: dns_query
detection:
    c2:
        QueryName: 'oob.moika.tech'
    lure:
        QueryName:
            - 'npm.t-in-one.io'
            - 'docs.t-in-one.io'
            - 'jira.t-in-one.io'
    condition: c2 or lure
falsepositives:
    - None expected; dedicated attacker infrastructure
level: high
```

### 4. Sigma — npm postinstall spawns node (process_creation)

Flags an `npm install` driving a `node scripts/postinstall.js` execution. Hunt-only — pair with the moika.tech network anchors. ✅ compiles · confidence: **medium**

<!-- audit: rule at /tmp/dc_proc.yml; sigma convert --without-pipeline -t splunk -> exit 0 AND -t log_scale -> exit 0. sigma check exited 1 ONLY due to offline MITRE D3FEND fetch (HTTP 403) -- environment, not rule. Behavioral backstop for when network IOCs rotate; scoped to postinstall.js filename + npm parent to avoid alerting on ALL postinstall hooks. process_creation alone cannot see the C2 -> correlate with rules 1-3. Technique-only tags. Confidence capped medium (behavioral). Tune CommandLine to environment. -->

```yaml
title: NPM postinstall Hook Executes node scripts/postinstall.js
id: 7c41ad22-9e88-4f0a-bd3c-aa01b0901002
status: experimental
description: Detects a node process launched from an npm postinstall lifecycle hook running scripts/postinstall.js, consistent with the dependency-confusion stager.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/
author: Actioner
date: 2026/05/30
tags:
    - attack.t1059.007
    - attack.t1195.003
    - attack.t1027
logsource:
    category: process_creation
detection:
    node_proc:
        Image|endswith:
            - '\node.exe'
            - '/node'
    postinstall_script:
        CommandLine|contains: 'scripts/postinstall.js'
    parent_npm:
        ParentImage|contains:
            - 'npm'
            - 'node_modules/.bin'
    condition: node_proc and postinstall_script and parent_npm
falsepositives:
    - Legitimate packages with a scripts/postinstall.js build step; correlate with the moika.tech network IOCs to confirm
level: medium
```

### 5. YARA — moika.tech obfuscated stager / dropped init files (file)

Matches the unique C2 string, X-Secret value, and stager recon strings on disk. ✅ compiles · confidence: **high** · sample: fired ✓

<!-- audit: rule at /tmp/dc.yar; yarac /tmp/dc.yar /tmp/dc_out.yarc -> exit 0. Sample-test: yara on /tmp/dc_pos.txt (REAL published strings X-Secret/l95Hd.../oob.moika.tech//payload/linux) FIRED npm_depconf_moika_stager; /tmp/dc_neg.txt (benign) quiet -> sample: fired ✓. Two anchors ($secret, $c2) are campaign-unique. -->

```yara
rule npm_depconf_moika_stager
{
    meta:
        description = "npm dependency-confusion moika.tech postinstall stager / dropped init files"
        author = "Actioner"
        date = "2026-05-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/"
        mitre = "T1195.003,T1027,T1059.007,T1071.001"
    strings:
        $secret = "l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1" ascii
        $c2     = "oob.moika.tech" ascii nocase
        $ep1    = "/payload/win" ascii
        $ep2    = "/payload/mac" ascii
        $ep3    = "/payload/linux" ascii
        $hdr    = "X-Secret" ascii
        $r1     = "process.versions.node" ascii
        $r2     = "os.platform" ascii
    condition:
        $secret or $c2 or
        ( $hdr and 1 of ($ep*) and 1 of ($r*) )
}
```

## Sources

- [Microsoft Security Blog — Malicious npm packages abuse dependency confusion to profile developer environments (2026-05-29)](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/) — primary advisory; source of all IOCs and TTPs in this report
- [SafeDep — 164 npm Packages Target Cloud and Finance via oob.moika.tech](https://safedep.io/oob-moika-tech-dependency-confusion-campaign/) — independent corroboration naming the oob[.]moika[.]tech C2 and the dependency-confusion cluster
- [Sonatype — Inside a 176-Package npm Campaign Built to Beat Your Internal Dependencies](https://www.sonatype.com/blog/inside-a-176-package-npm-campaign-built-to-beat-your-internal-dependencies) — independent analysis of the same high-version dependency-confusion campaign
- [The Hacker News — Malicious Sicoob NuGet Steals Banking Credentials as npm Packages Target Cloud Secrets](https://thehackernews.com/2026/05/malicious-sicoob-nuget-steals-banking.html) — news coverage of the npm cluster targeting cloud/finance scopes
- [MITRE ATT&CK — T1195.003 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/003/) — technique reference for the dependency-confusion vector

<!--
CORROBORATION NOTE: SafeDep and Sonatype independently document the same campaign;
SafeDep explicitly names the oob.moika.tech C2. Per-source scope/package counts differ
(Microsoft "33/~45 across nine scopes"; SafeDep "164"; Sonatype "176") because the cluster
expanded across multiple publishing bursts and each vendor counted at a different time --
the C2, maintainer aliases, and postinstall TTP are consistent across all three.
-->
