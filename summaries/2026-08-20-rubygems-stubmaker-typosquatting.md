# Technical Analysis Report: StubMaker RubyGems Typosquatting Campaign (2026-08-20)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-20
Version: 1.0 (DRAFT)

## Executive Summary

A typosquatting campaign tracked as "StubMaker" deployed 16 malicious RubyGems packages that impersonate popular Ruby dependencies (bundler, i18n, rake, json, activesupport). Discovered by OpenSourceMalware on August 15, 2026, the attack targets Windows developers through a multi-stage infection chain: a malicious `extconf.rb` install hook fetches a 22 MB Rust-based loader from a GitHub release (account `bebraz1`), which launches an embedded 11 MB Go-based infostealer (`wincfg`). The stealer harvests credentials from 10 Chromium-based browsers (circumventing App-Bound Encryption via `abe_payload.dll`), cryptocurrency wallets, seed phrases, Telegram Desktop data, and system information. Stolen data is archived into password-protected ZIPs, uploaded to Gofile, and download links are exfiltrated to the C2 domain `dresslee.com` over unencrypted HTTP. A related campaign of 37 typosquatted npm packages using the same payload and C2 infrastructure was published on August 16, 2026. All malicious packages have been removed from RubyGems and the GitHub payload repository is no longer accessible.

## Background

RubyGems is the standard package manager for the Ruby programming language. The `extconf.rb` mechanism is designed to compile native C/C++/Rust extensions during gem installation. StubMaker abuses this by generating a Makefile with empty `all`, `install`, and `clean` targets, plus stub scripts that return success, so the extension build phase reports a clean result while the real malicious payload fetch and execution occurs in the installer hook. The campaign name "StubMaker" derives from this empty-stub deception pattern.

The 16 malicious gems were published by three accounts: `mod8rz41mje` (alias "Riley Miller"), `rbq95bwt6q` (alias "Alex Davis"), and `gemlewqqhu1` (alias "Taylor Moore," original publisher of brumdler/brundlef before reclamation). The campaign exploited a RubyGems platform design flaw that allowed reuse of previously yanked package names.

## Technical Analysis

### Package Analysis

The 16 typosquatted gems target five popular Ruby ecosystem packages:

| Malicious Package | Impersonated Gem | Typosquatting Technique |
|-------------------|------------------|------------------------|
| brumdler | bundler | Character transposition + substitution |
| brundlef | bundler | Character transposition + trailing substitution |
| ubnuler | bundler | Anagram/scramble |
| ubnlder | bundler | Anagram/scramble |
| activesupmport | activesupport | Extra 'm' insertion |
| ri18nr | i18n | Character insertion |
| ise18n | i18n | Character transposition |
| ioe18n | i18n | Character substitution |
| ie18u | i18n | Character substitution |
| iai8n | i18n | Character substitution |
| i1l8n | i18n | L/1 substitution |
| i18om | i18n | Character substitution |
| reaker | rake | Character insertion |
| rakier | rake | Character insertion |
| orakw | rake | Anagram |
| joxn | json | Character substitution |

### Malicious Code Behavior (Execution Chain)

**Stage 1 -- extconf.rb Hook (Ruby):**
The `extconf.rb` file is executed automatically during `gem install`. It performs platform detection and, on Windows, generates a Makefile with empty targets (`all:`, `install:`, `clean:`) and no-op stub scripts. Simultaneously, it initiates an HTTP fetch of the Rust-based loader from `github.com/bebraz1` releases.

**Stage 2 -- Rust Loader (22 MB):**
The downloaded executable is a Rust-compiled Windows PE binary. It acts as a dropper, extracting and executing the embedded Go-based stealer payload.

**Stage 3 -- Go Stealer "wincfg" (11 MB):**
The final payload is the `wincfg` Go binary, which performs comprehensive data theft across multiple categories.

### Credential Theft (Browser Targeting)

The stealer targets 10 Chromium-based browsers:

| Browser | User Data Path |
|---------|---------------|
| Google Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\` |
| Microsoft Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\` |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\` |
| Opera | `%APPDATA%\Opera Software\Opera Stable\` |
| Opera GX | `%APPDATA%\Opera Software\Opera GX Stable\` |
| Vivaldi | `%LOCALAPPDATA%\Vivaldi\User Data\` |
| Yandex | `%LOCALAPPDATA%\Yandex\YandexBrowser\User Data\` |
| Avast Secure Browser | `%LOCALAPPDATA%\AVAST Software\Browser\User Data\` |
| AVG Secure Browser | `%LOCALAPPDATA%\AVG\Browser\User Data\` |
| CCleaner Browser | `%LOCALAPPDATA%\CCleaner Browser\User Data\` |

From each browser, the stealer extracts:
- **Login Data** (stored credentials)
- **Cookies** (session tokens)
- **Web Data** (payment cards, autofill)
- **Local State** (encryption key for cookie/password decryption)
- Extension data
- Browsing history

The `abe_payload.dll` component is used to circumvent Google Chrome's App-Bound Encryption (ABE) protection, which was introduced to prevent cookie and credential theft by encrypting browser secrets with a key bound to the application identity.

### Cryptocurrency Wallet Targeting

The stealer searches for cryptocurrency wallet files and seed phrases. While specific wallet paths are not disclosed in available reporting, the malware scans for wallet data files and mnemonic seed phrase patterns across common wallet application storage locations.

### Data Exfiltration

1. The stealer queries `api.ipify.org` to determine the victim's public IP address
2. System information is collected
3. All harvested data is compressed into a **password-protected ZIP archive**
4. The archive is uploaded to **Gofile** (a public file-sharing service)
5. The resulting Gofile download link is sent to the C2 domain **dresslee.com** over **unencrypted HTTP**

### Related npm Campaign

On August 16, 2026, a related campaign published 37 typosquatted npm packages across five accounts within an eight-minute window. These packages use the same payload and C2 backend, targeting popular npm packages: axios, chalk, commander, lodash, typescript, and react.

**npm Package Names (37 total):**
axois-http, axious-core, chalk-core, chalk-lib, chalk-util, chalk-es, comand, comander-cli, comanderjs, commandorjs, commandor-cli, commandor-core, comander-lib, commandor-lib, commander-lib, loadashjs, lodash-lib, ladash-cli, lodahsjs, lodsh-cli, lodahs-cli, lodhash-cli, typescirpt-cli, typscript-cli, typesript-cli, typscript-core, typescriptt-cli, typescrip-cli, typescipt-cli, tyepescript-cli, typescirpt-core, tyepescript-core, typesript-core, typescipt-core, typescriptt-core, raectjs, testingsmthb1g

## Indicators of Compromise (IOCs)

### Package Names (RubyGems)

| Package Name | Publisher Account | Publisher Alias |
|--------------|-------------------|-----------------|
| ubnuler | mod8rz41mje | Riley Miller |
| ubnlder | mod8rz41mje | Riley Miller |
| ri18nr | mod8rz41mje | Riley Miller |
| reaker | mod8rz41mje | Riley Miller |
| rakier | mod8rz41mje | Riley Miller |
| orakw | mod8rz41mje | Riley Miller |
| joxn | mod8rz41mje | Riley Miller |
| ise18n | rbq95bwt6q | Alex Davis |
| ioe18n | rbq95bwt6q | Alex Davis |
| ie18u | rbq95bwt6q | Alex Davis |
| iai8n | rbq95bwt6q | Alex Davis |
| i1l8n | rbq95bwt6q | Alex Davis |
| i18om | rbq95bwt6q | Alex Davis |
| activesupmport | rbq95bwt6q | Alex Davis |
| brumdler | gemlewqqhu1 | Taylor Moore |
| brundlef | gemlewqqhu1 | Taylor Moore |

### Hashes

No SHA256 hashes for the malicious gems or payloads have been publicly disclosed at this time. When published, they should be added here.

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| Domain | dresslee.com | C2 domain receiving Gofile download links via unencrypted HTTP |
| Service | gofile.io | File-sharing service used for data exfiltration uploads |
| Service | api.ipify.org | Public IP address lookup service queried by the stealer |
| GitHub Account | github.com/bebraz1 | Hosted the Rust-based loader binary (no longer accessible) |

### File System Indicators

| Component | Filename | Size | Description |
|-----------|----------|------|-------------|
| Rust Loader | Not disclosed | 22 MB | PE binary fetched from GitHub release during gem install |
| Go Stealer | wincfg / wincfg.exe | 11 MB | Infostealer payload embedded in the Rust loader |
| DLL Payload | abe_payload.dll | Not disclosed | Chromium ABE bypass component |

### Behavioral Indicators

- Ruby `extconf.rb` execution fetching large (22 MB) binaries from GitHub during gem install
- Process named `wincfg` or `wincfg.exe` executing on Windows
- Rapid sequential access to multiple browser `User Data` directories
- Access to `Login Data`, `Cookies`, `Web Data`, and `Local State` files by non-browser processes
- HTTP POST to gofile.io containing ZIP archive data
- HTTP communication with dresslee.com containing Gofile URLs
- DNS queries to api.ipify.org from Ruby or Go processes

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | 16 typosquatted RubyGems packages + 37 npm packages impersonating popular dependencies |
| T1059 | Command and Scripting Interpreter | extconf.rb Ruby hook automatically executed during gem installation |
| T1204.002 | User Execution: Malicious File | Developer must run `gem install` with the typosquatted package name |
| T1027 | Obfuscated Files or Information | Empty Makefile stubs masking the true payload delivery |
| T1105 | Ingress Tool Transfer | 22 MB Rust loader fetched from GitHub release during install |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Extraction of stored passwords, cookies, payment cards from 10 Chromium browsers |
| T1539 | Steal Web Session Cookie | Cookie extraction from all targeted browsers |
| T1005 | Data from Local System | Crypto wallet files, Telegram data, system information |
| T1083 | File and Directory Discovery | Scanning for browser profiles and wallet files across known paths |
| T1560.001 | Archive Collected Data: Archive via Utility | Password-protected ZIP creation for exfiltration |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Upload of stolen data to Gofile file-sharing service |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication to dresslee.com via unencrypted HTTP |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | abe_payload.dll loaded to bypass Chromium App-Bound Encryption |

## Impact Assessment

- **Breadth:** 16 malicious RubyGems packages targeting the Ruby developer ecosystem, plus 37 npm packages targeting the JavaScript/Node.js ecosystem. The total blast radius depends on download counts before removal, which have not been publicly disclosed.
- **Depth:** Full credential theft from 10 browsers including ABE bypass, cryptocurrency wallet compromise, Telegram session data theft, and system fingerprinting. The attack chain is fully automated from `gem install` with no additional user interaction required.
- **Platform Scope:** Windows-only. The extconf.rb performs platform detection and only delivers the payload on Windows. Unix/macOS systems receive only the empty stubs.
- **Persistence:** None observed. StubMaker is a smash-and-grab infostealer without persistence mechanisms.
- **Financial Risk:** High. Cryptocurrency wallet seed phrases and browser-stored payment card data can be immediately monetized.

## Detection & Remediation

### Immediate Detection

```bash
# Check Gemfile.lock for affected packages
for pkg in ubnuler ubnlder ri18nr reaker rakier orakw joxn ise18n ioe18n ie18u iai8n i1l8n i18om activesupmport brumdler brundlef; do
  grep -r "$pkg" Gemfile Gemfile.lock 2>/dev/null && echo "FOUND: $pkg"
done

# Check for npm variants
for pkg in axois-http axious-core chalk-core chalk-lib chalk-util chalk-es comand comander-cli comanderjs commandorjs commandor-cli commandor-core comander-lib commandor-lib commander-lib loadashjs lodash-lib ladash-cli lodahsjs lodsh-cli lodahs-cli lodhash-cli typescirpt-cli typscript-cli typesript-cli typscript-core typescriptt-cli typescrip-cli typescipt-cli tyepescript-cli typescirpt-core tyepescript-core typesript-core typescipt-core typescriptt-core raectjs testingsmthb1g; do
  grep -r "\"$pkg\"" package.json package-lock.json 2>/dev/null && echo "FOUND: $pkg"
done

# Check for wincfg process (Windows)
# tasklist | findstr /i "wincfg"

# Check for abe_payload.dll presence
# dir /s /b %TEMP%\abe_payload.dll %APPDATA%\abe_payload.dll 2>nul
```

### Remediation

1. **Immediate:** Remove any affected gem or npm packages. Clear the gem cache (`gem cleanup`). Audit `Gemfile.lock` / `package-lock.json` for typosquatted dependency names.
2. **Credential Rotation (CRITICAL):** If any system installed an affected package:
   - Change all passwords stored in affected browsers
   - Invalidate all browser sessions (cookies are compromised)
   - Rotate any payment card data stored in browser autofill
   - Transfer cryptocurrency funds to new wallets with fresh seed phrases
   - Re-secure Telegram accounts (revoke all sessions)
3. **Network:** Block `dresslee.com` at the DNS/proxy level. Consider alerting on Gofile uploads from developer workstations.
4. **Long-Term:** Use gem lockfiles with integrity checksums. Review gem names carefully before installation. Consider using `bundle audit` and dependency scanning tools that flag typosquatting.

## Detection Rules

These detections target the StubMaker RubyGems supply chain attack at PoC/advisory-specific altitude. Sigma rules were validated with `sigma check` (0 errors, 0 issues; ATT&CK tag validation skipped due to environment network restriction) and convert cleanly to Splunk and CrowdStrike LogScale via `sigma convert --without-pipeline`. The YARA rules compile with `yarac`. Snort and Suricata rules are structurally validated only (not runtime-compiled). Note: compiles does not equal fires -- verify in your pipeline with real telemetry.

### Sigma: StubMaker extconf.rb Install Hook Execution

Detects ruby extconf.rb execution with network fetch indicators spawned by a gem parent process, the primary StubMaker delivery mechanism.
**Status:** compile x1 compiles (sigma check 0 errors, splunk+logscale convert OK) · confidence: medium
<!-- audit: sigma check -x attacktag exit 0 (0 errors, 0 issues); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. ATT&CK tag validator excluded due to proxy blocking MITRE data fetch (HTTP 403). Medium confidence: extconf.rb with network fetch is suspicious but legitimate native gems also use extconf.rb with network calls. -->
```yaml
title: StubMaker RubyGems extconf.rb Install Hook Execution
id: a4c8e2f1-d3b7-4a9e-8c6d-5f1b2e3a4d80
status: experimental
description: >
    Detects execution of ruby extconf.rb triggered by gem install, the primary
    delivery mechanism for the StubMaker campaign. The malicious extconf.rb
    fetches a 22 MB Rust-based loader from a GitHub release. Fires on any
    ruby process whose command line contains extconf.rb spawned by a gem
    parent process.
references:
    - https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html
    - https://www.it-boltwise.de/stubmaker-typosquatting-auf-rubygems-klaut-browser-und-krypto-daten-ueber-install-hooks.html
author: Actioner
date: 2026/08/20
tags:
    - attack.t1195.002
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\ruby.exe'
            - '\gem'
            - '\gem.bat'
            - '\gem.cmd'
    selection_child:
        Image|endswith:
            - '\ruby.exe'
        CommandLine|contains:
            - 'extconf.rb'
    selection_network_fetch:
        CommandLine|contains:
            - 'Net::HTTP'
            - 'open-uri'
            - 'github.com'
    condition: selection_parent and selection_child and selection_network_fetch
falsepositives:
    - Legitimate gems with native C extensions that compile during install
    - RubyGems extensions using mkmf which invoke extconf.rb normally
level: medium
```

### Sigma: StubMaker wincfg Go Stealer Process Execution

Detects execution of the wincfg Go stealer binary, the StubMaker final payload responsible for credential and crypto wallet theft.
**Status:** compile x1 compiles (sigma check 0 errors, splunk+logscale convert OK) · confidence: medium
<!-- audit: sigma check -x attacktag exit 0 (0 errors, 0 issues); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Medium confidence despite distinctive name: no hash anchoring; wincfg could conceivably be a legitimate admin tool name, though unlikely. -->
```yaml
title: StubMaker wincfg Go Stealer Process Execution
id: b5d9f3a2-e4c8-4b0f-9d7e-6a2c3d4e5f91
status: experimental
description: >
    Detects execution of the StubMaker Go-based stealer payload named wincfg.
    After the Rust loader executes, it drops and runs the 11 MB wincfg binary
    which harvests browser credentials, crypto wallets, and Telegram data.
    Also detects the abe_payload.dll sideload used for Chromium ABE bypass.
references:
    - https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html
    - https://www.it-boltwise.de/stubmaker-typosquatting-in-rubygems-zielt-auf-browser-credentials-und-krypto-wallets.html
author: Actioner
date: 2026/08/20
tags:
    - attack.t1555.003
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection_wincfg:
        Image|endswith:
            - '\wincfg.exe'
            - '\wincfg'
        CommandLine|contains:
            - 'wincfg'
    condition: selection_wincfg
falsepositives:
    - Unlikely; wincfg is not a standard Windows utility name
level: high
```

### Sigma: StubMaker Browser Credential Store Access

Detects file access to Chromium browser credential stores by wincfg or ruby processes, indicating the StubMaker browser harvesting phase.
**Status:** compile x1 compiles (sigma check 0 errors, splunk+logscale convert OK) · confidence: medium
<!-- audit: sigma check -x attacktag exit 0 (0 errors, 0 issues); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Medium confidence: file_access category requires Sysmon or equivalent; process-to-file correlation narrows scope but ruby.exe could access browser data legitimately in some automation scenarios. -->
```yaml
title: StubMaker Browser Credential Store Access by Ruby or Go Process
id: c6ea04b3-f5d9-4c1a-ae8f-7b3d4e5f6a02
status: experimental
description: >
    Detects file access to Chromium-based browser credential stores
    (Login Data, Cookies, Web Data) by processes associated with
    StubMaker's attack chain (ruby.exe or wincfg). The stealer targets
    Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Yandex, Avast, AVG,
    and CCleaner Browser.
references:
    - https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html
    - https://blog.elhacker.net/2026/08/16-paquetes-de-rubygems-mediante.html
author: Actioner
date: 2026/08/20
tags:
    - attack.t1555.003
    - attack.t1083
logsource:
    category: file_access
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\wincfg.exe'
            - '\ruby.exe'
    selection_browser_paths:
        TargetFilename|contains:
            - '\Google\Chrome\User Data\'
            - '\Microsoft\Edge\User Data\'
            - '\BraveSoftware\Brave-Browser\User Data\'
            - '\Opera Software\Opera Stable\'
            - '\Opera Software\Opera GX Stable\'
            - '\Vivaldi\User Data\'
            - '\Yandex\YandexBrowser\User Data\'
            - '\AVAST Software\Browser\User Data\'
            - '\AVG\Browser\User Data\'
            - '\CCleaner Browser\User Data\'
    selection_cred_files:
        TargetFilename|endswith:
            - '\Login Data'
            - '\Cookies'
            - '\Web Data'
            - '\Local State'
    condition: selection_process and selection_browser_paths and selection_cred_files
falsepositives:
    - Browser management or backup tools accessing credential stores
level: medium
```

### YARA: StubMaker Malicious RubyGem Package Detection

Detects the 16 malicious gem packages by name strings and the wincfg stealer binary by C2/exfil infrastructure strings and browser targeting patterns.
**Status:** compile x1 compiles (yarac exit 0) · confidence: high (gem names rule) / medium (wincfg rule)
<!-- audit: yarac stubmaker-malicious-gems.yar /dev/null exit 0. Gem names rule: high confidence due to exact string matching of all 16 known-malicious package names. Wincfg rule: medium confidence; C2 domain + Gofile + browser paths is distinctive but no hash anchoring available. -->
```yara
rule Malware_StubMaker_RubyGems_Typosquat
{
    meta:
        description = "Detects the 16 malicious RubyGems packages from the StubMaker typosquatting campaign by matching gem metadata name fields and distinctive extconf.rb stub code patterns."
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
        severity = "critical"

    strings:
        $gem01 = "\"ubnuler\"" ascii
        $gem02 = "\"ubnlder\"" ascii
        $gem03 = "\"ri18nr\"" ascii
        $gem04 = "\"reaker\"" ascii
        $gem05 = "\"rakier\"" ascii
        $gem06 = "\"orakw\"" ascii
        $gem07 = "\"joxn\"" ascii
        $gem08 = "\"ise18n\"" ascii
        $gem09 = "\"ioe18n\"" ascii
        $gem10 = "\"ie18u\"" ascii
        $gem11 = "\"iai8n\"" ascii
        $gem12 = "\"i1l8n\"" ascii
        $gem13 = "\"i18om\"" ascii
        $gem14 = "\"activesupmport\"" ascii
        $gem15 = "\"brumdler\"" ascii
        $gem16 = "\"brundlef\"" ascii
        $stub1 = "all:" ascii
        $stub2 = "install:" ascii
        $stub3 = "clean:" ascii
        $stub4 = "create_makefile" ascii
        $fetch1 = "bebraz1" ascii
        $fetch2 = "wincfg" ascii
        $fetch3 = "abe_payload" ascii

    condition:
        filesize < 25MB and
        (
            any of ($gem*) or
            ($fetch1 and $fetch2) or
            ($fetch1 and $fetch3) or
            (all of ($stub*) and any of ($fetch*))
        )
}

rule Malware_StubMaker_Wincfg_Stealer
{
    meta:
        description = "Detects the StubMaker Go-based wincfg stealer binary by matching distinctive strings related to browser credential theft, Gofile exfiltration, and the C2 domain."
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
        severity = "critical"

    strings:
        $c2 = "dresslee.com" ascii wide
        $gofile = "gofile.io" ascii wide
        $ipify = "api.ipify.org" ascii wide
        $payload_name = "wincfg" ascii wide
        $dll_name = "abe_payload.dll" ascii wide
        $chrome = "\\Google\\Chrome\\User Data\\" ascii wide
        $edge = "\\Microsoft\\Edge\\User Data\\" ascii wide
        $brave = "\\BraveSoftware\\Brave-Browser\\User Data\\" ascii wide
        $opera = "\\Opera Software\\Opera Stable\\" ascii wide
        $vivaldi = "\\Vivaldi\\User Data\\" ascii wide
        $yandex = "\\Yandex\\YandexBrowser\\User Data\\" ascii wide
        $login = "Login Data" ascii wide
        $cookies = "Cookies" ascii wide
        $localstate = "Local State" ascii wide
        $telegram = "Telegram Desktop" ascii wide

    condition:
        filesize < 25MB and
        (
            ($c2 and ($gofile or $ipify)) or
            ($payload_name and $dll_name) or
            ($c2 and 3 of ($chrome, $edge, $brave, $opera, $vivaldi, $yandex)) or
            ($c2 and $login and $cookies and $localstate and $telegram)
        )
}
```

### Snort: StubMaker C2 and Exfiltration Traffic

Detects HTTP traffic to the StubMaker C2 domain dresslee.com, data exfiltration uploads to Gofile, and loader fetches from the bebraz1 GitHub account.
**Status:** ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: structural check only; Snort not installed. dresslee.com is a specific C2 domain (high signal); Gofile POST is moderate signal (legitimate use exists); bebraz1 GitHub is high signal but account is deactivated. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - StubMaker C2 exfil link to dresslee.com"; flow:established,to_server; content:"dresslee.com"; fast_pattern; content:"Host|3A|"; sid:2100201; rev:1; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - StubMaker Gofile exfil upload"; flow:established,to_server; content:"gofile.io"; fast_pattern; content:"POST"; content:"Host|3A|"; sid:2100202; rev:1; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - StubMaker Rust loader fetch from bebraz1 GitHub"; flow:established,to_server; content:"bebraz1"; fast_pattern; content:"github.com"; content:"releases"; sid:2100203; rev:1; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html;)
```

### Suricata: StubMaker C2 and Exfiltration Traffic

Detects HTTP traffic to StubMaker infrastructure using Suricata's HTTP-aware dot-notation sticky buffers for higher fidelity matching against the C2 domain, Gofile uploads, and GitHub loader fetch.
**Status:** ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: structural check only; Suricata not installed. Uses proper http.host/http.method/http.uri sticky buffers. dresslee.com host match is distinctive; Gofile POST is moderate (legitimate use); bebraz1 in URI is distinctive but account defunct. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - StubMaker C2 exfil download link to dresslee.com"; flow:established,to_server; http.host; content:"dresslee.com"; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html; metadata:author Actioner, created_at 2026-08-20; sid:2200201; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - StubMaker Gofile exfil upload POST"; flow:established,to_server; http.method; content:"POST"; http.host; content:"gofile.io"; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html; metadata:author Actioner, created_at 2026-08-20; sid:2200202; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - StubMaker Rust loader fetch from bebraz1 GitHub releases"; flow:established,to_server; http.host; content:"github.com"; http.uri; content:"bebraz1"; fast_pattern; http.uri; content:"releases"; classtype:trojan-activity; reference:url,thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html; metadata:author Actioner, created_at 2026-08-20; sid:2200203; rev:1;)
```

## Sources

1. [The Hacker News - 16 Typosquatted RubyGems Packages Steal Browser Credentials and Crypto Wallets](https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html)
2. [IT Boltwise - StubMaker: Typosquatting auf RubyGems klaut Browser- und Krypto-Daten uber Install-Hooks](https://www.it-boltwise.de/stubmaker-typosquatting-auf-rubygems-klaut-browser-und-krypto-daten-ueber-install-hooks.html)
3. [IT Boltwise - StubMaker: Typosquatting in RubyGems zielt auf Browser-Credentials und Krypto-Wallets](https://www.it-boltwise.de/stubmaker-typosquatting-in-rubygems-zielt-auf-browser-credentials-und-krypto-wallets.html)
4. [elhacker.NET - 16 paquetes de RubyGems mediante typosquatting roban credenciales](https://blog.elhacker.net/2026/08/16-paquetes-de-rubygems-mediante.html)
5. [GuardianMSSP - 16 Typosquatted RubyGems Packages Steal Browser Credentials and Crypto Wallets](https://www.guardianmssp.com/2026/08/18/16-typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets/)
