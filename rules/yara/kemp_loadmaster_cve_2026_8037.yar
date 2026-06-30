rule Exploit_CVE_2026_8037_LoadMaster_AccessV2_Payload
{
    meta:
        description = "Detects HTTP request payloads targeting the Progress Kemp LoadMaster /accessv2 API endpoint with command injection patterns consistent with CVE-2026-8037 exploitation. The exploit sends JSON POST bodies containing apiuser/apipass credentials alongside heap-spray keys (g0-g16) with shell breakout payloads. This rule matches against HTTP request captures, PCAP content, or WAF logs containing the raw request body."
        author = "Actioner"
        date = "2026-06-30"
        reference = "https://thehackernews.com/2026/06/progress-kemp-loadmaster-flaw-could-let.html"
        reference_watchtower = "https://labs.watchtowr.com/enterprise-tech-in-shell-out-progress-kemp-loadmaster-uninitialized-heap-to-pre-auth-rce-cve-2026-8037/"
        cve = "CVE-2026-8037"
        severity = "critical"

    strings:
        $uri = "/accessv2" ascii nocase
        $method = "POST" ascii
        $apiuser = "\"apiuser\"" ascii nocase
        $apipass = "\"apipass\"" ascii nocase

        // Heap spray JSON keys from watchTowr PoC
        $spray_g0 = "\"g0\"" ascii
        $spray_g1 = "\"g1\"" ascii
        $spray_g2 = "\"g2\"" ascii
        $spray_g3 = "\"g3\"" ascii

        // Command injection breakout patterns
        $inj1 = "'; " ascii
        $inj2 = "';cat " ascii
        $inj3 = "';/bin/" ascii
        $inj4 = "';curl " ascii
        $inj5 = "';wget " ascii
        $inj6 = "';echo " ascii
        $inj7 = "';id" ascii
        $inj8 = "';python" ascii
        $inj9 = "';bash " ascii
        $inj10 = "';nc " ascii

        // /etc/passwd read (common PoC payload)
        $passwd = "/etc/passwd" ascii

    condition:
        filesize < 1MB and
        $uri and $method and
        ($apiuser or $apipass) and
        (
            (2 of ($spray_*) and 1 of ($inj*)) or
            ($apiuser and 1 of ($inj*) and $passwd)
        )
}

rule Exploit_CVE_2026_8037_LoadMaster_PostExploit_Webshell
{
    meta:
        description = "Detects potential web shell or backdoor scripts deployed on a compromised Progress Kemp LoadMaster appliance following CVE-2026-8037 exploitation. This rule requires at least one LoadMaster-specific string (Kemp paths, binaries, or CVE reference) alongside reverse shell or persistence indicators to reduce false positives on generic admin scripts."
        author = "Actioner"
        date = "2026-06-30"
        reference = "https://thehackernews.com/2026/06/progress-kemp-loadmaster-flaw-could-let.html"
        cve = "CVE-2026-8037"
        severity = "medium"

    strings:
        // Shell script backdoor indicators
        $sh1 = "#!/bin/bash" ascii
        $sh2 = "#!/bin/sh" ascii
        $sh3 = "#!/usr/bin/env python" ascii
        $sh4 = "#!/usr/bin/perl" ascii

        // LoadMaster / CVE-specific strings (required to anchor to this CVE)
        $kemp1 = "/opt/kemp/" ascii
        $kemp2 = "balcfg" ascii
        $kemp3 = "lmadmin" ascii
        $kemp4 = "accessv2" ascii nocase
        $kemp5 = "CVE-2026-8037" ascii nocase
        $kemp6 = "loadmaster" ascii nocase

        // Reverse shell patterns
        $rev1 = "bash -i >& /dev/tcp/" ascii
        $rev2 = "nc -e /bin/" ascii
        $rev3 = "python -c 'import socket" ascii
        $rev4 = "mkfifo /tmp/" ascii

        // Persistence mechanisms
        $pers1 = "crontab" ascii
        $pers2 = "/etc/cron" ascii
        $pers3 = "authorized_keys" ascii

    condition:
        filesize < 100KB and
        (1 of ($sh*)) and
        (1 of ($kemp*)) and
        (1 of ($rev*) or 1 of ($pers*))
}
