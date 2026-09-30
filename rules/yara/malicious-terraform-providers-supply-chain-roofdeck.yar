rule Malware_TraderTraitor_ROOFDECK : tradertraitor dprk macos
{
    meta:
        description = "Detects ROOFDECK ARM64 Rust backdoor deployed as secondary implant by TraderTraitor, featuring Nostr-based C2 and RSA-signed commands"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $path1 = "com.apple.internal.ck" ascii
        $name1 = "iSync" ascii fullword
        $c2_1 = "hubpage.cloud" ascii
        $c2_2 = "grenight.com" ascii
        $nostr1 = "relay.damus.io" ascii
        $nostr2 = "nos.lol" ascii
        $nostr3 = "relay.nostr.band" ascii
        $nostr4 = "nostr.wine" ascii
        $endpoint = "/app_version" ascii
        $cmd1 = "rssh" ascii fullword
        $cmd2 = "persist" ascii fullword
        $cmd3 = "destroy" ascii fullword
        $cmd4 = "clipboard" ascii fullword

    condition:
        filesize < 20MB and
        (
            ($path1 and $name1) or
            (1 of ($c2_*) and 1 of ($nostr*)) or
            ($endpoint and 2 of ($cmd*)) or
            (2 of ($nostr*) and 2 of ($cmd*))
        )
}
