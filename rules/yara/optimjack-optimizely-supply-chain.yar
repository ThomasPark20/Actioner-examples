rule Supply_Chain_OPTIMJACK_TrackJS
{
    meta:
        description = "Detects OPTIMJACK malicious JavaScript payload (track.js) used in the Optimizely supply chain attack. Matches crypto-clipper markers, card skimming patterns, and exfiltration endpoints."
        author = "Actioner"
        date = "2026-11-21"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        hash = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        hash2 = "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $marker1 = "window._k7" ascii
        $marker2 = "window.__k7b" ascii
        $c2_domain = "1688360.cc" ascii
        $exfil_card = "/card.php" ascii
        $exfil_hit = "/hit.php" ascii
        $track_path = "/track.js" ascii
        $channel = "02111110" ascii
        $coruna_marker = "BIGNIAO" ascii
        $wallet_btc = "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW" ascii
        $wallet_eth = "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e" ascii
        $wallet_tron = "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa" ascii
        $wallet_sol = "FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n" ascii
        $icu_domain1 = "5vobauua3ojpklx.icu" ascii
        $icu_domain2 = "eil786npto9u5bq.icu" ascii
        $skimmer_fn = "sendBeacon" ascii
        $swap_keyword1 = "wallet" ascii nocase
        $swap_keyword2 = "deposit" ascii nocase
        $obfuscation = "atob(" ascii

    condition:
        filesize < 2MB and
        (
            ($c2_domain and 2 of ($exfil_card, $exfil_hit, $track_path)) or
            (2 of ($marker1, $marker2, $channel, $coruna_marker)) or
            (any of ($wallet_*) and $skimmer_fn) or
            ($c2_domain and any of ($wallet_*)) or
            (any of ($icu_domain*) and $obfuscation) or
            ($skimmer_fn and any of ($swap_keyword*) and any of ($wallet_*))
        )
}

rule Supply_Chain_OPTIMJACK_Injector
{
    meta:
        description = "Detects OPTIMJACK injector code planted in Optimizely Project JavaScript fields. Matches loader patterns that dynamically create script elements pointing to attacker C2 or use base64-encoded URLs with eval fallback."
        author = "Actioner"
        date = "2026-11-21"
        reference = "https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/"
        hash = "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $c2_plain = "1688360.cc/track.js" ascii
        $c2_domain = "1688360.cc" ascii
        $injector_domain = "webshell.lol" ascii
        $injector_path = "webshell.lol/get.js" ascii
        $dynamic_script1 = "createElement" ascii
        $dynamic_script2 = "document.head" ascii
        $obfuscation1 = "atob(" ascii
        $eval_fallback = "eval(" ascii
        $marker1 = "window._k7" ascii
        $marker2 = "window.__k7b" ascii
        $linkforge = "linkforge.cc" ascii

    condition:
        filesize < 5MB and
        (
            $c2_plain or
            $injector_path or
            ($c2_domain and $dynamic_script1 and $dynamic_script2) or
            ($injector_domain and $dynamic_script1) or
            ($obfuscation1 and $eval_fallback and any of ($marker*)) or
            ($linkforge and $dynamic_script1)
        )
}
