rule OPTIMJACK_TrackJS_Payload
{
    meta:
        description = "Detects OPTIMJACK track.js payload variants used in the Optimizely supply chain attack (November 2026)"
        author = "Actioner Research"
        date = "2026-11-20"
        reference = "https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/"
        hash1 = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        hash2 = "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f"

    strings:
        $domain1 = "1688360.cc" ascii wide
        $domain2 = "webshell.lol" ascii wide
        $path_track = "/track.js" ascii
        $path_card = "/card.php" ascii
        $path_hit = "/hit.php" ascii
        $marker1 = "window._k7" ascii
        $marker2 = "window.__k7b" ascii
        $channel = "02111110" ascii
        $b64_payload = "aHR0cHM6Ly8xNjg4MzYw" ascii
        $ios_domain1 = "5vobauua3ojpklx.icu" ascii wide
        $ios_domain2 = "eil786npto9u5bq.icu" ascii wide

    condition:
        any of ($domain1, $domain2) and any of ($path_track, $path_card, $path_hit, $marker1, $marker2)
        or $b64_payload
        or $channel and any of ($ios_domain1, $ios_domain2)
}

rule OPTIMJACK_Loader_Variants
{
    meta:
        description = "Detects OPTIMJACK JavaScript loader variants injected into Optimizely project snippets"
        author = "Actioner Research"
        date = "2026-11-20"
        reference = "https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/"
        hash = "123f813b18cf5a3b513beabd52a110e19f1c7834f2aa9b972633b2214c57e737"

    strings:
        $loader_direct = "1688360.cc/track.js" ascii wide
        $loader_b64 = "aHR0cHM6Ly8xNjg4MzYwLmNjL3RyYWNrLmpz" ascii
        $embedded_hash = "c2a34c579e4c2e8802752c93b3a9cca0230610f3e4dd6688f4272459c7c7c162" ascii
        $getjs = "webshell.lol/get.js" ascii wide
        $linkforge = "linkforge.cc" ascii wide
        $marker_k7 = "window._k7" ascii
        $marker_k7b = "window.__k7b" ascii
        $atob_pattern = "atob(" ascii
        $eval_pattern = "eval(" ascii
        $createElement = "createElement" ascii

    condition:
        any of ($loader_direct, $loader_b64, $embedded_hash, $getjs, $linkforge)
        or ($marker_k7 and $marker_k7b and ($atob_pattern or $eval_pattern) and $createElement)
}

rule OPTIMJACK_CryptoClipper_Wallets
{
    meta:
        description = "Detects cryptocurrency wallet addresses used by the OPTIMJACK attacker for fund theft"
        author = "Actioner Research"
        date = "2026-11-20"
        reference = "https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/"

    strings:
        $btc = "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW" ascii wide
        $eth = "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e" ascii wide nocase
        $tron = "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa" ascii wide
        $sol = "FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n" ascii wide
        $ton = "UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p" ascii wide
        $ltc = "ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5" ascii wide
        $bch = "qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58" ascii wide
        $doge = "DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5" ascii wide
        $cashout_tron = "TMLQvDvpgSyx94maptc3TxvmCVtT5qHVup" ascii wide

    condition:
        any of them
}
