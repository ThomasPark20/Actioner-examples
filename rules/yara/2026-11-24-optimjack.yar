rule OPTIMJACK_TrackJS_Payload
{
    meta:
        description = "Detects OPTIMJACK track.js payload - crypto clipper, card skimmer, and screenshot collector"
        author = "Actioner"
        date = "2026-11-24"
        reference = "https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer"
        hash1 = "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3"
        hash2 = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"

    strings:
        $domain1 = "1688360.cc" ascii wide
        $domain2 = "1688360.cc/track.js" ascii wide
        $domain3 = "1688360.cc/card.php" ascii wide
        $domain4 = "1688360.cc/hit.php" ascii wide

        $global1 = "window._k7" ascii
        $global2 = "window.__k7b" ascii
        $global3 = "window._cc" ascii
        $global4 = "window._qxc" ascii
        $global5 = "window._shot" ascii

        $wallet_eth = "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e" ascii wide nocase
        $wallet_btc = "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW" ascii wide
        $wallet_trx = "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa" ascii wide
        $wallet_sol = "FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n" ascii wide
        $wallet_ltc = "ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5" ascii wide
        $wallet_ton = "UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p" ascii wide
        $wallet_bch = "qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58" ascii wide
        $wallet_doge = "DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5" ascii wide

    condition:
        any of ($domain*) or
        3 of ($global*) or
        any of ($wallet*)
}

rule OPTIMJACK_Loader_ProjectJS
{
    meta:
        description = "Detects OPTIMJACK loader injected into Optimizely Project JavaScript field"
        author = "Actioner"
        date = "2026-11-24"
        reference = "https://www.reversinglabs.com/blog/optimjack-when-trusted-javascript-becomes-a-supply-chain-attack"

    strings:
        $loader_url = "1688360.cc/track.js" ascii wide
        $channel = "data-channel-code" ascii
        $channel_val = "02111110" ascii

        $icu_domain1 = "5vobauua3ojpklx.icu" ascii wide
        $icu_domain2 = "eil786npto9u5bq.icu" ascii wide
        $icu_domain3 = "l7bcsnwc7nzr3uo.icu" ascii wide
        $icu_domain4 = "ios-hack.icu" ascii wide
        $icu_domain5 = "je4ft3gn8vxudum.icu" ascii wide

    condition:
        $loader_url or
        ($channel and $channel_val) or
        (2 of ($icu_domain*))
}

rule OPTIMJACK_iOS_ExploitKit_Loader
{
    meta:
        description = "Detects OPTIMJACK iOS exploit kit loader (boot.js) targeting Coruna and DarkSword chains"
        author = "Actioner"
        date = "2026-11-24"
        reference = "https://www.zscaler.com/blogs/security-research/attackers-exploit-optimizely-flaw-inject-malicious-javascript"

    strings:
        $path1 = "/JIUJIU888/weifile.html" ascii wide
        $path2 = "/JIUJIU888/index.js" ascii wide
        $path3 = "/A8/a.html" ascii wide
        $path4 = "/B9/b.html" ascii wide
        $path5 = "/D11/b.html" ascii wide
        $path6 = "/C10/c.html" ascii wide
        $path7 = "boot.js" ascii wide

        $channel = "data-channel-code" ascii
        $chain_url = "data-chain-url" ascii

        $icu1 = "5vobauua3ojpklx.icu" ascii wide
        $icu2 = "eil786npto9u5bq.icu" ascii wide
        $icu3 = "ios-hack.icu" ascii wide
        $icu4 = "q1ls1ho9x7wsxlu.icu" ascii wide

        $keychain = "keychain-2.db" ascii wide

    condition:
        2 of ($path*) or
        ($channel and $chain_url) or
        (any of ($icu*) and $path7) or
        ($keychain and (any of ($icu*) or any of ($path1, $path2, $path3, $path4, $path5, $path6)))
}

rule OPTIMJACK_CardSkimmer_Behavior
{
    meta:
        description = "Detects OPTIMJACK card skimmer behavioral patterns in JavaScript"
        author = "Actioner"
        date = "2026-11-24"
        reference = "https://phoenix.security/optimjack-optimizely-supply-chain-attack-card-skimmer-ios/"

    strings:
        $beacon = "navigator.sendBeacon" ascii
        $card_php = "/card.php" ascii
        $hit_php = "/hit.php" ascii
        $html2canvas = "html2canvas" ascii
        $cookie_capture = "document.cookie" ascii

        $session_set_cc = "sessionStorage.setItem(\"cc_\"" ascii
        $session_get_cc = "sessionStorage.getItem(\"cc_\"" ascii

        $fn_call = "Function.prototype.call" ascii
        $fn_apply = "Function.prototype.apply" ascii

        $sendBeacon = "sendBeacon" ascii

    condition:
        ($beacon and $card_php) or
        ($hit_php and $html2canvas and $cookie_capture) or
        (($session_set_cc or $session_get_cc) and ($fn_call or $fn_apply)) or
        ($card_php and $sendBeacon and $html2canvas)
}

import "hash"

rule OPTIMJACK_TrackJS_SHA256
{
    meta:
        description = "Detects known OPTIMJACK track.js samples by SHA256 hash"
        author = "Actioner"
        date = "2026-11-24"
        reference = "https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer"

    condition:
        hash.sha256(0, filesize) == "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3" or
        hash.sha256(0, filesize) == "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40" or
        hash.sha256(0, filesize) == "c2a34c579e4c2e8802752c93b3a9cca0230610f3e4dd6688f4272459c7c7c162" or
        hash.sha256(0, filesize) == "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f"
}
