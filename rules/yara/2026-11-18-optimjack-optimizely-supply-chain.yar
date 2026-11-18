import "hash"

rule SupplyChain_OPTIMJACK_TrackJS_Payload
{
    meta:
        description = "Detects OPTIMJACK malicious track.js payload used in Optimizely supply chain attack. Matches crypto clipper, card skimmer, and screenshot theft markers."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $marker1 = "window._k7" ascii
        $marker2 = "window._cc" ascii
        $marker3 = "window._qxc" ascii
        $marker4 = "window._shot" ascii
        $marker5 = "window.__k7b" ascii

        $exfil1 = "/card.php" ascii
        $exfil2 = "/hit.php" ascii
        $exfil3 = "html2canvas" ascii

        $c2_1 = "1688360.cc" ascii
        $c2_2 = "1688360" ascii

        $wallet_eth = "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e" ascii nocase
        $wallet_btc = "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW" ascii
        $wallet_trx = "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa" ascii

        $func1 = "navigator.sendBeacon" ascii
        $func2 = "Function.prototype.call" ascii
        $func3 = "Function.prototype.apply" ascii
        $func4 = "navigator.clipboard" ascii

    condition:
        filesize < 1MB and
        (
            (3 of ($marker*)) or
            (1 of ($c2*) and 1 of ($exfil*)) or
            (2 of ($wallet*) and 1 of ($func*)) or
            (2 of ($marker*) and 1 of ($exfil*))
        )
}

rule SupplyChain_OPTIMJACK_BootJS_iOS_Loader
{
    meta:
        description = "Detects OPTIMJACK boot.js iOS exploit kit loader that fingerprints iOS version and loads Coruna or DarkSword exploit chains in hidden iframes."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $channel = "02111110" ascii
        $marker = "BIGNIAO" ascii
        $path1 = "JIUJIU888" ascii
        $path2 = "/boot.js" ascii
        $path3 = "rce_loader" ascii
        $path4 = "rce_worker" ascii
        $path5 = "weifile.html" ascii
        $path6 = "data-channel-code" ascii

        $domain1 = "eil786npto9u5bq" ascii
        $domain2 = "5vobauua3ojpklx" ascii
        $domain3 = "l7bcsnwc7nzr3uo" ascii

        $ios_check = "iPhone" ascii
        $ios_check2 = "iPad" ascii

    condition:
        filesize < 500KB and
        (
            (2 of ($path*) and 1 of ($domain*)) or
            ($marker and 1 of ($path*)) or
            ($channel and 1 of ($domain*)) or
            (1 of ($domain*) and $path1 and ($ios_check or $ios_check2))
        )
}

rule SupplyChain_OPTIMJACK_Known_Hashes
{
    meta:
        description = "Detects known OPTIMJACK malicious files by SHA256 hash. Covers track.js payload builds, iOS exploit loaders, and Coruna stage files. Forensic lookback rule — hashes rotated across 26 builds on Nov 16."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        tlp = "WHITE"
        severity = "critical"
        hash1 = "acdf428f9cc564a9d16ff2a4f67e9af53dfa1bced92b4925283c8151581091fb"
        hash2 = "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f"
        hash3 = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        hash4 = "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3"
        hash5 = "f33e040e5416be881f103186c226ad325381a287a6d0ee1f5e9fbfddcbc24507"
        hash6 = "e027f69d350f83965519e5ad7d947807c17d763138eaa24d2042a2f5ac6f339e"
        hash7 = "d024dc37d8633382c3e2bed176132fd64322f4ce1c1bd11d563e700553c3b36c"
        hash8 = "1bd3c4ed902616fefc29e92b8d8f0eaa0e8eaa96b4064f3d6c80b6e13977d3b6"
        hash9 = "54a54421cbdadc281a224713a97e3ccd9ba6dd3e2578e7e72864a47052ab4d00"
        hash10 = "d437b6799fc200f02832ee70a377b361471468bd887a133e26eb52832b7b2664"

    condition:
        hash.sha256(0, filesize) == "acdf428f9cc564a9d16ff2a4f67e9af53dfa1bced92b4925283c8151581091fb" or
        hash.sha256(0, filesize) == "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f" or
        hash.sha256(0, filesize) == "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40" or
        hash.sha256(0, filesize) == "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3" or
        hash.sha256(0, filesize) == "f33e040e5416be881f103186c226ad325381a287a6d0ee1f5e9fbfddcbc24507" or
        hash.sha256(0, filesize) == "e027f69d350f83965519e5ad7d947807c17d763138eaa24d2042a2f5ac6f339e" or
        hash.sha256(0, filesize) == "d024dc37d8633382c3e2bed176132fd64322f4ce1c1bd11d563e700553c3b36c" or
        hash.sha256(0, filesize) == "1bd3c4ed902616fefc29e92b8d8f0eaa0e8eaa96b4064f3d6c80b6e13977d3b6" or
        hash.sha256(0, filesize) == "54a54421cbdadc281a224713a97e3ccd9ba6dd3e2578e7e72864a47052ab4d00" or
        hash.sha256(0, filesize) == "d437b6799fc200f02832ee70a377b361471468bd887a133e26eb52832b7b2664"
}
