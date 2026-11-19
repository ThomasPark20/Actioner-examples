import "hash"

rule Supply_Chain_OPTIMJACK_TrackJS_Loader
{
    meta:
        description = "Detects OPTIMJACK malicious track.js payload loader and card skimmer JavaScript served through compromised Optimizely snippets"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        hash = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        severity = "high"
        tlp = "WHITE"

    strings:
        $domain1 = "1688360.cc" ascii wide
        $domain2 = "webshell.lol" ascii wide
        $path1 = "/track.js" ascii wide
        $path2 = "/card.php" ascii wide
        $path3 = "/hit.php" ascii wide
        $global1 = "window._k7" ascii
        $global2 = "window.__k7b" ascii
        $channel = "02111110" ascii

    condition:
        filesize < 500KB and
        (
            (1 of ($domain*) and 1 of ($path*)) or
            (2 of ($global*, $channel) and 1 of ($domain*))
        )
}

rule Supply_Chain_OPTIMJACK_iOS_Exploit_Router
{
    meta:
        description = "Detects OPTIMJACK iOS exploit routing JavaScript that directs visitors to Coruna and DarkSword exploit kits"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $icu1 = "5vobauua3ojpklx.icu" ascii wide
        $icu2 = "eil786npto9u5bq.icu" ascii wide
        $icu3 = "l7bcsnwc7nzr3uo.icu" ascii wide
        $icu4 = "je4ft3gn8vxudum.icu" ascii wide
        $icu5 = "ioshack.icu" ascii wide
        $exploit_path1 = "/A8/" ascii
        $exploit_path2 = "/JIUJIU888/" ascii
        $exploit_path3 = "/D11/" ascii
        $exploit_path4 = "/C10/" ascii
        $boot = "boot.js" ascii
        $channel = "data-channel-code" ascii

    condition:
        filesize < 500KB and
        (
            2 of ($icu*) or
            (1 of ($icu*) and 1 of ($exploit_path*)) or
            (1 of ($icu*) and ($boot or $channel))
        )
}

rule Supply_Chain_OPTIMJACK_Crypto_Clipper
{
    meta:
        description = "Detects OPTIMJACK crypto wallet address clipper JavaScript that replaces cryptocurrency addresses on web pages"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html"
        severity = "high"
        tlp = "WHITE"

    strings:
        $clipboard = "navigator.clipboard" ascii
        $beacon = "navigator.sendBeacon" ascii
        $html2canvas = "html2canvas" ascii
        $cookie_exfil = "document.cookie" ascii
        $wallet_term1 = "wallet" ascii nocase
        $wallet_term2 = "deposit" ascii nocase
        $domain = "1688360.cc" ascii wide
        $global1 = "window._k7" ascii
        $global2 = "window.__k7b" ascii

    condition:
        filesize < 500KB and
        $domain and
        (
            ($clipboard and 1 of ($wallet_term*)) or
            ($beacon and $html2canvas) or
            (1 of ($global*) and $cookie_exfil)
        )
}

rule Supply_Chain_OPTIMJACK_TrackJS_Hash
{
    meta:
        description = "Detects known OPTIMJACK track.js samples by SHA-256 file hash"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        hash1 = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        hash2 = "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3"
        hash3 = "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f"
        hash4 = "c2a34c579e4c2e8802752c93b3a9cca0230610f3e4dd6688f4272459c7c7c162"
        severity = "critical"
        tlp = "WHITE"

    condition:
        filesize < 500KB and
        (
            hash.sha256(0, filesize) == "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40" or
            hash.sha256(0, filesize) == "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3" or
            hash.sha256(0, filesize) == "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f" or
            hash.sha256(0, filesize) == "c2a34c579e4c2e8802752c93b3a9cca0230610f3e4dd6688f4272459c7c7c162"
        )
}
