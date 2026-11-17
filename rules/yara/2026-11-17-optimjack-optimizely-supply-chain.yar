/*
 * OPTIMJACK Optimizely Supply Chain Attack - YARA Rules
 * Author: Actioner
 * Date: 2026-11-17
 * Reference: https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
 */

rule Supply_Chain_OPTIMJACK_TrackJS_Payload
{
    meta:
        description = "Detects the OPTIMJACK track.js payload via distinctive JavaScript globals, exfiltration endpoints, and crypto clipper markers used in the Optimizely supply chain attack"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/"
        hash = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        severity = "critical"

    strings:
        $global1 = "window._k7" ascii
        $global2 = "window.__k7b" ascii
        $global3 = "window._cc" ascii
        $global4 = "window._shot" ascii
        $global5 = "window._qxc" ascii
        $exfil1 = "/card.php" ascii
        $exfil2 = "/hit.php" ascii
        $wallet_btc = "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW" ascii
        $wallet_eth = "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e" ascii
        $wallet_trx = "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa" ascii
        $domain = "1688360.cc" ascii

    condition:
        filesize < 500KB and
        (
            ($domain and 2 of ($exfil*)) or
            (3 of ($global*)) or
            (2 of ($wallet*) and 1 of ($exfil*))
        )
}

rule Supply_Chain_OPTIMJACK_Loader_Variants
{
    meta:
        description = "Detects OPTIMJACK loader variants injected into Optimizely Project JavaScript, including the base64-obfuscated and inline eval fallback forms"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer"
        severity = "high"

    strings:
        $loader_plain = "1688360.cc/track.js" ascii
        $loader_b64_marker = "atob(" ascii
        $channel = "02111110" ascii
        $ios_path1 = "JIUJIU888" ascii
        $ios_path2 = "boot.js" ascii
        $global_marker = "window._k7" ascii

    condition:
        filesize < 2MB and
        (
            $loader_plain or
            ($loader_b64_marker and $global_marker) or
            ($channel and $ios_path1) or
            ($channel and $ios_path2 and $global_marker)
        )
}
