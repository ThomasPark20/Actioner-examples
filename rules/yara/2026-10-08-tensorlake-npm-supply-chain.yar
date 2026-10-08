rule Supply_Chain_ShaiHulud_Tensorlake_Payload
{
    meta:
        description = "Detects the Shai-Hulud worm payload (Math_Symbol.js) from the compromised tensorlake@0.5.144 npm package"
        author = "Actioner"
        date = "2026-10-08"
        reference = "https://socket.dev/blog/tensorlake-compromise"
        hash = "b50a00900399ba99fb6ce1fc151519cb99d44320ef2a631f2237e1aea0ad6fec"
        severity = "critical"

    strings:
        $wormtag = "WORMTAG" ascii
        $tensrlake = "tensrlake" ascii
        $killswitch = "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner" ascii
        $marker = "thebeautifulmarchoftime" ascii
        $dune1 = "sandworm" ascii
        $dune2 = "sardaukar" ascii
        $dune3 = "fedaykin" ascii
        $dune4 = "ornithopter" ascii
        $dune5 = "sietch" ascii
        $eth_addr = "0xb614155Fd88114d40549b259457Bcf921Df091B9" ascii
        $c2_domain = "iseekaigogo" ascii
        $math_sym = "Math_Symbol" ascii

    condition:
        filesize < 2MB and
        (
            ($wormtag and $tensrlake) or
            $killswitch or
            ($eth_addr and 2 of ($dune*)) or
            ($c2_domain and $math_sym) or
            (4 of ($dune*) and $marker)
        )
}

rule Supply_Chain_ShaiHulud_Tensorlake_Dropper
{
    meta:
        description = "Detects the Shai-Hulud dropper (setup.mjs) from the compromised tensorlake@0.5.144 npm package"
        author = "Actioner"
        date = "2026-10-08"
        reference = "https://socket.dev/blog/tensorlake-compromise"
        hash = "25a0735d0db7dc40e5d45ce42d9c106067e6a66e184d967cfecfab17c3bcb5ef"
        severity = "high"

    strings:
        $setup_import = "Math_Symbol" ascii
        $bun_download = "oven-sh/bun/releases" ascii
        $wormtag = "WORMTAG" ascii
        $worm_profile = "WORM_PROFILE" ascii

    condition:
        filesize < 500KB and
        $bun_download and
        ($setup_import or $wormtag or $worm_profile)
}
