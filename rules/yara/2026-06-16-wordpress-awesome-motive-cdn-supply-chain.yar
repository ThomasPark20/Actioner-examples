rule AwesomeMotive_SupplyChain_BackdoorPlugin
{
    meta:
        description = "Detects the hidden backdoor plugin installed by the Awesome Motive CDN supply chain attack. Matches on PHP files containing the web shell parameter names, the XOR key, and characteristic plugin metadata."
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://sansec.io/research/optinmonster-supply-chain-attack"
        severity = "critical"
        hash = "n/a - payload is generated per-request with rotating hashes"

    strings:
        $xor_key = "jX9kM2nP4qR6sT8v" ascii wide
        $shell_param = "developer_api1_fm" ascii wide
        $eval_param = "developer_api1_eval" ascii wide
        $shell_title = "WPM File Manager" ascii wide
        $plugin_slug1 = "content-delivery-helper" ascii wide
        $plugin_slug2 = "database-optimizer" ascii wide
        $backdoor_user = "developer_api1" ascii wide
        $backdoor_email = "customer1usx@gmail.com" ascii wide

    condition:
        any of ($xor_key, $shell_param, $eval_param, $shell_title) or
        (any of ($plugin_slug1, $plugin_slug2) and any of ($backdoor_user, $backdoor_email))
}

rule AwesomeMotive_SupplyChain_MaliciousJS
{
    meta:
        description = "Detects the malicious JavaScript payload injected into Awesome Motive CDN-served plugin files. Matches on the XOR encryption key, C2 domain, and characteristic exfiltration code patterns."
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://sansec.io/research/optinmonster-supply-chain-attack"
        severity = "high"

    strings:
        $xor_key = "jX9kM2nP4qR6sT8v" ascii
        $c2_domain = "tidio.cc" ascii
        $c2_path1 = "/cdn-cgi/p" ascii
        $c2_path2 = "/cdn-cgi/b" ascii
        $c2_path3 = "/cdn-cgi/l" ascii
        $c2_path4 = "/cdn-cgi/pe-p" ascii
        $c2_path5 = "/cdn-cgi/pe-b" ascii
        $c2_path6 = "/cdn-cgi/pe-l" ascii
        $cookie_check = "wordpress_logged_in_" ascii
        $localStorage_key = "_pe_ts" ascii
        $rogue_user = "developer_api1" ascii
        $beacon_method = "sendBeacon" ascii
        $exfil_email = "customer1usx" ascii

    condition:
        ($xor_key and $c2_domain) or
        ($c2_domain and 2 of ($c2_path*)) or
        ($xor_key and any of ($cookie_check, $localStorage_key, $rogue_user)) or
        ($beacon_method and $exfil_email and $c2_domain)
}
