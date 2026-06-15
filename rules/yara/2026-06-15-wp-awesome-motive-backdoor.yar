rule SupplyChain_AwesomeMotive_Backdoor_Plugin_PHP
{
    meta:
        description = "Detects the hidden backdoor plugin installed by the Awesome Motive CDN supply chain attack. Matches on distinctive strings from the web shell and eval entry points."
        author = "Actioner"
        date = "2026-06-15"
        reference = "https://sansec.io/research/optinmonster-supply-chain-attack"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $shell_brand = "WPM File Manager & Shell" ascii
        $param_fm = "developer_api1_fm" ascii
        $param_eval = "developer_api1_eval" ascii
        $account = "developer_api1" ascii
        $email = "customer1usx@gmail.com" ascii
        $slug1 = "content-delivery-helper" ascii
        $slug2 = "database-optimizer" ascii

    condition:
        filesize < 500KB and
        (
            $shell_brand or
            ($param_fm and $param_eval) or
            (any of ($slug*) and ($account or $email))
        )
}

rule SupplyChain_AwesomeMotive_Malicious_JS
{
    meta:
        description = "Detects malicious JavaScript injected via Awesome Motive CDN supply chain attack. Keys on XOR exfiltration key, C2 domain, and admin detection logic."
        author = "Actioner"
        date = "2026-06-15"
        reference = "https://sansec.io/research/optinmonster-supply-chain-attack"
        tlp = "WHITE"
        severity = "high"

    strings:
        $xor_key = "jX9kM2nP4qR6sT8v" ascii
        $c2_domain = "tidio.cc" ascii
        $c2_path1 = "/cdn-cgi/p" ascii
        $c2_path2 = "/cdn-cgi/pe-p" ascii
        $c2_path3 = "/cdn-cgi/l" ascii
        $c2_path4 = "/cdn-cgi/pe-l" ascii
        $wp_cookie = "wordpress_logged_in_" ascii
        $localstorage = "_pe_ts" ascii
        $rest_nonce = "wpApiSettings" ascii

    condition:
        filesize < 2MB and
        (
            $xor_key or
            ($c2_domain and any of ($c2_path*)) or
            ($c2_domain and $wp_cookie) or
            ($localstorage and $rest_nonce and $c2_domain)
        )
}
