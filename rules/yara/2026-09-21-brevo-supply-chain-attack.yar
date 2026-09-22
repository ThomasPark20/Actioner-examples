rule Supply_Chain_Brevo_Injected_JS
{
    meta:
        description = "Detects JavaScript files injected during the Brevo supply chain attack via Cloudflare Worker (Sep 2026)"
        author = "Actioner"
        date = "2026-09-21"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        hash1 = "58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308"
        hash2 = "f67d572d2d30407b3f470904326411450763108980cdad89550fbb221fb06782"
        hash3 = "9b62c12bc5c7feb9802f58e6cf75a368690df3c754e37cc64483a92acacf87a5"
        severity = "high"

    strings:
        $domain1 = "cdn.sendibt1.com" ascii wide
        $domain2 = "cdn2.sendibt1.com" ascii wide
        $domain3 = "cdn3.sendibt1.com" ascii wide
        $domain4 = "cdn4.sendibt1.com" ascii wide
        $domain9 = "cdn9.sendibt1.com" ascii wide
        $domain10 = "cdn10.sendibt1.com" ascii wide
        $domain11 = "cdn11.sendibt1.com" ascii wide
        $loader_url = "/f.js" ascii
        $wp_path = "/wp-admin/update.php" ascii
        $wp_action = "action=upload-plugin" ascii
        $plugin_zip = "/p/wm.zip" ascii
        $c2_path1 = "/api/v1/0044d4a" ascii
        $c2_path2 = "/api/v1/e08a3c4" ascii
        $c2_path3 = "/api/v1/4aff112" ascii
        $c2_path4 = "/api/v1/b832c14" ascii
        $c2_path5 = "/api/v1/4ead0ff" ascii
        $c2_path6 = "/api/v1/8e4c615" ascii
        $c2_path7 = "/api/v1/f659473" ascii
        $inject_pattern = "document.createElement(\"script\")" ascii
        $self_selector = "script[data-c]" ascii

    condition:
        filesize < 5MB and
        (
            (1 of ($domain*) and ($loader_url or $inject_pattern or $self_selector)) or
            (1 of ($domain*) and 1 of ($c2_path*)) or
            (1 of ($domain*) and ($wp_path or $wp_action or $plugin_zip)) or
            (2 of ($c2_path*) and 1 of ($domain*))
        )
}
