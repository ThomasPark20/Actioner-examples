rule Brevo_ClickFix_JS_Injection
{
    meta:
        description = "Detects the malicious JavaScript injection pattern used in the Brevo supply chain ClickFix attack"
        author = "Actioner"
        date = "2026-09-20"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        reference = "https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/"
        hash = "58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308"

    strings:
        $inject1 = "sendibt1.com/f.js" ascii wide
        $inject2 = "sendibt1.com" ascii wide
        $loader_pattern = "document.createElement(\"script\")" ascii
        $async_append = "h.appendChild(s)" ascii
        $domain_cdn2 = "cdn2.sendibt1.com" ascii wide
        $domain_cdn9 = "cdn9.sendibt1.com" ascii wide
        $domain_cdn11 = "cdn11.sendibt1.com" ascii wide
        $domain_cdn10 = "cdn10.sendibt1.com" ascii wide

    condition:
        ($inject1) or ($inject2 and $loader_pattern and $async_append) or (any of ($domain_cd*))
}

rule Brevo_ClickFix_WP_Backdoor
{
    meta:
        description = "Detects the Web Media Optimizer WordPress backdoor plugin from the Brevo supply chain attack"
        author = "Actioner"
        date = "2026-09-20"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        hash = "f359ab0d2f732b54dd3300065f4d6553f4df1b67454b71fd81197e26f02af4a8"

    strings:
        $plugin_name = "Web Media Optimizer" ascii wide
        $c2_domain = "glegchner.com" ascii wide
        $c2_path = "/ads.php" ascii wide
        $must_use = "mu-plugins" ascii wide
        $wp_upload = "upload-plugin" ascii wide

    condition:
        ($plugin_name and ($c2_domain or $must_use)) or ($c2_domain and $c2_path) or ($plugin_name and $wp_upload)
}

rule Brevo_ClickFix_C2_Communication
{
    meta:
        description = "Detects C2 API patterns used by the Brevo ClickFix malware for fingerprinting and command delivery"
        author = "Actioner"
        date = "2026-09-20"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"

    strings:
        $api1 = "/api/v1/0044d4a" ascii
        $api2 = "/api/v1/e08a3c4" ascii
        $api3 = "/api/v1/8e4c615" ascii
        $api4 = "/api/v1/f659473" ascii
        $api5 = "/api/v1/4aff112" ascii
        $api6 = "/api/v1/b832c14" ascii
        $api7 = "/api/v1/4ead0ff" ascii
        $domain = "sendibt1.com" ascii wide
        $clickfix_domain = "corralos.beer" ascii wide

    condition:
        (any of ($api*) and $domain) or ($clickfix_domain and any of ($api*))
}
