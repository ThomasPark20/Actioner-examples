rule Supply_Chain_Brevo_ClickFix_Loader
{
    meta:
        description = "Detects the JavaScript malware loader injected into Brevo SDK and widget scripts during the September 2026 supply chain attack"
        author = "Actioner"
        date = "2026-09-19"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "high"

    strings:
        $inject1 = "sendibt1.com/f.js" ascii
        $inject2 = "sendibt1.com" ascii
        $api_path1 = "/api/v1/0044d4a" ascii
        $api_path2 = "/api/v1/e08a3c4" ascii
        $api_path3 = "/api/v1/8e4c615" ascii
        $api_path4 = "/api/v1/f659473" ascii
        $api_path5 = "/api/v1/4aff112" ascii
        $api_path6 = "/api/v1/b832c14" ascii
        $api_path7 = "/api/v1/4ead0ff" ascii
        $c2_domain1 = "glegchner.com" ascii
        $c2_domain2 = "yelahaye.surf" ascii
        $c2_domain3 = "boiseno.club" ascii
        $plugin_url = "/p/wm.zip" ascii

    condition:
        filesize < 5MB and
        (
            ($inject1) or
            ($inject2 and 2 of ($api_path*)) or
            (2 of ($c2_domain*)) or
            ($inject2 and $plugin_url)
        )
}

rule Supply_Chain_Brevo_WebMediaOptimizer_Backdoor
{
    meta:
        description = "Detects the Web Media Optimizer malicious WordPress plugin deployed via the Brevo supply chain attack"
        author = "Actioner"
        date = "2026-09-19"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "medium"

    strings:
        $name = "Web Media Optimizer" ascii nocase
        $c2_1 = "glegchner.com" ascii
        $c2_2 = "/ads.php" ascii
        $wp_func1 = "must-use" ascii
        $wp_func2 = "wp_options" ascii
        $wp_func3 = "update-plugin" ascii

    condition:
        filesize < 2MB and
        $name and
        (
            ($c2_1 and $c2_2) or
            (1 of ($c2_*) and 1 of ($wp_func*))
        )
}
