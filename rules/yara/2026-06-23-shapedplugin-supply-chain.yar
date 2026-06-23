rule ShapedPlugin_LicenseLoader_Backdoor
{
    meta:
        description = "Detects the ShapedPlugin LicenseLoader.php initial loader used in the supply chain attack (CVE-2026-49777)"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html"
        severity = "critical"

    strings:
        $loader_name = "LicenseLoader" ascii
        $c2_ip = "194.76.217.28" ascii
        $c2_port = "2871" ascii
        $fake_plugin1 = "woocommerce-subscription" ascii
        $fake_plugin2 = "woocommerce-notification" ascii
        $php_tag = "<?php" ascii

    condition:
        $php_tag and $loader_name and ($c2_ip or $c2_port or $fake_plugin1 or $fake_plugin2)
}

rule ShapedPlugin_Exfiltration_Payload
{
    meta:
        description = "Detects the ShapedPlugin credential-stealing payload targeting wp-config.php and 2FA secrets"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html"
        severity = "high"

    strings:
        $exfil_domain = "generate.2faplugin.org" ascii
        $install_persist = "install-persistent.php" ascii
        $wp_config_read = "wp-config.php" ascii
        $fake_plugin1 = "woocommerce-subscription" ascii
        $fake_plugin2 = "woocommerce-notification" ascii
        $php_tag = "<?php" ascii

    condition:
        $php_tag and ($exfil_domain or ($install_persist and $wp_config_read)) and ($fake_plugin1 or $fake_plugin2)
}

rule ShapedPlugin_Webshell_Indicators
{
    meta:
        description = "Detects web shell and attacker tool indicators associated with the ShapedPlugin supply chain backdoor"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html"
        severity = "high"

    strings:
        $tiny_fm = "Tiny File Manager" ascii
        $adminer = "Adminer" ascii
        $hidden_admin = "wp_support_sys" ascii
        $suspicious1 = "class-wp-cache-manager.php" ascii
        $suspicious2 = "init-core-helper.php" ascii
        $suspicious3 = "wp-db-update.php" ascii
        $c2_domain = "cdn-stats-api.com" ascii
        $sp_option1 = "_wp_sp_" ascii
        $sp_option2 = "_tmp_sp" ascii
        $php_tag = "<?php" ascii

    condition:
        $php_tag and (
            ($tiny_fm and $adminer) or
            ($hidden_admin and ($c2_domain or 1 of ($suspicious*))) or
            $c2_domain or
            (2 of ($suspicious*)) or
            ($sp_option1 and $sp_option2 and 1 of ($suspicious*))
        )
}
