rule BdThemes_Supply_Chain_Webshell_EmerRun
{
    meta:
        description = "Detects emer-run.php webshell and persistence artifacts from the BdThemes WordPress supply chain attack"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/"
        reference2 = "https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/"

    strings:
        $webshell_name = "emer-run.php" ascii
        $c2_domain = "ia-cdn.com" ascii
        $c2_path = "/fz/c" ascii
        $backdoor_param = "_wplogin" ascii
        $db_option1 = "fz_emer_login_tokens" ascii
        $db_option2 = "fz_emer_done_v1" ascii
        $fake_plugin = "wp-smart-thumbnails" ascii

    condition:
        4 of them
}

rule BdThemes_Supply_Chain_W2JS_Payload
{
    meta:
        description = "Detects the w2.js JavaScript payload used in the BdThemes supply chain attack for admin account creation and webshell deployment"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/"

    strings:
        $c2_url = "ia-cdn.com/fz/c" ascii
        $wp_rest = "/wp-json/wp/v2/users" ascii
        $webshell = "emer-run" ascii
        $nonce = "wp_create_nonce" ascii
        $role = "administrator" ascii

    condition:
        $c2_url and 2 of ($wp_rest, $webshell, $nonce, $role)
}

rule BdThemes_Supply_Chain_MU_Plugin_Backdoor
{
    meta:
        description = "Detects must-use plugin backdoor components from the BdThemes supply chain attack including the magic login and stealth module"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/"

    strings:
        $login_param = "_wplogin" ascii
        $option_tokens = "fz_emer_login_tokens" ascii
        $option_done = "fz_emer_done_v1" ascii
        $mu_path = "mu-plugins" ascii
        $wp_set_auth = "wp_set_auth_cookie" ascii
        $wp_set_current = "wp_set_current_user" ascii

    condition:
        ($login_param and $option_tokens) or ($option_done and 2 of ($mu_path, $wp_set_auth, $wp_set_current))
}
