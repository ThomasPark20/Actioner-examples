rule Supply_Chain_ARVE_WordPress_Backdoor_CVE_2026_18072
{
    meta:
        description = "Detects the ARVE WordPress plugin backdoor (CVE-2026-18072) via distinctive function name, request parameters, and C2 domain"
        author = "Actioner"
        date = "2026-08-02"
        reference = "https://hackread.com/wordfence-critical-backdoor-arve-wordpress-plugin/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $func = "_arve_uc_init" ascii
        $param1 = "_wplogin" ascii
        $param2 = "_wpm" ascii
        $c2 = "fontswp.com" ascii
        $hook = "add_action" ascii
        $wp_cookie = "wp_set_auth_cookie" ascii

    condition:
        filesize < 100KB and
        $func and
        ($param1 or $param2) and
        ($c2 or $wp_cookie) and
        $hook
}
