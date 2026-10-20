rule RankMathPRO_SupplyChain_Backdoor
{
    meta:
        description = "Detects Rank Math PRO 3.0.123 supply chain backdoor components"
        author = "CTI Analyst"
        date = "2026-10-20"
        reference = "https://rankmath.com/kb/pro-3-0-123-security-incident/"
        cve = "CVE-2026-111862"
        hash = "f99a42f622e9a638f1b27dc051a48619a5a2d7f3432a4480fecf1413253629c9"
        severity = "critical"

    strings:
        $xor_key = "xmmqhn" ascii wide
        $db_opt1 = "_uf6qdn2hmm" ascii
        $db_opt2 = "t8krdk990phb" ascii
        $db_opt3 = "_np5pvf754c" ascii
        $c2_domain = "rank1cdn.com" ascii wide nocase
        $cron_marker = "#ms6v46" ascii
        $backdoor_file = "class-wp-cache-util.php" ascii
        $rogue_email = "@wp-mail.net" ascii nocase
        $rogue_user = "wpsupport_" ascii nocase

        $php_b64 = "base64_decode" ascii
        $php_proc = "proc_open" ascii
    condition:
        any of ($xor_key, $db_opt1, $db_opt2, $db_opt3, $c2_domain, $cron_marker) or
        ($backdoor_file and $php_b64) or
        ($rogue_email and $rogue_user) or
        ($xor_key and $php_b64 and $php_proc)
}

rule RankMathPRO_CachePreloader_Dropper
{
    meta:
        description = "Detects the first-stage cache preloader dropper from Rank Math PRO 3.0.123 compromise"
        author = "CTI Analyst"
        date = "2026-10-20"
        reference = "https://www.bleepingcomputer.com/news/security/wordpress-seo-plugin-rank-math-compromised-to-backdoor-websites/"
        severity = "critical"

    strings:
        $cache_preloader = "_cache-preloader-" ascii
        $xor_key = "xmmqhn" ascii
        $b64 = "base64_decode" ascii
        $proc = "proc_open" ascii
        $wp_cache_util = "class-wp-cache-util" ascii
        $c2 = "rank1cdn" ascii

    condition:
        ($cache_preloader and any of ($xor_key, $b64, $proc)) or
        ($c2 and $xor_key) or
        ($wp_cache_util and $xor_key and $b64)
}
