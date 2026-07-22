rule wp2shell_webshell_minimal : webshell wp2shell
{
    meta:
        description = "Detects minimal PHP webshell variants deployed via the wp2shell exploit chain (CVE-2026-63030 / CVE-2026-60137). Matches eval/system/passthru/shell_exec with superglobal input patterns and the WP2SHELL response marker."
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.bleepingcomputer.com/news/security/critical-wp2shell-wordpress-flaws-exploited-to-install-webshells/"
        reference2 = "https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137"
        hash1 = "2a1410d8e2a8337ac2171cedea8c0fdc47c647a0"
        hash2 = "58eca847e9eae9e6b08cc211f1559817b71bc4cc"
        hash3 = "ebea44890f434d5d67ede22009a3f4bb5cac33f8"

    strings:
        // WP2SHELL response marker
        $marker = "WP2SHELL::" ascii

        // Minimal eval shell with fallback to 404
        $eval_fallback = "http_response_code(404)" ascii

        // Command execution via superglobals
        $exec_get_c = "shell_exec($_GET[" ascii
        $exec_post_c = "shell_exec($_POST[" ascii
        $system_get = "system($_GET[" ascii
        $system_post = "system($_POST[" ascii
        $passthru_get = "passthru($_GET[" ascii
        $passthru_post = "passthru($_POST[" ascii
        $eval_post = "eval($_POST[" ascii
        $eval_get = "eval($_GET[" ascii
        $eval_request = "eval($_REQUEST[" ascii

        // Function availability checks (webshell fingerprint)
        $func_check1 = "function_exists('system')" ascii
        $func_check2 = "function_exists('passthru')" ascii
        $func_check3 = "function_exists('shell_exec')" ascii
        $func_check4 = "function_exists('popen')" ascii

        // REST API endpoint registration for webshell
        $rest_register = "register_rest_route" ascii
        $rest_passthru = "passthru(" ascii

        // PHP opening tag required
        $php_tag = "<?php" ascii nocase

    condition:
        $php_tag and (
            $marker or
            ($eval_fallback and any of ($eval_post, $eval_get, $eval_request)) or
            any of ($exec_get_c, $exec_post_c, $system_get, $system_post, $passthru_get, $passthru_post) or
            (2 of ($func_check*)) or
            ($rest_register and $rest_passthru)
        )
}

rule wp2shell_webshell_plugin_cmsmap : webshell wp2shell
{
    meta:
        description = "Detects the CMSmap obfuscated webshell plugin deployed via wp2shell. Uses hex-encoded concatenation and gzip-compressed base64 encoding. Fake Author: WordPress.org Community header."
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://thehackernews.com/2026/07/wordpress-wp2shell-exploitation-grows.html"
        reference2 = "https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137"
        hash4 = "d9a220c8039f1c4d72cae7ccb8b3a33dec8815be"
        hash5 = "e9756e2338f84746007235e4cab7a70d5b3ca47f"

    strings:
        // Fake plugin header claiming WordPress.org authorship
        $plugin_header = "Author: WordPress.org Community" ascii

        // Obfuscation patterns: hex-encoded string concatenation
        $hex_concat1 = /\\x[0-9a-fA-F]{2}\.\\x[0-9a-fA-F]{2}\.\\x[0-9a-fA-F]{2}/ ascii
        $hex_concat2 = /chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)/ ascii

        // Gzip + base64 deobfuscation chain
        $gzdecode = "gzdecode(base64_decode(" ascii
        $gzinflate = "gzinflate(base64_decode(" ascii
        $gzuncompress = "gzuncompress(base64_decode(" ascii

        // Eval with deobfuscation
        $eval_gz = /eval\s*\(\s*gz(decode|inflate|uncompress)\s*\(/ ascii

        $php_tag = "<?php" ascii nocase

    condition:
        $php_tag and filesize < 200KB and (
            ($plugin_header and any of ($hex_concat*, $gzdecode, $gzinflate, $gzuncompress, $eval_gz)) or
            ($eval_gz and any of ($hex_concat*))
        )
}
