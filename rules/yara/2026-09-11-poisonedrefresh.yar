rule PoisonedRefresh_Rootkit_Strings
{
    meta:
        description = "Detects PoisonedRefresh fileless Linux rootkit targeting F5 BIG-IP APM based on hardcoded operational strings"
        author = "Actioner"
        date = "2026-09-11"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit"
        hash = "26bd5b0722d1dbab5db749a063c49bc8638653ac2addfead7a9cb3d6d57bccc9"
        severity = "high"

    strings:
        $rc4_key = "TrswBWIl90Z5e38n"
        $socket_path = "/run/bigtlog.pipe"
        $auth_token = "Kzwd6jM5"
        $webshell_prefix = "BSOHAzPB"
        $webshell_key = "wSLjN1beuR"
        $php_target1 = "apm_css.php3"
        $php_target2 = "full_wt.php3"
        $php_target3 = "webtop_popup_css.php3"
        $proc_maps = "/proc/self/maps"
        $proc_exe = "/proc/self/exe"
        $apr_hook = "apr_dso_load"
        $apr_time = "apr_time_now"
        $libc_hook = "__libc_start_main"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (
            ($rc4_key and $socket_path) or
            ($auth_token and $webshell_prefix) or
            ($webshell_key and any of ($php_target*)) or
            (3 of ($rc4_key, $socket_path, $auth_token, $webshell_prefix, $webshell_key)) or
            (all of ($apr_*) and $proc_maps and any of ($php_target*)) or
            ($proc_exe and $libc_hook and any of ($apr_*))
        )
}

rule PoisonedRefresh_PHP_Webshell
{
    meta:
        description = "Detects PoisonedRefresh PHP web shell payload injected into BIG-IP APM PHP scripts in memory"
        author = "Actioner"
        date = "2026-09-11"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit"
        severity = "critical"

    strings:
        $magic = "BSOHAzPB"
        $cipher_key = "wSLjN1beuR"
        $php_input = "php://input"
        $eval = "eval("
        $css_type = "text/css; charset=utf-8"
        $status_201 = "201"

    condition:
        $magic and $cipher_key and
        (
            $php_input or
            ($eval and $css_type) or
            ($status_201 and $css_type)
        )
}

rule PoisonedRefresh_Installer
{
    meta:
        description = "Detects PoisonedRefresh installer component that infects httpd and install media on F5 BIG-IP APM"
        author = "Actioner"
        date = "2026-09-11"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit"
        severity = "medium"

    strings:
        $target_httpd = "/usr/sbin/httpd"
        $install_path = "/mnt/tm_install"
        $socket_path = "/run/bigtlog.pipe"
        $rc4_key = "TrswBWIl90Z5e38n"
        $rc_local = "rc.local"
        $selinux = "SELINUX"
        $bigstart = "bigstart"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        $target_httpd and $install_path and
        ($socket_path or $rc4_key) and
        1 of ($rc_local, $selinux, $bigstart)
}
