rule Rootkit_PoisonedRefresh_LinuxAgntIC
{
    meta:
        description = "Detects the PoisonedRefresh fileless Linux rootkit (Linux/Agnt-IC) targeting F5 BIG-IP APM via CVE-2025-53521, based on embedded operational strings"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/"
        hash = "26bd5b0722d1dbab5db749a063c49bc8638653ac2addfead7a9cb3d6d57bccc9"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $rc4_key = "TrswBWIl90Z5e38n" ascii
        $magic = "BSOHAzPB" ascii
        $ws_key = "wSLjN1beuR" ascii
        $auth_token = "Kzwd6jM5" ascii
        $socket_path = "/run/bigtlog.pipe" ascii
        $php1 = "apm_css.php3" ascii
        $php2 = "full_wt.php3" ascii
        $php3 = "webtop_popup_css.php3" ascii
        $apr_hook = "apr_dso_load" ascii
        $libphp = "libphp" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            ($rc4_key and 1 of ($magic, $ws_key, $auth_token)) or
            ($socket_path and 2 of ($php1, $php2, $php3)) or
            (4 of ($rc4_key, $magic, $ws_key, $auth_token, $socket_path, $apr_hook, $libphp))
        )
}

rule Rootkit_PoisonedRefresh_WebShellStrings
{
    meta:
        description = "Detects PoisonedRefresh web shell trigger strings and encryption keys in ELF binaries or memory dumps"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/"
        hash = "26bd5b0722d1dbab5db749a063c49bc8638653ac2addfead7a9cb3d6d57bccc9"
        tlp = "WHITE"
        severity = "high"

    strings:
        $magic = "BSOHAzPB" ascii
        $ws_key = "wSLjN1beuR" ascii
        $auth = "Kzwd6jM5" ascii
        $rc4 = "TrswBWIl90Z5e38n" ascii
        $socket = "/run/bigtlog.pipe" ascii

    condition:
        3 of them
}
