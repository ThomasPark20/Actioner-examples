rule Exploit_CVE_2026_15409_SMA1000_Config_Tampering
{
    meta:
        description = "Detects SonicWall SMA1000 Unit conf.json containing unauthorized API routes (/__api__/login or /__api__/logout) indicating exploitation of CVE-2026-15409"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008"
        severity = "critical"

    strings:
        $api_login = "/__api__/login" ascii
        $api_logout = "/__api__/logout" ascii
        $json_routes = "\"routes\"" ascii
        $json_listeners = "\"listeners\"" ascii

    condition:
        filesize < 5MB and
        ($api_login or $api_logout) and
        ($json_routes or $json_listeners)
}
