rule Exploit_CVE_2026_16723_Fastjson_RCE_Payload
{
    meta:
        description = "Detects Fastjson CVE-2026-16723 exploit payload with @type jar:http scheme for remote class loading"
        author = "Actioner"
        date = "2026-07-26"
        reference = "https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $type_key = "\"@type\"" ascii
        $jar_http = "jar:http" ascii nocase
        $type_key_w = "\"@type\"" wide
        $jar_http_w = "jar:http" wide nocase

    condition:
        filesize < 10MB and
        (($type_key and $jar_http) or ($type_key_w and $jar_http_w))
}
