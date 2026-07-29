rule CVE_2026_61511_vBulletin_Exploit_Request
{
    meta:
        description = "Detects CVE-2026-61511 exploit HTTP request patterns targeting vBulletin ajax/render/pagenav with phpfuck-encoded payload"
        author = "Actioner (DRAFT)"
        date = "2026-07-29"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-61511"
        severity = "critical"

    strings:
        $uri1 = "ajax/render/pagenav" ascii nocase
        $uri2 = "routestring=ajax" ascii nocase
        $param1 = "pagenav%5Bpagenumber%5D" ascii nocase
        $param2 = "pagenav[pagenumber]" ascii nocase
        $xor_encoded1 = "%5E" ascii
        $xor_raw = ")^(" ascii
        $post_method = "POST " ascii

    condition:
        $post_method and
        ($uri1 or $uri2) and
        ($param1 or $param2) and
        ($xor_encoded1 or $xor_raw)
}

rule CVE_2026_61511_vBulletin_PHPFuck_Payload
{
    meta:
        description = "Detects phpfuck-style payload patterns used in CVE-2026-61511 exploit - long sequences of digits, XOR operators, and parentheses"
        author = "Actioner (DRAFT)"
        date = "2026-07-29"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-61511"
        severity = "critical"

    strings:
        $phpfuck_pattern1 = /\(9{5,}\)\.?\^/ ascii
        $phpfuck_pattern2 = /\^\.?\(9{5,}\)/ ascii
        $phpfuck_pattern3 = /((\(9+\)\.\^){3,})/ ascii
        $vbulletin_context = "pagenav" ascii nocase

    condition:
        $vbulletin_context and
        (any of ($phpfuck_pattern*))
}
