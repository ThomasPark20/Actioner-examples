rule JetBrains_Malicious_Plugin_APIKeyTheft
{
    meta:
        description = "Detects malicious JetBrains plugins that exfiltrate AI API keys to C2 server 39.107.60.51"
        author = "CTI Analyst (Automated Draft)"
        date = "2026-06-17"
        reference = "https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys"
        severity = "high"

    strings:
        $c2_ip = "39.107.60.51" ascii wide
        $c2_endpoint = "/api/software/" ascii wide
        $auth_token = "F48D2AA7CF341F782C1D" ascii wide
        $header_key = "X-Api-Key" ascii wide
        $sk_prefix = "sk-" ascii

        $pkg_id1 = "org.sm.yms.toolkit" ascii
        $pkg_id2 = "com.json.simple.kit" ascii
        $pkg_id3 = "org.bug.find.tools" ascii
        $pkg_id4 = "org.translate.ai.simple" ascii
        $pkg_id5 = "com.yy.test.ai.simple" ascii
        $pkg_id6 = "com.dev.ai.toolkit" ascii
        $pkg_id7 = "com.json.view.simple" ascii
        $pkg_id8 = "com.my.git.ai.kit" ascii
        $pkg_id9 = "org.check.ai.ds" ascii
        $pkg_id10 = "com.review.tool.code" ascii
        $pkg_id11 = "org.code.assist.dev.tool" ascii
        $pkg_id12 = "com.coder.ai.dpt" ascii
        $pkg_id13 = "com.my.code.tools" ascii
        $pkg_id14 = "ord.cp.code.ai.kit" ascii
        $pkg_id15 = "com.dp.git.ai.tool" ascii

    condition:
        filesize < 50MB and (
            ($c2_ip and $c2_endpoint and $auth_token) or
            ($auth_token and $header_key) or
            ($c2_ip and $auth_token) or
            (any of ($pkg_id*) and ($c2_ip or $auth_token or $c2_endpoint)) or
            ($sk_prefix and $c2_ip and $auth_token)
        )
}

rule JetBrains_Plugin_C2_AuthToken
{
    meta:
        description = "Detects the static C2 authentication token used by malicious JetBrains AI plugins"
        author = "CTI Analyst (Automated Draft)"
        date = "2026-06-17"
        reference = "https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys"
        severity = "critical"

    strings:
        $token = "F48D2AA7CF341F782C1D" ascii wide nocase
        $endpoint = "/api/software/" ascii wide

    condition:
        all of them
}
