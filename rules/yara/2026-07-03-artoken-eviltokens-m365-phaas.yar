// YARA rule for ARToken/EvilTokens Microsoft 365 PhaaS phishing payload
// Source: https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
// Generated: 2026-07-03 by Actioner

rule PhaaS_ARToken_EvilTokens_Phishing_Payload
{
    meta:
        description = "Detects ARToken/EvilTokens phishing-as-a-service JavaScript payload via operator UUID, localStorage key, C2 domains, XOR key, or API endpoint patterns"
        author = "Actioner"
        date = "2026-07-03"
        reference = "https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/"
        severity = "high"

    strings:
        $uuid = "84eb384d-cd3e-4c90-a283-c960ce557913" ascii wide
        $jwt_key = "artoken_jwt" ascii wide
        $c2_domain = "spx.pamconj.com" ascii wide
        $dashboard = "dashboard-bl.pamconj.com" ascii wide
        $api_endpoint = "/api/device/start" ascii wide
        $client_mode = "clientMode" ascii wide
        $prt_setup = "/prt/setup" ascii wide
        $prt_refresh = "/prt/refresh" ascii wide
        $prt_cookie = "/prt/cookie" ascii wide
        $prt_renew = "/prt/renew" ascii wide
        $xor_key = { E9 45 E0 DB 35 30 D5 A5 77 F3 4D 97 65 94 0F E3 }
        $img_artifact = "pumber.png" ascii wide

    condition:
        filesize < 5MB and
        (
            $uuid or
            $jwt_key or
            $c2_domain or
            $dashboard or
            ($img_artifact and 1 of ($uuid, $jwt_key, $c2_domain, $dashboard, $api_endpoint, $client_mode)) or
            ($xor_key and 1 of ($api_endpoint, $client_mode, $uuid, $jwt_key)) or
            ($api_endpoint and $client_mode and 1 of ($prt_*))
        )
}
