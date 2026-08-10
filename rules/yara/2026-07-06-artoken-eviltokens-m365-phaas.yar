/*
 * Actioner - ARToken/EvilTokens M365 PhaaS Detection Rules
 * Date: 2026-07-06
 * Reference: https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
 */

rule Phishing_ARToken_EvilTokens_Page
{
    meta:
        description = "Detects ARToken/EvilTokens phishing page HTML/JavaScript artifacts including the artoken_jwt localStorage key, XOR decryption key, device code API calls, and anti-analysis checks"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/"
        severity = "high"

    strings:
        $jwt_key = "artoken_jwt" ascii wide
        $api_start = "/api/device/start" ascii wide
        $api_status = "/api/device/status/" ascii wide
        $antibot = "X-Antibot-Token" ascii wide
        $clientmode = "clientMode" ascii wide
        $broker = "broker" ascii wide
        $xor_key_partial = { E9 45 E0 DB 35 30 D5 A5 }
        $webdriver = "navigator.webdriver" ascii
        $clipboard = "navigator.clipboard.writeText" ascii
        $crypto_decrypt = "crypto.subtle.decrypt" ascii
        $device_login = "microsoft.com/devicelogin" ascii wide
        $persist_flag = "persistAfterPassChange" ascii wide
        $operator_uuid = "84eb384d-cd3e-4c90-a283-c960ce557913" ascii wide

    condition:
        filesize < 5MB and
        (
            ($jwt_key and 1 of ($api_start, $api_status)) or
            ($antibot and $clientmode) or
            ($xor_key_partial and $crypto_decrypt) or
            ($operator_uuid) or
            (3 of ($api_start, $api_status, $antibot, $clientmode, $broker, $webdriver, $clipboard, $device_login, $persist_flag))
        )
}

rule Phishing_EvilTokens_Workers_Payload
{
    meta:
        description = "Detects EvilTokens Cloudflare Workers phishing payload with characteristic DOM manipulation, AES-GCM decryption, and anti-analysis behavior"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1"
        severity = "high"

    strings:
        $dom_placeholder = "<div id=\"r\">" ascii wide
        $aes_gcm = "AES-GCM" ascii wide
        $body_inject = "document.body.innerHTML" ascii wide
        $b64_decode = "atob(" ascii
        $antibot_header = "X-Antibot-Token" ascii wide
        $hint_param = "?hint=" ascii wide
        $device_start = "/device/start" ascii wide

    condition:
        filesize < 2MB and
        (
            ($dom_placeholder and $aes_gcm and $body_inject) or
            ($antibot_header and $device_start) or
            (4 of them)
        )
}
