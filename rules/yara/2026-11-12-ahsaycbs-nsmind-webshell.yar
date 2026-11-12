rule Webshell_AhsayCBS_Nsmind_Signed_API
{
    meta:
        description = "Detects the nsmind.jsp signed-API web shell via hardcoded API key and HMAC secret"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://www.huntress.com/blog/ahsaycbs-webshells"
        hash = "6c695baad1d81ed49194d07a79381292c0466208ff1a9862c0c55f971d6a409f"
        severity = "critical"

    strings:
        $api_key = "NS_f1ChEBy4SCYGyIDkYcsWOivwtWyXt5il" ascii
        $hmac_secret = "NS_aAXMPsB8zsMdkVbjTp6zicnj9w8Hkaew" ascii
        $x_auth = "X-Auth-Token" ascii
        $x_sig = "X-Signature" ascii
        $hmac_sha = "HmacSHA256" ascii

    condition:
        filesize < 100KB and
        1 of ($api_key, $hmac_secret) and
        2 of ($x_auth, $x_sig, $hmac_sha)
}
