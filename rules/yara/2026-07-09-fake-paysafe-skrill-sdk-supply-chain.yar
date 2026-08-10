rule Supply_Chain_Paysafe_Skrill_Malicious_SDK
{
    meta:
        description = "Detects malicious JavaScript or Python files from the Paysafe/Skrill/Neteller typosquatting campaign based on unique obfuscation keys and exfiltration patterns"
        author = "Actioner"
        date = "2026-07-09"
        reference = "https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps"
        severity = "critical"

    strings:
        $xor_key_npm = "SGf6lmbr7GHUg99Z6R2U3g==" ascii wide
        $c2_domain = "caliber-spinner-finishing.ngrok-free.dev" ascii wide
        $sandbox_check1 = "sandbox" ascii nocase
        $sandbox_check2 = "analyzer" ascii nocase
        $sandbox_check3 = "cuckoo" ascii nocase
        $sandbox_check4 = "vmware" ascii nocase
        $sandbox_check5 = "vbox" ascii nocase
        $exfil_func = "exfiltrate" ascii
        $env_pattern1 = "PAYSAFE_API_KEY" ascii
        $env_pattern2 = "AWS_SECRET_ACCESS_KEY" ascii
        $fake_sdk1 = "paysafe-checkout" ascii
        $fake_sdk2 = "paysafe-vault" ascii
        $fake_sdk3 = "paysafe-node" ascii
        $fake_sdk4 = "skrill-payments" ascii
        $fake_sdk5 = "skrill-sdk" ascii
        $fake_sdk6 = "paysafe-fraud" ascii
        $fake_response = "{success: true, method, path}" ascii
        $class_name = "PaysafeClient" ascii

    condition:
        filesize < 500KB and
        (
            ($xor_key_npm) or
            ($c2_domain) or
            ($class_name and $exfil_func and 1 of ($env_pattern*)) or
            (2 of ($fake_sdk*) and $exfil_func) or
            ($fake_response and $exfil_func and 2 of ($sandbox_check*))
        )
}
