rule UTA0560_GRIMWEDGE_Backdoor_Strings
{
    meta:
        description = "Detects GRIMWEDGE JavaScript backdoor via distinctive command handler strings and C2 communication pattern"
        author = "Actioner"
        date = "2026-09-15"
        reference = "https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/"
        hash = "59dc108e22cb856c228bbf8a1ab955fb66f0844a07fe10fa0d9fc3823d2cbbcb"
        severity = "critical"

    strings:
        $c2 = "opusaccel.top" ascii wide
        $cmd_info = "Info" ascii
        $cmd_dir = "Dir" ascii
        $cmd_mkdir = "Mkdir" ascii
        $cmd_tasklist = "Tasklist" ascii
        $cmd_taskkill = "Taskkill" ascii
        $cmd_type = "Type" ascii
        $cmd_run = "Run" ascii
        $cmd_upload = "Upload" ascii
        $loader1 = "WScript.Shell" ascii wide
        $loader2 = "eval(" ascii wide
        $loader3 = "MSXML2.XMLHTTP" ascii wide

    condition:
        filesize < 1MB and
        (
            $c2 or
            (4 of ($cmd_*) and 1 of ($loader*))
        )
}

rule UTA0560_LONGTALE_Chrome_Extension
{
    meta:
        description = "Detects LONGTALE malicious Chrome extension masquerading as Google Gemini used by JungleBamboo/APT31"
        author = "Actioner"
        date = "2026-09-15"
        reference = "https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/"
        hash = "5eb5645511b00e4f4d73125654eeb3a3930fcf09c65685dc7f03f725331492e3"
        severity = "critical"

    strings:
        $ext_id = "ckiknalbeplpcpofpnabcnhjcegckfei" ascii
        $s1 = "gitprogram.com" ascii wide
        $s2 = "MutationObserver" ascii wide
        $s3 = "chrome.cookies" ascii wide
        $s4 = "localStorage" ascii wide
        $s5 = "sessionStorage" ascii wide
        $s6 = "toDataURL" ascii wide

    condition:
        filesize < 5MB and
        (
            $ext_id or
            ($s1 and 3 of ($s2, $s3, $s4, $s5, $s6))
        )
}
