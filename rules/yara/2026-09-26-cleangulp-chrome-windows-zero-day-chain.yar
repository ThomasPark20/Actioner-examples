rule UTA0565_CLEANGULP_Backdoor
{
    meta:
        description = "Detects CLEANGULP backdoor deployed by Chinese threat actor UTA0565 via custom Base64 alphabet, C2 domain, and beacon URI patterns"
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/"
        hash = "8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb"
        severity = "critical"

    strings:
        $c2_domain = "thecovnresation" ascii wide
        $beacon_uri = "/beacon/pre-register" ascii wide
        $custom_b64 = "3GHIJKLMNOPQRSTUb4Fcd0fghijklmnopq/rstuvwxyzABCDEWXYZ12V56789a+e" ascii wide
        $aes_key = "cbeeb7dd5e89261cde032825fd10bb80bad2e3fbf5b91fdc9137ad463ffa8f21" ascii wide
        $cmd_shell = "shell" ascii
        $cmd_ps = "ps" ascii
        $cmd_upload = "upload" ascii
        $cmd_download = "download" ascii
        $cmd_bof = "bof" ascii

    condition:
        filesize < 2MB and
        (
            $c2_domain or
            $custom_b64 or
            $aes_key or
            ($beacon_uri and 2 of ($cmd_*))
        )
}

rule UTA0565_CLEANGULP_Dropper
{
    meta:
        description = "Detects CLEANGULP dropper by filename pattern and known file size used by UTA0565"
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/"
        hash = "8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb"
        severity = "critical"

    strings:
        $mz = "MZ"
        $s1 = "thecovnresation" ascii wide
        $s2 = "/beacon/pre-register" ascii wide
        $s3 = "chrome_cleanup" ascii wide
        $s4 = "MicrosoftIME" ascii wide

    condition:
        $mz at 0 and
        filesize < 2MB and
        2 of ($s1, $s2, $s3, $s4)
}
