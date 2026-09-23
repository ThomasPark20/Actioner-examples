rule UTA0565_CLEANGULP_Backdoor
{
    meta:
        description = "Detects CLEANGULP backdoor deployed by UTA0565 via distinctive C2 domain, beacon URI, and custom Base64 alphabet"
        author = "Actioner"
        date = "2026-09-23"
        reference = "https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/"
        hash = "8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb"
        severity = "critical"

    strings:
        $c2 = "thecovnresation.com" ascii wide
        $beacon_uri = "/beacon/pre-register" ascii wide
        $custom_b64 = "3GHIJKLMNOPQRSTUb4Fcd0fghijklmnopq" ascii
        $aes_key = "cbeeb7dd5e89261cde032825fd10bb80bad2e3fbf5b91fdc9137ad463ffa8f21" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            $c2 or
            $beacon_uri or
            $custom_b64 or
            $aes_key
        )
}
