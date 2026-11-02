rule Malware_VOLTA_Infostealer_Strings
{
    meta:
        description = "Detects VOLTA infostealer (self-named VOLTA-AUTODOXER) by distinctive strings related to AI-powered credential triage and Roblox/crypto targeting"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://blog.talosintelligence.com/volta-infostealer/"
        severity = "critical"

    strings:
        $volta1 = "VOLTA-AUTODOXER" ascii wide nocase
        $volta2 = "volta_debug.txt" ascii wide
        $report1 = "Identity_Report.txt" ascii wide
        $report2 = "AI_Analysis.txt" ascii wide
        $api1 = "openrouter.ai/api/v1/chat/completions" ascii wide
        $section1 = "WALLET VAULTS CRACKED" ascii wide nocase
        $section2 = "WHAT THEY'RE WORTH" ascii wide nocase
        $section3 = "THEIR OPSEC" ascii wide nocase
        $enrich1 = "rolimons.com" ascii wide
        $refusal1 = "I cannot" ascii wide
        $refusal2 = "I can't assist" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $volta1 or
            ($volta2 and $api1) or
            (2 of ($report1, $report2, $section1, $section2, $section3)) or
            ($api1 and $enrich1) or
            ($api1 and 1 of ($refusal1, $refusal2) and 1 of ($section1, $section2, $section3))
        )
}
