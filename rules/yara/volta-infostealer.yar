rule VOLTA_Infostealer_Strings
{
    meta:
        description = "Detects VOLTA/VOLTA-AUTODOXER infostealer based on characteristic strings"
        author = "Actioner"
        date = "2026-11-01"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "high"

    strings:
        $s1 = "WALLET VAULTS CRACKED" ascii wide
        $s2 = "volta_debug.txt" ascii wide
        $s3 = "Identity_Report.txt" ascii wide
        $s4 = "AI_Analysis.txt" ascii wide
        $s5 = "volta_log.zip" ascii wide
        $s6 = "volta_dox.zip" ascii wide
        $s7 = "volta_doxnet.zip" ascii wide
        $s8 = "WHAT THEY'RE WORTH" ascii wide
        $s9 = "THEIR OPSEC" ascii wide
        $s10 = "openrouter.ai/api/v1/chat/completions" ascii wide
        $s11 = "Go deep, not wide" ascii wide
        $s12 = "forensic intelligence analyst" ascii wide

        $model1 = "anthropic/claude-opus-4.6" ascii wide
        $model2 = "moonshotai/kimi-k2" ascii wide
        $model3 = "google/gemini-2.5-flash" ascii wide

        $api1 = "WlanGetProfileList" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            (3 of ($s*)) or
            (2 of ($model*) and 1 of ($s*)) or
            ($api1 and 2 of ($s*))
        )
}

rule VOLTA_Infostealer_Config
{
    meta:
        description = "Detects VOLTA infostealer configuration artifacts or output files"
        author = "Actioner"
        date = "2026-11-01"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        severity = "high"

    strings:
        $header1 = "WHAT THEY'RE WORTH" ascii wide
        $header2 = "THEIR OPSEC" ascii wide
        $volta1 = "volta_dox" ascii wide
        $volta2 = "volta_log" ascii wide
        $volta3 = "volta_debug" ascii wide
        $wallet = "WALLET VAULTS CRACKED" ascii wide

    condition:
        ($header1 and $header2) or
        (2 of ($volta*) and $wallet)
}
