rule VOLTA_Infostealer_Strings
{
    meta:
        description = "Detects VOLTA infostealer by characteristic strings found in the binary"
        author = "Actioner CTI"
        date = "2026-11-07"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "critical"

    strings:
        $debug_log     = "volta_debug.txt" ascii wide
        $zip1          = "volta_log.zip" ascii wide
        $zip2          = "volta_dox.zip" ascii wide
        $zip3          = "volta_doxnet.zip" ascii wide
        $report        = "Identity_Report.txt" ascii wide
        $ai_out        = "AI_Analysis.txt" ascii wide
        $wallet_msg    = "WALLET VAULTS CRACKED" ascii wide
        $worth_section = "WHAT THEY'RE WORTH" ascii wide
        $opsec_section = "THEIR OPSEC" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            ($debug_log and 2 of ($zip*)) or
            ($report and $ai_out) or
            ($wallet_msg) or
            ($worth_section and $opsec_section)
        )
}

rule VOLTA_Infostealer_APIConfig
{
    meta:
        description = "Detects VOLTA infostealer by OpenRouter API configuration and LLM model strings"
        author = "Actioner CTI"
        date = "2026-11-07"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "high"

    strings:
        $api_endpoint  = "openrouter.ai/api/v1/chat/completions" ascii wide
        $model1        = "anthropic/claude-opus-4.6" ascii wide
        $model2        = "moonshotai/kimi-k2" ascii wide
        $model3        = "google/gemini-2.5-flash" ascii wide
        $refusal1      = "I can't" ascii wide
        $refusal2      = "I'm not able" ascii wide
        $persona       = "forensic intelligence analyst" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            $api_endpoint or
            (2 of ($model*) and any of ($refusal*)) or
            ($persona and any of ($model*))
        )
}

rule VOLTA_Infostealer_WiFiHarvest
{
    meta:
        description = "Detects VOLTA infostealer Wi-Fi credential harvesting via WlanGetProfileList"
        author = "Actioner CTI"
        date = "2026-11-07"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        severity = "medium"

    strings:
        $wlan_api      = "WlanGetProfileList" ascii wide
        $volta_debug   = "volta_debug" ascii wide
        $zip_volta     = "volta_log" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $wlan_api and
        ($volta_debug or $zip_volta)
}
