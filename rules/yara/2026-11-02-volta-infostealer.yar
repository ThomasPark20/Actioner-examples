import "hash"

rule VOLTA_Infostealer_Strings
{
    meta:
        description = "Detects VOLTA infostealer by distinctive strings: debug log name, exfil archives, LLM prompt markers, and OpenRouter API endpoint"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "critical"

    strings:
        $debug_log    = "volta_debug.txt" ascii wide
        $exfil1       = "volta_log.zip" ascii wide
        $exfil2       = "volta_dox.zip" ascii wide
        $exfil3       = "volta_doxnet.zip" ascii wide
        $report_id    = "Identity_Report.txt" ascii wide
        $ai_output    = "AI_Analysis.txt" ascii wide
        $api_endpoint = "openrouter.ai/api/v1/chat/completions" ascii wide
        $prompt_worth = "WHAT THEY'RE WORTH" ascii wide
        $prompt_opsec = "THEIR OPSEC" ascii wide
        $wallet_crack = "WALLET VAULTS CRACKED" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            ($debug_log and 2 of ($exfil*)) or
            ($api_endpoint and ($prompt_worth or $prompt_opsec)) or
            (4 of them)
        )
}

rule VOLTA_Infostealer_Hash
{
    meta:
        description = "Detects known VOLTA infostealer sample by SHA256 hash"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        severity = "critical"

    condition:
        hash.sha256(0, filesize) == "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
}
