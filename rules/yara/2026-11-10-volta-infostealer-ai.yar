import "hash"

rule VOLTA_Infostealer_Artifacts
{
    meta:
        description = "Detects VOLTA infostealer based on distinctive strings found in samples"
        author = "Actioner CTI (DRAFT)"
        date = "2026-11-10"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "high"

    strings:
        $file1 = "volta_debug.txt" ascii wide
        $file2 = "volta_log.zip" ascii wide
        $file3 = "volta_dox.zip" ascii wide
        $file4 = "volta_doxnet.zip" ascii wide
        $file5 = "Identity_Report.txt" ascii wide
        $file6 = "AI_Analysis.txt" ascii wide
        $log1 = "WALLET VAULTS CRACKED" ascii wide
        $api1 = "openrouter.ai/api/v1/chat/completions" ascii wide
        $api2 = "openrouter.ai" ascii wide
        $model1 = "anthropic/claude-opus-4.6" ascii wide
        $model2 = "moonshotai/kimi-k2" ascii wide
        $model3 = "google/gemini-2.5-flash" ascii wide
        $prompt1 = "WHAT THEY'RE WORTH" ascii wide
        $prompt2 = "THEIR OPSEC" ascii wide
        $prompt3 = "forensic intelligence analyst" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            (3 of ($file*)) or
            ($log1 and 1 of ($file*)) or
            ($api1 and 1 of ($model*)) or
            ($api2 and 2 of ($prompt*)) or
            (2 of ($model*) and 1 of ($prompt*))
        )
}

rule VOLTA_Infostealer_Hash
{
    meta:
        description = "Detects known VOLTA infostealer sample by SHA256 hash"
        author = "Actioner CTI (DRAFT)"
        date = "2026-11-10"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        severity = "high"

    condition:
        hash.sha256(0, filesize) == "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
}
