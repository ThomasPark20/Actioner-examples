import "pe"

rule Malware_VOLTA_Infostealer_Strings
{
    meta:
        description = "Detects VOLTA infostealer based on characteristic strings including debug log paths, dossier filenames, exfiltration archive names, and LLM model fallback chain identifiers"
        author = "Actioner"
        date = "2026-11-11"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $debug = "volta_debug.txt" ascii wide
        $report = "Identity_Report.txt" ascii wide
        $analysis = "AI_Analysis.txt" ascii wide
        $zip1 = "volta_log.zip" ascii wide
        $zip2 = "volta_dox.zip" ascii wide
        $zip3 = "volta_doxnet.zip" ascii wide
        $model1 = "anthropic/claude-opus-4.6" ascii
        $model2 = "moonshotai/kimi-k2" ascii
        $model3 = "google/gemini-2.5-flash" ascii
        $api = "/api/v1/chat/completions" ascii
        $openrouter = "openrouter.ai" ascii
        $worth = "WHAT THEY'RE WORTH" ascii wide
        $opsec = "THEIR OPSEC" ascii wide
        $wallet = "WALLET VAULTS CRACKED" ascii wide
        $refusal1 = "I can't" ascii wide
        $refusal2 = "I'm not able" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            (3 of ($debug, $report, $analysis, $zip1, $zip2, $zip3)) or
            (2 of ($model1, $model2, $model3) and $api) or
            ($openrouter and $api and 1 of ($worth, $opsec, $wallet)) or
            (4 of them)
        )
}

rule Malware_VOLTA_Infostealer_Artifacts_Broad
{
    meta:
        description = "Broadly detects VOLTA infostealer variants by matching PE64 binaries containing two or more VOLTA-prefixed artifact name strings (volta_debug, volta_log, volta_dox)"
        author = "Actioner"
        date = "2026-11-11"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        tlp = "WHITE"
        severity = "high"

    strings:
        $volta1 = "volta_debug" ascii wide
        $volta2 = "volta_log" ascii wide
        $volta3 = "volta_dox" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        pe.machine == pe.MACHINE_AMD64 and
        2 of ($volta*)
}
