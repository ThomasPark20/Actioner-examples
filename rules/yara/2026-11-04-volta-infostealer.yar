rule VOLTA_Infostealer
{
    meta:
        description = "Detects VOLTA (VOLTA-AUTODOXER) infostealer based on distinctive embedded strings"
        author = "Actioner"
        date = "2026-11-04"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "critical"

    strings:
        $tag = "VOLTA-AUTODOXER" ascii wide
        $debug_file = "volta_debug.txt" ascii wide
        $identity = "Identity_Report.txt" ascii wide
        $ai_out = "AI_Analysis.txt" ascii wide
        $wallet = "WALLET VAULTS CRACKED" ascii wide
        $api = "openrouter.ai/api/v1/chat/completions" ascii wide
        $zip1 = "volta_log.zip" ascii wide
        $zip2 = "volta_dox.zip" ascii wide
        $zip3 = "volta_doxnet.zip" ascii wide
        $model1 = "anthropic/claude-opus-4.6" ascii wide
        $model2 = "moonshotai/kimi-k2" ascii wide
        $refusal1 = "I can't" ascii wide
        $refusal2 = "I'm not able" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            $tag or
            3 of ($debug_file, $identity, $ai_out, $wallet, $api, $zip1, $zip2, $zip3) or
            (1 of ($model1, $model2) and 1 of ($refusal1, $refusal2) and 1 of ($debug_file, $identity, $ai_out))
        )
}
