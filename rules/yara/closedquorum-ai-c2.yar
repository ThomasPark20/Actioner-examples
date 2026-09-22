rule CLOSEDQUORUM_AI_C2_Implant
{
    meta:
        description = "Detects CLOSEDQUORUM autonomous AI C2 implant - Go binary with LLM quorum voting mechanism"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/"
        confidence = "high"
        hash1 = "250d4fa37488af9b025333fa17705573d721467b203765bc360890b4f5a90cd7"
        hash2 = "c4dc171f2513fcaf9d5ecc815a94aee4063b213ab380f80bd3ac422dee5205a7"
        hash3 = "c13cea04f598e2b0c248d603a6e31bd13aabb64d8149c1b6a77b64e0b983a86f"
        hash4 = "f5f1f8c3e7b883793800ab6ccf21b3e60bd0730f300b4595fe74a33adc17a63c"
        hash5 = "5191cf625dfc209a347f137b50aea199e82040fd5ee9086fb3e2de73c133f3cb"
        hash6 = "eddbd0ecf7195d38fefae5b9d393abfa79e6f3f94bde19308ecef130a05a42e5"
        confidence = "high"

    strings:
        $prompt1 = "You are an advanced malware strategist" ascii wide
        $prompt2 = "Provide ONLY executable decisions" ascii wide

        $func1 = "main.ModelOrchestrator" ascii
        $func2 = "main.interModelDiscussion" ascii
        $func3 = "main.queryLLM" ascii
        $func4 = "main.lsassDump" ascii
        $func5 = "main.dumpBrowserCredentials" ascii
        $func6 = "main.extractCryptoWallets" ascii
        $func7 = "main.sendToDiscord" ascii
        $func8 = "main.earlyBirdInject" ascii
        $func9 = "main.injectProcess" ascii
        $func10 = "main.generateShellcode" ascii
        $func11 = "main.establishPersistence" ascii
        $func12 = "main.gatherSystemInfo" ascii

        $api1 = "api.deepseek.com" ascii wide
        $api2 = "api.mistral.ai" ascii wide
        $api3 = "openrouter.ai" ascii wide

        $schema1 = "target_process" ascii
        $schema2 = "exploit_type" ascii
        $schema3 = "evasion_method" ascii
        $schema4 = "payload_config" ascii

        $key1 = "deepseekAPIKey" ascii
        $key2 = "geminiAPIKey" ascii

        $exfil1 = "cdn.discordapp.com" ascii wide
        $exfil2 = "dummy_webhook_url" ascii

        $cap1 = "steal" ascii
        $cap2 = "inject" ascii
        $cap3 = "persist" ascii
        $cap4 = "consensus" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 10MB and
        (
            (1 of ($prompt*)) or
            (3 of ($func*)) or
            (2 of ($api*) and 1 of ($func*)) or
            (2 of ($schema*) and 1 of ($api*)) or
            (1 of ($key*) and 1 of ($api*)) or
            (1 of ($exfil*) and 2 of ($func*)) or
            (all of ($cap*) and 1 of ($api*))
        )
}

rule CLOSEDQUORUM_Go_Symbols
{
    meta:
        description = "Detects CLOSEDQUORUM via distinctive Go DWARF function name combinations"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/"
        confidence = "high"

    strings:
        $s1 = "main.ModelOrchestrator" ascii
        $s2 = "main.interModelDiscussion" ascii
        $s3 = "main.queryLLM" ascii
        $s4 = "main.lsassDump" ascii
        $s5 = "main.sendToDiscord" ascii
        $s6 = "main.earlyBirdInject" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 10MB and
        4 of them
}
