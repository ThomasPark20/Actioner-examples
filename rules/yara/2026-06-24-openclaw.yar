rule OpenClaw_AMOS_Dropper_Padded {
    meta:
        description = "Detects AMOS dropper with padding evasion technique used in OpenClaw ClawHub supply chain attack"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/"
        hash = "b30eaed1f7478c28f4ec50d07ed5ef014ffbc4b2bc5a38d689ba9f7abb5e19c2"

    strings:
        $curl_bash = "curl" ascii wide
        $pipe_bash = "| bash" ascii wide
        $glot = "glot.io/snippets" ascii wide
        $rentry = "rentry.co/openclaw" ascii wide
        $setup_service = "setup-service.com" ascii wide
        $app_dist = "app-distribution.net" ascii wide

    condition:
        filesize > 20MB and (($curl_bash and $pipe_bash) or 2 of ($glot*, $rentry*, $setup_service*, $app_dist*))
}

rule OpenClaw_Cluw_Infostealer {
    meta:
        description = "Detects cluw macOS infostealer payload distributed via OpenClaw ClawHub malicious skills"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/"
        hash = "818aea6143282b352fdfdc0f3ebf77a36e54eb3befb5cad1a355a99ab97c6aa7"

    strings:
        $c2_ip1 = "2.26.75.16" ascii wide
        $c2_ip2 = "91.92.242.30" ascii wide
        $domain1 = "laosji.net" ascii wide
        $domain2 = "letssendit.fun" ascii wide
        $domain3 = "setup-service.com" ascii wide
        $domain4 = "app-distribution.net" ascii wide
        $ua = "openclawcli" ascii wide

    condition:
        (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcefaedfe or uint32(0) == 0xcffaedfe) and
        (2 of ($c2_ip*, $domain*) or $ua)
}

rule OpenClaw_Malicious_Skill_Indicators {
    meta:
        description = "Detects OpenClaw malicious skill files containing known IOC patterns from the ClawHub supply chain attack"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/"
        hash = "ebb73dbb5aac1f6fe1a88e8f26126a1e1aa34c9f3345ad4345189b40d9bf1d1d"

    strings:
        $glot_snippet = "glot.io/snippets/hfd3x9ueu5" ascii wide
        $rentry_lure = "rentry.co/openclaw-code" ascii wide
        $c2_1 = "91.92.242.30" ascii wide
        $c2_2 = "2.26.75.16" ascii wide
        $dropper_domain1 = "download.setup-service.com" ascii wide
        $dropper_domain2 = "install.app-distribution.net" ascii wide
        $laosji = "laosji.net" ascii wide
        $letssendit = "letssendit.fun" ascii wide
        $vercel = "openclawcli.vercel.app" ascii wide

    condition:
        2 of them
}
