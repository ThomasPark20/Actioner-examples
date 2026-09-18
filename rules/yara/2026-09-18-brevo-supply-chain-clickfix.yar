rule Brevo_Supply_Chain_Injected_Script_Loader
{
    meta:
        description = "Detects the injected JavaScript loader appended to Brevo JS assets (sdk-loader.js, brevo-conversations.js) during the September 2026 supply chain attack"
        author = "Actioner"
        date = "2026-09-18"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "critical"
        hash = "58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308"

    strings:
        $loader1 = "cdn.sendibt1.com" ascii
        $loader2 = "cdn2.sendibt1.com" ascii
        $loader3 = "cdn3.sendibt1.com" ascii
        $loader4 = "cdn4.sendibt1.com" ascii
        $loader5 = "cdn9.sendibt1.com" ascii
        $loader6 = "cdn10.sendibt1.com" ascii
        $loader7 = "cdn11.sendibt1.com" ascii
        $inject_pattern = "document.createElement(\"script\")" ascii
        $inject_src = "sendibt1.com/f.js" ascii

    condition:
        filesize < 5MB and
        (any of ($loader*) or $inject_src) and
        $inject_pattern
}

rule Brevo_Supply_Chain_Sendibt1_Domain_Reference
{
    meta:
        description = "Detects any file referencing the sendibt1.com malicious domain used in the Brevo supply chain attack"
        author = "Actioner"
        date = "2026-09-18"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "medium"

    strings:
        $domain = "sendibt1.com" ascii wide nocase

    condition:
        filesize < 10MB and $domain
}

rule Brevo_Supply_Chain_ClickFix_C2_API_Paths
{
    meta:
        description = "Detects files containing the specific C2 API endpoint path hashes used by the Brevo ClickFix malware for fingerprinting and command delivery"
        author = "Actioner"
        date = "2026-09-18"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "high"

    strings:
        $api1 = "/api/v1/0044d4a" ascii
        $api2 = "/api/v1/e08a3c4" ascii
        $api3 = "/api/v1/4aff112" ascii
        $api4 = "/api/v1/b832c14" ascii
        $domain = "sendibt1.com" ascii

    condition:
        filesize < 5MB and
        $domain and
        2 of ($api*)
}
