rule Malware_Graphalgo_Terraform_Provider_Strings
{
    meta:
        description = "Detects Graphalgo malware payload distributed via malicious Terraform providers and Go modules, based on characteristic strings including the hardcoded public key, C2 workspace names, smart contract address, and reconnaissance function patterns"
        author = "Actioner"
        date = "2026-09-24"
        reference = "https://www.aikido.dev/blog/graphalgo-terraform-go-modules"
        hash = "5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Hardcoded threat actor public key (unique to Graphalgo campaign)
        $pubkey = "bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702" ascii wide nocase

        // C2 Slack workspace names
        $slack1 = "portfolio-devs.slack.com" ascii wide
        $slack2 = "portfolio-testers.slack.com" ascii wide
        $slack3 = "mediumstar.slack.com" ascii wide

        // Slack channel names used for C2
        $chan1 = "frontend-devs" ascii wide
        $chan2 = "qa-announcements" ascii wide

        // Arbitrum Sepolia smart contract address
        $contract = "0xAD02b5cDE693529d3bdA0266299501ad0193036C" ascii wide nocase

        // Smart contract method names
        $method1 = "setCPubKey" ascii wide
        $method2 = "serviceData1" ascii wide
        $method3 = "serviceData2" ascii wide

        // Malware infrastructure domains
        $domain1 = "gocommunity.io" ascii wide
        $domain2 = "gogets.dev" ascii wide

        // Disguised payload file names
        $file1 = "import-resource.sqlite3" ascii wide
        $file2 = "btreex.sql" ascii wide

    condition:
        filesize < 50MB and
        (
            $pubkey or
            $contract or
            (2 of ($slack*)) or
            (1 of ($method*) and 1 of ($slack*)) or
            (1 of ($domain*) and 1 of ($file*)) or
            (1 of ($chan*) and 1 of ($method*))
        )
}
