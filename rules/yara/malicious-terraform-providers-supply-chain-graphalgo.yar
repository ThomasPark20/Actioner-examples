rule Malware_Graphalgo_Go_Implant : graphalgo dprk supply_chain
{
    meta:
        description = "Detects Go-based Graphalgo malware distributed via malicious Terraform providers and Go modules, identified by characteristic strings related to blockchain C2 and Slack beacon channels"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://www.aikido.dev/blog/graphalgo-terraform-go-modules"
        tlp = "WHITE"
        severity = "high"

    strings:
        $magic = "helloipbot!!" ascii
        $magic_hex = { 68 65 6C 6C 6F 69 70 62 6F 74 21 21 }
        $slack1 = "portfolio-devs.slack.com" ascii
        $slack2 = "portfolio-testers.slack.com" ascii
        $slack3 = "mediumstar.slack.com" ascii
        $slack_api = "conversations.history" ascii
        $contract = "0xAD02b5cDE693529d3bdA0266299501ad0193036C" ascii
        $method1 = "setCPubKey" ascii
        $method2 = "serviceData1" ascii
        $method3 = "serviceData2" ascii
        $pubkey = "bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702" ascii
        $domain1 = "gocommunity.io" ascii
        $domain2 = "gogets.dev" ascii

    condition:
        filesize < 50MB and
        (
            $magic or $magic_hex or
            2 of ($slack*) or
            ($contract and 1 of ($method*)) or
            $pubkey or
            (1 of ($domain*) and 1 of ($slack*))
        )
}
