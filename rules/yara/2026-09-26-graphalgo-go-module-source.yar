rule graphalgo_go_module_source
{
    meta:
        description = "Detects source code of malicious Go modules (gocommunity.io/orderedbtree, gogets.dev/btreex) used in the Graphalgo supply chain campaign."
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.aikido.dev/blog/graphalgo-terraform-go-modules"

    strings:
        $mod1 = "gocommunity.io/orderedbtree" ascii
        $mod2 = "gogets.dev/btreex" ascii
        $contract = "AD02b5cDE693529d3bdA0266299501ad0193036C" ascii nocase
        $slack = "portfolio-devs.slack.com" ascii

    condition:
        filesize < 10MB and
        any of ($mod*) and
        ($contract or $slack)
}
