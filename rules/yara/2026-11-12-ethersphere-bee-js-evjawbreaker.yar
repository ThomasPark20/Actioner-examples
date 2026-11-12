rule Supply_Chain_BeeJS_Evjawbreaker_Backdoor
{
    meta:
        description = "Detects the evjawbreaker Go backdoor deployed by the compromised bee-js / Swarm Desktop supply chain attack"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "9b73e7cd4e1425e770392549d8df46c706139ef476f4f7b9ac405165dc8d9696"
        severity = "critical"

    strings:
        $go_mod = "evjawbreaker" ascii fullword
        $eth_func = "evjawbreaker/internal/eth" ascii
        $parse_abi = "ParseABIString" ascii fullword
        $contract = "0xf8a900Db50b3331be6B768bA460BB59f3E40C344" ascii nocase
        $selector1 = "0x02d91518" ascii
        $selector2 = "0x1f049b68" ascii
        $persist_linux = "solidity-langsupport-runner" ascii
        $persist_macos = "com.solidity.langsupport.runner" ascii

    condition:
        filesize < 20MB and
        (
            ($go_mod and 2 of ($eth_func, $parse_abi, $contract, $selector1, $selector2)) or
            ($contract and 1 of ($persist_linux, $persist_macos) and 1 of ($go_mod, $eth_func))
        )
}
