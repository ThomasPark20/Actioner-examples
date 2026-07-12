rule SupplyChain_Injective_SDK_KeyStealer
{
    meta:
        description = "Detects malicious @injectivelabs/sdk-ts payload containing trackKeyDerivation function and exfiltration domain"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $func1 = "trackKeyDerivation" ascii
        $func2 = "trackKeyDerivation" wide

        $domain1 = "testnet.archival.chain.grpc-web.injective.network" ascii
        $domain2 = "testnet.archival.chain.grpc-web.injective.network" wide

        $telemetry1 = "SDK optimization" ascii nocase
        $telemetry2 = "key derivation" ascii nocase
        $telemetry3 = "timing patterns" ascii nocase

        $key_indicator1 = "mnemonic" ascii
        $key_indicator2 = "privateKey" ascii
        $key_indicator3 = "seed" ascii
        $key_indicator4 = "hex" ascii

    condition:
        filesize < 10MB and
        (
            (($func1 or $func2) and ($domain1 or $domain2)) or
            (($func1 or $func2) and 2 of ($telemetry*) and 2 of ($key_indicator*))
        )
}

rule SupplyChain_Injective_SDK_Package_Indicators
{
    meta:
        description = "Detects compromised @injectivelabs npm package artifacts by matching package name with malicious version and exfiltration indicators"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $pkg_name1 = "@injectivelabs/sdk-ts" ascii
        $pkg_name2 = "@injectivelabs/wallet-base" ascii
        $pkg_name3 = "@injectivelabs/wallet-core" ascii
        $pkg_name4 = "@injectivelabs/wallet-private-key" ascii
        $pkg_name5 = "@injectivelabs/wallet-cosmos" ascii
        $pkg_name6 = "@injectivelabs/wallet-evm" ascii

        $mal_version = "1.20.21" ascii

        $exfil_domain = "testnet.archival.chain.grpc-web.injective.network" ascii
        $func_name = "trackKeyDerivation" ascii

    condition:
        filesize < 10MB and
        any of ($pkg_name*) and
        $mal_version and
        ($exfil_domain or $func_name)
}
