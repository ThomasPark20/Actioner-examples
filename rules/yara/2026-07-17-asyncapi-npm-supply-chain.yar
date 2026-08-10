/*
 * AsyncAPI npm Supply Chain Compromise — YARA Detection Rules
 * Report: /home/user/Actioner-examples/summaries/2026-07-17-asyncapi-npm-supply-chain.md
 * Generated: 2026-07-17
 */

rule AsyncAPI_Miasma_Runtime_Payload
{
    meta:
        description = "Detects the Miasma modular runtime (M-RED-TEAM v6.4) payload delivered via the AsyncAPI npm supply chain compromise, targeting campaign identifiers, encryption parameters, and C2 API paths"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "critical"

    strings:
        $campaign = "miasma-train-p1" ascii
        $org = "miasma-test-org" ascii
        $version = "M-RED-TEAM" ascii
        $master_key = "rt-vault-master-key-32b-aaaaaaaa" ascii
        $info_str = "rt-file-key" ascii
        $api_beacon = "/api/v1/beacon" ascii
        $api_file_result = "/api/v1/file-result" ascii
        $api_file_content = "/api/v1/file-content/" ascii
        $mdns = "_miasma._tcp" ascii
        $lockpath = ".miasma/run/node.lock" ascii
        $rentry = "rentry.co/elzotebo999" ascii

    condition:
        filesize < 20MB and
        (
            2 of ($campaign, $org, $version) or
            ($master_key and $info_str) or
            (2 of ($api_beacon, $api_file_result, $api_file_content) and 1 of ($campaign, $org, $version, $mdns)) or
            $rentry or
            ($mdns and 1 of ($campaign, $org, $version)) or
            ($lockpath and 1 of ($campaign, $org, $version, $mdns))
        )
}

rule AsyncAPI_Miasma_ImportTime_Loader
{
    meta:
        description = "Detects the AsyncAPI npm supply chain compromise import-time loader code via campaign-specific IPFS CIDs or the distinctive obfuscation variable name"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "high"

    strings:
        $obfusc_var = "const _0x5af5e1" ascii
        $ipfs_cid1 = "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf" ascii
        $ipfs_cid2 = "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9" ascii

    condition:
        filesize < 500KB and
        (
            $obfusc_var or
            1 of ($ipfs_cid*)
        )
}
