rule SupplyChain_AsyncAPI_Miasma_Loader
{
    meta:
        description = "Detects Miasma malware loader injected into AsyncAPI npm packages via distinctive encryption key material, campaign identifiers, and IPFS CIDs"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "critical"

    strings:
        $key1 = "rt-vault-master-key-32b-aaaaaaaa" ascii
        $campaign1 = "miasma-train-p1" ascii
        $campaign2 = "miasma-test-org" ascii
        $campaign3 = "M-RED-TEAM" ascii
        $ipfs1 = "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf" ascii
        $ipfs2 = "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9" ascii
        $path_win = "NodeJS\\sync.js" ascii
        $path_unix = "NodeJS/sync.js" ascii
        $lock = ".miasma/run/node.lock" ascii
        $obf = "const _0x5af5e1" ascii

    condition:
        filesize < 10MB and (
            $key1 or
            2 of ($campaign*) or
            any of ($ipfs*) or
            ($obf and any of ($path*)) or
            ($lock and any of ($path*))
        )
}

rule SupplyChain_AsyncAPI_Miasma_Payload_Strings
{
    meta:
        description = "Detects Miasma payload files from the AsyncAPI npm supply chain compromise by matching distinctive loader strings (mDNS service name, persistence identifier, encryption key prefix)"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        hash1 = "8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c"
        hash2 = "b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a"
        hash3 = "b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292"
        hash4 = "6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71"
        hash5 = "24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168"
        severity = "critical"

    strings:
        $mdns = "_miasma._tcp" ascii
        $svc = "miasma-monitor" ascii
        $vault = "rt-vault-master" ascii
        $spawn = "windowsHide" ascii
        $detach = "detached" ascii

    condition:
        filesize < 10MB and
        $svc and $vault and
        ($spawn or $detach or $mdns)
}
