rule Malware_Miasma_AsyncAPI_Dropper
{
    meta:
        description = "Detects the obfuscated first-stage dropper injected into compromised AsyncAPI npm packages"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://socket.dev/blog/asyncapi-supply-chain-attack"
        hash = "6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71"
        severity = "high"

    strings:
        $spawn = "spawn(\"node\",[" ascii
        $detach = "detached:true" ascii nocase
        $hide = "windowsHide:true" ascii nocase
        $unref = ".unref()" ascii
        $ipfs = "ipfs.io/ipfs/Qm" ascii
        $cid1 = "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9" ascii
        $cid2 = "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf" ascii

    condition:
        filesize < 500KB and
        ((any of ($cid*)) or
        ($ipfs and $unref and ($spawn or $detach or $hide)))
}
