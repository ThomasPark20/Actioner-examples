rule AsyncAPI_NPM_Miasma_Loader
{
    meta:
        description = "Detects the obfuscated import-time loader injected into compromised AsyncAPI npm packages, including the HKDF master key, spawn pattern, and IPFS CID strings"
        author = "Actioner"
        date = "2026-07-23"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "critical"

    strings:
        $master_key = "rt-vault-master-key-32b-aaaaaaaa" ascii
        $ipfs_cid1 = "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf" ascii
        $ipfs_cid2 = "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9" ascii
        $campaign = "miasma-train-p1" ascii
        $org_id = "miasma-test-org" ascii
        $drop_win = "\\NodeJS\\sync.js" ascii
        $drop_linux = "/.local/share/NodeJS/sync.js" ascii
        $drop_macos = "/Library/Application Support/NodeJS/sync.js" ascii
        $spawn_pattern = "detached" ascii
        $spawn_hide = "windowsHide" ascii
        $miasma_svc = "miasma-monitor" ascii

    condition:
        filesize < 10MB and
        (
            $master_key or
            any of ($ipfs_cid*) or
            ($campaign and $org_id) or
            (2 of ($drop_*) and $spawn_pattern and $spawn_hide) or
            ($miasma_svc and any of ($drop_*))
        )
}

rule AsyncAPI_NPM_Miasma_Campaign_Strings
{
    meta:
        description = "Detects AsyncAPI npm supply chain compromise artifacts by campaign-specific strings: obfuscation markers, dead-drop URLs, mDNS service name, and Ethereum contract address"
        author = "Actioner"
        date = "2026-07-23"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "critical"

    strings:
        $obfusc = "const _0x5af5e1" ascii
        $rentry = "rentry.co/elzotebo" ascii
        $mdns = "_miasma._tcp" ascii
        $eth_addr = "0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710" ascii

    condition:
        filesize < 10MB and
        (
            ($obfusc and 1 of ($rentry, $mdns, $eth_addr)) or
            2 of ($rentry, $mdns, $eth_addr)
        )
}
