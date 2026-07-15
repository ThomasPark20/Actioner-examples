rule Malware_Miasma_RAT_AsyncAPI_Payload
{
    meta:
        description = "Detects the Miasma RAT payload delivered via compromised AsyncAPI npm packages, based on campaign identifiers and cryptographic key material"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://socket.dev/blog/asyncapi-supply-chain-attack"
        hash = "9e214f38537e69bf51c7fa1ddd35ae495e9cb897231ec010baf9e4f29407ee9a"
        severity = "critical"

    strings:
        $campaign = "miasma-train-p1" ascii
        $key1 = "rt-vault-master-key-32b-aaaaaaaa" ascii
        $key2 = "rt-baked-key" ascii
        $key3 = "rt-file-key-material-v1" ascii
        $key4 = "rt-file-key" ascii
        $svc = "miasma-monitor" ascii
        $cmd1 = "CollectData" ascii
        $cmd2 = "ManualSelfDestruct" ascii
        $cmd3 = "BatchDispatch" ascii
        $cmd4 = "UpdateBeaconInterval" ascii

    condition:
        filesize < 10MB and
        ($campaign or 2 of ($key*)) and
        (1 of ($cmd*) or $svc)
}
