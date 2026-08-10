rule Malware_Miasma_AsyncAPI_Runtime_Strings
{
    meta:
        description = "Detects the Miasma RAT runtime via distinctive configuration and campaign strings from the AsyncAPI npm supply chain compromise (July 2026)"
        author = "Actioner"
        date = "2026-07-21"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "critical"

    strings:
        $cfg1 = "miasma-train-p1" ascii
        $cfg2 = "rt-vault-master-key-32b-aaaaaaaa" ascii
        $cfg3 = "rt-file-key" ascii
        $cfg4 = "rt-baked-key" ascii
        $svc1 = "_miasma._tcp" ascii
        $svc2 = "miasma-monitor" ascii
        $c2_1 = "/api/v1/beacon" ascii
        $c2_2 = "/api/v1/file-result" ascii
        $eth1 = "0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710" ascii

    condition:
        filesize < 15MB and 3 of them
}
