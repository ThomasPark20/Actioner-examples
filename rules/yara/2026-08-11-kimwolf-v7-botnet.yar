rule Malware_Kimwolf_V7_ELF_Botnet
{
    meta:
        description = "Detects Kimwolf v7 botnet ELF binaries via distinctive strings and structural markers"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/"
        hash = "406647de09a0ffa279756b4ccb344b1b76a333320c5b50fd367901fa006cf0ff"
        hash = "345222bca004595977f971d76900b0c65fd9bf9d91c50cd0c5bf5a93f1ad9e49"
        hash = "2ec2e85b0358e0c681cb5067489a9086ec97dbbf7e3c952dd9cd496b319d5af5"
        severity = "critical"

    strings:
        $ver = "boxv7" ascii
        $sock = "@n" ascii
        $proc1 = "netd_service" ascii fullword
        $proc2 = "TVHelper" ascii fullword
        $proc3 = "inetd" ascii fullword
        $rpc1 = "rpcuniverse.com" ascii
        $rpc2 = "0xrpc.io" ascii
        $rpc3 = "llamarpc.com" ascii
        $rpc4 = "publicnode.com" ascii
        $onion = "edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion" ascii
        $func1 = "attack_case17_http2_flood" ascii
        $func2 = "build_http2_attack_headers" ascii
        $func3 = "prng_seed_from_urandom" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            ($ver and $sock and 2 of ($proc*)) or
            ($onion) or
            (2 of ($rpc*) and 1 of ($proc*)) or
            (1 of ($func*) and $ver)
        )
}
