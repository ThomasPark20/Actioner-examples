rule ChainDrop_Worm_Payload_Strings
{
    meta:
        description = "Detects ChainDrop npm supply chain worm payload via distinctive strings including the token exfiltration marker, Dune-themed repository description, and runtime guard variable"
        author = "Actioner"
        date = "2026-08-09"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        severity = "critical"

    strings:
        $marker1 = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii
        $marker2 = "Shai-Hulud: Here We Go Again" ascii
        $marker3 = "thebeautifulmarchoftime" ascii
        $envflag = "_NODE_RUNTIME_INIT" ascii
        $c2path = "/router" ascii
        $contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii nocase
        $getter = "0x53ed5143" ascii
        $setup = "setup.mjs" ascii
        $mathfile1 = "Math_Symbol.js" ascii
        $mathfile2 = "math_init.js" ascii

    condition:
        filesize < 5MB and
        (
            any of ($marker*) or
            ($contract and $getter) or
            ($envflag and any of ($mathfile*)) or
            (3 of them)
        )
}

rule ChainDrop_Setup_Dropper
{
    meta:
        description = "Detects the ChainDrop setup.mjs dropper via distinctive string combinations including the runtime guard variable, preinstall hooks, and Bun download indicators"
        author = "Actioner"
        date = "2026-08-09"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash1 = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        hash2 = "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
        hash3 = "b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678"
        severity = "critical"

    strings:
        $preinstall = "preinstall" ascii
        $setup = "setup.mjs" ascii
        $bun_dl = "bun-dl-" ascii
        $bun_check = "Bun" ascii
        $node_runtime = "_NODE_RUNTIME_INIT" ascii

    condition:
        filesize < 100KB and
        $setup and
        $node_runtime and
        ($preinstall or $bun_dl or $bun_check)
}
