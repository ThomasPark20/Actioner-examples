/*
    ChainDrop NPM Worm - Malicious Payload Detection
    References:
        - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
        - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
*/

rule ChainDrop_Setup_Loader
{
    meta:
        description = "Detects ChainDrop setup.mjs loader script that bootstraps the Bun runtime and executes the obfuscated payload"
        author = "Actioner"
        date = "2026-08-10"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash1 = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        hash2 = "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
        severity = "critical"

    strings:
        $preinstall = "\"preinstall\"" ascii
        $setup_mjs = "setup.mjs" ascii
        $bun_dl = "bun-dl-" ascii
        $node_runtime = "_NODE_RUNTIME_INIT" ascii
        $math_symbol = "Math_Symbol" ascii
        $math_init = "math_init.js" ascii

    condition:
        filesize < 1MB and
        3 of them
}

rule ChainDrop_Obfuscated_Payload
{
    meta:
        description = "Detects ChainDrop's heavily obfuscated Bun-based payload containing Base91 encoding with custom alphabets and PBKDF2 key derivation"
        author = "Actioner"
        date = "2026-08-10"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        severity = "critical"

    strings:
        $shai_hulud = "Shai-Hulud" ascii wide
        $here_we_go = "Here We Go Again" ascii wide
        $russian_check = "russian language detected" ascii nocase
        $marker1 = "thebeautifulmarchoftime" ascii
        $marker2 = "thebeautifulsnadsoftime" ascii
        $api_key_msg = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii
        $eth_contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii nocase
        $eth_selector = "0x53ed5143" ascii

    condition:
        filesize < 2MB and
        2 of them
}

rule ChainDrop_Credential_Harvester
{
    meta:
        description = "Detects ChainDrop credential harvesting component targeting cloud tokens, SSH keys, and developer tool configurations"
        author = "Actioner"
        date = "2026-08-10"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        severity = "high"

    strings:
        $npm_cache_c2 = "npm-cache.com" ascii
        $pypi_get_c2 = "pypi-get.com" ascii
        $js_mirror_c2 = "js-mirror.com" ascii
        $c2_path = "/router" ascii
        $c2_path2 = "/cdn-cgi/rum" ascii
        $cred1 = ".npmrc" ascii
        $cred2 = ".docker/config.json" ascii
        $cred3 = "gh-token-monitor" ascii
        $cred4 = ".kube/config" ascii
        $proc_mem = "/proc/" ascii
        $proc_maps = "/maps" ascii

    condition:
        filesize < 2MB and
        1 of ($npm_cache_c2, $pypi_get_c2, $js_mirror_c2) and
        2 of ($cred*, $c2_path, $c2_path2, $proc_mem, $proc_maps)
}

rule ChainDrop_NPM_Worm_Propagation
{
    meta:
        description = "Detects ChainDrop's npm self-propagation module that steals tokens and republishes packages with malicious preinstall hooks"
        author = "Actioner"
        date = "2026-08-10"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        severity = "critical"

    strings:
        $dune1 = "sardaukar" ascii
        $dune2 = "mentat" ascii
        $dune3 = "fremen" ascii
        $dune4 = "atreides" ascii
        $dune5 = "harkonnen" ascii
        $shai = "Shai-Hulud" ascii
        $opensearch = "opensearch-js" ascii
        $release_drafter = "release-drafter.yml" ascii
        $preinstall = "preinstall" ascii
        $setup = "setup.mjs" ascii

    condition:
        filesize < 2MB and
        2 of ($dune*) and
        ($shai or ($preinstall and $setup) or ($opensearch and $release_drafter))
}
