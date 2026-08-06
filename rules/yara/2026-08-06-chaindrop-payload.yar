rule Malware_ChainDrop_NPM_Worm_Payload
{
    meta:
        description = "Detects ChainDrop npm supply chain worm payload (Math_Symbol.js / math_init.js) via characteristic Dune-themed obfuscation strings and credential harvesting patterns"
        author = "Actioner"
        date = "2026-08-06"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        severity = "critical"

    strings:
        $dune1 = "fedaykin" ascii
        $dune2 = "tleilaxu" ascii
        $dune3 = "sardaukar" ascii
        $dune4 = "ornithopter" ascii
        $dune5 = "sandworm" ascii
        $dune6 = "navigator" ascii
        $dune7 = "sietch" ascii
        $dune8 = "lasgun" ascii

        $cred1 = "registry.npmjs.org/-/whoami" ascii
        $cred2 = "gh auth token" ascii
        $cred3 = "gcloud config config-helper" ascii
        $cred4 = "az account get-access-token" ascii

        $c2_1 = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii
        $c2_2 = "0x53ed5143" ascii
        $c2_3 = "npm-cache.com" ascii

        $shai = "Shai-Hulud" ascii nocase
        $marker = "thebeautifulmarchoftime" ascii

    condition:
        filesize < 1MB and
        (
            (3 of ($dune*) and 1 of ($cred*)) or
            (2 of ($c2_*) and 1 of ($dune*)) or
            ($shai and 2 of ($dune*)) or
            ($marker and 1 of ($cred*))
        )
}
