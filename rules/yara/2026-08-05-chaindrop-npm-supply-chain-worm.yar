rule ChainDrop_ShaiHulud_Setup_Loader
{
    meta:
        description = "Detects the ChainDrop/Shai-Hulud npm worm setup.mjs preinstall loader and Math_*.js payload variants based on known hashes and distinctive strings"
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/"
        hash1 = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        hash2 = "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
        hash3 = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $c2_1 = "npm-cache.com" ascii
        $c2_2 = "pypi-get.com" ascii
        $c2_3 = "js-mirror.com" ascii
        $uri = "/router" ascii
        $eth_contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii
        $eth_selector = "0x53ed5143" ascii
        $gh_fallback = "Shai-Hulud: Here We Go Again" ascii
        $npm_whoami = "registry.npmjs.org/-/whoami" ascii
        $aes_gcm = "aes-256-gcm" ascii nocase
        $rsa_oaep = "RSA-OAEP" ascii

    condition:
        filesize < 1MB and
        (
            (2 of ($c2_*) and $uri) or
            ($eth_contract and $eth_selector) or
            ($gh_fallback) or
            ($npm_whoami and 1 of ($c2_*)) or
            ($aes_gcm and $rsa_oaep and 1 of ($c2_*))
        )
}

rule ChainDrop_ShaiHulud_MathJS_Variant
{
    meta:
        description = "Detects ChainDrop Math_Symbol.js / Math_init.js payload variants by filename-embedded strings and C2 indicators"
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $c2_1 = "npm-cache.com" ascii
        $c2_2 = "pypi-get.com" ascii
        $c2_3 = "js-mirror.com" ascii
        $cred_1 = "gh auth token" ascii
        $cred_2 = "gcloud config config-helper" ascii
        $cred_3 = "az account get-access-token" ascii
        $cred_4 = "azd auth token" ascii
        $tok_npm = "npm_" ascii
        $tok_ghp = "ghp_" ascii
        $tok_gho = "gho_" ascii
        $tok_ghs = "ghs_" ascii

    condition:
        filesize < 1MB and
        1 of ($c2_*) and
        (2 of ($cred_*) or 3 of ($tok_*))
}

rule ChainDrop_ShaiHulud_Persistence_Hook
{
    meta:
        description = "Detects ChainDrop persistence files planted in .claude/settings.json or .vscode/tasks.json with malicious hooks"
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/"
        hash = "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
        tlp = "WHITE"
        severity = "high"

    strings:
        $claude_hook = "SessionStart" ascii
        $claude_setup = ".vscode/setup.mjs" ascii
        $vscode_task = "Environment Setup" ascii
        $vscode_run = "folderOpen" ascii
        $setup_mjs = "setup.mjs" ascii

    condition:
        filesize < 100KB and
        (
            ($claude_hook and $claude_setup) or
            ($vscode_task and $vscode_run and $setup_mjs)
        )
}
