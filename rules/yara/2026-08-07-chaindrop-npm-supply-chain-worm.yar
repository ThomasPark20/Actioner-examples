rule ChainDrop_NPM_Supply_Chain_Worm
{
    meta:
        description = "Detects ChainDrop npm supply chain worm payload files (setup.mjs, math_init.js) by characteristic strings including exfiltration markers, C2 endpoints, environment variable markers, and Dune-themed identifiers"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        severity = "critical"

    strings:
        $marker1 = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii
        $marker2 = "thebeautifulmarchoftime" ascii
        $marker3 = "thebeautifulsnadsoftime" ascii
        $marker4 = "Shai-Hulud: Here We Go Again" ascii
        $env_var = "_NODE_RUNTIME_INIT" ascii
        $c2_1 = "npm-cache.com" ascii
        $c2_2 = "/router" ascii
        $contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii nocase
        $selector1 = "0x53ed5143" ascii
        $selector2 = "0xd3c159e5" ascii
        $dune1 = "sardaukar" ascii
        $dune2 = "fremen" ascii
        $dune3 = "atreides" ascii
        $dune4 = "harkonnen" ascii
        $file1 = "math_init.js" ascii
        $file2 = "Math_Symbol.js" ascii
        $file3 = "setup.mjs" ascii

    condition:
        filesize < 1MB and
        (
            any of ($marker*) or
            ($env_var and 2 of ($c2_*, $contract, $selector*)) or
            (3 of ($dune*) and 1 of ($file*)) or
            ($contract and 1 of ($selector*))
        )
}

rule ChainDrop_NPM_Persistence_Config
{
    meta:
        description = "Detects ChainDrop worm's IDE persistence configuration files -- .claude/settings.json with SessionStart hook or .vscode/tasks.json invoking cross-linked setup.mjs"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        severity = "high"

    strings:
        $claude_hook = "SessionStart" ascii
        $claude_cmd = ".vscode/setup.mjs" ascii
        $vscode_task = "Environment Setup" ascii
        $vscode_cmd = ".claude/setup.mjs" ascii

    condition:
        filesize < 10KB and
        (
            ($claude_hook and $claude_cmd) or
            ($vscode_task and $vscode_cmd)
        )
}
