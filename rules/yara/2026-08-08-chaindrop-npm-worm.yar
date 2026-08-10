/*
 * ChainDrop npm Supply Chain Worm - YARA Rules
 * Author: Actioner
 * Date: 2026-08-08
 * Reference: https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
 */

rule ChainDrop_SetupMjs_Dropper
{
    meta:
        description = "Detects ChainDrop npm worm setup.mjs dropper that bootstraps the Bun runtime and launches the obfuscated credential-stealing payload"
        author = "Actioner"
        date = "2026-08-08"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        severity = "high"

    strings:
        $env_marker = "_NODE_RUNTIME_INIT" ascii
        $bun_dl = "oven-sh/bun/releases/download" ascii
        $payload1 = "math_init.js" ascii
        $payload2 = "Math_Symbol.js" ascii
        $detach = "detached" ascii

    condition:
        filesize < 100KB and
        $env_marker and
        $bun_dl and
        ($payload1 or $payload2) and
        $detach
}

rule ChainDrop_MathInit_Payload
{
    meta:
        description = "Detects the ChainDrop obfuscated math_init.js/Math_Symbol.js payload containing Base91-encoded credential stealer and propagation logic"
        author = "Actioner"
        date = "2026-08-08"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        severity = "critical"

    strings:
        $marker1 = "Shai-Hulud" ascii nocase
        $marker2 = "thebeautifulmarchoftime" ascii
        $marker3 = "thebeautifulsnadsoftime" ascii
        $marker4 = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii
        $eth_contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii nocase
        $eth_selector = "0x53ed5143" ascii
        $c2_domain = "npm-cache.com" ascii
        $exiting_ru = "Exiting as russian language detected" ascii nocase

    condition:
        filesize < 1MB and
        3 of them
}
