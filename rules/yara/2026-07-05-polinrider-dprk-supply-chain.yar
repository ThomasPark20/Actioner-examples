/*
    PolinRider DPRK Supply Chain Campaign - YARA Rules
    Date: 2026-07-05
    Author: Actioner
    Threat Actor: Contagious Interview / Lazarus / Famous Chollima / DPRK-attributed
    Campaign: PolinRider
*/

rule PolinRider_JS_Obfuscator_Variants
{
    meta:
        description = "Detects PolinRider shuffle-cipher JavaScript payloads injected into developer config files. Covers both the original and new obfuscator variants."
        author = "Actioner"
        date = "2026-07-05"
        reference = "https://github.com/OpenSourceMalware/PolinRider"
        reference2 = "https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands"
        threat_actor = "Contagious Interview / Lazarus"
        severity = "critical"

    strings:
        $orig_marker = "rmcej%otb%" ascii
        $orig_decoder = "_$_1e42" ascii
        $orig_seed1 = "2857687" ascii
        $orig_seed2 = "2667686" ascii
        $orig_global = "global['!']" ascii
        $new_marker = "Cot%3t=shtP" ascii
        $new_decoder = "MDy" ascii
        $new_seed1 = "1111436" ascii
        $new_seed2 = "3896884" ascii
        $new_global = "global['_V']" ascii
        $eval_exec = "eval(" ascii
        $config_target1 = "postcss.config" ascii
        $config_target2 = "tailwind.config" ascii
        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "m6:tTh^D)cBz?NM]" ascii
        $aes_salt = "98cb54c0b4ac259d30c9c1ca1ae87c68" ascii

    condition:
        filesize < 5MB and
        (
            ($orig_marker and ($orig_decoder or $orig_seed1 or $orig_seed2 or $orig_global))
            or
            ($new_marker and ($new_decoder or $new_seed1 or $new_seed2 or $new_global))
            or
            (($orig_global or $new_global) and $eval_exec and ($config_target1 or $config_target2))
            or
            ($xor_key1 or $xor_key2 or $aes_salt)
        )
}

rule PolinRider_Rollup_Polyfill_Malware
{
    meta:
        description = "Detects malicious npm packages masquerading as Rollup polyfill utilities. Identifies the obfuscated loader, sandbox evasion checks, and JSONKeeper payload retrieval pattern used by PolinRider Rollup packages."
        author = "Actioner"
        date = "2026-07-05"
        reference = "https://research.jfrog.com/post/rollup-polyfill-masquerading/"
        threat_actor = "Contagious Interview / Lazarus"
        severity = "critical"

    strings:
        $func1 = "ValidateSvgModule" ascii
        $func2 = "checkPlugin" ascii
        $func3 = "getPlugin" ascii
        $b64_pkg = "c3dpZnQtcGFyc2Utc3RyZWFt" ascii
        $env_codespace = "CODESPACE_NAME" ascii
        $env_codesandbox = "CODESANDBOX_HOST" ascii
        $env_vercel = "VERCEL" ascii
        $env_lambda = "AWS_LAMBDA_FUNCTION_NAME" ascii
        $env_gcloud = "GOOGLE_CLOUD_PROJECT" ascii
        $env_azure = "AZURE_FUNCTIONS_ENVIRONMENT" ascii
        $env_socket = "SOCKET_DEV" ascii
        $jsonkeeper = "jsonkeeper.com" ascii
        $wallet1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $wallet2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii
        $search1 = "*.env*" ascii
        $search2 = "*.pem" ascii
        $search3 = "*private key*" ascii
        $search4 = "*secret phrase*" ascii

    condition:
        filesize < 2MB and
        (
            ($b64_pkg and any of ($func*))
            or
            ($jsonkeeper and 3 of ($env_*))
            or
            (any of ($wallet*) and 2 of ($search*) and any of ($env_*))
        )
}

rule PolinRider_VSCode_Task_Weaponized
{
    meta:
        description = "Detects weaponized .vscode/tasks.json files with runOn folderOpen auto-execution combined with indicators of malicious content such as woff2 font execution or obfuscated commands, as used in PolinRider/TaskJacker campaigns."
        author = "Actioner"
        date = "2026-07-05"
        reference = "https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands"
        threat_actor = "Contagious Interview / Lazarus"
        severity = "high"

    strings:
        $auto_run = "folderOpen" ascii
        $run_on = "runOn" ascii
        $task_label = "eslint-check" ascii
        $woff2_exec = ".woff2" ascii
        $node_cmd = "node" ascii

    condition:
        filesize < 50KB and
        $auto_run and $run_on and
        ($task_label or ($woff2_exec and $node_cmd))
}
