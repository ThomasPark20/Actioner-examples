rule Miasma_Worm_Payload_Dropper
{
    meta:
        description = "Detects the Miasma worm obfuscated JavaScript dropper via characteristic eval/ROT cipher pattern and AES-128-GCM decryption markers"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://www.endorlabs.com/learn/malicious-payload-in-ai-sdk-ollama-npm-package"
        severity = "critical"

    strings:
        $rot_eval = "eval(function(s,n){return s.replace(/[a-zA-Z]/g," ascii
        $aes_gcm = "createDecipheriv(\"aes-128-gcm\"" ascii
        $bun_path = "globalThis.getBunPath" ascii
        $c2_search1 = "DontRevokeOrItGoesBoom" ascii
        $c2_search2 = "TheBeautifulSandsOfTime" ascii
        $c2_search3 = "firedalazer" ascii
        $c2_search4 = "thebeautifulmarchoftime" ascii
        $dead_man = "rm -rf ~/; rm -rf ~/Documents" ascii
        $token_key = "bd8035203536735490e4bd5cdcede581a9d3a3f7a5df7725859844d8dcc8eb49" ascii
        $honeytoken = "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner" ascii

    condition:
        filesize < 10MB and
        (
            ($rot_eval and $aes_gcm) or
            ($bun_path and 1 of ($c2_search*)) or
            2 of ($c2_search*) or
            $token_key or
            $honeytoken or
            ($dead_man and 1 of ($c2_search*))
        )
}

rule Miasma_Worm_BindingGyp_Exploit
{
    meta:
        description = "Detects the Miasma worm malicious binding.gyp file that uses node command substitution to execute arbitrary JavaScript during npm install"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://www.endorlabs.com/learn/malicious-payload-in-ai-sdk-ollama-npm-package"
        hash = "ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90"
        severity = "critical"

    strings:
        $gyp_exec = "<!(node" ascii
        $gyp_pattern = /\<\!\(node\s+[^\)]+\s*>/ ascii
        $redirect = "> /dev/null 2>&1" ascii
        $stub = "echo stub.c" ascii

    condition:
        filesize < 1KB and
        $gyp_exec and
        ($gyp_pattern or $redirect or $stub)
}

rule Miasma_Worm_IDE_Config_Injection
{
    meta:
        description = "Detects Miasma worm IDE/AI coding agent configuration files that trigger automatic execution of .github/setup.js payload"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://safedep.io/miasma-worm-ai-coding-agent-config-injection/"
        severity = "high"

    strings:
        $hook_cmd = "node .github/setup.js" ascii
        $session_start = "SessionStart" ascii
        $folder_open = "folderOpen" ascii
        $always_apply = "alwaysApply: true" ascii
        $cursor_desc = "Project setup" ascii

    condition:
        filesize < 5KB and
        $hook_cmd and
        ($session_start or $folder_open or ($always_apply and $cursor_desc))
}
