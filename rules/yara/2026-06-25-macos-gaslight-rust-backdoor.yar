import "macho"

rule macOS_Gaslight_Rust_Backdoor : DPRK backdoor macos
{
    meta:
        description = "Detects macOS.Gaslight Rust backdoor based on embedded strings, configuration fields, and operator command verbs"
        author = "Actioner CTI"
        date = "2026-06-25"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash1 = "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525"
        hash2 = "77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca"
        severity = "critical"

    strings:
        // Configuration schema field names (serde plaintext)
        $cfg_tg_room = "tg_room_id" ascii
        $cfg_aes_key = "aes_key" ascii
        $cfg_github_token = "github_token" ascii
        $cfg_github_repo = "github_repo" ascii
        $cfg_main_upload = "main_upload_url" ascii
        $cfg_main_base = "main_base_url" ascii
        $cfg_payload_macos = "payload_path_macos" ascii
        $cfg_persist_name = "persist_name_macos" ascii
        $cfg_persist_type = "persist_type_macos" ascii
        $cfg_init_python = "init_python_enable" ascii
        $cfg_persist_enable = "persist_enable" ascii

        // Operator command verbs
        $cmd_shell = "shell" ascii
        $cmd_upload = "upload" ascii
        $cmd_kill = "kill" ascii
        $cmd_stop = "stop" ascii
        $cmd_focus = "focus" ascii

        // LaunchAgent persistence label
        $persist_label = "com.apple.system.services.activity" ascii

        // Bot token redaction string
        $redaction = "file/token:redacted" ascii

        // Signing identifier pattern
        $sign_id = "endpoint-macos-aarch64" ascii

    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xBEBAFECA) and
        (
            (5 of ($cfg_*)) or
            ($persist_label and $redaction) or
            ($persist_label and 3 of ($cfg_*)) or
            (4 of ($cfg_*) and 3 of ($cmd_*)) or
            ($sign_id and 2 of ($cfg_*))
        )
}

rule macOS_Gaslight_Python_Stealer : DPRK stealer macos
{
    meta:
        description = "Detects the embedded Python stealer component of macOS.Gaslight targeting browser data, keychain, and system information"
        author = "Actioner CTI"
        date = "2026-06-25"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash1 = "baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239"
        severity = "high"

    strings:
        $collected = "collected_data.zip" ascii
        $keychain = "login.keychain-db" ascii
        $ps_aux = "ps aux" ascii
        $sys_profiler = "system_profiler" ascii
        $chrome = "Chrome" ascii
        $brave = "Brave" ascii
        $firefox = "Firefox" ascii
        $safari = "Safari" ascii

    condition:
        filesize < 50KB and
        $collected and
        $keychain and
        4 of ($chrome, $brave, $firefox, $safari) and
        ($ps_aux or $sys_profiler)
}

rule macOS_Gaslight_Prompt_Injection : AI_evasion DPRK
{
    meta:
        description = "Detects the LLM prompt injection payload embedded in macOS.Gaslight designed to deceive AI-assisted analysis tools"
        author = "Actioner CTI"
        date = "2026-06-25"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        severity = "high"

    strings:
        // Prompt injection scaffolding tokens
        $scaffold1 = "{{DATA}}" ascii

        // Fabricated system messages patterns
        $fake_token_expiry = "token expir" ascii nocase
        $fake_oom = "out-of-memory" ascii nocase
        $fake_disk = "disk exhaustion" ascii nocase
        $fake_injection = "injection vulnerabilit" ascii nocase
        $fake_static = "static-analysis" ascii nocase

        // Markdown fence indicators
        $md_fence = "```" ascii

    condition:
        filesize < 500KB and
        $scaffold1 and
        $md_fence and
        3 of ($fake_*)
}

rule macOS_Gaslight_Bash_Installer : DPRK installer macos
{
    meta:
        description = "Detects the bash installer script used by macOS.Gaslight to fetch a standalone Python runtime from astral-sh/python-build-standalone"
        author = "Actioner CTI"
        date = "2026-06-25"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash1 = "b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394"
        severity = "medium"

    strings:
        $python_build = "python-build-standalone" ascii
        $astral = "astral-sh" ascii
        $cpython = "cpython-3.10" ascii
        $arm64 = "arm64" ascii
        $x86_64 = "x86_64" ascii

    condition:
        filesize < 10KB and
        $python_build and
        $astral and
        $cpython and
        ($arm64 or $x86_64)
}
