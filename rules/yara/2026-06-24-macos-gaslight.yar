rule macOS_Gaslight_Rust_Backdoor
{
    meta:
        description = "Detects macOS.Gaslight DPRK Rust backdoor based on embedded configuration schema fields, prompt injection markers, and unique strings"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525"

    strings:
        // Configuration schema fields (serde)
        $cfg_tg_room = "tg_room_id" ascii
        $cfg_main_upload = "main_upload_url" ascii
        $cfg_main_base = "main_base_url" ascii
        $cfg_aes_key = "aes_key" ascii
        $cfg_github_token = "github_token" ascii
        $cfg_github_repo = "github_repo" ascii
        $cfg_payload_macos = "payload_path_macos" ascii
        $cfg_persist_macos = "persist_name_macos" ascii
        $cfg_persist_type = "persist_type_macos" ascii
        $cfg_init_python = "init_python_enable" ascii
        $cfg_persist_enable = "persist_enable" ascii

        // Prompt injection markers
        $pi_marker = "{{DATA}}" ascii
        $pi_system = "[system]" ascii

        // Bot token redaction
        $redact = "file/token:redacted" ascii

        // Command verbs
        $cmd_shell = "shell" ascii
        $cmd_upload = "upload" ascii
        $cmd_kill = "kill" ascii
        $cmd_focus = "focus" ascii

        // Collection artifact path
        $collect_path = "collected_data.zip" ascii

        // LaunchAgent label
        $la_label = "com.apple.system.services.activity" ascii

        // Ad-hoc signing identifier prefix
        $signing_id = "endpoint-macos-aarch64-" ascii

        // Rust aes-gcm crate indicator
        $aes_gcm = "aes-gcm" ascii

    condition:
        uint32(0) == 0xFEEDFACF and  // Mach-O 64-bit magic
        (
            (5 of ($cfg_*)) or
            ($redact and 2 of ($cfg_*)) or
            ($la_label and $signing_id) or
            ($pi_marker and $pi_system and 2 of ($cfg_*)) or
            (8 of them)
        )
}

rule macOS_Gaslight_Python_Stealer
{
    meta:
        description = "Detects the embedded Python stealer payload associated with macOS.Gaslight that harvests browser data, keychain, and system information"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239"

    strings:
        $browser_chrome = "Chrome" ascii
        $browser_brave = "Brave" ascii
        $browser_firefox = "Firefox" ascii
        $browser_safari = "Safari" ascii
        $keychain = "login.keychain-db" ascii
        $ps_aux = "ps aux" ascii
        $sys_prof = "system_profiler" ascii
        $collected = "collected_data.zip" ascii

    condition:
        filesize < 50KB and
        $keychain and
        $collected and
        3 of ($browser_*) and
        ($ps_aux or $sys_prof)
}

rule macOS_Gaslight_Bash_Installer
{
    meta:
        description = "Detects the Bash installer script used by macOS.Gaslight to deploy a standalone Python runtime for payload execution"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394"

    strings:
        $python_standalone = "python-build-standalone" ascii
        $astral = "astral-sh" ascii
        $cpython = "cpython-3.10" ascii
        $build_date = "20250708" ascii

    condition:
        filesize < 10KB and
        3 of them
}
