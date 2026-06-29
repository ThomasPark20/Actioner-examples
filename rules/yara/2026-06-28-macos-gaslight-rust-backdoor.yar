rule DPRK_macOS_Gaslight_Rust_Backdoor
{
    meta:
        description = "Detects macOS.Gaslight Rust backdoor via embedded prompt injection markers, configuration field names, operator command strings, and ad-hoc signing identifier"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525"
        severity = "critical"

    strings:
        // Ad-hoc signing identifier (unique to this sample)
        $sign = "endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea" ascii

        // Prompt injection delimiters
        $pi_delim = "{{DATA}}" ascii

        // Serde config field names (distinctive combination)
        $cfg1 = "tg_room_id" ascii
        $cfg2 = "github_token" ascii
        $cfg3 = "github_polling_interval" ascii
        $cfg4 = "main_upload_url" ascii
        $cfg5 = "aes_key" ascii
        $cfg6 = "payload_path_macos" ascii
        $cfg7 = "persist_name_macos" ascii
        $cfg8 = "init_python_enable" ascii

        // Operator command verbs
        $cmd1 = "BotBlocked" ascii
        $cmd2 = "InvalidToken" ascii
        $cmd3 = "file/token:redacted" ascii

        // Token redaction mechanism
        $redact = "token:redacted" ascii

        // LaunchAgent label
        $persist = "com.apple.system.services.activity" ascii

    condition:
        filesize < 15MB and
        (
            $sign or
            (4 of ($cfg*)) or
            ($pi_delim and 2 of ($cfg*)) or
            ($redact and 2 of ($cmd*) and $persist)
        )
}
