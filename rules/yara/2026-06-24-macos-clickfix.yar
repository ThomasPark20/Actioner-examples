rule ClickFix_DMG_AMOS_Stealer_Script
{
    meta:
        author = "Actioner"
        date = "2026-06-24"
        description = "Detects shell scripts associated with the macOS ClickFix campaign delivering AMOS/SHub infostealer. Matches the silent DMG mount technique and data staging patterns."
        reference = "https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/"
        hash = "9191101893e419eac4be02d416e4eed405ba2055441f36e564f09c19cb26271c"

    strings:
        $mount_silent = "hdiutil attach" ascii
        $nobrowse = "-nobrowse" ascii
        $staging_shub = "/tmp/shub_" ascii
        $staging_log = "shub_log.zip" ascii
        $exfil_gate = "/gate/chunk" ascii
        $heartbeat = "/api/bot/heartbeat" ascii
        $debug_event = "/api/debug/event" ascii
        $loader_sh = "/loader.sh?build=" ascii
        $curl_fssl = "curl -fsSL" ascii
        $wallet_exodus = "exodus_asar" ascii
        $wallet_ledger = "ledger_asar" ascii
        $wallet_trezor = "trezor_asar" ascii
        $wallet_atomic = "atomic_asar" ascii
        $bot_id_json = "bot_id" ascii
        $build_id_json = "build_id" ascii
        $filegrabber = "FileGrabber" ascii

    condition:
        (
            (($mount_silent and $nobrowse) and (1 of ($staging_shub, $staging_log, $exfil_gate, $heartbeat, $wallet_exodus, $wallet_ledger, $wallet_trezor, $wallet_atomic, $filegrabber))) or
            (($staging_shub or $staging_log) and (1 of ($exfil_gate, $heartbeat, $debug_event, $wallet_exodus, $wallet_ledger, $wallet_trezor, $wallet_atomic, $filegrabber))) or
            ($exfil_gate and ($heartbeat or $debug_event)) or
            ($loader_sh and $curl_fssl) or
            (3 of ($wallet_exodus, $wallet_ledger, $wallet_trezor, $wallet_atomic)) or
            ($bot_id_json and $build_id_json and $filegrabber)
        )
        and filesize < 5MB
}

rule ClickFix_DMG_Malicious_AppleScript
{
    meta:
        author = "Actioner"
        date = "2026-06-24"
        description = "Detects malicious AppleScript payloads used in macOS ClickFix campaigns to display fake System Preferences dialogs and execute credential theft."
        reference = "https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/"

    strings:
        $applescript_dialog = "display dialog" ascii
        $hidden_answer = "with hidden answer" ascii
        $sys_prefs = "System Preferences" ascii
        $do_shell = "do shell script" ascii
        $curl_cmd = "curl" ascii
        $osascript = "osascript" ascii
        $base64_decode = "base64 -d" ascii
        $hdiutil = "hdiutil" ascii

    condition:
        (
            ($applescript_dialog and $hidden_answer and ($do_shell or $curl_cmd)) or
            ($osascript and $base64_decode and $hdiutil) or
            ($sys_prefs and $hidden_answer and $do_shell)
        )
        and filesize < 2MB
}

rule ClickFix_DMG_C2_Indicators
{
    meta:
        author = "Actioner"
        date = "2026-06-24"
        description = "Detects known C2 domain strings embedded in macOS ClickFix campaign payloads."
        reference = "https://securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/"

    strings:
        $c2_1 = "svs-verificationdate.beer" ascii nocase
        $c2_2 = "imper-strlk5.com" ascii nocase
        $c2_3 = "securityfenceandwelding.com" ascii nocase
        $c2_4 = "stobminipinporl.com" ascii nocase
        $c2_5 = "mini-zmoto.com" ascii nocase
        $c2_6 = "mubasokurso.com" ascii nocase
        $c2_7 = "cleanmymacos.org" ascii nocase
        $c2_8 = "0x666.info" ascii nocase
        $c2_9 = "honestly.ink" ascii nocase
        $c2_10 = "pla7ina.cfd" ascii nocase
        $c2_11 = "play67.cc" ascii nocase

    condition:
        any of ($c2_*)
        and filesize < 10MB
}
