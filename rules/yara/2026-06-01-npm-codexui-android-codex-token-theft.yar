rule Malware_codexui_android_Codex_Token_Stealer
{
    meta:
        description = "Detects the malicious codexui-android npm package install chunk that exfiltrates OpenAI Codex auth.json tokens"
        author = "Actioner"
        date = "2026-06-03"
        reference = "https://www.aikido.dev/blog/codex-remote-ui-steals-ai-tokens"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $chunk    = "chunk-PUR7OUAG" ascii
        $xorkey   = "anyclaw2026" ascii
        $c2host   = "sentry.anyclaw.store" ascii
        $path     = "/startlog" ascii
        $comment  = "Send tokens to our startlog endpoint" ascii nocase
        $auth     = ".codex/auth.json" ascii
        $ua       = "codexui/" ascii
        $codexenv = "CODEX_HOME" ascii

    condition:
        $c2host or
        $comment or
        ($xorkey and ($path or $auth)) or
        ($chunk and ($auth or $codexenv)) or
        (2 of ($path, $auth, $ua, $codexenv))
}
