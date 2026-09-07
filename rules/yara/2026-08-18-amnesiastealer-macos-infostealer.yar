rule Malware_AmnesiaStealer_macOS_Strings
{
    meta:
        description = "Detects AmnesiaStealer macOS infostealer via characteristic embedded strings and configuration markers"
        author = "Actioner"
        date = "2026-08-18"
        reference = "https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/"
        hash = "de5748aac4a4d4cb48cf050652679e6bc49eda33d9ffaa0d280b578122fab55a"
        severity = "critical"

    strings:
        $xor_key = "4mn3s1a_2o26!xK" ascii
        $safe_storage_pw = "pqz8N3vKxRmY2aLcQ" ascii
        $build_marker = "BUILD_V3_MARKER.txt" ascii
        $build_variant = "v3_shell_chrome" ascii
        $debug_prefix = "[HYBRID_DEBUG]" ascii
        $config_clipper = "CLIPPER_ENABLED" ascii
        $config_encryption = "ENCRYPTION_KEY" ascii
        $module_stream = "stream_module" ascii
        $c2_path_join = "/api/bot/join" ascii
        $c2_path_actions = "/api/bot/actions" ascii
        $ws_register = "\"type\":\"register\"" ascii
        $tcc_msg = "Safari container fully protected by TCC" ascii
        $fallback_msg = "provision fallback (destructive)" ascii

    condition:
        filesize < 15MB and
        (
            ($xor_key and $safe_storage_pw) or
            ($build_marker and $build_variant) or
            (4 of ($c2_path*, $ws_register, $debug_prefix, $config_*, $module_stream)) or
            ($tcc_msg and $fallback_msg)
        )
}
